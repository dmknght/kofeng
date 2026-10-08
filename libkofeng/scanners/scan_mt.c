/*
 * scan_mt.c - the parallel walk: one producer enumerating, N workers scanning.
 *
 * The queue, the workers and the one lock that serialises the caller's callback.
 * Nothing here decides anything about an object: a worker takes a path and hands it to
 * the same sx_scan_file the single threaded walk uses, so the two walks differ in
 * WHO calls it and in nothing else. Thread-safety notes live beside the code that
 * needs them; the open ones are listed in the survey at the end of this comment.
 *
 * OPEN (found by reading, not yet fixed): the workers' path buffers and stacks are not
 * freed at join; a worker whose scanner failed to allocate falls back to scs[0], which
 * the producer's read_dir also writes (st.unreadable); should_stop, the cache hooks and
 * on_event_detected run on worker threads outside the callback lock.
 */

#define _GNU_SOURCE

#include "scan.h"
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../../libgenome/genotype/analysis/xref.h"
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


/* ---- the parallel walk ---------------------------------------------------- */

void sx_mtq_put(struct walk *w, const char *path, size_t len)
{
	struct mtq *q = w->q;
	char *copy = kof_strdup_n(path, len);

	if (!copy) {
		w->out_of_memory = 1;
		return;
	}
	pthread_mutex_lock(&q->lock);
	while (q->n == q->cap && !q->aborted)
		pthread_cond_wait(&q->can_put, &q->lock);
	if (q->aborted) {
		pthread_mutex_unlock(&q->lock);
		free(copy);
		w->aborted = 1;
		return;
	}
	q->slot[q->tail] = copy;
	q->tail = (q->tail + 1u) % q->cap;
	q->n++;
	pthread_cond_signal(&q->can_take);
	pthread_mutex_unlock(&q->lock);
}

/* One path, or NULL when there will be no more. The caller owns what it gets. */
static char *mtq_take(struct mtq *q)
{
	char *p;

	pthread_mutex_lock(&q->lock);
	while (q->n == 0 && !q->closed && !q->aborted)
		pthread_cond_wait(&q->can_take, &q->lock);
	if (q->n == 0 || q->aborted) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}
	p = q->slot[q->head];
	q->head = (q->head + 1u) % q->cap;
	q->n--;
	pthread_cond_signal(&q->can_put);
	pthread_mutex_unlock(&q->lock);
	return p;
}

/*
 * What a worker sees. Its own walk - so its own path buffer, its own object
 * count and its own scanner - plus the queue and the lock that serialises the
 * callback.
 */
struct worker {
	struct walk       w;
	struct mtq       *q;
	pthread_mutex_t  *cb_lock;
	kof_on_object     cb;
	void             *user;
	pthread_t         id;
};

/*
 * The callback, under the lock.
 *
 * Serialised rather than left to the caller because the alternative is a
 * callback contract that changes with the number of scanners - every existing
 * caller would have to be audited for thread safety before it could ever pass
 * more than one. The lock is held only for the call itself, and a callback that
 * merely counts or prints is nowhere near the cost of the scan that produced it.
 */
static int worker_cb(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct worker *wk = user;
	int rc;

	pthread_mutex_lock(wk->cb_lock);
	rc = wk->cb ? wk->cb(name, bytes, len, res, wk->user) : 0;
	pthread_mutex_unlock(wk->cb_lock);
	if (rc) {
		pthread_mutex_lock(&wk->q->lock);
		wk->q->aborted = 1;
		pthread_cond_broadcast(&wk->q->can_take);
		pthread_cond_broadcast(&wk->q->can_put);
		pthread_mutex_unlock(&wk->q->lock);
	}
	return rc;
}

static void *worker_main(void *arg)
{
	struct worker *wk = arg;
	char *path;

	while ((path = mtq_take(wk->q)) != NULL) {
		sx_scan_file(&wk->w, path);
		free(path);
		if (wk->w.aborted)
			break;
	}
	return NULL;
}

int kof_scan_walk_mt(struct kof_scanner **scs, unsigned n_sc, const char *path,
		     const struct kof_scan_option *opt, kof_on_object cb,
		     void *user)
{
	struct mtq q;
	struct walk prod;
	struct worker *wk = NULL;
	pthread_mutex_t cb_lock;
	struct stat sb;
	uint64_t total = 0;
	unsigned i, started = 0;
	int rc;

	if (!scs || !n_sc || !scs[0] || !path)
		return KOF_ERR_ARG;
	/*
	 * One scanner is the ordinary walk, and taking that path rather than
	 * running a producer and a single worker keeps the common case free of
	 * threads entirely - including the object ORDER, which a caller that
	 * asked for one scanner has every reason to expect unchanged.
	 */
	if (n_sc == 1)
		return kof_scan_walk(scs[0], path, opt, cb, user);

	if ((opt->follow_symlinks ? stat : kof_lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;
	/* A single file has nothing to spread. */
	if (!S_ISDIR(sb.st_mode))
		return kof_scan_walk(scs[0], path, opt, cb, user);
	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	memset(&q, 0, sizeof q);
	/* Four slots per worker: enough that a worker starting a small file does
	 * not wait on the producer, small enough that the producer cannot run
	 * away from them. */
	q.cap = (size_t)n_sc * 4u;
	q.slot = calloc(q.cap, sizeof *q.slot);
	if (!q.slot)
		return KOF_ERR_READ;   /* no memory for the queue */
	if (pthread_mutex_init(&q.lock, NULL) != 0 ||
	    pthread_cond_init(&q.can_put, NULL) != 0 ||
	    pthread_cond_init(&q.can_take, NULL) != 0 ||
	    pthread_mutex_init(&cb_lock, NULL) != 0) {
		free(q.slot);
		return KOF_ERR_READ;   /* no memory for the queue */
	}

	wk = calloc(n_sc, sizeof *wk);
	if (!wk) {
		free(q.slot);
		return KOF_ERR_READ;   /* no memory for the queue */
	}
	for (i = 0; i < n_sc; i++) {
		wk[i].q        = &q;
		wk[i].cb_lock  = &cb_lock;
		wk[i].cb       = cb;
		wk[i].user     = user;
		wk[i].w.sc     = scs[i] ? scs[i] : scs[0];
		wk[i].w.opt    = opt;
		wk[i].w.cb     = worker_cb;
		wk[i].w.user   = &wk[i];
		if (pthread_create(&wk[i].id, NULL, worker_main, &wk[i]) != 0)
			break;
		started++;
	}

	/*
	 * The producer runs on this thread, and it is the existing walk with the
	 * queue attached: same directory reading, same symlink policy, same depth
	 * limit, same stack. Nothing about finding files is written twice.
	 */
	memset(&prod, 0, sizeof prod);
	prod.sc  = scs[0];
	prod.opt = opt;
	prod.q   = started ? &q : NULL;
	if (!started) {
		/* No thread could be created: scan on this thread rather than
		 * returning nothing, which is the answer a caller can still use. */
		free(wk);
		pthread_mutex_destroy(&q.lock);
		pthread_cond_destroy(&q.can_put);
		pthread_cond_destroy(&q.can_take);
		pthread_mutex_destroy(&cb_lock);
		free(q.slot);
		return kof_scan_walk(scs[0], path, opt, cb, user);
	}

	{
		char sq[4096];
		size_t n = kof_path_squash(path, sq, sizeof sq);

		if (n)
			sx_push_dir(&prod, sq, n, 0);
	}
	while (!prod.aborted && !prod.out_of_memory && prod.n > 0) {
		struct pending p = prod.stack[--prod.n];
		sx_read_dir(&prod, p.path, p.depth);
		free(p.path);
	}
	while (prod.n > 0)
		free(prod.stack[--prod.n].path);
	free(prod.stack);
	free(prod.path_buf);

	pthread_mutex_lock(&q.lock);
	q.closed = 1;
	pthread_cond_broadcast(&q.can_take);
	pthread_mutex_unlock(&q.lock);

	for (i = 0; i < started; i++) {
		pthread_join(wk[i].id, NULL);
		total += wk[i].w.objects;
		/* A worker's own walk allocated a path buffer and a directory
		 * stack, and nothing freed them. */
		while (wk[i].w.n > 0)
			free(wk[i].w.stack[--wk[i].w.n].path);
		free(wk[i].w.stack);
		free(wk[i].w.path_buf);
	}
	/* The producer's count goes onto the first scanner now that no worker is
	 * using it. */
	scs[0]->st.unreadable += prod.unreadable;

	/* Whatever a stopped run left in the ring. */
	while (q.n > 0) {
		free(q.slot[q.head]);
		q.head = (q.head + 1u) % q.cap;
		q.n--;
	}
	free(q.slot);
	free(wk);
	pthread_mutex_destroy(&q.lock);
	pthread_cond_destroy(&q.can_put);
	pthread_cond_destroy(&q.can_take);
	pthread_mutex_destroy(&cb_lock);

	rc = (int)total;
	return rc;
}
