/* SPDX-License-Identifier: Apache-2.0 */
/*
 * awalk.c - libkofantarc's answer to libkoforbit/kofwalk/kofwalk.h.
 *
 * THE MEMORY SCAN'S LOGIC LIVES HERE, not in the scanner. A host asks "what is
 * running and what should I look at"; deciding that a file-backed mapping is
 * scanned as its FILE, that an anonymous executable region is scanned as
 * BYTES, and that a kernel mapping is neither - those are answers about
 * /proc, and /proc is this library's subject. The scanner was doing it, which
 * meant the same decisions would have had to be made a second time, slightly
 * differently, for Windows.
 *
 *
 * IT INCLUDES kofproc.h, WHICH IS AN ENGINE-SIDE HEADER, AND THAT IS ALLOWED.
 *
 * The rule at the top of kofantarc.h is that this library collects and does
 * not judge: no kofeng.h, no scanning, no verdict. A RECORD LAYOUT is not a
 * judgement - filling one is the same thing libkofgrille's wtext.c does when
 * it converts its own record into kof_evt, and for the same reason: the layout
 * is the meeting point, and a collector that could not fill it would need
 * somebody else to copy its fields one at a time.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "aproc.h"
#include "kofwalk.h"

struct awalk {
	struct kof_walk_api api;
	struct kof_walk_option o;

	struct kofa_plist *list;
	struct kofa_proc   proc;
	int                have_proc;

	/* The pid list, when there is one, and how far through it we are. */
	uint32_t idx;

	struct kofa_pmem  *mem;
	struct kofa_region rg;
	int                have_rg;

	struct kofa_sweep  sweep;
	uint64_t procs, refused, regions, bytes;
};

/* Fill the engine's record form from what the /proc walk found. The two are
 * different vocabularies for the same facts and this is the only place that
 * knows both. */
static void to_build(const struct kofa_proc *p, struct kof_proc_build *b)
{
	memset(b, 0, sizeof *b);
	b->os = 2;                      /* KOF_PLAT_LINUX */
	b->pid = p->pid;
	b->ppid = p->ppid;
	b->start_time = p->start_time;
	b->n_fd = p->n_fd;
	b->n_socket = p->n_socket;
	b->n_like_stdin = p->n_like_stdin;
	b->plat_a = p->uid;
	b->plat_b = p->gid;
	b->exe = p->exe;
	b->comm = p->comm;
	b->cmdline = p->cmdline;
	b->fd0 = p->fd_stdin;
	b->fd1 = p->fd_stdout;
	b->fd2 = p->fd_stderr;

	if (p->flags & KOFA_PF_EXE_GONE)
		b->flags |= KOF_PROC_F_EXE_GONE;
	if (p->flags & KOFA_PF_EXE_MEMFD)
		b->flags |= KOF_PROC_F_EXE_MEMFD;
	if (p->fds_read)
		b->flags |= KOF_PROC_F_FDS_READ;
	if (p->is_kthread)
		b->flags |= KOF_PROC_F_KTHREAD;
	if (p->exe_on_disk)
		b->flags |= KOF_PROC_F_EXE_ON_DISK;
}

/* Is this pid one the caller asked for? With no list, every one is. */
static int wanted(const struct awalk *w, uint32_t pid)
{
	uint32_t i;

	if (!w->o.pids || !w->o.n_pids)
		return 1;
	for (i = 0; i < w->o.n_pids; i++)
		if (w->o.pids[i] == pid)
			return 1;
	return 0;
}

static void close_mem(struct awalk *w)
{
	if (w->mem) {
		struct kofa_pmem_stat st;

		kofa_pmem_stats(w->mem, &st);
		w->regions += st.regions_seen;
		w->bytes += st.bytes_read;
		kofa_pmem_close(w->mem);
		w->mem = NULL;
	}
	w->have_rg = 0;
}

static int open_mem_for(struct awalk *w, const struct kofa_proc *p)
{
	struct kofa_pmem_option po;
	int err = 0;

	memset(&po, 0, sizeof po);
	/*
	 * EXECUTABLE ONLY. What a memory scan is looking for is code with no
	 * file behind it; the rest of an address space is the process's own
	 * working data, and see the note on KOFA_MW_HEAP for why searching it
	 * says what a process TOUCHED rather than what it is.
	 */
	po.want = KOFA_MW_DEFAULT | KOFA_MW_EXEC_ONLY;
	po.sweep = &w->sweep;

	w->mem = kofa_pmem_open(p->pid, p->start_time, &po, &err);
	return w->mem != NULL;
}

static int a_next_proc(void *self, struct kof_proc_build *out)
{
	struct awalk *w = self;

	if (!w || !out)
		return 0;
	close_mem(w);
	w->have_proc = 0;

	/*
	 * A PID LIST IS WALKED DIRECTLY, not filtered out of the whole table.
	 * Filtering would open and read /proc for four hundred processes to
	 * reach one, which is exactly the cost the list exists to avoid - see
	 * kof_walk_option.
	 */
	if (w->o.pids && w->o.n_pids) {
		while (w->idx < w->o.n_pids) {
			uint32_t pid = w->o.pids[w->idx++];
			struct kofa_pmem *m;
			int err = 0;

			/* start_time 0: the caller named a pid and means
			 * whatever holds it now - see kofa_pmem_open. */
			m = kofa_pmem_open(pid, 0, NULL, &err);
			if (!m) {
				w->refused++;
				continue;
			}
			w->proc = *kofa_pmem_proc(m);
			kofa_pmem_close(m);

			if (!open_mem_for(w, &w->proc)) {
				w->refused++;
				continue;
			}
			w->procs++;
			w->have_proc = 1;
			to_build(&w->proc, out);
			return 1;
		}
		return 0;
	}

	while (kofa_plist_next(w->list, &w->proc)) {
		if (w->proc.flags & (KOFA_PF_REFUSED | KOFA_PF_KERNEL)) {
			if (w->proc.flags & KOFA_PF_REFUSED)
				w->refused++;
			continue;
		}
		if (!wanted(w, w->proc.pid))
			continue;
		if (!open_mem_for(w, &w->proc)) {
			w->refused++;
			continue;
		}
		w->procs++;
		w->have_proc = 1;
		to_build(&w->proc, out);
		return 1;
	}
	return 0;
}

static int a_next_item(void *self, struct kof_walk_item *out)
{
	struct awalk *w = self;

	if (!w || !out || !w->mem)
		return 0;
	memset(out, 0, sizeof *out);

	for (;;) {
		struct kofa_chunk c;

		/* Still handing out the pieces of the region in hand. */
		if (w->have_rg && kofa_pmem_next_chunk(w->mem, &w->rg, &c)) {
			out->kind = KOF_WALK_BYTES;
			out->addr = c.addr;
			out->p = c.p;
			out->len = c.len;
			return 1;
		}
		w->have_rg = 0;

		if (!kofa_pmem_next_region(w->mem, &w->rg))
			return 0;

		if (w->rg.flags & KOFA_RGF_UNBACKED) {
			/* Nothing on disk holds these bytes, so they are read
			 * out of the process - chunk by chunk, skipping pages
			 * that are entirely zero. */
			w->have_rg = 1;
			continue;
		}

		/*
		 * AN INODE IS WHAT MAKES A PATH A FILE. [vdso] has a path and
		 * no inode; treating it as one meant a stat that could never
		 * succeed and an open that could never work, 31 times a sweep
		 * on this machine. See KOFA_RGF_KERNEL_MAPPED.
		 */
		if (w->rg.inode && w->rg.path && w->rg.path[0]) {
			out->kind = KOF_WALK_FILE;
			out->path = w->rg.path;
			return 1;
		}
		/* A region with neither: nothing to scan, and not an error. */
	}
}

static void a_stats(void *self, uint64_t *procs, uint64_t *refused,
		    uint64_t *regions, uint64_t *bytes)
{
	struct awalk *w = self;

	if (!w)
		return;
	if (procs)   *procs = w->procs;
	if (refused) *refused = w->refused;
	if (regions) *regions = w->regions;
	if (bytes)   *bytes = w->bytes;
}

static void a_close(void *self)
{
	struct awalk *w = self;

	if (!w)
		return;
	close_mem(w);
	if (w->list)
		kofa_plist_close(w->list);
	free(w);
}

struct kof_walk_api *kof_walk_open(const struct kof_walk_option *opt, int *err)
{
	struct awalk *w = calloc(1, sizeof *w);
	int e = 0;

	if (!w) {
		if (err) *err = KOFA_ERR_NOMEM;
		return NULL;
	}
	if (opt)
		w->o = *opt;

	/* No process table is opened when the caller named its pids: the whole
	 * point of naming them is not to walk it. */
	if (!w->o.pids || !w->o.n_pids) {
		w->list = kofa_plist_open(NULL, &e);
		if (!w->list) {
			free(w);
			if (err) *err = e;
			return NULL;
		}
	}

	w->api.self      = w;
	w->api.next_proc = a_next_proc;
	w->api.next_item = a_next_item;
	w->api.stats     = a_stats;
	w->api.close     = a_close;

	if (err) *err = KOFA_OK;
	return &w->api;
}
