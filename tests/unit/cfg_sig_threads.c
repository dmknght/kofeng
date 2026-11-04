#define _GNU_SOURCE
/*
 * cfg_sig_threads - eight scanners over ONE engine and the same objects, every one signing function units and scoring them against the same CFG blocks:
 * the verdicts, the matched diagnoses and the percentages are equal, and (under the thread sanitiser, make ASAN_FLAGS=-fsanitize=thread) no race.
 *
 * What is shared is the engine's index (the set, its filters, the pack's reads) and the object bytes' parse; what is per scanner is the matcher's state
 * (the votes, the best result per block), the allocator that charges the scan's ledger and the signing call's own memory. The objects: the reference
 * function (every diagnose fires), a variant (some fire), a small function (8 of the reference's 24 blocks: signed, fires the diagnoses up to a third) and a longer one with a jump changed, each scanned 30 times by each thread
 * in a different order.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "../../libkofeng/analyzers/cfgsign.h"
#include "../../libkofeng/scanners/scan.h"
#include <celllysis/cfg.h>
#include <kofmod/elf.h>

#include "cfg_scene.h"

static int failures;
static char root[300];
static const char *builder = "build/release/bin/ksigbuilder";
static const char *dbdir = "build/test/databases-sigs";

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

#include "cfg_pack.h"

#define N_OBJ 4u
#define N_TH 20u
#define N_THREADS 8u
#define N_ROUNDS 30u

static struct cs_obj OBJ[N_OBJ];
static kof_engine *ENG;

struct answer {
	char     verdict[160];
	uint32_t fired;          /* bit t-1: the diagnose of threshold t matched */
	unsigned pct;
	uint32_t nobj;
	uint64_t limit_hits, unsigned_objs;     /* the scanner's own counters at the answer (diagnosis of a differing answer; not compared) */
};

static void chain(struct cs_spec *g, uint32_t nb)
{
	uint32_t i;

	memset(g, 0, sizeof *g);
	g->nb = nb;
	for (i = 0; i + 1u < nb; i++) {
		g->kind[i] = CS_COND;
		g->t[i] = i + 2u < nb ? i + 2u : nb - 1u;
	}
	g->kind[nb - 1u] = CS_EXIT;
}

static void ask(kof_scanner *sc, const struct cs_obj *o, struct answer *a)
{
	kdet_run *run;
	const struct kdet_object *d;
	uint32_t i;

	memset(a, 0, sizeof *a);
	run = kscan_explain(sc, o->b, o->n, "sample", NULL);
	if (!run)
		return;
	d = kdet_run_verdict(run);              /* the object the file's verdict was made on (the root, or its normalised view) */
	if (!d)
		d = kdet_run_find(run, "sample");
	a->nobj = kdet_run_count(run);
	if (d) {
		struct kdet_info info;

		kdet_info(ENG, &d->res, &info);
		if (info.verdict)
			snprintf(a->verdict, sizeof a->verdict, "%s", info.verdict);
		for (i = 0; i < d->res.n_diag; i++)
			if (d->res.diag[i].state == KOF_DIAG_ST_MATCH) {
				const char *p = strrchr(d->res.diag[i].name, '_');
				const unsigned t = p ? (unsigned)atoi(p + 1) : 0u;

				if (t >= 1u && t <= N_TH)
					a->fired |= 1u << (t - 1u);
				if (d->res.diag[i].n_part && !a->pct)
					a->pct = d->res.diag[i].part[0].pct;
			}
	}
	a->limit_hits = kscan_stats(sc)->limit_hits;
	a->unsigned_objs = kscan_stats(sc)->mutation_unsigned_objects;
	kdet_run_free(run);
}

struct job {
	unsigned id;
	struct answer got[N_OBJ];
	int seen[N_OBJ];
	int ok;
	char why[400];
};

static void *worker(void *arg)
{
	struct job *j = arg;
	kof_scanner *sc = kscan_new(ENG);
	unsigned r, k;

	j->ok = sc != NULL;
	for (r = 0; sc && r < N_ROUNDS; r++)
		for (k = 0; k < N_OBJ; k++) {
			const unsigned which = (k + j->id + r) % N_OBJ;
			struct answer a;

			ask(sc, &OBJ[which], &a);
			if (!j->seen[which]) {
				j->got[which] = a;
				j->seen[which] = 1;
			} else if (j->got[which].fired != a.fired || j->got[which].pct != a.pct || strcmp(j->got[which].verdict, a.verdict)) {
				j->ok = 0;
				snprintf(j->why, sizeof j->why, "object %u round %u: first answer fired %05x pct %u \"%s\", now fired %05x pct %u \"%s\" (limit_hits %llu -> %llu, unsigned objects %llu -> %llu; objects %u -> %u)", which, r, j->got[which].fired,
					 j->got[which].pct, j->got[which].verdict, a.fired, a.pct, a.verdict, (unsigned long long)j->got[which].limit_hits, (unsigned long long)a.limit_hits,
					 (unsigned long long)j->got[which].unsigned_objs, (unsigned long long)a.unsigned_objs, j->got[which].nobj, a.nobj);
			}
		}
	if (sc)
		kscan_free(sc);
	return NULL;
}

int main(void)
{
	struct cs_spec g[4];
	struct scene sc;
	struct kgenome_elf_info ei;
	struct kof_obj_ctx c;
	struct kof_cfgsign cs;
	struct kof_cfgsign_req rq;
	pthread_t th[N_THREADS];
	struct job job[N_THREADS];
	unsigned i, k;
	char cmd[400];

	if (access(builder, X_OK) != 0) {
		printf("cfg_sig_threads: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_cfgthr_XXXXXX");
	if (!mkdtemp(root))
		return 2;
	chain(&g[0], 24);
	chain(&g[1], 19);
	chain(&g[2], 8);
	chain(&g[3], 30);
	g[3].kind[3] = CS_JUMP; g[3].t[3] = 9;
	for (i = 0; i < N_OBJ; i++)
		OKF(cs_build(&OBJ[i], &g[i], 1, 0), "build %u", i);
	memset(&c, 0, sizeof c);
	memset(&ei, 0, sizeof ei);
	ei.elf_data = 1;
	c.format = KOF_FMT_ELF; c.arch = KGENOME_ARCH_X86_64; c.obj_size = OBJ[0].n; c.file_header = &ei;
	memset(&rq, 0, sizeof rq);
	rq.ctx = &c; rq.data.p = OBJ[0].b; rq.data.n = OBJ[0].n; rq.off = OBJ[0].f_off[0]; rq.len = OBJ[0].f_len[0];
	OKF(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_SIGNED, "the reference is signed");
	OKF(make_pack(&sc, "thr", cs.sign.key, cs.sign.n_key, N_TH, 5u) == 0, "the pack builds (see %s)", sc.err);
	ENG = keng_open(sc.db);
	OKF(ENG != NULL, "the pack opens");
	/*
	 * EIGHT SCANNERS NEED A CEILING FOR EIGHT. Each reserves its fixed cost (12 MiB and the memo, about 50 MB) from the engine's 512 MiB, and an object's share is what is
	 * left over the scanners alive at that moment: with all eight alive the share can be one byte, and a scanner then refuses every optional allocation of the
	 * object - the function is left unsigned (KOF_MTN_S_FUNC_UNSIGNED) and the diagnose does not fire, whichever thread the clock favours. Measured: 3 failures in 20
	 * runs at the default cap, none with the cap below.
	 */
	if (ENG)
		OKF(keng_set_memory_cap(ENG, 2048ull << 20) != 0, "the engine takes a memory cap of 2 GiB");
	if (ENG) {
		for (i = 0; i < N_THREADS; i++) {
			memset(&job[i], 0, sizeof job[i]);
			job[i].id = i;
			OKF(pthread_create(&th[i], NULL, worker, &job[i]) == 0, "thread %u", i);
		}
		for (i = 0; i < N_THREADS; i++)
			pthread_join(th[i], NULL);
		for (i = 0; i < N_THREADS; i++) {
			OKF(job[i].ok, "thread %u saw two answers for one object: %s", i, job[i].why);
			for (k = 0; k < N_OBJ; k++)
				OKF(job[i].got[k].fired == job[0].got[k].fired && job[i].got[k].pct == job[0].got[k].pct && !strcmp(job[i].got[k].verdict, job[0].got[k].verdict), "object %u: thread %u and thread 0 disagree (%s / %s, fired %05x / %05x)", k, i,
				    job[i].got[k].verdict, job[0].got[k].verdict, job[i].got[k].fired, job[0].got[k].fired);
		}
		OKF(job[0].got[0].fired == (1u << N_TH) - 1u && job[0].got[0].verdict[0], "the reference fires every diagnose (%05x, \"%s\")", job[0].got[0].fired, job[0].got[0].verdict);
		/* THE SMALL FUNCTION IS SIGNED (owner, 2026-11-01: the floor is one reachable block, KGENOME_CFG_ANCHOR_MIN; it was twelve keys): its 8 blocks are 8 of the reference's 24, a third of them (33%),
		 * so the diagnose of threshold t (t * 5 percent of the reference's blocks) fires for t <= 6: the first six, and no other. The test expected "nothing" from the era of the old floor. */
		OKF(job[0].got[2].fired == (1u << 6) - 1u && job[0].got[2].verdict[0], "the small function (8 of 24 blocks) fires the diagnoses up to 30%% and no more (fired %05x, \"%s\")", job[0].got[2].fired, job[0].got[2].verdict);
		OKF(job[0].got[1].fired != 0 && job[0].got[1].fired != (1u << N_TH) - 1u, "the variant fires some diagnoses, not all (%05x)", job[0].got[1].fired);
		keng_close(ENG);
	}
	if (!failures) {
		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	if (failures) {
		printf("cfg_sig_threads: %d FAIL\n", failures);
		return 1;
	}
	printf("cfg_sig_threads: ok\n");
	return 0;
}
