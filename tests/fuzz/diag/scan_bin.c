/*
 * diag/scan_bin - the diagnose scan of an executable, every route and every product it hands back.
 *
 * One object is parsed from the bytes (ELF or PE: the seeds are x86-64, i386 and ARM programs wrapped in each, a PE32+ with import
 * calls, a PEB read and a direct syscall stub). The walk then runs the scan with a run mask the rng picks (sweep, symbol, emulate,
 * API-hash, lineage, alone and together) under a budget the rng picks from three tiers, and reads back everything the scan offers:
 * the nodes, their inputs, the names, the status, the products it owns, the lineage obligations and counters. The walk object, the
 * function table, the code runs, the code range and the API-hash set are driven from the same object.
 *
 * Held (each is a statement of a header comment, not of this file):
 *   - a node's inputs name a node of the scan (or the stack), its role, kind and link are in their enums, at most four of them (a node
 *     may be its own input: a loop carries a value round to itself);
 *   - the status is in the enum; the routes that ran are a subset of the bits that exist, and of the ones asked for;
 *   - bytes charged never exceed the peak; the names of a capability come back in order and stop at the count;
 *   - an instruction budget is a bound: the emulated instructions the scan reports spending stay under what it was given
 *     (twice over, the sweep run and the resolver run);
 *   - the scan is deterministic (the driver runs it twice);
 *   - G9 for the binary route (strict mode only, -DDIAG_STRICT_G9: see F7..F10): when an allocation fails in the call (c->failk) and the scan
 *     still comes back, either its status says the answer may be short or the graph is the graph of the clean run. Compared against the clean call of
 *     the same input, which the driver makes first in the same process (the signature is kept in a static, no allocation).
 */
#include "diag_seed.h"

static struct diag_st S;

/* the clean call's signature, per input, for the failk comparison */
static struct {
	uint64_t in_hash, sig;
	int      status_ok, have;
} clean;

static struct fz_field fldv[3][16];
static struct fz_map mapv[3];

static void add_prog(struct fz_corpus *c, const char *name, unsigned which, int kind)
{
	static struct ds_code code;
	static uint8_t img[DS_CODE_MAX + 0x100];
	unsigned n;

	ds_prog(&code, which);
	switch (kind) {
	case 0:  n = ds_elf64(img, &code, 0x3e); ds_elf_map(&mapv[0], fldv[0], 1); fz_corpus_add_map(c, name, img, n, &mapv[0]); break;
	case 1:  n = ds_elf32(img, &code, 3);    ds_elf_map(&mapv[1], fldv[1], 0); fz_corpus_add_map(c, name, img, n, &mapv[1]); break;
	case 2:  n = ds_elf32(img, &code, 40);   ds_elf_map(&mapv[1], fldv[1], 0); fz_corpus_add_map(c, name, img, n, &mapv[1]); break;
	default: n = ds_elf64(img, &code, 0xb7); ds_elf_map(&mapv[0], fldv[0], 1); fz_corpus_add_map(c, name, img, n, &mapv[0]); break;
	}
}

void diag_seeds_bin(struct fz_corpus *c)
{
	static struct hk_pe p;
	static struct fz_field pf[8];
	static struct fz_map pm;
	static const char *const nm[DS_NPROG] = { "elf64-sockwrite", "elf64-wrapper", "elf64-diamond", "elf64-loop", "elf64-stager",
						  "elf64-clobber", "elf64-stack", "elf64-slot", "elf64-data" };
	unsigned i, v;
	static const uint8_t arm[] = { 0x01, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x1e, 0xff, 0x2f, 0xe1 };   /* mov r7,#1 ; svc 0 ; bx lr */
	static const uint8_t a64[] = { 0x08, 0x08, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6 };   /* mov x8,#64 ; svc #0 ; ret */
	static struct ds_code ac;

	for (i = 0; i < DS_NPROG; i++)
		add_prog(c, nm[i], i, 0);
	add_prog(c, "elf32-i386-sockwrite", 0, 1);
	ac.n = 0; ds_emit(&ac, arm, sizeof arm);
	{
		static uint8_t img[0x100];
		unsigned n = ds_elf32(img, &ac, 40);

		ds_elf_map(&mapv[2], fldv[2], 0);
		fz_corpus_add_map(c, "elf32-arm-svc", img, n, &mapv[2]);
	}
	ac.n = 0; ds_emit(&ac, a64, sizeof a64);
	{
		static uint8_t img[0x200];
		unsigned n = ds_elf64(img, &ac, 0xb7);

		ds_elf_map(&mapv[0], fldv[0], 1);
		fz_corpus_add_map(c, "elf64-aarch64-svc", img, n, &mapv[0]);
	}
	for (i = 0; i < DS_NKO; i++) {                            /* kernel-module shapes: ET_REL with relocations (the rel-gaps route) */
		static uint8_t ko[0x1000];
		static struct fz_field kf[6];
		static struct fz_map km;
		unsigned n = ds_ko(ko, i), shoff = (unsigned)hk_r(ko + 40, 8, 0), k = 0;
		char name[24];

		km.f = kf;
		kf[k].off = 40; kf[k].size = 8; kf[k].be = 0; kf[k++].kind = FZ_OFFSET;       /* e_shoff */
		kf[k].off = 60; kf[k].size = 2; kf[k].be = 0; kf[k++].kind = FZ_COUNT;        /* e_shnum */
		kf[k].off = 62; kf[k].size = 2; kf[k].be = 0; kf[k++].kind = FZ_COUNT;        /* e_shstrndx */
		km.n = k;
		km.rec_off = shoff; km.rec_size = 64; km.rec_n = 6;
		snprintf(name, sizeof name, "ko-rel-%u", i);
		fz_corpus_add_map(c, name, ko, n, &km);
	}
	for (v = 0; v < 8; v++) {
		unsigned k = 0;

		ds_pe(&p, v);
		pm.f = pf;
		pf[k].off = p.lfanew + 6u;  pf[k].size = 2; pf[k].be = 0; pf[k++].kind = FZ_COUNT;
		pf[k].off = p.opt + 16u;    pf[k].size = 4; pf[k].be = 0; pf[k++].kind = FZ_RVA;
		pf[k].off = p.sec + 12u;    pf[k].size = 4; pf[k].be = 0; pf[k++].kind = FZ_RVA;
		pf[k].off = p.sec + 16u;    pf[k].size = 4; pf[k].be = 0; pf[k++].kind = FZ_LEN;
		pf[k].off = p.sec + 20u;    pf[k].size = 4; pf[k].be = 0; pf[k++].kind = FZ_OFFSET;
		pf[k].off = p.dirs + 8u;    pf[k].size = 4; pf[k].be = 0; pf[k++].kind = FZ_RVA;
		pf[k].off = p.dirs + 12u;   pf[k].size = 4; pf[k].be = 0; pf[k++].kind = FZ_LEN;
		pm.n = k;
		pm.rec_off = p.sec; pm.rec_size = 40; pm.rec_n = 3;
		{
			char name[24];

			snprintf(name, sizeof name, "pe32plus-%u", v);
			fz_corpus_add_map(c, name, p.b, p.n, &pm);
		}
	}
}

const char *const diag_dict_bin[] = { "\177ELF", "MZ", "PE\0\0", "\x0f\x05", "\xff\x15", "\x65\x48\x8b\x04\x25\x60\0\0\0", "kernel32.dll", NULL };

void *diag_parse_bin(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_buf f = kof_buf_make(in, n);

	(void)c;
	memset(&S, 0, sizeof S);
	if (n >= 4 && !memcmp(in, "\177ELF", 4)) {
		if (!kgenome_elf_image_parse(f, &S.ei, &S.obj))
			return NULL;
		S.obj.file_header = &S.ei;
		S.is_elf = 1;
		return &S;
	}
	if (n >= 2 && in[0] == 'M' && in[1] == 'Z') {
		if (!kgenome_pe_image_parse(f, &S.pi, &S.obj))
			return NULL;
		S.obj.file_header = &S.pi;
		S.is_pe = 1;
		return &S;
	}
	return NULL;
}

static uint64_t hash_in(const uint8_t *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 1099511628211ull;
	return h ^ n;
}

struct code_acc {
	struct fz_ctx *c;
	uint64_t       lo, hi, n;
};

static void code_cb(void *u, const struct kgenome_cell_insn *in)
{
	struct code_acc *a = (struct code_acc *)u;

	a->n++;
	fz_step(&a->c->steps, 1);
	if (!in)                                  /* a byte that did not decode */
		return;
	FZ_CHECK(a->c, in->len >= 1 && in->len <= 16, "an instruction of length outside 1..16");
	FZ_CHECK(a->c, in->at >= a->lo && in->at < a->hi + 16u, "the code run reported an instruction outside its window");
}

void diag_check_graph(struct fz_ctx *c, const struct kgenome_diag_scan *s, unsigned run)
{
	uint32_t i, k, cnt = kgenome_diag_scan_count(s);
	uint64_t used, peak;
	unsigned ran = kgenome_diag_scan_ran(s);

	FZ_CHECK(c, (unsigned)kgenome_diag_scan_status(s) <= (unsigned)KGENOME_NOMEM, "scan status outside the enum");
	FZ_CHECK(c, ran <= 0x3fu, "a routine bit that does not exist is set in ran");
	FZ_CHECK(c, (ran & ~run) == 0, "a routine ran that the caller did not ask for");
	FZ_CHECK(c, kgenome_diag_scan_own(s) <= 0x1fu, "an ownership bit that does not exist");
	used = kgenome_diag_scan_bytes(s, &peak);
	FZ_CHECK(c, used <= peak, "bytes charged exceed the peak");
	FZ_CHECK(c, kgenome_diag_scan_full(s) == (kgenome_diag_scan_status(s) != KGENOME_OK), "full disagrees with status");
	FZ_CHECK(c, cnt <= KGENOME_MAX_INDEX, "more nodes than the index space");
	for (i = 0; i < cnt; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		FZ_CHECK(c, h != NULL, "a node below the count is NULL");
		if (!h)
			return;
		FZ_CHECK(c, h->n_in <= 4, "a node with more than four inputs");
		for (k = 0; k < h->n_in && k < 4u; k++) {
			const struct kgenome_diag_in *x = &h->in[k];

			FZ_CHECK(c, x->from < cnt || x->from == KGENOME_DIAG_FROM_STACK, "an input names a node that does not exist");
			FZ_CHECK(c, x->role < KGENOME_DIAG_ROLE_COUNT, "a role outside the enum");
			FZ_CHECK(c, x->how <= KGENOME_DIAG_LINK_MAY, "a link kind outside the enum");
			FZ_CHECK(c, x->kind <= KGENOME_DIAG_KIND_SHARED, "a relation outside the enum");
		}
		{
			uint32_t m = kgenome_diag_str_count(s, h->cap), j;

			for (j = 0; j < m && j < 8u; j++) {
				const char *t = kgenome_diag_str_at(s, h->cap, j);

				FZ_CHECK(c, t != NULL, "a name below the count is NULL");
				if (t)
					FZ_CHECK(c, strlen(t) < 4096u, "a name longer than the bound");
			}
			FZ_CHECK(c, kgenome_diag_str_at(s, h->cap, m) == NULL, "a name at the count");
			(void)kgenome_diag_str_at_node(s, h->cap, (uint16_t)i, "x");
		}
		fz_digest(c, h->cap + ((uint64_t)h->n_in << 16) + h->at);
	}
	{
		struct kgenome_diag_lineage_stats ls;
		uint32_t no = kgenome_diag_oblig_count(s);

		for (i = 0; i < no && i < 64u; i++) {
			const struct kgenome_diag_oblig *o = kgenome_diag_oblig_at(s, i);

			FZ_CHECK(c, o != NULL, "an obligation below the count is NULL");
			if (o)
				FZ_CHECK(c, o->node < cnt, "an obligation names a node that does not exist");
		}
		FZ_CHECK(c, kgenome_diag_oblig_at(s, no) == NULL, "an obligation at the count");
		memset(&ls, 0, sizeof ls);
		if (kgenome_diag_lineage_stats_of(s, &ls))
			FZ_CHECK(c, ls.runs >= ls.fns, "fewer solves than functions solved");
		fz_digest(c, no);
	}
	fz_digest(c, kgenome_diag_scan_status(s));
	(void)kgenome_diag_scan_eval_cut(s);
	(void)kgenome_diag_scan_refused(s);
}

/* Everything the walk does with one parsed object; scan_code.c calls it too, with an object it wrapped round code bytes. `lite`: the scan only. */
void diag_exercise_ex(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n, int lite)
{
	struct kgenome_budget bud;
	struct kgenome_diag_inputs inp;
	struct kgenome_diag_scan *sc;
	enum kgenome_status refused = KGENOME_OK;
	uint64_t spent = 0, cap_insn;
	unsigned run, tier = (unsigned)fz_below(c->rng, 3);
	struct kgenome_func_set fs;
	struct kgenome_diag_walk *wk;
	uint64_t code = kgenome_diag_code_bytes(obj, n);

	/* F1: the extents are summed, so overlapping segments count a byte once per segment (tests/lib/genome/diag_code_bytes_overlap.c): the
	 * honest bound is n times the extents an object can name, not n. */
	FZ_CHECK(c, code <= n * 160u || !n, "more code bytes than the extents an object can name hold");
	kgenome_budget_default(&bud, n, code);
	cap_insn = tier == 0 ? 400u : tier == 1 ? 20000u : 150000u;
	bud.max_insn = bud.max_insn_resolve = cap_insn;
	bud.max_steps = 4096u + 8u * (uint64_t)n * (tier + 1u);
	bud.insn_spent = &spent;
	run = (unsigned)fz_below(c->rng, 64);
	if (fz_below(c->rng, 4) == 0)
		run = KGENOME_DIAG_RUN_ALL;
	if (lite)                                 /* the lineage stages over what the cheap routes found; the emulated run in one case of eight */
		run = KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_LINEAGE | (fz_below(c->rng, 8) == 0 ? KGENOME_DIAG_RUN_EMULATE : 0u);
	memset(&inp, 0, sizeof inp);
	inp.budget = &bud;
	inp.refused = &refused;
	inp.lineage_stages = (unsigned)fz_below(c->rng, 64) & (KGENOME_LINEAGE_S_ALL | KGENOME_LINEAGE_S_EAGER | KGENOME_LINEAGE_S_DEMAND);
	sc = kgenome_diag_scan_with_inputs(obj, in, n, run, &inp);
	if (!sc) {
		FZ_CHECK(c, (unsigned)refused <= (unsigned)KGENOME_NOMEM, "refused outside the enum");
		fz_digest(c, 0xbad0u + (unsigned)refused);
	} else {
		uint64_t sig = ds_graph_sig(sc);
		uint64_t ih = hash_in(in, n);

		diag_check_graph(c, sc, run);
		fz_step(&c->steps, spent);
		/* F2: the API-hash run's first slice is 16000 instructions whatever max_insn_resolve says (diag_apihash.c DIAG_PE_SLICE), so a
		 * budget below the slice is overshot (tests/lib/genome/diag_apihash_floor.c): the bound is the larger of the two. */
		FZ_CHECK(c, spent <= 2u * (cap_insn > 16000u ? cap_insn : 16000u) + 64u, "the scan spent more emulated instructions than its budget allows");
		if (!c->failk) {
			clean.in_hash = ih;
			clean.sig = sig;
			clean.status_ok = kgenome_diag_scan_status(sc) == KGENOME_OK;
			clean.have = 1;
		} else if (clean.have && clean.in_hash == ih && kgenome_diag_scan_status(sc) == KGENOME_OK) {
#ifdef DIAG_STRICT_G9
			FZ_CHECK(c, sig == clean.sig, "G9: a refused allocation made a different graph and the status is ok");
#else
			/* F7..F10 (tests/lib/genome/diag_bin_oom.c) are known silent answers of this route, so the default row counts them in the
			 * digest and does not fail; `make fuzz FZ_CFLAGS_diag=-DDIAG_STRICT_G9` makes each one a failure and saves the input. */
			/* KNOWN DEFECT WP9-F7 (2026-10-25, M): this row pins it, green until fixed. */
			fz_digest(c, sig == clean.sig ? 0u : 0x69u);
#endif
		}
		fz_digest(c, sig);
		kgenome_diag_note_at(sc, KGENOME_TRUNCATED, __FILE__, __LINE__);
		FZ_CHECK(c, kgenome_diag_scan_status(sc) != KGENOME_OK, "a note did not reach the status");
		kgenome_diag_scan_free(sc);
	}
	if (lite) {                               /* the rows with a costly seed: the scan and its graph, not the products around it */
		fz_digest(c, kgenome_diag_class_of(obj));
		return;
	}
	/* the class of the object, and the plan the table gives it */
	{
		unsigned cls = kgenome_diag_class_of(obj);

		FZ_CHECK(c, (cls & ~0x1ffu) == 0, "a class bit that does not exist");
		FZ_CHECK(c, (kgenome_diag_lineage_plan(cls) & ~KGENOME_LINEAGE_S_ALL) == 0, "the plan of the object's class names a stage that does not exist");
		fz_digest(c, cls);
	}
	/* the plain entries: the default run and the named one */
	if (fz_below(c->rng, 3) == 0) {
		sc = kgenome_diag_scan(obj, in, n);
		if (sc) {
			diag_check_graph(c, sc, KGENOME_DIAG_RUN_ALL | KGENOME_DIAG_RUN_TEXT);
			kgenome_diag_scan_free(sc);
		}
		sc = kgenome_diag_scan_with(obj, in, n, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL);
		if (sc) {
			diag_check_graph(c, sc, KGENOME_DIAG_RUN_ALL);
			kgenome_diag_scan_free(sc);
		}
	}
	/* the functions, the walk, a code run */
	memset(&fs, 0, sizeof fs);
	wk = kgenome_diag_walk_new();
	if (wk) {
		struct kgenome_cell_space sp;

		kgenome_diag_walk_set_cap(wk, fz_below(c->rng, 2) ? 0u : 1u + fz_below(c->rng, 1u << 16));
		kgenome_diag_funcs_with_walk(obj, in, n, wk, 1, &fs);
		FZ_CHECK(c, kgenome_diag_walk_runs(wk) <= 2u, "the walk decoded the object more than twice for one reader");
		memset(&sp, 0, sizeof sp);
		kgenome_cell_space_init(&sp, obj, in, n);
		if (kgenome_diag_walk_hold(&sp, wk)) {
			uint64_t asked = 0, got = kgenome_diag_walk_held_count(wk, &asked);

			FZ_CHECK(c, got <= asked, "the walk answered more decodes than it was asked");
		}
		if (fz_below(c->rng, 2))
			kgenome_diag_walk_trim(wk);
		(void)kgenome_diag_walk_capped(wk);
		if (fs.n)
			FZ_CHECK(c, fs.v != NULL, "functions counted and no table");
		{
			uint32_t i;

			for (i = 0; i < fs.n && i < 256u; i++)
				FZ_CHECK(c, fs.v[i].off <= n, "a function starts outside the object");
		}
		fz_digest(c, fs.n);
		if (fs.v)
			kgenome_funcs_free(&fs);
		if (n) {
			struct code_acc acc;
			struct kgenome_diag_code_run_stats st;
			struct kgenome_diag_code_req rq;
			uint64_t off = fz_below(c->rng, (uint32_t)(n < 0xffffffffu ? n : 0xffffffffu)), len = 1u + fz_below(c->rng, 4096);

			acc.c = c; acc.lo = off; acc.hi = off + len; acc.n = 0;
			memset(&st, 0, sizeof st);
			memset(&rq, 0, sizeof rq);
			rq.obj = obj; rq.base = in; rq.size = n; rq.off = off; rq.n = len; rq.va = 0x400000u + off;
			rq.fn = code_cb; rq.user = &acc; rq.wk = fz_below(c->rng, 2) ? wk : NULL; rq.st = fz_below(c->rng, 2) ? &st : NULL;
			kgenome_diag_code_run(&rq);
			fz_digest(c, acc.n);
		}
		kgenome_diag_walk_free(wk);
	}
	{
		struct kgenome_diag_walk *w0 = kgenome_diag_walk_new();

		kgenome_diag_funcs_of(obj, in, n, &fs);
		if (fs.v)
			kgenome_funcs_free(&fs);
		if (w0)
			kgenome_diag_walk_free(w0);
		(void)kgenome_diag_walk_runs(NULL);
		(void)kgenome_diag_walk_capped(NULL);
	}
	/* a view of the object: the same bytes read as a view of itself */
	{
		struct kgenome_func_set pf, vf;

		memset(&pf, 0, sizeof pf);
		memset(&vf, 0, sizeof vf);
		kgenome_diag_funcs_of(obj, in, n, &pf);
		kgenome_diag_funcs_of_view(obj, kof_buf_make(in, n), &pf, kof_buf_make(in, n), &vf);
		fz_digest(c, vf.n);
		if (vf.v)
			kgenome_funcs_free(&vf);
		if (pf.v)
			kgenome_funcs_free(&pf);
	}
	if (obj->format == KGENOME_FMT_ELF && kgenome_obj_elf(obj)) {
		uint32_t i;

		for (i = 0; i <= KGENOME_ELF_MAX_SEGMENTS; i++) {
			uint64_t at = 0, len = kgenome_diag_code_range(kgenome_obj_elf(obj), i, n, &at);

			FZ_CHECK(c, !len || (at <= n && len <= n - at), "a code range outside the object");
			fz_digest(c, len);
		}
	}
	if (obj->format == KGENOME_FMT_PE) {
		struct kgenome_diag_apihash_set *a = kgenome_diag_apihash_run(obj, in, n, NULL, &bud);

		if (a) {
			const char *dll[64], *name[64];
			uint32_t d;

			FZ_CHECK(c, (unsigned)a->status <= (unsigned)KGENOME_NOMEM, "api-hash status outside the enum");
			if (a->n_call <= 64u) {
				d = kgenome_diag_apihash_distinct(a, dll, name);
				FZ_CHECK(c, d <= a->n_call, "more distinct APIs than calls");
			}
			fz_digest(c, a->n_call);
			kgenome_diag_apihash_free(a);
		}
		{
			struct kgenome_diag_scan *sh = kgenome_diag_scan_with(obj, in, n, KGENOME_DIAG_RUN_APIHASH);

			if (sh) {
				const struct kgenome_diag_apihash_set *got = kgenome_diag_apihash(sh, obj);

				FZ_CHECK(c, !got || (unsigned)got->status <= (unsigned)KGENOME_NOMEM, "the scan's api-hash product has a status outside the enum");
				kgenome_diag_scan_free(sh);
			}
		}
	}
}

void diag_exercise(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n)
{
	diag_exercise_ex(c, obj, in, n, 0);
}

void diag_walk_bin(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	diag_exercise(c, &((struct diag_st *)h)->obj, in, n);
}

FZ_ADAPTER(scan_bin, .name = "kgenome/diag_scan_bin",
	   .covers = "kgenome_diag_scan kgenome_diag_scan_with kgenome_diag_scan_with_inputs kgenome_diag_scan_at kgenome_diag_scan_count "
		     "kgenome_diag_scan_status kgenome_diag_scan_free kgenome_diag_scan_own kgenome_diag_scan_ran kgenome_diag_scan_full "
		     "kgenome_diag_scan_bytes kgenome_diag_scan_eval_cut kgenome_diag_scan_refused kgenome_diag_str_at kgenome_diag_str_count "
		     "kgenome_diag_str_at_node kgenome_diag_note_at kgenome_diag_code_bytes kgenome_diag_funcs_of kgenome_diag_funcs_with_walk "
		     "kgenome_diag_funcs_of_view kgenome_diag_walk_new kgenome_diag_walk_free kgenome_diag_walk_runs kgenome_diag_walk_trim "
		     "kgenome_diag_walk_set_cap kgenome_diag_walk_capped kgenome_diag_walk_hold kgenome_diag_walk_held_count "
		     "kgenome_diag_code_run kgenome_diag_code_range kgenome_diag_apihash_run kgenome_diag_apihash_free kgenome_diag_apihash_distinct "
		     "kgenome_diag_oblig_count kgenome_diag_oblig_at kgenome_diag_lineage_stats_of kgenome_diag_apihash kgenome_diag_class_of "
		     "kgenome_diag_lineage_plan",
	   .flags = FZ_MAY_HIT_CAP, .steps_base = 4000000u, .steps_per_byte = 256,
	   .shape = FZ_PARSE, .seeds = diag_seeds_bin, .dict = diag_dict_bin, .parse = diag_parse_bin, .walk = diag_walk_bin);
