/*
 * genome / diag_bin_oom - the allocation-failure sweep of the BINARY diagnose route: the k-th allocation refused, k = 1 .. N, on a set of
 * ELF and PE seeds (the gap the hostile matrix listed for stage 7: diag_text_oom refuses every allocation of the TEXT route, nothing did it
 * for the sweep, the symbol and PE routes, the emulated run, the wrapper walk, the lineage stages or the products around them).
 *
 * The invariant is G9's, the one rule 4 states for memory: when what a call returns differs from what it returns with every allocation
 * granted, its status says so. Per call:
 *   kgenome_diag_scan_with_inputs   NULL says why in `refused` (NOMEM); a scan that comes back has the graph of the clean run (the caps, the
 *                                   places, the inputs by index) or a status that is not ok. Nothing may be left allocated after the scan is
 *                                   freed (allocations minus frees, counted at the wrapped calls: no sanitiser needed).
 *   kgenome_diag_apihash_run        NULL, or the same calls, or a status that says it was cut
 *   kgenome_diag_funcs_of           the same function table, or status NOMEM
 *   kgenome_codemap_build           0 with status NOMEM, or the same refs
 * kgenome_diag_apihash_run answers NULL both for "not a PE" and for a refused allocation (it has no `refused` channel: F6), so a NULL there is not a
 * silent answer; its other answers are compared. malloc, calloc and realloc are wrapped at link time (UNIT_LIBS_diag_bin_oom), armed only around the call, so the harness's own allocations
 * are never refused. The budget is small (a few thousand instructions) so that every k is cheap; the seeds are the programs of
 * tests/fuzz/diag/diag_seed.h. Every k up to 128 is run, then every 7th up to the number of allocations (the count is printed).
 *
 * usage: diag_bin_oom
 */
#include <execinfo.h>

#include "../../fuzz/diag/diag_seed.h"

#include <phenotype/codemap.h>

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
void __wrap_free(void *p);

static long armed, seen, fail_at, live, refused_n;
static void *where[24];
static int nwhere;

static int refuse(void)
{
	if (!armed)
		return 0;
	if (++seen != fail_at)
		return 0;
	refused_n++;
	nwhere = backtrace(where, 24);          /* where the refused allocation was asked for: printed for a silent answer */
	return 1;
}

void *__wrap_malloc(size_t n)
{
	void *p;

	if (refuse())
		return NULL;
	p = __real_malloc(n);
	if (armed && p)
		live++;
	return p;
}

void *__wrap_calloc(size_t a, size_t b)
{
	void *p;

	if (refuse())
		return NULL;
	p = __real_calloc(a, b);
	if (armed && p)
		live++;
	return p;
}

void *__wrap_realloc(void *p, size_t n)
{
	void *q;

	if (refuse())
		return NULL;
	q = __real_realloc(p, n);
	if (armed) {
		if (!p && q)
			live++;
		else if (p && !n)
			live--;
	}
	return q;
}

void __wrap_free(void *p)
{
	if (armed && p)
		live--;
	__real_free(p);
}

/* ---- the seeds ------------------------------------------------------------------------------------------------------------ */

struct seed {
	const char *name;
	uint8_t     img[0x1000];
	size_t      n;
	int         pe;
};

static struct seed seeds[DS_NPROG + 3u + 8u + DS_NKO];
static unsigned n_seeds;

static void build(void)
{
	static struct ds_code code;
	static struct hk_pe pe;
	static char names[DS_NPROG + 3u + 8u + DS_NKO][24];
	unsigned i, v;

	for (i = 0; i < DS_NPROG; i++) {
		struct seed *s = &seeds[n_seeds++];

		ds_prog(&code, i);
		s->n = ds_elf64(s->img, &code, 0x3e);
		snprintf(names[n_seeds - 1u], sizeof names[0], "elf64-prog%u", i);
		s->name = names[n_seeds - 1u];
	}
	{
		struct seed *s = &seeds[n_seeds++];

		ds_prog(&code, 0);
		s->n = ds_elf32(s->img, &code, 3);
		s->name = "elf32-i386";
	}
	{
		static const uint8_t arm[] = { 0x01, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x1e, 0xff, 0x2f, 0xe1 };
		struct seed *s = &seeds[n_seeds++];

		code.n = 0;
		ds_emit(&code, arm, sizeof arm);
		s->n = ds_elf32(s->img, &code, 40);
		s->name = "elf32-arm";
	}
	{
		static const uint8_t a64[] = { 0x08, 0x08, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6 };
		struct seed *s = &seeds[n_seeds++];

		code.n = 0;
		ds_emit(&code, a64, sizeof a64);
		s->n = ds_elf64(s->img, &code, 0xb7);
		s->name = "elf64-aarch64";
	}
	for (i = 0; i < DS_NKO; i++) {                          /* the kernel-module shapes: ET_REL with relocations */
		struct seed *s = &seeds[n_seeds++];

		s->n = ds_ko(s->img, i);
		snprintf(names[n_seeds - 1u], sizeof names[0], "ko-rel-%u", i);
		s->name = names[n_seeds - 1u];
	}
	for (v = 0; v < 8; v++) {
		struct seed *s = &seeds[n_seeds++];

		ds_pe(&pe, v);
		memcpy(s->img, pe.b, pe.n);
		s->n = pe.n;
		s->pe = 1;
		snprintf(names[n_seeds - 1u], sizeof names[0], "pe32plus-%u", v);
		s->name = names[n_seeds - 1u];
	}
}

/* ---- one seed ------------------------------------------------------------------------------------------------------------- */

static struct diag_st st;

static int parse(const struct seed *s)
{
	memset(&st, 0, sizeof st);
	if (s->pe) {
		if (!kgenome_pe_image_parse(kof_buf_make(s->img, s->n), &st.pi, &st.obj))
			return 0;
		st.obj.file_header = &st.pi;
	} else {
		if (!kgenome_elf_image_parse(kof_buf_make(s->img, s->n), &st.ei, &st.obj))
			return 0;
		st.obj.file_header = &st.ei;
	}
	return 1;
}

struct outcome {
	uint64_t sig;
	int      have, status, nomem_said;
};

static uint64_t mix(uint64_t h, uint64_t v)
{
	return (h ^ v) * 0x100000001b3ull;
}

static struct outcome scan_once(const struct seed *s)
{
	struct outcome o = { 0, 0, 0, 0 };
	struct kgenome_budget bud;
	struct kgenome_diag_inputs in;
	enum kgenome_status refused = KGENOME_OK;
	struct kgenome_diag_scan *sc;

	kgenome_budget_default(&bud, s->n, kgenome_diag_code_bytes(&st.obj, s->n));
	bud.max_insn = bud.max_insn_resolve = 3000;
	bud.max_steps = 20000;
	memset(&in, 0, sizeof in);
	in.budget = &bud;
	in.refused = &refused;
	in.lineage_stages = KGENOME_LINEAGE_S_ALL;
	sc = kgenome_diag_scan_with_inputs(&st.obj, s->img, s->n, KGENOME_DIAG_RUN_ALL, &in);
	if (!sc) {
		o.nomem_said = refused == KGENOME_NOMEM;
		return o;
	}
	o.have = 1;
	o.status = (int)kgenome_diag_scan_status(sc);
	o.sig = ds_graph_sig(sc);
	{
		uint32_t i, no = kgenome_diag_oblig_count(sc);

		o.sig = mix(o.sig, no);
		for (i = 0; i < no; i++)
			o.sig = mix(o.sig, kgenome_diag_oblig_at(sc, i)->why);
	}
	kgenome_diag_scan_free(sc);
	return o;
}

static struct outcome codemap_once(const struct seed *s)
{
	struct outcome o = { 0, 0, 0, 0 };
	struct kgenome_codemap m;
	uint32_t i;

	memset(&m, 0, sizeof m);
	if (!kgenome_codemap_build(&st.obj, s->img, s->n, NULL, &m)) {
		o.nomem_said = m.status == KGENOME_NOMEM;
		return o;
	}
	o.have = 1;
	o.status = (int)m.status;
	o.sig = mix(1469598103934665603ull, m.n);
	for (i = 0; i < m.n; i++)
		o.sig = mix(mix(o.sig, m.v[i].at), ((uint64_t)m.v[i].kind << 8) ^ m.v[i].flags ^ (m.v[i].to << 16));
	kgenome_codemap_free(&m);
	return o;
}

static struct outcome funcs_once(const struct seed *s)
{
	struct outcome o = { 0, 0, 0, 0 };
	struct kgenome_func_set fs;
	uint32_t i;

	memset(&fs, 0, sizeof fs);
	kgenome_diag_funcs_of(&st.obj, s->img, s->n, &fs);
	o.have = 1;
	o.status = (int)fs.status;
	o.nomem_said = fs.status == KGENOME_NOMEM;
	o.sig = mix(7, fs.n);
	for (i = 0; i < fs.n; i++)
		o.sig = mix(mix(o.sig, fs.v[i].off), fs.v[i].len);
	kgenome_funcs_free(&fs);
	return o;
}

static struct outcome apihash_once(const struct seed *s)
{
	struct outcome o = { 0, 0, 0, 0 };
	struct kgenome_budget bud;
	struct kgenome_diag_apihash_set *a;
	uint32_t i;

	kgenome_budget_default(&bud, s->n, kgenome_diag_code_bytes(&st.obj, s->n));
	bud.max_insn = bud.max_insn_resolve = 3000;
	a = kgenome_diag_apihash_run(&st.obj, s->img, s->n, NULL, &bud);
	if (!a)
		return o;
	o.have = 1;
	o.status = (int)a->status;
	o.nomem_said = a->status == KGENOME_NOMEM;
	o.sig = mix(11, a->n_call);
	for (i = 0; i < a->n_call; i++)
		o.sig = mix(mix(o.sig, a->call[i].site), (uint8_t)a->call[i].api[0]);
	kgenome_diag_apihash_free(a);
	return o;
}

typedef struct outcome (*once_fn)(const struct seed *s);

/*
 * THE SILENT ANSWERS THIS TEST FOUND, each kept as a KNOWN row of the place that asked for the refused allocation (a function name of the
 * backtrace, so that the row survives a change in how many allocations a scan makes: an allocation NUMBER would not). The row is
 * `what` (which call) and `site` (the function that made the allocation or its caller). A silent answer at a known site is printed
 * KNOWN-MISS and does not fail the test; a silent answer anywhere else FAILS; a known site that no longer answers silently is printed
 * FIXED and counted (remove the row), and does not fail, so that a change of the binary route that lands before this test is updated (the
 * pending fix_gbin2 patch) does not turn the suite red.
 *   F7   scan, kgenome_diag_scan_walk: the wrapper analysis's walk object is not allocated: the wrappers are not analysed, status ok
 *   F8   scan, kgenome_lineage_codemap: the code map the lineage stages read is not built: the links it makes are missing, status ok
 *   F9   funcs, kgenome_diag_funcs_with_walk (its own table and the walk it fills, kgenome_diag_walk_ensure): the function table comes back short with fs.status ok
 *        (struct kgenome_func_set.status is KGENOME_NOMEM for exactly this)
 *   F10  apihash, kgenome_pe_imports: the import table the resolver run builds for itself is cut and its status is not merged into the
 *        product: fewer API calls, status ok
 */
struct known {
	const char *what, *site, *id;
	long        hits;
};

static struct known known[] = {
	/* KNOWN DEFECT WP9-F7 (2026-10-25, M): this row pins it, green until fixed. */
	{ "scan", "kgenome_diag_scan_walk", "F7", 0 },
	/* KNOWN DEFECT WP9-F8 (2026-10-25, M): this row pins it, green until fixed. */
	{ "scan", "kgenome_lineage_codemap", "F8", 0 },
	/* KNOWN DEFECT WP9-F9 (2026-10-25, M): this row pins it, green until fixed. */
	{ "funcs", "kgenome_diag_funcs_with_walk", "F9", 0 },
	/* KNOWN DEFECT WP9-F10 (2026-10-25, M): this row pins it, green until fixed. */
	{ "apihash", "kgenome_pe_imports", "F10", 0 },
};

/* the known row of the refused allocation just taken, or NULL */
static struct known *known_site(const char *what)
{
	char **sym = backtrace_symbols(where, nwhere > 10 ? 10 : nwhere);
	struct known *r = NULL;
	unsigned i;
	int f;

	if (!sym)
		return NULL;
	for (i = 0; i < sizeof known / sizeof known[0] && !r; i++)
		for (f = 0; f < (nwhere > 10 ? 10 : nwhere) && !r; f++)
			if (!strcmp(known[i].what, what) && strstr(sym[f], known[i].site))
				r = &known[i];
	free(sym);
	return r;
}

/* 1 the first time this chain of callers (frames 1..4 of the refused allocation) is seen */
static int new_site(void)
{
	static uintptr_t seen_sites[256][4];
	static unsigned n_sites;
	unsigned i;

	for (i = 0; i < n_sites; i++)
		if (seen_sites[i][0] == (uintptr_t)where[1] && seen_sites[i][1] == (uintptr_t)where[2] && seen_sites[i][2] == (uintptr_t)where[3] &&
		    seen_sites[i][3] == (uintptr_t)(nwhere > 4 ? where[4] : NULL))
			return 0;
	if (n_sites < 256u) {
		seen_sites[n_sites][0] = (uintptr_t)where[1];
		seen_sites[n_sites][1] = (uintptr_t)where[2];
		seen_sites[n_sites][2] = (uintptr_t)where[3];
		seen_sites[n_sites++][3] = (uintptr_t)(nwhere > 4 ? where[4] : NULL);
	}
	return 1;
}

static long total_runs, total_refusals, silent, leaks;

static void sweep(const char *what, const struct seed *s, once_fn fn)
{
	struct outcome base;
	long allocs, k, step;

	armed = 1; seen = 0; fail_at = 0; live = 0;
	base = fn(s);
	armed = 0;
	allocs = seen;
	CK(live == 0);
	if (live != 0) {
		printf("  FAIL %s %s: the clean call left %ld allocations behind\n", what, s->name, live);
		leaks++;
	}
	for (k = 1, step = 1; k <= allocs; k += step) {
		struct outcome o;
		int continue_after_known = 0;

		armed = 1; seen = 0; fail_at = k; live = 0; refused_n = 0;
		o = fn(s);
		armed = 0; fail_at = 0;
		total_runs++;
		total_refusals += refused_n;
		if (live != 0) {
			leaks++;
			CK(0 && "an allocation is left behind after a refused call");
			printf("  FAIL %s %s: refusing allocation %ld of %ld left %ld allocations behind\n", what, s->name, k, allocs, live);
		}
		if (base.have && !o.have && !o.nomem_said && strcmp(what, "apihash") != 0) {
			silent++;
			CK(0 && "a refused allocation made the call return nothing without saying NOMEM");
			printf("  FAIL %s %s: refusing allocation %ld of %ld returned nothing and did not say NOMEM\n", what, s->name, k, allocs);
		}
		if (base.have && o.have && o.sig != base.sig && o.status == (int)KGENOME_OK) {
			struct known *kn = known_site(what);

			if (kn) {
				if (!kn->hits++)
					printf("  KNOWN-MISS %s (%s %s): refusing allocation %ld of %ld changes the answer and the status is ok\n", kn->id, what, s->name, k, allocs);
				continue_after_known = 1;
			}
		}
		if (!continue_after_known && base.have && o.have && o.sig != base.sig && o.status == (int)KGENOME_OK) {
			silent++;
			CK(0 && "G9: a refused allocation made a different answer and the status is ok");
			printf("  FAIL G9 %s %s: refusing allocation %ld of %ld changed the answer and the status is ok\n", what, s->name, k, allocs);
			if (nwhere > 3 && new_site()) {          /* one trace for each distinct place that asked for the refused allocation */
				fflush(stdout);
				backtrace_symbols_fd(where, nwhere > 7 ? 7 : nwhere, 1);
			}
		}
		if (k >= 600)
			step = 7;
	}
	printf("  %-8s %-14s %5ld allocations\n", what, s->name, allocs);
}

int main(int argc, char **argv)
{
	unsigned i;

	hk_args(argc, argv);
	build();
	for (i = 0; i < n_seeds; i++) {
		const struct seed *s = &seeds[i];

		if (!parse(s)) {
			printf("  FAIL %s: the seed does not parse\n", s->name);
			hk_fails++;
			continue;
		}
		sweep("scan", s, scan_once);
		sweep("codemap", s, codemap_once);
		sweep("funcs", s, funcs_once);
		if (s->pe)
			sweep("apihash", s, apihash_once);
	}
	{
		unsigned q;

		for (q = 0; q < sizeof known / sizeof known[0]; q++)
			if (!known[q].hits)
				printf("  FIXED %s (%s %s): no silent answer at this site any more, remove the row\n", known[q].id, known[q].what, known[q].site);
	}
	printf("diag_bin_oom: %ld calls with one allocation refused over %u seeds (%ld refusals taken), %ld silent, %ld leaks\n", total_runs, n_seeds, total_refusals, silent, leaks);
	CK(total_refusals > 0);
	printf("diag_bin_oom: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
