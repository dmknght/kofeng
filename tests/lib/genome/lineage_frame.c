/*
 * lineage_frame - THE LINEAGE READS THE FRAME (phenotype/frame.h) THE SIGNING MADE, and the table of functions the engine holds.
 *
 * The lineage built its own graph of every function it solved (`.be = 0`, a block rule of its own) and found its own functions. It now reads the function's frame from the
 * object's cache and the engine's function table. What is pinned, over the generator's programs on four targets (ELF x86-64 and i386, PE x64 and x86), with symbols and stripped:
 *   SAME_LINKS   the links the lineage finds are the same whether the scan makes its own frames, is handed a cache that already holds the frame of every function of the table (as the signing
 *                leaves it), or is handed an empty one: one product, three ways to reach it
 *   BUILT_ONCE   a scan that is handed the full cache builds no frame of a table function (it only reads them); one handed an empty cache builds each function at most once, however many
 *                times the lineage solves it (a function is solved again when its obligations ask for another stage), and the cache holds what it says
 *   TABLE        the scan reads the table it is handed (`kgenome_diag_inputs.funcs`) and nothing else: entries the stage cannot read (no length, past the object) are skipped and change no
 *                link; the PE reads its table like the ELF (the completion of the lineage's own is gone)
 *   HOSTILE      a byte of every 61st poisoned in the image, and a memory allowance from 1 byte up in steps: no crash, a status said, the links the allowance leaves are a subset of the full ones
 * RED: the base has no `kgenome_diag_inputs.frames` and builds a graph per solve; this file does not compile there. The rows that stay red on a partial change are SAME_LINKS (a frame
 * built with another byte order or block rule than the one the solve reads would change a link) and BUILT_ONCE (a cache that is not asked, or asked twice).
 * Why the old tests missed it: (a) the lineage's graph was a private of the solve, so nothing could hand it another; (b) the lineage tests compare links to an oracle, never two
 * routes to the same product; (c) no test counted builds.
 */
#include "lineage_check.h"

/* The allocators are wrapped at link time (UNIT_LIBS_lineage_frame in mk/tests.mk), armed only around the scan: the k-th allocation of the scan is refused, for every k. */
void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
static int armed;
static unsigned long alloc_seen, fail_k;

/* kgenome_cell_decode is wrapped too: how many times each offset of the image is decoded during one scan (the scan makes the object's walk, and every reader after it reads the walk's trace). */
uint32_t __real_kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out);
uint32_t __wrap_kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out);
static const uint8_t *dec_base;
static uint64_t dec_n;
static uint16_t *dec_at;

uint32_t __wrap_kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out)
{
	const uint32_t len = __real_kgenome_cell_decode(arch, be, p, n, va, out);

	if (len && dec_at && p >= dec_base && (uint64_t)(p - dec_base) < dec_n && dec_at[p - dec_base] < 0xffffu)
		dec_at[p - dec_base]++;
	return len;
}
static unsigned dec_max;                /* the most times one offset was decoded in the last scan */

static int refuse(void)
{
	return armed && ++alloc_seen == fail_k;
}

void *__wrap_malloc(size_t n) { return refuse() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b) { return refuse() ? NULL : __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n) { return refuse() ? NULL : __real_realloc(p, n); }

#include <phenotype/frame.h>

struct run_out {
	struct lg_links links;
	uint32_t built, hits, n_table;
	unsigned dec_max;                                       /* the most times one offset was decoded (how 0) */
	enum kgenome_status status;
};

/* One scan of `g` with the symbol route and the lineage, `how`: 0 the scan's own frames, 1 a cache already holding every function's frame, 2 an empty cache, 3 a table with entries the stage
 * cannot read added (a length of 0, an offset past the object, a start inside the headers), 4 a memory allowance of `budget` bytes, 5 and 6 the scan with the k-th allocation refused (5 with
 * the table and an empty cache, 6 with neither: the frames are the lineage's own, through its allocator, 8 with a cache that already holds every frame: the facts memo is made in the scan). */
static int scan_one(const struct lg_img *g, int target, unsigned stages, int how, uint64_t budget, struct run_out *out)
{
	struct kgenome_elf_info ei;
	struct kgenome_pe_info pi;
	struct kgenome_obj obj;
	struct kgenome_diag_inputs in;
	struct kgenome_diag_scan *s;
	struct kgenome_func_set fs;
	struct kgenome_frame_cache *cache = NULL;
	struct kgenome_frame_src src;
	struct kgenome_budget kb;
	const int pe = target == LG_T_PE64 || target == LG_T_PE32;
	struct lg_scan sc;
	uint32_t i, built0 = 0;

	memset(out, 0, sizeof *out);
	memset(&fs, 0, sizeof fs);
	if (pe) {
		if (!kgenome_pe_image_parse(kof_buf_make(g->b, g->n), &pi, &obj))
			return 0;
		obj.file_header = &pi;
	} else {
		if (!kgenome_elf_image_parse(kof_buf_make(g->b, g->n), &ei, &obj))
			return 0;
		obj.file_header = &ei;
	}
	memset(&in, 0, sizeof in);
	in.lineage_stages = stages;
	if (how == 4) {
		kgenome_budget_default(&kb, g->n, g->n);
		kb.max_bytes = budget;
		in.budget = &kb;
	}
	if (how && how != 4 && how != 6) {
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();

		kgenome_diag_funcs_with_walk(&obj, g->b, g->n, wk, &fs);
		kgenome_diag_walk_free(wk);
		if (how == 3 && fs.n) {
			struct kgenome_func *nv = calloc((size_t)fs.n + 3u, sizeof *nv);
			const struct kgenome_func *last = &fs.v[fs.n - 1u];

			memcpy(nv + 1, fs.v, (size_t)fs.n * sizeof *nv);
			nv[0].off = 1;
			nv[0].len = 2;                                     /* inside the headers */
			nv[fs.n + 1u].off = last->off + last->len;         /* a length of 0, after everything */
			nv[fs.n + 2u].off = g->n + 100u;                   /* past the object */
			nv[fs.n + 2u].len = 8;
			free(fs.v);
			fs.v = nv;
			fs.n += 3u;
		}
		cache = kgenome_frame_cache_new(NULL, 0);
		memset(&src, 0, sizeof src);
		src.obj = &obj; src.base = g->b; src.size = g->n; src.fs = &fs;
		if (how == 1 || how == 8)                           /* (8: the same cache, with an allocation refused in the scan: the facts memo of a frame the signing made is allocated there) */
			for (i = 0; i < fs.n; i++)
				(void)kgenome_frame_get(cache, &src, i);
		if (how == 7)                                       /* every frame of the cache made from a decode one instruction short of the function's: not this function's frame */
			for (i = 0; i < fs.n; i++) {
				struct kgenome_frame whole;

				if (kgenome_frame_make(&src, fs.v[i].off, fs.v[i].len, KGENOME_FRAME_KEEP_INSN, &whole) == KGENOME_FRAME_OK && whole.n_insn > 1u) {
					struct kgenome_frame_insns pre = { .v = whole.in, .n = whole.n_insn - 1u, .skipped = 0, .off = fs.v[i].off, .len = fs.v[i].len };
					struct kgenome_frame_src sp = src;

					sp.pre = &pre;
					(void)kgenome_frame_get(cache, &sp, i);
				}
				kgenome_frame_release(&whole, NULL);
			}
		built0 = kgenome_frame_cache_built(cache);
		in.funcs = &fs;
		in.frames = cache;
	}
	alloc_seen = 0;
	armed = how == 5 || how == 6 || how == 8;
	if (how == 0) {
		dec_base = g->b;
		dec_n = g->n;
		dec_at = calloc((size_t)g->n, sizeof *dec_at);
	}
	s = kgenome_diag_scan_with_inputs(&obj, g->b, g->n, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE, &in);
	armed = 0;
	if (dec_at) {
		uint64_t q;

		dec_max = 0;
		for (q = 0; q < dec_n; q++)
			dec_max = dec_at[q] > dec_max ? dec_at[q] : dec_max;
		free(dec_at);
		dec_at = NULL;
	}
	if (!s) {
		kgenome_frame_cache_free(cache);
		kgenome_funcs_free(&fs);
		return 0;
	}
	sc.s = s;
	lg_actual(&out->links, &sc);
	out->status = kgenome_diag_scan_status(s);
	out->dec_max = dec_max;
	out->n_table = fs.n;
	if (cache) {
		out->built = kgenome_frame_cache_built(cache) - built0;
		out->hits = kgenome_frame_cache_hits(cache);
	}
	kgenome_diag_scan_free(s);
	kgenome_frame_cache_free(cache);
	kgenome_funcs_free(&fs);
	return 1;
}

static int same_links(const struct lg_links *a, const struct lg_links *b)
{
	struct lg_links x = *a, y = *b;
	int i;

	if (x.n != y.n)
		return 0;
	qsort(x.v, (size_t)x.n, sizeof x.v[0], lg_link_cmp);
	qsort(y.v, (size_t)y.n, sizeof y.v[0], lg_link_cmp);
	for (i = 0; i < x.n; i++)
		if (lg_link_cmp(&x.v[i], &y.v[i]))
			return 0;
	return 1;
}

static long n_scans, n_links, n_hits, n_built_empty, n_bogus, n_budget, n_poison, n_oom, n_oom_null, n_badframe;
static int swept[8];
static unsigned worst_dec[8];

static int one(void *user, const struct lg_prog *p, const struct lg_cg *c, const struct lg_img *g, const struct lg_oracle *o, int target, int strip, uint64_t seed)
{
	static struct run_out a, b, e;
	const unsigned stages = *(const unsigned *)user;

	(void)p; (void)c; (void)o;
	if (!scan_one(g, target, stages, 0, 0, &a) || !scan_one(g, target, stages, 1, 0, &b) || !scan_one(g, target, stages, 2, 0, &e))
		return 0;
	n_scans++;
	n_links += a.links.n;
	if (a.dec_max > worst_dec[target & 7])
		worst_dec[target & 7] = a.dec_max;
	/* THE CODE IS DECODED ONCE: the stub of a PE x86 was read by decoding the head of every function again (thunk_slot), the PE route read every section again, a frame the lineage asked for was
	 * decoded from the bytes: one scan decodes an offset at most once (the walk), and every later reader reads its trace. RED on the base: 2 on the PE targets. */
	CK(a.dec_max <= 1u);
	if (!same_links(&a.links, &b.links) || !same_links(&a.links, &e.links)) {
		printf("  seed %llu %s%s: the links differ with the frames the scan made (%d), a full cache (%d), an empty one (%d)\n", (unsigned long long)seed,
		       lg_target_name(target), strip ? " stripped" : "", a.links.n, b.links.n, e.links.n);
		return 1;
	}
	CK(b.built == 0u);                                      /* a cache that already holds every table function builds none: the lineage only reads them */
	n_hits += b.hits;
	CK(e.built <= e.n_table);                               /* each function is made at most once, however often it is solved */
	n_built_empty += e.built;
	/* TABLE: entries the stage cannot read are skipped and change nothing */
	{
		static struct run_out t;

		if (scan_one(g, target, stages, 3, 0, &t)) {
			if (!same_links(&a.links, &t.links)) {
				printf("  seed %llu %s: unreadable table entries changed the links (%d, then %d)\n", (unsigned long long)seed, lg_target_name(target), a.links.n, t.links.n);
				return 1;
			}
			n_bogus++;
		}
	}
	/* HOSTILE: bytes of the code that decode as nothing (0x06 is no instruction in 64-bit mode): the frame's graph is the cut one (said, never a crash), the scan still answers */
	if (!strip) {
		static struct lg_img gp;
		static struct run_out z;
		uint32_t at;

		memcpy(&gp, g, sizeof gp);
		for (at = gp.code_off; at < gp.n && at < gp.code_off + 4096u; at += 61u)
			gp.b[at] = 0x06;
		if (scan_one(&gp, target, stages, 0, 0, &z))
			n_poison++;
	}
	/* HOSTILE: a memory allowance from 1 byte up; what the allowance leaves is a subset of the full answer and the scan says it was cut (or it is whole) */
	if (!strip) {
		static struct run_out m;
		uint64_t bud;

		/* the first programs of each target get a fine ladder (a step of a quarter), the rest a coarse one: every refusal of a charge the lineage makes is met somewhere */
		const int fine = swept[target & 7] < 6;

		for (bud = 1; bud < 4u * 1024u * 1024u; bud = fine ? bud + bud / 4u + 1u : bud * 8u) {
			if (!scan_one(g, target, stages, 4, bud, &m))
				continue;
			n_budget++;
			if (m.links.n > a.links.n || (m.links.n < a.links.n && m.status == KGENOME_OK)) {
				printf("  seed %llu %s: allowance %llu: %d links of %d and no status\n", (unsigned long long)seed, lg_target_name(target), (unsigned long long)bud, m.links.n, a.links.n);
				return 1;
			}
		}
	}
	/* HOSTILE: a cache whose frames are not the functions' (made from a decode one instruction short): the solve says so (BAD_INPUT) and solves nothing from them, it never lays one decode's facts
	 * over another's blocks. RED on a solve that trusted the cache: no status. */
	if (!strip && a.links.n > 0) {
		static struct run_out m;

		if (scan_one(g, target, stages, 7, 0, &m)) {
			CK(m.status != KGENOME_OK);
			CK(m.links.n <= a.links.n);
			n_badframe++;
		}
	}
	/* HOSTILE: the k-th allocation of the scan refused, for EVERY k (the frames, the table of functions, the codemap, the stub and pop tables, the cache): the links that come back are a
	 * subset of the full answer, and fewer of them are said (a status), never silent; a scan that cannot even start answers NULL */
	if (!strip && swept[target & 7]++ < 6) {
		static struct run_out m;
		unsigned long n, k;
		int way;


		for (way = 5; way <= 8; way++) {
			if (way == 7)
				continue;
			fail_k = 0;
			if (!scan_one(g, target, stages, way, 0, &m))
				return 0;
			n = alloc_seen;
			for (k = 1; k <= n; k++) {
				fail_k = k;
				if (!scan_one(g, target, stages, way, 0, &m)) {
					n_oom_null++;
					continue;
				}
				n_oom++;
				if (m.links.n > a.links.n || (m.links.n < a.links.n && m.status == KGENOME_OK)) {
					printf("  seed %llu %s: way %d, allocation %lu of %lu refused: %d links of %d and no status\n", (unsigned long long)seed, lg_target_name(target), way, k, n, m.links.n, a.links.n);
					fail_k = 0;
					return 1;
				}
			}
		}
		fail_k = 0;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const unsigned feat = LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_MEM;
	unsigned stages = KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | KGENOME_LINEAGE_S_SUMM;
	long programs = 0;

	hk_args(argc, argv);
	CK(lg_each(feat, (int)(40 * hk_scale()), 321, NULL, &programs, one, &stages) == 0);
	CK(n_oom > 2000 && n_oom_null > 0 && n_badframe > 20);
	{ int t; for (t = 0; t < 8; t++) if (worst_dec[t]) printf("  target %d: an offset decoded at most %u times in one scan\n", t, worst_dec[t]); }
	CK(n_scans > 100 && n_links > 0 && n_hits > 0 && n_built_empty > 0 && n_bogus > 100 && n_budget > 300 && n_poison > 100);
	printf("lineage_frame: %ld programs, %ld scans x3 ways, %ld links, %ld frames read from a full cache, %ld built into an empty one; %ld tables with unreadable entries, %ld allowances, %ld poisoned images, %ld scans with one allocation refused (%ld of them answered NULL), %d failure(s)\n",
	       programs, n_scans, n_links, n_hits, n_built_empty, n_bogus, n_budget, n_poison, n_oom, n_oom_null, hk_fails);
	return hk_fails != 0;
}
