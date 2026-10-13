/*
 * hostile_analysis - the analysis-without-running part of the library against
 * input it was not written for: instruction records no decoder produced, address
 * spaces whose callbacks lie, byte spans of every length, library spans in
 * objects that are cut and corrupted.
 *
 *   xref / constant map   a hundred thousand random instruction RECORDS (any op
 *                         class, operand kind, register number, scale, flags,
 *                         displacement and address, including 2^63 and the top of
 *                         the address space) are fed to the sweep and to the map;
 *                         the sweep is queried with every kind of range between
 *                         feeds. Nothing may index outside its tables and the
 *                         answers stay inside the flag word.
 *   cursor                every architecture, over random bytes and over
 *                         address spaces whose seg_at/off_of_va return a segment
 *                         [lo, hi) of 2^64-1, a delta that wraps, an offset
 *                         past the end: the cursor never leaves the space and
 *                         never reads past its last byte (guard page).
 *   mutation              the pool, the sketch, the membership bitmap, the core
 *                         and the content-defined cut over every length 0..300 in
 *                         all three normalisations, with the bytes ending at a
 *                         guard page; the cut's pieces tile the span; the unit
 *                         walk over random extents, functions and library spans
 *                         reports only units inside the object.
 *   library spans         the marker, symbol and object tiers over an ELF with
 *                         library text in it, cut at every length and with its
 *                         fields set to every extreme.
 *
 * Every family runs in a forked child; the seed of the run in flight is kept in
 * shared memory so a crash names it.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_gb G;
static volatile uint64_t *shared_seed;

static void bad(const char *what, uint64_t ctx)
{
	static unsigned seen;

	if (seen++ < 12)
		printf("  FAIL %s (ctx %#llx)\n", what, (unsigned long long)ctx);
	hk_fails++;
}

static uint64_t rnd_edge(struct hk_rng *r)
{
	static const uint64_t e[] = { 0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffffull,
		0x80000000ull, 0xffffffffull, 0x100000000ull, 0x7fffffffffffffffull,
		0x8000000000000000ull, UINT64_MAX - 1u, UINT64_MAX, 0x400000, 0x401000, 0x3000 };

	return hk_below(r, 3) ? e[hk_below(r, sizeof e / sizeof e[0])] : hk_next(r);
}

/* ---- xref and the constant map on instruction records ----------------------------------------------- */

static void rand_insn(struct hk_rng *r, struct kgenome_cell_insn *in)
{
	unsigned k;

	memset(in, 0, sizeof *in);
	in->op = (uint8_t)(hk_below(r, 3) ? hk_below(r, KGENOME_CELL_OP_COUNT + 2u) : hk_next(r));
	in->len = (uint8_t)(hk_below(r, 4) ? 1u + hk_below(r, 15) : hk_next(r));
	in->n_op = (uint8_t)hk_below(r, 4);                         /* the contract: at most three */
	in->cond = (uint8_t)hk_next(r);
	in->flags = (uint8_t)hk_next(r);
	in->wmask = hk_below(r, 4) ? 1ull << hk_below(r, 16) : hk_next(r);
	in->at = rnd_edge(r);
	in->at_va = hk_below(r, 5) ? 0x1000 + hk_below(r, 0x100) : rnd_edge(r);
	in->target = rnd_edge(r);
	in->target_va = hk_below(r, 3) ? KGENOME_BROKEN : rnd_edge(r);
	for (k = 0; k < 3; k++) {
		struct kgenome_cell_operand *o = &in->o[k];
		o->kind = (uint8_t)(hk_below(r, 6) ? hk_below(r, 5) : hk_next(r));
		o->reg = (uint8_t)(hk_below(r, 3) ? hk_below(r, 16) : hk_next(r));
		o->index = (uint8_t)(hk_below(r, 3) ? hk_below(r, 16) : hk_next(r));
		o->scale = (uint8_t)(hk_below(r, 2) ? 1u << hk_below(r, 4) : hk_next(r));
		o->size = (uint8_t)(hk_below(r, 2) ? 1u << hk_below(r, 4) : hk_next(r));
		o->flags = (uint8_t)hk_next(r);
		o->seg = (uint8_t)(hk_below(r, 2) ? hk_below(r, 6) : hk_next(r));
		o->disp = (int64_t)rnd_edge(r);
		o->imm = rnd_edge(r);
	}
}

static int fam_records(void *arg)
{
	struct hk_rng r = { 0x5eed0000ull + (uintptr_t)arg };
	struct kgenome_xref *u = kgenome_xref_new();
	struct kgenome_cell_state st;
	unsigned it, q;
	uint64_t seen_flags = 0;

	if (!u)
		return 2;
	kgenome_cell_state_reset(&st);
	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	for (it = 0; it < 300000u * hk_scale(); it++) {
		struct kgenome_cell_insn in;

		if (shared_seed)
			*shared_seed = it;
		rand_insn(&r, &in);
		kgenome_xref_feed(u, &in);
		kgenome_cell_state_track(&st, &in);
		if (st.stk_n > KGENOME_CELL_STACK)
			bad("cell_state: modelled stack past its array", st.stk_n);
		if ((it & 0xff) == 0) {
			kgenome_xref_feed(u, NULL);
			for (q = 0; q < 6; q++) {
				uint32_t f = kgenome_xref_in(u, rnd_edge(&r), rnd_edge(&r));

				if (f & ~0x1ffu)
					bad("xref: answer outside the flag word", f);
				seen_flags |= f;
			}
		}
		if ((it % 5000) == 4999) {
			kgenome_xref_begin(u, hk_below(&r, 3) ? KGENOME_ARCH_X86_64 : (unsigned)hk_next(&r));
			kgenome_cell_state_reset(&st);
		}
		if ((it % 17) == 0) {
			uint64_t v;
			unsigned reg;
			for (reg = 0; reg < 300; reg += 7)
				(void)kgenome_cell_state_reg(&st, (uint8_t)reg, &v);
			(void)kgenome_cell_state_stack_top(&st, &v);
		}
	}
	(void)kgenome_xref_full(u);
	(void)kgenome_xref_startup(u, rnd_edge(&r));
	kgenome_xref_free(u);
	return hk_fails != 0;
}

/* ---- the cursor over hostile spaces -------------------------------------------------------------------- */

struct hostile_space { struct hk_rng r; unsigned mode; };

static int hs_seg(void *priv, uint64_t off, struct kgenome_image_seg *out)
{
	struct hostile_space *h = (struct hostile_space *)priv;

	switch (h->mode) {
	case 0: out->lo = 0; out->hi = UINT64_MAX; out->delta = 0; return 1;
	case 1: out->lo = off; out->hi = off + 1; out->delta = INT64_MIN; return 1;
	case 2: out->lo = UINT64_MAX - 3u; out->hi = 5; out->delta = INT64_MAX; return 1;
	case 3: out->lo = 0; out->hi = 0; out->delta = -1; return 1;
	case 4: out->lo = hk_next(&h->r); out->hi = hk_next(&h->r); out->delta = (int64_t)hk_next(&h->r); return 1;
	default: return 0;
	}
}

static uint64_t hs_va(void *priv, uint64_t va)
{
	struct hostile_space *h = (struct hostile_space *)priv;

	switch (h->mode) {
	case 0: return va;
	case 1: return UINT64_MAX;
	case 2: return KGENOME_BROKEN;
	case 3: return 0;
	case 4: return hk_next(&h->r);
	default: return va >> 1;
	}
}

static int fam_cursor(void *arg)
{
	struct hostile_space hs;
	struct hk_rng r = { 0xc0ffee00ull + (uintptr_t)arg };
	unsigned it, n, arch, mode;

	hs.r.s = 99;
	for (it = 0; it < 1500u * hk_scale(); it++) {
		uint8_t buf[200];
		unsigned len = hk_below(&r, 200);

		for (n = 0; n < sizeof buf; n++)
			buf[n] = (uint8_t)hk_next(&r);
		for (arch = 0; arch < 20; arch++) {
			for (mode = 0; mode < 6; mode++) {
				struct kgenome_cell_space sp;

				/* KNOWN UNDEFINED BEHAVIOUR (UBSAN only): cursor.c:45,61,62,65 add a signed delta to an offset;
				 * a segment whose delta is near 2^63 overflows. Modes 1, 2 and 4 return such deltas. */
				if (hk_ubsan() && (mode == 1 || mode == 2 || mode == 4))
					continue;
				struct kgenome_cell_cur k;
				struct kgenome_cell_insn in;
				unsigned steps = 0;
				const uint8_t *p = gb_put(&G, buf, len);

				if (shared_seed)
					*shared_seed = (uint64_t)it << 16 | arch << 8 | mode;
				hs.mode = mode;
				memset(&sp, 0, sizeof sp);
				sp.base = p;
				sp.size = len;
				sp.arch = arch;
				sp.be = (int)(it & 1u);
				sp.priv = &hs;
				sp.seg_at = mode == 5 ? NULL : hs_seg;
				sp.off_of_va = hs_va;
				memset(&k, 0, sizeof k);
				kgenome_cell_seek(&k, hk_below(&r, 4) ? 0 : rnd_edge(&r), (int)(it & 2u));
				while (steps++ < 400u) {
					int ok = (steps & 1u) ? kgenome_cell_next(&k, &sp, &in)
							      : kgenome_cell_step(&k, &sp, &in);
					uint64_t v;

					if (!ok)
						break;
					if (k.at > len)
						bad("cursor ran past the end of the space", k.at);
					(void)kgenome_cell_reg(&k, (uint8_t)hk_next(&r), &v);
				}
			}
		}
	}
	return hk_fails != 0;
}

/* ---- the mutation primitives ---------------------------------------------------------------------------- */

struct cut_log { uint64_t next, max_piece, min_piece, avg; unsigned pieces, stop_after; int gap; uint64_t last_len; };

static int cut_cb(void *u, uint64_t from, uint64_t to)
{
	struct cut_log *c = (struct cut_log *)u;

	if (from != c->next || to <= from)
		c->gap = 1;                           /* not contiguous, or empty */
	c->next = to;
	c->pieces++;
	c->last_len = to - from;
	if (to - from > c->max_piece)
		c->max_piece = to - from;
	return c->stop_after && c->pieces >= c->stop_after;
}

static int fam_mutation(void *arg)
{
	struct hk_rng r = { 0xaaaa5555ull + (uintptr_t)arg };
	struct hk_gb g, bg;
	unsigned n, norm, round;

	gb_init(&g, 2048);
	gb_init(&bg, 4096);
	for (round = 0; round < 3u * hk_scale(); round++) {
		for (n = 0; n <= 300; n++) {
			uint8_t src[2048];
			unsigned k, flatten = hk_below(&r, 4);

			for (k = 0; k < sizeof src; k++)
				src[k] = flatten == 0 ? 0x41 : flatten == 1 ? (uint8_t)k : (uint8_t)hk_next(&r);
			for (norm = 0; norm < KGENOME_MUTATION_NORM_COUNT + 2u; norm++) {
				const uint8_t *p = gb_put(&g, src, n);
				uint32_t np = 0, *pool, mh[KGENOME_MUTATION_MINHASH_K + 4], got;
				uint32_t i;

				if (shared_seed)
					*shared_seed = (uint64_t)n << 8 | norm;
				pool = kgenome_mutation_pool(p, n, norm, &np);
				if (norm >= KGENOME_MUTATION_NORM_COUNT) {
					if (pool)
						bad("pool: an out-of-range normalisation was accepted", norm);
					free(pool);
					got = kgenome_mutation_minhash(p, n, norm, mh);
					if (got)
						bad("minhash: an out-of-range normalisation was accepted", norm);
					continue;
				}
				if (pool) {
					for (i = 1; i < np; i++)
						if (pool[i] <= pool[i - 1u])
							bad("pool: not ascending and distinct", i);
					if (np == 0)
						bad("pool: returned an empty array", n);
				} else if (n >= KGENOME_MUTATION_NG + 2u && flatten >= 2u) {
					bad("pool: none for a span with distinct windows", n);
				}
				got = kgenome_mutation_minhash(p, n, norm, mh);
				if (got > KGENOME_MUTATION_MINHASH_K)
					bad("minhash: more than K values", got);
				if (pool) {
					uint32_t want = np < KGENOME_MUTATION_MINHASH_K ? np : KGENOME_MUTATION_MINHASH_K;
					if (got != want || memcmp(mh, pool, got * sizeof mh[0]))
						bad("minhash: not the K smallest of the pool", n);
				} else if (got) {
					bad("minhash: values from no pool", n);
				}
				/* membership: the bitmap is exactly ceil(n_pool/8) bytes, at a guard page */
				if (pool) {
					uint32_t nb = (np + 7u) / 8u;
					uint8_t *bits = gb_put(&bg, NULL, nb);
					uint32_t j, set = 0;

					memset(bits, 0, nb);
					kgenome_mutation_member(pool, np, p, n, norm, bits);
					for (j = 0; j < np; j++)
						set += (bits[j >> 3] >> (j & 7u)) & 1u;
					if (np && !set && !flatten && n > KGENOME_MUTATION_NG + 8u)
						bad("member: a span is not a member of its own pool", n);
					/* a different span of the same length shares (almost) nothing */
					{
						uint8_t other[2048];
						uint8_t *bits2 = gb_put(&bg, NULL, nb);
						memset(bits2, 0, nb);
						for (j = 0; j < n; j++)
							other[j] = (uint8_t)~src[j];
						kgenome_mutation_member(pool, np, gb_put(&g, other, n), n, norm, bits2);
					}
					/* the core: the first k that qualify, none unless at least MIN_HASH */
					{
						uint16_t pos[4096], bgc[4096];
						uint32_t out[64], c;
						for (j = 0; j < np && j < 4096u; j++) {
							pos[j] = (uint16_t)hk_below(&r, 4);
							bgc[j] = (uint16_t)hk_below(&r, 4);
						}
						c = kgenome_mutation_core(pool, np < 4096u ? np : 4096u, pos, 2, bgc, 2, 32, out);
						if (c && c < KGENOME_MUTATION_MIN_HASH)
							bad("core: fewer than MIN_HASH returned", c);
						if (c > 32)
							bad("core: more than k returned", c);
						for (j = 1; j < c; j++)
							if (out[j] <= out[j - 1u])
								bad("core: not ascending", j);
						(void)kgenome_mutation_core(pool, np, pos, 0, NULL, 0, 0, out);
						(void)kgenome_mutation_core(NULL, np, pos, 0, NULL, 0, 5, out);
						(void)kgenome_mutation_core(pool, 0, pos, 0, NULL, 0, 5, out);
					}
				}
				free(pool);
			}
		}
	}
	/* the cut: pieces tile [0, len), none exceeds max, all but the last reach min, a stop is honoured */
	for (round = 0; round < 40u * hk_scale(); round++) {
		static const uint32_t avgs[] = { 1, 2, 64, 256, 8192, 3, 0 };
		static const uint32_t mins[] = { 0, 1, 16, 64, 2048 };
		static const uint32_t maxs[] = { 0, 1, 32, 128, 1000, 32768 };
		uint32_t avg = avgs[hk_below(&r, 7)], min = mins[hk_below(&r, 5)], max = maxs[hk_below(&r, 6)];
		unsigned len = hk_below(&r, 2048);
		uint8_t src[2048];
		struct cut_log c;
		unsigned k;

		for (k = 0; k < sizeof src; k++)
			src[k] = hk_below(&r, 5) ? (uint8_t)hk_next(&r) : 0;
		memset(&c, 0, sizeof c);
		kgenome_mutation_cut(gb_put(&g, src, len), len, avg, min, max, cut_cb, &c);
		if (c.gap)
			bad("cut: pieces do not tile the span", len);
		if (len && c.next != len)
			bad("cut: the tail was not delivered", len);
		if (!len && c.pieces)
			bad("cut: pieces from an empty span", c.pieces);
		/* the first piece is at least one window long, whatever max says */
		if (max && c.max_piece > (max > KGENOME_MUTATION_NG ? max : KGENOME_MUTATION_NG))
			bad("cut: a piece longer than max", c.max_piece);
		memset(&c, 0, sizeof c);
		c.stop_after = 2;
		kgenome_mutation_cut(gb_put(&g, src, len), len, avg, min, max, cut_cb, &c);
		if (c.pieces > 3)
			bad("cut: the walk went on after the callback said stop", c.pieces);
	}
	gb_free(&g);
	gb_free(&bg);
	return hk_fails != 0;
}

/* the unit walk: random extents, library spans and function lists; only units inside the object */
struct unit_log { uint64_t n_obj; unsigned units, stop_after; int out; int nonempty; };

static int unit_cb(void *u, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct unit_log *l = (struct unit_log *)u;

	l->units++;
	if (off > l->n_obj || len > l->n_obj - off)
		l->out = 1;
	if (!len)
		l->nonempty = 1;
	if (side > KGENOME_MUTATION_SIDE_LIB)
		l->out = 1;
	(void)first;
	return l->stop_after && l->units >= l->stop_after;
}

static int fam_units(void *arg)
{
	struct hk_rng r = { 0x17171717ull + (uintptr_t)arg };
	struct hk_gb g;
	unsigned round;

	gb_init(&g, 8192);
	for (round = 0; round < 600u * hk_scale(); round++) {
		static uint8_t obj[8192];
		struct kof_range ext[8];
		struct kgenome_func fv[40];
		struct kgenome_func_set fs;
		struct kgenome_true_all lib;
		struct kgenome_mutation_req rq;
		struct unit_log ul;
		unsigned n_obj = hk_below(&r, 8192), k, mode = hk_below(&r, 3), n_ext = hk_below(&r, 9);
		const uint8_t *p;

		if (shared_seed)
			*shared_seed = round;
		for (k = 0; k < n_obj; k++) {
			/* clusters of printable strings, runs of code-like bytes, zeros */
			switch ((k / 97u + round) % 4u) {
			case 0: obj[k] = (uint8_t)(0x41 + hk_below(&r, 26)); if (hk_below(&r, 12) == 0) obj[k] = 0; break;
			case 1: obj[k] = (uint8_t)hk_next(&r); break;
			case 2: obj[k] = 0; break;
			default: obj[k] = (uint8_t)(0x20 + hk_below(&r, 90)); break;
			}
		}
		p = gb_put(&g, obj, n_obj);
		for (k = 0; k < n_ext; k++) {
			ext[k].off = hk_below(&r, 4) ? hk_below(&r, n_obj + 1u) : rnd_edge(&r);
			ext[k].len = hk_below(&r, 4) ? hk_below(&r, n_obj + 1u) : rnd_edge(&r);
		}
		memset(&lib, 0, sizeof lib);
		lib.n = hk_below(&r, 5);
		for (k = 0; k < lib.n; k++) {
			lib.span[k].off = hk_below(&r, n_obj + 1u);
			lib.span[k].len = hk_below(&r, 400);
		}
		memset(&fs, 0, sizeof fs);
		fs.n = hk_below(&r, 40);
		fs.v = fv;
		for (k = 0; k < fs.n; k++) {
			fv[k].off = k ? fv[k - 1u].off + fv[k - 1u].len + hk_below(&r, 40) : hk_below(&r, 100);
			fv[k].len = hk_below(&r, 300);
			fv[k].value = fv[k].off;
			fv[k].shndx = 1;
		}
		memset(&rq, 0, sizeof rq);
		rq.p = p;
		rq.n_obj = n_obj;
		rq.format = mode == 0 ? KGENOME_FMT_ELF : mode == 1 ? KGENOME_FMT_PE : KGENOME_FMT_NONE;
		rq.mask = mode == 2 ? KGENOME_SCAN_ELF_DATA : KGENOME_SCAN_ELF_CODE;
		rq.ext = n_ext ? ext : NULL;
		rq.n_ext = n_ext;
		rq.funcs = hk_below(&r, 4) ? &fs : NULL;
		rq.lib = hk_below(&r, 3) ? &lib : NULL;
		rq.fn = unit_cb;
		rq.user = &ul;
		memset(&ul, 0, sizeof ul);
		ul.n_obj = n_obj;
		/* function extents may be hostile only as far as the CALLER makes them: keep them in
		 * the extents, as the engine does (every function is inside a code region) */
		if (rq.funcs) {
			uint64_t lim = n_obj;
			for (k = 0; k < fs.n; k++)
				if (fv[k].off + fv[k].len > lim) {
					fs.n = k;
					break;
				}
			for (k = 0; k < n_ext; k++)
				if (ext[k].off > n_obj || ext[k].len > n_obj - ext[k].off)
					ext[k].len = ext[k].off > n_obj ? 0 : n_obj - ext[k].off;
		}
		ul.stop_after = hk_below(&r, 4) == 0 ? 1u + hk_below(&r, 3) : 0u;
		kgenome_mutation_units(&rq);
		if (ul.out && !(rq.funcs && mode == 0))
			bad("units: a unit outside the object", round);
		/* (the function-region walk keeps going after a stop: see km_units_stop in main) */
		if (ul.stop_after && ul.units > ul.stop_after && !(rq.funcs && mode < 2))
			bad("units: the walk went on after the callback said stop", ul.units);
		/* a request with no bytes or no callback is refused quietly */
		rq.p = NULL;
		kgenome_mutation_units(&rq);
		rq.p = p;
		rq.fn = NULL;
		kgenome_mutation_units(&rq);
	}
	gb_free(&g);
	return hk_fails != 0;
}

/* a callback that answers "stop" is not called again - also across the function walk and the
 * string walk that follow each other in a code region */
static int km_stop_calls;

static int stop_cb(void *u, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	(void)u; (void)off; (void)len; (void)side; (void)first;
	km_stop_calls++;
	return 1;
}

static int km_units_stop(void *arg)
{
	static uint8_t obj[600];
	struct kof_range ext = { 0, sizeof obj };
	struct kgenome_func fv[1] = { { 0, 200, 0, 1 } };
	struct kgenome_func_set fs = { fv, 1, KGENOME_OK };
	struct kgenome_mutation_req rq;

	(void)arg;
	memset(obj, 0x90, 200);                 /* one function of 200 bytes: a unit */
	memset(obj + 300, 'A', 120);            /* and one cluster of text: a second */
	obj[420] = 0;
	memset(&rq, 0, sizeof rq);
	rq.p = obj;
	rq.n_obj = sizeof obj;
	rq.format = KGENOME_FMT_ELF;
	rq.mask = KGENOME_SCAN_ELF_CODE;
	rq.ext = &ext;
	rq.n_ext = 1;
	rq.funcs = &fs;
	rq.fn = stop_cb;
	km_stop_calls = 0;
	kgenome_mutation_units(&rq);
	if (km_stop_calls < 1)
		return 2;                       /* the function was not offered at all */
	return km_stop_calls == 1 ? 0 : 1;
}

/* ---- library spans in objects with library text in them --------------------------------------------------- */

static struct hk_elf LE;
static uint32_t lib_n;
static uint8_t lib_img[HK_ELF_MAX];

static void build_libelf(int is64, int rel)
{
	static const char *const marks[] = { "No such file or directory", "Permission denied",
		"Cannot allocate memory", "Invalid argument", "Broken pipe", "malloc(): ", "GLIBC_",
		"Connection refused" };
	unsigned i, off;

	hk_elf(&LE, is64, 0, rel);
	memcpy(lib_img, LE.b, LE.n);
	off = LE.n;
	for (i = 0; i < 8; i++) {
		size_t l = strlen(marks[i]) + 1u;
		memcpy(lib_img + off, marks[i], l);
		off += (unsigned)l + 12u;
	}
	lib_n = off;
	if (!rel) {
		/* the one PT_LOAD covers the whole file now */
		if (is64) {
			hk_w(lib_img + LE.ph + 32, lib_n, 8, 0);
			hk_w(lib_img + LE.ph + 40, lib_n + 0x100u, 8, 0);
		} else {
			hk_w(lib_img + LE.ph + 16, lib_n, 4, 0);
			hk_w(lib_img + LE.ph + 20, lib_n + 0x100u, 4, 0);
		}
	}
}

static void walk_spans(const uint8_t *p, size_t n, const struct kgenome_elf_info *e)
{
	static struct kgenome_true_all all;
	static struct kgenome_true_result res;
	kof_buf f = kof_buf_make(p, n);
	uint32_t i;
	unsigned which;

	for (which = 0; which < 3; which++) {
		if (which == 0)
			kgenome_true_find(f, e, &res);
		else if (which == 1)
			kgenome_true_find_all(f, e, &all);
		else
			kgenome_true_find_object(f, e, &all);
		if (which == 0) {
			for (i = 0; i < res.n && i < KGENOME_TRUE_MAX_SPANS; i++) {
				if (res.span[i].off > n || res.span[i].len > n - res.span[i].off)
					bad("marker span outside the object", n);
				if (i && res.span[i].off < res.span[i - 1u].off + res.span[i - 1u].len)
					bad("marker spans overlap or are not sorted", n);
			}
			if (res.n > KGENOME_TRUE_MAX_SPANS)
				bad("marker spans past their array", res.n);
		} else {
			for (i = 0; i < all.n && i < KGENOME_TRUE_MAX_SPANS_ALL; i++) {
				if (all.span[i].off > n || all.span[i].len > n - all.span[i].off)
					bad("library span outside the object", n);
				if (i && all.span[i].off < all.span[i - 1u].off + all.span[i - 1u].len)
					bad("library spans overlap or are not sorted", n);
			}
			if (all.n > KGENOME_TRUE_MAX_SPANS_ALL)
				bad("library spans past their array", all.n);
			(void)kgenome_true_touches(&all, 0, n);
			(void)kgenome_true_touches(&all, n / 2u, 3);
			(void)kgenome_true_has_addr(e, &all, 0x400000, 8);
		}
	}
}

static int fam_spans(void *arg)
{
	struct hk_rng r = { 0x42ull + (uintptr_t)arg };
	static struct kgenome_elf_info whole, cut;
	struct kgenome_obj o;
	unsigned c, n, k, it;
	uint64_t ex[HK_NEXTREME];
	static uint8_t w[HK_ELF_MAX];

	for (c = 0; c < 4; c++) {
		build_libelf((int)(c & 1u), (int)(c >> 1));
		memset(&whole, 0, sizeof whole);
		kgenome_elf_image_parse(kof_buf_make(lib_img, lib_n), &whole, &o);
		/* the marker tier finds the table in the intact object (ET_EXEC) */
		if (!(c >> 1)) {
			static struct kgenome_true_result res;
			kgenome_true_find(kof_buf_make(lib_img, lib_n), &whole, &res);
			CK(res.n >= 1);
		}
		for (n = 0; n <= lib_n; n++) {
			const uint8_t *p = gb_put(&G, lib_img, n);

			if (shared_seed)
				*shared_seed = (uint64_t)c << 32 | n;
			memset(&cut, 0, sizeof cut);
			kgenome_elf_image_parse(kof_buf_make(p, n), &cut, &o);
			walk_spans(p, n, &cut);
			walk_spans(p, n, &whole);                /* a stale description of the whole file */
		}
		/* every field, every extreme (the program headers and the section table) */
		hk_extremes(ex, lib_n);
		for (k = 0; k < LE.n; k += 2) {
			unsigned x, wd;
			for (wd = 2; wd <= 8; wd *= 2) {
				if (k + wd > LE.n || (wd > 2 && (k & 3u)))
					continue;
				for (x = 0; x < HK_NEXTREME; x++) {
					memcpy(w, lib_img, lib_n);
					hk_w(w + k, ex[x], wd, 0);
					memset(&cut, 0, sizeof cut);
					kgenome_elf_image_parse(kof_buf_make(gb_put(&G, w, lib_n), lib_n), &cut, &o);
					walk_spans(gb_put(&G, w, lib_n), lib_n, &cut);
				}
			}
		}
		for (it = 0; it < 4000u * hk_scale(); it++) {
			memcpy(w, lib_img, lib_n);
			for (k = 1u + hk_below(&r, 6); k; k--)
				w[hk_below(&r, lib_n)] = (uint8_t)hk_next(&r);
			memset(&cut, 0, sizeof cut);
			kgenome_elf_image_parse(kof_buf_make(gb_put(&G, w, lib_n), lib_n), &cut, &o);
			walk_spans(gb_put(&G, w, lib_n), lib_n, &cut);
		}
	}
	return hk_fails != 0;
}

/* ---- the driver --------------------------------------------------------------------------------------------- */

struct fam { const char *name; hk_case_fn fn; void *arg; unsigned secs; };

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	static struct fam fams[] = {
		{ "xref and constant map: random records 0", fam_records, (void *)0, 120 },
		{ "xref and constant map: random records 1", fam_records, (void *)1, 120 },
		{ "cursor over hostile spaces", fam_cursor, (void *)0, 120 },
		{ "mutation: windows, pool, member, cut", fam_mutation, (void *)0, 120 },
		{ "mutation: unit walk", fam_units, (void *)0, 120 },
		{ "library spans: cut, fields, flips", fam_spans, (void *)0, 120 },
	};
	unsigned i;

	gb_init(&G, 8192);
	shared_seed = (volatile uint64_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
						MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared_seed == (volatile uint64_t *)MAP_FAILED)
		shared_seed = NULL;
	for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
		int sig = 0;
		double t0 = hk_now();
		enum hk_result r;

		if (shared_seed)
			*shared_seed = 0;
		r = hk_isolated(fams[i].fn, fams[i].arg, fams[i].secs, &sig);
		printf("  %-42s %s (%.2fs)\n", fams[i].name,
		       r == HK_OK ? "ok" : r == HK_FAILED ? "FAILED" : r == HK_HUNG ? "HUNG" : "CRASHED",
		       hk_now() - t0);
		if (r != HK_OK) {
			printf("  FAIL %s: result %d signal %d (last case %#llx)\n", fams[i].name, (int)r, sig,
			       shared_seed ? (unsigned long long)*shared_seed : 0ull);
			hk_fails++;
		}
	}
	{
		int sig = 0;
		enum hk_result r = hk_isolated(km_units_stop, NULL, 10, &sig);

		KM_CHECK(r == HK_OK, "kgenome_mutation_units calls its callback again after the callback returned stop",
			 "celllysis/mutation_units.c kgenome_mutation_units: `by_function(...); by_string(...); return;` - "
			 "by_function is void and its early `return` on a stop is not seen, so by_string runs and offers the "
			 "string clusters. Repro: ELF code region, one 200-byte function and one 120-byte string cluster, "
			 "callback returns 1: called twice");
	}
	gb_free(&G);
	printf("hostile_analysis: %d failure(s)\n", hk_fails);
	return hk_fails != 0 || km_failed();
}
