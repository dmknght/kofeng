/*
 * arm_index_gen - writes the derived indexes of the ARM state, Thumb state and AArch64 decoders as CONST data.
 *
 * WHY IT IS A TOOL. The decoders read an index that is derived from their hand-written rows (arm32_rows.c, thumb_rows.c,
 * arm64_tab.c). It used to be built by code inside libkgenome on the first decode, into writable static storage guarded by
 * a compare-and-swap and a spin: writable global state in a lib that must be safe on many threads (.bss 0x12030 for ARM
 * and Thumb, 0x1020 for AArch64), and a waiter that spins unbounded on the builder. The derivation is a function of the
 * rows alone, so it is done here, once, and the output is checked in beside the decoders (arm32_index_tab.c,
 * arm64_l1_tab.c) the way the x86 tables are (x86_gen.c). The lib keeps no builder.
 *
 * tests/lib/genome/arm_index.c includes this file (ARMIDX_NO_MAIN) and compares what armidx_build makes with the checked-in
 * tables, so a row changed without re-running `make genotype-arm-index` fails the unit tests.
 *
 * usage: arm_index_gen <dir>        writes <dir>/arm32/arm32_index_tab.c and <dir>/arm64/arm64_l1_tab.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <genotype/arm32/arm32_ids.h>
#include <genotype/arm32/thumb_ids.h>
#include <genotype/arm32/arm32_private.h>
#include <genotype/arm64/arm64_private.h>

#define ARM_POOL 2048u
#define THUMB_POOL 2048u
#define MAXLIST 64u
#define MAXROWS 1024u

#define L1_SHIFT KGENOME_ARM64_L1_SHIFT
#define L1_N KGENOME_ARM64_L1_N
#define L1_MORE KGENOME_ARM64_L1_MORE

struct armidx {
	struct kgenome_arm32_row arm_lists[ARM_POOL];
	unsigned arm_used;
	uint16_t arm_idx[2 * KGENOME_ARM32_KEYS];
	struct kgenome_arm32_row thumb_lists[THUMB_POOL];
	unsigned thumb_used;
	uint16_t thumb_narrow[KGENOME_THUMB_NARROW_KEYS];
	uint16_t thumb_wide[KGENOME_THUMB_WIDE_KEYS];
	unsigned shadowed_arm32, shadowed_thumb;        /* rows no key reaches: a mistake in the order of the rows */
	uint16_t l1[L1_N];                              /* AArch64: the identity of every word with these top bits, or L1_MORE */
};

static unsigned key_arm32(uint32_t w) { return kgenome_arm32_key12(w); }
static unsigned key_narrow(uint32_t w) { return kgenome_thumb_narrow_key(w); }
static unsigned key_wide(uint32_t w) { return kgenome_thumb_wide_key(w); }

/*
 * One index, built by walking the key's bits from the top instead of trying every
 * key against every row.
 *
 * The old builder took each of the 8192 ARM state keys (1024 Thumb) and tested it
 * against every row of the table. MEASURED on the 300 KB ARM sample (callgrind,
 * whole scan 45.4 M Ir) that was 19.8 M Ir, 44% of the scan, spent on the first
 * decode - and the answer for most keys is the same list as the key beside it.
 * The walk fixes one key bit at a time, keeping only the rows still compatible;
 * when no row of the list (up to the one the key decides) looks at a bit not yet
 * fixed, every key below is the same list, which is built once and written to the
 * whole run of keys. Keys are still reached in increasing order and the pool is
 * filled the same way, so the tables are byte for byte what the old builder made.
 *
 * `pre_mask`/`pre_val` are bits every word of this table has fixed (the
 * unconditional space's 1111); `direct` allows the by-name entries. `hits` counts,
 * per row, the keys that reach it.
 */
struct bld {
	const struct kgenome_arm32_row *rows;
	unsigned nbits;
	uint32_t keymask, pre_mask;
	unsigned kbit[16];              /* the word bit each key bit comes from */
	int direct;
	struct kgenome_arm32_row *pool;
	unsigned cap, *used;
	uint16_t *idx;
	unsigned char *hits;
	unsigned prev_start, prev_n;
};

/* The pool entry (or the by-name entry) for the list the candidates make; the
 * rows it reaches are marked. */
static uint16_t bld_emit(struct bld *x, const uint16_t *cand, unsigned nc)
{
	struct kgenome_arm32_row list[MAXLIST + 1u];
	unsigned n = 0, found = ~0u, i, c;
	int decided = 0;

	for (c = 0; c < nc && !decided; c++) {
		const struct kgenome_arm32_row *r = &x->rows[cand[c]];

		x->hits[cand[c]] = 1;
		if (n >= MAXLIST)
			abort();
		memset(&list[n], 0, sizeof list[n]);    /* padding too: lists are compared bytewise */
		list[n].mask = r->mask;
		list[n].value = r->value;
		list[n].id = r->id;
		n++;
		if (!(r->mask & ~(x->keymask | x->pre_mask)))
			decided = 1;
	}
	if (!decided) {
		memset(&list[n], 0, sizeof list[n]);    /* mask 0, name 0 (INVALID) */
		n++;
	}
	if (x->direct && n == 1 && decided)
		return (uint16_t)(KGENOME_ARM32_DIRECT | list[0].id);
	/* neighbouring keys mostly share a list: try the last one first */
	if (x->prev_n == n && !memcmp(&x->pool[x->prev_start], list, n * sizeof list[0])) {
		found = x->prev_start;
	} else {
		for (i = 0; i + n <= *x->used; i++)
			if (!memcmp(&x->pool[i], list, n * sizeof list[0])) {
				found = i;
				break;
			}
	}
	if (found == ~0u) {
		if (*x->used + n > x->cap)
			abort();
		found = *x->used;
		memcpy(&x->pool[found], list, n * sizeof list[0]);
		*x->used += n;
	}
	if (found >= KGENOME_ARM32_DIRECT)
		abort();
	x->prev_start = found;
	x->prev_n = n;
	return (uint16_t)found;
}

/* `bit` is the next key bit to fix (counting down), `kk` the key so far. */
static void bld_walk(struct bld *x, int bit, unsigned kk, const uint16_t *cand, unsigned nc)
{
	uint32_t rest = 0;
	unsigned c;
	int b, free_bits = 0;

	for (b = 0; b <= bit; b++)
		rest |= 1u << x->kbit[b];
	/* Does anything the list is made of look at a bit not yet fixed? */
	for (c = 0; c < nc; c++) {
		const struct kgenome_arm32_row *r = &x->rows[cand[c]];

		if (r->mask & rest) {
			free_bits = 1;
			break;
		}
		if (!(r->mask & ~(x->keymask | x->pre_mask)))
			break;          /* decided: the list ends here */
	}
	if (bit < 0 || !free_bits) {
		uint16_t v = bld_emit(x, cand, nc);
		unsigned run = 1u << (bit + 1), k;

		for (k = 0; k < run; k++)
			x->idx[kk + k] = v;
		return;
	}
	{
		uint16_t sub[MAXROWS];
		unsigned v;

		for (v = 0; v < 2u; v++) {
			unsigned n = 0;

			for (c = 0; c < nc; c++) {
				const struct kgenome_arm32_row *r = &x->rows[cand[c]];

				if (((r->mask >> x->kbit[bit]) & 1u) &&
				    ((r->value >> x->kbit[bit]) & 1u) != v)
					continue;
				sub[n++] = cand[c];
			}
			bld_walk(x, bit - 1, kk | (v << bit), sub, n);
		}
	}
}

/* One index to build: the canonical rows, the key that indexes them, the bits
 * the table fixes in advance (`pre_*`), where the index goes and where the
 * builder records which rows it reached. */
struct bld_job {
	const struct kgenome_arm32_row *rows;
	unsigned nrows, keys;
	unsigned (*keyf)(uint32_t);
	uint32_t pre_mask, pre_val;
	int direct;
	uint16_t *idx;
	unsigned char *hits;
};

/* The list pool the jobs of one family share, and how much of it is used. */
struct bld_pool {
	struct kgenome_arm32_row *pool;
	unsigned cap, used;
};

static void build_one(const struct bld_job *job, struct bld_pool *pl)
{
	const struct kgenome_arm32_row *rows = job->rows;
	const unsigned nrows = job->nrows, keys = job->keys;
	unsigned (*const keyf)(uint32_t) = job->keyf;
	const uint32_t pre_mask = job->pre_mask, pre_val = job->pre_val;
	struct bld x;
	uint16_t cand[MAXROWS];
	unsigned b, j, nc = 0;

	if (nrows > MAXROWS)
		abort();
	memset(&x, 0, sizeof x);
	x.rows = rows;
	x.pre_mask = pre_mask;
	x.direct = job->direct;
	x.pool = pl->pool;
	x.cap = pl->cap;
	x.used = &pl->used;
	x.idx = job->idx;
	x.hits = job->hits;
	while ((1u << x.nbits) < keys)
		x.nbits++;
	if ((1u << x.nbits) != keys || x.nbits > 16u)
		abort();
	for (b = 0; b < 32; b++) {
		unsigned kb = keyf(1u << b), i = 0;

		if (!kb)
			continue;
		if (kb & (kb - 1u))
			abort();        /* a word bit that feeds two key bits */
		while ((1u << i) != kb)
			i++;
		x.kbit[i] = b;
		x.keymask |= 1u << b;
	}
	/* The rows the fixed bits allow, in priority order. */
	for (j = 0; j < nrows; j++)
		if (!((pre_val ^ rows[j].value) & rows[j].mask & pre_mask))
			cand[nc++] = (uint16_t)j;
	bld_walk(&x, (int)x.nbits - 1, 0, cand, nc);
}

static unsigned count_dead(const unsigned char *hits, unsigned n)
{
	unsigned i, dead = 0;

	for (i = 0; i < n; i++)
		dead += !hits[i];
	return dead;
}

/*
 * THE AARCH64 LOOKUP ON THE TOP 11 BITS.
 *
 * An entry is an identity when the tree would give that identity for EVERY word
 * with those top bits, and L1_MORE (send the word down the tree) otherwise. It is
 * found without running words through the tree: the top bits are the bits known,
 * a row is skipped if they contradict it, taken if they fix everything it tests,
 * and if some row ahead of the answer tests a bit that is not known, or a row
 * carries a check, the entry is MORE. A node whose key is partly unknown is
 * answered only if every bucket its key can still select agrees. That is
 * conservative - it never claims an identity the tree would not give - and
 * tests/lib/genome/genotype_arm64.c compares it with the tree.
 *
 * MEASURED over 8.3 M words of real AArch64 code (118 Mirai-family ELF files),
 * one thread: the tree alone costs 12.6 ns a word; with this lookup 5.5 ns, and
 * the whole adapter path 18.3 ns against 20.0 for the decoder it replaced. The
 * lookup answers 83.3% of those words (the 17% that walk the tree are ret,
 * orr, hint, logical immediates, ldur and register-offset loads). A key of 10,
 * 9 or 8 bits more changed nothing.
 */
static unsigned resolve_node(const struct kgenome_arm64_node *n, uint32_t km, uint32_t kv);

static unsigned resolve_rows(const struct kgenome_arm64_row *r, uint32_t km, uint32_t kv)
{
	for (;; r++) {
		if ((kv ^ r->val) & km & r->mask)
			continue;               /* a known bit contradicts the row */
		if (r->mask & ~km)
			return L1_MORE;         /* the row tests a bit that is not known */
		if (r->fl)
			return L1_MORE;
		if (r->id >= KGENOME_ARM64_NODE0)
			return resolve_node(kgenome_arm64_nodes[r->id - KGENOME_ARM64_NODE0], km, kv);
		return r->id;
	}
}

static unsigned resolve_node(const struct kgenome_arm64_node *n, uint32_t km, uint32_t kv)
{
	unsigned w0 = (unsigned)__builtin_popcount(n->m0);
	unsigned nb = w0 + (unsigned)__builtin_popcount(n->m1), i;
	unsigned res = L1_MORE, kk = 0, kval = 0, fr, sub;
	int first = 1;

	/*
	 * ONLY THE KEYS THE KNOWN BITS ALLOW ARE VISITED. This tried all 2^nb keys,
	 * rebuilt each one bit by bit and then threw away the ones that contradict
	 * a known bit: MEASURED on a 95 KB A64 ELF (callgrind, whole scan 57.2 M Ir)
	 * the table build was 8.3 M Ir, 14.5% of the scan. A key bit whose position
	 * is known is fixed by it, and the free ones are enumerated as the subsets
	 * of their mask - the same keys, in the same increasing order, so the answer
	 * is the one it was.
	 */
	for (i = 0; i < nb; i++) {
		unsigned pos = i < w0 ? n->sh0 + i : n->sh1 + (i - w0);

		if ((km >> pos) & 1u) {
			kk |= 1u << i;
			kval |= ((kv >> pos) & 1u) << i;
		}
	}
	fr = (unsigned)((1ull << nb) - 1u) & ~kk;
	sub = 0;
	do {
		unsigned id = resolve_rows(n->b[kval | sub], km, kv);

		if (id == L1_MORE || (!first && id != res))
			return L1_MORE;
		res = id;
		first = 0;
		sub = (sub - fr) & fr;
	} while (sub);
	return res;
}

/* Everything the decoders index, from the rows. */
static void armidx_build(struct armidx *o)
{
	static unsigned char hc[MAXROWS], hu[MAXROWS], hn[MAXROWS], hw[MAXROWS];
	struct bld_pool pa = { o->arm_lists, ARM_POOL, 0 };
	struct bld_pool pt = { o->thumb_lists, THUMB_POOL, 0 };
	const struct bld_job cond = { kgenome_arm32_src_cond, kgenome_arm32_src_cond_n,
				      KGENOME_ARM32_KEYS, key_arm32, 0, 0, 0, o->arm_idx, hc };
	const struct bld_job unc = { kgenome_arm32_src_unc, kgenome_arm32_src_unc_n,
				     KGENOME_ARM32_KEYS, key_arm32, 0xf0000000u, 0xf0000000u, 0,
				     o->arm_idx + KGENOME_ARM32_KEYS, hu };
	const struct bld_job narrow = { kgenome_thumb_src_narrow, kgenome_thumb_src_narrow_n,
					KGENOME_THUMB_NARROW_KEYS, key_narrow, 0, 0, 1, o->thumb_narrow, hn };
	const struct bld_job wide = { kgenome_thumb_src_wide, kgenome_thumb_src_wide_n,
				      KGENOME_THUMB_WIDE_KEYS, key_wide, 0, 0, 1, o->thumb_wide, hw };
	unsigned k;

	memset(o, 0, sizeof *o);
	pa.pool = o->arm_lists;
	pt.pool = o->thumb_lists;
	memset(hc, 0, sizeof hc);
	memset(hu, 0, sizeof hu);
	memset(hn, 0, sizeof hn);
	memset(hw, 0, sizeof hw);
	build_one(&cond, &pa);
	build_one(&unc, &pa);
	o->arm_used = pa.used;
	o->shadowed_arm32 = count_dead(hc, kgenome_arm32_src_cond_n) + count_dead(hu, kgenome_arm32_src_unc_n);
	build_one(&narrow, &pt);
	build_one(&wide, &pt);
	o->thumb_used = pt.used;
	o->shadowed_thumb = count_dead(hn, kgenome_thumb_src_narrow_n) + count_dead(hw, kgenome_thumb_src_wide_n);
	for (k = 0; k < L1_N; k++)
		o->l1[k] = (uint16_t)resolve_node(&kgenome_arm64_top, ~0u << L1_SHIFT, k << L1_SHIFT);
}

#ifndef ARMIDX_NO_MAIN
static void put_u16(FILE *f, const char *decl, const uint16_t *v, unsigned n)
{
	unsigned i;

	fprintf(f, "%s[%u] = {", decl, n);
	for (i = 0; i < n; i++)
		fprintf(f, "%s%s%u", i ? "," : "", i % 16u ? " " : "\n\t", v[i]);
	fprintf(f, "\n};\n\n");
}

static void put_rows(FILE *f, const char *decl, const struct kgenome_arm32_row *r, unsigned n)
{
	unsigned i;

	fprintf(f, "%s[%u] = {\n", decl, n);
	for (i = 0; i < n; i++)
		fprintf(f, "\t{ 0x%08xu, 0x%08xu, %u },\n", r[i].mask, r[i].value, r[i].id);
	fprintf(f, "};\n\n");
}

int main(int argc, char **argv)
{
	static struct armidx o;
	char path[1024];
	FILE *f;

	if (argc != 2) {
		fprintf(stderr, "usage: arm_index_gen <libgenome/genotype>\n");
		return 2;
	}
	armidx_build(&o);

	snprintf(path, sizeof path, "%s/arm32/arm32_index_tab.c", argv[1]);
	f = fopen(path, "w");
	if (!f)
		return 1;
	fprintf(f, "/* Generated by tools/genotype/arm_index_gen.c - do not edit. `make genotype-arm-index` writes it. */\n"
		   "#include \"arm32_private.h\"\n\n");
	put_rows(f, "const struct kgenome_arm32_row kgenome_arm32_lists", o.arm_lists, o.arm_used);
	put_u16(f, "const uint16_t kgenome_arm32_idx", o.arm_idx, 2 * KGENOME_ARM32_KEYS);
	put_rows(f, "const struct kgenome_arm32_row kgenome_thumb_lists", o.thumb_lists, o.thumb_used);
	put_u16(f, "const uint16_t kgenome_thumb_idx_narrow", o.thumb_narrow, KGENOME_THUMB_NARROW_KEYS);
	put_u16(f, "const uint16_t kgenome_thumb_idx_wide", o.thumb_wide, KGENOME_THUMB_WIDE_KEYS);
	fprintf(f, "const struct kgenome_arm32_stats kgenome_arm32_index_stats = { %u, %u, %u, %u, %u, %u };\n",
		o.shadowed_arm32, o.shadowed_thumb, o.arm_used, o.thumb_used, ARM_POOL, THUMB_POOL);
	if (fclose(f))
		return 1;

	snprintf(path, sizeof path, "%s/arm64/arm64_l1_tab.c", argv[1]);
	f = fopen(path, "w");
	if (!f)
		return 1;
	fprintf(f, "/* Generated by tools/genotype/arm_index_gen.c - do not edit. `make genotype-arm-index` writes it. */\n"
		   "#include \"arm64_private.h\"\n\n");
	put_u16(f, "const uint16_t kgenome_arm64_l1", o.l1, L1_N);
	return fclose(f) ? 1 : 0;
}
#endif /* ARMIDX_NO_MAIN */
