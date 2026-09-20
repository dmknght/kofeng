/*
 * kofoverlord.c - the two-track comparison.
 */

#include "kofoverlord.h"

#include <string.h>

#include <kofmod/elf.h>
#include <kofmod/kofplague.h>
#include "../kofmatchers/kofplague.h"
#include "../kofparsers/rangelist.h"

#define PT_LOAD 1u

/*
 * WHICH ANOMALIES COUNT AS DAMAGE.
 *
 * Not all of them, and the difference was measured. SECTAB_MISSING means the
 * binary was stripped - a normal state, present in 8% of the clean objects here
 * and 30% of the botnet ones - and SECNAME_TRUNC is a limit of this engine's
 * own record rather than a fact about the file. Neither is evidence that two
 * objects were damaged the same way, and counting them made the anchor track
 * fire on 28% of the corpus in place of the 4% it was measured at.
 *
 * What is left is inconsistency: a table that points past the end, a segment
 * that does not fit, an entry point outside anything mapped. Those are things
 * a linker does not produce.
 */
#define OVL_DAMAGE (~(uint64_t)(KOF_ELF_ANOM_SECTAB_MISSING | \
			        KOF_ELF_ANOM_SECNAME_TRUNC))

/* FNV-1a, 64 bit. A string is kept as its hash: the sets are compared and
 * never read back, and sixty-four bits over a few hundred strings makes a
 * collision a thing that does not happen in practice. */
static uint64_t str_hash(const uint8_t *p, uint64_t n)
{
	uint64_t h = 1469598103934665603ull;
	uint64_t i;

	for (i = 0; i < n; i++) {
		h ^= p[i];
		h *= 1099511628211ull;
	}
	return h;
}

static int printable(uint8_t c) { return c >= 0x20u && c < 0x7fu; }

static void sort_u32(uint32_t *v, uint32_t n)
{
	uint32_t i, j;

	for (i = 1; i < n; i++) {
		uint32_t k = v[i];

		for (j = i; j && v[j - 1] > k; j--)
			v[j] = v[j - 1];
		v[j] = k;
	}
}

static uint32_t dedup_u32(uint32_t *v, uint32_t n)
{
	uint32_t i, w = 0;

	for (i = 0; i < n; i++)
		if (!w || v[w - 1] != v[i])
			v[w++] = v[i];
	return w;
}

static void sort_u64(uint64_t *v, uint32_t n)
{
	uint32_t i, j;

	for (i = 1; i < n; i++) {
		uint64_t k = v[i];

		for (j = i; j && v[j - 1] > k; j--)
			v[j] = v[j - 1];
		v[j] = k;
	}
}

static uint32_t dedup_u64(uint64_t *v, uint32_t n)
{
	uint32_t i, w = 0;

	for (i = 0; i < n; i++)
		if (!w || v[w - 1] != v[i])
			v[w++] = v[i];
	return w;
}

/* Per-mille, saturating, and never dividing by zero. */
static uint16_t permille(uint64_t a, uint64_t b)
{
	uint64_t lo, hi;

	if (!a || !b)
		return 0;
	lo = a < b ? a : b;
	hi = a < b ? b : a;
	return (uint16_t)((lo * 1000u) / hi);
}

/* Jaccard of two SORTED slices, per mille. Sorted at build time so this is a
 * merge and not a set: a descriptor is compared many times and sorting once is
 * the difference between a linear pass and a hash table per comparison. */
static uint16_t jaccard(const uint64_t *a, uint32_t na,
			const uint64_t *b, uint32_t nb)
{
	uint32_t i = 0, j = 0, inter = 0, uni;

	if (!na || !nb)
		return 0;
	while (i < na && j < nb) {
		if (a[i] == b[j]) {
			inter++; i++; j++;
		} else if (a[i] < b[j]) {
			i++;
		} else {
			j++;
		}
	}
	uni = na + nb - inter;
	return uni ? (uint16_t)(((uint64_t)inter * 1000u) / uni) : 0;
}

/*
 * Collect the printable runs of one span into the pool.
 *
 * The span is already the part of the region the library does not own - see
 * kof_ovl_build - so everything found here is the author's, which is what makes
 * a later match evidence of identity rather than of a shared build.
 */
static void collect(struct kof_ovl_desc *d, const uint8_t *p, uint64_t n)
{
	uint64_t i = 0;

	while (i < n) {
		uint64_t s;

		if (!printable(p[i])) {
			i++;
			continue;
		}
		s = i;
		while (i < n && printable(p[i]))
			i++;
		if (i - s < KOF_OVL_MIN_STRING)
			continue;
		if (d->n_str >= KOF_OVL_MAX_STRINGS) {
			d->truncated = 1;
			return;
		}
		d->str[d->n_str++] = str_hash(p + s, i - s);
	}
}

int kof_ovl_build(struct kof_ovl_desc *d, kof_buf file,
		  const struct kof_elf_info *e)
{
	struct kof_lib_result lib;
	uint32_t si;

	if (!d)
		return 0;
	memset(d, 0, sizeof *d);
	if (!file.p || !file.n || !e || !e->valid || !e->load_count)
		return 0;

	d->fsize     = file.n;
	d->cls       = e->elf_class;
	d->end       = e->elf_data;
	d->etype     = e->e_type;
	d->machine   = e->e_machine;
	d->anomalies = e->anomalies & OVL_DAMAGE;

	kof_lib_find(file, e, &lib);

	for (si = 0; si < e->seg_count && si < KOF_ELF_MAX_SEGMENTS; si++) {
		const struct kof_elf_seg *g = &e->seg[si];
		struct kof_ovl_region *r;
		struct kof_range keep[KOF_LIB_MAX_SPANS + 2];
		struct kof_rlist kl;
		uint64_t len;
		uint32_t k;

		if (g->type < 32u)
			d->ptypes |= 1u << g->type;
		if (g->type != PT_LOAD)
			continue;
		if (d->n_region >= KOF_OVL_MAX_REGIONS) {
			d->truncated = 1;
			break;
		}
		if (g->file_off >= file.n)
			continue;
		len = file.n - g->file_off;
		if (len > g->file_size)
			len = g->file_size;

		r = &d->region[d->n_region];
		r->fsz = len;
		r->x   = (g->perm & KOF_PERM_X) != 0;

		/* The region, minus whatever the library owns of it. */
		kof_rl_init(&kl, keep, (uint32_t)(sizeof keep / sizeof keep[0]));
		kof_rl_add(&kl, file.n, g->file_off, len);
		if (lib.n)
			kof_rl_subtract(&kl, lib.span, lib.n);
		kof_rl_normalise(&kl);

		r->str_off = d->n_str;
		for (k = 0; k < kl.n; k++) {
			collect(d, file.p + keep[k].off, keep[k].len);
			/* And the block hashes of the same bytes - one pass
			 * each, over the same span the library is already out
			 * of. */
			if (d->n_blk < KOF_OVL_MAX_BLOCKS)
				d->n_blk += kof_plague_hash_span(
					file.p + keep[k].off, keep[k].len,
					KOF_PLAGUE_RAW, d->blk + d->n_blk,
					KOF_OVL_MAX_BLOCKS - d->n_blk);
		}
		sort_u64(d->str + r->str_off, d->n_str - r->str_off);
		d->n_str = r->str_off +
			   dedup_u64(d->str + r->str_off, d->n_str - r->str_off);
		r->str_n = d->n_str - r->str_off;
		d->n_region++;
	}
	sort_u32(d->blk, d->n_blk);
	d->n_blk = dedup_u32(d->blk, d->n_blk);
	return d->n_region ? 1 : 0;
}

/*
 * PAIRING IS BY EXECUTABILITY AND SIZE RANK, NEVER BY INDEX.
 *
 * Two builds of one program can differ by a segment - a toolchain that emits a
 * separate read-only segment, a PT_GNU_RELRO that splits one in two - and an
 * index pairing then compares a code region against a data one, after which
 * every dimension is noise. Executable first because it is what the region IS;
 * size rank second because within one kind the largest is the same thing in
 * both objects.
 */
static uint32_t pair_regions(const struct kof_ovl_desc *a,
			     const struct kof_ovl_desc *b,
			     uint8_t *ia, uint8_t *ib)
{
	uint32_t n = 0, pass;

	for (pass = 0; pass < 2; pass++) {
		uint8_t want = pass == 0;
		uint8_t la[KOF_OVL_MAX_REGIONS], lb[KOF_OVL_MAX_REGIONS];
		uint32_t na = 0, nb = 0, i, j, k;

		for (i = 0; i < a->n_region; i++)
			if (a->region[i].x == want)
				la[na++] = (uint8_t)i;
		for (i = 0; i < b->n_region; i++)
			if (b->region[i].x == want)
				lb[nb++] = (uint8_t)i;
		/* descending by size - insertion, at most eight */
		for (i = 1; i < na; i++)
			for (j = i; j && a->region[la[j - 1]].fsz <
					a->region[la[j]].fsz; j--) {
				uint8_t t = la[j]; la[j] = la[j - 1]; la[j - 1] = t;
			}
		for (i = 1; i < nb; i++)
			for (j = i; j && b->region[lb[j - 1]].fsz <
					b->region[lb[j]].fsz; j--) {
				uint8_t t = lb[j]; lb[j] = lb[j - 1]; lb[j - 1] = t;
			}
		for (k = 0; k < na && k < nb && n < KOF_OVL_MAX_REGIONS; k++) {
			ia[n] = la[k];
			ib[n] = lb[k];
			n++;
		}
	}
	return n;
}

static uint32_t popcount32(uint32_t x)
{
	uint32_t n = 0;

	while (x) { n += x & 1u; x >>= 1; }
	return n;
}

static uint32_t popcount64(uint64_t x)
{
	uint32_t n = 0;

	while (x) { n += (uint32_t)(x & 1u); x >>= 1; }
	return n;
}

void kof_ovl_compare(const struct kof_ovl_desc *a, const struct kof_ovl_desc *b,
		     struct kof_ovl_vec *v)
{
	uint8_t ia[KOF_OVL_MAX_REGIONS], ib[KOF_OVL_MAX_REGIONS];
	uint32_t n, i, str_sum = 0, str_cnt = 0;
	uint16_t worst = 1000;

	if (!v)
		return;
	memset(v, 0, sizeof *v);
	if (!a || !b || !a->n_region || !b->n_region)
		return;

	v->cls_match   = (a->cls == b->cls && a->end == b->end);
	v->etype_match = (a->etype == b->etype);
	v->same_arch   = (a->machine == b->machine);
	v->nload_match = (a->n_region == b->n_region);

	v->size_ratio = permille(a->fsize, b->fsize);
	v->applied |= KOF_OVL_D_SIZE;

	if (a->ptypes || b->ptypes) {
		uint32_t ci = popcount32(a->ptypes & b->ptypes);
		uint32_t cu = popcount32(a->ptypes | b->ptypes);

		v->ptype_jac = cu ? (uint16_t)((ci * 1000u) / cu) : 0;
		v->applied |= KOF_OVL_D_PTYPE;
	}
	/*
	 * Shared header damage. Both broken is the anchor; one broken against
	 * one intact is a real disagreement, so the dimension applies in both
	 * cases. Neither broken tells us nothing and does not apply.
	 */
	if (a->anomalies || b->anomalies) {
		uint32_t ci = popcount64(a->anomalies & b->anomalies);
		uint32_t cu = popcount64(a->anomalies | b->anomalies);

		v->anom_jac  = cu ? (uint16_t)((ci * 1000u) / cu) : 0;
		v->anom_both = (a->anomalies && b->anomalies);
		v->applied |= KOF_OVL_D_ANOM;
	}

	n = pair_regions(a, b, ia, ib);
	for (i = 0; i < n; i++) {
		const struct kof_ovl_region *ra = &a->region[ia[i]];
		const struct kof_ovl_region *rb = &b->region[ib[i]];
		uint16_t s = permille(ra->fsz, rb->fsz);

		if (s < worst)
			worst = s;
		/*
		 * A region with no strings on either side did not fail to
		 * match; there was nothing to match, and averaging a zero in
		 * would punish a pair that agrees everywhere it can.
		 */
		if (ra->str_n || rb->str_n) {
			uint16_t j = jaccard(a->str + ra->str_off, ra->str_n,
					     b->str + rb->str_off, rb->str_n);

			str_sum += j;
			str_cnt++;
			if (j > v->str_max)
				v->str_max = j;
		}
	}
	if (n) {
		v->reg_size = worst;
		v->applied |= KOF_OVL_D_REGSIZE;
	}
	if (str_cnt) {
		v->str_mean = (uint16_t)(str_sum / str_cnt);
		v->applied |= KOF_OVL_D_STRINGS;
	}
}

/*
 * THE RULES.
 *
 * Conjunctions, measured. Each was required to fire on none of one half of the
 * clean corpus and was then counted against the other half, which it had never
 * seen; all three hold at zero on both.
 *
 * Class, endianness and type must match in every rule and are not negotiable: a
 * 32-bit object and a 64-bit one are not builds of the same program, whatever
 * else agrees.
 */
uint32_t kof_ovl_verdict(const struct kof_ovl_vec *v)
{
	uint32_t track = 0;

	if (!v || !v->cls_match || !v->etype_match)
		return KOF_OVL_NONE;

	/*
	 * STRINGS. Content, after the library was taken out. The threshold is
	 * low because what it is over is small and entirely the author's: 0.20
	 * of what a program wrote is a great deal of a program, while 0.20 of a
	 * file that still had its libc in it would be the libc.
	 */
	if ((v->applied & KOF_OVL_D_STRINGS) && v->str_mean >= 200)
		track |= KOF_OVL_STRINGS;

	/*
	 * STRUCTURE. No content at all, which is what lets it answer when the
	 * payload is ciphertext - and it is tight in compensation: the
	 * worst-fitting region within 30%, the file sizes within 30%, the same
	 * number of loadable regions, the segment table identical.
	 */
	if ((v->applied & (KOF_OVL_D_REGSIZE | KOF_OVL_D_PTYPE | KOF_OVL_D_SIZE)) ==
	    (KOF_OVL_D_REGSIZE | KOF_OVL_D_PTYPE | KOF_OVL_D_SIZE) &&
	    v->nload_match && v->reg_size >= 700 && v->size_ratio >= 700 &&
	    v->ptype_jac >= 1000)
		track |= KOF_OVL_STRUCTURE;

	/*
	 * ANCHOR. Two objects damaged the same way that are also the same
	 * shape. Weak alone - it fired on 4.4% of the corpus - and kept because
	 * damage is an anchor rather than a coincidence, and because what it
	 * catches it catches at no cost beside the other two.
	 */
	if ((v->applied & (KOF_OVL_D_ANOM | KOF_OVL_D_REGSIZE)) ==
	    (KOF_OVL_D_ANOM | KOF_OVL_D_REGSIZE) &&
	    v->anom_both && v->anom_jac >= 500 &&
	    v->reg_size >= 300 && v->size_ratio >= 300)
		track |= KOF_OVL_ANCHOR;

	return track;
}

const char *kof_ovl_track_name(uint32_t track)
{
	switch (track) {
	case KOF_OVL_STRINGS:   return "strings";
	case KOF_OVL_STRUCTURE: return "structure";
	case KOF_OVL_ANCHOR:    return "anchor";
	default:                return track ? "mixed" : "none";
	}
}

uint32_t kof_ovl_strings_pct(const uint64_t *obj, uint32_t n_obj,
			     const uint64_t *ref, uint32_t n_ref)
{
	uint32_t i = 0, j = 0, in = 0;

	if (!obj || !ref || !n_obj || !n_ref)
		return 0;
	while (i < n_obj && j < n_ref) {
		if (obj[i] == ref[j]) {
			in++; i++; j++;
		} else if (obj[i] < ref[j]) {
			i++;
		} else {
			j++;
		}
	}
	return (uint32_t)(((uint64_t)in * 100u) / n_ref);
}

uint32_t kof_ovl_blocks_pct(const uint32_t *obj, uint32_t n_obj,
			    const uint32_t *ref, uint32_t n_ref)
{
	uint32_t i = 0, j = 0, in = 0;

	if (!obj || !ref || !n_obj || !n_ref)
		return 0;
	while (i < n_obj && j < n_ref) {
		if (obj[i] == ref[j]) {
			in++; i++; j++;
		} else if (obj[i] < ref[j]) {
			i++;
		} else {
			j++;
		}
	}
	return (uint32_t)(((uint64_t)in * 100u) / n_ref);
}
