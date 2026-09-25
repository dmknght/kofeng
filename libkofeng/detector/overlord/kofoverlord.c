/*
 * kofoverlord.c - the two-track comparison.
 */

#include "kofoverlord.h"

#include <string.h>

#include <kofmod/elf.h>
#include <kofmod/kofplague.h>
#include "../matchers/kofplague.h"
#include "../../kofcore/rangelist.h"

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

int kof_ovl_build(struct kof_ovl_desc *d, kof_buf file,
		  const struct kof_elf_info *e,
		  const struct kof_range *lib_span, uint32_t lib_n)
{
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
		if (lib_n)
			kof_rl_subtract(&kl, lib_span, lib_n);
		kof_rl_normalise(&kl);

		/* The block hashes of the span the library is already out of. */
		for (k = 0; k < kl.n; k++)
			if (d->n_blk < KOF_OVL_MAX_BLOCKS)
				d->n_blk += kof_plague_hash_span(
					file.p + keep[k].off, keep[k].len,
					KOF_PLAGUE_RAW, d->blk + d->n_blk,
					KOF_OVL_MAX_BLOCKS - d->n_blk);
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

		/*
		 * n_region IS BOUNDED HERE TOO, not only where it is built.
		 *
		 * la[] and lb[] are KOF_OVL_MAX_REGIONS long and `na`/`nb`
		 * count into them, so a desc whose n_region says more than the
		 * region[] array holds would write past both. kof_ovl_build
		 * caps it, and the module-side twin in kofmod/kofoverlord.h
		 * writes `i < s->n_region && i < KOF_OVL_MAX_REGIONS` for
		 * exactly this reason - this side was the one that trusted the
		 * count.
		 */
		for (i = 0; i < a->n_region && i < KOF_OVL_MAX_REGIONS; i++)
			if (a->region[i].x == want)
				la[na++] = (uint8_t)i;
		for (i = 0; i < b->n_region && i < KOF_OVL_MAX_REGIONS; i++)
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
	uint32_t n, i;
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

		v->ptype_jac = (uint16_t)(cu ? (ci * 1000u) / cu : 0u);
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

		v->anom_jac  = (uint16_t)(cu ? (ci * 1000u) / cu : 0u);
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
	}
	if (n) {
		v->reg_size = worst;
		v->applied |= KOF_OVL_D_REGSIZE;
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
	case KOF_OVL_STRUCTURE: return "structure";
	case KOF_OVL_ANCHOR:    return "anchor";
	default:                return track ? "mixed" : "none";
	}
}

/*
 * CONTAINMENT OVER TWO SORTED SETS, ONCE.
 *
 * The string set is sixty-four bit hashes and the block set is thirty-two, so
 * these were the same eleven lines written twice with one word changed. They
 * are one function now, and `wide` is a constant at both call sites - so the
 * compiler still emits two specialised loops and the merge is the same
 * instructions it was, with one place to change if the answer ever should.
 *
 * CONTAINMENT AND NOT JACCARD, which is the part both callers must agree on:
 * how much of the REFERENCE is here, so a variant that added a string or grew
 * a function is still the same program. See kof_ovl_blocks_pct in the header
 * for why the other question is the wrong one.
 *
 * Both sides are sorted and deduplicated at build time - see kof_ovl_build -
 * so this is a merge and not a set membership test.
 */
static inline uint32_t contain_pct(const void *obj, uint32_t n_obj,
				   const void *ref, uint32_t n_ref, int wide)
{
	const uint64_t *o8 = obj, *r8 = ref;
	const uint32_t *o4 = obj, *r4 = ref;
	uint32_t i = 0, j = 0, in = 0;

	if (!obj || !ref || !n_obj || !n_ref)
		return 0;
	while (i < n_obj && j < n_ref) {
		uint64_t a = wide ? o8[i] : o4[i];
		uint64_t b = wide ? r8[j] : r4[j];

		if (a == b) {
			in++; i++; j++;
		} else if (a < b) {
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
	return contain_pct(obj, n_obj, ref, n_ref, 0);
}
