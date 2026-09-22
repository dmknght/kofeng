/*
 * kofmod/kofoverlord.h - declaring the SHAPE of a reference object, and asking
 * how near the object in hand is to it.
 *
 * WHAT THIS IS FOR. A signature says "these bytes are that family" and a plague
 * block says "this run of code came from it". Both are claims about CONTENT,
 * and both go quiet on an object whose content has been encrypted - which, for
 * the corpus this was built against, is most of them. A shape asks the other
 * question: is this the same program, judged only by what the builder produced
 * - how big the file is, how many loadable regions and how big each, which
 * program header types are there. Encrypting a payload changes none of that.
 *
 * Measured: 71.5% of 925 deduplicated IoT-botnet ELFs matched another sample on
 * shape alone, at zero false positives against 3870 clean objects, 1000 of them
 * adversarially packed.
 *
 *
 * HEADER ONLY, AND THAT IS THE POINT
 *
 * A shape is a hundred-odd bytes of constants and the comparison is a handful
 * of divisions, so the rule carries the shape in its own .rodata and the
 * arithmetic is inlined. No section in the pack, no entry in the module ABI,
 * nothing for ksigbuilder to learn - and, more to the point, ONE DEFINITION of
 * what "alike" means, in a header both the rule and the generator include. Two
 * spellings of this would be two rules that disagree about the same file.
 *
 *
 * ONE PERCENTAGE, AND IT IS STILL A CONJUNCTION
 *
 * kof_ovl_shape_pct answers with the WORST-agreeing dimension, never an average
 * of them. So `>= 70` means EVERY dimension agrees to at least seventy percent,
 * which is exactly the rule that measured zero false positives; an average
 * would let a perfect match on one dimension pay for a total disagreement on
 * another, and no threshold recovers what that kind of sum destroys.
 *
 * Three facts are not percentages at all and answer zero when they differ:
 * class, endianness and object type. A 32-bit object and a 64-bit one are not
 * builds of the same program, and "eighty percent alike" about them would be
 * answering a question nobody asked. The same goes for the segment table: two
 * builds of one program have the same program header types, and one that gained
 * a PT_GNU_RELRO came from a different toolchain.
 */

#ifndef KOFMOD_KOFOVERLORD_H
#define KOFMOD_KOFOVERLORD_H

#include <stdint.h>
#include <kofmod/elf.h>

/*
 * Loadable regions a shape holds. An ELF the linker produced has two to four;
 * the objects with more are not programs.
 */
#define KOF_OVL_MAX_REGIONS 8u

/*
 * A reference object's shape, as a rule declares it.
 *
 * Written by the generator in kofviewer, from a sample somebody identified.
 * Nobody types one: every field is read off that file.
 */
struct kof_ovl_shape {
	uint64_t fsize;
	uint64_t region_fsz[KOF_OVL_MAX_REGIONS];
	uint32_t ptypes;      /* bit per p_type value below 32 */
	uint16_t etype;
	uint8_t  cls;         /* KOF_ELFCLASS_*  */
	uint8_t  end;         /* KOF_ELFDATA_*   */
	uint8_t  n_region;
	uint8_t  region_x[KOF_OVL_MAX_REGIONS];   /* executable? */
};

/* ELF's own value for a loadable segment. */
#define KOF_OVL_PT_LOAD 1u

/* Per cent of the smaller over the larger; zero when either side is empty. */
static inline uint32_t kof_ovl_ratio_pct(uint64_t a, uint64_t b)
{
	uint64_t lo, hi;

	if (!a || !b)
		return 0;
	lo = a < b ? a : b;
	hi = a < b ? b : a;
	return (uint32_t)((lo * 100u) / hi);
}

/*
 * THE OBJECT IN HAND, AS A SHAPE.
 *
 * One definition, used by the rule when it compares and by the generator when
 * it writes a reference down. Two spellings of "which regions does this object
 * have" would be a rule that measures something the generator never recorded.
 */
static inline void kof_ovl_shape_of(const struct kof_elf_info *e,
				    uint64_t file_size,
				    struct kof_ovl_shape *s)
{
	uint32_t i;

	if (!s)
		return;
	for (i = 0; i < sizeof *s; i++)
		((unsigned char *)s)[i] = 0;
	if (!e || !e->valid)
		return;
	s->fsize = file_size;
	s->etype = e->e_type;
	s->cls   = e->elf_class;
	s->end   = e->elf_data;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *g = &e->seg[i];
		uint64_t len;

		if (g->type < 32u)
			s->ptypes |= 1u << g->type;
		if (g->type != KOF_OVL_PT_LOAD || !g->file_size)
			continue;
		if (s->n_region >= KOF_OVL_MAX_REGIONS ||
		    g->file_off >= file_size)
			continue;
		len = file_size - g->file_off;
		if (len > g->file_size)
			len = g->file_size;
		s->region_fsz[s->n_region] = len;
		s->region_x[s->n_region]   = (g->perm & KOF_PERM_X) != 0;
		s->n_region++;
	}
}

/*
 * HOW ALIKE, nought to a hundred, worst dimension first.
 *
 * `e` is the object in hand, as kof_elf(ctx) gives it. Zero when the two cannot
 * be builds of the same program at all - see the header note - and zero when
 * either side has no loadable region, which is the same answer as "nothing
 * agreed" and is one a rule must not try to tell apart.
 */
static inline uint32_t kof_ovl_shape_pct(const struct kof_elf_info *e,
					 const struct kof_ovl_shape *s,
					 uint64_t file_size)
{
	struct kof_ovl_shape cur;
	uint32_t worst, i, j, pass, paired = 0;

	if (!e || !s || !s->n_region)
		return 0;
	kof_ovl_shape_of(e, file_size, &cur);
	if (!cur.n_region || cur.n_region != s->n_region)
		return 0;
	if (cur.cls != s->cls || cur.end != s->end || cur.etype != s->etype)
		return 0;
	if (cur.ptypes != s->ptypes)
		return 0;

	worst = kof_ovl_ratio_pct(cur.fsize, s->fsize);

	/*
	 * PAIRED BY EXECUTABILITY AND SIZE RANK, NEVER BY INDEX. Two builds of
	 * one program can list their segments in a different order; by index
	 * that compares a code region against a data one and everything after
	 * is noise.
	 */
	for (pass = 0; pass < 2; pass++) {
		unsigned char want = pass == 0;
		unsigned char la[KOF_OVL_MAX_REGIONS], lb[KOF_OVL_MAX_REGIONS];
		uint32_t na = 0, nb = 0, k;

		for (i = 0; i < cur.n_region; i++)
			if (cur.region_x[i] == want)
				la[na++] = (unsigned char)i;
		for (i = 0; i < s->n_region && i < KOF_OVL_MAX_REGIONS; i++)
			if (s->region_x[i] == want)
				lb[nb++] = (unsigned char)i;
		for (i = 1; i < na; i++)
			for (j = i; j && cur.region_fsz[la[j - 1]] <
					cur.region_fsz[la[j]]; j--) {
				unsigned char t = la[j];
				la[j] = la[j - 1]; la[j - 1] = t;
			}
		for (i = 1; i < nb; i++)
			for (j = i; j && s->region_fsz[lb[j - 1]] <
					s->region_fsz[lb[j]]; j--) {
				unsigned char t = lb[j];
				lb[j] = lb[j - 1]; lb[j - 1] = t;
			}
		for (k = 0; k < na && k < nb; k++) {
			uint32_t p = kof_ovl_ratio_pct(cur.region_fsz[la[k]],
						       s->region_fsz[lb[k]]);

			if (p < worst)
				worst = p;
			paired++;
		}
	}
	if (!paired)
		return 0;
	return worst > 100u ? 100u : worst;
}

/*
 * The rule-facing spelling, so a module reads like the plague one beside it:
 *
 *     if (kof_ovl_shape(ref_50d7781f) >= 70u)
 *             KOF_SCAN_SUSPECT(KOF_MALVAR_AUTO);
 *
 * SUSPECT and not INFECT is the generator's default and the reason is in the
 * question this asks: a shape says the object came out of the same BUILDER, not
 * that it is the same family. A Mirai-derived builder that produced a coinminer
 * is a true shape match and a false family name.
 */
#define kof_ovl_shape(ref) kof_ovl_shape_pct(kof_elf(ctx), &(ref), (ctx)->obj_size)

/*
 * A CALL CHAIN, AS SOMETHING A RULE CAN CARRY.
 *
 * What the code DOES: which capabilities it asks the system for, in order,
 * which of them carry a program-level flag, and which took an argument an
 * earlier one produced. See kofoverlord/ovlflow.h for how one is read out of
 * code, and kof_ovl_chain in kofmod/kofsig.h for how a rule asks about one.
 *
 * NO ADDRESSES AND NO INDICES. kof_flow_node - the engine's working record -
 * holds a virtual address, a function number and a step count, and none of
 * those survives a rebuild or belongs in a signature. What survives is the
 * shape, and a stored chain is exactly the shape.
 *
 * Fixed and small, because a rule's reference lands in the module's .rodata
 * beside its strings and its block hashes, and a reference that needed an
 * allocation would be one somebody has to remember to free.
 */
struct kof_ovlf_step {
	uint8_t cap;    /* enum kof_flow_cap - kofdisasm/flow.h */
	/*
	 * The KOF_FLOWF_* bits that are about the PROGRAM: in a loop, the
	 * value was later branched to, the import was called through a
	 * register, the page is writable and executable at once. The bit that
	 * says how confidently the selector was decoded is not one of them and
	 * is never stored - that would be a rule about the decoder.
	 */
	uint8_t flags;
	/*
	 * THE LINK, as a distance and not an index.
	 *
	 * "Its buffer came from the step two before it" is the same claim in
	 * every build; "its buffer came from node 674" is a fact about one
	 * file. Only the first argument carrying one is kept: a rule that
	 * pinned all four would be pinning the calling convention.
	 *
	 * 0 means no link was seen, which is NOT the same as "there is none".
	 */
	uint8_t back;
};

/* Long enough for every shape measured so far - the longest chain holding an
 * alloc-exec in 1500 PE samples was 19 steps - and short enough that the
 * alignment table stays a few hundred cells. */
#define KOF_OVLF_CHAIN_MAX 24u

struct kof_ovlf_chain {
	struct kof_ovlf_step s[KOF_OVLF_CHAIN_MAX];
	uint8_t n;
};

#endif /* KOFMOD_KOFOVERLORD_H */
