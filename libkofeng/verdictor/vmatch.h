#ifndef KOF_VMATCH_H
#define KOF_VMATCH_H

/*
 * vmatch.h - the MATCHING LIBRARY of the verdict: how a sample's evidence compares with the profile of a malware variant, and how the
 * fired diagnoses are grouped by what they themselves declare. PURE: it reads the request, writes the caller's arrays, allocates
 * nothing, keeps no global and is safe on many threads. It is NOT wired into the scanner or the verdict composer yet (the pack carries
 * no family / variant / type per diagnose yet).
 *
 * THE MODEL (the owner's). A DISEASE is what a diagnose finds, from the engine's two lists (kofmod/diseaselist.h: ACT x OBJ). A
 * TAG is a named set of activities and objects (tagcat.h). MALWARE is family -> variant, each variant having a SET of malware
 * types (famcat.h). A DIAGNOSE is the detection unit and carries a family, a variant, ONE type and a tag. The type belongs to the
 * diagnose, never to the sample, the variant or the family. A variant's PROFILE D(v) is the union of the tags of ALL the diagnoses
 * that declare that variant (the caller forms it; this file takes it as a set of elements). The scan's evidence is D(x), the set of
 * tags of the diagnoses that FIRED on the sample x (this file forms it from the fired diagnoses: one fact, one carrier).
 *
 * THREE KINDS OF EVIDENCE. An element of a set is a (kind, a, b): KOF_VMATCH_TAG (a = tag id), KOF_VMATCH_FAMILY (a = family id) or
 * KOF_VMATCH_VARIANT (a = family id, b = variant id: a variant id is only read together with its family). Elements of different kinds
 * are never equal. D(x) holds the tag of every fired diagnose and, for a diagnose that declares a variant, its family and its
 * (family, variant), each only when the caller's `x_kinds` mask asks for that kind; D(v) is whatever elements the caller passes. The
 * numbers are returned per kind and in total, and the library WEIGHS NOTHING: no kind counts more than another, the caller reads the
 * per-kind numbers and decides what they mean.
 *
 * REUSE (read before writing, rule 2). The tree held no set similarity: verdict.c's kof_verdict_make picks a LEAD disease and names
 * it (that stays the verdict composer's), and the mutation matcher (detectors/mutations) scores byte-block hashes, kof_mutation_pct =
 * seen * 100 / n_hash. What is taken from the latter is its convention: integer counts, each element counted once, ONE division defined
 * once (here in vm_permille). The comparator and the sort of the sets are written here because kof_cmp_u32 compares one word and
 * qsort may allocate; nothing else of the old code is replaced or touched.
 *
 * SIMILARITY (a score, never a decision). For each candidate variant v:
 *     M = D(x) & D(v)    matched: seen in the sample and known of the variant
 *     U = D(v) \ D(x)    unseen:  known of the variant, not seen in the sample
 *     N = D(x) \ D(v)    extra:   seen in the sample, not in the variant's profile
 *     J = |M| / |D(x) | D(v)|, the Jaccard index, J = 1 when both sets are empty,
 * given as an INTEGER in permille, 0..1000, rounded DOWN (|M| * 1000 / |union|): no floating point. A set is a set: an element given
 * twice counts once. The same numbers are given per kind (J of the tags alone, of the families alone, of the variants alone; 1000 when
 * both of that kind are empty). The elements of M, U and N are listed (each ascending by kind, a, b) when the caller gives room.
 *
 * ATTRIBUTION is NOT computed by similarity. It is read from the fired diagnoses' own declarations: they are grouped by (family,
 * variant) and each group keeps the list of its diagnoses WITH THEIR OWN type (types are never merged into one type for the sample;
 * a variant that two diagnoses declare with two types keeps two entries and two types). A diagnose that declares no variant goes to ONE
 * group, `unattributed` (has_variant = 0). Groups are in the order of the first fired diagnose of each; the entries of a group are in
 * fired order. The similarity scores are reported beside each group (the score of the candidate with the same family and variant, when
 * the caller passed one) and for any further candidates the caller passes; they never change the groups. Nothing here names a family
 * from one common tag, and a tag that many variants share is not evidence of a family.
 *
 * WHAT IT DOES NOT DO. No threshold, no tie-break, no ranking, no verdict, no name: it returns every candidate with its numbers, in
 * the caller's order, and the caller sorts and decides. It does not parse or look up anything: tag, diagnose, family, variant and type
 * are plain 32-bit ids and no meaning is assumed of how they are made (0 is an id like any other; "no variant" is a flag, not an id).
 *
 * OUTPUTS AND BOUNDS. The caller owns every output array and gives its capacity (0 with a NULL array is allowed: counts only). An
 * array that is too small is never a silent cut: the result holds the TRUE totals (n_groups, n_entries, n_scores, n_elems), the arrays
 * hold the first `cap` elements of the full ordering, and the status is KOF_VMATCH_TRUNCATED. The ordering of elements is, per candidate,
 * M then U then N, candidates in order; a score's elem_first is its position in that ordering (it is valid even when the array ends
 * before it). The INPUT bounds are DoS bounds of this unit's work, each stated at its definition; an input past one is refused with
 * KOF_VMATCH_TOO_LARGE and its numbers are not computed (a refusal, not a wrong answer). Stack use is about 60 KB.
 */

#include <stdint.h>

#define KOF_VMATCH_TAG 0u
#define KOF_VMATCH_FAMILY 1u
#define KOF_VMATCH_VARIANT 2u
#define KOF_VMATCH_KINDS 3u

/* The most elements one candidate's profile may be given with (repeats count). Bounds the stack copy that is sorted for the merge: a
 * profile is a few dozen tags, and 1024 elements of 12 bytes sort in well under a millisecond. */
#define KOF_VMATCH_SET_MAX 1024u
/* The most fired diagnoses in one request. Bounds the quadratic grouping (n * groups compares, 1 million at most) and the stack
 * tables of the group of each diagnose; D(x) holds at most KOF_VMATCH_KINDS times this many elements (36 KB of stack). */
#define KOF_VMATCH_FIRED_MAX 1024u
/* The most candidate variants in one request. Bounds the lookup of a group's candidate (groups * candidates compares) and the sorting
 * work (candidates * KOF_VMATCH_SET_MAX * log). */
#define KOF_VMATCH_CAND_MAX 1024u

#define KOF_VMATCH_NONE 0xffffffffu         /* kof_vmatch_group.score_index: no candidate of this variant was passed */

/* One element of a set. b is read only for KOF_VMATCH_VARIANT (the variant id; a is its family) and is 0 for the other kinds. */
struct kof_vmatch_elem {
	uint32_t kind, a, b;
};

enum kof_vmatch_status {
	KOF_VMATCH_OK = 0,
	KOF_VMATCH_TRUNCATED,       /* an output array was too small; the result holds the true totals */
	KOF_VMATCH_TOO_LARGE,       /* an input past its bound (the fired list or the candidate list: nothing is computed; one candidate's
	                               profile: that score has KOF_VMATCH_SKIPPED and the others are computed). Wins over TRUNCATED. */
	KOF_VMATCH_BAD_REQUEST      /* a NULL input array with a non-zero count, a kind past KOF_VMATCH_KINDS (in a profile, or a bit of x_kinds), a NULL output array with a non-zero capacity, a NULL request */
};

#define KOF_VMATCH_SKIPPED 1u       /* kof_vmatch_score.flags: this candidate's profile exceeded KOF_VMATCH_SET_MAX; counts are 0 */

/* One fired diagnose, as it declared itself. */
struct kof_vmatch_fired {
	uint32_t diag;              /* its id */
	uint32_t tag;               /* its tag */
	uint32_t type;              /* its ONE malware type */
	uint32_t family;            /* meaningful only when has_variant */
	uint32_t variant;           /* meaningful only when has_variant */
	uint32_t has_variant;       /* 0: it declares no variant (the `unattributed` group) */
};

/* One candidate variant and its profile D(v): the elements the caller forms for it (for the tags: the tags of every diagnose that
 * declares it); any order, repeats allowed. */
struct kof_vmatch_cand {
	uint32_t family, variant;
	const struct kof_vmatch_elem *elem;
	uint32_t n_elem;
};

/* One diagnose of a group. */
struct kof_vmatch_entry {
	uint32_t diag, tag, type;
};

/* One group of fired diagnoses with the same (family, variant), or the unattributed one. */
struct kof_vmatch_group {
	uint32_t has_variant;       /* 0: the unattributed group (family and variant are 0) */
	uint32_t family, variant;
	uint32_t entry_first;       /* its entries are entry[entry_first .. entry_first + entry_count) of the full ordering */
	uint32_t entry_count;
	uint32_t score_index;       /* index of the candidate with this family and variant (the first one), or KOF_VMATCH_NONE */
};

/* The similarity of one candidate. */
struct kof_vmatch_score {
	uint32_t family, variant;   /* the candidate's, copied */
	uint32_t matched, unseen, extra;    /* |M|, |U|, |N|, all kinds */
	uint32_t permille;          /* J in 0..1000, rounded down, all kinds */
	uint32_t kmatched[KOF_VMATCH_KINDS], kunseen[KOF_VMATCH_KINDS], kextra[KOF_VMATCH_KINDS];   /* the same per kind */
	uint32_t kpermille[KOF_VMATCH_KINDS];
	uint32_t elem_first;        /* position of M's first element in the full ordering (then |U| elements, then |N|) */
	uint32_t flags;             /* KOF_VMATCH_SKIPPED */
};

struct kof_vmatch_req {
	const struct kof_vmatch_fired *fired;
	uint32_t n_fired;
	const struct kof_vmatch_cand *cand;
	uint32_t n_cand;
	uint32_t x_kinds;           /* bit k set: D(x) includes the kind k (1u << KOF_VMATCH_TAG ...) */
	/* outputs, the caller's; each with its capacity (elements) */
	struct kof_vmatch_group *group;
	uint32_t group_cap;
	struct kof_vmatch_entry *entry;
	uint32_t entry_cap;
	struct kof_vmatch_score *score;
	uint32_t score_cap;
	struct kof_vmatch_elem *elems;
	uint32_t elems_cap;
};

struct kof_vmatch_res {
	enum kof_vmatch_status status;
	uint32_t n_x;               /* |D(x)|, distinct, all kinds */
	uint32_t n_xk[KOF_VMATCH_KINDS];    /* per kind */
	uint32_t n_groups;          /* true totals, whatever the capacities */
	uint32_t n_entries;         /* always n_fired */
	uint32_t n_scores;          /* always n_cand */
	uint32_t n_elems;
};

/* Fill *res (and the arrays). Always sets res->status. On BAD_REQUEST or a TOO_LARGE fired/candidate list nothing is computed and
 * only n_entries / n_scores (how many were offered) are set. */
void kof_vmatch(const struct kof_vmatch_req *rq, struct kof_vmatch_res *res);

#endif
