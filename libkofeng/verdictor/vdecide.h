#ifndef KOF_VDECIDE_H
#define KOF_VDECIDE_H

/*
 * vdecide.h - the DECISION of the verdict over what kof_vmatch returned: which group of matched diagnoses leads, and which of its
 * diagnoses names the tag and the type. PURE (reads the arrays, writes one struct, allocates nothing, no global).
 *
 * TEMPORARY, NOT MEASURED. The owner wired the pipeline first to test it on real samples; no pack with catalog facts has been
 * scanned over a corpus yet, so every parameter here is the simplest rule that gives an answer and none is backed by a number.
 * The rule (each step is the whole of it; nothing else decides):
 *
 *   1. Detection is not decided here: one matched diagnose is enough (the owner's rule, 2026-10-11).
 *   2. LEAD GROUP = the (family, variant) group with the highest `cover` = matched tags / tags of the variant (permille,
 *      from kof_vmatch's per-kind counts); ties: more matched tags, then the higher Jaccard, then the group of the diagnose that
 *      matched first (database order, so deterministic). No threshold: a variant of which one tag of twenty matched still leads
 *      when it is the only group, and the name carries `cover` beside it so a reader sees how much of it was seen. A candidate
 *      whose profile was too large for kof_vmatch (KOF_VMATCH_SKIPPED) has cover 0.
 *   3. When every matched diagnose declares no variant there is no group to lead: level TAG, named by a tag and a type.
 *   4. The lead's TAG and TYPE are those of the diagnose of the lead group with the LOWEST type value (the old verdict's
 *      rule for a lead disease: lower type first), ties by the first fired.
 *   5. Every other type a matched diagnose carries is reported (other_types); two families that both matched are reported as
 *      n_groups > 1. Nothing here picks "the family" by a margin or a threshold: that is for the owner's measurement.
 */

#include "vmatch.h"

struct kof_vdecision {
	uint32_t level;             /* KOF_VCAT_NONE (no fired diagnose), _TAG or _VARIANT (kofresult.h) */
	uint32_t lead_group;        /* index into the group array, or KOF_VMATCH_NONE */
	uint32_t lead_entry;        /* index into the entry array: the diagnose that gives the tag and the type */
	uint32_t other_types;       /* mask over kof_maltype of the other entries' types */
	uint32_t cover, jaccard;    /* of the lead group, permille */
};

/* `group`, `entry`, `score` are the arrays kof_vmatch filled for `res` (res->n_groups / n_entries / n_scores their totals; the
 * arrays must hold them all). res->status must be OK. */
void kof_vdecide(const struct kof_vmatch_res *res, const struct kof_vmatch_group *group, const struct kof_vmatch_entry *entry,
		 const struct kof_vmatch_score *score, struct kof_vdecision *out);

#endif
