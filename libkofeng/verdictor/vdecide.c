/* vdecide.c - see vdecide.h. */
#include <string.h>

#include "vdecide.h"
#include "../kofcore/kofresult.h"

static uint32_t cover_of(const struct kof_vmatch_group *g, const struct kof_vmatch_score *score, uint32_t *matched, uint32_t *jac)
{
	const struct kof_vmatch_score *s;
	uint32_t den;

	*matched = 0;
	*jac = 0;
	if (g->score_index == KOF_VMATCH_NONE)
		return 0;
	s = &score[g->score_index];
	if (s->flags & KOF_VMATCH_SKIPPED)
		return 0;
	*matched = s->kmatched[KOF_VMATCH_TAG];
	*jac = s->permille;
	den = s->kmatched[KOF_VMATCH_TAG] + s->kunseen[KOF_VMATCH_TAG];
	return den ? (s->kmatched[KOF_VMATCH_TAG] * 1000u) / den : 0u;
}

void kof_vdecide(const struct kof_vmatch_res *res, const struct kof_vmatch_group *group, const struct kof_vmatch_entry *entry,
		 const struct kof_vmatch_score *score, struct kof_vdecision *out)
{
	uint32_t g, e, best = KOF_VMATCH_NONE, bc = 0, bm = 0, bj = 0, lead_e, un = KOF_VMATCH_NONE;

	memset(out, 0, sizeof *out);
	out->lead_group = out->lead_entry = KOF_VMATCH_NONE;
	if (!res || res->n_entries == 0u)
		return;
	for (g = 0; g < res->n_groups; g++) {
		uint32_t m, j, c;

		if (!group[g].has_variant) {
			un = g;
			continue;
		}
		c = cover_of(&group[g], score, &m, &j);
		if (best == KOF_VMATCH_NONE || c > bc || (c == bc && (m > bm || (m == bm && j > bj)))) {
			best = g;
			bc = c;
			bm = m;
			bj = j;
		}
	}
	if (best == KOF_VMATCH_NONE)
		best = un;
	out->level = group[best].has_variant ? KOF_VCAT_VARIANT : KOF_VCAT_TAG;
	out->lead_group = best;
	out->cover = group[best].has_variant ? bc : 0u;
	out->jaccard = group[best].has_variant ? bj : 0u;
	lead_e = group[best].entry_first;
	for (e = group[best].entry_first; e < group[best].entry_first + group[best].entry_count; e++)
		if (entry[e].type < entry[lead_e].type)
			lead_e = e;
	out->lead_entry = lead_e;
	for (e = 0; e < res->n_entries; e++)
		if (entry[e].type != entry[lead_e].type && entry[e].type < 32u)
			out->other_types |= 1u << entry[e].type;
}
