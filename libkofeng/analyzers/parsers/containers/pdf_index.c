/*
 * pdf_index.c - the lookups by object number the parse's passes share.
 *
 * WHAT THIS SERVES: pdf_resolve_refs (an object's reference to another), referrer_of in
 * pdf_entries.c (who pointed at this stream) and the redefinition test in the walk - all
 * three answered "which object has number N" by reading the table from the top. See
 * struct pdf_index in pdf_int.h for why that is no longer something to do.
 */

#include "pdf_int.h"
#include <kofcmp.h>
#include <stddef.h>
#include <stdlib.h>

int pdf_index_build(struct kof_pdf_info *p, struct pdf_index *ix, enum pdf_ix_kind kind)
{
	uint64_t bytes = (uint64_t)p->n_objects * sizeof *ix->v;
	uint32_t i, n = 0;

	ix->v = NULL;
	ix->n = 0;
	ix->bytes = 0;
	if (!p->n_objects)
		return 1;
	if (bytes > kof_view_room(&p->mem))
		return 0;
	ix->v = malloc((size_t)bytes);
	if (!ix->v)
		return 0;
	for (i = 0; i < p->n_objects; i++) {
		const struct kof_pdf_object *o = &p->object[i];

		switch (kind) {
		case PDF_IX_STREAM_NUM:
			if (!o->stream_len)
				continue;
			ix->v[n].key = o->num;
			break;
		case PDF_IX_REF:
			if (!o->ref_num)
				continue;
			ix->v[n].key = o->ref_num;
			break;
		case PDF_IX_NUM_GEN:
			ix->v[n].key = ((uint64_t)o->num << 32) | o->gen;
			break;
		}
		ix->v[n].idx = i;
		ix->v[n].pad = 0;
		n++;
	}
	pdf_keys_sort(ix->v, n);
	ix->n = n;
	ix->bytes = bytes;
	p->mem.held += bytes;
	return 1;
}

void pdf_index_free(struct kof_pdf_info *p, struct pdf_index *ix)
{
	free(ix->v);
	p->mem.held = ix->bytes < p->mem.held ? p->mem.held - ix->bytes : 0;
	ix->v = NULL;
	ix->n = 0;
	ix->bytes = 0;
}

const struct pdf_key *pdf_index_find(const struct pdf_index *ix, uint64_t key)
{
	const uint32_t lo = kof_lower_bound_u64(ix->v, ix->n, sizeof *ix->v, offsetof(struct pdf_key, key), key);

	return lo < ix->n && ix->v[lo].key == key ? &ix->v[lo] : NULL;
}

/*
 * THIS NUMBER AND GENERATION, SEEN BEFORE - decided over the whole table once it is built.
 *
 * It was an 8192 bit filter beside the walk with a scan of the table behind every hit,
 * which was cheap while the table held 4096 rows and a duplicate was rare: with a table as
 * long as the file the filter fills up, every object hits it, and the scan behind it is
 * the whole table. Sorted, the objects that share a number and a generation are
 * neighbours, and every one after the first of its group is a redefinition - the same
 * answer, since "an earlier object has it" is "it is not the lowest of its group".
 *
 * See KOF_PDF_ANOM_OBJ_REDEFINED for why it is recorded and not resolved: an incrementally
 * updated document does it on purpose, and which definition a viewer picks is a question
 * only the cross reference table answers.
 */
void pdf_mark_redefined(struct kof_pdf_info *p)
{
	struct pdf_index ix;
	uint32_t i;

	if (p->n_objects < 2u)
		return;
	if (!pdf_index_build(p, &ix, PDF_IX_NUM_GEN)) {
		/* No room for the test: said, because a redefinition that is not looked for is
		 * one that is not reported, and that is the shape of this bit's whole value. */
		p->anomalies |= KOF_PDF_ANOM_OBJECTS_FULL;
		return;
	}
	for (i = 1; i < ix.n; i++) {
		if (ix.v[i].key != ix.v[i - 1u].key)
			continue;
		p->anomalies |= KOF_PDF_ANOM_OBJ_REDEFINED;
		p->object[ix.v[i].idx].flags |= KOF_PDF_OBJ_REDEFINED;
	}
	pdf_index_free(p, &ix);
}
