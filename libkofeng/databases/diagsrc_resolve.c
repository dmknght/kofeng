/*
 * diagsrc_resolve.c - what a parsed diagnose source means: the rules about what a diagnose may say. Split from diagsrc.c; the text is unchanged. See diagsrc.h.
 */

#include "diagsrc_int.h"

/* ---- the tree -------------------------------------------------------------- */

/*
 * THE RULES ABOUT WHAT A DIAGNOSE MAY SAY, in one place, in the order the file
 * says it - several are about order (a tail before the head, a sequence after
 * the head it makes) and an error names the line that broke it.
 */
int kof_dsrc_resolve(const struct kof_dsrc *d, struct kof_dsrc_view *v,
		     const struct kof_dsrc_report *r)
{
	struct { char label[32]; char name[KOF_DSRC_NAME_LEN]; int used; } sy[8];
	int n_sym = 0, errs = 0, i;
	uint32_t q;
	int last = (int)d->lines;

	memset(v, 0, sizeof *v);
	for (q = 0; q < d->n; q++) {
		const struct kof_dsrc_item *it = &d->item[q];
		int ln = (int)it->line;
		struct kof_dsrc_node *nd;
		int k;

		switch (it->kind) {
		case KDS_NAME:
			memcpy(v->name, it->s1, sizeof v->name);
			break;
		case KDS_DISEASE: {
			/* What a well-formed disease is, asked of the one function that
			 * decides it - see kofdisease.h. */
			const char *why = kof_disease_check(it->s1);

			if (v->disease[0])
				kof_dsrc_say_err(r, &errs, ln, "a diagnose has one disease");
			if (why)
				kof_dsrc_say_err(r, &errs, ln, why);
			memcpy(v->disease, it->s1, sizeof v->disease);
			v->disease_type = (uint8_t)it->a;
			break;
		}
		case KDS_ANALYSIS:
			v->analysis |= it->a;
			break;
		case KDS_USE_EMU:
			v->analysis |= KOF_DIAG_USES_EMU;
			break;
		case KDS_FORMAT:
		case KDS_SUBTYPE: {
			uint16_t fact = it->kind == KDS_FORMAT
					? (uint16_t)KOF_FACT_FORMAT
					: (uint16_t)KOF_FACT_OBJ_KIND;

			if (v->n_when >= (int)KOF_DIAG_MAX_WHEN) {
				kof_dsrc_say_err(r, &errs, ln, "too many conditions");
				break;
			}
			for (k = 0; k < v->n_when; k++)
				if (v->when[k].fact == fact)
					kof_dsrc_say_err(r, &errs, ln, "declared twice");
			v->when[v->n_when].fact = fact;
			v->when[v->n_when].val = it->v;
			v->n_when++;
			break;
		}
		case KDS_ATTRB:
			if (v->n_when >= (int)KOF_DIAG_MAX_WHEN) {
				kof_dsrc_say_err(r, &errs, ln, "too many conditions");
				break;
			}
			v->when[v->n_when].fact = it->a;
			v->when[v->n_when].val = it->v;
			v->n_when++;
			break;
		case KDS_HEAD:
			if (v->n_nd) {
				kof_dsrc_say_err(r, &errs, ln, "a diagnose has one head");
				break;
			}
			nd = &v->nd[0];
			nd->cap = it->a;
			nd->flags = it->b;
			v->n_nd = 1;
			break;
		case KDS_TAIL:
			if (v->n_nd >= (int)KOF_DSRC_MAX_NODE) {
				kof_dsrc_say_err(r, &errs, ln,
					"too many nodes in one diagnose");
				break;
			}
			if (!v->n_nd) {
				kof_dsrc_say_err(r, &errs, ln,
					"KOF_DIAG_DECLARE_TAIL before the head");
				break;
			}
			nd = &v->nd[v->n_nd++];
			nd->cap = it->a;
			nd->bits |= (uint8_t)it->b;
			break;
		case KDS_ACTION:
			if (v->n_nd >= (int)KOF_DSRC_MAX_NODE) {
				kof_dsrc_say_err(r, &errs, ln,
					"too many nodes in one diagnose");
				break;
			}
			/* The first word restates the head, so the line reads on
			 * its own; it must be the head this diagnose declared. */
			if (!v->n_nd || it->a != v->nd[0].cap) {
				kof_dsrc_say_err(r, &errs, ln,
					"KOF_DIAG_ACTION names a block that "
					"is not this diagnose's head");
				break;
			}
			nd = &v->nd[v->n_nd++];
			nd->cap = it->b;
			nd->val = it->v;
			nd->bits |= KOF_DIAG_B_VAL;
			break;
		case KDS_SYMBOL:
			if (n_sym >= (int)(sizeof sy / sizeof sy[0])) {
				kof_dsrc_say_err(r, &errs, ln, "too many symbols");
				break;
			}
			memcpy(sy[n_sym].label, it->s1, strlen(it->s1) + 1u);
			memcpy(sy[n_sym].name, it->s2, strlen(it->s2) + 1u);
			sy[n_sym].used = 0;
			n_sym++;
			break;
		case KDS_FIELD: {
			int hit = -1, hits = 0, si = -1;

			for (k = 0; k < n_sym; k++)
				if (!strcmp(sy[k].label, it->s1))
					si = k;
			if (si < 0) {
				kof_dsrc_say_err(r, &errs, ln,
					"no symbol declared with that label");
				break;
			}
			for (k = 0; k < v->n_nd; k++)
				if (v->nd[k].cap == it->a) {
					hit = k;
					hits++;
				}
			if (hits != 1) {
				kof_dsrc_say_err(r, &errs, ln, hits
					? "that capability is in this diagnose more than once"
					: "no node of that capability");
				break;
			}
			memcpy(v->nd[hit].sym, sy[si].name,
			       strlen(sy[si].name) + 1u);
			v->nd[hit].bits |= KOF_DIAG_B_FIELD_OF;
			sy[si].used = 1;
			/* and it is what the object must refer to, or the analysis
			 * has nothing to find: the gate is the symbol table. */
			for (k = 0; k < v->n_ref; k++)
				if (!strcmp(v->ref[k], sy[si].name))
					break;
			if (k == v->n_ref) {
				if (v->n_ref >= (int)KOF_DIAG_MAX_NEED) {
					kof_dsrc_say_err(r, &errs, ln, "too many symbols");
					break;
				}
				memcpy(v->ref[v->n_ref], sy[si].name,
				       strlen(sy[si].name) + 1u);
				v->n_ref++;
			}
			break;
		}
		case KDS_SEQUENCE:
			if (v->has_seq || !v->n_nd) {
				kof_dsrc_say_err(r, &errs, ln, v->has_seq
					? "a diagnose has one sequence"
					: "KOF_DIAG_DECLARE_SEQUENCE comes after "
					  "the head it makes");
				break;
			}
			/* What the object must import, so each has to be a name that
			 * can be imported - or the sequence can never be found. */
			if (!kgenome_nucleo_cap_named(it->a) || !kgenome_nucleo_cap_named(it->b)) {
				kof_dsrc_say_err(r, &errs, ln,
					"no imported name is that capability, so "
					"the sequence can never be found");
				break;
			}
			v->seq_first = it->a;
			v->seq_then = it->b;
			v->has_seq = 1;
			if (v->n_need + 2 > (int)KOF_DIAG_MAX_NEED) {
				kof_dsrc_say_err(r, &errs, ln, "too many signs");
				break;
			}
			v->need[v->n_need++] = it->a;
			v->need[v->n_need++] = it->b;
			break;
		default:
			break;
		}
	}

	/*
	 * A DECLARATION THAT COULD NOT BE READ is not in the list, so what is
	 * missing from the whole - a head, an analysis, a symbol's user - may be
	 * exactly that line, and saying so as well points at the wrong thing. The
	 * line that failed has been reported; the rest waits until it is fixed.
	 */
	if (d->bad)
		return errs;
	if (!v->name[0])
		kof_dsrc_say_err(r, &errs, last, "a diagnose needs KOF_DIAG_NAME");
	if (!(v->analysis & (KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL |
			     KOF_DIAG_ANALYSIS_APIHASH)))
		kof_dsrc_say_err(r, &errs, last, "a diagnose needs KOF_DIAG_ANALYSIS");
	if (!v->n_nd)
		kof_dsrc_say_err(r, &errs, last, "a diagnose needs a head");
	/*
	 * AND THE ANCHOR MUST BE RARE, which is a cost statement and not a
	 * correctness one - see the note on anchors in kofmod/kofdiagtree.h.
	 * Matching starts by trying every node that could be the root, so a
	 * root of READ costs one descent per read in the object; one 1.1 MB
	 * sample here holds 447 indirect calls.
	 */
	if (v->n_nd && (v->nd[0].cap == KGENOME_NUCLEO_READ ||
			v->nd[0].cap == KGENOME_NUCLEO_WRITE ||
			v->nd[0].cap == KGENOME_NUCLEO_EXEC_REG))
		kof_dsrc_say_warn(r, "anchoring on a common capability - every one in "
			    "the object starts a descent");
	for (i = 0; i < n_sym; i++)
		if (!sy[i].used)
			kof_dsrc_say_err(r, &errs, last,
				"a declared symbol is attached to nothing");
	/*
	 * THE GATE IS DERIVED FROM THE HEAD AND THE TAILS, for a diagnose that only
	 * names can satisfy: with no syscall or hash analysis there is no other way
	 * for its capabilities to appear, so an object that imports none of them is
	 * not worth the analysis. A diagnose that DOES have such an analysis is not
	 * gated by imports - a stripped static binary imports nothing - and one
	 * whose head is built from a declared sequence is gated by the two calls it
	 * is built from, because the head's own capability is not what the object
	 * imports.
	 */
	if (!v->has_seq && !(v->analysis & (KOF_DIAG_ANALYSIS_SYSCALL |
					    KOF_DIAG_ANALYSIS_APIHASH)))
		for (i = 0; i < v->n_nd; i++) {
			int k;

			if (!kgenome_nucleo_cap_named(v->nd[i].cap))
				continue;       /* an action has no import name */
			for (k = 0; k < v->n_need && v->need[k] != v->nd[i].cap; k++)
				;
			if (k < v->n_need)
				continue;
			if (v->n_need >= (int)KOF_DIAG_MAX_NEED) {
				kof_dsrc_say_err(r, &errs, last, "too many signs");
				break;
			}
			v->need[v->n_need++] = v->nd[i].cap;
		}
	/* A head the engine builds out of a declared sequence is not bare: the
	 * two calls are what it is made of. */
	if (v->n_nd == 1 && !v->has_seq &&
	    !(v->nd[0].bits & (KOF_DIAG_B_VAL | KOF_DIAG_B_FIELD_OF)))
		kof_dsrc_say_warn(r, "a head with no tail, action or symbol says only "
			    "that a call exists");
	return errs;
}
