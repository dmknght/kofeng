/*
 * OLD-DISEASE (owner, 2026-10-28): the parts of this file about diseases are the OLD logic - a disease as (maltype, free-text
 * behaviour path), its id and its records in the pack. The NEW disease is the pair (ACT, OBJ) of kofmod/diseaselist.h and has no
 * text. Nothing is removed yet: this is marked for review and removal in the disease rework (changing the pack layout or version is
 * the owner's decision). `grep -rn OLD-DISEASE` lists every marked place.
 */
/*
 * diagsrc_resolve.c - what a parsed diagnose source means: the rules about what a diagnose may say. Split from diagsrc.c; the text is unchanged. See diagsrc.h.
 */

#include "diagsrc_int.h"

/* ---- the tree -------------------------------------------------------------- */

/* The formats a KOF_TARGET_FORMAT line names, as a bit per format; the answer is how many DISTINCT formats that is (0 when
 * the words are not there or one is not a format). */
static int fmt_set(const char *words, uint64_t *set)
{
	char tmp[KOF_DSRC_WORDS_LEN];
	char *tok, *next;
	int pop = 0;
	uint64_t b;

	*set = 0;
	if (!words[0] || strlen(words) >= sizeof tmp)
		return 0;
	memcpy(tmp, words, strlen(words) + 1u);
	for (tok = tmp; tok; tok = next) {
		uint64_t v;

		next = strchr(tok, '|');
		if (next)
			*next++ = 0;
		if (!kof_dsrc_when_value(tok, &v) || v >= 64u) {
			*set = 0;
			return 0;
		}
		*set |= (uint64_t)1 << v;
	}
	for (b = *set; b; b >>= 1)
		pop += (int)(b & 1u);
	return pop;
}

/*
 * THE RULES ABOUT WHAT A DIAGNOSE MAY SAY, in one place, in the order the file
 * says it - several are about order (a tail before the head, a sequence after
 * the head it makes) and an error names the line that broke it.
 */
int kof_dsrc_resolve(const struct kof_dsrc *d, struct kof_dsrc_view *v,
		     const struct kof_dsrc_report *r)
{
	struct { char label[32]; char name[KOF_DSRC_NAME_LEN]; int used; } sy[8];
	int n_sym = 0, errs = 0, i, has_form = 0;
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
		case KDS_FAMILY:
		case KDS_VARIANT:
		case KDS_TYPE:
		case KDS_TAG: {
			unsigned bit = it->kind == KDS_FAMILY ? KOF_DSRC_META_FAMILY :
				       it->kind == KDS_VARIANT ? KOF_DSRC_META_VARIANT :
				       it->kind == KDS_TYPE ? KOF_DSRC_META_TYPE :
				       KOF_DSRC_META_TAG;

			if (v->meta & bit) {
				kof_dsrc_say_err(r, &errs, ln, "declared twice");
				break;
			}
			v->meta |= bit;
			if (it->kind == KDS_FAMILY)
				memcpy(v->family, it->s1, sizeof v->family);
			else if (it->kind == KDS_VARIANT)
				memcpy(v->variant, it->s1, sizeof v->variant);
			else if (it->kind == KDS_TAG)
				memcpy(v->tag, it->s1, sizeof v->tag);
			else
				v->type = (uint8_t)it->a;
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
			uint64_t val = it->v, set = 0;

			if (v->n_when >= (int)KOF_DIAG_MAX_WHEN) {
				kof_dsrc_say_err(r, &errs, ln, "too many conditions");
				break;
			}
			/*
			 * SEVERAL FORMATS ARE A SET, NOT A NUMBER: the words' values ORed into one number name no format (ELF | PE
			 * is the number of a third one), so the diagnose is for any of them through KOF_FACT_FORMAT_SET, a bit per
			 * format. One format keeps the fact it always had, bit for bit.
			 */
			if (it->kind == KDS_FORMAT && fmt_set(it->s1, &set) > 1) {
				fact = (uint16_t)KOF_FACT_FORMAT_SET;
				val = set;
			}
			for (k = 0; k < v->n_when; k++)
				if (v->when[k].fact == fact ||
				    (it->kind == KDS_FORMAT && (v->when[k].fact == KOF_FACT_FORMAT ||
								v->when[k].fact == KOF_FACT_FORMAT_SET)))
					kof_dsrc_say_err(r, &errs, ln, "declared twice");
			v->when[v->n_when].fact = fact;
			v->when[v->n_when].val = val;
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
	/*
	 * THE DETECTION FORM, when the source declares one (diagsrc_form.c): a diagnose is a graph OR a form, never both -
	 * the graph is answered by the analysis of the code and the form by the pattern matcher and the similarity set, at
	 * different stages, and an AND of the two has no stage that can answer it. A form needs no analysis and no head.
	 */
	v->form = kof_dsrc_form_resolve(d, r, &errs, &has_form);
	if (has_form && (v->n_nd || v->analysis || v->n_ref || v->has_seq))
		kof_dsrc_say_err(r, &errs, last, "a diagnose is a graph or a form: this one declares "
			"both a head, an analysis or a symbol and the declarations of a form");
	if (!v->name[0])
		kof_dsrc_say_err(r, &errs, last, "a diagnose needs KOF_DIAG_NAME");
	/* The four catalog declarations go together: a diagnose with some of them has a
	 * family nobody can tie to a variant, a tag or a type. None is an old-style diagnose. */
	if (v->meta && v->meta != KOF_DSRC_META_ALL)
		kof_dsrc_say_err(r, &errs, last, "KOF_DIAG_FAMILY, KOF_DIAG_VARIANT, "
			"KOF_DIAG_TYPE and KOF_DIAG_TAG are written together or not at all");
	if (has_form)
		return errs;
	if (!(v->analysis & (KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL |
			     KOF_DIAG_ANALYSIS_APIHASH | KOF_DIAG_ANALYSIS_TEXT)))
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

static uint64_t mix(uint64_t h, uint64_t x)
{
	unsigned i;

	for (i = 0; i < 8u; i++) {
		h ^= (x >> (i * 8u)) & 0xffu;
		h *= 1099511628211ull;
	}
	return h;
}

/* What the diagnose LOOKS FOR, without its name, disease or catalog facts, and without the local labels of its blocks and matchers (a view
 * has them resolved to indexes): the one identity the builder refuses a collision by and the editor recognises a diagnose already in the tree by. */
uint64_t kof_dsrc_view_body_hash(const struct kof_dsrc_view *v)
{
	uint64_t h = 1469598103934665603ull;
	int i;
	const char *p;

	h = mix(h, v->analysis);
	h = mix(h, (uint64_t)v->n_nd);
	for (i = 0; i < v->n_nd; i++) {
		h = mix(h, v->nd[i].cap);
		h = mix(h, v->nd[i].flags);
		h = mix(h, v->nd[i].bits);
		h = mix(h, v->nd[i].val);
		for (p = v->nd[i].sym; *p; p++)
			h = mix(h, (unsigned char)*p);
	}
	for (i = 0; i < v->n_need; i++)
		h = mix(h, v->need[i]);
	for (i = 0; i < v->n_ref; i++)
		for (p = v->ref[i]; *p; p++)
			h = mix(h, (unsigned char)*p);
	for (i = 0; i < v->n_when; i++) {
		h = mix(h, v->when[i].fact);
		h = mix(h, v->when[i].val);
	}
	h = mix(h, (uint64_t)v->has_seq);
	h = mix(h, ((uint64_t)v->seq_first << 16) | v->seq_then);
	/* A FORM IS WHAT A DIAGNOSE LOOKS FOR TOO: two with the same facts and different markers or blocks are two
	 * diagnoses, and with no nodes to tell them apart they would hash alike and be refused as one. The stream is the
	 * record's own bytes, so "the same" is what the loader would see. */
	if (v->form) {
		size_t k, n = kof_form_wire_size(v->form);
		uint8_t *w = n ? malloc(n) : NULL;

		if (w && kof_form_wire_write(v->form, w) == n)
			for (k = 0; k < n; k++)
				h = mix(h, w[k]);
		free(w);
	}
	return h;
}

/* Two diagnoses that are one: see the note at the top of this file. */

int kof_dsrc_view_same(const struct kof_dsrc_view *a, const struct kof_dsrc_view *b)
{
	return a && b && a->meta == KOF_DSRC_META_ALL && b->meta == KOF_DSRC_META_ALL && !strcmp(a->family, b->family) &&
	       !strcmp(a->variant, b->variant) && !strcmp(a->tag, b->tag) && a->type == b->type &&
	       kof_dsrc_view_body_hash(a) == kof_dsrc_view_body_hash(b);
}
