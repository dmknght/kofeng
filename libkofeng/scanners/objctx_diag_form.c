/*
 * objctx_diag_form.c - the detection forms of the diagnoses (KDIG_SEC_FORM, pack/diagform.h): what a signature's kof_scan
 * used to compute, answered for a diagnose.
 *
 * A FORM IS ANSWERED BY THE FUNCTIONS THE ENGINE ALWAYS ASKED, not by a second matcher. A marker is searched in its
 * region mask by the same extents and the same pattern matcher a module's kof_find_str uses (oc_find_str_mask, objctx.c),
 * a marker at an offset by kof_match_at, a block by the similarity set's kof_mutation_pct - the very set the packs'
 * blocks are in (a form's blocks are numbered after theirs: kof_form.blk_base). What is written here is the expression
 * over the answers and WHEN each is asked.
 *
 * WHEN. The string matchers are asked at the DETECT stage, after the modules (the object in hand, the modules' own
 * searches already made); the similarity matchers at the SIMILAR stage, which is the object the chain scores (a block is
 * cut from the normalised view, so a parent that has a view is not scored - scan_pipeline.c, st_similar). A diagnose is
 * asked at most once per object: `fdone` says it was, `fhit` what it came to, both wiped with the object. A matcher is
 * answered once per object however many leaves of the expression name it, and the expression short circuits like the
 * C operators it spells, so a marker no leaf needs is not searched.
 *
 * WHAT IS NOT ASKED. A diagnose no verdict and no rule reads (oc_diag_used) and one whose shape (the target format and
 * subtype, the conditions it declared: oc_diag_when_met) this object does not have. A module that asks for a form
 * diagnose through kof_diag reads the answer of the stage that has run (strings are asked on demand; a similarity form
 * is read once the SIMILAR stage has scored the object - before it, it reads "no", it is not scored yet).
 */

#include "../kofcore/kofdebug.h"
#include "objctx_int.h"
#include "scan_int.h"
#include "../detectors/linkage/kofdiag.h"
#include "../detectors/mutations/kofmutation.h"
#include "../detectors/pattern/kofmatch.h"
#include "../databases/pack/diagform.h"
#include "../databases/pack/dbtables.h"

#include <string.h>

struct fx {
	struct kof_scanner        *sc;
	const struct kof_obj_ctx  *ctx;
	const struct kof_form     *f;
	int8_t                     memo[KOF_FORM_MAX_MATCH];   /* -1 not asked, else the answer */
	struct kof_diag_match     *rec;    /* the report's record of this diagnose's matchers (sc->diag.xm[i]), NULL when not asked for */
};

/* The record of matcher k, or NULL: past what a report holds, or no report. */
static struct kof_diag_match *fx_rec(const struct fx *x, uint8_t k)
{
	return x->rec && k < KOF_DIAG_REPORT_MATCH ? &x->rec[k] : NULL;
}

/* One marker of the form as the matcher takes it: the descriptor and the bytes. */
static void fx_ent(const struct fx *x, uint8_t idx, struct kof_str_ent *e, const uint8_t **bytes)
{
	const struct kof_form_str *s = &x->f->str[idx];

	memset(e, 0, sizeof *e);
	e->len = s->len;
	e->kind = s->kind;
	e->flags = s->flags;
	*bytes = x->f->pool + s->off;
}

/* The offset an AT matcher compares at, or 0 with *off unset when it lies outside the object (no entry point, a step
 * before the start or past the end): the host's own bound, as for kof_find_str_at. */
static int fx_at(const struct fx *x, const struct kof_form_match *m, uint64_t *off)
{
	int64_t base;
	int64_t v;

	switch (m->anchor) {
	case KOF_FORM_ANCHOR_BOF:
		base = 0;
		break;
	case KOF_FORM_ANCHOR_ENTRY:
		/* No entry point (KOF_NA) or an unresolved one (KOF_BROKEN) are the top two values of the word: as a signed number they
		 * are negative, and a base below zero answers no (below). One test for the three. */
		_Static_assert(KOF_NA > (uint64_t)INT64_MAX && KOF_BROKEN > (uint64_t)INT64_MAX, "NA and BROKEN read as negative");
		base = (int64_t)x->ctx->entry_off;
		break;
	default:
		base = (int64_t)x->ctx->obj_size;
		break;
	}
	if (base < 0)
		return 0;
	if ((m->at > 0 && base > INT64_MAX - m->at) || (m->at < 0 && base < INT64_MIN - m->at))
		return 0;
	v = base + m->at;
	if (v < 0)
		return 0;
	*off = (uint64_t)v;
	return 1;
}

static int fx_find(struct fx *x, const struct kof_form_match *m, struct kof_diag_match *rec)
{
	struct kof_str_ent e;
	const uint8_t *bytes;
	uint8_t k, found = 0;

	if (m->rule == KOF_FORM_R_AT) {
		uint64_t off;

		fx_ent(x, m->arg[0], &e, &bytes);
		return fx_at(x, m, &off) &&
		       kof_match_at(&x->sc->match.m, off, bytes, e.len, e.kind, e.flags);
	}
	for (k = 0; k < m->n; k++) {
		int hit;

		fx_ent(x, m->arg[k], &e, &bytes);
		hit = oc_find_str_mask(x->ctx, m->mask, &e, bytes);
		if (rec)
			rec->found = (uint8_t)(rec->found + (hit != 0));
		KOF_TRACE("[form] find string %u (len %u) in regions %x: %s\n", (unsigned)m->arg[k], (unsigned)e.len, (unsigned)m->mask,
			  hit ? "found" : "not found");
		if (m->rule == KOF_FORM_R_ALL && !hit)
			return 0;               /* stops at the first miss, like kof_find_str_all */
		if (m->rule == KOF_FORM_R_ANY && hit)
			return 1;               /* and at the first hit, like kof_find_str_any */
		found = (uint8_t)(found + (hit != 0));
		if (m->rule == KOF_FORM_R_MULTI && found >= m->thresh)
			return 1;
	}
	return m->rule == KOF_FORM_R_ALL;
}

/* Every block of the matcher reaches its percentage (the editor's rule: a matcher holds what all of its blocks demand). */
static int fx_sim(struct fx *x, const struct kof_form_match *m, struct kof_diag_match *rec)
{
	uint8_t k;

	/* A set refused at load (reported there) scores nothing: kof_mutation_pct answers 0 for it. */
	for (k = 0; k < m->n; k++) {
		uint32_t pct = kof_mutation_pct(&x->sc->mutation, x->f->blk_base + m->arg[k]);

		KOF_TRACE("[form] sim block %u (set number %u) pct=%u need=%u\n", (unsigned)m->arg[k],
			  (unsigned)(x->f->blk_base + m->arg[k]), (unsigned)pct, (unsigned)m->thresh);
		if (rec && (k == 0 || pct < rec->pct))
			rec->pct = (uint16_t)(pct > 65535u ? 65535u : pct);
		if (pct < m->thresh)
			return 0;
	}
	return 1;
}

static int fx_match(struct fx *x, uint8_t k)
{
	if (x->memo[k] < 0) {
		const struct kof_form_match *m = &x->f->match[k];

		struct kof_diag_match *rec = fx_rec(x, k);

		x->sc->st.work_form_matchers++;
		if (rec) {
			rec->kind = m->kind == KOF_FORM_M_FIND ? KDET_M_FIND : KDET_M_SIMILAR;
			rec->n = m->n;
			rec->mask = m->mask;
			rec->need = m->kind == KOF_FORM_M_FIND ? 0 : m->thresh;
		}
		x->memo[k] = (int8_t)(m->kind == KOF_FORM_M_FIND ? fx_find(x, m, rec) : fx_sim(x, m, rec));
		if (rec)
			rec->result = x->memo[k] ? KDET_M_YES : KDET_M_NO;
		KOF_TRACE("[form] matcher %u (%s) = %d\n", (unsigned)k, m->kind == KOF_FORM_M_FIND ? "find" : "similarity", x->memo[k]);
	}
	return x->memo[k];
}

static int fx_node(struct fx *x, uint32_t i)
{
	const struct kof_form_node *n = &x->f->node[i];

	switch (n->op) {
	case KOF_FORM_OP_LEAF:
		return fx_match(x, n->a);
	case KOF_FORM_OP_NOT:
		return !fx_node(x, n->a);
	case KOF_FORM_OP_AND:
		return fx_node(x, n->a) && fx_node(x, n->b);
	default:
		return fx_node(x, n->a) || fx_node(x, n->b);
	}
}

/* Is this form asked of this object at all: something reads it (oc_diag_used) and the object has the shape it declared. */
static int form_applies(const struct kof_scanner *sc, const struct kof_obj_ctx *ctx, const struct kof_diag *d)
{
	return oc_diag_used(sc, d) && oc_diag_when_met(ctx, d);
}

int oc_diag_form_hit(const struct kof_scanner *sc, uint32_t i)
{
	return sc && i < sc->diag.cap && ((unsigned)(sc->diag.fdone[i >> 3] >> (i & 7u)) & 1u) &&
	       ((unsigned)(sc->diag.fhit[i >> 3] >> (i & 7u)) & 1u);
}

/*
 * ASK ONE FORM DIAGNOSE: its answer for this object, computed the first time and read after. A SIMILARITY form is asked
 * only by oc_diag_forms, after the set has counted the object's windows (sx_need_mutation); a caller that is not the stage
 * must not ask one - kof_diag reads its answer with oc_diag_form_hit.
 */
int oc_diag_form_ask(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, uint32_t i)
{
	const struct kof_diag *d;
	struct fx x;
	int hit;

	if (!sc || !sc->eng || i >= sc->eng->n_diag || i >= sc->diag.cap)
		return 0;
	d = &sc->eng->diag[i];
	if (!d->form)
		return 0;
	if ((unsigned)(sc->diag.fdone[i >> 3] >> (i & 7u)) & 1u)
		return oc_diag_form_hit(sc, i);
	KOF_TRACE("[form] asking %u %s (%s): %u matcher(s), %u block(s), blk_base %u\n", (unsigned)i, d->name,
		  d->form->n_sim ? "similarity" : "strings", (unsigned)d->form->n_match, (unsigned)d->form->n_block,
		  (unsigned)d->form->blk_base);
	if (!form_applies(sc, ctx, d)) {
		KOF_TRACE("[form] %u not asked: used=%d shape=%d\n", (unsigned)i, oc_diag_used(sc, d), oc_diag_when_met(ctx, d));
		return 0;
	}
	sc->st.work_form_asks++;
	x.sc = sc;
	x.ctx = ctx;
	x.f = d->form;
	memset(x.memo, -1, sizeof x.memo);
	x.rec = NULL;
	if (sc->diag.xm) {
		uint32_t k;

		x.rec = sc->diag.xm[i];
		memset(x.rec, 0, KOF_DIAG_REPORT_MATCH * sizeof *x.rec);
		for (k = 0; k < KOF_DIAG_REPORT_MATCH; k++)
			x.rec[k].result = KDET_M_NOT_ASKED;
	}
	hit = fx_node(&x, (uint32_t)d->form->n_node - 1u);
	sc->diag.fdone[i >> 3] |= (uint8_t)(1u << (i & 7u));
	KOF_TRACE("[form] %u %s answered %d\n", (unsigned)i, d->name, hit);
	if (hit)
		sc->diag.fhit[i >> 3] |= (uint8_t)(1u << (i & 7u));
	return hit;
}

void oc_diag_forms(struct kof_scanner *sc, struct kof_obj_ctx *ctx, int sim, struct kof_result *out)
{
	uint32_t i, n;

	if (!sc || !sc->eng || !sc->eng->n_form)
		return;                 /* a database with no form: nothing to walk, per object and per stage */
	n = sc->eng->n_diag < sc->diag.cap ? sc->eng->n_diag : sc->diag.cap;
	KOF_TRACE("[form] stage %s: %u form diagnose(s) in the database, %u diagnose(s) walked (cap %u)\n", sim ? "similar" : "detect",
		  (unsigned)sc->eng->n_form, (unsigned)n, (unsigned)sc->diag.cap);
	for (i = 0; i < n; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];

		if (!d->form || (d->form->n_sim != 0) != (sim != 0))
			continue;
		if ((unsigned)(sc->diag.fdone[i >> 3] >> (i & 7u)) & 1u)
			continue;
		if (!form_applies(sc, ctx, d)) {
			KOF_TRACE("[form] %u skipped at %s: used=%d shape=%d\n", (unsigned)i, sim ? "similar" : "detect",
				  oc_diag_used(sc, d), oc_diag_when_met(ctx, d));
			continue;
		}
		/* The feed is the first ask's cost, and only for an object that has a form to score. It is also what makes asking a
		 * similarity form safe: this is the only caller that asks one (a module's kof_diag reads what this stage found). */
		if (sim)
			sx_need_mutation(sc, ctx);
		(void)oc_diag_form_ask(sc, ctx, i);
		/* Asked, so the object was EXAMINED: a clean answer from a form is a clean object, not one nothing looked at
		 * (the scanner's "no module targets this format"). */
		if (out && ((unsigned)(sc->diag.fdone[i >> 3] >> (i & 7u)) & 1u)) {
			out->examined++;
			sc->st.ran++;
		}
	}
}
