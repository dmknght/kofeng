/*
 * OLD-DISEASE (owner, 2026-10-28): the parts of this file about diseases are the OLD logic - a disease as (maltype, free-text
 * behaviour path), its id and its records in the pack. The NEW disease is the pair (ACT, OBJ) of kofmod/diseaselist.h and has no
 * text. Nothing is removed yet: this is marked for review and removal in the disease rework (changing the pack layout or version is
 * the owner's decision). `grep -rn OLD-DISEASE` lists every marked place.
 */
/*
 * scan_verdict.c - what the scan state says about an object: the diseases it has and the
 * verdict they make.
 *
 * THE VERDICT IS MADE OF DISEASES. The object's answer is kof_result.verdict, composed by
 * the verdictor (kof_verdict_make) from the diseases the matched diagnoses declare, and it
 * carries the ids of the diagnoses that matched. The NAMES are the verdictor's
 * (verdictor/); what they are made of is state the scanner holds - which diagnoses
 * matched - and so reading it is the scanner's job.
 */

#define _GNU_SOURCE

#include "../kofcore/kofdebug.h"
#include "scan_int.h"
#include "objctx_int.h"
#include "../verdictor/verdict.h"
#include "../verdictor/vmatch.h"
#include "../verdictor/vdecide.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * THE DISEASES AN OBJECT HAS - the ones the diagnoses that matched declare - and which
 * diagnoses those were. A normal scan runs the analysis only when a diagnose that
 * declares a disease can be answered on the object; the report
 * (kscan_explain: kof_scan_set_explain) runs every diagnose.
 *
 * A diagnose that carries catalog facts (family, variant, tag, type) is read like one that declares a disease: its facts ARE
 * its declaration. `meta` lists the engine indices of the matched ones (sx_catalog turns them into the verdict's name).
 *
 * `dis` and `diag` have room for one id per diagnose, so nothing is cut to fit a table: a
 * disease left out is evidence the verdict never saw. Two diagnoses that find the same
 * disease count it once; both are in `diag`.
 */
static void sx_collect(const struct kof_obj_ctx *ctx, uint32_t *dis, uint32_t *n_dis,
		       uint32_t *diag, uint32_t *n_diag, uint32_t *meta, uint32_t *n_meta)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i, k, n = 0, nd = 0, nm = 0, lim;

	/*
	 * What the diagnoses found: all of them when the caller asked for the report,
	 * otherwise the ones that declare a disease (the verdict reads those). The
	 * analysis is run for it only when one of them is answerable on this object
	 * (kof_scan_diag_feeds_verdict); one that already ran - a module asked - is
	 * read as it stands.
	 */
	if (sc->obj.diag.all || sc->obj.diag.graph || kof_scan_diag_feeds_verdict(ctx)) {
		kof_scan_diag_force(ctx);
		oc_diag_trace_scan(sc);
		lim = sc->obj.diag.graph ? kof_scan_diag_count(ctx) : 0;
		for (i = 0; i < lim; i++) {
			const struct kof_diag *d = &sc->eng->diag[i];
			int seen = 0;

			if (!(d->disease || d->family_id) || !((sc->diag.hit[i >> 3] >> (i & 7u)) & 1u))
				continue;
			diag[nd++] = d->id;
			if (d->family_id)
				meta[nm++] = i;
			for (k = 0; k < n && !seen && d->disease; k++)
				seen = dis[k] == d->disease;
			if (!seen && d->disease)
				dis[n++] = d->disease;
		}
	}
	/*
	 * THE DIAGNOSES WHOSE FORM MATCHED (KDIG_SEC_FORM): answered at the DETECT and SIMILAR stages, which have run by now
	 * (oc_diag_forms), so this only reads. They are not in the graph analysis' bits, and the analysis does not have to
	 * have run for them to count. Same rule as above: one that declares a disease, a disease counted once.
	 */
	lim = kof_scan_diag_count(ctx);
	for (i = 0; i < lim; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];
		int seen = 0;

		if (!d->form || !(d->disease || d->family_id) || !oc_diag_form_hit(sc, i))
			continue;
		KOF_TRACE("[verdict] form diagnose %u %s matched: disease %08x family %llx\n", (unsigned)i, d->name,
			  (unsigned)d->disease, (unsigned long long)d->family_id);
		diag[nd++] = d->id;
		if (d->family_id)
			meta[nm++] = i;
		for (k = 0; k < n && !seen && d->disease; k++)
			seen = dis[k] == d->disease;
		if (!seen && d->disease)
			dis[n++] = d->disease;
	}
	KOF_TRACE("[verdict] collected: %u disease(s), %u matched diagnose(s), %u with a family\n", (unsigned)n, (unsigned)nd, (unsigned)nm);
	*n_dis = n;
	*n_diag = nd;
	*n_meta = nm;
}

/* A table of the distinct 64-bit catalog ids of one kind of one object: the matching library takes 32-bit ids, and a fold of
 * the 64 bits could make two ids one, so an id is its INDEX here (exact). Bounded by SX_IDTAB_MAX: past it the object's
 * verdict is made without the catalog (reported as a cut), never with a wrong identity. */
#define SX_IDTAB_MAX 65536u
struct sx_idtab {
	uint64_t *v;
	uint32_t n, cap;
};

static int sx_idx(struct sx_idtab *t, uint64_t id, uint32_t *out)
{
	uint32_t i;

	for (i = 0; i < t->n; i++)
		if (t->v[i] == id) {
			*out = i;
			return 1;
		}
	if (t->n == t->cap) {
		uint32_t nc = t->cap ? t->cap * 2u : 64u;
		uint64_t *nv;

		if (nc > SX_IDTAB_MAX || !(nv = realloc(t->v, (size_t)nc * sizeof *nv)))
			return 0;
		t->v = nv;
		t->cap = nc;
	}
	t->v[t->n] = id;
	*out = t->n++;
	return 1;
}

/*
 * THE CATALOG VERDICT: the matched diagnoses that carry catalog facts -> kof_vmatch -> kof_vdecide -> `*cat`.
 *
 *   fired      one kof_vmatch_fired per matched diagnose (its tag, family, variant as table indices, its OWN type)
 *   candidates the distinct (family, variant) of the matched ones; the profile D(v) of a candidate is the family, the
 *              variant and the tag of EVERY diagnose the database holds for that variant (not only the matched ones), so
 *              the numbers say how much of the variant was seen
 *   then       kof_vmatch groups and scores, kof_vdecide picks the lead (verdictor/vdecide.c: temporary rule)
 *
 * Returns 1 with `*cat` filled, 0 when there is nothing to name or a bound refused the input (then `*cut` is set and the
 * caller says so; the verdict falls back to the diseases, never to a wrong name). The diagnose list of kof_vmatch is bounded
 * by KOF_VMATCH_FIRED_MAX: matched diagnoses past it are counted in cat->n_fired and the cut is flagged.
 */
static int sx_catalog(const struct kof_scanner *sc, const uint32_t *meta, uint32_t n_meta, struct kof_verdict_cat *cat,
		      int *cut)
{
	struct sx_idtab tag = { 0 }, fam = { 0 }, var = { 0 };
	struct kof_vmatch_fired *fired = NULL;
	struct kof_vmatch_cand *cand = NULL;
	struct kof_vmatch_elem *pool = NULL, *pe;
	struct kof_vmatch_group *grp = NULL;
	struct kof_vmatch_entry *ent = NULL;
	struct kof_vmatch_score *scr = NULL;
	struct kof_vmatch_req rq;
	struct kof_vmatch_res res;
	struct kof_vdecision dec;
	uint32_t n = n_meta, i, c, nc = 0, k, d, made = 0;
	size_t pool_n = 0;
	const struct kof_diag *dg = sc->eng->diag;
	const struct kof_diag *lead;
	int ok = 0;

	if (n > KOF_VMATCH_FIRED_MAX) {
		n = KOF_VMATCH_FIRED_MAX;
		*cut = 1;
	}
	fired = calloc((size_t)n + 1u, sizeof *fired);
	cand = calloc((size_t)n + 1u, sizeof *cand);
	grp = calloc((size_t)n + 1u, sizeof *grp);
	ent = calloc((size_t)n + 1u, sizeof *ent);
	scr = calloc((size_t)n + 1u, sizeof *scr);
	if (!fired || !cand || !grp || !ent || !scr)
		goto fail;
	for (i = 0; i < n; i++) {
		const struct kof_diag *x = &dg[meta[i]];
		uint32_t t, f, v;

		if (!sx_idx(&tag, x->tag_id, &t) || !sx_idx(&fam, x->family_id, &f) || !sx_idx(&var, x->variant_id, &v))
			goto fail;
		fired[i].diag = meta[i];
		fired[i].tag = t;
		fired[i].type = x->type;
		fired[i].family = f;
		fired[i].variant = v;
		fired[i].has_variant = x->variant_id != 0u;
		for (c = 0; c < nc && fired[i].has_variant; c++)
			if (cand[c].family == f && cand[c].variant == v)
				break;
		if (fired[i].has_variant && c == nc) {
			cand[nc].family = f;
			cand[nc].variant = v;
			nc++;
		}
	}
	/* The profiles. One pass counts the diagnoses of each candidate (so its array is sized), the next fills it. */
	for (c = 0; c < nc; c++) {
		uint32_t cnt = 2u;

		for (d = 0; d < sc->eng->n_diag; d++)
			if (dg[d].family_id && dg[d].variant_id == var.v[cand[c].variant] && dg[d].family_id == fam.v[cand[c].family])
				cnt++;
		pool_n += cnt < KOF_VMATCH_SET_MAX + 1u ? cnt : KOF_VMATCH_SET_MAX + 1u;
	}
	pool = calloc(pool_n + 1u, sizeof *pool);
	KOF_TRACE("[mem] catalog verdict: %u fired, %u candidate(s), %zu profile element(s), id tables tag=%u family=%u variant=%u (all freed at its end)\n",
		  (unsigned)n, (unsigned)nc, pool_n, (unsigned)tag.n, (unsigned)fam.n, (unsigned)var.n);
	if (!pool)
		goto fail;
	pe = pool;
	for (c = 0; c < nc; c++) {
		struct kof_vmatch_elem *first = pe;
		uint32_t nt = 0, over = 0;

		pe->kind = KOF_VMATCH_FAMILY;
		pe->a = cand[c].family;
		pe++;
		pe->kind = KOF_VMATCH_VARIANT;
		pe->a = cand[c].family;
		pe->b = cand[c].variant;
		pe++;
		for (d = 0; d < sc->eng->n_diag && !over; d++) {
			uint32_t t, dup = 0;

			if (!dg[d].family_id || dg[d].variant_id != var.v[cand[c].variant] || dg[d].family_id != fam.v[cand[c].family])
				continue;
			if (!sx_idx(&tag, dg[d].tag_id, &t))
				goto fail;
			for (k = 0; k < nt && !dup; k++)
				dup = first[2u + k].a == t;
			if (dup)
				continue;
			if (2u + nt >= KOF_VMATCH_SET_MAX) {
				over = 1;	/* past the library's bound: it says SKIPPED for this candidate (cover 0) */
				break;
			}
			pe->kind = KOF_VMATCH_TAG;
			pe->a = t;
			pe++;
			nt++;
		}
		cand[c].elem = first;
		cand[c].n_elem = over ? KOF_VMATCH_SET_MAX + 1u : 2u + nt;
		if (over) {
			/* A candidate past the library's bound is passed with n_elem = SET_MAX + 1 (it answers SKIPPED, cover 0): its
			 * storage is the SET_MAX + 1 slots the pool gave it, the rest padded with an id no tag has. */
			pe = first + 2u + nt;
			for (k = 2u + nt; k < KOF_VMATCH_SET_MAX + 1u; k++, pe++) {
				pe->kind = KOF_VMATCH_TAG;
				pe->a = 0xffffffffu;
			}
		}
	}
	memset(&rq, 0, sizeof rq);
	rq.fired = fired;
	rq.n_fired = n;
	rq.cand = cand;
	rq.n_cand = nc;
	rq.x_kinds = (1u << KOF_VMATCH_TAG) | (1u << KOF_VMATCH_FAMILY) | (1u << KOF_VMATCH_VARIANT);
	rq.group = grp;
	rq.group_cap = n;
	rq.entry = ent;
	rq.entry_cap = n;
	rq.score = scr;
	rq.score_cap = nc;
	kof_vmatch(&rq, &res);
	/* The element lists (M, U, N) are not asked for (elems_cap 0), so TRUNCATED is the answer of a complete group, entry and
	 * score list. TOO_LARGE with groups made is one candidate's profile past its bound (its score says SKIPPED, cover 0: the
	 * others are computed). Anything else (a bound on the fired list, a bad request) is a refusal: the numbers are not read. */
	if ((res.status > KOF_VMATCH_TOO_LARGE) || (res.status == KOF_VMATCH_TOO_LARGE && res.n_groups == 0u) || res.n_groups > n ||
	    res.n_scores > nc)
		goto fail;
	kof_vdecide(&res, grp, ent, scr, &dec);
	if (dec.level == (uint32_t)KOF_VCAT_NONE)
		goto fail;
	lead = &dg[ent[dec.lead_entry].diag];
	memset(cat, 0, sizeof *cat);
	cat->level = (uint8_t)dec.level;
	cat->type = lead->type;
	cat->cut = (uint8_t)(*cut != 0);
	cat->other_types = dec.other_types;
	cat->cover = dec.cover;
	cat->jaccard = dec.jaccard;
	cat->n_groups = res.n_groups;
	cat->n_fired = n_meta;
	cat->family_id = dec.level == (uint32_t)KOF_VCAT_VARIANT ? lead->family_id : 0u;
	cat->variant_id = dec.level == (uint32_t)KOF_VCAT_VARIANT ? lead->variant_id : 0u;
	cat->tag_id = lead->tag_id;
	made = 1;
	ok = 1;
	goto out;
fail:
	if (!made && n_meta)
		*cut = 1;
out:
	free(fired);
	free(cand);
	free(pool);
	free(grp);
	free(ent);
	free(scr);
	free(tag.v);
	free(fam.v);
	free(var.v);
	return ok;
}

int kof_scan_verdict_cat(const struct kof_obj_ctx *ctx, struct kof_finding *v, struct kof_verdict_cat *cat, int *incomplete)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_verdict_in in;
	struct kof_verdict_disease *vd = NULL;
	uint32_t *dis = NULL, *diag = NULL, *meta = NULL, cap, i, n_dis = 0, n_diag = 0, n_meta = 0;
	int made = 0, cut = 0, has_cat = 0;

	memset(v, 0, sizeof *v);
	memset(cat, 0, sizeof *cat);
	*incomplete = 0;
	if (!sc || !sc->eng)
		return 0;
	sc->st.work_verdicts++;
	cap = sc->eng->n_diag;
	dis = calloc((size_t)cap + 1u, sizeof *dis);
	diag = calloc((size_t)sc->eng->n_diag + 1u, sizeof *diag);
	meta = calloc((size_t)sc->eng->n_diag + 1u, sizeof *meta);
	vd = calloc((size_t)cap + 1u, sizeof *vd);
	if (!dis || !diag || !vd || !meta) {
		/* no verdict at all is not a clean answer: it is made of this */
		*incomplete = 1;
		OC_LIMIT(sc, "disease list for the verdict not allocated");
		goto out;
	}
	sx_collect(ctx, dis, &n_dis, diag, &n_diag, meta, &n_meta);
	for (i = 0; i < n_dis; i++) {
		const struct kof_disease_ent *ent = kof_db_disease(sc->eng, dis[i]);

		vd[i].id = dis[i];
		vd[i].type = ent ? ent->type : 0xffu;
		vd[i].name = ent ? ent->name : NULL;
	}
	in.dis = vd;
	in.n_dis = n_dis;
	in.diag = diag;
	in.n_diag = n_diag;
	in.fmt = ctx ? ctx->format : 0u;
	in.arch = ctx ? ctx->arch : 0u;
	if (n_meta) {
		sc->st.work_catalogs++;
		has_cat = sx_catalog(sc, meta, n_meta, cat, &cut);
	}
	if (has_cat) {
		kof_verdict_make_cat(&in, cat, sc->eng->names, v);
		made = 1;
	} else if (n_dis) {
		kof_verdict_make(&in, v);
		made = 1;
	} else if (n_meta) {
		/* matched diagnoses whose catalog verdict could not be made (a bound) and no disease: the object is detected, and the
		 * cut says the name is missing; it is marked below. */
		*incomplete = 1;
	}
	if (cut)
		OC_LIMIT(sc, "catalog verdict: a bound cut the matched diagnoses");
	KOF_TRACE("[verdict] made=%d (catalog %d, %u disease(s), %u diagnose(s)), incomplete=%d%s%s\n", made, has_cat, (unsigned)n_dis,
		  (unsigned)n_diag, *incomplete, made ? ", name " : ", no verdict: the object is clean", made ? v->name : "");
out:
	free(dis);
	free(diag);
	free(meta);
	free(vd);
	/* A fact about the object, and the set the verdict read is whole only when it is. */
	if (kof_scan_incomplete(ctx) != 0)
		*incomplete = 1;
	/*
	 * MEMORY REFUSED INSIDE THE ANALYSIS THE VERDICT READ is a verdict that may be missing a
	 * disease, and sx_verdict_make only marks an object with NO verdict unfinished (a
	 * verdict already made is not taken back for a diagnose that could not add to it). So the
	 * object is cut here - broken = LIMIT, limit_hits - for the one status that is no bound of
	 * the object but an allocation that failed, and which therefore never fires in a normal run
	 * (the budget statuses are the object's own and stay as they were).
	 */
	if (kof_scan_diag_status(ctx) == KGENOME_NOMEM)
		OC_LIMIT(sc, "diagnose analysis ran out of memory, the verdict may lack a disease");
	return made;
}

/*
 * AN ANALYSIS THAT WAS NOT FINISHED, AND NOTHING MATCHED: that is not a clean
 * object, it is one the engine could not finish, and the result says so with the
 * reason that exists for it (a limit). Only when no verdict was made - an object that
 * already has one is not made "unfinished" by a diagnose that could not add to it - and
 * never over a reason an earlier stage already recorded.
 */
void sx_verdict_gap(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		    struct kof_result *res, int incomplete)
{
	if (!incomplete || res->broken)
		return;
	/*
	 * AN OPTIONAL ROUTE THAT RAN OUT ON AN OBJECT THAT OPENED IS NOT A CUT
	 * OBJECT. The emulate route of the diagnose scan spends its instruction
	 * budget on a packer's stub - an 811 KB static ELF unpacked by its own
	 * unpacker, whose child holds the program - and the object then came
	 * back "Limit reached" over a child that was scanned in full. The
	 * evidence is the child's (which carries its own status, and a cut of
	 * its own is reported there), so the wrapper is not marked. It stays
	 * visible: stats.analysis_moot counts it, the result says so
	 * (analysis_moot) for -v and an examiner, and DEBUG traces it. An
	 * object that did NOT open has nothing else to read, and the cut
	 * stays its LIMIT (rule 4).
	 */
	if (sx_opened(sc)) {
		res->analysis_moot = 1;
		sc->st.analysis_moot++;
		KOF_TRACE("[cut] analysis moot (diagnose status %d): the object opened into %u child(ren)\n",
			  (int)kof_scan_diag_status(ctx), (unsigned)sc->child.n);
	} else {
		oc_scan_limit(sc);	/* counted once (limit_hits) */
		res->broken = KOF_BROKEN_LIMIT;
	}
}

/*
 * THE OBJECT'S VERDICT, from the diseases it has: the verdictor names it (see
 * kof_verdict_make), this puts it in the result. The stage that asks runs once per
 * object, after every detector, rule and diagnose has said what it found.
 */
void sx_verdict_make(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		     struct kof_result *res)
{
	int incomplete;

	res->has_verdict = (uint8_t)(kof_scan_verdict_cat(ctx, &res->verdict, &res->cat, &incomplete) != 0);
	res->verdict_incomplete = (uint8_t)(incomplete != 0);
	if (!res->has_verdict)
		sx_verdict_gap(sc, ctx, res, incomplete);
}
