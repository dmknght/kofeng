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

#include "scan_int.h"
#include "objctx_int.h"
#include "../verdictor/verdict.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * THE DISEASES AN OBJECT HAS - the ones the diagnoses that matched declare - and which
 * diagnoses those were. A normal scan runs the analysis only when a diagnose that
 * declares a disease can be answered on the object; the report
 * (kof_scan_option.report_diag) runs every diagnose.
 *
 * `dis` and `diag` have room for one id per diagnose, so nothing is cut to fit a table: a
 * disease left out is evidence the verdict never saw. Two diagnoses that find the same
 * disease count it once; both are in `diag`.
 */
static void sx_collect(const struct kof_obj_ctx *ctx, uint32_t *dis, uint32_t *n_dis,
		       uint32_t *diag, uint32_t *n_diag)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i, k, n = 0, nd = 0, lim;

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

			if (!d->disease || !((sc->diag.hit[i >> 3] >> (i & 7u)) & 1u))
				continue;
			diag[nd++] = d->id;
			for (k = 0; k < n && !seen; k++)
				seen = dis[k] == d->disease;
			if (!seen)
				dis[n++] = d->disease;
		}
	}
	*n_dis = n;
	*n_diag = nd;
}

int kof_scan_verdict(const struct kof_obj_ctx *ctx, struct kof_finding *v,
		     int *incomplete)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_verdict_in in;
	struct kof_verdict_disease *vd = NULL;
	uint32_t *dis = NULL, *diag = NULL, cap, i, n_dis = 0, n_diag = 0;
	int made = 0;

	memset(v, 0, sizeof *v);
	*incomplete = 0;
	if (!sc || !sc->eng)
		return 0;
	cap = sc->eng->n_diag;
	dis = calloc((size_t)cap + 1u, sizeof *dis);
	diag = calloc((size_t)sc->eng->n_diag + 1u, sizeof *diag);
	vd = calloc((size_t)cap + 1u, sizeof *vd);
	if (!dis || !diag || !vd) {
		/* no verdict at all is not a clean answer: it is made of this */
		*incomplete = 1;
		OC_LIMIT(sc, "disease list for the verdict not allocated");
		goto out;
	}
	sx_collect(ctx, dis, &n_dis, diag, &n_diag);
	for (i = 0; i < n_dis; i++) {
		const struct kof_disease_ent *ent = kof_db_disease(sc->eng, dis[i]);

		vd[i].id = dis[i];
		vd[i].type = ent ? ent->type : 0xffu;
		vd[i].name = ent ? ent->name : NULL;
	}
	if (n_dis) {
		in.dis = vd;
		in.n_dis = n_dis;
		in.diag = diag;
		in.n_diag = n_diag;
		in.fmt = ctx ? ctx->format : 0u;
		in.arch = ctx ? ctx->arch : 0u;
		kof_verdict_make(&in, v);
		made = 1;
	}
out:
	free(dis);
	free(diag);
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

	res->has_verdict = (uint8_t)(kof_scan_verdict(ctx, &res->verdict, &incomplete) != 0);
	res->verdict_incomplete = (uint8_t)(incomplete != 0);
	if (!res->has_verdict)
		sx_verdict_gap(sc, ctx, res, incomplete);
}
