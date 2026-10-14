/*
 * scan_verdict.c - what the scan state says about a finding: its method word, the
 * verdict slot it may take, and the diseases the scan collected for the syndrome.
 *
 * The NAMES are the verdictor's (verdictor/); what they are made of is
 * state the scanner holds - which method answered, which disease was found - and
 * so reading it is the scanner's job.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objctx_int.h"
#include "../databases/pack/kofsyndrome.h"
#include "../verdictor/verdict.h"
#include "../kofcore/kofmod/heur.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * THE DISEASES AN OBJECT HAS - found by its detectors, heuristics and diagnoses - and
 * what they make - see
 * databases/pack/kofsyndrome.h. A normal scan runs the analysis only when a
 * diagnose that declares a disease can be answered on the object; the report
 * (kof_scan_option.report_diag) runs every diagnose.
 *
 * kof_scan_diseases writes up to `cap` disease ids to `out` (kof_db_disease turns
 * one into a name and a type) and returns how many matched, which may exceed
 * `cap`; two diagnoses that find the same disease count once.
 * kof_scan_syndrome infers the type from every one of them, and returns 0 when no
 * disease was found, or the database has no syndrome pack. What the detectors and
 * heuristics found is always there; the diagnoses' are added only when the object
 * was scanned for all of them (kof_scan_option.report_diag).
 */
static uint32_t kof_scan_diseases(const struct kof_obj_ctx *ctx, uint32_t *out,
			   uint32_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i, k, n = 0, lim;

	if (!sc || !sc->eng)
		return 0;
	/* What the modules found: always there, the scan collected it. */
	for (i = 0; i < sc->obj.n_dis_set; i++) {
		if (out && n < cap)
			out[n] = sc->subject.dis_set[i];
		n++;
	}
	/*
	 * What the diagnoses found: all of them when the caller asked for the report,
	 * otherwise the ones that declare a disease (the verdict reads those). The
	 * analysis is run for it only when one of them is answerable on this object
	 * (kof_scan_diag_feeds_verdict); one that already ran - a rule asked - is
	 * read as it stands.
	 */
	if (!sc->obj.diag.all && !sc->obj.diag.graph &&
	    !kof_scan_diag_feeds_verdict(ctx))
		return n;
	kof_scan_diag_force(ctx);
	oc_diag_trace_scan(sc);
	if (!sc->obj.diag.graph)
		return n;
	lim = kof_scan_diag_count(ctx);
	for (i = 0; i < lim; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];
		int seen = 0;

		if (!d->disease || !((sc->diag.hit[i >> 3] >> (i & 7u)) & 1u))
			continue;
		/*
		 * A disease more than one detector found is one finding - read off the
		 * modules' set and the diagnoses already passed, not off `out`, so the
		 * count is the same whether or not the caller gave a buffer.
		 */
		for (k = 0; k < sc->obj.n_dis_set; k++)
			if (sc->subject.dis_set[k] == d->disease)
				seen = 1;
		for (k = 0; k < i && !seen; k++)
			if (sc->eng->diag[k].disease == d->disease &&
			    ((sc->diag.hit[k >> 3] >> (k & 7u)) & 1u))
				seen = 1;
		if (seen)
			continue;
		if (out && n < cap)
			out[n] = d->disease;
		n++;
	}
	return n;
}

int kof_scan_syndrome(const struct kof_obj_ctx *ctx, struct kof_synd_result *r)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t *dis, cap, n;
	int rc = 0;

	memset(r, 0, sizeof *r);
	if (!sc || !sc->eng)
		return 0;
	/* Room for every disease there can be - the modules' and one per diagnose -
	 * so that nothing is cut to fit a table: a disease left out is evidence the
	 * inference never saw. */
	cap = sc->obj.n_dis_set + sc->eng->n_diag;
	dis = calloc((size_t)cap + 1u, sizeof *dis);
	if (!dis) {
		/* no inference at all is not a clean answer: the verdict is made of this */
		r->incomplete = 1;
		OC_LIMIT(sc, "disease list for the syndrome not allocated");
		return 0;
	}
	n = kof_scan_diseases(ctx, dis, cap);
	if (sc->eng->synd) {
		rc = kof_synd_infer(sc->eng->synd, dis, n < cap ? n : cap, r);
		/*
		 * kof_synd_infer answers n_query == 0 for an empty question and ALSO when its
		 * working set could not be allocated (it has no status to say so, and is not
		 * this file's to change): diseases were asked and none was counted, which is
		 * the second.
		 */
		if (n && !r->n_query) {
			r->incomplete = 1;
			OC_LIMIT(sc, "syndrome inference not allocated");
		}
	} else {
		r->n_query = n < cap ? n : cap;     /* diseases, and nothing to read them by */
	}
	free(dis);
	/* AFTER the inference, which writes the whole result: whether the set it
	 * read is whole is a fact about the object and not about the profiles. */
	r->incomplete = (uint32_t)(r->incomplete || kof_scan_incomplete(ctx) != 0);
	/*
	 * MEMORY REFUSED INSIDE THE ANALYSIS THE VERDICT READ is a verdict that may be missing a
	 * disease, and sx_syndrome_verdict only marks an object with NO finding unfinished (a
	 * finding already made is not taken back for a diagnose that could not add to it). So the
	 * object is cut here - broken = LIMIT, limit_hits - for the one status that is no bound of
	 * the object but an allocation that failed, and which therefore never fires in a normal run
	 * (the budget statuses are the object's own and stay as they were).
	 */
	if (kof_scan_diag_status(ctx) == KGENOME_NOMEM)
		OC_LIMIT(sc, "diagnose analysis ran out of memory, the verdict may lack a disease");
	return rc;
}


/*
 * THE OBJECT'S VERDICT, from the diseases it has: the verdictor names it (see
 * kof_verdict_syndrome), this puts it in the result and the file's slot. The
 * stage that asks runs once per object, after every detector, rule and diagnose
 * has said what it found.
 */
void sx_syndrome_verdict(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt, struct kof_result *res,
			 const struct kof_synd_result *r)
{
	struct kof_verdict_in in;
	struct kof_finding *f;

	if (!r->n_query) {
		/*
		 * NOTHING MATCHED, AND NOT EVERYTHING WAS ASKED: that is not a clean
		 * object, it is one the engine could not finish, and the result says
		 * so with the reason that exists for it (a limit). Only when no finding
		 * of any kind was made - an object that already has a detection is not
		 * made "unfinished" by a diagnose that could not add to it - and never
		 * over a reason an earlier stage already recorded.
		 */
		if (r->incomplete && !res->n && !res->broken) {
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
		return;
	}
	if (res->n >= KOF_MAX_FINDINGS) {
		res->dropped++;
		return;
	}
	in.synd = r;
	in.fmt = ctx ? ctx->format : 0u;
	in.arch = ctx ? ctx->arch : 0u;
	f = &res->v[res->n++];
	kof_verdict_syndrome(&in, f);
	f->is_verdict = (uint8_t)sx_verdict_take(sc, f, opt->all_matches, 0);
}

/*
 * WHETHER A DISEASE STANDS FOR A MODULE'S FINDING: the module declared one, so the
 * set the syndromes read holds it (sx_disease_add) and the object's verdict is
 * composed from the set. An unpacker's report is not read through a disease - it
 * names what opened - and is never covered.
 */
int sx_finding_covered(const struct kof_module *m, const struct kof_finding *f)
{
	return m && m->disease && f->engine != (uint8_t)KOF_ENGINE_UNPACKER;
}

/*
 * TAKE A FINDING INTO THE FILE'S ONE VERDICT SLOT - see sc->subject.slot.
 *
 * Returns 1 when the slot now holds this finding, 0 when it was kept out by
 * one that outranks it. The caller still has the finding in the object's own
 * array either way: the array is how an EXAMINER sees everything that fired,
 * and the slot is what a scan REPORTS. Two different questions, and losing
 * the first to answer the second is what the note above KOF_MAX_FINDINGS
 * warns against.
 *
 * `covered` is the one reason a finding stays out of the slot by KIND: a
 * disease stands for it (sx_finding_covered), so the syndrome verdict of the
 * object (sx_syndrome_verdict) is what reports it, under the name the
 * syndromes compose. Every other finding IS its object's answer and takes
 * the slot by rank. The filter used to be the finding's ENGINE - only the
 * syndrome's and an unpacker's took - which answered "covered" for every
 * detector, rule and model of a database that declares no disease at all
 * (the shipped one): 358 of 358 files the roll-up counted infected, suspected
 * or heuristic over 791 corpus files delivered no verdict event, and a packed
 * miner came back "infected 1 file(s)" with nothing above it. The roll-up
 * (kverdict_filemap_fold) and the events now read one fact: a finding either
 * has a disease behind it that makes the verdict, or it is the verdict.
 */
int sx_verdict_take(struct kof_scanner *sc, const struct kof_finding *f,
			int all_matches, int covered)
{
	int rank, have;

	if (!sc || !f || covered)
		return 0;
	rank = kverdict_level_rank(f->level);
	have = sc->subject.have ? kverdict_level_rank(sc->subject.lvl) : -1;
	/*
	 * ALL MATCHES MEANS EVERY FINDING IS REPORTED, and the engine says
	 * so here rather than leaving a host to work it out.
	 *
	 * The alternative was a host that skipped findings the engine had
	 * not marked unless the user had passed a flag - which puts the
	 * rule "what does a scan report" in the tool, where a second tool
	 * will write it differently. A scanner takes what the user asked
	 * for and prints what the engine answered; deciding which findings
	 * count is not its question.
	 *
	 * The slot still tracks the strongest, because a FILE's verdict is
	 * one thing even when every finding is listed.
	 */
	if (all_matches) {
		if (have <= rank) {
			sc->subject.slot      = *f;
			sc->subject.lvl  = f->level;
			sc->subject.have = 1;
		}
		return 1;
	}
	/* Equal rank keeps the first: whichever matcher the engine reached
	 * first is the one that answered. */
	if (have >= rank)
		return 0;
	sc->subject.slot      = *f;
	sc->subject.lvl  = f->level;
	sc->subject.have = 1;
	return 1;
}

/*
 * THE VALUES BEHIND A VERDICT, filled in one place so that no call site has
 * to know the form - see kof_verdict_name.
 *
 * `cls` is the module's declared class, and `family_off` is what proves it
 * was declared: KOF_MALTYPE_VIRUS is 0, so a module that said nothing has a
 * maltype that reads as "Virus", and absence must not become a claim.
 */
static void sx_verdict_vals(struct kof_finding *f, const struct kof_obj_ctx *ctx,
			 const struct kof_module *m, uint32_t engine)
{
	f->fmt    = ctx ? ctx->format : 0u;
	f->arch   = ctx ? ctx->arch : 0u;
	f->engine = (uint8_t)engine;
	f->verdict = (uint8_t)(f->level == KOF_LEVEL_INFECT
			       ? KOF_VERDICT_INFECTED
			       : f->level == KOF_LEVEL_SUSPECT
				 ? KOF_VERDICT_SUSPECTED
				 : KOF_VERDICT_HEUR);
	f->type = 0;
	f->type_known = 0;
	if (m && m->kind == KOF_PACK_HEUR) {
		/*
		 * A RULE READS THE PARSE, whatever the caller was doing when
		 * it fired, and the only thing it may claim is a TYPE - see
		 * KOF_HEUR_SCAN_CLASS. It has no family of its own: the
		 * build tool refuses KOF_TARGET_NAME on a rule, because a
		 * shape many programs share cannot name one program.
		 */
		/*
		 * THE PARSE, UNLESS IT READ THE GRAPH. A rule that reached
		 * its conclusion through kof_diag did not reach it through
		 * the parse, and the method word is the one field that says
		 * which - same test as the detector path below, same scope.
		 */
		{
			const struct kof_scanner *sc = kof_scan_of(ctx);

			f->engine = (uint8_t)(sc && sc->mod.diag_read
					      ? KOF_ENGINE_DIAGNOSE
					      : KOF_ENGINE_ANALYZER);
		}
		if (KOF_ENG_CLASS_OF(m->heur_want)) {
			f->type = (uint8_t)(KOF_ENG_CLASS_OF(m->heur_want)
					    - 1u);
			f->type_known = 1;
		}
	} else if (m && m->family_off) {
		f->type = (uint8_t)m->maltype;
		f->type_known = 1;
	}
}

void sx_finding_str(const struct kof_scanner *sc,
			const struct kof_obj_ctx *ctx,
			const struct kof_module *m, struct kof_finding *f)
{
	const char *variant = kof_db_name(sc->eng, m, sc->mod.rep_name_id);
	const char *family  = kof_db_family(sc->eng, m);

	/*
	 * A RULE THAT PREDICTS A FAMILY names itself by the prediction.
	 *
	 * <target>/Heur:<family>#<variant>?<shape>: the FAMILY slot holds what the
	 * rule predicts the object is, and the "?" carries the one thing a
	 * heuristic must admit - that the family is a guess, and the SHAPE after
	 * the mark is all that was actually shown. Composed here, with the other
	 * names, and not at the rule's call site: it was the one place a finding
	 * was named outside this function. With no prediction the shape is all
	 * there is, and the general path below writing it as the family is right.
	 */
	if (m && m->kind == KOF_PACK_HEUR) {
		const char *pf = kof_db_heur_predict(sc->eng, m);

		if (pf && pf[0]) {
			sx_verdict_vals(f, ctx, m, KOF_ENGINE_ANALYZER);
			/*
			 * A rule may predict the TYPE - see KOF_HEUR_SCAN_CLASS -
			 * and that is the only thing it may predict; the family it
			 * recognised goes where a family goes.
			 */
			if (KOF_ENG_CLASS_OF(m->heur_want)) {
				f->type = (uint8_t)(KOF_ENG_CLASS_OF(m->heur_want) - 1u);
				f->type_known = 1;
			}
			kof_verdict_name(f, pf, variant, family);
			return;
		}
	}

	/*
	 * AN UNPACKER THAT NAMED WHAT IT COULD NOT OPEN. The module identified
	 * the packer and recorded why nothing came out of it, so the finding is
	 * the pair: the packer is the family and the reason is the reason, under
	 * the method word that says an unpacker produced it - not the analyzer's
	 * parse and not a pattern. `Heur#ELF-x64/Packer:MidgetPack.00!Unpacker?
	 * Encrypted` is what a reader gets, where before the only trace was a
	 * "broken" count with no name beside it.
	 */
	if (m && m->kind == KOF_PACK_UNPACK && m->family_off) {
		const char *why = sc->mod.rep_reason == KOF_BROKEN_ENCRYPTED ? "Encrypted"
				: sc->mod.rep_reason == KOF_BROKEN_DAMAGED ? "Damaged"
				: sc->mod.rep_reason == KOF_BROKEN_UNSUPPORTED ? "Unsupported"
				: sc->mod.rep_reason == KOF_BROKEN_LIMIT ? "Limit" : NULL;

		sx_verdict_vals(f, ctx, m, KOF_ENGINE_UNPACKER);
		kof_verdict_name(f, (family && family[0]) ? family : "unknown",
				 variant, why);
		return;
	}
	/* The target word, the type word and the order they go in are
	 * kof_verdict_name's now - see the note there. */
	/*
	 * A SIMILARITY VERDICT CARRIES ITS SCORE AND SAYS WHAT IT IS.
	 *
	 * <target>/<type>:<family>#<score>!Mutation. The slot that holds a
	 * variant for a pattern rule holds the MEASUREMENT for this one,
	 * because that is what a reader of such a verdict needs: a rule
	 * demanding fifty and a sample scoring eighty-three are different
	 * facts, and the variant a hand-written rule could put there cannot
	 * know either. The mark names the method, exactly as a heuristic's
	 * does - see kverdict_name.
	 *
	 * ASKED IS NOT THE SAME AS ANSWERED, and reading it as though it were
	 * was a bug with a name on it. sc->mod.mutation_asked only says
	 * kof_mutation_score was CALLED. A rule written as
	 *
	 *     if (kof_mutation_score(blk) >= 50u) ...
	 *     if (kof_find_str_all(rng, s0, s1)) ...
	 *
	 * calls it on every object, so a file that matched the STRING was
	 * named "#<the block>!Mutation?0" - a verdict announcing the method
	 * that did not reach it, and a score of nought beside a detection.
	 *
	 * So the block has to have matched something. Not "reached the rule's
	 * threshold", which the engine cannot know - the threshold is a
	 * number in the module's own code - but at least one hash in common.
	 * A rule whose block scored under its threshold while a string
	 * carried the verdict still reports the block's number, and that is
	 * the honest residue: the block did find something, just not enough.
	 */
	if (sc->mod.mutation_asked >= 0 && sc->mod.n_mutation_blk && sc->mod.mutation_hit &&
	    !sc->mod.str_hit) {
		char shape[16];
		/* The best single block's containment - see
		 * kof_scanner.mod.mutation_best for why it is not the set's. */
		unsigned pct = sc->mod.mutation_best;

		if (pct > 100u)
			pct = 100u;

		/*
		 * <family>#<the rule's id>!Mutation?<how much of its blocks>.
		 *
		 * THE VARIANT IS THE RULE'S ID, like every other method's. It was the fold
		 * of the block hashes, an eight-digit hex string, so a mutation finding read
		 * `Mirai.9d8c6f7e` where a pattern finding of the same family reads
		 * `Mirai.02`: the one field that names WHICH RULE in the database was a
		 * rule's id for one method and a hash for another, and nothing that read the
		 * name could look the rule up. The measurement stays where it always was,
		 * behind the mark, and the identity of the block set is still on the finding
		 * as sim_of for a tool that wants it - it is a property of the blocks, and
		 * the id is a property of the rule, which is what a name is for.
		 */
		f->sim_pct = (uint8_t)pct;
		f->sim_kind = (uint8_t)KOF_SIM_MUTATION;
		f->sim_of = kof_mutation_name_of(sc->mod.mutation_blk,
					       sc->mod.n_mutation_blk);
		snprintf(shape, sizeof shape, "%u", pct);
		sx_verdict_vals(f, ctx, m, KOF_ENGINE_MUTATION);
		kof_verdict_name(f, (family && family[0]) ? family : "unknown",
				 variant, shape);
		return;
	}
	/*
	 * AND A FINDING THAT CAME OFF THE NODE GRAPH SAYS SO.
	 *
	 * Same test as the two measures above: asked, answered, and no
	 * pattern of its own matched. A rule that matched bytes AND read the
	 * graph is a pattern finding - the bytes are what reached it, and
	 * naming the expensive half would send a reader to the wrong place.
	 */
	if (sc->mod.diag_read && !sc->mod.str_hit) {
		sx_verdict_vals(f, ctx, m, KOF_ENGINE_DIAGNOSE);
		kof_verdict_name(f, (family && family[0]) ? family : "unknown",
				 variant, NULL);
		return;
	}
	sx_verdict_vals(f, ctx, m, KOF_ENGINE_PATTERN);
	kof_verdict_name(f, (family && family[0]) ? family : "unknown",
			 variant, NULL);
}

