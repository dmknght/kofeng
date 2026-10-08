/*
 * scan_verdict.c - naming a finding: the verdict word, the target, the family and
 * what the engine says about how it was reached.
 *
 * kverdict_* compose the string once, forward, and record where each part landed, so
 * nothing downstream searches for a separator. finding_str decides which method word
 * (Pattern, Plague, Overlord, Pathogen, Analyzer, Unpacker) a finding carries from
 * what was asked and ANSWERED while its module ran; verdict_take decides whether a
 * finding owns the object's one verdict slot.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../../libgenome/genotype/analysis/xref.h"
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


/*
 * The one spelling. See kverdict_compose in kofeng.h for why it is a function.
 *
 * "#" between the family and the variant, not "-": a family name may contain a
 * hyphen and several in bases/ do, so the old separator could not be told from
 * the name around it by eye or by anything reading the string back. "#" appears
 * in no family and in no variant.
 */
void kverdict_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant)
{
	int has_t = target && target[0];
	int has_v = variant && variant[0];

	if (!out || !cap)
		return;
	if (has_t && has_v)
		snprintf(out, cap, "%s/%s:%s#%s", target, maltype, family,
			 variant);
	else if (has_t)
		snprintf(out, cap, "%s/%s:%s", target, maltype, family);
	else if (has_v)
		snprintf(out, cap, "%s:%s#%s", maltype, family, variant);
	else
		snprintf(out, cap, "%s:%s", maltype, family);
}

/*
 * Compose onto a finding, and say where each part went.
 *
 * Written once, forward, so the offsets fall out of the writing rather than
 * being searched for afterwards - which is the whole point: nothing downstream
 * should ever have to look for a separator this function just placed.
 */
static void span_put(struct kof_finding *f, struct kof_name_span *sp,
		     size_t *at, const char *text)
{
	size_t n = 0;

	sp->at = (uint16_t)*at;
	if (text)
		while (text[n] && *at + n + 1u < sizeof f->name) {
			f->name[*at + n] = text[n];
			n++;
		}
	sp->n = (uint16_t)n;
	*at += n;
}

static void sep_put(struct kof_finding *f, size_t *at, char c)
{
	if (*at + 1u < sizeof f->name)
		f->name[(*at)++] = c;
}

void kverdict_name(struct kof_finding *f, const char *target,
		      const char *maltype, const char *family,
		      const char *variant, const char *shape)
{
	size_t at = 0;

	if (!f)
		return;
	f->target.at = f->target.n = 0;
	f->maltype = f->family = f->variant = f->shape = f->target;

	if (target && target[0]) {
		span_put(f, &f->target, &at, target);
		sep_put(f, &at, '/');
	}
	span_put(f, &f->maltype, &at, maltype);
	sep_put(f, &at, ':');
	span_put(f, &f->family, &at, family);
	if (variant && variant[0]) {
		sep_put(f, &at, '#');
		span_put(f, &f->variant, &at, variant);
	}
	if (shape && shape[0]) {
		/*
		 * "!" AND NOT "?".
		 *
		 * The mark says HOW the verdict was reached - a shape a
		 * heuristic recognised, a similarity measurement - and "?"
		 * reads as doubt about the whole name rather than as a label on
		 * the part after it. A reader scanning a log sees
		 * "Heur:Meterp#3!Shellcode" as a finding with its method
		 * attached, where the same line with a question mark reads as
		 * the engine being unsure it found anything.
		 */
		sep_put(f, &at, '!');
		span_put(f, &f->shape, &at, shape);
	}
	f->name[at] = 0;
}

/*
 * GET THE VERDICT NAME - see kofeng.h for the form and why it lives here.
 *
 * Written once, forward, so every span falls out of the writing. The fields
 * it reads are the enums on the finding; the three it is handed are the ones
 * that cannot be enums - a family a researcher chose, a variant, and a
 * reason some findings have and most do not.
 */
void kof_verdict_name(struct kof_finding *f, const char *family,
		      const char *variant, const char *reason)
{
	char tgt[32];
	size_t at = 0;

	if (!f)
		return;
	f->target.at = f->target.n = 0;
	f->maltype = f->family = f->variant = f->shape = f->reason = f->target;

	/*
	 * How sure, first, because that is what a reader sorts a log by. No
	 * span: the word is kof_verdict_word(f->verdict) and a caller that
	 * wants it has the value, so recording where it landed would be a
	 * second copy of a fact that cannot drift from itself.
	 */
	span_put(f, &f->target, &at, kof_verdict_word(f->verdict));
	f->target.at = f->target.n = 0;
	/*
	 * A HASH HERE AND A BANG LATER, and the reason is typographic
	 * rather than semantic: '#' is the wider glyph, so it makes the
	 * stronger break, and the strongest break in this name is between
	 * how sure the engine is and everything else. What follows -
	 * family, variant, engine - is one run about one thing, and the
	 * narrow '!' keeps it reading as a run.
	 */
	sep_put(f, &at, '#');

	kverdict_target(tgt, sizeof tgt, f->fmt, f->arch);
	if (tgt[0]) {
		span_put(f, &f->target, &at, tgt);
		sep_put(f, &at, '/');
	}

	/*
	 * WHAT IT IS. A rule that recognised a shape has not established a
	 * class and says so - `type_known` is 0 - and then the word is the
	 * one the vocabulary already has for "a rule, not a signature".
	 * Writing a maltype there would be claiming something nobody did.
	 */
	span_put(f, &f->maltype, &at,
		 f->type_known ? kof_maltype_name(f->type) : "Heur");
	sep_put(f, &at, ':');
	span_put(f, &f->family, &at, family);

	if (variant && variant[0]) {
		/*
		 * A DOT, because a variant is part of the family's name and
		 * not a mark against it: "Mirai.01" reads as one name with a
		 * generation, where "Mirai!01" reads as two things stuck
		 * together.
		 */
		sep_put(f, &at, '.');
		span_put(f, &f->variant, &at, variant);
	}
	if (f->engine != (uint8_t)KOF_ENGINE_NONE) {
		/* Attached, not separated: how it was found is an addition
		 * to the name above it, not a new field of equal weight. */
		sep_put(f, &at, '!');
		span_put(f, &f->shape, &at, kof_engine_name(f->engine));
	}
	if (reason && reason[0]) {
		sep_put(f, &at, '?');
		span_put(f, &f->reason, &at, reason);
	}
	f->name[at] = 0;
}

/*
 * "ELF-x64", or "ELF" when there is no architecture to name.
 *
 * An object with no architecture - a script, or one nothing identified - gets
 * the format alone: a "-any" suffix would be a field describing nothing.
 */
void kverdict_target(char *out, size_t cap, uint8_t format, uint8_t arch)
{
	const char *fmt = kof_format_name(format);

	if (arch == KOF_ARCH_ANY || format == KOF_FMT_UNKNOWN)
		snprintf(out, cap, "%s", fmt);
	else
		snprintf(out, cap, "%s-%s", fmt, kof_arch_name(arch));
}

/*
 * TAKE A FINDING INTO THE FILE'S ONE VERDICT SLOT - see kof_scanner.verdict.
 *
 * Returns 1 when the slot now holds this finding, 0 when it was kept out by
 * one that outranks it. The caller still has the finding in the object's own
 * array either way: the array is how an EXAMINER sees everything that fired,
 * and the slot is what a scan REPORTS. Two different questions, and losing
 * the first to answer the second is what the note above KOF_MAX_FINDINGS
 * warns against.
 */
int sx_verdict_take(struct kof_scanner *sc, const struct kof_finding *f,
			int all_matches)
{
	int rank, have;

	if (!sc || !f)
		return 0;
	rank = kverdict_level_rank(f->level);
	have = sc->verdict_have ? kverdict_level_rank(sc->verdict_lvl) : -1;
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
			sc->verdict      = *f;
			sc->verdict_lvl  = f->level;
			sc->verdict_have = 1;
		}
		return 1;
	}
	/* Equal rank keeps the first: whichever matcher the engine reached
	 * first is the one that answered. */
	if (have >= rank)
		return 0;
	sc->verdict      = *f;
	sc->verdict_lvl  = f->level;
	sc->verdict_have = 1;
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
void sx_verdict_vals(struct kof_finding *f, const struct kof_obj_ctx *ctx,
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

			f->engine = (uint8_t)(sc && sc->diag_read
					      ? KOF_ENGINE_PATHOGEN
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
	const char *variant = kof_db_name(sc->eng, m, sc->rep_name_id);
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
		const char *why = sc->rep_reason == KOF_BROKEN_ENCRYPTED ? "Encrypted"
				: sc->rep_reason == KOF_BROKEN_DAMAGED ? "Damaged"
				: sc->rep_reason == KOF_BROKEN_UNSUPPORTED ? "Unsupported"
				: sc->rep_reason == KOF_BROKEN_LIMIT ? "Limit" : NULL;

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
	 * <target>/<type>:<family>#<score>!Plague. The slot that holds a
	 * variant for a pattern rule holds the MEASUREMENT for this one,
	 * because that is what a reader of such a verdict needs: a rule
	 * demanding fifty and a sample scoring eighty-three are different
	 * facts, and the variant a hand-written rule could put there cannot
	 * know either. The mark names the method, exactly as a heuristic's
	 * does - see kverdict_name.
	 *
	 * ASKED IS NOT THE SAME AS ANSWERED, and reading it as though it were
	 * was a bug with a name on it. sc->plague_asked only says
	 * kof_plague_score was CALLED. A rule written as
	 *
	 *     if (kof_plague_score(blk) >= 50u) ...
	 *     if (kof_find_str_all(rng, s0, s1)) ...
	 *
	 * calls it on every object, so a file that matched the STRING was
	 * named "#<the block>!Plague?0" - a verdict announcing the method
	 * that did not reach it, and a score of nought beside a detection.
	 *
	 * So the block has to have matched something. Not "reached the rule's
	 * threshold", which the engine cannot know - the threshold is a
	 * number in the module's own code - but at least one hash in common.
	 * A rule whose block scored under its threshold while a string
	 * carried the verdict still reports the block's number, and that is
	 * the honest residue: the block did find something, just not enough.
	 */
	if (sc->plague_asked >= 0 && sc->n_plague_blk && sc->plague_hit &&
	    !sc->str_hit) {
		char shape[16];
		/* The best single block's containment - see
		 * kof_scanner.plague_best for why it is not the set's. */
		unsigned pct = sc->plague_best;

		if (pct > 100u)
			pct = 100u;

		/*
		 * <family>#<the rule's id>!Plague?<how much of its blocks>.
		 *
		 * THE VARIANT IS THE RULE'S ID, like every other method's. It was the fold
		 * of the block hashes, an eight-digit hex string, so a plague finding read
		 * `Mirai.9d8c6f7e` where a pattern finding of the same family reads
		 * `Mirai.02`: the one field that names WHICH RULE in the database was a
		 * rule's id for one method and a hash for another, and nothing that read the
		 * name could look the rule up. The measurement stays where it always was,
		 * behind the mark, and the identity of the block set is still on the finding
		 * as sim_of for a tool that wants it - it is a property of the blocks, and
		 * the id is a property of the rule, which is what a name is for.
		 */
		f->sim_pct = (uint8_t)pct;
		f->sim_kind = (uint8_t)KOF_SIM_PLAGUE;
		f->sim_of = kof_plague_name_of(sc->plague_blk,
					       sc->n_plague_blk);
		snprintf(shape, sizeof shape, "%u", pct);
		sx_verdict_vals(f, ctx, m, KOF_ENGINE_PLAGUE);
		kof_verdict_name(f, (family && family[0]) ? family : "unknown",
				 variant, shape);
		return;
	}
	/*
	 * AND THE SAME FOR A SIMILARITY MEASURE THAT CARRIES ITS OWN
	 * REFERENCE - kof_plague_blocks, kof_plague_shape.
	 *
	 * The mark goes BEHIND the variant, where every other method's does,
	 * and not in front of it. It was a prefix on the variant for one
	 * revision - "Ovl-3f2ka" - which put the method inside the field that
	 * names the pattern, so the two could no longer be told apart by
	 * anything reading the name. A variant is a variant; what recognised
	 * it is the shape.
	 *
	 * ASKED AND ANSWERED, as above: a measure that returned nothing did
	 * not reach this verdict and does not get to name it.
	 */
	if (sc->ovl_asked >= 0 && sc->ovl_pct) {
		char shape[16];

		f->sim_pct = (uint8_t)(sc->ovl_pct > 100u ? 100u
							  : sc->ovl_pct);
		f->sim_kind = (uint8_t)KOF_SIM_OVERLORD;
		snprintf(shape, sizeof shape, "%u", sc->ovl_pct);
		sx_verdict_vals(f, ctx, m, KOF_ENGINE_OVERLORD);
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
	if (sc->diag_read && !sc->str_hit) {
		sx_verdict_vals(f, ctx, m, KOF_ENGINE_PATHOGEN);
		kof_verdict_name(f, (family && family[0]) ? family : "unknown",
				 variant, NULL);
		return;
	}
	sx_verdict_vals(f, ctx, m, KOF_ENGINE_PATTERN);
	kof_verdict_name(f, (family && family[0]) ? family : "unknown",
			 variant, NULL);
}
