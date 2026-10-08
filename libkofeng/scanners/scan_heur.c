/*
 * scan_heur.c - the heuristic stages: the rules that read the parse (EXAMINE before
 * the object is opened, VERDICT after), and the one model score over the whole
 * object.
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
 * THE FORMS OF A SCRIPT, AS OBJECTS - and deliberately NOT inside
 * sx_unpack_object.
 *
 * It was in there, which looked tidy and was wrong three ways, and the third
 * one is why nothing ever came of it:
 *
 *   - sx_unpack_object returns at its first line when the database has no
 *     unpacker modules. kofviewer opened with no --db is exactly that engine,
 *     so the reader who asked to see the folded form of a shell got a tree
 *     with no child in it and no reason given. Folding needs a lexical table
 *     and a parse; it does not need a database, and nothing about it should
 *     have been behind one.
 *   - it returns again once a signature has NAMED the object, unless the
 *     caller asked for every match. That is the right economy for a scan and
 *     the wrong one for these: a named webshell is the case where seeing what
 *     it builds matters most.
 *   - and it is under kof_mod_unpack_mode, which is about what a MODULE may
 *     do to the object it was handed. No module is involved here.
 *
 * What it does keep is the deep-scan gate, because that is the one condition
 * that is genuinely shared: everything here produces a child, and deep off
 * means do not descend.
 *
 * ONE CHILD AND NOT ONE PER PASS. The level is what the passes cost, not what
 * they are for: the form pass runs wherever the heuristics run, and level 2 -
 * the rung that already means "do the expensive thing the cheap things cannot"
 * - adds the fold, which walks every assignment looking for a constant right
 * hand side. What comes out is one object either way, in the LAST form the
 * levels asked for. A tree that carried the intermediate as well made the
 * reader decide which node to take a marker from, and the answer was never the
 * intermediate.
 */
int sx_script_forms(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth)
{
	if (sc->broken || ctx->format != KOF_FMT_SCRIPT)
		return 0;
	if (!kof_objtree_may_open(opt) || pdepth > EMU_MAX_PACKER_DEPTH)
		return 0;

	return kof_scan_script_forms(ctx, opt->heur_level >= 2) != 0;
}

/*
 * WHAT THE HEURISTIC IS ALLOWED TO SEE, AND WHY IT IS GATHERED HERE.
 *
 * Everything below already exists by the time this runs: the anomaly word came
 * out of the parse, the depth came down the walk, and whether an unpacker gave up
 * is the value sx_unpack_object just returned. Nothing is searched for and no pass is
 * made over the object, which is why this runs unless the caller switched it off
 * rather than only when the caller asked for it.
 *
 * Marker-derived evidence is deliberately absent. Knowing that a family has two
 * markers present but did not fire means asking about markers whose module's
 * logic never reached them, which is a pass over the object that would
 * otherwise not happen - so it is not free, and nothing here gathers it. There
 * was a --heur level for asking; it gathered nothing and changed no verdict, so
 * it is gone. If that evidence is ever collected it needs its own switch again,
 * and the switch should arrive with the collector rather than before it.
 */
void sx_heur_object(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth,
			uint32_t partial, struct kof_result *out)
{
	const struct kof_heur_model *m = kof_heur_default();
	struct kof_heur_facts f;
	const char *guess = "Unknown";
	int32_t score = 0;

	if (opt->heur_off)
		return;

	/*
	 * AN ELF THE MODEL WAS MEASURED ON, WHICH IS AN EXECUTABLE OR A SHARED
	 * OBJECT AND NOT A RELOCATABLE ONE.
	 *
	 * Every weight in kofheur.c came from a population of 6523 malware and
	 * 13638 clean ELF objects, and that population is programs. An ET_REL is
	 * a different shape: no program headers, no entry point, sections that
	 * the module loader relocates rather than maps. Asking the table about
	 * one is asking it a question it was never measured against, and the
	 * answer it gives is the one a machine sees most - every .ko under
	 * /lib/modules came back "ELF-x64/Heur:Truncated".
	 *
	 * The bar is what makes that serious. 747 centinats was chosen because
	 * no clean object in the measured corpus reached it; a population that
	 * was not in the corpus has no such guarantee, and a false positive on
	 * kernel modules is a false positive on the largest single group of ELF
	 * files most Linux hosts have.
	 *
	 * ONLY THE SCORE STOPS. The parse still records every anomaly and an
	 * examiner still prints them - what is withheld is a VERDICT from a
	 * model that has no evidence about this kind of object.
	 */
	if (ctx->format == KOF_FMT_ELF) {
		const struct kof_elf_info *ei = kof_elf(ctx);

		if (!ei || (ei->e_type != KOF_ELF_EXEC &&
			    ei->e_type != KOF_ELF_DYN))
			return;
	}

	memset(&f, 0, sizeof f);
	f.format       = ctx->format;
	/*
	 * PACKER layers, not tree depth.
	 *
	 * A file three directories down inside a tar is not three layers of
	 * packing, it is a directory tree - and depth counted every child the
	 * same way, so an ordinary archive of archives scored like something
	 * that had been wrapped to be hidden. Only a module that declared itself
	 * an UNPACK or DECRYPT step adds a layer now.
	 */
	f.anomalies    = kof_heur_anomalies(ctx);
	/*
	 * The object that WAS packed, not the one that came out.
	 *
	 * See kof_scanner.packed_here. Both are true of a packed sample and they
	 * are different objects: this marks the file on disk, and packer_depth
	 * above marks what was inside it.
	 */
	if (sc->packed_here)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_PACKED);
	if (partial)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_UNPACK_PARTIAL);
	if (!kof_heur_score(m, &f, &score, &guess))
		return;                 /* no model for this format - say nothing */

	/*
	 * Published before the bar is consulted.
	 *
	 * The bar decides whether this becomes a FINDING; it does not decide
	 * whether the caller is allowed to know the number. An examiner wants
	 * the score on every object precisely so it can show how far short of
	 * the bar something came.
	 */
	out->heur_scored    = 1;
	out->heur_score     = score;
	out->heur_flags     = f.flags;
	out->heur_anomalies = f.anomalies;
	out->heur_depth     = pdepth > 255u ? 255u : (uint8_t)pdepth;
	/* And whether the emulator produced anything from this object, which is
	 * the thing a caller offering "run it" has to know before offering it
	 * again. See kof_result.emu_unpacked. */
	out->emu_unpacked   = sc->emu_produced;

	if (score < m->bar_centinats || out->n >= KOF_MAX_FINDINGS)
		return;

	/*
	 * A NAMED FAMILY SUPERSEDES A GUESS ABOUT THE SHAPE.
	 *
	 * The heuristic's measured worth is on objects the database MISSED -
	 * eleven percent of those, at this bar. On an object it did not miss it
	 * contributes nothing to the verdict, and printing both put two
	 * verdicts on one object: "Botnet:Mirai" and "Heur:Truncated" for the
	 * same bytes, leaving a reader to work out which one the scanner
	 * actually means.
	 *
	 * The SCORE is still published above, so an examiner shows how the
	 * object scored either way. What is suppressed is the second verdict,
	 * not the second fact.
	 */
	/*
	 * AND IT YIELDS TO A RULE TOO, not only to a named detection.
	 *
	 * The test was "some finding at a level other than HEUR", written
	 * when this model was the only thing producing a HEUR finding. A
	 * rule in bases/heur reports at the same level, so the model did not
	 * yield to one - and an object came back with both
	 * `Heur:Infected`, which is a rule concluding the file is infected,
	 * and `Anomaly:WriteExec`, which is the structural reason to suspect
	 * it. The second is how you get to the first; printing both states
	 * the evidence and the conclusion as two findings.
	 *
	 * So: anything that already named this object wins. This model
	 * exists for the objects nothing else had a word for.
	 */
	if (out->n)
		return;
	/*
	 * AND IT STAYS SILENT ON AN OBJECT THAT OPENED.
	 *
	 * The same condition the drop above uses, for the same reason: this
	 * object is a wrapper and what is worth naming is what came out of
	 * it. Without this the model filled the hole the drop had just made
	 * - a rule fired on the parent, its finding MOVED to the child, and
	 * the model then wrote its own structural note where the rule's
	 * finding had been. 007 Spy.exe reported `Anomaly:WriteExec` on the
	 * file and `Heur:Infected` on its child, which is the evidence and
	 * the conclusion printed as two findings about one file.
	 */
	if (sc->n_kids > sc->n_views + sc->n_carved)
		return;

	{
		struct kof_finding *fi = &out->v[out->n++];

		char fmtarch[32], sv[16];

		fi->level = KOF_LEVEL_HEUR;
		/*
		 * <target>/Heur:<what it looks like>:<how strongly>.
		 *
		 * Three parts because a reader asks three things and a bare
		 * number answers none of them: which population it was judged
		 * against, what the evidence suggests, and how far past the bar
		 * it went. The middle word comes from the model's own table -
		 * the engine does not know these words - so a heuristic
		 * authored elsewhere names its own findings.
		 *
		 * Heur is not a family and never becomes one. It is the engine
		 * saying it recognised a shape, not a thing.
		 */
		kverdict_target(fmtarch, sizeof fmtarch, ctx->format, ctx->arch);
		snprintf(sv, sizeof sv, "s%d", score);
		/*
		 * "Anomaly" AND NOT "Heur", because the two are not the same
		 * kind of statement and shared a word.
		 *
		 * A rule in bases/heur recognises a BEHAVIOUR - this writes
		 * and then executes, this loads shellcode - and `Heur` says
		 * "a rule, not a signature". What reaches here is the
		 * statistical model over PARSE ANOMALIES: a section that is
		 * writable and executable, a segment past the end of the
		 * file. That is a fact about the file's structure and a
		 * reason to look, not a claim that the file does anything.
		 *
		 * Printed under one word they read as the same finding at the
		 * same confidence, and `Heur:Truncated` - a file that is cut
		 * short - sat beside `Heur:Infected`, which is a conclusion.
		 * The LEVEL stays KOF_LEVEL_HEUR: how sure, which is the same
		 * question for both. What differs is what is being claimed.
		 */
		/*
		 * Anomalies is where a type goes because that is what this
		 * found - a structure, not a behaviour. The family is which
		 * anomaly weighed most; the engine is the parse.
		 */
		fi->type = (uint8_t)KOF_MALTYPE_ANOMALY;
		fi->type_known = 1;
		fi->fmt = ctx->format;
		fi->arch = ctx->arch;
		fi->engine = (uint8_t)KOF_ENGINE_ANALYZER;
		fi->verdict = (uint8_t)KOF_VERDICT_HEUR;
		kof_verdict_name(fi, guess, sv, NULL);
		fi->is_verdict = (uint8_t)sx_verdict_take(sc, fi, opt->all_matches);
	}
}

/*
 * THE HEURISTIC RULES, at one of their two points in an object's life.
 *
 * Returns the OR of what the rules that FIRED asked the engine for - see
 * KOF_HEUR_WANT in kofmod/heur.h. An OR and not a last-writer, so two rules
 * asking for the same thing is the same request and the answer does not depend
 * on the order the packs happened to load in. That matters: --jobs must not
 * change a verdict, and scan_mt is the test that says so.
 *
 * The mask is returned rather than stored on the scanner. A field would be
 * state, and state is exactly how "this object asked for the emulator" becomes
 * "the rest of the scan uses it" - the bug this is shaped to make impossible.
 */
uint32_t sx_heur_run(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt,
			 struct kof_result *out, uint32_t phase,
			 uint32_t present, const char **predict)
{
	uint32_t want = 0, i;
	/*
	 * ZERO MEANS UNSTATED, and unstated is level 1.
	 *
	 * Not a default written into the struct, because there is no
	 * initialiser to write it in: every caller declares a
	 * kof_scan_option on the stack and clears it, so a field whose
	 * useful value is 1 arrives as 0. Reading 0 as "the level every rule
	 * ran at before there was a choice" is what keeps kofexaminer, the
	 * unit tests and any embedder working unchanged - the alternative
	 * silently disabled every heuristic for all of them.
	 *
	 * Level 0 is not spelled here: it is opt->heur_off, tested above.
	 */
	uint32_t lvl = opt->heur_level ? opt->heur_level : 1u;

	if (predict)
		*predict = NULL;
	if (opt->heur_off)
		return 0;
	for (i = 0; i < sc->eng->n_heur; i++) {
		const struct kof_module *m = &sc->eng->heur[i];

		if (m->heur_phase != phase)
			continue;
		/*
		 * A rule gated above this scan's level is not ENTERED, not
		 * merely ignored afterwards. That is the whole point of the
		 * declaration: the cost it was gated for - and for a rule that
		 * walks a symbol table, that cost is real - must not be paid by
		 * a caller who did not ask for it. Beside the phase test
		 * because they are the same kind of thing, a property of the
		 * rule that the scan compares against without running anything.
		 */
		if (m->heur_level > lvl)
			continue;
		if (!sx_prefilter(m, ctx, present, &sc->st, out))
			continue;

		/* Same as the detector loop: a rule that declared markers or
		 * blocks is what makes the pass worth running. */
		if (m->n_str)
			sx_need_multi(sc, ctx);
		if (m->n_block)
			sx_need_plague(sc, ctx);

		sx_mod_begin(sc, m);
		KOF_TIME_BEGIN(KOF_T_HEUR);
		m->fn(ctx);
		KOF_TIME_END(KOF_T_HEUR);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;
		want |= m->heur_want;
		/*
		 * The FIRST prediction wins, and it is kept whether or not this
		 * rule's finding survives the named-family test below.
		 *
		 * Kept, because a prediction is used for two different things: it
		 * is written into the finding, and it decides which decoder is
		 * tried first. The second is worth having even on an object a
		 * signature already named - the name is about the container, the
		 * decoder is about what is inside it.
		 */
		if (predict && !*predict) {
			const char *pf = kof_db_heur_predict(sc->eng, m);

			if (pf && pf[0])
				*predict = pf;
		}
		/*
		 * FIRED FOR THE ACTION, NOT FOR A VERDICT - see KOF_HEUR_ACT.
		 * After `want`, so the ask it fired for is honoured, and after
		 * the prediction, so the decoder it would have steered is
		 * still steered. Before the finding, because the finding is
		 * the whole of what it declines to make.
		 */
		if (sc->rep_level == (uint32_t)KOF_LVL_ACT)
			continue;
		/*
		 * A NAMED FAMILY SUPERSEDES A GUESS ABOUT THE SHAPE, and the
		 * rule is the same one the scored model follows a few functions
		 * down. The ASK is not suppressed with it: whether the object
		 * is worth interpreting was decided before anything was named,
		 * and withdrawing it here would leave a rule that fires and
		 * does nothing on precisely the objects a signature already
		 * half-recognised.
		 */
		{
			uint32_t k;
			int named = 0;

			for (k = 0; k < out->n; k++)
				if (out->v[k].level != KOF_LEVEL_HEUR)
					named = 1;
			if (named)
				continue;
		}
		{
			struct kof_finding *f = sx_mod_report(sc, ctx, opt, out, m,
							      KOF_LEVEL_HEUR);

			/* The bit is this finding's index: the drop below reads it. */
			if (f && (m->heur_want & KOF_ENG_KEEP_ON_OPEN))
				sc->heur_keep |= 1u << (unsigned)(f - out->v);
		}
		/* One HEUR line per object, the same way the detector loop
		 * stops at the first family - and for the same reason: the
		 * rules after it can only lengthen a list that already says
		 * what the object looks like. */
		if (!opt->all_matches)
			break;
	}
	return want;
}
