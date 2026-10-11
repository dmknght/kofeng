/*
 * scan_pipeline.c - one object through its stages: the pipeline table and the loop
 * that runs it.
 *
 * A stage is a function over the object's kof_pipeline and a row in `pipeline` below;
 * the order of the rows is the order things happen to an object, and it is
 * stated here once and nowhere else. The chain rows (the opening steps and the
 * host's own NORMZ) are subject to the chain's stops - a detection, a rule's
 * conclusion, a child that came out, a cancel - and the rows around them are not.
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
#include <celllysis/xref.h>
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include "scan_int.h"

/*
 * OPENING AN OBJECT, IN ORDER.
 *
 * The steps of enum kof_analyze, each one a runner, tried from the top until
 * one of them produces something. What comes out is a child, and a child comes
 * back round to the top of this same list on its own pass - so the order below
 * is not "what to do to this object", it is "what to try first", and the rest
 * happens by recursion.
 *
 * WHY A TABLE AND NOT THE THREE CALLS IT REPLACES.
 *
 * The rule "stop at the first step that yields" was already here, written out
 * by hand: sx_unpack_object, then a kids0 comparison, then sx_norm_emit under an if.
 * Written that way it holds for exactly the two things that were wired up, and
 * the next step added has to re-derive it - which is how sx_norm_emit came to be
 * called BEFORE unpacking in its first version, and gave a UPX stub a view of
 * its own compressed payload. Here the rule is the loop, once, and a new step
 * is a row.
 *
 * ONE ROW PER STEP. A module declares its step (KOF_ANALYZE_STEP) and the row
 * for that step asks exactly those modules, in database order, so the order the
 * steps were designed in - read a container's table, then undo a packer, then a
 * cipher, then search - is the order modules run in, and a new step is a row
 * and not a rewrite of a loop. The OPEN stage's gate and its predicted-family
 * pass run before the first row's modules; its end (declared files, the
 * ciphertext check) runs once, wherever the stage stops.
 *
 * The last row is the host's own and has no modules: NORMZ is sx_norm_emit.
 */

/*
 * FACTS: what is true of the object before any module looks - its format, its
 * regions, what a library left in it - and the per-object reset that makes
 * nothing from the last object visible. Host only; no module runs here.
 */
static void st_facts(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *out = p->out;

	out->from_packer = (uint8_t)(p->from_packer != 0);
	memset(&p->ctx, 0, sizeof p->ctx);
	kof_mod_attach(&p->ctx, sc);
	sx_obj_begin(sc);
	/*
	 * A CALLER THAT WANTS THE REPORT WANTS EVERY DIAGNOSE COMPUTED IN THE ONE
	 * ANALYSIS, so it is said at the start of the object and not discovered
	 * at the end. Decided late, the scan that had already run without the
	 * diagnoses no verdict reads would have to be thrown away and run again -
	 * the same object analysed twice for one answer.
	 */
	sc->diag_all = opt->report_diag != 0;

	/*
	 * How big the object is, before anything tries to sx_identify it.
	 *
	 * It is a property of the bytes, not of the parse, and leaving it to the
	 * collectors meant an object nothing recognised reported a size of zero.
	 * Everything downstream reads that as an empty file: KOF_SCAN_ALL resolves
	 * to no extents, so sx_regions_present drops it, so the sx_prefilter skips every
	 * module that names it - which is precisely the modules written to run on
	 * anything, the ones with no format header at all. They could not match an
	 * unidentified object, ever, and nothing said so.
	 */
	p->ctx.obj_size = p->buf.n;

	kof_match_begin(&sc->m, p->buf);

	/*
	 * THE CHILD'S OWN DECLARATION FIRST, then the caller's.
	 *
	 * opt->as_format is about the object the CALLER handed in - a submitted
	 * event record, which has no magic for a sniff to find. as_fmt is what
	 * the thing that produced THIS child said about it, and for a child the
	 * second is the specific claim: the caller's applies to the root of the
	 * walk and would otherwise be re-applied to every object under it.
	 */
	sx_identify(sc, p->buf, &p->ctx,
		 p->as_fmt ? p->as_fmt : (opt ? opt->as_format : 0u),
		 opt ? opt->as_view : NULL, opt ? opt->as_view_len : 0u);
	/*
	 * AND THE LANGUAGE THE PRODUCER DECLARED BEATS THE ONE READ BACK.
	 *
	 * Same reason the format is declared: a view is a view OF something,
	 * and a re-read of it answers about the bytes rather than about what
	 * they are a view of. For a normalised script the two disagree the
	 * moment the decode succeeds - the payload's own "<?php" makes the
	 * view read as PHP - and kof_module_precond then declines every rule
	 * written for the language the object actually is. See
	 * kof_src_declare_lang.
	 */
	if (sc->cur_lang) {
		p->ctx.subtype = sc->cur_subtype;
		p->ctx.subfamily = sc->cur_subfam;
		/* And out to the caller, which has the same problem the engine
		 * had: reading the bytes gives the wrong answer. */
		out->subtype = sc->cur_subtype;
		out->subfamily = sc->cur_subfam;
		out->lang_known = 1;
	}
	/* And the one fact about it that three later steps would each have
	 * worked out for themselves - see sx_lib_facts. */
	sx_lib_facts(sc, &p->ctx, p->buf);

	/*
	 * A DECLARED REGION TABLE BEATS A PARSED ONE, and for an object that
	 * has one there is no parsed one to beat.
	 *
	 * Installed after sx_identify rather than inside it because sx_identify's job
	 * is to say WHAT the object is, and this says where its parts are -
	 * which the producer knew and no reading of the bytes can recover. See
	 * kof_src_declare_regions.
	 */
	if (sc->n_cur_rgn) {
		uint32_t g;

		p->ctx.resolve_scan = sx_declared_resolve_scan;
		/* And out to the caller, which has the same problem the engine
		 * had: it cannot work these out from the bytes either. */
		for (g = 0; g < sc->n_cur_rgn && g < KOF_MAX_REGIONS; g++) {
			out->region[g].mask = sc->cur_rgn[g].mask;
			out->region[g].off = sc->cur_rgn[g].off;
			out->region[g].len = sc->cur_rgn[g].len;
		}
		out->n_region = g;
		out->region_fmt = sc->cur_rgn_fmt;
	}

	/*
	 * BOTH UNIONS, because a region has to be RESOLVED for whoever is
	 * going to read it - see kof_engine.heur_scan_mask. The detector
	 * union alone left a heuristic scoped to a region reading "absent"
	 * on every object, which is the worst shape a fault can have: the
	 * rule is loaded, it runs, and it answers no.
	 */
	{
		uint32_t resolve = sc->eng->scan_mask | sc->eng->heur_scan_mask;

		p->present = sx_regions_present(&p->ctx, resolve);
		p->present |= sx_sym_halves_present(&p->ctx, resolve);
	}
	sc->st.objects++;
	sc->st.object_bytes += p->buf.n;

	/*
	 * NOT HERE ANY MORE - the first module that declares a marker asks for
	 * it, and one that ends the object without declaring any never does.
	 * See kof_scanner.multi_ready for why, and sx_need_multi for how.
	 */
	sc->cur_present  = p->present;
	sc->cur_from_packer = (uint8_t)(p->from_packer != 0);

	/*
	 * And the same for similarity: every block any loaded rule declared is
	 * counted once, so a module's kof_plague_score is a division - but on
	 * the first ask rather than here, for the reason above.
	 *
	 * Gated twice on purpose, and both gates still apply inside the feed.
	 * The set is NULL unless some pack carried a block, so a database
	 * without plague rules never reaches this. And within it, a region is
	 * fed only for the normalizers some block of that region actually asked
	 * for - a pack whose blocks all hash raw bytes pays one pass, not three.
	 *
	 * THE GENERATION BUMP IS NOT DEFERRED WITH THE FEED. It is O(1) - see
	 * kof_plague_begin - and it is what makes "this object fed nothing" read
	 * as nothing rather than as whatever the last object fed.
	 */
	kof_plague_begin(&sc->plague);
	/*
	 * THIS OBJECT'S DESCRIPTOR IS NOT THE LAST ONE'S.
	 *
	 * Here and not inside sx_plague_feed, which returns early when no pack
	 * carried a block: a database with no plague rules would then have left
	 * the previous object's descriptor in place, and every kof_plague_blocks
	 * rule would have measured the wrong file. Built on the first ask - see
	 * ovl_of - so this costs a store.
	 */
	/* What the two gated measures compare themselves against - see
	 * kof_scanner.heur_lvl. Unstated is level 1, exactly as sx_heur_object
	 * reads it, so the two cannot drift. */
	sc->heur_lvl = opt->heur_off ? 0u
		     : (opt->heur_level ? opt->heur_level : 1u);
}

/*
 * THE MODULES OF ONE STAGE, in database order, over the ones that could target
 * this format. DETECT and SIMILAR are this loop with a different set: a module
 * that names similarity blocks is SIMILAR's, every other is DETECT's.
 */
static void run_modules(struct kof_pipeline *p, int similarity)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *out = p->out;

	/*
	 * ONLY THE MODULES THAT COULD TARGET THIS FORMAT - see kof_engine.mod_at.
	 * The ones outside the run are excluded for exactly the reason
	 * kof_module_precond would have excluded them, so they are counted as
	 * such and the stats keep meaning what they meant.
	 */
	{
		const struct kof_engine *e = sc->eng;
		uint32_t lo = 0, hi = e->n_mods, k;
		const uint32_t *ix = NULL;

		if (e->mod_by_target && p->ctx.format < KOF_TARGET_COUNT) {
			ix = e->mod_by_target;
			lo = e->mod_at[p->ctx.format];
			hi = e->mod_at[p->ctx.format + 1u];
			/* Once per object: the second call is the same run's other half. */
			if (!similarity) {
				sc->st.considered += e->n_mods - (hi - lo);
				sc->st.by_target  += e->n_mods - (hi - lo);
			}
		}

	for (k = lo; k < hi; k++) {
		const struct kof_module *m = &e->mods[ix ? ix[k] : k];
		struct kof_finding *f;

		if ((m->n_block != 0) != (similarity != 0))
			continue;

		/*
		 * BETWEEN MODULES, WHICH IS WHERE A SLOW OBJECT CAN BE LEFT.
		 *
		 * The callback is the host's other way out and it runs once
		 * the object is finished; on a large shared object that is
		 * hundreds of milliseconds after the host asked to stop. This
		 * is the same question asked where the time is actually
		 * spent - see should_stop in kofeng.h.
		 *
		 * Before sx_prefilter rather than after: a module ruled out by
		 * the sx_prefilter costs almost nothing, so asking first is what
		 * puts the check on the path that is slow.
		 */
		if (opt->should_stop && opt->should_stop(opt->stop_user))
			break;

		if (!sx_prefilter(m, &p->ctx, p->present, &sc->st, out))
			continue;

		/* What this module declared it reads, produced now that a
		 * module needing it has actually survived the sx_prefilter. */
		if (m->n_str)
			sx_need_multi(sc, &p->ctx);
		if (m->n_block)
			sx_need_plague(sc, &p->ctx);

		sx_mod_begin(sc, m);
		m->fn(&p->ctx);

		/*
		 * AND, IF IT BOTH FOUND SOMETHING AND KNOWS HOW TO UNDO IT,
		 * ASK IT WHAT THE REPAIR WOULD BE.
		 *
		 * Three conditions and every one of them is needed. The module
		 * has to have REPORTED, because a repair with no detection
		 * behind it is a file being rewritten for no stated reason. It
		 * has to have OFFERED - KOF_SCAN_CURABLE - because finding a
		 * family says nothing about where its payload starts and a
		 * repair without an offset has nothing to act on. And it has
		 * to HAVE a cure at all, which nearly no module does.
		 *
		 * WHAT COMES BACK IS A DESCRIPTION, not a changed file: see
		 * kof_content.cure_patch. Nothing on disk is touched here, by
		 * anybody, ever. A scan that repaired what it found would be a
		 * scan nobody could run twice.
		 */
		if (sc->rep_valid && sc->cure_have && m->cure)
			m->cure(&p->ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;

		/* Accumulate. Keeping only the last would drop a finding whenever two
		 * families match one object, and the cap is counted rather than
		 * silently applied. */
		f = sx_mod_report(sc, &p->ctx, opt, out, m, sc->rep_level);

		/*
		 * Stop unless the caller asked for everything - AND ONLY AT AN
		 * INFECTION. The remaining modules can only lengthen a list that
		 * already says the object is not clean, and on a database of any size
		 * that is most of the work; but a SUSPECTED is not that answer, it is a
		 * weaker one, and stopping on it hid the INFECTED further down the
		 * database: an object carrying both was reported as merely suspected
		 * because the weaker rule sorted first (tests/unit/scan_logic.c). A
		 * result with no room left for another finding is also the end.
		 *
		 * It saves nothing on a clean object, which is nearly every object -
		 * this is a bound on the worst case, not a throughput win.
		 */
		if (!opt->all_matches && (!f || f->level == KOF_LEVEL_INFECT))
			break;
	}
	}

}

/*
 * DETECT: the detectors, in database order, cheapest test first. A detector
 * that names a family ends the stage unless the caller asked for everything.
 */
static void st_detect(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	struct kof_result *out = p->out;

	run_modules(p, 0);

	/*
	 * WHAT THE DETECTORS ALONE FOUND, taken here because this is the last
	 * moment at which it is still true: sx_heur_run appends below, and once it
	 * has, nothing downstream can tell a rule's guess from a detection. See
	 * analyze_arg.det_n for what reads it and why the distinction matters.
	 */
	p->det_n = out->n;

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->m.n_calls;
	sc->st.bytes_searched += sc->m.n_bytes_scanned;
	sc->st.gram_bytes     += sc->m.n_bytes_indexed;
}

/*
 * SIMILAR: the rules that compare the object with declared blocks - after the
 * steps that decide WHICH object that is.
 *
 * A block is cut from the normalised view, so the object it is looked for in is
 * the view. They used to run with the detectors, before the object was opened
 * or normalised: the parent was scored, its verdict (which stops at the first
 * finding) carried the parent's number, and the view - the thing the block was
 * made from - was never asked. Here the chain's own rule decides it: a step that
 * PRODUCED something (an unpacked image, a member, the view) ends the chain, so
 * a parent that has a view, or was opened, is not scored and its child is, when
 * the child reaches this stage itself; an object that produced nothing - nothing
 * to unpack, nothing a normalisation could change - is scored as it is. And a
 * detector's verdict ends the chain before this, as it ends the others.
 *
 * A parent under a rule's threshold is not clean-so-skip: the view is a child
 * and is scanned whatever the parent would have scored.
 */
static void st_similar(struct kof_pipeline *p)
{
	run_modules(p, 1);
}

/*
 * EXAMINE: the rules that read the parse, asked before the object is opened.
 * What they predict and what they ask the engine for is collected here and
 * read by every stage below.
 */
static void st_examine(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *out = p->out;

	/*
	 * EXAMINE: what the object IS, asked before it is opened.
	 *
	 * Here and not earlier so a rule knows whether a family was named, and
	 * here and not later because this is the last moment at which what it
	 * asks for can still change what happens to the object.
	 */
	p->want = sx_heur_run(sc, &p->ctx, opt, out, KOF_HEUR_EXAMINE, p->present, &p->predict);
	/*
	 * ---- AND AN ASK FROM THIS PASS COUNTS -----------------------------
	 *
	 * KOF_ENG_USE_PATHOGEN was being read in sx_unpack_object and nowhere
	 * else, so an object that is not unpacked never saw it. MEASURED:
	 * the msf stager asked and was analysed because a decoder produced a
	 * child; a kernel module - which no unpacker touches - asked through
	 * the same declaration and was never analysed at all.
	 *
	 * The two are OR-ed rather than assigned: a producer's ask and this
	 * object's own are both asks, and neither may cancel the other.
	 */
	sc->diag_ask |= (p->want & KOF_ENG_USE_PATHOGEN) != 0;
	/*
	 * ---- AND A DIAGNOSE'S OWN DECLARATION IS AN ASK -------------------
	 *
	 * A diagnose states which files it is worth running on; this is where
	 * the engine reads that and routes. Two things follow from a match and
	 * both are the same decision:
	 *
	 *   the analysis runs on this object, and
	 *   the object is INTERPRETED, because the shape that qualifies a
	 *   msfvenom payload also says the payload is probably encrypted -
	 *   six of the seven samples here are - and the walk over a ciphertext
	 *   finds nothing. Measured: without it, x86_alpha_upper's decoded
	 *   child is never produced and the one detection on that file goes.
	 *
	 * THIS REPLACED A HEURISTIC RULE that carried the shape test and asked
	 * on the diagnose's behalf. It had to publish a verdict to be allowed
	 * to ask - 12 Heur lines across the msfvenom corpus saying only that
	 * the engine had decided to look - and the test lived in a different
	 * module from the declaration it was gating.
	 */
	if (kof_scan_diag_sign_asks(&p->ctx)) {
		sc->diag_ask = 1;
		p->want |= KOF_ENG_USE_EMU;
	}
	/*
	 * A rule's own guess wins; the inherited one is the fallback.
	 *
	 * A heuristic firing on THIS object knows more about it than its parent
	 * did - so its prediction takes precedence. The inherited family is for
	 * the case no rule fired at all, which is exactly the formatless
	 * intermediate layer a decoder peels: nothing recognises it, but its
	 * parent was a Meterp payload, so it very probably is one too, and
	 * trying that decoder first is the whole point of carrying the guess
	 * down.
	 */
	if (!p->predict)
		p->predict = p->inherit_predict;
	p->concluded = (p->want & (uint32_t)KOF_ENG_CONCLUDE) ? 1 : 0;
}

/*
 * SCRIPT: the second form of a script, after opening, so a script that was
 * packed is read as what it turned out to be.
 */
static void st_script(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *out = p->out;

	/*
	 * After, so a script that was packed is normalised as the source it
	 * turned out to be rather than as the wrapper - the unpacked child
	 * reaches this same step with its own parse behind it. The flag follows
	 * sx_unpack_object's rule: "not fully examined" is only worth saying about
	 * an object something actually tried to open.
	 */
	if (sx_script_forms(sc, &p->ctx, opt, p->pdepth) && sc->broken)
		out->broken = sc->broken;
}

/*
 * SERVE: what the engine completed is declared on the object.
 */
static void st_serve(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;

	/*
	 * WHAT THE ENGINE COMPLETED IS DECLARED ON THE OBJECT, so the result
	 * carries it like any producer's - see kof_result.syms. A tool then shows
	 * what the engine returned for a stager's symbols instead of reading the
	 * file's table itself and printing a different answer.
	 */
	{
		uint32_t ns = 0;
		const uint8_t *sb = kof_scan_served_syms(&p->ctx, &ns);

		if (sb && sc->cur_src)
			kof_src_declare_syms(sc->cur_src, sb, ns);
	}
}

/*
 * VERDICT: the rules that read what the other stages produced - and, first, the
 * analysis a rule asked for by DECLARATION, built now so a rule here finds it.
 * It is a feed like the pattern and similarity feeds, demanded and built on
 * demand (see diag_ready), and not a stage of its own: nothing happens to the
 * object in it.
 */
static void st_verdict(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *out = p->out;

	/*
	 * ---- AND THE PATHOGEN ANALYSIS RUNS, IF ANYTHING ASKED -----------
	 *
	 * ONE ASKER, AND IT IS THE DATABASE. A diagnose declares the symbols
	 * or the file attributes that make an object worth the walk and the
	 * EXAMINE pass sets sc->diag_ask from that; a rule reaching for a
	 * diagnose or the graph sets it too, at the moment it asks.
	 *
	 * There was a second asker - a caller's want_diag, which turned the
	 * analysis on for every object so a tool could list what it found.
	 * It is gone with the listing: a switch that makes the engine do its
	 * most expensive work on files nothing recognised is not a reporting
	 * mode, it is the gate turned off.
	 *
	 * WHY IT IS RUN HERE RATHER THAN WAITED FOR. The analysis used to
	 * happen only when a signature asked a question that needed it, which
	 * means an object nobody questioned was never analysed at all - and
	 * the findings are wanted by the verdict layer, which has not been
	 * written yet and so asks nothing. A rule's ask is the decision; this
	 * is where the decision is acted on.
	 *
	 * The latch inside makes it once per object however many times it is
	 * reached, and an object nobody asked about still does no work.
	 *
	 * BETWEEN THE TWO HEURISTIC PHASES, which is the only place it can
	 * be. EXAMINE is where a rule ASKS; VERDICT is where a rule reads
	 * what the analysis found and concludes. Run after VERDICT - which
	 * is where it was - the graph existed only once nothing was left to
	 * read it, and a rule asking kof_diag_graph() got nothing at all.
	 *
	 * A SIGNATURE DOES NOT HAVE TO WAIT FOR THIS. It runs before this
	 * point, and reaching for a diagnose or the graph runs the analysis
	 * there and then - see diag_ready. This is for the object whose
	 * analysis was asked for by a DECLARATION rather than by a question:
	 * nothing would otherwise read it until the VERDICT phase, and a
	 * rule there would find a graph that had never been built.
	 */
	if (sc->diag_ask)
		kof_scan_diag_force(&p->ctx);

	(void)sx_heur_run(sc, &p->ctx, opt, out, KOF_HEUR_VERDICT, p->present, NULL);
}

/*
 * RECONCILE: a parent whose children were opened does not keep a guess about
 * itself that its payload may contradict.
 */
static void st_reconcile(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	struct kof_result *out = p->out;

	/*
	 * A RULE'S HEUR IS A LAST RESORT, and an object that OPENED is not the
	 * last resort - its children are.
	 *
	 * A rule says "I could not sx_identify this, but here is its shape". When
	 * the object unpacks, the thing worth identifying is what came out, not
	 * the wrapper: rc4_1 is an encrypted stager, and the reader wants the
	 * Trojan:Meterp on the payload three layers down, not a Heur:Shellcode
	 * on the ciphertext that carried it. So a rule's heur on an object that
	 * produced children is dropped.
	 *
	 * THE SIGNAL IS NOT LOST, it MOVES. The same shape rule fires on the
	 * decoded child; if nothing can name that child either, the child
	 * produces no children of its own, so its heur is kept. The prediction
	 * ends up on the leaf that nothing could open or name, which is where
	 * "I could not sx_identify this" belongs.
	 *
	 * DONE BEFORE sx_heur_object, so only the RULE heur is dropped. The scored
	 * model that follows is about the object's own structure - a truncated
	 * header is truncated whether or not the object unpacked - so it is
	 * added after this and stays. Only children this object PRODUCED count;
	 * sc->n_kids is reset before it was scanned, and a container's members
	 * are its children too, but a container carries no rule heur to drop.
	 */
	/*
	 * A RULE MAY SAY ITS FINDING IS ABOUT THIS OBJECT.
	 *
	 * The assumption above - that a rule heur on an object which opened is
	 * always a failure to sx_identify the wrapper - holds for every rule that
	 * guesses at a payload and for none that recognises a CARRIER. "This
	 * executable has a second executable glued to it" is true of the parent
	 * and of nothing else, and the child it names is an ordinary file that
	 * no shape rule fires on - so there is no leaf for the signal to move
	 * to and the drop would simply delete it.
	 *
	 * KOF_ENG_KEEP_ON_OPEN is how such a rule says so, per finding rather
	 * than per object: two rules may fire here and only one of them mean
	 * it. See sc->heur_keep and the note in kofmod/heur.h.
	 */
	/*
	 * VIEWS DO NOT COUNT, because nothing came out of the object when one
	 * was made - see kof_scanner.n_views. Subtracted rather than tested
	 * separately so the question stays the one it always was: did this
	 * object YIELD anything.
	 *
	 * AND NEITHER DOES A CARVE, for the reason that decides the same
	 * question in analyze_object and in the family pass: a carved child
	 * was not declared by anything, so the host did not turn out to be a
	 * wrapper around it. The drop above rests on "the finding belongs to
	 * the child that came out" - true of a container's member and of an
	 * unpacked image, and false of a file glued past the last segment. A
	 * shape rule that says "this object is packed" is not answered by
	 * finding something appended to it, and dropping it there deletes a
	 * verdict about the host with nowhere for it to go: the carved child
	 * is an ordinary file that no shape rule fires on.
	 *
	 * That is what KOF_ENG_KEEP_ON_OPEN was carrying on its own - see the
	 * note in bases/heur/appended_00.c, where the bit was added because
	 * three samples came back clean with the carried ELF extracted. The
	 * bit is still right for what it says, and it is still honoured below;
	 * it is simply no longer the only thing standing between a carve and
	 * a deleted finding, which would have needed every future rule to
	 * remember it.
	 */
	_Static_assert(KOF_MAX_FINDINGS <= 32, "heur_keep is a 32-bit mask of finding slots");
	if (p->yielded && out->n > 0) {
		uint32_t r, w = 0, keep = sc->heur_keep;

		for (r = 0; r < out->n; r++)
			if (out->v[r].level != KOF_LEVEL_HEUR ||
			    (keep & (1u << r)))
				out->v[w++] = out->v[r];
			else if (out->v[r].is_verdict && sc->verdict_have &&
				 out->v[r].level == sc->verdict_lvl &&
				 !strcmp(out->v[r].name, sc->verdict.name)) {
				/*
				 * AND THE SLOT GOES WITH IT - but only if it
				 * is still the one in the slot.
				 *
				 * This finding MOVES to the leaf, and it had
				 * already been taken into the subject's one
				 * verdict slot; a slot holding a finding
				 * nobody reports is a subject with no verdict
				 * at all. Measured: 007 Spy.exe reported
				 * nothing, because the rule fired on the
				 * parent, took the slot, was dropped, and the
				 * identical finding at the leaf was then
				 * refused for equal rank.
				 *
				 * `is_verdict` SAYS IT TOOK THE SLOT ONCE,
				 * NOT THAT IT STILL HOLDS IT. On the Sality
				 * samples the rule takes it, the unpacker
				 * then takes it with `Virus:Sality#Body`, and
				 * clearing on the stale bit threw the named
				 * verdict away - the file came back with the
				 * shape that led to it instead. So the slot
				 * is compared before it is given up.
				 */
				sc->verdict_have = 0;
				sc->verdict_lvl  = 0;
			}
		out->n = w;
	}
}

/*
 * MODEL: the scored model over the whole object.
 */
static void st_model(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *out = p->out;

	/*
	 * Last, because the unpack result is one of the facts - and NOT FOR A
	 * VIEW, whose structure is not its own.
	 *
	 * The scored model reads the parse: where the sections end against
	 * where the file ends, whether a segment runs past it. A normalised
	 * view keeps its parent's headers byte for byte and is SHORTER than
	 * they describe, so every one of those questions has the wrong answer
	 * about it - measured before this, an ordinary view came back
	 * ELF-other/Heur:Appended, which is a finding about the normaliser.
	 *
	 * The RULE heuristics still run: those read bytes, and the bytes are
	 * the point of having a view. Only the model that reasons about layout
	 * is skipped, because the layout belongs to the parent and the parent
	 * is scanned too.
	 */
	if (!sc->n_cur_rgn)
		sx_heur_object(sc, &p->ctx, opt, p->pdepth,
			    out->broken == KOF_BROKEN_DAMAGED, out);
}

/*
 * REPORT: what each diagnose made of this object, for a caller that asked.
 *
 * LAST, after every verdict is final, because asking runs the diagnoses no
 * verdict reads and rebuilds the graph with them: whatever it changes is not
 * something a verdict can have read.
 */
static void st_report(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	uint32_t n, i, k = 0;

	if (!p->opt->report_diag)
		return;
	n = kof_scan_diag_count(&p->ctx);
	if (!n)
		return;
	/* One buffer for the scanner's life, lent to the caller for its callback
	 * - see kof_result.diag. */
	if (!sc->diag_rep) {
		sc->diag_rep = calloc(KOF_DB_MAX_DIAG, sizeof *sc->diag_rep);
		if (!sc->diag_rep)
			return;
	}
	for (i = 0; i < n; i++)
		if (kof_scan_diag_report(&p->ctx, i, &sc->diag_rep[k]))
			k++;
	p->out->diag = sc->diag_rep;
	p->out->n_diag = k;
}

static void st_recover(struct kof_pipeline *p)
{
	sx_recover(p->sc, &p->ctx, p->opt, p->out, p->want);
}

static void st_open(struct kof_pipeline *p)
{
	sx_open_step(p->sc, &p->ctx, p->opt, p->out, p->pdepth, p->want,
		     p->predict, p->step, &p->open);
}

/* The end of the OPEN stage, once, if it began. A refusal answers 0, which is
 * what the object's `broken` is then set to - nothing wanted to open it. */
/* Whether the rows of the current group produced a child that is not a carve:
 * a carve is a file glued on, so the host is still the subject - see
 * KOF_ANALYZE_CARVE. The one place this is asked. */
static int group_yielded(const struct kof_pipeline *p)
{
	return p->sc->n_kids - p->kids0 != p->sc->n_carved - p->carved0;
}

static void open_finish(struct kof_pipeline *p)
{
	if (p->open.state == KOF_OPEN_FRESH || p->open.state == KOF_OPEN_DONE)
		return;
	p->yielded = group_yielded(p);
	p->out->broken = sx_open_end(p->sc, &p->ctx, p->opt, &p->open);
}

static void st_normz(struct kof_pipeline *p)
{
	sx_norm_emit(p->sc, &p->ctx, p->buf);
}

/*
 * `chain` rows are the ones the chain's stops apply to; `ends_group` closes a run
 * of rows that answer ONE question together: whether the object was opened. The
 * four opening steps are that group - an object can be a container of an encoded
 * payload, or a packer wrapped round a cipher, and the steps are ordered precisely
 * so each can act on what the one before left. Stopping between them when a child
 * appeared made the later steps never see the parent: measured, 5 of 38 encoded
 * Meterpreter stagers lost the child a decoder produced beside the one the
 * interpreter had already made. What stops the chain is the GROUP having produced
 * something, checked once at its end.
 */
#define ROW_CHAIN      1u
#define ROW_GROUP_END  2u

static const struct stage_row {
	enum kof_stage    stage;
	enum kof_analyze  step;         /* meaningful for the opening rows */
	unsigned          flags;
	void            (*run)(struct kof_pipeline *);
} pipeline[] = {
	{ KOF_STAGE_FACTS,     KOF_ANALYZE_UNWRAP,  0,                              st_facts },
	{ KOF_STAGE_RECOVER,   KOF_ANALYZE_RECOVER, 0,                              st_recover },
	{ KOF_STAGE_DETECT,    KOF_ANALYZE_UNWRAP,  0,                              st_detect },
	{ KOF_STAGE_EXAMINE,   KOF_ANALYZE_UNWRAP,  0,                              st_examine },
	{ KOF_STAGE_UNWRAP,    KOF_ANALYZE_UNWRAP,  ROW_CHAIN,                      st_open },
	{ KOF_STAGE_UNPACK,    KOF_ANALYZE_UNPACK,  ROW_CHAIN,                      st_open },
	{ KOF_STAGE_DECRYPT,   KOF_ANALYZE_DECRYPT, ROW_CHAIN,                      st_open },
	{ KOF_STAGE_CARVE,     KOF_ANALYZE_CARVE,   ROW_CHAIN | ROW_GROUP_END,      st_open },
	{ KOF_STAGE_NORMZ,     KOF_ANALYZE_NORMZ,   ROW_CHAIN | ROW_GROUP_END,      st_normz },
	{ KOF_STAGE_SIMILAR,   KOF_ANALYZE_UNWRAP,  ROW_CHAIN | ROW_GROUP_END,      st_similar },
	{ KOF_STAGE_SCRIPT,    KOF_ANALYZE_UNWRAP,  0,                              st_script },
	{ KOF_STAGE_SERVE,     KOF_ANALYZE_UNWRAP,  0,                              st_serve },
	{ KOF_STAGE_VERDICT,   KOF_ANALYZE_UNWRAP,  0,                              st_verdict },
	{ KOF_STAGE_RECONCILE, KOF_ANALYZE_UNWRAP,  0,                              st_reconcile },
	{ KOF_STAGE_MODEL,     KOF_ANALYZE_UNWRAP,  0,                              st_model },
	{ KOF_STAGE_REPORT,    KOF_ANALYZE_UNWRAP,  0,                              st_report }
};

void sx_pipeline_run(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	const struct kof_scan_option *opt = p->opt;
	uint32_t i;
	int chain_begun = 0, chain_over = 0;

	for (i = 0; i < sizeof pipeline / sizeof pipeline[0]; i++) {
		const struct stage_row *r = &pipeline[i];

		p->stage = r->stage;
		p->step = r->step;
		if (!(r->flags & ROW_CHAIN)) {
			r->run(p);
			continue;
		}
		if (chain_over)
			continue;
		if (!chain_begun) {
			/* What the current GROUP of rows has produced is measured
			 * from where it began. */
			p->kids0 = sc->n_kids;
			p->carved0 = sc->n_carved;
			chain_begun = 1;
		}
		/*
		 * AND A DETECTION STOPS THE CHAIN, for the same reason a
		 * produced child does: the question the later steps exist to
		 * answer has been answered.
		 *
		 * ANALYSIS IS NOT SKIPPED - IT IS ENDED. The step that had not
		 * run yet is the one that does not run; everything up to and
		 * including the step that led here still ran, and the verdict
		 * still rests on a parse rather than on a guess about one. That
		 * is the difference between this and asking the detectors first
		 * and the analysers never.
		 *
		 * WHAT IT COSTS, MEASURED. Over 5248 real ELF samples, 1341 of
		 * which were detected: 1092 files carry a detector's verdict on
		 * a parent, and stopping there loses a differently-named
		 * descendant in 6 of them - 6 objects out of 3023. Four of the
		 * six are the same family under a second signature id; two name
		 * another family. Every one of the six is a NORMALISED VIEW and
		 * not an unpacked payload, which is the weakest thing the chain
		 * produces: a view is a rendering of bytes already searched, and
		 * 852 of the 858 views that reported were repeating a name their
		 * parent had already been given.
		 *
		 * ONLY WITH all_matches OFF. A caller that asked for every
		 * finding has said that the first one is not the answer.
		 */
		if (p->det_n && !opt->all_matches) {
			chain_over = 1;
			open_finish(p);
			continue;
		}
		/*
		 * A RULE THAT REACHED A VERDICT STOPS THE CHAIN, exactly as a
		 * detector's verdict does above.
		 *
		 * This was scoped to the NORMZ step for one revision, on the
		 * argument that a conclusion only makes RE-READING pointless
		 * and unwrapping is still worth doing. That is a patch and
		 * not a rule: the engine's flow is "a verdict ends the
		 * search", and a finding that claims the file is malware
		 * while the search continues produces a result that
		 * contradicts the verdict it just gave.
		 *
		 * SO A RULE CHOOSES. One that has decided declares
		 * KOF_ENG_CONCLUDE and interrupts; one that is surveying -
		 * "this looks like a loader", "this has something appended" -
		 * declares nothing and the chain runs on. The two are
		 * different kinds of statement and the rule author is who
		 * knows which one was made.
		 *
		 * all_matches overrides it, for the reason it overrides the
		 * detector stop: that caller said the first answer is not the
		 * answer.
		 */
		if (p->concluded && !opt->all_matches) {
			chain_over = 1;
			open_finish(p);
			continue;
		}

		/* The OPEN stage ends where the host's own step begins. */
		if (r->stage == KOF_STAGE_NORMZ)
			open_finish(p);
		r->run(p);
		/*
		 * PRODUCED SOMETHING, SO STOP.
		 *
		 * The object is a wrapper around the thing that just came out,
		 * and the thing is what is worth looking at. Asking a later
		 * step about the wrapper cannot help: normalising a compressed
		 * or encrypted blob finds no zero runs and no text, because
		 * there is none to find until it has been opened.
		 *
		 * n_kids is how the rest of this file already asks "was it
		 * opened" - see family_opened in sx_unpack_object, which compares
		 * the same counter across the same call. A container yields
		 * too, and stops the chain for the same reason: an archive's
		 * bytes ARE its members, and each member is normalised as
		 * itself when its own pass reaches this loop.
		 */
		/*
		 * A CARVED CHILD DOES NOT STOP THE CHAIN.
		 *
		 * The rule is "something came out of this, so the thing that
		 * came out is the subject" - true of a container's member and
		 * of an unpacked image, and false of a payload found by
		 * searching. Nothing declared that an ELF is carrying a file,
		 * so the host is a whole program that happens to have one glued
		 * on, and it still deserves the steps below.
		 *
		 * Measured before this: an 8.6 MB ELF with 4.2 MB appended had
		 * the appendix extracted and then no normalised view of itself
		 * at all, so the 4.4 MB that is the actual program - with a
		 * static library inside it to cut - was never rendered.
		 */
		/*
		 * WHAT THIS STEP PRODUCED, not what the object has.
		 *
		 * Both counters run for the whole object while `kids0` is this
		 * step's, so subtracting the total carved from the total kids
		 * and comparing against a per-step mark mixes two scopes. An
		 * earlier step's carve then reads as a shortfall in this one -
		 * harmless only because NORMZ happens to be last, which is the
		 * kind of accident that stops being true when a step is added.
		 */
		if (r->flags & ROW_GROUP_END) {
			if (group_yielded(p)) {
				chain_over = 1;
				open_finish(p);
				continue;
			}
			p->kids0 = sc->n_kids;
			p->carved0 = sc->n_carved;
		}
		/*
		 * And between steps, because a step is the unit of work that
		 * is worth interrupting: unpacking a large object is where the
		 * time goes, and a cancel asked for during it should not then
		 * pay for a normalisation nobody is waiting for.
		 */
		if (opt->should_stop && opt->should_stop(opt->stop_user)) {
			chain_over = 1;
			open_finish(p);
		}
	}
	/* A chain that ran to its end without a stop has finished the OPEN stage
	 * already, before NORMZ; this is for one that never reached it. */
	open_finish(p);
}

void sx_scan_object(struct kof_scanner *sc, kof_buf buf,
		    const struct kof_scan_option *opt, struct kof_result *out,
		    uint32_t pdepth, int from_packer,
		    const char *inherit_predict, uint8_t as_fmt)
{
	struct kof_pipeline p;

	memset(&p, 0, sizeof p);
	p.sc = sc;
	p.opt = opt;
	p.out = out;
	p.buf = buf;
	p.pdepth = pdepth;
	p.from_packer = from_packer;
	p.inherit_predict = inherit_predict;
	p.as_fmt = as_fmt;
	sx_pipeline_run(&p);
}
