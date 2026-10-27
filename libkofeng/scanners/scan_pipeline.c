/*
 * scan_pipeline.c - one object through its stages: the pipeline table and the loop
 * that runs it.
 *
 * A stage is a function over the object's kof_pipeline and a row in `pipeline` below;
 * the order of the rows is the order things happen to an object, and it is
 * stated here once and nowhere else. The chain rows (the opening steps and the
 * host's own NORMZ) are subject to the chain's stops - a child that came out, a
 * cancel - and the rows around them are not. Nothing a module says is a stop: the
 * verdict is read off every disease the object has.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objctx_int.h"
#include <stdlib.h>
#include <string.h>

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
 * by hand: the open stage, then a kids0 comparison, then sx_norm_emit under an if.
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
	/* the constants of a script are asked for at this level: the one scan of its text collects them with the names (objctx_textscan.c) */
	sc->obj.text.deep = (uint8_t)(opt && opt->heur_level >= 2);
	/*
	 * EVERY DIAGNOSE ONLY WHEN THE CALLER ASKED FOR THE REPORT, and it is
	 * said at the start of the object so the one analysis covers them all and
	 * is not run twice. A scan that did not ask computes what some reader
	 * needs: a rule that names a diagnose, or a diagnose that declares a
	 * disease the verdict reads - see diag_has_reader.
	 */
	sc->obj.diag.all = opt && opt->report_diag != 0;

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

	kof_match_begin(&sc->match.m, p->buf);

	/*
	 * THE CHILD'S OWN DECLARATION FIRST, then the caller's.
	 *
	 * opt->as_format is about the object the CALLER handed in - a submitted
	 * event record, which has no magic for a sniff to find. as_fmt is what
	 * the thing that produced THIS child said about it, and for a child the
	 * second is the specific claim: the caller's applies to the root of the
	 * walk and would otherwise be re-applied to every object under it.
	 */
	if (!sx_inherit_image(sc, &p->ctx))
		sx_identify(sc, p->buf, &p->ctx,
			 p->as_fmt ? p->as_fmt : (opt ? opt->as_format : 0u),
			 opt ? opt->as_view : NULL, opt ? opt->as_view_len : 0u);
	/*
	 * AND THE ANALYSIS OF THE OBJECT IT RENDERS, when it renders one - see
	 * objprod.h. After the image, before anything reads either.
	 */
	{
		const struct kof_prod *pr = kof_src_prod_of(sc->cur.src);

		if (pr)
			kof_prod_adopt(sc, pr);
	}
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
	if (sc->cur.lang) {
		p->ctx.subtype = sc->cur.subtype;
		p->ctx.subfamily = sc->cur.subfam;
		/* And out to the caller, which has the same problem the engine
		 * had: reading the bytes gives the wrong answer. */
		out->subtype = sc->cur.subtype;
		out->subfamily = sc->cur.subfam;
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
	if (sc->cur.n_rgn) {
		uint32_t g;

		p->ctx.resolve_scan = sx_declared_resolve_scan;
		/* And out to the caller, which has the same problem the engine
		 * had: it cannot work these out from the bytes either. */
		/* KNOWN DEFECT N-REGION16 (2026-10-24, R) [sev M]: this copy clips kof_result.region[] to KOF_MAX_REGIONS (16) and says nothing,
		 * while the declared table (sc->cur.rgn) is now as long as the producer's. Trigger: a normalised PE with more than 16
		 * disjoint code extents. Effect: the host sees 16 regions and n_region 16, the rest vanish without a flag or oc_scan_limit.
		 * Reproducer: corp300/015_240fe (2048 library spans). Fix: report the cut (KOF_BROKEN_LIMIT, limit_hits) or add a total count (ABI). */
		for (g = 0; g < sc->cur.n_rgn && g < KOF_MAX_REGIONS; g++) {
			out->region[g].mask = sc->cur.rgn[g].mask;
			out->region[g].off = sc->cur.rgn[g].off;
			out->region[g].len = sc->cur.rgn[g].len;
		}
		out->n_region = g;
		out->region_fmt = sc->cur.rgn_fmt;
	}

	{
		uint32_t resolve = sc->eng->scan_mask;

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
	sc->cur.present  = p->present;
	sc->cur.from_packer = (uint8_t)(p->from_packer != 0);

	/*
	 * And the same for similarity: every block any loaded rule declared is
	 * counted once, so a module's kof_mutation_score is a division - but on
	 * the first ask rather than here, for the reason above.
	 *
	 * Gated twice on purpose, and both gates still apply inside the feed.
	 * The set is NULL unless some pack carried a block, so a database
	 * without mutation rules never reaches this. And within it, a region is
	 * fed only for the normalizers some block of that region actually asked
	 * for - a pack whose blocks all hash raw bytes pays one pass, not three.
	 *
	 * THE GENERATION BUMP IS NOT DEFERRED WITH THE FEED. It is O(1) - see
	 * kof_mutation_begin - and it is what makes "this object fed nothing" read
	 * as nothing rather than as whatever the last object fed.
	 */
	/* What the last object's state was charged to the ledger is given back with it. */
	oc_scan_release(sc, sc->mutation.ledgered);
	sc->mutation.ledgered = 0;
	/* And what the last object's found-table grew to (scan_feed.c, sx_multi_prepass). */
	oc_scan_release(sc, sc->match.pix_ledgered);
	sc->match.pix_ledgered = 0;
	kof_mutation_begin(&sc->mutation);
	/*
	 * THIS OBJECT'S DESCRIPTOR IS NOT THE LAST ONE'S.
	 *
	 * Here and not inside sx_mutation_feed, which returns early when no pack
	 * carried a block: a database with no mutation rules would then have left
	 * the previous object's descriptor in place, and every kof_mutation_blocks
	 * rule would have measured the wrong file. Built on the first ask, so
	 * this costs a store.
	 */
	/* What the gated measures compare themselves against - see
	 * kof_scanner.cur.heur_lvl. Unstated is level 1, exactly as sx_heur_object
	 * reads it, so the two cannot drift. */
	sc->cur.heur_lvl = opt->heur_off ? 0u
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
		struct kof_mod_walk walk;
		uint32_t mi;

		kof_mod_walk_begin(&walk, e, p->ctx.format);
		if (walk.indexed && !similarity) {
			/* Once per object: the second call is the same run's other half. */
			sc->st.considered += e->n_mods - kof_mod_walk_count(&walk);
			sc->st.by_target  += e->n_mods - kof_mod_walk_count(&walk);
		}

	while (kof_mod_walk_next(&walk, &mi)) {
		const struct kof_module *m = &e->mods[mi];

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
			sx_need_mutation(sc, &p->ctx);

		sx_mod_begin(sc, m);
		m->fn(&p->ctx);
		sc->mod.cur   = NULL;
		/* What it marked goes out; nothing it did names the object. */
		sx_mod_end(sc, out);
	}
	}

}

/*
 * DETECT: the detectors, in database order, cheapest test first. Every one that
 * fires reports: nothing a detector says ends the stage.
 */
static void st_detect(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;

	run_modules(p, 0);

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->match.m.n_calls;
	sc->st.bytes_searched += sc->match.m.n_bytes_scanned;
	sc->st.gram_bytes     += sc->match.m.n_bytes_indexed;
	/* A hex walk that could not look (no memory for the wide walk) is a "no" that
	 * is not evidence: the object says so (the result at the verdict stage). */
	if (sc->match.m.n_hex_cut)
		oc_scan_limit(sc);
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
 * EXAMINE: what the object asks of the engine, before it is opened.
 * What a diagnose's own declaration asks for is collected here and read by every
 * stage below.
 */
static void st_examine(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;

	/*
	 * ---- A DIAGNOSE'S OWN DECLARATION IS AN ASK -----------------------
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
	 * The ask is OR-ed into what a producer asked: neither may cancel the
	 * other.
	 */
	if (kof_scan_diag_sign_asks(&p->ctx)) {
		sc->obj.diag.ask = 1;
		p->want |= KOF_ENG_USE_EMU;
	}
	/*
	 * The family the producer decodes is the prediction, when there is one:
	 * the formatless intermediate layer a decoder peels is something
	 * nothing recognises, but its parent was a Meterp payload, so it very
	 * probably is one too, and trying that decoder first is the whole point
	 * of carrying the guess down.
	 */
	p->predict = p->inherit_predict;
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
	 * the open stage's rule: "not fully examined" is only worth saying about
	 * an object something actually tried to open.
	 */
	if (sx_script_forms(sc, &p->ctx, opt, p->pdepth) && sc->obj.open.broken)
		out->broken = sc->obj.open.broken;
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

		if (sb && sc->cur.src && !kof_src_declare_syms(sc->cur.src, sb, ns))
			oc_scan_limit(sc);      /* the result carries no served symbols: said (engine_defect2 E2) */
	}
}

/*
 * ANALYSE: the analysis a declaration asked for, built now so that whatever reads
 * it finds it. It is a feed like the pattern and similarity feeds, demanded and
 * built on demand (see diag_ready), and not a stage of its own: nothing happens to
 * the object in it.
 */
static void st_analyse(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;

	/*
	 * ---- THE DIAGNOSE ANALYSIS RUNS, IF ANYTHING ASKED ---------------
	 *
	 * ONE ASKER, AND IT IS THE DATABASE. A diagnose declares the symbols
	 * or the file attributes that make an object worth the walk and the
	 * EXAMINE stage sets sc->obj.diag.ask from that; a module reaching for
	 * a diagnose or the graph sets it too, at the moment it asks.
	 *
	 * A module does not have to wait for this. It runs before this point,
	 * and reaching for a diagnose or the graph runs the analysis there and
	 * then - see diag_ready. This is for the object whose analysis was
	 * asked for by a DECLARATION rather than by a question.
	 *
	 * The latch inside makes it once per object however many times it is
	 * reached, and an object nobody asked about still does no work.
	 */
	if (sc->obj.diag.ask) {
		kof_scan_diag_force(&p->ctx);
		oc_diag_trace_scan(sc);
	}
}

/*
 * MODEL: the scored model's measurement over the whole object - published for an
 * examiner (kof_result.heur_*); it names nothing.
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
	 * Only the model that reasons about layout is skipped, because the
	 * layout belongs to the parent and the parent is scanned too.
	 *
	 * A VIEW IS KNOWN BY ITS KIND (KOF_ENT_NORMALIZED, the one carrier), not by
	 * having declared regions: a script view used to be told apart by the one BODY
	 * region it declared, which made a region the carrier of a different fact.
	 */
	if (!sc->cur.n_rgn && kof_src_kind_of(sc->cur.src) != KOF_ENT_NORMALIZED)
		sx_heur_object(sc, &p->ctx, opt, p->pdepth,
			    out->broken == KOF_BROKEN_DAMAGED, out);
}

/*
 * VERDICT: what the diseases the object has make.
 *
 * ONCE, after everything that can find a disease has run, and the answer is kept
 * in the result: the set is read and the name composed from it one time and
 * nothing downstream reads it again.
 */
static void st_verdict(struct kof_pipeline *p)
{
	sx_verdict_make(p->sc, &p->ctx, p->out);
	/* A bound cut this object's evidence (oc_scan_limit): the result says so, over
	 * no earlier reason - and a clean answer is not given for it. */
	if (p->sc->obj.open.cut && !p->out->broken)
		p->out->broken = KOF_BROKEN_LIMIT;
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
	if (!sc->diag.rep) {
		sc->diag.rep = calloc(sc->diag.cap ? sc->diag.cap : 1u, sizeof *sc->diag.rep);
		if (!sc->diag.rep)
			return;
	}
	for (i = 0; i < n; i++)
		if (kof_scan_diag_report(&p->ctx, i, &sc->diag.rep[k]))
			k++;
	p->out->diag = sc->diag.rep;
	p->out->n_diag = k;
}

static void st_recover(struct kof_pipeline *p)
{
	sx_recover(p->sc, &p->ctx, p->opt, p->out);
}

static void st_open(struct kof_pipeline *p)
{
	sx_open_step(p);
}

/* The end of the OPEN stage, once, if it began. A refusal answers 0, which is
 * what the object's `broken` is then set to - nothing wanted to open it. */
/* Whether the rows of the current group produced a child that is not a carve:
 * a carve is a file glued on, so the host is still the subject - see
 * KOF_ANALYZE_CARVE. The one place this is asked. */
static int group_yielded(const struct kof_pipeline *p)
{
	return p->sc->child.n - p->kids0 != p->sc->child.n_carved - p->carved0;
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
	{ KOF_STAGE_ANALYSE,     KOF_ANALYZE_UNWRAP,  0,                              st_analyse },
	{ KOF_STAGE_MODEL,     KOF_ANALYZE_UNWRAP,  0,                              st_model },
	{ KOF_STAGE_VERDICT,   KOF_ANALYZE_UNWRAP,  0,                              st_verdict },
	{ KOF_STAGE_REPORT,    KOF_ANALYZE_UNWRAP,  0,                              st_report }
};

/* One object through every stage. */
static void sx_pipeline_run(struct kof_pipeline *p)
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
			p->kids0 = sc->child.n;
			p->carved0 = sc->child.n_carved;
			chain_begun = 1;
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
		 * opened" - see the open stage (scan_unpack.c), which compares
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
			p->kids0 = sc->child.n;
			p->carved0 = sc->child.n_carved;
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
	/* What this object learned is shared with the renderings of it it made. */
	kof_prod_publish(sc);
	/*
	 * AND WHAT THE FILE SIZED IS GIVEN BACK: the tables of its parsed view (zip, pdf) and
	 * the extent buffers that grew for it. Nothing reads either after the pipeline - the
	 * children are already collected, and the next object parses its own - so holding
	 * them would charge the ledger, for the rest of the tree, for the structure of an
	 * object that is finished.
	 */
	sx_views_release(sc);
}
