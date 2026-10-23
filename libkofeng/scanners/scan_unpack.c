/*
 * scan_unpack.c - the OPEN stage: ask the unpack modules, in order, whether this
 * object is a wrapper around something, and decide whether the interpreter may be
 * started on what nothing opened.
 *
 * A family the producer predicted goes first; the rest follow in database order, carves
 * last. What comes out is a child, and a child goes round the whole pipeline again.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../kofcore/kofmod/kofsig.h"
#include "../kofcore/kofdebug.h"
#include <string.h>


static int sx_unp_eligible(const struct kof_scanner *sc,
			const struct kof_module *m,
			const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt)
{
	/*
	 * KOF_EMU_ONLY replaces the packer modules and only those. A container
	 * still has to be opened by the code that knows its format - there is
	 * nothing to interpret in a zip.
	 */
	if (opt->emu_use == KOF_EMU_ONLY && kof_step_hides_program(m->step))
		return 0;
	/*
	 * AND NEVER ITS OWN OUTPUT.
	 *
	 * A derived object is the parent with ranges changed - see `derive` in
	 * kofsig.h - so offering it back to the module that changed them is
	 * offering a module its own work to do again. Three modules wrote
	 * their own guard against exactly that and two of the three were wrong
	 * when they were written: `strxor_tab_00.c` first tried "skip a
	 * payload that already reads as text", which threw away six records
	 * whose ciphertext is printable by chance.
	 *
	 * ONLY A DERIVED OBJECT. A NEW one - a container member, a rebuilt
	 * image - is a different file and is offered to everyone, so a zip
	 * inside a zip is opened by the zip module again, and MPRESS under
	 * MPRESS is unpacked twice.
	 */
	if (sx_derived_by(sc) == m)
		return 0;
	/*
	 * Same preconditions as a detector's, from the same place.
	 *
	 * This loop used to spell out three of the four and leave subtype out,
	 * so KOF_TARGET_SUBTYPE on an unpacker built, reported "require subtype"
	 * and then did nothing. No unpacker in bases/ declares one, so honouring
	 * it changes no scan today - it makes the declaration mean what the
	 * build tool already says it means.
	 */
	return kof_module_precond(m, ctx, ctx->obj_size) == KOF_PRECOND_OK;
}

/* Whether an unpacker's declared family is the one that was predicted. Both are
 * strings; NULL on either side is "no", so an unpacker that declares no family
 * never matches and an object with no prediction never has a family pass. */
static int sx_unp_is_family(const struct kof_scanner *sc,
			 const struct kof_module *m, const char *predict)
{
	const char *fam;

	if (!predict)
		return 0;
	fam = kof_db_family(sc->eng, m);
	return fam && strcmp(fam, predict) == 0;
}

/*
 * ONE UNPACK MODULE'S TURN: what it needs, what it is cleared of, the call, and
 * what comes of it.
 *
 * The family pass and the general pass each spelled this out and had drifted
 * (one of them lost a reset); it is the detector loop's turn too, in sx_mod_end's
 * terms: a module runs, and what it marked goes out in one place.
 */
static void unpack_turn(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			struct kof_result *res, const struct kof_module *m)
{
	if (m->n_str)
		sx_need_multi(sc, ctx);
	if (m->n_block)
		sx_need_mutation(sc, ctx);
	/* What this module marked, and not what the last one did. */
	sx_mod_begin(sc, m);
	{
		uint32_t k0 = sc->child.n;

	KOF_TIME_BEGIN(KOF_T_UNPACK);
	m->fn(ctx);
	KOF_TIME_END(KOF_T_UNPACK);
		/* A module that has not read a table the object has - see sx_walk_check. */
		sx_walk_check(sc, ctx, m);
		/* What a carve produced does not make its host
		 * a wrapper - see KOF_ANALYZE_CARVE. */
		if (m->step == KOF_ANALYZE_CARVE &&
		    sc->child.n > k0)
			sc->child.n_carved += sc->child.n - k0;
	}
	sc->mod.cur = NULL;
	/* What it marked goes out; nothing it did names the object. */
	if (res)
		sx_mod_end(sc, res);
	/* A build claimed by a module that opened nothing is
	 * a guess about somebody else's file - see
	 * kof_scanner.obj.open.pend_build. */
	sc->obj.open.pend_build[0] = 0;
	sc->obj.open.pend_build_of = NULL;
	/* The machine, if this module asked for one. Its
	 * regions point into the machine's own memory and the
	 * module has returned, so nothing may read them
	 * again - see kof_scanner.emu.live. */
	kof_scan_emu_release(sc);
}

/*
 * THE OPEN STAGE'S GATE: whether this object is to be opened at all, decided once.
 *
 * Every early return is a refusal that must still leave the per-object state
 * clean - the notes inside say why they sit where they do - and the emulator's
 * stance is set here, in one value, for oc_emu_run to read.
 */
static int open_gate(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		     const struct kof_scan_option *opt, uint32_t pdepth,
		     uint32_t want)
{
	if (sc->eng->n_unp == 0)
		return 0;
	/*
	 * A fresh attempt for every object.
	 *
	 * Hitting a limit while unpacking one container does not mean the tree is
	 * finished: the memory ceiling is about what is alive at this instant, and
	 * by the time a child is being unpacked its siblings have been scanned and
	 * released, so there is room again. What does carry across the whole tree
	 * is `budget`, which is never reset - that is the bomb defence, and it is
	 * the one that has to be cumulative.
	 *
	 * Sticky exhaustion looked harmless and quietly halved the engine: the
	 * first container to reach the ceiling stopped every container after it.
	 */

	/*
	 * AND WHETHER ANYBODY SPOKE FOR THE INTERPRETER ON THIS OBJECT.
	 *
	 * Resolved here because every term is the host's: a diagnose's ask rides in
	 * `want` from this object's EXAMINE stage, a producer's ask rides in
	 * cur_want from the module that made the object, and both are bounded
	 * by options a module cannot see. c_emu_run or-s the result into the
	 * vouch the asking module passes - see emu_stance in scan.h.
	 *
	 * The heur gate applies to the PRODUCER's ask only. A diagnose's ask
	 * came from a declaration that matched this object; the producer's is a
	 * declaration carried with the child and is honoured at the level the
	 * producer named.
	 */
	/*
	 * A DIAGNOSE'S ASK DOES NOT LOOK AT emu_use, AND THAT IS NOT AN OVERSIGHT.
	 *
	 * The option word cannot tell an explicit "--emu never" apart from the
	 * NEVER a default or `--heur 1` leaves behind, and turning the second
	 * of those into a run is the whole point of the ask. kofexaminer sets
	 * emu_use nowhere at all, so reading it here is reading a zero nobody
	 * wrote. `emu_forbidden` is the refusal somebody DID write, and it is
	 * the one a rule may not talk past.
	 *
	 * A PRODUCER's ask is bounded more tightly - it is a declaration
	 * carried with a child rather than a declaration that matched the object
	 * in front of us - so it yields to emu_use and to the heuristic level the
	 * producer named.
	 */
	{
		int default_ok = opt->emu_use != KOF_EMU_NEVER;
		int ask = (want & KOF_ENG_USE_EMU) != 0 ||
			  (default_ok && (sc->cur.want & KOF_ENG_USE_EMU) &&
			   !sc->obj.emu.produced && !opt->heur_off &&
			   opt->heur_level >= sc->cur.want_level);
		/*
		 * THE TWO REFUSALS NO VOUCH TALKS PAST. Not budgets - those are in
		 * oc_emu_run with the other ceilings - but "run nothing, I mean it"
		 * and "this is already a payload of a payload".
		 */
		if (opt->emu_forbidden || pdepth > EMU_MAX_PACKER_DEPTH)
			sc->obj.emu.stance = KOF_EMU_STANCE_BANNED;
		else if (opt->emu_use == KOF_EMU_ONLY)
			sc->obj.emu.stance = ask ? KOF_EMU_STANCE_ONLY_ASKED
					     : KOF_EMU_STANCE_ONLY;
		else if (ask)
			sc->obj.emu.stance = KOF_EMU_STANCE_ASKED;
		else
			sc->obj.emu.stance = default_ok ? KOF_EMU_STANCE_GUESS
						    : KOF_EMU_STANCE_NOBODY;
	}

	/*
	 * DEEP SCAN OFF MEANS DO NOT OPEN IT, and this is the only place that
	 * can honour that - everything below produces children.
	 *
	 * It was honoured only at the far end of the walk, where children are
	 * PUSHED, so every container was decompressed in full and the results
	 * dropped on the floor. Measured: --heur 0 --max-produced 1 on a gzip
	 * still reported "the engine could not finish", which is a scan that
	 * paid for work nobody asked for AND then failed at it.
	 *
	 * Nothing is lost by refusing here. What is inside a container is
	 * declared by its parse - ctx->entries - and its bytes are still
	 * covered by a region, so a rule still searches them. That is the
	 * distinction kofeng.h draws on the field itself: off means "do not
	 * descend", never "do not look".
	 *
	 * Returning 0 and not sc->broken: refusing to open something is not a
	 * failure to examine it. `broken` means "something wanted to look and
	 * could not", and here nothing wanted to.
	 *
	 * AFTER the per-object resets just above and not before them. Those
	 * three fields are hygiene - the note on them says why sticky
	 * exhaustion "looked harmless and quietly halved the engine" - so an
	 * early return that skipped them would leave the previous object's
	 * state standing for this one.
	 */
	if (!kof_objtree_may_open(opt))
		return 0;

	/*
	 * A VIEW IS NOT OPENED, ONLY MATCHED.
	 *
	 * Everything openable in a normalised view was openable in the object
	 * it was made from, and was opened there - the parent is scanned whole
	 * and before this. Opening the view again produces the same content a
	 * second time: measured on an ELF carrying 4.2 MB past its last
	 * segment, which came out once as a child of the file and again as a
	 * child of its view, the same bytes with the padding taken out.
	 *
	 * THE OBJECT SAYS SO ITSELF - see kof_src_kind_of. It was "has a
	 * declared region table", which is a consequence of being a view and
	 * not the fact: a view of an object whose regions could not be resolved
	 * carries no table, and its parent's appendix came out twice.
	 *
	 * WHAT THIS GIVES UP, because it is not nothing. A decoded payload can
	 * be a whole file that exists nowhere in the parent - base64 in, an ELF
	 * out - and that file is then not parsed as one. Its BYTES are in the
	 * view and every rule searches them, which is what the view is for; it
	 * is the structure that is not recovered.
	 */
	if (kof_src_kind_of(sc->cur.src) == KOF_ENT_NORMALIZED)
		return 0;

	kof_mod_unpack_mode(ctx, 1);
	return 1;
}

	/*
	 * FAMILY FIRST, when one was predicted.
	 *
	 * The producer of this object may have named the family it expects
	 * (the family it declares with KOF_TARGET_NAME). The decoders of that family are tried
	 * before any other, so an object correctly predicted is opened by the
	 * one module written for it and the rest are never entered.
	 *
	 * This is a REORDERING and never a filter, and the distinction is the
	 * whole safety of it. If the predicted family's decoders open the object
	 * the general pass is skipped - the best case, and the only time
	 * anything is saved. If they do not, the general pass runs every
	 * eligible unpacker exactly as it always has. So a wrong prediction
	 * costs the order it imposed and misses nothing: the worst case is the
	 * old case. The number of children before and after is how "did it open
	 * it" is answered, because producing a child is the only thing an
	 * unpacker does that the next pass would want to know about.
	 */
static int open_family(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		       const struct kof_scan_option *opt,
		       struct kof_result *res,
		       const char *predict, int *applies)
{
	uint32_t i;
	uint32_t kids0 = sc->child.n;
	uint32_t carved0 = sc->child.n_carved;

	for (i = 0; i < sc->eng->n_unp && !sc->obj.open.broken; i++) {
		const struct kof_module *m = &sc->eng->unp[i];

		if (!sx_unp_eligible(sc, m, ctx, opt) ||
		    !sx_unp_is_family(sc, m, predict))
			continue;
		*applies = 1;
		unpack_turn(sc, ctx, res, m);
	}
	/*
	 * OPENED, AND A CARVE DID NOT OPEN ANYTHING - the same rule
	 * analyze_object applies one level up, and for the same
	 * reason: a carved child is a file that was glued on, so the
	 * host is still an unopened object and the general pass below
	 * is still owed to it. Counted as an opening, one family's
	 * carver would stand in for every other unpacker in the
	 * database.
	 *
	 * Both counters are the whole object's, so both marks are
	 * this pass's - see the note on the same subtraction in
	 * analyze_object.
	 */

	return sc->child.n - kids0 > sc->child.n_carved - carved0;
}

	/*
	 * The general pass, unless the predicted family already opened it.
	 *
	 * It skips the family-matched modules when a prediction was made,
	 * because the family pass above already ran them - re-running one that
	 * declined would be doing its work twice.
	 */
	/*
	 * TWO ROUNDS, AND A CARVE GOES IN THE SECOND.
	 *
	 * A carve says "there is a whole file glued on here". That is the right
	 * answer when nothing can explain those bytes and the wrong one when
	 * something can: on a TeamTNT sample the unclaimed run at the end of a
	 * Go binary is an Ezuri key and ciphertext, and appended_00.c carved it
	 * out as 340052 bytes nothing can read - beside the ELF that ezuri.c
	 * decrypted from the very same bytes. Two objects, one run, and one of
	 * them unreadable by construction.
	 *
	 * Ordering is the whole fix, because the carve module cannot tell: it
	 * asks kunp_opened_already, and running first it is always the answer
	 * "no". Deciding by kind rather than by database order also keeps it out
	 * of the hands of whoever adds the next module.
	 *
	 * A carve that finds something a packer already explained still costs
	 * nothing but the ask - it declines and the loop moves on.
	 */
/* One STEP of the general pass: the modules that declared it, in database
 * order. Returns 0 when the tree's budget is gone and the caller must not go on. */
static int open_pass(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		     const struct kof_scan_option *opt,
		     struct kof_result *res,
		     const char *predict, enum kof_analyze step, int *applies)
{
	uint32_t i;

	for (i = 0; i < sc->eng->n_unp; i++) {
		const struct kof_module *m = &sc->eng->unp[i];

		if (m->step != (uint32_t)step)
			continue;
		if (!sx_unp_eligible(sc, m, ctx, opt))
			continue;
		/* Skip what the family pass already tried. Guarded on `predict`
		 * so the resolve-and-compare is not paid on the overwhelming
		 * majority of objects, which no rule spoke for. */
		if (predict && sx_unp_is_family(sc, m, predict))
			continue;

		*applies = 1;
		/*
		 * NARROWED TO THE LIMIT, for the reason spelled out where the
		 * interpreter's gate was narrowed the same way: `broken` was
		 * written here as any reason at all, and that turns one
		 * module's honest note into a refusal to let the rest look.
		 *
		 * Measured: PECompact reports KOF_BROKEN_UNSUPPORTED on
		 * 007 Spy.exe - true, it recognised the packer and cannot
		 * unpack that build - and that one line ended the loop before
		 * emu_generic_00, the module whose whole job is the object
		 * nothing static could open. The file went from a recovered
		 * child to "Unsupported by this build".
		 *
		 * The budget is the one thing that genuinely stops the tree,
		 * and it is the only thing this now stops for.
		 */
		if (sc->obj.open.broken == KOF_BROKEN_LIMIT)
			return 0;       /* nothing left to spend on this tree */
		unpack_turn(sc, ctx, res, m);
	}
	return 1;
}

/*
 * THE RECOVERING MODULES - see KOF_ANALYZE_RECOVER.
 *
 * Every one of them, on every object: open_gate answers whether an object is
 * worth OPENING, and that is not the question here. An object that already has a
 * named finding is refused by the gate and is the one whose symbols a tool
 * shows most readily. Nothing chains from a recovery either - it produces no
 * child, so there is nothing for a later step to be spared.
 */
void sx_recover(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		const struct kof_scan_option *opt, struct kof_result *res)
{
	int applies = 0;

	if (!sc->eng || sc->eng->n_unp == 0)
		return;
	/* The producing surface for the length of the step, and not after: the
	 * gate that turns it on for the opening steps is the one this skips. */
	kof_mod_unpack_mode(ctx, 1);
	(void)open_pass(sc, ctx, opt, res, NULL, KOF_ANALYZE_RECOVER,
			&applies);
	kof_mod_unpack_mode(ctx, 0);
}

/*
 * ONE STEP OF OPENING AN OBJECT: the modules that declared `step`, and before
 * the first of them the gate and the predicted family.
 *
 * Called once per row of analyze_steps, in enum order, so the order the steps
 * were designed in (see enum kof_analyze) is the order modules run in - a
 * container's table is read before a packer is asked about the same bytes, and
 * a carve, which searches, comes last. `o` is the object's own record of where
 * the stage is: the gate is decided on the first call, a refusal or an opening
 * by the predicted family answers every later call without work.
 */
void sx_open_step(struct kof_pipeline *p)
{
	struct kof_scanner *sc = p->sc;
	struct kof_obj_ctx *ctx = &p->ctx;
	const struct kof_scan_option *opt = p->opt;
	struct kof_result *res = p->out;
	const uint32_t pdepth = p->pdepth, want = p->want;
	const char *predict = p->predict;
	const enum kof_analyze step = p->step;
	struct kof_open *o = &p->open;

	if (o->state == KOF_OPEN_FRESH) {
		o->state = open_gate(sc, ctx, opt, pdepth, want)
			   ? KOF_OPEN_ACTIVE : KOF_OPEN_REFUSED;
		if (o->state == KOF_OPEN_ACTIVE && predict &&
		    open_family(sc, ctx, opt, res, predict, &o->applies))
			o->state = KOF_OPEN_FAMILY;
	}
	if (o->state != KOF_OPEN_ACTIVE)
		return;
	(void)open_pass(sc, ctx, opt, res, predict, step, &o->applies);
}

/*
 * THE END OF THE OPEN STAGE, whichever row it ended on: the declared carried
 * files, the ciphertext check, and the answer - how much of the tree's budget
 * the object ate, or 0 when nothing wanted to open it. Called once, and only
 * for an object whose gate let it in.
 */
uint32_t sx_open_end(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		     const struct kof_scan_option *opt, struct kof_open *o)
{
	int applies = o->applies;

	if (o->state == KOF_OPEN_FRESH || o->state == KOF_OPEN_REFUSED ||
	    o->state == KOF_OPEN_DONE)
		return 0;
	o->state = KOF_OPEN_DONE;
	/*
	 * A COMPLETE FILE SITTING AT AN OFFSET IS NOT AN UNPACKING PROBLEM -
	 * AND IT IS NOT THE ENGINE'S SEARCH EITHER, ANY MORE.
	 *
	 * It was: two magics written into the scanner, run over every object of
	 * every format, before the loop above had even been consulted about
	 * what the object's structure already said. Three consequences, all one
	 * fault.
	 *
	 * Finding a THIRD kind of carried file meant editing the engine, so
	 * what the engine could find was a property of its own build rather
	 * than of the database - which is the one thing every other kind of
	 * detection here avoids.
	 *
	 * NOT searching was worse. A format that names its own attachments -
	 * PDF /EF, a zip directory - has already produced them, so a search
	 * finds the same bytes again: measured, one attachment became two
	 * children and 0.69MB was scanned twice. Expressing "do not search a
	 * PDF" needed a table in the engine naming formats, which is the
	 * engine deciding a module's business.
	 *
	 * And WHERE to look - a PE's overlay and resources, an ELF's data,
	 * never their code - is format knowledge that was sitting in the
	 * scanner.
	 *
	 * So it is gone, and NOTHING REPLACES IT YET. Its successor is not
	 * another sweep: a rescan of every object for two-byte magics is the
	 * cost that made the old one wrong, whatever declared it. What comes
	 * instead is per studied case - a rule's ASK honoured here rather than
	 * a search performed here.
	 *
	 * What remains is step 4 below: the carried files the STRUCTURE named,
	 * which needs no search at all.
	 */
	/*
	 * NOTHING OPENED IT: THE INTERPRETER IS NOT STARTED FROM HERE.
	 *
	 * It used to be - a chain of three gates (a rule's ask, a producer's ask and
	 * the entropy gate) ended in a branch that did nothing but count, because the
	 * run itself had moved into the unpack modules: a module asks with
	 * kunp_emu_run and the host answers in oc_emu_run, from emu_stance above, in
	 * ONE place. The chain was left behind with its comments and one live side
	 * effect, `heur_emu++`, which counted every ask and then counted the run again
	 * - so a scan spent its whole-scan ceiling at half the runs it was meant to
	 * allow. The notes that justified each gate - why a rule's ask skips the
	 * entropy gate, why only LIMIT refuses a run - are with the policy they
	 * explain, in oc_emu_run and kof_scan_emu_unpack.
	 */
	/*
	 * THE CARRIED FILES THE STRUCTURE NAMED, AND THIS IS LAST ON PURPOSE.
	 *
	 * The order of this whole function is the pipeline, and the pipeline is:
	 *
	 *   1. the PARSE has already said what the object is made of - which
	 *      bytes are which region, and which of them are files it carries.
	 *      That happened in sx_identify(), before any module ran.
	 *   2. the DETECTORS have had their say, in the caller.
	 *   3. the UNPACKERS and the emulator have finished above: whatever was
	 *      compressed or encoded is now an object of its own.
	 *   4. ONLY THEN are declared carried files opened.
	 *
	 * Last because every step before it can change the answer. An object
	 * that was packed is not the file the author wrote, so its structure's
	 * claims about what it carries are claims about the wrapper; the
	 * unpacked child is where those claims are worth acting on, and the
	 * child is scanned as an object in its own right, so it reaches this
	 * same step with its own parse behind it. Running this first would open
	 * attachments named by a wrapper before anything had established that
	 * the wrapper was the file.
	 *
	 * AND IT ONLY RUNS UNDER DEEP SCAN, which is not a saving but the
	 * definition of the two levels:
	 *
	 *   deep OFF   the carried file stays BYTES IN A REGION. Its own format
	 *              names that region - KOF_SCAN_EMBEDDED where the format
	 *              has carried files at all - so a rule still searches it,
	 *              the parse still says how many there are and how big, and
	 *              nothing is decompressed or copied to learn that.
	 *   deep ON    the same ranges become children, from the same table, so
	 *              a file cannot be searchable and unextractable or the
	 *              reverse.
	 *
	 * kof_objtree_may_open is checked inside, at the top, so this is one
	 * call rather than a call and a guard that could disagree.
	 */
	if (!sc->obj.open.broken && kof_objtree_declared(ctx, opt))
		applies = 1;

	kof_mod_unpack_mode(ctx, 0);

	/*
	 * NOTHING OPENED IT AND ITS CODE IS A CIPHERTEXT, WHICH IS NOT CLEAN.
	 *
	 * The last thing asked about a PE, after every unpacker and the
	 * interpreter have had their turn, and only when none of them produced
	 * anything. A large EXECUTABLE section at 7.9 bits per byte that the
	 * entry point is NOT in is a program whose code this scan never saw:
	 * the bytes that ran are somewhere else, and the ones that are supposed
	 * to be the program are indistinguishable from random.
	 *
	 * AFTER, AND THAT IS THE WHOLE REASON IT IS HERE AND NOT IN A MODULE.
	 * Of 26 files in one collection with this shape, several are MPRESS and
	 * UPX - which this engine opens completely. A module would have said
	 * "unsupported" about them before the module that unpacks them ran, and
	 * the first reason recorded is the one kept. Asked here, the question
	 * is the right one: did anything at all get inside?
	 *
	 * Measured: a Safengine sample whose .text is 794,624 bytes at 8.00
	 * bits, entry point in .sedata, reported "clean 1 file(s)" - a true
	 * statement about bytes nobody could read and a false impression about
	 * the program.
	 */
	if (!sc->obj.open.broken && !sc->child.n && ctx->format == KOF_FMT_PE)
		sx_dense_code_unread(sc, ctx);

	/*
	 * "Not fully examined" means both halves: something wanted to open this
	 * object, and the budget was gone. The budget is shared by the whole tree,
	 * so once it runs out every later object inherits the flag - and reporting
	 * that on an object no unpacker would have touched anyway is noise that
	 * makes the real case harder to see.
	 */
	return applies ? sc->obj.open.broken : 0;
}
