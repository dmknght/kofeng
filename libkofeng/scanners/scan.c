/*
 * scan.c - one object through the pipeline: the core every stage unit hangs from.
 *
 * What is here: the scanner's lifecycle, the per-object and per-module resets
 * (obj_begin, mod_begin), the shared turn of one module (sx_mod_report: report to
 * finding to verdict slot to repair), the detector loop, and sx_scan_object, which
 * runs the stages in order. The stages themselves are units of their own:
 *
 *   scan_facts.c    what is true of an object before a module looks (format, regions)
 *   scan_feed.c     the work shared by modules, done once per object (plague, multi)
 *   scan_heur.c     heuristic rules (EXAMINE, VERDICT) and the model score
 *   scan_unpack.c   the OPEN stage: unpack modules and the interpreter's stance
 *   scan_norm*.c    the NORMALISE stage: the view of an object with noise removed
 *   scan_verdict.c  naming a finding and the object's one verdict slot
 *   scan_walk.c     from a path to objects: directories, files, the tree of kids
 *   scan_mt.c       the parallel walk
 *
 * Shared between them only through scan_int.h, with the sx_ prefix. What is NOT here:
 * the untrusted boundary a module reads through (objctx*.c), and how a search is
 * answered (the matcher).
 *
 * OPEN, found by reading and not yet changed (the order below is the order they
 * should be done in, each verified against the three-mode corpus snapshot):
 *   - sx_scan_object is one function of ~540 lines whose stages pass state through
 *     loose scanner fields (cur_*, pend_*, emu_*, diag_*, packed_here ...). It should
 *     take an explicit per-object state and return a stage outcome.
 *   - "did this object yield" is spelled three ways: analyze_object (kids minus
 *     carved, per step), unpack_object (family_opened) and the post-hoc drop
 *     (kids over views plus carved, totals).
 *   - out->n_region, the repair offered by a second module, and a should_stop break
 *     leave no trace in the result.
 *   - from_packer has three carriers (argument, out, scanner).
 */

/* lstat and the dirent walk are POSIX and the tree builds as strict ISO C11, so the
 * feature level has to be asked for - and before any include, or it does nothing.
 *
 * _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h (below),
 * whose POSIX branch defines kof_memmem by calling the real memmem - a
 * GNU/BSD extension the compiler must still see declared to compile that
 * inline function, whether or not scan.c itself calls it. _POSIX_C_SOURCE
 * alone does not just omit memmem on glibc, it suppresses it (any of
 * _POSIX_C_SOURCE/_XOPEN_SOURCE defined without _GNU_SOURCE/_DEFAULT_SOURCE
 * opts into strict POSIX). Missed originally because this project's builds
 * so far all ran on Windows, where kof_memmem never touches the real memmem
 * - a real Linux build fails immediately with "implicit declaration of
 * function 'memmem'". _GNU_SOURCE is a superset of _POSIX_C_SOURCE 200809L,
 * so nothing else this file relied on changes. */
#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
/* The rule ABI: the phase ids and what a rule may ask the engine for. The
 * engine-side model next door is a different file with a similar name - see the
 * note at the top of kofmod/heur.h. */
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
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

struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *ctx)
{
	return (struct kof_scanner *)(void *)(uintptr_t)ctx->priv;
}

struct kof_scanner *kof_scan_new(const struct kof_engine *eng)
{
	struct kof_scanner *sc = calloc(1, sizeof *sc);

	if (!sc)
		return NULL;
	sc->eng = eng;
	sc->sink_fd = -1;   /* 0 is stdin; calloc would have made this a live fd */

	/* The matcher owns the search state: the presence set and the memo are how a
	 * search is answered, not how a scan is bookkept. */
	if (!kof_match_state_init(&sc->m, eng->n_str, eng->memo_size))
		goto fail;
	/*
	 * The symbol block's matcher: its own presence table, sized for a
	 * block rather than for a file, and no memo.
	 *
	 * 20 bits is 1M slots - 2MB against the file table's 32MB - and the
	 * block is capped at KOF_SYM_MAX_BYTES, a quarter megabyte, so
	 * occupancy stays under a quarter even at the cap and is a fraction of
	 * a percent at the median few kilobytes.
	 *
	 * The threshold is 2 rather than 140 because the arithmetic behind 140
	 * is about a buffer of megabytes: stamping costs one pass, and over a
	 * block this small the second search already pays it back.
	 *
	 * No memo here - c_find_str keeps the cell in sc->m, where the slot is
	 * already allocated by the database. See the note there.
	 */
	sc->msym.gram_bits = 20;
	sc->msym.gram_min = 2;
	if (!kof_match_state_init(&sc->msym, eng->n_str, 0))
		goto fail;

	/*
	 * The similarity counters, when the database brought any blocks.
	 *
	 * Skipped entirely when it did not, which is the common case: no
	 * allocation, and the feed below is never reached because the set is
	 * NULL. A database with no plague rules costs nothing here.
	 */
	if (eng->plague && !kof_plague_ctx_init(&sc->plague, eng->plague))
		goto fail;

	/* One counter per region, and one word per marker for where it was seen.
	 * A failure here is not fatal: the prepass needs both and simply does
	 * not run without them. */
	sc->live = calloc(KOF_MULTIMATCH_BITS, sizeof *sc->live);
	if (eng->multi && eng->multi->n_pat) {
		sc->found = calloc(eng->multi->n_pat, sizeof *sc->found);
		sc->mask_ok = calloc(eng->n_masks ? eng->n_masks : 1u,
				     sizeof *sc->mask_ok);
	}
	return sc;

fail:
	kof_scan_free(sc);
	return NULL;
}

void kof_scan_free(struct kof_scanner *sc)
{
	uint32_t i;

	if (!sc)
		return;
	kof_match_state_free(&sc->m);
	kof_match_state_free(&sc->msym);
	/* The last object's graph, which the per-object reset never reached
	 * because there was no next object - see diag_graph. */
	if (sc->diag_graph) {
		kof_diag_scan_free(sc->diag_graph);
		sc->diag_graph = NULL;
	}
	if (sc->relocs) {
		kof_elf_reloc_table_free(sc->relocs);
		free(sc->relocs);
		sc->relocs = NULL;
	}
	kof_apihash_free(sc->apihash);
	sc->apihash = NULL;
	free(sc->gr);
	free(sc->live);
	free(sc->found);
	free(sc->mask_ok);
	sc->live = NULL;
	sc->found = NULL;
	sc->mask_ok = NULL;
	kof_scan_kids_reset(sc);
	free(sc->kids);
	free(sc->kid_packer);
	free(sc->kid_family);
	free(sc->kid_derived_by);
	free(sc->kid_want);
	free(sc->kid_want_level);
	free(sc->kid_n_xw);
	free(sc->kid_xw);
	/*
	 * KOF_TARGET_COUNT AND NOT KOF_FMT_COUNT.
	 *
	 * The array is the width of the target axis, and event verbs are
	 * numbered in the same space as the file formats - so a loop bounded by
	 * formats freed the file-format views and leaked every event one. It
	 * was one allocation per scanner for AMSI and is now two; the bound
	 * that sizes the array is the bound that must empty it.
	 */
	for (i = 0; i < KOF_TARGET_COUNT; i++)
		free(sc->view[i]);
	free(sc->inf);
	free(sc->lzw);
	free(sc->bz);
	free(sc->lzx);
	kof_plague_ctx_done(&sc->plague);
	free(sc->lzh);
	kof_xref_free(sc->use);
	free(sc->sym);
	free(sc->pend_syms);
	free(sc->pend_sec);
	free(sc->pend_imp);
	free(sc->emu_rep_p);
	free(sc->imp_pool);
	free(sc->sym_ext[0]);
	free(sc->sym_ext[1]);
	free(sc);
}

const struct kof_stats *kof_scan_stats(const struct kof_scanner *sc)
{
	return &sc->st;
}

/* ---- the byte accessors handed to a module --------------------------------- */

/*
 * Turn a named range into extents.
 *
 * Here rather than in objctx.c because only the parse knows where a region is, and this
 * is the file that ran it. KOF_SCAN_ALL needs no parse at all, which is what lets a
 * module naming only that region run against input nothing identified.
 */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				struct kof_range *ext)
{
	uint32_t n;

	if (scan_mask & KOF_SCAN_ALL) {
		ext[0].off = 0;
		ext[0].len = ctx->obj_size;
		return ctx->obj_size ? 1u : 0u;
	}
	if (!ctx->resolve_scan)
		return 0;
	n = ctx->resolve_scan(ctx, scan_mask, ext, KOF_SCAN_MAX_EXTENTS);
	if (n >= KOF_SCAN_MAX_EXTENTS) {
		/*
		 * The region did not fit, so what follows searches part of it.
		 *
		 * Said rather than swallowed. A buffer that filled exactly is
		 * indistinguishable from one that filled and had more to write, and
		 * the two lead to the same place: a search over some of a region,
		 * reported as a search over the region. That is the one answer this
		 * engine must never give quietly, so it is a limit like any other -
		 * the caller set the size, and the caller can be told it bound.
		 */
		struct kof_scanner *sc = kof_scan_of(ctx);

		if (!sc->broken)
			sc->broken = KOF_BROKEN_LIMIT;
		n = KOF_SCAN_MAX_EXTENTS;
	}
	return n;
}

/* ---- deriving per-object facts --------------------------------------------- */



/*
 * Can this module be ruled out without calling it?
 *
 * Every test reads a field of the module's record against a fact already produced.
 * None touches the blob, which is what makes this a pre-use filter rather than the
 * same conditions written inside the module - those are correct and save nothing,
 * because reaching them costs the call.
 *
 * Absent constraints mean unconstrained, so a module with an empty record runs. The
 * default has to fall that way: over-running costs time, under-running costs
 * detections and would not show up as a failure anywhere.
 */


/* ---- the multi-pattern prepass ----------------------------------------------------- */

/*
 * Answer every marker of every worthwhile region, before any module runs.
 *
 * WHY THIS IS A SEPARATE PASS AND NOT PART OF THE MODULE LOOP
 *
 * Because the saving is shared. A region's markers are asked about by many
 * modules, and the lazy path reads the region once for each of them; read once
 * for all of them, the cost stops growing with the database. Doing it inside
 * the loop would mean the first module to name a region paid for every other
 * module's markers, which is the same total but attributed to whoever happened
 * to be first - and it would have to happen before that module's own logic
 * ran, which is this function.
 *
 * It writes nothing but memo cells, so it is invisible: a cell means "is this
 * marker in this region mask of this object" and has one answer whoever fills
 * it. kof_match_lookup reads the cell before it does anything else, so a
 * module's calls turn into table reads without knowing it. See find_str in
 * kofmod/kofsig.h, which reserved exactly this.
 *
 * THE PRECONDITIONS ARE EVALUATED TWICE, ON PURPOSE
 *
 * Once here to count what is live, once in the loop below to decide what runs.
 * They are integer comparisons against a record already in cache, and the
 * alternative - a survivor list built here and consumed there - is a second
 * representation of the same decision that could disagree with the first.
 */




/* ---- naming a finding ------------------------------------------------------ */

/*
 * <target>/<what the author wrote>
 *
 *     ELF-x64/Botnet:Mirai-04gix              (KOF_MALVAR_AUTO)
 *     PE-x86/Hacktool:Meterpreter-Generic     (KOF_MALVAR_GENERIC)
 *     Zip/Exploit:ZipSlip-CVE-2018-1002200    (a custom variant)
 *
 * The target is composed and not authored: it is what the engine established by
 * parsing, so a module cannot claim a format it was not run against or an
 * architecture the object does not have. Everything after the "/" is authored -
 * a type from enum kof_maltype, a family, a variant - which is the part that
 * needs a person, and the "/" marks exactly that boundary: computed fact on the
 * left, human classification on the right.
 *
 * Three different separators past the "/", one per boundary, each chosen not to
 * collide with what a variant already tends to contain: KOF_MALVAR_AUTO's own
 * output and hand written variants like "CVE-2018-1002200" both use "-"
 * internally, so "-" is spent on exactly one boundary (family/variant) and nowhere
 * else, or "Mirai-CVE-2018-1002200" would read as a run of hyphens with no visible
 * structure. ":" separates type from family, matching how a reader already parses
 * "Category: Item" elsewhere; "." is avoided entirely here for the same collision
 * reason "-" is only used once.
 *
 * Format and architecture are one token joined by a dash rather than two parts.
 * They answer one question - what does this run on - and splitting them made every
 * name carry a separator that never told anyone anything.
 *
 * The operating system is absent on purpose. ELF does not say it, so "Linux" would
 * be a guess wearing the clothes of a fact, which is also why this reads "ELF-x64"
 * and not the "Linux/x64" other engines write.
 *
 * An object with no architecture - a script, or one nothing identified - gets the
 * format alone. A "-any" suffix would be a field describing nothing.
 */










/* ---- sx_identify -------------------------------------------------------------- */

/*
 * The format table.
 *
 * Each collector answers two questions separately: does this object look like
 * mine, and - once a buffer exists - what does it say. The split is what lets the
 * view be allocated only for formats actually met, and it is why sniff takes no
 * buffer.
 *
 * Order is priority. It matters as soon as two formats can claim one object, and
 * writing it down here is cheaper than discovering it is implied by the order of
 * two if statements somewhere.
 */

/*
 * Decide what the object is and fill the matching view.
 *
 * Nothing is allocated for a format the sniff rejected, and a view once allocated
 * is kept: a directory of ELF binaries allocates one view for the whole walk, and
 * a scanner that never meets a PE never allocates a PE view.
 *
 * An allocation failure leaves the object unidentified rather than failing the
 * scan. That is the same answer an unrecognised format gets, and it is the right
 * one: the object still gets scanned by every module whose target covers unknown.
 */


/* ---- the routine ---------------------------------------------------------- */

/*
 * Run the unpackers, once the detectors have had their say.
 *
 * After, not before, and that ordering is a decision rather than a convenience. An
 * archive whose entry names carry "../" is an exploit against whatever will open
 * it, and it has already been named by the time this runs - so unless the caller
 * asked for everything, there is nothing to gain from opening it and a budget to
 * lose. The same policy that already decides whether to keep running detectors
 * decides whether to open the container.
 */



/*
 * The preconditions an unpacker gets, the same a detector does minus the region
 * test an unpacker has no use for. Its own function because the two passes below
 * both apply it, and a check that lived in one loop and not the other would let
 * the family pass run a module the general pass would have ruled out.
 */
const struct kof_module *sx_kof_scan_derived_by(const struct kof_scanner *sc)
{
	return sc ? sc->cur_derived_by : NULL;
}



/*
 * WHAT A MODULE OFFERED TO PUT BACK, out to the caller.
 *
 * The detector loop does this inline after calling a module's kof_cure(); an
 * UNPACK module has no kof_cure() to call, because the facts a Sality repair
 * needs - the host bytes the virus saved, and where its body begins - exist
 * only while the interpreter that decrypted them is alive, and that is during
 * kof_unpack and nowhere else. So an unpack module describes the repair where
 * it can see it, and this takes the description.
 *
 * NOTHING IS WRITTEN HERE EITHER. Same contract as the detector's: the host
 * bounds-checked every patch when the module asked for it, the file is still
 * reported infected, and whether any of it is applied is the caller's.
 *
 * ONCE, for the first module that described one - see the same rule in the
 * detector loop. Two modules repairing one object are two modules disagreeing
 * about what it is.
 */
void sx_take_repair(struct kof_scanner *sc, struct kof_result *res)
{
	uint32_t q;

	if (!res || !sc->cure_have)
		return;
	if (res->repair.n_fix || res->repair.truncate)
		return;
	for (q = 0; q < sc->n_cure_fix && q < KOF_MAX_FIX; q++) {
		res->repair.fix[q].off = sc->cure_fix[q].off;
		res->repair.fix[q].n = sc->cure_fix[q].n;
		memcpy(res->repair.fix[q].b, sc->cure_fix[q].b,
		       sc->cure_fix[q].n);
	}
	res->repair.n_fix = q;
	res->repair.truncate = sc->cure_trunc_set ? sc->cure_trunc : 0u;
}

/*
 * A MODULE'S REPORT, TAKEN - the one place a finding is made from one.
 *
 * Four loops run modules (detectors, heuristics, and the two unpack passes) and
 * each wrote this out by hand: append a finding if there is room and count it
 * if there is not, name it, offer it for the verdict slot, take the repair and
 * the infected spans the module described, and clear the report. They had
 * drifted - the detector loop copied the repair inline and only on the cure
 * path, the unpack loops through take_repair, the heuristic loop not at all - so
 * a change to "what a report becomes" was a change in four places and a
 * review of which of them it had missed.
 *
 * `level` is the finding's, passed rather than read from the report because a
 * heuristic rule's finding is a HEUR whatever level the rule's own report named.
 * Returns the finding, or NULL when the result was full and it was only counted.
 */
struct kof_finding *sx_mod_report(struct kof_scanner *sc,
				  const struct kof_obj_ctx *ctx,
				  const struct kof_scan_option *opt,
				  struct kof_result *res,
				  const struct kof_module *m, uint32_t level)
{
	struct kof_finding *f = NULL;

	if (res->n < KOF_MAX_FINDINGS) {
		f = &res->v[res->n++];
		f->level = level;
		sx_finding_str(sc, ctx, m, f);
		/* The subject's one verdict - see kof_scanner.verdict. Every
		 * site that makes a finding offers it; a site that forgets makes
		 * a finding nothing reports, which is what the detector loop once
		 * did to every signature detection. */
		f->is_verdict = (uint8_t)sx_verdict_take(sc, f, opt->all_matches);
	} else {
		res->dropped++;
	}
	sx_take_repair(sc, res);
	sx_take_infected(sc, res);
	sc->rep_valid = 0;
	return f;
}

/*
 * ---- WHAT BELONGS TO ONE MODULE'S TURN, cleared before every module --------
 *
 * What a module reported, what it asked of the plague and pattern sets, whether
 * it read the graph, what repair it offered. These were cleared in two of the
 * four loops that run modules - detectors and heuristics - and not in the two
 * unpackers' loops, whose reports go through the same sx_finding_str that reads
 * them: an unpacker's finding could be labelled by the previous module's
 * Pathogen read or carry its similarity block. One function, called by all four,
 * so a new loop cannot forget one.
 */
void sx_mod_begin(struct kof_scanner *sc, const struct kof_module *m)
{
	sc->rep_valid = 0;
	sc->rep_reason = 0;
	/* Nothing asked yet - see scan.h. */
	sc->plague_asked = -1;
	sc->n_plague_blk = 0;
	sc->plague_hit = 0;
	sc->plague_tot = 0;
	sc->plague_best = 0;
	sc->str_hit = 0;
	sc->diag_read = 0;
	sc->cure_have = 0;
	sc->cure_at = 0;
	sc->cur_mod = m;
	sc->emu_run_by = NULL;
	/* A sink the previous module left open is not this one's. */
	kof_scan_sink_discard(sc);
}

/*
 * AND WHERE THE INFECTION IS, out to the caller - see `struct kof_infected`.
 *
 * SEPARATE FROM sx_take_repair, because the two are different statements and a
 * module may make either without the other: a rule that can locate a family's
 * body but not put the host back marks the body and offers no repair, and that
 * is a useful thing to be able to say.
 */
void sx_take_infected(struct kof_scanner *sc, struct kof_result *res)
{
	uint32_t q;

	if (!res || !sc->n_infect || res->n_infected)
		return;
	for (q = 0; q < sc->n_infect && q < KOF_MAX_INFECTED; q++)
		res->infected[q] = sc->infect[q];
	res->n_infected = q;
}



















/*
 * ---- THE START OF AN OBJECT: EVERYTHING THAT IS ABOUT ONE OBJECT ------------
 *
 * ONE FUNCTION, called once, first, for every object that enters sx_scan_object -
 * and the only place per-object state is cleared. It was cleared at seven
 * places in two functions, and the second of them, sx_unpack_object, is not reached
 * by an object that already has a finding of its own unless all_matches is on.
 * So a decoded child with its own verdict went on carrying its parent's
 * `superseded` (its report was dropped as "a wrapper"), `opened_by` and
 * `packer_build` (its result named its parent's packer), `packed_here` and
 * `emu_produced` (a heuristic read them), and `broken` (sx_script_forms refused
 * to fold it because a sibling had hit a limit). Reset where the object BEGINS
 * and none of that depends on which steps the object happens to reach.
 *
 * WHAT IS NOT HERE, on purpose:
 *   - what belongs to ONE MODULE's turn: sx_mod_begin.
 *   - what is declared for the NEXT child (the pend_* set): pend_clear, which is
 *     spent by the child it was written for and not by the object.
 *   - the verdict slot, which is per SUBJECT - see scan_tree.
 *   - `budget`, which is per tree and never reset: the bomb defence.
 */
static void obj_begin(struct kof_scanner *sc)
{
	/* Computed-once results: one array, one clear - see enum kof_obj_latch. */
	memset(sc->latch, 0, sizeof sc->latch);
	/* ...and what those latches guarded. Freed and not kept the way `sym` is:
	 * `sym` has a fixed cap and is reused, these are sized by what a sweep
	 * found, and reusing them would mean carrying the largest met so far. */
	kof_xref_free(sc->use);
	sc->use = NULL;
	if (sc->relocs) {
		kof_elf_reloc_table_free(sc->relocs);
		free(sc->relocs);
		sc->relocs = NULL;
	}
	kof_apihash_free(sc->apihash);
	sc->apihash = NULL;
	/* The graph of the object that has just finished: held until here so
	 * anything reporting on it could still read it. */
	if (sc->diag_graph) {
		kof_diag_scan_free(sc->diag_graph);
		sc->diag_graph = NULL;
	}
	sc->gr_n = 0;                   /* the serialised copy of that graph */
	sc->use_cut = 0;
	sc->emu_full = 0;               /* only the PE branch of a run sets it */

	/* The pathogen demand. See KOF_ENG_USE_PATHOGEN: there is no state to set,
	 * so one object's ask cannot become the next object's. */
	sc->diag_ask = 0;
	memset(sc->diag_hit, 0, sizeof sc->diag_hit);

	/* The symbol block is rebuilt on first use. */
	sc->sym_served = 0;
	sc->sym_n = 0;
	sc->msym_bound = 0;
	sc->sym_ext_done[0] = sc->sym_ext_done[1] = 0;

	/* What a module asked of the interpreter. `emu_slice` has one writer and
	 * used to have no reader that cleared it, so the first module to ask ran
	 * every later object in slices as well. [Read off the code, not measured
	 * on a sample: the only shipped module that sets it is the Sality one.] */
	sc->emu_slice = 0;

	/* What was found, and what was claimed: the sentinel and not zero, because
	 * zero is entry 0. And no finding of the last object's is protected from
	 * this one's drop - the bits are slot numbers in a result about to be
	 * refilled. */
	sc->pend_entry = KOF_ENTRY_NONE;
	sc->heur_keep = 0;

	/* How this object came to exist and whether it is only a wrapper: which
	 * module opened the LAST one says nothing about this one. */
	sc->opened_by[0] = 0;
	sc->packer_build[0] = 0;
	sc->pend_build[0] = 0;
	sc->pend_build_of = NULL;
	sc->mod_tag[0] = 0;
	sc->mod_tag_of = NULL;
	sc->packed_here = 0;
	sc->emu_produced = 0;
	sc->emu_ran = 0;
	sc->emu_stance = KOF_EMU_STANCE_BANNED;
	sc->emu_run_by = NULL;
	sc->superseded = 0;

	/* A fresh attempt for every object. Hitting a limit while unpacking one
	 * container does not mean the tree is finished: the room it held is back
	 * by the time the next is scanned. Only `budget` is cumulative. */
	sc->broken = 0;
	sc->stop = 0;

	/* What a repair or an infection note refers to. */
	sc->cure_have = 0;
	sc->cure_at = 0;
	sc->n_cure_fix = 0;
	sc->cure_trunc_set = 0;
	sc->n_infect = 0;
	sc->ovl_asked = -1;
	sc->ovl_pct = 0;
}

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
 * WHAT THE FIRST ROW IS HIDING, WHICH IS THE POINT OF THE first/last FIELDS.
 *
 * One runner covers four steps, because today a module cannot ask for anything
 * finer: every module in bases/unp/ declares KOF_UNPACK_KIND(KOF_UNP_PACKER) -
 * the packers, the AES decryptor, the five msf decoders and the payload carver,
 * all the same word - and sx_unpack_object walks them in database order. So the
 * row says UNWRAP..CARVE and means it: those four are not ordered with respect
 * to each other yet. When a module starts declaring its real step, this row
 * splits into rows and the loop above it does not change.
 *
 * The last row is the host's own and has no modules: NORMZ is sx_norm_emit.
 */
struct analyze_arg {
	struct kof_scanner              *sc;
	struct kof_obj_ctx              *ctx;
	const struct kof_scan_option    *opt;
	struct kof_result               *out;
	kof_buf                          buf;
	uint32_t                         pdepth;
	uint32_t                         want;
	const char                      *predict;
	/*
	 * HOW MANY OF out->v A DETECTOR PUT THERE, counted before the
	 * heuristics ran.
	 *
	 * Not out->n, and the difference is the whole reason this field exists.
	 * By the time this struct is filled the rule heuristics have appended
	 * their own findings, and a rule heuristic is not a verdict that the
	 * object has been identified - it is usually the opposite, "I could not
	 * sx_identify this", which is exactly the object whose remaining steps
	 * matter most. Stopping on one measured six samples where the parent
	 * said Heur:Truncated and the payload one layer down said Botnet:Mirai:
	 * the chain would have ended on the weaker of the two statements and
	 * deleted the stronger.
	 *
	 * Whether a heuristic MAY stop the chain is a question for the rule
	 * that wrote it rather than for the engine - see enum kof_eng_want,
	 * which has no word for it yet. Until it does, only a detector counts.
	 */
	uint32_t                         det_n;
	/* A rule said its finding is a conclusion - see KOF_ENG_CONCLUDE.
	 * Kept apart from det_n because the two are different claims and the
	 * note on det_n is a measurement about detectors only. */
	int                              concluded;
};

static void step_open(struct analyze_arg *a)
{
	a->out->broken = sx_unpack_object(a->sc, a->ctx, a->opt, a->out,
				       a->pdepth, a->want, a->predict);
}

static void step_normz(struct analyze_arg *a)
{
	sx_norm_emit(a->sc, a->ctx, a->buf);
}

static const struct analyze_step {
	enum kof_analyze  first;	/* the steps this runner serves, */
	enum kof_analyze  last;		/* inclusive - see above	 */
	void            (*run)(struct analyze_arg *);
} analyze_steps[] = {
	{ KOF_ANALYZE_UNWRAP, KOF_ANALYZE_CARVE, step_open  },
	{ KOF_ANALYZE_NORMZ,  KOF_ANALYZE_NORMZ, step_normz }
};

static void analyze_object(struct analyze_arg *a)
{
	uint32_t i;

	for (i = 0; i < sizeof analyze_steps / sizeof analyze_steps[0]; i++) {
		uint32_t kids0 = a->sc->n_kids;
		uint32_t carved0 = a->sc->n_carved;

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
		if (a->det_n && !a->opt->all_matches)
			return;
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
		if (a->concluded && !a->opt->all_matches)
			return;

		analyze_steps[i].run(a);
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
		if (a->sc->n_kids - kids0 != a->sc->n_carved - carved0)
			return;
		/*
		 * And between steps, because a step is the unit of work that
		 * is worth interrupting: unpacking a large object is where the
		 * time goes, and a cancel asked for during it should not then
		 * pay for a normalisation nobody is waiting for.
		 */
		if (a->opt->should_stop && a->opt->should_stop(a->opt->stop_user))
			return;

	}
}


void sx_scan_object(struct kof_scanner *sc, kof_buf buf,
			const struct kof_scan_option *opt, struct kof_result *out,
			uint32_t pdepth, int from_packer,
			const char *inherit_predict, uint8_t as_fmt)
{
	struct kof_obj_ctx ctx;
	uint32_t present, want, det_n;
	const char *predict = NULL;

	out->from_packer = (uint8_t)(from_packer != 0);
	memset(&ctx, 0, sizeof ctx);
	kof_mod_attach(&ctx, sc);
	obj_begin(sc);

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
	ctx.obj_size = buf.n;

	kof_match_begin(&sc->m, buf);

	/*
	 * THE CHILD'S OWN DECLARATION FIRST, then the caller's.
	 *
	 * opt->as_format is about the object the CALLER handed in - a submitted
	 * event record, which has no magic for a sniff to find. as_fmt is what
	 * the thing that produced THIS child said about it, and for a child the
	 * second is the specific claim: the caller's applies to the root of the
	 * walk and would otherwise be re-applied to every object under it.
	 */
	sx_identify(sc, buf, &ctx,
		 as_fmt ? as_fmt : (opt ? opt->as_format : 0u),
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
		ctx.subtype = sc->cur_subtype;
		ctx.subfamily = sc->cur_subfam;
		/* And out to the caller, which has the same problem the engine
		 * had: reading the bytes gives the wrong answer. */
		out->subtype = sc->cur_subtype;
		out->subfamily = sc->cur_subfam;
		out->lang_known = 1;
	}
	/* And the one fact about it that three later steps would each have
	 * worked out for themselves - see sx_lib_facts. */
	sx_lib_facts(sc, &ctx, buf);

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

		ctx.resolve_scan = sx_declared_resolve_scan;
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

		present = sx_regions_present(&ctx, resolve);
		present |= sx_sym_halves_present(&ctx, resolve);
	}
	sc->st.objects++;
	sc->st.object_bytes += buf.n;

	/*
	 * NOT HERE ANY MORE - the first module that declares a marker asks for
	 * it, and one that ends the object without declaring any never does.
	 * See kof_scanner.multi_ready for why, and sx_need_multi for how.
	 */
	sc->cur_present  = present;
	sc->cur_from_packer = (uint8_t)(from_packer != 0);

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

		if (e->mod_by_target && ctx.format < KOF_TARGET_COUNT) {
			ix = e->mod_by_target;
			lo = e->mod_at[ctx.format];
			hi = e->mod_at[ctx.format + 1u];
			sc->st.considered += e->n_mods - (hi - lo);
			sc->st.by_target  += e->n_mods - (hi - lo);
		}

	for (k = lo; k < hi; k++) {
		const struct kof_module *m = &e->mods[ix ? ix[k] : k];

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

		if (!sx_prefilter(m, &ctx, present, &sc->st, out))
			continue;

		/* What this module declared it reads, produced now that a
		 * module needing it has actually survived the sx_prefilter. */
		if (m->n_str)
			sx_need_multi(sc, &ctx);
		if (m->n_block)
			sx_need_plague(sc, &ctx);

		sx_mod_begin(sc, m);
		m->fn(&ctx);

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
			m->cure(&ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;

		/* Accumulate. Keeping only the last would drop a finding whenever two
		 * families match one object, and the cap is counted rather than
		 * silently applied. */
		(void)sx_mod_report(sc, &ctx, opt, out, m, sc->rep_level);

		/*
		 * Stop unless the caller asked for everything. The remaining modules
		 * can only lengthen a list that already says the object is not clean,
		 * and on a database of any size that is most of the work.
		 *
		 * It saves nothing on a clean object, which is nearly every object -
		 * this is a bound on the worst case, not a throughput win.
		 */
		if (!opt->all_matches)
			break;
	}
	}

	/*
	 * WHAT THE DETECTORS ALONE FOUND, taken here because this is the last
	 * moment at which it is still true: sx_heur_run appends below, and once it
	 * has, nothing downstream can tell a rule's guess from a detection. See
	 * analyze_arg.det_n for what reads it and why the distinction matters.
	 */
	det_n = out->n;

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->m.n_calls;
	sc->st.bytes_searched += sc->m.n_bytes_scanned;
	sc->st.gram_bytes     += sc->m.n_bytes_indexed;

	/*
	 * EXAMINE: what the object IS, asked before it is opened.
	 *
	 * Here and not earlier so a rule knows whether a family was named, and
	 * here and not later because this is the last moment at which what it
	 * asks for can still change what happens to the object.
	 */
	want = sx_heur_run(sc, &ctx, opt, out, KOF_HEUR_EXAMINE, present, &predict);
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
	sc->diag_ask |= (want & KOF_ENG_USE_PATHOGEN) != 0;
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
	if (kof_scan_diag_sign_asks(&ctx)) {
		sc->diag_ask = 1;
		want |= KOF_ENG_USE_EMU;
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
	if (!predict)
		predict = inherit_predict;

	{
		struct analyze_arg a;

		a.sc = sc; a.ctx = &ctx; a.opt = opt; a.out = out;
		a.buf = buf; a.pdepth = pdepth; a.want = want;
		a.predict = predict;
		a.det_n = det_n;
		a.concluded = (want & (uint32_t)KOF_ENG_CONCLUDE) ? 1 : 0;
		analyze_object(&a);
	}
	/*
	 * After, so a script that was packed is normalised as the source it
	 * turned out to be rather than as the wrapper - the unpacked child
	 * reaches this same step with its own parse behind it. The flag follows
	 * sx_unpack_object's rule: "not fully examined" is only worth saying about
	 * an object something actually tried to open.
	 */
	if (sx_script_forms(sc, &ctx, opt, pdepth) && sc->broken)
		out->broken = sc->broken;

	/*
	 * WHAT THE ENGINE COMPLETED IS DECLARED ON THE OBJECT, so the result
	 * carries it like any producer's - see kof_result.syms. A tool then shows
	 * what the engine returned for a stager's symbols instead of reading the
	 * file's table itself and printing a different answer.
	 */
	{
		uint32_t ns = 0;
		const uint8_t *sb = kof_scan_served_syms(&ctx, &ns);

		if (sb && sc->cur_src)
			kof_src_declare_syms(sc->cur_src, sb, ns);
	}

	/* VERDICT: how it was reached, which only exists once it has been. */
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
		kof_scan_diag_force(&ctx);

	(void)sx_heur_run(sc, &ctx, opt, out, KOF_HEUR_VERDICT, present, NULL);

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
	if (sc->n_kids > sc->n_views + sc->n_carved && out->n > 0) {
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
		sx_heur_object(sc, &ctx, opt, pdepth,
			    out->broken == KOF_BROKEN_DAMAGED, out);

}






/*
 * Scan one object and everything it turns out to contain.
 *
 * Iterative, with its own stack, for the same reason the directory walk is: the
 * depth of an object tree is chosen by whoever built the file, and putting it on
 * the C stack makes the failure mode a crash inside a library. It also keeps
 * exactly one parsed view of each format in use at a time - a child parsed while
 * its parent's view was still live would overwrite it, since there is one view per
 * format per scanner.
 *
 * A child holds a reference to whatever its bytes live in, so the parent's mapping
 * survives exactly as long as something still points into it and no longer.
 */
















