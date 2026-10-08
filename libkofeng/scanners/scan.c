/*
 * scan.c - one object through the pipeline: the core every stage unit hangs from.
 *
 * What is here: the scanner's lifecycle, the per-object and per-module resets
 * (sx_obj_begin, mod_begin), the shared turn of one module (sx_mod_report: report to
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
 * DONE in the rewrite (each verified against the three-mode corpus snapshot): the
 * stages are rows of one table (scan_pipeline.c), the opening steps are declared
 * by the modules (KOF_ANALYZE_STEP), "was the object opened" is one predicate
 * (group_yielded), the four copies of "report to finding" are sx_mod_report, the
 * interpreter's permission is one enum (kof_emu_stance), and the parallel walk's
 * leaks and its producer race are gone, the repair that goes out belongs to the
 * finding the object is reported under, the detector loop stops at an infection
 * and not at the first report, and a file cut short is never cached as clean (all
 * three by tests/unit/scan_logic.c).
 *
 * OPEN, found by reading and not yet changed:
 *   - detectors and rules are not placed in the table by a declaration: every
 *     detector runs at DETECT. Placing one between opening steps, under a
 *     condition, needs two fields in the pack's module record, which is a
 *     format decision and not this file's to take.
 *   - the scanner still carries `cur_present` and `cur_from_packer` for the
 *     lazily built feeds beside the same facts in kof_pipeline; they are set once,
 *     by FACTS, and read by sx_need_plague, which is not given the pipeline.
 *   - the per-object `sx_scan_object` reset (sx_obj_begin) still clears ~45 scanner
 *     fields by hand; the OPEN stage's kof_open is the pattern to follow.
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
void sx_take_repair(struct kof_scanner *sc, struct kof_result *res, int owner)
{
	uint32_t q;

	if (!res || !sc->cure_have)
		return;
	/*
	 * WHOSE REPAIR, when more than one module describes one.
	 *
	 * The object is reported under ONE finding - the verdict - and the repair
	 * that goes out has to be the repair for THAT: first-come meant the first
	 * detector in database order won whatever it had found, so an object
	 * reported as infected by one family came with the patches of another
	 * family's weaker guess (tests/unit/scan_logic.c). So the module whose
	 * finding owns the verdict replaces what an earlier, lesser one offered,
	 * and a module that does not own it only fills an empty place - an object
	 * whose verdict has no repair still gets the repair of a finding that has
	 * one, rather than none.
	 */
	if (!owner && (res->repair.n_fix || res->repair.truncate))
		return;
	res->repair.n_fix = 0;
	res->repair.truncate = 0;
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
	sx_take_repair(sc, res, f && f->is_verdict);
	sx_take_infected(sc, res, f && f->is_verdict);
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
	/*
	 * WHAT THIS MODULE DESCRIBES, and only it. The patches, the cut and the
	 * infected spans were cleared once per OBJECT, so the second module to
	 * describe a repair appended its patches after the first's: the repair of an
	 * object two detectors reported was the two of them, in database order,
	 * and neither was the one that matches the verdict
	 * (tests/unit/scan_logic.c).
	 */
	sc->cure_have = 0;
	sc->cure_at = 0;
	sc->n_cure_fix = 0;
	sc->cure_trunc_set = 0;
	sc->n_infect = 0;
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
void sx_take_infected(struct kof_scanner *sc, struct kof_result *res, int owner)
{
	uint32_t q;

	if (!res || !sc->n_infect)
		return;
	/* The same rule as the repair: the spans that go out are the verdict's. */
	if (!owner && res->n_infected)
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
void sx_obj_begin(struct kof_scanner *sc)
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

	/* What a repair or an infection note refers to is cleared with the module's
	 * turn - see sx_mod_begin - and not here: a module describes its OWN. */
	sc->ovl_asked = -1;
	sc->ovl_pct = 0;
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
















