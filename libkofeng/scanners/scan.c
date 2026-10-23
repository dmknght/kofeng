/*
 * scan.c - one object through the pipeline: the core every stage unit hangs from.
 *
 * What is here: the scanner's lifecycle, the per-object and per-module resets
 * (sx_obj_begin, mod_begin), the shared end of one module's turn (sx_mod_end: the
 * marks it left), and sx_scan_object, which runs the stages in order. The stages
 * themselves are units of their own:
 *
 *   scan_facts.c    what is true of an object before a module looks (format, regions)
 *   scan_feed.c     the work shared by modules, done once per object (mutation, multi)
 *   scan_heur.c     the model score
 *   scan_unpack.c   the OPEN stage: unpack modules and the interpreter's stance
 *   scan_norm*.c    the NORMALISE stage: the view of an object with noise removed
 *   scan_verdict.c  the diseases an object has and its verdict
 *   verdictor/verdict.c  how a verdict is spelled
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
 * (group_yielded), the interpreter's permission is one enum (kof_emu_stance), and
 * the parallel walk's leaks and its producer race are gone, and a file cut short is
 * never cached as clean (tests/unit/scan_logic.c).
 *
 * OPEN, found by reading and not yet changed:
 *   - detectors are not placed in the table by a declaration: every detector
 *     runs at DETECT. Placing one between opening steps, under a condition,
 *     needs two fields in the pack's module record, which is a format decision
 *     and not this file's to take.
 *   - the scanner still carries `cur_present` and `cur_from_packer` for the
 *     lazily built feeds beside the same facts in kof_pipeline; they are set once,
 *     by FACTS, and read by sx_need_mutation, which is not given the pipeline.
 *   - the scanner's per-module reset (sx_mod_begin) still clears its scalars by
 *     hand, on purpose: three of the fields are arrays whose bytes need no clearing
 *     and a wipe would be paid for by every module of every object. The
 *     per-object reset (sx_obj_begin) is one wipe of sc->obj - see scan_state.h.
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
#include "objctx_int.h"
#include "../detectors/pattern/kofpix.h"
#include "../detectors/linkage/kofdiag.h"
#include "../kofcore/kofplatform.h"
#include <stdlib.h>
#include <string.h>

static void sym_decl_free(struct kof_scanner *sc);

/*
 * WHAT A SCANNER COSTS BEFORE IT SCANS ANYTHING, reserved from the engine's budget when it is
 * made: its struct, the parsed views of the formats it may meet (2.7 MB), the decompressor
 * states (bzip2 3.7 MB, LZX 2.1 MB, the rest 0.2 MB), the symbol and declaration buffers, and
 * the table the database sizes per thread (the memo, a bounded cache) and the pattern sweep's context. A
 * round 12 MiB for the first group, measured as the resident cost of a scanner after trim
 * plus every state it can grow; the database-sized tables are added exactly. The per-thread
 * similarity counters of the block matcher are NOT in it (they belong to the index builder's
 * accounting, see kofbudget.h). The names quota (KOF_SCAN_NAMES, scan_types.h, 1 MiB) is inside it,
 * not on top: the parts that are measured come to 8.9 MB (the struct 0.24 MB including the 64 KiB
 * pending-name buffer, the views 2.7, the decompressor states 6.0), so the round figure has the
 * room, and adding it would move every cap-floor test (tests/unit/endian_view.c runs at
 * KOF_ENGINE_MEM_MIN and loses its view to 2 MiB).
 */
#define KOF_SCAN_FIXED (12ull << 20)

uint64_t kof_scan_fixed(const struct kof_engine *eng)
{
	/*
	 * NOTHING HERE FOLLOWS THE NUMBER OF MARKERS. The memo is a cache of at most KOF_MEMO_CELLS_MAX
	 * cells (it was two bytes for every marker and mask: 48 MB at eight million), and the pattern
	 * sweep's context is a fixed set of buffers (it was a word for every marker: 32 MB, cleared
	 * for every object). What the sweep finds beyond its starting table is charged to the object.
	 */
	return KOF_SCAN_FIXED + kof_match_memo_bytes(eng->memo_size) +
	       (eng->pix_regions ? kofpix_ctx_fixed(eng->pix_set) : 0u);
}

struct kof_scanner *kof_scan_make(const struct kof_engine *eng, int *why)
{
	struct kof_scanner *sc;
	uint64_t fixed = kof_scan_fixed(eng);

	if (why)
		*why = KSCAN_NEW_NOMEM;
	if (eng->budget && !kof_budget_charge(eng->budget, fixed)) {
		if (why)
			*why = KSCAN_NEW_BUDGET;
		return NULL;            /* the engine cannot afford another scanner */
	}
	if (eng->budget)
		atomic_fetch_add(&eng->budget->holders, 1u);
	sc = calloc(1, sizeof *sc);
	if (!sc) {
		if (eng->budget) {
			kof_budget_release(eng->budget, fixed);
			atomic_fetch_sub(&eng->budget->holders, 1u);
		}
		return NULL;
	}
	sc->root_fixed = eng->budget ? fixed : 0;
	sc->eng = eng;
	sc->sink.fd = -1;   /* 0 is stdin; calloc would have made this a live fd */

	/* The matcher owns the search state: the presence set and the memo are how a
	 * search is answered, not how a scan is bookkept. */
	if (!kof_match_state_init(&sc->match.m, eng->n_str, eng->memo_size))
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
	sc->match.msym.gram_bits = 20;
	sc->match.msym.gram_min = 2;
	if (!kof_match_state_init(&sc->match.msym, eng->n_str, 0))
		goto fail;

	/*
	 * The similarity counters, when the database brought any blocks.
	 *
	 * Skipped entirely when it did not, which is the common case: no
	 * allocation, and the feed below is never reached because the set is
	 * NULL. A database with no mutation rules costs nothing here.
	 */
	if (eng->mutation && !kof_mutation_ctx_init(&sc->mutation, eng->mutation))
		goto fail;

	/* One counter per region, and one word per marker for where it was seen.
	 * A failure here is not fatal: the prepass needs both and simply does
	 * not run without them. */
	/*
	 * The per-diagnose state, sized by the database and not by a constant:
	 * three bitmaps (matched, gate open, could not say) in one block, the
	 * bound nodes, and the head sequences. One allocation per scanner.
	 */
	sc->diag.cap = eng->n_diag;
	sc->diag.bm = (eng->n_diag + 7u) / 8u;
	{
		size_t n = eng->n_diag ? eng->n_diag : 1u;

		sc->diag.hit = calloc(3u * (sc->diag.bm ? sc->diag.bm : 1u), 1u);
		sc->diag.bind = calloc(n, sizeof *sc->diag.bind);
		sc->diag.n_bind = calloc(n, 1u);
		sc->diag.seq = calloc(n, sizeof *sc->diag.seq);
		if (!sc->diag.hit || !sc->diag.bind || !sc->diag.n_bind ||
		    !sc->diag.seq)
			goto fail;
		sc->diag.gate = sc->diag.hit + (sc->diag.bm ? sc->diag.bm : 1u);
		sc->diag.unk = sc->diag.gate + (sc->diag.bm ? sc->diag.bm : 1u);
	}
	sc->match.live = calloc(KOF_MULTIMATCH_BITS, sizeof *sc->match.live);
	if (eng->pix_regions) {
		sc->match.mask_ok = calloc(eng->n_masks ? eng->n_masks : 1u,
				     sizeof *sc->match.mask_ok);
		sc->match.pix_ready = kofpix_ctx_init(&sc->match.pix, eng->pix_set, 0);
		if (sc->match.pix_ready && !sc->match.mask_ok) {
			kofpix_ctx_free(&sc->match.pix);
			sc->match.pix_ready = 0;
		}
	}
	if (why)
		*why = KSCAN_NEW_OK;
	return sc;

fail:
	kof_scan_free(sc);
	return NULL;
}

struct kof_scanner *kof_scan_new(const struct kof_engine *eng)
{
	return kof_scan_make(eng, NULL);
}

void kof_scan_free(struct kof_scanner *sc)
{
	uint32_t i;

	if (!sc)
		return;
	if (sc->eng->budget && sc->root_fixed) {
		kof_budget_release(sc->eng->budget, sc->root_fixed + sc->root_held);
		atomic_fetch_sub(&sc->eng->budget->holders, 1u);
	}
	kof_match_state_free(&sc->match.m);
	kof_match_state_free(&sc->match.msym);
	kof_prod_unadopt(sc);
	/* The last object's graph, which the per-object reset never reached
	 * because there was no next object - see diag_graph. */
	kof_scan_diag_drop(sc);
	kof_scan_text_drop(sc);
	if (sc->obj.diag.relocs) {
		kgenome_elf_reloc_table_free(sc->obj.diag.relocs);
		free(sc->obj.diag.relocs);
		sc->obj.diag.relocs = NULL;
	}
	kgenome_diag_apihash_free(sc->obj.diag.apihash);
	sc->obj.diag.apihash = NULL;
	kgenome_pe_imptab_free(&sc->obj.diag.pe_imp);
	free(sc->diag.rep);
	free(sc->diag.hit);             /* and diag_gate and diag_unk, one block */
	free(sc->diag.bind);
	free(sc->diag.n_bind);
	free(sc->diag.seq);
	free(sc->diag.gr);
	free(sc->match.live);
	if (sc->match.pix_ready)
		kofpix_ctx_free(&sc->match.pix);
	sc->match.pix_ready = 0;
	free(sc->match.mask_ok);
	sc->match.live = NULL;
	sc->match.mask_ok = NULL;
	kof_scan_kids_reset(sc);
	free(sc->child.list);
	free(sc->child.packer);
	free(sc->child.family);
	free(sc->child.derived_by);
	free(sc->child.want);
	free(sc->child.want_level);
	free(sc->child.n_xw);
	free(sc->child.xw);
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
		free(sc->cache.view[i]);
	free(sc->cache.inf);
	free(sc->cache.lzw);
	free(sc->cache.bz);
	free(sc->cache.lzx);
	kof_mutation_ctx_done(&sc->mutation);
	free(sc->cache.lzh);
	kgenome_xref_free(sc->obj.diag.use);
	sym_decl_free(sc);
	free(sc->syms.decl);
	free(sc->syms.buf);
	kgenome_funcs_free(&sc->obj.sym.funcs);
	kgenome_diag_walk_free(sc->obj.diag.walk);
	free(sc->pend.syms);
	free(sc->pend.desc_buf);
	kgenome_funcs_free(&sc->pend.funcs);
	free(sc->pend.fixed);
	free(sc->pend.rgn);
	free(sc->pend.sec);
	free(sc->pend.imp);
	free(sc->emu.rep_p);
	free(sc->pend.imp_pool);
	free(sc->syms.ext[0]);
	free(sc->syms.ext[1]);
	free(sc);
}

/*
 * WHAT A SCANNER KEEPS BETWEEN OBJECTS, GIVEN BACK ON REQUEST (kscan_trim).
 *
 * A scanner is one per thread and lives as long as its host: the parsed view of
 * every format it has met, the decompressor states, the presence table the
 * matcher grew for the largest object, the symbol block and the last object's
 * analysis all stay allocated so the next object does not pay to make them again.
 * For a daemon that is the high-water mark of the worst object it ever saw (71 MB
 * steady against a 4.8 MB median object, measured over 700 scans), and the
 * allocator keeps the freed part too - hence the two flags: CACHES drops what the
 * scanner holds, HEAP asks the C library to give its free pages back.
 *
 * Between scans only: while any scan is running on this scanner (a callback
 * included) nothing is touched. Idempotent, and everything dropped is made again on
 * demand, so the findings of the next scan are the ones it would have had.
 */
void kof_scan_trim(struct kof_scanner *sc, unsigned flags)
{
	uint32_t i;
	int did = 0;

	if (!sc || sc->busy)
		return;
	if (!flags)
		flags = KOF_TRIM_CACHES | KOF_TRIM_HEAP;
	if (flags & KOF_TRIM_CACHES) {
		/* The last object's products (the graph, the decode trace, the symbol
		 * state) stay until the next object begins; this is that beginning. */
		kof_scan_emu_release(sc);
		kof_scan_kids_reset(sc);
		sx_obj_begin(sc);
		/* The similarity matcher's state, and what the ledger was charged for it. */
		did |= sc->mutation.held != 0;
		oc_scan_release(sc, sc->mutation.ledgered);
		sc->mutation.ledgered = 0;
		oc_scan_release(sc, sc->match.pix_ledgered);
		sc->match.pix_ledgered = 0;
		kof_mutation_trim(&sc->mutation);
		for (i = 0; i < KOF_TARGET_COUNT; i++) {
			did |= sc->cache.view[i] != NULL;
			free(sc->cache.view[i]);
			sc->cache.view[i] = NULL;
		}
		did |= sc->cache.inf || sc->cache.lzw || sc->cache.bz || sc->cache.lzx ||
		       sc->cache.lzh || sc->match.m.gram || sc->syms.buf || sc->pend.syms ||
		       sc->pend.fixed || sc->pend.rgn;
		free(sc->cache.inf);
		free(sc->cache.lzw);
		free(sc->cache.bz);
		free(sc->cache.lzx);
		free(sc->cache.lzh);
		sc->cache.inf = NULL;
		sc->cache.lzw = NULL;
		sc->cache.bz = NULL;
		sc->cache.lzx = NULL;
		sc->cache.lzh = NULL;
		kof_match_state_trim(&sc->match.m);
		kof_match_state_trim(&sc->match.msym);
		free(sc->syms.buf);
		sc->syms.buf = NULL;
		sc->syms.cap = 0;
		free(sc->syms.ext[0]);
		free(sc->syms.ext[1]);
		sc->syms.ext[0] = sc->syms.ext[1] = NULL;
		free(sc->pend.syms);
		sc->pend.syms = NULL;
		sc->pend.syms_cap = 0;
		free(sc->pend.fixed);
		sc->pend.fixed = NULL;
		sc->pend.fixed_cap = 0;
		free(sc->pend.rgn);
		sc->pend.rgn = NULL;
		sc->pend.rgn_cap = 0;
		free(sc->pend.desc_buf);
		sc->pend.desc_buf = NULL;
		sc->pend.desc_cap = 0;
		free(sc->emu.rep_p);
		sc->emu.rep_p = NULL;
	}
	if ((flags & KOF_TRIM_HEAP) && kof_heap_trim())
		did = 1;
	if (did)
		sc->st.scan_trims++;
}

const struct kof_stats *kof_scan_stats(const struct kof_scanner *sc)
{
	return &sc->st;
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
const struct kof_module *sx_derived_by(const struct kof_scanner *sc)
{
	return sc ? sc->cur.derived_by : NULL;
}



/*
 * ---- WHAT BELONGS TO ONE MODULE'S TURN, cleared before every module --------
 *
 * What a module marked as infected and which module is running. One function,
 * called by every loop that runs modules, so a new loop cannot forget one.
 */
void sx_mod_begin(struct kof_scanner *sc, const struct kof_module *m)
{
	/*
	 * WHAT THIS MODULE DESCRIBES, and only it: the infected spans were cleared once
	 * per OBJECT, so the second module to mark something appended its spans after
	 * the first's.
	 */
	sc->mod.n_infect = 0;
	sc->mod.cur = m;
	sc->obj.emu.run_by = NULL;
	/* A sink the previous module left open is not this one's. */
	kof_scan_sink_discard(sc);
}

/*
 * WHERE A MODULE SAID THE INFECTION IS, out to the caller - see `struct kof_infected`.
 * The end of every module's turn (a detector's, an unpacker's), taken once: the
 * first module's spans go out and a later one cannot replace them.
 */
void sx_mod_end(struct kof_scanner *sc, struct kof_result *res)
{
	uint32_t q;

	if (!res || !sc->mod.n_infect)
		return;
	if (res->n_infected)
		return;
	for (q = 0; q < sc->mod.n_infect && q < KOF_MAX_INFECTED; q++)
		res->infected[q] = sc->mod.infect[q];
	res->n_infected = q;
}

/* The imports a module reported for the object that has just finished. */
static void sym_decl_free(struct kof_scanner *sc)
{
	uint32_t i;

	for (i = 0; i < sc->obj.sym.n_decl; i++) {
		free(sc->syms.decl[i].dll);
		free(sc->syms.decl[i].fn);
	}
	sc->obj.sym.n_decl = 0;
}

/*
 * ---- THE START OF AN OBJECT: EVERYTHING THAT IS ABOUT ONE OBJECT ------------
 *
 * ONE FUNCTION, called once, first, for every object that enters sx_scan_object -
 * and the only place per-object state is cleared. It was cleared at seven
 * places in two functions, and the second of them, the open stage, was not reached
 * by an object that already had a finding of its own.
 * So a decoded child with its own finding went on carrying its parent's
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
 *   - `budget`, which is per tree and never reset: the bomb defence.
 */
static const char *const prod_names[KOF_PROD_COUNT] = {
	"syms", "funcs", "walk", "relocs", "pe_imports", "apihash", "diag", "use"
};

const char *kof_prod_name(enum kof_prodkind p)
{
	return (unsigned)p < KOF_PROD_COUNT ? prod_names[p] : "?";
}

void kof_prod_ran(struct kof_scanner *sc, enum kof_prodkind p)
{
	if (sc->obj.prod_runs[p] != 255u)
		sc->obj.prod_runs[p]++;
	if (sc->obj.prod_runs[p] > 1u)
		sc->prod_repeat[p]++;
}

void kof_prod_again(struct kof_scanner *sc, enum kof_prodkind p)
{
	/* The count is the number of builds; a named repeat is one the table
	 * does not hold against the object. */
	if (sc->obj.prod_runs[p] != 255u)
		sc->obj.prod_runs[p]++;
}

void kof_prod_sync_walk(struct kof_scanner *sc)
{
	uint32_t r = kgenome_diag_walk_runs(sc->obj.diag.walk);

	while (sc->obj.prod_runs[KOF_PROD_WALK] < r && sc->obj.prod_runs[KOF_PROD_WALK] < 255u)
		kof_prod_ran(sc, KOF_PROD_WALK);
}

uint32_t kof_scan_prod_repeats(const struct kof_scanner *sc, enum kof_prodkind p)
{
	return sc && (unsigned)p < KOF_PROD_COUNT ? sc->prod_repeat[p] : 0;
}

void sx_obj_begin(struct kof_scanner *sc)
{
	/*
	 * RELEASE FIRST. Everything sc->obj owns that is not a plain value goes back
	 * here, and each release leaves its field NULL or empty; the wipe below then
	 * clears the rest, which is every scalar, flag and latch the struct holds.
	 */
	/* ...what the latches guarded. Freed and not kept the way `syms.buf` is:
	 * that has a fixed cap and is reused, these are sized by what a sweep
	 * found, and reusing them would mean carrying the largest met so far. */
	/* A rendering's analysis is the parent's: let go of it before the frees
	 * below, which are for what THIS scanner derived. */
	kof_prod_unadopt(sc);
	kgenome_xref_free(sc->obj.diag.use);
	if (sc->obj.diag.relocs) {
		kgenome_elf_reloc_table_free(sc->obj.diag.relocs);
		free(sc->obj.diag.relocs);
	}
	kgenome_diag_apihash_free(sc->obj.diag.apihash);
	kgenome_pe_imptab_free(&sc->obj.diag.pe_imp);
	/* The graph of the object that has just finished: held until here so
	 * anything reporting on it could still read it. */
	kof_scan_diag_drop(sc);
	kof_scan_text_drop(sc);
	sym_decl_free(sc);
	kgenome_funcs_free(&sc->obj.sym.funcs);
	kof_prod_sync_walk(sc);
	if (kgenome_diag_walk_capped(sc->obj.diag.walk))
		sc->st.trace_capped++;
	kgenome_diag_walk_free(sc->obj.diag.walk);

	/* The bitmaps are the scanner's, sized by the database and kept; only their
	 * bytes are the object's. The diagnose demand (obj.diag.ask, .all) is
	 * cleared by the wipe, and recomputed per object (oc_diag_demand): there is
	 * no state to set, so one object's ask cannot become the next object's. */
	memset(sc->diag.hit, 0, sc->diag.bm);
	memset(sc->diag.unk, 0, sc->diag.bm);

	/*
	 * THE WIPE: the latches (one array, see enum kof_obj_latch), the symbol
	 * block's state, the analysis products, the interpreter's stance and slice
	 * (`emu.slice` had one writer and no reader that cleared it, so the first
	 * module to ask ran every later object in slices as well - read off the
	 * code, not measured on a sample: the only shipped module that sets it is
	 * the Sality one), how the object came to exist and which module opened it,
	 * `superseded`, and the fresh attempt every object gets: a limit hit while
	 * unpacking one container does not mean the tree is finished, the room it
	 * held is back by the time the next is scanned. Only `ledger.budget` is
	 * cumulative. A field added to struct kof_scan_obj is reset here without
	 * being named.
	 */
	memset(&sc->obj, 0, sizeof sc->obj);
	/* The stance of an object nobody has spoken for (KOF_EMU_STANCE_BANNED is
	 * 0; written out because the wipe must not be what decides it). */
	sc->obj.emu.stance = KOF_EMU_STANCE_BANNED;

	/* What was claimed: the sentinel and not zero, because zero is entry 0. */
	sc->pend.entry = KOF_ENTRY_NONE;

	/* What an infection note refers to is cleared with the module's turn - see
	 * sx_mod_begin - and not here: a module describes its OWN. */
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
















