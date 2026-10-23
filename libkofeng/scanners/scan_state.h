/*
 * scan_state.h - struct kof_scanner, the mutable state of one scan thread.
 *
 * It was one struct of 193 fields in one header. It is now a handful of
 * sub-structs, each named for the LIFETIME or the STAGE that owns what is in it,
 * and each documented with who writes and reads it (scan_state_life.h,
 * scan_state_child.h, scan_state_stage.h):
 *
 *   sc->obj      wiped for every object by sx_obj_begin - the one reset
 *   sc->mod      wiped for every module's turn by sx_mod_begin
 *   sc->cur      the object in hand (set by the walk and FACTS)
 *   sc->pend     what a producer declared for its next child (oc_pend_clear)
 *   sc->child    the children collected, drained by the walk
 *   sc->emu      what an interpreter run left behind
 *   sc->sink     what a module emitted and has not closed
 *   sc->ledger   the budget of the tree - cumulative, never per object
 *   sc->cache    parsed views and decompressor states, kept for the scanner
 *   sc->match    the matchers' state, one set per thread
 *   sc->syms     the symbol block's allocations
 *   sc->diag     the diagnose pools
 *
 * `mutation` (the similarity counters) is the one field that stays at the top
 * level although it belongs in sc->match: kofexamine's inspector reads
 * sc->mutation directly, and kofexamine is not edited by this change. It moves
 * into sc->match with that tool's upgrade.
 *
 * The rule for a new field: ask which of those lifetimes it has, and put it
 * there. If it has none, it is a new stage and gets a struct of its own, with
 * the same header comment.
 */

#ifndef KOFENG_SCAN_STATE_H
#define KOFENG_SCAN_STATE_H

#include "scan_types.h"
#include "scan_state_life.h"
#include "scan_state_child.h"
#include "scan_state_stage.h"

/*
 * Everything mutable, one per thread.
 *
 * The engine it points at is immutable and shared. Splitting them is what keeps the
 * 32MB presence table out of the per-file path: it belongs to the thread, is allocated
 * once, and is reused for every object.
 */
struct kof_src_read_io;   /* objsrc.h */

struct kof_scanner {
	const struct kof_engine *eng;
	/*
	 * The similarity counters, one set per thread.
	 *
	 * Beside the pattern matcher's state and for the same reason: the index
	 * they count against belongs to the engine and is shared, and only the
	 * counting is per object. Empty when no loaded block exists, which is
	 * what keeps a build with no mutation rules from allocating anything.
	 */
	struct kof_mutation_ctx mutation;
	/*
	 * Where notes go, when anybody wants them.
	 *
	 * NULL in every scan that did not ask, which is every scan that is not
	 * somebody debugging a module - so the cost of a module leaving its notes
	 * in is one NULL test at the call.
	 */
	kof_on_debug debug_cb;
	void *debug_user;
	struct kof_stats st;
	/*
	 * Scans running on this scanner (nested ones count: a callback may scan), so that a
	 * trim asked for from inside one is refused instead of freeing what the scan is
	 * standing on. And how many scanners share the resident allowance of the parallel
	 * walk this scanner is a worker of - 1 outside it; see kof_scan_budget.
	 */
	unsigned busy;
	unsigned share;
	/* The host's scratch directory for spills (kof_scan_option.scratch_dir), for the scan in
	 * progress; NULL is the platform's. Borrowed. */
	const char *scratch;
	/* The seam a file is read through (objsrc.h): NULL is read(2); a test's table otherwise
	 * (kof_scan_read_hook). Borrowed. */
	const struct kof_src_read_io *read_io;
	/* What this scanner holds of the engine's budget (kofcore/kofbudget.h): its fixed cost for
	 * as long as it lives, and its share while an object is being scanned. */
	uint64_t root_fixed, root_held;
	/* What the root file in hand holds of the budget (kof_src_charged), for as long as it is
	 * scanned: the share of the object is cut from what is left after it. */
	uint64_t file_held;

	/* Products made more than once for one object, per product, over the scanner's
	 * life - see enum kof_prodkind. Not per object: a test reads it after the scan. */
	uint32_t prod_repeat[KOF_PROD_COUNT];
	struct kof_scan_obj obj;   /* per object: wiped by sx_obj_begin */
	struct kof_scan_mod mod;   /* per module: wiped by sx_mod_begin */
	struct kof_scan_cur cur;   /* the object in hand */
	struct kof_scan_pend pend;   /* declared for the next child */
	struct kof_scan_child child;   /* children collected, drained by the walk */
	struct kof_scan_emu emu;   /* what an interpreter run left behind */
	struct kof_scan_sink sink;   /* what a module emitted and has not closed */
	struct kof_scan_spill spill; /* where a big produced object goes: see objctx_spill.c */
	struct kof_scan_ledger ledger;   /* the budget ledger: per tree, never per object */
	struct kof_scan_cache cache;   /* views and decompressor states, kept for the scanner */
	struct kof_scan_match match;   /* the matchers' state */
	struct kof_scan_syms syms;   /* the symbol block's allocations */
	struct kof_scan_diag diag;   /* the diagnose pools */
};

#endif
