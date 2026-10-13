/*
 * scan.h - scan one object.
 *
 * This is the leaf of the scan tree and the only place a module is ever entered. It
 * takes bytes, never a path: producing bytes - from a file now, from a descriptor,
 * memory or a decompressor later - belongs to whatever calls this.
 *
 * All mutable state lives in kof_scanner, one per thread, and the engine it points
 * at is immutable. That split is what makes the expensive parts affordable: the
 * presence table is 32MB, so it is allocated once per thread and reused for every
 * object, not per file and not per module.
 *
 * Types: scan_types.h. State: scan_state.h (struct kof_scanner). Functions: here.
 *
 * THE UNIT MAP. A `kof_scan_<word>_` function is declared here and defined by the
 * unit that owns the word, so a name says where to look and one prefix covers
 * every unit (a decision, not drift: a prefix per file would be nine prefixes for
 * one header):
 *
 *   kof_scan_new, _free, _stats, _resolve_range   scan.c        the scanner and its regions
 *   kof_scan_walk                                 scan_walk.c   the tree walk
 *   kof_scan_walk_mt                              scan_mt.c     the walk over threads
 *   kof_scan_budget, _kids_reset, _sink_discard   objctx_child.c  budgets and children
 *   kof_scan_emu_*                                objctx_emu.c  the interpreter's runs
 *   kof_scan_diag_*, _incomplete, _served_syms    objctx_diag.c the diagnose product
 *   kof_scan_script_forms                         objctx_script.c script forms
 *   kof_scan_mutation_*                           scan_feed.c   feeding similarity
 *   kof_scan_syndrome                             scan_verdict.c  the verdict's diseases
 *
 * kof_scan_of is an inline of this header. A new function takes the word of the
 * unit that defines it and is added to this map.
 */

#ifndef KOFENG_SCAN_H
#define KOFENG_SCAN_H

#include "scan_types.h"
#include "scan_state.h"

/* Give a top level object its budget. Children inherit what is left. */
void kof_scan_budget(struct kof_scanner *, uint64_t obj_size,
		     const struct kof_scan_option *);

/* Release anything a module left half-produced, and hand back what it finished. */
void kof_scan_kids_reset(struct kof_scanner *);
void kof_scan_sink_discard(struct kof_scanner *);



/*
 * THE CHAIN BUILDERS STOOD HERE - one on the scanner and one for a caller
 * that had an object and no scan, so the viewer and the engine read an object
 * the same way. They are gone with the chain. What is kept from them is the
 * rule that made them one function: a second copy is what kofviewer had, and
 * it answered for two architectures while the engine read ten.
 *
 * AND THAT AN EMPTY ANSWER NEEDS A REASON. The builder returned one line
 * saying which gate it stopped at - the architecture, the bytes, the
 * regions, the partition - because a page that just says nothing tells a
 * reader nothing. Before that the reasons went to stderr behind an
 * environment variable, which is worse than nothing and is also rule 1.
 */


struct kof_scanner *kof_scan_new(const struct kof_engine *);
void                 kof_scan_free(struct kof_scanner *);

const struct kof_stats *kof_scan_stats(const struct kof_scanner *);

/*
 * Present an object to a module: fills in every field a module can reach.
 *
 * Defined in objctx.c, which is the whole untrusted boundary - every entry bounds
 * checks, and nothing else in the tree lets module code near memory.
 */
void kof_mod_attach(struct kof_obj_ctx *, struct kof_scanner *);

/* Swap the producing surface in for the length of one unpacker, and out again. */
void kof_mod_unpack_mode(struct kof_obj_ctx *, int on);

/*
 * THE LAST RESORT: run the object and keep what it writes.
 *
 * Entered when every module that could have opened this object has run and none
 * of them did, and the gate in emu_unpack.h says the object either hides its
 * code behind something dense or cannot be loaded as written. `force` skips the
 * gate, for a caller who has asked for this object specifically rather than
 * scanned a tree.
 * Lives here rather than in scan.c because producing a child is this file's
 * business - the same ceilings, the same sink, the same accounting.
 *
 * Returns non-zero if it ATTEMPTED the object - which is not the same as
 * having produced anything from it. The difference is what lets a refusal be
 * reported: "the entry point is not in this file" is a fact about the object,
 * and an object nobody tried to open must not carry it, while an object that
 * was tried and could not be opened must.
 */
/*
 * Run the interpreter and GATHER. Answers how many regions it left; it creates
 * nothing - see the note on kof_scanner.emu_live.
 */
uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force);
/* The machine and its regions let go - called when the receiver returns. */
void     kof_scan_emu_release(struct kof_scanner *sc);

/*
 * The script in the form a signature should be written on, handed over as ONE
 * child: how it was typed taken out of it, and with `deep` what it builds out
 * of its own literals built first. Answers the child's length, or 0 when there
 * was nothing worth a child. See the note over the definition.
 */
uint32_t kof_scan_script_forms(const struct kof_obj_ctx *ctx, int deep);


/* Turn a named range into extents. objctx.c needs it; the parse is what knows. */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *, uint32_t scan_mask,
				struct kof_range *ext);

/*
 * Credit an object's units to a mutation context - the ONE feed, for the scanner
 * and for any tool that scores blocks against an object, so the number a tool
 * shows is the one the scanner computes. `present` is the region bits the parse
 * has (all bits for a caller that has not asked); `funcs` and `lib` are the
 * parse's, or NULL for an object whose headers do not describe its own bytes -
 * see kgenome_mutation_units. `ext` is scratch for one region's extents.
 */
struct kof_mutation_ctx;
struct kgenome_func_set;
struct kgenome_true_all;
/* One unit of `region`, as kgenome_mutation_units cuts it; non-zero stops the walk. */
typedef int (*kof_scan_unit_fn)(void *user, uint32_t region, uint64_t off,
				uint64_t len, uint32_t side,
				const struct kgenome_func *first);
void kof_scan_mutation_units(const struct kof_obj_ctx *ctx, kof_buf b,
			   uint32_t present, const struct kgenome_func_set *funcs,
			   const struct kgenome_true_all *lib, struct kof_range *ext,
			   kof_scan_unit_fn fn, void *user);
void kof_scan_mutation_feed(struct kof_mutation_ctx *pc, const struct kof_obj_ctx *ctx,
			  kof_buf b, uint32_t present, int from_packer,
			  const struct kgenome_func_set *funcs,
			  const struct kgenome_true_all *lib, struct kof_range *ext);

/*
 * Recover the scanner from a context handed to a module.
 *
 * INLINE, BECAUSE EVERY ACCESSOR A MODULE CALLS BEGINS WITH IT. A signature
 * module reads the object a byte at a time through the content vtable, and the
 * lookup was a call in front of each of those: MEASURED, one module's whole-file
 * scan made 5.63 M c_rd8 calls and the call into kof_scan_of plus the one into
 * oc_mc were about 10 of the 24 instructions each cost.
 */
static inline struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *ctx)
{
	return (struct kof_scanner *)(void *)(uintptr_t)ctx->priv;
}

/*
 * Scan whatever a path names. Returns the number of objects scanned or a KOF_ERR_*.
 * The facade in kofeng.c is the only intended caller.
 */
/* The scan of a buffer: what kscan_bytes (kofeng.c) answers. */
int kof_scan_bytes(struct kof_scanner *sc, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *opt,
		   kof_on_object cb, void *user);

int kof_scan_walk(struct kof_scanner *, const char *path,
		  const struct kof_scan_option *, kof_on_object cb, void *user);

/*
 * The same walk, spread over several scanners.
 *
 * One thread finds the files and the rest scan them, which is the split the
 * shape of the work already had: enumerating a directory is a syscall per entry
 * and scanning a file is a pass over its bytes, and only the second one is worth
 * a core. Measured over 12.9GB, a scan is 71% memmem and 100% of one core, so
 * the ceiling on a single thread is the one core it uses.
 *
 * The caller supplies the scanners because making one is the caller's job in
 * this API and always has been - the engine is immutable and shared, the
 * scanner is per thread. Handing in an array rather than a count keeps it that
 * way: nothing here allocates a scanner, and a caller that wants different
 * budgets per worker can set them.
 *
 * The callback is serialised, so a caller writes it exactly as it would for the
 * single threaded walk. What is NOT preserved is the ORDER objects arrive in:
 * files come back as the workers finish them. A caller that needs the old order
 * passes one scanner.
 */
int kof_scan_walk_mt(struct kof_scanner **, unsigned n_sc, const char *path,
		     const struct kof_scan_option *, kof_on_object cb, void *user);

/*
 * A LOADED DIAGNOSE DECLARED SIGNS THIS OBJECT CARRIES - see KOF_DIAG_HAS_ATTRB
 * and the head and tails a diagnose declares. Non-zero means the analysis is worth starting on this
 * object, which is the routing a heuristic rule used to do by hand.
 */
int kof_scan_diag_sign_asks(const struct kof_obj_ctx *ctx);
/*
 * Could this object's analysis not say everything it was asked: a diagnose that
 * ran returned 'cannot say' (a limit was reached on its scan), or the symbol
 * block was cut. 1 means the diseases of the object may be incomplete.
 */
int kof_scan_incomplete(const struct kof_obj_ctx *ctx);
/*
 * THE STATUS OF THE OBJECT'S DIAGNOSE SCAN, read back from the lib: KGENOME_OK
 * when it ran whole or never ran, else the worst limit any routine of it reached -
 * the instruction budget, a node store, the memory allowance the engine passed
 * (kgenome_budget.max_bytes, the ledger). The detail behind kof_scan_incomplete,
 * for a tool that says WHICH limit.
 */
enum kgenome_status kof_scan_diag_status(const struct kof_obj_ctx *ctx);
/* Free the object's diagnose graph and give back the bytes it was charged to this
 * scanner's memory ceiling - the one place the graph dies. */
void kof_scan_diag_drop(struct kof_scanner *sc);
/* The symbol block the engine completed for this object, or NULL when it added
 * nothing - see kof_result.syms. */
const uint8_t *kof_scan_served_syms(const struct kof_obj_ctx *ctx, uint32_t *n);

void kof_scan_diag_force(const struct kof_obj_ctx *);

/*
 * WHAT EACH LOADED DIAGNOSE MAKES OF THIS OBJECT, for a tool that reports.
 *
 * ONE STATE PER DIAGNOSE, in the order the checks run - the first that fails is
 * the reason, so a state also says how far the diagnose got:
 *
 *   SHAPE     the file is not the kind this diagnose is about (its conditions)
 *   NO_ROUTE  the analysis it is written for is not one this file offers
 *   SIGNS     the file lacks an import or a symbol reference the diagnose needs
 *   SEEN      the file carries the signs and the analysis ran, but the nodes
 *             did not form the diagnose's tree
 *   MATCH     the tree was found; `at` says where each node is
 *
 * SEEN is the interesting one for a person writing a rule: the file looks like
 * what the diagnose describes and it still did not match.
 *
 * ASKING RUNS THE ANALYSIS for all of them, read by a verdict or not, once per
 * object. The cost is the scan's own - a normal scan skips a diagnose no verdict
 * reads, and this is the one caller that must not.
 *
 * The types are in kofeng.h: a caller receives them in kof_result.diag.
 */
uint32_t kof_scan_diag_count(const struct kof_obj_ctx *ctx);
/* 1 and `out` filled, or 0 for an index past the end or an object with nothing
 * to analyse. */
int kof_scan_diag_report(const struct kof_obj_ctx *ctx, uint32_t i,
			 struct kof_diag_report *out);

/*
 * THE TYPE AN OBJECT'S DISEASES MAKE, inferred from every disease its detectors,
 * heuristics and diagnoses found (see databases/pack/kofsyndrome.h). Returns 0
 * when no disease was found, or the database has no syndrome pack. The same
 * all-diagnoses analysis as kof_scan_diag_report, so asking costs what that costs
 * and a normal scan pays nothing: what the detectors and heuristics found is
 * always there, the diagnoses' are added only when the object was scanned for all
 * of them (kof_scan_option.report_diag). The list of disease ids it is made of is
 * scan_verdict.c's own.
 */
int kof_scan_syndrome(const struct kof_obj_ctx *ctx, struct kof_synd_result *r);

#endif /* KOFENG_SCAN_H */
