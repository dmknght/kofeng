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
 */

#ifndef KOFENG_SCAN_H
#define KOFENG_SCAN_H

#include "../kofeng.h"
#include "../kofdb/kofdb.h"
#include "../kofmatchers/kofmatch.h"
#include "../kofparsers/binaries/elf_parse.h"
#include "../kofparsers/binaries/pe_parse.h"
#include "../kofunpack/pe_rebuild.h"
#include "../kofparsers/containers/gzip_parse.h"
#include "../kofparsers/containers/docole_parse.h"
#include "../kofparsers/containers/zip_parse.h"
#include "../kofparsers/containers/tar_parse.h"
#include "../kofparsers/containers/sevenzip_parse.h"
#include "../kofparsers/containers/rar_parse.h"
#include "../kofparsers/containers/xz_parse.h"
#include "../kofparsers/containers/rtf_parse.h"
#include "../kofparsers/containers/pdf_parse.h"
#include "objsrc.h"
#include "../kofdecomp/inflate.h"
#include "../kofdecomp/nrv2.h"
#include "../kofdecomp/lzma.h"

/*
 * Everything mutable, one per thread.
 *
 * The engine it points at is immutable and shared. Splitting them is what keeps the
 * 32MB presence table out of the per-file path: it belongs to the thread, is allocated
 * once, and is reused for every object.
 */
struct kof_scanner {
	const struct kof_engine *eng;

	struct kof_match_ctx m;
	/*
	 * One parsed view per format, allocated the first time an object of that
	 * format is seen and kept for the life of the scanner.
	 *
	 * Not all of them up front: a view is kilobytes, and a scanner on a Linux
	 * host never meets a PE, so allocating every format's view would make the
	 * cost of supporting a format something every scanner pays whether or not
	 * it ever meets one. Not per object either, which is what this was avoiding
	 * in the first place - that puts a malloc of kilobytes in the hot path for
	 * every file.
	 *
	 * Indexed by enum kof_format, so adding a format adds a table row and no
	 * field here.
	 */
	void *view[KOF_FMT_COUNT];

	/* Set while a module runs: find_str is called from inside one, and the ids it
	 * passes are module local, so the host has to know whose they are. */
	const struct kof_module *cur_mod;

	/*
	 * Where a region resolve puts its extents.
	 *
	 * Here rather than on the stack of whoever asks, because KOF_SCAN_MAX_EXTENTS
	 * is sized for an archive whose regions come apart into thousands of runs -
	 * and a buffer that size in every frame that resolves a region is a stack
	 * cost paid on every object to hold the worst archive anyone has seen.
	 *
	 * Two, not one, and they are never live at the same moment for the same
	 * reason: `ext` answers a search, `ext_gather` feeds a copy, and a module doing
	 * one is not doing the other. Kept apart anyway, because the day one calls the
	 * other the failure would be silent.
	 */
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	struct kof_range ext_gather[KOF_SCAN_MAX_EXTENTS];

	/* What the running module reported. A module cannot hold state, so a finding
	 * has to land here. */
	uint32_t rep_level, rep_name_id;
	int      rep_valid;

	/*
	 * PRODUCING CHILDREN
	 *
	 * Set only while an unpacker runs. `cur_src` is the object it is unpacking,
	 * which a window child has to reference so the parent's mapping outlives
	 * it; `kids` collects what it produced, and the caller drains that once the
	 * module has returned.
	 *
	 * Collected rather than scanned as they arrive: a child cannot be scanned
	 * while its parent's parsed view is live, because there is one view per
	 * format per scanner and the child's parse would overwrite the parent's.
	 * Draining afterwards keeps exactly one view of each format in use and
	 * keeps the object tree off the C stack.
	 */
	struct kof_objsrc  *cur_src;
	struct kof_objsrc **kids;
	/*
	 * Per child: was it produced by an EXECUTABLE PACKER rather than by a
	 * container. Parallel to `kids` because it is a property of the child's
	 * provenance and has to travel with it onto the work list, where the
	 * module that made it is long out of scope.
	 */
	uint8_t            *kid_packer;
	uint32_t            n_kids, cap_kids;

	/*
	 * Did a packer open THIS object.
	 *
	 * The fact belongs to the file that was packed, not to what came out of
	 * it - and that is the bug it exists to fix. "Packed" used to be derived
	 * from an object's depth, which credits it to the CHILD: the packed file
	 * itself, sitting at depth 0, was never scored for being packed, and the
	 * child that got the credit is by construction the clean-looking program
	 * the packer was hiding.
	 *
	 * Cleared per object in unpack_object, read by heur_object after it.
	 */
	int                 packed_here;

	/*
	 * Set while the emulator stage runs, and read where children are
	 * recorded. What that stage produces is a packer's payload by
	 * definition - it is memory a program wrote before running it - but no
	 * module made it, so the usual test on `cur_mod` would file it as a
	 * container entry and lose the distinction downstream.
	 */
	int                 emu_stage;

	/*
	 * What the next child produced should be called, already sanitised.
	 *
	 * Held here rather than passed to each producer because there are two ways to
	 * make a child and a module names them the same way whichever it uses. Cleared
	 * as it is consumed, and cleared when a module returns, so a name set for a
	 * child that never appeared cannot drift onto the following one.
	 */
	char pend_label[KOF_SRC_LABEL_MAX];
	/*
	 * How long it is, rather than where its first NUL is.
	 *
	 * A name is a range of the object and the object chooses its bytes, so a NUL
	 * inside one is the file's business and not a terminator. A compound file
	 * puts one after every character - its names are UTF-16 - and measuring with
	 * strlen turned "ThisDocument" into "T".
	 */
	uint32_t pend_label_len;

	/* The object being emitted, before it becomes a child. Heap while it is
	 * small, an unnamed temporary file once it is not - see objsrc.h. */
	uint8_t  *sink_mem;
	size_t    sink_len, sink_cap;
	int       sink_fd;
	uint64_t  sink_spilled;   /* bytes already written to sink_fd */

	/*
	 * What is left of the produced-bytes budget for this top level object, and
	 * whether it ran out. Charged across the whole tree, not per child.
	 */
	uint64_t budget;        /* total bytes this tree may still produce */
	uint32_t kids_left;

	/*
	 * Produced bytes alive right now: the object being emitted, plus every
	 * child that has been produced and not yet finished with. This is the
	 * number the 128MB ceiling is about, and the only one that bounds memory -
	 * `budget` bounds work over time and would allow any amount of it at once.
	 */
	uint64_t resident, resident_max;

	/*
	 * The most one produced object may hold. Past it the object is closed with
	 * what it has and the rest of that entry is dropped - see KOF_OBJ_CAP.
	 * Never above resident_max, or the cap could not be reached.
	 */
	uint64_t obj_cap;

	/*
	 * The DEFLATE decoder, allocated the first time one is needed.
	 *
	 * 32KB of sliding window, and it is per thread rather than per stream for
	 * the same reason the parsed views are: an archive of a thousand entries
	 * would otherwise be a thousand allocations of it, and a scanner that never
	 * meets a compressed file never pays for it at all. Nothing carries over
	 * between streams - kof_inflate resets every field, including zeroing the
	 * window, which is what keeps one entry's bytes out of the next.
	 */
	struct kof_inflate *inf;

	/*
	 * Where notes go, when anybody wants them.
	 *
	 * NULL in every scan that did not ask, which is every scan that is not
	 * somebody debugging a module - so the cost of a module leaving its notes
	 * in is one NULL test at the call.
	 */
	kof_on_debug debug_cb;
	void        *debug_user;

	/*
	 * Why this object was not finished, or zero. The FIRST reason recorded is
	 * kept: whatever stopped things first is what explains everything after it,
	 * and a budget running out because a decoder had already given up is not
	 * news about the budget.
	 */
	uint32_t broken;
	/*
	 * Production has stopped, which only a LIMIT causes.
	 *
	 * Separate from `broken` because the two answer different questions: broken
	 * is what the caller is told about this object, stop is whether there is any
	 * point continuing. Damage is worth reporting and worth carrying on from.
	 */
	uint32_t stop;

	struct kof_stats st;
};

/* Give a top level object its budget. Children inherit what is left. */
void kof_scan_budget(struct kof_scanner *, uint64_t obj_size,
		     const struct kof_scan_option *);

/* Release anything a module left half-produced, and hand back what it finished. */
void kof_scan_kids_reset(struct kof_scanner *);


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
uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force);

/*
 * WHOLE EXECUTABLES CARRIED INSIDE THIS OBJECT, offered as children.
 *
 * Not an unpacker: nothing is compressed and nothing is decoded. A dropper that
 * appends its payload, or lays one out per architecture inside its own code
 * segment, leaves a complete file sitting at an offset - and until it is handed
 * over as an object, no collector parses it and no signature can name it.
 *
 * Returns how many were produced. See embedded.h for why the header test is
 * strict and what it measured.
 */
uint32_t kof_scan_embedded(const struct kof_obj_ctx *ctx);

/* Turn a named range into extents. objctx.c needs it; the parse is what knows. */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *, uint32_t scan_mask,
				struct kof_range *ext);

/* Recover the scanner from a context handed to a module. */
struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *);

/*
 * Scan whatever a path names. Returns the number of objects scanned or a KOF_ERR_*.
 * The facade in kofeng.c is the only intended caller.
 */
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

#endif /* KOFENG_SCAN_H */