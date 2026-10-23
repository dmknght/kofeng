/*
 * scan_state_stage.h - the scanner's state that belongs to one stage or lives for the whole scanner: ledger, cache, match, syms, diag.
 *
 * Part of struct kof_scanner (scan_state.h); include scan.h, not this file.
 */

#ifndef KOFENG_SCAN_STATE_STAGE_H
#define KOFENG_SCAN_STATE_STAGE_H

#include "scan_types.h"
#include "../detectors/pattern/kofpix.h"

/*
 * sc->ledger: struct kof_scan_ledger
 *
 * THE BUDGET LEDGER: what the tree may still produce. Cumulative over a tree
 * and reset only where a new top-level object is given its budget
 * (kof_scan_budget), never per object - this is the bomb defence.
 *
 * Owner: objctx_child.c (charge, release, budget), scan_norm.c (charges a
 * rendering), objctx_diag.c (reads the ceiling for the lib). Files that touch
 * it: objctx_child.c, scan_norm.c, tests/unit/diag_ledger_e2e.c,
 * objctx_decomp_buf.c, objctx_int.h, objctx_emu.c, objctx_script.c,
 * tests/unit/child_fuzz.c.
 */
struct kof_scan_ledger {
	const char *res_why;
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
	 * HOW MANY INTERPRETER RUNS THIS TREE MAY STILL SPEND - KOF_SCAN_EMU_MAX,
	 * given again to every top-level object with the rest of its budget. It was
	 * counted in kof_stats.heur_emu, which never resets, so a scanner that had
	 * interpreted 512 objects in its LIFETIME refused every later ask with no word
	 * - a watcher scanning for a month stopped interpreting on the first day. A
	 * tree is the unit that can be a bomb (an archive of a million members that all
	 * ask), and that is what this bounds.
	 */
	uint32_t emu_left;
	/*
	 * THE INSTRUCTIONS THIS TREE MAY STILL EXECUTE, and how many more runs are
	 * protected from running out of them. `emu_left` above counts RUNS and bounds the
	 * number of objects that ask; this bounds the CPU they may spend, which a run count
	 * cannot (one run of a spin loop is the whole of its per-object limit, and a tree
	 * of 512 of them was 85 s). Sized from the ROOT alone at kof_scan_budget
	 * (oc_emu_tree_insn), consumed by every emulator of the tree (oc_emu_charge), and
	 * every run's own limit is the smaller of its per-object limit and what is left
	 * here (objctx_emu.c, objctx_diag.c). `emu_floor_left` is how many of the tree's
	 * first runs still get their floor when nothing is left: the root's and the first
	 * children's, so a packed file that is the whole tree is never denied its unpack.
	 */
	uint64_t emu_insn_left;
	uint32_t emu_floor_left;
	/*
	 * THE BYTES THIS TREE MAY STILL OFFER AS WINDOWS. A window is a child that is a view of
	 * its parent's bytes: it costs no produced byte, no memory and no budget, but it is
	 * SCANNED, so many windows aimed at one blob multiply the work with nothing charged.
	 * What a legitimate tree offers is each object's bytes about once, so the sum cannot
	 * pass the root plus everything the tree may produce - which is the number the
	 * produced-bytes budget already is (see kof_scan_budget). Past it oc_window refuses and
	 * the tree says Limit: a bomb of windows is bounded by the same figure as a bomb of
	 * decoded bytes, and no archive that lists an entry twice is refused for it. This was
	 * "twice the archive's length", in zip.c alone, and refused a zip that listed every
	 * member three times.
	 */
	uint64_t window_left;
	/*
	 * NAMES HELD NOW, AND THE QUOTA (KOF_SCAN_NAMES) - see there. Reset with the rest of
	 * the ledger by kof_scan_budget; charged by oc_names_take, given back by oc_names_give.
	 */
	uint64_t names, names_max;
};

/*
 * sc->cache: struct kof_scan_cache
 *
 * CROSS-OBJECT CACHES: one parsed view per target and the decompressor states,
 * allocated the first time they are needed and kept for the life of the
 * scanner, plus the two scratch extent tables.
 *
 * Owner: scan_facts.c (views), objctx_decomp*.c (decompressor states),
 * scan_feed.c / objctx_child.c / objctx_script.c (extent scratch). Files that
 * touch it: objctx_decomp.c, objctx_decomp_folder.c, scan_facts.c, scan.c,
 * objctx_decomp_entry.c, scan_feed.c, objctx.c, objctx_child.c,
 * objctx_script.c, scan_ext.c.
 */
struct kof_scan_cache {
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
	/*
	 * Indexed by TARGET VALUE, not by file-format count. Event targets are
	 * numbered above the file formats - KOF_EVT_AMSI is 19 - so a table
	 * sized by KOF_FMT_COUNT would be written past by the first event
	 * scanned.
	 */
	void *view[KOF_TARGET_COUNT];
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
	/*
	 * The arrays are the FLOOR of those buffers and the storage a caller that asks for a
	 * fixed KOF_SCAN_MAX_EXTENTS (the presence probe, which only asks whether there is
	 * one) uses as it always did. The buffers that grow past them are `ext_buf` and
	 * `gather_buf`, reached through kof_scan_ext_buf and given back by sx_ext_release -
	 * see scan_ext.c. The pieces of an ENTRY (kof_scan_resolve_entry) go into
	 * `gather_buf` the same way, and are never cut silently.
	 */
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	struct kof_range ext_gather[KOF_SCAN_MAX_EXTENTS];
	struct kof_ext_buf ext_buf, gather_buf;
	/*
	 * What the tables of the parsed views hold (zip, pdf: see struct kof_view_ops), as the
	 * ledger was charged for it. Charged when the parse ends and given back when the
	 * object does (sx_views_release), which is why it is here and not in sc->obj: it is
	 * released by the scan that charged it, not wiped by the next one.
	 */
	uint64_t view_held;
	/*
	 * The DEFLATE decoder, allocated the first time one is needed.
	 *
	 * 32KB of sliding window, and it is per thread rather than per stream for
	 * the same reason the parsed views are: an archive of a thousand entries
	 * would otherwise be a thousand allocations of it, and a scanner that never
	 * meets a compressed file never pays for it at all. Nothing carries over
	 * between streams - kuncoat_inflate resets every field, including zeroing the
	 * window, which is what keeps one entry's bytes out of the next.
	 */
	struct kuncoat_inflate *inf;
	/* 20KB of dictionary, allocated on the first LZW stream and reused for
	 * the rest - the same treatment `inf` gets, and for the same reason:
	 * most scans never meet one. */
	struct kuncoat_lzw *lzw;
	/*
	 * And 3.7MB for bzip2, on the same terms - allocated when the first
	 * stream needs it and never per stream.
	 *
	 * It is two orders of magnitude larger than the other two, and that is
	 * the format rather than a choice: the last stage is a permutation of a
	 * whole block, so the block and a link per byte have to exist at once
	 * before any of it can be produced. A scan that never meets a .bz2 pays
	 * nothing, which is what makes the size affordable.
	 */
	struct kuncoat_bunzip *bz;
	/*
	 * And 2.1MB for LZX, on the same terms.
	 *
	 * The size is the window: the format allows 2MB of it, a help file is
	 * free to say so, and the window has to exist before the first match
	 * can be copied out of it. Sizing it to the stream is not open either -
	 * the width comes from the container, so a scanner would be
	 * reallocating whenever a cabinet and a help file disagreed.
	 */
	struct kuncoat_lzx *lzx;
	/*
	 * And 90KB for LHA's and ARJ's coding, on the same terms: a dictionary
	 * wide enough for the largest variant, plus its three decoding tables.
	 */
	struct kuncoat_lzhuf *lzh;
};

/*
 * sc->match: struct kof_scan_match
 *
 * THE MATCHERS' STATE, one set per thread, allocated in kof_scan_new: the file
 * matcher and its memo, the symbol block's own matcher, the similarity
 * counters, and the multi-pattern sweep's scratch. The index they count
 * against belongs to the engine.
 *
 * Owner: scan_pipeline.c, scan_feed.c, objctx.c (the module-facing finders).
 * Files that touch it: scan.c, scan_feed.c, objctx.c, objctx_diag.c,
 * scan_pipeline.c, objctx_int.h, objctx_emu.c.
 */
struct kof_scan_match {
	struct kof_match_ctx m;
	/*
	 * A SECOND MATCHER, BOUND TO THAT BLOCK.
	 *
	 * `m` is bound to the object's bytes, and the block is not in the
	 * object - so a search scoped to KOF_SCAN_SYM_IMP has a different
	 * buffer to run over and cannot borrow it. Everything else is the same
	 * machinery, which is the point: the extents of one half of the block
	 * are a kof_range list like any other, so the matcher answers them the
	 * way it answers a region.
	 *
	 * Initialised with NO presence table and NO memo. Both exist to make a
	 * database-sized number of searches over a file-sized buffer
	 * affordable, and this buffer is at most a quarter megabyte and usually
	 * a few kilobytes - building a 32MB table to avoid scanning it would
	 * cost more than every search it could ever save.
	 */
	struct kof_match_ctx msym;
	/*
	 * HOW MANY MARKERS ARE LIVE ON EACH REGION, FOR THIS OBJECT.
	 *
	 * Refilled per object from the modules the preconditions left, and read
	 * by the multi-pattern prepass to decide whether a region is worth one
	 * pass. One counter per region bit - tens of bytes, not a table.
	 *
	 * `pix` is the other half: the pattern sweep's scratch (kofpix.h) - a buffer of
	 * survivors, a slice of records, a cache of marker bytes and a SPARSE table of what
	 * the sweeps of this object found, keyed by marker id, where bit b says that marker was
	 * seen in region b. It was one word per marker of the database, cleared per object:
	 * 32 MB at eight million markers, memset for every object whatever it was. Now what
	 * an object touches is what it costs, and the table is bounded by the object's ledger
	 * (`pix_ledgered` is what it was charged beyond the fixed part). The sweeps fill it
	 * and a module's question reads it, which is what lets a mask naming CODE|DATA be
	 * answered by an OR instead of a second pass over the bytes.
	 *
	 * Not initialised when the allocation failed or the database has no table, and that is
	 * not an error: no sweep, which is the behaviour this engine had before there was one.
	 */
	uint32_t *live;
	struct kofpix_ctx pix;
	uint64_t pix_ledgered;
	int      pix_ready;
	/*
	 * WHICH MASKS A SWEEP CAN ANSWER FOR, THIS OBJECT.
	 *
	 * multi_prepass used to hand the answer to every marker under every
	 * answerable mask (67 million memo cells for nine hundred searches at
	 * 200,000 rules, 24.8% of that scan). It now records only WHICH masks
	 * are answerable, and the question reads `pix` when one is asked about.
	 * One byte per mask, cleared per object.
	 */
	uint8_t *mask_ok;
};

/*
 * sc->syms: struct kof_scan_syms
 *
 * THE SYMBOL BLOCK'S ALLOCATIONS: the byte buffer, the two extent lists and
 * the array of imports a module reported. Kept between objects; the per-object
 * lengths are in obj.sym.
 *
 * Owner: objctx_diag.c. Files that touch it: objctx_diag.c, objctx.c, scan.c,
 * scan_walk.c, scan_pipeline.c, tests/unit/diag_pe_emu.c.
 */
struct kof_scan_syms {
	/*
	 * THE IMPORTS A MODULE REPORTED for this object - see sym_import in
	 * struct kof_content. Owned strings; merged into the symbol block when
	 * it is built, and per object like the block they complete.
	 */
	struct kof_sym_decl *decl;
	uint32_t cap_decl;
	/*
	 * THE OBJECT'S SYMBOL RECORDS, built at most once per object.
	 *
	 * Lazily: most objects are never asked, and the block is up to a quarter
	 * megabyte, so building it for every object would be a walk of the
	 * symbol table nothing reads. Allocated once for the scanner and reused
	 * across objects rather than per object - the size is fixed by the cap,
	 * so there is nothing to gain by freeing and taking it again.
	 *
	 * `sym_done` is what makes it once-per-object rather than once-per-ask:
	 * a file with no symbols must not be re-walked by every module that
	 * asks, and "built, and the answer was nothing" has to be
	 * distinguishable from "not built yet".
	 */
	uint8_t *buf;
	uint32_t cap;      /* bytes allocated for `sym` - see oc_syms */
	/*
	 * THE TWO HALVES' EXTENTS, BUILT AT MOST ONCE PER OBJECT.
	 *
	 * Which records are imports and which are exports is a property of the
	 * OBJECT, not of the pattern being looked for - so building the list
	 * inside every search was a walk of every record per marker, and a
	 * database with two hundred symbol-scoped markers paid it two hundred
	 * times over for one unchanging answer.
	 *
	 * Allocated on the first symbol search a scanner ever does, and kept:
	 * two lists at the extent cap is 128KB against the presence table's
	 * 32MB, and a scanner that never meets a symbol range never takes it.
	 */
	struct kof_range *ext[2];
	uint32_t ext_n[2];
};

/*
 * sc->diag: struct kof_scan_diag
 *
 * THE DIAGNOSE POOLS, sized by the database in kof_scan_new: the bitmaps
 * (matched, gate open, could not say - one allocation), the bound nodes, the
 * head sequences, the report, and the serialised graph block. The contents of
 * the bitmaps are wiped per object by sx_obj_begin; the per-object products
 * are in obj.diag.
 *
 * Owner: objctx_diag.c (computes), objprod.c (copies them into and out of a
 * parent's product), scan_pipeline.c (the report), scan_verdict.c (reads).
 * Files that touch it: objctx_diag.c, scan.c, objprod.c, objctx.c,
 * scan_pipeline.c, tests/unit/diag_ledger_e2e.c, scan_verdict.c, scan_unpack.c.
 */
struct kof_scan_diag {
	/*
	 * WHICH DIAGNOSES THIS OBJECT CARRIES, worked out once.
	 *
	 * DEMAND DRIVEN, on the same terms as everything else here: reading
	 * the nodes out of an object costs a decode of its code regions, and
	 * an object whose verdict comes from a rule that names no diagnose
	 * must not pay for it. The first rule that asks pays; the rest read
	 * the answer.
	 */
	/*
	 * ONE BIT PER DIAGNOSE (its slot), for as many as the database holds:
	 * diag_cap, allocated once per scanner in kof_scan_new. A fixed 256 here
	 * was the table that capped the loader (KOF_DB_MAX_DIAG) and, with it, a
	 * database's diagnoses 257 and on were not loaded.
	 */
	uint8_t *hit;
	uint32_t cap;              /* diagnoses this scanner has room for  */
	uint32_t bm;               /* bytes in each bitmap                 */
	/*
	 * THE DIAGNOSES THAT COULD NOT SAY: their gate was open, the scan ran, and a
	 * limit was reached on it so a 'no' would not be an answer - see
	 * kof_diag_match_known. Set where diag_hit is, cleared with it.
	 */
	uint8_t *unk;
	/* The head sequences handed to the scan, which keeps the pointer while its
	 * graph lives. */
	struct kgenome_diag_seq *seq;
	/*
	 * WHICH DIAGNOSES' GATES THIS OBJECT PASSES, one bit each, worked out
	 * ONCE per object for all of them - see diag_gates.
	 *
	 * It was asked per diagnose, at two places, and each ask that carried
	 * a symbol sign walked the object's whole symbol table for that one
	 * diagnose: N diagnoses cost 2N walks of the same table. The answer to
	 * "which of these objects' signs are present" is one fact about the
	 * object, so it is one walk and one bitmap.
	 */
	uint8_t *gate;
	/*
	 * WHICH NODE EACH DIAGNOSE BOUND EACH OF ITS OWN NODES TO - see
	 * kof_diag_share.
	 *
	 * A match used to be a bit and nothing else, so "both of these
	 * happened" was all a rule could ask. Two diagnoses are a SHAPE only
	 * when they meet: a W+X region filled by a read, and a socket whose
	 * descriptor that same read uses, are a stager - and the same two
	 * findings about two different reads are a packer and a downloader
	 * in one file. Only the node index tells them apart.
	 *
	 * ALL OF THEM, not the ones a diagnose marked. The mark was a fact
	 * about a pair of behaviours written into the declaration of one of
	 * them; the verdict asks for the join now, so the engine has to be
	 * able to answer about any node. 16 KB, once per scanner, bounded by
	 * the database and not by the object.
	 */
	uint16_t (*bind)[KOF_DB_MAX_DIAG_NODE];
	uint8_t *n_bind;
	/*
	 * And the same graph as the RECORD BLOCK a rule reads - see
	 * kofmod/kofdiagtree.h. Serialised on the first ask and kept until the
	 * object ends, because every later ask reads the same bytes.
	 */
	uint8_t *gr;
	uint32_t gr_cap;       /* its allocation: a header and a record per node */
	/* The report for the object being finished, built by kof_scan_diag_report and
	 * lent to the caller for the length of its callback. */
	struct kof_diag_report *rep;
};

#endif
