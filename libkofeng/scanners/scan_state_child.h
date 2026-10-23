/*
 * scan_state_child.h - the scanner's state about the object in hand and the children it produces: cur, pend, child, emu, sink.
 *
 * Part of struct kof_scanner (scan_state.h); include scan.h, not this file.
 */

#ifndef KOFENG_SCAN_STATE_CHILD_H
#define KOFENG_SCAN_STATE_CHILD_H

#include "scan_types.h"

/*
 * sc->cur: struct kof_scan_cur
 *
 * THE OBJECT IN HAND: facts the walk and the FACTS stage set when an object
 * enters sx_scan_object, read by every later stage. Overwritten for each
 * object, not wiped; a field here that must not carry over has to be set where
 * the object is begun.
 *
 * Owner: scan_walk.c and scan_pipeline.c (set), scan_facts.c (regions, library
 * spans), scan_feed.c / scan_unpack.c / scan_heur.c (read). Files that touch
 * it: scan_facts.c, scan_pipeline.c, scan_walk.c, objprod.c, objctx_emu.c,
 * scan_feed.c, objctx.c, objctx_child.c, scan_norm.c, objctx_decrypt.c,
 * objctx_diag.c, objctx_decomp_folder.c, objctx_script.c, scan_unpack.c,
 * objctx_decomp_entry.c, scan_norm_syms.c, objctx_decomp.c,
 * objctx_decomp_buf.c, scan.c.
 */
struct kof_scan_cur {
	/*
	 * THE PARENT'S ANALYSIS, when this object is a rendering of one - see
	 * objprod.h. While set, diag_graph and apihash point into it and are NOT
	 * this scanner's to free (prod_borrowed); the per-object reset lets go of
	 * them first.
	 */
	const struct kof_prod *prod;
	uint8_t prod_borrowed;
	/*
	 * THREE FIELDS STOOD HERE and all three went with the chain: the
	 * swept reference, the flag saying the sweep had run, and the
	 * flattened profile derived from it. By the end none of them was
	 * read - one was only freed, two were only written - which is what a
	 * removed subsystem leaves behind when the state outlives the code
	 * that filled it.
	 */
	/*
	 * AND THE TWO BATCHED PASSES, ON THE SAME TERMS AS THE TWO ABOVE.
	 *
	 * The multi-pattern sweep and the similarity feed used to run at the
	 * top of scan_object for every object, before the first module was
	 * asked anything. That is the right cost when the modules that need
	 * them are going to run - and the wrong one the moment anything can
	 * end the scan of an object early, because the most expensive work was
	 * already done by then and no verdict could ever avoid it.
	 *
	 * So they are demand-driven now: the first module that DECLARES markers pays for the
	 * sweep, the first that declares blocks pays for the feed, and an
	 * object whose verdict came from a module declaring neither pays for
	 * neither. Measured on 5248 real ELF samples, 167 objects reached the
	 * end of the module loop with no marker-carrying detector surviving the
	 * prefilter at all: 25 MB swept for nobody.
	 *
	 * WHAT A MODULE DECLARES IS THE TEST, not what it does, because that is
	 * the thing the loader knows without running anything - see
	 * kof_module.n_str and n_block. A module with no markers has nothing to
	 * look up: the sweep sizes its own tables from exactly this count (see
	 * multi_prepass), so a module that could search without declaring would
	 * already be mis-sized today.
	 *
	 * Reset per object beside every other per-object fact. kof_mutation_begin
	 * is NOT deferred with the feed - it is a generation bump, O(1), and
	 * leaving it eager is what keeps a block from reading the last object's
	 * answer when this object never fed anything.
	 */
	/* What regions this object has, worked out once in scan_object and kept
	 * because the deferred passes above need it at a point where only the
	 * scanner is still in scope. */
	uint32_t present;
	/* And whether this object came out of a packer, which the feed reads
	 * for the same reason and cannot recover on its own. */
	uint8_t from_packer;
	/* And what its producer declared it needs, travelling with it the same
	 * way cur_from_packer does - the module that said it is long gone by
	 * the time the object is scanned. */
	uint32_t             want, want_level;
	/* Where the module that recognised this object says its program will
	 * be. Per OBJECT, not per child - see emu_watch in kofsig.h. */
	struct { uint64_t rva, len; } xw[KGENOME_EMU_EXEC_WATCH];
	uint32_t n_xw;
	/*
	 * THE HEURISTIC LEVEL THIS SCAN ASKED FOR, as kof_scan_option spells
	 * it: 0 when heuristics are off, otherwise 1 and up.
	 *
	 * Kept here because the two most expensive similarity measures are
	 * gated on it and the content hooks that answer them have no option
	 * to read - see c_mutation_blocks and c_pth_match. Set once per object,
	 * beside the two ready flags and for the same reason.
	 */
	uint32_t heur_lvl;
	/* The module-facing code reader's cursor - see libgenome/celllysis/celllysis.h.
	 * One per object, because a module walks one run of code at a time. */
	struct kgenome_cell_cur cell;
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
	struct kof_objsrc *src;
	/* And the one that derived the object being SCANNED, so it can be
	 * skipped - see unp_eligible. */
	const struct kof_module *derived_by;
	/*
	 * The declared region table of the object being scanned, if it has one.
	 *
	 * Held on the scanner because a resolver is reached through ctx and ctx
	 * carries no room of its own - the same route every other host accessor
	 * takes. Set from the source at the top of scan_object and empty for
	 * every object that was identified rather than declared.
	 *
	 * BORROWED, NOT COPIED: it points into `src`'s own table (kof_src_regions_of), which lives
	 * as long as `src` does, so a table of any length is one table in one place.
	 */
	const struct kof_src_region *rgn;
	uint32_t n_rgn;
	uint8_t rgn_fmt;
	/* The language this object's producer declared, carried the same way
	 * cur_rgn is - see kof_src_declare_lang. */
	uint8_t subtype;
	uint8_t subfam;
	uint8_t lang;
	/*
	 * WHICH BYTES OF THIS OBJECT ARE THE STATIC LIBRARY'S, WORKED OUT ONCE.
	 *
	 * At the top of scan_object, beside the parse that it needs and that
	 * every reader of it would otherwise have to wait for anyway - so it is
	 * a FACT ABOUT THE OBJECT, like its format or its regions, and not a
	 * question each consumer asks for itself.
	 *
	 * It was the second kind. The normaliser worked it out to decide what
	 * to leave out of the view, the block builder worked it out again to
	 * decide which side of enum kgenome_mutation_side each block was on, and
	 * a shape matcher (since removed) a third time - three walks of the same bytes, three
	 * places for the answer to differ, and no way for a reader to see one
	 * answer and know the others matched it.
	 *
	 * Empty for anything that is not an ELF, and for a VIEW, whose headers
	 * describe the file its parent was: kgenome_true_find reads segment offsets,
	 * and on a view they point at bytes that have moved.
	 */
	struct kgenome_true_all lib;
	uint8_t lib_ok;
};

/*
 * sc->pend: struct kof_scan_pend
 *
 * WHAT A PRODUCER DECLARED FOR THE NEXT CHILD it is about to make. Spent by
 * kid_push and dropped by oc_pend_clear (objctx_child.c), the one list of what
 * a pending declaration is; also cleared when a module ends without producing.
 * The buffers (syms, desc_buf, sec, imp, imp_pool, funcs) are kept and only
 * their counts reset.
 *
 * Owner: objctx_child.c (the declaring slots and the push), scan_norm.c (the
 * normaliser declares through the same slots), objctx_emu.c (decl, n_xw/xw),
 * scan_unpack.c. Files that touch it: objctx_child.c, scan_norm.c,
 * objctx_emu.c, scan.c, objctx_script.c.
 */
struct kof_scan_pend {
	/* What a module declared before the run - instruction patterns
	 * (`emu_watch_insn`), API return values (`emu_api_returns`) and image
	 * patches (`emu_patch`), all in kofsig.h. */
	struct kgenome_emu_decl decl;
	/*
	 * THE MODULE THAT DERIVED THE CHILD BEING BUILT, and then the one that
	 * derived each child - see `derive` in kofsig.h.
	 *
	 * A derived object is the parent with ranges changed, so offering it
	 * back to the module that changed them is offering a module its own
	 * output. That is what the three hand-written recursion guards were
	 * for. A NEW object carries NULL here and is offered to everyone,
	 * which is what keeps a zip inside a zip working.
	 */
	/*
	 * THE SECTIONS A MODULE DECLARED FOR THE CHILD IT IS BUILDING.
	 *
	 * Allocated on first use, like every other expensive fixed-size piece
	 * of per-scan state - most objects never produce a child and no object
	 * that produces a flat payload declares one. Spent by the push, beside
	 * the region table and the symbols.
	 */
	struct kgenome_sec_decl *sec;
	uint32_t n_sec;
	uint64_t entry_rva;
	int entry_set;
	/* Directories a module rebuilt, which override the parent's - see
	 * `child_dir` in kofsig.h. */
	struct kgenome_dir_decl dir[16];
	/* The child is an image laid out by those sections, and the engine
	 * writes its header - see kgenome_pe_write_hdr. */
	int image;
	/*
	 * WHAT THE CHILD IMPORTS, as the producer declared it - see `import`
	 * in kofsig.h, and kgenome_pe_write_imports, which turns this into a real
	 * directory when the child closes.
	 *
	 * HELD HERE RATHER THAN WRITTEN AS IT ARRIVES, for the reason the
	 * sections are: a module may keep declaring until it closes the child,
	 * and the table's own size is not known until the last one is in. The
	 * pool is one blob because the strings are short and the count is
	 * bounded - 32 libraries and 512 functions is what the one module
	 * doing this meets, and a per-entry allocation for a name that averages
	 * fifteen bytes would cost more in bookkeeping than in text.
	 */
	struct kgenome_imp_decl *imp;
	uint32_t n_imp;
	char *imp_pool;
	uint32_t imp_pool_n;
	uint64_t imp_at;
	int imp_set;
	int superseded;   /* said, not yet spent */
	/*
	 * WHAT THE DECLARED IMAGE IS TO BE WRITTEN AS - see `as_format` in
	 * kofsig.h. Pending like every other declaration: set before the child
	 * is closed, cleared with the rest of the pending set. Zero `as_fmt`
	 * means "the parent's format", which is what a packer wants.
	 */
	uint8_t                   as_fmt, as_arch;
	/* The format of the object a declared image was built ON, kept for the
	 * region vocabulary - see decl_sec_to_regions. */
	uint8_t img_fmt;
	uint64_t as_base;
	const struct kof_module *derived_by;
	/*
	 * Set while the emulator stage runs, and read where children are
	 * recorded. What that stage produces is a packer's payload by
	 * definition - it is memory a program wrote before running it - but no
	 * module made it, so the usual test on `cur_mod` would file it as a
	 * container entry and lose the distinction downstream.
	 */
	/*
	 * What the next child produced should be called, already sanitised.
	 *
	 * Held here rather than passed to each producer because there are two ways to
	 * make a child and a module names them the same way whichever it uses. Cleared
	 * as it is consumed, and cleared when a module returns, so a name set for a
	 * child that never appeared cannot drift onto the following one.
	 */
	char label[KOF_SRC_NAME_MAX + 1u];
	/*
	 * The producer named this child with something longer than the standard of the
	 * container allows (oc_name_limit). The child is opened without a name and its
	 * object is reported damaged; consumed with the label, cleared with the rest.
	 */
	uint8_t name_bad;
	/*
	 * How long it is, rather than where its first NUL is.
	 *
	 * A name is a range of the object and the object chooses its bytes, so a NUL
	 * inside one is the file's business and not a terminator. A compound file
	 * puts one after every character - its names are UTF-16 - and measuring with
	 * strlen turned "ThisDocument" into "T".
	 */
	uint32_t label_len;
	/*
	 * And what the next child IS, declared by whatever is about to produce
	 * it.
	 *
	 * KOF_FMT_DECLARED_RAW IS HOW "RAW" IS SAID, because KOF_FMT_UNKNOWN
	 * cannot say it. That constant is 0, and 0 is also what this field
	 * holds when nobody declared anything - so "this child is a run of
	 * bytes and must not be sniffed" and "no claim was made" were the same
	 * value, and the first of the two was unsayable.
	 *
	 * It mattered for exactly one producer and it mattered a lot. The
	 * normalised view of an ELF still begins \x7fELF, so with no way to
	 * say otherwise it was sniffed back into an ELF, parsed against
	 * headers that no longer describe it, and reported as a damaged one:
	 * gawk's view came back ELF-other/Heur:Appended, which is a finding
	 * about the normaliser.
	 *
	 * HOST SIDE ONLY. A module still says KOF_FMT_UNKNOWN to mean "I will
	 * not name this one" - see c_child_format - and that reading is
	 * unchanged. This value is out of the range of enum kof_format and no
	 * module can produce it. Consumed by kid_push exactly as the label is, and for the same
	 * reason: a claim that outlived its child would be attached to the next
	 * one, which is the one way this could name the wrong object.
	 */
	uint8_t fmt;
	/* And the language that goes with it - see kof_src_declare_lang. Spent
	 * by c_child beside pend_fmt and cleared there the same way. */
	uint8_t subtype;
	uint8_t subfam;
	uint8_t lang;
	/* And what the NEXT child's regions are, spent by kid_push exactly as
	 * pend_fmt is and cleared there whatever happens to the child. The table is the scanner's
	 * own buffer, grown to what the producer declares (oc_pend_regions) and kept between
	 * children like `fixed` and `syms`: freed by scan_free and by kscan_trim. */
	struct kof_src_region *rgn;
	uint32_t n_rgn, rgn_cap;
	uint8_t rgn_fmt;
	/* And whether the next child is one. Spent by kid_push like the rest. */
	/*
	 * AND THE SYMBOL RECORDS THE NEXT CHILD IS TO BE READ WITH.
	 *
	 * A rendering cannot build its own - its headers describe the file
	 * before the transform - so the producer hands them over with the
	 * bytes, exactly as it hands over the region table. Spent by kid_push
	 * and cleared there whatever becomes of the child, so a block made for
	 * one view can never be attached to the next.
	 *
	 * Heap, because KOF_SYM_MAX_BYTES is a quarter of a megabyte and this
	 * is a scanner that runs one per thread; allocated the first time
	 * anything renders and kept for the rest of the scan.
	 */
	uint8_t *syms;
	uint32_t syms_cap;  /* bytes allocated for it */
	uint32_t n_syms;
	/* The view's functions, mapped from the parent's - see kgenome_funcs_remap. */
	struct kgenome_func_set funcs;
	/*
	 * THE UNITS OF THE PARENT'S CUT THAT THE VIEW'S DECODE REWROTE, in the view's own
	 * offsets, sorted and apart - see kof_src_declare_fixed. Kept for the next view and
	 * only grows.
	 */
	struct kof_range *fixed;
	uint32_t fixed_cap, n_fixed;
	/*
	 * AND THE IMAGE IT IS A RENDERING OF - format, architecture, entry and the
	 * parent's info struct with every file offset carried through the
	 * transform (see kof_src_declare_desc). `pend_desc.info` points at
	 * pend_desc_buf, which is kept for the next view and only grows. Spent by
	 * kid_push with the rest.
	 */
	struct kof_src_desc desc;
	uint8_t *desc_buf;
	uint32_t desc_cap;
	uint8_t desc_set;
	/* And what it is for, which is also its name when nothing named it. */
	uint32_t kind;
	/* And which entry it is the content of, or KOF_ENTRY_NONE. */
	uint32_t entry;
	/* And what the producing module says has to be DONE to it, in the same
	 * KOF_ENG_* vocabulary a module uses, with the lowest --heur
	 * level the ask is honoured at. See child_want in kofsig.h. */
	uint32_t want, want_level;
	/*
	 * AND THE OEP RANGES THE NEXT CHILD IS TO BE WATCHED AT.
	 *
	 * Declared by a module while the PARENT is in front of it and meant for
	 * the CHILD, so they travel the same road as pend_want: set here, spent
	 * by kid_push, handed back when that child is the object being scanned.
	 * Kept in sc->xw while it is. They used to be written straight into
	 * sc->xw, which is cleared per object - so a module declared them, the
	 * child was pushed, the clear ran, and every run saw none.
	 */
	uint32_t n_xw;
	struct { uint64_t rva, len; } xw[KGENOME_EMU_EXEC_WATCH];
};

/*
 * sc->child: struct kof_scan_child
 *
 * THE CHILDREN AN UNPACKER PRODUCED, collected and drained by the walk once
 * the module has returned. The parallel arrays carry what each child's
 * producer said about it, because the module is out of scope by the time the
 * child is reached.
 *
 * Owner: objctx_child.c (kid_push appends), scan_walk.c (drains and pushes
 * onto the work list), scan_unpack.c / scan_heur.c / scan_pipeline.c (the
 * counts). Files that touch it: objctx_child.c, scan_walk.c, scan_unpack.c,
 * scan.c, scan_pipeline.c, scan_norm.c, scan_heur.c, objprod.c, objctx_emu.c,
 * tests/unit/child_fuzz.c.
 */
struct kof_scan_child {
	struct kof_objsrc **list;
	/*
	 * Per child: was it produced by an EXECUTABLE PACKER rather than by a
	 * container. Parallel to `kids` because it is a property of the child's
	 * provenance and has to travel with it onto the work list, where the
	 * module that made it is long out of scope.
	 */
	uint8_t *packer;
	/* What each child's producer declared it needs. Parallel to `kids` for
	 * the reason kid_packer is: the claim is the child's and the module
	 * that made it is out of scope by the time the child is reached. */
	uint32_t *want;
	uint32_t *want_level;
	/* One count and KGENOME_EMU_EXEC_WATCH (rva,len) pairs per child, flat. */
	uint32_t *n_xw;
	uint64_t *xw;
	/*
	 * The family the producing unpacker DECODES, per child, or NULL.
	 *
	 * A pointer into a pack mapping (kof_db_family), which outlives the
	 * scan, so it is safe to keep. It is what lets a child inherit its
	 * parent's family as a prediction: an intermediate layer msf_xor peeled
	 * is formatless, so no heuristic fires on it and it would otherwise lose
	 * the Meterp guess its parent carried - and with it the family-first
	 * fast path. See the push loop in the walk.
	 */
	const char **family;
	const struct kof_module **derived_by;
	uint32_t            n, cap;
	/*
	 * HOW MANY OF n_kids ARE VIEWS RATHER THAN PAYLOADS.
	 *
	 * "This object produced children" is read as "something came out of it,
	 * so a rule that guessed at what it was has been answered by the thing
	 * itself" - and on that reading every rule heuristic on the object is
	 * withdrawn. See where out->v is filtered in scan.c.
	 *
	 * A normalised view breaks that reading. Nothing came out of the
	 * object; the same object was written down again more plainly. Counting
	 * it withdrew findings that were correct, and it did so on almost every
	 * binary, because a view is made for any executable of 4 KB or more
	 * with a long zero run in it. Measured as a silent detection loss: an
	 * ELF of the exact shape Heur:Shellcode exists for reported it at 176
	 * bytes and said nothing at 4216, with no difference between the two
	 * but the view.
	 *
	 * Counted rather than flagged because a view is still a child in every
	 * other respect - it is scanned, it is budgeted, it is freed - and only
	 * this one question needs to tell them apart.
	 */
	uint32_t n_views;
	/*
	 * And how many are CARVED - a payload found by searching, not a
	 * rendering and not an unpacking.
	 *
	 * The analysis steps stop at the first one that produces a child,
	 * because a child usually replaces its parent as the subject. A carve
	 * does not: nothing declared that an ELF is carrying a file, so the
	 * host is a whole program that happens to have something glued to it
	 * and is still worth every later step. Counted out for the same reason
	 * n_views is - see KOF_ANALYZE_CARVE.
	 */
	uint32_t n_carved;
};

/*
 * sc->emu: struct kof_scan_emu
 *
 * WHAT A RUN LEFT BEHIND, held rather than handed over: the live machine, the
 * gathered regions and the image the run assembled. Released when the module
 * that asked for the run returns.
 *
 * Owner: objctx_emu.c. Files that touch it: objctx_emu.c, scan_unpack.c,
 * objctx_child.c, scan.c, scan_heur.c.
 */
struct kof_scan_emu {
	/* A run a module asked to be paused on, and the report it will be
	 * gathered with when it finishes - see `emu_resume` in kofsig.h. */
	struct kgenome_emu_unp_report *rep_p;
	int paused;
	/*
	 * WHAT A RUN LEFT BEHIND, HELD RATHER THAN HANDED OVER.
	 *
	 * The interpreter is not a producer. It gathers, and a MODULE decides
	 * what any of it is and gives that to the engine - see
	 * DESIGN-object-pipeline.md. Two reasons, and the second is the one
	 * that matters: only a module knows what a family's run means, and a
	 * component that both runs hostile code and creates objects is a wider
	 * surface than one that only runs it.
	 *
	 * `emu_live` is the machine itself, kept alive while the regions below
	 * still point into its memory, and released when the module that asked
	 * for the run returns.
	 */
	struct kgenome_emu *live;
	/* An image a run ASSEMBLED rather than left lying in its memory - the
	 * un-mapped PE, the rebuilt ELF. It is the engine's allocation, so the
	 * engine holds it for as long as a region points at it. */
	uint8_t *own;
	struct kof_emu_rgn {
		const uint8_t *p;
		/*
		 * WHEN THE ENGINE OWNS THOSE BYTES, AND IT USUALLY MUST.
		 *
		 * `kgenome_emu_next_written` hands back a buffer the emulator owns
		 * and REPLACES ON THE NEXT CALL - it says so beside itself.
		 * That was safe while the interpreter emitted each run as it
		 * walked them; it is not safe now that the regions are gathered
		 * first and handed to a module afterwards, because every
		 * pointer but the last is freed before the module ever sees it.
		 *
		 * Measured on msfvenom's `poly`: the module was handed a
		 * four-kilobyte region whose bytes had become the scanner's own
		 * section table by the time it copied them, so the child came
		 * out as a correct ELF header in front of 4012 zero bytes.
		 *
		 * So a gathered region is copied, and this is the copy to free.
		 * NULL where the bytes belong to something with a longer life -
		 * a snapshot lives in the machine and the machine outlives the
		 * module - and then `p` points into that.
		 */
		uint8_t       *own;
		uint64_t       va, n;
		uint32_t       kind;    /* KOF_EMU_RGN_* */
	}                         rgn[KOF_EMU_RGN_MAX];
	uint32_t n_rgn;
	/*
	 * WHAT THIS RUN HOLDS THAT THE LEDGER KNOWS ABOUT: `held` is the assembled image
	 * and the copies of the written regions (the gather made them, the engine owns
	 * them until the module returns), charged when gathered and given back when
	 * they are freed or handed to the child. The machine's own memory is not in it:
	 * the emulator asks for that itself (kgenome_emu_cfg.account) and gives it back
	 * when it is freed.
	 */
	uint64_t held;
	/* What the machine has been granted by emu_account and not yet returned. */
	uint64_t charged;
};

/*
 * sc->sink: struct kof_scan_sink
 *
 * THE EMIT SINK: what a module emitted and has not closed. Discarded at the
 * start of every module and every object (kof_scan_sink_discard).
 *
 * Owner: objctx_child.c (emit/close), objctx_decomp_buf.c (the fixed-size
 * arm). Files that touch it: objctx_child.c, objctx_decomp_buf.c,
 * tests/unit/child_fuzz.c, scan.c.
 */
struct kof_scan_sink {
	/* The object being emitted, before it becomes a child. Heap while it is
	 * small, an unnamed temporary file once it is not - see objsrc.h. */
	uint8_t *mem;
	size_t    len, cap;
	int fd;
	uint64_t spilled;   /* bytes already written to sink_fd */
	/*
	 * The sink is a FIXED extent - a copy of the parent, or an image laid
	 * out from declared sections - written at addresses rather than
	 * appended to. See `derive` and `image` in kofsig.h. It never spills.
	 *
	 * `sink_at` is where the next emit lands, which is what lets a
	 * decompressor write straight into a section: every decoder in the
	 * engine funnels through c_emit, so moving the cursor is all it takes
	 * and not one of them has to know.
	 */
	int fixed;
	uint64_t at;
	/*
	 * AN ENTRY THAT MET ITS OWN BOUND (object cap, declared-ratio clamp), and what
	 * the walk does about it - see oc_entry_cut.
	 *
	 * `cut` is the reason the child being built will carry (KOF_BROKEN_LIMIT, 0
	 * none): stamped on the source when the sink closes, so the object says it was
	 * cut and the parent's entry loop is not told to stop. `refuse` is set when the
	 * sink was closed BY the cut (OC_REFUSE_*): the rest of that entry is refused,
	 * and a module's own close of it answers "made". Both end where the next entry
	 * begins (oc_entry_begin, oc_child) and at every discard.
	 */
	uint32_t cut;
	uint8_t  refuse;
};

/*
 * sc->spill: struct kof_scan_spill
 *
 * WHERE A BIG PRODUCED OBJECT GOES, decided once per scanner (and again if the host
 * names another directory): see objctx_spill.c for the flow. `state` is 0 until the first
 * object that wants to spill, then 1 (a file may be made there and holds the object)
 * or 2 (it may not, and `why` says which: KOF_SPILL_*). `io` is NULL for the real calls and
 * a test's table otherwise - the same seam either way, so what a test exercises is what runs.
 *
 * Owner: objctx_spill.c. Files that touch it: objctx_child_sink.c, objctx_child.c.
 */
struct kof_spill_io {
	/* A new anonymous file, in `first` when it names a directory; -1 on failure. */
	int (*open)(void *user, const char *first);
	/* All of the bytes, or 0 (ENOSPC, EIO...). */
	int (*write)(void *user, int fd, const void *p, uint64_t n);
	/* Bytes free where the file is, and whether that place is RAM; 0 when unknown. */
	int (*space)(void *user, int fd, uint64_t *avail, int *ram);
	void *user;
};

enum kof_spill_why {
	KOF_SPILL_NONE = 0,
	KOF_SPILL_UNAVAILABLE,   /* no directory a file can be made in */
	KOF_SPILL_RAM,           /* the place is a RAM filesystem and the host did not name it */
	KOF_SPILL_SMALL,         /* too little free space for an object the size the cap allows */
	KOF_SPILL_FULL           /* a write failed or the space ran out while writing */
};

struct kof_scan_spill {
	int state;                      /* 0 not probed, 1 usable, 2 not */
	uint32_t why;                   /* enum kof_spill_why, when state is 2 */
	const char *probed_for;         /* the scratch directory the probe was made for */
	uint64_t avail;                 /* free bytes at the last look */
	uint64_t since;                 /* bytes written since that look */
	const struct kof_spill_io *io;
};

#endif
