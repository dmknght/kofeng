/*
 * kofeditor_object.h - struct object, the viewer's record of one object under view.
 *
 * Not part of the draft model: it is what a marker was taken from, which the model
 * reaches through the host's array. A part of kofeditor.h, included by it and by nothing else.
 */
#ifndef KOF_KOFEDITOR_OBJECT_H
#define KOF_KOFEDITOR_OBJECT_H

struct dash_infect;
struct dash_shell;

struct object {
	char      name[256];


	/*
	 * WHAT A TREE ROW SHOWS, when the name is not the answer.
	 *
	 * obj_label composes a row from the object's FORMAT - "ELF-x64",
	 * "raw" - which is right for a scanned object and says nothing about
	 * an event. A log's rows want "//4021 FileNew pid=5104 f.exe", which
	 * only the record can supply.
	 *
	 * Empty for every ordinary object, and then obj_label behaves exactly
	 * as it did. Non-empty overrides it - one field, checked in one place,
	 * rather than obj_label learning what a log is.
	 */
	char      label[64];
	/*
	 * REGIONS THE ENGINE DECLARED for this object, and the count.
	 *
	 * Almost always zero, and then the parser's own resolver answers as it
	 * always has. Non-zero for a NORMALISED VIEW, which cannot be parsed
	 * for them: it keeps its parent's header byte for byte, so identifying
	 * it from its bytes yields an ELF or a PE whose offsets describe the
	 * parent - before the padding was taken out. Drawn from those, a view's
	 * data region begins at the parent's offset, runs into the kept code,
	 * and shows padding the view no longer carries.
	 *
	 * See kof_result.region, which is where these come from and why the
	 * engine has to be the one to say.
	 */
	struct kof_scan_region rgn[KOF_MAX_REGIONS];
	uint32_t  n_rgn;
	/* Which format's vocabulary rgn[].mask is written in - the PARENT's,
	 * because that is where the bits were resolved. A bit cannot be named
	 * without it: 1u << 5 is UNCLAIMED in an ELF and OVERLAY in a PE. */
	uint8_t   rgn_fmt;
	/*
	 * THE LANGUAGE THE ENGINE SCANNED THIS OBJECT AS, when it declared one
	 * - see kof_result.lang_known.
	 *
	 * Kept for the same reason rgn[] is: a normalised view's own bytes
	 * answer about themselves, and a decode can change the answer outright.
	 * A shell dropper whose base64 payload decodes to PHP reads back as
	 * PHP, and the panel then declined every rule written for the language
	 * the object actually is - beside a verdict saying one of them had
	 * fired.
	 */
	uint8_t   lang_known;
	uint8_t   subtype;
	uint8_t   subfamily;
	/*
	 * Set when the engine handed the symbol records over with the object -
	 * see kof_result.syms. sym_build must not overwrite them: the object is
	 * a rendering whose own headers cannot produce a block, and building
	 * from them yields none.
	 */
	uint8_t   sym_declared;

	/*
	 * THE BLOCKS THE CARVE CUT FROM THIS OBJECT, KEPT.
	 *
	 * The carve hashes every region, so it reads the whole object too:
	 * measured at 310ms on a 15MB view and 0.7s on a sample with three
	 * objects, paid on every arrival at the object rather than once.
	 *
	 * KEPT ONLY WHEN NOTHING WAS TICKED, which is what makes it exact
	 * rather than close. The cut positions do not depend on what the
	 * author has ticked - the share-out deliberately counts the whole
	 * table, see the note on it - but how many of the cuts FIT does, so a
	 * list recorded with none ticked is the list a fresh carve produces
	 * with none ticked, and nothing else is reused.
	 */
	struct mtn_block *carve;
	uint32_t          n_carve;
	uint8_t           carve_done;

	uint8_t  *own;              /* the copy, NULL for the mapped top level */
	void     *mapped;           /* or a spill file, mapped instead of copied */
	uint64_t  mapped_len;
	int       too_big;          /* kept nowhere: past the session's budget */
	kof_buf   buf;
	uint32_t  depth;            /* how many "//" its name carries */
	/*
	 * WHICH ENTRY OF ITS PARENT THIS OBJECT IS THE CONTENT OF, or
	 * KOF_ENTRY_NONE.
	 *
	 * From the engine and not worked out here - see kof_result.entry_of.
	 * It is what lets one stream be ONE row: an entry describes the coded
	 * extent where it lies in the file, and this object is that stream's
	 * content. Before this arrived the tree showed both, with nothing
	 * saying they were the same stream and the first of them opening onto
	 * compressed noise.
	 */
	uint32_t  entry_of;
	/* And what the producer said it IS - enum kof_entry_kind. The format of
	 * decoded content is almost always unknown, so this is the only thing
	 * that separates a peeled payload from a page description stream, and
	 * the two want opposite answers from every item in the Analysis menu. */
	uint32_t  entry_kind;

	const struct kof_parser *fmt;
	struct kof_obj_ctx            ctx;
	void                         *info;

	/*
	 * WHAT OPENED THIS OBJECT, in the engine's own words and in one field:
	 * "PE:MPRESS 2.12-2.19 LZMA" where the module could name a build,
	 * "MSF.xor" where it could not. See kof_result.packer_build - the whole
	 * answer is there and nothing here works any of it out.
	 */
	char              packer[48];
	/*
	 * The interpreter has already been run on this object.
	 *
	 * Asking twice cannot produce a different answer - the bytes have not
	 * changed and the run is deterministic - so a second press appended a
	 * second identical set of children, and a third a third. Recorded per
	 * object because the question is per object.
	 */
	int               emu_done;
	/*
	 * What the scanner's own gate makes of this object, when no module
	 * claimed it: KOF_EMU_UNP_* .
	 *
	 * ONCE, AND NOT UNTIL SOMETHING SHOWS IT - see obj_emu_why. It reads
	 * every executable segment, so computing it beside the parse faulted a
	 * spilled object in whole to fill one row; and computing it while
	 * drawing would do that on every keystroke. `emu_why_done` separates
	 * "not worked out yet" from "worked out, and the answer is zero",
	 * which a single field cannot say.
	 */
	uint8_t           emu_why;
	uint8_t           emu_why_done;
	/*
	 * SHA-256 OF THIS OBJECT'S BYTES, hex, or "" before it is computed.
	 *
	 * OF THE BYTES AND NOT OF THE FILE, which is the whole reason it is
	 * here rather than taken from the path. A child - an unpacked payload,
	 * a stream out of a PDF, a PE an event carried - has no path at all,
	 * and its hash is the one somebody actually wants to look up: it is
	 * the IOC for the thing that was hidden, not for the wrapper anybody
	 * can rebuild. For the top-level object the two are the same.
	 *
	 * COMPUTED ONCE, BESIDE THE PARSE, for the reason emu_why is: the
	 * property pane is repainted on every keystroke, and hashing a
	 * hundred-megabyte mapping per frame is not a slow feature, it is an
	 * unusable one.
	 */
	char              sha256[65];
	/*
	 * The version that module read out of the object, or -1 for none.
	 *
	 * Signed and not a flag beside a uint, because 0 is a version a container
	 * can carry and "it never said" has to be a different answer from "it
	 * said zero".
	 *
	 * It is the FORMAT version the module found in the file - UPX's l_info
	 * byte, RAR's archive version - and not the packer's release. The two get
	 * confused, so nothing here pretends to know that a UPX l_info of 13
	 * means UPX 3.9x: the module reported a field called version and this
	 * shows the field.
	 */
	/* What the engine said about this object, kept whole. */
	struct kof_result heur;
	/*
	 * Whether the engine got to the end of THIS object, and what stopped it.
	 *
	 * Kept per object rather than for the file, because it is per object: a
	 * container that opened may hold one entry it could not, and the packed
	 * parent being incomplete says nothing about the child that came out of
	 * it. enum kof_broken, KOF_BROKEN_NONE when it finished.
	 */
	uint32_t          broken;
	/*
	 * WHAT EACH DIAGNOSE MADE OF THIS OBJECT - an owned copy of
	 * kof_result.diag, which the engine lends only for the callback. Empty
	 * when the scan did not ask. See draw_decl_diag.
	 */
	struct kof_diag_report *diag;
	uint32_t                n_diag;
	/*
	 * THE FUNCTIONS ITS SYMBOLS NAME, built once beside the symbol block - see
	 * funcs.h. Empty for an object with none, and for a normalised view, whose
	 * headers describe its parent.
	 */
	struct kgenome_func_set     funcs;
	uint8_t                 funcs_done;
	/* What Analysis > Analyze disassembly found: labels and comments by file offset, from the engine (kof_codenotes_build). Empty until asked. */
	struct kof_codenotes        notes;
	uint8_t                 notes_done;

	/*
	 * The object's symbol records, in the KSYM layout kofsym.h fixes.
	 *
	 * Built ONCE, when the object is parsed, and right-sized: the cap is
	 * 4096 records and a scratch of that size for each of MAX_OBJ objects
	 * would be thirty megabytes held to show a table nobody may open, while
	 * the real counts are tens to a few thousand. NULL and zero for a file
	 * with no symbols and for every non-ELF - which is a normal answer, not
	 * a failure, so nothing downstream treats it as one.
	 */
	/*
	 * THE OBJECT'S SYMBOL BLOCK - the engine's, one copy, unsplit.
	 *
	 * It used to be two blocks that this file built by copying records out
	 * of the engine's according to their UNDEFINED flag. That was a second
	 * implementation of "which half is this symbol in", and it disagreed
	 * with the engine's: the engine coalesces adjacent records of one half
	 * into runs, so a pattern is never matched across a record of the other
	 * half, while a copied half joins records the engine keeps apart. On
	 * 23.8% of files the halves interleave, so the two really did answer
	 * differently.
	 *
	 * Now the block is whatever kof_syms_build returned and the halves are
	 * kof_sym_extents' answer - the same call kof_find_str makes.
	 */
	uint8_t          *sym;
	uint32_t          sym_n;
	/* THE UNITS OF THE PARENT'S CUT THAT THIS VIEW'S DECODE REWROTE, in its offsets - copied
	 * from kof_result.fixed, and handed to the cut so the table shows the scanner's units. */
	struct kof_range *fixed;
	uint32_t          n_fixed;

	/*
	 * WHERE THIS OBJECT'S LOADER KEEPS ITS PAYLOAD, from the tool's own
	 * analysis (kofscfind) - the engine does not look for loaders. Worked out
	 * ONCE per object, when it is examined (scfind_object in kv_collect.c),
	 * and read from here by every pane after that: the symbol tables, the
	 * menu, the status line. payload_at is the symbol's value, zero when
	 * nothing was found; payload_len the blob's size as it sits in the object;
	 * payload_bits 32 or 64 where the payload said so, 0 where it did not.
	 * sc_done says the analysis ran, whatever it answered.
	 */
	uint64_t          payload_at;
	uint64_t          payload_len;
	uint32_t          payload_bits;
	uint8_t           sc_done;
	/* Set on the object the VIEWER derived from a parent's payload (the
	 * engine never produces one), so the
	 * menu can find it without inferring anything from the name. A name
	 * test alone would also match an unpacker's child that happened to sit
	 * under the same parent. */
	int               payload_of;
	/*
	 * WHERE A RULE SAID THE INFECTION IS - see struct kof_infected.
	 *
	 * Copied from the result rather than worked out here, and worked out
	 * nowhere: a module that can describe a repair had to locate the damage
	 * to do it, so this is a fact the scan already established. Nothing in
	 * this file searches for it, and nothing here decides what counts as
	 * infected.
	 */
	struct kof_infected infected[KOF_MAX_INFECTED];
	uint32_t          n_infected;
	/* What the Infection dialog shows, computed ONCE when it is first shown (kv_dashdata.c dash_*_get) and kept here until the
	 * object goes (dash_drop). Heap, sized to the rows. NULL until then. */
	struct dash_infect *inf_data;
	struct dash_shell  *shell_data;
	/*
	 * WHICH MAPPED FILE OF A PROCESS VIEW THIS ROW IS, plus one - zero
	 * means it is not one. An index into view.seen_path, which holds the
	 * full path; the object's own name carries the basename because that
	 * is what fits a tree row.
	 */
	uint32_t          proc_path;
	/*
	 * WHICH VARIABLE IT CAME OUT OF, and what was wrapped round it.
	 *
	 * Kept on the child rather than left in its name: the name says what
	 * the object is, and the symbol is a fact about where in the PARENT it
	 * was found. A reader wants both, and only one of them belongs in a
	 * tree row eighteen columns wide.
	 */
	char              payload_sym[KOF_SYM_NAME_MAX + 1];
};
/*
 * WHAT THE EDITOR IS DRIVING: the draft, plus the little of its surroundings a
 * draft actually refers to.
 *
 * Measured rather than guessed. Of the forty-two model functions, three need
 * the object a marker was taken from, two the directory a rule is written to,
 * and one each the sample's path, the engine and whether the file is somebody
 * else's. Nothing else. So those seven are here and the rest of the viewer -
 * the tree, the panes, the selection - is not reachable from a function that
 * takes one of these.
 *
 * The four pointers borrow the host's storage rather than copying it: `n_obj`
 * and `foreign` change while a session runs, and a copy of a number that
 * changes is a number that goes stale.
 */

#endif /* KOF_KOFEDITOR_OBJECT_H */
