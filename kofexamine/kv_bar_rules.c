/* kv_bar_rules.c - which menu-bar items exist for the object in hand, which are enabled, and why one is grey (split from kv_bar.c, bodies unchanged). */
#define _GNU_SOURCE
#include "kv.h"
#include <celllysis/disasm.h>
#include "kv_bar_private.h"

/*
 * IS THERE AN UNPACKER TO CHOOSE BETWEEN, for the file being examined.
 *
 * THE FILE AND NOT THE SELECTED ROW, unlike the four object items above. Dump
 * writes every object of the document, so its meaning does not change as the
 * cursor moves - and a menu whose shape changed while somebody walked the
 * tree would be changing for no reason the reader did anything about.
 */
static int dump_has_choice(const struct view *v)
{
	if (!v->n_obj)
		return 0;
	return kv_cap(v->obj[0].ctx.format, KV_CAP_UNPACK);
}

/*
 * Is an item offered at all, for THIS object.
 *
 * Analysis is where that matters: symbols belong to an executable and a zip has
 * none, so the menu is built from the object in hand rather than from a fixed
 * list. An item that cannot apply is drawn greyed rather than removed, because a
 * menu whose length changes as you move between objects is one you cannot learn.
 */

/*
 * WHICH ITEMS EXIST AT ALL for the object in hand.
 *
 * Distinct from bar_enabled, which greys an item and says why. Something that
 * cannot apply to this KIND of object should not be a grey row a reader has to
 * click to be told about - Disassembly on an event log is not "disabled", it is
 * meaningless, and a menu that lists it is a menu describing the wrong tool.
 */
/*
 * COULD THESE BYTES BE CODE - the question the disassembler and the emulator
 * both rest on.
 *
 * kv_cap answers it for a FORMAT, and says yes for KOF_FMT_UNKNOWN because
 * bytes nothing claimed are exactly what a peeled payload looks like. But
 * decoded content is formatless TOO, and a page description stream is not
 * code - so the format alone said yes to everything a PDF produced, and
 * "Disassembly" was offered on a font program.
 *
 * The kind is what separates them, and it is the parse's own answer carried
 * down by the engine rather than anything worked out here. Where the parse
 * named the thing and the name is not code, the answer is no; where nothing
 * named it, the answer stays yes, because that is the case these two items
 * exist for.
 */
int obj_maybe_code(const struct object *o)
{
	if (!o)
		return 0;
	if (o->fmt)
		return kv_cap(o->ctx.format, KV_CAP_CODE);
	switch (o->entry_kind) {
	case KOF_ENT_CONTENT:
	case KOF_ENT_FONT:
	case KOF_ENT_IMAGE:
	case KOF_ENT_METADATA:
	case KOF_ENT_STRUCTURE:
		/* The parse said what these are, and none of them is a program.
		 * EMBEDDED is deliberately absent: a carried file is a file of
		 * unknown kind, which is the one the sniff chain declined - so
		 * it falls to the default and stays offered. */
		return 0;
	default:
		return kv_cap(KOF_FMT_UNKNOWN, KV_CAP_CODE);
	}
}

int bar_shown(struct view *v, int i)
{
	int verb;

	if (i < 0 || i >= BI_COUNT)
		return 0;

	/*
	 * A FILTER SLOT IS A SLOT WHETHER OR NOT IT HAS A VERB.
	 *
	 * The test was "bar_filt_verb returned something", which is a question
	 * about the CONTENTS of the slot and not about which item this is. The
	 * table has twenty slots and the sorted verb list is shorter, so the
	 * leftover slot answered -1, fell past this branch to the general rules
	 * at the bottom, and was shown - an empty row under the last verb.
	 *
	 * Asking which item it is instead cannot go wrong that way: a slot is a
	 * slot, and whether it has a verb only decides if it is drawn.
	 */
	/*
	 * WHAT CANNOT APPLY TO THE OBJECT UNDER THE CURSOR IS NOT DRAWN.
	 *
	 * These four are about the selected object rather than the file, and
	 * for most objects of most formats the answer is no: a page stream has
	 * no symbols, no entry point and nothing to run. Greying them left four
	 * dead rows in the Analysis menu of every document, which a reader
	 * learns to skip and which teaches nothing - see the note on `enabled`
	 * in kofview.h for the distinction this rests on.
	 *
	 * The CAPABILITY is here and the transient part stays in bar_enabled: a
	 * disassembler that applies to this object but whose bytes were not
	 * kept is momentarily unavailable, and a row that vanishes for that
	 * would flicker as the reader moves.
	 */
	switch (i) {
	/* One dump or the other, never both - see the note on the enum. */
	case BI_DUMP:
	case BI_DUMP_STATIC:
	case BI_DUMP_EMU:
		return dump_has_choice(v);
	case BI_DUMP_PLAIN:
		return !dump_has_choice(v);
	/* The mode, and a file: the one thing this acts on is a document that
	 * was opened without its children being separated. */
	case BI_SEPARATE:
		return v->heur_off && v->n_obj != 0;
	case BI_DISANALYSE:
	case BI_DISASM: {
		const struct object *ob = cur_obj(v);

		if (!obj_maybe_code(ob))
			return 0;
		/* Offered where the library has text for the object's
		 * architecture (kgenome_disasm_level_obj: x86, ARM in ARM
		 * state, AArch64). An image of another architecture would be
		 * decoded as instructions it does not contain, which is not a
		 * thing to offer and then explain. */
		if (!ob->fmt)
			return 1;
		{
			struct kgenome_obj g;

			kof_genome_obj(&ob->ctx, &g);
			return kgenome_disasm_level_obj(&g) != KGENOME_DISASM_NONE;
		}
	}
case BI_UNPACKER: {
		const struct object *ob = cur_obj(v);

		/*
		 * NOT ON WHAT MPRESS PRODUCED, and only on that.
		 *
		 * The static path for MPRESS recovers the entry point the
		 * program actually has, rebuilds the import directory from the
		 * packer's own hints, and cuts the decompressed span back into
		 * the sections it came from - measured against Avast's own
		 * unpacked output of the same file, 1263 of 1265 pages match
		 * byte for byte. There is nothing left for an interpreter to
		 * find, and offering it here invites a reader to spend a run
		 * discovering that: one sample faults after 22 instructions
		 * because what is under MPRESS is VMProtect, and another
		 * spends ten seconds reaching ExitProcess for two command line
		 * strings.
		 *
		 * Every other object still gets the row. This is a statement
		 * about one packer, not about the interpreter.
		 */
		/* The producer's source basename, which is what
		 * kof_result.produced_by carries - "mpress_pe", not the
		 * debug-note prefix "MPRESS.PE" this used to be matched
		 * against. */
		if (ob && ob->packer[0] &&
		    strncmp(ob->packer, "MPRESS", 6) == 0)
			return 0;
		return obj_maybe_code(ob);
	}
	default:
		break;
	}

	if (i >= BI_FILT_V0 && i <= BI_FILT_V27) {
		verb = bar_filt_verb(i);
		/*
		 * Only verbs the log actually contains. A submenu listing
		 * every verb the format can express would be mostly rows that
		 * filter nothing, and the reader cannot tell those from the
		 * ones that would.
		 */
		return v->log && verb > 0 &&
		       (v->log_verbs & (1u << (unsigned)verb)) != 0;
	}
	if (i == BI_FILTER || i == BI_FILT_APPLY)
		return v->log != NULL;

	/*
	 * WHAT AN EVENT RECORD IS NOT.
	 *
	 * Disassembly, the shellcode finder and the unpackers all
	 * ask questions about a parsed executable. A record is a struct: it
	 * has no symbol table, no instructions, no variables to search and
	 * nothing for an unpacker to open.
	 *
	 * REBUILD IS NOT ONE OF THEM, and it used to be listed here on the
	 * grounds that it re-runs the scan, which for a log would discard the
	 * event window and find nothing. That is not what happens: it reopens
	 * through file_open, and file_open recognises a log and builds the
	 * event window again - the same road opening one takes.
	 *
	 * Hiding it also removed the item at exactly the point a reader wants
	 * it. A rule declared off a record's command line is generated into
	 * the source tree, and the next thing anybody would do is build the
	 * database and look again - which was the one action the menu did not
	 * offer while a log was open.
	 *
	 * THE TEST IS THE OBJECT, NOT THE FILE, and that is the whole
	 * difference. A PE carried inside a submission is an executable that
	 * happens to have arrived in a log - it has every one of those things,
	 * and hiding them because of the container it came in would make the
	 * one place a reader most wants a disassembler the one place without
	 * one.
	 *
	 * The event filter stays offered either way: it is about the LOG, and
	 * the log is still open whichever row is picked.
	 */
	if (v->log && !v->pe_of[v->node[v->sel_node].obj]) {
		switch (i) {
		case BI_DISASM:
		case BI_DISANALYSE:
		case BI_INFECTION:
		case BI_UNPACKER:
		case BI_DUMP_STATIC:
		case BI_DUMP_EMU:
			return 0;
		default:
			break;
		}
	}
	return 1;
}

int dump_needs_rebuild(const struct view *v, int use_emu)
{
	return use_emu ? !tree_has_emu(v) : (v->emu_mode != 0);
}

int bar_enabled(struct view *v, int i)
{
	switch (i) {
	/* Off for a viewer that has no file behind it, which is the one case
	 * where there is nowhere for a dump to go: the directory is named after
	 * the file and placed beside it. */
	/* The parent is live whenever either of its children could be. */
	case BI_DUMP:
	case BI_DUMP_PLAIN:
		return v->path && v->path[0];
	case BI_DUMP_STATIC:
	case BI_DUMP_EMU:
		/*
		 * A rebuild throws the draft away - the same reason stepping
		 * to another file is refused with one open - so the wait is on
		 * the rebuild and not on the item. Dumping the tree that is
		 * already on screen touches nothing and is allowed with a
		 * draft open; see dump_needs_rebuild.
		 */
		return v->path && v->path[0] &&
		       (!draft_edited(&v->ed) ||
			!dump_needs_rebuild(v, i == BI_DUMP_EMU));
	/* And this one, for the same reason: it rebuilds, always. */
	case BI_SEPARATE:
		return v->path && v->path[0] && !draft_edited(&v->ed);
case BI_UNPACKER:
		/* Whether it APPLIES is bar_shown's - emu_here acts on the
		 * selected object. What is left here is the wait: an edited
		 * draft, or nothing open. */
		return v->path && v->path[0] && !draft_edited(&v->ed);
	/*
	 * x86 only, because the decoder in here is x86 - offering it
	 * on an ARM object would print an answer that is wrong in a way a reader
	 * cannot see. An object with no format at all IS offered: raw bytes out
	 * of an encoder are exactly what this is for, and the mode is then the
	 * reader's to pick.
	 */
	case BI_DISANALYSE:
	case BI_DISASM: {
		const struct object *ob = cur_obj(v);

		/* The format and the architecture are bar_shown's. What is left
		 * is whether there are bytes to show right now: a large child
		 * is scanned and not kept, and that is a state rather than a
		 * property of the object. */
		return ob && ob->buf.p && v->rgn_len != 0;
	}
	case BI_DASH:      return 1;
	/* Manage > Syndromes: the session's tag catalog, kept in the view (nothing is stored). Needs no object. */
	case BI_SYNTAB:    return 1;
	/* Manage > Pathogens: the session's catalog, kept in the view (nothing is stored). Needs no object. */
	case BI_FAMILIES:  return 1;
	/* Needs a file to step from, and nothing the reader typed that would be
	 * lost - moving on is the one action here that throws work away. */
	case BI_NEXT:
	case BI_PREV:      return v->path && v->path[0] && !draft_edited(&v->ed);
	/*
	 * Rebuilding replaces the database this file was examined against, so
	 * the file is examined again - which throws the draft away for the same
	 * reason stepping to another file does.
	 */
	case BI_REBUILD:   return v->basedir[0] && v->dbdir[0] &&
				  !draft_edited(&v->ed);
	case BI_QUIT:      return 1;
	case BI_FIND:      return 1;
	case BI_GOTO:      return 1;            /* draw_goto / goto_take */
	/*
	 * THE INFECTION DIALOG IS SWITCHED OFF FOR NOW (owner): the item stays in the menu, greyed. The analysis behind its two
	 * tabs (shellcode candidates and the infection-prone regions) is to be reworked against real-world samples before it is
	 * offered. When it is switched back on, the item is live when the engine reported infected ranges on the object (Infected
	 * data) or the format can carry shellcode (Shellcode, a capability of the format: kv_cap); the dialog is complete.
	 */
	case BI_INFECTION: return 0;
	/* Always: the text it decodes usually comes from outside the file, so
	 * there is nothing about the object that could make it unavailable. */
	case BI_ENCSTR:    return 1;
	case BI_KEYS:
	case BI_ABOUT:     return 1;
	/*
	 * The filter, live whenever there is a log to filter.
	 *
	 * It has to be said, because the default below is OFF - which is the
	 * right default for a table where a missing case means somebody added
	 * an item and has not decided what makes it usable yet, and which is
	 * exactly what happened here: the whole submenu was unreachable
	 * because clicking the parent hit the disabled path and only printed a
	 * message. The children are toggles and need nothing but the log; the
	 * ones for verbs the log does not contain are not disabled, they are
	 * not there at all - see bar_shown.
	 */
	case BI_FILTER:
	case BI_FILT_APPLY:
		return v->log != NULL;
	default:
		if (bar_filt_verb(i) > 0)
			return v->log != NULL;
		return 0;
	}
}

/*
 * WHY AN ITEM IS GREY, IN THE WORDS A READER NEEDS.
 *
 * bar_enabled decides; this explains, and the two are kept apart so the
 * decision has one home. Every reason here is the negation of the test there -
 * read them side by side when either changes.
 *
 * NULL for an item whose greyness explains itself: an item disabled because no
 * file is open is answered by the empty screen.
 */
const char *bar_why_off(struct view *v, int i)
{
	switch (i) {
	case BI_DISANALYSE:
	case BI_DISASM: {
		/*
		 * TWO REASONS, AND ONE OF THEM WAS BEING TOLD AS THE OTHER.
		 *
		 * bar_enabled refuses this both for an object with no bytes to
		 * read and for one whose machine this build cannot decode - it
		 * says so itself, in the note about ARM. The single message
		 * here covered both, so an AArch64 binary full of code was
		 * told it had none. Split, because the two want different
		 * things from the reader: one is a file with nothing in it,
		 * the other is a gap in this build.
		 */
		const struct object *o = cur_obj(v);

		if (!o || !o->buf.p || !v->rgn_len)
			return "Nothing to disassemble - this object has no "
			       "bytes in the selected region";
		return "This build decodes x86 only - the object's machine is "
		       "something else";
	}
	case BI_NEXT:
	case BI_PREV:
	case BI_UNPACKER:
	case BI_DUMP_STATIC:
	case BI_DUMP_EMU:
		if (draft_edited(&v->ed))
			return "Finish or undo the draft first";
		return NULL;
	case BI_REBUILD:
		/*
		 * THREE TESTS IN bar_enabled, AND THIS ANSWERED FOR TWO.
		 *
		 * Rebuilding also needs the draft settled, because it examines
		 * the file again and that throws the draft away. Grey for that
		 * reason, the reader was told to set a database and a tree they
		 * had already set - a message that sends somebody looking in
		 * the wrong place is worse than no message, which is the whole
		 * reason this function exists.
		 */
		if (draft_edited(&v->ed))
			return "Finish or undo the draft first - rebuilding "
			       "examines the file again";
		return "Set both a database and a content tree first";
	default:
		return NULL;
	}
}
