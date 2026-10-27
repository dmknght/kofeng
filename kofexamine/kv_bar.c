#define _GNU_SOURCE
#include "kv.h"



/*
 * The menu's three states, as one scheme rather than three unrelated choices.
 *
 * They were: enabled on a dark panel, disabled on a WHITE one, and the cursor
 * as a bare reverse-video. So the drop-down had two background colours at once,
 * the brighter of the two belonged to the items you cannot use - which made the
 * dead entries the loudest thing on screen - and the cursor, being a reverse of
 * whatever happened to be current, came out the same white as the disabled
 * rows. Three states, two of them indistinguishable, and the emphasis backwards.
 *
 * One background for the whole panel, so it reads as one panel; disabled differs
 * only in how bright its text is, which is what "disabled" should look like; and
 * the cursor is the one row that inverts, stated explicitly instead of reversing
 * whatever the terminal was left holding.
 */

/*
 * 37 and not 90 for the disabled row, which is the whole trick.
 *
 * 90 is bright black and 100 is bright black as a background - the same colour
 * twice, so the label is not dim, it is GONE. The note on the Save button in
 * this file says exactly that and this managed to walk into it anyway while
 * fixing something else. 37 is the ordinary white: clearly weaker than the 97
 * beside it, still ink on the panel rather than a hole in it.
 *
 * The rule this leaves behind: a foreground and a background from the same
 * pair - 30/40, 37/47, 90/100, 97/107 - is never a colour, it is an erasure.
 */

#define BAR_W 30


static const struct {
	const char *label;
	int         menu;
	/* The item this one hangs under, or -1 for a top-level entry. */
	int         parent;
	/*
	 * Draw a rule ABOVE this item.
	 *
	 * On the item BELOW the break rather than the one above it, so
	 * appending to a group does not move the break - which is the
	 * mistake the other spelling invites.
	 *
	 * BOTH the drawer and the hit test must count the extra row. They
	 * are two separate walks over this table and they have disagreed
	 * before - see the note on bar_col - so the row comes from one
	 * helper, bar_gap, that both call.
	 */
	int         sep;
} bar_item[BI_COUNT] = {
	{ "Next File",      BM_FILE, -1, 0 },
	{ "Previous File",  BM_FILE, -1, 0 },
	{ "Quit",           BM_FILE, -1, 1 },
	{ "Find...",        BM_EDIT, -1, 0 },
	{ "Go to...",       BM_EDIT, -1, 0 },
	{ "Dashboard",         BM_ANALYSIS, -1, 0 },
	{ "Pathogens",  BM_MANAGE, -1, 0 },
	{ "Syndromes",         BM_MANAGE, -1, 0 },
	{ "Disassembly",       BM_ANALYSIS, -1, 0 },
	{ "Analyze disassembly", BM_ANALYSIS, -1, 0 },
	{ "Infection",                BM_ANALYSIS, -1, 0 },
	{ "Decode string",            BM_ANALYSIS, -1, 0 },
	{ "Unpack with ...",   BM_ANALYSIS, -1, 1 },
	{ "Dump",              BM_ANALYSIS, -1, 0 },
	{ "Static unpacker",   BM_ANALYSIS, BI_DUMP, 0 },
	{ "Emu unpacker",      BM_ANALYSIS, BI_DUMP, 0 },
	/* The same word, because a reader should not have to care which of the
	 * two they are looking at - they never see both. */
	{ "Dump",              BM_ANALYSIS, -1, 0 },
	{ "Separate children", BM_ANALYSIS, -1, 0 },
	{ "Rebuild database",  BM_ANALYSIS, -1, 0 },
	{ "Filter events",     BM_ANALYSIS, -1, 1 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "",                  BM_ANALYSIS, BI_FILTER, 0 },
	{ "Apply filter",      BM_ANALYSIS, BI_FILTER, 1 },
	{ "Keyboard",          BM_HELP, -1, 0 },
	{ "About",          BM_HELP, -1, 0 }
};

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
 * The enum and the table are two lists of the same items, written apart, and
 * an item is added to both by hand.
 *
 * MORE initialisers than the array holds is a compile error already. FEWER is
 * SILENT: the array zero-fills, so a forgotten row becomes an item with a NULL
 * label and menu 0 - drawn on the File menu, crashing whatever prints it. This
 * is the cheapest possible way to be told instead, and it costs nothing at
 * run time.
 */
_Static_assert(sizeof bar_item / sizeof bar_item[0] == BI_COUNT,
	       "the menu table and its enum disagree");

/* Does this item open a submenu rather than do something. */
int bar_has_sub(int i)
{
	int k;

	for (k = 0; k < BI_COUNT; k++)
		if (bar_item[k].parent == i)
			return 1;
	return 0;
}

/*
 * The wording an item shows now, which for the unpacker switch is not the
 * wording in the table: a menu entry should say what pressing it does, and what
 * it does depends on which unpacker filled the tree.
 */
/* The verb a filter child stands for, or -1. */
/*
 * WHICH VERB A FILTER SLOT STANDS FOR, in the order a reader reads.
 *
 * It was the verb's own number, which is the order the collector learnt its
 * event ids in - so ImageLoad and ImageUnload sat three rows apart with file
 * events between them, and a reader looking for "the image ones" had to scan
 * the whole list to find out there were two.
 *
 * Sorted by NAME instead, which puts the pairs together for the reason they
 * read as pairs: they share a prefix because they are the same subject. The
 * numbers do not change - this is a presentation order and nothing stored ever
 * sees it.
 *
 * Built once and kept, because it is asked for by every walk over the menu -
 * the drawer, the hit test, the keyboard cursor - and it is the same answer
 * every time.
 */
static int bar_filt_verb(int i)
{
	static uint8_t order[KOF_EVT_TYPE_COUNT];
	static int n_order;
	int k;

	if (i < BI_FILT_V0 || i > BI_FILT_V27)
		return -1;

	if (!n_order) {
		/* Insertion sort over a couple of dozen names, once. Verb 0 is
		 * not a verb and KOF_EVT_CONT is not an event a reader filters
		 * on - see log_scan_verbs - so neither is offered a slot. */
		int vb;

		for (vb = 1; vb < KOF_EVT_TYPE_COUNT; vb++) {
			const char *name;
			int at;

			if (vb == KOF_EVT_CONT)
				continue;
			name = kof_evt_verb_name((uint16_t)vb);
			for (at = n_order; at > 0; at--) {
				const char *prev =
					kof_evt_verb_name(order[at - 1]);

				if (strcmp(prev, name) <= 0)
					break;
				order[at] = order[at - 1];
			}
			order[at] = (uint8_t)vb;
			n_order++;
		}
	}

	k = i - BI_FILT_V0;
	return k < n_order ? (int)order[k] : -1;
}

static const char *bar_label(struct view *v, int i)
{
	/*
	 * "Unpack with X", naming the ACTION first and the tool second.
	 *
	 * Three earlier wordings were worse. "Reopen with" named the mechanism
	 * rather than the result. "Examine with emulator" read as though the
	 * menu would open the emulator and show its insides. "Use Emu unpacker"
	 * put the tool first and the verb nowhere - a row that begins "Use"
	 * does not say what happens, and "Emu unpacker" as a noun is a thing
	 * this program never calls anything anywhere else.
	 *
	 * "emulator" in full: the row is the widest in its menu either way, so
	 * the abbreviation bought nothing and cost a reader the word.
	 */
	if (i == BI_UNPACKER) {
		(void)v;
		/*
		 * "Unpack", not "Unpack with emulator", because it no longer
		 * names a mechanism: the engine's modules are offered the
		 * object and the interpreter is the fallback - see emu_here.
		 * A row that promised the emulator and then quietly used a
		 * static unpacker would be describing the wrong thing, and a
		 * reader choosing between two rows would be choosing between
		 * an action and an implementation detail.
		 */
		return "Unpack";
	}
	/* Says which way the toggle goes, for the reason above. */
	if (i == BI_DISASM)
		return v->dis_open ? "Hide disassembly" : "Show disassembly";
	/*
	 * A FILTER ROW SHOWS ITS OWN STATE, because it is a checkbox and not a
	 * command: a reader has to be able to see what is on before deciding
	 * what to change, and a row that only acted would make them toggle it
	 * to find out.
	 *
	 * The verb's name comes from kof_evt_verb_name, the same one the event
	 * panel prints, so the menu and the rows cannot disagree about what a
	 * verb is called. A row that is off says so; one that is on says so
	 * immediately, which is the contract the other branches already have.
	 */
	{
		int verb = bar_filt_verb(i);

		if (verb > 0) {
			static char row[40];

			snprintf(row, sizeof row, "[%c] %s",
				 (v->log_keep & (1u << (unsigned)verb)) ? 'x'
									: ' ',
				 kof_evt_verb_name((uint16_t)verb));
			return row;
		}
	}
	return bar_item[i].label;
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

static int bar_shown(struct view *v, int i)
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
		/* This disassembler is x86. An image of another architecture
		 * would be decoded as instructions it does not contain, which
		 * is not a thing to offer and then explain. */
		return !ob->fmt || ob->ctx.arch == KGENOME_ARCH_X86 ||
		       ob->ctx.arch == KGENOME_ARCH_X86_64;
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

/*
 * How many rows this item takes before its own: 1 for a rule above it, else 0.
 *
 * One function, called by BOTH the drawer and the hit test, because they are
 * two walks over the same table and the whole class of bug here is one of them
 * counting a row the other does not. See the note on bar_col for the last time
 * that happened.
 */
static int bar_gap(struct view *v, int i)
{
	return (i > 0 && bar_item[i].sep && bar_shown(v, i)) ? 1 : 0;
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
	/* SWITCHED OFF for now (owner): Syndromes stays listed and greyed. It is the old Syndrome table (kv_syntable.c, kv_syn.c and the
	 * tag-source backend under databases/tagsrc*): the code stays and is to be removed later, on request. When it is switched back
	 * on the condition was `v->syn != NULL` (a directory of files, not a property of the object). */
	case BI_SYNTAB:    return 0;
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
 * Where each menu's block starts on the bar.
 *
 * Derived from what draw_bar actually emits - a space, the name, a space - not
 * from a guess at it. They disagreed by one column per menu, so Help's title sat
 * at 25 while everything that used this number thought it was at 27: its
 * drop-down opened three columns to the right of the word it belongs to, and
 * clicking the left half of "Help" opened Analysis instead.
 */
int bar_col(int m)
{
	int c = 2, i;

	for (i = 0; i < m; i++)
		c += (int)strlen(bar_name[i]) + 2;
	return c;
}

/*
 * The menu bar's drop-down and its submenu, as kv_menu sees them.
 *
 * Two descriptors over one table: `shown` is what distinguishes them, because a
 * drop-down holds the items of one menu that have no parent and a submenu holds
 * the children of one of those. Everything after that - where the rows land,
 * which one a click hit, how a greyed one is drawn - is the same question and
 * is now answered in one place.
 */
static int bm_shown_top(void *ud, int i)
{
	struct view *v = ud;

	return bar_item[i].menu == v->bar_open && bar_item[i].parent < 0 &&
	       bar_shown(v, i);
}

static int bm_shown_sub(void *ud, int i)
{
	struct view *v = ud;

	return bar_item[i].parent == v->bar_sub && bar_shown(v, i);
}

static int bm_enabled(void *ud, int i) { return bar_enabled((struct view *)ud, i); }
static int bm_rule(void *ud, int i)    { return bar_gap((struct view *)ud, i); }
static int bm_sub(void *ud, int i)     { (void)ud; return bar_has_sub(i); }
static const char *bm_label(void *ud, int i)
{
	return bar_label((struct view *)ud, i);
}

static struct kv_menu bar_menu(struct view *v, int sub)
{
	struct kv_menu m;

	memset(&m, 0, sizeof m);
	m.n = BI_COUNT;
	m.ud = v;
	m.shown = sub ? bm_shown_sub : bm_shown_top;
	m.enabled = bm_enabled;
	/*
	 * A submenu draws rules too. It used not to, on the grounds that the
	 * children of one item are one group - which held while the only
	 * submenu was two dump kinds, and stopped holding with the event
	 * filter: a list of checkboxes followed by the button that acts on
	 * them is two groups, and without a rule between them Apply reads as
	 * one more thing to tick.
	 *
	 * It still never opens a further submenu - nothing nests that deep,
	 * and has_sub is what would draw the arrow saying it did.
	 */
	m.rule_above = bm_rule;
	m.has_sub = sub ? NULL : bm_sub;
	m.label = bm_label;
	m.w = BAR_W;
	m.c_on  = BAR_ON;
	m.c_off = BAR_OFF;
	m.c_cur = BAR_CUR;
	return m;
}

void draw_bar(struct out *o, struct view *v)
{
	int m, i;

	row_start(o, 1, 1);
	out_str(o, A_HEAD " ");
	for (m = 0; m < BM_COUNT; m++) {
		/* The open menu's title wears the same highlight its panel
		 * uses, so the two read as one control rather than two. */
		if (m == v->bar_open)
			out_fmt(o, BAR_CUR " %s " A_HEAD, bar_name[m]);
		else
			out_fmt(o, " %s ", bar_name[m]);
	}
	for (i = (int)o->col_hint; i < g_cols; i++)
		out_str(o, " ");
	out_str(o, A_OFF);

	if (v->bar_open < 0)
		return;

	/* The drop-down, drawn over whatever is under it. */
	{
		struct kv_menu top = bar_menu(v, 0);
		int col = bar_col(v->bar_open);

		kv_menu_draw(o, &top, 2, col, v->bar_sel, v->bar_sub);

		/* The open submenu, beside its parent rather than over it. */
		if (v->bar_sub >= 0) {
			struct kv_menu sub = bar_menu(v, 1);
			int r = kv_menu_row_of(&top, v->bar_sub);

			if (r >= 0)
				kv_menu_draw(o, &sub, 2 + r, col + BAR_W,
					     v->bar_sel, -1);
		}
	}
}

/*
 * Which item a click on an open drop-down landed on, or -1.
 *
 * The submenu is tested FIRST. It is drawn over whatever is to the right of its
 * parent, so a click inside it is inside the submenu whatever else is there -
 * testing the parent panel first would answer for a column the reader cannot
 * see.
 */
int bar_item_at(struct view *v, int row, int col)
{
	struct kv_menu top = bar_menu(v, 0);
	int c0 = bar_col(v->bar_open);

	/* The submenu column first: it is drawn over what would otherwise be
	 * empty screen beside the drop-down, so a click there is its click. */
	if (v->bar_sub >= 0 && col >= c0 + BAR_W && col < c0 + 2 * BAR_W) {
		struct kv_menu sub = bar_menu(v, 1);
		int r = kv_menu_row_of(&top, v->bar_sub);

		return r < 0 ? -1 : kv_menu_at_row(&sub, row - (2 + r));
	}
	if (col < c0 || col >= c0 + BAR_W)
		return -1;
	/* A rule's own row belongs to nothing, which kv_menu_at_row answers
	 * with -1 rather than with the item under it. */
	return kv_menu_at_row(&top, row - 2);
}

/* The items of one menu, in table order. Returns how many, up to `cap`. */
static int bar_items_of(struct view *v, int menu, int *out, int cap)
{
	int i, n = 0;

	for (i = 0; i < BI_COUNT && n < cap; i++)
		if (bar_shown(v, i) && bar_item[i].menu == menu &&
		    bar_item[i].parent < 0)
			out[n++] = i;
	return n;
}

/*
 * The rows of a submenu: the children of `parent`.
 *
 * Same filter as the loop that DRAWS them, because a cursor that walks a
 * different set from the one on the screen is a cursor that skips rows or rests
 * on rows nobody can see.
 */
static int bar_kids_of(struct view *v, int parent, int *out, int cap)
{
	int i, n = 0;

	for (i = 0; i < BI_COUNT && n < cap; i++)
		if (bar_shown(v, i) && bar_item[i].parent == parent)
			out[n++] = i;
	return n;
}

/*
 * Open item `i`'s submenu and put the cursor on its first usable row.
 *
 * While a submenu is open the cursor lives INSIDE it - bar_sel holds a child -
 * and the parent stays lit through bar_sub. Without this the submenu drew rows
 * that nothing selected and Enter ran the parent again, so the keyboard could
 * open a submenu and then not reach anything in it.
 */
void bar_enter_sub(struct view *v, int i)
{
	int kids[BI_COUNT], n = bar_kids_of(v, i, kids, BI_COUNT), k;

	v->bar_sub = i;
	v->bar_sel = n ? kids[0] : i;
	for (k = 0; k < n; k++)
		if (bar_enabled(v, kids[k])) {
			v->bar_sel = kids[k];
			break;
		}
}

/*
 * Open a menu by index and land the cursor on its first usable item.
 *
 * First ENABLED, not first: a menu whose top row is greyed - File's "Open",
 * which is not built yet - would otherwise open with the cursor on something
 * that does nothing, and an arrow press to leave it reads as the key not
 * working.
 */
void bar_open_menu(struct view *v, int menu)
{
	int items[BI_COUNT], n = bar_items_of(v, menu, items, BI_COUNT), i;

	/*
	 * AND A BAR MENU OPENS EMPTY TOO, for the reason menu_open_at gives.
	 * This lit the first enabled item, so opening the bar with the pointer
	 * pointed at a command nobody had chosen.
	 */
	(void)items; (void)n; (void)i;
	v->bar_open = menu;
	v->bar_sub = -1;
	v->bar_sel = -1;
}

/* Move the cursor up or down within the open menu, skipping disabled rows so
 * the cursor never rests on something Enter would ignore. */
void bar_move_item(struct view *v, int dir)
{
	int items[BI_COUNT], n, cur = -1, i, step;

	if (v->bar_open < 0)
		return;
	n = v->bar_sub >= 0 ? bar_kids_of(v, v->bar_sub, items, BI_COUNT)
			    : bar_items_of(v, v->bar_open, items, BI_COUNT);
	for (i = 0; i < n; i++)
		if (items[i] == v->bar_sel)
			cur = i;
	/*
	 * FROM NOTHING, EITHER END - see menu_step. A menu now opens with no
	 * item lit, and `cur` is then -1: stepping down must land on the first
	 * item and stepping up on the LAST, which -1 gives for down and not
	 * for up.
	 */
	if (cur < 0 && dir < 0)
		cur = 0;
	for (step = 0; step < n; step++) {
		cur = (cur + dir + n) % n;
		if (bar_enabled(v, items[cur])) {
			v->bar_sel = items[cur];
			return;
		}
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
static const char *bar_why_off(struct view *v, int i)
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


void bar_run(struct view *v, int i)
{
	if (!bar_enabled(v, i)) {
		/*
		 * A GREYED ITEM THAT DOES NOTHING WHEN CLICKED TEACHES NOTHING.
		 *
		 * Any item can be pressed from any pane, so it answers through
		 * act_msg - the slot that shows wherever the reader is and fades
		 * on its own.
		 */
		const char *why = bar_why_off(v, i);

		if (why) {
			snprintf(v->act_msg, sizeof v->act_msg, "%s", why);
			v->act_ok = 0;
		}
		return;
	}
	/* A parent opens; it does not act. Clicking it again closes what it
	 * opened, so the same press undoes itself. */
	if (bar_has_sub(i)) {
		if (v->bar_sub == i) {
			v->bar_sub = -1;
			v->bar_sel = i;
		} else {
			bar_enter_sub(v, i);
		}
		return;
	}
	/*
	 * A CHECKBOX DOES NOT CLOSE THE MENU, which is the whole difference
	 * between it and every other row here.
	 *
	 * Turning three verbs off means three presses, and a menu that shut
	 * after each one would mean reopening and re-descending twice. So the
	 * toggle happens before the close below and returns - the submenu
	 * stays exactly where it was, with the row now ticked.
	 */
	{
		int verb = bar_filt_verb(i);

		if (verb > 0) {
			v->log_keep ^= 1u << (unsigned)verb;
			return;
		}
	}

	v->bar_open = -1;
	v->bar_sel = -1;
	v->bar_sub = -1;
	switch (i) {
	case BI_FILT_APPLY:
		/*
		 * Applied to the OBJECT PANEL by rebuilding the window: the
		 * filter is part of what a window contains, so there is one
		 * place that knows about it and no second filtering step for
		 * the two to disagree at.
		 *
		 * Back to the start of the log rather than staying put,
		 * because the event the selection was on may be one of the
		 * ones just hidden - and a selection pointing at a row that no
		 * longer exists is the way a panel starts describing the wrong
		 * event.
		 */
		if (v->log) {

			v->log_first = 0;
			log_window(v);
			tree_build(v);
			v->sel_node = 0;
			v->sel_a = v->sel_b = KGENOME_BROKEN;
			v->dis_have = 0;
			view_select(v);
			if (!v->log_keep)
				snprintf(v->act_msg, sizeof v->act_msg,
					 "Every event type is unticked - "
					 "nothing to show");
			else
				snprintf(v->act_msg, sizeof v->act_msg,
					 "Filtered: %u event(s) in the window",
					 (unsigned)(v->n_obj ? v->n_obj - 1u
							     : 0));
			v->act_ok = 1;
		}
		break;
	/*
	 * IT HAD NO CASE, so it fell to `default: break;` - the menu closed and
	 * the program stayed open. That is the failure the note further down
	 * describes for BI_FIND, and this was the other instance of it: an item
	 * bar_enabled reports live, with nothing behind it.
	 *
	 * No confirmation, matching Ctrl+Q, which leaves whatever is open
	 * without asking. Two ways out that disagree about that would be worse
	 * than either.
	 */
	case BI_QUIT:    v->quit = 1; break;
	case BI_FIND:
		v->find_open = 1;
		v->goto_open = 0;              /* they share the box */
		v->edit = 500;
		v->ed.dr.warn[0] = 0;
		break;
	/* An item has to be here as well as in
	 * bar_enabled: an item that reports itself live and has no case falls
	 * to `default: break;` - the menu closes and nothing happens, which
	 * is exactly how BI_GOTO looked before the dialog existed. */
	case BI_SYNTAB:
		syn_open(v);
		return;
	case BI_FAMILIES:
		fam_open(v);
		break;
	case BI_INFECTION:
		prop_show_infection(v);
		v->act_msg[0] = 0;
		break;
	case BI_GOTO:
		v->goto_open = 1;
		v->find_open = 0;      /* they share the box - see draw_goto */
		v->gotobuf[0] = 0;
		v->num_fresh = 1;
		v->edit = 520;
		v->ed.dr.warn[0] = 0;
		break;
	case BI_DUMP_STATIC: dump_all(v, 0); break;
	case BI_DUMP_PLAIN:  dump_all(v, 0); break;
	case BI_DUMP_EMU:    dump_all(v, 1); break;
	case BI_UNPACKER: emu_here(v); break;
	case BI_DISASM:   dis_toggle(v, 0, KGENOME_BROKEN); break;
	case BI_DISANALYSE: dis_analyse(v); break;
	case BI_NEXT:    open_step(v, +1); break;
	case BI_PREV:    open_step(v, -1); break;
	case BI_SEPARATE: separate_now(v); break;
	case BI_REBUILD: rebuild_db(v); break;
	case BI_ENCSTR:
		enc_open_with(v, NULL, 0);      /* keeps whatever was typed */
		v->act_msg[0] = 0;
		break;
	case BI_DASH:
		/* Whatever the last copy or dump said belongs to the screen
		 * it was said on, not to a page opened afterwards. */
		prop_show(v);
		v->act_msg[0] = 0;
		break;
	case BI_KEYS:    v->help_open = 1; v->help_off = 0; break;
	case BI_ABOUT:   v->help_open = 2; v->help_off = 0; break;
	default: break;
	}
}
