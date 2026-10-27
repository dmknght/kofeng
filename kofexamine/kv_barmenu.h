/*
 * kv_barmenu.h - the menu bar (menus and items) and the properties tabs.
 *
 * A part of kv.h, included by it and by nothing else.
 */
#ifndef KV_BARMENU_H
#define KV_BARMENU_H

/* ---- the menu bar ---------------------------------------------------------
 *
 * One row at the top, and the place every command has a name.
 *
 * The context menu on the hex pane stays: it acts on what is under the pointer
 * and is worth having there. This is for the commands that act on the whole
 * session - opening, saving, searching, and the two Help dialogs - which have
 * nowhere else to be discovered. Nothing here is only reachable from here; the
 * chords still work, and the bar is where somebody finds out that they exist.
 */
/*
 * THERE IS NO ANALYSE MENU, AND THAT IS A DECISION.
 *
 * It held Strings and Symbols, and neither has anything behind it. The engine's
 * parsers are shallow on purpose: for a PE they record the sixteen data
 * directories as an RVA and a size and walk none of them, so IMPORT is an index
 * rather than a table; for an ELF they record section names and never read
 * .dynsym or resolve a string table. A symbol list would therefore not be a
 * view of something the engine knows - it would be two new walkers over
 * untrusted structures, written in the front end, duplicating the layer that
 * deliberately stops short of them.
 *
 * What the tool CAN say about an object is what the engine already worked out,
 * and that is one page rather than a menu of them. So it is one item, under
 * File, next to the other things that are about the file in hand.
 */
enum bar_menu {
	BM_FILE = 0, BM_EDIT, BM_ANALYSIS,
	/* Managing the catalogs the tool edits (malware families, syndromes). */
	BM_MANAGE,
	/* Help is always the last menu on the bar (owner). */
	BM_HELP, BM_COUNT
};

/*
 * Dump, next to them, because it is about this file too.
 *
 * The same directory kofexamine --dump writes, from the same code - see
 * kof_dump_object. Here because the viewer is where the question comes up: a
 * region is what the parse decided rather than anything on disk, so the way to
 * check what a rule will actually search is to have the bytes of that region in
 * a file. Reaching for a second tool to get them, on the object already open and
 * already parsed, was the gap.
 *
 * It writes the WHOLE tree - the file and everything the unpackers recovered
 * from it - not the selected node, and that is deliberate. The objects are
 * already collected and already parsed, so dumping one of them and making
 * somebody come back for the next is a menu item that has to be used repeatedly
 * to do one thing.
 */
enum bar_item {
	/* File menu, in the order the menu shows them: moving between files, a rule, Quit. The table bar_item in kv_bar.c is
	 * positional, so its entries follow this order. */
	BI_NEXT = 0, BI_PREV,
	BI_QUIT,
	BI_FIND, BI_GOTO,
	/*
	 * Analysis is what the tool does TO an object, as against File which is
	 * what it does to the draft. Dashboard and Dump both answer questions
	 * about the bytes in front of the reader and neither writes a signature,
	 * so they belong together and not beside Save.
	 */
	/*
	 * ANALYSIS, in the order a reader works through it: what the object IS,
	 * then what is inside it, then what to DO about it. The rule after
	 * BI_INFECTION is where that turns over - everything above answers a
	 * question, everything below writes something or re-runs the scan.
	 */
	BI_DASH,
	/* MANAGE menu, in the order it shows: the malware families, then the syndrome table. */
	BI_FAMILIES,
	/* The tag sources, as four tables: this is what the diagnose panel's Tag cells pick from. It needs no object: it is
	 * about the directory. SWITCHED OFF for now and moved out of Analysis into Manage (owner); the code stays. */
	BI_SYNTAB,
	/* Label replaced at draw time by the mode's own wording - a menu that
	 * offers "Show" and "Hide" side by side always has one of them wrong. */
	BI_DISASM,
	/* Reads the whole object's code once and names what it finds - see dis_analyse. The panel then shows labels and comments from it. */
	BI_DISANALYSE,
	/*
	 * The Infection dialog: two tabs, the places of the binary an infector commonly uses (with the engine's infected
	 * ranges highlighted) and the data that carries execute permission (with the shellcode finder's answer). It runs
	 * nothing: the engine's ranges and the finder's answer were cached on the object when it was examined.
	 */
	BI_INFECTION,
	/*
	 * The decoder. Beside BI_INFECTION because it answers the same kind of
	 * question - "what is in here that is not in plain sight" - and above
	 * the rules that act, because it only looks.
	 */
	BI_ENCSTR,
	BI_UNPACKER,
	/*
	 * Beside BI_UNPACKER because it is the same machine doing the work -
	 * one runs the object to RECOVER bytes, this one runs it to record
	 * what it ASKED FOR. A reader who has just unpacked something is
	 * exactly the reader who wants the second question answered.
	 */
	/*
	 * TWO DUMPS, AND ONLY ONE OF THEM IS EVER DRAWN.
	 *
	 * BI_DUMP is the executable's: it opens a submenu because there are two
	 * ways to peel such a file - read it, or run it - and which one worked
	 * is the interesting part of the answer.
	 *
	 * BI_DUMP_PLAIN is every other file's. A PDF cannot be run at all; its
	 * members come out by being read and there is no second way, so the
	 * submenu was asking the reader to choose between a thing and nothing.
	 * It acts instead of opening.
	 *
	 * Two ITEMS rather than one that changes shape, because the shape is
	 * what a reader learns: an item that sometimes opens a box and
	 * sometimes fires is an item nobody can predict. Each of these is one
	 * thing, and dump_has_choice decides which exists.
	 */
	BI_DUMP, BI_DUMP_STATIC, BI_DUMP_EMU, BI_DUMP_PLAIN,
	/*
	 * Only ever drawn in the one mode that can use it - see
	 * view.heur_off. Once the children are separated there is nothing for
	 * it to do, and an item that does nothing is hidden rather than
	 * greyed: see the note on `enabled` in kofview.h.
	 */
	BI_SEPARATE,
	BI_REBUILD,

	/*
	 * FILTER EVENTS, for a log - a parent with one child per verb and an
	 * Apply below them.
	 *
	 * One slot per possible verb rather than a dynamic list, because
	 * bar_item is a table indexed by this enum and every walk over it -
	 * the drawer, the hit test, the keyboard cursor - agrees only because
	 * they all read the same table. A verb the log does not contain is
	 * hidden by bar_shown, which is the same mechanism that hides Symbols
	 * for an object with none.
	 */
	BI_FILTER,
	BI_FILT_V0, BI_FILT_V1, BI_FILT_V2, BI_FILT_V3, BI_FILT_V4,
	BI_FILT_V5, BI_FILT_V6, BI_FILT_V7, BI_FILT_V8, BI_FILT_V9,
	BI_FILT_V10, BI_FILT_V11, BI_FILT_V12, BI_FILT_V13, BI_FILT_V14,
	BI_FILT_V15, BI_FILT_V16, BI_FILT_V17, BI_FILT_V18, BI_FILT_V19,
	BI_FILT_V20, BI_FILT_V21, BI_FILT_V22, BI_FILT_V23, BI_FILT_V24,
	BI_FILT_V25, BI_FILT_V26, BI_FILT_V27,   /* KOF_EVT_TYPE_COUNT - 2 = 27 verbs */
	BI_FILT_APPLY,

	BI_KEYS, BI_ABOUT,
	BI_COUNT
};

/*
 * THE DASHBOARD IS A BOOK OF FIVE PAGES, selected from a tab strip in its top rule (by a click, and by nothing else).
 *
 * Overview is what the page always was: the object, then what its header says, its regions, the anomalies and the
 * heuristic. Segments and Sections are one table each over what the header describes (a PE has no segments; its
 * Segments page says so). Imports and Exports are the symbol tables that were a dialog of their own.
 *
 * WHICH ONE IS SHOWING LIVES IN THE VIEW (view.prop_pg): the page is rebuilt from scratch every frame, and a choice
 * kept in the builder would be forgotten on the next keystroke. A table has no scroll state of its own: the page's
 * vertical offset (view.prop_off) and sideways offset (view.prop_hoff) move every table on it.
 *
 * THE INFECTION DIALOG IS THE SAME DIALOG with a second book of two pages (PROP_PG_INF_*: Infected data, Shellcode),
 * chosen by view.prop_inf; its strip, tables, scroll, selection and count are the dashboard's, not copies of them.
 */
enum prop_page {
	PROP_PG_OVERVIEW = 0,
	PROP_PG_SEGMENTS,
	PROP_PG_SECTIONS,
	PROP_PG_IMPORTS,
	PROP_PG_EXPORTS,
	PROP_PG_INF_DATA,       /* the Infection dialog's tabs (view.prop_inf): Infected data, Shellcode */
	PROP_PG_INF_SHELL,
	PROP_PG_COUNT
};
/* How far one wheel notch and one sideways key move the dashboard page, in lines and columns. */
#define PROP_WHEEL_ROWS 3
#define PROP_WHEEL_COLS 8
#define PROP_KEY_COLS   4

/*
 * One object's identity, as rows.
 *
 * Shared by the object being looked at and by every object above it, so the two
 * cannot describe the same thing differently - the reason this is a function
 * and not a second copy of the block.
 *
 * `full` is what separates them. The object in focus gets a row per fact,
 * because that is what the panel is for. An enclosing object gets size, format
 * and arch folded onto one line: a chain four deep would otherwise be
 * twenty-four rows of context above the thing somebody actually opened.
 */
/*
 * THE COPY BUTTON'S LABEL, in one place because two things need it: the row
 * that draws it and the click that carries it out.
 *
 * The click finds it by SEARCHING THE DRAWN ROW for this text. That is not the
 * obvious way round - the row could record its own columns - and it is the way
 * round that works: prop_object_rows used to record an index into the full row
 * list while the click path is answered in indices into the rows the page
 * actually put on screen, which begin at the scroll offset. Two different
 * numbers, compared as one.
 */
#define PROP_CP_LABEL "[ Copy full path ]"

/*
 * PICK A FILE OUT OF A DIRECTORY - the first, or the one either side of a name.
 *
 * One walk answering all three questions, because they are one question asked
 * with different comparisons, and two walks are two chances for the ordering to
 * drift. When it drifted the symptom was quiet: the folder opened on the file
 * one rule called first, and the very first step forward skipped it, because
 * the other rule did not think it was a file at all.
 *
 * Ordering is by NAME rather than by whatever readdir hands back, which is the
 * only property that makes forward-then-back return to where it started.
 *
 * `from` is the base name to move away from, and is ignored - may be NULL - for
 * PICK_FIRST. Returns 0 and touches nothing when there is no such file; the
 * caller says so in whatever terms suit where it was called from.
 */
enum { PICK_FIRST = 0, PICK_NEXT = 1, PICK_PREV = -1 };


#endif /* KV_BARMENU_H */
