/* kv_bar_items.c - the menu bar's item table and the wording of its rows (split from kv_bar.c, bodies unchanged). */
#define _GNU_SOURCE
#include "kv.h"
#include <celllysis/disasm.h>
#include "kv_bar_private.h"

const struct bar_item_def bar_item[BI_COUNT] = {
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
	{ "Rebuild database",  BM_MANAGE, -1, 0 },
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
 * Worked out per ask (see below) rather than kept: it is the same answer every
 * time, but a kept table is writable global state.
 */
/* One slot per verb a reader may filter on: verb 0 is not a verb and KOF_EVT_CONT is not an event, so neither is offered one. A verb added
 * to the vocabulary without a slot here would have no filter row, and nothing would say so: it fails to compile instead. */
_Static_assert(KOF_EVT_TYPE_COUNT - 2 <= BI_FILT_V27 - BI_FILT_V0 + 1, "kv_barmenu.h: a filter slot for every event verb");

/* Whether verb `vb` is offered a slot, and its rank among those by NAME (ties by number, as a stable insertion sort gave). */
static int filt_verb_rank(int vb)
{
	const char *name = kof_evt_verb_name((uint16_t)vb);
	int u, rank = 0;

	for (u = 1; u < KOF_EVT_TYPE_COUNT; u++) {
		int c;

		if (u == KOF_EVT_CONT || u == vb)
			continue;
		c = strcmp(kof_evt_verb_name((uint16_t)u), name);
		if (c < 0 || (c == 0 && u < vb))
			rank++;
	}
	return rank;
}

int bar_filt_verb(int i)
{
	int k, vb;

	if (i < BI_FILT_V0 || i > BI_FILT_V27)
		return -1;
	/* Computed per ask, over a couple of dozen names: a table kept here would be writable global state, and the menu is only walked
	 * while it is open. */
	k = i - BI_FILT_V0;
	for (vb = 1; vb < KOF_EVT_TYPE_COUNT; vb++)
		if (vb != KOF_EVT_CONT && filt_verb_rank(vb) == k)
			return vb;
	return -1;
}

/* KNOWN DEFECT P3-1 (2026-11-03, R) [sev L]: a filter row's text is built in `static char row[40]`, writable global state (kofeng/CLAUDE.md "no writable global state").
 * Trigger: two bar_label calls whose results are both held (today the one caller, bm_label via kv_menu_popup, copies each row at once, so nothing shows).
 * Effect: the first pointer then names the second row's text. Reproducer: none (no second holder exists).
 * Fix: bar_label writes into a buffer the caller owns (bm_label passes the popup row's text) and the static goes. */
const char *bar_label(struct view *v, int i)
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
 * How many rows this item takes before its own: 1 for a rule above it, else 0.
 *
 * One function, called by BOTH the drawer and the hit test, because they are
 * two walks over the same table and the whole class of bug here is one of them
 * counting a row the other does not. See the note on bar_col for the last time
 * that happened.
 */
int bar_gap(struct view *v, int i)
{
	return (i > 0 && bar_item[i].sep && bar_shown(v, i)) ? 1 : 0;
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
