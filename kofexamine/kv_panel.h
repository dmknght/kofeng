/*
 * kv_panel.h - the event panel, how a panel is divided, the format categories and the page.
 *
 * A part of kv.h, included by it and by nothing else.
 */
#ifndef KV_PANEL_H
#define KV_PANEL_H

/* Resolve whichever region the cursor is on, and put the hex pane back where it
 * was the last time this row was looked at. */
/* ---- the event panel -------------------------------------------------------
 *
 * WHY THE TWO PANES SHARE A PALETTE.
 *
 * A field list beside a hex dump is two views of one record, and the question
 * a reader has is always the same: which bytes is this row talking about. Left
 * to prose the answer is an offset they have to count to; given a colour it is
 * a glance. So every row takes a background from a small palette and the bytes
 * it covers take the SAME background - the mapping is the colour, and it goes
 * both ways: a run of odd bytes in the dump names itself by matching a row.
 *
 * Small on purpose. A record yields up to about a dozen rows and a palette that
 * gave each its own hue would be a dozen colours nobody can hold; six that
 * repeat are six a reader can, and two rows sharing one are never adjacent in
 * the dump because the rows are sorted by offset - so a repeat is always half
 * a record away from its twin.
 *
 * 256-colour, like A_S_SHN and for the same reason: the sixteen are spoken for
 * by meanings this tool uses everywhere else - red is a marker the database
 * counted, blue is a drag selection - and a palette built from them would say
 * those things by accident. A terminal without 256-colour ignores the sequence
 * and loses the mapping; it does not break the layout.
 *
 *
 * WHY THE DUMP TAKES THE FOREGROUND AND THE PANEL TAKES THE BACKGROUND.
 *
 * They were both backgrounds to begin with, and on the fixed head that reads
 * well - four bytes of pid in a block of colour is a thing the eye lands on.
 *
 * The head is not where a record is read. Every one of these ends with the
 * text arena, and the arena is where the fact is: the path, the command line,
 * the AMSI submission. It is the last field, it is by far the longest, and it
 * is the one a reader opened the record to see - so it is exactly the field a
 * solid background ruins. A hundred and fifty cells of ground is not a
 * highlight, it is a wall, and it stands over the one part of the record
 * nobody is skimming.
 *
 * So the dump colours the GLYPHS. The hex pane is already a foreground display
 * - byte_colour tells NULs from text that way - so a field colour joins the
 * scheme instead of covering it, and a long field reads as a long run of one
 * ink rather than a slab. The panel's name chip stays a background because it
 * is eleven characters wide and it is the legend: it has to be the strongest
 * statement of "this colour is this row" on the screen, and it can afford to
 * be, because it is short.
 */
/*
 * HOW MUCH OF ONE SUBMISSION IS HELD FOR READING.
 *
 * The collector will send up to sixty-four kilobytes of a script block, and
 * this matches it so that what a reader sees here is what a scanner would get.
 * Two buffers of that size are taken once when a log is opened, not per event:
 * every record can be the big one, so making it conditional would only move
 * the cost to whichever event was selected.
 */

/*
 * A MEGABYTE, NOT THE COLLECTOR'S SIXTY-FOUR KILOBYTES.
 *
 * Matching the collector's spill cap looked right and is the wrong bound: this
 * reads a LOG, and a log holds whatever its producer wrote. Capped at one
 * collector's limit, a submission from any other - or from a later build of
 * this one - was silently shown as a prefix, and a carried image came out
 * 65536 bytes long whatever it really was.
 *
 * Two of these, taken once when a log is opened rather than per event: every
 * record can be the big one, so making it conditional would only move the cost
 * to whichever event was selected.
 */
#define EVT_JOIN_MAX (1024u * 1024u)
#define EVT_TEXT_MAX (1024u * 1024u)

/* ---- how the panel is divided ---------------------------------------------
 *
 * THREE ZONES, because the record has three kinds of thing in it and they want
 * different shapes on screen.
 *
 * The metadata is a table: a dozen short values, each one a number or a word.
 * Laid down the screen one per line it was a tall column of mostly empty rows,
 * and the field a reader had come for - the submission - was pushed off the
 * bottom. Two columns side by side halve that height and waste nothing,
 * because none of these values is wide.
 *
 * The submission is not a table row at all. It is a document: hundreds or
 * thousands of characters that a reader wants to scroll through, select out of
 * and copy. So it gets a box of its own under the table, with the full width
 * and its own scroll, and the table above it stays put while it moves.
 *
 * The warnings sit between them, full width and flush left, because they are
 * about the record as a whole and belong to neither.
 */

/* The object box: tall enough to show a line of context either side of what a
 * reader is looking at, short enough to leave the table and the hex pane their
 * room. */
#define EVT_BOX_ROWS 3

/*
 * Put a file offset on screen, a few rows down rather than at the very top.
 *
 * Landing a jump on the first row leaves nothing above it, and what is above a
 * marker is half of what says whether it is the right marker - the string before
 * it, the padding, the structure it sits in. Two rows of lead-in costs nothing
 * and is what a reader would have scrolled to anyway.
 */
#define JUMP_LEAD 2u

/*
 * WHAT THE RULE APPLIES TO, SEEDED FROM THE OBJECT THE FIRST MARKER CAME OFF.
 *
 * That object's format is the one format the reader has already shown they
 * care about. Seeded rather than fixed: everything after this is theirs to add
 * and remove on the Format row.
 *
 * AND THE SUBTYPE WITH IT, FOR A SCRIPT AND NOT FOR AN EXECUTABLE, because the
 * word means different things on the two axes:
 *
 *   - for a script the subtype is the LANGUAGE, and a marker taken out of a
 *     php file is a php marker. Left off, the rule declares no subtype, and a
 *     rule with no subtype is offered every script on the machine - every
 *     python file, every shell script - to be told no. That is the cost the
 *     subtype axis exists to avoid, and paying it by ACCIDENT, because a field
 *     was left blank, is the worst way to pay it.
 *
 *   - for an ELF or a PE the subtype is a LAYOUT VARIANT - relocatable,
 *     executable, shared - and the same bytes routinely appear in all three.
 *     Seeding it there would narrow the rule to whichever kind happened to be
 *     open, and lose the other two silently. So it is not seeded.
 *
 * KV_CAP_TEXT is exactly that line: the formats whose subtype is what the file
 * IS WRITTEN IN rather than how it is laid out.
 */
/* Defined with the event panel, where the record is - see evt_decl_target. */
#define EVT_TARGET_NONE 0xffu

/*
 * Fill and place a chooser.
 *
 * The contents are built here rather than by each caller so that what a list
 * offers stays next to what picking from it does - two halves of one decision,
 * which drift apart the moment they live in different functions.
 */
/*
 * FORMATS BY KIND, because eighteen names in one column is a list nobody reads.
 *
 * The grouping is the reader's question and not the enum's order: somebody
 * adding a format to a rule is thinking "this also applies to documents", not
 * "this also applies to number nine". The enum stays in whatever order the
 * engine needs; this says how to present it.
 *
 * A format missing from every row here would be unreachable, so the last row is
 * a catch-all built by subtraction rather than written out - a format added to
 * the engine turns up under Other until somebody files it, instead of
 * disappearing.
 */
struct fmt_cat {
	/* Which of the engine's groups this row shows - the formats in it and
	 * the word for it both come from there. */
	enum kof_format_group group;
	/*
	 * THIS ROW OPENS LANGUAGES, NOT FORMATS.
	 *
	 * One row has a submenu that is not a list of formats: Scripts holds a
	 * single format and the thing a researcher is choosing between is the
	 * LANGUAGE - php, aspx, jsp. Those are subtypes, so picking one sets the
	 * format AND the subtype together, which is the pair that actually
	 * describes the object. A submenu with one row reading "Script" offered
	 * the reader a click for no information.
	 */
	uint8_t     langs;
};

/*
 * The condition rows, in reading order.
 *
 * Built once and walked by everything that cares - the row table, the drawing,
 * the click routing - because reading order is not array order: a nested
 * condition is stored after its parent but drawn between the parent's own rows
 * and whatever follows the parent's block. Walking the array instead put the
 * rule that joins one top level condition to the next above that condition's
 * children rather than below them, which is where it belonged.
 */
/*
 * A CONDITION IS TWO LINES, IN THE ORDER IT IS DECIDED: the matchers it is made
 * of, and then the tag it finds. A condition no longer names a verdict level or
 * a variant - what an object is called is made from the diseases that matched.
 */
enum cseq_kind { CS_COND = 0, CS_MATCH };

enum prow_kind {
	RW_OPT = 0, RW_RANGES, RW_STRHDR, RW_STR, RW_ADDS, RW_ADDM,
	RW_MATCH, RW_MARKERS, RW_ADDC, RW_COND, RW_CMATCH,
	RW_MATHDR, RW_CNDHDR, RW_CJOIN,
	/* The block table's heading, its column names and its rows - see
	 * draw_decl_blocks, which draws TWO rows before the first block. */
	RW_BLKHDR, RW_BLKCOL, RW_BLK,
	/*
	 * THE SIMILARITY TABLE: its heading, its column names and its three
	 * rows - one per measure. See draw_decl_sim.
	 */
	/* THE DIAGNOSES this file carries - see draw_decl_diag. */
	RW_DIAGHDR, RW_DIAGCOL, RW_DIAG,
	/* The format row and the [+ Options] button - see prow_build. */
	RW_FMTS, RW_OPTBTN,
	/* The title bar of tabs, and the output pane's rows - see
	 * draw_decl_tabs and draw_decl_preview. */
	RW_TABS, RW_PREV
};

#define MENU_W 24

#define PROP_MAX  600
/*
 * BYTES, NOT COLUMNS, and the difference is what cut a table's border.
 *
 * A line carries its own colour escapes and its glyphs may be multi-byte: a
 * 70-column rule drawn from U+2500 is 210 bytes on its own, so at 200 the top
 * and bottom of every wide table lost their right-hand corner while the rows
 * between them - mostly ASCII - fitted and kept theirs. A frame with three
 * sides reads as a drawing bug, which is what it was.
 */
#define PROP_W    KV_TAB_LINE

/* A LINE CARRIES ITS OWN COLOURS, INSIDE ITS TEXT - see prop_put, which draws
 * one. Declared here rather than beside the properties page because more than
 * one dialog builds pages of these. */
struct prop_line {
	char text[PROP_W];
};

/*
 * A page of lines in a box - the shape three dialogs share. Declared here with
 * prop_line because both are the vocabulary of that shared renderer; the
 * renderer itself is defined beside the properties page, which is where its
 * dependencies live.
 */
#define PAGE_COUNT_POS   0
#define PAGE_COUNT_LINES 1
#define PAGE_COUNT_ITEMS 2

struct page {
	const char       *title;
	/* A tab strip replaces the title (the dashboard's). */
	const char       *tab[KV_DD_TABS];
	int               tab_n;
	int               tab_sel;
	/* The lines the caller produced. A page that is a window over more lines than it holds (a table page produces only
	 * the rows it draws) says how many scrolling lines there are in all (`total`, 0 = n - fixed) and which of them
	 * the first produced one is (`first`). */
	struct prop_line *line;
	uint32_t          n;
	/* The first `fixed` lines stay where they are while the rest scrolls:
	 * a table's controls and column headings. */
	uint32_t          fixed;
	uint32_t          total, first;
	uint32_t         *off;          /* the caller's scroll; clamped by the draw */
	int               full;         /* fill the screen, or fit the text */
	/* At least this wide, when the lines are narrower: a page whose lines
	 * change as the reader moves must not change its width with them, or
	 * what it was drawn over shows through where it was. */
	int               width;
	int               record;       /* record rows for selection and copy */
	const char       *foot;         /* bottom-rule hint, or NULL */
	/* How the position is said: PAGE_COUNT_POS after the corner (the help pages), or the dashboard's at the right
	 * corner (dash_count_text): the lines of the overview, the items of a table page. */
	int               count_kind;
	/* Where the reader dragged the box (full pages only: the dashboard); page_draw clamps it and writes the offset that remains back. */
	struct dlg_off   *move;

	/* Written while drawing, read while clicking: the box, the strip, the close button, the body, the
	 * scrollbar, the count (kv_dash_dialog.h). */
	struct kv_dd_geo  geo;
	struct kv_dd_in   in;           /* the state it was drawn from (its scroll numbers are what the scrollbar is read with) */
	uint32_t          shown;
};


#endif /* KV_PANEL_H */
