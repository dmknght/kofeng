/*
 * kofview.h - the terminal, and what is drawn on it.
 *
 * WHAT THIS IS, AND WHY IT IS NOT IN kofviewer.c ANY MORE.
 *
 * Everything here is about a TERMINAL and nothing here knows what an object,
 * a region or a signature is - which was already true while it sat at the top
 * of kofviewer.c, and was the only reason that file could be read at all. Moved
 * out, the boundary is enforced rather than observed: a helper that starts
 * asking about the file under view will not compile here.
 *
 * The point of the move is the widgets that follow it. A menu, a dialog, a
 * scrollable page - the viewer has two of the first and four of the second, each
 * written separately, and every one of them re-derives the same things: where
 * the box is, which row a click landed on, how a disabled row is coloured. They
 * cannot be shared while the code they would share is buried in a sixteen
 * thousand line file next to the object tree.
 *
 * WHAT BELONGS HERE: the raw-mode dance, one output buffer, the escape
 * sequences, the glyphs, and the colours that mean the same thing on every
 * screen - an identifier is blue wherever it appears.
 *
 * WHAT DOES NOT: any palette that is about one KIND of thing. The byte classes
 * of a hex dump, the token colours of a disassembly, the field colours of a
 * symbol table - those are vocabulary the viewer speaks, they change when its
 * panes change, and a module that held them would be a module every pane had a
 * reason to edit.
 */

#ifndef KOFVIEW_H
#define KOFVIEW_H

#include <stddef.h>
#include <stdint.h>

/* ---- the terminal --------------------------------------------------------- */

/*
 * How big it is, refreshed by kofview_size().
 *
 * Globals rather than a handle, because there is one terminal: a program that
 * could address two of these would still only be able to draw on one, and every
 * geometry helper in the viewer reads them. The alternative is a parameter
 * threaded through several hundred call sites to describe something that cannot
 * vary.
 */
extern int g_rows, g_cols;

/*
 * Everything this program puts on the terminal goes through one call.
 *
 * It used to be two - fputs for the mode changes, write for the frames - and
 * that was a real bug rather than untidiness. stdout to a terminal is line
 * buffered and a mode change carries no newline, so "turn the mouse on" sat in
 * stdio's buffer for the whole session while every frame went straight out
 * around it: the terminal was never asked to report a click, so it never did.
 *
 * It also makes the restore path correct - write is async-signal-safe and
 * fputs/fflush are not, and the restore runs from a signal handler.
 */
void term_write_n(const char *s, size_t n);
void term_write(const char *s);

/*
 * Raw mode, alternate screen, no cursor - and every one put back on the way
 * out, including the way out nobody plans for. A tool that leaves a terminal in
 * raw mode after a crash is a tool people stop running, so the restore is
 * registered before the first change is made and is idempotent.
 */
int  term_setup(void);
void term_restore(void);
void term_size(void);

/* ---- one frame, one write ------------------------------------------------- */

/*
 * A frame is built here and written once.
 *
 * Not because building is cheap but because a terminal renders what it has
 * received: a screen written row by row is briefly a screen half old and half
 * new, which is the tearing the synchronised-output mode exists to hide and
 * cannot hide from a writer that flushes in pieces.
 */
struct out {
	char  *p;
	size_t n, cap;
	/* Printable columns emitted since the last out_at, so a caller laying
	 * out a line can record where its pieces landed. Escapes do not count;
	 * nothing here needs more than that. */
	size_t col_hint;
	/*
	 * And WHERE that row began, which col_hint alone cannot say.
	 *
	 * col_hint counts from the last positioning, not from column one, so
	 * "1 + col_hint" is only the real column when the row started at column
	 * one. A dialog that starts its rows at column three needs the base to
	 * turn a hit test into a subtraction.
	 */
	int    col_base;
	int    row_hint;
};

/* Bytes with no interpretation - a caller that has already decided where an
 * escape ends and text begins. out_str is this with strlen. */
void out_add(struct out *o, const char *s, size_t n);
void out_str(struct out *o, const char *s);
void out_glyph(struct out *o, const char *g);
void out_at(struct out *o, int row, int col);
#if defined(__GNUC__)
void out_fmt(struct out *o, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
#else
void out_fmt(struct out *o, const char *fmt, ...);
#endif

/* ---- the box-drawing glyphs ----------------------------------------------- */

/*
 * Named rather than written inline, because there are two sets: a terminal that
 * cannot show U+2500 gets ASCII, and a box drawn half in each is worse than a
 * box drawn entirely in either.
 *
 * THESE ARE THE ONLY CHARACTERS THIS PROGRAM PRINTS THAT ARE NOT PLAIN ASCII.
 *
 * Everything else is: every byte taken from the file being read is clamped to
 * 0x20..0x7e before it reaches the screen, and the panes are divided with '|'
 * and '-'. So this block is the whole of the question "what does this look
 * like on a terminal that is not the one it was written on".
 *
 * On Windows it is not the same question, which is why the switch is thrown
 * here rather than left for somebody to remember. A console has a CODE PAGE,
 * and the default is 437: the three bytes of U+2502 are not one character
 * there, they are three - the console draws them as "Gamma-o-e", and the
 * scrollbar comes out as a column of that. Neither half of that is
 * survivable: the glyphs are wrong AND each one is three columns wide where
 * out_glyph told the layout it is one, so the frame after it is out of place
 * too. A switch that exists but that nothing sets is the same as no switch:
 * KOFVIEW_ASCII_BOX was referenced here and defined nowhere, so the ASCII set
 * was unreachable code and Windows got the mess.
 *
 * ASCII rather than the code page's own box drawing characters (CP437 has a
 * real U+2502 at byte 0xb3), because that would only move the assumption: 0xb3
 * is a box character on 437, a superscript three on 1252, and nothing at all
 * on 65001. The low 128 are the same in every one of them, which is the only
 * guarantee available here, and a frame drawn in '|' and '-' is legible on a
 * console with any code page and any font - which is more than can be said for
 * a frame drawn in the right characters on the wrong one.
 *
 * The alternative was SetConsoleOutputCP(CP_UTF8) at startup, which keeps the
 * rounded corners. It is one line and it is not taken here: it changes a
 * setting that outlives the program on a console it does not own, legacy
 * conhost has never been reliable about it, and the failure mode when it does
 * not take is the mess above rather than a plainer box.
 *
 * Both directions stay available to anyone who knows their own terminal:
 * -DKOFVIEW_ASCII_BOX forces the plain set on a POSIX terminal that cannot
 * draw the others, and -DKOFVIEW_UTF8_BOX keeps the rounded ones on a Windows
 * console that has been set to UTF-8 already.
 */
#if defined(_WIN32) && !defined(KOFVIEW_UTF8_BOX)
#define KOFVIEW_ASCII_BOX 1
#endif

#ifdef KOFVIEW_ASCII_BOX
#define G_TL "+"
#define G_TR "+"
#define G_BL "+"
#define G_BR "+"
#define G_H  "-"
#define G_V  "|"
#else
#define G_TL "\xe2\x95\xad"     /* U+256D */
#define G_TR "\xe2\x95\xae"     /* U+256E */
#define G_BL "\xe2\x95\xb0"     /* U+2570 */
#define G_BR "\xe2\x95\xaf"     /* U+256F */
#define G_H  "\xe2\x94\x80"     /* U+2500 */
#define G_V  "\xe2\x94\x82"     /* U+2502 - the scrollbar's own */
#endif

/* ---- the colours that mean one thing everywhere --------------------------- */

/*
 * A vocabulary, not a palette. Each of these says what a piece of text IS, so
 * the same kind of fact is the same colour on every screen - an identifier is
 * blue in the tree, in a dialog and on the status line, and a reader learns it
 * once.
 *
 * A colour that is about one kind of CONTENT - a byte class, a disassembly
 * token, a symbol field - is not here. Those belong to the pane that speaks
 * them.
 */
#define A_OFF   "\033[0m"
#define A_BOLD  "\033[1m"
#define A_DIM   "\033[90m"
#define A_ID    "\033[34m"      /* a name: a symbol, a family, a field */
#define A_LOC   "\033[36m"      /* a place: an offset, an address */
#define A_SIZE  "\033[32m"      /* a quantity */
#define A_BAD   "\033[31m"      /* wrong, and worth acting on */
#define A_WARN  "\033[33m"      /* worth reading */
#define A_HEUR  "\033[35m"      /* a heuristic's word, never a signature's */
#define A_AND   "\033[36m"
#define A_OR    "\033[33m"
#define A_SEL   "\033[7m"       /* the thing under the cursor */

/* ---- a dropdown ------------------------------------------------------------
 *
 * A column of rows, some of them choosable, with a rule where one group of them
 * ends and the next begins. The viewer has two - the menu bar's and the hex
 * pane's right-click menu - and they were two implementations of this: two
 * draws, two hit tests, two "which row can Enter land on" walks, and two
 * answers to what a greyed row looks like.
 *
 * They were not, however, two of the same TABLE, and they should not be. What
 * an item says, when it is available and what it does are the menu's own
 * business; where the rows go and which one the mouse hit are not.
 *
 * The three colours are the caller's because the two menus do not look alike -
 * the bar is white on dark grey, the context menu black on light - and making
 * them match is a decision about the tool's appearance rather than about this
 * widget. Passing them keeps that decision one line away.
 */
struct kv_menu {
	int          n;                          /* items in the caller's table */
	void        *ud;

	/* Is this item in this menu at all - the context mask, the parent, the
	 * "only while a draft is open" rules. A hidden item takes no row. */
	int        (*shown)(void *ud, int i);
	/*
	 * Choosable. A shown-but-not-enabled item takes a row and is drawn
	 * grey.
	 *
	 * THE TWO ARE FOR DIFFERENT KINDS OF NO, and this note used to argue
	 * for only one of them - that hiding teaches nobody what the tool can
	 * do. True of a thing that is momentarily unavailable; false of a thing
	 * that cannot apply. "Symbols" on a page description stream is not off
	 * because something is in the way, it is off because the concept does
	 * not reach that object - and a greyed row there is a permanent piece
	 * of furniture the reader has to learn to ignore, on every object of
	 * every document format.
	 *
	 * So: CANNOT APPLY is hidden, MOMENTARILY UNAVAILABLE is greyed. Save
	 * with nothing edited is grey - it will work in a second. Symbols on a
	 * PDF is gone - it never will.
	 */
	int        (*enabled)(void *ud, int i);
	/* Draw a rule above this item. Where the caller keeps groups, this is
	 * "the group changed"; where it keeps a flag, it is the flag. */
	int        (*rule_above)(void *ud, int i);
	const char *(*label)(void *ud, int i);
	/* Opens a submenu rather than acting. NULL when none of them can. */
	int        (*has_sub)(void *ud, int i);

	int          w;                          /* column width, borders in */
	const char  *c_on, *c_off, *c_cur;       /* usable, greyed, under cursor */
};

/* ---- what a FORMAT can be asked -------------------------------------------
 *
 * A menu item that is always choosable teaches the reader that it always
 * applies, and then answers "nothing here" when it does not. "Symbols" on a
 * PDF is not a thing that failed; it is a thing that was never possible, and
 * the difference belongs on the screen BEFORE the click.
 *
 * So: DISABLED BY DEFAULT, enabled for the object under the cursor. Disabled
 * and not hidden, for the reason kv_menu's own note gives - an item that
 * vanishes reads as a missing feature.
 *
 * THIS ANSWERS THE FORMAT HALF ONLY, and that is deliberate. Whether an ELF
 * HAS symbols is a fact about one file and belongs to whoever holds the parse;
 * whether an ELF CAN have them is a fact about the format and belongs here,
 * where one table serves the menu and the dashboard rather than each growing
 * its own. A caller ANDs the two.
 *
 * It is keyed on the SELECTED OBJECT'S format and not the file's, so an
 * attachment answers for itself: a PE carried inside a PDF is a PE, and the
 * items that apply to executables apply to it.
 */
enum kv_cap {
	/* An import or export table the format defines a place for. */
	KV_CAP_SYMBOLS = 0,
	/* Machine code, at somewhere the format names - so disassembling from
	 * there means something rather than starting mid-instruction. */
	KV_CAP_CODE,
	/* Running or peeling it could yield another object. The emulator
	 * interprets instructions, so this is the executable formats and the
	 * formatless bytes that may be some - never a container, whose members
	 * come out by being read rather than by being run. */
	KV_CAP_UNPACK,
	/*
	 * SHELLCODE COULD BE CARRIED HERE, so asking is worth offering.
	 *
	 * A CAPABILITY AND NOT A FINDING, which is the whole reason it is in
	 * this table. "Find shellcode" used to be drawn only when a rule had
	 * ALREADY reported some - so on the files it exists for, the row was
	 * missing and a reader was told by its absence that there was nothing
	 * to ask. That is backwards twice over: the menu is how somebody ASKS,
	 * and a question that only appears once it has been answered is not a
	 * question.
	 *
	 * So this says where shellcode can live - a native executable image -
	 * and the action says what is actually there, including "nothing".
	 *
	 * NOT KOF_FMT_UNKNOWN, and that is the one difference from KV_CAP_CODE.
	 * Formatless bytes may well BE shellcode, but then they are the answer
	 * rather than the place to look for one: offering "find shellcode in
	 * variables" on a peeled payload asks the reader to search a thing for
	 * itself. Variables are a fact about a structured image.
	 */
	KV_CAP_SHELLCODE,
	KV_CAP_COUNT
};

/* Non-zero if a format of this kind can be asked this at all. KOF_FMT_UNKNOWN
 * answers YES to the code questions: bytes nothing claimed are exactly what a
 * peeled payload looks like, and refusing there would turn the one case the
 * emulator exists for into the one case it is not offered. A caller that knows
 * MORE than the format - that the parse called these bytes a page description
 * stream, say - is expected to say so itself. */
int kv_cap(uint8_t format, int cap);

/* Drawn rows, rules included - what the caller needs to place the box. */
int  kv_menu_rows(const struct kv_menu *);
/* The item on a drawn row, or -1 for a rule and for past the end. */
int  kv_menu_at_row(const struct kv_menu *, int row);
/* And the reverse, for a caller anchoring a submenu to the row it opens on. */
int  kv_menu_row_of(const struct kv_menu *, int item);
/* The first item Enter could act on, so a menu never opens on a dead row. */
int  kv_menu_first(const struct kv_menu *);
/* The next choosable item in direction `d`, or `cur` when there is none: a
 * key that moves onto a greyed row and stops is a key that appears broken. */
int  kv_menu_step(const struct kv_menu *, int cur, int d);
/*
 * `sel2` is a second row to highlight - the bar draws its open submenu's parent
 * that way, so the trail from the bar to the submenu stays visible. Pass -1 for
 * a menu with no such thing.
 */
void kv_menu_draw(struct out *, const struct kv_menu *, int top, int left,
		  int sel, int sel2);

#endif /* KOFVIEW_H */
