#define _GNU_SOURCE
#include "kv.h"

const char *const mtn_colour[MTN_COLOURS] = {
	"\033[48;5;24m\033[97m",    /* slate blue   */
	"\033[48;5;58m\033[97m",    /* olive        */
	"\033[48;5;53m\033[97m",    /* plum         */
	"\033[48;5;23m\033[97m",    /* deep teal    */
	"\033[48;5;94m\033[97m"     /* burnt orange */
};
/*
 * How many rows the draft panel is using.
 *
 * File scope so the geometry helpers stay parameterless - they are called from
 * everywhere including the click routing, and threading a view pointer through
 * them to ask one question would be worse than one number kept in step in one
 * place. Updated at the top of every frame.
 *
 * Zero until there is a draft: an empty panel would cost the hex view its
 * height on every file, including the many opened to be read rather than
 * written about. It appears with the first declaration and leaves with the last.
 */
int g_decl_rows;

/*
 * How many rows the disassembly panel is using, and zero when it is closed.
 *
 * It takes them from the BOTTOM OF THE HEX COLUMN and from nowhere else: the
 * object tree beside it keeps its full height, because the tree is how a reader
 * moves between objects and losing half of it to look at one is the wrong
 * trade. So the split is horizontal inside one column rather than a new pane.
 *
 * File scope beside g_decl_rows and for the same reason - the geometry helpers
 * are called from the click routing as well as the drawing, and threading a
 * view pointer through them to ask one question would be worse.
 */
int g_disasm_rows;

/*
 * THE EVENT PANEL, which takes its rows the same way and from the same place.
 *
 * A record in the hex pane is 512 bytes of struct, and reading a pid out of it
 * by counting offsets is not something a reader should have to do - the fields
 * are what the record MEANS and the bytes are only how it is stored. So the
 * panel spells them, in the same wording montrace prints, under the bytes they
 * came from.
 *
 * Its own counter rather than the disassembler's, even though the two can
 * never be open at once - disassembly is hidden for a log and this is hidden
 * for everything else. Sharing one would make that mutual exclusion load
 * bearing, and the day something makes them overlap the failure would be a
 * panel drawn at the other one's height rather than a compile error.
 */
int g_evt_rows;

/*
 * What each declaration is called on screen.
 *
 * Not the macro's name. KOF_TARGET_SIZE_MIN is what gets written to the file
 * and is the right name there, where the reader is looking at C; on a panel it
 * is a token to decode, and "size_min" does not say whether it is a minimum
 * this module requires or a minimum it refuses.
 *
 * The two size rows are spelled as the COMPARISON they are. "Smallest file
 * size" reads as a description of the file rather than as a condition on it,
 * and the reader then has to work out which way it points; ">=" says it and
 * needs no working out. Whoever is writing a signature is writing C, so the
 * operator is the familiar spelling rather than a jargon one.
 *
 * The two are not equally cheap and the panel does not pretend otherwise: the
 * minimum becomes a declared precondition the host evaluates without calling
 * the module, the maximum becomes a test in the body, and the generated source
 * shows which is which. See KOF_TARGET_SIZE_MIN in kofsig.h for why there is
 * no declared maximum.
 */
const char *const opt_word[OPT_COUNT] = {
	"File size >=", "File size <=",
	"Architecture", "File subtype"
};

/* Where the last click was. Declared here because the row callbacks are
 * written beside the rows that register them, which is above its definition. */
int g_mx, g_my;
/* Which way the wheel last turned: +1 down, -1 up. Beside g_mx for the same
 * reason - a wheel callback asks it exactly as a click callback asks where the
 * pointer was. */
int g_wheel;


/*
 * One line of text inside a box, with the caret shown and the view following it.
 *
 * `*off` is how far the text is scrolled inside the box and is adjusted here
 * rather than by the caller: the only thing that should move it is the caret
 * leaving the box, and the caret is what this draws. That is also why there is
 * no wheel binding for it - a field that scrolls under the pointer would fight
 * the panel the pointer is over.
 *
 * The caret is an underline on the character it sits on, and a space when it is
 * past the end. A block cursor would hide the character; this is the same thing
 * every terminal editor does.
 */
/*
 * WHERE THE OPEN FIELD IS, SO A CLICK IN IT CAN BECOME A CARET.
 *
 * Every text box on the panel goes through field_draw, and only the open one is
 * drawn with `editing` set - so one record is enough for all of them, and no
 * caller has to remember to keep a box of its own in step with its drawing.
 *
 * `room` is cleared at the top of every frame: a field whose row scrolled out
 * of view is not drawn, and a stale rectangle would swallow clicks meant for
 * whatever now occupies those columns.
 */
struct kv_g_fld g_fld;

/*
 * AND WHAT IS SELECTED IN IT, for the same reason and in the same shape.
 *
 * field_draw paints the range and does not own it - the view does, across
 * keystrokes and pointer motion - so it is copied here once a frame beside
 * g_fld rather than added to twelve call sites that have nothing to say about
 * it. Normalised on the way in, because painting reads it and a paint has no
 * business knowing which end the drag started at.
 */
struct kv_g_fsel g_fsel;

/*
 * Copy through the terminal, not through a clipboard this program can reach.
 *
 * OSC 52 hands the bytes to whatever is drawing the screen, which is the only
 * thing that works when the screen is being drawn on another machine - and
 * being usable over ssh is most of why this is a TUI. A terminal with the
 * sequence disabled ignores it silently; there is no reply to wait for and
 * nothing better to fall back to.
 */
/*
 * The viewer's own clipboard.
 *
 * OSC 52 asks the TERMINAL to set the system clipboard, and most terminals
 * refuse by default - a program that can write the clipboard can also read a
 * password out of it, so VTE and others ship with it off. Nothing here can
 * change that, and a copy that silently does nothing is worse than no copy at
 * all. So the bytes are kept here as well: the system clipboard is attempted,
 * and Ctrl+V inside this program works whether or not the terminal allowed it.
 */
char   g_clip[8192];
size_t g_clip_n;

const char *const bar_name[BM_COUNT] = {
	/*
	 * Hyphenated, because the bar is a row of single words and a title with
	 * a space in it reads as two of them - "Switch" and "File" - which is a
	 * menu that does not exist next to a menu that does.
	 */
	"File", "Edit", "Analysis", "Switch-File", "Help"
};

/* ---- the properties page --------------------------------------------------------
 *
 * What the engine knows about this object, on one scrollable page.
 *
 * The same facts kofexamine prints, and deliberately the same facts: a
 * researcher who has read one should recognise the other, and two tools over
 * one engine disagreeing about what a file is would be worse than either of
 * them missing something. What differs is only that this one can be scrolled
 * and the other one scrolls past.
 *
 * Built as lines rather than drawn directly, because scrolling a page is a
 * window over a list and painting one is not. The per-format blocks are the
 * point of the whole thing - an ELF has segments and a zip has entries, and a
 * page that shows neither because it shows only what they have in common is a
 * page nobody opens twice.
 */

/*
 * A LINE CARRIES ITS OWN COLOURS, INSIDE ITS TEXT.
 *
 * There was a `col` field beside the text, set by every caller and read by
 * none - prop_put draws the text and nothing else. So prop_add's first
 * argument, which reads exactly like the colour a row is painted in, painted
 * nothing, and had not since the page was written. Nine rows asked for a colour
 * and came out in the default one; the heuristic verdict was one of them.
 *
 * The escapes belong in the text because the page is a table of different KINDS
 * of fact - a name, an offset, a size - and one colour per row cannot say which
 * is which. Every other row on this page already worked that way.
 */
struct prop_line g_prop[PROP_MAX];
uint32_t         g_n_prop;

uint32_t g_prop_tab_off[PROP_TAB_COUNT];
/*
 * HOW FAR EACH TABLE IS SCROLLED SIDEWAYS, in columns.
 *
 * A value is routinely wider than the column it is in - a PATH or an
 * LD_LIBRARY_PATH runs past any width worth giving it - and the page itself
 * does not scroll sideways, so without this the tail of such a value is
 * unreachable. Shift and the wheel, which is the gesture every terminal
 * already uses for it.
 */
uint32_t g_prop_tab_hoff[PROP_TAB_COUNT];
int      g_prop_tab_scroll_v[PROP_TAB_COUNT];
int      g_prop_tab_scroll_h[PROP_TAB_COUNT];

/* g_mx, g_my are declared beside struct hit - the row callbacks need them. */
int g_mod_shift;         /* shift was held for it */
int g_mod_ctrl;          /* and control, which slides text sideways */

/* The close control's box is recorded in the frame for whoever draws one; no
 * dialog here asks for it yet, so the hit test lives with its first caller
 * rather than sitting unused. */

/*
 * WHERE EACH DIALOG'S BOX ENDED UP, recorded as it is drawn and read when it is
 * clicked - the same arrangement g_prop_tab_* uses for the tables, and for the
 * same reason: the geometry exists in one place, the drawing, and a second copy
 * of the arithmetic in the click handler is a second thing to keep in step.
 */
struct dframe g_goto_f, g_find_f, g_enc_f;
