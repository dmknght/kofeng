/*
 * kv_input.h - input (keys, navigation) and the framed dialogs (struct dframe).
 *
 * A part of kv.h, included by it and by nothing else.
 */
#ifndef KV_INPUT_H
#define KV_INPUT_H

/* ---- input ---------------------------------------------------------------- */

/*
 * THERE IS NO ALT HERE, and there was.
 *
 * A chord with Alt is ESC-then-the-letter on the wire, and a bit above the key
 * space used to carry the letter through to menu-bar shortcuts. What was wanted
 * is the windowed-editor gesture - tap Alt, the menu bar takes focus - and a
 * terminal never reports a modifier on its own, so that gesture cannot be built
 * at all. What the shortcuts offered instead was a different thing wearing the
 * same key. F10 opens the bar; every other hot key here is Ctrl+key.
 */

enum key {
	K_NONE = 0, K_UP = 256, K_DOWN, K_LEFT, K_RIGHT, K_PGUP, K_PGDN,
	K_HOME, K_END,
	/*
	 * CTRL+SPACE, which a terminal sends as a NUL byte.
	 *
	 * Named up here rather than passed through as 0, because 0 is this
	 * reader's "no key" - returning the byte closed the program on a chord
	 * nobody had bound. The two meanings needed separating before the key
	 * could be given a job.
	 */
	K_CTRL_SPACE,
	/* Not a key: the terminal changed size while nothing was being typed,
	 * and the loop has to be told so it repaints. */
	K_RESIZE,
	/* A bracketed paste, whose bytes are in g_paste. */
	K_PASTE,
	/* Forward delete - CSI 3 ~, which is a different key from backspace and
	 * arrives as a different sequence. It used to fall through the CSI
	 * decoder's default and come back as 27, so pressing Delete in a field
	 * did what Escape does: dropped the focus, leaving the text alone. */
	K_DEL,
	/*
	 * F10, which is how a text UI activates its menu bar.
	 *
	 * NOT Alt on its own: a terminal never reports a bare modifier. Alt only
	 * exists on the wire attached to a key - Alt+F arrives as ESC 'f' - so
	 * "press Alt to reach the menu" cannot be built, while "press F10" is
	 * what every program with a menu bar in a terminal already uses.
	 */
	K_F10,
	/* Kept contiguous and last: handle() tests the range to let mouse
	 * events past the modes that own the keyboard. */
	K_BACKTAB,
	K_CLICK, K_RCLICK, K_WHEEL_UP, K_WHEEL_DOWN, K_DRAG, K_RELEASE
};

/*
 * ---- navigating a list that may have submenus -------------------------------
 *
 * ONE KEY TABLE FOR EVERY MENU HERE, because there are two of them and they
 * were drifting. The menu bar grew Left/Right for submenus; the draft panel's
 * choosers grew the same thing again later, spelled separately - two bodies of
 * code that have to agree and nothing making them. What a reader learns
 * pressing one menu has to hold for the other, and that only stays true while
 * the mapping has one home.
 *
 * WHAT IS SHARED IS THE MEANING, NOT THE ACTION. Right is "go inward" in both,
 * but inward opens a submenu in a chooser and, on the menu bar with no submenu
 * under the cursor, steps to the next top-level menu. The caller carries out
 * the intent; it does not get to decide which key produced it.
 */
enum kv_nav {
	KV_NAV_NONE = 0,   /* not a navigation key */
	KV_NAV_PREV,       /* up */
	KV_NAV_NEXT,       /* down */
	KV_NAV_IN,         /* right: into the submenu of the current row */
	KV_NAV_OUT,        /* left: back out to the list this one came from */
	KV_NAV_TAKE,       /* enter */
	KV_NAV_DISMISS     /* escape */
};

/*
 * A CENTRED BOX WITH A SMOOTH BORDER - the frame three dialogs were each
 * drawing for themselves.
 *
 * Find drew no border at all and cleared to the end of the line; Go to drew a
 * full-width box out of G_TL/G_H/G_TR by hand; the properties page has its own
 * inside page_draw. Three implementations of one rectangle, and they disagreed
 * about where a dialog sits - two of them pinned to the bottom edge, which is
 * where a status bar goes, not where a question goes.
 *
 * THE ROWS ARE NOT PRE-FILLED, and that is the constraint the API is shaped
 * around. A frame that painted blank rows for the caller to overwrite would put
 * every row through a blank state inside one frame, which is exactly the
 * flicker-while-typing that find_row's comment records. So a row is opened,
 * written by the caller, and closed - the same three steps goto_row and
 * goto_edge already had, generalised to a box that is not the width of the
 * screen.
 */
struct dframe {
	/*
	 * WHERE THE READER PUT IT, as an offset from where it would otherwise
	 * open.
	 *
	 * An offset and not an absolute position, so a box that has been moved
	 * still follows the terminal when it is resized rather than ending up
	 * off the edge or pinned to a corner. Kept across opens - a reader who
	 * moved the find box out of the way meant it to stay out of the way -
	 * and each box has its own, because they are separate globals.
	 */
	struct dlg_off off;
	int y, x;                       /* top-left of the box itself */
	int w, h;                       /* including the border */
	int ix;                         /* first column INSIDE, for a row */
	int iw;                         /* columns available inside */
	int btn_y, btn_x0, btn_x1;      /* the close control, or -1 */
	/* What the clip was before the box took it - see dframe_begin. */
	struct out_clip save;
};


#endif /* KV_INPUT_H */
