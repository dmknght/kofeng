#define _GNU_SOURCE
#include "kv.h"


/* How long to wait for the rest of an escape sequence before calling the byte a
 * lone Escape. See read_key. */
#define ESC_WAIT_MS 50


enum kv_nav kv_nav_key(int key)
{
	switch (key) {
	case K_UP:    return KV_NAV_PREV;
	case K_DOWN:  return KV_NAV_NEXT;
	case K_RIGHT: return KV_NAV_IN;
	case K_LEFT:  return KV_NAV_OUT;
	case '\r': case '\n':   return KV_NAV_TAKE;
	case 27:                return KV_NAV_DISMISS;
	default:                return KV_NAV_NONE;
	}
}

/*
 * Move a cursor over `n` rows, where -1 means NO CURSOR YET.
 *
 * A list opens with no row selected - pressing a control to see the choices is
 * not the same as pointing at the first one - so the first arrow BRINGS THE
 * CURSOR IN rather than moving it. Down lands on the first row and Up on the
 * last, which is the end nearest the control these lists are drawn above.
 *
 * Anything but PREV and NEXT returns the cursor unchanged.
 */
int kv_nav_step(int sel, int n, enum kv_nav nav)
{
	if (n <= 0)
		return -1;
	if (nav == KV_NAV_NEXT)
		return sel < 0 ? 0 : (sel + 1 < n ? sel + 1 : sel);
	if (nav == KV_NAV_PREV)
		return sel < 0 ? n - 1 : (sel > 0 ? sel - 1 : sel);
	return sel;
}

static char   g_paste[4096];    /* the last bracketed paste */
static size_t g_paste_n;

/*
 * WHAT A PASTE SHOULD INSERT, in one place.
 *
 * A bracketed paste is the terminal handing the system clipboard over already,
 * so it is used as given. A Ctrl+V has to go and ASK for it - wl-paste, xclip,
 * xsel - so that it pastes what every other program would; only when none of
 * them answers does it fall back to this program's own last copy, which is the
 * best it can then do.
 *
 * One function because there is more than one field to paste into and they were
 * getting it different: the string editor asked the clipboard tools, the find
 * box read g_clip directly and so pasted only what had been copied inside this
 * program - a Ctrl+V of something yanked from a terminal or a browser put the
 * wrong bytes in the search box, or nothing at all.
 */
size_t paste_src(int k, const char **out)
{
	static char clip[8192];
	size_t sn;

	if (k == K_PASTE) {
		*out = g_paste;
		return g_paste_n;
	}
	sn = paste_extern(clip, sizeof clip);
	if (sn) {
		*out = clip;
		return sn;
	}
	*out = g_clip;
	return g_clip_n;
}

/*
 * SGR mouse reporting, not the original X10 encoding.
 *
 * X10 packs the coordinates into single bytes with an offset of 32, so column
 * 224 and beyond cannot be expressed and the ones near it collide with UTF-8.
 * SGR is "ESC [ < b ; x ; y M" in plain digits with no ceiling, and every
 * terminal that reports a click at all has understood it for a decade.
 */
/*
 * The legacy encoding, for terminals that did not take the SGR request.
 *
 * "ESC [ M b x y", three bytes each biased by 32. It cannot express a column
 * past 223 and it has no separate release code worth trusting, but it is what
 * arrives when ?1006 was ignored - and a request being ignored is silent, so a
 * viewer that only speaks SGR looks to its user like a viewer whose mouse does
 * nothing at all. Which is exactly how it looked.
 */
/*
 * ONE BYTE, AND AN INTERRUPTED READ IS NOT THE END OF INPUT.
 *
 * THE BUG THIS EXISTS TO KILL. Every read in this file used to be written as
 * `read(...) != 1`, and the caller turned that into K_NONE - which the main
 * loop treats as end of input and QUITS on. A terminal resize interrupts a
 * blocked read with EINTR, so resizing the window closed the viewer: no
 * message, no crash, exit status 0. Measured: one vertical resize, gone.
 *
 * The first read in read_key still wants to SURFACE a resize rather than hide
 * it, so it asks separately. Everywhere else - the tail of an escape sequence,
 * the digits of a mouse report - the bytes are already in the terminal's
 * buffer and the only right answer is to go back and get them.
 *
 * Returns 1 with *c filled, or 0 for a real end: EOF, or an error that is not
 * a signal.
 */
static int read_byte(unsigned char *c)
{
	for (;;) {
		ssize_t n = read(STDIN_FILENO, c, 1);

		if (n == 1)
			return 1;
		if (n < 0 && errno == EINTR)
			continue;
		return 0;
	}
}

static int read_mouse_x10(void)
{
	unsigned char t[3];
	int b;

	if (!read_byte(t) || !read_byte(t + 1) || !read_byte(t + 2))
		return K_NONE;
	b = t[0] - 32;
	g_mx = t[1] - 32;
	g_my = t[2] - 32;
	g_mod_shift = (b & 0x04) != 0;
	g_mod_ctrl  = (b & 0x10) != 0;

	if (b & 0x40)
		return (b & 3) == 0 ? K_WHEEL_UP : K_WHEEL_DOWN;
	if (b & 0x20)
		return K_DRAG;
	/* Button 3 in this encoding is "released", whichever was let go. */
	if ((b & 3) == 3)
		return K_RELEASE;
	if ((b & 3) == 2)
		return K_RCLICK;
	return K_CLICK;
}

static int read_mouse(void)
{
	char t[32];
	size_t n = 0;
	int b, x, y;

	while (n + 1 < sizeof t) {
		if (!read_byte((unsigned char *)t + n))
			return K_NONE;
		if (t[n] == 'M' || t[n] == 'm')
			break;
		n++;
	}
	{
		int release = t[n] == 'm';

		t[n] = 0;
		if (sscanf(t, "%d;%d;%d", &b, &x, &y) != 3)
			return K_RESIZE;        /* ignored (one repaint): K_NONE means end of input */
		g_mx = x;
		g_my = y;
		if (release)
			return K_RELEASE;
	}
	g_mod_shift = (b & 0x04) != 0;
	g_mod_ctrl  = (b & 0x10) != 0;
	if ((b & 0x20))                      /* motion, with a button held */
		return K_DRAG;
	if ((b & 0x40) && (b & 3) == 0)
		return K_WHEEL_UP;
	if ((b & 0x40) && (b & 3) == 1)
		return K_WHEEL_DOWN;
	if ((b & 3) == 2)
		return K_RCLICK;
	return K_CLICK;
}

/* Is there input already waiting. Used to collapse a burst of key repeats into
 * one frame; never blocks. */
int key_pending(void)
{
	return kof_in_ready(0);
}

int read_key(void)
{
	unsigned char c, seq[3];
	ssize_t n;

	/*
	 * A read interrupted by a window change is not end of input.
	 *
	 * There was no handler at all before, so a terminal resized while this
	 * was blocked here went unnoticed until the next keystroke: the screen
	 * kept the layout it had been drawn for, which is what a panel that has
	 * grown or shrunk on its own looks like. Locking a screen resizes the
	 * terminal on most desktops, which is why it showed up after leaving it
	 * alone rather than while working.
	 */
	/*
	 * THE ONLY READ THAT MAY REPORT A RESIZE, and the only one that blocks
	 * for a person rather than for the rest of a sequence.
	 *
	 * ANY interrupted read here means a resize, whether or not the flag
	 * still says so. It used to be `EINTR && kof_tty_resize_pending()`,
	 * and the flag is cleared by the DRAW - so a second resize arriving in
	 * the window between the draw clearing it and this read blocking left
	 * EINTR with the flag already at zero. That fell through to K_NONE and
	 * the loop quit. Measured, with the flag logged: `read n=-1 errno=4
	 * winch_pending=0`, on an ordinary resize.
	 *
	 * Reporting a resize that has already been drawn costs one repaint of
	 * an unchanged screen. Getting it wrong the other way closes the
	 * program somebody was working in.
	 */
	for (;;) {
		n = read(STDIN_FILENO, &c, 1);
		if (n == 1) {
			/*
			 * A NUL BYTE IS A KEY, AND IT IS THIS FUNCTION'S OWN
			 * "NO KEY".
			 *
			 * A terminal sends 0x00 for Ctrl+Space (and Ctrl+@),
			 * and K_NONE is 0 - so the byte was returned, the loop
			 * read it as end of input, and the program CLOSED on a
			 * chord nobody had bound. A stray Ctrl+Space over a
			 * draft that had not been generated lost the draft.
			 *
			 * So it is given a name of its own, above the byte
			 * values, and the sentinel keeps 0 to itself.
			 */
			if (c == 0)
				return K_CTRL_SPACE;
			break;
		}
		if (n < 0 && errno == EINTR)
			return K_RESIZE;
		return K_NONE;   /* 0 is EOF; anything else is a real error */
	}
	if (c != 27)
		return c;
	/*
	 * A LONE ESCAPE HAS TO BE ANSWERABLE WITHOUT A SECOND KEY.
	 *
	 * Escape is both a key and the first byte of every sequence, and the
	 * only thing that tells them apart is whether more bytes follow. This
	 * read used to be unconditional, so a lone Escape sat here until the
	 * NEXT keystroke arrived - and that keystroke was then consumed as the
	 * second byte of a sequence that was never sent. What a reader saw was
	 * an Escape that did nothing, a menu that closed only on the second
	 * press, and - worse - every Alt combination after a stray Escape
	 * behaving as plain Escape, because the Alt's own ESC was eaten as the
	 * tail of the pending one.
	 *
	 * Fifty milliseconds, which is what vim's ttimeoutlen uses for the same
	 * decision. A terminal emits a sequence as one write, so the bytes are
	 * already in the buffer when this polls; the wait only ever elapses for
	 * a key pressed by a person, and fifty milliseconds is below what a
	 * person can perceive as lag.
	 */
	if (!kof_in_ready(ESC_WAIT_MS))
		return 27;
	if (read(STDIN_FILENO, seq, 1) != 1)
		return 27;
	/*
	 * ESC followed by anything that is not a sequence introducer is Escape.
	 *
	 * It used to be marked as Alt+that character and there were menu
	 * shortcuts on the other end. They are gone: what was wanted was a TAP
	 * of Alt taking the menu bar, which a terminal cannot report at all, and
	 * a chord that is not that gesture is a second way in that nobody asked
	 * for. The hot keys this program has are Ctrl+key.
	 */
	if (seq[0] != '[' && seq[0] != 'O')
		return 27;
	if (read(STDIN_FILENO, seq + 1, 1) != 1)
		return 27;
	if (seq[1] == '<')
		return read_mouse();
	if (seq[1] == '2') {
		/*
		 * Bracketed paste: ESC [ 200 ~ ... ESC [ 201 ~
		 *
		 * Read whole and handed over as one thing, because that is what
		 * it is. Fed through the key handler byte by byte it would be
		 * indistinguishable from someone typing very fast, which is
		 * exactly the confusion the brackets exist to remove.
		 */
		unsigned char t[4];
		size_t pn = 0;

		if (read(STDIN_FILENO, t, 1) != 1)
			return 27;
		/*
		 * CSI 21 ~ is F10 and CSI 200 ~ is a paste, and they share their
		 * first two bytes. Told apart here rather than in the switch
		 * below, because this branch has already consumed the '2' - and
		 * F10 was being swallowed as a malformed paste.
		 */
		if (t[0] == '1') {
			if (read(STDIN_FILENO, t, 1) != 1 || t[0] != '~')
				return 27;
			return K_F10;
		}
		if (t[0] != '0')
			return 27;
		if (read(STDIN_FILENO, t, 1) != 1)
			return 27;
		if (read(STDIN_FILENO, t, 1) != 1 || t[0] != '~')
			return 27;
		g_paste_n = 0;
		for (;;) {
			unsigned char c2;

			if (read(STDIN_FILENO, &c2, 1) != 1)
				break;
			if (c2 == 27) {
				unsigned char e[5];
				size_t k = 0;

				while (k < 5 && read(STDIN_FILENO, e + k, 1)
				       == 1) {
					k++;
					if (e[k - 1] == '~')
						break;
				}
				break;          /* the closing bracket */
			}
			if (pn + 1 < sizeof g_paste)
				g_paste[pn++] = (char)c2;
		}
		g_paste_n = pn;
		return K_PASTE;
	}
	if (seq[1] == 'M')
		return read_mouse_x10();
	switch (seq[1]) {
	case 'A': return K_UP;
	case 'B': return K_DOWN;
	case 'C': return K_RIGHT;
	case 'D': return K_LEFT;
	case 'H': return K_HOME;
	case 'F': return K_END;
	/* Shift+Tab. CSI Z, not a tab with a modifier: the terminal has one
	 * code for it and this is the one. */
	case 'Z': return K_BACKTAB;
	case '3': if (read(STDIN_FILENO, seq + 2, 1) != 1) return 27; return K_DEL;
	case '5': if (read(STDIN_FILENO, seq + 2, 1) != 1) return 27; return K_PGUP;
	case '6': if (read(STDIN_FILENO, seq + 2, 1) != 1) return 27; return K_PGDN;
	default:  return 27;
	}
}

void hex_step(struct view *v, long lines)
{
	long per;
	long long at;
	uint64_t max;

	/*
	 * A ROW IS A LINE WHEN THE PANE IS SHOWING TEXT, and a line is not a
	 * fixed number of bytes - so the step is walked rather than multiplied.
	 *
	 * Here rather than at the five places that scroll, for the reason
	 * byte_under dispatches internally too: the wheel, the arrows and both
	 * page keys all come through this one call, and a second layout they
	 * each had to know about is a layout one of them would forget.
	 */
	if (text_pane(v)) {
		struct object *ob = cur_obj(v);
		uint64_t n = ob ? ob->buf.n : 0;
		const uint8_t *b = ob ? ob->buf.p : NULL;
		uint64_t a;

		if (!b)
			n = 0;
		uint64_t top;

		a = txt_line_start(v, b, n, v->rgn_at);
		while (lines > 0 && a < v->rgn_len) {
			uint64_t nx = txt_line_end(v, b, n, a);

			if (nx >= v->rgn_len)
				break;
			a = nx;
			lines--;
		}
		while (lines < 0 && a > 0) {
			a = txt_line_start(v, b, n, a - 1u);
			lines++;
		}
		/* And never past the point where the last line is on the
		 * bottom row - see txt_max_top. */
		top = txt_max_top(v, b, n, txt_bot(v) - hex_top() + 1);
		v->rgn_at = a > top ? top : a;
		return;
	}

	per = v->per > 0 ? v->per : 16;
	at = (long long)v->rgn_at + lines * per;
	max = hex_max(v);

	if (at < 0)
		at = 0;
	if ((uint64_t)at > max)
		at = (long long)max;
	v->rgn_at = (uint64_t)at;
}

/*
 * THE TEXT PANE'S TWO WHEELS, registered where the pane is drawn.
 *
 * Three lines each, and that is the point: what used to decide this was a
 * chain of geometry tests inside on_wheel that every scrollable area had to be
 * added to. The pane declares what it answers, beside the rectangle it answers
 * in - which is the same rectangle it clips its drawing to.
 */
void hit_wheel_text(struct view *v, uint32_t arg)
{
	(void)arg;
	hex_step(v, g_wheel > 0 ? 3 : -3);
}

void hit_hwheel_text(struct view *v, uint32_t arg)
{
	(void)arg;
	txt_hscroll(v, g_wheel > 0 ? 4 : -4);
}

/* A click says which pane as well as which row, so it moves the focus too:
 * clicking a row nobody is looking at and having nothing happen is the one
 * behaviour a mouse must not have. */
/* Milliseconds on a clock that does not go backwards; only differences are
 * ever taken from it. */
uint64_t now_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
		return 0;
	return (uint64_t)t.tv_sec * 1000u + (uint64_t)(t.tv_nsec / 1000000);
}

/*
 * Grow a selection out to the whole printable run around it.
 *
 * What a double click means in every text editor, and what a researcher taking
 * a marker actually wants: a string is a run of printable bytes between two
 * that are not, and picking its ends by dragging is the fiddliest thing in this
 * tool. Bounded by the region being looked at, so it cannot walk into bytes the
 * pane is not showing.
 */
void select_run(struct view *v)
{
	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);
	uint64_t a = v->sel_a, b;

	if (a == KGENOME_BROKEN || !bp)
		return;
	b = a;
	while (a > 0) {
		uint64_t f = view_map(v, a - 1u, 0);

		if (f == KGENOME_BROKEN || f >= bn || !byte_text(bp[f]))
			break;
		a--;
	}
	while (b + 1u < v->rgn_len) {
		uint64_t f = view_map(v, b + 1u, 0);

		if (f == KGENOME_BROKEN || f >= bn || !byte_text(bp[f]))
			break;
		b++;
	}
	v->sel_a = a;
	v->sel_b = b;
}


/*
 * A matcher id on a condition's row, clicked to ask what to do with it.
 *
 * It used to remove the matcher where it stood. Removing is still one of the
 * three things offered, and it is the only one of them that loses work - so it
 * is now something picked off a list rather than the meaning of landing on a
 * number.
 *
 * The columns are the ones the row was DRAWN at, not columns worked out again
 * from a start and a stride. See view.cnd_ids for what that arithmetic cost
 * the last two times it drifted from the drawing.
 */
void cnd_id_click(struct view *v, uint32_t g)
{
	uint32_t m;

	for (m = 0; m < v->ed.dr.n_grp && m < MAX_GROUP; m++) {
		if (v->cnd_ids[g][m][0] < 0)
			continue;
		if (g_mx >= v->cnd_ids[g][m][0] &&
		    g_mx <= v->cnd_ids[g][m][1]) {
			ch_open(v, CH_CMATCH2, CH_PAIR(g, m), g_my, g_mx);
			return;
		}
	}
}

/*
 * Move whatever bar was taken hold of to where the pointer is.
 *
 * The row under the pointer names a fraction of the track, and the fraction
 * names a position in the content. Clamped at both ends rather than checked,
 * because a pointer dragged past the pane is an ordinary thing to do and
 * stopping at the end is what it means.
 */
void bar_to(struct view *v, int which)
{
	int top, bot;
	uint64_t frac, max;

	if (which == 1) {                       /* the hex pane */
		uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);

		top = hex_top(); bot = hex_last();
		if (bot <= top)
			return;
		max = hex_max(v);
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->rgn_at = frac * max / (uint64_t)(bot - top);
		v->rgn_at = v->rgn_at / per * per;
	} else if (which == 2) {                /* the object tree */
		uint32_t rows;

		top = hex_top(); bot = hex_bot();
		if (bot <= top || !v->n_node)
			return;
		rows = (uint32_t)(bot - top + 1);
		if (v->n_node <= rows)
			return;
		max = v->n_node - rows;
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->tree_top = (uint32_t)(frac * max / (uint64_t)(bot - top));
	} else if (which == 3) {                /* the draft panel */
		uint32_t vis;

		if (g_decl_rows < 3)
			return;
		top = decl_top() + 1;
		bot = decl_top() + g_decl_rows - 2;
		vis = (uint32_t)(g_decl_rows - 2);
		if (bot <= top || v->n_prow <= vis)
			return;
		max = v->n_prow - vis;
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->prow_off = (uint32_t)(frac * max / (uint64_t)(bot - top));
	} else if (which == 4) {                /* the disassembly panel */
		/*
		 * The track is the hex pane's range, not the file's - see the
		 * note where this bar is drawn. So the fraction names a place
		 * inside what the hex is showing, and the panel never leaves it.
		 */
		int64_t hi = dis_max_bias(v);

		top = dis_top(); bot = hex_bot();
		if (bot <= top || hi <= 0)
			return;
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->dis_bias = (int64_t)(frac * (uint64_t)hi /
					(uint64_t)(bot - top));
	}
}

/* Is the pointer on a scrollbar, and which. 0 for none. */
int bar_under(struct view *v)
{
	if (g_my >= hex_top() && g_my <= hex_last()) {
		if (g_mx == g_cols && v->rgn_len)
			return 1;
	}
	if (g_my >= hex_top() && g_my <= hex_bot()) {
		if (g_mx == TREE_W)
			return 2;
	}
	/* Before the hex bar's own row test would ever reach here: the panel
	 * owns the bottom of the same column. */
	if (g_disasm_rows && g_mx == g_cols &&
	    g_my >= dis_top() && g_my <= hex_bot() && dis_max_bias(v) > 0)
		return 4;
	if (g_decl_rows && g_mx == g_cols && g_my > decl_top() &&
	    g_my < decl_top() + g_decl_rows - 1)
		return 3;
	return 0;
}
