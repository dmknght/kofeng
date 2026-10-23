#define _GNU_SOURCE
#include "kv.h"


/*
 * ONE TEXT FIELD, FOR EVERY TEXT FIELD.
 *
 * Lifted out of the key handler so that a new box does not get a new editor.
 * Every field in this panel is expected to behave the way a text field behaves
 * anywhere - select all, copy, paste, arrows, Home, End, Delete, backspace,
 * insert at the caret - and the way to guarantee that is for there to be one
 * implementation of it rather than a family of near-copies that drift.
 *
 * `v->edit` names which field is open and is cleared here when it closes, so a
 * caller that has to do something on close - a string declaration, which has to
 * be parsed back out of the text - can see that it happened.
 *
 * Returns 1: a key that reaches a field is consumed by it.
 */
/*
 * `accept` says which characters this field takes, or is NULL for any printable
 * one. It exists because a family name reaches a filesystem path, a C literal
 * and a verdict line - so the field refuses what the build would refuse, as it
 * is typed, rather than letting a draft be finished and then rejected.
 */
int field_key(struct view *v, char *buf, size_t cap, int k,
	      int (*accept)(int))
{
	size_t n;

	n = strlen(buf);
	/* A field just opened puts the caret at the end of what is
	 * already in it, which is where typing continues from. */
	if (v->edit != v->edit_prev) {
		v->edit_prev = v->edit;
		v->caret = (uint32_t)n;
		fsel_clear(v);
	}
	if (v->caret > n)
		v->caret = (uint32_t)n;

	/*
	 * Copy and paste, with the keys everything else uses.
	 *
	 * A terminal keeps Ctrl+Shift+C and Ctrl+Shift+V for itself and
	 * passes the unshifted pair straight through, so these are free
	 * to take - and taking them is what makes a text field here
	 * behave like a text field anywhere else.
	 */
	if (k == 0x01) {                /* Ctrl+A - the whole of it */
		fsel_set(v, 0, (uint32_t)n);
		return 1;
	}
	if (k == 0x03) {                /* Ctrl+C */
		/*
		 * THE SELECTION WHEN THERE IS ONE, the whole field when there
		 * is not.
		 *
		 * Copying all of it regardless is what this used to do, and it
		 * is wrong the moment a range can exist: a reader who drags
		 * through half a pattern and presses Ctrl+C is asking for that
		 * half. With nothing selected the field IS the selection, which
		 * is the convention a one-line box gets to keep.
		 */
		uint32_t lo, hi;

		if (fsel_range(v, &lo, &hi) && hi <= n) {
			copy_osc52(buf + lo, hi - lo);
			copy_said(v, hi - lo);
		} else {
			copy_osc52(buf, n);
			copy_said(v, n);
		}
		return 1;
	}
	/*
	 * Anything that writes replaces the selection first.
	 *
	 * Done here rather than in each branch so no branch can forget:
	 * a field that is shown as selected and then appends is worse
	 * than one that never offered selection.
	 */
	{
		uint32_t lo, hi;

		if (fsel_range(v, &lo, &hi) &&
		    (k == 127 || k == 8 || k == K_DEL || k == 0x16 ||
		     k == K_PASTE || (k >= 0x20 && k < 0x7f))) {
			if (hi > n)
				hi = (uint32_t)n;
			if (lo > hi)
				lo = hi;
			memmove(buf + lo, buf + hi, n - hi + 1u);
			n -= hi - lo;
			v->caret = lo;
			fsel_clear(v);
			if (k == 127 || k == 8 || k == K_DEL)
				return 1;
		} else if (fsel_range(v, &lo, &hi) &&
			   (k == K_LEFT || k == K_RIGHT || k == K_HOME ||
			    k == K_END || k == 27 || k == '\r' ||
			    k == '\n')) {
			fsel_clear(v);
		}
	}
	if (k == 0x16 || k == K_PASTE) {        /* Ctrl+V, or a paste */
		/*
		 * A bracketed paste is the terminal handing over the system
		 * clipboard already - use it as given. A Ctrl+V asks the
		 * clipboard tools for it, so it pastes what any program would;
		 * only when none is installed does it fall back to this
		 * program's own last copy, which is the best it can then do.
		 */
		const char *src;
		size_t sn = paste_src(k, &src), i;

		for (i = 0; i < sn && n + 2u < cap; i++) {
			char c2 = src[i];

			if (c2 < 0x20 || c2 >= 0x7f)
				continue;   /* a field holds a line */
			memmove(buf + v->caret + 1u, buf + v->caret,
				n - v->caret + 1u);
			buf[v->caret++] = c2;
			n++;
		}
		return 1;
	}
	if (k == K_LEFT) {
		if (v->caret)
			v->caret--;
	} else if (k == K_RIGHT) {
		if (v->caret < n)
			v->caret++;
	} else if (k == K_HOME) {
		v->caret = 0;
	} else if (k == K_END) {
		v->caret = (uint32_t)n;
	} else if (k == 27 || k == '\r' || k == '\n') {
		v->edit = 0;
	} else if (k == 127 || k == 8) {
		/* Deletes what is BEFORE the caret, which is what
		 * backspace means; the character under it is what
		 * a delete key takes, below. */
		if (v->caret) {
			memmove(buf + v->caret - 1u, buf + v->caret,
				n - v->caret + 1u);
			v->caret--;
		}
	} else if (k == K_DEL) {
		if (v->caret < n)
			memmove(buf + v->caret, buf + v->caret + 1u,
				n - v->caret);
	} else if (k >= 0x20 && k < 0x7f && n + 2u < cap &&
		   (!accept || accept(k))) {
		memmove(buf + v->caret + 1u, buf + v->caret,
			n - v->caret + 1u);
		buf[v->caret++] = (char)k;
	}
	return 1;
}

/*
 * The keyboard, while the menu bar is open. Returns 1 if it took the key.
 *
 * Left and right move between menus, up and down within one, Enter runs the
 * selected item - a submenu parent opens, everything else acts - and Escape
 * backs out one level. The same model every menu bar in a terminal uses, which
 * is the point: a reader does not have to learn this one.
 */
static int bar_key(struct view *v, int k)
{
	if (v->bar_open < 0)
		return 0;
	/* The same vocabulary the choosers use - see kv_nav_key. The MEANINGS
	 * below are the bar's own: sideways with no submenu open walks the bar,
	 * which is a thing only a bar can do. */
	switch (kv_nav_key(k)) {
	case KV_NAV_OUT:
		/*
		 * Out of a submenu first, and only then along the bar.
		 *
		 * The two directions are what a submenu is navigated with
		 * everywhere, and giving them the job is what lets Escape mean
		 * one thing. It used to walk the bar whatever was open, so the
		 * only way back out of a submenu was Escape - which then had to
		 * be pressed twice to leave the bar, once per level.
		 */
		if (v->bar_sub >= 0) {
			v->bar_sel = v->bar_sub;   /* back onto the parent */
			v->bar_sub = -1;
		} else {
			bar_open_menu(v, (v->bar_open + BM_COUNT - 1) %
					 BM_COUNT);
		}
		return 1;
	case KV_NAV_IN:
		/* Into the selected submenu when there is one; along the bar
		 * when there is not. */
		if (v->bar_sub < 0 && v->bar_sel >= 0 &&
		    bar_has_sub(v->bar_sel) && bar_enabled(v, v->bar_sel))
			bar_enter_sub(v, v->bar_sel);
		else if (v->bar_sub >= 0)
			break;                  /* already in it; nothing to do */
		else
			bar_open_menu(v, (v->bar_open + 1) % BM_COUNT);
		return 1;
	case KV_NAV_PREV:
		/* Inside an open submenu the arrows walk it; the submenu draws
		 * its own selection, so leave the bar cursor alone. */
		bar_move_item(v, -1);
		return 1;
	case KV_NAV_NEXT:
		bar_move_item(v, +1);
		return 1;
	case KV_NAV_TAKE:
		if (v->bar_sel >= 0)
			bar_run(v, v->bar_sel);
		return 1;
	case KV_NAV_DISMISS:
		/*
		 * ONE PRESS LEAVES THE BAR, from however deep in it.
		 *
		 * It used to unwind a level at a time, so leaving a submenu
		 * took two presses - and from the outside that is
		 * indistinguishable from an Escape that was dropped, which is
		 * exactly how it was reported. Escape means "I am done with
		 * this", and the level is not what a reader is counting.
		 */
		v->bar_open = v->bar_sel = v->bar_sub = -1;
		return 1;
	default:
		break;
	}
	return 1;                               /* the open bar swallows the rest */
}
/*
 * handle_f10 - F10, which opens the menu bar from the keyboard.
 *
 * Lifted out of handle() whole. -1 means "not mine, carry on down the chain",
 * which is what falling out of the bottom of this block used to mean; anything
 * else is what handle() itself would have returned.
 */
int handle_f10(struct view *v, int k)
{
	if (k == K_F10) {
		if (v->bar_open >= 0)
			v->bar_open = v->bar_sel = v->bar_sub = -1;
		else
			bar_open_menu(v, BM_FILE);
		return 1;
	}
	/*
	 * An open bar owns the KEYBOARD, the same way the properties page does -
	 * and only the keyboard.
	 *
	 * bar_key swallows every key it does not use, which is right: a letter
	 * typed under an open menu must not reach the pane behind it. It is
	 * wrong for the mouse, and that is how this broke. A menu opened by
	 * CLICKING the bar could not then be clicked: the click on the item
	 * arrived here as K_CLICK, bar_key swallowed it, and click() - which
	 * holds the whole hit test for menu rows - was never reached. The menu
	 * stayed down, every later click vanished into it, and the program read
	 * as frozen while it was in fact answering every keystroke.
	 *
	 * The range test is the one the enum was made contiguous for.
	 */
	return -1;
}

/*
 * handle_bar_key - a key while the menu bar has the focus.
 *
 * Lifted out of handle() whole. -1 means "not mine, carry on down the chain",
 * which is what falling out of the bottom of this block used to mean; anything
 * else is what handle() itself would have returned.
 */
int handle_bar_key(struct view *v, int k)
{
	if (v->bar_open >= 0 && !(k >= K_CLICK && k <= K_RELEASE) &&
	    bar_key(v, k))
		return 1;
	/*
	 * Ctrl+C IN A DIALOG COPIES THE DIALOG, tested before every other owner
	 * of that key.
	 *
	 * The box is over everything else, so while one is up it is the only
	 * thing a reader can be selecting in - and the disassembly panel's own
	 * Ctrl+C below would otherwise answer for a selection nobody can see.
	 */
	return -1;
}

/*
 * handle_copy_key - Ctrl+C, which belongs to whichever pane can copy.
 *
 * Lifted out of handle() whole. -1 means "not mine, carry on down the chain",
 * which is what falling out of the bottom of this block used to mean; anything
 * else is what handle() itself would have returned.
 */
int handle_copy_key(struct view *v, int k)
{
	if (k == 0x03 && v->sym_open && v->dlg_have) {
		dlg_copy(v);
		return 1;
	}
	if (k == 0x03 && v->dis_open && (v->dis_have || dis_hex_sel(v)) &&
	    !v->prop_open && !v->find_open && !v->edit) {
		dis_copy(v);
		return 1;
	}

	/*
	 * THE SYMBOLS DIALOG OWNS THE KEYBOARD WHILE IT IS UP.
	 *
	 * Everything it does not use is swallowed rather than passed down. It
	 * is a modal over the pane, so a Down arrow meant for the table must
	 * not scroll a hex pane the reader cannot see - which is the failure
	 * that makes a dialog feel like it is not really there. The mouse is
	 * NOT swallowed here: click() holds the hit test for the box, the same
	 * arrangement the menu bar above needed and for the same reason.
	 *
	 * Tab switches halves, because two tabs a click apart want a key too,
	 * and it is the key every other tabbed thing uses.
	 */
	return -1;
}

/*
 * handle_symd_key - a key while the symbols dialog is open.
 *
 * Lifted out of handle() whole. -1 means "not mine, carry on down the chain",
 * which is what falling out of the bottom of this block used to mean; anything
 * else is what handle() itself would have returned.
 */
int handle_symd_key(struct view *v, int k)
{
	if (v->sym_open && !(k >= K_CLICK && k <= K_RELEASE)) {
		int pg = symd_rows() > 1 ? symd_rows() - 1 : 1;

		/*
		 * TYPING GOES TO THE FILTER WHILE IT IS OPEN, and only then.
		 *
		 * The dialog's own keys are arrows, Tab and Escape; a field
		 * that swallowed those would be a field nobody could leave.
		 * Escape closes the field rather than the dialog, which is the
		 * one place this differs from the rest of the program and is
		 * what a reader who mistyped a pattern expects.
		 */
		if (v->edit == ED_SYMFILT) {
			/*
			 * ONE EDITOR. field_key is what every other field in
			 * this program uses, so the caret, the selection,
			 * Ctrl+A and paste behave here the way they do
			 * everywhere - a hand-written copy is a copy that
			 * drifts, and this one had already drifted before it
			 * was a day old.
			 *
			 * Two keys are the dialog's rather than the field's:
			 * the vertical ones scroll the list underneath, which
			 * is what a reader narrowing a long table expects, and
			 * Escape closes the FIELD - the dialog's own Escape
			 * would take the table away with it.
			 */
			switch (k) {
			case K_UP: case K_DOWN: case K_PGUP: case K_PGDN:
				break;          /* the dialog's, see below */
			case 27:
				v->edit = 0;
				return 1;
			default: {
				int r2 = field_key(v, v->sy_filt,
						   sizeof v->sy_filt, k, NULL);

				if (k == '\r' || k == '\n')
					v->edit = 0;
				symd_filter_compile(v);
				v->sym_at = 0;
				return r2;
			}
			}
		}
		switch (k) {
		/* Escape and the close button, and no letter - see the note on
		 * bare keys in handle(). */
		case 27:
			dlg_close(v);
			break;
		case '\t':
			v->sym_open = v->sym_open == SYMN_IMP ? SYMN_EXP
							     : SYMN_IMP;
			v->sym_at = 0;
			v->sym_hoff = 0;
			break;
		case K_UP:    symd_scroll(v, -1);            break;
		case K_DOWN:  symd_scroll(v, 1);             break;
		case K_LEFT:  symd_hscroll(v, -4);           break;
		case K_RIGHT: symd_hscroll(v, 4);            break;
		case K_PGUP:  symd_scroll(v, -(int64_t)pg);  break;
		case K_PGDN:  symd_scroll(v, pg);            break;
		case K_HOME:  v->sym_at = 0;                 break;
		case K_END:   v->sym_at = symd_max(v);       break;
		default:      break;
		}
		return 1;
	}

	/*
	 * The properties page owns the keyboard while it is up.
	 *
	 * Unlike the two help boxes it is a page rather than a card, so "any
	 * key closes" is the wrong contract: the keys a reader reaches for are
	 * the ones that move down it. Only the three that mean "done" close it,
	 * and everything else is swallowed so a keystroke meant for the page
	 * does not land on the draft behind it.
	 */
	return -1;
}

/*
 * The Decoder owns the keyboard while it is up.
 *
 * A FORM, so Tab moves between its controls and Enter runs it - the two things
 * a form does everywhere else. Esc closes; every other key goes to whichever
 * field has the caret, which is how a pasted string gets in.
 */
int handle_enc_key(struct view *v, int k)
{
	if (!v->enc_open)
		return -1;
	switch (k) {
	case 27:
		v->enc_open = 0;
		v->edit = 0;
		return 1;
	/*
	 * TAB MOVES, THE ARROWS CHOOSE - and keeping those apart is not a
	 * detail. They were one key at first: Tab cycled the coding when the
	 * caret was in the input, which meant that once it reached xor there
	 * was no way back to the input that did not also leave xor. A key that
	 * moves focus and changes a value depending on where the focus is
	 * cannot be pressed twice with the same meaning.
	 */
	case '\t':
		if (v->edit == ED_ENC_IN && kof_codec_keyed(v->enc_type)) {
			v->edit = ED_ENC_KEY;
			v->caret = (uint32_t)strlen(v->enc_key);
		} else {
			v->edit = ED_ENC_IN;
			v->caret = (uint32_t)strlen(v->enc_in);
		}
		return 1;
	case K_LEFT:
	case K_RIGHT:
		v->enc_type = k == K_RIGHT
			    ? (v->enc_type + 1u) % (uint32_t)KOF_CODEC_COUNT
			    : (v->enc_type + (uint32_t)KOF_CODEC_COUNT - 1u) %
			      (uint32_t)KOF_CODEC_COUNT;
		v->enc_res_n = 0;
		v->enc_done = 0;
		if (!kof_codec_keyed(v->enc_type) && v->edit == ED_ENC_KEY)
			v->edit = ED_ENC_IN;
		return 1;
	case '\r': case '\n':
		enc_do(v);
		return 1;
	case 0x03:                      /* Ctrl+C */
		dlg_copy(v);
		return 1;
	/*
	 * THE WHEEL MOVES THE PLAINTEXT, sideways with shift - the window is
	 * the only thing in this box that has anywhere to scroll.
	 */
	case K_WHEEL_UP:
	case K_WHEEL_DOWN: {
		uint32_t *off = g_mod_shift ? &v->enc_hoff : &v->enc_voff;
		uint32_t step = g_mod_shift ? 8u : 1u;

		if (k == K_WHEEL_UP)
			*off = *off > step ? *off - step : 0u;
		else
			*off += step;   /* clamped where the window is drawn */
		return 1;
	}
	case K_CLICK: case K_RCLICK: case K_DRAG: case K_RELEASE:
		return -1;              /* the mouse goes to enc_click */
	default:
		if (v->edit == ED_ENC_KEY)
			return field_key(v, v->enc_key, sizeof v->enc_key, k,
					 NULL);
		v->edit = ED_ENC_IN;
		return field_key(v, v->enc_in, sizeof v->enc_in, k, NULL);
	}
}

/*
 * handle_prop_key - a key while the dashboard is open.
 *
 * Lifted out of handle() whole. -1 means "not mine, carry on down the chain",
 * which is what falling out of the bottom of this block used to mean; anything
 * else is what handle() itself would have returned.
 */
int handle_prop_key(struct view *v, int k)
{
	if (v->prop_open) {
		int room = g_rows - 6;

		if (room < 1)
			room = 1;
		switch (k) {
		case K_UP:
			if (v->prop_off)
				v->prop_off--;
			return 1;
		case K_DOWN:
			v->prop_off++;
			return 1;
		case K_WHEEL_UP:
		case K_WHEEL_DOWN: {
			/*
			 * A WHEEL OVER A TABLE SCROLLS THAT TABLE, and the
			 * page otherwise.
			 *
			 * Which is what a reader means by it: a table with its
			 * own window is a thing to scroll, and scrolling the
			 * page under the pointer instead moves the table out
			 * from under it. The page is still what the wheel gets
			 * anywhere else, and the arrows and PgUp always mean
			 * the page - so nothing that worked stops working.
			 */
			int t = prop_tab_at(v, g_my, g_mx);

			/*
			 * ONLY IF IT CAN MOVE. A table with fewer rows than it
			 * shows has no scroll to take, and taking the wheel
			 * anyway left the page stuck under it.
			 */
			if (t >= 0 && !(g_mod_shift ? g_prop_tab_scroll_h[t]
						    : g_prop_tab_scroll_v[t]))
				t = -1;
			if (t >= 0) {
				/*
				 * SHIFT MEANS SIDEWAYS, which is the gesture
				 * every terminal already uses for it - and the
				 * only way to reach the tail of a PATH, since
				 * the page itself has no horizontal scroll.
				 */
				uint32_t *off = g_mod_shift
						? &g_prop_tab_hoff[t]
						: &g_prop_tab_off[t];
				uint32_t step = g_mod_shift ? 8u : 1u;

				if (k == K_WHEEL_UP)
					*off = *off > step ? *off - step : 0u;
				else
					*off += step;
				return 1;
			}
			if (k == K_WHEEL_UP)
				v->prop_off = v->prop_off > 3u
					      ? v->prop_off - 3u : 0;
			else
				v->prop_off += 3u;
			return 1;
		}
		case K_PGUP:
			v->prop_off = v->prop_off > (uint32_t)room
				      ? v->prop_off - (uint32_t)room : 0;
			return 1;
		case K_PGDN:
			v->prop_off += (uint32_t)room;
			return 1;
		case K_HOME:
			v->prop_off = 0;
			return 1;
		case K_END:
			/* Clamped where it is drawn, which is the only place
			 * that knows how many lines there are. */
			v->prop_off = 0xffffffu;
			return 1;
		case K_DRAG:
			/*
			 * THE DRAG HAS TO REACH THE SELECTION LAYER, and this
			 * is where it did not.
			 *
			 * It was swallowed here on the reasoning that the
			 * click handler had "already fed" the selection. The
			 * click only sets the ANCHOR; extending it is
			 * on_drag's dlg_drag branch, and that branch was never
			 * reached while this page was up. So dragging across
			 * the dashboard picked out exactly what the press had
			 * picked and no more - which looked like a viewer with
			 * no drag selection at all.
			 *
			 * A modal still owns the mouse: this is handed to the
			 * selection layer and then swallowed, rather than
			 * falling through to the panes underneath.
			 */
			on_drag(v);
			return 1;
		case K_RELEASE:
			on_release(v);
			return 1;
		case 0x03:                      /* Ctrl+C */
			dlg_copy(v);
			return 1;
		case 27:
		case '\r':
		case '\n':
			v->prop_open = 0;
			return 1;
		case K_CLICK:
		case K_RCLICK:
			/*
			 * Only the close control closes it.
			 *
			 * A click anywhere used to dismiss the page, which
			 * meant every attempt to scroll it by grabbing at it,
			 * or to click a line to read it more closely, threw the
			 * page away. A window with a close button is closed by
			 * its close button.
			 *
			 * Everything else a click does here is a SELECTION, and
			 * that is click()'s - it holds the hit test for every
			 * dialog's recorded text and this one is no longer an
			 * exception to it.
			 */
			if (g_my == v->prop_y && g_mx >= v->prop_x0 &&
			    g_mx <= v->prop_x1) {
				v->prop_open = 0;
				return 1;
			}
			/*
			 * -1, NOT 0. In this function 0 means "handled, and the
			 * answer is 0" - and 0 is what handle() returns to quit.
			 * "Not mine, carry on down the chain" is -1, which is
			 * what lets the click reach click() and be a selection.
			 */
			return -1;
		}
	}
	/*
	 * A field being edited takes every printable key.
	 *
	 * Before the switch rather than inside it: while a name is being typed,
	 * "q" is a letter and not a command, and a text field that quits the
	 * program on one keystroke is the kind of thing people only find out
	 * once.
	 */
	/*
	 * A mode that takes the keyboard must not take the mouse.
	 *
	 * These two branches used to return for every event, mouse included, so
	 * while a chooser was open no click reached the router that would have
	 * dismissed it - and while a name was being typed, clicking anywhere
	 * else left the focus where it was and every key stayed a letter. Both
	 * looked like the mouse had stopped working.
	 */
	return -1;
}

/*
 * handle_chooser_key - a key while a chooser is open.
 *
 * Lifted out of handle() whole. -1 means "not mine, carry on down the chain",
 * which is what falling out of the bottom of this block used to mean; anything
 * else is what handle() itself would have returned.
 */
int handle_chooser_key(struct view *v, int k)
{
	if (k >= K_CLICK && k <= K_RELEASE)
		;                       /* fall through to the router below */
	else if (v->ch.open) {
		enum kv_nav nav = kv_nav_key(k);

		switch (nav) {
		case KV_NAV_PREV:
		case KV_NAV_NEXT:
			/*
			 * OVER A SEPARATOR AND NOT ONTO IT. kv_nav_step stops
			 * at the ends rather than wrapping, so a rule sitting
			 * at the top or bottom would trap the cursor - the
			 * loop gives up when a step changes nothing and the
			 * selection is left where it was.
			 */
			{
				int to = v->ch.sel, from;

				do {
					from = to;
					to = kv_nav_step(to, v->ch.n, nav);
				} while (to >= 0 && to < v->ch.n &&
					 v->ch.sep[to] && to != from);
				if (to >= 0 && to < v->ch.n && v->ch.sep[to])
					to = v->ch.sel;
				v->ch.sel = to;
				ch_follow(&v->ch);
			}
			break;
		case KV_NAV_IN:
			/*
			 * ch_take is what opens a submenu - the same call the
			 * click makes - so there is ONE path that builds one
			 * and the two ways in cannot drift. On a row that acts
			 * rather than opening, this does nothing: a sideways
			 * key that sometimes carries out the highlighted item
			 * is a key nobody can press with confidence.
			 */
			if (v->ch.sel >= 0 && v->ch.sel < v->ch.n &&
			    v->ch.sub[v->ch.sel])
				ch_take(v);
			break;
		case KV_NAV_OUT:
			/* Back to the list this one came from, landing on the
			 * row that opened it - where its cursor already is. */
			if (v->ch_up.open) {
				v->ch = v->ch_up;
				v->ch_up.open = 0;
			}
			break;
		case KV_NAV_TAKE:
			/* Nothing is highlighted until an arrow says so, so
			 * there is nothing for Enter to take. */
			if (v->ch.sel >= 0)
				ch_take(v);
			break;
		case KV_NAV_DISMISS:
			v->ch.open = 0;
			break;
		default:
			if (k == 'q')
				v->ch.open = 0;
			break;
		}
		return 1;
	} else if (v->edit) {
		/*
		 * One editor, several fields. The code says which: 1 the
		 * family, 4+i a condition's custom variant, 103+i a condition's
		 * expression, 200+i an optional size, 300+i a matcher's
		 * comment, 400+i a condition's comment.
		 *
		 * Each band is tested as a band, not as "at least". The size
		 * editor used to claim everything from 200 up, so the comment
		 * boxes added above it opened, took the caret, and then
		 * silently dropped every key that was not a digit.
		 */
		if (v->edit >= 200 && v->edit < 200 + OPT_COUNT) {
			/*
			 * A size, typed as digits and nothing else.
			 *
			 * Bounded on the way in rather than checked on the way
			 * out: a field that accepts a number it will refuse is
			 * a field that wastes the typing. Sixteen digits is far
			 * past any object this engine will be handed, and a
			 * minus sign is simply not a character a size has.
			 */
			int oi = (v->edit - 200) % OPT_COUNT;
			size_t nn = strlen(v->num);

			if (k == 27 || k == '\r' || k == '\n') {
				v->ed.dr.opt_val[oi] = strtoull(v->num, NULL, 10);
				v->edit = 0;
			} else if ((k == 127 || k == 8) && nn) {
				v->num[nn - 1u] = 0;
			} else if (k >= '0' && k <= '9' && nn < 16u) {
				if (v->num_fresh) {
					v->num[0] = 0;
					nn = 0;
				}
				v->num[nn] = (char)k;
				v->num[nn + 1u] = 0;
			}
			v->num_fresh = 0;
			return 1;
		}
		/*
		 * Esc closes the box whether or not the field has the caret.
		 * A click on the pane behind takes the caret away but leaves
		 * the box up - deliberately, so a half-typed offset survives a
		 * stray click - and without this there was then no key that
		 * would put it away, only the Cancel button.
		 */
		if (v->goto_open && k == 27) {
			v->goto_open = 0;
			v->edit = 0;
			return 1;
		}
		if (v->edit == 520) {
			/*
			 * The Go to field: hex digits, the two prefixes, and
			 * the editing a one-line number needs and no more.
			 * Enter jumps, Esc closes without moving - the same
			 * pair every other prompt here uses.
			 */
			size_t nn = strlen(v->gotobuf);

			if (v->edit != v->edit_prev) {
				v->edit_prev = v->edit;
				v->caret = (uint32_t)nn;
				fsel_clear(v);
			}
			if (k == 27) {
				v->goto_open = 0;
				v->edit = 0;
			} else if (k == '\r' || k == '\n') {
				goto_take(v);
			} else if ((k == 127 || k == 8) && nn) {
				v->gotobuf[nn - 1u] = 0;
				v->caret = (uint32_t)(nn - 1u);
			} else if (k == 0x16 || k == K_PASTE) {
				/* An offset is exactly the kind of thing that
				 * gets copied out of a report and pasted in
				 * here, so it takes the system clipboard like
				 * every other field - see paste_src. Only the
				 * characters an offset can hold are kept, so a
				 * pasted "0x1a2b\n" arrives clean. */
				const char *src;
				size_t sn = paste_src(k, &src), i;

				for (i = 0; i < sn &&
				     nn + 1u < sizeof v->gotobuf; i++) {
					char c2 = src[i];

					if (!((c2 >= '0' && c2 <= '9') ||
					      (c2 >= 'a' && c2 <= 'f') ||
					      (c2 >= 'A' && c2 <= 'F') ||
					      c2 == 'x' || c2 == 'X' ||
					      c2 == 'n' || c2 == 'N'))
						continue;
					if (v->num_fresh) {
						v->gotobuf[0] = 0;
						nn = 0;
						v->num_fresh = 0;
					}
					v->gotobuf[nn++] = c2;
					v->gotobuf[nn] = 0;
				}
				v->caret = (uint32_t)nn;
			} else if (((k >= '0' && k <= '9') ||
				    (k >= 'a' && k <= 'f') ||
				    (k >= 'A' && k <= 'F') ||
				    k == 'x' || k == 'X' || k == 'n' || k == 'N')
				   && nn + 1u < sizeof v->gotobuf) {
				if (v->num_fresh) {
					v->gotobuf[0] = 0;
					nn = 0;
				}
				v->gotobuf[nn] = (char)k;
				v->gotobuf[nn + 1u] = 0;
				v->caret = (uint32_t)(nn + 1u);
			}
			v->num_fresh = 0;
			return 1;
		}
		if (v->edit == 500) {
			/*
			 * Typing into the find dialog.
			 *
			 * Enter searches forward and Shift is not consulted for
			 * anything: the dialog has buttons for backwards and for
			 * scope, which is why there is no chord for either. A
			 * terminal cannot tell Ctrl+Shift+F from Ctrl+F without
			 * one of the newer key protocols, and a control that
			 * works on some terminals is worse than a button.
			 */
			/*
			 * ONE EDITOR, and the two things this field does that
			 * the others do not.
			 *
			 * The body used to be an eighty-line copy of field_key
			 * - the same caret, the same selection, the same paste
			 * - written out again because of those two. It is the
			 * copy that drifts: Ctrl+A here selected a field that
			 * a later fix to field_key had already taught to be
			 * selected differently.
			 *
			 * ESCAPE also puts the dialog away, not just the
			 * caret. ENTER searches and LEAVES THE FIELD OPEN, so
			 * pressing it again searches again - field_key closes
			 * on Enter because every other field is finished by
			 * it, and this one is not.
			 */
			int esc = k == 27, run = k == '\r' || k == '\n';
			int r2 = field_key(v, v->find, sizeof v->find, k, NULL);

			/* The pattern changed, so what it compiles to has to -
			 * see find_compile. Cheap: it is a few dozen bytes of
			 * text and nothing else asks. */
			find_compile(v);
			if (esc) {
				v->find_open = 0;
			} else if (run) {
				v->edit = 500;
				v->find_at = KGENOME_BROKEN;
				find_run(v, 0);
			}
			return r2;
		}
		if (v->edit >= ED_STR && v->edit < ED_STR + MAX_DECL) {
			uint32_t si = (uint32_t)(v->edit - ED_STR);
			/* The cap is the declaration's, not the scratch's: see
			 * DECL_HEXS_CAP. They are the same size today, and
			 * naming the right one is what keeps them that way. */
			int r2 = field_key(v, v->ed.dr.sedit,
					   sizeof v->ed.dr.decl[si].hexs, k,
					   NULL);

			/* field_key clears v->edit when the field closes, and
			 * closing is when the text becomes a declaration. */
			if (!v->edit)
				decl_edit_commit(&v->ed, si);
			return r2;
		}
		{
		/*
		 * Which box the keys are going into, and how much it holds.
		 *
		 * The cap used to be one number for every field, which was the
		 * smallest of them - so a comment stopped at the length of a
		 * variant name for no reason a typist could see. Each field
		 * carries its own now, taken from the array it is.
		 */
		char *buf;
		size_t cap;
		/* A name goes into a path, a literal and a verdict line; the
		 * rest of these are prose. See kof_name_char in kofsig.h. */
		int (*accept)(int) = NULL;

		/*
		 * THE MUTATION THRESHOLD, AND IT HAS TO BE ASKED FIRST.
		 *
		 * ED_GRP_PCT is 700 and the chain below opens with
		 * "v->edit >= 300", so every key typed into the threshold was
		 * going into a matcher's note - the box showed nothing changing
		 * and a comment two panels away filled up with digits.
		 *
		 * Committed on every key rather than on leaving the field: the
		 * score beside it is what the number is being chosen against,
		 * and a threshold that only took effect afterwards would be a
		 * number the reader could not see the effect of.
		 */
		/*
		 * THE STEP OF AN AT PLACE, asked before the chain below for
		 * the same reason the threshold is: that chain opens at 300
		 * and would swallow every digit typed here.
		 *
		 * Committed on every key rather than on leaving the field,
		 * which is what lets the row beside it stay true - and the
		 * number is the author's from the first one, so at_auto goes
		 * off and a later anchor change will not convert it.
		 */
		if (v->edit >= ED_AT_OFF &&
		    v->edit < ED_AT_OFF + (int)MAX_GROUP) {
			uint32_t gi = (uint32_t)(v->edit - ED_AT_OFF);
			int r2 = field_key(v, v->at_buf, sizeof v->at_buf, k,
					   at_digit);

			if (gi < v->ed.dr.n_grp) {
				struct group *q = &v->ed.dr.grp[gi];
				unsigned long long got =
					strtoull(v->at_buf, NULL, 0);

				/* An empty box is a box nothing has been typed
				 * into yet, not a step of zero. */
				if (v->at_buf[0]) {
					q->at_off = q->at_off < 0
						  ? -(int64_t)got
						  : (int64_t)got;
					q->at_auto = 0;
					grp_at_fix_sign(q);
				}
			}
			return r2;
		}
		if (v->edit >= ED_GRP_PCT &&
		    v->edit < ED_GRP_PCT + (int)MAX_GROUP) {
			uint32_t bi = (uint32_t)(v->edit - ED_GRP_PCT);
			int r2 = field_key(v, v->grp_pct_buf,
					   sizeof v->grp_pct_buf, k, mtn_digit);
			unsigned long got = strtoul(v->grp_pct_buf, NULL, 10);

			/*
			 * THE BOX NEVER HOLDS A NUMBER THAT IS NOT THE VALUE.
			 *
			 * Clamping on the way out and leaving the text alone
			 * meant the box showed 5075 while the rule used 100.
			 * The text is corrected instead, so what is read off
			 * the panel is what the rule will demand.
			 */
			if (got > 100u) {
				got = 100u;
				snprintf(v->grp_pct_buf,
					 sizeof v->grp_pct_buf, "100");
				v->caret = 3;
			}
			/* An empty box is not a threshold of zero - it is a
			 * box nothing has been typed into yet. */
			if (bi < v->ed.dr.n_grp && v->grp_pct_buf[0])
				v->ed.dr.grp[bi].pct = (uint8_t)got;
			return r2;
		}
		if (v->edit == 501) {
			buf = v->ed.dr.note;
			cap = sizeof v->ed.dr.note;
		} else if (v->edit == 1) {
			buf = v->ed.dr.family;
			cap = sizeof v->ed.dr.family;
			accept = kof_name_char;
		} else if (v->edit >= 300) {
			buf = v->ed.dr.grp[(v->edit - 300) % MAX_GROUP].note;
			cap = sizeof v->ed.dr.grp[0].note;
		} else if (v->edit >= 103) {
			buf = v->ed.dr.cnd[(v->edit - 103) % MAX_GROUP].expr;
			cap = sizeof v->ed.dr.cnd[0].expr;
		} else {
			return -1;      /* no other box is open here */
		}
		return field_key(v, buf, cap, k, accept);
		}
	}

	return -1;
}
