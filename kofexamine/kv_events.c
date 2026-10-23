#define _GNU_SOURCE
#include "kv.h"

/*
 * on_drag - what handle() does about a mouse drag.
 *
 * Lifted out of the router's switch whole, because a case body of eighty or a
 * hundred and sixty lines is a function that has not been given a name.
 */
void on_drag(struct view *v)
{
		uint64_t at;

		/*
		 * A DIALOG'S TEXT SELECTION FIRST: the box is a modal, so a drag
		 * while one is up is the box's, whatever else on screen would
		 * otherwise have taken it. dlg_at clamps to the recorded text, so
		 * dragging past the last row extends to it rather than stopping
		 * the moment the pointer leaves the box.
		 */
		/*
		 * A BOX BEING MOVED OWNS THE MOTION, before anything else looks
		 * at it - including a dialog's own text selection, which is the
		 * other thing a drag inside a dialog means.
		 */
		if (v->dlg_move) {
			v->dlg_move->dx = v->dlg_mdx + (g_mx - v->dlg_mx);
			v->dlg_move->dy = v->dlg_mdy + (g_my - v->dlg_my);
			return;
		}
		/*
		 * A DRAG THROUGH THE OPEN TEXT FIELD.
		 *
		 * Only the far end moves - `fld_a` stays where the press put
		 * it - and the caret follows it, which is what a text box does
		 * and what makes the following keystroke land where the pointer
		 * stopped. The ROW is not tested: a one-line box has only one,
		 * and a pointer that strayed a row up or down mid-drag is still
		 * dragging through this field. The column is clamped to the
		 * box, so dragging off either end selects to that end rather
		 * than stopping.
		 */
		if (v->fld_drag && v->edit && g_fld.room > 0) {
			int c = g_mx - g_fld.col;
			uint32_t k;

			if (c < 0)
				c = 0;
			if (c > g_fld.room)
				c = g_fld.room;
			k = g_fld.off + (uint32_t)c;
			fsel_set(v, v->fld_a,
				 k > g_fld.len ? g_fld.len : k);
			v->caret = v->fld_b;
			return;
		}
		if (v->dlg_drag) {
			int r, c;

			if (dlg_at(v, g_my, g_mx, &r, &c)) {
				v->dlg_br = r;
				v->dlg_bc = c;
			}
			return;
		}
		if (v->bar_drag) {
			bar_to(v, v->bar_drag);
			return;
		}
		if (v->sizing) {
			/*
			 * The divider follows the pointer, and the panel takes
			 * what is above it. Bounded at both ends: a panel taller
			 * than the screen would leave no hex to take bytes from,
			 * and one of zero rows would hide the draft while it was
			 * still being written.
			 */
			int want = g_rows - g_my - 2;

			if (want < 1)
				want = 1;
			if (want > g_rows - 8)
				want = g_rows - 8 > 1 ? g_rows - 8 : 1;
			v->ed.dr.decl_cap = (uint32_t)want;
			return;
		}
		if (v->evt_txt_drag) {
			int c = 0;

			/* Only the far end moves. The box is one string, so a
			 * drag down it is a drag through the text rather than
			 * from one row to another. */
			if (evt_text_at(v, g_my, g_mx, &c)) {
				v->evt_txt_b = c;
				evt_sync_hex(v, 0);
			}
			return;
		}
		if (v->dis_dragging && g_disasm_rows) {
			int idx = g_my - dis_top();
			int c = g_mx - (TREE_W + 3);
			int len;

			if (idx < 0)
				idx = 0;
			if (idx >= v->dis_lines)
				idx = v->dis_lines - 1;
			idx = dis_real_row(v, idx);
			if (idx < 0)
				return;
			/* Clamped to the row's own text: a pointer past the end
			 * of a short line selects that line to its end, which is
			 * what dragging over ragged text does everywhere. */
			len = (int)strlen(v->dis_line[idx]);
			if (c < 0)
				c = 0;
			if (c > len - 1)
				c = len > 0 ? len - 1 : 0;
			v->dis_b_at = v->dis_line_at[idx];
			v->dis_bc = c;
			dis_sync_bytes(v);
			return;
		}
		if (v->dragging && byte_under(v, g_my, g_mx, &at)) {
			if (at != v->sel_a)
				v->dragged = 1;
			v->sel_b = at;
			v->sel_from_dis = 0;
			/* The bias tracks the START of the run, so dragging
			 * downward does not drag the panel with it - the run's
			 * head stays where the reader can see it. */
			dis_bias_to_sel(v);
		}
}

/*
 * on_release - what handle() does about the mouse button coming up.
 *
 * Lifted out of the router's switch whole, because a case body of eighty or a
 * hundred and sixty lines is a function that has not been given a name.
 */
void on_release(struct view *v)
{
		/* Letting go of a box's title row puts it down where it is. */
		v->dlg_move = NULL;
		/*
		 * A PRESS THAT NEVER MOVED IS A CLICK, and a click on a table
		 * of values means the value.
		 *
		 * The anchor was laid on the exact character so that a DRAG
		 * can express any span; that leaves a plain click selecting
		 * one character, which is not what anyone means by clicking a
		 * field. The word is restored here, where "did it move" is
		 * finally known - a single-character span after a press is
		 * exactly the case where nothing moved.
		 */
		/*
		 * A PRESS THAT NEVER MOVED SELECTS NOTHING, and that is the
		 * whole of it.
		 *
		 * It used to expand to the word under the pointer, on the
		 * reasoning that a click on a table of values means the value.
		 * That reasoning does not survive contact: the "word" is
		 * whatever dlg_word's separators happen to cut, so clicking a
		 * path took a fragment of it, clicking a number beside a name
		 * took one of the two, and which you got depended on where in
		 * the row you pressed. A selection nobody asked for, of a
		 * span nobody chose.
		 *
		 * So a click places the caret and picks nothing; a DRAG picks
		 * exactly what was dragged over. One gesture, one meaning.
		 */
		/*
		 * A PRESS THAT NEVER MOVED KEEPS ITS ONE CHARACTER.
		 *
		 * It used to drop the selection entirely on the reasoning that
		 * a click picks nothing, and that left a click on a value with
		 * NO visible answer at all - the page looked as though the
		 * click had missed. One character lit is a caret: it says
		 * where the next drag starts from, and a double click on the
		 * same spot then takes the whole cell.
		 */
		/* The drag is over; what was picked stays picked, so
		 * Ctrl+C has something to copy after the button comes up. */
		v->dlg_drag = 0;
		v->sizing = 0;
		v->bar_drag = 0;
		/*
		 * The drag ENDS and the selection STAYS.
		 *
		 * The same shape as the hex pane, which is the point: dragging
		 * out a run picks it, and what to do with it is a separate act
		 * through the same right-click menu. Copying on release was
		 * tried and is wrong here - it makes one pane in the tool
		 * behave unlike the other, and it changes the clipboard on a
		 * gesture that in every other pane changes nothing.
		 */
		v->evt_txt_drag = 0;
		/* Same rule for the panel's text boxes: the range stays, and
		 * Ctrl+C is what takes it. */
		v->fld_drag = 0;
		if (v->dis_dragging) {
			v->dis_dragging = 0;
			return;
		}
		if (v->menu_open)
			return;
		v->dragging = 0;
}

/*
 * on_wheel - what handle() does about a wheel notch, either direction.
 *
 * Lifted out of the router's switch whole, because a case body of eighty or a
 * hundred and sixty lines is a function that has not been given a name.
 */
static void on_wheel(struct view *v, int k)
{
		int down = k == K_WHEEL_DOWN;

		/*
		 * WHATEVER IS UNDER THE POINTER SAID SO ITSELF.
		 *
		 * Asked before the chain below, which is the same chain of
		 * geometry tests the right button used to have at the top of
		 * click() - and it had the same fault: an area that grew a
		 * scroll had to be added to a list in this function, and the
		 * text pane was missing from both directions of it.
		 *
		 * Areas still in the chain keep working; they are migrated by
		 * declaring a rectangle where they are drawn, and each one that
		 * moves is a branch that leaves here. The modal below is asked
		 * FIRST and stays there, because a modal is not one of the
		 * panels the pointer chooses between.
		 */
		g_wheel = down ? 1 : -1;
		if (!v->sym_open &&
		    hit_run(v, (g_mod_shift || g_mod_ctrl)
			       ? (uint8_t)HIT_HWHEEL : (uint8_t)HIT_WHEEL))
			return;

		/*
		 * The dialog first, wherever the pointer is.
		 *
		 * The rule below - the wheel turns whatever it is over - is
		 * about panels laid out side by side. A modal is not one of
		 * those: it is over them, it is the only thing the reader can
		 * be looking at, and scrolling the tree behind it because the
		 * pointer happened to be on the left would move something they
		 * cannot see.
		 */
		if (v->sym_open) {
			/* Shift (or ctrl) turns the wheel sideways, the same
			 * binding the tree, the draft panel and the marker
			 * list already use - see the branch below. */
			if (g_mod_shift || g_mod_ctrl)
				symd_hscroll(v, down ? 4 : -4);
			else
				symd_scroll(v, down ? 3 : -3);
			return;
		}

		/* Shift turns the wheel sideways, the way it does in every
		 * other program that has both. */
		/*
		 * No wheel binding for the text fields.
		 *
		 * They scroll by following their caret, which is the only thing
		 * that should move them - and a field that also moved under the
		 * pointer would fight the panel the pointer is over, which is
		 * exactly what it did.
		 */
		if (g_mod_shift || g_mod_ctrl) {
			/*
			 * Sideways.
			 *
			 * The draft panel is columns of fixed width and one of
			 * them - the comment - holds a sentence. Sliding it is
			 * the only way to read the end of one without making
			 * every other column narrower, so the panel takes the
			 * modified wheel too.
			 */
			uint32_t *h;

			/*
			 * THE TEXT PANE TAKES IT TOO, and it was the one pane
			 * with anything to scroll across.
			 *
			 * This chain knew the marker list, the draft panel and
			 * the tree, and answered NULL for the bytes pane -
			 * which was right while that pane was a hex dump, since
			 * a hex row is as wide as the pane by construction.
			 * A line of source is not, and a minified script is one
			 * line of two hundred thousand characters.
			 *
			 * Through txt_hscroll rather than by moving txt_col
			 * here, so the wheel and the arrow keys cannot end up
			 * with different ideas of where the text stops.
			 */
			if (text_pane(v) && g_mx > TREE_W &&
			    g_my >= hex_top() && g_my <= hex_last()) {
				txt_hscroll(v, down ? 4 : -4);
				return;
			}
			h = (g_decl_rows && g_my > decl_top() &&
			     g_my < mark_row())
			    ? &v->decl_hoff :
			    (g_mx <= TREE_W) ? &v->tree_hoff : NULL;

			if (h) {
				if (down)
					*h += 4u;
				else
					*h = *h > 4u ? *h - 4u : 0u;
			}
			return;
		}
		/*
		 * OVER THE DISASSEMBLY PANEL, THE WHEEL MOVES THE PANEL.
		 *
		 * This is the way out of a conflict that cannot be resolved by
		 * any rule: the hex pane shows about 270 bytes and the panel
		 * about 60, so a selection more than a few hex rows down has no
		 * row in the panel while the two are locked together. Every
		 * automatic answer either stopped the panel following the scroll
		 * or let the highlight leave the rows.
		 *
		 * So the reader gets the wheel. The panel follows the hex by
		 * default and the bracket on the divider says how far it
		 * reaches; pointing at the panel and turning the wheel moves the
		 * panel alone, by one instruction at a time. Nothing has to
		 * guess what was meant.
		 */
		/* The panel's own rows, when the pointer is over them - the
		 * same rule the disassembler's wheel follows below. */
		/*
		 * The box scrolls; the table does not, because the table
		 * always fits - the panel is sized to hold it.
		 */
		if (g_evt_rows && evt_live(v) &&
		    g_my >= evt_box_top(v) &&
		    g_my < evt_box_top(v) + EVT_BOX_ROWS && g_mx > TREE_W) {
			int hi = evt_box_total(v) - EVT_BOX_ROWS;

			v->evt_scroll += down ? 1 : -1;
			if (v->evt_scroll > hi)
				v->evt_scroll = hi;
			if (v->evt_scroll < 0)
				v->evt_scroll = 0;
			return;
		}
		if (g_disasm_rows && g_my >= dis_top() && g_my <= hex_bot() &&
		    g_mx > TREE_W) {
			/* Four bytes: about one instruction, and the same step
			 * whichever way the wheel turns. */
			v->dis_bias += down ? 4 : -4;
			if (v->dis_bias < 0)
				v->dis_bias = 0;
			if (v->dis_bias > dis_max_bias(v))
				v->dis_bias = dis_max_bias(v);
			return;
		}
		if (g_mx <= TREE_W && g_my >= hex_top() &&
		    g_my <= hex_bot()) {
			/*
			 * THE WHEEL SCROLLS THE PANEL. IT DOES NOT SELECT.
			 *
			 * It used to step the selection - three objects per
			 * notch - so looking down a process with sixty mapped
			 * libraries meant opening and parsing every one of
			 * them on the way past, and whatever was being read in
			 * the hex pane was gone. A wheel is how you LOOK
			 * somewhere else; a click is how you go there. Every
			 * other panel in this tool already draws that line.
			 */
			int rows = hex_bot() - hex_top() + 1;
			uint32_t max = (rows > 0 &&
					v->n_node > (uint32_t)rows)
				       ? v->n_node - (uint32_t)rows : 0u;

			if (v->log && down && v->tree_top >= max) {
				goto_node(v, v->n_node);        /* slide the event window forward */
				return;
			}
			if (v->log && !down && v->tree_top == 0u) {
				goto_node(v, (uint32_t)-1);     /* ... and back */
				return;
			}
			if (down)
				v->tree_top = v->tree_top + 3u > max
					      ? max : v->tree_top + 3u;
			else
				v->tree_top = v->tree_top > 3u
					      ? v->tree_top - 3u : 0u;
		} else if (g_decl_rows && g_my > decl_top() &&
			   g_my < mark_row()) {
			/* The draft grows past its pane long before the object
			 * does, so the wheel over it moves it and not the hex
			 * behind it. The clamp is left to the next layout,
			 * which is the only place that knows how tall the
			 * panel ended up. */
			if (down)
				v->prow_off += 3u;
			else
				v->prow_off = v->prow_off > 3u
					      ? v->prow_off - 3u : 0u;
		} else {
			hex_step(v, down ? 3 : -3);
		}
}

/*
 * on_cursor_down - what handle() does about the cursor moving down.
 *
 * Lifted out of the router's switch whole, because a case body of eighty or a
 * hundred and sixty lines is a function that has not been given a name.
 */
static void on_cursor_down(struct view *v)
{
		if (v->menu_open) {
			menu_step(v, 1);
			return;
		}
		if (v->pane == 0 &&
			   (v->sel_node + 1 < v->n_node ||
			    (v->log && v->n_node))) {
			/*
			 * PAST THE LAST ROW IS A PAGE TURN, for a log.
			 *
			 * The guard here was "there is another row", which is
			 * the right answer for a file - its objects are all of
			 * them - and the wrong one for a log, whose rows are a
			 * window over millions. It made the keyboard stop at
			 * the bottom of the window while the wheel, which has
			 * no such guard, turned the page: two ways to move
			 * through the same list that disagreed about how long
			 * it was.
			 */
			goto_node(v, v->sel_node + 1u);
		} else if (v->pane == 1) {
			hex_step(v, 1);
		}
}

/*
 * on_cursor_up - what handle() does about the cursor moving up.
 *
 * Lifted out of the router's switch whole, because a case body of eighty or a
 * hundred and sixty lines is a function that has not been given a name.
 */
static void on_cursor_up(struct view *v)
{
		if (v->menu_open) {
			menu_step(v, -1);
			return;
		}
		if (v->pane == 0 && (v->sel_node || v->log)) {
			/* And back, the same way: at the top of a log's window
			 * there is a page before it. goto_node reads the
			 * wrapped -1 as that request. */
			goto_node(v, v->sel_node - 1u);
		} else if (v->pane == 1) {
			hex_step(v, -1);
		}
}



/* A refusal that must be visible whichever pane has the focus: the draft's own
 * channel (say_note) is drawn only while the draft panel is focused. */
static void say_act(struct view *v, const char *s)
{
	snprintf(v->act_msg, sizeof v->act_msg, "%s", s);
	v->act_ok = 0;
}

int handle(struct view *v, int k)
{
	int page = hex_last() - hex_top();

	if (k == 0x11)                  /* Ctrl+Q quits from anywhere, dialogs and menus included */
		return 0;

	/*
	 * Ctrl+C with a run of disassembly picked.
	 *
	 * First, because it is about a selection the reader can see, and every
	 * other owner of the keyboard below either has no selection or has its
	 * own copy already. The keyboard equivalent of the menu item, and the
	 * shortcut anybody tries first on highlighted text.
	 */
	/*
	 * F10 opens the menu bar, and closes it again.
	 *
	 * Before every mode below, because the bar is above them on screen and a
	 * reader reaching for the menu means the menu whatever else is up.
	 */
	{
		int r = handle_f10(v, k);

		if (r >= 0)
			return r;
	}
	{
		int r = handle_bar_key(v, k);

		if (r >= 0)
			return r;
	}
	/* The tag sources' page and pick list own the keyboard while up. */
	{
		int r = handle_syn_key(v, k);

		if (r >= 0)
			return r;
	}
	{
		int r = handle_copy_key(v, k);

		if (r >= 0)
			return r;
	}
	{
		int r = handle_enc_key(v, k);

		if (r >= 0)
			return r;
	}
	{
		int r = handle_symd_key(v, k);

		if (r >= 0)
			return r;
	}
	{
		int r = handle_prop_key(v, k);

		if (r >= 0)
			return r;
	}
	{
		int r = handle_chooser_key(v, k);

		if (r >= 0)
			return r;
	}
	if (page < 1)
		page = 1;

	/*
	 * EITHER HELP BOX, and the same keys.
	 *
	 * The wheel scrolls it, a click has to reach click() - which is the only
	 * code that knows where the Close button was drawn - and every other key
	 * is eaten so the page can be read to the end.
	 *
	 * Written as a guard on the block rather than as a case inside it,
	 * because "not handled here" cannot be spelled with a return in this
	 * function: 0 is what Ctrl+Q returns and it means QUIT.
	 */
	if (v->help_open &&
	    (k < K_CLICK || k == K_WHEEL_UP || k == K_WHEEL_DOWN)) {
		switch (k) {
		case 27:                /* Esc */
		case '\r':
		case '\n':
			v->help_open = 0;
			break;
		case K_UP:
		case K_WHEEL_UP:
			if (v->help_off > 0)
				v->help_off--;
			break;
		case K_DOWN:
		case K_WHEEL_DOWN:
			v->help_off++;   /* clamped where the box is measured */
			break;
		case K_PGUP:
			v->help_off -= 8;
			break;
		case K_PGDN:
			v->help_off += 8;
			break;
		case 0x03:              /* Ctrl+C */
			dlg_copy(v);
			break;
		default:
			break;
		}
		if (v->help_off < 0)
			v->help_off = 0;
		return 1;
	}

	switch (k) {
	/*
	 * The chords a text editor has taught everyone.
	 *
	 * Ctrl+Q leaves whatever is open; the bare q still closes a dialog and
	 * still quits when nothing is open, because it was the only way out
	 * before this and muscle memory is not worth breaking to make a point.
	 */
	case 0x11:                      /* Ctrl+Q */
		return 0;
	case 0x03: {                    /* Ctrl+C */
		/*
		 * COPY WHAT WAS PICKED IN THE EVENT PANEL.
		 *
		 * After choosing, not on the click that chose - a selection
		 * that copied itself the moment it was made would be replaced
		 * by the next thing the reader pointed at, which is the
		 * opposite of what a clipboard is for.
		 *
		 * Nothing picked means nothing happens. Falling through to
		 * some other copy would put bytes on the clipboard that the
		 * reader did not ask for and cannot see.
		 */
		char sel[512];
		size_t n = evt_sel_text(v, sel, sizeof sel);

		if (n) {
			copy_osc52(sel, n);
			copy_said(v, n);
			break;
		}
		/*
		 * AND OTHERWISE WHAT IS PICKED IN THE BYTES PANE.
		 *
		 * There was no other branch, so Ctrl+C over a selection did
		 * nothing at all and the only way to copy it was the right
		 * button. That was survivable while the pane was a hex dump -
		 * "copy these bytes" is a question with two answers, hex or
		 * ascii, and a menu is where a question with two answers
		 * belongs. It is not survivable now the pane can be TEXT:
		 * selecting a line of a script and pressing the chord every
		 * editor has is not a thing a reader will think to look in a
		 * menu for.
		 *
		 * The same call the menu item makes, so what the chord does and
		 * what the item does cannot disagree about what "the selection"
		 * is - but not through menu_run, whose first act is to ask
		 * whether the item is in the menu that is open. There is no
		 * menu open here.
		 */
		copy_selection(v, 0);
		break;
	}
	/*
	 * STEPPING THROUGH A DIRECTORY WITHOUT REACHING FOR THE MENU.
	 *
	 * Ctrl+] is the PREVIOUS file and Ctrl+\ the next one.
	 *
	 * That way round because of where the keys sit: on a US layout \ is to
	 * the right of ], so the rightward key steps forward. The pair reads as
	 * a direction on the keyboard rather than as a bracket that has to be
	 * remembered.
	 *
	 * Ctrl+[ WOULD HAVE BEEN THE OBVIOUS PARTNER AND CANNOT BE USED. A
	 * terminal sends Ctrl+[ as 0x1B, which is the Escape key, byte for
	 * byte - and 0x1B is also how every arrow, function key and mouse
	 * report begins. Binding it here would mean Escape opened a file:
	 * every closed dialog, every abandoned text field, every timed-out
	 * escape sequence. So the pair is the two keys next to it, which are
	 * distinct bytes (0x1C and 0x1D) and reach this loop unaltered because
	 * ISIG is off - see term_setup.
	 *
	 * Guarded by the same test the menu items use rather than a copy of it:
	 * they are one action asked for two ways, and an action that is
	 * available from the keyboard but greyed in the menu is a bug waiting
	 * to be reported.
	 */
	case 0x1d:                      /* Ctrl+] */
		if (bar_enabled(v, BI_PREV))
			open_step(v, -1);
		else
			say_act(v, "Finish or undo the draft first");
		break;
	case 0x1c:                      /* Ctrl+\ */
		if (bar_enabled(v, BI_NEXT))
			open_step(v, +1);
		else
			say_act(v, "Finish or undo the draft first");
		break;
	case 0x06:                      /* Ctrl+F */
		v->find_open = 1;
		v->edit = 500;
		v->ed.dr.warn[0] = 0;
		break;
	case 0x0e:                      /* Ctrl+N, the next hit */
		if (v->find[0])
			find_run(v, 0);
		break;
	case 0x0f:                      /* Ctrl+O */
		say_act(v, "No file picker - pass the file on the "
			   "command line");
		break;
	/*
	 * READ IT THE OTHER WAY - the same thing the context menu offers.
	 *
	 * Ctrl+Space because it is free, it is not a letter, and a terminal
	 * gives it to us unaltered. See K_CTRL_SPACE for why it took until now
	 * to be usable.
	 */
	case K_CTRL_SPACE:
		view_toggle_text(v);
		break;
	case '\r': case '\n':
		if (v->menu_open) {
			/* Nothing is lit until the reader lights it - see
			 * menu_open_at - and Enter on nothing does nothing. */
			if (v->menu_sel >= 0)
				menu_run(v, v->menu_sel);
			v->menu_open = 0;
			break;
		}
		break;
	/*
	 * TAB IS A CHARACTER TOO, and it went with the letters.
	 *
	 * It moved the focus between the three panes, from before a click did.
	 * A click does now - see the note in click() on the pane a press
	 * selects - so the keyboard-only route it was is a route nobody takes,
	 * and a viewer that swallows Tab cannot have a field in it that wants
	 * one. Shift+Tab goes with it: half a pair is worse than neither.
	 */
	case K_BACKTAB:
		break;
	case K_RESIZE:
		break;                  /* the loop redraws after every key */
	case K_CLICK:  click(v, 0); break;
	case K_RCLICK: click(v, 1); break;
case K_DRAG:
		on_drag(v);
		break;
case K_RELEASE:
		on_release(v);
		break;
	case 27:
		if (v->menu_open) {
			v->menu_open = 0;
			break;
		}
		v->sel_a = v->sel_b = KGENOME_BROKEN;
		dis_bias_to_sel(v);
		break;
	/*
	 * The wheel turns whatever the pointer is over.
	 *
	 * It used to always scroll the hex pane, which meant scrolling a tree
	 * that was under the cursor moved something else on the other side of
	 * the screen. A wheel that ignores where it is pointing is a wheel
	 * people stop using.
	 */
	case K_WHEEL_UP:
case K_WHEEL_DOWN:
		on_wheel(v, k);
		break;
	/*
	 * NO BARE LETTERS, and no bare space or tab.
	 *
	 * j k g G b m q, space and tab were all bound here - vi's keys plus a
	 * few - from before this had a mouse, a menu bar or a text pane. Every
	 * one of them is a character somebody may want to TYPE, and a viewer
	 * that acts on a letter is one you cannot put a text field in without
	 * first remembering which letters are safe. The arrows, the page keys,
	 * Home, End, Escape and the Ctrl chords cover all of it and none of
	 * them is a character.
	 */
	case K_DOWN:
		on_cursor_down(v);
		break;
	case K_UP:
		on_cursor_up(v);
		break;
	case K_PGDN: hex_step(v,  page); break;
	case K_PGUP: hex_step(v, -page); break;
	case K_HOME: v->rgn_at = 0; break;
	case K_END:
		/* The end means the same thing in both layouts and is found two
		 * different ways - hex_max counts rows of `per` bytes, which a
		 * line is not. Both answer in one step rather than walking. */
		v->rgn_at = text_pane(v) ? txt_home_end(v) : hex_max(v);
		break;
	/*
	 * SIDEWAYS, AND ONLY WHERE THERE IS A SIDEWAYS TO GO.
	 *
	 * A hex row is as wide as the pane by construction, so these keys have
	 * nothing to do there and have always done nothing. A line of source
	 * does not fit - a minified script is one line of two hundred thousand
	 * characters - so the text pane is the one thing here that can be
	 * scrolled across, and it takes the keys that were free.
	 */
	case K_LEFT:
		if (text_pane(v))
			txt_hscroll(v, -8);
		break;
	case K_RIGHT:
		if (text_pane(v))
			txt_hscroll(v, 8);
		break;
	default:
		break;
	}
	return 1;
}
