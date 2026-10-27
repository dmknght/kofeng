#define _GNU_SOURCE
#include "kv.h"

static int  hit_probe(const struct view *v, uint8_t want);
/*
 * click_bar_menu - a click while a bar menu is down.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
static int click_bar_menu(struct view *v)
{
	if (v->bar_open >= 0) {
		v->bar_open = -1;       /* a click anywhere else closes it */
		v->bar_sub = -1;
		return 1;
	}

	/*
	 * A CLICK INSIDE THE OPEN FIELD IS A CARET, NOT A CLICK AWAY.
	 *
	 * Ahead of everything that reads the panel, and ahead of `v->edit = 0`
	 * below, because that assignment is what made this impossible: the
	 * strings row already carried a branch for "the click landed in the box
	 * that is open", and it could never be true - edit had been cleared two
	 * screens earlier in the same function. So clicking the character you
	 * wanted to fix closed the box and jumped the pane to the bytes.
	 *
	 * Done here rather than per field so the answer is the same in all of
	 * them: the column under the pointer, plus however far the box is
	 * scrolled, is the character the caret goes to - and past the end of
	 * the text it goes to the end, which is where clicking the empty part
	 * of a box should put it.
	 */
	return 0;
}

/*
 * click_field - a click inside an open text field.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
static int click_field(struct view *v)
{
	if (v->edit && g_fld.room > 0 && !v->ch.open && !v->menu_open &&
	    g_my == g_fld.row && g_mx >= g_fld.col &&
	    g_mx < g_fld.col + g_fld.room) {
		uint32_t k = g_fld.off + (uint32_t)(g_mx - g_fld.col);

		v->caret = k > g_fld.len ? g_fld.len : k;
		/*
		 * AND THE PRESS IS THE ANCHOR OF A DRAG.
		 *
		 * An empty range, so a plain click still reads as "put the
		 * caret here" and selects nothing; the motion handler moves the
		 * far end while the button is down. This is what makes a box on
		 * this panel behave like the text box it looks like - part of a
		 * pattern can be dragged through and taken, rather than all of
		 * it or none.
		 */
		fsel_set(v, v->caret, v->caret);
		v->fld_drag = 1;
		/*
		 * And the field counts as already open.
		 *
		 * field_key puts the caret at the end whenever it sees a field
		 * it has not typed into yet - which is right when a box is
		 * opened by its button, and wrong here: the click has just said
		 * where the caret goes, and the next keystroke would move it
		 * back to the end before inserting anything.
		 */
		v->edit_prev = v->edit;
		return 1;
	}

	/*
	 * THE SYMBOLS DIALOG'S TEXT SELECTION starts here, before the box's own
	 * hit test.
	 *
	 * A press on a row of text is the start of a drag; the close button and
	 * the tabs are tested by the box afterwards, and they are not on a text
	 * row, so the two cannot both claim a click. A press anywhere else
	 * inside the box clears whatever was selected, which is what every
	 * other text selection does and what makes a stray click a way OUT of a
	 * selection rather than something that leaves it stuck on screen.
	 */
	return 0;
}

/*
 * click_menu - a click on the hex pane's context menu.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
int click_menu(struct view *v)
{
	if (v->menu_open) {
		int k = g_my - v->menu_row;

		/* Anywhere off the menu dismisses it. A menu that only closes
		 * on the right key is a menu people leave open. */
		if (g_mx >= v->menu_col && g_mx < v->menu_col + MENU_W &&
		    k >= 0 && k < menu_rows(v)) {
			int a = menu_at_row(v, k);

			if (a >= 0 && menu_enabled(v, a))
				menu_run(v, a);
		}
		v->menu_open = 0;
		return 1;
	}
	/*
	 * The scrollbars and the divider come AFTER the overlays.
	 *
	 * They are painted underneath, so they have to be tested underneath: a
	 * chooser item that happened to land on the divider row sent the click
	 * to the divider and started a resize instead of choosing anything.
	 * Anything drawn on top of the panes must have first refusal on a
	 * click, which is the same order they are drawn in.
	 */
	return 0;
}

/*
 * click_scrollbar - a click on a scrollbar.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
static int click_scrollbar(struct view *v)
{
	{
		int which = bar_under(v);

		if (which) {
			/*
			 * On the thumb, take hold of it where it is; on the
			 * track, jump.
			 *
			 * A bar that recentres under the pointer every time it
			 * is touched cannot be dragged - the first press throws
			 * the view somewhere else and the drag continues from
			 * there, which is what "sometimes lands in the wrong
			 * place" is. One row of track is many bytes of a large
			 * object, so the jump will never be exact; taking hold
			 * of the thumb is how a fine adjustment is made.
			 */
			int top, bot, t0, t1 = 0;
			uint64_t total = 0, shown = 0, off = 0;

			if (which == 1) {
				uint64_t per = (uint64_t)(v->per > 0 ? v->per
								    : 16);
				top = hex_top(); bot = hex_last();
				total = v->rgn_len; off = v->rgn_at;
				shown = (uint64_t)(bot - top + 1) * per;
			} else if (which == 2) {
				top = hex_top(); bot = hex_bot();
				total = v->n_node; off = v->tree_top;
				shown = (uint64_t)(bot - top + 1);
			} else if (which == 4) {
				/*
				 * The disassembly panel's track is what the
				 * panel can reach: the hex pane's range when it
				 * follows the hex, and the PINNED RUN when it
				 * does not. Reading dis_hex_shown either way
				 * made the thumb of a pinned panel describe a
				 * window it does not have.
				 */
				top = dis_top(); bot = hex_bot();
				total = v->dis_len != KGENOME_BROKEN
					? v->dis_len : dis_hex_shown(v);
				off = (uint64_t)v->dis_bias;
				shown = dis_span_of(v);
			} else {
				top = decl_top() + 1;
				bot = decl_top() + g_decl_rows - 2;
				total = v->n_prow; off = v->prow_off;
				shown = (uint64_t)(g_decl_rows - 2);
			}
			t0 = kv_bar_thumb(top, bot, off, total, shown, &t1);
			v->bar_drag = which;
			if (t0 < 0 || g_my < top + t0 || g_my >= top + t0 + t1)
				bar_to(v, which);
			return 1;
		}
	}

	/* Pressing the divider starts a resize; the drag handler does the rest.
	 * Tested before anything else claims the row, and only when there is a
	 * panel to resize. */
	/*
	 * A press on a panel ROW starts a line selection.
	 *
	 * The terminal's own selection is not available here - the viewer holds
	 * the mouse, which is what lets it do everything else - so copying a few
	 * instructions out has to be something the panel does itself.
	 */
	return 0;
}

/*
 * click_disasm - a click in the disassembly pane.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
static int click_disasm(struct view *v, int rclick)
{
	if (g_disasm_rows && g_my >= dis_top() && g_my <= hex_bot() &&
	    g_mx > TREE_W) {
		int idx = g_my - dis_top();

		/*
		 * The panel's own menu, which is a SHORT one.
		 *
		 * ctx 4 rather than 1|4: everything the hex pane offers is not
		 * wanted here. "View disassembly" would open what is already
		 * open; copying the ASCII of an instruction is not a thing
		 * anybody does. What is left is copying the text, copying the
		 * bytes behind it, declaring those bytes, and searching - which
		 * are the four questions the selection can answer.
		 */
		if (rclick) {
			/*
			 * The one-row fallback is for a panel with NOTHING
			 * picked - not for one showing a range picked in the
			 * hex pane. It used to fire on that too: the right
			 * click replaced the reader's range with the single row
			 * under the pointer, so the menu that opened offered to
			 * copy one line of what they had selected, and the rest
			 * of the highlight went out as the menu came up.
			 */
			idx = dis_real_row(v, idx);
			if (!v->dis_have && !dis_hex_sel(v) &&
			    idx >= 0 && idx < v->dis_lines) {
				int ln = (int)strlen(v->dis_line[idx]);

				v->dis_a_at = v->dis_b_at = v->dis_line_at[idx];
				v->dis_ac = 0;
				v->dis_bc = ln > 0 ? ln - 1 : 0;
				v->dis_have = 1;
				dis_sync_bytes(v);
			}
			v->menu_ctx = 4;
			v->menu_off = v->sel_a != KGENOME_BROKEN
				      ? view_map(v, v->sel_a, 0) : 0;
			menu_open_at(v, g_my, g_mx);
			return 1;
		}

		/*
		 * Only where there is text.
		 *
		 * A press past the end of a line used to pick the whole line,
		 * so clicking the empty half of the panel lit a row for no
		 * reason anybody could see. The panel is text, and text is
		 * selected where it is.
		 */
		idx = dis_real_row(v, idx);
		if (idx >= 0 && idx < v->dis_lines &&
		    g_mx >= TREE_W + 3 &&
		    g_mx < TREE_W + 3 + (int)strlen(v->dis_line[idx])) {
			int c = g_mx - (TREE_W + 3);

			v->dis_a_at = v->dis_b_at = v->dis_line_at[idx];
			v->dis_ac = v->dis_bc = c;
			v->dis_have = 1;
			v->dis_dragging = 1;
			v->act_msg[0] = 0;
			dis_sync_bytes(v);
		} else {
			/* Somewhere with nothing on it: the selection goes,
			 * rather than being left lit behind the click. */
			v->dis_have = 0;
			v->dis_dragging = 0;
		}
		return 1;
	}

	/*
	 * The disassembly panel's heading: a close button and a mode switch.
	 *
	 * Before the hex hit test, because the heading sits inside the hex
	 * column and a click there is about the panel rather than about a byte.
	 */
	return 0;
}

/* Forget last frame's rectangles. Called where the frame starts drawing. */
void hit_reset(struct view *v)
{
	v->n_hit = 0;
}

/*
 * The general form: a rectangle and which buttons it answers.
 *
 * `x1` and `y1` are inclusive, as every other hit test in this file is.
 * Anything scrolled or clipped out registers nothing - it is drawn by nobody,
 * so the same predicate that guards the paint guards the call.
 */
void hit_zone(struct view *v, int y0, int x0, int y1, int x1,
		     uint8_t btn, void (*fn)(struct view *, uint32_t),
		     uint32_t arg)
{
	struct hit *h;

	if (v->n_hit >= HIT_MAX || x1 < x0 || y1 < y0 || y0 < 0)
		return;
	h = &v->hit[v->n_hit++];
	h->y0 = (int16_t)y0;
	h->y1 = (int16_t)y1;
	h->x0 = (int16_t)x0;
	h->x1 = (int16_t)x1;
	h->btn = btn;
	h->fn = fn;
	h->arg = arg;
}

/* One row, left button - what almost every control is. */
void hit_add(struct view *v, int y, int x0, int x1,
		    void (*fn)(struct view *, uint32_t), uint32_t arg)
{
	hit_zone(v, y, x0, y, x1, HIT_L, fn, arg);
}

/* Which rectangle is under the pointer for this gesture, or none. */
static const struct hit *hit_at(const struct view *v, uint8_t want)
{
	uint32_t i = v->n_hit;

	/*
	 * Backwards, so the LAST rectangle registered at a position wins - the
	 * one painted over the others, which is the one the reader can see. It
	 * is also why a pane may declare itself whole and a control inside it
	 * still answer: the control is drawn later.
	 */
	while (i--) {
		const struct hit *h = &v->hit[i];

		if ((h->btn & want) && g_my >= h->y0 && g_my <= h->y1 &&
		    g_mx >= h->x0 && g_mx <= h->x1)
			return h;
	}
	return NULL;
}

/*
 * Run whatever is there, if anything.
 *
 * A rectangle registered with NO callback is a DECLARATION and not an action:
 * it says the button means something here and leaves the handling to the chain
 * below. hit_probe counts it, this does not run it, and the click carries on.
 */
int hit_run(struct view *v, uint8_t want)
{
	const struct hit *h = hit_at(v, want);

	if (!h || !h->fn)
		return 0;
	h->fn(v, h->arg);
	return 1;
}

/* Ask without running: the right-button gate needs to know whether the press
 * means anything here before the chain below it starts changing state. */
static int hit_probe(const struct view *v, uint8_t want)
{
	return hit_at(v, want) != NULL;
}

/*
 * The rest of the draft panel's rows, as callbacks written beside nothing at
 * all - they are reached only through the spans the draw registers, so the
 * question "which row is this" is never asked twice. What used to sit here was
 * a 390-line walk that re-counted the rows in the drawing's order; the count
 * and the drawing were two readings of one row order, and a row added to one
 * and not the other made every click below it land one row out.
 */

/* A row that is a heading: it belongs to the panel, and it does nothing. */
void hit_row_none(struct view *v, uint32_t arg)
{
	(void)v;
	(void)arg;
}

/* [+ Condition] under the Conditions bar - a new top-level one. */
void hit_row_addcond(struct view *v, uint32_t arg)
{
	(void)arg;
	if (grp_tab_count(&v->ed, v->ed.dr.tab) && g_mx >= v->a_c0 &&
	    g_mx <= v->a_c1)
		cnd_add(&v->ed);
}

/*
 * One row of a condition's block. `g` is the row's place in the drawn
 * sequence, which is what says which of the two shapes it is; cseq_idx turns
 * that into the condition it is about.
 */
void hit_row_cond(struct view *v, uint32_t g)
{
	uint32_t ci;

	if (g >= v->n_cseq)
		return;
	ci = v->cseq_idx[g];
	v->ed.dr.cur_cnd = ci;

	if (v->cseq_kind[g] == CS_MATCH) {
		/* The block's first row, so it carries the block's remove
		 * button - see the drawing. */
		if (g_mx >= g_cols - 4) {
			cnd_remove(&v->ed, ci);
			return;
		}
		if (v->cnd_mt[ci][0] > 0 && g_mx >= v->cnd_mt[ci][0] &&
		    g_mx <= v->cnd_mt[ci][1])
			ch_open(v, CH_CMATCH, ci, g_my, g_mx);
		else if (v->cnd_op[ci][0] > 0 && g_mx >= v->cnd_op[ci][0] &&
			 g_mx <= v->cnd_op[ci][1])
			cnd_set_op(&v->ed, ci, !v->ed.dr.cnd[ci].op);
		/* A typed expression is a FIELD, not a list of ids - so it
		 * takes the caret rather than having one of its characters
		 * removed. */
		else if (v->cnd_ex[ci][0] > 0 && g_mx >= v->cnd_ex[ci][0] &&
			 g_mx <= v->cnd_ex[ci][1])
			v->edit = 103 + (int)ci;
		else
			cnd_id_click(v, ci);
		return;
	}

	/* CS_COND: the tag row. */
	if (v->cnd_tg[ci][0] > 0 && g_mx >= v->cnd_tg[ci][0] &&
	    g_mx <= v->cnd_tg[ci][1])
		syn_pick_tag(v, PK_TAG_COND, ci);
}

/*
 * click_marker_line - a click on the marker line.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
/* Defined below; the properties modal hands the mouse to the selection layer
 * rather than swallowing it - see the K_DRAG case there. */

static int click_marker_line(struct view *v, struct object *ob)
{
	if (g_my == mark_row()) {
		/* The status line is a readout, not a control. */
		(void)v; (void)ob;
		return 1;
	}
	return 0;
}

/*
 * click_hex - a click on a byte of the hex pane.
 *
 * Lifted out of click() whole. It answers 1 when it has dealt with the
 * click and 0 to let the chain carry on, which is exactly what the `return`
 * and the fall-through meant where this used to sit.
 */
static int click_hex(struct view *v, int rclick)
{
	if (g_my >= hex_top() && g_my <= hex_last() && g_mx > TREE_W) {
		uint64_t at;

		v->pane = 1;
		if (rclick) {
			int per = v->per > 0 ? v->per : 16;
			int base = TREE_W + 3;
			uint64_t row0 = v->rgn_at +
					(uint64_t)(g_my - hex_top()) *
					(uint64_t)per;

			/* The offset column is its own thing to right-click on:
			 * it names a place, and the bytes name contents. */
			v->menu_ctx = (g_mx >= base && g_mx < base + 8) ? 2 : 1;
			v->menu_off = row0 < v->rgn_len
				      ? view_map(v, row0, 0) : 0;
			menu_open_at(v, g_my, g_mx);
			return 1;
		}
		if (byte_under(v, g_my, g_mx, &at)) {
			v->find_i = v->find_n = 0;
			/*
			 * A second click on the byte just clicked, soon after,
			 * is a double click. Timed rather than counted because
			 * a terminal reports two presses and nothing else - it
			 * has no notion of a double click to pass on.
			 */
			uint64_t now = now_ms();
			int again = at == v->last_click &&
				    now - v->last_click_ms < 400u;

			v->last_click = at;
			v->last_click_ms = now;
			/*
			 * SHIFT (OR CTRL) EXTENDS, the way it does in a text
			 * editor: the anchor stays and the far end comes to the
			 * click.
			 *
			 * A base64 payload is a hundred bytes and more, and
			 * dragging over one that runs off the bottom of the
			 * pane means dragging into the edge and waiting for it
			 * to scroll. Click the start, wheel down, shift-click
			 * the end.
			 *
			 * CTRL AS WELL AS SHIFT, and that is not a convenience.
			 * Measured here: xterm and VTE take Shift as "bypass
			 * mouse reporting and do the terminal's OWN selection",
			 * so on those the shift-click never arrives - the
			 * terminal highlights the text itself instead. Ctrl is
			 * not claimed that way and does arrive, so it is the
			 * binding that works; shift stays accepted because a
			 * reader whose terminal passes it should not have to
			 * learn that this one program wants something else.

			 *
			 * Only when there IS an anchor: a modified click on a
			 * pane with no selection is an ordinary click, not an
			 * extension from nowhere.
			 */
			if ((g_mod_shift || g_mod_ctrl) &&
			    v->sel_a != KGENOME_BROKEN)
				v->sel_b = at;
			else
				v->sel_a = v->sel_b = at;
			v->sel_from_dis = 0;    /* the hex pane owns it now */
			v->dis_have = 0;        /* a stale panel-text selection must not win Ctrl+C */
			v->dis_dragging = 0;
			dis_bias_to_sel(v);
			v->dragging = 1;
			/*
			 * A deliberate act outranks a stale confirmation.
			 *
			 * The status line's action slot ages out on its own, but
			 * four seconds is still four seconds during which a
			 * reader who has just dragged out a run sees what
			 * happened before it instead of the run they selected.
			 * Selecting bytes is a request for the readout; making
			 * it clears whatever was being announced.
			 */
			v->act_msg[0] = 0;
			v->dragged = 0;
			if (again) {
				select_run(v);
				v->dragging = 0;
				v->dragged = 1;
			}
		} else {
			/*
			 * Inside the pane but on nothing - past the ASCII
			 * column, or the gap between the two halves. The
			 * selection goes, for the reason the disassembly
			 * panel's does: bytes left lit behind a click that
			 * chose nothing are bytes the reader has to remember
			 * they did not choose.
			 */
			v->sel_a = v->sel_b = KGENOME_BROKEN;
			v->dragging = 0;
			v->dragged = 0;
			dis_bias_to_sel(v);
		}
		return 1;
	}
	return 0;
}


/*
 * The help box takes the click; one of the steps click() walks, in the order it asks.
 * 1 when the press was handled.
 */
static int click_help(struct view *v)
{
	/*
	 * The help box takes the click, the bar takes the row it owns and
	 * whatever is under an open menu. Both before the panes, for the same
	 * reason the chooser is: what is drawn on top is asked first.
	 *
	 * EITHER HELP BOX CLOSES ON ITS BUTTON AND NOWHERE ELSE. Both scroll,
	 * and a page that vanishes on the click that starts a drag cannot be
	 * read to the end.
	 */
	if (v->help_open) {
		int r, c;

		if (v->help_btn_y >= 0 && g_my == v->help_btn_y &&
		    g_mx >= v->help_btn_x0 && g_mx <= v->help_btn_x1) {
			v->help_open = 0;
			return 1;
		}
		/* Anything else in the box is a SELECTION, through the same
		 * layer the properties page and the symbol table use - these
		 * pages record their rows for exactly this. */
		if (dlg_at(v, g_my, g_mx, &r, &c)) {
			/* The character pressed, not the word around it - see
			 * the note in on_release. */
			v->dlg_ar = v->dlg_br = r;
			v->dlg_ac = v->dlg_bc = c;
			v->dlg_have = 1;
			v->dlg_drag = 1;
			return 1;
		}
		v->dlg_have = 0;
		v->dlg_drag = 0;
		return 1;
	}
	return 0;
}

/*
 * An item of the open menu was pressed. 1 when it was.
 */
static int click_bar_item(struct view *v)
{
	if (v->bar_open >= 0) {
		int i = bar_item_at(v, g_my, g_mx);

		if (i >= 0) {
			bar_run(v, i);
			return 1;
		}
	}
	return 0;
}

/*
 * A press on the menu bar row opens the menu under it. 1 when the press was on that row.
 */
static int click_bar_title(struct view *v)
{
	if (g_my == 1) {
		int m;

		v->bar_open = -1;
		for (m = 0; m < BM_COUNT; m++) {
			int c0 = bar_col(m);

			if (g_mx >= c0 &&
			    g_mx < c0 + (int)strlen(bar_name[m]) + 2) {
				v->bar_open = m;
				v->bar_sel = -1;
				v->bar_sub = -1;
				break;
			}
		}
		return 1;
	}
	return 0;
}

/*
 * A double or triple click on the dashboard, from the geometry the tables returned and the text they recorded - not from
 * what is drawn, so a cell scrolled partly out of view is taken whole. 2 = the cell under the point, 3 = the whole line
 * (a table row's cells as the copy takes them; any other line as it reads). The visible part is what is lit; the copy
 * takes the full text (dlg_select_full). 1 when a selection was made.
 */
static int click_pick(struct view *v, int rw, int r, int c, int n)
{
	uint32_t slot, row;
	int k, kind = n >= 2 ? prop_cell_at(v, g_my, g_mx, &slot, &row, &k) : 0;
	char line[PROP_W];

	if (n == 2 && kind == 2 && k >= 0) {
		const struct kv_tab_geo *g = &v->prop_tab[slot].geo;
		const char *t = prop_cell_text(v, slot, row, k);

		if (!t || g->cw[k] <= 0)
			return 0;
		dlg_select_full(v, r, g->cx[k], g->cx[k] + g->cw[k] - 1, t, strlen(t));
		return 1;
	}
	if (n == 3) {
		int last = (int)v->dlg_cols[rw] - 1;

		if (kind == 2) {
			size_t l = prop_row_text(v, slot, row, line, sizeof line);

			dlg_select_full(v, r, 0, last < 0 ? 0 : last, line, l);
		} else {
			dlg_select_full(v, r, 0, last < 0 ? 0 : last, NULL, 0);
		}
		return 1;
	}
	(void)c;
	return 0;
}

/*
 * A press inside the symbol table or the properties page: a text selection, the
 * Copy-path button, or a double click on a cell. 1 when the press was handled; 0
 * when the page is not modal and the press goes on to the panes.
 */
static int click_dialog_text(struct view *v)
{
	/*
	 * A DIALOG'S TEXT SELECTION, whichever dialog is up.
	 *
	 * The properties page had its own copy of this - an anchor, a row, two
	 * columns and a dragging flag on the view - answering the same question
	 * the symbol table already asked this layer. One recording, one
	 * selection, one Ctrl+C.
	 */
	if (v->prop_open) {
		int r, c;

		if (dlg_at(v, g_my, g_mx, &r, &c)) {
			/*
			 * THE BUTTON BEFORE THE SELECTION.
			 *
			 * Nothing read prop_cp_row after the dashboard moved
			 * onto the page renderer, so pressing this did what a
			 * press on any other row does - started a text
			 * selection - and the button looked dead. It is
			 * recognised here by the label it drew, which needs no
			 * agreement about row numbering between the two paths.
			 */
			/*
			 * ON THE RECORDED ROW, WHICH IS NOT `r`.
			 *
			 * `r` is a line of the PAGE - dlg_at answers in
			 * content space so a selection survives a scroll - and
			 * this page has more lines than the recording has
			 * rows. Indexing dlg_line with it read past the end of
			 * the array on any page scrolled far enough, and found
			 * the label on the wrong row before that.
			 */
			int rw = g_my - v->dlg_y0;
			const char *cp = (rw >= 0 && rw < v->dlg_rows)
				? strstr(v->dlg_line[rw], PROP_CP_LABEL) : 0;

			if (cp && v->path && v->path[0]) {
				int x0 = dlg_col_of_byte(v, rw,
					(uint32_t)(cp - v->dlg_line[rw]));

				if (c >= x0 && c < x0 +
				    (int)(sizeof PROP_CP_LABEL - 1)) {
					size_t n = strlen(v->path);

					copy_osc52(v->path, n);
					copy_said(v, n);
					return 1;
				}
			}

			/*
			 * ANCHORED ON THE CHARACTER PRESSED, not on the word
			 * around it.
			 *
			 * This used to expand to the whole word here, so every
			 * press picked a column's value and a drag then
			 * extended from a boundary the reader had not chosen.
			 * Selecting two columns of one row, or part of one
			 * value, was not expressible.
			 *
			 * A plain CLICK leaves one character lit, which is a
			 * caret: it says where a drag would start. A DOUBLE
			 * click takes the whole cell, which is the gesture a
			 * table of values actually wants.
			 */
			/* Shift (or ctrl) extends from where the selection
			 * already starts - the same gesture as in the hex
			 * pane, including why ctrl is accepted too. */
			if ((g_mod_shift || g_mod_ctrl) && v->dlg_have) {
				v->dlg_br = r;
				v->dlg_bc = c;
				v->dlg_drag = 1;
				return 1;
			}
			/* Presses in a row on one place: the second takes the whole cell, the third the whole line. */
			if (click_pick(v, rw, r, c, dlg_click_count(v, r, c)))
				return 1;
			v->dlg_ar = v->dlg_br = r;
			v->dlg_ac = v->dlg_bc = c;
			v->dlg_have = 1;
			v->dlg_drag = 1;
			return 1;
		}
		v->dlg_have = 0;
		v->dlg_drag = 0;
		if (v->prop_open)
			return 1;         /* a modal page: nothing under it takes the click */
	}
	return 0;
}

/*
 * The framed dialogs: moving one, then pressing inside the one that is open. 1 when handled.
 */
static int click_boxes(struct view *v, int rclick)
{
	/*
	 * MOVING THE BOX IS ASKED ABOUT FIRST, because the title row carries no
	 * other control and a box being dragged must not also be acting on the
	 * press that is dragging it.
	 */
	if ((v->enc_open && dframe_grab(v, &g_enc_f)) ||
	    (v->goto_open && dframe_grab(v, &g_goto_f)) ||
	    (v->find_open && dframe_grab(v, &g_find_f)))
		return 1;
	if (v->enc_open && enc_click(v, rclick))
		return 1;
	if (v->goto_open && goto_click(v))
		return 1;
	if (v->find_open && find_click(v))
		return 1;
	return 0;
}

/*
 * Any click leaves whatever was being typed; a pattern is committed first.
 */
static void click_leave_edit(struct view *v)
{
	/*
	 * A STRING EDIT IS COMMITTED BEFORE THE FOCUS GOES, not dropped.
	 *
	 * Every other field types straight into the thing it edits, so leaving
	 * it keeps what was typed. A pattern does not: it is typed into a
	 * scratch buffer and parsed back into the declaration when the field
	 * closes, and closing only ever happened on the keyboard path. So
	 * clicking away after editing a pattern threw the edit away without a
	 * word - the row still showed the old bytes, which reads as the edit
	 * having been saved until it is opened again and is not there.
	 */
	if (v->edit >= ED_STR && v->edit < ED_STR + MAX_DECL) {
		uint32_t si = (uint32_t)(v->edit - ED_STR);

		v->edit = 0;
		decl_edit_commit(&v->ed, si);
	}

	/* Any click leaves whatever was being typed. The header branch below
	 * puts the focus back if the click landed on a field, so this is the
	 * whole of "click away to stop editing". */
	v->edit = 0;
}

/*
 * A press while a pick-list is open: a row, the parent list, or away. 1 when handled.
 */
static int click_chooser(struct view *v)
{
	if (v->ch.open) {
		/* The row under the pointer is counted from the first one
		 * DRAWN, which is not item zero once the list scrolls. */
		int k = g_my - v->ch.row + v->ch.off;

		if (g_mx >= v->ch.col && g_mx < v->ch.col + v->ch.w &&
		    g_my >= v->ch.row && k >= 0 && k < v->ch.n &&
		    k < v->ch.off + ch_vis(&v->ch)) {
			/* On the rule between two halves: inside the list, so
			 * it is not a dismiss, and not a row, so it is not a
			 * pick either. */
			if (v->ch.sep[k])
				return 1;
			v->ch.sel = k;
			ch_take(v);
			return 1;
		}
		/*
		 * A CLICK ON THE PARENT MENU MOVES TO THAT ROW, it does not
		 * dismiss everything.
		 *
		 * Only the front chooser was tested, so with a submenu open a
		 * click on another row of the list that opened it fell through
		 * to "outside the menu" and closed both. Picking Document and
		 * then Executable made the whole thing vanish rather than
		 * showing the other list, which reads as a menu that cannot be
		 * changed your mind about.
		 *
		 * Re-running the parent row is what reopens the child, so the
		 * switch costs no new code path - it is the same call the first
		 * pick made.
		 */
		if (v->ch_up.open) {
			int ku = g_my - v->ch_up.row + v->ch_up.off;

			if (g_mx >= v->ch_up.col &&
			    g_mx < v->ch_up.col + v->ch_up.w &&
			    g_my >= v->ch_up.row &&
			    ku >= 0 && ku < v->ch_up.n &&
			    ku < v->ch_up.off + ch_vis(&v->ch_up)) {
				struct chooser up = v->ch_up;

				up.sel = ku;
				v->ch = up;             /* it is the front one */
				v->ch_up.open = 0;
				ch_take(v);
				return 1;
			}
		}
		v->ch.open = 0;
		v->ch_up.open = 0;
		return 1;
	}
	return 0;
}

/*
 * A press in the event panel: its text box or a field row. 1 when handled.
 */
static int click_evt_panel(struct view *v, int rclick)
{
	/*
	 * A ROW OF THE EVENT PANEL, which picks the field AND takes the hex
	 * pane to it.
	 *
	 * Scrolling as well as lighting, because the panel is at most half the
	 * column and a record is 512 bytes: the field a reader picks is more
	 * often off the top of the dump than on it, and a highlight nobody can
	 * see is the same as no highlight. Picking a row is asking "where is
	 * this", so the answer is to go there.
	 */
	/*
	 * THE VALUE COLUMN IS TEXT, and a press in it starts a selection
	 * rather than moving the dump.
	 *
	 * Two columns, two gestures. The name says which bytes, so pressing it
	 * lights them and goes there. The value is the thing itself - a path, a
	 * command line, a script somebody submitted - and what a reader does
	 * with text is pick a piece of it out. Making the whole row mean "jump"
	 * left no way to do that at all, on the one field where it matters
	 * most.
	 *
	 * Nothing is copied here. Copying on click is how a selection gets
	 * overwritten by the next thing the reader points at; Ctrl+C after
	 * choosing is the contract every other text does.
	 */
	/*
	 * THE BOX IS TEXT, and a press in it starts a selection. The TABLE is a
	 * list of fields, and a press in it picks one and takes the dump to its
	 * bytes.
	 *
	 * Two zones, two gestures, and neither is a guess about what a click
	 * meant: they are different parts of the panel and they look different.
	 *
	 * Nothing is copied here. Copying on click is how a selection gets
	 * overwritten by the next thing the reader points at; Ctrl+C after
	 * choosing is the contract every other text has.
	 */
	/*
	 * A RIGHT-CLICK IN THE BOX OPENS ITS OWN MENU.
	 *
	 * Before the left-click branch, because that one returns for every
	 * press inside the box and would swallow this. The selection is left
	 * alone: right-clicking to copy what you just selected is the gesture,
	 * and moving the selection first would copy the wrong thing.
	 */
	if (evt_live(v) && rclick && evt_text_at(v, g_my, g_mx, NULL)) {
		v->menu_ctx = 8;
		menu_open_at(v, g_my, g_mx);
		return 1;
	}
	if (evt_live(v) && !rclick) {
		int c = 0, r;

		if (evt_text_at(v, g_my, g_mx, &c)) {
			v->evt_txt_a = v->evt_txt_b = c;
			v->evt_txt_drag = 1;
			evt_reveal_char(v, c);
			evt_sync_hex(v, 0);
			return 1;
		}
		r = evt_meta_at(v, g_my, g_mx);
		if (r >= 0) {
			uint16_t fo = 0, fl = 0;

			/* A press on a field clears the text pick: the two
			 * zones are one panel, and a highlight left behind in
			 * text the reader has moved away from reads as still
			 * selected. */
			v->evt_txt_a = v->evt_txt_b = 0;
			if (r == v->evt_sel) {
				v->evt_sel = -1;
				return 1;
			}
			v->evt_sel = r;
			if (kof_evt_field_extent(&v->evt, (unsigned)r, &fo,
						 &fl) && fl) {
				uint64_t per = (uint64_t)(v->per > 0 ? v->per
								    : 16);
				uint64_t hrow = (uint64_t)fo / per;

				v->rgn_at = hrow > JUMP_LEAD
					? (hrow - JUMP_LEAD) * per : 0;
				if (v->rgn_at > hex_max(v))
					v->rgn_at = hex_max(v);
			}
			return 1;
		}
	}
	return 0;
}

/*
 * A press on the heading of the event or disassembly panel: close, or the mode. 1 when handled.
 */
static int click_pane_heads(struct view *v)
{
	if (g_evt_rows && g_my == evt_top() - 1 && g_mx > TREE_W) {
		if (g_mx >= g_cols - 3) {
			v->evt_open = 0;
			g_evt_rows = 0;
		}
		return 1;
	}
	if (g_disasm_rows && g_my == dis_top() - 1 && g_mx > TREE_W) {
		if (g_mx >= g_cols - 3) {
			v->dis_open = 0;
			g_disasm_rows = 0;
			v->dis_have = 0;
			return 1;
		}
		/* The mode, where it is written. Anywhere else on the heading
		 * does nothing, so a stray click on a rule is not a state
		 * change nobody asked for. */
		if (g_mx >= TREE_W + 5 && g_mx <= TREE_W + 24) {
			v->dis_bits = v->dis_bits == 64 ? 32 : 64;
			dis_drop_analysis(v);   /* it was made reading the other width */
			return 1;
		}
		return 1;
	}
	return 0;
}

/*
 * The draft panel: the sizing row, then its own area down to the marker line. 1 when handled.
 */
static int click_draft_area(struct view *v, int rclick)
{
	if (g_decl_rows && g_my == hex_bot() + 1) {
		v->sizing = 1;
		return 1;
	}

	if (g_decl_rows && g_my >= decl_top() && g_my < mark_row())
		v->pane = 3;
	/*
	 * THE PANEL SWALLOWS ITS OWN AREA.
	 *
	 * Every row FROM the heading down to the marker line belongs to the
	 * draft, whether or not a control is drawn on it, so a click that
	 * found nothing registered stops here rather than falling through to
	 * the hex pane underneath - which is what the unconditional `return 1`
	 * at the foot of the walk this replaced did.
	 *
	 * The heading is inside this test rather than answered before it: it
	 * had its own routine reading a chain of column pairs, one of which
	 * belonged to another row, and the type box opened the options list
	 * because of it. Every row of the panel is now read the one way.
	 */
	if (g_decl_rows && g_my >= decl_top() && g_my < mark_row()) {
		hit_run(v, rclick ? (uint8_t)HIT_R : (uint8_t)HIT_L);
		return 1;
	}
	return 0;
}

/*
 * The tree and the hex pane: the press moves the cursor in the pane it landed on.
 */
static void click_panes(struct view *v)
{
	if (g_my >= hex_top() && g_my <= hex_bot()) {
		if (g_mx <= TREE_W) {
			uint32_t k = v->tree_top + (uint32_t)(g_my - hex_top());

			v->pane = 0;
			goto_node(v, k);
		} else {
			v->pane = 1;
		}
	}
}

void click(struct view *v, int rclick)
{
	struct object *ob = cur_obj(v);

	/*
	 * The right button is the hex pane's alone.
	 *
	 * Everywhere else it used to do whatever the left button does, which is
	 * a mouse with one button pretending to have two: right-clicking a tree
	 * row moved the cursor, right-clicking "hit" opened the dialog. A
	 * button that duplicates another teaches nothing and surprises whoever
	 * expected a menu.
	 */
	/*
	 * ASKED OF THE FRAME, NOT OF A LIST KEPT HERE.
	 *
	 * This was four rectangles written out in this condition, and every
	 * pane that grew a context menu had to be added to them. Twice it was
	 * not: the event panel's text box and the string decoder's plaintext
	 * window both opened a menu, ran the item, and did nothing - because
	 * the press was refused here, three screens above anything that could
	 * have told the reader so, and the rectangle that would have allowed it
	 * lived in a different function from the code that drew the box.
	 *
	 * Now a pane declares its own right-button rectangle where it paints
	 * it - see hit_zone in redraw - so the two cannot disagree, and a pane
	 * that forgets is broken only in itself.
	 *
	 * menu_open stays here: it is not a property of any
	 * pane but of what is on top of all of them.
	 */
	if (rclick && (v->menu_open || !hit_probe(v, HIT_R)))
		return;

	if (click_help(v))
		return;
	if (click_bar_item(v))
		return;
	if (click_bar_title(v))
		return;
	if (click_bar_menu(v))
		return;
	if (click_field(v))
		return;
	if (fam_click(v, rclick))
		return;
	if (syn_modal(v) && syn_click(v))
		return;
	if (click_dialog_text(v))
		return;
	if (click_boxes(v, rclick))
		return;

	click_leave_edit(v);

	if (click_chooser(v))
		return;
	if (click_menu(v))
		return;
	if (click_scrollbar(v))
		return;
	if (click_disasm(v, rclick))
		return;
	if (click_evt_panel(v, rclick))
		return;
	if (click_pane_heads(v))
		return;

	if (click_draft_area(v, rclick))
		return;
	if (click_marker_line(v, ob))
		return;
	if (click_hex(v, rclick))
		return;
	click_panes(v);
	(void)rclick;   /* the menu it will open does not exist yet */
}
