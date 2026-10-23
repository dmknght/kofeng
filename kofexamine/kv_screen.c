#define _GNU_SOURCE
#include "kv.h"


/* ---- the disassembly panel ------------------------------------------------
 *
 * WHY IT IS A PANEL AND NOT A DIALOG.
 *
 * The question it answers is "what do these bytes do", and the bytes are on
 * screen already. A box over the top of them would hide the thing being asked
 * about and make the answer something to memorise before dismissing it; a strip
 * under the hex keeps both in view, and scrolling the hex scrolls the
 * disassembly with it. That is also why it has a close button of its own rather
 * than a key to press: it behaves like the panels around it.
 *
 * WHAT IT DECODES, AND THE ONE THING IT CANNOT KNOW.
 *
 * The decoder needs to be told 32 or 64 bit, and the bytes never say. For an
 * object with a header the collector already worked it out and the panel starts
 * there. For raw bytes - a payload unwrapped out of an encoder, which is the
 * case this is most useful for - there is no header and no answer, so the
 * heading carries the mode and clicking it changes it. Guessing silently would
 * be worse than asking: the same bytes are valid in both modes and mean
 * different things, and a reader who cannot see which was assumed cannot tell.
 */
#define DIS_MIN_ROWS 4


/*
 * The frame that is already on the screen.
 *
 * Repainting is skipped when the new frame is byte for byte the last one, which
 * is what stops button-event tracking from rewriting the screen with what it
 * already says at every report of a pointer that has not left the byte it was
 * on.
 *
 * This used to be a hand-kept list of the fields a frame depends on, and that
 * list did what such lists do: a condition added to the draft moved nothing the
 * list watched, so the screen did not repaint and the button looked dead while
 * quietly working - the clicks landed, and several conditions appeared at once
 * the moment something else moved. Comparing the picture instead cannot fall
 * behind a field, because the picture is the only thing that has to be right.
 */
static char  *g_last;
static size_t g_last_n;

/* The properties page was up on the frame before this one. */
/*
 * WHICH FULL-COVER DIALOG WAS DRAWN LAST FRAME, or 0.
 *
 * An id and not a flag, because switching from one dialog straight to another
 * has to repaint the panes once: the box that is leaving is only erased by
 * what was under it.
 */
static int g_modal_drawn;

void redraw(struct view *v)
{
	struct out o = { 0 };
	int wiped = 0, under;

	g_fld.room = 0;
	/* What field_draw paints as selected, normalised once rather than at
	 * every character - see g_fsel. */
	if (!fsel_range(v, &g_fsel.lo, &g_fsel.hi))
		g_fsel.lo = g_fsel.hi = 0;
	term_size();
	if (g_term_small) {
		/* 60 columns written into 40 wrap every line into the next: say so instead */
		free(g_last);
		g_last = NULL;
		g_last_n = 0;
		term_write("[2J[HTerminal too small - need at least 60x12");
		return;
	}
	/*
	 * THE SCREEN, as the outermost bound every drawer is inside.
	 *
	 * Set here and not in out_add's defaults because a struct out is also
	 * used as a plain string builder - the clipboard is assembled with the
	 * same calls - and a builder that silently dropped what did not fit on
	 * a screen would be a builder that corrupts a copy.
	 *
	 * Set AFTER term_size, because this is the size the frame is being
	 * drawn for.
	 */
	out_clip_set(&o, 1, 1, g_rows, g_cols);
	/*
	 * AND THE POINTER MAP IS CLEARED WITH IT.
	 *
	 * Every rectangle in it describes where something was PAINTED, so it
	 * lives exactly as long as the frame does. Cleared here rather than in
	 * the draft panel, which is where it started: the panes drawn before
	 * the panel register rectangles too, and a clear halfway through the
	 * frame throws away whatever came first.
	 */
	hit_reset(v);
	if (kof_tty_resize_pending()) {
		/*
		 * The cached frame describes a screen of the old size, and the
		 * terminal has thrown away whatever was on it. Comparing
		 * against it would let an unchanged frame skip the repaint and
		 * leave the screen as the resize left it.
		 */
		kof_tty_resize_clear();
		free(g_last);
		g_last = NULL;
		g_last_n = 0;
		term_write("\033[2J");
		wiped = 1;
	}
	/* The panes are laid out around the draft, so its height is settled
	 * before anything asks where it is. */
	{
		/* Groups and their markers, plus the header - capped so the
		 * panel cannot eat the pane it is about. */
		/* How tall the draft is, counted where it is drawn rather than
		 * restated here: the two used to be separate sums, and the one
		 * that fell behind was always this one. */
		uint32_t want;

		mtn_sync(v);
		prow_build(v);
		want = v->n_prow;
		/*
		 * THE SCROLL STAYS WHERE THE READER LEFT IT when the draft
		 * grows.
		 *
		 * Adding a matcher or a pattern used to jump the panel to its
		 * new end, on the reasoning that what was just added is what
		 * you want to see. In practice it threw the reader off whatever
		 * they were looking at every time they declared something - the
		 * panel lurched, and a row they had half-read was gone. Only a
		 * loaded or switched draft returns to the top (prow_home); an
		 * edit keeps the offset it had, clamped below to whatever still
		 * fits.
		 */
		if (v->prow_home) {
			v->prow_off = 0;
			v->prow_home = 0;
		}
		v->prow_seen = v->n_prow;

		/* Two more than the rows it shows: the heading it starts with
		 * and the rule it ends on, which is what puts a border between
		 * the draft and the status line. */
		/*
		 * Always present, empty or not.
		 *
		 * The family, the type and the generate button live on its
		 * first row, and hiding the whole panel until something had
		 * been declared meant none of them could be reached until
		 * after the first string was taken - the one order of work the
		 * tool happened to be built around.
		 */
		/*
		 * AND NEVER TALLER THAN THE SCREEN IT IS DRAWN ON.
		 *
		 * decl_cap is a PREFERENCE - 12 by default, or whatever the
		 * divider was last dragged to - and it was compared only
		 * against how many rows the draft has. Neither of those knows
		 * how tall the terminal is NOW. A draft of twelve rows on a
		 * twelve-row terminal gave g_decl_rows = 14, and then
		 * decl_top() is g_rows - g_decl_rows = -2 and hex_bot() is -4:
		 * every pane below is laid out from a negative row.
		 *
		 * It has to be re-applied on every frame rather than when the
		 * cap is set, because the screen shrinks underneath a cap that
		 * was legal when it was chosen - which is exactly what a
		 * vertical resize is.
		 *
		 * g_rows - 8 is not a new number: it is the same ceiling the
		 * divider drag already applies when it sets the cap. The two
		 * disagreed only because one of them ran again after a resize
		 * and the other did not.
		 */
		int rows = (int)(want < v->ed.dr.decl_cap ? want
							  : v->ed.dr.decl_cap);
		int room = g_rows - 8;

		if (room < 1)
			room = 1;
		if (rows > room)
			rows = room;
		g_decl_rows = rows + 2;
		if (g_decl_rows) {
			/* The furthest it can be scrolled, computed before the
			 * comparison rather than inside it: adding the window
			 * to the offset overflows when the offset is the "show
			 * me the end" sentinel, and an offset of minus one
			 * draws every row one line too low. */
			uint32_t vis = (uint32_t)(g_decl_rows - 2);
			uint32_t max_off = v->n_prow > vis ? v->n_prow - vis
							   : 0u;

			if (v->prow_off > max_off)
				v->prow_off = max_off;
		}
	}

	/*
	 * Synchronised output, DEC mode 2026.
	 *
	 * A frame is one write, but a terminal is free to render what it has
	 * received so far - so a screen rewritten row by row is briefly a screen
	 * half old and half new. This asks it to hold the picture until the
	 * frame is complete. Terminals that do not know the mode ignore it,
	 * which is why it can be sent unconditionally.
	 */
	/*
	 * A full-screen modal paints alone.
	 *
	 * The three panes underneath are 15KB of a 16KB frame and every byte of
	 * them is overdrawn by the box a moment later. Synchronised output is
	 * supposed to make that invisible and does, on a terminal that honours
	 * mode 2026 - on one that does not, a write that large is rendered in
	 * pieces and the pieces are the panes being painted before the box
	 * covers them. That is the flash, and it showed up while scrolling
	 * because scrolling is when frames come fastest.
	 *
	 * So they are skipped while the page is up, and drawn on the frame
	 * it OPENS on: that one still has to erase the menu the reader opened
	 * it from, and nothing under a modal can change afterwards because the
	 * modal has the keyboard.
	 */
	/*
	 * THE PANES ARE NOT REPAINTED UNDER A DIALOG THAT COVERS THEM.
	 *
	 * Every frame used to paint the panes and then the box on top, and a
	 * frame happens on every mouse motion - so dragging a selection
	 * across a dialog repainted the whole screen behind it tens of times
	 * a second. The box always won in the end, but the intermediate
	 * state is a real state on a terminal that does not honour
	 * synchronized output, and that flash of the pane underneath is what
	 * a reader sees.
	 *
	 * The properties page has been exempt from this since it was
	 * written; nothing else was, and nothing about the other dialogs
	 * makes them different. What is under a modal cannot change while it
	 * is up, so there is nothing to repaint.
	 *
	 * THE FIRST FRAME STILL PAINTS, and so does the frame after a
	 * resize, and so does a switch from one dialog to another - the id
	 * below is what makes the third case work, because the box that is
	 * leaving is erased only by what was under it.
	 */
	{
		int modal = v->prop_open   ? 1
			  : v->sym_open    ? 3
			  : v->help_open   ? 4
			  : syn_page_up(v) ? 5
			  : syn_modal(v)   ? 6 : 0;

		/* A bar menu opened over the dialog is another picture: it has to be
		 * erased when it moves or closes, and only the panes can do that. */
		if (modal)
			modal = modal * 100 + (v->bar_open + 2);

		under = !modal || wiped || g_modal_drawn != modal;
		/*
		 * A POP-UP LIST OVER THE PANES, NOT A PAGE: the tag chooser covers
		 * part of them and changes size as its search narrows it, so what
		 * it uncovers has to be painted again on every frame.
		 */
		if (syn_modal(v) && !syn_page_up(v))
			under = 1;
		g_modal_drawn = modal;
	}

	/*
	 * The panel's height, settled before anything is drawn because every
	 * geometry helper below reads it. Half of what the hex column has, and
	 * never so much that the hex is left with less than the panel.
	 */
	/*
	 * The symbol view takes the whole column.
	 *
	 * The panel disassembles the bytes the hex pane is showing, and this
	 * view is showing none: leaving it open would reserve its rows, cost
	 * the table a third of its height, and fill them with the last region's
	 * instructions - which would read as a disassembly OF THE SYMBOLS.
	 * dis_open itself is left alone, so the panel is still there when the
	 * reader moves back to a region.
	 */
	if (v->dis_open && !sym_view(v)) {
		int room = hex_bot() - hex_top() + 1;

		dis_follow_hex(v);
		int want_rows = room / 2;

		if (want_rows < DIS_MIN_ROWS)
			want_rows = DIS_MIN_ROWS;
		/* Two rows for the hex to keep, plus the heading. */
		if (want_rows > room - 3)
			want_rows = room - 3;
		g_disasm_rows = want_rows > 0 ? want_rows : 0;
		/* nowhere to put it: dis_open is left alone so the panel returns when there is room */
	} else {
		g_disasm_rows = 0;
	}

	/*
	 * THE EVENT PANEL'S HEIGHT, settled the same way and after the
	 * disassembler on purpose: g_disasm_rows is what hex_bot's neighbours
	 * are measured against, and a panel sized before it would be sized
	 * against last frame's number.
	 *
	 * As tall as the record needs and no taller. Unlike a disassembly,
	 * which is as long as the reader keeps scrolling, a record has a fixed
	 * number of fields - so a fixed half-column would leave blank rows the
	 * hex pane could have had on almost every event. It still gets a cap,
	 * because a process start with a long command line yields enough rows
	 * to crowd out the bytes the panel is explaining.
	 */
	/*
	 * A DEFERRED TREE REBUILD, here and nowhere else.
	 *
	 * Nothing holds a node index at the top of a frame, which is what makes
	 * this the only safe place - see tree_dirty. The selection is kept by
	 * OBJECT rather than by row, because the rebuild is what moves the rows.
	 */
	if (v->tree_dirty) {
		uint32_t want_obj = v->n_node ? v->node[v->sel_node].obj : 0;
		uint32_t k;

		v->tree_dirty = 0;
		tree_build(v);
		for (k = 0; k < v->n_node; k++)
			if (v->node[k].obj == want_obj && !v->node[k].mask) {
				v->sel_node = k;
				break;
			}
		if (v->sel_node >= v->n_node)
			v->sel_node = v->n_node ? v->n_node - 1u : 0;
		/*
		 * AND RE-RESOLVE THE SELECTION, which is the half that was
		 * missing.
		 *
		 * The extents, the region length and the scroll clamp all
		 * belong to the row that is selected, and the rebuild is what
		 * moves the rows. Left alone they went on describing whatever
		 * was selected before - and with the wrong extents view_map
		 * runs off the end and answers 0 for every byte, so the pane
		 * showed byte zero of the object repeated: sixteen 4D per line
		 * with the offset column stuck at 00000000.
		 */
		view_select(v);
	}

	if (evt_have_rec(v) && v->evt_open && !sym_view(v)) {
		int room = hex_bot() - hex_top() + 1;
		int meta[64], warn[64], nm2 = 0, nw2 = 0;
		int want;


		/*
		 * The table, the warnings, and the box with its rule - the
		 * three zones, added up. Asked from the same classifier the
		 * drawer uses, so the panel is never a row taller or shorter
		 * than what goes in it.
		 */
		want = evt_meta_lines(v) + evt_warn_lines(v);
		if (evt_zones(v, meta, &nm2, warn, &nw2) >= 0)
			want += 1 + EVT_BOX_ROWS;

		if (want > room / 2)
			want = room / 2;
		/* Two rows for the hex to keep, plus the heading. */
		if (want > room - 3)
			want = room - 3;
		g_evt_rows = want > 0 ? want : 0;
	} else {
		g_evt_rows = 0;
	}

	out_str(&o, "\033[?2026h");
	if (under) {
		/*
		 * EACH PANE INSIDE ITS OWN RECTANGLE.
		 *
		 * The frame is drawn first and unclipped because it is what
		 * SEPARATES the panes - the dividers belong to no one of them.
		 * Everything after it is given the region it is about, so a row
		 * that measures wrong is short rather than written across its
		 * neighbour. The rectangles are the same expressions the click
		 * routing tests, so a pane cannot draw where it cannot be
		 * clicked.
		 */
		struct out_clip cl;

		draw_frame(&o, v);
		cl = out_clip_set(&o, hex_top(), 1, hex_bot(), TREE_W);
		draw_tree(&o, v);
		out_clip_restore(&o, cl);
		cl = out_clip_set(&o, hex_top(), TREE_W + 1, hex_last(),
				  g_cols);
		/* One pane, two renderings - see KV_CAP_TEXT. Everything
		 * around it, this clip included, is the same either way. */
		if (text_pane(v))
			draw_text(&o, v);
		else
			draw_hex(&o, v);
		out_clip_restore(&o, cl);
		/*
		 * WHERE THE RIGHT BUTTON MEANS SOMETHING, declared by the pane
		 * that drew it - see the gate at the top of click().
		 *
		 * The same rectangle the clip above uses, so the pane cannot be
		 * right-clickable where it cannot draw.
		 */
		hit_zone(v, hex_top(), TREE_W + 1, hex_last(), g_cols,
			 HIT_R, NULL, 0);
		/*
		 * AND THE WHEEL, BOTH WAYS, when the pane is showing text.
		 *
		 * A hex row is as wide as the pane by construction, so sideways
		 * means nothing there and the plain wheel is answered by the
		 * chain in on_wheel as it always was. A line of source is not,
		 * and neither direction reached this pane before.
		 */
		if (text_pane(v)) {
			hit_zone(v, hex_top(), TREE_W + 1, hex_last(), g_cols,
				 HIT_WHEEL, hit_wheel_text, 0);
			hit_zone(v, hex_top(), TREE_W + 1, hex_last(), g_cols,
				 HIT_HWHEEL, hit_hwheel_text, 0);
		}
		cl = out_clip_set(&o, dis_top() - 1, TREE_W + 1, hex_bot(),
				  g_cols);
		draw_disasm(&o, v);
		out_clip_restore(&o, cl);
		if (g_disasm_rows)
			hit_zone(v, dis_top(), TREE_W + 1, hex_bot(), g_cols,
				 HIT_R, NULL, 0);
		cl = out_clip_set(&o, evt_top() - 1, TREE_W + 1, hex_bot(),
				  g_cols);
		draw_evt(&o, v);
		out_clip_restore(&o, cl);
		/* The event panel's TEXT BOX, not the whole panel: the field
		 * table above it has no menu. */
		if (evt_live(v))
			hit_zone(v, evt_box_top(v), TREE_W + 1,
				 evt_box_top(v) + EVT_BOX_ROWS - 1, g_cols,
				 HIT_R, NULL, 0);
		cl = out_clip_set(&o, decl_top(), 1, g_rows - 1, g_cols);
		draw_decl(&o, v);
		out_clip_restore(&o, cl);
		/* Two rows: the status line, and the rule above it that
		 * closes the draft panel - see draw_marker_line. */
		cl = out_clip_set(&o, mark_row() - 1, 1, mark_row(), g_cols);
		draw_marker_line(&o, v);
		out_clip_restore(&o, cl);
	}
	/*
	 * THE DIALOGS ARE PAINTED ON EVERY FRAME, under the panes or not.
	 *
	 * `under` decides only whether the panes behind a full-screen modal are
	 * repainted. The boxes themselves were inside that test, so once a dialog
	 * was open and its first frame drawn, nothing painted it again: a scroll,
	 * a click on a tab, a typed filter all changed the state and left the
	 * screen as it was.
	 */
	{
		/*
		 * THE DECODER BEFORE THE CONTEXT MENU, because its plaintext
		 * window has a menu of its own.
		 *
		 * Drawn after it, the box painted over the menu it had just
		 * opened - the right-click did everything it was supposed to
		 * and nothing appeared, which reads as a dead menu item. A
		 * modal goes under whatever it pops up, not over it.
		 */
		if (v->enc_open) {
			draw_enc(&o, v);
			/* Its plaintext window, whose geometry the draw just
			 * settled - see enc_in_text, which is this rectangle. */
			if (v->enc_txt_h > 0)
				hit_zone(v, v->enc_txt_y, v->enc_txt_x,
					 v->enc_txt_y + v->enc_txt_h - 1,
					 v->enc_txt_x + v->enc_txt_w - 1,
					 HIT_R, NULL, 0);
		}
		if (v->menu_open)
			draw_menu(&o, v);
		if (v->find_open)
			draw_find(&o, v);
		if (v->goto_open)
			draw_goto(&o, v);
		if (v->sym_open)
			draw_symbols(&o, v);
	}
	/*
	 * THE BAR IS DRAWN ON EVERY FRAME, modal or not.
	 *
	 * It sat inside the block above, so once a full-screen page was up
	 * nothing repainted that row - and whatever stood there when the
	 * page opened stayed on the screen underneath it. A message from
	 * just before, "switched file" and the like, then read as part of
	 * the page's bottom border.
	 *
	 * The reason the panes are skipped does not reach it: they are 15 KB
	 * of a 16 KB frame and this is one line.
	 */
	draw_bar(&o, v);
	if (v->prop_open)
		draw_prop(&o, v);
	if (syn_modal(v))
		draw_syn(&o, v);
	if (v->help_open)
		draw_help(&o, v);
	draw_chooser(&o, v);
	out_str(&o, "\033[?2026l");

	/* Nothing moved: the frame is the one already on the screen. */
	if (o.n && o.n == g_last_n && !memcmp(o.p, g_last, o.n)) {
		free(o.p);
		return;
	}
	if (o.n) {
		char *keep = realloc(g_last, o.n);

		if (keep) {
			memcpy(keep, o.p, o.n);
			g_last = keep;
			g_last_n = o.n;
		}
	}
	if (o.n)
		(void)kof_write_all(STDOUT_FILENO, o.p, o.n);
	free(o.p);
}
