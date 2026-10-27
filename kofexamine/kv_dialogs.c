#define _GNU_SOURCE
#include "kv.h"
#include "goto_parse.h"


/*
 * The find dialog.
 *
 * A box rather than a line, because searching has more than one setting and a
 * line can only hold the one being typed. Every setting is a control that says
 * its own state, so nothing has to be remembered between openings.
 *
 * Regex is drawn and refused. Leaving it out would invite the question every
 * time; drawing it greyed answers it once and marks the place the work goes.
 */
/*
 * Four rows: a top rule and three of content.
 *
 * No bottom rule. The status line already has one directly beneath, and two
 * horizontal lines with nothing between them read as a mistake rather than as a
 * frame.
 */
/*
 * Five rows: a border, three of content, and a border. It was four and the box
 * had no bottom edge at all - the side bars simply stopped, which reads as a
 * dialog that has been cut off rather than one that ends.
 */
#define FIND_H 5

/*
 * The Go to box: its own height and its own rows, no longer borrowed from the
 * find dialog.
 *
 * Five rows because it has three of content and a border top and bottom, and it
 * spans the FULL WIDTH so that no column of the panel underneath shows through
 * beside it. Sharing find's rows left columns one and two unpainted - find
 * starts its rows at column three - and the two columns of whatever was behind
 * it, read down five rows, is what made the dialog look like it was floating on
 * top of a mess.
 */
#define GOTO_H 5

/* ---- the decoder ---------------------------------------------------------
 *
 * WHAT IT IS FOR. A dropper carries its second stage encoded, and until the
 * bytes are decoded every rule written against what the command DOES is written
 * against something that is not in the file. The scanner extracts the case a
 * decoder named itself - see bases/decomp/cmdb64_00.c - and that is the only
 * case a scanner may take, because a run with no anchor is a guess and a
 * scanner that guesses produces children nobody asked for.
 *
 * A PERSON TYPING INTO A FIELD IS NOT A GUESS. So this takes whatever they give
 * it, applies whichever coding they name, and shows what comes out. Nothing
 * here decides anything.
 *
 * THE CODINGS ARE THE ONES WITH NO KEY OR A KEY SOMEBODY CAN TYPE. That is the
 * whole selection rule. A coding whose key has to be RECOVERED is a different
 * problem and belongs in a module that derives it - see the note in
 * bases/unp/ezuri.c, which does exactly that and is the shape to copy.
 */

/* What one decoding may produce. Past this it is not something a box on a
 * terminal has anything to say about, and Extract re-runs from the field. */
/*
 * WHERE THE ANSWER LANDS. Sized for a decoded script rather than for a string:
 * a dropper's payload is the thing worth reading, and a box that truncated it
 * would send the reader somewhere else for what it just produced.
 */
#define ENC_OUT_MAX (64u << 10)

/* Rows of plaintext the box shows. Enough for a dropper's script to be read
 * without scrolling, few enough that the form stays on one screen. */
#define ENC_RES_ROWS 8
/* The widest the decoder's result window may be, in columns; its rule is drawn from a three-byte glyph, which sizes the buffer. */
#define ENC_RES_MAX_W 120u

static int  enc_in_text(const struct view *v, int y, int x);

/*
 * Position and draw the top rule. Returns 0 when the terminal is too small to
 * draw the box honestly, and the caller draws nothing at all - a box clipped to
 * a screen that cannot hold it is worse than no box.
 */
int dframe_begin(struct out *o, struct dframe *f, const char *title,
			int want_w, int want_h, int close)
{
	/* close 1: the "[ Close ]" button, 2: the "[x]" box of a small dialog (the same hit test either way). */
	const char *btn = close == 2 ? "[x]" : "[ Close ]";
	int i, fill;

	f->btn_y = f->btn_x0 = f->btn_x1 = -1;
	f->w = want_w;
	if (f->w > g_cols - 4)
		f->w = g_cols - 4;
	f->h = want_h;
	if (f->h > g_rows - 4)
		f->h = g_rows - 4;
	if (f->w < 24 || f->h < 3)
		return 0;
	f->x = (g_cols - f->w) / 2 + 1;
	if (f->x < 2)
		f->x = 2;
	/*
	 * A THIRD OF THE WAY DOWN, not halfway.
	 *
	 * A box centred vertically sits over the hex pane's middle, which is
	 * where the reader was looking when they opened it. Higher leaves the
	 * rows under the cursor visible, and a dialog that asks about what is
	 * on screen should not be standing on it.
	 */
	f->y = (g_rows - f->h) / 3;
	if (f->y < 2)
		f->y = 2;
	/*
	 * AND THEN WHEREVER THE READER DRAGGED IT, clamped so the whole box
	 * stays on screen. Clamped rather than refused: a terminal that shrank
	 * under a moved box should bring it back into view, not lose it.
	 */
	f->x += f->off.dx;
	f->y += f->off.dy;
	if (f->x + f->w - 1 > g_cols)
		f->x = g_cols - f->w + 1;
	if (f->x < 1)
		f->x = 1;
	if (f->y + f->h - 1 > g_rows)
		f->y = g_rows - f->h + 1;
	if (f->y < 2)
		f->y = 2;               /* row 1 is the menu bar */
	f->ix = f->x + 2;
	f->iw = f->w - 4;
	/* The box owns these rows and these columns and nothing else. Set
	 * before the first thing is drawn and given back by dframe_done. */
	f->save = out_clip_set(o, f->y, f->x, f->y + f->h - 1,
			       f->x + f->w - 1);

	out_at(o, f->y, f->x);
	o->col_hint = 0;
	out_str(o, A_DIM);
	out_glyph(o, G_TL);
	out_glyph(o, G_H);
	out_fmt(o, A_OFF A_BOLD " %s " A_OFF A_DIM, title ? title : "");
	fill = f->w - 4 - (title ? (int)strlen(title) : 0) - 2;
	/*
	 * sizeof btn - 1, AND THE -1 IS THE WHOLE BUG THIS ONCE HAD.
	 *
	 * btn is "[ Close ]": nine columns on screen and ten bytes in the
	 * array. Subtracting sizeof took one column too many out of the fill,
	 * so the top rule came out one short and the box was a column narrower
	 * at the top than at every row under it - visible as a notch by the
	 * right corner.
	 *
	 * Only the Decode string dialog showed it, because it is the only
	 * caller that asks for a close control; Go to and Find pass close 0 and
	 * take the branch that was always right.
	 *
	 * The panel header at the other end of this file computes the same row
	 * and gets it right - `(int)sizeof close - 1` - and the comment above
	 * that one already names this exact failure: "a rule one short draws a
	 * box narrower at the top than at every row below it, and the step is
	 * visible." Two implementations of one rectangle, and the one with the
	 * warning written on it was not the one with the bug.
	 */
	if (close)
		fill -= (int)strlen(btn);
	if (fill < 0)
		fill = 0;
	for (i = 0; i < fill; i++)
		out_glyph(o, G_H);
	if (close) {
		f->btn_y = f->y;
		f->btn_x0 = f->x + (int)o->col_hint;
		out_fmt(o, A_OFF A_ID "%s" A_OFF A_DIM, btn);
		f->btn_x1 = f->x + (int)o->col_hint - 1;
	}
	out_glyph(o, G_H);
	out_glyph(o, G_TR);
	out_str(o, A_OFF);
	return 1;
}

/* Open row `r` (0 based, inside the frame): the left wall, then the cursor
 * where the caller writes. */
/* Hand the screen back. Every drawer that got a 1 out of dframe_begin calls
 * this, whether or not it drew a bottom rule. */
void dframe_done(struct out *o, struct dframe *f)
{
	out_clip_restore(o, f->save);
}

void dframe_row(struct out *o, const struct dframe *f, int r)
{
	out_at(o, f->y + 1 + r, f->x);
	o->col_hint = 0;
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF " ");
	out_at(o, f->y + 1 + r, f->ix);
	o->col_hint = 0;
}

/* Close the row the caller has just written: pad to the edge, then the wall. */
void dframe_edge(struct out *o, const struct dframe *f)
{
	while ((int)o->col_hint < f->iw)
		out_str(o, " ");
	out_str(o, A_DIM " ");
	out_glyph(o, G_V);
	out_str(o, A_OFF);
}

/* The bottom rule, with an optional caption sitting on it. */
void dframe_end(struct out *o, const struct dframe *f, const char *foot)
{
	int i, fill;

	out_at(o, f->y + f->h - 1, f->x);
	o->col_hint = 0;
	out_str(o, A_DIM);
	out_glyph(o, G_BL);
	out_glyph(o, G_H);
	if (foot && foot[0])
		out_fmt(o, " %s ", foot);
	fill = f->w - 3 - (foot && foot[0] ? (int)strlen(foot) + 2 : 0);
	for (i = 0; i < fill; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_BR);
	out_str(o, A_OFF);
}

static uint8_t g_encbuf[ENC_OUT_MAX];

void enc_do(struct view *v)
{
	uint32_t len = (uint32_t)strlen(v->enc_in);
	uint32_t key = kof_codec_keyed(v->enc_type)
		     ? kof_codec_key(v->enc_key) : 0;
	struct kuncoat_step step;
	enum kuncoat_status st;
	uint8_t keybyte[1];
	uint64_t got = 0;

	v->enc_res_n = 0;
	v->enc_done = 1;
	if (!len)
		return;
	kof_codec_step(v->enc_type, key, v->enc_way, keybyte, &step);
	st = kuncoat_transform(&step, (const uint8_t *)v->enc_in, len,
			       g_encbuf, ENC_OUT_MAX, &got);
	/* A result that filled the box is shown as what fits - the same as before
	 * the status existed; anything else is "this coding cannot do it". */
	if (st == KUNCOAT_OK || st == KUNCOAT_OVER_BUDGET)
		v->enc_res_n = (uint32_t)got;
}

/*
 * The plaintext as LINES, walked rather than indexed.
 *
 * An index would be an array sized for the worst case and rebuilt on every
 * decode; the walk is over at most ENC_OUT_MAX bytes and happens once a frame,
 * which is far below what a redraw already costs.
 */
static uint32_t enc_lines(const struct view *v)
{
	uint32_t i, n = 1;

	if (!v->enc_res_n)
		return 0;
	for (i = 0; i < v->enc_res_n; i++)
		if (g_encbuf[i] == '\n')
			n++;
	return n;
}

/* Where line `want` starts and how long it is, not counting its newline. */
static void enc_line(const struct view *v, uint32_t want, uint32_t *off,
		     uint32_t *len)
{
	uint32_t i, n = 0, beg = 0;

	*off = *len = 0;
	for (i = 0; i <= v->enc_res_n; i++) {
		if (i == v->enc_res_n || g_encbuf[i] == '\n') {
			if (n == want) {
				*off = beg;
				*len = i - beg;
				return;
			}
			n++;
			beg = i + 1u;
		}
	}
}

/* The widest line, which is how far sideways the window may go. */
static uint32_t enc_widest(const struct view *v)
{
	uint32_t i, w = 0, run = 0;

	for (i = 0; i < v->enc_res_n; i++) {
		if (g_encbuf[i] == '\n') {
			run = 0;
			continue;
		}
		if (++run > w)
			w = run;
	}
	return w;
}


void draw_enc(struct out *o, struct view *v)
{
	struct dframe *f = &g_enc_f;

	/* Four form rows, the count line, then the window: its two rules and
	 * the text between them. Plus the box's own two. */
	if (!dframe_begin(o, f, "Decode string", 100, ENC_RES_ROWS + 8, 1))
		return;

	dframe_row(o, f, 0);
	/*
	 * "string", AND IT DOES NOT CHANGE.
	 *
	 * It used to read "encoded" or "plain" depending on which way the box
	 * was set, which was a label describing a MODE rather than the field
	 * under it - and with a button for each direction there is no mode
	 * left to describe. What goes in the field is a string; which way it
	 * is read is the button that is pressed.
	 */
	out_fmt(o, A_DIM "%-9s" A_OFF, "string");
	v->e_in[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == ED_ENC_IN ? A_SEL : A_ID);
	field_draw(o, v->enc_in, v->caret, &v->enc_in_off, f->iw - 13,
		   v->edit == ED_ENC_IN, "paste or type a string");
	out_str(o, "]" A_OFF);
	v->e_in[1] = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, f);

	/*
	 * THE CODING, AND NOTHING ELSE ON THE ROW.
	 *
	 * It carried a "way" switch and, for the codings with no key, the
	 * sentence "this coding has no key" - a control for a question the
	 * buttons below now answer, and a line of prose saying that a box
	 * which is not drawn is not drawn. The row asks one thing.
	 */
	dframe_row(o, f, 1);
	out_fmt(o, A_DIM "%-9s" A_OFF, "type");
	v->e_type[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_ID "[ %-7s ]" A_OFF, kof_codec_name(v->enc_type));
	v->e_type[1] = o->col_base + (int)o->col_hint - 1;
	if (kof_codec_keyed(v->enc_type)) {
		out_fmt(o, A_DIM "   key " A_OFF);
		v->e_key[0] = o->col_base + (int)o->col_hint;
		out_fmt(o, "%s[", v->edit == ED_ENC_KEY ? A_SEL : A_ID);
		field_draw(o, v->enc_key, v->caret, &v->enc_key_off, 10,
			   v->edit == ED_ENC_KEY,
			   v->enc_type == KOF_CODEC_CAESAR ? "1-25" : "hex");
		out_str(o, "]" A_OFF);
		v->e_key[1] = o->col_base + (int)o->col_hint - 1;
	} else {
		v->e_key[0] = v->e_key[1] = -1;
	}
	dframe_edge(o, f);

	/*
	 * ONE BUTTON PER DIRECTION, because they are two things to do with
	 * this string rather than two settings of one thing. Pressing one
	 * says which way as well as go.
	 */
	dframe_row(o, f, 2);
	out_fmt(o, "%-9s", "");
	v->e_go[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Decode ]" A_OFF,
		v->enc_in[0] ? "\033[42;30m" : "\033[47;90m");
	v->e_go[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->e_enc[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Encode ]" A_OFF,
		v->enc_in[0] ? "\033[42;30m" : "\033[47;90m");
	v->e_enc[1] = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, f);

	/*
	 * WHAT CAME BACK, and nothing at all before anything has.
	 *
	 * The row used to open with the word "plain" whether or not there was
	 * any - a label with nothing under it and nothing to do, on a form
	 * where every other row is a control.
	 */
	dframe_row(o, f, 3);
	if (v->enc_res_n)
		out_fmt(o, "%-9s" A_SIZE "%lu" A_OFF A_DIM
			" bytes, %lu line(s)" A_OFF, "",
			(unsigned long)v->enc_res_n,
			(unsigned long)enc_lines(v));
	else if (v->enc_done && v->enc_in[0])
		out_fmt(o, "%-9s" A_WARN "%s" A_OFF, "",
			v->enc_way ? "that coding cannot write this string"
				   : "that coding cannot read this string");
	dframe_edge(o, f);

	/*
	 * THE PLAINTEXT IN A WINDOW OF ITS OWN, with its own two scrollbars.
	 *
	 * A decoded script is longer than any box and its lines are longer than
	 * any width, so showing a prefix would send the reader somewhere else
	 * for the thing this just produced. A window with a border says where
	 * the text starts and stops, and the two bars say how much of it is off
	 * the screen - which a box that simply ran out of rows does not.
	 *
	 * RECORDED INTO THE SELECTION LAYER as it is drawn, so dragging through
	 * it and Ctrl+C work exactly as they do on the properties page. That is
	 * the whole reason the layer is not part of any one dialog.
	 */
	{
		uint32_t nl = enc_lines(v), wide = enc_widest(v);
		uint32_t shown = nl > (uint32_t)ENC_RES_ROWS
			       ? (uint32_t)ENC_RES_ROWS : nl;
		int iw = f->iw - 4;             /* the window's inside */
		int r;
		char rule[ENC_RES_MAX_W * 3u + 1u];
		uint32_t k = 0;

		if (iw < 8)
			iw = 8;
		if ((uint32_t)iw > ENC_RES_MAX_W)
			iw = (int)ENC_RES_MAX_W;
		/* Clamped here, where how much fits is finally known. */
		if (nl > (uint32_t)ENC_RES_ROWS) {
			if (v->enc_voff > nl - (uint32_t)ENC_RES_ROWS)
				v->enc_voff = nl - (uint32_t)ENC_RES_ROWS;
		} else {
			v->enc_voff = 0;
		}
		if (wide > (uint32_t)iw) {
			if (v->enc_hoff > wide - (uint32_t)iw)
				v->enc_hoff = wide - (uint32_t)iw;
		} else {
			v->enc_hoff = 0;
		}

		while (k < (uint32_t)iw) {
			memcpy(rule + k * 3u, G_H, sizeof G_H - 1u);
			k++;
		}
		rule[k * (sizeof G_H - 1u)] = 0;

		dframe_row(o, f, 4);
		out_fmt(o, "  " A_DIM G_TL "%s" G_TR A_OFF, rule);
		dframe_edge(o, f);

		/* Where the window is, for the click and the wheel. */
		v->enc_txt_y = f->y + 6;
		v->enc_txt_x = f->ix + 3;
		v->enc_txt_w = iw;
		v->enc_txt_h = ENC_RES_ROWS;
		dlg_rec_begin(v, v->enc_txt_y, v->enc_txt_x);

		for (r = 0; r < ENC_RES_ROWS; r++) {
			char line[PROP_W];
			uint32_t off = 0, len = 0, n = 0;
			const char *bar = G_V;

			dframe_row(o, f, 5 + r);
			out_fmt(o, "  " A_DIM G_V A_OFF);
			if ((uint32_t)r < shown) {
				enc_line(v, v->enc_voff + (uint32_t)r,
					 &off, &len);
				if (v->enc_hoff < len) {
					off += v->enc_hoff;
					len -= v->enc_hoff;
				} else {
					len = 0;
				}
				if (len > (uint32_t)iw)
					len = (uint32_t)iw;
				for (n = 0; n < len; n++) {
					uint8_t c = g_encbuf[off + n];

					line[n] = (c >= 0x20u && c <= 0x7eu)
						? (char)c : '.';
				}
			}
			line[n] = 0;
			out_fmt(o, A_ID "%-*.*s" A_OFF, iw, iw, line);
			dlg_rec_text(v, line);
			dlg_rec_src(v, v->enc_voff + (uint32_t)r);
			/*
			 * THE VERTICAL BAR LIVES IN THE WALL, one cell per row -
			 * the same thumb the dashboard's tables use, and drawn
			 * only when there is more than fits. A full-height thumb
			 * says nothing.
			 */
			{
				const char *b = kv_bar_at(ENC_RES_ROWS, r,
							  v->enc_voff, nl,
							  (uint32_t)ENC_RES_ROWS,
							  0);

				if (b)
					bar = b;
			}
			out_str(o, bar);
			dframe_edge(o, f);
		}

		/*
		 * AND SIDEWAYS ON THE BOTTOM RULE, where a horizontal bar goes.
		 * Drawn as a run of thumb glyphs over the rule so the rule
		 * still reads as the window's edge.
		 */
		dframe_row(o, f, 5 + ENC_RES_ROWS);
		out_fmt(o, "  " A_DIM G_BL A_OFF);
		if (wide > (uint32_t)iw) {
			int c;

			for (c = 0; c < iw; c++) {
				const char *b = kv_bar_at(iw, c, v->enc_hoff,
							  wide, (uint32_t)iw,
							  1);

				out_str(o, b ? b : A_DIM G_H A_OFF);
			}
		} else {
			out_fmt(o, A_DIM "%s" A_OFF, rule);
		}
		out_fmt(o, A_DIM G_BR A_OFF);
		dframe_edge(o, f);

		dlg_paint_sel(o, v);
	}

	/*
	 * NO HELP BUTTON ON THIS BOX.
	 *
	 * It opened the keyboard page, which is a list of the viewer's chords
	 * and says nothing about a coding - so on this form it was a control
	 * that led away from the only thing the reader came here to do. The
	 * page is still on the menu bar, where a reader looking for keys
	 * looks.
	 */
	dframe_end(o, f, NULL);
	dframe_done(o, f);
}

/* Non-zero when a click landed on the frame's close control. */
int dframe_hit_close(const struct dframe *f, int my, int mx)
{
	return f->btn_y >= 0 && my == f->btn_y &&
	       mx >= f->btn_x0 && mx <= f->btn_x1;
}

/* Open the box, optionally filled from a range of the object. */
void enc_open_with(struct view *v, const uint8_t *p, uint32_t n)
{
	uint32_t i;

	if (p && n) {
		if (n > ENC_IN_MAX - 1u)
			n = ENC_IN_MAX - 1u;
		for (i = 0; i < n; i++)
			v->enc_in[i] = (char)p[i];
		v->enc_in[n] = 0;
		v->enc_in_off = 0;
		v->enc_res_n = 0;
		v->enc_done = 0;
	}
	v->enc_open = 1;
	v->edit = ED_ENC_IN;
	v->caret = (uint32_t)strlen(v->enc_in);
}

/* Non-zero when a screen position is inside the plaintext window. */
static int enc_in_text(const struct view *v, int y, int x)
{
	return v->enc_txt_h > 0 && y >= v->enc_txt_y &&
	       y < v->enc_txt_y + v->enc_txt_h &&
	       x >= v->enc_txt_x && x < v->enc_txt_x + v->enc_txt_w;
}

/* The selected plaintext, as bytes. The same span dlg_copy takes, handed back
 * instead of being put on the clipboard - so Copy and Declare cannot disagree
 * about what was picked. */
size_t enc_sel_text(struct view *v, char *out, size_t cap)
{
	int r0, c0, r1, c1, r;
	size_t n = 0;

	if (!dlg_span(v, &r0, &c0, &r1, &c1))
		return 0;
	for (r = r0; r <= r1 && n + 1u < cap; r++) {
		int row = dlg_row_of_src(v, r), len, from, to;

		if (row < 0)
			continue;
		len = (int)v->dlg_cols[row];
		from = (r == r0) ? c0 : 0;
		to   = (r == r1) ? c1 + 1 : len;
		if (to > len)
			to = len;
		while (to > from &&
		       v->dlg_line[row][v->dlg_bx[row][to - 1]] == ' ')
			to--;
		if (n && n + 1u < cap)
			out[n++] = '\n';
		while (from < to && n + 1u < cap)
			out[n++] = v->dlg_line[row][v->dlg_bx[row][from++]];
	}
	out[n] = 0;
	return n;
}

/* A click in the Decoder: a control, or nothing. */
int enc_click(struct view *v, int rclick)
{
	const struct dframe *f = &g_enc_f;

	/*
	 * THE CHOOSER IS ON TOP, SO IT GETS THE MOUSE FIRST.
	 *
	 * The coding list opens ABOVE the control it belongs to, which puts its
	 * lower rows over this box - and this runs before the chooser's own
	 * handler, so it swallowed them. The last row was the worst case: click
	 * "reverse" and nothing happened, the list stayed up, and every click
	 * after it was eaten the same way. It read as a frozen menu.
	 */
	if (v->ch.open)
		return 0;
	/*
	 * AN OPEN MENU GETS THE CLICK, WHEREVER IT LANDED.
	 *
	 * This box swallows every click inside its frame, and the menu its own
	 * plaintext window opens is drawn over that frame - so a click meant to
	 * dismiss the menu was eaten here and the menu stayed up. Clicking
	 * again ate it again: a menu that could not be closed, and a repaint
	 * with nothing changed on every attempt.
	 *
	 * click_menu is the one place that decides what a click on an open menu
	 * means - run the item under it, or dismiss - and calling it here is
	 * what keeps that decision in one place.
	 */
	if (v->menu_open)
		return click_menu(v);
	if (!f->w)
		return 0;
	/*
	 * A RIGHT-CLICK IN THE PLAINTEXT OPENS ITS OWN MENU, and the selection
	 * is left alone: right-clicking to copy what you just selected is the
	 * gesture, and moving the selection first would copy the wrong thing.
	 */
	if (rclick && enc_in_text(v, g_my, g_mx)) {
		v->menu_ctx = 16;
		menu_open_at(v, g_my, g_mx);
		return 1;
	}
	if (dframe_hit_close(f, g_my, g_mx)) {
		v->enc_open = 0;
		v->edit = 0;
		return 1;
	}
	if (g_my < f->y || g_my >= f->y + f->h ||
	    g_mx < f->x || g_mx >= f->x + f->w)
		return 0;
	if (g_my == f->y + 1 && g_mx >= v->e_in[0] && g_mx <= v->e_in[1]) {
		v->edit = ED_ENC_IN;
		v->caret = (uint32_t)strlen(v->enc_in);
		return 1;
	}
	if (g_my == f->y + 2) {
		if (g_mx >= v->e_type[0] && g_mx <= v->e_type[1]) {
			ch_open(v, CH_ENC_TYPE, 0, g_my, v->e_type[0]);
			return 1;
		}
		if (v->e_key[0] >= 0 && g_mx >= v->e_key[0] &&
		    g_mx <= v->e_key[1]) {
			v->edit = ED_ENC_KEY;
			v->caret = (uint32_t)strlen(v->enc_key);
			return 1;
		}
	}
	if (g_my == f->y + 3) {
		/* The button IS the direction - see draw_enc. */
		if (g_mx >= v->e_go[0] && g_mx <= v->e_go[1]) {
			v->enc_way = 0;
			enc_do(v);
		} else if (g_mx >= v->e_enc[0] && g_mx <= v->e_enc[1]) {
			v->enc_way = 1;
			enc_do(v);
		}
		return 1;
	}
	/*
	 * A PRESS IN THE PLAINTEXT STARTS A SELECTION, through the same layer
	 * the properties page and the symbol table use - the window records its
	 * rows as it draws them for exactly this.
	 */
	if (enc_in_text(v, g_my, g_mx)) {
		int r, c;

		if (dlg_at(v, g_my, g_mx, &r, &c)) {
			if ((g_mod_shift || g_mod_ctrl) && v->dlg_have) {
				v->dlg_br = r;
				v->dlg_bc = c;
			} else {
				v->dlg_ar = v->dlg_br = r;
				v->dlg_ac = v->dlg_bc = c;
				v->dlg_have = 1;
			}
			v->dlg_drag = 1;
		}
		return 1;
	}
	return 1;
}



/*
 * The number typed in, or KGENOME_BROKEN when it is not one.
 *
 * The parsing itself is in goto_parse.h, where a test can reach it - see the
 * note there on why the base rules are the part worth testing. This only
 * translates that header's "bad" into the engine's KGENOME_BROKEN, which are the
 * same value but named for two different vocabularies.
 */
static uint64_t goto_value(const struct view *v)
{
	uint64_t n = kof_goto_parse(v->gotobuf);

	return n == KOF_GOTO_BAD ? KGENOME_BROKEN : n;
}

/*
 * Take the offset there, and SELECT the byte as well as scrolling to it.
 *
 * Scrolling alone puts the answer on the screen and leaves the reader to find
 * which of sixteen columns it was - so the byte is selected, which is also what
 * makes the disassembly panel and every menu item that works on a selection
 * point at it.
 */
void goto_take(struct view *v)
{
	uint64_t val = goto_value(v), fo;

	if (val == KGENOME_BROKEN) {
		say_err(&v->ed, "%s", "Not a number");
		return;
	}
	if (!v->goto_file && val >= v->rgn_len) {
		say_err(&v->ed, "Past the end of the region");
		return;
	}
	fo = v->goto_file ? val : view_map(v, val, 0);
	{
		/*
		 * Bounded by WHAT THE ROW IS SHOWING, not by the file.
		 *
		 * On a symbol row view_map returns an offset into the built
		 * block, so comparing it with the file size let an offset past
		 * the end of a small block through and refused one inside a
		 * large file's block.
		 */
		uint64_t bn = 0;

		(void)view_bytes(v, &bn);
		if (v->goto_file)
			bn = cur_obj(v)->buf.n;
		if (fo == KGENOME_BROKEN || fo >= bn) {
			say_err(&v->ed, "Past the end of the %s",
				v->goto_file ? "file" : "region");
			return;
		}
	}
	/* GOTO is the reader naming a place, from the row they are on - the
	 * same ask as a search, so it answers the same way. */
	view_show_in(v, v->node[v->sel_node].obj,
		     v->node[v->sel_node].sym, fo, 0);
	{
		uint64_t r = view_unmap(v, fo);

		if (r != KGENOME_BROKEN) {
			v->sel_a = v->sel_b = r;
			v->sel_from_dis = 0;
		}
	}
	v->goto_open = 0;
	v->edit = 0;
	say_note(&v->ed, "At file offset 0x%llx", (unsigned long long)fo);
}

/*
 * GO TO, one line: the number, what it is measured from, and what it resolved
 * to.
 *
 * The resolved value is shown while it is being typed rather than after the
 * jump, because an offset typed into the wrong base is the mistake this dialog
 * exists to make, and seeing "0x120 -> file 0x1120" says which base was used
 * before Enter commits to it.
 */
/* Fill the row out to the right border and close it. */
void draw_goto(struct out *o, struct view *v)
{
	struct dframe *f = &g_goto_f;
	uint64_t val = goto_value(v);
	int ok = val != KGENOME_BROKEN;

	if (!dframe_begin(o, f, "Go to", 64, GOTO_H, 0))
		return;

	/*
	 * The field and what the number is measured from.
	 *
	 * Every click box is recorded as col_base + col_hint, not 1 + col_hint:
	 * col_hint counts from wherever the row was positioned, so the shorter
	 * form is only right for a row that starts at column one. The find
	 * dialog's boxes have been two columns off for exactly that reason -
	 * see the note on col_base - and this box is not going to repeat it.
	 */
	dframe_row(o, f, 0);
	out_fmt(o, A_DIM "Go to " A_OFF);
	v->g_txt[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == 520 ? A_SEL : A_ID);
	field_draw(o, v->gotobuf, v->caret, &v->goto_off, 18,
		   v->edit == 520, "offset");
	out_str(o, "]" A_OFF);
	v->g_txt[1] = o->col_base + (int)o->col_hint - 1;
	out_fmt(o, A_DIM "  as " A_OFF);
	v->g_mode[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%s]" A_OFF, A_ID, v->goto_file ? "File" : "Region");
	v->g_mode[1] = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, f);

	/*
	 * WHAT THE NUMBER RESOLVED TO, while it is being typed.
	 *
	 * An offset typed in the wrong base is the mistake this box invites -
	 * "10" is sixteen here - so it is shown in both bases before Enter
	 * commits to it, and a field that is not a number says so rather than
	 * waiting for the jump to fail.
	 */
	dframe_row(o, f, 1);
	if (!v->gotobuf[0])
		out_fmt(o, A_DIM "hex by default - 0x for hex, 0n for decimal"
			A_OFF);
	else if (!ok)
		out_fmt(o, "%snot a number" A_OFF, A_WARN);
	else
		out_fmt(o, A_DIM "= " A_OFF "%s0x%llx" A_OFF A_DIM
			" = %llu, from the %s" A_OFF, A_ID,
			(unsigned long long)val, (unsigned long long)val,
			v->goto_file ? "file" : "region");
	dframe_edge(o, f);

	dframe_row(o, f, 2);
	v->g_go[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Go ]" A_OFF, ok ? A_ID : A_DIM);
	v->g_go[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->g_cancel[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_ID "[ Cancel ]" A_OFF);
	v->g_cancel[1] = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, f);

	dframe_end(o, f, NULL);
	dframe_done(o, f);
}

/*
 * A click inside the Go to box. Mirrors find_click, including the rule that a
 * click OUTSIDE only takes the caret away - the dialog keeps its place until
 * Cancel or Esc, because losing a half-typed offset to a stray click on the
 * hex pane is the kind of thing a tool only has to do once.
 */
int goto_click(struct view *v)
{
	const struct dframe *f = &g_goto_f;
	int top = f->y;

	/* The box's own geometry, not a second guess at it - the frame was
	 * recorded where it was drawn. */
	if (!f->w || g_my < top || g_my >= top + f->h ||
	    g_mx < f->x || g_mx >= f->x + f->w) {
		v->edit = 0;
		return 0;
	}
	if (g_my == top + 1 && g_mx >= v->g_txt[0] && g_mx <= v->g_txt[1]) {
		v->edit = 520;
		return 1;
	}
	if (g_my == top + 1 && g_mx >= v->g_mode[0] && g_mx <= v->g_mode[1]) {
		/* File offsets are what every report and every finding names;
		 * region offsets are what the hex gutter shows. Both are "the
		 * offset" depending on what is being read, so it is a toggle
		 * rather than a guess. */
		v->goto_file = !v->goto_file;
		return 1;
	}
	if (g_my == top + 3) {
		if (g_mx >= v->g_cancel[0] && g_mx <= v->g_cancel[1]) {
			v->goto_open = 0;
			v->edit = 0;
		} else if (g_mx >= v->g_go[0] && g_mx <= v->g_go[1]) {
			goto_take(v);
		}
	}
	return 1;
}

void draw_find(struct out *o, struct view *v)
{
	struct dframe *f = &g_find_f;

	/*
	 * Wide enough for the widest row, which is the three checkboxes:
	 * "[ ] Regex" + "[ ] Ignore case" + "[x] Search whole object" and two
	 * gaps of three. Counted rather than rounded up, so the box is as wide
	 * as it has to be and no wider.
	 */
	if (!dframe_begin(o, f, "Find", 9 + 3 + 15 + 3 + 24 + 4, FIND_H, 0))
		return;

	dframe_row(o, f, 0);
	out_fmt(o, A_DIM "Find " A_OFF);
	v->f_txt[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == 500 ? A_SEL : A_ID);
	field_draw(o, v->find, v->caret, &v->find_off, 30, v->edit == 500, "");
	out_str(o, "]" A_OFF);
	v->f_txt[1] = o->col_base + (int)o->col_hint - 1;
	out_fmt(o, A_DIM "  as " A_OFF);
	v->f_mode[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%s]" A_OFF, A_WARN, v->find_hex ? "Hex" : "Text");
	v->f_mode[1] = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, f);

	dframe_row(o, f, 1);
	v->f_rx[0] = o->col_base + (int)o->col_hint;
	/*
	 * LIVE NOW. It was drawn permanently greyed - bright black on white,
	 * because the same colour twice is a grey block where a label should
	 * be - while there was nothing behind it. There is: the engine's own
	 * regex, compiled by kof_regex_compile and walked by
	 * kof_hex_walk_flags, which is the pair the matcher uses.
	 *
	 * A_BAD when the pattern will not compile, so the reason the search
	 * stopped finding things is on the control that caused it.
	 *
	 * NOT WITH HEX. A regex is over text; hex names bytes, and the two
	 * spellings of a pattern are not both true of one field.
	 */
	if (v->find_hex)
		out_fmt(o, "\033[47;90m[ ] Regex" A_OFF);
	else
		out_fmt(o, "%s[%s] Regex" A_OFF,
			v->find_rx_bad ? A_BAD : A_ID,
			v->find_regex ? "x" : " ");
	v->f_rx[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "   ");
	v->f_ic[0] = o->col_base + (int)o->col_hint;
	if (v->find_hex)
		out_fmt(o, "\033[47;90m[ ] Ignore case" A_OFF);
	else
		out_fmt(o, "%s[%s] Ignore case" A_OFF, A_ID,
			v->find_icase ? "x" : " ");
	v->f_ic[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "   ");
	v->f_all[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%s] Search whole object" A_OFF, A_ID,
		v->find_scope ? "x" : " ");
	v->f_all[1] = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, f);

	dframe_row(o, f, 2);
	v->f_next[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Find next ]" A_OFF, v->find[0] ? A_ID : A_DIM);
	v->f_next[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->f_back[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Find previous ]" A_OFF, v->find[0] ? A_ID : A_DIM);
	v->f_back[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->f_cancel[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_ID "[ Cancel ]" A_OFF);
	v->f_cancel[1] = o->col_base + (int)o->col_hint - 1;
	/* Where the hit is belongs on the status line, which says it already.
	 * Saying it twice made the dialog a row taller for no new fact. */
	dframe_edge(o, f);

	dframe_end(o, f, NULL);
	dframe_done(o, f);
}

/*
 * A PRESS ON A BOX'S TITLE ROW TAKES HOLD OF THE BOX.
 *
 * The title row is the handle, which is the gesture every windowed thing has
 * used for forty years - nothing has to be drawn to explain it. The close
 * control sits on that row too and is a BUTTON, so it is excluded: a handle
 * that also closed the box would make the box impossible to grab by its right
 * hand end.
 *
 * Generic, on the frame rather than on any one dialog, so find and goto and the
 * decoder all gain it from the same nine lines - and a box added later gains it
 * without anybody remembering to.
 */
/* Take hold of a box's offset at the pointer: the one place a drag starts, for a framed dialog (dframe_grab) and for the
 * dashboard's frame (kv_dd). on_drag moves `off` by the pointer's travel and on_release lets go. */
void dlg_hold(struct view *v, struct dlg_off *off)
{
	v->dlg_move = off;
	v->dlg_mx = g_mx;
	v->dlg_my = g_my;
	v->dlg_mdx = off->dx;
	v->dlg_mdy = off->dy;
}

int dframe_grab(struct view *v, struct dframe *f)
{
	if (g_my != f->y || g_mx < f->x || g_mx > f->x + f->w - 1)
		return 0;
	if (f->btn_y == f->y && g_mx >= f->btn_x0 && g_mx <= f->btn_x1)
		return 0;
	dlg_hold(v, &f->off);
	return 1;
}

/* Which control a click landed on. */
/*
 * Which control a click landed on, and whether the dialog wanted it at all.
 *
 * A click outside the box is NOT a close. The dialog is a tool for looking
 * through the object, so moving the tree to another region while it is open is
 * an ordinary thing to do - and the next search then runs in the region that is
 * now current, which is the whole point of it staying. Cancel and Esc are what
 * close it, because those are the two things that mean "I am done".
 */
int find_click(struct view *v)
{
	const struct dframe *f = &g_find_f;
	int top = f->y;

	/* The box's own geometry, recorded where it was drawn - see g_find_f. */
	if (!f->w || g_my < top || g_my >= top + f->h ||
	    g_mx < f->x || g_mx >= f->x + f->w) {
		v->edit = 0;            /* the field loses the caret, not the
					 * dialog its place */
		return 0;
	}
	if (g_my == top + 1 && g_mx >= v->f_txt[0] && g_mx <= v->f_txt[1]) {
		v->edit = 500;
		return 1;
	}
	if (g_my == top + 1 && g_mx >= v->f_mode[0] &&
	    g_mx <= v->f_mode[1]) {
		v->find_hex = !v->find_hex;
		/* A regex is over text - see the note in draw_find. */
		if (v->find_hex)
			v->find_regex = 0;
		find_compile(v);
		v->find_at = KGENOME_BROKEN;
		return 1;
	}
	if (g_my == top + 2) {
		if (!v->find_hex && g_mx >= v->f_rx[0] && g_mx <= v->f_rx[1]) {
			v->find_regex = !v->find_regex;
			find_compile(v);
			v->find_at = KGENOME_BROKEN;
		} else if (!v->find_hex && g_mx >= v->f_ic[0] &&
			   g_mx <= v->f_ic[1]) {
			v->find_icase = !v->find_icase;
			v->find_at = KGENOME_BROKEN;
		} else if (g_mx >= v->f_all[0] && g_mx <= v->f_all[1]) {
			v->find_scope = !v->find_scope;
			v->find_at = KGENOME_BROKEN;
		}
		return 1;
	}
	if (g_my == top + 3) {
		if (g_mx >= v->f_cancel[0] && g_mx <= v->f_cancel[1]) {
			v->find_open = 0;
			v->edit = 0;
		} else if (!v->find[0]) {
			;
		} else if (g_mx >= v->f_next[0] && g_mx <= v->f_next[1]) {
			find_run(v, 0);
		} else if (g_mx >= v->f_back[0] && g_mx <= v->f_back[1]) {
			find_run(v, 1);
		}
	}
	return 1;
}
