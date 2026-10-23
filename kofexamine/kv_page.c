#define _GNU_SOURCE
#include "kv.h"


/*
 * The page, as a window over the lines.
 *
 * Near full screen on purpose: the sections below the fold are the ones a
 * reader has to go looking for, and a small box would put every section but the
 * first one there.
 *
 * The chrome carries what the chrome is for. Which lines are on screen goes on
 * the bottom rule, where a reader looks for their position in a document; the
 * way out goes top right, where a window's close control is. Neither is a line
 * of the page: a row spent telling you which keys work is a row not spent on
 * the file, and it says the same thing every time you open it.
 */
/*
 * A PAGE OF LINES IN A BOX - the last thing three dialogs were each doing on
 * their own.
 *
 * The properties page, About and Keyboard differ in what they list and in
 * whether the box fills the screen; everything else was written three times.
 * Where the border goes, how the scroll is clamped to what fits, where the
 * close control lands and what a click on it has to compare against, and - for
 * the two that record - which rows the selection layer was told about.
 *
 * It is not in kofview.c with the terminal because the recording lives on the
 * view: dlg_rec_* is how every dialog in this file becomes selectable, and a
 * page that could not record would be a page that copies differently from the
 * symbol table beside it.
 *
 * The caller owns the lines and the offset. This clamps the offset, because
 * how far a page can scroll is a fact about the box and the caller does not
 * know the box until this has drawn it.
 */
/* Narrower than this and the title, the close control and the position on the
 * bottom rule stop fitting on their own rows. */
#define PAGE_MIN_W 60

/* A row without its colour escapes: what the terminal actually shows, which is
 * what a click and a copy are both answered in. */
static uint32_t prop_plain(const char *s, char *out, uint32_t cap);


/* Defined with the properties page, which is where the idiom of a line
 * carrying its own colours comes from; About draws its rows the same way so
 * there is one function that knows how to skip an escape. */
static void prop_put(struct out *o, const char *s, int room, int sa, int sb);

/*
 * One line onto the screen, colours and all.
 *
 * The lines carry their own SGR because the page is a table of different
 * KINDS of fact - a name, an offset, a size - and one colour per row cannot say
 * which is which. printf's "%-.*s" cannot be used on them: it would count the
 * escape bytes as width and cut a line off in the middle of one, so the width
 * is counted here over printable columns only, the same way field_draw does it.
 */
/*
 * One property line without its colours, so it can be copied.
 *
 * The stored line carries the escapes it is painted with, and those are the
 * reason a page full of facts was a page you had to retype: a selection made
 * with the terminal's own mouse takes the box rules and the neighbouring column
 * with it, and the escapes are invisible until they are pasted somewhere.
 *
 * Column for column with prop_put, deliberately - it is the same walk with
 * out_str replaced by a store - so a click at screen column N lands on the
 * character this writes at index N. Two walks that disagreed would put the word
 * under the cursor one place away from the word that gets copied.
 */
/*
 * WHERE ONE VALUE ENDS AND THE NEXT BEGINS ON THIS PAGE.
 *
 * Not whitespace alone. The page is written as key=value pairs packed on one
 * line - "off=624 size=28 vaddr=0x400270 perm=R--" - so a word bounded only by
 * spaces is the whole pair, and clicking the number handed back "size=28" when
 * the number was the point. Breaking on "=" as well makes each half selectable
 * on its own, which is what a reader clicking a number means.
 *
 * The comma is here for the same reason and the colon is NOT: an offset written
 * "0x400270" has no colon, but a name might, and splitting a name is worse than
 * making somebody drag.
 */

static uint32_t prop_plain(const char *s, char *out, uint32_t cap)
{
	uint32_t n = 0;

	while (*s) {
		if (*s == '\033') {
			while (*s && *s != 'm')
				s++;
			if (*s)
				s++;
			continue;
		}
		if (n + 1u < cap)
			out[n++] = *s;
		s++;
	}
	out[n] = 0;
	while (n && out[n - 1u] == ' ')
		out[--n] = 0;
	return n;
}

static void prop_put(struct out *o, const char *s, int room, int sa, int sb)
{
	int n = 0, inv = 0;

	while (*s && n < room) {
		if (*s == '\033') {
			const char *e = s;
			char t[32];
			size_t l;

			while (*e && *e != 'm')
				e++;
			if (*e)
				e++;
			l = (size_t)(e - s);
			if (l < sizeof t) {
				memcpy(t, s, l);
				t[l] = 0;
				out_str(o, t);
			}
			s = e;
			continue;
		}
		{
			char t[8];
			int want = sa >= 0 && n >= sa && n <= sb;
			int len = 1, k;

			/* The reverse is turned on and off around the run
			 * rather than per character: the line carries its own
			 * colours and re-emitting them inside a reversed span
			 * would cancel it halfway. */
			if (want != inv) {
				out_str(o, want ? A_SEL : A_OFF);
				inv = want;
			}
			/*
			 * ONE GLYPH PER COLUMN, not one byte.
			 *
			 * A multi-byte glyph reached the terminal intact even
			 * when written a byte at a time, but each byte counted
			 * against `room` - so a line holding one was padded two
			 * columns short and stopped before the border. The
			 * length comes from the lead byte, and a sequence cut
			 * off by the end of the string stops there rather than
			 * reading past it. See vis_cols, which has to agree
			 * with this or the box and its contents are measured
			 * differently.
			 */
			if (((unsigned char)*s & 0xe0u) == 0xc0u)
				len = 2;
			else if (((unsigned char)*s & 0xf0u) == 0xe0u)
				len = 3;
			else if (((unsigned char)*s & 0xf8u) == 0xf0u)
				len = 4;
			for (k = 0; k < len && s[k]; k++)
				t[k] = s[k];
			t[k] = 0;
			s += k;
			out_str(o, t);
			n++;
		}
	}
	out_str(o, A_OFF);
	while (n++ < room)
		out_str(o, " ");
}

void page_draw(struct out *o, struct view *v, struct page *p)
{
	static const char close[] = "[ Close ]";
	struct out_clip cl;
	int room, inner, y, i, title_used = 0;
	uint32_t k, fx, body, nb;
	char pos[48];

	p->btn_y = -1;
	p->tab_y = -1;
	if (p->full) {
		/*
		 * FULL HEIGHT, BUT ONLY AS WIDE AS IT HAS ANYTHING TO SAY.
		 *
		 * The page is a column of label/value rows about a hundred
		 * columns wide at most; on a wide terminal the rest was empty
		 * box - half a screen of border round nothing, which reads as
		 * a page that failed to fill itself rather than as a page that
		 * is this wide. The height still fills, because the whole
		 * point of `full` is that the sections below the fold are the
		 * ones a reader has to go looking for.
		 */
		p->top = 2;
		p->w = PAGE_MIN_W;
		for (k = 0; k < p->n; k++) {
			int len = vis_cols(p->line[k].text) + 4;

			if (len > p->w)
				p->w = len;
		}
		if (p->width > p->w)
			p->w = p->width;
		if (p->w > g_cols - 4)
			p->w = g_cols - 4;
		/* Centred, now that it is not the width of the screen: a box
		 * pinned to the left with a screen's worth of gap on the right
		 * reads as a box that failed to fill rather than one that is
		 * this wide. */
		p->left = (g_cols - p->w) / 2;
		if (p->left < 2)
			p->left = 2;
		p->h = g_rows - 3;
	} else {
		int maxrows = g_rows - 8, want;

		if (maxrows < 3)
			maxrows = 3;
		p->w = PAGE_MIN_W;
		for (k = 0; k < p->n; k++) {
			int len = vis_cols(p->line[k].text) + 4;

			if (len > p->w)
				p->w = len;
		}
		if (p->w > g_cols - 4)
			p->w = g_cols - 4;
		want = (int)p->n > maxrows ? maxrows : (int)p->n;
		p->h = want + 4;
		p->top = (g_rows - p->h) / 2;
		p->left = (g_cols - p->w) / 2;
		if (p->top < 2)
			p->top = 2;
		if (p->left < 2)
			p->left = 2;
	}
	if (p->w < 30 || p->h < 6)
		return;                 /* no room to draw a box honestly */

	/* Everything from here down is inside the box, which is now stated
	 * once rather than trusted to each row's own width arithmetic. */
	cl = out_clip_set(o, p->top, p->left, p->top + p->h - 1,
			  p->left + p->w - 1);

	room = p->full ? p->h - 2 : p->h - 4;
	if (room < 1)
		room = 1;
	inner = p->w - 4;
	/* The lines that do not scroll take their rows first; what scrolls is
	 * the rest, in what is left. */
	fx = p->fixed < p->n ? p->fixed : p->n;
	if (fx > (uint32_t)room)
		fx = (uint32_t)room;
	body = (uint32_t)room - fx;
	nb = p->n - fx;
	if (nb > body) {
		if (*p->off > nb - body)
			*p->off = nb - body;
	} else {
		*p->off = 0;
	}
	p->shown = nb - *p->off;
	if (p->shown > body)
		p->shown = body;

	/*
	 * THE TOP RULE, COUNTED RATHER THAN GUESSED.
	 *
	 * The row is: corner, one rule, a space, the title, a space, the fill,
	 * then either the close control or one more rule, then the corner. Every
	 * one of those is a column, and the fill is what is left - which is why
	 * it is written as a subtraction of named pieces rather than as a number
	 * somebody counted once. A rule one short draws a box narrower at the
	 * top than at every row below it, and the step is visible.
	 */
	out_at(o, p->top, p->left);
	out_str(o, A_DIM);
	out_glyph(o, G_TL);
	out_glyph(o, G_H);
	/*
	 * THE TABS, OR THE TITLE - never both. `used` counts what the title
	 * row has spent so that the fill below is a subtraction of things
	 * that were actually drawn, which is the same discipline the single
	 * title uses and the reason that one is right.
	 */
	if (p->tab_n > 0) {
		int ti;

		p->tab_y = p->top;
		for (ti = 0; ti < p->tab_n && ti < 2; ti++) {
			int len = (int)strlen(p->tab[ti]);

			if (ti) {
				out_glyph(o, G_H);
				title_used += 1;
			}
			p->tab_x0[ti] = p->left + 2 + title_used;
			p->tab_x1[ti] = p->tab_x0[ti] + len + 1;
			out_str(o, A_OFF);
			out_str(o, ti == p->tab_sel ? "\033[7m" : A_DIM);
			out_fmt(o, " %s ", p->tab[ti]);
			out_str(o, A_OFF A_DIM);
			title_used += len + 2;
		}
	} else {
		out_fmt(o, A_OFF A_BOLD " %s " A_OFF A_DIM, p->title);
		title_used = (int)strlen(p->title) + 2;
	}
	if (p->close) {
		/* corner + rule + " title " + fill + " " + close + rule + corner */
		int fill = p->w - 1 - 1 - title_used -
			   (1 + (int)sizeof close - 1) - 1 - 1;

		p->btn_y = p->top;
		p->btn_x0 = p->left + p->w - 2 - ((int)sizeof close - 1);
		p->btn_x1 = p->btn_x0 + (int)sizeof close - 2;
		for (i = 0; i < fill; i++)
			out_glyph(o, G_H);
		out_str(o, " " A_OFF);
		out_str(o, "\033[47;30m");
		out_str(o, close);
		out_str(o, A_OFF A_DIM);
		out_glyph(o, G_H);
		out_glyph(o, G_TR);
		out_str(o, A_OFF);
	} else {
		int fill = p->w - 1 - 1 - title_used - 1;

		for (i = 0; i < fill; i++)
			out_glyph(o, G_H);
		out_glyph(o, G_TR);
		out_str(o, A_OFF);
	}

	/*
	 * The bottom rule: where in the page this window is, and whatever the
	 * caller wants said beside it.
	 *
	 * The note is HERE and not in the status bar, and that is forced rather
	 * than chosen: while a full-screen page is up the rows under it are not
	 * repainted - see `under` in redraw() - so a message written to the
	 * status line would not appear until the page was closed, by which time
	 * it is about something the reader can no longer see.
	 */
	snprintf(pos, sizeof pos, "%u-%u of %u", *p->off + 1u,
		 *p->off + p->shown, nb);
	{
		const char *foot = nb > body
				 ? pos : (p->foot ? p->foot : pos);
		int used;

		out_at(o, p->top + p->h - 1, p->left);
		out_str(o, A_DIM);
		out_glyph(o, G_BL);
		out_glyph(o, G_H);
		out_fmt(o, " %s ", foot);
		used = 1 + 1 + (int)strlen(foot) + 2;
		if (p->full && v->act_msg[0]) {
			int fit = p->w - used - 2;

			if (fit > 12) {
				out_fmt(o, A_OFF "%s%.*s" A_OFF A_DIM " ",
					v->act_ok ? A_SIZE : A_WARN, fit,
					v->act_msg);
				used += ((int)strlen(v->act_msg) > fit
					 ? fit : (int)strlen(v->act_msg)) + 1;
			}
		}
		for (i = used; i < p->w - 1; i++)
			out_glyph(o, G_H);
		out_glyph(o, G_BR);
		out_str(o, A_OFF);
	}

	/*
	 * One pass per row: the left rule, the line, the right rule.
	 *
	 * It used to blank every interior row and then draw the content over
	 * the blanks, which painted the whole box twice per frame for no
	 * visible difference - and the frame is the thing that has to stay
	 * small, because a large one is what tears.
	 */
	if (p->record)
		dlg_rec_begin(v, p->top + 1, p->left + 2);
	for (y = 0; y < p->h - 2; y++) {
		out_at(o, p->top + 1 + y, p->left);
		out_str(o, A_DIM);
		out_glyph(o, G_V);
		out_str(o, A_OFF " ");
		if ((uint32_t)y < fx ||
		    (uint32_t)y - fx < p->shown) {
			uint32_t idx = (uint32_t)y < fx
				       ? (uint32_t)y
				       : fx + *p->off + ((uint32_t)y - fx);

			prop_put(o, p->line[idx].text, inner, -1, -1);
			if (p->record) {
				char plain[PROP_W];

				prop_plain(p->line[idx].text, plain,
					   sizeof plain);
				dlg_rec_text(v, plain);
				dlg_rec_src(v, idx);
			}
		} else {
			for (i = 0; i < inner; i++)
				out_str(o, " ");
		}
		out_str(o, " " A_DIM);
		out_glyph(o, G_V);
		out_str(o, A_OFF);
	}
	/*
	 * AND THE BOX CLAIMS ITS OWN RECTANGLE, the way every control here
	 * claims its row.
	 *
	 * A page is drawn OVER the declaration panel, and a click on one of
	 * its rows was reaching whatever the panel had at that column: the
	 * panel changed height, the next frame laid the box out against the
	 * new height, and what the old box had drawn outside the new one
	 * stayed on the screen. That is the "row of the panel inside the
	 * dialog" this looked like, and it was one click away at any time.
	 *
	 * hit_row_none is the declaration that does nothing: the rectangle is
	 * registered LAST, so hit_at - which scans backwards - finds it before
	 * the panel's rows, and hit_run stops the chain there. Both buttons,
	 * because a right-click reaching a pane under a box is the same bug.
	 */
	hit_zone(v, p->top, p->left, p->top + p->h - 1, p->left + p->w - 1,
		 (uint8_t)(HIT_L | HIT_R), hit_row_none, 0);
	/* Last, so the selection is over everything the box drew. */
	if (p->record)
		dlg_paint_sel(o, v);
	out_clip_restore(o, cl);
}

void draw_prop(struct out *o, struct view *v)
{
	struct page pg;

	prop_build(v);
	memset(&pg, 0, sizeof pg);
	pg.title = "Properties";
	pg.line = g_prop;
	pg.n = g_n_prop;
	pg.off = &v->prop_off;
	pg.full = 1;
	pg.close = 1;
	pg.record = 1;
	page_draw(o, v, &pg);
	v->prop_y = pg.btn_y;
	v->prop_x0 = pg.btn_x0;
	v->prop_x1 = pg.btn_x1;
}
