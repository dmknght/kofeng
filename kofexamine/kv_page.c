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
/* prop_put is declared in kv_shared.h: the families dialog draws its lines the same way. */

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

void prop_put(struct out *o, const char *s, int room, int sa, int sb)
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

/* The box of a page: over the whole screen when `full`, else as wide as its text and as tall as its lines (at
 * most the screen less its margins). The frame's own geometry is kv_dd_fill's. */
static void page_box(struct view *v, struct page *p, struct kv_dd_in *in)
{
	struct kv_dd_geo *g = &p->geo;
	uint32_t k;
	int w = PAGE_MIN_W, maxrows = g_rows - 8;

	(void)v;
	memset(g, 0, sizeof *g);
	for (k = 0; k < p->n; k++) {
		int len = vis_cols(p->line[k].text) + 4;

		if (len > w)
			w = len;
	}
	if (p->full) {
		if (p->width > w)
			w = p->width;
		g->top = 2;
		g->h = g_rows - 3;
	} else {
		int want = (int)p->n > (maxrows < 3 ? 3 : maxrows) ? (maxrows < 3 ? 3 : maxrows) : (int)p->n;

		g->h = want + 4;
		g->top = (g_rows - g->h) / 2 < 2 ? 2 : (g_rows - g->h) / 2;
	}
	g->w = w > g_cols - 4 ? g_cols - 4 : w;
	g->left = (g_cols - g->w) / 2 < 2 ? 2 : (g_cols - g->w) / 2;
	in->dx = p->move ? p->move->dx : 0;
	in->dy = p->move ? p->move->dy : 0;
	kv_dd_place(in, g);
	kv_dd_fill(in, g);
	if (p->move) {
		p->move->dx = g->dx;
		p->move->dy = g->dy;
	}
}

/* The scroll, clamped to what the box shows: the first scrolling line, how many are shown. */
static void page_scroll(struct page *p, uint32_t *fx, uint32_t *body, uint32_t *nb)
{
	int room = p->full ? p->geo.h - 2 : p->geo.h - 4;

	if (room < 1)
		room = 1;
	*fx = p->fixed < p->n ? p->fixed : p->n;
	if (*fx > (uint32_t)room)
		*fx = (uint32_t)room;
	*body = (uint32_t)room - *fx;
	*nb = p->total ? p->total : p->n - *fx;
	*p->off = kv_tab_clamp(*p->off, *nb, *body);
	p->shown = *nb - *p->off < *body ? *nb - *p->off : *body;
}

/* One body row: the walls, then the line (or blanks when the page has nothing there), recorded for selection. */
static void page_row(struct out *o, struct view *v, struct page *p, const struct kv_dd_in *in, int y,
		     uint32_t fx)
{
	struct kv_dd_geo *g = &p->geo;
	char left[64], right[64];
	uint32_t abs = (uint32_t)y < fx ? (uint32_t)y : fx + *p->off + ((uint32_t)y - fx);
	uint32_t at = (uint32_t)y < fx ? (uint32_t)y : fx + (*p->off + ((uint32_t)y - fx) - p->first);
	int live = ((uint32_t)y < fx || (uint32_t)y - fx < p->shown) && at < p->n &&
		   ((uint32_t)y < fx || *p->off + ((uint32_t)y - fx) >= p->first);
	int i;

	kv_dd_walls(in, g, y, left, right, sizeof left);
	out_at(o, g->body_y0 + y, g->left);
	out_str(o, left);
	if (live) {
		prop_put(o, p->line[at].text, g->body_cols, -1, -1);
		if (p->record) {
			char plain[PROP_W];

			prop_plain(p->line[at].text, plain, sizeof plain);
			dlg_rec_text(v, plain);
			dlg_rec_src(v, abs);
		}
	} else {
		for (i = 0; i < g->body_cols; i++)
			out_str(o, " ");
	}
	out_str(o, right);
}

void page_draw(struct out *o, struct view *v, struct page *p)
{
	struct kv_dd_in in;
	struct kv_dd_geo *g = &p->geo;
	char rule[1024], count[48];
	uint32_t fx, body, nb;
	struct out_clip cl;
	int y;

	memset(&in, 0, sizeof in);
	in.cols = g_cols;
	in.rows = g_rows;
	in.title = p->title;
	in.n_tab = p->tab_n;
	in.tab_sel = p->tab_sel;
	memcpy(in.tab, p->tab, sizeof in.tab);
	page_box(v, p, &in);
	if (!g->ok)
		return;
	page_scroll(p, &fx, &body, &nb);
	/* The count is the data layer's (dash_count_text): the dashboard's at the right corner with a unit, the help pages' after the
	 * corner without one, and their hint while everything fits. */
	{
		static const char *const unit[] = { NULL, "lines", "items" };

		dash_count_text(count, sizeof count, unit[p->count_kind], *p->off, p->shown, nb);
		in.count = count;
		if (p->count_kind == PAGE_COUNT_POS) {
			in.count = nb > body ? count : (p->foot ? p->foot : count);
			in.count_left = 1;
		}
	}
	in.act = p->full && v->act_msg[0] ? v->act_msg : NULL;
	in.act_ok = v->act_ok;
	in.fixed = fx;
	in.total = p->count_kind != PAGE_COUNT_POS ? nb : 0u;
	in.off = *p->off;
	in.shown = body;
	kv_dd_fill(&in, g);
	cl = out_clip_set(o, g->top, g->left, g->top + g->h - 1, g->left + g->w - 1);
	out_at(o, g->top, g->left);
	kv_dd_top(&in, g, rule, sizeof rule);
	out_str(o, rule);
	out_at(o, g->top + g->h - 1, g->left);
	kv_dd_bottom(&in, g, rule, sizeof rule);
	out_str(o, rule);
	if (p->record)
		dlg_rec_begin(v, g->body_y0, g->body_x0);
	for (y = 0; y < g->body_rows; y++)
		page_row(o, v, p, &in, y, fx);
	/* The box claims its own rectangle, so a press on it never reaches a pane under it (hit_zone is registered last: hit_at
	 * scans backwards). Both buttons: a right press reaching a pane under a box is the same bug. */
	p->in = in;
	hit_zone(v, g->top, g->left, g->top + g->h - 1, g->left + g->w - 1, (uint8_t)(HIT_L | HIT_R), hit_row_none, 0);
	if (p->record)
		dlg_paint_sel(o, v);
	out_clip_restore(o, cl);
}

/*
 * THE DASHBOARD, placed on the screen. It decides nothing: the dialog's layout (kv_dash_dialog.c) says how big the
 * body is before the page is built, the page builders (kv_props*.c, kv_table.c) produce lines for that size, the
 * strip's labels and the count come from the data layer (kv_dashdata.c), page_draw places it all, and what came
 * back - the dialog's geometry, every table's - is kept in the view for the click, the wheel and the copy.
 */
void draw_prop(struct out *o, struct view *v)
{
	struct kv_dd_in in;
	struct kv_dd_geo g;
	static char lab[KV_DD_TABS][32];
	struct page pg;
	unsigned i;

	memset(&in, 0, sizeof in);
	in.cols = g_cols;
	in.rows = g_rows;
	kv_dd_layout(&in, &g);
	v->prop_room_rows = g.body_rows;
	v->prop_room_cols = g.body_cols;
	prop_build(v);
	v->prop_hoff = kv_tab_clamp(v->prop_hoff, v->prop_hmax, 0u);
	memset(&pg, 0, sizeof pg);
	pg.title = "Properties";
	pg.tab_n = (int)dash_tabs(v, cur_obj(v), lab);
	for (i = 0; i < (unsigned)pg.tab_n; i++)
		pg.tab[i] = lab[i];
	pg.tab_sel = v->prop_inf ? v->prop_pg - PROP_PG_INF_DATA : v->prop_pg;
	pg.line = g_prop;
	pg.n = g_n_prop;
	pg.fixed = v->prop_fixed;
	pg.total = v->prop_total;
	pg.first = v->prop_vfirst;
	pg.off = &v->prop_off;
	pg.full = 1;
	pg.width = g_cols;
	pg.record = 1;
	pg.move = &v->prop_move;
	pg.count_kind = v->prop_total ? PAGE_COUNT_ITEMS : PAGE_COUNT_LINES;
	page_draw(o, v, &pg);
	v->prop_geo = pg.geo;
	v->prop_in = pg.in;
	/* The filter line is the page's first line: a screen row and absolute columns, now that the dialog
	 * has said where its body is. */
	if (v->sy_fy >= 0 && pg.geo.ok) {
		int *box[6] = { &v->sy_fbox[0], &v->sy_fbox[1], &v->sy_ic_box[0], &v->sy_ic_box[1], &v->sy_rx_box[0],
				&v->sy_rx_box[1] };

		v->sy_fy += pg.geo.body_y0;
		for (i = 0; i < 6; i++)
			*box[i] += pg.geo.body_x0;
		prop_filter_over(o, v, pg.geo.top, pg.geo.left, pg.geo.top + pg.geo.h - 1, pg.geo.left + pg.geo.w - 1);
	}
}
