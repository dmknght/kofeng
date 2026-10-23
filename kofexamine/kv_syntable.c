#define _GNU_SOURCE
#include "kv.h"

/*
 * kv_syntable.c - the Syndrome table on the screen: the page and the boxes over
 * it, the mouse and the keys. The model is kv_syn.c's.
 *
 * Every box is a page of lines (page_draw, the renderer the properties page and
 * both Help boxes use) and every line is built with the spans a click can land
 * on recorded beside it, so what is drawn and what answers are one walk. A text
 * box is the line's own text while it is not focused and the program's one
 * field editor (field_draw, field_key) painted over it while it is.
 */

#define SEARCH_COL  8           /* " Search " */
#define SEARCH_W    24
#define HEAD_ROWS   3u          /* tabs, search and buttons, column names */
#define PICK_HEAD   2u          /* search and buttons, column names */

/* A text box or a list of names in the form: as wide as the screen leaves it
 * once the buttons beside it are counted, at most 36. */
static int form_w(void)
{
	int w = g_cols - 52;

	return w < 20 ? 20 : w > 36 ? 36 : w;
}

static const char *const tab_word[SYN_TABS] = {
	"Activities", "Types", "Families", "Tags"
};

static const char *const head_act[] = { "Name", "Used", "Comment" };
static const char *const head_typ[] = { "Name", "Used" };
static const char *const head_tag[] = {
	"Name", "Activities", "Types", "Family", "Formats/Arch/Subtype",
	"Used", "Comment"
};

static const char *const *const heads[SYN_TABS] = {
	head_act, head_typ, head_typ, head_tag
};
static const int n_heads[SYN_TABS] = { 3, 2, 2, 7 };
/* How wide a column may be before the box is narrower than the table. */
static const int cap_act[] = { 28, 5, 60 };
static const int cap_typ[] = { 28, 5 };
static const int cap_tag[] = { 24, 24, 24, 14, 44, 5, 60 };
static const int *const caps[SYN_TABS] = { cap_act, cap_typ, cap_typ, cap_tag };

/* ---- the shared title bar ------------------------------------------------ */

size_t tabbar_text(char *out, size_t cap, const char *const *word, uint32_t n,
		   uint32_t active, int *c0, int *c1)
{
	size_t at = 0;
	int col = 1;
	uint32_t t;

	at += (size_t)snprintf(out + at, cap - at, A_HEAD " " A_OFF);
	for (t = 0; t < n && at + 1u < cap; t++) {
		if (t) {
			at += (size_t)snprintf(out + at, cap - at,
					       A_DIM " | " A_OFF);
			col += 3;
		}
		c0[t] = col + 1;
		at += (size_t)snprintf(out + at, cap - at, "%s %s " A_OFF,
				       t == active ? A_SEL : A_ID, word[t]);
		col += (int)strlen(word[t]) + 2;
		c1[t] = col;
	}
	return at < cap ? at : cap - 1u;
}

/* ---- a cell of a table --------------------------------------------------- */

/* `src` into `w` columns: cut with a mark when it is longer, padded when not;
 * a byte that is not plain ASCII is a "?" so the width is the byte count. */
static void cell_put(char *dst, size_t cap, const char *src, int w)
{
	int i, n = (int)strlen(src);
	int cut = n > w;

	if ((size_t)w + 1u > cap)
		w = (int)cap - 1;
	for (i = 0; i < w; i++) {
		unsigned char c = i < n ? (unsigned char)src[i] : ' ';

		dst[i] = c >= 0x20 && c < 0x7f ? (char)c : '?';
	}
	if (cut && w > 0)
		dst[w - 1] = '~';
	dst[w] = 0;
}

/* Narrow the widest columns until the row fits `avail`, none past its floor. */
static void fit_cols(int *w, const int *floor, int n, int avail)
{
	for (;;) {
		int total = 2 * (n - 1), i, best = -1;

		for (i = 0; i < n; i++) {
			total += w[i];
			if (w[i] > floor[i] && (best < 0 || w[i] > w[best]))
				best = i;
		}
		if (total <= avail || best < 0)
			return;
		w[best]--;
	}
}

/* ---- the table page ------------------------------------------------------ */

static void page_buttons(struct syn_layer *ly, uint32_t li)
{
	static const struct { const char *w; int act; } b[] = {
		{ "[Add]", SYA_ADD }, { "[Edit]", SYA_EDIT },
		{ "[Delete]", SYA_DEL }, { "[Check]", SYA_CHECK },
		{ "[Save]", SYA_SAVE }
	};
	unsigned i;

	for (i = 0; i < sizeof b / sizeof b[0]; i++) {
		int c0 = syn_ly_col(ly, li);

		syn_ly_put(ly, li, A_ID, b[i].w);
		syn_ly_hit(ly, li, c0, syn_ly_col(ly, li) - 1, b[i].act, 0);
		syn_ly_put(ly, li, "", " ");
	}
}

/* The search box as a line holds it: the text, or what the box is for. */
static void search_cell(struct syn_layer *ly, uint32_t li, const char *text,
			int editing)
{
	char t[SEARCH_W + 1];

	cell_put(t, sizeof t, text[0] || editing ? text : "name, type...",
		 SEARCH_W);
	syn_ly_put(ly, li, text[0] ? A_ID : A_DIM, t);
	syn_ly_hit(ly, li, SEARCH_COL, SEARCH_COL + SEARCH_W - 1, SYA_SEARCH, 0);
}

static void page_rows(struct view *v, struct syn_layer *ly, const int *w)
{
	struct kv_syn *s = v->syn;
	uint32_t r;
	int c, nc = n_heads[s->tab];

	for (r = 0; r < s->n_rows; r++) {
		const struct kof_tagent *e = &s->set.e[s->rows[r]];
		char cell[7][160], t[PROP_W - 16], one[160];
		size_t at = 0;
		uint32_t li = syn_ly_line(ly);

		syn_row_cells(s, e, s->tab, cell);
		at += (size_t)snprintf(t, sizeof t, "%s",
				       !e->dirty ? "  " : e->fresh ? "+ "
								  : "* ");
		for (c = 0; c < nc && at + 1u < sizeof t; c++) {
			cell_put(one, sizeof one, cell[c], w[c]);
			at += (size_t)snprintf(t + at, sizeof t - at, "%s  ",
					       one);
		}
		syn_ly_put(ly, li, r == s->sel[s->tab] ? A_SEL : "", t);
		syn_ly_hit(ly, li, 0, 400, SYA_ROW, r);
	}
	if (!s->n_rows) {
		uint32_t li = syn_ly_line(ly);

		syn_ly_put(ly, li, A_DIM, s->filt[0]
			   ? "  nothing matches the search"
			   : "  nothing here yet - [Add] makes one");
	}
}

static void build_page(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_layer *ly = &s->page;
	int w[7] = { 0 }, fl[7] = { 0 }, c, nc = n_heads[s->tab];
	int avail = g_cols - 10;
	char bar[PROP_W], head[PROP_W], one[160];
	int c0[SYN_TABS], c1[SYN_TABS];
	uint32_t li, r, t;
	size_t at = 0;

	syn_ly_reset(ly);
	ly->fixed = HEAD_ROWS;
	li = syn_ly_line(ly);
	tabbar_text(bar, sizeof bar, tab_word, SYN_TABS, (uint32_t)s->tab, c0,
		    c1);
	syn_ly_put(ly, li, "", bar);
	for (t = 0; t < SYN_TABS; t++)
		syn_ly_hit(ly, li, c0[t] - 1, c1[t] - 1, SYA_TAB, t);

	li = syn_ly_line(ly);
	syn_ly_put(ly, li, A_DIM, " Search ");
	search_cell(ly, li, s->filt, v->edit == ED_SYN_SEARCH);
	syn_ly_put(ly, li, "", "   ");
	page_buttons(ly, li);

	for (c = 0; c < nc; c++)
		w[c] = (int)strlen(heads[s->tab][c]);
	for (r = 0; r < s->n_rows; r++) {
		char cell[7][160];

		syn_row_cells(s, &s->set.e[s->rows[r]], s->tab, cell);
		for (c = 0; c < nc; c++) {
			int l = (int)strlen(cell[c]);

			l = l > caps[s->tab][c] ? caps[s->tab][c] : l;
			if (l > w[c])
				w[c] = l;
		}
	}
	/* The comment, the last column, gives way first; only when that is not
	 * enough do the others, each to a floor of a few columns. */
	for (c = 0; c < nc; c++)
		fl[c] = c == nc - 1 ? 8 : w[c];
	fit_cols(w, fl, nc, avail);
	for (c = 0; c < nc; c++)
		fl[c] = w[c] < 8 ? w[c] : 8;
	fit_cols(w, fl, nc, avail);
	li = syn_ly_line(ly);
	at += (size_t)snprintf(head, sizeof head, "  ");
	for (c = 0; c < nc && at + 1u < sizeof head; c++) {
		cell_put(one, sizeof one, heads[s->tab][c], w[c]);
		at += (size_t)snprintf(head + at, sizeof head - at, "%s  ", one);
	}
	syn_ly_put(ly, li, A_DIM, head);
	page_rows(v, ly, w);
}

/* ---- the form ------------------------------------------------------------ */

static void field_line(struct syn_layer *ly, uint32_t li, const char *label,
		       const char *text, int code)
{
	char t[40];
	int c0;

	syn_ly_put(ly, li, A_DIM, label);
	c0 = syn_ly_col(ly, li);
	cell_put(t, sizeof t, text, form_w());
	syn_ly_put(ly, li, A_ID, t);
	syn_ly_hit(ly, li, c0, c0 + form_w() - 1, SYA_FIELD, (uint32_t)code);
}

static void button(struct syn_layer *ly, uint32_t li, const char *w, int act,
		   uint32_t arg)
{
	int c0 = syn_ly_col(ly, li);

	syn_ly_put(ly, li, A_ID, w);
	syn_ly_hit(ly, li, c0, syn_ly_col(ly, li) - 1, act, arg);
	syn_ly_put(ly, li, "", "  ");
}

/* A line of the tag form that names entities: the names, a button that
 * chooses them and, for the three kinds a tag refers to, one that makes a new
 * one. */
static void ref_line(struct kv_syn *s, struct syn_layer *ly, const char *label,
		     const char *names, int pick, int new_kind,
		     const char *new_word)
{
	uint32_t li = syn_ly_line(ly);
	char t[40];

	syn_ly_put(ly, li, A_DIM, label);
	cell_put(t, sizeof t, names[0] ? names : "-", form_w());
	syn_ly_put(ly, li, names[0] ? A_ID : A_DIM, t);
	syn_ly_put(ly, li, "", " ");
	button(ly, li, "[Select]", SYA_PICK, (uint32_t)pick);
	if (new_kind && !s->has_parent)
		button(ly, li, new_word, SYA_NEW, (uint32_t)new_kind);
}

static void attr_names(const struct kof_tagent *e, unsigned cls, char *out,
		       size_t cap)
{
	size_t at = 0;
	unsigned i;

	out[0] = 0;
	for (i = 0; i < e->n_attr[cls] && at + 2u < cap; i++)
		at += (size_t)snprintf(out + at, cap - at, "%s%s", i ? ", " : "",
				       kof_tagsrc_vocab_word(cls,
							     e->attr[cls][i]));
}

static void build_form(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_form *f = &s->form;
	struct syn_layer *ly = &s->frm;
	char names[300];
	uint32_t li;

	syn_ly_reset(ly);
	field_line(ly, syn_ly_line(ly), " Name        ", f->name, ED_SYN_NAME);
	if (f->kind == KOF_TAGSRC_K_TAG) {
		const char *fam = f->e.has_fam
			? kof_tagset_name(&s->set, KOF_TAGSRC_K_FAMILY, f->e.fam)
			: NULL;

		kof_tagset_join(&s->set, KOF_TAGSRC_K_ACTIVITY, f->e.act,
				f->e.n_act, names, sizeof names);
		ref_line(s, ly, " Activities  ", names, PK_ACT,
			 KOF_TAGSRC_K_ACTIVITY, "[+ New activity]");
		kof_tagset_join(&s->set, KOF_TAGSRC_K_TYPE, f->e.typ, f->e.n_typ,
				names, sizeof names);
		ref_line(s, ly, " Types       ", names, PK_TYP,
			 KOF_TAGSRC_K_TYPE, "[+ New type]");
		ref_line(s, ly, " Family      ", f->e.has_fam ? (fam ? fam : "?")
							     : "", PK_FAM,
			 KOF_TAGSRC_K_FAMILY, "[+ New family]");
		attr_names(&f->e, KOF_TAGSRC_A_FORMAT, names, sizeof names);
		ref_line(s, ly, " Formats     ", names, PK_FMT, 0, "");
		attr_names(&f->e, KOF_TAGSRC_A_ARCH, names, sizeof names);
		ref_line(s, ly, " Arch        ", names, PK_ARCH, 0, "");
		attr_names(&f->e, KOF_TAGSRC_A_SUBTYPE, names, sizeof names);
		ref_line(s, ly, " Subtypes    ", names, PK_SUB, 0, "");
	}
	if (f->kind == KOF_TAGSRC_K_TAG || f->kind == KOF_TAGSRC_K_ACTIVITY)
		field_line(ly, syn_ly_line(ly), " Comment     ", f->cmt,
			   ED_SYN_COMMENT);
	syn_ly_line(ly);
	li = syn_ly_line(ly);
	syn_ly_put(ly, li, "", " ");
	button(ly, li, "[ OK ]", SYA_OK, 0);
	button(ly, li, "[ Cancel ]", SYA_CANCEL, 0);
	if (f->err[0]) {
		li = syn_ly_line(ly);
		syn_ly_put(ly, li, A_BAD, " ");
		syn_ly_put(ly, li, A_BAD, f->err);
	}
}

/* ---- the pick list ------------------------------------------------------- */

static void build_pick(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_pick *p = &s->pick;
	struct syn_layer *ly = &p->ly;
	int w[4] = { 4, 0, 0, 0 }, fl[4] = { 6, 6, 6, 6 }, c;
	char head[PROP_W], one[160];
	uint32_t li, i;
	size_t at = 0;

	syn_pick_vis(v);
	syn_ly_reset(ly);
	ly->fixed = PICK_HEAD;
	li = syn_ly_line(ly);
	syn_ly_put(ly, li, A_DIM, " Search ");
	search_cell(ly, li, p->filt, v->edit == ED_SYN_PICK);
	syn_ly_put(ly, li, "", "   ");
	if (p->multi)
		button(ly, li, "[ OK ]", SYA_OK, 0);
	button(ly, li, "[ Cancel ]", SYA_CANCEL, 0);
	for (c = 0; c < p->ncol; c++)
		w[c] = (int)strlen(p->head[c]);
	for (i = 0; i < p->n_vis; i++)
		for (c = 0; c < p->ncol; c++) {
			int l = (int)strlen(p->row[p->vis[i]].col[c]);

			l = l > 40 ? 40 : l;
			if (l > w[c])
				w[c] = l;
		}
	fit_cols(w, fl, p->ncol, g_cols - 16);
	li = syn_ly_line(ly);
	at += (size_t)snprintf(head, sizeof head, "    ");
	for (c = 0; c < p->ncol; c++) {
		cell_put(one, sizeof one, p->head[c], w[c]);
		at += (size_t)snprintf(head + at, sizeof head - at, "%s  ", one);
	}
	syn_ly_put(ly, li, A_DIM, head);
	for (i = 0; i < p->n_vis; i++) {
		const struct syn_prow *pr = &p->row[p->vis[i]];
		char t[PROP_W - 16];

		li = syn_ly_line(ly);
		at = (size_t)snprintf(t, sizeof t, "%s",
				      !p->multi ? "    "
				      : pr->pos ? "[x] " : "[ ] ");
		for (c = 0; c < p->ncol && at + 1u < sizeof t; c++) {
			cell_put(one, sizeof one, pr->col[c], w[c]);
			at += (size_t)snprintf(t + at, sizeof t - at, "%s  ",
					       one);
		}
		syn_ly_put(ly, li, i == p->sel ? A_SEL : "", t);
		syn_ly_hit(ly, li, 0, 400, SYA_PROW, i);
	}
	if (!p->n_real) {
		li = syn_ly_line(ly);
		syn_ly_put(ly, li, A_DIM, "    nothing matches the search");
	}
}

/* ---- drawing a layer ----------------------------------------------------- */

static void layer_draw(struct out *o, struct view *v, struct syn_layer *ly,
		       const char *title, int full, const char *foot)
{
	struct page pg;

	if (!ly->n)
		syn_ly_line(ly);
	memset(&pg, 0, sizeof pg);
	pg.title = title;
	pg.line = ly->line;
	pg.n = ly->n;
	pg.fixed = ly->fixed;
	pg.off = &ly->off;
	pg.full = full;
	pg.width = full ? g_cols : 0;
	pg.close = 1;
	pg.foot = foot;
	page_draw(o, v, &pg);
	ly->top = pg.top;
	ly->left = pg.left;
	ly->w = pg.w;
	ly->h = pg.h;
	ly->shown = pg.shown;
	ly->btn_y = pg.btn_y;
	ly->btn_x0 = pg.btn_x0;
	ly->btn_x1 = pg.btn_x1;
}

/* The screen row of a line of a layer, or 0 when it is scrolled out. */
static int line_row(const struct syn_layer *ly, uint32_t li)
{
	if (li < ly->fixed)
		return ly->top + 1 + (int)li;
	if (li < ly->fixed + ly->off || li >= ly->fixed + ly->off + ly->shown)
		return 0;
	return ly->top + 1 + (int)ly->fixed + (int)(li - ly->fixed - ly->off);
}

/* The text box that has the focus, painted over the line that holds it. */
static void field_over(struct out *o, struct view *v,
		       const struct syn_layer *ly, uint32_t li, int col,
		       int room, char *text, uint32_t *off, int code,
		       const char *ph)
{
	int y = line_row(ly, li);

	if (v->edit != code || !y)
		return;
	out_at(o, y, ly->left + 2 + col);
	o->col_hint = 0;
	out_str(o, A_SEL);
	field_draw(o, text, v->caret, off, room, 1, ph);
	out_str(o, A_OFF);
}

static void draw_page(struct out *o, struct view *v)
{
	struct kv_syn *s = v->syn;
	char foot[96];

	build_page(v);
	snprintf(foot, sizeof foot, "%u shown, %u changed", s->n_rows,
		 syn_dirty(s));
	layer_draw(o, v, &s->page, "Syndrome table", 1, foot);
	field_over(o, v, &s->page, 1, SEARCH_COL, SEARCH_W, s->filt, &s->foff,
		   ED_SYN_SEARCH, "name, type...");
}

static void draw_form(struct out *o, struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_form *f = &s->form;
	char title[48];

	build_form(v);
	snprintf(title, sizeof title, "%s %s", f->edit ? "Edit" : "Add",
		 kof_tagsrc_kind_word(f->kind));
	layer_draw(o, v, &s->frm, title, 0,
		   "Tab next field  Enter OK  Esc cancels");
	field_over(o, v, &s->frm, 0, 13, form_w(), f->name, &f->name_off,
		   ED_SYN_NAME, "");
	if (f->kind == KOF_TAGSRC_K_TAG || f->kind == KOF_TAGSRC_K_ACTIVITY)
		field_over(o, v, &s->frm, s->frm.n - (f->err[0] ? 4u : 3u), 13,
			   form_w(), f->cmt, &f->cmt_off, ED_SYN_COMMENT, "");
}

static void draw_pick(struct out *o, struct view *v)
{
	struct syn_pick *p = &v->syn->pick;

	build_pick(v);
	layer_draw(o, v, &p->ly, p->title, 0, p->multi
		   ? "Enter ticks  Tab applies  Esc cancels"
		   : "Enter picks  Esc cancels");
	field_over(o, v, &p->ly, 0, SEARCH_COL, SEARCH_W, p->filt, &p->foff,
		   ED_SYN_PICK, "name, type...");
}

void draw_syn(struct out *o, struct view *v)
{
	struct kv_syn *s = v->syn;

	if (s->open)
		draw_page(o, v);
	if (s->form.open)
		draw_form(o, v);
	if (s->res_open)
		layer_draw(o, v, &s->res, s->res_title, 0, "Esc closes");
	if (s->pick.open)
		draw_pick(o, v);
}

/* ---- the mouse ----------------------------------------------------------- */

/* The topmost layer, which owns every click. */
static struct syn_layer *top_layer(struct kv_syn *s)
{
	if (s->pick.open)
		return &s->pick.ly;
	if (s->res_open)
		return &s->res;
	if (s->form.open)
		return &s->frm;
	return &s->page;
}

/* The span under the pointer on a layer, or NULL. Last recorded wins. */
static const struct syn_hit *hit_under(const struct syn_layer *ly)
{
	int r = g_my - (ly->top + 1), col = g_mx - (ly->left + 2);
	uint32_t li, i;

	if (r < 0 || r >= ly->h - 2 || col < 0)
		return NULL;
	if ((uint32_t)r < ly->fixed) {
		li = (uint32_t)r;
	} else {
		uint32_t k = (uint32_t)r - ly->fixed;

		if (k >= ly->shown)
			return NULL;
		li = ly->fixed + ly->off + k;
	}
	for (i = ly->nh; i--;)
		if (ly->hit[i].line == li && col >= ly->hit[i].c0 &&
		    col <= ly->hit[i].c1)
			return &ly->hit[i];
	return NULL;
}

static void focus(struct view *v, int code)
{
	v->edit = code;
	v->edit_prev = 0;
}

static void click_page(struct view *v, const struct syn_hit *h)
{
	struct kv_syn *s = v->syn;

	switch (h->act) {
	case SYA_TAB:    syn_tab_set(v, (int)h->arg); break;
	case SYA_ROW:    s->sel[s->tab] = h->arg; v->edit = 0; break;
	case SYA_SEARCH: focus(v, ED_SYN_SEARCH); break;
	case SYA_ADD:    syn_form_open(v, 0, 0); break;
	case SYA_EDIT:   syn_form_open(v, 0, 1); break;
	case SYA_DEL:    syn_delete(v); break;
	case SYA_CHECK:  syn_check(v); break;
	case SYA_SAVE:   syn_save(v); break;
	default: break;
	}
}

static void click_form(struct view *v, const struct syn_hit *h)
{
	switch (h->act) {
	case SYA_FIELD:  focus(v, (int)h->arg); break;
	case SYA_OK:     syn_form_ok(v); break;
	case SYA_CANCEL: syn_form_cancel(v); break;
	case SYA_PICK:   syn_form_pick(v, (int)h->arg); break;
	case SYA_NEW:    syn_form_new(v, (int)h->arg); break;
	default: break;
	}
}

static void click_pick(struct view *v, const struct syn_hit *h)
{
	switch (h->act) {
	case SYA_SEARCH: focus(v, ED_SYN_PICK); break;
	case SYA_OK:     syn_pick_ok(v); break;
	case SYA_CANCEL: syn_pick_cancel(v); break;
	case SYA_PROW:   syn_pick_toggle(v, h->arg); break;
	default: break;
	}
}

/* The close control of a layer is its way out: Cancel for the two that ask
 * something, away for the page and the result. */
static void close_layer(struct view *v)
{
	struct kv_syn *s = v->syn;

	if (s->pick.open)
		syn_pick_cancel(v);
	else if (s->res_open)
		s->res_open = 0;
	else if (s->form.open)
		syn_form_cancel(v);
	else
		syn_close(v);
}

int syn_click(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_layer *ly;
	const struct syn_hit *h;

	if (!syn_modal(v))
		return 0;
	ly = top_layer(s);
	if (ly->btn_y == g_my && g_mx >= ly->btn_x0 && g_mx <= ly->btn_x1) {
		close_layer(v);
		return 1;
	}
	h = hit_under(ly);
	if (!h)
		return 1;
	if (s->pick.open)
		click_pick(v, h);
	else if (s->form.open && !s->res_open)
		click_form(v, h);
	else if (!s->res_open)
		click_page(v, h);
	if (s->open && !s->pick.open && !s->form.open)
		syn_rows(v);
	return 1;
}

/* ---- the keys ------------------------------------------------------------ */

/* A name takes lower case and a hyphen, and what is typed is made one. */
static int name_accept(int c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

static int name_key(struct view *v, char *buf, size_t cap, int k)
{
	char t[KOF_TAGSRC_NAME_LEN];
	int r;

	if (k >= 'A' && k <= 'Z')
		k += 32;
	else if (k == ' ' || k == '_')
		k = '-';
	r = field_key(v, buf, cap, k, name_accept);
	/* A paste brings whatever it holds: the box ends up a name regardless. */
	kof_tagsrc_name_norm(t, sizeof t, buf);
	snprintf(buf, cap, "%s", t);
	if (v->caret > strlen(buf))
		v->caret = (uint32_t)strlen(buf);
	return r;
}

static int printable(int k)
{
	return k >= 0x20 && k < 0x7f;
}

/* Keep the cursor row on the screen. */
static void follow(uint32_t sel, uint32_t *off, uint32_t body)
{
	if (!body)
		return;
	if (sel < *off)
		*off = sel;
	else if (sel >= *off + body)
		*off = sel - body + 1u;
}

static void move(uint32_t *sel, uint32_t n, int k, uint32_t pg)
{
	uint32_t last = n ? n - 1u : 0u;

	switch (k) {
	case K_UP:   if (*sel) (*sel)--; break;
	case K_DOWN: if (*sel < last) (*sel)++; break;
	case K_PGUP: *sel = *sel > pg ? *sel - pg : 0u; break;
	case K_PGDN: *sel = *sel + pg < last ? *sel + pg : last; break;
	case K_HOME: *sel = 0; break;
	case K_END:  *sel = last; break;
	default: break;
	}
}

static int is_move(int k)
{
	return k == K_UP || k == K_DOWN || k == K_PGUP || k == K_PGDN ||
	       k == K_HOME || k == K_END;
}

static int key_page(struct view *v, int k)
{
	struct kv_syn *s = v->syn;
	uint32_t body = g_rows > 8 ? (uint32_t)g_rows - 8u : 1u;

	if (v->edit == ED_SYN_SEARCH && !is_move(k)) {
		if (k == 27) {
			v->edit = 0;
			return 1;
		}
		if (k == '\t' || k == K_BACKTAB)
			return 1;
		field_key(v, s->filt, sizeof s->filt, k, NULL);
		s->sel[s->tab] = 0;
		s->page.off = 0;
		syn_rows(v);
		return 1;
	}
	if (is_move(k)) {
		uint32_t *sel = &s->sel[s->tab];

		move(sel, s->n_rows, k, body > 1u ? body - 1u : 1u);
		follow(*sel, &s->page.off, body);
		return 1;
	}
	switch (k) {
	case 27:
		syn_close(v);
		return 1;
	case K_LEFT:
		syn_tab_set(v, (s->tab + SYN_TABS - 1) % SYN_TABS);
		return 1;
	case K_RIGHT: case '\t':
		syn_tab_set(v, (s->tab + 1) % SYN_TABS);
		return 1;
	case K_BACKTAB:
		syn_tab_set(v, (s->tab + SYN_TABS - 1) % SYN_TABS);
		return 1;
	case '\r': case '\n':
		syn_form_open(v, 0, 1);
		return 1;
	case K_DEL:
		syn_delete(v);
		return 1;
	default:
		break;
	}
	if (printable(k)) {
		focus(v, ED_SYN_SEARCH);
		field_key(v, s->filt, sizeof s->filt, k, NULL);
		s->sel[s->tab] = 0;
		s->page.off = 0;
		syn_rows(v);
	}
	return 1;
}

static int key_form(struct view *v, int k)
{
	struct kv_syn *s = v->syn;
	struct syn_form *f = &s->form;
	int has_cmt = f->kind == KOF_TAGSRC_K_TAG ||
		      f->kind == KOF_TAGSRC_K_ACTIVITY;

	if (k == '\t' || k == K_BACKTAB) {
		focus(v, v->edit == ED_SYN_NAME && has_cmt ? ED_SYN_COMMENT
							   : ED_SYN_NAME);
		return 1;
	}
	if (k == '\r' || k == '\n') {
		syn_form_ok(v);
		return 1;
	}
	if (k == 27) {
		if (v->edit)
			v->edit = 0;
		else
			syn_form_cancel(v);
		return 1;
	}
	if (v->edit == ED_SYN_NAME)
		return name_key(v, f->name, sizeof f->name, k);
	if (v->edit == ED_SYN_COMMENT)
		return field_key(v, f->cmt, sizeof f->cmt, k, NULL);
	if (printable(k))
		focus(v, ED_SYN_NAME);
	return 1;
}

static int key_pick(struct view *v, int k)
{
	struct syn_pick *p = &v->syn->pick;
	uint32_t body = g_rows > 10 ? (uint32_t)g_rows - 10u : 1u;

	if (is_move(k)) {
		move(&p->sel, p->n_vis, k, body);
		follow(p->sel, &p->ly.off, body);
		return 1;
	}
	if (k == 27) {
		syn_pick_cancel(v);
		return 1;
	}
	if (k == '\r' || k == '\n') {
		/* Nothing matches: Enter does not choose "(none)" for you. */
		if (p->multi || p->n_real)
			syn_pick_toggle(v, p->sel);
		return 1;
	}
	if (k == '\t' && p->multi) {
		syn_pick_ok(v);
		return 1;
	}
	if (k == '\t' || k == K_BACKTAB)
		return 1;
	field_key(v, p->filt, sizeof p->filt, k, NULL);
	syn_pick_home(v);
	return 1;
}

static int key_res(struct view *v, int k)
{
	struct kv_syn *s = v->syn;

	switch (k) {
	case 27: case '\r': case '\n':
		s->res_open = 0;
		break;
	case K_UP:   if (s->res.off) s->res.off--; break;
	case K_DOWN: s->res.off++; break;
	case K_PGUP: s->res.off = s->res.off > 8u ? s->res.off - 8u : 0u; break;
	case K_PGDN: s->res.off += 8u; break;
	default: break;
	}
	return 1;
}

int handle_syn_key(struct view *v, int k)
{
	struct kv_syn *s = v->syn;
	struct syn_layer *ly;

	if (!syn_modal(v))
		return -1;
	if (k == K_CLICK)
		return -1;              /* click() asks syn_click */
	if (k == K_RCLICK || k == K_DRAG || k == K_RELEASE || k == K_RESIZE ||
	    k == K_F10)
		return k == K_RESIZE || k == K_F10 ? -1 : 1;
	ly = top_layer(s);
	if (k == K_WHEEL_UP || k == K_WHEEL_DOWN) {
		if (k == K_WHEEL_UP)
			ly->off = ly->off > 3u ? ly->off - 3u : 0u;
		else
			ly->off += 3u;
		return 1;
	}
	if (s->pick.open)
		return key_pick(v, k);
	if (s->res_open)
		return key_res(v, k);
	if (s->form.open)
		return key_form(v, k);
	return key_page(v, k);
}
