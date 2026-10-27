#define _GNU_SOURCE

/*
 * kv_props_tab.c - the dashboard's table pages and the controls of its tab strip.
 *
 *   Segments  the program headers of an ELF (a PE has none, and the page says so)
 *   Sections  the section headers of an ELF, the sections of a PE
 *   Imports   the object's imported symbols
 *   Exports   its exported symbols, both with the filter the Symbols dialog had (retired)
 *
 * Each is ONE table drawn by the table renderer (kv_table.c) through prop_table_page: its heading stays and its rows
 * are the page's own scrolling lines, so the page's offsets - vertical (view.prop_off) and sideways (view.prop_hoff)
 * - are the table's, and the wheel, a key and the scrollbar move the same thing. This file spells the data as columns
 * and decides nothing about content: that is kv_dashdata.c (segments, sections, entropy, the filtered symbols).
 *
 * PAGES ARE SWITCHED BY A CLICK ON THE TAB STRIP AND BY NOTHING ELSE (owner decision): no key changes page. The keys
 * here act INSIDE a page - the filter field and the sideways pan of a symbol page.
 */

#include "kv_props_private.h"

/* ---- which page, and what changing it resets --------------------------------------------- */

static int page_is_syms(const struct view *v)
{
	return v->prop_pg == PROP_PG_IMPORTS || v->prop_pg == PROP_PG_EXPORTS;
}

/* Open the dashboard, on its overview, at the top. The symbol filter is the view's and is kept: a
 * reader who narrowed the imports and looked at the exports comes back to the same words. */
void prop_show(struct view *v)
{
	v->prop_open = 1;
	v->prop_move.dx = v->prop_move.dy = 0;
	v->prop_off = 0;
	v->prop_inf = 0;
	v->prop_pg = PROP_PG_OVERVIEW;
	v->prop_hoff = 0;
}

/* Open the Infection dialog (the dashboard's dialog over its second book), on its first tab, at the top. */
void prop_show_infection(struct view *v)
{
	prop_show(v);
	v->prop_inf = 1;
	v->prop_pg = PROP_PG_INF_DATA;
}

/* Close it, and with it anything that belonged to it: the filter box may hold the caret and the
 * recorded text may hold a selection, and a next box would be painted over by both. */
void prop_close(struct view *v)
{
	if (v->edit == ED_SYMFILT)
		v->edit = 0;
	v->prop_open = 0;
	v->dlg_have = 0;
	v->dlg_drag = 0;
	free(v->dlg_full);
	v->dlg_full = NULL;
	prop_tabs_free(v);
}

/* Switch pages (a click on the strip). A table's offset is a position in THAT table's rows and
 * means somewhere else in the next one's, so the page the switch lands on starts at the top; the
 * page's own scroll too. */
void prop_page_set(struct view *v, unsigned pg)
{
	if (pg >= PROP_PG_COUNT || pg == v->prop_pg)
		return;
	v->prop_pg = (uint8_t)pg;
	v->prop_off = 0;
	v->dlg_have = 0;
	v->dlg_drag = 0;
	v->prop_hoff = 0;
	if (v->edit == ED_SYMFILT && !page_is_syms(v))
		v->edit = 0;
}

/* ---- the segments and sections pages ------------------------------------------------------------------------- */

/* What a layout table's cell callback walks: the data function and the row. */
struct prop_laytab {
	const struct object *ob;
	enum dash_lay which;
	char row[DASH_COLS][DASH_CELL];
};

static void lay_cell(void *user, uint32_t row, const char **out)
{
	struct prop_laytab *T = user;
	uint32_t k;

	dash_layout_cell(T->ob, T->which, row, T->row);
	for (k = 0; k < KV_TAB_COLS; k++)
		out[k] = k < DASH_COLS ? T->row[k] : "";
}

/* One layout page: what the table is, says, and its rows. Segments and Sections are the same page over a different
 * `which`; the columns, their tones and their natural widths are the data's (dash_layout, dash_layout_widths). */
static void layout_page(struct view *v, const struct object *ob, enum dash_lay which)
{
	static struct prop_laytab T;
	struct prop_col col[KV_TAB_COLS];
	struct kv_tab_spec t;
	struct dash_table d;
	uint16_t w[DASH_COLS];
	uint32_t k;

	dash_layout(ob, which, &d);
	if (!d.n_col) {
		prop_say(A_DIM, "%s", d.none);
		return;
	}
	if (d.declared != d.n_row)
		prop_say(A_WARN, "%u kept, the header declares %u", d.n_row, d.declared);
	memset(&T, 0, sizeof T);
	T.ob = ob;
	T.which = which;
	dash_layout_widths(ob, which, w);
	for (k = 0; k < d.n_col; k++) {
		col[k].name = d.head[k];
		col[k].width = w[k];
		col[k].right = 0;
		col[k].attr = prop_tone_sgr(d.tone[k]);
	}
	prop_spec(&t, col, d.n_col, d.n_row, d.lead, 1, lay_cell, &T);
	prop_table_page(v, &t, g_n_prop);
}

/* ---- the symbol pages --------------------------------------------------------------------------------------- */

/*
 * Compile the filter when it is being read as a regex.
 *
 * rx_compile is the engine's, the same one a rule's pattern goes through, so what this page accepts and what a
 * signature accepts cannot drift. It refuses a pattern with no concrete run in it - that refusal is about the
 * PREFILTER a rule needs and is not interesting here, but the alternative is a second regex implementation, which
 * is worse than a filter that occasionally says "not yet". A refusal leaves sy_frx_bad set, and then NOTHING
 * MATCHES and the compiler's words are on the page (dash_filter_ok).
 */
void prop_sym_filter_compile(struct view *v)
{
	v->sy_prog_n = 0;
	v->sy_frx_bad = 0;
	if (!v->sy_frx || !v->sy_filt[0])
		return;
	if (!rx_compile(v->sy_filt, v->sy_prog, (uint32_t)sizeof v->sy_prog,
			&v->sy_prog_n, v->sy_rx_err, sizeof v->sy_rx_err))
		v->sy_frx_bad = 1;
}

/* The view's filter state as the data layer takes it. */
static struct dash_filter filter_of(const struct view *v)
{
	struct dash_filter f;

	f.text = v->sy_filt;
	f.icase = v->sy_ficase;
	f.rx = v->sy_frx;
	f.bad = v->sy_frx_bad;
	f.prog = v->sy_prog;
	f.prog_n = v->sy_prog_n;
	f.err = v->sy_rx_err;
	return f;
}

struct prop_syms {
	const struct dash_syms *S;
	struct dash_symcell c;
};

static void sym_cell(void *user, uint32_t row, const char **out)
{
	struct prop_syms *P = user;
	uint32_t k;

	dash_syms_cell(P->S, row, &P->c);
	for (k = 0; k < DASH_SYM_COLS; k++)
		out[k] = P->c.cell[k];
}

/* The symbol a shellcode finder named gets the colour the dialog gave it. */
static const char *sym_rowattr(void *user, uint32_t row)
{
	struct prop_syms *P = user;

	return dash_syms_found(P->S, row) ? A_S_FOUND : NULL;
}

/*
 * The filter line: the field, and its two ticks, as ONE line of the page - the first of its fixed lines. The text
 * is drawn INTO the line (placeholder when empty) so the line records like any other; while the field is being
 * typed into, draw_prop paints the live field - caret and selection - over the same columns (prop_filter_over).
 * The columns of the three boxes are recorded here relative to the line and made absolute by draw_prop, which is
 * the only code that knows where the page landed.
 */
/* What the filter line keeps beside its field: the margin and the two tick boxes " [x] icase [x] regex". */
#define SYM_FILTER_TAIL 22

static void sym_filter_line(struct view *v, int room)
{
	char field[80];
	int fw = room;
	size_t n = strlen(v->sy_filt);

	if (fw > (int)sizeof field - 1)
		fw = (int)sizeof field - 1;
	if (fw < 8)
		fw = 8;
	snprintf(field, sizeof field, "%-*.*s", fw, fw, n ? v->sy_filt : "filter");
	v->sy_fbox[0] = 2;
	v->sy_fbox[1] = 2 + fw - 1;
	v->sy_ic_box[0] = v->sy_fbox[1] + 2;
	v->sy_ic_box[1] = v->sy_ic_box[0] + 8;
	v->sy_rx_box[0] = v->sy_ic_box[1] + 2;
	v->sy_rx_box[1] = v->sy_rx_box[0] + 8;
	prop_add("  %s%s" A_OFF " %s[%s] icase" A_OFF " %s[%s] regex" A_OFF,
		 v->edit == ED_SYMFILT ? A_SEL : (v->sy_frx && v->sy_frx_bad) ? A_BAD : n ? A_ID : A_DIM, field,
		 v->sy_ficase ? A_SEL : A_DIM, v->sy_ficase ? "x" : " ",
		 v->sy_frx ? A_SEL : A_DIM, v->sy_frx ? "x" : " ");
}

/*
 * The imports or the exports of the object in hand: the filter line, then one table over dash_syms. Columns in the
 * order the record stores them, so a reader moving between this page and the hex is reading the same sequence
 * twice; the ROW pans (the page's sideways offset), so a long name and the value after it are both reachable at any
 * width and the record number stays put. Every empty case says which empty it is.
 */
void prop_symbols(struct view *v, const struct object *ob, uint8_t which)
{
	static struct dash_syms S;
	static struct prop_syms P;
	/* The fixed widths are the value spellings' (kof_sym_*_name, the flag string); the name, size and value columns follow the
	 * data. Numeric columns are right-aligned, heading included. */
	struct prop_col col[DASH_SYM_COLS] = {
		{ NULL, 4, 0, A_S_IDX }, { NULL, 7, 0, A_S_TYPE }, { NULL, 6, 0, A_S_BIND }, { NULL, 9, 0, A_S_VIS },
		{ NULL, 5, 0, A_S_FLAG }, { NULL, 0, 0, A_S_NAME }, { NULL, 5, 1, A_S_SHN }, { NULL, 0, 1, A_S_SIZE },
		{ NULL, 0, 1, A_S_VAL }
	};
	const char *what = which == SYMN_IMP ? "imports" : "exports";
	struct dash_filter f = filter_of(v);
	struct kv_tab_spec t;
	uint32_t k;

	v->sy_fy = -1;
	dash_syms_load(v, &f, ob, which, &S);
	if (S.why == DASH_NA) {
		prop_say(A_DIM, "no %s: this kind of object has no symbol table", what);
		return;
	}
	sym_filter_line(v, v->prop_room_cols - SYM_FILTER_TAIL);
	v->sy_fy = 0;       /* the filter line is line 0 of the page; draw_prop makes it a screen row */
	if (S.cut)
		prop_say(A_WARN, "the symbol block was cut (%s): %u listed, the object declares more",
			 S.cut == 1 ? "no room" : "source limit", S.got);
	switch (S.why) {
	case DASH_RX:     prop_say(A_BAD, "%s", v->sy_rx_err);                       return;
	case DASH_FILTER: prop_say(A_DIM, "no symbol matches the filter");           return;
	case DASH_NONE:   prop_say(A_DIM, "this object declares no %s", what);       return;
	default:          break;
	}
	P.S = &S;
	for (k = 0; k < DASH_SYM_COLS; k++)
		col[k].name = dash_sym_head[k];
	col[5].width = (uint16_t)S.nw;
	col[7].width = (uint16_t)S.sw;
	col[8].width = (uint16_t)(S.wd + 2);
	prop_spec(&t, col, DASH_SYM_COLS, S.n, 1, 5, sym_cell, &P);
	t.rowattr = sym_rowattr;
	prop_table_page(v, &t, g_n_prop);
}

/* ---- the Infection dialog's pages ------------------------------------------------------------------------------ */

/* What the two pages' cell callbacks walk: the kept result (one of the two is set) and the row's cells. */
struct prop_wide {
	const struct dash_infect *I;
	const struct dash_shell *S;
	struct dash_widecell c;
};

static void wide_cell(void *user, uint32_t row, const char **out)
{
	struct prop_wide *P = user;
	uint32_t k;

	if (P->I)
		dash_infect_cell(P->I, row, &P->c);
	else
		dash_shell_cell(P->S, row, &P->c);
	for (k = 0; k < KV_TAB_COLS; k++)
		out[k] = k < DASH_WIDE_COLS ? P->c.cell[k] : "";
}

/* A row the engine reported as infected is drawn in the bad colour, one the finder or the evidence flagged in the warning
 * colour; the other rows keep their column colours. */
static const char *wide_rowattr(void *user, uint32_t row)
{
	struct prop_wide *P = user;

	if (P->I)
		return dash_infect_flagged(P->I, row) ? A_BAD : NULL;
	return dash_shell_flagged(P->S, row) ? A_WARN : NULL;
}

/* One page of the dialog from a dash_table: the sentence when there is no table, the cut when rows were not kept, else the
 * table through the same renderer as every other (prop_spec, prop_table_page). The last column is the value: its width is
 * the data's (`vw`, from the sizes, no text produced) and the measure pass of the other columns skips its text, so a page of
 * 1024 rows does not render 1024 hex strings to find a width. Numbers are right-aligned. */
static void wide_page(struct view *v, const struct dash_table *d, struct prop_wide *P, const uint8_t *right, uint32_t vw)
{
	struct prop_col col[KV_TAB_COLS];
	struct kv_tab_spec t;
	uint32_t k;

	if (!d->n_col) {
		prop_say(A_DIM, "%s", d->none);
		return;
	}
	if (d->not_shown)
		prop_say(A_WARN, "%u of %u rows kept, the dialog holds no more", d->n_row, d->declared);
	for (k = 0; k < d->n_col; k++) {
		col[k].name = d->head[k];
		col[k].width = k + 1u == d->n_col ? (uint16_t)(vw < 0xffffu ? vw : 0xffffu) : 0;
		col[k].right = right[k];
		col[k].attr = prop_tone_sgr(d->tone[k]);
	}
	prop_spec(&t, col, d->n_col, d->n_row, d->lead, (int)d->n_col - 1, wide_cell, P);
	t.rowattr = wide_rowattr;
	P->c.no_value = 1;
	kv_tab_measure(&t);
	P->c.no_value = 0;
	prop_table_page(v, &t, g_n_prop);
}

/* The kept result is made by the first call for this object (dash_*_get) and read by every frame after it. */
static void infect_page(struct view *v, struct object *ob)
{
	static struct prop_wide P;
	static const uint8_t right[DASH_WIDE_COLS] = { 0, 0, 0, 1, 0, 0 };
	struct dash_infect *I = dash_infect_get(ob);
	struct dash_table d;

	if (!I) {
		prop_say(A_BAD, "not enough memory to list the regions");
		return;
	}
	dash_infect_table(I, &d);
	memset(&P, 0, sizeof P);
	P.I = I;
	wide_page(v, &d, &P, right, dash_infect_value_width(I));
}

static void shell_page(struct view *v, struct object *ob)
{
	static struct prop_wide P;
	static const uint8_t right[DASH_WIDE_COLS] = { 0, 0, 0, 1, 0, 0, 0, 0, 0 };
	struct dash_shell *S = dash_shell_get(ob);
	struct dash_table d;

	if (!S) {
		prop_say(A_BAD, "not enough memory to list the candidates");
		return;
	}
	dash_shell_table(S, &d);
	memset(&P, 0, sizeof P);
	P.S = S;
	wide_page(v, &d, &P, right, dash_shell_value_width(S));
}

/* The table pages, one builder: which page is showing says which table. */
void prop_page_table_build(struct view *v, struct object *ob)
{
	switch (v->prop_pg) {
	case PROP_PG_SEGMENTS: layout_page(v, ob, DASH_LAY_SEG); break;
	case PROP_PG_SECTIONS: layout_page(v, ob, DASH_LAY_SEC); break;
	case PROP_PG_INF_DATA:  infect_page(v, ob); break;
	case PROP_PG_INF_SHELL: shell_page(v, ob); break;
	default:               prop_symbols(v, ob, v->prop_pg == PROP_PG_IMPORTS ? SYMN_IMP : SYMN_EXP); break;
	}
}

/* ---- the strip, the filter and the keys --------------------------------------------------------- */

/*
 * The live filter field, painted over the filter line while it is being typed into: caret, selection
 * and scroll are field_draw's, so the box behaves like every other text box in the program. The
 * boxes are screen columns by now (draw_prop); the rectangle is the page's, which the paint is
 * clipped to.
 */
void prop_filter_over(struct out *o, struct view *v, int y0, int x0, int y1, int x1)
{
	struct out_clip cl;

	if (v->edit != ED_SYMFILT || !page_is_syms(v) || v->sy_fy < 0)
		return;
	cl = out_clip_set(o, y0, x0, y1, x1);
	out_at(o, v->sy_fy, v->sy_fbox[0]);
	o->col_hint = 0;
	out_str(o, A_SEL);
	field_draw(o, v->sy_filt, v->caret, &v->sy_foff, v->sy_fbox[1] - v->sy_fbox[0] + 1, 1, "filter");
	out_str(o, A_OFF);
	out_clip_restore(o, cl);
}

/* The page's offset for the pointer's row on the scrollbar (kv_dd_bar_offset reads the drawn geometry). */
void prop_bar_to(struct view *v)
{
	v->prop_off = kv_dd_bar_offset(&v->prop_in, &v->prop_geo, g_my);
}

/* A press on the tab strip or on the filter line. 1 when it was one of those. The strip is the dialog's geometry
 * (kv_dash_dialog.h), recorded as it was drawn. */
int prop_click(struct view *v)
{
	int tab = kv_dd_tab_at(&v->prop_geo, g_my, g_mx);

	if (kv_dd_grab_at(&v->prop_geo, g_my, g_mx)) {
		dlg_hold(v, &v->prop_move);
		return 1;
	}
	if (tab >= 0) {
		prop_page_set(v, (unsigned)tab + (v->prop_inf ? (unsigned)PROP_PG_INF_DATA : 0u));
		return 1;
	}
	/* The dialog's scrollbar, in its right wall: a press moves the page to that place and a drag follows (on_drag). */
	if (v->prop_geo.bar_rows > 0 && g_mx == v->prop_geo.bar_x && g_my >= v->prop_geo.bar_y0 &&
	    g_my < v->prop_geo.bar_y0 + v->prop_geo.bar_rows) {
		prop_bar_to(v);
		v->prop_bar_drag = 1;
		return 1;
	}
	if (page_is_syms(v) && v->sy_fy >= 0 && g_my == v->sy_fy) {
		if (g_mx >= v->sy_fbox[0] && g_mx <= v->sy_fbox[1]) {
			v->edit = ED_SYMFILT;
			return 1;
		}
		/* Each tick moves the list back to the top: an offset is a position in the rows the filter
		 * was showing and means somewhere else in the rows it shows now. */
		if (g_mx >= v->sy_ic_box[0] && g_mx <= v->sy_ic_box[1]) {
			v->sy_ficase = !v->sy_ficase;
			v->prop_off = 0;
			return 1;
		}
		if (g_mx >= v->sy_rx_box[0] && g_mx <= v->sy_rx_box[1]) {
			v->sy_frx = !v->sy_frx;
			prop_sym_filter_compile(v);
			v->prop_off = 0;
			return 1;
		}
	}
	return 0;
}

/* THE ONE SCROLL of the dashboard page, in lines and columns, saturating at zero; the clamp to what the page holds is
 * kv_tab_clamp, applied where the page is drawn (the only place that knows the room). Wheel, keys and the scrollbar
 * all come here, so a table and the lines around it can never move differently. */
void prop_scroll(struct view *v, int dy, int dx)
{
	uint32_t ay = (uint32_t)(dy < 0 ? -dy : dy), ax = (uint32_t)(dx < 0 ? -dx : dx);

	v->prop_off = dy < 0 ? (v->prop_off > ay ? v->prop_off - ay : 0u) : v->prop_off + ay;
	v->prop_hoff = dx < 0 ? (v->prop_hoff > ax ? v->prop_hoff - ax : 0u) : v->prop_hoff + ax;
}

/*
 * A key that acts INSIDE a symbol page: the filter field while it is open, and the sideways pan. 1 when it was
 * consumed. No key changes the page (owner decision: the strip is clicked). The vertical keys are the page's own
 * (handle_prop_key), which is the table's scroll.
 *
 * Typing goes to the filter while it is open, and only then - the caret's keys are the field's, and
 * the vertical ones scroll the list underneath, which is what a reader narrowing a long table
 * expects. Escape closes the FIELD and not the page.
 */
int prop_page_key(struct view *v, int k)
{
	if (!page_is_syms(v) || (k >= K_CLICK && k <= K_RELEASE))
		return 0;
	if (v->edit == ED_SYMFILT) {
		switch (k) {
		case K_UP: case K_DOWN: case K_PGUP: case K_PGDN:
			return 0;               /* the page's, below */
		case 27:
			v->edit = 0;
			return 1;
		default:
			(void)field_key(v, v->sy_filt, sizeof v->sy_filt, k, NULL);
			if (k == '\r' || k == '\n')
				v->edit = 0;
			prop_sym_filter_compile(v);
			v->prop_off = 0;
			return 1;
		}
	}
	switch (k) {
	case K_LEFT:  prop_scroll(v, 0, -PROP_KEY_COLS); return 1;
	case K_RIGHT: prop_scroll(v, 0, PROP_KEY_COLS);  return 1;
	default:      return 0;
	}
}
