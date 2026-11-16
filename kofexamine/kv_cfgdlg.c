#define _GNU_SOURCE
#include "kv.h"
#include "kv_cfgdlg.h"

/*
 * The dialog of a function, in the frame the Syndromes and Pathogens dialogs use - draggable by its top rule, a scrollbar in its right wall, the wheel scrolls it down and
 * shift or ctrl wheel sideways (kv_main_key, with a body of rows in place of a table: kv_main_body) - with THREE TABS in the top rule:
 *   Overview  the engine's head of the function's lineage (lineageview.c's counts)
 *   Disasm    the disassembly panel's own rows of the function (kv_disasm.c, dis_func_rows: the same formatter, labels, comments and colours, the function as its data)
 *   Lineage   this function's slice of the object's whole value-flow graph (kof_lineageview_build, kv_lineagebody.c), every link of every kind - drawn by the same
 *             kv_graph*.c in the top pane, the engine's rows of the links with a tick box each in the bottom pane (a ticked link is lit in the drawing); the
 *             engine's head of it (the counts) is the Overview's last rows
 * It decides nothing: the rows are kv_cfgbody.c's, kv_disasm.c's and kv_lineagebody.c's, the nodes, the edges, the words and the facts are the engine's, the places are kv_graph*.c's;
 * what is here is the placement of the frame, the routing of a press and which tab is shown.
 *
 * DISABLED by the owner 2026-11-15 (CFG): the Graph tab (the engine's graph, kof_cfgview_build, drawn by kv_graph*.c) and the Overview's CFG facts (the function's
 * head, the counts, the unit id, the keys, the calls table, the unreachable blocks: kv_cfgbody.c). The press on the "Graph" tab title went with the tab. To re-enable:
 * KV_CFG_TAB_GRAPH and its title back, and the #if 0 blocks of this file, kv_cfgdlg.h and kv_cfgbody.[ch] taken out.
 *
 * DECODES. Opening the dialog decodes nothing for the Overview (it decoded the function once for the Overview and the Graph while those were made). The Disasm tab is made the first time it is shown and not
 * before (a reader who never opens it never pays it); the rows are kept for the life of the dialog, so a tab switched to again decodes nothing. The Lineage tab is made at
 * open (its head is the Overview's): it decodes nothing - the object's whole diagnose-scan, once per object, not per function, is paid by view_explain (kv_collect.c) when
 * hit_plg_cfg opens the dialog (reading it is asking, the engine's own rule for the diagnose surface); a second function's dialog in the same object reads the same answer.
 *
 * KEYS. The same as the catalog dialogs and none added: Esc or Enter closes, the wheel scrolls (the page keys and the copy key of the help page it replaced went with that page);
 * the tabs are switched by a press on their title and by nothing else. A press on [ Close ] closes; a press on the top rule beside the tabs takes hold of the box. On the
 * Lineage tab the wheel scrolls the pane it is over, and a press on a link's tick box ticks it (kv_lineagebody.c); no key does either.
 */

static const char *const cfg_tab_title[KV_CFG_TABS] = { "Overview", "Disasm", "Lineage" };      /* "Graph" DISABLED by the owner 2026-11-15 (CFG) */

static struct kv_cfg_ui *cfg_ui(const struct view *v)
{
	return v->cfgd;
}

/* Columns of `s` from the `hoff`-th printable one on, into `out`: the colour escapes are kept (they say how the rest is drawn), the glyphs before `hoff` are dropped. */
static void rows_from(const char *s, uint32_t hoff, char *out, size_t cap)
{
	size_t n = 0;
	uint32_t seen = 0;

	while (*s && n + 1u < cap) {
		if (*s == '\033') {
			while (*s && *s != 'm' && n + 1u < cap)
				out[n++] = *s++;
			if (*s == 'm' && n + 1u < cap)
				out[n++] = *s++;
			continue;
		}
		if (((unsigned char)*s & 0xc0u) != 0x80u && seen < hoff) {
			seen++;
			s++;
			while (((unsigned char)*s & 0xc0u) == 0x80u)
				s++;
			continue;
		}
		out[n++] = *s++;
	}
	out[n] = 0;
}

/* One row of the Disasm tab: the margin column, then the panel's row from column `hoff`. */
static void dis_row(const void *user, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap)
{
	const struct dis_func_rows *d = user;

	(void)ncols;
	if (cap < 2)
		return;
	out[0] = ' ';
	out[1] = 0;
	if (row < d->n)
		rows_from(d->row[row], hoff, out + 1, cap - 1u);
}

int cfgd_up(const struct view *v)
{
	return v->cfgd && v->cfgd->open;
}

static void cfgd_drop(struct kv_cfg_ui *u)
{
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	kv_cfgbody_free(&u->body);
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
	dis_func_rows_free(&u->dis);
	u->dis_made = 0;
	kv_lineagebody_free(&u->lin);
}

/* The Overview's rows: the engine's head of the function's lineage (its counts: lineageview.c). kv_cfgbody.c's rows and the blank row before the head stood first:
 * DISABLED by the owner 2026-11-15 (CFG); to re-enable, take the #if 0 blocks of ov_rows and ov_row out. */
static uint32_t ov_rows(const struct kv_cfg_ui *u, uint32_t *n_col)
{
	uint32_t r = 0, c = 0, i;

#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	kv_cfgbody_size(&u->body, KV_CFG_TAB_OVERVIEW, &r, &c);
#endif /* DISABLED by the owner 2026-11-15 (CFG) */

	for (i = 0; i < u->lin.gv.n_head; i++)
		if (strlen(u->lin.gv.head[i]) > c)
			c = (uint32_t)strlen(u->lin.gv.head[i]);
	*n_col = c;
	return r + (u->lin.gv.n_head ? (r ? 1u : 0u) + u->lin.gv.n_head : 0u);
}

static void ov_row(const void *user, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap)
{
	const struct kv_cfg_ui *u = user;
	uint32_t r = 0, gap = 0;

#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	uint32_t c;

	kv_cfgbody_size(&u->body, KV_CFG_TAB_OVERVIEW, &r, &c);
	if (row < r) {
		kv_cfgbody_row(&u->body, row, hoff, ncols, out, cap);
		return;
	}
	gap = r ? 1u : 0u;
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
	if (cap < 2)
		return;
	out[0] = ' ';
	out[1] = 0;
	if (row >= r + gap && row - r - gap < u->lin.gv.n_head && hoff < strlen(u->lin.gv.head[row - r - gap]))
		snprintf(out + 1, cap - 1u, "%.*s", (int)(ncols - 1u), u->lin.gv.head[row - r - gap] + hoff);
}

void cfgd_free(struct view *v)
{
	if (!v->cfgd)
		return;
	cfgd_drop(v->cfgd);
	free(v->cfgd);
	v->cfgd = NULL;
}

static void cfgd_close(struct view *v)
{
	if (v->cfgd) {
		v->cfgd->open = 0;
		cfgd_drop(v->cfgd);
	}
	v->dlg_move = NULL;
}

void cfgd_open(struct view *v, uint64_t func_off, uint64_t func_len, const struct object *o)
{
	struct kv_cfg_ui *u = v->cfgd;

	if (!u) {
		u = calloc(1, sizeof *u);
		if (!u)
			return;
		v->cfgd = u;
	}
	cfgd_drop(u);
	/* DISABLED by the owner 2026-11-15: the engine's CFG answer for the Overview and the Graph (kof_cfgview_build). To re-enable: take this #if 0 out, with kv_cfgbody.[ch]'s
	 * and hit_plg_cfg's request (kv_decl_blocks.c). */
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	kv_cfgbody_make(&u->body, rq);
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
	u->m.move.dx = u->m.move.dy = 0;        /* a dialog opens centred; where it was dragged is forgotten */
	u->m.off = 0;
	u->m.hoff = 0;
	u->tab = KV_CFG_TAB_OVERVIEW;
	memset(u->off, 0, sizeof u->off);
	memset(u->hoff, 0, sizeof u->hoff);
	u->func_off = func_off;
	u->func_len = func_len;
	{
		struct kof_lineageview_req lq;

		memset(&lq, 0, sizeof lq);
		lq.lin = o ? o->lineage : NULL;
		lq.n_lin = o && o->lineage ? o->n_lineage : 0u;
		lq.lin_in = o ? o->lineage_in : NULL;
		lq.n_lin_in = o && o->lineage_in ? o->n_lineage_in : 0u;
		lq.off = func_off;
		lq.len = func_len;
		lq.base = o ? o->buf.p : NULL;
		lq.size = o ? o->buf.n : 0u;
		kv_lineagebody_make(&u->lin, &lq);
	}
	u->open = 1;
}

void draw_cfgd(struct out *o, struct view *v)
{
	struct kv_cfg_ui *u = cfg_ui(v);
	struct kv_main_body body;
	struct kv_main_in in;
	uint32_t ov_r, ov_c, gr_r = 0, gr_c = 0;

	if (!u || !u->open)
		return;
	memset(&body, 0, sizeof body);
	if (u->tab == KV_CFG_TAB_DISASM) {
		if (!u->dis_made) {
			/* the decode of the function: the rows of the panel, bounded by its length in bytes (an instruction is at least one byte). The bound was what the engine's
			 * CFG answer decoded (u->body.cf.n_insn + n_skip), DISABLED by the owner 2026-11-15 with it. */
			dis_func_rows(v, u->func_off, u->func_len, u->func_len, &u->dis);
			u->dis_made = 1;
		}
		body.n_row = u->dis.n;
		body.n_col = u->dis.width;
		body.row = dis_row;
		body.user = &u->dis;
	} else if (u->tab == KV_CFG_TAB_LINEAGE) {
		/* the room is the body's rows of the last frame: the box keeps its size from tab to tab (below), so it is this frame's too */
		kv_lineagebody_size(&u->lin, u->m.geo.body_rows > 0 ? (uint32_t)u->m.geo.body_rows : 0u, &body.n_row, &body.n_col);
		body.row = kv_lineagebody_row;
		body.user = &u->lin;
	} else {
		body.n_row = ov_rows(u, &body.n_col);
		body.row = ov_row;
		body.user = u;
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
		u->body.tab = u->tab;
	} else {
		u->body.tab = u->tab;
		kv_cfgbody_size(&u->body, u->tab, &body.n_row, &body.n_col);
		body.row = kv_cfgbody_row;
		body.user = &u->body;
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
	}
	/* the box keeps its size from tab to tab: the Overview's and the Lineage panes' (below), the larger. (The Overview table's width and the Graph tab's size
	 * came from kof_cfgview_build: DISABLED by the owner 2026-11-15, in #if 0.) */
	ov_c = 0;
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	kv_cfgbody_size(&u->body, KV_CFG_TAB_OVERVIEW, &ov_r, &ov_c);
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
	ov_r = ov_rows(u, &gr_c);                       /* its rows with the lineage head; its width stays the table's (a head line is scrolled to, not a wider box) */
	if (!ov_c)
		ov_c = gr_c;                            /* no table: the head's width */
	gr_c = 0;
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	kv_cfgbody_size(&u->body, KV_CFG_TAB_GRAPH, &gr_r, &gr_c);
#endif /* DISABLED by the owner 2026-11-15 (CFG) */

	memset(&in, 0, sizeof in);
	in.body = &body;
	in.tab = cfg_tab_title;
	in.n_tab = KV_CFG_TABS;
	in.tab_sel = (int)u->tab;
	{
		/* and the Lineage tab's two panes whole: the drawing and what it left out, the rule, a link row with its tick box (a screen too small for them
		 * gets the box the screen has, and each pane scrolls) */
		uint32_t i, lw = u->lin.g.width, lh = u->lin.g.height + u->lin.n_xl + 1u + u->lin.gv.n_note;

		for (i = 0; i < u->lin.gv.n_note; i++)
			if (strlen(u->lin.gv.note[i].text) + 4u > lw)
				lw = (uint32_t)strlen(u->lin.gv.note[i].text) + 4u;
		if (lw > ov_c)
			ov_c = lw;
		if (lh > ov_r)
			ov_r = lh;
	}
	in.want_w = (int)(ov_c > gr_c ? ov_c : gr_c) + 5;     /* the frame, the margin column of the body and the widest row: the longest line was the calls title, which hid that the margin was not counted */
	in.want_h = (int)(ov_r > gr_r ? ov_r : gr_r) + 2;
	{
		/* THE STRIP MUST FIT: the Graph tab and the Overview's CFG facts (DISABLED by the owner 2026-11-15) made the box at least that wide and tall; with
		 * them gone a function with no lineage has an empty Overview, and a box too small for its own strip of titles is not drawn at all (measured: tests/tui
		 * t_cfg_view.py closing_works_and_it_opens_again saw no dialog). The floor is the strip: every title with its brackets and spaces, and [ Close ]. */
		int strip = 14;
		uint32_t t;

		for (t = 0; t < KV_CFG_TABS; t++)
			strip += (int)strlen(cfg_tab_title[t]) + 4;
		if (in.want_w < strip)
			in.want_w = strip;
		if (in.want_h < 4)
			in.want_h = 4;
		/* and the Disasm tab's rows, which are made when that tab is first shown (not here): at most one a byte of the function, so the box asks for that
		 * many and the screen bounds it (kv_dd_layout), as the Graph's height did before it was disabled. */
		if (u->func_len && (uint64_t)in.want_h < u->func_len + 2u)
			in.want_h = u->func_len + 2u > (uint64_t)INT32_MAX ? INT32_MAX : (int)(u->func_len + 2u);
	}
	kv_cover_begin(&u->cv);
	(void)kv_main_draw(o, v, &u->m, &in);
	kv_form_cover_main(&u->cv, &u->m);
}

int cfgd_uncovered(struct view *v)
{
	struct kv_cfg_ui *u = cfg_ui(v);

	return u && u->open && kv_cover_uncovered(&u->cv);
}

/* A press while the dialog is up: it is modal, so every press is answered here. The menu bar was asked first. */
int cfgd_click(struct view *v, int rclick)
{
	struct kv_cfg_ui *u = cfg_ui(v);
	int r;

	if (!u || !u->open)
		return 0;
	if (rclick)
		return 1;
	r = kv_main_press(v, &u->m);
	if (r == KV_MAIN_NONE && u->tab == KV_CFG_TAB_LINEAGE && g_my >= u->m.geo.body_y0 && g_my < u->m.geo.body_y0 + u->m.geo.body_rows &&
	    g_mx >= u->m.geo.body_x0 && g_mx < u->m.geo.body_x0 + u->m.geo.body_cols) {
		(void)kv_lineagebody_press(&u->lin, (uint32_t)(g_my - u->m.geo.body_y0), g_mx - u->m.geo.body_x0);
		return 1;
	}
	if (r == KV_MAIN_CLOSE) {
		cfgd_close(v);
	} else if (r <= KV_MAIN_TAB(0) && KV_MAIN_TAB(0) - r < (int)KV_CFG_TABS && (uint32_t)(KV_MAIN_TAB(0) - r) != u->tab) {
		u->off[u->tab] = u->m.off;              /* each tab keeps the scroll it was left at */
		u->hoff[u->tab] = u->m.hoff;
		u->tab = (uint32_t)(KV_MAIN_TAB(0) - r);
		u->m.off = u->off[u->tab];
		u->m.hoff = u->hoff[u->tab];
	}
	return 1;
}

/* -1: not mine. While the dialog is up every key is its own; a press goes on to cfgd_click through click(). */
int handle_cfgd_key(struct view *v, int k)
{
	struct kv_cfg_ui *u = cfg_ui(v);

	if (!u || !u->open)
		return -1;
	if (k == K_CLICK || k == K_RCLICK)
		return -1;
	if ((k == K_WHEEL_UP || k == K_WHEEL_DOWN) && u->tab == KV_CFG_TAB_LINEAGE) {     /* the pane under the wheel scrolls, not the frame */
		if (g_my >= u->m.geo.body_y0 && g_my < u->m.geo.body_y0 + u->m.geo.body_rows)
			kv_lineagebody_wheel(&u->lin, (uint32_t)(g_my - u->m.geo.body_y0), k == K_WHEEL_UP, g_mod_shift || g_mod_ctrl);
		return 1;
	}
	if (kv_main_key(v, &u->m, k, 1))
		return 1;
	if (k == 27 || k == '\r' || k == '\n')
		cfgd_close(v);
	return 1;
}
