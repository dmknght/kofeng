#define _GNU_SOURCE
#include "kv.h"
#include "kv_cfgdlg.h"

/*
 * The CFG dialog of a function, in the frame the Syndromes and Pathogens dialogs use - draggable by its top rule, a scrollbar in its right wall, the wheel scrolls it down and
 * shift or ctrl wheel sideways (kv_main_key, with a body of rows in place of a table: kv_main_body) - with THREE TABS in the top rule:
 *   Overview  the engine's facts about the function and its calls as a table (kv_cfgbody.c)
 *   Disasm    the disassembly panel's own rows of the function (kv_disasm.c, dis_func_rows: the same formatter, labels, comments and colours, the function as its data)
 *   Graph     the engine's graph (kof_cfgview_build) drawn by kv_graph*.c, as it was
 * It decides nothing: the rows are kv_cfgbody.c's and kv_disasm.c's, the nodes, the edges, the words and the facts are the engine's, the places are kv_graph*.c's; what is here is
 * the placement of the frame, the routing of a press and which tab is shown.
 *
 * DECODES. Opening the dialog decodes the function once (kof_cfgview_build, for the Overview and the Graph). The Disasm tab decodes it a second time, for the text, the first
 * time it is shown and not before (a reader who never opens the tab never pays it); the rows are kept for the life of the dialog, so a tab switched to again decodes nothing.
 *
 * KEYS. The same as the catalog dialogs and none added: Esc or Enter closes, the wheel scrolls (the page keys and the copy key of the help page it replaced went with that page);
 * the tabs are switched by a press on their title and by nothing else. A press on [ Close ] closes; a press on the top rule beside the tabs takes hold of the box.
 */

static const char *const cfg_tab_title[KV_CFG_TABS] = { "Overview", "Disasm", "Graph" };

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
	kv_cfgbody_free(&u->body);
	dis_func_rows_free(&u->dis);
	u->dis_made = 0;
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

void cfgd_open(struct view *v, const struct kof_cfgview_req *rq)
{
	struct kv_cfg_ui *u = v->cfgd;

	if (!u) {
		u = calloc(1, sizeof *u);
		if (!u)
			return;
		v->cfgd = u;
	}
	cfgd_drop(u);
	kv_cfgbody_make(&u->body, rq);
	u->m.move.dx = u->m.move.dy = 0;        /* a dialog opens centred; where it was dragged is forgotten */
	u->m.off = 0;
	u->m.hoff = 0;
	u->tab = KV_CFG_TAB_OVERVIEW;
	memset(u->off, 0, sizeof u->off);
	memset(u->hoff, 0, sizeof u->hoff);
	u->func_off = rq->func_off;
	u->func_len = rq->func_len;
	u->open = 1;
}

void draw_cfgd(struct out *o, struct view *v)
{
	struct kv_cfg_ui *u = cfg_ui(v);
	struct kv_main_body body;
	struct kv_main_in in;
	uint32_t ov_r, ov_c, gr_r, gr_c;

	if (!u || !u->open)
		return;
	memset(&body, 0, sizeof body);
	if (u->tab == KV_CFG_TAB_DISASM) {
		if (!u->dis_made) {
			/* the second decode of the function: the rows of the panel, bounded by what the engine decoded (the instructions and the bytes it stepped over) */
			dis_func_rows(v, u->func_off, u->func_len, (uint64_t)u->body.cf.n_insn + u->body.cf.n_skip, &u->dis);
			u->dis_made = 1;
		}
		body.n_row = u->dis.n;
		body.n_col = u->dis.width;
		body.row = dis_row;
		body.user = &u->dis;
	} else {
		u->body.tab = u->tab;
		kv_cfgbody_size(&u->body, u->tab, &body.n_row, &body.n_col);
		body.row = kv_cfgbody_row;
		body.user = &u->body;
	}
	/* the box keeps its size from tab to tab: the larger of the two tabs the engine's answer fills */
	kv_cfgbody_size(&u->body, KV_CFG_TAB_OVERVIEW, &ov_r, &ov_c);
	kv_cfgbody_size(&u->body, KV_CFG_TAB_GRAPH, &gr_r, &gr_c);
	memset(&in, 0, sizeof in);
	in.body = &body;
	in.tab = cfg_tab_title;
	in.n_tab = KV_CFG_TABS;
	in.tab_sel = (int)u->tab;
	in.want_w = (int)(ov_c > gr_c ? ov_c : gr_c) + 5;     /* the frame, the margin column of the body and the widest row: the longest line was the calls title, which hid that the margin was not counted */
	in.want_h = (int)(ov_r > gr_r ? ov_r : gr_r) + 2;
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
	if (kv_main_key(v, &u->m, k, 1))
		return 1;
	if (k == 27 || k == '\r' || k == '\n')
		cfgd_close(v);
	return 1;
}
