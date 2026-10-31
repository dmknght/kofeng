/*
 * kx_tagdata - what Manage > Syndromes says, as DATA (kofexamine/kv_tagdata.c), asserted on with no viewer and no screen. The units under
 * test are INCLUDED (kv_tagdata.c and the shared table renderer and dialog frame it uses).
 *
 *   CELLS    name, activities and objects as the engine's words (capitalised for display: Scan, C2, Network) in the engine's order, comma-joined; an empty object set is ""; every
 *            activity and every object fit the cell buffers; a buffer too small cuts and terminates; a bad index is blank
 *   LISTS    9 activities and 8 objects, the engine's words, the bit of an item is its engine value (never its position)
 *   TABLE    rendered with no heading: one line a row; for every width of the box and every sideways offset the click extent of each cell
 *            (kv_tag_hit_of) equals, character for character, the run the renderer drew for that cell (an oracle read off the line)
 *   EMPTY    an empty objects cell answers over KV_TAG_EMPTY_HIT columns from its start, clipped by the scroll; an empty cell never answers
 *            past its width
 *   SIZE     the content size grows with the longest row up to the shared caps, never below the minimum
 *   BUTTON   the label and the shared row: [ Add Syndrome ] left, [ Save ] and [ Discard ] right, greyed while not dirty
 *   MENU     toggling flips exactly that bit, twice restores; the last activity cannot be taken away (the engine says so); objects may
 *            all be cleared; an unknown tag or item changes nothing
 *   ERROR    one line per status, a full catalog names its limit
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include "../../kofexamine/kofview.h"
#include "../../kofexamine/kv_tagdata.h"
#include "../../kofexamine/kv_formdata.h"

#include "../../kofexamine/kv_table.c"
#include "../../kofexamine/kv_dash_dialog.c"
#include "../../kofexamine/kv_tagdata.c"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define SCAN (1u << KOF_DISEASE_ACT_SCAN)
#define STEAL (1u << KOF_DISEASE_ACT_STEAL)
#define EXEC (1u << KOF_DISEASE_ACT_EXECUTION)
#define NET (1u << KOF_DISEASE_OBJ_NETWORK)
#define FIL (1u << KOF_DISEASE_OBJ_FILE)

static struct kof_tagcat_tag T[KV_TAG_MAX];
static struct kof_tagcat C;

static void fresh(void)
{
	memset(T, 0, sizeof T);
	kof_tagcat_init(&C, T, KV_TAG_MAX);
}

static void plain(const char *s, char *out, size_t cap)
{
	size_t n = 0;

	while (*s) {
		if (*s == '\033') {
			while (*s && *s != 'm')
				s++;
			if (*s)
				s++;
			continue;
		}
		if (n + 1 < cap)
			out[n++] = *s;
		s++;
	}
	out[n] = 0;
}

static void lists(void)
{
	struct kv_pick a = kv_tag_acts(), o = kv_tag_objs();
	char b[KV_PICK_LABEL], w[KV_PICK_LABEL];
	uint32_t i;

	CK(a.n == 9u && o.n == 8u);
	for (i = 0; i < a.n; i++) {
		kof_disease_display(kof_disease_act_name(a.bit(i)), w, sizeof w);      /* the engine's one display function */
		CK(a.bit(i) == (uint32_t)KOF_DISEASE_ACT_SCAN + i && !strcmp(a.label(i, b), w) && strcmp(b, kof_disease_act_name(a.bit(i))) != 0);
	}
	for (i = 0; i < o.n; i++) {
		kof_disease_display(kof_disease_obj_name(o.bit(i)), w, sizeof w);
		CK(o.bit(i) == (uint32_t)KOF_DISEASE_OBJ_NETWORK + i && !strcmp(o.label(i, b), w) && b[0] >= 'A' && b[0] <= 'Z');
	}
	CK(!strcmp(a.label(0, b), "Scan") && !strcmp(a.label(4, b), "Escalation") && !strcmp(a.label(7, b), "C2") &&
	   !strcmp(a.label(8, b), "Destruction") && !strcmp(o.label(0, b), "Network") && !strcmp(o.label(7, b), "Input"));
	CK(kv_pick_has(&a, SCAN, 0) && !kv_pick_has(&a, SCAN, 1) && !kv_pick_has(&a, ~0u, 9) && kv_pick_flip(&a, 0, 9) == 0u);
	CK(kv_pick_flip(&a, SCAN, 0) == 0u && kv_pick_flip(&a, 0, 8) == (1u << KOF_DISEASE_ACT_DESTRUCTION));
	CK(kv_tag_list_of(KV_TAG_ACTS).n == 9u && kv_tag_list_of(KV_TAG_OBJS).n == 8u);
}

static void cells(void)
{
	char nm[KOF_TAGCAT_NAME_MAX + 8], ac[192], ob[192];
	uint32_t i;

	fresh();
	CK(kof_tagcat_add(&C, "recon", SCAN | STEAL, NET | FIL, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "x", EXEC, 0, NULL) == KOF_TAGCAT_OK);
	kv_tag_cells(&C, 0, nm, sizeof nm, ac, sizeof ac, ob, sizeof ob);
	CK(!strcmp(nm, "recon") && !strcmp(ac, "Scan, Steal") && !strcmp(ob, "Network, File"));   /* the engine's order */
	kv_tag_cells(&C, 1, nm, sizeof nm, ac, sizeof ac, ob, sizeof ob);
	CK(!strcmp(nm, "x") && !strcmp(ac, "Execution") && ob[0] == 0);
	kv_tag_cells(&C, 2, nm, sizeof nm, ac, sizeof ac, ob, sizeof ob);
	CK(!nm[0] && !ac[0] && !ob[0]);
	CK(!strcmp(kv_tag_label_add(), "[ Add Syndrome ]"));
	/* every activity and every object: the longest cells still fit their buffers */
	fresh();
	CK(kof_tagcat_add(&C, "all", kof_tagcat_act_mask_all(), kof_tagcat_obj_mask_all(), NULL) == KOF_TAGCAT_OK);
	kv_tag_cells(&C, 0, nm, sizeof nm, ac, sizeof ac, ob, sizeof ob);
	CK(!strncmp(ac, "Scan, Steal, Execution", 22) && strstr(ac, "C2, Destruction") && strlen(ac) < sizeof ac - 1);
	CK(!strncmp(ob, "Network, File, Memory", 21) && strstr(ob, "Input") && strlen(ob) < sizeof ob - 1);
	for (i = 0; i < 9; i++) {
		char w[KV_PICK_LABEL];

		kof_disease_display(kof_tagcat_act_name(i), w, sizeof w);
		CK(strstr(ac, w));
	}
	/* a buffer too small cuts and terminates */
	kv_tag_cells(&C, 0, nm, 2, ac, 6, ob, 4);
	CK(strlen(nm) == 1 && strlen(ac) == 5 && strlen(ob) == 3);
}

/* The oracle's table: each cell is a run of its own letter, so the extent of a cell on a line is the run the renderer put there. */
static void x_cell(void *user, uint32_t row, const char **out)
{
	struct kv_tag_tab *tt = user;
	size_t a, b, c, d;

	tag_cell(user, row, out);
	a = strlen(tt->name);
	b = strlen(tt->acts);
	c = strlen(tt->objs);
	d = strlen(tt->comment);
	memset(tt->comment, 'C', d);
	memset(tt->name, 'N', a);
	memset(tt->acts, 'A', b);
	memset(tt->objs, 'O', c);
}

static void table(void)
{
	static char line[8][KV_TAB_LINE];
	struct kv_tag_tab tt;
	struct kv_tab_spec t, tx;
	struct kv_tab_geo g;
	struct kv_tab_in in;
	uint32_t w, h, i, hits = 0;

	fresh();
	CK(kof_tagcat_add(&C, "recon", SCAN | STEAL, NET, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "persist-x", EXEC, 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_set_comment(&C, 0, "scans hosts") == KOF_TAGCAT_OK);
	kv_tag_spec(&t, &tt, &C);
	CK(t.n_row == 2 && t.n_col == 4 && t.col[0] == NULL && t.flex == KV_TAG_COL_COMMENT);
	/* "persist-x", "Scan, Steal", "Network" and the gap before the comment column; the comment column takes the rest */
	CK(t.width[0] == 9 + KV_TAG_GAP && t.width[1] == 11 + KV_TAG_GAP && t.width[2] == 12);   /* 7 + the gap is 11: never under the 12 columns of an empty cell */
	tx = t;
	tx.cell = x_cell;
	for (w = 3; w <= 60; w++)
		for (h = 0; h <= 40; h++) {
			in.row0 = 0;
			in.rows = 8;
			in.hoff = h;
			in.width = (int)w;
			in.margin = 1;
			in.heading = 0;
			CK(kv_tab_render(&tx, &in, line, 8, &g, NULL) == 2 && !g.has_head && g.shown == 2);
			for (i = 0; i < 2; i++) {
				char p[KV_TAB_LINE];
				int c;

				plain(line[i], p, sizeof p);
				for (c = 0; c < (int)w + 4; c++) {
					int ch = c < (int)strlen(p) ? p[c] : ' ';
					enum kv_tag_hit want = ch == 'N' ? KV_TAG_HIT_NAME : ch == 'A' ? KV_TAG_HIT_ACTS : ch == 'O' ? KV_TAG_HIT_OBJS
											      : KV_TAG_HIT_NONE;   /* 'C', the comment, opens nothing */
					enum kv_tag_hit got = kv_tag_hit_of(&C, i, &g, c);

					/* the empty objects cell of row 1 answers over its own columns and nothing is drawn there */
					if (i == 1 && got == KV_TAG_HIT_OBJS && want == KV_TAG_HIT_NONE)
						continue;
					if (got != want) {
						printf("  width %u hoff %u row %u col %d want %d got %d line [%s]\n", w, h, i, c, (int)want, (int)got, p);
						CK(0);
					}
					hits += want != KV_TAG_HIT_NONE;
				}
			}
		}
	CK(hits > 1000);
	/* the comment cells: row 0 holds "scans hosts", row 1 is empty and has no cell to hit */
	{
		char cm[KOF_TAGCAT_COMMENT_MAX + 1];

		kv_tag_comment_cell(&C, 0, cm, sizeof cm);
		CK(!strcmp(cm, "scans hosts"));
		kv_tag_comment_cell(&C, 1, cm, sizeof cm);
		CK(!cm[0]);
		kv_tag_comment_cell(&C, 7, cm, sizeof cm);
		CK(!cm[0]);
		kv_tag_comment_cell(&C, 0, cm, 4);
		CK(!strcmp(cm, "sca"));
	}
	CK(kv_tag_hit_of(&C, 5, &g, 3) == KV_TAG_HIT_NONE);
}

static void empty_cell(void)
{
	struct kv_tag_tab tt;
	struct kv_tab_spec t;
	static char line[8][KV_TAB_LINE];
	struct kv_tab_geo g;
	struct kv_tab_in in;
	int c, n = 0, x0 = -1;

	fresh();
	CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	kv_tag_spec(&t, &tt, &C);
	in.row0 = 0;
	in.rows = 8;
	in.hoff = 0;
	in.width = 70;
	in.margin = 1;
	in.heading = 0;
	kv_tab_render(&t, &in, line, 8, &g, NULL);
	for (c = 0; c < 80; c++)
		if (kv_tag_hit_of(&C, 0, &g, c) == KV_TAG_HIT_OBJS) {
			x0 = x0 < 0 ? c : x0;
			n++;
		}
	CK(n == KV_TAG_EMPTY_HIT && x0 == g.cx[KV_TAG_COL_OBJS]);
	/* narrower than the empty width: only what is visible answers */
	in.width = g.cx[KV_TAG_COL_OBJS] + 5;
	kv_tab_render(&t, &in, line, 8, &g, NULL);
	for (n = 0, c = 0; c < 80; c++)
		n += kv_tag_hit_of(&C, 0, &g, c) == KV_TAG_HIT_OBJS;
	CK(n > 0 && n <= g.cw[KV_TAG_COL_OBJS] && n < KV_TAG_EMPTY_HIT);
}

static void size(void)
{
	int w0, h0, w1, h1, w2, h2;
	char big[KOF_TAGCAT_NAME_MAX + 1];
	uint32_t i;

	fresh();
	kv_tag_content_size(&C, &w0, &h0);
	CK(w0 == kv_dd_catalog_limits.min_w + 6 && h0 == kv_dd_catalog_limits.min_h);
	memset(big, 'n', 60);
	big[60] = 0;
	CK(kof_tagcat_add(&C, big, kof_tagcat_act_mask_all(), kof_tagcat_obj_mask_all(), NULL) == KOF_TAGCAT_OK);
	kv_tag_content_size(&C, &w1, &h1);
	CK(h1 == h0 && w1 > w0 && w1 <= KV_DD_CATALOG_WIDTH_MAX);
	CK(w1 == KV_DD_CATALOG_WIDTH_MAX);                  /* 60 + the activities + the objects need more than the cap */
	/* the longest comment never widens the dialog past the catalog limit, however many columns it holds */
	{
		char cm[KOF_TAGCAT_COMMENT_MAX + 1];
		int w3, h3;

		fresh();
		CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK);
		kv_tag_content_size(&C, &w3, &h3);
		memset(cm, 'c', KOF_TAGCAT_COMMENT_MAX);
		cm[KOF_TAGCAT_COMMENT_MAX] = 0;
		CK(kof_tagcat_set_comment(&C, 0, cm) == KOF_TAGCAT_OK);
		kv_tag_content_size(&C, &w3, &h3);
		CK(w3 == KV_DD_CATALOG_WIDTH_MAX && h3 == h0);
		CK(kof_tagcat_set_comment(&C, 0, "short") == KOF_TAGCAT_OK);
		kv_tag_content_size(&C, &w3, &h3);
		CK(w3 == w0);                                  /* a short one fits inside the minimum */
		fresh();
		CK(kof_tagcat_add(&C, big, kof_tagcat_act_mask_all(), kof_tagcat_obj_mask_all(), NULL) == KOF_TAGCAT_OK);
	}
	for (i = 0; i < 40; i++) {
		char nm[8];

		snprintf(nm, sizeof nm, "t%u", (unsigned)i);
		CK(kof_tagcat_add(&C, nm, SCAN, 0, NULL) == KOF_TAGCAT_OK);
	}
	kv_tag_content_size(&C, &w2, &h2);
	CK(h2 == KV_DD_CATALOG_HEIGHT_MAX && w2 == w1);
}

static void button(void)
{
	struct kv_dd_geo g;
	struct kv_dd_btn b[KV_DD_BTN_COUNT];
	uint32_t n;

	memset(&g, 0, sizeof g);
	g.ok = 1;
	g.body_y0 = 3;
	g.body_rows = 10;
	g.body_x0 = 4;
	g.body_cols = 50;
	n = kv_dd_buttons(&g, kv_tag_label_add(), 0, b);
	CK(n == 3 && !strcmp(b[0].label, "[ Add Syndrome ]") && b[0].id == KV_DD_BTN_ADD);
	CK(b[0].enabled && !b[1].enabled && !b[2].enabled);
	CK(b[0].y == 12 && b[0].x0 == 6 && b[0].x1 - b[0].x0 + 1 == 16 && b[2].x1 == 4 + 50 - 2);
	CK(kv_dd_btn_at(b, n, 12, b[0].x0) == (int)KV_DD_BTN_ADD && kv_dd_btn_at(b, n, 12, b[1].x0) == -1 &&
	   kv_dd_btn_at(b, n, 12, b[2].x0) == -1);
	CK(kv_dd_buttons(&g, kv_tag_label_add(), 1, b) == 3 && kv_dd_btn_at(b, 3, 12, b[1].x0) == (int)KV_DD_BTN_SAVE);
	g.body_cols = 18;
	CK(kv_dd_buttons(&g, kv_tag_label_add(), 0, b) == 1);
	g.body_cols = 17;
	CK(kv_dd_buttons(&g, kv_tag_label_add(), 0, b) == 0);
}

static void menu(void)
{
	uint32_t i;

	fresh();
	CK(kof_tagcat_add(&C, "a", SCAN | STEAL, NET, NULL) == KOF_TAGCAT_OK);
	for (i = 0; i < 9; i++)
		CK(kv_tag_menu_checked(&C, 0, KV_TAG_ACTS, i) == (i == 0 || i == 1));
	for (i = 0; i < 8; i++)
		CK(kv_tag_menu_checked(&C, 0, KV_TAG_OBJS, i) == (i == 0));
	CK(kv_tag_menu_toggle(&C, 0, KV_TAG_ACTS, 2) == KOF_TAGCAT_OK && C.tag[0].acts == (SCAN | STEAL | EXEC));
	CK(kv_tag_menu_toggle(&C, 0, KV_TAG_ACTS, 2) == KOF_TAGCAT_OK && C.tag[0].acts == (SCAN | STEAL));   /* twice restores */
	CK(kv_tag_menu_toggle(&C, 0, KV_TAG_OBJS, 1) == KOF_TAGCAT_OK && C.tag[0].objs == (NET | FIL));
	CK(kv_tag_menu_toggle(&C, 0, KV_TAG_OBJS, 1) == KOF_TAGCAT_OK && kv_tag_menu_toggle(&C, 0, KV_TAG_OBJS, 0) == KOF_TAGCAT_OK &&
	   C.tag[0].objs == 0u);                                                                             /* objects may all go */
	CK(kv_tag_menu_toggle(&C, 0, KV_TAG_ACTS, 0) == KOF_TAGCAT_OK && kv_tag_menu_toggle(&C, 0, KV_TAG_ACTS, 1) == KOF_TAGCAT_NO_ACTIVITY &&
	   C.tag[0].acts == STEAL);                                                                          /* the last one stays */
	CK(kv_tag_menu_toggle(&C, 7, KV_TAG_ACTS, 0) == KOF_TAGCAT_NO_TAG && !kv_tag_menu_checked(&C, 7, KV_TAG_ACTS, 0));
	{
		uint32_t rev = C.rev;

		CK(kv_tag_menu_toggle(&C, 0, KV_TAG_ACTS, 99) == KOF_TAGCAT_OK && C.tag[0].acts == STEAL && !kv_tag_menu_checked(&C, 0, KV_TAG_ACTS, 99));
		(void)rev;
	}
}

static void errors(void)
{
	char s[96];
	int st;

	kv_tag_error_text(&C, KOF_TAGCAT_OK, s, sizeof s);
	CK(s[0] == 0);
	CK(strlen(kof_tagcat_status_text(KOF_TAGCAT_BAD_CHAR)) <= KV_FORM_ERR_COLS);
	for (st = 1; st <= (int)KOF_TAGCAT_NO_TAG; st++) {
		kv_tag_error_text(&C, (enum kof_tagcat_status)st, s, sizeof s);
		CK(s[0] && strlen(s) <= KV_FORM_ERR_COLS);       /* fits the error row of the form */
	}
	kv_tag_error_text(&C, KOF_TAGCAT_NO_ACTIVITY, s, sizeof s);
	CK(!strcmp(s, "Select at least one Activity"));
	fresh();
	kv_tag_error_text(&C, KOF_TAGCAT_FULL, s, sizeof s);
	CK(strstr(s, "64") != NULL);
}

int main(void)
{
	lists();
	cells();
	table();
	empty_cell();
	size();
	button();
	menu();
	errors();
	printf("kx_tagdata: %d failure(s)\n", fails);
	return fails != 0;
}
