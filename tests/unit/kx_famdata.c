/*
 * kx_famdata - what Manage > Pathogens says, as DATA (kofexamine/kv_famdata.c), asserted on with no viewer and no screen. The
 * units under test are INCLUDED (kv_famdata.c, and the table renderer it measures with).
 *
 *   ROWS     a family line, its variants (creation order, whatever order they were added in), its add-variant line, then the next
 *            family; an empty catalog has no rows
 *   CELLS    the family row carries no types; a variant's name is indented and its types are the engine's names in the engine's order,
 *            "(none)" when it has none; the add-variant cell is the indent and the button label; the longest name and every type fit
 *   TABLE    rendered with no heading: one line a row; the add-variant button's span from the returned geometry equals, for every width
 *            of the box and every sideways offset, the span of the characters drawn on that line (an oracle read off the line); a click
 *            on the types column of a variant row is column 1
 *   BUTTON   the last body row: [ Add family ] left, [ Save ] and [ Discard ] right (greyed, answer nothing), fewer in a narrow box,
 *            none in a box too small or not drawn
 *   MENU     one item per selectable type, no Packer, the labels are the engine's; toggling flips exactly that bit, twice restores, an
 *            unknown variant is refused; the Add variant dialog's mask helpers
 *   ERROR    one line per status, a full catalog names its limits
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include "../../kofexamine/kofview.h"
#include "../../kofexamine/kv_famdata.h"

#include "../../kofexamine/kv_table.c"
#include "../../kofexamine/kv_famdata.c"

static int fails;

#define BOT (1u << KOF_MALTYPE_BOTNET)
#define TRO (1u << KOF_MALTYPE_TROJAN)
#define VIR (1u << KOF_MALTYPE_VIRUS)

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static struct kof_famcat_fam F[KV_FAM_MAX_FAMILY];
static struct kof_famcat_var V[KV_FAM_MAX_VARIANT];
static struct kof_famcat C;
static struct kv_fam_row R[KV_FAM_MAX_ROW];

static void fresh(void)
{
	memset(F, 0, sizeof F);
	memset(V, 0, sizeof V);
	kof_famcat_init(&C, F, KV_FAM_MAX_FAMILY, V, KV_FAM_MAX_VARIANT);
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

static void model(void)
{
	uint32_t f;
	uint32_t n;

	fresh();
	CK(kv_fam_rows(&C, R, KV_FAM_MAX_ROW) == 0);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "Gafgyt", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, BOT | TRO, 0, NULL) == KOF_FAMCAT_OK);
	n = kv_fam_rows(&C, R, KV_FAM_MAX_ROW);
	CK(n == 7);
	{
		static const enum kv_fam_kind kind[] = { KV_FAM_FAMILY, KV_FAM_VARIANT, KV_FAM_VARIANT, KV_FAM_ADDVAR, KV_FAM_FAMILY,
							 KV_FAM_VARIANT, KV_FAM_ADDVAR };
		static const int32_t var[] = { -1, 0, 2, -1, -1, 1, -1 };
		static const uint32_t fam[] = { 0, 0, 0, 0, 1, 1, 1 };
		uint32_t i;

		for (i = 0; i < 7; i++)
			CK(R[i].kind == kind[i] && R[i].variant == var[i] && R[i].family == fam[i]);
	}
	/* a short buffer: the total, nothing past it */
	memset(R, 0xee, sizeof R);
	CK(kv_fam_rows(&C, R, 2) == 7 && R[2].family == 0xeeeeeeeeu);
}

static void cells(void)
{
	char nm[KOF_FAMCAT_NAME_MAX + 8], ty[128], cm[KOF_FAMCAT_COMMENT_MAX + 1], big[KOF_FAMCAT_NAME_MAX + 1];
	uint32_t f;

	fresh();
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, BOT | TRO, 0, NULL) == KOF_FAMCAT_OK);
	kv_fam_rows(&C, R, KV_FAM_MAX_ROW);
	kv_fam_cells(&C, &R[0], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(nm, "Mirai") && ty[0] == 0);
	kv_fam_cells(&C, &R[1], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(nm, "  Mirai_A") && !strcmp(ty, "Botnet"));
	kv_fam_cells(&C, &R[2], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(nm, "  Mirai_B") && !strcmp(ty, "Trojan, Botnet"));   /* the engine's order, not the order ticked */
	C.var[0].types = 0;                                                /* the library never makes this; the cell still says it */
	kv_fam_cells(&C, &R[1], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(ty, "(none)"));
	kv_fam_cells(&C, &R[3], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(nm, "  [ Add variant ]") && ty[0] == 0);
	CK(!strcmp(kv_fam_label_add_variant(), "[ Add variant ]") && !strcmp(kv_fam_label_add_family(), "[ Add family ]"));
	/* the longest name and every type */
	fresh();
	memset(big, 'n', 60);
	big[60] = 0;
	CK(kof_famcat_add_family(&C, big, NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, kof_famcat_type_mask_all(), 0, NULL) == KOF_FAMCAT_OK);
	kv_fam_rows(&C, R, KV_FAM_MAX_ROW);
	kv_fam_cells(&C, &R[2], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(strlen(nm) == 64 && !strncmp(nm + 2, big, 60) && !strcmp(nm + 62, "_B"));
	CK(!strncmp(ty, "Virus, Trojan, Rootkit", 22) && strstr(ty, "Hacktool") && !strstr(ty, "Packer") && strlen(ty) < sizeof ty - 1);
	/* a buffer too small cuts and terminates */
	kv_fam_cells(&C, &R[2], nm, 8, ty, 6, cm, 4);
	CK(strlen(nm) == 7 && strlen(ty) == 5);
}

/* The oracle's table: the same rows, but the add-variant button is drawn as a run of X, so the span of the button on a line is the
 * run of X the renderer put there and no assumption about spaces inside the label is made. */
static void x_cell(void *user, uint32_t row, const char **out)
{
	struct kv_fam_tab *ft = user;

	fam_cell(user, row, out);
	if (ft->row[row].kind == KV_FAM_ADDVAR)
		snprintf(ft->name, sizeof ft->name, "%*s%.*s", (int)KV_FAM_INDENT, "", (int)strlen(kv_fam_label_add_variant()),
			 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
}

static void table(void)
{
	struct kv_fam_tab ft;
	struct kv_tab_spec t, tx;
	static char line[8][KV_TAB_LINE];
	struct kv_tab_geo g;
	struct kv_tab_in in;
	uint32_t f, n, w, h, i, hits = 0;

	fresh();
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	n = kv_fam_rows(&C, R, KV_FAM_MAX_ROW);
	kv_fam_spec(&t, &ft, &C, R, n);
	CK(t.n_row == 4 && t.n_col == 3 && t.col[0] == NULL && t.col[1] == NULL && t.col[2] == NULL);
	CK(t.width[0] == 17 && t.width[1] == 6 + KV_FAM_COMMENT_GAP && t.width[2] == 0 && t.flex == KV_FAM_COL_COMMENT);          /* "  [ Add variant ]", "Botnet" */
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
			CK(kv_tab_render(&t, &in, line, 8, &g, NULL) == 4 && !g.has_head && g.shown == 4);
			CK(kv_tab_render(&tx, &in, line, 8, &g, NULL) == 4);
			for (i = 0; i < 4; i++) {
				char p[KV_TAB_LINE];
				int c;

				plain(line[i], p, sizeof p);
				if (R[i].kind != KV_FAM_ADDVAR)
					continue;
				for (c = 0; c < (int)w + 4; c++) {
					int want = p[c] == 'X' && c < (int)strlen(p);

					if (kv_fam_button_at(&g, c) != want) {
						printf("  width %u hoff %u col %d want %d line [%s]\n", w, h, c, want, p);
						CK(0);
					}
					hits += (uint32_t)want;
				}
			}
		}
	CK(hits > 1000);
	/* a click on the types column of a variant row is column 1, on the button row column 0 */
	in.row0 = 0;
	in.rows = 8;
	in.hoff = 0;
	in.width = 60;
	in.margin = 1;
	in.heading = 0;
	kv_tab_render(&t, &in, line, 8, &g, NULL);
	{
		uint32_t row;
		int k;

		CK(kv_tab_hit(&g, 1, g.cx[1], &row, &k) == 2 && row == 1 && k == 1 && R[row].kind == KV_FAM_VARIANT);
		CK(kv_tab_hit(&g, 3, g.cx[0] + 2, &row, &k) == 2 && row == 3 && k == 0 && R[row].kind == KV_FAM_ADDVAR);
		CK(kv_fam_button_at(&g, g.cx[0] + 2) && !kv_fam_button_at(&g, g.cx[0] + 1) &&
		   kv_fam_button_at(&g, g.cx[0] + 2 + 14) && !kv_fam_button_at(&g, g.cx[0] + 2 + 15));
	}
}

static void button(void)
{
	struct kv_dd_geo g;
	struct kv_fam_btn b[KV_FAM_BTN_COUNT];
	uint32_t n, i;

	memset(&g, 0, sizeof g);
	g.ok = 1;
	g.body_y0 = 3;
	g.body_rows = 10;
	g.body_x0 = 4;
	g.body_cols = 50;
	n = kv_fam_buttons(&g, 0, b);
	CK(n == 3);
	CK(b[0].id == KV_FAM_BTN_ADD_FAMILY && b[1].id == KV_FAM_BTN_SAVE && b[2].id == KV_FAM_BTN_DISCARD);
	for (i = 0; i < n; i++)
		CK(b[i].y == 12 && b[i].x1 - b[i].x0 + 1 == (int)strlen(b[i].label) && b[i].x0 >= 4 && b[i].x1 < 4 + 50);
	CK(b[0].x0 == 6 && b[0].x1 < b[1].x0 && b[1].x1 < b[2].x0 && b[2].x1 == 4 + 50 - 2);   /* Add family left, Save and Discard right */
	CK(b[0].enabled && !b[1].enabled && !b[2].enabled);
	/* Save and Discard follow the dirty flag: enabled iff dirty, and then they answer by id on their own columns */
	CK(kv_fam_buttons(&g, 1, b) == 3 && b[0].enabled && b[1].enabled && b[2].enabled);
	CK(kv_fam_btn_at(b, 3, 12, b[1].x0) == (int)KV_FAM_BTN_SAVE && kv_fam_btn_at(b, 3, 12, b[1].x1) == (int)KV_FAM_BTN_SAVE &&
	   kv_fam_btn_at(b, 3, 12, b[2].x0) == (int)KV_FAM_BTN_DISCARD && kv_fam_btn_at(b, 3, 12, b[2].x1 + 1) == -1);
	CK(kv_fam_buttons(&g, 0, b) == 3 && !b[1].enabled && !b[2].enabled && kv_fam_btn_at(b, 3, 12, b[1].x0) == -1);
	/* a greyed button answers nothing; an enabled one answers by id, on its own columns only */
	for (i = 0; i < 60; i++) {
		int want = i >= (uint32_t)b[0].x0 && i <= (uint32_t)b[0].x1 ? (int)KV_FAM_BTN_ADD_FAMILY : -1;

		CK(kv_fam_btn_at(b, n, 12, (int)i) == want);
		CK(kv_fam_btn_at(b, n, 11, (int)i) == -1 && kv_fam_btn_at(b, n, 13, (int)i) == -1);
	}
	/* narrower: only Add family; narrower still, none; too short or not ok, none */
	g.body_cols = 40;
	CK(kv_fam_buttons(&g, 0, b) == 1 && b[0].id == KV_FAM_BTN_ADD_FAMILY);
	g.body_cols = 15;
	CK(kv_fam_buttons(&g, 0, b) == 0);
	g.body_cols = 16;
	CK(kv_fam_buttons(&g, 0, b) == 1);
	g.body_cols = 50;
	g.body_rows = 2;
	CK(kv_fam_buttons(&g, 0, b) == 0);
	g.body_rows = 10;
	g.ok = 0;
	CK(kv_fam_buttons(&g, 0, b) == 0);
}

static void menu(void)
{
	uint32_t i, f, all = 0;

	fresh();
	CK(kof_famcat_add_family(&C, "Mirai", NULL, VIR, &f) == KOF_FAMCAT_OK);
	CK(kv_fam_menu_count() == (uint32_t)KOF_MALTYPE_COUNT - 1u && kv_fam_menu_count() <= KV_FAM_TICKS);
	for (i = 0; i < kv_fam_menu_count(); i++) {
		uint32_t j;

		CK(strcmp(kv_fam_menu_label(i), "Packer") != 0);
		if (i == 0) {
			/* the only type cannot be unticked: a variant has at least one */
			CK(kv_fam_menu_checked(&C, 0, 0) && kv_fam_menu_toggle(&C, 0, 0) == KOF_FAMCAT_NO_TYPE && kv_fam_menu_checked(&C, 0, 0));
			all = kv_fam_mask_flip(all, i);
			continue;
		}
		CK(!kv_fam_menu_checked(&C, 0, i));
		CK(kv_fam_menu_toggle(&C, 0, i) == KOF_FAMCAT_OK && kv_fam_menu_checked(&C, 0, i));
		for (j = 0; j < kv_fam_menu_count(); j++)
			CK(kv_fam_menu_checked(&C, 0, j) == (j == i || j == 0));
		CK(kv_fam_menu_toggle(&C, 0, i) == KOF_FAMCAT_OK && !kv_fam_menu_checked(&C, 0, i) && C.var[0].types == VIR);
		all = kv_fam_mask_flip(all, i);
	}
	CK(all == kof_famcat_type_mask_all());
	CK(kv_fam_mask_flip(0, kv_fam_menu_count()) == 0 && !kv_fam_mask_has(~0u, kv_fam_menu_count()));
	CK(kv_fam_menu_toggle(&C, 5, 0) == KOF_FAMCAT_NO_FAMILY && !kv_fam_menu_checked(&C, 5, 0));
	CK(kv_fam_menu_toggle(&C, 0, kv_fam_menu_count()) == KOF_FAMCAT_OK && C.var[0].types == VIR);   /* past the list: no bit */
	/* two variants of a family may not end up with one set: {Virus, Trojan} minus Trojan is the first variant's set */
	CK(kof_famcat_add_variant(&C, 0, NULL, VIR | TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kv_fam_menu_toggle(&C, 1, 1) == KOF_FAMCAT_DUP_TYPES && C.var[1].types == (VIR | TRO));
}

/* A click opens something only over the text of a cell (first to last character, indent and padding excluded), clipped to what the
 * sideways scroll shows; an empty comment cell answers over KV_FAM_EMPTY_HIT columns. The positions are the geometry's own. */
static void click_extents(uint32_t n)
{
	static char L[8][KV_TAB_LINE];
	struct kv_fam_tab ft;
	struct kv_tab_spec t;
	struct kv_tab_in in = { 0, 8, 0, 60, 1, 0 };
	struct kv_tab_geo g;
	uint32_t var = 99;
	int c0, c1, c2;

	kv_fam_spec(&t, &ft, &C, R, n);
	t.n_sticky = 1;
	kv_tab_render(&t, &in, L, 8, &g, NULL);
	c0 = g.cx[0];
	c1 = g.cx[1];
	c2 = g.cx[2];
	/* a family row: its name only ("Mirai", 5 characters); no types, no comment */
	CK(kv_fam_hit_of(&C, &R[0], &g, c0, &var) == KV_FAM_HIT_FAMILY && var == 0);
	CK(kv_fam_hit_of(&C, &R[0], &g, c0 + 4, &var) == KV_FAM_HIT_FAMILY);
	CK(kv_fam_hit_of(&C, &R[0], &g, c0 - 1, &var) == KV_FAM_HIT_NONE && kv_fam_hit_of(&C, &R[0], &g, c0 + 5, &var) == KV_FAM_HIT_NONE);
	CK(kv_fam_hit_of(&C, &R[0], &g, c1, &var) == KV_FAM_HIT_NONE && kv_fam_hit_of(&C, &R[0], &g, c2, &var) == KV_FAM_HIT_NONE);
	/* a variant row: "  Mirai_B" (the two indent columns are not text), "Trojan", "var note" (8 characters) */
	var = 99;
	CK(kv_fam_hit_of(&C, &R[2], &g, c0 + 1, &var) == KV_FAM_HIT_NONE && var == 99);
	CK(kv_fam_hit_of(&C, &R[2], &g, c0 + 2, &var) == KV_FAM_HIT_VARIANT && var == 1);
	CK(kv_fam_hit_of(&C, &R[2], &g, c0 + 8, &var) == KV_FAM_HIT_VARIANT);
	CK(kv_fam_hit_of(&C, &R[2], &g, c0 + 9, &var) == KV_FAM_HIT_NONE);       /* the gap after the name */
	CK(kv_fam_hit_of(&C, &R[2], &g, c1 - 1, &var) == KV_FAM_HIT_NONE);
	CK(kv_fam_hit_of(&C, &R[2], &g, c1, &var) == KV_FAM_HIT_TYPES && var == 1);
	CK(kv_fam_hit_of(&C, &R[2], &g, c1 + 5, &var) == KV_FAM_HIT_TYPES);
	CK(kv_fam_hit_of(&C, &R[2], &g, c1 + 6, &var) == KV_FAM_HIT_NONE);       /* the padding and the gap of the types column */
	CK(kv_fam_hit_of(&C, &R[2], &g, c2 - 1, &var) == KV_FAM_HIT_NONE);
	CK(kv_fam_hit_of(&C, &R[2], &g, c2, &var) == KV_FAM_HIT_COMMENT && var == 1);
	CK(kv_fam_hit_of(&C, &R[2], &g, c2 + 7, &var) == KV_FAM_HIT_COMMENT);
	CK(kv_fam_hit_of(&C, &R[2], &g, c2 + 8, &var) == KV_FAM_HIT_NONE);       /* right of the text, still inside the flex column */
	CK(kv_fam_hit_of(&C, &R[2], &g, g.width - 1, &var) == KV_FAM_HIT_NONE);
	CK(kv_fam_hit_of(&C, &R[2], &g, -1, &var) == KV_FAM_HIT_NONE && kv_fam_hit_of(&C, &R[2], &g, g.width, &var) == KV_FAM_HIT_NONE);
	/* the add-variant line opens nothing here (the button has its own test) */
	CK(kv_fam_hit_of(&C, &R[3], &g, c0 + 2, &var) == KV_FAM_HIT_NONE);
	/* an empty comment cell answers over KV_FAM_EMPTY_HIT columns from its start, and no further */
	CK(kof_famcat_set_comment(&C, 0, "") == KOF_FAMCAT_OK);
	kv_fam_spec(&t, &ft, &C, R, n);
	t.n_sticky = 1;
	kv_tab_render(&t, &in, L, 8, &g, NULL);
	c2 = g.cx[2];
	CK(kv_fam_hit_of(&C, &R[1], &g, c2, &var) == KV_FAM_HIT_COMMENT && var == 0);
	CK(kv_fam_hit_of(&C, &R[1], &g, c2 + KV_FAM_EMPTY_HIT - 1, &var) == KV_FAM_HIT_COMMENT);
	CK(kv_fam_hit_of(&C, &R[1], &g, c2 + KV_FAM_EMPTY_HIT, &var) == KV_FAM_HIT_NONE);
	CK(kv_fam_hit_of(&C, &R[0], &g, c2, &var) == KV_FAM_HIT_NONE);          /* a family has no comment, empty or not */
	/* scrolled sideways: a box too narrow for the table, panned: only the characters still shown answer */
	in.width = 24;
	in.hoff = 5;
	kv_tab_render(&t, &in, L, 8, &g, NULL);
	CK(g.hoff == 5 && g.cw[1] > 0 && g.cfrom[1] == 5);
	CK(kv_fam_hit_of(&C, &R[1], &g, g.cx[1], &var) == KV_FAM_HIT_TYPES);        /* the last character of "Botnet" */
	CK(kv_fam_hit_of(&C, &R[1], &g, g.cx[1] + 1, &var) == KV_FAM_HIT_NONE);
	CK(kv_fam_hit_of(&C, &R[1], &g, g.cx[0] + 2, &var) == KV_FAM_HIT_VARIANT);    /* the sticky name column does not move */
	in.hoff = 100;                                  /* clamped to the largest pan */
	kv_tab_render(&t, &in, L, 8, &g, NULL);
	CK(g.hoff == g.hmax && g.hmax > 5);
	CK(g.cw[1] == 0 || kv_fam_hit_of(&C, &R[1], &g, g.cx[1], &var) == KV_FAM_HIT_NONE);   /* the types text is scrolled out */
	CK(g.cw[2] > 0 && kv_fam_hit_of(&C, &R[2], &g, g.cx[2], &var) == KV_FAM_HIT_COMMENT);
}

/* The comment column: VARIANT rows only; the target of a click on it; the content size counts it. */
static void comment_column(void)
{
	char nm[KOF_FAMCAT_NAME_MAX + 8], ty[128], cm[KOF_FAMCAT_COMMENT_MAX + 1];
	struct kv_fam_tab ft;
	struct kv_tab_spec t;
	int w0, h0, w1, h1;
	uint32_t f, n;

	fresh();
	CK(kof_famcat_add_family(&C, "Mirai", "first note", BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, "var note", TRO, 0, NULL) == KOF_FAMCAT_OK);
	n = kv_fam_rows(&C, R, KV_FAM_MAX_ROW);
	kv_fam_cells(&C, &R[0], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(cm[0] == 0);                                        /* a family row has no comment */
	kv_fam_cells(&C, &R[1], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(cm, "first note") && !strcmp(ty, "Botnet"));
	kv_fam_cells(&C, &R[2], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(!strcmp(cm, "var note") && !strcmp(ty, "Trojan"));
	kv_fam_cells(&C, &R[3], nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
	CK(cm[0] == 0);                                        /* the add-variant line */
	kv_fam_spec(&t, &ft, &C, R, n);
	CK(t.n_col == 3 && t.width[2] == 10);                  /* "first note", measured */
	click_extents(n);
	/* the content size grows with the longest row, comment included; the layout clips it to the screen */
	kv_fam_content_size(&C, R, n, &w0, &h0);
	{
		char big[KOF_FAMCAT_COMMENT_MAX + 1];

		memset(big, 'c', KOF_FAMCAT_COMMENT_MAX);
		big[KOF_FAMCAT_COMMENT_MAX] = 0;
		CK(kof_famcat_set_comment(&C, 1, big) == KOF_FAMCAT_OK);
	}
	kv_fam_content_size(&C, R, n, &w1, &h1);
	CK(h1 == h0 && w1 > w0 && w1 >= 9 + 2 + 6 + 2 + 120);   /* "  Mirai_B", "Trojan", 120 characters */
}

static void errors(void)
{
	char s[160];
	int st;

	fresh();
	for (st = KOF_FAMCAT_OK; st <= KOF_FAMCAT_NO_FREE_LETTER; st++) {
		kv_fam_error_text(&C, (enum kof_famcat_status)st, s, sizeof s);
		CK((st == KOF_FAMCAT_OK) == (s[0] == 0));
	}
	kv_fam_error_text(&C, KOF_FAMCAT_FULL, s, sizeof s);
	CK(strstr(s, "64 families") && strstr(s, "256 variants"));
	kv_fam_error_text(&C, KOF_FAMCAT_VARIANT_NAME, s, sizeof s);
	CK(strstr(s, "over 60 characters"));            /* 256 variants: 2 letters, 63 - 1 - 2 */
	kv_fam_error_text(&C, KOF_FAMCAT_DUP_FAMILY, s, 5);
	CK(strlen(s) == 4);
}

int main(void)
{
	model();
	cells();
	table();
	button();
	menu();
	comment_column();
	errors();
	printf("kx_famdata: %d failure(s)\n", fails);
	return fails != 0;
}
