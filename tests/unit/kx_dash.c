/*
 * kx_dash - the dashboard's pages (kofexamine/kv_props_table.c, kv_props_tab.c), driven without a terminal. The units are INCLUDED into
 * this file, so the real page builders, the real table renderer and the real keys run; what the rest of the viewer would answer (the
 * row writer, the half of the symbol block a mask names, the field editor) is stubbed. The renderers themselves are kx_dashapi's.
 *
 *   BLOCK    a block of the overview: tones as colours, the producer's bound said
 *   LAYOUT   the Segments and Sections pages: the heading stays (fixed), the rows are the page's window, the entropy column, the
 *            object that is no ELF or PE says why once
 *   SYMBOLS  the filter line and table of the symbol pages, the four empty cases, a long name panned by the page's sideways offset
 *   KEYS     the filter field and the sideways pan act inside a symbol page; NO KEY CHANGES THE PAGE (owner decision: the strip is
 *            clicked) - Tab, Shift+Tab and the digits are tried on every page; the scroll is the page's
 *   STRIP    a click on a tab selects it and resets what belongs to the page it leaves; the page's scroll and pan are one function
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../kofexamine/kv.h"
#include "../lib/genome/hk.h"
#include "../../kofexamine/kv_props_private.h"
#include "../../libkofeng/analyzers/parsers/binaries/sym_pool.h"

#include "kx_dash_stubs.h"

#include "../../kofexamine/kv_dashdata.c"
#include "../../kofexamine/kv_table.c"
#include "../../kofexamine/kv_dash_dialog.c"
#include "../../kofexamine/kv_props_table.c"
#include "../../kofexamine/kv_props_tab.c"

/* ---- helpers ---------------------------------------------------------------------------------------------- */

/* The line as the terminal shows it: escape sequences gone. */
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

static void line_plain(uint32_t i, char *out, size_t cap)
{
	plain(g_prop[i].text, out, cap);
}

static void reset_page(void)
{
	g_n_prop = 0;
}

/* ================================================================================ RENDER */

static struct object OB;
static struct kof_parser FMT;
static struct kgenome_elf_info EI;
static struct hk_elf E;

static int find_line(const char *needle)
{
	uint32_t i;
	char t[PROP_W];

	for (i = 0; i < g_n_prop; i++) {
		line_plain(i, t, sizeof t);
		if (strstr(t, needle))
			return (int)i;
	}
	return -1;
}

/* A block of the overview is drawn label by label with its tones as colours, and the producer's bound is said. */
static void block_render(void)
{
	static struct dash_block b;
	char t[PROP_W];

	memset(&b, 0, sizeof b);
	snprintf(b.head, sizeof b.head, "Head");
	b.n = 2;
	snprintf(b.row[0].label, sizeof b.row[0].label, "name");
	b.row[0].label_tone = DT_DIM;
	b.row[0].n = 2;
	b.row[0].s[0].tone = DT_SIZE;  snprintf(b.row[0].s[0].text, sizeof b.row[0].s[0].text, "12");
	b.row[0].s[1].tone = DT_BAD;   snprintf(b.row[0].s[1].text, sizeof b.row[0].s[1].text, " bad");
	b.row[1].n = 1;                                      /* no label: just the span */
	b.row[1].s[0].tone = DT_WARN;  snprintf(b.row[1].s[0].text, sizeof b.row[1].s[0].text, "  lone");
	b.not_shown = 7;
	reset_page();
	prop_block(&b);
	CK(g_n_prop == 4u);                                  /* heading, two rows, the count, and no blank line before the first heading */
	line_plain(0, t, sizeof t);
	CK(strcmp(t, "Head") == 0);
	CK(strstr(g_prop[1].text, A_DIM) != NULL && strstr(g_prop[1].text, A_SIZE "12") != NULL && strstr(g_prop[1].text, A_BAD " bad") != NULL);
	line_plain(1, t, sizeof t);
	CK(strcmp(t, "  name        12 bad") == 0);
	line_plain(2, t, sizeof t);
	CK(strcmp(t, "  lone") == 0 && strstr(g_prop[2].text, A_WARN) != NULL);
	line_plain(3, t, sizeof t);
	CK(strcmp(t, "  7 more not shown") == 0);
	/* an empty block draws nothing, not even its heading */
	memset(&b, 0, sizeof b);
	snprintf(b.head, sizeof b.head, "Empty");
	reset_page();
	prop_block(&b);
	CK(g_n_prop == 0);
}

/* The pages are drawn from the data: the layout page's tables and counts, the symbol page's filter line and table. */
static void page_render(void)
{
	static const char *const names[3] = { "puts", "main", "exit" };
	static const int undef[3] = { 1, 0, 1 };
	struct view *v = calloc(1, sizeof *v);
	static struct kof_range probe[KOF_SCAN_MAX_EXTENTS];
	struct kgenome_obj o;
	struct kof_symw w;
	struct kof_symrec r;
	static uint8_t blk[4096];
	uint32_t i, nb;

	g_cols = 170;
	g_rows = 50;
	hk_elf(&E, 1, 0, 0);
	memset(&OB, 0, sizeof OB);
	memset(&EI, 0, sizeof EI);
	memset(&o, 0, sizeof o);
	CK(kgenome_elf_image_parse(kof_buf_make(E.b, E.n), &EI, &o));
	OB.buf = kof_buf_make(E.b, E.n);
	OB.fmt = &FMT;
	OB.info = &EI;
	OB.ctx.format = KOF_FMT_ELF;
	v->prop_room_rows = 44;
	v->prop_room_cols = 166;
	reset_page();
	v->prop_n_tab = 0;
	v->prop_pg = PROP_PG_SEGMENTS;
	prop_page_table_build(v, &OB);
	CK(find_line("PT_LOAD") >= 0 && find_line("entropy") == 0 && v->prop_fixed == 1u && v->prop_total == 1u && g_n_prop == 2u);
	CK(v->prop_n_tab == 1u && v->prop_tab[0].geo.has_head && v->prop_tab[0].abs_head == 0 && v->prop_tab[0].abs_row == 1);
	reset_page();
	v->prop_n_tab = 0;
	v->prop_pg = PROP_PG_SECTIONS;
	prop_page_table_build(v, &OB);
	CK(find_line(".symtab") >= 0 && find_line("SHT_SYMTAB") >= 0 && find_line("entropy") == 0 && v->prop_total == 6u && g_n_prop == 7u);
	/* the page's own scroll windows the rows: the heading stays and the rows start at the offset, clamped to what is there */
	v->prop_room_rows = 5;                              /* the heading and four rows */
	v->prop_off = 2;
	reset_page();
	v->prop_n_tab = 0;
	prop_page_table_build(v, &OB);
	CK(g_n_prop == 5u && v->prop_off == 2u && v->prop_vfirst == 2u && v->prop_tab[0].geo.row0 == 2u && v->prop_tab[0].abs_row == 3);
	CK(find_line(" .text ") < 0 && find_line(".strtab") >= 0);
	v->prop_off = 100;
	reset_page();
	v->prop_n_tab = 0;
	prop_page_table_build(v, &OB);
	CK(v->prop_off == 2u);                               /* 6 rows, 4 shown: the last start is 2 */
	v->prop_off = 0;
	v->prop_room_rows = 44;
	/* the object that has neither says why, once */
	memset(&OB, 0, sizeof OB);
	reset_page();
	v->prop_fixed = v->prop_total = 0;
	v->prop_pg = PROP_PG_SEGMENTS;
	prop_page_table_build(v, &OB);
	CK(g_n_prop == 1u && find_line("not a parsed ELF or PE") >= 0 && v->prop_fixed == 0u && v->prop_total == 0u);

	kof_symw_begin(&w, blk, sizeof blk, 3, 0);
	for (i = 0; i < 3; i++) {
		memset(&r, 0, sizeof r);
		r.type = 2; r.bind = 1;
		r.flags = undef[i] ? KOF_SYM_F_UNDEFINED : KOF_SYM_F_DEFINED;
		r.value = 0x1000u + i;
		r.name = names[i];
		r.name_len = (uint32_t)strlen(names[i]);
		CK(kof_symw_put(&w, &r) == 1);
	}
	nb = kof_symw_end(&w);
	memset(&OB, 0, sizeof OB);
	OB.fmt = &FMT;
	OB.ctx.format = KOF_FMT_ELF;
	OB.sym = blk;
	OB.sym_n = nb;
	v->probe = probe;
	reset_page();
	prop_symbols(v, &OB, SYMN_IMP);
	CK(v->sy_fy == 0 && v->prop_fixed == 2u && v->prop_total == 2u && find_line("filter") == 0 && find_line("[ ] icase") == 0 && find_line("[ ] regex") == 0);
	CK(find_line("puts") > 0 && find_line("exit") > 0 && find_line("main") < 0);
	CK(find_line("rec") > 0 && find_line("name") > 0 && find_line("value") > 0);     /* the table's heading */
	/* each of the four empties is its own sentence on the page */
	snprintf(v->sy_filt, sizeof v->sy_filt, "zzz");
	reset_page();
	prop_symbols(v, &OB, SYMN_IMP);
	CK(find_line("no symbol matches the filter") >= 0 && find_line("puts") < 0);
	snprintf(v->sy_filt, sizeof v->sy_filt, "(");
	v->sy_frx = 1;
	prop_sym_filter_compile(v);
	reset_page();
	prop_symbols(v, &OB, SYMN_IMP);
	CK(v->sy_frx_bad && find_line("bad pattern") >= 0);
	v->sy_filt[0] = 0;
	v->sy_frx = 0;
	prop_sym_filter_compile(v);
	OB.ctx.format = KOF_FMT_SCRIPT;
	reset_page();
	prop_symbols(v, &OB, SYMN_EXP);
	CK(g_n_prop == 1u && find_line("this kind of object has no symbol table") >= 0 && v->sy_fy == -1);
	free(v);
}

/* A long name pans: the value after it is reached by the offset, and the record number stays. */
static void symbols_pan(void)
{
	char longname[200];
	const char *names[2];
	static const int undef[2] = { 1, 1 };
	struct view *v = calloc(1, sizeof *v);
	static struct kof_range probe[KOF_SCAN_MAX_EXTENTS];
	struct kof_symw w;
	struct kof_symrec r;
	static uint8_t blk[8192];
	char t[PROP_W];
	uint32_t i, nb;
	int ln;

	memset(longname, 'n', sizeof longname - 1);
	longname[sizeof longname - 1] = 0;
	names[0] = longname;
	names[1] = "short";
	kof_symw_begin(&w, blk, sizeof blk, 2, 0);
	for (i = 0; i < 2; i++) {
		memset(&r, 0, sizeof r);
		r.type = 2; r.bind = 1; r.flags = undef[i] ? KOF_SYM_F_UNDEFINED : KOF_SYM_F_DEFINED;
		r.value = 0x1000u + i;
		r.name = names[i];
		r.name_len = (uint32_t)strlen(names[i]);
		CK(kof_symw_put(&w, &r) == 1);
	}
	nb = kof_symw_end(&w);
	memset(&OB, 0, sizeof OB);
	OB.ctx.format = KOF_FMT_ELF;
	OB.sym = blk;
	OB.sym_n = nb;
	v->probe = probe;
	v->prop_room_cols = 96;
	v->prop_room_rows = 36;
	reset_page();
	prop_symbols(v, &OB, SYMN_IMP);
	ln = find_line("short");
	CK(ln > 0);
	if (ln < 0)
		return;
	line_plain((uint32_t)ln, t, sizeof t);
	CK(strstr(t, "0x00001001") == NULL);              /* the value is off the page at 100 columns */
	CK(strlen(t) <= (size_t)v->prop_room_cols);
	reset_page();
	v->prop_hoff = 10000;                              /* far past the end: clamped, and the value is in view */
	prop_symbols(v, &OB, SYMN_IMP);
	ln = find_line("0x00001001");
	CK(ln > 0);
	free(v);
	g_cols = 170;
	g_rows = 50;
}

static uint8_t SYMBLK[KOF_SYM_MAX_BYTES];

static struct view *symview(uint32_t nsym, const char *const *names, const int *undef)
{
	struct view *v = calloc(1, sizeof *v);
	static struct kof_range probe[KOF_SCAN_MAX_EXTENTS];
	struct kof_symw w;
	struct kof_symrec r;
	uint32_t i;

	kof_symw_begin(&w, SYMBLK, sizeof SYMBLK, nsym, 0);
	for (i = 0; i < nsym; i++) {
		memset(&r, 0, sizeof r);
		r.type = 2;
		r.bind = 1;
		r.flags = undef[i] ? KOF_SYM_F_UNDEFINED : KOF_SYM_F_DEFINED;
		r.value = 0x1000u + i;
		r.name = names[i];
		r.name_len = (uint32_t)strlen(names[i]);
		CK(kof_symw_put(&w, &r) == 1);
	}
	memset(&OB, 0, sizeof OB);
	OB.fmt = &FMT;
	OB.ctx.format = KOF_FMT_ELF;
	OB.sym = SYMBLK;
	OB.sym_n = kof_symw_end(&w);
	v->probe = probe;
	return v;
}

/* ================================================================================ KEYS AND THE STRIP */

static void keys_and_strip(void)
{
	static const char *const names[3] = { "a", "b", "c" };
	static const int undef[3] = { 1, 1, 1 };
	struct view *v = symview(3, names, undef);
	int k, pg;

	/* NO KEY CHANGES THE PAGE: on every page, none of Tab, Shift+Tab, 1-4, nor anything else a person might try */
	for (pg = 0; pg < (int)PROP_PG_COUNT; pg++) {
		static const int keys[] = { '\t', K_BACKTAB, '1', '2', '3', '4', 'i', 'e', 'l', 'o', K_UP, K_DOWN, K_LEFT, K_RIGHT,
					    K_PGUP, K_PGDN, K_HOME, K_END };
		unsigned i;

		for (i = 0; i < sizeof keys / sizeof keys[0]; i++) {
			v->prop_pg = (uint8_t)pg;
			v->edit = 0;
			(void)prop_page_key(v, keys[i]);
			CK(v->prop_pg == (uint8_t)pg);
			v->edit = ED_SYMFILT;
			(void)prop_page_key(v, keys[i]);
			CK(v->prop_pg == (uint8_t)pg);
		}
	}
	/* on a page that is no symbol page the keys are the dashboard's (not consumed here) */
	v->edit = 0;
	for (pg = PROP_PG_OVERVIEW; pg <= PROP_PG_SECTIONS; pg++) {
		v->prop_pg = (uint8_t)pg;
		for (k = K_UP; k <= K_END; k++)
			CK(prop_page_key(v, k) == 0);
	}
	/* a symbol page: the vertical keys are the page's (not consumed here); the sideways pan is */
	v->prop_pg = PROP_PG_IMPORTS;
	reset_page();
	v->prop_hoff = 0;
	for (k = K_UP; k <= K_END; k++)
		if (k != K_LEFT && k != K_RIGHT)
			CK(prop_page_key(v, k) == 0);
	CK(prop_page_key(v, K_RIGHT) == 1 && v->prop_hoff == (uint32_t)PROP_KEY_COLS);
	CK(prop_page_key(v, K_LEFT) == 1 && v->prop_hoff == 0u);
	CK(prop_page_key(v, K_LEFT) == 1 && v->prop_hoff == 0u);
	/* THE ONE SCROLL: saturating at zero, and the same function for the wheel, the keys and the bar */
	v->prop_off = 5;
	v->prop_hoff = 3;
	prop_scroll(v, -2, -1);
	CK(v->prop_off == 3u && v->prop_hoff == 2u);
	prop_scroll(v, -100, -100);
	CK(v->prop_off == 0u && v->prop_hoff == 0u);
	prop_scroll(v, 7, 9);
	CK(v->prop_off == 7u && v->prop_hoff == 9u);
	/* the filter field: typing edits it and the list goes back to the top; Escape closes the FIELD */
	v->sy_filt[0] = 0;
	v->edit = ED_SYMFILT;
	v->prop_off = 7;
	g_field_keys = 0;
	CK(prop_page_key(v, 'x') == 1 && strcmp(v->sy_filt, "x") == 0 && v->prop_off == 0u && g_field_keys == 1);
	CK(prop_page_key(v, '\r') == 1 && v->edit == 0);
	v->edit = ED_SYMFILT;
	CK(prop_page_key(v, 27) == 1 && v->edit == 0 && strcmp(v->sy_filt, "x") == 0);
	/* with the field open, the vertical keys are still the page's and not the field's */
	v->edit = ED_SYMFILT;
	g_field_keys = 0;
	CK(prop_page_key(v, K_DOWN) == 0 && g_field_keys == 0);
	/* mouse events are never keys here */
	CK(prop_page_key(v, K_CLICK) == 0 && prop_page_key(v, K_WHEEL_UP) == 0);
	v->edit = 0;

	/* THE STRIP: a click on a label (the dialog's returned geometry) selects its page; the page left behind is not carried over */
	v->prop_pg = PROP_PG_OVERVIEW;
	memset(&v->prop_geo, 0, sizeof v->prop_geo);
	v->prop_geo.ok = 1;
	v->prop_geo.tab_y = 2;
	v->prop_geo.n_tab = 5;
	for (k = 0; k < 5; k++) {
		v->prop_geo.tab_x0[k] = 10 + 14 * k;
		v->prop_geo.tab_x1[k] = 10 + 14 * k + 9;
	}
	v->prop_off = 5;
	v->prop_hoff = 5;
	g_my = 2;
	g_mx = 10 + 14 * 4 + 4;
	CK(prop_click(v) == 1 && v->prop_pg == PROP_PG_EXPORTS && v->prop_off == 0u && v->prop_hoff == 0u);
	g_mx = 10 + 14 + 10;                      /* in the gap between two labels */
	CK(prop_click(v) == 0 && v->prop_pg == PROP_PG_EXPORTS);
	g_my = 3;
	g_mx = 12;
	CK(prop_click(v) == 0 && v->prop_pg == PROP_PG_EXPORTS);
	g_my = 2;
	g_mx = 10 + 14 * 3;
	v->edit = ED_SYMFILT;
	CK(prop_click(v) == 1 && v->prop_pg == PROP_PG_IMPORTS && v->edit == ED_SYMFILT);   /* between symbol pages the field stays */
	g_mx = 10 + 14;
	CK(prop_click(v) == 1 && v->prop_pg == PROP_PG_SEGMENTS && v->edit == 0);           /* leaving them closes it */
	/* the scrollbar: a press moves the page to that place and takes the drag */
	v->prop_geo.bar_x = 90;
	v->prop_geo.bar_y0 = 10;
	v->prop_geo.bar_rows = 11;
	v->prop_in.total = 110;
	v->prop_in.shown = 10;
	g_mx = 90;
	g_my = 20;
	CK(prop_click(v) == 1 && v->prop_off == 100u && v->prop_bar_drag == 1);
	g_my = 15;
	prop_bar_to(v);
	CK(v->prop_off == 50u);
	v->prop_bar_drag = 0;
	g_mx = 89;
	CK(prop_click(v) == 0);
	/* the filter's controls */
	v->prop_pg = PROP_PG_EXPORTS;
	v->sy_fy = 6;
	v->sy_fbox[0] = 20; v->sy_fbox[1] = 40;
	v->sy_ic_box[0] = 42; v->sy_ic_box[1] = 50;
	v->sy_rx_box[0] = 52; v->sy_rx_box[1] = 60;
	g_my = 6;
	v->prop_off = 3;
	g_mx = 30;
	CK(prop_click(v) == 1 && v->edit == ED_SYMFILT);
	g_mx = 45;
	CK(prop_click(v) == 1 && v->sy_ficase == 1 && v->prop_off == 0u);
	v->prop_off = 3;
	g_mx = 55;
	CK(prop_click(v) == 1 && v->sy_frx == 1 && v->prop_off == 0u);
	g_mx = 70;
	CK(prop_click(v) == 0);
	/* open and close */
	v->edit = ED_SYMFILT;
	v->dlg_have = 1;
	prop_close(v);
	CK(v->prop_open == 0 && v->edit == 0 && v->dlg_have == 0);
	prop_show(v);
	CK(v->prop_open == 1 && v->prop_pg == PROP_PG_OVERVIEW && v->prop_off == 0u);
	free(v);
}

/* ================================================================================ LAZY AND ONCE */

/* Counting seams: the two analyses of the Infection dialog, wrapped at link time (UT_LDX_kx_dash). */
static unsigned n_regions, n_lister;
enum kgenome_status __real_kgenome_infect_regions(const struct kgenome_infect_req *rq, struct kgenome_infect_res *rs);
enum kgenome_status __wrap_kgenome_infect_regions(const struct kgenome_infect_req *rq, struct kgenome_infect_res *rs);
enum kgenome_status __wrap_kgenome_infect_regions(const struct kgenome_infect_req *rq, struct kgenome_infect_res *rs)
{
	n_regions++;
	return __real_kgenome_infect_regions(rq, rs);
}
enum kgenome_status __real_kofscfind_list(const struct kofscfind_list_in *in, struct kofscfind_list_res *res);
enum kgenome_status __wrap_kofscfind_list(const struct kofscfind_list_in *in, struct kofscfind_list_res *res);
enum kgenome_status __wrap_kofscfind_list(const struct kofscfind_list_in *in, struct kofscfind_list_res *res)
{
	n_lister++;
	return __real_kofscfind_list(in, res);
}

static void obj_of(struct object *o, struct hk_elf *e)
{
	struct kgenome_obj g;
	static struct kgenome_elf_info info[2];
	static unsigned k;
	struct kgenome_elf_info *i = &info[k++ & 1u];

	memset(o, 0, sizeof *o);
	memset(i, 0, sizeof *i);
	memset(&g, 0, sizeof g);
	CK(kgenome_elf_image_parse(kof_buf_make(e->b, e->n), i, &g));
	o->buf = kof_buf_make(e->b, e->n);
	o->fmt = &FMT;
	o->info = i;
	o->ctx.format = KOF_FMT_ELF;
	o->ctx.arch = KGENOME_ARCH_X86_64;
	o->ctx.entry_off = e->text;
}

/* Opening the dialog runs the analysis once; redraws, scrolls, a tab switch and a reopen on the same object run it no more; another
 * object runs it once; and what it kept is freed with the object. */
static void lazy_once(void)
{
	static struct hk_elf A, B;
	static struct object O1, O2;
	struct view *v = calloc(1, sizeof *v);
	unsigned i;

	g_cols = 170;
	g_rows = 50;
	hk_elf(&A, 1, 0, 0);
	hk_elf(&B, 1, 0, 0);
	obj_of(&O1, &A);
	obj_of(&O2, &B);
	v->prop_room_rows = 44;
	v->prop_room_cols = 166;
	n_regions = n_lister = 0;
	prop_show_infection(v);                              /* showing does nothing by itself: the analysis runs when a page is built */
	CK(n_regions == 0u && n_lister == 0u && O1.inf_data == NULL && O1.shell_data == NULL);
	reset_page();
	v->prop_n_tab = 0;
	prop_page_table_build(v, &O1);                       /* the first build: once, for both tabs */
	CK(n_regions == 1u && n_lister == 1u && O1.inf_data != NULL && O1.shell_data != NULL && find_line("entry point") >= 0);
	for (i = 0; i < 10u; i++) {                          /* ten redraws, a scroll and a resize */
		v->prop_off = i;
		v->prop_room_cols = 120 + (int)i;
		reset_page();
		v->prop_n_tab = 0;
		prop_page_table_build(v, &O1);
	}
	CK(n_regions == 1u && n_lister == 1u);
	v->prop_pg = PROP_PG_INF_SHELL;                      /* the other tab */
	for (i = 0; i < 10u; i++) {
		reset_page();
		v->prop_n_tab = 0;
		prop_page_table_build(v, &O1);
	}
	CK(n_regions == 1u && n_lister == 1u && find_line("execute permission") >= 0);
	prop_close(v);                                       /* close and reopen on the same object */
	prop_show_infection(v);
	reset_page();
	v->prop_n_tab = 0;
	prop_page_table_build(v, &O1);
	v->prop_pg = PROP_PG_INF_SHELL;
	reset_page();
	v->prop_n_tab = 0;
	prop_page_table_build(v, &O1);
	CK(n_regions == 1u && n_lister == 1u);
	reset_page();                                        /* another object: once */
	v->prop_n_tab = 0;
	prop_page_table_build(v, &O2);
	prop_page_table_build(v, &O2);
	CK(n_regions == 2u && n_lister == 2u);
	dash_drop(&O1);                                      /* freed with the object, and made again if asked for again */
	CK(O1.inf_data == NULL && O1.shell_data == NULL);
	reset_page();
	v->prop_n_tab = 0;
	prop_page_table_build(v, &O1);
	CK(n_regions == 3u && n_lister == 3u);
	dash_drop(&O1);
	dash_drop(&O2);
	prop_tabs_free(v);
	free(v);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	block_render();
	page_render();
	symbols_pan();
	keys_and_strip();
	lazy_once();
	printf("kx_dash: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
