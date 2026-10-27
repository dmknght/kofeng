/*
 * kx_dashdata - what the dashboard says, as DATA (kofexamine/kv_dashdata.c), asserted on with no viewer and no screen. The unit is
 * INCLUDED into this file; the three things it asks of the rest of the viewer (the half of the symbol block a mask names, the
 * permission and offset spellings) are the stubs of kx_dash_stubs.h.
 *
 *   HEADER     the overview's format block of hk.h's objects in all four class x order shapes and as ET_REL, and of a PE, against the
 *              bytes (an independent reader): format, arch, symbols, entry (address, section, file offset, permission), layout and the declared counts, in that order (one fact per row)
 *   REGIONS    the share of each region, the partition check and its MISMATCH row, the object no parser divides
 *   ANOMALIES  the parser's bits by name, the reconstructed payload, no parser, and none
 *   LAYOUT     both tables: columns, kept rows, declared and not-shown counts, every cell against the bytes; hostile counts, an escape in
 *              a name, no program headers, no section table, a PE (no segments), an object that is no ELF or PE
 *   SYMBOLS    the filter against a model over an exhaustive small alphabet (plain, folded, regex), the refused regex, the rows after
 *              the filter, the four reasons for no rows, the cut block, the widths, the row a finder named
 *   TABS       the strip's five labels (no counts)
 *   INFECTION  the Infection dialog's two tables: the rows as cells, the engine's ranges flagged (on the entry, beside every region, hostile
 *              counts), the sentences for an object that has no rows, the shellcode finder's row, a variable and a range in executable memory
 *   ENTROPY    the entropy cell of every row against an independent double-precision oracle, hostile and bounded ranges, the
 *              core's hundredths-of-a-bit call over an exhaustive small alphabet
 *   COUNT      the dialog's "a-b of N lines|items" text
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

#include <math.h>

#include "../../kofexamine/kv_dashdata.c"

static struct object OB;
static struct kof_parser FMT;
static struct kgenome_elf_info EI;
static struct kgenome_pe_info PI;
static struct hk_elf E;
static struct hk_pe P;
static struct dash_block BK;

static uint64_t rd(const uint8_t *p, unsigned n, int be)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		v |= (uint64_t)p[be ? n - 1u - i : i] << (8u * i);
	return v;
}

static void obj_elf(struct hk_elf *e)
{
	struct kgenome_obj o;

	memset(&OB, 0, sizeof OB);
	memset(&EI, 0, sizeof EI);
	memset(&o, 0, sizeof o);
	CK(kgenome_elf_image_parse(kof_buf_make(e->b, e->n), &EI, &o));
	OB.buf = kof_buf_make(e->b, e->n);
	OB.fmt = &FMT;
	OB.info = &EI;
	OB.ctx.format = KOF_FMT_ELF;
	OB.ctx.arch = e->is64 ? KGENOME_ARCH_X86_64 : KGENOME_ARCH_X86;
	OB.ctx.subtype = (uint8_t)(e->rel ? KGENOME_ELF_REL : KGENOME_ELF_EXEC);
	OB.ctx.entry_off = e->rel ? KGENOME_NA : e->text;
}

static void obj_pe(int plus)
{
	struct kgenome_obj o;

	hk_pe(&P, plus);
	memset(&OB, 0, sizeof OB);
	memset(&PI, 0, sizeof PI);
	memset(&o, 0, sizeof o);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &PI, &o));
	OB.buf = kof_buf_make(P.b, P.n);
	OB.fmt = &FMT;
	OB.info = &PI;
	OB.ctx.format = KOF_FMT_PE;
	OB.ctx.arch = plus ? KGENOME_ARCH_X86_64 : KGENOME_ARCH_X86;
}

/* The text of a row: its spans joined. */
static void row_text(const struct dash_row *r, char *out, size_t cap)
{
	uint32_t i;

	size_t n = 0;

	out[0] = 0;
	if (!r)
		return;
	for (i = 0; i < r->n; i++)
		n += (size_t)snprintf(out + n, n < cap ? cap - n : 0u, "%s", r->s[i].text);
}

static const struct dash_row *find_row(const struct dash_block *b, const char *label)
{
	uint32_t i;

	for (i = 0; i < b->n; i++)
		if (strcmp(b->row[i].label, label) == 0)
			return &b->row[i];
	return NULL;
}

static int row_index(const struct dash_block *b, const char *label)
{
	uint32_t i;

	for (i = 0; i < b->n; i++)
		if (strcmp(b->row[i].label, label) == 0)
			return (int)i;
	return -1;
}

/* ================================================================================ HEADER */

static void header_elf_shapes(void)
{
	int is64, be, rel;

	for (is64 = 0; is64 < 2; is64++)
		for (be = 0; be < 2; be++)
			for (rel = 0; rel < 2; rel++) {
				char t[200];
				char want[80];

				hk_elf(&E, is64, be, rel);
				obj_elf(&E);
				dash_header(&OB, &BK);
				CK(strcmp(BK.head, "ELF") == 0 && BK.not_shown == 0);
				/* one fact per row: format, arch, symbols, entry (not for a relocatable), layout; the size is the Object block's */
				CK(row_index(&BK, "format") == 0 && row_index(&BK, "arch") == 1 && row_index(&BK, "symbols") == 2);
				CK(row_index(&BK, "entry") == (rel ? -1 : 3) && row_index(&BK, "layout") == (rel ? 3 : 7) && find_row(&BK, "size") == NULL);
				CK(find_row(&BK, "permission") == NULL && find_row(&BK, "section") == NULL);
				CK(BK.n == (rel ? 4u : 8u) && find_row(&BK, "segments") == NULL && find_row(&BK, "sections") == NULL);   /* matching counts add no row */
				row_text(find_row(&BK, "format"), t, sizeof t);
				snprintf(want, sizeof want, "ELF \xc2\xb7 %s", rel ? "ET_REL" : "ET_EXEC");
				CK(strcmp(t, want) == 0);
				CK((uint64_t)(rel ? 1 : 2) == rd(E.b + 16, 2, be));
				row_text(find_row(&BK, "arch"), t, sizeof t);
				snprintf(want, sizeof want, "%s \xc2\xb7 %s", rd(E.b + 18, 2, be) == 62 ? "x86-64 64-bit" : "x86 32-bit",
					 be ? "big-endian" : "little-endian");
				CK(strcmp(t, want) == 0);
				row_text(find_row(&BK, "symbols"), t, sizeof t);
				CK(strstr(t, "stripped") != NULL && strstr(t, "static") == NULL && strstr(t, "dynamic") == NULL);
				if (!rel) {
					row_text(find_row(&BK, "entry"), t, sizeof t);
					CK(strcmp(t, "R-X at .text") == 0 || strncmp(t, "R-X at ", 7) == 0);   /* the segment's permission, then the section */
					row_text(&BK.row[4], t, sizeof t);
					snprintf(want, sizeof want, "%-15s 0x", "virtual address");
					CK(strncmp(t, want, strlen(want)) == 0 &&
					   strtoull(t + strlen(want) - 2, NULL, 16) == rd(E.b + 24, is64 ? 8 : 4, be));
					row_text(&BK.row[5], t, sizeof t);
					snprintf(want, sizeof want, "%-15s 0x", "file offset");
					CK(strncmp(t, want, strlen(want)) == 0);
					row_text(&BK.row[6], t, sizeof t);
					snprintf(want, sizeof want, "%-15s 0x", "section offset");
					CK(strncmp(t, want, strlen(want)) == 0);
				}
				row_text(find_row(&BK, "layout"), t, sizeof t);
				snprintf(want, sizeof want, "%s%llu sections", rel ? "" : "1 loadable segment \xc2\xb7 ",
					 (unsigned long long)rd(E.b + (is64 ? 60u : 48u), 2, be));
				CK(strcmp(t, want) == 0);
			}
}

static void header_hostile(void)
{
	char t[100];

	/* a header that claims more than the clamp keeps: warn tone and both numbers */
	hk_elf(&E, 1, 0, 0);
	hk_w(E.b + 60, 0xfff0, 2, 0);
	obj_elf(&E);
	dash_header(&OB, &BK);
	row_text(find_row(&BK, "sections"), t, sizeof t);
	CK(strstr(t, "kept, the header declares 65520") != NULL);
	CK(find_row(&BK, "sections")->s[0].tone == DT_WARN);
	/* an e_type past the table has a number and no name (not the name of its low byte) */
	hk_elf(&E, 1, 0, 0);
	hk_w(E.b + 16, 0x102, 2, 0);
	obj_elf(&E);
	dash_header(&OB, &BK);
	row_text(find_row(&BK, "format"), t, sizeof t);
	CK(strstr(t, "type 258") != NULL && strstr(t, "ET_") == NULL);
	/* a normalised view has no format block (its header is its parent's) */
	OB.entry_kind = KOF_ENT_NORMALIZED;
	dash_header(&OB, &BK);
	CK(BK.n == 0 && BK.head[0] == 0 && !dash_has_header(&OB));
	/* nor does an object nothing parsed */
	memset(&OB, 0, sizeof OB);
	dash_header(&OB, &BK);
	CK(BK.n == 0);
}

static void header_pe_rows(void)
{
	int plus;

	char rva_pfx[32], fo_pfx[32];

	snprintf(rva_pfx, sizeof rva_pfx, "%-15s 0x", "RVA");
	snprintf(fo_pfx, sizeof fo_pfx, "%-15s 0x", "file offset");
	for (plus = 0; plus < 2; plus++) {
		char t[200];

		obj_pe(plus);
		dash_header(&OB, &BK);
		CK(strcmp(BK.head, "PE") == 0);
		CK(row_index(&BK, "format") == 0 && row_index(&BK, "arch") == 1 && row_index(&BK, "entry") == 2 && find_row(&BK, "size") == NULL);
		CK(find_row(&BK, "stub") && find_row(&BK, "summary") && !find_row(&BK, "sections") && !find_row(&BK, "headers"));
		row_text(find_row(&BK, "format"), t, sizeof t);
		CK(strncmp(t, plus ? "PE32+" : "PE32", plus ? 5u : 4u) == 0);
		CK(rd(P.b + PI.lfanew + 4, 2, 0) == PI.machine);
		row_text(find_row(&BK, "arch"), t, sizeof t);
		CK(strstr(t, OB.ctx.arch == KGENOME_ARCH_X86_64 ? "x86-64 64-bit" : "x86 32-bit") != NULL);
		row_text(find_row(&BK, "entry"), t, sizeof t);
		CK(strstr(t, " at ") != NULL);
		row_text(&BK.row[3], t, sizeof t);
		CK(strncmp(t, rva_pfx, strlen(rva_pfx)) == 0);
		row_text(&BK.row[4], t, sizeof t);
		CK(strncmp(t, fo_pfx, strlen(fo_pfx)) == 0);
		row_text(&BK.row[5], t, sizeof t);
		CK(strncmp(t, "section offset ", 15) == 0);
		row_text(find_row(&BK, "stub"), t, sizeof t);
		CK(strstr(t, "NT headers at file offset 0x") != NULL && strstr(t, "headers end at 0x") != NULL && strstr(t, "lfanew") == NULL);
	}
}

/* ================================================================================ REGIONS AND ANOMALIES */

static struct view *regview(uint64_t *bytes, const char *const *labels, uint32_t n, uint64_t size)
{
	struct view *v = calloc(1, sizeof *v);
	uint32_t i;

	memset(&OB, 0, sizeof OB);
	OB.buf.n = size;
	OB.ctx.format = KOF_FMT_ELF;
	v->n_node = n + 2u;
	v->sel_node = 0;
	v->node[0].obj = 0;                      /* the object's own row: no mask */
	for (i = 0; i < n; i++) {
		v->node[1u + i].obj = 0;
		v->node[1u + i].mask = 1u << i;
		v->node[1u + i].bytes = bytes[i];
		snprintf(v->node[1u + i].label, sizeof v->node[1u + i].label, "%s", labels[i]);
	}
	v->node[n + 1u].obj = 0;                 /* a symbol half: never counted */
	v->node[n + 1u].mask = 1u << 20;
	v->node[n + 1u].sym = SYMN_IMP;
	v->node[n + 1u].bytes = 999;
	snprintf(v->node[n + 1u].label, sizeof v->node[n + 1u].label, "SYM_IMP");
	return v;
}

static void regions_rows(void)
{
	static const char *const lab[3] = { "CODE", "DATA", "UNCLAIMED" };
	uint64_t b3[3] = { 300, 100, 100 };
	struct view *v = regview(b3, lab, 3, 500);
	char t[100];
	const struct dash_row *r;

	dash_regions(v, &OB, &BK);
	CK(strcmp(BK.head, "Regions") == 0 && BK.n == 3u);              /* the symbol half is not a region */
	CK(strcmp(BK.row[0].label, "CODE") == 0 && BK.row[0].label_tone == DT_ID);
	row_text(&BK.row[0], t, sizeof t);
	CK(strstr(t, "300") != NULL && strstr(t, " 60.0%") != NULL);       /* the share is of the partition's total */
	row_text(&BK.row[1], t, sizeof t);
	CK(strstr(t, " 20.0%") != NULL);
	CK(find_row(&BK, "MISMATCH") == NULL);
	/* the regions do not add up to the object: said, in the bad tone, with both numbers */
	OB.buf.n = 520;
	dash_regions(v, &OB, &BK);
	r = find_row(&BK, "MISMATCH");
	CK(r && r->s[0].tone == DT_BAD);
	row_text(r, t, sizeof t);
	CK(strcmp(t, "regions sum to 500 of 520") == 0);
	/* a process record does not claim to partition */
	OB.ctx.format = KOF_EVT_PROC;
	dash_regions(v, &OB, &BK);
	CK(find_row(&BK, "MISMATCH") == NULL);
	free(v);
	/* no parser divides it: one row, and no heading is lost */
	v = regview(b3, lab, 0, 500);
	dash_regions(v, &OB, &BK);
	CK(BK.n == 1u && strcmp(BK.row[0].label, "whole") == 0);
	row_text(&BK.row[0], t, sizeof t);
	CK(strcmp(t, "no parser divides this object") == 0);
	free(v);
}

static uint64_t g_anom;
static const char *anom_name(uint32_t i)
{
	return i == 3 ? "SEG_PAST_EOF" : i == 9 ? NULL : "ODD";
}

static uint64_t anom_of(const void *info)
{
	(void)info;
	return g_anom;
}

static void anomalies_rows(void)
{
	char t[100];
	uint32_t i;
	int x;

	memset(&FMT, 0, sizeof FMT);
	FMT.anomalies = anom_of;
	FMT.anomaly_name = anom_name;
	memset(&OB, 0, sizeof OB);
	OB.fmt = &FMT;
	OB.info = &FMT;
	g_anom = 0;
	dash_anomalies(&OB, &BK);
	CK(strcmp(BK.head, "Anomalies") == 0 && BK.n == 1u);
	row_text(&BK.row[0], t, sizeof t);
	CK(strcmp(t, "  none") == 0);
	/* every bit of the word, exhaustively over a small family, names its row in bit order; an unnamed bit is bitN */
	for (x = 0; x < 64; x += 7) {
		g_anom = (1ull << x) | (1ull << 3) | (1ull << 9) | (x == 63 ? 1ull << 63 : 0);
		dash_anomalies(&OB, &BK);
		CK(BK.n >= 2u && BK.n <= 4u);
		for (i = 0; i < BK.n; i++)
			CK(BK.row[i].s[0].tone == DT_BAD);
		CK(strcmp(BK.row[0].s[0].text, x < 3 ? "  ODD" : "  SEG_PAST_EOF") == 0 || x < 3);
	}
	g_anom = 1ull << 9;
	dash_anomalies(&OB, &BK);
	CK(BK.n == 1u && strcmp(BK.row[0].s[0].text, "  bit9") == 0);
	/* a reconstruction says what it is, in place of the parser's list */
	OB.payload_of = 1;
	dash_anomalies(&OB, &BK);
	CK(BK.n == 1u && strncmp(BK.row[0].s[0].text, "  RECONSTRUCTED_", 16) == 0 && BK.row[0].s[0].tone == DT_WARN);
	/* no parser */
	memset(&OB, 0, sizeof OB);
	dash_anomalies(&OB, &BK);
	CK(BK.n == 1u && strstr(BK.row[0].s[0].text, "no parser claimed") != NULL);
	memset(&FMT, 0, sizeof FMT);
}

/* The heuristic is the engine's: shown as scored, never recomputed. Not scored is said, and is not a score of zero. */
static void heuristic_rows(void)
{
	const struct kof_heur_model *hm = kof_heur_default();
	char t[100];

	memset(&OB, 0, sizeof OB);
	OB.ctx.format = KOF_FMT_ELF;
	dash_heuristic(&OB, &BK);
	CK(strcmp(BK.head, "Heuristic") == 0 && BK.n == 1u);
	CK(strstr(BK.row[0].s[0].text, "not scored") != NULL);
	OB.heur.heur_scored = 1;
	OB.heur.heur_score = hm->bar_centinats - 1;
	dash_heuristic(&OB, &BK);
	CK(strcmp(BK.row[0].label, "score") == 0 && BK.row[0].s[0].tone == DT_SIZE);
	row_text(&BK.row[0], t, sizeof t);
	CK(atoi(t) == hm->bar_centinats - 1 && strstr(t, "to report") != NULL);
	CK(find_row(&BK, "verdict") == NULL);
	OB.heur.heur_score = hm->bar_centinats;
	dash_heuristic(&OB, &BK);
	CK(BK.row[0].s[0].tone == DT_HEUR && find_row(&BK, "verdict") != NULL);
}

/* ================================================================================ LAYOUT */

static void layout_elf_shapes(void)
{
	int is64, be, rel;

	for (is64 = 0; is64 < 2; is64++)
		for (be = 0; be < 2; be++)
			for (rel = 0; rel < 2; rel++) {
				struct dash_table sg, sc;
				char c[DASH_COLS][DASH_CELL];
				uint32_t i;
				static const char *const nm[6] = { "", ".text", ".symtab", ".strtab", ".rela.text", ".shstrtab" };

				hk_elf(&E, is64, be, rel);
				obj_elf(&E);
				dash_layout(&OB, DASH_LAY_SEG, &sg);
				dash_layout(&OB, DASH_LAY_SEC, &sc);
				CK(sc.n_col == 12u && sc.n_row == 6u && sc.declared == 6u && sc.not_shown == 0 && sc.lead == 2u);
				CK(strcmp(sc.head[0], "#") == 0 && strcmp(sc.head[1], "name") == 0 && strcmp(sc.head[10], "align") == 0 && strcmp(sc.head[11], "entropy") == 0);
				for (i = 0; i < sc.n_row; i++) {
					const uint8_t *h = E.b + E.sh + i * E.sh_ent;

					dash_layout_cell(&OB, DASH_LAY_SEC, i, c);
					CK((uint32_t)atoi(c[0]) == i);
					CK(strcmp(c[1], nm[i]) == 0);
					CK(strtoull(c[4], NULL, 16) == rd(h + (is64 ? 16 : 12), is64 ? 8 : 4, be));
					CK(strtoull(c[5], NULL, 16) == rd(h + (is64 ? 24 : 16), is64 ? 8 : 4, be));
					CK(strtoull(c[6], NULL, 10) == rd(h + (is64 ? 32 : 20), is64 ? 8 : 4, be));
					CK(strtoull(c[7], NULL, 10) == rd(h + (is64 ? 40 : 24), 4, be));
					CK(strtoull(c[8], NULL, 10) == rd(h + (is64 ? 44 : 28), 4, be));
					CK(strtoull(c[9], NULL, 10) == rd(h + (is64 ? 56 : 36), is64 ? 8 : 4, be));
					CK(strtoull(c[10], NULL, 10) == rd(h + (is64 ? 48 : 32), is64 ? 8 : 4, be));
				}
				/* a row past the table is empty cells, not a read past the array */
				dash_layout_cell(&OB, DASH_LAY_SEC, 6, c);
				CK(c[0][0] == 0 && c[10][0] == 0);
				dash_layout_cell(&OB, DASH_LAY_SEC, 0xffffffffu, c);
				CK(c[0][0] == 0);
				if (rel) {
					CK(sg.n_col == 0 && sg.n_row == 0 && strcmp(sg.none, "no program headers") == 0);
				} else {
					const uint8_t *p = E.b + E.ph;

					CK(sg.n_col == 9u && strcmp(sg.head[8], "entropy") == 0 && sg.n_row == 1u && sg.declared == 1u && sg.lead == 2u);
					dash_layout_cell(&OB, DASH_LAY_SEG, 0, c);
					CK(strcmp(c[1], "PT_LOAD") == 0 && strcmp(c[2], "R-X") == 0);
					CK(strtoull(c[3], NULL, 16) == rd(p + (is64 ? 8 : 4), is64 ? 8 : 4, be));
					CK(strtoull(c[4], NULL, 16) == rd(p + (is64 ? 16 : 8), is64 ? 8 : 4, be));
					CK(strtoull(c[5], NULL, 10) == rd(p + (is64 ? 32 : 16), is64 ? 8 : 4, be));
					CK(strtoull(c[6], NULL, 10) == rd(p + (is64 ? 40 : 20), is64 ? 8 : 4, be));
					CK(strtoull(c[7], NULL, 16) == rd(p + (is64 ? 48 : 28), is64 ? 8 : 4, be));
				}
			}
}

static void layout_hostile(void)
{
	struct dash_table t;
	char c[DASH_COLS][DASH_CELL];

	/* a header claiming 65520 sections: the table holds what the parse kept and says how many it did not */
	hk_elf(&E, 1, 0, 0);
	hk_w(E.b + 60, 0xfff0, 2, 0);
	obj_elf(&E);
	dash_layout(&OB, DASH_LAY_SEC, &t);
	CK(t.declared == 65520u && t.n_row == EI.sec_count && t.n_row <= KGENOME_ELF_MAX_SECTIONS);
	CK(t.not_shown == 65520u - t.n_row);
	/* program headers claimed past the file: kept < claimed, the rest said */
	hk_elf(&E, 1, 0, 0);
	hk_w(E.b + 56, 70, 2, 0);
	obj_elf(&E);
	dash_layout(&OB, DASH_LAY_SEG, &t);
	CK(t.declared == 70u && t.n_row == EI.seg_count && t.not_shown == 70u - t.n_row);
	/* a claim BELOW what is kept (shnum 3 of 6 headers present): nothing is "not shown" */
	hk_elf(&E, 1, 0, 0);
	hk_w(E.b + 60, 3, 2, 0);
	obj_elf(&E);
	dash_layout(&OB, DASH_LAY_SEC, &t);
	CK(t.declared == 3u && t.n_row == 3u && t.not_shown == 0);
	/* an escape in a section name is made visible */
	hk_elf(&E, 1, 0, 0);
	E.b[E.shstr + 1] = 0x1b;
	obj_elf(&E);
	dash_layout_cell(&OB, DASH_LAY_SEC, 1, c);
	CK(strcmp(c[1], "?text") == 0);
	{
		uint32_t i, k;
		int raw = 0;

		for (i = 0; i < 6; i++) {
			dash_layout_cell(&OB, DASH_LAY_SEC, i, c);
			for (k = 0; k < DASH_COLS; k++)
				if (strchr(c[k], 0x1b))
					raw = 1;
		}
		CK(!raw);
	}
	/* no section table at all */
	hk_elf(&E, 1, 0, 0);
	hk_w(E.b + 60, 0, 2, 0);
	obj_elf(&E);
	dash_layout(&OB, DASH_LAY_SEC, &t);
	CK(t.n_col == 0 && strcmp(t.none, "no section headers") == 0);
	/* a normalised view and an object nothing parsed: both tables say why, in one sentence */
	OB.entry_kind = KOF_ENT_NORMALIZED;
	dash_layout(&OB, DASH_LAY_SEG, &t);
	CK(t.n_col == 0 && strstr(t.none, "normalised view") != NULL);
	memset(&OB, 0, sizeof OB);
	dash_layout(&OB, DASH_LAY_SEC, &t);
	CK(t.n_col == 0 && strstr(t.none, "not a parsed ELF or PE") != NULL);
	dash_layout_cell(&OB, DASH_LAY_SEC, 0, c);
	CK(c[0][0] == 0);
}

static void layout_pe(void)
{
	int plus;

	for (plus = 0; plus < 2; plus++) {
		struct dash_table sg, sc;
		char c[DASH_COLS][DASH_CELL];
		uint32_t i;

		obj_pe(plus);
		dash_layout(&OB, DASH_LAY_SEG, &sg);
		dash_layout(&OB, DASH_LAY_SEC, &sc);
		CK(sg.n_col == 0 && strstr(sg.none, "mapped by its sections") != NULL);
		CK(sc.n_col == 9u && strcmp(sc.head[8], "entropy") == 0 && sc.n_row == PI.sec_count && sc.declared == PI.nsec_claimed && sc.n_row == 3u);
		for (i = 0; i < sc.n_row; i++) {
			const uint8_t *h = P.b + P.sec + i * 40u;

			dash_layout_cell(&OB, DASH_LAY_SEC, i, c);
			CK(strcmp(c[1], PI.sec[i].name) == 0);
			CK(strtoull(c[2], NULL, 16) == rd(h + 12, 4, 0));
			CK(strtoull(c[3], NULL, 16) == rd(h + 8, 4, 0));
			CK(strtoull(c[4], NULL, 16) == rd(h + 20, 4, 0));
			CK(strtoull(c[5], NULL, 10) == rd(h + 16, 4, 0));
			CK(strtoull(c[7], NULL, 16) == rd(h + 36, 4, 0));
		}
	}
}

/* ================================================================================ SYMBOLS */

static uint8_t SYMBLK[KOF_SYM_MAX_BYTES];

static uint32_t build_syms(const char *const *names, const int *undef, uint32_t n, uint64_t value_base)
{
	struct kof_symw w;
	struct kof_symrec r;
	uint32_t i;

	kof_symw_begin(&w, SYMBLK, sizeof SYMBLK, n, 0);
	for (i = 0; i < n; i++) {
		memset(&r, 0, sizeof r);
		r.type = 2;
		r.bind = 1;
		r.flags = undef[i] ? KOF_SYM_F_UNDEFINED : KOF_SYM_F_DEFINED;
		r.shndx = (uint16_t)(3u + i);
		r.size = 10u + i;
		r.value = value_base + i;
		r.name = names[i];
		r.name_len = (uint32_t)strlen(names[i]);
		CK(kof_symw_put(&w, &r) == 1);
	}
	return kof_symw_end(&w);
}

static int model_has(const char *name, const char *filt, int icase)
{
	size_t nl = strlen(name), fl = strlen(filt), i, k;

	for (i = 0; i + fl <= nl; i++) {
		for (k = 0; k < fl; k++) {
			char a = name[i + k], b = filt[k];

			if (icase) {
				a = (char)((a >= 'A' && a <= 'Z') ? a + 32 : a);
				b = (char)((b >= 'A' && b <= 'Z') ? b + 32 : b);
			}
			if (a != b)
				break;
		}
		if (k == fl)
			return 1;
	}
	return 0;
}

static struct dash_filter mkfilter(const char *text, int icase, int rx, uint8_t *prog, uint32_t cap, uint32_t *n, char *err)
{
	struct dash_filter f;
	int ok = 1;

	*n = 0;
	err[0] = 0;
	if (rx && text[0])
		ok = rx_compile(text, prog, cap, n, err, 96);
	f.text = text;
	f.icase = icase;
	f.rx = rx;
	f.bad = rx && text[0] && !ok;
	f.prog = prog;
	f.prog_n = *n;
	f.err = err;
	return f;
}

static void filter_suite(void)
{
	static const char alpha[] = { 'a', 'b', 'A' };
	char name[8], filt[4], err[96];
	uint8_t prog[512];
	uint32_t a, b, c, f1, f2, nl, fl, pn;
	unsigned long n = 0;
	int icase, frx;

	for (icase = 0; icase < 2; icase++)
		for (frx = 0; frx < 2; frx++)
			for (nl = 0; nl <= 3; nl++)
				for (a = 0; a < (nl > 0 ? 3u : 1u); a++)
					for (b = 0; b < (nl > 1 ? 3u : 1u); b++)
						for (c = 0; c < (nl > 2 ? 3u : 1u); c++)
							for (fl = 0; fl <= 2; fl++)
								for (f1 = 0; f1 < (fl > 0 ? 3u : 1u); f1++)
									for (f2 = 0; f2 < (fl > 1 ? 3u : 1u); f2++) {
										struct dash_filter f;

										memset(name, 0, sizeof name);
										memset(filt, 0, sizeof filt);
										if (nl > 0) name[0] = alpha[a];
										if (nl > 1) name[1] = alpha[b];
										if (nl > 2) name[2] = alpha[c];
										if (fl > 0) filt[0] = alpha[f1];
										if (fl > 1) filt[1] = alpha[f2];
										f = mkfilter(filt, icase, frx, prog, sizeof prog, &pn, err);
										CK(dash_filter_ok(&f, name, nl) == (fl == 0 ? 1 : model_has(name, filt, icase)));
										n++;
									}
	CK(n > 2000);
	/* a pattern the engine refuses matches NOTHING, and the compile says so */
	{
		struct dash_filter f = mkfilter("(", 0, 1, prog, sizeof prog, &pn, err);

		CK(f.bad == 1 && err[0]);
		CK(dash_filter_ok(&f, "(", 1) == 0 && dash_filter_ok(&f, "", 0) == 0);
		/* refused means refused, whatever a stale program is still sitting in the buffer */
		f = mkfilter("ab", 0, 1, prog, sizeof prog, &pn, err);
		CK(f.bad == 0 && dash_filter_ok(&f, "xaby", 4) == 1);
		f.bad = 1;
		CK(dash_filter_ok(&f, "xaby", 4) == 0);
	}
}

static struct view *symview(uint32_t nsym, const char *const *names, const int *undef, uint64_t base)
{
	struct view *v = calloc(1, sizeof *v);
	static struct kof_range probe[KOF_SCAN_MAX_EXTENTS];

	memset(&OB, 0, sizeof OB);
	OB.fmt = &FMT;
	OB.ctx.format = KOF_FMT_ELF;
	OB.sym = SYMBLK;
	OB.sym_n = build_syms(names, undef, nsym, base);
	v->probe = probe;
	return v;
}

static struct dash_syms SY;
static struct dash_symcell SC;

static void symbols_data(void)
{
	static const char *const names[6] = { "puts", "Printf", "main", "exit", "helper", "PUTCHAR" };
	static const int undef[6] = { 1, 1, 0, 1, 0, 1 };
	struct view *v = symview(6, names, undef, 0x1000);
	struct dash_filter none = { "", 0, 0, 0, NULL, 0, "" };
	uint8_t prog[512];
	char err[96];
	uint32_t i, pn;
	static const char *const imp[4] = { "puts", "Printf", "exit", "PUTCHAR" };

	/* imports: the four undefined records in reading order; the number is the position in the LIST */
	dash_syms_load(v, &none, &OB, SYMN_IMP, &SY);
	CK(SY.why == DASH_OK && SY.n == 4u && SY.got == 4u && SY.cut == 0);
	for (i = 0; i < SY.n; i++) {
		dash_syms_cell(&SY, i, &SC);
		CK((uint32_t)atoi(SC.cell[0]) == i && strcmp(SC.cell[5], imp[i]) == 0);
		CK(strstr(SC.cell[6], "UND") != NULL);
		CK(strtoull(SC.cell[8], NULL, 16) == 0x1000u + (i == 0 ? 0 : i == 1 ? 1 : i == 2 ? 3 : 5));
	}
	CK(SY.wd == 8 && SY.sw == 8 && SY.nw == 7);                      /* "PUTCHAR" is the longest import */
	dash_syms_cell(&SY, 4, &SC);                                    /* past the end: empty cells */
	CK(SC.cell[0][0] == 0 && SC.cell[5][0] == 0);
	/* exports are the other two */
	dash_syms_load(v, &none, &OB, SYMN_EXP, &SY);
	CK(SY.n == 2u && SY.got == 2u);
	dash_syms_cell(&SY, 0, &SC);
	CK(strcmp(SC.cell[5], "main") == 0);
	/* the filter narrows (folded or not); the number is the position in what is listed; got stays the unfiltered count */
	{
		struct dash_filter f = mkfilter("put", 0, 0, prog, sizeof prog, &pn, err);

		dash_syms_load(v, &f, &OB, SYMN_IMP, &SY);
		CK(SY.n == 1u && SY.got == 4u);
		dash_syms_cell(&SY, 0, &SC);
		CK(strcmp(SC.cell[5], "puts") == 0 && atoi(SC.cell[0]) == 0);
		f = mkfilter("put", 1, 0, prog, sizeof prog, &pn, err);
		dash_syms_load(v, &f, &OB, SYMN_IMP, &SY);
		CK(SY.n == 2u);
		dash_syms_cell(&SY, 1, &SC);
		CK(strcmp(SC.cell[5], "PUTCHAR") == 0 && atoi(SC.cell[0]) == 1);
		/* the four reasons for no rows */
		f = mkfilter("zzz", 0, 0, prog, sizeof prog, &pn, err);
		dash_syms_load(v, &f, &OB, SYMN_IMP, &SY);
		CK(SY.why == DASH_FILTER && SY.n == 0 && SY.got == 4u);
		f = mkfilter("(", 0, 1, prog, sizeof prog, &pn, err);
		dash_syms_load(v, &f, &OB, SYMN_IMP, &SY);
		CK(SY.why == DASH_RX && SY.n == 0);
	}
	OB.ctx.format = KOF_FMT_SCRIPT;
	dash_syms_load(v, &none, &OB, SYMN_EXP, &SY);
	CK(SY.why == DASH_NA);
	OB.ctx.format = KOF_FMT_ELF;
	/* a cut block is reported, never presented as whole */
	SYMBLK[KOF_SYM_H_TRUNC] = KOF_SYM_TRUNC_ROOM;
	dash_syms_load(v, &none, &OB, SYMN_IMP, &SY);
	CK(SY.cut == 1 && SY.n == 4u);
	SYMBLK[KOF_SYM_H_TRUNC] = KOF_SYM_TRUNC_SOURCE;
	dash_syms_load(v, &none, &OB, SYMN_IMP, &SY);
	CK(SY.cut == 2);
	SYMBLK[KOF_SYM_H_TRUNC] = 0;
	free(v);
	/* nothing declared in the half asked for */
	{
		static const char *const one[1] = { "main" };
		static const int def[1] = { 0 };
		struct view *w = symview(1, one, def, 0x1000);

		dash_syms_load(w, &none, &OB, SYMN_IMP, &SY);
		CK(SY.why == DASH_NONE && SY.n == 0 && SY.got == 0);
		free(w);
	}
}

/* Wide values widen the columns, the longest name sets the name column, the finder's row is found by VALUE. */
static void symbols_widths_and_found(void)
{
	char longname[300];
	const char *names[3];
	static const int undef[3] = { 1, 1, 1 };
	struct dash_filter none = { "", 0, 0, 0, NULL, 0, "" };
	struct view *v;

	memset(longname, 'n', sizeof longname - 1);
	longname[sizeof longname - 1] = 0;
	names[0] = longname;
	names[1] = "short";
	names[2] = "esc\x1b[31mx";
	v = symview(3, names, undef, 0x100000000ull);       /* values past 32 bits */
	dash_syms_load(v, &none, &OB, SYMN_IMP, &SY);
	CK(SY.wd == 16 && SY.sw == 12 && SY.nw == 299);
	dash_syms_cell(&SY, 0, &SC);
	CK(strlen(SC.cell[5]) == 299u && strcmp(SC.cell[8], "0x0000000100000000") == 0);
	dash_syms_cell(&SY, 2, &SC);
	CK(strchr(SC.cell[5], 0x1b) == NULL && strstr(SC.cell[5], "esc?[31mx") != NULL);
	/* the row a finder named: only that value, and zero is a real value that "no payload" must not claim */
	OB.payload_at = 0x100000001ull;
	CK(!dash_syms_found(&SY, 0) && dash_syms_found(&SY, 1) && !dash_syms_found(&SY, 2) && !dash_syms_found(&SY, 3));
	OB.payload_at = 0;
	CK(!dash_syms_found(&SY, 0) && !dash_syms_found(&SY, 1));
	free(v);
	/* a symbol whose value IS zero (every undefined symbol): no payload must not claim it */
	v = symview(3, names, undef, 0);
	dash_syms_load(v, &none, &OB, SYMN_IMP, &SY);
	OB.payload_at = 0;
	CK(!dash_syms_found(&SY, 0));
	OB.payload_at = 1;
	CK(!dash_syms_found(&SY, 0) && dash_syms_found(&SY, 1));
	free(v);
}

static void size_text_rows(void)
{
	char t[80];

	dash_size_text(t, sizeof t, 0);
	CK(strcmp(t, "0 bytes") == 0);
	dash_size_text(t, sizeof t, 1);
	CK(strcmp(t, "1 byte") == 0);
	dash_size_text(t, sizeof t, 1023);
	CK(strcmp(t, "1023 bytes") == 0);
	dash_size_text(t, sizeof t, 1024);
	CK(strcmp(t, "1024 bytes (1.0 KiB)") == 0);
	dash_size_text(t, sizeof t, 127723);
	CK(strcmp(t, "127723 bytes (124.7 KiB)") == 0);
	dash_size_text(t, sizeof t, 1048575);                  /* truncated, never rounded up to 1024.0 KiB */
	CK(strcmp(t, "1048575 bytes (1023.9 KiB)") == 0);
	dash_size_text(t, sizeof t, 1048576);
	CK(strcmp(t, "1048576 bytes (1.0 MiB)") == 0);
	dash_size_text(t, sizeof t, UINT64_MAX);
	CK(strncmp(t, "18446744073709551615 bytes (", 28) == 0 && strstr(t, " EiB)") != NULL);
	dash_size_text(t, 12, 127723);                          /* a small buffer cuts, never overruns */
	CK(strlen(t) < 12);
}

static void tabs_labels(void)
{
	static const char *const names[5] = { "a", "b", "c", "d", "e" };
	static const int undef[5] = { 1, 1, 0, 0, 0 };
	struct view *v = symview(5, names, undef, 1);
	char lab[DASH_TABS][32];

	dash_tabs(v, &OB, lab);
	CK(strcmp(lab[0], "Overview") == 0 && strcmp(lab[1], "Segments") == 0 && strcmp(lab[2], "Sections") == 0);
	CK(strcmp(lab[3], "Imports") == 0 && strcmp(lab[4], "Exports") == 0);   /* five tabs, no count on the strip */
	v->probe = NULL;                                   /* no probe: the labels are still there */
	dash_tabs(v, &OB, lab);
	CK(strcmp(lab[3], "Imports") == 0 && strcmp(lab[4], "Exports") == 0);
	free(v);
}

/* A block that has more rows than its bound says how many it did not show: nothing is dropped silently. */
static void block_bound(void)
{
	struct view *v = calloc(1, sizeof *v);
	uint32_t i;
	static char label[DASH_ROWS + 20][16];

	memset(&OB, 0, sizeof OB);
	OB.ctx.format = KOF_FMT_ELF;
	v->n_node = DASH_ROWS + 20u;
	for (i = 0; i < v->n_node; i++) {
		snprintf(label[i], sizeof label[i], "R%u", i);
		v->node[i].obj = 0;
		v->node[i].mask = 1u;
		v->node[i].bytes = 1;
		snprintf(v->node[i].label, sizeof v->node[i].label, "%.15s", label[i]);
	}
	OB.buf.n = v->n_node;
	dash_regions(v, &OB, &BK);
	CK(BK.n == DASH_ROWS && BK.not_shown == 20u);
	free(v);
}


/* ================================================================================ INFECTION DIALOG */

static struct dash_infect INF;
static struct dash_shell SHL;
static struct dash_widecell WC;

static int inf_row(const char *name)
{
	uint32_t i;

	for (i = 0; i < INF.n; i++)
		if (strcmp(INF.row[i].name, name) == 0)
			return (int)i;
	return -1;
}

static int shl_row(const char *name)
{
	uint32_t i;

	for (i = 0; i < SHL.n; i++)
		if (strcmp(SHL.row[i].name, name) == 0)
			return (int)i;
	return -1;
}

static void perm_text(char *out, unsigned p)
{
	snprintf(out, 4, "%c%c%c", (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-', (p & 1) ? 'X' : '-');
}

/* Infected data: the library's rows spelled as cells, the engine's ranges on the entry, none, and outside every region. */
static void infect_rows(void)
{
	struct dash_table t;
	char want[48];
	int r, k;
	uint32_t i, flagged = 0;

	hk_elf(&E, 1, 0, 0);
	obj_elf(&E);
	/* none reported: every row is plain, the table has five columns in the owner's order */
	dash_infect_load(&OB, &INF);
	dash_infect_table(&INF, &t);
	CK(INF.why == DASH_OK && INF.n >= 4u && INF.total == INF.n && t.n_col == DASH_INF_COLS && strcmp(t.head[5], "value") == 0 && t.n_row == INF.n && t.not_shown == 0);
	CK(strcmp(t.head[0], "region") == 0 && strcmp(t.head[1], "file offset") == 0 && strcmp(t.head[2], "address") == 0 &&
	   strcmp(t.head[3], "size") == 0 && strcmp(t.head[4], "state") == 0);
	for (i = 0; i < INF.n; i++) {
		CK(!dash_infect_flagged(&INF, i));
		dash_infect_cell(&INF, i, &WC);
		CK(strcmp(WC.cell[4], "-") == 0);
	}
	r = inf_row("entry point");
	CK(r >= 0);
	dash_infect_cell(&INF, (uint32_t)r, &WC);
	snprintf(want, sizeof want, "0x%x", E.text);
	CK(strcmp(WC.cell[1], want) == 0);
	snprintf(want, sizeof want, "0x%llx", (unsigned long long)EI.entry_addr);
	CK(strcmp(WC.cell[2], want) == 0 && strcmp(WC.cell[3], "16") == 0);
	/* the value column of this table is the same builder: the 16 bytes at the entry, no dots */
	{
		char hx[64];
		size_t o = 0;
		unsigned q;

		for (q = 0; q < 16u; q++)
			o += (size_t)snprintf(hx + o, sizeof hx - o, "%s%02x", q ? " " : "", E.b[E.text + q]);
		CK(strcmp(WC.cell[5], hx) == 0);
		CK(dash_infect_value_width(&INF) >= 47u);
	}

	/* an infected range on the entry: that row and the section it is in are the highlighted ones, each says "infected" and the kind */
	OB.n_infected = 1;
	OB.infected[0].off = E.text + 4u;
	OB.infected[0].len = 4;
	OB.infected[0].kind = KOF_INF_DAMAGE;
	dash_infect_load(&OB, &INF);
	for (i = 0; i < INF.n; i++)
		flagged += (uint32_t)dash_infect_flagged(&INF, i);
	CK(flagged >= 2u && dash_infect_flagged(&INF, (uint32_t)inf_row("entry point")) &&
	   dash_infect_flagged(&INF, (uint32_t)inf_row("entry section .text")));
	for (i = 0; i < INF.n; i++) {
		dash_infect_cell(&INF, i, &WC);
		CK(dash_infect_flagged(&INF, i) ? strcmp(WC.cell[4], "infected (damage)") == 0 : strcmp(WC.cell[4], "-") == 0);
	}
	OB.infected[0].kind = KOF_INF_BODY;
	dash_infect_load(&OB, &INF);
	dash_infect_cell(&INF, (uint32_t)inf_row("entry point"), &WC);
	CK(strcmp(WC.cell[4], "infected (body)") == 0);

	/* outside every region (past the end of the object): a row of its own, no address, and nothing else flagged by it */
	OB.infected[0].off = E.n + 100u;
	OB.infected[0].len = 8;
	dash_infect_load(&OB, &INF);
	r = inf_row("reported by the engine");
	CK(r == (int)INF.n - 1 && dash_infect_flagged(&INF, (uint32_t)r));
	dash_infect_cell(&INF, (uint32_t)r, &WC);
	snprintf(want, sizeof want, "0x%x", E.n + 100u);
	CK(strcmp(WC.cell[1], want) == 0 && strcmp(WC.cell[2], "-") == 0 && strcmp(WC.cell[3], "8") == 0 && strcmp(WC.cell[4], "infected (body)") == 0);
	for (k = 0; k < r; k++)
		CK(!dash_infect_flagged(&INF, (uint32_t)k));
	CK(!dash_infect_flagged(&INF, INF.n));    /* a row past the end is not flagged */
	dash_infect_cell(&INF, INF.n + 5u, &WC);
	CK(WC.cell[0][0] == 0 && WC.cell[4][0] == 0);                                  /* ... and its cells are empty */

	/* the engine's ranges beyond what the object keeps are not read (KOF_MAX_INFECTED) */
	OB.n_infected = 1000;
	dash_infect_load(&OB, &INF);
	CK(INF.n <= KGENOME_INFECT_MAX);

	/* no entry in the file (an ET_REL): no entry row, the table still lists the rest */
	hk_elf(&E, 1, 0, 1);
	obj_elf(&E);
	dash_infect_load(&OB, &INF);
	CK(INF.why == DASH_OK && inf_row("entry point") < 0);

	/* an object that is not a parsed ELF or PE: nothing to list, and the sentence says so; a report of the engine still shows */
	memset(&OB, 0, sizeof OB);
	OB.buf.n = 64;
	OB.ctx.format = KOF_FMT_UNKNOWN;
	dash_infect_load(&OB, &INF);
	dash_infect_table(&INF, &t);
	CK(INF.why == DASH_NA && INF.n == 0 && t.n_col == 0 && strstr(t.none, "not a parsed ELF or PE") != NULL);
	OB.n_infected = 1;
	OB.infected[0].off = 3;
	OB.infected[0].len = 5;
	OB.infected[0].kind = KOF_INF_BODY;
	dash_infect_load(&OB, &INF);
	dash_infect_table(&INF, &t);
	CK(INF.why == DASH_OK && INF.n == 1 && t.n_col == DASH_INF_COLS && inf_row("reported by the engine") == 0);

	/* a PE: its regions are the PE's and are in the same five columns */
	obj_pe(1);
	dash_infect_load(&OB, &INF);
	CK(INF.why == DASH_OK && inf_row("entry point") >= 0 && inf_row("last section .reloc") >= 0);
}

/* Shellcode: the finder's row first and flagged, the variable in executable memory, the ranges; every cell against the bytes. */
static void shell_rows(void)
{
	struct dash_table t;
	char want[48], perm[4];
	uint8_t *s;
	int r;

	hk_elf(&E, 1, 0, 0);
	obj_elf(&E);
	/* a plain program: nothing carries execute permission that is data, and the sentence says so */
	dash_shell_load(&OB, &SHL);
	dash_shell_table(&SHL, &t);
	CK(SHL.why == DASH_NONE && SHL.n == 0 && t.n_col == 0 && strstr(t.none, "no variable or data range") != NULL);

	/* a data object inside the executable segment (symbol "helper", 6 bytes at text + 10) is a symbol row */
	s = E.b + E.symtab + 3u * E.sym_ent;
	s[4] = 0x11;                                /* GLOBAL OBJECT */
	obj_elf(&E);
	dash_shell_load(&OB, &SHL);
	dash_shell_table(&SHL, &t);
	r = shl_row("helper");
	CK(SHL.why == DASH_OK && SHL.n == 1 && r == 0 && t.n_col == DASH_SHELL_COLS && t.n_row == 1);
	CK(strcmp(t.head[0], "name") == 0 && strcmp(t.head[1], "address") == 0 && strcmp(t.head[2], "file offset") == 0 &&
	   strcmp(t.head[3], "size") == 0 && strcmp(t.head[4], "perm") == 0 && strcmp(t.head[5], "type") == 0 && strcmp(t.head[6], "refs") == 0 &&
	   strcmp(t.head[7], "entropy") == 0 && strcmp(t.head[8], "value") == 0);
	dash_shell_cell(&SHL, 0, &WC);
	snprintf(want, sizeof want, "0x%x", 0x400000u + E.text + 10u);
	CK(strcmp(WC.cell[1], want) == 0);
	snprintf(want, sizeof want, "0x%x", E.text + 10u);
	CK(strcmp(WC.cell[2], want) == 0 && strcmp(WC.cell[3], "6") == 0 && strcmp(WC.cell[4], "R-X") == 0 && strcmp(WC.cell[5], "symbol") == 0 &&
	   !dash_shell_flagged(&SHL, 0));
	/* the value: the range's own bytes in hex, from an independent reader of the object */
	{
		char hx[64];
		unsigned q;

		size_t o = 0;

		for (q = 0; q < 6u; q++)
			o += (size_t)snprintf(hx + o, sizeof hx - o, "%s%02x", q ? " " : "", E.b[E.text + 10u + q]);
		CK(strcmp(WC.cell[8], hx) == 0);
	}

	/* the finder's answer: its row comes first and is flagged, with its words; the same symbol is not repeated */
	OB.payload_at = 0x400000u + E.text + 10u;
	OB.payload_len = 6;
	OB.payload_bits = 64;
	dash_shell_load(&OB, &SHL);
	CK(SHL.n == 1 && dash_shell_flagged(&SHL, 0));
	dash_shell_cell(&SHL, 0, &WC);
	CK(strcmp(WC.cell[0], "payload") == 0 && strcmp(WC.cell[5], "finder") == 0 && WC.cell[8][0] != 0 && strchr(WC.cell[8], '.') == NULL);
	/* a payload address the object does not map: still the finder's row, with no file offset and no permission */
	OB.payload_at = 0x10;
	dash_shell_load(&OB, &SHL);
	dash_shell_cell(&SHL, 0, &WC);
	CK(SHL.n == 2 && strcmp(WC.cell[2], "-") == 0 && strcmp(WC.cell[4], "---") == 0);
	OB.payload_at = 0;
	OB.payload_len = 0;

	/* the value text, one builder for both tables: the whole range up to DASH_VALUE_BYTES, " ..." beyond, "-" with no bytes */
	{
		static uint8_t big[2u * DASH_VALUE_BYTES + 64u];
		static char txt[DASH_VALUE_CELL];
		kof_buf f = kof_buf_make(big, sizeof big);
		uint32_t i;

		for (i = 0; i < sizeof big; i++)
			big[i] = (uint8_t)(i * 7u + 3u);
		dash_value_text(txt, sizeof txt, f, 0, 40);
		CK(strlen(txt) == 40u * 3u - 1u && strstr(txt, "...") == NULL && strncmp(txt, "03 0a 11", 8) == 0);
		CK(dash_value_len(f, 0, 40) == strlen(txt));
		dash_value_text(txt, sizeof txt, f, 0, DASH_VALUE_BYTES);               /* exactly the cap: all of it, no dots */
		CK(strlen(txt) == 3u * DASH_VALUE_BYTES - 1u && strstr(txt, "...") == NULL && dash_value_len(f, 0, DASH_VALUE_BYTES) == strlen(txt));
		dash_value_text(txt, sizeof txt, f, 0, DASH_VALUE_BYTES + 1u);          /* one over: the cap and the dots */
		CK(strlen(txt) == 3u * DASH_VALUE_BYTES - 1u + 4u && strcmp(txt + strlen(txt) - 4, " ...") == 0 &&
		   dash_value_len(f, 0, DASH_VALUE_BYTES + 1u) == strlen(txt));
		dash_value_text(txt, sizeof txt, f, 5, ~0ull);                          /* a hostile size */
		CK(strlen(txt) == 3u * DASH_VALUE_BYTES - 1u + 4u && strncmp(txt, "26 2d", 5) == 0);
		dash_value_text(txt, sizeof txt, f, f.n, 8);                            /* at the end: no bytes */
		CK(strcmp(txt, "-") == 0 && dash_value_len(f, f.n, 8) == 1u);
		dash_value_text(txt, sizeof txt, f, f.n - 3u, 8);                       /* past the end: only what is there, and the dots */
		CK(strlen(txt) == 3u * 3u - 1u + 4u && dash_value_len(f, f.n - 3u, 8) == strlen(txt));
		dash_value_text(txt, sizeof txt, f, KGENOME_NA, 8);
		CK(strcmp(txt, "-") == 0);
		dash_value_text(txt, sizeof txt, f, 0, 0);
		CK(strcmp(txt, "-") == 0);
		dash_value_text(txt, 10, f, 0, 40);                                     /* a small buffer cuts and never overruns */
		CK(strlen(txt) < 10u);
		dash_value_text(txt, 0, f, 0, 40);
	}

	/* the context columns from the library's facts: refs by kind, decode share, entropy, shape; "?" and "-" are not the same */
	{
		static struct dash_shell F;
		struct kofscfind_row *q;

		memset(&F, 0, sizeof F);
		F.row = calloc(4, sizeof *F.row);
		F.n = 4;
		F.file = kof_buf_make(E.b, E.n);
		q = &F.row[0];                          /* referenced: call 1, read 3; complete map; decodes 92% with a system call; 7.35 bits */
		q->what = KOFSCFIND_W_SYMBOL; q->size = 40; q->off = 0; q->facts_ok = 1;
		q->facts.refs_known = 1; q->facts.refs.call = 1; q->facts.refs.read = 3; q->facts.decodes = 1; q->facts.decode_pct = 92;
		q->facts.syscall = 1; q->facts.entropy_centi = 735; q->facts.shape = KGENOME_RANGE_CODE_LIKE; q->facts.analysed = 40;
		q->strong = 1; q->flagged = 1;
		dash_shell_cell(&F, 0, &WC);
		CK(strcmp(WC.cell[6], "call 1 \xc2\xb7 read 3") == 0 && strcmp(WC.cell[7], "7.3") == 0 && dash_shell_flagged(&F, 0));
		q = &F.row[1];                          /* a cut map: the counts are what was seen; a pointer table word; the range is cut at the cap */
		q->what = KOFSCFIND_W_RANGE; q->size = 20000; q->off = 0; q->facts_ok = 1;
		q->facts.refs_known = 1; q->facts.refs_partial = 1; q->facts.refs.jump = 2; q->facts.refs_ptr = 1; q->facts.decodes = 1;
		q->facts.decode_pct = 50; q->facts.entropy_centi = 800; q->facts.shape = KGENOME_RANGE_RANDOM; q->facts.analysed = DASH_VALUE_BYTES;
		dash_shell_cell(&F, 1, &WC);
		CK(strcmp(WC.cell[6], "jump 2 \xc2\xb7 ptr 1 ?") == 0 && strcmp(WC.cell[7], "8.0+") == 0 && !dash_shell_flagged(&F, 1));
		q = &F.row[2];                          /* no map (an architecture the sweep does not track): unknown; no decoder: "-" */
		q->what = KOFSCFIND_W_RANGE; q->size = 8; q->off = 0; q->facts_ok = 1; q->facts.shape = KGENOME_RANGE_MIXED; q->facts.analysed = 8;
		dash_shell_cell(&F, 2, &WC);
		CK(strcmp(WC.cell[6], "?") == 0);
		q = &F.row[3];                          /* a map that is complete and nothing refers to the range: "-"; no bytes at all: "-" everywhere */
		q->what = KOFSCFIND_W_RANGE; q->size = 8; q->off = KGENOME_NA; q->facts_ok = 0;
		dash_shell_cell(&F, 3, &WC);
		CK(strcmp(WC.cell[6], "-") == 0 && strcmp(WC.cell[7], "-") == 0 && strcmp(WC.cell[8], "-") == 0);
		F.row[3].facts_ok = 1; F.row[3].off = 0; F.row[3].facts.refs_known = 1;
		dash_shell_cell(&F, 3, &WC);
		CK(strcmp(WC.cell[6], "-") == 0);
		/* the width is the longest text without producing any */
		CK(dash_shell_value_width(&F) == dash_value_len(F.file, 0, 20000) || dash_shell_value_width(&F) >= 3u * E.n - 1u);
		WC.no_value = 1;
		dash_shell_cell(&F, 0, &WC);
		CK(WC.cell[8][0] == 0);                 /* measuring: no value text */
		WC.no_value = 0;
		free(F.row);
	}

	/* a writable and executable segment is a range row */
	hk_elf(&E, 1, 0, 0);
	E.b[E.ph + 4] = 7;                          /* p_flags RWX */
	obj_elf(&E);
	dash_shell_load(&OB, &SHL);
	r = shl_row("segment #0 (writable and executable)");
	CK(r == 0 && SHL.n == 1);
	dash_shell_cell(&SHL, 0, &WC);
	perm_text(perm, KGENOME_PERM_R | KGENOME_PERM_W | KGENOME_PERM_X);
	snprintf(want, sizeof want, "%u", E.n);
	CK(strcmp(WC.cell[1], "0x400000") == 0 && strcmp(WC.cell[2], "0x0") == 0 && strcmp(WC.cell[3], want) == 0 && strcmp(WC.cell[4], perm) == 0 &&
	   strcmp(WC.cell[5], "range") == 0 && !dash_shell_flagged(&SHL, 0));

	/* an ET_REL: a variable in an executable section; the address is the section's plus the value */
	hk_elf(&E, 1, 0, 1);
	s = E.b + E.symtab + 3u * E.sym_ent;
	s[4] = 0x11;
	s[8] = 10; s[9] = s[10] = s[11] = s[12] = s[13] = s[14] = s[15] = 0;
	obj_elf(&E);
	dash_shell_load(&OB, &SHL);
	CK(SHL.n == 1 && strcmp(SHL.row[0].name, "helper") == 0 && SHL.row[0].off == E.text + 10u && SHL.row[0].perm == (KGENOME_PERM_R | KGENOME_PERM_X));

	/* a PE with a writable executable section: a range row in RVA and raw offset */
	obj_pe(1);
	PI.sec[0].perm = KGENOME_PE_PERM_R | KGENOME_PE_PERM_W | KGENOME_PE_PERM_X;
	dash_shell_load(&OB, &SHL);
	r = shl_row(".text (writable and executable section)");
	CK(r == 0 && SHL.row[0].va == PI.sec[0].mem_rva && SHL.row[0].off == PI.sec[0].file_off && SHL.row[0].what == KOFSCFIND_W_RANGE);

	/* not an executable image: the sentence says it, and a finder row is never invented */
	memset(&OB, 0, sizeof OB);
	OB.buf.n = 64;
	OB.ctx.format = KOF_FMT_UNKNOWN;
	dash_shell_load(&OB, &SHL);
	dash_shell_table(&SHL, &t);
	CK(SHL.why == DASH_NA && SHL.n == 0 && t.n_col == 0 && strstr(t.none, "not an executable image") != NULL);
}

/* The strip of the Infection book: two labels, in the owner's order; the dashboard's stays five. */
static void infect_tabs(void)
{
	struct view *v = calloc(1, sizeof *v);
	char lab[DASH_TABS][32];

	CK(dash_tabs(v, &OB, lab) == 5u && strcmp(lab[0], "Overview") == 0);
	v->prop_inf = 1;
	CK(dash_tabs(v, &OB, lab) == 2u && strcmp(lab[0], "Infected data") == 0 && strcmp(lab[1], "Shellcode") == 0);
	free(v);
}

/* ================================================================================ ENTROPY AND THE COUNT */

/* Independent oracle: Shannon entropy of n bytes in bits per byte, in doubles (the library's is integer arithmetic). */
static double ent_oracle(const uint8_t *p, uint64_t n)
{
	uint64_t h[256] = { 0 }, i;
	double e = 0;

	for (i = 0; i < n; i++)
		h[p[i]]++;
	for (i = 0; i < 256; i++)
		if (h[i])
			e -= ((double)h[i] / (double)n) * log2((double)h[i] / (double)n);
	return e;
}

/* The cell must read "x.xx" (plus "+" when `cut`) within the library's own accuracy of the oracle. */
static void want_entropy(const char *cell, const uint8_t *p, uint64_t n, int cut)
{
	double got = atof(cell), want = ent_oracle(p, n);
	size_t l = strlen(cell);

	CK(l >= 4u && cell[l - (cut ? 2 : 1)] != '.' && (cut ? cell[l - 1] == '+' : isdigit((unsigned char)cell[l - 1])));
	CK(strchr(cell, '.') != NULL && strchr(cell, '.')[1] != 0 && strchr(cell, '.')[2] != 0);
	CK(fabs(got - want) <= 0.011);
}

static void centi_core(void)
{
	uint32_t h[256];
	unsigned a, b, c, k;
	uint32_t i;

	CK(kentropy_hist_centi(NULL, 5) == 0);
	memset(h, 0, sizeof h);
	CK(kentropy_hist_centi(h, 0) == 0);
	h[7] = 100;
	CK(kentropy_hist_centi(h, 100) == 0);
	for (i = 0; i < 256; i++)
		h[i] = 3;
	CK(kentropy_hist_centi(h, 768) == 800);
	h[0] = 1000000;                               /* a bucket above the total: clamped, still within 0..800 */
	CK(kentropy_hist_centi(h, 768) <= 800u);
	/* every histogram over three symbols with counts 0..14: within the rounding of the double oracle */
	for (a = 0; a < 15; a++)
		for (b = 0; b < 15; b++)
			for (c = 0; c < 15; c++) {
				uint64_t n = a + b + c;
				double e = 0, cnt[3] = { (double)a, (double)b, (double)c };
				uint32_t got;

				if (!n)
					continue;
				for (k = 0; k < 3; k++)
					if (cnt[k] > 0)
						e -= cnt[k] / (double)n * log2(cnt[k] / (double)n);
				memset(h, 0, sizeof h);
				h[0] = a; h[1] = b; h[2] = c;
				got = kentropy_hist_centi(h, n);
				CK(fabs((double)got / 100.0 - e) <= 0.0055);                   /* rounding to a hundredth (0.005) plus the 12-bit log (0.00025) */
			}
}

static void obj_elf_over(uint8_t *buf, uint32_t n)
{
	struct kgenome_obj o;

	memset(&OB, 0, sizeof OB);
	memset(&EI, 0, sizeof EI);
	memset(&o, 0, sizeof o);
	CK(kgenome_elf_image_parse(kof_buf_make(buf, n), &EI, &o));
	OB.buf = kof_buf_make(buf, n);
	OB.fmt = &FMT;
	OB.info = &EI;
	OB.ctx.format = KOF_FMT_ELF;
}

static void entropy_suite(void)
{
	enum { BIG = 3 << 19 };       /* 1.5 MiB: past the 1 MiB bound */
	uint8_t *big = malloc((size_t)BIG + 16u);
	uint32_t i, x = 12345u;
	char c[DASH_COLS][DASH_CELL];
	char cell[DASH_CELL];
	uint8_t *sh;

	centi_core();
	/* every row of a plain object: segment 0 and each section, against the bytes the header names */
	hk_elf(&E, 1, 0, 0);
	obj_elf(&E);
	for (i = 0; i < EI.sec_count; i++) {
		const uint8_t *h = E.b + E.sh + i * E.sh_ent;
		uint64_t off = rd(h + 24, 8, 0), len = rd(h + 32, 8, 0);

		dash_layout_entropy(&OB, DASH_LAY_SEC, i, cell, sizeof cell);
		if (rd(h + 4, 4, 0) == 8u || !len || off >= E.n)
			CK(strcmp(cell, "-") == 0);
		else
			want_entropy(cell, E.b + off, len > E.n - off ? E.n - off : len, 0);
		dash_layout_cell(&OB, DASH_LAY_SEC, i, c);
		CK(strcmp(c[11], cell) == 0);                      /* the last cell of the row is the same text */
	}
	dash_layout_entropy(&OB, DASH_LAY_SEG, 0, cell, sizeof cell);
	want_entropy(cell, E.b + rd(E.b + E.ph + 8, 8, 0), rd(E.b + E.ph + 32, 8, 0) > E.n ? E.n : rd(E.b + E.ph + 32, 8, 0), 0);
	dash_layout_cell(&OB, DASH_LAY_SEC, 99, c);            /* a row past the table: empty cells, entropy included */
	CK(c[0][0] == 0 && c[11][0] == 0);

	/* hostile and bounded ranges over a big buffer: the first 4 KiB is the ELF, then a zero block, then noise */
	memset(big, 0, (size_t)BIG + 16u);
	memcpy(big, E.b, E.n);
	for (i = 8192; i < BIG; i++) {
		x = x * 1103515245u + 12345u;
		big[i] = (uint8_t)(x >> 16);
	}
	sh = big + E.sh;
#define SETSEC(k, type, off, len) do { hk_w(sh + (k) * E.sh_ent + 4, (type), 4, 0); hk_w(sh + (k) * E.sh_ent + 24, (off), 8, 0); \
				       hk_w(sh + (k) * E.sh_ent + 32, (len), 8, 0); } while (0)
	SETSEC(1, 1, 8192, BIG - 8192);                         /* past the bound: a prefix, said with "+" */
	SETSEC(2, 1, 4096, 4096);                               /* all zero */
	SETSEC(3, 1, BIG - 100, 1ull << 40);                    /* a size far past the file: clipped, not read out of bounds */
	SETSEC(4, 1, 1ull << 40, 100);                          /* an offset past the file */
	SETSEC(5, 8, 8192, 4096);                               /* NOBITS: no bytes in the file */
	obj_elf_over(big, BIG);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 1, cell, sizeof cell);
	want_entropy(cell, big + 8192, 1u << 20, 1);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 2, cell, sizeof cell);
	CK(strcmp(cell, "0.00") == 0);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 3, cell, sizeof cell);
	want_entropy(cell, big + BIG - 100, 100, 0);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 4, cell, sizeof cell);
	CK(strcmp(cell, "-") == 0);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 5, cell, sizeof cell);
	CK(strcmp(cell, "-") == 0);
	/* exactly the bound: no marker; one byte more: the marker */
	SETSEC(1, 1, 8192, 1u << 20);
	obj_elf_over(big, BIG);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 1, cell, sizeof cell);
	want_entropy(cell, big + 8192, 1u << 20, 0);
	SETSEC(1, 1, 8192, (1u << 20) + 1u);
	obj_elf_over(big, BIG);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 1, cell, sizeof cell);
	CK(strchr(cell, '+') != NULL);
#undef SETSEC
	free(big);
	/* a PE: each section's raw bytes */
	obj_pe(0);
	for (i = 0; i < PI.sec_count; i++) {
		const uint8_t *h = P.b + P.sec + i * 40u;
		uint64_t off = rd(h + 20, 4, 0), len = rd(h + 16, 4, 0);

		dash_layout_entropy(&OB, DASH_LAY_SEC, i, cell, sizeof cell);
		if (!len || off >= P.n)
			CK(strcmp(cell, "-") == 0);
		else
			want_entropy(cell, P.b + off, len > P.n - off ? P.n - off : len, 0);
	}
	/* an object nothing parsed has no ranges */
	memset(&OB, 0, sizeof OB);
	dash_layout_entropy(&OB, DASH_LAY_SEC, 0, cell, sizeof cell);
	CK(strcmp(cell, "-") == 0);
}

/* The dialog's count text: lines on the overview, items on a table page; nothing is cut. */
static void count_text(void)
{
	char t[48];

	dash_count_text(t, sizeof t, "lines", 0, 20, 20);
	CK(strcmp(t, "1-20 of 20 lines") == 0);
	dash_count_text(t, sizeof t, "items", 4, 4, 30);
	CK(strcmp(t, "5-8 of 30 items") == 0);
	dash_count_text(t, sizeof t, "items", 0, 0, 0);
	CK(strcmp(t, "0 of 0 items") == 0);
	dash_count_text(t, sizeof t, "lines", 0, 0, 0);
	CK(strcmp(t, "0 of 0 lines") == 0);
	dash_count_text(t, sizeof t, NULL, 2, 3, 9);
	CK(strcmp(t, "3-5 of 9") == 0);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	header_elf_shapes();
	header_hostile();
	header_pe_rows();
	regions_rows();
	anomalies_rows();
	heuristic_rows();
	layout_elf_shapes();
	layout_hostile();
	layout_pe();
	filter_suite();
	symbols_data();
	symbols_widths_and_found();
	size_text_rows();
	tabs_labels();
	entropy_suite();
	count_text();
	block_bound();
	infect_rows();
	shell_rows();
	infect_tabs();
	printf("kx_dashdata: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
