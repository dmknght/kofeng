#define _GNU_SOURCE

/*
 * kv_dashdata.c - the dashboard's content as data. See kv_dashdata.h for the contract: nothing here draws, takes a
 * terminal's geometry or writes an escape sequence; a row is text and a tone, a table is columns, a count and a
 * cell function. Where the facts come from is the engine's parse of the object (kgenome_elf_info, kgenome_pe_info on
 * ob->info, the region partition on the view's tree, the heuristic result on ob->heur, the SYM block) and the two
 * accessors of libgenome for the header fields the parse does not keep.
 */

#include "kv.h"

/* ---- row builders ----------------------------------------------------------------------------------------- */

static struct dash_row *row_new(struct dash_block *b, const char *label, enum dash_tone lt)
{
	struct dash_row *r;

	if (b->n >= DASH_ROWS) {
		b->not_shown++;
		return NULL;
	}
	r = &b->row[b->n++];
	memset(r, 0, sizeof *r);
	snprintf(r->label, sizeof r->label, "%s", label);
	r->label_tone = lt;
	return r;
}

static void span(struct dash_row *r, enum dash_tone t, const char *fmt, ...)
{
	va_list ap;

	if (!r || r->n >= DASH_SPANS)
		return;
	r->s[r->n].tone = t;
	va_start(ap, fmt);
	vsnprintf(r->s[r->n].text, sizeof r->s[r->n].text, fmt, ap);
	va_end(ap);
	r->n++;
}

static void block_begin(struct dash_block *b, const char *head)
{
	memset(&b->n, 0, sizeof *b - offsetof(struct dash_block, n));
	snprintf(b->head, sizeof b->head, "%s", head);
}

/* A header whose count matches what was kept says nothing: the table and its corner count are the answer. A count
 * that did not add up is said (warn tone), because a bound cut evidence and that must be reported. */
static void claimed(struct dash_block *b, const char *label, uint32_t have, uint32_t claim)
{
	struct dash_row *r;

	if (have == claim)
		return;
	r = row_new(b, label, DT_DIM);
	span(r, DT_WARN, "%u kept, the header declares %u", have, claim);
}

/* ---- the overview's format block ------------------------------------------------------------------------- */

/* The words come from the engine's libraries (kgenome_arch_title, kgenome_elf_shape, kgenome_elf_entry_sec; the
 * type is kof_inspect_subtype_name's one spelling): nothing here decides what a
 * number means, it only places the answer in a row. A value the library does not name is shown as its number. */

/* A word that came out of a file, safe to put on a terminal: a byte below a space is not text. */
static void clean_into(char *out, size_t cap, const char *s, size_t max)
{
	size_t i = 0;

	for (; i + 1u < cap && i < max && s[i]; i++)
		out[i] = ((unsigned char)s[i] < 0x20u || (unsigned char)s[i] == 0x7fu) ? '?' : s[i];
	out[i] = 0;
}

/* 127723 as "127,723". */
/* A size as the bytes, then the rounded figure in brackets: "127723 bytes (124.7 KiB)". One function for every row
 * that prints a size, the Object block's included. The rounding truncates (1048575 is 1023.9 KiB, never 1024.0). */
void dash_size_text(char *out, size_t cap, uint64_t n)
{
	static const char *const unit[] = { "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
	uint64_t u = 1024u;
	unsigned k = 0;

	if (n < 1024u) {
		snprintf(out, cap, "%llu byte%s", (unsigned long long)n, n == 1u ? "" : "s");
		return;
	}
	while (k < 5u && n / u >= 1024u) {
		u <<= 10;
		k++;
	}
	snprintf(out, cap, "%llu bytes (%llu.%llu %s)", (unsigned long long)n, (unsigned long long)(n / u),
		 (unsigned long long)((n % u) * 10u / u), unit[k]);
}

static void sep(struct dash_row *r)
{
	span(r, DT_DIM, " \xc2\xb7 ");
}

/* The entry point, as the owner laid it out: one row that says what it is - the permission of the memory it runs from
 * and where that is (the section's name) - and under it, in the value column, the same point as numbers: its address,
 * its place in the file and its distance from the start of that section. They are one fact told three ways, so they
 * sit under the row and not beside it. `kind` names the address ("virtual address" for ELF, "RVA" for PE); the labels
 * are padded to one width so the values line up. `perm` is the containing segment's or section's. */
static void entry_num(struct dash_block *b, const char *label, const char *fmt, uint64_t v)
{
	struct dash_row *r = row_new(b, " ", DT_DIM);        /* a blank label: the value column, under the row above */

	span(r, DT_DIM, "%-15s ", label);
	span(r, DT_LOC, fmt, (unsigned long long)v);
}

static void entry_rows(struct dash_block *b, uint64_t addr, const char *kind, const char *name, int named,
		       uint64_t delta, uint64_t file_off, unsigned perm)
{
	struct dash_row *r = row_new(b, "entry", DT_DIM);
	char fo[24], pm[4];

	if (perm) {
		prop_perm(pm, sizeof pm, perm);
		span(r, DT_ID, "%s", pm);
	} else {
		span(r, DT_WARN, "none");
	}
	span(r, DT_DIM, " at ");
	if (named)
		span(r, DT_NAME, "%s", name);
	else
		span(r, DT_WARN, "no section");
	entry_num(b, kind, "0x%llx", addr);
	prop_off(fo, sizeof fo, file_off);
	if (strcmp(fo, "-") != 0)
		entry_num(b, "file offset", "0x%llx", file_off);
	if (named)
		entry_num(b, "section offset", "0x%llx", delta);
}

/* The architecture as the library names it, with its width; the header's own number when the list has no name for
 * it (never an invented one). */
static void arch_clause(struct dash_row *r, uint8_t arch, unsigned machine, const char *fallback)
{
	const char *t = kgenome_arch_title(arch);

	if (t)
		span(r, DT_ID, "%s", t);
	else
		span(r, DT_SIZE, fallback, machine);
}

static void count_clause(struct dash_row *r, int *any, uint32_t n, const char *one, const char *many)
{
	if (!n)
		return;
	if (*any)
		sep(r);
	span(r, DT_SIZE, "%u", n);
	span(r, DT_DIM, " %s", n == 1u ? one : many);
	*any = 1;
}

static void header_elf(const struct object *ob, struct dash_block *b)
{
	const struct kgenome_elf_info *e = ob->info;
	const char *tn = e->e_type < KGENOME_ELF_TYPE_COUNT ? kof_inspect_subtype_name(KOF_FMT_ELF, (uint8_t)e->e_type) : NULL;
	struct kgenome_elf_shape sh;
	struct dash_row *r;
	uint32_t si = 0;
	uint64_t delta = 0;
	int any, named;

	block_begin(b, "ELF");
	r = row_new(b, "format", DT_DIM);
	span(r, DT_ID, "ELF");
	sep(r);
	if (tn)
		span(r, DT_ID, "%s", tn);
	else
		span(r, DT_SIZE, "type %u", e->e_type);

	r = row_new(b, "arch", DT_DIM);
	arch_clause(r, ob->ctx.arch, e->e_machine, "machine %u");
	sep(r);
	span(r, DT_ID, "%s", e->elf_data == KGENOME_ELFDATA_BE ? "big-endian" : "little-endian");

	kgenome_elf_shape(e, &sh);
	r = row_new(b, "symbols", DT_DIM);
	if (!e->sec_count)
		span(r, DT_WARN, "no section table");
	else if (sh.has_symtab)
		span(r, DT_ID, "not stripped");
	else if (sh.has_debug)
		span(r, DT_ID, "debug info only");
	else
		span(r, DT_ID, "stripped");

	/* An ET_REL has no entry in the file: no row, not an empty one. */
	if (ob->ctx.entry_off != KGENOME_NA || e->entry_addr) {
		named = kgenome_elf_entry_sec(e, &si, &delta) == 0;
		{
			char nm[KGENOME_ELF_SECNAME_MAX + 1];

			if (named)
				clean_into(nm, sizeof nm, e->sec[si].name, sizeof e->sec[si].name);
			else
				nm[0] = 0;
			entry_rows(b, e->entry_addr, "virtual address", nm, named, delta, ob->ctx.entry_off, e->entry_perm);
		}
	}

	r = row_new(b, "layout", DT_DIM);
	any = 0;
	count_clause(r, &any, e->load_count, "loadable segment", "loadable segments");
	count_clause(r, &any, e->sec_count, "section", "sections");
	if (!any)
		b->n--;
	claimed(b, "segments", e->phnum, e->phnum_claimed);
	claimed(b, "sections", e->shnum, e->shnum_claimed);
}

static void header_pe(const struct object *ob, struct dash_block *b)
{
	const struct kgenome_pe_info *p = ob->info;
	const char *tn = kof_inspect_subtype_name(KOF_FMT_PE, ob->ctx.subtype);
	char sz[80];
	struct dash_row *r;

	block_begin(b, "PE");
	r = row_new(b, "format", DT_DIM);
	span(r, DT_ID, "%s", p->pe32_plus ? "PE32+" : "PE32");
	if (tn) {
		sep(r);
		span(r, DT_ID, "%s", tn);
	}
	r = row_new(b, "arch", DT_DIM);
	arch_clause(r, ob->ctx.arch, p->machine, "machine 0x%04x");
	{
		int named = p->entry_sec < p->sec_count && p->entry_sec < KGENOME_PE_MAX_SECTIONS;
		char nm[KGENOME_PE_SECNAME_MAX + 1];

		if (named)
			clean_into(nm, sizeof nm, p->sec[p->entry_sec].name, sizeof p->sec[p->entry_sec].name);
		else
			nm[0] = 0;
		entry_rows(b, p->entry_rva, "RVA", nm, named,
			   named ? p->entry_rva - p->sec[p->entry_sec].mem_rva : 0u, ob->ctx.entry_off, p->entry_perm);
	}
	if (p->clr_len) {
		r = row_new(b, "CLI header", DT_DIM);
		span(r, DT_DIM, "managed (.NET) header at file offset ");
		span(r, DT_LOC, "0x%llx", (unsigned long long)p->clr_off);
		sep(r);
		dash_size_text(sz, sizeof sz, p->clr_len);
		span(r, DT_SIZE, "%s", sz);
		sep(r);
		span(r, DT_DIM, "entry token ");
		span(r, DT_LOC, "0x%08x", p->clr_entry_token);
	}
	r = row_new(b, "stub", DT_DIM);
	span(r, DT_DIM, "NT headers at file offset ");
	span(r, DT_LOC, "0x%llx", (unsigned long long)p->lfanew);
	sep(r);
	dash_size_text(sz, sizeof sz, p->stub_len);
	span(r, DT_SIZE, "%s", sz);
	span(r, DT_DIM, " of DOS stub");
	sep(r);
	span(r, DT_DIM, "headers end at ");
	span(r, DT_LOC, "0x%llx", (unsigned long long)p->header_end);
	span(r, DT_DIM, ", declared ");
	dash_size_text(sz, sizeof sz, p->size_of_headers);
	span(r, DT_SIZE, "%s", sz);
	r = row_new(b, "summary", DT_DIM);
	span(r, DT_DIM, "code ");
	dash_size_text(sz, sizeof sz, p->size_of_code);
	span(r, DT_SIZE, "%s", sz);
	sep(r);
	span(r, DT_DIM, "initialised data ");
	dash_size_text(sz, sizeof sz, p->size_of_init_data);
	span(r, DT_SIZE, "%s", sz);
	sep(r);
	span(r, DT_DIM, "uninitialised data ");
	dash_size_text(sz, sizeof sz, p->size_of_uninit_data);
	span(r, DT_SIZE, "%s", sz);
	if (p->cert_len) {
		r = row_new(b, "signature", DT_DIM);
		span(r, DT_DIM, "certificate table at file offset ");
		span(r, DT_LOC, "0x%llx", (unsigned long long)p->cert_off);
		sep(r);
		dash_size_text(sz, sizeof sz, p->cert_len);
		span(r, DT_SIZE, "%s", sz);
	}
	if (p->overlay_len) {
		r = row_new(b, "overlay", DT_WARN);
		span(r, DT_DIM, "data after the last section at file offset ");
		span(r, DT_LOC, "0x%llx", (unsigned long long)p->overlay_off);
		sep(r);
		dash_size_text(sz, sizeof sz, p->overlay_len);
		span(r, DT_WARN, "%s", sz);
	}
	claimed(b, "sections", p->nsec, p->nsec_claimed);
}

/* Does this object get a format block - the test the overview applies, spelled once. The block carries the file size,
 * so the identity rows leave it out for these and keep it for everything else. */
int dash_has_header(const struct object *ob)
{
	return ob->fmt && ob->info && ob->entry_kind != KOF_ENT_NORMALIZED &&
	       (ob->ctx.format == KOF_FMT_ELF || ob->ctx.format == KOF_FMT_PE);
}

/* The format block, for an object that has one: the parse is the engine's, and a normalised view's header is its
 * parent's over bytes that moved, so it has none. An empty block (n == 0, no heading) otherwise. */
void dash_header(const struct object *ob, struct dash_block *b)
{
	memset(b, 0, sizeof *b);
	if (!dash_has_header(ob))
		return;
	if (ob->ctx.format == KOF_FMT_ELF)
		header_elf(ob, b);
	else
		header_pe(ob, b);
}

/* ---- regions, anomalies, heuristic ---------------------------------------------------------------------- */

/*
 * The regions, which is the engine's own division of the file and the thing every range in every signature is
 * written against. The share is there because that is how a packed file announces itself: one region holding
 * nearly all of it. The symbol halves are left out of the sum on purpose: it is a PARTITION CHECK - the regions
 * are extents of the file and must add up to it - and the halves are built, so their bytes are not the file's.
 */
void dash_regions(const struct view *v, const struct object *ob, struct dash_block *b)
{
	uint32_t i, n = 0, cur = v->node[v->sel_node].obj;
	uint64_t total = 0;

	block_begin(b, "Regions");
	for (i = 0; i < v->n_node; i++)
		if (v->node[i].obj == cur && v->node[i].mask && !v->node[i].sym) {
			n++;
			total += v->node[i].bytes;
		}
	/* No parser claimed the bytes, so nothing divided them: a file with no regions, not one whose regions fail to
	 * add up. */
	if (!n) {
		struct dash_row *r = row_new(b, "whole", DT_DIM);

		span(r, DT_DIM, "no parser divides this object");
		return;
	}
	for (i = 0; i < v->n_node; i++) {
		const struct node *nd = &v->node[i];
		struct dash_row *r;

		if (nd->obj != cur || !nd->mask || nd->sym)
			continue;
		/* "H 4.8" meant nothing to a reader: the unit is bits per byte, 0 to 8, and is said. */
		r = row_new(b, nd->label, DT_ID);
		span(r, DT_SIZE, "%-10llu", (unsigned long long)nd->bytes);
		span(r, DT_LOC, "%5.1f%%", total ? 100.0 * (double)nd->bytes / (double)total : 0.0);
		span(r, DT_DIM, "  %.1f/8 bits",
		     (double)kof_inspect_region_entropy(&ob->ctx, ob->buf, nd->mask) / 8.0);
	}
	/* The sum only means something where the format claims to partition: a process record's head and descriptor
	 * links are deliberately not scan regions (KOF_SCAN_PROC_CLAIMED). */
	if (total != ob->buf.n && ob->ctx.format != KOF_EVT_PROC) {
		struct dash_row *r = row_new(b, "MISMATCH", DT_BAD);

		span(r, DT_BAD, "regions sum to %llu of %llu", (unsigned long long)total, (unsigned long long)ob->buf.n);
	}
}

/*
 * What the parser thought was wrong with it. Said even when there is nothing, because "no anomalies" is a finding
 * and an absent section reads as a section that was not checked. A reconstructed payload says what it is in place
 * of the parser's list (display only: no anomaly bit is added).
 */
void dash_anomalies(const struct object *ob, struct dash_block *b)
{
	struct dash_row *r;
	uint32_t i;

	block_begin(b, "Anomalies");
	if (ob->payload_of) {
		r = row_new(b, "", DT_NONE);
		span(r, DT_WARN, "  RECONSTRUCTED_%s-%s_SHELLCODE", ob->fmt ? kof_format_name(ob->ctx.format) : "RAW",
		     ob->fmt ? kof_arch_name(ob->ctx.arch) : "?");
	} else if (ob->fmt && ob->info && ob->fmt->anomalies) {
		uint64_t anom = ob->fmt->anomalies(ob->info);

		if (!anom) {
			r = row_new(b, "", DT_NONE);
			span(r, DT_DIM, "  none");
		}
		for (i = 0; i < 64; i++) {
			const char *an;

			if (!(anom >> i & 1))
				continue;
			an = ob->fmt->anomaly_name(i);
			r = row_new(b, "", DT_NONE);
			if (an)
				span(r, DT_BAD, "  %s", an);
			else
				span(r, DT_BAD, "  bit%u", i);
		}
	} else {
		r = row_new(b, "", DT_NONE);
		span(r, DT_DIM, "  no parser claimed these bytes");
	}
}

/* The engine's heuristic result (ob->heur), shown and not recomputed; the traces under it with their weights. */
void dash_heuristic(const struct object *ob, struct dash_block *b)
{
	const struct kof_heur_model *hm = kof_heur_default();
	struct kof_heur_facts hf;
	const char *guess = "Unknown";
	int32_t sc = 0;
	uint32_t k;
	struct dash_row *r;

	block_begin(b, "Heuristic");
	if (!heur_of(ob, &hf, &sc, &guess)) {
		r = row_new(b, "", DT_NONE);
		span(r, DT_DIM, "  no model for this format - not scored");
		return;
	}
	r = row_new(b, "score", DT_DIM);
	span(r, sc >= hm->bar_centinats ? DT_HEUR : DT_SIZE, "%d", sc);
	span(r, DT_DIM, "  of %d to report", hm->bar_centinats);
	if (sc >= hm->bar_centinats) {
		r = row_new(b, "verdict", DT_DIM);
		span(r, DT_HEUR, "%s", guess);
	}
	for (k = 0; k < hm->n_anom; k++)
		if (hm->anom[k].format == hf.format && (hf.anomalies & hm->anom[k].mask)) {
			r = row_new(b, "", DT_NONE);
			span(r, DT_WARN, "     +%-6d", hm->anom[k].centinats);
			span(r, DT_DIM, " %s", hm->anom[k].guess);
		}
	for (k = 0; k < hm->n_flag; k++)
		if (hf.flags & KOF_HEUR_FL(hm->flag[k].fact)) {
			r = row_new(b, "", DT_NONE);
			span(r, DT_WARN, "     +%-6d", hm->flag[k].centinats);
			span(r, DT_DIM, " %s", hm->flag[k].guess);
		}
}

/* ---- the layout tables ----------------------------------------------------------------------------------- */

/* The section flags as the letters a linker's tools use; bits with no letter are one '+'. */
static void shflags_cell(char *out, size_t cap, uint64_t f)
{
	static const struct { uint64_t bit; char ch; } map[] = {
		{ 0x1, 'W' }, { 0x2, 'A' }, { 0x4, 'X' }, { 0x10, 'M' }, { 0x20, 'S' }, { 0x40, 'I' },
		{ 0x80, 'L' }, { 0x100, 'O' }, { 0x200, 'G' }, { 0x400, 'T' }, { 0x800, 'C' }
	};
	size_t n = 0, i;
	uint64_t known = 0;

	for (i = 0; i < sizeof map / sizeof map[0]; i++) {
		known |= map[i].bit;
		if ((f & map[i].bit) && n + 1u < cap)
			out[n++] = map[i].ch;
	}
	if ((f & ~known) && n + 1u < cap)
		out[n++] = '+';
	if (!n && cap > 1u)
		out[n++] = '-';
	out[n] = 0;
}

static int is_elf(const struct object *ob)
{
	return ob->fmt && ob->info && ob->entry_kind != KOF_ENT_NORMALIZED && ob->ctx.format == KOF_FMT_ELF;
}

static int is_pe(const struct object *ob)
{
	return ob->fmt && ob->info && ob->entry_kind != KOF_ENT_NORMALIZED && ob->ctx.format == KOF_FMT_PE;
}

/* The tone of each column of a layout table: which kind of fact it holds. The renderer maps a tone to a colour
 * (kv_props_table.c tone_sgr); the data says what a column IS, so a new column is declared here and nowhere else. */
static const enum dash_tone seg_tone[] = { DT_DIM, DT_TYPE, DT_FLAG, DT_LOC, DT_ALT, DT_SIZE, DT_BIND, DT_DIM, DT_HEUR };
static const enum dash_tone sec_tone[] = { DT_DIM, DT_NAME, DT_TYPE, DT_FLAG, DT_ALT, DT_LOC, DT_SIZE, DT_BIND, DT_ID,
					   DT_SIZE, DT_DIM, DT_HEUR };
static const enum dash_tone pe_tone[] = { DT_DIM, DT_NAME, DT_ALT, DT_BIND, DT_LOC, DT_SIZE, DT_FLAG, DT_TYPE, DT_HEUR };

void dash_layout(const struct object *ob, enum dash_lay which, struct dash_table *t)
{
	static const char *const sh[] = { "#", "type", "flags", "offset", "vaddr", "filesz", "memsz", "align", "entropy" };
	static const char *const nh[] = { "#", "name", "type", "flags", "addr", "offset", "size", "link", "info",
					  "entsize", "align", "entropy" };
	static const char *const ph[] = { "#", "name", "rva", "vsize", "offset", "rawsize", "perm", "flags", "entropy" };
	const char *const *h = NULL;
	const enum dash_tone *tone = NULL;
	uint32_t k;

	memset(t, 0, sizeof *t);
	if (is_elf(ob)) {
		const struct kgenome_elf_info *e = ob->info;

		h = which == DASH_LAY_SEG ? sh : nh;
		tone = which == DASH_LAY_SEG ? seg_tone : sec_tone;
		t->n_col = which == DASH_LAY_SEG ? 9u : 12u;
		t->lead = 2;
		t->n_row = which == DASH_LAY_SEG ? e->seg_count : e->sec_count;
		t->declared = which == DASH_LAY_SEG ? e->phnum_claimed : e->shnum_claimed;
		if (!t->n_row) {
			t->n_col = 0;
			t->none = which == DASH_LAY_SEG ? "no program headers" : "no section headers";
		}
	} else if (is_pe(ob)) {
		const struct kgenome_pe_info *p = ob->info;

		if (which == DASH_LAY_SEG) {
			/* A PE has sections and no segments: the loader maps by section, and there is no second table to hold
			 * a different answer. Said, so that an empty half is not mistaken for a missing one. */
			t->none = "none - a PE is mapped by its sections";
			return;
		}
		h = ph;
		tone = pe_tone;
		t->n_col = 9;
		t->lead = 2;
		t->n_row = p->sec_count;
		t->declared = p->nsec_claimed;
		if (!t->n_row) {
			t->n_col = 0;
			t->none = "no section headers";
		}
	} else {
		t->none = ob->entry_kind == KOF_ENT_NORMALIZED
			  ? "no segments or sections: this object is not a parsed ELF or PE (a normalised view's header is its parent's)"
			  : "no segments or sections: this object is not a parsed ELF or PE";
		return;
	}
	for (k = 0; k < t->n_col; k++) {
		t->head[k] = h[k];
		t->tone[k] = tone[k];
	}
	t->not_shown = t->declared > t->n_row ? t->declared - t->n_row : 0u;
}

static void layout_cell_plain(const struct object *ob, enum dash_lay which, uint32_t i, char c[][DASH_CELL])
{
	uint32_t k;

	for (k = 0; k < DASH_COLS; k++)
		c[k][0] = 0;
	if (is_elf(ob)) {
		const struct kgenome_elf_info *e = ob->info;

		if (which == DASH_LAY_SEG && i < e->seg_count) {
			const struct kgenome_elf_seg *g = &e->seg[i];
			const char *w = kof_inspect_ptype_name(g->type);
			uint64_t al = 0;

			snprintf(c[0], DASH_CELL, "%u", i);
			if (w)
				snprintf(c[1], DASH_CELL, "%s", w);
			else
				snprintf(c[1], DASH_CELL, "0x%x", g->type);
			prop_perm(c[2], DASH_CELL, g->perm);
			snprintf(c[3], DASH_CELL, "0x%llx", (unsigned long long)g->file_off);
			snprintf(c[4], DASH_CELL, "0x%llx", (unsigned long long)g->mem_addr);
			snprintf(c[5], DASH_CELL, "%llu", (unsigned long long)g->file_size);
			snprintf(c[6], DASH_CELL, "%llu", (unsigned long long)g->mem_size);
			if (kgenome_elf_seg_align(ob->buf, e, i, &al))
				snprintf(c[7], DASH_CELL, "0x%llx", (unsigned long long)al);
			else
				snprintf(c[7], DASH_CELL, "-");
		} else if (which == DASH_LAY_SEC && i < e->sec_count) {
			const struct kgenome_elf_sec *s = &e->sec[i];
			const char *w = kof_inspect_shtype_name(s->type);
			uint64_t al = 0, es = 0;
			int have = kgenome_elf_sec_layout(ob->buf, e, i, &al, &es);

			snprintf(c[0], DASH_CELL, "%u", i);
			clean_into(c[1], DASH_CELL, s->name, sizeof s->name);
			if (w)
				snprintf(c[2], DASH_CELL, "%s", w);
			else
				snprintf(c[2], DASH_CELL, "0x%x", s->type);
			shflags_cell(c[3], DASH_CELL, s->flags);
			snprintf(c[4], DASH_CELL, "0x%llx", (unsigned long long)s->mem_addr);
			snprintf(c[5], DASH_CELL, "0x%llx", (unsigned long long)s->file_off);
			snprintf(c[6], DASH_CELL, "%llu", (unsigned long long)s->file_size);
			snprintf(c[7], DASH_CELL, "%u", e->sec_link[i]);
			snprintf(c[8], DASH_CELL, "%u", e->sec_info[i]);
			if (have) {
				snprintf(c[9], DASH_CELL, "%llu", (unsigned long long)es);
				snprintf(c[10], DASH_CELL, "%llu", (unsigned long long)al);
			} else {
				snprintf(c[9], DASH_CELL, "-");
				snprintf(c[10], DASH_CELL, "-");
			}
		}
	} else if (is_pe(ob) && which == DASH_LAY_SEC) {
		const struct kgenome_pe_info *p = ob->info;

		if (i < p->sec_count) {
			const struct kgenome_pe_sec *s = &p->sec[i];

			snprintf(c[0], DASH_CELL, "%u", i);
			clean_into(c[1], DASH_CELL, s->name, sizeof s->name);
			snprintf(c[2], DASH_CELL, "0x%llx", (unsigned long long)s->mem_rva);
			snprintf(c[3], DASH_CELL, "0x%llx", (unsigned long long)s->mem_size);
			snprintf(c[4], DASH_CELL, "0x%llx", (unsigned long long)s->file_off);
			snprintf(c[5], DASH_CELL, "%llu", (unsigned long long)s->file_size);
			prop_perm(c[6], DASH_CELL, s->perm);
			snprintf(c[7], DASH_CELL, "0x%08x", s->characteristics);
		}
	}
}

/*
 * THE ENTROPY OF THE BYTES A SEGMENT OR SECTION OCCUPIES IN THE FILE, bits per byte, two decimals; "-" when it
 * occupies none (a NOBITS section, an empty or out-of-file range). The range is clipped to the file, so a hostile
 * offset or size reads nothing outside it. The number is the core's (kentropy_hist_centi), not computed here.
 *
 * BOUND: at most DASH_ENTROPY_MAX bytes of a range are counted, and a longer range says so with a trailing "+" (the
 * value is then the entropy of its first DASH_ENTROPY_MAX bytes). The number chose itself: the cell is made for each row
 * the page draws on every frame, a frame draws about 50 rows, and counting 1 MiB costs about a millisecond at the
 * byte-histogram's rate [Inference: not timed on this machine], which keeps a frame near 50 ms; the bound limits cost
 * and the "+" keeps it from hiding that the figure is for a prefix.
 */
#define DASH_ENTROPY_MAX (1u << 20)

static int layout_range(const struct object *ob, enum dash_lay which, uint32_t i, uint64_t *off, uint64_t *len)
{
	*off = *len = 0;
	if (is_elf(ob)) {
		const struct kgenome_elf_info *e = ob->info;

		if (which == DASH_LAY_SEG && i < e->seg_count) {
			*off = e->seg[i].file_off;
			*len = e->seg[i].file_size;
			return 1;
		}
		if (which == DASH_LAY_SEC && i < e->sec_count && e->sec[i].type != KGENOME_ELF_SHT_NOBITS) {
			*off = e->sec[i].file_off;
			*len = e->sec[i].file_size;
			return 1;
		}
	} else if (is_pe(ob) && which == DASH_LAY_SEC) {
		const struct kgenome_pe_info *p = ob->info;

		if (i < p->sec_count) {
			*off = p->sec[i].file_off;
			*len = p->sec[i].file_size;
			return 1;
		}
	}
	return 0;
}

void dash_layout_entropy(const struct object *ob, enum dash_lay which, uint32_t i, char *out, size_t cap)
{
	uint64_t off, len;
	uint32_t hist[256], centi;
	int cut = 0;

	if (!layout_range(ob, which, i, &off, &len) || off >= ob->buf.n || !len) {
		snprintf(out, cap, "-");
		return;
	}
	if (len > ob->buf.n - off)
		len = ob->buf.n - off;
	if (len > DASH_ENTROPY_MAX) {
		len = DASH_ENTROPY_MAX;
		cut = 1;
	}
	memset(hist, 0, sizeof hist);
	kentropy_count(hist, ob->buf.p + off, len);
	centi = kentropy_hist_centi(hist, len);
	snprintf(out, cap, "%u.%02u%s", centi / 100u, centi % 100u, cut ? "+" : "");
}

/* The text of one row, entropy included: the plain cells, and the last column from the range's bytes. */
void dash_layout_cell(const struct object *ob, enum dash_lay which, uint32_t i, char c[][DASH_CELL])
{
	struct dash_table t;

	layout_cell_plain(ob, which, i, c);
	dash_layout(ob, which, &t);
	if (t.n_col && i < t.n_row)
		dash_layout_entropy(ob, which, i, c[t.n_col - 1u], DASH_CELL);
}

/* The natural width of every column, from the heading and every row's text. The entropy column is NOT measured: asking
 * its cell for every row would count every range, and the page asks only for the rows it draws; its width is the
 * heading's (a value is at most "8.00+"). */
void dash_layout_widths(const struct object *ob, enum dash_lay which, uint16_t w[DASH_COLS])
{
	struct dash_table d;
	char row[DASH_COLS][DASH_CELL];
	uint32_t i, k;

	dash_layout(ob, which, &d);
	for (k = 0; k < DASH_COLS; k++)
		w[k] = k < d.n_col ? (uint16_t)strlen(d.head[k]) : 0u;
	for (i = 0; i < d.n_row; i++) {
		layout_cell_plain(ob, which, i, row);
		for (k = 0; k + 1u < d.n_col; k++) {
			size_t l = strlen(row[k]);

			if (l > w[k])
				w[k] = (uint16_t)l;
		}
	}
}

/* ---- the symbol tables ----------------------------------------------------------------------------------- */

const char *const dash_sym_head[DASH_SYM_COLS] = { "rec", "type", "bind", "vis", "flags", "name", "sec", "size", "value" };

/*
 * Does a name pass the filter. Three ways of asking one question, and the engine answers two of them: a regex is
 * compiled once when the text changes (by the caller) and walked here with kof_hex_walk_flags, which is what the
 * matcher itself walks, so a pattern that selects rows here selects the same bytes written into a rule; a plain
 * filter is a substring test, folded or not. An empty filter passes everything; a regex the engine refused matches
 * nothing (passing everything read as a search that found everything).
 */
int dash_filter_ok(const struct dash_filter *f, const char *name, uint32_t n)
{
	uint32_t i;

	if (!f->text || !f->text[0])
		return 1;
	if (f->rx) {
		kof_buf d;

		if (f->bad || !f->prog_n)
			return 0;
		d = kof_buf_make((const uint8_t *)name, n);
		for (i = 0; i <= n; i++)
			if (kof_hex_walk_flags(d, i, f->prog, f->icase ? (uint8_t)KOF_STR_ICASE : 0u))
				return 1;
		return 0;
	}
	{
		size_t fl = strlen(f->text);

		if (fl > n)
			return 0;
		for (i = 0; i + fl <= n; i++) {
			size_t k;

			for (k = 0; k < fl; k++) {
				char a = name[i + k], b = f->text[k];

				if (f->icase) {
					if (a >= 'A' && a <= 'Z')
						a = (char)(a + 32);
					if (b >= 'A' && b <= 'Z')
						b = (char)(b + 32);
				}
				if (a != b)
					break;
			}
			if (k == fl)
				return 1;
		}
	}
	return 0;
}

/*
 * The imports or the exports of `ob` after the filter: the records of the half in reading order (the engine's
 * extents say which records are an import and which an export), the filter removing rows in place and in order so
 * a reader who clears it finds the list where it was, the widths one table needs (decided by the whole table, or a
 * column cannot be read down), whether the block was cut, and - when there are no rows - which of four findings
 * that is.
 */
void dash_syms_load(const struct view *v, const struct dash_filter *f, const struct object *ob, uint8_t which,
		    struct dash_syms *S)
{
	uint32_t n, keep = 0, i;

	S->why = DASH_OK;
	S->n = S->got = 0;
	S->cut = 0;
	S->wd = 8;
	S->sw = 8;
	S->nw = 4;
	S->ob = ob;
	if (!kv_cap(ob->ctx.format, KV_CAP_SYMBOLS) || (v->log && !v->pe_of[v->node[v->sel_node].obj])) {
		S->why = DASH_NA;
		return;
	}
	n = v->probe ? sym_half_recs(ob, sym_row_mask(which), v->probe, KOF_SCAN_MAX_EXTENTS, S->idx,
				     KOF_SYM_MAX_RECS) : 0u;
	S->got = n;
	if (kof_sym_truncated(ob->sym, (uint32_t)ob->sym_n))
		S->cut = (ob->sym[KOF_SYM_H_TRUNC] & KOF_SYM_TRUNC_ROOM) ? 1 : 2;
	if (f->text && f->text[0]) {
		for (i = 0; i < n; i++) {
			const uint8_t *r = ob->sym ? kof_sym_rec(ob->sym, (uint32_t)ob->sym_n, S->idx[i]) : 0;
			uint32_t len = 0;
			const char *nm;

			if (!r)
				continue;
			nm = kof_sym_name(ob->sym, (uint32_t)ob->sym_n, r, &len);
			if (dash_filter_ok(f, nm, len))
				S->idx[keep++] = S->idx[i];
		}
		n = keep;
	}
	S->n = n;
	if (!n) {
		S->why = (f->rx && f->bad && f->err && f->err[0]) ? DASH_RX
			 : (f->text && f->text[0] && S->got) ? DASH_FILTER : DASH_NONE;
		return;
	}
	for (i = 0; i < n; i++) {
		const uint8_t *r = kof_sym_rec(ob->sym, (uint32_t)ob->sym_n, S->idx[i]);
		uint32_t len = 0;

		if (!r)
			continue;
		if (kof_sym_u64(r, KOF_SYM_R_VALUE) > 0xffffffffull || kof_sym_u64(r, KOF_SYM_R_SIZE) > 0xffffffffull)
			S->wd = 16;
		(void)kof_sym_name(ob->sym, (uint32_t)ob->sym_n, r, &len);
		if ((int)len > S->nw)
			S->nw = (int)len;
	}
	S->sw = S->wd == 16 ? 12 : 8;
}

/* One row. The record number is the position in the LIST (decimal: it is how many records in this one is, which the
 * reader counts rather than reads); the value is hex with its 0x because it IS an address out of the file. */
void dash_syms_cell(const struct dash_syms *S, uint32_t row, struct dash_symcell *out)
{
	const uint8_t *blk = S->ob->sym;
	uint32_t nb = (uint32_t)S->ob->sym_n, len = 0, k;
	const uint8_t *r = row < S->n ? kof_sym_rec(blk, nb, S->idx[row]) : 0;
	char fl[8], shn[8];
	const char *nm;

	for (k = 0; k < DASH_SYM_COLS; k++)
		out->cell[k] = "";
	if (!r)
		return;
	sym_flag_str(r[KOF_SYM_R_FLAGS], fl);
	sym_shn_str(r, shn, sizeof shn);
	snprintf(out->c[0], sizeof out->c[0], "%u", row);
	snprintf(out->c[1], sizeof out->c[1], "%s", kof_sym_type_name(r[KOF_SYM_R_TYPE]));
	snprintf(out->c[2], sizeof out->c[2], "%s", kof_sym_bind_name(r[KOF_SYM_R_BIND]));
	snprintf(out->c[3], sizeof out->c[3], "%s", kof_sym_vis_name(r[KOF_SYM_R_VIS]));
	snprintf(out->c[4], sizeof out->c[4], "%s", fl);
	nm = kof_sym_name(blk, nb, r, &len);
	clean_into(out->name, sizeof out->name, nm, len);
	snprintf(out->c[5], sizeof out->c[5], "%5s", shn);
	snprintf(out->c[6], sizeof out->c[6], "%*llu", S->sw, (unsigned long long)kof_sym_u64(r, KOF_SYM_R_SIZE));
	snprintf(out->c[7], sizeof out->c[7], "0x%0*llx", S->wd, (unsigned long long)kof_sym_u64(r, KOF_SYM_R_VALUE));
	for (k = 0; k < 5; k++)
		out->cell[k] = out->c[k];
	out->cell[5] = out->name;
	out->cell[6] = out->c[5];
	out->cell[7] = out->c[6];
	out->cell[8] = out->c[7];
}

/* Compared on the symbol's own VALUE against what the finder reported, which is why the finder reports a value and
 * not a record index. payload_at is guarded because zero IS a real symbol value (every undefined symbol has it), so
 * "no payload" must not be spelled as an address. */
int dash_syms_found(const struct dash_syms *S, uint32_t row)
{
	const uint8_t *r = row < S->n ? kof_sym_rec(S->ob->sym, (uint32_t)S->ob->sym_n, S->idx[row]) : 0;

	return r && S->ob->payload_at && kof_sym_u64(r, KOF_SYM_R_VALUE) == S->ob->payload_at;
}

/* ---- the Infection dialog ------------------------------------------------------------------------------- */

/* The engine's word for what an infected range is (KOF_INF_*): the malware's own bytes, or the host's that were overwritten. */
static const char *inf_kind_word(uint32_t kind)
{
	return kind == KOF_INF_BODY ? "body" : kind == KOF_INF_DAMAGE ? "damage" : "other";
}

static void off_cell(char *out, size_t cap, uint64_t v)
{
	if (v == KGENOME_NA || v == KGENOME_BROKEN)
		snprintf(out, cap, "-");
	else
		snprintf(out, cap, "0x%llx", (unsigned long long)v);
}

static void wide_clear(struct dash_widecell *w)
{
	uint32_t k;

	for (k = 0; k < DASH_WIDE_COLS; k++) {
		w->c[k][0] = 0;
		w->cell[k] = w->c[k];
	}
	w->value[0] = 0;
}

/* ---- the value text, one builder for both tables ---------------------------------------------------------- */

/* The bytes of the range that are shown: none for a range with no file bytes, else at most DASH_VALUE_BYTES and at most what
 * the file holds. */
static uint64_t value_bytes(kof_buf f, uint64_t off, uint64_t size)
{
	uint64_t n = size < DASH_VALUE_BYTES ? size : DASH_VALUE_BYTES;

	if (off == KGENOME_NA || off >= f.n || !n)
		return 0;
	return n > f.n - off ? f.n - off : n;
}

uint32_t dash_value_len(kof_buf f, uint64_t off, uint64_t size)
{
	uint64_t n = value_bytes(f, off, size);

	return n ? (uint32_t)(3u * n - 1u + (size > n ? 4u : 0u)) : 1u;
}

void dash_value_text(char *out, size_t cap, kof_buf f, uint64_t off, uint64_t size)
{
	static const char hex[] = "0123456789abcdef";
	uint64_t n = value_bytes(f, off, size), i;
	size_t o = 0;

	if (!cap)
		return;
	if (!n) {
		snprintf(out, cap, "-");
		return;
	}
	for (i = 0; i < n && o + 4u < cap; i++) {
		uint8_t b = f.p[off + i];

		if (i)
			out[o++] = ' ';
		out[o++] = hex[b >> 4];
		out[o++] = hex[b & 15u];
	}
	if (size > n && o + 5u < cap) {
		memcpy(out + o, " ...", 4);
		o += 4;
	}
	out[o] = 0;
}

/* The object the library reads: the engine's own descriptor when it parsed an ELF or PE (over the view this object holds and
 * the bytes it holds), else a bare size. */
static void genome_of(const struct object *ob, struct kgenome_obj *g)
{
	if (is_elf(ob) || is_pe(ob)) {
		kof_genome_obj(&ob->ctx, g);
		g->file_header = ob->info;
	} else {
		memset(g, 0, sizeof *g);
	}
	g->obj_size = ob->buf.n;
}

void dash_infect_load(const struct object *ob, struct dash_infect *I)
{
	struct kgenome_infect_range in[KOF_MAX_INFECTED];
	struct kgenome_infect_row *rows;
	struct kgenome_infect_req rq;
	struct kgenome_infect_res rs;
	struct kgenome_obj g;
	enum kgenome_status st;
	uint32_t q, n = ob->n_infected < KOF_MAX_INFECTED ? ob->n_infected : KOF_MAX_INFECTED;

	for (q = 0; q < n; q++) {
		in[q].off = ob->infected[q].off;
		in[q].len = ob->infected[q].len;
		in[q].kind = ob->infected[q].kind;
		in[q]._pad = 0;
	}
	free(I->row);
	memset(I, 0, sizeof *I);
	rows = malloc(KGENOME_INFECT_MAX * sizeof *rows);
	memset(&rq, 0, sizeof rq);
	genome_of(ob, &g);
	rq.obj = &g;
	rq.file = ob->buf;
	rq.inf = in;
	rq.n_inf = n;
	rq.out = rows;
	rq.cap = rows ? KGENOME_INFECT_MAX : 0u;
	st = kgenome_infect_regions(&rq, &rs);
	I->n = rs.n;
	I->total = rs.total;
	I->file = ob->buf;
	if (rows && rs.n) {
		struct kgenome_infect_row *shrunk = realloc(rows, rs.n * sizeof *rows);

		rows = shrunk ? shrunk : rows;
	}
	if (!rs.n) {
		free(rows);
		rows = NULL;
	}
	I->row = rows;
	I->why = rs.n ? DASH_OK : st == KGENOME_BAD_INPUT ? DASH_NA : DASH_NONE;
}

void dash_infect_table(const struct dash_infect *I, struct dash_table *t)
{
	static const char *const head[DASH_INF_COLS] = { "region", "file offset", "address", "size", "state", "value" };
	static const enum dash_tone tone[DASH_INF_COLS] = { DT_NAME, DT_LOC, DT_ALT, DT_SIZE, DT_TYPE, DT_ID };
	uint32_t k;

	memset(t, 0, sizeof *t);
	t->n_row = I->n;
	t->declared = I->total;
	t->not_shown = I->total > I->n ? I->total - I->n : 0u;
	if (!I->n) {
		t->none = I->why == DASH_NA ? "this object is not a parsed ELF or PE: there are no regions an infector uses to list"
					    : "no region an infector commonly uses was found in this object";
		return;
	}
	t->n_col = DASH_INF_COLS;
	t->lead = 1;
	for (k = 0; k < DASH_INF_COLS; k++) {
		t->head[k] = head[k];
		t->tone[k] = tone[k];
	}
}

void dash_infect_cell(const struct dash_infect *I, uint32_t row, struct dash_widecell *out)
{
	const struct kgenome_infect_row *r;

	wide_clear(out);
	if (row >= I->n)
		return;
	r = &I->row[row];
	snprintf(out->c[0], DASH_WIDE, "%s", r->name);
	off_cell(out->c[1], DASH_WIDE, r->off);
	off_cell(out->c[2], DASH_WIDE, r->addr);
	snprintf(out->c[3], DASH_WIDE, "%llu", (unsigned long long)r->len);
	if (r->flagged)
		snprintf(out->c[4], DASH_WIDE, "infected (%s)", inf_kind_word(r->inf_kind));
	else
		snprintf(out->c[4], DASH_WIDE, "-");
	if (!out->no_value)
		dash_value_text(out->value, sizeof out->value, I->file, r->off, r->len);
	out->cell[5] = out->value;
}

int dash_infect_flagged(const struct dash_infect *I, uint32_t row)
{
	return row < I->n && I->row[row].flagged;
}

uint32_t dash_infect_value_width(const struct dash_infect *I)
{
	uint32_t i, w = 1;

	for (i = 0; i < I->n; i++) {
		uint32_t l = dash_value_len(I->file, I->row[i].off, I->row[i].len);

		w = l > w ? l : w;
	}
	return w;
}

void dash_shell_load(const struct object *ob, struct dash_shell *S)
{
	struct kofscfind_list_in in;
	struct kofscfind_list_res rs;
	struct kgenome_obj g;
	enum kgenome_status st;
	struct kofscfind_row *rows;

	free(S->row);
	memset(S, 0, sizeof *S);
	rows = malloc(KOFSCFIND_ROWS_MAX * sizeof *rows);
	memset(&in, 0, sizeof in);
	genome_of(ob, &g);
	in.obj = &g;
	in.file = ob->buf;
	in.payload_va = ob->payload_at;
	in.payload_len = ob->payload_len;
	in.payload_bits = ob->payload_bits;
	in.out = rows;
	in.cap = rows ? KOFSCFIND_ROWS_MAX : 0u;
	st = kofscfind_list(&in, &rs);
	S->n = rs.n;
	S->total = rs.total;
	S->file = ob->buf;
	if (rows && rs.n) {
		struct kofscfind_row *shrunk = realloc(rows, rs.n * sizeof *rows);

		rows = shrunk ? shrunk : rows;
	}
	if (!rs.n) {
		free(rows);
		rows = NULL;
	}
	S->row = rows;
	S->why = rs.n ? DASH_OK : st == KGENOME_UNSUPPORTED ? DASH_NA : DASH_NONE;
}

void dash_shell_table(const struct dash_shell *S, struct dash_table *t)
{
	static const char *const head[DASH_SHELL_COLS] = { "name", "address", "file offset", "size", "perm", "type", "refs",
							   "entropy", "value" };
	static const enum dash_tone tone[DASH_SHELL_COLS] = { DT_NAME, DT_LOC, DT_ALT, DT_SIZE, DT_BIND, DT_TYPE, DT_REFS,
							      DT_ENT, DT_ID };
	uint32_t k;

	memset(t, 0, sizeof *t);
	t->n_row = S->n;
	t->declared = S->total;
	t->not_shown = S->total > S->n ? S->total - S->n : 0u;
	if (!S->n) {
		t->none = S->why == DASH_NA ? "this object is not an executable image: no variable or range in it carries execute permission"
					    : "no variable or data range in this object carries execute permission";
		return;
	}
	t->n_col = DASH_SHELL_COLS;
	t->lead = 1;
	for (k = 0; k < DASH_SHELL_COLS; k++) {
		t->head[k] = head[k];
		t->tone[k] = tone[k];
	}
}

/* How the code reaches the range, by kind: "call 1 · read 3 · ptr 2". "?" when the reference map was not asked (an architecture
 * the sweep does not track) or was cut, and then a count is only what was seen ("call 1 ?"); "-" when it is complete and nothing
 * refers to the range. */
static void refs_cell(char *out, size_t cap, const struct kgenome_range_facts *f, int ok)
{
	static const char *const word[6] = { "call", "jump", "read", "write", "arg", "ptr" };
	const uint32_t n[6] = { f->refs.call, f->refs.jump, f->refs.read, f->refs.write, f->refs.arg, f->refs_ptr };
	size_t o = 0;
	uint32_t k;

	out[0] = 0;
	if (!ok) {
		snprintf(out, cap, "-");
		return;
	}
	for (k = 0; k < 6u; k++)
		if (n[k] && o + 24u < cap)
			o += (size_t)snprintf(out + o, cap - o, "%s%s %u", o ? " \xc2\xb7 " : "", word[k], n[k]);
	if (!o)
		snprintf(out, cap, "%s", f->refs_known && !f->refs_partial ? "-" : "?");
	else if (!f->refs_known || f->refs_partial)
		snprintf(out + o, cap - o, " ?");
}

void dash_shell_cell(const struct dash_shell *S, uint32_t row, struct dash_widecell *out)
{
	static const char *const what[] = { "", "finder", "symbol", "range" };
	const struct kofscfind_row *r;
	const struct kgenome_range_facts *f;
	const char *cut;

	wide_clear(out);
	if (row >= S->n)
		return;
	r = &S->row[row];
	f = &r->facts;
	cut = r->facts_ok && f->analysed < r->size ? "+" : "";       /* judged by the first bytes only */
	snprintf(out->c[0], DASH_WIDE, "%s", r->name);
	off_cell(out->c[1], DASH_WIDE, r->va);
	off_cell(out->c[2], DASH_WIDE, r->off);
	snprintf(out->c[3], DASH_WIDE, "%llu", (unsigned long long)r->size);
	prop_perm(out->c[4], DASH_WIDE, r->perm);
	snprintf(out->c[5], DASH_WIDE, "%s", r->what <= KOFSCFIND_W_RANGE ? what[r->what] : "");
	refs_cell(out->c[6], DASH_WIDE, f, (int)r->facts_ok);
	if (r->facts_ok)
		snprintf(out->c[7], DASH_WIDE, "%u.%u%s", f->entropy_centi / 100u, f->entropy_centi / 10u % 10u, cut);
	else
		snprintf(out->c[7], DASH_WIDE, "-");
	if (!out->no_value)
		dash_value_text(out->value, sizeof out->value, S->file, r->off, r->size);
	out->cell[8] = out->value;
}

int dash_shell_flagged(const struct dash_shell *S, uint32_t row)
{
	return row < S->n && S->row[row].flagged;
}

uint32_t dash_shell_value_width(const struct dash_shell *S)
{
	uint32_t i, w = 1;

	for (i = 0; i < S->n; i++) {
		uint32_t l = dash_value_len(S->file, S->row[i].off, S->row[i].size);

		w = l > w ? l : w;
	}
	return w;
}

/* ---- the kept result ---------------------------------------------------------------------------------------- */

/* THE ANALYSIS RUNS ONCE PER OBJECT, for both tabs together, the first time either is shown (never at open or in the scan):
 * the regions an infector uses and the candidates with their facts. A tab switch, a redraw, a scroll, a resize and a reopen of the
 * dialog read what is kept on the object. Memory short: what could not be made stays NULL and the page says so. */
static void infection_once(struct object *ob)
{
	if (!ob->inf_data) {
		ob->inf_data = calloc(1, sizeof *ob->inf_data);
		if (ob->inf_data)
			dash_infect_load(ob, ob->inf_data);
	}
	if (!ob->shell_data) {
		ob->shell_data = calloc(1, sizeof *ob->shell_data);
		if (ob->shell_data)
			dash_shell_load(ob, ob->shell_data);
	}
}

struct dash_infect *dash_infect_get(struct object *ob)
{
	infection_once(ob);
	return ob->inf_data;
}

struct dash_shell *dash_shell_get(struct object *ob)
{
	infection_once(ob);
	return ob->shell_data;
}

void dash_drop(struct object *ob)
{
	if (ob->inf_data)
		free(ob->inf_data->row);
	free(ob->inf_data);
	ob->inf_data = NULL;
	if (ob->shell_data)
		free(ob->shell_data->row);
	free(ob->shell_data);
	ob->shell_data = NULL;
}

/* ---- the strip --------------------------------------------------------------------------------------------- */

/* The strip names the pages and carries no count. An empty page keeps its tab, so "this object imports nothing" stays
 * distinguishable from "no imports tab". */
uint32_t dash_tabs(const struct view *v, const struct object *ob, char lab[][32])
{
	static const char *const name[DASH_TABS] = { "Overview", "Segments", "Sections", "Imports", "Exports" };
	static const char *const inf[2] = { "Infected data", "Shellcode" };
	const char *const *w = v->prop_inf ? inf : name;
	uint32_t i, n = v->prop_inf ? 2u : DASH_TABS;

	(void)ob;
	for (i = 0; i < n; i++)
		snprintf(lab[i], 32, "%s", w[i]);
	return n;
}

/* THE ONE COUNT TEXT of a dialog: the rows now visible out of all of them - "a-b of N lines" on the overview (the lines of
 * the page), "a-b of N items" on a table page (the rows of the table, after the filter), a bare "a-b of N" for a page that
 * names no unit. `first` is the 0-based first visible row and `shown` how many; nothing is cut mid-number (the dialog drops the
 * whole text when it does not fit). */
void dash_count_text(char *out, size_t cap, const char *unit, uint32_t first, uint32_t shown, uint32_t total)
{
	const char *sp = unit && unit[0] ? " " : "";

	if (!unit)
		unit = "";
	if (!total || !shown)
		snprintf(out, cap, "0 of %u%s%s", total, sp, unit);
	else
		snprintf(out, cap, "%u-%u of %u%s%s", first + 1u, first + shown, total, sp, unit);
}
