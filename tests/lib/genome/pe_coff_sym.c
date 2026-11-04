/*
 * pe_coff_sym.c - kgenome_pe_coff_syms (pe_coff_sym.c): the one walk of a PE's own COFF
 * local symbol table, both halves of what it reports - the NAME (inline Name[8], or
 * through the string table for a longer one) on top of the off/value/shndx/size
 * fntab_pe_coff_linkage.c already pins for the function-boundary side of this same walk.
 *
 * RED/GREEN for PE-SYM-NAME-GAP's libgenome half: before kgenome_pe_coff_syms existed
 * there was no way to ask this question at all (the name logic in this file is new, not
 * a bug fix to something that ran before) - what this test pins is that the new code
 * reads the two name forms correctly AND degrades a hostile table the same way
 * fntab_pe_coff.c's own bound-checking already does for the SAME table (truncated mid-
 * record, a declared count past the file, a string-table offset past the table's own
 * end, a section number out of range, a corrupt aux-record count): none of these may
 * crash, read outside the object, or report a function this file does not have.
 *
 * Coverage gap closed: fntab_pe.c:t_coff and fntab_pe_coff_linkage.c:t_coff_value_shndx
 * both build a COFF table with the kit's pb_syms(), which hard-codes the name "sym" for
 * every record (see fntab_pe_kit.h) - neither ever exercises a REAL name, inline or
 * through the string table, so a bug in the name path would pass both unnoticed. This
 * file builds its own table (pb_syms_named, below) precisely because pb_syms cannot.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/pe_image.h>

#include "fntab_pe_kit.h"

/* A COFF symbol table with REAL names: `name[i]` inline when it is 8 bytes or fewer,
 * otherwise through the string table that follows the records. All at section 1
 * (.text), Type 0x20 (function), StorageClass EXTERNAL. Returns the table's file
 * offset (PointerToSymbolTable). */
static uint32_t pb_syms_named(struct pb *p, const char *const *name, const uint32_t *value, unsigned n)
{
	uint8_t *t = p->b + p->n;
	uint32_t coff_off = p->n, total_str = 4u, stroff = 4u, i;
	uint8_t *str = t + (uint32_t)n * 18u;

	for (i = 0; i < n; i++)
		if (strlen(name[i]) > 8u)
			total_str += (uint32_t)strlen(name[i]) + 1u;
	memset(t, 0, (uint32_t)n * 18u + total_str);
	for (i = 0; i < n; i++) {
		uint8_t *r = t + i * 18u;
		size_t l = strlen(name[i]);

		if (l <= 8u) {
			memcpy(r, name[i], l);
		} else {
			w(r + 4, stroff, 4);
			memcpy(str + stroff, name[i], l + 1u);
			stroff += (uint32_t)l + 1u;
		}
		w(r + 8, value[i], 4);
		w(r + 12, 1, 2);
		w(r + 14, 0x20, 2);
		r[16] = 2;
		r[17] = 0;
	}
	w(str, total_str, 4);
	w(p->b + p->lfanew + 12, coff_off, 4);
	w(p->b + p->lfanew + 16, n, 4);
	p->n = coff_off + (uint32_t)n * 18u + total_str;
	return coff_off;
}

struct hit {
	uint32_t n;
	char names[8][64];
	uint32_t n_name[8];
};

static int collect(void *user, const struct kgenome_pe_coff_sym *s)
{
	struct hit *h = user;
	uint32_t slot, i;

	CK(h->n < 8u);
	if (h->n >= 8u)
		return 0;
	slot = h->n++;
	/* The struct is only valid for the call: copy what the test needs out of it. */
	for (i = 0; i < s->name_len && i < 63u; i++)
		h->names[slot][i] = s->name[i];
	h->names[slot][i] = 0;
	h->n_name[slot] = s->name_len;
	return 1;
}

static void t_names_inline_and_strtab(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit h;
	static const char *nm[2] = { "calc", "a_mingw_generated_helper_name" };
	static const uint32_t val[2] = { 0x00, 0x20 };
	uint32_t n_bad = 999, t0;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(p.b + t0 + 0x20, "\x55\x8b\xec\x33\xc0\x5d\xc3", 7);
	pb_syms_named(&p, nm, val, 2);
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));

	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect, &h, &n_bad);
	CK(h.n == 2u && n_bad == 0u);
	if (h.n == 2u) {
		CK(h.n_name[0] == 4u && !strcmp(h.names[0], "calc"));
		CK(h.n_name[1] == strlen("a_mingw_generated_helper_name") &&
		   !strcmp(h.names[1], "a_mingw_generated_helper_name"));
	}
	free(p.b);
}

/* A section number past the table: counted in n_bad, not reported, no crash. */
static void t_hostile_section_out_of_range(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit h;
	static const char *nm[1] = { "calc" };
	static const uint32_t val[1] = { 0 };
	uint32_t coff_off, n_bad = 0, t0;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = pb_syms_named(&p, nm, val, 1);
	w(p.b + coff_off + 12, 99, 2);    /* SectionNumber 99: the file has one section */
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect, &h, &n_bad);
	CK(h.n == 0u && n_bad == 1u);
	free(p.b);
}

/* NumberOfSymbols lying far past the file: the walk is bounded by the file's own
 * length, not the declared count - the one valid record is still found, nothing
 * past the file is read (ASAN/a guard page would fault on it if it were). */
static void t_hostile_count_past_file(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit h;
	static const char *nm[1] = { "calc" };
	static const uint32_t val[1] = { 0 };
	uint32_t coff_off, n_bad = 0, t0;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = pb_syms_named(&p, nm, val, 1);
	w(p.b + p.lfanew + 16, 0x7fffffffu, 4);   /* NumberOfSymbols: absurd */
	(void)coff_off;
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect, &h, &n_bad);
	CK(h.n == 1u && !strcmp(h.names[0], "calc"));
	free(p.b);
}

/* A string-table offset past the table's own declared end: the empty name, not a
 * read into whatever follows - the symbol itself is reported with no name (so this
 * function gets no KSYM record at the engine layer, but the WALK does not crash or
 * invent one). */
static void t_hostile_strtab_offset_past_end(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit h;
	static const char *nm[1] = { "a_mingw_generated_helper_name" };
	static const uint32_t val[1] = { 0 };
	uint32_t coff_off, n_bad = 0, t0;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = pb_syms_named(&p, nm, val, 1);
	w(p.b + coff_off + 4, 0xffffu, 4);   /* the long-name offset: far past the string table's real size */
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect, &h, &n_bad);
	/* the symbol is still reported, with no name */
	CK(h.n == 1u && h.n_name[0] == 0u);
	free(p.b);
}

/* A truncated table: the file ends mid-second-record. The first (whole) record is
 * still found; the second is simply not there to find - not a partial or garbled
 * read of it. */
static void t_hostile_truncated_mid_record(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit h;
	static const char *nm[2] = { "calc", "helper2" };
	static const uint32_t val[2] = { 0, 0x10 };
	uint32_t coff_off, n_bad = 0, t0;
	kof_buf cut;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(p.b + t0 + 0x10, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = pb_syms_named(&p, nm, val, 2);
	pb_done(&p);

	cut = kof_buf_make(p.b, coff_off + 18u + 9u);  /* nine bytes into the second record */
	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(cut, &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(cut, &info, collect, &h, &n_bad);
	/* only the whole record survives a cut mid-record */
	CK(h.n == 1u && !strcmp(h.names[0], "calc"));
	free(p.b);
}

/* A corrupt NumberOfAuxSymbols (the primary record claims 200 auxiliary records the
 * file does not hold): the walk advances past them without reading any - the symbol
 * itself is still reported (aux records carry only the size, never the name or the
 * section), just without a size. */
static void t_hostile_corrupt_aux_count(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit h;
	static const char *nm[1] = { "calc" };
	static const uint32_t val[1] = { 0 };
	uint32_t coff_off, n_bad = 0, t0;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = pb_syms_named(&p, nm, val, 1);
	p.b[coff_off + 17] = 200;   /* NumberOfAuxSymbols: absurd, no such records follow */
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect, &h, &n_bad);
	/* the symbol survives a bogus aux count */
	CK(h.n == 1u && !strcmp(h.names[0], "calc"));
	free(p.b);
}

/* group 27 (pe_elf_fixtures campaign): genuinely new hostile cases not already covered above
 * (out-of-range section, declared count past file, string-table offset past its own end,
 * mid-record truncation, corrupt NumberOfAuxSymbols, NULL args - all already pinned). */

struct hit2 {
	uint32_t n;
	char names[4][64];
	uint8_t has_size[4];
	uint64_t size[4];
	uint32_t value[4];
};

static int collect2(void *user, const struct kgenome_pe_coff_sym *s)
{
	struct hit2 *h = user;
	uint32_t slot, i;

	CK(h->n < 4u);
	if (h->n >= 4u)
		return 0;
	slot = h->n++;
	for (i = 0; i < s->name_len && i < 63u; i++)
		h->names[slot][i] = s->name[i];
	h->names[slot][i] = 0;
	h->has_size[slot] = s->has_size;
	h->size[slot] = s->size;
	h->value[slot] = s->value;
	return 1;
}

/* Multiple aux records chained to ONE primary (NumberOfAuxSymbols 2, two real 18-byte aux
 * records follow): only the FIRST aux record's TotalSize is ever read (the format layout this
 * walk assumes, see pe_coff_sym.c's own header); a second aux record with a DIFFERENT TotalSize
 * must never override it, and the walk must still land exactly on the next real symbol after
 * skipping both. */
static void t_hostile_multiple_aux_records(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit2 h;
	uint32_t coff_off, n_bad = 1, t0;
	uint8_t *r;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(p.b + t0 + 0x20, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = p.n;
	r = p.b + p.n;
	memset(r, 0, 18u * 4u);
	memcpy(r, "calc", 4);
	w(r + 8, 0, 4); w(r + 12, 1, 2); w(r + 14, 0x20, 2); r[16] = 2; r[17] = 2;      /* naux = 2 */
	w(r + 18 + 4, 5, 4);                                                           /* aux1 TotalSize: the real one */
	w(r + 36 + 4, 777, 4);                                                         /* aux2 TotalSize: must be ignored */
	memcpy(r + 54, "helper", 6);
	w(r + 54 + 8, 0x20, 4); w(r + 54 + 12, 1, 2); w(r + 54 + 14, 0x20, 2); r[54 + 16] = 2; r[54 + 17] = 0;
	w(p.b + p.lfanew + 12, coff_off, 4);
	w(p.b + p.lfanew + 16, 4, 4);
	p.n += 18u * 4u + 4u;
	w(p.b + p.n - 4u, 4, 4);        /* the string table: just its own 4-byte size, empty */
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect2, &h, &n_bad);
	CK(n_bad == 0u && h.n == 2u);
	if (h.n == 2u) {
		CK(!strcmp(h.names[0], "calc") && h.has_size[0] && h.size[0] == 5u);
		CK(!strcmp(h.names[1], "helper") && h.value[1] == 0x20u && !h.has_size[1]);
	}
	free(p.b);
}

/* A corrupt NumberOfAuxSymbols that claims MORE aux records than really follow a symbol:
 * not merely "harmless" (t_hostile_corrupt_aux_count already shows the symbol with the bogus
 * count survives) but a genuine collateral loss - the walk advances past whatever naux claims
 * REGARDLESS of what is really there, so a REAL symbol that happens to sit in that stretch is
 * silently never visited as its own record. This is the format's own self-describing-count
 * shape (every COFF reader trusts NumberOfAuxSymbols the same way; the walk's header comment
 * already states "the loop advances... whatever NumberOfAuxSymbols claims") - characterized
 * here as expected, not filed as a new defect report: the walk still terminates, does not read
 * out of bounds, and resumes correctly on the first record past the whole corrupted run. */
static void t_hostile_aux_count_swallows_next_symbol(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct hit2 h;
	uint32_t coff_off, n_bad = 0, t0;
	uint8_t *r;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(p.b + t0 + 0x20, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(p.b + t0 + 0x40, "\x55\x8b\xec\x5d\xc3", 5);
	coff_off = p.n;
	r = p.b + p.n;
	memset(r, 0, 18u * 5u);
	memcpy(r, "calc", 4);
	w(r + 8, 0, 4); w(r + 12, 1, 2); w(r + 14, 0x20, 2); r[16] = 2;
	r[17] = 3;                                          /* NumberOfAuxSymbols: claims 3, really 0 */
	/* indices 1 and 2: never a real record, filler (whatever naux=3 skips past) */
	memcpy(r + 54, "helper", 6);                        /* index 3: a REAL symbol, swallowed by the bogus naux */
	w(r + 54 + 8, 0x20, 4); w(r + 54 + 12, 1, 2); w(r + 54 + 14, 0x20, 2); r[54 + 16] = 2;
	memcpy(r + 72, "tail", 4);                          /* index 4: the first record past the whole corrupted run */
	w(r + 72 + 8, 0x40, 4); w(r + 72 + 12, 1, 2); w(r + 72 + 14, 0x20, 2); r[72 + 16] = 2;
	w(p.b + p.lfanew + 12, coff_off, 4);
	w(p.b + p.lfanew + 16, 5, 4);
	p.n += 18u * 5u + 4u;
	w(p.b + p.n - 4u, 4, 4);
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	memset(&h, 0, sizeof h);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect2, &h, &n_bad);
	/* "calc" and "tail" are found; "helper" - a real record the bogus count swallowed - is not;
	 * the walk neither crashed nor read anything it should not have. */
	CK(h.n == 2u);
	if (h.n == 2u) {
		CK(!strcmp(h.names[0], "calc"));
		CK(!strcmp(h.names[1], "tail") && h.value[1] == 0x40u);
	}
	free(p.b);
}

/* NULL fn, no info, no file: every guard answers nothing, not a crash. */
static void t_null_and_no_table(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	uint32_t n_bad = 77;

	pb_init(&p, 0x4000, 0, 0x14c);
	(void)pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	pb_done(&p);    /* no symbol table at all: PointerToSymbolTable/NumberOfSymbols stay 0 */

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));

	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, NULL, NULL, &n_bad);
	/* a NULL callback: nothing is walked, n_bad is reset and not left stale */
	CK(n_bad == 0u);
	kgenome_pe_coff_syms(kof_buf_make(NULL, 0), &info, collect, NULL, NULL);
	kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), NULL, collect, NULL, NULL);
	{
		struct hit h;

		memset(&h, 0, sizeof h);
		kgenome_pe_coff_syms(kof_buf_make(p.b, p.n), &info, collect, &h, NULL);
		/* no table in the file: nothing reported, n_bad may be NULL */
		CK(h.n == 0u);
	}
	free(p.b);
}

int main(void)
{
	t_names_inline_and_strtab();
	t_hostile_section_out_of_range();
	t_hostile_count_past_file();
	t_hostile_strtab_offset_past_end();
	t_hostile_truncated_mid_record();
	t_hostile_corrupt_aux_count();
	t_hostile_multiple_aux_records();
	t_hostile_aux_count_swallows_next_symbol();
	t_null_and_no_table();
	printf("pe_coff_sym: %d failure(s)\n", fails);
	return fails != 0;
}
