/*
 * infect_regions - kgenome_infect_regions on hand-built views. Linked against libkgenome.a alone.
 *
 * Oracle: the expected rows are written down from the numbers the test puts in the headers, not from the function: an ELF with a
 * text and a data segment, a page of padding between them, a note segment, init_array, a section table and an overlay; a PE32+
 * with a raw size beyond the virtual size, a header cave, TLS callbacks, an import and a relocation directory inside the last
 * section and an overlay. Ranges the engine reported are placed on the entry, partly on it, on nothing, and as hostile numbers.
 * Damaged views: zero-length and past-the-end sections, counts above the arrays, an object that is not parsed, and the bounds.
 */
#include <kgenome.h>

#include "hk.h"

#define ELF_SIZE 0x1800u

static uint8_t file[ELF_SIZE];
static struct kgenome_elf_info E;
static struct kgenome_obj      EO;
static struct kgenome_infect_row rows[KGENOME_INFECT_MAX + 4u];

static void put64(uint8_t *p, uint64_t v)
{
	unsigned k;

	for (k = 0; k < 8; k++)
		p[k] = (uint8_t)(v >> (8u * k));
}

static void seg(uint32_t i, uint32_t type, uint32_t perm, uint64_t off, uint64_t sz, uint64_t addr)
{
	E.seg[i].type = type;
	E.seg[i].perm = perm;
	E.seg[i].file_off = off;
	E.seg[i].file_size = sz;
	E.seg[i].mem_addr = addr;
	E.seg[i].mem_size = sz;
}

static void sec(uint32_t i, const char *name, uint32_t type, uint64_t flags, uint64_t off, uint64_t sz, uint64_t addr)
{
	snprintf(E.sec[i].name, sizeof E.sec[i].name, "%s", name);
	E.sec[i].type = type;
	E.sec[i].flags = flags;
	E.sec[i].file_off = off;
	E.sec[i].file_size = sz;
	E.sec[i].mem_addr = addr;
}

static void elf_view(void)
{
	memset(file, 0, sizeof file);
	memset(&E, 0, sizeof E);
	memset(&EO, 0, sizeof EO);
	E.valid = 1;
	E.elf_class = KGENOME_ELFCLASS_64;
	E.elf_data = KGENOME_ELFDATA_LE;
	E.e_type = 2;
	E.entry_addr = 0x400400;
	E.phoff = 0x40;
	E.phentsize = 56;
	E.phnum = 3;
	E.shoff = 0x1540;
	E.shentsize = 64;
	E.shnum = 5;
	E.seg_count = 3;
	E.sec_count = 5;
	seg(0, 1, KGENOME_PERM_R | KGENOME_PERM_X, 0, 0x800, 0x400000);
	seg(1, 1, KGENOME_PERM_R | KGENOME_PERM_W, 0x1000, 0x400, 0x601000);
	seg(2, 4, KGENOME_PERM_R, 0x300, 0x20, 0x400300);
	sec(0, "", 0, 0, 0, 0, 0);
	sec(1, ".text", 1, 6, 0x400, 0x300, 0x400400);
	sec(2, ".init_array", 14, 3, 0x1000, 0x10, 0x601000);
	sec(3, ".data", 1, 3, 0x1010, 0x3f0, 0x601010);
	sec(4, ".shstrtab", 3, 0, 0x1500, 0x40, 0);
	put64(file + 0x40 + 56u * 1u + 48u, 0x1000);        /* p_align of segment 1 */
	EO.format = KGENOME_FMT_ELF;
	EO.arch = KGENOME_ARCH_X86_64;
	EO.subtype = 2;
	EO.obj_size = ELF_SIZE;
	EO.entry_off = 0x400;
	EO.file_header = &E;
}

static struct kgenome_infect_res run(const struct kgenome_obj *o, const struct kgenome_infect_range *in, uint32_t n, uint32_t cap,
				     enum kgenome_status *st)
{
	struct kgenome_infect_req rq;
	struct kgenome_infect_res rs;

	memset(rows, 0x5a, sizeof rows);
	rq.obj = o;
	rq.file = kof_buf_make(file, o ? o->obj_size : 0);
	rq.inf = in;
	rq.n_inf = n;
	rq.out = rows;
	rq.cap = cap;
	*st = kgenome_infect_regions(&rq, &rs);
	return rs;
}

/* The row of a kind; a kind with no row answers an empty one (kind 0), so a missing row fails a check instead of a dereference. */
static const struct kgenome_infect_row *kind(const struct kgenome_infect_res *rs, uint32_t k)
{
	static const struct kgenome_infect_row missing;
	uint32_t i;

	for (i = 0; i < rs->n; i++)
		if (rows[i].kind == k)
			return &rows[i];
	return &missing;
}

static int is(const struct kgenome_infect_row *r, uint64_t off, uint64_t len, uint64_t addr)
{
	return r->kind && r->off == off && r->len == len && r->addr == addr;
}

static uint32_t count(const struct kgenome_infect_res *rs, uint32_t k)
{
	uint32_t i, n = 0;

	for (i = 0; i < rs->n; i++)
		n += rows[i].kind == k;
	return n;
}

static void elf_regions(void)
{
	struct kgenome_infect_res rs;
	enum kgenome_status st;
	const struct kgenome_infect_row *r;

	elf_view();
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_OK);
	CK(rs.n == 9 && rs.total == 9 && rs.n_flagged == 0 && rs.n_reported == 0);
	CK(is(kind(&rs, KGENOME_INFECT_ENTRY), 0x400, KGENOME_INFECT_ENTRY_AREA, 0x400400));
	r = kind(&rs, KGENOME_INFECT_ENTRY_SECTION);
	CK(is(r, 0x400, 0x300, 0x400400) && strcmp(r->name, "entry section .text") == 0);
	r = kind(&rs, KGENOME_INFECT_LAST_SECTION);
	CK(is(r, 0x1500, 0x40, KGENOME_NA) && strcmp(r->name, "last section .shstrtab") == 0);   /* not mapped: no address */
	r = kind(&rs, KGENOME_INFECT_LAST_SEGMENT);
	CK(is(r, 0x1000, 0x400, 0x601000) && strcmp(r->name, "last segment #1") == 0);
	/* the padding after it runs to the next page boundary, but stops where the next section starts (0x1500) */
	CK(is(kind(&rs, KGENOME_INFECT_SLACK), 0x1400, 0x100, KGENOME_NA));
	r = kind(&rs, KGENOME_INFECT_GAP);
	CK(is(r, 0x800, 0x800, KGENOME_NA) && strcmp(r->name, "gap between segments #0 and #1") == 0);
	r = kind(&rs, KGENOME_INFECT_INIT);
	CK(is(r, 0x1000, 0x10, 0x601000) && strcmp(r->name, "init section .init_array") == 0 && count(&rs, KGENOME_INFECT_INIT) == 1);
	r = kind(&rs, KGENOME_INFECT_NOTE);
	CK(is(r, 0x300, 0x20, 0x400300) && strcmp(r->name, "note segment #2") == 0);
	/* the section table ends at 0x1540 + 5 * 64 = 0x1680; the object is 0x1800 long */
	CK(is(kind(&rs, KGENOME_INFECT_OVERLAY), 0x1680, 0x180, KGENOME_NA));

	/* an init section by name only: .ctors is PROGBITS, nothing else says it runs first */
	sec(3, ".ctors", 1, 3, 0x1010, 0x3f0, 0x601010);
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(count(&rs, KGENOME_INFECT_INIT) == 2);
	sec(3, ".data", 1, 3, 0x1010, 0x3f0, 0x601010);

	/* no entry in the file (an ET_REL): no entry row; the section that holds the declared address is still listed */
	EO.entry_off = KGENOME_NA;
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_ENTRY)->kind && rs.n == 8);
	EO.entry_off = KGENOME_BROKEN;
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_ENTRY)->kind);
	EO.entry_off = ELF_SIZE;        /* at the end of the object: nothing there to patch */
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_ENTRY)->kind);
}

static void elf_flags(void)
{
	struct kgenome_infect_range in[2];
	struct kgenome_infect_res rs;
	enum kgenome_status st;
	const struct kgenome_infect_row *r;
	uint32_t i, flagged = 0;

	elf_view();
	/* on the entry: the entry area and the section that holds it, nothing else */
	in[0].off = 0x405; in[0].len = 4; in[0].kind = 1; in[0]._pad = 0;
	rs = run(&EO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_OK && rs.n == 9 && rs.n_flagged == 2 && rs.n_reported == 0);
	r = kind(&rs, KGENOME_INFECT_ENTRY);
	CK(r->flagged && r->inf_kind == 1 && r->inf_index == 0);
	CK(kind(&rs, KGENOME_INFECT_ENTRY_SECTION)->flagged);
	CK(!kind(&rs, KGENOME_INFECT_GAP)->flagged && !kind(&rs, KGENOME_INFECT_OVERLAY)->flagged);

	/* one byte before the entry area and one inside it: partial overlap flags it; a range that ENDS where a region starts does not */
	in[0].off = 0x3ff; in[0].len = 2; in[0].kind = 0;
	rs = run(&EO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(kind(&rs, KGENOME_INFECT_ENTRY)->flagged && kind(&rs, KGENOME_INFECT_ENTRY)->inf_kind == 0 && rs.n_flagged == 2);
	in[0].off = 0x3f0; in[0].len = 0x10;
	rs = run(&EO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(rs.n_flagged == 1 && rs.n_reported == 1 && !kind(&rs, KGENOME_INFECT_ENTRY)->flagged && rs.n == 10);

	/* on nothing the list names: the header. It comes back as a row of its own, with the address the image maps it at */
	in[0].off = 0x20; in[0].len = 8; in[0].kind = 0;
	rs = run(&EO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(rs.n == 10 && rs.total == 10 && rs.n_reported == 1 && rs.n_flagged == 1);
	r = &rows[rs.n - 1u];
	CK(r->kind == KGENOME_INFECT_REPORTED && r->off == 0x20 && r->len == 8 && r->addr == 0x400020 && r->flagged &&
	   strcmp(r->name, "reported by the engine") == 0);

	/* two ranges: the second's index and kind are the row's */
	in[0].off = 0x1100; in[0].len = 4; in[0].kind = 0;
	in[1].off = 0x1700; in[1].len = 4; in[1].kind = 1; in[1]._pad = 0;
	rs = run(&EO, in, 2, KGENOME_INFECT_MAX, &st);
	CK(kind(&rs, KGENOME_INFECT_LAST_SEGMENT)->flagged && kind(&rs, KGENOME_INFECT_LAST_SEGMENT)->inf_index == 0);
	r = kind(&rs, KGENOME_INFECT_OVERLAY);
	CK(r->flagged && r->inf_kind == 1 && r->inf_index == 1);

	/* a zero-length range touches nothing and is still reported; an offset past the object too, with no address */
	in[0].off = 0x400; in[0].len = 0;
	in[1].off = 0x9000; in[1].len = 4;
	rs = run(&EO, in, 2, KGENOME_INFECT_MAX, &st);
	CK(rs.n_reported == 2 && rs.n_flagged == 2);
	CK(rows[rs.n - 2u].addr == 0x400400 && rows[rs.n - 1u].addr == KGENOME_NA);

	/* hostile: a length that wraps flags every region that starts after it and never reads outside */
	in[0].off = 0x10; in[0].len = ~0ull; in[0].kind = 0;
	rs = run(&EO, in, 1, KGENOME_INFECT_MAX, &st);
	for (i = 0; i < rs.n; i++)
		flagged += rows[i].flagged;
	CK(flagged == rs.n && rs.n_reported == 0);
	in[0].off = ~0ull; in[0].len = ~0ull;
	rs = run(&EO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(rs.n_flagged == 1 && rs.n_reported == 1);
}

static void bounds(void)
{
	static struct kgenome_infect_range many[KGENOME_INFECT_RANGE_MAX + 40u];
	struct kgenome_infect_res rs;
	enum kgenome_status st;
	uint32_t i;

	elf_view();
	/* the room: a short row array is said, and the total is what there would have been */
	rs = run(&EO, NULL, 0, 3, &st);
	CK(st == KGENOME_TRUNCATED && rs.n == 3 && rs.total == 9);
	rs = run(&EO, NULL, 0, 0, &st);
	CK(st == KGENOME_TRUNCATED && rs.n == 0 && rs.total == 9);
	/* a range inside a region the room cannot hold is still that region's: no row of its own, and the total does not move */
	{
		struct kgenome_infect_range in = { 0x405, 4, 1, 0 };

		rs = run(&EO, &in, 1, 1, &st);
		CK(st == KGENOME_TRUNCATED && rs.n == 1 && rs.total == 9 && rs.n_reported == 0);
		rs = run(&EO, &in, 1, 0, &st);
		CK(rs.n == 0 && rs.total == 9);
	}
	/* more ranges than the bound: the first ones are used, the cut is said */
	for (i = 0; i < KGENOME_INFECT_RANGE_MAX + 40u; i++) {
		many[i].off = 0x20u + i;
		many[i].len = 1;
		many[i].kind = 0;
		many[i]._pad = 0;
	}
	rs = run(&EO, many, KGENOME_INFECT_RANGE_MAX + 40u, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_TRUNCATED);
	CK(rs.n_reported <= KGENOME_INFECT_RANGE_MAX);
	CK(rs.total <= KGENOME_INFECT_MAX);
	/* tables full to their capacity, a header that claims 65535 program headers, and sections that are empty, past the end,
	 * or huge: only what the object holds is listed, and every range is inside the object */
	E.seg_count = KGENOME_ELF_MAX_SEGMENTS;
	E.sec_count = KGENOME_ELF_MAX_SECTIONS;
	E.phnum = 65535;
	sec(2, ".past", 1, 3, ELF_SIZE + 5u, 0x40, 0);
	sec(3, ".huge", 1, 3, 0x1010, ~0ull, 0);
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_OK && rs.n <= KGENOME_INFECT_MAX);
	for (i = 0; i < rs.n; i++)
		CK(rows[i].off == KGENOME_NA || (rows[i].off <= ELF_SIZE && rows[i].len <= ELF_SIZE - rows[i].off));
	/* a name from the file with a control byte is shown with '?' */
	elf_view();
	sec(4, ".sh\x1b[31m", 3, 0, 0x1500, 0x40, 0);
	rs = run(&EO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(strcmp(kind(&rs, KGENOME_INFECT_LAST_SECTION)->name, "last section .sh?[31m") == 0);
	/* an object that is not parsed: no regions, and what the engine said is still there */
	{
		struct kgenome_infect_range one = { 0x10, 4, 1, 0 };
		struct kgenome_obj bad;

		memset(&bad, 0, sizeof bad);
		bad.obj_size = 64;
		rs = run(&bad, &one, 1, KGENOME_INFECT_MAX, &st);
		CK(st == KGENOME_BAD_INPUT && rs.n == 1 && rows[0].kind == KGENOME_INFECT_REPORTED && rows[0].addr == KGENOME_NA);
		rs = run(NULL, &one, 1, KGENOME_INFECT_MAX, &st);
		CK(st == KGENOME_BAD_INPUT && rs.n == 1);
		rs = run(NULL, NULL, 0, KGENOME_INFECT_MAX, &st);
		CK(st == KGENOME_BAD_INPUT && rs.n == 0 && rs.total == 0);
		elf_view();
		E.valid = 0;
		rs = run(&EO, &one, 1, KGENOME_INFECT_MAX, &st);
		CK(st == KGENOME_BAD_INPUT && rs.n == 1);
	}
}

/* ---- PE32+ -------------------------------------------------------------------------------------------------- */

#define PE_SIZE 0xd00u
static struct kgenome_pe_info P;
static struct kgenome_obj     PO;

static void psec(uint32_t i, const char *name, uint64_t rva, uint64_t vsz, uint64_t off, uint64_t rsz, uint32_t perm)
{
	snprintf(P.sec[i].name, sizeof P.sec[i].name, "%s", name);
	P.sec[i].mem_rva = rva;
	P.sec[i].mem_size = vsz;
	P.sec[i].file_off = off;
	P.sec[i].file_size = rsz;
	P.sec[i].perm = perm;
}

static void pe_view(void)
{
	memset(file, 0, sizeof file);
	memset(&P, 0, sizeof P);
	memset(&PO, 0, sizeof PO);
	P.valid = 1;
	P.pe32_plus = 1;
	P.image_base = 0x140000000ull;
	P.header_end = 0x178;
	P.n_dirs = 16;
	P.sec_count = 3;
	P.nsec = 3;
	P.entry_rva = 0x1010;
	P.entry_sec = 0;
	psec(0, ".text", 0x1000, 0x300, 0x400, 0x400, KGENOME_PE_PERM_R | KGENOME_PE_PERM_X);
	psec(1, ".rdata", 0x2000, 0x200, 0x800, 0x200, KGENOME_PE_PERM_R);
	psec(2, ".evil", 0x3000, 0x600, 0xa00, 0x200, KGENOME_PE_PERM_R | KGENOME_PE_PERM_W);
	P.dir[KGENOME_PE_DIR_IMPORT].rva = 0x3010;
	P.dir[KGENOME_PE_DIR_IMPORT].size = 0x28;
	P.dir[KGENOME_PE_DIR_BASERELOC].rva = 0x3100;
	P.dir[KGENOME_PE_DIR_BASERELOC].size = 0x10;
	P.dir[KGENOME_PE_DIR_TLS].rva = 0x2010;
	P.dir[KGENOME_PE_DIR_TLS].size = 0x28;
	P.overlay_off = 0xc00;
	P.overlay_len = 0x100;
	/* the TLS directory at file 0x810: AddressOfCallBacks (offset 24) -> RVA 0x2100 = file 0x900; two callbacks then a zero */
	put64(file + 0x810 + 24, 0x140002100ull);
	put64(file + 0x900, 0x140001010ull);
	put64(file + 0x908, 0x140001020ull);
	PO.format = KGENOME_FMT_PE;
	PO.arch = KGENOME_ARCH_X86_64;
	PO.obj_size = PE_SIZE;
	PO.entry_off = 0x410;
	PO.file_header = &P;
}

static void pe_regions(void)
{
	struct kgenome_infect_res rs;
	enum kgenome_status st;
	const struct kgenome_infect_row *r;

	pe_view();
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_OK && rs.n == 9 && rs.total == 9);
	CK(is(kind(&rs, KGENOME_INFECT_ENTRY), 0x410, 16, 0x1010));
	r = kind(&rs, KGENOME_INFECT_ENTRY_SECTION);
	CK(is(r, 0x400, 0x400, 0x1000) && strcmp(r->name, "entry section .text") == 0);
	r = kind(&rs, KGENOME_INFECT_LAST_SECTION);
	CK(is(r, 0xa00, 0x200, 0x3000) && strcmp(r->name, "last section .evil") == 0);
	/* virtual 0x600 over raw 0x200: the last 0x400 exist only in memory, so there is no file offset */
	r = kind(&rs, KGENOME_INFECT_SLACK);
	CK(is(r, KGENOME_NA, 0x400, 0x3200) && strcmp(r->name, "virtual beyond raw size in .evil") == 0);
	/* both directories point into the last section; their file offsets come from the section table */
	CK(is(kind(&rs, KGENOME_INFECT_DIR_RELOC), 0xb00, 0x10, 0x3100));
	CK(is(kind(&rs, KGENOME_INFECT_DIR_IMPORT), 0xa10, 0x28, 0x3010));
	/* the cave: from the end of the headers to the first section's raw data */
	CK(is(kind(&rs, KGENOME_INFECT_HEADER_CAVE), 0x178, 0x400 - 0x178, 0x178));
	r = kind(&rs, KGENOME_INFECT_TLS);
	CK(is(r, 0x900, 24, 0x2100) && strcmp(r->name, "TLS callbacks (2)") == 0);
	CK(is(kind(&rs, KGENOME_INFECT_OVERLAY), 0xc00, 0x100, KGENOME_NA));

	/* raw beyond virtual: the other direction of the slack, with file bytes */
	psec(2, ".evil", 0x3000, 0x100, 0xa00, 0x300, KGENOME_PE_PERM_R | KGENOME_PE_PERM_W);
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	r = kind(&rs, KGENOME_INFECT_SLACK);
	CK(is(r, 0xb00, 0x200, 0x3100) && strcmp(r->name, "raw beyond virtual size in .evil") == 0);
	/* equal sizes: no slack row */
	psec(2, ".evil", 0x3000, 0x200, 0xa00, 0x200, KGENOME_PE_PERM_R);
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_SLACK)->kind);
	/* a directory outside the last section is not listed */
	P.dir[KGENOME_PE_DIR_IMPORT].rva = 0x2020;
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_DIR_IMPORT)->kind && kind(&rs, KGENOME_INFECT_DIR_RELOC)->kind);
	/* no TLS callbacks pointer that resolves: no row; an array of none is the terminator alone */
	put64(file + 0x900, 0);
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(is(kind(&rs, KGENOME_INFECT_TLS), 0x900, 8, 0x2100) && strcmp(kind(&rs, KGENOME_INFECT_TLS)->name, "TLS callbacks (0)") == 0);
	put64(file + 0x810 + 24, 0x100ull);                 /* below the image base */
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_TLS)->kind);
	put64(file + 0x810 + 24, 0x140009000ull);           /* an RVA in no section */
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(!kind(&rs, KGENOME_INFECT_TLS)->kind);
}

static void pe_flags(void)
{
	struct kgenome_infect_range in[1];
	struct kgenome_infect_res rs;
	enum kgenome_status st;

	pe_view();
	in[0].off = 0x200; in[0].len = 4; in[0].kind = 1; in[0]._pad = 0;       /* inside the cave only */
	rs = run(&PO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(rs.n_flagged == 1 && rs.n_reported == 0 && kind(&rs, KGENOME_INFECT_HEADER_CAVE)->flagged &&
	   kind(&rs, KGENOME_INFECT_HEADER_CAVE)->inf_kind == 1);
	in[0].off = 0x412; in[0].len = 2; in[0].kind = 0;                       /* on the entry */
	rs = run(&PO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(rs.n_flagged == 2 && kind(&rs, KGENOME_INFECT_ENTRY)->flagged && kind(&rs, KGENOME_INFECT_ENTRY_SECTION)->flagged);
	in[0].off = 0xb08; in[0].len = 0x10;                                    /* across the end of the reloc directory and past it */
	rs = run(&PO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(kind(&rs, KGENOME_INFECT_DIR_RELOC)->flagged && kind(&rs, KGENOME_INFECT_LAST_SECTION)->flagged &&
	   !kind(&rs, KGENOME_INFECT_DIR_IMPORT)->flagged && rs.n_flagged == 2);
	in[0].off = 0xc80;                                                      /* the virtual-only slack has no file bytes: never flagged */ in[0].len = 0x10;
	rs = run(&PO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(kind(&rs, KGENOME_INFECT_OVERLAY)->flagged && !kind(&rs, KGENOME_INFECT_SLACK)->flagged);
	in[0].off = 0x10; in[0].len = 4;                                        /* the DOS header: no region */
	rs = run(&PO, in, 1, KGENOME_INFECT_MAX, &st);
	CK(rs.n_reported == 1 && rows[rs.n - 1u].addr == KGENOME_NA);           /* no section maps it: no address (kgenome_image_off_to_addr) */
}

static void pe_damaged(void)
{
	struct kgenome_infect_res rs;
	enum kgenome_status st;
	uint32_t i;

	pe_view();
	P.sec_count = KGENOME_PE_MAX_SECTIONS;
	P.nsec = (uint16_t)KGENOME_PE_MAX_SECTIONS;
	P.n_dirs = 100000;
	psec(1, ".zero", 0x2000, 0x200, 0x800, 0, KGENOME_PE_PERM_R);          /* zero raw size */
	psec(2, ".past", 0x3000, 0x600, PE_SIZE + 1u, 0x200, KGENOME_PE_PERM_R); /* past the end */
	P.dir[KGENOME_PE_DIR_TLS].rva = ~0ull;
	P.dir[KGENOME_PE_DIR_IMPORT].rva = ~0ull;
	P.header_end = ~0ull;
	P.overlay_off = ~0ull;
	P.overlay_len = ~0ull;
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_OK && rs.n <= KGENOME_INFECT_MAX);
	for (i = 0; i < rs.n; i++)
		CK(rows[i].off == KGENOME_NA || (rows[i].off <= PE_SIZE && rows[i].len <= PE_SIZE - rows[i].off));
	/* a table that did not parse */
	pe_view();
	P.valid = 0;
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_BAD_INPUT && rs.n == 0);
	pe_view();
	PO.format = KGENOME_FMT_NONE;
	rs = run(&PO, NULL, 0, KGENOME_INFECT_MAX, &st);
	CK(st == KGENOME_BAD_INPUT && rs.n == 0);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	elf_regions();
	elf_flags();
	bounds();
	pe_regions();
	pe_flags();
	pe_damaged();
	printf("infect_regions: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
