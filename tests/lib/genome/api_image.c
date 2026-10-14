/*
 * api_image - the functional contract of the image API that no test named:
 * the address translations (image_addr.h), the boundary table and the offset
 * visitor (offmap.h), the small ELF/PE section predicates, the symbol-table
 * reader, the relocation lookup, the CLR region vocabulary, the function-list
 * builders and the ledger's note.
 *
 * Linked against libkgenome.a alone. Every object is built in memory by hk.h.
 * Where a case sits next to a hostile value it is the CONTRACT that is asserted
 * (what is returned for a value no honest file holds); the byte-level hostile
 * sweeps are in hostile_image.c.
 */

#include <kgenome.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_elf E;
static struct hk_pe  P;

static int parse_elf(struct hk_elf *e, struct kgenome_elf_info *i, struct kgenome_obj *o)
{
	memset(i, 0, sizeof *i);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(kof_buf_make(e->b, e->n), i, o))
		return 0;
	o->file_header = i;
	return 1;
}

static int parse_pe(struct hk_pe *p, struct kgenome_pe_info *i, struct kgenome_obj *o)
{
	memset(i, 0, sizeof *i);
	memset(o, 0, sizeof *o);
	if (!kgenome_pe_image_parse(kof_buf_make(p->b, p->n), i, o))
		return 0;
	o->file_header = i;
	return 1;
}

/* ---- image_addr.h ------------------------------------------------------------ */

static void t_image_addr(void)
{
	static struct kgenome_elf_info ei;
	static struct kgenome_pe_info pi;
	struct kgenome_obj eo, po, none;
	struct kgenome_image_seg g;

	hk_elf(&E, 1, 0, 0);
	hk_pe(&P, 1);
	CK(parse_elf(&E, &ei, &eo));
	CK(parse_pe(&P, &pi, &po));

	/* ELF: one PT_LOAD over the file at 0x400000 */
	memset(&g, 0xaa, sizeof g);
	CK(kgenome_image_seg_at(&eo, E.text, &g) == 1);
	CK(g.lo == 0 && g.hi == E.n && g.delta == 0x400000);
	CK(kgenome_image_off_to_addr(&eo, E.text) == 0x400000u + E.text);
	CK(kgenome_image_addr_to_off(&eo, 0x400000u + E.text) == E.text);
	CK(kgenome_image_off_to_addr(&eo, 0) == 0x400000u);
	CK(kgenome_image_off_to_addr(&eo, E.n - 1u) == 0x400000u + E.n - 1u);
	/* the first byte past the file half, and far past it, are in no mapping */
	CK(kgenome_image_off_to_addr(&eo, E.n) == KGENOME_BROKEN);
	CK(kgenome_image_off_to_addr(&eo, UINT64_MAX) == KGENOME_BROKEN);
	CK(kgenome_image_seg_at(&eo, E.n, &g) == 0);
	CK(kgenome_image_addr_to_off(&eo, 0x400000u + E.n) == KGENOME_BROKEN);
	CK(kgenome_image_addr_to_off(&eo, 0x3fffffu) == KGENOME_BROKEN);
	CK(kgenome_image_addr_to_off(&eo, 0) == KGENOME_BROKEN);
	CK(kgenome_image_addr_to_off(&eo, UINT64_MAX) == KGENOME_BROKEN);
	/* round trip over every offset of the file */
	{
		uint64_t off;
		int ok = 1;
		for (off = 0; off < E.n; off++)
			ok &= kgenome_image_addr_to_off(&eo, kgenome_image_off_to_addr(&eo, off)) == off;
		CK(ok);
	}

	/* PE: image_base + rva; addr_to_off takes an address or a bare RVA */
	CK(kgenome_image_off_to_addr(&po, P.text_off) == 0x140000000ull + 0x1000);
	CK(kgenome_image_off_to_addr(&po, P.idata_off + 5u) == 0x140000000ull + 0x2005);
	CK(kgenome_image_addr_to_off(&po, 0x140000000ull + 0x1000) == P.text_off);
	CK(kgenome_image_addr_to_off(&po, 0x1000) == P.text_off);
	/* a header offset belongs to no section; a hole beyond the raw size neither */
	CK(kgenome_image_off_to_addr(&po, 0x10) == KGENOME_BROKEN);
	CK(kgenome_image_seg_at(&po, 0x10, &g) == 0);
	CK(kgenome_image_addr_to_off(&po, 0x140000000ull + 0x1200) == KGENOME_BROKEN);
	CK(kgenome_image_off_to_addr(&po, UINT64_MAX) == KGENOME_BROKEN);
	CK(kgenome_image_seg_at(&po, P.text_off, &g) == 1 &&
	   g.lo == P.text_off && g.hi == P.text_off + 0x200);

	/* an object that is neither, or has no parsed view, answers "nowhere" */
	memset(&none, 0, sizeof none);
	CK(kgenome_image_seg_at(&none, 0, &g) == 0);
	CK(kgenome_image_off_to_addr(&none, 0) == KGENOME_BROKEN);
	CK(kgenome_image_addr_to_off(&none, 0x1000) == KGENOME_BROKEN);
	CK(kgenome_image_seg_at(NULL, 0, &g) == 0);
	CK(kgenome_image_off_to_addr(NULL, 0) == KGENOME_BROKEN);
	CK(kgenome_image_addr_to_off(NULL, 0) == KGENOME_BROKEN);
	eo.file_header = NULL;
	CK(kgenome_image_seg_at(&eo, 0, &g) == 0);
	CK(kgenome_image_addr_to_off(&eo, 0x400000) == KGENOME_BROKEN);
}

/* ---- offmap.h ---------------------------------------------------------------- */

static void t_offmap_at(void)
{
	static const uint64_t from[] = { 10, 20, 30 };
	static const uint64_t to[]   = {  5,  5, 15 };
	struct kgenome_offmap m = { from, to, 3, 40, 25 };
	uint64_t off;

	/* exact marks answer exactly */
	CK(kgenome_offmap_at(&m, 10) == 5);
	CK(kgenome_offmap_at(&m, 20) == 5);
	CK(kgenome_offmap_at(&m, 30) == 15);
	/* between: the lower mark plus the distance, held below the next mark */
	CK(kgenome_offmap_at(&m, 12) == 5);       /* 5+2 = 7 > to[1] = 5 -> held */
	CK(kgenome_offmap_at(&m, 33) == 18);
	/* below the first mark */
	CK(kgenome_offmap_at(&m, 0) == 0);
	CK(kgenome_offmap_at(&m, 9) == 5);
	/* the end, and past it */
	CK(kgenome_offmap_at(&m, 40) == 25);
	CK(kgenome_offmap_at(&m, 41) == 25);
	CK(kgenome_offmap_at(&m, UINT64_MAX) == 25);
	CK(kgenome_offmap_at(&m, 39) <= 25);
	/* no table is the identity */
	CK(kgenome_offmap_at(NULL, 77) == 77);
	m.n = 0;
	CK(kgenome_offmap_at(&m, 77) == 77);
	CK(kgenome_offmap_at(&m, UINT64_MAX) == UINT64_MAX);
	/* monotone tables give monotone answers, never past to_end */
	{
		struct hk_rng r = { 0x9e3779b97f4a7c15ull };
		unsigned round;
		for (round = 0; round < 200; round++) {
			uint64_t f[16], t[16], a = 0, b = 0, prev = 0;
			uint32_t n = 1 + hk_below(&r, 16), i;
			struct kgenome_offmap q;
			for (i = 0; i < n; i++) {
				a += 1 + hk_below(&r, 50);
				b += hk_below(&r, 50);
				f[i] = a; t[i] = b;
			}
			q.from = f; q.to = t; q.n = n;
			q.from_end = a + 20; q.to_end = b + hk_below(&r, 20) + 20;
			for (off = 0; off < q.from_end + 3; off++) {
				uint64_t v = kgenome_offmap_at(&q, off);
				CK(v >= prev);
				CK(v <= q.to_end);
				prev = v;
			}
		}
	}
}

struct vis { uint32_t pos, ext; uint64_t sum; };

static void vis_fn(void *u, uint64_t *off, uint64_t *len)
{
	struct vis *v = (struct vis *)u;
	if (len)
		v->ext++;
	else
		v->pos++;
	v->sum += *off;
}

static void t_info_offsets(void)
{
	static struct kgenome_elf_info ei, ei2;
	static struct kgenome_pe_info pi, pi2;
	struct kgenome_obj o;
	struct vis v;
	uint64_t from0[1] = { 0 }, to0[1] = { 0x10 };
	struct kgenome_offmap shift;

	hk_elf(&E, 1, 0, 0);
	CK(parse_elf(&E, &ei, &o));
	memset(&v, 0, sizeof v);
	kgenome_elf_info_offsets(&ei, vis_fn, &v);
	/* phoff, shoff; two header claims; 2 per segment; 2 per section */
	CK(v.pos == 2);
	CK(v.ext == 2u + 2u * ei.seg_count + 2u * ei.sec_count);

	hk_pe(&P, 0);
	CK(parse_pe(&P, &pi, &o));
	memset(&v, 0, sizeof v);
	kgenome_pe_info_offsets(&pi, vis_fn, &v);
	CK(v.pos == 3);
	CK(v.ext == 5u + 2u * pi.sec_count + 7u);

	/* remap by a table that moves everything 0x10 up: every position is +0x10,
	 * and an extent keeps its length */
	shift.from = from0; shift.to = to0; shift.n = 1;
	shift.from_end = E.n; shift.to_end = E.n + 0x10u;
	ei2 = ei;
	kgenome_elf_info_remap(&ei2, &shift);
	CK(ei2.phoff == ei.phoff + 0x10u);
	CK(ei2.shoff == ei.shoff + 0x10u);
	CK(ei2.sec[1].file_off == ei.sec[1].file_off + 0x10u);
	CK(ei2.sec[1].file_size == ei.sec[1].file_size);
	CK(ei2.seg[0].file_off == 0x10u);
	CK(ei2.seg[0].file_size == ei.seg[0].file_size);
	CK(ei2.entry_addr == ei.entry_addr);        /* an address, not an offset */
	CK(ei2.phnum == ei.phnum && ei2.e_machine == ei.e_machine);

	shift.from_end = P.n; shift.to_end = P.n + 0x10u;
	pi2 = pi;
	kgenome_pe_info_remap(&pi2, &shift);
	CK(pi2.lfanew == pi.lfanew + 0x10u);
	CK(pi2.sec[0].file_off == pi.sec[0].file_off + 0x10u);
	CK(pi2.sec[0].file_size == pi.sec[0].file_size);
	CK(pi2.sec[0].mem_rva == pi.sec[0].mem_rva);   /* an RVA is not an offset */
	CK(pi2.entry_rva == pi.entry_rva);
	CK(pi2.image_base == pi.image_base);

	/* the identity table leaves the description alone (compare field by field:
	 * struct padding is not defined) */
	{
		uint64_t f[2] = { 0, 100 }, t[2] = { 0, 100 };
		struct kgenome_offmap id = { f, t, 2, E.n, E.n };
		ei2 = ei;
		kgenome_elf_info_remap(&ei2, &id);
		CK(ei2.phoff == ei.phoff && ei2.shoff == ei.shoff);
		CK(ei2.sec[2].file_off == ei.sec[2].file_off && ei2.sec[2].file_size == ei.sec[2].file_size);
	}
	/* the sentinels survive a remap */
	ei2 = ei;
	ei2.phoff = KGENOME_NA;
	ei2.shoff = KGENOME_BROKEN;
	shift.from_end = E.n; shift.to_end = E.n + 0x10u;
	kgenome_elf_info_remap(&ei2, &shift);
	CK(ei2.phoff == KGENOME_NA && ei2.shoff == KGENOME_BROKEN);
}

/* ---- the ELF predicates and readers ------------------------------------------ */

static void t_elf_small(void)
{
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	uint64_t off = 99;
	struct kgenome_elf_seg g;

	hk_elf(&E, 1, 0, 0);
	CK(parse_elf(&E, &ei, &o));

	CK(kgenome_elf_seg_is_load(&ei.seg[0]));
	CK(kgenome_elf_seg_is_code(&ei.seg[0]));
	/* .text: PROGBITS + EXEC is code, no other section here is */
	CK(kgenome_elf_sec_is_code(&ei.sec[1]));
	CK(!kgenome_elf_sec_is_code(&ei.sec[0]));
	CK(!kgenome_elf_sec_is_code(&ei.sec[2]));
	CK(!kgenome_elf_sec_is_code(&ei.sec[4]));

	/* extents are clipped to the object and report the offset */
	CK(kgenome_elf_sec_extent(&ei.sec[1], E.n, &off) == 32 && off == E.text);
	CK(kgenome_elf_sec_extent(&ei.sec[1], E.text + 10u, &off) == 10 && off == E.text);
	CK(kgenome_elf_sec_extent(&ei.sec[1], E.text, &off) == 0);
	CK(kgenome_elf_sec_extent(&ei.sec[1], 0, &off) == 0);
	CK(kgenome_elf_seg_extent(&ei.seg[0], E.n, &off) == E.n && off == 0);
	CK(kgenome_elf_seg_extent(&ei.seg[0], 5, &off) == 5);
	g = ei.seg[0];
	g.file_off = UINT64_MAX - 3u;
	g.file_size = 100;
	CK(kgenome_elf_seg_extent(&g, E.n, &off) == 0 && off == UINT64_MAX - 3u);
	g.file_off = 4;
	g.file_size = UINT64_MAX;
	CK(kgenome_elf_seg_extent(&g, 10, &off) == 6);
	/* a segment of another type, and one with no file half, is not a load */
	g = ei.seg[0];
	g.type = 6;
	CK(!kgenome_elf_seg_is_load(&g) && !kgenome_elf_seg_is_code(&g));
	g = ei.seg[0];
	g.file_size = 0;
	CK(!kgenome_elf_seg_is_load(&g));
	g = ei.seg[0];
	g.perm = KGENOME_PERM_R | KGENOME_PERM_W;
	CK(kgenome_elf_seg_is_load(&g) && !kgenome_elf_seg_is_code(&g));

	/* load_at_off / va_to_off */
	CK(kgenome_elf_load_at_off(&ei, 0) == &ei.seg[0]);
	CK(kgenome_elf_load_at_off(&ei, E.n - 1u) == &ei.seg[0]);
	CK(kgenome_elf_load_at_off(&ei, E.n) == NULL);
	CK(kgenome_elf_load_at_off(&ei, UINT64_MAX) == NULL);
	CK(kgenome_elf_va_to_off(&ei, 0x400000u + E.text, 4, &off) == 1 && off == E.text);
	CK(kgenome_elf_va_to_off(&ei, 0x400000u + E.n - 4u, 4, &off) == 1 && off == E.n - 4u);
	/* an extent that runs past the file half is refused, not clipped */
	CK(kgenome_elf_va_to_off(&ei, 0x400000u + E.n - 4u, 5, &off) == 0);
	CK(kgenome_elf_va_to_off(&ei, 0x400000u, UINT64_MAX, &off) == 0);
	CK(kgenome_elf_va_to_off(&ei, 0x400000u + E.n, 0, &off) == 0);
	CK(kgenome_elf_va_to_off(&ei, UINT64_MAX, 1, &off) == 0);
	CK(kgenome_elf_va_to_off(&ei, 0x3fffffu, 1, &off) == 0);
	/* an overflowing segment (vaddr near the top, huge file size) is no address */
	ei.seg[0].mem_addr = UINT64_MAX - 7u;
	ei.seg[0].file_size = 64;
	CK(kgenome_elf_va_to_off(&ei, UINT64_MAX - 7u, 8, &off) == 1);
	CK(kgenome_elf_va_to_off(&ei, UINT64_MAX - 7u, 9, &off) == 1);   /* 9 <= 64 file bytes */
	CK(kgenome_elf_va_to_off(&ei, UINT64_MAX, 1, &off) == 1);   /* last byte of the segment's file half */
	CK(kgenome_elf_va_to_off(&ei, 5, 1, &off) == 0);

	CK(kgenome_elf_sniff(kof_buf_make(E.b, E.n)) == 1);
	CK(kgenome_elf_sniff(kof_buf_make(E.b, 3)) == 0);
	CK(kgenome_elf_sniff(kof_buf_make(E.b, 0)) == 0);
	CK(kgenome_elf_sniff(kof_buf_make(NULL, 0)) == 0);
	CK(kgenome_elf_sniff(kof_buf_make(P.b, 64)) == 0);
}

static void t_elf_symbols(void)
{
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_elf_symtab t;
	struct kgenome_elf_symbol s;
	unsigned c;

	for (c = 0; c < 4; c++) {
		int is64 = (int)(c & 1u), be = (int)(c >> 1);
		kof_buf f;

		hk_elf(&E, is64, be, 1);
		f = kof_buf_make(E.b, E.n);
		CK(parse_elf(&E, &ei, &o));
		memset(&t, 0xaa, sizeof t);
		CK(kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_BEST, &t) == 1);
		CK(t.off == E.symtab && t.n == 4 && t.n_decl == 4);
		CK(t.str == E.strtab && t.strn == 18);
		CK(t.recsize == (is64 ? 24u : 16u));
		CK(t.elf64 == is64 && t.be == be && t.origin == 1);
		/* FULL is the same one; DYN has none in this object */
		CK(kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_FULL, &t) == 1 && t.n == 4);
		CK(kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_DYN, &t) == 0);
		CK(t.off == 0 && t.n == 0);

		CK(kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_BEST, &t) == 1);
		CK(kgenome_elf_symbol_at(f, &t, 0, &s) == 1 && s.value == 0 && s.shndx == 0);
		CK(kgenome_elf_symbol_at(f, &t, 1, &s) == 1);
		CK(s.nameoff == 1 && s.shndx == 1 && s.info == 0x12 && s.size == 6);
		CK(s.value == 0x400000u + E.text);
		CK(kgenome_elf_symbol_at(f, &t, 2, &s) == 1 && s.nameoff == 6 && s.shndx == 0);
		CK(kgenome_elf_symbol_at(f, &t, 3, &s) == 1 && s.value == 0x400000u + E.text + 10u);
		/* the buffer ends inside the record: refused, and the walk ends */
		{
			kof_buf cut = kof_buf_make(E.b, E.symtab + 3u * t.recsize + t.recsize - 1u);
			CK(kgenome_elf_symbol_at(cut, &t, 3, &s) == 0);
			CK(kgenome_elf_symbol_at(cut, &t, 2, &s) == 1);
		}
		CK(kgenome_elf_symbol_at(f, &t, 1000000, &s) == 0);
		/* a clipped view reports what the FILE holds and what the header CLAIMS */
		{
			kof_buf cut = kof_buf_make(E.b, E.symtab + 2u * t.recsize + 5u);
			CK(kgenome_elf_symtab_of(cut, &ei, KGENOME_ELF_SYMTAB_BEST, &t) == 1);
			CK(t.n == 2 && t.n_decl == 4);
		}
		/* NULL arguments */
		CK(kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_BEST, NULL) == 0);
		CK(kgenome_elf_symtab_of(f, NULL, KGENOME_ELF_SYMTAB_BEST, &t) == 0);
		CK(kgenome_elf_symtab_of(kof_buf_make(NULL, 0), &ei, KGENOME_ELF_SYMTAB_BEST, &t) == 0);
		CK(t.off == 0 && t.n == 0);
		CK(kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_BEST, &t) == 1);
		CK(kgenome_elf_symbol_at(f, NULL, 0, &s) == 0);
		CK(kgenome_elf_symbol_at(f, &t, 0, NULL) == 0);
		memset(&t, 0, sizeof t);
		CK(kgenome_elf_symbol_at(f, &t, 0, &s) == 0);   /* no table: nothing to read */
	}
}

/* An index whose byte offset wraps the 64-bit address space must not land on a
 * record of the table. The repro is for the product's i * recsize. */
static int symbol_wrap_case(void *arg)
{
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_elf_symtab t;
	struct kgenome_elf_symbol s;
	kof_buf f;
	uint64_t i;

	(void)arg;
	hk_elf(&E, 1, 0, 1);
	f = kof_buf_make(E.b, E.n);
	if (!parse_elf(&E, &ei, &o) ||
	    !kgenome_elf_symtab_of(f, &ei, KGENOME_ELF_SYMTAB_BEST, &t))
		return 2;
	/* 24 * i == 2^64 + 32 (mod 2^64): the byte offset of record 1, plus 8 */
	i = (UINT64_MAX / 24u) + 1u;
	while ((i * 24u) != 32u && i < (UINT64_MAX / 24u) + 4u)
		i++;
	if (kgenome_elf_symbol_at(f, &t, i, &s) != 0)
		return 1;
	/* and the plain "last index": i*24 == -24 reads the record BEFORE the table */
	return kgenome_elf_symbol_at(f, &t, UINT64_MAX, &s) == 0 ? 0 : 1;
}

static void t_symbol_index_wrap(void)
{
	int sig = 0;
	enum hk_result r = hk_isolated(symbol_wrap_case, NULL, 5, &sig);

	CK(r == HK_OK);   /* kgenome_elf_symbol_at accepts an index whose i*recsize wraps and returns a record of the table */
}

static void t_reloc_in(void)
{
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_elf_relocs rt;
	const struct kgenome_elf_reloc *r;
	kof_buf f;

	hk_elf(&E, 1, 0, 1);
	f = kof_buf_make(E.b, E.n);
	CK(parse_elf(&E, &ei, &o));
	memset(&rt, 0, sizeof rt);
	CK(kgenome_elf_reloc_table(f, &ei, KGENOME_ELF_RELOC_CODE, &rt) == 2);
	CK(rt.n == 2 && rt.v);
	/* call at text+3 (a rel32 hole of 4 bytes): any instruction covering it */
	r = kgenome_elf_reloc_in(&rt, E.text + 2u, 5);
	CK(r && r->where == E.text + 3u && r->call);
	CK(kgenome_elf_reloc_in(&rt, E.text + 3u, 1) == r);
	CK(kgenome_elf_reloc_in(&rt, E.text + 3u, 0) == NULL);      /* empty window */
	CK(kgenome_elf_reloc_in(&rt, E.text, 3) == NULL);           /* ends before it */
	CK(kgenome_elf_reloc_in(&rt, E.text + 7u, 4) == NULL);
	CK(kgenome_elf_reloc_in(&rt, UINT64_MAX, 255) == NULL);     /* at + len wraps */
	CK(kgenome_elf_reloc_in(&rt, UINT64_MAX - 1u, 4) == NULL);
	CK(kgenome_elf_reloc_in(&rt, 0, 10) == NULL);
	CK(kgenome_elf_reloc_in(NULL, 0, 4) == NULL);
	/* the data kind is a separate request; asking for it alone yields no call */
	kgenome_elf_reloc_table_free(&rt);
	CK(rt.v == NULL && rt.n == 0);
	kgenome_elf_reloc_table_free(&rt);          /* idempotent */
	CK(rt.v == NULL && rt.n == 0);
	CK(kgenome_elf_reloc_in(&rt, E.text + 3u, 4) == NULL);
}

/* ---- the PE predicates ------------------------------------------------------- */

static void t_pe_small(void)
{
	static struct kgenome_pe_info pi;
	struct kgenome_obj o;
	uint64_t off = 77;
	kof_buf f;
	struct kgenome_pe_imptab t;
	char buf[8];
	uint32_t i;

	hk_pe(&P, 1);
	f = kof_buf_make(P.b, P.n);
	CK(parse_pe(&P, &pi, &o));
	CK(kgenome_obj_pe(&o) == &pi);
	CK(kgenome_obj_elf(&o) == (const void *)&pi);
	CK(kgenome_pe_sniff(f) == 1);
	CK(kgenome_pe_sniff(kof_buf_make(P.b, 0x3f)) == 0);
	CK(kgenome_pe_sniff(kof_buf_make(P.b, P.lfanew + 3u)) == 0);
	CK(kgenome_pe_sniff(kof_buf_make(P.b, P.lfanew + 4u)) == 1);
	CK(kgenome_pe_sniff(kof_buf_make(NULL, 0)) == 0);
	CK(kgenome_pe_sniff(kof_buf_make(E.b, 64)) == 0);
	{
		uint8_t c[0x100];
		memcpy(c, P.b, sizeof c);
		hk_w(c + 0x3c, 0xffffffffu, 4, 0);
		CK(kgenome_pe_sniff(kof_buf_make(c, sizeof c)) == 0);
		hk_w(c + 0x3c, 0xfffffffcu, 4, 0);
		CK(kgenome_pe_sniff(kof_buf_make(c, sizeof c)) == 0);
	}

	CK(!kgenome_pe_is_mapped(NULL));
	CK(!kgenome_pe_is_mapped(&pi));
	pi.layout = KGENOME_PE_LAYOUT_MAPPED;
	CK(kgenome_pe_is_mapped(&pi));
	pi.layout = KGENOME_PE_LAYOUT_FILE;

	CK(kgenome_pe_sec_perm(0) == 0);
	CK(kgenome_pe_sec_perm(0x20000000u) == KGENOME_PE_PERM_X);
	CK(kgenome_pe_sec_perm(0x40000000u) == KGENOME_PE_PERM_R);
	CK(kgenome_pe_sec_perm(0x80000000u) == KGENOME_PE_PERM_W);
	CK(kgenome_pe_sec_perm(0xe0000000u) == (KGENOME_PE_PERM_X | KGENOME_PE_PERM_W | KGENOME_PE_PERM_R));
	CK(kgenome_pe_sec_perm(0x0000ffffu) == 0);
	CK(kgenome_pe_sec_perm(0xffffffffu) == 7);

	CK(kgenome_pe_sec_is_code(&pi.sec[0]));
	CK(!kgenome_pe_sec_is_code(&pi.sec[1]));
	CK(!kgenome_pe_sec_is_code(&pi.sec[2]));

	CK(kgenome_pe_sec_extent(&pi.sec[0], P.n, &off) == 0x200 && off == P.text_off);
	CK(kgenome_pe_sec_extent(&pi.sec[0], P.text_off + 7u, &off) == 7);
	CK(kgenome_pe_sec_extent(&pi.sec[0], 0, &off) == 0);
	CK(kgenome_pe_sec_extent(&pi.sec[0], P.text_off, &off) == 0);

	CK(kgenome_pe_sec_at_off(&pi, P.text_off) == &pi.sec[0]);
	CK(kgenome_pe_sec_at_off(&pi, P.text_off + 0x1ff) == &pi.sec[0]);
	CK(kgenome_pe_sec_at_off(&pi, P.text_off + 0x200) == &pi.sec[1]);
	CK(kgenome_pe_sec_at_off(&pi, P.reloc_off + 0x1ff) == &pi.sec[2]);
	CK(kgenome_pe_sec_at_off(&pi, P.reloc_off + 0x200) == NULL);
	CK(kgenome_pe_sec_at_off(&pi, 0) == NULL);
	CK(kgenome_pe_sec_at_off(&pi, UINT64_MAX) == NULL);

	/* rva_to_off (inline) over the same table */
	CK(kgenome_pe_rva_to_off(&pi, 0x1000) == P.text_off);
	CK(kgenome_pe_rva_to_off(&pi, 0x11ff) == P.text_off + 0x1ff);
	CK(kgenome_pe_rva_to_off(&pi, 0x1200) == KGENOME_BROKEN);
	CK(kgenome_pe_rva_to_off(&pi, 0x500) == KGENOME_BROKEN);
	CK(kgenome_pe_rva_to_off(&pi, UINT64_MAX) == KGENOME_BROKEN);
	CK(kgenome_pe_rva_to_off(NULL, 0) == KGENOME_BROKEN);
	pi.layout = KGENOME_PE_LAYOUT_MAPPED;
	CK(kgenome_pe_rva_to_off(&pi, 0x3fff) == 0x3fff);
	CK(kgenome_pe_rva_to_off(&pi, pi.size_of_image) == KGENOME_BROKEN);
	pi.layout = KGENOME_PE_LAYOUT_FILE;

	/* imp_name: the import's name, bounded by the destination */
	memset(&t, 0, sizeof t);
	kgenome_pe_imptab_build(f, &pi, &t);
	CK(t.n == 3 && t.n_dll == 2 && t.status == KGENOME_OK);
	CK(kgenome_pe_imptab_is_of(&t, f));
	CK(!kgenome_pe_imptab_is_of(&t, kof_buf_make(P.b, P.n - 1u)));
	CK(!kgenome_pe_imptab_is_of(NULL, f));
	CK(kgenome_pe_imp_name(f, &t.v[0], buf, sizeof buf) == 7);          /* "ExitPro" */
	CK(!strcmp(buf, "ExitPro"));
	CK(kgenome_pe_imp_name(f, &t.v[0], buf, 1) == 0 && buf[0] == 0);
	CK(kgenome_pe_imp_name(f, &t.v[0], buf, 0) == 0);
	CK(kgenome_pe_imp_name(f, &t.v[1], buf, sizeof buf) == 0);          /* by ordinal */
	CK(kgenome_pe_imp_name(f, NULL, buf, sizeof buf) == 0 && buf[0] == 0);
	CK(kgenome_pe_imp_name(kof_buf_make(P.b, 4), &t.v[0], buf, sizeof buf) == 0);
	for (i = 0; i < t.n; i++)
		CK(t.v[i].dll < t.n_dll);
	kgenome_pe_imptab_free(&t);
	CK(t.v == NULL && t.n == 0 && t.dll == NULL);
	kgenome_pe_imptab_free(&t);         /* again: nothing left to free */
	kgenome_pe_imptab_free(NULL);
}

/* ---- the CLR vocabulary and claims -------------------------------------------- */

static uint64_t id_rva(const void *u, uint64_t rva)
{
	(void)u;
	return rva;
}

static void build_clr(uint8_t *b, size_t n)
{
	/* CLI header at 0; metadata root at 0x100: BSJB, v1.1, 12-byte version,
	 * 2 streams (#~ at 0x140 len 0x10, #Strings at 0x150 len 8). */
	uint8_t *m = b + 0x100;

	memset(b, 0, n);
	hk_w(b, 72, 4, 0);
	hk_w(b + 8, 0x100, 4, 0);
	hk_w(b + 12, 0x80, 4, 0);
	hk_w(b + 24, 0x180, 4, 0);          /* resources */
	hk_w(b + 28, 0x20, 4, 0);
	memcpy(m, "BSJB", 4);
	hk_w(m + 4, 1, 2, 0); hk_w(m + 6, 1, 2, 0);
	hk_w(m + 12, 12, 4, 0);
	memcpy(m + 16, "v4.0.30319", 11);
	hk_w(m + 28, 0, 2, 0);
	hk_w(m + 30, 2, 2, 0);
	hk_w(m + 32, 0x40, 4, 0); hk_w(m + 36, 0x10, 4, 0); memcpy(m + 40, "#~", 3);
	hk_w(m + 44, 0x50, 4, 0); hk_w(m + 48, 8, 4, 0); memcpy(m + 52, "#Strings", 9);
}

static void t_clr(void)
{
	static uint8_t b[0x200];
	struct kgenome_clr_meta m;
	struct kof_range r[KGENOME_CLR_CLAIM_MAX + 2];
	struct kof_rlist l;
	uint32_t n, i;

	build_clr(b, sizeof b);
	CK(kgenome_clr_read(kof_buf_make(b, sizeof b), 0, id_rva, NULL, &m) == 1);
	CK(kgenome_clr_present(&m));
	CK(m.root_off == 0x100 && m.tables.off == 0x140 && m.tables.len == 0x10);
	CK(m.strings.off == 0x150 && m.strings.len == 8);
	CK(m.streams == 2 && m.streams_read == 2 && !strcmp(m.version, "v4.0.30319"));
	CK(m.res_off == 0x180 && m.res_len == 0x20);
	CK(!kgenome_clr_present(NULL));
	memset(&m.root_off, 0, sizeof m.root_off);
	CK(!kgenome_clr_present(&m));
	CK(kgenome_clr_read(kof_buf_make(b, sizeof b), 0, id_rva, NULL, &m) == 1);

	/* claims: every region a stream holds, in layout order, bounded by cap */
	memset(r, 0, sizeof r);
	n = kgenome_clr_claims(&m, r, KGENOME_CLR_CLAIM_MAX);
	CK(n == 4);     /* root, tables, strings, resources */
	for (i = 1; i < n; i++)
		CK(r[i - 1].off <= r[i].off);
	CK(kgenome_clr_claims(&m, r, 0) == 0);
	CK(kgenome_clr_claims(&m, r, 2) == 2);
	CK(kgenome_clr_claims(&m, NULL, 4) == 0);
	CK(kgenome_clr_claims(NULL, r, 4) == 0);
	{
		struct kgenome_clr_meta none;
		memset(&none, 0, sizeof none);
		CK(kgenome_clr_claims(&none, r, 4) == 0);
	}

	/* add_ranges takes a mask of regions and the object's size, and the list's cap
	 * is the caller's buffer */
	{
		struct kof_range buf[16];
		struct kof_range tiny[1];

		kof_rl_init(&l, buf, 16);
		kgenome_clr_add_ranges(&m, 0, &l, sizeof b);
		CK(l.n == 0);
		kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, &l, sizeof b);
		CK(l.n >= 3 && l.n <= 16);
		for (i = 0; i < l.n; i++)
			CK(l.v[i].off + l.v[i].len <= sizeof b);
		kof_rl_init(&l, buf, 16);
		kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, &l, 0x150);   /* a smaller object */
		for (i = 0; i < l.n; i++)
			CK(l.v[i].off + l.v[i].len <= 0x150);
		kof_rl_init(&l, tiny, 1);
		kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, &l, sizeof b);
		CK(l.n == 1);                       /* full list: no write past it */
		kof_rl_init(&l, NULL, 0);
		kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, &l, sizeof b);
		CK(l.n == 0);
		kof_rl_init(&l, buf, 16);
		kgenome_clr_add_ranges(NULL, KGENOME_SCAN_CLR_CLAIMED, &l, 10);
		CK(l.n == 0);
	}

	/* names */
	{
		static const uint32_t bits[] = { KGENOME_SCAN_CLR_HEADER, KGENOME_SCAN_CLR_TABLES,
			KGENOME_SCAN_CLR_STRINGS, KGENOME_SCAN_CLR_US, KGENOME_SCAN_CLR_BLOB,
			KGENOME_SCAN_CLR_RESOURCE };
		unsigned j, k;
		for (j = 0; j < 6; j++) {
			const char *nm = kgenome_clr_region_name(bits[j]);
			CK(nm && nm[0]);
			for (k = 0; k < j; k++)
				CK(strcmp(nm, kgenome_clr_region_name(bits[k])) != 0);
		}
	}
	for (i = 0; i < KGENOME_CLR_ANOM_COUNT; i++) {
		const char *s = kgenome_clr_anomaly_name(i);
		CK(s && s[0]);
	}
	CK(kgenome_clr_region_name(0) == NULL);
	CK(kgenome_clr_region_name(KGENOME_SCAN_CLR_HEADER | KGENOME_SCAN_CLR_US) == NULL);
	CK(kgenome_clr_region_name(0xffffffffu) == NULL);
	CK(!strcmp(kgenome_clr_anomaly_name(KGENOME_CLR_ANOM_COUNT), "?"));
	CK(!strcmp(kgenome_clr_anomaly_name(0xffffffffu), "?"));
}

/* ---- funcs ------------------------------------------------------------------- */

static void t_funcs(void)
{
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint64_t ent[3];
	kof_buf f;

	hk_elf(&E, 1, 0, 0);
	f = kof_buf_make(E.b, E.n);
	CK(parse_elf(&E, &ei, &o));

	/* no symbols (stripped): functions from entries cut the code segment */
	ent[0] = E.text; ent[1] = E.text + 10u; ent[2] = E.text + 14u;
	kgenome_elf_funcs_from_entries(f, &ei, E.text, ent, 3, &fs);
	CK(fs.status == KGENOME_OK && fs.n == 3);
	CK(fs.v[0].off == E.text && fs.v[0].len == 10);
	CK(fs.v[1].off == E.text + 10u && fs.v[1].len == 4);
	CK(fs.v[2].off == E.text + 14u);
	CK(fs.v[2].off + fs.v[2].len <= E.n);
	kgenome_funcs_free(&fs);
	CK(fs.v == NULL && fs.n == 0);
	kgenome_funcs_free(&fs);                /* idempotent */

	/* the entry point is added when the list lacks it; an entry outside the code
	 * segment is an entry of nothing */
	ent[0] = E.text + 10u; ent[1] = E.n + 100u; ent[2] = 1u << 30;
	kgenome_elf_funcs_from_entries(f, &ei, E.text, ent, 3, &fs);
	CK(fs.n == 2 && fs.v[0].off == E.text && fs.v[1].off == E.text + 10u);
	kgenome_funcs_free(&fs);

	/* degenerate requests */
	kgenome_elf_funcs_from_entries(f, &ei, E.text, ent, 0, &fs);
	CK(fs.n == 0 && fs.v == NULL);
	kgenome_elf_funcs_from_entries(kof_buf_make(NULL, 0), &ei, E.text, ent, 3, &fs);
	CK(fs.n == 0 && fs.v == NULL);
	kgenome_elf_funcs_from_entries(f, NULL, E.text, ent, 3, &fs);
	CK(fs.n == 0 && fs.v == NULL);
	kgenome_elf_funcs_from_entries(f, &ei, KGENOME_BROKEN, ent, 3, &fs);
	CK(fs.status == KGENOME_OK);
	kgenome_funcs_free(&fs);
	/* unsorted and duplicate entries: memory-safe, and every function stays in the file */
	ent[0] = E.text + 14u; ent[1] = E.text; ent[2] = E.text;
	kgenome_elf_funcs_from_entries(f, &ei, E.text + 5u, ent, 3, &fs);
	{
		uint32_t i;
		for (i = 0; i < fs.n; i++)
			CK(fs.v[i].off + fs.v[i].len <= E.n);
	}
	kgenome_funcs_free(&fs);
}

/* ---- the ledger's note --------------------------------------------------------- */

static void t_ledger_note(void)
{
	struct kgenome_ledger l;
	int s;

	kgenome_ledger_init(&l, 100);
	CK(l.status == KGENOME_OK);
	kgenome_ledger_note(&l, KGENOME_OK);
	CK(l.status == KGENOME_OK);
	kgenome_ledger_note(&l, KGENOME_TRUNCATED);
	CK(l.status == KGENOME_TRUNCATED);
	kgenome_ledger_note(&l, KGENOME_OK);        /* never improves */
	CK(l.status == KGENOME_TRUNCATED);
	kgenome_ledger_note(&l, KGENOME_NOMEM);
	CK(l.status == KGENOME_NOMEM);
	kgenome_ledger_note(&l, KGENOME_OVER_BUDGET);   /* never worsens to a lesser one */
	CK(l.status == KGENOME_NOMEM);
	/* a note moves neither the count nor the limit */
	CK(l.used == 0 && l.peak == 0 && l.limit == 100);
	for (s = KGENOME_OK; s <= KGENOME_NOMEM; s++) {
		kgenome_ledger_init(&l, 0);
		kgenome_ledger_note(&l, (enum kgenome_status)s);
		CK(l.status == (enum kgenome_status)s);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	t_image_addr();
	t_offmap_at();
	t_info_offsets();
	t_elf_small();
	t_elf_symbols();
	t_symbol_index_wrap();
	t_reloc_in();
	t_pe_small();
	t_clr();
	t_funcs();
	t_ledger_note();
	printf("api_image: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
