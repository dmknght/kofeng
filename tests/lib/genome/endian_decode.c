/*
 * endian_decode - which analyses of a big-endian object are endian-aware, pinned.
 *
 * The canonical form (endian.h) is for what is read as BYTES: patterns, block hashes,
 * string clusters. Everything that DECODES an instruction or READS a table reads the
 * order from the object, and must give the same answer for a big-endian object as for
 * its little-endian twin. The twin is endian_kit.h's, written field by field.
 *
 *   1  decoders      MIPS and ARM instruction words: the decoder given the big-endian bytes
 *                    with be set answers what it gives for the little-endian bytes
 *   2  the cursor    a walk over the code of a big-endian object equals the walk over its
 *                    twin, instruction for instruction - for MIPS, ARM BE32, and ARM BE8,
 *                    whose DATA is big-endian and whose instructions are not
 *   3  the parse     header, segments, sections, e_flags, the symbol table, the
 *                    relocation table and the function extents of a big-endian object equal
 *                    its twin's
 *   4  e_flags       the field the parse keeps for the byte order of the code
 */

#include <kgenome.h>
#include <celllysis/decode.h>

#include "endian_kit.h"

static int same_insn(const struct kgenome_cell_insn *a, const struct kgenome_cell_insn *b)
{
	return a->op == b->op && a->len == b->len && a->n_op == b->n_op && a->cond == b->cond &&
	       a->flags == b->flags && a->wmask == b->wmask && a->at == b->at &&
	       a->at_va == b->at_va && a->target == b->target && a->target_va == b->target_va &&
	       !memcmp(a->o, b->o, sizeof a->o);
}

static void words(unsigned arch, const char *name)
{
	struct hk_rng r = { 0x853c49e6748fea9bull + arch };
	unsigned i, differ = 0, decoded = 0;

	for (i = 0; i < 300000; i++) {
		uint32_t w = (uint32_t)hk_next(&r);
		uint8_t lb[8], bb[8];
		struct kgenome_cell_insn a, b;
		uint32_t na, nb;

		hk_w(lb, w, 4, 0);
		hk_w(bb, w, 4, 1);
		memset(lb + 4, 0, 4);
		memset(bb + 4, 0, 4);
		memset(&a, 0, sizeof a);
		memset(&b, 0, sizeof b);
		na = kgenome_cell_decode(arch, 0, lb, 8, 0x1000, &a);
		nb = kgenome_cell_decode(arch, 1, bb, 8, 0x1000, &b);
		if (na != nb || (na && !same_insn(&a, &b)))
			differ++;
		decoded += na != 0;
	}
	if (differ) {
		printf("  FAIL %s: %u of 300000 words decode differently\n", name, differ);
		hk_fails++;
	}
	CK(decoded > 1000);     /* the loop decoded something, so it compared something */
}

struct parsed {
	struct kgenome_elf_info info;
	struct kgenome_obj g;
};

static int parse(const uint8_t *b, uint32_t n, struct parsed *p)
{
	memset(p, 0, sizeof *p);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), &p->info, &p->g))
		return 0;
	p->g.file_header = &p->info;
	return 1;
}

/* Walk `count` instructions from the start of .text; fill `out`. */
static unsigned walk(const struct parsed *p, const uint8_t *b, uint32_t n, uint64_t at,
		     struct kgenome_cell_insn *out, unsigned count, int force_be)
{
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k;
	unsigned i;

	kgenome_cell_space_init(&sp, &p->g, b, n);
	if (force_be >= 0) {
		sp.be = force_be;
		sp.code_le = 0;
	}
	memset(&k, 0, sizeof k);
	CK(kgenome_cell_seek(&k, at, 0));
	for (i = 0; i < count; i++) {
		memset(&out[i], 0, sizeof out[i]);
		if (!kgenome_cell_next(&k, &sp, &out[i]))
			break;
	}
	return i;
}

static void cursor(void)
{
	/* mips32, arm-be32, arm-be8, and a 64-bit MIPS */
	static const unsigned pick[] = { 0, 3, 4, 6 };
	unsigned a;

	for (a = 0; a < sizeof pick / sizeof pick[0]; a++) {
		const struct ek_arch *ar = &ek_archs[pick[a]];
		struct ek_obj be, le;
		struct parsed pb, pl;
		struct kgenome_cell_insn wb[24], wl[24], wrong[24];
		unsigned nb, nl, i, mismatched = 0;

		ek_build(&be, ar, 1, ar->unit != 0);
		ek_build(&le, ar, 0, 1);
		CK(parse(be.b, be.n, &pb));
		CK(parse(le.b, le.n, &pl));
		CK(kgenome_obj_big_endian(&pb.g));
		nb = walk(&pb, be.b, be.n, be.text, wb, 24, -1);
		nl = walk(&pl, le.b, le.n, le.text, wl, 24, -1);
		CK(nb == nl);
		CK(nb >= 8);
		for (i = 0; i < nb && i < nl; i++)
			if (!same_insn(&wb[i], &wl[i]))
				mismatched++;
		if (mismatched) {
			printf("  FAIL %s: %u of %u instructions differ from the twin's\n", ar->name,
			       mismatched, nb);
			hk_fails++;
		}
		/* ARM BE8 is the case the order of the DATA gets wrong: read big-endian, the
		 * little-endian instruction words come out as other instructions. */
		if (pick[a] == 6) {
			unsigned bad = 0;

			CK(kgenome_obj_code_little_endian(&pb.g));
			nb = walk(&pb, be.b, be.n, be.text, wrong, 24, 1);
			for (i = 0; i < nb && i < nl; i++)
				bad += !same_insn(&wrong[i], &wl[i]);
			CK(bad > 0 || nb != nl);
		} else {
			CK(!kgenome_obj_code_little_endian(&pb.g) || ar->machine != 40);
		}
	}
}

static int same_sec(const struct kgenome_elf_sec *a, const struct kgenome_elf_sec *b)
{
	return a->file_off == b->file_off && a->file_size == b->file_size &&
	       a->mem_addr == b->mem_addr && a->flags == b->flags && a->type == b->type &&
	       a->name_hash == b->name_hash && !strcmp(a->name, b->name);
}

static void parse_equal(void)
{
	unsigned k;

	for (k = 0; k < EK_NARCH; k++) {
		const struct ek_arch *a = &ek_archs[k];
		struct ek_obj be, le;
		struct parsed pb, pl;
		struct kgenome_elf_symtab tb, tl;
		struct kgenome_elf_relocs rb, rl;
		struct kgenome_func_set fb, fl;
		uint64_t i;
		uint32_t s;

		ek_build(&be, a, 1, a->unit != 0);
		ek_build(&le, a, 0, 1);
		CK(parse(be.b, be.n, &pb));
		CK(parse(le.b, le.n, &pl));
		CK(pb.info.elf_data == KGENOME_ELFDATA_BE && pl.info.elf_data == KGENOME_ELFDATA_LE);
		CK(pb.info.e_machine == pl.info.e_machine && pb.info.e_type == pl.info.e_type);
		CK(pb.info.e_flags == a->flags && pl.info.e_flags == a->flags);
		CK(pb.info.entry_addr == pl.info.entry_addr);
		CK(pb.info.phoff == pl.info.phoff && pb.info.phnum == pl.info.phnum);
		CK(pb.info.shoff == pl.info.shoff && pb.info.shnum == pl.info.shnum);
		CK(pb.info.seg_count == pl.info.seg_count && pb.info.sec_count == pl.info.sec_count);
		CK(pb.info.anomalies == pl.info.anomalies);
		CK(pb.g.arch == pl.g.arch && pb.g.entry_off == pl.g.entry_off);
		for (s = 0; s < pb.info.seg_count; s++)
			CK(pb.info.seg[s].file_off == pl.info.seg[s].file_off &&
			   pb.info.seg[s].file_size == pl.info.seg[s].file_size &&
			   pb.info.seg[s].mem_addr == pl.info.seg[s].mem_addr &&
			   pb.info.seg[s].type == pl.info.seg[s].type);
		for (s = 0; s < pb.info.sec_count; s++)
			CK(same_sec(&pb.info.sec[s], &pl.info.sec[s]));
		/* the symbol table: every record, in the order and width of the file */
		CK(kgenome_elf_symtab_of(kof_buf_make(be.b, be.n), &pb.info, KGENOME_ELF_SYMTAB_FULL, &tb));
		CK(kgenome_elf_symtab_of(kof_buf_make(le.b, le.n), &pl.info, KGENOME_ELF_SYMTAB_FULL, &tl));
		CK(tb.n == tl.n && tb.n == 5 && tb.elf64 == tl.elf64 && tb.recsize == tl.recsize);
		for (i = 0; i < tb.n && i < tl.n; i++) {
			struct kgenome_elf_symbol sb, sl;

			CK(kgenome_elf_symbol_at(kof_buf_make(be.b, be.n), &tb, i, &sb));
			CK(kgenome_elf_symbol_at(kof_buf_make(le.b, le.n), &tl, i, &sl));
			CK(sb.value == sl.value && sb.size == sl.size && sb.nameoff == sl.nameoff &&
			   sb.shndx == sl.shndx && sb.info == sl.info && sb.other == sl.other);
		}
		/* relocations (the RELA section; MIPS64's split r_info is the one layout that
		 * is not the class's) */
		memset(&rb, 0, sizeof rb);
		memset(&rl, 0, sizeof rl);
		(void)kgenome_elf_reloc_table(kof_buf_make(be.b, be.n), &pb.info,
					      KGENOME_ELF_RELOC_CODE | KGENOME_ELF_RELOC_DATA, &rb);
		(void)kgenome_elf_reloc_table(kof_buf_make(le.b, le.n), &pl.info,
					      KGENOME_ELF_RELOC_CODE | KGENOME_ELF_RELOC_DATA, &rl);
		CK(rb.n == rl.n && rb.n == 3);
		for (i = 0; i < rb.n && i < rl.n; i++)
			CK(rb.v[i].where == rl.v[i].where && rb.v[i].type == rl.v[i].type &&
			   rb.v[i].addend == rl.v[i].addend && rb.v[i].defined == rl.v[i].defined);
		kgenome_elf_reloc_table_free(&rb);
		kgenome_elf_reloc_table_free(&rl);
		/* the function extents */
		memset(&fb, 0, sizeof fb);
		memset(&fl, 0, sizeof fl);
		kgenome_funcs_build(KGENOME_FMT_ELF, be.b, be.n, &pb.info, &fb);
		kgenome_funcs_build(KGENOME_FMT_ELF, le.b, le.n, &pl.info, &fl);
		CK(fb.n == fl.n);
		for (s = 0; s < fb.n && s < fl.n; s++)
			CK(fb.v[s].off == fl.v[s].off && fb.v[s].len == fl.v[s].len);
		kgenome_funcs_free(&fb);
		kgenome_funcs_free(&fl);
	}
}

int main(void)
{
	words(KGENOME_ARCH_MIPS, "mips");
	words(KGENOME_ARCH_ARM, "arm");
	cursor();
	parse_equal();
	if (hk_fails) {
		printf("endian_decode: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("endian_decode: ok\n");
	return 0;
}
