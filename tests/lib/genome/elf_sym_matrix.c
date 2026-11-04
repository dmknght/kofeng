/*
 * elf_sym_matrix - two ELF symbol-table hostile shapes named in the "Symbol-route audit, groups
 * 23-28" follow-up (STATUS.md, 2026-11-04: "Symbol matrix extension (dynsym-alone, import/export
 * table corruption, strip variants, deliberately wrong st_value placement): NOT done") that are
 * not already covered by tests/lib/genome/fntab_cov.c's t_symtab_oracle (6000 random cases) or
 * t_merge_rows (synthetic kgenome_func records, not real ELF bytes):
 *
 *   DEGENERATE STRIP   a .symtab that EXISTS and holds several entries, every one of them
 *                       STT_NOTYPE size 0 - the shape `strip --strip-unneeded` (not `--strip-all`,
 *                       which drops the section outright and IS already covered by fntab_cov.c's
 *                       "no .symtab at all" rows) leaves behind: local-symbol entries zeroed in
 *                       place but the section kept. Distinct from fntab_cov.c's t_with_walk_cases
 *                       "symtab with an OBJECT only" retry test (info 0x11, STT_OBJECT, a WRONG
 *                       TYPE), which proves the retry fires on a type mismatch, not on this exact
 *                       degenerate-strip shape (STT_NOTYPE, not STT_OBJECT).
 *
 *   NESTED FUNC        two real .symtab FUNC entries where the second's st_value lands strictly
 *                       inside the first's declared [value, value+size) - self-referential in the
 *                       sense fntab_merge.c's own comment uses ("an exact body and a label inside
 *                       it of the SAME source: dropped, not counted"), already unit-tested at
 *                       t_merge_rows with SYNTHETIC kgenome_func records (mkf()). This exercises
 *                       the same rule end to end from genuine ELF bytes - kgenome_elf_symbol_at's
 *                       real decode feeding kgenome_fntab_symtab feeding kgenome_fntab_merge -
 *                       which is a different code path up to the merge boundary and was not
 *                       exercised by the synthetic test or by t_symtab_oracle (whose oracle
 *                       (sym_expect) does not itself drop nested bodies, so a random case landing
 *                       on this shape would have disagreed with the oracle rather than confirmed
 *                       the merge rule on purpose).
 *
 * Both run kgenome_fntab_symtab (the real strategy) directly on a file written by fntab_kit.h's
 * elf_build, the same writer t_symtab_oracle differentials against; the nested case also runs the
 * result through kgenome_fntab_merge, the real merge function (not a copy).
 */
#include "fntab_kit.h"

static uint8_t TX[0x100];

/* STT_NOTYPE (low nibble 0 of st_info), GLOBAL bind (high nibble 1): info 0x10. size 0 on every
 * entry. A real `strip --strip-unneeded` leaves such entries in .symtab rather than removing the
 * section (that is `strip --strip-all`, already covered as "no .symtab" elsewhere). */
static void t_degenerate_strip(void)
{
	struct sym notype[4] = {
		{ "a", 0x400000u + TEXT_OFF,        0, 0x10, 1 },
		{ "b", 0x400000u + TEXT_OFF + 0x10, 0, 0x10, 1 },
		{ "c", 0x400000u + TEXT_OFF + 0x20, 0, 0x10, 1 },
		{ "d", 0x400000u + TEXT_OFF + 0x30, 0, 0x10, 1 },
	};
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	uint32_t n;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX);
	in.sections = 1; in.dyn = 0; in.sym = notype; in.nsym = 4;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));

	/* direct call to the strategy: every entry is read (no crash, no out-of-bounds), none kept -
	 * STT_NOTYPE with size 0 fails sym_expect's own "FUNC, IFUNC, or NOTYPE-with-a-size" test
	 * (fntab_cov.c's sym_expect, line ~1267) for the identical reason the real strategy excludes
	 * it (genotype/image/funcs.c: a size-0 NOTYPE names no function, only a label). */
	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	CK(l.n == 0 && l.status == KGENOME_OK);
	kgenome_fntab_list_free(&l);

	/* end to end: the orchestrator's retry (fntab_build_elf.c) must set symtab_empty from this REAL
	 * degenerate .symtab (not from a section that is absent or empty) and fall through to the WALK
	 * case, since there is no .dynsym here either. */
	{
		struct kgenome_func_set fs;

		kgenome_diag_funcs_with_walk(&o, B, n, NULL, &fs);
		CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
		kgenome_funcs_free(&fs);
	}
}

/* Two FUNC entries, same source (.symtab): A at [TEXT_OFF+0x10, TEXT_OFF+0x50) size 0x40, B's
 * st_value landing strictly inside A's range (TEXT_OFF+0x20, 0x10 into A's 0x40 - "points at
 * itself plus some offset into its own declared size" read as: a FUNC the table also names a
 * second, later FUNC that starts inside). Expect: kgenome_fntab_symtab reads BOTH exactly as
 * declared (it does no overlap filtering of its own - that is the merge's job, per fntab.h's
 * "two sources meet" comment), then kgenome_fntab_merge drops the nested one and counts it. */
static uint8_t TXN[0x200];

static void t_nested_func_same_source(void)
{
	struct sym nest[2] = {
		{ "outer", 0x400000u + TEXT_OFF + 0x10, 0x40, 0x12, 1 },
		{ "inner", 0x400000u + TEXT_OFF + 0x20, 0x08, 0x12, 1 },
	};
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	struct kgenome_func_set s;
	uint32_t n;

	/* a text section of 0x200 bytes (content unused: neither call here decodes it), so every
	 * offset below sits well inside the PT_LOAD segment kgenome_elf_va_to_off bounds against -
	 * the real strategy checks the segment, not just the file, and a text_n as small as
	 * x86_text()'s fixed 0x40 bytes would make the segment end BEFORE "outer"'s declared end
	 * (TEXT_OFF+0x10+0x40 = TEXT_OFF+0x50 > TEXT_OFF+0x40) and the symbol would be silently
	 * skipped as out-of-segment instead of exercising the nested-overlap path this test wants. */
	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TXN; in.text_n = sizeof TXN;
	in.sections = 1; in.dyn = 0; in.sym = nest; in.nsym = 2;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));

	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	/* the strategy itself keeps both - it has no overlap rule, only the merge does */
	CK(l.n == 2 && l.status == KGENOME_OK);
	CK(l.v[0].off == TEXT_OFF + 0x10 && l.v[0].len == 0x40);
	CK(l.v[1].off == TEXT_OFF + 0x20 && l.v[1].len == 0x08);

	memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	/* n_extra stays 0 here: fntab_merge.c's `if (!(p->source & e->source)) out->n_extra++;` only
	 * counts a nested label when it comes from a DIFFERENT source than the body holding it (that is
	 * the ALREADY-tested t_merge_rows case, "of ANOTHER source: dropped, counted"); a SAME-source
	 * nested label (this test: both entries are S_SYM) is dropped WITHOUT counting - "of the SAME
	 * source: dropped, not counted (it was always so)", per the comment one line above that test. */
	CK(s.n == 1 && s.v[0].off == TEXT_OFF + 0x10 && s.v[0].len == 0x40 && s.n_extra == 0);
	kgenome_funcs_free(&s);

	/* the boundary variant: inner is ONE byte, starting on A's LAST byte (off 0x4f, A's range being
	 * [0x10,0x50)) so inner's OWN end (0x50) lands exactly on A's end - still "e->off + e->len <= pend"
	 * (fntab_merge.c), the inside case, not the overlap-past-the-end case the control below is. A
	 * same-size-8 inner here (this test's first draft) runs 7 bytes PAST A's end and is a different
	 * shape - two same-rank bodies that overlap without one containing the other, which the merge
	 * keeps BOTH of (fntab_merge.c's own "neither holds the other" branch) - so it had to shrink to
	 * stay a genuine nested/contained case and not silently turn into that other shape. */
	nest[1].value = 0x400000u + TEXT_OFF + 0x10 + 0x3fu;
	nest[1].size = 1;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	CK(l.n == 2);
	memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 1 && s.n_extra == 0);
	kgenome_funcs_free(&s);

	/* control: inner starts ONE byte past A's end - a sibling, not nested, both kept */
	nest[1].value = 0x400000u + TEXT_OFF + 0x10 + 0x40u;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	CK(l.n == 2);
	memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 2 && s.n_extra == 0);
	kgenome_funcs_free(&s);
}

int main(void)
{
	t_degenerate_strip();
	t_nested_func_same_source();
	printf("elf_sym_matrix: %d failure(s) of %lu check(s)\n", fails, checks);
	return fails != 0;
}
