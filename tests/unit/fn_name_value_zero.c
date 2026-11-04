/*
 * fn_name_value_zero.c - isolates the exact drop point of the finding reported as
 * "ELF-SIZE0-NAME-GAP" (pe_elf_fixtures/INVENTORY_AND_PLAN.md group 24).
 *
 * ROOT CAUSE, confirmed by this test AND by a real differential build (gcc -c, with and
 * without -ffunction-sections, on the same source: /mnt/games/normtest/pe_elf_fixtures/
 * gen/scratch/g24/t24_{plain,funcsec}.o): the property that makes a function's name
 * unreachable is st_value == 0 (any symbol whose address IS the object's base address,
 * typically the first/only symbol of its own section in an ET_REL object - the normal
 * shape of a Linux kernel module), NOT symbol SIZE == 0 as the earlier report guessed.
 *
 * kof_sym_name_at (sym_any.c) uses value 0 as the sentinel for "kof_func_name was given
 * no symbol at all" (kof_func_name passes f->off when f is NULL). A real symbol whose
 * st_value is genuinely 0 is indistinguishable from that sentinel, so its name can never
 * be found - regardless of whether its size is 0, and regardless of ELF vs PE, since
 * kof_func_name/kof_sym_name_at are format-agnostic. The two records below have the SAME
 * size (0, matching the SIZE0 label the earlier report used) and differ ONLY in value,
 * which isolates the cause to the value==0 check and rules out size.
 *
 * Coverage gap this closes: no existing test under tests/unit or tests/lib/genome calls
 * kof_func_name or kof_sym_name_at with a record whose value is 0 (grep, 2026-11-04);
 * tests/unit/code_notes.c only exercises the `blk == NULL` (no symbol block at all) path.
 * Reason the gap existed: (a) line executed (the `if (!value) return;` guard runs on
 * every lookup) but (b) never exercised with the boundary input that flips it - a real
 * record whose value is exactly 0.
 *
 * No defect-marker comment was placed above the sink in sym_any.c: this package's mandate is
 * tests only (owner, merge-gate message), not an engine edit. Reported instead as
 * ELF-VALUE0-NAME-GAP (M) in the audit report; the coordinator decides the comment/fix.
 */
#include <stdio.h>
#include <string.h>

#include <kgenome.h>
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../../libkofeng/analyzers/parsers/binaries/sym_pool.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* A minimal two-record KSYM block, built the one way every producer builds one
 * (kof_symw_*, sym_pool.h) so this test cannot drift from the real encoding. */
static uint32_t build_blk(uint8_t *out, uint32_t cap, uint64_t v0, uint64_t v1)
{
	struct kof_symw w;
	struct kof_symrec r;

	kof_symw_begin(&w, out, cap, 2u, 0u);
	memset(&r, 0, sizeof r);
	r.type = 2u; r.bind = 1u; r.shndx = 1u; r.value = v0; r.size = 0u;
	r.name = "func_at_value_zero"; r.name_len = (uint32_t)strlen(r.name);
	CK(kof_symw_put(&w, &r));
	r.value = v1; r.name = "func_at_value_0x40"; r.name_len = (uint32_t)strlen(r.name);
	CK(kof_symw_put(&w, &r));
	return kof_symw_end(&w);
}

static void t_value_zero_is_unreachable(void)
{
	uint8_t blk[512];
	uint32_t n = build_blk(blk, sizeof blk, 0u, 0x40u);
	struct kgenome_func f0, f1;
	char out[64];

	memset(&f0, 0, sizeof f0); f0.off = 0x1000u; f0.value = 0u;    f0.shndx = 1u;
	memset(&f1, 0, sizeof f1); f1.off = 0x1040u; f1.value = 0x40u; f1.shndx = 1u;

	/* CONTROL: a record whose value is nonzero is found - the block and the
	 * records in it are good, so a failure of the next check is the value==0
	 * guard and nothing else. */
	CK(kof_func_name(&f1, blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "func_at_value_0x40"));

	/* RED: the same lookup, same block, a record that is genuinely there at
	 * value 0 - kof_func_name falls back to fcn_<off> instead of finding it.
	 * On the CURRENT code this fails (returns 0, out == "fcn_00001000"); the
	 * defect is the `if (!value) return;` sentinel in kof_sym_name_at treating
	 * a real address-0 symbol the same as "no symbol was asked for". */
	CK(kof_func_name(&f0, blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "func_at_value_zero"));
}

/* Differential control redone purely in terms of the KSYM/func-table contract,
 * independent of any ELF parsing: SIZE is NOT the variable. Both records above
 * already have size 0 (sy.size == 0 in the real ELF case too - see t24_plain.o);
 * only f.value differs, and only the f.value == 0 case breaks. This directly
 * separates "ELF-SIZE0-NAME-GAP" (the earlier, Inference-labelled guess) from
 * what the real cause is. */
static void t_size_is_not_the_variable(void)
{
	uint8_t blk[512];
	uint32_t n = build_blk(blk, sizeof blk, 0x80u, 0x40u);  /* neither at 0 now */
	struct kgenome_func f0, f1;
	char out[64];

	memset(&f0, 0, sizeof f0); f0.off = 0x1080u; f0.value = 0x80u; f0.shndx = 1u;
	memset(&f1, 0, sizeof f1); f1.off = 0x1040u; f1.value = 0x40u; f1.shndx = 1u;
	/* Both are size-0 symbols (see build_blk: r.size is never set non-zero) and
	 * BOTH are found when neither value is 0 - size-0 alone is not the gap. */
	CK(kof_func_name(&f0, blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "func_at_value_zero"));
	CK(kof_func_name(&f1, blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "func_at_value_0x40"));
}

/* Direct calls to kof_sym_name_at itself (merge 133's pointer-signature change), not routed through
 * kof_func_name: the NULL-pointer path as its own code path, and the shndx filter distinguishing two
 * records that share a value. */
static void t_sym_name_at_direct(void)
{
	uint8_t blk[512];
	uint32_t n = build_blk(blk, sizeof blk, 0u, 0u);  /* two records, BOTH at value 0, different shndx needed */
	char out[64];
	uint64_t v = 0u;

	/* NULL value: never reachable via kof_func_name (always passes &f->value when f is non-NULL), so this
	 * exercises the "no value to look up" path directly. */
	out[0] = 'X'; out[1] = 0;
	kof_sym_name_at(blk, n, NULL, -1, out, sizeof out);
	CK(out[0] == 0);

	/* Both records in build_blk share value 0 here; the second record's shndx is also 1 (build_blk always
	 * writes shndx=1 implicitly via r.shndx=1u for the first put, but the second put in build_blk does not
	 * reset r.shndx, so it stays 1 for both - an honest same-value, same-shndx collision). shndx=-1 (any
	 * section) must find SOME record deterministically (the first one the block holds), not crash or loop. */
	kof_sym_name_at(blk, n, &v, -1, out, sizeof out);
	CK(out[0] != 0);
	CK(!strcmp(out, "func_at_value_zero"));   /* first record in insertion order wins, documented here */

	/* A shndx that matches no record at this value: empty, not a wrong match. */
	out[0] = 'X'; out[1] = 0;
	kof_sym_name_at(blk, n, &v, 99, out, sizeof out);
	CK(out[0] == 0);
}

int main(void)
{
	t_value_zero_is_unreachable();
	t_size_is_not_the_variable();
	t_sym_name_at_direct();
	printf("fn_name_value_zero: %d failure(s)\n", fails);
	return fails != 0;
}
