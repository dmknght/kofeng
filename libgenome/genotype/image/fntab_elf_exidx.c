/*
 * fntab_elf_exidx.c - the EHABI index strategy of the ELF function table (32-bit ARM): .ARM.exidx, the table the ARM unwinder searches by PC. The survey of the Bazaar
 * corpus (meta_survey/bazaar.txt, 2026-11-16) found it in 688 of 1918 ARM ELF files, which carry an .eh_frame far less often than x86-64 does.
 *
 * THE FORMAT (ARM IHI 0038, "Exception Handling ABI for the ARM Architecture", section 6): the table is a run of 8-byte rows sorted by address. Word 0 of a row is a
 * prel31 offset - bits 0..30, sign-extended from bit 30, relative to the address of the word itself - to the START of a function, bit 31 clear; word 1 is
 * EXIDX_CANTUNWIND (1), an inline unwind description (bit 31 set) or a prel31 offset to the table entry. A row covers the code from its start to the next row's start: the
 * table states no end, so this strategy gives STARTS ONLY (source EXIDX) and the ends step closes each at the next start of the table.
 * Found by section (SHT_ARM_EXIDX 0x70000001, by the type and not the name) or, with no section table, by its segment PT_ARM_EXIDX (0x70000001).
 *
 * WHAT A ROW MAY BE THAT IS NOT A FUNCTION: the linker ends the table with a CANTUNWIND row at the end of the code (the start of no function). Such a start lies at the end
 * of the code extent or past it, where the ends step drops it (n_extra); one that lands inside the extent is kept as what the table says: a declared START, no body
 * (round 4: EHABI 5.3 gives leaf functions no row, so the next row is not an end).
 *
 * HOSTILE INPUT: a row with bit 31 of word 0 set is refused and counted (out->n_bad); a start that is not in an executable, file-backed segment or that lies in a stub
 * section is refused and counted; the table is read as far as the file holds it (the loop is bounded by its size over 8); rows out of order are taken as they are (the
 * merge sorts); the list's own cap is reported (P_CAP).
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/elf_types.h>
#include "elf_image.h"
#include "fntab_private.h"

#define SHT_ARM_EXIDX 0x70000001u
#define PT_ARM_EXIDX 0x70000001u
#define EM_ARM 40u

void kgenome_fntab_exidx(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out)
{
	uint64_t at = 0, n = 0, va = 0, i;
	uint32_t k;
	int be;

	if (!file.p || !e || !e->valid || !out || e->e_machine != EM_ARM || e->e_type == KGENOME_ELF_REL)
		return;
	if (kgenome_fntab_elf_section(e, SHT_ARM_EXIDX, NULL, &k)) {
		at = e->sec[k].file_off;
		n = e->sec[k].file_size;
		va = e->sec[k].mem_addr;
	} else {
		for (k = 0; k < e->seg_count && k < KGENOME_ELF_MAX_SEGMENTS; k++)
			if (e->seg[k].type == PT_ARM_EXIDX && e->seg[k].file_size) {
				at = e->seg[k].file_off;
				n = e->seg[k].file_size;
				va = e->seg[k].mem_addr;
				break;
			}
	}
	if (!n || at >= file.n)
		return;
	if (n > file.n - at)
		n = file.n - at;
	be = e->elf_data == KGENOME_ELFDATA_BE;
	for (i = 0; i + 8u <= n; i += 8u) {
		uint32_t w0;
		uint64_t fva, off;
		struct kgenome_func f;

		if (!kof_rd_u32(file, at + i, be, &w0))
			break;
		if (w0 & 0x80000000u) {
			out->n_bad++;
			continue;
		}
		/* prel31: sign-extend bit 30, add the address of the word; an ELF32's addresses are 32 bits */
		fva = (va + i + (uint64_t)((int64_t)(int32_t)(w0 << 1) >> 1)) & 0xffffffffu;
		memset(&f, 0, sizeof f);
		if (fva & 1u) {
			fva &= ~(uint64_t)1u;
			f.isa_mode = KGENOME_FN_ISA_THUMB;
		}
		if (!kgenome_fntab_elf_code_va(e, fva, &off)) {
			out->n_bad++;
			continue;
		}
		f.off = off;
		f.source = KGENOME_FN_S_EXIDX;
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}
