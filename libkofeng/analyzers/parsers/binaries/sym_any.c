/*
 * sym_any.c - the one place that decides WHICH symbol builder an object gets.
 *
 * ELF and PE each have their own, and both fill the single KSYM layout that
 * kofmod/kofsym.h fixes. The choice used to be made twice - once in the
 * scanner's content accessor and once in kofviewer - which is two places to
 * keep in step for a decision that has one right answer.
 */

#include <kofmod/kofsym.h>
#include "elf_sym.h"
#include "pe_sym.h"

uint32_t kof_syms_build(uint32_t format, const uint8_t *data, uint64_t data_n,
			const void *info, uint8_t *out, uint32_t cap)
{
	kof_buf b = kof_buf_make(data, data_n);

	if (!info || !out || cap < KOF_SYM_HDRLEN)
		return 0;
	if (format == KOF_FMT_ELF)
		return kof_elf_syms(b, info, out, cap);
	if (format == KOF_FMT_PE)
		return kof_pe_syms(b, info, out, cap);
	/* Any other format has no symbols to give, which a reader takes as a
	 * count of zero - the same answer a stripped ELF gives. */
	return 0;
}
