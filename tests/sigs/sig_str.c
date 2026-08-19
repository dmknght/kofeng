/*
 * sig_str.c - proves the byte access path.
 *
 * Where sig_entry_gt only reads scalar facts the host had already collected, this
 * one reaches into the object itself, which is the first time a module touches
 * untrusted bytes. Everything about that path is on the host side: the range is
 * clamped, an out of range read yields zero, and the search is one call rather
 * than a loop in the module.
 *
 * The pattern text never reaches the compiler. kof_find_str drops its literal
 * argument, and kofpat reads it out of this source at build time and emits the
 * compiled bytes under a name derived from the line number. So the readable form
 * stays here for whoever maintains it while the blob carries only bytes.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

/* Reads elf->sec_count, so it needs the ELF view and therefore exactly one
 * target: kof_elf() casts, and a cast needs a guaranteed format. */
KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "StrTest");

/*
 * A compiler comment lives in .comment, which carries no SHF_ALLOC and so is never
 * part of the process image. NOLOAD is exactly that set of sections and a small
 * fraction of the file - looking for a toolchain trace anywhere else is both slower
 * and more likely to be an accident.
 */
KOF_TARGET_RANGE(toolchain, KOF_SCAN_ELF_NOLOAD);
KOF_DEFINE_STR(gcc_comment, "GCC: (GNU)", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

/* Case folded on purpose, to exercise that path. Note this still matches the symbol
 * version strings in .dynstr, which are inside a loaded segment and therefore in
 * DATA - a known false positive kept here as a reminder that a region is not a
 * section. */
KOF_TARGET_RANGE(loaded_data, KOF_SCAN_ELF_DATA);
KOF_DEFINE_STR(glibc, "gLiBc", KOF_CASE_ICASE, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	const struct kof_elf_info *elf = kof_elf(ctx);

	/* Scalar checks first. If they fail nothing else is looked at, which is the
	 * ordering that matters even though the searches themselves already
	 * happened on the host side. */
	if (ctx->arch != KOF_ARCH_X86_64 || elf->sec_count == 0)
		return;

	if (kof_find_str(toolchain, gcc_comment))
		KOF_SCAN_INFECT("GccComment");

	/* Suspicion carries a reason, not a name. The host composes the string from
	 * the format and architecture it already knows plus this code. */
	if (kof_find_str(loaded_data, glibc))
		KOF_SCAN_SUSPECT("AnomCombo");
}
