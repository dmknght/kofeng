/*
 * sig_hex.c - exercises hex patterns and offset-anchored comparison.
 *
 * Detects nothing anybody cares about. It exists so that every part of the hex path
 * is wired up on every build: the compiler parses each syntax form, the packer
 * carries the compiled program, the loader validates it, and the matcher walks it
 * against real objects.
 *
 * The two ways of asking are both here on purpose, because they are the ones that
 * are easy to confuse:
 *
 *   kof_find_str      search a declared region for the pattern
 *   kof_find_str_at   compare at one offset the module worked out
 *
 * The second is what a packer or an infector signature is actually made of - the
 * bytes at the entry point - and it is the one that cannot be written as a
 * declaration, because the entry point is a property of the file.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);
KOF_TARGET_RANGE(loaded, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);

/* Wildcards: the displacement of a call is different in every binary, the opcode
 * and what follows it are not. */
KOF_DEFINE_HEXSTR(call_then_pop, "E8 ?? ?? ?? ?? 5D");

/* A nibble wildcard, and a gap: two fixed parts a few bytes apart. */
KOF_DEFINE_HEXSTR(spaced, "48 8? [2-8] 48 8B");

/* Alternatives: one instruction, several encodings. */
KOF_DEFINE_HEXSTR(jcc, "( 74 | 75 | EB ) ?? 48");

/* The ELF header itself, which every object of this format has at offset zero -
 * so it proves an anchored compare works rather than proving anything about
 * malware. */
KOF_DEFINE_HEXSTR(elf_magic64, "7F 45 4C 46 02 01 01");

KOF_DEFINE_SCAN
{
	const struct kof_elf_info *elf = kof_elf(ctx);

	if (!elf->valid)
		return;

	/* Anchored: one comparison at a computed offset, no search at all. */
	if (kof_find_str_at(0, elf_magic64) &&
	    kof_find_str_multi(code, call_then_pop, spaced, jcc) >= 2)
		KOF_SCAN_MATCH("Test.HexCombo", KOF_LVL_INFECT);

	/* A window rather than a point: the same call sequence somewhere in the
	 * first part of the entry point's code, when there is an entry point. */
	if (ctx->entry_off != KOF_NA && ctx->entry_off != KOF_BROKEN &&
	    kof_find_str_in(ctx->entry_off, 256, call_then_pop))
		KOF_SCAN_MATCH("Test.HexAtEntry", KOF_LVL_SUSPECT);

	/* Scalars read directly, the way a structural check reads them. */
	if (kof_in_obj(0, 4) && kof_u32(0) == 0x464c457fu &&
	    kof_find_str(loaded, spaced))
		KOF_SCAN_MATCH("Test.HexSpaced", KOF_LVL_SUSPECT);
}
