/*
 * sig_endian_mips_00.c - a byte pattern cut from the LITTLE-endian build of a program, and nothing
 * else. It exists for the test that a big-endian object of the same program is
 * found through its normalised view and not without it (tests/unit/endian_view.c):
 * twelve instruction words, written in the order a little-endian MIPS object holds
 * them, in the code of an ELF built for that architecture only.
 *
 * It names its architecture so that the same bytes in an object of another one
 * - the test builds one - are not a detection.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_ARCH(KOF_ARCH_MIPS);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "EndianMips");

KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);

/* 12 words, little-endian */
KOF_DEFINE_HEXSTR(words, "84 62 BD 43 17 61 BD 42 7A 5F BD 41 CD 5D BD 40 50 5C BD 4F A3 5A BD 4E 36 59 BD 4D 99 57 BD 4C EC 55 BD 4B 7F 54 BD 4A C2 52 BD 49 55 51 BD 48");

KOF_DEFINE_SCAN
{
	if (kof_find_str(code, words))
		KOF_SCAN_INFECT("EndianMips");
}
