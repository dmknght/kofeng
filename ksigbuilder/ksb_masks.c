/*
 * ksb_masks.c - --arch-mask and --subtype-mask: a mask from names.
 */

#include "ksb.h"

#include <kofmod/elf.h>      /* the ELF region names a range may be built from */
#include <kofmod/pe.h>       /* and the PE ones */

/*
 * --arch-mask "KGENOME_ARCH_X86|KGENOME_ARCH_X86_64" -> the bit mask, on stdout.
 *
 * Here rather than in a shell wrapper because a shell cannot include
 * kofsig.h, and the copy it kept instead was wrong twice over: it matched
 * substrings, so KGENOME_ARCH_X86 - a prefix of KGENOME_ARCH_X86_64 - set both bits,
 * and it listed eight of the eleven architectures. A shell that asks this
 * program cannot fall behind the header this program compiles against.
 *
 * The mask has one bit per enum value, so KGENOME_ARCH_ANY is bit 0 and is a real
 * choice rather than the absence of one: a rule may target objects that have no
 * architecture.
 */
int ksb_arch_mask_main(int argc, char **argv)
{
	uint32_t mask = 0;
	const char *p;
	char tok[64];

	if (argc != 3) {
		fprintf(stderr, "usage: %s --arch-mask "
				"\"KOF_ARCH_A|KOF_ARCH_B\"\n", argv[0]);
		return 2;
	}
	for (p = argv[2]; *p; ) {
		size_t n = 0;
		uint8_t val;

		while (*p == ' ' || *p == '\t' || *p == '|')
			p++;
		while (*p && *p != '|' && *p != ' ' && *p != '\t') {
			if (n + 1 < sizeof tok)
				tok[n++] = *p;
			p++;
		}
		tok[n] = 0;
		if (!n)
			continue;
		if (!kof_arch_from_name(tok, &val)) {
			fprintf(stderr, "ksigbuilder: \"%s\" is not a known "
					"architecture. Known:\n", tok);
#define X_SHOW(name, v, word) fprintf(stderr, "    %s\n", #name);
			KOF_ARCH_LIST(X_SHOW)
#undef X_SHOW
			return 1;
		}
		mask |= 1u << val;
	}
	if (!mask) {
		fprintf(stderr, "ksigbuilder: --arch-mask names no architecture\n");
		return 1;
	}
	printf("%lu\n", (unsigned long)mask);
	return 0;
}

/*
 * --subtype-mask "KGENOME_ELF_EXEC|KGENOME_ELF_DYN" -> "<mask> <ELF|PE>" on stdout.
 *
 * Two formats' subtypes share one number space on purpose - KGENOME_ELF_REL and
 * KGENOME_PE_DLL are both 1 - so which format was named is part of the answer, and
 * naming both at once is an error rather than a union. ksigbuilder --module takes
 * the format word back and checks it against what the source targets.
 *
 * Here for the same reason as --arch-mask: the shell kept its own copies of
 * both lists and matched them as substrings, which is a bug waiting for a
 * subtype whose name is a prefix of another.
 */
int ksb_subtype_mask_main(int argc, char **argv)
{
	uint32_t mask = 0;
	int saw_elf = 0, saw_pe = 0;
	const char *p;
	char tok[64];

	if (argc != 3) {
		fprintf(stderr, "usage: %s --subtype-mask "
				"\"KOF_ELF_A|KOF_ELF_B\"\n", argv[0]);
		return 2;
	}
	for (p = argv[2]; *p; ) {
		size_t n = 0;
		int hit = 0;

		while (*p == ' ' || *p == '\t' || *p == '|')
			p++;
		while (*p && *p != '|' && *p != ' ' && *p != '\t') {
			if (n + 1 < sizeof tok)
				tok[n++] = *p;
			p++;
		}
		tok[n] = 0;
		if (!n)
			continue;
#define X_ELF(name, val)                                                     \
		if (!hit && strcmp(tok, #name) == 0)                         \
			{ mask |= 1u << (val); saw_elf = 1; hit = 1; }
		KOF_ELF_TYPE_LIST(X_ELF)
#undef X_ELF
#define X_PE(name, val)                                                      \
		if (!hit && strcmp(tok, #name) == 0)                         \
			{ mask |= 1u << (val); saw_pe = 1; hit = 1; }
		KOF_PE_IMAGE_LIST(X_PE)
#undef X_PE
		if (!hit) {
			fprintf(stderr, "ksigbuilder: \"%s\" is not a known "
					"subtype. Known:\n", tok);
#define X_SHOW(name, val) fprintf(stderr, "    %s\n", #name);
			KOF_ELF_TYPE_LIST(X_SHOW)
			KOF_PE_IMAGE_LIST(X_SHOW)
#undef X_SHOW
			return 1;
		}
	}
	if (!mask) {
		fprintf(stderr, "ksigbuilder: --subtype-mask names no subtype\n");
		return 1;
	}
	if (saw_elf && saw_pe) {
		fprintf(stderr, "ksigbuilder: --subtype-mask mixes ELF and PE "
				"subtypes; their values collide\n");
		return 1;
	}
	printf("%lu %s\n", (unsigned long)mask, saw_elf ? "ELF" : "PE");
	return 0;
}
