/*
 * genotype - instruction decoders, one per architecture.
 *
 * WHY A DIRECTORY AND NOT A FILE. The emulator, the code sweep and the
 * cross-reference pass each decode instructions for an architecture, and the
 * architectures share nothing but the questions asked of them: what is the
 * length, what is it, what are its operands, how does control leave it. Their
 * encodings, register files and operand models differ in kind (x86 has prefixes
 * and variable length, ARM has fixed words and conditions on everything), so
 * each gets its own target with its own tables, its own generator and its own
 * instruction structure, and this header is only what they have in common.
 *
 *   x86/    x86 and x86-64; tables generated from a reference decoder.
 *   arm32/  32-bit ARM: ARM state and Thumb state; hand-written rows with the
 *           bit pattern beside each, and an index the code derives from them.
 *   arm64/  AArch64; a decode tree held as data, with a derived first-level index.
 *
 * An architecture is added by adding a directory. Nothing outside it changes,
 * which is the test of whether the split is real.
 */
#ifndef KGENOME_GENOTYPE_H
#define KGENOME_GENOTYPE_H

/*
 * What a decode attempt came to is the lib's one status (kgenome_status.h):
 * OK, TRUNCATED (the bytes might be an instruction, but the buffer ends first)
 * and - under its decoder name - INVALID, which is BAD_INPUT: these bytes are
 * not an instruction. The decoders kept saying INVALID; it is an alias and not a
 * seventh value, so a status means one thing in every part of the lib.
 */
#include "../kgenome_status.h"
#define KGENOME_INVALID KGENOME_BAD_INPUT

/* The architectures this tree has (or will have) a decoder for. */
enum kgenome_gt_arch {
	KGENOME_GT_ARCH_X86_32,
	KGENOME_GT_ARCH_X86_64
};

#endif /* KGENOME_GENOTYPE_H */
