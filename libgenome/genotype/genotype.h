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
#ifndef KOF_GENOTYPE_H
#define KOF_GENOTYPE_H

/* What a decode attempt came to, the same for every architecture. */
enum gt_status {
	GT_OK = 0,
	GT_INVALID = 1,         /* these bytes are not an instruction              */
	GT_TRUNCATED = 2        /* they might be, but the buffer ends first        */
};

/* The architectures this tree has (or will have) a decoder for. */
enum gt_arch {
	GT_ARCH_X86_32,
	GT_ARCH_X86_64
};

#endif /* KOF_GENOTYPE_H */
