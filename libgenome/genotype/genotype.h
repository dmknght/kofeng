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
#include <stddef.h>
#include <stdint.h>

#include "../kgenome_status.h"
#define KGENOME_INVALID KGENOME_BAD_INPUT

/* The architectures this tree has (or will have) a decoder for. */
enum kgenome_gt_arch {
	KGENOME_GT_ARCH_X86_32,
	KGENOME_GT_ARCH_X86_64
};


/*
 * WHAT A FORMATTER ANSWERS BESIDES THE TEXT: how control leaves the instruction
 * and, for a direct branch, where it goes. One result struct for every
 * architecture's formatter (kgenome_arm32_format, kgenome_arm64_format), so the
 * one entry above them (celllysis/disasm.h) hands the caller the same record
 * whatever the architecture.
 *
 * `status` is KGENOME_OK when `text` is the instruction in full; UNSUPPORTED when
 * the bytes decode as an instruction of a space the formatter does not spell yet
 * (the text is then the word as data, ".inst 0x..."): the length is still right;
 * BAD_INPUT when they are not an instruction; TRUNCATED when `cap` was too small.
 * `target` is meaningful only when `has_target`: a direct branch's destination, in
 * the address space of the `pc` the caller passed. An indirect branch has none.
 */
enum kgenome_gt_flow {
	KGENOME_GT_FLOW_NEXT = 0,       /* falls through */
	KGENOME_GT_FLOW_JUMP,           /* unconditional branch */
	KGENOME_GT_FLOW_COND,           /* conditional branch */
	KGENOME_GT_FLOW_CALL,
	KGENOME_GT_FLOW_RET,
	KGENOME_GT_FLOW_TRAP            /* system call, breakpoint, undefined */
};

struct kgenome_gt_fmt_res {
	enum kgenome_status status;
	size_t   len;                   /* characters written, without the terminator */
	uint8_t  flow;                  /* enum kgenome_gt_flow */
	uint8_t  has_target;
	uint64_t target;
};

#endif /* KGENOME_GENOTYPE_H */
