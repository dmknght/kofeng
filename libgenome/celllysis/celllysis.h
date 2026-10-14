/*
 * celllysis.h - reading code without running it: THE API.
 *
 * Celllysis breaks a body of code open into its parts - instructions, the
 * values registers hold between them, the addresses that reach them - and
 * answers questions about those parts. It does not run anything: that is
 * phenotype's (libgenome/phenotype), which expresses the code in an environment.
 * What it reads is what genotype sequences: libgenome/genotype holds the decode
 * TABLES (x86 and x86-64, ARM32 in ARM and Thumb state, ARM64) and celllysis
 * turns what they find into facts. MIPS is the exception: its decoder is still
 * written straight into celllysis's form (decode_mips.c), recognising what the
 * analysis asks about and nothing more, and has no table of its own yet.
 *
 *     bytes -> genotype (decode) -> celllysis (translate, track, walk)
 *           -> the engine (nucleo: what a number or a name MEANS)
 *
 * THE DEPENDENCY RUNS ONE WAY. genotype knows nothing of celllysis, celllysis
 * knows nothing of the engine's objects, and the engine reaches all of it
 * through this header. What the engine alone knows - how a file offset becomes
 * an address in a PE or an ELF - arrives as a `struct kgenome_cell_space`, so this
 * library never includes a parser and can read a buffer that has no file.
 *
 * THE VOCABULARY IS kofmod/cell.h: struct kgenome_cell_insn, the opcode classes, the
 * operand kinds. A signature module reads the same form, so nothing is
 * translated between what the engine sees and what a rule sees.
 *
 * FOUR THINGS ARE HERE, and each is its own header so a user takes only what it
 * asks:
 *   decode.h       one instruction, in the one form (kgenome_cell_decode)
 *   cell_state.h   what the registers and the stack hold, from instructions
 *   this file      the address space, and the cursor that walks it
 *   xref.h         where an address comes from (separate: it needs no cursor)
 */
#ifndef KGENOME_CELLLYSIS_H
#define KGENOME_CELLLYSIS_H

#include <stdint.h>

/* The vocabulary, and with it KGENOME_BROKEN and KOF_ARCH_*. */
#include <celllysis/cell.h>
#include <genotype/image/image_addr.h>
#include "cell_state.h"
#include "decode.h"
#include "../kgenome_status.h"

/*
 * ---- THE ADDRESS SPACE ----------------------------------------------------
 *
 * The code is a buffer and the cursor walks it in OFFSETS, because that is what
 * every other accessor takes; a relative branch is computed in ADDRESSES. The
 * two are related by the object's layout, which only the object's parser knows,
 * so it is asked rather than assumed.
 *
 * A SEGMENT IS CONTIGUOUS IN BOTH SPACES, so inside one the conversion is a
 * single addition. The cursor keeps the segment its last answer came from and
 * asks again only on leaving it - MEASURED over a 12 MB subset, 1.3 million
 * conversions for 1.3 million instructions and all but a handful landed in the
 * segment of the one before.
 */
/* struct kgenome_image_seg (genotype/image/image_addr.h): the file offsets it covers,
 * [lo, hi), and the address minus offset across it. */

struct kgenome_cell_space {
	const uint8_t *base;    /* the bytes */
	uint64_t       size;
	unsigned       arch;    /* KOF_ARCH_* - which decoder */
	int            be;      /* big-endian object: the DATA order (ARM-BE, MIPS-BE) */
	void          *priv;    /* the owner's, handed back to the callbacks */
	/*
	 * The segment containing file offset `off`, or 0. A relocatable
	 * object has no load address and answers one segment spanning
	 * everything with delta 0: the file is the only coherent address
	 * space it has, and a branch computed in it still lands on a file
	 * offset.
	 */
	int      (*seg_at)(void *priv, uint64_t off, struct kgenome_image_seg *out);
	/* The file offset of an address, or KGENOME_BROKEN - for a target that is
	 * not in the segment the walk is in. */
	uint64_t (*off_of_va)(void *priv, uint64_t va);
	/* The code is little-endian although `be` is set (ARM BE8): 0, the
	 * default of every existing initialiser, means the code follows `be`.
	 * APPENDED, so no field above moved. */
	int      code_le;
	/*
	 * A DECODE THE OWNER ALREADY HOLDS, asked before the decoder runs. The owner
	 * of an object's decode product (the diagnose walk keeps one per object:
	 * diag_wrapper_walk.c) answers with the instruction at file offset `off`
	 * when it has decoded exactly that offset in this space, and 0 when it has
	 * not - "not held" and "does not decode" are both answered by the decoder
	 * that runs next, so a 0 is never a verdict. `va` is the address the cursor
	 * gave the offset and `left` the bytes that may be read (at most 16).
	 * The answer is field for field what kgenome_cell_decode would have written,
	 * `at` and `target` aside, which cell_fetch sets itself from its own cursor.
	 * NULL, the default of every existing initialiser, means: always decode.
	 * APPENDED, so no field above moved.
	 */
	uint32_t (*held)(void *priv, uint64_t off, uint64_t va, uint32_t left,
			 struct kgenome_cell_insn *out);
	void    *held_priv;
};

/*
 * ---- THE CURSOR -----------------------------------------------------------
 *
 * One per walk. A walk follows one run of code at a time, so the state is a
 * struct the caller owns and nothing is allocated - an allocation per walk
 * would be a handle in the module ABI for no gain.
 */
struct kgenome_cell_cur {
	uint64_t at;            /* the cursor, a file offset */
	struct kgenome_cell_state st;   /* what the walk knows: see cell_state.h */
	uint8_t  open;
	uint8_t  seg_ok;        /* `seg` has been established */
	/*
	 * INVALIDATED BY kgenome_cell_seek AND NOT BY COMPARING THE SPACE. The
	 * caller's space is usually a local, so the NEXT object's is very
	 * often at the same address as this one's - a pointer compare would
	 * say "same object" about a different file. Every walk starts with a
	 * seek, so clearing it there is sufficient and cannot be got wrong.
	 */
	struct kgenome_image_seg seg;
};

/*
 * Start a walk at `off`. `keep` carries the register map across the move, which
 * is what following a branch inside one walk needs; 0 starts it empty.
 */
int kgenome_cell_seek(struct kgenome_cell_cur *k, uint64_t off, int keep);

/*
 * Decode at the cursor, advance it, update the map. Answers 0 at the end of the
 * buffer or on bytes that do not decode, and leaves the cursor where it was.
 *
 * AN INDIRECT BRANCH IS RESOLVED FROM WHAT IS KNOWN, which is the difference
 * between decoding and pseudo-emulation: `jmp eax` has no target in its
 * encoding, and when the map holds eax - or the modelled stack holds what a
 * `ret` will take - the target IS known and saying so is not a guess.
 *
 * And on ARM a literal-pool load is rewritten as the MOV of the constant it is,
 * because the word is in the buffer and nothing about it is unknown.
 */
int kgenome_cell_next(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
		  struct kgenome_cell_insn *out);

/*
 * THE SAME WITHOUT THE MAP: decode at the cursor, translate, resolve a direct
 * target, advance - and nothing is learned from the instruction. For a caller
 * that keeps a state of its own (a function summary, a walk over the call graph)
 * and asks neither kgenome_cell_reg nor for an indirect branch's target, the map is
 * work it throws away: MEASURED, tracking was a third of the cost of a step.
 */
int kgenome_cell_step(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
		  struct kgenome_cell_insn *out);

/*
 * AN OBSERVER OF INSTRUCTIONS: what a reader of code hands each instruction to.
 * `in` is NULL for a byte that did not decode (the reader stepped over it).
 * Whoever reads the code - a cursor, a trace of an earlier walk - calls it the
 * same way, so a consumer (xref.h's kgenome_xref_feed) is written once and does not
 * know where the instructions came from.
 */
typedef void (*kgenome_cell_insn_fn)(void *user, const struct kgenome_cell_insn *in);

/* A register's constant, or 0 for "not knowable here" - a real answer. */
int kgenome_cell_reg(const struct kgenome_cell_cur *k, uint8_t r, uint64_t *out);

#endif /* KGENOME_CELLLYSIS_H */
