/*
 * disasm.h - ONE ENTRY: bytes and an architecture in, one instruction as text out.
 *
 * WHAT IT IS FOR. A viewer draws instructions and the engine's code analyses
 * walk them; neither should know which decoder an architecture has or how its
 * text is spelled. This is the one place that says: kgenome_disasm decodes the
 * instruction at `p`, spells it, and returns what a viewer needs as DATA - how
 * many bytes it took, the text, how control leaves it and where a direct branch
 * goes. The caller computes nothing of its own: the length is what to advance
 * by, the target is what to show, the status is whether to trust the text.
 *
 * WHAT IS SUPPORTED, AS MEASURED (tests/lib/genome/disasm_oracle.c, and the
 * numbers in the report that came with this entry). `kgenome_disasm_level`
 * answers by architecture:
 *
 *   x86, x86-64    KGENOME_DISASM_TEXT: every instruction the decoder has.
 *   ARM (A32)      KGENOME_DISASM_TEXT: the integer instruction set in ARM state;
 *                  coprocessor, VFP and Advanced SIMD words come back
 *                  KGENOME_UNSUPPORTED (".inst 0x...": right length, no mnemonic).
 *                  Thumb state is not spelled: a caller that knows the code is
 *                  Thumb must not ask (kgenome_disasm_level_obj says so for an
 *                  object whose entry point is Thumb).
 *   AArch64        KGENOME_DISASM_TEXT: the base integer set, branches, system,
 *                  loads and stores; scalar floating point, Advanced SIMD, SVE
 *                  and SME come back KGENOME_UNSUPPORTED.
 *   everything else KGENOME_DISASM_NONE: MIPS decodes (length and branch targets)
 *                  but its decoder keeps only what the sweeps ask, so there is
 *                  nothing to spell; PowerPC, RISC-V, SPARC and the rest have no
 *                  decoder at all. Asking anyway answers KGENOME_UNSUPPORTED, len 0.
 *
 * LENGTH. x86 is variable. ARM and AArch64 instructions are one aligned word, so
 * `len` is 4 (or `n` when fewer bytes are left) even for a word that is not an
 * instruction: the caller advances by it and the alignment survives data.
 * `align` is the instruction alignment of the architecture (1 for x86, 4 here).
 *
 * ADDRESSES. `va` is the address the instruction sits at, in whatever space the
 * caller shows (a file offset in kofexamine); `target` is in the same space.
 */
#ifndef KGENOME_DISASM_H
#define KGENOME_DISASM_H

#include <stddef.h>
#include <stdint.h>

#include <genotype/genotype.h>

struct kgenome_obj;
struct kgenome_x86_insn;        /* a caller that wants the decoded x86 instruction names it by pointer: genotype/x86/x86.h is not on this surface */

enum kgenome_disasm_level {
	KGENOME_DISASM_NONE = 0,        /* no text for this architecture */
	KGENOME_DISASM_TEXT = 1         /* text for the instructions in kgenome_disasm's list above */
};

/* The level for an architecture (enum kgenome_arch), by the architecture alone. */
unsigned kgenome_disasm_level(unsigned arch);

/* The level for an object: the architecture's, except for an ARM object whose code is Thumb. */
unsigned kgenome_disasm_level_obj(const struct kgenome_obj *obj);

/*
 * WHICH ARCHITECTURE TO READ AN OBJECT IN: its own when this entry has text for it, and otherwise x86, at
 * `bits` (32 or 64) - raw bytes with no header, and x86 objects whose width the reader may have changed, are
 * read as x86. Never KGENOME_ARCH_ANY: the answer is always an architecture kgenome_disasm can decode.
 */
unsigned kgenome_disasm_arch(const struct kgenome_obj *obj, unsigned bits);

/* The architecture's short word ("x86", "x64", "a32", "a64"), NULL when it has none. */
const char *kgenome_disasm_name(unsigned arch);

/* Instruction alignment in bytes: 1 for x86, 4 for ARM and AArch64, 1 for what has no text. */
unsigned kgenome_disasm_align(unsigned arch);

/* The longest instruction of the architecture, in bytes: a buffer of this size always holds one. */
unsigned kgenome_disasm_max_len(unsigned arch);

/* Is the code of this object big-endian (an ARM-BE object that is not BE8). */
int kgenome_disasm_code_be(const struct kgenome_obj *obj);

/* Enough for the text of one instruction. */
#define KGENOME_DISASM_TEXT_MAX 192u

struct kgenome_disasm_req {
	unsigned       arch;            /* enum kgenome_arch */
	int            be;              /* the code is big-endian (kgenome_disasm_code_be) */
	int            len_only;        /* only the length is wanted (a resynchronising walk): no text is made, `text` may be NULL; `status` is then OK for an instruction, BAD_INPUT for what is not one, TRUNCATED for too few bytes */
	const uint8_t *p;               /* the bytes at the instruction */
	size_t         n;               /* how many may be read */
	uint64_t       va;
	char          *text;            /* the caller's buffer, and its size */
	size_t         cap;
	/*
	 * OPTIONAL, x86 only: where to leave the decoded instruction. A caller that annotates x86 with the lib's own
	 * calls (kgenome_x86_cond_text) needs it, and would otherwise decode the bytes a second time. NULL: not wanted.
	 */
	struct kgenome_x86_insn *x86;
};

struct kgenome_disasm_res {
	enum kgenome_status status;     /* OK: the text is the instruction. UNSUPPORTED: it is one, not spelled. BAD_INPUT: not an instruction. TRUNCATED: too few bytes, or `cap` too small */
	uint32_t       len;             /* bytes to advance by; 0 only when nothing could be read or the architecture has no text */
	uint8_t        flow;            /* enum kgenome_gt_flow */
	uint8_t        has_target;      /* a direct branch: `target` is where it goes */
	uint64_t       target;
	uint8_t        has_x86;         /* req->x86 was given and holds the decoded instruction */
};

void kgenome_disasm(const struct kgenome_disasm_req *req, struct kgenome_disasm_res *res);

#endif /* KGENOME_DISASM_H */
