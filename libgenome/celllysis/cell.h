/*
 * cell.h - one decoded instruction, in the form every architecture is read into.
 *
 * DEFINED BY libgenome (the instruction form is what kgenome analyses); the
 * engine re-exports it as <kofmod/cell.h> so a module sees the same type.
 *
 *
 * WHY THIS EXISTS, WHICH IS A MEASUREMENT AND NOT A PREFERENCE.
 *
 * A polymorphic file infector re-encodes its decryptor for every file it
 * infects. Sality is the one measured here: four samples, and the bytes at
 * their entry points share NOTHING -
 *
 *     f6c69cf28bd20faff20fbeed434684c7...
 *     6033d886c38d3d3d0c9fe60fc1c86a00...
 *     f6c2c4f7c0fa360e32eb020fcd750769...
 *     e800000000 5d 0f6ed5 0f7ed7 81c70c020000 57 b477 c3
 *
 * A byte signature taken from one of them names one of them. That is not a
 * limitation of the signature; it is what a byte signature IS against a
 * generator. The public write-ups say the same in plainer words: a signature
 * over a stream of bytes "or a stream of mnemonics" detects one GENERATION,
 * not the malware - so the industry writes detection CODE over the semantics
 * instead, and the ClamAV bytecode signature for Xpaj is a worked example of
 * exactly that: find a small anchor, then walk the disassembly, checking what
 * each instruction MEANS - an opcode class, an operand that is a register from
 * a set, a displacement inside the frame - and following the relative branches
 * that the junk between them ends with.
 *
 * None of that can be written against this engine today. A module can read
 * bytes, ask whether an address is referenced, and drive the interpreter. It
 * cannot decode one instruction.
 *
 *
 * WHAT THIS IS, AND THE NAME FOR IT IS PSEUDO-EMULATION.
 *
 * It decodes and it does NOT execute: no memory is written, no branch is
 * taken, nothing is guessed about a value that arrives from somewhere this did
 * not see. What it keeps is a CONSTANT MAP over the registers - `mov eax, 4`
 * makes eax known, `add eax, 1` keeps it known, `mov eax, [esi]` makes it
 * unknown again - so a module can ask "what is in this register here" and get
 * either an answer or an honest no.
 *
 * That is the difference from libgenome's emulator (phenotype), and it is not a smaller version of
 * it. The interpreter runs hostile code and costs millions of instructions;
 * this reads a few dozen and cannot run anything. A module wanting to know
 * what a decryptor DOES uses this. A module wanting the bytes the decryptor
 * PRODUCED uses the interpreter. The two answer different questions and the
 * Sality work needed both: the shape of the loader, and the plaintext under
 * it.
 *
 *
 * THE VOCABULARY IS THIS ENGINE'S, NOT THE DECODER'S.
 *
 * Nothing here names the decoder, and a module never includes it. The opcode
 * CLASS is what a rule is written against - `KGENOME_CELL_XOR` covers every encoding
 * of xor, which is the whole point when the generator picks encodings - and
 * the operand kinds are the four a rule asks about. A module written against
 * this does not change when the decoder underneath it is replaced.
 *
 *
 * OFFSETS, NOT ADDRESSES, AND BOTH FOR A BRANCH.
 *
 * The cursor walks the OBJECT, in file offsets, because that is what every
 * other module accessor takes - kof_u8, kof_find_str_at, ctx->entry_off. A
 * relative branch is computed in addresses, so the engine resolves it and
 * reports the target BOTH ways: `target` is where to point the cursor and
 * `target_va` is what the instruction said. A target outside the object is
 * KGENOME_BROKEN, which is a fact about the branch rather than a failure.
 */
#ifndef KGENOME_CELL_H
#define KGENOME_CELL_H

#include <stdint.h>

#include "arch.h"

/*
 * ---- OPCODE CLASSES -------------------------------------------------------
 *
 * Deliberately coarse. A class exists when a rule would ask for it; two
 * instructions that a rule would always accept together are one class. The
 * arithmetic and logic ones are separate because a decrypt loop is identified
 * by WHICH operation it applies, and the shifts are separate from the rotates
 * for the same reason.
 *
 * KGENOME_CELL_OTHER is not a failure. It means "decoded, and not one of these" - the
 * length is right and the cursor can step past it, which is what a walk
 * through junk needs most.
 */
enum kgenome_cell_op_class {
	KGENOME_CELL_OTHER = 0,
	KGENOME_CELL_NOP,
	KGENOME_CELL_MOV, KGENOME_CELL_MOVZX, KGENOME_CELL_MOVSX, KGENOME_CELL_LEA, KGENOME_CELL_XCHG,
	KGENOME_CELL_PUSH, KGENOME_CELL_POP,
	KGENOME_CELL_ADD, KGENOME_CELL_SUB, KGENOME_CELL_ADC, KGENOME_CELL_SBB,
	KGENOME_CELL_AND, KGENOME_CELL_OR, KGENOME_CELL_XOR, KGENOME_CELL_NOT, KGENOME_CELL_NEG,
	KGENOME_CELL_INC, KGENOME_CELL_DEC,
	KGENOME_CELL_CMP, KGENOME_CELL_TEST,
	KGENOME_CELL_SHL, KGENOME_CELL_SHR, KGENOME_CELL_SAR, KGENOME_CELL_ROL, KGENOME_CELL_ROR, KGENOME_CELL_RCL, KGENOME_CELL_RCR,
	KGENOME_CELL_MUL, KGENOME_CELL_IMUL, KGENOME_CELL_DIV, KGENOME_CELL_IDIV,
	KGENOME_CELL_CALL, KGENOME_CELL_JMP, KGENOME_CELL_JCC, KGENOME_CELL_LOOP, KGENOME_CELL_RET,
	KGENOME_CELL_INT, KGENOME_CELL_CMOV, KGENOME_CELL_SETCC,
	KGENOME_CELL_FPU,               /* any x87 - junk engines are fond of them */
	KGENOME_CELL_STRING,            /* MOVS/STOS/LODS/SCAS/CMPS */
	KGENOME_CELL_PRIV,              /* something a user mode program should not run */

	/*
	 * ADDED WHEN THIS BECAME THE ENGINE'S ONE INTERNAL FORM.
	 *
	 * The sweep used to read a decoder's own structure - the decoder's
	 * INSTRUX on x86, hand-written bit tests everywhere else - so the
	 * same question was answered four times in four spellings and a
	 * new architecture meant another copy. These are the classes it
	 * distinguishes that the list above did not carry.
	 *
	 * AT THE END, because a stored rule carries these numbers.
	 */
	KGENOME_CELL_SYSCALL,           /* syscall/sysenter; INT stays its own */
	KGENOME_CELL_WIDEN,             /* CBW/CWDE/CDQE and the like: same value */
	KGENOME_CELL_MOV_SPECIAL,       /* a control or system register */
	KGENOME_CELL_IRET,
	KGENOME_CELL_UD,                /* an instruction that is defined to fault */
	KGENOME_CELL_OP_COUNT
};

/* ---- WHAT A DECODER COULD NOT SAY -------------------------------------- */
/*
 * `kgenome_cell_insn.flags`
 *
 * FAR separates `retf` from `ret` and `jmp far` from `jmp`, which matters
 * because a far branch leaves the model the sweep is keeping.
 */
#define KGENOME_CELL_F_FAR      (1u << 0)
/* The branch is indirect: through a register or through memory. */
#define KGENOME_CELL_F_INDIRECT (1u << 1)
/* A repeated string operation. */
#define KGENOME_CELL_F_REP      (1u << 2)

/* `kgenome_cell_operand.flags` */
#define KGENOME_CELL_OF_WRITE   (1u << 0)
#define KGENOME_CELL_OF_READ    (1u << 1)
/* The memory operand is relative to the instruction pointer. */
#define KGENOME_CELL_OF_RIPREL  (1u << 2)
/*
 * AH, CH, DH OR BH - the byte ABOVE the low one, in a register the operand
 * otherwise names the same way as AL/CL/DL/BL.
 *
 * Without this a consumer folding `mov dh, 0x10` into its constant map writes
 * 0x10 where the program put 0x1000, which is not an unknown value but a
 * WRONG one. MEASURED: msfvenom's x86-64 stager sets its mmap length exactly
 * that way, so the map had the allocation at 16 bytes.
 */
#define KGENOME_CELL_OF_HIGH8   (1u << 3)

/* ---- OPERAND KINDS ------------------------------------------------------ */
enum kgenome_cell_op_kind {
	KGENOME_CELL_O_NONE = 0,
	KGENOME_CELL_O_REG,             /* `reg` */
	KGENOME_CELL_O_MEM,             /* `reg` is the base, plus index*scale + disp */
	KGENOME_CELL_O_IMM,             /* `imm` */
	KGENOME_CELL_O_REL              /* a branch displacement; see `target` */
};

/*
 * Registers, in the decoder's own numbering, which is also the emulator's - so a
 * module that reads a register here and one that reads one from a paused run
 * spell it the same way.
 */
#define KGENOME_CELL_REG_AX   0u
#define KGENOME_CELL_REG_CX   1u
#define KGENOME_CELL_REG_DX   2u
#define KGENOME_CELL_REG_BX   3u
#define KGENOME_CELL_REG_SP   4u
#define KGENOME_CELL_REG_BP   5u
#define KGENOME_CELL_REG_SI   6u
#define KGENOME_CELL_REG_DI   7u
#define KGENOME_CELL_REG_NONE 0xffu

/*
 * SEGMENT REGISTERS, AS AN INDEX AND NOT AS A PREFIX BYTE.
 *
 * `seg` below carries the decoder's segment register NUMBER - the x86
 * encoding order, ES CS SS DS FS GS - and not the 0x64/0x65 override bytes
 * that appear in the instruction stream. The two were confused once and the
 * cost was silent: every test comparing `seg` against 0x64 or 0x65 was a
 * condition that could not be true, so `fs:[0x30]` - the PEB fetch at the
 * top of every Windows import-resolving stub - was never recognised, and
 * neither was the i386 vDSO syscall entry at `gs:[0x10]`. Named here so the
 * next reader does not have to know which of the two a number is.
 */
#define KGENOME_CELL_SEG_ES 0u
#define KGENOME_CELL_SEG_CS 1u
#define KGENOME_CELL_SEG_SS 2u
#define KGENOME_CELL_SEG_DS 3u
#define KGENOME_CELL_SEG_FS 4u
#define KGENOME_CELL_SEG_GS 5u

struct kgenome_cell_operand {
	uint8_t  kind;          /* enum kgenome_cell_op_kind */
	uint8_t  reg;           /* REG, or a MEM base; KGENOME_CELL_REG_NONE if absent */
	uint8_t  index;         /* MEM index, or KGENOME_CELL_REG_NONE */
	uint8_t  scale;         /* 1, 2, 4, 8 */
	uint8_t  size;          /* access width in bytes */
	uint8_t  flags;         /* CELL_OF_* */
	uint8_t  seg;           /* segment register, or KGENOME_CELL_REG_NONE */
	uint8_t  _pad;
	int64_t  disp;          /* MEM displacement */
	uint64_t imm;           /* IMM value, zero extended */
};

/*
 * ONE DECODED INSTRUCTION.
 *
 * `n_op` counts only the operands the instruction reads or writes explicitly;
 * the implicit ones a decoder reports - the flags register, the stack pointer
 * behind a push - are dropped, because a rule that had to skip them would be
 * a rule written against the decoder rather than against the program.
 */
struct kgenome_cell_insn {
	uint8_t  op;            /* enum kgenome_cell_op_class */
	uint8_t  len;
	uint8_t  n_op;
	uint8_t  cond;          /* the condition code of a JCC/CMOV/SETCC */
	uint8_t  flags;         /* CELL_F_* */
	uint8_t  _pad[3];
	/*
	 * EVERY REGISTER THIS INSTRUCTION WRITES, one bit each.
	 *
	 * Including the ones it does not name: `mul` writes the pair
	 * above its operand, `push` moves the stack pointer, a string
	 * operation walks its own index registers. A consumer that had to
	 * find those by walking operands would be reading the decoder's
	 * idea of which operands are worth reporting - and the decoder
	 * reports them while a hand-written ARM decoder does not, which
	 * is exactly the kind of difference this form exists to remove.
	 *
	 * It is also what the sweep does most often: forget what it knew
	 * about everything this instruction touched.
	 */
	uint64_t wmask;
	uint64_t at;            /* the offset it was decoded at */
	uint64_t at_va;         /* and the address it would run at */
	/*
	 * Where a branch goes. KGENOME_BROKEN when the target is outside the
	 * object, or when the branch is indirect - `jmp eax` has a target this
	 * cannot know, and saying so is not the same as saying zero.
	 */
	uint64_t target;
	uint64_t target_va;
	struct kgenome_cell_operand o[3];
};

/*
 * THE SLOT AN INDIRECT BRANCH GOES THROUGH, or KGENOME_BROKEN when it is not a fixed one: `[rip+disp]` on x86-64, `[abs32]` on i386, and
 * `[ebx+disp]` on i386 when the caller knows the GOT address `gotbase` (0 = it does not). `wide` is a 64-bit object. A base or index register of any
 * other kind is a table lookup or a vtable call, and fs:/gs: is thread data: neither is an import slot. The ONE place that asks - the ELF import
 * route, the PE import route and the call-name table all read a branch's slot through it.
 */
uint64_t kgenome_cell_slot_of(const struct kgenome_cell_insn *in, int wide, uint64_t gotbase);

/*
 * THE CALLS THAT GO THROUGH AN IMPORT TABLE - what a reader of an ELF's PLT/GOT or a PE's IAT has to decide for every instruction, and the one place
 * that decides it. The ELF import route (diag_elfimp.c) and the call-name table (callnames.c) both read the same code for the same thing, a `call`/`jmp`
 * through a slot that the loader fills; each keeps its own import list (the route only the names the vocabulary has a word for, the table every named
 * one) and looks the slot up in it, and everything else is here:
 *   - which sections hold STUBS (kgenome_elf_sec_is_stub), which decides only whether a `jmp [slot]` is a PLT entry or a tail call in the program's own code;
 *   - the i386 GOT register (the lowest JUMP_SLOT is the first slot after the three reserved words, `ebx = lowest slot - 12`: a psABI fact);
 *   - the `endbr64` / `endbr32` in front of an IBT stub, which belongs to the stub (a call lands on it).
 * Feed every instruction of a code extent, in order, to kgenome_cell_plt_at; call it with NULL (or kgenome_cell_plt_reset) at the start of an extent.
 *   kgenome_cell_plt_init      zero the state for an object of this width over these bytes
 *   kgenome_cell_plt_import    one import of the object (its slot and relocation type): tells the lowest JUMP_SLOT; call it for EVERY import, kept or not
 *   kgenome_cell_plt_ready     after the imports: the stub sections and the GOT register. `ei` NULL is a PE (a `jmp [iat]` is a thunk wherever it is)
 * KGENOME_CELL_PLT_STUB is a `jmp [slot]` in a stub area; KGENOME_CELL_PLT_SLOT is any other `call`/`jmp [slot]`. The slot is not looked up here.
 */
struct kgenome_elf_info;

enum kgenome_cell_plt_kind {
	KGENOME_CELL_PLT_NONE = 0,
	KGENOME_CELL_PLT_STUB,
	KGENOME_CELL_PLT_SLOT
};

#define KGENOME_CELL_PLT_SECTIONS 128u          /* the most sections it remembers; the same bound as KGENOME_ELF_MAX_SECTIONS */

struct kgenome_cell_plt {
	const uint8_t *base;
	uint64_t size;
	uint64_t min_jslot;
	uint64_t gotbase;
	uint64_t prev_end_va, prev_va, prev_at;
	uint32_t n_stubsec;
	int      wide;
	int      no_sections;           /* every `jmp [slot]` is taken for a stub: a PE, or an ELF with no section table to say */
	uint8_t  prev_endbr;
	struct { uint64_t lo, hi; } stubsec[KGENOME_CELL_PLT_SECTIONS];
};

struct kgenome_cell_plt_site {
	uint64_t slot;                  /* the address the instruction goes through */
	uint64_t endbr_at, endbr_va;    /* the `endbr` that directly precedes a STUB, when has_endbr: its offset and address */
	uint8_t  kind;                  /* enum kgenome_cell_plt_kind */
	uint8_t  has_endbr;
};

void kgenome_cell_plt_init(struct kgenome_cell_plt *p, const uint8_t *base, uint64_t size, int wide);
void kgenome_cell_plt_import(struct kgenome_cell_plt *p, uint64_t slot, uint32_t reloc_type);
void kgenome_cell_plt_ready(struct kgenome_cell_plt *p, const struct kgenome_elf_info *ei);
void kgenome_cell_plt_reset(struct kgenome_cell_plt *p);
/* One instruction (NULL resets). Returns the kind; `out` is filled for a STUB or a SLOT. */
int kgenome_cell_plt_at(struct kgenome_cell_plt *p, const struct kgenome_cell_insn *in, struct kgenome_cell_plt_site *out);

#endif /* KGENOME_CELL_H */
