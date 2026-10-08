/*
 * genotype/x86 - an x86 / x86-64 instruction decoder.
 *
 * WHAT IT IS FOR. The emulator, the code sweep and the cross-reference pass all
 * decode the same bytes with the same engine, and the engine they use fills in
 * far more than any of them reads - the text of the mnemonic, the CPUID features,
 * the flags each instruction touches, every implicit operand. This decodes what
 * they read and nothing else, from tables that are generated (x86_gen.c) rather
 * than written, so that what an encoding MEANS is never a second opinion.
 *
 * TWO STEPS, BECAUSE MOST CALLERS NEED ONE. gt_x86_decode finds the instruction:
 * its length, its identity, its prefixes, and the raw displacement and immediates.
 * That is all a sweep that is looking for branches needs, and it is the part that
 * has to be fast. gt_x86_operand builds ONE operand - a register number, a
 * base+index*scale+disp, a value - when somebody asks for it, implicit operands
 * (the stack pointer a push moves, the flags a compare sets) included. MEASURED
 * before the split, on 44.7 M instructions of PE and ELF code: finding the
 * instruction cost 17 ns and building every operand of it another 15, and most
 * instructions are looked at for one or two operands, or none.
 *
 * WHAT IT RETURNS. Everything an instruction says about itself and nothing about
 * what a particular machine would do with it. Operand values are decoded, not
 * interpreted.
 *
 * WHAT IT DOES NOT DO. REX2 and the APX forms of EVEX, and the 3DNow! suffix map,
 * are reported as undecodable: nothing in the corpus this was built against
 * encodes them. An EVEX instruction's mask, zeroing and rounding are returned as
 * the raw payload byte (`evex`), not as operand decorations.
 */
#ifndef KOF_GENOTYPE_X86_H
#define KOF_GENOTYPE_X86_H

#include <stddef.h>
#include <stdint.h>

#include "x86_ids.h"
#include "../genotype.h"

#define GT_X86_MAX_OPS 10

/* Operand types. The values are the reference decoder's, so a port is a rename. */
enum gt_x86_optype {
	GT_X86_OP_NONE, GT_X86_OP_REG, GT_X86_OP_MEM, GT_X86_OP_IMM, GT_X86_OP_REL,
	GT_X86_OP_FAR, GT_X86_OP_NEAR, GT_X86_OP_CONST, GT_X86_OP_BANK, GT_X86_OP_DFV
};

/* Register classes, likewise. */
enum gt_x86_regtype {
	GT_X86_REG_NONE, GT_X86_REG_GPR, GT_X86_REG_SEG, GT_X86_REG_FPU,
	GT_X86_REG_MMX, GT_X86_REG_SSE, GT_X86_REG_CR, GT_X86_REG_DR, GT_X86_REG_TR,
	GT_X86_REG_BND, GT_X86_REG_MSK, GT_X86_REG_TILE, GT_X86_REG_MSR,
	GT_X86_REG_XCR, GT_X86_REG_SYS, GT_X86_REG_X87, GT_X86_REG_MXCSR,
	GT_X86_REG_PKRU, GT_X86_REG_SSP, GT_X86_REG_FLG, GT_X86_REG_RIP,
	GT_X86_REG_UIF
};

/* Where an operand is encoded. */
enum gt_x86_enc {
	GT_X86_ENC_NP, GT_X86_ENC_R, GT_X86_ENC_M, GT_X86_ENC_V, GT_X86_ENC_D,
	GT_X86_ENC_O, GT_X86_ENC_I, GT_X86_ENC_C, GT_X86_ENC_1, GT_X86_ENC_L,
	GT_X86_ENC_A, GT_X86_ENC_E, GT_X86_ENC_S
};

#define GT_X86_ACC_R   0x01u
#define GT_X86_ACC_W   0x02u
#define GT_X86_ACC_CR  0x04u
#define GT_X86_ACC_CW  0x08u

#define GT_X86_OF_DEFAULT  0x01u    /* implicit - not written in the instruction  */
#define GT_X86_OF_SEXT_OP1 0x02u    /* sign-extended to the first operand's size  */
#define GT_X86_OF_SEXT_DWS 0x04u    /* sign-extended to the default word size     */

/* Memory operand bits. The low byte is what this decoder saw; the high byte is
 * what the encoding says the operand IS. */
#define GT_X86_M_SEG     0x0001u
#define GT_X86_M_BASE    0x0002u
#define GT_X86_M_INDEX   0x0004u
#define GT_X86_M_DISP    0x0008u
#define GT_X86_M_RIPREL  0x0010u
#define GT_X86_M_BCAST   0x0020u    /* EVEX embedded broadcast                    */
#define GT_X86_M_STACK   0x0100u
#define GT_X86_M_STRING  0x0200u
#define GT_X86_M_DIRECT  0x0400u
#define GT_X86_M_AG      0x0800u    /* address generation only - lea              */
#define GT_X86_M_BITBASE 0x1000u
#define GT_X86_M_MIB     0x2000u
#define GT_X86_M_VSIB    0x4000u
#define GT_X86_M_SHSTK   0x8000u

struct gt_x86_op {
	uint8_t  type, enc, acc, flags;
	uint16_t size;                  /* bytes of data used; 0xffff: not known  */
	uint8_t  rtype;                 /* register                               */
	uint16_t rsize;                 /* its size in bytes (a tile register is 1024) */
	uint32_t reg;                   /* register number; an MSR's is its address */
	uint8_t  high8;                 /* AH, CH, DH or BH                       */
	uint8_t  seg, base, index, scale;
	uint8_t  bsz, isz;              /* base and index register sizes          */
	uint8_t  rawsize;               /* immediate: bytes encoded               */
	uint8_t  count;                 /* registers, starting with `reg`         */
	uint16_t elem;                  /* a gather's element size (what its text names)   */
	uint16_t mf;                    /* GT_X86_M_*                             */
	uint16_t sel;                   /* far address: the segment selector      */
	int64_t  v;                     /* displacement, immediate, relative      */
};

/* Instruction flags. */
#define GF_X86_REX      0x0001u
#define GF_X86_66       0x0002u /* present (may be mandatory: see GF_X86_M66) */
#define GF_X86_67       0x0004u
#define GF_X86_LOCK     0x0008u
#define GF_X86_F2       0x0010u
#define GF_X86_F3       0x0020u
#define GF_X86_SEG      0x0040u
#define GF_X86_MODRM    0x0080u
#define GF_X86_SIB      0x0100u
#define GF_X86_M66      0x0200u /* the 66 is part of the opcode, not a size prefix */
#define GF_X86_RIPREL   0x0400u

/*
 * A decoded instruction. It holds what finding the instruction produced and a
 * copy of its bytes; operands, displacement and immediates are read out of the
 * copy by gt_x86_operand, and the rarely wanted attributes (category, condition,
 * operand count, effective operand mode) by the accessors below. MEASURED:
 * filling all of them at decode cost about a third of the decode.
 *
 * `leaf`, `mo`, `dsz`, `osz` and `code` are the working state those read; a caller has
 * no use for them and must not rely on them.
 */
struct gt_x86_insn {
	uint16_t id;                    /* enum gt_x86_id                         */
	uint16_t leaf;
	uint16_t flags;                 /* GF_X86_*                               */
	uint8_t  len;
	uint8_t  mode;                  /* 32 or 64                               */
	uint8_t  rex;                   /* the REX byte, 0 if none                */
	uint8_t  seg;                   /* last segment prefix that counts, 0 if none */
	uint8_t  segr;                  /* the last segment prefix byte, counting or not (a branch hint is one) */
	uint8_t  rep;                   /* last F2 / F3 byte, 0 if none           */
	uint8_t  opc;                   /* the last opcode byte                   */
	uint8_t  mo;                    /* offset of the byte after the opcode    */
	uint8_t  dsz;                   /* displacement bytes                     */
	uint8_t  osz;                   /* size selector (see gt_x86_osz)         */
	uint8_t  sp;                    /* encoding: 0 legacy, 1 VEX, 2 XOP, 3 EVEX */
	uint8_t  vexv;                  /* VEX/EVEX register in vvvv, un-inverted, V' as bit 4 */
	uint8_t  xr;                    /* EVEX R'                                */
	uint8_t  evex;                  /* EVEX payload byte 3: z, L'L, b, V', aaa */
	uint8_t  code[16];              /* the instruction's own bytes            */
};

/* Decode one instruction at p, of which n bytes may be read. mode is 32 or 64. */
enum gt_status gt_x86_decode(struct gt_x86_insn *out, const uint8_t *p, size_t n,
			     int mode);

/* Attributes read on demand. */
unsigned gt_x86_nops(const struct gt_x86_insn *in);   /* implicit ones included */
unsigned gt_x86_cat(const struct gt_x86_insn *in);
unsigned gt_x86_cond(const struct gt_x86_insn *in);
unsigned gt_x86_efop(const struct gt_x86_insn *in);   /* effective operand mode: 0 16, 1 32, 2 64 */
unsigned gt_x86_osz(const struct gt_x86_insn *in);    /* size selector. Legacy: bit 0 a 66 that sizes, bit 1 REX.W; VEX/XOP: bit 0 L, bit 1 W; EVEX: bit 0 W, bits 1-2 L'L */
unsigned gt_x86_asz(const struct gt_x86_insn *in);    /* address size in bytes: 2, 4 or 8 */
unsigned gt_x86_mand(const struct gt_x86_insn *in);   /* bit 0 66, bit 1 F2, bit 2 F3 are part of the opcode */
unsigned gt_x86_repeated(const struct gt_x86_insn *in); /* a string instruction under REP/REPZ/REPNZ: it repeats while rcx counts down */
unsigned gt_x86_nform(const struct gt_x86_insn *in);  /* operands the instruction's DEFINITION calls explicit: INSB counts its [rdi] and dx, though neither is written */
unsigned gt_x86_nexp(const struct gt_x86_insn *in);   /* operands 0 .. nexp-1 are written in the instruction; the rest are implicit */
unsigned gt_x86_wgpr(const struct gt_x86_insn *in);   /* general registers it writes without naming one: a bit per register 0-15 */

/*
 * The instruction as text, Intel syntax, in `buf` (at least GT_X86_TEXT bytes).
 * `rip` is the address it sits at, which a relative branch and a RIP-relative
 * operand are shown resolved against. Returns the length written, 0 on failure.
 *
 * "MOV       dword ptr [rbx+0x8], eax": the mnemonic, padded so the operands line
 * up, then the explicit operands, then nothing - an implicit operand is never
 * printed. A prefix the instruction takes is named in front of it (REP, LOCK,
 * BND, XACQUIRE ...) and one it does not take is not.
 */
#define GT_X86_TEXT 160u
size_t gt_x86_format(const struct gt_x86_insn *in, uint64_t rip, char *buf, size_t cap);

/* Build operand k (0 <= k < gt_x86_nops) of a decoded instruction. */
void gt_x86_operand(const struct gt_x86_insn *in, unsigned k, struct gt_x86_op *out);

/* All of them: for a caller that reads most operands anyway. */
void gt_x86_operands(const struct gt_x86_insn *in, struct gt_x86_op *out);

#endif /* KOF_GENOTYPE_X86_H */
