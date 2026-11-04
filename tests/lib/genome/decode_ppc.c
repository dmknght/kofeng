/*
 * decode_ppc - the PowerPC adapter (celllysis/decode_ppc.c) against what the instruction set says.
 *
 * Every word is worked out from the instruction-form diagrams (the form beside it) or is the output of the
 * LLVM assembler for the line named; each says what the instruction IS: its class, the registers it writes
 * (wmask: the thing the constant map forgets), a branch's target, and the operands where a consumer reads
 * them by value. Register numbers: r0..r31 are 0..31, LR 32, CTR 33, XER 34, CR 35.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <celllysis/celllysis.h>

static int failures;

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define BIT(r) (1ull << (r))
#define LR 32u
#define CTR 33u
#define XER 34u
#define CR 35u
#define NOTGT KGENOME_BROKEN
#define GPRS(lo, hi) (((1ull << ((hi) + 1u)) - 1ull) & ~((1ull << (lo)) - 1ull))

static uint32_t dec(uint32_t w, uint64_t va, int be, int wide, struct kgenome_cell_insn *k)
{
	uint8_t b[4];

	if (be) {
		b[0] = (uint8_t)(w >> 24); b[1] = (uint8_t)(w >> 16); b[2] = (uint8_t)(w >> 8); b[3] = (uint8_t)w;
	} else {
		b[3] = (uint8_t)(w >> 24); b[2] = (uint8_t)(w >> 16); b[1] = (uint8_t)(w >> 8); b[0] = (uint8_t)w;
	}
	return kgenome_cell_decode_ppc(b, 4, va, be, wide, k);
}

struct row {
	const char *what;
	uint32_t w;
	uint64_t va;
	int wide;
	uint8_t op, n_op, flags, cond;
	uint64_t wmask, target_va;
};

#define R(what, w, va, wide, op, n, fl, cond, wm, tgt) \
	{ what, w, va, wide, KGENOME_CELL_##op, n, fl, cond, wm, tgt }
#define IND KGENOME_CELL_F_INDIRECT

static const struct row ROWS[] = {
	/* D-form arithmetic */
	R("addi r3,r4,-8",          0x3864fff8u, 0x1000, 0, ADD, 3, 0, 0, BIT(3), NOTGT),
	R("addi r3,r3,4",           0x38630004u, 0x1000, 0, ADD, 2, 0, 0, BIT(3), NOTGT),
	R("li r3,5 (addi rt,0)",    0x38600005u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("lis r3,0x1002",          0x3c601002u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("addis r3,r3,1",          0x3c630001u, 0x1000, 0, ADD, 2, 0, 0, BIT(3), NOTGT),
	R("addic r3,r4,1",          0x30640001u, 0x1000, 0, ADD, 3, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("addic. r3,r4,1",         0x34640001u, 0x1000, 0, ADD, 3, 0, 0, BIT(3) | BIT(XER) | BIT(CR), NOTGT),
	R("mulli r3,r4,3",          0x1c640003u, 0x1000, 0, IMUL, 3, 0, 0, BIT(3), NOTGT),
	R("subfic r3,r4,16",        0x20640010u, 0x1000, 0, OTHER, 0, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("cmpwi 0,r3,0",           0x2c030000u, 0x1000, 0, CMP, 2, 0, 0, BIT(CR), NOTGT),
	R("cmplwi 1,r3,65535",      0x2883ffffu, 0x1000, 0, CMP, 2, 0, 0, BIT(CR), NOTGT),
	R("ori r3,r4,5",            0x60830005u, 0x1000, 0, OR, 3, 0, 0, BIT(3), NOTGT),
	R("ori r3,r3,5",            0x60630005u, 0x1000, 0, OR, 2, 0, 0, BIT(3), NOTGT),
	R("nop (ori 0,0,0)",        0x60000000u, 0x1000, 0, NOP, 0, 0, 0, 0, NOTGT),
	R("andi. r3,r4,255",        0x708300ffu, 0x1000, 0, AND, 3, 0, 0, BIT(3) | BIT(CR), NOTGT),
	R("xori r3,r4,1",           0x68830001u, 0x1000, 0, XOR, 3, 0, 0, BIT(3), NOTGT),
	/* X and XO forms */
	R("add r3,r4,r5",           0x7c642a14u, 0x1000, 0, ADD, 3, 0, 0, BIT(3), NOTGT),
	R("add. r3,r4,r5",          0x7c642a15u, 0x1000, 0, ADD, 3, 0, 0, BIT(3) | BIT(CR), NOTGT),
	R("addo r3,r4,r5",          0x7c642e14u, 0x1000, 0, ADD, 3, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("add r3,r3,r5",           0x7c632a14u, 0x1000, 0, ADD, 2, 0, 0, BIT(3), NOTGT),
	R("subf r3,r4,r5",          0x7c642850u, 0x1000, 0, SUB, 3, 0, 0, BIT(3), NOTGT),
	R("subfc r3,r4,r5",         0x7c642810u, 0x1000, 0, SUB, 3, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("neg r3,r4",              0x7c6400d0u, 0x1000, 0, NEG, 2, 0, 0, BIT(3), NOTGT),
	R("mullw r3,r4,r5",         0x7c6429d6u, 0x1000, 0, IMUL, 3, 0, 0, BIT(3), NOTGT),
	R("divw r3,r4,r5",          0x7c642bd6u, 0x1000, 0, IDIV, 3, 0, 0, BIT(3), NOTGT),
	R("divwu r3,r4,r5",         0x7c642b96u, 0x1000, 0, DIV, 3, 0, 0, BIT(3), NOTGT),
	R("mr r3,r4 (or 3,4,4)",    0x7c832378u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("or r3,r4,r5",            0x7c832b78u, 0x1000, 0, OR, 3, 0, 0, BIT(3), NOTGT),
	R("and r3,r4,r5",           0x7c832838u, 0x1000, 0, AND, 3, 0, 0, BIT(3), NOTGT),
	R("xor r3,r4,r5",           0x7c832a78u, 0x1000, 0, XOR, 3, 0, 0, BIT(3), NOTGT),
	R("not r3,r4 (nor 3,4,4)",  0x7c8320f8u, 0x1000, 0, NOT, 2, 0, 0, BIT(3), NOTGT),
	R("nor r3,r4,r5",           0x7c8328f8u, 0x1000, 0, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("slw r3,r4,r5",           0x7c832830u, 0x1000, 0, SHL, 3, 0, 0, BIT(3), NOTGT),
	R("srw r3,r4,r5",           0x7c832c30u, 0x1000, 0, SHR, 3, 0, 0, BIT(3), NOTGT),
	R("sraw r3,r4,r5",          0x7c832e30u, 0x1000, 0, SAR, 3, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("srawi r3,r4,31",         0x7c83fe70u, 0x1000, 0, SAR, 3, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("extsb r3,r4",            0x7c830774u, 0x1000, 0, WIDEN, 2, 0, 0, BIT(3), NOTGT),
	R("cntlzw r3,r4",           0x7c830034u, 0x1000, 0, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("cmpw 1,r3,r4",           0x7c832000u, 0x1000, 0, CMP, 2, 0, 0, BIT(CR), NOTGT),
	/* rotates: the aliases the classes name, and the one that is none of them */
	R("slwi r3,r4,5",           0x54832834u, 0x1000, 0, SHL, 3, 0, 0, BIT(3), NOTGT),
	R("srwi r3,r4,5",           0x5483d97eu, 0x1000, 0, SHR, 3, 0, 0, BIT(3), NOTGT),
	R("clrlwi r3,r4,16",        0x5483043eu, 0x1000, 0, AND, 3, 0, 0, BIT(3), NOTGT),
	R("rotlwi r3,r4,5",         0x5483283eu, 0x1000, 0, ROL, 3, 0, 0, BIT(3), NOTGT),
	R("rlwinm r3,r4,0,0,31",    0x5483003eu, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("rlwinm r3,r4,5,6,7",     0x5483298eu, 0x1000, 0, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("rlwinm. r3,r4,5,6,7",    0x5483298fu, 0x1000, 0, OTHER, 0, 0, 0, BIT(3) | BIT(CR), NOTGT),
	R("rlwimi r3,r4,5,6,7",     0x5083298eu, 0x1000, 0, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("rlwnm r3,r4,r5,0,31",    0x5c83283eu, 0x1000, 0, ROL, 3, 0, 0, BIT(3), NOTGT),
	/* loads and stores */
	R("lwz r3,8(r1)",           0x80610008u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("lwz r3,16(0)",           0x80600010u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("lwzu r3,4(r4)",          0x84640004u, 0x1000, 0, MOV, 2, 0, 0, BIT(3) | BIT(4), NOTGT),
	R("stw r0,20(r1)",          0x90010014u, 0x1000, 0, MOV, 2, 0, 0, 0, NOTGT),
	R("stwu r1,-16(r1)",        0x9421fff0u, 0x1000, 0, MOV, 2, 0, 0, BIT(1), NOTGT),
	R("lbz r0,0x638(r30)",      0x881e0638u, 0x1000, 0, MOVZX, 2, 0, 0, BIT(0), NOTGT),
	R("lha r3,0(r1)",           0xa8610000u, 0x1000, 0, MOVSX, 2, 0, 0, BIT(3), NOTGT),
	R("lmw r29,-12(r1)",        0xbba1fff4u, 0x1000, 0, MOV, 2, 0, 0, GPRS(29, 31), NOTGT),
	R("stmw r29,-12(r1)",       0xbfa1fff4u, 0x1000, 0, MOV, 2, 0, 0, 0, NOTGT),
	R("lwzx r3,r4,r5",          0x7c64282eu, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("lwzx r3,0,r5",           0x7c60282eu, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("lwzux r3,r4,r5",         0x7c64286eu, 0x1000, 0, MOV, 2, 0, 0, BIT(3) | BIT(4), NOTGT),
	R("stwx r3,r4,r5",          0x7c64292eu, 0x1000, 0, MOV, 2, 0, 0, 0, NOTGT),
	R("lwbrx r3,r4,r5",         0x7c642c2cu, 0x1000, 0, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("stwbrx r3,r4,r5",        0x7c642d2cu, 0x1000, 0, OTHER, 0, 0, 0, 0, NOTGT),
	R("lwarx r3,r4,r5",         0x7c642828u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("stwcx. r3,r4,r5",        0x7c64292du, 0x1000, 0, MOV, 2, 0, 0, BIT(CR), NOTGT),
	R("lswi r5,r4,7",           0x7ca43caau, 0x1000, 0, OTHER, 0, 0, 0, BIT(5) | BIT(6), NOTGT),
	R("lswi r30,r4,0 (32 bytes)", 0x7fc404aau, 0x1000, 0, OTHER, 0, 0, 0, GPRS(30, 31) | GPRS(0, 5), NOTGT),
	R("lswi r5,r4,5 (two registers)", 0x7ca42caau, 0x1000, 0, OTHER, 0, 0, 0, BIT(5) | BIT(6), NOTGT),
	R("lswi r5,r4,4 (one register)",  0x7ca424aau, 0x1000, 0, OTHER, 0, 0, 0, BIT(5), NOTGT),
	R("lswi r5,r4,1 (one register)",  0x7ca40caau, 0x1000, 0, OTHER, 0, 0, 0, BIT(5), NOTGT),
	R("lswi r5,r4,8 (two registers)", 0x7ca444aau, 0x1000, 0, OTHER, 0, 0, 0, BIT(5) | BIT(6), NOTGT),
	R("lswx r3,r0,r4",          0x7c60242au, 0x1000, 0, OTHER, 0, 0, 0, GPRS(0, 31), NOTGT),
	R("lfs f1,8(r3)",           0xc0230008u, 0x1000, 0, FPU, 1, 0, 0, 0, NOTGT),
	R("lfsu f1,8(r3)",          0xc4230008u, 0x1000, 0, FPU, 1, 0, 0, BIT(3), NOTGT),
	R("stfd f31,-8(r1)",        0xdbe1fff8u, 0x1000, 0, FPU, 1, 0, 0, 0, NOTGT),
	R("dcbz r3,r4",             0x7c0327ecu, 0x1000, 0, OTHER, 0, 0, 0, 0, NOTGT),
	/* branches */
	R("b .+0x100",              0x48000100u, 0x1000, 0, JMP, 1, 0, 0, 0, 0x1100),
	R("b .-0x100",              0x4bffff00u, 0x1000, 0, JMP, 1, 0, 0, 0, 0xf00),
	R("bl .+0x100",             0x48000101u, 0x1000, 0, CALL, 1, 0, 0, BIT(LR), 0x1100),
	R("ba 0x100",               0x48000102u, 0x1000, 0, JMP, 1, 0, 0, 0, 0x100),
	R("bla 0x100",              0x48000103u, 0x1000, 0, CALL, 1, 0, 0, BIT(LR), 0x100),
	R("ba -4 (32-bit)",         0x4bfffffeu, 0x1000, 0, JMP, 1, 0, 0, 0, 0xfffffffcull),
	R("ba -4 (64-bit)",         0x4bfffffeu, 0x1000, 1, JMP, 1, 0, 0, 0, 0xfffffffffffffffcull),
	R("b wraps at 2^32",        0x48000100u, 0xffffff80u, 0, JMP, 1, 0, 0, 0, 0x80),
	R("beq .+16",               0x41820010u, 0x1000, 0, JCC, 3, 0, 1, 0, 0x1010),
	R("bne .-8",                0x4082fff8u, 0x1000, 0, JCC, 3, 0, 1, 0, 0xff8),
	R("bdnz .-8",               0x4200fff8u, 0x1000, 0, LOOP, 3, 0, 1, BIT(CTR), 0xff8),
	R("bdz .+8",                0x42400008u, 0x1000, 0, LOOP, 3, 0, 1, BIT(CTR), 0x1008),
	R("bdnzt 2,.+8",            0x41020008u, 0x1000, 0, LOOP, 3, 0, 1, BIT(CTR), 0x1008),
	R("bc 20,0,.+8 (always)",   0x42800008u, 0x1000, 0, JMP, 3, 0, 0, 0, 0x1008),
	R("bcl 20,0,.+4 (get pc)",  0x42800005u, 0x1000, 0, CALL, 3, 0, 0, BIT(LR), 0x1004),
	R("beql .+16",              0x41820011u, 0x1000, 0, CALL, 3, 0, 1, BIT(LR), 0x1010),
	R("blr",                    0x4e800020u, 0x1000, 0, RET, 3, 0, 0, 0, NOTGT),
	R("beqlr",                  0x4d820020u, 0x1000, 0, RET, 3, 0, 1, 0, NOTGT),
	R("bdnzlr",                 0x4e000020u, 0x1000, 0, RET, 3, 0, 1, BIT(CTR), NOTGT),
	R("blrl",                   0x4e800021u, 0x1000, 0, CALL, 3, IND, 0, BIT(LR), NOTGT),
	R("bctr",                   0x4e800420u, 0x1000, 0, JMP, 3, IND, 0, 0, NOTGT),
	R("bctrl",                  0x4e800421u, 0x1000, 0, CALL, 3, IND, 0, BIT(LR), NOTGT),
	R("bcctr 12,2",             0x4d820420u, 0x1000, 0, JMP, 3, IND, 1, 0, NOTGT),
	R("sc",                     0x44000002u, 0x1000, 0, SYSCALL, 0, 0, 0,
	  BIT(0) | GPRS(3, 12) | BIT(CR) | BIT(CTR) | BIT(XER), NOTGT),
	R("trap (tw 31,0,0)",       0x7fe00008u, 0x1000, 0, UD, 0, 0, 0, 0, NOTGT),
	R("twi 31,r3,5",            0x0fe30005u, 0x1000, 0, UD, 0, 0, 0, 0, NOTGT),
	R("tweq r3,r4",             0x7c832008u, 0x1000, 0, INT, 0, 0, 0, 0, NOTGT),
	R("twlti r3,-1",            0x0e03ffffu, 0x1000, 0, INT, 0, 0, 0, 0, NOTGT),
	R("rfi",                    0x4c000064u, 0x1000, 0, IRET, 0, 0, 0, 0, NOTGT),
	/* special registers, condition register */
	R("mflr r0",                0x7c0802a6u, 0x1000, 0, MOV, 2, 0, 0, BIT(0), NOTGT),
	R("mtlr r0",                0x7c0803a6u, 0x1000, 0, MOV, 2, 0, 0, BIT(LR), NOTGT),
	R("mfctr r3",               0x7c6902a6u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("mtctr r9",               0x7d2903a6u, 0x1000, 0, MOV, 2, 0, 0, BIT(CTR), NOTGT),
	R("mfxer r3",               0x7c6102a6u, 0x1000, 0, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("mfspr r3,272",           0x7c7042a6u, 0x1000, 0, MOV_SPECIAL, 2, 0, 0, BIT(3), NOTGT),
	R("mtspr 272,r4",           0x7c9043a6u, 0x1000, 0, MOV_SPECIAL, 2, 0, 0, 0, NOTGT),
	R("mfcr r3",                0x7c600026u, 0x1000, 0, MOV_SPECIAL, 0, 0, 0, BIT(3), NOTGT),
	R("mtcrf 255,r3",           0x7c6ff120u, 0x1000, 0, MOV_SPECIAL, 0, 0, 0, BIT(CR), NOTGT),
	R("mfmsr r3",               0x7c6000a6u, 0x1000, 0, PRIV, 0, 0, 0, BIT(3), NOTGT),
	R("mtmsr r3",               0x7c600124u, 0x1000, 0, PRIV, 0, 0, 0, 0, NOTGT),
	R("crand 1,2,3",            0x4c221a02u, 0x1000, 0, OTHER, 0, 0, 0, BIT(CR), NOTGT),
	R("sync",                   0x7c0004acu, 0x1000, 0, OTHER, 0, 0, 0, 0, NOTGT),
	R("isync",                  0x4c00012cu, 0x1000, 0, OTHER, 0, 0, 0, 0, NOTGT),
	/* floating point */
	R("fadds f1,f2,f3",         0xec22182au, 0x1000, 0, FPU, 0, 0, 0, 0, NOTGT),
	R("fadds. f1,f2,f3",        0xec22182bu, 0x1000, 0, FPU, 0, 0, 0, BIT(CR), NOTGT),
	R("fcmpu 0,f2,f3",          0xfc021800u, 0x1000, 0, FPU, 0, 0, 0, BIT(CR), NOTGT),
	/* what is not claimed */
	R("AltiVec (opcode 4)",     0x10221800u, 0x1000, 0, OTHER, 0, 0, 0, 0, NOTGT),
	R("INVALID (all zero)",     0x00000000u, 0x1000, 0, UD, 0, 0, 0, 0, NOTGT),
	/* 64-bit */
	R("ld r3,8(r4)",            0xe8640008u, 0x1000, 1, MOV, 2, 0, 0, BIT(3), NOTGT),
	R("ldu r3,8(r4)",           0xe8640009u, 0x1000, 1, MOV, 2, 0, 0, BIT(3) | BIT(4), NOTGT),
	R("lwa r3,4(r4)",           0xe8640006u, 0x1000, 1, MOVSX, 2, 0, 0, BIT(3), NOTGT),
	R("std r3,8(r4)",           0xf8640008u, 0x1000, 1, MOV, 2, 0, 0, 0, NOTGT),
	R("ld in 32-bit mode",      0xe8640008u, 0x1000, 0, UD, 0, 0, 0, 0, NOTGT),
	R("mulld r3,r4,r5",         0x7c6429d2u, 0x1000, 1, IMUL, 3, 0, 0, BIT(3), NOTGT),
	R("mullw in 64-bit mode",   0x7c6429d6u, 0x1000, 1, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("sraw in 64-bit mode",    0x7c832e30u, 0x1000, 1, OTHER, 0, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("srawi in 64-bit mode",   0x7c83fe70u, 0x1000, 1, OTHER, 0, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("srad r3,r4,r5",          0x7c832e34u, 0x1000, 1, SAR, 3, 0, 0, BIT(3) | BIT(XER), NOTGT),
	R("slw in 64-bit mode",     0x7c832830u, 0x1000, 1, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("sld r3,r4,r5",           0x7c832836u, 0x1000, 1, SHL, 3, 0, 0, BIT(3), NOTGT),
	R("rlwinm in 64-bit mode",  0x54832834u, 0x1000, 1, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("rldicl r3,r4,5,6",       0x78832940u, 0x1000, 1, OTHER, 0, 0, 0, BIT(3), NOTGT),
	R("b in 64-bit mode",       0x48000100u, 0xfffffffffffff000ull, 1, JMP, 1, 0, 0, 0, 0xfffffffffffff100ull),
};

static void check_rows(void)
{
	size_t i;

	for (i = 0; i < sizeof ROWS / sizeof *ROWS; i++) {
		const struct row *r = &ROWS[i];
		struct kgenome_cell_insn k;
		uint32_t n = dec(r->w, r->va, 1, r->wide, &k);
		int good = n == 4 && k.len == 4 && k.op == r->op && k.n_op == r->n_op && k.flags == r->flags &&
			   k.cond == r->cond && k.wmask == r->wmask && k.target_va == r->target_va && k.at_va == r->va;

		if (!good) {
			printf("  FAIL %s %08x: n=%u op=%u(want %u) n_op=%u(%u) flags=%u(%u) cond=%u(%u) wmask=%llx(%llx) tgt=%llx(%llx)\n",
			       r->what, r->w, n, k.op, r->op, k.n_op, r->n_op, k.flags, r->flags, k.cond, r->cond,
			       (unsigned long long)k.wmask, (unsigned long long)r->wmask,
			       (unsigned long long)k.target_va, (unsigned long long)r->target_va);
			failures++;
		}
		/* the same word read little-endian from reversed bytes is the same instruction */
		{
			struct kgenome_cell_insn l;

			if (dec(r->w, r->va, 0, r->wide, &l) != 4 || l.op != k.op || l.wmask != k.wmask ||
			    l.target_va != k.target_va || l.n_op != k.n_op || l.cond != k.cond) {
				printf("  FAIL %s: byte order\n", r->what);
				failures++;
			}
		}
	}
	printf("  %zu rows\n", sizeof ROWS / sizeof *ROWS);
}

/* the operands a consumer reads by value */
static void check_operands(void)
{
	struct kgenome_cell_insn k;

	dec(0x3864fff8u, 0x1000, 1, 0, &k);                     /* addi r3,r4,-8 */
	ok("addi o0", k.o[0].kind == KGENOME_CELL_O_REG && k.o[0].reg == 3 && k.o[0].flags == KGENOME_CELL_OF_WRITE);
	ok("addi o1", k.o[1].kind == KGENOME_CELL_O_REG && k.o[1].reg == 4);
	ok("addi o2", k.o[2].kind == KGENOME_CELL_O_IMM && k.o[2].imm == 0xfffffff8u && k.o[2].size == 4);
	dec(0x3864fff8u, 0x1000, 1, 1, &k);
	ok("addi 64-bit imm sign-extends", k.o[2].imm == 0xfffffffffffffff8ull && k.o[2].size == 8);
	dec(0x38630004u, 0x1000, 1, 0, &k);                     /* addi r3,r3,4 */
	ok("two-operand form", k.o[0].reg == 3 && k.o[0].flags == (KGENOME_CELL_OF_WRITE | KGENOME_CELL_OF_READ) &&
	   k.o[1].kind == KGENOME_CELL_O_IMM && k.o[1].imm == 4);
	dec(0x3c601002u, 0x1000, 1, 0, &k);                     /* lis r3,0x1002 */
	ok("lis value", k.o[1].kind == KGENOME_CELL_O_IMM && k.o[1].imm == 0x10020000u);
	dec(0x3c608000u, 0x1000, 1, 1, &k);                     /* lis r3,0x8000: sign-extended in 64-bit mode */
	ok("lis 0x8000 64-bit", k.o[1].imm == 0xffffffff80000000ull);
	dec(0x80610008u, 0x1000, 1, 0, &k);                     /* lwz r3,8(r1) */
	ok("lwz mem", k.o[1].kind == KGENOME_CELL_O_MEM && k.o[1].reg == 1 && k.o[1].index == KGENOME_CELL_REG_NONE &&
	   k.o[1].disp == 8 && k.o[1].size == 4 && k.o[1].flags == KGENOME_CELL_OF_READ);
	dec(0x80600010u, 0x1000, 1, 0, &k);                     /* lwz r3,16(0): no base register */
	ok("RA=0 is no base", k.o[1].reg == KGENOME_CELL_REG_NONE && k.o[1].disp == 16);
	dec(0x9421fff0u, 0x1000, 1, 0, &k);                     /* stwu r1,-16(r1) */
	ok("stwu mem", k.o[0].kind == KGENOME_CELL_O_MEM && k.o[0].reg == 1 && k.o[0].disp == -16 &&
	   k.o[0].flags == KGENOME_CELL_OF_WRITE && k.o[1].kind == KGENOME_CELL_O_REG && k.o[1].reg == 1);
	dec(0x7c64282eu, 0x1000, 1, 0, &k);                     /* lwzx r3,r4,r5 */
	ok("indexed", k.o[1].reg == 4 && k.o[1].index == 5 && k.o[1].scale == 1 && k.o[1].disp == 0);
	dec(0x7c60282eu, 0x1000, 1, 0, &k);                     /* lwzx r3,0,r5: EA = r5 */
	ok("indexed RA=0", k.o[1].reg == 5 && k.o[1].index == KGENOME_CELL_REG_NONE);
	dec(0xe8640006u, 0x1000, 1, 1, &k);                     /* lwa r3,4(r4) */
	ok("lwa disp", k.o[1].disp == 4 && k.o[1].size == 4);
	dec(0x7c642850u, 0x1000, 1, 0, &k);                     /* subf r3,r4,r5 = r5 - r4: minuend first */
	ok("subf operand order", k.o[0].reg == 3 && k.o[1].reg == 5 && k.o[2].reg == 4);
	dec(0x7c832b78u, 0x1000, 1, 0, &k);                     /* or r3,r4,r5: dest is RA */
	ok("or dest is RA", k.o[0].reg == 3 && k.o[1].reg == 4 && k.o[2].reg == 5);
	dec(0x7c832378u, 0x1000, 1, 0, &k);                     /* mr r3,r4 */
	ok("mr", k.o[0].reg == 3 && k.o[1].reg == 4);
	dec(0x7c0802a6u, 0x1000, 1, 0, &k);                     /* mflr r0 */
	ok("mflr", k.o[0].reg == 0 && k.o[1].kind == KGENOME_CELL_O_REG && k.o[1].reg == LR);
	dec(0x7d2903a6u, 0x1000, 1, 0, &k);                     /* mtctr r9 */
	ok("mtctr", k.o[0].reg == CTR && k.o[1].reg == 9 && k.o[0].flags == KGENOME_CELL_OF_WRITE);
	dec(0x7c7042a6u, 0x1000, 1, 0, &k);                     /* mfspr r3,272 */
	ok("mfspr other", k.o[1].kind == KGENOME_CELL_O_IMM && k.o[1].imm == 272);
	dec(0x54832834u, 0x1000, 1, 0, &k);                     /* slwi r3,r4,5 */
	ok("slwi", k.o[0].reg == 3 && k.o[1].reg == 4 && k.o[2].imm == 5);
	dec(0x5483043eu, 0x1000, 1, 0, &k);                     /* clrlwi r3,r4,16 */
	ok("clrlwi mask", k.o[2].imm == 0xffffu);
	dec(0x5483003cu, 0x1000, 1, 0, &k);                     /* rlwinm r3,r4,0,0,30 : clrrwi 1 */
	ok("clrrwi mask", k.op == KGENOME_CELL_AND && k.o[2].imm == 0xfffffffeu);
	dec(0x5483063eu, 0x1000, 1, 0, &k);                     /* rlwinm r3,r4,0,24,31 : mask 0xff */
	ok("mask 0xff", k.op == KGENOME_CELL_AND && k.o[2].imm == 0xffu);
	dec(0x548306beu, 0x1000, 1, 0, &k);                     /* rlwinm r3,r4,0,26,31 */
	ok("mask 0x3f", k.o[2].imm == 0x3fu);
	dec(0x5483003eu | (31u << 6) | (0u << 1), 0x1000, 1, 0, &k);   /* rlwinm r3,r4,0,31,31 (mb>me is the wrapping form only when mb>me) */
	ok("mask 0x1", k.op == KGENOME_CELL_AND && k.o[2].imm == 1u);
	dec(0x54830000u | (30u << 6) | (1u << 1), 0x1000, 1, 0, &k);   /* rlwinm r3,r4,0,30,1: the wrapped mask 0xc0000003 */
	ok("wrapped mask", k.op == KGENOME_CELL_AND && k.o[2].imm == 0xc0000003u);
	dec(0x41820010u, 0x1000, 1, 0, &k);                     /* beq */
	ok("bc operands", k.o[0].kind == KGENOME_CELL_O_REL && k.o[1].kind == KGENOME_CELL_O_IMM && k.o[1].imm == 12 &&
	   k.o[2].imm == 2);
	dec(0x4e800020u, 0x1000, 1, 0, &k);                     /* blr */
	ok("blr operand", k.o[0].kind == KGENOME_CELL_O_REG && k.o[0].reg == LR && k.o[0].flags == KGENOME_CELL_OF_READ);
	dec(0x4e800420u, 0x1000, 1, 0, &k);
	ok("bctr operand", k.o[0].reg == CTR);
	dec(0x2c030005u, 0x1000, 1, 0, &k);                     /* cmpwi 0,r3,5 */
	ok("cmpwi operands", k.o[0].reg == 3 && k.o[1].kind == KGENOME_CELL_O_IMM && k.o[1].imm == 5);
	dec(0x2c03ffffu, 0x1000, 1, 0, &k);                     /* cmpwi 0,r3,-1: signed */
	ok("cmpwi negative", k.o[1].imm == 0xffffffffu);
	dec(0x2803ffffu, 0x1000, 1, 0, &k);                     /* cmplwi 0,r3,65535: unsigned */
	ok("cmplwi unsigned", k.o[1].imm == 0xffffu);
	dec(0xa8610000u, 0x1000, 1, 0, &k);                     /* lha r3,0(r1) */
	ok("lha size", k.op == KGENOME_CELL_MOVSX && k.o[1].size == 2);
	dec(0xa0610000u, 0x1000, 1, 0, &k);                     /* lhz */
	ok("lhz size", k.op == KGENOME_CELL_MOVZX && k.o[1].size == 2);
	dec(0x88610000u, 0x1000, 1, 0, &k);                     /* lbz */
	ok("lbz size", k.op == KGENOME_CELL_MOVZX && k.o[1].size == 1);
	dec(0x7c830774u, 0x1000, 1, 0, &k);                     /* extsb */
	ok("extsb size", k.o[0].reg == 3 && k.o[1].reg == 4 && k.o[1].size == 1);
	dec(0x7c630774u, 0x1000, 1, 0, &k);                     /* extsb r3,r3 */
	ok("extsb same reg", k.n_op == 1 && k.o[0].reg == 3);
}

/* a buffer that is too short, and the pointers a caller may get wrong */
static void check_short(void)
{
	static const uint8_t b[8] = { 0x4e, 0x80, 0x00, 0x20, 0x38, 0x60, 0x00, 0x05 };
	struct kgenome_cell_insn k;
	unsigned n;

	for (n = 0; n < 4; n++)
		ok("short buffer", kgenome_cell_decode_ppc(b, n, 0, 1, 0, &k) == 0);
	ok("exactly four", kgenome_cell_decode_ppc(b, 4, 0, 1, 0, &k) == 4 && k.op == KGENOME_CELL_RET);
	ok("seven is four", kgenome_cell_decode_ppc(b + 4, 7, 0, 1, 0, &k) == 4 && k.op == KGENOME_CELL_MOV);
	ok("null bytes", kgenome_cell_decode_ppc(NULL, 4, 0, 1, 0, &k) == 0);
	ok("null out", kgenome_cell_decode_ppc(b, 4, 0, 1, 0, NULL) == 0);
	/* through the one way in */
	ok("dispatch PPC", kgenome_cell_decode(KGENOME_ARCH_PPC, 1, b, 4, 0x1000, &k) == 4 && k.op == KGENOME_CELL_RET);
	ok("dispatch PPC64 reads ld", kgenome_cell_decode(KGENOME_ARCH_PPC64, 1, (const uint8_t[]){ 0xe8, 0x64, 0, 8 }, 4, 0, &k) == 4 &&
	   k.op == KGENOME_CELL_MOV);
	ok("dispatch PPC refuses ld", kgenome_cell_decode(KGENOME_ARCH_PPC, 1, (const uint8_t[]){ 0xe8, 0x64, 0, 8 }, 4, 0, &k) == 4 &&
	   k.op == KGENOME_CELL_UD);
	ok("dispatch PPC64 little-endian", kgenome_cell_decode(KGENOME_ARCH_PPC64, 0, (const uint8_t[]){ 0x20, 0x00, 0x80, 0x4e }, 4, 0, &k) == 4 &&
	   k.op == KGENOME_CELL_RET);
}

/* every word of the architecture: the adapter is total, 4 long, deterministic, and a class never lies about a branch's target */
static void check_every_word(void)
{
	uint64_t x = 0x1234567887654321ull;
	unsigned i;
	unsigned long long br = 0;

	for (i = 0; i < 2000000; i++) {
		struct kgenome_cell_insn k, k2;
		uint32_t w;
		int wide = (int)(i & 1);

		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		w = (uint32_t)(x >> 8);
		if (dec(w, 0x10000000u + 4u * i, 1, wide, &k) != 4 || k.len != 4 || k.op >= KGENOME_CELL_OP_COUNT ||
		    dec(w, 0x10000000u + 4u * i, 1, wide, &k2) != 4 || memcmp(&k, &k2, sizeof k)) {
			printf("  FAIL random word %08x\n", w);
			failures++;
			return;
		}
		/* a direct branch has a target; nothing else does; a class that falls through has none */
		if ((k.op == KGENOME_CELL_JMP || k.op == KGENOME_CELL_JCC || k.op == KGENOME_CELL_LOOP ||
		     k.op == KGENOME_CELL_CALL) && !(k.flags & KGENOME_CELL_F_INDIRECT)) {
			br++;
			if (k.target_va == NOTGT || k.o[0].kind != KGENOME_CELL_O_REL) {
				printf("  FAIL direct branch %08x without a target\n", w);
				failures++;
				return;
			}
			if (!wide && k.target_va > 0xffffffffull) {
				printf("  FAIL 32-bit target out of range %08x\n", w);
				failures++;
				return;
			}
		} else if (k.target_va != NOTGT) {
			printf("  FAIL target on a non-branch %08x\n", w);
			failures++;
			return;
		}
		/* a register is never claimed written beyond CR (35) */
		if (k.wmask >> 36) {
			printf("  FAIL wmask %llx for %08x\n", (unsigned long long)k.wmask, w);
			failures++;
			return;
		}
	}
	printf("  2000000 random words, %llu direct branches\n", br);
}

int main(void)
{
	check_rows();
	check_operands();
	check_short();
	check_every_word();
	printf("decode_ppc: %s\n", failures ? "FAILED" : "all ok");
	return failures ? 1 : 0;
}
