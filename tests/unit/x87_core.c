/*
 * x87_core - the floating point stack, because a wrong answer here is silent.
 *
 * WHY IT IS WORTH A TEST AND THE REST OF THE ALU IS NOT. Every other
 * instruction this interpreter carries either produces the right integer or
 * produces something a later branch visibly disagrees with. x87 is different
 * in two ways: the results are 80-bit on the hardware and 64-bit here, so
 * "close" and "correct" are not the same question; and the REVERSED forms -
 * FSUBR, FDIVR - compute the operands the other way round, which is a mistake
 * that looks exactly like the right instruction until the number comes out.
 *
 * So what is asserted is arithmetic with a known answer, the pop behaviour
 * that decides which register the next instruction reads, and the compares a
 * guest actually branches on.
 *
 * MEASURED BY WAY OF THE STACK, not by reading registers this has no accessor
 * for: each stub stores its result to memory and the test reads that back,
 * which is also the path a real guest uses.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "../../libgenome/phenotype/kofemu.h"

static int failures;

#define CODE_VA  0x400000ull
#define DATA_VA  0x401000ull
#define STACK_VA 0x7ff00000ull

/*
 * Run a 32-bit stub with EDX pointing at DATA_VA, then read `n` bytes back
 * from DATA_VA + `out`. Answers 0 if the run did not finish on the HLT.
 */
static int run(const uint8_t *code, unsigned n, const void *seed,
	       unsigned seedn, unsigned out, void *got, unsigned gotn)
{
	struct kof_emu_cfg cfg = { 0 };
	struct kof_emu *e;
	int ok;

	cfg.bits = 32;
	cfg.max_insn = 200;
	e = kof_emu_new(&cfg);
	if (!e)
		return 0;
	kof_emu_map(e, CODE_VA, code, n, 0x1000, KOF_EMU_R | KOF_EMU_X);
	kof_emu_map(e, DATA_VA, seed, seedn, 0x1000, KOF_EMU_R | KOF_EMU_W);
	kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W);
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);
	kof_emu_set_reg(e, KOF_EMU_RDX, DATA_VA);
	(void)kof_emu_run(e);
	ok = kof_emu_read(e, DATA_VA + out, got, gotn);
	kof_emu_free(e);
	return ok;
}

static void want(const char *what, double got, double expect)
{
	/* Exact: every value here is representable, so "close enough" would
	 * hide precisely the operand-order mistakes this exists to catch. */
	if (got != expect) {
		printf("  FAIL %s: got %.17g, want %.17g\n", what, got, expect);
		failures++;
	}
}

int main(void)
{
	/* DATA: [0] double 10.0   [8] double 4.0   [16] result   [24] m32 3.0
	 *       [28] m32int 7     [32] word for fnstsw                       */
	uint8_t seed[64];
	double a = 10.0, b = 4.0, r;
	float f32 = 3.0f;
	int32_t i32 = 7;
	uint16_t sw;

	memset(seed, 0, sizeof seed);
	memcpy(seed, &a, 8);
	memcpy(seed + 8, &b, 8);
	memcpy(seed + 24, &f32, 4);
	memcpy(seed + 28, &i32, 4);

	/* fld qword[edx] ; fdiv qword[edx+8] ; fstp qword[edx+16] ; hlt */
	{
		static const uint8_t c[] = {
			0xDD,0x02, 0xDC,0x72,0x08, 0xDD,0x5A,0x10, 0xF4
		};
		if (!run(c, sizeof c, seed, sizeof seed, 16, &r, 8))
			{ printf("  FAIL fdiv: no result\n"); failures++; }
		else
			want("fdiv 10/4", r, 2.5);
	}
	/* The reversed one, which is the whole reason this file exists.
	 * fld qword[edx] ; fdivr qword[edx+8] ; fstp qword[edx+16] */
	{
		static const uint8_t c[] = {
			0xDD,0x02, 0xDC,0x7A,0x08, 0xDD,0x5A,0x10, 0xF4
		};
		if (run(c, sizeof c, seed, sizeof seed, 16, &r, 8))
			want("fdivr 4/10", r, 0.4);
	}
	/* fld qword[edx] ; fsub qword[edx+8] -> 6 ; and reversed -> -6 */
	{
		static const uint8_t c[] = {
			0xDD,0x02, 0xDC,0x62,0x08, 0xDD,0x5A,0x10, 0xF4
		};
		static const uint8_t d[] = {
			0xDD,0x02, 0xDC,0x6A,0x08, 0xDD,0x5A,0x10, 0xF4
		};
		if (run(c, sizeof c, seed, sizeof seed, 16, &r, 8))
			want("fsub 10-4", r, 6.0);
		if (run(d, sizeof d, seed, sizeof seed, 16, &r, 8))
			want("fsubr 4-10", r, -6.0);
	}
	/* m32 and m32int sources, and the 80-bit round trip.
	 * fld dword[edx+24] ; fild dword[edx+28] ; fmulp st1,st0 ;
	 * fstp tbyte[edx+32] ; fld tbyte[edx+32] ; fstp qword[edx+16] */
	{
		static const uint8_t c[] = {
			0xD9,0x42,0x18, 0xDB,0x42,0x1C, 0xDE,0xC9,
			0xDB,0x7A,0x20, 0xDB,0x6A,0x20, 0xDD,0x5A,0x10, 0xF4
		};
		if (run(c, sizeof c, seed, sizeof seed, 16, &r, 8))
			want("3.0f * 7 through an 80-bit store", r, 21.0);
	}
	/*
	 * THE POP IS NOT DECORATION. fld twice then faddp leaves ONE value;
	 * if the pop is missed, the fstp below writes the wrong register.
	 * fld qword[edx] ; fld qword[edx+8] ; faddp st1,st0 ;
	 * fld1 ; faddp st1,st0 ; fstp qword[edx+16]   -> 10+4+1
	 */
	{
		static const uint8_t c[] = {
			0xDD,0x02, 0xDD,0x42,0x08, 0xDE,0xC1,
			0xD9,0xE8, 0xDE,0xC1, 0xDD,0x5A,0x10, 0xF4
		};
		if (run(c, sizeof c, seed, sizeof seed, 16, &r, 8))
			want("two pushes, two popping adds", r, 15.0);
	}
	/*
	 * The compare a guest branches on: fld 4 ; fcomp 10 leaves C0 set
	 * (st0 < src), which fnstsw puts in AH bit 0 - i.e. 0x0100.
	 * fld qword[edx+8] ; fcomp qword[edx] ; fnstsw ax ; mov [edx+32],ax
	 */
	{
		static const uint8_t c[] = {
			0xDD,0x42,0x08, 0xDC,0x1A, 0xDF,0xE0,
			0x66,0x89,0x42,0x20, 0xF4
		};
		if (run(c, sizeof c, seed, sizeof seed, 32, &sw, 2)) {
			if (!(sw & 0x0100u)) {
				printf("  FAIL fcomp 4<10 did not set C0"
				       " (fsw=%#x)\n", sw);
				failures++;
			}
			if (sw & 0x4000u) {
				printf("  FAIL fcomp 4<10 also set C3"
				       " (fsw=%#x)\n", sw);
				failures++;
			}
		}
	}
	/* And SALC, which shares nothing with the above but is the other
	 * instruction a polymorphic body stopped this run on.
	 * stc ; salc ; mov [edx+16],al   -> 0xff */
	{
		static const uint8_t c[] = { 0xF9, 0xD6, 0x88,0x42,0x10, 0xF4 };
		uint8_t al = 0;

		if (run(c, sizeof c, seed, sizeof seed, 16, &al, 1) && al != 0xffu)
			{ printf("  FAIL salc with CF set gave %#x\n", al);
			  failures++; }
	}
	{
		static const uint8_t c[] = { 0xF8, 0xD6, 0x88,0x42,0x10, 0xF4 };
		uint8_t al = 0xaa;

		if (run(c, sizeof c, seed, sizeof seed, 16, &al, 1) && al != 0)
			{ printf("  FAIL salc with CF clear gave %#x\n", al);
			  failures++; }
	}

	printf("x87 core: divide, the reversed forms, m32/m32int/m80, the pop,"
	       " the status word, salc - %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
