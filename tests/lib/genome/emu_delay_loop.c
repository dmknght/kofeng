/*
 * emu_delay_loop - a counted delay loop is skipped, and what is left is exactly
 * what running every lap would have left.
 *
 * WHY THIS NEEDS A TEST. The skip (libgenome/phenotype/emu_loop.c) sets a
 * counter to the value it has one lap before the exit and lets the loop finish
 * itself. That is only sound if the shape it recognised is a shape with no other
 * effect, and the counter, the flags and the stop address come out the same. The
 * way to say so is to run the same loop twice: once as it is, once with an
 * instruction in the body that the recogniser does not know and that changes
 * nothing (`lea edx,[rdx]`), so the second is run lap by lap - and compare. A
 * loop is run for several counts, the small ones (inside the probe count, never
 * skipped) and the large (skipped), because the arithmetic is the part that can
 * be off by one at either end.
 *
 * AND WHAT THE SKIP COSTS THE RUN, which is the point of it: the skipped laps are
 * not in `insn` (the instruction budget and the stall test read that) and ARE in
 * the guest's clock, so a program timing its own wait sees the time the laps would
 * have taken. A body that is not register-only is not skipped at all.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/emu.h>

static int failures;

#define CODE_VA  0x400000ull
#define STACK_VA 0x7ff00000ull

/* The status flags a loop's last compare leaves: CF PF AF ZF SF OF. */
#define FLAGS_MASK 0x8d5ull

enum shape {
	DEC_JNZ, SUB_JNZ, DEC64_JNZ, INC_CMP_JNE, INC_CMP_JB, INC_CMP_JL,
	NOP_LOOP, DEC_CMP_JNE, DEC_JNZ_32
};

static const char *const shape_name[] = {
	"dec ecx; jnz", "sub ecx,1; jnz", "dec rcx; jnz", "inc; cmp; jne",
	"inc; cmp; jb", "inc; cmp; jl", "nop; loop", "dec; cmp 3; jne",
	"dec ecx; jnz (32-bit)"
};

struct out {
	uint64_t rcx, flags, insn, tsc;
	int ok;
};

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * The program: rdtsc ; set up the counter ; the loop (with `extra` bytes in its
 * body when asked) ; rdtsc ; pushf ; pop rbx ; hlt. rdtsc is read into rsi (the
 * low half) before and rdi after, so the clock the loop cost is rdi - rsi.
 */
static unsigned build(uint8_t *c, enum shape sh, uint32_t n, int extra)
{
	uint8_t body[16];
	unsigned b = 0, k = 0, at = 0;
	int8_t rel;

	c[at++] = 0x0f; c[at++] = 0x31;                         /* rdtsc        */
	c[at++] = 0x89; c[at++] = 0xc6;                         /* mov esi,eax  */
	switch (sh) {
	case DEC_JNZ: case DEC_JNZ_32: case SUB_JNZ: case NOP_LOOP: case DEC_CMP_JNE:
		c[at++] = 0xb9; put32(c + at, n); at += 4;      /* mov ecx,n    */
		break;
	case DEC64_JNZ:
		c[at++] = 0x48; c[at++] = 0xb9;                 /* mov rcx,n    */
		put32(c + at, n); at += 4; put32(c + at, 0); at += 4;
		break;
	default:
		c[at++] = 0x31; c[at++] = 0xc9;                 /* xor ecx,ecx  */
		break;
	}
	switch (sh) {
	case DEC_JNZ: case DEC_CMP_JNE:
		body[b++] = 0xff; body[b++] = 0xc9;             /* dec ecx      */
		break;
	case DEC_JNZ_32:
		body[b++] = 0x49;                               /* dec ecx (i386) */
		break;
	case SUB_JNZ:
		body[b++] = 0x83; body[b++] = 0xe9; body[b++] = 0x01; /* sub ecx,1 */
		break;
	case DEC64_JNZ:
		body[b++] = 0x48; body[b++] = 0xff; body[b++] = 0xc9; /* dec rcx   */
		break;
	case NOP_LOOP:
		body[b++] = 0x90;                               /* nop          */
		break;
	default:
		body[b++] = 0xff; body[b++] = 0xc1;             /* inc ecx      */
		break;
	}
	switch (sh) {
	case INC_CMP_JNE: case INC_CMP_JB: case INC_CMP_JL:
		body[b++] = 0x81; body[b++] = 0xf9; put32(body + b, n); b += 4; /* cmp ecx,n */
		break;
	case DEC_CMP_JNE:
		body[b++] = 0x83; body[b++] = 0xf9; body[b++] = 0x03;   /* cmp ecx,3 */
		break;
	default:
		break;
	}
	if (extra) {
		body[b++] = 0x8d; body[b++] = 0x12;             /* lea edx,[rdx] - nothing */
	}
	if (sh == NOP_LOOP) {
		rel = (int8_t)-(int)(b + 2u);
		body[b++] = 0xe2; body[b++] = (uint8_t)rel;     /* loop         */
	} else {
		uint8_t jcc = sh == INC_CMP_JB ? 0x72 : sh == INC_CMP_JL ? 0x7c : 0x75;

		rel = (int8_t)-(int)(b + 2u);
		body[b++] = jcc; body[b++] = (uint8_t)rel;
	}
	for (k = 0; k < b; k++)
		c[at++] = body[k];
	c[at++] = 0x0f; c[at++] = 0x31;                         /* rdtsc        */
	c[at++] = 0x89; c[at++] = 0xc7;                         /* mov edi,eax  */
	c[at++] = 0x9c;                                         /* pushf        */
	c[at++] = 0x5b;                                         /* pop rbx      */
	c[at++] = 0xf4;                                         /* hlt          */
	return at;
}

static struct out run(enum shape sh, uint32_t n, int extra)
{
	uint8_t code[64];
	struct kgenome_emu_cfg cfg = { 0 };
	struct kgenome_emu *e;
	struct out o;
	unsigned len = build(code, sh, n, extra);

	memset(&o, 0, sizeof o);
	cfg.bits = sh == DEC_JNZ_32 ? 32u : 64u;
	cfg.max_insn = 8u << 20;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return o;
	kgenome_emu_map(e, CODE_VA, code, len, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, STACK_VA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, CODE_VA);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
	kgenome_emu_set_reg(e, KGENOME_EMU_RDX, 0);
	(void)kgenome_emu_run(e);
	o.rcx = kgenome_emu_get_reg(e, KGENOME_EMU_RCX);
	o.flags = kgenome_emu_get_reg(e, KGENOME_EMU_RBX) & FLAGS_MASK;
	o.insn = kgenome_emu_insn_count(e);
	o.tsc = (uint32_t)(kgenome_emu_get_reg(e, 7) - kgenome_emu_get_reg(e, 6));
	o.ok = 1;
	kgenome_emu_free(e);
	return o;
}

int main(void)
{
	static const uint32_t counts[] = { 3, 17, 40, 1000, 200000 };
	unsigned s, i;

	for (s = 0; s <= DEC_JNZ_32; s++) {
		for (i = 0; i < sizeof counts / sizeof *counts; i++) {
			uint32_t n = counts[i];
			struct out fast, slow;

			/* The loop that counts DOWN TO 3 needs a count above it. */
			if (s == DEC_CMP_JNE && n <= 3u)
				continue;
			fast = run((enum shape)s, n, 0);
			slow = run((enum shape)s, n, 1);
			if (!fast.ok || !slow.ok ||
			    fast.rcx != slow.rcx || fast.flags != slow.flags) {
				printf("  FAIL %s, %u laps: counter %#llx flags %#llx, run lap by lap %#llx %#llx\n",
				       shape_name[s], (unsigned)n,
				       (unsigned long long)fast.rcx, (unsigned long long)fast.flags,
				       (unsigned long long)slow.rcx, (unsigned long long)slow.flags);
				failures++;
			}
			if (n >= 1000u) {
				/* skipped: a few dozen instructions, not hundreds of thousands */
				if (fast.insn > 200u) {
					printf("  FAIL %s, %u laps: %llu instructions run\n",
					       shape_name[s], (unsigned)n,
					       (unsigned long long)fast.insn);
					failures++;
				}
				/* and the clock saw the laps it did not run */
				if (fast.tsc + 8u < slow.tsc / 2u) {
					printf("  FAIL %s, %u laps: the guest's clock moved %llu, lap by lap %llu\n",
					       shape_name[s], (unsigned)n,
					       (unsigned long long)fast.tsc,
					       (unsigned long long)slow.tsc);
					failures++;
				}
			}
		}
	}

	/* A body that touches memory is not a delay: every lap is run. */
	{
		static const uint8_t mem[] = {
			0xb9, 0xe8, 0x03, 0x00, 0x00,           /* mov ecx,1000        */
			0x89, 0x4c, 0x24, 0xf0,                 /* mov [rsp-16],ecx    */
			0xff, 0xc9,                             /* dec ecx             */
			0x75, 0xf9,                             /* jnz -7              */
			0xf4
		};
		struct kgenome_emu_cfg cfg = { 0 };
		struct kgenome_emu *e;
		uint64_t insn;

		cfg.bits = 64;
		cfg.max_insn = 1u << 20;
		e = kgenome_emu_new(&cfg);
		kgenome_emu_map(e, CODE_VA, mem, sizeof mem, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_map(e, STACK_VA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
		kgenome_emu_set_rip(e, CODE_VA);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
		(void)kgenome_emu_run(e);
		insn = kgenome_emu_insn_count(e);
		if (insn < 3000u) {
			printf("  FAIL a loop that stores was skipped: %llu instructions\n",
			       (unsigned long long)insn);
			failures++;
		}
		kgenome_emu_free(e);
	}

	printf("emu delay loop: counted shapes skipped, state equal to the run lap by lap - %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
