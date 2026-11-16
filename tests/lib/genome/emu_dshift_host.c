/*
 * emu_dshift_host.c - THE UNDEFINED CORNER OF A 16 BIT DOUBLE SHIFT, against the host CPU (DEAD2-1).
 *
 * SHLD/SHRD mask the count with 31, so a 16 bit form can shift by 16..31, past its operand size; the
 * value and the flags there are the silicon's and a protector folds both into a key. The emulator
 * runs that corner on the host where the host is x86-64 (kgenome_emu_host_dshift16). It never did: the
 * switch that enables it was defined in emu_state.c and tested in emu_ops.c, which never saw it, so
 * the instruction stopped the run as unsupported. RED on the code before the fix.
 *
 * ORACLE: the same instruction executed natively here, one per (direction, count, operands), every
 * count 16..31 and the count 48 (masked to 16), the immediate and the CL form; the result and the six
 * modelled flags (CF PF AF ZF SF OF) are compared. Counts below 16 are pinned too (the arithmetic
 * path), so a mutant that sends every count to the host or none is caught. SIMULATED bytes.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <phenotype/emu.h>

#if defined(__x86_64__)

static int fails;
#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

#define CODE  0x400000ull
#define STACK 0x7ff00000ull
#define FL_MASK 0x8d5u                  /* CF PF AF ZF SF OF */

static void native(int left, uint16_t dst, uint16_t src, uint8_t cnt, uint16_t *r, uint64_t *fl)
{
	uint16_t v = dst;
	uint64_t f = 0;

	if (left)
		__asm__ volatile ("shldw %%cl, %2, %0\n\tpushfq\n\tpopq %1" : "+r"(v), "=r"(f) : "r"(src), "c"(cnt) : "cc");
	else
		__asm__ volatile ("shrdw %%cl, %2, %0\n\tpushfq\n\tpopq %1" : "+r"(v), "=r"(f) : "r"(src), "c"(cnt) : "cc");
	*r = v;
	*fl = f;
}

/* shld/shrd bx, ax, cnt (the immediate, or CL when `by_cl`); pushfq; pop rdx; hlt */
static int emulated(int left, int by_cl, uint16_t dst, uint16_t src, uint8_t cnt, uint16_t *r, uint64_t *fl,
		    enum kgenome_emu_stop *stop)
{
	uint8_t c[16];
	unsigned n = 0;
	int ended;
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	c[n++] = 0x66; c[n++] = 0x0f;
	c[n++] = (uint8_t)((left ? 0xa4 : 0xac) + (by_cl ? 1 : 0));
	c[n++] = 0xc3;                  /* modrm: rm = bx, reg = ax */
	if (!by_cl)
		c[n++] = cnt;
	c[n++] = 0x9c;                  /* pushfq  */
	c[n++] = 0x5a;                  /* pop rdx */
	c[n++] = 0xf4;                  /* hlt     */
	memset(&cfg, 0, sizeof cfg);
	cfg.bits = 64;
	cfg.max_insn = 100;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return 0;
	kgenome_emu_map(e, CODE, c, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, STACK, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x800u);
	kgenome_emu_set_reg(e, KGENOME_EMU_RBX, dst);
	kgenome_emu_set_reg(e, KGENOME_EMU_RCX, cnt);
	kgenome_emu_set_reg(e, KGENOME_EMU_RAX, src);
	kgenome_emu_set_rip(e, CODE);
	*stop = kgenome_emu_run(e);
	*r = (uint16_t)kgenome_emu_get_reg(e, KGENOME_EMU_RBX);
	*fl = kgenome_emu_get_reg(e, KGENOME_EMU_RDX);
	ended = kgenome_emu_get_rip(e) == CODE + n - 1u;   /* stopped at the hlt: everything before it ran */
	kgenome_emu_free(e);
	return ended;
}

int main(void)
{
	static const uint16_t vals[][2] = { { 0x1234, 0xabcd }, { 0x8001, 0x7ffe }, { 0, 0xffff },
					    { 0xffff, 0 }, { 0x00ff, 0xff00 }, { 0x5555, 0xaaaa } };
	unsigned d, k, cnt, cl;

	for (d = 0; d < 2; d++)
		for (k = 0; k < sizeof vals / sizeof vals[0]; k++)
			for (cnt = 1; cnt <= 48; cnt++) {
				uint16_t rn, re = 0;
				uint64_t fn, fe = 0;
				enum kgenome_emu_stop st = KGENOME_EMU_STOP_BUDGET;

				if (cnt > 31 && cnt != 48)
					continue;
				native((int)d, vals[k][0], vals[k][1], (uint8_t)cnt, &rn, &fn);
				for (cl = 0; cl < 2; cl++) {
				CK(emulated((int)d, (int)cl, vals[k][0], vals[k][1], (uint8_t)cnt, &re, &fe, &st),
				   "%s %s count %u (%04x,%04x): stopped before the end (%s)", d ? "shld" : "shrd",
				   cl ? "cl" : "imm", cnt, vals[k][0], vals[k][1], kgenome_emu_stop_name(st));
				CK(re == rn, "%s %s count %u (%04x,%04x): %04x, host %04x", d ? "shld" : "shrd",
				   cl ? "cl" : "imm", cnt, vals[k][0], vals[k][1], re, rn);
				/* below the operand size only CF ZF SF PF (and OF at 1) are defined: compare those; at and
				 * past it the host's are the answer, all six */
				{
					uint64_t m = (cnt & 31u) >= 16u ? FL_MASK : (cnt == 1 ? 0x8c5u : 0x0c5u);

					CK((fe & m) == (fn & m), "%s imm count %u (%04x,%04x): flags %03llx, host %03llx",
					   d ? "shld" : "shrd", cnt, vals[k][0], vals[k][1],
					   (unsigned long long)(fe & m), (unsigned long long)(fn & m));
				}
				}
			}
	printf("emu_dshift_host: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}

#else
int main(void)
{
	printf("emu_dshift_host: skipped (the host is not x86-64)\n");
	return 0;
}
#endif
