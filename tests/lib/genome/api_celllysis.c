/*
 * api_celllysis - the analysis-without-running API that no test named: the constant
 * map (cell_state), the cursor over an address space, the capability vocabulary
 * (nucleo), the cross-reference sweep, the library-span lines and the mutation
 * windows - each against its contract, with the boundary values where an end
 * is computed as `start + length` and an index is taken from a file.
 *
 * ONE DIFFERENTIAL, because it is the strongest check available for what the
 * constant map is for: t_map_vs_emulator runs random straight-line x86-64 on the
 * interpreter one instruction at a time and holds every register the map CLAIMS
 * to know against the interpreter's. A map that says "unknown" is never wrong;
 * a map that says a number must say the number. The forms it generates are the
 * ones the map answers correctly today; the 32-bit forms it answers wrongly are
 * pinned as KNOWN-MISS with the shortest repro.
 *
 * Linked against libkgenome.a alone; objects are built in memory by hk.h.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>

#include "hk.h"
#include "../../unit/known_miss.h"

/* ---- the constant map ------------------------------------------------------------------------- */

static uint32_t dec64(const uint8_t *b, unsigned n, uint64_t va, struct kgenome_cell_insn *in)
{
	return kgenome_cell_decode_x86(b, n, va, 64, in);
}

/* decode and track a whole byte string; returns the number of instructions */
static unsigned track_all(struct kgenome_cell_state *st, const uint8_t *b, unsigned n, uint64_t va)
{
	unsigned off = 0, cnt = 0;

	while (off < n) {
		struct kgenome_cell_insn in;
		uint32_t l = dec64(b + off, n - off, va + off, &in);

		if (!l)
			break;
		kgenome_cell_state_track(st, &in);
		off += l;
		cnt++;
	}
	return cnt;
}

static void t_state_basics(void)
{
	struct kgenome_cell_state st;
	uint64_t v = 0;
	unsigned r;

	memset(&st, 0xaa, sizeof st);
	kgenome_cell_state_reset(&st);
	CK(st.known == 0 && st.stk_known == 0 && st.stk_n == 0);
	for (r = 0; r < 16; r++)
		CK(kgenome_cell_state_reg(&st, (uint8_t)r, &v) == 0);
	CK(kgenome_cell_state_stack_top(&st, &v) == 0);
	/* a register number past the file is "not known", never an index */
	CK(kgenome_cell_state_reg(&st, 16, &v) == 0);
	CK(kgenome_cell_state_reg(&st, 0xff, &v) == 0);
	st.known = 0xffff;
	CK(kgenome_cell_state_reg(&st, 16, &v) == 0 && kgenome_cell_state_reg(&st, 255, &v) == 0);
	st.reg[3] = 77;
	CK(kgenome_cell_state_reg(&st, 3, &v) == 1 && v == 77);

	/* xor eax,eax ; mov al,5 ; mov ecx,0x1000 ; add ecx... a constant is a number */
	kgenome_cell_state_reset(&st);
	{
		static const uint8_t code[] = {
			0x31, 0xc0,                                 /* xor eax, eax        */
			0xb0, 0x05,                                 /* mov al, 5           */
			0xb9, 0x00, 0x10, 0, 0,                     /* mov ecx, 0x1000     */
			0x48, 0x89, 0xcb,                           /* mov rbx, rcx        */
			0x48, 0x83, 0xc3, 0x10,                     /* add rbx, 0x10       */
			0x6a, 0x07,                                 /* push 7              */
			0x5a,                                       /* pop rdx             */
		};
		CK(track_all(&st, code, sizeof code, 0x1000) == 7);
		CK(kgenome_cell_state_reg(&st, 0, &v) && v == 5);
		CK(kgenome_cell_state_reg(&st, 1, &v) && v == 0x1000);
		CK(kgenome_cell_state_reg(&st, 3, &v) && v == 0x1010);
		CK(kgenome_cell_state_reg(&st, 2, &v) && v == 7);
		CK(kgenome_cell_state_stack_top(&st, &v) == 0);      /* the pop emptied it */
	}
	/* reset forgets everything */
	kgenome_cell_state_reset(&st);
	CK(kgenome_cell_state_reg(&st, 1, &v) == 0);

	/* the modelled stack: a call pushes the address after it, and the pop that follows
	 * learns it (the call $+5 ; pop idiom) */
	kgenome_cell_state_reset(&st);
	{
		static const uint8_t code[] = { 0xe8, 0, 0, 0, 0, 0x5b };   /* call $+5 ; pop rbx */
		struct kgenome_cell_insn in;
		CK(dec64(code, sizeof code, 0x2000, &in) == 5);
		kgenome_cell_state_track(&st, &in);
		CK(kgenome_cell_state_stack_top(&st, &v) == 1 && v == 0x2005);
		CK(dec64(code + 5, 1, 0x2005, &in) == 1);
		kgenome_cell_state_track(&st, &in);
		CK(kgenome_cell_state_reg(&st, 3, &v) && v == 0x2005);
	}
	/* sixteen slots; the seventeenth drops the oldest rather than refusing */
	kgenome_cell_state_reset(&st);
	{
		struct kgenome_cell_insn in;
		unsigned i;
		for (i = 0; i < KGENOME_CELL_STACK + 5u; i++) {
			uint8_t c[2] = { 0x6a, (uint8_t)(i + 1u) };
			dec64(c, 2, 0, &in);
			kgenome_cell_state_track(&st, &in);
			CK(st.stk_n <= KGENOME_CELL_STACK);
		}
		CK(st.stk_n == KGENOME_CELL_STACK);
		CK(kgenome_cell_state_stack_top(&st, &v) && v == KGENOME_CELL_STACK + 5u);
	}
	/* a pop with nothing modelled forgets the register; a load forgets it too */
	kgenome_cell_state_reset(&st);
	{
		static const uint8_t code[] = { 0xb8, 5, 0, 0, 0, 0x58, 0xb9, 9, 0, 0, 0, 0x8b, 0x09 };
		struct kgenome_cell_insn in;
		unsigned off;

		dec64(code, 5, 0, &in); kgenome_cell_state_track(&st, &in);
		CK(kgenome_cell_state_reg(&st, 0, &v) && v == 5);
		dec64(code + 5, 1, 5, &in); kgenome_cell_state_track(&st, &in);        /* pop rax: empty model */
		CK(kgenome_cell_state_reg(&st, 0, &v) == 0);
		dec64(code + 6, 5, 6, &in); kgenome_cell_state_track(&st, &in);
		CK(kgenome_cell_state_reg(&st, 1, &v) && v == 9);
		off = 11;
		dec64(code + off, 2, off, &in); kgenome_cell_state_track(&st, &in);    /* mov ecx, [rcx] */
		CK(kgenome_cell_state_reg(&st, 1, &v) == 0);
	}
	/* a register against itself is zero, and mul by a known zero clears eax and edx */
	kgenome_cell_state_reset(&st);
	{
		static const uint8_t code[] = { 0x48, 0x31, 0xdb, 0xf7, 0xe3, 0x40, 0xb7, 0x10 };   /* xor rbx,rbx; mul ebx; mov dil,0x10 */
		track_all(&st, code, 5, 0);
		CK(kgenome_cell_state_reg(&st, 3, &v) && v == 0);
		CK(kgenome_cell_state_reg(&st, 0, &v) && v == 0);
		CK(kgenome_cell_state_reg(&st, 2, &v) && v == 0);
	}
	/* cdq after a small known eax gives a known zero edx; after a negative one it is unknown */
	kgenome_cell_state_reset(&st);
	{
		static const uint8_t pos[] = { 0xb8, 5, 0, 0, 0, 0x99 };
		static const uint8_t neg[] = { 0xb8, 0, 0, 0, 0x80, 0x99 };
		track_all(&st, pos, sizeof pos, 0);
		CK(kgenome_cell_state_reg(&st, 2, &v) && v == 0);
		kgenome_cell_state_reset(&st);
		track_all(&st, neg, sizeof neg, 0);
		CK(kgenome_cell_state_reg(&st, 2, &v) == 0);
	}
	/* an operand that is a register number past the file does not index the map */
	{
		struct kgenome_cell_insn in;
		struct kgenome_cell_state s2;
		unsigned k;

		kgenome_cell_state_reset(&s2);
		memset(&in, 0, sizeof in);
		for (k = 0; k < KGENOME_CELL_OP_COUNT; k++) {
			unsigned a;
			in.op = (uint8_t)k;
			in.n_op = 3;
			for (a = 0; a < 3; a++) {
				in.o[a].kind = KGENOME_CELL_O_REG;
				in.o[a].reg = (uint8_t)(15u + 17u * a + k);
				in.o[a].scale = (uint8_t)k;
				in.o[a].size = (uint8_t)(1u << (k & 3u));
			}
			in.wmask = ~0ull;
			in.at_va = KGENOME_BROKEN;
			in.len = 15;
			kgenome_cell_state_track(&s2, &in);
			in.o[0].reg = (uint8_t)(k & 15u);
			in.o[1].kind = KGENOME_CELL_O_IMM;
			in.o[1].imm = UINT64_MAX;
			kgenome_cell_state_track(&s2, &in);
			CK(s2.stk_n <= KGENOME_CELL_STACK);
		}
	}
}

/* ---- the differential: what the map claims, against what the interpreter computes ------------------------ */

static unsigned emit_form(uint8_t *o, struct hk_rng *r, int dangerous)
{
	/* the forms the map answers correctly (and, with `dangerous`, the 32-bit ones it does not) */
	static const unsigned good[] = { 0, 1, 2, 3, 4, 5, 7, 10, 12, 14, 16, 17, 18, 19, 20, 21, 22, 23 };
	static const unsigned bad32[] = { 6, 8, 9, 11, 13, 15 };
	unsigned form = dangerous ? bad32[hk_below(r, sizeof bad32 / sizeof bad32[0])]
				  : good[hk_below(r, sizeof good / sizeof good[0])];
	unsigned n = 0, a = hk_below(r, 8), b = hk_below(r, 8);
	uint32_t imm = (uint32_t)hk_next(r);
	static const uint8_t alu8[] = { 0, 1, 4, 5, 6 };
	static const uint8_t alurr[] = { 0x01, 0x09, 0x21, 0x29, 0x31 };

	if (a == 4)
		a = 3;
	if (b == 4)
		b = 5;
	if (hk_below(r, 3) == 0)
		imm = hk_below(r, 300);
	if (hk_below(r, 6) == 0)
		imm = 0xffffffffu;
	switch (form) {
	case 0:  o[n++] = (uint8_t)(0xb8 + a); memcpy(o + n, &imm, 4); n += 4; break;
	case 1:  { uint64_t v = hk_below(r, 2) ? imm : hk_next(r);
		   o[n++] = 0x48; o[n++] = (uint8_t)(0xb8 + a); memcpy(o + n, &v, 8); n += 8; } break;
	case 2:  o[n++] = 0x48; o[n++] = 0xc7; o[n++] = (uint8_t)(0xc0 + a); memcpy(o + n, &imm, 4); n += 4; break;
	case 3:  o[n++] = (uint8_t)(0xb0 + a); o[n++] = (uint8_t)imm; break;
	case 4:  o[n++] = 0x66; o[n++] = (uint8_t)(0xb8 + a); memcpy(o + n, &imm, 2); n += 2; break;
	case 5:  o[n++] = 0x48; o[n++] = 0x89; o[n++] = (uint8_t)(0xc0 | (b << 3) | a); break;
	case 6:  o[n++] = 0x89; o[n++] = (uint8_t)(0xc0 | (b << 3) | a); break;
	case 7:  o[n++] = 0x48; o[n++] = 0x83; o[n++] = (uint8_t)(0xc0 | (alu8[hk_below(r, 5)] << 3) | a); o[n++] = (uint8_t)imm; break;
	case 8:  o[n++] = 0x83; o[n++] = (uint8_t)(0xc0 | (alu8[hk_below(r, 5)] << 3) | a); o[n++] = (uint8_t)imm; break;
	case 9:  o[n++] = 0x81; o[n++] = (uint8_t)(0xc0 | (alu8[hk_below(r, 5)] << 3) | a); memcpy(o + n, &imm, 4); n += 4; break;
	case 10: o[n++] = 0x48; o[n++] = alurr[hk_below(r, 5)]; o[n++] = (uint8_t)(0xc0 | (b << 3) | a); break;
	case 11: o[n++] = alurr[hk_below(r, 5)]; o[n++] = (uint8_t)(0xc0 | (b << 3) | a); break;
	case 12: o[n++] = 0x48; o[n++] = 0xff; o[n++] = (uint8_t)(0xc0 | (hk_below(r, 2) << 3) | a); break;
	case 13: o[n++] = 0xff; o[n++] = (uint8_t)(0xc0 | (hk_below(r, 2) << 3) | a); break;
	case 14: o[n++] = 0x48; o[n++] = 0xf7; o[n++] = (uint8_t)(0xc0 | ((2 + hk_below(r, 2)) << 3) | a); break;
	case 15: o[n++] = 0xf7; o[n++] = (uint8_t)(0xc0 | ((2 + hk_below(r, 2)) << 3) | a); break;
	case 16: o[n++] = 0x48; o[n++] = 0x87; o[n++] = (uint8_t)(0xc0 | (b << 3) | a); break;
	case 17: o[n++] = 0x6a; o[n++] = (uint8_t)imm; break;
	case 18: o[n++] = 0x99; break;
	case 19: o[n++] = 0x48; o[n++] = 0x99; break;
	case 20: o[n++] = 0xf7; o[n++] = (uint8_t)(0xe0 | a); break;
	case 21: o[n++] = 0x48; o[n++] = 0xf7; o[n++] = (uint8_t)(0xe0 | a); break;
	case 22: o[n++] = (uint8_t)(0x58 + a); break;
	default: o[n++] = (uint8_t)(0x50 + a); break;
	}
	return n;
}

/* returns the number of registers the map claimed wrongly, over `seqs` random sequences */
static unsigned diff_run(uint64_t seed, unsigned seqs, int dangerous, char *first, size_t firstn)
{
	struct hk_rng r = { seed };
	unsigned s, wrong = 0;

	first[0] = 0;
	for (s = 0; s < seqs; s++) {
		uint8_t code[256];
		unsigned n = 0, ni = 0, i, off = 0, reg;
		struct kgenome_emu_cfg cfg = { 100000, 32, 0, 64 };
		struct kgenome_emu *e;
		struct kgenome_cell_state st;

		while (ni < 24) {
			n += emit_form(code + n, &r, dangerous && hk_below(&r, 2));
			ni++;
		}
		code[n++] = 0xf4;
		e = kgenome_emu_new(&cfg);
		kgenome_emu_map(e, 0x400000, code, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_map(e, 0x7ff00000, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
		kgenome_emu_set_rip(e, 0x400000);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, 0x7ff08000);
		kgenome_cell_state_reset(&st);
		for (i = 0; i < ni; i++) {
			struct kgenome_cell_insn in;
			uint32_t l = dec64(code + off, n - off, 0x400000u + off, &in);

			if (!l) {
				kgenome_emu_free(e);
				return wrong + 1000u;
			}
			kgenome_cell_state_track(&st, &in);
			if (kgenome_emu_step(e) != KGENOME_EMU_STOP_BUDGET)
				break;
			for (reg = 0; reg < 16; reg++) {
				uint64_t v;
				if (reg == KGENOME_CELL_REG_SP)
					continue;
				if (kgenome_cell_state_reg(&st, (uint8_t)reg, &v) &&
				    v != kgenome_emu_get_reg(e, reg)) {
					if (!wrong++ && firstn) {
						unsigned q;
						int w = snprintf(first, firstn, "reg %u map=%#llx emu=%#llx after:", reg,
								 (unsigned long long)v,
								 (unsigned long long)kgenome_emu_get_reg(e, reg));
						for (q = 0; q < l && w > 0 && (size_t)w < firstn; q++)
							w += snprintf(first + w, firstn - (size_t)w, " %02x", code[off + q]);
					}
				}
			}
			off += l;
		}
		kgenome_emu_free(e);
	}
	return wrong;
}

static int fam_map_vs_emu(void *arg)
{
	char first[160];
	unsigned wrong = diff_run(0x1001 * (1u + (unsigned)(uintptr_t)arg), 400u * hk_scale(), 0, first, sizeof first);

	if (wrong)
		printf("  FAIL constant map disagrees with the interpreter %u times; first: %s\n", wrong, first);
	return wrong != 0;
}

/* The 32-bit forms: the map keeps a 64-bit result where the instruction zero-extends a 32-bit one */
static int km_map_32bit(void *arg)
{
	struct kgenome_cell_state st;
	uint64_t v = 0;
	/* mov ecx, 0xffffffff ; inc ecx : the interpreter (and the CPU) leave rcx = 0 */
	static const uint8_t inc[] = { 0xb9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc1 };
	/* mov rbx, 0x1122334455667788 ; mov ebx, ebx : the upper half is cleared */
	static const uint8_t mov[] = { 0x48, 0xbb, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x89, 0xdb };
	int rc = 0;

	(void)arg;
	kgenome_cell_state_reset(&st);
	track_all(&st, inc, sizeof inc, 0);
	if (kgenome_cell_state_reg(&st, 1, &v) && v != 0)
		rc |= 1;
	kgenome_cell_state_reset(&st);
	track_all(&st, mov, sizeof mov, 0);
	if (kgenome_cell_state_reg(&st, 3, &v) && v != 0x55667788ull)
		rc |= 2;
	return rc;
}

static void t_map_vs_emulator(void)
{
	static unsigned seeds[2] = { 0, 1 };
	int sig = 0, i;
	char first[160];
	unsigned wrong;

	for (i = 0; i < 2; i++)
		CK(hk_isolated(fam_map_vs_emu, (void *)(uintptr_t)seeds[i], 60, &sig) == HK_OK);
	/* and the shape of the miss, measured: it is the 32-bit forms and only them */
	wrong = diff_run(77, 300, 1, first, sizeof first);
	CK(wrong > 0);      /* while the miss stands this is non-zero: the KM below flips with it */
	KM_CHECK(hk_isolated(km_map_32bit, NULL, 10, &sig) == HK_OK,
		 "the constant map keeps a 64-bit result for a 32-bit operation on a known register",
		 "celllysis/cell_state.c kgenome_cell_state_track, the INC/DEC/NOT/NEG/ADD/SUB/AND/OR/XOR arms and "
		 "the register-to-register MOV (cell_put only narrows sizes 1 and 2): `mov ecx,0xffffffff ; inc ecx` "
		 "leaves rcx known as 0x100000000 where the instruction leaves 0, and `mov rbx,0x1122334455667788 ; "
		 "mov ebx,ebx` leaves the upper half. 4466 of 48000 claims disagreed with the interpreter in the "
		 "random run, every one a 32-bit form (opcodes 89 /r, 81 /r, 83 /r, FF /0-1, F7 /2-3 without REX.W)");
}

/* ---- the cursor and the address space ------------------------------------------------------------------- */

struct cb_log { unsigned seg_calls, va_calls; };

static int seg_ident(void *priv, uint64_t off, struct kgenome_image_seg *out)
{
	struct cb_log *l = (struct cb_log *)priv;

	l->seg_calls++;
	out->lo = 0;
	out->hi = 0x1000;
	out->delta = 0x400000;
	return off < 0x1000;
}

static uint64_t va_ident(void *priv, uint64_t va)
{
	struct cb_log *l = (struct cb_log *)priv;

	l->va_calls++;
	return va >= 0x400000 && va < 0x401000 ? va - 0x400000 : KGENOME_BROKEN;
}

static void t_cursor(void)
{
	/* 0: mov eax, 0x401010     (b8)
	 * 5: call eax              (ff d0)   -> the target is read from the map: file offset 0x10
	 * 7: jmp +9                (eb 07)   -> direct, offset 0x10
	 * 9: ret                   (c3)
	 * 10: nop ; ...            */
	static uint8_t code[0x20];
	struct cb_log lg = { 0, 0 };
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	uint64_t v = 0;

	memset(code, 0x90, sizeof code);
	code[0] = 0xb8; code[1] = 0x10; code[2] = 0x00; code[3] = 0x40; code[4] = 0x00;
	code[5] = 0xff; code[6] = 0xd0;
	code[7] = 0xeb; code[8] = 0x07;
	code[9] = 0xc3;
	memset(&sp, 0, sizeof sp);
	sp.base = code;
	sp.size = sizeof code;
	sp.arch = KGENOME_ARCH_X86;
	sp.priv = &lg;
	sp.seg_at = seg_ident;
	sp.off_of_va = va_ident;
	memset(&k, 0, sizeof k);

	/* nothing before a seek */
	CK(kgenome_cell_next(&k, &sp, &in) == 0);
	CK(kgenome_cell_step(&k, &sp, &in) == 0);
	CK(kgenome_cell_seek(NULL, 0, 0) == 0);
	CK(kgenome_cell_reg(NULL, 0, &v) == 0);
	CK(kgenome_cell_seek(&k, 0, 0) == 1);

	CK(kgenome_cell_next(&k, &sp, &in) == 1);
	CK(in.op == KGENOME_CELL_MOV && in.len == 5 && in.at == 0 && in.at_va == 0x400000);
	CK(k.at == 5);
	CK(kgenome_cell_reg(&k, 0, &v) == 1 && v == 0x400010);
	/* the call through eax: the target is the value the map holds, resolved to a file offset */
	CK(kgenome_cell_next(&k, &sp, &in) == 1);
	CK(in.op == KGENOME_CELL_CALL && in.target_va == 0x400010 && in.target == 0x10);
	CK(kgenome_cell_next(&k, &sp, &in) == 1);
	CK(in.op == KGENOME_CELL_JMP && in.target == 0x10 && in.target_va == 0x400010);
	/* step does the same walk without the map: the register is not resolved */
	CK(kgenome_cell_seek(&k, 0, 0) == 1);
	CK(kgenome_cell_step(&k, &sp, &in) == 1 && k.at == 5);
	CK(kgenome_cell_reg(&k, 0, &v) == 0);
	CK(kgenome_cell_step(&k, &sp, &in) == 1 && in.op == KGENOME_CELL_CALL && in.target == KGENOME_BROKEN);
	/* seek keeps the map when asked */
	CK(kgenome_cell_seek(&k, 0, 0) == 1);
	CK(kgenome_cell_next(&k, &sp, &in) == 1);
	CK(kgenome_cell_seek(&k, 5, 1) == 1);
	CK(kgenome_cell_reg(&k, 0, &v) == 1 && v == 0x400010);
	CK(kgenome_cell_seek(&k, 5, 0) == 1);
	CK(kgenome_cell_reg(&k, 0, &v) == 0);
	/* the end of the space and beyond it */
	CK(kgenome_cell_seek(&k, sizeof code, 0) == 1);
	CK(kgenome_cell_next(&k, &sp, &in) == 0);
	CK(kgenome_cell_seek(&k, UINT64_MAX, 0) == 1);
	CK(kgenome_cell_next(&k, &sp, &in) == 0 && kgenome_cell_step(&k, &sp, &in) == 0);
	CK(kgenome_cell_seek(&k, sizeof code - 1u, 0) == 1);
	CK(kgenome_cell_next(&k, &sp, &in) == 1 && in.len == 1);          /* the last byte: a nop */
	CK(kgenome_cell_next(&k, &sp, &in) == 0);
	/* an instruction cut by the end of the space is refused, not read past it */
	{
		uint8_t b2[3] = { 0xb8, 1, 2 };
		struct kgenome_cell_space s2 = sp;
		s2.base = b2;
		s2.size = sizeof b2;
		CK(kgenome_cell_seek(&k, 0, 0) == 1);
		CK(kgenome_cell_next(&k, &s2, &in) == 0);
	}
	/* NULL space, NULL base, NULL out */
	CK(kgenome_cell_seek(&k, 0, 0) == 1);
	CK(kgenome_cell_next(&k, NULL, &in) == 0);
	CK(kgenome_cell_next(&k, &sp, NULL) == 0);
	{
		struct kgenome_cell_space s3 = sp;
		s3.base = NULL;
		CK(kgenome_cell_next(&k, &s3, &in) == 0 && kgenome_cell_step(&k, &s3, &in) == 0);
		s3 = sp;
		s3.seg_at = NULL;
		s3.off_of_va = NULL;
		CK(kgenome_cell_next(&k, &s3, &in) == 1);           /* callbacks are optional: no address */
		CK(in.at_va == KGENOME_BROKEN);
	}
	CK(lg.seg_calls > 0);
}

static void t_space_big_endian(void)
{
	static struct hk_elf e;
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_cell_space sp;
	unsigned be;

	for (be = 0; be < 2; be++) {
		hk_elf(&e, 0, (int)be, 0);
		hk_w(e.b + 18, 8, 2, (int)be);               /* EM_MIPS */
		memset(&ei, 0, sizeof ei);
		CK(kgenome_elf_image_parse(kof_buf_make(e.b, e.n), &ei, &o));
		o.file_header = &ei;
		CK(ei.elf_data == (be ? KGENOME_ELFDATA_BE : KGENOME_ELFDATA_LE));
		kgenome_cell_space_init(&sp, &o, e.b, e.n);
		CK(sp.base == e.b && sp.size == e.n && sp.arch == o.arch);
		CK(sp.seg_at != NULL && sp.off_of_va != NULL && sp.priv == &o);
		if (!be)
			CK(sp.be == 0);
	}
}

static int km_space_be(void *arg)
{
	static struct hk_elf e;
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_cell_space sp;

	(void)arg;
	hk_elf(&e, 0, 1, 0);
	hk_w(e.b + 18, 8, 2, 1);
	memset(&ei, 0, sizeof ei);
	if (!kgenome_elf_image_parse(kof_buf_make(e.b, e.n), &ei, &o) || ei.elf_data != KGENOME_ELFDATA_BE)
		return 2;
	o.file_header = &ei;
	kgenome_cell_space_init(&sp, &o, e.b, e.n);
	return sp.be == 1 ? 0 : 1;
}

/* ---- the capability vocabulary ----------------------------------------------------------------------------- */

static void t_nucleo(void)
{
	uint8_t fl = 0xff;
	uint64_t a[8];
	unsigned arch, i;
	const struct kgenome_nucleo_abi *fx;

	/* x86-64 mmap(NULL, len, prot, ...): PROT_EXEC makes it an executable allocation, W+X when writable */
	memset(a, 0, sizeof a);
	a[2] = 3;
	CK(kgenome_nucleo_cap_of_syscall(64, 9, a, &fl) == KGENOME_NUCLEO_ALLOC && fl == 0);
	a[2] = 5;
	CK(kgenome_nucleo_cap_of_syscall(64, 9, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == 0);
	a[2] = 7;
	CK(kgenome_nucleo_cap_of_syscall(64, 9, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == KGENOME_NUCLEO_F_WX);
	CK(kgenome_nucleo_cap_of_syscall(64, 10, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC);      /* mprotect */
	CK(kgenome_nucleo_cap_of_syscall(64, 9, NULL, &fl) == KGENOME_NUCLEO_ALLOC && fl == 0);   /* no arguments: the number only */
	CK(kgenome_nucleo_cap_of_syscall(64, 9, a, NULL) == KGENOME_NUCLEO_ALLOC_EXEC);   /* flags are optional */
	CK(kgenome_nucleo_cap_of_syscall(32, 192, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC);   /* mmap2 */
	CK(kgenome_nucleo_cap_of_syscall(32, 125, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC);
	/* an unknown number is NONE, however large */
	CK(kgenome_nucleo_cap_of_syscall(64, 0xfffffffeu, a, &fl) == KGENOME_NUCLEO_NONE && fl == 0);
	CK(kgenome_nucleo_cap_of_syscall(64, 0xffffffffu, NULL, NULL) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_syscall(32, 0x7fffffffu, NULL, NULL) == KGENOME_NUCLEO_NONE);
	/* socket(domain, type): SOCK_RAW, AF_UNIX, SOCK_DGRAM */
	memset(a, 0, sizeof a);
	a[0] = 2; a[1] = 1;
	CK(kgenome_nucleo_cap_of_syscall(64, 41, a, &fl) == KGENOME_NUCLEO_NET_OPEN && fl == 0);
	a[1] = 3;
	CK(kgenome_nucleo_cap_of_syscall(64, 41, a, &fl) == KGENOME_NUCLEO_NET_RAW);
	a[1] = 2;
	CK(kgenome_nucleo_cap_of_syscall(64, 41, a, &fl) == KGENOME_NUCLEO_NET_OPEN && (fl & KGENOME_NUCLEO_F_DGRAM));
	a[0] = 1;
	CK(kgenome_nucleo_cap_of_syscall(64, 41, a, &fl) == KGENOME_NUCLEO_NET_OPEN && (fl & KGENOME_NUCLEO_F_LOCAL));
	a[0] = 0x101; a[1] = 0x80801;                   /* the high bits of the type are SOCK_NONBLOCK|CLOEXEC */
	CK(kgenome_nucleo_cap_of_syscall(64, 41, a, &fl) == KGENOME_NUCLEO_NET_OPEN);
	/* clone(flags): CLONE_THREAD makes a thread of it */
	memset(a, 0, sizeof a);
	CK(kgenome_nucleo_cap_of_syscall(64, 56, a, &fl) == KGENOME_NUCLEO_SPAWN);
	a[0] = KGENOME_NUCLEO_CLONE_THREAD;
	CK(kgenome_nucleo_cap_of_syscall(64, 56, a, &fl) == KGENOME_NUCLEO_THREAD);
	CK(kgenome_nucleo_cap_of_syscall(32, 120, a, &fl) == KGENOME_NUCLEO_THREAD);
	/* fcntl(fd, F_SETFL, O_NONBLOCK) and setsockopt(IPPROTO_IP, IP_HDRINCL) are claims only when read */
	memset(a, 0, sizeof a);
	a[1] = 4; a[2] = 0x800;
	CK(kgenome_nucleo_cap_of_syscall(64, 72, a, &fl) == KGENOME_NUCLEO_FD_NONBLOCK);
	a[2] = 0x7ff;
	CK(kgenome_nucleo_cap_of_syscall(64, 72, a, &fl) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_syscall(64, 72, NULL, &fl) == KGENOME_NUCLEO_NONE);
	memset(a, 0, sizeof a);
	a[1] = 0; a[2] = 3;
	CK(kgenome_nucleo_cap_of_syscall(64, 54, a, &fl) == KGENOME_NUCLEO_NET_HDRINCL);
	a[2] = 4;
	CK(kgenome_nucleo_cap_of_syscall(64, 54, a, &fl) == KGENOME_NUCLEO_NONE);
	a[1] = 0x100000000ull; a[2] = 3;              /* only the low 32 bits are the level */
	CK(kgenome_nucleo_cap_of_syscall(64, 54, a, &fl) == KGENOME_NUCLEO_NET_HDRINCL);
	/* the flags-valued argument: only fcntl's third */
	CK(kgenome_nucleo_arg_is_flags(64, 72, 2) == 1 && kgenome_nucleo_arg_is_flags(64, 72, 1) == 0);
	CK(kgenome_nucleo_arg_is_flags(32, 55, 2) == 1 && kgenome_nucleo_arg_is_flags(32, 221, 2) == 1);
	CK(kgenome_nucleo_arg_is_flags(32, 72, 2) == 0 && kgenome_nucleo_arg_is_flags(64, 55, 2) == 0);
	CK(kgenome_nucleo_arg_is_flags(64, 72, 0xffffffffu) == 0 && kgenome_nucleo_arg_is_flags(0, 0xffffffffu, 0) == 0);
	/* socket(.., SOCK_NONBLOCK) */
	memset(a, 0, sizeof a);
	a[1] = 0x801;
	CK(kgenome_nucleo_sock_nonblock(64, 41, a, 2) == 1);
	CK(kgenome_nucleo_sock_nonblock(64, 41, a, 0) == 0);          /* the argument was not read */
	CK(kgenome_nucleo_sock_nonblock(64, 41, NULL, 0) == 0);
	CK(kgenome_nucleo_sock_nonblock(32, 359, a, 2) == 1);
	CK(kgenome_nucleo_sock_nonblock(64, 359, a, 2) == 0 && kgenome_nucleo_sock_nonblock(32, 41, a, 2) == 0);
	a[1] = 1;
	CK(kgenome_nucleo_sock_nonblock(64, 41, a, 2) == 0);
	CK(kgenome_nucleo_sockcall_nonblock(1, a, 2) == 0);
	a[1] = 0x800;
	CK(kgenome_nucleo_sockcall_nonblock(1, a, 2) == 1 && kgenome_nucleo_sockcall_nonblock(2, a, 2) == 0);
	CK(kgenome_nucleo_sockcall_nonblock(1, NULL, 0) == 0 && kgenome_nucleo_sockcall_nonblock(1, a, 1) == 0);
	CK(kgenome_nucleo_sockcall_nonblock(0xffffffffu, a, 0xffffffffu) == 0);
	/* socketcall: the operation picks the word, and `have` says which arguments were read */
	memset(a, 0, sizeof a);
	a[0] = 2; a[1] = 3;
	CK(kgenome_nucleo_cap_of_sockcall(1, a, 3, &fl) == KGENOME_NUCLEO_NET_RAW);
	CK(kgenome_nucleo_cap_of_sockcall(1, a, 1, &fl) == KGENOME_NUCLEO_NET_OPEN);   /* the type was not read: not refined */
	CK(kgenome_nucleo_cap_of_sockcall(1, NULL, 3, &fl) == KGENOME_NUCLEO_NET_OPEN);
	CK(kgenome_nucleo_cap_of_sockcall(3, a, 0, &fl) == KGENOME_NUCLEO_NET_CONNECT);
	CK(kgenome_nucleo_cap_of_sockcall(0, a, 3, &fl) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_sockcall(0xffffffffu, a, 3, NULL) == KGENOME_NUCLEO_NONE);
	a[1] = 0; a[2] = 3;
	CK(kgenome_nucleo_cap_of_sockcall(14, a, 6, &fl) == KGENOME_NUCLEO_NET_HDRINCL);
	CK(kgenome_nucleo_cap_of_sockcall(14, a, 2, &fl) != KGENOME_NUCLEO_NET_HDRINCL);
	a[0] = 1;                                              /* i386: socketcall (102) with the operation in arg 0 */
	CK(kgenome_nucleo_cap_of_syscall(32, 102, a, &fl) == KGENOME_NUCLEO_NET_OPEN);
	CK(kgenome_nucleo_cap_of_syscall(32, 102, NULL, &fl) == KGENOME_NUCLEO_NONE);

	/* the names of syscalls */
	CK(!strcmp(kgenome_nucleo_sys_name(64, 41), "socket") && !strcmp(kgenome_nucleo_sys_name(64, 9), "mmap"));
	CK(!strcmp(kgenome_nucleo_sys_name(32, 102), "socketcall") && !strcmp(kgenome_nucleo_sys_name(32, 3), "read"));
	CK(kgenome_nucleo_sys_name(64, 0xfffffffeu) == NULL && kgenome_nucleo_sys_name(32, 0xffffffffu) == NULL);
	CK(!strcmp(kgenome_nucleo_sys_name(0, 3), "read"));              /* any `bits` but 64 is the 32-bit table */
	CK(kgenome_nucleo_sys_name(0, 41) == NULL);

	/* the per-architecture tables: every ABI is there, rows have names, numbers are unique */
	for (arch = 0; arch < 20; arch++) {
		fx = kgenome_nucleo_abi_of(arch);
		CK(fx != NULL && fx->tab != NULL && fx->n_tab > 0 && fx->n_arg >= 3 && fx->n_arg <= 8);
		CK(fx->prot_arg < fx->n_arg);
		for (i = 0; i < fx->n_tab; i++) {
			uint32_t j;
			CK(fx->tab[i].name && fx->tab[i].name[0]);
			for (j = i + 1u; j < fx->n_tab; j++)
				if (fx->tab[i].nr == fx->tab[j].nr)
					CK(0);
			CK(kgenome_nucleo_sys_name_abi(fx, fx->tab[i].nr) != NULL);
		}
	}
	CK(kgenome_nucleo_abi_of(0xffffffffu) == kgenome_nucleo_abi_of(0));          /* anything else is the default ABI */
	CK(kgenome_nucleo_abi_of(KGENOME_NUCLEO_A_PPC32) == kgenome_nucleo_abi_of(KGENOME_NUCLEO_A_PPC64));
	CK(kgenome_nucleo_abi_of(KGENOME_NUCLEO_A_ARM32) != kgenome_nucleo_abi_of(KGENOME_NUCLEO_A_MIPS32));
	/* AArch64: mmap is 222 and clone is 220 */
	fx = kgenome_nucleo_abi_of(KGENOME_NUCLEO_A_ARM64);
	CK(!strcmp(kgenome_nucleo_sys_name_abi(fx, 222), "mmap") && !strcmp(kgenome_nucleo_sys_name_abi(fx, 220), "clone"));
	CK(kgenome_nucleo_sys_name_abi(fx, 0xffffffffu) == NULL && kgenome_nucleo_sys_name_abi(fx, 9999) == NULL);
	memset(a, 0, sizeof a);
	a[2] = 7;
	CK(kgenome_nucleo_cap_of_syscall_abi(fx, 222, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == KGENOME_NUCLEO_F_WX);
	a[2] = 4;
	CK(kgenome_nucleo_cap_of_syscall_abi(fx, 226, a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == 0);
	CK(kgenome_nucleo_cap_of_syscall_abi(fx, 222, NULL, &fl) == KGENOME_NUCLEO_ALLOC);
	CK(kgenome_nucleo_cap_of_syscall_abi(fx, 0xffffffffu, a, &fl) == KGENOME_NUCLEO_NONE && fl == 0);
	memset(a, 0, sizeof a);
	a[0] = KGENOME_NUCLEO_CLONE_THREAD;
	CK(kgenome_nucleo_cap_of_syscall_abi(fx, 220, a, NULL) == KGENOME_NUCLEO_THREAD);
	a[0] = 1; a[1] = 3;
	CK(kgenome_nucleo_cap_of_syscall_abi(fx, 198, a, &fl) == KGENOME_NUCLEO_NET_RAW);

	/* names (imports) */
	CK(kgenome_nucleo_cap_of_name("mmap") == KGENOME_NUCLEO_ALLOC);
	CK(kgenome_nucleo_cap_of_name("mmap64@@GLIBC_2.2.5") == KGENOME_NUCLEO_ALLOC);       /* a version suffix is the same function */
	CK(kgenome_nucleo_cap_of_name("mmapx") == KGENOME_NUCLEO_NONE && kgenome_nucleo_cap_of_name("mma") == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_name("") == KGENOME_NUCLEO_NONE && kgenome_nucleo_cap_of_name(NULL) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_name("@") == KGENOME_NUCLEO_NONE && kgenome_nucleo_cap_of_name("@@x") == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_name("malloc") == KGENOME_NUCLEO_HEAP);
	CK(kgenome_nucleo_cap_of_name("recv") != KGENOME_NUCLEO_NONE && kgenome_nucleo_cap_of_name("recvfrom") != KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_name("VirtualAlloc") == KGENOME_NUCLEO_ALLOC);
	{
		char big[5000];
		memset(big, 'm', sizeof big - 1u);
		big[sizeof big - 1u] = 0;
		CK(kgenome_nucleo_cap_of_name(big) == KGENOME_NUCLEO_NONE);
	}
	/* name ids: 0 is "none", every id round-trips, past the end is NULL */
	CK(kgenome_nucleo_name_id("mmap") != 0 && !strcmp(kgenome_nucleo_name_of(kgenome_nucleo_name_id("mmap")), "mmap"));
	CK(kgenome_nucleo_name_id("mmap@@GLIBC_2.2.5") == kgenome_nucleo_name_id("mmap"));
	CK(kgenome_nucleo_name_id("nonexistent_function") == 0 && kgenome_nucleo_name_id(NULL) == 0 && kgenome_nucleo_name_id("") == 0);
	CK(kgenome_nucleo_name_of(0) == NULL && kgenome_nucleo_name_of(0xffffu) == NULL);
	{
		unsigned id, last = 0;
		for (id = 1; id < 0x10000u; id++) {
			const char *nm = kgenome_nucleo_name_of((uint16_t)id);
			if (!nm)
				break;
			last = id;
			if (kgenome_nucleo_name_id(nm) != id && kgenome_nucleo_cap_of_name(nm) == KGENOME_NUCLEO_NONE)
				CK(0);
			CK(kgenome_nucleo_cap_of_name(nm) != KGENOME_NUCLEO_NONE);
		}
		CK(last > 50);
		CK(kgenome_nucleo_name_of((uint16_t)(last + 1u)) == NULL);
	}
	/* a named call refined by its arguments: VirtualAlloc(addr, size, type, protect) */
	memset(a, 0, sizeof a);
	a[3] = 0x40;                                    /* PAGE_EXECUTE_READWRITE */
	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == KGENOME_NUCLEO_F_WX);
	a[3] = 0x20;                                    /* PAGE_EXECUTE_READ */
	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == 0);
	a[3] = 0x04;                                    /* PAGE_READWRITE */
	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", a, &fl) == KGENOME_NUCLEO_ALLOC);
	a[2] = 0x40;
	CK(kgenome_nucleo_cap_of_call("VirtualProtect", a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC);
	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", NULL, &fl) == KGENOME_NUCLEO_ALLOC && fl == 0);
	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", a, NULL) != KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_call("nothing_here", a, &fl) == KGENOME_NUCLEO_NONE && fl == 0);
	CK(kgenome_nucleo_cap_of_call(NULL, a, &fl) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_call("", a, &fl) == KGENOME_NUCLEO_NONE);
	a[0] = 2; a[1] = 3;
	CK(kgenome_nucleo_cap_of_call("socket", a, &fl) == KGENOME_NUCLEO_NET_RAW);
	CK(kgenome_nucleo_cap_of_call("WSASocketA", a, &fl) == KGENOME_NUCLEO_NET_RAW);
	CK(kgenome_nucleo_cap_of_call("mprotect", a, &fl) == KGENOME_NUCLEO_ALLOC);     /* named: no PROT argument is read */

	/* the generic level: net-recv is a kind of mem-read; nothing else has one */
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_NET_READ) == KGENOME_NUCLEO_MEM_READ);
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_READ) == KGENOME_NUCLEO_MEM_READ);
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_NET_WRITE) == KGENOME_NUCLEO_MEM_WRITE);
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_WRITE) == KGENOME_NUCLEO_MEM_WRITE);
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_ALLOC_EXEC) == KGENOME_NUCLEO_ALLOC);
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_ALLOC) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_generic(KGENOME_NUCLEO_NONE) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_generic(0xffffu) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_named(KGENOME_NUCLEO_ALLOC) == 1 && kgenome_nucleo_cap_named(KGENOME_NUCLEO_NONE) == 0);
	CK(kgenome_nucleo_cap_named(KGENOME_NUCLEO_MEM_READ) == 1);       /* named through a kind of it */
	CK(kgenome_nucleo_cap_named(0xffffu) == 0);
	/* which calls hand the guest something to hold */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "mmap") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "mprotect") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "mprotect64") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, NULL) == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC_EXEC, "VirtualAlloc") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_NET_OPEN, NULL) == 1 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "open") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_MEM_READ, "read") == 0 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_NONE, "x") == 0);
	CK(kgenome_nucleo_hands_on(0xffffu, NULL) == 0);
	/* which argument names the word the kernel symbol resolver is asked for */
	{
		unsigned arg = 99;
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_KSYM_LOOKUP, &arg) == KGENOME_NAME_DIRECT && arg == 0);
		arg = 99;
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_KPROBE_REG, &arg) == KGENOME_NAME_OBJECT && arg == 0);
		arg = 99;
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_ALLOC, &arg) == 0 && arg == 0);
		CK(kgenome_nucleo_name_arg(0xffffu, NULL) == 0);
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_SYMBOL_GET, NULL) == KGENOME_NAME_DIRECT);
	}
	/* success-is-zero names */
	CK(kgenome_nucleo_sys_zero_on_success("connect") == 1 && kgenome_nucleo_sys_zero_on_success("munmap") == 1);
	CK(kgenome_nucleo_sys_zero_on_success("socket") == 0 && kgenome_nucleo_sys_zero_on_success("execve") == 0);
	CK(kgenome_nucleo_sys_zero_on_success(NULL) == 0 && kgenome_nucleo_sys_zero_on_success("") == 0);
	CK(kgenome_nucleo_sys_zero_on_success("connectx") == 0 && kgenome_nucleo_sys_zero_on_success("connec") == 0);
}

/* ---- the cross-reference sweep ------------------------------------------------------------------------------ */

static void feed_code(struct kgenome_xref *u, const uint8_t *b, unsigned n, uint64_t va)
{
	unsigned off = 0;

	while (off < n) {
		struct kgenome_cell_insn in;
		uint32_t l = dec64(b + off, n - off, va + off, &in);

		if (!l) {
			kgenome_xref_feed(u, NULL);
			off++;
			continue;
		}
		kgenome_xref_feed(u, &in);
		off += l;
	}
}

static void t_xref(void)
{
	/* code at 0x1000; the payload variable at 0x3000, another at 0x3010 */
	static const uint8_t code[] = {
		0x48, 0x8b, 0x05, 0xf9, 0x1f, 0x00, 0x00,       /* 1000: mov rax, [rip+0x1ff9] -> 0x3000 */
		0xff, 0xd0,                                     /* 1007: call rax                        */
		0x48, 0x8d, 0x3d, 0x00, 0x20, 0x00, 0x00,       /* 1009: lea rdi, [rip+0x2000]  -> 0x3010 */
		0xc7, 0x05, 0xf6, 0x1f, 0x00, 0x00, 1, 0, 0, 0, /* 1010: mov dword [rip+0x1ff6], 1 -> 0x3010+? */
		0xc3,                                           /* 101a: ret                             */
	};
	struct kgenome_xref *u = kgenome_xref_new();
	uint32_t f;

	CK(u != NULL);
	CK(kgenome_xref_full(u) == 0);
	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	feed_code(u, code, sizeof code, 0x1000);
	f = kgenome_xref_in(u, 0x3000, 8);
	CK((f & KGENOME_XREF_READ) && (f & KGENOME_XREF_CALL));              /* loaded, then called: executed */
	CK(!(f & KGENOME_XREF_WRITE));
	CK(f & KGENOME_XREF_RGN_ICALL);                                       /* the region makes an indirect call */
	f = kgenome_xref_in(u, 0x3010, 1);
	CK(f & KGENOME_XREF_READ);
	CK(!(f & KGENOME_XREF_CALL));
	CK(kgenome_xref_in(u, 0x9000, 8) == 0);
	/* a range: a reference in the middle of the variable counts */
	CK(kgenome_xref_in(u, 0x2ff8, 16) & KGENOME_XREF_CALL);
	CK((kgenome_xref_in(u, 0x2fff, 1)) == 0);
	CK(kgenome_xref_in(u, 0x3000, 0) != 0);                               /* n < 1 is 1 */
	CK(kgenome_xref_in(NULL, 0x3000, 8) == 0 && kgenome_xref_in(u, 0, 8) == 0);
	/* every question twice gives the same answer */
	CK(kgenome_xref_in(u, 0x3000, 8) == kgenome_xref_in(u, 0x3000, 8));
	/* a run begun for another architecture records nothing */
	{
		struct kgenome_xref *v = kgenome_xref_new();
		kgenome_xref_begin(v, KGENOME_ARCH_ARM64);
		feed_code(v, code, sizeof code, 0x1000);
		CK(kgenome_xref_in(v, 0x3000, 8) == 0 && kgenome_xref_full(v) == 0);
		kgenome_xref_free(v);
		v = kgenome_xref_new();                /* and one never begun */
		feed_code(v, code, sizeof code, 0x1000);
		CK(kgenome_xref_in(v, 0x3000, 8) == 0);
		kgenome_xref_free(v);
	}
	/* NULL handles are ignored */
	kgenome_xref_begin(NULL, KGENOME_ARCH_X86_64);
	kgenome_xref_feed(NULL, NULL);
	kgenome_xref_free(NULL);
	CK(kgenome_xref_full(NULL) == 0);
	CK(kgenome_xref_startup(NULL, 0x1000) == 0);
	/* startup: room for 64 regions; past that it says no */
	{
		unsigned i, ok = 0;
		for (i = 0; i < 100; i++)
			ok += (unsigned)kgenome_xref_startup(u, 0x1000u + i);
		CK(ok == 64);
		CK(kgenome_xref_startup(u, 0) == 0);            /* full: even a no-op is refused */
	}
	kgenome_xref_free(u);

	/* a fresh sweep: the startup address makes the code that begins there "not the user's" */
	u = kgenome_xref_new();
	CK(kgenome_xref_startup(u, 0) == 1);               /* va 0 is ignored but acknowledged */
	CK(kgenome_xref_startup(u, 0x1000) == 1);
	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	feed_code(u, code, sizeof code, 0x1000);
	(void)kgenome_xref_in(u, 0x3000, 8);
	kgenome_xref_free(u);

	/* the table of distinct addresses holds 512; the 513th sets full and the answers say partial */
	u = kgenome_xref_new();
	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	{
		unsigned i;
		for (i = 0; i < KGENOME_XREF_MAX + 100u; i++) {
			struct kgenome_cell_insn in;
			static const uint8_t ld[] = { 0x48, 0x8b, 0x05, 0, 0, 0, 0 };    /* mov rax, [rip+disp] */
			uint8_t b[7];
			memcpy(b, ld, 7);
			hk_w(b + 3, 0x100000u + 16u * i, 4, 0);
			dec64(b, 7, 0x1000, &in);
			kgenome_xref_feed(u, &in);
		}
		CK(kgenome_xref_full(u) == 1);
		/* the first 512 distinct addresses are kept, so a query for one of them still answers */
		CK(kgenome_xref_in(u, 0x101007, 1) != 0);
	}
	kgenome_xref_free(u);
}

/* the end of a range is computed as va + n: a range that wraps the address space is still a range */
static int km_xref_wrap(void *arg)
{
	static const uint8_t code[] = { 0x48, 0x8b, 0x05, 0xf9, 0x1f, 0x00, 0x00, 0xff, 0xd0 };
	struct kgenome_xref *u = kgenome_xref_new();
	uint32_t f;

	(void)arg;
	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	feed_code(u, code, sizeof code, 0x1000);
	f = kgenome_xref_in(u, 0x3000, 8);
	if (!(f & KGENOME_XREF_CALL))
		return 2;
	/* the same variable, asked about with a declared size of 2^64-1 (a symbol's st_size) */
	f = kgenome_xref_in(u, 0x3000, UINT64_MAX);
	kgenome_xref_free(u);
	return (f & KGENOME_XREF_CALL) ? 0 : 1;
}

/* a query is a read: it must not freeze the answers to what had been fed by then */
static int km_xref_stale(void *arg)
{
	static const uint8_t load[] = { 0x48, 0x8b, 0x05, 0xf9, 0x1f, 0x00, 0x00 };      /* -> 0x3000 */
	static const uint8_t load2[] = { 0x48, 0x8b, 0x05, 0x09, 0x20, 0x00, 0x00 };     /* at 0x1007 -> 0x3010 */
	struct kgenome_xref *u = kgenome_xref_new();
	uint32_t before, after;

	(void)arg;
	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	feed_code(u, load, sizeof load, 0x1000);
	before = kgenome_xref_in(u, 0x3000, 8);               /* the sweep is part way */
	feed_code(u, load2, sizeof load2, 0x1007);
	after = kgenome_xref_in(u, 0x3010, 8);                /* an address first seen after the query */
	kgenome_xref_free(u);
	if (!(before & KGENOME_XREF_READ))
		return 2;
	return (after & KGENOME_XREF_READ) ? 0 : 1;
}

static int km_true_touches_wrap(void *arg)
{
	struct kgenome_true_all lib;

	(void)arg;
	memset(&lib, 0, sizeof lib);
	lib.n = 1;
	lib.span[0].off = 0x1000;
	lib.span[0].len = 0x100;
	if (!kgenome_true_touches(&lib, 0x1000, 8))
		return 2;
	return kgenome_true_touches(&lib, 0x800, UINT64_MAX) ? 0 : 1;
}

/* ---- the library spans ----------------------------------------------------------------------------------------- */

static void t_true(void)
{
	struct kgenome_true_all lib;
	static struct hk_elf e;
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	kof_buf f;

	memset(&lib, 0, sizeof lib);
	CK(kgenome_true_touches(&lib, 0, 100) == 0);
	CK(kgenome_true_touches(NULL, 0, 100) == 0);
	lib.n = 2;
	lib.span[0].off = 100; lib.span[0].len = 50;
	lib.span[1].off = 400; lib.span[1].len = 10;
	/* half-open overlap */
	CK(kgenome_true_touches(&lib, 100, 1) == 1);
	CK(kgenome_true_touches(&lib, 149, 1) == 1);
	CK(kgenome_true_touches(&lib, 150, 1) == 0);
	CK(kgenome_true_touches(&lib, 99, 1) == 0);
	CK(kgenome_true_touches(&lib, 99, 2) == 1);
	CK(kgenome_true_touches(&lib, 0, 1000) == 1);
	CK(kgenome_true_touches(&lib, 150, 250) == 0);
	CK(kgenome_true_touches(&lib, 150, 251) == 1);
	CK(kgenome_true_touches(&lib, 120, 0) == 0);                      /* an empty range touches nothing */
	CK(kgenome_true_touches(&lib, UINT64_MAX, 1) == 0);
	/* a zero-length span touches nothing */
	lib.span[0].len = 0;
	CK(kgenome_true_touches(&lib, 100, 10) == 0);

	/* an ELF with no library strings: nothing is the library's */
	hk_elf(&e, 1, 0, 0);
	f = kof_buf_make(e.b, e.n);
	CK(kgenome_elf_image_parse(f, &ei, &o));
	kgenome_true_find_object(f, &ei, &lib);
	CK(lib.n == 0);
	kgenome_true_find_all(f, &ei, &lib);
	CK(lib.n == 0);
	{
		struct kgenome_true_result res;
		kgenome_true_find(f, &ei, &res);
		CK(res.n == 0);
	}
	CK(kgenome_true_has_addr(&ei, &lib, 0x400000, 1) == 0);
	/* the output is cleared even when the object is refused, and a NULL output is ignored */
	memset(&lib, 0x55, sizeof lib);
	kgenome_true_find_object(kof_buf_make(NULL, 0), &ei, &lib);
	CK(lib.n == 0);
	memset(&lib, 0x55, sizeof lib);
	kgenome_true_find_object(f, NULL, &lib);
	CK(lib.n == 0);
	kgenome_true_find_object(f, &ei, NULL);
	kgenome_true_find_all(f, &ei, NULL);
	kgenome_true_find(f, &ei, NULL);
	CK(kgenome_true_has_addr(NULL, &lib, 0x400000, 1) == 0);
	CK(kgenome_true_has_addr(&ei, &lib, 0x400000, 0) == 0);
	CK(kgenome_true_has_addr(&ei, NULL, 0x400000, 1) == 0);
	CK(kgenome_true_has_addr(&ei, &lib, UINT64_MAX, 2) == 0);
	{
		struct kgenome_true_all one;
		memset(&one, 0, sizeof one);
		one.n = 1;
		one.span[0].off = e.text;
		one.span[0].len = 16;
		CK(kgenome_true_has_addr(&ei, &one, 0x400000u + e.text, 4) == 1);
		CK(kgenome_true_has_addr(&ei, &one, 0x400000u + e.text + 16u, 4) == 0);
		CK(kgenome_true_has_addr(&ei, &one, 0x400000u + e.text - 4u, 4) == 0);
		CK(kgenome_true_has_addr(&ei, &one, 0x400000u + e.text - 4u, 5) == 1);
	}
}

/* ---- the mutation windows ------------------------------------------------------------------------------------------ */

static void t_mutation_window(void)
{
	static const uint8_t p[40] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
				       21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40 };
	struct kgenome_mtn_win w;
	uint32_t norm, count;
	uint64_t at;
	uint8_t flat[24];

	CK(kgenome_mutation_drop_weight() != 0);
	{
		uint32_t d = 1, i;
		for (i = 1; i < KGENOME_MUTATION_NG; i++)
			d *= KGENOME_MUTATION_BASE;
		CK(kgenome_mutation_drop_weight() == d);
	}
	/* too short for one window: refused */
	for (norm = 0; norm < KGENOME_MUTATION_NORM_COUNT; norm++) {
		CK(kgenome_mtn_win_begin(&w, p, 0, norm) == 0);
		CK(kgenome_mtn_win_begin(&w, p, KGENOME_MUTATION_NG - 1u, norm) == 0);
		CK(kgenome_mtn_win_begin(&w, p, KGENOME_MUTATION_NG, norm) == (norm == KGENOME_MUTATION_RAW));
		CK(kgenome_mtn_win_begin(&w, p, KGENOME_MUTATION_NG + 1u, norm) == 1);
	}
	/* a window over n bytes advances n - NG + 1 times; the rolling value equals the window recomputed */
	for (norm = 0; norm < KGENOME_MUTATION_NORM_COUNT; norm++) {
		CK(kgenome_mtn_win_begin(&w, p, sizeof p, norm) == 1);
		count = 1;
		for (;;) {
			uint64_t i;
			uint32_t h = 0;
			for (i = 0; i < KGENOME_MUTATION_NG; i++)
				h = h * KGENOME_MUTATION_BASE + kgenome_mutation_byte(p, w.at + i, norm);
			CK(kgenome_mtn_win_value(&w) == kgenome_mutation_mix(h));
			if (!kgenome_mtn_win_next(&w))
				break;
			count++;
		}
		CK(count == (norm == KGENOME_MUTATION_RAW ? sizeof p : sizeof p - 1u) - KGENOME_MUTATION_NG + 1u);
		CK(kgenome_mtn_win_next(&w) == 0);              /* the end stays the end */
	}
	/* flat: every byte of the window equal after the normalisation */
	memset(flat, 7, sizeof flat);
	for (norm = 0; norm < KGENOME_MUTATION_NORM_COUNT; norm++) {
		CK(kgenome_mtn_win_begin(&w, flat, sizeof flat, norm) == 1);
		CK(kgenome_mtn_win_flat(&w) == 1);
	}
	CK(kgenome_mtn_win_begin(&w, p, sizeof p, KGENOME_MUTATION_RAW) == 1 && kgenome_mtn_win_flat(&w) == 0);
	/* an arithmetic run is flat under SUB (a constant step) and a repeating XOR key is flat under XOR */
	CK(kgenome_mtn_win_begin(&w, p, sizeof p, KGENOME_MUTATION_SUB) == 1 && kgenome_mtn_win_flat(&w) == 1);
	{
		uint8_t x[24];
		for (at = 0; at < sizeof x; at++)
			x[at] = (uint8_t)(0x55u ^ ((at & 1u) ? 0xa7u : 0x13u));
		CK(kgenome_mtn_win_begin(&w, x, sizeof x, KGENOME_MUTATION_XOR) == 1);
	}
	/* the last window never reads past the buffer: place it at a guard page */
	{
		struct hk_gb g;
		uint8_t *q;
		gb_init(&g, 64);
		for (norm = 0; norm < KGENOME_MUTATION_NORM_COUNT; norm++) {
			uint32_t n;
			for (n = 0; n <= 40; n++) {
				q = gb_put(&g, p, n);
				if (kgenome_mtn_win_begin(&w, q, n, norm)) {
					uint32_t c = 0;
					do {
						(void)kgenome_mtn_win_value(&w);
						(void)kgenome_mtn_win_flat(&w);
						c++;
					} while (kgenome_mtn_win_next(&w));
					CK(c >= 1);
				}
			}
		}
		gb_free(&g);
	}
	CK(kgenome_mutation_flat(p, 0, KGENOME_MUTATION_RAW) == 0);
	CK(kgenome_mutation_byte(p, 0, KGENOME_MUTATION_RAW) == 1);
	CK(kgenome_mutation_byte(p, 0, KGENOME_MUTATION_XOR) == (1 ^ 2));
	CK(kgenome_mutation_byte(p, 0, KGENOME_MUTATION_SUB) == 1);
	CK(kgenome_mutation_mix(0) == 0);
	CK(kgenome_mutation_mix(1) != 1);
}

static void t_mutation_by_function(void)
{
	CK(kgenome_mutation_by_function(KGENOME_FMT_ELF, KGENOME_SCAN_ELF_CODE) == 1);
	CK(kgenome_mutation_by_function(KGENOME_FMT_PE, KGENOME_SCAN_PE_CODE) == 1);
	CK(kgenome_mutation_by_function(KGENOME_FMT_NONE, KGENOME_SCAN_ELF_CODE) == 0);
	CK(kgenome_mutation_by_function(3, KGENOME_SCAN_ELF_CODE) == 0);
	CK(kgenome_mutation_by_function(KGENOME_FMT_ELF, KGENOME_SCAN_ELF_DATA) == 0);
	CK(kgenome_mutation_by_function(KGENOME_FMT_NONE, 0) == 0);
	CK(kgenome_mutation_by_function(0xffffffffu, 0xffffffffu) == 0);
	CK(kgenome_mutation_by_function(KGENOME_FMT_ELF, 0) == 0);
}

/* ---- the budget header: what its inline helpers promise ----------------------------------------------------------------- */

static void t_budget(void)
{
	struct kgenome_budget b;
	struct kgenome_ledger l;

	/* the saturating multiply */
	CK(kgenome_budget_sat_mul(0, UINT64_MAX) == 0 && kgenome_budget_sat_mul(UINT64_MAX, 0) == 0);
	CK(kgenome_budget_sat_mul(1ull << 63, 2) == UINT64_MAX && kgenome_budget_sat_mul(UINT64_MAX, UINT64_MAX) == UINT64_MAX);
	CK(kgenome_budget_sat_mul(UINT64_MAX / 3u, 3) == (UINT64_MAX / 3u) * 3u);
	CK(kgenome_budget_sat_mul(UINT64_MAX / 3u + 1u, 3) == UINT64_MAX);
	/* the defaults at the extremes: no field wraps, every field at or above its floor */
	memset(&b, 0, sizeof b);
	kgenome_budget_default(&b, UINT64_MAX, UINT64_MAX);
	CK(b.max_bytes == UINT64_MAX && b.max_insn == UINT64_MAX && b.max_steps == UINT64_MAX);
	CK(b.max_nodes == KGENOME_MAX_INDEX && b.max_names == KGENOME_MAX_INDEX);
	kgenome_budget_default(&b, UINT64_MAX - 100u, 0);
	CK(b.code_bytes == UINT64_MAX - 100u && b.max_bytes == UINT64_MAX);
	kgenome_budget_default(&b, 0, 0);
	CK(b.max_nodes == KGENOME_NODES_MIN && b.max_names == KGENOME_NODES_MIN && b.max_insn == KGENOME_INSN_MIN);
	CK(b.max_insn_resolve == KGENOME_RESOLVE_MIN && b.max_steps == (1ull << 20) && b.max_bytes == (256ull << 20));
	CK(b.deadline_ms == 0);
	/* a code size larger than the object is taken as it is (a caller's hint, not checked) */
	kgenome_budget_default(&b, 10, 1ull << 40);
	CK(b.code_bytes == 1ull << 40 && b.max_nodes == KGENOME_MAX_INDEX);
	/* the default overwrites a deadline left in the struct */
	b.deadline_ms = 99;
	kgenome_budget_default(&b, 100, 100);
	CK(b.deadline_ms == 0);

	/* the ledger: the allowance holds to the byte, a refusal charges nothing and says so */
	kgenome_ledger_init(&l, 100);
	CK(kgenome_ledger_charge(&l, 100) == 1 && l.used == 100 && l.peak == 100);
	CK(kgenome_ledger_charge(&l, 1) == 0 && l.used == 100 && l.status == KGENOME_OVER_BUDGET);
	CK(kgenome_ledger_try(&l, 1) == 0);
	CK(kgenome_ledger_room(&l) == 0);
	kgenome_ledger_release(&l, 40);
	CK(l.used == 60 && l.peak == 100 && kgenome_ledger_room(&l) == 40);
	kgenome_ledger_release(&l, 1000);                    /* saturates: never wraps */
	CK(l.used == 0 && kgenome_ledger_room(&l) == 100);
	CK(kgenome_ledger_charge(&l, UINT64_MAX) == 0);
	CK(kgenome_ledger_charge(&l, 0) == 1);
	/* no limit: UINT64_MAX of room, any charge is held (and the count can reach the top) */
	kgenome_ledger_init(&l, 0);
	CK(kgenome_ledger_room(&l) == UINT64_MAX);
	CK(kgenome_ledger_charge(&l, UINT64_MAX / 2u) == 1);
	CK(kgenome_ledger_charge(&l, UINT64_MAX / 2u) == 1);
	CK(l.used == UINT64_MAX - 1u && l.peak == UINT64_MAX - 1u);
	CK(kgenome_ledger_charge(&l, 5) == 1);              /* no limit: it is the caller's count */
	/* a soft charge refused does not mark the answer */
	kgenome_ledger_init(&l, 10);
	CK(kgenome_ledger_try(&l, 11) == 0 && l.status == KGENOME_OK);
	CK(kgenome_ledger_try(&l, 10) == 1 && l.used == 10);
	/* status words */
	CK(!strcmp(kgenome_status_name(KGENOME_OK), "ok") && !strcmp(kgenome_status_name(KGENOME_NOMEM), "nomem"));
	CK(!strcmp(kgenome_status_name((enum kgenome_status)99), "?") && !strcmp(kgenome_status_name((enum kgenome_status)-1), "?"));
	CK(kgenome_status_complete(KGENOME_OK) && !kgenome_status_complete(KGENOME_TRUNCATED));
	CK(kgenome_status_merge(KGENOME_OK, KGENOME_OK) == KGENOME_OK);
	CK(kgenome_status_merge(KGENOME_BAD_INPUT, KGENOME_TRUNCATED) == KGENOME_BAD_INPUT);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	int sig = 0;
	enum hk_result r;

	t_state_basics();
	t_map_vs_emulator();
	t_cursor();
	t_space_big_endian();
	r = hk_isolated(km_space_be, NULL, 10, &sig);
	KM_CHECK(r == HK_OK, "kgenome_cell_space_init decodes big-endian ELF code as little-endian",
		 "celllysis/space.c:94 sp->be = ((const uint8_t *)obj->file_header)[5] == 2u reads byte 5 of the parsed "
		 "struct kgenome_elf_info (inside `valid`, always 0), not e_ident[EI_DATA]: kgenome_elf_info.elf_data is "
		 "BE yet sp.be == 0. Repro: ELF32 big-endian, EM_MIPS, parse, kgenome_cell_space_init");
	t_nucleo();
	t_xref();
	r = hk_isolated(km_xref_wrap, NULL, 10, &sig);
	KM_CHECK(r == HK_OK, "kgenome_xref_in forgets a variable when asked about it with a size that wraps the address space",
		 "celllysis/xref.c:581 `u->va[...] < va + n` with n = 2^64-1 (a symbol's st_size): va+n wraps below va, "
		 "the loop never runs and the answer is 0 flags: the payload variable reads as unreferenced. "
		 "Repro: mov rax,[rip+0x1ff9]; call rax; kgenome_xref_in(u, 0x3000, UINT64_MAX) == 0");
	r = hk_isolated(km_xref_stale, NULL, 10, &sig);
	KM_CHECK(r == HK_OK, "kgenome_xref_in freezes the answers: instructions fed after the first query are never seen",
		 "celllysis/xref.c:559,568 `u->sorted = 1` is set by the first query (order_build) and never cleared by "
		 "kgenome_xref_feed/note, so the order index and the region flags keep describing the sweep as it was. "
		 "Repro: begin; feed `mov rax,[rip+0x1ff9]`; in(0x3000) = READ; feed a load of a NEW address 0x3010; in(0x3010) == 0 (flags of an address already known keep updating, a new one is not in the index); also a query before any feed makes every later answer 0");
	t_true();
	r = hk_isolated(km_true_touches_wrap, NULL, 10, &sig);
	KM_CHECK(r == HK_OK, "kgenome_true_touches misses a span when the range's end wraps the address space",
		 "celllysis/trueline.c kgenome_true_touches: `a < off + len` with len = UINT64_MAX; "
		 "span {0x1000,0x100}, touches(lib, 0x800, UINT64_MAX) == 0");
	t_mutation_window();
	t_mutation_by_function();
	t_budget();
	printf("api_celllysis: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
