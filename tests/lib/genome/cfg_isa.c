/*
 * genome / cfg_isa - every row of THE ONE ISA TABLE (cfg_isa.c) against instructions assembled by hand, per
 * architecture, and then whole streams through the builder: an ARM conditional return keeps its fall-through,
 * a MIPS delay slot is part of its block, an x86 call / rep / cmov / setcc does not split a block.
 *
 * The instruction words are written out here as numbers (R: worked out from the architecture manuals' encodings
 * and cross-checked against the decoder's class), so a decoder that changed what it reports for one of them
 * fails HERE, at the row that depended on it, and not as a different signature somewhere else.
 *
 * The decoder gives no register or condition for a MIPS branch (CS-4); the table reads the word. The rows below
 * for `b`, `bgez $0`, `bal` and `bltzal` are what that reading decides.
 */
#include "cfg_kit.h"

struct row {
	const char *what;
	unsigned isa;           /* index into ISAS */
	uint32_t word;          /* a 32-bit instruction (not x86) */
	int      expect;        /* enum kgenome_cfg_x */
	int      sys;           /* is it a syscall */
};

#define X_NONE KGENOME_CFG_X_NONE
#define X_BRC  KGENOME_CFG_X_BR_COND
#define X_BRJ  KGENOME_CFG_X_BR_JUMP
#define X_EXIT KGENOME_CFG_X_EXIT
#define X_CEX  KGENOME_CFG_X_COND_EXIT

static const struct row ROWS[] = {
	/* ARM32 (2): the condition is in `cond`, 14 = always */
	{ "arm bx lr",                2, 0xe12fff1eu, X_EXIT, 0 },
	{ "arm bxeq lr",              2, 0x012fff1eu, X_CEX, 0 },
	{ "arm bxne lr",              2, 0x112fff1eu, X_CEX, 0 },
	{ "arm bx r1",                2, 0xe12fff11u, X_EXIT, 0 },
	{ "arm bxne r1",              2, 0x112fff11u, X_CEX, 0 },
	{ "arm ldmfd sp!,{pc}",       2, 0xe8bd8000u, X_EXIT, 0 },
	{ "arm ldmeqfd sp!,{pc}",     2, 0x08bd8000u, X_CEX, 0 },
	{ "arm mov pc,lr",            2, 0xe1a0f00eu, X_EXIT, 0 },
	{ "arm moveq pc,lr",          2, 0x01a0f00eu, X_CEX, 0 },
	{ "arm ldr pc,[r1]",          2, 0xe591f000u, X_EXIT, 0 },
	{ "arm b",                    2, 0xea000000u, X_BRJ, 0 },
	{ "arm bne",                  2, 0x1a000000u, X_BRC, 0 },
	{ "arm beq",                  2, 0x0a000000u, X_BRC, 0 },
	{ "arm bl",                   2, 0xeb000000u, X_NONE, 0 },
	{ "arm svc",                  2, 0xef000000u, X_NONE, 1 },
	{ "arm addeq r0,r0,#1",       2, 0x02800001u, X_NONE, 0 },
	{ "arm nop",                  2, 0xe1a00000u, X_NONE, 0 },
	/* AArch64 (3): b.cond carries the condition code, cbz/tbz bit 24 */
	{ "a64 b",                    3, 0x14000000u, X_BRJ, 0 },
	{ "a64 b.ne",                 3, 0x54000001u, X_BRC, 0 },
	{ "a64 b.eq",                 3, 0x54000000u, X_BRC, 0 },
	{ "a64 b.al",                 3, 0x5400000eu, X_BRJ, 0 },
	{ "a64 b.nv",                 3, 0x5400000fu, X_BRJ, 0 },
	{ "a64 b.gt",                 3, 0x5400000cu, X_BRC, 0 },
	{ "a64 cbz x0",               3, 0xb4000000u, X_BRC, 0 },
	{ "a64 cbnz x0",              3, 0xb5000000u, X_BRC, 0 },
	{ "a64 tbz x0,#0",            3, 0x36000000u, X_BRC, 0 },
	{ "a64 ret",                  3, 0xd65f03c0u, X_EXIT, 0 },
	{ "a64 br x1",                3, 0xd61f0020u, X_EXIT, 0 },
	{ "a64 bl",                   3, 0x94000000u, X_NONE, 0 },
	{ "a64 blr x1",               3, 0xd63f0020u, X_NONE, 0 },
	{ "a64 svc",                  3, 0xd4000001u, X_NONE, 1 },
	{ "a64 nop",                  3, 0xd503201fu, X_NONE, 0 },
	/* MIPS little and big endian (4, 5): the word is read from the bytes */
	{ "mips beq r1,r2",           4, 0x10220000u, X_BRC, 0 },
	{ "mips beq r1,r1 (b)",       4, 0x10210000u, X_BRJ, 0 },
	{ "mips beq $0,$0 (b)",       4, 0x10000000u, X_BRJ, 0 },
	{ "mips bne r1,r0",           4, 0x14200000u, X_BRC, 0 },
	{ "mips bgez $0",             4, 0x04010000u, X_BRJ, 0 },
	{ "mips bgez r1",             4, 0x04210000u, X_BRC, 0 },
	{ "mips bltz r1",             4, 0x04200000u, X_BRC, 0 },
	{ "mips bal (bgezal $0)",     4, 0x04110000u, X_NONE, 0 },
	{ "mips bltzal r1",           4, 0x04300000u, X_NONE, 0 },
	{ "mips blez r1",             4, 0x18200000u, X_BRC, 0 },
	{ "mips j",                   4, 0x08000000u, X_BRJ, 0 },
	{ "mips jr ra",               4, 0x03e00008u, X_EXIT, 0 },
	{ "mips jr t9",               4, 0x03200008u, X_EXIT, 0 },
	{ "mips jal",                 4, 0x0c000000u, X_NONE, 0 },
	{ "mips jalr",                4, 0x0320f809u, X_NONE, 0 },
	{ "mips syscall",             4, 0x0000000cu, X_NONE, 1 },
	{ "mips nop",                 4, 0x00000000u, X_NONE, 0 },
	{ "mips-be beq r1,r2",        5, 0x10220000u, X_BRC, 0 },
	{ "mips-be beq r1,r1 (b)",    5, 0x10210000u, X_BRJ, 0 },
	{ "mips-be bgez $0",          5, 0x04010000u, X_BRJ, 0 },
	{ "mips-be bal",              5, 0x04110000u, X_NONE, 0 },
	{ "mips-be jr ra",            5, 0x03e00008u, X_EXIT, 0 },
};

struct xrow {
	const char *what;
	unsigned isa;           /* 0 x86-64, 1 i386 */
	uint8_t  b[8];
	uint32_t n;
	int      expect;
	int      sys;
};

static const struct xrow XROWS[] = {
	{ "ret",            0, { 0xc3 }, 1, X_EXIT, 0 },
	{ "ret 8 (stdcall)", 0, { 0xc2, 0x08, 0x00 }, 3, X_EXIT, 0 },
	{ "retf",           0, { 0xcb }, 1, X_EXIT, 0 },
	{ "iret",           0, { 0xcf }, 1, X_EXIT, 0 },
	{ "ud2",            0, { 0x0f, 0x0b }, 2, X_EXIT, 0 },
	{ "jmp rel32",      0, { 0xe9, 0, 0, 0, 0 }, 5, X_BRJ, 0 },
	{ "jmp rel8",       0, { 0xeb, 0 }, 2, X_BRJ, 0 },
	{ "jne rel32",      0, { 0x0f, 0x85, 0, 0, 0, 0 }, 6, X_BRC, 0 },
	{ "je rel8",        0, { 0x74, 0 }, 2, X_BRC, 0 },
	{ "jmp *rax",       0, { 0xff, 0xe0 }, 2, X_EXIT, 0 },
	{ "jmp *[rip+0]",   0, { 0xff, 0x25, 0, 0, 0, 0 }, 6, X_EXIT, 0 },
	{ "ljmp *(rax)",    0, { 0xff, 0x28 }, 2, X_EXIT, 0 },
	{ "loop",           0, { 0xe2, 0 }, 2, X_BRC, 0 },
	/* KNOWN DEFECT CL-1 (2026-10-30, M): this row pins it - the decoder reports jrcxz/jecxz as OTHER, so the table sees no branch. */
	{ "jrcxz (CL-1: should be X_BRC)", 0, { 0xe3, 0 }, 2, X_NONE, 0 },
	{ "call rel32",     0, { 0xe8, 0, 0, 0, 0 }, 5, X_NONE, 0 },
	{ "call *rax",      0, { 0xff, 0xd0 }, 2, X_NONE, 0 },
	{ "cmovne eax,ebx", 0, { 0x0f, 0x45, 0xc3 }, 3, X_NONE, 0 },
	{ "rep movsb",      0, { 0xf3, 0xa4 }, 2, X_NONE, 0 },
	{ "repne scasb",    0, { 0xf2, 0xae }, 2, X_NONE, 0 },
	{ "setne al",       0, { 0x0f, 0x95, 0xc0 }, 3, X_NONE, 0 },
	{ "syscall",        0, { 0x0f, 0x05 }, 2, X_NONE, 1 },
	{ "int3",           0, { 0xcc }, 1, X_NONE, 0 },
	{ "int 0x80 (x64)", 0, { 0xcd, 0x80 }, 2, X_NONE, 0 },
	{ "nop",            0, { 0x90 }, 1, X_NONE, 0 },
	{ "jmp far ptr (i386)", 1, { 0xea, 0, 0, 0, 0, 8, 0 }, 7, X_EXIT, 0 },
	{ "ret (i386)",     1, { 0xc3 }, 1, X_EXIT, 0 },
	{ "jne rel8 (i386)", 1, { 0x75, 0 }, 2, X_BRC, 0 },
	{ "jmp rel32 (i386)", 1, { 0xe9, 0, 0, 0, 0 }, 5, X_BRJ, 0 },
	{ "int 0x80 (i386)", 1, { 0xcd, 0x80 }, 2, X_NONE, 1 },
	{ "int 0x2e (i386)", 1, { 0xcd, 0x2e }, 2, X_NONE, 0 },
	{ "int3 (i386)",    1, { 0xcc }, 1, X_NONE, 0 },
	{ "sysenter",       1, { 0x0f, 0x34 }, 2, X_NONE, 1 },
	{ "call rel32 (i386)", 1, { 0xe8, 0, 0, 0, 0 }, 5, X_NONE, 0 },
};

static void rows(void)
{
	unsigned i;

	for (i = 0; i < sizeof ROWS / sizeof ROWS[0]; i++) {
		const struct row *r = &ROWS[i];
		const struct isa_t *isa = &ISAS[r->isa];
		const struct kgenome_cfg_isa *t = kgenome_cfg_isa_of(isa->arch);
		struct kgenome_cell_insn in;
		uint8_t b[8] = { 0 };
		int degraded = 0;
		enum kgenome_cfg_x x;

		CKM(t != NULL, "%s: no table row", r->what);
		if (!t)
			continue;
		put32(isa, b, r->word);
		CKM(kgenome_cell_decode(isa->arch, isa->be, b, 4, 0x1000, &in) == 4u, "%s: does not decode", r->what);
		in.at = 0;
		x = kgenome_cfg_isa_class(t, &in, isa->be, b, 4, &degraded);
		CKM((int)x == r->expect, "%s: class %d want %d (op %u cond %u flags %x)", r->what, (int)x, r->expect, in.op, in.cond, in.flags);
		CKM(!degraded, "%s: degraded with the bytes given", r->what);
		CKM(kgenome_cfg_isa_is_syscall(t, &in) == r->sys, "%s: syscall %d want %d", r->what, kgenome_cfg_isa_is_syscall(t, &in), r->sys);
	}
	for (i = 0; i < sizeof XROWS / sizeof XROWS[0]; i++) {
		const struct xrow *r = &XROWS[i];
		const struct isa_t *isa = &ISAS[r->isa];
		const struct kgenome_cfg_isa *t = kgenome_cfg_isa_of(isa->arch);
		struct kgenome_cell_insn in;
		int degraded = 0;
		enum kgenome_cfg_x x;

		CKM(kgenome_cell_decode(isa->arch, 0, r->b, r->n, 0x1000, &in) == r->n, "%s: does not decode", r->what);
		x = kgenome_cfg_isa_class(t, &in, 0, NULL, 0, &degraded);
		CKM((int)x == r->expect, "%s: class %d want %d (op %u)", r->what, (int)x, r->expect, in.op);
		CKM(kgenome_cfg_isa_is_syscall(t, &in) == r->sys, "%s: syscall %d want %d", r->what, kgenome_cfg_isa_is_syscall(t, &in), r->sys);
	}
}

/* A table with no row for an architecture is UNSUPPORTED, never another ISA's reading. */
static void unsupported(void)
{
	struct kgenome_cfg g;
	struct kgenome_cfg_req rq;
	struct kgenome_cell_insn in;
	unsigned a;

	memset(&in, 0, sizeof in);
	in.op = KGENOME_CELL_NOP;
	in.len = 1;
	memset(&rq, 0, sizeof rq);
	rq.in = &in;
	rq.n_in = 1;
	for (a = 0; a < KGENOME_ARCH_COUNT; a++) {
		const int has = a == KGENOME_ARCH_X86 || a == KGENOME_ARCH_X86_64 || a == KGENOME_ARCH_ARM || a == KGENOME_ARCH_ARM64 ||
				a == KGENOME_ARCH_MIPS || a == KGENOME_ARCH_MIPS64;

		rq.arch = a;
		CKM(has == (kgenome_cfg_isa_of(a) != NULL), "arch %u: table row presence", a);
		CKM(kgenome_cfg_build(&rq, &g) == (has ? KGENOME_OK : KGENOME_UNSUPPORTED), "arch %u: status", a);
		kgenome_cfg_free(&g, NULL);
	}
	CK(kgenome_cfg_isa_of(KGENOME_ARCH_OTHER) == NULL);
	CK(kgenome_cfg_isa_of(KGENOME_ARCH_ANY) == NULL);
}

/* MIPS without the object bytes: every branch is taken for a conditional one and the graph says TRUNCATED. */
static void mips_without_bytes(void)
{
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	struct kgenome_cfg_req rq;
	uint32_t n;

	prog_add(&p, O_NOP, 0);
	prog_add(&p, O_B, 3);
	prog_add(&p, O_NOP, 0);
	prog_add(&p, O_RET, 0);
	CK(blob_make(&ISAS[4], &p, 0x1000, &x));
	n = blob_decode(&ISAS[4], &x, &in);
	blob_map_ops(&p, &x, in, n);
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = KGENOME_ARCH_MIPS; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_TRUNCATED);
	CK(g.b[0].term == KGENOME_CFG_T_COND);          /* `b` seen as conditional: said, not hidden */
	kgenome_cfg_free(&g, NULL);
	rq.bytes = x.b; rq.bytes_len = x.len;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.b[0].term == KGENOME_CFG_T_JUMP);
	kgenome_cfg_free(&g, NULL);
	rq.bytes_len = 4;                               /* bytes that stop before the branch's word */
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_TRUNCATED);
	kgenome_cfg_free(&g, NULL);
	free(in);
	blob_free(&x);
	prog_free(&p);
}

/* The delay slot is part of the block: the slot's own instruction is never a block start, whatever it is, and a target
 * that points into a slot is dropped (it would cut the branch from its slot). */
static void mips_slot(void)
{
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	struct kgenome_cfg_req rq;
	uint32_t n, i;

	/* 0 nop; 1 jcc ->2; 2 nop; 3 ret : the slot of op 1 is instruction 2; op 2 is instruction 3 */
	prog_add(&p, O_NOP, 0);
	prog_add(&p, O_JCC, 2);
	prog_add(&p, O_NOP, 0);
	prog_add(&p, O_RET, 0);
	CK(blob_make(&ISAS[4], &p, 0x1000, &x));
	n = blob_decode(&ISAS[4], &x, &in);
	CK(n == 6);                                     /* nop, jcc, slot, nop, ret, slot */
	blob_map_ops(&p, &x, in, n);
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = KGENOME_ARCH_MIPS; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len; rq.bytes = x.b; rq.bytes_len = x.len;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.n_all == 2 && g.b[0].n_insn == 3 && g.b[1].n_insn == 3);
	CK(g.b[0].term == KGENOME_CFG_T_COND && g.b[0].succ[0] == 1 && g.b[0].succ[1] == 1);
	CK(g.b[1].term == KGENOME_CFG_T_EXIT);
	kgenome_cfg_free(&g, NULL);
	/* aim the branch at its own slot (instruction 2, address 0x1000 + 8 + 4): the edge goes, the block does not split */
	{
		struct kgenome_cell_insn *m = malloc((size_t)n * sizeof *m);

		memcpy(m, in, (size_t)n * sizeof *m);
		m[1].target_va = m[2].at_va;
		rq.in = m;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CK(g.n_all == 2 && g.b[0].n_insn == 3);
		CK(g.b[0].term == KGENOME_CFG_T_FALL && g.b[0].succ[0] == 1 && g.b[0].succ[1] == KGENOME_CFG_NONE);
		kgenome_cfg_free(&g, NULL);
		free(m);
	}
	/* a branch that is the last instruction has no slot in the array: TRUNCATED */
	rq.in = in; rq.n_in = 5;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_TRUNCATED);
	CK(g.n_all == 2 && g.b[1].n_insn == 2 && g.b[1].term == KGENOME_CFG_T_EXIT);
	kgenome_cfg_free(&g, NULL);
	for (i = 0; i < n; i++)
		CK(in[i].len == 4);
	free(in);
	blob_free(&x);
	prog_free(&p);
}

/* x86: calls, rep, cmov, setcc, syscall and int3 in the middle of a stream do not split it; the whole stream is one block. */
static void x86_no_split(void)
{
	static const uint8_t code[] = {
		0x90, 0x0f, 0x45, 0xc3, 0xf3, 0xa4, 0x0f, 0x95, 0xc0, 0xe8, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd0,
		0x0f, 0x05, 0xcc, 0xf2, 0xae, 0x90, 0xc3 };
	unsigned ii;

	for (ii = 0; ii < 2; ii++) {
		struct kgenome_cell_insn in[32];
		struct kgenome_cfg_req rq;
		struct kgenome_cfg g;
		uint32_t pos = 0, n = 0;

		while (pos < sizeof code) {
			const uint32_t l = kgenome_cell_decode(ISAS[ii].arch, 0, code + pos, (uint32_t)sizeof code - pos, 0x1000 + pos, &in[n]);

			CK(l != 0);
			if (!l)
				return;
			in[n].at = pos;
			n++;
			pos += l;
		}
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = n; rq.arch = ISAS[ii].arch; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + sizeof code;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CK(g.n_all == 1 && g.n_blk == 1 && g.n_edge == 0 && g.b[0].term == KGENOME_CFG_T_EXIT && g.b[0].n_insn == n);
		CK(g.b[0].n_call == 3 && g.n_call == 3 && g.b[0].call_kinds == ((1u << KGENOME_CFG_CK_DIRECT) | (1u << KGENOME_CFG_CK_INDIRECT) | (1u << KGENOME_CFG_CK_SYSCALL)));
		CK(g.call[0].kind == KGENOME_CFG_CK_DIRECT && g.call[1].kind == KGENOME_CFG_CK_INDIRECT && g.call[2].kind == KGENOME_CFG_CK_SYSCALL && g.call[0].id == 0);
		CK(g.n_sys == 1);
		kgenome_cfg_free(&g, NULL);
	}
}

/* ARM: a conditional return then a plain return is two blocks and one edge; a conditional load of pc likewise. */
static void arm_cond_exit_streams(void)
{
	static const uint32_t words[][3] = {
		{ 0x012fff1eu, 0xe1a00000u, 0xe12fff1eu },      /* bxeq lr ; nop ; bx lr */
		{ 0x08bd8000u, 0xe1a00000u, 0xe12fff1eu },      /* ldmeqfd sp!,{pc} ; nop ; bx lr */
		{ 0x01a0f00eu, 0xe1a00000u, 0xe12fff1eu },      /* moveq pc,lr ; nop ; bx lr */
		{ 0x112fff11u, 0xe1a00000u, 0xe12fff1eu },      /* bxne r1 ; nop ; bx lr */
	};
	unsigned w, k;

	for (w = 0; w < sizeof words / sizeof words[0]; w++) {
		struct kgenome_cell_insn in[3];
		struct kgenome_cfg_req rq;
		struct kgenome_cfg g;
		uint8_t b[12];

		for (k = 0; k < 3; k++) {
			put32(&ISAS[2], b + 4u * k, words[w][k]);
			CK(kgenome_cell_decode(KGENOME_ARCH_ARM, 0, b + 4u * k, 4, 0x1000 + 4u * k, &in[k]) == 4u);
			in[k].at = 4u * k;
		}
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = 3; rq.arch = KGENOME_ARCH_ARM; rq.va_lo = 0x1000; rq.va_hi = 0x100c;
		CKM(kgenome_cfg_build(&rq, &g) == KGENOME_OK, "arm stream %u", w);
		CKM(g.n_all == 2 && g.n_blk == 2 && g.n_edge == 1 && g.b[0].succ[0] == 1 && g.b[0].term == KGENOME_CFG_T_FALL &&
		    g.b[0].out_deg == 1 && g.b[1].in_deg == 1 && g.b[1].term == KGENOME_CFG_T_EXIT, "arm stream %u: shape", w);
		kgenome_cfg_free(&g, NULL);
	}
}

int main(void)
{
	rows();
	unsupported();
	mips_without_bytes();
	mips_slot();
	x86_no_split();
	arm_cond_exit_streams();
	if (fails)
		printf("cfg_isa: %d FAILED\n", fails);
	else
		printf("cfg_isa: ok\n");
	return fails != 0;
}
