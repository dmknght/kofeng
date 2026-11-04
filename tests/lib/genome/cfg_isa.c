/*
 * genome / cfg_isa - every row of THE ONE ISA TABLE (cfg_isa.c) against instructions assembled by hand, per
 * architecture, and then whole streams through the builder: an ARM conditional return keeps its fall-through,
 * a MIPS delay slot is part of its block, an x86 call / rep / cmov / setcc does not split a block.
 *
 * The instruction words are written out here as numbers (R: worked out from the architecture manuals' encodings
 * and cross-checked against the decoder's class), so a decoder that changed what it reports for one of them
 * fails HERE, at the row that depended on it, and not as a different signature somewhere else.
 *
 * CS-4 (fixed): the decoder fills a MIPS branch's registers and `cond` directly - the rows below for `b`,
 * `bgez $0`, `bal` and `bltzal`, plus the branch-likely and COP1 BC rows (CL-3), are read straight off the
 * decoded instruction, with no object bytes behind them (mips_without_bytes() pins that).
 */
#include "cfg_kit.h"

struct row {
	const char *what;
	unsigned isa;           /* index into ISAS */
	uint32_t word;          /* a 32-bit instruction (not x86) */
	int      expect;        /* enum kgenome_cfg_x */
	int      sys;           /* is it a syscall */
	int      annul;         /* CL-3: KGENOME_CELL_F_ANNUL must be set (1) or clear (0, the default) */
};

#define X_NONE KGENOME_CFG_X_NONE
#define X_BRC  KGENOME_CFG_X_BR_COND
#define X_BRJ  KGENOME_CFG_X_BR_JUMP
#define X_EXIT KGENOME_CFG_X_EXIT
#define X_CEX  KGENOME_CFG_X_COND_EXIT

static const struct row ROWS[] = {
	/* ARM32 (2): the condition is in `cond`, 14 = always */
	{ "arm bx lr",                2, 0xe12fff1eu, X_EXIT, 0, 0 },
	{ "arm bxeq lr",              2, 0x012fff1eu, X_CEX, 0, 0 },
	{ "arm bxne lr",              2, 0x112fff1eu, X_CEX, 0, 0 },
	{ "arm bx r1",                2, 0xe12fff11u, X_EXIT, 0, 0 },
	{ "arm bxne r1",              2, 0x112fff11u, X_CEX, 0, 0 },
	{ "arm ldmfd sp!,{pc}",       2, 0xe8bd8000u, X_EXIT, 0 , 0 },
	{ "arm ldmeqfd sp!,{pc}",     2, 0x08bd8000u, X_CEX, 0 , 0 },
	{ "arm mov pc,lr",            2, 0xe1a0f00eu, X_EXIT, 0 , 0 },
	{ "arm moveq pc,lr",          2, 0x01a0f00eu, X_CEX, 0 , 0 },
	{ "arm ldr pc,[r1]",          2, 0xe591f000u, X_EXIT, 0 , 0 },
	{ "arm b",                    2, 0xea000000u, X_BRJ, 0, 0 },
	{ "arm bne",                  2, 0x1a000000u, X_BRC, 0, 0 },
	{ "arm beq",                  2, 0x0a000000u, X_BRC, 0, 0 },
	{ "arm bl",                   2, 0xeb000000u, X_NONE, 0, 0 },
	{ "arm svc",                  2, 0xef000000u, X_NONE, 1, 0 },
	{ "arm addeq r0,r0,#1",       2, 0x02800001u, X_NONE, 0 , 0 },
	{ "arm nop",                  2, 0xe1a00000u, X_NONE, 0, 0 },
	/* AArch64 (3): b.cond carries the condition code, cbz/tbz bit 24 */
	{ "a64 b",                    3, 0x14000000u, X_BRJ, 0, 0 },
	{ "a64 b.ne",                 3, 0x54000001u, X_BRC, 0, 0 },
	{ "a64 b.eq",                 3, 0x54000000u, X_BRC, 0, 0 },
	{ "a64 b.al",                 3, 0x5400000eu, X_BRJ, 0, 0 },
	{ "a64 b.nv",                 3, 0x5400000fu, X_BRJ, 0, 0 },
	{ "a64 b.gt",                 3, 0x5400000cu, X_BRC, 0, 0 },
	{ "a64 cbz x0",               3, 0xb4000000u, X_BRC, 0, 0 },
	{ "a64 cbnz x0",              3, 0xb5000000u, X_BRC, 0, 0 },
	{ "a64 tbz x0,#0",            3, 0x36000000u, X_BRC, 0 , 0 },
	{ "a64 ret",                  3, 0xd65f03c0u, X_EXIT, 0, 0 },
	{ "a64 br x1",                3, 0xd61f0020u, X_EXIT, 0, 0 },
	{ "a64 bl",                   3, 0x94000000u, X_NONE, 0, 0 },
	{ "a64 blr x1",               3, 0xd63f0020u, X_NONE, 0, 0 },
	{ "a64 svc",                  3, 0xd4000001u, X_NONE, 1, 0 },
	{ "a64 nop",                  3, 0xd503201fu, X_NONE, 0, 0 },
	/* MIPS little and big endian (4, 5): the word is read from the bytes */
	{ "mips beq r1,r2",           4, 0x10220000u, X_BRC, 0 , 0 },
	{ "mips beq r1,r1 (b)",       4, 0x10210000u, X_BRJ, 0 , 0 },
	{ "mips beq $0,$0 (b)",       4, 0x10000000u, X_BRJ, 0 , 0 },
	{ "mips bne r1,r0",           4, 0x14200000u, X_BRC, 0 , 0 },
	{ "mips bgez $0",             4, 0x04010000u, X_BRJ, 0, 0 },
	{ "mips bgez r1",             4, 0x04210000u, X_BRC, 0, 0 },
	{ "mips bltz r1",             4, 0x04200000u, X_BRC, 0, 0 },
	{ "mips bal (bgezal $0)",     4, 0x04110000u, X_NONE, 0, 0 },
	{ "mips bltzal r1",           4, 0x04300000u, X_NONE, 0, 0 },
	{ "mips blez r1",             4, 0x18200000u, X_BRC, 0, 0 },
	{ "mips j",                   4, 0x08000000u, X_BRJ, 0, 0 },
	{ "mips jr ra",               4, 0x03e00008u, X_EXIT, 0, 0 },
	{ "mips jr t9",               4, 0x03200008u, X_EXIT, 0, 0 },
	{ "mips jal",                 4, 0x0c000000u, X_NONE, 0, 0 },
	{ "mips jalr",                4, 0x0320f809u, X_NONE, 0, 0 },
	{ "mips syscall",             4, 0x0000000cu, X_NONE, 1, 0 },
	{ "mips nop",                 4, 0x00000000u, X_NONE, 0, 0 },
	{ "mips-be beq r1,r2",        5, 0x10220000u, X_BRC, 0 , 0 },
	{ "mips-be beq r1,r1 (b)",    5, 0x10210000u, X_BRJ, 0 , 0 },
	{ "mips-be bgez $0",          5, 0x04010000u, X_BRJ, 0, 0 },
	{ "mips-be bal",              5, 0x04110000u, X_NONE, 0, 0 },
	{ "mips-be jr ra",            5, 0x03e00008u, X_EXIT, 0, 0 },
	/* CL-3: branch-likely (annuls its delay slot when not taken) and COP1 BC rows, little-endian (4) */
	{ "mips beql r1,r2",          4, 0x50220000u, X_BRC, 0, 1 },
	{ "mips beql r1,r1 (b)",      4, 0x50210000u, X_BRJ, 0, 1 },
	{ "mips bnel r1,r0",          4, 0x54200000u, X_BRC, 0, 1 },
	{ "mips blezl r1",            4, 0x58200000u, X_BRC, 0, 1 },
	{ "mips bgtzl r1",            4, 0x5c200000u, X_BRC, 0, 1 },
	{ "mips bltzl r1",            4, 0x04220000u, X_BRC, 0, 1 },
	{ "mips bgezl r1",            4, 0x04230000u, X_BRC, 0, 1 },
	{ "mips bltzall r1",          4, 0x04320000u, X_NONE, 0, 1 },
	{ "mips bgezall r1",          4, 0x04330000u, X_NONE, 0, 1 },
	{ "mips bc1f",                4, 0x45000000u, X_BRC, 0, 0 },
	{ "mips bc1t",                4, 0x45010000u, X_BRC, 0, 0 },
	{ "mips bc1fl",               4, 0x45020000u, X_BRC, 0, 1 },
	{ "mips bc1tl",               4, 0x45030000u, X_BRC, 0, 1 },
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
		CKM(((in.flags & KGENOME_CELL_F_ANNUL) != 0) == (r->annul != 0), "%s: annul %d want %d",
		    r->what, (in.flags & KGENOME_CELL_F_ANNUL) != 0, r->annul);
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
				a == KGENOME_ARCH_MIPS || a == KGENOME_ARCH_MIPS64 ||
				a == KGENOME_ARCH_PPC || a == KGENOME_ARCH_PPC64;

		rq.arch = a;
		CKM(has == (kgenome_cfg_isa_of(a) != NULL), "arch %u: table row presence", a);
		CKM(kgenome_cfg_build(&rq, &g) == (has ? KGENOME_OK : KGENOME_UNSUPPORTED), "arch %u: status", a);
		kgenome_cfg_free(&g, NULL);
	}
	CK(kgenome_cfg_isa_of(KGENOME_ARCH_OTHER) == NULL);
	CK(kgenome_cfg_isa_of(KGENOME_ARCH_ANY) == NULL);
}

/*
 * CS-4 (fixed): a MIPS `b` (beq r,r) is read correctly as an unconditional jump with NO object bytes at all -
 * decode_mips.c put the comparison into `cond`/o[1]/o[2] at decode time, so cfg_isa.c needs nothing it was not
 * already handed. Before the fix this built TRUNCATED and read `b` as merely conditional without the bytes;
 * that degraded path no longer exists for MIPS (kgenome_cfg_isa_class's be/bytes/n/degraded parameters are
 * unused by it now - see the comment there).
 */
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
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.b[0].term == KGENOME_CFG_T_JUMP);          /* `b` read straight off the decode, bytes or not */
	kgenome_cfg_free(&g, NULL);
	rq.bytes = x.b; rq.bytes_len = x.len;           /* giving the bytes anyway changes nothing */
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.b[0].term == KGENOME_CFG_T_JUMP);
	kgenome_cfg_free(&g, NULL);
	rq.bytes_len = 4;                               /* bytes that stop before the branch's word: still unused */
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.b[0].term == KGENOME_CFG_T_JUMP);
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

/*
 * CL-3: a branch-likely's delay slot runs ONLY on the taken path. Hand-assembled (no abstract op for a likely
 * branch exists in cfg_kit.h): 0 nop, 1 beql $1,$2 -> 4, 2 addiu (the slot, taken-only), 3 addiu (not-taken
 * lands here, skipping the slot), 4 nop (the target), 5 jr ra, 6 nop (jr's own, ordinary, merged slot).
 */
static void mips_annul(void)
{
	static const uint32_t words[] = {
		0x00000000u,            /* nop */
		0x50220002u,            /* beql $1,$2, offset 2 -> va 0x1004+4+2*4 = 0x1010 (index 4) */
		0x24630001u,            /* addiu $3,$3,1 (slot, taken-only) */
		0x24840001u,            /* addiu $4,$4,1 (not-taken lands here) */
		0x00000000u,            /* nop (the target) */
		0x03e00008u,            /* jr ra */
		0x00000000u,            /* nop (jr's own delay slot) */
	};
	struct kgenome_cell_insn in[7];
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g;
	uint8_t b[28];
	unsigned k;

	for (k = 0; k < 7; k++) {
		put32(&ISAS[4], b + 4u * k, words[k]);
		CK(kgenome_cell_decode(KGENOME_ARCH_MIPS, 0, b + 4u * k, 4, 0x1000 + 4u * k, &in[k]) == 4u);
		in[k].at = 4u * k;
	}
	CK(in[1].flags & KGENOME_CELL_F_ANNUL);
	CK(in[1].target_va == 0x1010u);                 /* instruction 4 */
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = 7; rq.arch = KGENOME_ARCH_MIPS; rq.va_lo = 0x1000; rq.va_hi = 0x101c;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.n_all == 4);
	if (g.n_all == 4) {
		CK(g.b[0].n_insn == 2 && g.b[0].term == KGENOME_CFG_T_COND && g.b[0].succ[0] == 1 && g.b[0].succ[1] == 2);
		CK(g.b[1].n_insn == 1 && g.b[1].first == 2 && g.b[1].term == KGENOME_CFG_T_JUMP && g.b[1].succ[0] == 3);
		CK(g.b[2].n_insn == 1 && g.b[2].first == 3 && g.b[2].term == KGENOME_CFG_T_FALL && g.b[2].succ[0] == 3);
		CK(g.b[3].n_insn == 3 && g.b[3].first == 4 && g.b[3].term == KGENOME_CFG_T_EXIT);
		CK(g.n_blk == 4 && g.n_edge == 4);
	}
	kgenome_cfg_free(&g, NULL);
	/* a likely branch whose target leaves the function (KGENOME_CFG_F_SPLIT_EXITS): the ordinary merged-slot
	 * fallback applies - CL-3's split is only for a local, resolved target. */
	{
		struct kgenome_cell_insn in2[3];

		memcpy(in2, in, 2u * sizeof *in2);             /* nop, beql (still annul) */
		in2[1].target_va = 0x9000u;                    /* outside [va_lo, va_hi) */
		put32(&ISAS[4], b + 8, 0x03e00008u);            /* jr ra at instruction 2 */
		CK(kgenome_cell_decode(KGENOME_ARCH_MIPS, 0, b + 8, 4, 0x1008u, &in2[2]) == 4u);
		in2[2].at = 8u;
		memset(&rq, 0, sizeof rq);
		rq.in = in2; rq.n_in = 3; rq.arch = KGENOME_ARCH_MIPS; rq.va_lo = 0x1000; rq.va_hi = 0x100c;
		rq.flags = KGENOME_CFG_F_SPLIT_EXITS;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		/* cfg-2: a conditional branch that leaves the function with KGENOME_CFG_F_SPLIT_EXITS is COND_EXIT,
		 * not a block end - the slot (here a `jr ra`) stays merged into the one block, which simply runs
		 * off the end (no successor: it is the function's last and only block). */
		CK(g.n_all == 1 && g.b[0].n_insn == 3 && g.b[0].term == KGENOME_CFG_T_FALL && g.b[0].succ[0] == KGENOME_CFG_NONE);
		kgenome_cfg_free(&g, NULL);
	}
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

/* PowerPC: no delay slot, `cond` 0 = BO says always. The branch rows of cfg_isa.c, then streams through the builder. */
static void ppc_rows_and_streams(void)
{
	static const struct { const char *what; uint32_t w; int expect; int sys; } PR[] = {
		{ "ppc b",            0x48000100u, X_BRJ, 0 },
		{ "ppc ba",           0x48000102u, X_BRJ, 0 },
		{ "ppc bl",           0x48000101u, X_NONE, 0 },
		{ "ppc beq",          0x41820010u, X_BRC, 0 },
		{ "ppc bne",          0x4082fff8u, X_BRC, 0 },
		{ "ppc bdnz",         0x4200fff8u, X_BRC, 0 },
		{ "ppc bc 20,0 (always)", 0x42800008u, X_BRJ, 0 },
		{ "ppc bcl 20,0,.+4 (get pc)", 0x42800005u, X_NONE, 0 },
		{ "ppc beql",         0x41820011u, X_NONE, 0 },
		{ "ppc blr",          0x4e800020u, X_EXIT, 0 },
		{ "ppc beqlr",        0x4d820020u, X_CEX, 0 },
		{ "ppc bdnzlr",       0x4e000020u, X_CEX, 0 },
		{ "ppc blrl",         0x4e800021u, X_NONE, 0 },
		{ "ppc bctr",         0x4e800420u, X_EXIT, 0 },
		{ "ppc bcctr 12,2",   0x4d820420u, X_CEX, 0 },
		{ "ppc bctrl",        0x4e800421u, X_NONE, 0 },
		{ "ppc sc",           0x44000002u, X_NONE, 1 },
		{ "ppc trap",         0x7fe00008u, X_EXIT, 0 },
		{ "ppc tweq",         0x7c832008u, X_NONE, 0 },
		{ "ppc rfi",          0x4c000064u, X_EXIT, 0 },
		{ "ppc mflr",         0x7c0802a6u, X_NONE, 0 },
		{ "ppc nop",          0x60000000u, X_NONE, 0 },
		{ "ppc invalid word", 0x00000000u, X_EXIT, 0 },
	};
	static const uint32_t diamond[] = { 0x2c030000u, 0x4182000cu, 0x38600001u, 0x4e800020u, 0x38600000u, 0x4e800020u };
	static const uint32_t cret[] = { 0x4d820020u, 0x60000000u, 0x4e800020u };
	static const uint32_t loop[] = { 0x38600003u, 0x38630001u, 0x4200fffcu, 0x4e800020u };
	static const uint32_t tail[] = { 0x7c0802a6u, 0x48000101u, 0x7c0803a6u, 0x48000100u };
	const struct isa_t isa = { KGENOME_ARCH_PPC, 1, "ppc" };
	const struct kgenome_cfg_isa *t = kgenome_cfg_isa_of(KGENOME_ARCH_PPC);
	unsigned i, k;

	CK(t != NULL && kgenome_cfg_isa_of(KGENOME_ARCH_PPC64) != NULL);
	if (!t)
		return;
	CK(!t->delay_slots && t->predicated && t->always_cond == 0);
	for (i = 0; i < sizeof PR / sizeof PR[0]; i++) {
		struct kgenome_cell_insn in;
		uint8_t b[4];
		int degraded = 0;
		enum kgenome_cfg_x x;

		put32(&isa, b, PR[i].w);
		CKM(kgenome_cell_decode(KGENOME_ARCH_PPC, 1, b, 4, 0x1000, &in) == 4u, "%s: does not decode", PR[i].what);
		x = kgenome_cfg_isa_class(t, &in, 1, NULL, 0, &degraded);
		CKM((int)x == PR[i].expect, "%s: class %d want %d (op %u cond %u flags %x)", PR[i].what, (int)x, PR[i].expect, in.op, in.cond, in.flags);
		CKM(!degraded, "%s: degraded", PR[i].what);
		CKM(kgenome_cfg_isa_is_syscall(t, &in) == PR[i].sys, "%s: syscall", PR[i].what);
	}
	/* streams */
	{
		const struct { const uint32_t *w; unsigned n; unsigned blocks, edges; } S[] = {
			{ diamond, 6, 3, 2 }, { cret, 3, 2, 1 }, { loop, 4, 3, 3 }, { tail, 4, 1, 0 },
		};

		for (i = 0; i < sizeof S / sizeof S[0]; i++) {
			struct kgenome_cell_insn in[8];
			struct kgenome_cfg_req rq;
			struct kgenome_cfg g;
			uint8_t b[4];

			for (k = 0; k < S[i].n; k++) {
				put32(&isa, b, S[i].w[k]);
				CK(kgenome_cell_decode(KGENOME_ARCH_PPC, 1, b, 4, 0x1000 + 4u * k, &in[k]) == 4u);
				in[k].at = 4u * k;
			}
			memset(&rq, 0, sizeof rq);
			rq.in = in; rq.n_in = S[i].n; rq.arch = KGENOME_ARCH_PPC; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + 4u * S[i].n;
			CKM(kgenome_cfg_build(&rq, &g) == KGENOME_OK, "ppc stream %u", i);
			CKM(g.n_blk == S[i].blocks && g.n_edge == S[i].edges, "ppc stream %u: %u blocks %u edges (want %u %u)", i,
			    (unsigned)g.n_blk, (unsigned)g.n_edge, S[i].blocks, S[i].edges);
			kgenome_cfg_free(&g, NULL);
		}
	}
}

int main(void)
{
	rows();
	ppc_rows_and_streams();
	unsupported();
	mips_without_bytes();
	mips_slot();
	mips_annul();
	x86_no_split();
	arm_cond_exit_streams();
	if (fails)
		printf("cfg_isa: %d FAILED\n", fails);
	else
		printf("cfg_isa: ok\n");
	return fails != 0;
}
