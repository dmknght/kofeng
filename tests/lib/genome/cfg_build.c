/*
 * genome / cfg_build - the blocks and edges of one function (celllysis/cfg.h), through <kgenome.h> alone, linked
 * against libkgenome.a and nothing else.
 *
 * What it proves, and what each part would miss if it were the only one:
 *   HAND       fixed programs whose blocks were worked out on paper (diamond, loop, a self loop, unreachable
 *              code, a conditional tail call, a tail jump, a switch-shaped indirect jump, an ARM conditional
 *              return, a MIPS `b`, a MIPS call spelt as a branch), assembled for EVERY architecture the
 *              table has and decoded by the lib's own decoder. Labelled R (read, by hand).
 *   REFERENCE  3000 random programs per architecture against ref_build (cfg_kit.h), the textbook leader rule
 *              on the abstract program with no decoder and no lib code in it.
 *   MEMORY     the product is ONE block array; the temporary is released; free leaves an empty struct and a
 *              second free is a no-op.
 */
#include "cfg_kit.h"

struct want {
	uint32_t first_op;
	uint8_t  term;
	uint32_t s0, s1;
	uint8_t  reach;
};

/* The expected blocks of one hand-made program (op indices, not instruction indices). */
struct hand {
	const char *name;
	uint32_t n_ops;
	struct op ops[16];
	uint32_t nb, n_blk, n_edge;
	struct want w[8];
	/* only the architectures that can spell all of its ops: 0 = every one, otherwise a mask over ISAS[] */
	unsigned only;
};

#define N 0xffffffffu
static const struct hand HAND[] = {
	{ "diamond", 6, { {O_NOP,0}, {O_JCC,4}, {O_NOP,0}, {O_JMP,5}, {O_NOP,0}, {O_RET,0} },
	  4, 4, 4, { {0, KGENOME_CFG_T_COND, 2, 1, 1}, {2, KGENOME_CFG_T_JUMP, 3, N, 1}, {4, KGENOME_CFG_T_FALL, 3, N, 1}, {5, KGENOME_CFG_T_EXIT, N, N, 1} }, 0 },
	{ "loop", 3, { {O_NOP,0}, {O_JCC,1}, {O_RET,0} },
	  3, 3, 3, { {0, KGENOME_CFG_T_FALL, 1, N, 1}, {1, KGENOME_CFG_T_COND, 1, 2, 1}, {2, KGENOME_CFG_T_EXIT, N, N, 1} }, 0 },
	{ "unreachable-junk", 3, { {O_RET,0}, {O_NOP,0}, {O_JMP,1} },
	  2, 1, 0, { {0, KGENOME_CFG_T_EXIT, N, N, 1}, {1, KGENOME_CFG_T_JUMP, 1, N, 0} }, 0 },
	{ "cond-tail-call-is-no-block-end", 4, { {O_NOP,0}, {O_JCC,OUT}, {O_NOP,0}, {O_RET,0} },
	  1, 1, 0, { {0, KGENOME_CFG_T_EXIT, N, N, 1} }, 0 },
	{ "tail-jump-leaves", 4, { {O_NOP,0}, {O_JMP,OUT}, {O_NOP,0}, {O_RET,0} },
	  2, 1, 0, { {0, KGENOME_CFG_T_EXIT, N, N, 1}, {2, KGENOME_CFG_T_EXIT, N, N, 0} }, 0 },
	{ "call-and-syscall-do-not-split", 5, { {O_NOP,0}, {O_CALL,OUT}, {O_SYS,0}, {O_NOP,0}, {O_RET,0} },
	  1, 1, 0, { {0, KGENOME_CFG_T_EXIT, N, N, 1} }, 0 },
	{ "indirect-jump-is-exit", 4, { {O_NOP,0}, {O_IJMP,0}, {O_NOP,0}, {O_RET,0} },
	  2, 1, 0, { {0, KGENOME_CFG_T_EXIT, N, N, 1}, {2, KGENOME_CFG_T_EXIT, N, N, 0} }, 0 },
	{ "cond-and-indirect", 5, { {O_JCC,3}, {O_NOP,0}, {O_IJMP,0}, {O_NOP,0}, {O_RET,0} },
	  3, 3, 2, { {0, KGENOME_CFG_T_COND, 2, 1, 1}, {1, KGENOME_CFG_T_EXIT, N, N, 1}, {3, KGENOME_CFG_T_EXIT, N, N, 1} }, 0 },
	{ "falls-off-the-end", 2, { {O_NOP,0}, {O_NOP,0} },
	  1, 1, 0, { {0, KGENOME_CFG_T_FALL, N, N, 1} }, 0 },
	{ "arm-conditional-return-keeps-fall-through", 4, { {O_NOP,0}, {O_CRET,0}, {O_NOP,0}, {O_RET,0} },
	  2, 2, 1, { {0, KGENOME_CFG_T_FALL, 1, N, 1}, {2, KGENOME_CFG_T_EXIT, N, N, 1} }, 1u << 2 },
	{ "mips-b-is-a-jump", 4, { {O_NOP,0}, {O_B,3}, {O_NOP,0}, {O_RET,0} },
	  3, 2, 1, { {0, KGENOME_CFG_T_JUMP, 2, N, 1}, {2, KGENOME_CFG_T_FALL, 2, N, 0}, {3, KGENOME_CFG_T_EXIT, N, N, 1} }, (1u << 4) | (1u << 5) },
	{ "mips-bal-is-a-call", 4, { {O_NOP,0}, {O_BAL,3}, {O_NOP,0}, {O_RET,0} },
	  1, 1, 0, { {0, KGENOME_CFG_T_EXIT, N, N, 1} }, (1u << 4) | (1u << 5) },
	{ "x86-loop-is-conditional", 4, { {O_NOP,0}, {O_LOOP,0}, {O_NOP,0}, {O_RET,0} },
	  3, 3, 3, { {0, KGENOME_CFG_T_FALL, 1, N, 1}, {0, 0, 0, 0, 0}, {2, KGENOME_CFG_T_EXIT, N, N, 1} }, 0 },
};

static void hand_one(const struct hand *h, unsigned ii)
{
	const struct isa_t *isa = &ISAS[ii];
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	struct refg r;
	uint32_t i, b;
	char tag[96];

	if (!strcmp(h->name, "x86-loop-is-conditional"))
		return;         /* checked on its own below: its expected blocks differ by what the loop target is */
	for (i = 0; i < h->n_ops; i++)
		prog_add(&p, h->ops[i].kind, h->ops[i].tgt);
	if (!blob_make(isa, &p, 0x401000, &x)) {
		CKM(h->only != 0 && !(h->only & (1u << ii)), "%s: %s could not spell a program it should", h->name, isa->name);
		prog_free(&p);
		return;
	}
	if (h->only && !(h->only & (1u << ii))) {
		blob_free(&x);
		prog_free(&p);
		return;
	}
	snprintf(tag, sizeof tag, "%s/%s", h->name, isa->name);
	CKM(blob_cfg(isa, &p, &x, &in, &g) == KGENOME_OK, "%s: status", tag);
	CKM(g.n_all == h->nb && g.n_blk == h->n_blk && g.n_edge == h->n_edge, "%s: n_all %u (want %u) n_blk %u (%u) n_edge %u (%u)", tag,
	    g.n_all, h->nb, g.n_blk, h->n_blk, g.n_edge, h->n_edge);
	for (b = 0; b < h->nb && b < g.n_all; b++) {
		const struct want *w = &h->w[b];
		const struct kgenome_cfg_block *k = &g.b[b];

		CKM(k->first == x.insn_of_op[w->first_op] && k->term == w->term && k->succ[0] == w->s0 && k->succ[1] == w->s1 && k->reach == w->reach,
		    "%s: block %u first %u term %u succ %u,%u reach %u", tag, b, k->first, k->term, k->succ[0], k->succ[1], k->reach);
	}
	ref_build(isa, &p, &r);
	CKM(cfg_equals_ref(&g, &r, &x, tag), "%s: differs from the reference", tag);
	refg_free(&r);
	kgenome_cfg_free(&g, NULL);
	free(in);
	blob_free(&x);
	prog_free(&p);
}

static void hand_all(void)
{
	unsigned h, i;

	for (h = 0; h < sizeof HAND / sizeof HAND[0]; h++)
		for (i = 0; i < N_ISAS; i++)
			hand_one(&HAND[h], i);
}

/* x86 `loop`: a conditional branch with a target (rel8). 0 NOP; 1 LOOP -> 0; 2 RET: blocks [0..1] COND (target block 0 = itself, fall block 1). */
static void x86_loop(void)
{
	unsigned ii;

	for (ii = 0; ii < 2; ii++) {
		struct prog p = { 0 };
		struct blob x;
		struct kgenome_cell_insn *in = NULL;
		struct kgenome_cfg g;

		prog_add(&p, O_NOP, 0);
		prog_add(&p, O_LOOP, 0);
		prog_add(&p, O_RET, 0);
		CK(blob_make(&ISAS[ii], &p, 0x1000, &x));
		CK(blob_cfg(&ISAS[ii], &p, &x, &in, &g) == KGENOME_OK);
		CK(g.n_all == 2 && g.b[0].term == KGENOME_CFG_T_COND && g.b[0].succ[0] == 0 && g.b[0].succ[1] == 1 && g.b[1].term == KGENOME_CFG_T_EXIT);
		CK(g.b[0].in_deg == 1 && g.b[1].in_deg == 1);
		kgenome_cfg_free(&g, NULL);
		free(in);
		blob_free(&x);
		prog_free(&p);
	}
}


/* ---- the differences from the lineage's old builder (CONSOLIDATION cfg-1 .. cfg-3 in cfg_build.c), each shown by an input ---- */
static void consolidation(void)
{
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL, *m;
	struct kgenome_cfg g;
	struct kgenome_cfg_req rq;
	uint32_t n, i;

	/* cfg-1: instructions not in strictly increasing address order are BAD_INPUT, never searched anyway */
	prog_add(&p, O_NOP, 0); prog_add(&p, O_JCC, 3); prog_add(&p, O_NOP, 0); prog_add(&p, O_RET, 0);
	CK(blob_make(&ISAS[0], &p, 0x1000, &x));
	n = blob_decode(&ISAS[0], &x, &in);
	blob_map_ops(&p, &x, in, n);
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 3);
	kgenome_cfg_free(&g, NULL);
	m = malloc((size_t)n * sizeof *m);
	memcpy(m, in, (size_t)n * sizeof *m);
	m[2] = in[3]; m[3] = in[2];
	rq.in = m;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_BAD_INPUT && g.b == NULL && g.n_all == 0);
	memcpy(m, in, (size_t)n * sizeof *m);
	m[3].at_va = m[2].at_va;                       /* a duplicate address */
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_BAD_INPUT);
	/* a target inside the extent that is not the start of an instruction is no edge (a jump into the middle of one) */
	memcpy(m, in, (size_t)n * sizeof *m);
	m[1].target_va = in[2].at_va;                  /* the nop after the jcc: a boundary, an edge */
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.b[0].term == KGENOME_CFG_T_COND);
	kgenome_cfg_free(&g, NULL);
	m[1].target_va = in[3].at_va + 1;              /* one byte past the ret: inside the extent, not an instruction */
	rq.va_hi = in[3].at_va + 8;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 1 && g.b[0].term == KGENOME_CFG_T_EXIT);
	kgenome_cfg_free(&g, NULL);
	rq.va_hi = x.va0 + x.len;
	/* the extent ends before the instruction the jcc names (which IS in the array): the target is outside the function */
	memcpy(m, in, (size_t)n * sizeof *m);
	rq.va_hi = in[3].at_va;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 1);
	kgenome_cfg_free(&g, NULL);
	rq.va_hi = x.va0 + x.len;
	free(m);
	rq.in = NULL; rq.n_in = 3;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_BAD_INPUT);
	rq.in = in; rq.n_in = 0;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 0 && g.n_blk == 0 && g.b == NULL);
	CK(kgenome_cfg_build(NULL, &g) == KGENOME_BAD_INPUT);
	free(in); blob_free(&x); prog_free(&p);

	/* cfg-2: split_exits. nop; jcc OUT; nop; ret */
	prog_add(&p, O_NOP, 0); prog_add(&p, O_JCC, OUT); prog_add(&p, O_NOP, 0); prog_add(&p, O_RET, 0);
	for (i = 0; i < 2; i++) {
		CK(blob_make(&ISAS[i], &p, 0x1000, &x));
		n = blob_decode(&ISAS[i], &x, &in);
		blob_map_ops(&p, &x, in, n);
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = n; rq.arch = ISAS[i].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 1 && g.b[0].n_insn == n);
		kgenome_cfg_free(&g, NULL);
		rq.flags = KGENOME_CFG_F_SPLIT_EXITS;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 2 && g.n_blk == 2 && g.n_edge == 1);
		CK(g.b[0].term == KGENOME_CFG_T_FALL && g.b[0].succ[0] == 1 && g.b[0].out_deg == 1 && g.b[1].term == KGENOME_CFG_T_EXIT);
		CK(g.b[0].n_insn == x.insn_of_op[2] && g.b[1].first == x.insn_of_op[2]);
		kgenome_cfg_free(&g, NULL);
		free(in); blob_free(&x);
	}
	prog_free(&p);

	/* cfg-6: a jmp whose target is a relocation hole (target_va BROKEN) leaves the function; nop; jmp hole; nop; ret */
	{
		static const uint8_t code[] = { 0x90, 0xe9, 0, 0, 0, 0, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];
		uint32_t pos = 0, k = 0;

		while (pos < sizeof code) {
			const uint32_t l = kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + pos, (uint32_t)sizeof code - pos, 0x1000 + pos, &v[k]);

			CK(l != 0);
			v[k].at = pos;
			k++;
			pos += l;
		}
		CK(k == 4 && v[1].op == KGENOME_CELL_JMP);
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = k; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1008;
		v[1].target_va = 0x1006;                        /* a local jump over the nop: an edge */
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.b[0].term == KGENOME_CFG_T_JUMP && g.n_edge == 1);
		kgenome_cfg_free(&g, NULL);
		v[1].target_va = KGENOME_BROKEN;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.b[0].term == KGENOME_CFG_T_EXIT && g.n_edge == 0 && g.n_blk == 1);
		kgenome_cfg_free(&g, NULL);
	}
	/* cfg-4: a call that does not return is NOT a block end here: `nop; call abort; ` followed by the next function's first instructions is one block that
	 * falls into them (the lineage cuts it by the callee's name or structure; the signature must not depend on a callee) */
	{
		static const uint8_t code[] = { 0x90, 0xe8, 0, 0, 0, 0, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];
		uint32_t pos = 0, k = 0;

		while (pos < sizeof code) {
			const uint32_t l = kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + pos, (uint32_t)sizeof code - pos, 0x1000 + pos, &v[k]);

			v[k].at = pos;
			k++;
			pos += l;
		}
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = k; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1008;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 1 && g.b[0].n_insn == 4 && g.n_call == 1);
		kgenome_cfg_free(&g, NULL);
	}
	/* cfg-3: x86 iret ends the flow (the old builder let the block go on): nop; iret; nop; ret */
	{
		static const uint8_t code[] = { 0x90, 0xcf, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];

		for (i = 0; i < 4; i++) {
			CK(kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + i, 4 - i, 0x1000 + i, &v[i]) == 1u);
			v[i].at = i;
		}
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = 4; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1004;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 2 && g.n_blk == 1 && g.b[0].term == KGENOME_CFG_T_EXIT && g.b[1].reach == 0);
		kgenome_cfg_free(&g, NULL);
	}
	/* cfg-3: AArch64 b.al is a jump with no fall-through edge (the old builder kept one): nop; b.al +8; nop; ret */
	{
		static const uint32_t w[4] = { 0xd503201fu, 0x5400004eu, 0xd503201fu, 0xd65f03c0u };
		struct kgenome_cell_insn v[4];
		uint8_t b[16];

		for (i = 0; i < 4; i++) {
			put32(&ISAS[3], b + 4u * i, w[i]);
			CK(kgenome_cell_decode(KGENOME_ARCH_ARM64, 0, b + 4u * i, 4, 0x1000 + 4u * i, &v[i]) == 4u);
			v[i].at = 4u * i;
		}
		CK(v[1].op == KGENOME_CELL_JCC && v[1].target_va == 0x100cu);
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = 4; rq.arch = KGENOME_ARCH_ARM64; rq.va_lo = 0x1000; rq.va_hi = 0x1010;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 3 && g.n_blk == 2 && g.n_edge == 1);
		CK(g.b[0].term == KGENOME_CFG_T_JUMP && g.b[0].succ[0] == 2 && g.b[0].succ[1] == KGENOME_CFG_NONE && g.b[1].reach == 0);
		kgenome_cfg_free(&g, NULL);
	}
}

/* FNR-1 (2026-11-04): KGENOME_CFG_F_TRAP_EXITS used to end the path at EVERY one-byte int3/hlt, so an int3 carried
 * INLINE in a function body (instrumented or obfuscated code) cut the block there and orphaned the real code behind
 * it as unreachable. No existing test built a request with this flag at all (the TRAP_EXITS branch of classify()
 * had zero coverage - reason (a), "line never executed"), so the bug was never hit. Fixed: an int3/hlt is the exit
 * only when it stands right after a CALL (the MSVC "call does not return" idiom); anywhere else it is a plain
 * (non-flow) instruction and does not split the block. */
static void fnr1_trap_exits(void)
{
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g;

	/* mid-body int3, NOT after a call: nop; int3; nop; ret - must stay ONE reachable block (the int3 does not end it) */
	{
		static const uint8_t code[] = { 0x90, 0xcc, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];
		uint32_t i;

		for (i = 0; i < 4; i++) {
			CK(kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + i, (uint32_t)sizeof code - i, 0x1000 + i, &v[i]) == 1u);
			v[i].at = i;
		}
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = 4; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1004;
		rq.bytes = code; rq.bytes_len = sizeof code; rq.flags = KGENOME_CFG_F_TRAP_EXITS;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CKM(g.n_all == 1, "fnr1 mid-body int3: n_all %u (want 1: must not split the block)", g.n_all);
		if (g.n_all == 1) {
			CKM(g.b[0].n_insn == 4 && g.b[0].term == KGENOME_CFG_T_EXIT && g.b[0].reach == 1,
			    "fnr1 mid-body int3: n_insn %u term %u reach %u", g.b[0].n_insn, g.b[0].term, g.b[0].reach);
		}
		kgenome_cfg_free(&g, NULL);
	}
	/* the idiom TRAP_EXITS exists for is unchanged: call abort(); int3  - the int3 right after the CALL still ends the path, and the code behind it (another function's bytes here) is unreachable. */
	{
		static const uint8_t code[] = { 0xe8, 0, 0, 0, 0, 0xcc, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];
		uint32_t pos = 0, k = 0, l;

		while (pos < sizeof code) {
			l = kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + pos, (uint32_t)sizeof code - pos, 0x1000 + pos, &v[k]);
			CK(l != 0 && k < 4);
			v[k].at = pos;
			k++;
			pos += l;
		}
		CKM(k == 4, "fnr1 call+int3 fixture: decoded %u insns (want 4)", k);
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = k; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + (uint64_t)sizeof code;
		rq.bytes = code; rq.bytes_len = sizeof code; rq.flags = KGENOME_CFG_F_TRAP_EXITS;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CKM(g.n_all == 2 && g.n_blk == 1, "fnr1 call+int3: n_all %u n_blk %u (want 2,1: the mark after the call still exits)", g.n_all, g.n_blk);
		if (g.n_all == 2)
			CKM(g.b[0].term == KGENOME_CFG_T_EXIT && g.b[0].reach == 1 && g.b[1].reach == 0,
			    "fnr1 call+int3: b0.term %u b0.reach %u b1.reach %u", g.b[0].term, g.b[0].reach, g.b[1].reach);
		kgenome_cfg_free(&g, NULL);
	}
	/* the other byte the flag watches, hlt (0xf4), mid-body and NOT after a call: nop; hlt; nop; ret - same rule, same result */
	{
		static const uint8_t code[] = { 0x90, 0xf4, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];
		uint32_t i;

		for (i = 0; i < 4; i++) {
			CK(kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + i, (uint32_t)sizeof code - i, 0x1000 + i, &v[i]) == 1u);
			v[i].at = i;
		}
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = 4; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1004;
		rq.bytes = code; rq.bytes_len = sizeof code; rq.flags = KGENOME_CFG_F_TRAP_EXITS;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CKM(g.n_all == 1, "fnr1 mid-body hlt: n_all %u (want 1: must not split the block)", g.n_all);
		if (g.n_all == 1)
			CKM(g.b[0].n_insn == 4 && g.b[0].term == KGENOME_CFG_T_EXIT, "fnr1 mid-body hlt: n_insn %u term %u", g.b[0].n_insn, g.b[0].term);
		kgenome_cfg_free(&g, NULL);
	}
	/* hlt right after a call still exits too (the idiom is not int3-only): call abort(); hlt */
	{
		static const uint8_t code[] = { 0xe8, 0, 0, 0, 0, 0xf4, 0x90, 0xc3 };
		struct kgenome_cell_insn v[4];
		uint32_t pos = 0, k = 0, l;

		while (pos < sizeof code) {
			l = kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + pos, (uint32_t)sizeof code - pos, 0x1000 + pos, &v[k]);
			CK(l != 0 && k < 4);
			v[k].at = pos;
			k++;
			pos += l;
		}
		CKM(k == 4, "fnr1 call+hlt fixture: decoded %u insns (want 4)", k);
		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = k; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + (uint64_t)sizeof code;
		rq.bytes = code; rq.bytes_len = sizeof code; rq.flags = KGENOME_CFG_F_TRAP_EXITS;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CKM(g.n_all == 2 && g.n_blk == 1, "fnr1 call+hlt: n_all %u n_blk %u (want 2,1: hlt after the call still exits)", g.n_all, g.n_blk);
		if (g.n_all == 2)
			CKM(g.b[0].term == KGENOME_CFG_T_EXIT && g.b[0].reach == 1 && g.b[1].reach == 0,
			    "fnr1 call+hlt: b0.term %u b0.reach %u b1.reach %u", g.b[0].term, g.b[0].reach, g.b[1].reach);
		kgenome_cfg_free(&g, NULL);
	}
}

/* Random programs: the lib's graph equals the reference's on every architecture that can spell the program. */
static void random_vs_reference(void)
{
	unsigned ii, round, checked[N_ISAS] = { 0 };
	struct crng rg;

	crng_seed(&rg, 20261030);
	for (ii = 0; ii < N_ISAS; ii++) {
		for (round = 0; round < 3000; round++) {
			struct prog p;
			struct blob x;
			struct kgenome_cell_insn *in = NULL;
			struct kgenome_cfg g;
			struct refg r;
			char tag[64];

			prog_random(&ISAS[ii], &rg, 2u + crng_below(&rg, 60), &p);
			if (!blob_make(&ISAS[ii], &p, 0x10000u + 4u * round, &x)) {
				prog_free(&p);
				continue;
			}
			if (isa_is_x86(&ISAS[ii])) {
				/* a x86 `loop` was not drawn (rel8), so every op is encodable */
			}
			ref_build(&ISAS[ii], &p, &r);
			snprintf(tag, sizeof tag, "%s#%u", ISAS[ii].name, round);
			if (blob_cfg(&ISAS[ii], &p, &x, &in, &g) != KGENOME_OK) {
				CKM(0, "%s: build failed", tag);
			} else {
				CKM(cfg_equals_ref(&g, &r, &x, tag), "%s: differs from the reference", tag);
				checked[ii]++;
			}
			kgenome_cfg_free(&g, NULL);
			free(in);
			refg_free(&r);
			blob_free(&x);
			prog_free(&p);
		}
	}
	for (ii = 0; ii < N_ISAS; ii++)
		CKM(checked[ii] > 2000, "%s: only %u programs were checked", ISAS[ii].name, checked[ii]);
}

/* Product and temporaries: one block array lives, one temporary is released; free empties; free twice is nothing. */
static void memory_shape(void)
{
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	struct counting c = { 0 };
	struct kgenome_cfg_mem mem = COUNTING_MEM(&c);
	struct kgenome_cfg_req rq;
	uint32_t i;

	for (i = 0; i < 20; i++)
		prog_add(&p, i % 4 == 3 ? O_JCC : O_NOP, i % 7);
	prog_add(&p, O_RET, 0);
	CK(blob_make(&ISAS[0], &p, 0x1000, &x));
	memset(&rq, 0, sizeof rq);
	x.n_insn = blob_decode(&ISAS[0], &x, &in);
	CK(x.n_insn != 0);
	rq.in = in; rq.n_in = x.n_insn;
	rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len; rq.mem = mem;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(c.n_alloc == 2 && c.n_free == 1);            /* the temporary is already back, the block array is held */
	CK(c.live == (int64_t)((size_t)g.n_all * sizeof *g.b));
	kgenome_cfg_free(&g, &mem);
	CK(c.n_free == 2 && c.live == 0);
	CK(g.b == NULL && g.n_all == 0 && g.n_blk == 0);
	kgenome_cfg_free(&g, &mem);                     /* a second free: nothing */
	CK(c.n_free == 2);
	kgenome_cfg_free(NULL, &mem);
	free(in);
	blob_free(&x);
	prog_free(&p);
}

int main(void)
{
	hand_all();
	x86_loop();
	random_vs_reference();
	memory_shape();
	consolidation();
	fnr1_trap_exits();
	if (fails)
		printf("cfg_build: %d FAILED\n", fails);
	else
		printf("cfg_build: ok\n");
	return fails != 0;
}
