/*
 * cfg_obj.c - THE BLOCK LAYER (celllysis/cfg.h, kgenome_cfg_obj_build; phenotype/fntab_blocks.c): the blocks of a whole object by recursive descent,
 * on bytes built here for each shape (no malware: the bytes reproduce the shape).
 *
 * WHAT IT PINS
 *   descent    a call's target and a branch's target are read, the data behind a jump is not (a linear sweep would read its bytes as a call)
 *   blocks     leaders (seed, target, after a block end, a join), terms, successors as indices, the calls of a block, the facts of a block
 *   said       an indirect jump ends its block INDIRECT and is counted; an indirect call is counted; a target outside the code, inside another
 *              instruction (overlap) or at bytes that decode as nothing is a LOOSE row with its reason; a seed that is not code keeps its entry
 *              with no block and the reason
 *   budget     the work bound stops the descent with OVER_BUDGET, what was read kept, the path's block STOP/BUDGET; a byte allowance too small for
 *              the map is OVER_BUDGET with nothing held
 *   isa        a MIPS delay slot belongs to its branch's block; ARM `mov lr, pc; mov pc, rN` is a call (FU-ARM-PAIR), the code after it is read
 *   one decode on a PE built here: every instruction the walk decoded at the same alignment is read back from its trace (n_fresh 0); a function
 *              that only the descent reads at its true alignment (behind a byte that made the linear walk desynchronise) is decoded fresh and said
 *   D1         a chained .pdata part far from its function is a block (seeded and reached by the function's jump), not a mask
 *   noret      (2026-11-16) a call's continuation waits for its callee: garbage after a call to a function that cannot return is not read (x86-64 ud2, i386
 *              endless loop, a layer of such calls, a tail jump to one, ARM, MIPS with its delay slots); what may return lets it be read (an indirect
 *              jump, an unreadable callee, a callee outside, a join on release); a recursion cycle is resolved as returning and said; the work bound
 *              with a call waiting; ARM `blx label` is the other instruction set
 * Why the old tests missed what this covers: (a) the layer is new; the linear walk it replaces had no test that a data run behind a jmp makes no start.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <celllysis/cfg.h>
#include <celllysis/cfg_private.h>
#include <genotype/image/fntab.h>
#include <genotype/image/pe_image.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>

#include "fntab_pe_kit.h"

#define VA 0x400000u

static int seg_at(void *priv, uint64_t off, struct kgenome_image_seg *out)
{
	(void)priv; (void)off;
	out->lo = 0;
	out->hi = 0x10000u;
	out->delta = (int64_t)VA;
	return 1;
}

static uint64_t off_of_va(void *priv, uint64_t va)
{
	(void)priv;
	return va >= VA && va < VA + 0x10000u ? va - VA : KGENOME_BROKEN;
}

struct one {
	struct kgenome_cell_space sp;
	struct kgenome_cfg_obj_ext ext;
	struct kgenome_cfg_obj_seed seed[8];
	struct kgenome_cfg_obj_req rq;
	struct kgenome_cfg_obj g;
};

static void one(struct one *o, unsigned arch, int be, const uint8_t *b, uint32_t n, const uint64_t *seeds, uint32_t ns, uint64_t max_insn)
{
	uint32_t i;

	memset(o, 0, sizeof *o);
	o->sp.base = b;
	o->sp.size = n;
	o->sp.arch = arch;
	o->sp.be = be;
	o->sp.seg_at = seg_at;
	o->sp.off_of_va = off_of_va;
	o->sp.raw = 1;
	o->ext.off = 0;
	o->ext.len = n;
	for (i = 0; i < ns; i++) {
		o->seed[i].off = seeds[i];
		o->seed[i].src = KGENOME_FN_S_ENTRY;
	}
	o->rq.sp = &o->sp;
	o->rq.ext = &o->ext;
	o->rq.n_ext = 1;
	o->rq.seed = o->seed;
	o->rq.n_seed = ns;
	o->rq.max_insn = max_insn;
	(void)kgenome_cfg_obj_build(&o->rq, &o->g);
}

static const struct kgenome_cfg_obj_block *blk(const struct kgenome_cfg_obj *g, uint64_t off)
{
	const uint32_t i = kgenome_cfg_obj_block_at(g, off);

	return i != KGENOME_CFG_NONE && g->b[i].off == off ? &g->b[i] : NULL;
}

static uint32_t idx(const struct kgenome_cfg_obj *g, uint64_t off)
{
	const uint32_t i = kgenome_cfg_obj_block_at(g, off);

	return i != KGENOME_CFG_NONE && g->b[i].off == off ? i : 0xfffffff0u;
}

static int has_loose(const struct kgenome_cfg_obj *g, uint64_t target, uint8_t why)
{
	uint32_t i;

	for (i = 0; i < g->n_loose; i++)
		if (g->loose[i].target == target && g->loose[i].why == why)
			return 1;
	return 0;
}

/* call f; jmp g; <data that decodes as a call>; f: xor eax,eax; ret; <data>; g: je h; nop; nop; h: ret */
static void t_descent(void)
{
	static uint8_t b[0x30];
	static const uint64_t s0[1] = { 0 };
	struct one o;
	const struct kgenome_cfg_obj_block *x;

	memset(b, 0xff, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xeb\x19", 7);                  /* 0: call 0x10; 5: jmp 0x20 */
	memcpy(b + 7, "\xe8\x10\x00\x00\x00hi\0\0", 9);                  /* 7: a linear sweep reads `call 0x1c` */
	memcpy(b + 0x10, "\x31\xc0\xc3", 3);
	memcpy(b + 0x20, "\x74\x02\x90\x90\xc3", 5);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK);
	CK(o.g.n_b == 5 && o.g.n_insn == 8 && o.g.n_fresh == 8);       /* no `held`: every instruction is decoded here */
	x = blk(&o.g, 0);
	CK(x && x->len == 7 && x->n_insn == 2 && x->term == KGENOME_CFG_OBJ_T_JUMP && x->succ[0] == idx(&o.g, 0x20) && x->succ[1] == KGENOME_CFG_NONE);
	CK(x && (x->flags & KGENOME_CFG_OBJ_B_SEED) && x->n_call == 1 && x->call_first == 0);
	CK(o.g.n_call == 1 && o.g.call[0].at == 0 && o.g.call[0].target == 0x10 && o.g.call[0].tgt_blk == idx(&o.g, 0x10) && o.g.call[0].flags == 0);
	x = blk(&o.g, 0x10);
	CK(x && x->len == 3 && x->term == KGENOME_CFG_OBJ_T_RET && (x->flags & KGENOME_CFG_OBJ_B_CALLED));
	x = blk(&o.g, 0x20);
	CK(x && x->term == KGENOME_CFG_OBJ_T_COND && x->succ[0] == idx(&o.g, 0x24) && x->succ[1] == idx(&o.g, 0x22) && (x->flags & KGENOME_CFG_OBJ_B_BRANCHED));
	x = blk(&o.g, 0x22);
	CK(x && x->term == KGENOME_CFG_OBJ_T_FALL && x->len == 2 && x->succ[1] == idx(&o.g, 0x24));
	x = blk(&o.g, 0x24);
	CK(x && x->term == KGENOME_CFG_OBJ_T_RET && (x->flags & KGENOME_CFG_OBJ_B_BRANCHED));
	CK(kgenome_cfg_obj_block_at(&o.g, 7) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x1c) == KGENOME_CFG_NONE);
	CK(o.g.n_loose == 0 && o.g.n_e == 1 && o.g.e[0].blk == idx(&o.g, 0) && o.g.e[0].src == KGENOME_FN_S_ENTRY);
	CK(kgenome_cfg_obj_block_at(&o.g, 0x23) == idx(&o.g, 0x22));
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* a join: a second seed inside a run read before splits that run's block, and a path that runs into a read instruction falls into it */
static void t_join(void)
{
	static const uint8_t b[] = { 0x90, 0x90, 0x90, 0xc3 };
	static const uint64_t s[2] = { 0, 2 };
	struct one o;

	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s, 2, 0);
	/* the worklist reads the last seed first (2: nop; ret), then 0 runs into 2 */
	CK(o.g.status == KGENOME_OK && o.g.n_b == 2 && o.g.n_insn == 4);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_FALL && blk(&o.g, 0)->succ[1] == idx(&o.g, 2) && blk(&o.g, 0)->len == 2);
	CK(blk(&o.g, 2) && blk(&o.g, 2)->term == KGENOME_CFG_OBJ_T_RET && (blk(&o.g, 2)->flags & KGENOME_CFG_OBJ_B_SEED));
	CK(o.g.n_e == 2);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* a loop: a branch back into the run that read it makes its target a leader (nop; nop; jne 1; ret) */
	{
		static const uint8_t l[] = { 0x90, 0x90, 0x75, 0xfd, 0xc3 };
		static const uint64_t z[1] = { 0 };

		one(&o, KGENOME_ARCH_X86_64, 0, l, sizeof l, z, 1, 0);
		CK(o.g.n_b == 3 && blk(&o.g, 1) && (blk(&o.g, 1)->flags & KGENOME_CFG_OBJ_B_BRANCHED) && blk(&o.g, 1)->term == KGENOME_CFG_OBJ_T_COND &&
		   blk(&o.g, 1)->succ[0] == idx(&o.g, 1) && blk(&o.g, 1)->succ[1] == idx(&o.g, 4) && blk(&o.g, 0)->succ[1] == idx(&o.g, 1));
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* the other order: 0 is read first, the seed 2 lands on a read instruction and still starts a block */
	{
		static const uint64_t r[2] = { 2, 0 };

		one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, r, 2, 0);
		CK(o.g.n_b == 2 && blk(&o.g, 2) && blk(&o.g, 0) && blk(&o.g, 0)->succ[1] == idx(&o.g, 2));
		kgenome_cfg_obj_free(&o.g, NULL);
	}
}

/* what is not known is said: an indirect jump, an indirect call, a call out of the code, a jump into an instruction, bytes that decode as nothing, a seed out of the code */
static void t_said(void)
{
	static uint8_t b[0x20];
	static const uint64_t s[5] = { 0, 2, 0x10, 0x18, 0x40 };
	struct one o;
	uint32_t i;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xff\xe0", 2);                                       /* 0: jmp rax */
	memcpy(b + 2, "\xff\xd0\xe8\x00\x10\x00\x00\xc3", 8);           /* 2: call rax; 4: call 0x1009 (outside); 9: ret */
	memcpy(b + 0x10, "\xb8\xeb\x01\x00\x00\xeb\xfa", 7);            /* 0x10: mov eax,0x1eb; 0x15: jmp 0x11 (inside the mov) */
	b[0x18] = 0x06;                                                 /* 0x18: push es is no x86-64 instruction */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s, 5, 0);
	CK(o.g.status == KGENOME_OK);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_INDIRECT && o.g.n_indirect_jmp == 1);
	CK(o.g.n_indirect_call == 1 && o.g.n_call == 2 && (o.g.call[0].flags & KGENOME_CFG_OBJ_C_INDIRECT) && o.g.call[0].tgt_blk == KGENOME_CFG_NONE);
	CK(o.g.call[1].at == 4 && o.g.call[1].tgt_blk == KGENOME_CFG_NONE && has_loose(&o.g, o.g.call[1].target, KGENOME_CFG_OBJ_W_OUTSIDE));
	CK(has_loose(&o.g, 0x11, KGENOME_CFG_OBJ_W_OVERLAP) && blk(&o.g, 0x10) && blk(&o.g, 0x10)->term == KGENOME_CFG_OBJ_T_JUMP &&
	   blk(&o.g, 0x10)->succ[0] == KGENOME_CFG_NONE);
	for (i = 0; i < o.g.n_e; i++) {
		if (o.g.e[i].off == 0x18)
			CK(o.g.e[i].blk == KGENOME_CFG_NONE && o.g.e[i].why == KGENOME_CFG_OBJ_W_UNDECODABLE);
		if (o.g.e[i].off == 0x40)
			CK(o.g.e[i].blk == KGENOME_CFG_NONE && o.g.e[i].why == KGENOME_CFG_OBJ_W_OUTSIDE);
	}
	CK(o.g.n_e == 5);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* ANTI-DISASSEMBLY: a branch into the middle of the instruction behind it (`je +1; mov eax, imm32` with a ret inside the imm): the target is pushed
	 * unread, then the path's own next instruction covers it; when it is popped it is inside an instruction: LOOSE/OVERLAP, said, not read */
	{
		static const uint8_t c[] = { 0x74, 0x01, 0xb8, 0xc3, 0x90, 0x90, 0x90, 0x0f, 0x0b };
		static const uint64_t z[1] = { 0 };

		one(&o, KGENOME_ARCH_X86_64, 0, c, sizeof c, z, 1, 0);
		CK(o.g.n_loose == 1 && o.g.loose[0].from == 0 && o.g.loose[0].target == 3 && o.g.loose[0].why == KGENOME_CFG_OBJ_W_OVERLAP);
		CK(blk(&o.g, 0) && blk(&o.g, 0)->succ[0] == KGENOME_CFG_NONE && blk(&o.g, 2) && blk(&o.g, 2)->term == KGENOME_CFG_OBJ_T_EXIT);   /* ud2 ends the path */
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* a path that runs into bytes that decode as nothing ends STOP/UNDECODABLE; one that runs off its extent ends STOP/OUTSIDE */
	{
		static const uint8_t c[] = { 0x90, 0x06, 0x90 };
		static const uint64_t z[2] = { 0, 2 };

		one(&o, KGENOME_ARCH_X86_64, 0, c, sizeof c, z, 2, 0);
		CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_STOP && blk(&o.g, 0)->stop == KGENOME_CFG_OBJ_W_UNDECODABLE);
		CK(blk(&o.g, 2) && blk(&o.g, 2)->term == KGENOME_CFG_OBJ_T_STOP && blk(&o.g, 2)->stop == KGENOME_CFG_OBJ_W_OUTSIDE);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* a two-byte instruction whose second byte is the first of an instruction another path read: OVERLAP, not read */
	{
		static const uint8_t c[] = { 0x90, 0x74, 0x90, 0xc3 };          /* seed 2: nop; ret.  seed 0: nop; je (over 2) */
		static const uint64_t z[2] = { 0, 2 };

		one(&o, KGENOME_ARCH_X86_64, 0, c, sizeof c, z, 2, 0);
		CK(blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 1 && blk(&o.g, 0)->stop == KGENOME_CFG_OBJ_W_OVERLAP && o.g.n_insn == 3);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* two extents that overlap: the bytes they share are one place, read once */
	{
		static uint8_t c[0x18];
		static const uint64_t z[2] = { 0, 0x10 };

		memset(c, 0x90, sizeof c);
		c[0x10] = 0xc3;
		one(&o, KGENOME_ARCH_X86_64, 0, c, sizeof c, z, 2, 0);
		kgenome_cfg_obj_free(&o.g, NULL);
		{
			struct kgenome_cfg_obj_ext two[2] = { { 0, 0x14 }, { 0x08, 0x10 } };

			o.rq.ext = two;
			o.rq.n_ext = 2;
			(void)kgenome_cfg_obj_build(&o.rq, &o.g);
			CK(o.g.status == KGENOME_OK && o.g.n_insn == 17 && o.g.n_b == 2 && blk(&o.g, 0x10) && blk(&o.g, 0)->len == 0x10);
			kgenome_cfg_obj_free(&o.g, NULL);
		}
	}
	/* an instruction that would run into one another path read: the path stops before it (OVERLAP), nothing is read twice */
	{
		static const uint8_t c[] = { 0x90, 0xb8, 0x90, 0x90, 0x90, 0x90, 0xc3 };      /* seed 2: nop x4; ret.  seed 0: nop; mov eax,imm32 over them */
		static const uint64_t z[2] = { 0, 2 };

		one(&o, KGENOME_ARCH_X86_64, 0, c, sizeof c, z, 2, 0);
		CK(blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 1 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_STOP && blk(&o.g, 0)->stop == KGENOME_CFG_OBJ_W_OVERLAP);
		CK(blk(&o.g, 2) && blk(&o.g, 2)->n_insn == 5);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
}

/* the caller's allocator: refuses after `left` allocations */
static int g_left = -1;
static void *cnt_alloc(void *u, size_t n) { (void)u; if (g_left == 0) return NULL; if (g_left > 0) g_left--; return malloc(n); }
static void cnt_release(void *u, void *p, size_t n) { (void)u; (void)n; free(p); }

/* more instructions, calls, entries and loose targets than the first allocation holds (64): the tables grow and keep what they held; a refused allocation at
 * each place is NOMEM with nothing held */
static void t_grow(void)
{
	static uint8_t b[0x400];
	static uint64_t s[100];
	struct one o;
	uint32_t i, k;
	int ok_all = 1;

	memset(b, 0x90, sizeof b);
	for (i = 0; i < 100; i++) {                                     /* 100 calls out of the code: 100 loose rows, 100 calls */
		b[i * 5u] = 0xe8;
		memset(b + i * 5u + 1u, 0x7f, 4);
		s[i] = i * 5u;
	}
	b[0x3ff] = 0xc3;
	memset(&o, 0, sizeof o);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s, 8, 0);
	o.rq.seed = NULL;
	o.rq.n_seed = 0;
	kgenome_cfg_obj_free(&o.g, NULL);
	{
		struct kgenome_cfg_obj_seed sd[100];

		for (i = 0; i < 100; i++) {
			sd[i].off = s[i];
			sd[i].src = 1;
		}
		o.rq.seed = sd;
		o.rq.n_seed = 100;
		(void)kgenome_cfg_obj_build(&o.rq, &o.g);
		CK(o.g.status == KGENOME_OK && o.g.n_call == 100 && o.g.n_loose == 100 && o.g.n_e == 100 && o.g.n_b == 100 && o.g.n_insn == 100u + (0x400u - 500u));
		kgenome_cfg_obj_free(&o.g, NULL);
		o.rq.mem.alloc = cnt_alloc;
		o.rq.mem.release = cnt_release;
		for (k = 0; k < 40; k++) {
			g_left = (int)k;
			(void)kgenome_cfg_obj_build(&o.rq, &o.g);
			if (o.g.status == KGENOME_OK)
				break;
			ok_all &= o.g.status == KGENOME_NOMEM && o.g.b == NULL && o.g.n_b == 0;
			kgenome_cfg_obj_free(&o.g, &o.rq.mem);
		}
		CK(ok_all && k > 3 && k < 40);
		kgenome_cfg_obj_free(&o.g, &o.rq.mem);
		g_left = -1;
	}
}

static uint64_t g_cur, g_peak;
static void *peak_alloc(void *u, size_t n)
{
	size_t *p = malloc(n + sizeof(size_t) * 2u);

	(void)u;
	if (!p)
		return NULL;
	p[0] = n;
	g_cur += n;
	if (g_cur > g_peak)
		g_peak = g_cur;
	return p + 2;
}
static void peak_release(void *u, void *q, size_t n)
{
	size_t *p = (size_t *)q - 2;

	(void)u;
	g_cur -= p[0];
	(void)n;
	free(p);
}

static void t_budget(void)
{
	static uint8_t b[0x30];
	static const uint64_t s0[1] = { 0 };
	struct one o;
	struct kgenome_budget bud;
	uint32_t i, stops = 0;

	memset(b, 0xff, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xeb\x19", 7);
	memcpy(b + 0x10, "\x31\xc0\xc3", 3);
	memcpy(b + 0x20, "\x74\x02\x90\x90\xc3", 5);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 3);
	CK(o.g.status == KGENOME_OVER_BUDGET && o.g.n_insn == 3);
	for (i = 0; i < o.g.n_b; i++)
		if (o.g.b[i].term == KGENOME_CFG_OBJ_T_STOP && o.g.b[i].stop == KGENOME_CFG_OBJ_W_BUDGET)
			stops++;
	CK(stops == 1);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* a seed the work bound never reached says so */
	{
		static const uint64_t two[2] = { 0, 0x10 };

		one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, two, 2, 1);
		CK(o.g.status == KGENOME_OVER_BUDGET && o.g.n_e == 2 &&
		   ((o.g.e[0].why == KGENOME_CFG_OBJ_W_BUDGET) + (o.g.e[1].why == KGENOME_CFG_OBJ_W_BUDGET)) == 1);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* THE BYTE ALLOWANCE, swept: no build ever holds more than it allows (the caller's allocator counts), what is kept grows with it, a partial answer is
	 * OVER_BUDGET, and the first allowance that answers OK answers what no allowance does */
	{
		uint32_t full_insn, full_b, mb, saw_partial = 0, saw_none = 0, bad = 0;

		one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
		full_insn = (uint32_t)o.g.n_insn;
		full_b = o.g.n_b;
		kgenome_cfg_obj_free(&o.g, NULL);
		for (mb = 8; mb < 32768u; mb += 8u) {
			memset(&bud, 0, sizeof bud);
			bud.max_bytes = mb;
			one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 0, 0);
			o.rq.n_seed = 1;
			o.rq.budget = &bud;
			o.rq.mem.alloc = peak_alloc;
			o.rq.mem.release = peak_release;
			g_cur = g_peak = 0;
			(void)kgenome_cfg_obj_build(&o.rq, &o.g);
			bad += g_peak > mb;
			if (o.g.status == KGENOME_OVER_BUDGET && !o.g.n_b)
				saw_none++;
			else if (o.g.status == KGENOME_OVER_BUDGET)
				saw_partial++;          /* blocks kept, a later table refused: true and partial */
			else if (o.g.status == KGENOME_OK)
				bad += o.g.n_insn != full_insn || o.g.n_b != full_b;
			else
				bad++;
			{
				const enum kgenome_status st = o.g.status;

				kgenome_cfg_obj_free(&o.g, &o.rq.mem);
				bad += g_cur != 0;      /* everything given back */
				if (st == KGENOME_OK)
					break;
			}
		}
		if (bad || !saw_none || !saw_partial || mb >= 32768u) printf("  sweep: bad %u none %u partial %u mb %u full %u\n", bad, saw_none, saw_partial, mb, full_insn);
		CK(!bad && saw_none && saw_partial && mb < 32768u);
	}
	/* the byte allowance: too small for the map, nothing is held */
	memset(&bud, 0, sizeof bud);
	bud.max_bytes = 16;
	memset(&o, 0, sizeof o);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 0, 0);
	o.rq.n_seed = 1;
	o.rq.budget = &bud;
	(void)kgenome_cfg_obj_build(&o.rq, &o.g);
	CK(o.g.status == KGENOME_OVER_BUDGET && o.g.n_b == 0 && o.g.b == NULL);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* no ISA row: said */
	one(&o, KGENOME_ARCH_RISCV64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_UNSUPPORTED && o.g.n_b == 0);
	/* hostile requests */
	CK(kgenome_cfg_obj_build(NULL, &o.g) == KGENOME_BAD_INPUT && kgenome_cfg_obj_build(&o.rq, NULL) == KGENOME_BAD_INPUT);
	CK(kgenome_cfg_obj_block_at(NULL, 0) == KGENOME_CFG_NONE);
}

/* MIPS32 BE: `b +8` with its delay slot, data, `jr $ra` with its delay slot: two blocks of two instructions; the data is not read */
static void t_mips_delay(void)
{
	static const uint8_t b[] = {
		0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,         /* 0: b 0x0c; nop */
		0xff, 0xff, 0xff, 0xff,                                 /* 8: data */
		0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00          /* 0x0c: jr $ra; nop */
	};
	static const uint64_t s0[1] = { 0 };
	struct one o;

	one(&o, KGENOME_ARCH_MIPS, 1, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_b == 2 && o.g.n_insn == 4);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 2 && blk(&o.g, 0)->len == 8 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_JUMP &&
	   blk(&o.g, 0)->succ[0] == idx(&o.g, 0x0c));
	CK(blk(&o.g, 0x0c) && blk(&o.g, 0x0c)->n_insn == 2 && blk(&o.g, 0x0c)->term == KGENOME_CFG_OBJ_T_RET);
	CK(kgenome_cfg_obj_block_at(&o.g, 8) == KGENOME_CFG_NONE);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* `jr $t9` is a jump through a register (a PIC tail call), not a return */
	{
		static const uint8_t t9[] = { 0x03, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00 };

		one(&o, KGENOME_ARCH_MIPS, 1, t9, sizeof t9, s0, 1, 0);
		CK(o.g.n_b == 1 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_INDIRECT && o.g.n_indirect_jmp == 1);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
}

/* ARM (ARMv4 call through a register): `mov lr, pc; mov pc, r3; bx lr` is one block with a call; without the `mov lr, pc` the jump ends the block */
static void t_arm_pair(void)
{
	static const uint8_t b[] = { 0x0f, 0xe0, 0xa0, 0xe1, 0x03, 0xf0, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1 };
	static const uint8_t c[] = { 0x00, 0x00, 0xa0, 0xe1, 0x03, 0xf0, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1 };     /* mov r0, r0 instead */
	static const uint64_t s0[1] = { 0 };
	struct one o;

	one(&o, KGENOME_ARCH_ARM, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_b == 1 && o.g.n_insn == 3 && blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_RET);
	CK(o.g.n_call == 1 && o.g.call[0].at == 4 && o.g.call[0].flags == (KGENOME_CFG_OBJ_C_INDIRECT | KGENOME_CFG_OBJ_C_LINKED) && o.g.n_indirect_call == 1);
	kgenome_cfg_obj_free(&o.g, NULL);
	one(&o, KGENOME_ARCH_ARM, 0, c, sizeof c, s0, 1, 0);
	CK(o.g.n_b == 1 && o.g.n_insn == 2 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_INDIRECT && o.g.n_call == 0);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* `bxeq lr` leaves only when the condition holds: the path goes on (COND_EXIT, fall-through), `bx lr` returns */
	{
		static const uint8_t d[] = { 0x1e, 0xff, 0x2f, 0x01, 0x1e, 0xff, 0x2f, 0xe1 };

		one(&o, KGENOME_ARCH_ARM, 0, d, sizeof d, s0, 1, 0);
		CK(o.g.n_b == 2 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_COND_EXIT && blk(&o.g, 0)->succ[1] == idx(&o.g, 4) && blk(&o.g, 4)->term == KGENOME_CFG_OBJ_T_RET);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* the pair is two ADJACENT instructions: a `mov lr, pc` that is not right before the jump makes no call */
	{
		const struct kgenome_cfg_isa *isa = kgenome_cfg_isa_of(KGENOME_ARCH_ARM);
		struct kgenome_cell_insn p0, j0;

		CK(kgenome_cell_decode(KGENOME_ARCH_ARM, 0, b, 4, 0x1000, &p0) == 4 && kgenome_cell_decode(KGENOME_ARCH_ARM, 0, b + 4, 4, 0x1004, &j0) == 4);
		p0.at = 0; j0.at = 4;
		CK(isa && kgenome_cfg_isa_linked(isa, &p0, &j0) && !kgenome_cfg_isa_linked(isa, NULL, &j0));
		j0.at = 8;
		CK(!kgenome_cfg_isa_linked(isa, &p0, &j0));
	}
}

/* ---- A CALL'S FALL-THROUGH WAITS FOR ITS CALLEE (2026-11-16) ---------------------------------------------------------------------------------------------
 * Each object below puts GARBAGE right after a call to a function that cannot return: bytes that, read as code, are a call to a fake function. A descent
 * that assumes every call returns (the code before this change) reads them and makes a block and a CALLED target of them; this one does not read them.
 * Why the old tests missed it: (a) every callee of every old row returned. */

/* x86-64: entry `call f; call g; <garbage: call 0x2c>`; f: `xor eax,eax; ret`; g: `mov eax,60; syscall; ud2` (cfg_isa: ud2 is an EXIT, not a return) */
static void t_noret_x64(void)
{
	static uint8_t b[0x30];
	static const uint64_t s0[1] = { 0 };
	struct one o;
	const struct kgenome_cfg_obj_block *x;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xe8\x16\x00\x00\x00", 10);       /* 0: call 0x10; 5: call 0x20 */
	memcpy(b + 0x0a, "\xe8\x1d\x00\x00\x00", 5);                       /* 0x0a: garbage, read as code it is `call 0x2c` */
	memcpy(b + 0x10, "\x31\xc0\xc3", 3);
	memcpy(b + 0x20, "\xb8\x3c\x00\x00\x00\x0f\x05\x0f\x0b", 9);
	b[0x2c] = 0xc3;
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 7 && o.g.n_b == 3);
	CK(kgenome_cfg_obj_block_at(&o.g, 0x0a) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x2c) == KGENOME_CFG_NONE);
	x = blk(&o.g, 0);
	CK(x && x->len == 10 && x->n_insn == 2 && x->n_call == 2 && x->succ[0] == KGENOME_CFG_NONE && x->succ[1] == KGENOME_CFG_NONE);
	CK(x && x->term == KGENOME_CFG_OBJ_T_NORET && (x->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(blk(&o.g, 0x10) && blk(&o.g, 0x10)->term == KGENOME_CFG_OBJ_T_RET && !(blk(&o.g, 0x10)->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(blk(&o.g, 0x20) && blk(&o.g, 0x20)->term == KGENOME_CFG_OBJ_T_EXIT && (blk(&o.g, 0x20)->flags & (KGENOME_CFG_OBJ_B_CALLED | KGENOME_CFG_OBJ_B_NORET)) ==
	   (KGENOME_CFG_OBJ_B_CALLED | KGENOME_CFG_OBJ_B_NORET));
	CK(o.g.n_call == 2 && o.g.call[0].flags == 0 && o.g.call[1].at == 5 && o.g.call[1].flags == KGENOME_CFG_OBJ_C_NORET);
	CK(o.g.n_noret_call == 1 && o.g.n_assumed == 0 && o.g.n_round == 1 && o.g.n_loose == 0);
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* i386: the same with g an endless loop `jmp $` (no return on any path: it is not an exit of the table, it is a loop with no way out) */
static void t_noret_i386(void)
{
	static uint8_t b[0x30];
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xe8\x16\x00\x00\x00\xe8\x1d\x00\x00\x00", 15);
	memcpy(b + 0x10, "\x31\xc0\xc3", 3);
	memcpy(b + 0x20, "\xeb\xfe", 2);
	b[0x2c] = 0xc3;
	one(&o, KGENOME_ARCH_X86, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 5 && o.g.n_b == 3);
	CK(kgenome_cfg_obj_block_at(&o.g, 0x0a) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x2c) == KGENOME_CFG_NONE);
	CK(blk(&o.g, 0x20) && blk(&o.g, 0x20)->term == KGENOME_CFG_OBJ_T_JUMP && blk(&o.g, 0x20)->succ[0] == idx(&o.g, 0x20));
	CK(blk(&o.g, 0x20) && (blk(&o.g, 0x20)->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET && o.g.n_noret_call == 1);
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* a fixed point over layers: entry `call g2; <garbage>`; g2 `call h; <garbage>`; h `ud2`. g2 does not return because h does not; both calls are NORET and
 * neither garbage run is read. And a tail jump: f `jmp g` where g is `ud2`: f does not return either. */
static void t_noret_layers(void)
{
	static uint8_t b[0x40];
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x1b\x00\x00\x00\xe8\x2b\x00\x00\x00", 10);       /* 0: call 0x20; 5: garbage `call 0x35` */
	memcpy(b + 0x20, "\xe8\x0b\x00\x00\x00\xe8\x0b\x00\x00\x00", 10); /* 0x20: call 0x30; 0x25: garbage `call 0x35` */
	memcpy(b + 0x30, "\x0f\x0b", 2);
	b[0x35] = 0xc3;
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 3 && o.g.n_b == 3);
	CK(kgenome_cfg_obj_block_at(&o.g, 5) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x25) == KGENOME_CFG_NONE &&
	   kgenome_cfg_obj_block_at(&o.g, 0x35) == KGENOME_CFG_NONE);
	CK(blk(&o.g, 0x20) && blk(&o.g, 0x20)->term == KGENOME_CFG_OBJ_T_NORET && (blk(&o.g, 0x20)->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(o.g.n_noret_call == 2 && o.g.n_assumed == 0);
	kgenome_cfg_obj_free(&o.g, NULL);
	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xe8\x1d\x00\x00\x00", 10);       /* 0: call 0x10; 5: garbage `call 0x27` */
	memcpy(b + 0x10, "\xe9\x0b\x00\x00\x00", 5);                       /* 0x10: jmp 0x20 */
	memcpy(b + 0x20, "\x0f\x0b", 2);
	b[0x27] = 0xc3;
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 3 && kgenome_cfg_obj_block_at(&o.g, 5) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x27) == KGENOME_CFG_NONE);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET && o.g.n_noret_call == 1);
	CK(blk(&o.g, 0x20) && (blk(&o.g, 0x20)->flags & KGENOME_CFG_OBJ_B_BRANCHED) && !(blk(&o.g, 0x20)->flags & KGENOME_CFG_OBJ_B_CALLED));
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* What may return lets the continuation be read: a callee that ends in an indirect jump (a switch), a callee whose bytes do not decode (said LOOSE, assumed to
 * return), a callee outside the extent, and a continuation another path read first (a join on release). */
static void t_returns(void)
{
	static uint8_t b[0x30];
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\x90\xc3", 7);                      /* 0: call 0x10; nop; ret */
	memcpy(b + 0x10, "\xff\x24\xc5\x00\x10\x00\x00", 7);              /* 0x10: jmp [rax*8+0x1000] */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.n_insn == 4 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 3 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_RET);
	CK(blk(&o.g, 0x10) && blk(&o.g, 0x10)->term == KGENOME_CFG_OBJ_T_INDIRECT && !(blk(&o.g, 0x10)->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(o.g.n_noret_call == 0 && o.g.n_assumed == 0 && o.g.n_round == 0);
	kgenome_cfg_obj_free(&o.g, NULL);
	b[0x10] = 0x06;                                                     /* not an x86-64 instruction */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.n_insn == 3 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 3 && has_loose(&o.g, 0x10, KGENOME_CFG_OBJ_W_UNDECODABLE));
	CK(o.g.n_round == 0);           /* released when its callee's place was found unreadable, not by a proof round */
	kgenome_cfg_obj_free(&o.g, NULL);
	memcpy(b, "\xe8\x00\x10\x00\x00", 5);                              /* 0: call 0x1005 (outside) */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.n_insn == 3 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 3 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_RET);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* a callee whose one way out is a jump out of the extent (a tail call outside) may return: the continuation is read */
	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\x90\xc3", 7);
	memcpy(b + 0x10, "\xe9\xeb\x0f\x00\x00", 5);                 /* 0x10: jmp 0x1000 (outside) */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.n_insn == 4 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 3 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_RET && o.g.n_noret_call == 0);
	kgenome_cfg_obj_free(&o.g, NULL);
	/* a WAITING call does not run into its continuation: entry `call g; L: ret` with g `ud2`, and another seed `jmp L` that reads L (which returns) while the
	 * call waits: the entry still cannot return (its call is NORET; L's return is not the entry's) */
	{
		static const uint64_t s3[2] = { 0x20, 0 };

		memset(b, 0xcc, sizeof b);
		memcpy(b, "\xe8\x0b\x00\x00\x00\xc3", 6);              /* 0: call 0x10; 5: ret */
		memcpy(b + 0x10, "\x0f\x0b", 2);
		memcpy(b + 0x20, "\xe9\xe0\xff\xff\xff", 5);           /* 0x20: jmp 5 */
		one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s3, 2, 0);
		CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET && (blk(&o.g, 0)->flags & KGENOME_CFG_OBJ_B_NORET));
		CK(blk(&o.g, 5) && !(blk(&o.g, 5)->flags & KGENOME_CFG_OBJ_B_NORET) && o.g.n_noret_call == 1);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
	/* the join: seed 0x20 `jmp 5` is read first (the worklist's last seed), so 5 is read and a leader when f returns and the call is released */
	{
		static const uint64_t s2[2] = { 0, 0x20 };

		memset(b, 0xcc, sizeof b);
		memcpy(b, "\xe8\x0b\x00\x00\x00\xc3", 6);                  /* 0: call 0x10; 5: ret */
		b[0x10] = 0xc3;
		memcpy(b + 0x20, "\xe9\xe0\xff\xff\xff", 5);               /* 0x20: jmp 5 */
		one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s2, 2, 0);
		CK(o.g.status == KGENOME_OK && o.g.n_insn == 4 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 1 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_FALL &&
		   blk(&o.g, 0)->succ[1] == idx(&o.g, 5) && !(blk(&o.g, 0)->flags & KGENOME_CFG_OBJ_B_NORET));
		kgenome_cfg_obj_free(&o.g, NULL);
	}
}

/* Recursion. f `call g; ret`, g `call f; ret`: neither can be proven to return or not (each waits on the other): both are RESOLVED AS RETURNING, said
 * (B_ASSUMED, n_assumed 2), and every continuation is read. A recursion with a base case is no cycle of waiting: h `test edi,edi; je L; call h; L: ret`
 * returns through L, nothing is assumed and no proof round is made. */
static void t_recursion(void)
{
	static uint8_t b[0x30];
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xc3", 6);                          /* 0: call f; ret */
	memcpy(b + 0x10, "\xe8\x0b\x00\x00\x00\xc3", 6);                   /* f 0x10: call g; ret */
	memcpy(b + 0x20, "\xe8\xeb\xff\xff\xff\xc3", 6);                   /* g 0x20: call f; ret */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 6 && o.g.n_b == 3);
	CK(blk(&o.g, 0x10) && (blk(&o.g, 0x10)->flags & KGENOME_CFG_OBJ_B_ASSUMED) && !(blk(&o.g, 0x10)->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(blk(&o.g, 0x20) && (blk(&o.g, 0x20)->flags & KGENOME_CFG_OBJ_B_ASSUMED));
	CK(blk(&o.g, 0) && !(blk(&o.g, 0)->flags & (KGENOME_CFG_OBJ_B_ASSUMED | KGENOME_CFG_OBJ_B_NORET)) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_RET);
	CK(o.g.n_assumed == 2 && o.g.n_noret_call == 0 && o.g.n_round == 1);
	kgenome_cfg_obj_free(&o.g, NULL);
	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xc3", 6);                          /* 0: call h; ret */
	memcpy(b + 0x10, "\x85\xff\x74\x05\xe8\xf7\xff\xff\xff\xc3", 10);  /* h 0x10: test edi,edi; je 0x19; call h; 0x19: ret */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 6 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 2);
	CK(o.g.n_assumed == 0 && o.g.n_round == 0 && !(blk(&o.g, 0x10)->flags & (KGENOME_CFG_OBJ_B_ASSUMED | KGENOME_CFG_OBJ_B_NORET)));
	kgenome_cfg_obj_free(&o.g, NULL);
	/* a function that only reaches a recursion cycle waits one round, then is answered by the assumption: entry `call k; ret`, k `call f; ud2`, f/g as above.
	 * k does not return (its call to f is released, and then ud2), so its caller's ret is not read */
	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x2b\x00\x00\x00\xc3", 6);                          /* 0: call 0x30 (k); 5: ret */
	memcpy(b + 0x10, "\xe8\x0b\x00\x00\x00\xc3", 6);
	memcpy(b + 0x20, "\xe8\xeb\xff\xff\xff\xc3", 6);
	{
		static uint8_t c[0x38];
		static const uint64_t s1[1] = { 0 };

		memcpy(c, b, 0x30);
		memcpy(c + 0x30, "\xe8\xdb\xff\xff\xff\x0f\x0b", 7);       /* k 0x30: call 0x10; ud2 */
		one(&o, KGENOME_ARCH_X86_64, 0, c, 0x37, s1, 1, 0);
		CK(o.g.status == KGENOME_OK && kgenome_cfg_obj_block_at(&o.g, 5) == KGENOME_CFG_NONE && blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET);
		CK(o.g.n_assumed == 2 && o.g.n_noret_call == 1 && o.g.n_round == 2 && blk(&o.g, 0x30) && (blk(&o.g, 0x30)->flags & KGENOME_CFG_OBJ_B_NORET));
		kgenome_cfg_obj_free(&o.g, NULL);
	}
}

/* What a round proves is kept: a call met AFTER its callee was proven not to return (in a continuation an assumption released) is NORET at once, with no further
 * round. entry `call f; call h; ret`, f/g a recursion pair, a second seed `call h; ud2`, h `ud2`: round 1 proves h and assumes f and g; the entry's continuation
 * then meets `call h`. And a cycle of three (f -> g -> k -> f) is one component: all three are assumed. And a released continuation past the extent's end
 * stops there (STOP/OUTSIDE on the call). */
static void t_proof_kept(void)
{
	static uint8_t b[0x48];
	static const uint64_t s2[2] = { 0x40, 0 };
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xe8\x26\x00\x00\x00\xc3", 11);      /* 0: call 0x10; 5: call 0x30; 0xa: ret */
	memcpy(b + 0x10, "\xe8\x0b\x00\x00\x00\xc3", 6);                       /* f: call g; ret */
	memcpy(b + 0x20, "\xe8\xeb\xff\xff\xff\xc3", 6);                       /* g: call f; ret */
	memcpy(b + 0x30, "\x0f\x0b", 2);                                           /* h: ud2 */
	memcpy(b + 0x40, "\xe8\xeb\xff\xff\xff\x0f\x0b", 7);                  /* 0x40: call h; ud2 */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s2, 2, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_round == 1 && o.g.n_assumed == 2 && o.g.n_noret_call == 2);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET && blk(&o.g, 0)->n_insn == 2 && kgenome_cfg_obj_block_at(&o.g, 0xa) == KGENOME_CFG_NONE);
	kgenome_cfg_obj_free(&o.g, NULL);
	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xc3", 6);                              /* 0: call f; ret */
	memcpy(b + 0x10, "\xe8\x0b\x00\x00\x00\xc3", 6);                       /* f: call g; ret */
	memcpy(b + 0x20, "\xe8\x0b\x00\x00\x00\xc3", 6);                       /* g: call k; ret */
	memcpy(b + 0x30, "\xe8\xdb\xff\xff\xff\xc3", 6);                       /* k: call f; ret */
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 8 && o.g.n_assumed == 3 && o.g.n_round == 1);
	CK(blk(&o.g, 0x30) && (blk(&o.g, 0x30)->flags & KGENOME_CFG_OBJ_B_ASSUMED) && blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_RET);
	kgenome_cfg_obj_free(&o.g, NULL);
	{
		static uint8_t c[0x15];
		static const uint64_t s1[1] = { 0x10 };

		memset(c, 0xcc, sizeof c);
		c[0] = 0xc3;                                                            /* f 0: ret */
		memcpy(c + 0x10, "\xe8\xeb\xff\xff\xff", 5);                       /* 0x10: call 0, the extent's last bytes */
		one(&o, KGENOME_ARCH_X86_64, 0, c, sizeof c, s1, 1, 0);
		CK(blk(&o.g, 0x10) && blk(&o.g, 0x10)->term == KGENOME_CFG_OBJ_T_STOP && blk(&o.g, 0x10)->stop == KGENOME_CFG_OBJ_W_OUTSIDE);
		kgenome_cfg_obj_free(&o.g, NULL);
	}
}

/* THE PROOF ROUND BOUND (KGENOME_CFG_OBJ_PROOF_ROUNDS): a chain of 70 recursion cycles, each reached only from the continuation of the one before it
 * (f_i `call g_i; call f_i+1; ret`, g_i `call f_i; ret`): every cycle costs a round, and past the bound every callee still waiting is resolved as returning
 * at once (assumed, said) and no call waits any more: the rest is read in one pass. All the code is read; the rounds made are the bound plus one. */
static void t_round_bound(void)
{
	enum { NCYC = 70 };
	static uint8_t b[NCYC * 0x20 + 0x10];
	static const uint64_t s0[1] = { 0 };
	struct one o;
	uint32_t i, assumed = 0;
	int32_t d;

	memset(b, 0xcc, sizeof b);
	for (i = 0; i < NCYC; i++) {
		uint8_t *f = b + 0x20u * i, *g = f + 0x10;

		f[0] = 0xe8; d = 0x10 - 5; memcpy(f + 1, &d, 4);                        /* call g_i */
		f[5] = 0xe8; d = 0x20 - 10; memcpy(f + 6, &d, 4);                       /* call f_i+1 (the last one: the trailing ret) */
		f[10] = 0xc3;
		g[0] = 0xe8; d = -0x10 - 5; memcpy(g + 1, &d, 4);                       /* call f_i */
		g[5] = 0xc3;
	}
	b[NCYC * 0x20] = 0xc3;
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 0, 0);
	o.seed[0].off = 0x10;                                                           /* the chain starts at g_0 (whose caller f_0 is not read first) */
	o.rq.n_seed = 1;
	(void)kgenome_cfg_obj_build(&o.rq, &o.g);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == NCYC * 5u + 1u);
	CK(o.g.n_round == KGENOME_CFG_OBJ_PROOF_ROUNDS + 1u);           /* past the bound no call waits: no further round */
	for (i = 0; i < o.g.n_b; i++)
		assumed += (o.g.b[i].flags & KGENOME_CFG_OBJ_B_ASSUMED) != 0;
	CK(assumed == o.g.n_assumed && o.g.n_assumed == 2u * (KGENOME_CFG_OBJ_PROOF_ROUNDS + 1u));    /* f_i and g_i of every cycle a round reached */
	kgenome_cfg_obj_free(&o.g, NULL);
	(void)s0;
}

/* the work bound with a call waiting: the call's block says STOP/BUDGET, nothing after it is read */
static void t_wait_budget(void)
{
	static uint8_t b[0x20];
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xc3", 6);
	memcpy(b + 0x10, "\x90\xc3", 2);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 1);
	CK(o.g.status == KGENOME_OVER_BUDGET && o.g.n_insn == 1 && blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_STOP &&
	   blk(&o.g, 0)->stop == KGENOME_CFG_OBJ_W_BUDGET);
	kgenome_cfg_obj_free(&o.g, NULL);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 2);
	CK(o.g.status == KGENOME_OVER_BUDGET && o.g.n_insn == 2 && blk(&o.g, 0) && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_STOP);
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* ARM (A32, LE): entry `bl f; bl g; <garbage: bl 0x20>`; f `bx lr`; g `b g`. And `blx label` goes to Thumb code: not read (LOOSE/ISA), assumed to return. */
static void t_noret_arm(void)
{
	static uint8_t b[0x28];
	static const uint64_t s0[1] = { 0 };
	struct one o;

	memset(b, 0, sizeof b);
	memcpy(b, "\x02\x00\x00\xeb\x02\x00\x00\xeb\x04\x00\x00\xeb", 12); /* 0: bl 0x10; 4: bl 0x14; 8: garbage `bl 0x20` */
	memcpy(b + 0x10, "\x1e\xff\x2f\xe1\xfe\xff\xff\xea", 8);           /* 0x10: bx lr; 0x14: b 0x14 */
	memcpy(b + 0x20, "\x1e\xff\x2f\xe1", 4);
	one(&o, KGENOME_ARCH_ARM, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 4 && kgenome_cfg_obj_block_at(&o.g, 8) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x20) == KGENOME_CFG_NONE);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 2 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET && o.g.n_noret_call == 1);
	kgenome_cfg_obj_free(&o.g, NULL);
	memset(b, 0, sizeof b);
	memcpy(b, "\x02\x00\x00\xfa\x1e\xff\x2f\xe1", 8);                   /* 0: blx 0x10 (Thumb); 4: bx lr */
	memcpy(b + 0x10, "\x70\x47", 2);                                    /* 0x10: Thumb `bx lr` */
	one(&o, KGENOME_ARCH_ARM, 0, b, sizeof b, s0, 1, 0);
	CK(o.g.n_insn == 2 && blk(&o.g, 0) && blk(&o.g, 0)->n_insn == 2 && kgenome_cfg_obj_block_at(&o.g, 0x10) == KGENOME_CFG_NONE);
	CK(has_loose(&o.g, 0x10, KGENOME_CFG_OBJ_W_ISA));
	kgenome_cfg_obj_free(&o.g, NULL);
	/* the same word as a `bl` (cond 0b1110) IS read: the instruction set test is the condition field and nothing else */
	b[3] = 0xeb;
	one(&o, KGENOME_ARCH_ARM, 0, b, sizeof b, s0, 1, 0);
	CK(blk(&o.g, 0x10) != NULL && !has_loose(&o.g, 0x10, KGENOME_CFG_OBJ_W_ISA));
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* MIPS32 BE, delay slots: entry `jal f; nop; jal g; nop; <garbage: jal 0x40; nop>`; f `jr ra; nop`; g `b g; nop`. The slot of a call is read with the call and
 * belongs to its block; f's continuation goes on in the same block; g's is not read. */
static void t_noret_mips(void)
{
	static uint8_t b[0x48];
	static const uint64_t s0[1] = { 0 };
	static const uint32_t w[][2] = { { 0x00, 0x0c10000c }, { 0x08, 0x0c100008 }, { 0x10, 0x0c100010 }, { 0x20, 0x1000ffff }, { 0x30, 0x03e00008 },
					 { 0x40, 0x03e00008 } };
	struct one o;
	uint32_t i;

	memset(b, 0, sizeof b);                                             /* 0 is `nop` */
	for (i = 0; i < sizeof w / sizeof *w; i++) {
		b[w[i][0]] = (uint8_t)(w[i][1] >> 24);
		b[w[i][0] + 1u] = (uint8_t)(w[i][1] >> 16);
		b[w[i][0] + 2u] = (uint8_t)(w[i][1] >> 8);
		b[w[i][0] + 3u] = (uint8_t)w[i][1];
	}
	one(&o, KGENOME_ARCH_MIPS, 1, b, sizeof b, s0, 1, 0);
	CK(o.g.status == KGENOME_OK && o.g.n_insn == 8);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->len == 0x10 && blk(&o.g, 0)->n_insn == 4 && blk(&o.g, 0)->term == KGENOME_CFG_OBJ_T_NORET);
	CK(kgenome_cfg_obj_block_at(&o.g, 0x10) == KGENOME_CFG_NONE && kgenome_cfg_obj_block_at(&o.g, 0x40) == KGENOME_CFG_NONE);
	CK(blk(&o.g, 0x20) && blk(&o.g, 0x20)->n_insn == 2 && (blk(&o.g, 0x20)->flags & KGENOME_CFG_OBJ_B_NORET));
	CK(blk(&o.g, 0x30) && blk(&o.g, 0x30)->term == KGENOME_CFG_OBJ_T_RET && o.g.n_noret_call == 1);
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* DISABLED by the owner 2026-11-16: these rows exercise the block layer's seeding (kgenome_fntab_blocks, phenotype/fntab_blocks.c), a function finder from decoded code;
 * the partition is made from metadata only and fntab_blocks.c is in #if 0. To re-enable: take this #if 0 out, the one in main and the one in fntab_blocks.c. */
#if 0
/* ---- a PE built here, through the walk ------------------------------------------------------------------------------------------------ */

static void pe_blocks(const struct pb *p, struct kgenome_cfg_obj *g, struct kgenome_diag_walk **wk_out)
{
	struct tab t;
	struct kgenome_fntab_blocks_req rq;

	memset(&t, 0, sizeof t);
	CK(kgenome_pe_image_parse(kof_buf_make(p->b, p->n), &t.info, &t.obj));
	t.obj.file_header = &t.info;
	t.obj.obj_size = p->n;
	memset(&rq, 0, sizeof rq);
	rq.obj = &t.obj;
	rq.data = p->b;
	rq.data_n = p->n;
	rq.walk = *wk_out = kgenome_diag_walk_new();
	(void)kgenome_fntab_blocks(&rq, g);
}

/* x64: f (entry, .pdata) calls g; g is behind a byte that desynchronises the linear walk (0xb8 eats g's first four bytes); h is a far chained part of f, which f jumps to. */
static void t_pe_one_decode(void)
{
	struct pb p;
	uint32_t t0;
	uint8_t *c;
	struct kgenome_cfg_obj g;
	struct kgenome_diag_walk *wk = NULL;
	uint64_t asked = 0, served;

	pb_init(&p, 0x4000, 1, 0x8664);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".rdata", 0x2000, 0x200, 0x200, CH_RDATA);
	pb_sec(&p, ".pdata", 0x3000, 24, 0x200, CH_RDATA);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x200);
	memcpy(c, "\x48\x83\xec\x28\xe8\0\0\0\0\x48\x83\xc4\x28\xe9\0\0\0\0", 18);         /* f: sub rsp; call g; add rsp; jmp h */
	rel32(c, 4, 5, 0x41);
	rel32(c, 13, 5, 0x100);
	c[0x40] = 0xb8;                                                                     /* a linear walk reads `mov eax, imm32` over g's first bytes */
	memcpy(c + 0x41, "\x31\xc0\xff\xc0\x90\xc3", 6);                                   /* g: xor eax,eax; inc eax; nop; ret */
	memcpy(c + 0x100, "\x31\xc9\xc3", 3);                                              /* h: xor ecx,ecx; ret */
	memcpy(at_rva(&p, 0x2000), "\x01\0\0\0", 4);                                       /* unwind info of f */
	memcpy(at_rva(&p, 0x2010), "\x21\0\0\0", 4);                                       /* of h: version 1, CHAININFO */
	w(at_rva(&p, 0x2014), 0x1000, 4); w(at_rva(&p, 0x2018), 0x1012, 4); w(at_rva(&p, 0x201c), 0x2000, 4);
	w(at_rva(&p, 0x3000), 0x1000, 4); w(at_rva(&p, 0x3004), 0x1012, 4); w(at_rva(&p, 0x3008), 0x2000, 4);
	w(at_rva(&p, 0x300c), 0x1100, 4); w(at_rva(&p, 0x3010), 0x1103, 4); w(at_rva(&p, 0x3014), 0x2010, 4);
	pb_dir(&p, KGENOME_PE_DIR_EXCEPTION, 0x3000, 24);
	pb_done(&p);
	pe_blocks(&p, &g, &wk);
	CK(g.status == KGENOME_OK);
	CK(blk(&g, t0) && (blk(&g, t0)->flags & KGENOME_CFG_OBJ_B_SEED) && blk(&g, t0)->term == KGENOME_CFG_OBJ_T_JUMP && blk(&g, t0)->succ[0] == idx(&g, t0 + 0x100));
	CK(blk(&g, t0 + 0x41) && (blk(&g, t0 + 0x41)->flags & (KGENOME_CFG_OBJ_B_CALLED | KGENOME_CFG_OBJ_B_FRESH)) == (KGENOME_CFG_OBJ_B_CALLED | KGENOME_CFG_OBJ_B_FRESH));
	CK(blk(&g, t0 + 0x100) && (blk(&g, t0 + 0x100)->flags & (KGENOME_CFG_OBJ_B_SEED | KGENOME_CFG_OBJ_B_BRANCHED)) == (KGENOME_CFG_OBJ_B_SEED | KGENOME_CFG_OBJ_B_BRANCHED));
	CK(!(blk(&g, t0)->flags & KGENOME_CFG_OBJ_B_FRESH) && !(blk(&g, t0 + 0x100)->flags & KGENOME_CFG_OBJ_B_FRESH));
	/* f's four, g's nop and ret (the walk met them again after the `mov eax` ended) and h's two were read back from the trace; g's first two were not
	 * where the walk read */
	CK(g.n_insn == 10 && g.n_fresh == 2);
	served = kgenome_diag_walk_held_count(wk, &asked);
	CK(served == 8 && asked == 10);
	CK(kgenome_cfg_obj_block_at(&g, t0 + 0x40) == KGENOME_CFG_NONE);
	CK(g.n_e == 2 && g.e[0].src == (KGENOME_FN_S_PDATA | KGENOME_FN_S_ENTRY) && g.e[1].src == KGENOME_FN_S_PDATA);    /* f (.pdata, entry), h (.pdata, chained) */
	kgenome_cfg_obj_free(&g, NULL);
	kgenome_diag_walk_free(wk);
	free(p.b);
}
#endif

/* PM5-D2 (2026-11-17): the ONE trap instruction behind a call that does not return goes in the call's block, which still ends T_NORET; a trap a seed names
 * (a leader) is not taken; what is not a trap is not read. 0: call 0x10; 5: hlt; 6: ud2 (not read: one trap only); 0x10: jmp $. RED before traps(): the
 * block was 5 bytes. Then with a seed at 5 the hlt is that seed's block, not the call's. */
static void t_trap(void)
{
	static uint8_t b[0x20];
	static const uint64_t s0[1] = { 0 }, s1[2] = { 0, 5 };
	struct one o;
	const struct kgenome_cfg_obj_block *x;

	memset(b, 0x00, sizeof b);
	memcpy(b, "\xe8\x0b\x00\x00\x00\xf4\x0f\x0b", 8);
	memcpy(b + 0x10, "\xeb\xfe", 2);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s0, 1, 0);
	x = blk(&o.g, 0);
	CK(o.g.status == KGENOME_OK && x && x->len == 6 && x->n_insn == 2 && x->term == KGENOME_CFG_OBJ_T_NORET && o.g.n_noret_call == 1);
	CK(kgenome_cfg_obj_block_at(&o.g, 6) == KGENOME_CFG_NONE && o.g.n_insn == 3);
	kgenome_cfg_obj_free(&o.g, NULL);
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s1, 2, 0);
	CK(blk(&o.g, 0) && blk(&o.g, 0)->len == 5 && blk(&o.g, 5) && (blk(&o.g, 5)->flags & KGENOME_CFG_OBJ_B_SEED) && !(blk(&o.g, 5)->flags & KGENOME_CFG_OBJ_B_FALLEN));
	kgenome_cfg_obj_free(&o.g, NULL);
}

/* KGENOME_CFG_OBJ_B_FALLEN (2026-11-17): a leader the instruction before runs into, that instruction no call: 0 seed: nop; 1 seed: nop; 2: call 0x10;
 * 7 seed: ret; 0x10: ret. Block 1 is FALLEN (a nop runs into it), block 7 is not (a call's continuation), block 0 is not (nothing before). */
static void t_fallen(void)
{
	static uint8_t b[0x14];
	static const uint64_t s[3] = { 0, 1, 7 };
	struct one o;

	memset(b, 0xcc, sizeof b);
	memcpy(b, "\x90\x90\xe8\x09\x00\x00\x00\xc3", 8);
	b[0x10] = 0xc3;
	one(&o, KGENOME_ARCH_X86_64, 0, b, sizeof b, s, 3, 0);
	CK(o.g.status == KGENOME_OK && blk(&o.g, 0) && blk(&o.g, 1) && blk(&o.g, 7));
	CK(blk(&o.g, 0) && !(blk(&o.g, 0)->flags & KGENOME_CFG_OBJ_B_FALLEN));
	CK(blk(&o.g, 1) && (blk(&o.g, 1)->flags & KGENOME_CFG_OBJ_B_FALLEN));
	CK(blk(&o.g, 7) && !(blk(&o.g, 7)->flags & KGENOME_CFG_OBJ_B_FALLEN));
	kgenome_cfg_obj_free(&o.g, NULL);
}

int main(void)
{
	t_descent();
	t_trap();
	t_fallen();
	t_join();
	t_said();
	t_budget();
	t_grow();
	t_mips_delay();
	t_arm_pair();
	t_noret_x64();
	t_noret_i386();
	t_noret_layers();
	t_returns();
	t_recursion();
	t_wait_budget();
	t_round_bound();
	t_proof_kept();
	t_noret_arm();
	t_noret_mips();
#if 0 /* DISABLED by the owner 2026-11-16: the block layer's seeding */
	t_pe_one_decode();
#endif
	printf("cfg_obj: %d failure(s)\n", fails);
	return fails != 0;
}
