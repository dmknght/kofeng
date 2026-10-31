/*
 * genome / cfg_callee - the facts a graph carries about its calls, and the SECOND signature over the callees' identities
 * (celllysis/cfg.h: kgenome_cfg_callee_src, kgenome_cfg_call, KGENOME_CFG_P_*, kgenome_cfg_pct_callee, KGENOME_CFG_ANCHOR_CALLEES).
 *
 * The identities here are SYNTHETIC numbers the test's callback makes up: the lib stores them, never computes or interprets one.
 *   FACTS       one record per call or syscall instruction of a reachable block, in instruction order, with the kind the lib reads
 *               (indirect, syscall, direct) or the caller's; a block says where its records are, how many, which kinds
 *   STRUCT ONLY the default policy leaves every callee field empty and the structural result is bit for bit the measured one
 *   SEPARATE    same shape + other identities: structural pct 100, callee pct moves; same identities + other shape: the reverse
 *   UNRESOLVED  identity 0 adds no element: a function of unresolved calls has no callee sketch, zeros never match each other,
 *               an extra unresolved call changes nothing
 *   MULTISET    counts matter: {1,1,1,2} against {1,1,2,2} is 3/5; the kind is part of the element
 *   REACHABLE   calls in unreachable blocks are not facts and not scored
 *   ANCHOR      a list of required identities, all of them; 0 never matches
 *   RESOURCES   budget and refusing allocator over the policy BOTH sign: OVER_BUDGET / NOMEM, nothing leaks
 */
#include "cfg_kit.h"

struct ids {
	uint64_t id[256];
	uint8_t  kind[256];
	uint32_t n, seen;
	uint32_t insn_seen[256];
};

static uint64_t id_of(void *user, uint32_t insn, const struct kgenome_cell_insn *in, uint8_t *kind)
{
	struct ids *c = user;
	const uint32_t k = c->seen++;

	(void)in;
	if (k < 256)
		c->insn_seen[k] = insn;
	if (k >= c->n)
		return 0;
	*kind = c->kind[k];
	return c->id[k];
}

/* Build `g` (x86-64) with the callee callback; returns the decoded array (free it). */
static struct kgenome_cell_insn *build_with(const struct gspec *g, struct ids *ids, struct kgenome_cfg *cg)
{
	struct prog p;
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg_req rq;
	uint32_t n;

	gspec_prog(g, &p, NULL);
	CK(blob_make(&ISAS[0], &p, 0x1000, &x));
	n = blob_decode(&ISAS[0], &x, &in);
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len;
	rq.callee.id_of = ids ? id_of : NULL;
	rq.callee.user = ids;
	if (ids)
		ids->seen = 0;
	CK(kgenome_cfg_build(&rq, cg) == KGENOME_OK);
	blob_free(&x);
	prog_free(&p);
	return in;
}

static enum kgenome_status sign_pol(const struct kgenome_cfg *g, unsigned policy, struct kgenome_cfg_sign *s)
{
	struct kgenome_cfg_sign_req rq;

	memset(&rq, 0, sizeof rq);
	rq.g = g;
	rq.policy = policy;
	return kgenome_cfg_sign(&rq, s);
}

/* a 14-block function shaped by `seed`, `calls` calls spread over its blocks */
static void shaped(struct gspec *g, uint32_t seed, uint32_t calls)
{
	struct crng r;
	uint32_t b;

	crng_seed(&r, seed);
	memset(g, 0, sizeof *g);
	g->nb = 14;
	for (b = 0; b < 14; b++) {
		g->kind[b] = b == 13 ? G_EXIT : (b % 3 == 2 ? G_COND : G_JUMP);
		g->t[b] = b == 13 ? 0u : (b % 3 == 2 ? (b + 2u < 14u ? b + 2u : 13u) : b + 1u);
		if (g->kind[b] == G_COND && b + 1u >= 14u)
			g->kind[b] = G_EXIT;
	}
	while (calls--)
		g->calls[crng_below(&r, 14)]++;
}

static void facts(void)
{
	/* nop; call rel; call *rax; syscall; nop; ret ; plus an unreachable block with a call */
	static const uint8_t code[] = { 0x90, 0xe8, 0, 0, 0, 0, 0xff, 0xd0, 0x0f, 0x05, 0x90, 0xc3, /* unreachable: */ 0xe8, 0, 0, 0, 0, 0xc3 };
	struct kgenome_cell_insn in[16];
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g;
	struct ids ids;
	uint32_t pos = 0, n = 0;

	while (pos < sizeof code) {
		const uint32_t l = kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + pos, (uint32_t)sizeof code - pos, 0x1000 + pos, &in[n]);

		CK(l != 0);
		in[n].at = pos;
		n++;
		pos += l;
	}
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + sizeof code;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(g.n_all == 2 && g.n_blk == 1);
	CK(g.n_call == 3 && g.b[0].n_call == 3 && g.b[0].call_first == 0 && g.b[1].n_call == 0 && g.b[1].call_kinds == 0);
	CK(g.call[0].insn == 1 && g.call[1].insn == 2 && g.call[2].insn == 3);
	CK(g.call[0].kind == KGENOME_CFG_CK_DIRECT && g.call[1].kind == KGENOME_CFG_CK_INDIRECT && g.call[2].kind == KGENOME_CFG_CK_SYSCALL);
	CK(g.call[0].id == 0 && g.call[1].id == 0 && g.call[2].id == 0);
	kgenome_cfg_free(&g, NULL);
	CK(g.call == NULL && g.n_call == 0);
	/* the caller's identities and kinds: asked once per call of a REACHABLE block, in order; kind 0 leaves the lib's reading */
	memset(&ids, 0, sizeof ids);
	ids.n = 3; ids.id[0] = 0xaaaa; ids.kind[0] = KGENOME_CFG_CK_IMPORT; ids.id[1] = 0xbbbb; ids.kind[1] = 0; ids.id[2] = 59; ids.kind[2] = 0;
	rq.callee.id_of = id_of; rq.callee.user = &ids;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(ids.seen == 3 && ids.insn_seen[0] == 1 && ids.insn_seen[1] == 2 && ids.insn_seen[2] == 3);
	CK(g.call[0].id == 0xaaaa && g.call[0].kind == KGENOME_CFG_CK_IMPORT);
	CK(g.call[1].id == 0xbbbb && g.call[1].kind == KGENOME_CFG_CK_INDIRECT && g.call[2].id == 59 && g.call[2].kind == KGENOME_CFG_CK_SYSCALL);
	CK(g.b[0].call_kinds == ((1u << KGENOME_CFG_CK_IMPORT) | (1u << KGENOME_CFG_CK_INDIRECT) | (1u << KGENOME_CFG_CK_SYSCALL)));
	kgenome_cfg_free(&g, NULL);
	/* a kind the enum does not have is stored and cannot index outside the byte */
	ids.kind[0] = 255;
	ids.seen = 0;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.call[0].kind == 255);
	kgenome_cfg_free(&g, NULL);
}

static void default_is_struct_only(void)
{
	struct gspec g;
	struct ids ids;
	struct kgenome_cfg cg;
	struct kgenome_cfg_sign a, b, c, d;
	struct kgenome_cell_insn *in;
	uint32_t i;

	shaped(&g, 1, 8);
	memset(&ids, 0, sizeof ids);
	ids.n = 8;
	for (i = 0; i < 8; i++) { ids.id[i] = 100u + i; ids.kind[i] = KGENOME_CFG_CK_IMPORT; }
	in = build_with(&g, &ids, &cg);
	CK(sign_pol(&cg, 0, &a) == KGENOME_OK);
	CK(a.n_ckey == 0 && a.n_cid == 0 && a.ccanon == 0 && a.n_key > 0 && a.canon != 0);
	CK(sign_pol(&cg, KGENOME_CFG_P_STRUCT, &b) == KGENOME_OK && sign_eq(&a, &b) && b.n_ckey == 0);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &c) == KGENOME_OK && sign_eq(&a, &c));         /* the structural part is the measured one */
	CK(c.n_ckey == 8 && c.n_cid == 8 && c.ccanon != 0);
	CK(sign_pol(&cg, KGENOME_CFG_P_CALLEES, &d) == KGENOME_OK);
	CK(d.canon == 0 && d.n_key == 0 && d.n_ckey == 8 && d.ccanon == c.ccanon && !memcmp(d.ckey, c.ckey, sizeof c.ckey) && d.n_blk == cg.n_blk);
	CK(sign_pol(&cg, 4, &d) == KGENOME_BAD_INPUT);
	kgenome_cfg_free(&cg, NULL);
	free(in);
}

static void separate_scores(void)
{
	struct gspec g, h;
	struct ids ids, other;
	struct kgenome_cfg cg;
	struct kgenome_cfg_sign a, b, c;
	struct kgenome_cell_insn *in;
	uint32_t i;

	shaped(&g, 2, 10);
	memset(&ids, 0, sizeof ids);
	ids.n = 10;
	for (i = 0; i < 10; i++) { ids.id[i] = 1000u + i; ids.kind[i] = KGENOME_CFG_CK_LOCAL; }
	other = ids;
	for (i = 0; i < 5; i++) other.id[i] = 5000u + i;                    /* half of the identities changed */
	in = build_with(&g, &ids, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &a) == KGENOME_OK);
	kgenome_cfg_free(&cg, NULL); free(in);
	in = build_with(&g, &other, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &b) == KGENOME_OK);
	kgenome_cfg_free(&cg, NULL); free(in);
	/* same structure, other identities: the structural score does not move, the callee score does */
	CK(a.canon == b.canon && kgenome_cfg_pct(&a, &b) == 100u);
	CK(a.ccanon != b.ccanon && kgenome_cfg_pct_callee(&a, &b) == 100u * 5u / 15u);        /* 5 shared of 15 distinct elements */
	CK(kgenome_cfg_pct_callee(&a, &a) == 100u && kgenome_cfg_pct_callee(&a, &b) == kgenome_cfg_pct_callee(&b, &a));
	/* same identities, another shape (a block's exit becomes a jump): the callee score does not move, the structural one does */
	h = g;
	h.kind[13] = G_JUMP; h.t[13] = 4;
	in = build_with(&h, &ids, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &c) == KGENOME_OK);
	kgenome_cfg_free(&cg, NULL); free(in);
	CK(c.canon != a.canon && kgenome_cfg_pct(&a, &c) < 100u);
	CK(c.ccanon == a.ccanon && kgenome_cfg_pct_callee(&a, &c) == 100u);
	/* the kind is part of an element: the same numbers as imports are not the same callees as local functions */
	for (i = 0; i < 10; i++) other.id[i] = ids.id[i], other.kind[i] = KGENOME_CFG_CK_IMPORT;
	in = build_with(&g, &other, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &b) == KGENOME_OK && kgenome_cfg_pct_callee(&a, &b) == 0u && a.canon == b.canon);
	kgenome_cfg_free(&cg, NULL); free(in);
}

static void unresolved(void)
{
	struct gspec g, h;
	struct ids ids, none;
	struct kgenome_cfg cg;
	struct kgenome_cfg_sign a, b, z1, z2;
	struct kgenome_cell_insn *in;
	uint32_t i;

	shaped(&g, 3, 8);
	memset(&ids, 0, sizeof ids);
	ids.n = 8;
	for (i = 0; i < 8; i++) { ids.id[i] = 7000u + i; ids.kind[i] = KGENOME_CFG_CK_IMPORT; }
	/* every identity unresolved: no sketch, and two such functions do not match through their zeros */
	memset(&none, 0, sizeof none);
	none.n = 8;
	in = build_with(&g, &none, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &z1) == KGENOME_OK && z1.n_ckey == 0 && z1.n_cid == 0);
	kgenome_cfg_free(&cg, NULL); free(in);
	in = build_with(&g, NULL, &cg);                   /* no callback at all: the same */
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &z2) == KGENOME_OK && z2.n_ckey == 0);
	kgenome_cfg_free(&cg, NULL); free(in);
	CK(kgenome_cfg_pct_callee(&z1, &z2) == 0u && kgenome_cfg_pct_callee(&z1, &z1) == 0u);
	/* the first three calls unresolved: the other five are scored and the three change nothing about them */
	in = build_with(&g, &ids, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &a) == KGENOME_OK);
	kgenome_cfg_free(&cg, NULL); free(in);
	/* the same five identities in a function with three more calls, all unresolved (zeros between them): same callee sketch */
	h = g;
	h.calls[0] = (uint8_t)(h.calls[0] + 3);
	{
		struct ids part;

		memset(&part, 0, sizeof part);
		/* calls of block 0 come first in instruction order: the three new ones are unresolved, then the old eight follow */
		part.n = 11;
		for (i = 0; i < 11; i++) {
			part.id[i] = i < 3 ? 0 : ids.id[i - 3];
			part.kind[i] = KGENOME_CFG_CK_IMPORT;
		}
		(void)part;
		in = build_with(&g, &ids, &cg);
		kgenome_cfg_free(&cg, NULL); free(in);
		in = build_with(&h, &part, &cg);
		CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &b) == KGENOME_OK);
		kgenome_cfg_free(&cg, NULL); free(in);
	}
	CKM(b.n_cid == 8 && b.n_ckey == a.n_ckey && b.ccanon == a.ccanon && !memcmp(a.ckey, b.ckey, sizeof a.ckey), "unresolved calls changed the callee signature (%u,%u)", a.n_cid, b.n_cid);
	CK(kgenome_cfg_pct_callee(&a, &b) == 100u && a.canon == b.canon);
}

static void multiset_counts(void)
{
	struct gspec g;
	struct ids x, y;
	struct kgenome_cfg cg;
	struct kgenome_cfg_sign a, b;
	struct kgenome_cell_insn *in;
	uint32_t i;

	shaped(&g, 4, 4);
	memset(&x, 0, sizeof x);
	x.n = 4;
	y = x;
	for (i = 0; i < 4; i++) { x.kind[i] = y.kind[i] = KGENOME_CFG_CK_LOCAL; }
	x.id[0] = x.id[1] = x.id[2] = 1; x.id[3] = 2;      /* {1,1,1,2} */
	y.id[0] = y.id[1] = 1; y.id[2] = y.id[3] = 2;      /* {1,1,2,2} */
	in = build_with(&g, &x, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_CALLEES, &a) == KGENOME_OK && a.n_ckey == 4);
	kgenome_cfg_free(&cg, NULL); free(in);
	in = build_with(&g, &y, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_CALLEES, &b) == KGENOME_OK && b.n_ckey == 4);
	kgenome_cfg_free(&cg, NULL); free(in);
	CKM(kgenome_cfg_pct_callee(&a, &b) == 60u, "multiset {1,1,1,2} vs {1,1,2,2}: %u (want 3/5 = 60)", kgenome_cfg_pct_callee(&a, &b));
	CK(a.ccanon != b.ccanon);
	/* order of the calls is not part of it */
	{
		struct ids z = x;

		z.id[0] = 2; z.id[3] = 1;
		in = build_with(&g, &z, &cg);
		CK(sign_pol(&cg, KGENOME_CFG_P_CALLEES, &b) == KGENOME_OK);
		kgenome_cfg_free(&cg, NULL); free(in);
		CK(b.ccanon == a.ccanon && kgenome_cfg_pct_callee(&a, &b) == 100u);
	}
}

static void reachable_only(void)
{
	struct gspec g, h;
	struct ids ids;
	struct kgenome_cfg cg;
	struct kgenome_cfg_sign a, b;
	struct kgenome_cell_insn *in;

	shaped(&g, 5, 6);
	memset(&ids, 0, sizeof ids);
	ids.n = 40;
	{
		uint32_t i;
		for (i = 0; i < 40; i++) { ids.id[i] = 900u + i; ids.kind[i] = KGENOME_CFG_CK_IMPORT; }
	}
	in = build_with(&g, &ids, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_CALLEES, &a) == KGENOME_OK && a.n_cid == 6);
	CK(ids.seen == 6);
	kgenome_cfg_free(&cg, NULL); free(in);
	/* an unreachable block with calls at the end: neither asked for nor scored */
	h = g;
	h.kind[13] = G_EXIT;
	h.nb = 15; h.kind[14] = G_EXIT; h.calls[14] = 5; h.pad[14] = 0;
	in = build_with(&h, &ids, &cg);
	CK(cg.n_all == 15 && cg.n_blk == 14 && ids.seen == 6 && cg.n_call == 6);
	CK(sign_pol(&cg, KGENOME_CFG_P_CALLEES, &b) == KGENOME_OK && b.ccanon == a.ccanon && kgenome_cfg_pct_callee(&a, &b) == 100u);
	kgenome_cfg_free(&cg, NULL); free(in);
}

static void anchor(void)
{
	struct gspec g;
	struct ids ids;
	struct kgenome_cfg cg;
	struct kgenome_cell_insn *in;
	struct kgenome_cfg_anchor_req r;
	uint64_t need_ok[2] = { 31, 33 }, need_missing[2] = { 31, 99 }, need_zero[1] = { 0 };

	memset(&g, 0, sizeof g);
	g.nb = 2; g.kind[0] = G_JUMP; g.t[0] = 1; g.kind[1] = G_EXIT; g.calls[0] = 3;       /* 2 blocks: far under a floor of 12 */
	memset(&ids, 0, sizeof ids);
	ids.n = 3; ids.id[0] = 31; ids.id[1] = 32; ids.id[2] = 33;
	ids.kind[0] = ids.kind[1] = ids.kind[2] = KGENOME_CFG_CK_IMPORT;
	in = build_with(&g, &ids, &cg);
	memset(&r, 0, sizeof r);
	r.min_blk = 12u;                                        /* the default floor is one block now: ask for a floor the 2 blocks do not reach */
	CK(!kgenome_cfg_anchor(&cg, &r));
	r.or_flags = KGENOME_CFG_ANCHOR_CALLEES; r.need = need_ok; r.n_need = 2;
	CK(kgenome_cfg_anchor(&cg, &r));
	r.need = need_missing;
	CK(!kgenome_cfg_anchor(&cg, &r));
	r.need = need_zero; r.n_need = 1;
	CK(!kgenome_cfg_anchor(&cg, &r));                       /* 0 is unresolved: never required, never matched */
	r.need = need_ok; r.n_need = 0;
	CK(!kgenome_cfg_anchor(&cg, &r));                       /* no list, no pass */
	r.n_need = 2; r.or_flags = 0;
	CK(!kgenome_cfg_anchor(&cg, &r));                       /* the flag is what asks */
	r.or_flags = KGENOME_CFG_ANCHOR_CALLEES; r.min_blk = 2;
	CK(kgenome_cfg_anchor(&cg, &r));
	r.need = NULL;
	CK(kgenome_cfg_anchor(&cg, &r));                        /* min_blk 2 passes on the blocks alone */
	r.min_blk = 12u;
	CK(!kgenome_cfg_anchor(&cg, &r));
	kgenome_cfg_free(&cg, NULL);
	free(in);
	/* a function WITH an unresolved call: a required identity 0 still matches nothing */
	ids.n = 1;
	in = build_with(&g, &ids, &cg);
	CK(cg.n_call == 3 && cg.call[1].id == 0 && cg.call[2].id == 0);
	r.or_flags = KGENOME_CFG_ANCHOR_CALLEES; r.need = need_zero; r.n_need = 1; r.min_blk = 12u;
	CK(!kgenome_cfg_anchor(&cg, &r));
	kgenome_cfg_free(&cg, NULL);
	free(in);
}

static void resources(void)
{
	struct gspec g;
	struct ids ids;
	struct kgenome_cfg cg;
	struct kgenome_cell_insn *in;
	struct kgenome_cfg_sign s, ref;
	uint32_t i, N;
	uint64_t b, first_ok = 0;

	shaped(&g, 6, 12);
	memset(&ids, 0, sizeof ids);
	ids.n = 12;
	for (i = 0; i < 12; i++) { ids.id[i] = 40u + i % 5u; ids.kind[i] = KGENOME_CFG_CK_IMPORT; }
	in = build_with(&g, &ids, &cg);
	CK(sign_pol(&cg, KGENOME_CFG_P_BOTH, &ref) == KGENOME_OK);
	for (b = 1; b < 6000; b++) {
		struct kgenome_budget bud;
		struct kgenome_cfg_sign_req rq;
		struct counting c = { 0 };

		memset(&bud, 0, sizeof bud);
		bud.max_bytes = b;
		memset(&rq, 0, sizeof rq);
		rq.g = &cg; rq.policy = KGENOME_CFG_P_BOTH; rq.budget = &bud; rq.mem = (struct kgenome_cfg_mem)COUNTING_MEM(&c);
		if (kgenome_cfg_sign(&rq, &s) == KGENOME_OK) {
			if (!first_ok) first_ok = b;
			CK(sign_eq(&s, &ref) && s.ccanon == ref.ccanon);
		} else {
			CKM(!first_ok && s.n_key == 0 && s.n_ckey == 0 && s.canon == 0, "budget %llu", (unsigned long long)b);
		}
		CKM(c.n_alloc == c.n_free, "budget %llu: leak", (unsigned long long)b);
	}
	CK(first_ok != 0);
	for (N = 1; N <= 3; N++) {
		struct kgenome_cfg_sign_req rq;
		struct counting c = { 0 };
		enum kgenome_status st;

		c.fail_at = N;
		memset(&rq, 0, sizeof rq);
		rq.g = &cg; rq.policy = KGENOME_CFG_P_BOTH; rq.mem = (struct kgenome_cfg_mem)COUNTING_MEM(&c);
		st = kgenome_cfg_sign(&rq, &s);
		CKM(N == 1 ? st == KGENOME_NOMEM && s.n_key == 0 : st == KGENOME_OK, "N=%u: status %d", N, (int)st);
		CK(c.live == 0);
	}
	/* the graph's own allocations: the calls table is the third, and refusing it frees the first two */
	{
		struct prog p;
		struct blob x;
		struct kgenome_cell_insn *in2 = NULL;
		uint32_t n;

		gspec_prog(&g, &p, NULL);
		CK(blob_make(&ISAS[0], &p, 0x1000, &x));
		n = blob_decode(&ISAS[0], &x, &in2);
		for (N = 1; N <= 4; N++) {
			struct kgenome_cfg_req rq;
			struct kgenome_cfg g2;
			struct counting c = { 0 };

			c.fail_at = N;
			memset(&rq, 0, sizeof rq);
			rq.in = in2; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len; rq.mem = (struct kgenome_cfg_mem)COUNTING_MEM(&c);
			{
				const enum kgenome_status st = kgenome_cfg_build(&rq, &g2);

				CKM(N <= 3 ? st == KGENOME_NOMEM && g2.b == NULL && g2.call == NULL : st == KGENOME_OK, "build N=%u: status %d", N, (int)st);
				kgenome_cfg_free(&g2, &rq.mem);
				CKM(c.live == 0, "build N=%u: %lld bytes live", N, (long long)c.live);
			}
		}
		free(in2); blob_free(&x); prog_free(&p);
	}
	kgenome_cfg_free(&cg, NULL);
	free(in);
}

int main(void)
{
	facts();
	default_is_struct_only();
	separate_scores();
	unresolved();
	multiset_counts();
	reachable_only();
	anchor();
	resources();
	if (fails)
		printf("cfg_callee: %d FAILED\n", fails);
	else
		printf("cfg_callee: ok\n");
	return fails != 0;
}
