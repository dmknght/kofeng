/*
 * fnprint_token.c - the normal form of an instruction, and the exact compare.
 *
 * WHAT IS KEPT AND WHAT IS NOT, because the fingerprint is only as good as this
 * table. Position independence is the point: moving the function, relinking the
 * object, changing an absolute address or the library it calls into must not
 * change it; changing what it does must.
 *
 *   kept       the opcode class, the condition, the operand shapes (kind, size,
 *              read/write), registers, a memory operand's base/index/scale/segment,
 *              a displacement under 64 KiB (stack slots, structure fields), an
 *              immediate that fits 16 bits as a signed value (sizes, flags,
 *              errno values, small constants), a branch that stays inside the
 *              function as the offset it lands at.
 *   a class    a RIP-relative or absolute operand (the address drops out), a
 *              displacement or immediate that is large (an address, an IP, a hash
 *              constant: class only), a call or jump that leaves the function
 *              (class, plus the caller's tag when its hook names the target).
 *   dropped    NOP (alignment inside and after a body), int3, and a trailing run
 *              of bytes that do not decode (padding).
 *
 * The weak token is the opcode class and condition only: a different register
 * allocation or a changed constant leaves it alone.
 */
#include "fnprint_private.h"

#include <stdlib.h>
#include <string.h>

#define CLS_RIP  (1ull << 60)
#define CLS_ABS  (2ull << 60)
#define CLS_BIGD (3ull << 60)
#define CLS_BIGI (4ull << 60)
#define CLS_LOCAL (5ull << 60)
#define CLS_OUT  (6ull << 60)
#define CLS_IMM  (7ull << 60)
#define CLS_DISP (8ull << 60)
#define CLS_BAD  (9ull << 60)

/* The condition field is meaningful for these only; elsewhere the decoder leaves other data in it. */
static uint32_t cond_of(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_JCC || in->op == KGENOME_CELL_CMOV ||
	       in->op == KGENOME_CELL_SETCC ? in->cond : 0u;
}

static int is_pad(const struct kgenome_cell_insn *in)
{
	if (in->op == KGENOME_CELL_NOP)
		return 1;
	/* int3 carries no operand in the decoder's form; `int 3` spelled with one is the same */
	return in->op == KGENOME_CELL_INT &&
	       (in->n_op == 0 || (in->o[0].kind == KGENOME_CELL_O_IMM && in->o[0].imm == 3));
}

static uint64_t imm_class(const struct kgenome_cell_operand *o)
{
	int64_t v = (int64_t)o->imm;

	if (o->size == 1) v = (int8_t)o->imm;
	else if (o->size == 2) v = (int16_t)o->imm;
	else if (o->size == 4) v = (int32_t)o->imm;
	if (v >= -0x10000 && v <= 0xffff)
		return CLS_IMM | ((uint64_t)v & 0xffffffffffffull);
	return CLS_BIGI | o->size;
}

static uint64_t mem_class(const struct kgenome_cell_operand *o)
{
	if (o->flags & KGENOME_CELL_OF_RIPREL)
		return CLS_RIP;
	if (o->reg == KGENOME_CELL_REG_NONE && o->index == KGENOME_CELL_REG_NONE)
		return CLS_ABS;
	if (o->disp >= -0x10000 && o->disp < 0x10000)
		return CLS_DISP | ((uint64_t)o->disp & 0xffffffffffffull);
	return CLS_BIGD;
}

static void operand(const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *o,
		    uint64_t rel_at, uint64_t flen, uint64_t ext, struct kgenome_fnprint_tok *t)
{
	uint64_t shape = (uint64_t)o->kind | ((uint64_t)o->size << 4) |
			 ((uint64_t)(o->flags & (KGENOME_CELL_OF_WRITE | KGENOME_CELL_OF_READ |
						 KGENOME_CELL_OF_HIGH8)) << 12);

	switch (o->kind) {
	case KGENOME_CELL_O_REG:
		t->s[t->ns++] = shape | ((uint64_t)o->reg << 24);
		break;
	case KGENOME_CELL_O_MEM:
		t->s[t->ns++] = shape | ((uint64_t)o->reg << 24) | ((uint64_t)o->index << 32) |
				((uint64_t)o->scale << 40) | ((uint64_t)o->seg << 48);
		t->s[t->ns++] = mem_class(o);
		break;
	case KGENOME_CELL_O_IMM:
		t->s[t->ns++] = shape;
		t->s[t->ns++] = imm_class(o);
		break;
	case KGENOME_CELL_O_REL: {
		int64_t at = (int64_t)rel_at + (int64_t)(in->target_va - in->at_va);

		t->s[t->ns++] = shape;
		if (in->target_va != KGENOME_BROKEN && at >= 0 && (uint64_t)at < flen)
			t->s[t->ns++] = CLS_LOCAL;      /* where it lands is folded in at the end (fnprint_pos_*) */
		else
			t->s[t->ns++] = CLS_OUT | (ext & 0xffffffffffffull);
		break;
	}
	default:
		t->s[t->ns++] = shape;
	}
}

/*
 * ENDBR64 / ENDBR32 (f3 0f 1e fa / fb): the landing pad -fcf-protection puts at the start of every
 * function and at every indirect-branch target. It is a NOP to a CPU without CET and carries no
 * operation, so it is padding for the fingerprint: the same source built with and without
 * -fcf-protection (a distribution default on some systems and not on others) is the same function.
 */
int kgenome_fnprint_is_landing_pad(const uint8_t *p, uint32_t n)
{
	return n >= 4 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && (p[3] == 0xfa || p[3] == 0xfb);
}

void kgenome_fnprint_tokens(const struct kgenome_cell_insn *in, uint64_t rel_at, uint64_t flen,
		uint64_t ext, struct kgenome_fnprint_tok *t)
{
	uint32_t j;

	t->ns = 0;
	t->w = 0;
	if (is_pad(in))
		return;
	t->s[t->ns++] = (uint64_t)in->op | ((uint64_t)cond_of(in) << 8) |
			((uint64_t)in->flags << 16) | ((uint64_t)in->n_op << 24) | (1ull << 32);
	for (j = 0; j < in->n_op && j < 3u && t->ns + 2u <= KGENOME_FNPRINT_TOK_MAX; j++)
		operand(in, &in->o[j], rel_at, flen, ext, t);
	t->w = ((uint64_t)in->op | ((uint64_t)cond_of(in) << 8)) + 1u;
}

static uint64_t mix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	h *= 0xff51afd7ed558ccdull;
	return h ^ (h >> 33);
}

int kgenome_fnprint_local_target(const struct kgenome_cell_insn *in, uint64_t rel_at, uint64_t flen, uint64_t *to)
{
	int64_t at;

	if (in->n_op < 1 || in->o[0].kind != KGENOME_CELL_O_REL || in->target_va == KGENOME_BROKEN)
		return 0;
	at = (int64_t)rel_at + (int64_t)(in->target_va - in->at_va);
	if (at < 0 || (uint64_t)at >= flen)
		return 0;
	*to = (uint64_t)at;
	return 1;
}

/* ---- positions: a branch target counted without the padding before it ------- */

void kgenome_fnprint_pos_reset(struct kgenome_fnprint_pos *s)
{
	s->n_pad = 0;
	s->n_tgt = 0;
}

void kgenome_fnprint_pos_free(struct kgenome_fnprint_pos *s, struct kgenome_ledger *led)
{
	if (led)
		kgenome_ledger_release(led, s->charged);
	free(s->pad_at);
	free(s->pad_cum);
	free(s->tgt);
	memset(s, 0, sizeof *s);
}

static int grow(uint32_t **a, uint32_t **b, uint32_t *cap, uint32_t n, struct kgenome_ledger *led, struct kgenome_fnprint_pos *s)
{
	uint32_t ncap;
	uint64_t add;
	uint32_t *na, *nb = NULL;

	if (n < *cap)
		return 1;
	ncap = *cap ? *cap * 2u : 64u;
	add = (uint64_t)(ncap - *cap) * sizeof **a * (b ? 2u : 1u);
	if (ncap < *cap || (led && !kgenome_ledger_charge(led, add)))
		return 0;
	na = realloc(*a, (size_t)ncap * sizeof **a);
	if (na)
		*a = na;
	if (na && b) {
		nb = realloc(*b, (size_t)ncap * sizeof **b);
		if (nb)
			*b = nb;
	}
	if (!na || (b && !nb)) {
		if (led)
			kgenome_ledger_release(led, add);
		return 0;
	}
	*cap = ncap;
	s->charged += add;
	return 1;
}

void kgenome_fnprint_pos_pad(struct kgenome_fnprint_pos *s, struct kgenome_ledger *led, uint64_t at, uint32_t len)
{
	uint32_t prev = s->n_pad ? s->pad_cum[s->n_pad - 1] : 0;

	if (s->failed || at > UINT32_MAX)
		return;
	if (!grow(&s->pad_at, &s->pad_cum, &s->cap_pad, s->n_pad, led, s)) {
		s->failed = 1;
		return;
	}
	s->pad_at[s->n_pad] = (uint32_t)at;
	s->pad_cum[s->n_pad] = prev + len;
	s->n_pad++;
}

void kgenome_fnprint_pos_target(struct kgenome_fnprint_pos *s, struct kgenome_ledger *led, uint64_t tgt)
{
	if (s->failed || tgt > UINT32_MAX)
		return;
	if (!grow(&s->tgt, NULL, &s->cap_tgt, s->n_tgt, led, s)) {
		s->failed = 1;
		return;
	}
	s->tgt[s->n_tgt++] = (uint32_t)tgt;
}

uint64_t kgenome_fnprint_pos_adj(const struct kgenome_fnprint_pos *s, uint32_t i)
{
	uint32_t lo = 0, hi = s->n_pad, t = s->tgt[i];

	while (lo < hi) {                       /* padding that starts before the target */
		uint32_t m = lo + (hi - lo) / 2u;

		if (s->pad_at[m] < t)
			lo = m + 1u;
		else
			hi = m;
	}
	return t - (lo ? s->pad_cum[lo - 1] : 0u);
}

uint64_t kgenome_fnprint_pos_fold(const struct kgenome_fnprint_pos *s, uint64_t fp)
{
	uint32_t i;

	if (!s)
		return fp;
	for (i = 0; i < s->n_tgt; i++)
		fp = mix(fp, CLS_LOCAL | (s->failed ? s->tgt[i] : kgenome_fnprint_pos_adj(s, i)));
	return fp;
}

void kgenome_fnprint_acc_init(struct kgenome_fnprint_acc *a)
{
	memset(a, 0, sizeof *a);
	a->fp = 0xcbf29ce484222325ull;
	a->fw = 0x84222325cbf29ce4ull;
}

void kgenome_fnprint_acc_bad(struct kgenome_fnprint_acc *a)
{
	a->pend_bad++;
	a->n_bad++;
}

void kgenome_fnprint_acc_good(struct kgenome_fnprint_acc *a, const struct kgenome_cell_insn *in, const struct kgenome_fnprint_tok *t)
{
	uint32_t i;

	if (in->op == KGENOME_CELL_SYSCALL ||
	    (in->op == KGENOME_CELL_INT && in->n_op >= 1 && in->o[0].kind == KGENOME_CELL_O_IMM &&
	     in->o[0].imm == 0x80))
		a->n_syscall++;
	if (!t->ns)
		return;                 /* padding: not part of the function */
	if (a->pend_bad) {
		a->fp = mix(a->fp, CLS_BAD | a->pend_bad);
		a->fw = mix(a->fw, CLS_BAD | a->pend_bad);
		a->pend_bad = 0;
	}
	for (i = 0; i < t->ns; i++)
		a->fp = mix(a->fp, t->s[i]);
	a->fw = mix(a->fw, t->w);
	a->n_insn++;
	if (in->op == KGENOME_CELL_CALL)
		a->n_call++;
	if (in->op == KGENOME_CELL_JMP || in->op == KGENOME_CELL_JCC || in->op == KGENOME_CELL_LOOP)
		a->n_branch++;
	if (in->flags & KGENOME_CELL_F_INDIRECT)
		a->has_ind = 1;
	a->last_op = in->op;
}

/* ---- the exact compare ---------------------------------------------------- */

struct cmp_side {
	const struct kgenome_fnprint_req *rq;
	const struct kgenome_fnprint_fn *f;
	uint64_t at;
	struct kgenome_fnprint_pos pos;
};

static int next_good(struct cmp_side *s, struct kgenome_fnprint_tok *t, struct kgenome_cell_insn *in, uint32_t *bad)
{
	*bad = 0;
	while (s->at < s->f->len) {
		uint64_t va = s->f->off + s->at;
		uint32_t n = kgenome_cell_decode(s->rq->arch, s->rq->be, s->rq->p + s->f->off + s->at,
						 (uint32_t)(s->f->len - s->at > 16 ? 16 : s->f->len - s->at),
						 va, in);

		if (!n) {
			(*bad)++;
			s->at++;
			continue;
		}
		kgenome_fnprint_tokens(in, s->at, s->f->len, 0, t);
		if (n == 4 && kgenome_fnprint_is_landing_pad(s->rq->p + s->f->off + s->at, n)) {
			t->ns = 0;
			t->w = 0;
		}
		if (!t->ns) {
			kgenome_fnprint_pos_pad(&s->pos, NULL, s->at, n);
		} else {
			uint64_t to;

			if (kgenome_fnprint_local_target(in, s->at, s->f->len, &to))
				kgenome_fnprint_pos_target(&s->pos, NULL, to);
		}
		s->at += n;
		if (t->ns)
			return 1;
	}
	return 0;
}

/* The targets of the two functions, counted without padding, are the same list. */
static int same_targets(const struct kgenome_fnprint_pos *x, const struct kgenome_fnprint_pos *y)
{
	uint32_t i;

	if (x->n_tgt != y->n_tgt || x->failed || y->failed)
		return x->n_tgt == y->n_tgt && x->failed == y->failed &&
		       (x->n_tgt == 0 || !memcmp(x->tgt, y->tgt, x->n_tgt * sizeof *x->tgt));
	for (i = 0; i < x->n_tgt; i++)
		if (kgenome_fnprint_pos_adj(x, i) != kgenome_fnprint_pos_adj(y, i))
			return 0;
	return 1;
}

int kgenome_fnprint_equal(const struct kgenome_fnprint_req *a, const struct kgenome_fnprint_fn *fa,
			  const struct kgenome_fnprint_req *b, const struct kgenome_fnprint_fn *fb)
{
	struct cmp_side sa, sb;
	int eq = 1;

	if (!a || !b || !fa || !fb || !a->p || !b->p || fa->off > a->n || fa->len > a->n - fa->off ||
	    fb->off > b->n || fb->len > b->n - fb->off)
		return 0;
	memset(&sa, 0, sizeof sa);
	memset(&sb, 0, sizeof sb);
	sa.rq = a; sa.f = fa;
	sb.rq = b; sb.f = fb;
	for (;;) {
		struct kgenome_fnprint_tok ta, tb;
		struct kgenome_cell_insn ia, ib;
		uint32_t ba, bb;
		int ga = next_good(&sa, &ta, &ia, &ba), gb = next_good(&sb, &tb, &ib, &bb);

		if (ga != gb) {
			eq = 0;
			break;
		}
		if (!ga)
			break;
		if (ba != bb || ta.ns != tb.ns || ta.w != tb.w ||
		    memcmp(ta.s, tb.s, ta.ns * sizeof ta.s[0])) {
			eq = 0;
			break;
		}
	}
	if (eq)
		eq = same_targets(&sa.pos, &sb.pos);
	kgenome_fnprint_pos_free(&sa.pos, NULL);
	kgenome_fnprint_pos_free(&sb.pos, NULL);
	return eq;
}
