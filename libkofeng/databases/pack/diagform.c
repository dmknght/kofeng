/*
 * pack/diagform.c - the detection form of a diagnose: its values, its checks and its wire. See diagform.h.
 */

#include "diagform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <celllysis/mutation_window.h>   /* KGENOME_MUTATION_* */
#include <kofmod/kofdiagtree.h>          /* KDIG_SEC_FORM */
#include "dbcore.h"                      /* KOF_STR_* */
#include "hexprog.h"
#include <celllysis/mutation.h>

struct kof_form *kof_form_new(void)
{
	return calloc(1, sizeof(struct kof_form));
}

void kof_form_free(struct kof_form *f)
{
	if (!f)
		return;
	free(f->pool);
	free(f->hash);
	free(f);
}

/* Grow a byte array to hold `need` bytes in total. Doubling, bounded by the stream's own limit: the form is the record
 * and the record is bounded, so this is the cost of a hostile record and no more. */
static int grow(void **p, uint32_t *cap, uint32_t need, size_t unit)
{
	void *g;
	uint32_t nc;

	if (need <= *cap)
		return 1;
	nc = *cap ? *cap : 256u;
	while (nc < need)
		nc *= 2u;
	g = realloc(*p, (size_t)nc * unit);
	if (!g)
		return 0;
	*p = g;
	*cap = nc;
	return 1;
}

int kof_form_add_str(struct kof_form *f, uint8_t kind, uint8_t flags, const uint8_t *p, uint32_t n)
{
	struct kof_form_str *s;
	uint32_t at;

	if (!f || !p || !n || f->n_str >= KOF_FORM_MAX_STR)
		return -1;
	if (kind == KOF_STR_LITERAL ? n > KOF_STR_MAX_LEN
	    : kind == KOF_STR_HEX ? n > KOF_HEX_MAX_PROG : 1)
		return -1;
	at = kind == KOF_STR_HEX
	   ? (f->pool_n + (KOF_HEX_PROG_ALIGN - 1u)) / KOF_HEX_PROG_ALIGN * KOF_HEX_PROG_ALIGN
	   : f->pool_n;
	if (at + n > KOF_FORM_MAX_WIRE || !grow((void **)&f->pool, &f->pool_cap, at + n, 1u))
		return -1;
	/* The gap an aligned program leaves is zero, not whatever the allocator held. */
	if (at > f->pool_n)
		memset(f->pool + f->pool_n, 0, at - f->pool_n);
	memcpy(f->pool + at, p, n);
	f->pool_n = at + n;
	s = &f->str[f->n_str];
	s->off = at;
	s->len = (uint16_t)n;
	s->kind = kind;
	s->flags = flags;
	return f->n_str++;
}

int kof_form_add_block(struct kof_form *f, uint32_t mask, uint8_t side, const uint32_t *h, uint32_t n)
{
	struct kof_form_block *b;

	if (!f || !h || !n || n > KOF_FORM_HASH_MAX || f->n_block >= KOF_FORM_MAX_BLOCK)
		return -1;
	/* 32 blocks of 128 hashes are 4096 values: the bound on the table is the bounds on its parts, nothing more to ask. */
	if (!grow((void **)&f->hash, &f->hash_cap, f->n_hash + n, sizeof *f->hash))
		return -1;
	memcpy(f->hash + f->n_hash, h, (size_t)n * sizeof *h);
	b = &f->block[f->n_block];
	b->mask = mask;
	b->side = side;
	b->n_hash = (uint16_t)n;
	b->first = f->n_hash;
	f->n_hash += n;
	return f->n_block++;
}

/* ---- the checks ------------------------------------------------------------ */

const char *kof_form_check(const struct kof_form *f)
{
	uint32_t i, k;
	uint8_t used[KOF_FORM_MAX_NODE];

	if (!f)
		return "no form";
	if (f->n_str > KOF_FORM_MAX_STR || f->n_match > KOF_FORM_MAX_MATCH ||
	    f->n_block > KOF_FORM_MAX_BLOCK || f->n_node > KOF_FORM_MAX_NODE)
		return "a table of the form is over its bound";
	if (!f->n_node)
		return "a form with no expression";
	for (i = 0; i < f->n_str; i++) {
		const struct kof_form_str *s = &f->str[i];

		if (!s->len || (uint64_t)s->off + s->len > f->pool_n)
			return "a marker lies outside the pool";
		if (s->flags & ~(KOF_STR_ICASE | KOF_STR_FULLWORD | KOF_STR_WIDE | KOF_STR_TOKEN))
			return "a marker has a flag this build does not know";
		if ((s->flags & KOF_STR_FULLWORD) && (s->flags & KOF_STR_TOKEN))
			return "a marker is both a whole word and a whole token";
		if (s->kind == KOF_STR_LITERAL) {
			if (s->len > KOF_STR_MAX_LEN)
				return "a literal is over the bound";
		} else if (s->kind == KOF_STR_HEX) {
			if (s->len > KOF_HEX_MAX_PROG)
				return "a hex program is over the bound";
			if (s->off % KOF_HEX_PROG_ALIGN)
				return "a hex program is misaligned";
			if (!kof_hex_prog_valid(f->pool + s->off, s->len))
				return "a hex program is malformed";
		} else {
			return "a marker has a kind this build does not know";
		}
	}
	for (i = 0; i < f->n_block; i++) {
		const struct kof_form_block *b = &f->block[i];

		if (b->n_hash < kgenome_mutation_block_min(b->mask) || b->n_hash > KOF_FORM_HASH_MAX)
			return "a block has too few or too many hashes";
		if ((uint64_t)b->first + b->n_hash > f->n_hash)
			return "a block's hashes lie outside the pool";
		if (b->side > (uint8_t)KGENOME_MUTATION_SIDE_LIB)
			return "a block names a side this build does not know";
		if (!b->mask)
			return "a block names no region";
	}
	for (i = 0; i < f->n_match; i++) {
		const struct kof_form_match *m = &f->match[i];

		if (!m->n || m->n > KOF_FORM_MAX_ARG)
			return "a matcher lists no name or too many";
		if (m->kind == KOF_FORM_M_FIND) {
			if (m->rule > (uint8_t)KOF_FORM_R_AT)
				return "a matcher has a rule this build does not know";
			for (k = 0; k < m->n; k++)
				if (m->arg[k] >= f->n_str)
					return "a matcher names a marker the form does not have";
			if (m->rule == KOF_FORM_R_AT) {
				if (m->n != 1u || m->anchor > KOF_FORM_ANCHOR_EOF || m->mask || m->thresh)
					return "an AT matcher is one marker, an anchor and a step";
			} else {
				if (!m->mask || m->anchor || m->at)
					return "a searching matcher names a region and no offset";
				if (m->rule == KOF_FORM_R_MULTI ? (!m->thresh || m->thresh > m->n) : m->thresh != 0)
					return "a threshold the matcher cannot reach";
			}
		} else if (m->kind == KOF_FORM_M_SIM) {
			for (k = 0; k < m->n; k++)
				if (m->arg[k] >= f->n_block)
					return "a matcher names a block the form does not have";
			if (!m->thresh || m->thresh > 100u || m->rule || m->anchor || m->mask || m->at)
				return "a similarity matcher is a percentage of 1 to 100";
		} else {
			return "a matcher has a kind this build does not know";
		}
	}
	/* One stage answers a form: the strings are searched when the object is detected, the blocks are scored where
	 * the similarity stage looks, and which object that is can differ (a block is cut from the normalised view). */
	{
		uint32_t n_sim = 0;

		for (i = 0; i < f->n_match; i++)
			n_sim += f->match[i].kind == KOF_FORM_M_SIM;
		if (n_sim != f->n_sim)
			return "the count of similarity matchers is not the form's";
		if (n_sim && n_sim != f->n_match)
			return "a form mixes string matchers and similarity matchers";
	}
	/* The expression is a TREE: children before the parent, the root last, every other node used exactly once, so
	 * its evaluation is linear in its size however a hostile record spells it. */
	memset(used, 0, sizeof used);
	for (i = 0; i < f->n_node; i++) {
		const struct kof_form_node *n = &f->node[i];

		switch (n->op) {
		case KOF_FORM_OP_LEAF:
			if (n->a >= f->n_match || n->b)
				return "an expression leaf names no matcher";
			break;
		case KOF_FORM_OP_NOT:
			if (n->a >= i || n->b || used[n->a]++)
				return "an expression is not a tree";
			break;
		case KOF_FORM_OP_AND:
		case KOF_FORM_OP_OR:
			if (n->a >= i || n->b >= i || used[n->a]++ || used[n->b]++)
				return "an expression is not a tree";
			break;
		default:
			return "an expression has an operator this build does not know";
		}
	}
	for (i = 0; i + 1u < f->n_node; i++)
		if (!used[i])
			return "an expression has a part nothing uses";
	return NULL;
}

/* ---- the wire --------------------------------------------------------------- */

static void put16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
	put16(p, v);
	put16(p + 2, v >> 16);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t get16(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t get32(const uint8_t *p)
{
	return get16(p) | (get16(p + 2) << 16);
}

static uint64_t get64(const uint8_t *p)
{
	return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

/* One walk for the size and the write: `out` NULL counts. Returns the stream's length. */
static size_t wire_walk(const struct kof_form *f, uint8_t *out)
{
	size_t at = 0;
	uint32_t i, k;

#define ITEM(tag, blen)                                   \
	do {                                              \
		if (out) {                                \
			out[at] = (uint8_t)(tag);         \
			put16(out + at + 1, (blen));      \
		}                                         \
		at += 3u;                                 \
	} while (0)
	for (i = 0; i < f->n_str; i++) {
		const struct kof_form_str *s = &f->str[i];

		ITEM(KOF_FORM_I_STR, 2u + s->len);
		if (out) {
			out[at] = s->kind;
			out[at + 1u] = s->flags;
			memcpy(out + at + 2u, f->pool + s->off, s->len);
		}
		at += 2u + s->len;
	}
	for (i = 0; i < f->n_block; i++) {
		const struct kof_form_block *b = &f->block[i];

		ITEM(KOF_FORM_I_BLOCK, 8u + 4u * (uint32_t)b->n_hash);
		if (out) {
			put32(out + at, b->mask);
			out[at + 4u] = 0;           /* reserved: was the normalizer */
			out[at + 5u] = b->side;
			put16(out + at + 6u, b->n_hash);
			for (k = 0; k < b->n_hash; k++)
				put32(out + at + 8u + 4u * k, f->hash[b->first + k]);
		}
		at += 8u + 4u * (size_t)b->n_hash;
	}
	for (i = 0; i < f->n_match; i++) {
		const struct kof_form_match *m = &f->match[i];

		if (m->kind == KOF_FORM_M_FIND) {
			ITEM(KOF_FORM_I_FIND, 16u + m->n);
			if (out) {
				out[at] = m->rule;
				out[at + 1u] = m->thresh;
				out[at + 2u] = m->anchor;
				out[at + 3u] = m->n;
				put32(out + at + 4u, m->mask);
				put64(out + at + 8u, (uint64_t)m->at);
				memcpy(out + at + 16u, m->arg, m->n);
			}
			at += 16u + m->n;
		} else {
			ITEM(KOF_FORM_I_SIM, 2u + m->n);
			if (out) {
				out[at] = m->thresh;
				out[at + 1u] = m->n;
				memcpy(out + at + 2u, m->arg, m->n);
			}
			at += 2u + m->n;
		}
	}
	ITEM(KOF_FORM_I_EXPR, 1u + 3u * (uint32_t)f->n_node);
	if (out) {
		out[at] = (uint8_t)f->n_node;
		for (i = 0; i < f->n_node; i++) {
			out[at + 1u + 3u * i] = f->node[i].op;
			out[at + 2u + 3u * i] = f->node[i].a;
			out[at + 3u + 3u * i] = f->node[i].b;
		}
	}
	at += 1u + 3u * (size_t)f->n_node;
#undef ITEM
	return at;
}

size_t kof_form_wire_size(const struct kof_form *f)
{
	size_t n;

	if (!f || kof_form_check(f))
		return 0;
	n = wire_walk(f, NULL);
	return n <= KOF_FORM_MAX_WIRE ? n : 0u;
}

size_t kof_form_wire_write(const struct kof_form *f, uint8_t *out)
{
	size_t n = kof_form_wire_size(f);

	if (!n || !out)
		return 0;
	return wire_walk(f, out);
}

size_t kof_form_section_size(size_t n)
{
	return n + 2u * ((n + 254u) / 255u);
}

size_t kof_form_section_write(const uint8_t *wire, size_t n, uint8_t *out)
{
	size_t at = 0, o = 0;

	while (at < n) {
		size_t c = n - at < 255u ? n - at : 255u;

		out[o++] = (uint8_t)KDIG_SEC_FORM;
		out[o++] = (uint8_t)c;
		memcpy(out + o, wire + at, c);
		o += c;
		at += c;
	}
	return o;
}

struct kof_form *kof_form_decode(const uint8_t *p, size_t n, const char **why)
{
	struct kof_form *f;
	size_t at = 0;
	const char *w = "the stream does not add up";

	if (!p || !n || n > KOF_FORM_MAX_WIRE) {
		if (why)
			*why = "the stream is empty or over its bound";
		return NULL;
	}
	f = kof_form_new();
	if (!f) {
		if (why)
			*why = "out of memory";
		return NULL;
	}
	while (at < n) {
		uint32_t tag, len;
		const uint8_t *b;

		if (n - at < 3u)
			goto bad;
		tag = p[at];
		len = get16(p + at + 1u);
		at += 3u;
		if (len > n - at)
			goto bad;
		b = p + at;
		at += len;
		switch (tag) {
		case KOF_FORM_I_STR:
			if (len < 3u || kof_form_add_str(f, b[0], b[1], b + 2, len - 2u) < 0)
				goto bad;
			break;
		case KOF_FORM_I_BLOCK: {
			uint32_t nh, k, h[KOF_FORM_HASH_MAX];

			if (len < 8u)
				goto bad;
			nh = get16(b + 6);
			if (nh > KOF_FORM_HASH_MAX || len != 8u + 4u * nh || b[4])
				goto bad;           /* the reserved byte is 0: an old stream that names XOR or SUB is refused whole */
			for (k = 0; k < nh; k++)
				h[k] = get32(b + 8u + 4u * k);
			if (kof_form_add_block(f, get32(b), b[5], h, nh) < 0)
				goto bad;
			break;
		}
		case KOF_FORM_I_FIND: {
			struct kof_form_match *m;

			if (len < 17u || f->n_match >= KOF_FORM_MAX_MATCH || b[3] > KOF_FORM_MAX_ARG ||
			    len != 16u + b[3])
				goto bad;
			m = &f->match[f->n_match++];
			memset(m, 0, sizeof *m);
			m->kind = KOF_FORM_M_FIND;
			m->rule = b[0];
			m->thresh = b[1];
			m->anchor = b[2];
			m->n = b[3];
			m->mask = get32(b + 4);
			m->at = (int64_t)get64(b + 8);
			memcpy(m->arg, b + 16, m->n);
			break;
		}
		case KOF_FORM_I_SIM: {
			struct kof_form_match *m;

			if (len < 3u || f->n_match >= KOF_FORM_MAX_MATCH || b[1] > KOF_FORM_MAX_ARG ||
			    len != 2u + b[1])
				goto bad;
			m = &f->match[f->n_match++];
			memset(m, 0, sizeof *m);
			m->kind = KOF_FORM_M_SIM;
			m->thresh = b[0];
			m->n = b[1];
			memcpy(m->arg, b + 2, m->n);
			f->n_sim++;
			break;
		}
		case KOF_FORM_I_EXPR: {
			uint32_t k, nn;

			if (f->n_node || len < 1u)
				goto bad;
			nn = b[0];
			if (nn > KOF_FORM_MAX_NODE || len != 1u + 3u * nn)
				goto bad;
			for (k = 0; k < nn; k++) {
				f->node[k].op = b[1u + 3u * k];
				f->node[k].a = b[2u + 3u * k];
				f->node[k].b = b[3u + 3u * k];
			}
			f->n_node = (uint16_t)nn;
			break;
		}
		default:
			/* A tag a later build adds is skipped by its length, like a section of the record. */
			break;
		}
	}
	w = kof_form_check(f);
	if (w)
		goto bad;
	if (why)
		*why = NULL;
	return f;
bad:
	if (why)
		*why = w;
	kof_form_free(f);
	return NULL;
}

/* ---- spelling -------------------------------------------------------------- */

struct spell {
	char  *out;
	size_t cap, n;
};

static void sp_put(struct spell *s, const char *t)
{
	size_t L = strlen(t);

	if (s->n + 1u < s->cap) {
		size_t room = s->cap - s->n - 1u;

		memcpy(s->out + s->n, t, L < room ? L : room);
		s->out[s->n + (L < room ? L : room)] = 0;
	}
	s->n += L;
}

/* The precedence a node binds with: or 1, and 2, not and a leaf 3. */
static int sp_prec(const struct kof_form_node *n)
{
	return n->op == KOF_FORM_OP_OR ? 1 : n->op == KOF_FORM_OP_AND ? 2 : 3;
}

static void sp_node(const struct kof_form *f, struct spell *s, uint32_t i, int outer)
{
	const struct kof_form_node *n = &f->node[i];
	int prec = sp_prec(n);
	char num[16];

	if (prec < outer)
		sp_put(s, "(");
	if (n->op == KOF_FORM_OP_LEAF) {
		snprintf(num, sizeof num, "%u", (unsigned)n->a);
		sp_put(s, num);
	} else if (n->op == KOF_FORM_OP_NOT) {
		sp_put(s, "!");
		sp_node(f, s, n->a, 3);
	} else {
		sp_node(f, s, n->a, prec);
		sp_put(s, n->op == KOF_FORM_OP_AND ? " & " : " | ");
		sp_node(f, s, n->b, prec + 1);
	}
	if (prec < outer)
		sp_put(s, ")");
}

size_t kof_form_expr_text(const struct kof_form *f, char *out, size_t cap)
{
	struct spell s;

	if (!out || !cap)
		return 0;
	out[0] = 0;
	s.out = out;
	s.cap = cap;
	s.n = 0;
	if (f && f->n_node && !kof_form_check(f))
		sp_node(f, &s, (uint32_t)f->n_node - 1u, 0);
	return s.n;
}
