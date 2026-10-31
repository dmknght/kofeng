/*
 * diag_form_wire - the detection form of a diagnose (pack/diagform.h): its values, its checks and its wire.
 *
 * WHAT IS PINNED, and why the old tests could not have caught any of it (a): none of this existed - the record had no such
 * section, the loader had no reader for one, so every assertion here fails on the old tree for want of the header; they are
 * RED by construction and the per-line reasons are below.
 *
 *   ROUND TRIP     a form built from arbitrary strings, blocks, matchers and expression trees encodes, decodes and
 *                  encodes to the same bytes (3000 forms from a seed), and a random form checks clean to begin with.
 *   TRUNCATION     EVERY strict prefix of a stream is refused (the expression is the last item, so a cut stream is a form
 *                  without one): exhaustive over the prefixes of 300 streams.
 *   MUTATION       EVERY byte of three small streams set to EVERY value: the decoder answers NULL or a form that
 *                  passes kof_form_check, never a crash, and what it accepts re-encodes and decodes to itself.
 *   SECTIONS       every length 0..1200 cut into KDIG_SEC_FORM sections of at most 255 bytes and put back together.
 *   BOUNDS         each cap at the value and one past it: 64 strings, 512 byte literal, 8192 byte program, 32 blocks, 128
 *                  hashes, 16 names, 128 nodes, 65536 bytes of stream - a hard refusal, never a cut.
 *   TREE           an expression node used twice (the exponential shape), a part nothing uses, a forward reference, a leaf
 *                  naming no matcher, an operator this build does not know: all refused, so evaluation is linear.
 *   STAGES         a form with string matchers and similarity matchers together is refused (one stage answers a form).
 *   FORWARD        a tag a later build adds is skipped by its length.
 *   SPELLING       the expression text (what kdb_diagnose_form_expr returns) is the tree's own precedence.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/databases/pack/diagform.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include <kofmod/kofdiagtree.h>

static int failures;

struct kof_form;
static void leaf(struct kof_form *f, uint8_t m);
static void join(struct kof_form *f, uint8_t op, uint8_t a, uint8_t b);

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static uint32_t rng_state = 0x9e3779b9u;

static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

/* A few compiled hex programs, the real ones: the checks read them with kof_hex_prog_valid. */
static uint8_t prog[4][KOF_HEX_MAX_PROG];
static uint32_t prog_n[4];

static void make_programs(void)
{
	static const char *const t[4] = { "E8 ?? ?? ?? ?? 5D C3", "( 41 | 42 43 ) ?? 44", "6A 40 [4-6] 8D 4D 00", "DE AD BE EF" };
	int i;

	for (i = 0; i < 4; i++)
		prog_n[i] = kof_hex_compile(t[i], prog[i], sizeof prog[i], NULL);
}

/* ---- a random valid form ------------------------------------------------------ */

/* An expression tree over `n_match` matchers with every non-root node used exactly once. Leaves first, then joins. */
static void random_tree(struct kof_form *f, uint32_t n_leaves_wanted)
{
	uint8_t pending[KOF_FORM_MAX_NODE];
	uint32_t np = 0, i;

	f->n_node = 0;
	for (i = 0; i < n_leaves_wanted; i++) {
		f->node[f->n_node].op = KOF_FORM_OP_LEAF;
		f->node[f->n_node].a = (uint8_t)(rnd() % f->n_match);
		f->node[f->n_node].b = 0;
		pending[np++] = (uint8_t)f->n_node++;
		if (np >= 2u && f->n_node + 2u < KOF_FORM_MAX_NODE && rnd() % 3u) {
			/* join the top two or negate the top one */
			if (rnd() % 4u == 0) {
				f->node[f->n_node].op = KOF_FORM_OP_NOT;
				f->node[f->n_node].a = pending[np - 1u];
				f->node[f->n_node].b = 0;
				pending[np - 1u] = (uint8_t)f->n_node++;
			} else {
				f->node[f->n_node].op = (rnd() & 1u) ? KOF_FORM_OP_AND : KOF_FORM_OP_OR;
				f->node[f->n_node].a = pending[np - 2u];
				f->node[f->n_node].b = pending[np - 1u];
				np--;
				pending[np - 1u] = (uint8_t)f->n_node++;
			}
		}
	}
	while (np > 1u) {
		f->node[f->n_node].op = (rnd() & 1u) ? KOF_FORM_OP_AND : KOF_FORM_OP_OR;
		f->node[f->n_node].a = pending[np - 2u];
		f->node[f->n_node].b = pending[np - 1u];
		np--;
		pending[np - 1u] = (uint8_t)f->n_node++;
	}
	if (rnd() % 5u == 0 && f->n_node < KOF_FORM_MAX_NODE) {
		f->node[f->n_node].op = KOF_FORM_OP_NOT;
		f->node[f->n_node].a = (uint8_t)(f->n_node - 1u);
		f->node[f->n_node].b = 0;
		f->n_node++;
	}
}

static struct kof_form *random_form(void)
{
	struct kof_form *f = kof_form_new();
	uint32_t i, k, ns, nb, nm, sim = rnd() % 3u == 0;
	uint8_t lit[600];

	if (!f)
		return NULL;
	ns = 1u + rnd() % 8u;
	nb = 1u + rnd() % 4u;
	for (i = 0; i < ns; i++) {
		uint8_t flags = (uint8_t)(rnd() & (KOF_STR_ICASE | KOF_STR_WIDE));

		if (rnd() & 1u)
			flags |= (rnd() & 1u) ? KOF_STR_FULLWORD : KOF_STR_TOKEN;
		if (rnd() % 4u == 0) {
			uint32_t pi = rnd() % 4u;

			if (kof_form_add_str(f, KOF_STR_HEX, (uint8_t)(flags & ~KOF_STR_WIDE), prog[pi], prog_n[pi]) < 0)
				return NULL;
		} else {
			uint32_t L = 1u + rnd() % 40u;

			for (k = 0; k < L; k++)
				lit[k] = (uint8_t)rnd();
			if (kof_form_add_str(f, KOF_STR_LITERAL, flags, lit, L) < 0)
				return NULL;
		}
	}
	for (i = 0; i < nb; i++) {
		uint32_t h[KOF_FORM_HASH_MAX], n = KGENOME_MUTATION_MIN_HASH + rnd() % 40u;

		for (k = 0; k < n; k++)
			h[k] = rnd();
		if (kof_form_add_block(f, 1u << (rnd() % 8u), (uint8_t)(rnd() & 1u), h, n) < 0)
			return NULL;
	}
	nm = 1u + rnd() % 6u;
	for (i = 0; i < nm; i++) {
		struct kof_form_match *m = &f->match[f->n_match++];

		memset(m, 0, sizeof *m);
		if (sim) {
			m->kind = KOF_FORM_M_SIM;
			m->thresh = (uint8_t)(1u + rnd() % 100u);
			m->n = (uint8_t)(1u + rnd() % 3u);
			for (k = 0; k < m->n; k++)
				m->arg[k] = (uint8_t)(rnd() % f->n_block);
			f->n_sim++;
		} else {
			m->kind = KOF_FORM_M_FIND;
			m->rule = (uint8_t)(rnd() % 4u);
			if (m->rule == KOF_FORM_R_AT) {
				m->n = 1;
				m->arg[0] = (uint8_t)(rnd() % f->n_str);
				m->anchor = (uint8_t)(rnd() % 3u);
				m->at = (int64_t)(int32_t)rnd();
			} else {
				m->n = (uint8_t)(1u + rnd() % 5u);
				for (k = 0; k < m->n; k++)
					m->arg[k] = (uint8_t)(rnd() % f->n_str);
				m->mask = 1u << (rnd() % 32u);
				if (m->rule == KOF_FORM_R_MULTI)
					m->thresh = (uint8_t)(1u + rnd() % m->n);
			}
		}
	}
	random_tree(f, 1u + rnd() % 10u);
	return f;
}

static int same_form(const struct kof_form *a, const struct kof_form *b)
{
	uint32_t i;

	if (a->n_str != b->n_str || a->n_match != b->n_match || a->n_block != b->n_block || a->n_node != b->n_node ||
	    a->n_sim != b->n_sim)
		return 0;
	for (i = 0; i < a->n_str; i++)
		if (a->str[i].len != b->str[i].len || a->str[i].kind != b->str[i].kind || a->str[i].flags != b->str[i].flags ||
		    memcmp(a->pool + a->str[i].off, b->pool + b->str[i].off, a->str[i].len))
			return 0;
	for (i = 0; i < a->n_block; i++)
		if (a->block[i].mask != b->block[i].mask ||
		    a->block[i].side != b->block[i].side || a->block[i].n_hash != b->block[i].n_hash ||
		    memcmp(a->hash + a->block[i].first, b->hash + b->block[i].first, a->block[i].n_hash * 4u))
			return 0;
	for (i = 0; i < a->n_match; i++)
		if (memcmp(&a->match[i], &b->match[i], sizeof a->match[i]))
			return 0;
	for (i = 0; i < a->n_node; i++)
		if (memcmp(&a->node[i], &b->node[i], sizeof a->node[i]))
			return 0;
	return 1;
}

static uint8_t *wire_of(const struct kof_form *f, size_t *n)
{
	uint8_t *w;

	*n = kof_form_wire_size(f);
	if (!*n)
		return NULL;
	w = malloc(*n);
	if (w && kof_form_wire_write(f, w) != *n) {
		free(w);
		return NULL;
	}
	return w;
}

static void round_trip(void)
{
	uint32_t i, good = 0, same = 0, again = 0, prefix_ok = 0, prefixes = 0;

	for (i = 0; i < 3000u; i++) {
		struct kof_form *f = random_form(), *g;
		size_t n = 0, n2 = 0, p;
		uint8_t *w, *w2;
		const char *why = "x";

		if (!f)
			continue;
		good += kof_form_check(f) == NULL;
		w = wire_of(f, &n);
		if (!w) {
			kof_form_free(f);
			continue;
		}
		g = kof_form_decode(w, n, &why);
		if (g && !why) {
			same += (uint32_t)(same_form(f, g) != 0);
			w2 = wire_of(g, &n2);
			again += w2 && n2 == n && !memcmp(w, w2, n);
			free(w2);
		}
		if (i < 300u) {
			for (p = 0; p < n; p++) {
				struct kof_form *h = kof_form_decode(w, p, NULL);

				prefixes++;
				prefix_ok += h == NULL;
				kof_form_free(h);
			}
		}
		kof_form_free(g);
		kof_form_free(f);
		free(w);
	}
	ok("3000 random forms check clean as built", good == 3000u);
	ok("3000 random forms decode to what was encoded", same == 3000u);
	ok("3000 random forms encode to the same bytes after a decode", again == 3000u);
	ok("every strict prefix of 300 streams is refused", prefixes > 1000u && prefix_ok == prefixes);
}

static void mutate_exhaustive(void)
{
	uint32_t s, accepted = 0, checked = 0, bad = 0;

	for (s = 0; s < 3u; s++) {
		struct kof_form *f;
		size_t n, i, v;
		uint8_t *w;

		for (;;) {
			f = random_form();
			w = f ? wire_of(f, &n) : NULL;
			if (w && n <= 220u)
				break;
			free(w);                /* a form too long for the sweep is given back before the next draw */
			kof_form_free(f);
		}
		for (i = 0; i < n; i++)
			for (v = 0; v < 256u; v++) {
				uint8_t keep = w[i];
				struct kof_form *g;

				w[i] = (uint8_t)v;
				g = kof_form_decode(w, n, NULL);
				checked++;
				if (g) {
					size_t n2;
					uint8_t *w2;
					struct kof_form *h;

					accepted++;
					bad += kof_form_check(g) != NULL;
					w2 = wire_of(g, &n2);
					h = w2 ? kof_form_decode(w2, n2, NULL) : NULL;
					bad += !h || !same_form(g, h);
					kof_form_free(h);
					free(w2);
				}
				kof_form_free(g);
				w[i] = keep;
			}
		free(w);
		kof_form_free(f);
	}
	ok("every byte of three streams set to every value was read without a crash", checked > 5000u);
	ok("what the decoder accepts passes its own check and survives a second round trip", accepted > 0 && !bad);
}

static void sections(void)
{
	size_t len;
	uint8_t src[1300], out[1300 + 2u * 6u], back[1300];
	uint32_t i;

	for (i = 0; i < sizeof src; i++)
		src[i] = (uint8_t)rnd();
	for (len = 0; len <= 1200u; len++) {
		size_t sz = kof_form_section_size(len), w = kof_form_section_write(src, len, out), at = 0, got = 0;
		int fine = sz == w && w == len + 2u * ((len + 254u) / 255u);

		while (at < w) {
			uint8_t tag = out[at], c = out[at + 1u];

			fine = fine && tag == KDIG_SEC_FORM && c >= 1u && at + 2u + c <= w;
			if (at + 2u + c > w)
				break;
			memcpy(back + got, out + at + 2u, c);
			got += c;
			at += 2u + c;
		}
		fine = fine && got == len && !memcmp(back, src, len) && at == w;
		if (!fine) {
			ok("every length 0..1200 is cut into sections of 1..255 bytes and put back", 0);
			return;
		}
	}
	ok("every length 0..1200 is cut into sections of 1..255 bytes and put back", 1);
}

/* ---- bounds -------------------------------------------------------------------- */

/* A minimal valid form: one literal, one ANY matcher, one leaf. */
static struct kof_form *minimal(void)
{
	struct kof_form *f = kof_form_new();
	struct kof_form_match *m;

	kof_form_add_str(f, KOF_STR_LITERAL, 0, (const uint8_t *)"abcd", 4u);
	m = &f->match[f->n_match++];
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_ANY;
	m->n = 1;
	m->mask = 1;
	f->node[0].op = KOF_FORM_OP_LEAF;
	f->n_node = 1;
	return f;
}

static void bounds(void)
{
	struct kof_form *f = kof_form_new();
	uint8_t big[9000];
	uint32_t h[KOF_FORM_HASH_MAX + 2u], i;
	size_t n;
	uint8_t *w;

	memset(big, 'a', sizeof big);
	for (i = 0; i < sizeof h / sizeof h[0]; i++)
		h[i] = i * 7u + 1u;
	for (i = 0; i < KOF_FORM_MAX_STR; i++)
		if (kof_form_add_str(f, KOF_STR_LITERAL, 0, big, 3u) < 0)
			break;
	ok("64 strings fit", i == KOF_FORM_MAX_STR);
	ok("the 65th string is refused, not dropped", kof_form_add_str(f, KOF_STR_LITERAL, 0, big, 3u) < 0 && f->n_str == 64u);
	kof_form_free(f);
	f = kof_form_new();
	ok("a 512 byte literal fits", kof_form_add_str(f, KOF_STR_LITERAL, 0, big, 512u) == 0);
	ok("a 513 byte literal is refused", kof_form_add_str(f, KOF_STR_LITERAL, 0, big, 513u) < 0);
	ok("an empty marker is refused", kof_form_add_str(f, KOF_STR_LITERAL, 0, big, 0u) < 0);
	ok("a program over 8192 bytes is refused", kof_form_add_str(f, KOF_STR_HEX, 0, big, 8193u) < 0);
	ok("a string of a kind this build does not know is refused", kof_form_add_str(f, 7u, 0, big, 3u) < 0);
	kof_form_free(f);
	f = kof_form_new();
	for (i = 0; i < KOF_FORM_MAX_BLOCK; i++)
		if (kof_form_add_block(f, 1u, 0, h, 16u) < 0)
			break;
	ok("32 blocks fit", i == KOF_FORM_MAX_BLOCK);
	ok("the 33rd block is refused", kof_form_add_block(f, 1u, 0, h, 16u) < 0);
	kof_form_free(f);
	f = kof_form_new();
	ok("a block of 128 hashes fits", kof_form_add_block(f, 1u, 0, h, KOF_FORM_HASH_MAX) == 0);
	ok("a block of 129 hashes is refused", kof_form_add_block(f, 1u, 0, h, KOF_FORM_HASH_MAX + 1u) < 0);
	kof_form_free(f);

	/* too few hashes is a check, not an add: a block of 15 hashes cannot be scored */
	f = minimal();
	kof_form_add_block(f, 1u, 0, h, 15u);
	f->match[0].kind = KOF_FORM_M_SIM;
	f->match[0].rule = 0;
	f->match[0].mask = 0;
	f->match[0].thresh = 50;
	f->match[0].arg[0] = 0;
	f->n_sim = 1;
	ok("a block of 15 hashes does not check", kof_form_check(f) != NULL);
	kof_form_free(f);

	/* 16 names in one matcher fit, 17 do not */
	f = minimal();
	for (i = 1; i < 20u; i++)
		kof_form_add_str(f, KOF_STR_LITERAL, 0, (const uint8_t *)"zzzz", 4u);
	for (i = 1; i < 16u; i++)
		f->match[0].arg[i] = (uint8_t)i;
	f->match[0].n = 16;
	ok("a matcher of 16 names checks", kof_form_check(f) == NULL);
	f->match[0].n = 17;
	ok("a matcher of 17 names does not", kof_form_check(f) != NULL);
	kof_form_free(f);

	/* 128 nodes fit: 64 leaves, 63 ANDs, one NOT; one more does not */
	f = kof_form_new();
	kof_form_add_str(f, KOF_STR_LITERAL, 0, (const uint8_t *)"abcd", 4u);
	for (i = 0; i < KOF_FORM_MAX_MATCH; i++) {
		struct kof_form_match *m = &f->match[f->n_match++];

		memset(m, 0, sizeof *m);
		m->kind = KOF_FORM_M_FIND;
		m->rule = KOF_FORM_R_ANY;
		m->n = 1;
		m->mask = 1;
	}
	for (i = 0; i < KOF_FORM_MAX_MATCH; i++) {
		f->node[f->n_node].op = KOF_FORM_OP_LEAF;
		f->node[f->n_node].a = (uint8_t)i;
		f->n_node++;
	}
	for (i = 0; i + 1u < KOF_FORM_MAX_MATCH; i++) {
		f->node[f->n_node].op = KOF_FORM_OP_AND;
		f->node[f->n_node].a = i ? (uint8_t)(KOF_FORM_MAX_MATCH + i - 1u) : 0;
		f->node[f->n_node].b = (uint8_t)(i ? i + 1u : 1u);
		f->n_node++;
	}
	f->node[f->n_node].op = KOF_FORM_OP_NOT;
	f->node[f->n_node].a = (uint8_t)(f->n_node - 1u);
	f->n_node++;
	ok("an expression of 128 nodes (64 matchers, 63 ands, a not) checks", f->n_node == 128u && kof_form_check(f) == NULL);
	w = wire_of(f, &n);
	ok("and goes over the wire", w != NULL);
	if (w) {
		struct kof_form *g = kof_form_decode(w, n, NULL);

		ok("and comes back", g && same_form(f, g));
		kof_form_free(g);
	}
	free(w);
	f->n_node = 129;
	ok("129 nodes do not check", kof_form_check(f) != NULL);
	kof_form_free(f);

	/* the stream bound: a stream one byte over refuses before it is read */
	{
		uint8_t *s = calloc(1, KOF_FORM_MAX_WIRE + 1u);

		ok("a stream over 65536 bytes is refused whole", s && !kof_form_decode(s, KOF_FORM_MAX_WIRE + 1u, NULL));
		ok("an empty stream is refused", !kof_form_decode(s, 0, NULL));
		free(s);
	}
}

/* ---- the tree, the stages, the forward skip ---------------------------------------- */

static void tree_and_stages(void)
{
	struct kof_form *f;
	size_t n;
	uint8_t *w;

	f = minimal();
	f->match[f->n_match] = f->match[0];
	f->n_match++;
	f->node[0].op = KOF_FORM_OP_LEAF;
	f->node[0].a = 0;
	f->node[1].op = KOF_FORM_OP_LEAF;
	f->node[1].a = 1;
	f->node[2].op = KOF_FORM_OP_AND;
	f->node[2].a = 0;
	f->node[2].b = 1;
	f->n_node = 3;
	ok("a plain AND of two matchers checks", kof_form_check(f) == NULL);
	f->node[2].b = 0;
	ok("AND(x, x) is not a tree (a node used twice)", kof_form_check(f) != NULL);
	f->node[2].b = 1;
	f->node[2].a = 2;
	ok("a node that names itself is refused", kof_form_check(f) != NULL);
	f->node[2].a = 0;
	f->node[3].op = KOF_FORM_OP_NOT;
	f->node[3].a = 2;
	f->n_node = 4;
	ok("a NOT over the root is a tree", kof_form_check(f) == NULL);
	f->node[3].a = 1;
	ok("a NOT over a node already used is not", kof_form_check(f) != NULL);
	f->node[3].a = 2;
	/* a part nothing uses */
	f->node[4].op = KOF_FORM_OP_LEAF;
	f->node[4].a = 0;
	f->node[5].op = KOF_FORM_OP_NOT;
	f->node[5].a = 3;
	f->n_node = 6;
	ok("a leaf nothing uses is refused", kof_form_check(f) != NULL);
	f->n_node = 4;
	f->node[0].a = 9;
	ok("a leaf naming a matcher the form has not is refused", kof_form_check(f) != NULL);
	f->node[0].a = 0;
	f->node[1].b = 5;
	ok("a leaf with a stray operand is refused", kof_form_check(f) != NULL);
	f->node[1].b = 0;
	f->node[3].op = 9;
	ok("an operator this build does not know is refused", kof_form_check(f) != NULL);
	f->node[3].op = KOF_FORM_OP_NOT;
	kof_form_free(f);

	f = minimal();
	f->match[0].rule = KOF_FORM_R_AT;
	ok("an AT matcher that names a region is refused", kof_form_check(f) != NULL);
	f->match[0].mask = 0;
	ok("an AT matcher with one marker and the BOF anchor checks", kof_form_check(f) == NULL);
	f->match[0].anchor = 3;
	ok("an anchor this build does not know is refused", kof_form_check(f) != NULL);
	f->match[0].anchor = 0;
	f->match[0].rule = KOF_FORM_R_MULTI;
	f->match[0].mask = 1;
	f->match[0].thresh = 0;
	ok("MULTI with a threshold of zero is refused", kof_form_check(f) != NULL);
	f->match[0].thresh = 2;
	ok("MULTI asking for more than it lists is refused", kof_form_check(f) != NULL);
	f->match[0].thresh = 1;
	ok("MULTI of one of one checks", kof_form_check(f) == NULL);
	f->match[0].arg[0] = 3;
	ok("a marker the form does not have is refused", kof_form_check(f) != NULL);
	kof_form_free(f);

	/* the stages: strings and similarity matchers cannot be one form */
	f = minimal();
	{
		uint32_t h[KGENOME_MUTATION_MIN_HASH], i;
		struct kof_form_match *m;

		for (i = 0; i < KGENOME_MUTATION_MIN_HASH; i++)
			h[i] = i + 1u;
		kof_form_add_block(f, 1u, 0, h, KGENOME_MUTATION_MIN_HASH);
		m = &f->match[f->n_match++];
		memset(m, 0, sizeof *m);
		m->kind = KOF_FORM_M_SIM;
		m->thresh = 60;
		m->n = 1;
		f->n_sim = 1;
		f->node[1].op = KOF_FORM_OP_LEAF;
		f->node[1].a = 1;
		f->node[2].op = KOF_FORM_OP_AND;
		f->node[2].a = 0;
		f->node[2].b = 1;
		f->n_node = 3;
		ok("a form of strings and blocks is refused (two stages)", kof_form_check(f) != NULL);
	}
	kof_form_free(f);

	/* a tag a later build adds is skipped by its length */
	f = minimal();
	w = wire_of(f, &n);
	if (w) {
		uint8_t *x = malloc(n + 7u);
		size_t exprat = n - (3u + 1u + 3u);          /* the EXPR item is the last: tag, len, n, one node */
		struct kof_form *g;

		memcpy(x, w, exprat);
		x[exprat] = 77u;
		x[exprat + 1u] = 4u;
		x[exprat + 2u] = 0;
		memcpy(x + exprat + 3u, "\1\2\3\4", 4u);
		memcpy(x + exprat + 7u, w + exprat, n - exprat);
		g = kof_form_decode(x, n + 7u, NULL);
		ok("an item with a tag a later build adds is skipped by its length", g && same_form(f, g));
		kof_form_free(g);
		/* a second EXPR item is refused (one expression a form), and the stream bound is a bound ON THE BYTES: padded with
		 * skipped items to exactly 65536 it is read, one byte more it is not */
		{
			uint8_t *y = malloc(KOF_FORM_MAX_WIRE + 8u);
			size_t k, pad;
			struct kof_form *g2;

			memcpy(y, w, n);
			memcpy(y + n, w + exprat, n - exprat);
			ok("a second expression item is refused", !kof_form_decode(y, n + (n - exprat), NULL));
			/* pad before the EXPR item with items of an unknown tag, each of 3 + 250 bytes, the last cut to fit */
			memcpy(y, w, exprat);
			k = exprat;
			pad = KOF_FORM_MAX_WIRE - n;
			while (pad) {
				size_t body = pad >= 253u ? 250u : pad - 3u;

				if (pad < 4u) {          /* an item is at least 3 bytes of header and a byte of body */
					body = 0;
					break;
				}
				y[k++] = 77u;
				y[k++] = (uint8_t)body;
				y[k++] = (uint8_t)(body >> 8);
				memset(y + k, 0xA5, body);
				k += body;
				pad -= body + 3u;
			}
			if (!pad) {
				memcpy(y + k, w + exprat, n - exprat);
				k += n - exprat;
				g2 = kof_form_decode(y, k, NULL);
				ok("a stream of exactly 65536 bytes is read (the bound is on the stream, items it skips count)",
				   k == KOF_FORM_MAX_WIRE && g2 && same_form(f, g2));
				kof_form_free(g2);
				y[k] = 77u;
				y[k + 1u] = 1u;
				y[k + 2u] = 0;
				y[k + 3u] = 0;
				ok("one more item is one byte too many for the bound: refused", !kof_form_decode(y, k + 4u, NULL));
			} else {
				ok("the padding could be made exact", 0);
			}
			free(y);
		}
		/* the same item with a length that runs past the stream is a refusal */
		x[exprat + 1u] = 200u;
		ok("an item whose length runs past the stream refuses the stream", !kof_form_decode(x, n + 7u, NULL));
		free(x);
	}
	free(w);
	kof_form_free(f);
}

/* ---- one field at a time: a form that checks clean, and each field the check guards set to a value it must refuse ---- */

static struct kof_form *rich_strings(void)
{
	struct kof_form *f = kof_form_new();
	struct kof_form_match *m;

	kof_form_add_str(f, KOF_STR_LITERAL, KOF_STR_ICASE, (const uint8_t *)"abcd", 4u);        /* 0 */
	kof_form_add_str(f, KOF_STR_HEX, 0, prog[0], prog_n[0]);                                  /* 1 */
	kof_form_add_str(f, KOF_STR_LITERAL, KOF_STR_FULLWORD, (const uint8_t *)"wxyz", 4u);      /* 2 */
	m = &f->match[f->n_match++];                                                              /* 0: ANY of 0, 1 */
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_ANY;
	m->n = 2;
	m->arg[1] = 1;
	m->mask = 0x80000000u;
	m = &f->match[f->n_match++];                                                              /* 1: 2 of 3 */
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_MULTI;
	m->n = 3;
	m->arg[1] = 1;
	m->arg[2] = 2;
	m->thresh = 2;
	m->mask = 0x10u;
	m = &f->match[f->n_match++];                                                              /* 2: AT entry + 8 */
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_AT;
	m->n = 1;
	m->arg[0] = 2;
	m->anchor = KOF_FORM_ANCHOR_ENTRY;
	m->at = 8;
	leaf(f, 0); leaf(f, 1); join(f, KOF_FORM_OP_AND, 0, 1); leaf(f, 2); join(f, KOF_FORM_OP_OR, 2, 3);
	return f;
}

static struct kof_form *rich_blocks(void)
{
	struct kof_form *f = kof_form_new();
	struct kof_form_match *m;
	uint32_t h[KOF_FORM_HASH_MAX], i;

	for (i = 0; i < KOF_FORM_HASH_MAX; i++)
		h[i] = i * 31u + 7u;
	kof_form_add_block(f, 0x20u, 0, h, 20u);
	kof_form_add_block(f, 0x40000000u, 1, h, KOF_FORM_HASH_MAX);
	m = &f->match[f->n_match++];
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_SIM;
	m->thresh = 75;
	m->n = 2;
	m->arg[1] = 1;
	f->n_sim = 1;
	leaf(f, 0);
	return f;
}

#define MUT(form, what, field, value) do { \
		struct kof_form *mf = (form); \
		mf->field = (value); \
		ok(what, kof_form_check(mf) != NULL); \
		kof_form_free(mf); \
	} while (0)

static void one_field_at_a_time(void)
{
	struct kof_form *f = rich_strings(), *g = rich_blocks();

	ok("the form of strings checks clean", kof_form_check(f) == NULL);
	ok("the form of blocks checks clean", kof_form_check(g) == NULL);
	kof_form_free(f);
	kof_form_free(g);

	MUT(rich_strings(), "a string of a kind this build does not know", str[0].kind, 2u);
	MUT(rich_strings(), "a flag this build does not know", str[0].flags, 0x10u);
	MUT(rich_strings(), "a marker that is a whole word and a whole token", str[2].flags, KOF_STR_FULLWORD | KOF_STR_TOKEN);
	MUT(rich_strings(), "a marker with no bytes", str[0].len, 0u);
	{
		struct kof_form *h = rich_strings();

		h->str[2].len = (uint16_t)(h->pool_n - h->str[2].off + 1u);
		ok("a marker that ends one byte past the pool", kof_form_check(h) != NULL);
		h->str[2].len = (uint16_t)(h->pool_n - h->str[2].off);
		ok("and the same marker ending exactly at the pool's end is fine", kof_form_check(h) == NULL);
		kof_form_free(h);
	}
	MUT(rich_strings(), "a literal of 513 bytes", str[0].len, 513u);
	{
		/* the program's bytes are valid where they sit and the offset is not aligned: only the alignment can refuse it */
		struct kof_form *h = rich_strings();

		memmove(h->pool + 1, h->pool + h->str[1].off, h->str[1].len);
		h->str[1].off = 1;
		ok("a valid hex program on an offset it does not align to", kof_form_check(h) != NULL);
		kof_form_free(h);
	}
	MUT(rich_strings(), "a hex program longer than the bound", str[1].len, (uint16_t)(KOF_HEX_MAX_PROG + 1u));
	{
		struct kof_form *h = rich_strings();

		memset(h->pool + h->str[1].off, 0xEE, h->str[1].len);
		ok("a hex program that is not one (bytes of nothing)", kof_form_check(h) != NULL);
		kof_form_free(h);
	}
	MUT(rich_strings(), "a matcher rule this build does not know", match[0].rule, 4u);
	MUT(rich_strings(), "a matcher of a kind this build does not know", match[0].kind, 2u);
	MUT(rich_strings(), "a searching matcher with an anchor", match[0].anchor, 1u);
	MUT(rich_strings(), "a searching matcher with a step", match[0].at, 4);
	MUT(rich_strings(), "a searching matcher with no region", match[0].mask, 0u);
	MUT(rich_strings(), "ANY with a threshold", match[0].thresh, 1u);
	MUT(rich_strings(), "MULTI with a threshold of zero", match[1].thresh, 0u);
	MUT(rich_strings(), "MULTI with more than it lists", match[1].thresh, 4u);
	MUT(rich_strings(), "AT with a region", match[2].mask, 1u);
	MUT(rich_strings(), "AT with a threshold", match[2].thresh, 1u);
	MUT(rich_strings(), "AT with an anchor this build does not know", match[2].anchor, 3u);
	MUT(rich_strings(), "AT over two markers", match[2].n, 2u);
	MUT(rich_strings(), "a matcher that lists nothing", match[0].n, 0u);
	MUT(rich_strings(), "a matcher that names a marker it has not", match[0].arg[1], 3u);
	MUT(rich_strings(), "a form counting a similarity matcher it has not", n_sim, 1u);

	MUT(rich_blocks(), "a block of a side this build does not know", block[1].side, 2u);
	MUT(rich_blocks(), "a block of no region", block[0].mask, 0u);
	MUT(rich_blocks(), "a block of 15 hashes", block[0].n_hash, 15u);
	MUT(rich_blocks(), "a block of 129 hashes", block[1].n_hash, 129u);
	MUT(rich_blocks(), "a block whose hashes end one past the pool", block[1].first, 21u);
	MUT(rich_blocks(), "a similarity matcher of 0 percent", match[0].thresh, 0u);
	MUT(rich_blocks(), "a similarity matcher of 101 percent", match[0].thresh, 101u);
	MUT(rich_blocks(), "a similarity matcher with a rule", match[0].rule, 1u);
	MUT(rich_blocks(), "a similarity matcher with a region", match[0].mask, 1u);
	MUT(rich_blocks(), "a similarity matcher with an anchor", match[0].anchor, 1u);
	MUT(rich_blocks(), "a similarity matcher with a step", match[0].at, 1);
	MUT(rich_blocks(), "a similarity matcher naming a block it has not", match[0].arg[1], 2u);
	MUT(rich_blocks(), "a form that lost its similarity count", n_sim, 0u);
	{
		/* a root that names itself, with every other node used (so nothing else refuses it): the evaluator would never end */
		struct kof_form *h = minimal();

		h->n_match = 1;
		h->n_node = 0;
		leaf(h, 0);
		join(h, KOF_FORM_OP_NOT, 0, 0);
		join(h, KOF_FORM_OP_AND, 2, 1);
		ok("a root that is its own child", kof_form_check(h) != NULL);
		kof_form_free(h);
		/* and a NOT that names itself while everything else is used: the evaluator would never end on it */
		h = minimal();
		h->n_node = 0;
		leaf(h, 0);
		join(h, KOF_FORM_OP_NOT, 1, 0);
		join(h, KOF_FORM_OP_AND, 0, 1);
		ok("a NOT that is its own child", kof_form_check(h) != NULL);
		/* the whole expression is one node that names itself: nothing else is left to refuse it */
		h->n_node = 0;
		join(h, KOF_FORM_OP_NOT, 0, 0);
		ok("an expression that is one NOT of itself", kof_form_check(h) != NULL);
		kof_form_free(h);
	}
	/* the field checks of the stream are the same ones: a block's normalizer and a rule, as bytes of a stream */
	{
		struct kof_form *h = rich_blocks();
		size_t n;
		uint8_t *w = wire_of(h, &n);
		struct kof_form *d;
		size_t at = 3u + 2u;                 /* the BLOCK item: tag and length, then mask u32 -> norm at +4 */

		d = w ? kof_form_decode(w, n, NULL) : NULL;
		ok("the blocks stream decodes", d != NULL);
		kof_form_free(d);
		if (w) {
			w[3u + 4u] = 3u;
			d = kof_form_decode(w, n, NULL);
			ok("a normalizer byte that is no normalizer refuses the stream", !d);
			kof_form_free(d);
			w[3u + 4u] = 1u;                 /* the removed XOR */
			d = kof_form_decode(w, n, NULL);
			ok("the removed XOR normalizer byte refuses the stream", !d);
			kof_form_free(d);
			w[3u + 4u] = 2u;                 /* the removed SUB */
			d = kof_form_decode(w, n, NULL);
			ok("the removed SUB normalizer byte refuses the stream", !d);
			kof_form_free(d);
			w[3u + 4u] = 0;
			w[3u + 5u] = 2u;
			d = kof_form_decode(w, n, NULL);
			ok("a side byte that is no side refuses the stream", !d);
			kof_form_free(d);
		}
		(void)at;
		free(w);
		kof_form_free(h);
	}
	/* an item whose length says more than its fields: refused (the length is the item's own, not a hint) */
	{
		struct kof_form *h = minimal();
		size_t n, at = 0;
		uint8_t *w = wire_of(h, &n), *x;

		while (w && at + 3u <= n && w[at] != KOF_FORM_I_FIND)
			at += 3u + (size_t)(w[at + 1u] | (w[at + 2u] << 8));
		x = w ? malloc(n + 1u) : NULL;
		if (x) {
			size_t len = (size_t)(w[at + 1u] | (w[at + 2u] << 8)), end = at + 3u + len;

			memcpy(x, w, end);
			x[end] = 0;
			memcpy(x + end + 1u, w + end, n - end);
			x[at + 1u] = (uint8_t)(len + 1u);
			ok("a FIND item with one byte more than its fields is refused", !kof_form_decode(x, n + 1u, NULL));
			x[at + 1u] = (uint8_t)len;
			ok("the same bytes with the true length are a stream whose next item starts at the stray byte (refused)",
			   !kof_form_decode(x, n + 1u, NULL));
			free(x);
		}
		free(w);
		kof_form_free(h);
	}
	/* the mask of a matcher is 32 bits wide on the wire */
	{
		struct kof_form *h = rich_strings();
		size_t n;
		uint8_t *w = wire_of(h, &n);
		struct kof_form *d = w ? kof_form_decode(w, n, NULL) : NULL;

		ok("a mask with its top bit set survives the wire", d && d->match[0].mask == 0x80000000u && d->match[2].at == 8);
		kof_form_free(d);
		free(w);
		kof_form_free(h);
	}
}

/* ---- spelling -------------------------------------------------------------------- */

static void leaf(struct kof_form *f, uint8_t m)
{
	f->node[f->n_node].op = KOF_FORM_OP_LEAF;
	f->node[f->n_node].a = m;
	f->node[f->n_node].b = 0;
	f->n_node++;
}

static void join(struct kof_form *f, uint8_t op, uint8_t a, uint8_t b)
{
	f->node[f->n_node].op = op;
	f->node[f->n_node].a = a;
	f->node[f->n_node].b = b;
	f->n_node++;
}

static int says(struct kof_form *f, const char *want)
{
	char t[128];
	size_t n = kof_form_expr_text(f, t, sizeof t);

	if (strcmp(t, want) || n != strlen(want)) {
		printf("  expression came out %s, wanted %s\n", t, want);
		return 0;
	}
	return 1;
}

static void spelling(void)
{
	struct kof_form *f = minimal();
	char tiny[4];

	f->n_match = 4;
	for (int i = 1; i < 4; i++) {
		f->match[i] = f->match[0];
		f->match[i].arg[0] = 0;
	}
	/* 0 & !1 | 2 */
	f->n_node = 0;
	leaf(f, 0); leaf(f, 1); join(f, KOF_FORM_OP_NOT, 1, 0); join(f, KOF_FORM_OP_AND, 0, 2); leaf(f, 2);
	join(f, KOF_FORM_OP_OR, 3, 4);
	ok("and binds tighter than or", kof_form_check(f) == NULL && says(f, "0 & !1 | 2"));
	/* (0 | 1) & 2 */
	f->n_node = 0;
	leaf(f, 0); leaf(f, 1); join(f, KOF_FORM_OP_OR, 0, 1); leaf(f, 2); join(f, KOF_FORM_OP_AND, 2, 3);
	ok("an or under an and is parenthesised", kof_form_check(f) == NULL && says(f, "(0 | 1) & 2"));
	/* !(0 & 1) */
	f->n_node = 0;
	leaf(f, 0); leaf(f, 1); join(f, KOF_FORM_OP_AND, 0, 1); join(f, KOF_FORM_OP_NOT, 2, 0);
	ok("a not over an and is parenthesised", kof_form_check(f) == NULL && says(f, "!(0 & 1)"));
	/* 0 | (1 | 2): the right child of an or of the same strength keeps its brackets, as the tree says */
	f->n_node = 0;
	leaf(f, 0); leaf(f, 1); leaf(f, 2); join(f, KOF_FORM_OP_OR, 1, 2); join(f, KOF_FORM_OP_OR, 0, 3);
	ok("the right child of an or is bracketed (the tree's own shape)", kof_form_check(f) == NULL && says(f, "0 | (1 | 2)"));
	ok("the text is cut at the buffer and the length wanted is returned",
	   kof_form_expr_text(f, tiny, sizeof tiny) == strlen("0 | (1 | 2)") && !tiny[3] && !strncmp(tiny, "0 |", 3));
	ok("no form has no text", kof_form_expr_text(NULL, tiny, sizeof tiny) == 0 && tiny[0] == 0);
	kof_form_free(f);
}

int main(void)
{
	make_programs();
	ok("the programs compiled", prog_n[0] && prog_n[1] && prog_n[2] && prog_n[3]);
	round_trip();
	mutate_exhaustive();
	sections();
	bounds();
	tree_and_stages();
	one_field_at_a_time();
	spelling();
	if (failures) {
		printf("diag_form_wire: %d FAIL\n", failures);
		return 1;
	}
	printf("diag_form_wire: ok\n");
	return 0;
}
