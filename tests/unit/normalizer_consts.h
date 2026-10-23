#ifndef KOFENG_TESTS_NORMALIZER_CONSTS_H
#define KOFENG_TESTS_NORMALIZER_CONSTS_H

/*
 * normalizer_consts.h - what the lib's constants path reports for a text, as a test reads it: the values the evaluator says a script's computed right
 * sides come to (kgenome_diag_scan_text, on_const, with the engine's string functions) and the text with them written where they were computed
 * (kgenome_textual_subst). The two calls the engine makes in objctx_script_consts.c, without the scanner. Every test that asks "what does this script build"
 * - normalizer_script (the differential), script_norm (the poly builds), silent_loss_parsers (the bounds) - asks it here.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/analyzers/parsers/scripts/script_apply.h"
#include <phenotype/diag_scan.h>
#include <textual/textual.h>

#ifndef NR_UNUSED
#define NR_UNUSED __attribute__((unused))
#endif

struct one {
	uint32_t off, len;
	uint8_t *v;
	uint32_t n;
	uint8_t  bare;          /* the head of a call, whose value is a name */
};

struct cset {
	struct one *c;
	unsigned n, cap;
	enum kgenome_status st;
	uint32_t cut;           /* expressions left unread for nesting past the evaluator's bound */
};

static void on_range(struct cset *s, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n, int bare);
static void on_const(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n) NR_UNUSED;
static void on_const(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	on_range(u, off, len, v, n, 0);
}

static void on_head(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n) NR_UNUSED;
static void on_head(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	on_range(u, off, len, v, n, 1);
}

static void on_range(struct cset *s, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n, int bare)
{

	if (s->n == s->cap) {
		s->cap = s->cap ? s->cap * 2u : 16u;
		s->c = realloc(s->c, s->cap * sizeof *s->c);
	}
	s->c[s->n].off = (uint32_t)off;
	s->c[s->n].len = (uint32_t)len;
	s->c[s->n].v = malloc(n + 1u);
	if (n)
		memcpy(s->c[s->n].v, v, n);
	s->c[s->n].n = n;
	s->c[s->n].bare = (uint8_t)bare;
	s->n++;
}

static void cset_free(struct cset *s) NR_UNUSED;
static void cset_free(struct cset *s)
{
	unsigned i;

	for (i = 0; i < s->n; i++)
		free(s->c[i].v);
	free(s->c);
	memset(s, 0, sizeof *s);
}

/* The constants of `p` in language `lang`, in order, and the scan's status. */
static void consts_of(uint32_t lang, const uint8_t *p, size_t n, struct cset *s) NR_UNUSED;
static void consts_of(uint32_t lang, const uint8_t *p, size_t n, struct cset *s)
{
	struct kgenome_budget kb;
	struct kgenome_diag_text_req rq;
	struct kgenome_diag_scan *sc;

	memset(s, 0, sizeof *s);
	kgenome_budget_default(&kb, n, 0);
	memset(&rq, 0, sizeof rq);
	rq.base = p;
	rq.size = n;
	rq.lang = lang;
	rq.budget = &kb;
	rq.apply = kof_script_apply;
	rq.on_const = on_const;
	rq.on_head = on_head;
	rq.const_user = s;
	sc = kgenome_diag_scan_text(&rq);
	s->st = sc ? kgenome_diag_scan_status(sc) : KGENOME_NOMEM;
	s->cut = kgenome_diag_scan_eval_cut(sc);
	kgenome_diag_scan_free(sc);
}

/* The text with every constant written where it was computed (the engine's call), into a fresh buffer. 0 when there was nothing to write. */
static uint32_t consts_text(uint32_t lang, const uint8_t *p, size_t n, const struct cset *s, uint8_t **out) NR_UNUSED;
static uint32_t consts_text(uint32_t lang, const uint8_t *p, size_t n, const struct cset *s, uint8_t **out)
{
	struct kgenome_textual_subst *sub;
	unsigned i;
	uint64_t cap;
	uint32_t w, ns;

	*out = NULL;
	if (!s->n)
		return 0;
	sub = malloc(s->n * sizeof *sub);
	for (i = 0; i < s->n; i++)
		sub[i] = (struct kgenome_textual_subst){ s->c[i].off, s->c[i].len, s->c[i].v, s->c[i].n, s->c[i].bare };
	ns = kgenome_textual_subst_order(sub, s->n);
	cap = kgenome_textual_subst_cap(lang, p, (uint32_t)n, sub, ns);
	*out = malloc((size_t)cap + 1u);
	w = kgenome_textual_subst(lang, p, (uint32_t)n, sub, ns, *out, (uint32_t)cap);
	free(sub);
	return w;
}


#endif /* KOFENG_TESTS_NORMALIZER_CONSTS_H */
