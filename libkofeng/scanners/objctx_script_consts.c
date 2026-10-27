/*
 * objctx_script_consts.c - what a script computes, written where it was computed: the engine's half of the two lib calls that make it.
 *
 * `$u = str_replace('T|', '', $a . $b . $c)` says what it makes only when it runs, and a view that keeps the call says nothing about the
 * program it builds. The EVALUATOR is the lib's (kgenome_diag_text_req.on_const: the same one that reads a callee's name and the code a
 * script hands to create_function, so there is one place that knows what str_replace and a join come to; its string functions are the
 * engine's hook, script_apply.h) and the TEXT WRITER is the lib's (kgenome_textual_subst, which writes a value the way the language writes a
 * literal). What is here is the decision between them: collect what the evaluator reports, within the allowance a script's decoded text has
 * (oc_script_dec_room), and have the text written with it. It replaced an older folder (script_fold.c) that carried an evaluation of its own
 * and read perl, powershell and tcl (the only rows of its table with a variable sigil besides php) with a str_replace they do not have; this
 * is asked of every language the evaluator serves and whose row has a `quote` (oc_script_consts_serves).
 *
 * A BOUND THAT FIRES IS REPORTED (oc_scan_limit) and what was collected up to it is still written: a constant left in its computed form is
 * a view that says less, never one that says something false.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "objctx_int.h"
#include "../analyzers/parsers/scripts/script_apply.h"
#include <phenotype/diag_scan.h>
#include <textual/textual.h>

struct sub_rec {
	uint32_t off, len, vn;
	uint8_t bare;           /* a call's head: the value is a name, written as it is */
	uint64_t voff;          /* into the arena, which moves while it grows: an offset, resolved when it stops */
};

struct oc_consts {
	uint32_t lang;
	struct sub_rec *r;
	uint32_t n, cap;
	uint8_t *arena;
	uint64_t an, acap, room;
	int fail;
};

static void on_range(struct oc_consts *a, uint64_t off, uint64_t len, const uint8_t *val, uint32_t n, int bare)
{

	if (a->fail)
		return;
	/* a value the language cannot write as one literal (a line break in a vbscript string, "%>" in a page) stays the expression that makes it */
	if (!bare && !kgenome_textual_subst_can(a->lang, val, n))
		return;
	if (off > 0xffffffffu || len > 0xffffffffu - off || a->an + n > a->room) {
		a->fail = 1;            /* the allowance for what a script computes is spent */
		return;
	}
	if (a->n == a->cap) {
		/* KNOWN DEFECT REV-D8c (2026-10-25, Inference) [sev L]: the sub_rec table doubles a uint32 capacity with no overflow guard and no ledger charge (only the arena is bounded, by a->room).
		 * Trigger: about 2^31 recorded substitutions (records of length 0 are not stopped by room). Effect: cap * 2u wraps to 0, realloc(0) and a write past the table;
		 * not reachable in practice (a->an and the script size bound it first, not measured). Reproducer: none. Fix: bound a->n by the same allowance as the arena, or refuse when cap > UINT32_MAX / 2. */
		uint32_t nc = a->cap ? a->cap * 2u : 16u;
		struct sub_rec *nr = realloc(a->r, (size_t)nc * sizeof *nr);

		if (!nr) {
			a->fail = 1;
			return;
		}
		a->r = nr;
		a->cap = nc;
	}
	if (a->an + n > a->acap) {
		uint64_t nc = a->acap ? a->acap * 2u : 4096u;
		uint8_t *na;

		while (nc < a->an + n)
			nc *= 2u;
		na = realloc(a->arena, (size_t)nc);
		if (!na) {
			a->fail = 1;
			return;
		}
		a->arena = na;
		a->acap = nc;
	}
	if (n)                  /* an empty value may come with no pointer */
		memcpy(a->arena + a->an, val, n);
	a->r[a->n++] = (struct sub_rec){ (uint32_t)off, (uint32_t)len, n, (uint8_t)bare, a->an };
	a->an += n;
}

int oc_script_consts_serves(uint32_t lang)
{
	return lang && kgenome_diag_text_serves(lang) && kgenome_textual_subst_can(lang, NULL, 0);
}

void oc_consts_on_const(void *u, uint64_t off, uint64_t len, const uint8_t *val, uint32_t n)
{
	on_range(u, off, len, val, n, 0);
}

/* The head of a call whose variable is one name: written bare, where it stands. */
void oc_consts_on_head(void *u, uint64_t off, uint64_t len, const uint8_t *val, uint32_t n)
{
	on_range(u, off, len, val, n, 1);
}

struct oc_consts *oc_consts_new(const struct kof_scanner *sc, uint32_t lang, uint64_t n)
{
	struct oc_consts *c = calloc(1, sizeof *c);

	if (c) {
		c->lang = lang;
		c->room = oc_script_dec_room(sc, n);
	}
	return c;
}

void oc_consts_free(struct oc_consts *c)
{
	if (!c)
		return;
	free(c->r);
	free(c->arena);
	free(c);
}

/*
 * What the evaluator reported for this text, written where it was computed. The report comes from the one scan of the text (objctx_textscan.c): the one the names
 * stage made with the constants asked for, or - when none was - the one this makes and keeps for the diagnose stage.
 */
uint32_t oc_script_consts(struct kof_scanner *sc, uint32_t lang, kof_buf b, uint8_t **text, uint32_t *text_n, uint64_t *charged)
{
	struct oc_consts *a;
	struct kgenome_textual_subst *sub = NULL;
	uint8_t *out = NULL;
	uint64_t cap;
	uint32_t i, w, nr, n_sub = 0;

	*text = NULL;
	*text_n = 0;
	*charged = 0;
	a = oc_text_consts(sc, lang, b);
	/* the evaluator's bound that fired (an expression nested past it) is said: what was collected is true, and partial. NOT the scan's status: that is
	 * the names' too (a table of them that filled) and the diagnose stage reports it from its own scan of the same text. */
	if (!a || oc_text_eval_cut(sc))
		oc_scan_limit(sc);
	if (!a)
		return 0;
	if (a->fail)
		oc_scan_limit(sc);
	if (!a->n)
		goto done;
	sub = malloc((size_t)a->n * sizeof *sub);
	if (!sub)
		goto done;
	for (i = 0; i < a->n; i++)
		sub[i] = (struct kgenome_textual_subst){ a->r[i].off, a->r[i].len, a->arena + a->r[i].voff, a->r[i].vn, a->r[i].bare };
	/* the constants came in order, the heads after them: in file order, and a head inside a range already taken is that range's (kgenome_textual_subst_order) */
	nr = kgenome_textual_subst_order(sub, a->n);
	cap = kgenome_textual_subst_cap(lang, b.p, (uint32_t)b.n, sub, nr);
	/* The text is the scanner's memory like any other: it has to fit under the ceiling, and under what 32 bits can address. */
	if (cap > 0xffffffffu || cap > oc_scan_room(sc) / 2u) {
		oc_scan_limit(sc);
		goto done;
	}
	out = malloc((size_t)cap);
	if (!out)
		goto done;
	w = kgenome_textual_subst(lang, b.p, (uint32_t)b.n, sub, nr, out, (uint32_t)cap);
	if (!w) {
		free(out);
		goto done;
	}
	scan_charge(sc, cap);
	*charged = cap;
	*text = out;
	*text_n = w;
	n_sub = nr;
done:
	free(sub);
	return n_sub;
}
