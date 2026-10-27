/*
 * objctx_textscan.c - the ONE scan of a script's text, made for whichever stage asks first and shared by the other two.
 *
 * WHY. The symbol block (the names a script calls), the constants stage and the diagnose stage each walked the object's text with the TEXT route
 * (kgenome_diag_scan_text): the names with on_node, the constants with on_const and on_head, the graph with none. The graph does not depend on which
 * callbacks are set (tests/lib/genome/diag_text_scan_same.c, and the node dump of every script corpus), so one walk gives all three. Callgrind over 71 php, 299 js and 297 shell
 * scripts: the walks were 55 to 75% of the instructions of a scan.
 *
 * THE ORDER IS THE ENGINE'S: the names are asked first (the gate reads them), the constants next (heuristic level 2), the graph last. The scan is made by the first stage that asks and
 * it tells the names and - when the level asks for the constants and the object is one the constants stage will take - collects them, because the stage that comes later
 * cannot ask a walk that has been made. A stage that finds the scan not made for what it needs (the constants not collected: the level was not asked at that
 * moment) makes its own and replaces it, so what a stage reads is always what a walk of its own would have given.
 *
 * WHAT IS KEPT, AND UNTIL WHEN: the scan, the distinct names and the collected constants, until the object ends (kof_scan_text_drop, sx_obj_begin). The graph leaves with
 * oc_text_take, which hands the diagnose stage its scan: it is that stage's from then on, and it is freed with the diagnose product (kof_scan_diag_drop) - a caller that takes one outside
 * that stage owns it and frees it (tests/unit/text_scan_hold.c did not, and unit-asan reported the scan it took). What is held is the scanner's memory (scan_charge) and is given back with it.
 */

#include <stdlib.h>
#include <string.h>

#include "objctx_int.h"
#include "../analyzers/parsers/scripts/script_apply.h"
#include "../analyzers/parsers/scripts/script_parse.h"
#include "../analyzers/parsers/scripts/script_route.h"
#include "../analyzers/parsers/scripts/script_sym.h"
#include "../analyzers/parsers/binaries/funcs.h"
#include <phenotype/diag_scan.h>
#include <phenotype/diag_text_names.h>
#include <textual/textual.h>

static int same_text(const struct kof_scan_obj_text *t, uint32_t lang, kof_buf b)
{
	return t->base == b.p && t->n == b.n && t->lang == lang;
}

/* Everything the product holds, given back; `deep` is the object's and stays. */
static void text_clear(struct kof_scanner *sc)
{
	struct kof_scan_obj_text *t = &sc->obj.text;
	uint8_t deep = t->deep, made = t->made;

	if (t->s)
		kgenome_diag_scan_free(t->s);
	oc_scan_release(sc, t->charged);
	free(t->name);
	oc_consts_free(t->consts);
	memset(t, 0, sizeof *t);
	t->deep = deep;
	t->made = made;
}

void kof_scan_text_drop(struct kof_scanner *sc)
{
	text_clear(sc);
	sc->obj.text.deep = 0;
}

/* A name the scan told, kept (the table's own string: it stays valid). */
static void name_kept(void *user, const char *name, uint32_t len)
{
	struct kof_scan_obj_text *t = user;

	(void)len;
	/* KNOWN DEFECT REV-D8b (2026-10-24, Inference) [sev L]: the name collector doubles a uint32 capacity (cap_name) with no overflow guard and no ledger charge.
	 * Trigger: 2^31 names (not reachable below the tree's memory cap: the count is bounded by the text). Effect: `nc` wraps to 0, realloc(0) then writes past the table.
	 * Reproducer: none. Fix: grow through one checked helper (uint64_t arithmetic, refuse past 0xffffffff, charge the scanner's ledger). */
	if (t->n_name == t->cap_name) {
		uint32_t nc = t->cap_name ? t->cap_name * 2u : 32u;
		const char **nn = realloc(t->name, (size_t)nc * sizeof *nn);

		if (!nn) {
			t->names_lost = 1;
			return;
		}
		t->name = nn;
		t->cap_name = nc;
	}
	t->name[t->n_name++] = name;
}

/* Make the scan of `b`, telling the names and - when `consts` - collecting the constants, and keep it. 1 when it was made. */
static int text_make(struct kof_scanner *sc, uint32_t lang, kof_buf b, int consts)
{
	struct kof_scan_obj_text *t = &sc->obj.text;
	struct kgenome_budget kb;
	struct kgenome_diag_text_names_acc *acc;
	struct kgenome_diag_text_req rq = { .base = b.p, .size = b.n, .lang = lang, .budget = &kb, .apply = kof_script_apply };
	uint64_t peak;

	text_clear(sc);
	acc = kgenome_diag_text_names_new(lang, name_kept, t);
	if (!acc)
		return 0;
	rq.on_node = kgenome_diag_text_names_node;
	rq.user = acc;
	if (consts) {
		t->consts = oc_consts_new(sc, lang, b.n);
		if (!t->consts) {
			kgenome_diag_text_names_free(acc);
			return 0;
		}
		rq.on_const = oc_consts_on_const;
		rq.on_head = oc_consts_on_head;
		rq.const_user = t->consts;
	}
	kgenome_budget_default(&kb, b.n, 0);
	kb.max_bytes = oc_scan_room(sc);
	t->s = kgenome_diag_scan_text(&rq);
	kgenome_diag_text_names_free(acc);
	if (!t->s) {
		text_clear(sc);
		return 0;
	}
	t->base = b.p;
	t->n = b.n;
	t->lang = lang;
	t->made = (uint8_t)(t->made < 255u ? t->made + 1u : 255u);
	t->eval_cut = (uint8_t)(kgenome_diag_scan_eval_cut(t->s) != 0);
	t->charged = kgenome_diag_scan_bytes(t->s, &peak);
	scan_charge(sc, t->charged);
	return 1;
}

/* Will the constants stage take this object: the level asks, the language is one the evaluator writes, and the object is not a view of a script (a form of a form is the form). */
static int consts_expected(const struct kof_scanner *sc, uint32_t lang, kof_buf b)
{
	return sc->obj.text.deep && oc_script_consts_serves(lang) && sc->cur.src && kof_src_kind_of(sc->cur.src) != KOF_ENT_NORMALIZED &&
	       b.n <= sc->ledger.obj_cap;
}

static void feed_names(void *user, void (*put)(void *, const char *, uint32_t), void *put_user)
{
	const struct kof_scan_obj_text *t = &((const struct kof_scanner *)user)->obj.text;
	uint32_t i;

	for (i = 0; i < t->n_name; i++)
		put(put_user, t->name[i], (uint32_t)strlen(t->name[i]));
}

/*
 * THE SYMBOL BLOCK OF AN OBJECT: a script's names come from the one scan of its text, made now if no stage has made it; every other format is the one builder
 * sym_any.c picks (kof_syms_build_grow). `*passes` is how many times a builder ran, for the product's count.
 */
uint32_t oc_syms_build(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, const struct kgenome_pe_imptab *imp, uint32_t *passes)
{
	uint32_t lang = oc_text_served(ctx) ? kof_script_textual_lang(ctx->subtype) : 0u;
	kof_buf b = kof_buf_make(sc->match.m.data.p, sc->match.m.data.n);

	if (lang && b.p && b.n && b.n <= 0xffffffffu &&
	    (same_text(&sc->obj.text, lang, b) || text_make(sc, lang, b, consts_expected(sc, lang, b))) && !sc->obj.text.names_lost)
		return kof_syms_build_grow_script(feed_names, sc, &sc->syms.buf, &sc->syms.cap, passes);
	/* no scan (not a script the route reads, nothing to read, memory refused): the block from a scan of its own, as it always was */
	return kof_syms_build_grow(ctx->format, b.p, b.n, ctx->file_header, imp, &sc->syms.buf, &sc->syms.cap, passes);
}

struct oc_consts *oc_text_consts(struct kof_scanner *sc, uint32_t lang, kof_buf b)
{
	struct kof_scan_obj_text *t = &sc->obj.text;

	if (same_text(t, lang, b) && t->consts)
		return t->consts;
	return text_make(sc, lang, b, 1) ? t->consts : NULL;
}

int oc_text_eval_cut(const struct kof_scanner *sc)
{
	return sc->obj.text.eval_cut;
}

struct kgenome_diag_scan *oc_text_take(struct kof_scanner *sc, uint32_t lang, kof_buf b)
{
	struct kof_scan_obj_text *t = &sc->obj.text;
	struct kgenome_diag_scan *s = t->s;

	if (!s || !same_text(t, lang, b))
		return NULL;
	oc_scan_release(sc, t->charged);
	t->charged = 0;
	t->s = NULL;
	return s;
}
