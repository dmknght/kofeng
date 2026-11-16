/*
 * script_text.c - THE ONE LEX of a script (script_private.h, kgenome_script_text_make): the language's own lexer run once over the
 * text, its per-byte answer kept (`kind`, `code`), the code of the eval()-literals php runs merged into `code`, and the text's one paren
 * table. Every function strategy (script_funcs.c, script_funcs_<lang>.c) and the island builder (script_islands.c) read this and nothing
 * else: no reader lexes again. Split out of script_funcs.c (2026-11-14, island package) where it was the head of the brace walk; no
 * logic changed in the move.
 */

#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <kgenome_budget.h>   /* kgenome_grow_cap */
#include <textual/textual.h>

#include "nucleo.h"           /* kgenome_nucleo_cap_of_name, KGENOME_NUCLEO_EVAL: the eval-literal island trigger asks the SAME
				 * per-language vocabulary the phenotype evaluator asks (diag_text_walk.c's callee_cap) */
#include "script_private.h"

/* How far one lookahead of the eval()-literal search reads (the header lookahead of script_funcs.c, FN_LOOKAHEAD, the same number). */
#define FN_LOOKAHEAD KGENOME_SCRIPT_LOOKAHEAD

static int is_name_php(uint8_t c)
{
	return kgenome_script_php_name(c);
}

/*
 * How many eval()-literal islands deep a PHP text is followed (below): an eval'd string that
 * itself contains `eval('...')` is followed one level further, up to this many. CHOSEN, not
 * measured (same convention as FN_LOOKAHEAD) - generous for a real obfuscation chain, small enough
 * that a hostile file built only to nest eval() cannot make this file do unbounded work. Provably
 * bounded regardless of the value chosen: a level's own candidates are disjoint STRING spans of
 * that level's text (the lexer's spans partition the input), so the bytes re-lexed at one level
 * can never exceed the text's own length - the recursion cannot blow up combinatorially, only
 * linearly in depth (R: reasoned from the span invariant in textual_span.h, not timed on a
 * corpus). A text nested past this depth is NOT merged as code (KGENOME_FNTAB_P_EVAL_SKIP,
 * reported on the object, never silent - rule 4: a cap must not be mistaken for a wrong answer).
 */
#define EVAL_LIT_DEPTH 8u

/* One STRING span, collected only when `mark_ctx.collect` is set (PHP only, see
 * kgenome_script_funcs_build) - the eval-literal island search (below) needs to tell "a string
 * starts here" apart from "code resumes here" at an eval() call's argument position, which the
 * is_code[] bitmap alone cannot say (it only marks CODE vs not). off/len/open_len/close_len/flags
 * are the span's own fields (textual_span.h) - no second lex pass reads them, this is the one
 * pass that already saw every span. */
struct str_lit {
	uint64_t off, len, open_len, close_len;
	uint8_t flags;
};

/* One eval()-literal island that was found AND merged as code (its own braces balanced - see
 * merge_eval_island): the span of its VALUE bytes, [off, off+len), used only to flag a function
 * found inside one (KGENOME_FN_F_EVAL_ISLAND) - never read for anything the brace-matching main
 * loop itself needs, which sees the merged is_code[] bits and nothing else. */
struct eval_island {
	uint64_t off, len;
};

struct mark_ctx {
	uint8_t *code;
	uint8_t *kind;          /* NULL for an eval literal's own lex: only the object's lex keeps kinds */
	uint64_t n;
	/* Only used/grown when `collect` is set: the eval-literal search's own input, never read by
	 * the brace-matching main loop. */
	struct str_lit *strs;
	uint32_t n_strs, cap_strs;
	int collect;
	int oom;        /* growing strs[] failed: collection stopped, reported via KGENOME_FNTAB_P_EVAL_SKIP */
};

static int mark_code_sink(void *user, const struct kgenome_textual_span *sp)
{
	struct mark_ctx *m = user;
	uint64_t from = sp->off, to = (uint64_t)sp->off + sp->len;

	if (sp->kind == KGENOME_TEXTUAL_CODE && to <= m->n) {
		memset(m->code + from, 1, (size_t)(to - from));
		return 1;
	}
	if (m->collect && sp->kind == KGENOME_TEXTUAL_STRING && to <= m->n) {
		if (m->n_strs == m->cap_strs) {
			uint32_t nc = kgenome_grow_cap(m->cap_strs, 16u);
			struct str_lit *ns = nc ? realloc(m->strs, (size_t)nc * sizeof *ns) : NULL;

			if (!ns) {
				m->oom = 1;
				m->collect = 0;         /* give up on islands, not on the base scan: the
							  * lex keeps running so is_code[] still comes
							  * out complete (rule: a failure of this
							  * OPTIONAL feature must not cost the base one) */
				return 1;
			}
			m->strs = ns;
			m->cap_strs = nc;
		}
		m->strs[m->n_strs].off = sp->off;
		m->strs[m->n_strs].len = sp->len;
		m->strs[m->n_strs].open_len = sp->open_len;
		m->strs[m->n_strs].close_len = sp->close_len;
		m->strs[m->n_strs].flags = sp->flags;
		m->n_strs++;
	}
	return 1;
}


/*
 * EVAL()-LITERAL ISLANDS (PHP only, 2026-11-10 - owner: "code loaded from a string needs to be
 * treated as an island of code and tokenized the same way [as real code]", based on nucleo's
 * existing per-language eval vocabulary).
 *
 * THE SHAPE FOUND, and no other: a call this language's own nucleo table (nucleo_names_php.c)
 * names KGENOME_NUCLEO_EVAL ("eval", "assert"), whose ONE argument is a single STRING literal that
 * is closed, does not interpolate (KGENOME_TEXTUAL_F_INTERP unset - a php single-quoted string or
 * a nowdoc, never a double-quoted one: a double-quoted string's VALUE is not always its raw bytes,
 * see below) and holds no backslash at all. That last check is what lets this file skip writing a
 * second unescaper (kofeng/CLAUDE.md rule 2): a single-quoted php string with no backslash in it
 * decodes to its own raw bytes exactly (single-quote escaping is only \\ and \', per php's own
 * rules), so the VALUE bytes read here are already what php would hand to eval() - there is
 * nothing to decode. A string that needs decoding (any backslash, or an interpolating string even
 * with none) is explicitly NOT a match: the decoded value's bytes do not in general correspond
 * 1:1 to the raw ones (an escape can shrink the length, interpolation substitutes a runtime value
 * this file never has), and this file's whole convention - a function's off/len is a span into the
 * OBJECT'S OWN BYTES - has nothing to point AT for a value that is not simply those bytes. This is
 * why "a literal argument" is scoped to a BARE, non-interpolating, escape-free literal and not
 * "any string php could eval()": it is not merely the smallest case, it is the one case whose
 * answer can be given in this file's own (off, len)-into-the-object vocabulary at all. A variable,
 * a concatenation, a function call (base64_decode(...) and friends) or an interpolating/escaped
 * string as the argument is left exactly as before this feature: an ordinary STRING span, opaque,
 * no island. The same reasoning is WHY this is not reached by reusing the phenotype evaluator
 * (diag_text_walk.c's layer_of_call, which already follows eval() through decodes and
 * concatenation for the diagnose/capability graph): that mechanism's answer is a COMPUTED value
 * with no byte-range in the object in the general case (kgenome_dtx_eval_range allocates it), and
 * phenotype's own scope/alias tracking is a diagnose-scan-lifetime mechanism kofeng/CLAUDE.md's own
 * celllysis/phenotype split keeps out of celllysis on purpose (script_funcs.h's header: "no scope
 * stack, no alias tracking, no diagnose-scan lifetime"). What IS reused is the one thing that is
 * genuinely one fact in one place: the name-to-capability vocabulary itself
 * (kgenome_nucleo_cap_of_name, nucleo.h) - this file asks it the same question phenotype's
 * callee_cap already asks, just syntactically (no value flow) and only for a literal argument.
 *
 * WHAT THIS DOES, mechanically, once a match is found: the value bytes are lexed a second time, as
 * their own PHP FRAGMENT (kgenome_textual_lex, KGENOME_TEXTUAL_FRAGMENT - the same flag
 * kgenome_textual_islands already uses for code with no opening tag), and the CODE bytes that lex
 * finds are OR'd into THIS file's own is_code[] bitmap at the island's real file offset. The
 * brace-matching main loop below is not told about this at all and does not need to be: it reads
 * is_code[] after every island has been merged into it, so a "function" keyword inside an eval'd
 * string is found by the SAME one pass that finds a top-level one, with no second code path (rule
 * 10). The one condition guarding the merge is that the island's OWN braces balance (counted over
 * its own is_code[] bits before it is merged): an unbalanced or malformed fragment is NOT merged -
 * forcing it in would desync the shared brace_depth counter for every byte of the script AFTER it,
 * corrupting evidence the main loop would otherwise have gotten right (rule 4: a cap, or here a
 * refusal to trust unverified evidence, must never be mistaken for a wrong answer - leaving the
 * bytes as an ordinary string is the same answer this file always gave them, not a worse one).
 *
 * RECURSION: an island may itself contain another eval()-literal island (the lex that read its
 * value bytes also collected ITS OWN string spans), followed up to EVAL_LIT_DEPTH levels, each
 * reported if a cap or an unbalanced fragment stops it (KGENOME_FNTAB_P_EVAL_SKIP on the object,
 * never silent).
 */

struct island_list {
	struct eval_island *v;
	uint32_t n, cap;
};

static int island_push(struct island_list *L, uint64_t off, uint64_t len)
{
	if (L->n == L->cap) {
		uint32_t nc = kgenome_grow_cap(L->cap, 8u);
		struct eval_island *nv = nc ? realloc(L->v, (size_t)nc * sizeof *nv) : NULL;

		if (!nv)
			return 0;
		L->v = nv;
		L->cap = nc;
	}
	L->v[L->n].off = off;
	L->v[L->n].len = len;
	L->n++;
	return 1;
}

/*
 * What every eval-island helper below reads: the object's bytes, the SHARED is_code[] bitmap
 * (mutated in place as islands are merged into it) and the current recursion level's own STRING
 * spans. Grouped into one struct (kofeng/CLAUDE.md's "one request, one result": a function takes
 * few enough loose parameters that `make check-rules`'s 8-parameter ceiling is about a caller's
 * clarity, not about trimming a real one below it) - `data`/`code` stay the SAME arrays at every
 * recursion level (absolute offsets throughout); `strs`/`n_strs` are rebuilt fresh per level (a
 * nested island's own lex collects its own string spans, remapped to absolute offsets once, in
 * merge_eval_island, rather than carrying a second base offset through every helper).
 */
struct eval_scan {
	const uint8_t *data;
	uint8_t *code;
	const struct str_lit *strs;
	uint32_t n_strs;
};

/*
 * Forward from `at`, skipping real whitespace and any run of bytes that is not code and not the
 * exact first byte of a collected string literal (a comment is transparent the same way
 * skip_trivia treats it for a declaration's own shape) - stopping at the first byte that is either
 * real (non-whitespace) code or a string literal's own start, whichever comes first. This is NOT
 * skip_trivia (used by every shape_* matcher above): skip_trivia reads THROUGH a string as noise
 * because a declaration's shape never cares what is inside one; an eval() call's argument position
 * is the one place in this file that must tell "a string starts here" apart from "code resumes
 * here", which is exactly what `*is_str`/`*str_idx` answer. `sc->strs` is assumed delivered in
 * ascending `off` order (the lexer's own span-stream invariant, textual_span.h: spans partition
 * the input in order) - a binary search, not a second sort. `bound` is the hard stop (the current
 * level's own scan_to); `limit` is the FN_LOOKAHEAD-style soft cap on how far this ONE lookahead
 * may run.
 */
static uint64_t skip_to_arg(const struct eval_scan *sc, uint64_t bound, uint64_t at, uint64_t limit,
			     int *is_str, uint32_t *str_idx)
{
	*is_str = 0;
	while (at < bound && at < limit) {
		if (sc->code[at]) {
			uint8_t c = sc->data[at];

			if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
				at++;
				continue;
			}
			return at;      /* real code: the argument is not a bare literal */
		}
		{
			uint32_t lo = 0, hi = sc->n_strs;

			while (lo < hi) {
				uint32_t mid = lo + (hi - lo) / 2;

				if (sc->strs[mid].off < at)
					lo = mid + 1u;
				else
					hi = mid;
			}
			if (lo < sc->n_strs && sc->strs[lo].off == at) {
				*is_str = 1;
				*str_idx = lo;
				return at;
			}
		}
		at++;           /* not code, not a string's own start: a comment byte, skip it too */
	}
	return at;
}

static void find_eval_islands(const struct eval_scan *sc, uint64_t scan_from, uint64_t scan_to,
			       uint32_t depth, struct island_list *islands, int *skipped);

/* A confirmed eval()-literal island [val_off, val_off+val_len): lex its own bytes as a PHP
 * fragment, merge its CODE bits into `psc->code[]` if (and only if) its own braces balance, then
 * look for a deeper island inside it. `*skipped` is set (never cleared) when this island, or one
 * nested inside it, was found but NOT merged - the depth cap, an allocation failure, or an
 * unbalanced fragment. `bound` is the caller's own scan range's end (its "scan_to"): a sanity
 * ceiling on val_len, never a byte this function reads - the real bound a STRING span cannot
 * exceed is the caller's own range, which already guarantees val_len fits it, so this can only
 * ever refuse a value that could not have been found by a correct caller. Only `psc->data`/`code`
 * are read from `psc`: the parent's own `strs`/`n_strs` say nothing about THIS island's content,
 * which gets its own fresh lex below. */
static void merge_eval_island(const struct eval_scan *psc, uint64_t bound, uint64_t val_off,
			       uint64_t val_len, uint32_t depth, struct island_list *islands,
			       int *skipped)
{
	struct mark_ctx smc;
	struct kgenome_textual_lex_req srq;
	struct kgenome_textual_lex_res sres;
	struct eval_scan nsc;
	uint8_t *subcode;
	int64_t bal = 0;
	uint64_t k;

	if (depth > EVAL_LIT_DEPTH || !val_len || val_len > bound) {
		if (val_len)
			*skipped = 1;
		return;
	}
	subcode = calloc((size_t)val_len, 1);
	if (!subcode) {
		*skipped = 1;
		return;
	}
	memset(&smc, 0, sizeof smc);
	smc.code = subcode;
	smc.n = val_len;
	smc.collect = 1;        /* a nested eval inside this one is followed too */
	memset(&srq, 0, sizeof srq);
	srq.in = psc->data + val_off;
	srq.n = (uint32_t)val_len;
	srq.lang = KGENOME_TEXTUAL_LANG_PHP;
	srq.flags = KGENOME_TEXTUAL_FRAGMENT;
	srq.sink = mark_code_sink;
	srq.user = &smc;
	(void)kgenome_textual_lex(&srq, &sres);
	if (smc.oom)
		*skipped = 1;

	/* the island's OWN braces, over its OWN code bytes only: must balance, or merging would
	 * desync the shared brace_depth counter for everything after it (see the header comment) */
	for (k = 0; k < val_len; k++) {
		if (!subcode[k])
			continue;
		if (psc->data[val_off + k] == '{')
			bal++;
		else if (psc->data[val_off + k] == '}' && --bal < 0)
			break;
	}
	if (bal != 0) {
		*skipped = 1;
		free(smc.strs);
		free(subcode);
		return;
	}
	for (k = 0; k < val_len; k++)
		if (subcode[k])
			psc->code[val_off + k] = 1;
	if (!island_push(islands, val_off, val_len))
		*skipped = 1;
	if (smc.n_strs) {
		/* the nested lex's spans are 0-based in its own fragment: remap to the object's own
		 * bytes once, here, rather than carrying a second base offset through every helper */
		for (k = 0; k < smc.n_strs; k++)
			smc.strs[k].off += val_off;
		nsc.data = psc->data;
		nsc.code = psc->code;
		nsc.strs = smc.strs;
		nsc.n_strs = smc.n_strs;
		find_eval_islands(&nsc, val_off, val_off + val_len, depth + 1u, islands, skipped);
	}
	free(smc.strs);
	free(subcode);
}

/* One forward scan of [scan_from, scan_to) for an eval()-literal call: at every identifier-start
 * CODE byte, ask nucleo whether the word is KGENOME_NUCLEO_EVAL for php, and when it is, require
 * "(" then a closed, non-interpolating, escape-free STRING literal then ")" with nothing else -
 * the one shape this feature recognises (see the header comment for why no other shape is). A
 * match's whole call (identifier through the closing ")") is skipped in one step, so a merged
 * island's own bytes are never re-examined as identifier candidates in this same scan. */
static void find_eval_islands(const struct eval_scan *sc, uint64_t scan_from, uint64_t scan_to,
			       uint32_t depth, struct island_list *islands, int *skipped)
{
	const uint8_t *data = sc->data, *code = sc->code;
	uint64_t i;

	for (i = scan_from; i < scan_to; i++) {
		uint64_t idlen, limit, popen;
		int is_str = 0;
		uint32_t str_idx = 0;
		char nb[64];

		if (!code[i] || !is_name_php(data[i]) || (i && code[i - 1u] && is_name_php(data[i - 1u])))
			continue;
		idlen = 0;
		while (i + idlen < scan_to && code[i + idlen] && is_name_php(data[i + idlen]))
			idlen++;
		if (!idlen || idlen >= sizeof nb) {
			i += idlen ? idlen - 1u : 0;
			continue;
		}
		memcpy(nb, data + i, (size_t)idlen);
		nb[idlen] = 0;
		if (kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PHP, nb) != KGENOME_NUCLEO_EVAL) {
			i += idlen - 1u;
			continue;
		}
		limit = i + idlen + FN_LOOKAHEAD < scan_to ? i + idlen + FN_LOOKAHEAD : scan_to;
		popen = skip_to_arg(sc, scan_to, i + idlen, limit, &is_str, &str_idx);
		if (is_str || popen >= limit || !code[popen] || data[popen] != '(') {
			i += idlen - 1u;
			continue;
		}
		(void)skip_to_arg(sc, scan_to, popen + 1u, limit, &is_str, &str_idx);
		if (!is_str) {
			i += idlen - 1u;
			continue;       /* no "(", or the argument is not a bare string: out of scope */
		}
		{
			const struct str_lit *sl = &sc->strs[str_idx];
			uint64_t val_off, val_len, close_at;

			if ((sl->flags & (KGENOME_TEXTUAL_F_OPEN | KGENOME_TEXTUAL_F_INTERP)) ||
			    sl->len < sl->open_len + sl->close_len) {
				i += idlen - 1u;
				continue;       /* unterminated or interpolating: not this shape */
			}
			val_off = sl->off + sl->open_len;
			val_len = sl->len - sl->open_len - sl->close_len;
			if (val_len && memchr(data + val_off, '\\', (size_t)val_len)) {
				i += idlen - 1u;
				continue;       /* an escape: the raw bytes are not the decoded value */
			}
			close_at = skip_to_arg(sc, scan_to, sl->off + sl->len, limit, &is_str, &str_idx);
			if (is_str || close_at >= limit || !code[close_at] || data[close_at] != ')') {
				i += idlen - 1u;
				continue;       /* a second argument, or something else before ")" */
			}
			merge_eval_island(sc, scan_to, val_off, val_len, depth, islands, skipped);
			i = close_at;   /* resume right after the whole call: its own bytes were
					  * already, or were deliberately not, merged above */
		}
	}
}


/*
 * THE PAREN TABLE: every code "(" of the text with the code ")" that closes it, built in one pass
 * over the code bytes (a stack), in order of the "(" - so a header's parameter list is matched by a
 * binary search and not by a scan from each candidate (a string or a comment inside contributes
 * nothing, so a default value of ")" or "{" cannot end a list early; an unclosed "(" has no
 * close). Matching from the "(" with a fresh depth and matching on one stack give the same ")": the
 * depth counted from a "(" never returns to zero before its own close.
 */
#define PAREN_NONE UINT32_MAX

struct paren_tab {
	uint32_t *open, *close;
	uint32_t n;
};

static int paren_tab_build(struct paren_tab *pt, const uint8_t *p, const uint8_t *code, uint64_t n)
{
	uint32_t *stack, depth = 0, cap = 0;
	uint64_t i;

	memset(pt, 0, sizeof *pt);
	for (i = 0; i < n; i++)
		cap += code[i] && p[i] == '(';
	if (!cap)
		return 1;
	pt->open = malloc((size_t)cap * sizeof *pt->open);
	pt->close = malloc((size_t)cap * sizeof *pt->close);
	stack = malloc((size_t)cap * sizeof *stack);
	if (!pt->open || !pt->close || !stack) {
		free(pt->open);
		free(pt->close);
		free(stack);
		memset(pt, 0, sizeof *pt);
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (!code[i])
			continue;
		if (p[i] == '(') {
			pt->open[pt->n] = (uint32_t)i;
			pt->close[pt->n] = PAREN_NONE;
			stack[depth++] = pt->n++;
		} else if (p[i] == ')' && depth) {
			pt->close[stack[--depth]] = (uint32_t)i;
		}
	}
	free(stack);
	return 1;
}

/* The ")" that closes the code "(" at `open`: 0 when it has none. */
static int paren_close(const struct paren_tab *pt, uint64_t open, uint64_t *close)
{
	uint32_t lo = 0, hi = pt->n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (pt->open[mid] < open)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (lo == pt->n || pt->open[lo] != open || pt->close[lo] == PAREN_NONE)
		return 0;
	*close = pt->close[lo];
	return 1;
}

int kgenome_script_paren_close(const struct kgenome_script_text *t, uint64_t open, uint64_t *close)
{
	const struct paren_tab pt = { t->par_open, t->par_close, t->n_par };

	return paren_close(&pt, open, close);
}

/* What one lex delivers into the two per-byte arrays: the kind of every byte, and which bytes are CODE. */
static int text_sink(void *user, const struct kgenome_textual_span *sp)
{
	struct mark_ctx *m = user;
	uint64_t to = (uint64_t)sp->off + sp->len;

	if (m->kind && to <= m->n)
		memset(m->kind + sp->off, sp->kind, (size_t)sp->len);
	return mark_code_sink(user, sp);
}

int kgenome_script_text_make(uint32_t lang, uint32_t flags, const uint8_t *p, uint64_t n, struct kgenome_script_text *out)
{
	struct mark_ctx mc;
	struct kgenome_textual_lex_req rq;
	struct kgenome_textual_lex_res lr;
	struct island_list *islands;
	uint8_t *code, *kind;
	int skipped = 0;

	memset(out, 0, sizeof *out);
	if (!p || !n || n > 0xffffffffu || !kgenome_textual_lang_known(lang))
		return 0;
	code = calloc((size_t)n, 1);
	kind = malloc((size_t)n);
	islands = calloc(1, sizeof *islands);
	if (!code || !kind || !islands) {
		free(code);
		free(kind);
		free(islands);
		return 0;
	}
	memset(&mc, 0, sizeof mc);
	mc.code = code;
	mc.kind = kind;
	mc.n = n;
	mc.collect = (lang == KGENOME_TEXTUAL_LANG_PHP);        /* eval()-literal islands: PHP only */
	memset(&rq, 0, sizeof rq);
	rq.in = p;
	rq.n = (uint32_t)n;
	rq.lang = lang;
	rq.flags = flags & KGENOME_TEXTUAL_FRAGMENT;
	rq.sink = text_sink;
	rq.user = &mc;
	(void)kgenome_textual_lex(&rq, &lr);
	if (mc.oom)
		skipped = 1;
	if (mc.collect && mc.n_strs) {
		struct eval_scan top_sc;

		top_sc.data = p;
		top_sc.code = code;
		top_sc.strs = mc.strs;
		top_sc.n_strs = mc.n_strs;
		/* depth 1: the top-level text is depth 0 (never checked against the cap, it is not
		 * itself an island); an island found here, or nested inside one, is depth >= 1. */
		find_eval_islands(&top_sc, 0, n, 1u, islands, &skipped);
	}
	free(mc.strs);
	{
		/* after the eval islands are merged: their code's parens are code too */
		struct paren_tab pt;

		if (!paren_tab_build(&pt, p, code, n)) {
			struct island_list *il = islands;

			free(il->v);
			free(il);
			free(code);
			free(kind);
			return 0;
		}
		out->par_open = pt.open;
		out->par_close = pt.close;
		out->n_par = pt.n;
	}
	out->p = p;
	out->n = n;
	out->lang = lang;
	out->flags = flags & KGENOME_TEXTUAL_FRAGMENT;
	out->code = code;
	out->kind = kind;
	out->evals = islands;
	out->eval_skipped = (uint8_t)skipped;
	return 1;
}

void kgenome_script_text_free(struct kgenome_script_text *t)
{
	struct island_list *islands = t->evals;

	if (islands)
		free(islands->v);
	free(islands);
	free(t->code);
	free(t->kind);
	free(t->par_open);
	free(t->par_close);
	memset(t, 0, sizeof *t);
}

void kgenome_script_eval_flag(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	const struct island_list *islands = t->evals;
	uint32_t i;

	/* Mark every surviving entry whose start lies inside a merged eval()-literal island (rule 7:
	 * say where the evidence came from) - one pass, after the walk has already decided the final
	 * list. `islands->n` is normally 0 or small (one entry per real eval()-literal call in the text). */
	for (i = 0; islands && i < l->n && islands->n; i++) {
		uint32_t ii;

		for (ii = 0; ii < islands->n; ii++)
			if (l->v[i].off >= islands->v[ii].off &&
			    l->v[i].off < islands->v[ii].off + islands->v[ii].len) {
				l->v[i].flags |= KGENOME_FN_F_EVAL_ISLAND;
				break;
			}
	}
	if (t->eval_skipped)
		l->partial |= KGENOME_FNTAB_P_EVAL_SKIP;
}
