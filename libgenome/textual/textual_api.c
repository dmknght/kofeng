/*
 * textual_api.c - the functions of textual.h: pick the language, walk the text, and deliver
 * what was found. THE ONE DRIVER: kgenome_textual_lex asks the row how the text is walked -
 * a page (`page`), one of the shared lexers (`whole`), or the language's own `lex` - and
 * is the only caller of that layer; the spans every one of them delivers come through
 * kgenome_textual_emit, here.
 */

#include "textual_lang.h"

static int flush(struct kgenome_textual_lexer *lx)
{
	if (!lx->have_pend)
		return 1;
	lx->have_pend = 0;
	lx->n_span++;
	lx->n_open += (lx->pend.flags & KGENOME_TEXTUAL_F_OPEN) != 0;
	if (!lx->sink(lx->user, &lx->pend)) {
		lx->refused = 1;
		return 0;
	}
	return 1;
}

int kgenome_textual_emit(struct kgenome_textual_lexer *lx, uint32_t len, uint8_t kind, uint8_t flags,
		 uint32_t open_len, uint32_t close_len)
{
	if (lx->refused)
		return 0;
	if (!len)
		return 1;
	if (lx->have_pend && lx->pend.kind == kind && !flags && !lx->pend.flags &&
	    (kind == KGENOME_TEXTUAL_CODE || kind == KGENOME_TEXTUAL_MARKUP)) {
		lx->pend.len += len;
		lx->pos += len;
		return 1;
	}
	if (!flush(lx))
		return 0;
	lx->pend.off = lx->pos;
	lx->pend.len = len;
	lx->pend.open_len = open_len;
	lx->pend.close_len = close_len;
	lx->pend.kind = kind;
	lx->pend.flags = flags;
	lx->have_pend = 1;
	lx->pos += len;
	return 1;
}

/* KNOWN DEFECT REV-D1 (2026-10-24, R) [sev M]: kgenome_textual_lex reports a lexer's cut three ways: n_bound (only sh_lex.c and textual_clike.c feed it), F_OPEN/n_open (depth caps of ruby, psh, tcl, ecma, cfm, perl's here-document table) and a refusal.
 * Trigger: a hostile text that reaches a cap of a lexer other than sh or the c-like page walks. Effect: the engine's `rs.n_bound` test (objctx_script_dec.c) sees only two of the lexers' bounds; the others surface as open spans or not at all.
 * Reproducer: none (read; textual_defect_attack.c covers refusal and open counts, not n_bound). Fix: one carrier: every lexer cap does `lx->n_bound++` (changes KOF_BROKEN_LIMIT for hostile deep texts: owner ok first). */
enum kgenome_textual_status kgenome_textual_lex(const struct kgenome_textual_lex_req *rq,
						struct kgenome_textual_lex_res *res)
{
	const struct kgenome_textual_lang *lang = kgenome_textual_lang_find(rq->lang);
	struct kgenome_textual_lexer lx = { .p = rq->in, .n = rq->n, .sink = rq->sink, .user = rq->user,
					    .fragment = (rq->flags & KGENOME_TEXTUAL_FRAGMENT) != 0 };

	res->n_span = res->n_open = res->n_bound = 0;
	if (!lang)
		return KGENOME_TEXTUAL_NO_LANG;
	if (lang->page)
		kgenome_textual_page_lex(&lx, lang->page);
	else if (lang->whole)
		(void)kgenome_textual_island_lex(&lx, lang->whole, lx.n);
	else
		lang->lex(&lx);
	flush(&lx);
	res->n_span = lx.n_span;
	res->n_open = lx.n_open;
	res->n_bound = lx.n_bound;
	if (lx.refused)
		return KGENOME_TEXTUAL_REFUSED;
	return lx.n_open ? KGENOME_TEXTUAL_OPEN : KGENOME_TEXTUAL_OK;
}

/* The state of one island walk: the spans of the lexer folded into islands. */
struct isl_walk {
	const struct kgenome_textual_islands_req *rq;
	struct kgenome_textual_island cur;
	uint8_t open, refused;
};

static int isl_deliver(struct isl_walk *w)
{
	w->open = 0;
	if (!w->rq->sink(w->rq->user, &w->cur)) {
		w->refused = 1;
		return 0;
	}
	return 1;
}

/* The tag's own bytes: the language row's `tag_own` of the span, or the whole span. */
static uint32_t tag_len(const struct isl_walk *w, const struct kgenome_textual_span *s, int close)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(w->rq->lang);

	return l && l->tag_own ? l->tag_own(w->rq->in + s->off, s->len, close) : s->len;
}

static int isl_span(void *u, const struct kgenome_textual_span *s)
{
	struct isl_walk *w = u;

	/* MARKUP while an island is open is code that ended with no closing tag: what follows php's __halt_compiler is data, and the island ends where
	 * the code did */
	if (s->kind == KGENOME_TEXTUAL_MARKUP && w->open) {
		w->cur.end_tag = s->off;
		return isl_deliver(w);
	}
	if (s->kind != KGENOME_TEXTUAL_TAG)
		return 1;
	/* the "#!" line of a script is a tag (the lexer keeps the interpreter's line from being dropped as a comment) and it opens nothing: a shell has no islands (L17 of the lexer audit) */
	if (s->off == 0 && s->len >= 2u && w->rq->in[0] == '#' && w->rq->in[1] == '!')
		return 1;
	if (s->flags & KGENOME_TEXTUAL_F_CLOSE) {
		if (!w->open)
			return 1;
		w->cur.end_tag = s->off;
		w->cur.close_len = tag_len(w, s, 1);
		w->cur.closed = 1;
		return isl_deliver(w);
	}
	if (w->open) {                          /* an opening tag inside an island that never closed: the first ends where the second begins (end_tag was left at n: the islands overlapped) */
		w->cur.end_tag = s->off;
		if (!isl_deliver(w))
			return 0;
	}
	w->cur = (struct kgenome_textual_island){ .off = s->off, .open_len = tag_len(w, s, 0), .end_tag = w->rq->n };
	w->open = 1;
	return 1;
}

enum kgenome_textual_status kgenome_textual_islands(const struct kgenome_textual_islands_req *rq)
{
	struct isl_walk w = { .rq = rq };
	struct kgenome_textual_lex_req lq = { .in = rq->in, .n = rq->n, .lang = rq->lang, .flags = rq->flags, .sink = isl_span, .user = &w };
	struct kgenome_textual_lex_res lr;
	enum kgenome_textual_status st;

	/* a fragment is code from its first byte: its island has no opening tag, and is open until a closing one */
	if (rq->flags & KGENOME_TEXTUAL_FRAGMENT) {
		w.cur = (struct kgenome_textual_island){ .end_tag = rq->n };
		w.open = 1;
	}
	st = kgenome_textual_lex(&lq, &lr);
	if (w.open && !w.refused)
		(void)isl_deliver(&w);
	return w.refused ? KGENOME_TEXTUAL_REFUSED : st;
}

int kgenome_textual_glue_always(uint8_t a, uint8_t b)
{
	(void)a;
	(void)b;
	return 1;
}

const char *kgenome_textual_kind_name(uint32_t kind)
{
	static const char *const name[KGENOME_TEXTUAL_KIND_COUNT] = {
		"markup", "tag", "code", "string", "comment"
	};

	return kind < KGENOME_TEXTUAL_KIND_COUNT ? name[kind] : "?";
}
