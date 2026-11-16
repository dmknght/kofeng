/*
 * script_funcs_tcl.c - the functions of a TCL text (script_private.h, kgenome_script_strategy).
 *
 * THE SPECIFICATION READ (the twelve rules of the Tcl(n) manual page, Tcl 8.6, and the proc(n), namespace(n), oo::class(n),
 * oo::define(n) pages):
 *   - A SCRIPT is commands separated by line breaks and ";"; a command is words separated by blanks; "\<line break>" is a blank.
 *     A word is braced {...} (braces nest, a backslash escapes one, nothing else is special), quoted "..." (a "[...]" in it is a
 *     script), or bare (a "[...]" in it is a script). "#" where a command begins is a comment to the end of the line.
 *   - A FUNCTION is the command "proc name args body" (also "::proc"): the entry runs from "proc" to the end of the body word.
 *     A proc is only a command: a "proc" that is not the first word of a command is a word ("puts proc", "list proc {} {}").
 *   - A braced word is a SCRIPT only to the command that takes it, and nothing in the text says which; the scripts read here are the
 *     bodies of: "namespace eval ns BODY..." (a namespace is not a function, its procs are units), "oo::class create C BODY",
 *     "oo::define C BODY" and the braced words after "if" (conditions and bodies alike: a condition holds no command at the
 *     start of its text that is "proc" with three words after it), "catch" and "eval". In an oo body "method name args body",
 *     "constructor args body" and "destructor body" are units (named "method"'s name, "constructor", "destructor");
 *     "oo::define C method name args body" on one line is one, from "oo::define". A "[...]" is a script anywhere (a proc in
 *     "set p [proc q {} {...}]" is a unit), except inside a quoted word of the text itself, which its lexer delivers as one
 *     STRING.
 *   - Only OUTERMOST: a proc body is never read, so a proc in a proc is the outer's.
 *   - A proc command that ENDS before its body word ("proc g {a}" then a line break) defines nothing and is not a unit. The text
 *     ending before the body word ends (an unclosed brace, or no body yet) is OPEN (KGENOME_FN_F_END_OPEN, run to the end).
 *
 * HOW IT IS READ. The lexer (textual/tcl/tcl_lex.c) delivers every braced and quoted word of the text as one STRING and does not
 * lex inside it ("a reader that wants the body as code" reads it). So: the text's own words are read off the lexer's spans (a
 * STRING run is a word or a part of one, a COMMENT run is skipped) and the bytes inside a braced word that is one of the scripts
 * above are read by the rules above, structurally: a braced word is skipped by matching its braces, a quoted word by its quote,
 * a "[" opens a script that ends at its "]", a "}" where a word begins ends the braced script being read. A script read so is
 * bounded by the lexer's span of the word it is in. ONE PASS: each byte is read once; the scripts being read are an explicit stack
 * (heap, grown by doubling), so a text of 100000 nested namespaces costs 100000 frames and no recursion.
 *
 * NOT MEASURED on real text: no .tcl file in /mnt/games/normtest/fix_island/corpus and no tclsh on this machine (2026-11-14); the
 * tests are the only evidence.
 *
 * LIMITS, named: brace counting inside a body follows the script's structure, not tcl's lexical count, so a "}" inside a quoted
 * word of a namespace body (which ends the body for tcl) does not end it here (such a body is broken tcl); the scripts of other
 * commands that take one (while, for, foreach, switch, uplevel, after, a proc body) are not read - a proc defined inside them is
 * not a unit; "[...]" inside a quoted word of the text itself is the lexer's STRING and is not read.
 */

#include <stdlib.h>

#include "script_private.h"

#include <textual/textual.h>

enum tcl_word { TW_NONE, TW_BARE, TW_QUOTE, TW_BRACE, TW_SCRIPT };
enum tcl_fkind { TF_TEXT, TF_BRACE, TF_BRACKET };
enum tcl_ckind { TC_NONE, TC_PROC, TC_NS, TC_OOCLASS, TC_OODEF, TC_CONT };

struct tcl_cmd {
	uint64_t start;
	uint64_t name_off, name_len;
	uint32_t nword;                 /* words ended so far */
	uint32_t body_at;               /* TC_PROC: the index of the body word */
	uint32_t script_from;           /* NS / OOCLASS / OODEF / CONT: braced words from this index on are scripts */
	uint8_t  kind, script_oo;
};

struct tcl_frame {
	uint8_t  kind;                  /* enum tcl_fkind */
	uint8_t  lexed;                 /* its bytes are the text's own: read through the lexer's spans */
	uint8_t  oo;                    /* an oo body: method / constructor / destructor are units */
	uint8_t  word;                  /* enum tcl_word being read */
	uint8_t  at_cmd;                /* the next word begins a command */
	uint64_t limit;                 /* a frame inside a braced STRING span of the text: it ends there at the latest */
	uint64_t word_start, bd;        /* TW_BRACE: braces open inside it */
	struct tcl_cmd cmd;
};

struct tcl_walk {
	const struct kgenome_script_text *t;
	struct kgenome_fntab_list *l;
	struct tcl_frame *f;
	uint32_t nf, cap;
	int nomem;
};

static int tcl_blank(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\v' || c == '\f';
}

static int tcl_eol(uint8_t c)
{
	return c == '\n' || c == '\r';
}

/* The length of a backslash and the line break after it at `i` ("\\\n", "\\\r\n", "\\\r"), 0 when it is not one. */
static uint64_t tcl_cont(const struct kgenome_script_text *t, uint64_t i)
{
	const uint8_t *p = t->p;

	if (p[i] != '\\' || i + 1u >= t->n || !tcl_eol(p[i + 1u]))
		return 0;
	return (p[i + 1u] == '\r' && i + 2u < t->n && p[i + 2u] == '\n') ? 3u : 2u;
}

static int tcl_is(const struct kgenome_script_text *t, uint64_t s, uint64_t e, const char *w)
{
	uint64_t len = strlen(w);

	return e - s == len && memcmp(t->p + s, w, len) == 0;
}

/* `w` or "::w". */
static int tcl_is_cmd(const struct kgenome_script_text *t, uint64_t s, uint64_t e, const char *w)
{
	return tcl_is(t, s, e, w) || (e - s > 2u && t->p[s] == ':' && t->p[s + 1u] == ':' && tcl_is(t, s + 2u, e, w));
}

static void tcl_emit(struct tcl_walk *w, const struct tcl_cmd *c, uint64_t end, uint16_t flags)
{
	struct kgenome_fntab_list *l = w->l;

	/* outermost only: a unit found in a script inside this one's words (a "[proc ...]" in its args) is this one's */
	while (l->n && l->v[l->n - 1u].off >= c->start)
		l->n--;
	if (!kgenome_script_emit(l, c->start, end, c->name_off, c->name_len, flags))
		w->nomem = 1;
}

static struct tcl_frame *tcl_push(struct tcl_walk *w, uint8_t kind, uint8_t lexed, uint8_t oo, uint64_t limit)
{
	struct tcl_frame *f;

	if (w->nf == w->cap) {
		uint32_t cap = w->cap ? w->cap * 2u : 16u;
		struct tcl_frame *v = cap > w->cap ? realloc(w->f, (size_t)cap * sizeof *v) : NULL;

		if (!v) {
			w->nomem = 1;
			return NULL;
		}
		w->f = v;
		w->cap = cap;
	}
	f = &w->f[w->nf++];
	memset(f, 0, sizeof *f);
	f->kind = kind;
	f->lexed = lexed;
	f->oo = oo;
	f->at_cmd = 1;
	f->limit = limit;
	return f;
}

/* A word begins at `i` in `f`. */
static void tcl_word_begin(struct tcl_frame *f, uint64_t i, uint8_t kind)
{
	if (f->at_cmd) {
		memset(&f->cmd, 0, sizeof f->cmd);
		f->cmd.start = i;
		f->at_cmd = 0;
	}
	f->word = kind;
	f->word_start = i;
	f->bd = 0;
}

/* Is the word that begins now (index nword + 1) a script of the command being read. */
static int tcl_is_script(const struct tcl_frame *f)
{
	const struct tcl_cmd *c = &f->cmd;

	return !f->at_cmd && c->kind >= TC_NS && c->script_from && c->nword + 1u >= c->script_from;
}

/* The first word of a command, [s, e): what the command is. */
static void tcl_cmd_first(const struct kgenome_script_text *t, struct tcl_frame *f, uint64_t s, uint64_t e)
{
	struct tcl_cmd *c = &f->cmd;

	if (tcl_is_cmd(t, s, e, "proc") || (f->oo && tcl_is(t, s, e, "method"))) {
		c->kind = TC_PROC;
		c->body_at = 4u;
	} else if (f->oo && (tcl_is(t, s, e, "constructor") || tcl_is(t, s, e, "destructor"))) {
		c->kind = TC_PROC;
		c->body_at = tcl_is(t, s, e, "constructor") ? 3u : 2u;
		c->name_off = s;
		c->name_len = e - s;
	} else if (tcl_is_cmd(t, s, e, "namespace")) {
		c->kind = TC_NS;
	} else if (tcl_is_cmd(t, s, e, "oo::class")) {
		c->kind = TC_OOCLASS;
	} else if (tcl_is_cmd(t, s, e, "oo::define")) {
		c->kind = TC_OODEF;
		c->script_from = 3u;
		c->script_oo = 1;
	} else if (tcl_is(t, s, e, "if") || tcl_is(t, s, e, "catch") || tcl_is(t, s, e, "eval")) {
		c->kind = TC_CONT;
		c->script_from = 2u;
	}
}

/* The word [s, e) of `f` ended. */
static void tcl_word_end(struct tcl_walk *w, struct tcl_frame *f, uint64_t e)
{
	const struct kgenome_script_text *t = w->t;
	struct tcl_cmd *c = &f->cmd;
	uint64_t s = f->word_start;
	uint32_t k = ++c->nword;

	f->word = TW_NONE;
	if (k == 1u) {
		tcl_cmd_first(t, f, s, e);
		return;
	}
	switch (c->kind) {
	case TC_PROC:
		if (k == c->body_at - 2u && !c->name_len) {
			int wrapped = e - s >= 2u && ((t->p[s] == '{' && t->p[e - 1u] == '}') || (t->p[s] == '"' && t->p[e - 1u] == '"'));

			c->name_off = s + (wrapped ? 1u : 0u);
			c->name_len = e - s - (wrapped ? 2u : 0u);
		}
		if (k == c->body_at) {
			tcl_emit(w, c, e, 0);
			c->kind = TC_NONE;
		}
		break;
	case TC_NS:
		if (k == 2u && tcl_is(t, s, e, "eval"))
			c->script_from = 4u;
		else if (k == 2u)
			c->kind = TC_NONE;
		break;
	case TC_OOCLASS:
		if (k == 2u && tcl_is(t, s, e, "create")) {
			c->script_from = 4u;
			c->script_oo = 1;
		} else if (k == 2u) {
			c->kind = TC_NONE;
		}
		break;
	case TC_OODEF:
		/* "oo::define C method name args body": the member is the command, from "oo::define" */
		if (k == 3u && tcl_is(t, s, e, "method")) {
			c->kind = TC_PROC;
			c->body_at = 6u;
		} else if (k == 3u && (tcl_is(t, s, e, "constructor") || tcl_is(t, s, e, "destructor"))) {
			c->kind = TC_PROC;
			c->body_at = tcl_is(t, s, e, "constructor") ? 5u : 4u;
			c->name_off = s;
			c->name_len = e - s;
		}
		break;
	default:
		break;
	}
}

/* The command of `f` ended (a line break, ";", or the end of its script): a proc whose body never came defines nothing - the
 * next word begins a new command (tcl_word_begin clears it) and the end of the text reads only a command still in hand. */
static void tcl_cmd_end(struct tcl_frame *f)
{
	f->at_cmd = 1;
}

/* The top frame's script ends at `e` (exclusive: the "]" or "}" that closes it is at e - 1): its word and command end, the frame
 * is popped, and the parent's word goes on (a bracket) or ends (a braced script). */
static void tcl_pop(struct tcl_walk *w, uint64_t at, uint64_t e)
{
	struct tcl_frame *f = &w->f[w->nf - 1u], *pa;
	uint8_t kind = f->kind;

	if (f->word != TW_NONE)
		tcl_word_end(w, f, at);
	tcl_cmd_end(f);
	w->nf--;
	pa = &w->f[w->nf - 1u];
	if (kind == TF_BRACE)
		tcl_word_end(w, pa, e);
}

/* A byte inside a braced word that is being skipped. Answers where the walk goes on. */
static uint64_t tcl_in_brace(struct tcl_walk *w, struct tcl_frame *f, uint64_t i)
{
	const uint8_t *p = w->t->p;

	if (p[i] == '\\')
		return i + 2u > w->t->n ? w->t->n : i + 2u;
	if (p[i] == '{') {
		f->bd++;
	} else if (p[i] == '}') {
		if (!f->bd) {
			tcl_word_end(w, f, i + 1u);
			return i + 1u;
		}
		f->bd--;
	}
	return i + 1u;
}

/* A byte inside a quoted word read structurally. */
static uint64_t tcl_in_quote(struct tcl_walk *w, struct tcl_frame *f, uint64_t i)
{
	const uint8_t *p = w->t->p;

	if (p[i] == '\\')
		return i + 2u > w->t->n ? w->t->n : i + 2u;
	if (p[i] == '"')
		tcl_word_end(w, f, i + 1u);
	else if (p[i] == '[')
		(void)tcl_push(w, TF_BRACKET, 0, 0, f->limit);
	return i + 1u;
}

/* A byte of code (not a span of the lexer's) where no braced or quoted word is being read: separators, the start of a word, a bare
 * word's bytes. Answers where the walk goes on. */
static uint64_t tcl_in_code(struct tcl_walk *w, uint64_t i)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	struct tcl_frame *f = &w->f[w->nf - 1u];
	uint64_t n = t->n, k = 0;
	uint8_t c = p[i];

	if (tcl_eol(c) || c == ';') {
		if (f->word != TW_NONE)
			tcl_word_end(w, f, i);
		tcl_cmd_end(f);
		return i + 1u;
	}
	if ((f->kind == TF_BRACKET && c == ']') || (f->kind == TF_BRACE && c == '}')) {
		tcl_pop(w, i, i + 1u);
		return i + 1u;
	}
	if (tcl_blank(c) || (k = tcl_cont(t, i)) != 0) {
		if (f->word != TW_NONE)
			tcl_word_end(w, f, i);
		return tcl_blank(c) ? i + 1u : i + k;
	}
	if (f->word == TW_NONE) {
		if (f->at_cmd && c == '#' && !f->lexed) {
			while (i < n && !tcl_eol(p[i]))
				i += (p[i] == '\\' && i + 1u < n) ? 2u : 1u;
			return i > n ? n : i;
		}
		if (c == '{' && !f->lexed) {
			if (tcl_is_script(f)) {
				uint8_t oo = f->cmd.script_oo;

				tcl_word_begin(f, i, TW_SCRIPT);
				(void)tcl_push(w, TF_BRACE, 0, oo, f->limit);
			} else {
				tcl_word_begin(f, i, TW_BRACE);
			}
			return i + 1u;
		}
		if (c == '"' && !f->lexed) {
			tcl_word_begin(f, i, TW_QUOTE);
			return i + 1u;
		}
		tcl_word_begin(f, i, TW_BARE);
	}
	if (c == '\\')
		return i + 2u > n ? n : i + 2u;
	if (c == '[')
		(void)tcl_push(w, TF_BRACKET, f->lexed, 0, f->limit);
	return i + 1u;
}

/* A span of the lexer's (STRING or COMMENT) in a frame of the text's own bytes, [i, r). */
static uint64_t tcl_in_span(struct tcl_walk *w, uint64_t i, uint64_t r)
{
	const struct kgenome_script_text *t = w->t;
	struct tcl_frame *f = &w->f[w->nf - 1u];

	if (t->kind[i] == KGENOME_TEXTUAL_COMMENT)
		return r;
	if (f->word == TW_NONE) {
		if (t->p[i] == '{' && tcl_is_script(f)) {
			uint8_t oo = f->cmd.script_oo;

			tcl_word_begin(f, i, TW_SCRIPT);
			/* the script is read inside the span: it ends at its closing brace, at the span's end at the latest */
			(void)tcl_push(w, TF_BRACE, 0, oo, r);
			return i + 1u;
		}
		tcl_word_begin(f, i, TW_BARE);
	}
	return r;
}

/*
 * Was the span of the lexer's that begins at `s` and runs to the end of the text closed: a braced word whose braces balance (a
 * backslash escapes one), or a quoted word whose last byte is its unescaped quote. Read once, at the end of the text.
 */
static int tcl_span_closed(const struct kgenome_script_text *t, uint64_t s)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, i, d = 0;

	if (p[s] == '"')
		return n - s >= 2u && p[n - 1u] == '"' && p[n - 2u] != '\\';
	if (p[s] != '{')
		return 1;
	for (i = s; i < n; i++) {
		if (p[i] == '\\')
			i++;
		else if (p[i] == '{')
			d++;
		else if (p[i] == '}' && d && !--d)
			return i + 1u == n;
	}
	return 0;
}

/*
 * The text ended. A bare word in hand ends with it (a word of the text's own that is a closed span too); a braced or quoted word
 * that never closed leaves its command open. Then a proc whose body word had not ended is OPEN; only the outermost is a unit.
 */
static void tcl_end(struct tcl_walk *w)
{
	const struct kgenome_script_text *t = w->t;
	uint32_t k = w->nf;

	while (k-- && !w->nomem) {
		struct tcl_frame *f = &w->f[k];

		if (f->word != TW_BARE || (f->lexed && t->kind[f->word_start] != KGENOME_TEXTUAL_CODE &&
					   !tcl_span_closed(t, f->word_start)))
			break;
		tcl_word_end(w, f, t->n);
		if (k)
			break;          /* the frame below is reading this script as its word: that word is open */
	}
	for (k = 0; k < w->nf && !w->nomem; k++) {
		const struct tcl_cmd *c = &w->f[k].cmd;

		if (!w->f[k].at_cmd && c->kind == TC_PROC) {
			tcl_emit(w, c, t->n, KGENOME_FN_F_END_OPEN);
			return;
		}
	}
}

int kgenome_script_funcs_tcl(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, i = 0;
	struct tcl_walk w;

	memset(&w, 0, sizeof w);
	w.t = t;
	w.l = l;
	if (!tcl_push(&w, TF_TEXT, 1, 0, n))
		return 0;
	if (n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu)
		i = 3u;
	while (i < n && !w.nomem) {
		struct tcl_frame *f = &w.f[w.nf - 1u];

		if (i >= f->limit && w.nf > 1u) {
			/* a script read inside a braced span of the text ends with the span */
			tcl_pop(&w, i, i);
			continue;
		}
		if (f->lexed && t->kind[i] != KGENOME_TEXTUAL_CODE) {
			uint64_t r = i;

			while (r < n && t->kind[r] == t->kind[i])
				r++;
			i = tcl_in_span(&w, i, r);
		} else if (f->word == TW_BRACE) {
			i = tcl_in_brace(&w, f, i);
		} else if (f->word == TW_QUOTE) {
			i = tcl_in_quote(&w, f, i);
		} else {
			i = tcl_in_code(&w, i);
		}
	}
	if (!w.nomem)
		tcl_end(&w);
	free(w.f);
	return !w.nomem;
}
