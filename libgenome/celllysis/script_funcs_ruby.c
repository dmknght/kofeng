/*
 * script_funcs_ruby.c - the functions of a RUBY text (script_private.h, kgenome_script_strategy).
 *
 * THE SPECIFICATION READ (the Ruby 3.3 grammar, parse.y, and its lexer's states; the same lexer states textual/ruby/ruby_lex.c names):
 *   - A METHOD is "def" NAME [PARAMS] BODY "end". NAME is an identifier (with "?", "!" or a setter's "=" glued to it), an operator
 *     ("+", "[]", "<=>", ...), or a singleton "RECV.name" / "RECV::name" (the entry's name is the whole "self.name"). PARAMS are in
 *     brackets or, without them, the rest of the line. A keyword after "def" is a NAME ("def end", "def if").
 *   - AN ENDLESS METHOD (Ruby 3.0) is "def NAME[(PARAMS)] = EXPR": it has no "end" and ends with its statement - at a line break
 *     outside brackets that does not follow a binary operator or a backslash, or at ";" - once every block opened in EXPR is closed.
 *     "==", "=~" and "=>" after the header are not that "=".
 *   - "end" CLOSES every one of: class, module, def, begin, case, for, if / unless / while / until when they begin an expression, and
 *     "do". "while x do", "until x do" and "for i in y do" are ONE block: their "do" opens nothing (the loop's do is counted once,
 *     cleared at the end of the loop's line). The MODIFIER forms "x if y", "x while y" are not blocks: the lexer state decides it
 *     (parse.y: keyword_if is a modifier unless the state is EXPR_BEG, i.e. an operand is expected). Here: a modifier follows a value
 *     (a name, a number, a literal, ")" "]" "}", "end", "self" ...) or one of return / break / next / yield / super (EXPR_MID and
 *     EXPR_ARG); a block keyword follows the start of a statement, an operator, an opening bracket, "," "|" or a keyword that takes
 *     an operand (then, else, do, and, or, not, ...). "{ }" blocks do not use "end".
 *   - A WORD IS NOT A KEYWORD after "." "&." "::" (a method name: "x.end", "a&.class", "Foo::begin"), after ":" (a symbol ":end"),
 *     "@" or "$" (a variable), when a ":" follows it (a label "end: 1"), after alias / undef (method names), and as the id of a
 *     heredoc ("<<end", "<<-if": the operator is code, its body a STRING).
 *   - Strings, heredoc bodies, %-literals, regular expressions, "=begin" blocks, comments and the data after "__END__" are the lexer's
 *     STRING and COMMENT spans: never read for a keyword.
 *   - A VISIBILITY CALL in front of the def on its statement ("private def x", "protected", "public", "module_function",
 *     "private_class_method", "public_class_method") belongs to the declaration: the entry starts at the first of them.
 *   - Methods inside class / module bodies are units (a class is not a function); a def inside an open def is the outer's.
 *   - OPEN (KGENOME_FN_F_END_OPEN, run to the end of the text): the text ended before the "end" that closes the def, inside its header's
 *     brackets, or inside a block opened in an endless def's expression.
 *
 * ONE PASS over the text: a block counter, a bracket counter and the state of the previous token, no stack. The cost is linear:
 * every byte is looked at a bounded number of times (the blanks after a ")" that closes a def's header are read twice, to see
 * whether "=" follows).
 *
 * NOT MEASURED on real text: no .rb file in /mnt/games/normtest/fix_island/corpus and no ruby on this machine (2026-11-14); the
 * tests are the only evidence.
 *
 * LIMITS, named: a def nested in another def's open header brackets ("def f(a = def g(b) = 1)") replaces the pending header, so the
 * first one is read as a def with an "end"; a local VARIABLE followed by a modifier is read as a method call (the same reading - both
 * are a value); "?x" character literals are recognised only after an operand position; a heredoc whose id is not glued to "<<" is
 * the lexer's question, not this file's.
 */

#include "script_private.h"

#include <textual/textual.h>

enum rb_prev {
	RB_BEG,         /* an operand is expected: a block keyword here opens */
	RB_VAL,         /* a value just ended: an "if" here is a modifier */
	RB_MID,         /* after return / break / next / yield / super: a modifier follows (EXPR_MID, EXPR_ARG) */
	RB_DOT          /* after "." "&." "::": the next word is a method name */
};

struct rb_walk {
	const struct kgenome_script_text *t;
	struct kgenome_fntab_list *l;
	uint64_t depth, paren, loopdo;
	uint64_t last_end;              /* past the last byte of code or string read (not blank, not comment) */
	uint8_t  lastc, lastc2;         /* that byte and the one before it, for a line that ends in an operator */
	enum rb_prev prev;
	int      at_stmt;               /* the next token begins a statement */
	int      chain;                 /* visibility words since the statement began */
	uint64_t chain_off;
	uint32_t skip_names;            /* alias / undef: names that follow */
	uint64_t heredoc_id;            /* where a heredoc's id begins (not a keyword); n when none */
	int      hdr;                   /* a def's "(" has not closed */
	int      hdr_is_fn;             /* and that def is the open function */
	uint64_t hdr_paren;             /* the bracket level outside it */
	int      on, endless;           /* the open (outermost) function */
	uint64_t off, name_off, name_len;
	uint64_t fdepth;                /* a def: the block level its "end" closes */
	uint64_t base;                  /* an endless def: the block level its statement ends at */
	int      nomem;
};

static int rb_name_start(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80u;
}

static int rb_name_byte(uint8_t c)
{
	return rb_name_start(c) || (c >= '0' && c <= '9');
}

static int rb_blank(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
}

static uint64_t rb_ident_end(const struct kgenome_script_text *t, uint64_t i)
{
	while (i < t->n && t->code[i] && rb_name_byte(t->p[i]))
		i++;
	return i;
}

/* A "?" or "!" glued to a name ends it, unless "=" follows ("a!=b"). */
static uint64_t rb_suffix(const struct kgenome_script_text *t, uint64_t e)
{
	const uint8_t *p = t->p;

	return e < t->n && t->code[e] && (p[e] == '?' || p[e] == '!') && !(e + 1u < t->n && p[e + 1u] == '=') ? e + 1u : e;
}

/* Is the "=" at `m` an assignment's (not "==", "=~", "=>"). */
static int rb_assign_at(const struct kgenome_script_text *t, uint64_t m)
{
	const uint8_t *p = t->p;

	return m < t->n && t->code[m] && p[m] == '=' &&
	       !(m + 1u < t->n && (p[m + 1u] == '=' || p[m + 1u] == '~' || p[m + 1u] == '>'));
}

static uint64_t rb_blanks(const struct kgenome_script_text *t, uint64_t i)
{
	while (i < t->n && t->code[i] && (t->p[i] == ' ' || t->p[i] == '\t'))
		i++;
	return i;
}

/* The operator method name at `i` (longest first), its length or 0. */
static uint64_t rb_op_name(const struct kgenome_script_text *t, uint64_t i)
{
	static const char *const op[] = {
		"[]=", "<=>", "===", "[]", "**", "+@", "-@", "!@", "~@", "==", "=~", "!=", "!~", "<<", ">>", "<=", ">=",
		"+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">", "`",
	};
	uint64_t k;

	for (k = 0; k < sizeof op / sizeof op[0]; k++) {
		uint64_t len = strlen(op[k]);

		if (t->n - i >= len && t->code[i] && memcmp(t->p + i, op[k], len) == 0)
			return len;
	}
	return 0;
}

static void rb_token(struct rb_walk *w, uint64_t end)
{
	w->lastc2 = end >= 2u ? w->t->p[end - 2u] : 0u;
	w->lastc = w->t->p[end - 1u];
	w->last_end = end;
	w->at_stmt = 0;
}

static void rb_emit(struct rb_walk *w, uint64_t end, uint16_t flags)
{
	w->on = 0;
	if (!kgenome_script_emit(w->l, w->off, end, w->name_off, w->name_len, flags))
		w->nomem = 1;
}

/* The end of a statement (a line break that does not continue it, or ";"): an endless def back at its level ends here. */
static void rb_stmt_end(struct rb_walk *w)
{
	if (w->on && w->endless && !w->hdr && w->depth == w->base)
		rb_emit(w, w->last_end, 0);
	w->loopdo = 0;
	w->prev = RB_BEG;
	w->at_stmt = 1;
	w->chain = 0;
}

/* A line break outside brackets: the statement goes on after a binary operator, "," "." or an opening bracket. */
static void rb_newline(struct rb_walk *w)
{
	uint8_t c = w->lastc;

	if (w->paren)
		return;
	if (w->last_end && w->prev != RB_VAL && w->prev != RB_MID &&
	    ((c && strchr("+-*/%^<>=,.(&", c)) || (c == '|' && w->lastc2 == '|')))
		return;
	rb_stmt_end(w);
}

/* "def" at [s, e): the header. Answers where the walk goes on. */
static uint64_t rb_def(struct rb_walk *w, uint64_t s, uint64_t e)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	uint64_t k = rb_blanks(t, e), j = k, m, start = w->chain ? w->chain_off : s;
	int endless = 0;

	if (k < t->n && t->code[k] && rb_name_start(p[k])) {
		j = rb_ident_end(t, k);
		if (j + 1u < t->n && t->code[j] && ((p[j] == '.' && p[j + 1u] != '.') || (p[j] == ':' && p[j + 1u] == ':'))) {
			j += p[j] == '.' ? 1u : 2u;     /* a receiver: the method's name follows */
			if (j < t->n && t->code[j] && rb_name_start(p[j]))
				j = rb_suffix(t, rb_ident_end(t, j));
			else if (j < t->n)
				j += rb_op_name(t, j);
		} else {
			j = rb_suffix(t, j);
		}
		if (j < t->n && p[j - 1u] != '?' && p[j - 1u] != '!' && rb_assign_at(t, j) &&
		    j + 1u < t->n && !rb_blank(p[j + 1u]))
			j++;                            /* a setter: "name=(v)" */
	} else if (k < t->n) {
		j = k + rb_op_name(t, k);
	}
	m = rb_blanks(t, j);
	w->prev = RB_BEG;
	w->at_stmt = 0;
	w->chain = 0;
	if (j > s)
		rb_token(w, j);
	if (rb_assign_at(t, m))
		endless = 1;
	if (!endless)
		w->depth++;
	if (!w->on) {
		w->on = 1;
		w->endless = endless;
		w->off = start;
		w->name_off = k;
		w->name_len = j - k;
		w->fdepth = w->depth;
		w->base = w->depth;
	}
	if (endless)
		return m + 1u;
	if (m < t->n && t->code[m] && p[m] == '(') {
		w->hdr = 1;
		w->hdr_is_fn = w->on && w->off == start && w->fdepth == w->depth;
		w->hdr_paren = w->paren;
		return m;
	}
	return j;
}

/* A ")" closed a def's header: "=" after it makes the def endless. Answers where the walk goes on. */
static uint64_t rb_hdr_close(struct rb_walk *w, uint64_t after)
{
	uint64_t m = rb_blanks(w->t, after);

	w->hdr = 0;
	if (!rb_assign_at(w->t, m))
		return after;
	if (w->depth)
		w->depth--;
	if (w->hdr_is_fn && w->on) {
		w->endless = 1;
		w->base = w->depth;
	}
	w->prev = RB_BEG;
	return m + 1u;
}

static int rb_is(const uint8_t *p, uint64_t s, uint64_t e, const char *kw)
{
	uint64_t len = strlen(kw);

	return e - s == len && memcmp(p + s, kw, len) == 0;
}

/* The keyword (or name) at [s, e). */
static uint64_t rb_keyword(struct rb_walk *w, uint64_t s, uint64_t e)
{
	const uint8_t *p = w->t->p;
	uint64_t beg = w->prev == RB_BEG ? 1u : 0u;

	if (rb_is(p, s, e, "def"))
		return rb_def(w, s, e);
	rb_token(w, e);
	if (rb_is(p, s, e, "end")) {
		if (w->depth)
			w->depth--;
		if (w->on && !w->endless && w->depth < w->fdepth)
			rb_emit(w, e, 0);
		w->prev = RB_VAL;
	} else if (rb_is(p, s, e, "class") || rb_is(p, s, e, "module") || rb_is(p, s, e, "begin") ||
		   rb_is(p, s, e, "case")) {
		w->depth++;
		w->prev = RB_BEG;
	} else if (rb_is(p, s, e, "if") || rb_is(p, s, e, "unless")) {
		w->depth += beg;
		w->prev = RB_BEG;
	} else if (rb_is(p, s, e, "while") || rb_is(p, s, e, "until")) {
		w->depth += beg;
		w->loopdo += beg;
		w->prev = RB_BEG;
	} else if (rb_is(p, s, e, "for")) {
		w->depth++;
		w->loopdo++;
		w->prev = RB_BEG;
	} else if (rb_is(p, s, e, "do")) {
		if (w->loopdo)
			w->loopdo--;
		else
			w->depth++;
		w->prev = RB_BEG;
	} else if (rb_is(p, s, e, "then") || rb_is(p, s, e, "else") || rb_is(p, s, e, "elsif") || rb_is(p, s, e, "when") ||
		   rb_is(p, s, e, "in") || rb_is(p, s, e, "and") || rb_is(p, s, e, "or") || rb_is(p, s, e, "not") ||
		   rb_is(p, s, e, "ensure") || rb_is(p, s, e, "rescue")) {
		w->prev = RB_BEG;
	} else if (rb_is(p, s, e, "return") || rb_is(p, s, e, "break") || rb_is(p, s, e, "next") || rb_is(p, s, e, "yield") ||
		   rb_is(p, s, e, "super") || rb_is(p, s, e, "defined?")) {
		w->prev = RB_MID;
	} else if (rb_is(p, s, e, "alias") || rb_is(p, s, e, "undef")) {
		w->skip_names = rb_is(p, s, e, "alias") ? 2u : 1u;
		w->prev = RB_BEG;
	} else {
		w->prev = RB_VAL;
	}
	return e;
}

/* Is [s, e) a visibility call that may stand in front of a def. */
static int rb_visibility(const uint8_t *p, uint64_t s, uint64_t e)
{
	return rb_is(p, s, e, "private") || rb_is(p, s, e, "protected") || rb_is(p, s, e, "public") ||
	       rb_is(p, s, e, "module_function") || rb_is(p, s, e, "private_class_method") ||
	       rb_is(p, s, e, "public_class_method");
}

/* A word at `s`. */
static uint64_t rb_word(struct rb_walk *w, uint64_t s)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	uint64_t e = rb_suffix(t, rb_ident_end(t, s));
	int stmt = w->at_stmt;

	if (e < t->n && t->code[e] && p[e] == ':' && !(e + 1u < t->n && p[e + 1u] == ':') && w->prev != RB_DOT) {
		rb_token(w, e + 1u);                /* a label: "end: 1" */
		w->prev = RB_BEG;
		w->chain = 0;
		return e + 1u;
	}
	if (w->prev == RB_DOT || s == w->heredoc_id || w->skip_names) {
		if (w->skip_names && w->prev != RB_DOT)
			w->skip_names--;
		rb_token(w, e);
		w->prev = RB_VAL;
		w->chain = 0;
		return e;
	}
	if (rb_visibility(p, s, e) && (stmt || w->chain)) {
		if (!w->chain)
			w->chain_off = s;
		w->chain = 1;
		rb_token(w, e);
		w->prev = RB_VAL;
		return e;
	}
	if (!rb_is(p, s, e, "def"))
		w->chain = 0;
	return rb_keyword(w, s, e);
}

/* A byte of code that is not a name, a blank or a line break, at `i`. */
static uint64_t rb_punct(struct rb_walk *w, uint64_t i)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	uint64_t n = t->n, j = i + 1u;
	uint8_t c = p[i], d = j < n && t->code[j] ? p[j] : 0u;
	enum rb_prev before = w->prev;

	w->chain = 0;
	w->prev = RB_BEG;
	if (c == ';' && !w->paren) {
		rb_stmt_end(w);                 /* ends a statement the way a line break does, with nothing to continue */
		return j;
	}
	if (c == '(' || c == '[' || c == '{') {
		w->paren++;
	} else if (c == ')' || c == ']' || c == '}') {
		if (w->paren)
			w->paren--;
		w->prev = RB_VAL;
		if (c == ')' && w->hdr && w->paren == w->hdr_paren) {
			rb_token(w, j);
			return rb_hdr_close(w, j);
		}
	} else if (c == '.' && d == '.') {
		j = i + 2u + (i + 2u < n && p[i + 2u] == '.');
	} else if (c == '.' || (c == '&' && d == '.') || (c == ':' && d == ':')) {
		j = i + 1u + (c != '.');
		w->prev = RB_DOT;
	} else if (c == ':' && rb_name_start(d)) {
		j = rb_suffix(t, rb_ident_end(t, j));   /* a symbol */
		w->prev = RB_VAL;
	} else if (c == '@' || c == '$') {
		while (j < n && t->code[j] && p[j] == '@')
			j++;
		j = rb_ident_end(t, j);
		if (j == i + 1u && c == '$' && j < n)
			j++;                            /* $! $0 $; ... */
		w->prev = RB_VAL;
	} else if (c == '?' && before == RB_BEG && d && !rb_blank(d) && d != '\n') {
		j = i + 2u + (d == '\\' && i + 2u < n);  /* a character literal "?a", "?\n": a value */
		w->prev = RB_VAL;
	} else if (c == '<' && d == '<') {
		j = i + 2u;
		if (j < n && t->code[j] && (p[j] == '~' || p[j] == '-'))
			j++;
		if (j < n && t->code[j] && rb_name_start(p[j]))
			w->heredoc_id = j;
	}
	rb_token(w, j);
	return j;
}

int kgenome_script_funcs_ruby(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, i = 0;
	struct rb_walk w;

	memset(&w, 0, sizeof w);
	w.t = t;
	w.l = l;
	w.prev = RB_BEG;
	w.at_stmt = 1;
	w.heredoc_id = n;
	if (n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu)
		i = 3u;
	while (i < n && !w.nomem) {
		uint8_t c = p[i], k = t->kind[i];

		if (k != KGENOME_TEXTUAL_CODE) {
			uint64_t r = i;

			while (r < n && t->kind[r] == k)
				r++;
			if (k != KGENOME_TEXTUAL_COMMENT) {
				rb_token(&w, r);
				w.prev = RB_VAL;
				w.chain = 0;
			}
			i = r;
		} else if (c == '\n') {
			rb_newline(&w);
			i++;
		} else if (rb_blank(c)) {
			i++;
		} else if (c == '\\' && i + 1u < n && (p[i + 1u] == '\n' || (p[i + 1u] == '\r' && i + 2u < n && p[i + 2u] == '\n'))) {
			i += p[i + 1u] == '\n' ? 2u : 3u;       /* a continued line */
		} else if (rb_name_start(c)) {
			i = rb_word(&w, i);
		} else if (c >= '0' && c <= '9') {
			i = rb_ident_end(t, i);
			rb_token(&w, i);
			w.prev = RB_VAL;
			w.chain = 0;
		} else {
			i = rb_punct(&w, i);
		}
	}
	if (w.nomem)
		return 0;
	if (w.on) {
		if (w.endless && !w.hdr && w.depth == w.base)
			rb_emit(&w, w.last_end, 0);
		else
			rb_emit(&w, n, KGENOME_FN_F_END_OPEN);
	}
	return !w.nomem;
}
