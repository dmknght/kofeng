#define _GNU_SOURCE
/*
 * normalizer_script - what the lib's constants path builds out of a script's own literals (the evaluator of the TEXT route, kgenome_diag_scan_text
 * with on_const, and the writer kgenome_textual_subst), against a reference interpreter that is handed the PROGRAM and not its text.
 *
 * THIS REPLACED THE TESTS OF script_fold.c. That folder read php, perl, powershell and tcl (the rows with a variable sigil), with a str_replace those
 * languages do not have, and handed back the ONE largest value; the engine now asks the lib for every language its evaluator serves and writes each
 * computed right side where it was computed (objctx_script_consts.c). What the old tests pinned is ported here, and where the new path answers
 * differently the test says so at the case (marked DIFFERENCE, and listed in docs/textual_pipeline.txt): first definition wins -> the last one does
 * (php, which keeps no control flow); chr() and strrev() are read now; a name defined later is read; the languages that had no sigil are served.
 *
 * THE REFERENCE IS NOT A SECOND PARSER. A generated corpus starts as a list of statements - `name = term . term ...`, where a term is a literal,
 * a variable or (php) `str_replace(expr, expr, expr)` - and the expected answer is computed from that list by evaluating it, straight. Only
 * afterwards is the list written out as source in the language's own spelling (quote style, the escapes of every byte, the spacing and the junk between
 * statements chosen at random). So a mistake in reading the TEXT - a quote, an escape, a name, a nesting - shows as a difference from a value that
 * never went through any text. The answer is the LIST of values the path reports, in order, one per statement whose right side is more than one term.
 *
 *   differential   thousands of generated programs: php (`.`), javascript, python and powershell (`+`)
 *   property       the text written with those values has no computed right side left (a second run reports nothing)
 *   known answers  N literals joined (1..300), N variables, str_replace chains, escapes, the bounds (a value of 1 MiB exactly and one byte more, nesting)
 *   not constant   a request value, a decoder, an unterminated literal; numbers are not strings (js `1 + 2`), a name assigned twice is not one value
 *   regressions    each a way this path first read a statement that is not the statement the program has (found on real files; the cause is on the line)
 */

#include <sys/resource.h>

#include "normalizer_ref.h"
#include "normalizer_consts.h"
#include "../../libkofeng/kofcore/kofcore.h"

#if defined(__SANITIZE_ADDRESS__)
#define UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UNDER_ASAN 1
#endif
#endif
#ifndef UNDER_ASAN
#define UNDER_ASAN 0
#endif

#define EV_VMAX (1u << 20)      /* diag_text_eval.c: the most bytes one value holds */
#define EV_NEST 256u            /* the most expressions open inside one another */

/* ---- the program, as data -------------------------------------------------------------- */

struct bytes {
	uint8_t *p;
	size_t   n;
};

struct ex;

struct tm {
	int          kind;                      /* 0 literal, 1 variable, 2 str_replace */
	struct bytes lit;
	int          var;
	struct ex   *a, *b, *c;
};

struct ex {
	struct tm *t;
	unsigned   n;
};

#define NAMES 24u
static char name_of[NAMES][12];

static void names_init(void)
{
	unsigned i;

	for (i = 0; i < NAMES; i++)
		snprintf(name_of[i], sizeof name_of[i], "%s%u", i % 3u ? "v" : "Var_", i * 7u);
}

static void bytes_free(struct bytes *b)
{
	free(b->p);
	b->p = NULL;
	b->n = 0;
}

static void ex_free(struct ex *e);

static void tm_free(struct tm *t)
{
	bytes_free(&t->lit);
	if (t->kind == 2) {
		ex_free(t->a);
		ex_free(t->b);
		ex_free(t->c);
	}
}

static void ex_free(struct ex *e)
{
	unsigned i;

	if (!e)
		return;
	for (i = 0; i < e->n; i++)
		tm_free(&e->t[i]);
	free(e->t);
	free(e);
}

/* The languages the generator writes: how a literal is spelled and what joins. */
enum esc { ESC_PHP, ESC_C, ESC_PSH };

struct lg {
	const char *name;
	uint32_t    lang;
	char        join;
	uint8_t     sigil;          /* a variable is written with "$" */
	uint8_t     fn;             /* str_replace exists (php) */
	const char *head;
	const char *eos;            /* what ends a statement */
	enum esc    esc;
};

static const struct lg PHP = { "php", KGENOME_TEXTUAL_LANG_PHP, '.', 1, 1, "<?php\n", ";", ESC_PHP };
static const struct lg JS = { "js", KGENOME_TEXTUAL_LANG_JS, '+', 0, 0, "", ";", ESC_C };
static const struct lg PY = { "py", KGENOME_TEXTUAL_LANG_PY, '+', 0, 0, "", "", ESC_C };
static const struct lg PSH = { "psh", KGENOME_TEXTUAL_LANG_PSH, '+', 1, 0, "", "", ESC_PSH };

static struct bytes random_literal(struct nrng *r, const struct lg *g, unsigned max)
{
	struct bytes b;
	unsigned i, n = nr_below(r, max + 1u);

	b.p = malloc(n + 1u);
	b.n = n;
	for (i = 0; i < n; i++) {
		uint32_t k = nr_below(r, 10u);

		if (k < 6u)
			b.p[i] = (uint8_t)"abcdeabcde fghij"[nr_below(r, 16u)];
		else if (k < 8u)
			b.p[i] = (uint8_t)"'\"\\\n\t.;(){}/*#<>=-"[nr_below(r, 17u)];
		else
			b.p[i] = (uint8_t)(1u + nr_below(r, g->esc == ESC_PHP ? 254u : 126u));
		if (b.p[i] == '$')
			b.p[i] = 'S';
	}
	return b;
}

static struct ex *random_ex(struct nrng *r, const struct lg *g, unsigned depth, const int *defined, unsigned n_defined);

static unsigned feat_var = 2, feat_repl = 1, feat_join = 1;

static void random_term(struct nrng *r, const struct lg *g, struct tm *t, unsigned depth, const int *defined, unsigned n_defined)
{
	uint32_t k = nr_below(r, 10u);

	memset(t, 0, sizeof *t);
	if (k < feat_var && n_defined) {
		t->kind = 1;
		t->var = defined[nr_below(r, n_defined)];
	} else if (k == 9u && feat_repl && g->fn && depth < 3u) {
		t->kind = 2;
		t->a = random_ex(r, g, depth + 1u, defined, n_defined);
		t->b = random_ex(r, g, depth + 1u, defined, n_defined);
		t->c = random_ex(r, g, depth + 1u, defined, n_defined);
	} else {
		t->lit = random_literal(r, g, 14u);
	}
}

static struct ex *random_ex(struct nrng *r, const struct lg *g, unsigned depth, const int *defined, unsigned n_defined)
{
	struct ex *e = calloc(1, sizeof *e);
	unsigned i;

	e->n = feat_join ? 1u + nr_below(r, depth ? 2u : 4u) : 1u;
	e->t = calloc(e->n, sizeof *e->t);
	for (i = 0; i < e->n; i++)
		random_term(r, g, &e->t[i], depth, defined, n_defined);
	return e;
}

/* ---- the reference interpreter ------------------------------------------------------ */

struct val {
	uint8_t *p;
	size_t   n;
	int      ok;
};

struct env {
	struct val v[NAMES];
};

static void val_free(struct val *v)
{
	free(v->p);
	v->p = NULL;
	v->n = 0;
	v->ok = 0;
}

static struct val val_of(const uint8_t *p, size_t n)
{
	struct val v;

	v.p = malloc(n + 1u);
	memcpy(v.p, p, n);
	v.n = n;
	v.ok = 1;
	return v;
}

static struct val ref_eval(const struct ex *e, const struct env *env);

/* One term; any term that cannot be evaluated makes the whole expression not constant (the evaluator takes all of it or none). */
static struct val ref_term(const struct tm *t, const struct env *env)
{
	struct val bad = { NULL, 0, 0 };

	if (t->kind == 0)
		return val_of(t->lit.p, t->lit.n);
	if (t->kind == 1) {
		const struct val *d = &env->v[t->var];

		return d->ok ? val_of(d->p, d->n) : bad;
	}
	{
		struct val a = ref_eval(t->a, env), b = ref_eval(t->b, env), c = ref_eval(t->c, env), o;
		size_t i, w = 0;

		if (!a.ok || !b.ok || !c.ok) {
			val_free(&a);
			val_free(&b);
			val_free(&c);
			return bad;
		}
		o.p = malloc(c.n * (b.n > a.n ? b.n : 1u) + b.n + c.n + 1u);
		if (!a.n) {                     /* php: a search of nothing leaves the subject as it is */
			memcpy(o.p, c.p, c.n);
			w = c.n;
		} else {
			for (i = 0; i < c.n;) {
				if (i + a.n <= c.n && !memcmp(c.p + i, a.p, a.n)) {
					memcpy(o.p + w, b.p, b.n);
					w += b.n;
					i += a.n;
				} else {
					o.p[w++] = c.p[i++];
				}
			}
		}
		o.n = w;
		o.ok = 1;
		val_free(&a);
		val_free(&b);
		val_free(&c);
		return o;
	}
}

static struct val ref_eval(const struct ex *e, const struct env *env)
{
	struct val acc = ref_term(&e->t[0], env);
	unsigned i;

	for (i = 1; acc.ok && i < e->n; i++) {
		struct val r = ref_term(&e->t[i], env);

		if (!r.ok) {
			val_free(&acc);
			val_free(&r);
			return acc;
		}
		acc.p = realloc(acc.p, acc.n + r.n + 1u);
		memcpy(acc.p + acc.n, r.p, r.n);
		acc.n += r.n;
		val_free(&r);
	}
	return acc;
}

/* ---- the source writer ------------------------------------------------------------------- */

struct src {
	uint8_t *p;
	size_t   n, cap;
};

static void src_put(struct src *s, const void *p, size_t n)
{
	if (s->n + n + 1u > s->cap) {
		s->cap = (s->n + n + 1u) * 2u;
		s->p = realloc(s->p, s->cap);
	}
	memcpy(s->p + s->n, p, n);
	s->n += n;
}

static void src_str(struct src *s, const char *z)
{
	src_put(s, z, strlen(z));
}

static void ws(struct src *s, struct nrng *r)
{
	static const char *const w[] = { "", "", " ", "  ", "\t", " \t " };

	src_str(s, w[nr_below(r, sizeof w / sizeof w[0])]);
}

/* One literal in quote `q`, each byte spelled one of the ways the language reads. */
static void write_literal(struct src *s, const struct lg *g, const struct bytes *b, char q, struct nrng *r)
{
	size_t i;
	char tmp[8];

	src_put(s, &q, 1u);
	for (i = 0; i < b->n; i++) {
		uint8_t c = b->p[i];
		uint32_t how = nr_below(r, 8u);
		const char *letter = c == '\n' ? "\\n" : c == '\r' ? "\\r" : c == '\t' ? "\\t" :
				     c == '\v' ? "\\v" : c == '\f' ? "\\f" : NULL;

		if (g->esc == ESC_PSH) {                        /* single quotes only: the quote is written twice */
			if (c == (uint8_t)q)
				src_put(s, &c, 1u);
			src_put(s, &c, 1u);
		} else if (g->esc == ESC_PHP && q == '\'') {    /* php's single quotes read two escapes and nothing else */
			if (c == (uint8_t)q || c == '\\')
				src_put(s, "\\", 1u);
			src_put(s, &c, 1u);
		} else if (c == (uint8_t)q || c == '\\' || c < 0x20 || c >= 0x7f || how < 2u) {
			if (letter && how & 1u) {
				src_str(s, letter);
			} else if ((c == (uint8_t)q || c == '\\') && how & 1u) {
				tmp[0] = '\\';
				tmp[1] = (char)c;
				src_put(s, tmp, 2u);
			} else if (how & 2u) {
				snprintf(tmp, sizeof tmp, "\\x%02x", c);
				src_str(s, tmp);
			} else {
				snprintf(tmp, sizeof tmp, "\\%03o", c);
				src_str(s, tmp);
			}
		} else {
			src_put(s, &c, 1u);
		}
	}
	src_put(s, &q, 1u);
}

static void write_ex(struct src *s, const struct lg *g, const struct ex *e, struct nrng *r);

static void write_term(struct src *s, const struct lg *g, const struct tm *t, struct nrng *r)
{
	char q = g->esc == ESC_PSH ? '\'' : nr_below(r, 2u) ? '"' : '\'';

	if (t->kind == 0) {
		write_literal(s, g, &t->lit, q, r);
	} else if (t->kind == 1) {
		if (g->sigil)
			src_str(s, "$");
		src_str(s, name_of[t->var]);
	} else {
		src_str(s, "str_replace(");
		ws(s, r);
		write_ex(s, g, t->a, r);
		ws(s, r);
		src_str(s, ",");
		ws(s, r);
		write_ex(s, g, t->b, r);
		ws(s, r);
		src_str(s, ",");
		ws(s, r);
		write_ex(s, g, t->c, r);
		ws(s, r);
		src_str(s, ")");
	}
}

static void write_ex(struct src *s, const struct lg *g, const struct ex *e, struct nrng *r)
{
	unsigned i;

	for (i = 0; i < e->n; i++) {
		if (i) {
			ws(s, r);
			src_put(s, &g->join, 1u);
			ws(s, r);
		}
		write_term(s, g, &e->t[i], r);
	}
}

/* Statements between statements that an assignment reader must step over. */
static void junk(struct src *s, const struct lg *g, struct nrng *r)
{
	static const char *const php[] = {
		"\n", "\n", "echo $v7;\n", "if ($v14 == 'x') { }\n", "\n\n", "$Var_0 == 1;\n", "  \n", "foo($v21, $v0);\n", "return;\n",
		"?>\n<html>\n<?php\n"
	};
	static const char *const js[] = {
		"\n", "\n", "foo(v7);\n", "\n\n", "  \n", "bar(v21, v0);\n", "// a comment\n"
	};
	static const char *const py[] = { "\n", "\n", "foo(v7)\n", "\n\n", "  \n", "# a comment\n" };
	static const char *const psh[] = { "\n", "\n", "Write-Host $v7\n", "\n\n", "  \n", "# a comment\n" };

	if (g == &PHP)
		src_str(s, php[nr_below(r, sizeof php / sizeof php[0])]);
	else if (g == &PY)
		src_str(s, py[nr_below(r, sizeof py / sizeof py[0])]);
	else if (g == &PSH)
		src_str(s, psh[nr_below(r, sizeof psh / sizeof psh[0])]);
	else
		src_str(s, js[nr_below(r, sizeof js / sizeof js[0])]);
}

/* ---- one generated program ---------------------------------------------------------------- */

struct prog {
	struct src  text;
	struct val *want;       /* the values the path must report, in order */
	unsigned    n_want, n_stmt;
};

static void prog_free(struct prog *g)
{
	unsigned i;

	free(g->text.p);
	for (i = 0; i < g->n_want; i++)
		val_free(&g->want[i]);
	free(g->want);
	memset(g, 0, sizeof *g);
}

/*
 * Generate, evaluate and write one program. Every statement has a name of its own (a name assigned twice is not one value to a language with no
 * control flow, and the path says so by not following it). A statement is REPORTED when its right side is more than one term, or a call: a single
 * literal or variable is not computed.
 */
static void make_program(struct nrng *r, const struct lg *g, struct prog *p)
{
	struct env env;
	int defined[NAMES];
	unsigned n_def = 0, i, ns = 2u + nr_below(r, 10u);

	memset(&env, 0, sizeof env);
	memset(p, 0, sizeof *p);
	p->want = calloc(NAMES, sizeof *p->want);
	src_str(&p->text, g->head);
	for (i = 0; i < ns && i < NAMES - 1u; i++) {
		struct ex *e = random_ex(r, g, 0, defined, n_def);
		struct val v = ref_eval(e, &env);
		int reported = e->n >= 2u || e->t[0].kind == 2;

		if (nr_below(r, 12u) == 0u) {
			/* a statement whose value is not constant: a name no one defined */
			ex_free(e);
			e = calloc(1, sizeof *e);
			e->n = 2;
			e->t = calloc(2, sizeof *e->t);
			e->t[0].kind = 1;
			e->t[0].var = (int)(NAMES - 1u);        /* never defined */
			e->t[1].lit = random_literal(r, g, 6u);
			val_free(&v);
			v = ref_eval(e, &env);
			reported = 0;
		}
		if (g->sigil)
			src_str(&p->text, "$");
		src_str(&p->text, name_of[i]);
		ws(&p->text, r);
		src_str(&p->text, "=");
		ws(&p->text, r);
		write_ex(&p->text, g, e, r);
		src_str(&p->text, g->eos);
		src_str(&p->text, "\n");
		junk(&p->text, g, r);
		if (v.ok) {
			if (reported)
				p->want[p->n_want++] = val_of(v.p, v.n);
			env.v[i] = v;
			defined[n_def++] = (int)i;
			v.p = NULL;
		}
		val_free(&v);
		ex_free(e);
	}
	p->n_stmt = i;
	for (i = 0; i < NAMES; i++)
		val_free(&env.v[i]);
}

/* ---- differential ---------------------------------------------------------------------------- */

static void differential(const struct lg *g, unsigned seeds, unsigned base)
{
	struct nrng r;
	unsigned seed, reported = 0, longest = 0;

	for (seed = 1; seed <= seeds; seed++) {
		struct prog p;
		struct cset s;
		unsigned i;
		int same;
		uint8_t *view = NULL;
		uint32_t vw;

		nr_seed(&r, base + seed);
		make_program(&r, g, &p);
		consts_of(g->lang, p.text.p, p.text.n, &s);
		same = s.n == p.n_want;
		for (i = 0; same && i < s.n; i++)
			same = s.c[i].n == p.want[i].n && !memcmp(s.c[i].v, p.want[i].p, p.want[i].n);
		NCKF(same, "seed %u (%s): reported %u values, want %u (first differing: %u)\n%.*s", seed, g->name, s.n, p.n_want, i,
		     (int)p.text.n, (char *)p.text.p);
		NCKF(s.st == KGENOME_OK, "seed %u (%s): status %d", seed, g->name, (int)s.st);
		/* the text with them written has none left */
		vw = consts_text(g->lang, p.text.p, p.text.n, &s, &view);
		if (s.n) {
			struct cset again;

			NCKF(vw != 0, "seed %u (%s): the values were not written\n%.*s", seed, g->name, (int)p.text.n, (char *)p.text.p);
			if (vw) {
				consts_of(g->lang, view, vw, &again);
				NCKF(again.n == 0u, "seed %u (%s): the written text still has %u computed right sides\n%.*s", seed, g->name, again.n,
				     (int)vw, (char *)view);
				cset_free(&again);
			}
		}
		free(view);
		reported += s.n != 0;
		for (i = 0; i < p.n_want; i++)
			if (p.want[i].n > longest)
				longest = (unsigned)p.want[i].n;
		cset_free(&s);
		prog_free(&p);
	}
	NCKF(reported > seeds / 2u || !feat_join, "%s generator reach: %u of %u built something", g->name, reported, seeds);
	NCKF(!feat_join || longest > 20u, "%s generator reach: longest %u", g->name, longest);
}

/* ---- known answers --------------------------------------------------------------------------- */

/* The values `src` reports in `lang`, compared with the NULL-ended list `want` (strings; a value with a NUL is not written this way). */
static int reports(uint32_t lang, const char *src, const char *const *want, struct cset *s)
{
	unsigned i, nw = 0;
	int ok;
	/* php is read from its tag: a text with none is markup */
	char *own = lang == KGENOME_TEXTUAL_LANG_PHP && strncmp(src, "<?", 2) ? malloc(strlen(src) + 8u) : NULL;

	if (own) {
		memcpy(own, "<?php ", 6u);
		strcpy(own + 6, src);
		src = own;
	}
	consts_of(lang, (const uint8_t *)src, strlen(src), s);
	free(own);
	while (want[nw])
		nw++;
	ok = s->n == nw;
	for (i = 0; ok && i < nw; i++)
		ok = s->c[i].n == strlen(want[i]) && !memcmp(s->c[i].v, want[i], s->c[i].n);
	return ok;
}

#define PHPL KGENOME_TEXTUAL_LANG_PHP

/* `want` is the whole list, in order; with none the path reports nothing (the macro's own NULL ends the list). */
#define REPORTS(lang, src, ...) do { \
	static const char *const w_[] = { __VA_ARGS__ __VA_OPT__(,) NULL }; \
	struct cset s_; \
	int ok_ = reports((lang), (src), w_, &s_); \
	NCKF(ok_, "[%s]: reported %u values, first [%.*s]", (src), s_.n, s_.n ? (int)s_.c[0].n : 0, s_.n ? (char *)s_.c[0].v : ""); \
	cset_free(&s_); \
} while (0)

static void known_answers(void)
{
	/* a join, a variable, str_replace, in the shape of a generator */
	REPORTS(PHPL, "$a='fun'; $b='ction x('; $c=str_replace('|','',$a.'|'.$b);", "function x(");
	REPORTS(PHPL, "$a = \"ab\" . \"cd\" . 'ef';", "abcdef");
	REPORTS(PHPL, "$a=\"x\";$b=$a.$a;$c=$b.$b.$a;", "xx", "xxxxx");
	REPORTS(PHPL, "$a=str_replace('a','bb','banana');", "bbbnbbnbb");
	REPORTS(PHPL, "$a=str_replace('ab','','ababab-ab');", "-");
	REPORTS(PHPL, "$a=str_replace('aa','b','aaaaa');", "bba");                       /* left to right, no overlap */
	REPORTS(PHPL, "$x=str_replace('1','2',str_replace('0','1','0101'));", "2222");
	/* a comparison is not an assignment */
	REPORTS(PHPL, "$a=='long literal value here'; $b='ok';");
	/* every escape the php reader knows, in dq: joined with a 'Z' so that the right side is computed (a single literal is the form's, not this path's).
	 * DIFFERENCE from the folder, which read "\X4b", dropped the backslash of an unknown escape ("\q" was q) and dropped a "\x" with no digit: php keeps all
	 * three as they are, and so does the value reader (tests/lib/genome/textual_value.c pins it). */
	REPORTS(PHPL, "$a=\"\\x41\\x42\\103\\x4a\\n\" . 'Z';", "ABCJ\nZ");
	REPORTS(PHPL, "$a='\\x70\\150' . 'Z';", "\\x70\\150Z");                        /* single quotes read two escapes */
	REPORTS(PHPL, "$a='it\\'s \\\\ done' . 'Z';", "it's \\ doneZ");
	REPORTS(PHPL, "$a=\"a\\tb\\vc\\fd\\re\" . 'Z';", "a\tb\vc\fd\reZ");
	REPORTS(PHPL, "$a=\"\\q\\z\" . 'Z';", "\\q\\zZ");                               /* DIFFERENCE: the folder said "qzZ" */
	REPORTS(PHPL, "$a=\"\\x4\" . 'Z';", "\x04Z");                                    /* one digit is a byte */
	REPORTS(PHPL, "$a=\"\\1018\" . 'Z';", "A8Z");                                    /* octal stops at three digits */
	REPORTS(PHPL, "$a=\"\\60\\4\" . 'Z';", "0\x04Z");
	/* spacing and sigils */
	REPORTS(PHPL, "$a=\t'x'\t.\t'y'\t;", "xy");
	REPORTS(PHPL, "   $a   =   'x'.'y' ;  ", "xy");
	REPORTS(PHPL, "$a_1='p'; $A1='q'; $r=$a_1.$A1.$a_1;", "pqp");
	/* an assignment whose value is empty is a constant too, now: the path writes it where it was computed */
	REPORTS(PHPL, "$a=''; $b=$a.'k';", "k");
	REPORTS(PHPL, "$a=str_replace('x','','xx'); $b='z';", "");
	/* DIFFERENCE: the folder kept the FIRST definition of a name ($a.'!' was "one!"); the evaluator keeps no control flow and a variable is its LAST
	 * assignment, for every use of it in the file */
	REPORTS(PHPL, "$a='one'; $a='two'; $b=$a.'!';", "two!");
	/* a join across lines, a comment, the close tag, a bracket, the end of the input */
	REPORTS(PHPL, "$a = 'ab' .\n    'cd';", "abcd");
	REPORTS(PHPL, "$a = 'ab'\n  . 'cd';", "abcd");
	REPORTS(PHPL, "$a = 'ab' . 'cd' ; // c\n", "abcd");
	REPORTS(PHPL, "<?php $a = 'ab' . 'cd' ?>", "abcd");
	REPORTS(PHPL, "f($a = 'ab' . 'cd')", "abcd");
	REPORTS(PHPL, "$a = 'ab' . 'cd'", "abcd");
	/* DIFFERENCE: functions the folder did not run */
	REPORTS(PHPL, "$a=chr(65).chr(66).chr(67);", "ABC");
	/* strrev is a decoder (the table says the form never rewrites a call of it): the decode hook shows what it makes, with the call kept, and this path
	 * leaves it alone, as it did */
	REPORTS(PHPL, "$a=strrev('cba') . 'Z';");
	/* DIFFERENCE: a name defined LATER is read (no control flow); the folder answered nothing for the first statement */
	REPORTS(PHPL, "$a=$b.'x'; $b='y';", "yx");
}

static void not_constant(void)
{
	/* what the path does NOT do: it follows no value from outside the file, and a decoder is the decode hook's, not this path's */
	REPORTS(PHPL, "$a=$_GET['p'] . 'x';");
	REPORTS(PHPL, "$a=base64_decode('QUJD') . 'x';");
	REPORTS(PHPL, "$x=$_GET['p']; $a = 'ab' . $x; $b = $a . 'cd';");
	/* `$v = $k[1]` is not $k, and nothing is joined on it */
	REPORTS(PHPL, "$k='abc'; $v = $k[1]; $w = $v . 'z';");
	/* an unterminated literal is not a constant */
	REPORTS(PHPL, "$a='abc' . 'def");
	REPORTS(PHPL, "$a=\"abc\\");
	/* a language whose newline ends the statement: it still does */
	REPORTS(KGENOME_TEXTUAL_LANG_PSH, "$a = 'ab'\n + 'cd'\n");
	/* a language with no join (tcl: two words are two words) */
	REPORTS(KGENOME_TEXTUAL_LANG_TCL, "set a \"ab\" \"cd\"\n");
}

/*
 * THE LANGUAGES THE FOLDER HAD NO SIGIL FOR are served now, each in its own spelling, and "+" is a join of two STRINGS and nothing else:
 * `1 + 2` is a sum in every one of them and the written literal would have said "12". And a variable is followed only where its value cannot depend on
 * the order the program runs in, which the evaluator does not know: a top-level name assigned exactly once.
 */
static void typed_languages(void)
{
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var a = 'x' + 'y';", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var a = 1 + 2;");
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var a = (5);");
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var a = 'x' + 1;");                           /* "x1" in js, a TypeError in python, a number elsewhere */
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var p = 'zap-'; var a = p + 'left';", "zap-left");
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var p = 'zap-'; p = 'other'; var a = p + 'left';");           /* assigned twice: not one value */
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "var p = 'zap-'; p += 'x'; var a = p + 'left';");
	REPORTS(KGENOME_TEXTUAL_LANG_JS, "function f(p) { var a = p + 'left'; }\nvar p = 'x';");    /* a parameter is no assignment */
	REPORTS(KGENOME_TEXTUAL_LANG_PY, "a = 'x' + 'y'\n", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_PY, "a = b'x' + b'y'\n");                          /* bytes is not str: not written back as a str */
	REPORTS(KGENOME_TEXTUAL_LANG_PY, "a = ('x' 'y')\n", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_PY, "new = ''\ndef f():\n    new = new + b' '\n");        /* found on quopri.py: came out new = ' ' */
	REPORTS(KGENOME_TEXTUAL_LANG_RUBY, "a = 'x' + 'y'\n", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_LUA, "a = 'x' .. 'y'\n", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_VBS, "a = \"x\" & \"y\"\n", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_VBS, "a = \"4\" + 5\n");                           /* vbscript: 9 */
	REPORTS(KGENOME_TEXTUAL_LANG_VBS, "a = \"x\" & \"\"\"\" & \"y\"\n", "x\"y");     /* a quote is written twice */
	REPORTS(KGENOME_TEXTUAL_LANG_PSH, "$a = 'x' + 'y'\n", "xy");
	REPORTS(KGENOME_TEXTUAL_LANG_PSH, "$a = 5 + \"4\"\n");                          /* powershell: 9 */
	/* a decimal number is one number: the walk's tokens are `2` `.` `58`, and php's join read them as the string "258" */
	REPORTS(PHPL, "$a = 2.58;");
	REPORTS(PHPL, "$a = 2.58 . 'x'; $b = 0.0; $c = 1 . 2;", "2.58x", "12");
	/* the byte in front of a bare variable is not part of it: javascript's `var a=b+c` came out `var a'..'` */
	{
		struct cset t;
		uint8_t *v = NULL;
		const char *in = "var p='x';var a=p+'y';", *want = "var p='x';var a='xy';";
		uint32_t w;

		consts_of(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)in, strlen(in), &t);
		w = consts_text(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)in, strlen(in), &t, &v);
		NCKF(w == strlen(want) && !memcmp(v, want, w), "bare variable: [%.*s]", (int)w, v ? (char *)v : "");
		free(v);
		cset_free(&t);
	}
}

/* ---- counts, the bounds ---------------------------------------------------------------------- */

/* N literals joined, N variables, each against the string that must come out. */
static void counts(void)
{
	static uint8_t src[1u << 20], want[1u << 16];
	unsigned n;

	for (n = 1; n <= 300u; n++) {
		size_t at = 0, w = 0;
		unsigned i;
		struct cset s;

		at += (size_t)snprintf((char *)src + at, sizeof src - at, "<?php $a = ");
		for (i = 0; i < n; i++) {
			char piece[8];
			size_t l = (size_t)snprintf(piece, sizeof piece, "%x", i);

			at += (size_t)snprintf((char *)src + at, sizeof src - at, "%s'%s'", i ? " . " : "", piece);
			memcpy(want + w, piece, l);
			w += l;
		}
		at += (size_t)snprintf((char *)src + at, sizeof src - at, ";");
		consts_of(PHPL, src, at, &s);
		if (n == 1u)
			NCKF(s.n == 0u, "one literal is not computed");
		else
			NCKF(s.n == 1u && s.c[0].n == w && !memcmp(s.c[0].v, want, w) && s.st == KGENOME_OK, "%u literals: %u values", n, s.n);
		cset_free(&s);
	}
	for (n = 1; n <= 320u; n += n < 300u ? 1u : 20u) {
		size_t at = 0, w = 0;
		unsigned i;
		struct cset s;

		at += (size_t)snprintf((char *)src, sizeof src, "<?php\n");
		for (i = 0; i < n; i++)
			at += (size_t)snprintf((char *)src + at, sizeof src - at, "$v%u='q%x';\n", i, i);
		at += (size_t)snprintf((char *)src + at, sizeof src - at, "$all=");
		for (i = 0; i < n; i++) {
			char piece[12];
			size_t l = (size_t)snprintf(piece, sizeof piece, "q%x", i);

			at += (size_t)snprintf((char *)src + at, sizeof src - at, "%s$v%u", i ? "." : "", i);
			memcpy(want + w, piece, l);
			w += l;
		}
		at += (size_t)snprintf((char *)src + at, sizeof src - at, ";");
		consts_of(PHPL, src, at, &s);
		if (n == 1u)
			NCKF(s.n == 0u, "one variable is not computed");
		else
			NCKF(s.n == 1u && s.c[0].n == w && !memcmp(s.c[0].v, want, w), "%u variables: %u values", n, s.n);
		cset_free(&s);
	}
}

/* The bound of one value, on both sides, and a long run of escapes. */
static void long_values(void)
{
	uint8_t *src = malloc(2u * EV_VMAX + 4096u);
	size_t at, i;
	struct cset s;

	/* EV_VMAX - 1 bytes in one literal and one more: exactly the bound; one byte more is not a constant */
	at = (size_t)snprintf((char *)src, 64, "<?php $a = '");
	for (i = 0; i < EV_VMAX - 1u; i++)
		src[at++] = (uint8_t)('a' + i % 26u);
	src[at++] = '\'';
	memcpy(src + at, " . 'y';", 7u);
	consts_of(PHPL, src, at + 7u, &s);
	NCKF(s.n == 1u && s.c[0].n == EV_VMAX && s.c[0].v[EV_VMAX - 1u] == 'y' && s.c[0].v[EV_VMAX - 2u] == (uint8_t)('a' + (EV_VMAX - 2u) % 26u),
	     "a value of exactly 1 MiB: %u values", s.n);
	cset_free(&s);
	at = (size_t)snprintf((char *)src, 64, "<?php $a = '");
	for (i = 0; i < EV_VMAX; i++)
		src[at++] = (uint8_t)('a' + i % 26u);
	src[at++] = '\'';
	memcpy(src + at, " . 'y';", 7u);
	consts_of(PHPL, src, at + 7u, &s);
	NCKF(s.n == 0u, "a value of 1 MiB and a byte is not constant (%u values)", s.n);
	cset_free(&s);
	/* 200k escapes in one literal: 800 KB of source, 200k bytes of value. DIFFERENCE: the folder read 300k escapes (1.2 MB of source); a literal whose TEXT is
	 * past EV_VMAX is not read here (the bound is on the text the evaluator holds while it decodes, not on the value), and 300k is not constant. */
	at = (size_t)snprintf((char *)src, 64, "<?php $a = \"");
	for (i = 0; i < 200000u; i++) {
		memcpy(src + at, "\\x41", 4u);
		at += 4u;
	}
	memcpy(src + at, "\" . 'z';", 8u);
	at += 8u;
	consts_of(PHPL, src, at, &s);
	NCKF(s.n == 1u && s.c[0].n == 200001u && s.c[0].v[0] == 'A' && s.c[0].v[199999] == 'A' && s.c[0].v[200000] == 'z', "200k escapes: %u values", s.n);
	cset_free(&s);
	at = (size_t)snprintf((char *)src, 64, "<?php $a = \"");
	for (i = 0; i < 300000u; i++) {
		memcpy(src + at, "\\x41", 4u);
		at += 4u;
	}
	memcpy(src + at, "\" . 'z';", 8u);
	at += 8u;
	consts_of(PHPL, src, at, &s);
	NCKF(s.n == 0u, "300k escapes (1.2 MB of text) are not constant: %u values", s.n);
	cset_free(&s);
	free(src);
}

/* A chain of variables each built from the one before: a variable is evaluated through the variables it names, and that recursion is bounded
 * (EV_DEPTH, 32: it was 8 until G5 - a name behind nine aliases was lost without a word - and a chain past it is now said, see diag_text_defects.c). DIFFERENCE: the folder's table was a hash and a chain of 3000 folded. */
static void chain_depth(void)
{
	static uint8_t src[1u << 16];
	unsigned depth, first_cut = 0;

	for (depth = 2; depth <= 40u; depth++) {
		size_t at = (size_t)snprintf((char *)src, 64, "<?php $v0 = 'a';\n");
		unsigned i;
		struct cset s;

		for (i = 1; i <= depth; i++)
			at += (size_t)snprintf((char *)src + at, 64, "$v%u = $v%u . 'b';\n", i, i - 1u);
		consts_of(PHPL, src, at, &s);
		/* every statement is its own constant, so the count is how many resolved */
		if (s.n != depth && !first_cut)
			first_cut = depth;
		NCKF(s.n <= depth, "chain %u: %u values", depth, s.n);
		cset_free(&s);
	}
	printf("  a chain of dependent variables first loses a link at %u variables (EV_DEPTH 32)\n", first_cut);
	NCKF(first_cut >= 32u && first_cut <= 34u, "the variable-depth bound first cuts a chain at %u variables", first_cut);
}

/* str_replace nested `depth` deep: EV_NEST levels evaluate and the next says it did not, and the scan says it was cut. */
static void nest_depth(void)
{
	static uint8_t src[1u << 16];
	unsigned depth, first_cut = 0;

	for (depth = 1; depth <= 300u; depth++) {
		size_t at = (size_t)snprintf((char *)src, 64, "<?php $d=");
		unsigned i;
		struct cset s;

		for (i = 0; i < depth; i++)
			at += (size_t)snprintf((char *)src + at, sizeof src - at, "str_replace('x','x',");
		at += (size_t)snprintf((char *)src + at, sizeof src - at, "'xyz-longer-than-ok'");
		for (i = 0; i < depth; i++)
			src[at++] = ')';
		src[at++] = ';';
		consts_of(PHPL, src, at, &s);
		if (s.n == 1u) {
			NCKF(s.c[0].n == 18u && !memcmp(s.c[0].v, "xyz-longer-than-ok", 18) && s.st == KGENOME_OK && !s.cut, "depth %u: %u bytes, status %d", depth,
			     s.c[0].n, (int)s.st);
		} else {
			NCKF(s.n == 0u && s.st == KGENOME_TRUNCATED && s.cut >= 1u, "depth %u: %u values, status %d, cut %u", depth, s.n, (int)s.st, s.cut);
			if (!first_cut)
				first_cut = depth;
		}
		cset_free(&s);
	}
	NCKF(first_cut == EV_NEST, "the nesting bound first fires at %u (EV_NEST %u)", first_cut, EV_NEST);
}

/* A file that opens a million calls chose to overflow the C stack once (a segmentation fault at 20000 levels, in the evaluator's recursion). */
static int group_nest_million(void *arg)
{
	size_t n = 1000000, at = 0, i;
	uint8_t *src = malloc(n * 22u + 64u);
	struct cset s;

	(void)arg;
	at += (size_t)snprintf((char *)src, 64, "<?php $d=");
	for (i = 0; i < n; i++) {
		memcpy(src + at, "str_replace('x','x',", 20u);
		at += 20u;
	}
	memcpy(src + at, "'k'", 3u);
	at += 3u;
	for (i = 0; i < n; i++)
		src[at++] = ')';
	src[at++] = ';';
	consts_of(PHPL, src, at, &s);
	NCKF(s.n == 0u && s.st == KGENOME_TRUNCATED && s.cut >= 1u, "a million nested calls: %u values, status %d, cut %u", s.n, (int)s.st, s.cut);
	cset_free(&s);
	free(src);
	return (int)nr_bad;
}

/* ---- allocation failure ------------------------------------------------------------------------ */

static long vm_bytes(void)
{
	long pages = 0, rss = 0;
	FILE *f = fopen("/proc/self/statm", "r");

	if (f) {
		if (fscanf(f, "%ld %ld", &pages, &rss) != 2)
			pages = 0;
		fclose(f);
	}
	return pages * sysconf(_SC_PAGESIZE);
}

static int cap_address_space(long headroom)
{
	struct rlimit rl;

	rl.rlim_cur = rl.rlim_max = (rlim_t)(vm_bytes() + headroom);
	return setrlimit(RLIMIT_AS, &rl) == 0;
}

/*
 * A JOIN OF N ONE-BYTE TERMS appends to ONE value (the buffer doubles): linear. The folder's arena copied the accumulator at every join (N*N/2 bytes:
 * a 30000-term chain reached 125 MB and 32768 terms its 512 MB bound), which this asks of the path at 160 MB of headroom: 30000 terms are 30000 bytes.
 */
static int group_chain_linear(void *arg)
{
	const unsigned N = 30000u;
	uint8_t *src = malloc((size_t)N * 4u + 64u);
	size_t at = 0;
	unsigned i;
	struct cset s;

	(void)arg;
	at += (size_t)snprintf((char *)src, 64, "<?php $a = ");
	for (i = 0; i < N; i++) {
		memcpy(src + at, i ? ".'x'" : "'x'", i ? 4u : 3u);
		at += i ? 4u : 3u;
	}
	src[at++] = ';';
	if (!cap_address_space(160L << 20))
		return 0;
	consts_of(PHPL, src, at, &s);
	NCKF(s.n == 1u && s.c[0].n == N, "30000 terms under capped address space: %u values", s.n);
	cset_free(&s);
	free(src);
	return (int)nr_bad;
}

/* A hundred thousand variables, address space capped: the answer is right or the status says it was cut - never a wrong value without it. */
static int group_vars_capped(void *arg)
{
	uint8_t *src = malloc(3u << 20);
	size_t at = 0;
	unsigned i;
	struct cset s;

	(void)arg;
	at += (size_t)snprintf((char *)src, 16, "<?php ");
	for (i = 0; i < 100000u; i++)
		at += (size_t)snprintf((char *)src + at, (3u << 20) - at, "$v%u='x';", i);
	at += (size_t)snprintf((char *)src + at, (3u << 20) - at, "$z=$v0.$v99999.'end';");
	if (!cap_address_space(8L << 20))
		return 0;
	consts_of(PHPL, src, at, &s);
	NCKF((s.n == 1u && s.c[0].n == 5u && !memcmp(s.c[0].v, "xxend", 5)) || (s.n == 0u && s.st != KGENOME_OK),
	     "100000 variables, capped: %u values, status %d", s.n, (int)s.st);
	cset_free(&s);
	free(src);
	return (int)nr_bad;
}

int main(void)
{
	names_init();
	known_answers();
	not_constant();
	typed_languages();
	counts();
	long_values();
	chain_depth();
	nest_depth();
	/* one feature at a time, then all of them */
	feat_var = 0; feat_repl = 0; feat_join = 0;
	differential(&PHP, 500u, 0x11000u);
	feat_join = 1;
	differential(&PHP, 500u, 0x12000u);
	feat_var = 2;
	differential(&PHP, 500u, 0x13000u);
	feat_var = 0; feat_repl = 1;
	differential(&PHP, 500u, 0x14000u);
	feat_var = 2;
	differential(&PHP, 2500u, 0x10000u);
	differential(&JS, 1000u, 0x20000u);
	differential(&PY, 1000u, 0x30000u);
	differential(&PSH, 1000u, 0x40000u);
	NCK(nr_group("nest-million", group_nest_million, NULL) == 0);
	if (!UNDER_ASAN)
		NCK(nr_group("chain", group_chain_linear, NULL) == 0);
	if (UNDER_ASAN) {
		printf("  allocation-failure groups skipped: the sanitiser cannot run with the address space capped\n");
	} else {
		NCK(nr_group("vars", group_vars_capped, NULL) == 0);
	}
	printf("normalizer_script: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
