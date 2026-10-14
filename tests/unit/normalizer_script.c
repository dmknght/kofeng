#define _GNU_SOURCE
/*
 * normalizer_script - what kof_script_fold builds out of a script's own
 * literals, against a reference interpreter that is handed the PROGRAM and not
 * its text.
 *
 * THE REFERENCE IS NOT A SECOND PARSER. A generated corpus starts as a list of
 * statements - `name = term . term . ...`, where a term is a literal, a
 * variable or `str_replace(expr, expr, expr)` - and the expected answer is
 * computed from that list by evaluating it, straight. Only afterwards is the
 * list written out as source, with the quote style, the escape spelling of
 * every byte (raw, \xHH, \OOO, \n, \', \\), the spacing and the junk between
 * statements chosen at random. So a mistake in reading the TEXT - a quote, an
 * escape, a variable name, a nesting - shows as a difference from a value that
 * never went through any text.
 *
 *   differential   thousands of generated programs, php (`.`), PowerShell (`+`)
 *                  and Tcl (no join: only the first term of an expression)
 *   known answers  N literals joined (1..300), str_replace chains, every escape
 *                  form, 1..300 variables (a hash table now), the first
 *                  definition of a name wins, a cap smaller than the answer
 *   not folded     chr() and fromCharCode are programs, not literals; so is a
 *                  language with no variable sigil - the answer is zero and
 *                  says so
 *   limits         nesting 1..300 (256 is the bound and the limit field says
 *                  so), the table of variables and the arena when the address
 *                  space cannot hold them (not under the sanitiser)
 *   KNOWN MISSES   each is a way the folder reads a statement that is not the
 *                  statement the program has; the cause is on the line
 */

#include <sys/resource.h>

#include "normalizer_ref.h"
#include <kofmod/script.h>
#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_norm.h"

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

/* ---- the program, as data ------------------------------------------------------ */

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

struct stmt {
	int        name;                        /* index into the name pool */
	struct ex *e;
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

static struct bytes random_literal(struct nrng *r, unsigned max, int nonempty)
{
	struct bytes b;
	unsigned i, n = nr_below(r, max + 1u);

	if (nonempty && !n)
		n = 1;
	b.p = malloc(n + 1u);
	b.n = n;
	for (i = 0; i < n; i++) {
		uint32_t k = nr_below(r, 10u);

		if (k < 6u)
			b.p[i] = (uint8_t)"abcdeabcde fghij"[nr_below(r, 16u)];
		else if (k < 8u)
			b.p[i] = (uint8_t)"'\"\\\n\t.;(){}/*#<>=-"[nr_below(r, 17u)];
		else
			b.p[i] = (uint8_t)(1u + nr_below(r, 254u));
		if (b.p[i] == '$')
			b.p[i] = 'S';
	}
	return b;
}

static struct ex *random_ex(struct nrng *r, unsigned depth, const int *defined,
			    unsigned n_defined);

/* How much of the grammar a generated program uses: out of ten, the share of
 * terms that are variables, whether str_replace appears, and whether an
 * expression may have more than one term. The classes of the differential
 * switch them on one at a time, so a difference names the feature. */
static unsigned feat_var = 2, feat_repl = 1, feat_join = 1;

static void random_term(struct nrng *r, struct tm *t, unsigned depth, const int *defined,
			unsigned n_defined)
{
	uint32_t k = nr_below(r, 10u);

	memset(t, 0, sizeof *t);
	if (k < feat_var && n_defined) {
		t->kind = 1;
		t->var = defined[nr_below(r, n_defined)];
	} else if (k == 9u && feat_repl && depth < 3u) {
		t->kind = 2;
		t->a = random_ex(r, depth + 1u, defined, n_defined);
		t->b = random_ex(r, depth + 1u, defined, n_defined);
		t->c = random_ex(r, depth + 1u, defined, n_defined);
	} else {
		t->lit = random_literal(r, 14u, 0);
	}
}

static struct ex *random_ex(struct nrng *r, unsigned depth, const int *defined,
			    unsigned n_defined)
{
	struct ex *e = calloc(1, sizeof *e);
	unsigned i;

	e->n = feat_join ? 1u + nr_below(r, depth ? 2u : 4u) : 1u;
	e->t = calloc(e->n, sizeof *e->t);
	for (i = 0; i < e->n; i++)
		random_term(r, &e->t[i], depth, defined, n_defined);
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

/* Set when a top-level expression lost a LATER term: the folder keeps what it had
 * and the statement is then not the statement the program holds (see
 * fold_statements), so the generator does not emit such a program. */
static int ref_dirty;

static struct val ref_eval(const struct ex *e, const struct env *env, unsigned concat, int strict);

static struct val ref_term(const struct tm *t, const struct env *env, unsigned concat)
{
	struct val bad = { NULL, 0, 0 };

	if (t->kind == 0)
		return val_of(t->lit.p, t->lit.n);
	if (t->kind == 1) {
		const struct val *d = &env->v[t->var];

		return d->ok ? val_of(d->p, d->n) : bad;
	}
	{
		struct val a = ref_eval(t->a, env, concat, 1), b = ref_eval(t->b, env, concat, 1);
		struct val c = ref_eval(t->c, env, concat, 1), o;
		size_t i, w = 0;

		if (!a.ok || !b.ok || !c.ok || !a.n) {
			val_free(&a);
			val_free(&b);
			val_free(&c);
			return bad;
		}
		o.p = malloc(c.n * (b.n > a.n ? b.n : 1u) + b.n + 1u);
		for (i = 0; i < c.n;) {
			if (i + a.n <= c.n && !memcmp(c.p + i, a.p, a.n)) {
				memcpy(o.p + w, b.p, b.n);
				w += b.n;
				i += a.n;
			} else {
				o.p[w++] = c.p[i++];
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

/*
 * An expression is its terms joined; with no join operator (Tcl) it is the first.
 * An ARGUMENT of str_replace must be followed by its comma or bracket, so a term
 * lost inside one loses the call (`strict`); a statement's own expression just
 * stops, which `ref_dirty` records.
 */
static struct val ref_eval(const struct ex *e, const struct env *env, unsigned concat, int strict)
{
	struct val acc = ref_term(&e->t[0], env, concat);
	unsigned i;

	for (i = 1; concat && acc.ok && i < e->n; i++) {
		struct val r = ref_term(&e->t[i], env, concat);

		if (!r.ok) {
			val_free(&r);
			if (strict) {
				val_free(&acc);
				return acc;
			}
			ref_dirty = 1;
			break;
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

/* One literal, in quote `q`, each byte spelled one of the ways the folder reads. */
static void write_literal(struct src *s, const struct bytes *b, char q, struct nrng *r)
{
	size_t i;
	char tmp[8];

	src_put(s, &q, 1u);
	for (i = 0; i < b->n; i++) {
		uint8_t c = b->p[i];
		uint32_t how = nr_below(r, 8u);
		const char *letter = c == '\n' ? "\\n" : c == '\r' ? "\\r" : c == '\t' ? "\\t" :
				     c == '\v' ? "\\v" : c == '\f' ? "\\f" : NULL;

		if (c == (uint8_t)q || c == '\\' || c < 0x20 || c >= 0x7f || how < 2u) {
			if (letter && how & 1u) {
				src_str(s, letter);
			} else if ((c == (uint8_t)q || c == '\\') && how & 1u) {
				tmp[0] = '\\';
				tmp[1] = (char)c;
				src_put(s, tmp, 2u);
			} else if (how & 2u) {
				snprintf(tmp, sizeof tmp, "\\x%02x", c);
				src_str(s, tmp);
			} else if (how & 4u) {
				snprintf(tmp, sizeof tmp, "\\X%02X", c);
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

static void write_ex(struct src *s, const struct ex *e, int tcl, char concat, struct nrng *r);

static void write_term(struct src *s, const struct tm *t, int tcl, char concat, struct nrng *r)
{
	char q = tcl || nr_below(r, 2u) ? '"' : '\'';

	if (t->kind == 0) {
		write_literal(s, &t->lit, q, r);
	} else if (t->kind == 1) {
		src_str(s, "$");
		src_str(s, name_of[t->var]);
	} else {
		src_str(s, "str_replace(");
		ws(s, r);
		write_ex(s, t->a, tcl, concat, r);
		ws(s, r);
		src_str(s, ",");
		ws(s, r);
		write_ex(s, t->b, tcl, concat, r);
		ws(s, r);
		src_str(s, ",");
		ws(s, r);
		write_ex(s, t->c, tcl, concat, r);
		ws(s, r);
		src_str(s, ")");
	}
}

static void write_ex(struct src *s, const struct ex *e, int tcl, char concat, struct nrng *r)
{
	unsigned i;

	for (i = 0; i < e->n; i++) {
		if (i) {
			ws(s, r);
			src_put(s, &concat, 1u);
			ws(s, r);
		}
		write_term(s, &e->t[i], tcl, concat, r);
	}
}

/* Statements between statements that an assignment reader must step over. */
static void junk(struct src *s, struct nrng *r)
{
	static const char *const j[] = {
		"\n", "\n", "echo $v7;\n", "if ($v14 == 'x') { }\n", "\n\n", "$Var_0 == 1;\n",
		"  \n", "foo($v21, $v0);\n", "return;\n", "?>\n<html>\n<?php\n"
	};

	src_str(s, j[nr_below(r, sizeof j / sizeof j[0])]);
}

/* ---- one generated program ---------------------------------------------------------------- */

struct prog {
	struct src  text;
	struct val  best;
	unsigned    n_stmt;
};

static void prog_free(struct prog *g)
{
	free(g->text.p);
	val_free(&g->best);
	memset(g, 0, sizeof *g);
}

/*
 * Generate, evaluate and write one program. `concat` is the language's join
 * (0 for Tcl). The answer is the longest value any statement built, the first of
 * equals, and a name keeps its FIRST value.
 */
static void make_program(struct nrng *r, char concat, int tcl, struct prog *g)
{
	struct env env;
	int defined[NAMES];
	unsigned n_def = 0, i, ns = 2u + nr_below(r, 9u);

	memset(&env, 0, sizeof env);
	memset(g, 0, sizeof *g);
	src_str(&g->text, "<?php\n");
	for (i = 0; i < ns; i++) {
		int name = (int)nr_below(r, 12u);        /* a small pool: names repeat */
		struct ex *e;
		struct val v;
		int fail_first = nr_below(r, 12u) == 0u;

		if (fail_first) {
			/* a statement whose FIRST term cannot be evaluated builds nothing */
			src_str(&g->text, "$");
			src_str(&g->text, name_of[name]);
			ws(&g->text, r);
			src_str(&g->text, "=");
			ws(&g->text, r);
			src_str(&g->text, nr_below(r, 2u) ? "$undefined_one" : "str_replace(\"\",\"x\",\"abc\")");
			ws(&g->text, r);
			src_str(&g->text, concat ? (concat == '.' ? ". \"tail\"" : "+ \"tail\"") : "");
			src_str(&g->text, ";");
			junk(&g->text, r);
			continue;
		}
		{
			unsigned tries = 0;

			do {
				e = random_ex(r, 0, defined, n_def);
				ref_dirty = 0;
				v = ref_eval(e, &env, (unsigned)(unsigned char)concat, 0);
				if (!ref_dirty)
					break;
				val_free(&v);
				ex_free(e);
			} while (++tries < 8u);
			if (ref_dirty) {                /* give up on this one: a plain literal */
				e = calloc(1, sizeof *e);
				e->n = 1;
				e->t = calloc(1, sizeof *e->t);
				e->t[0].lit = random_literal(r, 14u, 1);
				v = ref_eval(e, &env, (unsigned)(unsigned char)concat, 0);
			}
		}
		src_str(&g->text, "$");
		src_str(&g->text, name_of[name]);
		ws(&g->text, r);
		src_str(&g->text, "=");
		ws(&g->text, r);
		write_ex(&g->text, e, tcl, concat, r);
		src_str(&g->text, ";");
		junk(&g->text, r);
		if (v.ok && v.n) {
			if (v.n > g->best.n) {
				val_free(&g->best);
				g->best = val_of(v.p, v.n);
			}
			if (!env.v[name].ok) {
				env.v[name] = v;
				defined[n_def++] = name;
				v.p = NULL;
			}
		}
		val_free(&v);
		ex_free(e);
	}
	g->n_stmt = ns;
	for (i = 0; i < NAMES; i++)
		val_free(&env.v[i]);
}

/* ---- differential ---------------------------------------------------------------------------- */

static void fold_differential(uint8_t kind, char concat, int tcl, unsigned seeds, unsigned base)
{
	/* (the feature switches are read by the generator above) */
	const struct kof_lex *lx = kof_lex_for(kind);
	struct nrng r;
	unsigned seed, nonempty = 0, longest = 0;
	static uint8_t out[1u << 16];

	for (seed = 1; seed <= seeds; seed++) {
		struct prog g;
		uint32_t got, limit = 99, cap = (uint32_t)sizeof out;

		nr_seed(&r, base + seed);
		make_program(&r, concat, tcl, &g);
		memset(out, 0xee, 64);
		if (g.best.n && nr_below(&r, 6u) == 0u)
			cap = 1u + nr_below(&r, (uint32_t)g.best.n);
		got = kof_script_fold_ex(lx, g.text.p, (uint32_t)g.text.n, out, cap, &limit);
		{
			size_t want = g.best.n > cap ? cap : g.best.n;

			NCKF(got == want && (!want || !memcmp(out, g.best.p, want)) && limit == 0,
			     "seed %u (%s): got %u want %zu limit %u\n%.*s", seed,
			     tcl ? "tcl" : concat == '.' ? "php" : "psh", got, want, limit,
			     (int)g.text.n, (char *)g.text.p);
			if (!want)
				NCK(out[0] == 0xee);              /* nothing written for nothing */
		}
		nonempty += g.best.n != 0;
		if (g.best.n > longest)
			longest = (unsigned)g.best.n;
		prog_free(&g);
	}
	NCKF(nonempty > seeds / 2u, "generator reach: %u of %u built something", nonempty, seeds);
	NCKF(longest > (feat_join ? 20u : 8u), "generator reach: longest %u", longest);
}

/* ---- known answers --------------------------------------------------------------------------- */

static uint32_t fold_text(const char *src, uint8_t kind, uint8_t *out, uint32_t cap,
			  uint32_t *limit)
{
	return kof_script_fold_ex(kof_lex_for(kind), (const uint8_t *)src, (uint32_t)strlen(src),
				  out, cap, limit);
}

#define FOLDS(src, want) do { \
	uint8_t o_[4096]; \
	uint32_t l_ = 0, n_ = fold_text((src), KOF_SCRIPT_PHP, o_, sizeof o_, &l_); \
	NCKF(n_ == strlen(want) && !memcmp(o_, (want), n_) && l_ == 0, \
	     "fold of [%s]: got %u bytes [%.*s] limit %u, want [%s]", (src), n_, (int)n_, \
	     (char *)o_, l_, (want)); \
} while (0)

static void fold_known_answers(void)
{
	/* a join, a variable, str_replace, in the shape of a generator */
	FOLDS("$a='fun'; $b='ction x('; $c=str_replace('|','',$a.'|'.$b);", "function x(");
	FOLDS("$a = \"ab\" . \"cd\" . 'ef';", "abcdef");
	FOLDS("$a=\"x\";$b=$a.$a;$c=$b.$b.$a;", "xxxxx");
	FOLDS("$a=str_replace('a','bb','banana');", "bbbnbbnbb");
	FOLDS("$a=str_replace('ab','','ababab-ab');", "-");
	FOLDS("$a=str_replace('aa','b','aaaaa');", "bba");              /* left to right, no overlap */
	FOLDS("$x=str_replace('1','2',str_replace('0','1','0101'));", "2222");
	/* the first definition of a name wins */
	FOLDS("$a='one'; $a='two'; $b=$a.'!';", "one!");
	/* a comparison is not an assignment */
	FOLDS("$a=='long literal value here'; $b='ok';", "ok");
	/* every escape form, in both quotes */
	FOLDS("$a=\"\\x41\\x42\\103\\x4a\\X4b\\n\";", "ABCJK\n");
	FOLDS("$a='\\x70\\150\\x70\\72\\57\\57';", "php://");
	FOLDS("$a='it\\'s \\\"q\\\" \\\\ done';", "it's \"q\" \\ done");
	FOLDS("$a=\"a\\tb\\vc\\fd\\re\";", "a\tb\vc\fd\re");
	FOLDS("$a=\"\\q\\z\";", "qz");                                  /* an unknown escape is the byte */
	FOLDS("$a=\"x\\x\";", "x");                                     /* \x with no digit is dropped */
	FOLDS("$a=\"\\x4\" . 'Z';", "\x04Z");                            /* one digit is a byte */
	FOLDS("$a=\"\\1018\";", "A8");                                  /* octal stops at three digits */
	FOLDS("$a=\"\\60\\4\";", "0\x04");
	/* the longest wins, and the first of equals */
	FOLDS("$a='abc'; $b='abcd'; $c='wxyz';", "abcd");
	FOLDS("$a='1234'; $b='abcd';", "1234");
	/* spacing and sigils */
	FOLDS("$a=\t'x'\t.\t'y'\t;", "xy");
	FOLDS("   $a   =   'x'.'y' ;  ", "xy");
	FOLDS("$a_1='p'; $A1='q'; $r=$a_1.$A1.$a_1;", "pqp");
	FOLDS("$$a='x'; $b='yy';", "yy");                               /* a sigil alone is not a name */
	/* an assignment whose value is empty builds nothing and defines nothing */
	FOLDS("$a=''; $b=$a.'k';", "");
	FOLDS("$a=str_replace('x','','xx'); $b='z';", "z");
}

static void fold_not_folded(void)
{
	uint8_t o[256];
	uint32_t l = 5;

	/* what the header says it does NOT do: it runs nothing */
	NCK(fold_text("$a=chr(65).chr(66).chr(67);", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0 && l == 0);
	NCK(fold_text("$a=String.fromCharCode(65,66);", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0);
	NCK(fold_text("$a=base64_decode('QUJD');", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0);
	NCK(fold_text("$a=$_GET['p'];", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0);
	NCK(fold_text("$a=strrev('cba');", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0);
	/* an unterminated literal is not a constant, and does not hide the next one */
	NCK(fold_text("$a='abc", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0);
	NCK(fold_text("$a=\"abc\\", KOF_SCRIPT_PHP, o, sizeof o, &l) == 0);
	NCK(fold_text("$a='abc\n$b='xy';", KOF_SCRIPT_PHP, o, sizeof o, &l) == 7);   /* "abc\n$b=" */
	/* a name that is not defined yet is not a value */
	NCK(fold_text("$a=$b.'x'; $b='y';", KOF_SCRIPT_PHP, o, sizeof o, &l) == 1 && o[0] == 'y');
	/* a language with no variable sigil is declined, whatever it says */
	{
		static const uint8_t kinds[] = { KOF_SCRIPT_JS, KOF_SCRIPT_PYTHON, KOF_SCRIPT_RUBY,
						 KOF_SCRIPT_SHELL, KOF_SCRIPT_BAT, KOF_SCRIPT_LUA,
						 KOF_SCRIPT_CFM, KOF_SCRIPT_VBS, KOF_SCRIPT_ASP,
						 KOF_SCRIPT_ASPX, KOF_SCRIPT_JSP };
		unsigned i;

		for (i = 0; i < sizeof kinds; i++) {
			const struct kof_lex *lx = kof_lex_for(kinds[i]);

			NCKF(lx && !lx->var_sigil, "kind %u row", kinds[i]);
			NCKF(fold_text("$a='x'.'y'; var a = 'x' + 'y';", kinds[i], o, sizeof o, &l) == 0 &&
			     l == 0, "kind %u folded", kinds[i]);
		}
	}
	/* no language row at all */
	NCK(kof_lex_for(KOF_SCRIPT_ANY) == NULL && kof_lex_for(250) == NULL);
	NCK(kof_script_fold_ex(NULL, (const uint8_t *)"$a='x';", 7, o, sizeof o, &l) == 0 && l == 0);
	NCK(kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), NULL, 7, o, sizeof o, &l) == 0);
	NCK(kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), (const uint8_t *)"$a='x';", 0, o,
			       sizeof o, &l) == 0);
	NCK(kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), (const uint8_t *)"$a='x';", 7, NULL,
			       sizeof o, &l) == 0);
	NCK(kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), (const uint8_t *)"$a='x';", 7, o, 0,
			       &l) == 0);
	NCK(kof_script_fold(kof_lex_for(KOF_SCRIPT_PHP), (const uint8_t *)"$a='xy';", 8, o, 1) == 1);
	/* Tcl has no join: the first term is the whole value */
	NCK(fold_text("$a=\"ab\" . \"cd\";", KOF_SCRIPT_TCL, o, sizeof o, &l) == 2 && !memcmp(o, "ab", 2));
	/* Tcl has one quote */
	NCK(fold_text("$a='ab';", KOF_SCRIPT_TCL, o, sizeof o, &l) == 0);
	/* PowerShell joins with + */
	NCK(fold_text("$a='ab' + 'cd'; $b='ef'.'gh';", KOF_SCRIPT_PSH, o, sizeof o, &l) == 4 &&
	    !memcmp(o, "abcd", 4));
	/* Perl joins with '.' */
	NCK(fold_text("$a='ab' . 'cd';", KOF_SCRIPT_PERL, o, sizeof o, &l) == 4);
}

/* N literals joined, N variables, each against the string that must come out. */
static void fold_counts(void)
{
	static uint8_t src[1u << 20], out[1u << 16], want[1u << 16];
	unsigned n;

	for (n = 1; n <= 300u; n++) {
		size_t at = 0, w = 0;
		unsigned i;
		uint32_t limit = 9, got;

		/* $a = 'p0' . 'p1' . ... . 'p(n-1)'; */
		at += (size_t)snprintf((char *)src + at, sizeof src - at, "$a = ");
		for (i = 0; i < n; i++) {
			char piece[8];
			size_t l = (size_t)snprintf(piece, sizeof piece, "%x", i);

			at += (size_t)snprintf((char *)src + at, sizeof src - at, "%s'%s'", i ? " . " : "",
					       piece);
			memcpy(want + w, piece, l);
			w += l;
		}
		at += (size_t)snprintf((char *)src + at, sizeof src - at, ";");
		got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out,
					 sizeof out, &limit);
		NCKF(got == w && !memcmp(out, want, w) && !limit, "%u literals: %u vs %zu", n, got, w);
	}
	for (n = 1; n <= 320u; n += n < 300u ? 1u : 20u) {
		size_t at = 0, w = 0;
		unsigned i;
		uint32_t limit = 9, got;

		/* $v0 = 'q0'; ... ; $all = $v0 . $v1 ... ; names collide by prefix on purpose */
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
		got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out,
					 sizeof out, &limit);
		NCKF(got == w && !memcmp(out, want, w) && !limit, "%u variables: %u vs %zu limit %u", n,
		     got, w, limit);
	}
}

/* a long literal, and a chain of variables each built from the one before */
static void fold_long(void)
{
	size_t n = 1u << 20, i, at = 0;
	uint8_t *src = malloc(2u * n + 64u), *out = malloc(2u * n + 64u);
	uint32_t limit = 9, got;

	/* one megabyte in one literal: the folder returns the first `cap` bytes of it */
	at += (size_t)snprintf((char *)src, 64, "$a = '");
	for (i = 0; i < n; i++)
		src[at++] = (uint8_t)('a' + i % 26u);
	src[at++] = '\'';
	src[at++] = ';';
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, (uint32_t)n, &limit);
	NCKF(got == n && !limit && out[0] == 'a' && out[n - 1u] == (uint8_t)('a' + (n - 1u) % 26u),
	     "a 1 MiB literal: %u", got);
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, 1000u, &limit);
	NCKF(got == 1000u && !memcmp(out, src + 6, 1000u), "a 1 MiB literal into 1000 bytes: %u", got);
	/* 300k escapes in one literal: 1.2 MB of source, 300k bytes of answer */
	at = (size_t)snprintf((char *)src, 64, "$a = \"");
	for (i = 0; i < 300000u; i++) {
		memcpy(src + at, "\\x41", 4u);
		at += 4u;
	}
	src[at++] = '"';
	src[at++] = ';';
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, (uint32_t)n, &limit);
	NCKF(got == 300000u && !limit && out[0] == 'A' && out[299999] == 'A', "300k escapes: %u", got);
	/* $v1 = $v0 . 'b'; $v2 = $v1 . 'b'; ... a chain of 3000, each variable looked up once */
	at = (size_t)snprintf((char *)src, 64, "$v0 = 'a';\n");
	for (i = 1; i <= 3000u; i++)
		at += (size_t)snprintf((char *)src + at, 64, "$v%zu = $v%zu . 'b';\n", i, i - 1u);
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, (uint32_t)n, &limit);
	NCKF(got == 3001u && !limit && out[0] == 'a' && out[3000] == 'b', "a chain of 3000 variables: %u", got);
	free(src);
	free(out);
}

/* str_replace nested `depth` deep: 256 folds and 257 says it did not. */
static void fold_depth(void)
{
	static uint8_t src[1u << 16], out[256];
	unsigned depth;
	unsigned first_limit = 0;

	for (depth = 1; depth <= 300u; depth++) {
		size_t at = 0;
		unsigned i;
		uint32_t limit = 0, got;

		/* $ok = 'safe-value'; $d = str_replace('x','x', ... str_replace('x','x','xyz') ...); */
		at += (size_t)snprintf((char *)src + at, sizeof src - at, "$ok='safe-value'; $d=");
		for (i = 0; i < depth; i++)
			at += (size_t)snprintf((char *)src + at, sizeof src - at, "str_replace('x','x',");
		at += (size_t)snprintf((char *)src + at, sizeof src - at, "'xyz-longer-than-ok'");
		for (i = 0; i < depth; i++)
			src[at++] = ')';
		src[at++] = ';';
		got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, sizeof out,
					 &limit);
		if (depth <= 256u) {
			NCKF(got == 18u && !memcmp(out, "xyz-longer-than-ok", 18) && !limit,
			     "depth %u: got %u limit %u", depth, got, limit);
		} else {
			/* the statement is not folded, the limit says so, and the plain constant
			 * before it is still the answer - the bound is a cost bound, not silence */
			NCKF((limit & KOF_FOLD_DEPTH) && got == 10u && !memcmp(out, "safe-value", 10),
			     "depth %u: got %u limit %u", depth, got, limit);
			if (!first_limit)
				first_limit = depth;
		}
	}
	NCKF(first_limit == 257u, "the depth bound first fires at %u", first_limit);
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

/* A value doubled through variables reaches the arena's bound; with the address
 * space capped the bound is reached sooner, and the limit field says so. */
static int group_arena_limit(void *arg)
{
	static uint8_t src[4096], out[1u << 20];
	size_t at = 0;
	unsigned i;
	uint32_t limit = 0, got;

	(void)arg;
	at += (size_t)snprintf((char *)src + at, sizeof src - at, "$a0='%s';\n", "0123456789abcdef");
	for (i = 1; i <= 28u; i++)
		at += (size_t)snprintf((char *)src + at, sizeof src - at, "$a%u=$a%u.$a%u;\n", i, i - 1u,
				       i - 1u);
	if (!cap_address_space(48L << 20)) {
		printf("  cannot cap the address space: group skipped\n");
		return 0;
	}
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, sizeof out,
				 &limit);
	NCKF(limit & KOF_FOLD_ARENA, "no arena limit (limit %x)", limit);
	/* what was built before the bound is still the answer, and the cap holds it */
	NCKF(got == sizeof out, "got %u", got);
	return (int)nr_bad;
}

/* A hundred thousand variables need a table the address space cannot give. */
static int group_vars_limit(void *arg)
{
	static uint8_t out[64];
	uint8_t *src = malloc(3u << 20);
	size_t at = 0;
	unsigned i;
	uint32_t limit = 0, got;

	(void)arg;
	for (i = 0; i < 100000u; i++)
		at += (size_t)snprintf((char *)src + at, (3u << 20) - at, "$v%u='x';", i);
	at += (size_t)snprintf((char *)src + at, (3u << 20) - at, "$z=$v0.$v99999.'end';");
	if (!cap_address_space(1L << 20)) {
		printf("  cannot cap the address space: group skipped\n");
		return 0;
	}
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, sizeof out,
				 &limit);
	NCKF(limit & KOF_FOLD_VARS, "no variable limit (limit %x)", limit);
	/* the variables that did not fit were not remembered, so what joins them did not
	 * fold; the answer is whatever the first of them held */
	NCKF(got <= 3u, "got %u", got);
	free(src);
	return (int)nr_bad;
}

/*
 * A JOIN COPIES THE WHOLE ACCUMULATOR EVERY TIME.
 *
 * 'x'.'x'.'x'... of N terms is N joins, and each one appends a copy of everything
 * before it to the arena: N*N/2 bytes for an answer of N. Measured here: N = 16000
 * (64 KB of source) takes 125 MB; N = 32768 (128 KB) reaches the arena's own bound
 * of 512 MB and the statement is not folded. The header says a join is "a third
 * copy, which is what keeps the total bounded by the literals the file contains" -
 * the result is, the working set is not - and that the arena bound is "reachable
 * only by a file that doubles a value through variables", which this is not.
 *
 * Asked at 160 MB of headroom (the sanitiser cannot run capped, so it does not ask):
 * a 30000-term chain must fold to its 30000 bytes. It does not.
 */
static int group_chain_quadratic(void *arg)
{
	static uint8_t out[40000];
	const unsigned N = 30000u;
	uint8_t *src = malloc((size_t)N * 4u + 64u);
	size_t at = 0;
	unsigned i;
	uint32_t limit = 0, got;

	(void)arg;
	at += (size_t)snprintf((char *)src, 64, "$a = ");
	for (i = 0; i < N; i++) {
		memcpy(src + at, i ? ".'x'" : "'x'", i ? 4u : 3u);
		at += i ? 4u : 3u;
	}
	src[at++] = ';';
	if (!cap_address_space(160L << 20))
		return 0;
	got = kof_script_fold_ex(kof_lex_for(KOF_SCRIPT_PHP), src, (uint32_t)at, out, sizeof out,
				 &limit);
	free(src);
	return got == N && !limit ? 0 : 42;
}

/* ---- statements across lines, and statements that do not end where the constant does -------- */

static void fold_statements(void)
{
	uint8_t o[256];
	uint32_t l = 0, n;
	/*
	 * A STATEMENT THAT CONTINUES ON THE NEXT LINE IS READ AS ONE.
	 *
	 * Where the language ends a statement with a token (php, perl: ';') a newline inside
	 * an expression is whitespace, so `$a = 'ab' .\n 'cd';` is the constant 'abcd'. Where
	 * the newline ends the statement (PowerShell, Tcl) it stays a boundary.
	 */
	n = fold_text("$a = 'ab' .\n    'cd';", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 4u && !memcmp(o, "abcd", 4), "a join continued on the next line folds across it");
	n = fold_text("$a = 'ab'\n  . 'cd';", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 4u && !memcmp(o, "abcd", 4), "a join that begins on the next line is joined");
	n = fold_text("$a = 'ab'\n . 'cd'\n", KOF_SCRIPT_PSH, o, sizeof o, &l);
	NCKF(n == 2u && !memcmp(o, "ab", 2), "where a newline ends the statement it still does");

	/*
	 * A STATEMENT THAT ENDS IN SOMETHING THE FOLDER CANNOT EVALUATE IS NOT RECORDED.
	 *
	 * eval() takes terms while it can and gives back what it had; `$a = 'ab' . $x;`
	 * was recorded as 'ab' and `$b = $a . 'cd';` as 'abcd' - a value the program never
	 * holds (it holds 'ab', then the contents of $x, then 'cd'). A marker taken from
	 * that output matches nothing in the program. An index after a variable is the same:
	 * `$v = $k[1]` is not `$k`.
	 */
	n = fold_text("$x=$_GET['p']; $a = 'ab' . $x; $b = $a . 'cd';", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 0u, "a statement ending in a non-constant term builds nothing (%u)", n);
	n = fold_text("$k='abc'; $v = $k[1]; $w = $v . 'z';", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 3u && !memcmp(o, "abc", 3), "$k[1] is not read as $k, and nothing is joined on it");
	/* what still folds: the statement ends */
	n = fold_text("$a = 'ab' . 'cd' ; // c\n", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 4u, "a statement closed by a semicolon and a comment");
	n = fold_text("<?php $a = 'ab' . 'cd' ?>", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 4u, "a statement closed by the php close tag");
	n = fold_text("f($a = 'ab' . 'cd')", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 4u, "a statement closed by a bracket");
	n = fold_text("$a = 'ab' . 'cd'", KOF_SCRIPT_PHP, o, sizeof o, &l);
	NCKF(n == 4u, "a statement closed by the end of the input");
}

int main(void)
{
	names_init();
	fold_known_answers();
	fold_not_folded();
	fold_counts();
	fold_long();
	fold_depth();
	/* one feature at a time, then all of them */
	feat_var = 0; feat_repl = 0; feat_join = 0;
	fold_differential(KOF_SCRIPT_PHP, '.', 0, 500u, 0x11000u);
	feat_join = 1;
	fold_differential(KOF_SCRIPT_PHP, '.', 0, 500u, 0x12000u);
	feat_var = 2;
	fold_differential(KOF_SCRIPT_PHP, '.', 0, 500u, 0x13000u);
	feat_var = 0; feat_repl = 1;
	fold_differential(KOF_SCRIPT_PHP, '.', 0, 500u, 0x14000u);
	feat_var = 2;
	fold_differential(KOF_SCRIPT_PHP, '.', 0, 2500u, 0x10000u);
	fold_differential(KOF_SCRIPT_PSH, '+', 0, 1000u, 0x20000u);
	feat_join = 0;                  /* Tcl has no join to write */
	fold_differential(KOF_SCRIPT_TCL, 0, 1, 1000u, 0x30000u);
	fold_statements();
	if (!UNDER_ASAN)
		NCK(nr_group("chain", group_chain_quadratic, NULL) == 0);       /* 30000 one-byte terms: linear arena */
	if (UNDER_ASAN) {
		printf("  allocation-failure groups skipped: the sanitiser cannot run with the address "
		       "space capped\n");
	} else {
		NCK(nr_group("arena", group_arena_limit, NULL) == 0);
		NCK(nr_group("vars", group_vars_limit, NULL) == 0);
	}
	printf("normalizer_script: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
