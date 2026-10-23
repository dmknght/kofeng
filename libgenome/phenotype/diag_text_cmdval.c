/*
 * diag_text_cmdval.c - the constants of a COMMAND LANGUAGE (sh, batch, tcl): what a script computes in a variable or in a word, evaluated and told like the right sides of php's assignments.
 *
 * These languages have no expressions. A value is a WORD, and a word is read by the language's own reader (libgenome/textual: kgenome_textual_word_read tells the pieces - a literal in any of
 * its quotings, a variable, an expansion of one, the output of a command), so this file knows no quote and no operator: it asks for the pieces, gives each its value, and runs what a piece
 * asks for through THE SAME PATH the other languages use - the language's function table (its rows of shape EXPAND and CMD), kgenome_textual_fn_run and the engine's hook, kuncoat's
 * ops. `${x//a/b}`, batch's `%x:a=b%` and php's str_replace are one REPLACE; there is no string algorithm here.
 *
 * WHAT A VARIABLE IS. The same rule as the typed languages (the walk's `strict`): one assignment, at the top level, to a name nothing else writes. The reader tells what each command assigns; a
 * name counts as written by anything else when it appears in the text other than as a read (`$x`, `${x`, batch's `%x%`): `read x`, `unset x`, `for x in`, `export x`, a word in a string, a comment.
 * That is a plain scan of the SOURCE for the name, and it is stricter than the languages' grammars on purpose - a variable is trusted only when nothing in the file so much as mentions it again.
 * An assignment inside a group (`{ }`, `( )`, a batch block, where batch expands the whole block before it runs) or a function, an environment prefix (`x=1 cmd`), `local`, `+=`, and every
 * command that runs text (`eval`, `source`, tcl's `uplevel`, `upvar`, `subst`) make a name unknown. A name never assigned in the file is unknown: it may be in the environment.
 *
 * WHAT IS TOLD. For the right side of an assignment, and for every other word that holds an expansion or a command's output (and, in the shell and tcl, a word of several quoted pieces),
 * the value it comes to, when it is a computed one and not a literal as typed: on_const(range, value), written back as the language writes a literal (kgenome_textual_subst: the shell's and
 * tcl's double quotes, batch's raw text of plain bytes). A word of the shell with an unquoted expansion is told only when that expansion is one plain word: the shell would split the answer
 * into words and match it against files otherwise, and a literal in its place is not the same program.
 *
 * COMMAND SUBSTITUTION is the commands whose rows say they are pure functions of their words (echo, printf, rev, tr; tcl's string commands), a pipeline of them in the shell: the first
 * produces, the others read what the pipe carries (a row with STDIN). Anything else makes the word not constant.
 */

#include <stdlib.h>
#include <string.h>

#include <kofbytes.h>
#include <kofstrlist.h>

#include "diag_text_eval_private.h"
#include <textual/textual.h>

#define CV_DEPTH 8u
#define CV_NEST  32u
#define CV_NAME  200u
#define CV_ARGS  16u
#define CV_ASSIGNS 8u           /* the assignments of one command that are kept (`a=1 b=2 ... cmd`); a command that makes more says so */

struct cvar {
	uint32_t noff, nlen, voff, vlen, mentions;
	uint8_t  flags, n_assign, bad, state;
};

/* One command as the first pass read it (collect): its words and what it assigns, kept for the third pass (report) so the text's commands are read once. */
struct cmdrec {
	struct kgenome_textual_cmd cm;
	struct kgenome_textual_assign a[CV_ASSIGNS];
	uint32_t na;
};

struct cv {
	struct cmdrec *rec;                     /* the commands of the first pass, in order, when the constants will be told (x->on_const); NULL when none or when keeping was given up */
	uint32_t nrec, caprec;
	uint8_t rec_off;                        /* keeping was given up (the ledger or memory refused): the third pass reads the commands again */
	struct kgenome_dtx *x;
	struct kgenome_dtx_ev e;
	const uint8_t *in;
	uint32_t n, lang;
	struct cvar *v;
	uint32_t nv, cap;
	uint32_t *ht, htcap;
	uint32_t depth, nest;
	uint32_t work, work_cap;
	uint8_t dyn, fold;
	struct kgenome_dtx_val *cache;          /* one value per variable, kept once evaluated (a copy: the variable's own text is read again by whoever asks) */
};

/* The reader kept open for the scan (kgenome_dtx_cv_get): the variables collected once, whoever reads them. */
struct kgenome_dtx_cv {
	struct cv c;
};

/* ---- the variables -------------------------------------------------------------------------------------- */

/* The hash of the variable a slot of `ht` names (the slot holds its position + 1), by its name in the source. */
static uint32_t cv_hash(void *ctx, const void *slot)
{
	const struct cv *c = ctx;
	const struct cvar *v = &c->v[*(const uint32_t *)slot - 1u];

	return kgenome_dtx_name_hash(c->x->seed, c->in + v->noff, v->nlen, c->fold);
}

static struct cvar *cv_find(struct cv *c, const uint8_t *name, uint32_t n, int make)
{
	uint32_t h, i;

	if (!n)
		return NULL;
	if (n > CV_NAME) {                      /* a variable named with more than the reader looks up: not followed, and said */
		kgenome_dtx_cut(c->x);
		return NULL;
	}
	if (make) {
		uint32_t nc = kgenome_oatab_want(c->nv, c->htcap, 64u);

		if (nc && !kgenome_oatab_rehash((void **)&c->ht, &c->htcap, nc, sizeof *c->ht, cv_hash, c, &c->x->probes))
			return NULL;
	}
	if (!c->htcap)
		return NULL;
	h = kgenome_dtx_name_hash(c->x->seed, name, n, c->fold);
	for (i = h & (c->htcap - 1u); c->ht[i]; i = kgenome_oatab_next(i, c->htcap), c->x->probes++) {
		struct cvar *v = &c->v[c->ht[i] - 1u];

		if (v->nlen == n && kgenome_dtx_name_eq(c->in + v->noff, name, n, c->fold))
			return v;
	}
	if (!make)
		return NULL;
	if (c->nv == c->cap) {
		uint32_t nc = c->cap ? c->cap * 2u : 32u;
		struct cvar *nv = realloc(c->v, (size_t)nc * sizeof *nv);
		struct kgenome_dtx_val *ncache = realloc(c->cache, (size_t)nc * sizeof *ncache);

		if (!nv || !ncache) {
			if (nv)
				c->v = nv;
			if (ncache)
				c->cache = ncache;
			kgenome_diag_note(c->x->s, KGENOME_NOMEM);
			return NULL;
		}
		c->v = nv;
		c->cache = ncache;
		c->cap = nc;
	}
	memset(&c->v[c->nv], 0, sizeof c->v[0]);
	memset(&c->cache[c->nv], 0, sizeof c->cache[0]);
	c->v[c->nv].noff = (uint32_t)(name - c->in);
	c->v[c->nv].nlen = n;
	c->ht[i] = ++c->nv;
	return &c->v[c->nv - 1u];
}

static int ident_name(struct cv *c, const uint8_t *p, uint32_t n)
{
	uint32_t i;

	if (!n)
		return 0;
	for (i = 0; i < n; i++)
		if (!kof_is_word_byte(p[i]))
			return 0;
	if (n > CV_NAME) {                      /* a name the reader does not keep: the variable is not followed, and said */
		kgenome_dtx_cut(c->x);
		return 0;
	}
	return 1;
}

/* A command that runs text: no name is trusted in a file that has one. */
static int runs_text(const struct cv *c, const struct kgenome_textual_cmd *cm)
{
	static const char *const sh[] = { "eval", "source", ".", NULL };
	static const char *const tcl[] = { "eval", "uplevel", "upvar", "subst", "source", "interp", "trace", "namespace", NULL };
	const char *const *l = c->lang == KGENOME_TEXTUAL_LANG_SH ? sh : c->lang == KGENOME_TEXTUAL_LANG_TCL ? tcl : NULL;
	uint32_t k;

	if (!cm->n)
		return 0;
	for (k = 0; l && l[k]; k++)
		if (kgenome_textual_range_is(c->in, cm->w[0], l[k]))
			return 1;
	return 0;
}

/*
 * Keep one command for the third pass. Charged to the scan's ledger like its other tables, and never at the price of the scan: when the ledger or memory refuses, the records are
 * dropped and the third pass reads the commands again (the same answer, the cost it always had) - nothing is noted and nothing is lost.
 */
/* The assignments a command makes, at most CV_ASSIGNS of them: one more is asked for, and a command that has it is said to have been cut (it was read for eight and the rest dropped without a word).
 * `a` has room for CV_ASSIGNS + 1. */
static uint32_t read_assigns(struct cv *c, const struct kgenome_textual_cmd *cm, struct kgenome_textual_assign *a)
{
	uint32_t na = kgenome_textual_cmd_assigns(c->lang, c->in, cm, a, CV_ASSIGNS + 1u);

	if (na > CV_ASSIGNS) {
		kgenome_dtx_cut(c->x);
		na = CV_ASSIGNS;
	}
	return na;
}

static void rec_keep(struct cv *c, const struct kgenome_textual_cmd *cm, const struct kgenome_textual_assign *a, uint32_t na)
{
	struct cmdrec *r;

	if (c->rec_off || !c->x->on_const || c->x->layer)
		return;
	if (c->nrec == c->caprec) {
		uint32_t nc = c->caprec ? c->caprec * 2u : 64u;
		struct cmdrec *nr = NULL;

		if (kgenome_ledger_charge(&c->x->s->led, (uint64_t)(nc - c->caprec) * sizeof *nr))
			nr = realloc(c->rec, (size_t)nc * sizeof *nr);
		if (!nr) {
			free(c->rec);
			c->rec = NULL;
			c->nrec = c->caprec = 0;
			c->rec_off = 1;
			return;
		}
		c->rec = nr;
		c->caprec = nc;
	}
	r = &c->rec[c->nrec++];
	r->cm = *cm;
	memcpy(r->a, a, na * sizeof *a);
	r->na = na;
}

/* Pass 1: what each command assigns. */
static void collect(struct cv *c)
{
	struct kgenome_textual_cmd cm;
	uint32_t pos = 0;
	int depth = 0;

	memset(&cm, 0, sizeof cm);
	while (pos < c->n && kgenome_textual_cmd_read(c->lang, c->in, pos, c->n, &cm)) {
		struct kgenome_textual_assign a[CV_ASSIGNS + 1u];
		uint32_t na, k;

		if (runs_text(c, &cm))
			c->dyn = 1;
		na = read_assigns(c, &cm, a);
		rec_keep(c, &cm, a, na);
		for (k = 0; k < na; k++) {
			struct cvar *v;

			if (!ident_name(c, c->in + a[k].name.off, a[k].name.len))
				continue;
			v = cv_find(c, c->in + a[k].name.off, a[k].name.len, 1);
			if (!v)
				continue;
			if (v->n_assign < 255u)
				v->n_assign++;
			v->voff = a[k].value.off;
			v->vlen = a[k].value.len;
			v->flags = a[k].flags;
			if ((a[k].flags & (KGENOME_TEXTUAL_ASSIGN_ENV | KGENOME_TEXTUAL_ASSIGN_LOCAL | KGENOME_TEXTUAL_ASSIGN_UNREAD)) || depth > 0)
				v->bad = 1;
		}
		if (c->lang == KGENOME_TEXTUAL_LANG_SH && cm.n)         /* a brace group: what is inside is not at the top level */
			depth += kgenome_textual_range_is(c->in, cm.w[0], "{") ? 1 : kgenome_textual_range_is(c->in, cm.w[0], "}") ? -1 : 0;
		if (c->lang != KGENOME_TEXTUAL_LANG_TCL)
			depth += cm.paren;
		if (depth < 0)
			depth = 0;
		pos = cm.end > pos ? cm.end : pos + 1u;
	}
}

/* Pass 2: how many times each assigned name is written in the source other than as a read. */
static void census(struct cv *c)
{
	const uint8_t *in = c->in;
	uint32_t i = 0;
	int bat = c->lang == KGENOME_TEXTUAL_LANG_BAT;

	while (i < c->n) {
		uint32_t e;
		struct cvar *v;

		if (!kof_is_word_byte(in[i])) {
			i++;
			continue;
		}
		for (e = i; e < c->n && kof_is_word_byte(in[e]); e++)
			;
		v = cv_find(c, in + i, e - i, 0);
		if (v) {
			int read;

			if (bat)
				read = i && in[i - 1u] == '%' && e < c->n && (in[e] == '%' || in[e] == ':');
			else
				read = i && (in[i - 1u] == '$' || (in[i - 1u] == '{' && i > 1u && in[i - 2u] == '$') ||
					     (in[i - 1u] == '#' && i > 2u && in[i - 2u] == '{' && in[i - 3u] == '$'));
			if (!read && v->mentions < 0xffffu)
				v->mentions++;
		}
		i = e;
	}
}

/* ---- words --------------------------------------------------------------------------------------------------- */

struct wres {
	struct kgenome_dtx_val v;
	struct kgenome_dtx_list l;
	uint32_t pieces, ops, lits, vars;
	uint8_t  split;         /* the word is an argument: an unquoted expansion must be one plain word */
};

struct wsink {
	struct cv *c;
	struct wres *w;
};

static int read_word(struct cv *c, uint32_t from, uint32_t limit, uint32_t ctx, struct wres *w, uint32_t *end);
static int cmdsub(struct cv *c, struct kgenome_textual_range r, struct kgenome_dtx_val *out, struct kgenome_dtx_list *lout);

static void wres_free(struct wres *w)
{
	kgenome_dtx_val_free(&w->v);
	kgenome_dtx_ev_list_free(&w->l);
}

/* The value of the variable written at name, appended to `out`. */
static int var_value(struct cv *c, struct kgenome_textual_range name, struct kgenome_dtx_val *out);

/* A value that comes from an expansion or a command goes into the word, once it is one the language would not split and match against files where it is not quoted. */
static int put_expansion(struct wsink *s, const struct kgenome_dtx_val *v, int quoted)
{
	if (!quoted && s->w->split && s->c->x->lang->cmd_split && !kof_bytes_plain_word(v->p, v->n))
		return 0;
	return kgenome_dtx_ev_val_put(s->c->x, &s->w->v, v->p, v->n);
}

static int s_lit(void *u, const uint8_t *p, uint32_t n)
{
	struct wsink *s = u;

	s->w->pieces++;
	s->w->lits++;
	return kgenome_dtx_ev_val_put(s->c->x, &s->w->v, p, n);
}

static int s_var(void *u, struct kgenome_textual_range name, int quoted)
{
	struct wsink *s = u;
	struct kgenome_dtx_val t = { 0 };
	int ok;

	s->w->pieces++;
	s->w->vars++;
	ok = var_value(s->c, name, &t) && put_expansion(s, &t, quoted);
	kgenome_dtx_val_free(&t);
	return ok;
}

static int s_expand(void *u, struct kgenome_textual_range name, uint32_t row, const struct kgenome_textual_range *arg, uint32_t n_arg, int quoted)
{
	struct wsink *s = u;
	struct cv *c = s->c;
	struct kgenome_dtx_val a[3] = { { 0 }, { 0 }, { 0 } }, res = { 0 };
	struct kgenome_textual_fn f;
	const char *spelled;
	uint32_t k;
	int ok = 0;

	s->w->pieces++;
	s->w->ops++;
	if (n_arg > 2u || !kgenome_textual_fn_row(c->lang, row, &spelled, &f))
		return 0;
	if (!var_value(c, name, &a[0]))
		goto out;
	for (k = 0; k < n_arg; k++) {
		struct wres ow = { 0 };
		uint32_t end;

		if (!read_word(c, arg[k].off, arg[k].off + arg[k].len, c->lang == KGENOME_TEXTUAL_LANG_BAT ? KGENOME_TEXTUAL_CTX_TEXT : KGENOME_TEXTUAL_CTX_OPERAND, &ow, &end) ||
		    end != arg[k].off + arg[k].len || ow.l.on || !kgenome_dtx_ev_val_put(c->x, &a[1u + k], ow.v.p, ow.v.n)) {
			wres_free(&ow);
			goto out;
		}
		wres_free(&ow);
	}
	if (!kgenome_dtx_ev_run_row(&c->e, &f, a, 1u + n_arg, &res) || !put_expansion(s, &res, quoted))
		goto out;
	ok = 1;
out:
	for (k = 0; k < 3u; k++)
		kgenome_dtx_val_free(&a[k]);
	kgenome_dtx_val_free(&res);
	return ok;
}

static int s_cmd(void *u, struct kgenome_textual_range inner, int quoted)
{
	struct wsink *s = u;
	struct kgenome_dtx_val t = { 0 };
	struct kgenome_dtx_list l = { 0 };
	int ok = 0;

	s->w->pieces++;
	s->w->ops++;
	if (cmdsub(s->c, inner, &t, &l)) {
		if (l.on) {                     /* a list is the whole of the word or no value: a join takes it from the word */
			ok = s->w->pieces == 1u && !s->w->v.n;
			if (ok) {
				kgenome_dtx_ev_list_free(&s->w->l);
				s->w->l = l;
				memset(&l, 0, sizeof l);
			}
		} else {
			ok = put_expansion(s, &t, quoted);
		}
	}
	kgenome_dtx_val_free(&t);
	kgenome_dtx_ev_list_free(&l);
	return ok;
}

/* One word at `from`, its value in `w` (a list in w->l when it is one command's answer), where it ends in `*end`. */
static int read_word(struct cv *c, uint32_t from, uint32_t limit, uint32_t ctx, struct wres *w, uint32_t *end)
{
	struct wsink s = { c, w };
	struct kgenome_textual_word_sink sk = { &s, s_lit, s_var, s_expand, s_cmd };
	uint32_t e;

	if (c->nest >= CV_NEST || ++c->work > c->work_cap) {            /* a word nested past what is read, or the work spent on this text: said, not "not constant" */
		kgenome_dtx_ev_cut(c->x);
		return 0;
	}
	c->nest++;
	e = kgenome_textual_word_read(c->lang, c->in, from, limit, ctx, &sk);
	c->nest--;
	if (!e)
		return 0;
	if (w->l.on && (w->pieces > 1u || w->v.n))
		return 0;
	*end = e;
	return 1;
}

/* The text of an assignment's value, read as the language says: a word, or batch's raw text, or tcl's words joined. 1 and the value in `w`. */
static int value_text(struct cv *c, uint32_t voff, uint32_t vlen, uint8_t flags, struct wres *w)
{
	uint32_t end, pos = voff, vend = voff + vlen;

	if (!vlen)
		return 1;
	if (flags & KGENOME_TEXTUAL_ASSIGN_RAW)
		return read_word(c, voff, vend, KGENOME_TEXTUAL_CTX_TEXT, w, &end) && end == vend;
	if (flags & KGENOME_TEXTUAL_ASSIGN_WORDS) {
		while (pos < vend) {
			while (pos < vend && (c->in[pos] == ' ' || c->in[pos] == '\t'))
				pos++;
			if (pos >= vend)
				break;
			if (!read_word(c, pos, vend, KGENOME_TEXTUAL_CTX_WORD, w, &end) || end <= pos)
				return 0;
			pos = end;
		}
		return !w->l.on;
	}
	return read_word(c, voff, vend, c->lang == KGENOME_TEXTUAL_LANG_SH ? KGENOME_TEXTUAL_CTX_ASSIGN : KGENOME_TEXTUAL_CTX_WORD, w, &end) && end == vend;
}

static int var_value(struct cv *c, struct kgenome_textual_range name, struct kgenome_dtx_val *out)
{
	struct cvar *v = cv_find(c, c->in + name.off, name.len, 0);
	uint32_t idx;
	struct wres w = { 0 };
	int ok;

	if (!v || v->bad || c->dyn || v->n_assign != 1u || v->mentions != 1u || (v->flags & (KGENOME_TEXTUAL_ASSIGN_UNREAD | KGENOME_TEXTUAL_ASSIGN_ENV | KGENOME_TEXTUAL_ASSIGN_LOCAL)))
		return 0;
	idx = (uint32_t)(v - c->v);
	if (v->state == 2u)                                     /* evaluated before: the value kept */
		return kgenome_dtx_ev_val_put(c->x, out, c->cache[idx].p, c->cache[idx].n);
	if (v->state == 1u || v->state == 3u)                  /* being evaluated (a cycle), or known not to be a constant */
		return 0;
	if (c->depth >= CV_DEPTH) {                             /* a chain of variables deeper than the reader follows: said */
		kgenome_dtx_ev_cut(c->x);
		return 0;
	}
	v->state = 1;
	c->depth++;
	ok = value_text(c, v->voff, v->vlen, v->flags, &w) && !w.l.on;
	c->depth--;
	v->state = 0;
	if (!ok) {
		v->state = 3;
	} else {
		ok = kgenome_dtx_ev_val_put(c->x, out, w.v.p, w.v.n);
		if (ok && w.v.n <= 65536u) {                    /* a value that is not large is kept (a copy of it: the caller owns `out`) */
			c->cache[idx] = w.v;
			memset(&w.v, 0, sizeof w.v);
			v->state = 2;
		}
	}
	wres_free(&w);
	return ok;
}

/* ---- command substitution ---------------------------------------------------------------------------------------- */

/* One command of a substitution: its row, its arguments, run. `in` is what the pipe carries into it, NULL for the first. The answer in `res`, a list in `lres`. */
static int stage(struct cv *c, const struct kgenome_textual_cmd *cm, const struct kgenome_dtx_val *in, struct kgenome_dtx_val *res, struct kgenome_dtx_list *lres)
{
	struct wres av[CV_ARGS];
	struct kgenome_dtx_val a[CV_ARGS], name = { 0 };
	struct kgenome_textual_fn f;
	struct wres w0 = { 0 };
	uint8_t list[4096];
	uint64_t lw = 0;
	uint32_t first, n_args = 0, k, end, na = 0, i;
	int ok = 0;

	memset(av, 0, sizeof av);
	memset(a, 0, sizeof a);
	if (!cm->n || cm->redirect || cm->many)
		return 0;
	w0.split = 0;
	if (!read_word(c, cm->w[0].off, cm->w[0].off + cm->w[0].len, KGENOME_TEXTUAL_CTX_WORD, &w0, &end) || w0.l.on || end != cm->w[0].off + cm->w[0].len)
		goto out;
	if (!kgenome_dtx_ev_val_put(c->x, &name, w0.v.p, w0.v.n))
		goto out;
	first = 1;
	if (cm->n > 1u) {                                       /* a command named by two words ("string map") */
		struct wres w1 = { 0 };
		uint8_t buf[96];

		if (read_word(c, cm->w[1].off, cm->w[1].off + cm->w[1].len, KGENOME_TEXTUAL_CTX_WORD, &w1, &end) && !w1.l.on && w0.v.n + w1.v.n + 1u < sizeof buf) {
			/* an empty word has no bytes and no pointer (v.p is NULL, v.n 0): copying 0 bytes from NULL is undefined (C99 7.1.4), and -fsanitize=undefined reports it */
			if (w0.v.n)
				memcpy(buf, w0.v.p, w0.v.n);
			buf[w0.v.n] = ' ';
			if (w1.v.n)
				memcpy(buf + w0.v.n + 1u, w1.v.p, w1.v.n);
			if (kgenome_textual_fn_find(c->lang, buf, w0.v.n + 1u + w1.v.n, &f) && f.shape == KGENOME_TEXTUAL_SHAPE_CMD)
				first = 2;
		}
		wres_free(&w1);
	}
	if (first == 1u && (!kgenome_textual_fn_find(c->lang, w0.v.p, w0.v.n, &f) || f.shape != KGENOME_TEXTUAL_SHAPE_CMD))
		goto out;
	for (k = first; k < cm->n; k++) {
		if (na == CV_ARGS) {                    /* more arguments than a function of the table is run with */
			kgenome_dtx_ev_cut(c->x);
			goto out;
		}
		av[na].split = 1;
		if (!read_word(c, cm->w[k].off, cm->w[k].off + cm->w[k].len, KGENOME_TEXTUAL_CTX_WORD, &av[na], &end) || end != cm->w[k].off + cm->w[k].len)
			goto out;
		na++;
	}
	i = 0;
	while ((f.flags & KGENOME_TEXTUAL_FN_ECHOOPT) && i < na && !av[i].l.on) {          /* echo -n: no change to the value; -e and -E read backslashes */
		int o = kof_bytes_option(av[i].v.p, av[i].v.n, "n", "eE");

		if (o < 0)
			goto out;
		if (!o)
			break;
		i++;
	}
	if (f.flags & KGENOME_TEXTUAL_FN_COLLECT_ALL) {
		for (k = i; k < na; k++) {
			if (av[k].l.on || ((f.flags & KGENOME_TEXTUAL_FN_NOEDGE) && kof_bytes_edge_blank(av[k].v.p, av[k].v.n)) ||
			    kof_strlist_size(av[k].v.n) > sizeof list - lw)
				goto out;
			kof_strlist_put(list, &lw, av[k].v.p, av[k].v.n);
		}
		a[0] = (struct kgenome_dtx_val){ list, (uint32_t)lw, 0, 0 };
		a[1] = (struct kgenome_dtx_val){ (uint8_t *)(uintptr_t)f.set, (uint32_t)strlen(f.set), 0, 0 };
		n_args = 2;
	} else if (f.flags & KGENOME_TEXTUAL_FN_COLLECT_REST) {
		if (i >= na || av[i].l.on)
			goto out;
		for (k = i + 1u; k < na; k++) {
			if (av[k].l.on || kof_strlist_size(av[k].v.n) > sizeof list - lw)
				goto out;
			kof_strlist_put(list, &lw, av[k].v.p, av[k].v.n);
		}
		a[0] = av[i].v;
		a[1] = (struct kgenome_dtx_val){ list, (uint32_t)lw, 0, 0 };
		n_args = 2;
	} else {
		uint32_t base = 0;

		if (f.flags & KGENOME_TEXTUAL_FN_STDIN) {
			if (!in)
				goto out;
			a[0] = *in;
			base = 1;
		}
		if (base + (na - i) > CV_ARGS) {
			kgenome_dtx_ev_cut(c->x);
			goto out;
		}
		for (k = i; k < na; k++) {
			if (av[k].l.on && !(k == i && !base && f.op == KGENOME_TEXTUAL_DEC_JOIN))
				goto out;
			a[base + k - i] = av[k].v;
		}
		n_args = base + (na - i);
		if (f.op == KGENOME_TEXTUAL_DEC_JOIN && na > i && av[i].l.on) {           /* join of a list another command made: the list as it is, not text to be cut */
			f.opflags &= ~KGENOME_TEXTUAL_CALL_WSLIST;
			a[0] = (struct kgenome_dtx_val){ av[i].l.p, av[i].l.n, 0, 0 };
		}
	}
	if (!kgenome_dtx_ev_run_row(&c->e, &f, a, n_args, res))
		goto out;
	if (f.op == KGENOME_TEXTUAL_DEC_SPLIT) {                /* the answer is a list: moved, not copied */
		lres->p = res->p;
		lres->n = res->n;
		lres->cap = res->cap;
		lres->on = 1;
		memset(res, 0, sizeof *res);
	}
	ok = 1;
out:
	for (k = 0; k < CV_ARGS; k++)
		wres_free(&av[k]);
	wres_free(&w0);
	kgenome_dtx_val_free(&name);
	return ok;
}

/* The line breaks a command substitution takes off the end of what its commands wrote. */
static const struct kgenome_textual_fn rtrim_nl = {
	.op = KGENOME_TEXTUAL_DEC_RTRIM, .min_args = 1, .max_args = 1, .param = { KGENOME_TEXTUAL_FN_NONE, KGENOME_TEXTUAL_FN_NONE }, .form = KGENOME_TEXTUAL_FN_FORM_EVAL, .set = "\n",
};

static int cmdsub(struct cv *c, struct kgenome_textual_range r, struct kgenome_dtx_val *out, struct kgenome_dtx_list *lout)
{
	struct kgenome_textual_cmd cm;
	struct kgenome_dtx_val pipe_in = { 0 }, res = { 0 };
	struct kgenome_dtx_list lres = { 0 };
	uint32_t pos = r.off, lim = r.off + r.len;
	int have_in = 0, done = 0, ok = 0;

	if (c->nest >= CV_NEST) {
		kgenome_dtx_ev_cut(c->x);
		return 0;
	}
	c->nest++;
	memset(&cm, 0, sizeof cm);
	while (pos < lim && kgenome_textual_cmd_read(c->lang, c->in, pos, lim, &cm)) {
		pos = cm.end > pos ? cm.end : pos + 1u;
		if (!cm.n && !cm.redirect)
			continue;
		if (done || cm.andor || cm.paren || (cm.term && cm.term != '\n' && cm.term != '|'))
			goto out;               /* more than one command, or a list of them, or a background job: not a function of its words */
		if (!stage(c, &cm, have_in ? &pipe_in : NULL, &res, &lres))
			goto out;
		if (cm.pipe && cm.term == '|') {
			if (lres.on)
				goto out;
			kgenome_dtx_val_free(&pipe_in);
			pipe_in = res;
			memset(&res, 0, sizeof res);
			have_in = 1;
		} else {
			done = 1;
		}
	}
	if (!done)
		goto out;
	if (c->x->lang->cmd_strip && !lres.on) {
		struct kgenome_dtx_val t = { 0 };

		if (!kgenome_dtx_ev_run_row(&c->e, &rtrim_nl, &res, 1u, &t))
			goto out;
		kgenome_dtx_val_free(&res);
		res = t;
	}
	if (lres.on) {
		kgenome_dtx_ev_list_free(lout);
		*lout = lres;
		memset(&lres, 0, sizeof lres);
	} else if (!kgenome_dtx_ev_val_put(c->x, out, res.p, res.n)) {
		goto out;
	}
	ok = 1;
out:
	c->nest--;
	kgenome_dtx_val_free(&pipe_in);
	kgenome_dtx_val_free(&res);
	kgenome_dtx_ev_list_free(&lres);
	return ok;
}

/* ---- what is told -------------------------------------------------------------------------------------------------------- */

static void tell(struct cv *c, uint32_t off, uint32_t len, const struct wres *w)
{
	if (c->x->on_const && !w->l.on && !memchr(w->v.p ? w->v.p : (const uint8_t *)"", 0, w->v.n))
		c->x->on_const(c->x->const_user, off, len, w->v.p ? w->v.p : (const uint8_t *)"", w->v.n);
}

static int built(const struct wres *w)
{
	return w->ops || w->pieces >= 2u;
}

/* One command of pass 3: every assignment of it that can be evaluated, and - for a command that assigns nothing - the words with an operation in them. */
static void report_command(struct cv *c, const struct kgenome_textual_cmd *cm, const struct kgenome_textual_assign *a, uint32_t na)
{
	uint32_t k, own = 0, name_at;

	for (k = 0; k < na; k++)                /* `x=1 cmd args`: x is cmd's alone and the words after cmd are the command's arguments */
		own += (a[k].flags & KGENOME_TEXTUAL_ASSIGN_ENV) == 0;
	name_at = na - own;
	for (k = 0; k < na; k++) {
		struct cvar *v = ident_name(c, c->in + a[k].name.off, a[k].name.len) ? cv_find(c, c->in + a[k].name.off, a[k].name.len, 0) : NULL;
		struct wres w = { 0 };

		if (!v || v->bad || c->dyn || v->n_assign != 1u || v->mentions != 1u || (a[k].flags & (KGENOME_TEXTUAL_ASSIGN_UNREAD | KGENOME_TEXTUAL_ASSIGN_ENV | KGENOME_TEXTUAL_ASSIGN_LOCAL)))
			continue;
		if (a[k].value.len && value_text(c, a[k].value.off, a[k].value.len, a[k].flags, &w) && !w.l.on && built(&w) &&
		    !((a[k].flags & KGENOME_TEXTUAL_ASSIGN_CALL) && (memchr(w.v.p ? w.v.p : (const uint8_t *)"", '%', w.v.n) || memchr(w.v.p ? w.v.p : (const uint8_t *)"", '^', w.v.n))))
			tell(c, a[k].value.off, a[k].value.len, &w);
		wres_free(&w);
	}
	if (!own) {                             /* the words of a command that assigns nothing: an operation in a word is a value where it stands */
		for (k = name_at + 1u; k < cm->n && !cm->many; k++) {
			struct wres w = { 0 };
			uint32_t end;

			w.split = 1;
			if (read_word(c, cm->w[k].off, cm->w[k].off + cm->w[k].len, KGENOME_TEXTUAL_CTX_WORD, &w, &end) && end == cm->w[k].off + cm->w[k].len && !w.l.on &&
			    (w.ops || (w.lits >= 2u && !w.vars)))
				tell(c, cm->w[k].off, cm->w[k].len, &w);
			wres_free(&w);
		}
	}
}

/* Pass 3: every command, from the records of pass 1 when it kept them, else read again. */
static void report(struct cv *c)
{
	struct kgenome_textual_cmd cm;
	uint32_t pos = 0, k;

	if (c->rec && !c->rec_off) {
		for (k = 0; k < c->nrec; k++)
			report_command(c, &c->rec[k].cm, c->rec[k].a, c->rec[k].na);
		return;
	}
	memset(&cm, 0, sizeof cm);
	while (pos < c->n && kgenome_textual_cmd_read(c->lang, c->in, pos, c->n, &cm)) {
		struct kgenome_textual_assign a[8];
		uint32_t na = read_assigns(c, &cm, a);

		report_command(c, &cm, a, na);
		pos = cm.end > pos ? cm.end : pos + 1u;
	}
}

void kgenome_dtx_cmd_consts(struct kgenome_dtx *x)
{
	struct kgenome_dtx_cv *w;

	if (!x->on_const || x->layer || !x->n_in || !kgenome_textual_has_words(x->lang->id))
		return;
	/* the reader the path stage keeps open, or the one made now: the variables are collected and counted once for the text, whichever stage asks first */
	w = kgenome_dtx_cv_get(x);
	if (!w)
		return;
	w->c.work = 0;
	report(&w->c);
}

/* ---- the words of one command, for the identity of paths (diag_text_ident.c) ---------------------------------------------------- */

/*
 * The reader above, kept open for a few questions: the variables are collected and counted once (collect, census) and a command's words are then read as the walk reads any word of a
 * command line - the same single-assignment rule, the same expansions - and told as the constants they come to. Not told twice and not a second reader: diag_text_ident.c asks it for
 * the words of the commands that are nodes, so a path held in a variable (`P=/tmp/a; wget -O $P u; chmod +x $P`) is the same constant in both.
 */
static struct kgenome_dtx_cv *cv_new(struct kgenome_dtx *x)
{
	struct kgenome_dtx_cv *w;

	if (!x->lang->cmd_vals || !x->n_in || !kgenome_textual_has_words(x->lang->id))
		return NULL;
	if (!kgenome_dtx_charge(x, sizeof *w))
		return NULL;
	w = calloc(1, sizeof *w);
	if (!w)
		return NULL;
	w->c.x = x;
	w->c.e.x = x;
	w->c.in = x->in;
	w->c.n = x->n_in;
	w->c.lang = x->lang->id;
	w->c.fold = x->lang->fold;
	w->c.work_cap = 200000u + 16u * x->nt;
	collect(&w->c);
	if (w->c.nv)
		census(&w->c);
	return w;
}

struct kgenome_dtx_cv *kgenome_dtx_cv_get(struct kgenome_dtx *x)
{
	if (!x->cv_tried) {
		x->cv_tried = 1;
		x->cv = cv_new(x);
	}
	return x->cv;
}

uint32_t kgenome_dtx_cv_command(struct kgenome_dtx_cv *w, uint32_t off, struct kgenome_dtx_val *out, uint32_t *at, uint32_t max)
{
	struct kgenome_textual_cmd cm;
	uint32_t k, n = 0;

	memset(&cm, 0, sizeof cm);
	if (!kgenome_textual_cmd_read(w->c.lang, w->c.in, off, w->c.n, &cm))
		return 0;
	for (k = 0; k < cm.n && k < max; k++, n++) {
		struct wres wr = { 0 };
		uint32_t end;

		wr.split = 1;
		memset(&out[k], 0, sizeof out[k]);
		at[k] = cm.w[k].off;
		if (read_word(&w->c, cm.w[k].off, cm.w[k].off + cm.w[k].len, KGENOME_TEXTUAL_CTX_WORD, &wr, &end) && end == cm.w[k].off + cm.w[k].len && !wr.l.on) {
			out[k] = wr.v;
			memset(&wr.v, 0, sizeof wr.v);
		}
		wres_free(&wr);
	}
	return n;
}

void kgenome_dtx_cv_free(struct kgenome_dtx_cv *w)
{
	uint32_t k;

	if (!w)
		return;
	for (k = 0; k < w->c.nv; k++)
		kgenome_dtx_val_free(&w->c.cache[k]);
	free(w->c.cache);
	free(w->c.rec);
	free(w->c.v);
	free(w->c.ht);
	free(w);
}
