#define _GNU_SOURCE
/*
 * textual_quote - how each language writes a literal whose value is given (the row's `quote`, textual_lang.h; written by kgenome_textual_subst and by the
 * form's call stage), attacked rather than sampled.
 *
 * WHAT IS PINNED, for every language that has a quote row:
 *   - EXACT REFUSAL. kgenome_textual_subst_can says no for exactly the values the language cannot write - predicted here by a rule written from the
 *     language's own syntax (a line break in a vbscript string, "%>" in a page's island), never by the writer's table - and yes for the rest;
 *   - for every value the writer takes - each of the 256 bytes alone, every pair of bytes (65536), and 20000 random strings - the literal, put into the
 *     language's own statement, is ONE string to the lexer (one STRING span, the whole of the literal, closed), nothing else in the text is a string, and
 *     kgenome_textual_value on it gives back exactly the value;
 *   - python3 and perl read the same literals the same way (python: str literals of ASCII and UTF-8; perl: single-quoted bytes), where those interpreters
 *     are on the machine. The others (node, ruby, lua, pwsh, cscript, java) are not: [Unverified] against the real interpreter.
 */

#include "textual_check.h"

#include <unistd.h>
#include <sys/stat.h>

struct ctx {
	const char *name;
	uint32_t    lang;
	uint32_t    value_lang;     /* the row whose reader reads this one's literals (asp: vbscript's) */
	const char *pre, *post;
	int         refuses;        /* the oracle: which kind of value is refused (0 none, 1 vb, 2 page-ambiguous, 3 java page, 4 psh) */
};

static const struct ctx ctxs[] = {
	{ "php",  KGENOME_TEXTUAL_LANG_PHP,  KGENOME_TEXTUAL_LANG_PHP,  "<?php $a = ", ";\n", 0 },
	{ "js",   KGENOME_TEXTUAL_LANG_JS,   KGENOME_TEXTUAL_LANG_JS,   "var a = ", ";\n", 0 },
	{ "py",   KGENOME_TEXTUAL_LANG_PY,   KGENOME_TEXTUAL_LANG_PY,   "a = ", "\n", 0 },
	{ "perl", KGENOME_TEXTUAL_LANG_PERL, KGENOME_TEXTUAL_LANG_PERL, "$a = ", ";\n", 0 },
	{ "ruby", KGENOME_TEXTUAL_LANG_RUBY, KGENOME_TEXTUAL_LANG_RUBY, "a = ", "\n", 5 },
	{ "lua",  KGENOME_TEXTUAL_LANG_LUA,  KGENOME_TEXTUAL_LANG_LUA,  "a = ", "\n", 0 },
	{ "tcl",  KGENOME_TEXTUAL_LANG_TCL,  KGENOME_TEXTUAL_LANG_TCL,  "set a ", "\n", 0 },
	{ "sh",   KGENOME_TEXTUAL_LANG_SH,   KGENOME_TEXTUAL_LANG_SH,   "a=", "\n", 0 },
	{ "vbs",  KGENOME_TEXTUAL_LANG_VBS,  KGENOME_TEXTUAL_LANG_VBS,  "a = ", "\n", 1 },
	{ "cfm",  KGENOME_TEXTUAL_LANG_CFM,  KGENOME_TEXTUAL_LANG_CFM,  "<cfscript>a = ", ";</cfscript>\n", 0 },
	{ "psh",  KGENOME_TEXTUAL_LANG_PSH,  KGENOME_TEXTUAL_LANG_PSH,  "$a = ", "\n", 4 },
	{ "asp",  KGENOME_TEXTUAL_LANG_ASP,  KGENOME_TEXTUAL_LANG_VBS,  "<% a = ", " %>\n", 2 },
	{ "aspx", KGENOME_TEXTUAL_LANG_ASPX, KGENOME_TEXTUAL_LANG_ASPX, "<% string a = ", "; %>\n", 2 },
	{ "jsp",  KGENOME_TEXTUAL_LANG_JSP,  KGENOME_TEXTUAL_LANG_JSP,  "<% String a = ", "; %>\n", 3 },
};

/* The refusal, from the language's syntax and not from the table. */
static int has(const uint8_t *v, uint32_t n, const char *s)
{
	uint32_t i, l = (uint32_t)strlen(s);

	for (i = 0; i + l <= n; i++)
		if (!memcmp(v + i, s, l))
			return 1;
	return 0;
}

static int ctl(uint8_t b)
{
	return (b < 0x20u && b != '\t') || b == 0x7fu;
}

static int refused_by_syntax(int kind, const uint8_t *v, uint32_t n)
{
	uint32_t i;

	if (kind == 5)          /* ruby: a CR in the source is read as a line break and \r\n as \n */
		return has(v, n, "\r");
	if (kind == 3)
		return has(v, n, "%>") || has(v, n, "</script");
	for (i = 0; i < n; i++) {
		if (kind == 1 && ctl(v[i]))
			return 1;
		if (kind == 2 && (ctl(v[i]) || v[i] == '"' || v[i] == '\\'))
			return 1;
		if (kind == 4 && v[i] == 0xE2u)
			return 1;
	}
	return kind == 2 && (has(v, n, "%>") || has(v, n, "</script"));
}

struct one {
	uint32_t at, len;
	unsigned n_str;
	uint8_t  open;
};

static int pick(void *u, const struct kgenome_textual_span *s)
{
	struct one *o = u;

	if (s->kind == KGENOME_TEXTUAL_STRING) {
		o->at = s->off;
		o->len = s->len;
		o->n_str++;
		o->open |= (s->flags & KGENOME_TEXTUAL_F_OPEN) != 0;
	}
	return 1;
}

struct grabbed {
	struct kgenome_textual_span s;
	int have;
};

static int grab(void *u, const struct kgenome_textual_span *x)
{
	struct grabbed *t = u;

	if (x->kind == KGENOME_TEXTUAL_STRING && !t->have) {
		t->s = *x;
		t->have = 1;
	}
	return 1;
}

static uint32_t prng = 0x9e3779b9u;

static uint32_t rnd(void)
{
	prng ^= prng << 13;
	prng ^= prng >> 17;
	prng ^= prng << 5;
	return prng;
}

/* One value in one language: refusal exact; when written, one string, closed, whose value is the value. 0 when it was refused. */
static int one_value(const struct ctx *c, const uint8_t *v, uint32_t n, uint8_t *lit_out, uint32_t *lit_n)
{
	static uint8_t text[1024], lit[1024], got[1024];
	uint32_t pre = (uint32_t)strlen(c->pre), post = (uint32_t)strlen(c->post), w, vn = 0;
	int can = kgenome_textual_subst_can(c->lang, v, n), want = !refused_by_syntax(c->refuses, v, n);
	struct kgenome_textual_subst s = { pre, 1, v, n, 0 };
	struct one o = { 0 };
	struct kgenome_textual_lex_req q;
	struct kgenome_textual_lex_res lr;
	struct kgenome_textual_value_req vr;
	struct kgenome_textual_value_res vres;

	if (can != want) {
		printf("  FAIL %s: refusal differs for a value of %u bytes (first %02x): writer %d, syntax %d\n", c->name, n, n ? v[0] : 0, can, want);
		fails++;
		return 0;
	}
	if (!can)
		return 0;
	memcpy(text, c->pre, pre);
	text[pre] = '0';
	memcpy(text + pre + 1u, c->post, post);
	w = kgenome_textual_subst(c->lang, text, pre + 1u + post, &s, 1, lit, sizeof lit);
	if (!w) {
		printf("  FAIL %s: subst refused a value can() took (%u bytes)\n", c->name, n);
		fails++;
		return 0;
	}
	/* the literal is the text between pre and post */
	memcpy(got, lit, w);
	q = (struct kgenome_textual_lex_req){ .in = lit, .n = w, .lang = c->lang, .sink = pick, .user = &o };
	kgenome_textual_lex(&q, &lr);
	if (o.n_str != 1u || o.open || o.at != pre || o.len != w - pre - post) {
		printf("  FAIL %s: the written literal is not one closed string (%u strings, open %u, at %u len %u of %u) for a value of %u bytes, first %02x\n", c->name,
		       o.n_str, o.open, o.at, o.len, w, n, n ? v[0] : 0);
		fails++;
		return 0;
	}
	vr = (struct kgenome_textual_value_req){ .lang = c->value_lang, .lit = lit + o.at, .len = o.len, .open_len = 1, .close_len = 1,
						 .flags = KGENOME_TEXTUAL_F_INTERP, .out = got, .cap = o.len };
	/* the flags a span carries are the lexer's: ask for them */
	{
		struct grabbed sp = { { 0 }, 0 };

		q.sink = grab;
		q.user = &sp;
		kgenome_textual_lex(&q, &lr);
		vr.flags = sp.s.flags;
		vr.open_len = sp.s.open_len;
		vr.close_len = sp.s.close_len;
	}
	if (kgenome_textual_value(&vr, &vres) != KGENOME_TEXTUAL_OK || vres.n_out != n || (n && memcmp(got, v, n))) {
		printf("  FAIL %s: the value did not come back (%u bytes in, %u out), first %02x\n", c->name, n, vres.n_out, n ? v[0] : 0);
		fails++;
		return 0;
	}
	(void)vn;
	*lit_n = o.len;
	memcpy(lit_out, lit + o.at, o.len);
	return 1;
}

/* A file of literals for an interpreter to read back: the value as hex, and the literal, one per record. */
struct dump {
	FILE *f;
	unsigned n;
};

static void dump_put(struct dump *d, const uint8_t *v, uint32_t vn, const uint8_t *lit, uint32_t ln)
{
	uint32_t i;

	if (!d->f)
		return;
	for (i = 0; i < vn; i++)
		fprintf(d->f, "%02x", v[i]);
	fputc(' ', d->f);
	for (i = 0; i < ln; i++)
		fprintf(d->f, "%02x", lit[i]);
	fputc('\n', d->f);
	d->n++;
}

static void run_lang(const struct ctx *c, struct dump *py, struct dump *pl)
{
	static uint8_t v[16], lit[1024];
	unsigned a, b, it;
	uint32_t ln;

	for (a = 0; a < 256u; a++) {
		v[0] = (uint8_t)a;
		(void)one_value(c, v, 1, lit, &ln);
		for (b = 0; b < 256u; b++) {
			v[1] = (uint8_t)b;
			(void)one_value(c, v, 2, lit, &ln);
		}
	}
	(void)one_value(c, v, 0, lit, &ln);
	for (it = 0; it < 20000u; it++) {
		static const char hot[] = "'\"\\\n\r\t%>$[]{}#<&/ \x01\x7f";
		uint32_t n = rnd() % 14u, i;

		for (i = 0; i < n; i++)
			v[i] = (uint8_t)(rnd() % 3u ? (uint8_t)hot[rnd() % (sizeof hot - 1u)] : (uint8_t)rnd());
		if (one_value(c, v, n, lit, &ln)) {
			if (c->lang == KGENOME_TEXTUAL_LANG_PY) {
				uint32_t k;
				int ascii = 1;

				for (k = 0; k < n; k++)
					ascii &= v[k] < 0x80u;
				if (ascii)
					dump_put(py, v, n, lit, ln);
			} else if (c->lang == KGENOME_TEXTUAL_LANG_PERL) {
				dump_put(pl, v, n, lit, ln);
			}
		}
	}
}

/* Read the file back with the interpreter: a line is the hex of the value, a blank, and the hex of the literal's source; the interpreter prints the hex of
 * what the literal is, one line each, and the two must be the same. */
static void interpret(const char *name, const char *dir, const char *script, struct dump *d, const char *data)
{
	char cmd[1024], line[1024], want[1024];
	FILE *p, *f;
	unsigned n = 0, bad = 0;

	if (!d->n)
		return;
	snprintf(cmd, sizeof cmd, "%s/%s.script", dir, name);
	f = fopen(cmd, "w");
	if (!f)
		return;
	fputs(script, f);
	fclose(f);
	snprintf(cmd, sizeof cmd, "%s %s/%s.script %s 2>&1", !strcmp(name, "py") ? "python3 -I" : "perl", dir, name, data);
	p = popen(cmd, "r");
	if (!p) {
		printf("  %s interpreter not run\n", name);
		fails++;
		return;
	}
	f = fopen(data, "rb");
	while (f && fgets(want, sizeof want, f)) {
		char *sp = strchr(want, ' ');

		if (sp)
			*sp = 0;
		if (!fgets(line, sizeof line, p)) {
			bad++;
			break;
		}
		line[strcspn(line, "\n")] = 0;
		if (strcmp(line, want) && bad++ < 3u)
			printf("  FAIL %s read record %u as [%s], the value is [%s]\n", name, n, line, want);
		n++;
	}
	if (f)
		fclose(f);
	if (fgets(line, sizeof line, p) && bad < 3u) {
		printf("  FAIL %s printed more than it was given: %s\n", name, line);
		bad++;
	}
	pclose(p);
	if (bad)
		fails++;
	else
		printf("  %s: %u literals read back by the real interpreter, all equal\n", name, n);
}

int main(void)
{
	char dir[256], pyd[300], pld[300];
	unsigned i;
	struct dump py = { NULL, 0 }, pl = { NULL, 0 };

	snprintf(dir, sizeof dir, "build/kof_quote_XXXXXX");
	if (mkdtemp(dir)) {
		snprintf(pyd, sizeof pyd, "%s/py.data", dir);
		snprintf(pld, sizeof pld, "%s/perl.data", dir);
		py.f = fopen(pyd, "wb");
		pl.f = fopen(pld, "wb");
	}
	for (i = 0; i < sizeof ctxs / sizeof ctxs[0]; i++)
		run_lang(&ctxs[i], &py, &pl);
	/* the shell writes a double-quoted word (above, with the rest); batch has no literal and writes a value as it is, when every byte is one no part of the line can read
	 * as something else - and refuses an empty one, a blank, & | < > ^ ( ) % ! " , ; = and a control byte (this pinned "sh and batch write no literal" until the command languages' values were read) */
	CK(kgenome_textual_subst_can(KGENOME_TEXTUAL_LANG_BAT, (const uint8_t *)"a", 1));
	CK(kgenome_textual_subst_can(KGENOME_TEXTUAL_LANG_BAT, (const uint8_t *)"C:\\Temp\\x.exe", 13));
	CK(!kgenome_textual_subst_can(KGENOME_TEXTUAL_LANG_BAT, (const uint8_t *)"", 0));
	{
		static const char bad[] = " &|<>^()%!\",;=\t\r\n*?";
		uint8_t v[3] = { 'a', 0, 'b' };
		unsigned k;

		for (k = 0; k < sizeof bad - 1u; k++) {
			v[1] = (uint8_t)bad[k];
			if (kgenome_textual_subst_can(KGENOME_TEXTUAL_LANG_BAT, v, 3)) {
				printf("  FAIL batch writes %02x in a value\n", v[1]);
				fails++;
			}
		}
		for (k = 0; k < 256u; k++) {
			static const char plain[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-:\\/+@#$";
			uint8_t b = (uint8_t)k;

			if ((kgenome_textual_subst_can(KGENOME_TEXTUAL_LANG_BAT, &b, 1) != 0) != (k && memchr(plain, (int)k, sizeof plain - 1u) != NULL)) {
				printf("  FAIL batch and the byte %02x\n", k);
				fails++;
			}
		}
	}
	CK(!kgenome_textual_subst_can(9999u, (const uint8_t *)"a", 1));
	if (py.f && pl.f) {
		fclose(py.f);
		fclose(pl.f);
		py.f = pl.f = NULL;
		interpret("py", dir, "import ast,sys\nfor r in open(sys.argv[1]):\n    h,l=r.rstrip('\\n').split(' ')\n    print(ast.literal_eval(bytes.fromhex(l).decode('utf-8')).encode('utf-8').hex())\n", &py, pyd);
		interpret("perl", dir, "open(F,'<',$ARGV[0]) or die; while(<F>){ my ($h,$l)=split; my $v=eval pack('H*',$l); die $@ if $@; print unpack('H*',$v),\"\\n\"; }\n", &pl, pld);
	}
	{
		char f[320];
		static const char *const names[] = { "py.data", "perl.data", "py.script", "perl.script" };
		unsigned k;

		for (k = 0; k < 4u; k++) {
			snprintf(f, sizeof f, "%s/%s", dir, names[k]);
			(void)unlink(f);
		}
		(void)rmdir(dir);
	}
	printf("textual quote: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
