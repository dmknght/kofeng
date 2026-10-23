/*
 * genome / textual_bat - the windows batch lexer and form of the textual part, through <kgenome.h> alone.
 *
 * There is no cmd.exe here, so nothing below is an oracle in the sense of a second implementation of cmd. What
 * is asserted, and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS, one per rule with the neighbour it could be confused for (a case is the text and the
 *       one line it must come out as: textual_check.h). A case marked [Unverified] is a decision the lexer makes
 *       where the author could not check what cmd does, and says which side it errs on.
 *   (b) A GENERATOR of programs with a known structure: every piece is written with the class the generator
 *       says it has - code, string (and whether it holds a variable, and whether it was closed), comment - and the
 *       lexer's spans must equal that list byte for byte. Three line-ending styles, an optional UTF-8 BOM.
 *   (c) A SECOND READING, LINE BASED, of the same text (`oracle`): it splits on "\n", asks of each line whether
 *       it begins with REM or "::" or ":" and counts the quotes of a line, with no state kept between bytes. It
 *       agrees with the lexer on the generated programs and on word soup, and is the check the corpus run
 *       (`textual_bat <file>...`) counts differences with.
 *   (d) THE PARTITION and the idempotence of the form on random text, a text cut at every length, hostile
 *       texts (a deep run of "(" and "^", a huge string that never closes, NUL bytes) read in linear time.
 *   (e) FORM, VALUE and decoder known answers.
 *
 * Run with file names, it reads each file: partition, form of the form, the oracle, and the numbers.
 */

#include "textual_check.h"

#include <ctype.h>
#include <time.h>

#define BAT KGENOME_TEXTUAL_LANG_BAT

static void bat(const char *src, const char *want)
{
	expect_lang(BAT, src, want);
}

static void fm(const char *src, const char *want)
{
	form_lang(BAT, src, want);
}

/* ---- (a) known answers ---- */

static void rem_words(void)
{
	/* the word REM at the start of a line, in any case, after blanks and "@": a comment to the end of the line */
	bat("rem x", "K{rem x}");
	bat("REM", "K{REM}");
	bat("rEm x", "K{rEm x}");
	bat("  \t rem x", "C{  \t }K{rem x}");
	bat("@rem x", "C{@}K{rem x}");
	bat("@@ rem x", "C{@@ }K{rem x}");
	bat("(rem x)", "C{(}K{rem x)}");
	/* what ends the word: a blank, a delimiter, a byte that is no name byte and no operator */
	bat("rem\tx rem,x rem;x", "K{rem\tx rem,x rem;x}");
	bat("rem,x", "K{rem,x}");
	bat("rem;x", "K{rem;x}");
	bat("REM=\"\"\"", "K{REM=\"\"\"}");
	bat("rem. text", "K{rem. text}");
	bat("rem-----", "K{rem-----}");
	bat("rem:x", "K{rem:x}");
	bat("rem/?", "K{rem/?}");
	/* a longer name is a command, whatever it begins with; a byte of 0x80 or more is a name byte */
	bat("remote x", "C{remote x}");
	bat("rem1", "C{rem1}");
	bat("rem_x", "C{rem_x}");
	bat("rem\xc3\xa9", "C{rem\xc3\xa9}");
	bat("re", "C{re}");
	bat("rm x", "C{rm x}");
	/* [Unverified] an operator or a quote right behind the word ends it without making a comment: cmd may run what follows, so it is shown */
	bat("rem&echo hi", "C{rem&echo hi}");
	bat("rem|x", "C{rem|x}");
	bat("rem(x", "C{rem(x}");
	bat("rem)x", "C{rem)x}");
	bat("rem<x", "C{rem<x}");
	bat("rem>x", "C{rem>x}");
	bat("rem^x", "C{rem^x}");
	bat("rem\"x\"", "C{rem}S{\"x\"}");
	/* [Unverified] carets inside the word: the same side */
	bat("r^em x", "C{r^em x}");
	/* in an argument it is a word like another */
	bat("echo rem x", "C{echo rem x}");
	bat("set rem=1", "C{set rem=1}");
	bat("echo a > rem x", "C{echo a > rem x}");
	bat("goto rem", "C{goto rem}");
	/* [Unverified] not done: the command after IF's condition, ELSE and DO is a command start in cmd, here it is not */
	bat("if x==y rem z", "C{if x==y rem z}");
}

static void rem_lines(void)
{
	/* a comment ends at its line, a CR before the "\n" is not part of it, "&" ")" and quotes in it are text */
	bat("rem x\nrem y", "K{rem x}C{\n}K{rem y}");
	bat("rem x\r\nrem y\r\n", "K{rem x}C{\r\n}K{rem y}C{\r\n}");
	bat("rem x & echo y ) \"q", "K{rem x & echo y ) \"q}");
	bat("@echo off\r\nrem hi\r\n", "C{@echo off\r\n}K{rem hi}C{\r\n}");
	/* a lone CR is a blank, not a break: inside a comment it is a byte of the comment */
	bat("rem x\ry\nz", "K{rem x\ry}C{\nz}");
	bat("rem\r", "K{rem\r}");
	bat("rem x\r\r\ny", "K{rem x}C{\r\r\ny}");
	bat("rem\r\n", "K{rem}C{\r\n}");
	/* [Unverified] a trailing caret does not continue a REM line: the next line is read as it is, the side that shows more */
	bat("rem x ^\nrem y", "K{rem x ^}C{\n}K{rem y}");
	bat("rem x ^\necho \"a\"", "K{rem x ^}C{\necho }S{\"a\"}");
	/* after "&" "&&" "||" "|" a command starts, and a "(" or "@" after one keeps it */
	bat("echo a & rem x \"q\"", "C{echo a & }K{rem x \"q\"}");
	bat("echo a&&rem x", "C{echo a&&}K{rem x}");
	bat("echo a||rem x", "C{echo a||}K{rem x}");
	bat("echo a | rem x", "C{echo a | }K{rem x}");
	bat("echo a &@rem x", "C{echo a &@}K{rem x}");
	bat("echo a & (rem x", "C{echo a & (}K{rem x}");
	bat("echo a > b & rem x", "C{echo a > b & }K{rem x}");
	/* a block: each line of it starts a command, and the ")" in a comment closes nothing */
	bat("if 1==1 (\nrem x )\n) else (\n:: y )\n)", "C{if 1==1 (\n}K{rem x )}C{\n) else (\n}K{:: y )}C{\n)}");
	/* a caret joins the next line to this one, and the join is transparent: no command start unless there was one */
	bat("echo a ^\nrem x", "C{echo a ^\nrem x}");
	bat("echo a ^\r\n rem x", "C{echo a ^\r\n rem x}");
	bat("echo a &^\n rem x", "C{echo a &^\n }K{rem x}");
	bat("echo a &^\r\n rem x", "C{echo a &^\r\n }K{rem x}");
}

static void colon_lines(void)
{
	/* "::" at a line start is the comment form of a label */
	bat("::x", "K{::x}");
	bat(":: x\r\n", "K{:: x}C{\r\n}");
	bat("  \t:: x", "C{  \t}K{:: x}");
	bat(":::", "K{:::}");
	bat("::", "K{::}");
	bat(":: \"q rem ^", "K{:: \"q rem ^}");
	/* a label is code to its end, and nothing after its name is read: a quote does not open a string */
	bat(":label", "C{:label}");
	bat(":eof\r\n", "C{:eof\r\n}");
	bat(":lbl \"a b\" rem x", "C{:lbl \"a b\" rem x}");
	bat(":a \"x\nrem y", "C{:a \"x\n}K{rem y}");
	bat(":", "C{:}");
	bat(": x", "C{: x}");
	/* only a line start: after "&" cmd reads "::" as a drive name; after a caret the line is the same command; "@" is not a blank */
	bat("echo a & :: x", "C{echo a & :: x}");
	bat("echo a ^\n:: x", "C{echo a ^\n:: x}");
	bat("@:x", "C{@:x}");
	bat("goto :eof", "C{goto :eof}");
	bat("call :sub \"a b\"", "C{call :sub }S{\"a b\"}");
}

static void strings(void)
{
	bat("echo \"a b\"", "C{echo }S{\"a b\"}");
	bat("echo \"\"", "C{echo }S{\"\"}");
	bat("set \"x=a b\"", "C{set }S{\"x=a b\"}");
	bat("set x=\"a b\"", "C{set x=}S{\"a b\"}");
	/* a quote toggles: there is no escape in one, a doubled quote is two runs side by side */
	bat("\"a\"\"b\"", "S{\"a\"}S{\"b\"}");
	bat("echo \"a^\" b", "C{echo }S{\"a^\"}C{ b}");
	bat("echo \"a\\\" b", "C{echo }S{\"a\\\"}C{ b}");
	bat("echo a\"b c\"d", "C{echo a}S{\"b c\"}C{d}");
	/* what is in it is not code: operators, REM, "::", parentheses */
	bat("echo \"a & rem b\" & rem c", "C{echo }S{\"a & rem b\"}C{ & }K{rem c}");
	bat("echo \"rem x\"", "C{echo }S{\"rem x\"}");
	bat("if x (echo \")\")", "C{if x (echo }S{\")\"}C{)}");
	/* a variable in it: %1 %* %~dp0 %%i %name% !name! (INTERP) - and what is not one */
	bat("\"%1\"", "S*{\"%1\"}");
	bat("\"%*\"", "S*{\"%*\"}");
	bat("\"%~dp0x\"", "S*{\"%~dp0x\"}");
	bat("\"%%i\"", "S*{\"%%i\"}");
	bat("\"a%b%c\"", "S*{\"a%b%c\"}");
	bat("\"!v!\"", "S*{\"!v!\"}");
	bat("\"% %\"", "S*{\"% %\"}");
	bat("\"50%\"", "S{\"50%\"}");
	bat("\"a!\"", "S{\"a!\"}");
	bat("\"!!\"", "S{\"!!\"}");
	bat("\"!!!\"", "S{\"!!!\"}");
	bat("\"x!a!\"", "S*{\"x!a!\"}");
	bat("\"abc\"%x%", "S{\"abc\"}C{%x%}");
	/* a quote ends at its line: the string is open, the CR of a CRLF is not part of it, the next line is fresh */
	bat("echo \"abc", "C{echo }S!{\"abc}");
	bat("echo \"abc\ndef\"", "C{echo }S!{\"abc}C{\ndef}S!{\"}");
	bat("echo \"abc\r\ndef", "C{echo }S!{\"abc}C{\r\ndef}");
	bat("\"", "S!{\"}");
	bat("\"\r\n", "S!{\"}C{\r\n}");
	bat("\"\r", "S!{\"\r}");
	bat("\"a\r\r\n", "S!{\"a}C{\r\r\n}");
	bat("\"%a%", "S*!{\"%a%}");
	/* ^ outside a quote escapes the next byte, a quote too: no string, and a "&" after it is still an operator */
	bat("echo ^\"a & b^\"", "C{echo ^\"a & b^\"}");
	bat("echo ^^\"a\"", "C{echo ^^}S{\"a\"}");
	/* the escaped quote is a byte, the next one opens a string that runs to the line's end */
	bat("echo ^\"a\" & rem x", "C{echo ^\"a}S!{\" & rem x}");
	bat("echo ^", "C{echo ^}");
	bat("echo ^&\"a\"", "C{echo ^&}S{\"a\"}");
	bat("for /f ^\"usebackq^ eol^=^\n^ delims^=^\" %%a in (x) do y", "C{for /f ^\"usebackq^ eol^=^\n^ delims^=^\" %%a in (x) do y}");
	/* the forms of cmd that are not strings */
	bat("if /i \"%a%\"==\"x\" (", "C{if /i }S*{\"%a%\"}C{==}S{\"x\"}C{ (}");
	bat("for /f \"delims=\" %%a in ('type \"x y\"') do echo %%a",
	    "C{for /f }S{\"delims=\"}C{ %%a in ('type }S{\"x y\"}C{') do echo %%a}");
	bat("@echo off\necho. & echo( & echo:x", "C{@echo off\necho. & echo( & echo:x}");
	bat("echo %%i %~dp0 !v! 100%", "C{echo %%i %~dp0 !v! 100%}");
	bat("echo a >nul 2>&1", "C{echo a >nul 2>&1}");
}

static void encodings(void)
{
	static struct rend r;

	/* a UTF-8 BOM is code and does not hide the first line from the lexer */
	bat("\xef\xbb\xbf" "rem x", "C{\xef\xbb\xbf}K{rem x}");
	bat("\xef\xbb\xbf::x", "C{\xef\xbb\xbf}K{::x}");
	bat("\xef\xbb\xbf@echo off\r\n:: c", "C{\xef\xbb\xbf@echo off\r\n}K{:: c}");
	bat("\xef\xbb", "C{\xef\xbb}");
	bat("x\n \xef\xbb\xbf" "rem y", "C{x\n \xef\xbb\xbf}K{rem y}");
	bat("\xef\xbb\xbf\xef\xbb\xbf::y", "C{\xef\xbb\xbf\xef\xbb\xbf}K{::y}");
	bat("a\xef\xbb\xbf" "rem x", "C{a\xef\xbb\xbf" "rem x}");
	/* UTF-16 is not read: from its mark to the end one code span, a quote or a REM inside it is not looked at */
	bat("\xff\xfe" "r", "C{\xff\xfe" "r}");
	bat("rem x\n\xff\xfe" "rem y \"z", "K{rem x}C{\n\xff\xfe" "rem y \"z}");
	bat(" \xfe\xff::x\n::y", "C{ \xfe\xff::x\n::y}");
	bat("echo \xff\xfe\"a\"", "C{echo \xff\xfe}S{\"a\"}");
	bat("\xfe\xff", "C{\xfe\xff}");
	lex(&r, "\xff\xfe\"\0r\0" "e\0m\0 \0\"\0\n\0", 14, BAT);
	CK(!r.broken && strchr(r.out, 'S') == NULL && strchr(r.out, 'K') == NULL);
	/* without a BOM it is bytes with NULs: a NUL is no name byte, so "r\0e\0m\0" is never REM, and it still partitions */
	lex(&r, "r\0e\0m\0 \0x\0\n\0r\0e\0m\0", 18, BAT);
	CK(!r.broken && strchr(r.out, 'K') == NULL);
	lex(&r, "r\0e\0m\0 \0\"\0a\0\"\0\n\0", 16, BAT);
	CK(!r.broken);
}

/* ---- (b) the generator ---- */

#define GEN_MAX 60000u
#define EXP_MAX 8000u

struct gen {
	uint64_t s;
	uint8_t  b[GEN_MAX + 64];
	uint32_t n;
	struct kgenome_textual_span x[EXP_MAX];
	uint32_t nx;
	uint32_t over;
	uint32_t joined;        /* the line just written is a comment on a continued line: the next one is continued too */
	const char *eol;        /* NULL: a mix of "\n" and "\r\n" */
};

static uint32_t rnd(struct gen *g, uint32_t k)
{
	g->s ^= g->s >> 12;
	g->s ^= g->s << 25;
	g->s ^= g->s >> 27;
	return (uint32_t)((g->s * 2685821657736338717ull) >> 33) % k;
}

/* Write `t` as a span of `kind`: what the generator says it is, and what the lexer must answer. */
static void put_span(struct gen *g, const char *t, uint8_t kind, uint8_t flags, uint32_t open, uint32_t close)
{
	uint32_t l = (uint32_t)strlen(t);

	if (!l)
		return;
	if (g->n + l > GEN_MAX || g->nx + 1u >= EXP_MAX) {
		g->over = 1;
		return;
	}
	memcpy(g->b + g->n, t, l);
	if (kind == KGENOME_TEXTUAL_CODE && g->nx && g->x[g->nx - 1u].kind == KGENOME_TEXTUAL_CODE) {
		g->x[g->nx - 1u].len += l;
	} else {
		g->x[g->nx++] = (struct kgenome_textual_span){ .off = g->n, .len = l, .kind = kind, .flags = flags,
							       .open_len = open, .close_len = close };
	}
	g->n += l;
}

static void code(struct gen *g, const char *t)
{
	put_span(g, t, KGENOME_TEXTUAL_CODE, 0, 0, 0);
}

static void comment(struct gen *g, const char *t, uint32_t open)
{
	put_span(g, t, KGENOME_TEXTUAL_COMMENT, 0, open, 0);
}

/* A closed string of `content` ("" quotes added), or an open one. */
static void string(struct gen *g, const char *content, int interp, int open)
{
	char t[160];

	snprintf(t, sizeof t, "\"%s%s", content, open ? "" : "\"");
	put_span(g, t, KGENOME_TEXTUAL_STRING, (uint8_t)((interp ? KGENOME_TEXTUAL_F_INTERP : 0) |
							  (open ? KGENOME_TEXTUAL_F_OPEN : 0)), 1u, open ? 0u : 1u);
}

static void line_end(struct gen *g)
{
	code(g, g->eol ? g->eol : rnd(g, 2) ? "\r\n" : "\n");
}

static const char *pick(struct gen *g, const char *const *t, uint32_t n)
{
	return t[rnd(g, n)];
}

#define NOF(a) ((uint32_t)(sizeof (a) / sizeof (a)[0]))

/* contents of a string, and whether the lexer must call it a string that holds a variable */
static const struct { const char *t; int interp; } str_body[] = {
	{ "", 0 }, { "a b", 0 }, { "x=a  b", 0 }, { "%1", 1 }, { "%~dp0bin", 1 }, { "%%i", 1 }, { "%path%;c", 1 },
	{ "!v!", 1 }, { "50%", 0 }, { "a!", 0 }, { "rem x & y", 0 }, { ":: z", 0 }, { ")", 0 }, { "a^", 0 },
	{ "c:\\p q\\", 0 }, { "caf\xc3\xa9", 0 }, { "(", 0 }, { "%", 0 }, { "% %", 1 }, { "x!y!", 1 },
};

static void indent(struct gen *g)
{
	static const char *const in[] = { "", "", " ", "\t", "  ", " \t " };

	code(g, pick(g, in, NOF(in)));
}

static void gen_rem(struct gen *g)
{
	static const char *const word[] = { "rem", "REM", "Rem", "rEm" };
	static const char *const tail[] = { "", " text", " x & y ) \"q", ".", "-----", "=\"\"\"", "\tfoo", ",a", ";b", " ^", " ::", ":x" };
	char t[64];
	uint32_t k;

	indent(g);
	for (k = rnd(g, 3); k; k--)
		code(g, rnd(g, 2) ? "@" : " ");
	snprintf(t, sizeof t, "%s%s", pick(g, word, NOF(word)), pick(g, tail, NOF(tail)));
	comment(g, t, 3u);
}

static void gen_colon(struct gen *g)
{
	static const char *const tail[] = { "", " c", "::", " \"q", " rem x", " ^", "x ^" };
	static const char *const name[] = { "lbl", "eof", "a_b", " x", "", "-" };
	char t[64];

	indent(g);
	if (rnd(g, 2)) {
		snprintf(t, sizeof t, "::%s", pick(g, tail, NOF(tail)));
		comment(g, t, 2u);
	} else {
		const char *nm = pick(g, name, NOF(name)), *tl = rnd(g, 2) ? " \"a b\" rem y" : pick(g, tail, NOF(tail));

		/* ":" and "::..." is the comment form, so a label with no name takes no tail that begins with a colon */
		snprintf(t, sizeof t, ":%s%s", nm, !*nm && *tl == ':' ? " " : tl);
		code(g, t);
	}
}

/* A command: words, strings, operators; it may end in a string that never closes */
static void gen_command(struct gen *g)
{
	static const char *const word[] = { "echo ", "set ", "call ", "copy ", "if /i ", "@echo ", "for /f ", "echo.", "(echo ", "goto :eof " };
	static const char *const glue[] = { " ", "==", "=", " & ", "&&", "|", " > ", " 2>&1 ", ")", " ^& ", " ^^", "x" };
	uint32_t k, parts = 1u + rnd(g, 4);

	indent(g);
	code(g, pick(g, word, NOF(word)));
	for (k = 0; k < parts; k++) {
		uint32_t b = rnd(g, NOF(str_body));

		string(g, str_body[b].t, str_body[b].interp, k + 1u == parts && rnd(g, 6) == 0);
		if (g->nx && g->x[g->nx - 1u].flags & KGENOME_TEXTUAL_F_OPEN)
			return;
		code(g, pick(g, glue, NOF(glue)));
		if (rnd(g, 3) == 0)
			code(g, pick(g, word, NOF(word)));
	}
}

static void gen_after_amp(struct gen *g)
{
	static const char *const op[] = { "&", "&&", "||", "|", "& (", "&@", "| @" };
	static const char *const tail[] = { "rem x", "REM", "rem \"a b\" & c" };

	indent(g);
	code(g, "echo a ");
	code(g, pick(g, op, NOF(op)));
	code(g, " ");
	comment(g, pick(g, tail, NOF(tail)), 3u);
}

static void gen_escape(struct gen *g)
{
	indent(g);
	switch (rnd(g, 3)) {
	case 0:
		code(g, "echo ^\"x & y^\" rem z");
		break;
	case 1:
		code(g, "echo ^^");
		string(g, "a", 0, 0);
		break;
	default:
		code(g, "echo a ^& rem x");
	}
}

static void gen_join(struct gen *g)
{
	indent(g);
	if (rnd(g, 2)) {
		code(g, "echo a ^");
		line_end(g);
		indent(g);
		code(g, rnd(g, 2) ? "rem x " : ":: x ");
		string(g, "z", 0, 0);
	} else {
		code(g, "echo a &^");
		line_end(g);
		code(g, " ");
		comment(g, "rem x", 3u);
		g->joined = 1;
	}
}

static void gen_line(struct gen *g)
{
	switch (rnd(g, 14)) {
	case 0:
		code(g, "@echo off");
		break;
	case 1: case 2: case 3:
		gen_rem(g);
		break;
	case 4: case 5:
		gen_colon(g);
		break;
	case 6: case 7: case 8: case 9:
		gen_command(g);
		break;
	case 10:
		gen_after_amp(g);
		break;
	case 11:
		gen_escape(g);
		break;
	case 12:
		gen_join(g);
		break;
	default:
		break;          /* a blank line */
	}
}

static void gen_program(struct gen *g, uint64_t seed)
{
	uint32_t lines, k;

	g->n = g->nx = g->over = g->joined = 0;
	g->s = seed * 0x9e3779b97f4a7c15ull + 1u;
	g->eol = rnd(g, 3) == 0 ? "\n" : rnd(g, 2) ? "\r\n" : NULL;
	if (rnd(g, 5) == 0)
		code(g, "\xef\xbb\xbf");
	lines = 1u + rnd(g, 40);
	for (k = 0; k < lines; k++) {
		if (g->joined) {
			/* what follows a comment that was on a continued line is part of the join: no comment or label there */
			g->joined = 0;
			gen_command(g);
		} else {
			gen_line(g);
		}
		/* the last line has its break or not */
		if (k + 1u < lines || rnd(g, 2))
			line_end(g);
	}
}

/* ---- (c) the second reading ---- */

struct span_list {
	struct kgenome_textual_span *v;
	uint32_t n, cap;
};

static int collect(void *u, const struct kgenome_textual_span *s)
{
	struct span_list *l = u;

	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2u : 256u;
		l->v = realloc(l->v, l->cap * sizeof *l->v);
		if (!l->v)
			return 0;
	}
	l->v[l->n++] = *s;
	return 1;
}

static int is_space(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

/* (strchr says yes for a NUL: it finds the end of the set) */
static int in_set(uint8_t c, const char *set)
{
	return c != 0 && strchr(set, c) != NULL;
}

/* Past the bytes that do not begin a line's text: blanks and a UTF-8 BOM, and when `cmd` also "@(,;=" (what a command word may follow). */
static uint32_t lead(const uint8_t *p, uint32_t i, uint32_t le, int cmd)
{
	int seen = 0;       /* a byte of the second kind has been passed: a BOM after it is name bytes */

	while (i < le) {
		if (is_space(p[i]))
			i++;
		else if (cmd && in_set(p[i], "@(,;=")) {
			seen = 1;
			i++;
		} else if (!seen && i + 2u < le && p[i] == 0xef && p[i + 1u] == 0xbb && p[i + 2u] == 0xbf)
			i += 3u;
		else
			break;
	}
	return i;
}

static int is_name(uint8_t c)
{
	return isalnum(c) || c == '_' || c >= 0x80u;
}

/* REM at l[i..len) as a word: not followed by a name byte, an operator or a quote. */
static int rem_at(const uint8_t *l, uint32_t len, uint32_t i)
{
	if (i + 3u > len || tolower(l[i]) != 'r' || tolower(l[i + 1u]) != 'e' || tolower(l[i + 2u]) != 'm')
		return 0;
	return i + 3u == len || (!is_name(l[i + 3u]) && !in_set(l[i + 3u], "&|()<>^\""));
}

/* Does the line (CRs at its end dropped) end in a caret that is not itself escaped and not in quotes. */
static int ends_in_caret(const uint8_t *l, uint32_t len)
{
	uint32_t i, q = 0;

	while (len && l[len - 1u] == '\r')
		len--;
	for (i = 0; i < len; i++) {
		if (l[i] == '"')
			q ^= 1u;
		else if (l[i] == '^' && !q) {
			if (i + 1u == len)
				return 1;
			i++;
		}
	}
	return 0;
}

struct oracle {
	uint64_t lines, comment_lines, differ_comment, differ_string, mid_comments;
	char first[3][160];
	uint32_t n_first;
	uint32_t n;             /* the text's length: a CR before its very end is not before a break */
	int has_comment;        /* a comment began on the line just read */
	int join_comment;       /* ... and it was the first thing on a continued line */
};

static void differ(struct oracle *o, uint64_t *count, const char *what, uint32_t line, const char *file)
{
	(*count)++;
	if (o->n_first < 3u)
		snprintf(o->first[o->n_first++], sizeof o->first[0], "%s: line %u %s", file, line, what);
}

/* One line, [ls, le) without its "\n". `cont`: the line before it ended in a join. `kind`: 0 command, 1 comment, 2 label. */
static void oracle_line(struct oracle *o, const uint8_t *p, uint32_t ls, uint32_t le, int cont, uint32_t number,
			const struct span_list *sp, uint32_t *cursor, const char *file)
{
	uint32_t i = ls, want = UINT32_MAX, got = UINT32_MAX, got_end = 0, strings = 0, opens = 0, quotes = 0, k;
	int label = 0, mid = 0, caret = 0;

	if (!cont) {
		i = lead(p, i, le, 0);
		if (i < le && p[i] == ':') {
			label = 1;
			if (i + 1u < le && p[i + 1u] == ':')
				want = i;
		} else {
			i = lead(p, i, le, 1);
			if (rem_at(p + ls, le - ls, i - ls))
				want = i;
		}
	}
	for (k = ls; k < le; k++) {
		quotes += p[k] == '"';
		caret |= p[k] == '^';
	}
	/* the lexer's spans that begin on this line */
	while (*cursor < sp->n && sp->v[*cursor].off < ls)
		(*cursor)++;
	for (k = *cursor; k < sp->n && sp->v[k].off < le; k++) {
		const struct kgenome_textual_span *s = &sp->v[k];

		if (s->kind == KGENOME_TEXTUAL_COMMENT) {
			if (lead(p, ls, s->off, 1) == s->off && !cont) {
				got = s->off;
				got_end = s->off + s->len;
			} else {
				mid = 1;
				o->mid_comments++;
				if (cont && lead(p, ls, s->off, 1) == s->off)
					o->join_comment = 1;
			}
			o->has_comment = 1;
		} else if (s->kind == KGENOME_TEXTUAL_STRING) {
			strings++;
			opens += (s->flags & KGENOME_TEXTUAL_F_OPEN) != 0;
		}
	}
	o->lines++;
	if (want != UINT32_MAX)
		o->comment_lines++;
	if (want != got) {
		differ(o, &o->differ_comment, "comment start differs", number, file);
	} else if (got != UINT32_MAX) {
		uint32_t e = le;

		while (le < o->n && e > got && p[e - 1u] == '\r')
			e--;
		if (e != got_end)
			differ(o, &o->differ_comment, "comment end differs", number, file);
	}
	if (!label && want == UINT32_MAX && !mid && !caret && (strings != (quotes + 1u) / 2u || opens != (quotes & 1u)))
		differ(o, &o->differ_string, "string count differs", number, file);
}

/* The oracle over a whole text and the spans the lexer gave it. */
static void oracle(struct oracle *o, const uint8_t *p, uint32_t n, const struct span_list *sp, const char *file)
{
	uint32_t ls = 0, number = 1, cursor = 0;
	int cont = 0;

	o->n = n;
	while (ls < n || (ls == n && number == 1u && n == 0)) {
		const uint8_t *e = memchr(p + ls, '\n', n - ls);
		uint32_t le = e ? (uint32_t)(e - p) : n, line_start = ls;
		int comment_or_label;

		o->has_comment = o->join_comment = 0;
		{
			uint32_t b = lead(p, ls, le, 0);

			/* a UTF-16 byte order mark at a line start: what follows is not read */
			if (b + 1u < n && ((p[b] == 0xff && p[b + 1u] == 0xfe) || (p[b] == 0xfe && p[b + 1u] == 0xff)))
				return;
		}
		oracle_line(o, p, line_start, le, cont, number, sp, &cursor, file);
		/* a comment or a label line does not continue; a command line does when it ends in a caret */
		{
			uint32_t i = lead(p, ls, le, 0);

			comment_or_label = !cont && i < le && p[i] == ':';
			if (!cont && !comment_or_label)
				comment_or_label = rem_at(p + ls, le - ls, lead(p, i, le, 1) - ls);
		}
		/* blank lines (and lines of "@(,;=") after a join stay in it, and so does a comment that was the first thing on the continued line (as the
		 * lexer reads them); any other comment swallows what follows it, a caret too */
		cont = (cont && (lead(p, ls, le, 1) == le || o->join_comment)) ||
		       (!comment_or_label && !o->has_comment && ends_in_caret(p + ls, le - ls));
		if (!e)
			break;
		ls = le + 1u;
		number++;
	}
}

static void lex_list(struct span_list *l, const uint8_t *p, uint32_t n)
{
	struct kgenome_textual_lex_req rq = { .in = p, .n = n, .lang = BAT, .sink = collect, .user = l };
	struct kgenome_textual_lex_res rs;

	l->n = 0;
	kgenome_textual_lex(&rq, &rs);
}

static void generator(void)
{
	static struct gen g;
	static struct span_list sp;
	static struct oracle o;
	uint64_t seed;
	uint32_t programs = 0, bad = 0;

	for (seed = 1; seed <= 4000u; seed++) {
		static struct rend r;
		uint32_t i;
		int ok = 1;

		gen_program(&g, seed);
		if (g.over)
			continue;
		programs++;
		lex(&r, g.b, g.n, BAT);
		lex_list(&sp, g.b, g.n);
		ok = !r.broken && sp.n == g.nx;
		if (!ok && bad < 3u && sp.n != g.nx) {
			uint32_t k;

			printf("  FAIL generated program %llu: %u spans, wanted %u\n  text: ", (unsigned long long)seed, sp.n, g.nx);
			for (k = 0; k < g.n && k < 600u; k++)
				printf(g.b[k] >= 0x20 && g.b[k] < 0x7f ? "%c" : "\\x%02x", g.b[k]);
			printf("\n  got:    %s\n", r.out);
			{
				static struct rend w;
				uint32_t q;

				memset(&w, 0, sizeof w);
				w.in = g.b;
				w.n = g.n;
				for (q = 0; q < g.nx; q++)
					sink(&w, &g.x[q]);
				printf("  wanted: %s\n", w.out);
			}
		}
		for (i = 0; ok && i < sp.n; i++) {
			const struct kgenome_textual_span *a = &sp.v[i], *w = &g.x[i];

			ok = a->off == w->off && a->len == w->len && a->kind == w->kind && a->flags == w->flags &&
			     a->open_len == w->open_len && a->close_len == w->close_len;
			if (!ok && bad < 3u) {
				uint32_t k;

				printf("  FAIL generated program %llu, span %u: got off %u len %u kind %u flags %u open %u close %u,\n"
				       "       wanted off %u len %u kind %u flags %u open %u close %u\n  text: ",
				       (unsigned long long)seed, i, a->off, a->len, a->kind, a->flags, a->open_len, a->close_len,
				       w->off, w->len, w->kind, w->flags, w->open_len, w->close_len);
				for (k = 0; k < g.n && k < 600u; k++)
					printf(g.b[k] >= 0x20 && g.b[k] < 0x7f ? "%c" : "\\x%02x", g.b[k]);
				printf("\n");
			}
		}
		if (!ok) {
			bad++;
			fails++;
			if (bad > 5u)
				break;
			continue;
		}
		oracle(&o, g.b, g.n, &sp, "generated");
		/* the form of it: every closed string is there, no comment is, and it is its own form */
		{
			static uint8_t out[GEN_MAX * 2u], out2[GEN_MAX * 2u];
			struct kgenome_textual_form_req rq = { .in = g.b, .n = g.n, .lang = BAT, .out = out, .cap = sizeof out };
			struct kgenome_textual_form_res rs;
			uint32_t k, pos = 0;

			kgenome_textual_form(&rq, &rs);
			for (k = 0; k < sp.n; k++) {
				const struct kgenome_textual_span *s = &sp.v[k];

				if (s->kind != KGENOME_TEXTUAL_STRING)
					continue;
				/* in order: each string is found after the one before it */
				{
					uint32_t w;

					for (w = pos; w + s->len <= rs.n_out && memcmp(out + w, g.b + s->off, s->len); w++)
						;
					if (w + s->len > rs.n_out) {
						CK(0 && "a string of the program is not in its form");
						break;
					}
					pos = w + s->len;
				}
			}
			rq = (struct kgenome_textual_form_req){ .in = out, .n = rs.n_out, .lang = BAT, .out = out2, .cap = sizeof out2 };
			{
				uint32_t n1 = rs.n_out;

				kgenome_textual_form(&rq, &rs);
				if (rs.n_out != n1 || memcmp(out, out2, n1)) {
					printf("  FAIL the form of generated program %llu is not its own form\n", (unsigned long long)seed);
					fails++;
				}
			}
		}
	}
	printf("  generated programs: %u, comment lines %llu\n", programs, (unsigned long long)o.comment_lines);
	CK(programs > 3500u);
	CK(o.differ_comment == 0 && o.differ_string == 0);
	if (o.differ_comment || o.differ_string)
		printf("  oracle on generated programs: %llu comment, %llu string differences, first: %s\n",
		       (unsigned long long)o.differ_comment, (unsigned long long)o.differ_string, o.first[0]);
	CK(o.comment_lines > 3000u);
	free(sp.v);
	sp.v = NULL;
	sp.n = sp.cap = 0;
}

/* Word soup: pieces that change the lexer's mind, put together at random; spans partition it, the form is its own form,
 * and the line reading agrees. */
static void soup(void)
{
	static const char *const piece[] = {
		"rem ", "REM", "::", ":", ":lbl", "@", "&", "&&", "|", "||", "^", "^\n", "^\r\n", "\"", "\"a b\"", "\n", "\r\n", "\r",
		" ", "\t", "(", ")", "echo ", "%a%", "%1", "!v!", "x", "rem.", "rem&", "r^em", "if ", ">", "=", ",", ";", "\1", "\xef\xbb\xbf",
		"\xc3\xa9", "rem-", "remx ",
	};
	static struct span_list sp;
	static struct oracle o;
	static uint8_t b[600], out[1024], out2[1024];
	uint64_t s = 12345u;
	uint32_t i, bad = 0;

	for (i = 0; i < 60000u; i++) {
		uint32_t n = 0, pieces, k;
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		uint32_t n1;
		static struct rend r;

		s = s * 6364136223846793005ull + 1442695040888963407ull;
		pieces = (uint32_t)(s >> 33) % 30u;
		for (k = 0; k < pieces; k++) {
			const char *t;
			size_t l;

			s = s * 6364136223846793005ull + 1442695040888963407ull;
			t = piece[(uint32_t)(s >> 33) % NOF(piece)];
			l = t[0] == 1 ? 1u : strlen(t);
			/* the BOM only where one can be: a text's first bytes (the others would be bytes in the middle) */
			if (n + l > sizeof b)
				break;
			memcpy(b + n, t, l);
			if (t[0] == 1)
				b[n] = 0;
			n += (uint32_t)l;
		}
		lex(&r, b, n, BAT);
		if (r.broken) {
			printf("  FAIL partition on soup of %u bytes\n", n);
			fails++;
			return;
		}
		lex_list(&sp, b, n);
		memset(&o, 0, sizeof o);
		oracle(&o, b, n, &sp, "soup");
		if ((o.differ_comment || o.differ_string) && bad++ < 3u) {
			uint32_t q;

			printf("  FAIL oracle on soup: %s\n  text: ", o.first[0]);
			for (q = 0; q < n; q++)
				printf(b[q] >= 0x20 && b[q] < 0x7f ? "%c" : "\\x%02x", b[q]);
			printf("\n  spans: %s\n", r.out);
			fails++;
		}
		rq = (struct kgenome_textual_form_req){ .in = b, .n = n, .lang = BAT, .out = out, .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
		kgenome_textual_form(&rq, &rs);
		n1 = rs.n_out;
		CK(n1 <= KGENOME_TEXTUAL_FORM_CAP(n));
		rq = (struct kgenome_textual_form_req){ .in = out, .n = n1, .lang = BAT, .out = out2, .cap = KGENOME_TEXTUAL_FORM_CAP(n1) };
		kgenome_textual_form(&rq, &rs);
		if (rs.n_out != n1 || memcmp(out, out2, n1)) {
			uint32_t q;

			printf("  FAIL the form of soup is not its own form: ");
			for (q = 0; q < n; q++)
				printf(b[q] >= 0x20 && b[q] < 0x7f ? "%c" : "\\x%02x", b[q]);
			printf("\n");
			fails++;
			return;
		}
	}
	free(sp.v);
	sp.v = NULL;
	sp.n = sp.cap = 0;
}

/* ---- (e) form, value, decoders ---- */

static void forms(void)
{
	/* comments and indentation go, a line break stays one, blank lines collapse, CRLF is LF */
	fm("@echo off\r\nrem hi\r\n:: c\r\n\r\n  echo   a    b  \r\n", "@echo off\necho a b");
	/* a trailing comment goes with the blank in front of it */
	fm("echo a & rem t\r\necho b", "echo a &\necho b");
	/* a string is every byte of itself, an open one too, a label is code (its blanks are one) */
	fm("echo \"a   b\"   \"%1  x\"", "echo \"a   b\" \"%1  x\"");
	fm("echo \"abc  \r\nrem x", "echo \"abc  ");
	fm(":lbl    x\n\n\n:eof", ":lbl x\n:eof");
	/* it is its own form: ECHO text keeps the blank between words, quotes keep everything */
	fm("echo. & echo( & echo   x", "echo. & echo( & echo x");
	fm("echo ^\"a   b^\"", "echo ^\"a b^\"");
}

static uint8_t last_chain[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t hook_calls;

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
		       const uint8_t **out, uint32_t *out_len)
{
	(void)user;
	(void)in;
	(void)len;
	(void)out;
	(void)out_len;
	hook_calls++;
	memcpy(last_chain, chain, n_chain);
	return 0;
}

static void decoders(void)
{
	/* certutil -decode is a command with FILE arguments and not a call over a literal: the hook is never asked, however
	 * the text looks. Neither is a literal under a name that is a decoder in another language. */
	static const char *const src[] = {
		"certutil -decode \"a.b64\" out.exe",
		"certutil -decode in.txt \"out.exe\"",
		"set \"x=YWJj\" & echo base64_decode(\"YWJj\")",
		"powershell -enc \"YWJj\"",
		"echo atob(\"YWJj\") & b64decode(\"YWJj\")",
	};
	unsigned i;

	for (i = 0; i < sizeof src / sizeof src[0]; i++) {
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src[i], .n = (uint32_t)strlen(src[i]), .lang = BAT,
						       .out = fbuf, .decode = fake_decode };
		struct kgenome_textual_form_res rs;

		rq.cap = KGENOME_TEXTUAL_FORM_CAP(rq.n) + 64u;
		hook_calls = 0;
		kgenome_textual_form(&rq, &rs);
		CK(hook_calls == 0 && rs.n_decoded == 0 && rs.n_refused == 0);
		CK(rs.n_out == strlen(src[i]) && !memcmp(fbuf, src[i], rs.n_out));
	}
}

static enum kgenome_textual_status value_of(const char *lit, uint8_t flags, uint32_t open, uint32_t close, char *out, uint32_t cap,
					    uint32_t *n)
{
	struct kgenome_textual_value_req rq = { .lang = BAT, .lit = (const uint8_t *)lit, .len = (uint32_t)strlen(lit),
						.open_len = open, .close_len = close, .flags = flags, .out = (uint8_t *)out, .cap = cap };
	struct kgenome_textual_value_res rs;
	enum kgenome_textual_status st = kgenome_textual_value(&rq, &rs);

	*n = rs.n_out;
	return st;
}

static void values(void)
{
	char o[64];
	uint32_t n;

	/* a closed string with nothing to expand is the bytes between its quotes: there is no escape in one */
	CK(value_of("\"a b\"", 0, 1, 1, o, sizeof o, &n) == KGENOME_TEXTUAL_OK && n == 3 && !memcmp(o, "a b", 3));
	CK(value_of("\"\"", 0, 1, 1, o, sizeof o, &n) == KGENOME_TEXTUAL_OK && n == 0);
	CK(value_of("\"a\\n^\"", 0, 1, 1, o, sizeof o, &n) == KGENOME_TEXTUAL_OK && n == 4 && !memcmp(o, "a\\n^", 4));
	/* a variable in it is the program's, an open one is not a literal's value */
	CK(value_of("\"%1\"", KGENOME_TEXTUAL_F_INTERP, 1, 1, o, sizeof o, &n) == KGENOME_TEXTUAL_NO_VALUE);
	CK(value_of("\"abc", KGENOME_TEXTUAL_F_OPEN, 1, 0, o, sizeof o, &n) == KGENOME_TEXTUAL_NO_VALUE);
	CK(value_of("\"abc\"", 0, 1, 1, o, 2, &n) == KGENOME_TEXTUAL_SMALL);
}

/* ---- (d) any text at all ---- */

static void properties(void)
{
	partition_for(BAT, "\"^&|()<>%!:@\r\n \tremREM.=x,;-", 2024u);
	partition_for(BAT, "\"^\nrem:@& \r", 77u);
	partition_for(BAT, "r\0e\0m\0:\"^\n", 5u);
	form_property_for(BAT, "\"^&|()<>%!:@\r\n \tremREM.=x,;-", 99u);
	form_property_for(BAT, "\"^\nrem:@& \r", 31u);
	form_property_for(BAT, "\"^ \nrem\r:@&", 8u);
	/* the bytes of the two byte order marks, and a NUL's neighbours */
	partition_for(BAT, "\xff\xfe\xef\xbb\xbf\n\"rem:^ x", 41u);
	form_property_for(BAT, "\xff\xfe\xef\xbb\xbf\n\"rem:^ x", 42u);
}

struct whole {
	uint32_t next, n, broken;
};

static int whole_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct whole *c = u;

	if (sp->off != c->next || !sp->len)
		c->broken = 1;
	c->next = sp->off + sp->len;
	c->n++;
	return 1;
}

static void hostile(void)
{
	static const char sample[] = "\xef\xbb\xbf@echo off\r\nrem x ^\r\n:: c \"\r\nset \"a=%1\" & rem y\r\necho ^\"a^\" \"b\r\n(\r\n  :lbl \"q\r\n) else (rem z)\r\n";
	static struct rend r;
	static uint8_t big[2u * 1024u * 1024u];
	static const char *const unit[] = { "(", "^", "^\n", "\"", "\"a", "&rem ", "rem \"\n", ":\n", "::\r\n", "\r", "\1", "rem" };
	clock_t t0 = clock();
	uint32_t n, k;

	/* the spans partition a text cut at every length */
	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, BAT);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* a deep run of "(" and of "^", a string that never closes, NULs: 2 MB of each unit, in time linear in it */
	for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
		size_t ul = unit[k][0] == 1 ? 1u : strlen(unit[k]);
		uint32_t w = 0;
		struct whole c = { 0 };
		struct kgenome_textual_lex_req rq;
		struct kgenome_textual_lex_res rs;
		enum kgenome_textual_status st;

		while (w + ul <= sizeof big) {
			memcpy(big + w, unit[k], ul);
			if (unit[k][0] == 1)
				big[w] = 0;
			w += (uint32_t)ul;
		}
		rq = (struct kgenome_textual_lex_req){ .in = big, .n = w, .lang = BAT, .sink = whole_sink, .user = &c };
		st = kgenome_textual_lex(&rq, &rs);
		CK((st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c.next == w && !c.broken && rs.n_span == c.n);
	}
	/* one string of 2 MB that is not closed is ONE open span; one with a line break every 3 bytes is many */
	memset(big, 'a', sizeof big);
	big[0] = '"';
	{
		struct whole c = { 0 };
		struct kgenome_textual_lex_req rq = { .in = big, .n = sizeof big, .lang = BAT, .sink = whole_sink, .user = &c };
		struct kgenome_textual_lex_res rs;

		CK(kgenome_textual_lex(&rq, &rs) == KGENOME_TEXTUAL_OPEN && rs.n_span == 1 && rs.n_open == 1);
	}
	CK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
	/* CR, LF and CRLF endings give the same spans modulo the break: the same lines are comments */
	bat("rem a\nrem b\n::c\n", "K{rem a}C{\n}K{rem b}C{\n}K{::c}C{\n}");
	bat("rem a\r\nrem b\r\n::c\r\n", "K{rem a}C{\r\n}K{rem b}C{\r\n}K{::c}C{\r\n}");
	bat("rem a\rrem b\r::c\r", "K{rem a\rrem b\r::c\r}");
}

/* ---- the corpus: textual_bat <file>... ---- */

static int corpus(int argc, char **argv)
{
	static struct span_list sp;
	static struct oracle o;
	uint64_t bytes = 0, files = 0, open = 0, broken = 0, notidem = 0, spans[KGENOME_TEXTUAL_KIND_COUNT] = { 0 }, sbytes[KGENOME_TEXTUAL_KIND_COUNT] = { 0 };
	uint64_t big_files = 0;
	double lex_s = 0;
	int a;

	for (a = 1; a < argc; a++) {
		FILE *f = fopen(argv[a], "rb");
		uint8_t *b, *out, *out2;
		long n;
		uint32_t i, expect = 0, n1;
		clock_t t0;
		struct kgenome_textual_lex_req rq;
		struct kgenome_textual_lex_res rs;
		struct kgenome_textual_form_req fq;
		struct kgenome_textual_form_res fr;
		enum kgenome_textual_status st;

		if (!f)
			continue;
		fseek(f, 0, SEEK_END);
		n = ftell(f);
		fseek(f, 0, SEEK_SET);
		b = malloc((size_t)n + 1u);
		if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
			fclose(f);
			free(b);
			continue;
		}
		fclose(f);
		files++;
		bytes += (uint64_t)n;
		sp.n = 0;
		rq = (struct kgenome_textual_lex_req){ .in = b, .n = (uint32_t)n, .lang = BAT, .sink = collect, .user = &sp };
		t0 = clock();
		st = kgenome_textual_lex(&rq, &rs);
		lex_s += (double)(clock() - t0) / CLOCKS_PER_SEC;
		for (i = 0; i < sp.n; i++) {
			if (sp.v[i].off != expect || !sp.v[i].len) {
				printf("PARTITION BROKEN %s at span %u\n", argv[a], i);
				broken++;
				break;
			}
			expect += sp.v[i].len;
			spans[sp.v[i].kind]++;
			sbytes[sp.v[i].kind] += sp.v[i].len;
		}
		if (expect != (uint32_t)n && !broken)
			broken++;
		open += st == KGENOME_TEXTUAL_OPEN;
		if (st == KGENOME_TEXTUAL_OPEN && open <= 5u)
			printf("OPEN %s (%u open spans)\n", argv[a], rs.n_open);
		if (n > 100000)
			big_files++;
		oracle(&o, b, (uint32_t)n, &sp, argv[a]);
		out = malloc((size_t)KGENOME_TEXTUAL_FORM_CAP((uint32_t)n));
		out2 = malloc((size_t)KGENOME_TEXTUAL_FORM_CAP((uint32_t)n));
		if (out && out2) {
			fq = (struct kgenome_textual_form_req){ .in = b, .n = (uint32_t)n, .lang = BAT, .out = out, .cap = KGENOME_TEXTUAL_FORM_CAP((uint32_t)n) };
			kgenome_textual_form(&fq, &fr);
			n1 = fr.n_out;
			fq = (struct kgenome_textual_form_req){ .in = out, .n = n1, .lang = BAT, .out = out2, .cap = KGENOME_TEXTUAL_FORM_CAP(n1) };
			kgenome_textual_form(&fq, &fr);
			if (fr.n_out != n1 || memcmp(out, out2, n1)) {
				notidem++;
				printf("FORM NOT IDEMPOTENT %s\n", argv[a]);
			}
		}
		free(out);
		free(out2);
		free(b);
	}
	printf("files=%llu bytes=%llu (%.2f MB) lex %.3f s = %.1f MB/s; open=%llu partition_broken=%llu form_not_idempotent=%llu\n",
	       (unsigned long long)files, (unsigned long long)bytes, (double)bytes / 1048576.0, lex_s, lex_s > 0 ? (double)bytes / 1048576.0 / lex_s : 0.0,
	       (unsigned long long)open, (unsigned long long)broken, (unsigned long long)notidem);
	printf("spans: code=%llu (%llu B) string=%llu (%llu B) comment=%llu (%llu B)\n",
	       (unsigned long long)spans[KGENOME_TEXTUAL_CODE], (unsigned long long)sbytes[KGENOME_TEXTUAL_CODE],
	       (unsigned long long)spans[KGENOME_TEXTUAL_STRING], (unsigned long long)sbytes[KGENOME_TEXTUAL_STRING],
	       (unsigned long long)spans[KGENOME_TEXTUAL_COMMENT], (unsigned long long)sbytes[KGENOME_TEXTUAL_COMMENT]);
	printf("oracle: lines=%llu comment_lines=%llu differ_comment=%llu differ_string=%llu mid_line_comments=%llu\n",
	       (unsigned long long)o.lines, (unsigned long long)o.comment_lines, (unsigned long long)o.differ_comment,
	       (unsigned long long)o.differ_string, (unsigned long long)o.mid_comments);
	for (a = 0; a < (int)o.n_first; a++)
		printf("  %s\n", o.first[a]);
	(void)big_files;
	free(sp.v);
	return broken || notidem ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc > 1)
		return corpus(argc, argv);
	rem_words();
	rem_lines();
	colon_lines();
	strings();
	encodings();
	generator();
	soup();
	forms();
	decoders();
	values();
	properties();
	hostile();
	printf("textual bat: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
