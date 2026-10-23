#ifndef KGENOME_TEST_TEXTUAL_PAGEGEN_H
#define KGENOME_TEST_TEXTUAL_PAGEGEN_H

/*
 * textual_pagegen.h - a GENERATOR of valid asp and asp.net pages, for textual_asp.c and textual_aspx.c.
 *
 * A page is built from pieces whose class is KNOWN when they are written: markup, a tag, a directive, a
 * comment of the page, and islands whose bodies are put together from tokens of known class - code, a string,
 * a comment - in the body's own language (vbscript, c#, jscript). Each piece is appended to the page text
 * and, in the same call, to the rendering the lexer must produce (the format of textual_check.h), so the
 * lexer is checked against what the generator KNEW and not against a second lexer. Neighbours merge as the
 * lexer merges them: two runs of markup, or of code, are one span.
 *
 * WHAT THE GENERATOR KEEPS AWAY FROM, because the page scanner would read it differently from how it was
 * written: "%>" in an island's body except where it ends the island (a script element's body may hold it,
 * and does), "</" in any body (it would end a script element), a first byte after "<%" that makes a longer
 * tag ("=@#$:!-", a space is put in front), and a code token that glues to the next one into something else
 * ("/" only inside "a / b", no bare quote). It does NOT keep away from "<%" inside a string, from a quote in
 * a comment, from "%\>", "--" or "//" inside a string: those are the cases the lexer exists for.
 *
 * Deterministic: one 32-bit seed, the same LCG as the harness's.
 */

#include "textual_check.h"

enum pg_body { PG_VB, PG_CS, PG_JS };

#define PG_PAGE 2400u

struct pg {
	uint32_t s;
	char     page[PG_PAGE];
	uint32_t pn;
	char     want[4u * PG_PAGE];
	uint32_t wn;
	char     pk, pf[4], pb[PG_PAGE];       /* the span being grown: kind, flags, bytes */
	uint32_t pbn;
	int      on, over;
	int      aspx;
};

static inline uint32_t pg_rnd(struct pg *g, uint32_t n)
{
	g->s = g->s * 1103515245u + 12345u;
	return (g->s >> 16) % n;
}

static inline void pg_flush(struct pg *g)
{
	const char *f;

	if (!g->on)
		return;
	g->want[g->wn++] = g->pk;
	for (f = g->pf; *f; f++)
		g->want[g->wn++] = *f;
	g->want[g->wn++] = '{';
	memcpy(g->want + g->wn, g->pb, g->pbn);
	g->wn += g->pbn;
	g->want[g->wn++] = '}';
	g->want[g->wn] = 0;
	g->on = 0;
	g->pbn = 0;
}

/* One span (or a piece of one that merges) of `kind` with the flags `flags` ("*" interpolates, "!" open). */
static inline void pg_put(struct pg *g, char kind, const char *flags, const char *bytes)
{
	size_t l = strlen(bytes);

	/* a string that begins with a quote right after one that ended with a quote is read as one (vb doubles a
	 * quote, c# does in @"..."): the generator never writes two touching */
	if (kind != 'M' && bytes[0] == '"' && g->pn && g->page[g->pn - 1u] == '"')
		pg_put(g, 'C', "", " ");
	if (g->over || g->pn + l + 8u >= PG_PAGE || g->wn + g->pbn + 16u >= sizeof g->want) {
		g->over = 1;
		return;
	}
	memcpy(g->page + g->pn, bytes, l);
	g->pn += (uint32_t)l;
	g->page[g->pn] = 0;
	if (g->on && g->pk == kind && (kind == 'M' || kind == 'C') && !*flags && !*g->pf) {
		memcpy(g->pb + g->pbn, bytes, l);
		g->pbn += (uint32_t)l;
		return;
	}
	pg_flush(g);
	g->on = 1;
	g->pk = kind;
	strcpy(g->pf, flags);
	memcpy(g->pb, bytes, l);
	g->pbn = (uint32_t)l;
}

static inline const char *pg_pick(struct pg *g, const char *const *list, uint32_t n)
{
	return list[pg_rnd(g, n)];
}

#define PG_N(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

/* `n` bytes drawn from `alpha` into `out`, then "%>" and "</" taken out of them (see the header). */
static inline void pg_chars(struct pg *g, char *out, const char *alpha, uint32_t n, int script_body)
{
	uint32_t k, na = (uint32_t)strlen(alpha);

	for (k = 0; k < n; k++)
		out[k] = alpha[pg_rnd(g, na)];
	out[n] = 0;
	for (k = 0; k + 1u < n; k++) {
		if (out[k] == '<' && out[k + 1u] == '/')
			out[k] = ' ';
		if (!script_body && out[k] == '%' && out[k + 1u] == '>')
			out[k] = ' ';
	}
}

/* ---- body tokens ----------------------------------------------------------------------- */

struct pg_body_state {
	int lang;               /* enum pg_body */
	int fresh;              /* vb: a statement may begin here ("Rem" is a comment) */
	int bol;                /* c#: the next byte is first on its line */
	int need_nl;            /* a line comment or an unclosed string is open: only a line break may follow */
	int script;             /* the body of a <script runat="server"> element: "%>" is text there */
	int js_no_escape_digits;/* asp jscript: the form rewrites \x and octal, so the generator does not write them */
	int done;               /* a block comment is left open: nothing may follow */
};

static inline void pg_break(struct pg *g, struct pg_body_state *b)
{
	static const char *const nl[] = { "\n", "\r\n", "\n\n", "\n\t" };

	pg_put(g, 'C', "", pg_pick(g, nl, PG_N(nl)));
	b->fresh = 1;
	b->bol = 1;
	b->need_nl = 0;
}

static inline void pg_code(struct pg *g, struct pg_body_state *b)
{
	static const char *const vb[] = {
		"x", "Response.Write", "a = b + 1", "f(x, y)", "If a Then", "Else", "Set o = CreateObject", "a & b", "Remark",
		"xrem", "a.Rem", "Dim s", "For i = 1 To 9", "Next", "x = -1", "a <> b", "a >= b", "On Error Resume Next",
		"Request.Form(1)", "End If", "Rem_x", "a_b", "&H1F", "1.5", "s = s & Chr(34)"
	};
	static const char *const cs[] = {
		"int a = 1;", "foo(x, y);", "if (a < b) { c(); }", "List<Dictionary<string, int>> m;", "x => y", "a ?? b",
		"a / b", "unsafe {", "}", "[DllImport(kernel)]", " @class", " @x = 2;", "a ? b : c", "0x1F", "1.5f", "x++;",
		"for (var i = 0; i < n; i++)", "using (var s = new X())", "a.b?.c", "Convert.ToBase64String(b)", "new byte[] { 1, 2 }"
	};
	static const char *const js[] = {
		"var a = 1;", "foo(x, y);", "if (a < b) { c(); }", "a / b", "}", "{", "x++;", "function f(a) {", "return a;",
		"a.b = c.d;", "eval(x);", "new ActiveXObject(n)", "0x1F", "1.5"
	};
	const char *t;
	char tmp[64];

	if (b->need_nl)
		pg_break(g, b);
	t = b->lang == PG_VB ? pg_pick(g, vb, PG_N(vb)) : b->lang == PG_CS ? pg_pick(g, cs, PG_N(cs)) : pg_pick(g, js, PG_N(js));
	snprintf(tmp, sizeof tmp, "%s%s", pg_rnd(g, 4) ? " " : "", t);
	pg_put(g, 'C', "", tmp);
	pg_put(g, 'C', "", pg_rnd(g, 3) ? " " : "\t");
	b->fresh = b->bol = 0;
}

static inline void pg_vb_string(struct pg *g, struct pg_body_state *b, int open)
{
	char c[48], s[64];
	uint32_t n = pg_rnd(g, 10), k, w = 0;
	static const char alpha[] = "abc XYZ09\\',;{}()/*<%#@$_:&!?[]-+=.<%>\"\"";

	if (b->need_nl)
		pg_break(g, b);
	pg_chars(g, c, alpha, n, b->script);
	/* a quote inside is two quotes, and the doubled ones are made out of the lone ones */
	s[w++] = '"';
	for (k = 0; c[k] && w < 56u; k++) {
		if (c[k] == '"') {
			s[w++] = '"';
			s[w++] = '"';
		} else if (c[k] == '\n') {
			s[w++] = ' ';
		} else {
			s[w++] = c[k];
		}
	}
	if (open && w >= 3u && s[w - 1u] == '"')
		w--;                            /* an open string cannot end in a quote */
	if (!open)
		s[w++] = '"';
	s[w] = 0;
	/* an open string ending in a doubled quote would read as closed: drop to a plain byte */
	if (open) {
		uint32_t q = 0;

		for (k = 1; k < w; k++) {
			if (s[k] == '"') {
				if (k + 1u < w && s[k + 1u] == '"')
					k++;
				else
					q = 1;
			}
		}
		if (q)
			s[1] = 'a', s[2] = 0, w = 2;
	}
	pg_put(g, 'S', open ? "!" : "", s);
	b->fresh = b->bol = 0;
	b->need_nl = open;
}

static inline void pg_vb_comment(struct pg *g, struct pg_body_state *b)
{
	char c[40], s[64];
	static const char alpha[] = "abc XYZ09\\',;{}()/*<%#@$_:&!?[]-+=.\"";
	int rem = b->fresh && pg_rnd(g, 2);

	if (b->need_nl)
		pg_break(g, b);
	pg_chars(g, c, alpha, pg_rnd(g, 24), b->script);
	snprintf(s, sizeof s, "%s%s%s", rem ? (pg_rnd(g, 2) ? "Rem" : "REM") : "'", rem ? " " : "", c);
	if (rem && !b->fresh)
		return;
	pg_put(g, 'K', "", s);
	b->need_nl = 1;
	b->fresh = b->bol = 0;
}

static inline void pg_vb_misc(struct pg *g, struct pg_body_state *b)
{
	static const char *const misc[] = { "#1/1/2000 10:30:00#", "[end]", "[a 'b]", " : " };

	if (b->need_nl)
		pg_break(g, b);
	pg_put(g, 'C', "", pg_pick(g, misc, PG_N(misc)));
	b->fresh = b->bol = 0;
	if (g->page[g->pn - 1u] == ' ')
		b->fresh = 1;                   /* after the colon a statement may begin */
}

/* c# and jscript: "text" with escapes, 'c' */
static inline void pg_cs_string(struct pg *g, struct pg_body_state *b, int open)
{
	static const char *const esc_cs[] = { "\\\"", "\\\\", "\\n", "\\x41b", "\\u0041", "\\101", "\\'", "\\0" };
	static const char *const esc_js[] = { "\\\"", "\\\\", "\\n", "\\u0041", "\\'", "\\t" };
	static const char alpha[] = "abc XYZ09',;{}()/*<%#@$&!?[]-+=.";
	char s[96], c[24];
	uint32_t n = pg_rnd(g, 8), k, w = 0;

	if (b->need_nl)
		pg_break(g, b);
	pg_chars(g, c, alpha, n, b->script);
	s[w++] = '"';
	for (k = 0; c[k]; k++) {
		const char *e;

		if (pg_rnd(g, 5) == 0) {
			e = b->lang == PG_JS ? pg_pick(g, esc_js, PG_N(esc_js)) : pg_pick(g, esc_cs, PG_N(esc_cs));
			if (b->js_no_escape_digits && (e[1] == 'x' || (e[1] >= '0' && e[1] <= '7')))
				e = "\\n";
			memcpy(s + w, e, strlen(e));
			w += (uint32_t)strlen(e);
		}
		s[w++] = c[k];
	}
	if (open && w >= 2u && s[w - 1u] == '\\')
		s[w++] = 'a';
	if (!open)
		s[w++] = '"';
	s[w] = 0;
	pg_put(g, 'S', open ? "*!" : "*", s);
	b->fresh = b->bol = 0;
	b->need_nl = open;
}

static inline void pg_js_quote(struct pg *g, struct pg_body_state *b)
{
	static const char *const q[] = { "'a'", "'a\"b'", "'it\\'s'", "'%'", "'<%'", "'//'", "'/*'" };

	if (b->need_nl)
		pg_break(g, b);
	pg_put(g, 'S', "*", pg_pick(g, q, PG_N(q)));
	b->fresh = b->bol = 0;
}

static inline void pg_cs_char(struct pg *g, struct pg_body_state *b)
{
	static const char *const q[] = { "'a'", "'\"'", "'\\''", "'\\\\'", "'\\u0041'", "'{'", "'}'", "'/'" };

	if (b->need_nl)
		pg_break(g, b);
	pg_put(g, 'S', "*", pg_pick(g, q, PG_N(q)));
	b->fresh = b->bol = 0;
}

/* @"..." "" and \ are text; $"..." with holes; $@ and @$; raw """ ... """ with N quotes and N dollars */
static inline void pg_cs_special(struct pg *g, struct pg_body_state *b)
{
	static const char *const sp[] = {
		"@\"a\"\"b\"", "@\"C:\\dir\\\"", "@\"two\nlines\"", "@\"it's // not /* a comment\"", "@\"\"", "@\"\"\"\"",
		"$\"a{b}c\"", "$\"a{{b}}c\"", "$\"{x[\"k\"]}\"", "$\"{f(\"}\")}\"", "$\"{x:N2}\"", "$\"{('}')}\"", "$\"{{{x}}}\"",
		"$\"{a ? \"a\" : \"b\"} {c}\"", "$@\"a\"\"{x}\"\"\"", "@$\"{x}\\\"", "$\"\"",
		"\"\"\"a \"b\" c\"\"\"", "\"\"\"\n  two // lines\n  \"\"\"", "\"\"\"\"x \"\"\" y\"\"\"\"", "\"\"\"a{b}\"\"\"",
		"$\"\"\"a {x} \"b\" c\"\"\"", "$$\"\"\"{{x}} {y} \"q\" \"\"\"", "$\"\"\"{x[\"k\"]}\"\"\"", "\"\"\"\"\"x\"\"\"\"\""
	};
	/* which of them interpolate (the "*" flag): none - verbatim and raw strings have no escapes, and an
	 * interpolated regular string does */
	static const char *const star[] = { "$\"a{b}c\"", "$\"a{{b}}c\"", "$\"{x[\"k\"]}\"", "$\"{f(\"}\")}\"", "$\"{x:N2}\"",
					     "$\"{('}')}\"", "$\"{{{x}}}\"", "$\"{a ? \"a\" : \"b\"} {c}\"", "$\"\"" };
	const char *t;
	uint32_t k;
	int is_star = 0;

	if (b->need_nl)
		pg_break(g, b);
	t = pg_pick(g, sp, PG_N(sp));
	for (k = 0; k < PG_N(star); k++)
		is_star |= strcmp(t, star[k]) == 0;
	pg_put(g, 'S', is_star ? "*" : "", t);
	b->fresh = b->bol = 0;
}

static inline void pg_cs_comment(struct pg *g, struct pg_body_state *b)
{
	static const char alpha[] = "abc XYZ09\"',;{}()//**<%#@$&!?[]-+=.\n";
	char c[40], s[64];
	int block = pg_rnd(g, 2) != 0, open = block && pg_rnd(g, 6) == 0;
	uint32_t k;

	if (b->need_nl)
		pg_break(g, b);
	pg_chars(g, c, alpha, pg_rnd(g, 20), b->script);
	for (k = 0; c[k]; k++) {
		if (!block && c[k] == '\n')
			c[k] = ' ';
		if (block && c[k] == '*' && c[k + 1u] == '/')
			c[k] = ' ';
	}
	if (block)
		snprintf(s, sizeof s, "/*%s%s", c, open ? "" : "*/");
	else
		snprintf(s, sizeof s, "//%s", c);
	pg_put(g, 'K', open ? "!" : "", s);
	b->need_nl = !block;
	b->fresh = b->bol = 0;
	if (block && !open && strchr(s, '\n'))
		b->bol = 0;
	b->done = open;
}

/* a c# preprocessor line: code, with the text of #region as it is */
static inline void pg_cs_pp(struct pg *g, struct pg_body_state *b)
{
	static const char *const pp[] = {
		"#region User's methods \"x\" // not a comment\n", "#endregion\n", "#if DEBUG\n", "#else\n", "#endif\n",
		"  #region it's /* open\n", "#warning don't\n", "#error \"unclosed\n", "# region a'b\n", "#pragma warning disable 1591\n",
		"#define X\n", "#line 10\n"
	};

	if (!b->bol)
		pg_break(g, b);
	pg_put(g, 'C', "", pg_pick(g, pp, PG_N(pp)));
	b->bol = 1;
	b->fresh = 1;
}

static inline void pg_unit(struct pg *g, struct pg_body_state *b)
{
	uint32_t r = pg_rnd(g, 16);

	if (b->lang == PG_VB) {
		if (r < 4)
			pg_code(g, b);
		else if (r < 6)
			pg_break(g, b);
		else if (r < 9)
			pg_vb_string(g, b, 0);
		else if (r < 11)
			pg_vb_comment(g, b);
		else if (r < 12)
			pg_vb_string(g, b, 1);
		else if (r < 14)
			pg_vb_misc(g, b);
		else
			pg_code(g, b);
	} else if (b->lang == PG_CS) {
		if (r < 4)
			pg_code(g, b);
		else if (r < 5)
			pg_break(g, b);
		else if (r < 7)
			pg_cs_string(g, b, 0);
		else if (r < 8)
			pg_cs_string(g, b, pg_rnd(g, 4) == 0);
		else if (r < 9)
			pg_cs_char(g, b);
		else if (r < 11)
			pg_cs_special(g, b);
		else if (r < 13)
			pg_cs_comment(g, b);
		else if (r < 14)
			pg_cs_pp(g, b);
		else
			pg_code(g, b);
	} else {
		if (r < 4)
			pg_code(g, b);
		else if (r < 5)
			pg_break(g, b);
		else if (r < 8)
			pg_cs_string(g, b, 0);
		else if (r < 9)
			pg_cs_string(g, b, pg_rnd(g, 4) == 0);
		else if (r < 11)
			pg_js_quote(g, b);
		else if (r < 14)
			pg_cs_comment(g, b);
		else
			pg_code(g, b);
	}
}

/*
 * A body of up to `max` units in language `lang`. Its first byte must not lengthen the tag before it
 * ("<%" and "=" is "<%="): half the bodies begin with a space, the rest with a code unit, and no code unit
 * begins with one of those bytes.
 */
static inline void pg_body(struct pg *g, int lang, int script, int js_digits, uint32_t max)
{
	struct pg_body_state b = { .lang = lang, .fresh = 1, .bol = 1, .script = script, .js_no_escape_digits = js_digits };
	uint32_t n = pg_rnd(g, max + 1u), k;

	if (!n)
		return;
	if (pg_rnd(g, 2))
		pg_put(g, 'C', "", " ");
	else
		pg_code(g, &b);
	for (k = 1; k < n && !b.done && !g->over; k++)
		pg_unit(g, &b);
}


/* ---- the page ------------------------------------------------------------------------- */

/* The words a Language attribute may use for `lang`, in either page kind. */
static inline const char *pg_langword(struct pg *g, int lang)
{
	static const char *const a_vb[] = { "vbscript", "VBScript", "VBScript.Encode" };
	static const char *const a_js[] = { "jscript", "JavaScript", "JScript.Encode", "ECMAScript" };
	static const char *const x_vb[] = { "vb", "VB", "VisualBasic" };
	static const char *const x_cs[] = { "c#", "C#", "cs", "CSharp" };
	static const char *const x_js[] = { "js", "JScript", "JavaScript" };

	if (!g->aspx)
		return lang == PG_VB ? pg_pick(g, a_vb, PG_N(a_vb)) : pg_pick(g, a_js, PG_N(a_js));
	return lang == PG_VB ? pg_pick(g, x_vb, PG_N(x_vb)) : lang == PG_CS ? pg_pick(g, x_cs, PG_N(x_cs))
								      : pg_pick(g, x_js, PG_N(x_js));
}

/* <% ... %> and its siblings; the body is in `lang`. */
static inline void pg_island(struct pg *g, int lang)
{
	static const char *const t_asp[] = { "<%", "<%=", "<%", "<%" };
	static const char *const t_aspx[] = { "<%", "<%=", "<%#", "<%$", "<%:", "<%" };

	pg_put(g, 'T', "", g->aspx ? pg_pick(g, t_aspx, PG_N(t_aspx)) : pg_pick(g, t_asp, PG_N(t_asp)));
	pg_body(g, lang, 0, !g->aspx, 7);
	pg_put(g, 'T', "", "%>");
}

/* <script ... runat="server"> body </script>, in its own language when it names one. */
static inline void pg_script(struct pg *g, int page_lang, int has_dir)
{
	static const char *const open[] = {
		"<script%s runat=\"server\">", "<script runat=\"server\"%s>", "<SCRIPT%s RUNAT=Server>", "<script  runat = 'server' %s>",
		"<script%s runat=\"server\" src=\"a.vb\">", "<script title=\"a>b\"%s runat=\"server\">", "<script\n runat=\"server\"%s\n>"
	};
	static const char *const close[] = { "</script>", "</SCRIPT>", "</script  >", "</script\n>" };
	int lang = page_lang, with_attr = pg_rnd(g, 2) != 0;
	char attr[48], tag[160];

	attr[0] = 0;
	if (with_attr) {
		static const char *const fmt[] = { " language=\"%s\"", " LANGUAGE=%s", " language='%s'" };

		if (!g->aspx)
			lang = pg_rnd(g, 2) ? PG_VB : PG_JS;
		else if (has_dir)
			lang = (int)pg_rnd(g, 3);
		snprintf(attr, sizeof attr, pg_pick(g, fmt, PG_N(fmt)), pg_langword(g, lang));
	}
	snprintf(tag, sizeof tag, pg_pick(g, open, PG_N(open)), attr);
	pg_put(g, 'T', "", tag);
	pg_body(g, lang, 1, !g->aspx, 8);
	pg_put(g, 'T', "", pg_pick(g, close, PG_N(close)));
}

static inline void pg_directive(struct pg *g, int lang)
{
	char d[200];
	const char *w = pg_langword(g, lang);
	const char *decoy = g->aspx ? "Title=\"language vb\" " : "Title=\"language jscript\" ";
	uint32_t v = pg_rnd(g, 6);

	if (lang == (g->aspx ? PG_VB : PG_JS))
		decoy = g->aspx ? "Title=\"language c#\" " : "Title=\"language vbscript\" ";
	if (!g->aspx) {
		static const char *const f[] = {
			"<%%@ LANGUAGE=\"%s\" %%>", "<%%@ Language=%s %%>", "<%%@Language=\"%s\"%%>",
			"<%%@ CODEPAGE=65001 LANGUAGE=\"%s\" ENABLESESSIONSTATE=False %%>", "<%%@ LANGUAGE = %s%%>",
			"<%%@ Language='%s' %%>"
		};
		snprintf(d, sizeof d, f[v], w);
		if (v == 1 && pg_rnd(g, 2))
			snprintf(d, sizeof d, "<%%@ %sLanguage=%s %%>", decoy, w);
	} else {
		static const char *const f[] = {
			"<%%@ Page Language=\"%s\" %%>", "<%%@ Page Title=\"x\" Language='%s' CodeFile=\"a.cs\" %%>",
			"<%%@ Control Language=%s %%>", "<%%@ Master Language=\"%s\"%%>",
			"<%%@ Import Namespace=\"System.IO\" %%><%%@ Page Language=\"%s\" %%>", "<%%@ Page Language=\"%s\" Debug=\"true\" %%>"
		};
		snprintf(d, sizeof d, f[v], w);
		if (v == 5 && pg_rnd(g, 2))
			snprintf(d, sizeof d, "<%%@ Page %sLanguage=\"%s\" %%>", decoy, w);
	}
	pg_put(g, 'M', "", d);
}

static inline void pg_markup(struct pg *g)
{
	static const char *const m[] = {
		"Hello", "<b>x</b>", "a < b", "<br/>", "&lt;%", "<div class=\"a\">", "</div>", "<!-- plain -->",
		"<a href=\"x?a=1>2\">l</a>", "<![CDATA[ x ]]>", "<style>a>b{}</style>", "<script>var a = 1 < 2;</script>",
		"<script language=\"vbscript\">x = 1</script>", "<script runat=\"client\">x</script>",
		"<script data-runat=\"server\">x</script>", "<script title=\"runat=server\">x</script>",
		"<!--#include file=\"a.asp\"-->", "<!--#include virtual=\"/b/c.asp\"-->", "\r\n", "\n", " ", "< ", " %>",
		"<?xml version=\"1.0\"?>", "</script>", "<asp:Button runat=\"server\" Text=\"a > b\" />", "x%>y", "<-"
	};

	pg_put(g, 'M', "", pg_pick(g, m, PG_N(m)));
}

/* markup that an island sits inside: an attribute value, an html comment, a CDATA section, a client script */
static inline void pg_wrapped(struct pg *g, int lang)
{
	static const char *const w[][2] = {
		{ "<input value=\"", "\">" }, { "<!-- ", " -->" }, { "<![CDATA[ ", " ]]>" }, { "<script>var a='", "';</script>" },
		{ "<a href='", "'>" }, { "<textarea>", "</textarea>" }
	};
	uint32_t k = pg_rnd(g, PG_N(w));

	pg_put(g, 'M', "", w[k][0]);
	pg_island(g, lang);
	pg_put(g, 'M', "", w[k][1]);
}

/* <%-- ... --%> (aspx): a comment of the page; "%>" and "<%" inside it are its text */
static inline void pg_dash(struct pg *g)
{
	static const char alpha[] = "abc XYZ09\"',;{}()/*<%>#@$&!?[]-+=.\n";
	char c[48], s[64];
	uint32_t k;

	pg_chars(g, c, alpha, pg_rnd(g, 24), 1);
	for (k = 0; c[k] && c[k + 1u] && c[k + 2u] && c[k + 3u]; k++)
		if (!memcmp(c + k, "--%>", 4))
			c[k] = ' ';
	snprintf(s, sizeof s, "<%%--%s--%%>", c);
	pg_put(g, 'K', "", s);
}

/* One valid page. Its language is a directive's, or the default, and its islands and script elements are in it. */
static inline void pg_page(struct pg *g, int aspx)
{
	int def = aspx ? PG_CS : PG_VB, lang = def, has_dir;
	uint32_t n, k, dpos;

	g->aspx = aspx;
	if (pg_rnd(g, 3) == 0)
		lang = aspx ? (int)pg_rnd(g, 3) : PG_JS;
	has_dir = lang != def || pg_rnd(g, 4) != 0;
	n = 2u + pg_rnd(g, 9);
	dpos = pg_rnd(g, 3) ? 0 : pg_rnd(g, n + 1u);
	for (k = 0; k <= n && !g->over; k++) {
		uint32_t r;

		if (has_dir && k == dpos)
			pg_directive(g, lang);
		if (k == n)
			break;
		r = pg_rnd(g, 12);
		if (r < 3)
			pg_markup(g);
		else if (r < 6)
			pg_island(g, lang);
		else if (r < 8)
			pg_script(g, lang, has_dir);
		else if (r < 9)
			pg_wrapped(g, lang);
		else if (r < 10 && aspx)
			pg_dash(g);
		else
			pg_markup(g);
	}
	pg_flush(g);
}

/* ---- the checks over generated pages ------------------------------------------------------ */

/* Every page of `count`: the lexer's rendering is the generator's. Prints the first three differences. */
static inline void pg_check_lex(uint32_t lang, int aspx, uint32_t seed, uint32_t count)
{
	static struct pg g;
	static struct rend r;
	uint32_t i, bad = 0, checked = 0;
	uint64_t bytes = 0;

	for (i = 0; i < count; i++) {
		memset(&g, 0, sizeof g);
		g.s = seed + i * 2654435761u;
		pg_page(&g, aspx);
		if (g.over)
			continue;
		lex(&r, g.page, g.pn, lang);
		checked++;
		bytes += g.pn;
		if (r.broken || strcmp(r.out, g.want)) {
			if (++bad <= 3)
				printf("  FAIL generated page %u\n    page   %s\n    got    %s\n    wanted %s\n", i, g.page, r.out, g.want);
		}
	}
	printf("  generated pages: %u checked (%llu bytes), %u differ from what the generator knew\n", checked,
	       (unsigned long long)bytes, bad);
	CK(bad == 0);
	CK(checked > count / 2u);
}

/* what a lex of a text holds that the form must not touch: the strings, in order, and all the markup */
struct pg_keep {
	char     str[3u * PG_PAGE];
	char     mk[3u * PG_PAGE];
	uint32_t ns, nm;
	const uint8_t *in;
};

static inline int pg_keep_sink(void *u, const struct kgenome_textual_span *s)
{
	struct pg_keep *k = u;

	if (s->kind == KGENOME_TEXTUAL_STRING && k->ns + s->len + 2u < sizeof k->str) {
		memcpy(k->str + k->ns, k->in + s->off, s->len);
		k->ns += s->len;
		k->str[k->ns++] = 1;
	} else if (s->kind == KGENOME_TEXTUAL_MARKUP && k->nm + s->len + 1u < sizeof k->mk) {
		memcpy(k->mk + k->nm, k->in + s->off, s->len);
		k->nm += s->len;
	}
	return 1;
}

static inline void pg_keep_of(struct pg_keep *k, uint32_t lang, const uint8_t *in, uint32_t n)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = lang, .sink = pg_keep_sink, .user = k };
	struct kgenome_textual_lex_res rs;

	memset(k, 0, sizeof *k);
	k->in = in;
	kgenome_textual_lex(&rq, &rs);
}

/*
 * The form of every generated page: it keeps the strings and the markup as they were typed (a string that
 * is not closed too), the form of the form is itself, and what it wrote lexes as a partition.
 */
static inline void pg_check_form(uint32_t lang, int aspx, uint32_t seed, uint32_t count)
{
	static struct pg g;
	static struct pg_keep k1, k2;
	static uint8_t o1[4u * PG_PAGE], o2[4u * PG_PAGE];
	static struct rend r;
	uint32_t i, bad = 0, checked = 0;

	for (i = 0; i < count; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		uint32_t w1, w2;
		const char *why = NULL;

		memset(&g, 0, sizeof g);
		g.s = seed + i * 2654435761u;
		pg_page(&g, aspx);
		if (g.over)
			continue;
		checked++;
		rq = (struct kgenome_textual_form_req){ .in = (const uint8_t *)g.page, .n = g.pn, .lang = lang, .out = o1,
							.cap = KGENOME_TEXTUAL_FORM_CAP(g.pn) };
		kgenome_textual_form(&rq, &rs);
		w1 = rs.n_out;
		rq = (struct kgenome_textual_form_req){ .in = o1, .n = w1, .lang = lang, .out = o2, .cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
		kgenome_textual_form(&rq, &rs);
		w2 = rs.n_out;
		pg_keep_of(&k1, lang, (const uint8_t *)g.page, g.pn);
		pg_keep_of(&k2, lang, o1, w1);
		lex(&r, o1, w1, lang);
		if (w1 != w2 || memcmp(o1, o2, w1))
			why = "the form is not its own form";
		else if (k1.ns != k2.ns || memcmp(k1.str, k2.str, k1.ns))
			why = "a string was changed";
		else if (k1.nm != k2.nm || memcmp(k1.mk, k2.mk, k1.nm))
			why = "markup was changed";
		else if (r.broken)
			why = "the form does not lex as a partition";
		if (why && ++bad <= 3) {
			o1[w1] = 0;
			printf("  FAIL form of generated page %u: %s\n    page %s\n    form %s\n", i, why, g.page, (char *)o1);
		}
	}
	printf("  generated pages formed: %u checked, %u failed\n", checked, bad);
	CK(bad == 0);
}

#endif /* KGENOME_TEST_TEXTUAL_PAGEGEN_H */
