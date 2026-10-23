#ifndef KGENOME_TEST_TEXTUAL_CFM_GEN_H
#define KGENOME_TEST_TEXTUAL_CFM_GEN_H

/*
 * textual_cfm_gen.h - a GENERATOR of valid coldfusion pages and script components, for textual_cfm.c.
 *
 * A page is built from pieces whose class is KNOWN when they are written - markup, an html comment, a cf comment (nested),
 * a tag with nothing in it, a tag with attributes (code, strings, "#...#", comments inside), a <cfoutput> / <cfquery> /
 * <cfmail> body with "#...#" in its text, a <cfscript> block - and each piece is appended to the page text and, in the same
 * call, to the list of spans the lexer must produce. The lexer is checked against what the generator KNEW, not against a
 * second lexer. Neighbours merge as the lexer merges them: two runs of markup, or of code, are one span.
 *
 * WHAT THE GENERATOR KEEPS AWAY FROM, because the page scanner would read it differently from how it was written: a tag's
 * ">" outside a string or a "#...#"; a "/" at the end of a piece of tag code (it would meet the tag's end and become "/>");
 * a lone "#" or a lone quote in a string (an error in CFML, and the lexer's answer there is a decision of its own that
 * the hand cases state); "</cfscript" in a script body except where it ends it; "<cf" followed by a letter in markup. It does
 * NOT keep away from ">" , "<cfset>", "<!---", "--->", slash-slash and slash-star inside strings, from "#" in markup outside an output
 * tag, from "<!--" in markup, or from a ">" in a "#...#": those are the cases the lexer exists for.
 *
 * THE GENERATOR AND THE LEXER ARE BY ONE AUTHOR, so this catches inconsistency and slips, not a shared misreading of CFML:
 * the hand cases of textual_cfm.c state the rules, and the three real files of the corpus are read in scratch.
 */

#include "textual_check.h"

#define GEN_MAX 16384u

struct gsp {
	uint32_t off, len, open, close;
	uint8_t  kind, flags;
};

static uint32_t gen_rng;
static uint8_t gen_pg[GEN_MAX];
static uint32_t gen_pn, gen_nex;
static struct gsp gen_ex[4096];
static int gen_over;
static int gen_stop;      /* the text ends in what was just written: nothing may follow it */
static int gen_script_open; /* the script body just written ends in a string or comment that never closes */
static int gen_in_script; /* writing the body of a cfscript or a component: "</cfscript>" would end it */

static uint32_t gen_pick(uint32_t n)
{
	gen_rng = gen_rng * 1103515245u + 12345u;
	return (gen_rng >> 16) % n;
}

#define G_CODE KGENOME_TEXTUAL_CODE
#define G_STR  KGENOME_TEXTUAL_STRING
#define G_COM  KGENOME_TEXTUAL_COMMENT
#define G_MUP  KGENOME_TEXTUAL_MARKUP
#define G_TAG  KGENOME_TEXTUAL_TAG
#define G_INT  KGENOME_TEXTUAL_F_INTERP
#define G_OPN  KGENOME_TEXTUAL_F_OPEN
#define G_CLS  KGENOME_TEXTUAL_F_CLOSE
#define GN(a)  ((uint32_t)(sizeof (a) / sizeof (a)[0]))

/* Append `t` to the page as one piece of the class the generator says it is. */
static void gen_add(uint8_t kind, uint8_t flags, uint32_t open, uint32_t close, const char *t)
{
	uint32_t l = (uint32_t)strlen(t);

	if (!l)
		return;
	if (gen_pn + l > GEN_MAX || gen_nex >= GN(gen_ex)) {
		gen_over = 1;
		return;
	}
	memcpy(gen_pg + gen_pn, t, l);
	if (gen_nex && (kind == G_CODE || kind == G_MUP) && !flags && gen_ex[gen_nex - 1u].kind == kind &&
	    !gen_ex[gen_nex - 1u].flags)
		gen_ex[gen_nex - 1u].len += l;
	else
		gen_ex[gen_nex++] = (struct gsp){ gen_pn, l, open, close, kind, flags };
	gen_pn += l;
}

/* ---- strings ------------------------------------------------------------------------------------ */

/* %Q is the string's own quote, %O the other one. Every atom is whole: a quote is doubled, a "#" is doubled or opens
 * an expression that closes, and inside an expression a nested string closes. */
static const char *const str_atom[] = {
	"abc", " ", "x y", "%O", "%Q%Q", "##", "#x#", "#f(%Qa%Q)#", "#f(%Oa%O)#", "#a.b#", ">", "<cfset x>", "<!---", "--->",
	"//", "/*", "\\", "%", "</cfscript>", "<cfoutput>", "#f(%Q%Q)#", "#f(%Q#g(%Qz%Q)#%Q)#", "&", "\n", "\r\n", "=",
	"#a > b#", "</cfif>", "%Q%Q%Q%Q", "#h(%Qa%Q%Qb%Q)#",
};

/* The text of a string with its quote `q`, `open` when it is not closed. */
static void gen_str_text(char q, int open, char *dst, size_t cap)
{
	uint32_t n = gen_pick(6), k;
	size_t w = 0;

	dst[w++] = q;
	for (k = 0; k < n; k++) {
		const char *a = str_atom[gen_pick(GN(str_atom))];

		if (gen_in_script && !strcmp(a, "</cfscript>"))
			a = "</cfscripts>";
		for (; *a && w + 2u < cap; a++) {
			if (a[0] == '%' && a[1] == 'Q') {
				dst[w++] = q;
				a++;
			} else if (a[0] == '%' && a[1] == 'O') {
				dst[w++] = q == '"' ? '\'' : '"';
				a++;
			} else {
				dst[w++] = *a;
			}
		}
	}
	if (!open)
		dst[w++] = q;
	dst[w] = 0;
}

static void gen_str(int open)
{
	char t[512];
	char q = gen_pick(2) ? '"' : '\'';

	gen_str_text(q, open, t, sizeof t);
	gen_add(G_STR, (uint8_t)(G_INT | (open ? G_OPN : 0u)), 1u, open ? 0u : 1u, t);
}

/* ---- cf comments ---------------------------------------------------------------------------------- */

static const char *const cm_atom[] = { "abc ", "\n", "> ", "\"", "'", "#", "<cfset x> ", "-- ", "- ", "<!-- ", "--> ", "<! ", "</cfif> " };

static void gen_cm_body(char *dst, size_t cap, uint32_t depth)
{
	uint32_t n = gen_pick(5), k;

	dst[0] = 0;
	for (k = 0; k < n; k++) {
		char sub[256];
		const char *a;

		if (depth < 3u && gen_pick(5) == 0) {
			gen_cm_body(sub, sizeof sub - 32u, depth + 1u);
			if (strlen(dst) + strlen(sub) + 16u < cap) {
				strcat(dst, "<!--- ");
				strcat(dst, sub);
				strcat(dst, " ---> ");
			}
			continue;
		}
		a = cm_atom[gen_pick(GN(cm_atom))];
		if (strlen(dst) + strlen(a) + 1u < cap)
			strcat(dst, a);
	}
}

/* A cf comment, or the start of one when `open`. A space after the opener and in front of the closer: "<!---" and "--->"
 * glued to an atom that begins or ends with a dash would move the delimiter. */
static void gen_cf_comment(int open)
{
	char body[900], t[1000];

	gen_cm_body(body, sizeof body, 0);
	snprintf(t, sizeof t, open ? "<!--- %s" : "<!--- %s --->", body);
	gen_add(G_COM, (uint8_t)(open ? G_OPN : 0u), 5u, open ? 0u : 4u, t);
}

/* ---- tags ----------------------------------------------------------------------------------------- */

static const char *const tag_name[] = {
	"cfset", "cfif", "cfelseif", "cfexecute", "cfinclude", "cfhttp", "cffile", "cfloop", "cffunction", "cfargument",
	"cfreturn", "CFSET", "cf_mytag", "cfx_x", "cfmodule", "CfInclude", "cfheader", "cfparam", "cfcomponent",
};

/* Tag code that holds no quote, no "#", no ">" and does not end in "/". */
static const char *const tag_code[] = {
	" x = ", " a eq b ", " name=", " gt 1 ", " attr ", " a/b ", " http://h/p ", " a /* c */ b ", " -1 ", " a-b ", " x.y[1] ",
	" a & b ", " a // b ", " x < y ", " arguments=", " f(a, b) ", " (a) ", "\n  ", "\t", " a lt b and c gte d ", " x[1]=2 ",
};

static const char *const hash_code[] = { "#x#", "#a > b#", "##", " #a.b# ", "#f(a)#", "#a < b#", "#x# #y#" };

/* A "#...#" in tag code with a string in it: its text is split around the string, which is a STRING span. */
static void gen_tag_hash_str(void)
{
	char q = gen_pick(2) ? '"' : '\'', s[8] = { q, '>', q, 0 };

	gen_add(G_CODE, 0, 0, 0, " #f(");
	gen_add(G_STR, G_INT, 1u, 1u, s);
	gen_add(G_CODE, 0, 0, 0, ")# ");
}

static void gen_tag_piece(void)
{
	uint32_t t = gen_pick(12);

	if (t < 4u) {
		gen_add(G_CODE, 0, 0, 0, tag_code[gen_pick(GN(tag_code))]);
	} else if (t < 7u) {
		gen_add(G_CODE, 0, 0, 0, " ");
		gen_str(0);
	} else if (t < 8u) {
		gen_add(G_CODE, 0, 0, 0, hash_code[gen_pick(GN(hash_code))]);
	} else if (t < 9u) {
		gen_tag_hash_str();
	} else if (t < 10u) {
		char c[900], tx[1000];

		gen_cm_body(c, sizeof c, 1u);
		snprintf(tx, sizeof tx, "<!--- %s --->", c);
		gen_add(G_CODE, 0, 0, 0, " ");
		gen_add(G_COM, 0, 5u, 4u, tx);
	} else {
		gen_add(G_CODE, 0, 0, 0, " ");
		gen_str(0);
		gen_add(G_CODE, 0, 0, 0, " ");
		gen_str(0);
	}
}

/* What stands between the last piece and the tag's end (a blank, or nothing), and the end. */
static const struct { const char *pre, *end; } closers[] = {
	{ "", ">" }, { "", "/>" }, { "", "/ >" }, { "\n", "/>" }, { " ", ">" }, { "\n", ">" }, { "", "/\n>" },
};

/*
 * A tag `name` with `pieces` pieces of code in it: one TAG when it holds none and ends at once, else head, code, end. A tag
 * may be left unclosed when `last`: then it has no end, and may end in an open string. `self` allows "/>": an output tag
 * that closed itself would hold no text.
 */
static void gen_tag(const char *name, int closing, uint32_t pieces, int last, int self)
{
	char head[64];
	uint32_t k, ci;

	do
		ci = gen_pick(GN(closers));
	while (!self && closers[ci].end[0] == '/');
	snprintf(head, sizeof head, closing ? "</%s" : "<%s", name);
	if (!pieces && !closers[ci].pre[0]) {
		char t[96];

		snprintf(t, sizeof t, "%s%s", head, closers[ci].end);
		gen_add(G_TAG, 0, 0, 0, t);
		return;
	}
	gen_add(G_TAG, 0, 0, 0, head);
	if (!pieces)
		gen_add(G_CODE, 0, 0, 0, closers[ci].pre);
	for (k = 0; k < pieces; k++)
		gen_tag_piece();
	if (last && gen_pick(3) == 0) {
		/* the text ends in the tag: after its code, or inside a string that never closes */
		if (gen_pick(2) == 0) {
			gen_add(G_CODE, 0, 0, 0, " ");  /* a quote right after a string's would double it */
			gen_str(1);
		}
		gen_stop = 1;
		return;
	}
	if (pieces)
		gen_add(G_CODE, 0, 0, 0, closers[ci].pre[0] ? closers[ci].pre : " ");
	gen_add(G_TAG, 0, 0, 0, closers[ci].end);
}

/* ---- markup ---------------------------------------------------------------------------------------- */

/* Never ends in "<" or "<!--" (the next piece begins with "<"), never holds "<cf" + a letter, "<!---" or "</cf". */
static const char *const mk_atom[] = {
	"hello ", "<b>", "</b>", "<a href=\"x.html\">", "<img src='a.png'/>", "<p>\n", "text 50% off ", "a > b ", "<!-- c -->",
	"cost $5 ", "\n", "\r\n", "<cf>", "<cf ", "<c f>", "<!-- not a cf comment -- >", "&amp; ", "<script>var a = 1 // x\n</script>",
	"<input type=text name=\"x\" value=\"\">", "<!--[if IE]>", " / ", "<<", "<!-", 
};
/* Only outside an output tag: "#" is text there. "##" is text everywhere. */
static const char *const mk_hash_atom[] = { "#top ", "x#y ", "<a href=\"#top\">", "a # b ", "#", "#x#", "'#'", "<style>#id { color: #fff }</style>" };
static const char *const mk_out_atom[] = { "## ", "a ## b ", "##x## ", "<a href=\"##top\">" };

static void gen_markup(int in_out)
{
	uint32_t n = 1u + gen_pick(3), k;

	for (k = 0; k < n; k++) {
		uint32_t t = gen_pick(8);
		const char *a;

		if (t == 0 && !in_out)
			a = mk_hash_atom[gen_pick(GN(mk_hash_atom))];
		else if (t == 0)
			a = mk_out_atom[gen_pick(GN(mk_out_atom))];
		else
			a = mk_atom[gen_pick(GN(mk_atom))];
		/* "<cfs " cannot turn into a tag; "<cf " neither; but a markup ending in "<" followed by "cf" would */
		gen_add(G_MUP, 0, 0, 0, a);
	}
}

/* "#...#" in the text of an output tag: TAG, code (with a string perhaps), TAG. */
static void gen_out_hash(void)
{
	static const char *const body[] = { "x", "a.b(c)", " x + y ", "a > b", "a < b", "f(a, b)", "a & b" };
	uint32_t t = gen_pick(5);

	gen_add(G_TAG, 0, 0, 0, "#");
	if (t == 0) {
		char q = gen_pick(2) ? '"' : '\'', s[512];

		gen_add(G_CODE, 0, 0, 0, "f(");
		gen_str_text(q, 0, s, sizeof s);
		gen_add(G_STR, G_INT, 1u, 1u, s);
		gen_add(G_CODE, 0, 0, 0, ")");
	} else if (t == 1u) {
		char q = gen_pick(2) ? '"' : '\'', s[512];

		gen_add(G_CODE, 0, 0, 0, "toString(");
		gen_str_text(q, 0, s, sizeof s);
		gen_add(G_STR, G_INT, 1u, 1u, s);
		gen_add(G_CODE, 0, 0, 0, ") & ");
		gen_str_text(q, 0, s, sizeof s);
		gen_add(G_STR, G_INT, 1u, 1u, s);
	} else {
		const char *b = body[gen_pick(GN(body))];

		gen_add(G_CODE, 0, 0, 0, b);
	}
	gen_add(G_TAG, 0, 0, 0, "#");
}

static const char *const out_name[] = { "cfoutput", "cfquery", "cfmail", "CFOUTPUT", "CfQuery" };

/* An output tag, its text with "#...#" in it, nested output tags, and its end tag. */
static void gen_output(uint32_t depth)
{
	const char *name = out_name[gen_pick(GN(out_name))];
	uint32_t n = 1u + gen_pick(4), k;
	char t[64];

	if (gen_pick(3) == 0) {
		gen_tag(name, 0, 1u, 0, 0);     /* attributes: <cfoutput query=...> */
	} else {
		snprintf(t, sizeof t, "<%s>", name);
		gen_add(G_TAG, 0, 0, 0, t);
	}
	for (k = 0; k < n; k++) {
		uint32_t w = gen_pick(8);

		if (w < 3u)
			gen_markup(1);
		else if (w < 6u)
			gen_out_hash();
		else if (w == 6u && depth < 3u)
			gen_output(depth + 1u);
		else
			gen_add(G_MUP, 0, 0, 0, " ");
	}
	snprintf(t, sizeof t, "</%s>", name);
	gen_add(G_TAG, 0, 0, 0, t);
}

/* ---- script ---------------------------------------------------------------------------------------- */

/* No quote, no comment opener, nothing that ends a cfscript. A "<!---" is code here: the script does not know it. */
static const char *const sc_code[] = {
	"x = 1;", "foo(bar);", "a & b", "a / b", "if (a > b) { c(); }", "#x#", "<cfset", "a <b", "writeOutput(x);", "a /b/ c",
	"{", "}", "<!--- c --->", "</cfif>", "x = y ? 1 : 2;", "a.b[1]++;", "for (i = 1; i <= n; i++) {}", "var s = ", "return;",
	"</cfscripts>", "</cf script>", "<cfscript", "</ cfscript>", "arr = [1, 2];", "s = {a: 1};", "a == b", "x -= 1;",
};
static const char *const sc_blk[] = { "abc ", "\"", "'", "//", "<!--- ", "#", ">", "</cfif> ", "a*b", "a/b", "\n", "\r\n", "</cfscripts> " };
static const char *const sc_line[] = { "abc ", "\"", "'", "/*", "*/", "<!--- ", "#", ">", "</cfif> ", "//", "</cfscripts> " };
static const char *const sc_eol[] = { "\n", "\r\n", "\r", "\n  ", "\r\n\t" };

static void gen_sc_comment(int open)
{
	char t[640];
	uint32_t n = gen_pick(5), k;

	if (gen_pick(2) == 0) {
		strcpy(t, "//");
		for (k = 0; k < n; k++)
			strcat(t, sc_line[gen_pick(GN(sc_line))]);
		gen_add(G_COM, 0, 2u, 0, t);
		return;
	}
	strcpy(t, "/*");
	for (k = 0; k < n; k++)
		strcat(t, sc_blk[gen_pick(GN(sc_blk))]);
	if (!open)
		strcat(t, "*/");
	gen_add(G_COM, (uint8_t)(open ? G_OPN : 0u), 2u, open ? 0u : 2u, t);
}

/*
 * The code of a cfscript block or a component: tokens of known class, separated so that no token changes its neighbour.
 * White space goes between any two (a line break after a "//" comment, which would take the next token); the last token
 * is open about one block in eight when it is a string or a block comment.
 */
static void gen_script(void)
{
	uint32_t n = gen_pick(9), k;
	int final_open = gen_pick(8) == 0, after_line = 0;

	gen_script_open = 0;

	for (k = 0; k < n; k++) {
		uint32_t t = gen_pick(8);
		int open = k + 1u == n && final_open && (t == 3u || t == 4u || t == 5u);

		gen_add(G_CODE, 0, 0, 0, after_line ? sc_eol[gen_pick(GN(sc_eol))] : " ");
		after_line = 0;
		if (t < 3u) {
			gen_add(G_CODE, 0, 0, 0, sc_code[gen_pick(GN(sc_code))]);
		} else if (t == 3u || t == 4u) {
			gen_str(open);
		} else if (t == 5u) {
			gen_sc_comment(open);
			after_line = gen_ex[gen_nex - 1u].kind == G_COM && gen_ex[gen_nex - 1u].open == 2u &&
				     gen_ex[gen_nex - 1u].close == 0u && gen_pg[gen_ex[gen_nex - 1u].off + 1u] == '/';
		} else {
			gen_add(G_CODE, 0, 0, 0, sc_code[gen_pick(GN(sc_code))]);
		}
		if (open) {
			gen_script_open = 1;
			return;
		}
	}
	gen_add(G_CODE, 0, 0, 0, after_line ? sc_eol[gen_pick(GN(sc_eol))] : " ");
}

static const char *const sc_end[] = { "</cfscript>", "</CFSCRIPT>", "</cfscript >", "</cfscript\n>", "</CfScript\t>" };

static void gen_cfscript(int last)
{
	const char *name = gen_pick(2) ? "<cfscript" : "<CFSCRIPT";

	if (gen_pick(4) == 0) {
		gen_add(G_TAG, 0, 0, 0, name);
		gen_add(G_CODE, 0, 0, 0, " ");
		gen_add(G_TAG, 0, 0, 0, ">");
	} else {
		char t[16];

		snprintf(t, sizeof t, "%s>", name);
		gen_add(G_TAG, 0, 0, 0, t);
	}
	gen_in_script = 1;
	gen_script();
	gen_in_script = 0;
	if (last && gen_pick(4) == 0)
		gen_stop = 1;          /* not closed: the script runs to the end of the text */
	else
		gen_add(G_TAG, G_CLS, 0, 0, sc_end[gen_pick(GN(sc_end))]);
}

/* ---- the page -------------------------------------------------------------------------------------- */

/* The text ends inside something with no end tag: an open cf comment. */
static int gen_ends_unclosed(void)
{
	return gen_stop || (gen_nex && (gen_ex[gen_nex - 1u].flags & G_OPN) && gen_ex[gen_nex - 1u].kind == G_COM &&
			    gen_ex[gen_nex - 1u].open == 5u);
}

static void gen_piece(int last)
{
	uint32_t t = gen_pick(12);

	switch (t) {
	case 0:
	case 1:
	case 2:
		gen_markup(0);
		break;
	case 3:
		gen_cf_comment(last && gen_pick(5) == 0);
		break;
	case 4:
	case 5:
	case 6:
		gen_tag(tag_name[gen_pick(GN(tag_name))], gen_pick(4) == 0, gen_pick(5), last, 1);
		break;
	case 7: {
		static const char *const bare[] = { "cfelse", "cfabort", "cfbreak", "cfreturn" };
		char tx[48];

		snprintf(tx, sizeof tx, "<%s>", bare[gen_pick(GN(bare))]);
		gen_add(G_TAG, 0, 0, 0, tx);
		gen_add(G_TAG, 0, 0, 0, "</cfif>");
		break;
	}
	case 8:
	case 9:
		gen_output(0);
		break;
	default:
		gen_cfscript(last);
	}
}

/* One page. The text ends where a piece ends, or inside one that has no end. */
static void gen_page(uint32_t seed)
{
	uint32_t n, k;

	gen_rng = seed;
	gen_pn = gen_nex = 0;
	gen_over = 0;
	gen_stop = gen_in_script = 0;
	n = 1u + gen_pick(9);
	for (k = 0; k < n && !gen_over; k++) {
		gen_piece(k + 1u == n);
		if (gen_ends_unclosed())
			break;
	}
}

/* A script component: `component {` or with attributes, a doc comment before it, the code, "}". */
static void gen_component(uint32_t seed)
{
	static const char *const head[] = { "component {", "component\n{", "component extends=", "component accessors=true output=false {",
					    "/** doc */ component {", "// c\ncomponent {", "<!--- c --->\ncomponent {", "COMPONENT {",
					    "interface {", "component displayname=" };
	uint32_t h;
	char t[64];

	gen_rng = seed;
	gen_pn = gen_nex = 0;
	gen_over = gen_stop = 0;
	gen_in_script = 1;
	h = gen_pick(GN(head));
	/* the head, as spans: code, and the comment before it, and a string where the attribute has one */
	if (h == 4u) {
		gen_add(G_COM, 0, 2u, 2u, "/** doc */");
		gen_add(G_CODE, 0, 0, 0, " component {");
	} else if (h == 5u) {
		gen_add(G_COM, 0, 2u, 0, "// c");
		gen_add(G_CODE, 0, 0, 0, "\ncomponent {");
	} else if (h == 6u) {
		/* a cf comment is not a script comment: in script it is code (and "c" holds no quote) */
		gen_add(G_CODE, 0, 0, 0, "<!--- c --->\ncomponent {");
	} else if (h == 2u || h == 9u) {
		gen_add(G_CODE, 0, 0, 0, head[h]);
		snprintf(t, sizeof t, "%s", "\"x\"");
		gen_add(G_STR, G_INT, 1u, 1u, t);
		gen_add(G_CODE, 0, 0, 0, " {");
	} else {
		gen_add(G_CODE, 0, 0, 0, head[h]);
	}
	gen_script();
	if (!gen_script_open)
		gen_add(G_CODE, 0, 0, 0, "}");
	gen_in_script = 0;
}

#endif /* KGENOME_TEST_TEXTUAL_CFM_GEN_H */
