/*
 * genome / textual_jsp - the jsp lexer of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED. (a) KNOWN ANSWERS: a text and the one span line it must come out as (kind letter and the
 * bytes in braces, S* = a backslash escapes, ! = not closed). Every rule is paired with the neighbour it
 * could be confused for: "<%--" and "<%-", "%>" and "%\>", "<%" and "<\%", "${" and "\${", a CDATA end and a
 * string that holds "]]>", a text block and three quotes with no line break after them.
 * (b) A GENERATOR builds pages from pieces whose class is known when they are written - markup, EL, directives,
 * page comments, scriptlets, declarations, expressions and the XML elements, with java made of code, strings,
 * chars, text blocks and comments, some spelled with \uXXXX - and the expected spans are written by the
 * generator, never by the lexer; thousands of pages from a fixed seed. THE GENERATOR AND THE LEXER ARE BY
 * ONE AUTHOR, so (b) catches inconsistency and slips, not a shared misreading of the spec: (a) states the
 * spec's cases by hand, and the real java and jsp files of this machine were lexed in scratch against an
 * independent lexer (see the report that came with this test).
 * (c) The partition and the idempotence of the form on random text from a jsp alphabet, and on the generated pages,
 * where a form must also leave every string byte for byte. (d) Form known answers, and the decoder hook.
 */

#include "textual_check.h"

#define J KGENOME_TEXTUAL_LANG_JSP

static void jsp(const char *src, const char *want)
{
	expect_lang(J, src, want);
}

static void jform(const char *src, const char *want)
{
	form_lang(J, src, want);
}

/* ---- (a) the page ---------------------------------------------------------------------------- */

static void page_rules(void)
{
	jsp("", "");
	jsp("<b>x</b>", "M{<b>x</b>}");
	jsp("a<% x %>b", "M{a}T{<%}C{ x }T{%>}M{b}");
	jsp("<%= a %>", "T{<%=}C{ a }T{%>}");
	jsp("<%! int a; %>", "T{<%!}C{ int a; }T{%>}");
	/* "<%#" and "<%$" are tags in asp.net; in a jsp they are scriptlets whose code begins with that byte */
	jsp("<%# x %>", "T{<%}C{# x }T{%>}");
	jsp("<%$ x %>", "T{<%}C{$ x }T{%>}");
	/* an empty island, and one cut by the end of the text */
	jsp("<%%>", "T{<%}T{%>}");
	jsp("<%", "T{<%}");
	jsp("<% x", "T{<%}C{ x}");
	jsp("<%=", "T{<%=}");
	/* a "<%" inside the code is code: only "%>" means anything there */
	jsp("<% a <% b %>", "T{<%}C{ a <% b }T{%>}");

	/* directives are the page's, verbatim; "%>" ends one, "%\>" does not */
	jsp("<%@ page import=\"java.util.*\" %>", "M{<%@ page import=\"java.util.*\" %>}");
	jsp("<%@ taglib uri=\"http://x\" prefix=\"c\" %><% c %>", "M{<%@ taglib uri=\"http://x\" prefix=\"c\" %>}T{<%}C{ c }T{%>}");
	jsp("<%@ page info=\"a%\\>\" %><% c %>", "M{<%@ page info=\"a%\\>\" %>}T{<%}C{ c }T{%>}");
	/* a "%>" in a quoted attribute is not allowed by the spec; the first one ends the directive, so what
	 * follows it is not hidden in the directive's quotes */
	jsp("<%@ page info=\"a%> <% c %>\" %>", "M{<%@ page info=\"a%> }T{<%}C{ c }T{%>}M{\" %>}");
	jsp("<%@ page", "M{<%@ page}");

	/* a page comment ends at the first "--%>" whatever is inside */
	jsp("<%-- a %> <% b --%>x", "K{<%-- a %> <% b --%>}M{x}");
	jsp("<%----%>", "K{<%----%>}");
	jsp("<%-- open", "K!{<%-- open}");
	jsp("<%--%>", "K!{<%--%>}");
	/* "<%-" with one dash is a scriptlet */
	jsp("<%- a %>", "T{<%}C{- a }T{%>}");
	jsp("<% -- a %>", "T{<%}C{ -- a }T{%>}");

	/* "<\%" and "%\>" in markup, a stray "%>" in markup */
	jsp("a <\\% b %> c", "M{a <\\% b %> c}");
	jsp("<\\%= x %\\> <% y %>", "M{<\\%= x %\\> }T{<%}C{ y }T{%>}");
	jsp("a %> b", "M{a %> b}");
	jsp("<!-- <% x %> -->", "M{<!-- }T{<%}C{ x }T{%>}M{ -->}");
	jsp("<script>var a = \"<%= x %>\";</script>", "M{<script>var a = \"}T{<%=}C{ x }T{%>}M{\";</script>}");
	jsp("$<%= a %>{x}", "M{$}T{<%=}C{ a }T{%>}M{{x}}");

	/* an action's request-time attribute is an island inside the quotes */
	jsp("<jsp:include page=\"<%= x %>\"/>", "M{<jsp:include page=\"}T{<%=}C{ x }T{%>}M{\"/>}");
	jsp("<jsp:include page=\"<%= a(\"x\") %>\"/>", "M{<jsp:include page=\"}T{<%=}C{ a(}S*{\"x\"}C{) }T{%>}M{\"/>}");
	jsp("<jsp:directive.page import=\"a.b\"/><jsp:useBean id=\"x\" class=\"y\"/>",
	    "M{<jsp:directive.page import=\"a.b\"/><jsp:useBean id=\"x\" class=\"y\"/>}");
}

/* ---- (a) the island ends at the first "%>" ------------------------------------------------------ */

static void island_end(void)
{
	/* in a string: the string is open there, and "%\>" is the way to write it */
	jsp("<% String s = \"a%>b\"; %>c\";%>", "T{<%}C{ String s = }S*!{\"a}T{%>}M{b\"; %>c\";%>}");
	jsp("<% s = \"a%\\>b\"; %>", "T{<%}C{ s = }S*{\"a%\\>b\"}C{; }T{%>}");
	jsp("<% s = 'x%>", "T{<%}C{ s = }S*!{'x}T{%>}");
	/* in a comment */
	jsp("<% // c %> d", "T{<%}C{ }K{// c }T{%>}M{ d}");
	jsp("<% /* c %> d */ %>", "T{<%}C{ }K!{/* c }T{%>}M{ d */ %>}");
	jsp("<% /* c %\\> d */ x %>", "T{<%}C{ }K{/* c %\\> d */}C{ x }T{%>}");
	/* in a text block */
	jsp("<% s = \"\"\"\nabc %>", "T{<%}C{ s = }S*!{\"\"\"\nabc }T{%>}");
	/* a line comment ends where the island does: it is a whole comment, not an open one */
	jsp("<% x // c%>", "T{<%}C{ x }K{// c}T{%>}");
	jsp("<% x // c", "T{<%}C{ x }K{// c}");
	/* the comment of the page is not closed by "%>", only by "--%>" */
	jsp("<%--%>x --%>", "K{<%--%>x --%>}");
}

/* ---- (a) java --------------------------------------------------------------------------------- */

static void java_rules(void)
{
	/* comments */
	jsp("<% a /* b */ c // d\n e %>", "T{<%}C{ a }K{/* b */}C{ c }K{// d}C{\n e }T{%>}");
	jsp("<% /**/ x %>", "T{<%}C{ }K{/**/}C{ x }T{%>}");
	jsp("<% /*/ x %>", "T{<%}C{ }K!{/*/ x }T{%>}");
	jsp("<% /** doc */ x %>", "T{<%}C{ }K{/** doc */}C{ x }T{%>}");
	jsp("<% a / b %>", "T{<%}C{ a / b }T{%>}");
	/* a lone carriage return ends a line comment (JLS 3.4) */
	jsp("<% // c\r x %>", "T{<%}C{ }K{// c}C{\r x }T{%>}");
	jsp("<% // c\r\n x %>", "T{<%}C{ }K{// c}C{\r\n x }T{%>}");

	/* strings, chars and their escapes */
	jsp("<% s = \"a\\\"b\"; %>", "T{<%}C{ s = }S*{\"a\\\"b\"}C{; }T{%>}");
	jsp("<% s = \"a\\\\\"; t = 1; %>", "T{<%}C{ s = }S*{\"a\\\\\"}C{; t = 1; }T{%>}");
	jsp("<% c = '\"'; d = '\\''; %>", "T{<%}C{ c = }S*{'\"'}C{; d = }S*{'\\''}C{; }T{%>}");
	jsp("<% c = 'a'; %>", "T{<%}C{ c = }S*{'a'}C{; }T{%>}");
	/* a string that is not closed ends AT the line break, which is code; a backslash does not take a line break */
	jsp("<% s = \"abc\n x %>", "T{<%}C{ s = }S*!{\"abc}C{\n x }T{%>}");
	jsp("<% s = \"abc\\\n x %>", "T{<%}C{ s = }S*!{\"abc\\}C{\n x }T{%>}");
	jsp("<% s = \"\" + \"b\"; %>", "T{<%}C{ s = }S*{\"\"}C{ + }S*{\"b\"}C{; }T{%>}");
	jsp("<% a = b'; %>", "T{<%}C{ a = b}S*!{'; }T{%>}");

	/* a unicode escape is translated BEFORE lexing: it can close a string, end a comment, begin a comment */
	jsp("<% s = \"a\\u0022 + b; %>", "T{<%}C{ s = }S*{\"a\\u0022}C{ + b; }T{%>}");
	jsp("<% s = \"a\\uu0022 + b; %>", "T{<%}C{ s = }S*{\"a\\uu0022}C{ + b; }T{%>}");
	jsp("<% s = \\u0022a\" + b; %>", "T{<%}C{ s = }S*{\\u0022a\"}C{ + b; }T{%>}");
	jsp("<% // c\\u000a x(); %>", "T{<%}C{ }K{// c}C{\\u000a x(); }T{%>}");
	jsp("<% // c\\u000d x(); %>", "T{<%}C{ }K{// c}C{\\u000d x(); }T{%>}");
	jsp("<% /\\u002f c\n x %>", "T{<%}C{ }K{/\\u002f c}C{\n x }T{%>}");
	jsp("<% a \\u002f* c *\\u002f b %>", "T{<%}C{ a }K{\\u002f* c *\\u002f}C{ b }T{%>}");
	jsp("<% s = \"x\\u000a\"; %>", "T{<%}C{ s = }S*!{\"x}C{\\u000a}S*!{\"; }T{%>}");
	/* NOT an escape: an odd number of backslashes before the "u", so these are a backslash and "u0022" */
	jsp("<% s = \"a\\\\u0022 + b\"; %>", "T{<%}C{ s = }S*{\"a\\\\u0022 + b\"}C{; }T{%>}");
	jsp("<% a \\\\u0022 b %>", "T{<%}C{ a \\\\u0022 b }T{%>}");
	/* three backslashes: an even number (two) in front of the third, so "\u0022" there IS an escape, and it closes the string */
	jsp("<% s = \"a\\\\\\u0022 b\"; %>", "T{<%}C{ s = }S*{\"a\\\\\\u0022}C{ b}S*!{\"; }T{%>}");
	/* what an escape produces takes no part in another one: "\u005cu0022" is a backslash and "u0022" */
	jsp("<% s = \"a\\u005cu0022 b\"; %>", "T{<%}C{ s = }S*{\"a\\u005cu0022 b\"}C{; }T{%>}");
	/* an escape that spells the backslash escapes the next character, here an escaped quote */
	jsp("<% s = \"a\\u005c\\u0022 b\"; %>", "T{<%}C{ s = }S*{\"a\\u005c\\u0022 b\"}C{; }T{%>}");
	jsp("<% c = '\\u005c''; %>", "T{<%}C{ c = }S*{'\\u005c''}C{; }T{%>}");
	/* the page scanner reads raw bytes: "%\u003e" is not the end of the island */
	jsp("<% a %\\u003e b %>", "T{<%}C{ a %\\u003e b }T{%>}");
	/* "\u" that is not an escape (too few digits, or cut by the island) is raw bytes */
	jsp("<% s = \"a\\u00zz\"; %>", "T{<%}C{ s = }S*{\"a\\u00zz\"}C{; }T{%>}");
	jsp("<% x \\u00%>", "T{<%}C{ x \\u00}T{%>}");

	/* text blocks */
	jsp("<% s = \"\"\"\n  abc\n  \"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\n  abc\n  \"\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"  \t\n x\"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"  \t\n x\"\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"\r\n x\"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\r\n x\"\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"\n a\\\"\"\"b\n \"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\n a\\\"\"\"b\n \"\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"\n a \" b \"\" c\n \"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\n a \" b \"\" c\n \"\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"\n a\\\n b\"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\n a\\\n b\"\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"\n a // b /* c\n\"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\n a // b /* c\n\"\"\"}C{; }T{%>}");
	/* the first three quotes close it; a fourth begins a string */
	jsp("<% s = \"\"\"\n a\"\"\"\"; %>", "T{<%}C{ s = }S*{\"\"\"\n a\"\"\"}S*!{\"; }T{%>}");
	/* three quotes with no line break after the blanks are "" and the start of a string (java before 15) */
	jsp("<% s = \"\"\"abc\"\"\"; %>", "T{<%}C{ s = }S*{\"\"}S*{\"abc\"}S*{\"\"}C{; }T{%>}");
	jsp("<% s = \"\"\"  x\"\"\"; %>", "T{<%}C{ s = }S*{\"\"}S*{\"  x\"}S*{\"\"}C{; }T{%>}");
	jsp("<% s = \"\"; t = \"\"\"\nx\"\"\"; %>", "T{<%}C{ s = }S*{\"\"}C{; t = }S*{\"\"\"\nx\"\"\"}C{; }T{%>}");
	/* a text block's \u0022 closes it too: the opening is translated like everything else */
	jsp("<% s = \"\"\"\n a \\u0022\\u0022\\u0022; %>", "T{<%}C{ s = }S*{\"\"\"\n a \\u0022\\u0022\\u0022}C{; }T{%>}");

	/* code that has the shapes of other things */
	jsp("<% List<List<String>> a = new ArrayList<>(); %>", "T{<%}C{ List<List<String>> a = new ArrayList<>(); }T{%>}");
	jsp("<% @Override void f() { g(x -> x + 1); } %>", "T{<%}C{ @Override void f() { g(x -> x + 1); } }T{%>}");
	jsp("<% outer: for (;;) { break outer; } %>", "T{<%}C{ outer: for (;;) { break outer; } }T{%>}");
	jsp("<% a = b >> 2 >>> 3; c = d::e; %>", "T{<%}C{ a = b >> 2 >>> 3; c = d::e; }T{%>}");
	jsp("<% x = a % b; %>", "T{<%}C{ x = a % b; }T{%>}");
	jsp("<% x = 1.5e3f + 0x1F + 077 + 1_000L; %>", "T{<%}C{ x = 1.5e3f + 0x1F + 077 + 1_000L; }T{%>}");
	jsp("<% String[] s = {\"a\", \"b\"}; %>", "T{<%}C{ String[] s = {}S*{\"a\"}C{, }S*{\"b\"}C{}; }T{%>}");
}

/* ---- (a) the XML scripting elements ------------------------------------------------------------ */

static void xml_rules(void)
{
	jsp("<jsp:scriptlet> int a; </jsp:scriptlet>", "T{<jsp:scriptlet>}C{ int a; }T{</jsp:scriptlet>}");
	jsp("<jsp:declaration>int a;</jsp:declaration>", "T{<jsp:declaration>}C{int a;}T{</jsp:declaration>}");
	jsp("<jsp:expression>a</jsp:expression>", "T{<jsp:expression>}C{a}T{</jsp:expression>}");
	jsp("x<jsp:scriptlet >a</jsp:scriptlet >y", "M{x}T{<jsp:scriptlet >}C{a}T{</jsp:scriptlet >}M{y}");
	jsp("<jsp:scriptlet><![CDATA[ a < b ]]></jsp:scriptlet>",
	    "T{<jsp:scriptlet><![CDATA[}C{ a < b }T{]]></jsp:scriptlet>}");
	jsp("<jsp:scriptlet>\n<![CDATA[ x ]]>\n</jsp:scriptlet>",
	    "T{<jsp:scriptlet>\n<![CDATA[}C{ x }T{]]>\n</jsp:scriptlet>}");
	/* the first "]]>" ends the code, in a string too; then it is the end tag that must follow */
	jsp("<jsp:scriptlet><![CDATA[ s = \"]]>\" ]]></jsp:scriptlet>",
	    "T{<jsp:scriptlet><![CDATA[}C{ s = }S*!{\"}T{]]>}M{\" ]]></jsp:scriptlet>}");
	/* the end tag in a string is not the end inside CDATA, and is the end without it */
	jsp("<jsp:scriptlet><![CDATA[ s = \"</jsp:scriptlet>\"; ]]></jsp:scriptlet>",
	    "T{<jsp:scriptlet><![CDATA[}C{ s = }S*{\"</jsp:scriptlet>\"}C{; }T{]]></jsp:scriptlet>}");
	jsp("<jsp:scriptlet> s = \"</jsp:scriptlet>\" </jsp:scriptlet>",
	    "T{<jsp:scriptlet>}C{ s = }S*!{\"}T{</jsp:scriptlet>}M{\" </jsp:scriptlet>}");
	/* a second CDATA section continues the code */
	jsp("<jsp:scriptlet><![CDATA[a]]><![CDATA[b]]></jsp:scriptlet>",
	    "T{<jsp:scriptlet><![CDATA[}C{a]]><![CDATA[b}T{]]></jsp:scriptlet>}");
	jsp("<jsp:scriptlet><![CDATA[ // c ]]></jsp:scriptlet>", "T{<jsp:scriptlet><![CDATA[}C{ }K{// c }T{]]></jsp:scriptlet>}");
	/* not an element with a body: an empty element, another name, another case, a longer name */
	jsp("<jsp:scriptlet/>", "M{<jsp:scriptlet/>}");
	jsp("<jsp:scriptletx>a</jsp:scriptletx>", "M{<jsp:scriptletx>a</jsp:scriptletx>}");
	jsp("<JSP:scriptlet>a</JSP:scriptlet>", "M{<JSP:scriptlet>a</JSP:scriptlet>}");
	jsp("<jsp:include page=\"a\"/>", "M{<jsp:include page=\"a\"/>}");
	jsp("<jsp:text><![CDATA[ <% x %> ]]></jsp:text>", "M{<jsp:text><![CDATA[ }T{<%}C{ x }T{%>}M{ ]]></jsp:text>}");
	/* not closed: the code runs to the end of the text */
	jsp("<jsp:scriptlet> a", "T{<jsp:scriptlet>}C{ a}");
	jsp("<jsp:scriptlet><![CDATA[ a", "T{<jsp:scriptlet><![CDATA[}C{ a}");
	jsp("<jsp:scriptlet></jsp:scriptlet>", "T{<jsp:scriptlet>}T{</jsp:scriptlet>}");
}

/* ---- (a) EL ------------------------------------------------------------------------------------ */

static void el_rules(void)
{
	jsp("${a}", "M{${a}}");
	jsp("#{a.b}", "M{#{a.b}}");
	/* EL is read to its "}" before "<%" is looked for: a quoted "<%" is not an island */
	jsp("${\"<%\"} <% x %>", "M{${\"<%\"} }T{<%}C{ x }T{%>}");
	jsp("#{'<%'} <% x %>", "M{#{'<%'} }T{<%}C{ x }T{%>}");
	jsp("${a == \"}\" ? 1 : 2}<% x %>", "M{${a == \"}\" ? 1 : 2}}T{<%}C{ x }T{%>}");
	jsp("${\"a\\\"<%\"}<% x %>", "M{${\"a\\\"<%\"}}T{<%}C{ x }T{%>}");
	jsp("<c:out value=\"${a['<%']}\"/><% x %>", "M{<c:out value=\"${a['<%']}\"/>}T{<%}C{ x }T{%>}");
	/* a backslash makes "${" literal text, and then "<%" is an island */
	jsp("\\${\"<%\"}", "M{\\${\"}T{<%}S*!{\"}}");
	/* not EL: no brace, a space between */
	jsp("$ {\"<%\"}", "M{$ {\"}T{<%}S*!{\"}}");
	jsp("$<%= a %>", "M{$}T{<%=}C{ a }T{%>}");
	/* not closed before an unquoted "<%": it is not an EL, the island is found, and EL is off from then on */
	jsp("${ a <% x %> }", "M{${ a }T{<%}C{ x }T{%>}M{ }}");
	jsp("${ <% a %> ${\"<%\"} <% b %>", "M{${ }T{<%}C{ a }T{%>}M{ ${\"}T{<%}S*!{\"} <% b }T{%>}");
	jsp("${a", "M{${a}");
	jsp("${", "M{${}");
	/* EL inside an island is java text, not EL */
	jsp("<% s = \"${\"; %>${a}", "T{<%}C{ s = }S*{\"${\"}C{; }T{%>}M{${a}}");
}

/* ---- (a) a fragment is java from its first byte -------------------------------------------------- */

static void frag(const char *src, const char *want)
{
	static struct rend r;
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = J,
					      .flags = KGENOME_TEXTUAL_FRAGMENT, .sink = sink, .user = &r };
	struct kgenome_textual_lex_res rs;

	memset(&r, 0, sizeof r);
	r.in = (const uint8_t *)src;
	r.n = rq.n;
	kgenome_textual_lex(&rq, &rs);
	if (r.broken || r.next != rq.n || strcmp(r.out, want)) {
		printf("  FAIL fragment  %s\n       got    %s\n       wanted %s\n", src, r.out, want);
		fails++;
	}
}

static void fragments(void)
{
	/* no page around it: "%>" and "<%" mean nothing, a string may hold them, and "<%--" is not a comment */
	frag("x = \"a%>b\"; // c", "C{x = }S*{\"a%>b\"}C{; }K{// c}");
	frag("a <% b %> c", "C{a <% b %> c}");
	frag("s = \"\"\"\n t\n\"\"\"; /* c */", "C{s = }S*{\"\"\"\n t\n\"\"\"}C{; }K{/* c */}");
	frag("s = \"a\\u0022 + b;", "C{s = }S*{\"a\\u0022}C{ + b;}");
	frag("", "");
}

/* ---- (d) the form ------------------------------------------------------------------------------ */

static void form_rules(void)
{
	/* an island with no code goes whole, so does a page comment; an island cut by the end of the text too */
	jform("a<% %>b", "ab");
	jform("a<%-- c --%>b", "ab");
	/* a comment between two halves of what would be a tag: the gap stays, or the form of the form is another text */
	jform("<<%-- c --%>% x %>", "< % x %>");
	jform("x<% %>y<%= %>z<jsp:scriptlet> </jsp:scriptlet>w", "xyzw");
	jform("a<% ", "a");
	/* spacing between tokens goes, one space stays between two name bytes, a closing tag gets a line break */
	jform("<% x = 1 ; // c\n y = 2 ; %>", "<%x=1;\ny=2;\n%>");
	jform("<% a.b ( c ) %>", "<%a.b(c)\n%>");
	jform("<%= a + b %>", "<%=a+b\n%>");
	jform("<% int  x ; %>", "<%int x;\n%>");
	jform("<% a // c %>", "<%a\n%>");
	jform("<% a\r\n b %>", "<%a\nb\n%>");
	/* "+ +" and "> >" keep the typing's token boundary */
	jform("<% a + + b; a - - b; x > > y %>", "<%a+ +b;a- -b;x> >y\n%>");
	/* a lone brace joins the line above */
	jform("<% if (x)\n{\n y(); }\n%>", "<%if(x){\ny();}\n%>");
	/* closing up must not turn the tag "<%" into another one, nor make a "%>" out of a "%" and a ">" */
	jform("<% @SuppressWarnings(\"x\") int a; %>", "<% @SuppressWarnings(\"x\")int a;\n%>");
	jform("<% --i; %>", "<% --i;\n%>");
	jform("<% =x %>", "<% =x\n%>");
	jform("<% !x %>", "<% !x\n%>");
	jform("<% a % /* c */ > b %>", "<%a% >b\n%>");
	/* a string is never touched: no \x, no octal, no \u is written as the byte */
	jform("<% s = \"a  b\\u0041\\x41\\101\" ; %>", "<%s=\"a  b\\u0041\\x41\\101\";\n%>");
	jform("<% s = \"\"\"\n  a  b \\101\n  \"\"\" ; %>", "<%s=\"\"\"\n  a  b \\101\n  \"\"\";\n%>");
	/* an open comment is kept as typed */
	jform("<% a /* b", "<%a/* b");
	/* markup and directives are copied byte for byte */
	jform("<html>  <%@ page a=\"b\" %>\n\n<p>x</p>  ", "<html>  <%@ page a=\"b\" %>\n\n<p>x</p>  ");
	jform("${ a  \"<%\"  }  <% x %>", "${ a  \"<%\"  }  <%x\n%>");
	/* the XML elements */
	jform("<jsp:scriptlet> x = 1 ; </jsp:scriptlet>", "<jsp:scriptlet>x=1;\n</jsp:scriptlet>");
	jform("<jsp:scriptlet><![CDATA[ x = 1 ; ]]></jsp:scriptlet>", "<jsp:scriptlet><![CDATA[x=1;\n]]></jsp:scriptlet>");
	jform("<jsp:expression> a </jsp:expression>", "<jsp:expression>a\n</jsp:expression>");
}

/* The decoder hook: the chain it is asked for, and the literals it is never asked about. */
static uint8_t seen[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t seen_n, seen_calls;

static int hook(void *user, const uint8_t *chain, uint32_t n, const uint8_t *in, uint32_t len,
		const uint8_t **out, uint32_t *out_len)
{
	(void)user;
	(void)in;
	(void)len;
	memcpy(seen, chain, n);
	seen_n = n;
	seen_calls++;
	*out = (const uint8_t *)"@@";
	*out_len = 2;
	return 1;
}

static void decode_case(const char *src, uint32_t n_chain, const uint8_t *chain, const char *want)
{
	uint8_t out[512];
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = J,
					       .out = out, .cap = sizeof out, .decode = hook };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st;

	seen_n = seen_calls = 0;
	st = kgenome_textual_form(&rq, &rs);
	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || rs.n_out != strlen(want) ||
	    memcmp(out, want, rs.n_out) || seen_n != n_chain || (n_chain && memcmp(seen, chain, n_chain)) ||
	    rs.n_decoded != (n_chain ? 1u : 0u)) {
		out[rs.n_out < sizeof out ? rs.n_out : sizeof out - 1u] = 0;
		printf("  FAIL decode  %s\n       got %s  chain %u decoded %u\n       wanted %s  chain %u\n", src, out,
		       seen_n, rs.n_decoded, want, n_chain);
		fails++;
	}
}

static void decoders(void)
{
	static const uint8_t b64[] = { KGENOME_TEXTUAL_DEC_B64 }, hex[] = { KGENOME_TEXTUAL_DEC_HEX },
			     url[] = { KGENOME_TEXTUAL_DEC_URL },
			     url_b64[] = { KGENOME_TEXTUAL_DEC_URL, KGENOME_TEXTUAL_DEC_B64 };

	decode_case("<% s = new String(java.util.Base64.getDecoder().decode(\"QUJD\")); %>", 1, b64,
		    "<%s=new String(java.util.Base64.getDecoder().decoded_decode(\"@@\"));\n%>");
	decode_case("<% s = Base64.getMimeDecoder().decode(\"QUJD\"); %>", 1, b64, "<%s=Base64.getMimeDecoder().decoded_decode(\"@@\");\n%>");
	decode_case("<% b = new BASE64Decoder().decodeBuffer(\"QUJD\"); %>", 1, b64, "<%b=new BASE64Decoder().decoded_decodeBuffer(\"@@\");\n%>");
	decode_case("<% b = new sun.misc.BASE64Decoder().decodeBuffer(\"QUJD\"); %>", 1, b64,
		    "<%b=new sun.misc.BASE64Decoder().decoded_decodeBuffer(\"@@\");\n%>");
	decode_case("<% b = Base64.decodeBase64(\"QUJD\"); %>", 1, b64, "<%b=Base64.decoded_decodeBase64(\"@@\");\n%>");
	decode_case("<% b = javax.xml.bind.DatatypeConverter.parseBase64Binary(\"QUJD\"); %>", 1, b64,
		    "<%b=javax.xml.bind.DatatypeConverter.decoded_parseBase64Binary(\"@@\");\n%>");
	decode_case("<% b = DatatypeConverter.parseHexBinary(\"41\"); %>", 1, hex, "<%b=DatatypeConverter.decoded_parseHexBinary(\"@@\");\n%>");
	decode_case("<% s = URLDecoder.decode(\"a%20b\", \"UTF-8\"); %>", 1, url, "<%s=URLDecoder.decoded_decode(\"@@\",\"UTF-8\");\n%>");
	/* innermost first: the URL decoding is applied to the literal, then the base64 one */
	decode_case("<% b = Base64.getDecoder().decode(URLDecoder.decode(\"x\", \"UTF-8\")); %>", 2, url_b64,
		    "<%b=Base64.getDecoder().decoded_decode(URLDecoder.decoded_decode(\"@@\",\"UTF-8\"));\n%>");
	/* white space and comments between the tokens of the call do not matter */
	decode_case("<% b = Base64 . getDecoder ( ) /* c */ . decode ( \"QUJD\" ); %>", 1, b64,
		    "<%b=Base64.getDecoder().decoded_decode(\"@@\");\n%>");
	/* NOT a decoder: "decode" alone is ambiguous (Integer.decode), the url alphabet differs, a variable has no receiver,
	 * a name that only ends like one, a literal that is not the whole argument */
	decode_case("<% i = Integer.decode(\"12\"); %>", 0, NULL, "<%i=Integer.decode(\"12\");\n%>");
	decode_case("<% b = Base64.getUrlDecoder().decode(\"QUJD\"); %>", 0, NULL, "<%b=Base64.getUrlDecoder().decode(\"QUJD\");\n%>");
	decode_case("<% b = d.decode(\"QUJD\"); %>", 0, NULL, "<%b=d.decode(\"QUJD\");\n%>");
	decode_case("<% b = myparseHexBinary(\"41\"); %>", 0, NULL, "<%b=myparseHexBinary(\"41\");\n%>");
	decode_case("<% b = Base64.getDecoder().decode(\"QU\" + x); %>", 0, NULL, "<%b=Base64.getDecoder().decode(\"QU\"+x);\n%>");
	decode_case("<% b = Base64.getDecoder().decode(\"QU\".trim()); %>", 0, NULL, "<%b=Base64.getDecoder().decode(\"QU\".trim());\n%>");
}

/* ---- (b) the generator -------------------------------------------------------------------------- */

static uint32_t rng_state;

static uint32_t rnd(void)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return rng_state >> 16;
}

static uint32_t pick(uint32_t n)
{
	return rnd() % n;
}

#define PG_MAX 16384u

struct sp {
	uint32_t off, len, open, close;
	uint8_t  kind, flags;
};

static uint8_t pg[PG_MAX];
static uint32_t pn, nex;
static struct sp ex[4096];
static int gen_over;

/* Append `t` to the page as one piece of the class the generator says it is. */
static void add(uint8_t kind, uint8_t flags, uint32_t open, uint32_t close, const char *t)
{
	uint32_t l = (uint32_t)strlen(t);

	if (!l)
		return;
	if (pn + l > PG_MAX || nex >= sizeof ex / sizeof ex[0]) {
		gen_over = 1;
		return;
	}
	memcpy(pg + pn, t, l);
	if (nex && (kind == KGENOME_TEXTUAL_CODE || kind == KGENOME_TEXTUAL_MARKUP) && !flags &&
	    ex[nex - 1u].kind == kind && !ex[nex - 1u].flags)
		ex[nex - 1u].len += l;
	else
		ex[nex++] = (struct sp){ pn, l, open, close, kind, flags };
	pn += l;
}

#define CODE_ KGENOME_TEXTUAL_CODE
#define STR_  KGENOME_TEXTUAL_STRING
#define COM_  KGENOME_TEXTUAL_COMMENT
#define MUP_  KGENOME_TEXTUAL_MARKUP
#define TAG_  KGENOME_TEXTUAL_TAG
#define F_INT KGENOME_TEXTUAL_F_INTERP
#define F_OPN KGENOME_TEXTUAL_F_OPEN
#define F_CLS KGENOME_TEXTUAL_F_CLOSE

static const char *const sep_ws[] = { " ", "\n", "\t", "  ", "\r\n", " \n\t", "\n\n  ", "\f " };
static const char *const sep_eol[] = { "\n", "\r\n", "\r", "\\u000a", "\\u000d", "\\u000d\\u000a", "\n  ", "\r\n\t" };

/* Code with no quote, no comment opener, no "%>"; a backslash only in a \uXXXX escape or an even run. */
static const char *const code_piece[] = {
	"int a = 0;", "x", "foo(bar, baz)", "a + b", "i++", "i--", "List<List<String>> l = new ArrayList<>();",
	"x -> x + 1", "@Override", "@SuppressWarnings", "outer:", "a ? b : c", "a % b", "x <% y",
	"if (a >= b && c != d) { e(); }", "try { } catch (Exception e) { }", "for (int i = 0; i < n; i++) { }",
	"Map<String, List<Integer>> m;", "a >>> 2", "a >> b", "1.5e3f + 0x1F + 077", "this.x = y;", "a.b().c()",
	"switch (x) { case 1: break; default: }", "String[] s = {};", "char c = (char) 65;", "\\u0041bc",
	"a \\u002b b", "a \\\\u0022 b", "x\\u0061", "{", "}", ";", "a %", "a -", "a <", "i + +j", "a > > b",
};

/* Atoms of a string's content: every one is whole (an escape is complete), none holds a raw quote. */
static const char *const str_atom[] = {
	"abc", " ", "x y", "%", "<%", "<\\%", "%\\>", "\\\"", "\\\\", "\\n", "\\t", "\\0", "\\377", "\\u0041",
	"\\uuu0041", "//", "/*", "*/", "'", "${x}", "#{y}", "--", "<jsp:scriptlet>", "\\u005c\\u0022",
	"\\\\u0022", "\\\\\\\\", "\\\\\\u0041", "]]\\>",
};
/* Only where "]]>" and the end tag cannot mean anything. */
static const char *const plain_atom[] = { "]]>", "</jsp:scriptlet>", "</jsp:expression> ]]>" };

static const char *const chr_atom[] = {
	"a", "\"", "\\'", "\\\\", "\\u0041", "\\n", "%", "\\377", "<", ">", "\\u005c'", "\\u0022",
};

static const char *const tb_atom[] = {
	"abc", " ", "\n", "\r\n", "x\"y", "x\"\"y", "\\\"", "\\\"\"\"", "\\\\", "\\n", "\\\n", "%\\>", "//", "/*",
	"\\u0041", "<%", "${x}", "\\\r\n",
};

static const char *const blk_atom[] = {
	"abc", " ", "\n", "//", "\"", "'", "<%", "%\\>", "a*b", "a/b", "x\r\n", "\\u0041", "${x}", "--", "\\\\",
};

static const char *const line_atom[] = {
	"abc", " ", "\"", "'", "/*", "*/", "//", "<%", "%\\>", "\\u0041", "a\\b", "${x}", "--", "\\\\u000a",
};

#define N_(a) ((uint32_t)(sizeof (a) / sizeof (a)[0]))

/* How atoms are chosen: 0 plain page island, 1 XML element without CDATA, 2 with CDATA. */
static int gen_mode;

static void atoms(char *dst, size_t cap, const char *const *tab, uint32_t n_tab, uint32_t max, int plain)
{
	uint32_t n = pick(max + 1u), k;

	dst[0] = 0;
	for (k = 0; k < n; k++) {
		const char *a;

		if (plain && gen_mode == 0 && pick(12) == 0)
			a = plain_atom[pick(N_(plain_atom))];
		else
			a = tab[pick(n_tab)];
		if (strlen(dst) + strlen(a) + 1u < cap)
			strcat(dst, a);
	}
}

/* A string: the quotes may be written \u0022; open when the island ends in it. */
static void gen_str(int open)
{
	char body[512], text[640];
	const char *q1 = pick(8) == 0 ? "\\u0022" : "\"", *q2 = pick(8) == 0 ? "\\u0022" : "\"";

	atoms(body, sizeof body, str_atom, N_(str_atom), 6, 1);
	snprintf(text, sizeof text, open ? "%s%s" : "%s%s%s", q1, body, q2);
	add(STR_, (uint8_t)(F_INT | (open ? F_OPN : 0u)), (uint32_t)strlen(q1), open ? 0u : (uint32_t)strlen(q2), text);
}

static void gen_chr(int open)
{
	char text[64];
	const char *a = chr_atom[pick(N_(chr_atom))];

	snprintf(text, sizeof text, open ? "'%s" : "'%s'", a);
	add(STR_, (uint8_t)(F_INT | (open ? F_OPN : 0u)), 1u, open ? 0u : 1u, text);
}

static void gen_tb(int open)
{
	static const char *const blanks[] = { "", " ", "\t ", " \f" }, *const eols[] = { "\n", "\r\n" },
			  *const indent[] = { "", "  ", "\t" };
	char body[512], text[1024];
	const char *bl = blanks[pick(N_(blanks))], *eol = eols[pick(N_(eols))];
	uint32_t open_len = 3u + (uint32_t)strlen(bl) + (uint32_t)strlen(eol);

	atoms(body, sizeof body, tb_atom, N_(tb_atom), 7, 1);
	if (open)
		snprintf(text, sizeof text, "\"\"\"%s%s%s", bl, eol, body);
	else
		snprintf(text, sizeof text, "\"\"\"%s%s%s\n%s\"\"\"", bl, eol, body, indent[pick(N_(indent))]);
	add(STR_, (uint8_t)(F_INT | (open ? F_OPN : 0u)), open_len, open ? 0u : 3u, text);
}

static void gen_block(int open)
{
	char body[512], text[640];
	const char *o = pick(8) == 0 ? "/\\u002a" : "/*", *c = pick(8) == 0 ? "*\\u002f" : "*/";

	atoms(body, sizeof body, blk_atom, N_(blk_atom), 6, 1);
	snprintf(text, sizeof text, open ? "%s%s" : "%s%s%s", o, body, c);
	add(COM_, (uint8_t)(open ? F_OPN : 0u), (uint32_t)strlen(o), open ? 0u : (uint32_t)strlen(c), text);
}

static void gen_line(void)
{
	static const char *const opener[] = { "//", "/\\u002f", "\\u002f/", "\\u002f\\u002f" };
	char body[512], text[640];
	const char *o = opener[pick(N_(opener))];

	atoms(body, sizeof body, line_atom, N_(line_atom), 6, 1);
	snprintf(text, sizeof text, "%s%s", o, body);
	add(COM_, 0, (uint32_t)strlen(o), 0, text);
}

static int starts_alnum(const char *s)
{
	return (uint8_t)((s[0] | 0x20) - 'a') < 26u || (uint8_t)(s[0] - '0') < 10u;
}

static int safe_end(const char *s)
{
	uint8_t c = (uint8_t)s[strlen(s) - 1u];

	return (uint8_t)((c | 0x20u) - 'a') < 26u || (uint8_t)(c - '0') < 10u || strchr(")]};{", c) != NULL;
}

enum { P_NONE, P_CODE, P_UNSAFE, P_LIT, P_LINE };

static const char *const join_text[] = { "]]><![CDATA[", "]]>\n<![CDATA[", "]]> <![CDATA[" };

/*
 * The java of an island: tokens of known class, separated so that no token can change its neighbour's
 * class. An empty separator is used only where that holds: before a literal or comment after a code piece
 * that ends in a name byte or a closing bracket, and after a literal or a block comment before anything;
 * two code pieces, and anything after an operator, get white space; a line comment gets a line break (or an
 * escaped one). The last token is open about one island in ten when it is a literal or a block comment.
 */
static void gen_body(void)
{
	uint32_t n = pick(9), k;
	int prev = P_NONE, final_open = pick(10) == 0;

	for (k = 0; k < n; k++) {
		uint32_t t = pick(8);
		int final = k + 1u == n, open = final && final_open && t >= 2u && t <= 5u, empty;
		const char *cp = t < 2u ? code_piece[pick(N_(code_piece))] : NULL;

		if (gen_mode == 2 && k && pick(8) == 0) {
			/* a second CDATA section: the first one's window ends here, whatever token is in it */
			add(CODE_, 0, 0, 0, join_text[pick(N_(join_text))]);
			prev = P_UNSAFE;
		}
		if (prev == P_LINE) {
			add(CODE_, 0, 0, 0, sep_eol[pick(N_(sep_eol))]);
		} else {
			if (prev == P_NONE)
				empty = t >= 2u || starts_alnum(cp);
			else if (prev == P_LIT)
				empty = 1;
			else if (prev == P_CODE)
				empty = t >= 2u;
			else
				empty = 0;
			if (!empty || pick(3) == 0)
				add(CODE_, 0, 0, 0, sep_ws[pick(N_(sep_ws))]);
		}
		if (t < 2u) {
			add(CODE_, 0, 0, 0, cp);
			prev = safe_end(cp) ? P_CODE : P_UNSAFE;
		} else if (t == 2u) {
			gen_str(open);
			prev = P_LIT;
		} else if (t == 3u) {
			gen_chr(open);
			prev = P_LIT;
		} else if (t == 4u) {
			gen_tb(open);
			prev = P_LIT;
		} else if (t == 5u) {
			gen_block(open);
			prev = P_LIT;
		} else {
			gen_line();
			prev = P_LINE;
		}
		if (open)
			return;
	}
	if (pick(2) == 0)
		add(CODE_, 0, 0, 0, prev == P_LINE ? sep_eol[pick(N_(sep_eol))] : sep_ws[pick(N_(sep_ws))]);
}

/* An island of the page: its open tag, java, its close tag (not written when the text ends in it). */
static void gen_island(uint32_t kind, int end_open)
{
	static const char *const tag[] = { "<%", "<%=", "<%!" };
	static const char *const xname[] = { "scriptlet", "declaration", "expression" };
	static const char *const ws[] = { "", "\n", " " };
	char open[96], close[96];
	const char *nm = xname[kind % 3u], *w1 = ws[pick(3)], *w2 = ws[pick(3)], *w3 = ws[pick(3)];

	if (kind < 3u) {
		gen_mode = 0;
		add(TAG_, 0, 0, 0, tag[kind]);
		gen_body();
		if (!end_open)
			add(TAG_, F_CLS, 0, 0, "%>");
		return;
	}
	gen_mode = kind >= 6u ? 2 : 1;
	if (kind >= 6u) {
		snprintf(open, sizeof open, "<jsp:%s%s>%s<![CDATA[", nm, w3, w1);
		snprintf(close, sizeof close, "]]>%s</jsp:%s%s>", w2, nm, w3);
	} else {
		snprintf(open, sizeof open, "<jsp:%s%s>", nm, w3);
		snprintf(close, sizeof close, "</jsp:%s%s>", nm, w2);
	}
	add(TAG_, 0, 0, 0, open);
	gen_body();
	if (!end_open)
		add(TAG_, F_CLS, 0, 0, close);
}

static const char *const mk_atom[] = {
	"hello ", "<b>", "</b>", "<a href=\"x.html\">", "<img src='a.png'/>", "<p>\n", "text 50% off ", "a > b ",
	"<!-- c -->", "#anchor ", "cost $5 ", "\n", "<c:out value=\"x\"/>", "<jsp:include page=\"a.jsp\"/>",
	"<jsp:useBean id=\"b\" class=\"c\"/>", "<\\% esc %\\> ", "%> stray ", "<\\%= x %\\> ",
	"<jsp:scriptlet/>", "<jsp:text>t</jsp:text>", "<JSP:scriptlet>x</JSP:scriptlet>",
	"<jsp:scriptletx>y</jsp:scriptletx>", "<c:if test=\"${a > b}\">", "\\${lit} ", "&lt;% ",
};

static const char *const el_piece[] = {
	"${user.name}", "${\"<%\"}", "${'%>'}", "${a == \"}\" ? 1 : 2}", "${x['<%']}", "#{b.c}", "${\"a\\\"<%\"}",
	"${a.b > 3 ? '<%' : \"x\"}", "${fn:length(x)}", "${'<%' += \"<%\"}",
};

static const char *const dir_piece[] = {
	"<%@ page import=\"java.util.*\" %>", "<%@ taglib uri=\"http://java.sun.com/jsp/jstl/core\" prefix=\"c\" %>",
	"<%@ include file=\"a.jsp\" %>", "<%@ page info=\"a%\\>b\" %>", "<%@page contentType=\"text/html\"%>",
	"<%@ page\n  language=\"java\"\n%>", "<%@ page errorPage=\"<\\%x\" %>",
};

static const char *const cm_atom[] = {
	"abc ", "\n", "%> ", "<% s = \"x\"; %> ", "<%-- ", "a-- ", "- -", "<%= x %> ", "${a} ", "<jsp:scriptlet> ",
};

/* One piece of the page. `last` says the text ends in it, so it may be left open. */
static void gen_piece(int last)
{
	uint32_t t = pick(10), n, k;
	int end_open = last && pick(4) == 0;

	switch (t) {
	case 0:
	case 1:
		n = 1u + pick(3);
		for (k = 0; k < n; k++)
			add(MUP_, 0, 0, 0, mk_atom[pick(N_(mk_atom))]);
		break;
	case 2:
		add(MUP_, 0, 0, 0, el_piece[pick(N_(el_piece))]);
		break;
	case 3:
		add(MUP_, 0, 0, 0, dir_piece[pick(N_(dir_piece))]);
		break;
	case 4: {
		char body[256], whole[320];

		atoms(body, sizeof body, cm_atom, N_(cm_atom), 5, 0);
		snprintf(whole, sizeof whole, "<%%--%s%s", body, end_open ? "" : "--%>");
		add(COM_, (uint8_t)(end_open ? F_OPN : 0u), 4u, end_open ? 0u : 4u, whole);
		break;
	}
	case 5:
	case 6:
		gen_island(pick(3), end_open);
		break;
	case 7:
		gen_island(3u + pick(6), end_open);
		break;
	case 8:
		/* a request-time attribute: an island inside the quotes of a tag */
		add(MUP_, 0, 0, 0, "<jsp:include page=\"");
		gen_island(1, 0);
		add(MUP_, 0, 0, 0, "\"/>");
		break;
	default:
		add(MUP_, 0, 0, 0, mk_atom[pick(N_(mk_atom))]);
		gen_island(pick(3), end_open);
		break;
	}
}

/* ---- checking a page against what the generator knew -------------------------------------------- */

struct got {
	uint32_t off, len, open, close;
	uint8_t  kind, flags;
};

static struct got gs[4096];
static uint32_t n_gs;

static int collect(void *u, const struct kgenome_textual_span *s)
{
	(void)u;
	if (n_gs < sizeof gs / sizeof gs[0])
		gs[n_gs++] = (struct got){ s->off, s->len, s->open_len, s->close_len, s->kind, s->flags };
	return 1;
}

static uint32_t lex_spans(const uint8_t *in, uint32_t n)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = J, .sink = collect };
	struct kgenome_textual_lex_res rs;

	n_gs = 0;
	kgenome_textual_lex(&rq, &rs);
	return n_gs;
}

static void show(const char *what, const uint8_t *in, const struct got *g, uint32_t n)
{
	static const char kc[] = "MTCSK";
	uint32_t i, k;

	printf("       %s:", what);
	for (i = 0; i < n; i++) {
		printf(" %c%s%s%s%u/%u{", kc[g[i].kind], g[i].flags & F_INT ? "*" : "", g[i].flags & F_OPN ? "!" : "",
		       g[i].flags & F_CLS ? "^" : "", g[i].open, g[i].close);
		for (k = 0; k < g[i].len; k++) {
			uint8_t c = in[g[i].off + k];

			printf(c >= 0x20 && c < 0x7f ? "%c" : "\\x%02x", c);
		}
		printf("}");
	}
	printf("\n");
}

static int same_spans(const struct got *g, uint32_t n)
{
	uint32_t i;

	if (n != nex)
		return 0;
	for (i = 0; i < n; i++)
		if (g[i].off != ex[i].off || g[i].len != ex[i].len || g[i].kind != ex[i].kind ||
		    g[i].flags != ex[i].flags || g[i].open != ex[i].open || g[i].close != ex[i].close)
			return 0;
	return 1;
}

static void build_page(void)
{
	uint32_t n = 1u + pick(7), k;

	pn = nex = 0;
	gen_over = 0;
	for (k = 0; k < n; k++)
		gen_piece(k + 1u == n);
}

static uint32_t gen_checked, gen_spans[KGENOME_TEXTUAL_KIND_COUNT], gen_open;

/* Pages the generator wrote, lexed, and compared span by span with what it knew. */
static void generated(uint32_t seed, uint32_t count)
{
	uint32_t i, fail = 0;

	rng_state = seed;
	for (i = 0; i < count && fail < 3u; i++) {
		struct got want[4096];
		uint32_t k, n;

		build_page();
		if (gen_over)
			continue;
		n = lex_spans(pg, pn);
		gen_checked++;
		for (k = 0; k < nex; k++) {
			gen_spans[ex[k].kind]++;
			gen_open += (ex[k].flags & F_OPN) != 0;
		}
		if (!same_spans(gs, n)) {
			printf("  FAIL generated page %u (seed %u)\n", i, seed);
			for (k = 0; k < nex; k++)
				want[k] = (struct got){ ex[k].off, ex[k].len, ex[k].open, ex[k].close, ex[k].kind, ex[k].flags };
			show("wanted", pg, want, nex);
			show("got   ", pg, gs, n);
			fails++;
			fail++;
		}
	}
}

/* The strings of a text, in order, as one buffer of "len:bytes" records: what a form must never change. */
static uint32_t strings_of(const uint8_t *in, uint32_t n, uint8_t *out, uint32_t cap)
{
	uint32_t i, w = 0, c = lex_spans(in, n);

	for (i = 0; i < c; i++) {
		if (gs[i].kind != STR_)
			continue;
		if (w + gs[i].len + 5u > cap)
			return 0;
		out[w++] = (uint8_t)(gs[i].len >> 8);
		out[w++] = (uint8_t)gs[i].len;
		out[w++] = gs[i].flags;
		memcpy(out + w, in + gs[i].off, gs[i].len);
		w += gs[i].len;
	}
	return w;
}

/* The form of a generated page is its own form, fits its cap, and every string comes through byte for byte. */
static void generated_forms(uint32_t seed, uint32_t count)
{
	static uint8_t f1[PG_MAX * 2u], f2[PG_MAX * 2u], s1[PG_MAX * 2u], s2[PG_MAX * 2u];
	uint32_t i, fail = 0;

	rng_state = seed;
	for (i = 0; i < count && fail < 3u; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		uint32_t n1, n2, a, b;

		build_page();
		if (gen_over)
			continue;
		rq = (struct kgenome_textual_form_req){ .in = pg, .n = pn, .lang = J, .out = f1,
							.cap = KGENOME_TEXTUAL_FORM_CAP(pn) };
		kgenome_textual_form(&rq, &rs);
		n1 = rs.n_out;
		rq = (struct kgenome_textual_form_req){ .in = f1, .n = n1, .lang = J, .out = f2,
							.cap = KGENOME_TEXTUAL_FORM_CAP(n1) };
		kgenome_textual_form(&rq, &rs);
		n2 = rs.n_out;
		a = strings_of(pg, pn, s1, sizeof s1);
		b = strings_of(f1, n1, s2, sizeof s2);
		if (n2 != n1 || memcmp(f1, f2, n1) || a != b || memcmp(s1, s2, a)) {
			printf("  FAIL form of generated page %u (seed %u): %s\n       page: ", i, seed,
			       n2 != n1 || memcmp(f1, f2, n1) ? "not its own form" : "a string changed");
			fwrite(pg, 1, pn, stdout);
			printf("\n       form: ");
			fwrite(f1, 1, n1, stdout);
			printf("\n");
			show("page spans", pg, gs, lex_spans(pg, pn));
			show("form spans", f1, gs, lex_spans(f1, n1));
			fails++;
			fail++;
		}
	}
}

/* ---- (c) any input ------------------------------------------------------------------------------ */

static void properties(void)
{
	/* the characters that mean something to a jsp: its tags, quotes, escapes and the words of the elements */
	partition_for(J, "<%>=!@-$#{}\"'\\/*\n \tabcu0123;(){}[]:jsp.CDATA!", 0x4a53u);
	partition_for(J, "<%%>>--\"\"\"\\u0022\n /*", 0x4a54u);
	partition_for(J, "<jsp:scriptlet>/CDATA[]!%>\"\n ;", 0x4a55u);
	form_property_for(J, "<%>=!@-$#{}\"'\\/*\n \tabcu0123;(){}[]:jsp.CDATA!", 0x4a56u);
	form_property_for(J, "<%%>>--\"\"\"\\u0022\n /*x ;", 0x4a57u);
	form_property_for(J, "<jsp:scriptlet>/CDATA[]!%>\"\n ;x", 0x4a58u);
}

static void truncation(void)
{
	static const char sample[] =
		"<%@ page import=\"a.b\" %>\n<html><%-- c %> --%>${\"<%\"}<jsp:include page=\"<%= x %>\"/>\n"
		"<% String s = \"a%\\>b\\u0022; /* c */ // d\\u000a char c = '\\u005c''; s = \"\"\"\n t \\\"\"\"\n\"\"\"; %>"
		"<jsp:scriptlet><![CDATA[ a ]]><![CDATA[ \"x ]]></jsp:scriptlet><%! int a; %><%= a ";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, J);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* and the cut of a page in the middle of an escape is open, not lost */
	jsp("<% s = \"a\\u00", "T{<%}C{ s = }S*!{\"a\\u00}");
	jsp("<% s = \"a\\", "T{<%}C{ s = }S*!{\"a\\}");
}

int main(void)
{
	page_rules();
	island_end();
	java_rules();
	xml_rules();
	el_rules();
	fragments();
	form_rules();
	decoders();
	generated(0x6a737001u, 3000);
	generated(0x6a737002u, 3000);
	generated_forms(0x6a737003u, 3000);
	properties();
	truncation();
	printf("textual jsp: %s (%u generated pages; spans: %u markup %u tag %u code %u string %u comment, %u open)\n",
	       fails ? "FAILED" : "ok", gen_checked, gen_spans[MUP_], gen_spans[TAG_], gen_spans[CODE_], gen_spans[STR_],
	       gen_spans[COM_], gen_open);
	return fails != 0;
}
