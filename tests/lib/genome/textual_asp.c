/*
 * genome / textual_asp - the classic asp lexer of the textual part, through <kgenome.h> alone.
 *
 * A text is rendered as its spans, a kind letter and the bytes in braces (textual_check.h: M markup, T tag,
 * C code, S string, K comment; S* a backslash is an escape, S! not closed), so a case is the input and the
 * one line it must come out as. Each rule has the neighbour it could be confused for next to it.
 *
 * WHAT IS CHECKED, and the evidence behind each decision (there is no IIS, wscript or asp.dll on this
 * machine: the rules are from the documentation of the page and of the two languages [Inference], and the
 * second implementation used is pygments' VBScriptLexer and JavascriptLexer, run over the 14 distinct
 * files of the sample trees by /mnt/games/normtest/asp/tools/diff_pyg.py - 201 islands, 3090 strings and
 * comments, 0 differences; that tool is not part of the tree):
 *   - the page: "<%" ... "%>" islands, <%= %>, directives, the page language, <script runat="server">;
 *   - "%>" ends an island in a string or a comment; "%\>" does not; "<%" in a string is text;
 *   - vbscript and jscript bodies, chosen by the first directive and, per element, by language=;
 *   - the form: an empty island goes whole, a closing tag gets a line break, comments go, strings stay;
 *   - 6000 generated pages whose classes the generator knew, their forms, random strings.
 */

#include "textual_pagegen.h"

#include <time.h>

#define ASP KGENOME_TEXTUAL_LANG_ASP

static void expect(const char *src, const char *want)
{
	expect_lang(ASP, src, want);
}

static void form(const char *src, const char *want)
{
	form_lang(ASP, src, want);
}

static void islands(void)
{
	expect("", "");
	expect("hello", "M{hello}");
	expect("a<% x %>b", "M{a}T{<%}C{ x }T{%>}M{b}");
	expect("<%x%>", "T{<%}C{x}T{%>}");
	/* "<%=" is the one three byte tag; with a space it is code that begins with "=" */
	expect("<%= x %>", "T{<%=}C{ x }T{%>}");
	expect("<% =x %>", "T{<%}C{ =x }T{%>}");
	/* in classic asp "#", "$", "!" and ":" after "<%" are code, and <%-- is code too: it is not a comment here */
	expect("<%# x %>", "T{<%}C{# x }T{%>}");
	expect("<%$ x %>", "T{<%}C{$ x }T{%>}");
	expect("<%! x %>", "T{<%}C{! x }T{%>}");
	expect("<%: x %>", "T{<%}C{: x }T{%>}");
	expect("<%-- c --%>", "T{<%}C{-- c --}T{%>}");
	expect("<%%>", "T{<%}T{%>}");
	expect("<%=%>", "T{<%=}T{%>}");
	expect("<%%><%%>", "T{<%}T{%>}T{<%}T{%>}");
	/* not closed: the code runs to the end */
	expect("<% x", "T{<%}C{ x}");
	expect("<%", "T{<%}");
	expect("<%=", "T{<%=}");
	expect("a<", "M{a<}");
	expect("a < b <c>", "M{a < b <c>}");
	expect("<%>", "T{<%}C{>}");
	/* a markup "%>" is text */
	expect("a %> b", "M{a %> b}");
	/* an island in an attribute value, in an html comment, in a CDATA section, in a client script, in a textarea */
	expect("<input value=\"<%= v %>\">", "M{<input value=\"}T{<%=}C{ v }T{%>}M{\">}");
	expect("<!-- <% x %> -->", "M{<!-- }T{<%}C{ x }T{%>}M{ -->}");
	expect("<![CDATA[ <%= x %> ]]>", "M{<![CDATA[ }T{<%=}C{ x }T{%>}M{ ]]>}");
	expect("<script>var a = '<%= x %>';</script>", "M{<script>var a = '}T{<%=}C{ x }T{%>}M{';</script>}");
	expect("<textarea><% x %></textarea>", "M{<textarea>}T{<%}C{ x }T{%>}M{</textarea>}");
	/* includes are markup */
	expect("<!--#include file=\"a.asp\"-->", "M{<!--#include file=\"a.asp\"-->}");
	expect("<!--#include virtual=\"/b.asp\"--><% x %>", "M{<!--#include virtual=\"/b.asp\"-->}T{<%}C{ x }T{%>}");
}

static void ends_of_islands(void)
{
	/* "%>" ends the island in a string and in a comment: the page scanner finds it before vbscript reads */
	expect("<% a = \"x %> y\" %>", "T{<%}C{ a = }S!{\"x }T{%>}M{ y\" %>}");
	expect("<% ' c %> d", "T{<%}C{ }K{' c }T{%>}M{ d}");
	expect("<% Rem c %> d", "T{<%}C{ }K{Rem c }T{%>}M{ d}");
	/* "%\>" does not end it, and neither does "% >" */
	expect("<% a = \"%\\>\" %>", "T{<%}C{ a = }S{\"%\\>\"}C{ }T{%>}");
	expect("<% a = \"% >\" %>", "T{<%}C{ a = }S{\"% >\"}C{ }T{%>}");
	/* "<%" in a string is text, and so is "%" alone */
	expect("<% Response.Write \"<%\" %>", "T{<%}C{ Response.Write }S{\"<%\"}C{ }T{%>}");
	expect("<% x = \"a\" & \"%\" & \">\" %>", "T{<%}C{ x = }S{\"a\"}C{ & }S{\"%\"}C{ & }S{\">\"}C{ }T{%>}");
	/* the string that holds "%>" in a comment of the code that precedes: the first "%>" is the end */
	expect("<% x = 1 ' a \"b %> \"c\" %>", "T{<%}C{ x = 1 }K{' a \"b }T{%>}M{ \"c\" %>}");
	/* a script's end tag is not an island's: "</script>" is code in an island */
	expect("<% x = \"</script>\" %>", "T{<%}C{ x = }S{\"</script>\"}C{ }T{%>}");
}

static void directives(void)
{
	expect("<%@ LANGUAGE=VBScript %>x", "M{<%@ LANGUAGE=VBScript %>x}");
	expect("<%@Language=\"VBScript\"%>", "M{<%@Language=\"VBScript\"%>}");
	expect("<%@ x", "M{<%@ x}");
	expect("<%@", "M{<%@}");
	/* the directive is the page's own; the next island is code */
	expect("<%@ CODEPAGE=65001 %><% x %>", "M{<%@ CODEPAGE=65001 %>}T{<%}C{ x }T{%>}");
	/* the default is vbscript: "'" is a comment, a quote starts a string */
	expect("<% a = 'x' %>", "T{<%}C{ a = }K{'x' }T{%>}");
	/* jscript: "'" is a string, "//" and the C comment are comments, a backslash escapes */
	expect("<%@ LANGUAGE=\"JScript\" %><% a = 'x' // c\n b = \"q\\\"r\" /* d */ %>",
	       "M{<%@ LANGUAGE=\"JScript\" %>}T{<%}C{ a = }S*{'x'}C{ }K{// c}C{\n b = }S*{\"q\\\"r\"}C{ }K{/* d */}C{ }T{%>}");
	expect("<%@ language=JavaScript %><% a = 'x' %>", "M{<%@ language=JavaScript %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	expect("<%@ LANGUAGE = \"JScript.Encode\" %><% a = 'x' %>", "M{<%@ LANGUAGE = \"JScript.Encode\" %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	expect("<%@ LANGUAGE=\"ECMAScript\" %><% a = 'x' %>", "M{<%@ LANGUAGE=\"ECMAScript\" %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	expect("<%@Language='jscript'%><%='x'%>", "M{<%@Language='jscript'%>}T{<%=}S*{'x'}T{%>}");
	/* the language need not be the first attribute, and its name is read in any case */
	expect("<%@ CODEPAGE=65001 LANGUAGE=\"JSCRIPT\" ENABLESESSIONSTATE=False %><% a = 'x' %>",
	       "M{<%@ CODEPAGE=65001 LANGUAGE=\"JSCRIPT\" ENABLESESSIONSTATE=False %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	/* explicit vbscript, and VBScript.Encode (the encoded body is the vb lexer's) */
	expect("<%@ LANGUAGE=\"VBScript\" %><% a = 'x' %>", "M{<%@ LANGUAGE=\"VBScript\" %>}T{<%}C{ a = }K{'x' }T{%>}");
	expect("<%@ LANGUAGE = VBScript.Encode%><% a = 'x' %>", "M{<%@ LANGUAGE = VBScript.Encode%>}T{<%}C{ a = }K{'x' }T{%>}");
	/* a word "jscript" in another attribute's value is not the language: the quotes are read */
	expect("<%@ Title=\"language jscript\" %><% a = 'x' %>", "M{<%@ Title=\"language jscript\" %>}T{<%}C{ a = }K{'x' }T{%>}");
	expect("<%@ Title=\"x\" Language=\"JScript\" %><% a = 'x' %>", "M{<%@ Title=\"x\" Language=\"JScript\" %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	/* "language" is an attribute name, not a part of one: "xlanguage" is another */
	expect("<%@ xlanguage=JScript %><% a = 'x' %>", "M{<%@ xlanguage=JScript %>}T{<%}C{ a = }K{'x' }T{%>}");
	/* a name this tree has no lexer for is vbscript */
	expect("<%@ Language=PerlScript %><% a = 'x' %>", "M{<%@ Language=PerlScript %>}T{<%}C{ a = }K{'x' }T{%>}");
	/* a directive after other directives still names it; one in an island's string is not read */
	expect("<%@ CODEPAGE=1252 %><%@ Language=JScript %><% a = 'x' %>",
	       "M{<%@ CODEPAGE=1252 %><%@ Language=JScript %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	expect("<% a = \"<%@ Language=JScript\" %>%> b <% 'x' %>",
	       "T{<%}C{ a = }S{\"<%@ Language=JScript\"}C{ }T{%>}M{%> b }T{<%}C{ }K{'x' }T{%>}");
}

static void script_elements(void)
{
	expect("<script language=\"vbscript\" runat=\"server\">x = \"a\" 'c\n</script>after",
	       "T{<script language=\"vbscript\" runat=\"server\">}C{x = }S{\"a\"}C{ }K{'c}C{\n}T{</script>}M{after}");
	/* the element's own language, whatever the page's, in any case, quoted or not, in either order */
	expect("<SCRIPT LANGUAGE=JScript RUNAT=Server>a = 'x'; // c\n</SCRIPT>",
	       "T{<SCRIPT LANGUAGE=JScript RUNAT=Server>}C{a = }S*{'x'}C{; }K{// c}C{\n}T{</SCRIPT>}");
	expect("<script runat=\"server\" language=\"javascript\">a = 'x'</script>",
	       "T{<script runat=\"server\" language=\"javascript\">}C{a = }S*{'x'}T{</script>}");
	expect("<%@ Language=JScript %><script runat=server language=vbscript>a = 'x'</script>",
	       "M{<%@ Language=JScript %>}T{<script runat=server language=vbscript>}C{a = }K{'x'}T{</script>}");
	/* with no language of its own it is the page's */
	expect("<%@ Language=JScript %><script runat=\"server\">a = 'x'</script>",
	       "M{<%@ Language=JScript %>}T{<script runat=\"server\">}C{a = }S*{'x'}T{</script>}");
	expect("<script runat=\"server\">a = 'x'</script>", "T{<script runat=\"server\">}C{a = }K{'x'}T{</script>}");
	/* the language of an element does not change the page's: the island after it is still vbscript */
	expect("<script language=jscript runat=server>1</script><% a = 'x' %>",
	       "T{<script language=jscript runat=server>}C{1}T{</script>}T{<%}C{ a = }K{'x' }T{%>}");
	/* a name this tree has no lexer for is the page's language */
	expect("<script language=perlscript runat=server>a = 'x'</script>", "T{<script language=perlscript runat=server>}C{a = }K{'x'}T{</script>}");
	/* quotes: a ">" in a value does not end the tag; spaces around "=", single quotes, a line break inside */
	expect("<script title=\"a>b\" runat=\"server\">x</script>", "T{<script title=\"a>b\" runat=\"server\">}C{x}T{</script>}");
	expect("<script  runat = 'server'  >x</script>", "T{<script  runat = 'server'  >}C{x}T{</script>}");
	expect("<script\n runat=\"server\"\n>x</script>", "T{<script\n runat=\"server\"\n>}C{x}T{</script>}");
	expect("<script src=\"a.vbs\" runat=\"server\"></script>", "T{<script src=\"a.vbs\" runat=\"server\">}T{</script>}");
	/* NOT server scripts: no runat, runat="client", another attribute's name or value, a longer tag name */
	expect("<script language=\"vbscript\">x = 1</script>", "M{<script language=\"vbscript\">x = 1</script>}");
	expect("<script runat=\"client\">x</script>", "M{<script runat=\"client\">x</script>}");
	expect("<script data-runat=\"server\">x</script>", "M{<script data-runat=\"server\">x</script>}");
	expect("<script title=\"runat=server\">x</script>", "M{<script title=\"runat=server\">x</script>}");
	expect("<script runat=\"servers\">x</script>", "M{<script runat=\"servers\">x</script>}");
	expect("<scripts runat=\"server\">x</scripts>", "M{<scripts runat=\"server\">x</scripts>}");
	expect("<script runat=\"server\"", "M{<script runat=\"server\"}");
	/* a client script that holds an island still has it */
	expect("<script>a = <%= x %>;</script>", "M{<script>a = }T{<%=}C{ x }T{%>}M{;</script>}");
	/* the end tag is found before the language reads: in a string and in a comment too */
	expect("<script runat=server>x = \"</script>\"</script>", "T{<script runat=server>}C{x = }S!{\"}T{</script>}M{\"</script>}");
	expect("<script runat=server>' c </script> d</script>", "T{<script runat=server>}K{' c }T{</script>}M{ d</script>}");
	/* the end tag is "</script", white space, ">": "</scripts>" and "</script x>" are text of the body */
	expect("<script runat=server>a</scripts>b</script>c", "T{<script runat=server>}C{a</scripts>b}T{</script>}M{c}");
	expect("<script runat=server>a</script x>b</script  >c", "T{<script runat=server>}C{a</script x>b}T{</script  >}M{c}");
	expect("<script runat=server>a</SCRIPT\n>c", "T{<script runat=server>}C{a}T{</SCRIPT\n>}M{c}");
	/* not closed: the code runs to the end; "</script" cut off by the end is not a tag */
	expect("<script runat=\"server\">x = 1", "T{<script runat=\"server\">}C{x = 1}");
	expect("<script runat=server>x</script", "T{<script runat=server>}C{x</script}");
	/* inside the body "%>" and "<%" are text: it is not an island */
	expect("<script runat=server>x = \"%>\"</script>", "T{<script runat=server>}C{x = }S{\"%>\"}T{</script>}");
	expect("<script runat=server>a <% b %> c</script>", "T{<script runat=server>}C{a <% b %> c}T{</script>}");
	/* elements one after the other, with markup between, and an html comment around one */
	expect("<script runat=server>a</script>m<script runat=server>b</script>",
	       "T{<script runat=server>}C{a}T{</script>}M{m}T{<script runat=server>}C{b}T{</script>}");
	expect("<!-- <script runat=server>a</script> -->", "M{<!-- }T{<script runat=server>}C{a}T{</script>}M{ -->}");
}

static void vb_bodies(void)
{
	/* Rem is a comment where a statement can begin: the start of an island, a line, after ":"; not after an expression */
	expect("<% Rem x %>", "T{<%}C{ }K{Rem x }T{%>}");
	expect("<% a\nRem x\nb %>", "T{<%}C{ a\n}K{Rem x}C{\nb }T{%>}");
	expect("<% a: Rem x %>", "T{<%}C{ a: }K{Rem x }T{%>}");
	expect("<% a Rem x %>", "T{<%}C{ a Rem x }T{%>}");
	expect("<% Remark = 1 %>", "T{<%}C{ Remark = 1 }T{%>}");
	expect("<% a.Rem x %>", "T{<%}C{ a.Rem x }T{%>}");
	/* every island begins a statement: a Rem at the start of the second is a comment */
	expect("<% a %><% Rem x %>", "T{<%}C{ a }T{%>}T{<%}C{ }K{Rem x }T{%>}");
	/* the comment ends with its line; CRLF is not in it */
	expect("<% a ' c\r\nb %>", "T{<%}C{ a }K{' c}C{\r\nb }T{%>}");
	/* a quote is doubled inside a string; "" is an empty string; a backslash is a letter */
	expect("<% a = \"x\"\"y\" %>", "T{<%}C{ a = }S{\"x\"\"y\"}C{ }T{%>}");
	expect("<% a = \"\" %>", "T{<%}C{ a = }S{\"\"}C{ }T{%>}");
	expect("<% a = \"\"\"\" %>", "T{<%}C{ a = }S{\"\"\"\"}C{ }T{%>}");
	expect("<% a = \"x\\\" & \"y\" %>", "T{<%}C{ a = }S{\"x\\\"}C{ & }S{\"y\"}C{ }T{%>}");
	/* a string that is not closed ends at its line; at the end of the island it is open there */
	expect("<% a = \"x\nb %>", "T{<%}C{ a = }S!{\"x}C{\nb }T{%>}");
	expect("<% a = \"x %>", "T{<%}C{ a = }S!{\"x }T{%>}");
	/* a date literal and an extended name are code: the apostrophe in a name opens nothing */
	expect("<% d = #1/1/2000 10:30:00# %>", "T{<%}C{ d = #1/1/2000 10:30:00# }T{%>}");
	expect("<% [a 'b] = 1 %>", "T{<%}C{ [a 'b] = 1 }T{%>}");
	/* the continuation is a "_" that ends its line: Rem after it is not a statement start */
	expect("<% a = 1 + _\n Rem x %>", "T{<%}C{ a = 1 + _\n Rem x }T{%>}");
	/* the script encoder block is one opaque string */
	expect("<% #@~^AAAA==x'y\"z^#~@ %>", "T{<%}C{ }S{#@~^AAAA==x'y\"z^#~@}C{ }T{%>}");
}

/* excerpts of the webshells of the sample trees, whole statements as they were typed */
static void real_shell_shapes(void)
{
	/* cmdasp.asp: an island inside a form, Request.ServerVariables with quotes, a "<%" in the value of an attribute */
	expect("<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">\n<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">",
	       "M{<FORM action=\"}T{<%=}C{ Request.ServerVariables(}S{\"URL\"}C{) }T{%>}M{\" method=\"POST\">\n<input type=text name=\".CMD\" size=45 value=\"}T{<%=}C{ szCMD }T{%>}M{\">}");
	/* file.asp: code between two islands that closes one tag and opens the next in the middle of markup */
	expect("<%\nFor Each i In x\n%><a href=\"<%=Request.ServerVariables(\"URL\") & \"?path=\" & i.DriveLetter%>:\\\"><%=i.DriveLetter%>:</a><%\nNext\n%>",
	       "T{<%}C{\nFor Each i In x\n}T{%>}M{<a href=\"}T{<%=}C{Request.ServerVariables(}S{\"URL\"}C{) & }S{\"?path=\"}C{ & i.DriveLetter}T{%>}M{:\\\">}T{<%=}C{i.DriveLetter}T{%>}M{:</a>}T{<%}C{\nNext\n}T{%>}");
	/* aspcmd.asp: the jscript page */
	expect("<%@ Language = \"JScript\" %>\n<%\nvar oScript = new ActiveXObject(\"WScript.Shell\"); // run\nvar s = '\\\\' + \"\\\"x\";\n%>",
	       "M{<%@ Language = \"JScript\" %>\n}T{<%}C{\nvar oScript = new ActiveXObject(}S*{\"WScript.Shell\"}C{); }K{// run}C{\nvar s = }S*{'\\\\'}C{ + }S*{\"\\\"x\"}C{;\n}T{%>}");
}

static void fragments(void)
{
	/* a FRAGMENT is code of the page's language from its first byte: no tag is looked for */
	static struct rend r;
	static const char src[] = "a = \"x<%\" ' c %>\nb = 'y'";
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = ASP,
					      .flags = KGENOME_TEXTUAL_FRAGMENT, .sink = sink, .user = &r };
	struct kgenome_textual_lex_res rs;

	memset(&r, 0, sizeof r);
	r.in = (const uint8_t *)src;
	r.n = rq.n;
	kgenome_textual_lex(&rq, &rs);
	CK(!r.broken && r.next == rq.n);
	CK(strcmp(r.out, "C{a = }S{\"x<%\"}C{ }K{' c %>}C{\nb = }K{'y'}") == 0);
	if (strcmp(r.out, "C{a = }S{\"x<%\"}C{ }K{' c %>}C{\nb = }K{'y'}"))
		printf("  fragment got %s\n", r.out);
}

static void forms(void)
{
	/* an island with no code goes whole, tags and all: white space, a comment */
	form("a<% %>b", "ab");
	form("<%  ' only a comment %>", "");
	form("<% %><% Rem x %>", "");
	form("a<%= %>b", "ab");
	form("<script runat=\"server\"> ' c\n</script>x", "x");
	/* the closing tag gets a line break, and one only */
	form("<% a = 1 %>", "<%a=1\n%>");
	form("<% a = 1\n%>", "<%a=1\n%>");
	form("<%= x %>b", "<%=x\n%>b");
	form("<script runat=\"server\">x = 1</script>", "<script runat=\"server\">x=1\n</script>");
	/* comments go, a trailing one too; white space and blank lines collapse; a line break stays one */
	/* a line break after the tag is kept: it is the program's line */
	form("<%\n  a = 1 ' c\n\n\n   b = 2\n%>", "<%\na=1\nb=2\n%>");
	form("<% a = 1 : ' c\r\n b = 2 %>", "<%a=1:\nb=2\n%>");
	/* names keep a space where closing up would make one; so do the pairs that would glue */
	form("<% If a Then b %>", "<%If a Then b\n%>");
	form("<% a = b + +c %>", "<%a=b+ +c\n%>");
	form("<% a < > b %>", "<%a< >b\n%>");
	form("<%@ Language=JScript %><% a / /*c*/ / b %>", "<%@ Language=JScript %><%a/ /b\n%>");
	form("<%@ Language=JScript %><% a / /*c*/ b %>", "<%@ Language=JScript %><%a/b\n%>");
	form("<% a & &H1F %>", "<%a& &H1F\n%>");
	form("<% x = a & Hex(b) %>", "<%x=a& Hex(b)\n%>");
	form("<% x = 1 .ToString() %>", "<%x=1 .ToString()\n%>");
	/* closing up must not end the island: "% >" and "% (comment) >" keep their gap; nor open a directive: "<% @x" */
	form("<% a % > b %>", "<%a% >b\n%>");
	form("<%@ Language=JScript %><% a %/* c */> b %>", "<%@ Language=JScript %><%a% >b\n%>");
	form("<% @x %>", "<% @x\n%>");
	form("<% =x %>", "<% =x\n%>");
	/* a string, markup, and a directive are copied as typed */
	form("<%@ Language = JScript %> <b  class=\"a\">\n\n<% x = 'a  b' %>", "<%@ Language = JScript %> <b  class=\"a\">\n\n<%x='a  b'\n%>");
	form("<% a = \"x  ' y\" %><!-- <%= \"q\" %> -->", "<%a=\"x  ' y\"\n%><!-- <%=\"q\"\n%> -->");
	/* an island that holds only a vbscript comment goes, in an html comment too */
	form("<!-- <%= 'q' %> -->", "<!--  -->");
	/* a string that is not closed, and a comment that is not, stay as typed */
	form("<% a = \"x %>", "<%a=\"x %>");
	/* jscript: \x41 and the octal \101 are written as the byte; the escaped quote is not; vbscript's backslash is a letter */
	form("<%@ Language=JScript %><% a = \"\\x41\\101\\x22\" %>", "<%@ Language=JScript %><%a=\"AA\\x22\"\n%>");
	form("<% a = \"\\x41\" %>", "<%a=\"\\x41\"\n%>");
	/* a script element's code, jscript in a vbscript page */
	form("<script language=jscript runat=server>\n a = 1; // c\n b = 'x'\n</script>", "<script language=jscript runat=server>\na=1;\nb='x'\n</script>");
	/* a jscript block comment open at the end of the island has no line break put into it */
	form("<%@ Language=JScript %><% x /* c %>", "<%@ Language=JScript %><%x/* c %>");
	/* vbscript's continuation: its line break stays and a blank line after it does not collapse */
	form("<% a = 1 + _\n\n b %>", "<%a=1+ _\n\nb\n%>");
}

/* No call_chain: asp has no decoder it can call by name, so the hook is never asked. */
static int hook(void *u, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len, const uint8_t **out,
		uint32_t *out_len)
{
	(void)chain;
	(void)n_chain;
	(void)in;
	(void)len;
	*out = (const uint8_t *)"decoded";
	*out_len = 7;
	++*(int *)u;
	return 1;
}

static void no_call_chain(void)
{
	static uint8_t out[512];
	static const char src[] = "<% x = Convert.FromBase64String(\"QQ==\") %>";
	int asked = 0;
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = ASP, .out = out,
					       .cap = sizeof out, .decode = hook, .decode_user = &asked };
	struct kgenome_textual_form_res rs;

	kgenome_textual_form(&rq, &rs);
	CK(asked == 0 && rs.n_decoded == 0);
}

static void hostile(void)
{
	/* work is linear: 100000 server script tags that each open a quote which never closes would be read to the end each */
	static uint8_t big[600000];
	static struct rend r;
	uint32_t n = 0, k;
	clock_t t0 = clock();
	struct kgenome_textual_lex_req rq;
	struct kgenome_textual_lex_res rs;

	for (k = 0; k < 60000u && n + 16u < sizeof big; k++)
		n += (uint32_t)snprintf((char *)big + n, 16, "<script \"x ");
	rq = (struct kgenome_textual_lex_req){ .in = big, .n = n, .lang = ASP, .sink = sink, .user = &r };
	memset(&r, 0, sizeof r);
	r.n = n;
	r.in = big;
	kgenome_textual_lex(&rq, &rs);
	CK(r.next == n || r.broken == 0);
	/* and "<script <script ... >" with the one ">" at the very end */
	n = 0;
	for (k = 0; k < 60000u; k++)
		n += (uint32_t)snprintf((char *)big + n, 10, "<script ");
	big[n++] = '>';
	rq.n = n;
	memset(&r, 0, sizeof r);
	r.n = n;
	r.in = big;
	kgenome_textual_lex(&rq, &rs);
	CK(r.next == n || r.broken == 0);
	CK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
	printf("  hostile tags: %.2fs\n", (double)(clock() - t0) / CLOCKS_PER_SEC);
}

int main(void)
{
	islands();
	ends_of_islands();
	directives();
	script_elements();
	vb_bodies();
	real_shell_shapes();
	fragments();
	forms();
	no_call_chain();
	hostile();
	pg_check_lex(ASP, 0, 20260101u, 6000u);
	pg_check_form(ASP, 0, 20260202u, 3000u);
	partition_for(ASP, "<%%>=@-#$:!'\"\\ \n\r_/*&script runat=server language=jscript</>Rem x", 11u);
	partition_for(ASP, "<%@ LANGUAGE=JScript%>'\" \n</script runat=\"server\">", 12u);
	form_property_for(ASP, "<%>=@-#$:!'\"\\ \n_/*&scriptrunat=sevlg</Rem ", 13u);
	form_property_for(ASP, "<%@Language=JScript>'\"\\x41 \n</script runat=server>%", 14u);
	if (fails)
		printf("textual asp: %d FAILED\n", fails);
	else
		printf("textual asp: ok\n");
	return fails != 0;
}
