/*
 * genome / textual_aspx - the asp.net lexer of the textual part, through <kgenome.h> alone.
 *
 * A text is rendered as its spans, a kind letter and the bytes in braces (textual_check.h: M markup, T tag,
 * C code, S string, K comment; S* a backslash is an escape, S! not closed). Each rule has the neighbour it
 * could be confused for next to it.
 *
 * EVIDENCE. There is no asp.net, mono or csc on this machine: the rules are from the language references
 * [Inference]. The second implementation is pygments' CSharpLexer, run by
 * /mnt/games/normtest/asp/tools/diff_pyg.py over the five .aspx files of the sample trees (201 islands in
 * all with the asp ones, 0 differences in strings and comments); it does not know C# 11 raw strings or
 * the text of #region, which are therefore pinned here by the C# reference and nothing else.
 *
 *   - the page: directives (the first Language attribute names the island language), <%= <%# <%$ <%: and
 *     the comment <%-- --%>, <script runat="server">, server controls with islands in their attributes;
 *   - C#: "//" and the C comment, strings with escapes, @"" with a doubled quote, $"" with holes that
 *     hold strings, raw """ strings, characters like '"', #region text, generics and lambdas;
 *   - vb.net and jscript islands, per page and per element; .ashx and .asmx, whose source follows a directive;
 *   - the form, the call chain (Convert.FromBase64String), and 6000 generated pages.
 */

#include "textual_pagegen.h"

#include <time.h>

#define ASPX KGENOME_TEXTUAL_LANG_ASPX

static void expect(const char *src, const char *want)
{
	expect_lang(ASPX, src, want);
}

static void form(const char *src, const char *want)
{
	form_lang(ASPX, src, want);
}

static void tags(void)
{
	expect("", "");
	expect("a<% x %>b", "M{a}T{<%}C{ x }T{%>}M{b}");
	expect("<%= x %>", "T{<%=}C{ x }T{%>}");
	expect("<%# Eval(\"x\") %>", "T{<%#}C{ Eval(}S*{\"x\"}C{) }T{%>}");
	expect("<%#: Eval(\"x\") %>", "T{<%#}C{: Eval(}S*{\"x\"}C{) }T{%>}");
	expect("<%$ resources:Res, Key %>", "T{<%$}C{ resources:Res, Key }T{%>}");
	expect("<%: x %>", "T{<%:}C{ x }T{%>}");
	/* "<%!" is not a tag here: it is code that begins with "!" */
	expect("<%! x %>", "T{<%}C{! x }T{%>}");
	expect("<% =x %>", "T{<%}C{ =x }T{%>}");
	expect("<%%>", "T{<%}T{%>}");
	expect("<% x", "T{<%}C{ x}");
	expect("<%#", "T{<%#}");
	expect("a<", "M{a<}");
	expect("a<b", "M{a<b}");
	/* a markup "%>" is text */
	expect("a %> b", "M{a %> b}");
	/* the comment of the page: whole, with "%>", "<%" and "--" inside, never code */
	expect("<%-- c --%>", "K{<%-- c --%>}");
	expect("a<%-- c --%>b", "M{a}K{<%-- c --%>}M{b}");
	expect("<%-- a %> b <% c %> d -- e --%><% x %>", "K{<%-- a %> b <% c %> d -- e --%>}T{<%}C{ x }T{%>}");
	expect("<%----%>", "K{<%----%>}");
	expect("<%-- x", "K!{<%-- x}");
	expect("<%--", "K!{<%--}");
	/* a comment that hides a control is a comment; an html comment hides nothing: its island runs */
	expect("<%-- <asp:Button runat=\"server\" /> --%>", "K{<%-- <asp:Button runat=\"server\" /> --%>}");
	expect("<!-- <%= x %> -->", "M{<!-- }T{<%=}C{ x }T{%>}M{ -->}");
	/* server controls, with islands in their attributes */
	expect("<asp:Button runat=\"server\" OnClick=\"<%# x %>\" Text='<%$ r:K %>' />",
	       "M{<asp:Button runat=\"server\" OnClick=\"}T{<%#}C{ x }T{%>}M{\" Text='}T{<%$}C{ r:K }T{%>}M{' />}");
	expect("<asp:Label Text=\"a > b\" runat=\"server\" /><%= a %>", "M{<asp:Label Text=\"a > b\" runat=\"server\" />}T{<%=}C{ a }T{%>}");
	/* CDATA, style and a client script are markup; a "<%" in them is an island */
	expect("<![CDATA[ x <y> ]]>", "M{<![CDATA[ x <y> ]]>}");
	expect("<![CDATA[ <%= x %> ]]>", "M{<![CDATA[ }T{<%=}C{ x }T{%>}M{ ]]>}");
	expect("<style> a > b { c: d } </style>", "M{<style> a > b { c: d } </style>}");
	expect("<script type=\"text/javascript\">if (a<b) { x = \"y\"; }</script>", "M{<script type=\"text/javascript\">if (a<b) { x = \"y\"; }</script>}");
	expect("<script>var a = '<%= x %>';</script>", "M{<script>var a = '}T{<%=}C{ x }T{%>}M{';</script>}");
	expect("<%@ Page Language=\"C#\" %>x<%@ Import Namespace=\"System.IO\" %>", "M{<%@ Page Language=\"C#\" %>x<%@ Import Namespace=\"System.IO\" %>}");
	expect("<%@ Register TagPrefix=\"x\" Namespace=\"y\" Assembly=\"z\" %><x:a runat=\"server\" />",
	       "M{<%@ Register TagPrefix=\"x\" Namespace=\"y\" Assembly=\"z\" %><x:a runat=\"server\" />}");
}

static void ends(void)
{
	/* "%>" ends an island in a string and in a comment: the page scanner reads before C# does */
	expect("<% var s = \"a %> b\"; %>", "T{<%}C{ var s = }S*!{\"a }T{%>}M{ b\"; %>}");
	expect("<% // c %> d", "T{<%}C{ }K{// c }T{%>}M{ d}");
	expect("<% /* c %> d */ x %>", "T{<%}C{ }K!{/* c }T{%>}M{ d */ x %>}");
	expect("<% var s = \"<%\"; %>", "T{<%}C{ var s = }S*{\"<%\"}C{; }T{%>}");
	expect("<% var s = \"%\\>\"; %>", "T{<%}C{ var s = }S*{\"%\\>\"}C{; }T{%>}");
	expect("<%# \"</script>\" %>", "T{<%#}C{ }S*{\"</script>\"}C{ }T{%>}");
}

static void csharp(void)
{
	/* comments: "//" ends at the line (CRLF not in it), the C comment runs over lines, slash-star-slash is not whole */
	expect("<% a // c\r\n b %>", "T{<%}C{ a }K{// c}C{\r\n b }T{%>}");
	expect("<% a /* c\n d */ b %>", "T{<%}C{ a }K{/* c\n d */}C{ b }T{%>}");
	expect("<% /*/ x */ %>", "T{<%}C{ }K{/*/ x */}C{ }T{%>}");
	expect("<% /* x", "T{<%}C{ }K!{/* x}");
	expect("<% /// <summary>x</summary>\n %>", "T{<%}C{ }K{/// <summary>x</summary>}C{\n }T{%>}");
	/* strings: escapes, an escaped backslash before the quote, a line ends an unclosed one */
	expect("<% s = \"a\\\"b\"; %>", "T{<%}C{ s = }S*{\"a\\\"b\"}C{; }T{%>}");
	expect("<% s = \"a\\\\\"; t = 1; %>", "T{<%}C{ s = }S*{\"a\\\\\"}C{; t = 1; }T{%>}");
	expect("<% s = \"a\nb\"; %>", "T{<%}C{ s = }S*!{\"a}C{\nb}S*!{\"; }T{%>}");
	expect("<% s = \"a\r\nb %>", "T{<%}C{ s = }S*!{\"a}C{\r\nb }T{%>}");
	expect("<% s = \"a", "T{<%}C{ s = }S*!{\"a}");
	expect("<% s = \"a\\", "T{<%}C{ s = }S*!{\"a\\}");
	/* a comment marker in a string is the string's */
	expect("<% s = \"// not /* a comment\"; %>", "T{<%}C{ s = }S*{\"// not /* a comment\"}C{; }T{%>}");
	/* characters: a quote and an apostrophe, escaped */
	expect("<% c = '\"'; d = '\\''; e = '\\\\'; %>", "T{<%}C{ c = }S*{'\"'}C{; d = }S*{'\\''}C{; e = }S*{'\\\\'}C{; }T{%>}");
	expect("<% c = '\"'; s = \"x\"; %>", "T{<%}C{ c = }S*{'\"'}C{; s = }S*{\"x\"}C{; }T{%>}");
	/* verbatim: a doubled quote is a quote, a backslash is a letter, it runs over lines */
	expect("<% s = @\"a\"\"b\"; %>", "T{<%}C{ s = }S{@\"a\"\"b\"}C{; }T{%>}");
	expect("<% s = @\"C:\\dir\\\"; t = 1; %>", "T{<%}C{ s = }S{@\"C:\\dir\\\"}C{; t = 1; }T{%>}");
	expect("<% s = @\"a\nb // c\"; %>", "T{<%}C{ s = }S{@\"a\nb // c\"}C{; }T{%>}");
	expect("<% s = @\"x", "T{<%}C{ s = }S!{@\"x}");
	expect("<% @class = 1; %>", "T{<%}C{ @class = 1; }T{%>}");
	/* a verbatim identifier is not a string, nor is a lone dollar */
	expect("<% var @a = $b; %>", "T{<%}C{ var @a = $b; }T{%>}");
	/* interpolated: holes with strings and brackets in them, "{{" is a brace, a format after ":" */
	expect("<% s = $\"a{b}c\"; %>", "T{<%}C{ s = }S*{$\"a{b}c\"}C{; }T{%>}");
	expect("<% s = $\"a{{b}}c\"; %>", "T{<%}C{ s = }S*{$\"a{{b}}c\"}C{; }T{%>}");
	expect("<% s = $\"{x[\"k\"]}\"; %>", "T{<%}C{ s = }S*{$\"{x[\"k\"]}\"}C{; }T{%>}");
	expect("<% s = $\"{f(\"}\")}\"; %>", "T{<%}C{ s = }S*{$\"{f(\"}\")}\"}C{; }T{%>}");
	expect("<% s = $\"{('}')}\"; %>", "T{<%}C{ s = }S*{$\"{('}')}\"}C{; }T{%>}");
	expect("<% s = $\"{x:N2}\"; %>", "T{<%}C{ s = }S*{$\"{x:N2}\"}C{; }T{%>}");
	expect("<% s = $\"{{{x}}}\"; %>", "T{<%}C{ s = }S*{$\"{{{x}}}\"}C{; }T{%>}");
	expect("<% s = $@\"a\"\"{x}\"\"\"; %>", "T{<%}C{ s = }S{$@\"a\"\"{x}\"\"\"}C{; }T{%>}");
	expect("<% s = @$\"{x[\"k\"]}\"; %>", "T{<%}C{ s = }S{@$\"{x[\"k\"]}\"}C{; }T{%>}");
	/* raw string literals (C# 11): N quotes open it, N close it, fewer inside are text, no escape, lines allowed */
	expect("<% s = \"\"\"a \"b\" c\"\"\"; %>", "T{<%}C{ s = }S{\"\"\"a \"b\" c\"\"\"}C{; }T{%>}");
	expect("<% s = \"\"\"\n  two \\ lines\n  \"\"\"; %>", "T{<%}C{ s = }S{\"\"\"\n  two \\ lines\n  \"\"\"}C{; }T{%>}");
	expect("<% s = \"\"\"\"x \"\"\" y\"\"\"\"; %>", "T{<%}C{ s = }S{\"\"\"\"x \"\"\" y\"\"\"\"}C{; }T{%>}");
	expect("<% s = $\"\"\"a {x[\"k\"]} \"b\" c\"\"\"; %>", "T{<%}C{ s = }S{$\"\"\"a {x[\"k\"]} \"b\" c\"\"\"}C{; }T{%>}");
	expect("<% s = $$\"\"\"{{x}} {y} \"q\" \"\"\"; %>", "T{<%}C{ s = }S{$$\"\"\"{{x}} {y} \"q\" \"\"\"}C{; }T{%>}");
	expect("<% s = \"\"\"a", "T{<%}C{ s = }S!{\"\"\"a}");
	/* ... and the neighbours: "" is an empty string, @"""" a verbatim string of one quote, @""" starts one with a quote */
	expect("<% s = \"\"; t = \"x\"; %>", "T{<%}C{ s = }S*{\"\"}C{; t = }S*{\"x\"}C{; }T{%>}");
	expect("<% s = @\"\"\"\"; %>", "T{<%}C{ s = }S{@\"\"\"\"}C{; }T{%>}");
	expect("<% s = @\"\"\"abc\"; %>", "T{<%}C{ s = }S{@\"\"\"abc\"}C{; }T{%>}");
	/* the text of #region is not code: its apostrophe opens no character; the others are code with their comments */
	expect("<%\n#region User's methods\nint a;\n#endregion\n%>", "T{<%}C{\n#region User's methods\nint a;\n#endregion\n}T{%>}");
	expect("<% #region a'b \"c\n x %>", "T{<%}C{ #region a'b \"c\n x }T{%>}");
	expect("<%\n#warning don't\n#error \"x\n%>", "T{<%}C{\n#warning don't\n#error \"x\n}T{%>}");
	expect("<%\n  # region a'b\nx %>", "T{<%}C{\n  # region a'b\nx }T{%>}");
	expect("<%\n#if DEBUG // c\nx\n#endif\n%>", "T{<%}C{\n#if DEBUG }K{// c}C{\nx\n#endif\n}T{%>}");
	expect("<%\n#pragma warning disable 1591 // c\n%>", "T{<%}C{\n#pragma warning disable 1591 }K{// c}C{\n}T{%>}");
	expect("<%\n#pragma checksum \"a.cs\" \"{g}\" \"h\"\n%>", "T{<%}C{\n#pragma checksum }S*{\"a.cs\"}C{ }S*{\"{g}\"}C{ }S*{\"h\"}C{\n}T{%>}");
	/* ... and not at the start of a line it is not a directive: the apostrophe opens a character */
	expect("<% a #region b'c' %>", "T{<%}C{ a #region b}S*{'c'}C{ }T{%>}");
	expect("<% x = 1; #region a'b\n %>", "T{<%}C{ x = 1; #region a}S*!{'b}C{\n }T{%>}");
	/* "#regions" and "#errors" are not those directives */
	expect("<%\n#regions a'b\n%>", "T{<%}C{\n#regions a}S*!{'b}C{\n}T{%>}");
	/* generics, lambdas, attributes, unsafe, null-conditional: code, with their strings */
	expect("<% List<Dictionary<string, int>> m = a => b ?? \"x\"; c?.d(); %>",
	       "T{<%}C{ List<Dictionary<string, int>> m = a => b ?? }S*{\"x\"}C{; c?.d(); }T{%>}");
	expect("<script runat=\"server\">[DllImport(\"kernel32.dll\", CharSet = CharSet.Auto)] static extern int F(); unsafe { int* p = &x; }</script>",
	       "T{<script runat=\"server\">}C{[DllImport(}S*{\"kernel32.dll\"}C{, CharSet = CharSet.Auto)] static extern int F(); unsafe { int* p = &x; }}T{</script>}");
	expect("<% a = b / c; d = e /* f */ / g; %>", "T{<%}C{ a = b / c; d = e }K{/* f */}C{ / g; }T{%>}");
}

static void directives(void)
{
	/* the first directive that has a Language names it; the default is C# */
	expect("<%@ Page Language=\"C#\" %><% s = \"a\" // c\n %>", "M{<%@ Page Language=\"C#\" %>}T{<%}C{ s = }S*{\"a\"}C{ }K{// c}C{\n }T{%>}");
	expect("<%@ Page Language=\"VB\" %><% s = \"a\" ' c\n %>", "M{<%@ Page Language=\"VB\" %>}T{<%}C{ s = }S{\"a\"}C{ }K{' c}C{\n }T{%>}");
	expect("<%@ Page Language=\"VisualBasic\" %><% s = \"a\" ' c %>", "M{<%@ Page Language=\"VisualBasic\" %>}T{<%}C{ s = }S{\"a\"}C{ }K{' c }T{%>}");
	expect("<%@ Control Language=vb %><% s = 'x' %>", "M{<%@ Control Language=vb %>}T{<%}C{ s = }K{'x' }T{%>}");
	expect("<%@ Master language='VB'%><% s = 'x' %>", "M{<%@ Master language='VB'%>}T{<%}C{ s = }K{'x' }T{%>}");
	expect("<%@ Page Language=\"cs\" %><% c = '\"'; %>", "M{<%@ Page Language=\"cs\" %>}T{<%}C{ c = }S*{'\"'}C{; }T{%>}");
	expect("<%@ Page Language=\"CSharp\" %><% c = '\"'; %>", "M{<%@ Page Language=\"CSharp\" %>}T{<%}C{ c = }S*{'\"'}C{; }T{%>}");
	expect("<% c = '\"'; %>", "T{<%}C{ c = }S*{'\"'}C{; }T{%>}");
	/* jscript.net */
	expect("<%@ Page Language=\"JScript\" %><% a = 'x' // c\n %>", "M{<%@ Page Language=\"JScript\" %>}T{<%}C{ a = }S*{'x'}C{ }K{// c}C{\n }T{%>}");
	expect("<%@ Page Language=\"JavaScript\" %><% a = 'x' %>", "M{<%@ Page Language=\"JavaScript\" %>}T{<%}C{ a = }S*{'x'}C{ }T{%>}");
	/* a name in another attribute's value is not the language (the quotes are read) */
	expect("<%@ Page Title=\"a language vb\" Language=\"C#\" %><% s = 'x'; %>", "M{<%@ Page Title=\"a language vb\" Language=\"C#\" %>}T{<%}C{ s = }S*{'x'}C{; }T{%>}");
	expect("<%@ Page Title=\"x\" Language='VB' CodeFile=\"a.vb\" %><% s = 'x' %>", "M{<%@ Page Title=\"x\" Language='VB' CodeFile=\"a.vb\" %>}T{<%}C{ s = }K{'x' }T{%>}");
	/* an Import in front: the Language of the Page that follows is read */
	expect("<%@ Import Namespace=\"System.IO\" %><%@ Page Language=\"VB\" %><% s = 'x' %>",
	       "M{<%@ Import Namespace=\"System.IO\" %><%@ Page Language=\"VB\" %>}T{<%}C{ s = }K{'x' }T{%>}");
	/* wherever the directive stands, it is the page's: the island before it is in its language */
	expect("<% s = 'x' %><%@ Page Language=\"VB\" %>", "T{<%}C{ s = }K{'x' }T{%>}M{<%@ Page Language=\"VB\" %>}");
	/* with no directive that has one, the first server script that has one names it, and the page before it */
	expect("<% s = 'x' %><script runat=\"server\" language=\"VB\">a = 'y'</script>",
	       "T{<%}C{ s = }K{'x' }T{%>}T{<script runat=\"server\" language=\"VB\">}C{a = }K{'y'}T{</script>}");
	/* ... but a directive wins over the script, even when the script comes first */
	expect("<script runat=\"server\" language=\"VB\">a = 'y'</script><%@ Page Language=\"C#\" %><% s = 'x'; %>",
	       "T{<script runat=\"server\" language=\"VB\">}C{a = }K{'y'}T{</script>}M{<%@ Page Language=\"C#\" %>}T{<%}C{ s = }S*{'x'}C{; }T{%>}");
	/* a script element of another language is lexed in it */
	expect("<%@ Page Language=\"C#\" %><script runat=\"server\" language=\"VB\">a = 'y' ' c\n</script>",
	       "M{<%@ Page Language=\"C#\" %>}T{<script runat=\"server\" language=\"VB\">}C{a = }K{'y' ' c}C{\n}T{</script>}");
	/* a directive or a script tag inside a server script's string is not read */
	expect("<script runat=\"server\">string s = \"<%@ Page Language=\\\"VB\\\" %>\"; // c\n</script>",
	       "T{<script runat=\"server\">}C{string s = }S*{\"<%@ Page Language=\\\"VB\\\" %>\"}C{; }K{// c}C{\n}T{</script>}");
}

static void scripts(void)
{
	expect("<script runat=\"server\">void F() { s = \"a\"; } // c\n</script>x",
	       "T{<script runat=\"server\">}C{void F() { s = }S*{\"a\"}C{; } }K{// c}C{\n}T{</script>}M{x}");
	expect("<script language=\"C#\" runat=\"server\">s = @\"a\"\"b\";</script>", "T{<script language=\"C#\" runat=\"server\">}C{s = }S{@\"a\"\"b\"}C{;}T{</script>}");
	expect("<SCRIPT RUNAT=SERVER>x</SCRIPT>", "T{<SCRIPT RUNAT=SERVER>}C{x}T{</SCRIPT>}");
	expect("<script runat=server>x</script >", "T{<script runat=server>}C{x}T{</script >}");
	expect("<script runat=\"server\">s = \"</script>\"; </script>", "T{<script runat=\"server\">}C{s = }S*!{\"}T{</script>}M{\"; </script>}");
	expect("<script runat=\"server\">a</scripts>b</script>", "T{<script runat=\"server\">}C{a</scripts>b}T{</script>}");
	expect("<script runat=\"server\">s = \"%>\"; a <% b</script>", "T{<script runat=\"server\">}C{s = }S*{\"%>\"}C{; a <% b}T{</script>}");
	expect("<script runat=\"server\">x = 1", "T{<script runat=\"server\">}C{x = 1}");
	expect("<script>x</script>", "M{<script>x</script>}");
	expect("<script runat=\"client\">x</script>", "M{<script runat=\"client\">x</script>}");
	expect("<script title=\"a>b\" runat=\"server\"> x </script>", "T{<script title=\"a>b\" runat=\"server\">}C{ x }T{</script>}");
	expect("<script data-runat=\"server\">x</script>", "M{<script data-runat=\"server\">x</script>}");
	/* a <%-- comment --%> inside the element is its code: the element's body is read by its language */
	expect("<script runat=\"server\"><%-- x --%></script>", "T{<script runat=\"server\">}C{<%-- x --%>}T{</script>}");
	/* vb.net in an element: ' is a comment, "" a quote, _ a continuation */
	expect("<script runat=\"server\" language=\"vb\">Dim a = \"x\"\"y\" ' c\nDim b = 1 + _\n 2\n</script>",
	       "T{<script runat=\"server\" language=\"vb\">}C{Dim a = }S{\"x\"\"y\"}C{ }K{' c}C{\nDim b = 1 + _\n 2\n}T{</script>}");
}

static void handlers(void)
{
	/* .ashx and .asmx: the source follows the directive, whole, and is not read for "<%" */
	expect("<%@ WebHandler Language=\"C#\" Class=\"H\" %>\nusing System;\nclass H { string s = \"<% x %>\"; // c\n}",
	       "M{<%@ WebHandler Language=\"C#\" Class=\"H\" %>}C{\nusing System;\nclass H { string s = }S*{\"<% x %>\"}C{; }K{// c}C{\n}}");
	expect("<%@ WebService Language=\"C#\" Class=\"S\" %>\n[WebMethod] string F() { return @\"a\"\"b\"; }",
	       "M{<%@ WebService Language=\"C#\" Class=\"S\" %>}C{\n[WebMethod] string F() { return }S{@\"a\"\"b\"}C{; }}");
	expect("<%@ WebHandler Language=\"VB\" Class=\"H\" %>\nDim a = \"x\" ' c",
	       "M{<%@ WebHandler Language=\"VB\" Class=\"H\" %>}C{\nDim a = }S{\"x\"}C{ }K{' c}");
	expect("<%@ webhandler Class=\"H\" %>x = 'a';", "M{<%@ webhandler Class=\"H\" %>}C{x = }S*{'a'}C{;}");
	expect("<%@ WebHandler Class=\"H\" %>", "M{<%@ WebHandler Class=\"H\" %>}");
	/* a Page directive is not one: markup follows it */
	expect("<%@ Page Language=\"C#\" %>x<% y %>", "M{<%@ Page Language=\"C#\" %>x}T{<%}C{ y }T{%>}");
	/* "WebHandlers" is not "WebHandler" */
	expect("<%@ WebHandlers Language=\"C#\" %>x<% y %>", "M{<%@ WebHandlers Language=\"C#\" %>x}T{<%}C{ y }T{%>}");
}

static void real_shell_shapes(void)
{
	/* cmdasp.aspx: directives, a server script with ProcessStartInfo and a string with a backslash */
	expect("<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"false\" %>\n<%@ Import Namespace=\"System.Diagnostics\" %>\n<script Language=\"C#\" runat=\"server\">\nvoid Page_Load(object sender, EventArgs e){\n}\nstring myexec (string arg){\n\tmypsi.FileName = \"cmd.exe\";\n\tmypsi.Arguments = \"/C \"+arg;\n}\n</script>\n<HTML><body><form runat=\"server\"><asp:TextBox id=\"txtArg\" runat=\"server\" /></form></body></HTML>",
	       "M{<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"false\" %>\n<%@ Import Namespace=\"System.Diagnostics\" %>\n}T{<script Language=\"C#\" runat=\"server\">}C{\nvoid Page_Load(object sender, EventArgs e){\n}\nstring myexec (string arg){\n\tmypsi.FileName = }S*{\"cmd.exe\"}C{;\n\tmypsi.Arguments = }S*{\"/C \"}C{+arg;\n}\n}T{</script>}M{\n<HTML><body><form runat=\"server\"><asp:TextBox id=\"txtArg\" runat=\"server\" /></form></body></HTML>}");
}

static void fragments(void)
{
	static struct rend r;
	static const char src[] = "a = \"x<%\" // c %>\nb = 'y';";
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = ASPX,
					      .flags = KGENOME_TEXTUAL_FRAGMENT, .sink = sink, .user = &r };
	struct kgenome_textual_lex_res rs;

	memset(&r, 0, sizeof r);
	r.in = (const uint8_t *)src;
	r.n = rq.n;
	kgenome_textual_lex(&rq, &rs);
	CK(!r.broken && r.next == rq.n);
	CK(strcmp(r.out, "C{a = }S*{\"x<%\"}C{ }K{// c %>}C{\nb = }S*{'y'}C{;}") == 0);
}

static void forms(void)
{
	form("a<% %>b", "ab");
	form("<%-- c --%>x<%  /* c */ %>y", "xy");
	form("<script runat=\"server\"> // c\n</script>x", "x");
	form("<% a = 1; %>", "<%a=1;\n%>");
	form("<%= x %>b", "<%=x\n%>b");
	form("<%# Eval(\"a  b\") %>", "<%# Eval(\"a  b\")\n%>");
	form("<script runat=\"server\">int a = 1;</script>", "<script runat=\"server\">int a=1;\n</script>");
	/* comments go, a trailing one too, blank lines collapse */
	form("<%\n  a = 1; // c\n\n\n  b = 2; /* d */\n%>", "<%\na=1;\nb=2;\n%>");
	/* a lone brace joins the line above */
	form("<% if (a)\n{\n b(); } %>", "<%if (a){\nb();}\n%>");
	/* the pairs closing up would glue; "<% @x" would become a directive; "% >" would end the island */
	form("<% a = b + +c; x = y - -z; %>", "<%a=b+ +c;x=y- -z;\n%>");
	form("<% a < > b %>", "<%a< >b\n%>");
	form("<% a % > b %>", "<%a% >b\n%>");
	form("<% @x %>", "<% @x\n%>");
	form("<% x = 1 .ToString(); %>", "<%x=1 .ToString();\n%>");
	/* vb.net's rules: "+ _" must not become the name "+_", "a & h1" must not become the literal "&h1" */
	form("<%@ Page Language=\"VB\" %><% x = a & h1 %>", "<%@ Page Language=\"VB\" %><%x=a& h1\n%>");
	form("<%@ Page Language=\"VB\" %><% x = 1 + _\n\n 2 %>", "<%@ Page Language=\"VB\" %><%x=1+ _\n\n2\n%>");
	/* strings and markup as typed; directives too; the raw string and the verbatim one */
	form("<%@ Page Language = \"C#\" %> <b  class=\"a\">\n\n<% x = @\"a  \"\"b\"; %>", "<%@ Page Language = \"C#\" %> <b  class=\"a\">\n\n<%x=@\"a  \"\"b\";\n%>");
	form("<% s = \"\"\"a  \" b\"\"\"; %>", "<%s=\"\"\"a  \" b\"\"\";\n%>");
	/* the text of #region is kept, spacing and all, since it is code to the lexer: only its white space collapses */
	form("<%\n#region a'b\n x(); %>", "<%\n#region a'b\nx();\n%>");
	/* c#'s \x takes 1 to 4 hex digits and it has no octal: the form does not rewrite either */
	form("<% s = \"\\x41b\\101\"; %>", "<%s=\"\\x41b\\101\";\n%>");
	/* a literal that runs to the end of the island is not given a line break: it would be inside it */
	form("<% s = @\"a\nb %>", "<%s=@\"a\nb %>");
	form("<% x /* c %>", "<%x/* c %>");
	form("<% s = \"\"\"a\nb %>", "<%s=\"\"\"a\nb %>");
	/* "@" and a quote closed up would open a verbatim string */
	form("<% e @ \"a\" %>", "<%e@ \"a\"\n%>");
	/* an island that held nothing but a #region-less comment goes; a string only is code */
	form("<% \"x\" %>", "<%\"x\"\n%>");
}

static int hook(void *u, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len, const uint8_t **out,
		uint32_t *out_len)
{
	static char buf[16];

	(void)len;
	if (n_chain != 1u || chain[0] != KGENOME_TEXTUAL_DEC_B64 || memcmp(in, "QQ==", 4) != 0)
		return 0;
	memcpy(buf, "decoded", 7);
	*out = (const uint8_t *)buf;
	*out_len = 7;
	++*(int *)u;
	return 1;
}

static uint32_t run_form(const char *src, int *asked, struct kgenome_textual_form_res *rs)
{
	static uint8_t out[1024];
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = ASPX, .out = out,
					       .cap = sizeof out, .decode = hook, .decode_user = asked };

	kgenome_textual_form(&rq, rs);
	out[rs->n_out] = 0;
	return rs->n_out;
}

static void call_chain(void)
{
	struct kgenome_textual_form_res rs;
	int asked = 0;
	static const char *const same[] = {
		"<% x = Convert.FromBase64String(\"QQ==\" + y); %>",             /* the next byte is not ")" or ",": as typed */
		"<% x = Foo.Bar(\"QQ==\"); %>",                                   /* not a decoder */
		"<% x = Convert.FromBase64String(y, \"QQ==\"); %>",               /* not the first argument */
		"<% x = Convert.FromBase64String(\"AAAA\"); %>"                  /* the hook refuses it */
	};
	uint32_t k;

	/* the literal is replaced by the decoded value, the quotes and the call stay */
	run_form("<% x = Encoding.UTF8.GetString(Convert.FromBase64String(\"QQ==\")); %>", &asked, &rs);
	CK(rs.n_decoded == 1 && asked == 1);
	asked = 0;
	run_form("<% x = System.Convert.FromBase64String (\"QQ==\", 0); %>", &asked, &rs);
	CK(rs.n_decoded == 1);
	asked = 0;
	run_form("<%@ Page Language=\"VB\" %><% x = convert.frombase64string(\"QQ==\") %>", &asked, &rs);
	CK(rs.n_decoded == 1);
	for (k = 0; k < sizeof same / sizeof same[0]; k++) {
		asked = 0;
		run_form(same[k], &asked, &rs);
		CK(rs.n_decoded == 0);
	}
	/* the value shows in the output as one double-quoted literal inside the call that decoded it, which is named for it */
	{
		static const char src[] = "<%=Convert.FromBase64String(\"QQ==\")%>";
		static const char want[] = "<%=Convert.decoded_FromBase64String(\"decoded\")\n%>";
		static uint8_t out[256];
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = ASPX, .out = out,
						       .cap = sizeof out, .decode = hook, .decode_user = &asked };

		kgenome_textual_form(&rq, &rs);
		CK(rs.n_out == strlen(want) && memcmp(out, want, rs.n_out) == 0);
	}
}

int main(void)
{
	tags();
	ends();
	csharp();
	directives();
	scripts();
	handlers();
	real_shell_shapes();
	fragments();
	forms();
	call_chain();
	pg_check_lex(ASPX, 1, 20260303u, 6000u);
	pg_check_form(ASPX, 1, 20260404u, 3000u);
	partition_for(ASPX, "<%%>=@-#$:!'\"\\ \n\r{}/*$script runat=server language=vb</>", 21u);
	partition_for(ASPX, "<%--@ Page Language=vb%>'\"\"\" \n</script runat=\"server\">$@{}", 22u);
	form_property_for(ASPX, "<%>=@-#$:!'\"\\ \n{}/*$scriptrunat=sevlg</", 23u);
	form_property_for(ASPX, "<%-@ PageLanguage=vb>'\"\\x41 \n</script runat=server>%{}$", 24u);
	if (fails)
		printf("textual aspx: %d FAILED\n", fails);
	else
		printf("textual aspx: ok\n");
	return fails != 0;
}
