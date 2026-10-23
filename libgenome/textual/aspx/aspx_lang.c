/*
 * aspx_lang.c - the row for asp.net (.aspx, .ascx, .master, and .ashx/.asmx): a page with islands of c# (the
 * default), vb.net or jscript.net.
 *
 * WHAT THE PAGE HOST DECIDES, and what is decided here:
 *  - The page's language is the Language attribute of the first directive that has one (Page, Control, Master,
 *    WebHandler, WebService ...): "C#", "CS", "CSharp" are c#, "VB" and "VisualBasic" vb.net, "JS", "JScript",
 *    "JavaScript" jscript, any case, quoted or bare. With none in any directive, the first
 *    <script runat="server"> that has a language attribute names it. With none at all it is c#: asp.net's
 *    own default is the machine's configuration (vb in a stock one) [Unverified: from memory], and a page
 *    that depends on it would not be a webshell anyone could run on a default server. A name this tree has
 *    no lexer for (J#, C++) is read as c# too.
 *  - <script language="vb" runat="server"> ... </script> is lexed in its own language. asp.net itself
 *    refuses a page that mixes two, so this only matters for a page that does not run.
 *  - "%>" ends an island wherever it stands, in a string or a comment, and "</script>" ends a script
 *    element the same way: neither language reads the code before the page scanner has found both.
 *  - The three byte tags are "<%=", "<%#" (data binding), "<%$" (an expression builder) and "<%:" (html
 *    encoded, .NET 4); "<%!" is not one - in asp.net it is code that begins with "!". <%-- --%> is a
 *    COMMENT, which is how a server comment hides markup and controls; an html comment is not: "<!-- <%
 *    x %> -->" still runs x, and an <asp:Button runat="server"> in one still exists.
 *  - <%@ ... %> is markup. For .ashx and .asmx - <%@ WebHandler Language="C#" Class="X" %> and
 *    <%@ WebService ... %> - the TEXT AFTER THE DIRECTIVE IS THE SOURCE, whole: no "<%" is looked for in it
 *    and nothing is an island; it is lexed as code from the directive's end to the end of the text.
 *  - An island is lexed alone: a comment or a string open at its "%>" is open there.
 *
 * THE ROW.
 *  glue            kgenome_textual_glue_web (the page operators, OR kgenome_textual_vb_glue): the row is per page and the body
 *                  language is not known to it, so a space is kept wherever c#, jscript or vb.net would read the
 *                  closed up bytes differently ("+ _" must not become the name "+_", "a & h1" must not become
 *                  the hex literal "a &h1", a blank line after a continuation must not merge). What it costs:
 *                  vbscript's "a (1)" rule keeps "if (x)" and "if(x)" apart in c#, two forms of one program
 *                  where they could be one; safety of the vb.net island was chosen over that.
 *  join_brace      1: c#. A vb.net island has no lone "{" except after "_" in a collection initialiser, where
 *                  the join is harmless to every pass that reads the form.
 *  unescape_str    NULL: c# has no octal escape and its \x takes ONE TO FOUR hex digits, so "\x41b" is U+041B and
 *                  not "A" and "b": the form's rewrite (two digits at most) would change what the string
 *                  says. vb strings have no escapes, jscript.net's are not worth a second row.
 *  vb_lines        1: vb.net's continuation "_" and lone CR; in c# a "_" alone at the end of a line is a
 *                  name, and the form keeps its break.
 *  call_chain      Convert.FromBase64String("...") and Convert.FromHexString("...") (the same name in vb.net),
 *                  and UrlDecode: the literal IS the value that call decodes, and the name around it says so
 *                  (FromBase64String is the only name read, "Convert." in front of it is not asked). What the
 *                  program then does with the bytes - Encoding.UTF8.GetString(...), a MemoryStream, a
 *                  DeflateStream - is a wrapper this contract cannot express: the chain stops at it, so
 *                  gzip-then-base64 is decoded one layer, which is what the hook is asked for. The names
 *                  are matched in any case because vb.net's are not case sensitive. Not in the table:
 *                  Uri.UnescapeDataString (it does not turn "+" into a space, which the hook's url decoder
 *                  does) and anything that is a method of a variable.
 *  open_tail       1: an island may end inside a verbatim or raw string or a block comment, which run to the
 *                  "%>": the line break the form puts in front of the tag would be part of the literal.
 *  islands         1.
 */

#include "aspx.h"

static const struct kgenome_textual_script_lang langs[] = {
	{ "c#",          KGENOME_TEXTUAL_PAGE_CLIKE, KGENOME_TEXTUAL_CL_VERBATIM },
	{ "cs",          KGENOME_TEXTUAL_PAGE_CLIKE, KGENOME_TEXTUAL_CL_VERBATIM },
	{ "vb",          KGENOME_TEXTUAL_PAGE_VB,    0 },
	{ "visualbasic", KGENOME_TEXTUAL_PAGE_VB,    0 },
	{ "js",          KGENOME_TEXTUAL_PAGE_ECMA,  0 },
	{ "javascript",  KGENOME_TEXTUAL_PAGE_ECMA,  0 },
};

static const struct kgenome_textual_page page = {
	.langs = langs,
	.n_langs = sizeof langs / sizeof langs[0],
	.dash_comment = 1,
	.server_script = 1,
	.lang_from_script = 1,
	.fragment_code = 1,
	.directive_code = 1,
	.tag3 = "=#$:",
};

/* vb.net's names are not case sensitive: the match folds (textual_anchor.c's rows are lower case, for that). */
static const struct kgenome_textual_call_style style = {
	.rows = kgenome_textual_dotnet_decoders, .n_rows = KGENOME_TEXTUAL_DOTNET_PAGE, .fold = 1,
	.receiver = 1,
};

/* The island may be c# or vb.net (the language attribute, which the writer is not told): a literal that both read the same way - no quote, no
 * backslash, no control byte - and that cannot end the island or the script element. */
static const struct kgenome_textual_quote quote = { .q = '"', .refuse = "\\\"", .refuse_ctl = 1, .seq = KGENOME_TEXTUAL_PAGE_SEQ };

const struct kgenome_textual_lang kgenome_textual_lang_aspx = {
	.name = "aspx",
	.id = KGENOME_TEXTUAL_LANG_ASPX,
	.gap_comments = KGENOME_TEXTUAL_GAP_LINE | KGENOME_TEXTUAL_GAP_BLOCK,
	.page = &page,
	.glue = kgenome_textual_glue_web,
	.join_brace = 1,
	.vb_lines = 1,
	.islands = 1,
	.open_tail = 1,
	.calls = &style,
	.value = kgenome_textual_aspx_value,
	.concat = '+',
	.quote = &quote,
};
