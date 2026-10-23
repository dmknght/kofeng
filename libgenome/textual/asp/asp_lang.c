/*
 * asp_lang.c - the row for classic asp: a page with islands of vbscript (the default) or jscript.
 *
 * WHAT THE PAGE HOST DECIDES, and what is decided here:
 *  - The page's language is the first directive's Language attribute: <%@ LANGUAGE="JScript" %> and
 *    "JavaScript" and "ECMAScript" are jscript, any case, quoted or bare, "JScript.Encode" too (the name is
 *    matched by its beginning). Anything else, a page with no directive, and a name of an engine this tree
 *    has no lexer for (PerlScript) is read as vbscript, which is what IIS runs when nothing says otherwise.
 *  - <script language="..." runat="server"> ... </script> is an island of its own language, whatever the
 *    page's: a classic asp page may mix them. Without a language attribute it is the page's. A script
 *    element without runat is the browser's and is markup; a "<%" in it is an island all the same.
 *  - "%>" ends an island wherever it stands, in a string or a comment, and "</script>" ends a script
 *    element the same way (the page scanner finds both before any language reads the code); "%\>" does not,
 *    which is how a script writes the two bytes. [Inference] for "%\>": from the documentation of asp's
 *    script delimiters, not checked against IIS.
 *  - "<%= expr %>" is the one three byte tag: in classic asp "<%#" and "<%$" are code that begins with
 *    "#" (a date literal in vbscript) or "$". <%-- --%> is NOT a comment in classic asp: it is code.
 *  - <%@ ... %> is markup (the page's own), <!--#include file="x.asp"--> is markup, and so is an html
 *    comment: "<!-- <% x %> -->" still runs x, the server does not read html, so it is an island inside a
 *    markup span.
 *  - An island is lexed alone: a string or a comment that is open at its "%>" is open there, and the next
 *    island starts fresh (a statement can begin: "Rem" is a comment at the start of one).
 *
 * THE ROW.
 *  glue            the union of vbscript's, jscript's and c#'s operator pairs (kgenome_textual_glue_web) and
 *                  vbscript's own rules (kgenome_textual_vb_glue: "a (1)" is kept apart, "x _" too): the
 *                  row is per page and the body language is not known to it, so a space is kept wherever
 *                  any of them would read the closed up bytes differently. What that costs: "foo (x)" and
 *                  "foo(x)" are two forms in a jscript island, as they are in vbscript's.
 *  join_brace      0: the default island is vbscript, which has no brace; a jscript island's lone "{" stays
 *                  on its own line.
 *  unescape_str    php's hook: a vbscript string is never flagged as one with escapes (it has none), so the form only
 *                  touches jscript's, whose \xHH takes two digits and whose octal \101 is the legacy form.
 *  vb_lines        1: the continuation "_" and a lone CR are vbscript's line rules; in a jscript island "_"
 *                  as a whole word at the end of a line is a name and the form keeps its break, which is
 *                  what it would do anyway.
 *  call_chain      NULL, deliberately. VBScript has no function that decodes a literal (see vbs_lang.c);
 *                  JScript has unescape(), but it is the same word in a vbscript island, which would then
 *                  claim a decoder that language does not have; a name of the js row is not copied here.
 *  open_tail       1: a jscript island may end inside a block comment, and the line break the form puts in front of
 *                  "%>" would be part of it. (vbscript's open string ends at its line, where it is harmless.)
 *  islands         1.
 */

#include "asp.h"
#include "../php/php.h"

static const struct kgenome_textual_script_lang langs[] = {
	{ "vbscript",   KGENOME_TEXTUAL_PAGE_VB,   0 },
	{ "jscript",    KGENOME_TEXTUAL_PAGE_ECMA, 0 },
	{ "javascript", KGENOME_TEXTUAL_PAGE_ECMA, 0 },
	{ "ecmascript", KGENOME_TEXTUAL_PAGE_ECMA, 0 },
};

static const struct kgenome_textual_page page = {
	.langs = langs,
	.n_langs = sizeof langs / sizeof langs[0],
	.server_script = 1,
	.fragment_code = 1,
	.tag3 = "=",
};

/* The island may be vbscript or jscript (the language attribute, which the writer is not told): a literal that both read the same way - no quote,
 * no backslash, no control byte - and that cannot end the island or the script element. */
static const struct kgenome_textual_quote quote = { .q = '"', .refuse = "\\\"", .refuse_ctl = 1, .seq = KGENOME_TEXTUAL_PAGE_SEQ };

const struct kgenome_textual_lang kgenome_textual_lang_asp = {
	.name = "asp",
	.id = KGENOME_TEXTUAL_LANG_ASP,
	.gap_comments = KGENOME_TEXTUAL_GAP_LINE | KGENOME_TEXTUAL_GAP_BLOCK,
	.page = &page,
	.glue = kgenome_textual_glue_web,
	.vb_lines = 1,
	.islands = 1,
	.open_tail = 1,
	.unescape_str = kgenome_textual_php_unescape,
	.quote = &quote,
};
