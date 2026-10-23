/*
 * genome / textual_cfm - the coldfusion lexer of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED. (a) KNOWN ANSWERS: a text and the one span line it must come out as (kind letter and the bytes in
 * braces; S* = the string interpolates/escapes, ! = not closed). Every rule is paired with the neighbour it could be
 * confused for: "<cf>" and "<cfx>", "#" inside an output tag and outside, "#" with a partner and without, a quote doubled
 * and a quote that ends, "//" in markup, in a tag and in cfscript, "<!---" and "<!--", a script component and the word
 * "component" in prose, "</cfscript>" and "</cfscripts>".
 * (b) A GENERATOR (textual_cfm_gen.h) builds pages and script components from pieces whose class is known when they
 * are written, and the expected spans are the generator's, never the lexer's. THE GENERATOR AND THE LEXER ARE BY ONE
 * AUTHOR, so (b) catches inconsistency and slips, not a shared misreading of CFML [Unverified: there is no ColdFusion
 * engine on this machine, so every rule in (a) is the documented one, not an observed one]: the three real files of the
 * corpus were read in scratch.
 * (c) The partition and the idempotence of the form on random text (characters and tokens) and on the generated pages,
 * where a form must also leave every string, every markup run and every tag byte for byte. (d) Form known answers and the
 * decoder hook. (e) The value of a literal. (f) Hostile input: deep nesting, a huge unclosed literal, NUL bytes, the
 * three line endings, and work that must stay linear.
 */

#include <time.h>

#include "textual_cfm_gen.h"

#define C KGENOME_TEXTUAL_LANG_CFM

static void cf(const char *src, const char *want)
{
	expect_lang(C, src, want);
}

static void cform(const char *src, const char *want)
{
	form_lang(C, src, want);
}

/* ---- (a) the page ---------------------------------------------------------------------------- */

static void tags(void)
{
	cf("", "");
	cf("<b>x</b>", "M{<b>x</b>}");
	cf("<cfset x = 1>", "T{<cfset}C{ x = 1}T{>}");
	cf("a<cfset x = 1>b", "M{a}T{<cfset}C{ x = 1}T{>}M{b}");
	cf("<cfset x = 1 />", "T{<cfset}C{ x = 1 }T{/>}");
	/* a tag with nothing in it is one TAG, however it ends; with a blank in it, a head, the blank and the end */
	cf("<cfelse>", "T{<cfelse>}");
	cf("</cfif>", "T{</cfif>}");
	cf("<cfabort/>", "T{<cfabort/>}");
	cf("<cfabort />", "T{<cfabort}C{ }T{/>}");
	cf("<cfabort\n>", "T{<cfabort}C{\n}T{>}");
	cf("<cfabort/ >", "T{<cfabort/ >}");
	cf("</cfif >", "T{</cfif}C{ }T{>}");
	/* names are case-insensitive; "cf" and a letter or "_" make a tag, anything else is text */
	cf("<CFSET x=1>", "T{<CFSET}C{ x=1}T{>}");
	cf("<CfIf a>", "T{<CfIf}C{ a}T{>}");
	cf("<cf_mytag a=1>", "T{<cf_mytag}C{ a=1}T{>}");
	cf("<cfx_name>", "T{<cfx_name>}");
	cf("<cf>", "M{<cf>}");
	cf("<cf x>", "M{<cf x>}");
	cf("<cf1>", "M{<cf1>}");
	cf("a <cf b", "M{a <cf b}");
	cf("<c>", "M{<c>}");
	cf("<", "M{<}");
	cf("<c", "M{<c}");
	cf("<cf", "M{<cf}");
	cf("<cfs", "T{<cfs}");
	cf("</", "M{</}");
	/* a tag that never closes runs to the end of the text */
	cf("<cfset x = 1", "T{<cfset}C{ x = 1}");
	cf("<cfset", "T{<cfset}");
	/* html around it is markup, and so is an html comment: cf tags inside both are tags */
	cf("<!-- a -->", "M{<!-- a -->}");
	cf("<!-- <cfset x=1> -->", "M{<!-- }T{<cfset}C{ x=1}T{>}M{ -->}");
	cf("<input <cfif x>checked</cfif>>", "M{<input }T{<cfif}C{ x}T{>}M{checked}T{</cfif>}M{>}");
	/* "//" is a comment in cfscript and nowhere else; in a tag it is what a value holds */
	cf("see http://x.com/a <cfset a = 1>", "M{see http://x.com/a }T{<cfset}C{ a = 1}T{>}");
	cf("<cfhttp url=http://x.com//y>", "T{<cfhttp}C{ url=http://x.com//y}T{>}");
	cf("<cfset a = 1 /* c */ b >", "T{<cfset}C{ a = 1 /* c */ b }T{>}");
	/* ... and so a "/" that stands against the ">" is the tag's end, whatever is in front of it */
	cf("<cfset a = 1 /* c */>", "T{<cfset}C{ a = 1 /* c *}T{/>}");
	cf("<cfset a = 1 /* c */ >", "T{<cfset}C{ a = 1 /* c *}T{/ >}");
	cf("<cfset a = b / c>", "T{<cfset}C{ a = b / c}T{>}");
	/* the first ">" outside a string ends the tag */
	cf("<cfif a > b>", "T{<cfif}C{ a }T{>}M{ b>}");
}

static void strings(void)
{
	/* a quote is written twice; the other quote is a character; no backslash escape */
	cf("<cfset x = \"a\"\"b\">", "T{<cfset}C{ x = }S*{\"a\"\"b\"}T{>}");
	cf("<cfset x = 'it''s'>", "T{<cfset}C{ x = }S*{'it''s'}T{>}");
	cf("<cfset x = \"it's\">", "T{<cfset}C{ x = }S*{\"it's\"}T{>}");
	cf("<cfset x = 'say \"hi\"'>", "T{<cfset}C{ x = }S*{'say \"hi\"'}T{>}");
	cf("<cfset x = \"C:\\dir\\\">", "T{<cfset}C{ x = }S*{\"C:\\dir\\\"}T{>}");
	cf("<cfset x = \"\">", "T{<cfset}C{ x = }S*{\"\"}T{>}");
	cf("<cfset x = \"\"\"\">", "T{<cfset}C{ x = }S*{\"\"\"\"}T{>}");
	cf("<cfset x = \"\" & \"\">", "T{<cfset}C{ x = }S*{\"\"}C{ & }S*{\"\"}T{>}");
	/* a ">" in a string does not end the tag; a string runs over lines */
	cf("<cfset x = \">\">", "T{<cfset}C{ x = }S*{\">\"}T{>}");
	cf("<cfexecute arguments=\"/c dir > out.txt\">", "T{<cfexecute}C{ arguments=}S*{\"/c dir > out.txt\"}T{>}");
	cf("<cfset x = \"a\nb\">", "T{<cfset}C{ x = }S*{\"a\nb\"}T{>}");
	cf("<cfset x = \"a\r\nb\">", "T{<cfset}C{ x = }S*{\"a\r\nb\"}T{>}");
	/* not closed: it ends at the end of the text, which is where the tag ends too */
	cf("<cfset x = \"abc>", "T{<cfset}C{ x = }S*!{\"abc>}");
	cf("<cfset x = \"abc\"\">", "T{<cfset}C{ x = }S*!{\"abc\"\">}");
	cf("<cfset x = '", "T{<cfset}C{ x = }S*!{'}");
	/* "#expr#" in a string: a nested string of the SAME quote does not end it (shell.cfm) */
	cf("<cfset x = \"a#b#c\">", "T{<cfset}C{ x = }S*{\"a#b#c\"}T{>}");
	cf("<cfset x = \"#f(\"a\")#\">", "T{<cfset}C{ x = }S*{\"#f(\"a\")#\"}T{>}");
	cf("<cfset x = \"#f(\"a\" & \"b\")#\" & 'c'>", "T{<cfset}C{ x = }S*{\"#f(\"a\" & \"b\")#\"}C{ & }S*{'c'}T{>}");
	cf("<cfset x = \"#f(\"#g(\"z\")#\")#\">", "T{<cfset}C{ x = }S*{\"#f(\"#g(\"z\")#\")#\"}T{>}");
	cf("<cfset x = \"#f(\">\")#\">", "T{<cfset}C{ x = }S*{\"#f(\">\")#\"}T{>}");
	cf("<cfset x = \"#a > b#\">", "T{<cfset}C{ x = }S*{\"#a > b#\"}T{>}");
	/* "##" is a "#" */
	cf("<cfset x = \"##\">", "T{<cfset}C{ x = }S*{\"##\"}T{>}");
	cf("<cfset x = \"a##b\">", "T{<cfset}C{ x = }S*{\"a##b\"}T{>}");
	cf("<cfset x = \"###a#\">", "T{<cfset}C{ x = }S*{\"###a#\"}T{>}");
	/* a "#" with no partner is an error in CFML. What this lexer does: the expression is not read (the memo is set), the
	 * string is read as text from then on, so the quote ends it and no byte is lost */
	cf("<cfset x = \"#\">", "T{<cfset}C{ x = }S*{\"#\"}T{>}");
	cf("<cfset x = \"a#b\"> <cfset y = \"c\">", "T{<cfset}C{ x = }S*{\"a#b\"}T{>}M{ }T{<cfset}C{ y = }S*{\"c\"}T{>}");
	/* a "#" whose partner is far away is read as having it: the expression is `"><cfset y = "` (CFML would say the same
	 * or call it an error; either way the bytes are in the string and no tag is made of them) */
	cf("<cfset x = \"#\"><cfset y = \"#f(\">\")#\">", "T{<cfset}C{ x = }S*{\"#\"><cfset y = \"#f(\"}T{>}M{\")#\">}");
	/* the memo is the whole text's: after one failure (here: a nested string that runs to the end) no string
	 * interpolates, so the second tag's string ends at the quote it shows */
	cf("<cfset x = \"#f('a)#\"><cfset y = \"#g(\"z\")#\">",
	   "T{<cfset}C{ x = }S*{\"#f('a)#\"}T{>}T{<cfset}C{ y = }S*{\"#g(\"}C{z}S*{\")#\"}T{>}");
	/* an unclosed expression in a nested string fails the outer string too, and the text is read again without it */
	cf("<cfset x = \"#f(\"a)#\">", "T{<cfset}C{ x = }S*{\"#f(\"}C{a)#}S*!{\">}");
}

static void hashes(void)
{
	/* in a tag outside a string: its ">" is not the tag's end, its strings are strings */
	cf("<cfif #a > b# eq 1>", "T{<cfif}C{ #a > b# eq 1}T{>}");
	cf("<cfif #f(\">\")# eq 1>", "T{<cfif}C{ #f(}S*{\">\"}C{)# eq 1}T{>}");
	cf("<cfif ( #suppliedCode# neq secretCode )>", "T{<cfif}C{ ( #suppliedCode# neq secretCode )}T{>}");
	cf("<cfset x = ##>", "T{<cfset}C{ x = ##}T{>}");
	/* with no partner it is a character, and the tag ends where it does */
	cf("<cfif a eq #>", "T{<cfif}C{ a eq #}T{>}");

	/* in output text: only inside cfoutput, cfquery and cfmail; "#" is a TAG, the expression is code */
	cf("<cfoutput>#x#</cfoutput>", "T{<cfoutput>}T{#}C{x}T{#}T{</cfoutput>}");
	cf("#x#", "M{#x#}");
	cf("<a href=\"#top\">", "M{<a href=\"#top\">}");
	cf("<cfoutput>a ##b## c</cfoutput>", "T{<cfoutput>}M{a ##b## c}T{</cfoutput>}");
	cf("<cfoutput>#x#</cfoutput>#x#", "T{<cfoutput>}T{#}C{x}T{#}T{</cfoutput>}M{#x#}");
	cf("<cfoutput query=\"q\">#x#</cfoutput>", "T{<cfoutput}C{ query=}S*{\"q\"}T{>}T{#}C{x}T{#}T{</cfoutput>}");
	cf("<cfquery name=\"q\">select '#x#'</cfquery>",
	   "T{<cfquery}C{ name=}S*{\"q\"}T{>}M{select '}T{#}C{x}T{#}M{'}T{</cfquery>}");
	cf("<cfmail to=\"a\">#x#</cfmail>", "T{<cfmail}C{ to=}S*{\"a\"}T{>}T{#}C{x}T{#}T{</cfmail>}");
	cf("<CFOUTPUT>#x#</CFOUTPUT>", "T{<CFOUTPUT>}T{#}C{x}T{#}T{</CFOUTPUT>}");
	cf("<cfoutput><cfoutput>#a#</cfoutput>#b#</cfoutput>#c#",
	   "T{<cfoutput>}T{<cfoutput>}T{#}C{a}T{#}T{</cfoutput>}T{#}C{b}T{#}T{</cfoutput>}M{#c#}");
	/* a self-closing output tag has no text, a stray end tag does not go below zero */
	cf("<cfoutput/>#x#", "T{<cfoutput/>}M{#x#}");
	cf("</cfoutput></cfoutput><cfoutput>#x#</cfoutput>", "T{</cfoutput>}T{</cfoutput>}T{<cfoutput>}T{#}C{x}T{#}T{</cfoutput>}");
	cf("<cfset x = 1><cfoutput>#a#</cfoutput>", "T{<cfset}C{ x = 1}T{>}T{<cfoutput>}T{#}C{a}T{#}T{</cfoutput>}");
	/* strings in the expression, a ">" in it, a comparison */
	cf("<cfoutput>#f(\"a>b\")#</cfoutput>", "T{<cfoutput>}T{#}C{f(}S*{\"a>b\"}C{)}T{#}T{</cfoutput>}");
	cf("<cfoutput>#a < b#</cfoutput>", "T{<cfoutput>}T{#}C{a < b}T{#}T{</cfoutput>}");
	cf("<cfoutput>#Replace(foo, \"<\", \"&lt;\", \"All\")#</cfoutput>",
	   "T{<cfoutput>}T{#}C{Replace(foo, }S*{\"<\"}C{, }S*{\"&lt;\"}C{, }S*{\"All\"}C{)}T{#}T{</cfoutput>}");
	/* a tag inside a string of an expression is not a tag [Unverified: CF's tag scanner may read it]; outside a
	 * string a tag ends the expression - "#" with no partner is text, and the tag is a tag */
	cf("<cfoutput>#f(\"<cfset x>\")#</cfoutput>", "T{<cfoutput>}T{#}C{f(}S*{\"<cfset x>\"}C{)}T{#}T{</cfoutput>}");
	cf("<cfoutput>#a <cfset x=1> b#</cfoutput>", "T{<cfoutput>}M{#a }T{<cfset}C{ x=1}T{>}M{ b#}T{</cfoutput>}");
	/* a comment in the expression is a gap in it; a body of nothing but comments and blanks is no expression */
	cf("<cfoutput>#a <!--- c ---> b#</cfoutput>", "T{<cfoutput>}T{#}C{a }K{<!--- c --->}C{ b}T{#}T{</cfoutput>}");
	cf("<cfoutput>#<!--- c --->#</cfoutput>", "T{<cfoutput>}M{#}K{<!--- c --->}M{#}T{</cfoutput>}");
	cf("<cfoutput># #</cfoutput>", "T{<cfoutput>}M{# #}T{</cfoutput>}");
	cf("<cfoutput>#a <!--- c</cfoutput>", "T{<cfoutput>}M{#a }K!{<!--- c</cfoutput>}");
	cf("<cfif #a <!--- > ---> b# eq 1>", "T{<cfif}C{ #a }K{<!--- > --->}C{ b# eq 1}T{>}");
	/* the memo: after one "#" that found no partner, "#" in markup is text for the rest of the text */
	cf("<cfoutput>a # b</cfoutput><cfoutput>#x#</cfoutput>",
	   "T{<cfoutput>}M{a # b}T{</cfoutput>}T{<cfoutput>}M{#x#}T{</cfoutput>}");
	cf("<cfoutput>#", "T{<cfoutput>}M{#}");
	cf("<cfoutput>#x", "T{<cfoutput>}M{#x}");
}

static void comments(void)
{
	cf("<!--- a --->", "K{<!--- a --->}");
	cf("a<!--- c --->b", "M{a}K{<!--- c --->}M{b}");
	/* they nest */
	cf("<!--- a <!--- b ---> c --->x", "K{<!--- a <!--- b ---> c --->}M{x}");
	cf("<!--- a <!--- b ---> c", "K!{<!--- a <!--- b ---> c}");
	cf("<!------>", "K{<!------>}");
	cf("<!--- a ---->", "K{<!--- a ---->}");
	/* not closed */
	cf("<!--- a", "K!{<!--- a}");
	cf("<!---", "K!{<!---}");
	cf("<!--->", "K!{<!--->}");
	cf("<!---->", "K!{<!---->}");
	/* an html comment is markup; "<!--" with two dashes is not a cf comment */
	cf("<!-- a --->", "M{<!-- a --->}");
	cf("<!--", "M{<!--}");
	cf("<!-- a --- > <cfset x=1>", "M{<!-- a --- > }T{<cfset}C{ x=1}T{>}");
	/* one that holds tags, quotes and a "#" */
	cf("<!--- <cfset x = \"> # ---><cfset y=1>", "K{<!--- <cfset x = \"> # --->}T{<cfset}C{ y=1}T{>}");
	/* in a tag */
	cf("<cfset x = 1 <!--- c ---> >", "T{<cfset}C{ x = 1 }K{<!--- c --->}C{ }T{>}");
	cf("<cfset x = 1 <!--- > ---> >", "T{<cfset}C{ x = 1 }K{<!--- > --->}C{ }T{>}");
	cf("<cfset x = \"<!--- \" >", "T{<cfset}C{ x = }S*{\"<!--- \"}C{ }T{>}");
	cf("<cfset x = 1 <!--- c", "T{<cfset}C{ x = 1 }K!{<!--- c}");
	/* the head of a file, as in the corpus */
	cf("<!---\n/* ** */\n--->\n<cfapplication a=\"b\">", "K{<!---\n/* ** */\n--->}M{\n}T{<cfapplication}C{ a=}S*{\"b\"}T{>}");
}

static void scripts(void)
{
	cf("<cfscript>x = 1;</cfscript>", "T{<cfscript>}C{x = 1;}T{</cfscript>}");
	cf("<cfscript>x = 1; // c\n/* d */ s = \"a\"\"b\";</cfscript>",
	   "T{<cfscript>}C{x = 1; }K{// c}C{\n}K{/* d */}C{ s = }S*{\"a\"\"b\"}C{;}T{</cfscript>}");
	cf("<CFSCRIPT>a</CFSCRIPT>b", "T{<CFSCRIPT>}C{a}T{</CFSCRIPT>}M{b}");
	cf("<cfscript >a</cfscript >", "T{<cfscript}C{ }T{>}C{a}T{</cfscript >}");
	cf("<cfscript>a</cfscript\n>b", "T{<cfscript>}C{a}T{</cfscript\n>}M{b}");
	cf("<cfscript/>x", "T{<cfscript/>}M{x}");
	cf("<cfscript></cfscript>", "T{<cfscript>}T{</cfscript>}");
	/* the end tag is the first one there is: in a string, in a comment, and "</cfscripts>" is not it */
	cf("<cfscript>s = \"</cfscript>x</cfscript>", "T{<cfscript>}C{s = }S*!{\"}T{</cfscript>}M{x}T{</cfscript>}");
	cf("<cfscript>a /* </cfscript> */ b", "T{<cfscript>}C{a }K!{/* }T{</cfscript>}M{ */ b}");
	cf("<cfscript>a // </cfscript>b", "T{<cfscript>}C{a }K{// }T{</cfscript>}M{b}");
	cf("<cfscript>a</cfscripts>b</cfscript>", "T{<cfscript>}C{a</cfscripts>b}T{</cfscript>}");
	cf("<cfscript>a</cfscript", "T{<cfscript>}C{a</cfscript}");
	/* not closed: the script runs to the end of the text */
	cf("<cfscript>x = 1;", "T{<cfscript>}C{x = 1;}");
	cf("<cfscript>", "T{<cfscript>}");
	cf("<cfscript>/* a", "T{<cfscript>}K!{/* a}");
	cf("<cfscript>/* a</cfscript>x", "T{<cfscript>}K!{/* a}T{</cfscript>}M{x}");
	cf("<cfscript>s = \"a</cfscript>x", "T{<cfscript>}C{s = }S*!{\"a}T{</cfscript>}M{x}");
	/* comments of cfscript: a line ends at LF, CR or CRLF; a block comment does not nest; slash-star-slash is not whole. */
	cf("<cfscript>a // c\r\nb</cfscript>", "T{<cfscript>}C{a }K{// c}C{\r\nb}T{</cfscript>}");
	cf("<cfscript>a // c\rb</cfscript>", "T{<cfscript>}C{a }K{// c}C{\rb}T{</cfscript>}");
	cf("<cfscript>/* a /* b */ c */</cfscript>", "T{<cfscript>}K{/* a /* b */}C{ c */}T{</cfscript>}");
	cf("<cfscript>/*/ a</cfscript>", "T{<cfscript>}K!{/*/ a}T{</cfscript>}");
	cf("<cfscript>a / b</cfscript>", "T{<cfscript>}C{a / b}T{</cfscript>}");
	/* strings: doubled quotes, "#", no backslash escape */
	cf("<cfscript>a = 'x''y'; b = \"\\\";</cfscript>", "T{<cfscript>}C{a = }S*{'x''y'}C{; b = }S*{\"\\\"}C{;}T{</cfscript>}");
	cf("<cfscript>x = \"#f(\"a\")#\";</cfscript>", "T{<cfscript>}C{x = }S*{\"#f(\"a\")#\"}C{;}T{</cfscript>}");
	/* "#" outside a string is code; a cf comment is code in script (the script does not know it) */
	cf("<cfscript>x = #y#;</cfscript>", "T{<cfscript>}C{x = #y#;}T{</cfscript>}");
	cf("<cfscript><!--- x ---></cfscript>", "T{<cfscript>}C{<!--- x --->}T{</cfscript>}");
	/* markup after the block, and a second block */
	cf("<cfscript>a</cfscript> t <cfscript>b</cfscript>", "T{<cfscript>}C{a}T{</cfscript>}M{ t }T{<cfscript>}C{b}T{</cfscript>}");
}

static void components(void)
{
	/* the whole text is script: a text that begins with `component` and then a brace or an attribute */
	cf("component {}", "C{component {}}");
	cf("component\n{ x = 1; }", "C{component\n{ x = 1; }}");
	cf("component extends=\"a\" { x = 1; }", "C{component extends=}S*{\"a\"}C{ { x = 1; }}");
	cf("component accessors = true {", "C{component accessors = true {}");
	cf("/** doc */ component {", "K{/** doc */}C{ component {}");
	cf("// c\ncomponent {", "K{// c}C{\ncomponent {}");
	cf("COMPONENT {", "C{COMPONENT {}");
	cf("interface {", "C{interface {}");
	cf("\xEF\xBB\xBF" "component {", "C{\xEF\xBB\xBF" "component {}");
	cf("component { s = \"<cfset x>\"; // c </cfscript>\n}", "C{component { s = }S*{\"<cfset x>\"}C{; }K{// c </cfscript>}C{\n}}");
	cf("component { a </cfscript> b }", "C{component { a </cfscript> b }}");
	cf("component { <cfset x = 1> }", "C{component { <cfset x = 1> }}");
	/* "component" in prose, or a name that goes on, is markup; the tag form is a page */
	cf("component is nice", "M{component is nice}");
	cf("component", "M{component}");
	cf("components {", "M{components {}");
	cf("component of x = 1", "M{component of x = 1}");
	cf("a component {", "M{a component {}");
	cf("<cfcomponent a=\"b\"></cfcomponent>", "T{<cfcomponent}C{ a=}S*{\"b\"}T{>}T{</cfcomponent>}");
	cf("<!--- c --->\n<cfcomponent>", "K{<!--- c --->}M{\n}T{<cfcomponent>}");
}

/* A text lexed as a fragment: code from its first byte, the script's. */
static void frag(const char *src, const char *want)
{
	static struct rend r;
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = C,
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
	frag("x = \"a#b#\"; // c", "C{x = }S*{\"a#b#\"}C{; }K{// c}");
	frag("<b> <cfset x = 1>", "C{<b> <cfset x = 1>}");
	frag("a /* b */ c", "C{a }K{/* b */}C{ c}");
	frag("s = 'it''s", "C{s = }S*!{'it''s}");
	frag("", "");
}

/* ---- the spans as a list, for what the one-line form does not show (the close flag, NUL bytes) -------- */

struct got {
	struct gsp sp[4096];
	uint32_t n, next;
	int      broken;
};

static int got_sink(void *u, const struct kgenome_textual_span *s)
{
	struct got *g = u;

	if (s->off != g->next || !s->len)
		g->broken = 1;
	g->next = s->off + s->len;
	if (g->n < GN(g->sp))
		g->sp[g->n++] = (struct gsp){ s->off, s->len, s->open_len, s->close_len, s->kind, s->flags };
	return 1;
}

static void spans_of(struct got *g, const uint8_t *in, uint32_t n, uint32_t flags)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = C, .flags = flags, .sink = got_sink, .user = g };
	struct kgenome_textual_lex_res rs;

	memset(g, 0, sizeof *g);
	kgenome_textual_lex(&rq, &rs);
	if (g->next != n)
		g->broken = 1;
}

static void close_flag(void)
{
	static struct got g;
	const char *t = "<cfscript>a</cfscript><cfif x></cfif>";

	spans_of(&g, (const uint8_t *)t, (uint32_t)strlen(t), 0);
	CK(!g.broken && g.n == 7u);
	/* only the end tag of a script leaves the language: F_CLOSE, and no other tag has it */
	CK(g.sp[2].kind == KGENOME_TEXTUAL_TAG && (g.sp[2].flags & KGENOME_TEXTUAL_F_CLOSE));
	CK(!(g.sp[0].flags & KGENOME_TEXTUAL_F_CLOSE) && !(g.sp[3].flags & KGENOME_TEXTUAL_F_CLOSE) &&
	   !(g.sp[5].flags & KGENOME_TEXTUAL_F_CLOSE) && !(g.sp[6].flags & KGENOME_TEXTUAL_F_CLOSE));
	/* delimiters: a string is 1 and 1, a cf comment 5 and 4, a script comment 2 and 0 or 2 and 2 */
	t = "<cfset x = \"a\" <!--- c --->>";
	spans_of(&g, (const uint8_t *)t, (uint32_t)strlen(t), 0);
	CK(g.sp[2].kind == KGENOME_TEXTUAL_STRING && g.sp[2].open == 1u && g.sp[2].close == 1u);
	CK(g.sp[4].kind == KGENOME_TEXTUAL_COMMENT && g.sp[4].open == 5u && g.sp[4].close == 4u);
	t = "<cfscript>// a\n/* b */ /* c</cfscript>";
	spans_of(&g, (const uint8_t *)t, (uint32_t)strlen(t), 0);
	CK(g.sp[1].open == 2u && g.sp[1].close == 0u && g.sp[3].open == 2u && g.sp[3].close == 2u &&
	   g.sp[5].open == 2u && g.sp[5].close == 0u && (g.sp[5].flags & KGENOME_TEXTUAL_F_OPEN));
}

static void line_endings(void)
{
	static struct got g;
	static const char *const eol[] = { "\n", "\r\n", "\r" };
	uint32_t k;

	/* the three endings in markup, in a tag, in a string, in a cf comment, in cfscript: the partition holds and a
	 * script line comment ends at each */
	for (k = 0; k < 3u; k++) {
		char t[256];

		snprintf(t, sizeof t, "a%s<cfset%sx = \"p%sq\"%s>%s<!--- c%s--->%s<cfscript>// c%sd</cfscript>", eol[k], eol[k], eol[k],
			 eol[k], eol[k], eol[k], eol[k], eol[k]);
		spans_of(&g, (const uint8_t *)t, (uint32_t)strlen(t), 0);
		CK(!g.broken);
	}
	{
		const char *t = "<cfscript>// c\rd</cfscript>";

		spans_of(&g, (const uint8_t *)t, (uint32_t)strlen(t), 0);
		CK(g.sp[1].kind == KGENOME_TEXTUAL_COMMENT && g.sp[1].len == 4u && g.sp[2].kind == KGENOME_TEXTUAL_CODE);
	}
}

static void nul_bytes(void)
{
	static struct got g;
	static const uint8_t t[] = "<cfset x = \"a\0b\" \0 y>\0<cfscript>/*\0*/ \"\0\"</cfscript>\0#\0<!---\0--->";

	spans_of(&g, t, (uint32_t)sizeof t - 1u, 0);
	CK(!g.broken);
	/* a NUL is a byte like any: the string holds it, the comment holds it, the tag goes on past it */
	CK(g.n > 6u && g.sp[2].kind == KGENOME_TEXTUAL_STRING && g.sp[2].len == 5u);
	spans_of(&g, t, (uint32_t)sizeof t - 1u, KGENOME_TEXTUAL_FRAGMENT);
	CK(!g.broken);
}

/* ---- (b) the generator --------------------------------------------------------------------------- */

static int same_spans(const struct got *g, const uint8_t *page, uint32_t n)
{
	uint32_t i;

	if (g->broken || g->n != gen_nex || g->next != n)
		return 0;
	for (i = 0; i < g->n; i++) {
		const struct gsp *a = &g->sp[i], *b = &gen_ex[i];

		if (a->off != b->off || a->len != b->len || a->open != b->open || a->close != b->close ||
		    a->kind != b->kind || a->flags != b->flags)
			return 0;
	}
	(void)page;
	return 1;
}

static void show_fail(const char *what, uint32_t seed, const struct got *g)
{
	uint32_t i;
	static const char *const kn[] = { "M", "T", "C", "S", "K" };

	printf("  FAIL %s, seed %u, page of %u bytes:\n    ", what, seed, gen_pn);
	for (i = 0; i < gen_pn; i++)
		printf(gen_pg[i] >= 0x20 && gen_pg[i] < 0x7f ? "%c" : "\\x%02x", gen_pg[i]);
	printf("\n    wanted %u spans:", gen_nex);
	for (i = 0; i < gen_nex && i < 40u; i++)
		printf(" %s%x{%u,%u}", kn[gen_ex[i].kind], gen_ex[i].flags, gen_ex[i].off, gen_ex[i].len);
	printf("\n    got    %u spans:", g->n);
	for (i = 0; i < g->n && i < 40u; i++)
		printf(" %s%x{%u,%u}", kn[g->sp[i].kind], g->sp[i].flags, g->sp[i].off, g->sp[i].len);
	printf("\n");
}

static const uint8_t *find_bytes(const uint8_t *h, uint32_t hn, const uint8_t *nd, uint32_t nn)
{
	uint32_t i;

	for (i = 0; i + nn <= hn; i++)
		if (!memcmp(h + i, nd, nn))
			return h + i;
	return NULL;
}

/* Is every STRING, MARKUP and TAG span of the page in the form, in order and byte for byte (joins kept as typed). */
static int form_keeps(const uint8_t *out, uint32_t w)
{
	uint32_t i, at = 0;

	for (i = 0; i < gen_nex; i++) {
		const struct gsp *s = &gen_ex[i];
		const uint8_t *q;
		uint32_t len = s->len;

		if (s->kind != G_STR && s->kind != G_MUP && s->kind != G_TAG)
			continue;
		/* the form writes a line break after a "</cfscript>" tag's code, not in the tag; "\r\n" in a TAG's end is "\n" */
		if (s->kind == G_TAG && (gen_pg[s->off + len - 1u] == '\r' || gen_pg[s->off + len - 1u] == '\n'))
			continue;
		q = at <= w ? find_bytes(out + at, w - at, gen_pg + s->off, len) : NULL;
		if (!q)
			return 0;
		at = (uint32_t)(q - out) + len;
	}
	return 1;
}

static int form_twice(const uint8_t *in, uint32_t n, uint32_t flags, uint32_t *w1)
{
	static uint8_t o1[4u * GEN_MAX], o2[4u * GEN_MAX];
	struct kgenome_textual_form_req rq = { .in = in, .n = n, .lang = C, .flags = flags, .out = o1,
					       .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st = kgenome_textual_form(&rq, &rs);
	uint32_t w = rs.n_out;

	*w1 = w;
	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || w > KGENOME_TEXTUAL_FORM_CAP(n))
		return 0;
	rq = (struct kgenome_textual_form_req){ .in = o1, .n = w, .lang = C, .flags = flags, .out = o2,
						.cap = KGENOME_TEXTUAL_FORM_CAP(w) };
	st = kgenome_textual_form(&rq, &rs);
	/* the one thing that may differ is a flag the second pass is not given; the text is the same */
	if (rs.n_out != w || memcmp(o1, o2, w))
		return 0;
	memcpy(fbuf2, o1, w < sizeof fbuf2 ? w : sizeof fbuf2);
	return 1;
}

static void generator(void)
{
	static struct got g;
	uint32_t seed, pages = 0, spans = 0, with_open = 0, kinds[5] = { 0 }, i, w;
	uint8_t *saved = malloc(4u * GEN_MAX);

	for (seed = 1; seed <= 6000u; seed++) {
		gen_page(seed * 2654435761u + 7u);
		if (gen_over || !gen_pn)
			continue;
		spans_of(&g, gen_pg, gen_pn, 0);
		if (!same_spans(&g, gen_pg, gen_pn)) {
			show_fail("page", seed, &g);
			fails++;
			break;
		}
		pages++;
		spans += g.n;
		for (i = 0; i < g.n; i++) {
			kinds[g.sp[i].kind]++;
			with_open += (g.sp[i].flags & KGENOME_TEXTUAL_F_OPEN) != 0;
		}
		/* the form: its own form, within the cap, and the program's bytes as typed */
		if (!form_twice(gen_pg, gen_pn, KGENOME_TEXTUAL_KEEP_JOINS, &w)) {
			show_fail("form is not its own form (or is over its cap)", seed, &g);
			fails++;
			break;
		}
		memcpy(saved, fbuf2, w < sizeof fbuf2 ? w : sizeof fbuf2);
		if (w <= sizeof fbuf2 && !form_keeps(fbuf2, w)) {
			show_fail("form changed a string, a tag or markup", seed, &g);
			fails++;
			break;
		}
		/* and the same on the text as a fragment: the script's */
		if (!form_twice(gen_pg, gen_pn, KGENOME_TEXTUAL_FRAGMENT, &w)) {
			show_fail("fragment form is not its own form", seed, &g);
			fails++;
			break;
		}
	}
	free(saved);
	CK(pages > 4000u && kinds[0] > 1000u && kinds[1] > 4000u && kinds[2] > 4000u && kinds[3] > 2000u && kinds[4] > 500u &&
	   with_open > 200u);
	printf("  generator: %u pages, %u spans (markup %u tag %u code %u string %u comment %u), %u open\n", pages, spans,
	       kinds[0], kinds[1], kinds[2], kinds[3], kinds[4], with_open);
}

static void component_generator(void)
{
	static struct got g;
	uint32_t seed, n = 0, w;

	for (seed = 1; seed <= 3000u; seed++) {
		gen_component(seed * 40503u + 1u);
		if (gen_over)
			continue;
		spans_of(&g, gen_pg, gen_pn, 0);
		if (!same_spans(&g, gen_pg, gen_pn)) {
			show_fail("component", seed, &g);
			fails++;
			return;
		}
		/* as a fragment it is the same spans: the text is script either way */
		spans_of(&g, gen_pg, gen_pn, KGENOME_TEXTUAL_FRAGMENT);
		if (!same_spans(&g, gen_pg, gen_pn)) {
			show_fail("component as a fragment", seed, &g);
			fails++;
			return;
		}
		if (!form_twice(gen_pg, gen_pn, KGENOME_TEXTUAL_KEEP_JOINS, &w)) {
			show_fail("component form", seed, &g);
			fails++;
			return;
		}
		n++;
	}
	CK(n > 2000u);
}

/* ---- (c) random text ------------------------------------------------------------------------------- */

static const char *const tok[] = {
	"<cfset", "<cfoutput>", "</cfoutput>", "<cfscript>", "</cfscript>", "<cfif", "</cfif>", "<cfquery>", "\n<!---", "--->\n", "<!--",
	"-->", "\"", "'", "#", "##", ">", "/>", "/", " ", "\n", "\r\n", "x", "y1", "=", "//", "/*", "*/", "(", ")", "&", "{", "}",
	"component", "extends=", "toBinary(", "<", "</", "<cf", "a", "b", ",", ";", "\\", "\"\"", "''", "<cfmail>", "</cfmail>",
};

static uint32_t build_tokens(uint8_t *b, uint32_t cap, uint32_t *s)
{
	uint32_t w = 0, n, k;

	*s = *s * 1103515245u + 12345u;
	n = (*s >> 16) % 40u;
	for (k = 0; k < n; k++) {
		const char *t;
		size_t l;

		*s = *s * 1103515245u + 12345u;
		t = tok[(*s >> 16) % GN(tok)];
		l = strlen(t);
		if (w + l > cap)
			break;
		memcpy(b + w, t, l);
		w += (uint32_t)l;
	}
	return w;
}

static void random_text(void)
{
	static struct got g;
	uint8_t b[512];
	uint32_t s = 99u, i, n, w, k;
	static const uint32_t flag_set[] = { 0, KGENOME_TEXTUAL_FRAGMENT };

	for (i = 0; i < 60000u; i++) {
		n = build_tokens(b, sizeof b, &s);
		for (k = 0; k < 2u; k++) {
			spans_of(&g, b, n, flag_set[k]);
			if (g.broken) {
				printf("  FAIL partition on a token text of %u bytes (flags %u)\n", n, flag_set[k]);
				fails++;
				return;
			}
			if (!form_twice(b, n, flag_set[k], &w)) {
				printf("  FAIL form on a token text of %u bytes (flags %u):\n  ", n, flag_set[k]);
				for (w = 0; w < n; w++)
					printf(b[w] >= 0x20 && b[w] < 0x7f && b[w] != '\\' ? "%c" : "\\x%02x", b[w]);
				printf("\n");
				fails++;
				return;
			}
		}
	}
}

static void properties(void)
{
	static const char alpha[] = "<>/#\"' -!=cfsetoutpx\n\r&{}()*";

	random_text();
	partition_for(C, alpha, 5u);
	form_property_for(C, alpha, 6u);
	partition_for(C, "<cfscript>/*#\"'\n", 7u);
	form_property_for(C, "<cfscript>/*#\"'\n", 8u);
}

/* ---- (d) the form ------------------------------------------------------------------------------ */

static void form_rules(void)
{
	/* the white space inside a tag is one blank where two words or two quotes meet, and nothing at the ends */
	cform("<cfset  x  =  1  >", "<cfset x=1>");
	/* a comment between two halves of what would be a tag: the gap stays, or the form of the form is another text */
	cform("<c<!--- x --->fset a=1>", "<c fset a=1>");
	cform("<cfset x = 1 />", "<cfset x=1/>");
	cform("<cfset x = 1 / >", "<cfset x=1/ >");
	cform("<cfif  a  eq  b >x</cfif >", "<cfif a eq b>x</cfif>");
	cform("<cfexecute name=\"a\"   arguments=\"b\" >", "<cfexecute name=\"a\" arguments=\"b\">");
	cform("<cfif a eq \"x\" >", "<cfif a eq \"x\">");
	cform("<cfif #a#  eq  #b# >", "<cfif #a# eq #b#>");
	/* comments go; markup is copied byte for byte, and the comments around it take nothing with them */
	cform("a  <!--- c --->  b", "a    b");
	cform("<cfset x = 1 <!--- c ---> >", "<cfset x=1>");
	cform("<!-- html comment -->  <b>  x  </b>", "<!-- html comment -->  <b>  x  </b>");
	cform("<cfoutput>  #x#  </cfoutput>", "<cfoutput>  #x#  </cfoutput>");
	/* "#" is a word byte to the row (a bare "#a#" in a tag is code), so a gap next to one stays: "# x#" is not "#x#" */
	cform("<cfoutput>#  x  #</cfoutput>", "<cfoutput># x#</cfoutput>");
	cform("<cfoutput>#a  &  b#</cfoutput>", "<cfoutput>#a&b#</cfoutput>");
	/* a string is never touched */
	cform("<cfset s = \"a  b\"\"c##d\" >", "<cfset s=\"a  b\"\"c##d\">");
	cform("<cfset s = 'a  b' &  \"c\" >", "<cfset s='a  b'&\"c\">");
	/* a tag that holds nothing is the program */
	cform("<cfif x>  <cfelse>  </cfif>", "<cfif x>  <cfelse>  </cfif>");
	cform("<cfabort />", "<cfabort/>");
	/* script: white space goes, a line break stays one, a closing tag gets a line break in front */
	cform("<cfscript> x = 1 ; // c\n y = 2 ; </cfscript>", "<cfscript>x=1;\ny=2;\n</cfscript>");
	cform("<cfscript> a.b ( c ) </cfscript>", "<cfscript>a.b(c)\n</cfscript>");
	cform("<cfscript> if (x)\n{\n y(); }\n</cfscript>", "<cfscript>if(x){\ny();}\n</cfscript>");
	cform("<cfscript> return\n{ a: 1 }\n</cfscript>", "<cfscript>return\n{a:1}\n</cfscript>");
	cform("<cfscript> a + + b; a - - b; a < = b; x ? . y </cfscript>", "<cfscript>a+ +b;a- -b;a< =b;x? .y\n</cfscript>");
	cform("<cfscript> a / * b */ c </cfscript>", "<cfscript>a/ *b*/ c\n</cfscript>");
	/* what would make a tag of code that is not one keeps its gap: "</ cfscript>" is code, and so is "< cfset" */
	cform("<cfscript> a </ cfscript> b < cfset </cfscript>", "<cfscript>a</ cfscript>b< cfset\n</cfscript>");
	/* an open comment is kept as typed, and takes no line break in front of the tag */
	cform("<cfscript> a /* b</cfscript>", "<cfscript>a/* b</cfscript>");
	cform("<cfscript> s = \"b</cfscript>", "<cfscript>s=\"b</cfscript>");
	/* a script component */
	cform("component {\n  function f() {\n    return 1;\n  }\n}", "component{\nfunction f(){\nreturn 1;\n}\n}");
	/* two literals joined by & are one literal, unless the join is kept */
	cform("<cfset x = \"ev\" & \"al\" >", "<cfset x=\"eval\">");
	cform("<cfset x = \"a\" & b >", "<cfset x=\"a\"&b>");
	cform("<cfset x = \"a\"\"\" & \"b\" >", "<cfset x=\"a\"\"b\">");
	/* a CRLF in code is one line break; in a tag's head it is the tag's own */
	cform("<cfscript>a\r\nb</cfscript>", "<cfscript>a\nb\n</cfscript>");
}

/* The decoder hook: the chain it is asked for, and the literals it is never asked about. */
static uint8_t seen[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t seen_n, seen_calls;
static uint8_t seen_in[64];
static uint32_t seen_in_n;

static int hook(void *user, const uint8_t *chain, uint32_t n, const uint8_t *in, uint32_t len,
		const uint8_t **out, uint32_t *out_len)
{
	(void)user;
	memcpy(seen, chain, n);
	seen_n = n;
	seen_calls++;
	seen_in_n = len < sizeof seen_in ? len : (uint32_t)sizeof seen_in;
	memcpy(seen_in, in, seen_in_n);
	*out = (const uint8_t *)"@@";
	*out_len = 2;
	return 1;
}

static void decode_case(const char *src, uint32_t n_chain, const uint8_t *chain, const char *want)
{
	uint8_t out[512];
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = C,
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
	static const uint8_t b64[] = { KGENOME_TEXTUAL_DEC_B64 }, url[] = { KGENOME_TEXTUAL_DEC_URL },
			     rev[] = { KGENOME_TEXTUAL_DEC_REVERSE },
			     url_b64[] = { KGENOME_TEXTUAL_DEC_URL, KGENOME_TEXTUAL_DEC_B64 };

	/* toString(toBinary("...")): toBinary is the decoder; toString is not one, and stays, as the call it wraps is renamed */
	decode_case("<cfset x = toString(toBinary(\"QUJD\"))>", 1, b64, "<cfset x=toString(decoded_toBinary(\"@@\"))>");
	decode_case("<cfset x = toBinary(\"QUJD\")>", 1, b64, "<cfset x=decoded_toBinary(\"@@\")>");
	/* case does not matter, nor white space or a comment between the tokens */
	decode_case("<cfset x = TOBINARY ( \"QUJD\" )>", 1, b64, "<cfset x=decoded_TOBINARY(\"@@\")>");
	decode_case("<cfset x = urlDecode(\"a%20b\")>", 1, url, "<cfset x=decoded_urlDecode(\"@@\")>");
	decode_case("<cfset x = reverse(\"lave\")>", 1, rev, "<cfset x=decoded_reverse(\"@@\")>");
	/* innermost first: the URL decoding is applied to the literal, then the base64 one */
	decode_case("<cfset x = toBinary(urlDecode(\"QU%4aD\"))>", 2, url_b64, "<cfset x=decoded_toBinary(decoded_urlDecode(\"@@\"))>");
	/* in a script, and in output text, the same */
	decode_case("<cfscript>x = toString(toBinary('QUJD'));</cfscript>", 1, b64,
		    "<cfscript>x=toString(decoded_toBinary('@@'));\n</cfscript>");
	decode_case("<cfoutput>#toString(toBinary(\"QUJD\"))#</cfoutput>", 1, b64,
		    "<cfoutput>#toString(decoded_toBinary(\"@@\"))#</cfoutput>");
	/* a join of literals is the payload; the hook is given the value, with the doubled quote one quote */
	decode_case("<cfset x = toBinary(\"QU\" & \"JD\")>", 1, b64, "<cfset x=decoded_toBinary(\"@@\")>");
	CK(seen_in_n == 4u && !memcmp(seen_in, "QUJD", 4));
	decode_case("<cfset x = reverse(\"a\"\"b\")>", 1, rev, "<cfset x=decoded_reverse(\"@@\")>");
	CK(seen_in_n == 3u && !memcmp(seen_in, "a\"b", 3));
	/* NOT decoders, or not a literal the hook can read: binaryDecode has its encoding in the SECOND argument, evaluate
	 * runs its text, toString and charsetEncode do not decode, "#x#" is not text, a name that only ends like one */
	decode_case("<cfset x = binaryDecode(\"QUJD\", \"base64\")>", 0, NULL, "<cfset x=binaryDecode(\"QUJD\",\"base64\")>");
	decode_case("<cfset x = evaluate(\"QUJD\")>", 0, NULL, "<cfset x=evaluate(\"QUJD\")>");
	decode_case("<cfset x = toString(\"QUJD\")>", 0, NULL, "<cfset x=toString(\"QUJD\")>");
	decode_case("<cfset x = toBinary(\"#a#\")>", 0, NULL, "<cfset x=toBinary(\"#a#\")>");
	decode_case("<cfset x = mytoBinary(\"QUJD\")>", 0, NULL, "<cfset x=mytoBinary(\"QUJD\")>");
	decode_case("<cfset x = toBinary(\"QU\" & x)>", 0, NULL, "<cfset x=toBinary(\"QU\"&x)>");
	decode_case("<cfset x = toBinary(\"QUJD\" & x)>", 0, NULL, "<cfset x=toBinary(\"QUJD\"&x)>");
	decode_case("<cfset x = toBinary(a.\"QUJD\")>", 0, NULL, "<cfset x=toBinary(a.\"QUJD\")>");
}

/* ---- (e) the value ---------------------------------------------------------------------------- */

static void value_case(const char *lit, uint32_t open, uint32_t close, const char *want)
{
	uint8_t out[128];
	struct kgenome_textual_value_req rq = { .lang = C, .lit = (const uint8_t *)lit, .len = (uint32_t)strlen(lit),
						.open_len = open, .close_len = close, .flags = KGENOME_TEXTUAL_F_INTERP,
						.out = out, .cap = sizeof out };
	struct kgenome_textual_value_res rs;
	enum kgenome_textual_status st = kgenome_textual_value(&rq, &rs);

	if (!want) {
		CK(st == KGENOME_TEXTUAL_NO_VALUE);
		return;
	}
	if (st != KGENOME_TEXTUAL_OK || rs.n_out != strlen(want) || memcmp(out, want, rs.n_out)) {
		printf("  FAIL value of %s: status %d, %u bytes\n", lit, (int)st, rs.n_out);
		fails++;
	}
}

static void values(void)
{
	value_case("\"abc\"", 1, 1, "abc");
	value_case("\"\"", 1, 1, "");
	value_case("\"a\"\"b\"", 1, 1, "a\"b");
	value_case("'it''s'", 1, 1, "it's");
	value_case("\"it's\"", 1, 1, "it's");
	value_case("'say \"hi\"'", 1, 1, "say \"hi\"");
	value_case("\"##\"", 1, 1, "#");
	value_case("\"a##b####c\"", 1, 1, "a#b##c");
	value_case("\"C:\\dir\\\"", 1, 1, "C:\\dir\\");
	value_case("\"a\nb\"", 1, 1, "a\nb");
	/* an expression, a "#" alone: no value without running the program */
	value_case("\"#x#\"", 1, 1, NULL);
	value_case("\"a#b#c\"", 1, 1, NULL);
	value_case("\"#\"", 1, 1, NULL);
	value_case("\"###\"", 1, 1, NULL);
	/* a lone quote cannot be in a closed literal */
	value_case("'a'b'", 1, 1, NULL);
}

/* ---- (f) hostile input ------------------------------------------------------------------------- */

struct whole {
	uint32_t next, n;
	int      broken;
};

static int whole_sink(void *u, const struct kgenome_textual_span *s)
{
	struct whole *w = u;

	if (s->off != w->next || !s->len)
		w->broken = 1;
	w->next = s->off + s->len;
	w->n++;
	return 1;
}

static enum kgenome_textual_status lex_whole(const uint8_t *in, uint32_t n, uint32_t flags, struct whole *w,
					      struct kgenome_textual_lex_res *rs)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = C, .flags = flags, .sink = whole_sink, .user = w };

	memset(w, 0, sizeof *w);
	return kgenome_textual_lex(&rq, rs);
}

static void hostile(void)
{
	struct whole w;
	struct kgenome_textual_lex_res rs;
	static uint8_t big[900u * 1024u];
	uint32_t i, n;

	/* a cf comment nested a hundred thousand deep: the depth is a counter, so it is one comment, closed - and one that
	 * is not closed is one open comment */
	n = 0;
	for (i = 0; i < 100000u; i++, n += 5u)
		memcpy(big + n, "<!---", 5u);
	for (i = 0; i < 100000u; i++, n += 4u)
		memcpy(big + n, "--->", 4u);
	CK(lex_whole(big, n, 0, &w, &rs) == KGENOME_TEXTUAL_OK && w.n == 1u && !w.broken && w.next == n);
	CK(lex_whole(big, n - 4u, 0, &w, &rs) == KGENOME_TEXTUAL_OPEN && w.n == 1u && rs.n_open == 1u);
	CK(lex_whole(big, n / 2u, 0, &w, &rs) == KGENOME_TEXTUAL_OPEN && w.n == 1u && !w.broken);

	/* strings nested in expressions in strings, below the recursion bound (one string) and far above it (the partition
	 * holds, and every byte is in a span) */
	for (n = 0, i = 0; i < 20u; i++, n += 4u)
		memcpy(big + n, "\"#f(", 4u);
	memcpy(big + n, "\"z\"", 3u);
	n += 3u;
	for (i = 0; i < 20u; i++, n += 3u)
		memcpy(big + n, ")#\"", 3u);
	CK(lex_whole(big, n, 0, &w, &rs) == KGENOME_TEXTUAL_OK && w.n == 1u && !w.broken);
	for (n = 0, i = 0; i < 5000u; i++, n += 4u)
		memcpy(big + n, "\"#f(", 4u);
	memcpy(big + n, "\"z\"", 3u);
	n += 3u;
	for (i = 0; i < 5000u; i++, n += 3u)
		memcpy(big + n, ")#\"", 3u);
	{
		struct got *g = calloc(1, sizeof *g);

		lex_whole(big, n, KGENOME_TEXTUAL_FRAGMENT, &w, &rs);
		CK(!w.broken && w.next == n);
		memcpy(big + n, "", 0);
		free(g);
	}
	/* the same inside a tag, and in output text */
	{
		static uint8_t pg[64u * 1024u];
		uint32_t m = 0;

		memcpy(pg + m, "<cfset x = ", 11u);
		m += 11u;
		memcpy(pg + m, big, 2000u * 4u);
		m += 2000u * 4u;
		CK(lex_whole(pg, m, 0, &w, &rs) != KGENOME_TEXTUAL_REFUSED && !w.broken && w.next == m);
	}

	/* a huge literal that never closes: three spans (tag, code, string), not a loop */
	{
		const char *head = "<cfset x = \"";
		uint32_t hl = (uint32_t)strlen(head);

		memcpy(big, head, hl);
		memset(big + hl, 'a', sizeof big - hl);
		CK(lex_whole(big, (uint32_t)sizeof big, 0, &w, &rs) == KGENOME_TEXTUAL_OPEN && w.n == 3u && rs.n_open == 1u);
		memcpy(big, "<cfscript>/*", 12u);
		memset(big + 12, 'a', sizeof big - 12u);
		CK(lex_whole(big, (uint32_t)sizeof big, 0, &w, &rs) == KGENOME_TEXTUAL_OPEN && w.n == 2u);
		memcpy(big, "<!---", 5u);
		memset(big + 5, 'a', sizeof big - 5u);
		CK(lex_whole(big, (uint32_t)sizeof big, 0, &w, &rs) == KGENOME_TEXTUAL_OPEN && w.n == 1u);
	}

	/* LINEAR WORK. Each of these is a text where something never closes - a "#" with no partner, a quote, a comment, a
	 * tag - repeated until it is 900 KB. A lexer that read to the end for every one it could not close would do ~10^11
	 * steps here; this takes a blink, and the bound on the whole is a few seconds even under a sanitizer. */
	{
		static const char *const unit[] = {
			"\"#", "<cfset x = \"#", "<cfoutput>#", "#\"'", "'#'\"#", "<!---<!---", "<cfscript>\"#", "<cfif #", "<cfoutput>#a <cfset b>",
			"\"#f(\"", "<cfset a = \"#f(\"b", "#", "<cfoutput>#'", "\"#a\"#'", "<cfif a / ", "<cfscript>/*", "<cfscript>//", "<cfset x",
			"</cfscript", "<cfscript></cfscript", "<cfoutput>##", "<cf", "<cfset a=#x# #", "<cfoutput>#f(\"<cfif>\")#",
		};
		clock_t t0 = clock();
		uint32_t k;

		for (k = 0; k < GN(unit); k++) {
			size_t ul = strlen(unit[k]);
			uint32_t m = 0;

			while (m + ul <= sizeof big) {
				memcpy(big + m, unit[k], ul);
				m += (uint32_t)ul;
			}
			lex_whole(big, m, 0, &w, &rs);
			CK(!w.broken && w.next == m);
			lex_whole(big, m, KGENOME_TEXTUAL_FRAGMENT, &w, &rs);
			CK(!w.broken && w.next == m);
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 60.0);
	}
}

int main(void)
{
	tags();
	strings();
	hashes();
	comments();
	scripts();
	components();
	fragments();
	close_flag();
	line_endings();
	nul_bytes();
	generator();
	component_generator();
	properties();
	form_rules();
	decoders();
	values();
	hostile();
	printf("textual cfm: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
