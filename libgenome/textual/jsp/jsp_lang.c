/*
 * jsp_lang.c - the row for java server pages: a page, with <%-- comments --%> and the XML scripting
 * elements, whose islands are java. The page rules are in textual_page.c (the first "%>" ends an island)
 * and jsp_lex.c (<jsp:scriptlet>, EL); the java is textual_java.c.
 */

#include "jsp.h"

/* "<%=" and "<%!" are tags; "<%#" and "<%$" are scriptlets that begin with that byte, in a jsp. */
static const struct kgenome_textual_page page = {
	.body = kgenome_textual_java, .dash_comment = 1, .tag3 = "=!", .markup = kgenome_textual_jsp_markup,
	.fragment_code = 1,         /* a FRAGMENT is java from its first byte: a scriptlet's body, a decoded payload */
};

/*
 * The pairs that closing up white space would make into something else. The operators java writes twice
 * ("+ +" is not "++", "> >" is not the shift ">>": the form keeps the typing's token boundary, since it
 * cannot know a generic's close from a shift) and the comment opener, slash star. Then what only a jsp has:
 * "%" in front of ">" (a percent, a comment and a ">" must not close up into the island end), and "%" in front of
 * "=", "!", "@" or "-", which would turn the tag "<%" into "<%=", "<%!", "<%@" (a directive) or "<%--"
 * (a comment) when the first code byte of a scriptlet is one of them: `<% @SuppressWarnings("x") int a; %>`.
 * A backslash keeps its space too: java code has one only in a "\uXXXX" escape that may spell an operator
 * ("+ +" is "+ +"), and the byte on its other side cannot tell. KNOWN LIMIT: the escape's last
 * hex digit is a name byte, so "+ +" is closed up by the other rule and the form changes what it says.
 */
static int jsp_glue(uint8_t a, uint8_t b)
{
	return kgenome_textual_glue_twice(a, b, "+-*/%=!<>&|.:?^~") || (a == '/' && b == '*') || (a == '<' && b == '%') ||
	       (a == '%' && kof_byte_in_set(b, ">=!@-")) || a == '\\' || b == '\\';
}

/*
 * join_brace: java's braces are free-standing, so "{" alone on a line joins the line above.
 * unescape_str stays NULL: java has no "\x" escape, its octal escape is at most "\377" (a third digit only after
 * 0-3, so "\477" is "\47" and "7": the generic rewrite reads three digits and would write the wrong byte),
 * and "A" cannot be written as "A" without knowing the result is not a quote, a backslash or a line
 * break. The form leaves the spelled-out bytes of a string as typed.
 */
/* A java string: the backslash and the quote escaped, a control byte as its letter or \ooo (a \uXXXX is read before the lexer and a "\u000a" would be a
 * line break), and nothing that ends the island or the script element. */
static const struct kgenome_textual_quote quote = { .q = '"', .bs = "\\", .letters = KGENOME_TEXTUAL_JAVA_CTL, .ctl = 'o', .seq = KGENOME_TEXTUAL_PAGE_SEQ };

const struct kgenome_textual_lang kgenome_textual_lang_jsp = {
	.name = "jsp",
	.id = KGENOME_TEXTUAL_LANG_JSP,
	.gap_comments = KGENOME_TEXTUAL_GAP_LINE | KGENOME_TEXTUAL_GAP_BLOCK,
	.page = &page,
	.glue = jsp_glue,
	.join_brace = 1,
	.islands = 1,
	.open_tail = 1,     /* an open text block or block comment runs to the "%>": no line break goes into it */
	.call_chain = kgenome_textual_jsp_call_chain,
	.value = kgenome_textual_jsp_value,
	.concat = '+',
	.quote = &quote,
};
