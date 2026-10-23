/*
 * cfm_lex.c - THE LEXER OF COLDFUSION (CFML TAGS AND CFSCRIPT): a page, whose markup is everything outside a tag.
 *
 * WHAT IS WHAT [the rules are CFML's as documented; no engine was run - [Unverified] throughout]:
 *
 *   MARKUP   everything outside a cf tag and a comment, html tags and "<!-- -->" included: CF reads the cf tags inside an
 *            HTML comment and inside an HTML tag's attributes (<input <cfif x>checked</cfif>>), so nothing here is hidden.
 *   TAG      "<cfname" and "</cfname" (case-insensitive, cf then a letter or "_"), and the ">" or "/>" that ends it. A tag
 *            with nothing in it ("</cfif>", "<cfelse>") is one TAG; one with attributes is TAG, code, TAG. The code between
 *            is the attributes and the expression of cfset / cfif: names, operators, strings, "#...#" (cfm_code.c).
 *            No TAG has F_CLOSE but "</cfscript>" - the one that leaves a language - because the form puts a line
 *            break in front of such a tag, and "x#" is no place for one.
 *   COMMENT  "<!--- ... --->", nested; markup that holds it goes on around it. CF drops it when it compiles, as the form does.
 *   "#...#"  in output text: only inside <cfoutput>, <cfquery> and <cfmail> (a counter of how many are open; a "#" elsewhere
 *            is text, as "#top" in an href is). "#" is a TAG, the expression is code, "#" a TAG; "##" is a literal "#". A tag ends
 *            an expression before it closes, a comment inside it is a gap (cfm_code.c, hash_scan, says why).
 *   cfscript "<cfscript>" ... "</cfscript>" is script. The end tag is the first one there is, in a string or a comment too:
 *            the tag scanner reads for it before the script is read [Inference, as for jsp's "%>"], so the body never has to
 *            find it. Not closed: the body runs to the end of the text.
 *   a script component, a text that begins (after white space and comments) with `component` or `interface` and then "{" or
 *            an attribute (name =): the whole text is script, no cfscript tag. A fragment (a decoded payload) is script too.
 *
 * NOT DONE: tag islands inside cfscript (Lucee's ``` fences, CF11's <cfquery> in script), <cfimport prefix=> custom tags
 * (<x:name> is markup), the end of cfoutput inside a cfscript, `import` as a script component's first word.
 * "<cfset x = a > b>" ends at the first ">" (use GT); a bracket does not shelter it [Unverified: ACF accepts ">" in some
 * brackets].
 * KNOWN LIMIT, found by the random-token test: the form drops a COMMENT between two MARKUP spans and writes nothing in its
 * place (textual_form.c, the markup case), so a comment that stands between two halves of a token joins them - `<c<!--- x --->fset>`
 * becomes a tag, `#<!--- x --->#` becomes "##" - and the form of that form is not the first form. The same is true of jsp's
 * `<<%-- x --%>% y %>`. The lexer is not wrong about the first text (comments are removed by the language, and a tag is not made
 * of two pieces), the form is: it would need to write a gap where the two sides would glue. Not changed here (shared file); the
 * token test puts a line break at each side of a comment, which is how a comment is written.
 */

#include "cfm.h"

static int name_is(const uint8_t *p, uint32_t at, uint32_t len, const char *w)
{
	return strlen(w) == len && kgenome_textual_ci_eq(p + at, w, len);
}

/* White space, comments of both kinds (and a byte order mark): where code begins. */
static uint32_t trivia(const uint8_t *p, uint32_t n, uint32_t i)
{
	while (i < n) {
		uint8_t c = p[i];
		int closed;

		if (kof_is_space_byte(c)) {
			i++;
		} else if (c == '/' && i + 1u < n && p[i + 1u] == '/') {
			i = kgenome_textual_line_end(p, n, i);
		} else if (c == '/' && i + 1u < n && p[i + 1u] == '*') {
			i = kgenome_textual_c_block_end(p, n, i, &closed);
		} else if (c == '<' && i + 5u <= n && memcmp(p + i, "<!---", 5u) == 0) {
			i = kgenome_textual_cfm_comment_end(p, n, i, &closed);
		} else {
			break;
		}
	}
	return i;
}

/*
 * Is the whole text a script component: `component {`, `component extends="a" {`, `interface {`. The word alone is not
 * enough - prose begins with "component" too - so what follows it is a brace or an attribute (a name and "=").
 */
static int script_component(const uint8_t *p, uint32_t n)
{
	static const char *const word[] = { "component", "interface" };
	uint32_t i = n >= 3u && p[0] == 0xEFu && p[1] == 0xBBu && p[2] == 0xBFu ? 3u : 0u, k;

	i = trivia(p, n, i);
	for (k = 0; k < 2u; k++) {
		uint32_t l = (uint32_t)strlen(word[k]), j;

		if (i + l > n || !kgenome_textual_ci_eq(p + i, word[k], l) || (i + l < n && kgenome_textual_ident(p[i + l])))
			continue;
		j = trivia(p, n, i + l);
		if (j < n && p[j] == '{')
			return 1;
		if (j < n && kgenome_textual_ident(p[j])) {
			while (j < n && kgenome_textual_ident(p[j]))
				j++;
			while (j < n && kof_is_space_byte(p[j]))
				j++;
			return j < n && p[j] == '=';
		}
	}
	return 0;
}

/* The body of a cfscript tag from lx->pos: script up to the first "</cfscript" + white space + ">", and that tag. */
static void script_body(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, j = lx->pos, e = n, after = 0;

	while (j < n) {
		const uint8_t *q = memchr(p + j, '<', n - j);
		uint32_t k;

		if (!q)
			break;
		j = (uint32_t)(q - p);
		if (j + 10u < n && p[j + 1u] == '/' && kgenome_textual_ci_eq(p + j + 2u, "cfscript", 8u)) {
			for (k = j + 10u; k < n && kof_is_space_byte(p[k]); k++)
				;
			if (k < n && p[k] == '>') {
				e = j;
				after = k + 1u;
				break;
			}
		}
		j++;
	}
	kgenome_textual_cfm_code(lx, e, KGENOME_CFM_SCRIPT);
	if (after && !lx->refused)
		kgenome_textual_emit(lx, after - e, KGENOME_TEXTUAL_TAG, KGENOME_TEXTUAL_F_CLOSE, 0, 0);
}

/* The cf tag at lx->pos whose name is [name_at, name_end): its TAG spans, and what it does to the output depth. */
static void cf_tag(struct kgenome_textual_lexer *lx, uint32_t name_at, uint32_t name_end, uint32_t *depth)
{
	const uint8_t *p = lx->p;
	uint32_t at = lx->pos, nl = name_end - name_at, cl = kgenome_textual_cfm_closer(p, lx->n, name_end), stop;
	int closing = p[at + 1u] == '/', self = 0, closed = 1;

	if (cl) {
		self = p[name_end] == '/';
		kgenome_textual_emit(lx, name_end + cl - at, KGENOME_TEXTUAL_TAG, 0, 0, 0);
	} else {
		kgenome_textual_emit(lx, name_end - at, KGENOME_TEXTUAL_TAG, 0, 0, 0);
		stop = kgenome_textual_cfm_code(lx, lx->n, KGENOME_CFM_TAG);
		cl = stop < lx->n && !lx->refused ? kgenome_textual_cfm_closer(p, lx->n, stop) : 0u;
		closed = cl != 0;
		if (cl) {
			self = p[stop] == '/';
			kgenome_textual_emit(lx, cl, KGENOME_TEXTUAL_TAG, 0, 0, 0);
		}
	}
	if (!closed || lx->refused || self)
		return;
	if (!closing && name_is(p, name_at, nl, "cfscript")) {
		script_body(lx);
	} else if (name_is(p, name_at, nl, "cfoutput") || name_is(p, name_at, nl, "cfquery") ||
		   name_is(p, name_at, nl, "cfmail")) {
		if (!closing)
			(*depth)++;
		else if (*depth)
			(*depth)--;
	}
}

/* "#...#" in output text at `i`: the "#" TAGs and the code between. 0 when it is not one. */
static int out_hash(struct kgenome_textual_lexer *lx, uint32_t i)
{
	uint32_t e = kgenome_textual_cfm_hash(lx, i);

	if (!e)
		return 0;
	kgenome_textual_markup_to(lx, i);
	kgenome_textual_emit(lx, 1u, KGENOME_TEXTUAL_TAG, 0, 0, 0);
	kgenome_textual_cfm_code(lx, e - 1u, KGENOME_CFM_EXPR);
	kgenome_textual_emit(lx, 1u, KGENOME_TEXTUAL_TAG, 0, 0, 0);
	return 1;
}

void kgenome_textual_cfm_lex(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = 0, depth = 0;

	if (lx->fragment || script_component(p, n)) {
		kgenome_textual_cfm_code(lx, n, KGENOME_CFM_SCRIPT);
		return;
	}
	while (i < n && !lx->refused) {
		uint8_t c = p[i];
		uint32_t ne, na;

		if (!depth) {
			const uint8_t *q = memchr(p + i, '<', n - i);

			if (!q)
				break;
			i = (uint32_t)(q - p);
			c = '<';
		}
		if (c == '<') {
			int closed;

			if (i + 5u <= n && memcmp(p + i, "<!---", 5u) == 0) {
				uint32_t e = kgenome_textual_cfm_comment_end(p, n, i, &closed);

				kgenome_textual_markup_to(lx, i);
				kgenome_textual_emit(lx, e - i, KGENOME_TEXTUAL_COMMENT,
						     closed ? 0u : KGENOME_TEXTUAL_F_OPEN, 5u, closed ? 4u : 0u);
				i = lx->pos;
				continue;
			}
			ne = kgenome_textual_cfm_tag_name(p, n, i, &na);
			if (ne) {
				kgenome_textual_markup_to(lx, i);
				cf_tag(lx, na, ne, &depth);
				i = lx->pos;
				continue;
			}
		} else if (c == '#' && !(lx->aux & KGENOME_CFM_MEMO_HASH)) {
			if (i + 1u < n && p[i + 1u] == '#') {
				i += 2u;
				continue;
			}
			if (out_hash(lx, i)) {
				i = lx->pos;
				continue;
			}
		}
		i++;
	}
	if (!lx->refused)
		kgenome_textual_markup_to(lx, n);
}
