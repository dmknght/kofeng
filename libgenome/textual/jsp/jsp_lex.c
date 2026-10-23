/*
 * jsp_lex.c - what a jsp page has that the page host (textual_page.c) cannot see by looking for "<%": the
 * markup around the islands. The host handles <%-- --%>, <%@ %>, <%! %>, <%= %> and <% %>.
 *
 * TWO THINGS HERE, called by the host at a "<" that is not "<%" and at a "$" or "#":
 *
 * 1. THE XML FORM OF A SCRIPTING ELEMENT: <jsp:scriptlet>, <jsp:declaration>, <jsp:expression>, each ended
 *    by its own end tag, with the code optionally inside <![CDATA[ ... ]]>. These are islands like "<%":
 *    the begin tag (and the "<![CDATA[" that follows it, white space between) is one TAG, the end tag (and the
 *    "]]>" in front of it) one TAG with F_CLOSE. As with "%>", the first "]]>" there is ends the code, in a
 *    string or a comment too - an XML parser reads for it before java does - and without CDATA the first
 *    end tag does. A second CDATA section ("]]><![CDATA[") continues the code and is delivered as code.
 *    An element with "/>" holds no code and is markup. Names are case sensitive, as XML is.
 *    NOT DONE: the XML entities (&lt; &quot;) of a body without CDATA are not decoded, so such a body is
 *    lexed as typed; a java string written with &quot; is then not a string here [Inference: no
 *    corpus file has one; javac's own jspc would decode it].
 *
 * 2. EL, "${ ... }" and "#{ ... }" in template text and in attribute values, which Jasper reads to the first
 *    "}" that is outside quotes (a backslash takes the next byte inside quotes) BEFORE it looks for "<%"
 *    [Unverified: from memory of Tomcat's Parser.parseELExpression; the JSP spec says only that EL is
 *    evaluated in template text]. So `${"<%"}` is markup and not an island. A "\" right before the "$" makes
 *    it literal text. Decided against the evasion this opens: an EL that does not close before an unquoted
 *    "<%" or the end of the text is NOT an EL, it is markup, the islands in it are lexed, and EL tracking is
 *    off for the rest of the text (lx->aux), which also makes the work linear - a text of n/3 "${'" would
 *    otherwise scan to the end n/3 times. Known limit: a page that says isELIgnored="true" (or runs under a
 *    web.xml older than 2.4) treats "${" as text, and there `${"<%"} <% x %>` has an island this lexer
 *    does not see; the directive is not read for it.
 */

#include "jsp.h"

static uint32_t skip_ws(const uint8_t *p, uint32_t n, uint32_t i)
{
	while (i < n && kof_is_space_byte(p[i]))
		i++;
	return i;
}

/* After the "}" that closes the EL expression at `at`; 0 when it does not close (see above). */
static uint32_t el_end(const uint8_t *p, uint32_t n, uint32_t at)
{
	uint32_t j = at + 2u;
	uint8_t q = 0;

	while (j < n) {
		uint8_t c = p[j];

		if (q) {
			if (c == '\\')
				j++;
			else if (c == q)
				q = 0;
		} else if (c == '"' || c == '\'') {
			q = c;
		} else if (c == '}') {
			return j + 1u;
		} else if (c == '<' && j + 1u < n && p[j + 1u] == '%') {
			return 0;
		}
		j++;
	}
	return 0;
}

static uint32_t el(struct kgenome_textual_lexer *lx, uint32_t at)
{
	const uint8_t *p = lx->p;
	uint32_t e;

	if (lx->aux || at + 1u >= lx->n || p[at + 1u] != '{' || (at && p[at - 1u] == '\\'))
		return 0;
	e = el_end(p, lx->n, at);
	if (!e)
		lx->aux = 1;
	return e;
}

static const char *const xml_name[] = { "scriptlet", "declaration", "expression" };

/* The name at p[at] = "<jsp:" : its index, and in *to the offset of the ">" that ends the begin tag; -1 when it is not a begin tag with a body. */
static int xml_begin(const uint8_t *p, uint32_t n, uint32_t at, uint32_t *to, uint32_t *nlen)
{
	uint32_t k, l, j;

	if (at + 6u >= n || memcmp(p + at, "<jsp:", 5u) != 0)
		return -1;
	for (k = 0; k < sizeof xml_name / sizeof xml_name[0]; k++) {
		l = (uint32_t)strlen(xml_name[k]);
		if (at + 5u + l >= n || memcmp(p + at + 5u, xml_name[k], l) != 0)
			continue;
		j = skip_ws(p, n, at + 5u + l);
		if (j < n && p[j] == '>') {
			*to = j;
			*nlen = l;
			return (int)k;
		}
		return -1;
	}
	return -1;
}

/* "</jsp:name" + white space + ">" at i: the offset after it, 0 when it is not the end tag. */
static uint32_t xml_end_at(const uint8_t *p, uint32_t n, uint32_t i, int k)
{
	uint32_t l = (uint32_t)strlen(xml_name[k]), j;

	if (i + 6u + l >= n || memcmp(p + i, "</jsp:", 6u) != 0 || memcmp(p + i + 6u, xml_name[k], l) != 0)
		return 0;
	j = skip_ws(p, n, i + 6u + l);
	return j < n && p[j] == '>' ? j + 1u : 0;
}

static int cdata_at(const uint8_t *p, uint32_t n, uint32_t i)
{
	return i + 9u <= n && memcmp(p + i, "<![CDATA[", 9u) == 0;
}

/* The code of an element, [lx->pos, ...): the end tag's offset and the whole closing TAG's end. */
static void xml_code(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg, int k, int cdata)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = lx->pos;

	for (;;) {
		uint32_t e = i, after = 0, m;

		if (cdata) {
			while (e + 2u < n && !(p[e] == ']' && p[e + 1u] == ']' && p[e + 2u] == '>'))
				e++;
			if (e + 2u >= n) {
				pg->body(lx, n);
				return;
			}
			m = skip_ws(p, n, e + 3u);
			after = xml_end_at(p, n, m, k);
			if (!after && cdata_at(p, n, m)) {
				/* a second section: its delimiters are code, and the code goes on */
				if (!pg->body(lx, e) || !kgenome_textual_emit(lx, m + 9u - e, KGENOME_TEXTUAL_CODE, 0, 0, 0))
					return;
				i = lx->pos;
				continue;
			}
			if (!after)
				after = e + 3u;
		} else {
			while (e < n && !(p[e] == '<' && (after = xml_end_at(p, n, e, k)) != 0))
				e++;
			if (e >= n) {
				pg->body(lx, n);
				return;
			}
		}
		if (e > lx->pos && !pg->body(lx, e))
			return;
		kgenome_textual_emit(lx, after - e, KGENOME_TEXTUAL_TAG, KGENOME_TEXTUAL_F_CLOSE, 0, 0);
		return;
	}
}

static uint32_t xml_element(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg, uint32_t at)
{
	const uint8_t *p = lx->p;
	uint32_t gt, nlen, open_end, m;
	int k = xml_begin(p, lx->n, at, &gt, &nlen), cdata;

	if (k < 0)
		return 0;
	m = skip_ws(p, lx->n, gt + 1u);
	cdata = cdata_at(p, lx->n, m);
	open_end = cdata ? m + 9u : gt + 1u;
	if (!kgenome_textual_markup_to(lx, at) ||
	    !kgenome_textual_emit(lx, open_end - at, KGENOME_TEXTUAL_TAG, 0, 0, 0))
		return lx->pos;
	xml_code(lx, pg, k, cdata);
	return lx->pos;
}

uint32_t kgenome_textual_jsp_markup(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg,
				    uint32_t at)
{
	uint8_t c = lx->p[at];

	if (c == '<')
		return xml_element(lx, pg, at);
	return el(lx, at);
}
