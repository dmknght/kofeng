/*
 * textual_page.c - a page: markup with islands of code in it, the way asp, aspx and jsp have them.
 * The islands are "<%" ... "%>", and in asp and aspx a <script runat="server"> element too.
 *
 * WHAT IT DECIDES: where each island starts and ends, and nothing about the code inside - that is the
 * body lexer's, given the island's window. An island ends at the FIRST "%>" there is, inside a string or
 * a comment too: the page scanner reads for the tag before any language reads the code, which is why a
 * "%>" in a java string has to be written "%\>". The body therefore never has to look for the end, and
 * a string or comment it cannot close inside the window is open there.
 *
 *   <%@ ... %>     a directive: the page's, not code. Markup, verbatim.
 *   <%-- ... --%>  a comment of the page (aspx, jsp): a comment, and not code.
 *   <%= <%! <%# <%$  an expression, a declaration, a binding: code, with the tag's third byte in its TAG.
 *   <% ... %>      code.
 */

#include <string.h>

#include "textual_private.h"

/* The first "%>" at or after `from`; `n` when there is none. */
static uint32_t find_close(const uint8_t *p, uint32_t n, uint32_t from)
{
	while (from + 1u < n) {
		const uint8_t *q = memchr(p + from, '%', n - from - 1u);

		if (!q)
			return n;
		from = (uint32_t)(q - p);
		if (p[from + 1u] == '>')
			return from;
		from++;
	}
	return n;
}

int kgenome_textual_island_lex(struct kgenome_textual_lexer *lx, const struct kgenome_textual_script_lang *l, uint32_t end)
{
	if (l->lexer == KGENOME_TEXTUAL_PAGE_VB)
		return kgenome_textual_vb(lx, end);
	return l->lexer == KGENOME_TEXTUAL_PAGE_ECMA ? kgenome_textual_ecma(lx, end, l->flags)
						     : kgenome_textual_clike(lx, end, l->flags);
}

/* The code of [lx->pos, end) in language `l` of the page, or in its one language when it has no table. */
static int run_body(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg,
		    const struct kgenome_textual_script_lang *l, uint32_t end)
{
	return l ? kgenome_textual_island_lex(lx, l, end) : pg->body(lx, end);
}

/* An island of code in [from, end): its opening tag [lx->pos, from) is delivered by the caller. */
static int island(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg,
		  const struct kgenome_textual_script_lang *l, uint32_t end, uint32_t close_len)
{
	if (end > lx->pos && !run_body(lx, pg, l, end))
		return 0;
	return end >= lx->n || kgenome_textual_emit(lx, close_len, KGENOME_TEXTUAL_TAG, KGENOME_TEXTUAL_F_CLOSE, 0, 0);
}

/*
 * ATTRIBUTES, of a tag and of a directive, read as html reads them: a name runs to white space, "=" or the end;
 * "=" and a value follow, quoted (to the same quote, whatever it holds) or bare (to white space or ">"). A
 * name inside another attribute's value is therefore never taken for an attribute, and an attribute with no
 * "=" has no value. The first byte of a name is always part of it, so a stray quote or "=" cannot stall the
 * walk. Evidence for the quote rule: `<%@ Page Title="a language vb" Language="C#" %>` named vb under the
 * scan this replaced, which looked for the word language anywhere in the directive.
 */
struct page_attr {
	uint32_t ns, ne, vs, ve;
	uint8_t  has_value;
};

/* The next attribute of the list that ends at `e`, from *pi. 0 at ">" or at `e`. */
static int attr_next(const uint8_t *p, uint32_t e, uint32_t *pi, struct page_attr *a)
{
	uint32_t i = *pi;

	while (i < e && kof_is_space_byte(p[i]))
		i++;
	if (i >= e || p[i] == '>') {
		*pi = i;
		return 0;
	}
	a->ns = i++;
	while (i < e && !kof_is_space_byte(p[i]) && p[i] != '=' && p[i] != '>')
		i++;
	a->ne = i;
	while (i < e && kof_is_space_byte(p[i]))
		i++;
	a->has_value = i < e && p[i] == '=';
	if (a->has_value) {
		for (i++; i < e && kof_is_space_byte(p[i]); i++)
			;
		if (i < e && (p[i] == '"' || p[i] == '\'')) {
			const uint8_t *q = memchr(p + i + 1u, p[i], e - i - 1u);

			a->vs = i + 1u;
			a->ve = q ? (uint32_t)(q - p) : e;
			i = q ? a->ve + 1u : e;
		} else {
			a->vs = i;
			while (i < e && !kof_is_space_byte(p[i]) && p[i] != '>')
				i++;
			a->ve = i;
		}
	}
	*pi = i;
	return 1;
}

/* A name of the page's languages is matched in any case, letter by letter; "#" and digits as they are. */
static int word_eq(const uint8_t *p, const char *w, uint32_t n)
{
	uint32_t k;

	for (k = 0; k < n; k++) {
		uint8_t c = p[k];

		if (c >= 'A' && c <= 'Z')
			c = (uint8_t)(c | 0x20u);
		if (c != (uint8_t)w[k])
			return 0;
	}
	return 1;
}

static int attr_is(const uint8_t *p, const struct page_attr *a, const char *name)
{
	uint32_t l = (uint32_t)strlen(name);

	return a->ne - a->ns == l && word_eq(p + a->ns, name, l);
}

/* The row of the page's languages whose name `value` begins with; NULL when there is none. */
static const struct kgenome_textual_script_lang *lang_pick(const struct kgenome_textual_page *pg,
							   const uint8_t *p, uint32_t vs, uint32_t ve)
{
	uint32_t k;

	for (k = 0; k < pg->n_langs; k++) {
		uint32_t l = (uint32_t)strlen(pg->langs[k].word);

		if (ve - vs >= l && word_eq(p + vs, pg->langs[k].word, l))
			return &pg->langs[k];
	}
	return NULL;
}

/*
 * THE TAGS THAT ARE LOOKED AT ARE BOUNDED, so that a hostile page cannot make the scan quadratic: "<script
 * \"" repeated 100000 times has every tag open a quote that runs to the end of the text, and each scan
 * would read all of it. A page whose tags are well formed reads each tag once - the sum of the tags is at
 * most the text - so `left` is four times the text and a page that spends it is not an html page: the
 * tags after that are not looked at (they are markup), and a ">" is searched for from where the last
 * search ended, never twice over the same bytes.
 */
struct page_scan {
	uint32_t left;
	uint32_t gt_from, gt;           /* the first ">" at or after gt_from is at gt (n when there is none) */
};

static void scan_init(struct page_scan *ps, uint32_t n)
{
	ps->left = n > 0x3fffffffu ? 0xffffffffu : 4u * n + 4096u;
	ps->gt_from = 1;
	ps->gt = 0;
}

static uint32_t next_gt(struct page_scan *ps, const uint8_t *p, uint32_t n, uint32_t from)
{
	if (!(from >= ps->gt_from && from <= ps->gt)) {
		const uint8_t *q = from < n ? memchr(p + from, '>', n - from) : NULL;

		ps->gt_from = from;
		ps->gt = q ? (uint32_t)(q - p) : n;
	}
	return ps->gt;
}

/* What `<script ...>` says: whether it is a server script, and where its language attribute's value is. */
struct page_script {
	uint32_t lvs, lve;
	uint8_t  server, has_lang;
};

/*
 * `<script ... runat="server" ...>` at `i`: where its tag ends, or 0 when it is not a tag. The tag's
 * attributes are read for runat and language, the first of each; `sc->server` says runat was "server".
 */
static uint32_t script_tag(struct page_scan *ps, const uint8_t *p, uint32_t n, uint32_t i, struct page_script *sc)
{
	uint32_t j = i + 7u;
	struct page_attr a;

	sc->server = sc->has_lang = 0;
	if (j >= n || !(kof_is_space_byte(p[j]) || p[j] == '>' || p[j] == '/') || !word_eq(p + i + 1u, "script", 6u) ||
	    next_gt(ps, p, n, j) >= n)
		return 0;
	while (ps->left) {
		uint32_t from = j;
		int more = attr_next(p, n, &j, &a);

		ps->left -= j - from < ps->left ? j - from : ps->left;
		if (!more)
			return j < n && p[j] == '>' ? j + 1u : 0;
		if (attr_is(p, &a, "runat") && a.has_value && !sc->server)
			sc->server = a.ve - a.vs == 6u && word_eq(p + a.vs, "server", 6u);
		else if (attr_is(p, &a, "language") && a.has_value && !sc->has_lang) {
			sc->lvs = a.vs;
			sc->lve = a.ve;
			sc->has_lang = 1;
		}
	}
	return 0;
}

/*
 * The "</script>" that ends the element whose body begins at `from`: its offset, and in *len its length; n
 * when there is none. It is found before any language reads the body - in a string or a comment too, as a
 * "%>" is - and it is `</script`, white space and ">": "</scripts>" is not it (asp.net's own pattern is
 * "</script\s*>" [Unverified: from memory, no asp.net here]).
 */
static uint32_t script_close(const uint8_t *p, uint32_t n, uint32_t from, uint32_t *len)
{
	while (from < n) {
		const uint8_t *q = memchr(p + from, '<', n - from);
		uint32_t k, j;

		if (!q)
			break;
		k = (uint32_t)(q - p);
		j = k + 8u;
		if (j < n && p[k + 1u] == '/' && word_eq(p + k + 2u, "script", 6u)) {
			while (j < n && kof_is_space_byte(p[j]))
				j++;
			if (j < n && p[j] == '>') {
				*len = j + 1u - k;
				return k;
			}
		}
		from = k + 1u;
	}
	return n;
}

/* The end of "<%-- ... --%>" that begins at `at`: the offset of its "--%>", n when it never closes. */
static uint32_t dash_close(const uint8_t *p, uint32_t n, uint32_t at)
{
	uint32_t e;

	for (e = at + 4u; e + 3u < n && memcmp(p + e, "--%>", 4u) != 0; e++)
		;
	return e + 3u < n ? e : n;
}

/* A directive's first word, compared to `w`: <%@ WebHandler ... %> */
static int directive_is(const uint8_t *p, uint32_t s, uint32_t e, const char *w)
{
	uint32_t l = (uint32_t)strlen(w);

	while (s < e && kof_is_space_byte(p[s]))
		s++;
	return e - s >= l && word_eq(p + s, w, l) && (s + l == e || !kgenome_textual_ident(p[s + l]));
}

/* The value of the first attribute `language` in the directive window [s, e). */
static int directive_language(const uint8_t *p, uint32_t s, uint32_t e, uint32_t *vs, uint32_t *ve)
{
	struct page_attr a;

	while (attr_next(p, e, &s, &a)) {
		if (attr_is(p, &a, "language") && a.has_value) {
			*vs = a.vs;
			*ve = a.ve;
			return 1;
		}
	}
	return 0;
}

/*
 * THE LANGUAGE THE PAGE NAMES: the value of the first Language attribute of a directive, else, with `script`,
 * of the first <script runat="server"> that has one. The walk is the page's own - an island is skipped
 * from "<%" to "%>", a server script's body from its tag to its end tag - so a directive or a script tag
 * written inside a string of an island is not read. Every directive is looked at, not only the first: the
 * Language attribute belongs to Page, Control, Master, WebHandler or WebService and an Import or an
 * Assembly may come before it [Inference: from the asp.net directive reference; the five .aspx files of the
 * sample trees all begin with Page, so none of them tests the order].
 */
static int find_language(const struct kgenome_textual_page *pg, const uint8_t *p, uint32_t n, int scripts,
			 uint32_t *vs, uint32_t *ve)
{
	struct page_scan ps;
	uint32_t i = 0;

	scan_init(&ps, n);
	while (i < n) {
		const uint8_t *q = memchr(p + i, '<', n - i);
		struct page_script sc;
		uint32_t at, e, k, len;

		if (!q)
			break;
		at = (uint32_t)(q - p);
		i = at + 1u;
		if (at + 1u < n && p[at + 1u] == '%') {
			if (pg->dash_comment && at + 3u < n && p[at + 2u] == '-' && p[at + 3u] == '-') {
				e = dash_close(p, n, at);
				i = e < n ? e + 4u : n;
				continue;
			}
			e = find_close(p, n, at + 2u);
			if (at + 2u < n && p[at + 2u] == '@') {
				if (!scripts && directive_language(p, at + 3u, e, vs, ve))
					return 1;
				if (pg->directive_code && (directive_is(p, at + 3u, e, "webhandler") ||
							   directive_is(p, at + 3u, e, "webservice")))
					return 0;
			}
			i = e < n ? e + 2u : n;
		} else if (pg->server_script && at + 7u < n && (e = script_tag(&ps, p, n, at, &sc)) != 0 && sc.server) {
			if (sc.has_lang && scripts) {
				*vs = sc.lvs;
				*ve = sc.lve;
				return 1;
			}
			k = script_close(p, n, e, &len);
			i = k < n ? k + len : n;
		}
	}
	return 0;
}

/* The language the page's islands are in: what its directive names, else langs[0]. NULL for a one language page. */
static const struct kgenome_textual_script_lang *page_lang(const struct kgenome_textual_page *pg,
							   const uint8_t *p, uint32_t n)
{
	const struct kgenome_textual_script_lang *l;
	uint32_t vs, ve;

	if (!pg->langs)
		return NULL;
	/* a directive's language wins wherever it stands; the script elements are asked only when none has one */
	if (find_language(pg, p, n, 0, &vs, &ve) || (pg->lang_from_script && find_language(pg, p, n, 1, &vs, &ve)))
		l = lang_pick(pg, p, vs, ve);
	else
		l = NULL;
	return l ? l : &pg->langs[0];
}

/*
 * THE PAIRS OF BYTES THAT CLOSING UP WOULD MAKE SOMETHING ELSE OF, for a page whose island may be in any of
 * vbscript, jscript and c# (the row has one glue and the page is read before it is known which). Each
 * group is a pair some one of the three reads as a longer token or as something that is not code:
 *   - the same operator byte twice: "& &", "+ +", "- -", "/ /", "< <", "= =", "? ?" ...;
 *   - an operator and "=": the compound assignments and comparisons of all three ("+=", "<=", "!=", ":=");
 *   - "< >" "= >" "- >" "= <" "? .": "<>" (vb), "=>" (c#, js), "->" (c#), "=<" (vb), "?." (c#, js);
 *   - "/ *" starts a comment and "* /" is not asked: it is not a token outside one;
 *   - a digit and ".": "1 .ToString()" is a call on an int, "1.ToString()" is a malformed number;
 *   - "&" and h, o, b: "& Hex(x)" is a concatenation, "&Hex(x)" is a hex literal in vb;
 *   - "%" and ">" would end the island, "<" and "/" would end a script element (</script>): the form must
 *     not write either where the text had neither;
 *   - "%" and a byte that can follow "<%": closing "<% @x" up to "<%@x" makes a directive of code;
 *   - "@" or "$" and a quote or each other: c#'s @"..." and $"..." - `e@ "a"` closed up begins a verbatim string.
 * A bracket, a comma or a semicolon followed by itself is two tokens, and is not asked.
 */
int kgenome_textual_glue_web(uint8_t a, uint8_t b)
{
	if (kgenome_textual_glue_twice(a, b, "&+-*/\\^=<>!|.:?~%") || kgenome_textual_glue_assign(a, b, "+-*/\\^&|%<>!:?"))
		return 1;
	if ((a == '<' && (b == '>' || b == '/')) || (a == '=' && (b == '>' || b == '<')) ||
	    (a == '-' && b == '>') || (a == '?' && b == '.') || (a == '/' && b == '*'))
		return 1;
	if (a == '%' && kof_byte_in_set(b, ">@#$:!-"))
		return 1;
	if (kof_byte_in_set(a, "@$") && kof_byte_in_set(b, "\"@$"))
		return 1;
	if (kof_is_digit(a) && b == '.')
		return 1;
	if (a == '&' && (kof_is_digit(b) || kof_byte_in_set((uint8_t)(b | 0x20u), "hob")))
		return 1;
	return kgenome_textual_vb_glue(a, b);       /* and vbscript's own rules: the page's island may be vb */
}

/* The next byte the page has to look at: "<", and when the page has a markup hook "$" and "#" as well. */
static const uint8_t *next_open(const uint8_t *p, uint32_t n, uint32_t i, int hook)
{
	if (!hook)
		return memchr(p + i, '<', n - i);
	for (; i < n; i++)
		if (p[i] == '<' || p[i] == '$' || p[i] == '#')
			return p + i;
	return NULL;
}

void kgenome_textual_page_lex(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = 0;
	const struct kgenome_textual_script_lang *dl = page_lang(pg, p, n);
	struct page_scan ps;

	scan_init(&ps, n);
	if (pg->fragment_code && lx->fragment) {
		run_body(lx, pg, dl, n);
		return;
	}
	while (i < n) {
		const uint8_t *q = next_open(p, n, i, pg->markup != NULL);
		uint32_t at, e;

		if (!q)
			break;
		at = (uint32_t)(q - p);
		if (p[at] == '<' && at + 1u < n && p[at + 1u] == '%') {
			uint32_t tag = 2u;

			if (!kgenome_textual_markup_to(lx, at))
				return;
			if (pg->dash_comment && at + 3u < n && p[at + 2u] == '-' && p[at + 3u] == '-') {
				/* the comment of the page, to "--%>"; not closed it runs to the end, open */
				e = dash_close(p, n, at);
				if (!kgenome_textual_lit(lx, at, e < n ? e + 4u : n, KGENOME_TEXTUAL_COMMENT, 0, 4u, 4u, e < n) || e >= n)
					return;
				i = e + 4u;
				continue;
			}
			if (at + 2u < n && p[at + 2u] == '@') {
				/* a directive is the page's own, and is markup */
				e = find_close(p, n, at + 3u);
				i = e < n ? e + 2u : n;
				if (!kgenome_textual_emit(lx, i - at, KGENOME_TEXTUAL_MARKUP, 0, 0, 0))
					return;
				if (pg->directive_code && (directive_is(p, at + 3u, e, "webhandler") ||
							   directive_is(p, at + 3u, e, "webservice"))) {
					/* an .ashx or .asmx: what follows its directive is the source, whole */
					run_body(lx, pg, dl, n);
					return;
				}
				continue;
			}
			if (at + 2u < n && kof_byte_in_set(p[at + 2u], pg->tag3 ? pg->tag3 : "=!#$"))
				tag = 3u;
			if (!kgenome_textual_emit(lx, tag, KGENOME_TEXTUAL_TAG, 0, 0, 0))
				return;
			e = find_close(p, n, at + tag);
			if (!island(lx, pg, dl, e, 2u))
				return;
			i = lx->pos;
			continue;
		}
		if (pg->server_script && p[at] == '<' && at + 7u < n) {
			struct page_script sc;

			e = script_tag(&ps, p, n, at, &sc);
			if (e && sc.server) {
				/* its own language when it names one the page knows, else the page's */
				const struct kgenome_textual_script_lang *sl =
					sc.has_lang && pg->langs ? lang_pick(pg, p, sc.lvs, sc.lve) : NULL;
				uint32_t len, k = script_close(p, n, e, &len);

				if (!kgenome_textual_markup_to(lx, at) ||
				    !kgenome_textual_emit(lx, e - at, KGENOME_TEXTUAL_TAG, 0, 0, 0))
					return;
				if (k >= n) {
					/* no end tag: the code runs to the end of the text */
					run_body(lx, pg, sl ? sl : dl, n);
					return;
				}
				if (!island(lx, pg, sl ? sl : dl, k, len))
					return;
				i = lx->pos;
				continue;
			}
		}
		if (pg->markup && (e = pg->markup(lx, pg, at)) != 0) {
			if (lx->refused)
				return;
			i = e;
			continue;
		}
		i = at + 1u;
	}
	kgenome_textual_markup_to(lx, n);
}
