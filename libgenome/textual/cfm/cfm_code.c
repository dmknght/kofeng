/*
 * cfm_code.c - the code of coldfusion: strings, comments and "#...#", in the three places code is (enum kgenome_cfm_mode).
 *
 * WHAT IS ONE THING HERE, from the CFML documentation and the three real files of the corpus [Unverified: there is no
 * ColdFusion engine on this machine; every rule below is the documented one, not an observed one]:
 *
 *   a string      "..." or '...'. No backslash escape: a quote is written twice ("a""b"), a "#" is written "##", and
 *                 "#expr#" is an expression whose value goes into the string. The expression may hold strings of its
 *                 own, with the SAME quote (shell.cfm: "#StructFind(FORM, "authCode")#"), so a string is not "up to the
 *                 next quote": it is read with the expression in it. It may run over lines. Both quotes interpolate.
 *   a comment     "<!--- ... --->" in a tag and in markup, and it NESTS (the depth is a counter, which costs nothing
 *                 and so has no cap); slash-slash and the C block comment in cfscript only. In a tag they are not
 *                 comments: they are what an unquoted attribute value or an operator can hold.
 *   a tag's end   the first ">" that is outside a string, a comment and a "#...#". "/>" and "/ >" end it too and are
 *                 delivered as the tag's end, so that the "/" is not code (and the form, which closes up white space in
 *                 front of a tag, cannot turn "/ >" into "/>" and change its own mind on the next pass).
 *
 * "#...#" IN A STRING, in a tag outside any string, and in output text (cfm_lex.c). It is read to the first "#" that is not
 * inside a string of its own. NESTING: a string in an expression in a string ... is read by recursion, which is bounded
 * by CFM_MAX_NEST: that is a bound on the STACK, and the one thing it does on reaching it is to answer "not closed", the
 * same as running out of text. THAT ANSWER IS REMEMBERED (lx->aux): a "#" that never closes would otherwise read to the
 * end for every "#" after it. Once it fails, strings stop interpolating for the rest of the text (their own "#" is text,
 * so the quote ends them) and nothing is lost: every byte is still in a span, the string is plain where it was not
 * understood. Measured, -O2: 8 MB of each of 26 texts whose "#", quote, comment or tag never closes ("\"#", "<cfif #",
 * "<cfoutput>#'", "<!---<!---", ...), as a page and as a fragment, slowest 0.032 s - about 250 MB/s, the same as text that closes.
 */

#include "cfm.h"

#define CFM_MAX_NEST 64u        /* a bound on recursion, not on results: see above */

#define HS_TAGS 0x1u    /* a tag ends the expression before it closes (output text) */
#define HS_CMT  0x2u    /* a cf comment in the body is a gap; and the body must hold something else (markup, a tag) */

static uint32_t hash_scan(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t k, uint32_t depth, uint32_t how);

/* The string whose opening quote is at `j`, read with its "#...#": where it ends, and whether it closed. */
static uint32_t str_scan(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t j, uint32_t depth, int *closed)
{
	const uint8_t *p = lx->p;
	uint8_t q = p[j];
	uint32_t k = j + 1u;

	*closed = 0;
	while (k < end) {
		uint8_t c = p[k];

		if (c == q) {
			if (k + 1u < end && p[k + 1u] == q) {
				k += 2u;
				continue;
			}
			*closed = 1;
			return k + 1u;
		}
		if (c == '#' && !(lx->aux & KGENOME_CFM_MEMO_STR)) {
			uint32_t e;

			if (k + 1u < end && p[k + 1u] == '#') {
				k += 2u;
				continue;
			}
			e = hash_scan(lx, end, k, depth + 1u, 0);
			if (e) {
				k = e;
				continue;
			}
			lx->aux |= KGENOME_CFM_MEMO_STR;
			k = j + 1u;             /* this string again, now as text */
			continue;
		}
		k++;
	}
	return end;
}

/*
 * The "#" at `k` opens an expression: the offset after the "#" that closes it, or 0. A string in it is skipped whole.
 * In output text (HS_TAGS) a tag ends it before it closes - a "#" with no partner is text, and the tags after it are tags
 * [Unverified: that CF reads a text node's expressions up to the next tag is the documented model, not an observation;
 * the other reading would let a stray "#" hide every tag up to the next "#"].
 * HS_CMT, for the two places a comment can stand in an expression (output text and a tag): the comment is skipped whole
 * and is a comment, and a body of nothing but blanks and comments is not an expression. Both are for the form, which drops
 * a comment: `#a <!--- c ---> b#` must be the same expression after as before, and `#<!--- c --->#` would become "##",
 * which is a literal "#" and not an expression. In a string no comment is looked for.
 */
static uint32_t hash_scan(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t k, uint32_t depth, uint32_t how)
{
	const uint8_t *p = lx->p;
	uint32_t i = k + 1u, nm;
	int real = !(how & HS_CMT);

	if (depth > CFM_MAX_NEST)
		return 0;
	while (i < end) {
		uint8_t c = p[i];

		if (c == '#')
			return real ? i + 1u : 0u;
		if (c == '"' || c == '\'') {
			int closed;

			i = str_scan(lx, end, i, depth, &closed);
			if (!closed)
				return 0;
			real = 1;
			continue;
		}
		if (c == '<' && i + 5u <= end && memcmp(p + i, "<!---", 5u) == 0 && (how & HS_CMT)) {
			int closed;

			i = kgenome_textual_cfm_comment_end(p, end, i, &closed);
			if (!closed)
				return 0;
			continue;
		}
		if ((how & HS_TAGS) && c == '<' && kgenome_textual_cfm_tag_name(p, end, i, &nm))
			return 0;
		if (!kof_is_space_byte(c))
			real = 1;
		i++;
	}
	return 0;
}

uint32_t kgenome_textual_cfm_hash(struct kgenome_textual_lexer *lx, uint32_t at)
{
	uint32_t e = hash_scan(lx, lx->n, at, 0, HS_TAGS | HS_CMT);

	if (!e)
		lx->aux |= KGENOME_CFM_MEMO_HASH;
	return e;
}

uint32_t kgenome_textual_cfm_comment_end(const uint8_t *p, uint32_t end, uint32_t at, int *closed)
{
	uint32_t depth = 1, j = at + 5u;

	*closed = 0;
	while (j < end) {
		uint8_t c = p[j];

		if (c == '<' && j + 5u <= end && memcmp(p + j, "<!---", 5u) == 0) {
			depth++;
			j += 5u;
		} else if (c == '-' && j + 4u <= end && memcmp(p + j, "--->", 4u) == 0) {
			j += 4u;
			if (--depth == 0) {
				*closed = 1;
				return j;
			}
		} else {
			j++;
		}
	}
	return end;
}

uint32_t kgenome_textual_cfm_tag_name(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *name_at)
{
	uint32_t j = i + 1u;

	if (i >= n || p[i] != '<')
		return 0;
	if (j < n && p[j] == '/')
		j++;
	/* "cf" and a letter or "_": cf_mytag is a custom tag; "<cf>" and the "<cf" of prose are not tags */
	if (j + 2u >= n || (p[j] | 0x20u) != 'c' || (p[j + 1u] | 0x20u) != 'f' ||
	    !(kof_is_alpha(p[j + 2u]) || p[j + 2u] == '_'))
		return 0;
	*name_at = j;
	for (j += 3u; j < n && kgenome_textual_ident(p[j]); j++)
		;
	return j;
}

uint32_t kgenome_textual_cfm_closer(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint32_t j = i;

	if (j < n && p[j] == '/') {
		for (j++; j < n && kof_is_space_byte(p[j]); j++)
			;
	}
	return j < n && p[j] == '>' ? j + 1u - i : 0u;
}

/* The "#...#" at `i` in a tag, outside a string: its body is lexed as code, so a ">" in it is not the tag's end. */
static uint32_t tag_hash(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t i)
{
	uint32_t e;

	if (i + 1u < end && lx->p[i + 1u] == '#')
		return i + 2u;
	e = hash_scan(lx, end, i, 0, HS_CMT);
	if (!e) {
		lx->aux |= KGENOME_CFM_MEMO_HASH;
		return i + 1u;
	}
	kgenome_textual_cfm_code(lx, e, KGENOME_CFM_EXPR);
	return e;
}

uint32_t kgenome_textual_cfm_code(struct kgenome_textual_lexer *lx, uint32_t end, enum kgenome_cfm_mode mode)
{
	const uint8_t *p = lx->p;
	uint32_t i = lx->pos;
	int ok = 1;

	while (i < end && ok) {
		uint8_t c = p[i];
		int closed;
		uint32_t j;

		if (c == '/' && mode == KGENOME_CFM_SCRIPT && i + 1u < end && (p[i + 1u] == '/' || p[i + 1u] == '*')) {
			i = kgenome_textual_c_comment(lx, end, i, &ok);
		} else if (c == '<' && mode != KGENOME_CFM_SCRIPT && i + 5u <= end && memcmp(p + i, "<!---", 5u) == 0) {
			j = kgenome_textual_cfm_comment_end(p, end, i, &closed);
			ok = kgenome_textual_lit(lx, i, j, KGENOME_TEXTUAL_COMMENT, 0, 5u, 4u, closed);
			i = j;
		} else if (c == '"' || c == '\'') {
			j = str_scan(lx, end, i, 0, &closed);
			ok = kgenome_textual_lit(lx, i, j, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1u, 1u, closed);
			i = j;
		} else if (mode == KGENOME_CFM_TAG && c == '#' && !(lx->aux & KGENOME_CFM_MEMO_HASH)) {
			i = tag_hash(lx, end, i);
			ok = !lx->refused;
		} else if (mode == KGENOME_CFM_TAG && (c == '>' || c == '/') && kgenome_textual_cfm_closer(p, end, i)) {
			return kgenome_textual_code_to(lx, i) ? i : end;
		} else {
			i++;
		}
	}
	if (ok)
		(void)kgenome_textual_code_to(lx, end);
	return end;
}
