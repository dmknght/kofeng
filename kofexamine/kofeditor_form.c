#define _GNU_SOURCE

/*
 * kofeditor_form.c - the form of a unit: the diagnose source text each condition and each block matcher is written as, through the shared diagsrc printer.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


/*
 * THE DETECTION PART OF A UNIT, as the declarations a diagnose source reads (databases/diagsrc.h, the form).
 *
 * A PATTERNS CONDITION is the markers of the matchers its expression names, a range for each distinct region they search,
 * the matchers, and the expression over them; a BLOCKS MATCHER is the blocks it holds, and itself. Every line is a diagsrc
 * item, printed by the shared printer: this file has no string code of its own for a declaration, and it computes nothing
 * the engine decides - what a marker matches, what a block scores are the engine's, this only says what was drawn.
 *
 * WHAT HAS NO SPELLING IS REFUSED WITH A REASON, never written in a way that means something else: a marker with a byte a
 * literal cannot spell is a hex pattern, and where a hex pattern cannot hold what the marker means (a wide marker with such
 * a byte, a regex the panel has no wire for) the unit is not written. The caller checks the output with the reader the
 * builder uses, so a file Generate writes is one the builder accepts.
 */

#define FORM_NAME_MAX 24u

/* Add an item to `d` or say why not. */
static struct kof_dsrc_item *form_item(struct kof_dsrc *d, unsigned kind, const char **why)
{
	struct kof_dsrc_item *it;

	if (d->n >= KOF_DSRC_MAX_ITEM) {
		*why = "it needs more declarations than a diagnose source holds";
		return NULL;
	}
	it = &d->item[d->n];
	memset(it, 0, sizeof *it);
	it->kind = (uint8_t)kind;
	return it;
}

static int form_text(struct kof_dsrc *d, const char **t, uint32_t *n, const char *p, size_t len, const char **why)
{
	const char *q = kof_dsrc_text(d, p, len);

	if (!q) {
		*why = "its declarations are over the size of the source reader's text pool";
		return 0;
	}
	*t = q;
	*n = (uint32_t)len;
	return 1;
}

/* A mask in the KOF_SCAN_* words of the formats the header targets. The whole file, the symbol halves and every region a
 * target format names are spelled; a bit no such format names has no word and the unit is refused. */
static const char *form_mask_words(const struct kof_editor *e, uint32_t mask, char *out, size_t cap)
{
	uint32_t b;
	size_t at = 0;

	if (mask & KOF_SCAN_ALL) {
		snprintf(out, cap, "KOF_SCAN_ALL");
		return NULL;
	}
	out[0] = 0;
	for (b = 0; b < 32u; b++) {
		const char *w = NULL;
		uint32_t f;

		if (!(mask & (1u << b)))
			continue;
		if ((1u << b) == KOF_SCAN_SYM_IMP)
			w = "KOF_SCAN_SYM_IMP";
		else if ((1u << b) == KOF_SCAN_SYM_EXP)
			w = "KOF_SCAN_SYM_EXP";
		/* The word the source reader knows, from the first of the header's formats that has this region. */
		for (f = 0; !w && f < KOF_FMT_COUNT; f++)
			if (e->dr.fmt_mask & (1u << f))
				w = kof_dsrc_region_word((uint8_t)f, 1u << b);
		if (!w)
			return "it searches a region that none of the formats the header targets names";
		if (at + strlen(w) + 4u >= cap)
			return "its region mask is too long";
		at += (size_t)snprintf(out + at, cap - at, "%s%s", at ? " | " : "", w);
	}
	if (!at)
		return "it searches no region";
	/* The words mean the mask when the reader reads them back: every region of every format reads as itself (tests/unit/diagsrc_form.c,
	 * "words"), and a bit with no name was refused above. */
	return NULL;
}

/* One marker as a KDS_STR item named `name`. */
static const char *form_str(struct kof_dsrc *d, const struct decl *dc, const char *name)
{
	const char *why = NULL;
	struct kof_dsrc_item *it;
	char probe[2u * KOF_DSRC_LIT_MAX + 8u];
	unsigned opt = 0;
	int lit_ok;
	uint32_t i;

	if (dc->hex == DECL_RX)
		return "it has a regex marker, which the panel has no wire for yet";
	if (!dc->nbytes && !(dc->hex && dc->hexs[0]))
		return "it has an empty marker";
	if (dc->nbytes > KOF_DSRC_LIT_MAX && !(dc->hex && dc->hexs[0]))
		return "it has a marker over 512 bytes";
	if (!(it = form_item(d, KDS_STR, &why)))
		return why;
	snprintf(it->s1, sizeof it->s1, "%s", name);
	if (dc->icase)
		opt |= KDS_OPT_ICASE;
	if (dc->fullword == KOF_WORD_FULLWORD)
		opt |= KDS_OPT_FULLWORD;
	else if (dc->fullword == KOF_WORD_TOKEN)
		opt |= KDS_OPT_TOKEN;
	if (dc->hex && dc->hexs[0]) {
		/* A pattern as it was written. The panel's search ignores the options of a pattern (decl_pattern); one the
		 * author set is the author's, and the engine applies it, so it is written. */
		size_t L = strlen(dc->hexs);

		if (L > KOF_DSRC_TEXT_MAX)
			return "it has a hex pattern over 511 characters";
		it->a = KDS_STR_HEX;
		it->b = (uint16_t)(opt ? (opt | KDS_OPT_GIVEN) : 0u);
		if (!form_text(d, &it->t1, &it->n1, dc->hexs, L, &why))
			return why;
		d->n++;
		return NULL;
	}
	lit_ok = kof_dsrc_lit_escape(dc->bytes, dc->nbytes, probe, sizeof probe) != 0;
	if (dc->wide) {
		/* ASCII only: a byte above 0x7E or below a space has no escape, so lit_ok already says no for it */
		if (!lit_ok)
			return "it has a wide marker with a byte that has no text spelling";
		it->a = KDS_STR_WIDE;
		it->b = (uint16_t)(opt | KDS_OPT_GIVEN);
	} else if (lit_ok) {
		it->a = KDS_STR_PLAIN;
		/* A pattern declared from a selection is concrete bytes: the panel's search applied the options only to a
		 * literal (decl_pattern), so a hex one has the defaults. */
		it->b = (uint16_t)((dc->hex ? 0u : opt) | KDS_OPT_GIVEN);
	} else {
		/* A byte a literal cannot spell: the same bytes as a hex pattern. */
		char hx[KOF_DSRC_TEXT_MAX + 1u];
		size_t at = 0;

		if ((size_t)dc->nbytes * 3u > KOF_DSRC_TEXT_MAX)
			return "it has a marker of more than 170 bytes that needs a hex pattern";
		for (i = 0; i < dc->nbytes; i++)
			at += (size_t)snprintf(hx + at, sizeof hx - at, "%s%02X", i ? " " : "", (unsigned)dc->bytes[i]);
		it->a = KDS_STR_HEX;
		it->b = (uint16_t)((dc->hex ? 0u : opt) ? ((dc->hex ? 0u : opt) | KDS_OPT_GIVEN) : 0u);
		if (!form_text(d, &it->t1, &it->n1, hx, at, &why))
			return why;
		d->n++;
		return NULL;
	}
	if (!form_text(d, &it->t1, &it->n1, (const char *)dc->bytes, dc->nbytes, &why))
		return why;
	d->n++;
	return NULL;
}

/* The expression of a condition in the source's operators and the matchers' names ("m1 && !m2"). */
static const char *form_expr(const struct kof_editor *e, const struct cond *c, char *out, size_t cap)
{
	const char *p = c->expr;
	size_t at = 0;
	int depth = 0;

	out[0] = 0;
	for (; *p; p++) {
		const char *t = NULL;
		char num[24];

		if (*p == ' ')
			continue;
		if (*p >= '0' && *p <= '9') {
			unsigned long n = 0;

			while (*p >= '0' && *p <= '9' && n < 1000ul)
				n = n * 10ul + (unsigned long)(*p++ - '0');
			p--;
			snprintf(num, sizeof num, "m%lu", n);
			t = num;
		} else if (*p == '&') {
			t = " && ";
			if (p[1] == '&')
				p++;
		} else if (*p == '|') {
			t = " || ";
			if (p[1] == '|')
				p++;
		} else if (*p == '!') {
			t = "!";
		} else if (*p == '(' || *p == ')') {
			depth += *p == '(' ? 1 : -1;
			if (depth < 0)
				return "its expression has a parenthesis that does not match";
			t = *p == '(' ? "(" : ")";
		} else {
			return "its expression has a character a diagnose cannot say";
		}
		if (at + strlen(t) + 1u >= cap)
			return "its expression is too long";
		at += (size_t)snprintf(out + at, cap - at, "%s", t);
	}
	(void)e;
	if (depth)
		return "its expression has a parenthesis that does not match";
	return at ? NULL : "its expression names no matcher";
}

/* The declarations of one PATTERNS condition. */
static const char *form_condition(const struct kof_editor *e, uint32_t ci, struct kof_dsrc *d)
{
	const struct cond *c = &e->dr.cnd[ci];
	const char *why = NULL;
	uint32_t g, i, n_rng = 0, rng_mask[MAX_GROUP];
	char expr[256];
	struct kof_dsrc_item *it;

	if ((why = form_expr(e, c, expr, sizeof expr)) != NULL)
		return why;
	/* (A matcher that is not on this tab was refused before any text is made: draft_generate_with.)
	 * The ranges, one per distinct mask of the matchers that search. */
	for (g = 0; g < e->dr.n_grp; g++) {
		const struct group *q = &e->dr.grp[g];
		uint32_t mask, k;
		char words[256];

		if (!cnd_uses(e, c, g) || grp_is_at(q->rule))     /* cnd_uses: a matcher of the Patterns tab, which is a string matcher */
			continue;
		mask = grp_mask((struct kof_editor *)(uintptr_t)e, g);
		for (k = 0; k < n_rng && rng_mask[k] != mask; k++)
			;
		if (k < n_rng)
			continue;
		if ((why = form_mask_words(e, mask, words, sizeof words)) != NULL)
			return why;
		if (!(it = form_item(d, KDS_RANGE, &why)))
			return why;
		snprintf(it->s1, sizeof it->s1, "r%u", (unsigned)n_rng);
		it->v = mask;
		if (!form_text(d, &it->t1, &it->n1, words, strlen(words), &why))
			return why;
		d->n++;
		rng_mask[n_rng++] = mask;
	}
	/* The markers the matchers use, once each. */
	/* Asked of each marker in turn: the table has no capacity, so no word of 32 bits can stand for "which are used" (a cap that dropped marker 33 on). */
	for (i = 0; i < e->dr.n_decl; i++) {
		char name[FORM_NAME_MAX];

		for (g = 0; g < e->dr.n_grp; g++)
			if (cnd_uses(e, c, g) && (e->dr.decl[i].grp & (1u << g)))
				break;
		if (g == e->dr.n_grp)
			continue;
		snprintf(name, sizeof name, "s%u", i);
		if ((why = form_str(d, &e->dr.decl[i], name)) != NULL)
			return why;
	}
	/* The matchers. */
	for (g = 0; g < e->dr.n_grp; g++) {
		const struct group *q = &e->dr.grp[g];
		char names[KOF_FORM_MAX_ARG * (FORM_NAME_MAX + 2u)];
		size_t at = 0;
		uint32_t k = 0, mask;

		if (!cnd_uses(e, c, g))
			continue;
		for (i = 0; i < e->dr.n_decl; i++)
			if (e->dr.decl[i].grp & (1u << g)) {
				if (at + FORM_NAME_MAX + 2u >= sizeof names)
					return "a matcher lists more markers than a diagnose allows";
				at += (size_t)snprintf(names + at, sizeof names - at, "%ss%u", k ? ", " : "", (unsigned)i);
				k++;
			}
		if (!k)
			return "it names a matcher with no marker";
		if (k > KOF_FORM_MAX_ARG)
			return "a matcher lists more than sixteen markers";
		if (!(it = form_item(d, KDS_FIND, &why)))
			return why;
		snprintf(it->s1, sizeof it->s1, "m%u", (unsigned)grp_loc(e, g));
		it->a = (uint16_t)(q->rule > 3 ? 0 : q->rule);
		if (grp_is_at(q->rule)) {
			if (k != 1u)
				return "an AT matcher compares ONE marker";
			it->b = q->at_anchor;
			it->v = (uint64_t)q->at_off;
		} else {
			uint32_t kk;

			mask = grp_mask((struct kof_editor *)(uintptr_t)e, g);
			for (kk = 0; kk < n_rng && rng_mask[kk] != mask; kk++)
				;
			snprintf(it->s2, sizeof it->s2, "r%u", (unsigned)kk);
			if (q->rule == 2) {
				uint32_t th = grp_thresh_eff((struct kof_editor *)(uintptr_t)e, g);

				if (th < 1u || th > k || th > 255u)
					return "a threshold the matcher cannot reach";
				it->b = (uint16_t)th;
			}
		}
		if (!form_text(d, &it->t1, &it->n1, names, at, &why))
			return why;
		d->n++;
	}
	if (!(it = form_item(d, KDS_EXPR, &why)))
		return why;
	if (!form_text(d, &it->t1, &it->n1, expr, strlen(expr), &why))
		return why;
	d->n++;
	return NULL;
}

/* The declarations of one BLOCKS matcher: its blocks, and itself. */
static const char *form_block_matcher(const struct kof_editor *e, uint32_t g, struct kof_dsrc *d)
{
	const struct group *q = &e->dr.grp[g];
	const char *why = NULL;
	struct kof_dsrc_item *it;
	char names[KOF_FORM_MAX_ARG * (FORM_NAME_MAX + 2u)];
	size_t at = 0;
	uint8_t k;

	if (!q->n_sim)
		return "it holds no block";
	if (q->n_sim > KOF_FORM_MAX_ARG)
		return "it holds more than sixteen blocks";
	if (q->pct < 1u || q->pct > 100u)
		return "its threshold is not a percentage from 1 to 100";
	for (k = 0; k < q->n_sim; k++) {
		const struct mtn_block *b;
		char words[64], name[FORM_NAME_MAX];
		uint32_t mask = 0, j;

		if (q->sim[k].what != SIM_IT_BLOCK || q->sim[k].blk >= e->dr.n_blk || !e->dr.blk)
			return "it holds a measure that is not a block";
		b = &e->dr.blk[q->sim[k].blk];
		/* The region the block was cut from, in the engine's own spelling. */
		snprintf(words, sizeof words, "%s", !b->rgn_enum[0] ? "KOF_SCAN_ALL" : b->rgn_enum);
		if (!kof_dsrc_mask_of(words, &mask, NULL, 0))
			return "a block's region has no name the source reader knows";
		if (b->n_hash < kgenome_mutation_block_min(mask) || b->n_hash > KOF_FORM_HASH_MAX)
			return "a block has too few or too many hashes";
		snprintf(name, sizeof name, "b%u", (unsigned)q->sim[k].blk);
		/* a block named twice is one block */
		for (j = 0; j < k; j++)
			if (q->sim[j].blk == q->sim[k].blk)
				return "it names a block twice";
		if (!(it = form_item(d, KDS_BLOCK, &why)))
			return why;
		snprintf(it->s1, sizeof it->s1, "%s", name);
		it->b = b->side == (uint8_t)KGENOME_MUTATION_SIDE_LIB ? 1u : 0u;
		it->v = mask;
		if (!form_text(d, &it->t1, &it->n1, words, strlen(words), &why) ||
		    !form_text(d, &it->t2, &it->n2, (const char *)b->hash, (size_t)b->n_hash * sizeof b->hash[0], &why))
			return why;
		d->n++;
		at += (size_t)snprintf(names + at, sizeof names - at, "%s%s", k ? ", " : "", name);
	}
	if (!(it = form_item(d, KDS_SIMILAR, &why)))
		return why;
	snprintf(it->s1, sizeof it->s1, "m%u", (unsigned)grp_loc(e, g));
	it->a = q->pct;
	if (!form_text(d, &it->t1, &it->n1, names, at, &why))
		return why;
	d->n++;
	return NULL;
}

/* THE DETECTION DECLARATIONS OF UNIT (is_grp, idx) appended to `d`: NULL, or the reason the unit cannot be written. */
const char *draft_unit_form(const struct kof_editor *e, int is_grp, uint32_t idx, struct kof_dsrc *d)
{
	return is_grp ? form_block_matcher(e, idx, d) : form_condition(e, idx, d);
}
