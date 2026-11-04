#define _GNU_SOURCE

/*
 * kofeditor_cond.c - conditions of a draft: the expression text a condition holds, the matcher ids inside it, and the rewrite verbs (drop, negate, swap, shift).
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


/* What this matcher searches: what it was told, or the narrowest that holds
 * what it has. */
/*
 * Does this condition's expression name matcher `g`.
 *
 * Compared as a number rather than a character, because matcher 1 and matcher
 * 12 share a digit and a substring test would report the wrong one - which
 * would show up as a row listing matchers it does not use, and only on drafts
 * big enough that nobody was checking by hand any more.
 *
 * An empty expression names all of them, which is what it generates.
 */
/*
 * The next matcher id in an expression, and whether it is negated.
 *
 * ONE SCANNER, because every walk over these ids has to agree about where a
 * "!" belongs - does this condition name that matcher, is that one negated,
 * rewrite the list without it, renumber it. Written four times it would be four
 * places for the "!" to be lost, and a lost "!" is a condition that generates
 * the opposite of what the panel shows.
 *
 * A "!" negates only the number it actually reaches. "!(" is a parenthesis the
 * author typed around a group, and the group is not this list's to speak for -
 * so it is left to the emitter, which passes it through, and to cnd_canon,
 * which will disagree with the text and let the text be shown as typed.
 *
 * Returns 0 at the end of the expression.
 */
static int cnd_next_id(const char **pp, unsigned long *id, int *neg)
{
	const char *p = *pp;
	int n = 0;

	while (*p) {
		if (*p == '!') {
			/* Toggled: form_expr writes every "!" it is given, so "!!1"
			 * is two negations in the file and must be two here. A "!"
			 * that reaches no number ("!(") is reset by the next byte. */
			n = !n;
			p++;
			while (*p == ' ')
				p++;
			continue;
		}
		if (*p >= '0' && *p <= '9') {
			char *end;

			*id = strtoul(p, &end, 10);
			*neg = n;
			*pp = end;
			return 1;
		}
		n = 0;
		p++;
	}
	*pp = p;
	return 0;
}


int cnd_has_id(const struct cond *c, uint32_t id)
{
	const char *p = c->expr;
	unsigned long n;
	int neg;

	while (cnd_next_id(&p, &n, &neg))
		if (n == (unsigned long)id)
			return 1;
	return 0;
}

unsigned long cnd_foreign(const struct kof_editor *e, const struct cond *c)
{
	const char *p = c->expr;
	unsigned long n;
	int neg;

	while (cnd_next_id(&p, &n, &neg))
		if (n < 1ul || n > (unsigned long)grp_tab_count(e, DT_PATTERNS))
			return n + 1ul;
	return 0;
}

int cnd_uses(const struct kof_editor *e, const struct cond *c, uint32_t g)
{
	(void)c;
	return g < e->dr.n_grp && grp_tab(e, g) == DT_PATTERNS &&
	       cnd_has_id(c, grp_loc(e, g));
}

/*
 * Is this condition asking for that matcher to be ABSENT.
 *
 * Separate from cnd_uses because they are different questions and the panel
 * asks both: an id is drawn when the condition uses it, and drawn with a "!"
 * when the condition wants it missing.
 */
int cnd_neg(const struct kof_editor *e, const struct cond *c, uint32_t g)
{
	const char *p = c->expr;
	unsigned long n;
	int neg;

	if (!cnd_uses(e, c, g))
		return 0;
	while (cnd_next_id(&p, &n, &neg))
		if (n == (unsigned long)grp_loc(e, g))
			return neg;
	return 0;
}

/* The verbs of kofeditor_cnd_rewrite (enum kofeditor_cnd_verb) are in kofeditor_private.h. */

/* Cut [from, to) out of an expression with the operator that joined it to its neighbour (the one before it, else the one
 * after), and a group that is left empty with it. Returns where the scan resumes. */
static size_t cnd_cut(char *s, size_t from, size_t to)
{
	for (;;) {
		size_t a = to, b = from;

		while (b && s[b - 1] == ' ')
			b--;
		if (b && (s[b - 1] == '&' || s[b - 1] == '|')) {
			char o = s[--b];

			if (b && s[b - 1] == o)
				b--;
			from = b;
		} else {
			while (s[a] == ' ')
				a++;
			if (s[a] == '&' || s[a] == '|') {
				char o = s[a++];

				if (s[a] == o)
					a++;
				while (s[a] == ' ')
					a++;
				to = a;
			}
		}
		memmove(s + from, s + to, strlen(s + to) + 1u);
		a = from;
		while (s[a] == ' ')
			a++;
		b = from;
		while (b && s[b - 1] == ' ')
			b--;
		if (!b || s[b - 1] != '(' || s[a] != ')')
			return from;
		from = b - 1u;
		to = a + 1u;
		while (from && s[from - 1] == '!')
			from--;
	}
}

void kofeditor_cnd_rewrite(struct cond *c, uint32_t id, uint32_t to, int verb)
{
	char *s = c->expr;
	const char *p = s;
	unsigned long n;
	int neg;

	/* Edited IN PLACE: only the number (or its "!") the verb acts on changes, every other byte stays, so parentheses and
	 * a mix of & and | survive. Nothing is re-written, so no id can be dropped; an edit that would not fit in the field
	 * is not made. */
	while (cnd_next_id(&p, &n, &neg)) {
		size_t e = (size_t)(p - s), ns = e, bs, len, w;
		unsigned long val;
		char num[24];

		if (verb == KOFEDITOR_CND_SHIFT ? n <= (unsigned long)id : n != (unsigned long)id)
			continue;
		while (ns && s[ns - 1] >= '0' && s[ns - 1] <= '9')
			ns--;
		bs = ns;
		while (bs && (s[bs - 1] == '!' || s[bs - 1] == ' '))
			bs--;
		while (s[bs] == ' ')
			bs++;
		len = strlen(s);
		if (verb == KOFEDITOR_CND_DROP) {
			p = s + cnd_cut(s, bs, e);
		} else if (verb == KOFEDITOR_CND_NEG && neg) {
			size_t k = ns;

			while (s[--k] != '!')
				;
			memmove(s + k, s + k + 1u, len - k);
			p = s + e - 1u;
		} else if (verb == KOFEDITOR_CND_NEG) {
			if (len + 1u >= sizeof c->expr)
				continue;
			memmove(s + ns + 1u, s + ns, len - ns + 1u);
			s[ns] = '!';
			p = s + e + 1u;
		} else {
			val = verb == KOFEDITOR_CND_SWAP ? (unsigned long)to : n - 1ul;
			w = (size_t)snprintf(num, sizeof num, "%lu", val);
			if (len - (e - ns) + w >= sizeof c->expr)
				continue;
			memmove(s + ns + w, s + e, len - e + 1u);
			memcpy(s + ns, num, w);
			p = s + ns + w;
		}
	}
}

/* Take one matcher out of a condition's expression. A block matcher is no part
 * of a condition (only the Patterns tab has them), so nothing happens. */
void cnd_drop_matcher(const struct kof_editor *e, struct cond *c, uint32_t g)
{
	if (g < e->dr.n_grp && grp_tab(e, g) == DT_PATTERNS)
		kofeditor_cnd_rewrite(c, grp_loc(e, g), 0, KOFEDITOR_CND_DROP);
}

/*
 * Flip one matcher between "must be found" and "must be absent".
 *
 * A toggle rather than a set, because the row that opens this menu already
 * shows which way round it is and the menu names the other one. Two calls -
 * negate, then un-negate - leave the expression exactly as they found it.
 */
void cnd_negate_matcher(const struct kof_editor *e, struct cond *c,
			uint32_t g)
{
	if (g < e->dr.n_grp && grp_tab(e, g) == DT_PATTERNS)
		kofeditor_cnd_rewrite(c, grp_loc(e, g), 0, KOFEDITOR_CND_NEG);
}

/*
 * Put a different matcher where this one stands, keeping its negation.
 *
 * Not a remove followed by an add: an add appends, so the negation would be
 * left behind on the way through and "!1 and 2" would come back as "2 and 3".
 * Whether the caller may offer `to` at all - it must not already be in this
 * condition, nor in the gate above it - is cmatch_ok's answer, not this one's.
 *
 * AND THE LIST GOES BACK INTO THE ORDER THE ROW DRAWS IN.
 *
 * cnd_canon lists matchers by number, and the row shows its text box instead of
 * its ids the moment the expression and the canonical form disagree. Without
 * this, switching 1 for 3 left "3&2" - a list by every other measure - and the
 * author who clicked a matcher got a text box back. Reordering costs nothing,
 * because the negation travels with the id rather than with the position.
 */
void cnd_swap_matcher(struct kof_editor *e, uint32_t ci, uint32_t g,
		      uint32_t to)
{
	struct cond *c;
	char canon[sizeof e->dr.cnd[0].expr];
	int list;

	if (ci >= e->dr.n_cnd || g >= e->dr.n_grp || to >= e->dr.n_grp)
		return;
	c = &e->dr.cnd[ci];
	/* Both ends are string matchers, or nothing is done: a block matcher is
	 * not one a condition can name. */
	if (grp_tab(e, g) != DT_PATTERNS || grp_tab(e, to) != DT_PATTERNS)
		return;
	cnd_canon(e, ci, canon, sizeof canon);
	list = !strcmp(c->expr, canon);
	kofeditor_cnd_rewrite(c, grp_loc(e, g), grp_loc(e, to), KOFEDITOR_CND_SWAP);
	/* Back into the order the row draws, but only a list: a typed expression is the author's. */
	if (list) {
		cnd_canon(e, ci, canon, sizeof canon);
		snprintf(c->expr, sizeof c->expr, "%s", canon);
	}
}

/*
 * What a condition is called on screen: "1." for the first one. Numbered by
 * position, in creation order: the conditions are independent blocks, one file
 * each (only the Patterns tab has them).
 */
void cnd_label(struct kof_editor *e, uint32_t i, char *out, size_t cap)
{
	(void)e;
	snprintf(out, cap, "%u.", i + 1u);
}

/*
 * The expression a plain list of ids would produce, for comparing against what
 * is actually stored.
 *
 * The id row can add, remove and re-join, which covers every expression that is
 * a list. Anything else - a parenthesis, a mix of & and | - was typed, and
 * rendering that as a list would show a different condition from the one that
 * will be generated. So when the two disagree, the typed text is what is shown.
 */
void cnd_canon(struct kof_editor *e, uint32_t g, char *out, size_t cap)
{
	const struct cond *c = &e->dr.cnd[g];
	size_t at = 0;
	uint32_t m;

	out[0] = 0;
	for (m = 0; m < e->dr.n_grp; m++) {
		if (!cnd_uses(e, c, m))
			continue;
		/*
		 * `at` MUST STOP ADVANCING AT THE END OF THE BUFFER.
		 *
		 * snprintf returns the length it WANTED to write, so without
		 * this `at` walks past cap, "cap - at" wraps to an enormous
		 * size_t, and the next call is handed a buffer it believes is
		 * unbounded. It cannot be reached today - MAX_GROUP is 8 and
		 * each id costs at most three columns, so 24 of the 64 both
		 * callers pass - but that is a chain of three facts none of
		 * which is stated here, and the same shape has already had to
		 * be fixed once in the pack builder.
		 */
		if (at + 8u >= cap)
			break;
		/* The "!" is part of the list, not part of the typing. A
		 * negated id that canon left out would make every negated
		 * condition disagree with its own canonical form, and the row
		 * would fall back to the text box the moment it was negated. */
		at += (size_t)snprintf(out + at, cap - at, "%s%s%u",
				       at ? (c->op ? "|" : "&") : "",
				       cnd_neg(e, c, m) ? "!" : "",
				       grp_loc(e, m));
	}
}

/*
 * AND OR OR, and the expression rewritten to match.
 *
 * The word between two ids is drawn from `op`, but what the rule MEANS is in
 * `expr` - and the row only draws a list of ids while the two agree. Flipping
 * `op` alone left "1&2" written against a canonical form that now said "1|2",
 * so the row decided the expression had been typed by hand: it turned into the
 * raw text, and the next click on it opened a caret. A reader who asked for
 * "or" got a text box.
 *
 * Only for an expression that IS the list. One somebody typed is theirs, and
 * the word is not offered for it.
 */
void cnd_set_op(struct kof_editor *e, uint32_t i, int op)
{
	char canon[64];

	if (i >= e->dr.n_cnd)
		return;
	cnd_canon(e, i, canon, sizeof canon);
	if (e->dr.cnd[i].expr[0] && strcmp(e->dr.cnd[i].expr, canon) != 0)
		return;
	e->dr.cnd[i].op = op;
	cnd_canon(e, i, canon, sizeof canon);
	snprintf(e->dr.cnd[i].expr, sizeof e->dr.cnd[i].expr, "%s", canon);
}

void cnd_add(struct kof_editor *e)
{
	struct cond *c;

	if (e->dr.n_cnd >= MAX_GROUP)
		return;
	c = &e->dr.cnd[e->dr.n_cnd];
	memset(c, 0, sizeof *c);
	e->dr.cur_cnd = e->dr.n_cnd++;
	e->dr.warn[0] = 0;
}

/* Drop a condition. */
void cnd_remove(struct kof_editor *e, uint32_t i)
{
	/* A box open on a row that is about to move is a box on the wrong
	 * row - see kof_editor.edit. */
	if (e->edit)
		*e->edit = 0;

	if (i >= e->dr.n_cnd)
		return;
	memmove(&e->dr.cnd[i], &e->dr.cnd[i + 1u],
		(e->dr.n_cnd - i - 1u) * sizeof e->dr.cnd[0]);
	e->dr.n_cnd--;
	if (e->dr.cur_cnd >= e->dr.n_cnd && e->dr.n_cnd)
		e->dr.cur_cnd = e->dr.n_cnd - 1u;
}
