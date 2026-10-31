/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * inline wrapper calls memmem, and only _GNU_SOURCE declares it - the same
 * reason kofinspect.c, kofexamine.c and kofviewer.c all say so. */
#define _GNU_SOURCE

/*
 * kofeditor.c - the draft model of the diagnose panel, apart from the viewer
 * that drives it.
 *
 * See kofeditor.h for why this file exists and where the boundary was drawn.
 * What is here answers questions about a DRAFT: its strings, blocks, matchers
 * and conditions. Nothing here knows a pane is on screen. The one thing written
 * is the generator's output (draft_generate): a diagnose source per unit, and
 * only through the shared diagsrc printer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/script.h>
/* KOF_PROC_OS_LIST: the platform a process record is from, which is its
 * subtype - see the note on that list. */
#include <kofmod/proc.h>
/* For the object facts below - see "what an object IS". */
#include <phenotype/emu_unpack.h>
#include <celllysis/mutation.h>

#include "kofeditor.h"
#include "../libkofeng/databases/diagsrc.h"
#include "../libkofeng/databases/pack/hexprog.h"
#include "../libkofeng/detectors/pattern/kofmatch.h"
#include "../libkofeng/kofcore/kofplatform.h"





/*
 * The architectures to offer, generated from the engine's list.
 *
 * The word here is the identifier with KOF_ARCH_ cut off, because that is what
 * the panel shows and what the emitted KOF_TARGET_ARCH() is built back up from.
 * Generated rather than typed so the menu cannot offer an architecture the
 * builder will reject, or miss one it would accept - which it did, three of
 * them, while this was a hand written list.
 */
#define ARCH_X_WORD(name, val, short_word) { &#name[sizeof "KOF_ARCH_" - 1], val },
const struct kof_arch_word arch_word[] = { KOF_ARCH_LIST(ARCH_X_WORD) };
#undef ARCH_X_WORD

/* Both generated from the format headers, for the reason arch_word is: the menu
 * must offer exactly what the builder accepts. The prefix is cut off because
 * the panel shows the bare kind and the emitted declaration puts it back. */
#define ELF_SUB_X(name, val) &#name[sizeof "KOF_ELF_" - 1],
const char *const elf_sub[] = { KOF_ELF_TYPE_LIST(ELF_SUB_X) };
#undef ELF_SUB_X

#define PE_SUB_X(name, val) &#name[sizeof "KOF_PE_" - 1],
const char *const pe_sub[]  = { KOF_PE_IMAGE_LIST(PE_SUB_X) };
#undef PE_SUB_X

/*
 * AND THE SCRIPT KINDS, WHICH THE GENERATOR HAD NO NAMES FOR.
 *
 * KOF_TARGET_SUBTYPE was written for ELF and for PE and for nothing else, so a
 * draft that declared a script kind had it DROPPED from the source - the panel
 * said the rule was about php and the file written did not say so. Silent, and
 * the same shape as the format list that stopped at KOF_FMT_PDF.
 *
 * From KOF_SCRIPT_TYPE_LIST, like the two above come from theirs, so a kind
 * added to that list is a name here without anyone remembering to add it.
 */
#define SCRIPT_SUB_X(name, val) &#name[sizeof "KOF_SCRIPT_" - 1],
const char *const script_sub[] = { KOF_SCRIPT_TYPE_LIST(SCRIPT_SUB_X) };
#undef SCRIPT_SUB_X
const uint32_t script_sub_n = sizeof script_sub / sizeof script_sub[0];

/*
 * AND THE PLATFORM A PROCESS RECORD IS FROM, on the same axis for the same
 * reason - see KOF_PROC_OS_LIST. A command line is not one language, and a
 * rule about `cmd /c` has no business being offered a bash start.
 */
#define PROC_SUB_X(name, val) &#name[sizeof "KOF_PROC_OS_" - 1],
const char *const proc_sub[] = { KOF_PROC_OS_LIST(PROC_SUB_X) };
#undef PROC_SUB_X
const uint32_t proc_sub_n = sizeof proc_sub / sizeof proc_sub[0];



/* The subtypes, per format. The values overlap between formats, which is why
 * naming one format's values while targeting another is a build error. */


/*
 * One line: how many modules this object touched, and which one the hex pane is
 * lighting up. The rest is one keypress or one click away.
 */
/*
 * The bottom line: what is known about this object on the left, what is under
 * the cursor on the right.
 *
 * They used to be the same space, so making a selection erased the marker
 * counts - the two things a reader compares while choosing bytes. They are
 * different questions with different lifetimes and they get different halves.
 *
 * The pane indicator is gone. It named the thing with the keyboard focus, which
 * the caret in that pane already says, and it was the first thing on the line
 * that nobody needed.
 */
/*
 * The draft, as it stands.
 *
 * Grouped visually by region rather than sorted, because the order markers were
 * chosen in is information - it is the order somebody read the object - and a
 * signature's declarations do not care about order at all.
 */
/* The display words, from the engine's list. The menu offers exactly the types
 * a diagnose may declare. */
#define MALTYPE_X_WORD(name, word) word,
const char *const maltype_word[] = { KOF_MALTYPE_LIST(MALTYPE_X_WORD) };
#undef MALTYPE_X_WORD


/*
 * The pattern a declaration stands for, compiled the way the database will.
 *
 * Shared because two locators need it and a second reading of the same
 * declaration is a second thing to keep in step - which is how the panel came
 * to report "found" about markers the scan would miss in the first place.
 */
int decl_pattern(const struct decl *d, uint8_t *prog,
			const uint8_t **pat, uint32_t *plen,
			uint8_t *kind, uint8_t *flags)
{
	*flags = 0;
	if (d->hex && d->hexs[0]) {
		*plen = kof_hex_compile(d->hexs, prog, KOF_HEX_MAX_PROG, NULL);
		if (!*plen)
			return 0;       /* it will not compile; it cannot match */
		*pat = prog;
		*kind = KOF_STR_HEX;
	} else {
		*pat = d->bytes;
		*plen = d->nbytes;
		*kind = KOF_STR_LITERAL;
		if (!d->hex) {
			if (d->icase)
				*flags |= KOF_STR_ICASE;
			if (d->fullword == KOF_WORD_FULLWORD)
				*flags |= KOF_STR_FULLWORD;
			else if (d->fullword == KOF_WORD_TOKEN)
				*flags |= KOF_STR_TOKEN;
		}
	}
	return *pat && *plen && *plen <= 0xffffu;
}

/*
 * Does a range hold bytes found in that region.
 *
 * KOF_SCAN_ALL is the whole object, so a range built on it holds everything - a
 * bit test alone would say a marker found in the code section is not inside the
 * whole file, which is the one answer that cannot be right.
 */
int rng_holds(uint32_t rmask, uint32_t region)
{
	return (rmask & KOF_SCAN_ALL) || (region & KOF_SCAN_ALL) ||
	       (rmask & region);
}

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

/*
 * THE NUMBER A CONDITION NAMES A MATCHER BY IS ITS PLACE ON ITS OWN TAB.
 *
 * Each tab numbers its matchers from 1, and a condition's expression is over
 * those numbers and nothing else. `grp_loc` is the number of matcher `g` on its
 * tab (0 for one that is not there). A matcher on another tab has no number a condition
 * could write, so no expression can reach it.
 */
uint32_t grp_loc(const struct kof_editor *e, uint32_t g)
{
	uint32_t k, n = 0;

	if (g >= e->dr.n_grp)
		return 0;
	for (k = 0; k <= g; k++)
		n += grp_tab(e, k) == grp_tab(e, g);
	return n;
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

/*
 * The declared range that holds this region, made if there is not one.
 *
 * A region met for the first time becomes a range on its own; met again it
 * finds the range it is already in, merged or not. So the list of ranges grows
 * out of where markers were actually found, which is the only place a range
 * has any business coming from.
 */
/*
 * Does this range hold bytes found in that region.
 *
 * KOF_SCAN_ALL is the whole object, so a range built on it holds everything -
 * a bit test alone would have said a marker found in the code section is not
 * inside the whole file, which is the one answer that cannot be right.
 */
/*
 * A mask, spelled with the format's own region words.
 *
 * Built on demand rather than stored: a range is whatever a matcher currently
 * needs, and a name kept beside it would be one more thing to update when a
 * marker is added or taken away.
 */
void rng_name_of(const struct kof_parser *fmt, uint32_t mask,
			char *out, size_t cap)
{
	uint32_t b, k;
	size_t at = 0;

	out[0] = 0;
	if (mask & KOF_SCAN_ALL) {
		snprintf(out, cap, "WHOLE-FILE");
		return;
	}
	/*
	 * The symbol halves name themselves.
	 *
	 * The loop below asks the FORMAT what a bit is called, and these two
	 * are not a format's - they mean the same thing for every input that
	 * has a symbol block, which is why kofsig.h defines them rather than
	 * elf.h or pe.h. Left to the loop they would come back unnamed, and an
	 * unnamed mask falls out of the bottom of this function as WHOLE-FILE:
	 * a range that says "search the exports" would have been written into
	 * a rule as "search everything".
	 */
	for (b = 30u; b < 32u && at + 1u < cap; b++) {
		if (!(mask & (1u << b)))
			continue;
		at += (size_t)snprintf(out + at, cap - at, "%s%s",
				       at ? "&" : "",
				       b == 30u ? "SYM_IMP" : "SYM_EXP");
	}
	for (b = 0; b < 30u && at + 1u < cap; b++) {
		const char *w = NULL;

		if (!(mask & (1u << b)))
			continue;
		if (fmt)
			for (k = 0; k < fmt->n_regions; k++)
				if (fmt->regions[k] == (1u << b))
					w = fmt->region_name(1u << b);
		if (!w)
			continue;
		{
			const char *t = strrchr(w, '_');

			/*
			 * "&" and not "|" for the reader.
			 *
			 * The mask is a union of region bits, so the operator
			 * that BUILDS it is or - and the generated source says
			 * so, spelling it "CODE | DATA" in C. This string is
			 * not that: it answers "where does this matcher look",
			 * and the answer is both places.
			 */
			at += (size_t)snprintf(out + at, cap - at, "%s%s",
					       at ? "&" : "", t ? t + 1 : w);
		}
	}
	if (!out[0])
		snprintf(out, cap, "WHOLE-FILE");
}















/*
 * A hex pattern's concrete leading bytes, for locating it in the object.
 *
 * Whitespace is skipped, because the spelling in a file has it: bases/ writes
 * "2E 2E 5C" and reading that two characters at a time gives 2E 02 0E 5C - four
 * bytes, none of them the marker, so the row said "4" and reported the pattern
 * as absent from an object it is in.
 *
 * Stops at the first character that is not a hex digit, which is how a wildcard
 * or a gap ends the concrete part. Short is the honest answer there: there is no
 * byte a "??" is equal to, and inventing a 00 would be a marker the rule never
 * had. What the pattern IS remains in decl.hexs; this is only what can be
 * searched for.
 */
/*
 * A hex pattern, read by THE ENGINE'S COMPILER.
 *
 * What stood here read the text itself and kept only the concrete bytes,
 * stopping at the first character that was not a hex digit. That is right for
 * a pattern with no wildcard in it and quietly wrong for every pattern that
 * has one: "2E ?? 5C" came back as the single byte 2E, so the row said the
 * marker was one byte long and the search went looking for that one byte -
 * editing a working pattern to add a wildcard made it stop matching at the
 * wildcard.
 *
 * The repair is not a better parser here. kof_hex_compile is the parser, it
 * already knows "??" and "?4" and "[4-6]" and "( E8 | E9 )", it is what the
 * build runs over the same text, and a second reading of the same syntax in
 * this file would be a second thing to keep correct. So the panel compiles the
 * pattern exactly as the database will and asks the compiler how long a match
 * spans; the bytes array goes away, because a pattern with a wildcard has none.
 */
int decl_from_hexs(struct decl *d)
{
	uint8_t prog[KOF_HEX_MAX_PROG];
	struct kof_hex_stat st;

	free(d->bytes);
	d->bytes = NULL;
	d->nbytes = 0;
	if (!kof_hex_compile(d->hexs, prog, sizeof prog, &st)) {
		d->len = 0;
		d->span_max = 0;
		return 0;               /* kof_hex_error() says what is wrong */
	}
	d->len = st.min_span;
	d->span_max = st.max_span;
	return 1;
}



/*
 * Take the selection into the draft.
 *
 * The region comes from the tree row rather than from anything about the bytes,
 * because that is what the finished declaration will say: KOF_TARGET_RANGE names
 * where to look, and where somebody was looking when they found it is the
 * honest answer to that.
 */

/* ---- editing a declared string as text ------------------------------------ */

/*
 * Is this value one a person can type back?
 *
 * A literal is edited as the characters it is, so a byte that has no character
 * cannot survive the round trip: it would be shown as something, and whatever
 * that something was would be written back as itself. Refusing to open is the
 * only answer that does not quietly change the marker. Hex has no such problem
 * and is always editable - that is what hex is for.
 */
/*
 * THE SAME SET THE FILE ACCEPTS, which is printable ASCII and the three
 * whitespace bytes.
 *
 * This refused anything outside 0x20..0x7e, and that matched literal_safe until
 * literal_safe grew tab, newline and carriage return - a marker that crosses a
 * line is an ordinary thing to declare and is now written as "\t", "\n", "\r".
 * The two halves then disagreed: the panel would DECLARE such a marker and
 * then refuse to let it be edited, saying it was not text about something that
 * plainly is.
 *
 * The box shows them as escapes and decl_edit_commit reads them back - see
 * decl_edit_open - because a raw newline in a one-line field is not editable
 * whatever this answers.
 */
int decl_text_editable(const struct decl *d)
{
	uint32_t i;

	if (d->hex)
		return 1;
	for (i = 0; i < d->nbytes; i++) {
		uint8_t c = d->bytes[i];

		if (c == '\t' || c == '\n' || c == '\r')
			continue;
		if (c < 0x20 || c >= 0x7f)
			return 0;
	}
	return 1;
}

/*
 * Rewrite a condition's id list, applying one edit to one matcher.
 *
 * Drop, negate and switch are the same walk - read the ids in order, decide
 * what the new list says about each, write them back joined with the
 * condition's own operator - so they are one function with a verb rather than
 * three copies of the loop.
 *
 * Rewritten from the ids that are left rather than edited in place, because
 * removing "2" from "1&2|3" by deleting characters leaves "1&|3" - and an
 * expression that has to be repaired by hand after every removal is one nobody
 * will use the buttons on. Anything the author typed that is not a plain list -
 * parentheses, a mix of & and | - is preserved only in so far as the join it
 * was written with; that is the price of a list and a text box being the same
 * field.
 *
 * The room check is not decoration. A negation ADDS a character, so this is the
 * one edit that can make an expression longer than the one it replaces, and
 * "sizeof out - at" underflows to an enormous size_t the moment at passes the
 * end. Twenty-two columns is the widest one id can be written in - a "!", a
 * join, and every digit of an unsigned long somebody typed by hand.
 */
enum { CND_DROP = 0, CND_NEG, CND_SWAP, CND_SHIFT };

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

static void cnd_rewrite(struct cond *c, uint32_t id, uint32_t to, int verb)
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

		if (verb == CND_SHIFT ? n <= (unsigned long)id : n != (unsigned long)id)
			continue;
		while (ns && s[ns - 1] >= '0' && s[ns - 1] <= '9')
			ns--;
		bs = ns;
		while (bs && (s[bs - 1] == '!' || s[bs - 1] == ' '))
			bs--;
		while (s[bs] == ' ')
			bs++;
		len = strlen(s);
		if (verb == CND_DROP) {
			p = s + cnd_cut(s, bs, e);
		} else if (verb == CND_NEG && neg) {
			size_t k = ns;

			while (s[--k] != '!')
				;
			memmove(s + k, s + k + 1u, len - k);
			p = s + e - 1u;
		} else if (verb == CND_NEG) {
			if (len + 1u >= sizeof c->expr)
				continue;
			memmove(s + ns + 1u, s + ns, len - ns + 1u);
			s[ns] = '!';
			p = s + e + 1u;
		} else {
			val = verb == CND_SWAP ? (unsigned long)to : n - 1ul;
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
		cnd_rewrite(c, grp_loc(e, g), 0, CND_DROP);
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
		cnd_rewrite(c, grp_loc(e, g), 0, CND_NEG);
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
	cnd_rewrite(c, grp_loc(e, g), grp_loc(e, to), CND_SWAP);
	/* Back into the order the row draws, but only a list: a typed expression is the author's. */
	if (list) {
		cnd_canon(e, ci, canon, sizeof canon);
		snprintf(c->expr, sizeof c->expr, "%s", canon);
	}
}


/*
 * The draft, as one number.
 *
 * Compared against the number when the panel was last emptied to answer "has this changed" -
 * the same trick the frame repaint uses, and for the same reason: a flag set by
 * hand at every place that mutates the draft is a flag that gets missed at the
 * next place, and the one that gets missed is the one that loses somebody's
 * work.
 */
/*
 * The status line's two voices.
 *
 * Red is for something that went wrong and stopped what was asked for: a
 * refused edit. Yellow is for something worth knowing that stopped nothing -
 * a string that is not in this object.
 */
void say_err(struct kof_editor *e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(e->dr.warn, sizeof e->dr.warn, fmt, ap);
	va_end(ap);
	e->dr.warn_bad = 1;
}


/* ---- what an object IS, worked out once ------------------------------------
 *
 * HERE RATHER THAN IN THE VIEWER, because these are facts about an object and
 * not about a screen: a digest, the sets kof_mutation_build makes of it, what the
 * emulator's gate said. The panel was working each of them out for itself, and
 * more than once - kof_mutation_build ran twice per arrival at an object, once to
 * seed the draft and once to score it - which is the duplication this file
 * exists to stop for everything else the two tools share.
 *
 * Each is cached in the object, so it happens once however many times it is
 * asked for, and each is asked for where it is USED rather than when an object
 * is selected: they read every byte, and an object is spilled to a file and
 * mapped precisely so that looking at twenty rows of it costs twenty rows.
 */
/*
 * The digest, worked out the first time the pane that prints it is built.
 *
 * Not on selection: it reads every byte of the object, and only the
 * properties pane prints it, which the reader opens. Cached in the object, so a
 * pane that stays open pays once.
 */
void obj_sha256(struct object *o)
{
	if (!o || !o->buf.p || !o->buf.n)
		return;
	if (!o->sha256[0])
		khash_sha256_bytes(o->buf.p, o->buf.n, o->sha256);
}

void say_note(struct kof_editor *e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(e->dr.warn, sizeof e->dr.warn, fmt, ap);
	va_end(ap);
	e->dr.warn_bad = 0;
}



/* The vocabulary a family or variant name is allowed to be spelled in. Empty is
 * not this function's business - a name that has not been typed yet is a
 * different message from one typed wrongly. */





void decl_locate(struct kof_editor *e, struct decl *d)
{
	struct object *ob = &e->obj[d->obj < (*e->n_obj) ? d->obj : 0];
	struct kof_match_ctx m, msym;
	struct kof_region_map map;
	struct kof_locate lo;
	uint8_t prog[KOF_HEX_MAX_PROG];
	const uint8_t *pat;
	uint32_t plen, h;
	uint8_t kind, flags = 0;

	d->at = KGENOME_BROKEN;
	d->sym = 0;
	d->off_rgn = 0;
	d->at_rgn[0] = 0;
	d->at_mask = 0;
	d->n_hits = 0;
	d->hits_clipped = 0;
	if (!d->len || !e->scratch)
		return;
	if (!decl_pattern(d, prog, &pat, &plen, &kind, &flags))
		return;

	/*
	 * ONE CALL FOR WHERE A MARKER IS: the rule is kof_locate_str's and this
	 * only presents what it returns; see the note above it in kofinspect.h.
	 */
	memset(&m, 0, sizeof m);
	memset(&msym, 0, sizeof msym);
	if (!kof_match_state_init(&m, 0, 0))
		return;
	if (!kof_match_state_init(&msym, 0, 0)) {
		kof_match_state_free(&m);
		return;
	}
	kof_region_map_build(&map, &ob->ctx, ob->fmt);
	kof_locate_str(&m, &msym, &map, kof_buf_make(ob->buf.p, ob->buf.n),
		       ob->sym, ob->sym_n, d->mask, pat, (uint16_t)plen, kind,
		       flags, d->len, d->span_max, e->scratch,
		       KOF_SCAN_MAX_EXTENTS, &lo);
	kof_region_map_free(&map);
	kof_match_state_free(&msym);
	kof_match_state_free(&m);

	d->at = lo.at;
	d->at_mask = lo.at_mask;
	d->sym = lo.sym;
	d->off_rgn = lo.off_rgn;
	d->cur_hit = lo.cur_hit;
	d->hits_clipped = lo.clipped;
	d->n_hits = lo.n_hits < DECL_HITS_MAX ? lo.n_hits : DECL_HITS_MAX;
	for (h = 0; h < d->n_hits; h++) {
		d->hits[h] = lo.hits[h];
		d->hit_len[h] = lo.hit_len[h];
	}
	/* The label is presentation, so it is made here from the mask the
	 * locator returned rather than carried through it. */
	if (d->at_mask)
		rng_name_of(ob->fmt, d->at_mask, d->at_rgn, sizeof d->at_rgn);
}

/* How many markers are in this condition. */
/* Markers not yet in any condition. */
uint32_t decl_free(struct kof_editor *e)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_decl; i++)
		n += e->dr.decl[i].grp == 0;
	return n;
}



uint32_t grp_mask(struct kof_editor *e, uint32_t g)
{
	uint32_t i, need = 0;

	if (e->dr.grp[g].mask)
		return e->dr.grp[g].mask;
	for (i = 0; i < e->dr.n_decl; i++)
		if (e->dr.decl[i].grp & (1u << g))
			need |= e->dr.decl[i].mask0;
	return need ? need : KOF_SCAN_ALL;
}

uint32_t grp_count(struct kof_editor *e, uint32_t g)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_decl; i++)
		n += (e->dr.decl[i].grp >> g) & 1u;
	return n;
}


int grp_has_range(struct kof_editor *e, uint32_t g)
{
	/*
	 * AN AT MATCHER HAS NONE, and saying otherwise emits a range nothing
	 * uses.
	 *
	 * kof_find_str_at names no region, so a KOF_TARGET_RANGE written for it
	 * would be a declaration no call references - which the panel already
	 * calls an unused range - and worse, it becomes part of the module's
	 * scan_mask, which the engine uses as a PRECONDITION: the module is
	 * skipped outright on an object that has no such region. A matcher that
	 * looks at one offset would have been silently deciding which objects
	 * the whole rule is even offered.
	 */
	if (grp_is_at(e->dr.grp[g].rule))
		return 0;
	return grp_count(e, g) != 0 || e->dr.grp[g].mask != 0;
}

void grp_add(struct kof_editor *e)
{
	if (e->dr.n_grp >= MAX_GROUP)
		return;
	memset(&e->dr.grp[e->dr.n_grp], 0, sizeof e->dr.grp[0]);
	/*
	 * A NEW MATCHER STARTS AS "any", because it starts with one marker.
	 *
	 * Zero is find_all, which is a plural about a single thing:
	 * `kof_find_str_all(rng, s0)`. The author who adds a second marker
	 * chooses from the threshold menu, which is where the choice belongs -
	 * see where CH_THRESH is taken.
	 */
	e->dr.grp[e->dr.n_grp].rule = 1;
	e->dr.cur_grp = e->dr.n_grp++;
	e->dr.warn[0] = 0;
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





/*
 * Take a matcher out, and put every reference to it right.
 *
 * The one thing on this panel that could be added and not removed. Removing it
 * is not just a shift: the conditions name matchers by number, so every
 * expression has to be renumbered or a condition that said "2" starts meaning
 * the matcher that used to be 3 - the kind of change nothing on screen shows
 * and no one would look for.
 */
void grp_remove(struct kof_editor *e, uint32_t g)
{
	/* A box open on a row that is about to move is a box on the wrong
	 * row - see kof_editor.edit. */
	if (e->edit)
		*e->edit = 0;
	uint32_t i, k, gl;
	uint8_t gt;

	if (g >= e->dr.n_grp)
		return;
	gl = grp_loc(e, g);
	gt = grp_tab(e, g);
	for (i = 0; i < e->dr.n_decl; i++) {
		uint32_t lo = e->dr.decl[i].grp & ((1u << g) - 1u);
		uint32_t hi = e->dr.decl[i].grp >> (g + 1u);

		/* Its bit goes and every matcher above it moves down one -
		 * the same renumbering the matcher array itself gets. */
		e->dr.decl[i].grp = lo | (hi << g);
	}
	/* Only a string matcher is named by a condition, and the numbers move
	 * among the string matchers. A block matcher is its own unit: removing
	 * it renumbers nothing, and every other matcher keeps its own type and
	 * tag (they live in the matcher, which moves with it). */
	for (k = 0; gt == DT_PATTERNS && k < e->dr.n_cnd; k++) {
		cnd_rewrite(&e->dr.cnd[k], gl, 0, CND_DROP);
		cnd_rewrite(&e->dr.cnd[k], gl, 0, CND_SHIFT);
	}
	memmove(&e->dr.grp[g], &e->dr.grp[g + 1u],
		(e->dr.n_grp - g - 1u) * sizeof e->dr.grp[0]);
	e->dr.n_grp--;
	if (e->dr.cur_grp >= e->dr.n_grp && e->dr.n_grp)
		e->dr.cur_grp = e->dr.n_grp - 1u;
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

/*
 * The offset an AT matcher should start at: the one its marker is sitting on.
 *
 * Seeded rather than asked for, because the researcher clicked a marker they
 * were already looking at and the offset they mean is that one. decl.at is the
 * occurrence the marker's own row reports on - the one inside the region the
 * rule searches, when there is one - so the panel and the matcher agree about
 * which of several occurrences is "the" one without either being told.
 *
 * KGENOME_BROKEN means the bytes are not in this object at all - a marker carried
 * over from another sample. Left at zero then, which is a place that exists,
 * rather than writing a sentinel into generated C.
 */
void grp_seed_at(struct kof_editor *e, uint32_t g)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_decl; i++)
		if (e->dr.decl[i].grp & (1u << g)) {
			const struct decl *d = &e->dr.decl[i];

			/* An occurrence is a file offset, so it seeds the
			 * literal base. Naming a base is the author's choice
			 * and is made on the WHERE control. */
			e->dr.grp[g].at_anchor = KOF_ANCHOR_BOF;
			e->dr.grp[g].at_off = d->at == KGENOME_BROKEN
					    ? 0 : (int64_t)d->at;
			/*
			 * AND WHETHER THAT NUMBER IS A PLACE - see
			 * group.at_auto.
			 *
			 * Both halves are asked because both can fail. `at`
			 * is KGENOME_BROKEN when the bytes are not in this object
			 * at all, and the zero written above is then a
			 * default rather than a location. `mask0` is the
			 * region the bytes were SELECTED in and is zero for a
			 * marker read out of a source file or typed into the
			 * box - neither of which was located here, whatever
			 * a later search may have turned up.
			 */
			e->dr.grp[g].at_auto =
				(uint8_t)(d->at != KGENOME_BROKEN && d->mask0 != 0);
			return;
		}
}

uint32_t grp_thresh_eff(struct kof_editor *e, uint32_t g)
{
	if (grp_is_at(e->dr.grp[g].rule))
		return 1u;                      /* one comparison, one answer */
	if (e->dr.grp[g].rule == 1)
		return 1u;                      /* any: at least one */
	if (e->dr.grp[g].rule == 2)
		return e->dr.grp[g].thresh;
	return grp_count(e, g);                 /* all: every one of them */
}







uint32_t draft_hash(struct kof_editor *e)
{
	uint32_t h = 2166136261u, i, j;

	/* One step, the engine's - see kofcore.h. The mask and the cast were
	 * noise around a byte. */
	#define MIX(b) (h = kof_hash_step(h, (uint8_t)(b)))
	/* MIX takes ONE byte: a value wider than that is folded byte by byte, or its upper bytes are not part of the hash. */
	#define MIX32(w) do { uint32_t w_ = (uint32_t)(w); MIX(w_); MIX(w_ >> 8); MIX(w_ >> 16); MIX(w_ >> 24); } while (0)
	for (i = 0; e->dr.family[i]; i++)
		MIX((uint8_t)e->dr.family[i]);
	for (i = 0; e->dr.note[i]; i++)
		MIX((uint8_t)e->dr.note[i]);
	for (i = 0; e->dr.variant[i]; i++)
		MIX((uint8_t)e->dr.variant[i]);
	for (i = 0; i < e->dr.n_rng_add; i++)
		MIX32(e->dr.rng_add[i]);
	for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
		/*
		 * AN OPTION THE ENGINE FILLED IN READS AS ABSENT - see
		 * kof_draft.opt_auto.
		 *
		 * NEUTRALISED RATHER THAN SKIPPED, and the difference is the
		 * whole bug this was written to fix. The fold is over a
		 * SEQUENCE of steps, so leaving three of them out moves the
		 * hash exactly as changing their values would: the first
		 * attempt wrote `continue` here and an empty draft still came
		 * back edited, because the option had gone from "off, hashed"
		 * to "not hashed at all". Zero, fed in the same three steps,
		 * is what "the reader has set nothing" already hashed to.
		 */
		int on = e->dr.opt_auto[i] ? 0 : e->dr.opt_on[i];
		uint64_t val = e->dr.opt_auto[i] ? 0u : e->dr.opt_val[i];

		MIX(on);
		MIX32(val);
		MIX32(val >> 32);
	}
	for (i = 0; i < e->dr.n_decl; i++) {
		const struct decl *d = &e->dr.decl[i];

		MIX(d->len); MIX(d->hex); MIX32(d->mask); MIX(d->wide);
		MIX(d->grp); MIX(d->fullword); MIX(d->icase);
		/* The spelling when there is one - it is what would be
		 * written, and `bytes` may be NULL beside it. */
		if (d->hexs[0])
			for (j = 0; d->hexs[j]; j++)
				MIX((uint8_t)d->hexs[j]);
		else
			for (j = 0; j < d->nbytes; j++)
				MIX(d->bytes[j]);
	}
	for (i = 0; i < e->dr.n_grp; i++) {
		MIX(e->dr.grp[i].rule); MIX(e->dr.grp[i].thresh); MIX32(e->dr.grp[i].mask);
		MIX(e->dr.grp[i].at_anchor); MIX(e->dr.grp[i].at_auto);
		MIX32(e->dr.grp[i].at_off); MIX32((uint64_t)e->dr.grp[i].at_off >> 32);
		MIX(e->dr.grp[i].utype);
		for (j = 0; e->dr.grp[i].tag[j]; j++)
			MIX((uint8_t)e->dr.grp[i].tag[j]);
		for (j = 0; e->dr.grp[i].note[j]; j++)
			MIX((uint8_t)e->dr.grp[i].note[j]);
	}
	for (i = 0; i < e->dr.n_cnd; i++) {
		const struct cond *c = &e->dr.cnd[i];

		MIX(c->utype);
		for (j = 0; c->tag[j]; j++)
			MIX((uint8_t)c->tag[j]);
		MIX(c->op);
		for (j = 0; c->expr[j]; j++)
			MIX((uint8_t)c->expr[j]);
	}
	/*
	 * AND THE BLOCKS THE RULE IS MADE OF.
	 *
	 * Ticking a block, pointing a matcher at a different one or changing
	 * how one is hashed all change the rule that would be written - so a
	 * draft that reported itself unchanged after any of them would be a
	 * draft that loses them without warning. The block's own name is the
	 * fold of its hashes, so hashing that covers its content too.
	 */
	/*
	 * ONLY THE TICKED ONES. An unticked block is the ENGINE'S
	 * OFFER about the object, not part of the draft - and mixing those in
	 * made the draft dirty the moment a file was opened, because the carve
	 * runs on arrival. A dirty draft refuses to switch file, so opening a
	 * second sample needed a Discard first.
	 */
	/*
	 * AND AS A SET, NOT AS A LIST.
	 *
	 * The order of this array is not the draft's. mtn_order sorts it by
	 * where each block sits IN THE OBJECT IN FRONT OF THE READER, and a
	 * block the current file does not hold has no offset and sorts behind
	 * the ones it does - so arriving at another sample permutes the ticked
	 * blocks without changing one thing about the rule. Folded in order,
	 * that permutation is a different hash: the draft read as edited, and
	 * an edited draft refuses to step to the next file, so a rule holding a
	 * block the open file lacks could not be carried to another sample
	 * without discarding it first.
	 *
	 * The same fault the two notes below describe - a position mistaken for
	 * a fact - one level up, in the loop rather than in what it mixes. Each
	 * block is hashed on its own and the results are ADDED, so the set is
	 * what the answer depends on and the order is not.
	 */
	{
		uint32_t acc = 0;

		for (i = 0; i < e->dr.n_blk && e->dr.blk; i++) {
			uint32_t b = 2166136261u;

			if (!e->dr.blk[i].picked)
				continue;
			b = kof_hash_step(b, (uint8_t)e->dr.blk[i].id);
			acc += b;
		}
		MIX(acc);
		MIX(acc >> 8);
		MIX(acc >> 16);
		MIX(acc >> 24);
	}
	/* Ticking a measure is an edit - see kof_draft.sim_use - so a draft
	 * that reported itself unchanged after one would lose it silently. */
	for (i = 0; i < SIM_IT_COUNT; i++)
		MIX(e->dr.sim_use[i]);
	for (i = 0; i < e->dr.n_grp; i++) {
		uint32_t k;

		MIX(e->dr.grp[i].kind);
		if (e->dr.grp[i].kind != GRP_KIND_SIM)
			continue;
		/* EVERY ITEM, in order, and the one threshold they share:
		 * adding a measure, taking one out or moving the number are
		 * all edits, and a draft that reported itself unchanged after
		 * any of them would be a draft that loses them without
		 * warning. */
		MIX(e->dr.grp[i].pct);
		MIX(e->dr.grp[i].n_sim);
		for (k = 0; k < e->dr.grp[i].n_sim; k++) {
			const struct grp_sim_item *it = &e->dr.grp[i].sim[k];

			MIX(it->what);
			/*
			 * WHICH BLOCK, BY ITS NAME - not by where it sits in
			 * the list.
			 *
			 * The index is a position in a list the carve rebuilds
			 * and sorts into file order every time the object
			 * changes, so hashing it made the draft look edited the
			 * moment a rule was opened: the block it names had
			 * simply moved. What the rule says is the block's name,
			 * and that only changes when the block does.
			 */
			if (it->what == SIM_IT_BLOCK) {
				if (it->blk < e->dr.n_blk && e->dr.blk)
					MIX(e->dr.blk[it->blk].id);
			}
		}
	}
	#undef MIX32
	#undef MIX
	return h;
}




/*
 * HAS THE READER CHANGED ANYTHING since the panel was last emptied: the draft's
 * hash against the one taken then.
 */
int draft_edited(struct kof_editor *e)
{
	return draft_hash(e) != e->dr.saved_hash;
}












/*
 * Give every matcher searching `was` the mask `now`.
 *
 * By range rather than by matcher because that is what the summary row edits:
 * the row lists distinct ranges, and two matchers sharing one are two names for
 * the same decision - changing what DATA covers changes it for both.
 */
void rng_retarget(struct kof_editor *e, uint32_t was, uint32_t now)
{
	uint32_t g, i, w = 0;

	for (g = 0; g < e->dr.n_grp; g++) {
		if (!grp_has_range(e, g) || grp_mask(e, g) != was)
			continue;
		e->dr.grp[g].mask = now;
	}
	/*
	 * AND THE DECLARED LIST, which is the half this used to miss.
	 *
	 * A range put there by [+ Scan range] lives in rng_add until a matcher
	 * is given it, and this function only ever walked the matchers. Two
	 * things went wrong from that. Extending a range NO matcher had yet did
	 * nothing at all - the loop above matched nothing - so a range could
	 * only be widened after it had been handed to a matcher. And extending
	 * one that a matcher DID have moved the matcher to the wider mask while
	 * leaving the old narrow mask sitting in rng_add, where rng_all then
	 * reported it as a second, unused range: a region that appeared out of
	 * nowhere the moment you extended.
	 *
	 * Rewritten with a dedup, because the wider mask may already be
	 * declared - two entries for one mask would draw the same range twice.
	 */
	for (i = 0; i < e->dr.n_rng_add; i++) {
		uint32_t m = e->dr.rng_add[i] == was ? now : e->dr.rng_add[i];
		uint32_t k;
		int dup = 0;

		for (k = 0; k < w; k++)
			dup |= e->dr.rng_add[k] == m;
		if (!dup)
			e->dr.rng_add[w++] = m;
	}
	e->dr.n_rng_add = w;
	/*
	 * THE STRINGS ARE LEFT ALONE.
	 *
	 * This used to rewrite every marker's own region to the matcher's new
	 * range. That is a different fact: a string's region is where it WAS
	 * FOUND and the matcher's range is where it will be LOOKED FOR - the
	 * distinction the panel spends two column headings on. Widening a
	 * matcher to CODE&DATA does not move a marker that was found in CODE,
	 * and saying it does makes the row claim a provenance the search never
	 * established. Eligibility still holds: rng_holds is an overlap, so a
	 * CODE marker remains valid for a CODE&DATA matcher.
	 */
}

/* The ranges the matchers search, appended to mask[n..) distinct from everything already there: the one loop rng_removable and rng_all
 * share, so what counts as a range (grp_has_range, grp_mask) is said once. Returns the new count. */
static uint32_t rng_add_searched(struct kof_editor *e, uint32_t *mask, int *unused, uint32_t n, uint32_t cap)
{
	uint32_t g, k;

	for (g = 0; g < e->dr.n_grp && n < cap; g++) {
		uint32_t mm;
		int dup = 0;

		if (!grp_has_range(e, g))
			continue;
		mm = grp_mask(e, g);
		for (k = 0; k < n; k++)
			dup |= mask[k] == mm;
		if (dup)
			continue;
		mask[n] = mm;
		unused[n] = 0;
		n++;
	}
	return n;
}

/*
 * THE SCAN RANGES A READER MAY REMOVE, and which kind each one is.
 *
 * Two kinds on one list, because a reader thinks of them as one thing - the
 * ranges this draft has. An UNUSED range is a KOF_TARGET_RANGE the draft
 * declared that no matcher searches; removing it just drops the declaration. A
 * range a matcher DOES search has no life apart from that matcher - see the note
 * on grp.mask - so removing it removes the matcher, the same thing the matcher's
 * own [x] does, reached from where the reader was looking instead.
 *
 * Unused first, then the matcher ranges deduplicated. Enumerated the same way
 * where the menu is drawn and where a pick is carried out, so a row index means
 * the same on both sides.
 */
uint32_t rng_removable(struct kof_editor *e, uint32_t *mask, int *unused,
			      uint32_t cap)
{
	uint32_t n = 0, i, g;

	for (i = 0; i < e->dr.n_rng_add && n < cap; i++) {
		int used = 0;

		for (g = 0; g < e->dr.n_grp; g++)
			used |= grp_has_range(e, g) &&
				grp_mask(e, g) == e->dr.rng_add[i];
		if (used)
			continue;
		mask[n] = e->dr.rng_add[i];
		unused[n] = 1;
		n++;
	}
	return rng_add_searched(e, mask, unused, n, cap);
}

/*
 * EVERY RANGE THE DRAFT HAS, in one order.
 *
 * The distinct masks the matchers search, then the declared ones nothing
 * searches yet. Its own function because three places need the same list in the
 * same order - the row that draws the names, the click that turns a column into
 * a range, and the menu that acts on one - and a list built three times is a
 * list that disagrees with itself about which range is which.
 */
uint32_t rng_all(struct kof_editor *e, uint32_t *mask, int *unused,
			uint32_t cap)
{
	uint32_t n = rng_add_searched(e, mask, unused, 0, cap), g, k;

	for (g = 0; g < e->dr.n_rng_add && n < cap; g++) {
		int used = 0;

		for (k = 0; k < n; k++)
			used |= mask[k] == e->dr.rng_add[g];
		if (used)
			continue;
		mask[n] = e->dr.rng_add[g];
		unused[n] = 1;
		n++;
	}
	return n;
}

/* Drop an unused declared range from the draft. */
void rng_add_drop(struct kof_editor *e, uint32_t mask)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_rng_add; i++)
		if (e->dr.rng_add[i] == mask) {
			memmove(&e->dr.rng_add[i], &e->dr.rng_add[i + 1u],
				(e->dr.n_rng_add - i - 1u) * sizeof e->dr.rng_add[0]);
			e->dr.n_rng_add--;
			return;
		}
}

/*
 * Remove one scan range. An unused declaration is dropped; a range a matcher
 * searches takes the matcher(s) with it - backwards, because grp_remove shifts
 * every matcher above the one it drops down by one.
 */
void rng_delete(struct kof_editor *e, uint32_t mask, int unused)
{
	if (unused) {
		rng_add_drop(e, mask);
		say_note(e, "%s", "Scan range removed");
		return;
	}
	{
		uint32_t g = e->dr.n_grp;

		while (g-- > 0)
			if (grp_has_range(e, g) && grp_mask(e, g) == mask)
				grp_remove(e, g);
	}
	say_note(e, "%s", "Scan range removed with its matcher");
}

/*
 * Carry out one line of the scan range menu.
 *
 * `target` is the range being acted on - the only one, or the one picked from
 * the second list. `here` is where this draft's markers actually are, which is
 * what every line but the last is made of. The verbs are the menu's own order,
 * so the two cannot drift apart: whatever line n says, this does.
 */
void rng_apply(struct kof_editor *e, int verb, uint32_t target, uint32_t here)
{
	switch (verb) {
	case 0:
		rng_retarget(e, target, here);
		say_note(e, "%s", "Scan range switched");
		break;
	case 1:
		rng_retarget(e, target, target | here);
		say_note(e, "%s", "Scan range extended");
		break;
	case 2: {
		/*
		 * The range and nothing else.
		 *
		 * It used to create the matcher that would name it, which put
		 * a matcher on the panel nobody had asked for and which could
		 * not be wanted yet - it has no markers, and which markers
		 * belong in it is a decision only the researcher can make. A
		 * declared range with no matcher is an ordinary half-finished
		 * state; it is listed as unused and it stops the save, which
		 * is what a half-finished state should do.
		 */
		uint32_t k;

		for (k = 0; k < e->dr.n_grp; k++)
			if (grp_has_range(e, k) && grp_mask(e, k) == here) {
				say_note(e, "%s", "A matcher already searches "
					 "that range");
				return;
			}
		for (k = 0; k < e->dr.n_rng_add; k++)
			if (e->dr.rng_add[k] == here) {
				say_note(e, "%s", "That range is already "
					 "declared");
				return;
			}
		if (e->dr.n_rng_add >= MAX_GROUP) {
			say_err(e, "%s", "No room for another range");
			return;
		}
		e->dr.rng_add[e->dr.n_rng_add++] = here;
		say_note(e, "%s", "Scan range added - give it a matcher");
		break;
	}
	case 3:
		rng_retarget(e, target, KOF_SCAN_ALL);
		say_note(e, "%s", "Scan range is now the whole file");
		break;
	default:
		break;
	}
}

/*
 * Point every marker at the region it is actually in, here.
 *
 * A family's markers do not keep one address across its own files: the same
 * five kernel symbol names sit in a data section in the rootkit object and in
 * .rodata - which is CODE, because that segment executes - in the loader that
 * installs it. A rule carried from one to the other looks right on every row
 * and cannot fire, and switching five strings one at a time to find that out is
 * work nobody should do by hand.
 *
 * A marker that is not in this object at all is LEFT ALONE and counted. It may
 * well be a real marker of the family taken from another sample, and deleting a
 * declaration because the file in front of us does not happen to contain it
 * would throw away the researcher's work to tidy up a column.
 */
void draft_refresh(struct kof_editor *e)
{
	uint32_t i, g, moved = 0, gone = 0;

	for (i = 0; i < e->dr.n_decl; i++) {
		struct decl *d = &e->dr.decl[i];

		decl_locate(e, d);
		if (d->at == KGENOME_BROKEN) {
			gone++;
			continue;
		}
		if (!d->at_mask)
			continue;
		if (d->mask != d->at_mask)
			moved++;
		d->mask = d->at_mask;
		snprintf(d->rgn, sizeof d->rgn, "%.23s", d->at_rgn);
		d->off_rgn = 0;
	}
	/*
	 * And the matchers follow, because a range is not an independent fact:
	 * it is the union of the regions its markers are in, which is how one
	 * gets built in the first place. Leaving them behind would move every
	 * string and still search the old place.
	 */
	for (g = 0; g < e->dr.n_grp; g++) {
		uint32_t m = 0;

		for (i = 0; i < e->dr.n_decl; i++)
			if (e->dr.decl[i].grp & (1u << g))
				m |= e->dr.decl[i].mask;
		if (m)
			e->dr.grp[g].mask = m;
	}
	if (!moved && !gone)
		say_note(e, "Every marker is already in the region searched");
	else if (!gone)
		say_note(e, "Moved %u marker(s) to where they are",
			 moved);
	else
		say_note(e, "%u moved, %u not here - left as declared",
			 moved, gone);
}

/*
 * Bring every marker's range back in step with the matchers that search it.
 *
 * Derived state, so it is recomputed from what the draft currently holds
 * rather than updated at each of the half dozen places that can change a
 * matcher's range or take a matcher away. Run from the draw, which is the one
 * point every one of those passes through, and cheap enough to: a draft holds
 * at most MAX_DECL markers and a handful of matchers, and the search below is
 * reached only when the answer actually changed.
 */
void decl_sync_ranges(struct kof_editor *e)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_decl; i++) {
		struct decl *d = &e->dr.decl[i];
		uint32_t m = 0, g;

		for (g = 0; g < e->dr.n_grp; g++)
			if (d->grp & (1u << g))
				m |= e->dr.grp[g].mask;
		/* Searched by nothing: it falls back to where its bytes came
		 * from, and a marker read out of a source file has no such
		 * place - which is the dash the column shows. */
		if (!m)
			m = d->mask0;
		if (m == d->mask)
			continue;
		d->mask = m;
		if (m)
			rng_name_of(e->obj[d->obj < (*e->n_obj) ? d->obj : 0].fmt,
				    m, d->rgn, sizeof d->rgn);
		else
			snprintf(d->rgn, sizeof d->rgn, "-");
		/* The range decides which occurrence the row reports, so the
		 * marker has to be found again under the new one. */
		decl_locate(e, d);
	}
}

/*
 * Parse the scratch back into the declaration.
 *
 * A hex pattern keeps its spelling in `hexs` - that is what generation writes
 * and what a wildcard lives in - and the concrete prefix of it is decoded into
 * `bytes` so the row can still say how long it is and where it is. A literal is
 * its characters and nothing else.
 *
 * Either way the bytes have changed, so where they are is asked again rather
 * than carried over: the whole point of an edit is that it may no longer be the
 * same run, and a stale offset would light the wrong bytes in the pane.
 */
void decl_edit_commit(struct kof_editor *e, uint32_t i)
{
	struct decl *d;
	size_t n = strlen(e->dr.sedit);
	uint8_t *nb;

	if (i >= e->dr.n_decl)
		return;
	d = &e->dr.decl[i];
	/* Every refusal below comes BEFORE the marker is touched: "unchanged" is the status line's word and the marker's too. */
	if (!n) {
		/* A marker that never had text (a new one, left empty) is not kept: it would stay as a row of length 0. */
		if (!d->len) {
			decl_remove(e, i);
			say_note(e, "String %u had no text - not kept", i + 1u);
			return;
		}
		say_note(e, "String %u would be empty - unchanged", i + 1u);
		return;
	}
	if (d->hex) {
		/*
		 * Refused rather than truncated. A hex pattern cut off halfway
		 * is still a valid pattern - a shorter one, matching something
		 * else - so writing it would replace the marker with a marker
		 * nobody asked for, silently.
		 */
		if (n >= sizeof d->hexs) {
			say_note(e, "Hex pattern over %u characters - unchanged",
				 (unsigned)(sizeof d->hexs - 1u));
			return;
		}
		/*
		 * Refused by the same compiler the build uses, and in its own
		 * words. A pattern the panel accepted and the build then threw
		 * out is a rule that looked right in the viewer and does not
		 * exist in the database.
		 */
		{
			uint8_t prog[KOF_HEX_MAX_PROG];
			struct kof_hex_stat st;

			if (!kof_hex_compile(e->dr.sedit, prog, sizeof prog, &st)) {
				/*
				 * Capitalised here and not at the source: the
				 * same string is printed by ksigbuilder as
				 * "file:line: message", where lowercase is the
				 * convention every compiler follows. The status
				 * line is a sentence on its own and starts like
				 * one.
				 */
				char why[160];

				snprintf(why, sizeof why, "%s", kof_hex_error());
				if (why[0] >= 'a' && why[0] <= 'z')
					why[0] = (char)(why[0] - 32);
				say_note(e, "%s", why);
				return;
			}
			if (!st.min_span) {
				say_note(e, "String %u would be empty - unchanged", i + 1u);
				return;
			}
		}
		memcpy(d->hexs, e->dr.sedit, n + 1u);
		(void)decl_from_hexs(d);
	} else {
		size_t r, w = 0;

		nb = realloc(d->bytes, n + 1u);
		if (!nb)
			return;
		d->bytes = nb;
		/*
		 * The escapes the box shows, read back - see decl_edit_open.
		 * Only ever shortens, so the buffer sized for the text holds
		 * the bytes.
		 */
		for (r = 0; r < n; r++) {
			char c = e->dr.sedit[r];

			if (c == '\\' && r + 1u < n) {
				char nx = e->dr.sedit[r + 1u];

				if (nx == 't') { c = '\t'; r++; }
				else if (nx == 'n') { c = '\n'; r++; }
				else if (nx == 'r') { c = '\r'; r++; }
				else if (nx == '\\') { c = '\\'; r++; }
			}
			d->bytes[w++] = (uint8_t)c;
		}
		d->len = (uint32_t)w;
		d->nbytes = d->len;
	}
	decl_locate(e, d);
}

void decl_remove(struct kof_editor *e, uint32_t i)
{
	/* A box open on a row that is about to move is a box on the wrong
	 * row - see kof_editor.edit. */
	if (e->edit)
		*e->edit = 0;
	if (i >= e->dr.n_decl)
		return;
	free(e->dr.decl[i].bytes);
	memmove(&e->dr.decl[i], &e->dr.decl[i + 1u],
		(e->dr.n_decl - i - 1u) * sizeof e->dr.decl[0]);
	e->dr.n_decl--;
	if (e->dr.sel_decl >= e->dr.n_decl && e->dr.n_decl)
		e->dr.sel_decl = e->dr.n_decl - 1u;
}

/*
 * The counts, computed where the tables are.
 *
 * They were macros in the header, and a macro cannot count an array it cannot
 * see: the declaration had to carry a hand-written size, which made sizeof in
 * the assert meaningless and let a wrong number through as an "excess elements"
 * warning instead of an error. A variable filled by sizeof at the definition
 * cannot be wrong.
 */
const uint32_t arch_n         = sizeof arch_word     / sizeof arch_word[0];
const uint32_t elf_sub_n      = sizeof elf_sub       / sizeof elf_sub[0];
const uint32_t pe_sub_n       = sizeof pe_sub        / sizeof pe_sub[0];
/* Every target value the engine has - see fmt_word above. */
const uint32_t fmt_word_n     = KOF_TARGET_COUNT;
const uint32_t maltype_word_n = sizeof maltype_word  / sizeof maltype_word[0];




/*
 * TICK OR UNTICK A BLOCK, and the find_similar matcher for it comes and goes
 * with the tick.
 *
 * A block is ticked to be used, and the one thing a block can be used for is a
 * similarity matcher over it, so choosing the matcher by hand was a second
 * gesture that said the same thing - and a ticked block with no matcher was a
 * state the panel then had to warn about. Ticking adds the matcher, holding
 * that one block at the default threshold; unticking drops it, and grp_remove
 * renumbers the conditions that named it, which is why this is one call and not
 * three.
 *
 * A rule read from a file brings its own matchers and sets the tick itself,
 * not through here, so what a rule declared is never added twice.
 *
 * AN OLDER RULE'S MATCHER MAY HOLD SEVERAL BLOCKS. Unticking takes this block
 * out of it and removes the matcher only when nothing is left in it: the other
 * blocks are the author's and stay measured.
 */
void blk_set_picked(struct kof_editor *e, uint32_t i, int on)
{
	uint32_t g;

	if (i >= e->dr.n_blk)
		return;
	e->dr.blk[i].picked = (uint8_t)(on != 0);
	if (on) {
		if (grp_of_block(e, i) < MAX_GROUP || e->dr.n_grp >= MAX_GROUP)
			return;
		grp_add(e);
		grp_make_sim(e, e->dr.n_grp - 1u);
		grp_sim_add(e, e->dr.n_grp - 1u, SIM_IT_BLOCK, i);
		return;
	}
	while ((g = grp_of_block(e, i)) < MAX_GROUP) {
		uint32_t k;

		for (k = e->dr.grp[g].n_sim; k--; )
			if (e->dr.grp[g].sim[k].what == SIM_IT_BLOCK &&
			    e->dr.grp[g].sim[k].blk == i)
				grp_sim_del(e, g, k);
		if (!e->dr.grp[g].n_sim)
			grp_remove(e, g);
	}
}

/*
 * TURN A MATCHER INTO A SIMILARITY MATCHER, holding nothing yet.
 *
 * Which measures it ends up about is chosen on its own row afterwards - the
 * menu that creates it chooses the KIND, the way it does for the four search
 * rules, and a menu that also chose the measures would be two questions on one
 * row. It used to be given the first ticked block as a starting point; with
 * several measures to choose between there is no first item that is not a
 * guess, so it starts empty and its list row says so, exactly as a fresh
 * search matcher's says "none yet".
 */
int grp_make_sim(struct kof_editor *e, uint32_t g)
{
	if (g >= e->dr.n_grp)
		return 0;
	e->dr.grp[g].kind  = (uint8_t)GRP_KIND_SIM;
	e->dr.grp[g].n_sim = 0;
	if (!e->dr.grp[g].pct)
		e->dr.grp[g].pct = (uint8_t)GRP_PCT_DEFAULT;
	return 1;
}

uint32_t sim_pct_default(uint32_t what)
{
	/* Every measure left keeps GRP_PCT_DEFAULT, which is where the block scorer
	 * was measured. A matcher has one threshold, so this is what the FIRST
	 * measure put into an empty one sets it to - after that the author owns it. */
	(void)what;
	return GRP_PCT_DEFAULT;
}


int grp_sim_has(const struct kof_editor *e, uint32_t g, uint32_t what,
		uint32_t blk)
{
	uint32_t i;

	if (g >= e->dr.n_grp || e->dr.grp[g].kind != GRP_KIND_SIM)
		return 0;
	for (i = 0; i < e->dr.grp[g].n_sim; i++) {
		const struct grp_sim_item *it = &e->dr.grp[g].sim[i];

		if (it->what != what)
			continue;
		/* Only a block is told apart by which one - the other three
		 * are about the object and there is one of each. */
		if (what != SIM_IT_BLOCK || it->blk == blk)
			return 1;
	}
	return 0;
}

uint32_t grp_sim_of(const struct kof_editor *e, uint32_t what, uint32_t blk)
{
	uint32_t g;

	for (g = 0; g < e->dr.n_grp; g++)
		if (grp_sim_has(e, g, what, blk))
			return g;
	return MAX_GROUP;
}


int grp_sim_add(struct kof_editor *e, uint32_t g, uint32_t what, uint32_t blk)
{
	struct group *q;

	if (g >= e->dr.n_grp)
		return 0;
	q = &e->dr.grp[g];
	if (q->kind != GRP_KIND_SIM)
		return 0;
	if (grp_sim_has(e, g, what, blk))
		return 1;              /* already there, which is success */
	if (q->n_sim >= GRP_SIM_MAX)
		return 0;
	q->sim[q->n_sim].what = (uint8_t)what;
	q->sim[q->n_sim].blk  = what == SIM_IT_BLOCK ? blk : 0u;
	/* THE FIRST MEASURE SETS THE THRESHOLD, and only the first: after that
	 * the number on the row is the author's and adding a second measure
	 * must not move it under them. */
	if (!q->n_sim)
		q->pct = (uint8_t)sim_pct_default(what);
	q->n_sim++;
	return 1;
}

void grp_sim_del(struct kof_editor *e, uint32_t g, uint32_t i)
{
	struct group *q;

	if (g >= e->dr.n_grp)
		return;
	q = &e->dr.grp[g];
	if (q->kind != GRP_KIND_SIM || i >= q->n_sim)
		return;
	memmove(&q->sim[i], &q->sim[i + 1u],
		(size_t)(q->n_sim - i - 1u) * sizeof q->sim[0]);
	q->n_sim--;
}

/*
 * HOW A MATCHER IS NAMED IN A LIST, which is not always its search rule.
 *
 * grp_rule_label answers for the four search rules and means nothing to a block
 * matcher, whose `rule` field is zero - so a menu built from it alone listed a
 * find_similar as "find_all", which is a different matcher that this one is
 * not. Written once because two menus offer the same list and a third would
 * have been written the same wrong way.
 *
 * The number is the id a condition names it by, one-based, as everything the
 * reader sees uses.
 */
void grp_label(const struct kof_editor *e, uint32_t g, char *out, size_t cap)
{
	if (!out || !cap)
		return;
	if (g >= e->dr.n_grp) {
		snprintf(out, cap, "%u", g + 1u);
		return;
	}
	/*
	 * THE WORDS THE MATCHERS TABLE USES: find_str, find_at and find_sim,
	 * and a block matcher by its hash, since two of them differ in nothing
	 * else. The three threshold spellings of find_str are one matcher on
	 * screen.
	 */
	if (e->dr.grp[g].kind == GRP_KIND_SIM) {
		uint32_t b = e->dr.grp[g].n_sim ? e->dr.grp[g].sim[0].blk
						: e->dr.n_blk;

		snprintf(out, cap, "%u  find_sim  %08x", grp_loc(e, g),
			 b < e->dr.n_blk ? e->dr.blk[b].id : 0u);
	} else {
		snprintf(out, cap, "%u  %s", grp_loc(e, g),
			 grp_is_at(e->dr.grp[g].rule) ? "find_at" : "find_str");
	}
}


/*
 * Does this block clear what the rule demands of it.
 *
 * The demand is on the MATCHER that names the block, not on the block - a block
 * is a run of bytes and has no opinion about how much of it is enough. A block
 * no matcher names has no demand to clear.
 */
int blk_clears(const struct kof_editor *e, uint32_t i)
{
	uint32_t g = grp_of_block(e, i);

	/* The demand is the MATCHER'S threshold, which every measure it names
	 * has to reach - see struct group.pct. */
	return g < MAX_GROUP && i < e->dr.n_blk &&
	       e->dr.blk[i].score >= e->dr.grp[g].pct;
}

/*
 * A BLOCK MOVED, SO WHATEVER NAMES IT MOVES WITH IT.
 *
 * A matcher holds the block's INDEX, and the list is rebuilt whenever the
 * object changes: unticked blocks dropped, ticked ones compacted to the front,
 * the whole thing sorted into file order. Each of those moves a block to a
 * different index, and a matcher left pointing at the old one is a matcher
 * about a different block, or about nothing.
 *
 * Called with the OLD index and the new one, before the record is copied, so a
 * matcher is updated exactly once per move.
 */
void blk_moved(struct kof_editor *e, uint32_t from, uint32_t to)
{
	uint32_t g;

	if (from == to)
		return;
	for (g = 0; g < e->dr.n_grp; g++) {
		uint32_t i;

		if (e->dr.grp[g].kind != GRP_KIND_SIM)
			continue;
		for (i = 0; i < e->dr.grp[g].n_sim; i++)
			if (e->dr.grp[g].sim[i].what == SIM_IT_BLOCK &&
			    e->dr.grp[g].sim[i].blk == from)
				e->dr.grp[g].sim[i].blk = to;
	}
}

/*
 * A WHOLE REORDERING OF THE BLOCKS, applied to every matcher once.
 *
 * `to[old]` is where the block that WAS at `old` is now. It is not a series of
 * blk_moved calls, because a series cannot express a permutation: moving 0 to
 * 53 and then 53 to 4 moves the item that was just moved a second time, so a
 * matcher ended up naming a block it never named - and the draft read as edited
 * the moment a rule was opened, which refuses to switch file.
 */
void blk_permute(struct kof_editor *e, const uint32_t *to, uint32_t n)
{
	uint32_t g, i;

	for (g = 0; g < e->dr.n_grp; g++) {
		if (e->dr.grp[g].kind != GRP_KIND_SIM)
			continue;
		for (i = 0; i < e->dr.grp[g].n_sim; i++)
			if (e->dr.grp[g].sim[i].what == SIM_IT_BLOCK &&
			    e->dr.grp[g].sim[i].blk < n)
				e->dr.grp[g].sim[i].blk =
					to[e->dr.grp[g].sim[i].blk];
	}
}

/*
 * Which matcher names this block, or MAX_GROUP when none does.
 *
 * The question three things ask: the menu that offers a block to a new matcher
 * and must not offer one twice, the check that refuses a draft holding a
 * declared block nothing uses, and the table that shows what each block is
 * measured against.
 */
uint32_t grp_of_block(const struct kof_editor *e, uint32_t blk)
{
	return grp_sim_of(e, SIM_IT_BLOCK, blk);
}


uint8_t grp_tab(const struct kof_editor *e, uint32_t g)
{
	if (g >= e->dr.n_grp)
		return DT_PATTERNS;
	switch (e->dr.grp[g].kind) {
	case GRP_KIND_SIM:  return DT_BLOCKS;
	default:            return DT_PATTERNS;
	}
}

uint32_t grp_tab_count(const struct kof_editor *e, uint8_t tab)
{
	uint32_t g, n = 0;

	for (g = 0; g < e->dr.n_grp; g++)
		n += grp_tab(e, g) == tab;
	return n;
}


/* One word of a file name: lower case, [a-z0-9_-] kept and the rest dropped. */
static size_t name_word(char *out, size_t cap, size_t n, const char *w)
{
	for (; *w && n + 1u < cap; w++) {
		unsigned char ch = (unsigned char)*w;

		if (isalnum(ch) || ch == '_' || ch == '-')
			out[n++] = (char)tolower(ch);
	}
	return n;
}

/* `<type>_<family>_<tag>` of one diagnose unit: what a running id is counted
 * within, and the one place the output's name is composed. The type is the
 * UNIT's own (struct cond.utype), the family the header's and the tag the
 * unit's. A type or tag not chosen yet is written `<type>` / `<tag>` so the gap
 * shows; no family is left out (a generic diagnose), so no underscore is
 * doubled. */
static void tag_prefix(const struct kof_editor *e, uint8_t utype,
		       const char *tag, char *out, size_t cap)
{
	size_t n = 0;

	if (utype)
		n = name_word(out, cap, n, kof_maltype_name((uint32_t)utype - 1u));
	else
		n = (size_t)snprintf(out, cap, "<type>");
	if (e->dr.family[0]) {
		if (n && n + 1u < cap)
			out[n++] = '_';
		n = name_word(out, cap, n, e->dr.family);
	}
	if (n && n + 1u < cap)
		out[n++] = '_';
	if (tag[0])
		n = name_word(out, cap, n, tag);
	else
		n += (size_t)snprintf(out + n, n < cap ? cap - n : 0u, "<tag>");
	out[n < cap ? n : cap - 1u] = 0;
}

/*
 * THE DIAGNOSE UNITS, the one list, and the rule is two lines: a PATTERNS CONDITION is a unit, and a
 * BLOCKS MATCHER is a unit; nothing else is (a string matcher is part of the conditions that name it,
 * the Graphs tab writes nothing). The draw, the hit zones of the Type and Tag cells,
 * the file names, the preview and the writer all ask this list, so they cannot disagree about which
 * units exist. Order = the output's: the conditions first, then the block matchers.
 */
_Static_assert(DRAFT_UNIT_MAX == 2u * MAX_GROUP, "a draft holds MAX_GROUP conditions and MAX_GROUP matchers");

uint32_t draft_units(const struct kof_editor *e, struct draft_unit *out, uint32_t cap)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_cnd && n < cap; i++) {
		const struct cond *c = &e->dr.cnd[i];

		out[n].is_grp = 0;
		out[n].idx = i;
		out[n].utype = c->utype;
		out[n].tag = c->tag;
		n++;
	}
	for (i = 0; i < e->dr.n_grp && n < cap; i++) {
		const struct group *q = &e->dr.grp[i];

		if (q->kind != GRP_KIND_SIM)
			continue;
		out[n].is_grp = 1;
		out[n].idx = i;
		out[n].utype = q->utype;
		out[n].tag = q->tag;
		n++;
	}
	return n;
}

/* How many units the draft has: what Generate has to write. */
uint32_t draft_unit_count(const struct kof_editor *e)
{
	struct draft_unit u[DRAFT_UNIT_MAX];

	return draft_units(e, u, DRAFT_UNIT_MAX);
}

/* The units the open tab lists: Patterns its conditions, Blocks its matchers, Graphs none. */
uint32_t draft_units_on_tab(const struct kof_editor *e, uint8_t tab, struct draft_unit *out, uint32_t cap)
{
	struct draft_unit all[DRAFT_UNIT_MAX];
	uint32_t i, n = 0, m = draft_units(e, all, DRAFT_UNIT_MAX);

	if (tab != DT_PATTERNS && tab != DT_BLOCKS)
		return 0;
	for (i = 0; i < m && n < cap; i++)
		if (all[i].is_grp == (tab == DT_BLOCKS))
			out[n++] = all[i];
	return n;
}

/* Where unit (is_grp, idx) is in the output order, or -1 when it is no unit: its cells are not drawn and its name is empty. */
int draft_unit_find(const struct kof_editor *e, int is_grp, uint32_t idx)
{
	struct draft_unit u[DRAFT_UNIT_MAX];
	uint32_t i, n = draft_units(e, u, DRAFT_UNIT_MAX);

	for (i = 0; i < n; i++)
		if (!u[i].is_grp == !is_grp && u[i].idx == idx)
			return (int)i;
	return -1;
}

static int loaded_find(const struct kof_editor *e, uint32_t id);

/* A file name of a unit that is being worked out: only the part the numbering reads. */
struct unit_out {
	char  fn[200];
	char *text;
	size_t n;
	char  label[40];        /* "condition 2", "block matcher 3": what a refusal names */
};

/* The first `<prefix>_NN.c` (NN 01 to 99) that is not a file of `dir` and not the name of a unit before `k` in `u`; 0 when none is free.
 * THE ONE PLACE A NEW NAME IS NUMBERED: the panel shows it and Save writes it, so they cannot differ. */
static uint32_t unit_free_number(const char *dir, const char *prefix, const struct unit_out *u, uint32_t k)
{
	uint32_t nn, j;

	for (nn = 1; nn <= 99u; nn++) {
		char fn[200], path[4400];
		int taken = 0;

		snprintf(fn, sizeof fn, "%s_%02u.c", prefix, nn);
		snprintf(path, sizeof path, "%s/%s", dir, fn);
		for (j = 0; j < k; j++)
			taken |= !strcmp(u[j].fn, fn);
		if (!taken && access(path, F_OK) != 0)
			return nn;
	}
	return 0;
}

/* The name of unit k: the file of the diagnose it carries the id of, else the first free number (see unit_free_number). `u[0..k)` hold the
 * names of the units before it. A number is never derived from where the unit sits in the draft. */
static void unit_name_in(const struct kof_editor *e, const char *dir, const struct draft_unit *ul, uint32_t k, struct unit_out *u)
{
	uint32_t lid = ul[k].is_grp ? e->dr.grp[ul[k].idx].link : e->dr.cnd[ul[k].idx].link;
	int li = loaded_find(e, lid);
	char prefix[160];
	uint32_t nn;

	if (li >= 0) {
		snprintf(u[k].fn, sizeof u[k].fn, "%.*s.c", (int)DRAFT_LINK_MAX - 1, e->dr.loaded[li].name);
		return;
	}
	tag_prefix(e, ul[k].utype, ul[k].tag, prefix, sizeof prefix);
	nn = unit_free_number(dir, prefix, u, k);
	if (nn)
		snprintf(u[k].fn, sizeof u[k].fn, "%s_%02u.c", prefix, nn);
	else
		snprintf(u[k].fn, sizeof u[k].fn, "%s_--.c", prefix);
}

/* The file name of unit `k` of the list, as Save will write it into the tree's diagnoses directory (kof_draft.tree_dir). */
static void unit_name(const struct kof_editor *e, const struct draft_unit *u, uint32_t k, char *out, size_t cap)
{
	struct unit_out tmp[DRAFT_UNIT_MAX];
	uint32_t j;

	memset(tmp, 0, sizeof tmp);
	for (j = 0; j <= k && j < DRAFT_UNIT_MAX; j++)
		unit_name_in(e, e->dr.tree_dir, u, j, tmp);
	snprintf(out, cap, "%s", tmp[k].fn);
}

void draft_set_tree_dir(struct kof_editor *e, const char *dir)
{
	snprintf(e->dr.tree_dir, sizeof e->dr.tree_dir, "%s", dir ? dir : "");
}

void draft_unit_name(const struct kof_editor *e, int is_grp, uint32_t idx, char *out, size_t cap)
{
	struct draft_unit u[DRAFT_UNIT_MAX];
	int k;

	if (!out || !cap)
		return;
	out[0] = 0;
	draft_units(e, u, DRAFT_UNIT_MAX);
	k = draft_unit_find(e, is_grp, idx);
	if (k >= 0)
		unit_name(e, u, (uint32_t)k, out, cap);
}

void cnd_file_name(const struct kof_editor *e, uint32_t ci, char *out, size_t cap)
{
	draft_unit_name(e, 0, ci, out, cap);
}

void grp_file_name(const struct kof_editor *e, uint32_t g, char *out, size_t cap)
{
	draft_unit_name(e, 1, g, out, cap);
}

/* ---- THE GENERATOR'S OUTPUT: one diagnose source per unit ---------------------- */

/* The variant's LETTERS out of the header's catalog name "<family>_<letters>" ("Mirai_A" -> "A"), or NULL
 * when the name does not start with the family: the source names the family once, so only letters follow. */
static const char *variant_letters(const struct kof_editor *e)
{
	size_t n = strlen(e->dr.family);

	if (!n || strncmp(e->dr.variant, e->dr.family, n) || e->dr.variant[n] != '_')
		return NULL;
	return e->dr.variant + n + 1u;
}

/*
 * THE DECLARATIONS OF ONE UNIT, as diagsrc items: its name (the file's stem), the header's format
 * and subtype options (the declarations the panel has always had that a diagnose source can say),
 * and the four catalog lines - family and variant from the header, type and tag from the unit.
 * ONE function builds the list, for the file that is written and for the preview that lists it, and
 * the text of every line is the shared printer's (kof_dsrc_print): this file has no string code of
 * its own for a declaration.
 *
 * A gap (no family, no variant, no type, no tag) is simply not in the list; the caller that writes
 * refuses before it gets here (draft_unit_gap), the preview shows what is missing.
 */
void draft_unit_items(const struct kof_editor *e, const char *stem, uint8_t utype,
		      const char *tag, struct kof_dsrc *d)
{
	struct kof_dsrc_item *it;
	uint32_t f;

	memset(d, 0, sizeof *d);
	it = &d->item[d->n++];
	it->kind = KDS_NAME;
	snprintf(it->s1, sizeof it->s1, "%s", stem);
	if (e->dr.fmt_mask) {
		char words[KOF_DSRC_WORDS_LEN] = "";
		size_t at = 0;
		uint64_t val = 0;

		for (f = 0; f < KOF_FMT_COUNT; f++) {
			const char *id = kof_format_ident((uint8_t)f);

			if (!(e->dr.fmt_mask & (1u << f)) || !id)
				continue;
			if (at + strlen(id) + 4u >= sizeof words)
				break;
			at += (size_t)snprintf(words + at, sizeof words - at, "%s%s", at ? " | " : "", id);
			val |= (uint64_t)f;
		}
		it = &d->item[d->n++];
		it->kind = KDS_FORMAT;
		it->v = val;
		snprintf(it->s1, sizeof it->s1, "%s", words);
	}
	if (e->dr.opt_on[OPT_SUBTYPE]) {
		it = &d->item[d->n++];
		it->kind = KDS_SUBTYPE;
		it->v = e->dr.opt_val[OPT_SUBTYPE];
	}
	/* The two options a signature declared as targets (KOF_TARGET_SIZE_MIN, KOF_TARGET_ARCH) are conditions of the diagnose: the
	 * engine's facts for them (KOF_FACT_SIZE_MIN, KOF_FACT_ARCH_SET), written as KOF_DIAG_HAS_ATTRB lines. */
	if (e->dr.opt_on[OPT_SIZE_MIN]) {
		it = &d->item[d->n++];
		it->kind = KDS_ATTRB;
		it->a = (uint16_t)KOF_FACT_SIZE_MIN;
		it->v = e->dr.opt_val[OPT_SIZE_MIN];
	}
	if (e->dr.opt_on[OPT_ARCH] && e->dr.opt_val[OPT_ARCH] < 64u) {
		it = &d->item[d->n++];
		it->kind = KDS_ATTRB;
		it->a = (uint16_t)KOF_FACT_ARCH_SET;
		it->v = (uint64_t)1 << e->dr.opt_val[OPT_ARCH];
	}
	if (e->dr.family[0]) {
		it = &d->item[d->n++];
		it->kind = KDS_FAMILY;
		snprintf(it->s1, sizeof it->s1, "%s", e->dr.family);
	}
	if (e->dr.variant[0]) {
		it = &d->item[d->n++];
		it->kind = KDS_VARIANT;
		snprintf(it->s1, sizeof it->s1, "%s", variant_letters(e) ? variant_letters(e) : e->dr.variant);
	}
	if (utype) {
		it = &d->item[d->n++];
		it->kind = KDS_TYPE;
		it->a = (uint16_t)(utype - 1u);
	}
	if (tag[0]) {
		it = &d->item[d->n++];
		it->kind = KDS_TAG;
		snprintf(it->s1, sizeof it->s1, "%s", tag);
	}
}

/* Why a unit cannot be written, or NULL: the header and the unit must both say what the file is about. */
static const char *draft_unit_gap(const struct kof_editor *e, uint8_t utype, const char *tag)
{
	/* What a diagnose has no condition for is refused, not dropped: the file would say less than the panel does. */
	if (e->dr.opt_on[OPT_SIZE_MAX])
		return "the header sets a maximum size, which a diagnose has no condition for (the engine has none by design)";
	if (e->dr.opt_on[OPT_ARCH] && e->dr.opt_val[OPT_ARCH] >= 64u)
		return "the header names an architecture past the 64 a set of them holds";
	if (!e->dr.family[0])
		return "the header has no family";
	if (!e->dr.variant[0])
		return "the header has no variant";
	if (!utype)
		return "it has no type";
	if (!tag[0])
		return "it has no tag";
	if (!variant_letters(e) || !kof_dsrc_variant_word_ok(variant_letters(e)))
		return "the variant's name is not \"<family>_<letters>\"";
	if (!kof_dsrc_catalog_word_ok(e->dr.family) || !kof_dsrc_catalog_word_ok(tag))
		return "a name has a character a diagnose source cannot hold";
	return NULL;
}

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
	uint32_t used_decl = 0;
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
	for (g = 0; g < e->dr.n_grp; g++)
		if (cnd_uses(e, c, g))
			for (i = 0; i < e->dr.n_decl && i < 32u; i++)
				if (e->dr.decl[i].grp & (1u << g))
					used_decl |= 1u << i;
	for (i = 0; i < e->dr.n_decl && i < 32u; i++) {
		char name[FORM_NAME_MAX];

		if (!(used_decl & (1u << i)))
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
		for (i = 0; i < e->dr.n_decl && i < 32u; i++)
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

/*
 * WRITE THE OUTPUT: one `<type>_<family>_<tag>_NN.c` per unit into `dir` (the tree's bases/diagnoses).
 * ALL OR NOTHING: every unit is checked first - the header has a family and a variant, every unit a
 * type and a tag, no file of that name exists - and when any check fails NOTHING is written and `msg`
 * says which unit and why. A file is created with "wx" and never replaced: an existing file is
 * refused and named. Returns the number of files written, or -1 on a refusal (msg is the reason).
 * A write that fails part way removes the files this call made.
 */
int draft_generate(struct kof_editor *e, const char *dir, char *msg, size_t cap)
{
	return draft_generate_with(e, dir, msg, cap, 1);
}

/* What the reader said first about a text it was given: the writer reads its own output back. */
struct first_err {
	char msg[200];
	int  line;
	int  n;
};

static void first_err_cb(void *ud, int line, const char *m)
{
	struct first_err *f = ud;

	if (!f->n++) {
		snprintf(f->msg, sizeof f->msg, "%s", m);
		f->line = line;
	}
}

/*
 * THE TEXT OF ONE UNIT'S FILE: the catalog lines and, with `with_form`, its detection declarations; then the text is READ
 * BACK by the reader the builder uses (parse and resolve) and a file that would not build is a refusal here, naming the
 * line - Generate never writes a source ksigbuilder would reject for what the panel said. `with_form` 0 is the seam the
 * writer's own tests use (names, running ids, all-or-nothing): the catalog lines alone, nothing read back. Returns the text
 * (malloc'd) or NULL with `why` set.
 */
static char *unit_text(const struct kof_editor *e, const char *stem, const struct draft_unit *u, struct kof_dsrc *d,
		       size_t *n, int with_form, char *why, size_t cap)
{
	char *text;
	uint32_t q;

	draft_unit_items(e, stem, u->utype, u->tag, d);
	if (with_form) {
		const char *r = draft_unit_form(e, u->is_grp, u->idx, d);

		if (r) {
			snprintf(why, cap, "%s", r);
			return NULL;
		}
		for (q = 0; q < d->n; q++) {
			char one[8192];

			if (!kof_dsrc_print(&d->item[q], one, sizeof one)) {
				snprintf(why, cap, "one of its declarations cannot be written as source");
				return NULL;
			}
		}
	}
	text = kof_dsrc_patch("", 0, d, n);
	if (!text) {
		snprintf(why, cap, "out of memory");
		return NULL;
	}
	if (with_form) {
		struct kof_dsrc *back = calloc(1, sizeof *back);
		struct kof_dsrc_view v;
		struct first_err fe = { "", 0, 0 };
		const struct kof_dsrc_report rep = { first_err_cb, NULL, &fe };

		if (!back) {
			free(text);
			snprintf(why, cap, "out of memory");
			return NULL;
		}
		(void)kof_dsrc_parse(text, *n, back, &rep);
		if (!fe.n)
			(void)kof_dsrc_resolve(back, &v, &rep);
		else
			memset(&v, 0, sizeof v);
		kof_dsrc_view_free(&v);
		free(back);
		if (fe.n) {
			snprintf(why, cap, "the source it would write does not read: %s (line %d)", fe.msg, fe.line);
			free(text);
			return NULL;
		}
	}
	return text;
}

/* The bytes of a file, malloc'd (NUL added); NULL when it cannot be read whole. */
static char *file_bytes(FILE *f, size_t *n)
{
	char *p = NULL;
	size_t cap = 0, len = 0, got;

	for (;;) {
		char *q;

		if (len + 4097u > cap) {
			cap = cap ? cap * 2u : 8192u;
			q = realloc(p, cap);
			if (!q) {
				free(p);
				return NULL;
			}
			p = q;
		}
		got = fread(p + len, 1, 4096u, f);
		len += got;
		if (got < 4096u)
			break;
	}
	if (ferror(f)) {
		free(p);
		return NULL;
	}
	p[len] = 0;
	*n = len;
	return p;
}

/* Whether the diagnose already in `have` (its file `stem`.c, `on` bytes) says what unit k of the draft would write: both are read and
 * resolved by the builder's reader and compared by the builder's own identity (kof_dsrc_view_same: family, variant, type, tag and what it
 * looks for - the local labels of blocks and matchers, comments and spacing do not count); with `with_form` 0 the bytes are compared.
 * `id`, when given, receives the file's name and kof_dsrc_view_body_hash (only a with_form comparison reads it; else it is left alone). */
static int unit_in_file(const struct kof_editor *e, const char *stem, const struct draft_unit *ul, uint32_t k, const char *have, size_t on,
			int with_form, struct kof_dsrc *d, struct kof_dsrc *old, struct kof_dsrc *cand, struct draft_loaded *id)
{
	size_t cn = 0;
	char *want;
	char bad[260];
	int same = 0;

	want = unit_text(e, stem, &ul[k], d, &cn, with_form, bad, sizeof bad);
	if (!want)
		return 0;
	if (!with_form) {
		same = on == cn && !memcmp(have, want, cn);
	} else {
		struct first_err fo = { "", 0, 0 }, fc = { "", 0, 0 };
		const struct kof_dsrc_report ro = { first_err_cb, NULL, &fo }, rc = { first_err_cb, NULL, &fc };
		struct kof_dsrc_view vo, vc;

		memset(&vo, 0, sizeof vo);
		memset(&vc, 0, sizeof vc);
		(void)kof_dsrc_parse(have, on, old, &ro);
		(void)kof_dsrc_parse(want, cn, cand, &rc);
		if (!fo.n && !fc.n) {
			(void)kof_dsrc_resolve(old, &vo, &ro);
			(void)kof_dsrc_resolve(cand, &vc, &rc);
			same = !fo.n && !fc.n && kof_dsrc_view_same(&vo, &vc);
			if (same && id) {
				snprintf(id->name, sizeof id->name, "%s", vo.name);
				id->hash = kof_dsrc_view_body_hash(&vo);
			}
		}
		kof_dsrc_view_free(&vo);
		kof_dsrc_view_free(&vc);
	}
	free(want);
	return same;
}

/*
 * WHERE UNIT k GOES in `dir`, which is a question about the files that are already there and not only about the draft: the running id
 * of a name counts the draft's own units, so a new unit of a type, family and tag that the tree already has would name a file that exists.
 * A diagnose in the tree that says the same as the unit IS the unit (`*present`: nothing to write, the file is named); otherwise the unit
 * takes the first `<prefix>_NN.c` that is free in `dir` and among the units before it. A file is still never replaced. 0, or -1 with `why`.
 *
 * THE DIRECTORY IS READ AS IT IS BEFORE THIS SAVE: a file this Save is about to delete is still there, so its number is taken and a new
 * unit never gets the name of a file removed in the same call (a number comes back only in a later Save, when the file is really gone).
 */
static int unit_resolve(const struct kof_editor *e, const char *dir, const struct draft_unit *ul, uint32_t k, struct unit_out *u, int with_form,
			struct kof_dsrc *d, struct kof_dsrc *old, struct kof_dsrc *cand, int *present, char *why, size_t cap)
{
	char prefix[160], fn[200], path[4400];
	uint32_t nn;

	*present = 0;
	tag_prefix(e, ul[k].utype, ul[k].tag, prefix, sizeof prefix);
	for (nn = 1; nn <= 99u; nn++) {
		FILE *f;
		char stem[200];
		int same = 0;
		size_t on = 0;
		char *have;

		snprintf(fn, sizeof fn, "%s_%02u.c", prefix, nn);
		snprintf(path, sizeof path, "%s/%s", dir, fn);
		f = fopen(path, "rb");
		if (!f)
			continue;
		have = file_bytes(f, &on);
		snprintf(stem, sizeof stem, "%s", fn);
		stem[strlen(stem) - 2u] = 0;
		if (have)
			same = unit_in_file(e, stem, ul, k, have, on, with_form, d, old, cand, NULL);
		free(have);
		fclose(f);
		if (same) {
			snprintf(u[k].fn, sizeof u[k].fn, "%s", fn);
			*present = 1;
			return 0;
		}
	}
	nn = unit_free_number(dir, prefix, u, k);
	if (!nn) {
		snprintf(why, cap, "has no free number: 01 to 99 are taken in %s", dir);
		return -1;
	}
	snprintf(u[k].fn, sizeof u[k].fn, "%s_%02u.c", prefix, nn);
	return 0;
}

/* ---- THE LINK between a unit and the diagnose it was loaded from ------------------------------------------------------ */

/* A link is a diagnose name used as a file stem in the tree: letters, digits, '_' and '-' only, so it cannot hold a path, a dot or a NUL. */
static int link_name_ok(const char *n)
{
	size_t i, len = n ? strlen(n) : 0;

	if (!len || len >= DRAFT_LINK_MAX)
		return 0;
	for (i = 0; i < len; i++)
		if (!isalnum((unsigned char)n[i]) && n[i] != '_' && n[i] != '-')
			return 0;
	return 1;
}

/* The regular file `dir`/`name`.c, read whole (malloc'd, NUL added) with its mode: NULL for a missing file, a symlink, a directory, anything
 * else that is not a regular file, or one over 1 MiB. O_NOFOLLOW as well as lstat, so a link swapped in between is refused too. */
static char *tree_file(const char *dir, const char *name, size_t *n, mode_t *mode)
{
	char path[4400];
	struct stat st;
	FILE *f;
	char *b;
	int fd;

	if (!link_name_ok(name) || snprintf(path, sizeof path, "%s/%s.c", dir, name) >= (int)sizeof path)
		return NULL;
	if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (off_t)(1 << 20))
		return NULL;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	f = fdopen(fd, "rb");
	if (!f) {
		close(fd);
		return NULL;
	}
	b = file_bytes(f, n);
	fclose(f);
	*mode = st.st_mode & 07777u;
	return b;
}

/* Whether `dir`/`name`.c is simply not there (ENOENT): the one reason a file of a link may be left out of a Save quietly. Any other file that
 * cannot be read as a regular file (a symlink, a directory, too big, unreadable) is something to refuse about, not to skip. */
static int tree_missing(const char *dir, const char *name)
{
	char path[4400];
	struct stat st;

	return link_name_ok(name) && snprintf(path, sizeof path, "%s/%s.c", dir, name) < (int)sizeof path && lstat(path, &st) != 0 && errno == ENOENT;
}

/* The identity of a diagnose source: it reads and resolves, and its own name is `name`. 1 and the body hash, or 0. */
static int text_identity(const char *text, size_t n, const char *name, struct kof_dsrc *d, uint64_t *hash)
{
	struct first_err fe = { "", 0, 0 };
	const struct kof_dsrc_report rep = { first_err_cb, NULL, &fe };
	struct kof_dsrc_view v;
	int ok;

	memset(&v, 0, sizeof v);
	(void)kof_dsrc_parse(text, n, d, &rep);
	if (!fe.n)
		(void)kof_dsrc_resolve(d, &v, &rep);
	ok = !fe.n && !strcmp(v.name, name);
	if (ok)
		*hash = kof_dsrc_view_body_hash(&v);
	kof_dsrc_view_free(&v);
	return ok;
}

static uint32_t *unit_link_of(struct kof_editor *e, const struct draft_unit *u)
{
	return u->is_grp ? &e->dr.grp[u->idx].link : &e->dr.cnd[u->idx].link;
}

/* The loaded entry of id `id`, or -1. */
static int loaded_find(const struct kof_editor *e, uint32_t id)
{
	uint32_t i;

	for (i = 0; id && i < e->dr.n_loaded; i++)
		if (e->dr.loaded[i].id == id)
			return (int)i;
	return -1;
}

/* How many matchers and conditions of the draft carry the link `id` (every one, a unit or not). */
static uint32_t link_carriers(const struct kof_editor *e, uint32_t id)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_grp; i++)
		n += id && e->dr.grp[i].link == id;
	for (i = 0; i < e->dr.n_cnd; i++)
		n += id && e->dr.cnd[i].link == id;
	return n;
}

void draft_links_reset(struct kof_editor *e)
{
	uint32_t i;

	for (i = 0; i < MAX_GROUP; i++) {
		e->dr.grp[i].link = 0;
		e->dr.cnd[i].link = 0;
	}
	memset(e->dr.loaded, 0, sizeof e->dr.loaded);
	e->dr.n_loaded = 0;
}

uint32_t draft_unit_link(const struct kof_editor *e, int is_grp, uint32_t idx)
{
	if (is_grp)
		return idx < e->dr.n_grp ? e->dr.grp[idx].link : 0u;
	return idx < e->dr.n_cnd ? e->dr.cnd[idx].link : 0u;
}

uint32_t draft_links_loaded(const struct kof_editor *e)
{
	return e->dr.n_loaded;
}

uint32_t draft_links_removed(const struct kof_editor *e)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_loaded; i++)
		n += !link_carriers(e, e->dr.loaded[i].id);
	return n;
}

/*
 * LINK UNIT (is_grp, idx) TO THE DIAGNOSE `name` it was loaded from - only when the draft says EXACTLY what that file says: the unit is
 * regenerated from the loaded state and compared with the file by the builder's identity (kof_dsrc_view_same). A diagnose the panel
 * cannot represent whole (several matchers, an expression written by hand, a threshold or block that differs) therefore never gets a link, and
 * what has no link is never modified or deleted. The file must be a regular file of the tree (no symlink), named `name`.c and carrying that
 * name. Refused too: a unit that is already linked, a name another unit carries, a full list. 1 when linked, else 0.
 */
int draft_link_unit(struct kof_editor *e, int is_grp, uint32_t idx, const char *dir, uint32_t did, const char *name)
{
	struct draft_unit ul[DRAFT_UNIT_MAX];
	struct kof_dsrc *d = NULL, *old = NULL, *cand = NULL;
	struct draft_loaded id;
	char *have = NULL;
	size_t on = 0;
	mode_t mode;
	int k, linked = 0;

	if (!did || !link_name_ok(name) || e->dr.n_loaded >= DRAFT_LOADED_MAX || link_carriers(e, did) || loaded_find(e, did) >= 0)
		return 0;
	(void)draft_units(e, ul, DRAFT_UNIT_MAX);
	k = draft_unit_find(e, is_grp, idx);
	if (k < 0 || draft_unit_link(e, is_grp, idx))
		return 0;
	d = calloc(1, sizeof *d);
	old = calloc(1, sizeof *old);
	cand = calloc(1, sizeof *cand);
	have = d && old && cand ? tree_file(dir, name, &on, &mode) : NULL;
	memset(&id, 0, sizeof id);
	if (have && unit_in_file(e, name, ul, (uint32_t)k, have, on, 1, d, old, cand, &id) && !strcmp(id.name, name)) {
		*unit_link_of(e, &ul[k]) = did;
		id.id = did;
		e->dr.loaded[e->dr.n_loaded++] = id;
		linked = 1;
	}
	free(have);
	free(d);
	free(old);
	free(cand);
	return linked;
}

/* ---- THE SAVE: what was added is written, what was removed is deleted --------------------------------------------------- */

static FILE *fs_create(void *ud, const char *path)
{
	(void)ud;
	return fopen(path, "wbx");
}

static int fs_unlink(void *ud, const char *path)
{
	(void)ud;
	return unlink(path);
}

static const struct draft_fs fs_real = { NULL, fs_create, fs_unlink };

/* A file this Save deletes: kept whole in memory until the Save is over, so a failure part way can put it back. */
struct del_plan {
	uint32_t id;
	char   name[DRAFT_LINK_MAX];
	char  *bytes;
	size_t n;
	mode_t mode;
	int    keep;            /* a unit that says the same was added again: the file stays */
	int    gone;            /* deleted by this call */
};

/* Append to the status line; when it does not fit the end says so. */
static void say_add(char *msg, size_t cap, const char *fmt, ...)
{
	size_t at = strlen(msg);
	va_list ap;
	int w;

	if (at + 1u >= cap)
		return;
	va_start(ap, fmt);
	w = vsnprintf(msg + at, cap - at, fmt, ap);
	va_end(ap);
	if (w >= 0 && (size_t)w >= cap - at && cap > 4u)
		memcpy(msg + cap - 4u, "...", 4u);
}

/* " a, b, c" - the names (stems) of the files `names[i]` for the flagged entries. */
static void say_names(char *msg, size_t cap, const char *const *names, const int *flag, uint32_t n)
{
	uint32_t i, first = 1;

	for (i = 0; i < n; i++) {
		size_t L;
		char stem[200];

		if (!flag[i])
			continue;
		snprintf(stem, sizeof stem, "%s", names[i]);
		L = strlen(stem);
		if (L > 2u && !strcmp(stem + L - 2u, ".c"))
			stem[L - 2u] = 0;
		say_add(msg, cap, "%s%s", first ? " " : ", ", stem);
		first = 0;
	}
}

static void put_back(const char *dir, struct del_plan *dp, uint32_t nd, char *msg, size_t cap)
{
	uint32_t z;

	for (z = 0; z < nd; z++) {
		char path[4400];
		FILE *f;

		if (!dp[z].gone)
			continue;
		snprintf(path, sizeof path, "%s/%s.c", dir, dp[z].name);
		f = fopen(path, "wbx");
		if (f && fwrite(dp[z].bytes, 1, dp[z].n, f) == dp[z].n && fclose(f) == 0) {
			(void)chmod(path, dp[z].mode);
			dp[z].gone = 0;
			continue;
		}
		if (f)
			fclose(f);
		say_add(msg, cap, " [%s.c could not be put back]", dp[z].name);
	}
}

/* `with_form` 0 writes the catalog lines only, which is the seam the writer's own tests use; Generate passes 1. */
int draft_generate_with(struct kof_editor *e, const char *dir, char *msg, size_t cap, int with_form)
{
	return draft_generate_fs(e, dir, msg, cap, with_form, &fs_real);
}

/*
 * THE HEADER COMMENT in front of a unit's new text (kof_dsrc_head, diagsrc.h): the sample's file name and the digest the properties
 * pane shows for the object (obj_sha256, cached in the object), the host's date today, the engine's numbers.
 *
 * The name is the FILE's (the top-level segment of the object's name, kobj_toplevel_len). A draft with no object writes no sample
 * line. The researcher is not written: this tool has no account name to give (the old generator asked the system for it; that code
 * went with the old editor) and a guess would sign it for somebody. A failure leaves the text as it was.
 */
static void unit_head(struct kof_editor *e, struct unit_out *u)
{
	struct kof_dsrc_meta m;
	char name[256], today[24];
	struct object *ob = e->obj && e->n_obj && e->cur < *e->n_obj ? &e->obj[e->cur] : NULL;
	time_t now = time(NULL);
	struct tm tmv;
	size_t hn = 0;
	char *t;

	memset(&m, 0, sizeof m);
	if (ob) {
		size_t k = kobj_toplevel_len(ob->name);

		snprintf(name, sizeof name, "%.*s", (int)(k < sizeof name - 1u ? k : sizeof name - 1u), ob->name);
		obj_sha256(ob);
		m.name = kof_path_base(name);
		m.sha256 = ob->sha256[0] ? ob->sha256 : NULL;
	}
	if (localtime_r(&now, &tmv) == NULL || !strftime(today, sizeof today, "%Y-%m-%d", &tmv))
		return;
	m.date = today;
	t = kof_dsrc_head(u->text, u->n, &m, NULL, &hn);
	if (!t)
		return;
	free(u->text);
	u->text = t;
	u->n = hn;
}

/*
 * SAVE: ADD and REMOVE by one mechanism, the link (see draft_link_unit). The plan comes first and the disk is not touched until all of
 * it is sound:
 *   a unit with no link is NEW: written to a new file (a file in the tree that already says the same is not written again);
 *   a unit whose link was loaded and whose content still equals its file is UNTOUCHED;
 *   a unit whose link was loaded and whose content is not its file's is MODIFIED: editing a diagnose is not done, so it is reported,
 *     not written (no new duplicate) and its file is not deleted;
 *   a loaded link that no matcher or condition carries any more is REMOVED: its file is deleted - the file must still be the regular
 *     file that was loaded (name and body hash), or the Save refuses.
 * Then the new files are created and the removed ones unlinked; a failure part way puts back every file this call deleted (from the
 * copy kept in memory) and removes every file it created. Returns the number of files written, or -1 on a refusal (msg is the reason).
 */
int draft_generate_fs(struct kof_editor *e, const char *dir, char *msg, size_t cap, int with_form, const struct draft_fs *fs)
{
	struct unit_out *u = NULL;
	struct kof_dsrc *d = NULL, *old = NULL, *cand = NULL;
	struct draft_unit ul[DRAFT_UNIT_MAX];
	struct del_plan dp[DRAFT_LOADED_MAX];
	int present[DRAFT_UNIT_MAX], linked[DRAFT_UNIT_MAX], towrite[DRAFT_UNIT_MAX], gone_link[DRAFT_LOADED_MAX];
	const char *names[DRAFT_UNIT_MAX];
	char delnames[DRAFT_LOADED_MAX][DRAFT_LINK_MAX + 3];
	const char *delp[DRAFT_LOADED_MAX];
	int delflag[DRAFT_LOADED_MAX];
	uint32_t n, k, i, nsame = 0, nmod = 0, nnew = 0, nd = 0, ndel = 0;
	int rc = -1;
	const char *why;

	msg[0] = 0;
	memset(dp, 0, sizeof dp);
	memset(gone_link, 0, sizeof gone_link);
	u = calloc((size_t)MAX_GROUP * 2u + 2u, sizeof *u);
	d = calloc(1, sizeof *d);
	old = calloc(1, sizeof *old);
	cand = calloc(1, sizeof *cand);
	if (!u || !d || !old || !cand) {
		snprintf(msg, cap, "out of memory");
		goto out;
	}
	n = draft_units(e, ul, DRAFT_UNIT_MAX);
	for (k = 0; k < n; k++) {
		unit_name_in(e, dir, ul, k, u);
		if (!ul[k].is_grp) {
			const struct cond *c = &e->dr.cnd[ul[k].idx];

			snprintf(u[k].label, sizeof u[k].label, "condition %u", ul[k].idx + 1u);
			why = draft_unit_gap(e, ul[k].utype, ul[k].tag);
			if (!why && cnd_foreign(e, c))
				why = "it names a matcher that is not on this tab";
		} else {
			snprintf(u[k].label, sizeof u[k].label, "block matcher %u", ul[k].idx + 1u);
			why = draft_unit_gap(e, ul[k].utype, ul[k].tag);
		}
		if (why) {
			snprintf(msg, cap, "Not written: %s %s", u[k].label, why);
			goto out;
		}
	}
	{
		struct stat st;

		if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
			snprintf(msg, cap, "Not written: %s is not a directory", dir);
			goto out;
		}
	}
	/* THE LINKS. One diagnose, one carrier: a link two matchers or conditions carry is a draft that cannot say what is removed. */
	for (i = 0; i < e->dr.n_loaded; i++)
		if (link_carriers(e, e->dr.loaded[i].id) > 1u) {
			snprintf(msg, cap, "Not written: two units are linked to %s.c", e->dr.loaded[i].name);
			goto out;
		}
	for (k = 0; k < n; k++) {
		const uint32_t lid = *unit_link_of(e, &ul[k]);
		const char *lk = lid && loaded_find(e, lid) >= 0 ? e->dr.loaded[loaded_find(e, lid)].name : "";
		char *have;
		size_t on = 0;
		mode_t mode;

		linked[k] = 0;
		if (!lk[0])
			continue;
		have = tree_file(dir, lk, &on, &mode);
		if (!have) {
			if (!tree_missing(dir, lk)) {
				snprintf(msg, cap, "Not written: %s.c is not a regular file that can be read", lk);
				goto out;
			}
			/* The file is gone: nothing to modify and nothing to delete; the unit is new. */
			gone_link[loaded_find(e, lid)] = 1;
			continue;
		}
		linked[k] = unit_in_file(e, lk, ul, k, have, on, with_form, d, old, cand, NULL) ? 1 : 2;
		free(have);
		snprintf(u[k].fn, sizeof u[k].fn, "%s.c", lk);
		nmod += linked[k] == 2;
		nsame += linked[k] == 1;
	}
	/* A loaded link that nothing carries is a removal; one that a matcher carries which is no unit (its kind was changed) is a modification. */
	for (i = 0; i < e->dr.n_loaded; i++) {
		const char *nm = e->dr.loaded[i].name;
		uint32_t units = 0, carried = link_carriers(e, e->dr.loaded[i].id);

		if (gone_link[i])
			continue;
		for (k = 0; k < n; k++)
			units += *unit_link_of(e, &ul[k]) == e->dr.loaded[i].id;
		if (carried > units) {
			nmod++;
			continue;
		}
		if (carried)
			continue;
		{
			size_t on = 0;
			mode_t mode;
			uint64_t h = 0;
			char *have = tree_file(dir, nm, &on, &mode);

			if (!have) {
				if (!tree_missing(dir, nm)) {
					snprintf(msg, cap, "Not written: %s.c is not a regular file that can be read, so it is not deleted", nm);
					goto out;
				}
				gone_link[i] = 1;
				continue;
			}
			if (!text_identity(have, on, nm, d, &h) || h != e->dr.loaded[i].hash) {
				snprintf(msg, cap, "Not written: %s.c is not the diagnose that was loaded (it changed), so it is not deleted", nm);
				free(have);
				goto out;
			}
			dp[nd].id = e->dr.loaded[i].id;
			snprintf(dp[nd].name, sizeof dp[nd].name, "%s", nm);
			dp[nd].bytes = have;
			dp[nd].n = on;
			dp[nd].mode = mode;
			nd++;
		}
	}
	if (!n && !nd && !nmod) {
		snprintf(msg, cap, "Nothing to write: add a condition or a block matcher first");
		goto out;
	}
	for (k = 0; k < n; k++) {
		char bad[260];
		size_t len = strlen(u[k].fn);

		present[k] = 0;
		if (linked[k])
			continue;
		if (len < 3u || len - 2u >= KOF_DSRC_NAME_LEN) {
			snprintf(msg, cap, "Not written: the name %s is too long for a diagnose", u[k].fn);
			goto out;
		}
		if (unit_resolve(e, dir, ul, k, u, with_form, d, old, cand, &present[k], bad, sizeof bad) < 0) {
			snprintf(msg, cap, "Not written: %s %s", u[k].label, bad);
			goto out;
		}
		nsame += present[k] != 0;
		/* A unit added again that says what a file to be deleted says IS that diagnose: the file stays, and the unit takes its link. */
		for (i = 0; present[k] && i < nd; i++) {
			char fn[DRAFT_LINK_MAX + 3];

			snprintf(fn, sizeof fn, "%.*s.c", (int)DRAFT_LINK_MAX - 1, dp[i].name);
			dp[i].keep |= !strcmp(fn, u[k].fn);
		}
	}
	/* The text of every file, before the first is created. */
	for (k = 0; k < n; k++) {
		char stem[200], bad[260];

		towrite[k] = !linked[k] && !present[k];
		if (!towrite[k])
			continue;
		snprintf(stem, sizeof stem, "%s", u[k].fn);
		stem[strlen(stem) - 2u] = 0;
		u[k].text = unit_text(e, stem, &ul[k], d, &u[k].n, with_form, bad, sizeof bad);
		if (!u[k].text) {
			snprintf(msg, cap, "Not written: %s %s", u[k].label, bad);
			goto out;
		}
		/* unit_in_file compares what the draft says (a form read back ignores comments); the catalog-only seam (with_form 0) compares bytes and writes none. */
		if (with_form)
			unit_head(e, &u[k]);
		nnew++;
	}
	for (k = 0; k < n; k++) {
		char path[4400];
		FILE *f;

		if (!towrite[k])
			continue;
		snprintf(path, sizeof path, "%s/%s", dir, u[k].fn);
		f = fs->create(fs->ud, path);
		if (!f || fwrite(u[k].text, 1, u[k].n, f) != u[k].n) {
			uint32_t z;

			snprintf(msg, cap, "Not written: cannot create %s in %s", u[k].fn, dir);
			/* Only a file this call created is removed: "wx" failing means somebody else's. */
			if (f) {
				fclose(f);
				(void)remove(path);
			}
			for (z = 0; z < k; z++) {
				if (!towrite[z])
					continue;
				snprintf(path, sizeof path, "%s/%s", dir, u[z].fn);
				(void)remove(path);
			}
			goto out;
		}
		if (fclose(f) != 0) {
			uint32_t z;

			snprintf(msg, cap, "Not written: cannot finish %s in %s", u[k].fn, dir);
			for (z = 0; z <= k; z++) {
				if (!towrite[z])
					continue;
				snprintf(path, sizeof path, "%s/%s", dir, u[z].fn);
				(void)remove(path);
			}
			goto out;
		}
	}
	for (i = 0; i < nd; i++) {
		char path[4400];
		struct stat st;

		if (dp[i].keep)
			continue;
		snprintf(path, sizeof path, "%s/%s.c", dir, dp[i].name);
		/* The exact file, and only if it is still a regular file (not a link put there since the plan). */
		if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || fs->unlink(fs->ud, path) != 0) {
			uint32_t z;

			snprintf(msg, cap, "Not written: cannot delete %s.c from %s; nothing was changed", dp[i].name, dir);
			put_back(dir, dp, nd, msg, cap);
			for (z = 0; z < n; z++) {
				if (!towrite[z])
					continue;
				snprintf(path, sizeof path, "%s/%s", dir, u[z].fn);
				(void)remove(path);
			}
			goto out;
		}
		dp[i].gone = 1;
		ndel++;
	}
	/* Done: the draft's own record follows the disk. */
	for (k = 0; k < n; k++) {
		uint32_t *lk = unit_link_of(e, &ul[k]);

		if (!linked[k] && *lk)
			*lk = 0;                       /* its file was gone: a new unit now */
		for (i = 0; present[k] && i < nd; i++) {
			char fn[DRAFT_LINK_MAX + 3];

			snprintf(fn, sizeof fn, "%.*s.c", (int)DRAFT_LINK_MAX - 1, dp[i].name);
			if (dp[i].keep && !strcmp(u[k].fn, fn))
				*lk = dp[i].id;
		}
	}
	for (i = e->dr.n_loaded; i-- > 0; ) {
		int drop = gone_link[i];
		uint32_t z;

		for (z = 0; z < nd; z++)
			drop |= dp[z].gone && dp[z].id == e->dr.loaded[i].id;
		if (drop) {
			memmove(&e->dr.loaded[i], &e->dr.loaded[i + 1u], (e->dr.n_loaded - i - 1u) * sizeof e->dr.loaded[0]);
			e->dr.n_loaded--;
		}
	}
	/* A unit just written IS a loaded diagnose from now on: it takes the id the engine derives for its name (kof_diag_id32_, the engine's own
	 * function), so that taking it out later deletes the file written here and a second Save does not see it as new. */
	for (k = 0; k < n; k++) {
		char stem[DRAFT_LINK_MAX];
		uint64_t h = 0;
		uint32_t nid;

		if (!towrite[k] || strlen(u[k].fn) - 2u >= DRAFT_LINK_MAX)
			continue;
		snprintf(stem, sizeof stem, "%.*s", (int)strlen(u[k].fn) - 2, u[k].fn);
		nid = kof_diag_id32_(stem);
		if (!nid || e->dr.n_loaded >= DRAFT_LOADED_MAX || loaded_find(e, nid) >= 0 || link_carriers(e, nid) || *unit_link_of(e, &ul[k]) ||
		    !text_identity(u[k].text, u[k].n, stem, d, &h))
			continue;
		*unit_link_of(e, &ul[k]) = nid;
		e->dr.loaded[e->dr.n_loaded].id = nid;
		snprintf(e->dr.loaded[e->dr.n_loaded].name, sizeof e->dr.loaded[0].name, "%s", stem);
		e->dr.loaded[e->dr.n_loaded++].hash = h;
	}
	for (k = 0; k < n; k++)
		names[k] = u[k].fn;
	for (i = 0; i < nd; i++) {
		snprintf(delnames[i], sizeof delnames[i], "%.*s.c", (int)DRAFT_LINK_MAX - 1, dp[i].name);
		delp[i] = delnames[i];
		delflag[i] = dp[i].gone;
	}
	if (!nnew && !ndel && !nmod) {
		snprintf(msg, cap, "Nothing new to write: the %u diagnose%s already in %s say%s the same", n, n == 1u ? "" : "s", dir, n == 1u ? "s" : "");
	} else {
		if (nnew) {
			snprintf(msg, cap, "Wrote %u file%s to %s:", nnew, nnew == 1u ? "" : "s", dir);
			say_names(msg, cap, names, towrite, n);
			if (nsame)
				say_add(msg, cap, " (%u already there, unchanged)", nsame);
		} else if (nsame) {
			snprintf(msg, cap, "%u unchanged", nsame);
		}
		if (ndel) {
			say_add(msg, cap, "%sDeleted %u file%s from %s:", msg[0] ? "; " : "", ndel, ndel == 1u ? "" : "s", dir);
			say_names(msg, cap, delp, delflag, nd);
		}
		if (nmod)
			say_add(msg, cap, "%s%u modified diagnose%s not saved: editing is not done", msg[0] ? "; " : "", nmod, nmod == 1u ? "" : "s");
	}
	rc = (int)nnew;
out:
	if (u)
		for (k = 0; k < (uint32_t)MAX_GROUP * 2u + 2u; k++)
			free(u[k].text);
	for (i = 0; i < DRAFT_LOADED_MAX; i++)
		free(dp[i].bytes);
	free(u);
	free(d);
	free(old);
	free(cand);
	return rc;
}

/*
 * Call the draft as it stands the saved state: Generate wrote it out, so nothing is
 * left to lose and the guards that ask "is there work to finish or undo" (stepping to
 * another file, rebuilding the database) must stop answering yes. Without this the
 * reader saved six files and Rebuild still said "Finish or undo the draft first".
 */
void draft_mark_saved(struct kof_editor *e)
{
	e->dr.saved_hash = draft_hash(e);
}

/*
 * Empty the panel and call that the baseline state.
 *
 * draft_clear on its own leaves the panel looking edited: saved_hash still
 * describes whatever was in it, so an empty draft reads as work in progress and
 * the guards that ask "is there something to lose" all answer yes.
 *
 * This is what the New button does.
 */
void draft_reset(struct kof_editor *e)
{
	draft_clear(e);
	e->dr.saved_hash = draft_hash(e);
	e->dr.sel_decl = 0;
	e->dr.cur_grp = e->dr.cur_cnd = 0;
	e->dr.warn[0] = 0;
	say_note(e, "Panel cleared");
}








































/* Throw the draft away. Called before loading another signature into it, and
 * only once whoever owns the unsaved work has said so. */
void draft_clear(struct kof_editor *e)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_decl; i++)
		free(e->dr.decl[i].bytes);
	memset(e->dr.decl, 0, sizeof e->dr.decl);
	memset(e->dr.grp, 0, sizeof e->dr.grp);
	memset(e->dr.cnd, 0, sizeof e->dr.cnd);
	/* The links went with the units that carried them, and the loaded list belongs to the draft being thrown away. */
	memset(e->dr.loaded, 0, sizeof e->dr.loaded);
	e->dr.n_loaded = 0;
	memset(e->dr.opt_on, 0, sizeof e->dr.opt_on);
	memset(e->dr.opt_val, 0, sizeof e->dr.opt_val);
	memset(e->dr.opt_auto, 0, sizeof e->dr.opt_auto);
	e->dr.n_decl = e->dr.n_grp = e->dr.n_cnd = 0;
	/*
	 * THE TICKS GO WITH THE MATCHERS THAT USED THEM.
	 *
	 * The blocks themselves stay: they are what the ENGINE carved out of
	 * the object on screen, and the object has not changed. What a cleared
	 * draft loses is the choosing - and leaving the ticks behind left a
	 * blank panel reporting that a block it no longer uses has no matcher.
	 */
	for (i = 0; i < e->dr.n_blk && e->dr.blk; i++)
		e->dr.blk[i].picked = 0;
	e->dr.n_rng_add = 0;
	e->dr.cur_grp = e->dr.cur_cnd = e->dr.sel_decl = 0;
	e->dr.family[0] = 0;
	e->dr.variant[0] = 0;
	/* The note belongs to the signature, not to the session. Left behind,
	 * it followed the researcher from one rule into the next and got
	 * written into that one's file on the next save. */
	e->dr.note[0] = 0;
}





















