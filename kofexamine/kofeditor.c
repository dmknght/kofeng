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
 * and conditions. Nothing here knows a pane is on screen, and nothing writes a
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/script.h>
/* KOF_PROC_OS_LIST: the platform a process record is from, which is its
 * subtype - see the note on that list. */
#include <kofmod/proc.h>
/* For the object facts below - see "what an object IS". */
#include <phenotype/emu_unpack.h>

#include "kofeditor.h"
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
			const char *q = p + 1;

			while (*q == ' ')
				q++;
			if (*q >= '0' && *q <= '9') {
				/* Set rather than toggled: a "!" that does not
				 * reach a number is dropped below, so "!!1" is
				 * one negation here and one in the emitter,
				 * which drops the same one. Two readings of the
				 * same text that disagreed would be a panel
				 * showing the opposite of the generated file. */
				n = 1;
				p = q;
				continue;
			}
			n = 0;
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
		if (n < 1ul || n > (unsigned long)grp_tab_count(e, c->tab))
			return n + 1ul;
	return 0;
}

int cnd_uses(const struct kof_editor *e, const struct cond *c, uint32_t g)
{
	return g < e->dr.n_grp && grp_tab(e, g) == c->tab &&
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
enum { CND_DROP = 0, CND_NEG, CND_SWAP };

static void cnd_rewrite(struct cond *c, uint32_t id, uint32_t to, int verb)
{
	char out[sizeof c->expr];
	size_t at = 0;
	const char *p = c->expr;
	unsigned long n;
	int neg, first = 1;

	out[0] = 0;
	while (cnd_next_id(&p, &n, &neg)) {
		int w;

		if (n == (unsigned long)id) {
			if (verb == CND_DROP)
				continue;
			if (verb == CND_NEG)
				neg = !neg;
			else
				n = (unsigned long)to;
		}
		if (at + 22u >= sizeof out)
			break;
		w = snprintf(out + at, sizeof out - at, "%s%s%lu",
			     first ? "" : (c->op ? "|" : "&"),
			     neg ? "!" : "", n);
		if (w < 0)
			break;
		at += (size_t)w;
		first = 0;
	}
	out[at] = 0;
	snprintf(c->expr, sizeof c->expr, "%s", out);
}

/* Take one matcher out of a condition's expression. A matcher that is not on
 * the condition's tab has no number in it, so nothing happens. */
void cnd_drop_matcher(const struct kof_editor *e, struct cond *c, uint32_t g)
{
	if (g < e->dr.n_grp && grp_tab(e, g) == c->tab)
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
	if (g < e->dr.n_grp && grp_tab(e, g) == c->tab)
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

	if (ci >= e->dr.n_cnd || g >= e->dr.n_grp || to >= e->dr.n_grp)
		return;
	c = &e->dr.cnd[ci];
	/* Both ends are on the condition's own tab, or nothing is done: the
	 * other tabs' matchers are not ones it can name. */
	if (grp_tab(e, g) != c->tab || grp_tab(e, to) != c->tab)
		return;
	cnd_rewrite(c, grp_loc(e, g), grp_loc(e, to), CND_SWAP);
	cnd_canon(e, ci, canon, sizeof canon);
	snprintf(c->expr, sizeof c->expr, "%s", canon);
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

/*
 * WHAT THE GATE SAID, IF IT HAS BEEN ASKED - AND IT IS NOT ASKED BY LOOKING.
 *
 * Nothing about the emulator runs until the reader chooses Unpack with
 * emulator. That is a rule about the tool and not an optimisation: the
 * interpreter is the one thing here that executes what it is shown, and it
 * runs when somebody asks for it and not because a row was selected.
 *
 * The GATE is not the emulator - it reads a byte histogram and decides whether
 * emulating would be worth it - but it is about the emulator, it costs a walk
 * of every executable segment, and it was running on touch: a spilled object
 * faulted in whole to fill one status-line tag nobody had asked for. So it is
 * asked where the choice is made - see emu_here - and this only reports what
 * that left behind.
 */
uint8_t obj_emu_why(const struct object *o)
{
	return (o && o->emu_why_done) ? o->emu_why : 0u;
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
			need |= e->dr.decl[i].mask;
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
 * What a condition is called on screen: "1." for the first one of its tab.
 *
 * Numbered by position among the conditions of its own tab, in creation order:
 * the conditions are independent blocks, one file each, and the other tabs'
 * are on another list.
 */
void cnd_label(struct kof_editor *e, uint32_t i, char *out, size_t cap)
{
	uint32_t k, pos = 0;

	for (k = 0; k < i; k++)
		pos += e->dr.cnd[k].tab == e->dr.cnd[i].tab;
	snprintf(out, cap, "%u.", pos + 1u);
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
	/* The numbers move within the matcher's own tab, and only the
	 * conditions of that tab name them. */
	for (k = 0; k < e->dr.n_cnd; k++) {
		struct cond *c = &e->dr.cnd[k];
		char out[sizeof c->expr];
		size_t at = 0;
		const char *p = c->expr;
		unsigned long n;
		int neg, first = 1;

		if (c->tab != gt)
			continue;
		out[0] = 0;
		while (cnd_next_id(&p, &n, &neg)) {
			int w;

			if (n == (unsigned long)gl)
				continue;
			if (n > (unsigned long)gl)
				n--;
			/* The id moves down; whether it was negated does not.
			 * See cnd_rewrite for why the room is checked. */
			if (at + 22u >= sizeof out)
				break;
			w = snprintf(out + at, sizeof out - at, "%s%s%lu",
				     first ? "" : (c->op ? "|" : "&"),
				     neg ? "!" : "", n);
			if (w < 0)
				break;
			at += (size_t)w;
			first = 0;
		}
		out[at] = 0;
		snprintf(c->expr, sizeof c->expr, "%s", out);
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
	c->tab = e->dr.tab;
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
	for (i = 0; e->dr.family[i]; i++)
		MIX((uint8_t)e->dr.family[i]);
	for (i = 0; e->dr.note[i]; i++)
		MIX((uint8_t)e->dr.note[i]);
	MIX(e->dr.maltype);
	for (i = 0; i < e->dr.n_rng_add; i++)
		MIX(e->dr.rng_add[i]);
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
		MIX(val);
		MIX(val >> 32);
	}
	for (i = 0; i < e->dr.n_decl; i++) {
		const struct decl *d = &e->dr.decl[i];

		MIX(d->len); MIX(d->hex); MIX(d->mask);
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
		MIX(e->dr.grp[i].rule); MIX(e->dr.grp[i].thresh); MIX(e->dr.grp[i].mask);
		MIX(e->dr.grp[i].tag); MIX(e->dr.grp[i].tag >> 32);
		for (j = 0; e->dr.grp[i].note[j]; j++)
			MIX((uint8_t)e->dr.grp[i].note[j]);
	}
	for (i = 0; i < e->dr.n_cnd; i++) {
		const struct cond *c = &e->dr.cnd[i];

		MIX(c->tag); MIX(c->tag >> 32); MIX(c->tab);
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
			b = kof_hash_step(b, (uint8_t)e->dr.blk[i].norm);
			b = kof_hash_step(b, (uint8_t)e->dr.blk[i].anywhere);
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
	uint32_t n = 0, i, g, k;

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
	uint32_t n = 0, g, k;

	for (g = 0; g < e->dr.n_grp && n < cap; g++) {
		uint32_t m;
		int dup = 0;

		if (!grp_has_range(e, g))
			continue;
		m = grp_mask(e, g);
		for (k = 0; k < n; k++)
			dup |= mask[k] == m;
		if (dup)
			continue;
		mask[n] = m;
		unused[n] = 0;
		n++;
	}
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
	struct decl *d = &e->dr.decl[i];
	size_t n = strlen(e->dr.sedit);
	uint8_t *nb;

	if (i >= e->dr.n_decl)
		return;
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
		memcpy(d->hexs, e->dr.sedit, n + 1u);
		/*
		 * Refused by the same compiler the build uses, and in its own
		 * words. A pattern the panel accepted and the build then threw
		 * out is a rule that looked right in the viewer and does not
		 * exist in the database.
		 */
		if (!decl_from_hexs(d)) {
			{
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
			}
			return;
		}
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
	if (!d->len) {
		say_note(e, "String %u would be empty - unchanged",
			 i + 1u);
		return;
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


const struct kof_tagent *tag_find(const struct kof_editor *e, uint64_t id)
{
	return e->tags && id ? kof_tagset_find(e->tags, KOF_TAGSRC_K_TAG, id)
			     : NULL;
}

const char *tag_name(const struct kof_editor *e, uint64_t id)
{
	const struct kof_tagent *t = tag_find(e, id);

	return t ? t->name : "";
}

/* How many tags carry this name. */
static uint32_t tag_same_name(const struct kof_tagset *s, const char *name)
{
	size_t i;
	uint32_t n = 0;

	for (i = 0; i < s->n; i++)
		n += !s->e[i].removed && s->e[i].kind == KOF_TAGSRC_K_TAG &&
		     !strcmp(s->e[i].name, name);
	return n;
}

void tag_label(const struct kof_editor *e, uint64_t id, char *out, size_t cap)
{
	const struct kof_tagent *t = tag_find(e, id);
	size_t n;

	if (!cap)
		return;
	out[0] = 0;
	if (!t)
		return;
	n = (size_t)snprintf(out, cap, "%s", t->name);
	if (tag_same_name(e->tags, t->name) < 2u || n + 1u >= cap)
		return;
	/* Another tag has this name: which one is told by what it is about. */
	n += (size_t)snprintf(out + n, cap - n, " (");
	if (t->has_fam && n + 1u < cap) {
		const char *f = kof_tagset_name(e->tags, KOF_TAGSRC_K_FAMILY,
						t->fam);

		n += (size_t)snprintf(out + n, cap - n, "family %s",
				      f ? f : "?");
	}
	if (t->n_typ && n + 1u < cap) {
		n += (size_t)snprintf(out + n, cap - n, "%stypes ",
				      t->has_fam ? ", " : "");
		if (n + 1u < cap)
			n += kof_tagset_join(e->tags, KOF_TAGSRC_K_TYPE, t->typ,
					     t->n_typ, out + n, cap - n);
	}
	if (n + 2u < cap)
		snprintf(out + n, cap - n, ")");
}

/* A block matcher no condition uses is a diagnose of its own. */
int grp_standalone(const struct kof_editor *e, uint32_t g)
{
	uint32_t ci;

	if (g >= e->dr.n_grp || e->dr.grp[g].kind != GRP_KIND_SIM)
		return 0;
	for (ci = 0; ci < e->dr.n_cnd; ci++)
		if (cnd_uses(e, &e->dr.cnd[ci], g))
			return 0;
	return 1;
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

/* `<first type>_<family>_<tag>` of tag `id`: what a running id is counted
 * within. Every word is the tag's own - the first type it declares, its
 * family, its name - and a part it has not got is left out, so no underscore
 * is doubled. No tag has `<tag>` where the name goes, so the gap shows. */
static void tag_prefix(const struct kof_editor *e, uint64_t id, char *out,
		       size_t cap)
{
	const struct kof_tagent *t = tag_find(e, id);
	const char *w;
	size_t n = 0;

	if (!t) {
		snprintf(out, cap, "<tag>");
		return;
	}
	if (t->n_typ && (w = kof_tagset_name(e->tags, KOF_TAGSRC_K_TYPE,
					     t->typ[0])) != NULL)
		n = name_word(out, cap, n, w);
	if (t->has_fam && (w = kof_tagset_name(e->tags, KOF_TAGSRC_K_FAMILY,
					       t->fam)) != NULL) {
		if (n && n + 1u < cap)
			out[n++] = '_';
		n = name_word(out, cap, n, w);
	}
	if (n && n + 1u < cap)
		out[n++] = '_';
	n = name_word(out, cap, n, t->name);
	out[n] = 0;
}

/* The prefix of the diagnose `i` of the output order: the conditions first,
 * then the standalone block matchers - see cnd_file_name. */
static uint32_t prefix_run(const struct kof_editor *e, const char *mine,
			   uint32_t n_cond, uint32_t n_grp)
{
	char other[160];
	uint32_t k, id = 1;

	for (k = 0; k < n_cond; k++) {
		tag_prefix(e, e->dr.cnd[k].tag, other, sizeof other);
		id += !strcmp(mine, other);
	}
	for (k = 0; k < n_grp; k++) {
		if (!grp_standalone(e, k))
			continue;
		tag_prefix(e, e->dr.grp[k].tag, other, sizeof other);
		id += !strcmp(mine, other);
	}
	return id;
}

void cnd_file_name(const struct kof_editor *e, uint32_t ci, char *out,
		   size_t cap)
{
	char mine[160];

	if (!out || !cap)
		return;
	out[0] = 0;
	if (ci >= e->dr.n_cnd)
		return;
	tag_prefix(e, e->dr.cnd[ci].tag, mine, sizeof mine);
	snprintf(out, cap, "%s_%02u.c", mine,
		 prefix_run(e, mine, ci, 0));
}

void grp_file_name(const struct kof_editor *e, uint32_t g, char *out,
		   size_t cap)
{
	char mine[160];

	if (!out || !cap)
		return;
	out[0] = 0;
	if (!grp_standalone(e, g))
		return;
	tag_prefix(e, e->dr.grp[g].tag, mine, sizeof mine);
	snprintf(out, cap, "%s_%02u.c", mine,
		 prefix_run(e, mine, e->dr.n_cnd, g));
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
	e->dr.maltype = 0;
	/* The note belongs to the signature, not to the session. Left behind,
	 * it followed the researcher from one rule into the next and got
	 * written into that one's file on the next save. */
	e->dr.note[0] = 0;
}





















