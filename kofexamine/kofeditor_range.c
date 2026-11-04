#define _GNU_SOURCE

/*
 * kofeditor_range.c - ranges of a draft: which regions a range holds, the names of a range, and the verbs that add, retarget, delete and apply one.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


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
 * Bring every marker's range back in step with the matchers that search it.
 *
 * Derived state, so it is recomputed from what the draft currently holds
 * rather than updated at each of the half dozen places that can change a
 * matcher's range or take a matcher away. Run from the draw, which is the one
 * point every one of those passes through, and cheap enough to: a draft holds
 * as many markers as the author declared and a handful of matchers, and the search below is
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
