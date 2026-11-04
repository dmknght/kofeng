#define _GNU_SOURCE

/*
 * kofeditor_group.c - groups (block matchers) of a draft: their mask, count, seeding, similarity entries, labels and which tab they belong to.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


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
		kofeditor_cnd_rewrite(&e->dr.cnd[k], gl, 0, KOFEDITOR_CND_DROP);
		kofeditor_cnd_rewrite(&e->dr.cnd[k], gl, 0, KOFEDITOR_CND_SHIFT);
	}
	memmove(&e->dr.grp[g], &e->dr.grp[g + 1u],
		(e->dr.n_grp - g - 1u) * sizeof e->dr.grp[0]);
	e->dr.n_grp--;
	if (e->dr.cur_grp >= e->dr.n_grp && e->dr.n_grp)
		e->dr.cur_grp = e->dr.n_grp - 1u;
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
