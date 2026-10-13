#define _GNU_SOURCE
#include "kv.h"







/*
 * Turn one signature source into a draft.
 *
 * Line oriented, and deliberately narrow: it reads the shapes ksigbuilder
 * accepts and nothing else. A construct it does not recognise is skipped rather
 * than approximated, because a draft that quietly differs from the file it came
 * from is worse than one that is visibly short of it.
 */


/* The text between the first pair of quotes, unescaped only as far as
 * ksigbuilder unescapes it - which is not at all. */
/*
 * The inside of a C string literal, back to the bytes it stands for.
 *
 * The three escapes decl_put_literal writes - \" \\ \? - and no others, which is
 * the same set ksigbuilder accepts. An escaped quote in particular has to be
 * understood here or it ends the literal: reading realm=\"X\" quote to quote
 * yields realm= and drops the rest of the marker silently.
 *
 * Anything else after a backslash is passed through as written rather than
 * refused. This is a viewer: a file it cannot fully account for should be shown
 * as nearly as it can be, and the build is where a bad escape is an error.
 */



/*
 * Throw the draft away, and put the PANEL'S SCROLL back with it.
 *
 * The model half is the editor's - see draft_clear there. The three offsets are
 * this file's, because they are where a pane happens to be scrolled to and
 * nothing in the model knows a pane exists.
 */
void draft_wipe(struct view *v)
{
	draft_clear(&v->ed);
	v->note_off = 0;
	v->prow_off = 0;
	v->prow_seen = 0;
	v->prow_home = 1;
}




/*
 * LOAD A MUTATION RULE INTO THE PANEL, the way a pattern rule is loaded.
 *
 * Its blocks become the table's, marked as carried - they were cut from
 * ANOTHER sample, which is exactly what makes the score column mean something -
 * and ticked, so the condition rows show the rule's own thresholds and joins.
 * The carve then runs as usual and adds whatever else this object has, minus
 * anything the rule already holds; a block the rule declares and the carve
 * reproduces is one block, and mtn_mark refuses the second row.
 *
 * Zero when the file holds no blocks, which is how the caller tells a mutation
 * rule from a pattern one without knowing where either lives.
 */
static int mtn_load_rule(struct view *v, const char *path)
{
	static struct kof_mutation_decl d[MTN_MAX_BLOCK];
	/* Which condition each block matcher belongs to, by matcher index -
	 * see kof_mutation_decl.cnd. */
	uint8_t blk_cnd[MAX_GROUP] = { 0 };
	struct kof_verdict_decl verdict;
	static uint32_t pool[MTN_MAX_BLOCK * KOF_MUTATION_MAX_HASH];
	const struct object *o = cur_obj(v);
	uint32_t n = 0, i, j;

	if (!mutation_from_source(&v->ed, path, d, MTN_MAX_BLOCK, &n, pool,
				(uint32_t)(sizeof pool / sizeof pool[0]),
				&verdict))
		return 0;

	v->ed.dr.n_blk = 0;
	for (i = 0; i < n && v->ed.dr.n_blk < MTN_MAX_BLOCK; i++) {
		struct mtn_block *b = &v->ed.dr.blk[v->ed.dr.n_blk];
		const char *rn = d[i].region;

		memset(b, 0, sizeof *b);
		b->id     = d[i].id;
		b->norm   = (uint8_t)d[i].norm;
		/* And which half it was cut from, or a library block opened
		 * from a file would come back as an author-code one and be
		 * written out under the wrong macro - see enum kgenome_mutation_side. */
		b->side   = d[i].side;
		b->kept   = 1;
		b->picked = 1;
		b->colour = (uint8_t)(v->ed.dr.n_blk % MTN_COLOURS);
		b->n_hash = d[i].n_hash > KOF_MUTATION_MAX_HASH
			  ? KOF_MUTATION_MAX_HASH : d[i].n_hash;
		for (j = 0; j < b->n_hash; j++)
			b->hash[j] = d[i].hash[j];
		snprintf(b->rgn_enum, sizeof b->rgn_enum, "%s",
			 rn && rn[0] ? rn : "KOF_SCAN_ALL");
		snprintf(b->rgn, sizeof b->rgn, "%s",
			 kof_region_label(b->rgn_enum));
		/*
		 * `anywhere` IS THE AUTHOR'S CHOICE AND NOTHING ELSE.
		 *
		 * It was being set whenever the region failed to resolve, which
		 * conflated two different things: where the block is LOOKED FOR
		 * on this object, which depends on the object, and what the
		 * rule SAYS, which depends on nobody but whoever wrote it. The
		 * first falls back to the whole file - see mtn_mask_of_enum -
		 * and the second is only ever changed by clicking the region
		 * cell.
		 */
		b->mask = mtn_mask_of_enum(o, b->rgn_enum);
		b->anywhere = !strcmp(b->rgn_enum, "KOF_SCAN_ALL");
		/*
		 * AND THE MATCHER THAT NAMES IT, because that is where the
		 * percentage lives and what a condition combines.
		 *
		 * One block to a matcher - see struct group.kind - so a rule
		 * that named three blocks comes back as three matchers, which
		 * is the shape it was written in.
		 */
		if (v->ed.dr.n_grp < MAX_GROUP) {
			struct group *g = &v->ed.dr.grp[v->ed.dr.n_grp];

			memset(g, 0, sizeof *g);
			g->kind = (uint8_t)GRP_KIND_SIM;
			g->pct  = d[i].thr;
			blk_cnd[v->ed.dr.n_grp] = d[i].cnd;
			v->ed.dr.n_grp++;
			grp_sim_add(&v->ed, v->ed.dr.n_grp - 1u, SIM_IT_BLOCK,
				    v->ed.dr.n_blk);
			/* grp_sim_add sets the threshold from the measure when
			 * the matcher is empty; the file's own number is what
			 * this one has to keep. */
			g->pct  = d[i].thr;
		}
		v->ed.dr.n_blk++;
	}
	/*
	 * AND THE CONDITION THAT NAMES THEM, because a matcher nobody concludes
	 * anything from is an unfinished draft.
	 *
	 * The rule that was read said "all of these blocks" or "any of them";
	 * which it was is in the joins mutation_from_source recovered. One
	 * condition over every block matcher, with the op the file used - the
	 * same shape the condition editor would have produced by hand.
	 */
	if (v->ed.dr.n_grp) {
		struct cond *c;
		uint32_t g;
		/*
		 * A CONDITION THE STRING HALF ALREADY MADE IS THE CONDITION
		 * THESE MATCHERS JOIN.
		 *
		 * A file can hold both - see the loader that calls this - and
		 * the string reader runs first, so by here there may already be
		 * a condition carrying the rule's verdict and its markers. It
		 * used to be skipped entirely: the block matchers were built
		 * and nothing concluded anything from them, so a mixed rule
		 * opened with "Matchers: None" under its condition.
		 *
		 * ONLY WHEN THERE IS ONE CONDITION TO JOIN INTO. The two readers
		 * parse independently - mutation_from_source recovers a block's
		 * join but not which condition used it - so with several
		 * conditions there is no way here to say which one a block
		 * belongs to, and stapling every block onto the first would be a
		 * guess dressed as a fact. The proper fix is one reader over the
		 * whole kof_scan; until then a multi-condition mixed rule opens
		 * with its blocks unwired, which the panel shows rather than
		 * hides. No rule this editor generates is of that shape - it
		 * emits one condition - so this changes nothing a viewer round
		 * trips today.
		 */
		int fresh = !v->ed.dr.n_cnd;

		/*
		 * SEVERAL CONDITIONS ARE NO LONGER A REASON TO GIVE UP.
		 *
		 * This used to bail out here, so a rule written as
		 *
		 *     if (kof_mutation_score(blk) >= 40u) ...
		 *     if (kof_find_str_all(rng, s0, s1)) ...
		 *
		 * came back with the block matcher built and wired into
		 * nothing: the panel showed one matcher under a rule that
		 * plainly had two. mutation_from_source now records which `if`
		 * asked about each block - see kof_mutation_decl.cnd - so each
		 * matcher goes into the branch that used it.
		 */
		if (fresh) {
			cnd_add(&v->ed, 0);
			/* or when any block alone concludes it, and when they
			 * were ANDed in the file. Only on a condition this
			 * made: an existing one carries the author's own
			 * operator and it is not this function's to change. */
			for (g = 1; g < n; g++)
				if (!d[g].join)
					v->ed.dr.cnd[v->ed.dr.n_cnd - 1u].op = 1;
		}
		for (g = 0; g < v->ed.dr.n_grp; g++) {
			size_t l;
			uint32_t ci = blk_cnd[g];

			if (v->ed.dr.grp[g].kind != GRP_KIND_SIM ||
			    !grp_sim_has(&v->ed, g, SIM_IT_BLOCK,
					 v->ed.dr.grp[g].sim[0].blk))
				continue;
			/* The branch the file put it in, or the only one there
			 * is when the reader could not say. */
			if (ci >= v->ed.dr.n_cnd)
				ci = 0;
			c = &v->ed.dr.cnd[ci];
			if (cnd_uses(c, g))
				continue;
			/* The spelling the panel uses when it puts a matcher
			 * into a condition - see CH_CMATCH. */
			l = strlen(c->expr);
			snprintf(c->expr + l, sizeof c->expr - l, "%s%u",
				 l ? (c->op ? "|" : "&") : "", g + 1u);
		}
		/* And what it concludes, as the file said it - not as this
		 * function would have guessed. An existing condition was read
		 * from the same file and already has it, and only the one this
		 * function created needs telling. */
		if (fresh && v->ed.dr.n_cnd) {
			struct cond *c0 = &v->ed.dr.cnd[0];

			c0->level = verdict.level;
			c0->var_kind = verdict.kind;
			snprintf(c0->variant, sizeof c0->variant, "%s",
				 verdict.text);
		}
	}
	/*
	 * AND THE SHAPE MATCHER, in its own condition.
	 *
	 * Its own because it concludes its own thing - see the note on
	 * shp_level in kofeditor.h - and because that is the shape the panel
	 * wrote the file in. Read back into the same two rows it was written
	 * from, so opening a generated rule and saving it again changes
	 * nothing.
	 */
	/* The rule is in hand; the carve has not run against it yet. */
	v->mtn_segged = 0;
	v->mtn_scored = 0;
	v->prow_off = 0;
	return v->ed.dr.n_blk != 0;
}

/*
 * Show a signature that fired on this object, in place of whatever is in the
 * panel.
 *
 * Refuses while there is unsaved work and says so instead; the caller asks
 * again once that has been settled. Losing an hour of drafting to a click on a
 * list is the kind of thing a tool only has to do once.
 */
void draft_show(struct view *v, uint32_t idx)
{
	struct object *ob = cur_obj(v);

	if (idx >= ob->n_touch)
		return;
	draft_wipe(v);
	v->sel_touch = idx;
	/*
	 * FOLDED IS THE DEFAULT, for every draft and not only for a loaded
	 * rule that named no block.
	 *
	 * The table is as long as the object has areas - sixty rows on a large
	 * binary - and a reader opening a draft is almost never there to read
	 * all of them. Folded it is one line saying how many there are and how
	 * many are ticked, with the handle in reach; a ticked block stays
	 * visible either way, which is what blk_row_shown already does.
	 */
	v->blk_fold = 1;

	/*
	 * The source first, and the database only when there is no source.
	 *
	 * The database holds the strings and the names; the logic is compiled
	 * code and is not in it. A rule shown from the database alone has every
	 * marker in one find_all and one branch under it, which is a shape the
	 * module may never have had - so it is the fallback, and it says so.
	 */
	{
		const char *path = src_of(&v->ed, &ob->touch[idx]);
		int rc, blocks;

		/*
		 * BOTH HALVES OF THE FILE, because one file can hold both.
		 *
		 * Markers and blocks are two things a rule is written from, not
		 * two kinds of rule - a signature may search for a string AND
		 * score a block, and the panel has a row for each. The mutation
		 * reader used to be asked FIRST and its answer taken as final,
		 * so a rule that had both opened as its blocks alone and Save
		 * wrote that back over the strings.
		 *
		 * Neither reader minds a file that holds nothing for it: each
		 * answers zero and the other still has its half. The draft came
		 * from the file when EITHER found something.
		 */
		rc = path ? draft_from_source(&v->ed, path) : 0;
		blocks = path ? mtn_load_rule(v, path) : 0;

		v->prow_home = 1;       /* a loaded draft opens at its top */

		if (rc || blocks) {
			/*
			 * A draft that came from a file belongs to that file:
			 * generating writes it back rather than starting a
			 * numbered copy beside it. Opening a signature in order
			 * to change it is a deliberate act, which is the thing
			 * the do-not-overwrite rule exists to tell apart from
			 * a name that happened to collide.
			 */
			snprintf(v->ed.dr.gen_path, sizeof v->ed.dr.gen_path, "%.*s",
				 (int)sizeof v->ed.dr.gen_path - 1, path);
			v->ed.dr.gen_ok = 1;
			v->ed.dr.from_rule = 1;
			/* WHAT WAS READ IS WHAT IS SAVED. Left out on the
			 * block path, the draft was dirty the moment a block
			 * rule opened - nothing typed, and everything guarded
			 * by "finish the draft first" refused. */
			v->ed.dr.saved_hash = draft_hash(&v->ed);
			/* The path shows on its own; `warn` is for things that
			 * are wrong, and a loaded file is not one. */
			v->ed.dr.warn[0] = 0;
			if (rc < 0)
				say_note(&v->ed, "Partly read - check it against the file");
			return;
		}
		draft_from_touch(&v->ed, &ob->touch[idx]);
		v->prow_home = 1;       /* a loaded draft opens at its top */
		v->ed.dr.from_rule = 1;
	}
}




/*
 * Whether Save, Save As and Generate would do anything - asked in one place.
 *
 * generate() already decides this for itself, because a key runs it as well as
 * a button, and the buttons used to decide it a second time for their colour.
 * The two disagreed on exactly the case that matters: a signature opened out of
 * the Skip list and not yet touched drew Save GREEN and Save As grey, so the
 * one lit control on the screen was the one that overwrites somebody else's
 * file - and pressing it did nothing but set a message, because generate()
 * refused it. Both now read the same answer from here.
 */

int save_ok(struct view *v)
{
	int near_miss = 0;

	/* Nowhere to write is not a draft problem, and it is asked first:
	 * every other reason below describes the draft. */
	if (!v->ed.basedir || !v->ed.basedir[0])
		return 0;
	if (draft_missing_of(&v->ed, 0))
		return 0;
	/*
	 * WHETHER ANYTHING CHANGED IS NOT A REASON TO REFUSE.
	 *
	 * This used to answer draft_dirty for a draft that already has a file,
	 * and the result was a Save button that was grey when it should not
	 * have been. draft_dirty is a HASH of what the editor thinks the draft
	 * is, and a hash that does not cover every editable field says "nothing
	 * changed" after a change - which is exactly what was seen: edit a
	 * value inside a matcher and Save goes grey, switch which signature is
	 * being viewed and it comes back.
	 *
	 * A hash that has to enumerate every field to stay correct is a thing
	 * that will drift again the next time a field is added, and the cost of
	 * being wrong is the reader losing work. Writing a file that happens to
	 * be identical costs a write. So the change test is gone and only the
	 * VALIDITY tests remain - a missing family name, a string no matcher
	 * uses, a matcher no condition uses, a bad region. Those describe a
	 * draft that cannot be written correctly, which is a real refusal.
	 */
	if (v->ed.dr.gen_path[0])
		return 1;
	return !(draft_dup(&v->ed, &near_miss) && !near_miss);
}

int save_as_ok(struct view *v)
{
	int near_miss = 0;

	if (!v->ed.basedir || !v->ed.basedir[0])
		return 0;
	/* No change test here either - see save_ok. Save As still needs a file
	 * to be a copy OF, and still refuses a copy that would duplicate
	 * something the tree already holds. */
	if (draft_missing_of(&v->ed, 1) || !v->ed.dr.gen_path[0])
		return 0;
	return !(draft_dup(&v->ed, &near_miss) && !near_miss);
}
