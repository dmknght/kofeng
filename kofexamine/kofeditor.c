#define _GNU_SOURCE

/*
 * kofeditor.c - the draft as one thing: its hash, whether it is edited, refresh, reset and clear; and the three notes (obj_sha256, say_err, say_note).
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"



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
	if (e->dr.decl)
		memset(e->dr.decl, 0, (size_t)e->dr.n_decl * sizeof e->dr.decl[0]);
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
