/*
 * kv_view_mutation.inc - MUTATION MODE (the block table, the scoring pass, the signature generator model `ed`) and the file the session shows (`path`, `map`).
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P2. Main users (Inference, by unit names): kv_mutation.c and the draft panel (kv_decl.c).
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_decl.c, kv_main.c, kv_collect.c, kv_mutation.c, kv_actions.c.
 * Source lines of the old kv_view.h: 24-83.
 */
	/*
	 * MUTATION MODE: the same pane, asking a different question.
	 *
	 * It replaces the draft panel rather than sitting beside it because the
	 * two are alternatives - a signature is written out of patterns or out
	 * of blocks, and a screen offering both at once would be offering a
	 * choice nobody makes halfway.
	 */
	/*
	 * A POINTER, so ticked blocks can outlive opening the next file.
	 *
	 * Everything else about a view is about the file in front of it and is
	 * cleared when another is opened. These are not: a block ticked on one
	 * sample is the QUESTION being asked of the next one, and clearing it
	 * left the score column with nothing to measure. Held the way ext and
	 * probe are - allocated once in main, carried across the clear.
	 */

	uint32_t         n_plg;
	uint32_t         mtn_sel;          /* the row the keyboard is on */
	/*
	 * What the last scoring pass was about, so a frame that changed
	 * neither does not redo it.
	 *
	 * Scoring walks the object, which is the one thing in this panel that
	 * is not free - and the answer only moves when the blocks change or
	 * the reader moves to another object. Both are captured here.
	 */
	uint32_t         mtn_scored_obj;
	uint32_t         mtn_scored_n;
	int              mtn_scored;
	/* The blocks came from the object's own cached carve, so their scores
	 * are certainties and not measurements - see mtn_segment. */
	int              mtn_scores_known;
	/*
	 * FOLDED TABLES.
	 *
	 * The block table is as long as the object has areas - sixty-four rows
	 * on a large one - and a reader working on the matchers below it should
	 * not have to scroll past all of them to get there. Folding is per
	 * table and per session, not per object: it is a property of what the
	 * reader is doing, and a fold that reopened itself whenever the sample
	 * changed would be a fold that never holds.
	 *
	 * The heading and the column row stay in both states; the column row is
	 * what carries the control, and a table whose handle vanished when it
	 * was folded could not be opened again.
	 */
	int              blk_fold;
	/* Which object the table was carved from, so moving to another one
	 * carves that one instead of showing the last one's blocks. */
	uint32_t         mtn_seg_obj;
	int              mtn_segged;

	/* The signature generator's model - see kofeditor.h. */
	struct kof_editor ed;
	const char *path;
	void       *map;
	uint64_t    map_len;
