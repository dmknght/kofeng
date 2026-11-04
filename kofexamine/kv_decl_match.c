#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The draft panel's matcher rows: a search matcher's list row and a block matcher's one-block row. */

/* Defined below; a row registers its own callback before the callback is written. */
static void hit_row_addmatcher(struct view *v, uint32_t arg);
static int draw_block_matcher(struct out *o, struct view *v, uint32_t g, int r);
static int draw_str_matcher(struct out *o, struct view *v, uint32_t g, int r);


/* [+ Matcher] - a new matcher, whose rule is chosen before it has anything. */
static void hit_row_addmatcher(struct view *v, uint32_t arg)
{
	(void)arg;
	if (g_mx >= v->n_c0 && g_mx <= v->n_c1)
		ch_open(v, CH_RULE, MAX_GROUP, g_my, g_mx);
}

void hit_row_matcher(struct view *v, uint32_t g)
{
	v->ed.dr.cur_grp = g;
	v->ed.dr.warn[0] = 0;
	if (v->ed.dr.grp[g].kind == GRP_KIND_SIM) {
		/*
		 * A BLOCK MATCHER'S ROW has the threshold and the comment and
		 * nothing else to press: no kind to turn it into, no [x] - the
		 * block's tick made it and the tick takes it away. The
		 * threshold registered its own span as it was drawn, so it is
		 * answered there and not here.
		 */
		if (v->grp_nt[g][0] > 0 && g_mx >= v->grp_nt[g][0] &&
		    g_mx <= v->grp_nt[g][1])
			v->edit = 300 + (int)g;
	} else if (g_mx >= g_cols - 4)
		grp_remove(&v->ed, g);
	else if (g_mx >= v->grp_rl[g][0] &&
		 g_mx <= v->grp_rl[g][1])
		ch_open(v, CH_RULE, g, g_my, g_mx);
	else if (v->grp_sg[g][0] >= 0 && g_mx >= v->grp_sg[g][0] &&
		 g_mx <= v->grp_sg[g][1]) {
		/*
		 * THE OTHER WAY, AND THE NUMBER IS NOW THE AUTHOR'S.
		 *
		 * Flipping the sign names a different byte, so whatever the
		 * engine had located is no longer what this holds - see
		 * group.at_auto, which is what stops a later anchor change
		 * from converting a step somebody chose.
		 */
		struct group *q = &v->ed.dr.grp[g];

		q->at_off = -q->at_off;
		q->at_auto = 0;
		grp_at_fix_sign(q);
	} else if (v->grp_of[g][0] >= 0 && g_mx >= v->grp_of[g][0] &&
		   g_mx <= v->grp_of[g][1]) {
		at_off_edit_open(v, g);
	} else if (g_mx >= v->grp_rg[g][0] &&
		 g_mx <= v->grp_rg[g][1])
		/* The same half of the row, asking the
		 * question that half asks for this
		 * rule: which region, or which of the
		 * marker's occurrences. */
		ch_open(v,
			grp_is_at(v->ed.dr.grp[g].rule)
			? CH_ATOFF : CH_RANGE,
			g, g_my, g_mx);
	else if (v->grp_th[g][0] > 0 &&
		 g_mx >= v->grp_th[g][0] &&
		 g_mx <= v->grp_th[g][1])
		ch_open(v, CH_THRESH, g, g_my, g_mx);
	else if (v->grp_nt[g][0] > 0 &&
		 g_mx >= v->grp_nt[g][0] &&
		 g_mx <= v->grp_nt[g][1])
		v->edit = 300 + (int)g;
	
}

/*
 * A BLOCK MATCHER IS TWO ROWS: the block's function's name and hash, and the
 * threshold it must reach, with the comment box every matcher has; and the
 * unit's Type and Tag on a row of their own under it.
 *
 * The hash is bare, what a person compares against the block table; the name is
 * the block's own `sym`, the field the blocks table prints (the engine's
 * kof_func_name). The matcher holds nothing else - ticking
 * the block made it and unticking drops it, so there is no [x], no kind and no
 * list of items to add to. An older rule's matcher may name several blocks; the
 * first is shown and "+N" says how many more.
 */
static int draw_block_matcher(struct out *o, struct view *v, uint32_t g, int r)
{
	const struct group *q = &v->ed.dr.grp[g];
	uint32_t blk = q->n_sim ? q->sim[0].blk : v->ed.dr.n_blk;
	int y, c0;

	grp_spans_off(v, g);
	if (!PR_VIS(r))
		goto unit_row;
	y = PR(r);
	/* No word: find_sim is the only kind of the Blocks tab. Name first, then the hash. */
	ghead_lead(o, v, y, g, "");
	if (blk < v->ed.dr.n_blk && v->ed.dr.blk[blk].sym[0])
		out_fmt(o, A_DIM "%.*s: " A_OFF, (int)MTN_SYM_COL,
			v->ed.dr.blk[blk].sym);
	out_fmt(o, "%s%08x" A_OFF, A_ID,
		blk < v->ed.dr.n_blk ? v->ed.dr.blk[blk].id : 0u);
	if (q->n_sim > 1u)
		out_fmt(o, A_DIM " +%u" A_OFF, q->n_sim - 1u);
	out_str(o, A_DIM "   Threshold: " A_OFF);
	v->grp_th[g][0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s>= [", v->edit == ED_GRP_PCT + (int)g ? A_SEL : A_ID);
	c0 = (int)o->col_hint - 1;
	if (v->edit == ED_GRP_PCT + (int)g)
		field_draw(o, v->grp_pct_buf, v->caret, &v->grp_pct_off, 3, 1,
			   "");
	else
		out_fmt(o, "%3u", q->pct);
	out_str(o, "]" A_OFF A_DIM "%" A_OFF);
	v->grp_th[g][1] = (int)o->col_hint;
	draw_grp_note(o, v, g);
	/* After the row, so it wins where they overlap - see hit_at. */
	hit_add(v, y, c0, v->grp_th[g][1],   /* not past the comment box */
		hit_grp_pct, g);
unit_row:
	/* A block matcher IS a diagnose unit (the Blocks tab has no conditions): its own Type and Tag, under the row. */
	r++;
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		/* Not hit_row_matcher: its comment-box span is a column range of the first row. */
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
		out_fmt(o, "%7s", "");
		unit_cells(o, v, PR(r), 1, g);
	}
	return r + 1;
}

/*
 * A SEARCH MATCHER: two rows - what it IS, with its range and threshold, and
 * what it is about, the markers it searches for.
 */
static int draw_str_matcher(struct out *o, struct view *v, uint32_t g, int r)
{
	const struct group *q = &v->ed.dr.grp[g];
	char rl[16];
	uint32_t i;

	/* One name for the three searches - see where the kind menu is built.
	 * What is GENERATED still follows the threshold. */
	snprintf(rl, sizeof rl, "%s",
		 !grp_is_at(q->rule) ? "find_str" : grp_rule_label(q->rule));
	grp_spans_off(v, g);
	if (PR_VIS(r)) {
		char nm[40], lead[16];

		row_start(o, PR(r), 1);
		/*
		 * AN AT MATCHER SHOWS WHERE, NOT WHICH REGION.
		 *
		 * It names no range - see group.at_off - so the field that
		 * would hold one holds the offset instead, and the preposition
		 * changes with it. The control keeps the same click span,
		 * because it is the same half of the row: the thing that says
		 * where this matcher looks.
		 */
		if (grp_is_at(q->rule))
			nm[0] = 0;      /* drawn in parts, below */
		else if (grp_has_range(&v->ed, g))
			rng_name_of(cur_obj(v)->fmt, grp_mask(&v->ed, g), nm,
				    sizeof nm);
		else
			snprintf(nm, sizeof nm, "-");
		/*
		 * Named fields, not a table: a field that does not apply is
		 * simply absent.
		 */
		snprintf(lead, sizeof lead, "  %u.", grp_loc(&v->ed, g));
		out_fmt(o, "%s%-6.6s" A_OFF,
			g == v->ed.dr.cur_grp ? A_SEL : A_DIM, lead);
		v->grp_rl[g][0] = 1 + (int)o->col_hint;
		out_fmt(o, "%s%s" A_OFF, A_WARN, rl);
		v->grp_rl[g][1] = (int)o->col_hint;
		out_str(o, grp_is_at(q->rule) ? A_DIM " at " A_OFF
					      : A_DIM " in " A_OFF);
		if (grp_is_at(q->rule)) {
			/*
			 * THE THREE PARTS, EACH ITS OWN CONTROL - see
			 * view.grp_sg. Spelled with the same helpers
			 * everywhere, so the row and the preview cannot
			 * disagree.
			 */
			char mag[24];
			int freesign = grp_at_sign_free(q->at_anchor);

			v->grp_rg[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, A_LOC,
				kof_anchor_word(q->at_anchor));
			v->grp_rg[g][1] = (int)o->col_hint;
			out_str(o, " ");
			v->grp_sg[g][0] = 1 + (int)o->col_hint;
			/* Dim where it cannot be pressed, which is what the
			 * attribute cell says with the same colour: this is
			 * fixed, not chosen. */
			out_fmt(o, "%s%c" A_OFF, freesign ? A_ID : A_DIM,
				grp_at_sign(q->at_off));
			v->grp_sg[g][1] = (int)o->col_hint;
			if (!freesign)
				v->grp_sg[g][0] = v->grp_sg[g][1] = -1;
			out_str(o, " ");
			v->grp_of[g][0] = 1 + (int)o->col_hint;
			if (v->edit == ED_AT_OFF + (int)g) {
				/*
				 * AS WIDE AS WHAT IS IN IT, and one cell more
				 * to type into: the step is four or five
				 * characters in almost every rule.
				 */
				int room = (int)strlen(v->at_buf) + 1;

				if (room < 5)
					room = 5;
				out_str(o, A_SEL);
				field_draw(o, v->at_buf, v->caret,
					   &v->at_buf_off, room, 1, "0x...");
				out_str(o, A_OFF);
			} else {
				snprintf(mag, sizeof mag, "0x%llx",
					 grp_at_mag(q->at_off));
				out_fmt(o, "%s%s" A_OFF, A_LOC, mag);
			}
			v->grp_of[g][1] = (int)o->col_hint;
		} else {
			v->grp_rg[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, A_LOC, nm);
			v->grp_rg[g][1] = (int)o->col_hint;
		}
		/*
		 * TWO THINGS, AND ONLY ONE OF THEM IS A CONTROL.
		 *
		 * ">= N" is the threshold: it is what the author sets, and
		 * clicking it opens the menu of values. "of N" is how many
		 * markers the matcher currently holds - a fact about the
		 * matcher, changed by adding or removing a marker and by
		 * nothing else, so the clickable span ends where the control
		 * does.
		 *
		 * "==" at the top and ">=" below it, which is the difference
		 * the author is choosing between: a floor a bigger set can
		 * clear, or all of them however many there are.
		 */
		if (!grp_is_at(q->rule)) {
			uint32_t n = grp_count(&v->ed, g);
			uint32_t th = grp_thresh_eff(&v->ed, g);

			out_str(o, A_DIM "   Threshold: " A_OFF);
			v->grp_th[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s %u" A_OFF, A_ID,
				(n && th >= n) ? "==" : ">=", th);
			v->grp_th[g][1] = (int)o->col_hint;
			out_fmt(o, A_DIM " of " A_OFF "%s%u" A_OFF, A_SIZE, n);
		}
		draw_grp_note(o, v, g);
		out_at(o, PR(r), g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_matcher, g);
	}
	r++;

	/* The markers are the matcher's own row, because they are what it
	 * searches for and not a separate thing that happens to be nearby. */
	if (!PR_VIS(r)) {
		glist_gone(v, g);
		return r + 1;
	}
	{
		struct grp_list L;

		glist_begin(&L, o, v, PR(r), g, "Markers", v->grp_it[g],
			    v->grp_it[g] ? v->cap_str_col : 0u);
		for (i = 0; i < v->ed.dr.n_decl; i++) {
			/* Ten digits and a terminator: what %u can actually
			 * produce, so a large index is not labelled short. */
			char num[11];

			if (!(v->ed.dr.decl[i].grp & (1u << g)))
				continue;
			snprintf(num, sizeof num, "%u", i + 1u);
			glist_item(&L, num);
		}
		glist_end(&L, decl_free(&v->ed) != 0, "String");
	}
	return r + 1;
}

/*
 * draw_decl_matchers - the matchers of the open tab, one call each.
 *
 * One section of the draft panel. `r` is the panel's running row number and it
 * is passed in and handed back rather than shared.
 *
 * THE LIST IS ONE AND EACH TAB NUMBERS ITS OWN KIND OF IT FROM 1 (grp_loc), so
 * the Blocks tab opens at 1 whatever Patterns holds, and a tab switch renumbers
 * nothing. Patterns lists find_str and find_at, which its conditions name;
 * Blocks lists the find_sim that ticking a block made, and each IS a unit.
 */
int draw_decl_matchers(struct out *o, struct view *v, int r)
{
	uint32_t g;

	/* A matcher's marker list records one span per marker it names; the columns are sized to the strings table (a refusal is said by the call). */
	(void)decl_cols_reserve(v, v->ed.dr.n_decl);
	if (PR_VIS(r)) {
		sec_bar(o, v, PR(r), " Matchers");
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
	}
	r++;

	v->row_grp = PR(r);
	for (g = 0; g < v->ed.dr.n_grp; g++) {
		if (grp_tab(&v->ed, g) != v->ed.dr.tab)
			grp_spans_off(v, g);
		else if (v->ed.dr.grp[g].kind == GRP_KIND_SIM)
			r = draw_block_matcher(o, v, g, r);
		else
			r = draw_str_matcher(o, v, g, r);
	}

	/*
	 * AND THE BUTTON THAT ADDS ONE, AT THE FOOT OF THEM, on the Patterns
	 * tab only: a block matcher is made by ticking the block, so the Blocks
	 * tab has nothing to add by hand. At the foot it is beside the last
	 * thing added, which is where the reader is already looking.
	 */
	if (v->ed.dr.tab == DT_PATTERNS) {
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			v->n_c0 = 2;
			out_fmt(o, " " A_ID "[+ Matcher]" A_OFF);
			v->n_c1 = (int)o->col_hint;
			hit_add(v, PR(r), 0, g_cols - 1, hit_row_addmatcher, 0);
		}
		r++;
	}
	return r;
}
