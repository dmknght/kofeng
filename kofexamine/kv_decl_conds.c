#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The draft panel's Conditions table. */


/*
 * draw_decl_conds - the Patterns tab's conditions (the Blocks tab has none), each one a block of its own.
 *
 * One section of the draft panel. A condition is independent: its own matchers
 * (numbered on this tab), its own tag, one file. Nothing joins one condition to
 * the next - several files are the "or" between them. `r` is the panel's
 * running row number and it is passed in and handed back rather than shared.
 */
int draw_decl_conds(struct out *o, struct view *v, int r)
{
	uint32_t g;

	/* ---- the conditions: what it means ---- */
	if (PR_VIS(r)) {
		sec_bar(o, v, PR(r), " Conditions");
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
	}
	r++;
	v->row_cnd = PR(r);
	for (g = 0; g < v->n_cseq; g++) {
		uint32_t ci = v->cseq_idx[g];
		const struct cond *c2 = &v->ed.dr.cnd[ci];

		if (!PR_VIS(r)) {
			if (v->cseq_kind[g] == CS_COND)
				v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
			else if (v->cseq_kind[g] == CS_MATCH)
				v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			r++;
			continue;
		}
		row_start(o, PR(r), 1);
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_cond, g);

		if (v->cseq_kind[g] == CS_COND) {
			/* Under the label of the block's first row. */
			out_fmt(o, "%7s", "");

			/* THE TYPE AND THE TAG, each chosen from a list and never typed
			 * (the same cells as a block matcher's row). */
			unit_cells(o, v, PR(r), 0, ci);
			r++;
			continue;
		}

		if (v->cseq_kind[g] == CS_MATCH) {
			uint32_t m2;

			/*
			 * THE BLOCK'S NAME GOES ON ITS FIRST ROW, which this
			 * now is. A label on the last line names a thing the
			 * reader has already read past; on the first it says
			 * what they are about to read, and it is the mark that
			 * shows which condition the cursor is on.
			 *
			 * Same width as the rail it replaces - indent plus six
			 * columns - so the rows under it still line up.
			 */
			{
				char lab2[16];

				cnd_label(&v->ed, ci, lab2, sizeof lab2);
				out_fmt(o, "%*s", 1, "");
				out_fmt(o, "%s%-6.6s" A_OFF,
					ci == v->ed.dr.cur_cnd ? A_SEL : A_DIM,
					lab2);
			}
			out_str(o, A_DIM "Matchers: " A_OFF);
			for (m2 = 0; m2 < MAX_GROUP; m2++)
				v->cnd_ids[ci][m2][0] =
					v->cnd_ids[ci][m2][1] = -1;
			v->cnd_op[ci][0] = v->cnd_op[ci][1] = -1;
			v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
			{
				char canon[64];

				cnd_canon(&v->ed, ci, canon, sizeof canon);
				if (c2->expr[0] &&
				    strcmp(c2->expr, canon) != 0) {
					/* Typed, and not a list. Shown as
					 * written, because rendering it as a
					 * list would show a different
					 * condition from the generated one -
					 * and no id is drawn, so none of them
					 * is clickable. */
					v->cnd_ex[ci][0] = 1 +
							   (int)o->col_hint;
					out_str(o, v->edit == 103 + (int)ci
						   ? A_SEL : A_WARN);
					field_draw(o, c2->expr, v->caret,
						   &v->cnd_eoff[ci],
						   v->edit == 103 + (int)ci
						   ? 24
						   : (int)strlen(c2->expr),
						   v->edit == 103 + (int)ci,
						   "");
					out_str(o, A_OFF);
					v->cnd_ex[ci][1] = (int)o->col_hint;
					goto ids_done;
				}
			}
			if (grp_tab_count(&v->ed, DT_PATTERNS)) {
				uint32_t m;
				int first2 = 1;

				for (m = 0; m < v->ed.dr.n_grp; m++) {
					if (!cnd_uses(&v->ed, c2, m))
						continue;
					if (!first2) {
						if (v->cnd_op[ci][0] < 0)
							v->cnd_op[ci][0] = 2 +
							  (int)o->col_hint;
						out_fmt(o, "%s %s " A_OFF,
							c2->op ? A_OR : A_AND,
							c2->op ? "or" : "and");
						v->cnd_op[ci][1] =
							(int)o->col_hint - 1;
					}
					v->cnd_ids[ci][m][0] = 1 +
							       (int)o->col_hint;
					/* The "!" is not the id's colour: it
					 * says the opposite of what the id
					 * says, and reading past it is reading
					 * the condition backwards. It is inside
					 * the click window, because it is what
					 * the author is pointing at when they
					 * want it gone. */
					if (cnd_neg(&v->ed, c2, m))
						out_str(o, A_WARN "!" A_OFF);
					out_fmt(o, "%s%u" A_OFF, A_ID,
						grp_loc(&v->ed, m));
					v->cnd_ids[ci][m][1] = (int)o->col_hint;
					first2 = 0;
				}
				if (first2)
					out_str(o, A_DIM "None" A_OFF);
			} else {
				out_str(o, A_DIM "None" A_OFF);
			}
ids_done:
			v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			if (grp_tab_count(&v->ed, DT_PATTERNS)) {
				v->cnd_mt[ci][0] = 1 + (int)o->col_hint;
				out_fmt(o, "   " A_ID "[+ Matcher]" A_OFF);
				v->cnd_mt[ci][1] = (int)o->col_hint;
			}
			/*
			 * No comment box here.
			 *
			 * A note written above a branch in the source is about
			 * the search the branch makes - "matcher 1: Hooks" -
			 * and the search belongs to the matcher. Two places to
			 * put one remark meant the loader had to guess which,
			 * and it guessed the condition.
			 */
			/*
			 * REMOVING THE BLOCK BELONGS BESIDE ITS NAME.
			 *
			 * It was drawn on the verdict row, which carried the
			 * label until the label moved to the top of the block;
			 * afterwards the button sat two rows below the thing it
			 * names, beside a verdict it has nothing to do with,
			 * and the row a reader aims at - the one that says
			 * which condition this is - threw the click away. It is
			 * on the first row now, from the column every matcher's
			 * is drawn at.
			 */
			out_at(o, PR(r), g_cols - 4);
			out_str(o, A_BAD "[x]" A_OFF);
			r++;
			continue;
		}
	}

	/*
	 * AND THE BUTTON THAT ADDS A CONDITION, at the foot of them all - the
	 * same move the matchers just made, and for the same reason. It makes
	 * an independent block on this tab.
	 */
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->a_c0 = 2;
		out_fmt(o, " %s[+ Condition]" A_OFF,
			grp_tab_count(&v->ed, DT_PATTERNS) ? A_ID : A_DIM);
		v->a_c1 = (int)o->col_hint;
		v->b_c0 = v->b_c1 = -1;
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_addcond, 0);
	}
	r++;
	return r;
}
