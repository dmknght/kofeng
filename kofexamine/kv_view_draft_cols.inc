/*
 * kv_view_draft_cols.inc - WHERE THE DRAFT PANEL'S CONTROLS WERE DRAWN: comment boxes, string rows, at matchers, condition ids.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P2. Main users (Inference, by unit names): kv_decl.c, kv_click.c, kv_field.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_decl.c, kv_click.c, kv_field.c, kv_input.c, kv_keys.c.
 * Source lines of the old kv_view.h: 1174-1231.
 */
	/* The comment boxes, and the condition's own "+ matcher". Recorded per
	 * row as they are drawn, because a row that is scrolled out has no
	 * columns and must not answer a click meant for the one in its place. */
	int         grp_nt[MAX_GROUP][2];
	/* Where a string row's word/case block and its bytes were drawn. Read
	 * back rather than assumed: the columns move when a field widens, and
	 * a click routed by a remembered number goes to the wrong control. */
	int       (*str_wc)[2], (*str_by)[2];
	uint32_t    cap_str_col;        /* rows the two arrays above, and every matcher's grp_it, have room for (decl_cols_reserve) */
	int         grp_rl[MAX_GROUP][2], grp_rg[MAX_GROUP][2];
	/*
	 * AN AT MATCHER'S PLACE IS THREE CONTROLS, NOT ONE.
	 *
	 * The anchor names where to count from and opens a list; the sign
	 * says which way and is pressed; the step is typed. They were one
	 * span that opened the list, so the only way to change the number was
	 * to pick a different occurrence of the marker.
	 *
	 * -1 for a row that has none: a matcher that is not an AT, a row that
	 * is scrolled out, and the sign of an anchor that has no choice of
	 * one - see grp_at_sign_free.
	 */
	int         grp_sg[MAX_GROUP][2], grp_of[MAX_GROUP][2];
	char        at_buf[24];     /* the step being typed, as written */
	uint32_t    at_buf_off;
	int         grp_th[MAX_GROUP][2];
	int         cnd_op[MAX_GROUP][2];
	/* Two per condition: its matcher row and its tag row. */
	uint8_t     cseq_kind[2 * MAX_GROUP];
	uint32_t    cseq_idx[2 * MAX_GROUP];
	uint32_t    n_cseq;
	/*
	 * WHERE EACH MATCHER ID ON A CONDITION'S ROW WAS DRAWN.
	 *
	 * Recorded while drawing, the way every other clickable span on these
	 * rows is, rather than recomputed by the hit test from a start column
	 * and a stride. The stride version has been wrong twice - once when the
	 * ids grew past one digit, once when the separator stopped being ", " -
	 * and both times the failure was a click that removed a matcher the
	 * author had not pointed at. There is nothing to keep in step here: the
	 * columns come from the same pass that printed them.
	 *
	 * -1 means "not drawn": the condition does not name that matcher, or
	 * the row is showing a typed expression rather than a list.
	 */
	int         cnd_ids[MAX_GROUP][MAX_GROUP][2];
	/*
	 * And where its TYPED EXPRESSION box is, when the condition carries one
	 * that is not a plain list of ids.
	 *
	 * The box was drawn with a focus colour and the keys to edit it were
	 * wired (edit band 103+i), but nothing recorded a click range and
	 * nothing ever set that band - so a rule loaded from source with an
	 * expression like "(1&2)|3" showed a field that could not be focused or
	 * typed into by any means.
	 */
	int         cnd_ex[MAX_GROUP][2];
	int         cnd_mt[MAX_GROUP][2];
	int         row_rng, row_grp;
