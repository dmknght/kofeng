/*
 * kv_view_dlg.inc - A DIALOG'S TEXT, ITS SELECTION, THE BOX BEING MOVED AND THE LAST PRESS.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P7. Main users (Inference, by unit names): kv_dlgsel.c, kv_dialogs.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_dlgsel.c, kv_dialogs.c, kv_click.c, kv_events.c, kv_props_table.c.
 * Source lines of the old kv_view.h: 974-1053.
 */
	/*
	 * A DIALOG'S TEXT, AND THE CHARACTERS SELECTED IN IT.
	 *
	 * One set of fields for both dialogs, because only one of them can be
	 * selected in at a time - the boxes are modals, and the topmost owns
	 * the mouse. Two sets would be two things to keep in step for no gain.
	 *
	 * dlg_y0/dlg_x0 are where row 0, column 0 of the recorded text sits on
	 * screen, so a click can be turned into a (row, column) in the text
	 * without the click routing knowing how the box is laid out.
	 *
	 * The anchor is where the drag started and is NOT normalised: a
	 * selection dragged upwards has b before a, and normalising on the way
	 * in would make the anchor move as the pointer does. It is ordered when
	 * it is read, in dlg_span.
	 */
	char        dlg_line[DLG_ROWS][DLG_COLS];
	int         dlg_rows;
	/*
	 * WHERE EACH COLUMN OF A RECORDED ROW BEGINS IN ITS BYTES.
	 *
	 * The screen counts GLYPHS and the recording holds BYTES, and the two
	 * stopped agreeing the day these pages grew box rules: G_V is three
	 * bytes and one column, so from the first wall onwards a click at
	 * column N landed on byte N, three or six bytes to the left of what
	 * the reader pointed at. The highlight was drawn from the same wrong
	 * place, which put its edge in the middle of a glyph - a border that
	 * appeared several words away, and a stray character where the reverse
	 * video repainted half of one.
	 *
	 * Folding the glyphs down to ASCII in the recording would have squared
	 * the arithmetic and changed what a selection PAINTS and COPIES, which
	 * is the thing the recording exists to get right. This keeps the real
	 * bytes and adds the translation: dlg_bx[row][col] is the first byte of
	 * that column and dlg_bx[row][cols] is one past the last, so a span in
	 * columns becomes a span in bytes by two lookups.
	 */
	uint16_t    dlg_bx[DLG_ROWS][DLG_COLS + 1];
	uint16_t    dlg_cols[DLG_ROWS];
	/*
	 * WHICH LINE OF THE LIST each recorded row came from, and -1 when the
	 * recorder was not told.
	 *
	 * The recording is of the VISIBLE WINDOW, rebuilt every frame, so a row
	 * number means "third row on screen" and not "third line of the page".
	 * A selection stored as a row number therefore slid onto whatever the
	 * scroll had put there - the text under the highlight changed while the
	 * highlight stayed still. Anchoring on this instead makes a selection
	 * belong to the LINE it was made on, wherever that line goes.
	 */
	int         dlg_src[DLG_ROWS];
	int         dlg_y0, dlg_x0;
	int         dlg_ar, dlg_ac, dlg_br, dlg_bc;
	int         dlg_have;
	int         dlg_drag;
	/*
	 * THE BOX BEING MOVED, and where the grab started.
	 *
	 * A pointer to the frame rather than a code for which dialog: every box
	 * goes through dframe, the frames are static, and a code would be a
	 * second list to keep in step with the first. NULL when nothing is
	 * being moved.
	 */
	struct dlg_off *dlg_move;
	int         dlg_mx, dlg_my;     /* where the pointer took hold */
	int         dlg_mdx, dlg_mdy;   /* the box's offset when it did */
	/*
	 * THE LAST PRESS IN A DIALOG, so a second one on the same place can be
	 * recognised as a double click.
	 *
	 * Timed rather than counted, for the reason the hex pane's is: a
	 * terminal reports two presses and has no notion of a double click to
	 * pass on. Kept apart from last_click because that one is a byte
	 * OFFSET in the file and this is a place in a recorded page - the same
	 * number would mean two different things, and a click in one pane
	 * would arm a double click in the other.
	 */
	int         dlg_click_r, dlg_click_c;
	uint64_t    dlg_click_ms;
