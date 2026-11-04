/*
 * kv_view_menu.inc - THE CONTEXT MENU and the chooser it opens.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P3. Main users (Inference, by unit names): kv_menu.c, kv_chooser.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_menu.c, kv_click.c, kv_dialogs.c, kv_events.c, kv_chooser.c.
 * Source lines of the old kv_view.h: 506-513.
 */
	/* Which half of the hex pane the menu was opened on. */
	int         menu_ctx;       /* 1 bytes, 2 the offset column,
				     * 4 the disassembly, 8 the event box */
	uint64_t    menu_off;       /* the row offset it was opened on */

	int         menu_open, menu_row, menu_col, menu_sel, menu_scroll;
	struct chooser ch;
