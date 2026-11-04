/*
 * kv_view_props.inc - THE PROPERTIES PAGE: open flag and scroll.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P7. Main users (Inference, by unit names): kv_page.c, kv_props_tab.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_keys.c, kv_props_tab.c, kv_barmenu.h, kv_click.c, kv_page.c.
 * Source lines of the old kv_view.h: 904-943.
 */
	int         prop_open;      /* the properties page is up */
	/*
	 * A SECOND MODAL PAGE STOOD HERE - the call chain the sweep read and
	 * the trace the interpreter produced, as two tabs of one box. Both
	 * went with the chain matcher. The fields are gone rather than left
	 * at zero, because a dialog's state that nothing ever sets is a
	 * dialog the modal id below still counts.
	 */
	uint32_t    prop_off;       /* the first of its lines on screen */
	/*
	 * "[Copy full path]" on the folder row: which row carries it and which
	 * of that row's columns it occupies, or -1 when the page has no such
	 * row at all.
	 *
	 * Recorded per BUILD rather than per frame because the page scrolls -
	 * the row's index in g_prop is fixed, its position on the screen is
	 * not, so the click converts one to the other with prop_off the way the
	 * select path already does.
	 */
	/*
	 * WHAT IS SELECTED ON THE PAGE, WHICH IS NOT THE SAME AS WHAT WAS CLICKED.
	 *
	 * Clicking used to copy outright, and that is the wrong gesture: a reader
	 * clicks to look, and a click that reaches outside the program and changes
	 * the clipboard is a side effect nobody asked for. Selecting shows what
	 * would be taken and lets it be adjusted; Ctrl+C is when they say to take
	 * it. Same two steps the hex pane already uses, for the same reason.
	 *
	 * Columns index the line's PLAIN text - what prop_plain produces - so the
	 * range means the same thing to the painter and to the copier.
	 */
	/*
	 * Where the mouse went DOWN, which is not where the selection starts.
	 *
	 * A click selects the whole word under it, so the selection's ends are
	 * the word's ends. Dragging must grow from the point that was clicked,
	 * not from whichever end the word happened to put there - otherwise
	 * pulling back over the word does nothing until the pointer passes its
	 * far edge, which is what made dragging feel broken.
	 */
