/*
 * kv_view_find.inc - FIND, GO TO and the shellcode dialog.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P8. Main users (Inference, by unit names): kv_find.c, kv_dialogs.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_dialogs.c, kv_keys.c, kv_menu.c, kv_bar.c, kv_click.c.
 * Source lines of the old kv_view.h: 944-973.
 */
	/*
	 * What is being searched for, and where it was last found.
	 *
	 * `scope` is the one thing a terminal cannot give a modifier for:
	 * Ctrl+Shift+F arrives as the same byte as Ctrl+F on every terminal
	 * that does not implement the newer key protocols, so the choice
	 * between this region and the whole object is made inside the prompt
	 * with Tab rather than by a chord that most terminals cannot send.
	 */
	char        find[80];
	int         find_open;      /* the dialog is up */
	/*
	 * GO TO: an offset typed in, and where it is measured from.
	 *
	 * Its own flag and buffer rather than the find dialog's, because the two
	 * take different things - find takes bytes to look for, this takes one
	 * number - and sharing the field meant a half-typed search turning into
	 * an offset. `goto_file` says whether the number is a FILE offset or an
	 * offset into the region being looked at: both are what somebody means
	 * by "offset" depending on what they are reading, and the hex pane shows
	 * region offsets while every report and every finding names file ones.
	 */
	int         goto_open;
	/*
	 * The shellcode dialog: open, and how far down its byte dump is.
	 *
	 * Separate from the symbol tables' fields even though the two look
	 * alike, because they can be open over each other and a shared offset
	 * would move one when the other scrolled.
	 */
