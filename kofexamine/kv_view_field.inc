/*
 * kv_view_field.inc - THE FIELD BEING EDITED: the active pane, scroll of the note, the caret and the selected range, and `per`.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P8. Main users (Inference, by unit names): kv_field.c, kv_keys.c, kv_click.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_click.c, kv_events.c, kv_decl.c, kv_field.c, kv_families.c.
 * Source lines of the old kv_view.h: 1232-1295.
 */
	int         pane;           /* 0 tree, 1 hex, 2 markers, 3 draft */
	/*
	 * What the module says about itself, beside the family and the type.
	 *
	 * The two that are already there are a name and an enum; this is the
	 * sentence neither can hold - which family this really belongs to, why
	 * the type was chosen, what the sample was. Written into the generated
	 * source above the declarations, where the next reader meets it before
	 * any of the logic.
	 */

	/*
	 * How far the comment is scrolled inside its own box.
	 *
	 * Its own, not the panel's: the box is one field on a row of fields and
	 * sliding the whole row to read the end of it would take the buttons
	 * off the screen. Follows the caret while the field is being typed
	 * into, so what is being written is always the part on show.
	 */
	uint32_t    note_off;
	/*
	 * Where the caret is in whatever field is being typed into, and which
	 * field that was last time round.
	 *
	 * One caret because only one field is ever open. Comparing the field
	 * against last frame's is how it gets placed at the end of the text
	 * when a field is opened, without every place that opens one having to
	 * remember to say so.
	 */
	uint32_t    caret;
	int         edit_prev;
	/*
	 * WHAT IS SELECTED IN THE OPEN FIELD - a RANGE, unordered.
	 *
	 * It was one flag meaning "all of it", which is what Ctrl+A needs and
	 * is not what a text box is. Dragging the pointer through a pattern to
	 * take half of it, which is how anyone copies part of a string
	 * anywhere else, had nothing to express: the box answered a click with
	 * a caret and that was all it did. So the flag became the two ends of a
	 * range, and Ctrl+A is now the case where they are 0 and the length.
	 *
	 * `fld_a` is the anchor and is NOT normalised - a drag leftwards leaves
	 * b before a, and normalising as it moves would pin the anchor to
	 * whichever end the pointer passed last. Read them through fsel_lo and
	 * fsel_hi.
	 *
	 * Only the field that is OPEN can carry one, so they are cleared
	 * wherever the caret is placed afresh.
	 */
	uint32_t    fld_a, fld_b;
	int         fld_drag;       /* the pointer is extending it */
	/*
	 * WHICH FIELD THE RANGE BELONGS TO - `edit` as it was when the range
	 * was made.
	 *
	 * Without it a range outlives the box it was dragged in: open another
	 * field and the old offsets are painted into it, over text they were
	 * never about. Clearing at every place that assigns `edit` would be a
	 * rule thirty call sites have to remember; comparing is a rule kept in
	 * one place - see fsel_range.
	 */
	int         fld_of;
	int         per;            /* bytes a hex row shows, for click mapping */
