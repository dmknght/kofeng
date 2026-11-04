/*
 * kv_view_evt.inc - THE EVENT LOG: the browsed window, the selected event, the gathered content, the embedded executable, the text selection in a row.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P6. Main users (Inference, by unit names): kv_evt.c, kv_tree.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_evt.c, kv_tree.c, kv_main.c, kv_props.c, kv_click.c.
 * Source lines of the old kv_view.h: 127-329.
 */
	/*
	 * AN EVENT LOG, BROWSED AS A WINDOW RATHER THAN LOADED.
	 *
	 * A log holds millions of records and the object array holds MAX_OBJ,
	 * so the objects are a WINDOW over it: LOG_WIN events starting at
	 * log_first, rebuilt when the selection walks off either end. Nothing
	 * of a record is copied - each event object's buf points into the
	 * mapped file at that record's own extent, so the hex pane shows the
	 * real bytes and the memory cost of opening a log is the mapping.
	 *
	 * `log` is a second handle on the same file, used only to ask WHERE a
	 * record is; the bytes come from the mapping. Two handles because the
	 * questions are different and neither wants the other's file position.
	 */
	struct kofevt_log_r *log;
	uint64_t             log_n;      /* records in the file */
	uint64_t             log_first;  /* the window's first record */

	/*
	 * WHICH RECORD EACH ROW STANDS FOR, and where the window stopped.
	 *
	 * Rows are not records any more and the two must not be conflated: the
	 * verb filter hides some, and a continuation is absorbed into the event
	 * in front of it rather than given a row. The paging code used to
	 * recover the last row's record as `log_first + row - 1`, which is only
	 * true when every record in the window got a row - so with a filter on,
	 * turning the page landed somewhere unrelated to where the reader was.
	 */
	uint64_t             log_idx[MAX_OBJ];
	uint64_t             log_next;   /* the first record past the window */

	/*
	 * The tree needs rebuilding before the next frame.
	 *
	 * Set when something learns a fact that changes what rows exist - a
	 * carried image being identified, so its regions can be listed. Acted
	 * on at the top of the frame, because that is the one place where no
	 * caller is holding a node index.
	 */
	int                  tree_dirty;

	/*
	 * WHERE A SCAN'S RESULT FOR ITS OWN ROOT SHOULD GO, or -1.
	 *
	 * A scan reports the object it was given first, and on_object's normal
	 * job is to APPEND what it is told about. That is right when the engine
	 * is walking a file and discovering objects; it is wrong for a row the
	 * tree already has - a carried image, scanned on its own - where the
	 * findings belong to the row a reader is looking at and a second copy
	 * of it would appear beside itself.
	 */
	int                  into_obj;

	/*
	 * HOW MANY OF THOSE RECORDS ARE EVENTS.
	 *
	 * Not the same number as log_n, and the difference is not cosmetic: a
	 * continuation is a record and is not an event, so a log holding one
	 * AMSI submission split over nine chunks has ten records and one event.
	 * Reported as ten, the header told a reader there were nine things in
	 * the file that are not there.
	 *
	 * log_n stays the record count, because that is what indexes the file -
	 * kofevt_log_extent, the window, the paging all count records. This is
	 * only ever shown.
	 */
	uint64_t             log_events;

	/*
	 * WHICH VERBS THIS LOG ACTUALLY CONTAINS, and which of them to show.
	 *
	 * Both are masks of 1u << kof_evt_verb. `log_verbs` is what the file
	 * holds - built once by walking the MAPPING, which costs no I/O - and
	 * it is what the filter submenu offers: a menu listing verbs the log
	 * does not contain is a menu of rows that do nothing.
	 *
	 * `log_keep` is what the object panel shows. It starts equal to
	 * log_verbs, so opening a log shows everything, and Apply narrows it.
	 */
	uint32_t             log_verbs, log_keep;

	/*
	 * HOW MANY OF EACH, counted in the same walk that learns which verbs
	 * the file holds - so it costs nothing beyond the pass already made.
	 *
	 * A mask says a verb is present; a count says whether it is the trace.
	 * "RegSet" and "RegSet 41000" are different facts about a log, and the
	 * second is the one that decides where to look.
	 */
	uint64_t             log_count[32];

	/*
	 * THE SELECTED EVENT, SPELT OUT - the record itself and where the
	 * reader is inside its field list.
	 *
	 * Copied out of the mapping rather than pointed at it, for the reason
	 * log_window already copies: a log written by a build with a different
	 * head has its text at another offset, and a bounded copy into THIS
	 * build's struct is the only read of it that is defined.
	 *
	 * `evt_sel` is a row index, and -1 means the panel is open with
	 * nothing picked - which is the state it starts in, because landing on
	 * a record should show what it says before it starts pointing at one
	 * part of it.
	 */
	struct kof_evt       evt;
	int                  evt_have;   /* the copy above is a real record */
	int                  evt_open;   /* the reader has not closed it */
	int                  evt_n;      /* rows the record yields */
	int                  evt_sel;    /* the row lit in both panes, or -1 */
	int                  evt_scroll; /* first line drawn */
	/*
	 * HOW FAR THE VALUES ARE SHIFTED LEFT.
	 *
	 * The wrap shows the first six lines of a value, which is enough to see
	 * what a thing is and not enough to read a submitted script to its end.
	 * Shifting moves the whole value before it wraps, so the six lines
	 * become a window over it rather than its beginning - and a reader can
	 * reach the tail of an AMSI buffer without the panel eating the pane.
	 */


	/*
	 * THE WHOLE SUBMISSION, gathered from the event and the continuations
	 * behind it.
	 *
	 * The record holds a prefix - four hundred bytes of arena - and the
	 * rest arrives as KOF_EVT_CONT records, which this viewer folds into
	 * the same row. `join` is the raw bytes, in the order they were sent;
	 * `text` is the rendering of them, which is what a pane can show.
	 *
	 * Both are allocated once with the log and reused per selection: a
	 * record's content is bounded by what the collector will send, so a
	 * fixed pair costs the same for every event and there is nothing to
	 * grow or free while walking a log.
	 */
	char                *evt_join;
	char                *evt_text;
	size_t               evt_text_len;

	/*
	 * The gathered content is UTF-16LE - a NUL above every character.
	 *
	 * Kept because the HEX PANE needs it too, not only the field row: a
	 * dump of a script block is half NUL bytes, and a column of dots
	 * between every letter is the thing that makes it unreadable.
	 */
	int                  evt_wide;

	/*
	 * WHERE THE GATHERED CONTENT SITS IN THE NODE'S BYTES.
	 *
	 * The submission is one string once it is joined, and it is NOT one run
	 * in the file: the record holds the first four hundred bytes of it and
	 * each continuation holds the next, with a seventy-two byte head in
	 * between. So a character in the box maps to a byte in the dump only
	 * through a table of the pieces.
	 *
	 * Without it the sync could only mark a selection inside the FIRST
	 * record, which is the part a reader scrolls past.
	 *
	 * Capped, and the cap is honest: past it the map runs out and the sync
	 * marks nothing rather than marking the wrong bytes.
	 */
	struct { uint32_t at, len; } evt_seg[EVT_SEG_MAX];
	int                  evt_n_seg;

	/*
	 * AN EXECUTABLE CARRIED INSIDE AN EVENT, as a child object.
	 *
	 * Some submissions are a PE image rather than a script. The bytes are
	 * already gathered - kof_evt_join concatenates the raw content and
	 * nothing else, so what comes out is the file, byte for byte, with no
	 * record heads or padding between the pieces. What was missing was
	 * anywhere to LOOK at it: the panel renders text, and a PE rendered as
	 * text is a column of dots.
	 *
	 * So the event grows a child row, and selecting it puts the image in
	 * the hex pane like any other object. `pe_of` is the object index of
	 * the EVENT a child belongs to - zero for every row that is not one -
	 * because the child's bytes are its parent's join, materialised when
	 * the child is picked rather than for every event in the window.
	 */
	uint32_t             pe_of[MAX_OBJ];
	uint32_t             pe_at;   /* where the image starts in the join */

	/*
	 * A RUN OF CHARACTERS PICKED OUT OF ONE ROW'S VALUE.
	 *
	 * The name column and the value column answer different gestures. A
	 * click on the NAME is a question about the record - which bytes is
	 * this - so it lights the field and takes the dump there. A drag across
	 * the VALUE is a question about the text: an AMSI submission is a
	 * script, and what a reader wants from a script is to pull a URL or a
	 * base64 blob out of it and paste it somewhere else.
	 *
	 * Anchored to (row, character), not to screen positions: the value
	 * wraps and the panel scrolls, and a selection anchored to a screen
	 * cell would name a different part of the text after either.
	 */
	int                  evt_txt_a, evt_txt_b;
	int                  evt_txt_drag;
