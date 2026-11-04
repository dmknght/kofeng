/*
 * kv_view_text.inc - THE TEXT PANE: column origin, line-number anchor, longest line, forced hex.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P5. Main users (Inference, by unit names): kv_text.c, kv_view.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_text.c, kv_view.c.
 * Source lines of the old kv_view.h: 1296-1334.
 */
	/*
	 * THE TEXT PANE, which is this same pane rendered for something meant
	 * to be read - see KV_CAP_TEXT. Same region, same rgn_at, same
	 * selection, same menu; what changes is the layout and what the status
	 * line counts in.
	 *
	 * rgn_at STAYS THE BYTE OFFSET OF THE TOP OF THE PANE, exactly as the
	 * hex view leaves it. That is what lets goto, find, a marker jump and
	 * every scroll key keep working unchanged: they move a byte offset, and
	 * this pane rounds it down to the start of its line to draw.
	 */
	uint32_t    txt_col;        /* horizontal origin, in columns */
	/*
	 * THE LINE NUMBER OF THE TOP ROW, and an anchor to compute it from.
	 *
	 * Counting newlines from the start of the region every frame is one
	 * pass over the whole region per keystroke - three milliseconds on a
	 * ten megabyte script, on every arrow key. So the last answer is kept
	 * and the next one is counted FROM it, which is a few bytes when
	 * scrolling and a full rescan only when something jumps.
	 */
	uint64_t    txt_anchor;     /* a byte offset whose line number is known */
	uint64_t    txt_anchor_ln;  /* that line number, 0 based */
	/*
	 * The longest line the last frame drew, so sideways scrolling can stop
	 * where the text does. Without it the pane scrolls into blank space and
	 * the reader is left pressing a key that empties the screen - which
	 * reads as the key not working rather than as the end of the line.
	 */
	uint32_t    txt_maxlen;
	/*
	 * THE READER ASKED FOR BYTES, on something this would otherwise show
	 * as text.
	 *
	 * Sticky rather than per object: it is a preference about how to read,
	 * not a fact about a file, and a setting that resets when you step to
	 * the next node is one you set again on every node.
	 */
	uint8_t     hex_forced;
