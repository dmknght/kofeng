/*
 * kv_view_dis.inc - THE DISASSEMBLY PANEL: its range, line selection, text selection, bias and recorded lines.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P5. Main users (Inference, by unit names): kv_disasm.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_disasm.c, kv_click.c, kv_events.c, kv_clip.c, kv_menu.c.
 * Source lines of the old kv_view.h: 386-505.
 */
	/*
	 * THE DISASSEMBLY PANEL.
	 *
	 * `dis_open` is the panel; `dis_bits` is 32 or 64, because raw shellcode
	 * carries no header to say which and the answer changes what the same
	 * bytes mean - a payload unpacked out of a Metasploit encoder is bytes
	 * and nothing else. It is seeded from the object's architecture when
	 * there is one and left for the reader to change when there is not.
	 *
	 * `dis_at`/`dis_len` pin the panel to a RANGE the reader chose, and
	 * KGENOME_BROKEN in dis_len means it is not pinned: it follows the hex
	 * scroll instead. Both are region offsets, like every other position in
	 * this view.
	 */
	int         dis_open;
	int         dis_bits;
	uint64_t    dis_at, dis_len;

	/*
	 * A selection of LINES in the panel, and the text each one printed.
	 *
	 * Lines rather than characters, because an instruction is the unit
	 * somebody copies: half of a MOV pasted into a note is not a smaller
	 * answer, it is a wrong one. Held as row indices from the top of the
	 * panel, and -1 when nothing is selected.
	 *
	 * The text is kept because the panel is redrawn from the bytes every
	 * frame and the copy has to be of what was on screen - decoding it a
	 * second time at copy time would be a second decoder to disagree with
	 * the first, in exactly the case where the reader is looking at the
	 * output of the first.
	 */
	/*
	 * A TEXT SELECTION, character by character, the way one behaves
	 * anywhere else: an anchor where the press landed and a cursor where the
	 * pointer is, each a row and a column into the panel's own rows.
	 *
	 * It was whole lines, and whole lines are wrong for the same reason a
	 * hex selection is not whole rows: the reader picks what they mean to
	 * copy, and an operand or a mnemonic on its own is a thing people take.
	 *
	 * dis_have is 0 when nothing is selected.
	 */
	/*
	 * ANCHORED TO BYTES, NOT TO ROWS.
	 *
	 * Each end is the file offset of the instruction its row starts at, plus
	 * a column within that row's text. Row indices were tried and are wrong
	 * for one reason: they go stale the moment the panel scrolls, so row 3
	 * stayed lit while row 3 became a different instruction - and scrolling
	 * away and back lost the selection entirely. A byte offset means the
	 * highlight belongs to the instruction, which is what the reader picked.
	 */
	uint64_t    dis_a_at, dis_b_at;
	int         dis_ac, dis_bc;
	int         dis_have;           /* anything selected at all */
	int         dis_dragging;


	/*
	 * WHAT THE PANEL IS READING FROM when it is not pinned.
	 *
	 * See dis_follow_hex for the rule that sets it, and dis_seen_* for what
	 * it last saw of the two things that can move it.
	 */
	uint64_t    dis_follow;
	/*
	 * HOW FAR THE PANEL SITS FROM THE HEX SCROLL, and it is a CONSTANT.
	 *
	 * The panel reads from rgn_at + dis_bias, so scrolling the hex moves it
	 * by exactly as much - the two are locked together whatever the bias is.
	 * Selecting bytes is what sets the bias: enough to bring the selected run
	 * onto these rows. Nothing else changes it, so scrolling away and back
	 * puts the selection back where it was.
	 *
	 * This replaced four attempts that each tied the panel's POSITION to the
	 * selection instead of to the scroll. Every one of them broke one of the
	 * two things asked of it - either the panel stopped following the scroll,
	 * or the highlight left the rows and did not come back. A bias is the
	 * thing that was missing: an offset can satisfy both because it is not a
	 * position at all.
	 */
	int64_t     dis_bias;

	/*
	 * WHO SET THE BYTE SELECTION, and it has to be recorded because the
	 * sync runs both ways.
	 *
	 * The panel follows the hex selection, and picking lines in the panel
	 * SETS that selection - so without this the panel followed itself: a
	 * click on a line moved the selection, the selection moved the panel's
	 * start, and the row under the pointer was no longer the row that had
	 * been clicked. The hex pane does not scroll to a selection, so the two
	 * came apart as well.
	 *
	 * One flag, and the rule it encodes: a selection made HERE does not move
	 * this panel. A selection made in the hex pane does.
	 */
	int         sel_from_dis;
	/*
	 * The last instruction that set the flags (a CMP or a TEST) and where the next instruction would start, so a conditional jump read right after
	 * it - or after instructions that leave the flags alone - is explained as the comparison it is. Kept by dis_format as it goes; a row that is not
	 * the next of the last one starts from nothing known.
	 */
	struct dis_flow dis_flow;
	char        dis_line[64][DIS_LINE_MAX];
	/*
	 * The bytes each drawn line stands for.
	 *
	 * Kept so that a selection made in the panel can be turned back into a
	 * byte range - which is what lets the hex pane's own menu items work on
	 * it unchanged. Selecting three instructions and declaring them as a
	 * marker is the same act as selecting their bytes, and it should not
	 * need a second implementation to say so.
	 */
	uint64_t    dis_line_at[64], dis_line_len[64];
	uint8_t     dis_line_lbl[64];       /* the row is a label: no bytes, not selectable */
	int         dis_lines;
	int         dragging;
