/*
 * kv_view_hex.inc - THE HEX PANE: the extent buffers, the byte selection, the process a view is showing.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P5/P9. Main users (Inference, by unit names): kv_hex.c, kv_view.c, kv_collect.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_main.c, kv_view.c, kv_disasm.c, kv_click.c, kv_collect.c.
 * Source lines of the old kv_view.h: 330-385.
 */
	struct kof_range *ext;
	/*
	 * A SECOND EXTENT BUFFER, for anything that resolves a region that is
	 * not the one on screen.
	 *
	 * `ext` holds the SELECTED region's runs and is what view_map and
	 * view_unmap read - the hex pane's entire sense of where it is. Mutation
	 * mode resolves other regions to carve and to score, and resolving into
	 * `ext` overwrote that: the highlight then mapped through the wrong
	 * runs and landed nowhere, and the pane it was drawn over was reading
	 * the same wreckage.
	 */
	struct kof_range *ext2;
	uint32_t          n_ext;
	/*
	 * A second extent buffer, for asking about a region that is not the one
	 * being looked at.
	 *
	 * `ext` describes the selected node and the hex pane maps every byte
	 * through it. A lookup that resolved some other region into it left the
	 * pane mapping through extents that belonged to nothing it was showing
	 * - every offset came back as the start of the file, so declaring a
	 * string turned the whole pane into byte zero repeated. A question
	 * about another region gets its own paper.
	 */
	struct kof_range *probe;
	uint64_t          rgn_len, rgn_at;

	/*
	 * A selection of BYTES, not of screen text.
	 *
	 * Held as offsets into the region, which is what dissolves both problems
	 * a character selection has: there is no offset column and no ASCII
	 * column in this model, only bytes, so clicking either one names the
	 * same byte and neither can be dragged into the selection by accident.
	 * A press outside the hex pane is not a hex selection at all, so the
	 * tree and the markers line cannot be dragged into it either.
	 *
	 * KGENOME_BROKEN for "nothing selected", which is distinct from a selection
	 * of length zero.
	 */
	uint64_t    sel_a, sel_b;
	/* The process this view is showing, or 0 when it is a file. What makes
	 * next/prev step through pids instead of through a directory. */
	uint32_t    proc_pid;
	/* The process record v->map points at while proc_pid is set: the view's own,
	 * so two views never overwrite each other's (it was a static in proc_open). */
	uint8_t     proc_rec[8192];   /* KOF_PROC_REC_MAX, checked in kv_main.c */
	/* The mapped files already given a row - see proc_seen_path. */
#define PROC_SEEN_MAX 256u
	char        seen_path[PROC_SEEN_MAX][256];
	uint32_t    n_seen;
	/* Mapped files this view declined to read, and the bytes it did. */
	uint32_t    proc_skipped;
	uint64_t    proc_skipped_bytes;
