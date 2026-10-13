#define _GNU_SOURCE
#include "kv.h"


/*
 * The furthest the hex pane may be scrolled.
 *
 * Not rgn_len. Clamping the TOP of the view to the end of the data lets the pane
 * scroll until every row is past the end and the screen is blank - which it did,
 * and which is worse than not scrolling at all: an empty pane reads as a region
 * with nothing in it rather than as a cursor parked past the last byte.
 *
 * The limit is the position that puts the LAST row of data on the bottom row of
 * the pane. A region that fits entirely gets a limit of zero and does not scroll
 * at all - a ten row header has nothing below it to scroll to.
 */
uint64_t hex_max(const struct view *v)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t rows = (uint64_t)(hex_last() - hex_top() + 1);
	uint64_t last, top;

	if (!v->rgn_len)
		return 0;
	last = (v->rgn_len - 1u) / per * per;      /* where the last row starts */
	if (!rows)
		return last;
	top = (rows - 1u) * per;
	return last > top ? last - top : 0;
}

void view_select(struct view *v)
{
	struct object *o;
	uint32_t i;

	/* Before anything reads o->touch: this is the one place every path
	 * that changes the selection goes through. */
	object_touch(v, v->node[v->sel_node].obj);
	o = cur_obj(v);

	/* The one UI fact the model is told - see kof_editor.cur. */
	v->ed.cur = v->node[v->sel_node].obj;

	/* Before the early return below: a view with no extent buffer still
	 * has a selected row, and the panel is about the RECORD rather than
	 * about the extents. */
	evt_load(v);

	v->n_ext = 0;
	v->rgn_len = 0;
	if (!v->ext)
		return;
	/*
	 * A SYMBOL ROW IS A ROW OF EXTENTS LIKE ANY OTHER, and its extents come
	 * from the engine.
	 *
	 * It used to be a special case with n_ext left at zero, which meant
	 * view_map, view_unmap, the selection and the search each needed their
	 * own branch for it - and each of those branches was a place to get the
	 * two address spaces confused, which is what happened four separate
	 * times. Resolved the same way a region is, all of that goes away: the
	 * pane walks extents, so it shows exactly the records of that half and
	 * nothing between them.
	 */
	if (v->node[v->sel_node].sym) {
		uint32_t a, b2;

		v->n_ext = kof_sym_extents(o->sym, o->sym_n,
					   v->node[v->sel_node].mask, v->ext,
					   KOF_SCAN_MAX_EXTENTS);
		/*
		 * REVERSED FOR READING, and only for reading.
		 *
		 * The engine hands back its runs last-first, because a search
		 * wants the author's own symbols before the runtime's and a
		 * boolean answer does not care about order. A TABLE does: read
		 * in that order the symbol list runs backwards. So the extents
		 * are flipped here, where the decision is about the screen -
		 * the search still calls kof_sym_extents itself and still gets
		 * the engine's order.
		 */
		for (a = 0, b2 = v->n_ext; a + 1u < b2; a++) {
			struct kof_range t = v->ext[a];

			b2--;
			v->ext[a] = v->ext[b2];
			v->ext[b2] = t;
		}
	} else if (v->node[v->sel_node].piece) {
		/*
		 * ONE RUN, THE ROW'S OWN. Resolving its mask would answer about
		 * every run of that region at once, which is the concatenation
		 * this row exists to take apart.
		 */
		uint64_t off = v->node[v->sel_node].ent_off;
		uint64_t len = v->node[v->sel_node].ent_len;
		uint64_t n = o->buf.n ? o->buf.n : o->ctx.obj_size;

		if (off < n) {
			if (len > n - off)
				len = n - off;
			v->ext[0].off = off;
			v->ext[0].len = len;
			v->n_ext = len ? 1u : 0u;
		}
	} else if (v->node[v->sel_node].ent) {
		/*
		 * ONE EXTENT, THE ENTRY'S OWN, AND NOT A RESOLVE.
		 *
		 * There is nothing to resolve: an entry is one range and the
		 * parse already said which. Sending it through resolve_scan
		 * would answer about a REGION - the kind this entry belongs to,
		 * every entry of that kind at once - and the pane would show a
		 * different thing from the row the cursor is on.
		 *
		 * Clipped to what the object actually has. The range is derived
		 * from the file, and this is the last place before a read.
		 */
		uint64_t off = v->node[v->sel_node].ent_off;
		uint64_t len = v->node[v->sel_node].ent_len;
		uint64_t n = o->buf.n ? o->buf.n : o->ctx.obj_size;

		if (off < n) {
			if (len > n - off)
				len = n - off;
			v->ext[0].off = off;
			v->ext[0].len = len;
			v->n_ext = len ? 1u : 0u;
		}
	} else
		v->n_ext = kof_scan_resolve_range(&o->ctx,
						  v->node[v->sel_node].mask ?
						  v->node[v->sel_node].mask :
						  KOF_SCAN_ALL, v->ext);
	if (!v->n_ext && o->buf.n) {
		v->ext[0].off = 0;
		v->ext[0].len = o->buf.n;
		v->n_ext = 1;
	}
	for (i = 0; i < v->n_ext; i++)
		v->rgn_len += v->ext[i].len;

	/* A remembered place is re-clamped rather than trusted: the pane may be
	 * a different height than it was when the row was left. */
	/* A new row is a new place, so the sideways origin goes back to the
	 * left margin - carrying it over shows the middle of lines in a region
	 * the reader has not looked at yet. */
	v->txt_col = 0;
	/*
	 * AND THE LINE-NUMBER ANCHOR GOES WITH IT, for the same reason and a
	 * worse consequence.
	 *
	 * txt_anchor is "the line number of this byte offset", and both halves
	 * of that are about the region that was showing: the offset is in its
	 * address space and the count is of ITS newlines. Carried into the next
	 * row it is a fact about somewhere else, and txt_line_of then does
	 * arithmetic on it - see the note there for what the reader saw.
	 */
	v->txt_anchor = v->txt_anchor_ln = 0;
	v->rgn_at = v->node[v->sel_node].at;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

/*
 * Move the tree cursor, keeping each row's place.
 *
 * The row being left keeps where it was; the row being arrived at gets its own
 * back. A byte selection does not survive the move - it is an offset into the
 * region that was showing, and the same number means somewhere else in the next
 * one - and the module the markers line is on only resets when the OBJECT
 * changes, because it is a property of the object and not of the region.
 */
void goto_node(struct view *v, uint32_t k)
{
	uint32_t was;

	/*
	 * WALKING OFF THE END OF THE WINDOW SCROLLS THE LOG, rather than
	 * stopping at the last loaded event.
	 *
	 * Without this the list ends at whatever the window happened to hold
	 * and a reader concludes the log does too - which for a file of
	 * millions is the wrong answer given confidently. The window follows
	 * the selection instead, and the ids on screen keep counting.
	 */
	/* k == -1 is "one before the first row" and is handled below: it is also >= n_node */
	if (v->log && k != (uint32_t)-1 && k >= v->n_node && v->n_node) {
		uint32_t j;

		/*
		 * The next page begins where this one stopped - a number the
		 * window itself reports, because it is the only thing that
		 * knows how many records went into a row. Recomputing it from
		 * the row count assumed one record per row, which stopped
		 * being true when the verb filter arrived and stopped being
		 * true again when continuations were folded in.
		 */
		if (v->log_next < v->log_n &&
		    log_window_from(v, v->log_next)) {
			tree_build(v);
			/* Land on the first row of what was just loaded rather
			 * than at the top: the reader was moving DOWN. */
			v->sel_node = 0;
			for (j = 0; j < v->n_node; j++) {
				if (v->node[j].obj == 1u) {
					v->sel_node = j;
					break;
				}
			}
			v->sel_a = v->sel_b = KGENOME_BROKEN;
			v->dis_have = 0;
			view_select(v);
		}
		return;
	}
	if (v->log && k == (uint32_t)-1 && v->log_first) {
		/*
		 * A page back, by RECORDS rather than by rows. With a filter on
		 * this may not fill the screen - the records behind may be ones
		 * the filter hides - and that is the honest result: it shows
		 * what is there. Stepping back again keeps going.
		 */
		uint64_t back = (v->log_first > LOG_WIN) ?
				v->log_first - LOG_WIN : 0;

		if (log_window_from(v, back)) {
			tree_build(v);
			v->sel_node = v->n_node ? v->n_node - 1u : 0;
			v->sel_a = v->sel_b = KGENOME_BROKEN;
			v->dis_have = 0;
			view_select(v);
		}
		return;
	}

	if (k >= v->n_node || k == v->sel_node)
		return;
	was = v->node[v->sel_node].obj;
	v->node[v->sel_node].at = v->rgn_at;
	v->sel_node = k;
	v->sel_a = v->sel_b = KGENOME_BROKEN;
	/* The panel's rows are about the bytes that were on screen; moving to
	 * another region makes them about different ones. */
	v->dis_have = 0;
	v->dragging = 0;
	if (v->node[k].obj != was) {
		/* touch_default reads the list, so the list has to exist. */
		object_touch(v, v->node[k].obj);
		v->sel_touch = touch_default(&v->obj[v->node[k].obj]);
	}
	view_select(v);
}

/*
 * THE BYTES THE SELECTED ROW IS SHOWING, whatever kind of row it is.
 *
 * One accessor, because five places need it and they had all hard-coded
 * `ob->buf.p`: the pane, the copy, the marker being declared, the word the
 * double-click extends to, and the disassembler's feed. On a symbol row that
 * pointer is wrong - view_map returns an offset into the BLOCK, so indexing the
 * file with it reads unrelated bytes at the same number and hands them to the
 * copy and to the marker as though they were what was on screen. Every caller
 * asks here instead, so a row kind added later cannot be right in the drawing
 * and silently wrong in everything that acts on it.
 */
const uint8_t *view_bytes(const struct view *v, uint64_t *n)
{
	const struct object *o = &v->obj[v->node[v->sel_node].obj];

	if (sym_view(v))
		return sym_block(v, n);
	if (n)
		*n = o->buf.n;
	return o->buf.p;
}

/* The file offset of byte `at` of the selected region, and how much of that
 * extent is left. Regions are not contiguous, so a pane that walked the file
 * would show bytes the region does not contain. */
uint64_t view_map(const struct view *v, uint64_t at, uint64_t *run)
{
	uint32_t i;

	for (i = 0; i < v->n_ext; i++) {
		if (at < v->ext[i].len) {
			if (run)
				*run = v->ext[i].len - at;
			return v->ext[i].off + at;
		}
		at -= v->ext[i].len;
	}
	if (run)
		*run = 0;
	return 0;
}

/* The inverse of view_map: where in the region a file offset sits, or KGENOME_BROKEN
 * when the region does not contain it. Needed because the markers speak file
 * offsets and the hex cursor is an offset into the region. */
uint64_t view_unmap(const struct view *v, uint64_t off)
{
	uint64_t base = 0;
	uint32_t i;

	for (i = 0; i < v->n_ext; i++) {
		if (off >= v->ext[i].off && off < v->ext[i].off + v->ext[i].len)
			return base + (off - v->ext[i].off);
		base += v->ext[i].len;
	}
	return KGENOME_BROKEN;
}

/*
 * Which byte is under (row, col), if any.
 *
 * The hex pane draws each byte twice - once as two digits, once as a character -
 * and both are the same byte. So both map to it, and the separator columns and
 * the offset column map to nothing. That is the whole answer to "a drag picks up
 * the offset and the ASCII column too": those are not selectable things, they
 * are two renderings and one label of things that are.
 */
int byte_under(struct view *v, int row, int col, uint64_t *out)
{
	int per = v->per > 0 ? v->per : 16;
	int base = TREE_W + 3;
	int hexs = base + 10;
	int asci = hexs + 3 * per + 2;
	int k;
	uint64_t at;

	/*
	 * ANSWERED HERE AND NOT AT EVERY CALL SITE.
	 *
	 * "Which byte is under the pointer" is one question, and the pane has
	 * two layouts. Dispatching inside it means the press, the drag and
	 * anything added later all get the right answer without each having to
	 * remember there are two - which is exactly how the draft panel's
	 * column tests drifted apart.
	 */
	if (text_pane(v))
		return text_under(v, row, col, out, NULL, NULL);

	if (row < hex_top() || row > hex_last())
		return 0;
	if (col >= hexs && col < hexs + 3 * per)
		k = (col - hexs) / 3;
	else if (col >= asci && col < asci + per)
		k = col - asci;
	else
		return 0;

	at = v->rgn_at + (uint64_t)(row - hex_top()) * (uint64_t)per +
	     (uint64_t)k;
	if (at >= v->rgn_len)
		return 0;
	*out = at;
	return 1;
}


/*
 * The region row of `obj` that contains `file_off`, or the object row when none
 * does.
 *
 * A marker's region is a property of the bytes, not of what the tree cursor
 * happened to be sitting on when they were taken: selecting a string that is
 * plainly inside DATA and having it recorded as whole-file is the tree's state
 * leaking into the draft. Prefers a region over the whole-object row, because
 * the narrower answer is the one that makes the scan cheaper.
 */
uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off)
{
	uint32_t k, best = v->n_node;

	for (k = 0; k < v->n_node; k++) {
		uint32_t n, j;

		if (v->node[k].obj != obj)
			continue;
		/*
		 * A ROW THAT OWNS ITS BYTES IS ASKED ABOUT THOSE BYTES, and
		 * not about its mask.
		 *
		 * Every piece row of a region carries that region's mask, so
		 * resolving it answers about all the runs at once and the first
		 * such row would claim every offset in the region. An entry row
		 * has the same fault: its mask is KOF_SCAN_ALL.
		 *
		 * WHERE the cursor should end up is a separate question, and
		 * not this function's - see the `narrow` argument to view_show.
		 * Answering it here, by refusing to name a piece row at all,
		 * fixed a search over the whole file and broke a search inside
		 * one region: the reader was thrown out to the object row
		 * because that was the only answer left.
		 */
		if (v->node[k].piece || v->node[k].ent) {
			if (file_off >= v->node[k].ent_off &&
			    file_off < v->node[k].ent_off +
				       v->node[k].ent_len)
				return k;
			continue;
		}
		if (!v->node[k].mask) {
			if (best == v->n_node)
				best = k;               /* the object row */
			continue;
		}
		/* A symbol half is not in the file, so no file offset is ever
		 * in it and the resolver has nothing to say about the bit. */
		if (v->node[k].mask & KOF_SCAN_SYM)
			continue;
		n = kof_scan_resolve_range(&v->obj[obj].ctx, v->node[k].mask,
					   v->probe);
		for (j = 0; j < n; j++)
			if (file_off >= v->probe[j].off &&
			    file_off < v->probe[j].off + v->probe[j].len)
				return k;
	}
	return best;
}

static void view_show(struct view *v, uint32_t obj, uint64_t file_off,
		      int narrow);

/*
 * Jump to where a DECLARATION sits, whichever space that is in.
 *
 * A marker scoped to a symbol half has offsets into the built block, so the
 * file-offset jump below cannot be given one: view_unmap would read it as a
 * distance into the file and land on whatever region sits there - UNCLAIMED,
 * on the sample this was found with - which is a real address showing real
 * bytes, and none of them the marker's. So the tree moves to that half's row
 * first and the offset is used directly, the way view_map already treats a
 * symbol row.
 */
void view_show_in(struct view *v, uint32_t obj, uint8_t sym,
			 uint64_t off, int narrow)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t r, row;
	uint32_t k;

	/*
	 * AND `obj` IS PASSED ON, because the caller is not always standing in
	 * the object it names.
	 *
	 * This used to drop it here and let view_show resolve the offset in
	 * whatever row was selected. A marker declared against the PARENT,
	 * clicked while the reader was inside the :norm view, was then placed
	 * at the same number in the view - a real address holding real bytes,
	 * and none of them the marker's. That is the same address-space
	 * confusion the symbol half below exists to avoid, arriving by object
	 * rather than by space.
	 */
	if (!sym) {
		view_show(v, obj, off, narrow);
		return;
	}
	for (k = 0; k < v->n_node; k++)
		if (v->node[k].obj == obj && v->node[k].sym == sym)
			break;
	if (k >= v->n_node)
		return;                 /* this object has no such half */
	goto_node(v, k);
	/* The row has extents now, so a block offset places in it the same way
	 * a file offset places in a region. */
	r = view_unmap(v, off);
	if (r == KGENOME_BROKEN)
		return;
	row = r / per;
	v->rgn_at = row > JUMP_LEAD ? (row - JUMP_LEAD) * per : 0;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

void view_show_decl(struct view *v, const struct decl *d, uint64_t off)
{
	view_show_in(v, d->obj, sym_which_of(d->sym), off, 1);
}

static void view_show(struct view *v, uint32_t obj, uint64_t file_off,
		      int narrow)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t r, row;
	uint32_t best = node_at(v, obj, file_off);

	/*
	 * THE TREE MOVES TO THE ROW THAT HOLDS THE OFFSET, ALWAYS - not only
	 * when the row it is on cannot reach it.
	 *
	 * This used to run only after view_unmap had already FAILED, and that
	 * is the bug: when the current row could reach the offset, the hex pane
	 * scrolled to the bytes and the tree stayed where it was. Clicking a
	 * marker on the status bar while the whole-object row was selected did
	 * exactly that - the bytes appeared, and the region containing them was
	 * never selected, so the object panel said nothing about where the
	 * reader had just landed.
	 *
	 * The whole-object row reaches every offset in the object, so the
	 * failure path could not fire for it: the one row that most needs
	 * narrowing was the one row that never got it.
	 *
	 * node_at already prefers a REGION over the object row - "the narrower
	 * answer is the more useful place to land", which was the intent here
	 * all along - so asking it unconditionally is what makes the two jump
	 * paths agree. view_show_in does the same for a symbol half, and this
	 * is now the same behaviour for a file offset: one answer to "take me
	 * there", whether the caller came from the strings table or from the
	 * status bar.
	 *
	 * Guarded on best != sel_node, so a jump inside the row already
	 * selected costs nothing and does not redraw the tree.
	 */
	/*
	 * A SEARCH DOES NOT MOVE THE READER, AND A MARKER CLICK DOES.
	 *
	 * They are two different asks and this used to answer both the same
	 * way, which broke whichever one was not being looked at:
	 *
	 *   narrow  clicking a marker in the strings table or on the status
	 *           bar means "take me to it", and the narrowest region
	 *           holding it is the useful place to land. Keeping the cursor
	 *           put there left the bytes on screen with the panel still
	 *           describing somewhere else.
	 *   not     a SEARCH is asked from a row the reader chose. Narrowing
	 *           then throws them out of it: searching a whole file landed
	 *           the cursor in the first run of code, and - once that was
	 *           "fixed" by refusing to name a run at all - searching
	 *           INSIDE one region threw them out to the whole file. Both
	 *           are the same mistake, made in opposite directions.
	 *
	 * So a search stays wherever it already is, as long as that row can
	 * show the offset; view_unmap answers exactly that. When it cannot -
	 * a hit in another region with the scope set to the whole object - the
	 * tree moves, because the alternative is a hit that cannot be looked
	 * at.
	 */
	/*
	 * Staying put is only an option while the row the reader chose is in
	 * the object being asked about; otherwise "where they already are" is
	 * the wrong file.
	 */
	if (!narrow && v->node[v->sel_node].obj == obj &&
	    view_unmap(v, file_off) != KGENOME_BROKEN)
		best = v->sel_node;
	/*
	 * Through goto_node, which is the one place that knows what moving
	 * between rows costs. Open-coded here, it saved the old row's place
	 * and selected the new one and did NOT rebuild the marker list when
	 * the move crossed into another object - so the panel kept listing the
	 * previous object's markers beside the new object's bytes.
	 */
	if (best < v->n_node)
		goto_node(v, best);
	r = view_unmap(v, file_off);
	if (r == KGENOME_BROKEN)
		return;
	row = r / per;
	v->rgn_at = row > JUMP_LEAD ? (row - JUMP_LEAD) * per : 0;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}
