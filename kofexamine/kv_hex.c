#define _GNU_SOURCE
#include "kv.h"


void draw_hex(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	int top = hex_top(), bot = hex_last();
	int col = TREE_W + 3;
	int per = (g_cols - col - 12) / 4;
	int row;
	uint64_t at = v->rgn_at;
	/*
	 * WHERE THE BYTES COME FROM, and it is not always the object.
	 *
	 * A symbol row draws the KSYM block, which is built rather than read
	 * out of the file, so the pane is pointed at that buffer instead. Held
	 * as one pointer rather than branched on per byte: the pane reads it
	 * three times per column and a test repeated there is a test that can
	 * be forgotten in one of the three.
	 *
	 * `sym` also turns the HIGHLIGHTING off. hit_kind and decl_kind take
	 * FILE offsets - a marker's occurrences, a declared string's hits - and
	 * the offsets here are into the block, so asking them would light bytes
	 * that mean nothing: the highlight would be at the same numeric offset
	 * as a real hit somewhere entirely unrelated.
	 */
	uint64_t base_n = ob->buf.n;
	const uint8_t *base = ob->buf.p;
	int sym = sym_view(v);

	if (sym)
		base = sym_block(v, &base_n);
	if (!base)
		base_n = 0;

	if (per > 16)
		per = 16;
	if (per < 4)
		per = 4;
	v->per = per;

	for (row = top; row <= bot; row++) {
		uint64_t run = 0, off = view_map(v, at, &run);
		int k;

		/*
		 * Overwrite, then clear the tail - not clear, then write.
		 *
		 * A hex row fills its width, so writing over the old one leaves
		 * nothing to erase in front of it. Erasing first put every row
		 * of the pane through a blank state before its bytes arrived,
		 * and on a terminal that ignores synchronized output that blank
		 * is on screen: holding page-down strobed the whole pane.
		 */
		out_at(o, row, col);
		if (at >= v->rgn_len) {
			out_str(o, "\033[K");
			continue;
		}
		out_fmt(o, A_LOC "%08llx" A_OFF "  ",
			(unsigned long long)off);
		for (k = 0; k < per; k++) {
			if (at + (uint64_t)k >= v->rgn_len) {
				out_str(o, "   ");
				continue;
			}
			/* A run ending mid line is an extent boundary, marked
			 * because a marker written across one can never match:
			 * the matcher walks each extent on its own. */
			if ((uint64_t)k == run && k)
				out_str(o, A_WARN "|" A_OFF);
			else
				out_str(o, " ");
			{
				uint64_t fo = view_map(v, at + (uint64_t)k, 0);
				uint8_t bv = fo < base_n ? base[fo] : 0;
				/* hit_kind compares spaces itself now, so an
				 * engine hit inside a symbol record lights in
				 * the row that shows it. */
				int h = hit_kind(v, fo);

				/*
				 * decl_kind runs on a symbol row too.
				 *
				 * It used to be gated off there, from before a
				 * declaration recorded WHICH space its offsets
				 * were in: a block offset read as a file offset
				 * would have lit an unrelated byte at the same
				 * number. It records that now and compares only
				 * markers from the same space, so the gate is
				 * what stops a marker taken from SYM_EXP from
				 * being lit in the very row it was taken from.
				 *
				 * hit_kind stays gated: those are the engine's
				 * hits, which are file offsets and have no
				 * meaning here.
				 */
				/*
				 * The event panel's colour is asked for with
				 * the REGION offset, not the file offset the
				 * others use: its extents are offsets into the
				 * record, and for an event node the region IS
				 * the record - one object, no extents to map
				 * through. evt_live is false for every other
				 * kind of node, which is what keeps that
				 * equality from having to be checked here.
				 */
				const char *ec = evt_byte_colour(v,
							at + (uint64_t)k);
				const char *pl;

				out_str(o, in_sel(v, at + (uint64_t)k) ? A_SELB :
					(pl = mtn_lit_at(v, at + (uint64_t)k)) ? pl :
					h ? (h == 1 ? A_HIT1 : A_HIT2)
					  : ec ? ec
					  : decl_kind(v, fo) ? A_HIT3
					  : sym ? sym_byte_colour(base, (uint32_t)base_n, fo)
					  : byte_colour(bv));
				out_fmt(o, "%02X", bv);
				out_str(o, A_OFF);
			}
		}
		out_str(o, "  ");
		for (k = 0; k < per && at + (uint64_t)k < v->rgn_len; k++) {
			uint64_t fo = view_map(v, at + (uint64_t)k, 0);
			uint8_t c = fo < base_n ? base[fo] : 0;
			int h = hit_kind(v, fo);
			const char *ec = evt_byte_colour(v, at + (uint64_t)k);
			const char *pl;
			char glyph;

			out_str(o, in_sel(v, at + (uint64_t)k) ? A_SELB :
				(pl = mtn_lit_at(v, at + (uint64_t)k)) ? pl :
				h ? (h == 1 ? A_HIT1 : A_HIT2)
				  : ec ? ec
				  : decl_kind(v, fo) ? A_HIT3
				  : sym ? sym_byte_colour(base, (uint32_t)base_n, fo)
				  : byte_colour(c));
			/*
			 * ONE CELL, ONE BYTE, AND NO INTERPRETATION.
			 *
			 * The NUL halves of a UTF-16 script block were drawn as
			 * spaces here for a while, so the column read "I E X"
			 * instead of "I.E.X." - easier to read, and wrong for
			 * this pane. Some AMSI submissions carry a PE, whose
			 * header is mostly NULs and is not text at all, and a
			 * dump that decides which of its zeros are worth
			 * drawing is a dump that can no longer be checked
			 * against the file.
			 *
			 * The reading belongs one pane down: the event panel
			 * renders the gathered content as text, says when it
			 * collapsed pairs, and is allowed to because it is a
			 * rendering. This is the ground truth, and its whole
			 * value is that it never flatters the bytes.
			 */
			glyph = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
			out_fmt(o, "%c", glyph);
			out_str(o, A_OFF);
		}
		out_str(o, "\033[K");
		at += (uint64_t)per;
	}
	/* Only when the rows leave the column free. On a narrow terminal the
	 * hex reaches the edge, and a bar drawn over the last ASCII column
	 * would be a scrollbar that eats the thing it is scrolling. */
	if (col + 8 + 2 + per * 3 + 2 + per <= g_cols)
		kv_scrollbar(o, g_cols, top, bot, v->rgn_at, v->rgn_len,
			  (uint64_t)(bot - top + 1) * (uint64_t)per);
}

/* The composed name a scan would print for this module, less the target. */
const char *touch_colour(const struct kof_touch *t)
{
	return t->fired                        ? A_BAD :
	       t->kind == KOF_TOUCH_ELSEWHERE  ? A_LOC :
	       t->kind == KOF_TOUCH_INELIGIBLE ? A_DIM : A_WARN;
}

/*
 * Which module opened an object, coloured by what that module is.
 *
 * An EXECUTABLE PACKER is red. Its whole purpose is that the file cannot be
 * read as it stands, and there is no ordinary reason to ship a program that
 * way; that it was recognised at all is a statement about the object.
 *
 * A DECOMPRESSOR, ARCHIVE OR DOCUMENT PARSER is yellow. It says the object
 * arrived inside a container, which is how nearly all software arrives.
 *
 * The engine does not classify its unpackers - a module is only a kof_unpack
 * entry point and whatever name it gives itself through kof_debug - so the
 * split is made here, from that name. Unknown names take the quieter colour:
 * a module this list has not heard of is far more likely to be a new container
 * than a new packer, and guessing wrong towards red is the failure that trains
 * people to ignore the colour.
 */
void touch_head(const struct kof_touch *t, char *out, size_t cap)
{
	/*
	 * A SIMILARITY RULE SAYS SO IN ITS NAME, so the row does not say it
	 * again.
	 *
	 * The verdict beside this ends in "!Mutation" - see kverdict_name - and
	 * "structural" beside it is the same statement in a second vocabulary.
	 * The word is still right for a rule that declares neither markers nor
	 * blocks, which is what it was written for.
	 */
	const char *method = kof_touch_method(t);

	/* A rule that read the node graph declares no markers either, and
	 * "structural" would send a reader looking at the parse. */
	if (method)
		snprintf(out, cap, "%s", method);
	else if (t->mod && t->mod->n_block)
		out[0] = 0;
	else if (!t->n_str)
		snprintf(out, cap, "structural");
	else
		snprintf(out, cap, "%u/%u",
			 t->kind == KOF_TOUCH_INELIGIBLE ? t->n_present
							 : t->n_in_rgn,
			 t->n_str);
}



/*
 * Has this matcher a range worth naming.
 *
 * Holding markers is one way - the range is derived from where they are - and
 * being given one outright is the other. Only the first used to count, so a
 * matcher handed a range and no markers yet drew as having no range at all.
 */




/*
 * A new condition, inside the one that is selected when it has no expression of
 * its own to lose - which is how a gate gets its branches without a separate
 * "nest this" gesture: add a condition, give it the gate, then add the ones
 * that live under it.
 */
/*
 * Is matcher `m` offerable to condition `c`.
 *
 * One predicate rather than two copies of the same three tests: the list that
 * is shown and the code that acts on the choice used to filter differently -
 * the list hid the parent's matchers and the action did not - so the nth row of
 * the list and the nth matcher that passed the action's filter were different
 * matchers, and picking "2" quietly added 1.
 */
int cmatch_ok(struct view *v, uint32_t c, uint32_t m)
{
	if (cnd_uses(&v->ed.dr.cnd[c], m))
		return 0;
	/*
	 * Nor the ones its parent already tests: control only reaches a nested
	 * condition once the gate above it held, so repeating one of the gate's
	 * matchers inside is a search that has already been decided.
	 */
	if (v->ed.dr.cnd[c].parent >= 0 && cnd_uses(&v->ed.dr.cnd[v->ed.dr.cnd[c].parent], m))
		return 0;
	return 1;
}
