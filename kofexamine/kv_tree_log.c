#define _GNU_SOURCE
#include "kv.h"
#include "kv_tree_private.h"

/*
 * BUILD THE OBJECT WINDOW FOR AN EVENT LOG.
 *
 * obj[0] is the log itself, named KOFT-<system>-<arch> so the row says what
 * produced it rather than repeating the filename the title bar already shows.
 * obj[1..] are the events of the current window, one each, named with the
 * engine's own "//<n>" convention so tree_build nests them under the parent
 * without knowing anything about logs.
 *
 * The index in the name is the event's index IN THE FILE, not in the window -
 * a reader refers to event 40 000 by that number, and a row that renumbered
 * itself as the window moved would be unusable for exactly the thing a log is
 * read for.
 *
 * Each event's buf points INTO THE MAPPING at that record's own extent. Not a
 * copy, and not sizeof the struct: the on-disk length is the head plus this
 * record's own text, so a pane sized from the struct would show the next
 * record's opening bytes as this one's.
 */
/*
 * WHICH VERBS ARE IN THIS LOG, from the mapping and with no I/O.
 *
 * Every record's verb sits at a known offset in its head, and each record says
 * its own text length - so the whole file can be stepped through with pointer
 * arithmetic. A million events is a million additions and no syscalls, which
 * is the difference between asking this question at open and not asking it.
 *
 * Deliberately NOT done by reading records through kofevt_log_read: that
 * copies 512 bytes per event to look at two, and it is the same walk the
 * sparse index already knows how to do.
 */
void log_scan_verbs(struct view *v)
{
	const struct kofevt_log_hdr *h;
	const uint8_t *p, *end;

	v->log_verbs = 0;
	v->log_keep  = 0;
	v->log_events = 0;
	memset(v->log_count, 0, sizeof v->log_count);
	if (!v->log || !v->map)
		return;
	h = kofevt_log_header(v->log);
	if (h->head_size < offsetof(struct kof_evt, text_len) + 2u)
		return;

	p   = (const uint8_t *)v->map + h->hdr_size;
	end = (const uint8_t *)v->map + v->map_len;

	while (p + h->head_size <= end) {
		uint16_t verb = 0, tl = 0;

		memcpy(&verb, p + offsetof(struct kof_evt, verb), sizeof verb);
		memcpy(&tl, p + h->len_off, sizeof tl);
		/*
		 * A CONTINUATION IS NOT A KIND OF EVENT and must not appear in
		 * the filter menu. Offering "cont" as something to tick would
		 * invite a reader to hide the tails while keeping the heads,
		 * which is not a view of anything.
		 */
		if (verb != KOF_EVT_CONT) {
			v->log_events++;
			if (verb < 32u)
				v->log_count[verb]++;
		}
		if (verb < 32u && verb != KOF_EVT_CONT)
			v->log_verbs |= 1u << verb;
		if ((uint32_t)h->head_size + tl > h->rec_size)
			break;              /* the record contradicts itself */
		p += h->head_size + tl;
	}
	/* Everything shown until somebody narrows it. */
	v->log_keep = v->log_verbs;
}

/* Drop the previous window's objects and make object 0, the log itself. */
static void log_win_reset(struct view *v, const struct kofevt_log_hdr *h)
{
	uint64_t i;

	for (i = 0; i < v->n_obj; i++) {
		/*
		 * The buffers are the mapping and are not this loop's, but the
		 * kept answers ARE - see object.carve, which is heap and is
		 * kept so that returning to an object does not read it again.
		 */
		free(v->obj[i].carve);
		dash_drop(&v->obj[i]);
		memset(&v->obj[i], 0, sizeof v->obj[i]);
	}
	memset(v->pe_of, 0, sizeof v->pe_of);
	v->pe_at = 0;

	snprintf(v->obj[0].name, sizeof v->obj[0].name, "KOFT-%s-%s",
		 kof_evt_platform_name((uint8_t)h->platform),
		 kof_evt_arch_name((uint8_t)h->arch));
	snprintf(v->obj[0].label, sizeof v->obj[0].label, "%.48s",
		 v->obj[0].name);
	v->obj[0].buf   = kof_buf_make(v->map, v->map_len);
	v->obj[0].depth = 0;
}

/*
 * The child row of an AMSI submission that starts with "MZ": see the note at the call.
 * Returns the new object count.
 */
static uint32_t log_win_pe_row(struct view *v, const struct kofevt_log_hdr *h,
			       const struct object *o, uint64_t off, uint32_t len,
			       uint64_t id, uint64_t pe_bytes, uint32_t n)
{
		uint16_t oo = 0, cl = 0;
		const uint8_t *p8 = (const uint8_t *)v->map + off;

		memcpy(&oo, p8 + offsetof(struct kof_evt, off_object),
		       sizeof oo);
		memcpy(&cl, p8 + offsetof(struct kof_evt, content_len),
		       sizeof cl);
		if (cl >= 2u && oo != KOF_TEXT_NONE &&
		    (uint64_t)h->head_size + oo + 2u <= len &&
		    p8[h->head_size + oo] == 'M' &&
		    p8[h->head_size + oo + 1u] == 'Z') {
			struct object *c = &v->obj[n];

			memset(c, 0, sizeof *c);
			{
				/* Through a copy: the two names are
				 * fields of the same array, and
				 * snprintf may not read and write one
				 * object at once. */
				char pn[224];

				snprintf(pn, sizeof pn, "%.200s",
					 o->name);
				snprintf(c->name, sizeof c->name,
					 "%s//pe", pn);
			}
			/*
			 * NAMED NOW, FROM THE RECORD'S OWN PREFIX.
			 *
			 * It used to say "Img ?" until the row was
			 * clicked, because the image is only joined
			 * when it is picked - and a list where every
			 * carried file is a question mark until you
			 * open it is a list you have to open
			 * everything in.
			 *
			 * It does not need the join. A DOS header, a PE
			 * header and the machine word all sit in the
			 * first few hundred bytes, which is inside the
			 * record's own arena - so the format and the
			 * architecture are answerable from bytes that
			 * are already mapped.
			 *
			 * A THROWAWAY PARSE, and deliberately not kept:
			 * every SIZE it worked out is wrong, because it
			 * was given a prefix. What is taken from it is
			 * the two facts a prefix can answer honestly.
			 * The real parse happens on selection, against
			 * the whole image.
			 */
			{
				struct kof_obj_ctx tc;
				const struct kof_parser *tf;
				void *ti = NULL;
				kof_buf pre = kof_buf_make(
					p8 + h->head_size + oo, cl);

				memset(&tc, 0, sizeof tc);
				tf = kof_inspect_identify(pre, &tc,
							  &ti);
				if (tf)
					snprintf(c->label,
						 sizeof c->label,
						 "%llu Img %s-%s",
						 (unsigned long long)id,
						 kof_format_name(
							tc.format),
						 kof_arch_name(
							tc.arch));
				else
					snprintf(c->label,
						 sizeof c->label,
						 "%llu Img ?",
						 (unsigned long long)id);
				kof_inspect_free(tf, ti);
			}
			c->depth = 2;
			c->ctx.obj_size = pe_bytes;
			v->pe_of[n] = n - 1u;
			v->log_idx[n] = id;
			n++;
		}
	return n;
}

void log_window(struct view *v)
{
	const struct kofevt_log_hdr *h;
	uint64_t i;
	uint32_t n = 1;

	if (!v->log)
		return;
	h = kofevt_log_header(v->log);

	log_win_reset(v, h);

	for (i = v->log_first; i < v->log_n && n + 1u < MAX_OBJ; i++) {
		struct object *o = &v->obj[n];
		uint64_t off = 0, end;
		/*
		 * The event's OWN record number, taken before the chunks
		 * behind it are absorbed. `i` walks to the end of the span, so
		 * reading the id off it afterwards named the last chunk - an
		 * event five records in was labelled eleven.
		 */
		uint64_t id = i;
		uint64_t pe_bytes = 0;
		uint32_t len = 0;
		uint16_t vb = 0;

		if (!kofevt_log_extent(v->log, i, &off, &len))
			break;
		if (off + len > v->map_len)
			break;
		/*
		 * AND THAT THE RECORD IS ACTUALLY A struct kof_evt.
		 *
		 * The reads below reach into the mapping at FIXED offsets -
		 * verb at 32, content_len further in - while the only thing
		 * checked here was that the record fits the file. The log is
		 * record-agnostic on purpose: kofevt_log_open takes head_size
		 * from the file and asks only that it is non-zero, no larger
		 * than the record and big enough to hold the length field. A
		 * log declaring a head of two bytes is therefore accepted, and
		 * a two-byte record at the end of the mapping would have had
		 * its `verb` read thirty bytes past it.
		 *
		 * KOF_EVT_HEAD is the fixed part of the record, so one test
		 * covers every field these loops name.
		 */
		if (len < KOF_EVT_HEAD)
			break;

		memcpy(&vb, (const uint8_t *)v->map + off +
			    offsetof(struct kof_evt, verb), sizeof vb);

		/*
		 * A CONTINUATION GETS NO ROW OF ITS OWN.
		 *
		 * It is the tail of the record in front of it, not an event -
		 * see KOF_EVT_CONT. Listed separately it read as a second thing
		 * happening, named "cont", with a fragment of somebody else's
		 * script in it. Reached here it means its parent was filtered
		 * out or the window began in the middle of a chain; either way
		 * there is nothing for it to be the tail of on this screen.
		 */
		if (vb == KOF_EVT_CONT)
			continue;

		/*
		 * FILTERED HERE, so the window holds LOG_WIN events a reader
		 * asked to see rather than LOG_WIN records of which most are
		 * hidden. Filtering after the window was filled would leave a
		 * panel of three rows and no way to reach the fourth match.
		 */
		if (vb < 32u && v->log_keep && !(v->log_keep & (1u << vb)))
			continue;

		/*
		 * THE CHUNKS BEHIND IT BELONG TO THIS ROW.
		 *
		 * They sit immediately after it in the file, so the event's
		 * bytes are one contiguous range and the hex pane can show the
		 * whole thing - head, content, and every continuation - as the
		 * real file bytes they are, with nothing synthesised.
		 */
		end = off + len;
		/*
		 * The submission's total size, summed while the chunks are
		 * walked anyway. The child row needs it BEFORE anything is
		 * materialised - a tree row showing "0 bytes" beside an image
		 * is a row that says the thing is empty.
		 */
		{
			uint16_t cl0 = 0;

			memcpy(&cl0, (const uint8_t *)v->map + off +
				     offsetof(struct kof_evt, content_len),
			       sizeof cl0);
			pe_bytes = cl0;
		}
		while (i + 1u < v->log_n) {
			uint64_t coff = 0;
			uint32_t clen = 0;
			uint16_t cvb = 0;

			if (!kofevt_log_extent(v->log, i + 1u, &coff, &clen))
				break;
			if (coff + clen > v->map_len || clen < KOF_EVT_HEAD)
				break;
			memcpy(&cvb, (const uint8_t *)v->map + coff +
				     offsetof(struct kof_evt, verb),
			       sizeof cvb);
			if (cvb != KOF_EVT_CONT)
				break;
			{
				uint16_t ccl = 0;

				memcpy(&ccl, (const uint8_t *)v->map + coff +
					     offsetof(struct kof_evt,
						      content_len),
				       sizeof ccl);
				pe_bytes += ccl;
			}
			end = coff + clen;
			i++;
		}

		/*
		 * The parent's name is bounded explicitly rather than left to
		 * the compiler to worry about: it is "KOFT-<system>-<arch>",
		 * which is short, but sizeof says 256 and a %s of that plus an
		 * index cannot be proven to fit. Truncating the PARENT half
		 * would break the "//" nesting tree_build reads, so the bound
		 * is on the part that can afford it.
		 */
		snprintf(o->name, sizeof o->name, "%.64s//%llu",
			 v->obj[0].name, (unsigned long long)id);
		o->depth = 1;
		o->buf   = kof_buf_make((const uint8_t *)v->map + off,
				        (size_t)(end - off));
		v->log_idx[n] = id;

		/*
		 * The row's text comes from the RECORD, through the same
		 * kof_evt_label a TUI or a dashboard would use - so a row here
		 * and a row there cannot describe the same event differently.
		 *
		 * The record is copied out of the mapping rather than cast
		 * from it: a log written by a build with a shorter head has its
		 * text at a different offset, and the copy is bounded by what
		 * this build's struct is.
		 */
		{
			struct kof_evt rec;

			memset(&rec, 0, sizeof rec);
			memcpy(&rec, (const uint8_t *)v->map + off,
			       len < sizeof rec ? len : sizeof rec);
			kof_evt_label(&rec, id, o->label, sizeof o->label);
		}
		n++;

		/*
		 * AN EXECUTABLE INSIDE THE EVENT GETS A ROW OF ITS OWN.
		 *
		 * Tested on the RECORD's own first two content bytes, straight
		 * out of the mapping - two bytes, no join, no allocation. The
		 * expensive part is materialising the image, and that waits
		 * until somebody selects the row.
		 *
		 * "MZ" and nothing cleverer. A submission either begins with a
		 * DOS header or it does not; searching the middle of a script
		 * for the letters would offer a child row for every PowerShell
		 * one-liner that happens to contain them.
		 */
		if (n + 1u < MAX_OBJ && vb == KOF_EVT_AMSI_SCAN)
			n = log_win_pe_row(v, h, o, off, len, id, pe_bytes, n);

		if (n - 1u >= LOG_WIN)
			break;
	}
	/*
	 * Where the next page starts. Taken from the walk rather than computed
	 * from the window's size, because the two disagree the moment a filter
	 * hides a record or a chain of chunks is folded into one row.
	 */
	v->log_next = (i < v->log_n) ? i + 1u : v->log_n;
	v->n_obj = n;
}

/*
 * Move the window so that event `want` is in it, and say whether anything
 * moved.
 *
 * The window is placed so the wanted event is not on its very edge where
 * possible - stepping one row past the end otherwise reloads on every
 * keystroke, which is the difference between scrolling and thrashing.
 */
/*
 * MOVE THE WINDOW TO START AT `first`, and say whether it moved.
 *
 * A WALK, NOT A JUMP, and the difference is the bug this replaced. The old one
 * CENTRED the window on the record asked for - reasonable for "go to event
 * 90000", wrong for "the reader pressed Down at the bottom of the list": it
 * put the next record in the middle of a fresh window, so stepping off the end
 * moved the selection forty-eight events BACKWARDS, into the middle of what
 * had just been read.
 *
 * Turning a page starts the page where the last one ended. That is the only
 * behaviour that composes: a reader holding Down walks the log once, in order,
 * and never sees the same event twice.
 */
int log_window_from(struct view *v, uint64_t first)
{
	if (!v->log || !v->log_n)
		return 0;
	if (first >= v->log_n)
		return 0;
	if (first == v->log_first)
		return 0;

	v->log_first = first;
	log_window(v);
	return 1;
}
