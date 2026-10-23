#define _GNU_SOURCE
#include "kv.h"



/* Fill the scratch from a declaration and give it the caret. */
void decl_edit_open(struct view *v, uint32_t i)
{
	struct decl *d = &v->ed.dr.decl[i];

	if (i >= v->ed.dr.n_decl)
		return;
	if (!decl_text_editable(d)) {
		say_note(&v->ed, "String %u is not text - edit it as hex", i + 1u);
		return;
	}
	if (d->hex) {
		if (d->hexs[0]) {
			kof_hex_respace(d->hexs, v->ed.dr.sedit, sizeof v->ed.dr.sedit);
		} else {
			uint32_t k;
			size_t n = 0;

			for (k = 0; k < d->nbytes && n + 4u < sizeof v->ed.dr.sedit; k++)
				n += (size_t)snprintf(v->ed.dr.sedit + n,
						      sizeof v->ed.dr.sedit - n,
						      k ? " %02X" : "%02X",
						      d->bytes[k]);
		}
	} else {
		/*
		 * TAB, NEWLINE AND RETURN AS ESCAPES, because the box is ONE
		 * LINE. A marker that crosses a line is declarable now, and a
		 * raw newline dropped into a single-line field is a character
		 * the reader can neither see nor delete. Spelled the way the
		 * generated source spells them, so what is on screen is what is
		 * in the file; decl_edit_commit reads them back.
		 *
		 * A backslash is escaped too, or a marker holding the two
		 * characters "\" and "n" would come back as a newline.
		 */
		uint32_t k;
		size_t n = 0;

		for (k = 0; k < d->nbytes &&
			    n + 2u < sizeof v->ed.dr.sedit; k++) {
			uint8_t c = d->bytes[k];
			const char *esc = c == '\t' ? "\\t" :
					  c == '\n' ? "\\n" :
					  c == '\r' ? "\\r" :
					  c == '\\' ? "\\\\" : NULL;

			if (esc) {
				v->ed.dr.sedit[n++] = esc[0];
				v->ed.dr.sedit[n++] = esc[1];
			} else {
				v->ed.dr.sedit[n++] = (char)c;
			}
		}
		v->ed.dr.sedit[n] = 0;
	}
	v->ed.dr.sedit_off = 0;
	v->ed.dr.sel_decl = i;
	v->edit = ED_STR + (int)i;
}




/*
 * WHAT THE RECORD IN HAND IS ON THE TARGET AXIS, and which of its regions the
 * box is showing. EVT_TARGET_NONE when nothing can be written about it.
 *
 * THE CLIENT'S QUESTION AND NOT THE ENGINE'S, which kofsig.h states where
 * KOF_EVT_AMSI is defined: a verb is libkoforbit's vocabulary, a target is the
 * engine's, they are not one axis, and whoever holds the record is the only
 * side that knows both. This program holds the record.
 *
 * THEY ARE NOT ONE TO ONE AND CANNOT BE. KOF_EVT_PROC_START is verb 1, and 1
 * on the target axis is KOF_FMT_ELF. What a rule about a process start is
 * written against is not the start event as bytes, it is the PROCESS - pid,
 * parent, image, command line - and that record already exists as KOF_EVT_PROC
 * with a CMDLINE region for exactly the text this box is showing. So the verbs
 * whose subject is a process map there.
 *
 * WHAT IT FIXES. The draft used to be seeded from the OBJECT, and an event
 * node has no format at all - log_window builds it straight out of the mapping
 * and never parses it - so every string declared out of a record came back
 * KOF_FMT_UNKNOWN. That is not a missing label. Raw is a real target: the rule
 * it writes is offered every unclaimed byte the scanner meets, and is never
 * offered the event it was written from.
 *
 * A VERB THIS DOES NOT NAME GETS NOTHING, deliberately. A file event names a
 * path and a network event names an address - facts about something that is
 * not a process - and neither has a record shape on the target axis yet.
 * Refusing is honest; the nearest target would be a rule about something else.
 */
uint8_t evt_decl_target(const struct view *v, uint32_t *mask)
{
	int meta[64], warn[64], nm = 0, nw = 0, box;
	char fname[32], fval[512];
	uint8_t t;

	if (mask) *mask = 0;
	if (!evt_have_rec(v))
		return EVT_TARGET_NONE;
	switch (v->evt.verb) {
	case KOF_EVT_AMSI_SCAN:
		t = KOF_EVT_AMSI;
		break;
	case KOF_EVT_PROC_START:
	case KOF_EVT_PROC_STOP:
	case KOF_EVT_PROC_INFO:
		t = KOF_EVT_PROC;
		break;
	default:
		return EVT_TARGET_NONE;
	}

	/*
	 * AND THE REGION BIT, from the same classifier the drawer uses, so the
	 * field the reader dragged text out of is the field this names.
	 *
	 * The BIT and not a word. What the row shows is derived from it by the
	 * editor (rng_name_of), so a region word spelled in this file would be a
	 * second copy, and the one nothing checks.
	 */
	box = evt_zones(v, meta, &nm, warn, &nw);
	if (box >= 0 && kof_evt_field(&v->evt, (unsigned)box, fname,
				      sizeof fname, fval, sizeof fval)) {
		uint32_t bit = 0;

		if (t == KOF_EVT_AMSI && !strcmp(fname, "object"))
			bit = KOF_SCAN_AMSI_OBJ;
		else if (t == KOF_EVT_PROC && !strcmp(fname, "cmdline"))
			bit = KOF_SCAN_PROC_CMDLINE;
		if (bit && mask)
			*mask = bit;
	}
	return t;
}

/*
 * Declare a marker from the event box's selection.
 *
 * Not decl_add with a flag: that one takes a range of the HEX selection and
 * reads the object's bytes through view_map. This takes characters out of a
 * rendering, and the two differ in the one way that matters - `at` is not
 * known here. A UTF-16 submission's characters are two bytes each, its padding
 * has been trimmed, and past the record's own arena the text came from
 * continuation records that sit elsewhere in the object. So the marker is
 * recorded as one carried from a sample rather than found at an offset in it,
 * which is a state struct decl already has.
 */
void decl_add_text(struct view *v, const char *text, size_t n,
			  int from_evt)
{
	struct decl *d;

	if (!text || !n || v->ed.dr.n_decl >= MAX_DECL)
		return;
	d = &v->ed.dr.decl[v->ed.dr.n_decl];
	memset(d, 0, sizeof *d);
	d->len = (uint32_t)n;
	d->bytes = malloc(n);
	if (!d->bytes)
		return;
	memcpy(d->bytes, text, n);
	d->nbytes = d->len;
	d->hex = 0;
	/*
	 * THE ENCODING IS KNOWN, NOT GUESSED.
	 *
	 * The box shows a rendering, and the view already worked out what it
	 * was rendering when it built it - see evt_wide. So a marker taken from
	 * a UTF-16 submission is declared wide without anyone being asked, and
	 * ksigbuilder widens it at build time.
	 */
	d->wide = v->evt_wide;
	/*
	 * SUBSTRING - see the note in decl_add on why TOKEN is not a default.
	 *
	 * Here it is not even a question: what was dragged out of the box is a
	 * run of TEXT the reader picked by eye, so its edges are wherever the
	 * pointer stopped and a boundary rule over them is a claim nobody made.
	 * decl_add can look at the bytes either side and decide; this cannot,
	 * because the rendering it came from is not the object.
	 */
	d->fullword = KOF_WORD_SUBSTRING;
	d->obj = v->node[v->sel_node].obj;
	d->at = KGENOME_BROKEN;
	/*
	 * THE TARGET AND THE REGION, TAKEN FROM THE RECORD - see
	 * evt_decl_target. Seeded here rather than left to
	 * draft_seed_target because that one answers for the OBJECT under the
	 * cursor, which is the right answer for the image a record carries
	 * and the wrong one for the record itself.
	 *
	 * Only for text out of the event box. The decode box hands over the
	 * plaintext of something in the bytes pane, which may be the carried
	 * PE - a target this has no business overriding.
	 */
	{
		uint32_t rm = 0;
		uint8_t tgt = from_evt ? evt_decl_target(v, &rm)
				       : EVT_TARGET_NONE;

		if (tgt != EVT_TARGET_NONE && !v->ed.dr.fmt_mask)
			v->ed.dr.fmt_mask = 1u << tgt;
		d->mask = d->mask0 = rm;
		/* The column's word, from the one function that makes them -
		 * the same call every other declaration path ends with. */
		if (rm)
			rng_name_of(kof_parser_of(tgt), rm, d->rgn,
				    sizeof d->rgn);
		else
			snprintf(d->rgn, sizeof d->rgn, "%s", "OBJDATA");
	}
	v->ed.dr.n_decl++;
	v->ed.dr.sel_decl = v->ed.dr.n_decl - 1u;
	/*
	 * LOOKED FOR AT ONCE, and said so when it is not there.
	 *
	 * Nothing downstream asks whether a declared string is actually IN the
	 * object, so a string that is nowhere still gets a matcher and a
	 * condition - and never matches. The failure has no symptom at all.
	 *
	 * It cannot bite a marker dragged out of the hex pane, because those
	 * bytes came from the object. It bites every time on text this program
	 * DECODED: the plaintext of a base64 run does not exist in the file,
	 * only the base64 does. Locating it here costs one search per
	 * declaration and turns that into a sentence the reader sees while
	 * they are still looking at what they declared.
	 */
	draft_seed_target(v);
	decl_locate(&v->ed, d);
	if (d->at == KGENOME_BROKEN) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Declared, but these bytes are not in this object - "
			 "a rule on them cannot fire here");
		return;
	}
	snprintf(v->act_msg, sizeof v->act_msg,
		 "declared %u character(s)%s", (unsigned)n,
		 v->evt_wide ? " as a wide string" : "");
	v->act_ok = 1;
}

void decl_add(struct view *v, int hex)
{
	struct node *n = &v->node[v->sel_node];
	struct decl *d;
	uint64_t lo, hi, k;
	uint32_t i = 0, g;

	if (v->sel_a == KGENOME_BROKEN || v->ed.dr.n_decl >= MAX_DECL)
		return;

	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;

	d = &v->ed.dr.decl[v->ed.dr.n_decl];
	memset(d, 0, sizeof *d);
	d->len = (uint32_t)(hi - lo + 1u);
	d->bytes = malloc(d->len);
	if (!d->bytes)
		return;
	{
		/* From the view, not from the object: on a symbol row these
		 * offsets are into the built block. See view_bytes. */
		uint64_t bn = 0;
		const uint8_t *bp = view_bytes(v, &bn);

		for (k = lo; k <= hi; k++) {
			uint64_t f = view_map(v, k, 0);

			d->bytes[i++] = (bp && f < bn) ? bp[f] : 0;
		}
	}
	d->nbytes = d->len;
	d->hex = hex;
	/*
	 * THE DEFAULT IS READ OFF THE BYTES THEMSELVES, not assumed.
	 *
	 * It was KOF_WORD_TOKEN unconditionally, and the comment that stood
	 * here said TOKEN "breaks on whitespace and on nothing else, so a
	 * marker surrounded by quotes, brackets or dollars is still whole".
	 * That is the opposite of what TOKEN does. kof_str_abuts counts EVERY
	 * non-space neighbour as continuing the run, so a marker with a "(" or
	 * a quote next to it is NOT whole and cannot match - and a selection
	 * dragged out of source almost always has one.
	 *
	 * Measured on the first rule written this way:
	 *
	 *     @eval(@gzuncompress(@x(@base64_decode($m[1]),$k)));
	 *                          ^ the byte after the marker
	 *
	 * The generated signature was correct in every other respect and hit
	 * nothing, which is the failure this tree calls out everywhere else: a
	 * rule that silently never matches looks exactly like one that works.
	 *
	 * So the neighbours are looked at, and there are THREE answers because
	 * there are three modes - this used to give two, and the one it left
	 * out is the common case in a script.
	 *
	 *   TOKEN      both neighbours are whitespace or the edge. The marker
	 *              is a whole whitespace-delimited run - "<?php" is the
	 *              case it was written for.
	 *   FULLWORD   both neighbours are non-word bytes or the edge. The
	 *              marker is a whole NAME: punctuation beside it is a
	 *              boundary, whitespace beside it is too. This is what a
	 *              selection dragged out of source usually is -
	 *
	 *                  @eval(@gzuncompress($m));
	 *                        ^--- gzuncompress ---^
	 *
	 *              bounded by "(" on one side and "(" on the other, so
	 *              TOKEN cannot hold and FULLWORD can.
	 *   SUBSTRING  a neighbour is a word byte, so the marker is a FRAGMENT
	 *              of a longer name and no boundary describes it.
	 *
	 * THE STRICTEST ONE THAT HOLDS, and the ladder is sound because the
	 * modes nest: whitespace IS a non-word byte, so anything TOKEN accepts
	 * FULLWORD accepts too, and anything FULLWORD accepts SUBSTRING
	 * accepts. Going up the ladder can only ever NARROW what the marker
	 * matches, never widen it - so a default picked here cannot turn a rule
	 * into one that fires on more than the researcher asked for, and it
	 * cannot fail to match where it was taken from.
	 *
	 * The mode is still a field on the row and the researcher still
	 * overrides it; what changed is that the offer is now the tightest
	 * true one rather than the loosest.
	 */
	{
		uint64_t bn2 = 0;
		const uint8_t *bp2 = view_bytes(v, &bn2);
		uint64_t after = hi + 1u;
		int spaced = 1, worded = 0;

		if (lo > 0) {
			uint64_t f = view_map(v, lo - 1u, 0);

			if (bp2 && f < bn2) {
				if (!kof_is_space_byte(bp2[f]))
					spaced = 0;
				if (kof_is_word_byte(bp2[f]))
					worded = 1;
			}
		}
		if (after < v->rgn_len) {
			uint64_t f = view_map(v, after, 0);

			if (bp2 && f < bn2) {
				if (!kof_is_space_byte(bp2[f]))
					spaced = 0;
				if (kof_is_word_byte(bp2[f]))
					worded = 1;
			}
		}
		d->fullword = spaced ? KOF_WORD_TOKEN
			    : worded ? KOF_WORD_SUBSTRING
				     : KOF_WORD_FULLWORD;
	}
	d->obj = n->obj;
	/*
	 * The region the bytes are in, looked up from the bytes.
	 *
	 * It used to be whatever the tree cursor was on, which is a different
	 * fact: the hex pane follows a marker into DATA while the cursor stays
	 * on the object row, and a string taken there was recorded as
	 * whole-file even though the status bar named its region correctly one
	 * line below. Wanting to search the whole file is still sayable - the
	 * matcher's own range setting says it - but it should be said, not
	 * inherited from where a cursor happened to be.
	 *
	 * The object row remains the answer when nothing narrower claims the
	 * offset, and the engine has a bit for that: storing zero made "whole"
	 * the absence of a region rather than one of them, which is why a range
	 * built on it contained nothing.
	 */
	if (n->sym) {
		/*
		 * THE ROW IS THE ANSWER, and no lookup is wanted.
		 *
		 * This went through node_at like every other row, which is a
		 * FILE-offset lookup - and view_map on a symbol row returns an
		 * offset into the built block, so whichever region happened to
		 * sit at that distance from zero won. A name taken out of
		 * SYM_EXP at block offset 0x54 was declared HEADERS in libz
		 * and UNCLAIMED in a shorter-headered sample, neither of which
		 * contains the bytes.
		 *
		 * The lookup exists because the hex pane can follow a marker
		 * into another region while the tree cursor stays put, so the
		 * cursor is not evidence. On a symbol row the pane cannot go
		 * anywhere else - the block is one contiguous run - so the row
		 * IS the evidence, and it now carries the scan target to say
		 * so.
		 */
		char lab[sizeof n->label];

		/* Through a local: both point into `struct view`, so the
		 * compiler cannot prove the copy does not overlap itself. */
		snprintf(lab, sizeof lab, "%s", n->label);
		d->mask = d->mask0 = n->mask;
		snprintf(d->rgn, sizeof d->rgn, "%.23s", lab);
	} else {
		/*
		 * Mapped first: `lo` counts bytes along the region being
		 * looked at, not bytes into the file, and the two differ by
		 * the region's start. Handing the view coordinate to a
		 * file-offset lookup named whichever region happens to sit at
		 * that distance from zero - CODE for a string plainly inside
		 * DATA - and then sent the pane there.
		 */
		uint64_t at = view_map(v, lo, 0);
		uint32_t rk = at == KGENOME_BROKEN ? v->n_node
					       : node_at(v, n->obj, at);
		const struct node *rn = rk < v->n_node ? &v->node[rk] : n;
		/*
		 * A SCRIPT'S REGIONS ARE FOR READING IT, NOT FOR SCOPING A
		 * RULE TO, so a marker taken out of one is declared over the
		 * WHOLE OBJECT.
		 *
		 * For a binary the region a marker sits in is a real narrowing:
		 * CODE and DATA are far apart, the same bytes in the wrong one
		 * mean something else, and a rule that says which is a stronger
		 * rule. A script's BODY and MARKUP are not that. Measured over
		 * 101 shells in this corpus:
		 *
		 *   BODY is 91% of the bytes, so scoping to it saves 9%;
		 *   it takes 365 extents where the whole object takes 101, and
		 *     63% of those extents hold 1.2% of the bytes - most of the
		 *     matcher calls buy almost no work;
		 *   and 2 of the 101 files carry a marker that appears ONLY in
		 *     markup, so a BODY-scoped rule loses those files outright.
		 *
		 * Worse for detection, barely better for cost, and the reader
		 * did not ask for it - they clicked the run they happened to be
		 * reading. The default is therefore the object, and a
		 * researcher who really wants "in the code, not in the page"
		 * still says so with the range control on the row.
		 */
		if (v->obj[n->obj].ctx.format == KOF_FMT_SCRIPT) {
			d->mask = d->mask0 = KOF_SCAN_ALL;
			snprintf(d->rgn, sizeof d->rgn, "WHOLE-FILE");
		} else {
			d->mask = d->mask0 = rn->mask ? rn->mask
						      : KOF_SCAN_ALL;
			/* The column is narrow and a region word is short; a
			 * label long enough to overrun it is one that would not
			 * have fit on the row either. */
			snprintf(d->rgn, sizeof d->rgn, "%.23s",
				 rn->mask ? rn->label : "WHOLE-FILE");
		}
	}
	d->grp = 0;
	/* Not on a symbol row: there `lo` is a block offset and this field is
	 * a file offset. decl_locate sets it from the search either way. */
	d->at = n->sym ? KGENOME_BROKEN : view_map(v, lo, 0);
	(void)g;
	v->ed.dr.warn[0] = 0;
	v->ed.dr.sel_decl = v->ed.dr.n_decl;
	draft_seed_target(v);
	v->ed.dr.n_decl++;
	/*
	 * LOCATED, like every other path that produces a declaration.
	 *
	 * `at` was set straight from the selection and n_hits/cur_hit/at_mask
	 * left at zero, so a marker just taken from the pane showed no "n/m"
	 * occurrence count and no [<]/[>] step arrows - those are gated on
	 * n_hits > 1 - however many times its bytes appear. It looked like a
	 * marker that occurs once until the reader pressed "Update string
	 * regions", which is a thing they had no reason to press.
	 */
	decl_locate(&v->ed, &v->ed.dr.decl[v->ed.dr.n_decl - 1u]);

	/* The selection has been taken; leaving it lit would invite taking it
	 * twice. */
	v->sel_a = v->sel_b = KGENOME_BROKEN;
}
