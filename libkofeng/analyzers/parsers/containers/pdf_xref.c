/*
 * pdf_xref.c - the trailer and the cross reference sections of a PDF.
 *
 * WHAT THIS SERVES: the part of the file that is structure rather than
 * content. A classic section is MEASURED by its shape and not taken from
 * startxref, which is a claim the file makes about itself; the trailer is
 * read for what the host needs from it (/Root, /Encrypt, /Info). What a
 * section reaches is claimed into the header region after the objects have
 * claimed theirs.
 */

#include "pdf_int.h"

/* ---- the cross reference section ---------------------------------------------- */

/*
 * HOW FAR A CLASSIC CROSS REFERENCE SECTION REACHES.
 *
 * kofmod/pdf.h says the HEADER region is "the version line, the trailer, the xref
 * and the startxref pointer", and for a long time it was the first and the last of
 * those alone: the table and the trailer dictionary fell into the complement, so a
 * 9464 byte xref in an ordinary document was reported as bytes no structure owned,
 * and a rule aimed at the trailer - where /Encrypt and /Root live - could not reach
 * it through any region at all.
 *
 * MEASURED, NOT TAKEN FROM startxref. The offset in the file is a claim the file
 * makes about itself and this parse trusts none of those; the SHAPE, on the other
 * hand, is fixed by the format. After the keyword come subsections, each a start
 * and a count followed by exactly `count` twenty byte entries, then `trailer` and
 * a dictionary. Where that stops holding is where this stops and returns what it
 * had already validated, so a damaged tail still claims the part that was there.
 *
 * Refusing is the point as much as measuring is: "xref" is four bytes and a
 * compressed stream carries them as readily as any others, so a candidate whose
 * shape does not hold gets KGENOME_BROKEN and stays out of the region.
 */
static uint64_t xref_section_end(kof_buf f, uint64_t at, uint64_t *tr_off,
				 uint32_t *tr_len)
{
	uint64_t i, last_good;

	if (at + 4u > f.n || memcmp(f.p + at, "xref", 4u) != 0)
		return KGENOME_BROKEN;
	i = at + 4u;
	while (i < f.n && pdf_is_ws(f.p[i]))
		i++;
	if (i == at + 4u)
		return KGENOME_BROKEN;         /* "xref" must be followed by space */
	last_good = i;

	/* Subsections: "<start> <count>", then count entries of twenty bytes. */
	for (;;) {
		uint64_t count = 0, j = i;
		int any = 0;

		while (j < f.n && kof_is_digit(f.p[j])) {
			j++;
			any = 1;
		}
		if (!any || j >= f.n || !pdf_is_ws(f.p[j]))
			break;
		while (j < f.n && pdf_is_ws(f.p[j]))
			j++;
		any = 0;
		while (j < f.n && kof_is_digit(f.p[j]) && count < (1u << 24)) {
			count = count * 10u + (uint64_t)(f.p[j] - '0');
			j++;
			any = 1;
		}
		if (!any)
			break;
		while (j < f.n && pdf_is_ws(f.p[j]))
			j++;
		/* Twenty bytes each, which is the one width the format fixes.
		 * Divided rather than multiplied: `count` came out of the file
		 * and the product would wrap. */
		if (j > f.n || count > (f.n - j) / 20u)
			break;
		i = j + count * 20u;
		last_good = i;
		while (i < f.n && pdf_is_ws(f.p[i]))
			i++;
	}

	/* The trailer, and the dictionary it introduces. */
	if (i + 7u <= f.n && memcmp(f.p + i, "trailer", 7u) == 0) {
		uint64_t j = i + 7u;

		while (j < f.n && pdf_is_ws(f.p[j]))
			j++;
		if (j + 2u <= f.n && f.p[j] == '<' && f.p[j + 1u] == '<') {
			uint64_t dict_start = j;
			uint32_t depth = 0;

			/* Nesting counted, because a trailer holds dictionaries -
			 * /Root and /Encrypt are references but /ID is an array
			 * and a linearised trailer nests outright. Stopping at
			 * the first ">>" would have cut the claim short. */
			while (j + 1u < f.n) {
				if (f.p[j] == '<' && f.p[j + 1u] == '<') {
					depth++;
					j += 2u;
					continue;
				}
				if (f.p[j] == '>' && f.p[j + 1u] == '>') {
					j += 2u;
					if (--depth == 0)
						break;
					continue;
				}
				j++;
			}
			if (depth == 0) {
				/* The dictionary the trailer introduced, which
				 * is where /Info is declared. Handed back
				 * rather than re-found: this loop just measured
				 * it, and a second walk looking for "trailer"
				 * would have to decide all over again which
				 * occurrence of the word is the keyword. */
				if (tr_off && tr_len) {
					*tr_off = dict_start;
					*tr_len = (uint32_t)(j - dict_start);
				}
				last_good = j;
			}
		}
	}
	return last_good;
}

/*
 * The trailer end: every %%EOF and startxref, recorded and checked, never
 * followed.
 */
void pdf_read_trailer(kof_buf file, struct kof_pdf_info *p,
			     struct kof_runs *runs)
{
	uint64_t at;

/*
 * The trailer end, read before the objects so that a truncated file is
 * already known to be one. startxref is recorded and checked, never
 * followed.
 */
	uint64_t eof = KGENOME_BROKEN, sx, from;

	from = file.n > (1u << 16) ? file.n - (1u << 16) : 0;
	for (at = from; at < file.n; ) {
		uint64_t h = pdf_find_bytes(file, at, file.n, "%%EOF", 5u);

		if (h == KGENOME_BROKEN)
			break;
		eof = h;
		/*
		 * EVERY ONE OF THEM, AND NOT ONLY THE LAST.
		 *
		 * An incrementally updated document ends each revision
		 * with its own startxref and %%EOF, and they are all
		 * structure. Keeping only the last left the earlier
		 * ones owned by nothing, so a hybrid file - one with a
		 * classic table for old readers AND a cross reference
		 * stream for new ones - reported a revision's whole
		 * tail as bytes no structure claimed. `eof_off` still
		 * says the LAST, which is the one a reader resumes
		 * from; the claim is about all of them.
		 */
		kof_runs_add(runs, file.n, h, 5u, KOF_PDF_CLS_HEADERS);
		at = h + 5u;
	}
	if (eof == KGENOME_BROKEN)
		p->anomalies |= KOF_PDF_ANOM_NO_EOF;
	else
		p->eof_off = eof;   /* claimed in the loop above */

	sx = KGENOME_BROKEN;
	for (at = from; at < file.n; ) {
		uint64_t h = pdf_find_bytes(file, at, file.n, "startxref", 9u);

		if (h == KGENOME_BROKEN)
			break;
		sx = h;
		/* Each revision's pointer, for the reason the %%EOF
		 * loop above gives - and the digits with it, so the
		 * extent is the whole statement rather than a fixed
		 * nine bytes with its value left in the complement. */
		{
			uint64_t j = h + 9u;

			while (j < file.n && pdf_is_ws(file.p[j]))
				j++;
			while (j < file.n && kof_is_digit(file.p[j]))
				j++;
			kof_runs_add(runs, file.n, h, j - h,
				     KOF_PDF_CLS_HEADERS);
		}
		at = h + 9u;
	}
	if (sx == KGENOME_BROKEN) {
		p->anomalies |= KOF_PDF_ANOM_NO_XREF;
	} else {
		uint64_t i = sx + 9u, v = 0;
		int any = 0;

		while (i < file.n && pdf_is_ws(file.p[i]))
			i++;
		while (i < file.n && kof_is_digit(file.p[i]) && v < (1ull << 60)) {
			v = v * 10u + (uint64_t)(file.p[i] - '0');
			i++;
			any = 1;
		}
		/* Claimed in the loop above, keyword and value both -
		 * a second claim on the same bytes would be trimmed by
		 * kof_runs_settle and reported as an OVERLAP the file
		 * does not have. This only reads the value. */
		p->startxref = any ? v : 0;
		if (!any || v >= file.n)
			p->anomalies |= KOF_PDF_ANOM_BAD_STARTXREF;
	}
	/*
	 * /Encrypt USED TO BE SEARCHED FOR HERE, AND SHOULD NOT HAVE
	 * BEEN.
	 *
	 * The bytes were looked for in the last 64KiB of the file,
	 * which is neither where the name has to be nor the only place
	 * it can be: a linearised document puts its trailer at the
	 * FRONT and so never set the bit, while any stream in the tail
	 * carrying those eight bytes set it for a document that is not
	 * encrypted at all.
	 *
	 * It is a marker in the table now, so it is found where it is
	 * actually written - in an object's dictionary, which is where
	 * a cross reference stream keeps it, and in the trailer
	 * dictionary, which the xref section below reads.
	 */
}

/* The cross reference sections, claimed after the objects. */
void pdf_claim_xref(kof_buf file, struct kof_pdf_info *p,
			   struct kof_runs *runs, uint64_t hdr)
{
	uint64_t at;

/*
 * THE CROSS REFERENCE SECTIONS, CLAIMED AFTER THE OBJECTS.
 *
 * After, because that is what makes a candidate inside a stream
 * refusable. xref_section_end turns down most stray "xref" bytes by
 * validating the shape behind them, but HEADER is class zero and so
 * outranks every stream class in the settle: a survivor would TAKE
 * bytes the walk had already established belong to a stream, and the
 * region would be describing the file less accurately than before.
 *
 * The object table is in increasing offset order, so `oi` walks it once
 * alongside the search rather than being scanned per candidate - and a
 * stream that happens to be full of the string costs one skip instead
 * of one validation per hit.
 *
 * Every section, not just the last: an incrementally updated document
 * has one per revision, and the earlier ones are as much structure as
 * the newest. /Prev is not followed - it is another offset the file
 * chooses - so they are found the same way everything else here is.
 */
	uint32_t oi = 0;

	at = hdr;
	while (at < file.n) {
		uint64_t h = pdf_find_bytes(file, at, file.n, "xref", 4u);
		uint64_t xend, s_lim;

		if (h == KGENOME_BROKEN)
			break;
		at = h + 4u;
		/* "startxref" ends in "xref"; its own claim is made
		 * above, and this must not make a second one. */
		if (h >= 5u && memcmp(file.p + h - 5u, "start", 5u) == 0)
			continue;

		while (oi < p->n_objects &&
		       p->object[oi].stream_off +
		       p->object[oi].stream_len <= h)
			oi++;
		if (oi < p->n_objects && p->object[oi].stream_len &&
		    h >= p->object[oi].stream_off) {
			s_lim = p->object[oi].stream_off +
				p->object[oi].stream_len;
			if (s_lim > at)
				at = s_lim;
			continue;
		}

		xend = xref_section_end(file, h, &p->trailer_off,
					&p->trailer_len);
		if (xend == KGENOME_BROKEN || xend <= h)
			continue;
		kof_runs_add(runs, file.n, h, xend - h,
			     KOF_PDF_CLS_XREF);
		/*
		 * And read for what it declares. The trailer is a
		 * dictionary like any other - /Encrypt and /Root live
		 * in it - and nothing was reading it, so a classic
		 * document's own statement about itself reached no
		 * flag. The whole claimed range is passed because a
		 * table's entries are digits: the only names inside it
		 * are the trailer's own.
		 *
		 * A scratch object, because these are the FILE's facts
		 * and the trailer is not one of the numbered objects -
		 * giving it a row would invent one the document does
		 * not have. Only p->anomalies is meant to survive.
		 */
		{
			struct kof_pdf_object t;

			memset(&t, 0, sizeof t);
			pdf_dict_scan(file, h, xend - h, &t, p, 0);
		}
		if (xend > at)
			at = xend;
	}
}
