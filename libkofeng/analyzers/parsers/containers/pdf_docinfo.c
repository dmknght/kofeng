/*
 * pdf_docinfo.c - what a PDF says about itself: its /Info strings.
 *
 * WHAT THIS SERVES: the title, author, producer and the rest, read out of the
 * document's own dictionary for a person to see. Nothing here is evidence of
 * anything; a producer string is a claim the file makes.
 */

#include "pdf_int.h"

static const char *const DOCINFO_KEY[KOF_PDF_DOCINFO_COUNT] = {
	"/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer"
};

const char *kof_pdf_docinfo_name(unsigned which)
{
	static const char *const N[KOF_PDF_DOCINFO_COUNT] = {
		"title", "author", "subject", "keywords", "creator", "producer"
	};

	return which < KOF_PDF_DOCINFO_COUNT ? N[which] : "?";
}

/*
 * The STRING value that follows `key`, as the range INSIDE its delimiters.
 *
 * Two spellings, both of them the format's: a literal string in parentheses and
 * a hex string in angle brackets. Neither is decoded here - an escape inside a
 * literal and the hex pairs of the other are a rendering question, and a parse
 * that decoded them would need somewhere to put the result, which is the thing
 * a range exists to avoid.
 *
 * Parentheses NEST and may be escaped, and both matter: a title reading
 * "Report (final)" is one string with a nested pair, and a backslash before a
 * parenthesis means the character rather than the end. Counting depth and
 * honouring the escape is what stops the first inner ')' cutting the value
 * short - and a producer that writes either is not being hostile, it is writing
 * an ordinary document.
 */
static void dict_string(kof_buf f, uint64_t dict_off, uint64_t dict_len,
			const char *key, uint32_t klen,
			uint64_t *val_off, uint32_t *val_len, uint8_t *is_hex)
{
	uint64_t at = dict_off, end = dict_off + dict_len;

	*val_off = 0;
	*val_len = 0;
	*is_hex = 0;
	if (!dict_len || end > f.n)
		return;
	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end;
		uint32_t nm;
		int esc;

		if (!sl)
			return;
		pos = (uint64_t)(sl - f.p);
		nm = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (nm != klen || memcmp(name, key, klen) != 0)
			continue;
		while (raw_end < end && pdf_is_ws(f.p[raw_end]))
			raw_end++;
		if (raw_end >= end)
			return;
		if (f.p[raw_end] == '(') {
			uint64_t i = raw_end + 1u, start = i;
			uint32_t depth = 1;

			while (i < end) {
				if (f.p[i] == '\\') {
					i += 2u;       /* the next byte is data */
					continue;
				}
				if (f.p[i] == '(') {
					depth++;
				} else if (f.p[i] == ')') {
					if (--depth == 0)
						break;
				}
				i++;
			}
			if (depth == 0 && i > start) {
				*val_off = start;
				*val_len = (uint32_t)(i - start);
			}
			return;
		}
		if (f.p[raw_end] == '<' &&
		    !(raw_end + 1u < end && f.p[raw_end + 1u] == '<')) {
			uint64_t i = raw_end + 1u, start = i;

			while (i < end && f.p[i] != '>')
				i++;
			if (i < end && i > start) {
				*val_off = start;
				*val_len = (uint32_t)(i - start);
				*is_hex = 1;
			}
			return;
		}
		return;                /* a reference, a number, a dictionary */
	}
}

/*
 * Read the six /Info strings, from wherever this document declares them.
 *
 * TWO PLACES, because the format has two shapes. A classic document declares
 * /Info in its trailer dictionary; one with a cross reference STREAM has no
 * trailer keyword at all and puts the same keys on that stream's own
 * dictionary. Both are tried, in that order, and a document with neither
 * simply has no /Info - which is ordinary.
 *
 * ONE STEP, like every other reference this parse follows: /Info is `N 0 R`,
 * the object with that number is looked up in a table already built, and its
 * dictionary is read. A reference to a reference is refused rather than
 * chased, for the reason kof_pdf_object.ref_num gives.
 */
void pdf_read_docinfo(struct kof_pdf_info *p, kof_buf file)
{
	uint64_t doff = 0;
	uint64_t dlen = 0;
	uint32_t i;
	uint32_t num = 0;

	if (p->trailer_len) {
		doff = p->trailer_off;
		dlen = p->trailer_len;
	} else {
		for (i = 0; i < p->n_objects; i++)
			if (p->object[i].cat == KOF_PDF_CAT_XREF) {
				doff = p->object[i].dict_off;
				dlen = p->object[i].dict_len;
				break;
			}
	}
	if (!dlen)
		return;

	/* /Info N 0 R, and nothing else is accepted: a direct dictionary there
	 * is legal in the letter of the format and is not what any producer
	 * writes, so following only the reference keeps this to one shape. */
	{
		uint64_t at = doff, end = doff + dlen;

		if (end > file.n)
			return;
		while (at < end) {
			const uint8_t *sl = memchr(file.p + at, '/',
						   (size_t)(end - at));
			uint8_t name[PDF_NAME_MAX];
			uint64_t pos, raw_end;
			uint32_t nm;
			int esc;

			if (!sl)
				return;
			pos = (uint64_t)(sl - file.p);
			nm = pdf_name_decode(file, pos, end, name, &esc, &raw_end);
			at = pos + 1u;
			if (nm == 5u && memcmp(name, "/Info", 5u) == 0) {
				num = pdf_read_ref(file, raw_end, end);
				break;
			}
		}
	}
	if (!num)
		return;

	for (i = 0; i < p->n_objects; i++) {
		const struct kof_pdf_object *o = &p->object[i];
		uint32_t k;

		if (o->num != num)
			continue;
		for (k = 0; k < KOF_PDF_DOCINFO_COUNT; k++)
			dict_string(file, o->dict_off, o->dict_len,
				    DOCINFO_KEY[k],
				    (uint32_t)strlen(DOCINFO_KEY[k]),
				    &p->docinfo[k].off, &p->docinfo[k].len,
				    &p->docinfo[k].hex);
		return;
	}
}
