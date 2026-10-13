/*
 * pdf_int.h - what the units of the PDF parser share with each other, and with
 * nothing else.
 *
 * pdf_parse.c was one file of two and a half thousand lines. The units are split
 * by WHAT THEY READ, and each says in its first lines what that is:
 *
 *   pdf_parse.c    the parse itself: header, regions, references, the entry point
 *   pdf_walk.c     the objects: every "N G obj", its stream and what it claims
 *   pdf_xref.c     the trailer and the cross reference sections
 *   pdf_dict.c     one object's dictionary: what it announces
 *   pdf_entries.c  what the host reads: the entry table and each stream's chain
 *   pdf_docinfo.c  what the document says about itself
 *   pdf_names.c    region and anomaly names, for tools
 *
 * The lexical primitives below are inline for the reason they were `static`: a
 * scan that reads a name or a number at every key of every object pays for a
 * call there, and each unit that needs one gets its own copy to inline. The
 * functions after them are the calls between the units. Nothing outside this
 * directory includes this header; pdf_parse.h is the public one.
 */

#ifndef KOFENG_PDF_INT_H
#define KOFENG_PDF_INT_H

#include <stddef.h>
#include <string.h>
#include "../../../kofcore/kofcore.h"
#include "../../../kofcore/runlist.h"
#include "pdf_parse.h"

/* ---- lexical primitives ------------------------------------------------------- */

/*
 * A NAME AS THE FORMAT MEANS IT, NOT AS IT WAS SPELLED.
 *
 * #hh is a legal escape inside a PDF name, so /J#61vaScript IS /JavaScript to
 * every viewer that opens the document. Matching the bytes as written matches
 * what the author chose rather than what the name means, and the note above
 * dict_scan used to say the escape was "recorded separately" while nothing in
 * this file recorded it. So a name is copied out with its escapes undone, and
 * the tables are matched against that.
 *
 * Bounded at PDF_NAME_MAX, which is longer than every entry either table
 * holds: a longer name cannot match one, so truncating costs nothing that
 * refusing would have saved. A name ends at whitespace or at a delimiter,
 * which is what the format says ends one - so `/Type/ObjStm` is two names.
 */
#define PDF_NAME_MAX 48u

/*
 * Find `pat` in [from, to), or KGENOME_BROKEN.
 *
 * memchr for the first byte and memcmp for the rest, which is what every other
 * literal search in this tree does and for the same reason: both are vectorised in
 * any real libc and a byte at a time loop is an order of magnitude slower.
 */
static inline uint64_t pdf_find_bytes(kof_buf f, uint64_t from, uint64_t to,
			   const char *pat, uint32_t n)
{
	if (n == 0 || to > f.n || from >= to || (uint64_t)n > to - from)
		return KGENOME_BROKEN;
	for (;;) {
		const uint8_t *p;
		uint64_t left = to - from;

		if ((uint64_t)n > left)
			return KGENOME_BROKEN;
		p = memchr(f.p + from, pat[0], (size_t)(left - n + 1u));
		if (!p)
			return KGENOME_BROKEN;
		from = (uint64_t)(p - f.p);
		if (memcmp(f.p + from, pat, n) == 0)
			return from;
		from++;
	}
}

static inline int pdf_is_ws(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
	       c == '\f' || c == 0;
}

static inline int pdf_is_delim(uint8_t c)
{
	return c == '/' || c == '[' || c == ']' || c == '<' || c == '>' ||
	       c == '(' || c == ')' || c == '{' || c == '}' || c == '%';
}

static inline uint32_t pdf_name_decode(kof_buf f, uint64_t pos, uint64_t end,
			    uint8_t *out, int *esc, uint64_t *raw_end)
{
	uint32_t n = 0;
	uint64_t i = pos + 1u;          /* past the '/' */

	*esc = 0;
	out[n++] = '/';
	while (i < end && n < PDF_NAME_MAX) {
		uint8_t c = f.p[i];

		if (pdf_is_ws(c) || pdf_is_delim(c))
			break;
		if (c == '#' && i + 2u < end) {
			int h = kof_hex_val(f.p[i + 1u]);
			int l = kof_hex_val(f.p[i + 2u]);

			if (h >= 0 && l >= 0) {
				out[n++] = (uint8_t)(h * 16 + l);
				*esc = 1;
				i += 3u;
				continue;
			}
		}
		out[n++] = c;
		i++;
	}
	*raw_end = i;
	return n;
}

/*
 * The integer after /Length, or zero when there is not one to have.
 *
 * Zero for `12 0 R` as much as for a missing number. An indirect length is
 * legal and resolving it needs the object graph this parse does not build -
 * following it would mean trusting the same table the walk exists to avoid -
 * so it is refused as a value and recorded as a reason. The search for
 * "endstream" answers the question anyway, without trusting anything.
 */
static inline uint64_t pdf_read_length(kof_buf f, uint64_t at, uint64_t end,
			    struct kof_pdf_info *p)
{
	uint64_t v = 0, i = at, j;
	int any = 0, gen = 0;

	while (i < end && pdf_is_ws(f.p[i]))
		i++;
	while (i < end && kof_is_digit(f.p[i]) && v < (1ull << 48)) {
		v = v * 10u + (uint64_t)(f.p[i] - '0');
		i++;
		any = 1;
	}
	if (!any)
		return 0;

	/* `N G R` is a reference and not a length: a second integer, then an R. */
	j = i;
	while (j < end && pdf_is_ws(f.p[j]))
		j++;
	while (j < end && kof_is_digit(f.p[j])) {
		j++;
		gen = 1;
	}
	while (j < end && pdf_is_ws(f.p[j]))
		j++;
	if (gen && j < end && f.p[j] == 'R') {
		p->anomalies |= KOF_PDF_ANOM_LENGTH_INDIR;
		return 0;
	}
	return v;
}

/*
 * The object number of an `N G R` reference at `at`, or zero.
 *
 * Zero for anything that is not one - a direct string, an array, a dictionary -
 * because those need no following: the value is already where the caller is
 * looking. Only the number is returned; the generation is read to confirm the
 * shape and then dropped, since a document with two generations of the same
 * number live at once is one whose xref decides between them, and this parse
 * does not read the xref.
 */
static inline uint32_t pdf_read_ref(kof_buf f, uint64_t at, uint64_t end)
{
	uint64_t i = at, num = 0;
	int any = 0, gen = 0;

	while (i < end && pdf_is_ws(f.p[i]))
		i++;
	while (i < end && kof_is_digit(f.p[i]) && num < (1u << 28)) {
		num = num * 10u + (uint64_t)(f.p[i] - '0');
		i++;
		any = 1;
	}
	if (!any || !num)
		return 0;
	while (i < end && pdf_is_ws(f.p[i]))
		i++;
	while (i < end && kof_is_digit(f.p[i])) {
		i++;
		gen = 1;
	}
	while (i < end && pdf_is_ws(f.p[i]))
		i++;
	if (!gen || i >= end || f.p[i] != 'R')
		return 0;
	return (uint32_t)num;
}

/* ---- one object's dictionary (pdf_dict.c) ------------------------------------- */

void pdf_dict_scan(kof_buf f, uint64_t off, uint64_t len,
		   struct kof_pdf_object *o, struct kof_pdf_info *p,
		   uint64_t *declared_len);
/* Which of the format's filters this name is, or -1 for none of them; and the
 * KOF_PDF_F_ bit of filter `i`. */
int pdf_find_filter(const uint8_t *name, uint32_t nm);
uint32_t pdf_filter_bit(int i);

/* ---- the entry table (pdf_entries.c) ------------------------------------------ */

void pdf_build_entries(struct kof_pdf_info *p, kof_buf file);
uint32_t pdf_entries(const struct kof_obj_ctx *ctx,
		     const struct kof_entry **out);

/* ---- the document's own description (pdf_docinfo.c) --------------------------- */

void pdf_read_docinfo(struct kof_pdf_info *p, kof_buf file);

/* ---- the objects (pdf_walk.c) ------------------------------------------------- */

void pdf_walk_objects(kof_buf file, struct kof_pdf_info *p,
		      struct kof_runs *runs, uint8_t *seen_num, uint64_t hdr);

/* ---- the trailer and the cross reference sections (pdf_xref.c) ---------------- */

void pdf_read_trailer(kof_buf file, struct kof_pdf_info *p,
		      struct kof_runs *runs);
void pdf_claim_xref(kof_buf file, struct kof_pdf_info *p,
		    struct kof_runs *runs, uint64_t hdr);

#endif /* KOFENG_PDF_INT_H */
