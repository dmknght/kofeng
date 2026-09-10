/*
 * pdf_parse.c - walking a PDF for its objects.
 *
 * The walk is a scan for `N G obj`, and everything else follows from where those
 * land. That is a deliberate choice over reading the cross reference table, and
 * kofmod/pdf.h says why: the xref is a claim the file makes about itself, viewers
 * recover from it being wrong, and so malware is free to make it wrong.
 *
 * Every step is bounded by the object rather than by a terminator. A PDF that ends
 * mid-object, mid-stream or mid-dictionary is ordinary - documents are appended to,
 * truncated and stitched - so the parse has to produce a classification for what is
 * there instead of refusing the file.
 */

#include "pdf_parse.h"
#include "../runlist.h"

#include <string.h>

/* ---- searching ---------------------------------------------------------------- */

/*
 * Find `pat` in [from, to), or KOF_BROKEN.
 *
 * memchr for the first byte and memcmp for the rest, which is what every other
 * literal search in this tree does and for the same reason: both are vectorised in
 * any real libc and a byte at a time loop is an order of magnitude slower.
 */
static uint64_t find_bytes(kof_buf f, uint64_t from, uint64_t to,
			   const char *pat, uint32_t n)
{
	if (n == 0 || to > f.n || from >= to || (uint64_t)n > to - from)
		return KOF_BROKEN;
	for (;;) {
		const uint8_t *p;
		uint64_t left = to - from;

		if ((uint64_t)n > left)
			return KOF_BROKEN;
		p = memchr(f.p + from, pat[0], (size_t)(left - n + 1u));
		if (!p)
			return KOF_BROKEN;
		from = (uint64_t)(p - f.p);
		if (memcmp(f.p + from, pat, n) == 0)
			return from;
		from++;
	}
}

static int is_ws(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
	       c == '\f' || c == 0;
}

static int is_digit(uint8_t c)
{
	return c >= '0' && c <= '9';
}

/*
 * Read the `N G obj` that ends at `at`, where `at` is the 'o' of "obj".
 *
 * Walks BACKWARDS, because that is the direction the anchor gives: "obj" is what was
 * searched for, and the two numbers in front of it are what make it an object header
 * rather than the word appearing in a stream. Returns where the header starts, or
 * KOF_BROKEN when the bytes in front are not two numbers.
 */
static uint64_t obj_header_start(kof_buf f, uint64_t at, uint32_t *num,
				 uint32_t *gen)
{
	uint64_t i = at;
	uint64_t g_end, g_start, n_end, n_start;
	uint32_t v;

	if (i == 0)
		return KOF_BROKEN;
	/* whitespace, then the generation number */
	while (i > 0 && is_ws(f.p[i - 1u]))
		i--;
	if (i == at)
		return KOF_BROKEN;         /* "obj" must be preceded by space */
	g_end = i;
	while (i > 0 && is_digit(f.p[i - 1u]))
		i--;
	g_start = i;
	if (g_start == g_end || g_end - g_start > 10u)
		return KOF_BROKEN;

	while (i > 0 && is_ws(f.p[i - 1u]))
		i--;
	if (i == g_start)
		return KOF_BROKEN;
	n_end = i;
	while (i > 0 && is_digit(f.p[i - 1u]))
		i--;
	n_start = i;
	if (n_start == n_end || n_end - n_start > 10u)
		return KOF_BROKEN;

	v = 0;
	for (i = n_start; i < n_end; i++)
		v = v * 10u + (uint32_t)(f.p[i] - '0');
	*num = v;
	v = 0;
	for (i = g_start; i < g_end; i++)
		v = v * 10u + (uint32_t)(f.p[i] - '0');
	*gen = v;
	return n_start;
}

/* ---- what a dictionary announces ---------------------------------------------- */

struct marker { const char *s; uint32_t n; uint32_t bit; uint64_t anom; };

static const struct marker MARKERS[] = {
	{ "/JavaScript", 11u, KOF_PDF_OBJ_JS,         KOF_PDF_ANOM_JS },
	{ "/JS",          3u, KOF_PDF_OBJ_JS,         KOF_PDF_ANOM_JS },
	{ "/OpenAction", 11u, KOF_PDF_OBJ_OPENACTION, KOF_PDF_ANOM_OPENACTION },
	{ "/AA",          3u, KOF_PDF_OBJ_OPENACTION, KOF_PDF_ANOM_OPENACTION },
	{ "/Launch",      7u, KOF_PDF_OBJ_LAUNCH,     KOF_PDF_ANOM_LAUNCH },
	{ "/EmbeddedFile",13u, KOF_PDF_OBJ_EMBEDDED,  KOF_PDF_ANOM_EMBEDDED },
	{ "/Filespec",    9u, KOF_PDF_OBJ_EMBEDDED,   KOF_PDF_ANOM_EMBEDDED },
	{ "/ObjStm",      7u, KOF_PDF_OBJ_OBJSTM,     KOF_PDF_ANOM_OBJSTM },
	{ "/URI",         4u, KOF_PDF_OBJ_URI,        0 },
	{ "/GoToE",       6u, KOF_PDF_OBJ_GOTOE,      0 },
	{ "/RichMedia",  10u, KOF_PDF_OBJ_RICHMEDIA,  0 },
	{ "/XFA",         4u, KOF_PDF_OBJ_XFA,        0 },
	{ "/AcroForm",    9u, KOF_PDF_OBJ_ACROFORM,   0 },
	/* Here rather than as the raw window search this replaced. /Encrypt is
	 * declared in a dictionary - the trailer's in a classic document, an
	 * object's where the cross reference is a stream - and searching the
	 * last 64KiB of the file for the bytes found it in stream data too. */
	{ "/Encrypt",     8u, KOF_PDF_OBJ_ENCRYPT,    KOF_PDF_ANOM_ENCRYPTED }
};

static const struct marker FILTERS[] = {
	{ "/FlateDecode",    12u, KOF_PDF_F_FLATE,    0 },
	{ "/LZWDecode",      10u, KOF_PDF_F_LZW,      0 },
	{ "/ASCIIHexDecode", 15u, KOF_PDF_F_ASCIIHEX, 0 },
	{ "/ASCII85Decode",  14u, KOF_PDF_F_ASCII85,  0 },
	{ "/RunLengthDecode",16u, KOF_PDF_F_RUNLEN,   0 },
	{ "/DCTDecode",      10u, KOF_PDF_F_DCT,      0 },
	{ "/CCITTFaxDecode", 15u, KOF_PDF_F_CCITT,    0 },
	{ "/JBIG2Decode",    12u, KOF_PDF_F_JBIG2,    0 },
	{ "/JPXDecode",      10u, KOF_PDF_F_JPX,      0 },
	{ "/Crypt",           6u, KOF_PDF_F_CRYPT,    0 }
};

/*
 * THE NAMES A STREAM CAN CALL ITSELF, AND WHAT EACH ONE MEANS.
 *
 * Values, not keys: these appear after /Type or /Subtype, so they are matched
 * against the name that FOLLOWS one of those. Everything here is decidable
 * from the object's own dictionary - see enum kof_pdf_cat for why that is the
 * line and what deliberately falls outside it.
 */
static const struct { const char *s; uint32_t n; uint32_t cat; } TYPES[] = {
	{ "/ObjStm",       7u, KOF_PDF_CAT_OBJSTM },
	{ "/XRef",         5u, KOF_PDF_CAT_XREF },
	{ "/Metadata",     9u, KOF_PDF_CAT_METADATA },
	{ "/EmbeddedFile",13u, KOF_PDF_CAT_EMBEDDED },
	{ "/Image",        6u, KOF_PDF_CAT_IMAGE },
	{ "/Font",         5u, KOF_PDF_CAT_FONT },
	{ "/FontFile",     9u, KOF_PDF_CAT_FONT },
	{ "/FontFile2",   10u, KOF_PDF_CAT_FONT },
	{ "/FontFile3",   10u, KOF_PDF_CAT_FONT }
};

/* An image coding IS the statement that these bytes are pixels, and it is
 * there on the streams that declare no /Type at all - which the measurement
 * in kofmod/pdf.h says is most of them. */
#define PDF_F_IS_IMAGE (KOF_PDF_F_DCT | KOF_PDF_F_CCITT | \
			KOF_PDF_F_JBIG2 | KOF_PDF_F_JPX)

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

static int is_delim(uint8_t c)
{
	return c == '/' || c == '[' || c == ']' || c == '<' || c == '>' ||
	       c == '(' || c == ')' || c == '{' || c == '}' || c == '%';
}

static uint32_t hexval(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return (uint32_t)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (uint32_t)(c - 'a') + 10u;
	if (c >= 'A' && c <= 'F')
		return (uint32_t)(c - 'A') + 10u;
	return 16u;
}

static uint32_t name_decode(kof_buf f, uint64_t pos, uint64_t end,
			    uint8_t *out, int *esc, uint64_t *raw_end)
{
	uint32_t n = 0;
	uint64_t i = pos + 1u;          /* past the '/' */

	*esc = 0;
	out[n++] = '/';
	while (i < end && n < PDF_NAME_MAX) {
		uint8_t c = f.p[i];

		if (is_ws(c) || is_delim(c))
			break;
		if (c == '#' && i + 2u < end) {
			uint32_t h = hexval(f.p[i + 1u]);
			uint32_t l = hexval(f.p[i + 2u]);

			if (h < 16u && l < 16u) {
				out[n++] = (uint8_t)(h * 16u + l);
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
static uint64_t read_length(kof_buf f, uint64_t at, uint64_t end,
			    struct kof_pdf_info *p)
{
	uint64_t v = 0, i = at, j;
	int any = 0, gen = 0;

	while (i < end && is_ws(f.p[i]))
		i++;
	while (i < end && is_digit(f.p[i]) && v < (1ull << 48)) {
		v = v * 10u + (uint64_t)(f.p[i] - '0');
		i++;
		any = 1;
	}
	if (!any)
		return 0;

	/* `N G R` is a reference and not a length: a second integer, then an R. */
	j = i;
	while (j < end && is_ws(f.p[j]))
		j++;
	while (j < end && is_digit(f.p[j])) {
		j++;
		gen = 1;
	}
	while (j < end && is_ws(f.p[j]))
		j++;
	if (gen && j < end && f.p[j] == 'R') {
		p->anomalies |= KOF_PDF_ANOM_LENGTH_INDIR;
		return 0;
	}
	return v;
}

/*
 * Does an "endstream" stand at `at`, allowing what the format puts in front
 * of it?
 *
 * /Length counts the data bytes and a writer then puts an end of line before
 * the keyword, so a corroboration demanding the keyword exactly at the
 * declared end would fail on ordinary documents. Whitespace rather than CRLF
 * alone, because a writer padding to a boundary is still one whose /Length is
 * right - and bounded to a few bytes, so no field can make this walk.
 */
static int endstream_at(kof_buf f, uint64_t at)
{
	uint64_t i = at, lim = kof_sat_add(at, 8u);

	if (lim > f.n)
		lim = f.n;
	while (i < lim && is_ws(f.p[i]))
		i++;
	return i + 9u <= f.n && memcmp(f.p + i, "endstream", 9u) == 0;
}

/*
 * Read a dictionary's flags and filters.
 *
 * A substring search over the dictionary and not a parse of it. A real PDF lexer
 * would have to handle name escapes (#4A is 'J'), inherited attributes and indirect
 * references, and would still be searching for the same names - so the cost of being
 * exact is high and what it buys, for the question "does this object mention
 * /Launch", is nothing. What it does buy is being fooled by /J#61vaScript, which is
 * recorded separately: a dictionary containing an escaped name is itself the finding.
 *
 * ONE PASS OVER THE NAMES, not one pass per name. Every string in both tables begins
 * with '/', so the slashes in a dictionary are the only places any of them can start
 * - and there are far fewer slashes than there are table entries. Searching each name
 * separately meant twenty three passes over every dictionary in the document to
 * answer a question the first pass already had the position for.
 */
static void dict_scan(kof_buf f, uint64_t off, uint64_t len,
		      struct kof_pdf_object *o, struct kof_pdf_info *p,
		      uint64_t *declared_len)
{
	uint64_t end = off + len, at = off;
	uint32_t i, filter_seen = 0, known = 0;
	/* The best category seen so far, and the bytes that said it. A lower
	 * enum value is the more specific claim - see enum kof_pdf_cat, whose
	 * order is exactly this priority - so a later, vaguer name cannot
	 * displace an earlier one. */
	uint32_t best = KOF_PDF_CAT_COUNT;
	uint64_t best_off = 0;
	uint32_t best_len = 0;
	uint64_t filt_off = 0;
	uint32_t filt_len = 0;
	int want_type = 0;

	if (!len || end > f.n)
		return;

	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end;
		uint32_t n;
		int esc;

		if (!sl)
			break;
		pos = (uint64_t)(sl - f.p);
		n = name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (esc) {
			o->flags |= KOF_PDF_OBJ_NAME_ESC;
			p->anomalies |= KOF_PDF_ANOM_NAME_ESCAPED;
		}

		/*
		 * THE WHOLE NAME, not a prefix, and that is a fix and not a
		 * tightening: /AA is three bytes and matched /AAPL, /JS
		 * matched anything beginning /JS. A name ends where
		 * name_decode stopped, so its length is known and equality is
		 * the honest test.
		 */
		for (i = 0; i < sizeof MARKERS / sizeof MARKERS[0]; i++)
			if (MARKERS[i].n == n &&
			    memcmp(name, MARKERS[i].s, n) == 0) {
				o->flags |= MARKERS[i].bit;
				p->anomalies |= MARKERS[i].anom;
			}
		for (i = 0; i < sizeof FILTERS / sizeof FILTERS[0]; i++)
			if (FILTERS[i].n == n &&
			    memcmp(name, FILTERS[i].s, n) == 0) {
				o->filters |= FILTERS[i].bit;
				known++;
			}
		if (n == 7u && memcmp(name, "/Filter", 7u) == 0)
			filter_seen = 1;

		/*
		 * A TYPE NAME ONLY WHERE /Type OR /Subtype PUT IT.
		 *
		 * `want_type` carries that across one turn of the loop, because
		 * the value is the NEXT name and this walk sees one name at a
		 * time. Without it `/Image` would count wherever it appeared -
		 * including as a key, which /ImageMask is - and the category
		 * would be taken from a word rather than from a statement.
		 */
		if (want_type) {
			want_type = 0;
			for (i = 0; i < sizeof TYPES / sizeof TYPES[0]; i++)
				if (TYPES[i].n == n &&
				    memcmp(name, TYPES[i].s, n) == 0 &&
				    TYPES[i].cat < best) {
					best = TYPES[i].cat;
					/* Past the '/', so the name a reader
					 * sees is ObjStm and not /ObjStm. */
					best_off = pos + 1u;
					best_len = (uint32_t)(raw_end - pos - 1u);
				}
		}
		if ((n == 5u && memcmp(name, "/Type", 5u) == 0) ||
		    (n == 8u && memcmp(name, "/Subtype", 8u) == 0))
			want_type = 1;
		/* A font's stream is named by its KEY, not by a /Type - the
		 * FontFile entries above are keys for that reason, so they are
		 * tried against the name itself as well. */
		if (!want_type && best > KOF_PDF_CAT_FONT && n >= 9u &&
		    memcmp(name, "/FontFile", 9u) == 0) {
			best = KOF_PDF_CAT_FONT;
			best_off = pos + 1u;
			best_len = (uint32_t)(raw_end - pos - 1u);
		}
		/* The first filter name, kept in case nothing better turns up:
		 * it is a real category for an image and a real fallback for
		 * everything else, and it is bytes that are in the file. */
		if (!filt_len && known)
			for (i = 0; i < sizeof FILTERS / sizeof FILTERS[0]; i++)
				if (FILTERS[i].n == n &&
				    memcmp(name, FILTERS[i].s, n) == 0) {
					filt_off = pos + 1u;
					filt_len = (uint32_t)(raw_end - pos - 1u);
				}
		/* Only where the caller has somewhere to put it: the trailer is
		 * read through here too, and it has no stream to measure. */
		if (declared_len && n == 7u && memcmp(name, "/Length", 7u) == 0)
			*declared_len = read_length(f, raw_end, end, p);
	}

	/* A filter this build does not know is recorded rather than assumed to be
	 * Flate - the decision the unpacker makes rests on it. */
	if (filter_seen && !known) {
		o->filters |= KOF_PDF_F_OTHER;
		p->anomalies |= KOF_PDF_ANOM_UNKNOWN_FILTER;
	}

	/*
	 * THE CATEGORY, SETTLED ONCE THE WHOLE DICTIONARY HAS BEEN READ.
	 *
	 * Here and not in the loop because two of these read flags the loop is
	 * still filling: /JS makes a dictionary's stream a script wherever in it
	 * the name sat, and an image coding is a statement about the stream that
	 * arrives with /Filter rather than with /Type.
	 *
	 * Order is the priority in enum kof_pdf_cat, and the fallback chain ends
	 * at CONTENT rather than at UNKNOWN: a stream nothing described is still
	 * a stream, and a scan may still choose to look inside it.
	 */
	if (best < KOF_PDF_CAT_COUNT) {
		o->cat = best;
		o->cat_off = best_off;
		o->cat_len = best_len;
	} else if (o->flags & KOF_PDF_OBJ_OBJSTM) {
		o->cat = KOF_PDF_CAT_OBJSTM;
	} else if (o->flags & KOF_PDF_OBJ_EMBEDDED) {
		o->cat = KOF_PDF_CAT_EMBEDDED;
	} else if (o->flags & KOF_PDF_OBJ_JS) {
		o->cat = KOF_PDF_CAT_SCRIPT;
	} else if (o->filters & PDF_F_IS_IMAGE) {
		o->cat = KOF_PDF_CAT_IMAGE;
		o->cat_off = filt_off;
		o->cat_len = filt_len;
	} else {
		o->cat = KOF_PDF_CAT_CONTENT;
		o->cat_off = filt_off;
		o->cat_len = filt_len;
	}
}

/* ---- regions ------------------------------------------------------------------ */

/*
 * ONE ENTRY PER CLASS, IN CLASS ORDER, AND EVERY ONE NON-ZERO.
 *
 * kof_runs_resolve indexes this by run[].cls, so a class added to the enum and
 * forgotten here reads a zero - and a zero matches no mask, so that class's
 * bytes resolve into no region at all. The partition test is what notices:
 * those bytes become a hole rather than turning up somewhere wrong.
 */
static const uint32_t pdf_cls_bit[KOF_PDF_CLS_COUNT] = {
	KOF_SCAN_PDF_HEADER,
	KOF_SCAN_PDF_OBJECTS,
	KOF_SCAN_PDF_STREAM_PLAIN,
	KOF_SCAN_PDF_STREAM_PACKED,
	KOF_SCAN_PDF_STREAM_IMAGE
};

/* The view sizes region_bytes to the run list's ceiling so that adding a class
 * moves no field after it - see the note on region_bytes in kofmod/pdf.h. This
 * is where the two are held to agree. */
_Static_assert(KOF_PDF_CLS_COUNT <= KOF_RUNS_MAX_CLS,
	       "more PDF classes than the run list will carry");
_Static_assert(sizeof ((struct kof_pdf_info *)0)->region_bytes /
	       sizeof ((struct kof_pdf_info *)0)->region_bytes[0] ==
	       KOF_RUNS_MAX_CLS,
	       "region_bytes is no longer sized to the run list's ceiling");

static uint32_t pdf_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_pdf_info *p = (const struct kof_pdf_info *)ctx->file_header;

	if (!p || !p->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof p->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)p->run, p->n_runs, mask,
				pdf_cls_bit, KOF_SCAN_PDF_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

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
 * shape does not hold gets KOF_BROKEN and stays out of the region.
 */
static uint64_t xref_section_end(kof_buf f, uint64_t at)
{
	uint64_t i, last_good;

	if (at + 4u > f.n || memcmp(f.p + at, "xref", 4u) != 0)
		return KOF_BROKEN;
	i = at + 4u;
	while (i < f.n && is_ws(f.p[i]))
		i++;
	if (i == at + 4u)
		return KOF_BROKEN;         /* "xref" must be followed by space */
	last_good = i;

	/* Subsections: "<start> <count>", then count entries of twenty bytes. */
	for (;;) {
		uint64_t count = 0, j = i;
		int any = 0;

		while (j < f.n && is_digit(f.p[j])) {
			j++;
			any = 1;
		}
		if (!any || j >= f.n || !is_ws(f.p[j]))
			break;
		while (j < f.n && is_ws(f.p[j]))
			j++;
		any = 0;
		while (j < f.n && is_digit(f.p[j]) && count < (1u << 24)) {
			count = count * 10u + (uint64_t)(f.p[j] - '0');
			j++;
			any = 1;
		}
		if (!any)
			break;
		while (j < f.n && is_ws(f.p[j]))
			j++;
		/* Twenty bytes each, which is the one width the format fixes.
		 * Divided rather than multiplied: `count` came out of the file
		 * and the product would wrap. */
		if (j > f.n || count > (f.n - j) / 20u)
			break;
		i = j + count * 20u;
		last_good = i;
		while (i < f.n && is_ws(f.p[i]))
			i++;
	}

	/* The trailer, and the dictionary it introduces. */
	if (i + 7u <= f.n && memcmp(f.p + i, "trailer", 7u) == 0) {
		uint64_t j = i + 7u;

		while (j < f.n && is_ws(f.p[j]))
			j++;
		if (j + 2u <= f.n && f.p[j] == '<' && f.p[j + 1u] == '<') {
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
			if (depth == 0)
				last_good = j;
		}
	}
	return last_good;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_pdf_sniff(kof_buf file)
{
	uint64_t to = file.n < KOF_PDF_HEADER_SEARCH ? file.n
						     : KOF_PDF_HEADER_SEARCH;

	return find_bytes(file, 0, to, "%PDF-", 5u) != KOF_BROKEN;
}

int kof_pdf_parse(kof_buf file, struct kof_pdf_info *p, struct kof_obj_ctx *ctx)
{
	struct kof_runs runs;
	uint64_t at, hdr, to;
	/* 8192 bits for the redefinition filter above. A kilobyte of frame, on
	 * a path whose caller already hands it a 650KB view. */
	uint8_t seen_num[1024];

	memset(p, 0, sizeof *p);
	memset(seen_num, 0, sizeof seen_num);
	p->version = KOF_PDF_INFO_VERSION;

	to = file.n < KOF_PDF_HEADER_SEARCH ? file.n : KOF_PDF_HEADER_SEARCH;
	hdr = find_bytes(file, 0, to, "%PDF-", 5u);
	if (hdr == KOF_BROKEN)
		return 0;
	p->valid = 1;
	p->header_off = hdr;
	if (hdr != 0)
		p->anomalies |= KOF_PDF_ANOM_HEADER_OFFSET;
	if (hdr + 8u <= file.n && is_digit(file.p[hdr + 5u]) &&
	    is_digit(file.p[hdr + 7u])) {
		p->ver_major = (uint8_t)(file.p[hdr + 5u] - '0');
		p->ver_minor = (uint8_t)(file.p[hdr + 7u] - '0');
	}

	kof_runs_init(&runs, (struct kof_run *)p->run, KOF_PDF_MAX_EXTENTS,
		      KOF_PDF_CLS_COUNT);

	/*
	 * THE VERSION LINE, AND NOT WHAT MAY SIT IN FRONT OF IT.
	 *
	 * A reader accepts junk before %PDF- and malware uses that, which is why
	 * the offset is searched for and recorded above. The bytes themselves are
	 * not the header though, and claiming them as one put up to a kilobyte of
	 * whatever a builder prepended into the region this format documents as
	 * "small, and the part that describes the rest" - a PE stub landed in
	 * HEADER and a rule asking which bytes no structure owns was told none.
	 *
	 * They belong to nothing, which is what UNCLAIMED means, and the
	 * complement puts them there by construction now that this claim starts
	 * at the magic rather than at zero.
	 */
	kof_runs_add(&runs, file.n, hdr, hdr + 8u <= file.n ? 8u : file.n - hdr,
		     KOF_PDF_CLS_HEADER);
	/*
	 * AND THE BINARY COMMENT UNDER IT.
	 *
	 * A writer that puts any binary in the document is told to follow the
	 * version line with a comment holding four bytes above 127, so that a
	 * transport which guesses at text sees at once that it must not. It is
	 * as much a part of the header as the version is - and it was landing
	 * in UNCLAIMED, nine bytes of it, on every file that has one.
	 *
	 * Recognised by the '%' and bounded by the line, because that is all it
	 * is: a comment. Nothing reads its contents.
	 */
	{
		uint64_t c = hdr + 8u;

		while (c < file.n && (file.p[c] == '\r' || file.p[c] == '\n'))
			c++;
		if (c < file.n && file.p[c] == '%') {
			uint64_t e = c;

			while (e < file.n && file.p[e] != '\r' && file.p[e] != '\n')
				e++;
			while (e < file.n && (file.p[e] == '\r' || file.p[e] == '\n'))
				e++;
			kof_runs_add(&runs, file.n, hdr + 8u, e - (hdr + 8u),
				     KOF_PDF_CLS_HEADER);
		}
	}

	/*
	 * The trailer end, read before the objects so that a truncated file is
	 * already known to be one. startxref is recorded and checked, never
	 * followed.
	 */
	{
		uint64_t eof = KOF_BROKEN, sx, from;

		from = file.n > (1u << 16) ? file.n - (1u << 16) : 0;
		for (at = from; at < file.n; ) {
			uint64_t h = find_bytes(file, at, file.n, "%%EOF", 5u);

			if (h == KOF_BROKEN)
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
			kof_runs_add(&runs, file.n, h, 5u, KOF_PDF_CLS_HEADER);
			at = h + 5u;
		}
		if (eof == KOF_BROKEN)
			p->anomalies |= KOF_PDF_ANOM_NO_EOF;
		else
			p->eof_off = eof;   /* claimed in the loop above */

		sx = KOF_BROKEN;
		for (at = from; at < file.n; ) {
			uint64_t h = find_bytes(file, at, file.n, "startxref", 9u);

			if (h == KOF_BROKEN)
				break;
			sx = h;
			/* Each revision's pointer, for the reason the %%EOF
			 * loop above gives - and the digits with it, so the
			 * extent is the whole statement rather than a fixed
			 * nine bytes with its value left in the complement. */
			{
				uint64_t j = h + 9u;

				while (j < file.n && is_ws(file.p[j]))
					j++;
				while (j < file.n && is_digit(file.p[j]))
					j++;
				kof_runs_add(&runs, file.n, h, j - h,
					     KOF_PDF_CLS_HEADER);
			}
			at = h + 9u;
		}
		if (sx == KOF_BROKEN) {
			p->anomalies |= KOF_PDF_ANOM_NO_XREF;
		} else {
			uint64_t i = sx + 9u, v = 0;
			int any = 0;

			while (i < file.n && is_ws(file.p[i]))
				i++;
			while (i < file.n && is_digit(file.p[i]) && v < (1ull << 60)) {
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

	/*
	 * The objects.
	 *
	 * Anchored on "obj" and confirmed by the two numbers in front of it, which
	 * is what keeps the word appearing inside a stream from starting a phantom
	 * object. Each iteration advances past the anchor whether or not it was
	 * real, so the walk ends on the object.
	 */
	at = hdr;
	while (at < file.n) {
		uint64_t tok = find_bytes(file, at, file.n, "obj", 3u);
		uint64_t start, end, stop, dict_end, s_kw, s_end;
		uint64_t declared = 0;
		struct kof_pdf_object *o, spill;
		uint32_t num = 0, gen = 0;

		if (tok == KOF_BROKEN)
			break;
		at = tok + 3u;                  /* advance first, always */

		start = obj_header_start(file, tok, &num, &gen);
		if (start == KOF_BROKEN)
			continue;                /* "obj" inside something else */

		/* Where this object ends. A missing endobj is ordinary in a damaged
		 * file, so the next object's header bounds it instead. */
		end = find_bytes(file, tok + 3u, file.n, "endobj", 6u);
		if (end == KOF_BROKEN) {
			p->anomalies |= KOF_PDF_ANOM_TRUNCATED;
			end = file.n;
		} else {
			end += 6u;
		}

		/*
		 * Past the cap the walk CONTINUES; what it stops producing is rows.
		 *
		 * Breaking out was the obvious thing and it cost two: the rest of
		 * the document became one UNCLAIMED region, so a signature aimed at
		 * an object dictionary could not reach anything past the four
		 * thousandth object - and declared_objects, which this view promises
		 * is what the walk found BEFORE any cap, could never differ from
		 * n_objects because the walk stopped at the same moment the count
		 * did. A row is written into `spill` and discarded, so the regions
		 * and the count are still right when the table is not.
		 */
		if (p->n_objects >= KOF_PDF_MAX_OBJECTS) {
			p->anomalies |= KOF_PDF_ANOM_OBJECTS_FULL;
			o = &spill;
		} else {
			o = &p->object[p->n_objects];
		}
		memset(o, 0, sizeof *o);
		o->off = start;
		o->len = end - start;
		o->num = num;
		o->gen = gen;

		/* A stream, if there is one inside this object. */
		s_kw = find_bytes(file, tok + 3u, end, "stream", 6u);
		/* "endstream" contains "stream": only a match that is not preceded
		 * by "end" begins the data. */
		while (s_kw != KOF_BROKEN && s_kw >= 3u &&
		       memcmp(file.p + s_kw - 3u, "end", 3u) == 0)
			s_kw = find_bytes(file, s_kw + 6u, end, "stream", 6u);

		dict_end = (s_kw == KOF_BROKEN) ? end : s_kw;

		/*
		 * THE DICTIONARY IS READ BEFORE THE STREAM IS MEASURED.
		 *
		 * It has to be. /Length lives in the dictionary and is what the
		 * format says decides where the stream ends, so a parse that
		 * measured first and read the dictionary afterwards could only
		 * ever use the search - which is the recovery path and not the
		 * answer.
		 */
		o->dict_off = start;
		o->dict_len = dict_end > start ? dict_end - start : 0;
		dict_scan(file, o->dict_off, o->dict_len, o, p, &declared);

		if (s_kw != KOF_BROKEN) {
			uint64_t d = s_kw + 6u;

			/* The data begins after the EOL that must follow the
			 * keyword; both CRLF and LF appear. */
			if (d < file.n && file.p[d] == '\r')
				d++;
			if (d < file.n && file.p[d] == '\n')
				d++;

			/*
			 * THE KEYWORD BELONGS TO THE OBJECT, NOT TO NOBODY.
			 *
			 * The dictionary run ended where "stream" begins and the
			 * data run starts after the end of line that follows it,
			 * so the eight bytes between them - the word and its EOL
			 * - were owned by nothing. Fifteen streams in one
			 * ordinary document, 120 of its 161 unclaimed bytes: the
			 * single largest thing left in a region whose whole
			 * value is being nearly empty on a file with nothing to
			 * hide.
			 *
			 * The dictionary grows to cover it rather than a run of
			 * its own being added, so the two coalesce and it costs
			 * no extent. What dict_scan already read is unchanged -
			 * it was given the range that ends at the keyword, and a
			 * keyword holds no names.
			 */
			if (d > start)
				o->dict_len = d - start;

			s_end = find_bytes(file, d, file.n, "endstream", 9u);

			/*
			 * /Length, CORROBORATED RATHER THAN TRUSTED.
			 *
			 * The format says /Length decides and "endstream" is
			 * how a reader recovers when it is wrong, so searching
			 * alone was reading the fallback and calling it the
			 * answer: a stream whose DATA carries the nine bytes
			 * "endstream" got cut off at them, and everything past
			 * the decoy left the stream, never reached the
			 * decompressor, and raised nothing at all.
			 *
			 * Corroborated, because a length is a number the file
			 * chooses too and a huge one would pull the rest of the
			 * document into one opaque region - the same trick from
			 * the other end. So it wins only where an "endstream"
			 * really stands where it points, and the two disagreeing
			 * is itself the thing recorded.
			 */
			if (declared) {
				uint64_t dend = kof_sat_add(d, declared);

				if (dend <= file.n && endstream_at(file, dend)) {
					if (s_end != KOF_BROKEN && s_end < dend) {
						p->anomalies |=
						    KOF_PDF_ANOM_STREAM_DECOY;
						o->flags |=
						    KOF_PDF_OBJ_STREAM_DECOY;
					}
					s_end = dend;
				} else {
					/* Pointing at no keyword at all: damage
					 * as often as intent, so its own bit. */
					p->anomalies |= KOF_PDF_ANOM_LENGTH_BAD;
				}
			}

			if (s_end == KOF_BROKEN) {
				p->anomalies |= KOF_PDF_ANOM_STREAM_UNTERM;
				s_end = end;
			} else if (s_end + 9u > end) {
				/*
				 * THE STREAM BOUNDS THE OBJECT, NOT THE FIRST
				 * "endobj" IN THE FILE.
				 *
				 * `end` was taken before the stream had been
				 * located, by a search with nothing but the file to
				 * bound it - and compressed bytes carry the string
				 * "endobj" as readily as any other six. Taken from
				 * inside the stream it made the walk rewind into the
				 * stream body and read opaque bytes as dictionaries:
				 * a phantom object whose /Launch or /JS raised an
				 * anomaly about a document that declared neither, a
				 * run colliding with the stream's own so the file was
				 * reported OVERLAP when nothing in it overlapped, and
				 * a slot spent out of the object table that a real
				 * stream-bearing object then could not have.
				 *
				 * Re-taken from past "endstream", which is the first
				 * offset the object's own structure resumes at.
				 */
				uint64_t e2 = find_bytes(file, s_end + 9u, file.n,
							 "endobj", 6u);

				if (e2 == KOF_BROKEN) {
					p->anomalies |= KOF_PDF_ANOM_TRUNCATED;
					end = file.n;
				} else {
					end = e2 + 6u;
				}
			}
			if (s_end > d) {
				o->stream_off = d;
				o->stream_len = s_end - d;
				o->flags |= KOF_PDF_OBJ_STREAM;
				p->n_streams++;
				o->len = end - start;
			}
		}

		/*
		 * WHERE THE NEXT OBJECT BEGINS, AND WHY THE GAP IS OURS.
		 *
		 * One or two bytes of end of line sit between "endobj" and the
		 * next "N G obj". Left to nobody they became a run in the
		 * complement, and that gap is exactly what stopped kof_runs_add
		 * from joining one object's tail to the next one's dictionary -
		 * so a document's runs went dict, stream, tail, GAP, dict, and
		 * every object cost three extents instead of the one its bytes
		 * describe. Measured on an ordinary 1.65MB document: 180 of its
		 * 240 UNCLAIMED extents were four bytes or fewer of this, and
		 * OBJECTS resolved to 238 extents where 58 say the same thing.
		 *
		 * Not a cosmetic count. A region resolves into KOF_SCAN_MAX_EXTENTS
		 * ranges and one that does not fit is searched IN PART, with the
		 * scan saying KOF_BROKEN_LIMIT - and a benign PDF was reaching it.
		 * Whitespace between two structures is structure, so it goes to
		 * OBJECTS and consecutive objects coalesce into one run.
		 */
		stop = end;
		while (stop < file.n && is_ws(file.p[stop]))
			stop++;
		/* An object with no stream owns the gap as part of its own run;
		 * one with a stream has a tail below that reaches the same
		 * place. Only the RUN grows - the dictionary has already been
		 * read, and whitespace holds no names. */
		if (!o->stream_len && stop > start)
			o->dict_len = stop - start;

		kof_runs_add(&runs, file.n, o->dict_off, o->dict_len,
			     KOF_PDF_CLS_OBJECTS);
		/*
		 * IMAGE OUTRANKS THE CODING, because it answers a different
		 * question. Whether a stream is deflated says what has to
		 * happen before it can be read; whether it is pixels says
		 * whether reading it was ever going to be worth anything. An
		 * unfiltered image is still an image, so this is asked first
		 * and the coding decides only what is left.
		 */
		if (o->stream_len)
			kof_runs_add(&runs, file.n, o->stream_off, o->stream_len,
				     o->cat == KOF_PDF_CAT_IMAGE
				       ? KOF_PDF_CLS_STREAM_IMAGE
				       : (o->filters ? KOF_PDF_CLS_STREAM_PACKED
						     : KOF_PDF_CLS_STREAM_PLAIN));
		/* The tail of the object - "endstream endobj" - is structure. */
		if (o->stream_len) {
			uint64_t tail = o->stream_off + o->stream_len;

			if (stop > tail)
				kof_runs_add(&runs, file.n, tail, stop - tail,
					     KOF_PDF_CLS_OBJECTS);
		}

		/*
		 * THIS NUMBER AND GENERATION, SEEN BEFORE.
		 *
		 * Through an 8192 bit filter rather than a scan of the table,
		 * because the table holds four thousand objects and comparing
		 * against every earlier one is eight million compares per
		 * document - milliseconds, per object, on the scan path. A
		 * collision in the filter costs the walk it saved and only
		 * then; a duplicate is rare and a false hit on 13 bits rarer.
		 *
		 * See KOF_PDF_ANOM_OBJ_REDEFINED for why this is recorded and
		 * not resolved: an incrementally updated document does it on
		 * purpose, and which definition a viewer picks is a question
		 * only the cross reference table answers.
		 */
		{
			uint32_t b = o->num & 8191u;

			if (seen_num[b >> 3] & (uint8_t)(1u << (b & 7u))) {
				uint32_t k;

				for (k = 0; k < p->n_objects; k++)
					if (p->object[k].num == o->num &&
					    p->object[k].gen == o->gen) {
						p->anomalies |=
						    KOF_PDF_ANOM_OBJ_REDEFINED;
						o->flags |=
						    KOF_PDF_OBJ_REDEFINED;
						break;
					}
			}
			seen_num[b >> 3] |= (uint8_t)(1u << (b & 7u));
		}

		if (o != &spill)
			p->n_objects++;
		p->declared_objects++;
		if (stop > at)
			at = stop;
	}

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
	{
		uint32_t oi = 0;

		at = hdr;
		while (at < file.n) {
			uint64_t h = find_bytes(file, at, file.n, "xref", 4u);
			uint64_t xend, s_lim;

			if (h == KOF_BROKEN)
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

			xend = xref_section_end(file, h);
			if (xend == KOF_BROKEN || xend <= h)
				continue;
			kof_runs_add(&runs, file.n, h, xend - h,
				     KOF_PDF_CLS_HEADER);
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
				dict_scan(file, h, xend - h, &t, p, 0);
			}
			if (xend > at)
				at = xend;
		}
	}

	/* Both bits are read AFTER the settle, because the settle is what finds an
	 * overlap - it is the pass that sorts the runs and trims one against the
	 * next. Read before it, the bit was always clear and a PDF whose objects
	 * claimed each other's bytes was reported as an ordinary one. */
	kof_runs_settle(&runs, p->region_bytes);
	if (runs.full)
		p->anomalies |= KOF_PDF_ANOM_EXTENTS_FULL;
	if (runs.overlapped)
		p->anomalies |= KOF_PDF_ANOM_OVERLAP;
	p->n_runs = runs.n;

	ctx->obj_size = file.n;
	ctx->format = KOF_FMT_PDF;
	ctx->file_header = p;
	ctx->resolve_scan = pdf_resolve_scan;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */


#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_pdf_region_bits[] = { PDF_REGIONS(X_BIT) };
_Static_assert(sizeof kof_pdf_region_bits / sizeof kof_pdf_region_bits[0] ==
	       KOF_PDF_REGION_COUNT, "region list and its count disagree");

const char *kof_pdf_region_name(uint32_t bit)
{
	switch (bit) {
	PDF_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_pdf_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"HEADER_OFFSET", "NO_EOF", "NO_XREF",
		"BAD_STARTXREF", "OBJECTS_FULL", "EXTENTS_FULL", "OVERLAP",
		"STREAM_UNTERM", "ENCRYPTED", "JS", "OPENACTION", "LAUNCH",
		"EMBEDDED", "OBJSTM", "UNKNOWN_FILTER", "TRUNCATED",
		"LENGTH_BAD", "STREAM_DECOY", "LENGTH_INDIR",
		"NAME_ESCAPED", "OBJ_REDEFINED"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_PDF_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
