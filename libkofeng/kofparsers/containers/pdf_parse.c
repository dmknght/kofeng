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
	{ "/AcroForm",    9u, KOF_PDF_OBJ_ACROFORM,   0 }
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
		      struct kof_pdf_object *o, struct kof_pdf_info *p)
{
	uint64_t end = off + len, at = off;
	uint32_t i, filter_seen = 0, known = 0;

	if (!len || end > f.n)
		return;

	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint64_t pos, left;

		if (!sl)
			break;
		pos = (uint64_t)(sl - f.p);
		left = end - pos;
		at = pos + 1u;

		for (i = 0; i < sizeof MARKERS / sizeof MARKERS[0]; i++)
			if (MARKERS[i].n <= left &&
			    memcmp(f.p + pos, MARKERS[i].s, MARKERS[i].n) == 0) {
				o->flags |= MARKERS[i].bit;
				p->anomalies |= MARKERS[i].anom;
			}
		for (i = 0; i < sizeof FILTERS / sizeof FILTERS[0]; i++)
			if (FILTERS[i].n <= left &&
			    memcmp(f.p + pos, FILTERS[i].s, FILTERS[i].n) == 0) {
				o->filters |= FILTERS[i].bit;
				known++;
			}
		if (left >= 7u && memcmp(f.p + pos, "/Filter", 7u) == 0)
			filter_seen = 1;
	}

	/* A filter this build does not know is recorded rather than assumed to be
	 * Flate - the decision the unpacker makes rests on it. */
	if (filter_seen && !known) {
		o->filters |= KOF_PDF_F_OTHER;
		p->anomalies |= KOF_PDF_ANOM_UNKNOWN_FILTER;
	}
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t pdf_cls_bit[KOF_PDF_CLS_COUNT] = {
	KOF_SCAN_PDF_HEADER,
	KOF_SCAN_PDF_OBJECTS,
	KOF_SCAN_PDF_STREAM_PLAIN,
	KOF_SCAN_PDF_STREAM_PACKED
};

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

	memset(p, 0, sizeof *p);
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

	/* The header line itself, through the end of the version. */
	kof_runs_add(&runs, file.n, 0, hdr + 8u <= file.n ? hdr + 8u : file.n,
		     KOF_PDF_CLS_HEADER);

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
			at = h + 5u;
		}
		if (eof == KOF_BROKEN)
			p->anomalies |= KOF_PDF_ANOM_NO_EOF;
		else {
			p->eof_off = eof;
			kof_runs_add(&runs, file.n, eof, 5u, KOF_PDF_CLS_HEADER);
		}

		sx = KOF_BROKEN;
		for (at = from; at < file.n; ) {
			uint64_t h = find_bytes(file, at, file.n, "startxref", 9u);

			if (h == KOF_BROKEN)
				break;
			sx = h;
			at = h + 9u;
		}
		if (sx == KOF_BROKEN) {
			p->anomalies |= KOF_PDF_ANOM_NO_XREF;
		} else {
			uint64_t i = sx + 9u, v = 0;
			int any = 0;

			kof_runs_add(&runs, file.n, sx, 9u, KOF_PDF_CLS_HEADER);
			while (i < file.n && is_ws(file.p[i]))
				i++;
			while (i < file.n && is_digit(file.p[i]) && v < (1ull << 60)) {
				v = v * 10u + (uint64_t)(file.p[i] - '0');
				i++;
				any = 1;
			}
			p->startxref = any ? v : 0;
			if (!any || v >= file.n)
				p->anomalies |= KOF_PDF_ANOM_BAD_STARTXREF;
		}
		if (find_bytes(file, from, file.n, "/Encrypt", 8u) != KOF_BROKEN)
			p->anomalies |= KOF_PDF_ANOM_ENCRYPTED;
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
		uint64_t start, end, dict_end, s_kw, s_end;
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

		if (s_kw == KOF_BROKEN) {
			dict_end = end;
		} else {
			uint64_t d = s_kw + 6u;

			dict_end = s_kw;
			/* The data begins after the EOL that must follow the
			 * keyword; both CRLF and LF appear. */
			if (d < file.n && file.p[d] == '\r')
				d++;
			if (d < file.n && file.p[d] == '\n')
				d++;
			s_end = find_bytes(file, d, file.n, "endstream", 9u);
			if (s_end == KOF_BROKEN) {
				p->anomalies |= KOF_PDF_ANOM_STREAM_UNTERM;
				s_end = end;
			}
			if (s_end > d) {
				o->stream_off = d;
				o->stream_len = s_end - d;
				o->flags |= KOF_PDF_OBJ_STREAM;
				p->n_streams++;
				if (o->len < (s_end - start))
					o->len = s_end - start;
			}
		}

		o->dict_off = start;
		o->dict_len = dict_end > start ? dict_end - start : 0;
		dict_scan(file, o->dict_off, o->dict_len, o, p);

		kof_runs_add(&runs, file.n, o->dict_off, o->dict_len,
			     KOF_PDF_CLS_OBJECTS);
		if (o->stream_len)
			kof_runs_add(&runs, file.n, o->stream_off, o->stream_len,
				     o->filters ? KOF_PDF_CLS_STREAM_PACKED
						: KOF_PDF_CLS_STREAM_PLAIN);
		/* The tail of the object - "endstream endobj" - is structure. */
		if (o->stream_len) {
			uint64_t tail = o->stream_off + o->stream_len;

			if (end > tail)
				kof_runs_add(&runs, file.n, tail, end - tail,
					     KOF_PDF_CLS_OBJECTS);
		}

		if (o != &spill)
			p->n_objects++;
		p->declared_objects++;
		if (end > at)
			at = end;
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
		"EMBEDDED", "OBJSTM", "UNKNOWN_FILTER", "TRUNCATED"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_PDF_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
