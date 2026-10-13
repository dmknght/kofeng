/*
 * pdf_dict.c - what one object's dictionary announces.
 *
 * WHAT THIS SERVES: the walk hands over the bytes between "obj" and what ends
 * the dictionary; this reads them for the markers a document is judged by
 * (/JavaScript, /Launch, /EmbeddedFile ...), the filters a stream names, the
 * category it declares and the length it states. Nothing here decides what the
 * document is: it sets bits on the object and on the view.
 */

#include "pdf_int.h"

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
	{ "/Font",         5u, KOF_PDF_CAT_FONT }
};

/* An image coding IS the statement that these bytes are pixels, and it is
 * there on the streams that declare no /Type at all - which the measurement
 * in kofmod/pdf.h says is most of them. */
#define PDF_F_IS_IMAGE (KOF_PDF_F_DCT | KOF_PDF_F_CCITT | \
			KOF_PDF_F_JBIG2 | KOF_PDF_F_JPX)

/* Which of the format's filters this name is, or -1 for none of them. */
int pdf_find_filter(const uint8_t *name, uint32_t nm)
{
	uint32_t i;

	for (i = 0; i < sizeof FILTERS / sizeof FILTERS[0]; i++)
		if (nm == FILTERS[i].n &&
		    memcmp(name, FILTERS[i].s, (size_t)nm) == 0)
			return (int)i;
	return -1;
}

/* The KOF_PDF_F_ bit of the filter pdf_find_filter answered. */
uint32_t pdf_filter_bit(int i)
{
	return FILTERS[i].bit;
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
void pdf_dict_scan(kof_buf f, uint64_t off, uint64_t len,
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
	/* Set by /EF so that the /F or /UF immediately inside it reads as a
	 * reference to a carried file, and ONLY there. /F is among the most
	 * common keys the format has - a flag word in an annotation, the file
	 * name in the very Filespec that holds this /EF - so honouring it
	 * anywhere else would turn any of those into an attachment. */
	int want_ef = 0;

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
		n = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (esc) {
			o->flags |= KOF_PDF_OBJ_NAME_ESC;
			p->anomalies |= KOF_PDF_ANOM_NAME_ESCAPED;
		}

		/*
		 * THE WHOLE NAME, not a prefix, and that is a fix and not a
		 * tightening: /AA is three bytes and matched /AAPL, /JS
		 * matched anything beginning /JS. A name ends where
		 * pdf_name_decode stopped, so its length is known and equality is
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
		/*
		 * /FontFile* DESCRIBES ANOTHER OBJECT, NOT THIS ONE.
		 *
		 * It used to set the category here, which made the FONT the
		 * descriptor - a 200 byte dictionary of metrics - while the
		 * font PROGRAM, which is the quarter megabyte that matters,
		 * stayed CONTENT. The key is a reference; what it points at is
		 * the font.
		 */
		if (!o->ref_num && n >= 9u &&
		    memcmp(name, "/FontFile", 9u) == 0) {
			o->ref_num = pdf_read_ref(f, raw_end, end);
			o->ref_cat = KOF_PDF_CAT_FONT;
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
			*declared_len = pdf_read_length(f, raw_end, end, p);
		/* Where the script actually is, when it is not here. See
		 * kof_pdf_object.ref_num for why this kind of reference is
		 * worth following and the page tree is not. */
		if (!o->ref_num &&
		    ((n == 3u && memcmp(name, "/JS", 3u) == 0) ||
		     (n == 11u && memcmp(name, "/JavaScript", 11u) == 0))) {
			o->ref_num = pdf_read_ref(f, raw_end, end);
			o->ref_cat = KOF_PDF_CAT_SCRIPT;
		}

		/*
		 * WHERE A CARRIED FILE ACTUALLY IS.
		 *
		 * /Type /EmbeddedFile is how a carried file announces itself, and
		 * PDF 32000-1 makes that key OPTIONAL. So a document can attach an
		 * executable in a stream whose entire dictionary is
		 * `<< /Length 63 >>`, and then the only thing identifying it is the
		 * /Filespec that points at it.
		 *
		 * Measured on a file built for exactly that: the stream came out
		 * CONTENT - page drawing operators - which is the worst answer
		 * available for the one kind of stream most worth opening.
		 *
		 * One step, as /JS and /FontFile are followed, and one level in
		 * because /EF is a dictionary: /EF, then /F or /UF. want_ef is what
		 * keeps "one level in" honest.
		 */
		if (want_ef) {
			want_ef = 0;
			if (!o->ref_num &&
			    ((n == 2u && memcmp(name, "/F", 2u) == 0) ||
			     (n == 3u && memcmp(name, "/UF", 3u) == 0))) {
				o->ref_num = pdf_read_ref(f, raw_end, end);
				o->ref_cat = KOF_PDF_CAT_EMBEDDED;
				if (!o->ref_num)
					p->anomalies |=
					    KOF_PDF_ANOM_EF_UNRESOLVED;
			}
		}
		if (n == 3u && memcmp(name, "/EF", 3u) == 0) {
			/* `/EF 9 0 R` is two steps and this parse follows one.
			 * Said rather than skipped: the alternative is calling an
			 * attachment page content and reporting nothing. */
			if (pdf_read_ref(f, raw_end, end))
				p->anomalies |= KOF_PDF_ANOM_EF_UNRESOLVED;
			else
				want_ef = 1;
		}
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
	} else {
		o->cat = KOF_PDF_CAT_CONTENT;
	}
	(void)filt_off;
	(void)filt_len;

	/*
	 * NO NAME FROM THE CODING, AND THAT WAS A WRONG TURN WORTH RECORDING.
	 *
	 * cat_off/cat_len were falling back to the filter's own name when the
	 * dictionary declared no type, because a filter name IS bytes that are
	 * in the file and kunp_rcstruct_name needs a range rather than a string. It
	 * built, it named every child, and it read wrong: a document's tree
	 * came out as "//1.FlateDecode //2.FlateDecode //3.FlateDecode", which
	 * is a list of how things are compressed where a reader is looking for
	 * what they are. Twelve of fifteen rows in one document said the same
	 * uninformative word.
	 *
	 * A coding is not a category. So the name is left off entirely when
	 * nothing named a category, and such a child keeps the index the engine
	 * gave it - "//1", which says nothing and does not pretend to. The rows
	 * that DO carry a name carry one worth reading: ObjStm, Image,
	 * Metadata, XRef, EmbeddedFile.
	 *
	 * `cat` itself is still set for every stream - the region machinery
	 * needs it, and CONTENT is a real answer there even where it is not a
	 * name.
	 */
}
