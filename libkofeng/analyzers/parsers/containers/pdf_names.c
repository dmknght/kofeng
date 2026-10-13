/*
 * pdf_names.c - the names of a PDF's regions and anomalies, for tools.
 */

#include "pdf_int.h"

/* ---- names, for tools --------------------------------------------------------- */


#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_pdf_region_bits[] = { PDF_REGIONS(X_BIT) };

/*
 * THE NAME LIST AND THE CLASS LIST NAME THE SAME BITS.
 *
 * Two asserts, and it takes both. The union catches a region that one list has
 * and the other does not. The count catches the case the union cannot see - a
 * name listed twice while another is missing, which leaves the union short and
 * would be caught, or a name listed twice with none missing, which leaves the
 * union right and the length wrong.
 *
 * WHY IT MATTERS MORE THAN IT LOOKS. A signature writer picks a region by NAME,
 * in kofviewer or in a rule source, and ksigbuilder turns that name into a bit
 * through this list. The parse files bytes into regions by CLASS, through
 * pdf_cls_bit. A name in one list and not the other is therefore either a
 * region a rule can ask for and no byte is ever in - a rule that silently
 * matches nothing - or bytes filed into a region no rule can spell. Both are
 * silent, and both are what these two lines are for.
 */
#define X_RGN_OR(b) | (b)
_Static_assert((0u PDF_REGIONS(X_RGN_OR)) ==
	       (KOF_SCAN_PDF_CLAIMED | KOF_SCAN_PDF_UNCLAIMED),
	       "PDF_REGIONS and KOF_PDF_CLASSES name different region bits");
#undef X_RGN_OR
_Static_assert(sizeof kof_pdf_region_bits / sizeof kof_pdf_region_bits[0] ==
	       KOF_PDF_REGION_COUNT,
	       "PDF_REGIONS is not the classes plus UNCLAIMED");

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
		"NAME_ESCAPED", "OBJ_REDEFINED", "EF_UNRESOLVED"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_PDF_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
