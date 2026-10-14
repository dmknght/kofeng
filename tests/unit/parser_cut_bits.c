/*
 * parser_cut_bits - a table of a parser that filled is a cut the object SAYS.
 *
 * Parsers set a *_FULL anomaly bit when a table of the parse is full and what is past it
 * was not read; the engine reads the word once after the parse (sx_facts) through
 * kof_parser_cut_bits and the object comes back broken = KOF_BROKEN_LIMIT. A bit that
 * nothing read was a member gone with no word anywhere. This holds:
 *
 *   - the table of bits per format names every "full" bit the parsers set (script
 *     islands, PDF extents, registry extents, the three OLE bits that are not the
 *     module's own, ZIP entries and extents, 7z folders), and none that a module
 *     already reports itself (OLE ENTRIES_FULL is docole.c's: not reported twice);
 *   - end to end: a script with more code islands than the parse describes comes back
 *     broken = LIMIT, and one with fewer does not.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "../../libkofeng/kofcore/kofmod/script.h"
#include "../../libkofeng/kofcore/kofmod/pdf.h"
#include "../../libkofeng/kofcore/kofmod/reg.h"
#include "../../libkofeng/kofcore/kofmod/docole.h"
#include "../../libkofeng/kofcore/kofmod/zip.h"
#include "../../libkofeng/kofcore/kofmod/sevenzip.h"
#include "../../libkofeng/kofcore/kofmod/tar.h"
#include "../../libkofeng/kofcore/kofmod/rar.h"

static uint64_t bits_of(uint8_t fmt)
{
	return kof_parser_cut_bits(kof_parser_of(fmt));
}

static void table(void)
{
	CK(bits_of(KOF_FMT_SCRIPT) == KOF_SCRIPT_ANOM_ISLANDS_FULL);
	CK((bits_of(KOF_FMT_PDF) & KOF_PDF_ANOM_OBJECTS_FULL) && (bits_of(KOF_FMT_PDF) & KOF_PDF_ANOM_EXTENTS_FULL));
	CK(bits_of(KOF_FMT_REG) == KOF_REG_ANOM_EXTENTS_FULL);
	CK((bits_of(KOF_FMT_DOCOLE) & KOF_DOCOLE_ANOM_ENT_RUNS_FULL) != 0);
	CK((bits_of(KOF_FMT_DOCOLE) & KOF_DOCOLE_ANOM_DIR_OVERFLOW) != 0);
	CK((bits_of(KOF_FMT_DOCOLE) & KOF_DOCOLE_ANOM_EXTENTS_FULL) != 0);
	CK((bits_of(KOF_FMT_DOCOLE) & KOF_DOCOLE_ANOM_ENTRIES_FULL) != 0);   /* the engine's now, not the module's */
	CK((bits_of(KOF_FMT_DOCOLE) & KOF_DOCOLE_ANOM_WORK_FULL) != 0);
	CK((bits_of(KOF_FMT_DOCOLE) & KOF_DOCOLE_ANOM_DIR_DEPTH) == 0);      /* noted, not a limit */
	CK((bits_of(KOF_FMT_TAR) & KOF_TAR_ANOM_ENTRIES_FULL) && (bits_of(KOF_FMT_TAR) & KOF_TAR_ANOM_EXTENTS_FULL));
	CK((bits_of(KOF_FMT_RAR) & KOF_RAR_ANOM_ENTRIES_FULL) && (bits_of(KOF_FMT_RAR) & KOF_RAR_ANOM_EXTENTS_FULL));
	CK((bits_of(KOF_FMT_ZIP) & KOF_ZIP_ANOM_ENTRIES_FULL) && (bits_of(KOF_FMT_ZIP) & KOF_ZIP_ANOM_EXTENTS_FULL));
	CK(bits_of(KOF_FMT_7Z) == KOF_7Z_ANOM_FOLDERS_FULL);
	/* the five that were there */
	CK(bits_of(KOF_FMT_ARJ) != 0 && bits_of(KOF_FMT_LHA) != 0 && bits_of(KOF_FMT_CAB) != 0 &&
	   bits_of(KOF_FMT_CHM) != 0);
	/* and formats with nothing of the kind */
	CK(bits_of(KOF_FMT_ELF) == 0 && bits_of(KOF_FMT_PE) == 0);
	CK(kof_parser_cut_bits(NULL) == 0);
}

/* A page with a <script> body per island and markup after the last: the markup parse is
 * the one that lists islands (markup_parse.c) and says so when it ran out. */
#define ISL "<script>x=1;</script>\n"

static uint8_t *script_of(unsigned islands, size_t *len)
{
	size_t il = strlen(ISL), cap = (size_t)islands * il + 64u, at = 0;
	uint8_t *b = malloc(cap);
	unsigned i;

	if (!b)
		return NULL;
	for (i = 0; i < islands; i++) {
		memcpy(b + at, ISL, il);
		at += il;
	}
	memcpy(b + at, "<p>tail text after the last script</p>\n", 39);
	at += 39u;
	*len = at;
	return b;
}

static void e2e_islands(void)
{
	struct e2e r;
	size_t len;
	uint8_t *few = script_of(40, &len), *many;
	size_t len2;
	unsigned i, broke_few = 0, broke_many = 0;

	if (!e2e_open(NULL)) {
		printf("  (no test database: end to end skipped)\n");
		free(few);
		return;
	}
	CK(few != NULL);
	if (few) {
		(void)e2e_scan(few, len, &r);
		for (i = 0; i < r.n; i++)
			broke_few += r.o[i].broken == KOF_BROKEN_LIMIT;
	}
	many = script_of(KOF_SCRIPT_MAX_ISLAND + 40u, &len2);
	CK(many != NULL);
	if (many) {
		(void)e2e_scan(many, len2, &r);
		for (i = 0; i < r.n; i++)
			broke_many += r.o[i].broken == KOF_BROKEN_LIMIT;
	}
	CK(broke_few == 0u);
	CK(broke_many >= 1u);
	free(few);
	free(many);
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	table();
	e2e_islands();
	if (fails) {
		printf("parser_cut_bits: %d check(s) failed\n", fails);
		return 1;
	}
	printf("parser_cut_bits: every 'table full' bit a parser sets is read; a script with too many islands is cut\n");
	return 0;
}
