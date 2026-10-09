/*
 * object_label - what an object is called, from the state the engine holds.
 *
 * The label is crafted in the engine so a tool shows it and does not compose
 * it, and the order in which the answers are tried is the whole of its logic:
 * the module that opened the object says the most, a normalised view says what
 * it is a view of, a script says its language, and the format's name is what is
 * left. Each is asserted, and so is the one the order exists to get right - a
 * name the engine gave outranks "Norm", and a script with no language known is
 * "Script" and not a language it was never recognised as.
 */
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/script.h"

static int fails;

#define EQ(got, want) do { \
	if (strcmp((got), (want))) { \
		printf("  FAIL %s:%d\n    got  \"%s\"\n    want \"%s\"\n", \
		       __FILE__, __LINE__, (got), (want)); \
		fails++; \
	} \
} while (0)

static const char *label(uint32_t kind, const char *packer, uint8_t fmt,
			 uint8_t sub)
{
	static char b[48];

	kof_object_label(kind, packer, fmt, sub, b, sizeof b);
	return b;
}

int main(void)
{
	char tiny[6];

	/* The format's own name, for an object nothing opened. */
	EQ(label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_PE, 0), "PE");
	EQ(label(KOF_ENT_UNKNOWN, "", KOF_FMT_ELF, 0), "ELF");
	EQ(label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_UNKNOWN, 0), "Raw");

	/* A script by its language; one whose language is not known by its format. */
	EQ(label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_SCRIPT, KOF_SCRIPT_PHP), "PHP");
	EQ(label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_SCRIPT, KOF_SCRIPT_ANY), "Script");

	/* A normalised view says so. */
	EQ(label(KOF_ENT_NORMALIZED, NULL, KOF_FMT_PE, 0), "Norm");

	/* The module that opened the object outranks all of them. */
	EQ(label(KOF_ENT_NORMALIZED, "Unwrap:Gzip?Deflate", KOF_FMT_GZIP, 0),
	   "Unwrap:Gzip?Deflate");
	EQ(label(KOF_ENT_UNKNOWN, "PE:UPX 3.95", KOF_FMT_PE, 0), "PE:UPX 3.95");

	/* The subtype is read for a script and for nothing else. */
	EQ(label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_ELF, KOF_SCRIPT_PHP), "ELF");

	/* Cut at the buffer, never past it, and NUL terminated. */
	kof_object_label(KOF_ENT_UNKNOWN, "Unwrap:Zip?Deflate", KOF_FMT_ZIP, 0,
			 tiny, sizeof tiny);
	EQ(tiny, "Unwra");

	printf("object label: packer, Norm, script language, format name, cut%s\n",
	       fails ? " - FAILED" : " - ok");
	return fails != 0;
}
