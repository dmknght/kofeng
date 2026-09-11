/*
 * pdf_chain.c - what the parse says about a stream's coding, case by case.
 *
 * kof_entry.coding is the field the host runs, in the order it is written, and
 * the flag beside it is what stops a chain being run halfway. Both are derived
 * from a dictionary the file wrote, and getting either wrong is not visible in
 * any other column: a stream reported as stored and a stream coded by something
 * this build lacks look identical everywhere except here, and they lead to
 * opposite conclusions about what a rule will see.
 *
 * So this is a table of every shape a /Filter can take, each built on purpose,
 * with the chain and the flag it must produce. It is cheap - the parse only, no
 * engine, no database - which is the point: the thing most likely to drift
 * silently is the mapping, and a test that needs a scan to run is a test that
 * gets skipped.
 *
 * What it does NOT cover: whether the decoders are correct. That is the
 * decompressor's own question and belongs with the other differential tests.
 * This covers whether the parse tells the host the truth about what to run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/core/kofplatform.h"
#include "../../libkofeng/kofparsers/containers/pdf_parse.h"

static uint32_t fails;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	fails++;
}

/*
 * One object per case, so a case cannot be perturbed by its neighbours.
 *
 * The stream body is five bytes of nothing: this is about the DICTIONARY, and
 * real coded data would make each case a test of a decoder as well - two
 * questions in one assertion, which is how a failure stops telling you which
 * half broke.
 */
struct kase {
	const char *name;
	const char *dict;
	uint16_t    coding[4];
	int         incomplete;
};

static const struct kase CASES[] = {
	{ "bare flate",
	  "/Filter /FlateDecode /Length 5",
	  { KOF_UNP_ZLIB, 0, 0, 0 }, 0 },
	{ "flate in an array",
	  "/Filter [ /FlateDecode ] /Length 5",
	  { KOF_UNP_ZLIB, 0, 0, 0 }, 0 },
	/*
	 * The pair that put the array there. Named in order, both steps, and
	 * NOT flagged - this build can run both, so there is nothing missing.
	 */
	{ "ascii85 then flate",
	  "/Filter [ /ASCII85Decode /FlateDecode ] /Length 5",
	  { KOF_UNP_ASCII85, KOF_UNP_ZLIB, 0, 0 }, 0 },
	{ "ascii85 alone",
	  "/Filter /ASCII85Decode /Length 5",
	  { KOF_UNP_ASCII85, 0, 0, 0 }, 0 },
	/*
	 * A predictor is not a filter - it transforms what the filter produced
	 * - so the chain is right AND incomplete at once. This is the case that
	 * looks runnable and is not.
	 */
	{ "flate with a png predictor",
	  "/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 5 >> /Length 5",
	  { KOF_UNP_ZLIB, 0, 0, 0 }, 1 },
	/* 1 is the format's default and means no prediction. */
	{ "flate with predictor 1",
	  "/Filter /FlateDecode /DecodeParms << /Predictor 1 >> /Length 5",
	  { KOF_UNP_ZLIB, 0, 0, 0 }, 0 },
	{ "an indirect predictor is treated as present",
	  "/Filter /FlateDecode /DecodeParms << /Predictor 9 0 R >> /Length 5",
	  { KOF_UNP_ZLIB, 0, 0, 0 }, 1 },
	/* Four fit; a fifth cannot be written down, so it is reported. */
	{ "exactly four",
	  "/Filter [ /FlateDecode /FlateDecode /FlateDecode /FlateDecode ] /Length 5",
	  { KOF_UNP_ZLIB, KOF_UNP_ZLIB, KOF_UNP_ZLIB, KOF_UNP_ZLIB }, 0 },
	{ "five is one too many",
	  "/Filter [ /FlateDecode /FlateDecode /FlateDecode /FlateDecode "
	  "/FlateDecode ] /Length 5",
	  { KOF_UNP_ZLIB, KOF_UNP_ZLIB, KOF_UNP_ZLIB, KOF_UNP_ZLIB }, 1 },
	/* The other two transport codings, both decodable now. */
	{ "asciihex",
	  "/Filter /ASCIIHexDecode /Length 5",
	  { KOF_UNP_ASCIIHEX, 0, 0, 0 }, 0 },
	{ "runlength",
	  "/Filter /RunLengthDecode /Length 5",
	  { KOF_UNP_RUNLENGTH, 0, 0, 0 }, 0 },
	/* ASCIIHex is bounded by its input, so it may be a middle step. */
	{ "asciihex then flate",
	  "/Filter [ /ASCIIHexDecode /FlateDecode ] /Length 5",
	  { KOF_UNP_ASCIIHEX, KOF_UNP_ZLIB, 0, 0 }, 0 },
	{ "lzw",
	  "/Filter /LZWDecode /Length 5",
	  { KOF_UNP_LZW, 0, 0, 0 }, 0 },
	/*
	 * /EarlyChange 0 changes what the decoder must do, and this build does
	 * the default. Named AND flagged: the chain is right about what the
	 * coding is, and wrong to run - which is the case that would otherwise
	 * decode to plausible garbage rather than to nothing.
	 */
	{ "lzw with early change off",
	  "/Filter /LZWDecode /DecodeParms << /EarlyChange 0 >> /Length 5",
	  { KOF_UNP_LZW, 0, 0, 0 }, 1 },
	/* And an EarlyChange that says what this build does is not a refusal. */
	{ "lzw with early change 1",
	  "/Filter /LZWDecode /DecodeParms << /EarlyChange 1 >> /Length 5",
	  { KOF_UNP_LZW, 0, 0, 0 }, 0 },
	/*
	 * A filter with no decoder here. Empty chain AND the flag - empty alone
	 * would read as stored, which is the opposite of the truth. CCITTFax is
	 * an image coding, which this build deliberately does not do.
	 */
	{ "a coding this build lacks",
	  "/Filter /CCITTFaxDecode /Length 5",
	  { 0, 0, 0, 0 }, 1 },
	/* /Crypt does not end in "Decode" and is still a filter. A test that
	 * spelled the rule as "ends in Decode" would pass everything above and
	 * miss this. */
	{ "crypt is a filter too",
	  "/Filter /Crypt /Length 5",
	  { 0, 0, 0, 0 }, 1 },
	{ "no filter at all is stored",
	  "/Length 5",
	  { 0, 0, 0, 0 }, 0 }
};

#define N_CASES (sizeof CASES / sizeof CASES[0])

/* One document per case. Built rather than fixtured so the dictionary under
 * test is visible beside the expectation. */
static uint64_t build(const struct kase *k, uint8_t *out, uint64_t cap)
{
	int n = snprintf((char *)out, (size_t)cap,
			 "%%PDF-1.7\n"
			 "1 0 obj\n<<\n%s\n>>\nstream\nABCDE\nendstream\nendobj\n"
			 "trailer\n<< /Size 2 >>\nstartxref\n0\n%%%%EOF\n",
			 k->dict);

	return (n > 0 && (uint64_t)n < cap) ? (uint64_t)n : 0;
}

int main(void)
{
	static uint8_t doc[4096];
	struct kof_pdf_info *info = calloc(1, sizeof *info);
	uint32_t c;

	if (!info) {
		printf("pdf chain: out of memory\n");
		return 1;
	}

	for (c = 0; c < N_CASES; c++) {
		const struct kase *k = &CASES[c];
		struct kof_obj_ctx ctx;
		const struct kof_entry *tab = NULL;
		uint64_t n = build(k, doc, sizeof doc);
		uint32_t rows, j;
		int got_flag;

		if (!n) {
			fail(k->name, "the document did not fit");
			continue;
		}
		memset(&ctx, 0, sizeof ctx);
		if (!kof_pdf_parse(kof_buf_make(doc, n), info, &ctx)) {
			fail(k->name, "the parse refused a document it wrote");
			continue;
		}
		if (!ctx.entries) {
			fail(k->name, "no entry table");
			continue;
		}
		rows = ctx.entries(&ctx, &tab);
		if (rows != 1u || !tab) {
			fail(k->name, "one stream should be one entry");
			continue;
		}

		for (j = 0; j < 4u; j++)
			if (tab[0].coding[j] != k->coding[j]) {
				char why[128];

				snprintf(why, sizeof why,
					 "coding[%u] is %u, expected %u", j,
					 (unsigned)tab[0].coding[j],
					 (unsigned)k->coding[j]);
				fail(k->name, why);
				break;
			}

		got_flag = (tab[0].flags & KOF_ENT_F_CODED_UNKNOWN) != 0;
		if (got_flag != k->incomplete)
			fail(k->name, got_flag
				      ? "flagged incomplete and should not be"
				      : "not flagged, but a step is missing");
	}

	free(info);
	printf("pdf chain: %u case(s)%s\n", (unsigned)N_CASES,
	       fails ? " FAILED" : " ok");
	return fails ? 1 : 0;
}
