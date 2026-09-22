/*
 * reg_regions - a registry script's keys, values and hex runs land apart.
 *
 * WHAT THIS IS DEFENDING. The reason a .reg is parsed at all is that WHERE a
 * string sits decides what it means: "CurrentVersion\Run" on a key line is a
 * file that writes persistence, and the same characters inside a value's data
 * are a file that mentions it. A rule can only tell those apart if the regions
 * do, so this asserts that each marker comes back in ITS OWN region.
 *
 * THE HEX CONTINUATION IS THE PART THAT BREAKS. Every other line of the format
 * is a line; a hex value runs across as many as it likes behind a trailing
 * backslash. A parser that stopped at the first newline would cut an embedded
 * payload into pieces and hand a rule a fragment of it - so the test builds a
 * value that continues over three lines and asserts the region covers all of
 * them as one.
 *
 * AND THE BLANK LINE, which is not a nicety. line_end stops at '\n', so on a
 * CRLF file a blank line is one byte and that byte is '\r'. The first version
 * of this parser did not count that as blank, so every empty line in every
 * Windows-written .reg raised JUNK_LINE - the anomaly firing on the format's
 * own normal shape. The fixture below is CRLF throughout for that reason.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/analyzer/parsers/containers/reg_parse.h"

static int failures;

static void ok_(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

/* Is `m` inside any range this mask resolves to? */
static int in_region(const struct kof_obj_ctx *ctx, const char *text,
		     uint32_t mask, const char *m)
{
	struct kof_range r[64];
	uint32_t n, i;
	size_t ml = strlen(m);

	n = ctx->resolve_scan(ctx, mask, r, 64u);
	for (i = 0; i < n; i++) {
		uint64_t k;

		if (r[i].len < ml)
			continue;
		for (k = 0; k + ml <= r[i].len; k++)
			if (memcmp(text + r[i].off + k, m, ml) == 0)
				return 1;
	}
	return 0;
}

static const char FIXTURE[] =
	"Windows Registry Editor Version 5.00\r\n"
	"\r\n"
	"; MARKERCOMMENT\r\n"
	"[HKEY_CURRENT_USER\\Software\\MARKERKEY]\r\n"
	"\"Updater\"=\"MARKERVALUE\"\r\n"
	"\"Blob\"=hex:4d,5a,90,00,MARKERHEXA,\\\r\n"
	"  aa,bb,cc,dd,MARKERHEXB,\\\r\n"
	"  ee,ff,00,11,MARKERHEXC\r\n"
	"\r\n"
	"[-HKEY_CURRENT_USER\\Software\\MARKERGONE]\r\n";

int main(void);
int main(void)
{
	kof_buf b = kof_buf_make((const uint8_t *)FIXTURE, sizeof FIXTURE - 1u);
	struct kof_reg_info *info;
	struct kof_obj_ctx ctx;
	static struct kof_reg_info storage;

	info = &storage;
	memset(&ctx, 0, sizeof ctx);

	ok_(kof_reg_sniff(b) != 0, "the sniff claims a version 5 script");
	{
		static const char old[] = "REGEDIT4\r\n\r\n[HKEY_CLASSES_ROOT\\x]\r\n";
		kof_buf o = kof_buf_make((const uint8_t *)old, sizeof old - 1u);

		ok_(kof_reg_sniff(o) != 0, "and the Windows 9x spelling");
	}
	{
		static const char no[] = "[HKEY_CURRENT_USER\\Software\\X]\r\n"
					 "\"a\"=\"b\"\r\n";
		kof_buf o = kof_buf_make((const uint8_t *)no, sizeof no - 1u);

		/* regedit refuses a file with no version line, so this does
		 * too - the shape alone is not the format. */
		ok_(kof_reg_sniff(o) == 0,
		    "a file with keys and no version line is refused");
	}

	if (!kof_reg_parse(b, info, &ctx)) {
		printf("  FAIL the parse refused a well formed script\n");
		return 1;
	}

	ok_(info->valid != 0u, "the version line was understood");
	ok_(info->n_keys == 2u, "both key lines were counted");
	ok_(info->n_values == 2u, "both values were counted");
	ok_(info->n_hex == 1u, "the hex value was recognised as one");
	ok_(info->n_deletes == 1u, "the deletion was counted");
	ok_((info->anomalies & KOF_REG_ANOM_DELETES) != 0,
	    "a script that removes a key says so");
	/*
	 * THE ANOMALY THAT MUST NOT FIRE. Every blank line here is CRLF; if
	 * '\r' is not blank space then all of them are junk.
	 */
	ok_((info->anomalies & KOF_REG_ANOM_JUNK_LINE) == 0,
	    "a CRLF blank line is blank, not junk");
	ok_((info->anomalies & KOF_REG_ANOM_OLD_FORMAT) == 0,
	    "a version 5 script is not reported as the old format");

	/* ---- each marker in its own region ---- */

	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_KEYS, "MARKERKEY"),
	    "the key path is in KEYS");
	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_KEYS, "MARKERGONE"),
	    "the deleted key's path is in KEYS too");
	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_VALUES, "MARKERVALUE"),
	    "the value data is in VALUES");
	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_COMMENT, "MARKERCOMMENT"),
	    "the comment is in COMMENT");

	ok_(!in_region(&ctx, FIXTURE, KOF_SCAN_REG_VALUES, "MARKERKEY"),
	    "a key path does not appear in VALUES");
	ok_(!in_region(&ctx, FIXTURE, KOF_SCAN_REG_KEYS, "MARKERVALUE"),
	    "value data does not appear in KEYS");

	/* ---- the hex run is one region across three lines ---- */

	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_HEX, "MARKERHEXA"),
	    "the hex run's first line is in HEX");
	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_HEX, "MARKERHEXC"),
	    "and its last line, so the continuation was followed");
	/*
	 * ONE RUN AND NOT THREE. A rule matching a pattern that straddles a
	 * line break only works if the region is continuous, which is the
	 * whole point of following the backslash.
	 */
	ok_(in_region(&ctx, FIXTURE, KOF_SCAN_REG_HEX,
		      "MARKERHEXA,\\\r\n  aa,bb,cc,dd,MARKERHEXB"),
	    "the run is continuous across the line break");
	ok_(!in_region(&ctx, FIXTURE, KOF_SCAN_REG_HEX, "\"Blob\""),
	    "the value's name stays in VALUES, not in HEX");

	/* ---- and the partition holds ---- */
	{
		struct kof_range r[64];
		uint32_t n, i;
		uint64_t total = 0;

		n = ctx.resolve_scan(&ctx, KOF_SCAN_REG_CLAIMED |
					   KOF_SCAN_REG_UNCLAIMED, r, 64u);
		for (i = 0; i < n; i++)
			total += r[i].len;
		ok_(total == sizeof FIXTURE - 1u,
		    "the regions cover the object exactly once");
	}

	if (failures) {
		printf("reg regions: %d check(s) failed\n", failures);
		return 1;
	}
	printf("reg regions: sniff, keys apart from values, a hex run across "
	       "three lines, deletions, CRLF blanks, the partition - ok\n");
	return 0;
}
