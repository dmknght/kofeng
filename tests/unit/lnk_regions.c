/*
 * lnk_regions - a shell link's five strings land on the right bytes.
 *
 * WHAT THIS IS DEFENDING. A .lnk has no offset table: the id list says how
 * long it is, the link info says how long IT is, and each of the five strings
 * is a character count. So the COMMAND_LINE_ARGUMENTS - the only part anybody
 * scans a shortcut for - can only be reached by having measured everything in
 * front of it correctly, and a parser that got one length wrong publishes a
 * region pointing at the wrong bytes rather than failing. Nothing would say so.
 *
 * So the fixture is built with a distinct marker in every string, and the test
 * asserts that each region contains ITS OWN marker and no other's. An off-by-
 * one in the id list, a byte count read as a character count, or the five
 * strings taken in the wrong order all move at least one marker into the wrong
 * region, and every one of those is a real way to get this format wrong.
 *
 * BUILT FROM BYTES, so it needs no sample and runs on every host. The layout
 * is MS-SHLLINK's; see kofmod/lnk.h.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofparsers/containers/lnk_parse.h"

static int failures;

static void ok_(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static void w16(uint8_t *p, unsigned v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void w32(uint8_t *p, unsigned long v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static const uint8_t CLSID[16] = {
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

/* A counted UTF-16LE string. Returns where the next one goes. */
static uint32_t put_str(uint8_t *f, uint32_t at, const char *s)
{
	uint32_t n = (uint32_t)strlen(s), i;

	w16(f + at, n);
	at += 2u;
	for (i = 0; i < n; i++) {
		f[at + i * 2u]      = (uint8_t)s[i];
		f[at + i * 2u + 1u] = 0;
	}
	return at + n * 2u;
}

/* Does the range [off,len) hold this ASCII marker, read as UTF-16LE? */
static int has_marker(const uint8_t *f, uint64_t off, uint64_t len,
		      const char *m)
{
	uint64_t n = strlen(m), i, j;

	if (len < n * 2u)
		return 0;
	for (i = 0; i + n * 2u <= len; i += 2u) {
		for (j = 0; j < n; j++)
			if (f[off + i + j * 2u] != (uint8_t)m[j] ||
			    f[off + i + j * 2u + 1u] != 0)
				break;
		if (j == n)
			return 1;
	}
	return 0;
}

#define M_NAME "MARKERNAME"
#define M_REL  "MARKERREL"
#define M_WORK "MARKERWORK"
#define M_ICON "\\\\host\\share\\MARKERICON"

int main(void);
int main(void)
{
	uint8_t *f = calloc(1, 4096);
	struct kof_lnk_info *k = calloc(1, sizeof *k);
	struct kof_obj_ctx ctx;
	uint32_t at, idlist_len = 24u, args_chars;
	char args[600];
	uint64_t flen;

	if (!f || !k) {
		printf("lnk regions: out of memory\n");
		free(f);
		free(k);
		return 1;
	}

	/*
	 * A command line past KOF_LNK_ARGS_LONG, which is what an encoded
	 * payload in a shortcut looks like and what the anomaly is for.
	 */
	memset(args, 'A', sizeof args - 1);
	args[sizeof args - 1] = '\0';
	memcpy(args, "MARKERARGS", 10);
	args_chars = (uint32_t)strlen(args);

	w32(f + 0, 76);
	memcpy(f + 4, CLSID, sizeof CLSID);
	w32(f + 20, KOF_LNK_HAS_IDLIST | KOF_LNK_HAS_NAME |
		    KOF_LNK_HAS_RELPATH | KOF_LNK_HAS_WORKDIR |
		    KOF_LNK_HAS_ARGS | KOF_LNK_HAS_ICON |
		    KOF_LNK_IS_UNICODE);
	at = 76u;

	/* The id list: a length and that many bytes this does not decode. */
	w16(f + at, (unsigned)idlist_len);
	at += 2u;
	memset(f + at, 0x41, idlist_len);
	at += idlist_len;

	/* The five strings, in the order the format stores them. */
	at = put_str(f, at, M_NAME);
	at = put_str(f, at, M_REL);
	at = put_str(f, at, M_WORK);
	at = put_str(f, at, args);
	at = put_str(f, at, M_ICON);

	/* One ExtraData block, then the terminal size-under-four. */
	w32(f + at, 12);
	w32(f + at + 4u, 0xA0000001u);   /* EnvironmentVariableDataBlock */
	at += 12u;
	w32(f + at, 0);
	at += 4u;
	flen = at;

	ok_(kof_lnk_sniff(kof_buf_make(f, flen)), "the sniff claims it");
	memset(&ctx, 0, sizeof ctx);
	if (!kof_lnk_parse(kof_buf_make(f, flen), k, &ctx)) {
		printf("  FAIL the parse refused a well formed link\n");
		free(f);
		free(k);
		return 1;
	}

	ok_(k->valid != 0u, "the header agreed");
	ok_(k->unicode != 0u, "the strings were read as UTF-16");
	ok_(k->idlist_len == idlist_len, "the id list was measured");
	ok_(k->args.chars == args_chars, "the arguments kept their length");

	/*
	 * EACH MARKER IN ITS OWN REGION AND NOWHERE ELSE. This is the whole
	 * test: a length read wrongly anywhere ahead of a string slides every
	 * string after it, and the only way to catch that is to look at what
	 * the region actually contains.
	 */
	ok_(has_marker(f, k->name.off, k->name.len, M_NAME),
	    "NAME holds the description");
	ok_(has_marker(f, k->relpath.off, k->relpath.len, M_REL),
	    "RELPATH holds the relative path");
	ok_(has_marker(f, k->workdir.off, k->workdir.len, M_WORK),
	    "WORKDIR holds the working directory");
	ok_(has_marker(f, k->args.off, k->args.len, "MARKERARGS"),
	    "ARGUMENTS holds the command line");
	ok_(has_marker(f, k->icon.off, k->icon.len, "MARKERICON"),
	    "ICON holds the icon location");

	ok_(!has_marker(f, k->args.off, k->args.len, M_WORK),
	    "ARGUMENTS does not reach back into the working directory");
	ok_(!has_marker(f, k->workdir.off, k->workdir.len, "MARKERARGS"),
	    "WORKDIR does not reach forward into the arguments");

	ok_((k->anomalies & KOF_LNK_ANOM_ARGS_LONG) != 0,
	    "a command line past the threshold is reported");
	ok_((k->anomalies & KOF_LNK_ANOM_ICON_UNC) != 0,
	    "an icon on another machine is reported");
	ok_(k->n_extra == 1u, "the ExtraData chain was walked");

	/*
	 * AND THE PARTITION HOLDS. Every byte of the object belongs to exactly
	 * one region - the invariant the engine relies on when it hands a
	 * region to a rule.
	 */
	{
		struct kof_range r[32];
		uint32_t n, i;
		uint64_t total = 0;

		n = ctx.resolve_scan(&ctx, KOF_SCAN_LNK_CLAIMED |
					   KOF_SCAN_LNK_UNCLAIMED, r, 32u);
		for (i = 0; i < n; i++)
			total += r[i].len;
		ok_(total == flen, "the regions cover the object exactly once");
	}

	/* A file that is not a shell link is not claimed. */
	{
		uint8_t other[128];

		memset(other, 0, sizeof other);
		w32(other, 76);                 /* the size agrees, the CLSID
						 * does not - which is the case
						 * a size-only sniff would get
						 * wrong */
		ok_(!kof_lnk_sniff(kof_buf_make(other, sizeof other)),
		    "a file with the right size field and no CLSID is refused");
	}

	free(f);
	free(k);
	if (failures) {
		printf("lnk regions: %d check(s) failed\n", failures);
		return 1;
	}
	printf("lnk regions: sniff, the five strings in order, a long command "
	       "line, a UNC icon, extra data, the partition - ok\n");
	return 0;
}
