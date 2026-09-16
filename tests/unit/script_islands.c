/*
 * script_islands - a server page is markup with code in it, and the regions
 * have to say which is which.
 *
 * A .jsp or .asp is not a program with some text around it. It is TEXT WITH
 * CODE ISLANDS: markup, and inside it runs of "<% ... %>" that the server
 * executes. Two languages in one file, and calling the whole of it the program
 * is wrong in both directions - normalising markup by Java's rules turns
 * "http://x" in an href into a comment, and a marker meant for the program is
 * offered every byte of the page.
 *
 * So the three properties this asks about:
 *
 *   1. THE PARTITION. Every byte belongs to exactly one region, in order, with
 *      no gap and no overlap. region_partition.c asserts this for the formats
 *      it can walk a corpus of; there is no server-page corpus on a build
 *      machine, so this file carries its own.
 *
 *   2. THE HEADER IS THE WHOLE DIRECTIVE BLOCK, not the three bytes that open
 *      it. Reading only "<%@" put every directive in the body, so a rule asking
 *      for the program was handed them too.
 *
 *   3. A JSP COMMENT IS NOT AN ISLAND. "<%--" opens a comment; the server does
 *      not run it. Recorded as code it would be normalised as code and offered
 *      to every rule about the program.
 *
 * Buffers rather than files: the parser takes bytes, so the test can say
 * exactly what it is testing and a build machine needs nothing on disk.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <kofmod/script.h>

#include "../../libkofeng/core/kofplatform.h"
#include "../../libkofeng/kofparsers/scripts/script_parse.h"

static int fails;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %-26s %s\n", what, why);
	fails++;
}

/*
 * Resolve every region and check the extents tile [0, n) exactly.
 *
 * Sorted by offset before the walk because a resolver is free to emit its
 * regions in whatever order suits it - what it is not free to do is leave a
 * hole or overlap, and that is what this looks for.
 */
static void check_partition(const char *what, const char *src)
{
	struct kof_script_info info;
	struct kof_obj_ctx ctx;
	struct kof_range r[128];
	kof_buf f;
	uint32_t n, i, j;
	uint64_t at = 0;

	memset(&ctx, 0, sizeof ctx);
	f.p = (const uint8_t *)src;
	f.n = strlen(src);

	if (!kof_script_sniff(f)) {
		fail(what, "the sniff refused it");
		return;
	}
	if (!kof_script_parse(f, &info, &ctx)) {
		fail(what, "the parse refused it");
		return;
	}
	n = ctx.resolve_scan(&ctx, KOF_SCAN_SCRIPT_HEADER |
				   KOF_SCAN_SCRIPT_BODY |
				   KOF_SCAN_SCRIPT_MARKUP |
				   KOF_SCAN_SCRIPT_FOOTER,
			     r, (uint32_t)(sizeof r / sizeof r[0]));
	if (!n) {
		fail(what, "no regions at all");
		return;
	}
	for (i = 0; i < n; i++)
		for (j = i + 1u; j < n; j++)
			if (r[j].off < r[i].off) {
				struct kof_range t = r[i];

				r[i] = r[j];
				r[j] = t;
			}
	for (i = 0; i < n; i++) {
		if (r[i].off != at) {
			printf("  FAIL %-26s extent %u starts at %llu, "
			       "wanted %llu\n", what, i,
			       (unsigned long long)r[i].off,
			       (unsigned long long)at);
			fails++;
			return;
		}
		at += r[i].len;
	}
	if (at != f.n) {
		printf("  FAIL %-26s regions cover %llu of %llu bytes\n",
		       what, (unsigned long long)at,
		       (unsigned long long)f.n);
		fails++;
	}
}

/*
 * THE WAY A DECLARATION ASKS, WHICH IS ONE BIT AT A TIME.
 *
 * kof_region_map_build walks the format's region list and resolves each bit on
 * its own - see kofinspect.c - and that is the call every declared marker is
 * located through. A resolver that is only right when asked for everything at
 * once puts a marker in the wrong region, or in none, and the panel then says
 * the bytes are not in the object they were just taken from.
 *
 * So each bit is asked for separately here and the answers are summed: they
 * must still tile the object exactly, with no byte in two of them.
 */
static void check_per_bit(const char *what, const char *src)
{
	static const uint32_t bit[] = {
		KOF_SCAN_SCRIPT_HEADER, KOF_SCAN_SCRIPT_BODY,
		KOF_SCAN_SCRIPT_MARKUP, KOF_SCAN_SCRIPT_FOOTER
	};
	static const uint32_t n_bit = (uint32_t)(sizeof bit / sizeof bit[0]);
	struct kof_script_info info;
	struct kof_obj_ctx ctx;
	struct kof_range r[128];
	kof_buf f;
	uint32_t n = 0, b, i, j;
	uint64_t at = 0;

	memset(&ctx, 0, sizeof ctx);
	f.p = (const uint8_t *)src;
	f.n = strlen(src);
	if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx)) {
		fail(what, "sniff or parse refused it");
		return;
	}
	for (b = 0; b < n_bit; b++) {
		uint32_t got = ctx.resolve_scan(&ctx, bit[b], r + n,
						(uint32_t)(sizeof r /
							   sizeof r[0]) - n);

		if (bit[b] == KOF_SCAN_SCRIPT_BODY && info.n_island &&
		    got != info.n_island) {
			printf("  FAIL %-26s BODY alone gave %u extents, "
			       "wanted %u (one per island)\n",
			       what, got, info.n_island);
			fails++;
		}
		n += got;
	}
	for (i = 0; i < n; i++)
		for (j = i + 1u; j < n; j++)
			if (r[j].off < r[i].off) {
				struct kof_range t = r[i];

				r[i] = r[j];
				r[j] = t;
			}
	for (i = 0; i < n; i++) {
		if (r[i].off != at) {
			printf("  FAIL %-26s per-bit extent %u at %llu, "
			       "wanted %llu\n", what, i,
			       (unsigned long long)r[i].off,
			       (unsigned long long)at);
			fails++;
			return;
		}
		at += r[i].len;
	}
	if (at != f.n) {
		printf("  FAIL %-26s per-bit covers %llu of %llu\n", what,
		       (unsigned long long)at, (unsigned long long)f.n);
		fails++;
	}
}

/* How many bytes the header took, or (uint32_t)-1 when nothing claimed it. */
static uint32_t header_len(const char *src, uint16_t *n_island)
{
	struct kof_script_info info;
	struct kof_obj_ctx ctx;
	kof_buf f;

	memset(&ctx, 0, sizeof ctx);
	f.p = (const uint8_t *)src;
	f.n = strlen(src);
	if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx))
		return (uint32_t)-1;
	if (n_island)
		*n_island = info.n_island;
	return info.tag_len;
}

/* Two directives, markup, a comment, two code runs and an expression. */
static const char page[] =
	"<%@ page import=\"java.util.*\" %>\n"
	"<%@ page contentType=\"text/html\" %>\n"
	"<html>\n"
	"<body>\n"
	"<%-- a comment, which the server does not run --%>\n"
	"<% int total = 0; %>\n"
	"<p>rows</p>\n"
	"<% total = total + 1; %>\n"
	"<p>total <%= total %></p>\n"
	"</body>\n";

/* The other shape: one directive, then a bare "<%" opening code. */
static const char classic[] =
	"<%@ Language=VBScript %>\n"
	"<%\n"
	"  x = 1\n"
	"%>\n"
	"<html><body>done</body></html>\n";

/* Markup first. A page is not required to lead with its directive. */
static const char leading_markup[] =
	"<html>\n<body>\n"
	"<% y = 2 %>\n"
	"</body></html>\n";

/* No closing half anywhere - the shape Perl's POD has, and it is not a page. */
static const char pod_like[] =
	"=item C<%dependencies>\n"
	"\n"
	"Holds the factored dependencies.\n";

int main(void)
{
	uint32_t hl;
	uint16_t isl = 0;

	check_partition("jsp page", page);
	check_partition("classic asp", classic);
	check_partition("markup first", leading_markup);

	check_per_bit("jsp page per bit", page);
	check_per_bit("classic asp per bit", classic);
	check_per_bit("markup first per bit", leading_markup);

	/*
	 * THE DIRECTIVE BLOCK IS THE HEADER. Both directives and the newline
	 * between them, and nothing of the markup under them.
	 */
	hl = header_len(page, &isl);
	if (hl != (uint32_t)(strlen("<%@ page import=\"java.util.*\" %>\n"
				    "<%@ page contentType=\"text/html\" %>")))
		printf("  FAIL %-26s header is %u bytes\n",
		       "jsp directive block", hl), fails++;

	/*
	 * TWO ISLANDS AND AN EXPRESSION, AND NOT THE COMMENT. "<%--" is skipped
	 * outright, so three runs of code are recorded and the comment is left
	 * in the markup around it.
	 */
	if (isl != 3u)
		printf("  FAIL %-26s %u islands, wanted 3 "
		       "(the <%%-- comment must not be one)\n",
		       "jsp islands", isl), fails++;

	hl = header_len(classic, &isl);
	if (hl != (uint32_t)strlen("<%@ Language=VBScript %>"))
		printf("  FAIL %-26s header is %u bytes\n",
		       "asp directive block", hl), fails++;
	if (isl != 1u)
		printf("  FAIL %-26s %u islands, wanted 1\n",
		       "asp islands", isl), fails++;

	/*
	 * AND THE OTHER HALF HAS TO BE THERE. "<%" is two bytes of punctuation
	 * that occur in prose - measured, it claimed 208 .pm and 76 .pod files
	 * on one machine, because POD writes a hash as C<%name>. What none of
	 * them has is a "%>", so the pair is the magic and not the opener.
	 */
	{
		kof_buf f;

		f.p = (const uint8_t *)pod_like;
		f.n = strlen(pod_like);
		if (kof_script_sniff(f))
			fail("pod is not a page",
			     "sniff accepted \"<%\" with no \"%>\"");
	}

	if (fails) {
		printf("script islands: %d check(s) failed\n", fails);
		return 1;
	}
	printf("script islands: partition, directive block, comment, "
	       "closing half - ok\n");
	return 0;
}
