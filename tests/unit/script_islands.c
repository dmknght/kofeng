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
	/* Room for a page at the island cap: one extent per island and one per
	 * gap, plus the header and the footer. r[128] was written when the cap
	 * was 32 and would have made the overflow case fail as a hole in the
	 * partition rather than as what it is. */
	struct kof_range r[2u * KOF_SCRIPT_MAX_ISLAND + 8u];
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
				   KOF_SCAN_SCRIPT_MARKUP,
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
		KOF_SCAN_SCRIPT_MARKUP
	};
	static const uint32_t n_bit = (uint32_t)(sizeof bit / sizeof bit[0]);
	struct kof_script_info info;
	struct kof_obj_ctx ctx;
	/* Room for a page at the island cap: one extent per island and one per
	 * gap, plus the header and the footer. r[128] was written when the cap
	 * was 32 and would have made the overflow case fail as a hole in the
	 * partition rather than as what it is. */
	struct kof_range r[2u * KOF_SCRIPT_MAX_ISLAND + 8u];
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

/* How many bytes the HEADER REGION takes, or (uint32_t)-1 when nothing claimed
 * the object. Zero for php, which has no header - see KOF_SCAN_SCRIPT_HEADER. */
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
	return info.head_len;
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

/*
 * THE OTHER PLACE AN ASP.NET PAGE KEEPS CODE, and where its shells are: a
 * <script runat="server"> holding the whole program.
 *
 * The second <script> is the control: no "runat", so it is client-side
 * JavaScript that the server copies out. It must stay in the markup - claiming
 * it as server code would form JavaScript by the server language's rules.
 */
static const char aspx_el[] =
	"<%@ Page Language=\"C#\" %>\n"
	"<html>\n"
	"<script Language=\"c#\" runat=\"server\">\n"
	"  void Page_Load(object s, EventArgs e)\n"
	"  {\n"
	"      Process.Start(\"cmd.exe\", Request[\"c\"]);\n"
	"  }\n"
	"</script>\n"
	"<script>var t = 1;</script>\n"
	"</html>\n";

/*
 * Markup first. A page is not required to lead with its directive - and what it
 * opens with is MARKUP, not header. The header was [0, tag_end), so every byte
 * before the tag was declared part of it: measured at 20 of 103 corpus files
 * and up to 4072 bytes of html in one.
 */
static const char leading_markup[] =
	"<html>\n<body>\n"
	"<% y = 2 %>\n"
	"</body></html>\n";

/* No closing half anywhere - the shape Perl's POD has, and it is not a page. */
static const char pod_like[] =
	"=item C<%dependencies>\n"
	"\n"
	"Holds the factored dependencies.\n";

/*
 * PHP HAS BOTH SHAPES AND THE PARTITION DIFFERS BETWEEN THEM.
 *
 * A PROGRAM - code, and a closing tag that ends the file. Nothing follows the
 * "?>", so there is no markup and the tag is the FOOTER.
 */
static const char php_prog[] =
	"<?php\n"
	"  $c = $_GET[\"c\"];\n"
	"  @system($c);\n"
	"?>\n";

/*
 * A PAGE - html with code cut into it. The href is the reason this matters:
 * "//" in it is not a comment, and the form pass would read it as one if the
 * markup were handed to it as php.
 */
static const char php_page[] =
	"<?php\n"
	"  $c = $_GET[\"c\"];\n"
	"?>\n"
	"<html><a href=http://plain.example/p>link</a>\n"
	"<?php\n"
	"  @system($c);\n"
	"?>\n"
	"</html>\n";

int main(void)
{
	uint32_t hl;
	uint16_t isl = 0;

	check_partition("jsp page", page);
	check_partition("classic asp", classic);
	check_partition("markup first", leading_markup);
	{
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		struct kof_range r[8];
		kof_buf f;
		uint32_t n;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)leading_markup;
		f.n = strlen(leading_markup);
		if (kof_script_sniff(f) && kof_script_parse(f, &info, &ctx)) {
			n = ctx.resolve_scan(&ctx, KOF_SCAN_SCRIPT_MARKUP, r,
					     (uint32_t)(sizeof r / sizeof r[0]));
			/*
			 * What a page opens with before its tag is MARKUP. It
			 * was the HEADER - [0, tag_end) - so every byte before
			 * the tag was declared part of it: measured at 20 of
			 * 103 corpus files, up to 4072 bytes of html in one.
			 */
			if (!n || r[0].off != 0u || !r[0].len)
				printf("  FAIL %-26s the html before the tag is "
				       "not the first markup extent\n",
				       "markup before the tag"), fails++;
		}
	}

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
	 * TWO BLOCKS. NOT THE COMMENT, AND NOT THE EXPRESSION.
	 *
	 * Three things in this page open "<%" and only two of them are the
	 * program:
	 *
	 *   <% int total = 0; %>        owns its line - a block
	 *   <% total = total + 1; %>    owns its line - a block
	 *   <p>total <%= total %></p>   INSIDE a line of markup - glue
	 *   <%-- a comment --%>         not code at all
	 *
	 * The expression is the case the glue rule exists for: it is a value
	 * dropped into a sentence, and splitting the line at it produced three
	 * rows - "<p>total ", the expression, "</p>" - none of which is a thing
	 * anybody reads. Left unrecorded it falls into the markup around it and
	 * the line stays one line.
	 */
	if (isl != 2u)
		printf("  FAIL %-26s %u islands, wanted 2 (a block each, and "
		       "neither the <%%-- comment nor the <%%= expression)\n",
		       "jsp islands", isl), fails++;

	hl = header_len(classic, &isl);
	if (hl != (uint32_t)strlen("<%@ Language=VBScript %>"))
		printf("  FAIL %-26s header is %u bytes\n",
		       "asp directive block", hl), fails++;
	if (isl != 1u)
		printf("  FAIL %-26s %u islands, wanted 1\n",
		       "asp islands", isl), fails++;

	check_partition("aspx script element", aspx_el);
	check_per_bit("aspx script el per bit", aspx_el);

	/*
	 * ONE ISLAND AND IT IS THE SERVER ONE. Two <script> elements, and only
	 * the one carrying "runat" is code - so a second island here would mean
	 * client-side JavaScript had been claimed as the server's.
	 */
	hl = header_len(aspx_el, &isl);
	if (isl != 1u)
		printf("  FAIL %-26s %u islands, wanted 1 - only the "
		       "runat=\"server\" script is code\n",
		       "aspx script islands", isl), fails++;

	/*
	 * AND THE ISLAND IS THE CODE, NOT THE ELEMENT. The opening tag is a
	 * list of attributes; formed by the server language's rules its spaces
	 * would close up and `Language="c#" runat="server"` would become one
	 * token. So the tags belong to the markup and the island starts after
	 * the ">".
	 */
	{
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)aspx_el;
		f.n = strlen(aspx_el);
		if (kof_script_sniff(f) && kof_script_parse(f, &info, &ctx) &&
		    info.n_island == 1u) {
			const char *p = aspx_el + info.island[0].off;

			if (p[0] != '\n' || p[1] != ' ')
				printf("  FAIL %-26s island starts \"%.12s\", "
				       "wanted the code after the tag\n",
				       "aspx island is the code", p), fails++;
		}
	}

	/*
	 * ---- A "?>" THAT DOES NOT CLOSE ANYTHING ----
	 *
	 * Searching for the two bytes finds them wherever they are, and in a
	 * webshell they are very often inside a string: a dropper carrying the
	 * source of the file it writes. Measured on this corpus: 66 of them in
	 * 15 of 75 php files. Each ended an island early, so the code after it
	 * was called markup - and the form pass leaves markup alone, so the
	 * wrong label is now a wrong normalisation as well.
	 */
	{
		static const char in_str[] =
			"<?php\n"
			"$tpl = \"<?php eval($_POST[x]); ?>\";\n"
			"@system($_GET['c']);\n"
			"?>\n"
			"<html>real markup</html>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		struct kof_range r[8];
		kof_buf f;
		uint32_t n;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)in_str;
		f.n = strlen(in_str);
		if (kof_script_sniff(f) && kof_script_parse(f, &info, &ctx)) {
			n = ctx.resolve_scan(&ctx, KOF_SCAN_SCRIPT_BODY, r,
					     (uint32_t)(sizeof r / sizeof r[0]));
			/*
			 * The @system call has to be INSIDE the body. Ended at
			 * the string's "?>" the island stops before it and the
			 * call is markup - which is the whole failure.
			 */
			if (n != 1u ||
			    !kof_memmem(in_str + r[0].off, (size_t)r[0].len,
					"@system", 7u))
				printf("  FAIL %-26s %u body extent(s), and the "
				       "call after the string is not in one\n",
				       "?> inside a string", n), fails++;
		} else {
			fail("?> inside a string", "sniff or parse refused it");
		}
		check_partition("?> inside a string", in_str);
	}

	check_partition("php program", php_prog);
	check_partition("php page", php_page);
	check_per_bit("php program per bit", php_prog);
	check_per_bit("php page per bit", php_page);

	/*
	 * A PROGRAM IS NOT SPLIT: one run of code, and it is already the body.
	 *
	 * AND PHP HAS NO HEADER. "<?php" opens a block of code - it is the
	 * first byte of a body, the same as every "<?php" further down - so
	 * naming the first one a header cut one block in half and called the
	 * pieces different things.
	 */
	hl = header_len(php_prog, &isl);
	if (hl != 0u)
		printf("  FAIL %-26s header is %u bytes, wanted none\n",
		       "php has no header", hl), fails++;
	if (isl != 0u)
		printf("  FAIL %-26s %u islands, wanted 0 - a program that "
		       "ends with \"?>\" is not a page\n",
		       "php program islands", isl), fails++;

	/*
	 * A PAGE IS. Two runs of code with html between them, and the FIRST one
	 * has to be there: its opener is the tag that identified the file, so a
	 * walk that looked for an opener after the header would have started at
	 * the second and called the first block markup.
	 */
	hl = header_len(php_page, &isl);
	if (isl != 2u)
		printf("  FAIL %-26s %u islands, wanted 2\n",
		       "php page islands", isl), fails++;

	/*
	 * AND THE MARKUP IS NOT CODE. The bytes of the href have to come back
	 * under MARKUP, because that is what stops the form pass reading "//"
	 * in it as a comment and taking the rest of the line with it.
	 */
	{
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		struct kof_range r[32];
		kof_buf f;
		uint32_t n, i;
		int found = 0;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)php_page;
		f.n = strlen(php_page);
		if (kof_script_sniff(f) && kof_script_parse(f, &info, &ctx)) {
			n = ctx.resolve_scan(&ctx, KOF_SCAN_SCRIPT_MARKUP, r,
					     (uint32_t)(sizeof r / sizeof r[0]));
			for (i = 0; i < n; i++) {
				const char *p = php_page + r[i].off;

				if (r[i].len >= 5u &&
				    memchr(p, '<', (size_t)r[i].len) &&
				    strstr(php_page, "href=http://") >=  p &&
				    strstr(php_page, "href=http://") <
				    p + r[i].len)
					found = 1;
			}
		}
		if (!found)
			fail("php page markup",
			     "the href is not in a MARKUP extent");
	}

	/*
	 * ---- MORE ISLANDS THAN THE TABLE HOLDS ----
	 *
	 * The cap used to be 32 and the overflow used to EXTEND THE LAST ISLAND
	 * TO THE END OF THE OBJECT. A real 87 KB shell needs 122 islands, so
	 * the last one swallowed 67697 bytes - 78% of the file, nearly all of
	 * it html, declared to be code and then formed by php's rules.
	 *
	 * Two things are pinned. The tail past the cap is MARKUP, which is what
	 * the remainder of a page is; and the parse SAYS the list is short,
	 * because a silent cap is what let the first one survive.
	 *
	 * EACH ISLAND OWNS ITS LINE, and that is not incidental to the fixture.
	 * An island sharing a line with markup is INTERPOLATION - see php_block -
	 * and is not recorded at all, so the first version of this fixture wrote
	 * three hundred of them and produced one island. The test caught it,
	 * which is the only reason this note is here rather than a wrong number.
	 */
	{
		static char many[64u * 1024u];
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;
		uint32_t at = 0;
		int i;

		at += (uint32_t)snprintf(many, sizeof many, "<?php $x=1; ?>\n");
		for (i = 0; i < (int)KOF_SCRIPT_MAX_ISLAND + 8 &&
			    at < sizeof many - 64u; i++)
			at += (uint32_t)snprintf(many + at, sizeof many - at,
						 "<p>r%d</p>\n<?php echo $x; ?>\n",
						 i);
		snprintf(many + at, sizeof many - at, "<p>tail</p>\n");

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)many;
		f.n = strlen(many);
		if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx)) {
			fail("island overflow", "sniff or parse refused it");
		} else {
			if (!(info.anomalies & KOF_SCRIPT_ANOM_ISLANDS_FULL))
				fail("island overflow",
				     "the parse did not say the list is short");
			if (info.n_island != KOF_SCRIPT_MAX_ISLAND)
				printf("  FAIL %-26s %u islands, wanted the "
				       "cap\n", "island overflow",
				       info.n_island), fails++;
			/*
			 * AND THE LAST ISLAND DID NOT EAT THE TAIL. That is the
			 * regression itself: its length must still be one run of
			 * code, not the distance to the end of the object.
			 */
			if ((uint64_t)info.island[info.n_island - 1].off +
			    info.island[info.n_island - 1].len >= f.n - 16u)
				fail("island overflow",
				     "the last island swallowed the tail");
		}
		/* And the partition still holds over the whole of it. */
		check_partition("island overflow", many);
		check_per_bit("island overflow per bit", many);
	}

	/*
	 * A BARE "<%" IS NOT A HEADER, AND THE WALK MUST START ON IT.
	 *
	 * "<%@ ... %>" declares the page and is not code, so it is a header.
	 * "<%" OPENS A BLOCK of code, exactly as "<?php" does. Reporting two
	 * bytes of header for it started the island walk one byte inside the
	 * first block: the "<%" that opened it was never seen, the block ran
	 * to the file's end as markup, and the form pass copied it verbatim -
	 * measured on kacak.asp, 2691 bytes of VBScript declared to be page
	 * text while the rest of the same file was formed.
	 */
	{
		static const char bare[] =
			"<html>\n<body>\n"
			"<%\nDim x\nx = CreateObject(\"WScript.Shell\")\n%>\n"
			"<p>done</p>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)bare;
		f.n = strlen(bare);
		if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx)) {
			fail("bare <%", "sniff or parse refused it");
		} else {
			if (info.head_len)
				fail("bare <%", "a bare \"<%\" was given a "
				     "header");
			if (!info.n_island ||
			    info.island[0].off != info.tag_off)
				fail("bare <%", "the first island does not "
				     "start at the tag that opened it");
			/* And it is classic ASP, said by a second marker
			 * rather than by a directive there is none of. */
			if (info.kind != KOF_SCRIPT_ASP)
				fail("bare <%", "a page with no directive came "
				     "back with no kind");
		}
		check_partition("bare <%", bare);
	}

	/*
	 * A BLOCK OF CODE IS NOT ABSORBED BY THE TAG AROUND IT.
	 *
	 * One element that wraps code is one block of markup - that is what
	 * the merge is for, and every island it was written for is a FRAGMENT
	 * on a line of html. A block that owns its lines is not a fragment,
	 * and "<p>" around it does not make it page text: newaspcmd.asp kept
	 * its shell that way, never formed, while the rest of the file was.
	 */
	{
		static const char inline_frag[] =
			"<%@ Language=VBScript %>\n<table>\n"
			"<tr><td><% =row %></td></tr>\n"
			"</table>\n";
		static const char block_in_p[] =
			"<%@ Language=VBScript %>\n<p>\n"
			"<% szCMD = request(\"cmd\")\n"
			"Response.Write(szCMD)%>\n"
			"</p>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)inline_frag;
		f.n = strlen(inline_frag);
		if (kof_script_sniff(f) && kof_script_parse(f, &info, &ctx) &&
		    info.n_island)
			fail("inline fragment",
			     "a one line fragment inside <table> stayed code");

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)block_in_p;
		f.n = strlen(block_in_p);
		if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx) ||
		    !info.n_island)
			fail("block in <p>",
			     "a multi line block inside <p> became markup");
		check_partition("block in <p>", block_in_p);
	}

	/*
	 * AND A BLOCK THE FORM PASS EMPTIED IS EMPTY.
	 *
	 * A block holding one comment forms to "<%\n%>" - a code region with
	 * no code in it. The comment was how the file was typed and so was the
	 * block that was opened to hold it.
	 */
	{
		if (!kof_script_block_bare(KOF_SCRIPT_ASP,
					   (const uint8_t *)"<%\n%>", 5u))
			fail("bare block", "\"<%\\n%>\" is not empty");
		if (!kof_script_block_bare(KOF_SCRIPT_PHP,
					   (const uint8_t *)"<?php\n?>", 8u))
			fail("bare block", "\"<?php\\n?>\" is not empty");
		/* Joined neighbours, which is what the whitespace join makes
		 * of two emptied blocks. */
		if (!kof_script_block_bare(KOF_SCRIPT_ASP,
					   (const uint8_t *)"<%\n%>\n<%\n%>",
					   11u))
			fail("bare block", "two emptied blocks are not empty");
		/* And nothing that has a program in it. */
		if (kof_script_block_bare(KOF_SCRIPT_ASP,
					  (const uint8_t *)"<%Next%>", 8u))
			fail("bare block", "\"<%Next%>\" was called empty");
		if (kof_script_block_bare(KOF_SCRIPT_ASP,
					  (const uint8_t *)"<%=x%>", 6u))
			fail("bare block", "a value block was called empty");
		/* A kind with no delimiter pair is never bare: its island is
		 * code with nothing wrapped around it. */
		if (kof_script_block_bare(KOF_SCRIPT_SHELL,
					  (const uint8_t *)"", 0u))
			fail("bare block", "an empty buffer was called a "
			     "block");
	}

	/*
	 * THE BARE "<?" SHORT TAG, AND THE XML IT MUST NOT CLAIM.
	 *
	 * A 2006 shell opens with "<?" and nothing else, and the file was
	 * coming back as an object no module targets - not a script at all.
	 * The rule is the whitespace after it: an XML processing instruction
	 * puts its target straight after the "<?", so "<?xml" can never be
	 * the php short tag and "<?\n" can never be a PI.
	 */
	{
		static const char shorttag[] =
			"<?\n$x = 1;\necho $x;\n?>\n";
		static const char xmldoc[] =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<note><to>reader</to></note>\n";
		static const char xmlpi[] =
			"<?xml-stylesheet type=\"text/xsl\" href=\"a.xsl\"?>\n"
			"<doc/>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)shorttag;
		f.n = strlen(shorttag);
		if (!kof_script_sniff(f)) {
			fail("short tag", "\"<?\" was not taken as php");
		} else if (!kof_script_parse(f, &info, &ctx)) {
			fail("short tag", "sniffed and then would not parse");
		} else {
			if (info.kind != KOF_SCRIPT_PHP)
				fail("short tag", "a short tag file is not php");
			if (info.tag_off != 0u || info.tag_len != 2u)
				fail("short tag", "the tag is not the two bytes "
				     "that opened it");
			/* php has no header, so the tag opens the body. */
			if (info.head_len)
				fail("short tag", "a short tag was given a "
				     "header");
		}
		check_partition("short tag", shorttag);

		f.p = (const uint8_t *)xmldoc;
		f.n = strlen(xmldoc);
		if (kof_script_sniff(f))
			fail("xml is not php", "\"<?xml\" was taken as a "
			     "short tag");
		f.p = (const uint8_t *)xmlpi;
		f.n = strlen(xmlpi);
		if (kof_script_sniff(f))
			fail("xml pi is not php",
			     "a processing instruction was taken as php");
	}

	/*
	 * AND A PAGE WHOSE BLOCKS ARE SHORT TAGS IS STILL A PAGE.
	 *
	 * The island walk asks the same question the sniff does, so a short
	 * tag recognised by one and not the other would leave a page whose
	 * code nothing can find.
	 */
	{
		static const char shortpage[] =
			"<html>\n<body>\n"
			"<?\n$rows = load();\nforeach ($rows as $r) {\n?>\n"
			"<p>row</p>\n"
			"<?\n}\n?>\n"
			"</body>\n</html>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)shortpage;
		f.n = strlen(shortpage);
		if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx))
			fail("short tag page", "not taken as a script");
		else if (!info.n_island)
			fail("short tag page",
			     "the walk found no code in a page of short tags");
		check_partition("short tag page", shortpage);
	}

	/*
	 * COLDFUSION, WHOSE TAGS ARE ITS STATEMENTS.
	 *
	 * There are no delimiters to carve: a .cfm is html and the program is
	 * the "<cf...>" tags in it, arguments and all. The parse used to find
	 * one tag, call it a three byte header and stop - so the whole page,
	 * html included, came back as BODY and a rule scoped to the code
	 * searched the text as well. Measured over the four shells in the
	 * sample tree: 60 tags, 21 "#...#" interpolations, not one <cfscript>.
	 */
	{
		static const char cfm[] =
			"<html>\n<body>\n"
			"<cfif isdefined(\"form.cmd\")>\n"
			"<cfexecute name=\"cmd.exe\" arguments=\"/c #form.cmd#\">\n"
			"</cfexecute>\n</cfif>\n"
			"</body>\n</html>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)cfm;
		f.n = strlen(cfm);
		if (!kof_script_sniff(f) || !kof_script_parse(f, &info, &ctx)) {
			fail("coldfusion", "not taken as a script");
		} else {
			if (info.kind != KOF_SCRIPT_CFM)
				fail("coldfusion", "not recognised as CFML");
			if (info.head_len)
				fail("coldfusion", "a <cf> tag is a statement, "
				     "not a header");
			if (!info.n_island) {
				fail("coldfusion",
				     "the tags were not carved as code");
			} else {
				const char *p = cfm + info.island[0].off;
				uint32_t l = info.island[0].len;

				/* The html above the first tag is markup, and
				 * the tags themselves are one run of code:
				 * two adjacent ones are joined, which is what
				 * the whitespace join is for. */
				if (info.island[0].off != 14u)
					fail("coldfusion", "the code does not "
					     "start at the first tag");
				if (!l || l > 96u ||
				    !kof_memmem(p, l, "cfexecute", 9u))
					fail("coldfusion", "the statement that "
					     "runs a command is not in the "
					     "code region");
			}
		}
		check_partition("coldfusion", cfm);
		check_per_bit("coldfusion per bit", cfm);
	}

	/*
	 * AND AN ATTRIBUTE MAY HOLD A ">", which is the shape a shell in a page
	 * has - "arguments=\"/c dir > out.txt\"". A walk that stopped at the
	 * first ">" would cut the tag in half and leave the command in markup.
	 */
	{
		static const char redirect[] =
			"<html>\n"
			"<cfexecute name=\"cmd\" arguments=\"/c dir > o.txt\">\n"
			"</cfexecute>\n</html>\n";
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;

		memset(&ctx, 0, sizeof ctx);
		f.p = (const uint8_t *)redirect;
		f.n = strlen(redirect);
		if (kof_script_sniff(f) && kof_script_parse(f, &info, &ctx) &&
		    info.n_island) {
			const char *p = redirect + info.island[0].off;
			uint32_t l = info.island[0].len;

			if (l < 40u || !memchr(p, '>', l) ||
			    memcmp(p + l - 1u, ">", 1u))
				fail("coldfusion redirect",
				     "the tag was cut at a \">\" inside an "
				     "attribute");
		}
		check_partition("coldfusion redirect", redirect);
	}

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

	/*
	 * A MENTION IS NOT A TAG - see the note beside the shebang in
	 * script_parse.c. Three files that all hold "<?php":
	 *
	 *   a python tool that PRINTS one   -> python, the string is data
	 *   a shell script that echoes one  -> shell, same reason
	 *   a shell script that heredocs one -> php, the body is not a literal
	 */
	{
		static const char pytool[] =
			"#!/usr/bin/python\n"
			"code = raw_input(\"add tags e.g. <?php echo 1; ?>\")\n"
			"open('x.php','w').write(\"<?php eval($a); ?>\")\n";
		static const char shecho[] =
			"#!/bin/sh\n"
			"echo \"<?php system($_GET[0]); ?>\" > /var/www/x.php\n";
		static const char shhere[] =
			"#!/bin/sh\n"
			"cat > /var/www/x.php <<EOF\n"
			"<?php system($_GET[0]); ?>\n"
			"EOF\n";
		static const struct {
			const char *what;
			const char *src;
			uint8_t     kind;
		} row[] = {
			{ "python that prints php", pytool, KOF_SCRIPT_PYTHON },
			{ "sh that echoes php",     shecho, KOF_SCRIPT_SHELL },
			{ "sh that heredocs php",   shhere, KOF_SCRIPT_PHP }
		};
		struct kof_script_info info;
		struct kof_obj_ctx ctx;
		kof_buf f;
		size_t i;

		for (i = 0; i < sizeof row / sizeof row[0]; i++) {
			memset(&ctx, 0, sizeof ctx);
			f.p = (const uint8_t *)row[i].src;
			f.n = strlen(row[i].src);
			if (!kof_script_parse(f, &info, &ctx))
				fail(row[i].what, "would not parse");
			else if (info.kind != row[i].kind)
				fail(row[i].what, "the wrong language claimed "
				     "the file");
		}
	}

	if (fails) {
		printf("script islands: %d check(s) failed\n", fails);
		return 1;
	}
	printf("script islands: partition, directive block, comment, "
	       "bare tag, short tag, coldfusion, blocks kept, emptied "
	       "blocks, closing half, a mention is not a tag - ok\n");
	return 0;
}
