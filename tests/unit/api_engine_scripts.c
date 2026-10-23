/*
 * api_engine_scripts.c - the text parsers under analyzers/parsers/scripts:
 * kof_script_sniff/parse (which interpreter a file is for, and where a server
 * page keeps its code), the language walks it dispatches into (php_parse.h,
 * svrpage_parse.h, cfm_parse.h, markup_parse.h) and the island helpers they share
 * (scantext.h).
 *
 * A page is markup with code cut into it; what the parser publishes is the list of
 * code ISLANDS, and the contract is a partition: islands are in file order, never
 * overlap, lie inside the object, and the list says when it was cut short. Those
 * are asserted on real-shaped pages of every language and then on pages built to
 * hurt - a million unclosed tags, ten thousand islands, a comment that never ends -
 * each run in a forked child under an alarm and a time bound, since a text walk
 * that rescans for a closer from every opener is the shape of denial of service
 * that costs nothing to send.
 *
 * Every page is also cut at every length and flipped at every position from a
 * buffer that ends on an inaccessible page.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <time.h>

#include "../../libkofeng/analyzers/parsers/scripts/script_route.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/php_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/svrpage_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/cfm_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/markup_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/scantext.h"
#include <kofmod/kofsig.h>
#include <kofmod/script.h>

static const char pg_php[]  = "<html>\n<?php echo 1; ?>\n<p>x</p>\n<?php if(1){ ?>a<?php } ?></html>";
static const char pg_prog[] = "<?php\necho 1;\n?>\n";
static const char pg_asp[]  = "<%@ Language=VBScript %>\n<% Response.Write 1 %>\n<html></html>";
static const char pg_aspx[] = "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">void f(){}</script>\n<html/>";
static const char pg_jsp[]  = "<%@ page import=\"java.io.*\" %>\n<% out.println(1); %>";
static const char pg_cfm[]  = "<cfexecute name=\"x\"></cfexecute>\n<cfif a>b</cfif>\n<!--- c --->";
static const char pg_hta[]  = "<html><script language=\"vbscript\">MsgBox 1</script></html>";
static const char pg_sh[]   = "#!/bin/sh\nls\n";
static const char pg_py[]   = "#!/usr/bin/env python3\nprint(1)\n";

struct page {
	const char *name;
	const char *text;
	size_t      n;
	int         kind;
	int         min_islands;
};

#define PG(nm, t, k, mi) { nm, t, sizeof t - 1u, k, mi }

static const struct page pages[] = {
	PG("php", pg_php, KOF_SCRIPT_PHP, 1),
	PG("php program", pg_prog, KOF_SCRIPT_PHP, 0),
	PG("asp", pg_asp, KOF_SCRIPT_ASP, 1),
	PG("aspx", pg_aspx, KOF_SCRIPT_ASPX, 1),
	PG("jsp", pg_jsp, KOF_SCRIPT_JSP, 1),
	PG("cfm", pg_cfm, KOF_SCRIPT_CFM, 2),
	PG("hta", pg_hta, KOF_SCRIPT_VBS, 1),
	PG("shell", pg_sh, KOF_SCRIPT_SHELL, 0),
	PG("python", pg_py, KOF_SCRIPT_PYTHON, 0)
};

/* The partition contract of one parse. Returns non-zero when it holds. */
static int islands_ok(const struct kof_script_info *s, uint64_t size)
{
	uint32_t i;
	uint64_t end = 0;

	if (s->n_island > KOF_SCRIPT_MAX_ISLAND)
		return 0;
	for (i = 0; i < s->n_island; i++) {
		uint64_t off = s->island[i].off, len = s->island[i].len;

		if (!len || off < end || off + len > size)
			return 0;
		end = off + len;
	}
	if (s->tag_len && (uint64_t)s->tag_off + s->tag_len > size)
		return 0;
	if (s->head_len > size)
		return 0;
	return 1;
}

static struct kof_script_info *new_info(void)
{
	return calloc(1, sizeof(struct kof_script_info));
}

static void t_pages(void)
{
	struct kof_script_info *s = new_info();
	struct kof_obj_ctx ctx;
	unsigned i;

	if (!s) {
		CK(0, "memory");
		return;
	}
	for (i = 0; i < sizeof pages / sizeof pages[0]; i++) {
		kof_buf b = kof_buf_make(pages[i].text, pages[i].n);

		memset(&ctx, 0, sizeof ctx);
		CK(kof_script_sniff(b) == 1, "%s: sniff accepts it", pages[i].name);
		CK(kof_script_parse(b, s, &ctx) == 1, "%s: parse", pages[i].name);
		CK(s->kind == pages[i].kind, "%s: kind %u, expected %d", pages[i].name, s->kind, pages[i].kind);
		CK(s->n_island >= pages[i].min_islands, "%s: %u islands, at least %d expected", pages[i].name, s->n_island, pages[i].min_islands);
		CK(islands_ok(s, pages[i].n), "%s: islands are ordered, non-empty, inside the object", pages[i].name);
		CK(ctx.format == KOF_FMT_SCRIPT && ctx.subtype == s->kind && ctx.file_header == s, "%s: the context says script, kind, and where the view is", pages[i].name);
		CK(kof_script(&ctx) == s && kof_script_islands_of(&ctx) == s->n_island, "%s: the ABI accessors read the same view", pages[i].name);
		CK(ctx.resolve_scan != NULL, "%s: the regions can be resolved", pages[i].name);
		if (ctx.resolve_scan) {
			struct kof_range out[64];
			uint32_t n, k, total = 0;

			n = ctx.resolve_scan(&ctx, KOF_SCAN_SCRIPT_HEADER | KOF_SCAN_SCRIPT_BODY | KOF_SCAN_SCRIPT_MARKUP, out, 64);
			for (k = 0; k < n; k++)
				total += (uint32_t)out[k].len;
			/* a language the lib lexes has no regions (the lexer reads the whole object); one that has none is cut */
			if (kof_script_textual_lang(s->kind))
				CK(total == 0, "%s: a lexed language declares no region (%u)", pages[i].name, total);
			else
				CK(total == pages[i].n, "%s: the three regions together are the whole object (%u of %zu)", pages[i].name, total, pages[i].n);
		}
	}
	CK(s->from_shebang == 1, "python: named by its shebang");
	memset(&ctx, 0, sizeof ctx);
	{
		kof_buf b = kof_buf_make("hello world\n", 12);

		CK(kof_script_sniff(b) == 0, "prose is not a script");
		CK(kof_script_parse(b, s, &ctx) == 1 && s->kind == KOF_SCRIPT_ANY && s->n_island == 0, "parse never fails: an unnamed text is a script of no kind");
	}
	CK(kof_script_sniff(kof_buf_make(NULL, 0)) == 0 && kof_script_sniff(kof_buf_make("#", 1)) == 0, "NULL and one byte");
	CK(kof_script_parse(kof_buf_make(NULL, 0), s, &ctx) == 0, "an empty object does not parse");
	free(s);
}

static void t_walks(void)
{
	uint32_t tl = 0, hl = 0;
	kof_buf b;
	struct kof_script_info *s = new_info();

	if (!s) {
		CK(0, "memory");
		return;
	}
	b = kof_buf_make(pg_php, sizeof pg_php - 1u);
	CK(kof_php_find_tag(b, b.n, &tl) == 7 && tl == 5, "php tag found at 7, 5 long");
	CK(kof_php_find_tag(kof_buf_make("<?= $x ?>", 9), 9, &tl) == 0 && tl == 3, "the short echo tag");
	CK(kof_php_find_tag(kof_buf_make("<?PHP x", 7), 7, &tl) == 0, "case does not matter");
	CK(kof_php_find_tag(kof_buf_make("no tag here", 11), 11, &tl) == KOF_TXT_NONE, "no tag");
	CK(kof_php_find_tag(kof_buf_make("<?ph", 4), 4, &tl) == KOF_TXT_NONE, "a tag cut short is not a tag");
	CK(kof_php_find_tag(kof_buf_make(NULL, 0), 0, &tl) == KOF_TXT_NONE, "empty");
	CK(kof_php_is_page(b, 0) == 1, "html with code in it is a page");
	CK(kof_php_is_page(kof_buf_make(pg_prog, sizeof pg_prog - 1u), 0) == 0, "a program with a closing tag and a newline is not");
	CK(kof_php_is_page(kof_buf_make("<?php echo 1;", 13), 0) == 0, "no closing tag: a program");
	memset(s, 0, sizeof *s);
	kof_php_islands(b, 0, s);
	CK(s->n_island >= 1 && islands_ok(s, b.n), "php islands");

	b = kof_buf_make(pg_asp, sizeof pg_asp - 1u);
	CK(kof_svr_kind(b, b.n) == KOF_SCRIPT_ASP && kof_svr_kind(kof_buf_make(pg_aspx, sizeof pg_aspx - 1u), sizeof pg_aspx - 1u) == KOF_SCRIPT_ASPX &&
	   kof_svr_kind(kof_buf_make(pg_jsp, sizeof pg_jsp - 1u), sizeof pg_jsp - 1u) == KOF_SCRIPT_JSP, "asp, aspx and jsp are told apart");
	CK(kof_svr_kind(kof_buf_make("<%@ x %>", 8), 8) == KOF_SCRIPT_ANY && kof_svr_kind(kof_buf_make(NULL, 0), 0) == KOF_SCRIPT_ANY,
	   "a directive alone, and nothing, are of no kind");
	CK(kof_svr_find_tag(b, b.n, &tl, &hl) == 0 && hl == tl && tl > 2, "a directive is a header as long as itself");
	CK(kof_svr_find_tag(kof_buf_make("<% x %>", 7), 7, &tl, &hl) == 0 && tl == 2 && hl == 0, "a bare tag is no header");
	CK(kof_svr_find_tag(kof_buf_make("plain", 5), 5, &tl, &hl) == KOF_TXT_NONE, "no tag");
	memset(s, 0, sizeof *s);
	kof_svr_islands(b, 24, KOF_SCRIPT_ANY, s);
	CK(s->n_island == 1 && islands_ok(s, b.n), "asp island");

	b = kof_buf_make(pg_cfm, sizeof pg_cfm - 1u);
	CK(kof_cfm_find_tag(b, b.n, &tl) == 0 && tl == 20, "cfm: the first tag, whole");
	CK(kof_cfm_find_tag(kof_buf_make("<cf", 3), 3, &tl) == KOF_TXT_NONE && kof_cfm_find_tag(kof_buf_make("</cfif>", 7), 7, &tl) == KOF_TXT_NONE,
	   "a cut tag and a closing tag are not statements");
	memset(s, 0, sizeof *s);
	kof_cfm_islands(b, 0, s);
	CK(s->n_island == 2 && islands_ok(s, b.n), "cfm islands: both opening tags, not the comment");

	b = kof_buf_make(pg_hta, sizeof pg_hta - 1u);
	CK(kof_html_script_kind(b, b.n) == KOF_SCRIPT_VBS, "language=vbscript");
	CK(kof_html_script_kind(kof_buf_make("<script>x</script>", 18), 18) == KOF_SCRIPT_JS, "no language: javascript");
	CK(kof_html_script_kind(kof_buf_make("<script type=\"text/javascript\">x", 32), 32) == KOF_SCRIPT_JS && kof_html_script_kind(kof_buf_make("nothing", 7), 7) == KOF_SCRIPT_JS,
	   "type=javascript, and no script at all, are javascript");
	memset(s, 0, sizeof *s);
	kof_html_islands(b, 0, s);
	CK(s->n_island == 1 && s->island[0].len == 8 && islands_ok(s, b.n), "the body of a script element, not its tags");
	memset(s, 0, sizeof *s);
	kof_html_islands(kof_buf_make("<script>unterminated", 20), 0, s);
	CK(islands_ok(s, 20), "an unterminated element stays inside the object");
	kof_markup_merge(b, 0, s);
	CK(islands_ok(s, b.n), "merge keeps the contract");
	{
		struct kof_script_info *e = new_info();

		if (e) {
			kof_markup_merge(b, 0, e);
			CK(e->n_island == 0, "merge with no islands does nothing");
			free(e);
		}
	}
	free(s);
}

/*
 * `at + len > f.n` is the whole bounds test of kof_txt_tag_at, and for an offset near 2^64 the sum
 * wraps to a small number and the test passes: the byte read is f.p[at + i], one byte BEFORE the
 * buffer. The buffer here begins on the first byte after an inaccessible page.
 */
static int tag_at_wrap(void *arg)
{
	struct he_guard g;
	static const char txt[] = "xx<SCRIPT runat=server>body</Script>yy";
	int r;

	(void)arg;
	if (!he_guard_make2(&g, txt, sizeof txt - 1u, 1))
		return 9;
	r = kof_txt_tag_at(kof_buf_make(g.p, g.n), UINT64_MAX, "<", 1);
	he_guard_free(&g);
	return r == 0 ? 0 : 1;
}

static void t_scantext(void)
{
	struct he_status wrap = he_child(tag_at_wrap, NULL, 5);

	kof_buf b = kof_buf_make("xx<SCRIPT runat=server>body</Script>yy", 38);
	struct kof_script_info *s = new_info();

	if (!s) {
		CK(0, "memory");
		return;
	}
	CK(kof_txt_tag_at(b, 2, "<script", 7) == 1 && kof_txt_tag_at(b, 2, "<SCRIPT", 7) == 1, "tag_at ignores case");
	CK(kof_txt_tag_at(b, 3, "<script", 7) == 0 && kof_txt_tag_at(b, 35, "<script", 7) == 0,
	   "tag_at: a different place, one that runs off the end");
	CK(kof_txt_tag_at(b, 0, "xx", 0) == 1 || kof_txt_tag_at(b, 0, "xx", 0) == 0, "zero length does not read");
	CK(he_ok(wrap), "kof_txt_tag_at with an offset of 2^64-1 answers 0 without reading before the buffer");
	CK(kof_txt_has(b, 38, "RUNAT") == 1 && kof_txt_has(b, 38, "nothing") == 0 && kof_txt_has(b, 10, "body") == 0 && kof_txt_has(b, 0, "x") == 0,
	   "has: case folded, absent, outside the window, empty window");
	CK(kof_txt_find(b, 0, 38, "</script", 8) == 27 && kof_txt_find(b, 29, 38, "</script", 8) == KOF_TXT_NONE &&
	   kof_txt_find(b, 0, 30, "</script", 8) == KOF_TXT_NONE, "find: the first position at or after from, within to");
	CK(kof_txt_find(b, 0, UINT64_MAX, "yy", 2) == 36 && kof_txt_find(b, UINT64_MAX - 1u, UINT64_MAX, "yy", 2) == KOF_TXT_NONE &&
	   kof_txt_find(b, 5, 3, "yy", 2) == KOF_TXT_NONE, "find: to past the object is clipped, from near 2^64 and from > to find nothing");

	memset(s, 0, sizeof *s);
	CK(kof_isl_add(s, 10, 5) == 1 && kof_isl_add(s, 20, 0) == 1 && s->n_island == 1 && s->island[0].off == 10 && s->island[0].len == 5,
	   "add records one island and skips an empty one without calling the list full");
	{
		unsigned i;

		for (i = 1; i < KOF_SCRIPT_MAX_ISLAND; i++)
			CK(kof_isl_add(s, 100u + i * 10u, 5) == 1, "island %u", i);
		CK(s->n_island == KOF_SCRIPT_MAX_ISLAND, "the table fills at KOF_SCRIPT_MAX_ISLAND");
		CK(kof_isl_add(s, 99999, 5) == 0 && s->n_island == KOF_SCRIPT_MAX_ISLAND, "and the next add says so");
		kof_isl_seal(s, 100000);
		CK(s->anomalies & KOF_SCRIPT_ANOM_ISLANDS_FULL, "sealing a full list that ends before the object says the list is short");
		s->anomalies = 0;
		kof_isl_seal(s, 100u + (KOF_SCRIPT_MAX_ISLAND - 1u) * 10u + 5u);
		CK(!(s->anomalies & KOF_SCRIPT_ANOM_ISLANDS_FULL), "and one that ends at the object's end is complete");
	}
	memset(s, 0, sizeof *s);
	{
		/* The extents are 32 bits and part of the module ABI: an island that does not fit is refused and the
		 * anomaly says the list is short, never recorded at the wrapped offset. */
		CK(kof_isl_add(s, 0x100000005ull, 10) == 0 && s->n_island == 0 && (s->anomalies & KOF_SCRIPT_ANOM_ISLANDS_FULL),
		   "an island at offset 2^32+5 is refused and reported, not recorded at offset 5");
		s->anomalies = 0;
		CK(kof_isl_add(s, 5, 0x100000000ull) == 0 && s->n_island == 0 && (s->anomalies & KOF_SCRIPT_ANOM_ISLANDS_FULL),
		   "and so is one whose length does not fit");
		s->anomalies = 0;
		CK(kof_isl_add(s, 0xfffffff6ull, 10) == 1 && s->n_island == 1 && s->island[0].off == 0xfffffff6u &&
		   s->island[0].len == 10 && !s->anomalies, "one that ends exactly at 2^32 has both fields in range and is kept");
	}
	memset(s, 0, sizeof *s);
	{
		/* Joining must not wrap a length either. The buffer claims 8 GiB and holds 16 blanks: the guards decide before any
		 * blank beyond them is read, so a wrapped sum shows as a changed island and a read past the end as a crash. */
		static const uint8_t blanks[17] = "                ";
		kof_buf big = kof_buf_make(blanks, 0x200000000ull);

		s->n_island = 1;
		s->island[0].off = 0x10;
		s->island[0].len = 0xfffffff8u;
		kof_isl_join_ws(big, 0, s);
		CK(s->n_island == 1 && s->island[0].off == 0x10 && s->island[0].len == 0xfffffff8u,
		   "join_ws leaves an island alone when absorbing the blanks around it would pass 32 bits");
	}
	{
		/* Both server forms in one page, and the answers the memoised walk must give: a script element between two
		 * "<% %>", a client script that is not server code, and an unclosed element behind everything. */
		static const char pg[] = "<% x %>\n<script runat=server>aa</script>\n<%\ny\n%>\n<script>c</script>\n"
					 "<script runat=server>bb</script> <% z %>\n<%\nw\n%>";
		static const uint32_t want[][2] = { { 0, 7 }, { 29, 2 }, { 41, 7 }, { 89, 2 }, { 109, 7 } };
		unsigned i;

		memset(s, 0, sizeof *s);
		kof_svr_islands(kof_buf_make(pg, sizeof pg - 1u), 0, KOF_SCRIPT_ANY, s);
		kof_isl_join_ws(kof_buf_make(pg, sizeof pg - 1u), 0, s);
		CK(s->n_island == 5, "a page with both forms keeps all five islands: %u", s->n_island);
		for (i = 0; i < s->n_island && i < 5; i++)
			CK(s->island[i].off == want[i][0] && s->island[i].len == want[i][1], "island %u at %u+%u", i,
			   s->island[i].off, s->island[i].len);
		memset(s, 0, sizeof *s);
		{
			static const char un[] = "<% a %>\n<script runat=server>never closed\n<script runat=server>nor this";

			kof_svr_islands(kof_buf_make(un, sizeof un - 1u), 0, KOF_SCRIPT_ANY, s);
			CK(s->n_island == 1 && s->island[0].off == 0 && s->island[0].len == 7,
			   "an unclosed server element is not an island and ends the search for later ones");
		}
		{
			static const char ng[] = "<script <script runat=server>x</script>";

			memset(s, 0, sizeof *s);
			kof_svr_islands(kof_buf_make(ng, sizeof ng - 1u), 0, KOF_SCRIPT_ANY, s);
			CK(s->n_island == 1 && s->island[0].off == 29 && s->island[0].len == 1,
			   "an opener inside another's attribute list shares its '>' and its runat");
		}
	}
	memset(s, 0, sizeof *s);
	kof_isl_add(s, 0, 3);
	kof_isl_add(s, 4, 3);
	kof_isl_add(s, 12, 3);
	kof_isl_join_ws(kof_buf_make("abc def xyz ghi", 15), 0, s);
	CK(s->n_island >= 1 && islands_ok(s, 15), "joining keeps the contract");
	CK(kof_script_is_block(kof_buf_make("\n<?php\nx\n?>\n", 12), 1, 11) == 1, "a tag that spans lines is a block");
	CK(kof_script_is_block(kof_buf_make("a <?= $x ?> b", 13), 2, 11) == 0, "an insertion in a sentence is not");
	CK(kof_script_is_block(kof_buf_make("  <?= $x ?>  \n", 14), 2, 12) == 1, "one that owns its line is");
	CK(kof_script_is_block(kof_buf_make("x", 1), 0, 0) == 1 || kof_script_is_block(kof_buf_make("x", 1), 0, 0) == 0, "an empty island answers (callers give islands inside the object)");
	CK(strcmp(kof_script_region_name(KOF_SCAN_SCRIPT_BODY), "KOF_SCAN_SCRIPT_BODY") == 0 && kof_script_region_name(0xdead) == NULL, "region names: the enumerator spelling, NULL for a bit the format does not have");
	CK(kof_script_anomaly_name(0) != NULL && kof_script_anomaly_name(1000) == NULL, "anomaly names: NULL past the last");
	free(s);
}

/* ---- hostile pages -------------------------------------------------------------------------------- */

struct job {
	unsigned page;
	int      sweep;
};

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int parse_ok(kof_buf b, struct kof_script_info *s)
{
	struct kof_obj_ctx ctx;

	memset(&ctx, 0, sizeof ctx);
	(void)kof_script_sniff(b);
	(void)kof_script_parse(b, s, &ctx);
	return islands_ok(s, b.n);
}

static int sweep_child(void *arg)
{
	struct job *j = (struct job *)arg;
	const struct page *pg = &pages[j->page];
	struct kof_script_info *s = new_info();
	struct he_guard g;
	size_t i;
	unsigned bit;
	int bad = 0;

	if (!s)
		return 9;
	if (j->sweep == 0) {
		for (i = 0; i <= pg->n; i++) {
			if (!he_guard_make(&g, pg->text, i))
				return 9;
			bad |= !parse_ok(kof_buf_make(g.p, i), s);
			he_guard_free(&g);
		}
	} else {
		if (!he_guard_make(&g, pg->text, pg->n))
			return 9;
		for (i = 0; i < pg->n; i++)
			for (bit = 0; bit < 8; bit++) {
				g.p[i] ^= (uint8_t)(1u << bit);
				bad |= !parse_ok(kof_buf_make(g.p, pg->n), s);
				g.p[i] ^= (uint8_t)(1u << bit);
			}
		he_guard_free(&g);
	}
	free(s);
	return bad;
}

/* A page of `total` bytes made of `unit` repeated, optionally with a head. */
static uint8_t *repeat(const char *head, const char *unit, size_t total, size_t *out)
{
	size_t hl = strlen(head), ul = strlen(unit), at = 0;
	uint8_t *p = malloc(total + ul + hl + 1u);

	if (!p)
		return NULL;
	memcpy(p, head, hl);
	at = hl;
	while (at < total) {
		memcpy(p + at, unit, ul);
		at += ul;
	}
	*out = at;
	return p;
}

struct big {
	const char *name;
	const char *head;
	const char *unit;
	const char *km_what, *km_cap;   /* a known defect: the case is slow today */
	size_t      size;               /* 0: 1MB */
};

static const struct big bigs[] = {
	{ "unclosed php tags", "", "<?php ", NULL, NULL, 0 },
	{ "10000 php islands", "<html>", "<?php x ?>a", NULL, NULL, 0 },
	{ "unclosed asp", "<%@ Page %>", "<% ", NULL, NULL, 0 },
	{ "inline asp insertions", "<%@ Page %>", "<% x %>a", NULL, NULL, 512u << 10 },
	{ "server scripts never closed", "<%@ Page %>", "<script runat=\"server\">", NULL, NULL, 0 },
	{ "server script tags never ended", "<%@ Page %>", "<script ", NULL, NULL, 512u << 10 },
	{ "cfscript never closed", "<cfset a=1>", "<cfscript>", NULL, NULL, 512u << 10 },
	{ "markup tags never ended", "<?php x ?>", "<a ", NULL, NULL, 512u << 10 },
	{ "cfm tags", "", "<cfset a=1>", NULL, NULL, 0 },
	{ "cfm comments never closed", "<cfset a=1>", "<!--- ", NULL, NULL, 0 },
	{ "html scripts never closed", "<html>", "<script>", NULL, NULL, 0 },
	{ "unclosed elements", "<?php x ?>", "<p><td><b>", NULL, NULL, 0 },
	{ "elements wrapping code", "<table>", "<tr><?php x ?></tr>", NULL, NULL, 0 },
	{ "lone angle brackets", "<?php x ?>", "<", NULL, NULL, 0 },
	{ "shebang then tags", "#!/bin/sh\n", "<?php <% <cf ", NULL, NULL, 0 }
};

struct bigjob {
	unsigned which;
	size_t   size;
};

#define KM_BIT 0x10

static int big_child(void *arg)
{
	struct bigjob *j = (struct bigjob *)arg;
	const struct big *bg = &bigs[j->which];
	size_t n = 0;
	uint8_t *p = repeat(bg->head, bg->unit, j->size, &n);
	struct kof_script_info *s = new_info();
	struct he_guard g;
	double t0;
	int ok;

	if (!p || !s)
		return 9;
	if (!he_guard_make(&g, p, n))
		return 9;
	free(p);
	t0 = now();
	ok = parse_ok(kof_buf_make(g.p, n), s);
	printf("  %-30s %8zu bytes: %.3fs, %u islands, anomalies %llx\n", bg->name, n, now() - t0, s->n_island,
	       (unsigned long long)s->anomalies);
	he_guard_free(&g);
	if (!ok)
		return 1;
	if (now() - t0 < (bg->km_what ? 0.25 : 2.0))
		return 0;
	return bg->km_what ? KM_BIT : 2;
}

static void t_hostile(void)
{
	unsigned p, k;

	for (p = 0; p < sizeof pages / sizeof pages[0]; p++)
		for (k = 0; k < 2; k++) {
			struct job j;
			struct he_status st;

			j.page = p;
			j.sweep = (int)k;
			st = he_child(sweep_child, &j, 30);
			CK(he_ok(st), "%s, %s: %s", pages[p].name, k ? "every bit flipped" : "every prefix", he_how(st));
		}
	for (p = 0; p < sizeof bigs / sizeof bigs[0]; p++) {
		struct bigjob j;
		struct he_status st;

		j.which = p;
		j.size = bigs[p].size ? bigs[p].size : 1u << 20;
		st = he_child(big_child, &j, 60);
		if (!bigs[p].km_what) {
			CK(he_ok(st), "%s (%zuKB): %s", bigs[p].name, j.size >> 10, he_how(st));
			continue;
		}
		CK(st.exited && (st.code & 0x0f) == 0, "%s (%zuKB): %s", bigs[p].name, j.size >> 10, he_how(st));
		if (st.exited)
			KM_CHECK(!(st.code & KM_BIT), bigs[p].km_what, bigs[p].km_cap);
	}
}

int main(void)
{
	t_pages();
	t_walks();
	t_scantext();
	t_hostile();
	printf("api_engine_scripts: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
