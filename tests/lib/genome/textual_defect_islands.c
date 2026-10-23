/*
 * genome / textual_defect_islands - L17 of the lexer audit: kgenome_textual_islands (textual_api.c isl_span).
 *
 * An opening tag that comes while an island is open ("the first ends where the second begins", the comment said) delivered the first with end_tag = n, the end of the
 * TEXT, because the walk set the end only when a closing tag came: the islands of coldfusion, whose tags are all opening tags but "</cfscript>", overlapped - every one
 * of the four of `<cfset x=1>` and `<cfoutput>hi</cfoutput>` reached the end of the text. And the "#!" line of a shell script is a TAG (the lexer's way of keeping the
 * interpreter's line from being dropped as a comment) and was delivered as an island that opens at byte 0 and never closes, though the header says a shell has no islands.
 *
 * Asserted: for every language and every text of a small alphabet of its tags (a SWEEP, not a draw), the islands are in order, each one begins where the tag is and
 * ends no earlier than its tag's own bytes, and NONE OVERLAPS THE NEXT; an island that is not closed ends before the next one begins. And the two cases above, by value.
 *
 * Why the old tests missed it: (a) textual_islands.c never has a second opening tag before the first one closed (php, asp, aspx and jsp lex a second tag as code) and has
 * no coldfusion text; (c) it checks offsets of the texts it was written with and not the invariant the header states (islands are in order and do not overlap).
 *
 * usage: textual_defect_islands
 */

#include "textual_check.h"

struct got {
	struct kgenome_textual_island v[24];
	uint32_t n;
};

static int take(void *u, const struct kgenome_textual_island *is)
{
	struct got *g = u;

	if (g->n < 24u)
		g->v[g->n] = *is;
	g->n++;
	return 1;
}

static void islands(uint32_t lang, const uint8_t *src, uint32_t n, struct got *g)
{
	struct kgenome_textual_islands_req rq = { .in = src, .n = n, .lang = lang, .sink = take, .user = g };

	memset(g, 0, sizeof *g);
	(void)kgenome_textual_islands(&rq);
}

/* the invariants of the header: in order, inside the text, the tag's own bytes inside the island, and no overlap */
static int invariants(const struct got *g, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < g->n && i < 24u; i++) {
		const struct kgenome_textual_island *s = &g->v[i];

		if ((uint64_t)s->off + s->open_len > n || s->end_tag > n || s->end_tag < (uint64_t)s->off + s->open_len)
			return 0;
		if ((uint64_t)s->end_tag + s->close_len > n)
			return 0;
		if (i + 1u < g->n && i + 1u < 24u && (uint64_t)s->end_tag + s->close_len > g->v[i + 1u].off)
			return 0;
		if (i && s->off < g->v[i - 1u].off)
			return 0;
	}
	return 1;
}

static void sweep(uint32_t lang, const char *name, const char *alpha, uint32_t len)
{
	uint32_t na = (uint32_t)strlen(alpha), l, k, idx[10], shown = 0;
	uint8_t b[10];
	uint64_t cases = 0, bad = 0;
	static struct got g;

	for (l = 1; l <= len; l++) {
		for (k = 0; k < l; k++)
			idx[k] = 0;
		for (;;) {
			for (k = 0; k < l; k++)
				b[k] = (uint8_t)alpha[idx[k]];
			islands(lang, b, l, &g);
			cases++;
			if (!invariants(&g, l)) {
				bad++;
				if (shown < 3u) {
					uint32_t i;

					printf("  FAIL %s islands of [", name);
					for (i = 0; i < l; i++)
						printf(b[i] >= 0x20 && b[i] < 0x7f ? "%c" : "\\x%02x", b[i]);
					printf("]:");
					for (i = 0; i < g.n && i < 4u; i++)
						printf(" {%u,%u,%u,%u,%u}", g.v[i].off, g.v[i].open_len, g.v[i].end_tag, g.v[i].close_len, g.v[i].closed);
					printf("\n");
					shown++;
				}
			}
			for (k = 0; k < l && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == l)
				break;
		}
	}
	if (bad) {
		printf("  FAIL %s islands: %llu of %llu texts break the header's rules\n", name, (unsigned long long)bad, (unsigned long long)cases);
		fails++;
	}
}

int main(void)
{
	static struct got g;
	const char *cf = "<cfset x=1>\n<cfoutput>hi</cfoutput>\n";
	const char *sh = "#!/bin/sh\necho hi\n";

	islands(KGENOME_TEXTUAL_LANG_CFM, (const uint8_t *)cf, (uint32_t)strlen(cf), &g);
	CK(g.n >= 1u && invariants(&g, (uint32_t)strlen(cf)));
	islands(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)sh, (uint32_t)strlen(sh), &g);
	if (g.n) {
		printf("  FAIL sh islands of a script with a #! line: %u, a shell has none\n", g.n);
		fails++;
	}
	/* a "#!" line of any other language that names a tag is no island either */
	islands(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)"#!/bin/sh", 9, &g);
	CK(g.n == 0u);

	sweep(KGENOME_TEXTUAL_LANG_CFM, "cfm", "<cf/>a x#\n", 6);
	sweep(KGENOME_TEXTUAL_LANG_CFM, "cfm script", "<cfscript>/\n;", 6);
	sweep(KGENOME_TEXTUAL_LANG_SH, "sh", "#!a\n <'", 7);
	sweep(KGENOME_TEXTUAL_LANG_PHP, "php", "<?php =>\n\"'#/*", 6);
	sweep(KGENOME_TEXTUAL_LANG_ASP, "asp", "<%=>\n\"'rem ", 6);
	sweep(KGENOME_TEXTUAL_LANG_ASPX, "aspx", "<%=#@>\n\"'/", 6);
	sweep(KGENOME_TEXTUAL_LANG_JSP, "jsp", "<%=!@>\n\"'/-", 6);
	printf(fails ? "textual_defect_islands: %d FAILED\n" : "textual_defect_islands: ok\n", fails);
	return fails != 0;
}
