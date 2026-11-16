/*
 * diag/script_parts - kgenome_script_parts (celllysis/script_islands.h: the function table and the islands of a script from one lex) over
 * constructed pages of every language row, the input being [language byte][flags byte][text].
 *
 * Held (the island invariants, owner-agreed design points 1-4):
 *   LAYER   in each (layer, level) the islands are in file order, never overlap, lie inside the text, and none is empty
 *   LEVEL1  a level-1 island lies inside its level-0 parent (parent index valid), a FUNC names a function of its layer's table and lies
 *           inside that function's extent; a RUN holds no function start
 *   CODE    every function of the server table that starts inside a level-0 island is covered by a FUNC island of it
 *   TABLE   the function tables are ordered and disjoint (what kgenome_funcs_at's binary search needs), inside the text
 *   ORDER   the same text twice gives the same islands (the digest): the build is a pure function of the bytes
 *   API     kgenome_textual_lang_known is true exactly for the rows that lex; kgenome_textual_tag_own is never longer than its tag;
 *           kgenome_textual_page_syntax answers a value of its enum, NONE for a language that is not a page
 */
#include "diag_seed.h"

#include <celllysis/script_islands.h>
#include <textual/textual.h>

static const struct { uint32_t lang; const char *text; } PAGES[] = {
	{ KGENOME_TEXTUAL_LANG_PHP, "<html><?php function f(){ ?>x<?php } $a=1; ?><b><?php if ($x): ?>y<?php endif; ?>\n<script>var q=\"<?= $u ?>\"; function g(){return 1}</script><a onclick=\"go()\" href=\"javascript:h()\">x</a>" },
	{ KGENOME_TEXTUAL_LANG_PHP, "<?php\n$f = fn($a) => $a + 1;\nclass A { public static function m() { return function () { return 1; }; } }\n" },
	{ KGENOME_TEXTUAL_LANG_ASP, "<% If x Then %>a<% End If %>\n<% Sub s()\r\nResponse.Write 1\r\nEnd Sub %><script>function c(){}</script>" },
	{ KGENOME_TEXTUAL_LANG_ASP, "<%@ Language=JScript %><% function f(a) { %>x<% } %>" },
	{ KGENOME_TEXTUAL_LANG_ASPX, "<%@ Page Language=\"C#\" %><script runat=\"server\">\nvoid Page_Load(object s, EventArgs e)\n{\n Run();\n}\n</script><% if (a) { %>t<% } %>" },
	{ KGENOME_TEXTUAL_LANG_JSP, "<%! String run(String c) throws Exception { return c; } %><% if (a) { %>x<% } %>" },
	{ KGENOME_TEXTUAL_LANG_CFM, "<cffunction name=\"go\"><cfif x><cfset a=1></cfif></cffunction>\n<cfscript>function h(a) output=false { return a; }</cfscript>" },
	{ KGENOME_TEXTUAL_LANG_JS, "const f = (a) => { return a; };\nconst g = x => x + 1\nclass A { m(a) { return 1 } }\n" },
	{ KGENOME_TEXTUAL_LANG_PY, "@d\ndef f(a):\n    return a\nx = 1\n" },
	{ KGENOME_TEXTUAL_LANG_VBS, "Function f(a)\r\n f = a\r\nEnd Function\r\nx = f(1)\r\n" },
	{ KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\nf() { echo }; }\nf\n" },
	{ KGENOME_TEXTUAL_LANG_RUBY, "def f(a)\n  a\nend\nf(1)\n" },
	{ KGENOME_TEXTUAL_LANG_LUA, "local function f(a) return a end\nf(1)\n" },
	{ KGENOME_TEXTUAL_LANG_TCL, "proc f {a} { return $a }\nf 1\n" },
	{ KGENOME_TEXTUAL_LANG_BAT, "@echo off\r\ncall :f\r\nexit /b\r\n:f\r\necho x\r\ngoto :eof\r\n" },
};

static const char *const dict[] = { "<?php ", "?>", "<?=", "<%", "%>", "<%!", "<script>", "</script>", "<script runat=\"server\">",
				    "{", "}", "(", ")", "=>", "function ", "fn(", "if (x):", "endif;", "End If", "End Sub", "Sub s()\n",
				    "<cfif x>", "</cfif>", "onclick=\"", "javascript:", "\n", "\r\n", "def f():\n", " end\n", NULL };

static void seeds(struct fz_corpus *c)
{
	size_t i;
	uint8_t buf[1024];

	for (i = 0; i < sizeof PAGES / sizeof PAGES[0]; i++) {
		size_t l = strlen(PAGES[i].text);
		char nm[32];

		buf[0] = (uint8_t)PAGES[i].lang;
		buf[1] = 0;
		memcpy(buf + 2, PAGES[i].text, l);
		snprintf(nm, sizeof nm, "parts_%zu", i);
		fz_corpus_add(c, nm, buf, l + 2u);
	}
}

static void check_level(struct fz_ctx *c, const struct kgenome_script_islands *s, const struct kgenome_func_set *fs, uint32_t layer,
			uint32_t level, size_t n)
{
	const struct kgenome_script_isl_list *L = &s->lv[layer][level];
	uint32_t i;

	for (i = 0; i < L->n; i++) {
		const struct kgenome_script_island *e = &L->v[i];

		FZ_CHECK(c, e->len > 0 && e->off + e->len <= n, "an island empty or outside the text");
		FZ_CHECK(c, !i || L->v[i - 1u].off + L->v[i - 1u].len <= e->off, "islands of one layer and level overlap or are out of order");
		if (level == 1u) {
			FZ_CHECK(c, e->parent < s->lv[layer][0].n, "a level-1 island's parent is not a level-0 island");
			if (e->parent < s->lv[layer][0].n) {
				const struct kgenome_script_island *p = &s->lv[layer][0].v[e->parent];

				FZ_CHECK(c, e->off >= p->off && e->off + e->len <= p->off + p->len, "a level-1 island outside its parent");
			}
			if (e->kind == KGENOME_SCRIPT_ISL_FUNC) {
				FZ_CHECK(c, fs && e->func < fs->n, "a FUNC island names no function of its layer");
				if (fs && e->func < fs->n)
					FZ_CHECK(c, e->off >= fs->v[e->func].off && e->off + e->len <= fs->v[e->func].off + fs->v[e->func].len,
						 "a FUNC island outside its function");
			} else {
				FZ_CHECK(c, e->kind == KGENOME_SCRIPT_ISL_RUN, "a level-1 island that is neither FUNC nor RUN");
			}
		} else {
			FZ_CHECK(c, e->kind == KGENOME_SCRIPT_ISL_PIECE && e->parent == i, "a level-0 island that is not a PIECE of its own index");
		}
		fz_digest(c, e->off ^ (e->len << 20) ^ ((uint64_t)e->kind << 56) ^ ((uint64_t)layer << 60) ^ ((uint64_t)level << 62));
		fz_step(&c->steps, 1);
	}
}

static void check_table(struct fz_ctx *c, const struct kgenome_func_set *fs, size_t n)
{
	uint32_t i;

	for (i = 0; i < fs->n; i++) {
		FZ_CHECK(c, fs->v[i].len > 0 && fs->v[i].off + fs->v[i].len <= n, "a function empty or outside the text");
		FZ_CHECK(c, !i || fs->v[i - 1u].off + fs->v[i - 1u].len <= fs->v[i].off, "functions overlap or are out of order");
		fz_digest(c, fs->v[i].off ^ (fs->v[i].len << 24));
	}
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kgenome_script_parts p;
	struct kgenome_script_parts_req rq;
	uint32_t lang, i;

	if (n < 2u || n - 2u > 0xffffffffu)
		return 0;
	lang = in[0] % (KGENOME_TEXTUAL_LANG_COUNT + 1u);
	rq.lang = lang;
	rq.flags = in[1] & 1u ? KGENOME_TEXTUAL_FRAGMENT : 0u;
	rq.want = KGENOME_SCRIPT_PART_ISLANDS | (in[1] & 2u ? 0u : KGENOME_SCRIPT_PART_CLIENT);
	rq.in = in + 2;
	rq.n = n - 2u;
	FZ_CHECK(c, kgenome_textual_lang_known(lang) == (lang > KGENOME_TEXTUAL_LANG_NONE && lang < KGENOME_TEXTUAL_LANG_COUNT),
		 "lang_known disagrees with the rows");
	{
		enum kgenome_textual_block_syntax syn = kgenome_textual_page_syntax(lang, rq.in, (uint32_t)rq.n, (uint32_t)rq.n);

		FZ_CHECK(c, (unsigned)syn <= (unsigned)KGENOME_TEXTUAL_SYN_VB, "page syntax outside its enum");
		FZ_CHECK(c, syn == KGENOME_TEXTUAL_SYN_NONE || lang == KGENOME_TEXTUAL_LANG_ASP || lang == KGENOME_TEXTUAL_LANG_ASPX ||
			 lang == KGENOME_TEXTUAL_LANG_JSP, "a block syntax for a language that is not a page");
		fz_digest(c, syn);
	}
	FZ_CHECK(c, kgenome_textual_tag_own(lang, rq.in, (uint32_t)(rq.n < 6u ? rq.n : 6u), 0) <= (rq.n < 6u ? rq.n : 6u),
		 "a tag's own bytes longer than the tag");
	kgenome_script_parts(&rq, &p);
	FZ_CHECK(c, (unsigned)p.isl.status <= (unsigned)KGENOME_NOMEM, "status outside the enum");
	if (p.isl.status == KGENOME_OK && p.funcs.status == KGENOME_OK) {
		check_table(c, &p.funcs, rq.n);
		check_table(c, &p.isl.client_funcs, rq.n);
		for (i = 0; i < 2u; i++) {
			check_level(c, &p.isl, i ? &p.isl.client_funcs : &p.funcs, i, 0u, rq.n);
			check_level(c, &p.isl, i ? &p.isl.client_funcs : &p.funcs, i, 1u, rq.n);
		}
		/* every server function that starts in a level-0 island is covered by a FUNC island there */
		for (i = 0; i < p.funcs.n; i++) {
			const struct kgenome_script_isl_list *L1 = &p.isl.lv[KGENOME_SCRIPT_ISL_SERVER][1];
			uint32_t k, in0 = 0, cov = 0;

			for (k = 0; k < p.isl.lv[KGENOME_SCRIPT_ISL_SERVER][0].n; k++) {
				const struct kgenome_script_island *e = &p.isl.lv[KGENOME_SCRIPT_ISL_SERVER][0].v[k];

				in0 |= p.funcs.v[i].off >= e->off && p.funcs.v[i].off < e->off + e->len;
			}
			for (k = 0; k < L1->n; k++)
				cov |= L1->v[k].kind == KGENOME_SCRIPT_ISL_FUNC && L1->v[k].func == i;
			FZ_CHECK(c, !in0 || cov, "a function that starts in a level-0 island has no FUNC island");
		}
	}
	fz_digest(c, p.funcs.n ^ ((uint64_t)p.isl.n_pieces << 32));
	{
		/* the islands alone are given back by their own free, which leaves a zeroed table */
		struct kgenome_script_islands own = p.isl;

		memset(&p.isl, 0, sizeof p.isl);
		kgenome_script_islands_free(&own);
		FZ_CHECK(c, !own.lv[0][0].v && !own.lv[0][0].n && !own.client_funcs.v, "the free left a table behind");
	}
	kgenome_script_parts_free(&p);
	return 0;
}

FZ_ADAPTER(script_parts, .name = "kgenome/script_parts",
	   .covers = "kgenome_script_parts kgenome_script_parts_free kgenome_script_islands_free kgenome_textual_lang_known kgenome_textual_tag_own "
		     "kgenome_textual_page_syntax",
	   .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000, .steps_base = 4000000u, .steps_per_byte = 64,
	   .shape = FZ_REQ, .seeds = seeds, .dict = dict, .run = run);
