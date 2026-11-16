/*
 * genome / script_islands - the islands of a script (celllysis/script_islands.h, kgenome_script_parts) from CONSTRUCTED text only, linked
 * against libkgenome.a alone. Each language row is tested on its own specification (owner, 2026-11-14: "chia dispatch mỗi ngôn ngữ theo
 * đúng tiêu chuẩn ngôn ngữ").
 *
 * WHAT IS ASSERTED: the exact bytes of every island of a (layer, level) for the shapes the design names (owner-agreed points 1-4):
 * pieces at offset 0 and at the end, unterminated pieces, `<?=`, a syntax block joining pieces (braces, php's alternative syntax, vb's
 * If / Sub, cfml's paired tags), [run][function][run] at level 1, runs of white space and comments that are no island, the client layer
 * (a <script> body, an on* attribute, a javascript: url, and what is NOT code: src, a data block, an html comment), the per-language
 * function rows the islands are cut by (php `fn`, javascript arrows and methods, java and c# methods, cfml's tag and cfscript), CR / LF /
 * CRLF, a byte order mark, UTF-16, a table past the module ABI's 256 islands, hostile sizes in linear time, and the PROPERTIES of any
 * answer over generated pages: every code byte in exactly one island per layer and level, order independence of a concatenation, and
 * the same answer twice.
 *
 * WHY THE OLD TESTS MISSED IT: (a) for every group: the table did not exist - the islands were four readings (scan_ext.c's Merge 161
 * extents, the parse's kof_script_info list, the eval route's set, the mutation cut's remainder) and none of them joined a block across
 * tags, cut a page by its functions or read the client layer; tests/lib/genome/textual_islands.c tested the lexer's tag reader only.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_islands.h>

#define SRV KGENOME_SCRIPT_ISL_SERVER
#define CLI KGENOME_SCRIPT_ISL_CLIENT

/* ---- the kit --------------------------------------------------------------------------------------------------------------- */

static void parts_of(uint32_t lang, uint32_t flags, const char *src, size_t n, struct kgenome_script_parts *p)
{
	const struct kgenome_script_parts_req rq = { .lang = lang, .flags = flags, .want = KGENOME_SCRIPT_PART_ISLANDS | KGENOME_SCRIPT_PART_CLIENT,
						     .in = (const uint8_t *)src, .n = n };

	kgenome_script_parts(&rq, p);
}

/* The properties of any answer: ordered, disjoint, inside the text, a level-1 island inside its parent, a FUNC inside its function and
 * every function that starts in a level-0 island covered by a FUNC island of it, a RUN that holds a byte that is not white space. */
static void props(const char *src, size_t n, const struct kgenome_script_parts *p)
{
	uint32_t ly, lv, i, f;

	CK(p->isl.status == KGENOME_OK);
	for (ly = 0; ly < KGENOME_SCRIPT_ISL_LAYERS; ly++)
		for (lv = 0; lv < 2u; lv++) {
			const struct kgenome_script_isl_list *L = &p->isl.lv[ly][lv];
			const struct kgenome_func_set *fs = ly == SRV ? &p->funcs : &p->isl.client_funcs;

			for (i = 0; i < L->n; i++) {
				const struct kgenome_script_island *e = &L->v[i];

				CK(e->len > 0 && e->off + e->len <= n);
				CK(!i || L->v[i - 1u].off + L->v[i - 1u].len <= e->off);
				if (!lv) {
					CK(e->kind == KGENOME_SCRIPT_ISL_PIECE && e->parent == i);
					continue;
				}
				CK(e->parent < p->isl.lv[ly][0].n);
				if (e->parent < p->isl.lv[ly][0].n) {
					const struct kgenome_script_island *q = &p->isl.lv[ly][0].v[e->parent];

					CK(e->off >= q->off && e->off + e->len <= q->off + q->len);
				}
				if (e->kind == KGENOME_SCRIPT_ISL_FUNC) {
					CK(e->func < fs->n);
					if (e->func < fs->n)
						CK(e->off >= fs->v[e->func].off && e->off + e->len <= fs->v[e->func].off + fs->v[e->func].len);
				} else {
					uint64_t k;
					int code = 0;

					CK(e->kind == KGENOME_SCRIPT_ISL_RUN);
					for (k = e->off; k < e->off + e->len; k++)
						code |= !strchr(" \t\r\n", src[k]);
					CK(code);
				}
			}
		}
	for (f = 0; f < p->funcs.n; f++) {
		const struct kgenome_script_isl_list *L0 = &p->isl.lv[SRV][0], *L1 = &p->isl.lv[SRV][1];
		int in0 = 0, cov = 0;

		CK(!f || p->funcs.v[f - 1u].off + p->funcs.v[f - 1u].len <= p->funcs.v[f].off);
		for (i = 0; i < L0->n; i++)
			in0 |= p->funcs.v[f].off >= L0->v[i].off && p->funcs.v[f].off < L0->v[i].off + L0->v[i].len;
		for (i = 0; i < L1->n; i++)
			cov |= L1->v[i].kind == KGENOME_SCRIPT_ISL_FUNC && L1->v[i].func == f;
		CK(!in0 || cov);
	}
}

/* The islands of (layer, level) are exactly `want` (texts, NULL-terminated), in order; `kinds` (or NULL) the kind letter of each:
 * 'P' piece, 'F' function, 'R' run. */
static void want_isl(const char *where, const char *src, const struct kgenome_script_parts *p, uint32_t ly, uint32_t lv,
		     const char *const *want, const char *kinds)
{
	const struct kgenome_script_isl_list *L = &p->isl.lv[ly][lv];
	uint32_t i, nw = 0;
	int bad = hk_fails;

	while (want[nw])
		nw++;
	CK(L->n == nw);
	for (i = 0; i < nw && i < L->n; i++) {
		CK(L->v[i].len == strlen(want[i]) && !memcmp(src + L->v[i].off, want[i], strlen(want[i])));
		if (kinds)
			CK("PFR"[L->v[i].kind] == kinds[i]);
	}
	if (hk_fails != bad) {
		printf("  in %s (layer %u level %u): got %u, wanted %u\n", where, ly, lv, L->n, nw);
		for (i = 0; i < L->n; i++)
			printf("    %c [%llu,+%llu) fl %x |%.*s|\n", "PFR"[L->v[i].kind], (unsigned long long)L->v[i].off,
			       (unsigned long long)L->v[i].len, L->v[i].flags, (int)L->v[i].len, src + L->v[i].off);
	}
}

#define W(...) ((const char *const[]){ __VA_ARGS__, NULL })
#define NONE ((const char *const[]){ NULL })

/* One case: the text, its server level 0 and level 1 (kinds), and its client level 0. */
static void check(const char *where, uint32_t lang, uint32_t flags, const char *src, const char *const *l0, const char *const *l1,
		  const char *k1, const char *const *c0)
{
	struct kgenome_script_parts p;
	size_t n = strlen(src);

	parts_of(lang, flags, src, n, &p);
	props(src, n, &p);
	if (l0)
		want_isl(where, src, &p, SRV, 0, l0, NULL);
	if (l1)
		want_isl(where, src, &p, SRV, 1, l1, k1);
	if (c0)
		want_isl(where, src, &p, CLI, 0, c0, NULL);
	kgenome_script_parts_free(&p);
}

/* ---- php ------------------------------------------------------------------------------------------------------------------- */

static void php_pieces(void)
{
	/* a piece at offset 0 and one at the end that never closes (php: a file may omit its last "?>"); `<?=` is a piece; a tag with
	 * nothing in it, and one with a comment alone, are not islands */
	check("php pieces", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php echo 1; ?>A<?= $x ?>B<?php ?>C<?php // c\n ?>D<?php\n$y = 2;\n",
	      W(" echo 1; ", " $x ", "\n$y = 2;\n"), W(" echo 1; ", " $x ", "\n$y = 2;\n"), "RRR", NONE);
	/* the open flag on the one that ran to the end */
	{
		const char *s = "<?php $a; ?>x<?php $b;";
		struct kgenome_script_parts p;

		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, s, strlen(s), &p);
		CK(p.isl.lv[SRV][0].n == 2 && !(p.isl.lv[SRV][0].v[0].flags & KGENOME_SCRIPT_ISL_F_OPEN) &&
		   (p.isl.lv[SRV][0].v[1].flags & KGENOME_SCRIPT_ISL_F_OPEN));
		kgenome_script_parts_free(&p);
	}
	/* "?>" in a // or # comment closes the piece (php: a line comment ends before "?>"); in a string or a heredoc it does not */
	check("php close in comment", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php $a = 1; // x ?>M<?php $b; # y ?>N", W(" $a = 1; // x ", " $b; # y "),
	      NULL, NULL, NONE);
	check("php close in string", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php $a = '?>'; $b = <<<E\n?>\nE;\n?>M", W(" $a = '?>'; $b = <<<E\n?>\nE;\n"),
	      NULL, NULL, NONE);
	/* no tag: no island; a byte order mark in front of the tag is markup */
	check("php no tag", KGENOME_TEXTUAL_LANG_PHP, 0, "hello <?xml version", NONE, NONE, NULL, NONE);
	check("php bom", KGENOME_TEXTUAL_LANG_PHP, 0, "\xef\xbb\xbf<?php function f(){} ?>", W(" function f(){} "), W("function f(){}"), "F",
	      NONE);
}

static void php_join(void)
{
	/* a function opened in one piece and closed in a later one is ONE island with the markup between, and level 1 cuts it
	 * [function][run]; the next piece starts a new island */
	check("php function across tags", KGENOME_TEXTUAL_LANG_PHP, 0,
	      "<html><?php function f(){ ?>x<?php } $a=1; ?><b><?php g(); ?>",
	      W(" function f(){ ?>x<?php } $a=1; ", " g(); "), W("function f(){ ?>x<?php }", " $a=1; ", " g(); "), "FRR", NONE);
	/* an if block with braces across three pieces */
	check("php braces across tags", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php if ($a) { ?>A<?php } else { ?>B<?php } ?>C<?php echo 1; ?>",
	      W(" if ($a) { ?>A<?php } else { ?>B<?php } ", " echo 1; "), NULL, NULL, NONE);
	/* a stray "}" does not join a piece to the one before it; an open "{" runs to the last piece, flagged open */
	check("php stray close", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php $a; ?>x<?php } $b; ?>y<?php { $c; ?>z<?php $d;",
	      W(" $a; ", " } $b; ", " { $c; ?>z<?php $d;"), NULL, NULL, NONE);
}

static void php_alt(void)
{
	/* php's alternative syntax, every opener and closer, in any case; else: and elseif (...): continue the block */
	check("php alt if", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php if ($a): ?>A<?php elseif ($b): ?>B<?php else: ?>C<?php endif; ?>D<?php echo 9; ?>",
	      W(" if ($a): ?>A<?php elseif ($b): ?>B<?php else: ?>C<?php endif; ", " echo 9; "), NULL, NULL, NONE);
	/* a member or a static name spelled like a closer closes nothing */
	check("php alt member", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php if ($a): $o->endif(); A::endif(); ?>x<?php endif; ?>y<?php echo 1; ?>",
	      W(" if ($a): $o->endif(); A::endif(); ?>x<?php endif; ", " echo 1; "), NULL, NULL, NONE);
	check("php alt loops", KGENOME_TEXTUAL_LANG_PHP, 0,
	      "<?php foreach ($l as $x): ?>a<?php endforeach; ?>|<?php for ($i=0;$i<2;$i++): ?>b<?php endfor ?>|<?php while ($w): ?>c<?php endwhile; ?>|"
	      "<?php switch ($s): ?><?php case 1: ?>d<?php endswitch; ?>|<?php declare(ticks=1): ?>e<?php enddeclare; ?>",
	      W(" foreach ($l as $x): ?>a<?php endforeach; ", " for ($i=0;$i<2;$i++): ?>b<?php endfor ",
		" while ($w): ?>c<?php endwhile; ", " switch ($s): ?><?php case 1: ?>d<?php endswitch; ", " declare(ticks=1): ?>e<?php enddeclare; "),
	      NULL, NULL, NONE);
	check("php alt case", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php IF ($a): ?>A<?php EndIf; ?>", W(" IF ($a): ?>A<?php EndIf; "), NULL, NULL, NONE);
	/* not openers: do-while's while (no colon), a method named like a keyword, a ternary's ":" , a static call "::" */
	check("php alt not", KGENOME_TEXTUAL_LANG_PHP, 0,
	      "<?php do { $x(); } while ($a); ?>1<?php $o->if($a); ?>2<?php $t = $a ? ($b) : $c; ?>3<?php if ($a) A::b(); ?>4",
	      W(" do { $x(); } while ($a); ", " $o->if($a); ", " $t = $a ? ($b) : $c; ", " if ($a) A::b(); "), NULL, NULL, NONE);
}

static void php_funcs(void)
{
	/* [run][function][run][function]; nested functions and closures belong to the outermost; `static fn` and `fn` are functions whose
	 * body is one expression (php 7.4); a run of comments and white space between two functions is no island */
	check("php level 1", KGENOME_TEXTUAL_LANG_PHP, 0,
	      "<?php $a = 1;\nfunction f() { $g = function () { return 1; }; }\n/* c */\nfunction h() {}\n$m = fn($x) => $x + 1;\necho 2;\n",
	      W(" $a = 1;\nfunction f() { $g = function () { return 1; }; }\n/* c */\nfunction h() {}\n$m = fn($x) => $x + 1;\necho 2;\n"),
	      W(" $a = 1;\n", "function f() { $g = function () { return 1; }; }", "function h() {}", "\n$m = ", "fn($x) => $x + 1",
		";\necho 2;\n"),
	      "RFFRFR", NONE);
	check("php class methods", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php class A { public static function m() {} private function n() {} }",
	      W(" class A { public static function m() {} private function n() {} }"),
	      W(" class A { ", "public static function m() {}", "private function n() {}", " }"), "RFFR", NONE);
}

static void php_eol(void)
{
	/* CR, LF and CRLF: the same islands (php's tag takes one line break of any of the three) */
	check("php crlf", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php\r\nif ($a) {\r\n?>\r\nA\r\n<?php\r\n}\r\n?>\r\n",
	      W("\r\nif ($a) {\r\n?>\r\nA\r\n<?php\r\n}\r\n"), NULL, NULL, NONE);
	check("php cr", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php\rif ($a) {\r?>\rA\r<?php\r}\r?>\r", W("\rif ($a) {\r?>\rA\r<?php\r}\r"), NULL, NULL, NONE);
	/* UTF-16: php reads bytes, and "<\0?\0" is not its tag: no island, and nothing read past the text */
	{
		static const char u16[] = "<\0?\0p\0h\0p\0 \0e\0c\0h\0o\0 \0" "1\0;\0";
		struct kgenome_script_parts p;

		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, u16, sizeof u16 - 1u, &p);
		CK(p.isl.status == KGENOME_OK && p.isl.lv[SRV][0].n == 0);
		kgenome_script_parts_free(&p);
	}
}

static void php_header_tag(void)
{
	/* IS-6: a tag's own bytes are never more than the span asked about (it answered 2 for a 1-byte "<"; found by the fuzz row) */
	CK(kgenome_textual_tag_own(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)"<", 1u, 0) <= 1u);
	CK(kgenome_textual_tag_own(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)"", 0u, 0) == 0u);
	CK(kgenome_textual_tag_own(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)"<?php ", 6u, 0) == 5u);
	/* IS-5: a declaration's header does not cross a closing tag (php reads "?>" as ";"): no function, and the brace of the next piece
	 * is a block of its own */
	check("php header across a tag", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php function f() ?>x<?php { g(); } ?>", W(" function f() ", " { g(); } "),
	      W(" function f() ", " { g(); } "), "RR", NONE);
}

static void php_fragment(void)
{
	/* code from its first byte (an eval argument): the first piece starts at 0 and has no tag; "?>" leaves php as in a file */
	check("php fragment", KGENOME_TEXTUAL_LANG_PHP, KGENOME_TEXTUAL_FRAGMENT, "$a=1; function f(){} ?> x <?php g();",
	      W("$a=1; function f(){} ", " g();"), W("$a=1; ", "function f(){}", " g();"), "RFR", NONE);
}

static void php_client(void)
{
	/* the client layer: a <script> body (with a php piece inside it: both layers hold it), an on* value, a javascript: url; not code:
	 * a script with src, a data block, an html comment, a style body */
	check("php client", KGENOME_TEXTUAL_LANG_PHP, 0,
	      "<?php $u = 1; ?><script>var q = \"<?= $u ?>\"; function g() { return 1; }</script>"
	      "<a onclick=\"go()\" href=\"javascript:h()\">x</a><script src=\"a.js\">bad()</script>"
	      "<script type=\"text/template\"><b></b></script><!-- <script>c()</script> --><style>a{x:onclick=\"y\"}</style>"
	      "<script type=\"module\">m()</script><SCRIPT LANGUAGE=\"VBScript\">MsgBox 1</SCRIPT><script type=\"\">e()</script>",
	      W(" $u = 1; ", " $u "), NULL, NULL,
	      W("var q = \"<?= $u ?>\"; function g() { return 1; }", "go()", "h()", "m()", "MsgBox 1", "e()"));
	{
		const char *s = "<?php $a; ?><script>function g() { return 1; }</script><b onload=\"k()\">";
		struct kgenome_script_parts p;

		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, s, strlen(s), &p);
		props(s, strlen(s), &p);
		want_isl("php client level 1", s, &p, CLI, 1, W("function g() { return 1; }", "k()"), "FR");
		CK(p.isl.client_funcs.n == 1 && p.isl.lv[CLI][0].v[1].flags == KGENOME_SCRIPT_ISL_F_ATTR);
		CK(p.isl.lv[CLI][0].v[0].lang == KGENOME_TEXTUAL_LANG_JS && p.isl.lv[CLI][1].n && p.isl.lv[CLI][1].v[0].lang == KGENOME_TEXTUAL_LANG_JS);
		CK(p.isl.lv[SRV][1].n && p.isl.lv[SRV][1].v[0].lang == KGENOME_TEXTUAL_LANG_PHP);
		kgenome_script_parts_free(&p);
	}
	/* an unterminated script element runs to the end, open */
	{
		const char *s = "<?php $a; ?><script>x();";
		struct kgenome_script_parts p;

		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, s, strlen(s), &p);
		CK(p.isl.lv[CLI][0].n == 1 && (p.isl.lv[CLI][0].v[0].flags & KGENOME_SCRIPT_ISL_F_OPEN));
		kgenome_script_parts_free(&p);
	}
}

/* ---- server pages ---------------------------------------------------------------------------------------------------------- */

static void asp_vb(void)
{
	/* vbscript (asp's default): a block If across pieces joins, a one-line If does not; For/Next, Do/Loop, While/Wend, Select Case,
	 * With; a Sub across pieces is one function with the markup in it; ":" separates statements and " _" continues a line */
	check("asp if", KGENOME_TEXTUAL_LANG_ASP, 0, "<% If x Then %>a<% End If %>|<% If y Then z %>|<% If a Then : b : End If %>",
	      W(" If x Then %>a<% End If ", " If y Then z ", " If a Then : b : End If "), NULL, NULL, NONE);
	/* `End` alone is the statement that stops the program: it closes no block */
	check("asp end", KGENOME_TEXTUAL_LANG_ASP, 0, "<% If x Then %><% End %>a<% End If %>|<% y %>", W(" If x Then %><% End %>a<% End If ", " y "),
	      NULL, NULL, NONE);
	check("asp loops", KGENOME_TEXTUAL_LANG_ASP, 0,
	      "<% For i = 1 To 2 %>a<% Next %>|<% Do While x %>b<% Loop %>|<% While y %>c<% Wend %>|<% Select Case z %><% Case 1 %>d<% End Select %>"
	      "|<% With o %>e<% End With %>",
	      W(" For i = 1 To 2 %>a<% Next ", " Do While x %>b<% Loop ", " While y %>c<% Wend ",
		" Select Case z %><% Case 1 %>d<% End Select ", " With o %>e<% End With "),
	      NULL, NULL, NONE);
	check("asp sub", KGENOME_TEXTUAL_LANG_ASP, 0, "<% Sub s(a) %>\r\n<b>x</b>\r\n<% End Sub\r\nIf q _\r\n Then %>t<% End If %>",
	      W(" Sub s(a) %>\r\n<b>x</b>\r\n<% End Sub\r\nIf q _\r\n Then %>t<% End If "),
	      W("Sub s(a) %>\r\n<b>x</b>\r\n<% End Sub", "\r\nIf q _\r\n Then %>t<% End If "), "FR", NONE);
	/* jscript, named by the directive: braces */
	check("asp jscript", KGENOME_TEXTUAL_LANG_ASP, 0, "<%@ Language=JScript %><% function f(a) { %>x<% } %>",
	      W(" function f(a) { %>x<% } "), W("function f(a) { %>x<% }"), "F", NONE);
}

static void aspx_cs(void)
{
	/* c#: the methods of <script runat="server"> (a constructor-free method, an expression-bodied one), braces of "<% %>" joining */
	check("aspx c#", KGENOME_TEXTUAL_LANG_ASPX, 0,
	      "<%@ Page Language=\"C#\" %><script runat=\"server\">\nvoid Page_Load(object s, EventArgs e)\n{\n  Run();\n}\npublic int X() => 1;\n</script>"
	      "\n<% if (a) { %>t<% } %>",
	      W("\nvoid Page_Load(object s, EventArgs e)\n{\n  Run();\n}\npublic int X() => 1;\n", " if (a) { %>t<% } "),
	      W("void Page_Load(object s, EventArgs e)\n{\n  Run();\n}", "public int X() => 1", ";\n", " if (a) { %>t<% } "), "FFRR", NONE);
	/* a vb.net page: the vb rows */
	check("aspx vb", KGENOME_TEXTUAL_LANG_ASPX, 0, "<%@ Page Language=\"VB\" %><script runat=\"server\">\nSub Page_Load()\n Run()\nEnd Sub\n</script>",
	      W("\nSub Page_Load()\n Run()\nEnd Sub\n"), W("Sub Page_Load()\n Run()\nEnd Sub"), "F", NONE);
}

static void jsp_java(void)
{
	/* java: a method of "<%! %>" (with throws); a scriptlet is the body of _jspService and holds no function of its own; its braces
	 * join pieces */
	check("jsp", KGENOME_TEXTUAL_LANG_JSP, 0,
	      "<%! private String run(String c) throws Exception { return c; } %>\n<% if (a) { %>x<% } %>\n<% void g() { } %>",
	      W(" private String run(String c) throws Exception { return c; } ", " if (a) { %>x<% } ", " void g() { } "),
	      W("private String run(String c) throws Exception { return c; }", " if (a) { %>x<% } ", " void g() { } "), "FRR", NONE);
}

static void cfm_tags(void)
{
	/* cfml: a paired tag joins what it holds, a tag with no end tag does not; <cffunction> and cfscript's function are functions */
	check("cfm", KGENOME_TEXTUAL_LANG_CFM, 0,
	      "<cfif x>\n<cfset a=1>\n</cfif>\n<cfset b=2>\n<cffunction name=\"go\">\n<cfreturn 1>\n</cffunction>\n<cfscript>function h(a) output=false { return a; }</cfscript>",
	      W("<cfif x>\n<cfset a=1>\n</cfif>", "<cfset b=2>", "<cffunction name=\"go\">\n<cfreturn 1>\n</cffunction>",
		"<cfscript>function h(a) output=false { return a; }</cfscript>"),
	      W("<cfif x>\n<cfset a=1>\n</cfif>", "<cfset b=2>", "<cffunction name=\"go\">\n<cfreturn 1>\n</cffunction>", "<cfscript>",
		"function h(a) output=false { return a; }", "</cfscript>"),
	      "RRFRFR", NONE);
}


static void vb_blocks(void)
{
	/* the vb statement rules the join reads: Property Get/Let/Set, a vb.net Property whose Get / Set follows, `Set x = y` (an
	 * assignment), Declare / Delegate / MustOverride / Exit (no body), modifiers, `End` alone (a statement), a "_" continuation with
	 * blanks before the line break */
	check("vb property", KGENOME_TEXTUAL_LANG_ASP, 0,
	      "<% Public Property Get A() %>x<% End Property %>|<% Set o = Nothing %>|<% Declare Function F Lib \"k\" () %>|<% Exit Sub %>|"
	      "<% Private Sub S() %>y<% End Sub %>|<% End %>|<% If a _   \r\n Then %>z<% End If %>",
	      W(" Public Property Get A() %>x<% End Property ", " Set o = Nothing ", " Declare Function F Lib \"k\" () ", " Exit Sub ",
		" Private Sub S() %>y<% End Sub ", " End ", " If a _   \r\n Then %>z<% End If "),
	      NULL, NULL, NONE);
	/* (the vb.net Property header alone in its piece opens nothing there: count_vb's named limit) */
	check("vbnet property", KGENOME_TEXTUAL_LANG_ASPX, 0,
	      "<%@ Page Language=\"VB\" %><% Property P As Integer %>\n<% Get %>a<% End Get %><% End Property %>|<% MustOverride Sub M() %>|"
	      "<% Delegate Sub D() %>|<% Set(v) %>b<% End Set %>",
	      W(" Property P As Integer ", " Get %>a<% End Get %><% End Property ", " MustOverride Sub M() ", " Delegate Sub D() ",
		" Set(v) %>b<% End Set "),
	      NULL, NULL, NONE);
}

static void cfml_pairs(void)
{
	/* an end tag closes the nearest open tag of its name and what is open above it; one whose name is not open closes nothing; a tag
	 * closed by "/>" opens nothing */
	check("cfml pairs", KGENOME_TEXTUAL_LANG_CFM, 0,
	      "<cfoutput>\n<cfloop query=\"q\">\n</cfoutput>\n<cfset a=1>\n</cfif>\n<cfset b=2>\n<cfoutput/>\n<cfset c=3>",
	      W("<cfoutput>\n<cfloop query=\"q\">\n</cfoutput>", "<cfset a=1>", "</cfif>", "<cfset b=2>", "<cfoutput/>", "<cfset c=3>"),
	      NULL, NULL, NONE);
}

static void client_attrs(void)
{
	/* an unquoted handler, a type with parameters, a language attribute's javascript and vbscript and an unknown one, a name that is
	 * on + not letters, a javascript: url after blanks, a "<" that is not a tag */
	check("client attrs", KGENOME_TEXTUAL_LANG_PHP, 0,
	      "<?php $a; ?><b onclick=go()><b on-x=\"no()\"><a href=\"  javascript:j()\"><script type=\"text/javascript; charset=utf-8\">t()</script>"
	      "<script language=\"JavaScript1.2\">u()</script><script language=\"PerlScript\">p()</script><script type=\"text/vbscript\">v</script>"
	      "a < b <",
	      W(" $a; "), NULL, NULL, W("go()", "j()", "t()", "u()", "v"));
}

static void clipped(void)
{
	/* a vbscript page whose server script names jscript: the page's function table reads it as vb (the named limit of a mixed page),
	 * and the join reads it as braces - the two disagree, and a function that crosses its level-0 island is cut there and flagged */
	const char *s = "<%@ Language=VBScript %><script runat=\"server\" language=\"JScript\">function f() { return 1; }</script>\n<% x = 1 %>";
	struct kgenome_script_parts p;
	uint32_t i, clip = 0;

	parts_of(KGENOME_TEXTUAL_LANG_ASP, 0, s, strlen(s), &p);
	props(s, strlen(s), &p);
	for (i = 0; i < p.isl.lv[SRV][1].n; i++)
		clip += (p.isl.lv[SRV][1].v[i].flags & KGENOME_SCRIPT_ISL_F_CLIPPED) != 0;
	CK(clip >= 1u);
	/* the join reads the script element in the language it names (braces): it closes there, and the next piece is an island of its own */
	want_isl("clipped level 0", s, &p, SRV, 0, W("function f() { return 1; }", " x = 1 "), NULL);
	kgenome_script_parts_free(&p);
}

/* ---- languages with no tags ------------------------------------------------------------------------------------------------ */

static void js_rows(void)
{
	/* the whole text is one piece; arrows (a block body and an expression body: asi ends it at the line break), methods of a class and
	 * of an object literal; a call and a block on the next line are not a method; a module wrapper `(function () {...})()` is the top
	 * level and no unit: what it holds is (script_funcs.c, fn_wrapper) */
	check("js", KGENOME_TEXTUAL_LANG_JS, 0,
	      "const f = (a, b) => { return a; };\nconst g = x => x + 1\nclass A { static async m(a) { return 1 } get v() { return 2 } }\n"
	      "let o = { k(a) { return a }, z: 1 };\nfoo(x)\n{ y() }\n(function () { function in1() {} })();\n",
	      NULL,
	      W("const f = ", "(a, b) => { return a; }", ";\nconst g = ", "x => x + 1", "\nclass A { ", "static async m(a) { return 1 }",
		"get v() { return 2 }", " }\nlet o = { ", "k(a) { return a }", ", z: 1 };\nfoo(x)\n{ y() }\n(function () { ",
		"function in1() {}", " })();\n"),
	      "RFRFRFFRFRFR", NONE);
	/* the wrappers of a bundle: !function, an arrow; an expression that is not at a statement's start is a function */
	check("js wrappers", KGENOME_TEXTUAL_LANG_JS, 0,
	      "!function (e) { function a() {} var b = 1; }(x);\n(() => { const c = () => 2; })();\nvar d = (function () { return 3; });\n", NULL,
	      W("!function (e) { ", "function a() {}", " var b = 1; }(x);\n(() => { const c = ", "() => 2", "; })();\nvar d = (",
		"function () { return 3; }", ");\n"),
	      "RFRFRFR", NONE);
	/* the expression body goes on across a line break when the line ends in an operator or the next begins with one */
	check("js asi", KGENOME_TEXTUAL_LANG_JS, 0, "h = x =>\n x +\n 1\n . y\nz()\n", NULL, W("h = ", "x =>\n x +\n 1\n . y", "\nz()\n"), "RFR",
	      NONE);
}

static void plain_rows(void)
{
	/* a language with no tags: the whole text is one level-0 island (the extent the similarity cut always had); a text of white space
	 * and comments alone has none */
	/* the "#!" line is the interpreter's tag (sh delivers it as one): it names the language and is no code of a run */
	check("sh", KGENOME_TEXTUAL_LANG_SH, 0, "#!/bin/sh\nf() { echo; }\nf\n", W("#!/bin/sh\nf() { echo; }\nf\n"),
	      W("f() { echo; }", "\nf\n"), "FR", NONE);
	check("py blank", KGENOME_TEXTUAL_LANG_PY, 0, "  # only a comment\n\n", NONE, NONE, NULL, NONE);
}

/* ---- the table has no cap -------------------------------------------------------------------------------------------------- */

static void no_cap(void)
{
	/* 300 pieces: more than the module ABI's 256 (KOF_SCRIPT_MAX_ISLAND, kofmod/script.h) - every one is in the table */
	char *s = malloc(300u * 16u + 1u);
	size_t k = 0;
	uint32_t i;
	struct kgenome_script_parts p;

	if (!s) {
		CK(0);
		return;
	}
	for (i = 0; i < 300u; i++)
		k += (size_t)sprintf(s + k, "<?php f%u(); ?>x", i % 10u);
	parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, s, k, &p);
	CK(p.isl.lv[SRV][0].n == 300u && p.isl.n_pieces == 300u);
	props(s, k, &p);
	kgenome_script_parts_free(&p);
	free(s);
}

/* ---- hostile sizes: linear ------------------------------------------------------------------------------------------------- */

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void hostile(void)
{
	static const struct { uint32_t lang; const char *unit; uint32_t want_l0; } H[] = {
		{ KGENOME_TEXTUAL_LANG_PHP, "<?php { ?>a", 1 },                 /* every piece opens a block: one island, open */
		{ KGENOME_TEXTUAL_LANG_PHP, "<?php if(if(if(", 1 },              /* conditions that never close: no paren is read twice */
		{ KGENOME_TEXTUAL_LANG_PHP, "<?php if (1): ?>a", 1 },
		{ KGENOME_TEXTUAL_LANG_ASP, "<% If x Then %>a", 1 },
		{ KGENOME_TEXTUAL_LANG_CFM, "<cfif x>a", 1 },
		{ KGENOME_TEXTUAL_LANG_PHP, "<a \"", 0 },                        /* client tags whose quote never closes */
		{ KGENOME_TEXTUAL_LANG_PHP, "<script>x()</script>", 0 },
		{ KGENOME_TEXTUAL_LANG_JS, "x=>", 1 },
		{ KGENOME_TEXTUAL_LANG_JS, "(a)=>{", 1 },
	};
	uint32_t h;

	for (h = 0; h < sizeof H / sizeof H[0]; h++) {
		size_t ul = strlen(H[h].unit), reps = 100000u, k;
		char *s = malloc(ul * reps + 1u);
		struct kgenome_script_parts p;
		double t0;

		if (!s) {
			CK(0);
			continue;
		}
		for (k = 0; k < reps; k++)
			memcpy(s + k * ul, H[h].unit, ul);
		t0 = now();
		parts_of(H[h].lang, 0, s, ul * reps, &p);
		CK(now() - t0 < 2.0);
		CK(p.isl.status == KGENOME_OK && p.isl.lv[SRV][0].n == H[h].want_l0);
		if (now() - t0 >= 2.0 || p.isl.lv[SRV][0].n != H[h].want_l0)
			printf("  hostile %u: %.2f s, %u level-0 islands\n", h, now() - t0, p.isl.lv[SRV][0].n);
		kgenome_script_parts_free(&p);
		free(s);
	}
}

/* ---- properties over generated pages ------------------------------------------------------------------------------------- */

static const char *const TOK[] = { "<?php ", "?>", "<?= ", "{", "}", "if ($a): ", "endif; ", "function f() ", "fn($x) => $x; ", "$a = 1; ",
				   "// c ?>", "/* c */", "'s?>'", "\n", "\r\n", "<b>", "<script>", "</script>", "<a onclick=\"x()\">", "x " };

static size_t gen(struct hk_rng *r, char *out, size_t cap)
{
	size_t k = 0;
	uint32_t i, m = 1u + (uint32_t)(hk_next(r) % 40u);

	for (i = 0; i < m; i++) {
		const char *t = TOK[hk_next(r) % (sizeof TOK / sizeof TOK[0])];
		size_t l = strlen(t);

		if (k + l >= cap)
			break;
		memcpy(out + k, t, l);
		k += l;
	}
	out[k] = 0;
	return k;
}

static int same_parts(const struct kgenome_script_parts *a, const struct kgenome_script_parts *b, uint64_t shift, uint32_t skip0, uint32_t skip1)
{
	const struct kgenome_script_isl_list *A0 = &a->isl.lv[SRV][0], *B0 = &b->isl.lv[SRV][0];
	uint32_t i;

	if (A0->n != B0->n + skip0 || a->isl.lv[SRV][1].n != b->isl.lv[SRV][1].n + skip1)
		return 0;
	for (i = 0; i < B0->n; i++)
		if (A0->v[skip0 + i].off != B0->v[i].off + shift || A0->v[skip0 + i].len != B0->v[i].len || A0->v[skip0 + i].flags != B0->v[i].flags)
			return 0;
	return 1;
}

static void properties(void)
{
	struct hk_rng r = { 0x9e3779b97f4a15a1ull };
	static char a[4096], b[4096], ab[8300];
	uint32_t it;

	for (it = 0; it < 4000u; it++) {
		struct kgenome_script_parts pa, pb, pab, again;
		size_t na = gen(&r, a, 2000u), nb = gen(&r, b, 2000u);

		/* A closed: its last piece ended and every block it opened closed - then nothing of B joins A */
		memcpy(ab, a, na);
		memcpy(ab + na, "?>\n<p>", 6u);
		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, ab, na + 6u, &pa);
		props(ab, na + 6u, &pa);
		/* the same text twice: the same answer */
		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, ab, na + 6u, &again);
		CK(same_parts(&again, &pa, 0, 0, 0));
		kgenome_script_parts_free(&again);
		if (pa.isl.lv[SRV][0].n && (pa.isl.lv[SRV][0].v[pa.isl.lv[SRV][0].n - 1u].flags & KGENOME_SCRIPT_ISL_F_OPEN)) {
			kgenome_script_parts_free(&pa);
			continue;       /* A left a block open: B joins it, which is the rule, not a property of the concatenation */
		}
		memcpy(ab + na + 6u, b, nb);
		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, b, nb, &pb);
		parts_of(KGENOME_TEXTUAL_LANG_PHP, 0, ab, na + 6u + nb, &pab);
		props(ab, na + 6u + nb, &pab);
		/* ORDER INDEPENDENCE: the islands of A then B are A's and B's, B's moved by A's length */
		CK(same_parts(&pab, &pb, na + 6u, pa.isl.lv[SRV][0].n, pa.isl.lv[SRV][1].n));
		if (!same_parts(&pab, &pb, na + 6u, pa.isl.lv[SRV][0].n, pa.isl.lv[SRV][1].n) && hk_fails < 3) {
			printf("  ORDER: A |%.*s| B |%.*s|\n", (int)na, a, (int)nb, b);
			want_isl("A", ab, &pa, SRV, 0, NONE, NULL);
			want_isl("B", b, &pb, SRV, 0, NONE, NULL);
			want_isl("AB", ab, &pab, SRV, 0, NONE, NULL);
			want_isl("B1", b, &pb, SRV, 1, NONE, NULL);
			want_isl("AB1", ab, &pab, SRV, 1, NONE, NULL);
		}
		kgenome_script_parts_free(&pa);
		kgenome_script_parts_free(&pb);
		kgenome_script_parts_free(&pab);
		if (hk_fails > 20)
			break;
	}
}

int main(void)
{
	php_pieces();
	php_join();
	php_alt();
	php_funcs();
	php_eol();
	php_header_tag();
	php_fragment();
	php_client();
	asp_vb();
	aspx_cs();
	jsp_java();
	cfm_tags();
	vb_blocks();
	cfml_pairs();
	client_attrs();
	clipped();
	js_rows();
	plain_rows();
	no_cap();
	hostile();
	properties();
	printf("script_islands: %s (%d failure(s))\n", hk_fails ? "FAIL" : "ok", hk_fails);
	return hk_fails != 0;
}
