/*
 * genome / textual_pretty - kgenome_textual_pretty (textual.h), through <kgenome.h> alone, linked against
 * libkgenome.a and nothing else. No test of this call existed before this file (it is new, listed only in
 * tests/fuzz/exempt/wp3.txt as pending WP3) - this is the "area not checked gets attacking tests" pass.
 *
 * BUG (owner-reported, 2026-11-11, a real sample run through kofviewer): `tp_sink` dropped every blank
 * between two code tokens outright ("return $o;" rendered as "return$o;") because nothing re-emitted the
 * separator it skipped - unlike `kgenome_textual_form`'s `settle()`, which keeps exactly one space when
 * dropping it would glue two bytes together. The cases below pin: one blank kept as one space, several
 * collapsed to one, a blank either side of a STRING/COMMENT span (a span boundary, not mid-span - the
 * separator has to survive crossing it), and the "}"/";" break still eating any blank in front of it
 * (unaffected by the fix, pinned so a regression there would show here too).
 */

#include "textual_check.h"

static uint8_t pbuf[16384];

static void pretty_lang_flags(uint32_t lang, uint32_t flags, const char *src, const char *want)
{
	struct kgenome_textual_pretty_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src),
						 .lang = lang, .flags = flags, .out = pbuf, .cap = sizeof pbuf };
	struct kgenome_textual_pretty_res rs;
	enum kgenome_textual_status st = kgenome_textual_pretty(&rq, &rs);

	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || rs.truncated ||
	    rs.n_out != strlen(want) || memcmp(pbuf, want, rs.n_out)) {
		pbuf[rs.n_out < sizeof pbuf ? rs.n_out : sizeof pbuf - 1u] = 0;
		printf("  FAIL pretty of  %s\n       got    %s\n       wanted %s\n", src, (const char *)pbuf, want);
		fails++;
	}
}

static void php(const char *src, const char *want)
{
	pretty_lang_flags(KGENOME_TEXTUAL_LANG_PHP, KGENOME_TEXTUAL_FRAGMENT, src, want);
}

static void js(const char *src, const char *want)
{
	pretty_lang_flags(KGENOME_TEXTUAL_LANG_JS, 0, src, want);
}

int main(void)
{
	/* THE BUG, EXACTLY: a keyword and a variable, one space between them, kept as one - not zero. */
	php("return $o;", "return $o;");
	php("function x($t,$k){return $o;}", "function x($t,$k){\n  return $o;\n}");

	/* a run of several blanks collapses to the one space a reader needs, not all of them and not none */
	php("return    $o;", "return $o;");
	php("return\t\t $o;", "return $o;");

	/* a blank crossing INTO or OUT OF a STRING/COMMENT span: the span is a separate sink call from the
	 * surrounding CODE, so the fix has to carry the pending separator across the boundary, not just within
	 * one call's own loop. */
	php("return \"x\";", "return \"x\";");
	php("return/* c */$o;", "return/* c */$o;");       /* no blank in the source: none is owed either */
	php("return /* c */ $o;", "return /* c */ $o;");

	/* a blank right before "}" IS eaten (the dedent break always wins over a plain separator - tp_sep's
	 * own pend-beats-sp rule) - but one right before ";" is kept as the one space it asked for, the same
	 * uniform rule as anywhere else: ";" only becomes a break AFTER it is written, so the blank in front
	 * of it is an ordinary separator, not eaten. */
	php("{ $a=1; }", "{\n  $a=1;\n}");
	php("$a=1 ;", "$a=1 ;");

	/* operators keep their own single space too, same mechanism as the keyword/variable case */
	php("$a = 1 + 2;", "$a = 1 + 2;");

	/* a leading blank (nothing written yet) owes nothing - same rule the break already had */
	php(" return $o;", "return $o;");

	/* the real island, verbatim (owner's own sample, the exact text that read as "functionx"/"return$o"
	 * before the fix) - the whole point of FRAGMENT: no "<?php" tag of its own */
	php("function x($t,$k){$c=strlen($k);$l=strlen($t);$o=\"\";for($i=0;$i<$l;){for($j=0;($j<$c&&$i<$l);"
	    "$j++,$i++){$o.=$t[$i]^$k[$j];}}return $o;}",
	    "function x($t,$k){\n"
	    "  $c=strlen($k);\n"
	    "  $l=strlen($t);\n"
	    "  $o=\"\";\n"
	    "  for($i=0;$i<$l;){\n"
	    "    for($j=0;($j<$c&&$i<$l);$j++,$i++){\n"
	    "      $o.=$t[$i]^$k[$j];\n"
	    "    }\n"
	    "  }\n"
	    "  return $o;\n"
	    "}");

	/* cap boundary: running out of cap only truncates (never crashes, never writes past cap), and is said */
	{
		struct kgenome_textual_pretty_req rq = { .in = (const uint8_t *)"return $o;", .n = 10u,
							 .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = KGENOME_TEXTUAL_FRAGMENT,
							 .out = pbuf, .cap = 3u };
		struct kgenome_textual_pretty_res rs;
		enum kgenome_textual_status st = kgenome_textual_pretty(&rq, &rs);

		CK(st == KGENOME_TEXTUAL_OK);
		CK(rs.truncated == 1u);
		CK(rs.n_out == 3u && !memcmp(pbuf, "ret", 3));
	}

	/* BUG (owner-reported, 2026-11-11, a real obfuscated JS sample): a "}" that closes a VALUE (a function
	 * expression assigned to a variable) is immediately followed by ";" - the SAME assignment statement's
	 * own terminator, not a new statement - but the break this call forces after every "}" fired anyway,
	 * leaving the ";" alone on its own line ("owner: tức là đang có 1 cái ; nằm chỏng chơ"). Pinned on the
	 * owner's own shape: an inner function expression assigned back to the outer name, then called. */
	js("w=function(){return s4;};return w();",
	   "w=function(){\n  return s4;\n};\nreturn w();");
	/* the same closing-brace case with "," and ")" right after it (an argument, or an IIFE's own wrapper) -
	 * not reported, but the identical mechanism, so pinned alongside it */
	js("a(function(){x();},function(){y();});", "a(function(){\n  x();\n},function(){\n  y();\n});");
	js("(function(){z();})();", "(function(){\n  z();\n})();");
	/* unaffected: a "}" followed by a NEW statement still breaks - the one case the fix must not touch */
	js("if(x){y();}z();", "if(x){\n  y();\n}\nz();");
	/* the owner's REAL sample, verbatim shape: the source ITSELF already breaks "}" and ";" onto two
	 * lines of their own (a prior deobfuscator's formatting) - the lookahead must skip the "\n", not
	 * stop at it, since this call lays text out by block nesting and not by the source's own breaks */
	js("w=function(){\nreturn s4;\n}\n;\nreturn w();",
	   "w=function(){\n  return s4;\n};\nreturn w();");

	/* no "stmt_delim" row (shell, vbscript): copied through exactly as typed, no indentation attempted -
	 * so a run of blanks is kept exactly as written, not collapsed to one (that collapsing is tp_sink's own
	 * block-aware path; shell/vbscript take tp_verbatim instead, which never touches a blank at all) */
	pretty_lang_flags(KGENOME_TEXTUAL_LANG_SH, 0, "echo a  b", "echo a  b");

	printf("textual pretty: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
