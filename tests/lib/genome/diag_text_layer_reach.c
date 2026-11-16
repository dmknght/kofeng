/*
 * diag_text_layer_reach - how far the TEXT route's layering (diag_text_walk.c's layer_of_call: the text an eval()-class call
 * runs is lexed and walked as a further layer of the SAME scan, independent token array, independent of the outer one) reaches
 * for the three languages a dropper commonly wraps code for: php, javascript and powershell. This is the owner's named case -
 * "code embedded in a string that later gets executed", eval(decode(x)) and its js/powershell equivalents - from the angle the
 * existing tests (tests/unit/diag_text_e2e.c's decode-eval fixtures, tests/lib/genome/textual_php_calls.c's chain folding) do
 * not take: not "is base64_decode(...) recognised and the view substituted", but "once eval() runs it, is what is INSIDE the
 * decoded text itself analysed, or does the analysis stop at the decode".
 *
 * MEASURED HERE, not assumed from a comment (diag_text_lang_js.c's own header is STALE on this point - it says "No string
 * functions... see the report for the list js would need (atob...)", which no longer matches js_lang.c: atob, unescape and
 * decodeURIComponent ARE wired, as DECODE-capability nodes for the graph. What is measured below is a DIFFERENT fact: whether
 * the node graph being right is the same thing as the decoded bytes being re-lexed, and it is not - this is reported to the
 * coordinator as a one-line stale-comment finding, not fixed here (a comment fix is an engine edit and outside a test package's
 * remit per kofeng/CLAUDE.md's "Priority: features first" section)):
 *
 *   - eval("eval('x')") (php and javascript) and `eval(` nested in a literal with NO decoder at all: the inner eval() is found
 *     and gets ITS OWN node - the layer mechanism works for a plain literal in both languages.
 *   - eval(base64_decode('<literal>')) in PHP, with a working decode hook: the SAME is true - the decoded bytes are re-lexed and
 *     an eval() inside them is found. This is the existing, working path (api_textual.c, textual_php_calls.c prove the FOLD;
 *     this proves the FOLD's result is also WALKED as code, which is the layering feature's whole point and was not pinned by
 *     name anywhere).
 *   - eval(atob('<literal>')) in JAVASCRIPT and iex([Convert]::FromBase64String('<literal>')) in POWERSHELL, with the SAME
 *     working decode hook (so the absence below is not "no apply was given" - the hook is identical to the PHP case and is
 *     proven to decode correctly there): the DECODE node and the decode->eval link are still made (graph detection of the
 *     pattern is intact, matching diag_text_e2e.c's php decode-eval disease), but the decoded bytes are NEVER handed to a
 *     further layer - an eval() inside them is NOT found. kgenome_textual_fn_find(LANG_JS, "atob", ...) and
 *     kgenome_textual_fn_find(LANG_PSH, "Convert.FromBase64String", ...) both answer "no row" (js_fn.c, psh_fn.c: neither
 *     function is in the per-language PURE FUNCTION table the evaluator's ev_call_named reads - atob/FromBase64String are only
 *     in the SEPARATE decoder_row[] table the FORM/display and the nucleo name tables read), so kgenome_dtx_eval_range on
 *     eval's argument is never even attempted with the decoded bytes: it fails as "not constant" before the hook is asked.
 *     THIS IS A NAMED SCOPE LIMIT (CLAUDE.md #"An algorithm is never wrong"), not a crash or a wrong answer: a decode->eval
 *     LINK is reported for both languages (a diagnose keyed on that disease still matches), only the DEEPER analysis of what
 *     the decoded script does is missing. The next algorithm is naming atob/FromBase64String as rows of js_fn.c/psh_fn.c's
 *     table with form=NEVER, the same shape base64_decode already has in php_fn.c - left to the owner, this package adds tests
 *     only.
 *   - iex("iex('x')") in POWERSHELL, with NO decoder involved at all: unlike php and javascript, the inner iex() is NOT found
 *     either. This is a WIDER limit than the decode-specific one above: PowerShell's eval-equivalent does not reach the
 *     layering mechanism through its parenthesised call form at all yet, decoded or not. Reported as its own fact so a future
 *     fix to the atob-class gap is not mistaken for having fixed this one too (they are different code paths: layer_of_call is
 *     reached through kgenome_dtx_call_node, and this reports what actually executes for PSH's `iex(` shape today).
 *
 * WHY NO OLD TEST FOUND THIS: every js/psh fixture of diag_text.c, api_textual.c and script_dispatch.c checks that a single
 * DECODE or EVAL node appears (the flat graph), never that a SECOND node appears one layer inside the first - the line in
 * layer_of_call that would have run for js/psh (`kgenome_dtx_run_one(..., x->layer + 1u, ...)`) was executed only for php by
 * any test in this tree before this file. That is case (b) of the old-tests-missed-it taxonomy (CLAUDE.md "Tests"): the code
 * path exists and is reachable, but no fixture gave it a javascript or powershell input that would show whether it ran.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

#include "diag_text_graph.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* A real base64 decoder (plain loops, [Unverified] against any library - this is a test double, not a claim about kuncoat,
 * which tests/lib/uncoat tests check on their own): proves the gaps below are not "no apply was given" by being a hook that
 * genuinely decodes, used identically for the php case that WORKS and the js/psh cases that do not. */
static int b64_apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len,
		     uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t i, w = 0;
	int vals[4], nv = 0;

	(void)user;
	if (c->op != KGENOME_TEXTUAL_DEC_B64)
		return 0;
	for (i = 0; i < len; i++) {
		const char *p;

		if (in[i] == '=')
			continue;
		p = strchr(tab, (char)in[i]);
		if (!p)
			continue;
		vals[nv++] = (int)(p - tab);
		if (nv == 4) {
			if (w + 3u > cap)
				return 0;
			out[w++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
			out[w++] = (uint8_t)((vals[1] << 4) | (vals[2] >> 2));
			out[w++] = (uint8_t)((vals[2] << 6) | vals[3]);
			nv = 0;
		}
	}
	if (nv >= 2) {
		if (w + 1u > cap)
			return 0;
		out[w++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
		if (nv == 3) {
			if (w + 1u > cap)
				return 0;
			out[w++] = (uint8_t)((vals[1] << 4) | (vals[2] >> 2));
		}
	}
	*n_out = w;
	return 1;
}

static struct kgenome_diag_scan *scan_lang(const char *src, uint32_t lang, kgenome_textual_apply_fn apply)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = lang, .apply = apply };

	return kgenome_diag_scan_text(&rq);
}

struct want { int eval, decode, dec_eval; };

static void case_(const char *label, const char *src, uint32_t lang, kgenome_textual_apply_fn apply, struct want w)
{
	struct kgenome_diag_scan *s = scan_lang(src, lang, apply);

	CK(s != NULL, "%s: scan failed", label);
	if (!s)
		return;
	CK(count(s, KGENOME_NUCLEO_EVAL) == w.eval, "%s: eval nodes %d, wanted %d", label, count(s, KGENOME_NUCLEO_EVAL), w.eval);
	CK(count(s, KGENOME_NUCLEO_DECODE) == w.decode, "%s: decode nodes %d, wanted %d", label, count(s, KGENOME_NUCLEO_DECODE),
	   w.decode);
	CK(linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 0xff) == w.dec_eval, "%s: decode->eval link %d, wanted %d",
	   label, linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 0xff), w.dec_eval);
	kgenome_diag_scan_free(s);
}

int main(void)
{
	/* ---- the layer mechanism works on a plain literal, php and javascript: a second eval() one layer in gets its own node */
	case_("php literal nested eval", "<?php eval(\"eval('system(1);');\");", KGENOME_TEXTUAL_LANG_PHP, NULL,
	      (struct want){ 2, 0, 0 });
	case_("js literal nested eval", "eval(\"eval('console.log(1)')\")", KGENOME_TEXTUAL_LANG_JS, NULL,
	      (struct want){ 2, 0, 0 });

	/* ---- the working case: php's base64_decode is a row of php_fn.c's pure-function table, so a REAL decode (b64_apply)
	 * reaches a second layer and the eval() inside it gets its own node too - graph AND deep reparse both fire */
	case_("php base64_decode(lit) -> eval, decoded", "<?php eval(base64_decode('ZXZhbCgnc3lzdGVtKDEpJyk7'));",
	      KGENOME_TEXTUAL_LANG_PHP, b64_apply, (struct want){ 2, 1, 1 });
	/* the same text WITHOUT the hook: the decode and the link (named by the call alone) still appear, but there is nothing to
	 * lex a second layer from, so the eval count does not move - same shape as the js/psh gap below, for contrast */
	case_("php base64_decode(lit) -> eval, no hook", "<?php eval(base64_decode('ZXZhbCgnc3lzdGVtKDEpJyk7'));",
	      KGENOME_TEXTUAL_LANG_PHP, NULL, (struct want){ 1, 1, 1 });

	/* ---- the gap: javascript's atob and powershell's Convert.FromBase64String are DECODE-capability names (the graph is
	 * right: the decode node and the decode->eval link both appear, matching diag_text_e2e.c's php "decode-eval" shape) but
	 * are NOT rows of js_fn.c/psh_fn.c's pure-function table, so the evaluator never calls the hook for them and the decoded
	 * bytes are never walked as a layer - proven with the SAME working b64_apply as the php case above, so the absence is the
	 * missing table row and not a missing hook */
	case_("js atob(lit) -> eval, decoded hook present", "eval(atob(\"ZXZhbCgnY29uc29sZS5sb2coMSknKQ==\"))",
	      KGENOME_TEXTUAL_LANG_JS, b64_apply, (struct want){ 1, 1, 1 });
	case_("psh FromBase64String(lit) -> iex, decoded hook present",
	      "iex([Convert]::FromBase64String(\"aWV4ICd3cml0ZS1ob3N0IDEn\"))", KGENOME_TEXTUAL_LANG_PSH, b64_apply,
	      (struct want){ 1, 1, 1 });

	/* ---- the wider powershell gap: a PLAIN literal, no decoder anywhere, nested in iex(...): php and javascript found the
	 * inner eval() above (eval count 2); powershell does not find the inner iex() at all (eval count stays 1) - a narrower
	 * reach than the decode-specific gap above, and not fixed by wiring FromBase64String alone */
	case_("psh literal nested iex(...)", "iex(\"iex('write-host 1')\")", KGENOME_TEXTUAL_LANG_PSH, NULL,
	      (struct want){ 1, 0, 0 });

	printf(fails ? "diag_text_layer_reach: %d FAILED\n" : "diag_text_layer_reach: ok\n", fails);
	return fails != 0;
}
