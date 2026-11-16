/*
 * diag_text_islands - kgenome_diag_text_islands (diag_scan.h, 2026-11-10): the lineage-resolved value an eval()/create_function() call runs,
 * kept past layer_of_call's one C call instead of freed, for a shape the file's own bytes cannot answer any other way - hoho.php's real
 * shape: a function the program holds in a variable built by str_replace, called with an argument joined out of several variables. Neither
 * case is a bare literal, so Merge 167's own find_eval_islands (celllysis/script_funcs.c) never sees it; this is what a mechanism for that
 * gap has to resolve instead - the SAME evaluator (kgenome_dtx_target_node/kgenome_dtx_eval_var) the capability graph already uses.
 *
 * RED on code before this feature (kgenome_diag_text_req had no `islands` field and layer_of_call never persisted anything: the call would
 * not compile, the strongest possible RED - tests/lib/genome is linked against libkgenome.a alone, so a missing symbol or field is a build
 * failure, not a runtime one). GREEN after: the island's bytes are exactly the resolved body, and a real named function (`x`) inside it is
 * found by the SAME kgenome_script_funcs_build celllysis already uses for every other script function - proving a function inside an island
 * gets a real, nameable unit without any change to that routine at all.
 *
 * WHY THE OLD TESTS MISSED THIS (CLAUDE.md "Tests"): there was no "old test" to miss it - this is new coverage of new code, not a regression
 * of existing code; the RED/GREEN pair above is the project's own substitute requirement for a brand new mechanism (no prior behaviour to
 * diff against).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/script_funcs.h>
#include <celllysis/nucleo.h>
#include <genotype/image/funcs.h>
#include <textual/textual.h>

#include "diag_text_graph.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* The engine's real string-function hook is not reachable from a libgenome-only test (rule: tests/lib/genome links libkgenome.a alone, no
 * engine symbol) - str_replace is implemented here exactly as diag_text_scan_same.c's own apply() already does it for the same reason:
 * KGENOME_TEXTUAL_DEC_REPLACE's s1/n1 is the search, s2/n2 the replacement, byte for byte, no regex. */
static int apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	uint32_t i, w = 0;

	(void)user;
	if (c->op != KGENOME_TEXTUAL_DEC_REPLACE || !c->n1)
		return 0;
	for (i = 0; i < len;) {
		if (i + c->n1 <= len && !memcmp(in + i, c->s1, c->n1)) {
			if (w + c->n2 > cap)
				return 0;
			if (c->n2)
				memcpy(out + w, c->s2, c->n2);
			w += c->n2;
			i += c->n1;
		} else {
			if (w + 1u > cap)
				return 0;
			out[w++] = in[i++];
		}
	}
	*n_out = w;
	return 1;
}

static struct kgenome_diag_scan *scan_php(const char *src)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = KGENOME_TEXTUAL_LANG_PHP, .apply = apply };

	return kgenome_diag_scan_text(&rq);
}

/*
 * hoho.php's exact shape, trimmed to what this mechanism needs to resolve (real hoho.php: samples/php_shells/hoho.php, proved end to end
 * separately via kofexaminer --blocks on the real file): a callee built by str_replace over a scrambled literal (never a bare name, so
 * Merge 167's own literal-island matcher - which only ever looks at a CALL's own argument, never the callee - was never going to touch this
 * either way), called with a value joined out of several variables (never one literal token), whose value is real PHP code with its own named
 * function inside.
 */
#define HOHO \
	"<?php\n" \
	"$l=str_replace('k','','ckrekatek_fuknkkction');" \
	"$a='function x($t,$k){return ';" \
	"$b='$t^$k;}';" \
	"$U=$a.$b;" \
	"$s=$l('',$U);"

static void island_not_file_backed(void)
{
	struct kgenome_diag_scan *s = scan_php(HOHO);
	struct kgenome_diag_text_island_set iset;

	CK(s != NULL, "scan failed");
	if (s) {
		/* the capability graph still resolves $l -> create_function, exactly as it did before this feature (graph_path_unaffected
		 * below re-checks the status alone; this checks the actual node, here where HOHO's shape is already built). */
		CK(count(s, KGENOME_NUCLEO_CREATE) == 1, "create_function node missing from the capability graph");
		kgenome_diag_scan_free(s);
	}
	/* kgenome_diag_text_islands is its own scanner-free entry (like kgenome_diag_text_names beside it): the SAME question asked without a
	 * live scan, the shape kofexaminer needs (no sx_* scanner state reachable from tests/lib/genome either). */
	kgenome_diag_text_islands((const uint8_t *)HOHO, strlen(HOHO), KGENOME_TEXTUAL_LANG_PHP, apply, &iset);
	CK(iset.n == 1, "one island expected (one non-literal eval/create_function argument), got %u", iset.n);
	if (iset.n) {
		const char *want = "function x($t,$k){return $t^$k;}";

		CK(iset.v[0].len == strlen(want), "island length %u, wanted %zu", iset.v[0].len, strlen(want));
		CK(iset.v[0].len == strlen(want) && memcmp(iset.v[0].data, want, iset.v[0].len) == 0,
		   "island bytes do not match the resolved body");
		/* PROVENANCE: `at` is the real call site in the OUTER text (honest - never the value's own, nonexistent, file offset) - the
		 * call is `$l('', $U)`, which is NOT a bare "create_function(" spelling at all (the callee is a variable), so this is also
		 * proof the mechanism follows a callee resolved BY VALUE, not merely a literal eval()/create_function() spelled in the text. */
		CK(iset.v[0].at < strlen(HOHO), "call site %llu past the text (%zu bytes)",
		   (unsigned long long)iset.v[0].at, strlen(HOHO));
		CK(iset.status == KGENOME_OK, "collection status %d, wanted OK", (int)iset.status);
	}
	kgenome_diag_text_islands_free(&iset);
	CK(iset.n == 0 && iset.v == NULL, "free did not reset the set");
}

/* THE ISLAND BECOMES A REAL, NAMED, HASHABLE MUTATION UNIT: the one thing kgenome_script_funcs_build needs is a (data, len) buffer - it does
 * not care where it came from (funcs.h's own PLACE contract is about a FILE's own kgenome_func_set, never about what this function is handed
 * to build one FROM) - so running it on the island's own bytes, exactly as script_route.c's kof_script_island_units does for real, finds the
 * SAME function `x` a reader of the decoded text would see, with its own real name - invisible before this feature (the bytes did not exist
 * anywhere a mutation unit could be cut from), a real named unit after it. */
static void island_function_is_named(void)
{
	struct kgenome_diag_text_island_set iset;
	struct kgenome_func_set fs;
	/*
	 * kgenome_script_funcs_build reads a tag-delimited language's rules from a leading open tag, like any real PHP file - it has no
	 * "this buffer is already code" flag of its own (that is what script_route.c's kof_script_island_units adds, locally, for its one
	 * real caller: a synthetic "<?php\n" ahead of the island's bytes, removed from every offset handed back). Mirrored here so this
	 * lib-level test proves the SAME thing the engine adapter does, not a different shape of call.
	 */
	static const char tag[] = "<?php\n";
	uint8_t *tagged;

	kgenome_diag_text_islands((const uint8_t *)HOHO, strlen(HOHO), KGENOME_TEXTUAL_LANG_PHP, apply, &iset);
	CK(iset.n == 1, "one island expected, got %u", iset.n);
	memset(&fs, 0, sizeof fs);
	if (iset.n) {
		tagged = malloc(iset.v[0].len + (sizeof tag - 1u));
		CK(tagged != NULL, "out of memory");
		if (tagged) {
			memcpy(tagged, tag, sizeof tag - 1u);
			memcpy(tagged + (sizeof tag - 1u), iset.v[0].data, iset.v[0].len);
			kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, tagged, iset.v[0].len + (sizeof tag - 1u), &fs);
			free(tagged);
		}
	}
	CK(fs.n == 1, "one function expected inside the island, got %u", fs.n);
	if (fs.n) {
		uint32_t name_off = fs.v[0].name_off - (uint32_t)(sizeof tag - 1u);
		uint64_t off = fs.v[0].off - (uint64_t)(sizeof tag - 1u);

		CK(fs.v[0].name_len == 1u && iset.n && memcmp(iset.v[0].data + name_off, "x", 1u) == 0,
		   "the island's function is not named 'x'");
		/* off/len index the ISLAND's OWN buffer (script_route.h's own warning to a caller), not the outer text: proved by
		 * bounding it against the island's length, never the text's. */
		CK(iset.n && off + fs.v[0].len <= iset.v[0].len, "the function unit runs past its own island");
	}
	kgenome_funcs_free(&fs);
	kgenome_diag_text_islands_free(&iset);
}

/* NO OVERLAP WITH MERGE 167'S OWN DOMAIN: a bare literal argument gets no island here - that shape has a real file offset already and is
 * celllysis/script_funcs.c's find_eval_islands' own job, never processed twice. */
static void bare_literal_not_collected(void)
{
	static const char src[] = "<?php eval('function y(){return 1;}');";
	struct kgenome_diag_text_island_set iset;

	kgenome_diag_text_islands((const uint8_t *)src, strlen(src), KGENOME_TEXTUAL_LANG_PHP, apply, &iset);
	CK(iset.n == 0, "a bare literal eval() argument was collected as an island (%u): Merge 167's own domain, double work", iset.n);
	kgenome_diag_text_islands_free(&iset);
}

/* THE 3 EXISTING CAPABILITY-GRAPH CALL SITES ARE UNCHANGED: a request with no `islands` set (the ordinary kgenome_diag_scan_text call every
 * other test in this directory already makes) still resolves and walks hoho.php's shape for the graph exactly as before - this feature is an
 * addition, not a behavioural change. */
static void graph_path_unaffected(void)
{
	struct kgenome_diag_scan *s = scan_php(HOHO);

	CK(s != NULL, "scan failed");
	if (s) {
		CK(kgenome_diag_scan_status(s) == KGENOME_OK, "status %d, wanted OK", (int)kgenome_diag_scan_status(s));
		kgenome_diag_scan_free(s);
	}
}

int main(void)
{
	island_not_file_backed();
	island_function_is_named();
	bare_literal_not_collected();
	graph_path_unaffected();
	printf(fails ? "diag_text_islands: %d FAILED\n" : "diag_text_islands: ok\n", fails);
	return fails != 0;
}
