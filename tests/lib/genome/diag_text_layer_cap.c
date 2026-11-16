/*
 * diag_text_layer_cap - the two caps of the TEXT route's layering mechanism (diag_text_walk.c's layer_of_call, LAYER_DEPTH = 16;
 * diag_text_route.c's kgenome_diag_run_text, lay.room = 32 * file_size + 65536): a text an eval()/create_function() call runs is
 * lexed and walked as a further LAYER of the same scan (the hoho.php mechanism, see diag_text_walk.c's header comment), and a
 * program can nest that arbitrarily deep or make one layer arbitrarily large. Neither bound had an attacking test before this one
 * (`grep -rn LAYER_DEPTH tests/` found nothing): a regression that silently widened or narrowed either cap, or that stopped
 * reporting the cut, would have passed every existing diag_text* test, none of which nests past three layers.
 *
 * WHY THE OLD TESTS MISSED THIS (CLAUDE.md "Tests"): (a) the line that compares x->layer to LAYER_DEPTH was never executed with
 * x->layer anywhere near 16 - every existing fixture (diag_text.c, diag_text_e2e.c, script_dispatch.c, textual_php_calls.c)
 * nests eval at most two or three deep; (b) the room arithmetic (32 * size + 65536) was read nowhere by a boundary input - every
 * existing decode fixture is a few dozen bytes, far under the +65536 floor, so the multiplier was never exercised either side of
 * where it actually matters.
 *
 * Both caps are measured here, not merely read off the source: build_chain() constructs a REAL nested-eval PHP program (correctly
 * single-quote escaped, so the engine's own string lexer sees exactly what a PHP interpreter would) and the room probe uses a
 * synthetic `gzinflate` decoder whose answer length is read out of its own argument, so the room boundary can be hit with an
 * input of exactly one byte either side of it without needing a working compressor.
 *
 * A cap bounds COST and must never delete evidence silently (CLAUDE.md #4): both of these report what they cut
 * (kgenome_diag_scan_status: KGENOME_TRUNCATED for the depth, KGENOME_OVER_BUDGET for the room) rather than just stopping, and
 * the layer that triggered the cap keeps the node it already made (the walk of THAT layer is not thrown away, only the next one
 * is refused) - asserted below as "eval count at the cap equals the cap, not the cap minus one".
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

static struct kgenome_diag_scan *scan_php(const char *src, kgenome_textual_apply_fn apply)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = KGENOME_TEXTUAL_LANG_PHP, .apply = apply };

	return kgenome_diag_scan_text(&rq);
}

/* ---- LAYER_DEPTH: W nested eval('...') calls, innermost "1;" --------------------------------------------------------------- */

/* real PHP single-quote escaping (\\ and \' only), so depth grows the file linearly at the LEXER's own cost and not as a test
 * artefact: a naively-nested literal (no escaping, or escaping that does not account for the PREVIOUS level's own backslashes)
 * builds a string the engine's lexer does not read the way intended past depth 2 or 3 - measured while writing this test: an
 * earlier version of build_chain() that alternated single/double quotes without escaping gave 5 eval nodes at W=15 instead of
 * 15, because by the third level of nesting the un-escaped quote characters of an inner literal closed the outer one early. */
static char *build_chain(uint32_t w)
{
	char *cur = malloc(3);
	uint32_t i;

	cur[0] = '1'; cur[1] = ';'; cur[2] = 0;
	for (i = 0; i < w; i++) {
		size_t cn = strlen(cur), j, en = 0;
		char *esc = malloc(cn * 2u + 1u);
		char *nxt;

		for (j = 0; j < cn; j++) {
			if (cur[j] == '\\' || cur[j] == '\'')
				esc[en++] = '\\';
			esc[en++] = cur[j];
		}
		esc[en] = 0;
		nxt = malloc(en + 16u);
		sprintf(nxt, "eval('%s');", esc);
		free(esc);
		free(cur);
		cur = nxt;
	}
	return cur;     /* caller frees */
}

static void depth_case(uint32_t w, int want_eval, enum kgenome_status want_status)
{
	char *body = build_chain(w);
	char *src = malloc(strlen(body) + 8u);
	struct kgenome_diag_scan *s;

	sprintf(src, "<?php %s", body);
	s = scan_php(src, NULL);
	CK(s != NULL, "scan failed at W=%u", w);
	if (s) {
		CK(count(s, KGENOME_NUCLEO_EVAL) == want_eval, "W=%u: eval nodes %d, wanted %d", w,
		   count(s, KGENOME_NUCLEO_EVAL), want_eval);
		CK(kgenome_diag_scan_status(s) == want_status, "W=%u: status %d, wanted %d", w,
		   (int)kgenome_diag_scan_status(s), (int)want_status);
		kgenome_diag_scan_free(s);
	}
	free(body);
	free(src);
}

static void layer_depth(void)
{
	/* a shallow chain: nowhere near the cap, nothing cut */
	depth_case(1, 1, KGENOME_OK);
	depth_case(3, 3, KGENOME_OK);
	/* AT THE CAP (LAYER_DEPTH = 16): every layer 0..15 is walked and contributes its own eval node (16 of them); layer 16's
	 * content is "1;" with no further call, so the chain ends on its own and nothing is cut. */
	depth_case(16, 16, KGENOME_OK);
	/* ONE LAYER PAST IT: layer 16 is STILL walked (it was already created when layer 15's call was read) and its own eval
	 * node is STILL counted - the cap does not erase the layer that hit it, only refuses to go one deeper - but that node's
	 * own argument is layer 17's content, and creating layer 17 is refused (x->layer == 16 >= LAYER_DEPTH): the scan ends
	 * with 17 eval nodes, one PHP statement worth of code never walked, and the refusal said rather than silent. */
	depth_case(17, 17, KGENOME_TRUNCATED);
	/* one more past the cap again: the count does not climb past 17 and the status stays TRUNCATED, it does not become
	 * something worse or silently drop back to OK. (Not pushed further: the escaped literal this builds roughly doubles in
	 * size each level - CLAUDE.md #4's own lesson applies to the TEST too - and a few levels further trips the evaluator's
	 * OWN value-size bound, KGENOME_DTX_EV_VMAX, which is a different, already-covered cap and not LAYER_DEPTH's.) */
	depth_case(18, 17, KGENOME_TRUNCATED);
}

/* ---- room: lay.room = 32 * file_size + 65536 (diag_text_route.c) ------------------------------------------------------------ */

/* A synthetic `gzinflate` whose decoded length is spelled in its own argument (ASCII decimal, zero padded to a FIXED width so
 * that every file built by room_src() is exactly the same length and the room this test computes by hand is the room the
 * engine computes): proves the room arithmetic without needing a real compressor or a multi-megabyte fixture. */
static int room_apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len,
		      uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	uint32_t n = 0, i;

	(void)user;
	if (c->op != KGENOME_TEXTUAL_DEC_INFLATE)
		return 0;
	for (i = 0; i < len; i++) {
		if (in[i] < '0' || in[i] > '9')
			return 0;
		n = n * 10u + (uint32_t)(in[i] - '0');
	}
	if (n > cap)
		return 0;
	memset(out, 'A', n);
	*n_out = n;
	return 1;
}

static void room_src(char *out, size_t cap, uint32_t n)
{
	snprintf(out, cap, "<?php eval(gzinflate('%06u'));", n);
}

static void room_budget(void)
{
	char probe[64], src[64];
	uint32_t room;
	struct kgenome_diag_scan *s;

	room_src(probe, sizeof probe, 0u);
	room = 32u * (uint32_t)strlen(probe) + 65536u;         /* the formula diag_text_route.c states in its own comment */

	/* one byte under: the decode is inside the budget, OK */
	room_src(src, sizeof src, room - 1u);
	s = scan_php(src, room_apply);
	CK(s != NULL, "scan failed at room-1");
	if (s) {
		CK(kgenome_diag_scan_status(s) == KGENOME_OK, "room-1: status %d, wanted OK", (int)kgenome_diag_scan_status(s));
		kgenome_diag_scan_free(s);
	}
	/* EXACTLY AT THE ROOM: the check in layer_of_call is `v.n <= x->lay->room`, so the boundary value itself is accepted. */
	room_src(src, sizeof src, room);
	s = scan_php(src, room_apply);
	CK(s != NULL, "scan failed at room");
	if (s) {
		CK(kgenome_diag_scan_status(s) == KGENOME_OK, "room: status %d, wanted OK", (int)kgenome_diag_scan_status(s));
		kgenome_diag_scan_free(s);
	}
	/* ONE BYTE OVER: refused and said, not silently truncated to what fits. */
	room_src(src, sizeof src, room + 1u);
	s = scan_php(src, room_apply);
	CK(s != NULL, "scan failed at room+1");
	if (s) {
		CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET, "room+1: status %d, wanted OVER_BUDGET",
		   (int)kgenome_diag_scan_status(s));
		/* the call that asked for it still has its own node - the budget refuses the LAYER, not the call that made it */
		CK(count(s, KGENOME_NUCLEO_EVAL) == 1, "room+1: eval nodes %d, wanted 1", count(s, KGENOME_NUCLEO_EVAL));
		kgenome_diag_scan_free(s);
	}
}

int main(void)
{
	layer_depth();
	room_budget();
	printf(fails ? "diag_text_layer_cap: %d FAILED\n" : "diag_text_layer_cap: ok\n", fails);
	return fails != 0;
}
