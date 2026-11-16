/*
 * textual_php_chain_cap - the decoder chain's own cap, KGENOME_TEXTUAL_CHAIN_MAX (8).
 *
 * tests/lib/genome/api_textual.c's decode_hook() already pins chain recognition for every one of php's DEC_* rows,
 * innermost first, up to three deep (base64_decode/str_rot13/gzinflate, strrev/hex2bin). What none of that drives is
 * the cap itself: kgenome_textual_lang_chain (textual_anchor.c, called from textual_form.c with
 * cap = KGENOME_TEXTUAL_CHAIN_MAX) stops its walk with `while (k < cap && ...)`, so a LITERAL wrapped by MORE than 8
 * calls has never been built by any existing test - the deepest chain anywhere in the suite is 3.
 *
 * Asserted: exactly 8 wrapping calls are all read into the chain; a 9th is not - the chain stays 8, the caller's
 * array past n_chain is left alone (a canary past the promised length catches a hook given more than it should be),
 * and the form itself still completes (OK) on the 9-deep text - the cap stops the FOLD, not the LEX.
 */

#include "textual_check.h"

static uint8_t last_chain[KGENOME_TEXTUAL_CHAIN_MAX + 4u];
static uint32_t last_n_chain, hook_calls;

/* Records the chain it was handed and refuses every value: what is under test is the CHAIN, not a byte transform
 * (kuncoat's, see textual_php_calls.c's header). A hook that refuses still sees the chain, and the literal stays typed. */
static int capture_refuse(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
			  const uint8_t **out, uint32_t *out_len)
{
	uint32_t n = n_chain < sizeof last_chain ? n_chain : (uint32_t)sizeof last_chain;

	(void)user;
	(void)in;
	(void)len;
	(void)out;
	(void)out_len;
	hook_calls++;
	last_n_chain = n_chain;
	memcpy(last_chain, chain, n);
	return 0;
}

/* `depth` nested strrev(...) calls around 'x', lexed and formed with `capture_refuse` as the decode hook; `canary`
 * sets last_chain[8]/[9] before the call so an overrun past n_chain shows as a changed byte and not only a crash. */
#define RUN_DEPTH_MAX 64u

static void run_depth(uint32_t depth, int canary)
{
	char buf[16 + RUN_DEPTH_MAX * 8u + 1u];
	uint32_t i, w = 0;
	struct kgenome_textual_form_req rq;
	struct kgenome_textual_form_res rs;

	if (depth > RUN_DEPTH_MAX)
		abort();
	w = (uint32_t)sprintf(buf, "<?php ");
	for (i = 0; i < depth; i++)
		w += (uint32_t)sprintf(buf + w, "strrev(");
	w += (uint32_t)sprintf(buf + w, "'x'");
	for (i = 0; i < depth; i++)
		buf[w++] = ')';
	buf[w++] = ';';
	buf[w] = 0;

	hook_calls = 0;
	last_n_chain = 0;
	memset(last_chain, 0xff, sizeof last_chain);
	if (canary) {
		last_chain[8] = 0xaa;
		last_chain[9] = 0xbb;
	}
	rq = (struct kgenome_textual_form_req){ .in = (const uint8_t *)buf, .n = w, .lang = KGENOME_TEXTUAL_LANG_PHP,
					       .out = fbuf, .cap = sizeof fbuf, .decode = capture_refuse };
	CK(kgenome_textual_form(&rq, &rs) == KGENOME_TEXTUAL_OK);
}

static void cap_eight(void)
{
	uint32_t i;

	/* exactly at the cap: all 8 are read */
	run_depth(8u, 0);
	CK(hook_calls == 1 && last_n_chain == 8u);
	for (i = 0; i < 8u; i++)
		CK(last_chain[i] == KGENOME_TEXTUAL_DEC_REVERSE);

	/* one more than the cap: the chain is still 8, not 9, and the hook's own copy past n_chain (the canary) is untouched */
	run_depth(9u, 1);
	CK(hook_calls == 1 && last_n_chain == 8u);
	for (i = 0; i < 8u; i++)
		CK(last_chain[i] == KGENOME_TEXTUAL_DEC_REVERSE);
	CK(last_chain[8] == 0xaa && last_chain[9] == 0xbb);

	/* well past it: the walk still terminates (no runaway, no overflow) and the form still completes */
	run_depth(40u, 1);
	CK(hook_calls == 1 && last_n_chain == 8u);
	CK(last_chain[8] == 0xaa && last_chain[9] == 0xbb);
}

int main(void)
{
	cap_eight();
	printf(fails ? "textual_php_chain_cap: %d FAILED\n" : "textual_php_chain_cap: ok\n", fails);
	return fails != 0;
}
