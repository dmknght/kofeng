/*
 * hexprog_fuzz - a damaged HEX PROGRAM, which is what hex_prog_valid is for.
 *
 * Beside pack_fuzz and not inside it: that one damages a whole database and
 * asks whether the loader survives, which reaches a hex program only when the
 * mutation happens to land on one. This aims at the program encoding itself -
 * it compiles one, corrupts a few bytes, and walks whatever the validator
 * accepts - so the rarest fields get hit every iteration rather than by luck. 
 *
 * A program is compiled, then bytes of it are corrupted, then the validator is
 * asked - and whatever it ACCEPTS is walked against an object under ASAN. The
 * fault this is looking for is an accepted program that reads outside the
 * buffer it came in; a rejected one proves nothing and is the common case.
 *
 * The class alternative is the reason for this run: it is the newest encoding,
 * it carries a 32-byte payload that `len` does not describe, and a validator
 * that sized it as `len` bytes would let the matcher read 31 past the end.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../libkofeng/databases/hexprog.h"
#include "../../libkofeng/detector/matchers/kofmatch.h"
#include "../../libkofeng/databases/dbcore.h"

int kof_hex_prog_valid_for_test(const uint8_t *p, uint32_t len);

static unsigned s = 0xC0FFEEu;
static unsigned rnd(void){ s = s*1103515245u + 12345u; return s>>8; }

static const char *PATS[] = {
	"GET /[a-z]{4}\\.php", "A(bc|de)F", "[^0-9]{2}ABCD",
	"ab.{2,6}cd", "ABCDEF[a-f]", "X[a-z][A-Z]Y1234"
};

int main(void)
{
	/*
	 * ALIGNED LIKE THE PRODUCT'S, or the test measures itself.
	 *
	 * A hex program is 4-aligned where it really lives: the packer pads the
	 * string pool to KOF_HEX_PROG_ALIGN before each one and every section
	 * is laid out on KOF_PACK_SEC_ALIGN. A byte-aligned array here reports
	 * misaligned struct reads that the loader can never perform, which is a
	 * fault in the harness wearing the costume of a finding.
	 */
	_Alignas(8) uint8_t prog[KOF_HEX_MAX_PROG];
	_Alignas(8) uint8_t mut[KOF_HEX_MAX_PROG];
	uint8_t data[512];
	uint32_t plen, it, accepted = 0, walked = 0, misal = 0;

	for (it = 0; it < 40000u; it++) {
		const char *pat = PATS[rnd() % (sizeof PATS/sizeof PATS[0])];
		uint32_t k, nmut;
		struct kof_match_ctx m;

		plen = kof_regex_compile(pat, prog, sizeof prog, NULL);
		if (!plen) continue;
		memcpy(mut, prog, plen);
		nmut = 1u + rnd() % 6u;
		for (k = 0; k < nmut; k++)
			mut[rnd() % plen] = (uint8_t)rnd();
		{
			const struct kof_hex_hdr *hh = (const void *)mut;
			if (hh->steps_off % 4u || hh->alts_off % 4u) misal++;
		}
		if (!kof_hex_prog_valid_for_test(mut, plen))
			continue;
		accepted++;
		for (k = 0; k < sizeof data; k++) data[k] = (uint8_t)rnd();
		memset(&m, 0, sizeof m);
		if (!kof_match_state_init(&m, 0, 0)) continue;
		kof_match_begin(&m, kof_buf_make(data, sizeof data));
		kof_match_in(&m, 0, sizeof data, mut, (uint16_t)plen,
			     KOF_STR_HEX, (uint8_t)(rnd() & 0x0bu));
		kof_match_state_free(&m);
		walked++;
	}
	printf("hexprog fuzz: %u mutations, %u with a misaligned table offset, "
	       "%u accepted, %u walked, no fault\n", it, misal, accepted, walked);
	return 0;
}
