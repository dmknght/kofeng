/*
 * crc_fast.c - the pack's eight-bytes-a-step CRC-32 must be kof_crc32, bit for bit.
 *
 * The checksum is written into every pack by kof_crc32 (one byte a step) and read back by
 * kof_crc32_fast_cont (databases/pack/dbcrc.c) wherever a pack is checked whole or a slice at a time. A value
 * that differed would refuse every database already built, or - worse - accept a damaged one. So: the standard
 * check value, every length to 300 at every alignment against the reference, the piecewise form (any cut
 * of a buffer gives the same CRC as the buffer), and a large random buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/databases/pack/dbcrc.h"

static uint64_t rs = 0x2545F4914F6CDD1DULL;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 24); }

int main(void)
{
	static uint8_t buf[300 + 16];
	uint32_t bad = 0, i, len, al;
	uint8_t *big;

	if (kof_crc32_fast_cont(0, "123456789", 9) != 0xCBF43926u) {
		printf("  FAIL the standard check value\n");
		bad++;
	}
	for (i = 0; i < sizeof buf; i++)
		buf[i] = (uint8_t)rnd();
	for (al = 0; al < 16; al++)
		for (len = 0; len <= 300; len++)
			if (kof_crc32_fast_cont(0, buf + al, len) != kof_crc32(buf + al, len)) {
				if (bad++ < 4)
					printf("  FAIL length %u at alignment %u\n", len, al);
			}
	for (len = 0; len <= 300; len++) {          /* the pieces: every cut of a buffer */
		uint32_t cut = len ? rnd() % (len + 1u) : 0, c = kof_crc32_fast_cont(0, buf, cut);

		c = kof_crc32_fast_cont(c, buf + cut, len - cut);
		if (c != kof_crc32(buf, len)) {
			if (bad++ < 4)
				printf("  FAIL a buffer of %u cut at %u\n", len, cut);
		}
	}
	big = malloc((size_t)4 << 20);
	for (i = 0; i < (4u << 20); i++)
		big[i] = (uint8_t)rnd();
	if (kof_crc32_fast_cont(0, big, (uint64_t)4 << 20) != kof_crc32(big, (uint64_t)4 << 20)) {
		printf("  FAIL a 4 MiB buffer\n");
		bad++;
	}
	free(big);
	if (bad) {
		printf("crc_fast: FAILED (%u)\n", bad);
		return 1;
	}
	printf("crc_fast: 4800 lengths x alignments, 301 cuts, 4 MiB, the check value: all equal kof_crc32\n");
	return 0;
}
