/*
 * emu_zero_tail - the zero tail of a mapped span is a shared zero page, and a span
 * that overlaps it must not write into that page.
 *
 * kgenome_emu_map backs the part of a region past the bytes it is given with one
 * read-only page of zeroes (every modelled library maps a span of which almost
 * all is zero, and allocating each page was half the instructions of a scan).
 * Sections that overlap in memory are an ordinary thing for a packed or malformed
 * PE to declare: the second map finds the first one's zero tail and fills it. The
 * fill goes through page_own, which copies the page first; if it did not, every
 * emulation in the process - this one and every later one - would read the bytes
 * back from memory it never mapped. This pins that: it was checked by reading
 * kgenome_emu_map, and a test is what keeps it true.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/kofemu.h>

static int failures;

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define TAIL_VA 0x500000ull

int main(void)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *a, *b;
	uint8_t mark[16], got[16], zero[16];
	unsigned i;

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = 64;
	cfg.max_insn = 1000;
	cfg.max_pages = 256;
	for (i = 0; i < sizeof mark; i++)
		mark[i] = (uint8_t)(0xA0u + i);
	memset(zero, 0, sizeof zero);

	a = kgenome_emu_new(&cfg);
	check(a != NULL, "an emulator");
	if (!a)
		return 1;
	/* one byte of data and a four page region: the rest is the zero tail */
	{
		static const uint8_t one = 0x11;

		check(kgenome_emu_map(a, TAIL_VA, &one, 1, 0x4000, KGENOME_EMU_R | KGENOME_EMU_W),
		      "a span with a zero tail");
	}
	check(kgenome_emu_read(a, TAIL_VA + 0x2000, got, sizeof got) && !memcmp(got, zero, sizeof got),
	      "the tail reads zero");
	/* a second span that overlaps the tail and fills it */
	check(kgenome_emu_map(a, TAIL_VA + 0x2000, mark, sizeof mark, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W),
	      "an overlapping span");
	check(kgenome_emu_read(a, TAIL_VA + 0x2000, got, sizeof got) && !memcmp(got, mark, sizeof got),
	      "the overlapping span's bytes are there");
	/* ...and a different emulator that maps the same kind of tail still reads zero */
	b = kgenome_emu_new(&cfg);
	check(b != NULL, "a second emulator");
	if (b) {
		static const uint8_t one = 0x22;

		check(kgenome_emu_map(b, TAIL_VA, &one, 1, 0x4000, KGENOME_EMU_R | KGENOME_EMU_W),
		      "the same span in another emulator");
		check(kgenome_emu_read(b, TAIL_VA + 0x2000, got, sizeof got) && !memcmp(got, zero, sizeof got),
		      "its tail is still zero: the first one's fill did not reach the shared page");
		kgenome_emu_free(b);
	}
	kgenome_emu_free(a);
	if (failures) {
		printf("emu zero tail: %d failure(s)\n", failures);
		return 1;
	}
	printf("emu zero tail: an overlapping span is private, the shared zero page stays zero - ok\n");
	return 0;
}
