/*
 * elf_rebuild - putting a file back together out of an address space.
 *
 * Every field this reads was written by whatever was being unpacked, so the
 * test is in two halves: one image that SHOULD rebuild, and a set of headers
 * that must be refused rather than repaired. The refusals matter more - a
 * rebuild that trusts e_phnum allocates what the header asks for, and a header
 * is not a promise.
 *
 * The case in the middle is the one that cost real time: a section table that
 * is not there. e_shoff is a file offset and the section table lives past the
 * last PT_LOAD, so a running program never has it mapped - but the ADDRESS
 * still reads, because something else is there. Copying that produced a file
 * whose program headers were byte-identical to a static unpacker's and whose
 * region partition came back CODE=0 with everything under NOLOAD. So the
 * rebuilt header has to say "stripped" instead, and that is asserted here.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../libkofeng/kofunpack/elf_rebuild.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define BASE     0x400000ull
#define SPAN     0x8000u               /* the address space this test answers */

static uint8_t mem[SPAN];

/* Answers reads inside [BASE, BASE+SPAN) and nothing else. */
static int rd(void *user, uint64_t va, void *dst, uint32_t n)
{
	(void)user;
	if (va < BASE || va - BASE >= SPAN || n > SPAN - (va - BASE))
		return 0;
	memcpy(dst, mem + (va - BASE), n);
	return 1;
}

static void w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *p, uint32_t v) { unsigned i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (i * 8)); }
static void w64(uint8_t *p, uint64_t v) { unsigned i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8)); }

/* One ELF header and two PT_LOADs: a read-execute one and a read-write one. */
static void image(uint64_t shoff, uint16_t shnum)
{
	uint8_t *ph = mem + 64;
	unsigned i;

	memset(mem, 0, sizeof mem);
	memcpy(mem, "\177ELF\2\1\1", 7);
	w16(mem + 0x10, 2);            /* ET_EXEC   */
	w16(mem + 0x12, 0x3e);
	w32(mem + 0x14, 1);
	w64(mem + 0x18, BASE + 0x1000);
	w64(mem + 0x20, 64);           /* e_phoff    */
	w64(mem + 0x28, shoff);        /* e_shoff    */
	w16(mem + 0x34, 64);
	w16(mem + 0x36, 56);
	w16(mem + 0x38, 2);            /* e_phnum    */
	w16(mem + 0x3a, shnum ? 64 : 0);
	w16(mem + 0x3c, shnum);
	w16(mem + 0x3e, shnum ? 1 : 0);

	/* The first PT_LOAD covers file offset zero, which is where the header
	 * and the program headers are - that is what makes base and the lowest
	 * p_vaddr the same address, and every real ELF is built this way. */
	w32(ph + 0x00, 1); w32(ph + 0x04, 4 | 1);
	w64(ph + 0x08, 0); w64(ph + 0x10, BASE);
	w64(ph + 0x20, 0x2000); w64(ph + 0x28, 0x2000);

	w32(ph + 56 + 0x00, 1); w32(ph + 56 + 0x04, 4 | 2);
	w64(ph + 56 + 0x08, 0x2000); w64(ph + 56 + 0x10, BASE + 0x2000);
	w64(ph + 56 + 0x20, 0x800);  w64(ph + 56 + 0x28, 0x800);

	for (i = 0; i < 0x1000; i++)
		mem[0x1000 + i] = (uint8_t)(0x90 + (i & 7));
	for (i = 0; i < 0x800; i++)
		mem[0x2000 + i] = (uint8_t)(i * 7u + 3u);
}

static int try_rebuild(uint8_t **out, uint64_t *len)
{
	uint64_t lo = 0, hi = 0;

	return kof_elf_rebuild(BASE, rd, NULL, 1u << 20, out, len, &lo, &hi);
}

int main(void)
{
	uint8_t *f = NULL;
	uint64_t n = 0;
	unsigned k;

	/* 1. An ordinary image, no section table. */
	image(0, 0);
	if (!try_rebuild(&f, &n)) {
		fail("a well formed image did not rebuild");
	} else {
		printf("  dựng lại: %llu B\n", (unsigned long long)n);
		if (n != 0x2800)
			fail("the file is not as long as its segments reach");
		if (memcmp(f, "\177ELF", 4))
			fail("the header did not survive");
		if (memcmp(f + 0x1000, mem + 0x1000, 0x1000))
			fail("the executable segment is not at its file offset");
		if (memcmp(f, mem, 64))
			fail("the header the first segment covers was overwritten");
		if (memcmp(f + 0x2000, mem + 0x2000, 0x800))
			fail("the writable segment is not at its file offset");
		free(f); f = NULL;
	}

	/*
	 * 2. A section table the header points at but memory does not hold.
	 *    Section header zero must be all zeroes; here it is not, because
	 *    what is at that address is ordinary segment data.
	 */
	image(0x2000, 4);
	if (!try_rebuild(&f, &n)) {
		fail("an image with a bogus section table did not rebuild");
	} else {
		int shoff_kept = 0;

		for (k = 0x28; k < 0x30; k++)
			if (f[k])
				shoff_kept = 1;
		printf("  bảng section giả -> %s\n",
		       shoff_kept ? "GIỮ LẠI" : "khai là stripped");
		if (shoff_kept)
			fail("a section table that is not there was carried into "
			     "the rebuilt file");
		free(f); f = NULL;
	}

	/* 3. Headers that must be refused rather than believed. */
	{
		struct { const char *what; uint64_t off; unsigned width; uint64_t v; }
		bad[] = {
			{ "e_phnum quá lớn",       0x38, 2, 0xffff },
			{ "e_phentsize sai",       0x36, 2, 57 },
			{ "e_phnum bằng 0",        0x38, 2, 0 },
			{ "e_phoff ngoài trần",    0x20, 8, 0x40000000ull },
			{ "p_filesz ngoài trần",   64 + 0x20, 8, 0x40000000ull },
			{ "p_offset ngoài trần",   64 + 0x08, 8, 0x40000000ull },
			/* Would make bias wrap, and every read land elsewhere. */
			{ "p_vaddr trên cả base",  64 + 0x10, 8, BASE + 0x4000 }
		};

		for (k = 0; k < sizeof bad / sizeof *bad; k++) {
			image(0, 0);
			if (bad[k].width == 2)
				w16(mem + bad[k].off, (uint16_t)bad[k].v);
			else
				w64(mem + bad[k].off, bad[k].v);
			f = NULL; n = 0;
			if (try_rebuild(&f, &n)) {
				printf("  %-24s -> dựng ra %llu B\n", bad[k].what,
				       (unsigned long long)n);
				/*
				 * Producing something is allowed as long as it
				 * is bounded by what was READ - what must never
				 * happen is a file sized from the header.
				 */
				if (n > SPAN)
					fail("the file was sized from the header "
					     "rather than from what was readable");
				free(f);
			} else {
				printf("  %-24s -> từ chối\n", bad[k].what);
			}
		}
	}

	/* 4. Not an ELF at all. */
	image(0, 0);
	mem[1] = 'X';
	if (try_rebuild(&f, &n))
		fail("something that is not ELF was rebuilt anyway");

	printf("elf rebuild: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
