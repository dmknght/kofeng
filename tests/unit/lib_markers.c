/*
 * lib_markers.c - the marker tier's density rule, asked per RUN of markers
 * rather than once per segment.
 *
 * WHAT THIS PINS. koflib.c cuts a span from the first library string in a
 * loadable segment to the last, and refuses the span when it is too sparse to
 * be a table - "a library whose strings are five kilobytes apart is not a
 * library". Asked once over the whole segment, that test makes ONE stray
 * marker a veto over everything: a real errno table 585 bytes wide, plus a
 * lone `__libc_` a quarter of a megabyte away, is a 249 KB span needing fifty
 * hits to pass, and it has four. Nothing is cut and the whole of uclibc stays
 * in CODE.
 *
 * So the three cases that matter are here together, because the fix must move
 * exactly one of them:
 *
 *   a table on its own            cut, as it always was
 *   a table plus a distant stray  cut - this is the one that changed
 *   markers merely scattered      refused, as it always was
 *
 * The last is the reason the rule exists at all and is the thing a fix must
 * not trade away.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/overlord/koflib.h"
#include "../../libkofeng/analyzers/parsers/binaries/elf_parse.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"

static int fails;

static void check(int cond, const char *what, const char *why)
{
	if (cond) {
		printf("  ok   %s\n", what);
		return;
	}
	printf("  FAIL %s - %s\n", what, why);
	fails++;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

#define FILE_N   0x30000u
#define LOAD_OFF 0u

/*
 * A 64-bit little-endian ELF with one PT_LOAD over the whole file and no
 * section headers - which is what a stripped static build is, and all the
 * marker tier reads.
 */
static uint8_t *build(void)
{
	uint8_t *b = calloc(1, FILE_N);

	if (!b)
		return NULL;
	memcpy(b, "\177ELF", 4);
	b[4] = 2;                      /* ELFCLASS64  */
	b[5] = 1;                      /* ELFDATA2LSB */
	b[6] = 1;
	put16(b + 16, 2);              /* ET_EXEC */
	put16(b + 18, 62);             /* EM_X86_64 */
	put32(b + 20, 1);
	put64(b + 24, 0x400000u);      /* entry */
	put64(b + 32, 64);             /* phoff */
	put16(b + 52, 64);             /* ehsize */
	put16(b + 54, 56);             /* phentsize */
	put16(b + 56, 1);              /* phnum */

	put32(b + 64, 1);              /* PT_LOAD */
	put32(b + 68, 5);              /* R-X */
	put64(b + 72, LOAD_OFF);       /* offset */
	put64(b + 80, 0x400000u);      /* vaddr */
	put64(b + 88, 0x400000u);      /* paddr */
	put64(b + 96, FILE_N);         /* filesz */
	put64(b + 104, FILE_N);        /* memsz */
	put64(b + 112, 0x1000u);       /* align */
	return b;
}

/* The errno strings a libc keeps packed together. */
static void put_table(uint8_t *b, uint64_t at)
{
	static const char *const s[] = {
		"Permission denied", "No such file or directory",
		"Invalid argument", "Cannot allocate memory"
	};
	unsigned i;
	uint64_t o = at;

	for (i = 0; i < sizeof s / sizeof s[0]; i++) {
		memcpy(b + o, s[i], strlen(s[i]) + 1u);
		o += strlen(s[i]) + 1u;
	}
}

static uint32_t spans_of(uint8_t *b, struct kof_lib_result *out)
{
	static struct kof_elf_info e;
	struct kof_obj_ctx ctx;
	kof_buf f = kof_buf_make(b, FILE_N);

	memset(&e, 0, sizeof e);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_elf_parse(f, &e, &ctx))
		return 0xffffffffu;
	kof_lib_find(f, &e, out);
	return out->n;
}

/* A table on its own is what the tier was written for. */
static void a_table_is_cut(void)
{
	struct kof_lib_result r;
	uint8_t *b = build();

	if (!b)
		return;
	put_table(b, 0x20000u);
	check(spans_of(b, &r) == 1u, "markers: a packed table is one span",
	      "four strings inside a hundred bytes is a table");
	if (r.n == 1u)
		check(r.span[0].len < 1024u,
		      "markers: and the span is the table",
		      "not the segment it sits in");
	free(b);
}

/*
 * THE CASE THAT CHANGED. The table is the same; one marker a long way off is
 * added, and it used to take the whole answer with it.
 */
static void a_stray_does_not_veto_a_table(void)
{
	struct kof_lib_result r;
	uint8_t *b = build();
	uint32_t n;

	if (!b)
		return;
	memcpy(b + 0x1000u, "__libc_start_main", 18);
	put_table(b, 0x20000u);
	n = spans_of(b, &r);
	check(n >= 1u, "markers: a distant stray does not veto the table",
	      "the run that IS dense is judged on its own");
	if (n >= 1u && n != 0xffffffffu) {
		uint32_t i;
		int holds_table = 0, holds_stray = 0;

		for (i = 0; i < n; i++) {
			uint64_t a = r.span[i].off, z = a + r.span[i].len;

			if (a <= 0x20000u && z > 0x20000u)
				holds_table = 1;
			if (a <= 0x1000u && z > 0x1000u)
				holds_stray = 1;
		}
		check(holds_table, "markers: the table is in the answer",
		      "which is the cut that was being lost");
		check(!holds_stray, "markers: and the lone marker is not",
		      "one hit is not a table, wherever it lies");
	}
	free(b);
}

/*
 * AND THE RULE IT IS THERE FOR IS UNCHANGED. Twelve markers spread across the
 * segment are twelve runs of one, and a run of one never reaches the floor.
 */
static void scattered_markers_are_refused(void)
{
	struct kof_lib_result r;
	uint8_t *b = build();
	unsigned i;

	if (!b)
		return;
	for (i = 0; i < 12u; i++)
		memcpy(b + 0x2000u + i * 0x2800u, "GLIBC_2.2.5", 12);
	check(spans_of(b, &r) == 0u, "markers: scattered markers cut nothing",
	      "this is the input the density rule exists for");
	free(b);
}

/* Two hits are not a table either, however close they sit. */
static void two_markers_are_not_a_table(void)
{
	struct kof_lib_result r;
	uint8_t *b = build();

	if (!b)
		return;
	memcpy(b + 0x20000u, "Permission denied", 18);
	memcpy(b + 0x20020u, "Invalid argument", 17);
	check(spans_of(b, &r) == 0u, "markers: two hits are under the floor",
	      "three distinct positions is what makes it a table");
	free(b);
}

int main(void);
int main(void)
{
	printf("lib markers:\n");
	setvbuf(stdout, NULL, _IONBF, 0);

	a_table_is_cut();
	a_stray_does_not_veto_a_table();
	scattered_markers_are_refused();
	two_markers_are_not_a_table();

	if (fails) {
		printf("\nlib markers: %d check(s) failed\n", fails);
		return 1;
	}
	printf("\nlib markers: ok\n");
	return 0;
}
