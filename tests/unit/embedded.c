/*
 * embedded - finding a whole executable inside another object.
 *
 * The value of this pass is entirely in what it REFUSES. A four-byte magic
 * turns up by accident in any large file, and a scanner that made a child out
 * of every "\x7fELF" would spend its budget on noise and put nonsense in front
 * of a reader. So the tests below are mostly negative: a header is accepted
 * only when the fields that a real one must agree on do agree, and each of
 * those fields is broken here in turn to check that breaking it is enough.
 *
 * The measured justification for the strictness: with exactly these tests, no
 * binary in 1 328 clean ones carries an embedded executable, while a
 * multi-architecture dropper in the malware corpus yields seven - one payload
 * per architecture, each of which the database then names.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/kofunpack/embedded.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define PARENT  8192u
#define AT      1024u          /* where the embedded file is planted */

static uint8_t par[PARENT];

static void w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *p, uint32_t v) { unsigned i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (i * 8)); }
static void w64(uint8_t *p, uint64_t v) { unsigned i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8)); }

/* An ELF64 with one PT_LOAD of `fsz` bytes at file offset 0x200. */
static void plant_elf(uint64_t fsz)
{
	uint8_t *h = par + AT, *ph = par + AT + 64;

	memset(par, 0x41, sizeof par);
	memcpy(h, "\177ELF\2\1\1", 7);
	w16(h + 0x10, 2);              /* ET_EXEC   */
	w16(h + 0x12, 62);             /* x86-64    */
	w32(h + 0x14, 1);
	w64(h + 0x20, 64);             /* e_phoff   */
	w16(h + 0x34, 64);             /* e_ehsize  */
	w16(h + 0x36, 56);             /* e_phentsize */
	w16(h + 0x38, 1);              /* e_phnum   */

	w32(ph + 0x00, 1);             /* PT_LOAD   */
	w32(ph + 0x04, 5);
	w64(ph + 0x08, 0x200);
	w64(ph + 0x20, fsz);
}

/* An MZ/PE with one section of `rsz` bytes at raw offset 0x200. */
static void plant_pe(uint32_t rsz)
{
	uint8_t *h = par + AT, *pe, *sec;

	memset(par, 0x41, sizeof par);
	h[0] = 'M'; h[1] = 'Z';
	w32(h + 0x3c, 0x80);           /* e_lfanew */
	pe = h + 0x80;
	memcpy(pe, "PE\0\0", 4);
	w16(pe + 4, 0x8664);           /* machine  */
	w16(pe + 6, 1);                /* sections */
	w16(pe + 20, 0xf0);            /* optional header size */
	sec = pe + 24 + 0xf0;
	w32(sec + 16, rsz);            /* SizeOfRawData    */
	w32(sec + 20, 0x200);          /* PointerToRawData */
}

static int at(uint64_t off, struct kof_embedded *e)
{
	return kof_embedded_at(par, sizeof par, off, e);
}

int main(void)
{
	struct kof_embedded e;
	unsigned k;

	/* 1. A well formed ELF, and the extent its own headers describe. */
	plant_elf(0x100);
	if (!at(AT, &e)) {
		fail("a well formed embedded ELF was not found");
	} else {
		printf("  ELF nhúng: off=%llu len=%llu fmt=%u\n",
		       (unsigned long long)e.off, (unsigned long long)e.len,
		       e.fmt);
		if (e.off != AT || e.fmt != KOF_FMT_ELF)
			fail("the wrong offset or format came back");
		if (e.len != 0x300u)
			fail("the extent is not what the program headers say");
	}

	/* 2. Offset zero is the object itself and is never its own child. */
	plant_elf(0x100);
	memcpy(par, par + AT, 64 + 56);
	if (at(0, &e))
		fail("the object was reported as embedded in itself");

	/* 3. A length that runs off the end is clamped, not believed. */
	plant_elf(0xffffffffull);
	if (!at(AT, &e))
		fail("an ELF with an overlong segment was refused outright");
	else if (e.off + e.len > sizeof par)
		fail("the child reaches past the parent");

	/* 4. Each field that must agree, broken in turn. */
	{
		struct { const char *what; uint32_t off; unsigned w; uint64_t v; }
		bad[] = {
			{ "e_class",     4,    1, 7 },
			{ "e_data",      5,    1, 9 },
			{ "e_version",   6,    1, 2 },
			{ "e_type",      0x10, 2, 99 },
			{ "e_machine",   0x12, 2, 0x1234 },
			{ "e_ehsize",    0x34, 2, 40 }
		};

		for (k = 0; k < sizeof bad / sizeof *bad; k++) {
			plant_elf(0x100);
			if (bad[k].w == 1)
				par[AT + bad[k].off] = (uint8_t)bad[k].v;
			else
				w16(par + AT + bad[k].off, (uint16_t)bad[k].v);
			printf("  %-12s hỏng -> %s\n", bad[k].what,
			       at(AT, &e) ? "VẪN NHẬN" : "từ chối");
			if (at(AT, &e))
				fail("a header that disagrees with itself was "
				     "accepted");
		}
	}

	/* 5. The magic alone, followed by nothing that agrees with it. */
	memset(par, 0x41, sizeof par);
	memcpy(par + AT, "\177ELF", 4);
	if (at(AT, &e))
		fail("four bytes of magic were taken for a file");

	/* 6. PE needs the DOS stub AND the signature it points at. */
	plant_pe(0x100);
	if (!at(AT, &e)) {
		fail("a well formed embedded PE was not found");
	} else {
		printf("  PE nhúng : off=%llu len=%llu fmt=%u\n",
		       (unsigned long long)e.off, (unsigned long long)e.len,
		       e.fmt);
		if (e.fmt != KOF_FMT_PE || e.len != 0x300u)
			fail("the PE extent is not what its sections say");
	}
	plant_pe(0x100);
	w32(par + AT + 0x3c, 0x7fffffff);       /* e_lfanew past the parent */
	if (at(AT, &e))
		fail("an MZ pointing nowhere was taken for a PE");
	plant_pe(0x100);
	memcpy(par + AT + 0x80, "XX\0\0", 4);   /* no PE signature */
	if (at(AT, &e))
		fail("an MZ with no PE signature was taken for a PE");
	plant_pe(0x100);
	w16(par + AT + 0x80 + 4, 0x1234);       /* a machine nobody builds for */
	if (at(AT, &e))
		fail("a PE for an unknown machine was accepted");

	printf("embedded: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
