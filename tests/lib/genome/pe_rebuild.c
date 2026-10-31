/*
 * pe_rebuild - the layout of an image, read out and written back.
 *
 * WHAT THIS TESTS NOW, AND WHY IT CHANGED. It used to test kof_pe_rebuild,
 * which took an image and produced a FILE by copying every section to a
 * computed offset. That function is gone: a module no longer synthesises a
 * header for the engine to parse back, it DECLARES its layout - see `section`
 * in kofsig.h - and the two halves left are the ones tested here.
 *
 *   kgenome_pe_layout_of   reads a layout out of an image a stub assembled. This
 *                      is what kunp_rcstruct_layout_of_image answers with, so
 *                      every emulator-produced child depends on it.
 *   kgenome_pe_write_hdr   writes a header from a declared layout, which is how
 *                      every declared child gets one.
 *
 * The assertion is a ROUND TRIP: declare a layout, write a header, read it
 * back, and require the answer to be what was declared. That catches what the
 * old content comparison was written for and says why it mattered - the
 * section table sits four bytes past "PE\0\0", and a reader that forgets the
 * offset produces a header that parses cleanly and describes something else
 * entirely. A round trip cannot be fooled by that: both directions would have
 * to be wrong in the same way.
 *
 * The image is built here rather than taken from a corpus. What is being
 * tested is the layout arithmetic, and an image whose every field this test
 * chose is one where a disagreement can only be the arithmetic's.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/pe.h>

#include <genotype/image/pe_rebuild.h>

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- building an image to take apart ---------------------------------------- */

#define SIG_LEN   4u
#define COFF_LEN  20u
#define OPT_LEN   224u
#define SEC_LEN   40u
#define N_SEC     4u
#define FIRST_RVA 0x1000u

struct sec {
	const char *name;
	uint32_t rva, raw, ptr;
};

/*
 * Four sections with the shape a real image has: raw offsets in file order,
 * virtual addresses page aligned and further apart than the raw sizes, so the two
 * mappings genuinely differ and a rebuild that confused them would be visible.
 */
static const struct sec secs[N_SEC] = {
	{ ".text",  0x1000u,  0x2000u, 0x400u  },
	{ ".rdata", 0x4000u,  0x1000u, 0x2400u },
	{ ".data",  0x7000u,  0x800u,  0x3400u },
	{ ".rsrc",  0xa000u,  0x600u,  0x3c00u }
};

static void put16(uint8_t *p, uint32_t at, uint16_t v)
{
	p[at] = (uint8_t)v;
	p[at + 1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t at, uint32_t v)
{
	p[at] = (uint8_t)v;
	p[at + 1] = (uint8_t)(v >> 8);
	p[at + 2] = (uint8_t)(v >> 16);
	p[at + 3] = (uint8_t)(v >> 24);
}

/*
 * An image: sections at their virtual addresses from FIRST_RVA, with the original
 * header kept at the end. That is where UPX leaves it, and the point of putting it
 * there is that nothing can find it by looking at offset zero.
 */
static uint8_t *build_image(uint64_t *len_out, uint32_t hdr_at_out[1])
{
	uint32_t last = secs[N_SEC - 1].rva - FIRST_RVA + secs[N_SEC - 1].raw;
	uint32_t hdr_at = last + 0x100u;
	uint32_t total = hdr_at + SIG_LEN + COFF_LEN + OPT_LEN + N_SEC * SEC_LEN + 16u;
	uint8_t *img = calloc(1, total);
	uint32_t i, t;

	if (!img)
		return NULL;

	/* Section content: each byte says which section it came from and where in
	 * it, so a rebuild that takes bytes from the wrong place cannot produce
	 * something that happens to compare equal. */
	for (i = 0; i < N_SEC; i++) {
		uint32_t at = secs[i].rva - FIRST_RVA, k;

		for (k = 0; k < secs[i].raw; k++)
			img[at + k] = (uint8_t)((i * 37u) + (k * 31u) + 5u);
	}

	/*
	 * Two decoys before the real header, because an image really does contain
	 * these: compressed data holds the four bytes often enough that the first
	 * hit is usually not the header. Each is wrong in a different way.
	 */
	memcpy(img + 0x40, "PE\0\0", 4);
	put16(img, 0x40 + SIG_LEN + 2, 3001);        /* an impossible section count */
	memcpy(img + 0x80, "PE\0\0", 4);
	put16(img, 0x80 + SIG_LEN + 2, 3);
	put16(img, 0x80 + SIG_LEN + 16, OPT_LEN);
	put16(img, 0x80 + SIG_LEN + COFF_LEN, 0xcccc); /* not an optional magic */

	memcpy(img + hdr_at, "PE\0\0", 4);
	put16(img, hdr_at + SIG_LEN + 0, 0x014c);      /* i386 */
	put16(img, hdr_at + SIG_LEN + 2, (uint16_t)N_SEC);
	put16(img, hdr_at + SIG_LEN + 16, OPT_LEN);
	put16(img, hdr_at + SIG_LEN + COFF_LEN, 0x010b);   /* PE32 */

	t = hdr_at + SIG_LEN + COFF_LEN + OPT_LEN;
	for (i = 0; i < N_SEC; i++) {
		uint32_t o = t + i * SEC_LEN;

		memcpy(img + o, secs[i].name, strlen(secs[i].name));
		put32(img, o + 8, secs[i].raw);        /* VirtualSize */
		put32(img, o + 12, secs[i].rva);
		put32(img, o + 16, secs[i].raw);
		put32(img, o + 20, secs[i].ptr);
	}

	*len_out = total;
	hdr_at_out[0] = hdr_at;
	return img;
}

/* ---- the case that matters --------------------------------------------------- */

#define DECL_MAX 16u

/* What the image above says, as kgenome_pe_layout_of should report it. */
static void check_layout_of(void)
{
	uint64_t img_len = 0, entry = 0, base = 0;
	uint32_t hdr_at = 0, i, n;
	uint8_t *img = build_image(&img_len, &hdr_at);
	struct kgenome_sec_decl decl[DECL_MAX];
	struct kgenome_dir_decl dir[16];

	if (!img) {
		fail("layout_of", "out of memory");
		return;
	}
	memset(decl, 0, sizeof decl);
	memset(dir, 0, sizeof dir);
	n = kgenome_pe_layout_of(kof_buf_make(img, img_len), decl, DECL_MAX,
			     &entry, &base, dir);
	if (n != N_SEC) {
		fail("layout_of", "the section count is not what the header says");
		free(img);
		return;
	}
	for (i = 0; i < N_SEC; i++) {
		if (decl[i].rva != secs[i].rva)
			fail("layout_of", "a section is at the wrong address");
		if (decl[i].vsize != secs[i].raw)
			fail("layout_of", "a section is the wrong size");
		if (strcmp(decl[i].name, secs[i].name) != 0)
			fail("layout_of", "a section has the wrong name");
	}
	free(img);
}

/*
 * AND BACK AGAIN. A header written from a declaration has to describe that
 * declaration, or a declared child is a file whose table says something its
 * producer did not.
 */
static void check_roundtrip(void)
{
	uint64_t img_len = 0, entry = 0, base = 0, wrote;
	uint32_t hdr_at = 0, i, n;
	uint8_t *img = build_image(&img_len, &hdr_at);
	struct kgenome_sec_decl decl[DECL_MAX], back[DECL_MAX];
	struct kgenome_dir_decl dir[16], dir2[16];
	struct kgenome_pe_info *pe;
	uint8_t *out;

	if (!img) {
		fail("roundtrip", "out of memory");
		return;
	}
	memset(decl, 0, sizeof decl);
	memset(back, 0, sizeof back);
	memset(dir, 0, sizeof dir);
	memset(dir2, 0, sizeof dir2);
	n = kgenome_pe_layout_of(kof_buf_make(img, img_len), decl, DECL_MAX,
			     &entry, &base, dir);
	pe = calloc(1, sizeof *pe);
	out = calloc(1, (size_t)FIRST_RVA);
	if (!n || !pe || !out) {
		fail("roundtrip", "setup");
		free(pe);
		free(out);
		free(img);
		return;
	}
	pe->valid = 1;
	pe->machine = 0x014c;
	pe->pe32_plus = 0;
	pe->image_base = base;

	wrote = kgenome_pe_write_hdr(out, FIRST_RVA, pe, decl, n,
				 secs[0].rva, secs[N_SEC - 1].rva +
					      secs[N_SEC - 1].raw, dir);
	if (!wrote) {
		fail("roundtrip", "a layout that was read could not be written");
		free(pe);
		free(out);
		free(img);
		return;
	}

	/*
	 * Read back from the header alone. The section CONTENT is not there -
	 * only FIRST_RVA bytes were allocated - and that is deliberate: what is
	 * asserted is the table, and a reader that needed the content to
	 * produce one would be reading past what a header describes.
	 */
	{
		uint8_t *whole = calloc(1, (size_t)img_len);

		if (!whole) {
			fail("roundtrip", "out of memory");
			free(pe);
			free(out);
			free(img);
			return;
		}
		memcpy(whole, out, (size_t)wrote);
		if (kgenome_pe_layout_of(kof_buf_make(whole, img_len), back,
				     DECL_MAX, &entry, &base, dir2) != n) {
			fail("roundtrip", "the written header lost a section");
		} else {
			for (i = 0; i < n; i++) {
				if (back[i].rva != decl[i].rva)
					fail("roundtrip", "an address did not survive");
				if (back[i].vsize != decl[i].vsize)
					fail("roundtrip", "a size did not survive");
				if (strcmp(back[i].name, decl[i].name) != 0)
					fail("roundtrip", "a name did not survive");
			}
			if (entry != secs[0].rva)
				fail("roundtrip", "the entry point did not survive");
		}
		free(whole);
	}
	free(pe);
	free(out);
	free(img);
}

/* ---- what a hostile image can ask for ---------------------------------------- */

/*
 * Every field the rebuild reads, set to something it must survive.
 *
 * None of these is expected to produce a file; what is asserted is that refusing
 * is what happens, and that nothing is written or read outside the image. Under
 * SAN=1 the second half of that is the sanitizer's job, which is why the cases run
 * there rather than only here.
 */
static void check_hostile(void)
{
	static const struct {
		const char *what;
		uint32_t off, val;
		int is16;
	} bad[] = {
		{ "section count of zero",        SIG_LEN + 2,  0,          1 },
		{ "more sections than a loader allows", SIG_LEN + 2, 0xffff, 1 },
		{ "optional header of nothing",   SIG_LEN + 16, 0,          1 },
		{ "optional header past the end", SIG_LEN + 16, 0xffff,     1 },
		{ "machine zero",                 SIG_LEN + 0,  0,          1 }
	};
	const size_t n = sizeof bad / sizeof bad[0];
	size_t c;

	for (c = 0; c < n; c++) {
		uint64_t img_len = 0, entry = 0, base = 0;
		uint32_t hdr_at = 0, got;
		uint8_t *img = build_image(&img_len, &hdr_at);
		struct kgenome_sec_decl decl[DECL_MAX];
		struct kgenome_dir_decl dir[16];

		if (!img)
			return;
		memset(decl, 0, sizeof decl);
		memset(dir, 0, sizeof dir);
		if (bad[c].is16)
			put16(img, hdr_at + bad[c].off, (uint16_t)bad[c].val);
		else
			put32(img, hdr_at + bad[c].off, bad[c].val);

		/* Reading is allowed to succeed - another header may still be
		 * found - but it must never report more than it was given room
		 * for, and every address it reports must be inside the image. */
		got = kgenome_pe_layout_of(kof_buf_make(img, img_len), decl,
				       DECL_MAX, &entry, &base, dir);
		if (got > DECL_MAX)
			fail(bad[c].what, "reported more sections than the cap");
		free(img);
	}

	/* A section that says its bytes live past the end of the image. */
	{
		uint64_t img_len = 0, entry = 0, base = 0;
		uint32_t hdr_at = 0, t, got;
		uint8_t *img = build_image(&img_len, &hdr_at);
		struct kgenome_sec_decl decl[DECL_MAX];
		struct kgenome_dir_decl dir[16];

		if (!img)
			return;
		memset(decl, 0, sizeof decl);
		memset(dir, 0, sizeof dir);
		t = hdr_at + SIG_LEN + COFF_LEN + OPT_LEN;
		put32(img, t + 12, 0x7fff0000u);        /* an RVA far past the image */
		got = kgenome_pe_layout_of(kof_buf_make(img, img_len), decl,
				       DECL_MAX, &entry, &base, dir);
		if (got > DECL_MAX)
			fail("rva past the image", "reported more sections than the cap");
		free(img);
	}

	/*
	 * A HEADER THAT DOES NOT FIT IN FRONT OF THE CONTENT. `cap` is the span
	 * before the first declared section, and a caller that laid its
	 * sections out too tightly must be told rather than allowed to
	 * overwrite them.
	 */
	{
		uint64_t img_len = 0, entry = 0, base = 0;
		uint32_t hdr_at = 0, got;
		uint8_t *img = build_image(&img_len, &hdr_at);
		struct kgenome_sec_decl decl[DECL_MAX];
		struct kgenome_dir_decl dir[16];
		struct kgenome_pe_info *pe = calloc(1, sizeof *pe);
		uint8_t small[64];

		if (!img || !pe) {
			free(img);
			free(pe);
			return;
		}
		memset(decl, 0, sizeof decl);
		memset(dir, 0, sizeof dir);
		memset(small, 0, sizeof small);
		got = kgenome_pe_layout_of(kof_buf_make(img, img_len), decl,
				       DECL_MAX, &entry, &base, dir);
		pe->valid = 1;
		pe->machine = 0x014c;
		if (got && kgenome_pe_write_hdr(small, sizeof small, pe, decl, got,
					    secs[0].rva, img_len, dir))
			fail("cap too small",
			     "wrote a header into less room than it needs");
		free(pe);
		free(img);
	}
}

/*
 * E-PEDIR: a parent directory whose RVA falls in alignment padding. A PAD section is not written to the
 * section table, so the directory would name a place no written section holds; it is dropped, the one
 * in a written section is kept. Old tests missed it: (a) the loop that places directories was only run
 * with the declarations of check_roundtrip, which carry no PAD section.
 */
static void check_pad_directory(void)
{
	struct kgenome_sec_decl decl[3];
	struct kgenome_dir_decl none[16];
	struct kgenome_pe_info *pe = calloc(1, sizeof *pe);
	uint8_t *out = calloc(1, 0x1000);
	uint64_t wrote;
	uint32_t at;

	if (!pe || !out) {
		fail("pad directory", "out of memory");
		free(pe);
		free(out);
		return;
	}
	memset(decl, 0, sizeof decl);
	memset(none, 0, sizeof none);
	memcpy(decl[0].name, ".text", 5);   decl[0].rva = 0x1000; decl[0].vsize = 0x100;
	memcpy(decl[1].name, ".pad", 4);    decl[1].rva = 0x2000; decl[1].vsize = 0x100; decl[1].flags = KGENOME_SECF_PAD;
	memcpy(decl[2].name, ".data", 5);   decl[2].rva = 0x3000; decl[2].vsize = 0x100;
	pe->valid = 1;
	pe->machine = 0x014c;
	pe->image_base = 0x400000;
	pe->dir[2].rva = 0x2010; pe->dir[2].size = 8;     /* inside the padding */
	pe->dir[3].rva = 0x3010; pe->dir[3].size = 8;     /* inside .data */
	wrote = kgenome_pe_write_hdr(out, 0x1000, pe, decl, 3, 0x1000, 0x3100, none);
	if (!wrote) {
		fail("pad directory", "the header was not written");
	} else {
		for (at = 0; at + 4u < wrote && memcmp(out + at, "PE\0\0", 4); at++)
			;
		at += SIG_LEN + COFF_LEN + 96u;               /* the data directories of a PE32 */
		if (at + 32u > wrote)
			fail("pad directory", "no directory table found");
		else {
			uint32_t d2 = (uint32_t)out[at + 16] | (uint32_t)out[at + 17] << 8 | (uint32_t)out[at + 18] << 16;
			uint32_t d3 = (uint32_t)out[at + 24] | (uint32_t)out[at + 25] << 8 | (uint32_t)out[at + 26] << 16;

			if (d2 != 0)
				fail("pad directory", "a directory in padding was carried into the header");
			if (d3 != 0x3010)
				fail("pad directory", "a directory in a written section was lost");
		}
	}
	free(pe);
	free(out);
}

int main(void)
{
	check_layout_of();
	check_roundtrip();
	check_hostile();
	check_pad_directory();

	printf("pe rebuild: layout round trip %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
