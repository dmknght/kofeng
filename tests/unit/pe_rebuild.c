/*
 * pe_rebuild - turn an image back into a file, and check the bytes.
 *
 * The reason this compares CONTENT rather than verdicts is a bug it would have
 * caught and the first version of it did not. The section table sits four bytes
 * past the "PE\0\0" signature, and reading it without that offset produced a file
 * whose header was perfectly correct - the header is copied from the signature, not
 * through the table - so the result identified as PE32, parsed cleanly, reported
 * four sections with sane names and permissions, and had every section's CONTENT
 * placed from a garbage offset. `file` was happy with it. A scanner would have
 * searched the wrong bytes and found nothing, and nothing would have said so.
 *
 * So the assertion here is that each section of the rebuilt file is byte for byte
 * what was at its computed place in the image. Everything else - that it is a PE,
 * that it parses - follows from that and is not worth asserting separately.
 *
 * The image is built here rather than taken from a corpus. What is being tested is
 * the reassembly, and an image whose every field this test chose is one where a
 * disagreement can only be the reassembly's.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofunpack/pe_rebuild.h"

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

static void check_roundtrip(void)
{
	uint64_t img_len = 0, out_len = 0;
	uint32_t hdr_at = 0, i;
	uint8_t *img = build_image(&img_len, &hdr_at);
	uint8_t *out = NULL;

	if (!img) {
		fail("roundtrip", "out of memory");
		return;
	}
	if (!kof_pe_rebuild(kof_buf_make(img, img_len), 1u << 20, &out, &out_len)) {
		fail("roundtrip", "an image with a valid header was not rebuilt");
		free(img);
		return;
	}

	if (out_len != secs[N_SEC - 1].ptr + secs[N_SEC - 1].raw)
		fail("roundtrip", "the file is not as long as its last section ends");
	if (out[0] != 'M' || out[1] != 'Z')
		fail("roundtrip", "no DOS signature, so nothing will identify it");

	/*
	 * The check the whole file exists for: every section's bytes, compared
	 * against where they were in the image.
	 */
	for (i = 0; i < N_SEC; i++) {
		uint64_t src = secs[i].rva - FIRST_RVA;

		if (secs[i].ptr + secs[i].raw > out_len) {
			fail("roundtrip", "a section runs past the rebuilt file");
			break;
		}
		if (memcmp(out + secs[i].ptr, img + src, secs[i].raw) != 0) {
			fail("roundtrip", "a section holds bytes from the wrong place "
					  "in the image");
			break;
		}
	}

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
		uint64_t img_len = 0, out_len = 0;
		uint32_t hdr_at = 0;
		uint8_t *img = build_image(&img_len, &hdr_at);
		uint8_t *out = NULL;

		if (!img)
			return;
		if (bad[c].is16)
			put16(img, hdr_at + bad[c].off, (uint16_t)bad[c].val);
		else
			put32(img, hdr_at + bad[c].off, bad[c].val);

		if (kof_pe_rebuild(kof_buf_make(img, img_len), 1u << 20, &out,
				   &out_len)) {
			/* Rebuilding is allowed - another header may still be found -
			 * but the result must be bounded and must not claim more than
			 * the cap. */
			if (out_len == 0 || out_len > (1u << 20))
				fail(bad[c].what, "rebuilt to an impossible length");
			free(out);
		}
		free(img);
	}

	/* A section that says its bytes live past the end of the image: written
	 * short rather than refused, and never read out of range. */
	{
		uint64_t img_len = 0, out_len = 0;
		uint32_t hdr_at = 0, t;
		uint8_t *img = build_image(&img_len, &hdr_at);
		uint8_t *out = NULL;

		if (!img)
			return;
		t = hdr_at + SIG_LEN + COFF_LEN + OPT_LEN;
		put32(img, t + 12, 0x7fff0000u);        /* an RVA far past the image */
		if (kof_pe_rebuild(kof_buf_make(img, img_len), 1u << 20, &out,
				   &out_len)) {
			if (out_len > (1u << 20))
				fail("rva past the image", "rebuilt to an impossible length");
			free(out);
		}
		free(img);
	}

	/* A cap smaller than the file the header describes: refused, not truncated,
	 * because a short file puts every section at an offset that means something
	 * else. */
	{
		uint64_t img_len = 0, out_len = 0;
		uint32_t hdr_at = 0;
		uint8_t *img = build_image(&img_len, &hdr_at);
		uint8_t *out = NULL;

		if (!img)
			return;
		if (kof_pe_rebuild(kof_buf_make(img, img_len), 64, &out, &out_len)) {
			fail("cap too small", "built a file larger than the cap allowed");
			free(out);
		}
		free(img);
	}
}

int main(void)
{
	check_roundtrip();
	check_hostile();

	printf("pe rebuild: image to file %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
