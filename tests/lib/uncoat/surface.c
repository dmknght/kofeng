/*
 * uncoat / surface - every decoder family of libuncoat reached through <uncoat.h>
 * alone, linked against libkuncoat.a and nothing else.
 *
 * transform_status.c reaches kuncoat_transform, which dispatches to the ciphers,
 * the codings and inflate. The decompressors (aPLib, ASPack, LZMA, LZMAT, NRV2,
 * RAR 3/5, BCJ, BCJ2, LZW, OVBA, the text codings) are separate objects of the
 * archive that kuncoat_transform does not name - and a static archive links only
 * the members a test reaches. One symbol of the engine referenced from one of
 * those members would be an undefined reference only for a test that reached it.
 * This file reaches each of them.
 *
 * What is asserted is what holds for ANY input, so it is also the smallest
 * hostile-input check of each: an empty input and a garbage input never claim
 * more output than the room given (produced <= cap), never read past the input,
 * and an empty input is never a complete answer with bytes in it.
 */

#include <uncoat.h>

#include <stdio.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define OUT 256u

static uint8_t garbage[96];
static uint8_t out[OUT];

static int sink(void *user, const uint8_t *p, uint32_t n)
{
	(void)p;
	*(uint64_t *)user += n;
	return 0;
}

/* `st` is a status this build can return, and the room was respected. */
static void sane(enum kuncoat_status st, uint64_t produced, uint64_t cap)
{
	CK((unsigned)st <= (unsigned)KUNCOAT_BAD_ARG);
	CK(produced <= cap);
}

static void buffers(void)
{
	uint64_t n;
	unsigned i;

	for (i = 0; i < sizeof garbage; i++)
		garbage[i] = (uint8_t)(i * 37u + 11u);

	n = 99; sane(kuncoat_aplib_decode(garbage, 0, out, OUT, &n), n, OUT);
	CK(n == 0);
	n = 99; sane(kuncoat_aplib_decode(garbage, sizeof garbage, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_aspack_decode(garbage, 0, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_aspack_decode(garbage, sizeof garbage, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_lzma_decode(3, 0, 2, garbage, 0, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_lzma_decode(3, 0, 2, garbage, sizeof garbage, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_lzma2_decode(garbage, 0, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_lzma2_decode(garbage, sizeof garbage, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_lzmat_decode(garbage, 0, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_lzmat_decode(garbage, sizeof garbage, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_nrv2_decode(0, 32, garbage, 0, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_nrv2_decode(0, 32, garbage, sizeof garbage, out, OUT, &n), n, OUT);
	n = 99; sane(kuncoat_a85_decode(garbage, 0, out, OUT, &n), n, OUT);
	CK(n == 0);
	n = 99; sane(kuncoat_ahx_decode(garbage, 0, out, OUT, &n), n, OUT);
	CK(n == 0);
	n = 99; sane(kuncoat_ahx_decode(garbage, sizeof garbage, out, OUT, &n), n, OUT);
	{
		static uint8_t scratch[1u << 16];

		n = 99; sane(kuncoat_rar3_decode(garbage, 0, out, OUT, scratch, sizeof scratch, &n), n, OUT);
		n = 99; sane(kuncoat_rar3_decode(garbage, sizeof garbage, out, OUT, scratch, sizeof scratch, &n), n, OUT);
		n = 99; sane(kuncoat_rar5_decode(garbage, 0, out, OUT, scratch, sizeof scratch, &n), n, OUT);
		n = 99; sane(kuncoat_rar5_decode(garbage, sizeof garbage, out, OUT, scratch, sizeof scratch, &n), n, OUT);
	}
}

static void in_place_and_streams(void)
{
	static uint8_t buf[64];
	static struct kuncoat_lzw lzw;
	uint64_t n, got;

	/* the in-place filters change bytes and never the length */
	memset(buf, 0xe8, sizeof buf);
	CK(kuncoat_bcj_x86_decode(buf, sizeof buf, 0) <= sizeof buf);
	CK(kuncoat_mpress_cto_decode(buf, sizeof buf, 64) <= sizeof buf);
	kuncoat_aspack_e8e9_decode(buf, sizeof buf, 0xe8);
	CK(kuncoat_bcj2_decode(garbage, 0, garbage, 0, garbage, 0, garbage, 0, out, OUT) <= OUT);
	CK(kuncoat_bcj2_decode(garbage, sizeof garbage, garbage, 8, garbage, 8, garbage, 16, out, OUT) <= OUT);

	/* the streaming ones, with a sink that counts */
	got = 0; n = 99;
	sane(kuncoat_lzw_decode(&lzw, garbage, sizeof garbage, sink, &got, &n), n, ~0ull);
	got = 0; n = 99;
	sane(kuncoat_rle_decode(garbage, sizeof garbage, sink, &got, &n), n, ~0ull);
	got = 0; n = 99;
	sane(kuncoat_ovba_decode(garbage, sizeof garbage, sink, &got, &n), n, ~0ull);

	/* the sniffers answer yes or no and read within their input */
	CK(kuncoat_bunzip_sniff(garbage, 0) == 0);
	CK(kuncoat_bunzip_sniff((const uint8_t *)"BZh9", 4) >= 0);
	CK(kuncoat_ovba_plausible(garbage, 0) == 0);
}

int main(void)
{
	buffers();
	in_place_and_streams();
	printf("uncoat surface: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
