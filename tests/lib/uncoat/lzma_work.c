/*
 * lzma_work - the WORK an LZMA2 state reset does, counted rather than timed.
 *
 * A chunk header of five bytes can ask for a state reset, and a reset used to rewrite
 * every probability of the largest model the stream had ever grown (3.1 M words at
 * lc 8 lp 4) whatever the chunk then used: input of a few bytes per chunk bought
 * megabytes of stores, so a few KB of input held a decoder for seconds. A reset now
 * rewrites the fixed part of the model and a literal context is initialised the
 * first time it is used, so the work is bounded by the input and the output times a
 * small constant.
 *
 * This file includes the decoder's source with KUNCOAT_LZMA_WORK_HOOK defined, which
 * makes it add the number of probability words it writes to `kuncoat_lzma_work`. A
 * count is the same on a slow machine and a fast one, which a stopwatch is not.
 */

#define KUNCOAT_LZMA_WORK_HOOK 1

#include "hostile_common.h"
#include "hostile_lzenc.h"

#include "../../../libuncoat/decompressors/lzma.c"

uint64_t kuncoat_lzma_work;

#define NCHUNKS 400u

/* One big-model chunk, then NCHUNKS one-literal chunks that each ask for `reset`
 * (1: state only, so the big properties stay; 2: new tiny properties). */
static void storm(unsigned reset)
{
	static uint8_t big[100000];
	uint8_t tmp[64], out[NCHUNKS + 16];
	struct hv_lz e;
	size_t n = 0, cl, i;
	uint64_t p = 0, w0, bound;
	enum kuncoat_status st;

	if (!hv_lz_init(&e, tmp, sizeof tmp, 8, 4, 4, 4096)) {
		CK(0);
		return;
	}
	hv_lz_lit(&e, 'a');
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(big + n, 1, cl, 3, 224);        /* lc 8 lp 4 pb 4, dictionary reset */
	memcpy(big + n, tmp, cl);
	n += cl;
	for (i = 0; i < NCHUNKS; i++) {
		if (reset == 2u)
			hv_lz_reset(&e, 0, 0, 0);
		else
			hv_lz_reset(&e, 8, 4, 4);
		hv_lz_rc_start(&e, tmp, sizeof tmp);
		hv_lz_lit(&e, 'b');
		cl = hv_lz_rc_finish(&e);
		n += hv_lz2_head(big + n, 1, cl, reset, 0);
		memcpy(big + n, tmp, cl);
		n += cl;
	}
	big[n++] = 0;
	hv_lz_free(&e);
	CK(n < sizeof big);

	kuncoat_lzma_work = 0;
	hv_at(1, reset);
	st = kuncoat_lzma2_decode(big, n, out, sizeof out, &p);
	w0 = kuncoat_lzma_work;
	CKF(st == KUNCOAT_OK && p == NCHUNKS + 1u && out[0] == 'a' && out[NCHUNKS] == 'b',
	    "reset %u: %s, %llu bytes", reset, kuncoat_status_name(st), (unsigned long long)p);
	/* Each chunk: the fixed part (O_LITERAL words) and the one literal context it
	 * touches (0x300), plus the first chunk's two. The old reset wrote 3.1 M words per
	 * chunk. The bound is twice the real figure and a thousandth of the old. */
	bound = 2u * (uint64_t)(NCHUNKS + 2u) * ((uint64_t)O_LITERAL + 0x300u);
	printf("  (reset %u: %zu input bytes, %llu probability words written, bound %llu)\n", reset, n,
	       (unsigned long long)w0, (unsigned long long)bound);
	CKF(w0 <= bound, "reset %u wrote %llu words for %zu bytes of input", reset, (unsigned long long)w0, n);
}

/* Many chunks that each use one literal context of a big model and ask for no reset:
 * nothing is rewritten at all beyond first use. */
static void no_reset(void)
{
	static uint8_t big[100000];
	uint8_t tmp[64], out[NCHUNKS + 16];
	struct hv_lz e;
	size_t n = 0, cl;
	uint64_t p = 0;
	enum kuncoat_status st;

	if (!hv_lz_init(&e, tmp, sizeof tmp, 8, 4, 4, 4096)) {
		CK(0);
		return;
	}
	hv_lz_lit(&e, 'a');
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(big + n, 1, cl, 3, 224);
	memcpy(big + n, tmp, cl);
	n += cl;
	big[n++] = 0;
	hv_lz_free(&e);
	kuncoat_lzma_work = 0;
	hv_at(2, 0);
	st = kuncoat_lzma2_decode(big, n, out, sizeof out, &p);
	CKF(st == KUNCOAT_OK && p == 1u, "single chunk: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
	CKF(kuncoat_lzma_work <= (uint64_t)O_LITERAL + 0x300u, "single chunk wrote %llu words",
	    (unsigned long long)kuncoat_lzma_work);
}

HV_GROUP(no_reset)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	storm(1);
	storm(2);
	hv_expect_clean("single chunk", hv_grp_no_reset, NULL, 20);
	return hv_done("lzma_work");
}
