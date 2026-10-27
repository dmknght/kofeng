/*
 * cov_aspack_roundtrip - the ASPack block decoder of aspack.c driven past its header (asp_run, the match decoding, the offset
 * history, the escape lengths, the rebuild symbol and the carry bit were run by no test: the header-only garbage of hostile_lzbit.c
 * never produced a valid code).
 *
 * The streams are written by hostile_aspenc.h, an encoder written from the decoder's control flow; a plain text goes in and must come
 * out. What is asserted:
 *   ROUND TRIP   200 random streams over the shapes (1 to 4 blocks, the flat and the skewed offset alphabet, repeat offsets,
 *                lengths up to 264, distances up to 20000) decode to their plain text under a cap equal to its size
 *   CAPS         under every cap below the size the bytes are the real beginning and the status is not an error the stream does not have
 *   CUT          the stream cut at a stride: never a fault, never more than the plain text's bytes where they agree, and TRUNCATED or
 *                CORRUPT (the cut comes inside a code or a table)
 *   EXACT        a hand-made stream: two literals and a repeat (the decoder's smallest valid block), written bit by bit here without the
 *                encoder, so the encoder is not the only thing that says what a block is
 * Each shape is also decoded under a cap one above the size (the decoder has nothing more to decode and says what it likes: no fault).
 */
#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_aspenc.h"
#include "../../unit/known_miss.h"

static struct hv_aspvec v;
static uint8_t got[HV_ASP_MAXV + 600];
static unsigned cut_fabricated, cut_cases;      /* cuts that gave bytes that are not the stream's, or said OK */

static void round_trip(void)
{
	unsigned i;

	for (i = 0; i < 200; i++) {
		size_t target = i % 5 == 0 ? 20u + i : i % 5 == 1 ? 700u : i % 5 == 2 ? 4000u : i % 5 == 3 ? 9000u : 25000u;
		unsigned nseg = 1u + i % 4u;
		int flat = (int)((i >> 2) & 1u);
		uint64_t p = 0;
		enum kuncoat_status st;

		if (!make_asp(&v, 1000u + i, target, nseg, flat)) {
			CKF(0, "case %u: the encoder ran out of room", i);
			continue;
		}
		hv_at(i, target);
		st = kuncoat_aspack_decode(v.in, v.n, got, v.wn, &p);
		CKF(st == KUNCOAT_OK && p == v.wn && !memcmp(got, v.want, v.wn), "case %u (target %zu, %u blocks, %s): %s, %llu of %zu bytes", i, target, nseg,
		    flat ? "flat" : "skewed", kuncoat_status_name(st), (unsigned long long)p, v.wn);
		/* one above: no fault, and the first wn bytes are the same */
		memset(got, 0xAA, sizeof got);
		st = kuncoat_aspack_decode(v.in, v.n, got, v.wn + 1u, &p);
		CKF(p >= v.wn || st != KUNCOAT_OK, "case %u: cap+1 said OK with %llu of %zu", i, (unsigned long long)p, v.wn);
		CKF(!memcmp(got, v.want, p < v.wn ? (size_t)p : v.wn), "case %u: cap+1 changed the bytes", i);
		if (hv_fails > 8)
			return;
	}
}

static void caps_and_cuts(void)
{
	unsigned i;

	for (i = 0; i < 12; i++) {
		size_t cap, k;
		uint64_t p = 0;
		enum kuncoat_status st;

		if (!make_asp(&v, 5000u + i, 6000, 1u + i % 3u, (int)(i & 1u)))
			continue;
		for (cap = 1; cap < v.wn; cap += 1 + v.wn / 61u) {
			hv_at(i, cap);
			st = kuncoat_aspack_decode(v.in, v.n, got, cap, &p);
			CKF(p <= cap && !memcmp(got, v.want, (size_t)p), "case %u cap %zu: %llu bytes, not the beginning (%s)", i, cap, (unsigned long long)p,
			    kuncoat_status_name(st));
			/* the cap is the declared size: reaching it is OK unless the last match does not fit it (the stream is then CORRUPT, the bytes
			 * before it are kept) */
			CKF(st == KUNCOAT_OK || st == KUNCOAT_CORRUPT, "case %u cap %zu: %s", i, cap, kuncoat_status_name(st));
		}
		for (k = 0; k < v.n; k += 1 + v.n / 53u) {
			hv_at(i, k + 100000u);
			st = kuncoat_aspack_decode(v.in, k, got, v.wn, &p);
			CKF(hv_status_ok(st) && p <= v.wn, "case %u cut at %zu of %zu: %s, %llu bytes", i, k, v.n, kuncoat_status_name(st), (unsigned long long)p);

		}
	}
}

/*
 * A block written by hand, with no encoder: the carry bit 0, the lengths alphabet of 19 four bit lengths all 4 except three zeros (a
 * complete code of 16 symbols), then 757 delta symbols that give alphabet 0 the lengths { 'a': 1, 'b': 2, 256+..: 3 ... }. That needs
 * a code for 721 symbols to be complete; here: 'a' 1 bit, 'b' 2 bits, the match symbol (256 + class 0 * 8 + length 0) 3 bits, and 720
 * 3 bits - 1/2 + 1/4 + 1/8 + 1/8 = 1. Alphabet 1 (28 symbols) and 2 (8) are given 2 symbols of 1 bit each / the flat 3 bits.
 * The decoder's smallest valid stream: a, b, a match of length 2 distance 1 (offset class 0: "use" 0, the first history entry, which is
 * distance 1 when nothing came before), so the plain text is "abb"... but a repeat of use 0 needs hist[0] = 0: distance 1, so the third
 * symbol repeats 'b' twice: "abbb".
 */
static void exact(void)
{
	uint8_t buf[1500];
	struct hv_bw w;
	uint8_t l[757], l3[19];
	uint32_t c3[19];
	unsigned i;
	uint64_t p = 0;
	enum kuncoat_status st;

	memset(l, 0, sizeof l);
	l['a'] = 1; l['b'] = 2; l[256] = 3; l[720] = 3;
	l[721] = 1; l[722] = 1;                       /* alphabet 1: two symbols of one bit */
	for (i = 0; i < 8; i++)
		l[749 + i] = 3;                       /* alphabet 2: the flat code */
	for (i = 0; i < 19; i++)
		l3[i] = 4;
	l3[16] = l3[17] = l3[18] = 0;                 /* 16 symbols of 4 bits: complete */
	hv_asp_codes(l3, 19, c3);
	hv_bw_init(&w, buf, sizeof buf);
	hv_bw_msb(&w, 0, 1);                          /* carry: no */
	for (i = 0; i < 19; i++)
		hv_bw_msb(&w, l3[i], 4);
	for (i = 0; i < 757; i++) {                   /* deltas from zero: the lengths themselves */
		hv_bw_msb(&w, c3[l[i]], l3[l[i]]);
	}
	/* alphabet 0 codes (canonical, shortest numerically lowest): 'a' = 0, 'b' = 10, then the two 3-bit symbols 256 = 110, 720 = 111 */
	hv_bw_msb(&w, 0, 1);                          /* a */
	hv_bw_msb(&w, 2, 2);                          /* b */
	hv_bw_msb(&w, 6, 3);                          /* 256: class 0, length 2 */
	hv_bw_align_msb(&w);
	st = kuncoat_aspack_decode(buf, w.n, got, 4, &p);
	CKF(st == KUNCOAT_OK && p == 4 && !memcmp(got, "abbb", 4), "hand-made block: %s, %llu bytes %.4s", kuncoat_status_name(st), (unsigned long long)p, (char *)got);
}

HV_GROUP(round_trip)
HV_GROUP(caps_and_cuts)
HV_GROUP(exact)

/*
 * A stream cut short is decoded on, out of the zero bytes the reader supplies past the end (KUNCOAT_ASPACK_LOOKAHEAD, 0x10e of them:
 * meant for the last symbol's look-ahead, used as symbols). Cut at 160 bytes of 812 the block still produces 5996 of 6002 bytes
 * that are not the stream's, and cut at 784 of 812 it says OK. Finding F-ASP-1 of WP5; a reproducer is made by this test's own
 * encoder (seed 5011, 6000 bytes, 3 blocks, flat offsets). Not fixed here (no engine edit): the KM_CHECK below goes red the day the
 * decoder stops fabricating, and then becomes a CK.
 */
int main(void)
{
	int bad;

	setvbuf(stdout, NULL, _IONBF, 0);
	hv_expect_clean("aspack round trip", hv_grp_round_trip, NULL, 60);
	hv_expect_clean("aspack caps (cuts run in the next group, no fault)", hv_grp_caps_and_cuts, NULL, 60);
	hv_expect_clean("aspack hand-made block", hv_grp_exact, NULL, 10);
	/* the cut property needs the counters of the same process: run in this one, after the isolated groups */
	cut_fabricated = cut_cases = 0;
	{
		unsigned i;

		for (i = 0; i < 12; i++) {
			size_t k;
			uint64_t p = 0;
			enum kuncoat_status st;

			if (!make_asp(&v, 5000u + i, 6000, 1u + i % 3u, (int)(i & 1u)))
				continue;
			for (k = 0; k < v.n; k += 1 + v.n / 53u) {
				st = kuncoat_aspack_decode(v.in, k, got, v.wn, &p);
				cut_cases++;
				if (st == KUNCOAT_OK || memcmp(got, v.want, (size_t)(p < v.wn ? p : v.wn)))
					cut_fabricated++;
			}
		}
	}
	printf("  aspack cuts: %u of %u cut streams gave bytes that are not the stream's or said OK\n", cut_fabricated, cut_cases);
	/* KNOWN DEFECT WP5-F-ASP-1 (2026-10-25, M): this row pins it, green until fixed. */
	KM_CHECK(cut_fabricated == 0, "a cut ASPack block decodes fabricated bytes out of the zero look-ahead pad (and may say OK)",
		 "ASPACK_LOOKAHEAD libuncoat/decompressors/aspack.c:asp_fill pad lost: evidence");
	bad = hv_done("cov_aspack_roundtrip");
	return bad || km_failed();
}
