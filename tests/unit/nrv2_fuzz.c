/*
 * nrv2_fuzz - drive the NRV2 decoders with input that is not a stream.
 *
 * nrv2_upx.c proves the decoders right on real UPX blocks, using the length each
 * block declares as an oracle. It proves nothing about what they do when the input
 * is wrong, and that is the half that matters for safety: a UPX block reaches this
 * code from any ELF or PE a scanner is handed, so every bound in it is exposed to
 * whatever an author cared to put in the file.
 *
 * No seeds are needed and that is a property of the format rather than an
 * economy. NRV2 has no magic, no header and no checksum - any sequence of bytes is
 * a bit stream that decodes until it asks for something impossible - so random
 * input walks straight into the interesting paths instead of being turned away by
 * a signature check. Real blocks are used as well when a corpus is given, because
 * corrupting something valid reaches states random bytes reach rarely: a plausible
 * match length, a distance just past what has been produced, a prefix that nearly
 * terminates.
 *
 * WHAT IS ASSERTED, and each is a bug class rather than a behaviour:
 *
 *   - the status is one of the four. A decoder that returns something else has
 *     taken a path nobody wrote.
 *   - produced never exceeds the buffer. The bound that stops a heap overflow.
 *   - NOTHING PAST `produced` IS WRITTEN. The buffer is filled with a marker
 *     first and the tail is checked afterwards. ASan catches a write past the
 *     allocation; this catches a write inside it that the decoder should not have
 *     made, which is the same bug one byte earlier.
 *   - the same input decodes to the same output twice. The decoders keep no state
 *     between calls, so a difference means something carried over - and what would
 *     carry over is the previous stream's bytes.
 *   - a smaller buffer yields a prefix of the larger one's output. Where the
 *     receiver's limit lands must not change what was decoded before it.
 *
 * Under SAN=1 this is also where the window arithmetic is checked. It is all
 * bounds-tested indexing into a caller's buffer, so a sanitizer only sees a
 * mistake that leaves the allocation - which means the streams have to be decoded
 * in quantity for the check to be worth anything.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "../../libkofeng/kofdecomp/nrv2.h"

#define OUT_CAP   (1u << 20)
#define IN_MAX    8192u
#define MARKER    0xA5

static uint64_t failures, rounds_done, seeds;
static uint64_t by_status[4];

static void fail(uint64_t r, const char *why)
{
	printf("  FAIL round %llu: %s\n", (unsigned long long)r, why);
	if (++failures > 8)
		exit(1);
}

static uint64_t rng_state = 1;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

/* ---- seeds harvested from real files ---------------------------------------- */

/*
 * Real compressed blocks, taken from UPX packed ELF samples if any are to hand.
 *
 * Kept small and few: the point is a handful of streams that are genuinely valid
 * so that corrupting them lands inside the decoder rather than at its front door.
 */
#define MAX_SEEDS 24

static uint8_t  seed_buf[MAX_SEEDS][IN_MAX];
static uint32_t seed_len[MAX_SEEDS];
/* What the file said this block expands to. Kept so an UNCORRUPTED seed can be
 * checked against it - see the note on why that round type exists. */
static uint32_t seed_unc[MAX_SEEDS];
static int      seed_variant[MAX_SEEDS], seed_bits[MAX_SEEDS];

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int variant_of(unsigned m, int *bits)
{
	static const int V[9] = { KOF_NRV2B, KOF_NRV2B, KOF_NRV2B,
				  KOF_NRV2D, KOF_NRV2D, KOF_NRV2D,
				  KOF_NRV2E, KOF_NRV2E, KOF_NRV2E };
	static const int B[9] = { 32, 8, 16, 32, 8, 16, 32, 8, 16 };

	if (m < 2 || m > 10)
		return -1;
	*bits = B[m - 2];
	return V[m - 2];
}

static void harvest(const uint8_t *f, uint64_t n)
{
	uint64_t i, at;

	for (i = 0; i + 4 <= n && i < 8192; i++)
		if (!memcmp(f + i, "UPX!", 4))
			break;
	if (i + 4 > n || i >= 8192)
		return;
	at = (i - 4) + 12 + 12;         /* past l_info and p_info */

	while (at + 12 <= n && seeds < MAX_SEEDS) {
		uint32_t unc = rd32(f + at), cpr = rd32(f + at + 4);
		int bits, v;

		if (!unc || !cpr || cpr > unc || (uint64_t)cpr > n - (at + 12))
			break;
		v = variant_of(f[at + 8], &bits);
		if (v < 0)
			break;
		if (cpr <= IN_MAX) {
			memcpy(seed_buf[seeds], f + at + 12, cpr);
			seed_len[seeds] = cpr;
			seed_unc[seeds] = unc;
			seed_variant[seeds] = v;
			seed_bits[seeds] = bits;
			seeds++;
		}
		at += 12 + cpr;
	}
}

static void harvest_dir(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char path[4096];

	if (!d)
		return;
	while ((de = readdir(d)) != NULL && seeds < MAX_SEEDS) {
		struct stat st;
		void *map;
		int fd;

		if (de->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir, de->d_name)
		    >= sizeof path)
			continue;
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
		    st.st_size < 64) {
			close(fd);
			continue;
		}
		map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (map == MAP_FAILED)
			continue;
		if (!memcmp(map, "\177ELF", 4))
			harvest(map, (uint64_t)st.st_size);
		munmap(map, (size_t)st.st_size);
	}
	closedir(d);
}

/* ---- one round --------------------------------------------------------------- */

static uint8_t in[IN_MAX];
static uint8_t out_a[OUT_CAP], out_b[OUT_CAP];

static void one(uint64_t r)
{
	uint32_t n;
	int variant, bits;
	uint64_t cap, pa = 0, pb = 0, i;
	int sa, sb;

	/*
	 * One round in eight leaves a real block ALONE and checks it decodes.
	 *
	 * A fuzzer that only ever corrupts its seeds cannot tell a decoder that
	 * refuses everything from one that works: every round ends in an error
	 * status and every error status is allowed. That is not hypothetical - with
	 * only corrupting rounds, replacing this decoder's arithmetic shift with a
	 * logical one went undetected here, and it breaks every NRV2D and NRV2E
	 * stream there is. Holding one round in eight to the length the file
	 * declared is what makes the difference visible.
	 */
	if (seeds && (r % 8) == 3) {
		uint32_t s = (uint32_t)(rnd() % seeds);
		uint64_t p = 0;
		int st;

		if (seed_unc[s] <= OUT_CAP) {
			memset(out_a, MARKER, seed_unc[s]);
			st = kof_nrv2_decode(seed_variant[s], seed_bits[s],
					     seed_buf[s], seed_len[s], out_a,
					     seed_unc[s], &p);
			rounds_done++;
			if (st != KOF_DEC_OK)
				fail(r, "a real, untouched block did not decode");
			else if (p != seed_unc[s])
				fail(r, "a real block decoded to the wrong length");
			else
				by_status[KOF_DEC_OK]++;
		}
		return;
	}

	if (seeds && (r % 3) != 2) {
		/* Corrupt a real block: the type of round that reaches the states
		 * random input reaches only by accident. */
		uint32_t s = (uint32_t)(rnd() % seeds), k, hits;

		n = seed_len[s];
		memcpy(in, seed_buf[s], n);
		variant = seed_variant[s];
		bits = seed_bits[s];
		hits = 1 + (uint32_t)(rnd() % 6);
		for (k = 0; k < hits; k++) {
			/* A quarter aimed at the first bytes: the bit reader's
			 * first refill decides how everything after it is framed. */
			uint32_t at = (rnd() % 4) ? (uint32_t)(rnd() % n)
						  : (uint32_t)(rnd() % (n < 16 ? n : 16));
			in[at] ^= (uint8_t)(1u << (rnd() % 8));
		}
		if (rnd() % 4 == 0)
			n = 1 + (uint32_t)(rnd() % n);   /* and truncated */
	} else {
		n = 1 + (uint32_t)(rnd() % 512);
		for (i = 0; i < n; i++)
			in[i] = (uint8_t)rnd();
		variant = (int)(rnd() % 3);
		bits = (int)((rnd() % 3) == 0 ? 8 : (rnd() % 2 ? 16 : 32));
	}

	/* Buffers of every scale, including ones far too small: where the receiver's
	 * limit lands is the caller's business and must not corrupt anything. */
	switch (rnd() % 4) {
	case 0:  cap = 1 + rnd() % 64;      break;
	case 1:  cap = 1 + rnd() % 4096;    break;
	case 2:  cap = 1 + rnd() % 65536;   break;
	default: cap = OUT_CAP;             break;
	}

	memset(out_a, MARKER, cap);
	sa = kof_nrv2_decode(variant, bits, in, n, out_a, cap, &pa);
	rounds_done++;

	if (sa < 0 || sa > KOF_DEC_CORRUPT) {
		fail(r, "status is not one the decoder defines");
		return;
	}
	by_status[sa]++;

	if (pa > cap) {
		fail(r, "produced more than the buffer holds");
		return;
	}
	/* Nothing past what it says it produced may have been touched. */
	for (i = pa; i < cap; i++)
		if (out_a[i] != MARKER) {
			fail(r, "wrote past the end of what it produced");
			return;
		}

	/* Twice, into a different buffer: no state may carry between streams. */
	memset(out_b, MARKER ^ 0xff, cap);
	sb = kof_nrv2_decode(variant, bits, in, n, out_b, cap, &pb);
	if (sa != sb || pa != pb || (pa && memcmp(out_a, out_b, (size_t)pa) != 0)) {
		fail(r, "the same stream decoded differently the second time");
		return;
	}

	/*
	 * A smaller buffer must yield a prefix of the same bytes.
	 *
	 * This is the property the engine leans on when a budget cuts a decode
	 * short: what was produced before the limit has to be what would have been
	 * produced without it, or an object scanned under one limit differs from
	 * the same object scanned under another.
	 */
	if (pa > 1) {
		uint64_t small = pa / 2, pc = 0;

		memset(out_b, MARKER ^ 0xff, small);
		kof_nrv2_decode(variant, bits, in, n, out_b, small, &pc);
		if (pc > small) {
			fail(r, "the smaller decode overran its buffer");
			return;
		}
		if (pc && memcmp(out_a, out_b, (size_t)pc) != 0)
			fail(r, "a smaller buffer changed the bytes decoded");
	}
}

int main(int argc, char **argv)
{
	static const char *corpora[] = {
		"/mnt/games/virus_share/VirusShare_Linux_20160715",
		"tests/UPX_FILES"
	};
	uint64_t rounds = 20000, r;
	int i;

	if (argc > 1)
		rng_state = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);
	if (!rng_state)
		rng_state = 1;

	if (argc > 3)
		for (i = 3; i < argc; i++)
			harvest_dir(argv[i]);
	else
		for (i = 0; i < (int)(sizeof corpora / sizeof corpora[0]); i++)
			harvest_dir(corpora[i]);

	/*
	 * A stream of zero bits, which asks the prefix accumulator to double for
	 * ever.
	 *
	 * The only input that reaches the overflow guard, and the reason it is a
	 * case of its own: the guard turns a runaway accumulator into CORRUPT, and
	 * without it the loop simply runs until the input is exhausted and reports
	 * TRUNCATED - a difference no random round asserts on, so removing the
	 * guard passed twenty thousand rounds unnoticed.
	 */
	{
		static uint8_t zeros[512];
		int v;

		for (v = 0; v < 3; v++) {
			uint64_t p = 0;
			int st = kof_nrv2_decode(v, 32, zeros, sizeof zeros,
						 out_a, OUT_CAP, &p);

			if (st != KOF_DEC_CORRUPT)
				fail(0, "a runaway prefix was not refused as "
					"corrupt");
		}
	}

	for (r = 0; r < rounds && failures == 0; r++)
		one(r);

	printf("nrv2 fuzz: %llu round(s), %llu real seed(s); ok %llu stopped %llu "
	       "truncated %llu corrupt %llu\n",
	       (unsigned long long)rounds_done, (unsigned long long)seeds,
	       (unsigned long long)by_status[KOF_DEC_OK],
	       (unsigned long long)by_status[KOF_DEC_STOPPED],
	       (unsigned long long)by_status[KOF_DEC_TRUNCATED],
	       (unsigned long long)by_status[KOF_DEC_CORRUPT]);
	return failures != 0;
}
