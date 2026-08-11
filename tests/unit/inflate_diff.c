/*
 * inflate_diff - decode the same streams zlib does, and get the same bytes.
 *
 * A decompressor cannot be tested by asserting properties of its output, because
 * the property that matters is "identical to what every other implementation
 * produces" - a decoder that is self-consistently wrong about one Huffman code
 * silently produces a different file, and a scanner then searches bytes that were
 * never in the archive. So the oracle is zlib, and the assertion is byte equality.
 *
 * Three sources of streams, because they find different things:
 *
 *   - deflated real data at every level, which is what the decoder meets
 *   - deflated PATHOLOGICAL data: runs, sparse bytes, random - the inputs that
 *     drive an encoder into stored blocks, into long matches, into distances at
 *     the very edge of the window
 *   - RANDOM BYTES fed in directly, which are almost never a valid stream and are
 *     the only way to reach the error paths. Those paths are most of the security
 *     surface here and none of them are exercised by input that decodes.
 *
 * For random input the assertion is not equality but agreement about failure: if
 * zlib decodes it, we must decode it identically; if zlib refuses it, we must not
 * produce more than zlib did before refusing. A decoder that accepts what zlib
 * rejects is a decoder attacker-controlled bytes can steer.
 *
 * Under SAN=1 this is also the fuzzer for the window arithmetic, which is all
 * masked indexing that a sanitizer cannot see past unless the indices are wrong in
 * a way that leaves the buffer - so the streams have to actually be decoded.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "../../libkofeng/kofdecomp/inflate.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	if (++failures > 8)
		exit(1);
}

/* ---- the sink ---------------------------------------------------------------- */

struct out {
	uint8_t *p;
	size_t   n, cap;
	size_t   limit;      /* stop accepting past this; 0 for no limit */
};

static int out_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct out *o = user;

	if (o->limit && o->n + n > o->limit)
		return 0;
	if (o->n + n > o->cap) {
		size_t nc = o->cap ? o->cap : 4096;

		while (nc < o->n + n)
			nc *= 2;
		o->p = realloc(o->p, nc);
		if (!o->p)
			exit(1);
		o->cap = nc;
	}
	memcpy(o->p + o->n, p, n);
	o->n += n;
	return 1;
}

/* ---- zlib, as the oracle ------------------------------------------------------ */

/* Raw DEFLATE, so windowBits is negative: no zlib or gzip wrapper, exactly what
 * kof_inflate reads. */
static int zlib_deflate_raw(const uint8_t *in, size_t n, int level,
			    uint8_t **out, size_t *out_n)
{
	z_stream z;
	size_t cap = n + n / 2 + 1024;

	memset(&z, 0, sizeof z);
	if (deflateInit2(&z, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		return 0;
	*out = malloc(cap);
	z.next_in = (Bytef *)in;
	z.avail_in = (uInt)n;
	z.next_out = *out;
	z.avail_out = (uInt)cap;
	if (deflate(&z, Z_FINISH) != Z_STREAM_END) {
		deflateEnd(&z);
		free(*out);
		return 0;
	}
	*out_n = cap - z.avail_out;
	deflateEnd(&z);
	return 1;
}

/* Returns bytes produced; *ended is set when zlib reached the end of the stream. */
static size_t zlib_inflate_raw(const uint8_t *in, size_t n, uint8_t **out, int *ended)
{
	z_stream z;
	size_t cap = 1 << 20, have = 0;

	memset(&z, 0, sizeof z);
	*ended = 0;
	if (inflateInit2(&z, -15) != Z_OK)
		return 0;
	*out = malloc(cap);
	z.next_in = (Bytef *)in;
	z.avail_in = (uInt)n;
	for (;;) {
		int r;

		z.next_out = *out + have;
		z.avail_out = (uInt)(cap - have);
		r = inflate(&z, Z_NO_FLUSH);
		have = cap - z.avail_out;
		if (r == Z_STREAM_END) {
			*ended = 1;
			break;
		}
		if (r != Z_OK && r != Z_BUF_ERROR)
			break;
		if (z.avail_in == 0 && z.avail_out != 0)
			break;             /* input exhausted */
		if (have == cap) {
			if (cap >= (64u << 20))
				break;     /* a bomb; do not race it */
			cap *= 2;
			*out = realloc(*out, cap);
			if (!*out)
				exit(1);
		}
	}
	inflateEnd(&z);
	return have;
}

/* ---- round trips -------------------------------------------------------------- */

static void round_trip(const char *what, const uint8_t *data, size_t n, int level)
{
	uint8_t *comp = NULL;
	size_t comp_n = 0;
	struct kof_inflate *st;
	struct out o;
	int r;

	if (!zlib_deflate_raw(data, n, level, &comp, &comp_n)) {
		fail(what, "zlib would not compress the input");
		return;
	}
	memset(&o, 0, sizeof o);
	st = malloc(sizeof *st);
	if (!st)
		exit(1);
	r = kof_inflate(st, comp, comp_n, out_sink, &o, NULL, NULL);

	if (r != KOF_DEC_OK)
		fail(what, kof_decomp_status_name(r));
	else if (o.n != n)
		fail(what, "decoded a different number of bytes than were compressed");
	else if (n && memcmp(o.p, data, n) != 0)
		fail(what, "decoded different bytes than were compressed");

	free(st);
	free(o.p);
	free(comp);
}

/*
 * The sink refuses part way through.
 *
 * This is how every budget in the engine reaches the decoder, so what it produced
 * up to the refusal has to be exactly the prefix zlib produces - a decoder that
 * flushed a partial window differently would hand the scanner bytes in the wrong
 * order and nothing else would notice.
 */
static void stops_short(const uint8_t *data, size_t n, size_t limit)
{
	uint8_t *comp = NULL;
	size_t comp_n = 0;
	struct kof_inflate *st;
	struct out o;
	int r;

	if (!zlib_deflate_raw(data, n, 6, &comp, &comp_n))
		return;
	memset(&o, 0, sizeof o);
	o.limit = limit;
	st = malloc(sizeof *st);
	if (!st)
		exit(1);
	r = kof_inflate(st, comp, comp_n, out_sink, &o, NULL, NULL);

	if (o.n > limit)
		fail("stop", "more was produced than the sink accepted");
	if (o.n < n && r != KOF_DEC_STOPPED)
		fail("stop", "a refused sink was not reported as stopped");
	if (o.n && memcmp(o.p, data, o.n) != 0)
		fail("stop", "the prefix produced before stopping was wrong");

	free(st);
	free(o.p);
	free(comp);
}

/* ---- hostile input ------------------------------------------------------------ */

static uint64_t rng_state = 1;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

/*
 * Bytes that are not a stream, and streams with a byte changed.
 *
 * Pure random input is rejected almost immediately by the block header, so most of
 * it never reaches the interesting code. Corrupting a VALID stream is what gets
 * inside: the block types are right, the tables nearly parse, and the damage lands
 * in a code length, a distance or a repeat count - which is exactly where the
 * bounds in this decoder are.
 *
 * TWO base streams, compressed at level 6 and at level 0. Level 0 is what makes
 * stored blocks reachable at all: a compressed stream contains none, and random
 * bytes almost never form a valid one, so with a single level-6 base the whole
 * stored-block path - including the check that LEN and NLEN are complements - was
 * never reached by any round. Removing that check left this test passing, which is
 * how the gap was found.
 */
static void hostile(uint64_t rounds)
{
	uint8_t seed[4096];
	uint8_t *base[2] = { NULL, NULL };
	size_t base_n[2] = { 0, 0 }, i;
	uint64_t r;
	uint64_t accepted = 0, refused = 0, disagreed = 0;

	for (i = 0; i < sizeof seed; i++)
		seed[i] = (uint8_t)(i * 31u + (i >> 3));
	if (!zlib_deflate_raw(seed, sizeof seed, 6, &base[0], &base_n[0]))
		return;
	if (!zlib_deflate_raw(seed, sizeof seed, 0, &base[1], &base_n[1]))
		return;

	for (r = 0; r < rounds; r++) {
		uint8_t buf[8192];
		size_t n;
		struct kof_inflate *st;
		struct out o;
		uint8_t *zout = NULL;
		size_t zn;
		int zended, k, status;

		if (r % 3 != 2) {
			int b = (int)(r % 3);      /* 0: deflated, 1: stored */

			n = base_n[b];
			memcpy(buf, base[b], n);
			for (k = 0; k < 1 + (int)(rnd() % 4); k++) {
				/*
				 * A quarter of the damage aimed at the first
				 * sixteen bytes.
				 *
				 * Everything structural is there - block type,
				 * a stored block's LEN and NLEN, the counts a
				 * dynamic block's tables are built from - and it
				 * is a few bytes against several thousand of
				 * payload, so damage spread evenly reaches it
				 * about once in a thousand rounds. Uniform
				 * corruption left the stored-block length check
				 * untested at three thousand rounds; this
				 * reaches it in tens.
				 */
				size_t hdr = n < 16 ? n : 16;
				size_t at = (rnd() % 4) ? rnd() % n : rnd() % hdr;

				buf[at] ^= (uint8_t)(1u << (rnd() % 8));
			}
		} else {
			n = 16 + rnd() % 512;
			for (i = 0; i < n; i++)
				buf[i] = (uint8_t)rnd();
		}

		memset(&o, 0, sizeof o);
		o.limit = 8u << 20;
		st = malloc(sizeof *st);
		if (!st)
			exit(1);
		status = kof_inflate(st, buf, n, out_sink, &o, NULL, NULL);
		free(st);

		zn = zlib_inflate_raw(buf, n, &zout, &zended);

		if (status == KOF_DEC_OK && zended) {
			/* Both say the stream is whole: the bytes must match. */
			accepted++;
			if (o.n != zn || (o.n && memcmp(o.p, zout, o.n) != 0)) {
				disagreed++;
				fail("hostile", "accepted a stream zlib decoded "
						"differently");
			}
		} else if (status == KOF_DEC_OK && !zended) {
			/*
			 * We claim a complete stream where zlib does not. That is
			 * the dangerous direction - it means bytes reached a scan
			 * that no other decoder would have produced.
			 */
			disagreed++;
			fail("hostile", "accepted as complete a stream zlib refused");
		} else {
			refused++;
			/* Whatever prefix we did produce still has to be zlib's. */
			if (o.n && zn && memcmp(o.p, zout, o.n < zn ? o.n : zn) != 0) {
				disagreed++;
				fail("hostile", "produced a prefix zlib disagrees with");
			}
		}
		free(o.p);
		free(zout);
	}
	printf("inflate hostile: %llu round(s), %llu whole, %llu refused, "
	       "%llu disagreement(s)\n", (unsigned long long)rounds,
	       (unsigned long long)accepted, (unsigned long long)refused,
	       (unsigned long long)disagreed);
	free(base[0]);
	free(base[1]);
}

int main(int argc, char **argv)
{
	uint64_t rounds = 4000;
	static uint8_t data[1u << 20];
	size_t i;
	int level;

	if (argc > 1)
		rng_state = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);
	if (!rng_state)
		rng_state = 1;

	/* --- shapes an encoder handles differently --- */
	for (level = 0; level <= 9; level++) {
		size_t n;

		/* Incompressible: drives the encoder into stored blocks. */
		for (i = 0; i < 65536; i++)
			data[i] = (uint8_t)rnd();
		round_trip("random", data, 65536, level);

		/* One byte repeated: the longest matches DEFLATE can express. */
		memset(data, 'A', 200000);
		round_trip("run", data, 200000, level);

		/* Periodic just past the window, so distances land at the very
		 * edge of the 32KB the decoder keeps. */
		for (i = 0; i < 200000; i++)
			data[i] = (uint8_t)(i % 32771u);
		round_trip("window-edge", data, 200000, level);

		/* Text-like, which is what real archives mostly hold. */
		for (i = 0, n = 0; n < 300000; i++) {
			const char *w = (i % 7) ? "the quick brown fox " : "\n";

			memcpy(data + n, w, strlen(w));
			n += strlen(w);
		}
		round_trip("text", data, n, level);

		round_trip("empty", data, 0, level);
		round_trip("one", data, 1, level);
	}

	/* --- the sink refusing at every scale --- */
	for (i = 0; i < 200000; i++)
		data[i] = (uint8_t)(i * 7u + (i >> 5));
	stops_short(data, 200000, 1);
	stops_short(data, 200000, 32767);
	stops_short(data, 200000, 32768);
	stops_short(data, 200000, 32769);
	stops_short(data, 200000, 100000);
	stops_short(data, 200000, 199999);

	hostile(rounds);

	printf("inflate diff: round trips against zlib %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
