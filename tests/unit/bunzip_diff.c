/*
 * bunzip_diff - decode what bzip2 itself produced, and get the same bytes back.
 *
 * The oracle is the tool. tests/mkfixtures.sh compresses sample.tar with the
 * real bzip2, so the assertion here is byte equality against the input that
 * went in - which is the only assertion worth making about a decompressor. A
 * decoder that is self-consistently wrong about one Huffman table produces a
 * different file and nothing complains; the scan then searches bytes that were
 * never in the archive.
 *
 * WITHOUT THE FIXTURE THIS TEST REPORTS THAT IT DID NOTHING, rather than
 * passing. A missing fixture is a machine without bzip2 installed, which is a
 * gap in coverage and not a result - see mkfixtures.sh for why every skipped
 * fixture is printed.
 *
 * The rest is the part that matters for a scanner: what the decoder does with
 * input it was not given by a friendly tool. Truncation at every length, a bit
 * flipped at many positions, a sink that refuses - none of them may crash, none
 * may report OK, and none may hand back bytes that differ from the real output
 * while claiming success.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/extractor/decomp/bzip2.h"

static int failures;
static int checks;

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
	size_t   limit;         /* refuse past this; 0 for no limit */
};

static int out_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct out *o = user;

	if (o->limit && o->n + n > o->limit)
		return 0;
	if (o->n + n > o->cap) {
		size_t want = (o->n + n) * 2u + 4096u;
		uint8_t *q = realloc(o->p, want);

		if (!q)
			return 0;
		o->p = q;
		o->cap = want;
	}
	memcpy(o->p + o->n, p, n);
	o->n += n;
	return 1;
}

static uint8_t *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p;
	long n;

	*len = 0;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	p = malloc((size_t)n + 1u);
	if (!p) {
		fclose(f);
		return NULL;
	}
	if (n && fread(p, 1u, (size_t)n, f) != (size_t)n) {
		free(p);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return p;
}

static enum kof_decomp_status run(struct kof_bunzip *st, const uint8_t *in,
				  size_t n, struct out *o, uint64_t *got)
{
	o->n = 0;
	return kof_bunzip_decode(st, in, n, out_sink, o, got);
}

int main(void)
{
	static const char *bz_path  = "build/test/fixtures/sample.bz2";
	static const char *raw_path = "build/test/fixtures/sample.tar";
	struct kof_bunzip *st = malloc(sizeof *st);
	struct out o;
	uint8_t *bz = NULL, *raw = NULL;
	size_t bz_n = 0, raw_n = 0;
	uint64_t got = 0;

	if (!st) {
		printf("bunzip diff: out of memory\n");
		return 1;
	}
	memset(&o, 0, sizeof o);

	/*
	 * THE EMPTY STREAM, BUILT HERE, because it is the one stream a
	 * compressor rarely produces and a hand written file easily does: the
	 * four byte header, the end marker and a zero combined checksum. It has
	 * no blocks at all, so it exercises the loop's exit before its body.
	 */
	{
		static const uint8_t empty[] = {
			'B', 'Z', 'h', '9',
			0x17, 0x72, 0x45, 0x38, 0x50, 0x90,
			0x00, 0x00, 0x00, 0x00
		};
		enum kof_decomp_status s = run(st, empty, sizeof empty, &o, &got);

		checks++;
		if (s != KOF_DEC_OK || got != 0 || o.n != 0)
			fail("empty stream", "a header and an end marker is a "
			     "valid stream holding nothing");
		if (!kof_bunzip_sniff(empty, sizeof empty))
			fail("empty stream", "the sniff refused one");
	}

	/* Not bzip2 at all, in the shapes that are nearly it. */
	{
		static const uint8_t near1[] = "BZh0kofeng-not-a-stream";
		static const uint8_t near2[] = "BZh9kofeng-not-a-stream";
		static const uint8_t near3[] = "BZip2 is what this says";

		checks++;
		if (kof_bunzip_sniff(near1, sizeof near1 - 1u) ||
		    kof_bunzip_sniff(near2, sizeof near2 - 1u) ||
		    kof_bunzip_sniff(near3, sizeof near3 - 1u))
			fail("near misses", "four bytes of header is not a "
			     "stream without a block behind it");
		if (run(st, near2, sizeof near2 - 1u, &o, &got) != KOF_DEC_CORRUPT)
			fail("near misses", "a file that is not bzip2 decoded");
	}

	bz = slurp(bz_path, &bz_n);
	raw = slurp(raw_path, &raw_n);
	if (!bz || !raw || !bz_n || !raw_n) {
		free(bz);
		free(raw);
		free(o.p);
		free(st);
		printf("bunzip diff: %d check(s), NO FIXTURE - bzip2 was not "
		       "installed when the fixtures were built, so the decode "
		       "was not exercised against the tool\n", checks);
		return failures ? 1 : 0;
	}

	/* The whole point: what the tool compressed is what comes back. */
	{
		enum kof_decomp_status s = run(st, bz, bz_n, &o, &got);

		checks++;
		if (s != KOF_DEC_OK)
			fail("fixture", "a stream bzip2 wrote did not decode");
		else if (got != raw_n || o.n != raw_n ||
			 memcmp(o.p, raw, raw_n) != 0)
			fail("fixture", "decoded to different bytes than went in");
	}

	/*
	 * TWO STREAMS END TO END, which is what `bzip2 -c a b` writes and what
	 * every bzip2 reads whole. Stopping at the first end marker would drop
	 * the second file silently, which is the failure worth a test.
	 */
	{
		uint8_t *both = malloc(bz_n * 2u);

		checks++;
		if (both) {
			memcpy(both, bz, bz_n);
			memcpy(both + bz_n, bz, bz_n);
			if (run(st, both, bz_n * 2u, &o, &got) != KOF_DEC_OK ||
			    got != raw_n * 2u || o.n != raw_n * 2u ||
			    memcmp(o.p, raw, raw_n) != 0 ||
			    memcmp(o.p + raw_n, raw, raw_n) != 0)
				fail("concatenated", "the second stream was not "
				     "decoded, or not after the first");
			free(both);
		}
	}

	/*
	 * TRUNCATION AT EVERY LENGTH. A cut stream is the ordinary damaged
	 * archive, and the rule is the one inflate follows: whatever decoded
	 * before the input ran out is real output, the status says it did not
	 * finish, and nothing reads past the buffer - which is what the
	 * sanitised build of this test is actually checking.
	 */
	{
		size_t cut;

		checks++;
		for (cut = 1; cut < bz_n; cut += (bz_n / 97u) + 1u) {
			enum kof_decomp_status s = run(st, bz, cut, &o, &got);

			if (s == KOF_DEC_OK && cut < bz_n)
				fail("truncated", "a cut stream reported a "
				     "complete decode");
			if (o.n > raw_n)
				fail("truncated", "a cut stream produced more "
				     "than the whole one");
			if (o.n && memcmp(o.p, raw, o.n < raw_n ? o.n : raw_n) != 0) {
				/*
				 * Output before the cut must be a PREFIX of the
				 * real thing. A block is only handed on once it
				 * is whole, so a partial block produces nothing
				 * rather than something plausible.
				 */
				fail("truncated", "the bytes before the cut are "
				     "not the bytes that were there");
			}
		}
	}

	/*
	 * A SINGLE BIT FLIPPED. The block checksum is the only thing standing
	 * between a corrupted stream and confident wrong output, so this is the
	 * test that says the checksum is actually wired up: a flip that changes
	 * the data must never come back OK.
	 */
	{
		size_t at;

		checks++;
		for (at = 4; at < bz_n; at += (bz_n / 53u) + 1u) {
			enum kof_decomp_status s;

			bz[at] ^= 0x40u;
			s = run(st, bz, bz_n, &o, &got);
			bz[at] ^= 0x40u;

			if (s != KOF_DEC_OK)
				continue;      /* refused, which is the point */
			if (o.n != raw_n || memcmp(o.p, raw, raw_n) != 0)
				fail("bit flip", "a changed stream decoded to "
				     "changed bytes and reported success");
		}
	}

	/* A receiver that has had enough is not an error. */
	{
		enum kof_decomp_status s;

		checks++;
		o.limit = raw_n / 4u ? raw_n / 4u : 1u;
		s = run(st, bz, bz_n, &o, &got);
		o.limit = 0;
		if (s != KOF_DEC_STOPPED)
			fail("stopped", "a sink that refused more was not "
			     "reported as a stop");
	}

	free(bz);
	free(raw);
	free(o.p);
	free(st);

	if (failures) {
		printf("bunzip diff: %d check(s) failed\n", failures);
		return 1;
	}
	printf("bunzip diff: empty, near misses, fixture round trip, "
	       "concatenated, truncation, bit flips, stop - ok\n");
	return 0;
}
