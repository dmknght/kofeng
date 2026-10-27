/*
 * decomp/bunzip - kuncoat_bunzip_decode and kuncoat_bunzip_sniff against libbz2 as the oracle (the library the bzip2 tool and
 * Python's bz2 module are built on; it is linked here the way zlib is for the inflate row).
 *
 * Seeds are made by libbz2 at run time from plain texts built here (a repetitive text, a run of one byte that exercises the
 * first run-length stage, pseudo-random bytes, an empty stream, two streams in a row, block sizes 1 and 9): no blob is
 * stored. Held: the status is one of the enum, produced >= what the sink took, a refusing sink ends in STOPPED, the sink is
 * not called again after a refusal, a seed gives exactly its plain text, and when the stream decodes to the end and nothing
 * refused, libbz2 (following concatenated streams as the tool does) decodes the same bytes. A refusal by kuncoat of a stream
 * libbz2 accepts completely is held against the decoder unless it says UNSUPPORTED (a randomised block, which libbz2 still
 * carries). kuncoat OK where libbz2 errors is LENIENT and is not held (the classification is printed when this file is
 * compiled with -DDECOMP_CLASSIFY).
 */
#include <bzlib.h>
#include <stdio.h>

#include "decomp_common.h"

#define PLAIN_MAX 40000u

static struct kuncoat_bunzip st;
static uint8_t plain_buf[8][PLAIN_MAX];
static struct dc_plain plains[16];
static size_t n_plains;
static uint8_t flip_ok[16];      /* the seed is ONE stream (no second header for a flipped bit to hide, no trailing bytes to ignore) */

static size_t bz_pack(uint8_t *dst, size_t cap, const uint8_t *src, size_t n, int level)
{
	unsigned int dl = (unsigned int)cap;

	if (BZ2_bzBuffToBuffCompress((char *)dst, &dl, (char *)(uintptr_t)src, (unsigned int)n, level, 0, 0) != BZ_OK)
		return 0;
	return dl;
}

static void add_seed(struct fz_corpus *c, const char *name, const uint8_t *in, size_t n, const uint8_t *plain, size_t pn, int single)
{
	if (n_plains < 16 && fz_corpus_add(c, name, in, n)) {
		flip_ok[n_plains] = (uint8_t)single;
		plains[n_plains].p = plain;
		plains[n_plains].n = pn;
		n_plains++;
	}
}

static void seeds(struct fz_corpus *c)
{
	static uint8_t z[PLAIN_MAX * 2u + 1024u];
	uint64_t rs = 0x1234567u;
	size_t i, zn, zn2;

	n_plains = 0;
	for (i = 0; i < PLAIN_MAX; i++) {
		plain_buf[0][i] = (uint8_t)(size_t)"the quick brown fox jumps over the lazy dog. "[i % 45];   /* text */
		plain_buf[1][i] = 0x41;                                                                     /* one run: the first RLE stage */
		plain_buf[2][i] = (uint8_t)(fz_rng_star(&rs) >> 40);                                       /* noise */
		plain_buf[3][i] = (uint8_t)((size_t)"aaaabbbbbbbbbbbbbbbbbbbbbbbbbbbcdddd"[i % 37] + i / 700u);      /* runs of 4..N, varying */
	}
	zn = bz_pack(z, sizeof z, plain_buf[0], 12000, 9);
	add_seed(c, "text-9", z, zn, plain_buf[0], 12000, 1);
	zn = bz_pack(z, sizeof z, plain_buf[0], 3000, 1);
	add_seed(c, "text-1", z, zn, plain_buf[0], 3000, 1);
	zn = bz_pack(z, sizeof z, plain_buf[1], PLAIN_MAX, 9);
	add_seed(c, "run", z, zn, plain_buf[1], PLAIN_MAX, 1);
	zn = bz_pack(z, sizeof z, plain_buf[2], 5000, 2);
	add_seed(c, "noise", z, zn, plain_buf[2], 5000, 1);
	zn = bz_pack(z, sizeof z, plain_buf[3], 9000, 1);
	add_seed(c, "runs", z, zn, plain_buf[3], 9000, 1);
	zn = bz_pack(z, sizeof z, plain_buf[0], 0, 5);
	add_seed(c, "empty", z, zn, plain_buf[0], 0, 1);
	/* two streams in a row: the plain text is the concatenation */
	zn = bz_pack(z, 4000, plain_buf[0], 700, 3);
	zn2 = bz_pack(z + zn, 4000, plain_buf[3], 900, 3);
	memcpy(plain_buf[4], plain_buf[0], 700);
	memcpy(plain_buf[4] + 700, plain_buf[3], 900);
	add_seed(c, "two-streams", z, zn + zn2, plain_buf[4], 1600, 0);
	/* one stream, then bytes that do not begin another: ignored */
	zn = bz_pack(z, 4000, plain_buf[0], 400, 3);
	memset(z + zn, 'x', 9);
	add_seed(c, "trailing", z, zn + 9u, plain_buf[0], 400, 0);
}

static const char *const dict[] = { "BZh", "BZh9", "BZh1", "\x31\x41\x59\x26\x53\x59", "\x17\x72\x45\x38\x50\x90", NULL };

enum { O_BAD = 0, O_OK = 1, O_OVER = 2 };

/* libbz2 over the whole input, following concatenated streams; the output must fit in `cap` bytes. */
static int oracle(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *got, int *strict_end)
{
	size_t at = 0, o = 0;
	int streams = 0;

	*strict_end = 1;
	while (at < n) {
		bz_stream s;
		int r;

		memset(&s, 0, sizeof s);
		if (BZ2_bzDecompressInit(&s, 0, 0) != BZ_OK)
			return O_BAD;
		s.next_in = (char *)(uintptr_t)(in + at);
		s.avail_in = (unsigned int)(n - at);
		for (;;) {
			s.next_out = (char *)out + o;
			s.avail_out = (unsigned int)(cap - o);
			r = BZ2_bzDecompress(&s);
			o = cap - s.avail_out;
			if (r != BZ_OK)
				break;
			if (s.avail_out == 0)
				return BZ2_bzDecompressEnd(&s), O_OVER;
			if (s.avail_in == 0)
				break;
		}
		at = n - s.avail_in;
		BZ2_bzDecompressEnd(&s);
		if (r != BZ_STREAM_END) {
			*got = o;
			*strict_end = 0;                   /* a broken later stream ends the output: the file is not whole */
			return streams ? O_OK : O_BAD;     /* the first stream must be whole */
		}
		streams++;
		if (n - at < 4 || memcmp(in + at, "BZh", 3)) {
			*got = o;
			*strict_end = at == n;
			return O_OK;
		}
	}
	*got = o;
	return streams ? O_OK : O_BAD;
}

struct cmp_sink {
	const uint8_t *want;
	size_t         n;
	uint64_t       at;
	int            bad;
};

/* A receiver that compares what it is handed with the plain text. */
static int cmp_sink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct cmp_sink *s = (struct cmp_sink *)u;

	if (s->at + n > s->n || memcmp(s->want + s->at, p, n))
		s->bad = 1;
	s->at += n;
	return 1;
}

/*
 * What the CRCs are for, held on the SEEDS (their plain text is known): a single bit flipped in the compressed payload either breaks
 * the structure (an error status) or changes the data, and then the block CRC must refuse it: a decode that says OK is the plain text
 * and nothing else. 32 flips of the payload per seed, positions drawn from the iteration's generator, plus every bit of the block
 * CRC field (bytes 10..13 of the stream), which the combined CRC at the end also covers: those must be refused too. A decoder that
 * stops checking the block CRC answers OK with different bytes here and is caught (the mutant in tests_wp5/mutants.txt).
 */
static void crc_flips(struct fz_ctx *c, const uint8_t *in, size_t n, const struct dc_plain *w)
{
	static uint8_t m[40000];
	unsigned k;

	if (n < 24 || n > sizeof m || memcmp(in, "BZh", 3))
		return;
	for (k = 0; k < 64; k++) {
		struct cmp_sink cs;
		uint64_t p = 0;
		enum kuncoat_status r;
		size_t byte = k < 32 ? 10u + k / 8u : 14u + (size_t)fz_below(c->rng, n - 14u - 4u);
		unsigned bit = k < 32 ? k & 7u : (unsigned)fz_below(c->rng, 8);

		memcpy(m, in, n);
		m[byte] ^= (uint8_t)(0x80u >> bit);
		cs.want = w->p;
		cs.n = w->n;
		cs.at = 0;
		cs.bad = 0;
		r = kuncoat_bunzip_decode(&st, m, n, cmp_sink_fn, &cs, &p);
		if (k < 32)
			FZ_CHECK(c, r == KUNCOAT_CORRUPT, "a flipped bit of the block CRC was not refused");
		else if (r == KUNCOAT_OK)
			FZ_CHECK(c, !cs.bad && cs.at == w->n, "a flipped payload bit decoded OK to different bytes (the block CRC did not refuse it)");
	}
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	enum kuncoat_status r;
	uint64_t produced = 0;
	int sn = kuncoat_bunzip_sniff(in, n);

	r = kuncoat_bunzip_decode(&st, in, n, c->sink_fn, c->sink_user, &produced);
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, produced >= c->sink.total, "sink took more than the decoder says it produced");
	FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED, "a refusing sink did not end in STOPPED");
	if (!c->failk && c->iter < n_plains && plains[c->iter].p) {
		const struct dc_plain *w = &plains[c->iter];

		if (flip_ok[c->iter])
			crc_flips(c, in, n, w);

		FZ_CHECK(c, c->sink.total <= w->n && !memcmp(c->out, w->p, (size_t)(c->sink.total < w->n ? c->sink.total : w->n)),
			 "a good stream gave bytes that are not its plain text");
		if (!c->refused)
			FZ_CHECK(c, r == KUNCOAT_OK && c->sink.total == w->n, "a good stream was not decoded whole");
		FZ_CHECK(c, sn, "the sniff refused a stream libbz2 wrote");
	}
	if (!c->failk && !c->refused) {
		size_t room = (size_t)c->sink.total + 1u, got = 0;
		uint8_t *o = (uint8_t *)malloc(room);
		int se = 1, ob;

		if (o) {
			ob = oracle(in, n, o, room, &got, &se);
			if (r == KUNCOAT_OK && ob == O_OK)
				FZ_CHECK(c, got == c->sink.total && !memcmp(o, c->out, got), "libbz2 decodes this stream to a different result");
			else if (r == KUNCOAT_OK && ob == O_OVER)
				FZ_CHECK(c, 0, "libbz2 decodes more than the decoder produced");
			else if (r != KUNCOAT_OK && r != KUNCOAT_UNSUPPORTED && ob == O_OK && se)
				FZ_CHECK(c, 0, "the decoder refused a stream libbz2 decodes completely");
#ifdef DECOMP_CLASSIFY
			if (r == KUNCOAT_OK && ob == O_BAD)
			{
				char nm[96];
				FILE *f;

				fprintf(stderr, "classify bunzip: LENIENT (kuncoat OK, libbz2 error) n=%zu iter %u\n", n, c->iter);
				snprintf(nm, sizeof nm, "build/fuzz/found/bunzip_lenient_%u.bin", c->iter);
				if ((f = fopen(nm, "wb"))) { fwrite(in, 1, n, f); fclose(f); }
			}
			else if (r != KUNCOAT_OK && ob == O_OK && se)
				fprintf(stderr, "classify bunzip: STRICT (kuncoat %s, libbz2 OK) n=%zu\n", kuncoat_status_name(r), n);
#endif
			fz_digest(c, (uint64_t)ob << 50);
			free(o);
		}
	}
	fz_digest(c, (uint64_t)r ^ produced << 3 ^ (uint64_t)sn << 61 ^ dc_hash(c->out, c->sink.total) << 17);
	return (int)r;
}

FZ_ADAPTER(bunzip, .name = "kuncoat/bunzip", .covers = "kuncoat_bunzip_decode kuncoat_bunzip_sniff", .shape = FZ_BYTES, .seeds = seeds,
	   .dict = dict, .run = run, .steps_base = 4000000u);
