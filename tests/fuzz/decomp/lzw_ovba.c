/*
 * decomp/lzw_ovba - the two small streaming decoders: kuncoat_lzw_decode (LZW as PDF and TIFF write it: MSB-first codes, early
 * change) and kuncoat_ovba_decode / kuncoat_ovba_plausible (the MS-OVBA CompressedContainer of an Office macro).
 *
 * Seeds are made by the writers of tests/lib/uncoat/hostile_enc.h (hv_lzw_enc, hv_ovba_enc) from plain texts built here: text, a
 * long run that fills the table past its clear code, noise (stored OVBA chunks), a short text, empty. A seed must give its plain
 * text exactly (the oracle of a decoder that has an encoder here). Held for every input: the status is in the enum; produced >=
 * what the sink took; the sink is not called again after a refusal; a refusing sink ends in STOPPED; a stream that ends OK under
 * OVBA is also "plausible" when it made output (the pre-test must not refuse what the decoder accepts: the container begins with its
 * signature byte and a first chunk header that agrees with itself).
 */
#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"

#define PL 22000u

static uint8_t plain[4][PL];
static struct dc_plain pl_lzw[8], pl_ovba[8];
static size_t n_lzw, n_ovba;
static struct kuncoat_lzw lzw_st;

static void make_plain(void)
{
	uint64_t rs = 0x5eed5u;
	size_t i;

	for (i = 0; i < PL; i++) {
		plain[0][i] = (uint8_t)(size_t)"Sub AutoOpen() CreateObject(\"Wscript.Shell\").Run cmd End Sub\r\n"[i % 62];
		plain[1][i] = 'A';
		plain[2][i] = (uint8_t)(fz_rng_star(&rs) >> 41);
		plain[3][i] = (uint8_t)(i % 251u);
	}
}

static void add(struct fz_corpus *c, const char *name, const uint8_t *z, size_t zn, const uint8_t *p, size_t pn, struct dc_plain *pl, size_t *np)
{
	pl[*np].p = p;
	pl[*np].n = pn;
	(*np)++;
	fz_corpus_add(c, name, z, zn);
}

static int sink_checks(struct fz_ctx *c, enum kuncoat_status r, uint64_t produced, const struct dc_plain *pl, size_t np)
{
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, produced >= c->sink.total, "sink took more than the decoder says it produced");
	/* F-LZW-1: a refusing sink ends in STOPPED, or in the stream's own failure when the stream was found broken in the same flush the sink
	 * refused: the failure wins (lzw: the reproducer findings/lzw_refused_final_flush_reports_corrupt.bin under an always refusing
	 * sink gives CORRUPT; lzx documents the same precedence). Held: nothing else, and never OK. */
	FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED || r == KUNCOAT_CORRUPT || r == KUNCOAT_TRUNCATED, "a refusing sink did not end in STOPPED (or the stream's own failure)");
#ifdef DECOMP_CLASSIFY
	if (c->refused && r != KUNCOAT_STOPPED)
		fprintf(stderr, "classify sink: refused but %s, iter %u produced %llu total %llu cap %zu\n", kuncoat_status_name(r), c->iter,
			(unsigned long long)produced, (unsigned long long)c->sink.total, c->cap);
#endif
	if (!c->failk && c->iter < np && pl[c->iter].p) {
		uint64_t k = c->sink.total;

		FZ_CHECK(c, k <= pl[c->iter].n && !memcmp(c->out, pl[c->iter].p, (size_t)(k < pl[c->iter].n ? k : pl[c->iter].n)),
			 "a good stream gave bytes that are not its plain text");
		if (!c->refused)
			FZ_CHECK(c, r == KUNCOAT_OK && k == pl[c->iter].n, "a good stream was not decoded whole");
	}
	fz_digest(c, (uint64_t)r ^ produced << 3 ^ dc_hash(c->out, c->sink.total) << 17);
	return (int)r;
}

/* ---- lzw ---------------------------------------------------------------------------------------- */

static void lzw_seeds(struct fz_corpus *c)
{
	static uint8_t z[PL * 2u];
	size_t zn;

	make_plain();
	n_lzw = 0;
	zn = hv_lzw_enc(plain[0], 2000, z, sizeof z);
	add(c, "text", z, zn, plain[0], 2000, pl_lzw, &n_lzw);
	zn = hv_lzw_enc(plain[1], 20000, z, sizeof z);
	add(c, "run-clears-table", z, zn, plain[1], 20000, pl_lzw, &n_lzw);
	zn = hv_lzw_enc(plain[2], 6000, z, sizeof z);
	add(c, "noise", z, zn, plain[2], 6000, pl_lzw, &n_lzw);
	zn = hv_lzw_enc(plain[3], 12000, z, sizeof z);
	add(c, "periodic", z, zn, plain[3], 12000, pl_lzw, &n_lzw);
	zn = hv_lzw_enc(plain[0], 1, z, sizeof z);
	add(c, "one-byte", z, zn, plain[0], 1, pl_lzw, &n_lzw);
	zn = hv_lzw_enc(plain[0], 0, z, sizeof z);
	add(c, "empty", z, zn, plain[0], 0, pl_lzw, &n_lzw);
}

static const char *const lzw_dict[] = { "\x80\x0b", "\x80\x00", "\x40", "\x20", "\x10", "\x08", NULL };

static int lzw_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced = 0;
	enum kuncoat_status r = kuncoat_lzw_decode(&lzw_st, in, n, c->sink_fn, c->sink_user, &produced);

	return sink_checks(c, r, produced, pl_lzw, n_lzw);
}

FZ_ADAPTER(lzw, .name = "kuncoat/lzw", .covers = "kuncoat_lzw_decode", .shape = FZ_BYTES, .seeds = lzw_seeds, .dict = lzw_dict, .run = lzw_run);

/* ---- ovba --------------------------------------------------------------------------------------- */

static void ovba_seeds(struct fz_corpus *c)
{
	static uint8_t z[PL * 2u];
	size_t zn;

	make_plain();
	n_ovba = 0;
	zn = hv_ovba_enc(plain[0], 3000, z, sizeof z);
	add(c, "text", z, zn, plain[0], 3000, pl_ovba, &n_ovba);
	zn = hv_ovba_enc(plain[0], 9000, z, sizeof z);
	add(c, "text-3-chunks", z, zn, plain[0], 9000, pl_ovba, &n_ovba);
	/* noise is stored: a raw chunk of 4096 (the compressing writer would overrun a chunk's 4095 bytes on noise), then a compressed one */
	z[0] = 1;
	zn = 1u + hv_ovba_chunk(plain[2], 4096, z + 1, sizeof z - 1u, 1);
	add(c, "noise-raw-chunk", z, zn, plain[2], 4096, pl_ovba, &n_ovba);
	zn = hv_ovba_enc(plain[1], 4096, z, sizeof z);
	add(c, "run", z, zn, plain[1], 4096, pl_ovba, &n_ovba);
	zn = hv_ovba_enc(plain[3], 10, z, sizeof z);
	add(c, "short", z, zn, plain[3], 10, pl_ovba, &n_ovba);
}

static const char *const ovba_dict[] = { "\x01", "\x01\x2f\xb0", "\x01\x00\x30", NULL };

static int ovba_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced = 0;
	int pl = kuncoat_ovba_plausible(in, n);
	enum kuncoat_status r = kuncoat_ovba_decode(in, n, c->sink_fn, c->sink_user, &produced);

	if (r == KUNCOAT_OK && produced)
		FZ_CHECK(c, pl, "the plausibility pre-test refuses a container the decoder decodes whole");
	fz_digest(c, (uint64_t)pl << 56);
	return sink_checks(c, r, produced, pl_ovba, n_ovba);
}

FZ_ADAPTER(ovba, .name = "kuncoat/ovba", .covers = "kuncoat_ovba_decode kuncoat_ovba_plausible", .shape = FZ_BYTES, .seeds = ovba_seeds, .dict = ovba_dict,
	   .run = ovba_run);
