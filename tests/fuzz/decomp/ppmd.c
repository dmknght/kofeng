/*
 * decomp/ppmd - the PPMd (variant H) model of ppmd.h, driven as a handle: kuncoat_ppmd_new, _arena_want, _start_asked, _next,
 * _at, _over, _resume and _free. Any byte string is a stream to a range decoder, so the seeds are text, noise, zeros and the
 * block header RAR writes ("a7 18": restart, order 8, 25 MB) and what is held is a property of the MODEL, not of an encoder:
 *
 *   - a symbol is 0..255 or -1; a call after -1 is safe (it does NOT stay at -1: finding F-PPMD-1, see step());
 *   - the cursor kuncoat_ppmd_at stays inside the input and never moves back;
 *   - the same input gives the same symbols (the driver runs every case twice) and the symbols of a CUT input are the
 *     beginning of the symbols of the whole input (the model is a function of its stream: cov_ppmd_roundtrip.c shows it with an
 *     encoder, this row shows it for every byte string);
 *   - kuncoat_ppmd_arena_want is (byte + 1) MB, not clamped; an order outside 2..64 or an arena outside 1 MB .. 256 MB is
 *     refused and nothing is decoded; a model that stopped on its arena allowance (over) answers -1.
 * Input layout: [max_order][arena byte][flags: bit 0 resume once at the cursor, bit 1 resume at a random offset][stream]. The
 * arena byte is masked to 0..15 (a 16 MB arena at most) unless bit 7 of the flags asks for any value; a request above what the
 * allocation caps allow is a refusal of the start (FZ_MAY_HIT_CAP). Output goes to the sink in 64-byte batches, so the output cap
 * and the refusal quota stop the decode.
 */
#include "decomp_common.h"

#define MAXSYM 3000u

static void add(struct fz_corpus *c, const char *name, uint8_t order, uint8_t arena, uint8_t flags, const uint8_t *body, size_t n)
{
	uint8_t b[3 + 4000];

	b[0] = order; b[1] = arena; b[2] = flags;
	memcpy(b + 3, body, n);
	fz_corpus_add(c, name, b, 3u + n);
}

static void seeds(struct fz_corpus *c)
{
	static uint8_t body[4000];
	uint64_t rs = 77;
	size_t i;

	for (i = 0; i < sizeof body; i++)
		body[i] = (uint8_t)(size_t)"the model predicts the next byte from the bytes before it. "[i % 59];
	add(c, "text-o8", 8, 24, 0, body, 2000);
	for (i = 0; i < sizeof body; i++)
		body[i] = (uint8_t)(fz_rng_star(&rs) >> 40);
	add(c, "noise-o8", 8, 24, 0, body, 4000);
	add(c, "noise-o2-small", 2, 0, 0, body, 3000);
	add(c, "noise-o64", 64, 3, 0, body, 3000);
	add(c, "noise-resume", 8, 5, 1, body, 3000);
	add(c, "noise-resume-off", 16, 5, 2, body, 3000);
	memset(body, 0, sizeof body);
	add(c, "zeros", 8, 24, 0, body, 3000);
	add(c, "a7-18-zeros", 8, 24, 1, body, 256);
	for (i = 0; i < sizeof body; i++)
		body[i] = 0xff;
	add(c, "ff", 6, 9, 0, body, 3000);
}

struct pp_out {
	int      *syms;
	unsigned  ns, nb;
	uint8_t   batch[64];
	int       to_sink;
};

/* One symbol; 1 to go on, 0 when the model gave -1 or the sink refused. */
static int step(struct fz_ctx *c, struct kuncoat_ppmd *m, struct pp_out *o, uint64_t n)
{
	int s = kuncoat_ppmd_next(m);

	FZ_CHECK(c, s >= -1 && s <= 255, "a symbol outside -1..255");
	FZ_CHECK(c, kuncoat_ppmd_at(m) <= n, "the cursor is past the input");
	if (s < 0) {
		/* NOT held: -1 does not latch. An escape out of the root context returns -1 without marking the model broken (ppmd.c
		 * kuncoat_ppmd_next, the `!c->suffix` exit), so another call goes on from the moved context. Callers stop at the first -1
		 * (rar3.c); a call after it must still be safe, which is held: a symbol in -1..255 and a cursor inside the input. */
		int again = kuncoat_ppmd_next(m);

		FZ_CHECK(c, again >= -1 && again <= 255, "a call after -1 gave a symbol outside -1..255");
		FZ_CHECK(c, kuncoat_ppmd_at(m) <= n, "the cursor is past the input after -1");
		return 0;
	}
	o->syms[o->ns++] = s;
	o->batch[o->nb++] = (uint8_t)s;
	if (o->nb == 64u) {
		o->nb = 0;
		if (o->to_sink && !c->sink_fn(c->sink_user, o->batch, 64u))
			return 0;
	}
	return 1;
}

/* One decode of `body` under the header; the symbols are kept in syms. Returns how many; *started says the model started. */
static unsigned decode(struct fz_ctx *c, const uint8_t *hdr, const uint8_t *body, uint64_t n, int *syms, int *started, int to_sink, int resumes)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	struct pp_out o;
	uint8_t arena_byte = (uint8_t)((hdr[2] & 0x80u) ? hdr[1] : hdr[1] & 15u);
	uint64_t asked = kuncoat_ppmd_arena_want(arena_byte), last_at = 0;
	int ok = 1;

	memset(&o, 0, sizeof o);
	o.syms = syms;
	o.to_sink = to_sink;
	*started = 0;
	if (!m)
		return 0;
	FZ_CHECK(c, asked == ((uint64_t)arena_byte + 1u) << 20, "arena_want is not (byte + 1) MB");
	if (kuncoat_ppmd_start_asked(m, (int)hdr[0], asked, body, n, 0)) {
		*started = 1;
		FZ_CHECK(c, !kuncoat_ppmd_over(m), "over right after the start");
		while (ok && o.ns < MAXSYM) {
			uint64_t at;

			ok = step(c, m, &o, n);
			at = kuncoat_ppmd_at(m);
			FZ_CHECK(c, at >= last_at, "the cursor moved back");
			last_at = at;
			if (ok && resumes && o.ns == 700u) {
				uint64_t off = (hdr[2] & 2u) ? fz_below(c->rng, n + 2u) : at;

				if (off > n)
					off = n;
				if (!kuncoat_ppmd_resume(m, body, n, off))
					break;
				last_at = off;
			}
		}
		if (kuncoat_ppmd_over(m))
			FZ_CHECK(c, kuncoat_ppmd_next(m) == -1, "the model stopped on its arena allowance and still gave a symbol");
	}
	if (o.nb && to_sink)
		(void)c->sink_fn(c->sink_user, o.batch, o.nb);
	kuncoat_ppmd_free(m);
	return o.ns;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static int full[MAXSYM + 4], cut[MAXSYM + 4];
	uint8_t hdr[3] = { 0, 0, 0 };
	const uint8_t *body;
	uint64_t bn;
	int started = 0, st2 = 0;
	unsigned nf, nc, i, lim;

	if (n >= 3)
		memcpy(hdr, in, 3);
	body = n >= 3 ? in + 3 : in;
	bn = n >= 3 ? n - 3u : 0;
	nf = decode(c, hdr, body, bn, full, &started, 1, (hdr[2] & 3u) != 0);
	if (!c->failk && started && bn > 2 && !(hdr[2] & 3u)) {
		/* the same stream cut at a random length: its symbols are the beginning of the whole stream's */
		uint64_t m = 1u + fz_below(c->rng, bn - 1u);
		uint8_t *copy = (uint8_t *)malloc((size_t)m);

		if (copy) {
			memcpy(copy, body, (size_t)m);
			nc = decode(c, hdr, copy, m, cut, &st2, 0, 0);
			lim = nc < nf ? nc : nf;
			for (i = 0; i < lim; i++)
				if (cut[i] != full[i]) {
					FZ_CHECK(c, 0, "the symbols of a cut input are not the beginning of the whole input's");
					break;
				}
			free(copy);
		}
	}
	fz_digest(c, (uint64_t)nf ^ (uint64_t)started << 40);
	for (i = 0; i < nf && i < 64u; i++)
		fz_digest(c, (uint64_t)full[i] << 7);
	return started ? (nf >= MAXSYM ? 0 : 2) : 3;
}

FZ_ADAPTER(ppmd, .name = "kuncoat/ppmd", .covers = "kuncoat_ppmd_new kuncoat_ppmd_free kuncoat_ppmd_arena_want kuncoat_ppmd_start_asked kuncoat_ppmd_over "
	   "kuncoat_ppmd_resume kuncoat_ppmd_next kuncoat_ppmd_at", .shape = FZ_BYTES, .seeds = seeds, .run = run, .flags = FZ_MAY_HIT_CAP,
	   .steps_base = 8000000u, .backstop_s = 1800);   /* one child runs all the iterations of a long run: the default backstop is 60 s and 200000 cases take 400 s */
