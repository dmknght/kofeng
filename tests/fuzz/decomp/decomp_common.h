/*
 * decomp_common.h - what the adapters of tests/fuzz/decomp share: the run of a decoder that writes into a caller's buffer
 * (shape FZ_BYTES, an exact-size guard buffer), the properties that hold for every one of them, and a place to say which
 * of them a decoder is documented NOT to keep.
 *
 * HELD FOR EVERY BUFFER DECODER, whatever the input:
 *   - the status is one of the enum, produced <= cap, the margins of the output are intact (the driver);
 *   - the same input under a smaller cap gives the real beginning of the same output (a cap bounds COST and never
 *     changes a byte: the budget variants of the brief), unless the decoder says its cap is its DECLARED size and a
 *     filter over a range that is not all there is not applied (rar: DC_NO_CAP_PREFIX);
 *   - a stream that is one of the seeds, unmutated, gives exactly the plain text it was built from (the oracle of a
 *     decoder that has an encoder here), or under a short cap its beginning.
 * The cut-input property (a stream cut short gives a prefix of the full output) is NOT asserted: aPLib, LZMAT, LZMA,
 * LZX, LHA/ARJ and RAR are documented to hand back bytes a cut stream does not support (silent_loss_uncoat.c,
 * hostile_sweep.h HV_F_NO_PREFIX_TRUNC). The run still decodes a cut input (guard page after it) and checks status and
 * margins.
 *
 * Under "fail the k-th allocation" (c->failk) the answers may differ from the clean run and only the safety checks stay.
 */
#ifndef DECOMP_COMMON_H
#define DECOMP_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uncoat.h>

#include "../../lib/fuzz_drv.h"

/* A decoder of the shape (in, n) -> out[cap], produced. `par` is the adapter's own constant (variant, header byte...). */
typedef enum kuncoat_status (*dc_buf_fn)(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap,
					 uint64_t *produced);

struct dc_plain {
	const uint8_t *p;
	size_t         n;
};

#define DC_NO_CAP_PREFIX 1u     /* a smaller cap may change bytes (a filter that did not fit is not applied): the second call is made, its bytes are not compared */
#define DC_CAP_OK_MAY    4u     /* a cap below the true size may be reported OK (documented silent loss: LZMAT has no end marker) */
#define DC_EXACT_MAY_STOP 8u    /* cap == the true size may say STOPPED (the stream has bytes left after the data) */
#define DC_DECLARED_SIZE 2u     /* the cap IS the declared size: reaching it is OK and a cap above the true size says what it likes */

struct dc_buf {
	dc_buf_fn              fn;
	const void            *par;
	unsigned               flags;
	const struct dc_plain *plain;   /* plain[i]: what seed i decodes to; .p NULL = no statement */
	size_t                 n_plain;
};

static inline uint64_t dc_hash(const uint8_t *p, uint64_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;
	uint64_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

/*
 * One call under test, then the properties above. Returns the status; the output is c->out[0..*produced).
 * The caps used for the second call are drawn from c->rng (deterministic per iteration).
 */
static inline enum kuncoat_status dc_buf_run(struct fz_ctx *c, const struct dc_buf *d, const uint8_t *in, size_t n,
					     uint64_t *produced)
{
	enum kuncoat_status r, r2;
	uint64_t p = 0, p2 = 0, cap2;
	uint8_t *o2;

	r = d->fn(d->par, in, n, c->out, c->cap, &p);
	*produced = p;
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, p <= c->cap, "produced more than the output buffer");
	if (p > c->cap)
		return r;
	if (!c->failk && c->iter < d->n_plain && d->plain[c->iter].p) {
		const struct dc_plain *w = &d->plain[c->iter];

#ifdef DECOMP_CLASSIFY
		if ((p > w->n && !(d->flags & DC_DECLARED_SIZE)) || memcmp(c->out, w->p, (size_t)(p < w->n ? p : w->n)))
			fprintf(stderr, "classify plain: iter %u cap %zu produced %llu plain %zu status %s\n", c->iter, c->cap, (unsigned long long)p, w->n, kuncoat_status_name(r));
#endif
		if (!(d->flags & DC_NO_CAP_PREFIX) || c->cap >= w->n)
			FZ_CHECK(c, (p <= w->n || (d->flags & DC_DECLARED_SIZE)) && !memcmp(c->out, w->p, (size_t)(p < w->n ? p : w->n)), "a good stream gave bytes that are not its plain text");
		if (c->cap && c->cap >= w->n && !(d->flags & DC_DECLARED_SIZE && c->cap > w->n) && !(d->flags & DC_EXACT_MAY_STOP && c->cap == w->n && r == KUNCOAT_STOPPED))
			FZ_CHECK(c, r == KUNCOAT_OK && p == w->n, "a good stream under a roomy cap was not decoded whole");
	}
	if (!c->failk && p > 1) {
		cap2 = 1u + fz_below(c->rng, p - 1u);                       /* 1 .. p-1 */
		o2 = (uint8_t *)malloc((size_t)cap2);
		if (o2) {
			r2 = d->fn(d->par, in, n, o2, cap2, &p2);
			FZ_CHECK(c, (unsigned)r2 <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum (smaller cap)");
			FZ_CHECK(c, p2 <= cap2, "produced more than a smaller cap");
			if (p2 <= cap2 && !(d->flags & DC_NO_CAP_PREFIX))
				FZ_CHECK(c, !memcmp(o2, c->out, (size_t)p2), "a smaller cap changed the bytes it did produce");
			if (r == KUNCOAT_OK && !(d->flags & (DC_DECLARED_SIZE | DC_CAP_OK_MAY)))
				FZ_CHECK(c, r2 != KUNCOAT_OK || p2 == p, "a cap below the output was reported as the whole answer (OK)");
			free(o2);
		}
	}
	fz_digest(c, (uint64_t)r ^ p << 3 ^ dc_hash(c->out, p) << 17);
	return r;
}

/*
 * The reference decoder's answer against ours. `ref_ok`: the reference decoded the input to its end and made ref[0..reflen).
 * Then: under a cap that holds it, ours is OK with the same bytes (UNSUPPORTED is a gap and not held); under a smaller cap
 * ours stops with the real beginning and is not CORRUPT or TRUNCATED. When the reference REFUSES and ours is OK the case is
 * LENIENT: counted for the classification (compile with -DDECOMP_CLASSIFY), never held. `what` names the decoder.
 */
static inline void dc_cmp_ref(struct fz_ctx *c, const char *what, enum kuncoat_status r, uint64_t produced, const uint8_t *ref,
			      size_t reflen, int ref_ok)
{
	if (c->failk)
		return;
	if (ref_ok) {
		if (r == KUNCOAT_UNSUPPORTED || r == KUNCOAT_BAD_ARG)
			return;
		if (c->cap == 0) {
			FZ_CHECK(c, produced == 0, "produced bytes under a zero cap");   /* a zero cap is refused by contract (STOPPED or CORRUPT), whatever the stream holds */
		} else if (c->cap >= reflen) {
			FZ_CHECK(c, r == KUNCOAT_OK, "the reference decodes this stream completely and ours does not say OK");
			FZ_CHECK(c, produced == reflen && !memcmp(c->out, ref, (size_t)(produced < reflen ? produced : reflen)), "the reference decodes this stream to a different result");
		} else {
			FZ_CHECK(c, r != KUNCOAT_CORRUPT && r != KUNCOAT_TRUNCATED, "the reference decodes this stream and ours calls it broken under a small cap");
			FZ_CHECK(c, produced <= c->cap && !memcmp(c->out, ref, (size_t)produced), "under a small cap ours is not the beginning of the reference's output");
		}
	}
#ifdef DECOMP_CLASSIFY
	else if (r == KUNCOAT_OK && produced)
		fprintf(stderr, "classify %s: LENIENT (ours OK, the reference refuses) iter %u\n", what, c->iter);
	if (ref_ok && r != KUNCOAT_OK && r != KUNCOAT_STOPPED && r != KUNCOAT_OVER_BUDGET && r != KUNCOAT_UNSUPPORTED)
		fprintf(stderr, "classify %s: STRICT (ours %s, the reference decodes) iter %u\n", what, kuncoat_status_name(r), c->iter);
#else
	(void)what;
#endif
}

#endif /* DECOMP_COMMON_H */
