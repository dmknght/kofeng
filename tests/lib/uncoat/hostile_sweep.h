/*
 * hostile_sweep.h - one sweep engine for every decoder that turns a stream into
 * bytes, so each family test states its formats and its crafted cases and gets the
 * same hostile treatment: output cap at, below and above the true size; the input
 * cut at every length; every bit of the input flipped; guard pages after the input
 * and after the output; the invariants of uncoat_io.h checked on every call.
 *
 * A DECODER IS ADAPTED to one shape,
 *
 *     status = run(ctx, in, n, out, cap, &produced)
 *
 * with `out` a guard buffer of exactly `cap` bytes. A buffer decoder passes it
 * straight through. A sink decoder is given a sink that stores whole calls into it
 * and refuses the call that would not fit, which the decoder must report as STOPPED
 * (hv_bufsink_*). So "the output cap" means the same thing for both, and a write past
 * it faults in the buffer decoder and shows as `over` in the sink one.
 *
 * WHAT IS ASSERTED ON EVERY CALL, whatever the input:
 *   - the status is one of the seven;
 *   - produced <= cap, and (sink decoders) what the sink accepted never exceeds cap;
 *   - nothing was written before the output;
 *   - it returned (the caller wraps the sweep in an alarm).
 * WHAT IS ASSERTED OF A GOOD STREAM:
 *   - cap >= true size: OK and the exact bytes;
 *   - cap <  true size: not OK (unless the decoder is flagged as known to say OK),
 *     and the bytes are the real beginning;
 *   - the input cut short: a status other than OK (unless flagged) and the bytes are
 *     the real beginning - "output before the failure is real output" (status.h).
 */

#ifndef HOSTILE_SWEEP_H
#define HOSTILE_SWEEP_H

#include "hostile_common.h"

#define HV_F_TRUNC_OK_ALLOWED  0x01u   /* a cut stream may legitimately end OK (no end marker in the format) */
#define HV_F_CAP_OK_ALLOWED    0x02u   /* a short cap may be reported OK (documented silent loss, see silent_loss_uncoat.c) */
#define HV_F_EXACT_MAY_STOP    0x04u   /* cap == true size may say STOPPED when the stream has bytes left after the data */
#define HV_F_NO_PREFIX_TRUNC   0x08u   /* the bytes of a cut stream are not asserted to be a prefix */
#define HV_F_NO_PREFIX_CAP     0x10u   /* ... of a short cap */
#define HV_F_NO_FLIPS          0x20u   /* skip the bit-flip sweep (too slow per call) */
#define HV_F_DECLARED_SIZE     0x40u   /* the cap IS the declared size (RAR, ASPack, LZMAT): the decoder stops there and says
					 * OK; above the true size it has nothing more to decode and says what it likes */

typedef enum kuncoat_status (*hv_run_fn)(void *ctx, const uint8_t *in, size_t n,
					 uint8_t *out, size_t cap, uint64_t *produced);

struct hv_dec {
	const char *name;
	hv_run_fn   run;
	void       *ctx;
	unsigned    flags;
};

struct hv_vec {
	const char    *name;
	const uint8_t *in;
	size_t         n;
	const uint8_t *want;
	size_t         want_n;
};

/* ---- a sink that stores whole calls into the output buffer ---------------------- */

struct hv_bufsink {
	uint8_t *out;
	size_t   cap;
	uint64_t total;         /* bytes accepted and stored */
	uint64_t refused_n;     /* size of the call refused for lack of room (0: none) */
	uint64_t calls;
	int      over;          /* a call arrived AFTER a refusal */
	uint32_t sum;
};

static inline int hv_bufsink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct hv_bufsink *s = u;
	uint32_t i;

	s->calls++;
	if (s->refused_n) {
		s->over = 1;
		return 0;
	}
	for (i = 0; i < n; i++)
		s->sum += p[i];
	if (s->total + n > s->cap) {
		s->refused_n = n;
		return 0;
	}
	if (n)
		memcpy(s->out + s->total, p, n);
	s->total += n;
	return 1;
}

/* The weaker form, for a decoder whose `produced` counts what it decoded rather than what it
 * handed over (lzhuf: the bytes buffered in its dictionary when a stream fails are counted and
 * not delivered; see silent_loss_uncoat.c): never LESS than the sink accepted, and the sink is
 * not called after it refused. */
static inline void hv_bufsink_check_loose(const struct hv_bufsink *s, enum kuncoat_status st,
					  uint64_t dec_produced, const char *what)
{
	CKF(!s->over, "%s: the decoder called the sink again after it refused", what);
	CKF(dec_produced >= s->total, "%s: produced %llu, the sink accepted %llu", what,
	    (unsigned long long)dec_produced, (unsigned long long)s->total);
	if (s->refused_n)
		CKF(st == KUNCOAT_STOPPED, "%s: the sink refused and the status is %s", what, kuncoat_status_name(st));
}

/* Settle what a sink decoder returned against what the sink saw. */
static inline void hv_bufsink_check(const struct hv_bufsink *s, enum kuncoat_status st,
				    uint64_t dec_produced, const char *what)
{
	CKF(!s->over, "%s: the decoder called the sink again after it refused", what);
	/* The count the decoder reports is what it handed over: the accepted bytes, and
	 * at most the one refused call on top of them. */
	CKF(dec_produced >= s->total && dec_produced <= s->total + s->refused_n,
	    "%s: produced %llu, the sink accepted %llu (+%llu refused)", what,
	    (unsigned long long)dec_produced, (unsigned long long)s->total,
	    (unsigned long long)s->refused_n);
	if (s->refused_n)
		CKF(st == KUNCOAT_STOPPED, "%s: the sink refused and the status is %s", what,
		    kuncoat_status_name(st));
}

/* ---- the sweep -------------------------------------------------------------------- */

struct hv_sweep_mem {
	struct hv_gb gin, gout;
	size_t       in_max, out_max;
};

static inline int hv_sweep_mem_init(struct hv_sweep_mem *m, size_t in_max, size_t out_max)
{
	m->in_max = in_max;
	m->out_max = out_max;
	if (!hv_gb_init(&m->gin, in_max))
		return 0;
	if (!hv_gb_init(&m->gout, out_max)) {
		hv_gb_free(&m->gin);
		return 0;
	}
	return 1;
}

static inline void hv_sweep_mem_free(struct hv_sweep_mem *m)
{
	hv_gb_free(&m->gin);
	hv_gb_free(&m->gout);
}

/* One call through guard buffers; `keep` (cap bytes) receives what came out. */
static inline enum kuncoat_status hv_call(const struct hv_sweep_mem *m, const struct hv_dec *d,
					  const uint8_t *in, size_t n, size_t cap,
					  uint64_t *produced, uint8_t *keep)
{
	const uint8_t *ip = hv_in(&m->gin, in, n);
	uint8_t *op = hv_out(&m->gout, cap);
	enum kuncoat_status st;
	uint64_t p = 0x7171717171ull;

	st = d->run(d->ctx, ip, n, op, cap, &p);
	CKF(hv_status_ok(st), "%s: status %d", d->name, (int)st);
	CKF(p <= cap, "%s: produced %llu > cap %zu", d->name, (unsigned long long)p, cap);
	CKF(hv_out_canary_ok(op), "%s: wrote before the output", d->name);
	if (keep && p <= cap)
		memcpy(keep, op, (size_t)p);
	*produced = p;
	return st;
}

/* The caps worth trying for a true size of `full`: all of them when small. */
static inline size_t hv_next_cap(size_t c, size_t full)
{
	size_t step, nx;

	if (full <= 700u || c < 40u || c + 40u >= full)
		return c + 1u;
	step = full / 97u + 1u;
	nx = c + step;
	return nx + 40u > full ? full - 40u : nx;
}

static inline void hv_sweep_one(const struct hv_sweep_mem *m, const struct hv_dec *d,
				const struct hv_vec *v, uint8_t *keep, uint8_t *mut)
{
	enum kuncoat_status st;
	uint64_t p;
	size_t c, n, bit, full = v->want_n, stride, runs;
	char tag[96];

	/* The stream, whole: exact bytes. */
	hv_at(100, 0);
	snprintf(tag, sizeof tag, "%s/%s", d->name, v->name);
	st = hv_call(m, d, v->in, v->n, (d->flags & HV_F_DECLARED_SIZE) ? full : full + 8u, &p, keep);
	CKF(st == KUNCOAT_OK && p == full && !memcmp(keep, v->want, full),
	    "%s: whole stream: %s, %llu of %zu bytes", tag, kuncoat_status_name(st),
	    (unsigned long long)p, full);

	/* every cap (all of them when the answer is small) */
	for (c = 0; c <= full + 3u && c <= m->out_max; c = hv_next_cap(c, full)) {
		hv_at(101, c);
		st = hv_call(m, d, v->in, v->n, c, &p, keep);
		if (p <= c && p <= full && !(d->flags & HV_F_NO_PREFIX_CAP))
			CKF(!memcmp(keep, v->want, (size_t)p), "%s: cap %zu: not the real beginning", tag, c);
		if (d->flags & HV_F_DECLARED_SIZE) {
			if (c > 0 && c <= full)
				CKF(st == KUNCOAT_OK && p == c, "%s: declared size %zu of %zu: %s, produced %llu", tag, c, full,
				    kuncoat_status_name(st), (unsigned long long)p);
			else if (c > full)
				CKF(p <= full, "%s: declared size %zu above the stream: produced %llu", tag, c,
				    (unsigned long long)p);
			if (hv_fails > 12)
				return;
			continue;
		}
		if (c >= full) {
			int exact = c == full;

			CKF(p == full && (st == KUNCOAT_OK ||
					  (exact && st == KUNCOAT_STOPPED && (d->flags & HV_F_EXACT_MAY_STOP))),
			    "%s: cap %zu >= true size %zu: %s, produced %llu", tag, c, full,
			    kuncoat_status_name(st), (unsigned long long)p);
		} else if (!(d->flags & HV_F_CAP_OK_ALLOWED)) {
			CKF(st != KUNCOAT_OK, "%s: cap %zu < true size %zu: reported OK (produced %llu)",
			    tag, c, full, (unsigned long long)p);
		}
		if (hv_fails > 12)
			return;
	}

	/* the input cut at every length (at a stride when the answer is large: the work of a sweep is
	 * runs x output size, and is held near 40 MB of output so a big stream costs what a small one does) */
	runs = 40000000u / (full + 16u);
	if (runs < 16u)
		runs = 16u;
	if (runs > 700u)
		runs = 700u;
	stride = v->n <= runs ? 1u : v->n / runs + 1u;
	for (n = 0; n < v->n; n += stride) {
		hv_at(102, n);
		st = hv_call(m, d, v->in, n, full + 8u, &p, keep);
		if (!(d->flags & HV_F_NO_PREFIX_TRUNC) && p <= full)
			CKF(!memcmp(keep, v->want, (size_t)p), "%s: input cut at %zu: not the real beginning",
			    tag, n);
		if (!(d->flags & HV_F_TRUNC_OK_ALLOWED))
			CKF(st != KUNCOAT_OK || p == full, "%s: input cut at %zu of %zu: OK with %llu of %zu bytes",
			    tag, n, v->n, (unsigned long long)p, full);
		if (hv_fails > 12)
			return;
	}

	/* every bit of the input flipped */
	if (d->flags & HV_F_NO_FLIPS)
		return;
	runs = 40000000u / (full + 16u);        /* decodes allowed: 8 per byte position */
	if (runs > 2400u)
		runs = 2400u;
	if (runs < 64u)
		runs = 64u;
	runs /= 8u;
	stride = v->n <= runs ? 1u : v->n / runs + 1u;
	for (n = 0; n < v->n; n += stride)
		for (bit = 0; bit < 8; bit++) {
			hv_at(103, n * 8u + bit);
			memcpy(mut, v->in, v->n);
			mut[n] ^= (uint8_t)(1u << bit);
			st = hv_call(m, d, mut, v->n, full + 8u, &p, NULL);
			(void)st;
			if (hv_fails > 12)
				return;
		}
}

/*
 * "Output before the failure is real output" (status.h), measured: the input cut at
 * each length (every `stride`th), and for each the count of bytes handed back that are
 * not the real beginning. A decoder that treats the first byte past the end as zero and
 * finishes the symbol under way hands back such bytes, with status TRUNCATED.
 */
struct hv_tf {
	size_t nbad, worst, first, worst_cut, cuts;
};

static inline void hv_trunc_fab(const struct hv_sweep_mem *m, const struct hv_dec *d,
				const struct hv_vec *v, size_t start, size_t stride, struct hv_tf *r,
				uint8_t *keep)
{
	size_t cut, k;
	uint64_t p;

	memset(r, 0, sizeof *r);
	for (cut = start; cut < v->n; cut += stride) {
		hv_at(104, cut);
		(void)hv_call(m, d, v->in, cut, v->want_n + 8u, &p, keep);
		r->cuts++;
		for (k = 0; k < p && k < v->want_n && keep[k] == v->want[k]; k++)
			;
		if (k < p) {
			if (!r->nbad)
				r->first = cut;
			r->nbad++;
			if (p - k > r->worst) {
				r->worst = p - k;
				r->worst_cut = cut;
			}
		}
	}
}

/* Everything for one decoder and a list of vectors; run in the child. */
struct hv_sweep_job {
	const struct hv_dec *dec;
	const struct hv_vec *vecs;
	unsigned             nvec;
	size_t               in_max, out_max;
};

static inline int hv_sweep_job_run(void *arg)
{
	const struct hv_sweep_job *j = arg;
	struct hv_sweep_mem m;
	uint8_t *keep, *mut;
	unsigned i;

	if (!hv_sweep_mem_init(&m, j->in_max, j->out_max + 16u))
		return 1;
	keep = malloc(j->out_max + 64u);
	mut = malloc(j->in_max + 1u);
	if (!keep || !mut) {
		free(keep);
		free(mut);
		hv_sweep_mem_free(&m);
		return 1;
	}
	for (i = 0; i < j->nvec; i++)
		hv_sweep_one(&m, j->dec, &j->vecs[i], keep, mut);
	free(keep);
	free(mut);
	hv_sweep_mem_free(&m);
	return hv_fails != 0;
}

/* Forked, with an alarm: the entry the family tests call. */
static inline void hv_sweep(const struct hv_dec *d, const struct hv_vec *vecs, unsigned nvec,
			    size_t in_max, size_t out_max, unsigned secs)
{
	struct hv_sweep_job j;

	j.dec = d;
	j.vecs = vecs;
	j.nvec = nvec;
	j.in_max = in_max;
	j.out_max = out_max;
	hv_expect_clean(d->name, hv_sweep_job_run, &j, secs);
}

#endif /* HOSTILE_SWEEP_H */
