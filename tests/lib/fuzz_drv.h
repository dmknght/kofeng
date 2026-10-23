/*
 * fuzz_drv.h - what an adapter file sees of the fuzz driver (tests/lib/fuzz_drv.c).
 *
 * An ADAPTER is one row: a name, the public functions it drives (.covers, which tools/check_layers.py reads), a
 * shape, a seed builder and the callbacks of its shape. The row registers itself from a constructor;
 * there is no central table to edit, so two work packages never touch the same line.
 *
 *   FZ_BYTES   S1  run(c, in, n): the bytes go to a decoder; c->sink_fn / c->sink_user is a receiver with a quota,
 *                  c->out / c->cap an exact-size guard buffer the receiver fills. Returns the decoder's status (0..15).
 *   FZ_REQ     S3  run(c, in, n): the adapter builds its request from the bytes (c->rng picks language, arch...).
 *   FZ_PARSE   S2  parse(c, in, n) -> handle or NULL; walk(c, h, in, n) drives every accessor; drop(h).
 *   FZ_SEQ     S4  open(c, in, n) -> handle; op(c, h, op, a, b) for n_ops decoded from the bytes (10 bytes each:
 *                  op, a, b); close(h).
 *   FZ_TWO     S6  size(c, in, n) -> bytes needed; write(c, in, n, out, cap) -> bytes written. The driver gives an
 *                  exact-size guard buffer (cap == size) and cap-1, and checks written == size.
 * The driver checks for every shape: the mailbox attribution of a crash, allocation caps (hit = a finding unless the row
 * says FZ_MAY_HIT_CAP), a leak (net live bytes after the call, unless FZ_KEEPS_STATE), the step bound, determinism (the
 * call twice gives one digest unless FZ_NONDET), and the k-th allocation failing (unless FZ_NO_FAILK).
 *
 * Adding a row, the whole of it:
 *     static void seeds(struct fz_corpus *c) { fz_corpus_add(c, "min", MIN, sizeof MIN); }
 *     static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
 *     {   struct kuncoat_io io = {{in, n}, c->sink_fn, c->sink_user, 0, 0};
 *         int st = kuncoat_xxx(&io);
 *         FZ_CHECK(c, io.consumed <= n, "consumed past the input");
 *         fz_digest(c, (uint64_t)st ^ io.produced);
 *         return st; }
 *     FZ_ADAPTER(xxx, .name = "kuncoat/xxx", .covers = "kuncoat_xxx", .shape = FZ_BYTES, .seeds = seeds, .run = run);
 */
#ifndef KOF_TESTS_FUZZ_DRV_H
#define KOF_TESTS_FUZZ_DRV_H

#include "fuzz_kit.h"

enum fz_shape { FZ_BYTES = 1, FZ_REQ, FZ_PARSE, FZ_SEQ, FZ_TWO };

enum fz_flags {
	FZ_MAY_HIT_CAP  = 1,     /* the allocation caps may be reached by a hostile input (a declared size) */
	FZ_KEEPS_STATE  = 2,     /* net allocation after the call is not zero (a cache) */
	FZ_NONDET       = 4,     /* two calls on one input may differ */
	FZ_NO_FAILK     = 8,     /* skip the fail-the-k-th-allocation runs */
	FZ_POST_REFUSAL = 16,    /* the sink may be called again after it refused */
	FZ_PLANTED      = 32     /* a deliberately broken adapter of the kit's self-test: it must FAIL */
};

/* What the driver hands every callback. */
struct fz_ctx {
	struct fz_rng  *rng;
	uint64_t        seed;
	unsigned        iter;
	struct fz_steps steps;
	struct fz_sink  sink;
	int           (*sink_fn)(void *, const uint8_t *, uint32_t);
	void           *sink_user;
	uint8_t        *out;          /* exact-size guard buffer of cap bytes (FZ_BYTES, FZ_TWO) */
	size_t          cap;
	uint64_t        digest;
	int             fails;
	const char     *why;          /* first failed check */
	int             failk;        /* this call runs with the k-th allocation failing: a status may differ from the clean run */
	int             refused;      /* the sink refused once */
	uint64_t        after_refusal;/* calls the sink got after it refused */
	unsigned        n_ops;
};

struct fz_adapter {
	const char          *name;
	const char          *covers;      /* space-separated public functions this row drives */
	enum fz_shape        shape;
	unsigned             flags;
	const char          *expect;      /* FZ_PLANTED rows: what the self-test must see ("crash", "hang", or a text of the reason) */
	unsigned             backstop_s;  /* the hang backstop of one child, seconds; 0 = 60 */
	void               (*seeds)(struct fz_corpus *c);
	const char *const   *dict;
	uint64_t             steps_base, steps_per_byte;   /* the bound: base + per_byte * n; 0: 1M + 64 a byte */
	int                (*run)(struct fz_ctx *c, const uint8_t *in, size_t n);
	void              *(*parse)(struct fz_ctx *c, const uint8_t *in, size_t n);
	void               (*walk)(struct fz_ctx *c, void *h, const uint8_t *in, size_t n);
	void               (*drop)(void *h);
	int                (*op)(struct fz_ctx *c, void *h, unsigned op, uint64_t a, uint64_t b);
	void              *(*open)(struct fz_ctx *c, const uint8_t *in, size_t n);
	void               (*close)(void *h);
	unsigned             n_kinds;     /* FZ_SEQ: how many distinct op codes */
	uint64_t           (*size)(struct fz_ctx *c, const uint8_t *in, size_t n);
	uint64_t           (*write)(struct fz_ctx *c, const uint8_t *in, size_t n, uint8_t *out, uint64_t cap);
};

void fz_register(const struct fz_adapter *ad);

/* The row registers itself from a constructor: a linker section would be the lighter way, but AddressSanitizer pads every
 * global with a redzone and the section stops being an array. */
#define FZ_ADAPTER(id, ...) \
	static const struct fz_adapter fz_ad_##id = { __VA_ARGS__ }; \
	static void fz_reg_##id(void) __attribute__((constructor)); \
	static void fz_reg_##id(void) { fz_register(&fz_ad_##id); }

/* A check inside a callback: records the first reason, the driver prints it with adapter, iteration and seed. */
#define FZ_CHECK(c, cond, why_) do { if (!(cond)) { (c)->fails++; if (!(c)->why) (c)->why = (why_); } } while (0)

static inline void fz_digest(struct fz_ctx *c, uint64_t v) FZ_UNUSED;
static inline void fz_digest(struct fz_ctx *c, uint64_t v)
{
	c->digest = (c->digest ^ v) * 0x100000001b3ull;
}

#endif
