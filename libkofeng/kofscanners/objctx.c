/*
 * objctx.c - the scan context, as a module sees it.
 *
 * Builds a kof_obj_ctx and serves every call made through it. That makes this the
 * entire untrusted boundary: module code comes out of a database and runs native, and
 * every byte it can reach it reaches through one of these functions - so each one
 * bounds checks, and an out of range read yields zero rather than faulting. Ten
 * functions audited once beats bounds arithmetic repeated in every module.
 *
 * It sits with the scanner rather than beside the ABI headers in core/kofmod because
 * every line of it reads the scanner's per-object state - the match context, the
 * loaded engine, what the running module has reported. Put next to the headers it
 * would declare, it would reach sideways for all of that and be less cohesive, not
 * more. The headers are the contract; this is the scanner honouring it.
 *
 * Its own file for one reason: a mistake here is a memory safety bug rather than a
 * wrong answer, so it should read end to end without the scan routine in the way.
 *
 * Nothing here decides anything. These read, compare, and hand a declared string to
 * the matcher; what to do with the answer is the scan routine's business.
 */

#include "scan.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct kof_match_ctx *mc(const struct kof_obj_ctx *ctx)
{
	return &kof_scan_of(ctx)->m;
}

static uint8_t c_rd8(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint8_t v = 0;
	kof_rd_u8(mc(ctx)->data, off, &v);
	return v;
}

static uint16_t c_rd16(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint16_t v = 0;
	kof_rd_u16(mc(ctx)->data, off, 0, &v);
	return v;
}

static uint32_t c_rd32(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint32_t v = 0;
	kof_rd_u32(mc(ctx)->data, off, 0, &v);
	return v;
}

static uint64_t c_rd64(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint64_t v = 0;
	kof_rd_u64(mc(ctx)->data, off, 0, &v);
	return v;
}

static int c_memeq(const struct kof_obj_ctx *ctx, uint64_t off, const void *pat,
		   uint32_t len)
{
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return memcmp(s.p, pat, len) == 0;
}

static uint32_t c_csum(const struct kof_obj_ctx *ctx, uint64_t off, uint32_t len)
{
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return kof_crc32(s.p, s.n);
}

static void c_report(const struct kof_obj_ctx *ctx, uint32_t level,
		     uint32_t name_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	sc->rep_level   = level;
	sc->rep_name_id = name_id;
	sc->rep_valid   = 1;
}

/* ---- searching a declared string ------------------------------------------- */

/*
 * The string a module named, resolved against the running module's slice.
 *
 * NULL if the id is outside it. That is the only thing to check here: the id came
 * from a build-assigned constant, but a wrong pack would make it index another
 * module's string, and a signature reporting on somebody else's pattern is worse
 * than one that reports nothing.
 */
static const struct kof_str_ent *str_of(const struct kof_scanner *sc, uint32_t id)
{
	const struct kof_module *m = sc->cur_mod;

	if (!m || id >= m->n_str)
		return NULL;
	return &sc->eng->str_tab[m->str_base + id];
}

/*
 * The module facing search: resolve the range it named, then let the matcher answer.
 *
 * Everything about *how* to answer is the matcher's - the presence set, the memo,
 * the word boundaries. What is left here is the only part that needs the object's
 * parse: turning a named range into extents.
 */
static int c_find_str(const struct kof_obj_ctx *ctx, uint32_t str_id,
		      uint32_t range_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_module *m = sc->cur_mod;
	const struct kof_str_ent *e = str_of(sc, str_id);
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t n;

	if (!e || range_id >= m->n_rng)
		return 0;
	n = kof_scan_resolve_range(ctx, sc->eng->rng_tab[m->rng_base + range_id], ext);

	return kof_match_lookup(&sc->m,
				m->memo_base + str_id * m->n_rng + range_id,
				ext, n, sc->eng->str_pool + e->off, e->len,
				e->kind, e->flags, &sc->st.gram_answers);
}

/*
 * Compare at an offset the module computed.
 *
 * The offset is logic, not metadata: it comes from the entry point, from a field
 * read out of the object, from arithmetic on either. That is why it is a parameter
 * and not a declaration - the build cannot know it, and asking an author to declare
 * a value that depends on the file would be asking for the wrong thing. The bytes
 * stay metadata and stay in the database, which is what the two calls keep apart.
 *
 * The bound is the host's. Left to the module it would be a rule a signature has to
 * remember, on the one path where forgetting it reads outside the mapping, so it is
 * checked inside kof_match_at where it cannot be forgotten.
 */
static int c_find_str_at(const struct kof_obj_ctx *ctx, uint32_t str_id,
			 uint64_t off)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_str_ent *e = str_of(sc, str_id);

	if (!e)
		return 0;
	return kof_match_at(&sc->m, off, sc->eng->str_pool + e->off, e->len,
			    e->kind, e->flags);
}

static int c_find_str_in(const struct kof_obj_ctx *ctx, uint32_t str_id,
			 uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_str_ent *e = str_of(sc, str_id);

	if (!e)
		return 0;
	return kof_match_in(&sc->m, off, len, sc->eng->str_pool + e->off, e->len,
			    e->kind, e->flags);
}

/*
 * The same search, answering where instead of whether.
 *
 * Available to detectors as well as unpackers - it is a read, not a production -
 * which is why it sits with the other content accessors rather than below.
 */
static uint64_t c_find_str_where(const struct kof_obj_ctx *ctx, uint32_t str_id,
				 uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_str_ent *e = str_of(sc, str_id);

	if (!e)
		return KOF_BROKEN;
	return kof_match_where(&sc->m, off, len, sc->eng->str_pool + e->off,
			       e->len, e->kind, e->flags);
}

/*
 * A module saying it did not finish.
 *
 * The same flag every host-side limit sets, reached from the other side. Available
 * to detectors as well: a detector that could not follow a structure has the same
 * thing to say, and the answer it must not give is "clean".
 */
static void c_incomplete(const struct kof_obj_ctx *ctx)
{
	kof_scan_of(ctx)->exhausted = 1;
}

/*
 * A note on its way out.
 *
 * Resolved through the same name table a finding uses - a note and a detection are
 * both authored text keyed by the line that wrote them - and dropped entirely when
 * nobody is listening, which is the normal case.
 */
static void c_debug(const struct kof_obj_ctx *ctx, uint32_t name_id, uint64_t value)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const char *text;

	if (!sc->debug_cb || !sc->cur_mod)
		return;
	/* An id the table does not know is a stale table, and says so rather than
	 * borrowing the neighbouring name - the same rule findings follow. */
	text = kof_db_name(sc->eng, sc->cur_mod, name_id);
	sc->debug_cb(text ? text : "unknown", value, sc->debug_user);
}

/* ---- producing child objects ------------------------------------------------ */

/*
 * Where memory stops being the cheaper place to keep the answer.
 *
 * Below this a child is a malloc and a memcpy; above it the bytes go to an unnamed
 * temporary file and are mapped back, so a scan faults in only the pages it reads.
 * It is not a limit - the limits are the two budgets - only a change of storage.
 */
#define SINK_SPILL (1u << 20)

/*
 * The most one produced object may hold. Past it, the object is closed with what it
 * has and the REST OF THAT ENTRY IS DROPPED.
 *
 * Truncation, not chunking, and the difference is the whole point. An entry in a
 * container is a file: it has a header at offset zero and everything else in it is
 * located relative to that header. Cutting it at a byte count and calling the
 * remainder a second object produces something that was never a file - it begins
 * mid-structure, nothing identifies it, so no format is recognised, no region is
 * resolved, and every module that names a format is ruled out before it runs. A
 * stream cut into ten pieces is one object that can be parsed and nine that can
 * only be searched as raw bytes.
 *
 * Keeping the head is what makes the truncated object still worth having: a PE's
 * header, imports, entry point and first sections are all at the front, and so is
 * every structure a detector reads. The tail of an object this large is data.
 *
 * What is given up is real and is reported rather than hidden: an entry longer than
 * this is scanned in part, and the object is marked incomplete. That is the honest
 * trade at this size - an object of this size is almost never a packed executable
 * but an installer or an embedded package, whose interesting parts are entries in
 * their own right and are reached by unpacking it, not by scanning its tail.
 *
 * Clamped to half the resident ceiling below, so the object being built and the one
 * being scanned both fit under it.
 */
#define KOF_OBJ_CAP (64u << 20)

/*
 * The largest single emit accepted.
 *
 * A decompressor works from lengths written in the file it is decompressing, and a
 * wrong one is the normal hostile case rather than a bug: an entry that declares a
 * gigabyte and holds a kilobyte. The host cannot see how big the module's own
 * buffer is, so it cannot check that the pointer is good for the length - but it
 * can refuse a length no honest caller has, which turns "read a gigabyte from a
 * kilobyte buffer" into a refusal at the first call.
 *
 * A module with more than this to hand over calls again. That is not a burden: a
 * decompressor already works a window at a time.
 */
#define EMIT_MAX (1u << 20)

static int kid_push(struct kof_scanner *sc, struct kof_objsrc *kid)
{
	if (!kid)
		return 0;
	if (sc->kids_left == 0) {
		/* Refused, and recorded: a container that yields more children than
		 * the caller allows has not been fully examined, and saying so is
		 * the difference between "nothing else here" and "stopped looking". */
		sc->exhausted = 1;
		kof_src_unref(kid);
		return 0;
	}
	if (sc->n_kids == sc->cap_kids) {
		uint32_t nc = sc->cap_kids ? sc->cap_kids * 2 : 8;
		struct kof_objsrc **nv = realloc(sc->kids, nc * sizeof *nv);

		if (!nv) {
			kof_src_unref(kid);
			return 0;
		}
		sc->kids = nv;
		sc->cap_kids = nc;
	}
	sc->kids[sc->n_kids++] = kid;
	sc->kids_left--;
	return 1;
}

/*
 * Give produced bytes back to the memory ceiling.
 *
 * Hooked to the destruction of every produced source rather than called from the
 * scan loop, so the count falls on every path a child can die on - scanned and
 * released, refused by the child cap, abandoned by an aborted walk - and not only
 * on the one that was remembered.
 *
 * Two spellings because kof_src_on_free takes a void *. Casting this function to
 * that signature and calling through the cast is a call through an incompatible
 * pointer type, which is undefined however reliably it works; a wrapper costs
 * nothing and is simply correct.
 */
static void scan_release(struct kof_scanner *sc, uint64_t produced)
{
	sc->resident = produced < sc->resident ? sc->resident - produced : 0;
}

static void scan_release_cb(void *sc, uint64_t produced)
{
	scan_release(sc, produced);
}

/*
 * A child that is already a contiguous range of this object.
 *
 * No copy and no budget: nothing was produced, the parent's mapping is simply seen
 * through a different offset. What bounds it is the child count and the depth,
 * because a window can still be a way of pointing an object at itself.
 */
static int c_window(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc->cur_src || sc->exhausted)
		return 0;
	return kid_push(sc, kof_src_window(sc->cur_src, off, len));
}

/* Move whatever is in memory out to the descriptor, and keep writing there. */
static int sink_spill(struct kof_scanner *sc)
{
	if (sc->sink_fd < 0) {
		sc->sink_fd = kof_src_tmpfile();
		if (sc->sink_fd < 0)
			return 0;
	}
	if (sc->sink_len) {
		if (write(sc->sink_fd, sc->sink_mem, sc->sink_len) !=
		    (ssize_t)sc->sink_len)
			return 0;
		sc->sink_spilled += sc->sink_len;
		sc->sink_len = 0;
	}
	return 1;
}

/*
 * Bytes that did not exist before.
 *
 * The budget is charged HERE, at the write, and that placement is the whole point.
 * Checking a size after decompressing means the memory has already been spent, and
 * a declared size cannot be checked instead because the file declares it. A module
 * has no way to produce output except through this call, so it has no way to
 * produce output without spending budget - the same reason the bounds check on
 * find_str_at lives in the host.
 */
static int c_child(const struct kof_obj_ctx *ctx);

static int c_emit(const struct kof_obj_ctx *ctx, const void *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc->cur_src || sc->exhausted)
		return 0;
	if (n == 0)
		return 1;
	/* A length out of a file, refused before it is used to read anything. */
	if (n > EMIT_MAX) {
		sc->exhausted = 1;
		return 0;
	}
	/* Total work over the whole tree: the bomb defence. Cuts rather than
	 * discards, for the same reason the memory ceiling does - what has already
	 * been decompressed is a real prefix and is worth scanning. */
	if (n > sc->budget) {
		c_child(ctx);
		sc->exhausted = 1;
		return 0;
	}
	/*
	 * Memory right now: the hard one. Everything produced and still alive,
	 * including what has been written to a temporary file, because that file is
	 * very often on tmpfs and is memory there.
	 *
	 * Hitting it CUTS rather than discards. What has been decompressed so far is
	 * a real prefix of a real object and is worth scanning; throwing it away to
	 * refuse the next byte would mean a container slightly over the ceiling
	 * yielded nothing at all, which is the worst of both - the work was done and
	 * the answer was dropped. So the part in hand is closed as a child, and the
	 * object is marked as not fully examined.
	 *
	 * Residency does not fall here. These children are still pending, and only
	 * come off the count once the walk has scanned and released each of them -
	 * by which time this module has returned. That is the whole reason a cut is
	 * the right answer and "wait for room" is not.
	 */
	/*
	 * Two ceilings, one action. The object cap says this object has enough of
	 * the entry to be worth scanning; the resident ceiling says there is no
	 * memory to hold more of it. Either way what is in hand is closed as a
	 * child and the module is told no.
	 *
	 * Telling it matters: a decompressor that gets a zero stops working on this
	 * entry and moves to the next one, which is what should happen. A module
	 * that ignores the answer and emits again simply gets another zero - the
	 * sink is empty by then, and c_child makes no child out of nothing.
	 */
	if (sc->sink_len + sc->sink_spilled + n > sc->obj_cap ||
	    sc->resident + n > sc->resident_max) {
		c_child(ctx);
		sc->exhausted = 1;
		return 0;
	}
	if (sc->sink_len + n > SINK_SPILL && !sink_spill(sc)) {
		sc->exhausted = 1;
		return 0;
	}
	if (sc->sink_fd >= 0) {
		if (write(sc->sink_fd, bytes, n) != (ssize_t)n) {
			/* A short write is almost always a full tmpfs. Recorded, not
			 * swallowed: silently keeping a truncated object would report
			 * a prefix of a file as if it were the file. */
			sc->exhausted = 1;
			return 0;
		}
		sc->sink_spilled += n;
	} else {
		if (sc->sink_len + n > sc->sink_cap) {
			size_t nc = sc->sink_cap ? sc->sink_cap : 4096;
			uint8_t *nb;

			while (nc < sc->sink_len + n)
				nc *= 2;
			nb = realloc(sc->sink_mem, nc);
			if (!nb) {
				sc->exhausted = 1;
				return 0;
			}
			sc->sink_mem = nb;
			sc->sink_cap = nc;
		}
		memcpy(sc->sink_mem + sc->sink_len, bytes, n);
		sc->sink_len += n;
	}

	/*
	 * Charged only now, with the bytes actually stored.
	 *
	 * Charging before the write left the count standing when the write failed,
	 * and the ceiling shrank a little for every failure - a limit that tightens
	 * itself over a long scan is a limit nobody can predict.
	 */
	sc->budget -= n;
	sc->resident += n;
	if (sc->resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->resident;

	return 1;
}

/*
 * Decompression, as a host service.
 *
 * The decoder writes into the same sink an ordinary emit does, so nothing here
 * enforces a limit: c_emit already refuses past the object cap, past the resident
 * ceiling and past the total budget, and a refusal propagates back as a zero from
 * the sink, which stops the decoder where it stands. That is the property worth
 * stating plainly - a decompression bomb is not recognised, it is simply a stream
 * whose sink stops accepting, and it costs the same as any other stream that is
 * cut short.
 */
static int inflate_sink(void *user, const uint8_t *p, uint32_t n)
{
	const struct kof_obj_ctx *ctx = user;

	return c_emit(ctx, p, n);
}

/* NRV2's three codings and three bit widths, as the module ABI numbers them. */
static int nrv2_of(uint32_t method, int *variant, int *bits)
{
	static const struct { int v, b; } tab[9] = {
		{ KOF_NRV2B, 8 }, { KOF_NRV2B, 16 }, { KOF_NRV2B, 32 },
		{ KOF_NRV2D, 8 }, { KOF_NRV2D, 16 }, { KOF_NRV2D, 32 },
		{ KOF_NRV2E, 8 }, { KOF_NRV2E, 16 }, { KOF_NRV2E, 32 }
	};

	if (method < KOF_UNP_NRV2B_8 || method > KOF_UNP_NRV2E_32)
		return 0;
	*variant = tab[method - KOF_UNP_NRV2B_8].v;
	*bits    = tab[method - KOF_UNP_NRV2B_8].b;
	return 1;
}

/*
 * Decoders that cannot stream, and what they cost.
 *
 * NRV2 places no bound on how far a match may reach back, so the whole of its
 * output has to be addressable until the stream ends - there is no window size
 * that makes it streamable, the buffer IS the window. So this allocates, decodes,
 * and hands the result to the sink.
 *
 * That is TWICE the output alive at the moment of handover: the buffer, plus what
 * the sink has taken from it. Halving the allowance is the honest way to keep the
 * ceiling meaning what it says, and it is why a non-streaming decoder is a worse
 * deal than a streaming one rather than merely a different one.
 *
 * The size comes from what the container declared, clamped to that allowance. A
 * container that overstates gets the clamp; one that understates gets a decode
 * that stops early and an object marked incomplete. Neither is trusted: the
 * declared value sizes a buffer and bounds nothing.
 */
static uint64_t unpack_buffered(struct kof_scanner *sc,
				const struct kof_obj_ctx *ctx, int variant,
				int bits, const uint8_t *in, uint64_t in_len,
				uint64_t out_hint)
{
	uint64_t room, want, produced = 0, at;
	uint8_t *buf;
	int st;

	room = sc->resident < sc->resident_max
	     ? (sc->resident_max - sc->resident) / 2u : 0;
	if (room > sc->obj_cap)
		room = sc->obj_cap;
	if (room == 0) {
		sc->exhausted = 1;
		return 0;
	}
	want = out_hint ? out_hint : room;
	if (want > room) {
		want = room;
		sc->exhausted = 1;   /* the tail will not fit and will be dropped */
	}

	buf = malloc((size_t)want);
	if (!buf) {
		sc->exhausted = 1;
		return 0;
	}
	/* Charged while it is alive, so a module that unpacks inside an object that
	 * is itself produced cannot exceed the ceiling between the two of them. */
	sc->resident += want;
	if (sc->resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->resident;

	st = kof_nrv2_decode(variant, bits, in, in_len, buf, want, &produced);
	if (st != KOF_DEC_OK)
		sc->exhausted = 1;

	/* Whatever was decoded is real output and is worth scanning, whether or not
	 * the stream ended cleanly - the same rule the gzip path follows. */
	for (at = 0; at < produced; ) {
		uint64_t n = produced - at;

		if (n > EMIT_MAX)
			n = EMIT_MAX;
		if (!c_emit(ctx, buf + at, (uint32_t)n))
			break;
		at += n;
	}

	sc->resident -= want;
	free(buf);
	return at;
}

static uint64_t c_unpack(const struct kof_obj_ctx *ctx, uint32_t method,
			 uint64_t off, uint64_t len, uint64_t out_hint)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b;
	uint64_t produced = 0;
	int variant, bits;

	if (!sc->cur_src)
		return 0;
	b = kof_src_buf(sc->cur_src);
	/*
	 * Clipped to what the object holds, not refused.
	 *
	 * The length comes from a container's own metadata, and a compressed size
	 * that runs past the end of the file is the ordinary hostile case rather
	 * than an exceptional one - the same reasoning kof_clip_len is written for.
	 * Decoding what is really there and reporting truncation is more useful
	 * than declining to look.
	 */
	len = kof_clip_len(b.n, off, len);
	if (!len)
		return 0;

	if (method == KOF_UNP_DEFLATE) {
		if (!sc->inf) {
			sc->inf = malloc(sizeof *sc->inf);
			if (!sc->inf) {
				sc->exhausted = 1;
				return 0;
			}
		}
		/*
		 * A truncated or corrupt stream is not an error here.
		 *
		 * Whatever was decoded before the failure is real output and is
		 * the part worth scanning: archives inside malware are routinely
		 * damaged, and discarding a megabyte of decoded payload because
		 * the last block is missing throws away the part that identifies
		 * it. It is recorded as an incomplete examination, not a clean one.
		 */
		if (kof_inflate(sc->inf, b.p + off, len, inflate_sink,
				(void *)ctx, NULL, &produced) != KOF_DEC_OK)
			sc->exhausted = 1;
		return produced;
	}

	if (nrv2_of(method, &variant, &bits))
		return unpack_buffered(sc, ctx, variant, bits, b.p + off, len,
				       out_hint);

	return 0;      /* a method this engine does not have */
}

/* Close the object being emitted and start the next. */
static int c_child(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_objsrc *kid;
	uint64_t held;

	if (!sc->cur_src)
		return 0;
	if (sc->sink_len + sc->sink_spilled == 0)
		return 0;              /* nothing was emitted; not a child */

	if (sc->sink_fd >= 0) {
		if (!sink_spill(sc))
			return 0;
		held = sc->sink_spilled;
		kid = kof_src_fd(sc->sink_fd, sc->sink_spilled);
		sc->sink_fd = -1;
		sc->sink_spilled = 0;
	} else {
		held = sc->sink_len;
		kid = kof_src_heap(sc->sink_mem, sc->sink_len);
		sc->sink_mem = NULL;
		sc->sink_cap = 0;
	}
	sc->sink_len = 0;

	/*
	 * The bytes were charged to the sink and are now the child's. Ownership of
	 * the debt moves with them: from here on the count falls when the child is
	 * destroyed, wherever that happens - scanned and released, refused by the
	 * child cap, or abandoned because the walk was aborted.
	 */
	if (!kid) {
		scan_release(sc, held);
		return 0;
	}
	kof_src_on_free(kid, scan_release_cb, sc);
	return kid_push(sc, kid);
}

/*
 * Two vtables, differing only in whether the producer entries are there.
 *
 * A detector gets NULLs, so kof_emit and kof_child_window answer zero for it, and
 * the rule that only an unpacker produces children is carried by the pointers
 * rather than by a check somewhere that could be missed. Same shape as
 * resolve_scan being NULL when nothing identified the object.
 */
static const struct kof_content kof_detect_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_find_str_at,
	c_find_str_in, c_csum, NULL, NULL, NULL, NULL, c_find_str_where,
	c_incomplete
};

static const struct kof_content kof_unpack_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_find_str_at,
	c_find_str_in, c_csum, c_window, c_emit, c_child, c_unpack,
	c_find_str_where, c_incomplete
};

/*
 * Present an object to a module.
 *
 * Every field a module can reach is set here, so what a module is allowed to see is one
 * function rather than an assignment list the scan routine has to keep right.
 */
void kof_mod_attach(struct kof_obj_ctx *ctx, struct kof_scanner *sc)
{
	ctx->content = &kof_detect_vtable;
	ctx->report  = c_report;
	ctx->debug   = c_debug;
	ctx->priv    = sc;
}

/* Swap in the producing surface for the length of one unpacker. */
void kof_mod_unpack_mode(struct kof_obj_ctx *ctx, int on)
{
	ctx->content = on ? &kof_unpack_vtable : &kof_detect_vtable;
}

/*
 * The budget for one top level object, inherited by everything below it.
 *
 * Derived from the object rather than fixed: a ratio alone refuses a small archive
 * that legitimately expands, and a constant alone gives a tiny file the same
 * allowance as a large one. The floor and the ratio each cover the other's case.
 *
 * One budget for the whole tree. Per-child limits are how a container full of
 * entries that are each individually reasonable adds up to something that is not.
 */
void kof_scan_budget(struct kof_scanner *sc, uint64_t obj_size,
		     const struct kof_scan_option *opt)
{
	uint64_t want = opt->max_produced_bytes;

	if (want == 0) {
		/* A ratio, floored. Sixty-four rather than the thousand a single
		 * DEFLATE layer can reach: this is the total a tree may do, and an
		 * allowance that large on a large input is no allowance at all. */
		want = obj_size > (UINT64_MAX / 64u) ? UINT64_MAX : obj_size * 64u;
		if (want < (64ull << 20))
			want = 64ull << 20;
	}
	sc->budget = want;
	sc->kids_left = opt->max_children ? opt->max_children : 4096u;
	sc->resident = 0;
	sc->resident_max = opt->max_resident_bytes ? opt->max_resident_bytes
						   : (128ull << 20);
	/*
	 * Half the ceiling, at most.
	 *
	 * Not the whole of it: while a child is being unpacked, that child is itself
	 * resident, so a cap the size of the ceiling leaves no room to produce
	 * anything and the tree stops one level down. Half means the object in hand
	 * and the object being built both fit, which is what lets a container be
	 * unpacked one entry at a time.
	 */
	sc->obj_cap = sc->resident_max / 2 < KOF_OBJ_CAP ? sc->resident_max / 2
							 : KOF_OBJ_CAP;
	if (sc->obj_cap == 0)
		sc->obj_cap = 1;
	sc->exhausted = 0;
}

void kof_scan_kids_reset(struct kof_scanner *sc)
{
	uint32_t i;

	for (i = 0; i < sc->n_kids; i++)
		kof_src_unref(sc->kids[i]);
	sc->n_kids = 0;

	/* Whatever a module emitted and never closed is not an object, and the
	 * memory it was holding stops being resident. */
	scan_release(sc, sc->sink_len + sc->sink_spilled);
	free(sc->sink_mem);
	sc->sink_mem = NULL;
	sc->sink_len = sc->sink_cap = 0;
	if (sc->sink_fd >= 0)
		close(sc->sink_fd);
	sc->sink_fd = -1;
	sc->sink_spilled = 0;
}
