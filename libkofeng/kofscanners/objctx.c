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
 * Cut a produced object here and start another.
 *
 * A decompressed stream can be arbitrarily long, and one enormous child would be
 * one enormous allocation no matter what the totals allow. Chunking turns it into a
 * series of objects that are each finished with and released before the next
 * matters, which is what keeps the resident ceiling reachable at all.
 *
 * The cost is a pattern lying across a cut, which is the same trade the region
 * machinery already makes at an extent boundary. Chunks big enough that it is rare,
 * small enough that several fit under the ceiling.
 */
#define SINK_CHUNK (32u << 20)

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
	if (sc->resident + n > sc->resident_max) {
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

	/*
	 * Cut here rather than letting one object grow without end. The module is
	 * not told and does not need to be: it goes on emitting, and what it is
	 * emitting into simply becomes a new object.
	 */
	if (sc->sink_len + sc->sink_spilled >= sc->chunk)
		return c_child(ctx);
	return 1;
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
	c_find_str_in, c_csum, NULL, NULL, NULL
};

static const struct kof_content kof_unpack_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_find_str_at,
	c_find_str_in, c_csum, c_window, c_emit, c_child
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
	 * resident, so a chunk the size of the ceiling leaves no room to produce
	 * anything and the tree stops one level down. Half means the object in hand
	 * and the object being built both fit, which is what lets a stream be cut,
	 * scanned, released and continued.
	 */
	sc->chunk = sc->resident_max / 2 < SINK_CHUNK ? sc->resident_max / 2
						      : SINK_CHUNK;
	if (sc->chunk == 0)
		sc->chunk = 1;
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
