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

#include "../kofdecomp/ovba.h"
#include "../kofdecomp/lzma.h"
#include "../kofdecomp/bcj.h"
#include "../kofdecomp/rar3.h"
#include "../kofdecomp/rar5.h"
#include "../kofdecomp/bcj2.h"
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */
#include <kofmod/sevenzip.h>

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
static const struct kof_str_ent *str_of(const struct kof_scanner *sc, uint32_t id,
					const uint8_t **bytes)
{
	return kof_db_str(sc->eng, sc->cur_mod, id, bytes);
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
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);
	struct kof_range *ext = sc->ext;
	uint32_t n;

	uint32_t mask, slot, uid;

	if (!e || range_id >= m->n_rng || m->rng_base + range_id >= sc->eng->n_rng)
		return 0;
	mask = sc->eng->rng_tab[m->rng_base + range_id];

	/*
	 * The memo slot is the QUESTION, not the asker.
	 *
	 * Two modules declaring the same marker get the same uid from the build, and
	 * the same region mask resolves to the same extents - so they are asking one
	 * question and it is answered once. Keying by module instead made the answer
	 * private to whoever asked first, and nobody can ask a signature author to
	 * know which markers other authors chose.
	 */
	uid = sc->eng->packs[m->pack_id].uid_base + e->uid;
	slot = uid * sc->eng->n_masks + sc->eng->rng_uid[m->rng_base + range_id];

	n = kof_scan_resolve_range(ctx, mask, ext);
	return kof_match_lookup(&sc->m, slot, ext, n, bytes, e->len,
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
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);

	if (!e)
		return 0;
	return kof_match_at(&sc->m, off, bytes, e->len,
			    e->kind, e->flags);
}

static int c_find_str_in(const struct kof_obj_ctx *ctx, uint32_t str_id,
			 uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);

	if (!e)
		return 0;
	return kof_match_in(&sc->m, off, len, bytes, e->len,
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
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);

	if (!e)
		return KOF_BROKEN;
	return kof_match_where(&sc->m, off, len, bytes, e->len, e->kind,
			       e->flags);
}

/*
 * Record why an object was not finished, keeping the first answer.
 *
 * First rather than worst, because the reasons arrive in causal order: a decoder
 * that met an unsupported coding stops producing, and the budget it then fails to
 * spend is a consequence rather than a second problem.
 */
static void scan_broken(struct kof_scanner *sc, uint32_t reason)
{
	if (!sc->broken)
		sc->broken = reason;
	if (reason == KOF_BROKEN_LIMIT)
		sc->stop = 1;
}

/*
 * Whether the object may still PRODUCE, which is not the same question as whether
 * it is complete.
 *
 * A recorded reason used to stop everything, and that is wrong for three of the
 * four reasons there are. DAMAGED, UNSUPPORTED and ENCRYPTED describe what was
 * found; they are not instructions to stop looking. Only a limit is - past a
 * ceiling there is nowhere to put what comes next, and asking again produces the
 * same answer more slowly.
 *
 * Measured on a real workbook whose directory chain runs past the end of the file:
 * the module reports the damage, carries on as the ABI says it may, and every
 * extraction after that point returned nothing - so a document with three VBA
 * modules in it came back with none, and the reason it came back with none was that
 * it had said it was damaged.
 */
static int can_produce(const struct kof_scanner *sc)
{
	return sc->cur_src && !sc->stop;
}

/* A decoder's status, in the vocabulary the caller sees. Stopping is the
 * receiver's limit; everything else is the stream failing. */
static uint32_t broken_of_status(int st)
{
	if (st == KOF_DEC_STOPPED)
		return KOF_BROKEN_LIMIT;
	/* A coding this build lacks is a gap in the engine, not damage in the file,
	 * and the two are reported apart because they lead different places. */
	if (st == KOF_DEC_UNSUPPORTED)
		return KOF_BROKEN_UNSUPPORTED;
	return KOF_BROKEN_DAMAGED;
}

/*
 * A module saying it did not finish.
 *
 * The same flag every host-side limit sets, reached from the other side. Available
 * to detectors as well: a detector that could not follow a structure has the same
 * thing to say, and the answer it must not give is "clean".
 */
static void c_incomplete(const struct kof_obj_ctx *ctx, uint32_t reason)
{
	/* The module's vocabulary is the host's; a value outside it is recorded as
	 * the least specific reason rather than stored and printed as a number. */
	if (reason != KOF_BROKEN_UNSUPPORTED && reason != KOF_BROKEN_DAMAGED &&
	    reason != KOF_BROKEN_ENCRYPTED)
		reason = KOF_BROKEN_LIMIT;
	scan_broken(kof_scan_of(ctx), reason);
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
	if (!text)
		text = "unknown";
	/* The field, not the whole name: consumers ask "which version" without
	 * caring which module answered, the same way they always did - only
	 * without finding the dot themselves once per fact per object. */
	sc->debug_cb(kof_fact_id(text), text, value, sc->debug_user);
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
/*
 * Sixteen megabytes, and every part of that number was measured.
 *
 * It was 64MB, which is not a ceiling on anything real - it is a ceiling on
 * padding. Across 1352 zip entries in 180 real archives the median entry is 255
 * BYTES and the 95th percentile is 92KB, so 64MB is seven hundred times the
 * percentile that matters and 98.4% of entries never come near it.
 *
 * What it was paying for is the case that dominated the corpus and that nobody
 * would call an attack: a PE inflated with a repeated byte so a scanner with a size
 * limit gives up. One measured sample holds 824KB of DEFLATE expanding to exactly
 * 100MB, of which 95.75% is duplicate 4KB blocks - the whole real program is in the
 * first 2.8MB. That is the shape of the problem, and it is not the bomb the budget
 * was written for: no single object is impossibly expensive, they are each merely
 * expensive enough, and there are thousands of them.
 *
 * WHY NOT LESS. 8MB was tried and it is wrong, which is the useful half of this.
 * It decodes 205MB where 64MB decodes 11292MB and it runs the corpus in 6.70s
 * against 11.42s - and it LOSES A DETECTION. A UPX packed miner of 3.9MB unpacks
 * to 13.1MB, which is not padding: its declared expansion is 3.4x where the padded
 * sample's is 127x. A fixed cap cannot tell those apart, so it has to clear the
 * larger of them.
 *
 * At 16MB the corpus keeps all 52 findings, runs in 7.94s, and decodes 670MB of a
 * document set where 64MB decoded 2542MB. That is the whole of the reasoning: as
 * low as it goes without losing anything that was being found.
 *
 * Losing a tail is reported, never silent - an object cut here is marked as not
 * fully examined with a limit as the reason. A caller who would rather have the
 * whole of a large entry raises max_object_bytes and pays the decompression.
 */
#define KOF_OBJ_CAP (16u << 20)

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
	/*
	 * The pending name belongs to this child and to no other. Consumed whatever
	 * happens next - even if the child is then refused for a limit - because a
	 * name that survived a refusal would be attached to the following child,
	 * which is the one way this could report the wrong entry.
	 */
	if (sc->pend_label_len) {
		kof_src_label(kid, (const uint8_t *)sc->pend_label,
			      sc->pend_label_len);
		sc->pend_label[0] = 0;
		sc->pend_label_len = 0;
	}
	if (sc->kids_left == 0) {
		/* Refused, and recorded: a container that yields more children than
		 * the caller allows has not been fully examined, and saying so is
		 * the difference between "nothing else here" and "stopped looking". */
		scan_broken(sc, KOF_BROKEN_LIMIT);
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

	if (!can_produce(sc))
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

	if (!can_produce(sc))
		return 0;
	if (n == 0)
		return 1;
	/* A length out of a file, refused before it is used to read anything. */
	if (n > EMIT_MAX) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	/* Total work over the whole tree: the bomb defence. Cuts rather than
	 * discards, for the same reason the memory ceiling does - what has already
	 * been decompressed is a real prefix and is worth scanning. */
	if (n > sc->budget) {
		c_child(ctx);
		scan_broken(sc, KOF_BROKEN_LIMIT);
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
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (sc->sink_len + n > SINK_SPILL && !sink_spill(sc)) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (sc->sink_fd >= 0) {
		if (write(sc->sink_fd, bytes, n) != (ssize_t)n) {
			/* A short write is almost always a full tmpfs. Recorded, not
			 * swallowed: silently keeping a truncated object would report
			 * a prefix of a file as if it were the file. */
			scan_broken(sc, KOF_BROKEN_LIMIT);
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
				scan_broken(sc, KOF_BROKEN_LIMIT);
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
/*
 * What the sinks below carry.
 *
 * The sink signature hands back a void *, and what this one needs on the other
 * side is a pointer that is const - the two other sinks in this engine write
 * through theirs, so the typedef cannot be tightened for all of them. Passing
 * the const pointer as void * meant casting the const away and casting it
 * straight back, a promise no compiler can check and the engine's only such
 * cast. A one field carrier keeps the promise in the type instead.
 */
struct sink_carry {
	const struct kof_obj_ctx *ctx;
};

static int inflate_sink(void *user, const uint8_t *p, uint32_t n)
{
	const struct sink_carry *c = user;

	return c_emit(c->ctx, p, n);
}

/*
 * WHEN A STREAM'S OWN DECLARED EXPANSION SAYS NOT TO BOTHER.
 *
 * The object cap bounds how much one object may hold and says nothing about how it
 * got there, so a stream that expands absurdly is decoded up to that cap like any
 * other. Measured on this collection: 52 objects reach the cap and cost 3.75 of the
 * scan's 9.17 seconds, and the worst is one zip entry declaring 839MB out of a
 * 956KB file - one entry, nothing behind the name but padding.
 *
 * What separates those from real content is not the bytes, which have to be decoded
 * to be seen, but the RATIO THE CONTAINER DECLARES, which is free. Measured over
 * 12787 real zip entries of 4KB or more:
 *
 *     p50 2.8x  p95 6.5x  p99 21.4x  p99.5 29.9x  |  p99.9 654x  max 982x
 *
 * There is a gap and it is wide. Everything a real file does sits under thirty; the
 * padding sits at six hundred and up, and 0.4% of entries are above 32x. So the line
 * goes in the gap - chosen for where the two populations stop overlapping, not for
 * how much time it saves.
 *
 * A stream over the line is decoded to the floor below and no further. Not a
 * detection and not a verdict: the prefix is still scanned and the object is still
 * reported as cut. It costs a bomb its tail and a real file nothing, because a real
 * file is not on that side of the line.
 *
 * Only usable where the container SAYS what it expects. A decoder handed no size -
 * a gzip member, whose length is in a trailer nobody has read yet - gets the object
 * cap and nothing cleverer.
 */
#define KOF_DECLARED_RATIO_MAX 32u
#define KOF_EXPAND_FLOOR (1u << 20)

/*
 * A sink that stops once the expansion bound is reached.
 *
 * Wrapping rather than checking inside c_emit because the bound depends on the
 * INPUT to one decode, which c_emit has no way to see - it is handed bytes, not
 * the stream they came from.
 */
struct expand_sink {
	const struct kof_obj_ctx *ctx;
	uint64_t left;
};

static int expand_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct expand_sink *e = user;

	if (n > e->left)
		n = (uint32_t)e->left;
	if (n == 0)
		return 0;              /* the receiver has had enough */
	e->left -= n;
	return c_emit(e->ctx, p, n);
}

/*
 * What one decode is allowed to produce, given what the container declared.
 *
 * UINT64_MAX means "no opinion" - either nothing was declared, or what was declared
 * is within reason - and the caller then falls back to the object cap.
 */
static uint64_t expand_limit(uint64_t in_len, uint64_t declared)
{
	if (!declared || !in_len)
		return UINT64_MAX;
	if (declared / in_len <= KOF_DECLARED_RATIO_MAX)
		return UINT64_MAX;
	return KOF_EXPAND_FLOOR;
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
 * The three LZMA parameters, back out of the method id.
 *
 * Refused rather than clamped when they are past what the specification allows:
 * they size an allocation, and one that came out of a file is not a thing to round
 * into range.
 */
static int lzma_props_of(uint32_t method, unsigned *lc, unsigned *lp, unsigned *pb)
{
	uint32_t v;

	if (method < KOF_UNP_LZMA)
		return 0;
	v = method - KOF_UNP_LZMA;
	if (v > 224u)
		return 0;
	*lc = v % 9u;
	*lp = (v / 9u) % 5u;
	*pb = v / 45u;
	return *lc <= KOF_LZMA_MAX_LC && *lp <= KOF_LZMA_MAX_LP &&
	       *pb <= KOF_LZMA_MAX_PB;
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
/*
 * `peek_out` turns this from a producer into a reader.
 *
 * When it is set the decoded bytes are copied there and nothing is emitted -
 * which is the whole difference between unpack and unpack_peek. They share this
 * function rather than having one each because a second implementation of the
 * same dispatch is a second thing to get right: the first attempt at peek did
 * have its own, and on one architecture it decoded the same block to different
 * bytes than this did. Two paths that must agree, and no mechanism making them.
 */
static uint64_t unpack_buffered(struct kof_scanner *sc,
				const struct kof_obj_ctx *ctx, uint32_t method,
				int variant, int bits, const uint8_t *in,
				uint64_t in_len, uint64_t out_hint, uint32_t form,
				uint8_t *peek_out, uint32_t peek_cap)
{
	uint64_t room, want, produced = 0, decoded, at;
	uint8_t *buf;
	int st;

	room = sc->resident < sc->resident_max
	     ? (sc->resident_max - sc->resident) / 2u : 0;
	if (room > sc->obj_cap)
		room = sc->obj_cap;
	if (room == 0) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	want = out_hint ? out_hint : room;
	if (want > room) {
		want = room;
		scan_broken(sc, KOF_BROKEN_LIMIT);   /* the tail will not fit and will be dropped */
	}

	buf = malloc((size_t)want);
	if (!buf) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	/* Charged while it is alive, so a module that unpacks inside an object that
	 * is itself produced cannot exceed the ceiling between the two of them. */
	sc->resident += want;
	if (sc->resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->resident;

	if (method == KOF_UNP_RAR3 || method == KOF_UNP_RAR5) {
		uint64_t lim = expand_limit(in_len, out_hint);
		/*
		 * Working room for the channel delta filter, which writes a
		 * permutation of its input and so cannot work in place. Bounded by
		 * the format rather than by the entry - the filter refuses a block
		 * larger than this - and taken from the same budget as the output,
		 * because a produced object is charged for what producing it costs.
		 *
		 * The two formats bound it differently, so the smaller decoder does
		 * not pay for the larger one's room.
		 */
		uint64_t sn = method == KOF_UNP_RAR3 ? KOF_RAR3_SCRATCH
						     : KOF_RAR5_SCRATCH;
		uint8_t *scratch;

		if (want > lim) {
			want = lim;
			scan_broken(sc, KOF_BROKEN_LIMIT);
		}
		/*
		 * No larger than the output, because a filter cannot cover more of
		 * the entry than the entry holds. The format's bound is four
		 * megabytes and most entries are a fraction of that; taking the
		 * bound every time charged the budget for room nothing would use
		 * and turned ordinary archives into ones that hit a ceiling.
		 */
		if (sn > want)
			sn = want;
		scratch = malloc((size_t)sn);
		if (scratch)
			sc->resident += sn;
		if (method == KOF_UNP_RAR3)
			st = kof_rar3_decode(in, in_len, buf, want, scratch,
					     scratch ? sn : 0u, &produced);
		else
			st = kof_rar5_decode(in, in_len, buf, want, scratch,
					     scratch ? sn : 0u, &produced);
		if (scratch) {
			sc->resident -= sn;
			free(scratch);
		}
	} else if (method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86) {
		uint64_t lim = expand_limit(in_len, out_hint);

		if (want > lim) {
			want = lim;
			scan_broken(sc, KOF_BROKEN_LIMIT);
		}
		st = kof_lzma2_decode(in, in_len, buf, want, &produced);
		/*
		 * The transform is undone here, over the whole decoded buffer,
		 * because that is the only place it can be: it rewrites addresses
		 * that are relative to a position in the OUTPUT, so it cannot run
		 * on the compressed bytes and cannot run on a chunk of the output
		 * without knowing where that chunk sits. A buffered decode has the
		 * whole thing in hand and a streaming one never would.
		 */
		if (method == KOF_UNP_LZMA2_BCJ_X86 && produced)
			kof_bcj_x86_decode(buf, produced, 0);
	} else if (method >= KOF_UNP_LZMA) {
		unsigned lc, lp, pb;

		if (!lzma_props_of(method, &lc, &lp, &pb)) {
			sc->resident -= want;
			free(buf);
			scan_broken(sc, KOF_BROKEN_DAMAGED);
			return 0;
		}
		st = kof_lzma_decode(lc, lp, pb, in, in_len, buf, want, &produced);
	} else {
		st = kof_nrv2_decode(variant, bits, in, in_len, buf, want,
				     &produced);
	}
	/*
	 * STOPPED IS NOT A LIMIT WHEN THE CALLER GOT WHAT IT ASKED FOR.
	 *
	 * KOF_DEC_STOPPED means the output buffer filled. Whether that is a
	 * failure depends entirely on who chose the buffer's size, and until now
	 * this did not ask.
	 *
	 * Several formats carry no end marker in the stream at all - 7z writes
	 * its LZMA that way, and UPX's NRV2 blocks likewise - so the length comes
	 * out of the container and the decode ENDS by filling exactly that many
	 * bytes. Every one of those reported "a limit was reached", on a decode
	 * that had delivered the whole stream. A 1042 byte 7z came back broken
	 * for it, which is what made this visible.
	 *
	 * So: if the buffer was the size the module asked for and it filled,
	 * nothing was refused and there is nothing to report. If it was smaller
	 * than the module asked for, the clamp that made it smaller has already
	 * recorded the limit above - this is not the place that knows about it,
	 * and saying so twice was never what carried the message.
	 */
	if (st == KOF_DEC_STOPPED && out_hint && want == out_hint)
		st = KOF_DEC_OK;
	if (st != KOF_DEC_OK)
		scan_broken(sc, broken_of_status(st));

	/*
	 * An image becomes a file before anybody sees it.
	 *
	 * Done here rather than after the emit because this is the only place the
	 * whole output is one contiguous buffer: past this point it is in a sink
	 * that may already have spilled to a temporary file. The rebuild is bounded
	 * by what is left under the ceiling for the same reason the decode was.
	 */
	/*
	 * What the DECODER produced, kept before the rebuild changes it.
	 *
	 * This is what the call reports back, and the distinction matters: a module
	 * compares the answer against the length its container declared, and that
	 * length describes the image, not the file the host went on to assemble
	 * from it. Returning the file's size made every rebuilt object look short
	 * and every UPX packed PE was reported as not fully examined.
	 */
	decoded = produced;

	if (peek_out) {
		uint64_t n = produced < (uint64_t)peek_cap ? produced
							  : (uint64_t)peek_cap;

		if (n)
			memcpy(peek_out, buf, (size_t)n);
		sc->resident -= want;
		free(buf);
		return n;
	}

	if (form == KOF_FORM_PE_IMAGE && produced) {
		uint8_t *rebuilt = NULL;
		uint64_t rebuilt_len = 0;
		uint64_t rebuild_cap = sc->resident < sc->resident_max
				     ? sc->resident_max - sc->resident : 0;

		if (kof_pe_rebuild(kof_buf_make(buf, produced), rebuild_cap, &rebuilt,
				   &rebuilt_len)) {
			sc->resident -= want;
			free(buf);
			buf = rebuilt;
			want = rebuilt_len;
			produced = rebuilt_len;
			sc->resident += want;
			if (sc->resident > sc->st.peak_resident)
				sc->st.peak_resident = sc->resident;
		}
		/* A buffer that could not be rebuilt is emitted as it is: an image
		 * is still worth searching, and saying nothing about it would be
		 * worse than handing over something that does not identify. */
	}

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
	/*
	 * Everything emitted means the decode is what to report; a short emit means
	 * the sink refused and how far it got is the useful number. The two differ
	 * only after a rebuild, where what was emitted is a file assembled from what
	 * was decoded and is a different size by construction.
	 */
	return at == produced ? decoded : at;
}

/*
 * Decode the front of a stream into the caller's buffer.
 *
 * A read, not a production: nothing reaches a sink, nothing is charged against
 * the object ceiling, and a short or damaged stream is the caller's to judge
 * rather than something recorded against the object. What it is for is a
 * container whose layout is written in a header the container compressed - see
 * `unpack_peek` in kofsig.h.
 *
 * `cap` is the caller's buffer and the only size involved, so nothing a hostile
 * object declares can size anything here. The decoders all take an output
 * bound, and a back reference reaches only bytes already produced, so stopping
 * at `cap` gives the same first `cap` bytes a full decode would.
 */
static uint32_t c_unpack_peek(const struct kof_obj_ctx *ctx, uint32_t method,
			      uint64_t off, uint64_t len, void *out,
			      uint32_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	int variant, bits;
	kof_buf b;

	if (!sc->cur_src || !out || !cap)
		return 0;
	b = kof_src_buf(sc->cur_src);
	len = kof_clip_len(b.n, off, len);
	if (!len)
		return 0;

	/*
	 * Through the same decode as unpack, with the caller's buffer as the
	 * destination. `cap` is also the output bound, which matters more than
	 * it looks: NRV2 has no end marker and stops when the output is full,
	 * so the size it is given is part of the decode rather than a limit
	 * around it. A caller wanting the first N bytes of a block must pass
	 * the block's own declared size, not the size of its buffer.
	 */
	if (method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86 ||
	    method == KOF_UNP_RAR3 || method == KOF_UNP_RAR5)
		return (uint32_t)unpack_buffered(sc, ctx, method, 0, 0,
						 b.p + off, len, cap,
						 KOF_FORM_RAW,
						 (uint8_t *)out, cap);
	if (nrv2_of(method, &variant, &bits))
		return (uint32_t)unpack_buffered(sc, ctx, method, variant, bits,
						 b.p + off, len, cap,
						 KOF_FORM_RAW,
						 (uint8_t *)out, cap);
	if (method >= KOF_UNP_LZMA)
		return (uint32_t)unpack_buffered(sc, ctx, method, 0, 0,
						 b.p + off, len, cap,
						 KOF_FORM_RAW,
						 (uint8_t *)out, cap);
	return 0;      /* a method this engine does not peek into */
}

static uint64_t c_unpack(const struct kof_obj_ctx *ctx, uint32_t method,
			 uint64_t off, uint64_t len, uint64_t out_hint,
			 uint32_t form)
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
				scan_broken(sc, KOF_BROKEN_LIMIT);
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
		{
			struct expand_sink e;
			int st;

			e.ctx = ctx;
			e.left = expand_limit(len, out_hint);
			st = kof_inflate(sc->inf, b.p + off, len, expand_sink_fn,
					 &e, NULL, &produced);
			if (st != KOF_DEC_OK)
				scan_broken(sc, broken_of_status(st));
			else if (e.left == 0)
				scan_broken(sc, KOF_BROKEN_LIMIT);
		}
		return produced;
	}

	if (method == KOF_UNP_HEXTEXT) {
		/*
		 * Hex to bytes, streamed through the sink like DEFLATE.
		 *
		 * No output buffer of its own and no size hint needed: two input
		 * characters are one output byte, so the length is known and the
		 * bytes can leave as they are made. Whitespace between digits is
		 * skipped - it is legal in RTF and is used to break a blob up so a
		 * fixed prefix does not match.
		 */
		uint8_t out[512];
		uint32_t n = 0;
		int hi = -1;
		uint64_t i;

		for (i = 0; i < len; i++) {
			uint8_t ch = b.p[off + i];
			int v;

			if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
				continue;
			/*
			 * A nested group is skipped WHOLE, not just its braces.
			 *
			 * Its content is a different destination and is not this
			 * object's data. Skipping only the braces decodes the junk
			 * inside as if it were payload, which on a real document
			 * produced 2875922 bytes against the correct 2875905 - the
			 * right length to look plausible and wrong from the first
			 * byte.
			 */
			if (ch == '{') {
				uint32_t d = 0;

				while (i < len) {
					uint8_t g = b.p[off + i];

					if (g == '\\') {
						i += 2u;
						continue;
					}
					if (g == '{') {
						d++;
					} else if (g == '}') {
						d--;
						if (d == 0)
							break;
					}
					i++;
				}
				continue;
			}
			if (ch == '}')
				continue;
			if (ch == '\\') {
				uint64_t k = i + 1u;
				int alpha = 0;

				/*
				 * A control WORD is letters; a control SYMBOL is
				 * one character that is not. Both have to be
				 * stepped over and the second is the one that
				 * catches a reader out - the ignorable destination
				 * marker is written "\*", so a decoder that skips
				 * only the backslash lands on the asterisk, finds
				 * it is not a hex digit, and stops. Measured on a
				 * real document that ended the decode after zero
				 * bytes of a 2.8MB payload.
				 */
				while (k < len) {
					uint8_t d = b.p[off + k];

					if (!((d >= 'a' && d <= 'z') ||
					      (d >= 'A' && d <= 'Z')))
						break;
					alpha = 1;
					k++;
				}
				if (!alpha) {
					i = k;            /* the symbol itself */
					continue;
				}
				if (k < len && b.p[off + k] == '-')
					k++;
				while (k < len && b.p[off + k] >= '0' &&
				       b.p[off + k] <= '9')
					k++;
				if (k < len && b.p[off + k] == ' ')
					k++;
				i = k - 1u;
				continue;
			}
			if (ch >= '0' && ch <= '9')       v = ch - '0';
			else if ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'f')
				v = (ch | 0x20) - 'a' + 10;
			else
				continue;                 /* skipped, as the parser does */
			if (hi < 0) {
				hi = v;
				continue;
			}
			out[n++] = (uint8_t)((hi << 4) | v);
			hi = -1;
			if (n == sizeof out) {
				if (!c_emit(ctx, out, n))
					return produced;
				produced += n;
				n = 0;
			}
		}
		if (n && c_emit(ctx, out, n))
			produced += n;
		return produced;
	}
	if (method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86 ||
	    method == KOF_UNP_RAR3 || method == KOF_UNP_RAR5)
		return unpack_buffered(sc, ctx, method, 0, 0, b.p + off, len,
				       out_hint, form, NULL, 0);
	if (nrv2_of(method, &variant, &bits))
		return unpack_buffered(sc, ctx, method, variant, bits, b.p + off,
				       len, out_hint, form, NULL, 0);
	if (method >= KOF_UNP_LZMA)
		return unpack_buffered(sc, ctx, method, 0, 0, b.p + off, len,
				       out_hint, form, NULL, 0);

	return 0;      /* a method this engine does not have */
}

/*
 * Join one entry's chain and decode it, in that order.
 *
 * The joining has to happen first and into a buffer of its own, because every
 * decoder here reads a contiguous input - and an entry's bytes are a chain that is
 * not consecutive 23.6% of the time. The buffer is charged against the residency
 * ceiling while it is alive, on the same account as a decoder's output, so a
 * document full of large streams cannot walk past the limit one stream at a time.
 */
/*
 * Decode one BCJ2 folder: three coded streams and a raw one, merged.
 *
 * Every buffer is charged to the resident budget before it is taken and released
 * whatever happens after, because four allocations on one path is four ways to
 * leak. The output length is the folder's, which the archive states and the ratio
 * cap has already been applied to by the caller that chose to ask.
 */
static uint64_t decode_stream(const struct kof_7z_pack *pk, const uint8_t *in,
			      uint8_t *out, uint64_t cap, uint64_t *got)
{
	uint64_t n = 0;
	int st;

	*got = 0;
	if (pk->coder == KOF_7Z_CODER_LZMA2)
		st = kof_lzma2_decode(in, pk->size, out, cap, &n);
	else if (pk->coder == KOF_7Z_CODER_LZMA)
		st = kof_lzma_decode(pk->lc, pk->lp, pk->pb, in, pk->size,
				     out, cap, &n);
	else
		return 0;              /* a coder this build does not have */
	*got = n;
	return st == KOF_DEC_OK || n ? 1u : 0u;
}

static uint64_t unpack_bcj2(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			    uint32_t index)
{
	const struct kof_7z_info *z = kof_7z(ctx);
	const struct kof_7z_pack *pk[4] = { 0, 0, 0, 0 };
	uint8_t *buf[3] = { 0, 0, 0 };
	uint64_t len[3] = { 0, 0, 0 }, charged = 0, out_len, produced = 0;
	uint8_t *out = NULL;
	kof_buf b;
	uint32_t i;

	if (ctx->format != KOF_FMT_7Z || !z || !z->valid ||
	    index >= z->n_folders)
		return 0;
	out_len = z->folder[index].unpack_size;
	if (!out_len)
		return 0;

	for (i = 0; i < z->n_pack; i++)
		if (z->pack[i].folder == index && z->pack[i].role < 4u)
			pk[z->pack[i].role] = &z->pack[i];
	if (!pk[0] || !pk[1] || !pk[2] || !pk[3])
		return 0;              /* the folder is not the shape BCJ2 needs */

	b = kof_src_buf(sc->cur_src);
	for (i = 0; i < 4u; i++)
		if (kof_clip_len(b.n, pk[i]->off, pk[i]->size) != pk[i]->size)
			return 0;      /* a stream the object does not hold */

	/* The three coded streams, then the output. Charged together so a partial
	 * failure gives the budget back in one place.
	 *
	 * kof_sat_add, not +=: out_len and every out_size here is unclipped -
	 * sevenzip_parse.c reads them as a bare 64-bit varint straight off the
	 * stream, unlike the pack off/size pair checked against the real buffer
	 * a few lines above. Four attacker-chosen values near 2^64/4 each would
	 * otherwise wrap `charged` down to something small enough to slip past
	 * the budget check below while the mallocs further down still see the
	 * real, enormous sizes - the budget invariant this file otherwise
	 * enforces everywhere else, bypassed by exactly the overflow it exists
	 * to rule out. */
	charged = out_len;
	for (i = 0; i < 3u; i++)
		charged = kof_sat_add(charged, pk[i]->out_size);
	if (charged > (sc->resident < sc->resident_max
		       ? sc->resident_max - sc->resident : 0)) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	sc->resident += charged;
	if (sc->resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->resident;

	for (i = 0; i < 3u; i++) {
		if (pk[i]->out_size) {
			buf[i] = malloc((size_t)pk[i]->out_size);
			if (!buf[i])
				goto done;
			if (!decode_stream(pk[i], b.p + pk[i]->off, buf[i],
					   pk[i]->out_size, &len[i]))
				goto done;
		}
	}
	out = malloc((size_t)out_len);
	if (!out)
		goto done;

	produced = kof_bcj2_decode(buf[0], len[0], buf[1], len[1],
				   buf[2], len[2],
				   b.p + pk[3]->off, pk[3]->size,
				   out, out_len);
	if (produced != out_len)
		scan_broken(sc, KOF_BROKEN_DAMAGED);
	/* Emitted in bounded pieces: c_emit takes a uint32 length, and a folder can
	 * decode to more than that. */
	{
		uint64_t at2 = 0;

		while (at2 < produced) {
			uint64_t chunk = produced - at2;

			if (chunk > (1u << 20))
				chunk = 1u << 20;
			if (!c_emit(ctx, out + at2, (uint32_t)chunk))
				break;
			at2 += chunk;
		}
	}
done:
	free(out);
	for (i = 0; i < 3u; i++)
		free(buf[i]);
	sc->resident -= charged;
	return produced;
}

static uint64_t c_unpack_entry(const struct kof_obj_ctx *ctx, uint32_t method,
			       uint32_t index, uint64_t out_hint)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext = sc->ext_gather;
	kof_buf b;
	uint8_t *in;
	uint64_t total = 0, at = 0, produced = 0, room;
	uint32_t n, i;
	int st;

	(void)out_hint;
	if (!can_produce(sc))
		return 0;
	if (method == KOF_UNP_BCJ2)
		return unpack_bcj2(sc, ctx, index);
	if (!ctx->resolve_entry)
		return 0;
	if (method != KOF_UNP_OVBA)
		return 0;              /* the only coding entries are decoded with */

	b = kof_src_buf(sc->cur_src);
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	for (i = 0; i < n; i++)
		total += kof_clip_len(b.n, ext[i].off, ext[i].len);
	if (!total)
		return 0;

	room = sc->resident < sc->resident_max
	     ? sc->resident_max - sc->resident : 0;
	if (total > room) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	in = malloc((size_t)total);
	if (!in) {
		scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	sc->resident += total;
	if (sc->resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->resident;

	for (i = 0; i < n; i++) {
		uint64_t len = kof_clip_len(b.n, ext[i].off, ext[i].len);

		if (!len)
			continue;
		memcpy(in + at, b.p + ext[i].off, (size_t)len);
		at += len;
	}

	{
		struct sink_carry carry = { ctx };

		st = kof_ovba_decode(in, at, inflate_sink, &carry, &produced);
	}
	if (st != KOF_DEC_OK)
		scan_broken(sc, broken_of_status(st));

	sc->resident -= total;
	free(in);
	return produced;
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
 * Join a named region into the object being produced.
 *
 * The whole of it is a resolve and a loop of emits, and that is the point: the
 * bytes never leave the host, so a gather is charged, cut and refused by exactly
 * the code that already does that for a decompression. There is no second budget
 * and no path by which a module can assemble more than the ceiling allows.
 *
 * `cap` is the module's own limit and only ever tightens the host's. Applied to
 * what THIS call produces rather than to the object being built, so a module
 * gathering two regions into one child gets a limit per region - which is what a
 * caller means by it, since the sizes it knows are per region.
 *
 * A short return is not an error and is not reported as one: the module asked for a
 * region and got a prefix of it. Whether that is worth calling the object broken is
 * the module's judgement, because only it knows whether the rest mattered.
 */
static uint64_t c_gather(const struct kof_obj_ctx *ctx, uint32_t mask, uint64_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext = sc->ext_gather;
	kof_buf b = mc(ctx)->data;
	uint64_t done = 0;
	uint32_t n, i;

	if (!can_produce(sc))
		return 0;

	n = kof_scan_resolve_range(ctx, mask, ext);
	for (i = 0; i < n; i++) {
		kof_buf s = kof_slice(b, ext[i].off, ext[i].len);
		uint64_t at = 0;

		while (at < s.n) {
			uint64_t want = s.n - at;

			if (want > EMIT_MAX)
				want = EMIT_MAX;
			if (cap) {
				if (done >= cap)
					return done;
				if (want > cap - done)
					want = cap - done;
			}
			if (!c_emit(ctx, s.p + at, (uint32_t)want))
				return done;
			at += want;
			done += want;
		}
	}
	return done;
}

/*
 * Name the next child, from bytes in the object being unpacked.
 *
 * A bounded copy and nothing else. Making the bytes safe to print is NOT done here:
 * it happens once, in kof_src_label, which is the only way a label is ever set. Two
 * places doing it would look like defence in depth and would be the opposite - with
 * both present, breaking either one changes nothing observable, so neither is
 * covered by a test and neither can be shown to work. One place, and the test that
 * mutates it fails.
 */
static void c_name_next(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	uint64_t n;

	sc->pend_label[0] = 0;
	sc->pend_label_len = 0;
	if (!s.n)
		return;
	n = s.n < KOF_SRC_LABEL_MAX - 1u ? s.n : KOF_SRC_LABEL_MAX - 1u;
	memcpy(sc->pend_label, s.p, (size_t)n);
	sc->pend_label[n] = 0;
	sc->pend_label_len = (uint32_t)n;
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
	c_find_str_in, c_csum, NULL, NULL, NULL, NULL, NULL, c_find_str_where,
	NULL, NULL, c_incomplete, NULL
};

static const struct kof_content kof_unpack_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_find_str_at,
	c_find_str_in, c_csum, c_window, c_emit, c_child, c_unpack,
	c_unpack_peek, c_find_str_where, c_gather, c_name_next, c_incomplete,
	c_unpack_entry
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
	/* A name set for a child that was never produced dies with the module that
	 * set it. Otherwise it would be waiting for the next module's first child and
	 * would label it with an entry from a different object. */
	kof_scan_of(ctx)->pend_label[0] = 0;
	kof_scan_of(ctx)->pend_label_len = 0;
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
	sc->obj_cap = opt->max_object_bytes ? opt->max_object_bytes : KOF_OBJ_CAP;
	if (sc->obj_cap > sc->resident_max / 2)
		sc->obj_cap = sc->resident_max / 2;
	if (sc->obj_cap == 0)
		sc->obj_cap = 1;
	sc->broken = 0;
	sc->stop = 0;
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

/*
 * The id for a field name. See kof_on_debug.
 *
 * The text after the last dot when there is one, the whole string when there is
 * not, hashed. Here rather than in a header so the hash has exactly one
 * definition: two of them drifting apart would be an id that means one thing to
 * the engine and another to the tool comparing against it.
 */
uint32_t kof_fact_id(const char *field)
{
	const char *dot;

	if (!field || !*field)
		return 0;
	dot = strrchr(field, '.');
	if (dot && dot[1])
		field = dot + 1;
	return kof_crc32(field, (uint64_t)strlen(field));
}
