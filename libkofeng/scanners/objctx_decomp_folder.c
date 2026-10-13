/*
 * objctx_decomp_folder.c - the codings that decode a FOLDER and hand back one
 * file: BCJ2 (a 7z folder of four streams), MSZIP and LZX (a cabinet's or a
 * help file's blocks), and the join that gathers an entry's scattered pieces.
 *
 * WHAT THIS SERVES: a container module whose entry is not a byte range of the
 * object but a place inside something that has to be decoded to be reached.
 * The first range of the entry is a restart point; what comes before the file
 * is decoded and dropped, because those bytes belong to other entries.
 */


#include "objctx_decomp.h"
#include <stdlib.h>
#include <string.h>

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
	enum kuncoat_status st;

	*got = 0;
	if (pk->coder == KOF_7Z_CODER_LZMA2)
		st = kuncoat_lzma2_decode(in, pk->size, out, cap, &n);
	else if (pk->coder == KOF_7Z_CODER_LZMA)
		st = kuncoat_lzma_decode(pk->lc, pk->lp, pk->pb, in, pk->size,
				     out, cap, &n);
	else
		return 0;              /* a coder this build does not have */
	*got = n;
	return st == KUNCOAT_OK || n ? 1u : 0u;
}

uint64_t oc_unpack_bcj2(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
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

	b = kof_src_buf(sc->cur.src);
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
	if (charged > oc_scan_room(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, charged);

	/*
	 * A STREAM THAT IS EMPTY IS STILL A STREAM, AND STILL NEEDS A POINTER.
	 *
	 * BCJ2 cuts x86 into four: the code, the call targets, the jump
	 * targets and the range coder. A folder whose code has E8 calls and no
	 * E9 jumps has an EMPTY JUMP CHANNEL, which is an ordinary shape and
	 * not a damaged one.
	 *
	 * This skipped the allocation for such a channel and left the pointer
	 * NULL, and kuncoat_bcj2_decode refuses any NULL pointer outright - it
	 * bounds every read by the channel's LENGTH, so the pointer never
	 * mattered, but the guard does not know that. The decode returned 0,
	 * `produced != out_len` fired, and a sound archive was reported
	 * KOF_BROKEN_DAMAGED with nothing extracted.
	 *
	 * One byte rather than none, because malloc(0) may itself answer NULL
	 * and put us back where we started.
	 */
	for (i = 0; i < 3u; i++) {
		uint64_t want = pk[i]->out_size ? pk[i]->out_size : 1u;

		buf[i] = malloc((size_t)want);
		if (!buf[i])
			goto done;
		if (pk[i]->out_size &&
		    !decode_stream(pk[i], b.p + pk[i]->off, buf[i],
				   pk[i]->out_size, &len[i]))
			goto done;
	}
	out = malloc((size_t)out_len);
	if (!out)
		goto done;

	{
		struct kuncoat_bcj2_io bio = {
			.main_s = { buf[0], len[0] }, .call_s = { buf[1], len[1] },
			.jump_s = { buf[2], len[2] },
			.rc_s = { b.p + pk[3]->off, pk[3]->size },
			.out = out, .out_cap = out_len,
		};

		produced = kuncoat_bcj2_decode(&bio);
	}
	if (produced != out_len)
		oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
	oc_emit_all(ctx, out, produced);
done:
	free(out);
	for (i = 0; i < 3u; i++)
		free(buf[i]);
	oc_scan_release(sc, charged);
	return produced;
}

/*
 * What one MSZIP decode is producing: a window onto the folder's stream, and
 * the history the next block will need.
 */
struct mszip_out {
	const struct kof_obj_ctx *ctx;
	uint64_t skip, left;      /* of the FILE, inside the folder's stream */
	uint8_t *hist;            /* the last 32KB produced, for the next block */
	uint32_t hist_len;
	uint64_t emitted;
	int stopped;
};

/*
 * THE HISTORY IS KEPT WHATEVER IS EMITTED, and that is the whole subtlety
 * here: the bytes in front of this file belong to other files and are dropped,
 * but the NEXT BLOCK may reference them - so they go into the history even
 * though nothing is done with them. A sink that only remembered what it emitted
 * would decode the second block against a window with holes in it.
 */
static int mszip_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct mszip_out *o = user;
	uint32_t at = 0;

	/* The tail, for the block after this one. */
	if (n >= KUNCOAT_INF_WINDOW) {
		memcpy(o->hist, p + (n - KUNCOAT_INF_WINDOW), KUNCOAT_INF_WINDOW);
		o->hist_len = KUNCOAT_INF_WINDOW;
	} else if (n) {
		uint32_t keep = KUNCOAT_INF_WINDOW - n;

		if (o->hist_len > keep)
			memmove(o->hist, o->hist + (o->hist_len - keep), keep);
		else
			keep = o->hist_len;
		memcpy(o->hist + keep, p, n);
		o->hist_len = keep + n;
	}

	if (o->skip) {
		uint64_t drop = o->skip < n ? o->skip : n;

		o->skip -= drop;
		at = (uint32_t)drop;
	}
	while (at < n && o->left) {
		uint32_t take = n - at;

		if ((uint64_t)take > o->left)
			take = (uint32_t)o->left;
		if (!oc_emit(o->ctx, p + at, take)) {
			o->stopped = 1;
			return 0;
		}
		o->emitted += take;
		o->left -= take;
		at += take;
	}
	/* Past the file, and the folder still has blocks: keep decoding only
	 * while something is still wanted. */
	return o->left != 0 || o->skip != 0;
}

/*
 * MSZIP: A FOLDER OF DEFLATE BLOCKS THAT SHARE A DICTIONARY, and one file cut
 * out of what they decode to.
 *
 * The ranges resolve_entry hands back are the folder's BLOCKS in order, each
 * "CK" and then a deflate stream. They are not one stream and must not be
 * joined: every block is its own, and every block after the first may reference
 * up to 32KB of the previous one's output. So each is decoded separately with
 * the last block's tail as history - see kuncoat_inflate_seeded, whose note records
 * what decoding them from an empty window produces instead.
 *
 * WHY THE WHOLE FOLDER IS DECODED FOR ONE FILE. A CFFILE names a byte range
 * inside the folder's decoded stream, and a deflate stream cannot be entered
 * part way - so reaching a file at offset N means producing the N bytes in
 * front of it. Those bytes are dropped rather than emitted: they belong to
 * other files, which arrive as their own children with their own names.
 *
 * The cost is one folder decode per file, which is what makes the module's cap
 * on files per folder a real bound rather than tidiness.
 */
uint64_t oc_unpack_mszip(struct kof_scanner *sc,
			     const struct kof_obj_ctx *ctx, uint32_t index,
			     uint64_t out_hint)
{
	struct kof_range *ext = sc->cache.ext_gather;
	struct mszip_out snk;
	kof_buf b;
	uint32_t n, i;

	if (!ctx->resolve_entry || !oc_can_produce(sc))
		return 0;
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	b = kof_src_buf(sc->cur.src);
	memset(&snk, 0, sizeof snk);
	snk.ctx = ctx;
	/*
	 * `out_hint` carries where the file starts inside the folder and how
	 * long it is - the two numbers a CFFILE has and a range cannot hold.
	 * Packed rather than added to the entry: the entry is the host's shape
	 * and this is one format's business. See KOF_UNP_MSZIP.
	 */
	snk.skip = out_hint >> 32;
	snk.left = out_hint & 0xffffffffu;
	if (!snk.left)
		return 0;

	snk.hist = malloc(KUNCOAT_INF_WINDOW);
	if (!snk.hist) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, KUNCOAT_INF_WINDOW);

	if (!sc->cache.inf) {
		sc->cache.inf = malloc(sizeof *sc->cache.inf);
		if (!sc->cache.inf) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			free(snk.hist);
			oc_scan_release(sc, KUNCOAT_INF_WINDOW);
			return 0;
		}
	}

	for (i = 0; i < n && snk.left && !snk.stopped; i++) {
		uint64_t off = ext[i].off, len = kof_clip_len(b.n, off, ext[i].len);
		enum kuncoat_status st;
		struct kuncoat_span seed = { snk.hist, snk.hist_len };
		struct kuncoat_io io = {
			.in = { b.p + off + 2u, len - 2u },
			.sink = mszip_sink_fn, .user = &snk,
		};

		/* "CK", which every MSZIP block begins with. A block without it
		 * is not one, and decoding its first two bytes as deflate is
		 * how a wrong answer starts. */
		if (len < 2u || b.p[off] != 'C' || b.p[off + 1u] != 'K') {
			oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
			break;
		}
		/*
		 * `io.produced` is what the FOLDER decoded; what this call answers is
		 * what the FILE got, which is snk.emitted - the bytes in front
		 * of the file belong to other files and are dropped. The two
		 * were both accumulated and only the second was ever read.
		 */
		st = kuncoat_inflate_seeded(sc->cache.inf, &seed, &io);
		if (st != KUNCOAT_OK && st != KUNCOAT_STOPPED) {
			oc_scan_broken(sc, oc_broken_of_status(st));
			break;
		}
	}

	free(snk.hist);
	oc_scan_release(sc, KUNCOAT_INF_WINDOW);
	return snk.emitted;
}

/*
 * THE PIECES OF ONE ENTRY, JOINED INTO A BUFFER THE DECODERS CAN READ.
 *
 * Every decoder here takes contiguous input, and an entry's bytes are a chain
 * that is not consecutive 23.6% of the time, so the join is unavoidable. What
 * WAS avoidable is having it twice: oc_unpack_lzx and oc_unpack_entry each carried
 * the same seven steps - total the clipped extents, refuse when the ceiling has
 * no room, allocate, charge, copy - and each had to get the clip right in two
 * separate places, once for the size and once for the copy.
 *
 * Answers the buffer, CHARGED to the residency account, with *total set to its
 * length; the caller frees it and releases *total. NULL means nothing to join,
 * or no room for it - the reason is already recorded either way.
 */
uint8_t *oc_entry_join(struct kof_scanner *sc, kof_buf b,
			   const struct kof_range *ext, uint32_t n,
			   uint64_t *total)
{
	uint64_t want = 0, at = 0;
	uint8_t *in;
	uint32_t i;

	*total = 0;
	for (i = 0; i < n; i++)
		want += kof_clip_len(b.n, ext[i].off, ext[i].len);
	if (!want)
		return NULL;
	if (want > oc_scan_room(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return NULL;
	}
	in = malloc((size_t)want);
	if (!in) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return NULL;
	}
	scan_charge(sc, want);
	for (i = 0; i < n; i++) {
		uint64_t len = kof_clip_len(b.n, ext[i].off, ext[i].len);

		if (!len)
			continue;
		memcpy(in + at, b.p + ext[i].off, (size_t)len);
		at += len;
	}
	*total = at;
	return in;
}

/*
 * LZX: ONE FILE OUT OF A STREAM THAT CANNOT BE ENTERED PART WAY.
 *
 * The first range resolve_entry hands back starts at a RESTART POINT - a
 * cabinet folder's first block, a help file's reset interval - because that is
 * the only place an LZX stream can be picked up: its trees are stated as
 * differences from the previous block's and its window is whatever the last
 * 32KB produced.
 *
 * So the file is reached by decoding from there and dropping what comes before,
 * which is what the two halves of `out_hint` say. The dropped bytes are other
 * files; they arrive as their own children with their own names.
 *
 * ONE DECODE PER RANGE, AND THE DECODER IS RESET BETWEEN THEM. A restart is not
 * a place in one stream, it is the start of another: everything the coding
 * carries between blocks begins again there. A file longer than the distance
 * between two restarts therefore arrives as several ranges - see chm.h - and
 * running them together is what a single decode would do. The skip applies to
 * the first range only, because that is the one the file begins in; what a
 * range produces comes off `take` and the rest carry on from where it stopped.
 */
uint64_t oc_unpack_lzx_reset(struct kof_scanner *sc,
				 const struct kof_obj_ctx *ctx, uint32_t index,
				 uint32_t window_bits, uint64_t out_hint)
{
	struct kof_range *ext = sc->cache.ext_gather;
	struct expand_sink snk;
	enum kuncoat_status st = KUNCOAT_OK;
	kof_buf b;
	uint64_t skip, take, got = 0;
	uint32_t n, i;

	if (!ctx->resolve_entry || !oc_can_produce(sc))
		return 0;
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	b = kof_src_buf(sc->cur.src);
	skip = out_hint >> 32;
	take = out_hint & 0xffffffffu;
	if (!take)
		return 0;

	if (!sc->cache.lzx) {
		sc->cache.lzx = malloc(sizeof *sc->cache.lzx);
		if (!sc->cache.lzx) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
	}
	snk.ctx = ctx;
	/*
	 * THE RATIO IS THE FILE'S, SO THE INPUT IN IT IS ALL THE RANGES.
	 *
	 * One sink serves every range - `take` is the whole file's length and
	 * `left` is spent across all of them - so measuring the expansion
	 * against the FIRST range alone divides the input by however many
	 * reset intervals the file spans and multiplies the apparent ratio by
	 * the same number. A file over eight intervals reads as expanding
	 * eight times harder than it does, and an ordinary 5x one crosses a
	 * bound set at 32 and is cut to a megabyte for no reason the file
	 * gave.
	 *
	 * oc_unpack_lzx, which is the same decode with the pieces joined instead
	 * of restarted, already sums them - see its expand_limit(total, take).
	 * These two answered differently about the same question.
	 */
	{
		uint64_t in_all = 0;

		for (i = 0; i < n; i++)
			in_all += kof_clip_len(b.n, ext[i].off, ext[i].len);
		snk.left = expand_limit(in_all, take);
	}

	for (i = 0; i < n && take; i++) {
		uint64_t off = ext[i].off;
		uint64_t len = kof_clip_len(b.n, off, ext[i].len);
		const struct kuncoat_lzx_req rq = { window_bits, skip, take };
		struct kuncoat_io io = {
			.in = { b.p + off, len },
			.sink = oc_expand_sink_fn, .user = &snk,
		};

		if (!len)
			break;
		st = kuncoat_lzx_decode(sc->cache.lzx, &rq, &io);
		got += io.produced;
		/*
		 * Truncation is not an error, for the reason the DEFLATE path
		 * gives - and on every range but the last it is the ORDINARY
		 * end: the range holds one interval's bytes and the decoder
		 * asks for the next one's, which is not there because the next
		 * range is where they are. UNSUPPORTED is this decoder's way of
		 * saying the stream asked for x86 call translation, which it
		 * does not undo - the bytes are right everywhere except a few
		 * per frame, and saying so is better than either silence or a
		 * refusal.
		 */
		if (st != KUNCOAT_OK && st != KUNCOAT_TRUNCATED &&
		    st != KUNCOAT_STOPPED)
			break;
		if (st == KUNCOAT_STOPPED)
			break;         /* the receiver has had enough */
		if (!io.produced)
			break;         /* no progress: another pass would not
					* make any either */
		take -= io.produced;
		skip = 0;              /* only the first range holds the run-up */
	}

	oc_stream_note(sc, st, STREAM_PARTIAL | STREAM_FILLED, &snk);
	return got;
}

/*
 * LZX WHERE THE PIECES ARE ONE STREAM, which is what a cabinet folder is.
 *
 * A folder is compressed end to end and then cut into CFDATA blocks, each with
 * a header in front of it. The coding knows nothing about that cut - it is not
 * a restart, the trees and the window carry straight across it - so the pieces
 * are joined back into the stream they were and decoded once. That is the whole
 * difference from oc_unpack_lzx_reset, and getting it the wrong way round decodes
 * the first piece and produces refuse from the second.
 *
 * The join costs a copy of the folder's compressed bytes, charged to the
 * resident budget the same way the STORED join is. It is not avoidable: the
 * decoder takes a buffer, and the pieces are not adjacent in the object.
 */
uint64_t oc_unpack_lzx(struct kof_scanner *sc,
			   const struct kof_obj_ctx *ctx, uint32_t index,
			   uint32_t window_bits, uint64_t out_hint)
{
	struct kof_range *ext = sc->cache.ext_gather;
	struct expand_sink snk;
	enum kuncoat_status st;
	kof_buf b;
	uint8_t *in;
	uint64_t total = 0, skip, take, got = 0;
	uint32_t n;

	if (!ctx->resolve_entry || !oc_can_produce(sc))
		return 0;
	skip = out_hint >> 32;
	take = out_hint & 0xffffffffu;
	if (!take)
		return 0;
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	b = kof_src_buf(sc->cur.src);
	if (!sc->cache.lzx) {
		sc->cache.lzx = malloc(sizeof *sc->cache.lzx);
		if (!sc->cache.lzx) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
	}
	in = oc_entry_join(sc, b, ext, n, &total);
	if (!in)
		return 0;

	snk.ctx = ctx;
	snk.left = expand_limit(total, take);
	{
		const struct kuncoat_lzx_req rq = { window_bits, skip, take };
		struct kuncoat_io io = {
			.in = { in, total },
			.sink = oc_expand_sink_fn, .user = &snk,
		};

		st = kuncoat_lzx_decode(sc->cache.lzx, &rq, &io);
		got = io.produced;
	}
	oc_stream_note(sc, st, STREAM_PARTIAL | STREAM_FILLED, &snk);

	free(in);
	oc_scan_release(sc, total);
	return got;
}
