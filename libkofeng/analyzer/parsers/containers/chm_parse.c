/*
 * chm_parse.c - the ITSS filesystem inside a .chm, as far as it can be walked
 * without decoding anything.
 *
 * THE SHAPE, in the order this reads it:
 *
 *   ITSF      the file header. Says where the two header sections are and, in
 *             version 3, where the content area begins.
 *   ITSP      the directory header, in header section 1. Says how large a
 *             directory chunk is and how many there are.
 *   PMGL      a directory chunk holding entries. PMGI chunks are the index over
 *             them and hold no entries, so they are skipped rather than walked.
 *   entry     a name, and three numbers: which content section, where in it,
 *             and how long.
 *
 * EVERY NUMBER HERE CAME OUT OF THE FILE. The chunk count, the chunk size, the
 * name length, the entry offset and length - all of them are fields somebody
 * else wrote, and each one is bounded before it is used. That is not defensive
 * habit: a directory that claims four billion chunks and a name that claims to
 * be the whole object are the two cheapest things to write into a CHM, and
 * neither is a case a real file ever reaches.
 */

#include <string.h>

#include "chm_parse.h"
#include "../../../kofcore/rangelist.h"

#define CHM_ITSF_MIN   0x60u     /* through the v3 content offset */
#define CHM_ITSP_MIN   0x54u
#define CHM_CHUNK_HEAD 0x14u     /* "PMGL", free space, unused, prev, next */
#define CHM_CHUNK_MIN  0x40u
#define CHM_CHUNK_MAX  0x10000u
#define CHM_RESET_MIN  0x28u     /* the reset table header, through block size */
#define CHM_FRAME      0x8000u   /* what the block size is when it is not said */

/* ---- the variable length integer the directory is written in ----------------
 *
 * Seven bits per byte, most significant group first, high bit set on every byte
 * but the last. Bounded to five bytes: the values it carries are lengths and
 * offsets inside a file, and a run of continuation bytes longer than that is
 * either a value that cannot be one or a walk that has lost its place.
 */
static int chm_encint(kof_buf f, uint64_t *at, uint64_t end, uint64_t *out)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 5; i++) {
		uint8_t b;

		if (*at >= end || !kof_rd_u8(f, *at, &b))
			return 0;
		(*at)++;
		v = (v << 7) | (uint64_t)(b & 0x7fu);
		if (!(b & 0x80u)) {
			*out = v;
			return 1;
		}
	}
	return 0;
}

/* ---- regions ----------------------------------------------------------------- */

static uint32_t chm_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_chm_info *c = (const struct kof_chm_info *)ctx->file_header;
	struct kof_rlist l;

	if (!c || !c->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);
	if (mask & KOF_SCAN_CHM_HEADERS)
		kof_rl_add(&l, ctx->obj_size, 0,
			   c->dir_off ? c->dir_off : CHM_ITSF_MIN);
	if (mask & KOF_SCAN_CHM_DIRECTORY)
		kof_rl_add(&l, ctx->obj_size, c->dir_off, c->dir_len);
	if (mask & KOF_SCAN_CHM_CONTENT) {
		/*
		 * To the end of the object, because nothing in a CHM says where
		 * the content stops. The sections declare where they BEGIN;
		 * what follows the last one is the last one, and anything
		 * appended to the file lands in it. That is the honest split -
		 * a region that guessed an end would put an appended payload in
		 * UNCLAIMED on one file and in CONTENT on the next.
		 *
		 * STARTING AFTER THE DIRECTORY, whatever the header said. The
		 * content offset is a field like any other, and one that points
		 * back into the directory would put those bytes in two regions
		 * at once - which breaks the partition every region mask here
		 * rests on, in a way that shows up as bytes searched twice
		 * rather than as an error. The ENTRIES still use the declared
		 * offset: a region must partition, an entry must be honest, and
		 * the host clips an entry against the object anyway.
		 */
		uint64_t from = c->content_off;
		uint64_t dir_end = c->dir_off + c->dir_len;

		if (from < dir_end)
			from = dir_end;
		if (from < ctx->obj_size)
			kof_rl_add(&l, ctx->obj_size, from,
				   ctx->obj_size - from);
	}

	if (mask & KOF_SCAN_CHM_UNCLAIMED) {
		/* The complement, obtained by asking for everything else - see
		 * the note in pe_parse.c on why the claimants are not listed
		 * twice. */
		struct kof_range cv[8];
		struct kof_rlist cl;

		kof_rl_init(&cl, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		cl.n = chm_resolve_scan(ctx, KOF_SCAN_CHM_CLAIMED, cv, cl.cap);
		kof_rl_complement(&l, &cl, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

static uint32_t chm_entries(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out)
{
	const struct kof_chm_info *c = (const struct kof_chm_info *)ctx->file_header;

	if (!c || !c->valid || !out)
		return 0;
	*out = c->entry;
	return c->n_entries;
}

/*
 * THE PIECES OF ONE CODED ENTRY: the compressed bytes of each reset interval it
 * spans, in order, out of the pool the parse filled.
 *
 * Cut at the restarts because a restart is a new stream - see chm.h. An entry
 * with no runs is one the reset table could not place; answering with the
 * stream anyway would decode it from the beginning and hand back a different
 * page, which is the failure this shape exists to make impossible.
 */
static uint32_t chm_resolve_entry(const struct kof_obj_ctx *ctx, uint32_t index,
				  struct kof_range *out, uint32_t max_out)
{
	const struct kof_chm_info *c = (const struct kof_chm_info *)ctx->file_header;
	uint32_t i, n;

	if (!c || !c->valid || !out || !max_out || index >= c->n_entries)
		return 0;
	if (!(c->entry[index].flags & KOF_ENT_F_SCATTERED))
		return 0;
	n = c->split[index].n_run;
	if (!n || c->split[index].first_run + n > c->n_runs)
		return 0;
	if (n > max_out)
		n = max_out;
	for (i = 0; i < n; i++) {
		const uint32_t k = c->split[index].first_run + i;

		out[i].off = c->run[k].off;
		out[i].len = c->run[k].len;
	}
	return n;
}

/* ---- the entries ------------------------------------------------------------- */

/*
 * A NAME THE FORMAT WROTE FOR ITSELF, not content.
 *
 * "::DataSpace/Storage/MSCompressed/Content" is the compressed blob, "#IDXHDR"
 * and its siblings are the index. They are counted separately because a reader
 * asking "what is in this help file" means the pages, and a listing where nine
 * of twelve rows are bookkeeping answers a different question.
 */
static int chm_is_special(kof_buf f, uint64_t off, uint64_t len)
{
	uint8_t b;

	if (!len || !kof_rd_u8(f, off, &b))
		return 0;
	if (b == ':' || b == '#' || b == '$')
		return 1;
	/* "/#IDXHDR" and "/$OBJINST": the same names under the root. */
	if (b == '/' && len > 1u && kof_rd_u8(f, off + 1u, &b))
		return b == '#' || b == '$' || b == ':';
	return 0;
}

/* A path that means to leave wherever it is written - the same question
 * tar_parse asks of its own names, and the answer is a FACT recorded rather
 * than a refusal: a CHM is not extracted by this engine, so the interest is in
 * what the file was built to do. */
static int chm_traversal(kof_buf f, uint64_t off, uint64_t len)
{
	uint64_t i;

	if (len > KOF_CHM_MAX_NAME)
		len = KOF_CHM_MAX_NAME;
	for (i = 0; i + 1u < len; i++) {
		uint8_t a, b;

		if (!kof_rd_u8(f, off + i, &a) || !kof_rd_u8(f, off + i + 1u, &b))
			return 0;
		if (a == '.' && b == '.')
			return 1;
		if (i == 0 && (a == '\\' || (a >= 'A' && a <= 'z' && b == ':')))
			return 1;
	}
	return 0;
}

/* Does the name at `at` end with `tail` - which is how the three entries below
 * are recognised without carrying their full paths, one of which contains a
 * GUID that differs between writers. */
static int chm_name_ends(kof_buf f, uint64_t at, uint64_t len, const char *tail)
{
	uint64_t n = strlen(tail), i;

	if (len < n)
		return 0;
	for (i = 0; i < n; i++) {
		uint8_t b;

		if (!kof_rd_u8(f, at + len - n + i, &b) ||
		    b != (uint8_t)tail[i])
			return 0;
	}
	return 1;
}

/*
 * THE THREE ENTRIES THE COMPRESSED SECTION IS READ THROUGH - see chm.h.
 *
 * Matched on the tail of the name rather than the whole path: the reset table
 * lives under a GUID that is not the same in every writer's output, and a
 * parser that demanded one particular GUID would fail on the files it was
 * meant to read.
 */
static void chm_note_special(kof_buf f, struct kof_chm_info *c, uint64_t name_at,
			     uint64_t name_len, uint64_t off, uint64_t len)
{
	if (chm_name_ends(f, name_at, name_len, "MSCompressed/ControlData")) {
		c->ctrl_off = off;
		c->ctrl_len = len;
	} else if (chm_name_ends(f, name_at, name_len, "InstanceData/ResetTable")) {
		c->reset_off = off;
		c->reset_len = len;
	} else if (chm_name_ends(f, name_at, name_len, "MSCompressed/Content")) {
		c->lzx_off = off;
		c->lzx_len = len;
	}
}

/*
 * One PMGL chunk's entries.
 *
 * `end` is where the entries stop, which is NOT the end of the chunk: a chunk
 * keeps a quickref area at its tail whose length the header states, and walking
 * into it decodes the quickref's offsets as if they were entries. Stated here
 * because the failure is quiet - it produces entries with plausible numbers.
 */
static void chm_chunk(kof_buf f, struct kof_chm_info *c, uint64_t at,
		      uint64_t end)
{
	while (at < end && c->n_entries < KOF_CHM_MAX_ENTRIES) {
		uint64_t name_len = 0, sect = 0, off = 0, len = 0, name_at;
		struct kof_entry *e;

		if (!chm_encint(f, &at, end, &name_len))
			return;
		if (!name_len || name_len > KOF_CHM_MAX_NAME ||
		    at + name_len > end)
			return;
		name_at = at;
		at += name_len;
		if (!chm_encint(f, &at, end, &sect) ||
		    !chm_encint(f, &at, end, &off) ||
		    !chm_encint(f, &at, end, &len))
			return;

		if (chm_is_special(f, name_at, name_len)) {
			c->n_special++;
			/*
			 * THREE OF THEM ARE NOT BOOKKEEPING TO SKIP: they are
			 * how the compressed half is read at all. Recorded by
			 * name, from section 0, which is where the format keeps
			 * its own structures - a compressed ControlData would
			 * be a file that cannot be read without itself.
			 */
			if (sect == 0u && len)
				chm_note_special(f, c, name_at, name_len,
						 c->content_off + off, len);
			continue;
		}
		if (chm_traversal(f, name_at, name_len))
			c->anomalies |= KOF_CHM_ANOM_TRAVERSAL;

		if (!len)
			continue;      /* a directory marker, not a file */

		/*
		 * SECTION 0 IS THE UNCOMPRESSED ONE. Everything else is the LZX
		 * stream, where an entry is not a range of the object at all -
		 * see chm.h.
		 *
		 * Recorded here with its offset in the DECODED stream, and
		 * turned into a restart point and a skip by chm_place_coded
		 * once the walk is over. It cannot be done here: the directory
		 * is sorted by name, "::DataSpace" sorts after "/", and the
		 * three entries that describe the stream are therefore behind
		 * every page that needs them.
		 */
		if (sect != 0) {
			c->n_compressed++;
			e = &c->entry[c->n_entries];
			memset(e, 0, sizeof *e);
			e->index    = c->n_entries;
			e->kind     = KOF_ENT_EMBEDDED;
			e->format   = KOF_FMT_UNKNOWN;
			e->flags    = KOF_ENT_F_SCATTERED;
			e->name_off = name_at;
			e->name_len = name_len;
			e->len      = len;
			e->off      = off;      /* cleared by the fixup */
			c->n_entries++;
			continue;
		}

		e = &c->entry[c->n_entries];
		memset(e, 0, sizeof *e);
		e->index    = c->n_entries;
		e->kind     = KOF_ENT_EMBEDDED;
		e->format   = KOF_FMT_UNKNOWN;
		e->name_off = name_at;
		e->name_len = name_len;
		e->off      = c->content_off + off;
		e->len      = len;
		/* Clipped against the object rather than believed: the host
		 * clips again before windowing, and a row that cannot be true
		 * is better dropped here where the anomaly can be said. */
		if (e->off > f.n || e->len > f.n - e->off) {
			c->anomalies |= KOF_CHM_ANOM_ENTRY_PAST_EOF;
			continue;
		}
		c->n_entries++;
	}
	if (c->n_entries == KOF_CHM_MAX_ENTRIES)
		c->anomalies |= KOF_CHM_ANOM_ENTRIES_FULL;
}

/*
 * WHERE EACH CODED ENTRY IS DECODED FROM, out of the reset table.
 *
 * THE TABLE IS ONE ROW PER FRAME AND NOT ONE PER RESTART - measured on two real
 * help files: escanwin.chm declares 859477 bytes of content, a 32768 byte
 * frame and 27 rows, and 859477 rounds up to exactly 27 frames. Its reset
 * interval is 2, so only every SECOND row is a point the stream can be entered
 * at. Reading the table the other way round - a row per restart - places every
 * file past the first interval at the wrong offset, and the failure is quiet:
 * the decode succeeds and hands back somebody else's page.
 *
 * So an entry at decoded offset `uoff` is reached by rounding its frame DOWN to
 * a multiple of the interval, decoding from the row at that frame, and throwing
 * away what lies between.
 *
 * EVERY NUMBER HERE IS A FIELD. The row size, the row count, where the rows
 * start and how large a frame is are all written in the file, and the loop
 * below multiplies and divides by them.
 */
static void chm_place_coded(kof_buf f, struct kof_chm_info *c)
{
	uint64_t tab;
	uint32_t n = 0, esz = 0, toff = 0, i;

	if (!c->n_compressed)
		return;                /* a help file that stores everything */

	if (c->reset_len >= CHM_RESET_MIN) {
		kof_rd_u32(f, c->reset_off + 4u, 0, &n);
		kof_rd_u32(f, c->reset_off + 8u, 0, &esz);
		kof_rd_u32(f, c->reset_off + 12u, 0, &toff);
		kof_rd_u64(f, c->reset_off + 0x10u, 0, &c->lzx_uncomp_len);
		kof_rd_u64(f, c->reset_off + 0x20u, 0, &c->lzx_frame);
	}
	if (!c->lzx_frame)
		c->lzx_frame = CHM_FRAME;
	tab = c->reset_off + toff;

	/*
	 * Everything the placement needs, tested together because the answer to
	 * any of them missing is the same: there is no restart to decode from,
	 * and the entries stay in the table describable and unopened.
	 */
	if (!n || esz != 8u || toff < CHM_RESET_MIN || toff > c->reset_len ||
	    (uint64_t)n * 8u > c->reset_len - toff ||
	    !c->lzx_window_bits || !c->lzx_reset_interval || !c->lzx_len) {
		c->anomalies |= KOF_CHM_ANOM_NO_RESET_TABLE;
		n = 0;
	}
	c->n_reset = n;

	for (i = 0; i < c->n_entries; i++) {
		struct kof_entry *e = &c->entry[i];
		uint64_t uoff, frame, start, skip, want;
		uint64_t row, per;
		uint32_t first = c->n_runs, runs = 0;

		if (!(e->flags & KOF_ENT_F_SCATTERED))
			continue;
		/*
		 * The decoded offset the walk left here. Cleared because the
		 * entry is SCATTERED and off must not be read as a range of the
		 * object - it was a place to keep the number until the three
		 * describing entries had been seen.
		 */
		uoff = e->off;
		e->off = 0;
		if (!n) {
			c->n_unreachable++;
			continue;
		}
		if (c->lzx_uncomp_len &&
		    (uoff > c->lzx_uncomp_len ||
		     e->len > c->lzx_uncomp_len - uoff)) {
			c->anomalies |= KOF_CHM_ANOM_ENTRY_PAST_EOF;
			c->n_unreachable++;
			continue;
		}
		frame = uoff / c->lzx_frame;
		start = frame - frame % c->lzx_reset_interval;
		skip = uoff - start * c->lzx_frame;
		/* out_hint packs both into one word, so both have to fit in
		 * one half of it - see KOF_UNP_LZX. */
		if (start >= (uint64_t)n || skip > 0xffffffffu ||
		    e->len > 0xffffffffu) {
			c->n_unreachable++;
			continue;
		}

		/*
		 * ONE RUN PER INTERVAL, from the restart in front of the entry
		 * until what the entry needs has been covered.
		 *
		 * `want` counts output from the INTERVAL's start rather than
		 * from the entry's, which is why the skip is part of it: the
		 * first interval spends its first `skip` bytes getting to the
		 * entry, and every interval yields the same `per` whatever is
		 * done with it.
		 */
		per  = (uint64_t)c->lzx_reset_interval * c->lzx_frame;
		want = skip + e->len;
		for (row = start; want && row < (uint64_t)n; row += c->lzx_reset_interval) {
			uint64_t coff = 0, next = row + c->lzx_reset_interval;
			uint64_t cend;

			if (!kof_rd_u64(f, tab + row * 8u, 0, &coff) ||
			    coff >= c->lzx_len)
				break;
			/*
			 * Where this interval's bytes STOP: the next restart,
			 * or the end of the stream for the last one. A range
			 * that ran on would be handed to the decoder as a
			 * continuation of a stream that has already ended.
			 */
			if (next < (uint64_t)n) {
				if (!kof_rd_u64(f, tab + next * 8u, 0, &cend))
					break;
			} else {
				cend = c->lzx_len;
			}
			if (cend > c->lzx_len)
				cend = c->lzx_len;
			if (cend <= coff)
				break;
			if (runs >= KOF_CHM_MAX_ENT_RUNS ||
			    c->n_runs >= KOF_CHM_MAX_RUNS)
				break;
			c->run[c->n_runs].off = c->lzx_off + coff;
			c->run[c->n_runs].len = cend - coff;
			c->n_runs++;
			runs++;
			want = want > per ? want - per : 0;
		}
		if (want) {
			/* Short of what the entry needs: put the pool back and
			 * leave the entry describable and unopened, rather
			 * than offering a piece of a page as the page. */
			c->n_runs = first;
			c->n_unreachable++;
			continue;
		}
		c->split[i].first_run = first;
		c->split[i].n_run = runs;
		e->out_hint = (skip << 32) | e->len;
		/* Named only now: the window comes from ControlData, which the
		 * walk had not seen yet when the entry was recorded. */
		e->coding[0] = (uint16_t)KOF_UNP_LZX_RESET(c->lzx_window_bits);
	}
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_chm_sniff(kof_buf file)
{
	uint32_t v;

	if (!kof_in_range(file, 0, 8) ||
	    memcmp(file.p, "ITSF", 4) != 0)
		return 0;
	if (!kof_rd_u32(file, 4, 0, &v))
		return 0;
	/* Two and three are the versions that exist. Anything else calling
	 * itself ITSF is not a file this walk understands, and claiming it
	 * would take it away from whoever might. */
	return v == 2u || v == 3u;
}

int kof_chm_parse(kof_buf file, struct kof_chm_info *c, struct kof_obj_ctx *ctx)
{
	uint64_t s1_off = 0, s1_len = 0, at, end;
	uint32_t hdr_len = 0, itsp_len = 0, i;

	memset(c, 0, sizeof *c);
	c->version = KOF_CHM_INFO_VERSION;

	if (!kof_in_range(file, 0, 8) || memcmp(file.p, "ITSF", 4) != 0)
		return 0;
	c->valid = 1;
	kof_rd_u32(file, 4, 0, &c->itsf_version);
	kof_rd_u32(file, 8, 0, &hdr_len);
	kof_rd_u32(file, 16, 0, &c->timestamp);
	kof_rd_u32(file, 20, 0, &c->lang_id);
	if (c->itsf_version != 3u)
		c->anomalies |= KOF_CHM_ANOM_OLD_VERSION;

	/* Header section 1 is the directory. Section 0 is a five field block
	 * that says how long the file is, which fstat already said. */
	kof_rd_u64(file, 72, 0, &s1_off);
	kof_rd_u64(file, 80, 0, &s1_len);

	/*
	 * WHERE THE CONTENT BEGINS.
	 *
	 * Version 3 states it outright. Version 2 does not, and what stands in
	 * for it is the end of the header sections - which is a guess, recorded
	 * as one through KOF_CHM_ANOM_OLD_VERSION rather than presented as a
	 * fact. An entry offset is relative to this, so being wrong about it
	 * moves every entry; being wrong SILENTLY would hand the host ranges
	 * that look ordinary and hold the wrong bytes.
	 */
	if (c->itsf_version >= 3u)
		kof_rd_u64(file, 88, 0, &c->content_off);
	if (!c->content_off)
		c->content_off = s1_off + s1_len;

	if (s1_off + CHM_ITSP_MIN > file.n || !s1_len) {
		c->anomalies |= KOF_CHM_ANOM_TRUNCATED;
		goto done;
	}
	if (memcmp(file.p + s1_off, "ITSP", 4) != 0) {
		c->anomalies |= KOF_CHM_ANOM_BAD_DIRECTORY;
		goto done;
	}
	kof_rd_u32(file, s1_off + 8u, 0, &itsp_len);
	kof_rd_u32(file, s1_off + 16u, 0, &c->chunk_size);
	kof_rd_u32(file, s1_off + 44u, 0, &c->n_chunks);

	/*
	 * A chunk size that is not a power of two between 64 and 64K is not a
	 * CHM's - every writer uses 4096 - and a chunk COUNT is bounded by what
	 * the object could hold rather than by what the header claims. Both are
	 * the same defence: the walk below multiplies these two numbers.
	 */
	if (c->chunk_size < CHM_CHUNK_MIN || c->chunk_size > CHM_CHUNK_MAX ||
	    (c->chunk_size & (c->chunk_size - 1u)) != 0u ||
	    itsp_len < CHM_ITSP_MIN) {
		c->anomalies |= KOF_CHM_ANOM_BAD_DIRECTORY;
		goto done;
	}

	c->dir_off = s1_off + itsp_len;
	if (c->dir_off >= file.n) {
		c->anomalies |= KOF_CHM_ANOM_TRUNCATED;
		goto done;
	}
	{
		uint64_t room = (file.n - c->dir_off) / c->chunk_size;

		if ((uint64_t)c->n_chunks > room) {
			c->anomalies |= KOF_CHM_ANOM_TRUNCATED;
			c->n_chunks = (uint32_t)room;
		}
	}
	c->dir_len = (uint64_t)c->n_chunks * c->chunk_size;

	for (i = 0; i < c->n_chunks && c->n_entries < KOF_CHM_MAX_ENTRIES; i++) {
		uint64_t base = c->dir_off + (uint64_t)i * c->chunk_size;
		uint32_t free_space = 0;

		if (!kof_in_range(file, base, CHM_CHUNK_HEAD))
			break;
		if (memcmp(file.p + base, "PMGI", 4) == 0)
			continue;      /* the index over the chunks, not entries */
		if (memcmp(file.p + base, "PMGL", 4) != 0) {
			c->anomalies |= KOF_CHM_ANOM_BAD_CHUNK;
			continue;
		}
		kof_rd_u32(file, base + 4u, 0, &free_space);

		at = base + CHM_CHUNK_HEAD;
		end = base + c->chunk_size;
		/* The quickref area at the tail is not entries - see chm_chunk.
		 * A free-space field larger than the chunk is a file saying so;
		 * the walk then has nothing to read, which is the safe end. */
		if ((uint64_t)free_space <= (uint64_t)c->chunk_size - CHM_CHUNK_HEAD)
			end -= free_space;
		else
			end = at;
		if (end > file.n)
			end = file.n;
		chm_chunk(file, c, at, end);
	}

	/*
	 * WHAT CONTROLDATA SAYS ABOUT THE STREAM, which is not in the stream.
	 *
	 * Six words: a length in words, "LZXC", a version, the reset interval,
	 * the window size and a cache size. The window and the interval are
	 * counted in FRAMES of 32KB, which is why they are shifted rather than
	 * used as they stand - a file saying "window 8" means 256KB, and a
	 * decoder handed 8 would refuse a stream that is perfectly well formed.
	 */
	if (c->ctrl_len >= 6u * 4u) {
		uint32_t magic = 0, ver = 0, interval = 0, window = 0;

		kof_rd_u32(file, c->ctrl_off + 4u, 1, &magic);   /* "LZXC" */
		kof_rd_u32(file, c->ctrl_off + 8u, 0, &ver);
		kof_rd_u32(file, c->ctrl_off + 12u, 0, &interval);
		kof_rd_u32(file, c->ctrl_off + 16u, 0, &window);
		if (magic == 0x4c5a5843u && window && window <= 64u) {
			uint32_t bits = 15u;
			uint32_t frames = window;

			/* frames of 32KB -> a power of two window. */
			while (bits < 21u && (1u << (bits - 15u)) < frames)
				bits++;
			c->lzx_window_bits = bits;
			/* Version 2 counts the interval in frames as well;
			 * version 1 counted it in bytes. Both appear. */
			c->lzx_reset_interval = ver >= 2u
					      ? interval
					      : interval / 32768u;
			if (!c->lzx_reset_interval)
				c->lzx_reset_interval = 1u;
		}
	}

	/* The entries in the coded section are still holding decoded offsets -
	 * turn those into restart points now that all three describing entries
	 * have been seen. */
	chm_place_coded(file, c);

done:
	ctx->format = KOF_FMT_CHM;
	ctx->obj_size = file.n;
	ctx->file_header = c;
	ctx->resolve_scan = chm_resolve_scan;
	ctx->entries = chm_entries;
	ctx->resolve_entry = chm_resolve_entry;
	/* No architecture and no entry point: a container is not code - the
	 * same note every other container's parse ends on. */
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_chm_region_bits[] = { CHM_REGIONS(X_BIT) };
_Static_assert(sizeof kof_chm_region_bits / sizeof kof_chm_region_bits[0] ==
	       KOF_CHM_REGION_COUNT, "region list and its count disagree");

const char *kof_chm_region_name(uint32_t bit)
{
	switch (bit) {
	CHM_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_chm_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"OLD_VERSION", "TRUNCATED", "BAD_DIRECTORY", "BAD_CHUNK",
		"ENTRY_PAST_EOF", "TRAVERSAL", "ENTRIES_FULL",
		"NO_RESET_TABLE"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_CHM_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
