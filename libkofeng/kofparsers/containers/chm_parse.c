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
#include "../rangelist.h"

#define CHM_ITSF_MIN   0x60u     /* through the v3 content offset */
#define CHM_ITSP_MIN   0x54u
#define CHM_CHUNK_HEAD 0x14u     /* "PMGL", free space, unused, prev, next */
#define CHM_CHUNK_MIN  0x40u
#define CHM_CHUNK_MAX  0x10000u

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
			continue;
		}
		if (chm_traversal(f, name_at, name_len))
			c->anomalies |= KOF_CHM_ANOM_TRAVERSAL;

		/*
		 * SECTION 0 IS THE UNCOMPRESSED ONE, and it is the only one
		 * this build can point at. Everything else is LZX - see chm.h
		 * for why that is counted rather than reported as damage.
		 */
		if (sect != 0) {
			c->n_compressed++;
			continue;
		}
		if (!len)
			continue;      /* a directory marker, not a file */

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

done:
	ctx->format = KOF_FMT_CHM;
	ctx->obj_size = file.n;
	ctx->file_header = c;
	ctx->resolve_scan = chm_resolve_scan;
	ctx->entries = chm_entries;
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
		"ENTRY_PAST_EOF", "TRAVERSAL", "ENTRIES_FULL"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_CHM_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
