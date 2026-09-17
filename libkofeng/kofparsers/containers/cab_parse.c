/*
 * cab_parse.c - the cabinet's three tables, walked and bounded.
 *
 * CFHEADER says where the file table is and how many folders and files there
 * are; the folders follow the header; the files are at coffFiles; the data
 * blocks are wherever the folders point. Everything here is little endian and
 * everything here came out of the file.
 *
 * THE ONE PIECE OF ARITHMETIC WORTH EXPLAINING is how a file becomes a range.
 * A CFFILE names a folder and an offset INSIDE that folder's decoded stream,
 * and a folder's stream is the concatenation of its CFDATA payloads - which are
 * separated in the object by eight byte block headers. So for an UNCOMPRESSED
 * folder the walk below accumulates each block's extent and finds which block
 * an offset lands in; a file that fits inside one block is a contiguous range
 * and becomes a child, and a file that crosses a block boundary is not one
 * range at all and is counted rather than half described.
 *
 * A COMPRESSED folder has no such mapping - see cab.h - so its files are
 * counted and left alone.
 */

#include <string.h>

#include "cab_parse.h"
#include "../rangelist.h"

#define CAB_HDR_MIN    36u      /* through iCabinet */
#define CAB_FOLDER_LEN 8u
#define CAB_FILE_MIN   17u      /* the fixed part, plus at least one name byte */
#define CAB_DATA_HDR   8u       /* csum, cbData, cbUncomp */
#define CAB_BLOCK_MAX  0x8000u  /* the format's own ceiling on a block */

/* ---- regions ----------------------------------------------------------------- */

static uint32_t cab_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_cab_info *c = (const struct kof_cab_info *)ctx->file_header;
	struct kof_rlist l;

	if (!c || !c->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);
	if (mask & KOF_SCAN_CAB_HEADERS)
		kof_rl_add(&l, ctx->obj_size, 0,
			   c->folders_off ? c->folders_off : CAB_HDR_MIN);
	if (mask & KOF_SCAN_CAB_FOLDERS)
		kof_rl_add(&l, ctx->obj_size, c->folders_off, c->folders_len);
	if (mask & KOF_SCAN_CAB_NAMES)
		kof_rl_add(&l, ctx->obj_size, c->names_off, c->names_len);
	if (mask & KOF_SCAN_CAB_DATA) {
		/*
		 * From the first block to the end of the object.
		 *
		 * A cabinet states where its data BEGINS and not where it ends,
		 * and what follows the last block is either padding or
		 * something appended - which is the shape worth seeing, so it
		 * lands in DATA rather than being guessed into UNCLAIMED. The
		 * size the header declares is checked separately, and a
		 * mismatch is its own anomaly.
		 */
		uint64_t from = c->data_off;

		if (from < c->names_off + c->names_len)
			from = c->names_off + c->names_len;
		if (from < ctx->obj_size)
			kof_rl_add(&l, ctx->obj_size, from,
				   ctx->obj_size - from);
	}

	if (mask & KOF_SCAN_CAB_UNCLAIMED) {
		/* The complement, obtained by asking for everything else - see
		 * the note in pe_parse.c on why the claimants are not listed
		 * twice. */
		struct kof_range cv[8];
		struct kof_rlist cl;

		kof_rl_init(&cl, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		cl.n = cab_resolve_scan(ctx, KOF_SCAN_CAB_CLAIMED, cv, cl.cap);
		kof_rl_complement(&l, &cl, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

static uint32_t cab_entries(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out)
{
	const struct kof_cab_info *c = (const struct kof_cab_info *)ctx->file_header;

	if (!c || !c->valid || !out)
		return 0;
	*out = c->entry;
	return c->n_entries;
}

/*
 * THE PIECES OF ONE SCATTERED ENTRY, out of the pool the parse filled.
 *
 * Read from the view and never from the object, which is not a preference: the
 * host hands this a context and a range array, not the bytes, so an answer that
 * needed to walk block headers could not be given here at all. See the pool in
 * cab.h, and docole_resolve_entry, which is the same arrangement for the same
 * reason.
 */
static uint32_t cab_resolve_entry(const struct kof_obj_ctx *ctx, uint32_t index,
				  struct kof_range *out, uint32_t max_out)
{
	const struct kof_cab_info *c = (const struct kof_cab_info *)ctx->file_header;
	uint32_t i, n;

	if (!c || !c->valid || !out || !max_out || index >= c->n_entries)
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

/*
 * EVERY BLOCK OF ONE FOLDER, as ranges over the coded bytes.
 *
 * For a coding the host decodes block by block - MSZIP - the pieces are the
 * folder's blocks and not the file's extent: a file is a range of what the
 * blocks DECODE to, and a deflate stream cannot be entered part way, so
 * reaching a file means running the folder from its first block.
 *
 * The range covers the block's payload INCLUDING the two byte "CK", because
 * that is what the host checks before decoding - see unpack_mszip.
 */
static uint32_t cab_blocks(kof_buf f, struct kof_cab_info *c,
			   const struct kof_cab_folder *fo, uint32_t *first_run)
{
	uint64_t at = fo->data_off;
	uint32_t i, n = 0;

	*first_run = c->n_runs;
	for (i = 0; i < fo->n_blocks; i++) {
		uint16_t comp = 0, uncomp = 0;

		if (!kof_rd_u16(f, at + 4u, 0, &comp) ||
		    !kof_rd_u16(f, at + 6u, 0, &uncomp))
			break;
		if (comp > CAB_BLOCK_MAX || uncomp > CAB_BLOCK_MAX ||
		    at + CAB_DATA_HDR + comp > f.n)
			break;
		if (c->n_runs >= KOF_CAB_MAX_RUNS) {
			c->n_runs = *first_run;
			return 0;
		}
		c->run[c->n_runs].off = at + CAB_DATA_HDR;
		c->run[c->n_runs].len = comp;
		c->n_runs++;
		n++;
		at += CAB_DATA_HDR + comp;
	}
	return n;
}

/*
 * Cut one stored file into the pieces the blocks leave it in.
 *
 * Returns how many pieces were recorded, or zero when they do not fit what is
 * left of the pool - in which case the caller counts the file and does not
 * offer it, which is the honest answer rather than a truncated one.
 *
 * Bounded the same way cab_map is: by the folder's own block count, by each
 * block's declared length against the object, and now by the pool.
 */
static uint32_t cab_cut(kof_buf f, struct kof_cab_info *c,
			const struct kof_cab_folder *fo, uint64_t want,
			uint64_t left, uint32_t *first_run)
{
	uint64_t at = fo->data_off, seen = 0;
	uint32_t i, n = 0;

	*first_run = c->n_runs;
	for (i = 0; i < fo->n_blocks && left; i++) {
		uint16_t comp = 0, uncomp = 0;
		uint64_t take, from;

		if (!kof_rd_u16(f, at + 4u, 0, &comp) ||
		    !kof_rd_u16(f, at + 6u, 0, &uncomp))
			break;
		if (comp > CAB_BLOCK_MAX || uncomp > CAB_BLOCK_MAX ||
		    at + CAB_DATA_HDR + comp > f.n)
			break;
		if (want >= seen + uncomp) {
			seen += uncomp;
			at += CAB_DATA_HDR + comp;
			continue;
		}
		if (c->n_runs >= KOF_CAB_MAX_RUNS) {
			c->n_runs = *first_run;       /* give the pieces back */
			return 0;
		}
		from = want > seen ? want - seen : 0;
		take = (uint64_t)uncomp - from;
		if (take > left)
			take = left;
		c->run[c->n_runs].off = at + CAB_DATA_HDR + from;
		c->run[c->n_runs].len = take;
		c->n_runs++;
		n++;
		left -= take;
		want += take;
		seen += uncomp;
		at += CAB_DATA_HDR + comp;
	}
	if (left) {
		c->n_runs = *first_run;               /* incomplete: none of it */
		return 0;
	}
	return n;
}

/* ---- helpers ------------------------------------------------------------------ */

/* A NUL terminated string in the object, as a length - or 0 when it is not
 * terminated inside `cap` bytes, which is the only answer a walk can act on. */
static uint32_t cab_strlen(kof_buf f, uint64_t at, uint32_t cap)
{
	uint32_t i;

	for (i = 0; i < cap; i++) {
		uint8_t b;

		if (!kof_rd_u8(f, at + i, &b))
			return 0;
		if (!b)
			return i + 1u;    /* including the terminator */
	}
	return 0;
}

/* The same question tar and chm ask of their own names, and the answer is a
 * FACT recorded rather than a refusal: nothing here extracts a cabinet, so the
 * interest is in what the file was built to do. */
static int cab_traversal(kof_buf f, uint64_t at, uint32_t len)
{
	uint32_t i;

	for (i = 0; i + 1u < len; i++) {
		uint8_t a, b;

		if (!kof_rd_u8(f, at + i, &a) || !kof_rd_u8(f, at + i + 1u, &b))
			return 0;
		if (a == '.' && b == '.')
			return 1;
		if (i == 0 && (a == '\\' || a == '/' || b == ':'))
			return 1;
	}
	return 0;
}

/*
 * WHERE AN OFFSET INSIDE AN UNCOMPRESSED FOLDER LANDS IN THE OBJECT.
 *
 * Walks the folder's blocks accumulating their uncompressed extents, and
 * answers with the object offset and how much of the FILE is contiguous from
 * there. `*ok` is cleared when the block chain runs out, which a truncated
 * cabinet does.
 *
 * Bounded by the folder's own block count and by the object: a block header
 * that claims a huge length moves the walk past the end, and the loop stops
 * there rather than wrapping.
 */
static uint64_t cab_map(kof_buf f, const struct kof_cab_folder *fo,
			uint64_t want_off, uint64_t want_len,
			uint64_t *avail, int *ok)
{
	uint64_t at = fo->data_off, seen = 0;
	uint32_t i;

	*ok = 0;
	*avail = 0;
	for (i = 0; i < fo->n_blocks; i++) {
		uint16_t comp = 0, uncomp = 0;

		if (!kof_rd_u16(f, at + 4u, 0, &comp) ||
		    !kof_rd_u16(f, at + 6u, 0, &uncomp))
			return 0;
		if (comp > CAB_BLOCK_MAX || uncomp > CAB_BLOCK_MAX)
			return 0;
		if (at + CAB_DATA_HDR + comp > f.n)
			return 0;
		if (want_off < seen + uncomp) {
			uint64_t in_block = want_off - seen;

			*ok = 1;
			*avail = (uint64_t)uncomp - in_block;
			if (*avail > want_len)
				*avail = want_len;
			return at + CAB_DATA_HDR + in_block;
		}
		seen += uncomp;
		at += CAB_DATA_HDR + comp;
	}
	return 0;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_cab_sniff(kof_buf file)
{
	uint32_t res = 1;

	if (!kof_in_range(file, 0, CAB_HDR_MIN) ||
	    memcmp(file.p, "MSCF", 4) != 0)
		return 0;
	kof_rd_u32(file, 4, 0, &res);
	return res == 0u;
}

int kof_cab_parse(kof_buf file, struct kof_cab_info *c, struct kof_obj_ctx *ctx)
{
	uint64_t at;
	uint32_t hdr_res = 0, i;
	uint8_t  fold_res = 0, data_res = 0;

	memset(c, 0, sizeof *c);
	c->version = KOF_CAB_INFO_VERSION;

	if (!kof_in_range(file, 0, CAB_HDR_MIN) || memcmp(file.p, "MSCF", 4) != 0)
		return 0;
	c->valid = 1;

	{
		uint32_t u32;
		uint16_t u16;

		kof_rd_u32(file, 8, 0, &u32);
		c->declared_size = u32;
		kof_rd_u32(file, 16, 0, &u32);
		c->files_off = u32;
		kof_rd_u8(file, 24, &c->ver_minor);
		kof_rd_u8(file, 25, &c->ver_major);
		kof_rd_u16(file, 26, 0, &c->n_folders);
		kof_rd_u16(file, 28, 0, &c->n_files);
		kof_rd_u16(file, 30, 0, &u16);
		c->flags = u16;
		kof_rd_u16(file, 32, 0, &c->set_id);
		kof_rd_u16(file, 34, 0, &c->cab_index);
	}

	if (c->declared_size != file.n)
		c->anomalies |= KOF_CAB_ANOM_SIZE_MISMATCH;
	if (c->flags & (KOF_CAB_F_PREV_CABINET | KOF_CAB_F_NEXT_CABINET))
		c->anomalies |= KOF_CAB_ANOM_SPANNED;

	/*
	 * THE OPTIONAL PART OF THE HEADER, which is what moves the folder table.
	 *
	 * Three reserve sizes and up to four NUL terminated names, each present
	 * only when a flag says so. Getting this wrong does not fail - it lands
	 * the folder walk on the wrong bytes, which then parse as folders and
	 * point anywhere. So every piece is bounded and a name that is not
	 * terminated inside the object stops the walk.
	 */
	at = CAB_HDR_MIN;
	if (c->flags & KOF_CAB_F_RESERVE) {
		uint16_t cb = 0;

		if (!kof_rd_u16(file, at, 0, &cb)) {
			c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
			goto done;
		}
		hdr_res = cb;
		kof_rd_u8(file, at + 2u, &fold_res);
		kof_rd_u8(file, at + 3u, &data_res);
		at += 4u + hdr_res;
	}
	{
		int k;

		for (k = 0; k < 4; k++) {
			uint32_t n;
			int want = (k < 2) ? (c->flags & KOF_CAB_F_PREV_CABINET)
					   : (c->flags & KOF_CAB_F_NEXT_CABINET);

			if (!want)
				continue;
			n = cab_strlen(file, at, KOF_CAB_MAX_NAME);
			if (!n) {
				c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
				goto done;
			}
			at += n;
		}
	}

	if (at >= file.n) {
		c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
		goto done;
	}
	c->folders_off = at;

	/*
	 * The folders. Bounded by what the object could hold as well as by the
	 * count the header states: the two multiply, and the header's number is
	 * sixteen bits of somebody else's choosing.
	 */
	{
		uint64_t each = CAB_FOLDER_LEN + fold_res;
		uint64_t room = (file.n - at) / each;
		uint32_t n = c->n_folders;

		if ((uint64_t)n > room) {
			c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
			n = (uint32_t)room;
		}
		if (n > KOF_CAB_MAX_FOLDERS)
			n = KOF_CAB_MAX_FOLDERS;
		c->n_folders = (uint16_t)n;
		c->folders_len = (uint64_t)n * each;

		for (i = 0; i < n; i++) {
			uint64_t fat = at + (uint64_t)i * each;
			uint32_t off = 0;
			uint16_t blocks = 0, comp = 0;

			kof_rd_u32(file, fat, 0, &off);
			kof_rd_u16(file, fat + 4u, 0, &blocks);
			kof_rd_u16(file, fat + 6u, 0, &comp);
			c->folder[i].data_off = off;
			c->folder[i].n_blocks = blocks;
			c->folder[i].compress = (uint16_t)(comp & 0x000fu);
			if (c->folder[i].compress != KOF_CAB_C_NONE)
				c->anomalies |= KOF_CAB_ANOM_CODED;
			if (!c->data_off || off < c->data_off)
				c->data_off = off;
		}
	}

	/* ---- the files ---------------------------------------------------- */

	if (c->files_off < CAB_HDR_MIN || c->files_off >= file.n) {
		c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
		goto done;
	}
	c->names_off = c->files_off;
	at = c->files_off;

	for (i = 0; i < c->n_files; i++) {
		uint32_t size = 0, foff = 0, nlen;
		uint16_t ifold = 0;
		uint64_t name_at;

		if (at + CAB_FILE_MIN > file.n) {
			c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
			break;
		}
		kof_rd_u32(file, at, 0, &size);
		kof_rd_u32(file, at + 4u, 0, &foff);
		kof_rd_u16(file, at + 8u, 0, &ifold);
		name_at = at + 16u;
		nlen = cab_strlen(file, name_at, KOF_CAB_MAX_NAME);
		if (!nlen) {
			c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
			break;
		}
		at = name_at + nlen;

		if (cab_traversal(file, name_at, nlen - 1u))
			c->anomalies |= KOF_CAB_ANOM_TRAVERSAL;

		/*
		 * iFolder above 0xfffc is one of the format's continuation
		 * markers - a file whose bytes begin in the previous cabinet or
		 * end in the next. There is nothing here to point at either
		 * way, so it counts as spanned rather than as a bad folder.
		 */
		if (ifold >= 0xfffdu) {
			c->anomalies |= KOF_CAB_ANOM_SPANNED;
			c->n_coded++;
			continue;
		}
		if (ifold >= c->n_folders) {
			c->anomalies |= KOF_CAB_ANOM_BAD_FOLDER;
			continue;
		}
		if (!size)
			continue;      /* an empty file names nothing to open */

		/*
		 * A CODED FOLDER: the pieces are its BLOCKS, not the file's.
		 *
		 * MSZIP is the one this build decodes - see KOF_UNP_MSZIP - and
		 * what it needs is every block of the folder in order, because
		 * the file's bytes are somewhere inside what they decode to and
		 * a deflate stream cannot be entered part way. So the entry is
		 * scattered over the whole folder and carries where in the
		 * decoded stream the file sits.
		 *
		 * The other two codings, LZX and Quantum, have no decoder here;
		 * their files are counted and not offered, which is the same
		 * answer this build gives everywhere it lacks a coding.
		 */
		if (c->folder[ifold].compress != KOF_CAB_C_NONE) {
			uint32_t first = 0, runs;

			c->n_coded++;
			if (c->folder[ifold].compress != KOF_CAB_C_MSZIP)
				continue;
			if (c->n_entries >= KOF_CAB_MAX_FILES) {
				c->anomalies |= KOF_CAB_ANOM_FILES_FULL;
				break;
			}
			runs = cab_blocks(file, c, &c->folder[ifold], &first);
			if (!runs)
				continue;
			{
				struct kof_entry *e = &c->entry[c->n_entries];

				memset(e, 0, sizeof *e);
				e->index    = c->n_entries;
				e->kind     = KOF_ENT_EMBEDDED;
				e->format   = KOF_FMT_UNKNOWN;
				e->flags    = KOF_ENT_F_SCATTERED;
				e->name_off = name_at;
				e->name_len = nlen - 1u;
				e->len      = size;
				/* Where the file is inside the folder's decoded
				 * stream, which is what the decoder is told and
				 * what a range cannot say. */
				e->out_hint = ((uint64_t)foff << 32) | size;
				c->split[c->n_entries].first_run = first;
				c->split[c->n_entries].n_run = runs;
				c->coded[c->n_entries] = 1;
				c->n_entries++;
			}
			continue;
		}

		{
			uint64_t avail = 0, off;
			int ok = 0;

			off = cab_map(file, &c->folder[ifold], foff, size,
				      &avail, &ok);
			if (!ok) {
				c->anomalies |= KOF_CAB_ANOM_ENTRY_PAST_EOF;
				continue;
			}
			/*
			 * A FILE THAT CROSSES A BLOCK BOUNDARY IS NOT ONE
			 * RANGE, because the next block's header sits in the
			 * middle of it - a child holding a block header in its
			 * middle is a different file.
			 *
			 * So it is recorded as SCATTERED and its pieces go in
			 * the pool: the host joins them through resolve_entry.
			 * It used to be counted and dropped, which quietly lost
			 * EVERY STORED FILE OVER 32KB - a block is at most that
			 * and any file larger than one has a boundary in it.
			 */
			if (avail < size) {
				uint32_t first = 0;
				uint32_t runs;

				if (c->n_entries >= KOF_CAB_MAX_FILES) {
					c->anomalies |= KOF_CAB_ANOM_FILES_FULL;
					break;
				}
				runs = cab_cut(file, c, &c->folder[ifold],
					       foff, size, &first);
				c->n_split++;
				if (!runs)
					continue;     /* said by the count */
				{
					struct kof_entry *e =
						&c->entry[c->n_entries];

					memset(e, 0, sizeof *e);
					e->index    = c->n_entries;
					e->kind     = KOF_ENT_EMBEDDED;
					e->format   = KOF_FMT_UNKNOWN;
					e->flags    = KOF_ENT_F_SCATTERED;
					e->name_off = name_at;
					e->name_len = nlen - 1u;
					e->len      = size;
					c->split[c->n_entries].first_run = first;
					c->split[c->n_entries].n_run = runs;
					c->n_entries++;
				}
				continue;
			}
			if (off > file.n || size > file.n - off) {
				c->anomalies |= KOF_CAB_ANOM_ENTRY_PAST_EOF;
				continue;
			}
			if (c->n_entries >= KOF_CAB_MAX_FILES) {
				c->anomalies |= KOF_CAB_ANOM_FILES_FULL;
				break;
			}
			{
				struct kof_entry *e = &c->entry[c->n_entries];

				memset(e, 0, sizeof *e);
				e->index    = c->n_entries;
				e->kind     = KOF_ENT_EMBEDDED;
				e->format   = KOF_FMT_UNKNOWN;
				e->name_off = name_at;
				e->name_len = nlen - 1u;
				e->off      = off;
				e->len      = size;
				c->n_entries++;
			}
		}
	}
	c->names_len = at > c->names_off ? at - c->names_off : 0;

done:
	ctx->format = KOF_FMT_CAB;
	ctx->obj_size = file.n;
	ctx->file_header = c;
	ctx->resolve_scan = cab_resolve_scan;
	ctx->entries = cab_entries;
	ctx->resolve_entry = cab_resolve_entry;
	/* No architecture and no entry point: a container is not code - the
	 * same note every other container's parse ends on. */
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_cab_region_bits[] = { CAB_REGIONS(X_BIT) };
_Static_assert(sizeof kof_cab_region_bits / sizeof kof_cab_region_bits[0] ==
	       KOF_CAB_REGION_COUNT, "region list and its count disagree");

const char *kof_cab_region_name(uint32_t bit)
{
	switch (bit) {
	CAB_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_cab_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"TRUNCATED", "SIZE_MISMATCH", "SPANNED", "CODED",
		"BAD_FOLDER", "ENTRY_PAST_EOF", "TRAVERSAL", "FILES_FULL"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_CAB_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
