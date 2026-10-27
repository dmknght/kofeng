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
#include "cname.h"
#include "../../../kofcore/rangelist.h"
#include "../../../kofcore/tabgrow.h"

#define CAB_HDR_MIN    36u      /* through iCabinet */
#define CAB_FOLDER_LEN KOF_CAB_FOLDER_MIN
#define CAB_FILE_MIN   KOF_CAB_FILE_MIN
#define CAB_DATA_HDR   KOF_CAB_DATA_HDR
/*
 * THE TWO CEILINGS ON A BLOCK, and they are not the same number.
 *
 * A CFDATA holds at most 32768 bytes of OUTPUT - that is what the format fixes,
 * and it is why a stored file over 32KB is always scattered. What it holds of
 * INPUT can be larger, because a coding that meets bytes it cannot compress
 * emits more than it was given; the format allows a block six kilobytes of
 * slack for that.
 *
 * Bounding the compressed side by 32768 was a real loss and a quiet one: a
 * cabinet's fourth LZX block declares 32795 compressed bytes, the walk stopped
 * there, and the folder was handed to the decoder three blocks long - which
 * decodes, comes back short, and looks like a corrupt archive rather than like
 * a walk that gave up.
 */
#define CAB_BLOCK_MAX  0x8000u  /* cbUncomp: the format's ceiling on output */
#define CAB_CDATA_MAX  0x9800u  /* cbData: that, plus the slack it allows */

/* ---- regions ----------------------------------------------------------------- */

static uint32_t cab_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_cab_info *c = (const struct kof_cab_info *)ctx->file_header;
	struct kof_rlist l;

	if (!c || !c->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);
	/* KNOWN DEFECT WP2-D10 (2026-10-24, M) [sev L]: cab_resolve_scan ends HEADERS at folders_off while NAMES
	 * start at files_off, so a reserve area makes them overlap. Trigger: a header announcing a reserve
	 * area. Effect: HEADERS [0,172) over NAMES [44,186). Reproducer: tests/unit/ctr_regions.c (green
	 * until fixed), tests_wp2/findings/D10_cab_headers_names_overlap.bin. Fix: end HEADERS at
	 * min(folders_off, files_off). */
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
		/* KNOWN DEFECT WP2-D9 (2026-10-24, M) [sev L]: cab_resolve_scan starts DATA after the names only, so
		 * a byte can be in two regions (searched twice). Trigger: a 48 byte cabinet, no files, data
		 * offset 0. Effect: DATA overlaps HEADERS. Reproducer: tests/unit/ctr_regions.c (green until
		 * fixed), tests_wp2/findings/D9_cab_data_region_at_0.bin. Fix: start at max(declared offset,
		 * end of HEADERS, FOLDERS, NAMES). */
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
	return kof_rl_finish(&l);
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

/* ---- the work the parse needs and the view does not keep --------------------------------------- */

/*
 * ONE CFDATA BLOCK, as the walk reads it: where its payload is in the object, where its output
 * begins in the folder's decoded stream, and how long each is.
 */
struct cab_blk {
	uint64_t poff;       /* the payload, past the eight byte header */
	uint64_t ustart;     /* offset of this block's output in the folder's stream */
	uint32_t comp, uncomp;
};

/*
 * WHAT ONE FOLDER IS, once it has been walked: where its blocks are in `bl` and where its pieces
 * are in the view's pool when it is coded. A file reaches its bytes through these and not by
 * walking the folder's block headers from the start - which is what every file did, and what made
 * a cabinet of N files over B blocks cost N times B of header reads, a product the file chooses.
 */
struct cab_fb {
	uint32_t bl_first, bl_n;
	uint32_t run_first, run_n;
	uint8_t  listed;     /* the blocks were walked (to the first one that was not a block) */
	uint8_t  cut;        /* ... and the list is short because a table or the budget gave out */
	uint8_t  shared;     /* the pieces of the coded folder are in the pool */
};

struct cw {
	kof_buf f;
	struct kof_cab_info *c;
	struct cab_blk *bl;
	struct cab_fb *fb;
	uint32_t bl_n, bl_cap, fb_cap;
	uint32_t cap_folder, cap_entry, cap_split, cap_run;
	/* What the FILE can hold of blocks, and what the walk may visit, which is twice that: the
	 * budget that keeps folders aimed at the same blocks from costing more than the file is. */
	uint64_t blk_limit;
	uint64_t ent_limit;
};

static void cw_full(struct cw *w)
{
	w->c->anomalies |= KOF_CAB_ANOM_FILES_FULL;
}

/*
 * THE BLOCKS OF ONE FOLDER, walked once. The same checks as ever: a block header that does not
 * fit the object, or declares more than the format allows, ends the list there - the files past
 * it are not found, and the callers say so. A table or the budget that gives out is the other
 * way a list ends short, and that one says FILES_FULL here.
 */
static int cab_list(struct cw *w, uint32_t ifold)
{
	struct kof_cab_info *c = w->c;
	struct cab_fb *fb = &w->fb[ifold];
	const struct kof_cab_folder *fo = &c->folder[ifold];
	uint64_t at = fo->data_off, ustart = 0;
	uint32_t i;

	if (fb->listed)
		return !fb->cut;
	fb->listed = 1;
	fb->bl_first = w->bl_n;
	for (i = 0; i < fo->n_blocks; i++) {
		uint16_t comp = 0, uncomp = 0;
		struct cab_blk *b;

		if (!kof_rd_u16(w->f, at + 4u, 0, &comp) ||
		    !kof_rd_u16(w->f, at + 6u, 0, &uncomp))
			break;
		if (comp > CAB_CDATA_MAX || uncomp > CAB_BLOCK_MAX ||
		    at + CAB_DATA_HDR + comp > w->f.n)
			break;
		if (w->bl_n >= w->bl_cap) {
			void *t = w->bl;

			if (!kof_tab_grow(&c->mem, &t, &w->bl_cap, sizeof *w->bl,
					  (uint64_t)w->bl_n + 1u, w->blk_limit)) {
				fb->cut = 1;
				cw_full(w);
				break;
			}
			w->bl = (struct cab_blk *)t;
		}
		b = &w->bl[w->bl_n++];
		/* KNOWN DEFECT WP2-D14 (2026-10-24, M) [sev M]: cab_list takes each block payload at CAB_DATA_HDR (8)
		 * and ignores the per-block reserve (data_res is read, never used). Trigger: cbCFData 2.
		 * Effect: every member is shifted by the reserve (right length, first bytes are zeros).
		 * Reproducer: tests/unit/ctr_valid.c cab CRYPT (green until fixed). Fix: keep data_res, use
		 * CAB_DATA_HDR + data_res for poff, the block advance and the length check. */
		b->poff = at + CAB_DATA_HDR;
		b->ustart = ustart;
		b->comp = comp;
		b->uncomp = uncomp;
		ustart += uncomp;
		at += CAB_DATA_HDR + comp;
		fb->bl_n++;
	}
	return !fb->cut;
}

/* The first block of a listed folder whose output ends past `want`: the one a byte of the folder's
 * stream lands in. A search and not a walk, so a file costs the log of the blocks. fb->bl_n when no
 * block reaches that far - a cabinet that was cut. */
static uint32_t cab_block_at(const struct cw *w, const struct cab_fb *fb, uint64_t want)
{
	uint32_t lo = 0, hi = fb->bl_n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		const struct cab_blk *b = &w->bl[fb->bl_first + mid];

		if (b->ustart + b->uncomp > want)
			hi = mid;
		else
			lo = mid + 1u;
	}
	return lo;
}

/* One more piece in the view's pool, or 0 and the pool is as it was. */
static int cab_piece(struct cw *w, uint64_t off, uint64_t len)
{
	struct kof_cab_info *c = w->c;

	if (c->n_runs >= w->cap_run) {
		void *t = c->run;

		if (!kof_tab_grow(&c->mem, &t, &w->cap_run, sizeof *c->run,
				  (uint64_t)c->n_runs + 1u, w->blk_limit)) {
			cw_full(w);
			return 0;
		}
		c->run = (struct kof_cab_run *)t;
	}
	c->run[c->n_runs].off = off;
	c->run[c->n_runs].len = len;
	c->n_runs++;
	return 1;
}

/*
 * EVERY BLOCK OF ONE FOLDER, as ranges over the coded bytes - and in the pool ONCE, whatever
 * the number of files that name it.
 *
 * For a coding the host decodes block by block - MSZIP - the pieces are the folder's blocks and
 * not the file's extent: a file is a range of what the blocks DECODE to, and a deflate stream
 * cannot be entered part way, so reaching a file means running the folder from its first block.
 * That is the same list for every file of the folder, so the entries of a folder share one
 * range of the pool (their `split` rows are equal) instead of each carrying a copy: a coded
 * file used to cost the folder's block count in the pool, which is what made the pool a limit
 * on how many files of a cabinet could be offered.
 *
 * The range covers the block's payload INCLUDING the two byte "CK", because that is what the
 * host checks before decoding - see unpack_mszip.
 */
static uint32_t cab_blocks(struct cw *w, uint32_t ifold, uint32_t *first_run)
{
	struct cab_fb *fb = &w->fb[ifold];
	uint32_t i;

	if (fb->shared) {
		*first_run = fb->run_first;
		return fb->run_n;
	}
	fb->shared = 1;
	if (!cab_list(w, ifold))
		return 0;
	fb->run_first = w->c->n_runs;
	for (i = 0; i < fb->bl_n; i++) {
		const struct cab_blk *b = &w->bl[fb->bl_first + i];

		if (!cab_piece(w, b->poff, b->comp)) {
			/* The file is not offered, and it is said: the pool is a table and this is
			 * what a full one costs. */
			w->c->n_runs = fb->run_first;
			return 0;
		}
	}
	fb->run_n = fb->bl_n;
	*first_run = fb->run_first;
	return fb->run_n;
}

/*
 * Cut one stored file into the pieces the blocks leave it in.
 *
 * Returns how many pieces were recorded, or zero when they do not fit what is left of the pool
 * or the folder's blocks do not reach the end of the file - in which case the caller counts the
 * file and does not offer it, which is the honest answer rather than a truncated one.
 */
static uint32_t cab_cut(struct cw *w, uint32_t ifold, uint64_t want, uint64_t left,
			uint32_t *first_run)
{
	const struct cab_fb *fb = &w->fb[ifold];
	uint32_t k, n = 0;

	*first_run = w->c->n_runs;
	for (k = cab_block_at(w, fb, want); k < fb->bl_n && left; k++) {
		const struct cab_blk *b = &w->bl[fb->bl_first + k];
		uint64_t take, from;

		if (want >= b->ustart + b->uncomp)
			continue;
		from = want > b->ustart ? want - b->ustart : 0;
		take = (uint64_t)b->uncomp - from;
		if (take > left)
			take = left;
		if (!cab_piece(w, b->poff + from, take)) {
			w->c->n_runs = *first_run;    /* give the pieces back */
			return 0;
		}
		n++;
		left -= take;
		want += take;
	}
	if (left) {
		w->c->n_runs = *first_run;            /* incomplete: none of it */
		return 0;
	}
	return n;
}

/*
 * WHERE AN OFFSET INSIDE AN UNCOMPRESSED FOLDER LANDS IN THE OBJECT.
 *
 * Looks the offset up in the folder's block list and answers with the object offset and how much
 * of the FILE is contiguous from there. `*ok` is cleared when no block reaches the offset, which a
 * truncated cabinet does.
 */
static uint64_t cab_map(struct cw *w, uint32_t ifold, uint64_t want_off, uint64_t want_len,
			uint64_t *avail, int *ok)
{
	const struct cab_fb *fb = &w->fb[ifold];
	uint32_t k = cab_block_at(w, fb, want_off);

	*ok = 0;
	*avail = 0;
	if (k < fb->bl_n) {
		const struct cab_blk *b = &w->bl[fb->bl_first + k];
		uint64_t in_block = want_off - b->ustart;

		*ok = 1;
		*avail = (uint64_t)b->uncomp - in_block;
		if (*avail > want_len)
			*avail = want_len;
		return b->poff + in_block;
	}
	return 0;
}

/* One more row of the entry table and of its `split` beside it, or 0 and both are as they were:
 * the file is not offered and the walk of the files stops (FILES_FULL says so). */
static int cab_row(struct cw *w)
{
	struct kof_cab_info *c = w->c;

	if (c->n_entries >= w->cap_entry) {
		void *t = c->entry;

		if (!kof_tab_grow(&c->mem, &t, &w->cap_entry, sizeof *c->entry,
				  (uint64_t)c->n_entries + 1u, w->ent_limit)) {
			cw_full(w);
			return 0;
		}
		c->entry = (struct kof_entry *)t;
	}
	if (c->n_entries >= w->cap_split) {
		void *t = c->split;

		if (!kof_tab_grow(&c->mem, &t, &w->cap_split, sizeof *c->split,
				  (uint64_t)c->n_entries + 1u, w->ent_limit)) {
			cw_full(w);
			return 0;
		}
		c->split = (struct kof_cab_split *)t;
	}
	return 1;
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

/* THE FIXED HEADER: sizes, offsets, version, counts and flags, and the two anomalies
 * that can be read off it alone (a size that is not the object's, a spanned set). */
static void cab_read_header(kof_buf file, struct kof_cab_info *c)
{
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
}

/*
 * THE OPTIONAL PART OF THE HEADER, which moves the folder table: the reserve sizes
 * and the names. Returns 0 when the object ends inside it (nothing further is read),
 * else 1 with c->folders_off set and *fold_res the per-folder reserve.
 */
static int cab_read_optional(kof_buf file, struct kof_cab_info *c, uint8_t *fold_res)
{
	uint64_t at;
	uint32_t hdr_res = 0;
	uint8_t  data_res = 0;

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
			return 0;
		}
		hdr_res = cb;
		kof_rd_u8(file, at + 2u, fold_res);
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
			n = kof_cname_len(file, at, KOF_CAB_MAX_NAME);
			if (!n) {
				c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
				return 0;
			}
			at += n;
		}
	}
	if (at >= file.n) {
		c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
		return 0;
	}
	c->folders_off = at;
	return 1;
}

/* THE FOLDERS: bounded by what the object could hold, and the table is as long as they are. */
static void cab_read_folders(struct cw *w, uint8_t fold_res)
{
	kof_buf file = w->f;
	struct kof_cab_info *c = w->c;
	uint64_t at = c->folders_off;
	uint32_t i;

	/*
	 * The folders. Bounded by what the object could hold as well as by the
	 * count the header states: the two multiply, and the header's number is
	 * sixteen bits of somebody else's choosing. The table is allocated to the
	 * smaller, so what the file says never sizes it past what the file holds.
	 */
	{
		uint64_t each = CAB_FOLDER_LEN + fold_res;
		uint64_t room = (file.n - at) / each;
		uint32_t n = c->n_folders;
		void *t = c->folder;

		if ((uint64_t)n > room) {
			c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
			n = (uint32_t)room;
		}
		/* A table the ledger cannot afford is a shorter one, not none: the files in the
		 * folders past it are unreachable, and that is said. */
		w->cap_folder = 0;
		while (n && !kof_tab_grow(&c->mem, &t, &w->cap_folder, sizeof *c->folder, n, room)) {
			cw_full(w);
			n /= 2u;
		}
		c->folder = (struct kof_cab_folder *)t;
		c->n_folders = (uint16_t)n;
		c->folders_len = (uint64_t)n * each;
		/* The table is the folders' region only up to where the file table begins: a header that
		 * says more folders than lie in front of it would put the file table's bytes in two
		 * regions at once (and the declared count is sixteen bits the file chose). It was clipped
		 * by the fixed table before; the table is the file's size now, so it is clipped here. */
		if (c->files_off > at && c->folders_len > c->files_off - at)
			c->folders_len = c->files_off - at;

		for (i = 0; i < n; i++) {
			uint64_t fat = at + (uint64_t)i * each;
			uint32_t off = 0;
			uint16_t blocks = 0, comp = 0;

			memset(&c->folder[i], 0, sizeof c->folder[i]);
			kof_rd_u32(file, fat, 0, &off);
			kof_rd_u16(file, fat + 4u, 0, &blocks);
			kof_rd_u16(file, fat + 6u, 0, &comp);
			c->folder[i].data_off = off;
			c->folder[i].n_blocks = blocks;
			c->folder[i].compress = (uint16_t)(comp & 0x000fu);
			/* LZX states its window in the high byte, and nothing
			 * else uses that byte - see kof_cab_folder. */
			if (c->folder[i].compress == KOF_CAB_C_LZX)
				c->folder[i].window = (uint16_t)((comp >> 8) &
								 0x1fu);
			if (c->folder[i].compress != KOF_CAB_C_NONE)
				c->anomalies |= KOF_CAB_ANOM_CODED;
			if (!c->data_off || off < c->data_off)
				c->data_off = off;
		}
	}
}

/*
 * A FILE IN A CODED FOLDER, offered as a scattered entry over the folder's blocks.
 * Returns 1 when the file table is full and the walk of the files must stop, else 0.
 */
static int cab_coded_file(struct cw *w, uint16_t ifold, uint32_t size, uint32_t foff,
			  uint64_t name_at, uint32_t nlen)
{
/*
 * A CODED FOLDER: the pieces are its BLOCKS, not the file's.
 *
 * Neither coding this build has can be entered part way, so
 * what they need is every block of the folder in order - the
 * file's bytes are somewhere inside what those blocks decode
 * to. The entry is therefore scattered over the whole folder
 * and carries where in the decoded stream the file sits.
 *
 * WHICH CODING IS THE ENTRY'S OWN, in coding[0], which is what
 * that field is for: MSZIP's blocks are separate streams the
 * host seeds one from the next, LZX's are one stream the host
 * joins, and the two are told apart by the id rather than by a
 * table beside the entries.
 *
 * Quantum has no decoder here; its files are counted and not
 * offered, which is the same answer this build gives everywhere
 * it lacks a coding.
 */
	struct kof_cab_info *c = w->c;
	const struct kof_cab_folder *fo = &c->folder[ifold];
	uint32_t first = 0, runs, method = 0;

	c->n_coded++;
	if (fo->compress == KOF_CAB_C_MSZIP) {
		method = KOF_UNP_MSZIP;
	} else if (fo->compress == KOF_CAB_C_LZX &&
		   fo->window >= KUNCOAT_LZX_MIN_BITS &&
		   fo->window <= KUNCOAT_LZX_MAX_BITS) {
		method = KOF_UNP_LZX(fo->window);
	} else {
		return 0;
	}
	if (!cab_row(w))
		return 1;
	runs = cab_blocks(w, ifold, &first);
	if (!runs)
		return 0;
	{
		struct kof_entry *e = &c->entry[c->n_entries];

		memset(e, 0, sizeof *e);
		e->index     = c->n_entries;
		e->kind      = KOF_ENT_EMBEDDED;
		e->format    = KOF_FMT_UNKNOWN;
		e->flags     = KOF_ENT_F_SCATTERED;
		e->name_off  = name_at;
		e->name_len  = nlen - 1u;
		e->len       = size;
		e->coding[0] = (uint16_t)method;
		/* Where the file is inside the folder's decoded
		 * stream, which is what the decoder is told and
		 * what a range cannot say. */
		e->out_hint = ((uint64_t)foff << 32) | size;
		c->split[c->n_entries].first_run = first;
		c->split[c->n_entries].n_run = runs;
		c->n_entries++;
	}
	return 0;
}

/*
 * A FILE IN A STORED FOLDER: one range, or - when it crosses a block boundary - a
 * scattered entry over the pieces. Returns 1 when the file table is full and the walk
 * of the files must stop, else 0.
 */
static int cab_stored_file(struct cw *w, uint16_t ifold, uint32_t size, uint32_t foff,
			   uint64_t name_at, uint32_t nlen)
{
	struct kof_cab_info *c = w->c;
	uint64_t avail = 0, off;
	int ok = 0;

	if (!cab_list(w, ifold))
		return 0;     /* said by FILES_FULL: the folder's blocks were not all had */
	off = cab_map(w, ifold, foff, size, &avail, &ok);
	/* KNOWN DEFECT WP2-D2 (2026-10-24, M) [sev M]: cab_stored_file drops a file record whose size runs past its
	 * data, saying only an anomaly bit. Trigger: middle member claims 0xfffffff0. Effect: 2 of 3 opened,
	 * broken 0. Reproducer: tests/unit/ctr_liars.c cab/claimBoth (row of WP2-D1). Fix: report it as
	 * broken and keep the table going. */
	if (!ok) {
		c->anomalies |= KOF_CAB_ANOM_ENTRY_PAST_EOF;
		return 0;
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

		if (!cab_row(w))
			return 1;
		runs = cab_cut(w, ifold, foff, size, &first);
		c->n_split++;
		if (!runs)
			return 0;     /* said by the count */
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
		return 0;
	}
	if (off > w->f.n || size > w->f.n - off) {
		c->anomalies |= KOF_CAB_ANOM_ENTRY_PAST_EOF;
		return 0;
	}
	if (!cab_row(w))
		return 1;
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
		/* A plain range has no pieces: the row says so, and says it of this entry and not of
		 * whatever the table held. */
		c->split[c->n_entries].first_run = 0;
		c->split[c->n_entries].n_run = 0;
		c->n_entries++;
	}
	return 0;
}

/* THE FILE TABLE: every file's name and place, as entries - single ranges, scattered
 * block lists, or only counted where this build cannot offer them. */
static void cab_read_files(struct cw *w)
{
	kof_buf file = w->f;
	struct kof_cab_info *c = w->c;
	uint64_t at;
	uint32_t i;

	/* KNOWN DEFECT WP2-D3b (2026-10-24, M) [sev M]: The cab file table is skipped when coffFiles is past EOF
	 * (anomaly bit only). Trigger: coffFiles 0x7ffffff0. Effect: opens as nothing, broken 0. Reproducer:
	 * tests/unit/ctr_liars.c cab/offset (row of WP2-D1). Fix: as WP2-D3, set DAMAGED. */
	if (c->files_off < CAB_HDR_MIN || c->files_off >= file.n) {
		c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
		return;
	}
	c->names_off = c->files_off;
	at = c->files_off;
	/* A file is at least CAB_FILE_MIN bytes of the table that starts here: the rows cannot
	 * exceed that, whatever n_files says (it is sixteen bits the file chose). */
	w->ent_limit = (file.n - at) / CAB_FILE_MIN + 1u;

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
		nlen = kof_cname_len(file, name_at, KOF_CAB_MAX_NAME);
		/* KNOWN DEFECT WP2-D6 (2026-10-24, M) [sev M]: The cab file walk ends the table at a name with a NUL
		 * or past KOF_CAB_MAX_NAME (kof_cname_len answers 0). Trigger: one name with a NUL, or 5000
		 * bytes. Effect: every later file dropped, broken 0, names_invalid 0. Reproducer:
		 * tests/unit/ctr_names.c (green until fixed). Fix: end only that record, resynchronise on the
		 * next plausible one, set names_invalid. */
		if (!nlen) {
			c->anomalies |= KOF_CAB_ANOM_TRUNCATED;
			break;
		}
		at = name_at + nlen;

		if (kof_cname_traversal(file, name_at, nlen - 1u))
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

		if (c->folder[ifold].compress != KOF_CAB_C_NONE) {
			if (cab_coded_file(w, ifold, size, foff, name_at, nlen))
				break;
			continue;
		}
		if (cab_stored_file(w, ifold, size, foff, name_at, nlen))
			break;
	}
	c->names_len = at > c->names_off ? at - c->names_off : 0;
}

/* What a rule reads the cabinet through. */
static void cab_attach(kof_buf file, struct kof_cab_info *c, struct kof_obj_ctx *ctx)
{
	ctx->format = KOF_FMT_CAB;
	ctx->obj_size = file.n;
	ctx->file_header = c;
	ctx->resolve_scan = cab_resolve_scan;
	ctx->entries = cab_entries;
	ctx->resolve_entry = cab_resolve_entry;
	/* No architecture and no entry point: a container is not code - the
	 * same note every other container's parse ends on. */
}

void kof_cab_release(struct kof_cab_info *c)
{
	kof_tab_free((void **)&c->folder);
	kof_tab_free((void **)&c->entry);
	kof_tab_free((void **)&c->split);
	kof_tab_free((void **)&c->run);
	c->n_entries = 0;
	c->n_runs = 0;
	c->mem.held = 0;
	c->mem.rows = 0;
}

KOF_VIEW_HANDLES(cab, struct kof_cab_info, entry, n_entries)

/* The legacy count is inside the view and is not the parse's to write: see the end of struct
 * kof_cab_info. These pin where it is. */
_Static_assert(offsetof(struct kof_cab_info, legacy_arrays) == KOF_CAB_V2_TAIL_END,
	       "KOF_CAB_V2_TAIL_END is where the tail ends");
_Static_assert(offsetof(struct kof_cab_info, legacy_n_entries) == KOF_CAB_V1_ROWS_AT,
	       "the version 1 row count is not where version 1 had it");

int kof_cab_parse(kof_buf file, struct kof_cab_info *c, struct kof_obj_ctx *ctx)
{
	uint8_t fold_res = 0;
	uint64_t room;
	struct cw w;

	/*
	 * THE HEAD OF THE VIEW IS CLEARED, AND NOT THE LEGACY PADDING BEHIND IT: it is 135 KB that
	 * this version never uses, and clearing it for every cabinet would be the cost the other
	 * formats' views stopped paying. Its one word that is read - version 1's count - is
	 * zeroed by name. What the last parse left is let go first and the caller's room is put
	 * back (zip_parse.c says why).
	 */
	room = c->mem.room;
	kof_cab_release(c);
	memset(c, 0, offsetof(struct kof_cab_info, legacy_arrays));
	c->legacy_n_entries = 0;
	c->mem.room = room;
	c->version = KOF_CAB_INFO_VERSION;

	if (!kof_in_range(file, 0, CAB_HDR_MIN) || memcmp(file.p, "MSCF", 4) != 0)
		return 0;
	c->valid = 1;

	memset(&w, 0, sizeof w);
	w.f = file;
	w.c = c;
	/* What the FILE can hold of blocks, and twice that as the walk's budget (see struct cw). */
	w.blk_limit = 2u * (file.n / CAB_DATA_HDR) + 64u;
	w.ent_limit = file.n / CAB_FILE_MIN + 1u;

	cab_read_header(file, c);
	if (cab_read_optional(file, c, &fold_res)) {
		/* The per-folder state is as long as the folder table, and is the parse's own: it
		 * is charged while it lives and given back below. */
		cab_read_folders(&w, fold_res);
		if (c->n_folders) {
			void *t = NULL;

			if (kof_tab_grow(&c->mem, &t, &w.fb_cap, sizeof *w.fb, c->n_folders,
					 c->n_folders)) {
				w.fb = (struct cab_fb *)t;
				memset(w.fb, 0, (size_t)c->n_folders * sizeof *w.fb);
				cab_read_files(&w);
			} else {
				cw_full(&w);   /* no way to place any file, and that is said */
			}
		} else {
			cab_read_files(&w);
		}
	}
	kof_tab_drop(&c->mem, (void **)&w.bl, &w.bl_cap, sizeof *w.bl);
	kof_tab_drop(&c->mem, (void **)&w.fb, &w.fb_cap, sizeof *w.fb);
	c->mem.rows = c->n_entries;
	cab_attach(file, c, ctx);
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
