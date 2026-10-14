/*
 * chm.h - the CHM (HTML Help) view of an object.
 *
 * Including this header declares that the module targets CHM, on the same
 * terms as pdf.h and docole.h: a module may include exactly one format header,
 * because kof_chm() below casts ctx->file_header and the cast is sound only
 * while the host never calls a module for a format it did not declare.
 *
 * WHAT A CHM IS. An ITSS archive - "ITSF" at offset zero - holding a small
 * filesystem: a directory of named entries, and one or more content sections
 * the entries point into. Microsoft shipped it as the help format and it
 * outlived that: a .chm opens on a double click, runs script from its own
 * pages, and has been a delivery wrapper for as long as it has existed.
 *
 * WHY THE DIRECTORY IS THE PART THAT PAYS. The names are stored in the clear
 * and they are what an author chose - "/exploit.htm", "/#IDXHDR", a path with
 * a traversal in it. They are a region of their own for that reason, so a rule
 * can search a few kilobytes of names rather than the whole file, and it can do
 * so without decompressing anything. That is the same trade gzip.h describes
 * for its stored filename, one directory wide.
 *
 * WHERE THE PAGES ARE, and why reaching them takes three structures rather
 * than one. A CHM keeps its pages in
 * "::DataSpace/Storage/MSCompressed/Content", coded with LZX, and the coding
 * needs two numbers that are not in the stream: ControlData says how wide the
 * window is, and the reset table says where in the compressed bytes the stream
 * RESTARTS. It restarts because LZX codes each block's Huffman trees as a
 * difference from the block before, so a stream cannot be entered in the
 * middle - only at a restart. The table holds one compressed offset per 32KB
 * frame and every `lzx_reset_interval` frames is a restart.
 *
 * So an entry in the compressed section is not a range of the object at all.
 * It is KOF_ENT_F_SCATTERED and its pieces are the INTERVALS IT SPANS, one
 * range of compressed bytes each, beginning at the restart in front of it;
 * out_hint carries how far past that first restart to skip and how much to
 * take, and coding[0] names the coding and the window. That is why it takes a module - bases/decomp/chm.c - the way a
 * cabinet's coded folders do: pointing at bytes and decoding to them are
 * different operations, and the host only does the first.
 *
 * ONE RANGE PER INTERVAL AND NOT ONE FOR THE WHOLE REMAINING STREAM, which is
 * what this had first and is wrong in a way only a comparison shows. A restart
 * is a new stream: its trees, its window and its three repeated offsets all
 * begin again. A decoder run straight through one therefore reads the next
 * interval's first block as a continuation of the previous one and produces
 * refuse - measured, on a page of escanwin.chm that spans two intervals, as a
 * decode that simply fails. Cut at the restarts, each piece is handed to the
 * decoder on its own and the pieces are emitted in order.
 *
 * Entries in the UNCOMPRESSED section are ordinary ranges and become children
 * with no module at all.
 *
 * WHAT IS STILL NOT REACHED: a compressed section whose ControlData is absent
 * or names a coding other than LZX, and an entry whose frame is past the last
 * row of the reset table. Both are counted in n_unreachable and neither is
 * reported as engine failure - a document this build cannot fully open has
 * still been examined as fully as it intends to, the same judgement pdf.c's
 * PDF_F_IMAGE note records after measuring what the opposite did to ordinary
 * files.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KOFENG_CHM_H
#define KOFENG_CHM_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_CHM_INFO_VERSION 2

/*
 * Scan regions.
 *
 * DIRECTORY is where the names are, and it is the region worth searching -
 * see the note above. CONTENT is the data area: entry bytes, compressed or
 * not, which is where a stored payload sits and where a coded one sits coded -
 * a rule over this region sees LZX output as LZX, and the decoded pages arrive
 * as children instead. HEADERS is the two fixed structures that say where the
 * other two are.
 *
 * UNCLAIMED is whatever lies outside all three - a CHM with something appended
 * to it, which is the ordinary shape of a dropper that carries a help file.
 */
enum kof_scan_chm {
	KOF_SCAN_CHM_HEADERS   = 1u << 1,  /* ITSF, and the ITSP behind it */
	KOF_SCAN_CHM_DIRECTORY = 1u << 2,  /* the PMGL/PMGI chunks: the names */
	KOF_SCAN_CHM_CONTENT   = 1u << 3,  /* the sections the entries point at */
	KOF_SCAN_CHM_UNCLAIMED = 1u << 4
};

#define KOF_SCAN_CHM_CLAIMED (KOF_SCAN_CHM_HEADERS | KOF_SCAN_CHM_DIRECTORY | \
			      KOF_SCAN_CHM_CONTENT)

enum {
	/* The version is not 3. Version 2 exists, is rare, and puts the content
	 * area in a different place - so the offsets here are a guess for it
	 * and it is recorded rather than trusted. */
	KOF_CHM_ANOM_OLD_VERSION   = 1ull << 0,
	/* A structure the header points at is outside the object. */
	KOF_CHM_ANOM_TRUNCATED     = 1ull << 1,
	/* The directory header is not "ITSP", or its chunk size is not a power
	 * of two: the walk cannot be trusted and stops. */
	KOF_CHM_ANOM_BAD_DIRECTORY = 1ull << 2,
	/* A chunk claims to be neither PMGL nor PMGI. */
	KOF_CHM_ANOM_BAD_CHUNK     = 1ull << 3,
	/* An entry's bytes run past the end of the object. */
	KOF_CHM_ANOM_ENTRY_PAST_EOF = 1ull << 4,
	/* An entry name holds ".." or begins with a drive or a slash-slash -
	 * a path that means to escape wherever it is written. */
	KOF_CHM_ANOM_TRAVERSAL     = 1ull << 5,
	/* A table of the parse could not grow, or the work it is allowed ran out: more
	 * entries than the entry table took, or coded entries whose pieces no longer fit
	 * the pool. The ones recorded are real; what was past it was not examined, and
	 * the object says so. */
	KOF_CHM_ANOM_ENTRIES_FULL  = 1ull << 6,
	/*
	 * The compressed section declares a stream this build cannot enter:
	 * no ControlData, a coding that is not LZX, or a reset table too
	 * short to cover the frames the entries sit in.
	 *
	 * An ANOMALY and not only a count, because a help file whose pages are
	 * coded and whose bookkeeping for that coding is missing is a file
	 * somebody edited - a working compressor writes all three structures
	 * or none.
	 */
	KOF_CHM_ANOM_NO_RESET_TABLE = 1ull << 7
};

/* How many of the above there are, so the name table cannot fall behind. */
#define KOF_CHM_ANOM_COUNT 8

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT IS A LIMIT ON THE FILE. The entry table was 2048 rows, a name over 1024 bytes ended
 * the rest of its directory chunk, the pool of pieces was 2048 and one entry could take 64 of
 * them, so a help file with 2100 pages lost the last of them, a long name took its neighbours
 * with it and a page that spans a hundred reset intervals was not placed. A directory entry is
 * a name length, a name and three numbers - at least KOF_CHM_ENTRY_MIN bytes of the directory -
 * so the rows cannot exceed the length of the directory over it; a name is bounded by the chunk
 * that holds it (a chunk is at most 64 KiB) and the host judges how long a name may be
 * (oc_name_limit), never cutting one; and the pieces are bounded by the reset table, which has a
 * row of eight bytes for each: the walk may place twice as many as the table has rows, which a
 * help file whose pages are disjoint never reaches and a directory whose pages all claim the
 * whole stream reaches at once - it costs a multiple of the file and no more. Under that sits the
 * engine's per-object ledger (struct kof_view_mem.room). A table that cannot grow, or work past
 * its budget, raises ENTRIES_FULL: what was not placed is said, and what was is whole.
 */
#define KOF_CHM_ENTRY_MIN 5u

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2, the same change as the zip view's (zip.h has the long form): `entry[2048]`, the pool
 * of pieces and the rows that index it - 180 KB - are tables the parse allocates to the size of the
 * help file, reached through the pointers at the tail. `n_entries` WAS AT OFFSET 144 AND IS NOW
 * `legacy_n_entries`, ALWAYS ZERO: a module built against version 1 loops over a count of zero,
 * reads a valid empty table, and the engine - which sees that the walk below was never called while
 * the help file has rows - reports the object instead of passing it as examined (sx_walk_check).
 * The real count is `n_entries` at the tail. A module walks the table with kof_chm_next below; it
 * does not index `entry`.
 */
struct kof_chm_info {
	uint32_t version;          /* KOF_CHM_INFO_VERSION */
	uint32_t valid;            /* "ITSF" was there */
	uint64_t anomalies;

	uint32_t itsf_version;     /* 2 or 3 in practice */
	uint32_t lang_id;          /* the header's LCID: a build fingerprint */
	uint32_t timestamp;        /* what the header says; author controlled */

	uint64_t dir_off, dir_len;      /* the PMGL/PMGI chunks */
	uint64_t content_off;           /* where section 0's data begins */
	uint32_t chunk_size, n_chunks;

	/*
	 * THE THREE ENTRIES THAT DESCRIBE THE COMPRESSED SECTION.
	 *
	 * They are "::DataSpace/Storage/MSCompressed/..." - the format's own
	 * bookkeeping, which is why they are not offered as files - and they
	 * are the only way to decode anything: ControlData says what window the
	 * LZX stream uses and how often it restarts, the reset table says where
	 * each restart is in the compressed bytes, and Content is the stream.
	 *
	 * Offsets are into the OBJECT. Zero length means the entry was not
	 * there, which is a help file that stores everything uncompressed - and
	 * a real shape, not a fault.
	 */
	uint64_t ctrl_off, ctrl_len;
	uint64_t reset_off, reset_len;
	uint64_t lzx_off, lzx_len;

	/* What ControlData said: the LZX window as a power of two, and how many
	 * frames apart the stream restarts. Zero when there is no ControlData
	 * or it is not LZX. */
	uint32_t lzx_window_bits;
	uint32_t lzx_reset_interval;

	/*
	 * WHAT THE RESET TABLE DECLARES about the stream as a whole, and it is
	 * the only statement of it anywhere: the stream itself does not say how
	 * much it decodes to.
	 *
	 * lzx_frame is that table's own block size rather than the constant
	 * 32768, because it is a field and a file is free to write another
	 * number in it; every offset below is computed from it.
	 */
	uint64_t lzx_uncomp_len;
	uint64_t lzx_frame;
	uint32_t n_reset;          /* rows in the table: one per frame */
	uint32_t reserved1;

	uint32_t legacy_n_entries; /* version 1's count, kept for its offset: always 0 */
	uint32_t n_compressed;     /* entries that live in the coded section,
				    * whether or not they were reached */
	uint32_t n_unreachable;    /* of those, the ones with no restart point
				    * to decode from - see the note at the top */
	uint32_t n_special;        /* names beginning with ':' or '#': the
				    * format's own bookkeeping, not content */
	uint32_t reserved0;

	/* ---- version 2: from here the tables are the file's size ----------------------- */

	struct kof_view_mem mem;   /* what the tables hold; see range.h */

	/*
	 * The entries, in the host's own shape.
	 *
	 * struct kof_entry and not a struct of this format's own, because the
	 * host opens carried files generically from this table - see
	 * kof_objtree_declared - so an entry that is a plain range becomes a
	 * named child without this format needing a module at all.
	 */
	struct kof_entry *entry;   /* n_entries of them */

	/*
	 * THE PIECES OF THE CODED ENTRIES, in one pool - the arrangement
	 * cab.h keeps for its own scattered entries and for the same reason:
	 * resolve_entry is handed a context and a range array and has no way to
	 * walk the file, so whatever it answers has to be here already.
	 *
	 * Each run is one reset interval's compressed bytes. Meaningful only
	 * for an entry in the coded section - which is every SCATTERED one,
	 * since a section-0 entry is a plain range - and an entry with n_run of
	 * zero is one the reset table could not place.
	 */
	struct kof_chm_run {
		uint64_t off, len;
	} *run;                    /* n_runs of them */
	struct kof_chm_split {
		uint32_t first_run, n_run;
	} *split;                  /* one row per entry */
	uint32_t n_entries;        /* rows in `entry`: every page the walk met that the
				    * tables could take */
	uint32_t n_runs;
};

static inline const struct kof_chm_info *kof_chm(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_chm_info *)ctx->file_header;
}

/*
 * THE NEXT ENTRY OF THE HELP FILE, in directory order: row `*cursor`, and the cursor is advanced;
 * NULL at the end. The row's index - what kunp_static_entry takes - is the cursor minus one after
 * the call. See kof_zip_next, which this is the same walk as.
 */
static inline const struct kof_entry *kof_chm_next(const struct kof_obj_ctx *ctx,
						   uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_CHM_H */
