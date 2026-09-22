/*
 * cab.h - the Microsoft Cabinet view of an object.
 *
 * Including this header declares that the module targets CAB, on the same
 * terms as zip.h and chm.h: a module may include exactly one format header,
 * because kof_cab() below casts ctx->file_header and the cast is sound only
 * while the host never calls a module for a format it did not declare.
 *
 * WHY THIS ONE AND NOT THE OTHER OLD ARCHIVES. A cabinet is not a retro
 * format: Windows still installs from them, an MSI carries one inside itself,
 * and the delivery that made CVE-2021-40444 work was a .cab fetched by a
 * document. It is the archive a Windows machine opens without being asked
 * twice.
 *
 *
 * THE SHAPE, and the one thing about it that is unlike every other archive
 * here: THE COMPRESSION IS PER FOLDER, NOT PER FILE. A cabinet holds
 * CFFOLDERs, each a single coded stream, and CFFILEs that name a byte range
 * INSIDE one folder's decoded output. So a file is not a range of the cabinet -
 * it is a range of something that has to be produced first, and two files in
 * one folder cannot be decoded independently.
 *
 * That decides the shape of the entry table. A folder stored uncompressed IS
 * its bytes, with a block header every few kilobytes; a file that fits inside
 * one block is a plain range and becomes a child with no module involved, and
 * one that crosses a boundary is KOF_ENT_F_SCATTERED and is joined.
 *
 * A CODED FOLDER IS DECODED FROM ITS FIRST BLOCK, whichever file is wanted.
 * Neither MSZIP nor LZX can be entered part way, so the entry's pieces are the
 * WHOLE FOLDER's blocks and out_hint says where in the decoded stream the file
 * sits - the high 32 bits its offset, the low 32 its length. Which coding is
 * in the entry's own `coding[0]`, so a module asks for what the folder
 * declared rather than keeping a second table of it.
 *
 *   MSZIP  - one deflate stream per block, each free to reference the previous
 *            block's last 32KB as history. Decoding them independently gives
 *            the right bytes for the first block and plausible wrong ones after
 *            it, which is the one outcome this engine must never produce; the
 *            host seeds each stream with the last block's window instead.
 *   LZX    - one stream across every block, so the blocks are joined back
 *            together and decoded once. The window is in the folder's
 *            typeCompress and is carried in the method id.
 *   QUANTUM - no decoder here. Those files are counted in n_coded and left as
 *            bytes in the DATA region rather than reported as an engine
 *            failure, the judgement pdf.c's image note records after measuring
 *            what the opposite did to ordinary files.
 *
 *
 * SPANNING IS A FACT, NOT A FAILURE. A cabinet may say its content continues in
 * another file - szCabinetNext - and the rest of that content is not in this
 * object at all. It is recorded, because a set of cabinets is how a large
 * payload arrives in pieces small enough not to be looked at.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KOFENG_CAB_H
#define KOFENG_CAB_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_CAB_INFO_VERSION 1

/*
 * Scan regions.
 *
 * NAMES is split from the rest of the file table on purpose and for the reason
 * gzip.h splits its stored filename: it is the part of an archive an author
 * chose and reuses, it is stored in the clear whatever the folders are coded
 * with, and it is a few hundred bytes rather than the whole file. A rule about
 * what a dropper calls its payload searches NAMES.
 *
 * DATA is every CFDATA block: the coded streams and their block headers. It is
 * where a stored payload sits and where a coded one sits coded - a rule over
 * this region sees a compressed folder as compressed bytes, and its files
 * arrive decoded as children instead.
 */
enum kof_scan_cab {
	KOF_SCAN_CAB_HEADERS   = 1u << 1,  /* CFHEADER, reserves, cabinet names */
	KOF_SCAN_CAB_FOLDERS   = 1u << 2,  /* the CFFOLDER array */
	KOF_SCAN_CAB_NAMES     = 1u << 3,  /* the CFFILE array: names and sizes */
	KOF_SCAN_CAB_DATA      = 1u << 4,  /* the CFDATA blocks */
	KOF_SCAN_CAB_UNCLAIMED = 1u << 5
};

#define KOF_SCAN_CAB_CLAIMED (KOF_SCAN_CAB_HEADERS | KOF_SCAN_CAB_FOLDERS | \
			      KOF_SCAN_CAB_NAMES | KOF_SCAN_CAB_DATA)

/* CFHEADER flags, as the format defines them. */
enum {
	KOF_CAB_F_PREV_CABINET = 0x0001u,
	KOF_CAB_F_NEXT_CABINET = 0x0002u,
	KOF_CAB_F_RESERVE      = 0x0004u
};

/* CFFOLDER typeCompress, low byte. */
enum {
	KOF_CAB_C_NONE    = 0,
	KOF_CAB_C_MSZIP   = 1,
	KOF_CAB_C_QUANTUM = 2,
	KOF_CAB_C_LZX     = 3
};

enum {
	/* The header is shorter than the fixed part, or a table it points at
	 * is outside the object. */
	KOF_CAB_ANOM_TRUNCATED    = 1ull << 0,
	/* cbCabinet disagrees with the object's real length. Both directions
	 * are recorded: short means the file was cut, long means something was
	 * appended to a cabinet - which is a dropper's usual shape. */
	KOF_CAB_ANOM_SIZE_MISMATCH = 1ull << 1,
	/* The content continues in, or comes from, another file. */
	KOF_CAB_ANOM_SPANNED      = 1ull << 2,
	/* A folder is coded with something this build does not decode. */
	KOF_CAB_ANOM_CODED        = 1ull << 3,
	/* A file names a folder that does not exist. */
	KOF_CAB_ANOM_BAD_FOLDER   = 1ull << 4,
	/* A file's bytes run past the end of the object. */
	KOF_CAB_ANOM_ENTRY_PAST_EOF = 1ull << 5,
	/* A name holds ".." or an absolute path - what it means to do when it
	 * is extracted, recorded rather than refused. */
	KOF_CAB_ANOM_TRAVERSAL    = 1ull << 6,
	/* More files than the table below holds. */
	KOF_CAB_ANOM_FILES_FULL   = 1ull << 7
};

/* How many of the above there are, so the name table cannot fall behind. */
#define KOF_CAB_ANOM_COUNT 8

#define KOF_CAB_MAX_FILES   2048u
#define KOF_CAB_MAX_FOLDERS 256u
/* The pieces of every scattered entry, pooled - see `run` below. A stored file
 * is one piece per 32KB block, so this covers about 32MB of stored content
 * spread over however many files; past it, entries stay counted and unopened. */
#define KOF_CAB_MAX_RUNS    1024u
/* The format's own limit on a name is 256 bytes including the terminator. */
#define KOF_CAB_MAX_NAME    256u

struct kof_cab_folder {
	uint64_t data_off;      /* first CFDATA of this folder */
	uint32_t n_blocks;
	uint16_t compress;      /* KOF_CAB_C_*, the low byte of typeCompress */
	/*
	 * The LZX window as a power of two, out of the high byte of
	 * typeCompress. Zero for every other coding.
	 *
	 * It is not in the stream - see lzx.h - so a decoder handed only the
	 * bytes cannot run, and a cabinet that declares a width this build does
	 * not have is a folder left unopened rather than one decoded wrongly.
	 */
	uint16_t window;
};

struct kof_cab_info {
	uint32_t version;       /* KOF_CAB_INFO_VERSION */
	uint32_t valid;         /* "MSCF" was there */
	uint64_t anomalies;

	uint64_t declared_size; /* cbCabinet */
	uint64_t files_off;     /* coffFiles: where the CFFILE array begins */
	uint32_t flags;
	uint16_t set_id, cab_index;
	uint8_t  ver_major, ver_minor;

	uint16_t n_folders, n_files;
	uint32_t n_coded;       /* files in a folder this build cannot decode */
	/*
	 * Files that cross a CFDATA block boundary, which every stored file
	 * over 32KB does. They are entries like any other and carry
	 * KOF_ENT_F_SCATTERED: their bytes are several ranges with a block
	 * header between them, so resolve_entry answers for them and the host
	 * joins the pieces. Counted as well as recorded because "how much of
	 * this archive is in one piece" is a different question from "how much
	 * of it can be opened".
	 */
	uint32_t n_split;
	uint32_t reserved0;

	/* Where the names are, as one range: the CFFILE array. Its own region,
	 * for the reason at the top. */
	uint64_t names_off, names_len;
	uint64_t folders_off, folders_len;
	uint64_t data_off;      /* the first CFDATA in the cabinet */

	struct kof_cab_folder folder[KOF_CAB_MAX_FOLDERS];

	/*
	 * The files, in the host's own shape - struct kof_entry, so a file that
	 * is a plain range becomes a named child with no module involved. See
	 * kof_objtree_declared.
	 */
	struct kof_entry entry[KOF_CAB_MAX_FILES];
	uint32_t n_entries;

	/* Which pieces in the pool below belong to entry i, when it is
	 * scattered: [first_run, first_run + n_run). Zero of them means the
	 * entry is one range and `off`/`len` say where. */
	struct {
		uint32_t first_run, n_run;
	} split[KOF_CAB_MAX_FILES];

	/*
	 * THE PIECES OF THE SCATTERED ENTRIES, in one pool.
	 *
	 * A stored file crosses a block boundary as soon as it is larger than a
	 * block, and the eight byte header of the next block sits in the middle
	 * of it - so its bytes are several ranges of the object, which is what
	 * KOF_ENT_F_SCATTERED says and what resolve_entry answers.
	 *
	 * WORKED OUT AT PARSE TIME AND STORED, rather than walked when asked,
	 * for the reason docole.h gives about its own pool: resolve_entry is
	 * handed a view and not the object's bytes, so an answer that needed to
	 * read block headers could not be given at all.
	 *
	 * ONE POOL rather than an array per entry: a cabinet with one large
	 * file and a hundred small ones would otherwise size every row for the
	 * largest. An entry whose pieces do not fit what is left is not
	 * recorded - it stays counted in n_split, which is the honest answer
	 * for "there is more here than this build described".
	 */
	uint32_t n_runs;
	struct {
		uint64_t off, len;
	} run[KOF_CAB_MAX_RUNS];
};

static inline const struct kof_cab_info *kof_cab(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_cab_info *)ctx->file_header;
}

#endif /* KOFENG_CAB_H */
