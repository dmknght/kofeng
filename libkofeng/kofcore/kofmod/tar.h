/*
 * tar.h - the tar view of an object.
 *
 * A header block, then the file's bytes, then the next header block, until two
 * blocks of zeroes end it. Everything is 512 byte aligned and nothing is
 * compressed, which makes this the one container in this engine that a parser
 * finishes on its own: there is no decoder to write, now or later.
 *
 *
 * WHY IT MATTERS MORE THAN ITS SIZE SUGGESTS
 *
 * Almost nothing arrives as a plain tar. It arrives as a tar inside a gzip, which
 * is how Linux software and Linux malware are both shipped - measured over this
 * collection, 268 of 295 gzip files hold one. The engine already pays the expensive
 * part of that chain: it inflates the stream and produces the tar as a child. Until
 * this parser existed that child identified as nothing and everything inside it was
 * invisible, so the cost had been paid and the answer thrown away one step short.
 *
 *
 * WHY THERE IS NO NAMES REGION, WHEN ZIP HAS ONE
 *
 * Because the same split costs five times as much here and saves almost nothing.
 *
 * A zip keeps each entry name in one contiguous field beside its header, so naming
 * it separately costs one extra extent per entry. A tar scatters its name fields
 * THROUGH the 512 byte header - the name at 0, the link target at 157, the owner
 * and group at 265, the path prefix at 345 - so a NAMES region would come apart
 * into five extents per entry instead of one.
 *
 * And the thing it would save is small: measured over 431 real archives holding
 * 28316 entries, the header blocks are 1.9% of the bytes and the content is 96.9%.
 * Searching names separately would avoid at most 1.9% of a scan, at five times the
 * extents - and the extent budget is the binding constraint here, since the largest
 * archive in that collection holds 2007 entries.
 *
 * The names stay reachable, and more precisely than a region would allow: the entry
 * table below carries the offset and length of each one, so a module searches a
 * single name and knows WHICH entry answered. A region can only say the archive
 * contains the bytes somewhere.
 *
 *
 * WHAT UNCLAIMED MEANS HERE
 *
 * Every entry's content is padded out to a 512 byte boundary, and DATA claims only
 * the declared size - so the padding falls into the complement rather than being
 * claimed. That is not bookkeeping: the padding is slack, it is written by whatever
 * buffer the archiver happened to hold, and it is a place to put bytes that no
 * extractor will ever write out. An archive whose slack is not zeroes has had
 * something put there, and KOF_TAR_ANOM_SLACK says so.
 *
 * It costs nothing to leave it there. The complement is computed from the gaps at
 * resolve time, so an unclaimed run is not an extent anybody paid for during the
 * parse.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_TAR_H
#define KOFENG_TAR_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_TAR_INFO_VERSION 1

enum kof_scan_tar {
	KOF_SCAN_TAR_HEADERS   = 1u << 1,  /* the 512 byte blocks, whole */
	KOF_SCAN_TAR_DATA      = 1u << 2,  /* entry content, exactly as declared */
	KOF_SCAN_TAR_UNCLAIMED = 1u << 3   /* slack, the end blocks, anything after */
};

#define KOF_SCAN_TAR_CLAIMED (KOF_SCAN_TAR_HEADERS | KOF_SCAN_TAR_DATA)

enum kof_tar_class {
	KOF_TAR_CLS_HEADERS = 0,
	KOF_TAR_CLS_DATA,
	KOF_TAR_CLS_COUNT
};

/*
 * Type flags, POSIX 1003.1 and the GNU extensions that are actually met.
 *
 * The two long-name flags are why an entry's name is given as an offset rather than
 * copied: a GNU long name is stored as the DATA of a preceding pseudo entry, so the
 * name of the entry after it lives outside its own header.
 */
enum {
	KOF_TAR_T_FILE     = '0',
	KOF_TAR_T_FILE_ALT = '\0',  /* the older spelling of a regular file */
	KOF_TAR_T_HARDLINK = '1',
	KOF_TAR_T_SYMLINK  = '2',
	KOF_TAR_T_CHAR     = '3',
	KOF_TAR_T_BLOCK    = '4',
	KOF_TAR_T_DIR      = '5',
	KOF_TAR_T_FIFO     = '6',
	KOF_TAR_T_LONGNAME = 'L',   /* GNU: this entry's data is the next one's name */
	KOF_TAR_T_LONGLINK = 'K',   /* GNU: likewise for the link target */
	KOF_TAR_T_PAX      = 'x',   /* extended header for the next entry */
	KOF_TAR_T_PAX_GLOB = 'g'
};

/*
 * Bounds, sized from measurement rather than from the format, which has none: a tar
 * is a stream and may hold any number of entries.
 *
 * 2048 is what the extent budget allows. Each entry costs two runs - its header
 * block and its content - and KOF_SCAN_MAX_EXTENTS is 4096, so an archive past this
 * cannot have its regions described in full. The largest archive measured here
 * holds 2007, which is close enough to the ceiling to be worth saying out loud:
 * this is not generous headroom, it is the real worst case.
 */
#define KOF_TAR_MAX_ENTRIES 2048u
#define KOF_TAR_MAX_EXTENTS 4096u

#define KOF_TAR_BLOCK    512u
#define KOF_TAR_MAGIC_AT 257u    /* "ustar", the only thing that identifies a tar */

enum {
	KOF_TAR_ANOM_BAD_CHECKSUM = 1ull << 0, /* a header does not sum to its field */
	KOF_TAR_ANOM_BAD_SIZE     = 1ull << 1, /* the size field is not a number */
	KOF_TAR_ANOM_TRUNCATED    = 1ull << 2, /* an entry runs past the end */
	KOF_TAR_ANOM_ENTRIES_FULL = 1ull << 3,
	KOF_TAR_ANOM_EXTENTS_FULL = 1ull << 4,
	KOF_TAR_ANOM_NO_END       = 1ull << 5, /* no pair of zero blocks closes it */
	KOF_TAR_ANOM_TRAVERSAL    = 1ull << 6, /* a name escapes the extract root */
	KOF_TAR_ANOM_LONGNAME     = 1ull << 7, /* GNU long name or link used */
	KOF_TAR_ANOM_PAX          = 1ull << 8, /* PAX extended headers used */
	KOF_TAR_ANOM_OVERLAP      = 1ull << 9,
	/*
	 * Padding that is not zeroes.
	 *
	 * Every entry is padded to a block boundary and no extractor writes those
	 * bytes out, so what is in them is whatever the archiver left there - or what
	 * somebody put there. Both are worth knowing; neither is visible to a tool
	 * that lists an archive.
	 */
	KOF_TAR_ANOM_SLACK        = 1ull << 10,
	KOF_TAR_ANOM_STRANGE_TYPE = 1ull << 11 /* a type flag the format does not define */
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KOF_TAR_ANOM_COUNT 12


/*
 * One entry.
 *
 * `name_off` points into the object and may land in a preceding entry's DATA when a
 * GNU long name was used - which is why it is an offset and not a copy. `size` is
 * what the header declared; what the object actually holds is bounded by data_off
 * against the object's end, and the two disagreeing sets TRUNCATED.
 */
struct kof_tar_entry {
	uint64_t hdr_off;
	uint64_t data_off;
	uint64_t size;
	uint64_t name_off;
	uint64_t mtime;
	uint32_t name_len;
	uint32_t mode, uid, gid;
	uint8_t  typeflag;
	uint8_t  suspicious;      /* KOF_TAR_ENT_* */
	uint16_t reserved;
};

enum {
	KOF_TAR_ENT_TRAVERSAL = 1u << 0,  /* ../ or an absolute path */
	KOF_TAR_ENT_PAST_EOF  = 1u << 1,  /* content runs past the object */
	KOF_TAR_ENT_SLACK     = 1u << 2,  /* this entry's padding is not zeroes */
	KOF_TAR_ENT_BAD_SUM   = 1u << 3
};

struct kof_tar_info {
	uint32_t version;         /* KOF_TAR_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t n_entries;
	uint32_t n_dirs, n_links, n_files;
	uint64_t total_size;      /* declared, summed over the entries examined */
	uint64_t end_off;         /* where the zero blocks start, 0 if absent */

	uint64_t region_bytes[KOF_TAR_CLS_COUNT];

	/* Runs, classified and settled. Spelled out rather than including runlist.h,
	 * for the reason docole.h gives: the ABI must not depend on a host header. */
	uint32_t n_runs;
	uint32_t reserved0;
	struct {
		uint64_t off, len;
		uint32_t cls;         /* enum kof_tar_class */
		uint32_t reserved;
	} run[KOF_TAR_MAX_EXTENTS];

	struct kof_tar_entry entry[KOF_TAR_MAX_ENTRIES];
};

static inline const struct kof_tar_info *kof_tar(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_tar_info *)ctx->file_header;
}

#endif /* KOFENG_TAR_H */
