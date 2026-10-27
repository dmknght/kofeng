/*
 * infect.h - WHERE A BINARY IS COMMONLY INFECTED, and which of those places the engine said were.
 *
 * A file infector has a short list of places to put itself, and the list is a fact about the FORMAT, not about any
 * infector: the bytes at the entry point (patched to jump), the section that holds the entry, the last section or
 * segment (grown, or code appended to it), the padding after it and between segments (a cave that costs no file
 * growth), the init/fini tables (run before main), the note segment (retyped to a loadable one), the bytes appended
 * after everything (an overlay); in a PE also the header cave, the slack between a section's raw and virtual size,
 * the TLS callbacks (run before the entry point) and the import / relocation directories when they were moved into
 * the last section. kgenome_infect_regions lists those that exist in a PARSED ELF or PE, one row each.
 *
 * THE ENGINE'S RANGES COME IN AS INPUT and are never recomputed: a row whose file range overlaps one of them is
 * `flagged` and carries that range's own kind and index. A range that overlaps no listed region is still returned,
 * as a KGENOME_INFECT_REPORTED row of its own, so nothing the engine said is hidden by this list's choice of places.
 *
 * WHAT IT ANSWERS ON A DAMAGED OBJECT. It reads only the parsed view (kept sections and segments, already clamped by
 * the parse) and, for the TLS callback array, the bytes through kof_buf bounds. A section past the end of the file is
 * clipped to the file; a zero-length place is not listed (the entry point excepted); a table the parse could not keep
 * is simply not in the answer. An object that is not a valid ELF or PE answers KGENOME_BAD_INPUT with no regions, and
 * the engine's ranges still come back as REPORTED rows.
 *
 * BOUNDS. The regions are bounded by the parse's own tables (64 segments, 128 sections, 96 PE sections), so
 * KGENOME_INFECT_MAX rows hold every one of them. The engine's ranges are bounded by KGENOME_INFECT_RANGE_MAX:
 * more than that is KGENOME_TRUNCATED (the first ones are used), and so is a result that did not fit `cap`;
 * `total` is then the number of rows there would have been.
 *
 * The 16-byte entry area is a choice, not a measurement: a jump or call patch is 5 to 14 bytes. [Unverified]
 */
#ifndef KGENOME_IMAGE_INFECT_H
#define KGENOME_IMAGE_INFECT_H

#include <stdint.h>

#include <kofcore.h>
#include <kgenome_status.h>
#include <genotype/image/obj.h>

#define KGENOME_INFECT_NAME        56u
#define KGENOME_INFECT_MAX         320u
#define KGENOME_INFECT_RANGE_MAX   256u
#define KGENOME_INFECT_ENTRY_AREA  16u

enum kgenome_infect_kind {
	KGENOME_INFECT_ENTRY = 1,        /* the bytes at the entry point */
	KGENOME_INFECT_ENTRY_SECTION,    /* the section that holds the entry */
	KGENOME_INFECT_LAST_SECTION,     /* the section with the highest end in the file */
	KGENOME_INFECT_LAST_SEGMENT,     /* ELF: the loadable segment with the highest end */
	KGENOME_INFECT_SLACK,            /* padding after the last segment (ELF) or section (PE: raw beyond virtual, or the reverse) */
	KGENOME_INFECT_GAP,              /* padding between two loadable segments */
	KGENOME_INFECT_INIT,             /* .init .fini .ctors .dtors .init_array .fini_array .preinit_array */
	KGENOME_INFECT_NOTE,             /* a PT_NOTE segment with bytes */
	KGENOME_INFECT_OVERLAY,          /* bytes after everything the headers account for */
	KGENOME_INFECT_HEADER_CAVE,      /* PE: between the headers and the first section */
	KGENOME_INFECT_TLS,              /* PE: the TLS callback array */
	KGENOME_INFECT_DIR_RELOC,        /* PE: the relocation directory, when inside the last section */
	KGENOME_INFECT_DIR_IMPORT,       /* PE: the import directory, when inside the last section */
	KGENOME_INFECT_REPORTED          /* a range the engine reported that overlaps no listed region */
};

/* One range the engine reported (struct kof_infected): the lib passes `kind` through and does not read it. */
struct kgenome_infect_range {
	uint64_t off, len;
	uint32_t kind;
	uint32_t _pad;
};

struct kgenome_infect_row {
	char     name[KGENOME_INFECT_NAME];  /* what the region is, a section's name made printable */
	uint32_t kind;                       /* enum kgenome_infect_kind */
	uint32_t flagged;                    /* 1: overlaps a range the engine reported */
	uint32_t inf_kind;                   /* that range's kind (first overlapping one); meaningful when flagged */
	uint32_t inf_index;                  /* and its index in the input */
	uint64_t off, len;                   /* the file range; off is KGENOME_NA for a place the file does not hold */
	uint64_t addr;                       /* virtual address (ELF) or RVA (PE), KGENOME_NA when the place has none */
};

struct kgenome_infect_req {
	const struct kgenome_obj          *obj;     /* a parsed ELF or PE */
	kof_buf                            file;    /* the object's bytes */
	const struct kgenome_infect_range *inf;     /* the engine's ranges, may be NULL */
	uint32_t                           n_inf;
	struct kgenome_infect_row         *out;     /* the caller's rows */
	uint32_t                           cap;
};

struct kgenome_infect_res {
	uint32_t n;            /* rows written, at most cap */
	uint32_t total;        /* rows there are */
	uint32_t n_flagged;    /* of the rows written */
	uint32_t n_reported;   /* of the rows written: KGENOME_INFECT_REPORTED */
};

enum kgenome_status kgenome_infect_regions(const struct kgenome_infect_req *rq, struct kgenome_infect_res *rs);

#endif /* KGENOME_IMAGE_INFECT_H */
