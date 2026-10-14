/*
 * range.h - a range of bytes of an object: an offset and a length.
 *
 * A generic type, so it is defined in core. It is used by rangelist.h (the
 * geometry of a set of ranges), by the region resolvers of the parsers, by the
 * genome libs that partition an object, and by modules, which receive it through
 * <kofmod/kofsig.h> (that header re-exports this one). Types only: no function
 * lives here, and nothing here depends on anything but <stdint.h>.
 *
 * It used to be defined in the libgenome image directory, which made core
 * (rangelist.h, through kofsig.h) depend on the genome lib. A lib may include core;
 * core may not include a lib.
 */
#ifndef KOFENG_RANGE_H
#define KOFENG_RANGE_H

#include <stddef.h>
#include <stdint.h>

/*
 * THE INTERVAL TYPES OF THE TREE, and why each is its own type.
 *
 *   struct kof_range    (here)       a range of bytes of ONE OBJECT: offset, length.
 *   struct kof_run      (here)       a kof_range plus the class that claims it - the
 *                                    parsers' run lists (runlist.h) and the `run[]`
 *                                    array of every kofmod/ parser info. Same first
 *                                    two members, so a run is read as a range.
 *   struct kofa_run     (aproc.h)    a range of a PROCESS's address space
 *   struct kofw_diff_range (wdiff.h) (orbit): `addr`, not `off`, because it is a
 *                                    virtual address in another process and an object
 *                                    offset must never be mistaken for one.
 *   struct kgenome_emu_wrange (emu_private.h)  a HALF-OPEN [lo, hi) of guest addresses
 *                                    an emulated run watches. Half-open, not
 *                                    offset+length, because what it answers is "is this
 *                                    address inside" for a table of them, and the end
 *                                    of one range is the start of the next with no
 *                                    off + len to wrap at the top of the address space.
 */

/* A resolved range. len == 0 means the extent is empty. */
struct kof_range {
	uint64_t off;
	uint64_t len;
};

/* One run of bytes and what claims it: a range and the class number the format
 * gave it (the format's own enum - enum kof_zip_class and the like). `reserved`
 * keeps the record at 24 bytes and is zero. */
struct kof_run {
	uint64_t off, len;
	uint32_t cls;
	uint32_t reserved;
};

/*
 * THE MEMORY OF A VIEW'S TABLES, which are as long as the file says and not a
 * number chosen when the header was written.
 *
 * A parser view (struct kof_zip_info, struct kof_pdf_info) used to carry its
 * entries, objects and runs as fixed arrays - 4096, 4096 and 16384 - so a zip with
 * 2100 members lost every one of them (its NAMES region needed 4200 extents against
 * a buffer of 4096) and a PDF past its 4096th object lost the rest. The tables are
 * now allocated to the size the file's own structure needs, and this is the account
 * of them, in the view, so that whoever owns the view can charge what the parse
 * holds and give it back:
 *
 *   room    IN.  The bytes the parse may hold in tables, set by the caller before
 *           the parse (the engine passes what its per-object ledger has left, and
 *           never zero: one byte is how it says "nothing fits"). A table that would
 *           pass it is not grown and the parse says so with the format's own "table
 *           full" anomaly - the entries past it are reported as not read, never
 *           dropped in silence. ZERO IS A CALLER THAT KEEPS NO ACCOUNT (a test, a
 *           tool reading one file): the file's own bound is then the only one, and
 *           that bound is the file's length over the smallest record, so it is still
 *           a multiple of the input and never a count the file states.
 *   held    OUT. The bytes the tables hold now. The caller charges it and gives it
 *           back with the format's release function.
 *   rows    OUT. How many rows a module can walk (kof_zip_next, kof_pdf_next).
 *   walked  OUT. Bumped by every call of that walk. The engine reads it after an
 *           unpack module has run: rows > 0 and walked == 0 is a module built for
 *           the layout before the tables were dynamic, which would read nothing
 *           and say nothing - the object is then reported, not passed as examined.
 *
 * Module ABI: a module never writes it. Appended at the tail of the views that use
 * it; see the layout notes in zip.h and pdf.h.
 */
struct kof_view_mem {
	uint64_t room;
	uint64_t held;
	uint32_t rows;
	uint32_t walked;
};

_Static_assert(offsetof(struct kof_run, len) == offsetof(struct kof_range, len) &&
	       offsetof(struct kof_run, off) == offsetof(struct kof_range, off),
	       "a kof_run begins with a kof_range");

#endif /* KOFENG_RANGE_H */
