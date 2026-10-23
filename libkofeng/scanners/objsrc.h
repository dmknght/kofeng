/*
 * objsrc.h - where an object's bytes come from, and how long they live.
 *
 * A scan used to be one file at a time: map it, scan it, unmap it. Once an object
 * can yield children that is no longer enough, because a child is not always a
 * copy. The cheapest child - an overlay, a stored archive entry, anything already
 * contiguous in the parent - is a WINDOW into the parent's mapping, and it costs
 * nothing at all as long as the parent's mapping is still there when the child is
 * scanned. It is not: by then the parent has been scanned and would have been
 * unmapped.
 *
 * So the bytes get a lifetime of their own, separate from whatever produced them,
 * and it is counted rather than scoped. Three kinds, one struct:
 *
 *   file      a regular file read into memory (kof_src_file)
 *   window    a range inside another source; holds a reference to it
 *   produced  bytes the engine made - a heap buffer, or an unnamed temporary
 *             file mapped back in when it got too large to keep in memory
 *
 * A caller cannot tell them apart and does not need to. kof_src_buf() hands back
 * bytes either way, so the scan path, the parsers and the matcher are unchanged.
 *
 *
 * WHY A TEMPORARY FILE IS NOT A SECURITY PROBLEM HERE
 *
 * Writing decompressed output to disk is where a long line of scanner
 * vulnerabilities came from: attacker-controlled entry names, path traversal,
 * symlink races, and cleanup that did not run. Every one of those needs the file to
 * have a NAME.
 *
 * These have none. O_TMPFILE creates an inode with no directory entry at all - it
 * exists only as a descriptor and is reclaimed by the kernel when the descriptor
 * closes, including on SIGKILL, OOM and a crash. There is nothing to traverse to,
 * nothing to race, and no cleanup step that can be skipped. The fallback for a
 * filesystem without O_TMPFILE creates a name and unlinks it immediately, which
 * gets the same property one syscall later.
 *
 * The entry name from the archive is never used for anything but reporting. It is
 * carried on the source as a LABEL - already sanitised to printable ASCII by the
 * host that read it - and the only thing that ever consumes it is the string a
 * finding is printed with. Nothing opens it, joins it to a path, or compares it.
 */

#ifndef KOFENG_OBJSRC_H
#define KOFENG_OBJSRC_H

#include <stdint.h>
#include <stddef.h>

#include "../kofcore/kofcore.h"

struct kof_objsrc;

struct kof_budget;

/*
 * The seam the file read goes through: read(2) when `io` is NULL, a test's table
 * otherwise (kof_scan_read_hook), the same arrangement as the spill's. `read` answers
 * the bytes read, 0 at end of file, -1 with errno set on an error.
 */
struct kof_src_read_io {
	int64_t (*read)(void *user, int fd, void *buf, uint64_t n);
	void     *user;
};

/*
 * One request to read a file. `budget` is the engine's memory ceiling: the bytes are
 * charged to it from before they are read until the source is destroyed (NULL charges
 * nothing - an engine whose budget could not be allocated, or a test). `room` is the
 * most the caller wants held in memory for this file when a spill file is the alternative,
 * `limit` the most it may hold when it is not (never below `room`); see kof_scan_file_room.
 *
 * `spill_open` and `spill_write` (both NULL, or both set) are where a file larger than
 * `room` goes instead: the engine's own unnamed temporary file, as a produced object that
 * outgrew memory goes (see the note in objsrc.c). `spill_open(user)` answers a new
 * descriptor, or -1 when no file may be made; `spill_write` answers 1 when all of the
 * bytes are in it.
 */
struct kof_src_file_req {
	const char                   *path;
	struct kof_budget            *budget;
	uint64_t                      room;
	uint64_t                      limit;
	const struct kof_src_read_io *io;
	int                         (*spill_open)(void *user);
	int                         (*spill_write)(void *user, int fd, const void *p, uint64_t n);
	void                         *spill_user;
};

/*
 * Read a regular file into memory the engine owns. NULL on failure, and *err is a
 * KOF_ERR_*.
 *
 * READ, NOT MAPPED. A mapped file is read through plain pointers for as long as the object
 * lives and whoever owns the file can truncate it meanwhile: every page past the new end
 * then faults with SIGBUS inside whichever parser happened to read it. No check before or
 * after the map closes that race, and the only handler that survives it is a process-wide
 * one, which a host can replace and which cannot tell this fault from a genuine bug
 * (stage39a had one; the owner refused it - see the note in objsrc.c). The bytes are
 * therefore copied once, here, with read(2): a file that shrinks, or fails to read, shows
 * up as a short count or an error at this call and nowhere else, and the engine takes no
 * signal from the input at all. Nothing is installed, nothing is chained, nothing can be
 * swallowed.
 *
 * The copy is charged to the engine's budget, so a file is no longer free RSS. A file larger
 * than `room` is copied to the spill file instead, when the caller offers one that may be
 * made (a real disk, or a directory the host named); the engine maps that copy, which has no
 * name and so no writer. When there is none, it is held in memory up to `limit`, and past
 * that only the first `limit` bytes are read and the source is marked KOF_BROKEN_LIMIT
 * (kof_src_cut): a cap is a cost bound and it is said, never silent.
 *
 * ONLY A REGULAR FILE, and never through a symbolic link: a FIFO, socket, device or
 * directory is refused without waiting on it (KOF_ERR_OPEN), and a path that is a
 * symlink - at the last component, whenever the open happens - is refused the same
 * way. The engine does not follow symlinks anywhere.
 *
 * A zero length file succeeds and yields no bytes: it is a legitimate object that
 * every module will decline, not an error.
 */
struct kof_objsrc *kof_src_file(const struct kof_src_file_req *rq, int *err);

/*
 * Why the bytes of this source are not the whole file: 0 when they are, otherwise the
 * KOF_BROKEN_* reason the objects of this file are reported with. KOF_BROKEN_DAMAGED
 * is a file that ended before the size the system reported (truncated while it was read)
 * or whose read failed (EIO); the bytes held are what was read. KOF_BROKEN_LIMIT is a file
 * larger than the caller's room. Of the root: a window answers 0, and the walk asks the root
 * of the tree. A produced object answers LIMIT when it met its own bound while it was decoded
 * (kof_src_mark_cut), and the walk reads that as the object's own result.
 */
uint32_t kof_src_cut(const struct kof_objsrc *);
/* Marks a produced object as cut at its own bound (KOF_BROKEN_*); the walk reads it back
 * through kof_src_cut as the object's result. */
void kof_src_mark_cut(struct kof_objsrc *, uint32_t why);

/* The bytes of the engine's budget this source holds until it is destroyed (what
 * kof_src_file charged); 0 for a mapped or borrowed one. */
uint64_t kof_src_charged(const struct kof_objsrc *);

/*
 * A range of another source, without copying. The parent is referenced and stays
 * alive until this is released; the range is clipped to what the parent has.
 *
 * NULL if the range is empty after clipping - there is no object there.
 */
/*
 * HOW WIDE A NAME IS DISPLAYED, for the tools that draw one in a column. It is NOT a
 * limit on what the engine keeps: a child's label is allocated to the length its
 * container's standard allows (KOF_SRC_NAME_MAX below) and a name is never cut to fit
 * a buffer. Names are short in practice - measured over 28316 tar entries the median
 * is 26 characters - so a tool that truncates for display loses nothing.
 */
#define KOF_SRC_LABEL_MAX 96u

/*
 * THE LONGEST NAME THE ENGINE WILL HOLD, in bytes of the name as the container wrote
 * it: 65535, which is the widest length field any container here has (ZIP's file name
 * length is 16 bits, APPNOTE 4.4.4; RAR 4's name size is 16 bits too). Each format's
 * own, tighter limit is applied before this is reached (oc_name_limit); this is the
 * bound that sizes the pending buffer and refuses anything no standard allows.
 */
#define KOF_SRC_NAME_MAX 65535u

/*
 * Sanitise `len` bytes at `p` into the source's label, allocated to the size it needs.
 * Non-printable bytes become '.', which is what keeps a terminal escape in an archive
 * out of a report. A name longer than KOF_SRC_NAME_MAX is not cut: the source is
 * marked name-invalid instead (kof_src_name_bad) and carries no label.
 */
void kof_src_label(struct kof_objsrc *, const uint8_t *p, uint64_t len);

/* The bytes the label occupies (0 when there is none): what a caller that charges the
 * memory ceiling for it asks, and what kof_src_label_account arranges to give back. */
uint32_t kof_src_label_cost(const struct kof_objsrc *);

/* The caller has taken kof_src_label_cost() bytes from an account: when the source is
 * destroyed, `release(arg, cost)` is called, so the charge falls on every path a child
 * can die on. A slot of its own, not on_free's: that one gives back produced bytes to a
 * different account. */
void kof_src_label_account(struct kof_objsrc *, void (*release)(void *, uint64_t),
			   void *arg);

/*
 * THE RECORD OF A SOURCE IS MEMORY THE SCAN HOLDS, and for a window - a child that is a range
 * of its parent - it is ALL it holds: no byte of produced budget, no label of any size, only
 * this struct (several hundred bytes: regions, symbols, the description a producer declares).
 * A container of tiny members therefore costs its record per member and nothing else the
 * ledger sees, which let a 5 MB cabinet of 5-byte entries hold 723 MB of children.
 *
 * kof_src_record_cost() is what one record occupies; the caller takes that many bytes from
 * its account and says so here, and when the source is destroyed `release(arg, cost)` is
 * called on every path a child can die on. A slot of its own, like the label's.
 */
uint64_t kof_src_record_cost(void);
void kof_src_charge_record(struct kof_objsrc *, uint64_t cost,
			   void (*release)(void *, uint64_t), void *arg);

/* The producer said this member's name is longer than its format's standard allows.
 * The member itself is still opened (its bytes are evidence), without a name. */
void kof_src_declare_name_bad(struct kof_objsrc *);
int  kof_src_name_bad(const struct kof_objsrc *);

/* The label, or "" when the source has none. Never NULL. */
const char *kof_src_label_of(const struct kof_objsrc *);

/*
 * THE FORMAT WHATEVER PRODUCED THIS CHILD WAS WILLING TO DECLARE, or
 * KOF_FMT_UNKNOWN.
 *
 * Beside the label and for the same reason: both are things only the producer
 * knows, and both have to survive the gap between producing a child and
 * scanning it - which is a queue, so they cannot be passed as arguments.
 *
 * A CLAIM AND NOT A GUESS. A container knows a stream is page content because
 * its own structure said so; it does NOT know what is inside an attachment, so
 * it declares nothing there and the sniff chain decides. Declaring wrongly is
 * worse than declaring nothing - the parse named by it runs instead of the one
 * the bytes deserve - which is why this is only ever set from something the
 * format actually stated.
 */
void    kof_src_declare_fmt(struct kof_objsrc *, uint8_t fmt);

/* The language a producer knew and the bytes no longer say - see the fields it
 * sets. Returns 0 from kof_src_lang_of when nothing was declared. */
void    kof_src_declare_lang(struct kof_objsrc *, uint8_t subtype,
			     uint8_t subfamily);
int     kof_src_lang_of(const struct kof_objsrc *, uint8_t *subtype,
			uint8_t *subfamily);

/*
 * REGIONS THE PRODUCER NAMES, because nothing can work them out from the bytes.
 *
 * Every other object gets its regions from the parser that identified it. A
 * NORMALISED VIEW cannot: it is the parent with stretches of padding taken out,
 * so its own headers describe offsets that are no longer where they say. Parse
 * it and the regions come back wrong; do not parse it and there are none, and a
 * rule that names a region is filtered out before it runs - see the
 * `m->scan_mask & present` gate in scan.c, which is the second of the two
 * gates a rule has to pass.
 *
 * So the producer says. It knew the parent's regions and it knew what it did to
 * each of them, which is exactly what is needed and is knowable nowhere else.
 *
 * A TABLE IS AS LONG AS THE PRODUCER'S. This said "sixteen is past what either format
 * yields - one span per kind", and it was wrong: a kind has one span per DISJOINT extent,
 * and a PE with seventeen separate code sections lost the later ones from the view's regions
 * (norm_defect_engine N3). Nothing in the engine is bounded by this any more; it is the size
 * of the fixed scratch tables of the tools that cannot allocate (kofexaminer's extents).
 */
#define KOF_SRC_MAX_REGIONS 16u

struct kof_src_region {
	uint32_t mask;      /* the region bit, in the PARENT's vocabulary */
	uint64_t off, len;  /* where it landed in this object */
};

/*
 * `fmt` is the format whose REGION VOCABULARY the masks are written in, which
 * is the parent's and not this object's. A region bit means nothing on its own:
 * 1u << 3 is DATA in an ELF and DATA in a PE by coincidence, and 1u << 5 is
 * UNCLAIMED in one and OVERLAY in the other. Whatever is to name these bits -
 * a panel row, a rule being written against the view - has to be told which
 * table to read them from.
 */
/*
 * THIS OBJECT IS A RENDERING OF ANOTHER, not content that came out of one.
 *
 * A normalised view is the only thing that is. It matters because the two are
 * treated differently in ways that cannot be worked out from the bytes: a view
 * is not opened again and not normalised again, since everything openable in it
 * was openable in its parent and was opened there.
 *
 * A FLAG AND NOT "HAS A DECLARED REGION TABLE", which is what this was first.
 * A view of an object whose regions could not be resolved carries no table, so
 * that test called it content - and the appendix of such a file came out twice,
 * once from the file and once from its view.
 */

/* Returns 0 when the table could not be allocated (the object carries none and the caller says so),
 * 1 otherwise. There is no bound on `n` but what the producer declares. */
int      kof_src_declare_regions(struct kof_objsrc *, uint8_t fmt,
				 const struct kof_src_region *, uint32_t n);
uint8_t  kof_src_region_fmt_of(const struct kof_objsrc *);
/*
 * The symbol records a producer hands over with a rendering, because the
 * rendering's own headers can no longer produce them - see the note on the
 * definition. Declared before the child is pushed, read wherever the engine
 * would otherwise build a block.
 */
/* The four declarations below answer 0 when their copy could not be allocated (the child then carries
 * none of it) and 1 otherwise, nothing to declare included: a caller that gets 0 says so
 * (oc_scan_limit), because a view that arrives without its parent's symbols is not complete. */
int      kof_src_declare_syms(struct kof_objsrc *, const uint8_t *, uint32_t);
const uint8_t *kof_src_syms_of(const struct kof_objsrc *, uint32_t *);
struct kgenome_func;
int      kof_src_declare_funcs(struct kof_objsrc *, const struct kgenome_func *, uint32_t);
const struct kgenome_func *kof_src_funcs_of(const struct kof_objsrc *, uint32_t *);
/*
 * The units of the parent's cut that a view's decode rewrote, in the view's offsets: what the
 * view's own cut leaves whole instead of finding again - see kgenome_mutation_req.fixed.
 */
struct kof_range;
int      kof_src_declare_fixed(struct kof_objsrc *, const struct kof_range *, uint32_t);
const struct kof_range *kof_src_fixed_of(const struct kof_objsrc *, uint32_t *);


uint32_t kof_src_regions_of(const struct kof_objsrc *,
			    const struct kof_src_region **out);

/*
 * THE IMAGE A RENDERING IS A RENDERING OF, as its producer described it.
 *
 * A normalised view has the parent's header byte for byte and fewer bytes
 * after it, so its own header describes a file that is no longer under it and
 * parsing it again answers about that file. The description of the parent is
 * carried instead, with every file offset in it moved through the transform
 * (see genotype/image/offmap.h): the format, the architecture, the subtype, the
 * entry, and the format's own info struct. `info` is that struct, `info_len`
 * its size; both are copied.
 *
 * A source with no description is identified from its bytes as before.
 */
struct kof_src_desc {
	uint8_t     fmt;          /* enum kof_format of the image            */
	uint8_t     arch;
	uint8_t     subtype;
	uint64_t    entry_off;    /* in THIS object; KGENOME_NA/BROKEN as given */
	const void *info;
	uint32_t    info_len;
};
int kof_src_declare_desc(struct kof_objsrc *, const struct kof_src_desc *);
const struct kof_src_desc *kof_src_desc_of(const struct kof_objsrc *);

/* The parent's analysis, shared with the rendering - see objprod.h. The source
 * takes the reference it is given. */
struct kof_prod;
void kof_src_declare_prod(struct kof_objsrc *, struct kof_prod *);
const struct kof_prod *kof_src_prod_of(const struct kof_objsrc *);
uint8_t kof_src_fmt_of(const struct kof_objsrc *);

/* Which entry of its parent this source is the content of, or
 * KOF_ENTRY_NONE. Here for the reason the label and the format are: producing
 * a child and scanning it are separated by a queue, so what the producer knew
 * has to travel with the bytes. */
void     kof_src_declare_entry(struct kof_objsrc *, uint32_t index);
uint32_t kof_src_entry_of(const struct kof_objsrc *);

/* And what the producer said it is - enum kof_entry_kind, or
 * KOF_ENT_UNKNOWN. Carried for the same reason: a queue separates producing a
 * child from scanning it. */
void     kof_src_declare_kind(struct kof_objsrc *, uint32_t kind);
uint32_t kof_src_kind_of(const struct kof_objsrc *);

struct kof_objsrc *kof_src_window(struct kof_objsrc *parent, uint64_t off,
				  uint64_t len);

/* Take ownership of a malloc'd buffer. */
struct kof_objsrc *kof_src_heap(uint8_t *bytes, uint64_t len);

/* Bytes the caller owns and keeps alive; nothing is freed and nothing is
 * charged to the produced-memory ceiling. */
struct kof_objsrc *kof_src_borrow(const void *bytes, uint64_t len);

/*
 * Map an open descriptor and take ownership of it. Used for output that outgrew
 * memory: the bytes are already written, this turns them back into an object that
 * behaves exactly like a mapped file - only the pages a scan touches become
 * resident.
 */
struct kof_objsrc *kof_src_fd(int fd, uint64_t len);

struct kof_objsrc *kof_src_ref(struct kof_objsrc *);
void               kof_src_unref(struct kof_objsrc *);

kof_buf kof_src_buf(const struct kof_objsrc *);


/*
 * Tell someone when these bytes are actually gone.
 *
 * The scanner has a ceiling on how much produced data may be alive at once, and
 * that count has to fall exactly when the memory is freed. Doing it at the place
 * that seemed to be "finished with the object" looked equivalent and was not:
 * a child abandoned because the walk was aborted, or one refused because the child
 * cap was reached, or one whose allocation failed, all died on paths that never
 * reached that place - and each of them shrank the ceiling for the rest of the
 * scan by however much it had been charged.
 *
 * Hooked to destruction instead, the count cannot drift: it goes up in exactly one
 * place and comes down in exactly one place, and the second is the free itself.
 */
void kof_src_on_free(struct kof_objsrc *, void (*fn)(void *, uint64_t), void *user);

/*
 * An unnamed temporary file to write produced bytes into, or -1.
 *
 * Here rather than in the sink that uses it because the reason it is unnamed is the
 * same reason this header exists at all: the lifetime is the descriptor's, not a
 * directory entry's.
 */
int kof_src_tmpfile(void);
int kof_src_tmpfile_at(const char *dir);

/*
 * The directory a scratch file may be written in, or NULL when none is usable.
 *
 * Exported beside kof_src_tmpfile because a caller that needs a file it can
 * REOPEN BY NAME - a build log the viewer reads back after the build has
 * finished - cannot use the anonymous one, and would otherwise repeat the
 * search for a writable directory along with the environment variable that
 * differs per platform. One answer, two shapes of caller.
 */
const char *kof_src_tmpdir(void);

#endif /* KOFENG_OBJSRC_H */
