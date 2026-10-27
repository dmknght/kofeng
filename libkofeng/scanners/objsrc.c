/*
 * objsrc.c - lifetimes for object bytes.
 *
 * Nothing here knows what an object is. It owns mappings, buffers and descriptors,
 * counts references, and releases each kind the way that kind needs releasing. The
 * whole file is about one question - when do these bytes stop being valid - which
 * is why it is not in scan.c with the code that reads them.
 *
 * One struct for all three kinds rather than a tagged union: each field is a
 * resource to release if it is set, and release order falls out of the order they
 * are checked. Adding a fourth kind is adding a field, not a case to every switch.
 */

/* Before any include. O_TMPFILE is a GNU extension and mmap is POSIX; a feature
 * test macro after the first include does nothing at all. */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "objsrc.h"
#include "../analyzers/parsers/binaries/funcs.h"
#include "objprod.h"
#include "../kofcore/koftypes.h"
#include "../kofcore/kofhash.h"   /* KOF_ERR_* */
#include "../kofcore/kofbudget.h"
#include "../kofcore/range.h"


#include "../kofcore/kofplatform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/* Windows has no FIFO to block on and no symlink to follow through open(); its reparse
 * points are refused by the walk's own check (kofplatform_file.h says where the two
 * platforms differ), and a mapped file cannot be truncated under a view. */
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif
/* The file is read with read(2): on Windows a descriptor opened without this translates
 * CRLF, and the engine would be scanning bytes that are not the file's. */
#ifndef O_BINARY
#define O_BINARY 0
#endif

struct kof_objsrc {
	const uint8_t *p;
	uint64_t       n;
	uint32_t       refs;

	/* Each set field is a resource this source owns. */
	void              *map;      /* munmap(map, map_len) */
	size_t             map_len;
	/* Why these bytes are not the whole file (KOF_BROKEN_*, 0 when they are): set by
	 * kof_src_file on the root, read through kof_src_cut. */
	uint8_t            cut;
	uint8_t           *heap;     /* free() */
	struct kof_objsrc *parent;   /* unref: a window keeps its parent alive */

	/* Non-zero only for bytes the engine produced, which are the only ones it
	 * had to find memory for. */
	uint64_t           produced;

	/* Called with `produced` when this source is destroyed, so an owner can
	 * give the memory back to whatever account it came from. */
	void             (*on_free)(void *, uint64_t);
	void              *on_free_arg;

	/* What this object is called, sanitised, or NULL. Reporting only. Allocated to the
	 * name's own length (label_cost bytes with the NUL), never cut to a fixed room. */
	char              *label;
	uint32_t           label_cost;
	void             (*label_release)(void *, uint64_t);   /* gives label_cost back */
	void              *label_arg;
	uint8_t            name_bad;   /* the producer's name was past its standard's limit */

	/* What the scan took from its ledger for this record (kof_src_charge_record), given
	 * back when the source dies. */
	uint64_t           rec_cost;
	void             (*rec_release)(void *, uint64_t);
	void              *rec_arg;

	/* What the producer declared this is, or KOF_FMT_UNKNOWN. NOT reporting
	 * only: it decides which modules are even offered the object. */
	uint8_t            fmt;

	/*
	 * AND WHICH LANGUAGE, when the producer knew it and the bytes no longer
	 * say so.
	 *
	 * A NORMALISED SCRIPT IS THE CASE THIS EXISTS FOR. The view is declared
	 * as its parent's FORMAT already, for the reason kof_src_declare_fmt
	 * gives - a sniff of a view answers about the parent's magic. The
	 * language needs the same treatment and did not get it, and the effect
	 * was worse than being unidentified: decoding a shell dropper's base64
	 * puts "<?php" into the view, the script parser reads the view's family
	 * as PHP, and kof_module_precond then declines every SHELL rule on it.
	 * The pass that produced the evidence blocked the rules written to read
	 * it.
	 *
	 * Zero means the producer said nothing and the parse decides, which is
	 * every other child.
	 */
	uint8_t            subtype;
	uint8_t            subfamily;
	uint8_t            lang_set;

	/* KOF_ENTRY_NONE unless a producer said otherwise - set in src_new,
	 * because the calloc'd zero would mean entry 0. */
	uint32_t           entry_of;
	uint32_t           kind;

	/* What the producer said this object's regions are - see the note in
	 * objsrc.h. Empty for every source but a normalised view. */
	struct kof_src_region *rgn;       /* owned, n_rgn entries: allocated to what was declared */
	uint32_t              n_rgn;
	uint8_t               rgn_fmt;   /* whose vocabulary rgn[].mask uses */

	/*
	 * THE SYMBOLS THIS OBJECT IS TO BE READ WITH, when its own bytes cannot
	 * produce them - see kof_src_declare_syms. Owned, freed with the source.
	 * NULL for everything the engine did not render.
	 */
	uint8_t              *syms;
	uint32_t              n_syms;
	/* THE FUNCTIONS OF A VIEW, in its own offsets - see kgenome_funcs_remap and
	 * kof_src_declare_funcs. Owned, freed with the source. */
	struct kgenome_func      *funcs;
	uint32_t              n_funcs;
	/* THE UNITS OF THE PARENT'S CUT THAT THE DECODE REWROTE, in this object's offsets -
	 * see kof_src_declare_fixed. Owned, freed with the source. */
	struct kof_range     *fixed;
	uint32_t              n_fixed;

	/*
	 * WHAT THE PRODUCER SAYS THE OBJECT IS - the image description carried
	 * through the transform, see kof_src_declare_desc. `desc.info` points at
	 * `desc_info`, owned and freed with the source.
	 */
	struct kof_src_desc   desc;
	void                 *desc_info;
	uint8_t               has_desc;

	/* The parent's analysis, shared - see objprod.h. Released with the source. */
	struct kof_prod      *prod;
};

/*
 * Take a name in, and keep only the part that is a name.
 *
 * Two reductions, in this order, and each closes a different hole:
 *
 *   THE LAST COMPONENT ONLY. An archive entry is called "dir/sub/file", and what a
 *   report wants is "file". Taking the last component is also what makes a label
 *   safe by CONSTRUCTION rather than by filtering: whatever the archive wrote, the
 *   result cannot contain a separator, so it cannot be a relative path, cannot walk
 *   upwards, and cannot be absolute. An entry called "../../../../etc/cron.d/x"
 *   reduces to "x" before anything else looks at it.
 *
 *   PRINTABLE ASCII ONLY. Everything else becomes a dot. This is the reporting
 *   half: an escape sequence cannot survive because ESC is not printable, and a
 *   newline cannot split a log record because it is not either.
 *
 * A name that reduces to nothing, or to "." or "..", yields no label at all - the
 * caller then falls back to the index, which is always unambiguous.
 */
/*
 * Is this name UTF-16LE rather than bytes?
 *
 * A compound file stores its directory names that way and there is no ASCII copy
 * anywhere in the object, so a name arriving from one is every other byte a NUL.
 * Deciding by looking is what avoids a second naming convention: every other format
 * hands over bytes, this one hands over bytes too, and the difference is noticed
 * here rather than declared in an ABI field that ten formats would leave zero.
 *
 * Conservative on purpose. It wants an even length, at least one character, and
 * EVERY odd byte zero - one non-zero high half and the name is treated as bytes,
 * which is the right answer for a UTF-16 name outside the basic latin range and
 * the right answer for a byte name that happens to contain a NUL.
 */
static int looks_utf16le(const uint8_t *p, uint64_t len)
{
	uint64_t i;

	if (len < 2u || (len & 1u))
		return 0;
	for (i = 1; i < len; i += 2)
		if (p[i])
			return 0;
	return 1;
}

void kof_src_declare_fmt(struct kof_objsrc *s, uint8_t fmt)
{
	if (s)
		s->fmt = fmt;
}

void kof_src_declare_lang(struct kof_objsrc *s, uint8_t subtype,
			  uint8_t subfamily)
{
	if (!s)
		return;
	s->subtype = subtype;
	s->subfamily = subfamily;
	s->lang_set = 1;
}

int kof_src_lang_of(const struct kof_objsrc *s, uint8_t *subtype,
		    uint8_t *subfamily)
{
	if (!s || !s->lang_set)
		return 0;
	if (subtype)
		*subtype = s->subtype;
	if (subfamily)
		*subfamily = s->subfamily;
	return 1;
}


uint8_t kof_src_region_fmt_of(const struct kof_objsrc *s)
{
	return s ? s->rgn_fmt : 0u;
}

int kof_src_declare_regions(struct kof_objsrc *s, uint8_t fmt,
			    const struct kof_src_region *r, uint32_t n)
{
	struct kof_src_region *own = NULL;

	if (!s || !r)
		return 1;
	/*
	 * Copied rather than pointed at. The caller's table is a local in the
	 * function that built the view, and the source outlives it by the whole
	 * of the child's scan.
	 *
	 * ALLOCATED TO WHAT WAS DECLARED. The table was sixteen entries and a producer's own was
	 * clipped to them, silently: a PE with more disjoint code extents than that lost the later
	 * ones from the view's regions (norm_defect_engine N3). A table is as long as the producer's
	 * is. 0 is a failed allocation, and the caller says so (the view carries no table).
	 */
	if (n) {
		own = malloc((size_t)n * sizeof *own);
		if (!own) {
			free(s->rgn);
			s->rgn = NULL;
			s->n_rgn = 0;
			return 0;
		}
		memcpy(own, r, (size_t)n * sizeof *own);
	}
	free(s->rgn);
	s->rgn = own;
	s->n_rgn = n;
	s->rgn_fmt = fmt;
	return 1;
}

uint32_t kof_src_regions_of(const struct kof_objsrc *s,
			    const struct kof_src_region **out)
{
	if (!s || !s->n_rgn)
		return 0;
	if (out)
		*out = s->rgn;
	return s->n_rgn;
}

void kof_src_declare_entry(struct kof_objsrc *s, uint32_t index)
{
	if (s)
		s->entry_of = index;
}

uint32_t kof_src_entry_of(const struct kof_objsrc *s)
{
	return s ? s->entry_of : KOF_ENTRY_NONE;
}

void kof_src_declare_kind(struct kof_objsrc *s, uint32_t kind)
{
	if (s)
		s->kind = kind;
}

uint32_t kof_src_kind_of(const struct kof_objsrc *s)
{
	return s ? s->kind : 0u;
}

uint8_t kof_src_fmt_of(const struct kof_objsrc *s)
{
	return s ? s->fmt : 0u;
}

/* Character `i` of a name that may be UTF-16LE: the low byte of each unit. */
static inline uint8_t name_ch(const uint8_t *p, int wide, uint64_t i)
{
	return wide ? p[i * 2u] : p[i];
}

void kof_src_label(struct kof_objsrc *s, const uint8_t *p, uint64_t len)
{
	uint64_t i, base = 0, n, cnt;
	int wide;
	char *lab;

	if (!s)
		return;
	free(s->label);
	s->label = NULL;
	s->label_cost = 0;
	if (!p || !len)
		return;
	if (len > KOF_SRC_NAME_MAX) {
		/* Past anything a container's standard allows: invalid, not truncated. */
		s->name_bad = 1;
		return;
	}

	wide = looks_utf16le(p, len);
	cnt = wide ? len / 2u : len;
	for (i = 0; i < cnt; i++) {
		uint8_t c = name_ch(p, wide, i);

		if (c == '/' || c == '\\')
			base = i + 1;
	}
	if (base >= cnt)
		return;                 /* the name was all separators */

	n = cnt - base;
	lab = malloc((size_t)n + 1u);
	if (!lab) {
		/* UNNAMED, AND THE OBJECT SAYS SO. The child's index still tells it apart, but a name that was
		 * there and was not kept is a limit that fired (an allocation the engine could not get), and a
		 * refusal is reported and never a silent change of the answer (CLAUDE.md rule 4): the child
		 * carries KOF_BROKEN_LIMIT, which the walk reads back as its result, the same as the names
		 * quota being full (oc_names_take, whose caller says oc_scan_limit). The sweep that found this
		 * is tests/unit/cov_oom_formats.c. */
		kof_src_mark_cut(s, KOF_BROKEN_LIMIT);
		return;
	}
	for (i = 0; i < n; i++) {
		uint8_t c = name_ch(p, wide, base + i);

		lab[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
	}
	lab[n] = 0;

	/* "." and ".." are directory references, not names. */
	if (strcmp(lab, ".") == 0 || strcmp(lab, "..") == 0) {
		free(lab);
		return;
	}
	s->label = lab;
	s->label_cost = (uint32_t)n + 1u;
}

uint32_t kof_src_label_cost(const struct kof_objsrc *s)
{
	return s ? s->label_cost : 0u;
}

void kof_src_label_account(struct kof_objsrc *s, void (*release)(void *, uint64_t),
			   void *arg)
{
	if (s) {
		s->label_release = release;
		s->label_arg = arg;
	}
}

uint64_t kof_src_record_cost(void)
{
	return sizeof(struct kof_objsrc);
}

void kof_src_charge_record(struct kof_objsrc *s, uint64_t cost,
			   void (*release)(void *, uint64_t), void *arg)
{
	if (s) {
		s->rec_cost = cost;
		s->rec_release = release;
		s->rec_arg = arg;
	}
}

void kof_src_declare_name_bad(struct kof_objsrc *s)
{
	if (s)
		s->name_bad = 1;
}

int kof_src_name_bad(const struct kof_objsrc *s)
{
	return s && s->name_bad;
}

const char *kof_src_label_of(const struct kof_objsrc *s)
{
	return s && s->label ? s->label : "";
}

/*
 * A FILE THAT SHRINKS WHILE IT IS SCANNED, and why there is no signal handler for it.
 *
 * The scan used to read a mapped file through plain pointers for as long as the object
 * lived, and whoever owned the file could truncate it meanwhile: every page past the new
 * end then faulted with SIGBUS, in whatever parser or matcher happened to be reading it,
 * and the process died (tests/unit/hostile_engine_scan.c, c_trunc0). Nothing about the
 * size can be checked in advance: an fstat before the map, after it, or on every read is
 * a race with the very writer being defended against, so a map is safe only if a fault
 * is survived.
 *
 * stage39a survived it with a process-wide SIGBUS handler that replaced the faulting page
 * with a zero page. The owner refused that design, for three reasons that are this
 * file's rules now: the handling must not depend on the host (a handler is process-global
 * state: a host that installs its own silently brings the crash back, and ours swallows
 * signals the host expected); it must not depend on data the OS supplies (the fault
 * address of a signal); and it must never swallow a real SIGBUS or SIGSEGV, which is a
 * bug and has to kill the process.
 *
 * WHAT IS DONE INSTEAD: THE ENGINE NEVER TOUCHES A FILE-BACKED PAGE IT DOES NOT OWN. A file
 * is read with read(2) into a heap buffer charged to the engine's budget, once, when the
 * walk meets it. A file that is cut short is a short read at that call, an EIO is an error
 * at that call, and both are an ordinary return value: the object is reported
 * KOF_BROKEN_DAMAGED (kof_src_cut) with the bytes that were read, which are real bytes of
 * the file. No signal can arrive, so none is handled, and there is no table, no flag and
 * no chain to the previous handler. A file that GROWS is read to the size fstat reported
 * when it was opened (the bytes are one consistent prefix); one that is replaced by
 * rename keeps the descriptor on the old inode, so the bytes are the old file's.
 *
 * WHAT WAS WEIGHED:
 *   - mmap only when the file is stable (O_RDONLY, fstat size, fstat again after the scan)
 *     is NOT safe: the second fstat runs after the pages were read, so a truncation in
 *     between still faults. There is no portable way to stop another process truncating
 *     a file it may write (no mandatory lock, no immutable bit without privilege, a seal
 *     only on memfd), so no condition under which a map of someone else's file cannot
 *     fault exists.
 *   - A sliding window needs a consumer that accepts one. Every parser, matcher and module
 *     here takes a whole flat buffer (kof_buf), and the module ABI hands a module the
 *     object as one pointer and one length; a window is a rewrite of the pipeline, not of
 *     this unit.
 *   - Mapping a COPY the engine made in its own unnamed temporary file (as a produced object
 *     is, kof_src_fd) cannot be truncated by anyone, so it is what a file past the heap room
 *     goes to (spill_copy). It is not the default: every file would be written once more,
 *     and on a RAM filesystem (this host's /tmp) the copy is the same memory as the heap, so
 *     the caller does not offer one there (oc_spill_usable).
 *
 * COST, measured on this tree against the mapped file it replaces (254 ELF + 300 PE, 2.4 GB,
 * one scanner, hot cache, best of 7 alternating runs): ELF 12.89 s -> 12.74 s, PE 5.58 s ->
 * 5.77 s (+3.4%, all of it system time: the copy out of the page cache, 0.13 s -> 0.41 s);
 * verdict output identical; peak RSS 79.7 -> 89.1 MB and 124.1 -> 122.4 MB; the 90 MB
 * file 94.1 -> 94.4 MB (the scan reads all of it either way). What changes is accounting: the
 * bytes are charged to the 512 MiB ceiling instead of being free clean pages, so with many
 * scanners the share of each shrinks (kof_scan_file_room says how, and what it cost).
 */

/* The budget gets its bytes back when the source dies, on every path it can die on. */
static void file_release(void *budget, uint64_t n)
{
	kof_budget_release((struct kof_budget *)budget, n);
}

/* read(2) behind the seam. */
static int64_t sys_read(void *user, int fd, void *buf, uint64_t n)
{
	(void)user;
	return (int64_t)read(fd, buf, n > (1u << 30) ? (1u << 30) : (unsigned)n);
}

static const struct kof_src_read_io SYS_READ = { sys_read, NULL };

/*
 * `n` bytes into `dst`. The count that arrived: n when the file held them, fewer when it
 * ended first (it was truncated since fstat) or a read failed. Every failure is a count
 * and the caller says so; nothing here is silent and nothing is retried but EINTR.
 */
static uint64_t read_full(const struct kof_src_read_io *io, int fd, uint8_t *dst, uint64_t n)
{
	uint64_t off = 0;

	while (off < n) {
		int64_t r = io->read(io->user, fd, dst + off, n - off);

		if (r > 0) {
			if ((uint64_t)r > n - off)
				break;          /* a hook that claims more than was asked: a bug, not data */
			off += (uint64_t)r;
		} else if (r < 0 && errno == EINTR) {
			continue;
		} else {
			break;                  /* EOF (0) or an error: the file is not n bytes long */
		}
	}
	return off;
}

uint32_t kof_src_cut(const struct kof_objsrc *s)
{
	return s ? s->cut : 0u;
}

/* An object that met its own bound (oc_entry_cut) says so; the first reason stays. */
void kof_src_mark_cut(struct kof_objsrc *s, uint32_t why)
{
	if (s && !s->cut)
		s->cut = (uint8_t)why;
}

uint64_t kof_src_charged(const struct kof_objsrc *s)
{
	return s && s->on_free == file_release ? s->produced : 0u;
}

static struct kof_objsrc *src_new(void)
{
	struct kof_objsrc *s = calloc(1, sizeof *s);

	/*
	 * NOT LEFT AT THE CALLOC'D ZERO, because zero is entry 0 and is a real
	 * answer. Every other field here means nothing useful at zero and can
	 * be left; this one would claim that the object is the content of its
	 * parent's first entry. The root of a walk has no parent at all, so it
	 * would have claimed it loudest.
	 */
	if (s)
		s->entry_of = KOF_ENTRY_NONE;

	if (s)
		s->refs = 1;
	return s;
}

/*
 * The file, copied to the engine's own unnamed temporary file and mapped from there.
 * 1 when `s` now holds it; 0 when no file could be made, and then nothing was read.
 *
 * Nothing is charged: the pages are clean file pages the kernel can drop, which is what the
 * mapped input always was, and the offer of a file is the caller's statement that it is not
 * RAM (oc_spill_usable). The copy goes through a small buffer, so the peak is one chunk and
 * not the file. A source that ends early is DAMAGED with the part copied; a write that fails
 * (ENOSPC, EIO) is a LIMIT - the disk could not hold it - with the part that is in the file.
 * Either way the bytes mapped are bytes that were written and are in the file.
 */
#define COPY_CHUNK (1u << 20)

static int spill_copy(struct kof_objsrc *s, const struct kof_src_file_req *rq,
		      const struct kof_src_read_io *io, int fd, uint64_t size)
{
	uint8_t *chunk;
	uint64_t done = 0;
	int out = rq->spill_open(rq->spill_user);

	if (out < 0)
		return 0;
	chunk = malloc(COPY_CHUNK);
	if (!chunk) {
		close(out);
		return 0;
	}
	while (done < size) {
		uint64_t want = size - done < COPY_CHUNK ? size - done : COPY_CHUNK;
		uint64_t got = read_full(io, fd, chunk, want);

		if (got && !rq->spill_write(rq->spill_user, out, chunk, got)) {
			s->cut = KOF_BROKEN_LIMIT;
			break;
		}
		done += got;
		if (got < want) {
			s->cut = KOF_BROKEN_DAMAGED;
			break;
		}
	}
	free(chunk);
	if (done) {
		s->map = kof_map_file_ro(out, done);
		if (s->map) {
			s->map_len = (size_t)done;
			s->p = s->map;
			s->n = done;
		}
	}
	close(out);
	if (done && !s->map)
		s->cut = KOF_BROKEN_LIMIT;      /* no address space for it: nothing of it is held */
	if (done < size && !s->cut)
		s->cut = KOF_BROKEN_LIMIT;
	return 1;
}

struct kof_objsrc *kof_src_file(const struct kof_src_file_req *rq, int *err)
{
	const struct kof_src_read_io *io = rq->io ? rq->io : &SYS_READ;
	struct kof_objsrc *s;
	struct stat sb;
	uint64_t want, got;
	uint8_t *buf;
	int fd;

	*err = KOF_ERR_OPEN;

	/*
	 * O_NONBLOCK: open() of a FIFO with no writer blocks forever, and the type test
	 * below can only be made on a descriptor that exists (tests/unit/
	 * hostile_engine_scan.c, c_fifo). A regular file is unaffected by the flag.
	 * O_NOFOLLOW: THE ENGINE NEVER FOLLOWS A SYMLINK (the owner's decision, against
	 * a link swapped in between the walk's lstat and this open): a link here is
	 * ELOOP, which is KOF_ERR_OPEN like any other path that is not a regular file.
	 * O_NOCTTY: a terminal device named as the path must not become ours.
	 * Everything that is not a regular file - FIFO, socket, device, directory - is
	 * refused by the fstat, with KOF_ERR_OPEN as kofhash.h defines it.
	 */
	fd = open(rq->path, O_RDONLY | O_BINARY | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
		close(fd);
		return NULL;
	}
	s = src_new();
	if (!s) {
		close(fd);
		return NULL;
	}
	*err = 0;
	if (sb.st_size <= 0) {
		close(fd);
		return s;               /* an empty file: a legitimate object with no bytes */
	}

	/*
	 * HOW MUCH TO HOLD. The size fstat reported is the bound - never what the file says
	 * about itself. What fits the caller's room and the budget right now is held in the
	 * heap; a larger file goes to the spill file when there is one; failing both, the head
	 * of it is held and the source is marked LIMIT, so the part that was not read is a
	 * stated loss and not a clean answer.
	 */
	want = (uint64_t)sb.st_size;
	if (want > SIZE_MAX)
		want = SIZE_MAX;
	if (want > rq->room || (rq->budget && kof_budget_ask(rq->budget, want) < want)) {
		if (rq->spill_open && rq->spill_write &&
		    spill_copy(s, rq, io, fd, (uint64_t)sb.st_size)) {
			close(fd);
			return s;
		}
		if (want > rq->limit)
			want = rq->limit;
		if (rq->budget && want)
			want = kof_budget_ask(rq->budget, want);
	}
	/* Atomic against the other scanners: a charge that loses the race holds nothing. */
	if (rq->budget && want && !kof_budget_charge(rq->budget, want))
		want = 0;
	if ((uint64_t)sb.st_size > want)
		s->cut = KOF_BROKEN_LIMIT;
	if (want == 0) {
		close(fd);
		return s;               /* nothing affordable: an empty object marked LIMIT */
	}
	buf = malloc((size_t)want);
	if (!buf) {
		if (rq->budget)
			kof_budget_release(rq->budget, want);
		s->cut = KOF_BROKEN_LIMIT;
		close(fd);
		return s;
	}
	got = read_full(io, fd, buf, want);
	close(fd);
	if (got < want)
		s->cut = KOF_BROKEN_DAMAGED;    /* ended early or failed: said, whatever else was cut */
	s->heap = buf;
	s->p = buf;
	s->n = got;
	/* Charged for what was taken, given back for what was taken - not for what was read. */
	s->produced = want;
	if (rq->budget) {
		s->on_free = file_release;
		s->on_free_arg = rq->budget;
	}
	return s;
}

struct kof_objsrc *kof_src_window(struct kof_objsrc *parent, uint64_t off,
				  uint64_t len)
{
	struct kof_objsrc *s;
	uint64_t got;

	if (!parent)
		return NULL;
	/* Clipped, not refused: the offsets come from a parser reading a file, so
	 * a range that runs past the end is the normal hostile case rather than a
	 * programming error. */
	got = kof_clip_len(parent->n, off, len);
	if (got == 0)
		return NULL;

	s = src_new();
	if (!s)
		return NULL;
	s->parent = kof_src_ref(parent);
	s->p = parent->p + off;
	s->n = got;
	return s;
}

struct kof_objsrc *kof_src_heap(uint8_t *bytes, uint64_t len)
{
	struct kof_objsrc *s = src_new();

	if (!s) {
		free(bytes);
		return NULL;
	}
	s->heap = bytes;
	s->p = bytes;
	s->n = len;
	s->produced = len;
	return s;
}

/*
 * Bytes somebody else owns and will outlive the scan.
 *
 * kof_src_heap takes a block to free and kof_src_window needs a parent to hold
 * a reference on; a caller that already has a mapped buffer has neither, and
 * copying it to satisfy the constructor would double the memory for nothing.
 * `produced` stays zero, which is what it means: nothing was produced, these
 * bytes existed before the scan and are not charged to its ceiling.
 */
struct kof_objsrc *kof_src_borrow(const void *bytes, uint64_t len)
{
	struct kof_objsrc *s = src_new();

	if (!s)
		return NULL;
	s->p = bytes;
	s->n = len;
	return s;
}

/*
 * THE ONE MAP THAT IS LEFT, and why it is not the file problem above: `fd` is the engine's
 * own unnamed temporary file (O_TMPFILE, or unlinked at once), written in full by this
 * scanner before it gets here. It has no name for anyone to open and truncate, so no
 * writer exists to race. The only fault it can still raise is the disk failing under a
 * page, which is a genuine fault and is left to kill the process like any other.
 */
struct kof_objsrc *kof_src_fd(int fd, uint64_t len)
{
	struct kof_objsrc *s = src_new();

	if (!s) {
		close(fd);
		return NULL;
	}
	if (len > 0) {
		s->map = kof_map_file_ro(fd, len);
		if (!s->map) {
			close(fd);
			free(s);
			return NULL;
		}
		s->map_len = (size_t)len;
		s->p = s->map;
		s->n = len;
	}
	/* Charged as produced even though it is file backed: a temporary directory
	 * is very often tmpfs, where these pages are memory and are capped by a
	 * mount option this code cannot see. */
	s->produced = len;
	close(fd);
	return s;
}

struct kof_objsrc *kof_src_ref(struct kof_objsrc *s)
{
	if (s)
		s->refs++;
	return s;
}

/*
 * THE SYMBOL BLOCK A PRODUCER HANDS OVER WITH THE BYTES.
 *
 * WHY A RENDERING NEEDS ONE AT ALL. A symbol block is built from the object's
 * own section table - .symtab's offset, .strtab's offset - and a normalised
 * view's headers describe the file BEFORE the padding came out of it. Every
 * offset in them is stale wherever something collapsed ahead of it, so the
 * builder reads whatever now lies there and finds nothing: measured on a
 * uclibc bot, the file yields 677 symbols and its view yields zero. The view
 * had no SYM_EXP and no SYM_IMP at all, which is the half of the object a
 * similarity question is most often about.
 *
 * SO THE PRODUCER SAYS, exactly as it already says what the regions are. The
 * normaliser has the parent's block in front of it and knows which of its
 * records are the toolchain's, so it hands over the records that are left.
 *
 * COPIED, because the caller's buffer is the scanner's working one and is
 * rebuilt for the next object. Freed with the source.
 */
int kof_src_declare_syms(struct kof_objsrc *s, const uint8_t *b, uint32_t n)
{
	uint8_t *own;

	if (!s || !b || !n)
		return 1;
	own = malloc(n);
	if (!own)
		return 0;       /* the view arrives without them, and the caller says so (engine_defect2 E2) */
	memcpy(own, b, n);
	free(s->syms);
	s->syms = own;
	s->n_syms = n;
	return 1;
}

int kof_src_declare_funcs(struct kof_objsrc *s, const struct kgenome_func *v,
			  uint32_t n)
{
	struct kgenome_func *own;

	if (!s || !v || !n)
		return 1;
	own = malloc((size_t)n * sizeof *own);
	if (!own)
		return 0;       /* the view arrives without them, and the caller says so (engine_defect2 E2) */
	memcpy(own, v, (size_t)n * sizeof *own);
	free(s->funcs);
	s->funcs = own;
	s->n_funcs = n;
	return 1;
}

int kof_src_declare_fixed(struct kof_objsrc *s, const struct kof_range *v, uint32_t n)
{
	struct kof_range *own;

	if (!s || !v || !n)
		return 1;
	own = malloc((size_t)n * sizeof *own);
	if (!own)
		return 0;       /* the view arrives cut as its own bytes say, and the caller says so (E2) */
	memcpy(own, v, (size_t)n * sizeof *own);
	free(s->fixed);
	s->fixed = own;
	s->n_fixed = n;
	return 1;
}

int kof_src_declare_desc(struct kof_objsrc *s, const struct kof_src_desc *d)
{
	void *own;

	if (!s || !d || !d->info || !d->info_len)
		return 1;
	own = malloc(d->info_len);
	if (!own)
		return 0;       /* the view arrives without it, and is raw: the caller says so (E2) */
	memcpy(own, d->info, d->info_len);
	free(s->desc_info);
	s->desc = *d;
	s->desc.info = own;
	s->desc_info = own;
	s->has_desc = 1;
	return 1;
}

const struct kof_src_desc *kof_src_desc_of(const struct kof_objsrc *s)
{
	return s && s->has_desc ? &s->desc : NULL;
}

void kof_src_declare_prod(struct kof_objsrc *s, struct kof_prod *p)
{
	if (!s || !p)
		return;
	kof_prod_unref(s->prod);
	s->prod = p;
}

const struct kof_prod *kof_src_prod_of(const struct kof_objsrc *s)
{
	return s ? s->prod : NULL;
}

const struct kgenome_func *kof_src_funcs_of(const struct kof_objsrc *s, uint32_t *n)
{
	if (n)
		*n = s ? s->n_funcs : 0u;
	return s ? s->funcs : NULL;
}

const struct kof_range *kof_src_fixed_of(const struct kof_objsrc *s, uint32_t *n)
{
	if (n)
		*n = s ? s->n_fixed : 0u;
	return s ? s->fixed : NULL;
}

const uint8_t *kof_src_syms_of(const struct kof_objsrc *s, uint32_t *n)
{
	if (n)
		*n = s ? s->n_syms : 0u;
	return s ? s->syms : NULL;
}

void kof_src_unref(struct kof_objsrc *s)
{
	while (s && --s->refs == 0) {
		struct kof_objsrc *parent = s->parent;
		void (*on_free)(void *, uint64_t) = s->on_free;
		void *arg = s->on_free_arg;
		uint64_t produced = s->produced;
		uint64_t rec_cost;
		void (*rec_release)(void *, uint64_t);
		void *rec_arg;

		kof_unmap_file(s->map, s->map_len);
		free(s->heap);
		/* The label's bytes were taken from a quota by whoever labelled the child
		 * (kof_src_label_account); they go back on every path the child can die on. */
		if (s->label_cost && s->label_release)
			s->label_release(s->label_arg, s->label_cost);
		free(s->label);
		free(s->rgn);
		free(s->syms);
		free(s->funcs);
		free(s->fixed);
		free(s->desc_info);
		kof_prod_unref(s->prod);
		/* The record's own charge, read before the free and given back after it. */
		rec_cost = s->rec_cost;
		rec_release = s->rec_release;
		rec_arg = s->rec_arg;
		free(s);
		if (rec_cost && rec_release)
			rec_release(rec_arg, rec_cost);
		/* After the free, not before: the account should reflect memory
		 * that has already been handed back. */
		if (on_free)
			on_free(arg, produced);
		/* Iterating rather than recursing: a chain of windows can be as deep
		 * as the object tree, and releasing the root of one should not put
		 * that depth on the C stack. */
		s = parent;
	}
}

kof_buf kof_src_buf(const struct kof_objsrc *s)
{
	return s ? kof_buf_make(s->p, s->n) : kof_buf_make(NULL, 0);
}

void kof_src_on_free(struct kof_objsrc *s, void (*fn)(void *, uint64_t), void *user)
{
	if (s) {
		s->on_free = fn;
		s->on_free_arg = user;
	}
}

static int kof_src_tmpfile_in(char *dir_out, size_t dir_cap, const char *first);

/*
 * The first directory in the list above that a file can actually be made in.
 *
 * Answered by trying rather than by testing permissions: a directory that
 * stat says is writable can still refuse - a full filesystem, a read-only
 * mount, a container with no /tmp - and the only test that does not lie is
 * the one the caller was going to do anyway.
 */
const char *kof_src_tmpdir(void)
{
	/* KNOWN DEFECT R1b (2026-10-24, R) [sev L]: kof_src_tmpdir caches its answer in a writable static buffer filled without
	 * a lock, against the rule "no writable global state". Trigger: two scanners on two threads make their first
	 * spill file together. Effect: both write `kept`, a reader can see a half-written path (.bss 0x1000 per the graph_bin audit).
	 * Reproducer: none (read). Fix: fill it under a once flag, or let the host pass the directory. */
	static char kept[4096];
	int fd;

	if (kept[0])
		return kept;
	fd = kof_src_tmpfile_in(kept, sizeof kept, NULL);
	if (fd < 0) {
		kept[0] = 0;
		return NULL;
	}
	close(fd);
	return kept[0] ? kept : NULL;
}

int kof_src_tmpfile(void)
{
	return kof_src_tmpfile_in(NULL, 0, NULL);
}

/* The same, in the host's own directory when it named one and one can be made there;
 * the platform's otherwise (kof_scan_option.scratch_dir). */
int kof_src_tmpfile_at(const char *dir)
{
	return kof_src_tmpfile_in(NULL, 0, dir);
}

static int kof_src_tmpfile_in(char *dir_out, size_t dir_cap, const char *first)
{
	/*
	 * THE PLATFORM IS ASKED, NOT THE ENVIRONMENT.
	 *
	 * This read TMPDIR, TEMP and TMP, and that was wrong for an embedded
	 * engine: where the host process writes is the host's decision, and
	 * lifting it out of that process's environment made a variable set for
	 * something else into engine policy. kof_tmpdir asks the platform -
	 * GetTempPathA on Windows, the standard's P_tmpdir elsewhere - and the
	 * conventional second place stays as a fallback below.
	 */
#ifdef _WIN32
	static const char *const dirs[] = { NULL, "." };
#else
	static const char *const dirs[] = { NULL, "/var/tmp" };
#endif
	const char *env = kof_tmpdir();
	uint32_t i;

	/* `first`, when the host named one, before the platform's list. */
	for (i = 0; i < 1u + sizeof dirs / sizeof dirs[0]; i++) {
		const char *d = i == 0 ? first : dirs[i - 1u] ? dirs[i - 1u] : env;

		char path[4096];
		int fd;

		if (!d || !*d)
			continue;
#ifdef O_TMPFILE
		/* No directory entry is ever created, so there is nothing to
		 * traverse to, nothing to race, and nothing to clean up. */
		fd = open(d, O_TMPFILE | O_RDWR | O_EXCL, 0600);
		if (fd >= 0) {
			if (dir_out)
				snprintf(dir_out, dir_cap, "%s", d);
			return fd;
		}
#endif
		/* Same property one syscall later: the name exists only between
		 * these two calls, and never holds anything. */
		if ((size_t)snprintf(path, sizeof path, "%s%ckofXXXXXX", d,
				     KOF_PATH_SEP) >= sizeof path)
			continue;
#ifdef _WIN32
		/*
		 * TWO DIFFERENCES, BOTH SILENT IF IGNORED.
		 *
		 * Windows refuses to delete a file that is open, so the unlink
		 * below cannot be used to make the file anonymous: it fails,
		 * and every object this engine spills is left on disk. The
		 * _O_TEMPORARY flag reaches the same guarantee from the other
		 * end - the system deletes it when the last handle closes.
		 *
		 * And the CRT opens in TEXT mode by default, which turns every
		 * 0x0A written into 0x0D 0x0A. What is spilled here is a
		 * decompressed object - arbitrary bytes - so text mode does not
		 * add characters to a document, it shifts everything after the
		 * first newline and the scan reads back a file that is not the
		 * one produced.
		 */
		if (!_mktemp(path))
			continue;
		fd = _open(path, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY |
				 _O_TEMPORARY, _S_IREAD | _S_IWRITE);
		if (fd >= 0) {
			if (dir_out)
				snprintf(dir_out, dir_cap, "%s", d);
			return fd;
		}
#else
		fd = mkstemp(path);
		if (fd >= 0) {
			unlink(path);
			if (dir_out)
				snprintf(dir_out, dir_cap, "%s", d);
			return fd;
		}
#endif
	}
	return -1;
}