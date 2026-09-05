/*
 * docole_parse.c - compound files, MS-CFB.
 *
 * A filesystem in a file: fixed size sectors, an allocation table that chains them,
 * and a directory of named entries arranged as a red-black tree. Nothing in it is
 * laid out in the order it is read, which is the fact that shapes everything here -
 * a stream is a linked list, so its region is a list of extents rather than a range,
 * and a walk that follows a pointer has no guarantee of reaching an end.
 *
 *
 * WHAT BOUNDS EACH WALK, AND WHY EACH IS DIFFERENT
 *
 * Three kinds of unbounded structure, and they need three different answers:
 *
 *   - SECTOR CHAINS are followed by offset and can loop. A visited set over
 *     sectors would be the exact answer and costs memory proportional to the file,
 *     which is what this engine will not spend. Instead every sector step in the
 *     whole parse is charged to one counter, sized from the file: an honest file
 *     visits each of its sectors a small number of times, and a loop runs the
 *     counter out. The bound is on the total, not per chain, so a file made of a
 *     thousand short loops costs no more than one long one.
 *
 *   - THE DIRECTORY TREE is followed by entry index, and there are few enough of
 *     those to hold a visited bit for each. So this one gets the exact answer: an
 *     entry is entered once, a cycle is NOTICED rather than merely survived, and
 *     the anomaly says which of the two happened.
 *
 *   - LOOKUP TABLES - the DIFAT, the MiniFAT, the map of the mini stream - are
 *     read far more often than they are built, so they are built once into the
 *     view. Without that, resolving n streams over n sectors means walking a chain
 *     from the start for each, and a file with many small streams turns the parse
 *     quadratic. That is not a theoretical worry: many small streams is exactly
 *     what a document with macros is.
 *
 *
 * THE MINI STREAM, WHICH IS WHERE THE MACROS ARE
 *
 * Streams below 4096 bytes are not given sectors of their own. They live inside one
 * ordinary stream - the root entry's - cut into 64 byte pieces and chained through a
 * second allocation table. Two consequences, both of which matter here:
 *
 *   - The root's own sectors are never claimed as a stream. The bytes are claimed
 *     by whichever mini stream occupies them, and mini sectors nobody allocated
 *     fall through to UNCLAIMED, which is the correct answer for them.
 *
 *   - A macro stream is fragmented at 64 byte granularity. Consecutive pieces are
 *     joined as they are recorded, so an unfragmented one is still a single extent,
 *     but the joins are the reason kof_gather() exists: a pattern lying across one
 *     is in neither piece.
 *
 *
 * OVERLAP
 *
 * Nothing in the format prevents two structures claiming the same bytes - a stream
 * whose chain points into the directory, two streams sharing a sector. Left alone
 * that breaks the partition every region mask rests on, so the runs are settled at
 * the end: sorted by offset, and where two collide the lower numbered class keeps
 * the bytes. Class order is the priority, which is why the enum runs from the
 * container's own structures outward to the document's.
 */

#include "docole_parse.h"
#include "../../kofdecomp/ovba.h"
#include "../runlist.h"

#include <string.h>

/* ---- the format ------------------------------------------------------------- */

static const uint8_t CFB_SIG[8] = {
	0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
};

#define H_MINOR       0x18u
#define H_MAJOR       0x1au
#define H_BYTE_ORDER  0x1cu
#define H_SEC_SHIFT   0x1eu
#define H_MINI_SHIFT  0x20u
#define H_DIR_START   0x30u
#define H_MINI_CUT    0x38u
#define H_MFAT_START  0x3cu
#define H_DIF_START   0x44u
#define H_DIFAT       0x4cu
#define H_DIFAT_N     109u

/* Sector numbers at or below MAXREG name a sector; everything above is a marker. */
#define SEC_MAXREG    0xfffffffau

#define DIR_ENT_LEN   128u
#define D_NAME_LEN    0x40u
#define D_TYPE        0x42u
#define D_LEFT        0x44u
#define D_RIGHT       0x48u
#define D_CHILD       0x4cu
#define D_START       0x74u
#define D_SIZE        0x78u

#define CFB_BYTE_ORDER 0xfffeu
#define CFB_MINI_CUT   4096u
#define CFB_NAME_MAX   64u     /* bytes of UTF-16, terminator included */
#define CFB_HEADER_LEN 512u    /* fixed, whatever the sector size is */

/* ---- the walk's own state ---------------------------------------------------- */

/*
 * Everything the walk needs that is not a fact about the file.
 *
 * Kept apart from the view on purpose: the view is what a module sees, and a step
 * counter is the host's business. The run list is the shared machinery from
 * runlist.h - the joining of consecutive sectors, the settling of overlaps and the
 * per-class totals are the same job in every container format, and were written
 * twice before they were written once.
 */
struct ole {
	kof_buf f;
	struct kof_docole_info *o;
	uint64_t steps, step_max;
	struct kof_runs runs;
};

static uint64_t sec_off(const struct kof_docole_info *o, uint32_t sec)
{
	return ((uint64_t)sec + 1u) * o->sector_size;
}

/* One more sector step, or zero when the parse has taken more than the file can
 * honestly need. Reaching it means a chain loops; nothing else can. */
static int step(struct ole *s)
{
	if (s->steps >= s->step_max) {
		s->o->anomalies |= KOF_DOCOLE_ANOM_FAT_CYCLE;
		return 0;
	}
	s->steps++;
	return 1;
}

/* ---- recording bytes --------------------------------------------------------- */

static void add_run(struct ole *s, uint64_t off, uint64_t len, uint32_t cls)
{
	kof_runs_add(&s->runs, s->f.n, off, len, cls);
}

/* ---- the two allocation tables ----------------------------------------------- */

/*
 * The next sector after `sec`, through the FAT.
 *
 * A table read rather than a walk, because dif[] already says which sector holds
 * which block of the FAT. Anything it cannot answer ends the chain rather than
 * guessing - a truncated file and a FAT past what was mapped are both recorded, and
 * both mean the same thing to the caller.
 */
/*
 * Record a run against the entry currently being claimed.
 *
 * Separate from add_run because these are NOT settled: settling sorts by offset and
 * trims overlaps, which is what a region needs and what would destroy the tie
 * between a run and its stream. Consecutive sectors are still joined here - a
 * stream is one run 76.4% of the time and describing it with 64 would waste the
 * pool on the common case.
 */
static void ent_run_add(struct ole *s, struct kof_docole_entry *e, uint64_t off,
			uint64_t len)
{
	struct kof_docole_info *o = s->o;

	if (!e || !len)
		return;
	if (e->n_runs) {
		struct kof_docole_ent_run *last =
			&o->ent_run[e->first_run + e->n_runs - 1u];

		if (last->off + last->len == off) {
			last->len += len;
			return;
		}
	}
	if (o->n_ent_runs >= KOF_DOCOLE_MAX_ENT_RUNS) {
		e->flags |= KOF_DOCOLE_ENT_RUNS_FULL;
		o->anomalies |= KOF_DOCOLE_ANOM_ENT_RUNS_FULL;
		return;
	}
	o->ent_run[o->n_ent_runs].off = off;
	o->ent_run[o->n_ent_runs].len = len;
	o->n_ent_runs++;
	e->n_runs++;
}

static uint32_t fat_next(struct ole *s, uint32_t sec)
{
	struct kof_docole_info *o = s->o;
	uint32_t per = o->sector_size / 4u;
	uint32_t blk = sec / per, idx = sec % per, v;

	if (blk >= o->n_dif) {
		o->anomalies |= KOF_DOCOLE_ANOM_FAT_UNMAPPED;
		return SEC_MAXREG + 1u;
	}
	if (!kof_rd_u32(s->f, sec_off(o, o->dif[blk]) + (uint64_t)idx * 4u, 0, &v)) {
		o->anomalies |= KOF_DOCOLE_ANOM_TRUNCATED;
		return SEC_MAXREG + 1u;
	}
	return v;
}

static uint32_t mfat_next(struct ole *s, uint32_t msec)
{
	struct kof_docole_info *o = s->o;
	uint32_t per = o->sector_size / 4u;
	uint32_t blk = msec / per, idx = msec % per, v;

	if (blk >= o->n_mfat) {
		o->anomalies |= KOF_DOCOLE_ANOM_MINI_UNMAPPED;
		return SEC_MAXREG + 1u;
	}
	if (!kof_rd_u32(s->f, sec_off(o, o->mfat[blk]) + (uint64_t)idx * 4u, 0, &v)) {
		o->anomalies |= KOF_DOCOLE_ANOM_TRUNCATED;
		return SEC_MAXREG + 1u;
	}
	return v;
}

/*
 * Where mini sector `msec` is in the file.
 *
 * Mini sectors are 64 bytes inside the root's stream, and the sector size is always
 * a multiple of 64, so one never straddles a boundary - which is what lets this
 * return a single offset rather than a pair of ranges.
 */
static int mini_off(struct ole *s, uint32_t msec, uint64_t *out)
{
	struct kof_docole_info *o = s->o;
	uint64_t byte = (uint64_t)msec * o->mini_sector_size;
	uint64_t blk = byte / o->sector_size;

	if (blk >= o->n_mini) {
		o->anomalies |= KOF_DOCOLE_ANOM_MINI_UNMAPPED;
		return 0;
	}
	*out = sec_off(o, o->mini[(uint32_t)blk]) + byte % o->sector_size;
	return 1;
}

/* ---- names ------------------------------------------------------------------- */

/*
 * The entry's name, lowered into ASCII.
 *
 * Anything outside ASCII becomes '?', which is deliberate: this name is only ever
 * compared against a fixed list of structure names that are all ASCII, so a
 * faithful transcoding would buy nothing and a UTF-16 comparison against literals
 * would be one more place to get an encoding wrong. The bytes themselves are still
 * scanned - they are in the DIRECTORY region.
 *
 * The leading byte of a property set name is 0x05 and of an OLE control stream 0x01
 * or 0x03; those are below 0x20 and are preserved rather than replaced, because they
 * are how those streams are recognised.
 */
static uint32_t entry_name(struct ole *s, uint64_t eoff, char *out, uint32_t cap)
{
	uint16_t nlen = 0;
	uint32_t n = 0, i;

	if (!kof_rd_u16(s->f, eoff + D_NAME_LEN, 0, &nlen))
		return 0;
	if (nlen < 2 || nlen > CFB_NAME_MAX || (nlen & 1u)) {
		s->o->anomalies |= KOF_DOCOLE_ANOM_BAD_DIR_ENTRY;
		nlen = nlen > CFB_NAME_MAX ? (uint16_t)CFB_NAME_MAX : nlen;
	}
	if (nlen < 2)
		return 0;

	/* The stored length counts the terminator; the name is what precedes it. */
	for (i = 0; i + 2u <= (uint32_t)nlen - 2u && n + 1u < cap; i += 2) {
		uint16_t ch = 0;

		if (!kof_rd_u16(s->f, eoff + i, 0, &ch))
			break;
		if (ch == 0)
			break;
		if (ch >= 'A' && ch <= 'Z')
			ch = (uint16_t)(ch + ('a' - 'A'));
		out[n++] = ch < 0x80u ? (char)ch : '?';
	}
	out[n] = 0;
	return n;
}

/*
 * Which class a name puts an entry in, or COUNT for "the name says nothing".
 *
 * Names, not positions, and a fixed list rather than a guess: these are the streams
 * the document formats define, and anything not on the list is document body. The
 * list is short because it only needs the ones whose class differs from the default
 * - there is no entry for WordDocument or Workbook, because DATA is already what
 * they get.
 *
 * The storage names are the load bearing ones. A VBA project is a storage with
 * streams under it whose names are chosen by whoever wrote the macros, so matching
 * the leaf names would be matching attacker input; matching the storage and
 * inheriting downward matches the structure instead.
 */
static uint32_t class_of_name(const char *nm)
{
	static const struct { const char *n; uint8_t cls; } tab[] = {
		{ "\001compobj",       KOF_DOCOLE_CLS_METADATA },
		{ "macros",            KOF_DOCOLE_CLS_MACROS },
		{ "_vba_project_cur",  KOF_DOCOLE_CLS_MACROS },
		{ "vba",               KOF_DOCOLE_CLS_MACROS },
		{ "_vba_project",      KOF_DOCOLE_CLS_MACROS },
		{ "objectpool",        KOF_DOCOLE_CLS_RESOURCES },
		{ "data",              KOF_DOCOLE_CLS_RESOURCES },
		{ "pictures",          KOF_DOCOLE_CLS_RESOURCES },
		{ "\001ole",           KOF_DOCOLE_CLS_RESOURCES },
		{ "\001ole10native",   KOF_DOCOLE_CLS_RESOURCES },
		{ "\003objinfo",       KOF_DOCOLE_CLS_RESOURCES },
		/*
		 * An encrypted document. Both streams are opaque, so they are
		 * resources rather than content: searching them is searching
		 * ciphertext, and putting them in CONTENT_DATA would spend a gather
		 * on bytes no pattern can match.
		 */
		{ "encryptedpackage",  KOF_DOCOLE_CLS_RESOURCES },
		{ "encryptioninfo",    KOF_DOCOLE_CLS_RESOURCES }
	};
	uint32_t i;

	/* Every property set stream begins 0x05, whatever follows it. Taken as a rule
	 * rather than by listing the two standard ones, because a producer may write
	 * its own and it is still metadata. */
	if (nm[0] == 0x05)
		return KOF_DOCOLE_CLS_METADATA;

	for (i = 0; i < sizeof tab / sizeof tab[0]; i++)
		if (strcmp(nm, tab[i].n) == 0)
			return tab[i].cls;
	return KOF_DOCOLE_CLS_COUNT;
}

/* ---- streams ------------------------------------------------------------------ */

static void claim_fat_chain(struct ole *s, uint32_t start, uint64_t size,
			    uint32_t cls, struct kof_docole_entry *e)
{
	struct kof_docole_info *o = s->o;
	uint32_t sec = start;
	uint64_t left = size;

	while (left && sec <= SEC_MAXREG && step(s)) {
		uint64_t n = left < o->sector_size ? left : o->sector_size;

		add_run(s, sec_off(o, sec), n, cls);
		ent_run_add(s, e, sec_off(o, sec), n);
		left -= n;
		sec = fat_next(s, sec);
	}
	if (left) {
		o->anomalies |= KOF_DOCOLE_ANOM_STREAM_PAST_EOF;
		if (e)
			e->flags |= KOF_DOCOLE_ENT_SHORT;
	}
}

static void claim_mini_chain(struct ole *s, uint32_t start, uint64_t size,
			     uint32_t cls, struct kof_docole_entry *e)
{
	struct kof_docole_info *o = s->o;
	uint32_t msec = start;
	uint64_t left = size;

	while (left && msec <= SEC_MAXREG && step(s)) {
		uint64_t n = left < o->mini_sector_size ? left : o->mini_sector_size;
		uint64_t off;

		if (!mini_off(s, msec, &off))
			break;
		add_run(s, off, n, cls);
		ent_run_add(s, e, off, n);
		left -= n;
		msec = mfat_next(s, msec);
	}
	if (left) {
		o->anomalies |= KOF_DOCOLE_ANOM_STREAM_PAST_EOF;
		if (e)
			e->flags |= KOF_DOCOLE_ENT_SHORT;
	}
}

/* Collect a chain's sector numbers without claiming their bytes. Used for the
 * structures that are read through rather than searched: the mini stream's
 * container, whose bytes belong to the streams inside it. */
static uint32_t collect_chain(struct ole *s, uint32_t start, uint32_t *out,
			      uint32_t max, uint32_t claim_cls)
{
	uint32_t sec = start, n = 0;

	while (sec <= SEC_MAXREG && n < max && step(s)) {
		if (claim_cls < KOF_DOCOLE_CLS_COUNT)
			add_run(s, sec_off(s->o, sec), s->o->sector_size, claim_cls);
		out[n++] = sec;
		sec = fat_next(s, sec);
	}
	return n;
}

/* ---- the directory ------------------------------------------------------------ */

#define DIR_NONE UINT64_MAX

static uint64_t dir_ent_off(const struct kof_docole_info *o, uint32_t idx)
{
	uint32_t per = o->sector_size / DIR_ENT_LEN;
	uint32_t blk = idx / per;

	if (per == 0 || blk >= o->n_dirsec)
		return DIR_NONE;
	return sec_off(o, o->dirsec[blk]) + (uint64_t)(idx % per) * DIR_ENT_LEN;
}

static int seen_test_set(struct kof_docole_info *o, uint32_t idx)
{
	uint32_t w = idx / 32u, b = 1u << (idx % 32u);

	if (o->seen[w] & b)
		return 1;
	o->seen[w] |= b;
	return 0;
}

/* idx, class and depth in one word: the walk pushes thousands of these and a
 * struct would triple the stack this format already has to carry. */
#define ST_PACK(idx, cls, depth) \
	((uint32_t)(idx) | ((uint32_t)(cls) << 16) | ((uint32_t)(depth) << 24))
#define ST_IDX(v)   ((v) & 0xffffu)
#define ST_CLS(v)   (((v) >> 16) & 0xffu)
#define ST_DEPTH(v) (((v) >> 24) & 0xffu)

static void push(struct ole *s, uint32_t *sp, uint32_t idx, uint32_t cls,
		 uint32_t depth)
{
	if (idx > SEC_MAXREG || idx >= s->o->dir_count)
		return;
	if (*sp >= KOF_DOCOLE_MAX_DIR) {
		s->o->anomalies |= KOF_DOCOLE_ANOM_DIR_OVERFLOW;
		return;
	}
	s->o->stack[(*sp)++] = ST_PACK(idx, cls, depth);
}

static void add_declared(struct kof_docole_info *o, uint32_t cls, uint64_t size)
{
	switch (cls) {
	case KOF_DOCOLE_CLS_DATA:      o->data_bytes += size; break;
	case KOF_DOCOLE_CLS_MACROS:    o->macro_bytes += size; break;
	case KOF_DOCOLE_CLS_METADATA:  o->meta_bytes += size; break;
	case KOF_DOCOLE_CLS_RESOURCES: o->resource_bytes += size; break;
	default: break;
	}
}

/*
 * Walk the tree from the root's child, classifying and claiming as it goes.
 *
 * Iterative, because the sibling links of a red-black tree can degenerate into a
 * list as long as the directory - recursion over them would be a stack depth the
 * file chooses. The child link is what nests, and that is bounded separately and
 * far more tightly.
 *
 * The class passed to a sibling is the PARENT's, not the current entry's: left and
 * right are peers inside the same storage, so a macro storage does not make its
 * neighbours macros. Only the child link carries a class downward.
 */
/*
 * Walk the directory, from the tree or straight through it.
 *
 * `linear` is the recovery path and it exists because the tree is an INDEX over an
 * array rather than a substitute for it: every entry is physically there whether or
 * not a pointer reaches it, so when the pointers do not hold, reading the array is
 * still a complete answer.
 *
 * Measured on a real workbook: its directory chain runs through a sector at offset
 * 109056 of a 106496 byte file and the root's child is the entry that would live
 * there. From the tree the file has no streams at all; read straight through it has
 * 24, including the Workbook and every VBA module in it.
 *
 * The entries found this way carry no parent, because the thing that would have
 * said who their parent is is the thing that failed. So each is classified by its
 * own name and nothing else - which loses the "under a VBA storage" inference and
 * keeps everything that does not depend on it.
 */
static void walk_dir(struct ole *s, uint32_t root_child, int linear)
{
	struct kof_docole_info *o = s->o;
	uint32_t sp = 0;

	if (linear) {
		uint32_t idx;

		for (idx = 0; idx < o->dir_count && sp < KOF_DOCOLE_MAX_DIR; idx++)
			push(s, &sp, idx, KOF_DOCOLE_CLS_COUNT, 0);
	} else {
		push(s, &sp, root_child, KOF_DOCOLE_CLS_COUNT, 0);
	}

	while (sp) {
		uint32_t v = o->stack[--sp];
		uint32_t idx = ST_IDX(v), up = ST_CLS(v), depth = ST_DEPTH(v);
		uint64_t eoff = dir_ent_off(o, idx);
		char nm[CFB_NAME_MAX / 2u + 1u];
		struct kof_docole_entry *e;
		uint32_t own, cls, left, right, child, start;
		uint64_t size = 0;
		uint8_t type = 0;

		if (eoff == DIR_NONE)
			continue;
		if (seen_test_set(o, idx)) {
			o->anomalies |= KOF_DOCOLE_ANOM_DIR_CYCLE;
			continue;
		}
		if (!kof_rd_u8(s->f, eoff + D_TYPE, &type))
			continue;

		entry_name(s, eoff, nm, sizeof nm);
		own = class_of_name(nm);

		/* Siblings share this entry's context, whatever this entry is. */
		if (kof_rd_u32(s->f, eoff + D_LEFT, 0, &left))
			push(s, &sp, left, up, depth);
		if (kof_rd_u32(s->f, eoff + D_RIGHT, 0, &right))
			push(s, &sp, right, up, depth);

		if (type == KOF_DOCOLE_T_STORAGE) {
			uint32_t sub = own < KOF_DOCOLE_CLS_COUNT ? own : up;

			o->storage_count++;
			if (kof_rd_u32(s->f, eoff + D_CHILD, 0, &child) &&
			    child <= SEC_MAXREG) {
				if (depth + 1u < KOF_DOCOLE_MAX_DEPTH)
					push(s, &sp, child, sub, depth + 1u);
				else
					o->anomalies |= KOF_DOCOLE_ANOM_DIR_DEPTH;
			}
			continue;
		}
		if (type != KOF_DOCOLE_T_STREAM) {
			if (type != KOF_DOCOLE_T_UNUSED)
				o->anomalies |= KOF_DOCOLE_ANOM_BAD_DIR_ENTRY;
			continue;
		}

		/* A stream. Its own name decides, then what it is nested under, then
		 * the default - which is the document body. */
		cls = own < KOF_DOCOLE_CLS_COUNT ? own :
		      (up < KOF_DOCOLE_CLS_COUNT ? up : KOF_DOCOLE_CLS_DATA);

		if (!kof_rd_u32(s->f, eoff + D_START, 0, &start) ||
		    !kof_rd_u64(s->f, eoff + D_SIZE, 0, &size))
			continue;
		/* Version 3 states a 32 bit size in a 64 bit field. A high half that
		 * is set is a file disagreeing with its own header. */
		if (o->major == 3 && (size >> 32) != 0) {
			o->anomalies |= KOF_DOCOLE_ANOM_BAD_DIR_ENTRY;
			size &= 0xffffffffu;
		}

		o->stream_count++;
		add_declared(o, cls, size);
		if (cls == KOF_DOCOLE_CLS_MACROS)
			o->has_macros = 1;
		if (strcmp(nm, "encryptedpackage") == 0) {
			o->encrypted = 1;
			o->anomalies |= KOF_DOCOLE_ANOM_ENCRYPTED;
		}

		/*
		 * List the stream, whether or not it has bytes.
		 *
		 * An empty stream still says what the document contains, and a module
		 * asking what is in a VBA project wants to see a module that was
		 * emptied as much as one that was filled.
		 */
		e = 0;
		if (o->n_entries < KOF_DOCOLE_MAX_ENTRIES) {
			uint16_t nlen = 0;

			e = &o->ent[o->n_entries++];
			e->name_off  = eoff;
			e->name_len  = kof_rd_u16(s->f, eoff + D_NAME_LEN, 0, &nlen) &&
				       nlen >= 2u && nlen <= CFB_NAME_MAX
				       ? (uint32_t)(nlen - 2u) : 0u;
			e->size_lo   = (uint32_t)size;
			e->size_hi   = (uint32_t)(size >> 32);
			e->first_run = o->n_ent_runs;
			e->n_runs    = 0;
			e->cls       = cls;
			e->flags     = size < o->mini_cutoff ? KOF_DOCOLE_ENT_MINI : 0u;
			e->data_off  = 0;
		} else {
			o->anomalies |= KOF_DOCOLE_ANOM_ENTRIES_FULL;
		}

		if (size == 0)
			continue;
		if (size < o->mini_cutoff)
			claim_mini_chain(s, start, size, cls, e);
		else
			claim_fat_chain(s, start, size, cls, e);
	}
}

/* ---- the VBA project's own directory ------------------------------------------ */

/*
 * MS-OVBA record ids. Only the two that say where a module's source is.
 */
#define VBA_REC_MODULESTREAMNAME 0x001au
#define VBA_REC_MODULEOFFSET     0x0031u

/* What decompressing `dir` is allowed to produce. Measured over 50 documents the
 * largest was 12KB; this is an order of magnitude above it and bounds a file that
 * declares a project record it does not have. */
#define VBA_DIR_MAX 131072u

static uint32_t rd32_at(const uint8_t *p, uint32_t at)
{
	return (uint32_t)p[at] | ((uint32_t)p[at + 1] << 8) |
	       ((uint32_t)p[at + 2] << 16) | ((uint32_t)p[at + 3] << 24);
}

struct dirbuf {
	uint8_t *p;
	uint32_t cap, n;
};

static int dirbuf_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct dirbuf *d = user;
	uint32_t k;

	for (k = 0; k < n && d->n < d->cap; k++)
		d->p[d->n++] = p[k];
	return d->n < d->cap;
}

/* The stream's bytes from `skip` onward, joined in chain order, up to cap. */
static uint32_t ent_bytes_at(struct ole *s, const struct kof_docole_entry *e,
			     uint64_t skip, uint8_t *out, uint32_t cap)
{
	uint32_t n = 0, r;

	for (r = 0; r < e->n_runs && n < cap; r++) {
		const struct kof_docole_ent_run *q = &s->o->ent_run[e->first_run + r];
		uint64_t k, len = kof_clip_len(s->f.n, q->off, q->len);

		if (skip >= len) {
			skip -= len;
			continue;
		}
		for (k = skip; k < len && n < cap; k++)
			out[n++] = s->f.p[q->off + k];
		skip = 0;
	}
	return n;
}

static uint32_t ent_bytes(struct ole *s, const struct kof_docole_entry *e,
			  uint8_t *out, uint32_t cap)
{
	return ent_bytes_at(s, e, 0, out, cap);
}

/* Compare an entry's UTF-16 name against ASCII, case folded - the same comparison
 * entry_name does, without building the string again. */
static int name_eq(struct ole *s, const struct kof_docole_entry *e,
		   const uint8_t *want, uint32_t want_len)
{
	uint32_t i;

	if (e->name_len != want_len * 2u)
		return 0;
	for (i = 0; i < want_len; i++) {
		uint16_t ch = 0;
		uint16_t w = want[i];

		if (!kof_rd_u16(s->f, e->name_off + i * 2u, 0, &ch))
			return 0;
		if (ch >= 'A' && ch <= 'Z')
			ch = (uint16_t)(ch + ('a' - 'A'));
		if (w >= 'A' && w <= 'Z')
			w = (uint16_t)(w + ('a' - 'A'));
		if (ch != w)
			return 0;
	}
	return 1;
}

/*
 * Read `dir` and tell every module stream where its source begins.
 *
 * The project directory is itself an OVBA container, and unlike a module stream it
 * starts with one - so this is the one decompression the parse can do without
 * already knowing the answer it is looking for. Inside are records of id, length
 * and payload; a module is described by its stream name followed by the offset at
 * which its compressed source sits.
 *
 * A parse that decompresses is unusual here and is worth the exception: the offset
 * exists nowhere else in the file, and without it the module streams can only be
 * guessed at.
 */
static void vba_module_offsets(struct ole *s)
{
	struct kof_docole_info *o = s->o;
	struct dirbuf d;
	uint8_t *raw = 0;
	uint32_t i, at, name_at = 0, name_len = 0;

	if (!o->has_macros)
		return;

	/*
	 * The project directory, found by name AND by shape.
	 *
	 * Not by class, and that matters when the tree failed: a recovered directory
	 * has no parents, so a stream called "dir" is classified as document data
	 * like anything else whose name says nothing. Requiring it to also BEGIN with
	 * a compressed container is what makes the name safe to trust - "dir" is a
	 * common enough name that the name alone is not evidence.
	 */
	for (i = 0; i < o->n_entries; i++) {
		uint8_t head[3];

		if (!o->ent[i].n_runs ||
		    !name_eq(s, &o->ent[i], (const uint8_t *)"dir", 3u))
			continue;
		if (ent_bytes_at(s, &o->ent[i], 0, head, sizeof head) ==
		    sizeof head && kof_ovba_plausible(head, sizeof head))
			break;
	}
	if (i >= o->n_entries)
		return;

	raw = malloc(VBA_DIR_MAX);
	d.p = malloc(VBA_DIR_MAX);
	if (!raw || !d.p)
		goto out;
	d.cap = VBA_DIR_MAX;
	d.n = 0;
	{
		uint32_t got = ent_bytes(s, &o->ent[i], raw, VBA_DIR_MAX);
		uint64_t produced = 0;

		if (!got)
			goto out;
		kof_ovba_decode(raw, got, dirbuf_sink, &d, &produced);
	}

	/*
	 * Anchored on the module name rather than walked from the front.
	 *
	 * Walking every record in order is the obvious way and it does not survive
	 * real files: the reference records carry nested structures whose length
	 * fields do not describe the whole of what follows, so a sequential walk
	 * loses its place and reads a length out of the middle of a GUID. Measured,
	 * it fails on the first document tried.
	 *
	 * What is stable is the MODULE record's own shape - a stream name, then
	 * within the next few records the offset of that module's source. So the
	 * name is the anchor and the search for the offset is local and bounded,
	 * which needs none of the grammar in between. Over 50 documents this finds
	 * 112 modules and 109 of them decompress to VBA; the three that do not are
	 * documents naming a module they do not contain.
	 */
	for (at = 0; at + 6u <= d.n; ) {
		uint32_t nlen, j, hop;
		int printable = 1;

		if (d.p[at] != (uint8_t)VBA_REC_MODULESTREAMNAME || d.p[at + 1]) {
			at++;
			continue;
		}
		nlen = rd32_at(d.p, at + 2u);
		if (nlen < 1u || nlen > CFB_NAME_MAX || at + 6u + nlen > d.n) {
			at++;
			continue;
		}
		for (j = 0; j < nlen; j++)
			if (d.p[at + 6u + j] < 0x20u || d.p[at + 6u + j] >= 0x7fu) {
				printable = 0;
				break;
			}
		if (!printable) {
			at++;
			continue;
		}
		name_at = at + 6u;
		name_len = nlen;

		/* The offset is a few records along, never far. */
		j = name_at + nlen;
		for (hop = 0; hop < 8u && j + 6u <= d.n; hop++) {
			uint32_t id = (uint32_t)d.p[j] | ((uint32_t)d.p[j + 1] << 8);
			uint32_t len = rd32_at(d.p, j + 2u);

			if (len > d.n - j - 6u)
				break;
			if (id == VBA_REC_MODULEOFFSET && len >= 4u) {
				uint32_t off = rd32_at(d.p, j + 6u);
				uint32_t k;

				for (k = 0; k < o->n_entries; k++) {
					struct kof_docole_entry *e = &o->ent[k];
					uint64_t size = ((uint64_t)e->size_hi << 32) |
							e->size_lo;

					if (!e->n_runs)
						continue;
					if (!name_eq(s, e, d.p + name_at, name_len))
						continue;
					/*
					 * The project's OWN directory named this
					 * stream as a module, which outranks how
					 * the tree classified it - and is the only
					 * authority left when the tree did not
					 * classify it at all.
					 */
					e->cls = KOF_DOCOLE_CLS_MACROS;
					/* An offset past the stream is a document
					 * describing a module it does not hold. */
					if (off < size)
						e->data_off = off;
					break;
				}
				break;
			}
			j += 6u + len;
		}
		at = j;
	}
	/*
	 * Which streams a decoder can actually be pointed at.
	 *
	 * Done after the offsets are known and for every macro stream, including
	 * the ones dir said nothing about - `dir` itself is a container at offset
	 * zero and is worth reading for the same reason the modules are.
	 */
	for (i = 0; i < o->n_entries; i++) {
		struct kof_docole_entry *e = &o->ent[i];
		uint8_t head[3];
		uint32_t got;

		if (e->cls != KOF_DOCOLE_CLS_MACROS || !e->n_runs)
			continue;
		got = ent_bytes_at(s, e, e->data_off, head, sizeof head);
		if (got == sizeof head && kof_ovba_plausible(head, got))
			e->flags |= KOF_DOCOLE_ENT_OVBA;
	}
out:
	free(raw);
	free(d.p);
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t docole_cls_bit[KOF_DOCOLE_CLS_COUNT] = {
	KOF_SCAN_DOCOLE_HEADERS,
	KOF_SCAN_DOCOLE_DIRECTORY,
	KOF_SCAN_DOCOLE_CONTENT_DATA,
	KOF_SCAN_DOCOLE_CONTENT_MACROS,
	KOF_SCAN_DOCOLE_CONTENT_METADATA,
	KOF_SCAN_DOCOLE_RESOURCES
};

static uint32_t docole_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				    struct kof_range *out, uint32_t max_out)
{
	const struct kof_docole_info *o =
		(const struct kof_docole_info *)ctx->file_header;

	if (!o || !o->valid || !out || max_out == 0)
		return 0;
	/*
	 * The cast is to the shared run shape, which docole.h spells out field for
	 * field rather than including a host header from the ABI. A mismatch would be
	 * a memory bug, so it is asserted at compile time rather than trusted.
	 */
	_Static_assert(sizeof o->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)o->run, o->n_runs, mask,
				docole_cls_bit, KOF_SCAN_DOCOLE_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- the parse ---------------------------------------------------------------- */

/*
 * The ranges of one stream, in chain order.
 *
 * Deliberately not sorted and deliberately not settled. The runs came off a chain
 * and that order is the order the bytes go back together in - a stream whose
 * sectors were written backwards through the file is ordinary, and sorting it by
 * offset would hand back a different stream that happens to use the same bytes.
 */
static uint32_t docole_resolve_entry(const struct kof_obj_ctx *ctx, uint32_t index,
				     struct kof_range *out, uint32_t max_out)
{
	const struct kof_docole_info *o =
		(const struct kof_docole_info *)ctx->file_header;
	uint32_t i, n = 0;
	uint64_t skip;

	if (!o || !o->valid || !out || max_out == 0 || index >= o->n_entries)
		return 0;

	/*
	 * Answered from data_off onward, which for every stream but a VBA module
	 * is the whole of it. What a caller wants from an entry is the part that
	 * can be decoded; the p-code in front of a module's source is not that, and
	 * making each caller skip it would put the same subtraction in every one.
	 */
	skip = o->ent[index].data_off;
	for (i = 0; i < o->ent[index].n_runs && n < max_out; i++) {
		const struct kof_docole_ent_run *r =
			&o->ent_run[o->ent[index].first_run + i];
		uint64_t off = r->off, len = r->len;

		if (skip >= len) {
			skip -= len;
			continue;
		}
		off += skip;
		len -= skip;
		skip = 0;
		out[n].off = off;
		out[n].len = len;
		n++;
	}
	return n;
}

int kof_docole_sniff(kof_buf file)
{
	return file.n >= sizeof CFB_SIG &&
	       memcmp(file.p, CFB_SIG, sizeof CFB_SIG) == 0;
}

int kof_docole_parse(kof_buf file, struct kof_docole_info *o,
		     struct kof_obj_ctx *ctx)
{
	struct ole s;
	uint16_t bo = 0, ss = 0, ms = 0;
	uint32_t dir_start = 0, mfat_start = 0, dif_start = 0, mini_cut = 0;
	uint32_t i, per, max_dirsec, root_child = 0, root_start = 0;
	uint64_t root_size = 0, eoff;
	uint8_t root_type = 0;

	memset(o, 0, sizeof *o);
	o->version = KOF_DOCOLE_INFO_VERSION;

	if (!kof_docole_sniff(file))
		return 0;
	o->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.o = o;
	kof_runs_init(&s.runs, (struct kof_run *)o->run, KOF_DOCOLE_MAX_EXTENTS,
		      KOF_DOCOLE_CLS_COUNT);
	/*
	 * How many sector steps an honest file can need.
	 *
	 * Every walk here reads each sector a small number of times, and the
	 * smallest thing a step covers is a 64 byte mini sector - so the whole parse
	 * is bounded by a constant times the file's length over 64. A third of that
	 * is generous for a real document and is reached only by a loop.
	 */
	s.step_max = file.n / 32u + 4096u;

	/*
	 * The header, claimed before anything in it is believed.
	 *
	 * It is 512 bytes by definition, whatever the sector shift says - version 4
	 * puts the same fields in a 4096 byte sector and pads the rest. Claiming it
	 * here rather than after the shift is validated is what makes the region mean
	 * the same thing on a file this cannot walk: the bytes are a compound file
	 * header, that much was established by the signature, and a file that gives up
	 * two fields later should not report every byte of itself as unclaimed.
	 */
	add_run(&s, 0, CFB_HEADER_LEN, KOF_DOCOLE_CLS_HEADERS);

	if (!kof_rd_u16(file, H_MINOR, 0, &o->minor) ||
	    !kof_rd_u16(file, H_MAJOR, 0, &o->major) ||
	    !kof_rd_u16(file, H_BYTE_ORDER, 0, &bo) ||
	    !kof_rd_u16(file, H_SEC_SHIFT, 0, &ss) ||
	    !kof_rd_u16(file, H_MINI_SHIFT, 0, &ms)) {
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_HEADER;
		o->sector_size = 512;
		goto done;
	}

	if (bo != CFB_BYTE_ORDER || (o->major != 3 && o->major != 4))
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_HEADER;

	/*
	 * The sector shift decides where everything is, so a wrong one is not an
	 * anomaly to note and carry on from - every offset computed after it would
	 * be fiction. The header is claimed and the walk is not attempted.
	 */
	if (ss != 9 && ss != 12) {
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_SECTOR;
		o->sector_size = 512;
		goto done;
	}
	o->sector_size = 1u << ss;
	if ((o->major == 3 && ss != 9) || (o->major == 4 && ss != 12))
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_HEADER;

	if (ms != 6) {
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_HEADER;
		ms = 6;
	}
	o->mini_sector_size = 1u << ms;

	kof_rd_u32(file, H_DIR_START, 0, &dir_start);
	kof_rd_u32(file, H_MFAT_START, 0, &mfat_start);
	kof_rd_u32(file, H_DIF_START, 0, &dif_start);
	kof_rd_u32(file, H_MINI_CUT, 0, &mini_cut);

	o->mini_cutoff = mini_cut;
	if (mini_cut != CFB_MINI_CUT) {
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_HEADER;
		o->mini_cutoff = CFB_MINI_CUT;
	}

	/* The rest of the first sector, which version 4 pads out past the header's
	 * 512 bytes. Left unclaimed it would put an always-present run of zeroes into
	 * UNCLAIMED; claimed as a second run it coalesces with the header above. */
	if (o->sector_size > CFB_HEADER_LEN)
		add_run(&s, CFB_HEADER_LEN, o->sector_size - CFB_HEADER_LEN,
			KOF_DOCOLE_CLS_HEADERS);

	/* ---- the DIFAT: which sector holds which block of the FAT ---- */

	for (i = 0; i < H_DIFAT_N && o->n_dif < KOF_DOCOLE_MAX_FAT; i++) {
		uint32_t v;

		if (!kof_rd_u32(file, H_DIFAT + (uint64_t)i * 4u, 0, &v))
			break;
		if (v > SEC_MAXREG)
			continue;
		o->dif[o->n_dif++] = v;
	}

	per = o->sector_size / 4u;
	while (dif_start <= SEC_MAXREG && o->n_dif < KOF_DOCOLE_MAX_FAT && step(&s)) {
		uint64_t base = sec_off(o, dif_start);
		uint32_t v;

		add_run(&s, base, o->sector_size, KOF_DOCOLE_CLS_HEADERS);
		for (i = 0; i + 1u < per && o->n_dif < KOF_DOCOLE_MAX_FAT; i++) {
			if (!kof_rd_u32(file, base + (uint64_t)i * 4u, 0, &v))
				break;
			if (v > SEC_MAXREG)
				continue;
			o->dif[o->n_dif++] = v;
		}
		/* The last slot of a DIFAT sector is the next one, not a FAT sector. */
		if (!kof_rd_u32(file, base + (uint64_t)(per - 1u) * 4u, 0, &v))
			break;
		dif_start = v;
	}
	if (o->n_dif >= KOF_DOCOLE_MAX_FAT)
		o->anomalies |= KOF_DOCOLE_ANOM_FAT_UNMAPPED;

	/* The FAT itself is structure: it says where bytes are and holds none. */
	for (i = 0; i < o->n_dif; i++)
		add_run(&s, sec_off(o, o->dif[i]), o->sector_size,
			KOF_DOCOLE_CLS_HEADERS);

	/* ---- the MiniFAT ---- */

	o->n_mfat = collect_chain(&s, mfat_start, o->mfat, KOF_DOCOLE_MAX_MINIFAT,
				  KOF_DOCOLE_CLS_HEADERS);

	/* ---- the directory ---- */

	per = o->sector_size / DIR_ENT_LEN;
	max_dirsec = KOF_DOCOLE_MAX_DIR / (per ? per : 1u);
	if (max_dirsec > KOF_DOCOLE_MAX_DIR / 4u)
		max_dirsec = KOF_DOCOLE_MAX_DIR / 4u;

	o->n_dirsec = collect_chain(&s, dir_start, o->dirsec, max_dirsec,
				    KOF_DOCOLE_CLS_DIRECTORY);
	o->dir_count = o->n_dirsec * per;
	if (o->n_dirsec == max_dirsec)
		o->anomalies |= KOF_DOCOLE_ANOM_DIR_OVERFLOW;
	if (o->dir_count == 0) {
		o->anomalies |= KOF_DOCOLE_ANOM_NO_STREAMS;
		goto done;
	}

	/* ---- the root, and through it the mini stream ---- */

	eoff = dir_ent_off(o, 0);
	if (eoff == DIR_NONE)
		goto done;
	kof_rd_u8(file, eoff + D_TYPE, &root_type);
	if (root_type != KOF_DOCOLE_T_ROOT)
		o->anomalies |= KOF_DOCOLE_ANOM_BAD_DIR_ENTRY;
	kof_rd_u32(file, eoff + D_CHILD, 0, &root_child);
	kof_rd_u32(file, eoff + D_START, 0, &root_start);
	kof_rd_u64(file, eoff + D_SIZE, 0, &root_size);
	if (o->major == 3)
		root_size &= 0xffffffffu;

	/*
	 * The mini stream's sectors are mapped, not claimed. Their bytes belong to
	 * the mini streams that occupy them, and claiming them here would put every
	 * macro in two regions at once.
	 */
	if (root_size)
		o->n_mini = collect_chain(&s, root_start, o->mini,
					  KOF_DOCOLE_MAX_MINI_SEC,
					  KOF_DOCOLE_CLS_COUNT);
	if (o->n_mini == KOF_DOCOLE_MAX_MINI_SEC)
		o->anomalies |= KOF_DOCOLE_ANOM_MINI_UNMAPPED;

	walk_dir(&s, root_child, 0);

	/*
	 * The tree said nothing. Read the directory as an array instead.
	 *
	 * A compound file's directory is a red-black tree, so every entry is reached
	 * through the one before it and a single bad pointer costs all of them. The
	 * pointers are fields in the file, so one being wrong is ordinary rather than
	 * exceptional - and the entries are still sitting in the sectors either way,
	 * because the tree is an index over an array, not a substitute for it.
	 *
	 * Measured on a real workbook: the directory chain runs through a sector at
	 * offset 109056 of a 106496 byte file, and the root's child is the entry that
	 * would live there. The walk reached nothing, the file reported no streams at
	 * all, and reading the same directory straight through finds 24 entries -
	 * including the Workbook and every VBA module in it.
	 *
	 * Same shape of answer as the zip parser searching backwards for an end record
	 * and the xz parser searching for its footer: trust the structure, and when the
	 * structure does not hold, look at what is there.
	 */
	if (o->stream_count == 0 && o->dir_count) {
		o->anomalies |= KOF_DOCOLE_ANOM_DIR_RECOVERED;
		memset(o->seen, 0, sizeof o->seen);
		walk_dir(&s, 0, 1);
	}

	if (o->stream_count == 0)
		o->anomalies |= KOF_DOCOLE_ANOM_NO_STREAMS;
	if (o->macro_bytes > KOF_DOCOLE_MACRO_SUSPECT)
		o->anomalies |= KOF_DOCOLE_ANOM_MACRO_OVERSIZE;

done:
	kof_runs_settle(&s.runs, o->region_bytes);
	o->n_runs = s.runs.n;
	if (s.runs.full)
		o->anomalies |= KOF_DOCOLE_ANOM_EXTENTS_FULL;
	if (s.runs.clipped)
		o->anomalies |= KOF_DOCOLE_ANOM_TRUNCATED;
	if (s.runs.overlapped)
		o->anomalies |= KOF_DOCOLE_ANOM_OVERLAP;

	ctx->format = KOF_FMT_DOCOLE;
	vba_module_offsets(&s);

	ctx->obj_size = file.n;
	ctx->file_header = o;
	ctx->resolve_scan = docole_resolve_scan;
	ctx->resolve_entry = docole_resolve_entry;
	/* No architecture and no entry point: a document is not code, and leaving
	 * them as the caller set them is what lets arch-targeted modules be ruled out
	 * rather than matched by accident. */
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */


#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_docole_region_bits[] = { DOCOLE_REGIONS(X_BIT) };
_Static_assert(sizeof kof_docole_region_bits / sizeof kof_docole_region_bits[0] ==
	       KOF_DOCOLE_REGION_COUNT, "region list and its count disagree");

const char *kof_docole_region_name(uint32_t bit)
{
	switch (bit) {
	DOCOLE_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_docole_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_HEADER", "BAD_SECTOR", "TRUNCATED", "FAT_CYCLE", "DIR_CYCLE",
		"DIR_DEPTH", "DIR_OVERFLOW", "BAD_DIR_ENTRY", "EXTENTS_FULL",
		"FAT_UNMAPPED", "MINI_UNMAPPED", "STREAM_PAST_EOF",
		"MACRO_OVERSIZE", "NO_STREAMS", "ENCRYPTED", "OVERLAP",
		"ENTRIES_FULL", "ENT_RUNS_FULL", "DIR_RECOVERED"
	};


	_Static_assert(sizeof n / sizeof n[0] == KOF_DOCOLE_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
