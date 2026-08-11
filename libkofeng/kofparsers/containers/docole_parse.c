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
#include "../rangelist.h"

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
 * counter is the host's business. `last` is the coalescing hint - the index, plus
 * one, of the most recent run of each class, so that a chain running through
 * consecutive sectors records one extent instead of one per sector.
 */
struct ole {
	kof_buf f;
	struct kof_docole_info *o;
	uint64_t steps, step_max;
	uint32_t last[KOF_DOCOLE_CLS_COUNT];
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
	struct kof_docole_info *o = s->o;
	uint64_t got = kof_clip_len(s->f.n, off, len);

	if (len == 0)
		return;
	if (got != len)
		o->anomalies |= KOF_DOCOLE_ANOM_TRUNCATED;
	if (got == 0)
		return;

	/* Consecutive sectors of one chain are one extent. Only the last run of this
	 * class is tried: a chain lays its sectors down in order, so that is where a
	 * join can be, and searching further back would cost more than it saves. */
	if (s->last[cls]) {
		struct kof_docole_run *r = &o->run[s->last[cls] - 1u];

		if (r->off + r->len == off) {
			r->len += got;
			return;
		}
	}
	if (o->n_runs >= KOF_DOCOLE_MAX_EXTENTS) {
		o->anomalies |= KOF_DOCOLE_ANOM_EXTENTS_FULL;
		return;
	}
	o->run[o->n_runs].off = off;
	o->run[o->n_runs].len = got;
	o->run[o->n_runs].cls = cls;
	o->run[o->n_runs].reserved = 0;
	o->n_runs++;
	s->last[cls] = o->n_runs;
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
		{ "\003objinfo",       KOF_DOCOLE_CLS_RESOURCES }
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
			    uint32_t cls)
{
	struct kof_docole_info *o = s->o;
	uint32_t sec = start;
	uint64_t left = size;

	while (left && sec <= SEC_MAXREG && step(s)) {
		uint64_t n = left < o->sector_size ? left : o->sector_size;

		add_run(s, sec_off(o, sec), n, cls);
		left -= n;
		sec = fat_next(s, sec);
	}
	if (left)
		o->anomalies |= KOF_DOCOLE_ANOM_STREAM_PAST_EOF;
}

static void claim_mini_chain(struct ole *s, uint32_t start, uint64_t size,
			     uint32_t cls)
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
		left -= n;
		msec = mfat_next(s, msec);
	}
	if (left)
		o->anomalies |= KOF_DOCOLE_ANOM_STREAM_PAST_EOF;
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
static void walk_dir(struct ole *s, uint32_t root_child)
{
	struct kof_docole_info *o = s->o;
	uint32_t sp = 0;

	push(s, &sp, root_child, KOF_DOCOLE_CLS_COUNT, 0);

	while (sp) {
		uint32_t v = o->stack[--sp];
		uint32_t idx = ST_IDX(v), up = ST_CLS(v), depth = ST_DEPTH(v);
		uint64_t eoff = dir_ent_off(o, idx);
		char nm[CFB_NAME_MAX / 2u + 1u];
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

		if (size == 0)
			continue;
		if (size < o->mini_cutoff)
			claim_mini_chain(s, start, size, cls);
		else
			claim_fat_chain(s, start, size, cls);
	}
}

/* ---- settling ----------------------------------------------------------------- */

/*
 * Make the runs disjoint, so that the regions partition the object.
 *
 * Nothing in the format prevents two structures naming the same bytes, and a single
 * flipped sector number is enough to make it happen in a file nobody built to be
 * hostile. Sorted by offset with the class breaking ties, then front trimmed: taken
 * in order, a run can only collide with what is already behind it, so trimming the
 * front is all that is needed to leave every run contiguous.
 *
 * Insertion sort because the list is short - bounded by MAX_EXTENTS, and a real
 * document produces a few dozen - and because chains lay their runs down in order,
 * which makes this close to a linear pass on everything that is not trying to be
 * difficult.
 */
static void settle_runs(struct kof_docole_info *o)
{
	uint64_t end = 0;
	uint32_t i, j, w = 0;

	for (i = 1; i < o->n_runs; i++) {
		struct kof_docole_run t = o->run[i];

		for (j = i; j > 0 && (o->run[j - 1].off > t.off ||
		     (o->run[j - 1].off == t.off && o->run[j - 1].cls > t.cls)); j--)
			o->run[j] = o->run[j - 1];
		o->run[j] = t;
	}

	for (i = 0; i < o->n_runs; i++) {
		uint64_t off = o->run[i].off, lim = off + o->run[i].len;

		if (off < end)
			off = end;
		if (off >= lim)
			continue;
		end = lim;
		o->run[w].off = off;
		o->run[w].len = lim - off;
		o->run[w].cls = o->run[i].cls;
		o->run[w].reserved = 0;
		if (o->run[w].cls < KOF_DOCOLE_CLS_COUNT)
			o->region_bytes[o->run[w].cls] += o->run[w].len;
		w++;
	}
	o->n_runs = w;
}

/* ---- regions ------------------------------------------------------------------ */

static uint32_t cls_bit(uint32_t cls)
{
	static const uint32_t b[KOF_DOCOLE_CLS_COUNT] = {
		KOF_SCAN_DOCOLE_HEADERS,
		KOF_SCAN_DOCOLE_DIRECTORY,
		KOF_SCAN_DOCOLE_CONTENT_DATA,
		KOF_SCAN_DOCOLE_CONTENT_MACROS,
		KOF_SCAN_DOCOLE_CONTENT_METADATA,
		KOF_SCAN_DOCOLE_RESOURCES
	};

	return cls < KOF_DOCOLE_CLS_COUNT ? b[cls] : 0;
}

static uint32_t docole_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				    struct kof_range *out, uint32_t max_out)
{
	const struct kof_docole_info *o =
		(const struct kof_docole_info *)ctx->file_header;
	struct kof_rlist l;
	uint32_t i;

	if (!o || !o->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);

	for (i = 0; i < o->n_runs; i++)
		if (mask & cls_bit(o->run[i].cls))
			kof_rl_add(&l, ctx->obj_size, o->run[i].off, o->run[i].len);

	if (mask & KOF_SCAN_DOCOLE_UNCLAIMED) {
		/*
		 * The complement, and it is worth more here than in any format so
		 * far: sectors the allocation table marks free still hold whatever
		 * was in them before, and a deleted macro is one of them.
		 *
		 * The runs are already settled and in offset order, so the gaps
		 * between them are the answer directly - no second resolve and no
		 * second sort.
		 */
		uint64_t cursor = 0;

		for (i = 0; i < o->n_runs; i++) {
			if (o->run[i].off > cursor)
				kof_rl_add(&l, ctx->obj_size, cursor,
					   o->run[i].off - cursor);
			cursor = o->run[i].off + o->run[i].len;
		}
		if (cursor < ctx->obj_size)
			kof_rl_add(&l, ctx->obj_size, cursor, ctx->obj_size - cursor);
	}
	return kof_rl_normalise(&l);
}

/* ---- the parse ---------------------------------------------------------------- */

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

	walk_dir(&s, root_child);

	if (o->stream_count == 0)
		o->anomalies |= KOF_DOCOLE_ANOM_NO_STREAMS;
	if (o->macro_bytes > KOF_DOCOLE_MACRO_SUSPECT)
		o->anomalies |= KOF_DOCOLE_ANOM_MACRO_OVERSIZE;

done:
	settle_runs(o);

	ctx->format = KOF_FMT_DOCOLE;
	ctx->obj_size = file.n;
	ctx->file_header = o;
	ctx->resolve_scan = docole_resolve_scan;
	/* No architecture and no entry point: a document is not code, and leaving
	 * them as the caller set them is what lets arch-targeted modules be ruled out
	 * rather than matched by accident. */
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define DOCOLE_REGIONS(X)                       \
	X(KOF_SCAN_DOCOLE_HEADERS)                \
	X(KOF_SCAN_DOCOLE_DIRECTORY)              \
	X(KOF_SCAN_DOCOLE_CONTENT_DATA)           \
	X(KOF_SCAN_DOCOLE_CONTENT_MACROS)         \
	X(KOF_SCAN_DOCOLE_CONTENT_METADATA)       \
	X(KOF_SCAN_DOCOLE_RESOURCES)              \
	X(KOF_SCAN_DOCOLE_UNCLAIMED)

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
		"MACRO_OVERSIZE", "NO_STREAMS"
	};

	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
