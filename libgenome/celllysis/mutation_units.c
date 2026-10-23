/*
 * mutation_units.c - how an object is cut into the units a block is made from.
 *
 * ONE CUT, FOR THE TWO PEOPLE WHO NEED IT. A block is the sketch of one unit of
 * an object, and a scanner finds it by sketching the units of the object in
 * front of it. If the author's tool and the scanner cut differently the same
 * bytes would never meet, with no error anywhere - so the cut lives here and
 * both call it.
 *
 * A unit is one of:
 *   - a function, or a run of small ones that sit next to each other, in a
 *     region that is offered a function at a time;
 *   - a piece of any other region, cut where the window hash has its low bits
 *     clear - see kgenome_mutation_cut - so the same bytes are cut in the same places
 *     whatever was inserted before them.
 * Each carries its side - see enum kgenome_mutation_side - and a unit never spans a
 * join between the author's code and the static library.
 */

#include "mutation.h"

#include <string.h>

#include <genotype/image/obj.h>
#include <genotype/image/elf_types.h>
#include <genotype/image/pe_types.h>

/* Small functions are grouped up to this many bytes, and are "next to each
 * other" within this gap; a group below the floor is a stub and is not a unit. */
#define FN_GROUP 256u
#define FN_GAP   32u
#define FN_MIN   64u

int kgenome_mutation_by_function(uint32_t format, uint32_t mask)
{
	return (format == KGENOME_FMT_ELF && mask == KGENOME_SCAN_ELF_CODE) ||
	       (format == KGENOME_FMT_PE && mask == KGENOME_SCAN_PE_CODE);
}

static int fn_in(const struct kof_range *ext, uint32_t n, const struct kgenome_func *f)
{
	uint32_t k;

	for (k = 0; k < n; k++)
		if (f->off >= ext[k].off && f->len <= ext[k].len &&
		    f->off - ext[k].off <= ext[k].len - f->len)
			return 1;
	return 0;
}

static int fn_lib(const struct kgenome_true_all *lib, const struct kgenome_func *f)
{
	return lib && kgenome_true_touches(lib, f->off, f->len);
}

/* A function-region walk. A function the library owns is not offered. Answers 1 when the
 * callback said stop, so the caller does not offer it anything else. */
static int by_function(const struct kof_range *ext, uint32_t n_ext,
			const struct kgenome_func_set *funcs,
			const struct kgenome_true_all *lib,
			kgenome_mutation_unit_fn fn, void *user)
{
	uint32_t i = 0;

	while (funcs && i < funcs->n) {
		const struct kgenome_func *f = &funcs->v[i], *best = f;
		uint64_t lo = f->off, hi = f->off + f->len;
		uint32_t m = i;

		if (!fn_in(ext, n_ext, f) || fn_lib(lib, f)) {
			i++;
			continue;
		}
		while (f->len < FN_GROUP && hi - lo < FN_GROUP &&
		       m + 1u < funcs->n) {
			const struct kgenome_func *g = &funcs->v[m + 1u];

			if (g->len >= FN_GROUP || g->off < hi ||
			    g->off - hi > FN_GAP || !fn_in(ext, n_ext, g) ||
			    fn_lib(lib, g))
				break;
			hi = g->off + g->len;
			if (g->len > best->len)
				best = g;
			m++;
		}
		i = m + 1u;
		if (hi - lo < FN_MIN)
			continue;
		if (fn(user, lo, hi - lo, KGENOME_MUTATION_SIDE_USER, best))
			return 1;
	}
	return 0;
}

/*
 * DATA IN A CODE REGION. Most static IoT builds put .rodata in the executable
 * segment, so the region is "code" by its load flags and the author's strings
 * would be cut nowhere: functions are the only unit offered there. A data unit
 * is found from the bytes alone - no name, no section table, no gap arithmetic
 * - as a cluster of NUL-terminated printable strings with no more than STR_GAP
 * bytes between one and the next, so the binary tables that sit between strings
 * stay inside the block and the block weighs what the data weighs.
 *
 * The gap was measured, not chosen: on a static x64 bot whose .rodata is 15153
 * bytes, a gap of 4 cut its strings into 41 pieces of at most 3 KB and a gap of
 * 128 into 9 blocks of up to 4.4 KB. Small pieces defeat the similarity this is
 * for - each is scored alone, so a variant that moves one string loses a whole
 * piece - and the largest the gap can usefully be is where clusters stop
 * merging (128 and 256 gave the same nine).
 *
 * Code almost never holds four printable bytes and a NUL in a row, so a
 * cluster of STR_MIN bytes or more is data. It is not tied to a function, and
 * may overlap the tail of one that the entry walk left open.
 */
#define STR_RUN 4u
#define STR_GAP 128u
#define STR_MIN 64u

static int printable(uint8_t c)
{
	/* 0x20..0x7e as one unsigned compare, and the three controls (9, 10, 13) as bits of a
	 * constant: this is read once per byte of every region cut, and ran at 40 instructions a
	 * byte of code in the cluster search before. */
	return (uint8_t)(c - 0x20u) < 0x5fu || (c < 14u && (0x2600u >> c & 1u));
}

static uint64_t side_run(const struct kgenome_true_all *lib, uint64_t pos,
			 uint64_t end, uint32_t *side);

/*
 * A cluster is cut where it crosses a library boundary, like every other unit:
 * the string that sits in a data unit the library's span touches used to make
 * the whole cluster LIB, and a block cut from the author's side then scored 0
 * on the file that carries it (1 of 149 measured carriers).
 */
static int emit_cluster(uint64_t from, uint64_t to, const struct kgenome_true_all *lib,
			kgenome_mutation_unit_fn fn, void *user)
{
	while (from < to) {
		uint32_t side;
		uint64_t len = side_run(lib, from, to, &side);

		if (!len)
			break;
		if (len >= KGENOME_MUTATION_NG &&
		    fn(user, from, len, side, NULL))
			return 1;
		from += len;
	}
	return 0;
}

/* The next printable run closed by a NUL at or after `pos`. Found from the NUL, which is the rarer
 * byte: the search is a memchr and the run is read backwards from it. */
static int next_string(const uint8_t *p, uint64_t pos, uint64_t end,
		       uint64_t *s, uint64_t *e)
{
	while (pos < end) {
		const uint8_t *z = memchr(p + pos, 0, (size_t)(end - pos));
		uint64_t q, from;

		if (!z)
			return 0;
		q = (uint64_t)(z - p);
		for (from = q; from > pos && printable(p[from - 1u]); from--)
			;
		if (q - from >= STR_RUN) {
			*s = from;
			*e = q + 1u;
			return 1;
		}
		pos = q + 1u;
	}
	return 0;
}

/* The next cluster of strings at or after `pos`: whole strings, each within
 * STR_GAP of the one before, at least STR_MIN bytes. A string that would pass
 * the size cap opens the next cluster, so no string is ever cut. */
static int next_cluster(const uint8_t *p, uint64_t pos, uint64_t end,
			uint64_t *from, uint64_t *to)
{
	uint64_t s, e;

	while (next_string(p, pos, end, &s, &e)) {
		*from = s;
		*to = e;
		while (next_string(p, *to, end, &s, &e) &&
		       s - *to <= STR_GAP &&
		       e - *from <= KGENOME_MUTATION_SEG_AVG * 4u)
			*to = e;
		if (*to - *from >= STR_MIN)
			return 1;
		pos = *to;
	}
	return 0;
}

/* How far from `pos` the side stays the same, and which side it is. */
static uint64_t side_run(const struct kgenome_true_all *lib, uint64_t pos,
			 uint64_t end, uint32_t *side)
{
	uint64_t next = end;
	uint32_t i;

	*side = KGENOME_MUTATION_SIDE_USER;
	for (i = 0; lib && i < lib->n; i++) {
		uint64_t a = lib->span[i].off;
		uint64_t b = a + lib->span[i].len;

		if (pos >= a && pos < b) {
			*side = KGENOME_MUTATION_SIDE_LIB;
			return (b < end ? b : end) - pos;
		}
		if (a > pos && a < next)
			next = a;
	}
	return next - pos;
}

struct cut_ctx {
	kgenome_mutation_unit_fn fn;
	void *user;
	uint64_t off;
	uint32_t side;
	int stopped;
};

static int cut_piece(void *user, uint64_t from, uint64_t to)
{
	struct cut_ctx *c = user;

	c->stopped = c->fn(c->user, c->off + from, to - from, c->side, NULL) != 0;
	return c->stopped;
}

/* Cut [from, to) by content, apart at library joins so no unit spans one. A
 * short run is still a unit: whether it can be scored is a count of hashes,
 * and is decided where the block is made. */
static int cut_span(const uint8_t *p, uint64_t from, uint64_t to,
		    const struct kgenome_true_all *lib, kgenome_mutation_unit_fn fn,
		    void *user)
{
	while (from < to) {
		struct cut_ctx c;
		uint64_t len;

		c.fn = fn; c.user = user; c.off = from; c.stopped = 0;
		len = side_run(lib, from, to, &c.side);
		if (!len)
			break;
		kgenome_mutation_cut(p + from, len, KGENOME_MUTATION_SEG_AVG,
			       KGENOME_MUTATION_SEG_AVG / 4u,
			       KGENOME_MUTATION_SEG_AVG * 4u, cut_piece, &c);
		if (c.stopped)
			return 1;
		from += len;
	}
	return 0;
}

/*
 * [pos, end) of one extent as strings, and - when `pieces` - what lies between them by
 * content. A region offered a function at a time keeps only the strings: its other
 * bytes are instructions, which the functions already cover.
 */
static int cut_bytes(const struct kgenome_mutation_req *rq, uint64_t pos, uint64_t end,
		     int pieces)
{
	uint64_t from, to;

	for (; pos < end; pos = to) {
		if (!next_cluster(rq->p, pos, end, &from, &to))
			from = to = end;
		if ((pieces && cut_span(rq->p, pos, from, rq->lib, rq->fn, rq->user)) ||
		    (to > from && emit_cluster(from, to, rq->lib, rq->fn, rq->user)))
			return 1;
	}
	return 0;
}

/*
 * THE BYTES OF A REGION, WITH THE FIXED UNITS LEFT WHOLE.
 *
 * A fixed extent is one unit whatever its bytes say, and the cut is told where
 * the unit is instead of finding it: only what lies between fixed units is cut
 * by what it holds. A view needs this for what its decode rewrote. A string
 * cluster is found from printable bytes and a NUL, and a payload that came out
 * of a decode is not printable - on the sample this was measured on, cutting the
 * decoded view again gave 21 clusters where the parent's cut gave 16, and one
 * 6656 byte cluster of the parent came back as pieces of 626, 602, 452 and 302. The
 * view's units are the parent's, hashed over what the view holds.
 */
static int by_bytes(const struct kgenome_mutation_req *rq, int pieces)
{
	uint32_t k, f = 0;

	for (k = 0; k < rq->n_ext; k++) {
		uint64_t pos = rq->ext[k].off, end;

		if (pos >= rq->n_obj)
			continue;
		end = rq->ext[k].len > rq->n_obj - pos ? rq->n_obj : pos + rq->ext[k].len;
		while (pos < end) {
			uint64_t lim = end, ue;

			while (f < rq->n_fixed && rq->fixed[f].off + rq->fixed[f].len <= pos)
				f++;
			if (f < rq->n_fixed && rq->fixed[f].off < end)
				lim = rq->fixed[f].off > pos ? rq->fixed[f].off : pos;
			if (lim > pos) {
				if (cut_bytes(rq, pos, lim, pieces))
					return 1;
				pos = lim;
				continue;
			}
			ue = rq->fixed[f].off + rq->fixed[f].len;
			if (ue > end)
				ue = end;
			if (emit_cluster(pos, ue, rq->lib, rq->fn, rq->user))
				return 1;
			pos = ue;
		}
	}
	return 0;
}

void kgenome_mutation_units(const struct kgenome_mutation_req *rq)
{
	if (!rq->p || !rq->fn)
		return;
	if (kgenome_mutation_by_function(rq->format, rq->mask)) {
		if (!by_function(rq->ext, rq->n_ext, rq->funcs, rq->lib, rq->fn, rq->user))
			by_bytes(rq, 0);
		return;
	}
	by_bytes(rq, 1);
}
