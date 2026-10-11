/*
 * kofplague_units.c - how an object is cut into the units a block is made from.
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
 *     clear - see kof_plague_cut - so the same bytes are cut in the same places
 *     whatever was inserted before them.
 * Each carries its side - see enum kof_plague_side - and a unit never spans a
 * join between the author's code and the static library.
 */

#include "kofplague.h"

#include <string.h>

#include <kofmod/elf.h>
#include <kofmod/pe.h>

/* Small functions are grouped up to this many bytes, and are "next to each
 * other" within this gap; a group below the floor is a stub and is not a unit. */
#define FN_GROUP 256u
#define FN_GAP   32u
#define FN_MIN   64u

int kof_plague_by_function(uint32_t format, uint32_t mask)
{
	return (format == KOF_FMT_ELF && mask == KOF_SCAN_ELF_CODE) ||
	       (format == KOF_FMT_PE && mask == KOF_SCAN_PE_CODE);
}

static int fn_in(const struct kof_range *ext, uint32_t n, const struct kof_func *f)
{
	uint32_t k;

	for (k = 0; k < n; k++)
		if (f->off >= ext[k].off && f->len <= ext[k].len &&
		    f->off - ext[k].off <= ext[k].len - f->len)
			return 1;
	return 0;
}

static int fn_lib(const struct kof_true_all *lib, const struct kof_func *f)
{
	return lib && kof_true_touches(lib, f->off, f->len);
}

/* A function-region walk. A function the library owns is not offered. */
static void by_function(const struct kof_range *ext, uint32_t n_ext,
			const struct kof_func_set *funcs,
			const struct kof_true_all *lib,
			kof_plague_unit_fn fn, void *user)
{
	uint32_t i = 0;

	while (funcs && i < funcs->n) {
		const struct kof_func *f = &funcs->v[i], *best = f;
		uint64_t lo = f->off, hi = f->off + f->len;
		uint32_t m = i;

		if (!fn_in(ext, n_ext, f) || fn_lib(lib, f)) {
			i++;
			continue;
		}
		while (f->len < FN_GROUP && hi - lo < FN_GROUP &&
		       m + 1u < funcs->n) {
			const struct kof_func *g = &funcs->v[m + 1u];

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
		if (fn(user, lo, hi - lo, KOF_PLAGUE_SIDE_USER, best))
			return;
	}
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
	return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r';
}

static uint64_t side_run(const struct kof_true_all *lib, uint64_t pos,
			 uint64_t end, uint32_t *side);

/*
 * A cluster is cut where it crosses a library boundary, like every other unit:
 * the string that sits in a data unit the library's span touches used to make
 * the whole cluster LIB, and a block cut from the author's side then scored 0
 * on the file that carries it (1 of 149 measured carriers).
 */
static int emit_cluster(uint64_t from, uint64_t to, const struct kof_true_all *lib,
			kof_plague_unit_fn fn, void *user)
{
	while (from < to) {
		uint32_t side;
		uint64_t len = side_run(lib, from, to, &side);

		if (!len)
			break;
		if (len >= KOF_PLAGUE_NG &&
		    fn(user, from, len, side, NULL))
			return 1;
		from += len;
	}
	return 0;
}

static int by_string(const uint8_t *p, const struct kof_range *ext,
		     uint32_t n_ext, uint64_t n_obj,
		     const struct kof_true_all *lib, kof_plague_unit_fn fn,
		     void *user)
{
	uint32_t k;

	for (k = 0; k < n_ext; k++) {
		uint64_t pos = ext[k].off, end, from = 0, to = 0;

		if (pos >= n_obj)
			continue;
		end = ext[k].len > n_obj - pos ? n_obj : pos + ext[k].len;
		for (;;) {
			uint64_t q = pos, e = pos;
			int found = 0;

			while (q < end && printable(p[q]))
				q++;
			if (q - pos >= STR_RUN && q < end && !p[q]) {
				found = 1;
				e = q + 1u;
			}
			if (found && (!to || (pos - to <= STR_GAP &&
			    e - from <= KOF_PLAGUE_SEG_AVG * 4u))) {
				if (!to)
					from = pos;
				to = e;
				pos = e;
				continue;
			}
			/* Not extending: close what is open, and a string that
			 * would not fit opens the next cluster. */
			if (to && (found || pos >= end || pos - to > STR_GAP)) {
				if (to - from >= STR_MIN &&
				    emit_cluster(from, to, lib, fn, user))
					return 1;
				from = to = 0;
			}
			if (found) {
				from = pos;
				to = e;
				pos = e;
				continue;
			}
			if (pos >= end)
				break;
			pos = q > pos ? q : pos + 1u;
		}
	}
	return 0;
}

/* How far from `pos` the side stays the same, and which side it is. */
static uint64_t side_run(const struct kof_true_all *lib, uint64_t pos,
			 uint64_t end, uint32_t *side)
{
	uint64_t next = end;
	uint32_t i;

	*side = KOF_PLAGUE_SIDE_USER;
	for (i = 0; lib && i < lib->n; i++) {
		uint64_t a = lib->span[i].off;
		uint64_t b = a + lib->span[i].len;

		if (pos >= a && pos < b) {
			*side = KOF_PLAGUE_SIDE_LIB;
			return (b < end ? b : end) - pos;
		}
		if (a > pos && a < next)
			next = a;
	}
	return next - pos;
}

struct cut_ctx {
	kof_plague_unit_fn fn;
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

void kof_plague_units(const uint8_t *p, uint64_t n_obj, uint32_t format,
		      uint32_t mask, const struct kof_range *ext, uint32_t n_ext,
		      const struct kof_func_set *funcs,
		      const struct kof_true_all *lib,
		      kof_plague_unit_fn fn, void *user)
{
	uint32_t k;

	if (!p || !fn)
		return;
	if (kof_plague_by_function(format, mask)) {
		by_function(ext, n_ext, funcs, lib, fn, user);
		by_string(p, ext, n_ext, n_obj, lib, fn, user);
		return;
	}
	for (k = 0; k < n_ext; k++) {
		uint64_t eoff = ext[k].off, elen = ext[k].len, pos;

		if (eoff >= n_obj)
			continue;
		if (elen > n_obj - eoff)
			elen = n_obj - eoff;
		for (pos = eoff; pos < eoff + elen; ) {
			struct cut_ctx c;
			uint64_t len;

			c.fn = fn; c.user = user; c.off = pos; c.stopped = 0;
			len = side_run(lib, pos, eoff + elen, &c.side);
			if (!len)
				break;
			/* Cut apart, so no unit spans a join. A short run is
			 * still a unit: whether it can be scored is a count of
			 * hashes, and is decided where the block is made. */
			kof_plague_cut(p + pos, len, KOF_PLAGUE_SEG_AVG,
				       KOF_PLAGUE_SEG_AVG / 4u,
				       KOF_PLAGUE_SEG_AVG * 4u, cut_piece, &c);
			if (c.stopped)
				return;
			pos += len;
		}
	}
}
