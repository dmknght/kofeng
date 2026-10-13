/*
 * mutation.h - how an object is cut into the units a block is made from, and what
 * a window of bytes IS.
 *
 * This is the genotyping of bytes: it reads an object and produces the pieces and
 * the window hashes a block is sketched from, and it matches nothing. The index
 * that scores an object against the database's blocks is
 * detectors/mutations/kofmutation.h, which includes this one. The authoring tool
 * and the scanner both come here, so a block cut by one is found by the other.
 */

#ifndef KGENOME_MUTATION_H
#define KGENOME_MUTATION_H

#include <stdint.h>
#include <celllysis/mutation_window.h>
#include <genotype/image/funcs.h>
#include "trueline.h"

/*
 * THE GENERATOR SIDE: hash one span the way the matcher will read it.
 *
 * Here rather than in whoever is carving because there is one right answer and
 * several callers - the panel that offers blocks, anything that wants to
 * recognise a block it has been handed, a test. A generator that derived a
 * value differently from kof_mutation_unit would produce a rule that matches
 * nothing and reports no error, and the way to make that impossible is for
 * there to be one of it.
 *
 * ONE DEFINITION OF A WINDOW, three readers. The iterator below is what a window
 * IS - eight bytes as the normalizer presents them, rolled, mixed - and the pool
 * (the generator), the membership pass (the authoring tool asking whether a
 * sample holds a pool's windows) and the scan (kof_mutation_unit) all walk it.
 * Windows of one repeated byte are left out on every side - see
 * kgenome_mutation_flat. The loop was written out three times before it was one.
 */
struct kgenome_mtn_win {
	const uint8_t *p;
	uint64_t       n, at;
	uint32_t       norm, h, drop;
};

/* Position on the first window; 0 when the span has none. */
static inline int kgenome_mtn_win_begin(struct kgenome_mtn_win *w, const uint8_t *p, uint64_t n,
			       uint32_t norm)
{
	uint32_t i;

	if (norm != KGENOME_MUTATION_RAW) {
		if (n < 2u)
			return 0;
		n -= 1u;
	}
	if (n < KGENOME_MUTATION_NG)
		return 0;
	w->p = p; w->n = n; w->at = 0; w->norm = norm;
	w->drop = kgenome_mutation_drop_weight();
	w->h = 0;
	for (i = 0; i < KGENOME_MUTATION_NG; i++)
		w->h = w->h * KGENOME_MUTATION_BASE +
		       (uint32_t)kgenome_mutation_byte(p, i, norm);
	return 1;
}

static inline uint32_t kgenome_mtn_win_value(const struct kgenome_mtn_win *w)
{
	return kgenome_mutation_mix(w->h);
}

static inline int kgenome_mtn_win_flat(const struct kgenome_mtn_win *w)
{
	return kgenome_mutation_flat(w->p, w->at, w->norm);
}

/* Roll to the next window; 0 once the last has been given. */
static inline int kgenome_mtn_win_next(struct kgenome_mtn_win *w)
{
	if (w->at + KGENOME_MUTATION_NG >= w->n)
		return 0;
	if (w->norm == KGENOME_MUTATION_RAW) {
		w->h -= (uint32_t)w->p[w->at] * w->drop;
		w->h = w->h * KGENOME_MUTATION_BASE +
		       (uint32_t)w->p[w->at + KGENOME_MUTATION_NG];
	} else {
		w->h -= (uint32_t)kgenome_mutation_byte(w->p, w->at, w->norm) * w->drop;
		w->h = w->h * KGENOME_MUTATION_BASE +
		       (uint32_t)kgenome_mutation_byte(w->p, w->at + KGENOME_MUTATION_NG,
					       w->norm);
	}
	w->at++;
	return 1;
}


/*
 * HOW A BLOCK'S HASHES ARE CHOSEN - one generator, one definition of a window.
 *
 * The POOL of a span is every distinct window hash it has (not flat, see
 * kgenome_mutation_flat), ascending. A block is NOT the pool - that would be thousands
 * of values - it is a sample of it: the smallest KGENOME_MUTATION_MINHASH_K of the
 * windows worth keeping. For one sample "worth keeping" is every window, which
 * is kgenome_mutation_minhash: the bottom-k sketch every block so far was made with.
 *
 * WITH MORE THAN ONE SAMPLE it is a choice, and it is the one that matters.
 * Measured on 149 files that carry one exploit request (research notes in
 * /mnt/games/kofscratch/blkcut/PROPOSAL.md): a block cut from the span a unit
 * gives hit 3 of them; the same data cut by hand as 1200 bytes, 129; and a block
 * of the windows that EVERY sample shares and NO background file holds, 142 -
 * with the same 32 hashes for any span that contains the request, shifted,
 * grown or shrunk. The variable material of a span is inside it, so no choice
 * of where to cut removes it; what removes it is asking more than one sample
 * which windows are the data's and which the sample's. kgenome_mutation_member is that
 * question and kgenome_mutation_core is the answer.
 */
#define KGENOME_MUTATION_MINHASH_K 32u

/* Every distinct non-flat window hash of the span, ascending, malloc'd; NULL
 * (and *n_out 0) when the span has none. The CALLER bounds the span: a block's
 * input is a function or a cluster, never a file. */
uint32_t *kgenome_mutation_pool(const uint8_t *p, uint64_t n, uint32_t norm,
			  uint32_t *n_out);

/* The smallest K of the pool; ascending, distinct. */
uint32_t kgenome_mutation_minhash(const uint8_t *p, uint64_t n, uint32_t norm,
			    uint32_t *out);

/*
 * Which of `pool`'s windows does this sample hold? Bit i of `bits` (n_pool bits,
 * zeroed by the caller; set, never cleared) is set when the sample has window
 * pool[i] anywhere. One pass over the sample, a bit table first.
 */
void kgenome_mutation_member(const uint32_t *pool, uint32_t n_pool, const uint8_t *p,
		       uint64_t n, uint32_t norm, uint8_t *bits);

/*
 * The block of a pool, given how many positive samples held each window
 * (`pos`, against `pos_need`) and how many background samples did (`bg`, at most
 * `bg_max`; NULL for no background). The smallest `k` windows that pass, ascending
 * - the pool is ascending, so they are the first k. Returns 0 when fewer than
 * KGENOME_MUTATION_MIN_HASH pass: there is no invariant, informative material in this
 * span, and saying so is the answer - the alternative is a block made of the
 * sample's own accidents.
 */
uint32_t kgenome_mutation_core(const uint32_t *pool, uint32_t n_pool,
			 const uint16_t *pos, uint32_t pos_need,
			 const uint16_t *bg, uint32_t bg_max, uint32_t k,
			 uint32_t *out);

/*
 * WHERE TO CUT A SPAN OF BYTES THAT HAS NO FUNCTIONS - the other half of how
 * blocks are offered.
 *
 * Content-defined: a cut falls where the window hash of the bytes has its low
 * bits clear, so the same bytes are cut in the same places whatever was inserted
 * before them, and a block cut from one sample is recognisable in the next.
 * `avg` is the mean piece (a power of two), `min` and `max` bound it.
 *
 * Here, beside the hash it uses, and not in the panel that wants the pieces: a
 * second copy of the rolling loop is a second definition of what a window is.
 * `fn` is called for each piece in order with its [from, to) offsets inside the
 * span, and stops the walk by returning non-zero. A span of kof_mutation_ng bytes
 * or fewer is one piece.
 */
typedef int (*kgenome_mutation_cut_fn)(void *user, uint64_t from, uint64_t to);
void kgenome_mutation_cut(const uint8_t *p, uint64_t len, uint32_t avg, uint32_t min,
		    uint32_t max, kgenome_mutation_cut_fn fn, void *user);

/*
 * HOW AN OBJECT IS CUT INTO UNITS - the same cut for the tool that makes a block
 * and the scanner that finds it, so it is made here and nowhere else.
 *
 * `ext` are the extents of ONE region, resolved by the caller. A region that is
 * offered a function at a time (kgenome_mutation_by_function) yields the functions of
 * `funcs` that lie in it - grouped when small, dropped when they are stubs or
 * the library's - and, from the bytes alone, the clusters of
 * strings that such a region holds when .rodata shares its segment (by_string in
 * libgenome/celllysis/mutation_units.c). With `funcs` empty only the clusters remain. Any other region is cut by kgenome_mutation_cut at the fixed target
 * KGENOME_MUTATION_SEG_AVG, split where it crosses a library boundary so that no unit
 * spans one. `lib` may be NULL.
 *
 * `fn` gets each unit's file offset, length and side, in order, and stops the
 * walk by returning non-zero. A unit that is functions also gets the largest of
 * them - the one the unit is mostly made of, for a tool that names it; a piece of
 * bytes gets NULL.
 */
#define KGENOME_MUTATION_SEG_AVG 8192u        /* the mean carved piece, a power of two */

typedef int (*kgenome_mutation_unit_fn)(void *user, uint64_t off, uint64_t len,
				  uint32_t side, const struct kgenome_func *first);

int kgenome_mutation_by_function(uint32_t format, uint32_t mask);

/*
 * ONE REGION TO CUT, as a request: the object, the region and how it is offered,
 * what is known about the object's functions and its library, and where the
 * units go.
 */
struct kgenome_mutation_req {
	/* the object */
	const uint8_t                 *p;
	uint64_t                       n_obj;
	/* the region: its format and mask, and its extents (resolved by the caller) */
	uint32_t                       format;
	uint32_t                       mask;
	const struct kof_range        *ext;
	uint32_t                       n_ext;
	/* what is known about the object; both may be NULL */
	const struct kgenome_func_set *funcs;
	const struct kgenome_true_all *lib;
	/* the sink */
	kgenome_mutation_unit_fn       fn;
	void                          *user;
};

void kgenome_mutation_units(const struct kgenome_mutation_req *rq);

#endif /* KGENOME_MUTATION_H */
