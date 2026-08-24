/*
 * ppmd.c - PPMd variant H, the model RAR3 switches to for a block.
 *
 * EVERYTHING IS AN OFFSET, NOT A POINTER.
 *
 * The model is a graph of contexts and symbol states living inside one arena, and
 * Shkarin's original stores machine pointers in it. This stores 32-bit offsets
 * from the base instead, for two reasons that both matter here. It makes the
 * structures the same size whatever the host is, so the 12-byte unit the
 * suballocator is built around stays 12 bytes; and it makes every dereference a
 * bounds check away from being safe, which is the whole difference between a
 * model driven by a file and a model driven by an attacker.
 *
 * A zero offset is the null: the arena's first unit is never handed out.
 */

#include "ppmd.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ---- the shape of the model ---------------------------------------------- */

#define UNIT_SIZE   12u
#define N1           4u
#define N2           4u
#define N3           4u
#define N4          ((128u + 3u - 1u * N1 - 2u * N2 - 3u * N3) / 4u)
#define N_INDEXES   (N1 + N2 + N3 + N4)

#define MAX_O       64u          /* the deepest order the format allows */
#define INT_BITS     7u
#define PERIOD_BITS  7u
#define TOT_BITS    (INT_BITS + PERIOD_BITS)
#define INTERVAL    (1u << INT_BITS)
#define BIN_SCALE   (1u << TOT_BITS)
#define MAX_FREQ   124u

/*
 * The arena ceiling.
 *
 * The size comes from one byte of the file and 251MB is an ordinary value in the
 * wild - measured, not imagined. Refusing outright would lose those archives, and
 * honouring it would let a four byte header ask for a quarter of a gigabyte, so
 * it is clamped and the decode is allowed to fail short instead. A model that
 * runs out of arena restarts itself; that is a normal event in this format.
 */
#define ARENA_MAX   (64u << 20)

/*
 * SIX BYTES, AND THE SIX MATTER.
 *
 * The suballocator's unit is twelve bytes and the model packs two states into
 * one, so a state that a compiler pads out to eight makes every table in the
 * model the wrong size: the root context alone claims 256 states in 1536 bytes
 * and would need 2048, overrunning its own table on the first symbol decoded.
 * The successor is therefore kept as two halves, which is how RAR itself keeps
 * it and for exactly this reason - not as a space saving but as a layout the
 * arithmetic elsewhere depends on.
 */
struct state {
	uint8_t  symbol;
	uint8_t  freq;
	uint16_t succ_lo;
	uint16_t succ_hi;
};

/*
 * Null tolerant, because every caller reaches these through a bounds check that
 * can fail: st_at hands back NULL for an offset the arena does not contain, and
 * a model driven by a hostile file produces those. Answering zero is the same
 * as answering "no successor", which is a state the model already handles.
 */
static uint32_t st_succ(const struct state *s)
{
	if (!s)
		return 0;
	return (uint32_t)s->succ_lo | ((uint32_t)s->succ_hi << 16);
}

static void st_set_succ(struct state *s, uint32_t v)
{
	if (!s)
		return;
	s->succ_lo = (uint16_t)(v & 0xffffu);
	s->succ_hi = (uint16_t)(v >> 16);
}

struct context {                  /* RARPPM_CONTEXT */
	uint16_t num_stats;
	uint16_t summ_freq;
	uint32_t stats;               /* offset of struct state[] */
	uint32_t suffix;              /* offset of a context */
	/*
	 * one_state lives in the space summ_freq and stats occupy when
	 * num_stats is 1, exactly as the original overlays them - the model
	 * relies on a single symbol context costing no more than a pair of
	 * fields.
	 */
};

struct see {
	uint16_t summ;
	uint8_t  shift;
	uint8_t  count;
};

struct kof_ppmd {
	uint8_t  *arena;
	uint32_t  arena_size;
	uint32_t  lo_unit, hi_unit, text, units_start, glue_count;
	uint32_t  free_list[N_INDEXES];
	uint8_t   indx2units[N_INDEXES];
	uint8_t   units2indx[128];
	uint8_t   ns2bsindx[256];
	uint8_t   ns2indx[256];
	uint8_t   hb2flag[256];

	struct see see[25][16];
	struct see dummy_see;
	uint16_t  bin_summ[128][64];

	uint32_t  min_context, max_context;   /* context offsets */
	uint32_t  found_state;                /* state offset */
	int       max_order, init_esc, order_fall, run_length, init_rl;
	int       num_masked, hi_bits_flag;
	/*
	 * Masked symbols, held as a stamp rather than a flag.
	 *
	 * A symbol counts as masked when its entry EQUALS esc_count, and
	 * esc_count is bumped every time a symbol is decoded through an escape.
	 * That bump is how the whole mask is cleared in constant time - and
	 * reading the entry as a boolean instead keeps every symbol ever
	 * escaped masked for the rest of the stream, which is why the decode
	 * stayed right for a few dozen bytes and then could not find anything.
	 */
	uint8_t   char_mask[256];
	uint8_t   esc_count, prev_success;

	/* the range decoder */
	uint32_t  low, code, range;
	uint32_t  sub_low, sub_high, sub_scale;

	/* the stream, driven by the caller */
	const uint8_t *in;
	uint64_t  in_len, in_at;
	int       broken;
};

/* ---- arena access, bounds checked ---------------------------------------- */

static void *at_off(struct kof_ppmd *m, uint32_t off, uint32_t need)
{
	if (!off || off > m->arena_size || need > m->arena_size - off) {
		m->broken = 1;
		return NULL;
	}
	return m->arena + off;
}

static struct context *ctx_at(struct kof_ppmd *m, uint32_t off)
{
	return at_off(m, off, (uint32_t)sizeof(struct context));
}

static struct state *st_at(struct kof_ppmd *m, uint32_t off)
{
	return at_off(m, off, (uint32_t)sizeof(struct state));
}

/* A one symbol context keeps its only state where the other two fields sit. */
static uint32_t one_state_off(uint32_t ctx)
{
	return ctx + (uint32_t)offsetof(struct context, summ_freq);
}

/* ---- the suballocator ----------------------------------------------------- */

struct node { uint32_t next; };

static void ins_node(struct kof_ppmd *m, uint32_t off, uint32_t indx)
{
	struct node *n = at_off(m, off, (uint32_t)sizeof *n);

	if (!n)
		return;
	n->next = m->free_list[indx];
	m->free_list[indx] = off;
}

static uint32_t rem_node(struct kof_ppmd *m, uint32_t indx)
{
	uint32_t off = m->free_list[indx];
	struct node *n = at_off(m, off, (uint32_t)sizeof *n);

	if (!n)
		return 0;
	m->free_list[indx] = n->next;
	return off;
}

static uint32_t u2b(uint32_t units) { return units * UNIT_SIZE; }

/*
 * The index for a run of `nu` units, for any nu a caller can produce.
 *
 * ExpandUnits asks for one more than it has, so 129 reaches here from a context
 * holding the maximum 256 symbols - one past the table. The biggest bucket is
 * the right answer there and a read past the array is not.
 */
static uint32_t idx_of_units(struct kof_ppmd *m, uint32_t nu)
{
	if (nu == 0u)
		nu = 1u;
	if (nu > 128u)
		nu = 128u;
	return m->units2indx[nu - 1u];
}

static void split_block(struct kof_ppmd *m, uint32_t pv, uint32_t old_indx,
			uint32_t new_indx)
{
	uint32_t i, k, uodd;
	uint32_t nu = m->indx2units[old_indx] - m->indx2units[new_indx];
	uint32_t p = pv + u2b(m->indx2units[new_indx]);

	i = idx_of_units(m, nu);
	if (m->indx2units[i] != nu) {
		k = m->indx2units[--i];
		ins_node(m, p + u2b(k), idx_of_units(m, nu - k - 1u + 1u));
		nu = k;
	}
	uodd = i;
	ins_node(m, p, uodd);
}

static void glue_free_blocks(struct kof_ppmd *m)
{
	/*
	 * Adjacent free blocks are merged so a later request for a larger run
	 * can be met. The original threads a list through the blocks with a
	 * stamp field; the same is done here through the offsets, and a block
	 * that fails its bounds check ends the walk rather than the process.
	 */
	uint32_t i, head = 0, *prev = &head;

	for (i = 0; i < N_INDEXES; i++) {
		uint32_t next = m->free_list[i];

		m->free_list[i] = 0;
		while (next) {
			struct node *n = at_off(m, next, UNIT_SIZE);
			uint32_t here = next;

			if (!n)
				break;
			next = n->next;
			/* stamp the run length into the unit so the merge pass
			 * below can see how far it reaches */
			((uint32_t *)(void *)(m->arena + here))[0] = 0;
			((uint32_t *)(void *)(m->arena + here))[1] =
				m->indx2units[i];
			*prev = here;
			prev = &((uint32_t *)(void *)(m->arena + here))[2];
			*prev = 0;
		}
	}
	/* merge */
	for (i = head; i; ) {
		uint32_t *h = (uint32_t *)(void *)(m->arena + i);
		uint32_t nu = h[1];
		uint32_t nxt = i + u2b(nu);

		for (;;) {
			uint32_t *t;

			if (nxt + UNIT_SIZE > m->arena_size)
				break;
			t = (uint32_t *)(void *)(m->arena + nxt);
			if (t[0] != 0 || t[1] == 0)
				break;
			nu += t[1];
			t[1] = 0;
			nxt += u2b(t[1] ? t[1] : 0u);
			break;          /* one merge per pass, kept simple */
		}
		h[1] = nu;
		i = h[2];
	}
	/* and back onto the lists */
	for (i = head; i; ) {
		uint32_t *h = (uint32_t *)(void *)(m->arena + i);
		uint32_t nu = h[1], nxt = h[2];

		while (nu > 128u) {
			ins_node(m, i, N_INDEXES - 1u);
			nu -= 128u;
			i += u2b(128u);
		}
		if (nu) {
			uint32_t idx = idx_of_units(m, nu);

			if (m->indx2units[idx] != nu) {
				uint32_t k = nu - m->indx2units[--idx];

				ins_node(m, i + u2b(nu - k),
					 (uint32_t)idx_of_units(m, k));
			}
			ins_node(m, i, idx);
		}
		i = nxt;
	}
	m->glue_count = 255;
}

static uint32_t alloc_units_rare(struct kof_ppmd *m, uint32_t indx)
{
	uint32_t i, ret;

	if (!m->glue_count) {
		glue_free_blocks(m);
		if (m->free_list[indx])
			return rem_node(m, indx);
	}
	i = indx;
	do {
		if (++i == N_INDEXES) {
			uint32_t nu;

			m->glue_count--;
			nu = u2b(m->indx2units[indx]);
			if (m->units_start - m->lo_unit > nu) {
				m->units_start -= nu;
				return m->units_start;
			}
			return 0;
		}
	} while (!m->free_list[i]);
	ret = rem_node(m, i);
	if (!ret)
		return 0;
	split_block(m, ret, i, indx);
	return ret;
}

static uint32_t alloc_units(struct kof_ppmd *m, uint32_t nu)
{
	uint32_t indx = idx_of_units(m, nu), ret;

	if (m->free_list[indx])
		return rem_node(m, indx);
	ret = m->lo_unit;
	m->lo_unit += u2b(m->indx2units[indx]);
	if (m->lo_unit <= m->hi_unit)
		return ret;
	m->lo_unit -= u2b(m->indx2units[indx]);
	return alloc_units_rare(m, indx);
}

static uint32_t alloc_context(struct kof_ppmd *m)
{
	if (m->hi_unit != m->lo_unit) {
		m->hi_unit -= UNIT_SIZE;
		return m->hi_unit;
	}
	if (m->free_list[0])
		return rem_node(m, 0);
	return alloc_units_rare(m, 0);
}

static uint32_t expand_units(struct kof_ppmd *m, uint32_t old, uint32_t old_nu)
{
	uint32_t i0 = idx_of_units(m, old_nu);
	uint32_t i1 = idx_of_units(m, old_nu + 1u);
	uint32_t ptr;

	if (i0 == i1)
		return old;
	ptr = alloc_units(m, old_nu + 1u);
	if (ptr) {
		memcpy(m->arena + ptr, m->arena + old, u2b(old_nu));
		ins_node(m, old, i0);
	}
	return ptr;
}

static uint32_t shrink_units(struct kof_ppmd *m, uint32_t old, uint32_t old_nu,
			     uint32_t new_nu)
{
	uint32_t i0 = idx_of_units(m, old_nu);
	uint32_t i1 = idx_of_units(m, new_nu);

	if (i0 == i1)
		return old;
	if (m->free_list[i1]) {
		uint32_t ptr = rem_node(m, i1);

		if (ptr) {
			memcpy(m->arena + ptr, m->arena + old, u2b(new_nu));
			ins_node(m, old, i0);
		}
		return ptr;
	}
	split_block(m, old, i0, i1);
	return old;
}

static void free_units(struct kof_ppmd *m, uint32_t off, uint32_t nu)
{
	ins_node(m, off, (uint32_t)idx_of_units(m, nu));
}

static void sub_init(struct kof_ppmd *m)
{
	uint32_t i, k, diff;

	memset(m->free_list, 0, sizeof m->free_list);
	m->text = UNIT_SIZE;                  /* unit 0 is the null */
	diff = u2b(m->arena_size / 8u / UNIT_SIZE * 7u) / UNIT_SIZE;
	(void)diff;
	m->hi_unit = m->arena_size - (m->arena_size % UNIT_SIZE);
	m->units_start = m->hi_unit -
			 (m->arena_size / 8u / UNIT_SIZE * 7u) * UNIT_SIZE;
	m->lo_unit = m->units_start;
	m->glue_count = 0;
	(void)i; (void)k;
}

/* ---- the range decoder ---------------------------------------------------- */

/*
 * RAR's carryless range coder, not the one in lzma.c.
 *
 * They look alike and normalise differently, and the difference is the whole
 * decoder: this one carries a `low` alongside `code` and renormalises on the
 * span between them, where LZMA's tracks `code` against a top bit. Reading one
 * stream with the other's rule produces plausible bytes for a while and then
 * diverges, which is the failure mode worth naming because it is not obvious
 * from the output.
 */
#define RC_TOP  (1u << 24)
#define RC_BOT  (1u << 15)

static uint8_t rd_byte(struct kof_ppmd *m)
{
	if (m->in_at < m->in_len)
		return m->in[m->in_at++];
	m->broken = 1;
	return 0;
}

static void rd_init(struct kof_ppmd *m)
{
	uint32_t i;

	m->low = m->code = 0;
	m->range = 0xffffffffu;
	for (i = 0; i < 4u; i++)
		m->code = (m->code << 8) | rd_byte(m);
}

static void rd_normalize(struct kof_ppmd *m)
{
	/* A stream that has run out cannot make the loop below terminate on
	 * its own: every byte it reads is a zero and the span it is waiting on
	 * never widens. */
	while (!m->broken &&
	       ((m->low ^ (m->low + m->range)) < RC_TOP ||
		(m->range < RC_BOT &&
		 ((m->range = (~m->low + 1u) & (RC_BOT - 1u)), 1)))) {
		m->code = (m->code << 8) | rd_byte(m);
		m->range <<= 8;
		m->low <<= 8;
	}
}

static uint32_t rd_count(struct kof_ppmd *m, uint32_t scale)
{
	/*
	 * Both divisions are by a number the file chose.
	 *
	 * `scale` is a context's summed frequency and `range` is what is left
	 * of the coder's span after dividing by it - a corrupt or hostile model
	 * can drive either to zero, and an integer divide by zero is not a
	 * wrong answer, it is a signal that ends the process. Measured: one
	 * archive in the collection does exactly this.
	 */
	if (!scale) {
		m->broken = 1;
		return 0;
	}
	m->sub_scale = scale;
	m->range /= scale;
	if (!m->range) {
		m->broken = 1;
		return 0;
	}
	return (m->code - m->low) / m->range;
}

static void rd_decode(struct kof_ppmd *m)
{
	m->low += m->range * m->sub_low;
	m->range *= m->sub_high - m->sub_low;
}

/* ---- the tables the model is built on ------------------------------------- */

static const uint8_t exp_escape[16] = {
	25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2
};
static const uint16_t init_bin_esc[8] = {
	0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051
};

static void tables_init(struct kof_ppmd *m)
{
	uint32_t i, k, step;

	/* index -> how many 12-byte units that index stands for */
	for (i = 0, k = 1; i < N1; i++, k += 1)
		m->indx2units[i] = (uint8_t)k;
	for (; i < N1 + N2; i++, k += 2)
		m->indx2units[i] = (uint8_t)k;
	for (; i < N1 + N2 + N3; i++, k += 3)
		m->indx2units[i] = (uint8_t)k;
	for (; i < N_INDEXES; i++, k += 4)
		m->indx2units[i] = (uint8_t)k;

	/*
	 * units -> the index that covers them.
	 *
	 * k is clamped because the largest index stands for 125 units and this
	 * table runs to 128: the last three entries have no exact bucket and
	 * belong in the biggest one there is. Without the clamp k walks off the
	 * end of a 38 byte array on the three largest sizes - which UBSan
	 * catches on real archives, and which a release build would answer with
	 * whatever byte follows.
	 */
	for (i = 0, k = 0; i < 128u; i++) {
		if (m->indx2units[k] < i + 1u && k + 1u < N_INDEXES)
			k++;
		m->units2indx[i] = (uint8_t)k;
	}

	m->ns2bsindx[0] = 2u * 0u;
	m->ns2bsindx[1] = 2u * 1u;
	memset(m->ns2bsindx + 2, 2u * 2u, 9u);
	memset(m->ns2bsindx + 11, 2u * 3u, 256u - 11u);

	for (i = 0; i < 3u; i++)
		m->ns2indx[i] = (uint8_t)i;
	step = 1u;
	k = 1u;
	{
		uint32_t mm = 3u, cnt = 1u;

		for (i = 3u; i < 256u; i++) {
			m->ns2indx[i] = (uint8_t)mm;
			if (!--cnt) {
				mm++;
				cnt = mm - 2u;
			}
		}
	}
	(void)step; (void)k;

	memset(m->hb2flag, 0, 0x40u);
	memset(m->hb2flag + 0x40, 8u, 256u - 0x40u);

	m->dummy_see.shift = PERIOD_BITS;
	m->dummy_see.summ = 0;
	m->dummy_see.count = 64;
}

/* ---- the model ------------------------------------------------------------ */

static void restart_model(struct kof_ppmd *m)
{
	uint32_t i, k, mc;
	struct context *c;
	struct state *s;

	memset(m->free_list, 0, sizeof m->free_list);
	m->text = UNIT_SIZE;
	m->hi_unit = m->arena_size - (m->arena_size % UNIT_SIZE);
	m->units_start = m->hi_unit -
			 (m->arena_size / 8u / UNIT_SIZE * 7u) * UNIT_SIZE;
	m->lo_unit = m->units_start;
	m->glue_count = 0;

	m->esc_count = 1;
	memset(m->char_mask, 0, sizeof m->char_mask);
	m->order_fall = m->max_order;
	m->run_length = m->init_rl =
		-(int)((m->max_order < 12) ? m->max_order : 12) - 1;
	m->prev_success = 0;

	m->hi_unit -= UNIT_SIZE;
	mc = m->hi_unit;
	m->min_context = m->max_context = mc;
	c = ctx_at(m, mc);
	if (!c)
		return;
	c->suffix = 0;
	c->num_stats = 256;
	c->summ_freq = 256u + 1u;
	m->found_state = m->lo_unit;
	c->stats = m->lo_unit;
	m->lo_unit += u2b(256u / 2u);
	for (i = 0; i < 256u; i++) {
		s = st_at(m, c->stats + i * (uint32_t)sizeof(struct state));
		if (!s)
			return;
		s->symbol = (uint8_t)i;
		s->freq = 1;
		st_set_succ(s, 0);
	}

	for (i = 0; i < 128u; i++)
		for (k = 0; k < 8u; k++) {
			uint32_t j;

			for (j = 0; j < 64u; j += 8u)
				m->bin_summ[i][k + j] =
					(uint16_t)(BIN_SCALE -
						   init_bin_esc[k] /
						   (uint16_t)(i + 2u));
		}
	for (i = 0; i < 25u; i++)
		for (k = 0; k < 16u; k++) {
			m->see[i][k].summ = (uint16_t)((5u * i + 10u) <<
						       (PERIOD_BITS - 4u));
			m->see[i][k].shift = PERIOD_BITS - 4u;
			m->see[i][k].count = 4;
		}
}

static void start_model(struct kof_ppmd *m, int max_order)
{
	m->max_order = max_order;
	restart_model(m);
	m->ns2indx[0] = m->ns2indx[0];   /* tables are already built */
}

/*
 * Walk the suffix chain building the contexts a new successor needs.
 *
 * The one function in the model that allocates along a path rather than at a
 * point, and the one that decides how deep the model actually gets.
 */
static uint32_t create_successors(struct kof_ppmd *m, int skip, uint32_t p_off)
{
	uint32_t up_state_sym, up_state_freq, up_state_succ;
	uint32_t c = m->min_context;
	uint32_t ps[MAX_O], pn = 0;
	struct context *cc;
	struct state *fs = st_at(m, m->found_state);
	uint32_t upbranch;

	if (!fs)
		return 0;
	upbranch = st_succ(fs);

	if (!skip)
		ps[pn++] = m->found_state;

	cc = ctx_at(m, c);
	while (cc && cc->suffix) {
		uint32_t succ;
		struct state *p;

		c = cc->suffix;
		cc = ctx_at(m, c);
		if (!cc)
			return 0;
		if (p_off) {
			p = st_at(m, p_off);
			p_off = 0;
		} else if (cc->num_stats != 1) {
			uint32_t i;

			p = st_at(m, cc->stats);
			if (!p)
				return 0;
			for (i = 0; p->symbol != fs->symbol; i++) {
				p = st_at(m, cc->stats + (i + 1u) *
					  (uint32_t)sizeof(struct state));
				if (!p)
					return 0;
			}
		} else {
			p = st_at(m, one_state_off(c));
			if (!p)
				return 0;
		}
		succ = st_succ(p);
		if (succ != upbranch) {
			c = succ;
			break;
		}
		if (pn >= MAX_O)
			return 0;
		ps[pn++] = (uint32_t)((uint8_t *)p - m->arena);
	}

	{
		/*
		 * A BYTE, not a state.
		 *
		 * upbranch points into the text area, where symbols are
		 * written one after another at whatever offset comes next -
		 * so it is odd half the time. Reading it through a struct
		 * whose fields want two byte alignment is undefined even
		 * where it happens to work, and UBSan says so on real
		 * archives. The original reads *(byte*)UpBranch for the same
		 * reason.
		 */
		const uint8_t *ub = at_off(m, upbranch, 1u);

		if (!ub)
			return 0;
		up_state_sym = *ub;
		up_state_succ = upbranch + 1u;
	}
	cc = ctx_at(m, c);
	if (!cc)
		return 0;
	if (cc->num_stats != 1) {
		uint32_t i;
		struct state *p = st_at(m, cc->stats);

		if (!p)
			return 0;
		for (i = 0; p->symbol != (uint8_t)up_state_sym; i++) {
			p = st_at(m, cc->stats + (i + 1u) *
				  (uint32_t)sizeof(struct state));
			if (!p)
				return 0;
		}
		{
			uint32_t cf = p->freq - 1u;
			uint32_t s0 = cc->summ_freq - cc->num_stats - cf;

			/*
			 * s0 is a difference of three numbers the stream has
			 * had a hand in, so it can be zero - and the branch
			 * below divides by it. The original has the same shape
			 * and gets away with it on archives a compressor wrote;
			 * one archive in this collection reaches it and takes
			 * the process down with SIGFPE. Zero means the context
			 * has nothing left to share out, and the smallest
			 * frequency is the honest answer.
			 */
			if (2u * cf <= s0)
				up_state_freq = 1u + (5u * cf > s0);
			else if (s0 == 0u)
				up_state_freq = 1u;
			else
				up_state_freq = 1u + ((2u * cf + 3u * s0 - 1u) /
						      (2u * s0));
		}
	} else {
		struct state *p = st_at(m, one_state_off(c));

		if (!p)
			return 0;
		up_state_freq = p->freq;
	}

	while (pn) {
		uint32_t nc = alloc_context(m);
		struct context *n;
		struct state *ns;

		if (!nc)
			return 0;
		n = ctx_at(m, nc);
		if (!n)
			return 0;
		n->num_stats = 1;
		ns = st_at(m, one_state_off(nc));
		if (!ns)
			return 0;
		ns->symbol = (uint8_t)up_state_sym;
		ns->freq = (uint8_t)up_state_freq;
		st_set_succ(ns, up_state_succ);
		n->suffix = c;
		{
			struct state *p = st_at(m, ps[--pn]);

			if (!p)
				return 0;
			st_set_succ(p, nc);
		}
		c = nc;
	}
	return c;
}

static void rescale(struct kof_ppmd *m)
{
	uint32_t old_ns, i, adder, esc_freq, sum_freq;
	uint32_t cs = m->min_context;
	struct context *c = ctx_at(m, cs);
	struct state tmp, *p, *stats;
	uint32_t fs_off = m->found_state, stats_off;

	if (!c)
		return;
	stats_off = c->stats;
	stats = st_at(m, stats_off);
	if (!stats)
		return;

	/* the found state moves to the front */
	p = st_at(m, fs_off);
	if (!p)
		return;
	while (fs_off != stats_off) {
		struct state *q = st_at(m, fs_off - (uint32_t)sizeof(struct state));

		if (!q)
			return;
		tmp = *q;
		*q = *p;
		*p = tmp;
		p = q;
		fs_off -= (uint32_t)sizeof(struct state);
	}
	m->found_state = stats_off;

	stats->freq = (uint8_t)(stats->freq + 4u);
	c->summ_freq = (uint16_t)(c->summ_freq + 4u);
	esc_freq = c->summ_freq - stats->freq;
	adder = (m->order_fall != 0) ? 1u : 0u;
	stats->freq = (uint8_t)((stats->freq + adder) >> 1);
	sum_freq = stats->freq;
	old_ns = c->num_stats;

	for (i = 1; i < old_ns; i++) {
		struct state *s = st_at(m, stats_off +
					i * (uint32_t)sizeof(struct state));
		uint32_t k;

		if (!s)
			return;
		esc_freq -= s->freq;
		s->freq = (uint8_t)((s->freq + adder) >> 1);
		sum_freq += s->freq;
		/* keep the run sorted by frequency */
		for (k = i; k > 0; k--) {
			struct state *a = st_at(m, stats_off + k *
						(uint32_t)sizeof(struct state));
			struct state *b = st_at(m, stats_off + (k - 1u) *
						(uint32_t)sizeof(struct state));

			if (!a || !b || a->freq <= b->freq)
				break;
			tmp = *a;
			*a = *b;
			*b = tmp;
		}
	}

	{
		struct state *last = st_at(m, stats_off + (old_ns - 1u) *
					   (uint32_t)sizeof(struct state));

		if (!last)
			return;
		if (last->freq == 0) {
			uint32_t nn = 1, i2;

			while (1) {
				struct state *s =
					st_at(m, stats_off + (old_ns - 1u - nn) *
					      (uint32_t)sizeof(struct state));
				if (!s || s->freq != 0)
					break;
				nn++;
			}
			esc_freq += nn;
			c->num_stats = (uint16_t)(c->num_stats - nn);
			if (c->num_stats == 1) {
				struct state one;

				tmp = *stats;
				do {
					tmp.freq = (uint8_t)(tmp.freq -
							     (tmp.freq >> 1));
					esc_freq >>= 1;
				} while (esc_freq > 1);
				free_units(m, stats_off, (old_ns + 1u) >> 1);
				one = tmp;
				{
					struct state *dst =
						st_at(m, one_state_off(cs));

					if (!dst)
						return;
					*dst = one;
				}
				m->found_state = one_state_off(cs);
				return;
			}
			i2 = (old_ns + 1u) >> 1;
			nn = (c->num_stats + 1u) >> 1;
			if (i2 != nn) {
				uint32_t np = shrink_units(m, stats_off, i2, nn);

				if (np)
					c->stats = np;
			}
		}
	}
	c->summ_freq = (uint16_t)(sum_freq + esc_freq - (esc_freq >> 1));
	m->found_state = c->stats;
}

static void update_model(struct kof_ppmd *m)
{
	uint32_t fs_sym, fs_freq, fs_succ;
	uint32_t c, succ, ns, ns1, s0;
	/*
	 * The state the suffix context was found at, carried into
	 * create_successors.
	 *
	 * It is not an optimisation: create_successors uses it as the FIRST
	 * step of its walk instead of searching for the symbol again, and the
	 * two do not always land on the same state once the block above has
	 * swapped a pair to keep the run sorted. Passing nothing made the walk
	 * start one state out.
	 */
	uint32_t p_found = 0;
	struct state *fs = st_at(m, m->found_state);
	struct context *mc = ctx_at(m, m->min_context);

	if (!fs || !mc)
		return;
	fs_sym = fs->symbol;
	fs_freq = fs->freq;
	fs_succ = st_succ(fs);

	if (fs_freq < MAX_FREQ / 4u && mc->suffix) {
		struct context *sc = ctx_at(m, mc->suffix);

		if (!sc)
			return;
		if (sc->num_stats == 1) {
			struct state *s = st_at(m, one_state_off(mc->suffix));

			if (s && s->freq < 32u)
				s->freq = (uint8_t)(s->freq + 1u);
		} else {
			uint32_t i;
			struct state *s = st_at(m, sc->stats);

			if (!s)
				return;
			if (s->symbol != (uint8_t)fs_sym) {
				for (i = 1; ; i++) {
					struct state *q =
						st_at(m, sc->stats + i *
						      (uint32_t)sizeof(struct state));
					if (!q)
						return;
					if (q->symbol == (uint8_t)fs_sym) {
						s = q;
						break;
					}
					if (i + 1u >= sc->num_stats)
						return;
				}
				{
					struct state *prev =
						st_at(m, (uint32_t)((uint8_t *)s -
							m->arena) -
						      (uint32_t)sizeof(struct state));
					if (prev && s->freq >= prev->freq) {
						struct state t = *s;

						*s = *prev;
						*prev = t;
						s = prev;
					}
				}
			}
			if (s->freq < MAX_FREQ - 9u) {
				s->freq = (uint8_t)(s->freq + 2u);
				sc->summ_freq = (uint16_t)(sc->summ_freq + 2u);
			}
			p_found = (uint32_t)((uint8_t *)s - m->arena);
		}
	}

	if (!m->order_fall) {
		uint32_t nc = create_successors(m, 1, p_found);

		if (!nc) {
			restart_model(m);
			return;
		}
		m->min_context = m->max_context = nc;
		fs = st_at(m, m->found_state);
		if (fs)
			st_set_succ(fs, nc);
		return;
	}

	if (m->text + 1u >= m->units_start) {
		restart_model(m);
		return;
	}
	m->arena[m->text++] = (uint8_t)fs_sym;
	succ = m->text;
	if (m->text >= m->units_start) {
		restart_model(m);
		return;
	}

	if (fs_succ) {
		if (fs_succ <= m->text) {
			fs_succ = create_successors(m, 0, p_found);
			if (!fs_succ) {
				restart_model(m);
				return;
			}
		}
		if (!--m->order_fall) {
			succ = fs_succ;
			m->text -= (m->max_context != m->min_context) ? 1u : 0u;
		}
	} else {
		fs = st_at(m, m->found_state);
		if (fs)
			st_set_succ(fs, succ);
		fs_succ = m->min_context;
	}

	ns = mc->num_stats;
	/*
	 * s0 is what the min context has left once the found symbol and one
	 * unit per symbol are taken out of its total - the denominator every
	 * new state's frequency is scaled against. It was ns here, which is a
	 * count and not a frequency: the new states came out with plausible
	 * but wrong frequencies, and the model went astray a few dozen symbols
	 * later rather than at once.
	 */
	s0 = mc->summ_freq - ns - (fs_freq - 1u);
	for (c = m->max_context; c != m->min_context; ) {
		struct context *cc = ctx_at(m, c);
		struct state *s;

		if (!cc)
			return;
		ns1 = cc->num_stats;
		if (ns1 != 1) {
			if ((ns1 & 1) == 0) {
				uint32_t np = expand_units(m, cc->stats,
							   ns1 >> 1);
				if (!np) {
					restart_model(m);
					return;
				}
				cc->stats = np;
			}
			cc->summ_freq = (uint16_t)(cc->summ_freq +
					(uint32_t)(2u * ns1 < ns) +
					2u * (uint32_t)((4u * ns1 <= ns) &&
							(cc->summ_freq <=
							 8u * ns1)));
		} else {
			uint32_t np = alloc_units(m, 1);
			struct state *one;

			if (!np) {
				restart_model(m);
				return;
			}
			one = st_at(m, one_state_off(c));
			s = st_at(m, np);
			if (!one || !s) {
				restart_model(m);
				return;
			}
			*s = *one;
			cc->stats = np;
			if (s->freq < MAX_FREQ / 4u - 1u)
				s->freq = (uint8_t)(s->freq * 2u);
			else
				s->freq = MAX_FREQ - 4u;
			cc->summ_freq = (uint16_t)(s->freq + m->init_esc +
						   (ns > 3u));
		}
		{
			uint32_t cf = 2u * fs_freq * (cc->summ_freq + 6u);
			uint32_t sf = s0 + cc->summ_freq;
			struct state *nsx;

			nsx = st_at(m, cc->stats + ns1 *
				    (uint32_t)sizeof(struct state));
			if (!nsx) {
				restart_model(m);
				return;
			}
			if (cf < 6u * sf) {
				cf = 1u + (cf > sf) + (cf >= 4u * sf);
				cc->summ_freq = (uint16_t)(cc->summ_freq + 3u);
			} else {
				cf = 4u + (cf >= 9u * sf) + (cf >= 12u * sf) +
				     (cf >= 15u * sf);
				cc->summ_freq = (uint16_t)(cc->summ_freq + cf);
			}
			nsx->symbol = (uint8_t)fs_sym;
			nsx->freq = (uint8_t)cf;
			/* the text position this symbol was written at, not
			 * the context the found state ends up pointing to */
			st_set_succ(nsx, succ);
			cc->num_stats = (uint16_t)(ns1 + 1u);
		}
		c = cc->suffix;
	}
	m->max_context = m->min_context = fs_succ;
}

/* ---- the symbol decoders --------------------------------------------------- */

static struct see *make_esc_freq(struct kof_ppmd *m, uint32_t ctx, uint32_t diff,
				 uint32_t *escfreq)
{
	struct context *c = ctx_at(m, ctx);
	struct see *psee;

	if (!c)
		return &m->dummy_see;
	if (c->num_stats != 256u) {
		struct context *sfx = ctx_at(m, c->suffix);
		uint32_t r, idx;

		r = (uint32_t)m->ns2indx[diff - 1u];
		idx = (uint32_t)(diff < ((sfx ? sfx->num_stats : 0u) -
					 c->num_stats)) +
		      2u * (uint32_t)(c->summ_freq < 11u * c->num_stats) +
		      4u * (uint32_t)(m->num_masked > (int)diff) +
		      (uint32_t)m->hi_bits_flag;
		if (r >= 25u)
			r = 24u;
		if (idx >= 16u)
			idx = 15u;
		psee = &m->see[r][idx];
		*escfreq = psee->summ >> psee->shift;
		psee->summ = (uint16_t)(psee->summ - *escfreq);
		if (!*escfreq)
			*escfreq = 1u;
	} else {
		psee = &m->dummy_see;
		*escfreq = 1u;
	}
	return psee;
}

static void update1(struct kof_ppmd *m, uint32_t s_off)
{
	struct state *s = st_at(m, s_off);
	struct context *c = ctx_at(m, m->min_context);

	if (!s || !c)
		return;
	m->found_state = s_off;
	s->freq = (uint8_t)(s->freq + 4u);
	c->summ_freq = (uint16_t)(c->summ_freq + 4u);
	{
		struct state *prev = st_at(m, s_off -
					   (uint32_t)sizeof(struct state));

		if (prev && s->freq > prev->freq) {
			struct state t = *s;

			*s = *prev;
			*prev = t;
			m->found_state = s_off - (uint32_t)sizeof(struct state);
			s = prev;
		}
	}
	if (s->freq > MAX_FREQ)
		rescale(m);
}

static void update1_0(struct kof_ppmd *m, uint32_t s_off)
{
	struct state *s = st_at(m, s_off);
	struct context *c = ctx_at(m, m->min_context);

	if (!s || !c)
		return;
	m->prev_success = (uint8_t)(2u * s->freq > c->summ_freq);
	m->run_length += m->prev_success;
	c->summ_freq = (uint16_t)(c->summ_freq + 4u);
	s->freq = (uint8_t)(s->freq + 4u);
	m->found_state = s_off;
	if (s->freq > MAX_FREQ)
		rescale(m);
}

static void update2(struct kof_ppmd *m, uint32_t s_off)
{
	struct state *s = st_at(m, s_off);
	struct context *c = ctx_at(m, m->min_context);

	if (!s || !c)
		return;
	m->found_state = s_off;
	s->freq = (uint8_t)(s->freq + 4u);
	c->summ_freq = (uint16_t)(c->summ_freq + 4u);
	if (s->freq > MAX_FREQ)
		rescale(m);
	m->esc_count++;
	m->run_length = m->init_rl;
}

static void update_bin(struct kof_ppmd *m, uint32_t s_off)
{
	struct state *s = st_at(m, s_off);

	if (!s)
		return;
	m->found_state = s_off;
	m->prev_success = 1;
	m->run_length++;
	if (s->freq < 128u)
		s->freq = (uint8_t)(s->freq + 1u);
}

static int decode_bin_symbol(struct kof_ppmd *m)
{
	struct context *c = ctx_at(m, m->min_context);
	uint32_t one = one_state_off(m->min_context);
	struct state *rs = st_at(m, one);
	struct context *sfx;
	uint16_t *bs;
	uint32_t idx1, idx2, bs_val, mean;

	if (!c || !rs)
		return -1;
	sfx = ctx_at(m, c->suffix);
	m->hi_bits_flag = m->hb2flag[
		(uint8_t)(st_at(m, m->found_state) ?
			  st_at(m, m->found_state)->symbol : 0)];
	idx1 = (uint32_t)rs->freq - 1u;
	if (idx1 >= 128u)
		idx1 = 127u;
	idx2 = (uint32_t)m->prev_success +
	       (uint32_t)m->ns2bsindx[(sfx ? sfx->num_stats : 1u) - 1u] +
	       (uint32_t)m->hi_bits_flag +
	       2u * (uint32_t)m->hb2flag[rs->symbol] +
	       (uint32_t)((m->run_length >> 26) & 0x20);
	if (idx2 >= 64u)
		idx2 = 63u;
	bs = &m->bin_summ[idx1][idx2];
	bs_val = *bs;

	if (m->broken)
		return -1;
	if (rd_count(m, BIN_SCALE) < bs_val) {
		m->sub_low = 0;
		m->sub_high = bs_val;
		rd_decode(m);
		rd_normalize(m);
		mean = (bs_val + (1u << (PERIOD_BITS - 2u))) >> PERIOD_BITS;
		*bs = (uint16_t)(bs_val + INTERVAL - mean);
		update_bin(m, one);
		return 0;
	}
	m->sub_low = bs_val;
	m->sub_high = BIN_SCALE;
	rd_decode(m);
	rd_normalize(m);
	mean = (bs_val + (1u << (PERIOD_BITS - 2u))) >> PERIOD_BITS;
	*bs = (uint16_t)(bs_val - mean);
	m->init_esc = exp_escape[*bs >> 10];
	m->char_mask[rs->symbol] = m->esc_count;
	m->num_masked = 1;
	m->prev_success = 0;
	return -2;                        /* escape */
}

static int decode_symbol1(struct kof_ppmd *m)
{
	struct context *c = ctx_at(m, m->min_context);
	uint32_t count, hi_cnt, i;
	struct state *s;

	if (!c)
		return -1;
	count = rd_count(m, c->summ_freq);
	if (m->broken)
		return -1;
	s = st_at(m, c->stats);
	if (!s)
		return -1;
	hi_cnt = s->freq;
	if (count < hi_cnt) {
		m->sub_low = 0;
		m->sub_high = hi_cnt;
		rd_decode(m);
		rd_normalize(m);
		update1_0(m, c->stats);
		return 0;
	}
	if (count >= c->summ_freq)
		return -1;
	m->prev_success = 0;
	for (i = 1; i < c->num_stats; i++) {
		struct state *q = st_at(m, c->stats + i *
					(uint32_t)sizeof(struct state));

		if (!q)
			return -1;
		hi_cnt += q->freq;
		if (hi_cnt > count) {
			m->sub_low = hi_cnt - q->freq;
			m->sub_high = hi_cnt;
			rd_decode(m);
			rd_normalize(m);
			update1(m, c->stats + i *
				(uint32_t)sizeof(struct state));
			return 0;
		}
	}
	/* escape */
	m->sub_low = hi_cnt;
	m->sub_high = c->summ_freq;
	rd_decode(m);
	rd_normalize(m);
	m->num_masked = c->num_stats;
	m->hi_bits_flag = m->hb2flag[
		(uint8_t)(st_at(m, m->found_state) ?
			  st_at(m, m->found_state)->symbol : 0)];
	for (i = 0; i < c->num_stats; i++) {
		struct state *q = st_at(m, c->stats + i *
					(uint32_t)sizeof(struct state));
		if (q)
			m->char_mask[q->symbol] = m->esc_count;
	}
	return -2;
}

static int decode_symbol2(struct kof_ppmd *m)
{
	struct context *c = ctx_at(m, m->min_context);
	uint32_t count, hi_cnt = 0, escfreq, i, n;
	uint32_t hits[256], nh = 0;
	struct see *psee;

	if (!c)
		return -1;
	psee = make_esc_freq(m, m->min_context,
			     (uint32_t)(c->num_stats - m->num_masked), &escfreq);

	for (i = 0; i < c->num_stats && nh < 256u; i++) {
		struct state *q = st_at(m, c->stats + i *
					(uint32_t)sizeof(struct state));

		if (!q)
			return -1;
		if (m->char_mask[q->symbol] == m->esc_count)
			continue;
		hi_cnt += q->freq;
		hits[nh++] = c->stats + i * (uint32_t)sizeof(struct state);
	}

	count = rd_count(m, hi_cnt + escfreq);
	if (m->broken)
		return -1;
	if (count < hi_cnt) {
		uint32_t acc = 0;

		for (n = 0; n < nh; n++) {
			struct state *q = st_at(m, hits[n]);

			if (!q)
				return -1;
			acc += q->freq;
			if (acc > count) {
				m->sub_low = acc - q->freq;
				m->sub_high = acc;
				rd_decode(m);
				rd_normalize(m);
				/*
				 * A hit ages the SEE context; an escape feeds
				 * it. They were the other way round here,
				 * which taught the escape estimator the
				 * opposite of what happened and put the model
				 * wrong a couple of dozen symbols in.
				 */
				if (psee->shift < PERIOD_BITS &&
				    --psee->count == 0) {
					psee->summ = (uint16_t)(psee->summ * 2u);
					psee->count = (uint8_t)(3u <<
								psee->shift++);
				}
				update2(m, hits[n]);
				return 0;
			}
		}
		return -1;
	}
	if (count >= hi_cnt + escfreq)
		return -1;
	m->sub_low = hi_cnt;
	m->sub_high = hi_cnt + escfreq;
	rd_decode(m);
	rd_normalize(m);
	psee->summ = (uint16_t)(psee->summ + hi_cnt + escfreq);
	for (n = 0; n < nh; n++) {
		struct state *q = st_at(m, hits[n]);

		if (q)
			m->char_mask[q->symbol] = m->esc_count;
	}
	m->num_masked = c->num_stats;
	return -2;
}

/* ---- what the caller drives ------------------------------------------------ */

uint64_t kof_ppmd_arena_want(uint8_t max_mb_byte)
{
	uint64_t want = ((uint64_t)max_mb_byte + 1u) << 20;

	return want > ARENA_MAX ? ARENA_MAX : want;
}

struct kof_ppmd *kof_ppmd_new(void)
{
	struct kof_ppmd *m = calloc(1, sizeof *m);

	if (m)
		tables_init(m);
	return m;
}

void kof_ppmd_free(struct kof_ppmd *m)
{
	if (!m)
		return;
	free(m->arena);
	free(m);
}

int kof_ppmd_start(struct kof_ppmd *m, int max_order, uint64_t arena,
		   const uint8_t *in, uint64_t in_len, uint64_t in_at)
{
	if (!m || arena < UNIT_SIZE * 16u || arena > ARENA_MAX)
		return 0;
	if (max_order < 2 || max_order > (int)MAX_O)
		return 0;
	if (m->arena_size != (uint32_t)arena) {
		free(m->arena);
		m->arena = malloc((size_t)arena);
		if (!m->arena) {
			m->arena_size = 0;
			return 0;
		}
		m->arena_size = (uint32_t)arena;
	}
	memset(m->arena, 0, m->arena_size);
	m->in = in;
	m->in_len = in_len;
	m->in_at = in_at;
	m->broken = 0;
	m->esc_count = 1;
	sub_init(m);
	start_model(m, max_order);
	rd_init(m);
	return !m->broken && m->min_context != 0;
}

/* Where the model has read up to, so the caller's own cursor can follow. */
uint64_t kof_ppmd_at(const struct kof_ppmd *m) { return m ? m->in_at : 0; }

int kof_ppmd_resume(struct kof_ppmd *m, const uint8_t *in, uint64_t in_len,
		    uint64_t in_at)
{
	if (!m || !m->arena_size || !m->min_context)
		return 0;
	m->in = in;
	m->in_len = in_len;
	m->in_at = in_at;
	m->broken = 0;
	rd_init(m);
	return 1;
}

int kof_ppmd_next(struct kof_ppmd *m)
{
	struct context *c;
	struct state *fs;
	int sym;

	if (!m || m->broken || !m->min_context)
		return -1;
	c = ctx_at(m, m->min_context);
	if (!c)
		return -1;

	/*
	 * The decoders answer whether a symbol was found, not which one.
	 *
	 * Which one is read from found_state at the end, because the update
	 * that follows a hit REORDERS the table: a state whose frequency has
	 * just risen is swapped with the one before it to keep the run sorted,
	 * so the pointer the decoder matched on no longer holds the symbol it
	 * matched. Returning that pointer's symbol gave every byte as its own
	 * predecessor - the first four bytes of a file came out 7a 0c 09 1f
	 * where the file has 7b 0d 0a 20.
	 */
	sym = (c->num_stats != 1) ? decode_symbol1(m)
				  : decode_bin_symbol(m);

	while (sym == -2) {
		/*
		 * The symbol was not in this context. Walk out to the suffix
		 * chain until a context is reached that offers something the
		 * mask has not already ruled out.
		 */
		do {
			m->order_fall++;
			c = ctx_at(m, m->min_context);
			if (!c || !c->suffix)
				return -1;
			m->min_context = c->suffix;
			c = ctx_at(m, m->min_context);
			if (!c)
				return -1;
		} while (c->num_stats == (uint16_t)m->num_masked);
		sym = decode_symbol2(m);
	}
	if (sym < 0 || m->broken)
		return -1;

	fs = st_at(m, m->found_state);
	if (!fs)
		return -1;
	sym = fs->symbol;
	if (!m->order_fall && st_succ(fs) > m->text) {
		m->min_context = m->max_context = st_succ(fs);
	} else {
		update_model(m);
		/* The stamp wrapped, so every entry could collide with it:
		 * this is the one moment the mask really is cleared. */
		if (m->esc_count == 0) {
			m->esc_count = 1;
			memset(m->char_mask, 0, sizeof m->char_mask);
		}
	}
	return m->broken ? -1 : sym;
}
