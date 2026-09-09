/* SPDX-License-Identifier: Apache-2.0 */
/*
 * koffridge.c - the verdict cache. See koffridge.h for what it is keyed on and
 * why that is the only decision that matters.
 *
 * SHAPE: open addressing, linear probing, one flat allocation. No buckets, no
 * per-entry malloc, no arena. An entry is 288 bytes and the whole table is one
 * calloc, so a lookup is a hash, a mask and at most KOF_PROBE cache lines - and
 * the structure has no way to fragment over a long-running walk.
 *
 * EVICTION: least recently used WITHIN THE PROBE RUN, and nowhere else. A full
 * LRU needs a list and two pointer writes per hit, on the path this exists to
 * make cheap; a clock needs a sweep hand and a pass that can find nothing. The
 * probe run is the only set of slots this key could ever occupy, so the worst
 * entry in it is the right one to drop, and finding it costs the walk that was
 * happening anyway.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "koffridge.h"

/*
 * 4096 entries, about 1.2MB.
 *
 * Chosen against the thing it is for: the distinct modules behind every mapping
 * on a Windows workstation number in the low hundreds, and a whole-machine file
 * scan does not use this at all. Four thousand is an order of magnitude over
 * the working set it was sized for, which is where a default belongs - large
 * enough that nobody meets the eviction path by accident, small enough that a
 * caller who wanted a big one still has to say so.
 */
#define KOF_FRIDGE_DEFAULT 4096u

/*
 * How far a lookup walks before it gives up.
 *
 * 16 slots is one to two cache lines' worth of the hash array and is far past
 * the run lengths linear probing produces below a 0.75 load factor. Past it the
 * table is not full, it is BADLY DISTRIBUTED, and continuing to walk turns a
 * bounded miss into an unbounded one.
 */
#define KOF_PROBE 16u

struct entry {
	uint64_t h;             /* the identity's hash, 0 when the slot is free */
	uint64_t used;          /* the tick this entry was last read or written */
	uint32_t id_len;
	uint8_t  id[KOFFRIDGE_ID_MAX];
	struct koffridge_verdict v;
};

struct koffridge {
	struct entry *e;
	uint32_t cap;           /* a power of two */
	uint32_t mask;
	uint32_t used;
	uint64_t tick;
	uint64_t db_stamp;
	struct koffridge_stat st;
};

/*
 * FNV-1a, and the reason a stronger hash is not needed here: a collision costs
 * a probe, never a wrong answer. The identity bytes are compared in full before
 * any entry is returned, so this only has to spread - which FNV does, on the
 * short structured keys this takes - and not to resist anything.
 *
 * Never returns 0; that value marks a free slot.
 */
static uint64_t hash_id(const void *p, uint32_t n)
{
	const uint8_t *b = p;
	uint64_t h = 1469598103934665603ull;
	uint32_t i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h *= 1099511628211ull;
	}
	return h ? h : 1ull;
}

static uint32_t round_pow2(uint32_t n)
{
	uint32_t p = 1;

	while (p < n && p < (1u << 30))
		p <<= 1;
	return p;
}

struct koffridge *koffridge_open(uint32_t capacity, uint64_t db_stamp)
{
	struct koffridge *f = calloc(1, sizeof *f);

	if (!f)
		return NULL;
	f->cap = round_pow2(capacity ? capacity : KOF_FRIDGE_DEFAULT);
	f->mask = f->cap - 1u;
	f->e = calloc(f->cap, sizeof *f->e);
	if (!f->e) {
		free(f);
		return NULL;
	}
	f->db_stamp = db_stamp;
	f->st.capacity = f->cap;
	return f;
}

void koffridge_close(struct koffridge *f)
{
	if (!f)
		return;
	free(f->e);
	free(f);
}

uint64_t koffridge_db_stamp(const struct koffridge *f)
{
	return f ? f->db_stamp : 0ull;
}

void koffridge_clear(struct koffridge *f)
{
	if (!f)
		return;
	memset(f->e, 0, (size_t)f->cap * sizeof *f->e);
	f->used = 0;
	f->st.used = 0;
}

static int same_id(const struct entry *e, uint64_t h, const void *id,
		   uint32_t id_len)
{
	return e->h == h && e->id_len == id_len &&
	       memcmp(e->id, id, id_len) == 0;
}

int koffridge_get(struct koffridge *f, const void *id, uint32_t id_len,
		  struct koffridge_verdict *out)
{
	uint64_t h;
	uint32_t i, slot;

	if (!f || !id || !id_len || id_len > KOFFRIDGE_ID_MAX) {
		if (f)
			f->st.misses++;
		return 0;
	}
	h = hash_id(id, id_len);
	slot = (uint32_t)h & f->mask;

	for (i = 0; i < KOF_PROBE; i++) {
		struct entry *e = &f->e[(slot + i) & f->mask];

		/*
		 * A free slot ends the run. Nothing here ever deletes an entry
		 * - eviction overwrites - so there are no tombstones and a hole
		 * genuinely means the key was never inserted.
		 */
		if (!e->h)
			break;
		if (same_id(e, h, id, id_len)) {
			e->used = ++f->tick;
			if (out)
				*out = e->v;
			f->st.hits++;
			return 1;
		}
	}
	f->st.misses++;
	return 0;
}

/*
 * Which finding to keep, when the scan produced more than one.
 *
 * The worst, by kof_level_rank - which is the engine's own ordering and not a
 * second one invented here. A cache that kept the first would keep whichever
 * module happened to sit earliest in the database, and the answer would change
 * with a database update for no reason anybody could see.
 */
static void fill_verdict(struct koffridge_verdict *v,
			 const struct kof_result *res)
{
	uint32_t i, best = 0;
	int best_rank = -1;

	memset(v, 0, sizeof *v);
	if (!res)
		return;
	v->broken = res->broken;
	v->findings = res->n;
	if (!res->n)
		return;
	for (i = 0; i < res->n && i < KOF_MAX_FINDINGS; i++) {
		int r = kof_level_rank(res->v[i].level);

		if (r > best_rank) {
			best_rank = r;
			best = i;
		}
	}
	v->level = res->v[best].level;
	memcpy(v->name, res->v[best].name, sizeof v->name);
	v->name[sizeof v->name - 1] = '\0';
}

int koffridge_put(struct koffridge *f, const void *id, uint32_t id_len,
		  const struct kof_result *res)
{
	uint64_t h;
	uint32_t i, slot, victim = 0;
	uint64_t victim_used = 0;
	int have_victim = 0;
	struct entry *e;

	if (!f || !id || !id_len || id_len > KOFFRIDGE_ID_MAX) {
		if (f)
			f->st.refused++;
		return 0;
	}
	h = hash_id(id, id_len);
	slot = (uint32_t)h & f->mask;

	for (i = 0; i < KOF_PROBE; i++) {
		uint32_t at = (slot + i) & f->mask;

		e = &f->e[at];
		if (!e->h) {
			f->used++;
			f->st.used = f->used;
			goto store;
		}
		if (same_id(e, h, id, id_len))
			goto store;      /* rescanned: the newer answer wins */
		if (!have_victim || e->used < victim_used) {
			victim = at;
			victim_used = e->used;
			have_victim = 1;
		}
	}

	/*
	 * The run is full. Drop its least recently used entry rather than
	 * refusing, because a key that cannot be stored is a key that will miss
	 * for the rest of the walk - and the entry being dropped is by
	 * construction the one in this run that has gone longest unwanted.
	 */
	if (!have_victim) {
		f->st.refused++;
		return 0;
	}
	e = &f->e[victim];
	f->st.evictions++;

store:
	e->h = h;
	e->id_len = id_len;
	memcpy(e->id, id, id_len);
	if (id_len < KOFFRIDGE_ID_MAX)
		memset(e->id + id_len, 0, KOFFRIDGE_ID_MAX - id_len);
	fill_verdict(&e->v, res);
	e->used = ++f->tick;
	f->st.stores++;
	return 1;
}

void koffridge_stats(const struct koffridge *f, struct koffridge_stat *out)
{
	if (!out)
		return;
	if (!f) {
		memset(out, 0, sizeof *out);
		return;
	}
	*out = f->st;
}

size_t koffridge_describe(const struct koffridge *f, char *buf, size_t cap)
{
	uint64_t look;
	int n;

	if (!buf || !cap)
		return 0;
	if (!f) {
		buf[0] = '\0';
		return 0;
	}
	look = f->st.hits + f->st.misses;
	n = snprintf(buf, cap,
		     "fridge: %llu hit, %llu miss (%.1f%%), %llu stored, "
		     "%llu evicted, %u/%u used",
		     (unsigned long long)f->st.hits,
		     (unsigned long long)f->st.misses,
		     look ? (double)f->st.hits * 100.0 / (double)look : 0.0,
		     (unsigned long long)f->st.stores,
		     (unsigned long long)f->st.evictions,
		     f->st.used, f->st.capacity);
	if (n < 0)
		return 0;
	return (size_t)n < cap ? (size_t)n : cap - 1u;
}
