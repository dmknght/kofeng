/*
 * diag_oatab.h - the one open-addressing table of the diagnose family: linear probing, a power-of-two number of slots, an empty slot is all zero bytes, the
 * table grown (doubled) when one more entry would take it past half full, and rehashed in slot order.
 *
 * WHY ONE. The TEXT route kept four tables of this shape (its variables, the paths nodes hold, the keys of the relation layer's edges and the names of the functions a text defines) and each
 * spelled the same three things: when to grow, how to move the entries, what to do when memory is refused. Their rehash order and probe order decide which
 * of two equal-hash entries sits where and so what a lookup finds first; one function that does it makes "the same order" a fact and not four copies agreeing.
 *
 * The caller owns the table, the probe and the compare (what is the same entry is the table's own decision: a name, a scope and a length, a 64-bit key); this owns
 * only when a table grows and how its entries move. A caller that charges a budget asks kgenome_oatab_want first, charges the new size, then calls kgenome_oatab_rehash
 * (kgenome_dtx_oa_grow does all three for the TEXT route).
 */
#ifndef KGENOME_DIAG_OATAB_H
#define KGENOME_DIAG_OATAB_H

#include <stddef.h>
#include <stdint.h>

/* The full hash of the occupied slot `slot` (its low bits, masked by the capacity, are its home). `ctx` is the caller's. */
typedef uint32_t (*kgenome_oatab_hash_fn)(void *ctx, const void *slot);

/*
 * THE SEED OF A TEXT'S TABLES, AND THE HASH IT SEEDS. A name is hashed into a table by a function the file cannot know. Not FNV-1a: its step is a xor and a multiplication, so a
 * difference between two states only travels UP the word, and two names that collide from one start collide from every start that agrees with it in a few low bits - measured
 * (G1, 4096 names with one FNV-1a hash against a 32-bit seed that was only xor-ed into the start): the quadratic came back for the one run in thirty whose seed had a handful of
 * zero low bits, and a larger seed space does not close that. Here the state is 64 bits, started from a seed of 64, and every step ends in a shift that carries the high half down
 * (kgenome_oatab_step): a collision found against one seed says nothing about another.
 *
 * The seed is made from the text itself (every byte of it) and from `salt`, an address of the scan (what the system's address-space randomisation makes different from one run to
 * the next): an attacker has neither before the file is written. NOTHING a scan answers depends on the seed: a table is only looked up, never walked in slot order, and a lookup finds
 * the one entry of a name whichever slot holds it (tests/lib/genome/diag_text_defects.c scans one text under many seeds and compares the graphs).
 */
uint64_t kgenome_oatab_seed(const uint8_t *text, uint64_t n, uintptr_t salt);

#define KGENOME_OATAB_K 0x9e3779b97f4a7c15ull

/* One byte into a 64-bit state. */
static inline uint64_t kgenome_oatab_step(uint64_t h, uint8_t c)
{
	h = (h ^ c) * KGENOME_OATAB_K;
	return h ^ (h >> 32);
}

/* The 32 bits of a state a table indexes by (murmur3's finaliser of the two halves folded: each bit of the state reaches each bit of the answer). */
static inline uint32_t kgenome_oatab_fold(uint64_t h)
{
	uint32_t x = (uint32_t)(h ^ (h >> 32));

	x ^= x >> 16;
	x *= 0x85ebca6bu;
	x ^= x >> 13;
	x *= 0xc2b2ae35u;
	x ^= x >> 16;
	return x;
}

/* The slot after `i` in a table of `cap` slots (a power of two). */
static inline uint32_t kgenome_oatab_next(uint32_t i, uint32_t cap)
{
	return (i + 1u) & (cap - 1u);
}

/* The capacity the table needs before one more entry goes in: 0 when `cap` slots hold `n + 1` entries at or under half full, else double `cap` (`first` for an empty table). */
uint32_t kgenome_oatab_want(uint32_t n, uint32_t cap, uint32_t first);

/* Replace *tab (*cap slots of `elem` bytes) by a zeroed table of `nc` slots and move every occupied slot (one with a non-zero byte) in, in slot order, each to the first
 * empty slot from its home. 1; 0 when memory is refused, with *tab and *cap as they were. `work`, when not NULL, is given one for every slot the moves looked at (the
 * cost a test asserts: a table whose entries share a home is quadratic here and nowhere else a clock would show it). */
int kgenome_oatab_rehash(void **tab, uint32_t *cap, uint32_t nc, size_t elem, kgenome_oatab_hash_fn hash, void *ctx, uint64_t *work);

#endif /* KGENOME_DIAG_OATAB_H */
