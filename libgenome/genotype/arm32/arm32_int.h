/*
 * arm32_int.h - what the ARM state and Thumb state decoders share: the shape of a
 * table row, the first-level index, and the guard that builds it.
 *
 * A DECODE IS: INDEX, MATCH, EXTRACT. The canonical table is the hand-written rows
 * (arm32_rows.c, thumb_rows.c) in priority order. From them, the first time a
 * decode needs it, arm32_index.c derives a first-level index on a few bits of the
 * word, and for every key the short list of rows that can match it, in priority
 * order, cut after the first the key alone decides - so the LAST row of every list
 * matches whatever is left and the decoder's loop needs no end test.
 */
#ifndef KGENOME_GENOTYPE_ARM32_INT_H
#define KGENOME_GENOTYPE_ARM32_INT_H

#include <stdatomic.h>
#include <stdint.h>

struct kgenome_arm32_row {
	uint32_t mask;          /* the bits the row says something about          */
	uint32_t value;         /* what they must be                              */
	uint16_t id;            /* enum kgenome_arm32_id or enum kgenome_thumb_id            */
};

/*
 * The index keys. They live here, and not in the decoders, so that the decoders
 * and the code that builds the index cannot disagree on them.
 *
 * ARM state: bits 27..20 and 7..4, and one more bit that says whether the
 * condition is 15, which is its own instruction space: 8192 entries, the first
 * half for conditions 0..14 and the second for 15.
 */
#define KGENOME_ARM32_KEYS 4096u
static inline unsigned kgenome_arm32_key12(uint32_t w)
{
	return ((w >> 16) & 0xff0u) | ((w >> 4) & 0xfu);
}
static inline unsigned kgenome_arm32_key(uint32_t w)
{
	return kgenome_arm32_key12(w) | ((((w >> 28) + 1u) >> 4) << 12);
}

/* Thumb state, 16-bit: bits 15..6 of the halfword. */
#define KGENOME_THUMB_NARROW_KEYS 1024u
static inline unsigned kgenome_thumb_narrow_key(uint32_t h)
{
	return (h >> 6) & 0x3ffu;
}

/* Thumb state, 32-bit: the word is first halfword << 16 | second; bits 28..20
 * (first halfword 12..4) and bit 15 (second halfword's top bit). */
#define KGENOME_THUMB_WIDE_KEYS 1024u
static inline unsigned kgenome_thumb_wide_key(uint32_t w)
{
	return ((w >> 19) & 0x3feu) | ((w >> 15) & 1u);
}

/* IN THE THUMB INDEX AN ENTRY WITH ITS TOP BIT SET IS A NAME, not an offset: a
 * bucket whose one candidate row is decided by the key alone is answered without
 * touching a row. (MEASURED on the .text of the 21 Mirai ARM binaries: it took the
 * Thumb full path from 16.3 to 15.1 ns per instruction; in ARM state it put a
 * mispredicted branch into the lookup, decode alone 2.4 -> 4.7 ns, with no gain.) */
#define KGENOME_ARM32_DIRECT 0x8000u

/* THE CANONICAL ROWS: hand-written, in priority order. */
extern const struct kgenome_arm32_row kgenome_arm32_src_cond[], kgenome_arm32_src_unc[];
extern const unsigned kgenome_arm32_src_cond_n, kgenome_arm32_src_unc_n;
extern const struct kgenome_arm32_row kgenome_thumb_src_narrow[], kgenome_thumb_src_wide[];
extern const unsigned kgenome_thumb_src_narrow_n, kgenome_thumb_src_wide_n;

/* THE DERIVED ONES the decoders read: static storage, filled by the builders. */
extern struct kgenome_arm32_row kgenome_arm32_lists[];
extern uint16_t kgenome_arm32_idx[2 * KGENOME_ARM32_KEYS];
extern struct kgenome_arm32_row kgenome_thumb_lists[];
extern uint16_t kgenome_thumb_idx_narrow[KGENOME_THUMB_NARROW_KEYS];
extern uint16_t kgenome_thumb_idx_wide[KGENOME_THUMB_WIDE_KEYS];

/*
 * BUILT ON FIRST USE, once, by whichever thread gets there first: the state is 0
 * (not built), 1 (being built) or 2 (ready). A thread that finds it 0 takes it to
 * 1 with a compare-and-swap and builds; one that finds it 1 waits for 2 (the build
 * is microseconds). The store of 2 is a release and every decode's check an
 * acquire, so a thread that sees 2 sees the whole index. The check in a decode is
 * one load and one predictable branch (a plain load on x86).
 */
extern atomic_int kgenome_arm32_state, kgenome_thumb_state;
void kgenome_arm32_build(void);
void kgenome_thumb_build(void);

#if defined(__GNUC__) || defined(__clang__)
#define KGENOME_ARM32_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define KGENOME_ARM32_UNLIKELY(x) (x)
#endif

static inline void kgenome_arm32_ensure(void)
{
	if (KGENOME_ARM32_UNLIKELY(atomic_load_explicit(&kgenome_arm32_state, memory_order_acquire) != 2))
		kgenome_arm32_build();
}

static inline void kgenome_thumb_ensure(void)
{
	if (KGENOME_ARM32_UNLIKELY(atomic_load_explicit(&kgenome_thumb_state, memory_order_acquire) != 2))
		kgenome_thumb_build();
}

/* What the builders found, for the unit test: rows no key reaches (shadowed by an
 * earlier row: a mistake in the order), and the room used in the list pools. */
struct kgenome_arm32_stats {
	unsigned shadowed_arm32, shadowed_thumb;
	unsigned lists_arm32, lists_thumb;      /* rows used in the pools */
	unsigned cap_arm32, cap_thumb;          /* and the pools' size */
};
void kgenome_arm32_stats(struct kgenome_arm32_stats *out);

#endif /* KGENOME_GENOTYPE_ARM32_INT_H */
