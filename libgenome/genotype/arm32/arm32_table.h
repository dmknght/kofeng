/*
 * arm32_table.h - what the ARM state and Thumb state decoders share and what their
 * inline decode reads: the shape of a table row and the first-level index. Included by
 * arm32.h and thumb.h; the canonical rows and the index's statistics are in
 * arm32_private.h.
 *
 * A DECODE IS: INDEX, MATCH, EXTRACT. The canonical table is the hand-written rows
 * (arm32_rows.c, thumb_rows.c) in priority order. From them tools/genotype/arm_index_gen.c
 * derives, once, a first-level index on a few bits of the word, and for every key the short list of rows that can match it, in priority
 * order, cut after the first the key alone decides - so the LAST row of every list
 * matches whatever is left and the decoder's loop needs no end test.
 */
#ifndef KGENOME_GENOTYPE_ARM32_TABLE_H
#define KGENOME_GENOTYPE_ARM32_TABLE_H

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

/* THE DERIVED ONES the decoders read: const data, written by tools/genotype/arm_index_gen.c from the hand-written rows
 * (arm32_index_tab.c, checked in; `make genotype-arm-index`). Nothing is built at run time and nothing is written, so there
 * is no state to guard and a decode on any thread is a plain read. */
extern const struct kgenome_arm32_row kgenome_arm32_lists[];
extern const uint16_t kgenome_arm32_idx[2 * KGENOME_ARM32_KEYS];
extern const struct kgenome_arm32_row kgenome_thumb_lists[];
extern const uint16_t kgenome_thumb_idx_narrow[KGENOME_THUMB_NARROW_KEYS];
extern const uint16_t kgenome_thumb_idx_wide[KGENOME_THUMB_WIDE_KEYS];

#endif /* KGENOME_GENOTYPE_ARM32_TABLE_H */
