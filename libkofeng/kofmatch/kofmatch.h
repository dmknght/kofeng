/*
 * kofmatch.h - pattern matching over the object under scan.
 *
 * Reads the compiled format defined in kofeng/kofpat.h. The generator writes
 * that format and this reads it; neither knows anything else about the other.
 *
 * The context holds the object bytes and a one entry memo. The memo is what
 * makes the readable authoring form also the fast one: a module that writes
 * several separate kof_find_str() calls against the same set and region would
 * otherwise pay a pass for each. Caching one result turns N calls into one pass
 * plus N-1 comparisons, and it lives here rather than in the module because
 * modules are required to hold no state.
 */

#ifndef KOFENG_KOFMATCH_H
#define KOFENG_KOFMATCH_H

#include <stdint.h>
#include <kofeng/kofpat.h>
#include "../core/kofcore.h"

struct kof_match_ctx {
	kof_buf data;

	/* Last find_set result, keyed by the three values that determine it. */
	const uint8_t *memo_pat;
	uint64_t       memo_off;
	uint64_t       memo_len;
	uint64_t       memo_hits;
	int            memo_valid;

	/* Counters, for measuring whether the memo is worth its complexity. */
	uint64_t n_calls;
	uint64_t n_memo_hits;
	uint64_t n_bytes_scanned;
};

void kof_match_begin(struct kof_match_ctx *m, kof_buf data);

/*
 * Search [off, off+len) for every pattern in the compiled set.
 *
 * Returns a bitmask of which patterns were found; bit i for pattern i. Stores
 * the offset of the earliest hit in first_hit when that is non-NULL and anything
 * matched.
 *
 * off and len are clamped rather than rejected: ranges are normally computed
 * from untrusted sizes, and an expression like "sec->file_size - 0x40" underflows
 * to something enormous on a small section. Clamping turns that into a wrongly
 * sized search, which a module's own fixtures will catch; rejecting would turn it
 * into a silent no-match, which they would not. len == 0 means "to the end".
 */
/*
 * Find a literal in [off, off+len) of the object. Returns non-zero on a hit and
 * writes the absolute offset to *hit.
 *
 * The host side search primitive. Strings are declared, so the host holds the bytes
 * and calls this directly; nothing needs the compiled-array walk below until hex
 * patterns with wildcards exist.
 */
uint64_t kof_match_find(struct kof_match_ctx *m, uint64_t off, uint64_t len,
			const uint8_t *bytes, uint32_t nbytes, int nocase,
			uint64_t *hit);

uint64_t kof_match_find_set(struct kof_match_ctx *m,
			    uint64_t off, uint64_t len,
			    const uint8_t *compiled, uint32_t clen,
			    uint64_t *first_hit);

#endif /* KOFENG_KOFMATCH_H */
