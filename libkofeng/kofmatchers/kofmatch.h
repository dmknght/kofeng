/*
 * kofmatch.h - pattern matching over the object under scan.
 *
 * Reads the compiled format defined in kofmod/kofsig.h. The generator writes
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
#include <kofmod/kofsig.h>   /* struct kof_range */
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
uint64_t kof_match_find_set(struct kof_match_ctx *m,
			    uint64_t off, uint64_t len,
			    const uint8_t *compiled, uint32_t clen,
			    uint64_t *first_hit);

/*
 * The presence set: which four-byte sequences occur in an object.
 *
 * Matcher-side because it is pattern-matching machinery, not scan bookkeeping: it
 * answers "could this pattern be here" over the same bytes the search runs on. What
 * stays with the scanner is deciding *which* ranges to look in and remembering the
 * answers.
 *
 * The point of it is what it is not: it does not grow with the database. One fixed
 * table answers for any number of patterns, built in a single pass over the object
 * rather than once per pattern - O(bytes + patterns) instead of O(patterns x bytes).
 * An automaton over every pattern would also collapse the passes and would be exact,
 * but its size is the database's size; this trades exactness for a fixed footprint.
 * A collision makes a pattern get searched for that need not have been, which costs
 * time. Absence is never wrong, and absence is what gets acted on.
 */
struct kof_gram;

/* NULL when n_patterns is below the point where building pays for itself. Not a
 * failure: every call below accepts NULL and answers as if there were no table. */
struct kof_gram *kof_gram_new(uint32_t n_patterns);
void             kof_gram_free(struct kof_gram *);

/* Record every four-byte sequence of the object. Returns bytes covered. */
uint64_t kof_gram_build(struct kof_gram *, kof_buf);

/*
 * Could a pattern beginning with these bytes occur?
 *
 * Takes the length and checks it here rather than trusting the caller: the table is
 * keyed on four bytes, so a shorter pattern cannot be looked up and the answer has to
 * be "maybe". Leaving that to the call site is a contract nobody can see, and it
 * becomes a real out of bounds read the day a pattern is stored without a fixed size
 * buffer behind it.
 *
 * `icase` looks up every case variant - at most sixteen probes into a warm table, so
 * folding does not cost the filter. Never a false negative.
 */
int kof_gram_may_contain(const struct kof_gram *, const uint8_t *bytes, uint16_t len,
			 int icase);

/*
 * Find a literal inside a set of ranges, honouring case and word options.
 *
 * Fullword is here and not in the scanner because it is part of what "matched" means.
 * It needs the range bounds, which is why they are passed rather than a single buffer:
 * the edge of a range counts as a word boundary, and without that rule the obvious
 * check reads outside the object at offset zero.
 */
int kof_match_str(struct kof_match_ctx *, const struct kof_range *ext, uint32_t next,
		  const uint8_t *bytes, uint16_t len, int icase, int fullword);

#endif /* KOFENG_KOFMATCH_H */
