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
#include "hexprog.h"

struct kof_match_ctx {
	kof_buf data;

	/*
	 * Search state for one object, owned here because it is all searching: the
	 * presence set that says a pattern cannot be here, and the memo that stops the
	 * same question being asked twice. Neither is scan bookkeeping - the scanner
	 * decides *which* ranges to ask about, the matcher decides how to answer.
	 */
	struct kof_gram *gram;      /* owned; built lazily, see kof_match_begin */
	/*
	 * The presence table to USE for this object, which is the one above or
	 * nothing. Separate from ownership because the filter is worth having on a
	 * small object and worth skipping on a large one, and that is decided per
	 * object while the table itself is kept.
	 */
	struct kof_gram *gram_use;
	uint32_t         gram_patterns;   /* what the engine declared; 0 -> no table */
	/*
	 * HOW BIG A TABLE, and HOW MANY PATTERNS MAKE IT WORTH ONE. Zero on
	 * both means the defaults, which are sized for a whole file.
	 *
	 * A matcher over the symbol block wants neither default. The table is
	 * sized to keep occupancy low for the LARGEST buffer it will ever
	 * stamp, and that buffer is a quarter megabyte rather than a hundred,
	 * so 32MB of it would be memory nothing reads. And the threshold
	 * exists because stamping costs a pass over the buffer - which for a
	 * few kilobytes is paid back by the second search, not the hundred and
	 * fortieth.
	 */
	uint8_t          gram_bits;
	uint32_t         gram_min;

	/*
	 * The memo, one cell per (string, range) pair, STAMPED RATHER THAN CLEARED.
	 *
	 * A cell holds the generation that wrote it in its top bits and the answer in
	 * its bottom two, and a cell whose generation is not the current one reads as
	 * unknown. That is what makes starting an object O(1): clearing it instead is
	 * work proportional to the whole database, paid on every object, including the
	 * objects where the filters decide to run nothing at all. At four million
	 * records that memset is megabytes per object and it defeats the purpose of
	 * having a filter.
	 *
	 * The same trick the presence table already uses, for the same reason. Two
	 * bytes a cell rather than one is the price, and it buys back far more than it
	 * costs the moment the database stops being small.
	 */
	uint16_t        *memo;
	uint32_t         memo_len;  /* cells, not bytes */
	uint16_t         memo_gen;



	/* Counters, for measuring whether the memo is worth its complexity. */
	uint64_t n_calls;
	uint64_t n_bytes_scanned;
	uint64_t n_bytes_indexed;   /* what building the presence set cost */
};

void kof_match_begin(struct kof_match_ctx *m, kof_buf data);



/* Answers a memo cell can hold, in its low two bits. */
#define KOF_MEMO_UNKNOWN 0
#define KOF_MEMO_ABSENT  1
#define KOF_MEMO_PRESENT 2

/* The generation occupies the rest. Zero is never a live generation, so a freshly
 * allocated memo reads as entirely unknown without being written. */
#define KOF_MEMO_GEN_MAX 0x3fffu

/*
 * "Answer this one, and cache nothing."
 *
 * A slot past the end of the memo already means no cell, which kof_match_lookup
 * handles because a database can legitimately have no memo at all. This names
 * that, so a caller with a question the memo cannot key - one whose mask spans
 * two different buffers, say - says so rather than passing a plausible-looking
 * slot number and quietly overwriting the answer that belongs to it.
 */
#define KOF_MEMO_NONE 0xffffffffu

/*
 * Attach the per-object search state. `memo_len` counts cells; `gram` is built on
 * first use and restamped per object.
 */
int  kof_match_state_init(struct kof_match_ctx *, uint32_t n_patterns,
			  uint32_t memo_len);
void kof_match_state_free(struct kof_match_ctx *);

/*
 * Is a declared pattern present in these ranges? `slot` indexes the memo.
 *
 * Two stages, and the first is what makes it affordable: the presence set says whether
 * the pattern's first four bytes occur in the object at all, and only then is a search
 * run. A marker that is absent - nearly every marker for nearly every object - costs
 * one table lookup and no scan. That stage does not depend on the ranges, so absence
 * answers every range at once.
 *
 * `answered_without_scan` is incremented when the presence set settled it, so a caller
 * can report what the filter earned.
 *
 * This is the whole of what a caller wants, and the pieces underneath it are not
 * exported: a caller assembling them differently is a caller that can get the
 * two-stage order wrong.
 */
/*
 * The memo on its own, for a question this matcher cannot answer itself.
 *
 * The symbol block is searched by a SECOND matcher, because it is not the
 * object's bytes - but the question "is this marker in that range of this
 * object" is the same KIND of question and deserves the same cache. Rather
 * than give that matcher a memo of its own, which would double a table sized
 * by the whole database to serve a buffer of a few kilobytes, the caller reads
 * and writes the existing cell around a search it runs elsewhere.
 *
 * The cell protocol - the generation in the top bits, the answer in the low two
 * - stays here, where kof_match_lookup also uses it. A caller reimplementing it
 * would be a second copy of the one rule that decides whether a cached answer is
 * still this object's.
 *
 * get returns -1 for "not known", else 0 or 1. Both are no-ops when the matcher
 * has no memo, so a caller need not test for one.
 */
int  kof_match_memo_get(const struct kof_match_ctx *, uint32_t slot);
void kof_match_memo_put(struct kof_match_ctx *, uint32_t slot, int found);

int kof_match_lookup(struct kof_match_ctx *, uint32_t slot,
		     const struct kof_range *ext, uint32_t next,
		     const uint8_t *bytes, uint16_t len, uint8_t kind, uint8_t flags,
		     uint64_t *answered_without_scan);

/*
 * Does the pattern match at exactly this offset? No search - one compare, or one
 * bounded walk for a hex pattern.
 *
 * Separate from kof_match_lookup because it is a different operation with a
 * different cost, and conflating them would route a comparison of eight bytes
 * through range resolution and a memo. It is also not memoised: the offset is
 * computed by the module at run time, so there is nothing constant to key on, and
 * caching a memcmp would cost more than repeating it.
 *
 * The bound check is here rather than in the caller: a module supplies the offset,
 * the offset comes from the file, and a compare that walks off the mapping is the
 * one failure this layer exists to make impossible.
 */
int kof_match_at(struct kof_match_ctx *, uint64_t off,
		 const uint8_t *bytes, uint16_t len, uint8_t kind, uint8_t flags);

/* Search a single ad-hoc range, for the same reason: the module computed it. */
int kof_match_in(struct kof_match_ctx *, uint64_t off, uint64_t len,
		 const uint8_t *bytes, uint16_t plen, uint8_t kind, uint8_t flags);

/*
 * Where the pattern is, rather than whether it is there. KOF_BROKEN if absent.
 *
 * For unpackers. A packed executable is read relative to a marker its stub carries
 * - UPX's l_info is found by its magic and every block offset follows from it - so
 * "is it present" is not the question; "where" is. The search computes this either
 * way, so reporting it costs nothing that whether does not already cost.
 */
uint64_t kof_match_where(struct kof_match_ctx *, uint64_t off, uint64_t len,
			 const uint8_t *bytes, uint16_t plen, uint8_t kind,
			 uint8_t flags);

#endif /* KOFENG_KOFMATCH_H */
