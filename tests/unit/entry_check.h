/*
 * entry_check.h - the invariant every entry table has to hold.
 *
 * A region says which bytes are what kind; an entry says what one thing IS. The
 * second is what deep scan opens, so it is the one that turns a number in a
 * hostile file into a read, a decompression and a child object - and every field
 * in it came from bytes somebody else wrote.
 *
 * Shared with partition_check.h's reasoning: one copy, used by the test over
 * real files and the ones over files built to break it, because a second copy of
 * a check is a second thing that can be wrong in a way that agrees with the code
 * it is testing.
 *
 * WHAT IS CHECKED, and each one is a thing that would otherwise be a read:
 *
 *   in range        off + len inside the object, and no wrap. A parser derives
 *                   these from declared fields; kof_clip_len is what it is
 *                   supposed to use, and this is what notices when it did not.
 *   amplification   the declared bytes total at most 2x the object. A table of
 *                   entries that each claim the whole file is how a small input
 *                   asks for a large amount of work - the same ceiling
 *                   hostile_unpack already measures on the unpack side.
 *   distinct        no two entries with the same range. Two rows for one thing
 *                   is a doubled scan at best and a doubled child at worst, and
 *                   it is exactly what a declared entry duplicated by a
 *                   search of the same object used to look like.
 *   index unique    resolve_entry is keyed by index, so two rows with one index
 *                   make the call ambiguous - it would answer one of them and
 *                   there is no way to say which.
 *   kind, format    inside their enumerations. A kind out of range indexes a
 *                   policy table; a format out of range names a parser.
 *   the chain       every non-zero member a real method, no non-zero AFTER a
 *                   zero. A zero terminates, so a value behind one is a
 *                   coding the host will not run and the parser thinks it will.
 *   the name        name_off/name_len inside the object. It is a range into the
 *                   file precisely so no parser has to build a string, which
 *                   only holds if the range is readable.
 *   scattered       an entry whose bytes are a chain must have somewhere to ask.
 *                   The flag with no resolve_entry is a row nothing can open.
 *
 * NOT checked here: whether the flag KOF_ENT_F_CODED_UNKNOWN is set when it
 * should be. That is a question about the container's declared coding, so it
 * needs the file, and the harnesses that include this have a mutated one. It is
 * checked against built files instead, where the answer is known.
 */

#ifndef KOFENG_ENTRY_CHECK_H
#define KOFENG_ENTRY_CHECK_H

#include <stdio.h>
#include <kofmod/kofsig.h>

struct ec_report {
	uint64_t checked;        /* objects whose table was examined */
	uint64_t entries;        /* rows examined across all of them */
	uint64_t failed;
	uint64_t no_table;       /* parsers that publish no entries yet */
	int      quiet;
};

/* Is this a method id the engine could actually be handed?
 *
 * The enumeration is not contiguous - 1..13, then the NRV2 variants from 16,
 * then LZMA from 64 carrying lc/lp/pb in the id itself, which is why the top of
 * the range is 288 and not 64. Written out rather than bounded by the largest
 * value, because "less than the biggest" would accept 14 and 15, which name
 * nothing and would reach a decoder switch that has no case for them.
 *
 * THE TOP OF THE FIRST RANGE HAS TO MOVE WHEN A DECODER IS ADDED, and that is
 * deliberate. It was 9; adding ASCII85, ASCIIHex, RunLength and LZW made every
 * entry naming one of them fail this check, on 819 of 1278 objects in the fuzz
 * run - which is the invariant doing its job. A validator that tracked the
 * enumeration automatically would have accepted a method the engine cannot
 * perform just as readily, and said nothing. */
static int ec_method_ok(uint32_t m)
{
	if (m >= 1u && m <= 13u)
		return 1;
	if (m >= KOF_UNP_NRV2B_8 && m <= KOF_UNP_NRV2E_32)
		return 1;
	/* lc + 9*lp + 45*pb, each parameter bounded by the specification, so the
	 * widest legal id is base + 8 + 36 + 180. */
	if (m >= KOF_UNP_LZMA && m <= KOF_UNP_LZMA + 224u)
		return 1;
	return 0;
}

static int ec_check(const char *what, const struct kof_obj_ctx *ctx,
		    uint64_t obj_size, struct ec_report *rep)
{
	const struct kof_entry *tab = 0;
	uint32_t n, i, k;
	uint64_t declared = 0;
	const char *why = 0;
	uint32_t at = 0;

	if (!ctx->entries) {
		rep->no_table++;
		return 0;
	}
	n = ctx->entries(ctx, &tab);
	if (!n)
		return 0;
	/* Before the first way of failing, so that every failure is also a
	 * check - otherwise a run of nothing but failures reports zero checked
	 * and reads as a run where nothing was tested. */
	rep->checked++;
	if (!tab) {
		why = "a count with no table";
		goto done;
	}

	for (i = 0; i < n; i++) {
		const struct kof_entry *e = &tab[i];
		int seen_zero = 0;

		at = i;
		rep->entries++;

		if (e->flags & ~(uint32_t)(KOF_ENT_F_SCATTERED |
					   KOF_ENT_F_CODED_UNKNOWN)) {
			why = "a flag bit nothing defines";
			goto done;
		}
		if (e->kind >= KOF_ENT_KIND_COUNT) {
			why = "kind outside its enumeration";
			goto done;
		}
		if (e->format >= KOF_FMT_COUNT) {
			why = "format outside its enumeration";
			goto done;
		}

		/*
		 * The ranges, and SCATTERED is the one case where off/len are
		 * not the answer - the contract says a host must not read them
		 * then, so neither does this.
		 */
		if (e->flags & KOF_ENT_F_SCATTERED) {
			if (!ctx->resolve_entry) {
				why = "scattered with no resolve_entry to ask";
				goto done;
			}
		} else {
			if (e->off > obj_size || e->len > obj_size - e->off) {
				why = "range outside the object";
				goto done;
			}
			declared += e->len;
		}

		if (e->name_len) {
			if (e->name_off > obj_size ||
			    e->name_len > obj_size - e->name_off) {
				why = "name range outside the object";
				goto done;
			}
		}

		for (k = 0; k < 4u; k++) {
			if (!e->coding[k]) {
				seen_zero = 1;
				continue;
			}
			if (seen_zero) {
				why = "a coding behind the chain's terminator";
				goto done;
			}
			if (!ec_method_ok(e->coding[k])) {
				why = "a coding that names no method";
				goto done;
			}
		}

		/*
		 * Pairwise, and deliberately not sorted first.
		 *
		 * O(n^2) over a table bounded at 1024 is 500k comparisons in the
		 * worst case and the tables these harnesses produce are tens of
		 * rows; sorting would need a copy of the table, and a copy is
		 * memory proportional to the object, which is what
		 * partition_check.h avoids for the same reason.
		 */
		for (k = 0; k < i; k++) {
			if (tab[k].index == e->index) {
				why = "two entries with one index";
				goto done;
			}
			if ((e->flags & KOF_ENT_F_SCATTERED) ||
			    (tab[k].flags & KOF_ENT_F_SCATTERED))
				continue;
			if (tab[k].off == e->off && tab[k].len == e->len &&
			    e->len) {
				why = "two entries over the same bytes";
				goto done;
			}
		}
	}

	/* The ceiling last, because it is about the table and not a row. */
	if (obj_size && declared > obj_size * 2u) {
		why = "declared bytes over twice the object";
		at = n;
	}
done:
	if (why) {
		rep->failed++;
		if (!rep->quiet)
			printf("  FAIL %s: %s at entry %u of %u (object %llu)\n",
			       what, why, at, n, (unsigned long long)obj_size);
		return 1;
	}
	return 0;
}

#endif /* KOFENG_ENTRY_CHECK_H */
