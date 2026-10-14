/*
 * kofmultimatch.h - what a marker is to the region sweep: which markers can be keyed, the key
 * a position hashes to, where a hex marker's concrete run sits, and the verification of a
 * candidate. The table that FINDS candidates is kofpix.h; this is the half that DECIDES one.
 *
 * WHY THIS FILE IS SMALL NOW. It used to hold five table shapes (4-gram chain, Wu-Manber, bisect,
 * rekey, and the router that picked among them), all built at load from every marker of the
 * database: 484 bytes a rule, 4e6 rules = 1.85 GB of heap, plus a word a marker for every scanner.
 * The engine's cap is 512 MiB for everything, so the pattern side alone spent it at about a million
 * rules. They are gone, replaced by kofpix.h (a table that stays in the pack and answers the same
 * question with the same verification), and what was kept is what both would have had to say the
 * same way: a candidate one table accepts and another refuses would be a detection that depends on
 * how big the database is.
 *
 * WHAT THE LAZY PATH IS. Nothing is swept and the module's own calls search, one marker per call,
 * exactly as before any of this existed. It is the answer for a region with too few live markers
 * to pay for a pass (KOF_MULTIMATCH_MIN_LIVE), for a marker that cannot be keyed (shorter than
 * the key; a hex program whose concrete run is shorter than KOF_MULTIMATCH_HEX_MIN), for any mask
 * naming the symbol halves (those bytes are not the object's and a second matcher searches them),
 * and for a region the sweep could not finish (a read bound, a truncated pack: reported).
 *
 * MEASURED, AND NOT TO BE REDONE (the harness that produced these is gone; the numbers are from
 * the tables this replaced, 14300 region rows over clean /usr, three malware corpora and synthetic
 * sets to a million markers):
 *
 *   K < 8 live markers: a per-marker search beats any pass (PE was K=2 and K=3: by 151% and 222%).
 *   A presence filter in front of a chain lowers the line and never the slope: the per-marker
 *   path, a 24-bit stamp table and a bitset sized to the object are all LINEAR in the marker
 *   count (33/294/2938/14614 ms at 116/1k/10k/50k markers, against 5.3/5.5/7.5/17.2 for a gram
 *   table). A filter cannot flatten a curve, only lower it.
 *   Predicting cost from table occupancy: not correlated (measured 9.4% occupancy against a 33.6%
 *   admit rate; a crafted file had 0.0% occupancy and a 100% admit rate): markers are ASCII and
 *   real binaries are full of ASCII.
 *   Routing on the file's name or on what the file looks like: +253% / +442% against a
 *   per-region oracle; the crossover is invariant in size from 64 KB to 6.3 MB and in content.
 *   Aho-Corasick: flat in time and LINEAR IN RAM (1.2 MB at 116 markers, 106 MB at 10k, 17.7 GB
 *   projected at a million).
 *   Case folding with a per-byte test in the inner loop: three times slower (410 MB/s against
 *   1.17 GB/s), so the cost was the branch; kof_mm_swar_lower below folds four bytes at once.
 *   Markers sharing a four-byte head in a file full of those bytes made the chain walk quadratic
 *   (1157750 ms per MB at a million markers); kofpix.h bounds it (a read bound, reported) and
 *   keys each marker on the four bytes the fewest others contain.
 *
 * Private to detectors/pattern/ and the scanner's one sweep driver; not a module-facing header.
 */

#ifndef KOFENG_KOFMULTIMATCH_H
#define KOFENG_KOFMULTIMATCH_H

#include <stdint.h>
#include <kofmod/kofsig.h>   /* struct kof_range */
#include "../../kofcore/kofcore.h"
#include "kofmatch.h"

/* K below this many live markers on a region: per-marker search (measured above). */
#define KOF_MULTIMATCH_MIN_LIVE   8u

/* Key width: the four bytes a position hashes. The width the measurements were taken at. */
#define KOF_MULTIMATCH_KEY        4u

/*
 * HOW LONG A HEX ANCHOR HAS TO BE BEFORE IT IS WORTH BATCHING.
 *
 * A key hit is only a claim about the first KOF_MULTIMATCH_KEY bytes; what rejects the rest is the
 * compare of the whole anchor before the walk. An anchor exactly as long as the key rejects NOTHING -
 * every hit runs a walk - and a short run of code bytes is common by construction. bases/ had one:
 * `48 85 F6 75`, which is `test rsi,rsi; jne` and appears all over any x86-64 text section.
 *
 * THIS IS A GUARD, NOT A MEASURED WIN. On the shipping base the threshold changes nothing that can be
 * told from noise (4, 6 and 8 all reported the identical 10322 searches). What justifies it is the
 * shape: a key with no verify behind it is the `prefix` case, which went quadratic. Eight is the
 * smallest length at which the compare is doing real work; below it the lazy path's memmem skip does
 * the rejecting instead, which is what it is good at.
 */
#define KOF_MULTIMATCH_HEX_MIN    8u

/*
 * Region bits live in the low half of a mask word; KOF_SCAN_ALL is bit 0 and the two symbol halves
 * are bits 30 and 31, which a sweep never takes because those bytes are not the object's.
 */
#define KOF_MULTIMATCH_BITS       30u

/* The multiplier every key is hashed with. Bijective on 32 bits, so a hash is a lossless name for
 * the four bytes it came from. */
#define KOF_MM_MUL 2654435761u

/*
 * Case folding, four bytes at a time and without a branch. Per byte b, adding 0x7f-'A'+1 sets bit 7
 * when b >= 'A' and adding 0x7f-'Z' sets it when b > 'Z'; the difference is exactly [A-Z], and
 * 0x80 >> 2 is the 0x20 that lowercases it. Requiring the original high bit clear leaves everything
 * above ASCII alone.
 */
static inline uint32_t kof_mm_swar_lower(uint32_t v)
{
	uint32_t c  = v & 0x7f7f7f7fu;
	uint32_t ge = c + 0x3f3f3f3fu;
	uint32_t gt = c + 0x25252525u;

	return v | ((ge & ~gt & ~v & 0x80808080u) >> 2);
}

/*
 * One marker as the verification sees it.
 *
 * A literal is its own bytes. A hex program is its ANCHOR RUN - the table finds that, and `prog` is
 * what finishes the job.
 */
struct kof_multimatch_pat {
	const uint8_t *b;        /* literal: the bytes. hex: the anchor run */
	uint16_t       len;      /* literal: its length. hex: anchor_len */
	uint8_t        flags;    /* KOF_STR_ICASE | KOF_STR_FULLWORD; zero for hex */
	uint8_t        is_hex;

	/*
	 * Where a match may BEGIN, relative to a hit on the anchor run. A window and not a point: a gap
	 * or an alternation of unequal lengths ahead of the anchor makes the distance vary. The loader
	 * bounds the width, so the walk this drives cannot be entered an unbounded number of times per hit.
	 */
	const uint8_t *prog;     /* hex only: the compiled program */
	uint32_t       before_min, before_max;
	uint32_t       min_span; /* shortest a match can be, for a cheap reject */

	uint32_t       uid;      /* database-wide marker id */
};

/*
 * Can a marker of this kind and size be keyed at all? A literal needs the key's four bytes; a hex
 * program needs a concrete run of KOF_MULTIMATCH_HEX_MIN, which is read out of the program header
 * (so `bytes` must hold the whole program, VALIDATED by kof_hex_prog_valid, and `len` is its
 * length). Not keyable means left to the lazy path.
 */
int kof_multimatch_keyable(uint8_t kind, uint32_t len, const uint8_t *bytes);

/* The concrete run a hex program is keyed on, and how long it is. The program has been through
 * kof_hex_prog_valid; this does not check it again. */
const uint8_t *kof_multimatch_hex_anchor(const uint8_t *prog, uint32_t *len);

/*
 * Is the marker at `at` inside [base, base+span) of the object. For a hex marker `p->b` is the
 * anchor run and `at` is where the run sits. THE verification of a candidate, whichever table found
 * it.
 */
int kof_multimatch_pat_at(const struct kof_match_ctx *m,
			  const struct kof_multimatch_pat *p,
			  uint64_t at, uint64_t base, uint64_t span);

#endif /* KOFENG_KOFMULTIMATCH_H */
