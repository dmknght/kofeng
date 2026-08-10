/*
 * hexprog.h - a compiled hex pattern.
 *
 * The encoding of a hex string once the build has parsed it: what the signature
 * compiler writes into the pack's string pool and what the matcher walks. It is not
 * part of the pack container - kofpack.h owns that - it is the content of one pool
 * entry whose descriptor says KOF_STR_HEX.
 *
 * Both sides consult this file rather than each other, for the same reason the pack
 * layout is stated once: a writer and a reader that agree by inspection eventually
 * do not.
 *
 *
 * THE MODEL
 *
 * A pattern is a sequence of STEPS separated by GAPS. A step is a set of
 * ALTERNATIVES, each a fixed-length run of bytes with an optional mask.
 *
 *     { E8 ?? ?? ?? ?? 5D C3 }        one step, seven bytes, four masked
 *     { 6A 40 [4-6] 8D 4D }           two steps, gap 4..6 between them
 *     { ( E8 | E9 ) ?? ?? ?? ?? }     two steps, the first with two alternatives
 *
 * That covers the whole of the syntax worth having: a wildcard is a mask, a nibble
 * wildcard is a mask, a jump is a gap, and an opcode variant is an alternative.
 *
 * What it deliberately does not cover is a gap inside an alternative -
 * "( E8 [2-4] 2A | E9 )". The compiler refuses it with a message rather than
 * accepting it, because supporting it means an alternative no longer has a length,
 * which is what makes the walk below bounded.
 *
 *
 * WHY NOT BACKTRACKING
 *
 * The obvious matcher recurses: at each step, for each gap offset, for each
 * alternative, try the rest. With eight steps, an eight-wide gap and two
 * alternatives that is 16^8 paths in the worst case, reachable from a pattern a
 * researcher could write by accident - and it would be reached on a file an
 * attacker chose.
 *
 * So the walk carries a SET of reachable positions instead. After each step the set
 * is deduplicated, so two paths that arrive at the same offset stop being two paths.
 * Work becomes the sum over steps of (positions x gap span x alternatives) rather
 * than their product, which is the same reason a Thompson simulation beats
 * backtracking on a regex.
 *
 * The caps below then bound that sum by construction, at build time, so the matcher
 * needs no runtime budget of its own to be safe.
 *
 *
 * THE ANCHOR
 *
 * Searching means finding candidate positions, and a masked pattern gives nothing to
 * search for. So the compiler picks the longest run of concrete bytes in the pattern
 * and records where it is: the matcher searches for that run with the same
 * memchr-driven code a literal uses, then verifies the rest around each hit.
 *
 * The distance from a match's start to the run is a WINDOW, not a number: a gap or
 * an alternation of unequal lengths before the anchor makes it vary. So the matcher
 * finds the run and tries each start the window allows. That window is bounded by
 * the same gap cap as everything else, and is exactly one position wide for the
 * common pattern whose concrete bytes are at the front.
 *
 * anchor_len is also what decides whether the presence set can help. It keys on four
 * bytes, so a run of four or more can be looked up there and a whole pattern ruled
 * out for an object without touching it. A shorter run means the pattern is searched
 * on every object of the right format, forever, which is why the compiler prints the
 * anchor length rather than leaving it to be discovered from a profile.
 *
 * A pattern with no concrete byte at all is refused. It matches everything.
 */

#ifndef KOFENG_HEXPROG_H
#define KOFENG_HEXPROG_H

#include <stdint.h>

/*
 * Caps, enforced by the compiler so the matcher can trust them.
 *
 * These are the whole of the DoS story for hex patterns: a bound checked once at
 * build time costs nothing per object, where the same bound checked per match would
 * cost a comparison in the innermost loop. The numbers are chosen to be far above
 * what a readable pattern uses - real ones run to two or three steps and a gap of a
 * few bytes - and far below what would make the walk expensive.
 *
 * KOF_HEX_MAX_GAP_TOTAL is the sum over the pattern, not the limit on one gap. One
 * gap of 256 and four gaps of 64 cost the same, and only the total appears in the
 * work bound.
 */
#define KOF_HEX_MAX_STEPS     8u
#define KOF_HEX_MAX_ALTS      8u    /* per step */
#define KOF_HEX_MAX_ALT_LEN   256u  /* bytes in one alternative */
#define KOF_HEX_MAX_GAP_TOTAL 256u  /* summed (gap_max - gap_min) over the pattern */
#define KOF_HEX_MAX_REACH     512u  /* positions carried between steps */

/* The whole compiled program: header, two tables and the bytes. Not comparable
 * with a literal's length, which is why a pool entry is capped by its kind. */
#define KOF_HEX_MAX_PROG      8192u

/* A program is read as a struct out of the pool, never copied out of it, so its
 * offset has to carry the alignment those structs need. */
#define KOF_HEX_PROG_ALIGN    4u

/* An unbounded jump - "[4-]" or "[-]" - compiles to this rather than to infinity.
 * A pattern whose parts may be arbitrarily far apart is not a pattern, it is two
 * patterns and a kof_find_str_all. */
#define KOF_HEX_GAP_OPEN      256u

/*
 * The header of a compiled program, at offset 0 of the pool entry.
 *
 * Offsets inside are from the start of the program, not from the pool, so a program
 * can be relocated by copying it - which is what the loader does.
 */
struct kof_hex_hdr {
	uint16_t n_steps;
	uint16_t n_alts;        /* total across every step */

	/* Shortest and longest a match can be. min_span is what lets a compare at a
	 * fixed offset be refused in one comparison when the object is too short. */
	uint32_t min_span;
	uint32_t max_span;

	/* Where the concrete run is: which step, which byte within its (single)
	 * alternative, and how long. anchor_len == 0 never happens - the compiler
	 * refuses a pattern with no concrete byte - but the matcher checks anyway,
	 * because it reads this out of a file.
	 *
	 * anchor_in_alt is stored rather than derived. Deriving it means subtracting
	 * a prefix length the matcher would have to recompute, and a malformed pack
	 * could make that subtraction underflow into a read outside the program. One
	 * more field costs four bytes and removes the arithmetic entirely. */
	uint32_t anchor_step;
	uint32_t anchor_before_min;  /* least bytes between a match start and the run */
	uint32_t anchor_before_max;  /* most; equal to the least when nothing varies */
	uint32_t anchor_in_alt;      /* bytes from the start of that step's alternative */
	uint32_t anchor_len;

	uint32_t steps_off;     /* struct kof_hex_step x n_steps */
	uint32_t alts_off;      /* struct kof_hex_alt  x n_alts  */
	uint32_t data_off;      /* the byte and mask area */
	uint32_t total_len;     /* the whole program, for validation */
};

/* The gap is the one BEFORE this step; step 0 always has 0..0. Keeping it on the
 * step rather than between steps means the walk reads one record per iteration. */
struct kof_hex_step {
	uint16_t gap_min, gap_max;
	uint16_t alt_first, n_alts;   /* a slice of the alternative table */
};

/*
 * One alternative: `len` bytes at data_off, followed by `len` mask bytes if
 * KOF_HEX_ALT_MASKED is set.
 *
 * A mask of 0xff on every byte would be equivalent and simpler, and is not used: the
 * unmasked case is a memcmp the compiler vectorises, and it is the overwhelmingly
 * common one. Paying a mask load per byte to avoid one flag would slow every plain
 * hex pattern to make one rare kind marginally simpler.
 */
#define KOF_HEX_ALT_MASKED 1u

struct kof_hex_alt {
	uint16_t len;
	uint16_t flags;
	uint32_t data_off;
};

/* What compiling produced, for a build tool to report. The anchor length is the
 * one a researcher acts on: below four the presence set cannot speak for the
 * pattern and it is searched on every object of its format. */
struct kof_hex_stat {
	uint32_t len;
	uint32_t n_steps, n_alts;
	uint32_t min_span, max_span;
	uint32_t anchor_len;
};

/*
 * Compile hex text. Returns the program length written to `out`, or 0 with
 * kof_hex_error() describing the first thing that was wrong.
 *
 * In the library rather than in the build tool because the compiler, the loader's
 * validator and the matcher are three views of one encoding. Nothing on the scan
 * path calls it, so a static link never pulls it into a scanner.
 */
uint32_t    kof_hex_compile(const char *text, uint8_t *out, uint32_t cap,
			    struct kof_hex_stat *stat);
const char *kof_hex_error(void);

_Static_assert(sizeof(struct kof_hex_hdr)  == 48, "hex header changed size");
_Static_assert(sizeof(struct kof_hex_step) == 8,  "hex step grew padding");
_Static_assert(sizeof(struct kof_hex_alt)  == 8,  "hex alternative grew padding");

#endif /* KOFENG_HEXPROG_H */
