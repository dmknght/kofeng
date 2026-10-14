/*
 * executables_private.h - what the normaliser's files share and nobody else reads: the
 * byte tests of the collapse and the probes (wide_char, wide_run, zero_run), what a decode
 * pass writes (struct dec_out) and the three passes themselves, which executables_probe.c
 * runs in "would it write" mode. Not installed, not part of any surface.
 */
#ifndef KOF_EXECUTABLES_PRIVATE_H
#define KOF_EXECUTABLES_PRIVATE_H

#include <stdint.h>
#include <string.h>
#include "executables.h"

/* Printable ASCII, which is what a widened marker is made of. Control bytes are
 * refused: a run of "02 00 03 00" is a table of small integers, and reading it
 * as text is how structure gets rewritten as prose. */
static inline int wide_char(uint8_t lo, uint8_t hi)
{
	/*
	 * ONE RANGE TEST, NOT TWO COMPARES. `lo - 0x20` wraps for anything
	 * below the range, so the single unsigned compare answers both ends;
	 * `&` rather than `&&` keeps it branchless, which matters because this
	 * is read once per byte of every region normalised. Checked against
	 * the original on all 65536 (lo, hi) pairs.
	 */
	return (hi == 0u) & ((uint8_t)(lo - 0x20u) < 0x5fu);
}

/* How many UTF-16LE characters start at `i`, counted in CHARACTERS. */
static inline uint64_t wide_run(const uint8_t *p, uint64_t n, uint64_t i)
{
	uint64_t k = 0;

	while (i + 2u * k + 1u < n && wide_char(p[i + 2u * k], p[i + 2u * k + 1u]))
		k++;
	return k;
}

/* How many zero bytes start at `i`. */
/*
 * A WORD AT A TIME WHILE THERE IS A WORD LEFT.
 *
 * The runs this measures are the zero padding a linker leaves, which is
 * kilobytes at a stretch, and counting them a byte at a time was 456 million
 * instructions - 2.6% of the scan. Eight bytes are all zero exactly when the
 * word holding them is, and that is one compare for eight; the byte loop after
 * it finishes the tail and finds the exact end.
 *
 * Nothing reads a byte's place inside the word, so byte order does not enter
 * into it, and memcpy is how an unaligned 64-bit load is spelled portably.
 */
static inline uint64_t zero_run(const uint8_t *p, uint64_t n, uint64_t i)
{
	uint64_t k = 0;

	while (i + k + 8u <= n) {
		uint64_t w;

		memcpy(&w, p + i + k, sizeof w);
		if (w != 0u)
			break;
		k += 8u;
	}
	while (i + k < n && p[i + k] == 0u)
		k++;
	return k;
}

/*
 * WHAT A DECODE PASS WROTE, AND WHAT IT COULD NOT KEEP.
 *
 * The layered driver walks, each round, only the stretches the round before
 * produced. That list has one entry per decoded payload, so its size follows the
 * OBJECT - a file with a thousand payloads has a thousand entries - and it is
 * grown on demand rather than held to a number somebody picked. The one bound is
 * the allowance below: a table never takes more than the object's own size times
 * four (a payload is at least four bytes out of eight characters in, so no
 * object can fill it), which keeps a hostile size from driving the allocation.
 * When a table cannot grow - the allowance or the allocator says no - the stretch
 * is not remembered, `limit` says so, and the caller reports it: layers under
 * that payload were not looked for.
 *
 * `want` is clear for the single-pass entry points, which have no use for the
 * list and take no memory for it.
 */
struct dec_out {
	struct kof_exe_span *v;
	uint32_t n, cap;
	uint64_t room;          /* bytes this object's tables may take in all */
	uint32_t want;
	uint32_t limit;         /* KOF_EXE_DEC_* that fired */
	/* Set by kof_exe_decode_would_change only: a pass that reaches the point
	 * where it would WRITE answers "yes" instead, and writes nothing. */
	int probe;
};

static inline void dec_out_init(struct dec_out *o, uint64_t n, uint32_t want)
{
	memset(o, 0, sizeof *o);
	o->want = want;
	o->room = 4u * n + 4096u;
}

/* The three decode passes over [from, to) of `p`, in place; `wrote` records what they wrote
 * (NULL for the single-pass entry points). With wrote->probe set a pass answers 1 at the
 * point where it would write, and writes nothing. */
int kof_exe_pass_b64(uint8_t *p, uint64_t n, uint64_t from, uint64_t to, struct dec_out *wrote);
int kof_exe_pass_hex(uint8_t *p, uint64_t n, uint64_t from, uint64_t to, struct dec_out *wrote);
int kof_exe_pass_pct(uint8_t *p, uint64_t n, uint64_t from, uint64_t to, struct dec_out *wrote);

#endif /* KOF_EXECUTABLES_PRIVATE_H */
