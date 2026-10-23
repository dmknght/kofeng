#ifndef KOFSTRLIST_H
#define KOFSTRLIST_H

/*
 * kofstrlist.h - a LIST OF STRINGS in one buffer, the form kuncoat's SPLIT writes and its JOIN reads (libuncoat/decoders/strfn.c), and the one the script
 * evaluator keeps a list of values in (libgenome/phenotype/diag_text_eval_ops.c). It lives in core because both libs use it and neither may call the other: the
 * layout is written once, here.
 *
 * Each element is its length as 4 bytes, little endian, then its bytes. An empty buffer is the empty list; an element of no bytes is 4 bytes of zero. Nothing
 * here interprets an element - it is bookkeeping of where one ends.
 */

#include <stdint.h>
#include <string.h>

/* Room an element of `n` bytes takes. */
static inline uint64_t kof_strlist_size(uint32_t n)
{
	return 4u + (uint64_t)n;
}

/* Write one element at buf[*w] (the caller has checked kof_strlist_size(n) against its room). */
static inline void kof_strlist_put(uint8_t *buf, uint64_t *w, const uint8_t *p, uint32_t n)
{
	buf[*w] = (uint8_t)n;
	buf[*w + 1u] = (uint8_t)(n >> 8);
	buf[*w + 2u] = (uint8_t)(n >> 16);
	buf[*w + 3u] = (uint8_t)(n >> 24);
	if (n)
		memmove(buf + *w + 4u, p, n);   /* not memcpy: a caller that runs a step with `out` == `in` (tests/lib/uncoat/hostile_transform.c) gets a garbled list, never an overlapping copy */
	*w += 4u + (uint64_t)n;
}

/* The element at buf[*at] of a list `len` bytes long: 1 with its bytes and length and `*at` past it, 0 at the end or when the framing is broken (`*broken` set then). */
static inline int kof_strlist_next(const uint8_t *buf, uint64_t len, uint64_t *at, const uint8_t **p, uint32_t *n, int *broken)
{
	uint32_t l;

	if (*at >= len)
		return 0;
	if (len - *at < 4u) {
		*broken = 1;
		return 0;
	}
	l = (uint32_t)buf[*at] | (uint32_t)buf[*at + 1u] << 8 | (uint32_t)buf[*at + 2u] << 16 | (uint32_t)buf[*at + 3u] << 24;
	if (len - *at - 4u < l) {
		*broken = 1;
		return 0;
	}
	*p = buf + *at + 4u;
	*n = l;
	*at += 4u + (uint64_t)l;
	return 1;
}

#endif /* KOFSTRLIST_H */
