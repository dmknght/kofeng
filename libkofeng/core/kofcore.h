/*
 * kofcore.h - bounded buffer primitives shared by parser, loader and matcher.
 *
 * Internal to libkofeng; signature modules never see this.
 *
 * Every read of untrusted data goes through kof_slice() or the kof_rd_*()
 * helpers. No caller performs pointer arithmetic or its own bounds check.
 * That single rule removes the dominant bug class in binary parsers: an
 * "off + len" that wraps, passes a naive comparison, and reads out of range.
 * The arithmetic here is written so it cannot wrap.
 *
 * The helpers assemble scalars byte by byte rather than casting, so unaligned
 * offsets into an mmap are safe and byte order is explicit at every call.
 */

#ifndef KOFENG_KOFCORE_H
#define KOFENG_KOFCORE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef struct {
	const uint8_t *p;
	uint64_t       n;
} kof_buf;

static inline kof_buf kof_buf_make(const void *p, uint64_t n)
{
	kof_buf b;
	b.p = (const uint8_t *)p;
	b.n = p ? n : 0;
	return b;
}

/*
 * True if [off, off+len) lies inside b. Written as "len <= n - off" after
 * establishing "off <= n", so no addition is performed and nothing can wrap.
 */
static inline int kof_in_range(kof_buf b, uint64_t off, uint64_t len)
{
	if (off > b.n)
		return 0;
	return len <= b.n - off;
}

/* Sub-range, or a zero length buffer if the range is not contained. */
static inline kof_buf kof_slice(kof_buf b, uint64_t off, uint64_t len)
{
	kof_buf out;
	out.p = NULL;
	out.n = 0;
	if (!kof_in_range(b, off, len))
		return out;
	out.p = b.p + off;
	out.n = len;
	return out;
}

/*
 * Scalar reads. Each returns 1 and stores through out on success, or returns 0
 * and leaves out untouched. The caller decides what a failed read means; for a
 * parser it is usually a truncation anomaly rather than a fatal error.
 *
 * be selects big endian when non-zero.
 */

static inline int kof_rd_u8(kof_buf b, uint64_t off, uint8_t *out)
{
	if (!kof_in_range(b, off, 1))
		return 0;
	*out = b.p[off];
	return 1;
}

static inline int kof_rd_u16(kof_buf b, uint64_t off, int be, uint16_t *out)
{
	const uint8_t *q;
	if (!kof_in_range(b, off, 2))
		return 0;
	q = b.p + off;
	/* Assemble in uint32_t and narrow once: a uint16_t sub-expression is
	 * promoted to int by the usual arithmetic conversions, and assigning
	 * that back would be an implicit narrowing the build treats as an
	 * error. Being explicit here keeps the strict flags meaningful. */
	*out = (uint16_t)(be ? (((uint32_t)q[0] << 8) | (uint32_t)q[1])
			     : (((uint32_t)q[1] << 8) | (uint32_t)q[0]));
	return 1;
}

static inline int kof_rd_u32(kof_buf b, uint64_t off, int be, uint32_t *out)
{
	const uint8_t *q;
	if (!kof_in_range(b, off, 4))
		return 0;
	q = b.p + off;
	*out = be ? ((uint32_t)q[0] << 24 | (uint32_t)q[1] << 16 |
		     (uint32_t)q[2] << 8  | (uint32_t)q[3])
		  : ((uint32_t)q[3] << 24 | (uint32_t)q[2] << 16 |
		     (uint32_t)q[1] << 8  | (uint32_t)q[0]);
	return 1;
}

static inline int kof_rd_u64(kof_buf b, uint64_t off, int be, uint64_t *out)
{
	uint32_t lo, hi;
	if (be) {
		if (!kof_rd_u32(b, off, 1, &hi) ||
		    !kof_rd_u32(b, off + 4, 1, &lo))
			return 0;
	} else {
		if (!kof_rd_u32(b, off, 0, &lo) ||
		    !kof_rd_u32(b, off + 4, 0, &hi))
			return 0;
	}
	*out = ((uint64_t)hi << 32) | lo;
	return 1;
}

/*
 * Read an address sized field: 4 bytes for a 32 bit object, 8 for a 64 bit
 * one, widened into a uint64_t. This is the only place class dependence is
 * allowed to appear, which is what lets every layer above be written once.
 */
static inline int kof_rd_addr(kof_buf b, uint64_t off, int is64, int be,
			      uint64_t *out)
{
	if (is64)
		return kof_rd_u64(b, off, be, out);
	{
		uint32_t v;
		if (!kof_rd_u32(b, off, be, &v))
			return 0;
		*out = v;
		return 1;
	}
}

/*
 * CRC32 (reflected, polynomial 0xEDB88320) over a byte range.
 *
 * Bitwise rather than table driven on purpose: the inputs here are blob sized,
 * a few hundred bytes to a few kilobytes, so the table would cost more cache
 * than it saves and would turn a header only helper into another object to link
 * into everything.
 *
 * This is an integrity check against corruption and wrong-file mistakes, not a
 * security boundary. Anything that must resist tampering gets signed instead.
 */
/*
 * Arithmetic on values that came out of a file.
 *
 * Every one of these was written inline several times before it was written once,
 * and the copies were not all the same: the rounding in the database loader could
 * overflow and could divide by zero, while the one in the PE collector could not.
 * Two implementations of one idea is one implementation and one bug waiting for
 * the input that tells them apart.
 */
static inline uint64_t kof_sat_add(uint64_t a, uint64_t b)
{
	return (a > UINT64_MAX - b) ? UINT64_MAX : a + b;
}

/* Round up to a multiple of `a`. An alignment of zero rounds to itself rather
 * than dividing by it, because alignments are read from files too. */
static inline uint64_t kof_round_up(uint64_t v, uint64_t a)
{
	uint64_t r;

	if (a == 0)
		return v;
	r = v % a;
	return r ? kof_sat_add(v, a - r) : v;
}

/*
 * FNV-1a over bytes.
 *
 * Not a checksum and not a security property: it exists so a name can be compared
 * and bucketed without keeping the string, and so a comparison stays right when
 * the stored copy of the name was cut short. Split into a step so a caller reading
 * a NUL terminated name out of a bounded buffer can feed it one byte at a time
 * without first copying it somewhere.
 */
#define KOF_HASH_INIT 2166136261u

static inline uint32_t kof_hash_step(uint32_t h, uint8_t c)
{
	return (h ^ c) * 16777619u;
}

static inline uint32_t kof_hash_bytes(const void *p, uint64_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	uint32_t h = KOF_HASH_INIT;
	uint64_t i;

	for (i = 0; i < n; i++)
		h = kof_hash_step(h, b[i]);
	return h;
}

/*
 * How much of [off, off+len) is inside an object of `size` bytes. Zero if none.
 *
 * Clipping, not rejecting, and that is a decision rather than a convenience: a
 * range is normally computed from header fields, and an expression like
 * "sec->size - 0x40" underflows to something enormous on a small section.
 * Clipping turns that into a wrongly sized range, which a fixture catches;
 * rejecting turns it into a silent no-match, which nothing catches.
 *
 * kof_slice is the other half of the same question and answers it the other way:
 * it refuses a range that is not wholly inside, because a caller asking for a
 * struct wants the struct or nothing. Here the caller wants whatever is there.
 *
 * Saturating, since both arguments may be hostile and their sum may not fit.
 */
static inline uint64_t kof_clip_len(uint64_t size, uint64_t off, uint64_t len)
{
	uint64_t end;

	if (len == 0 || off >= size)
		return 0;
	end = kof_sat_add(off, len);
	if (end > size)
		end = size;
	return end - off;
}

static inline uint32_t kof_crc32(const void *data, uint64_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	uint32_t crc = 0xFFFFFFFFu;
	uint64_t i;
	int k;

	for (i = 0; i < len; i++) {
		crc ^= (uint32_t)p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
	}
	return ~crc;
}

/*
 * strdup, spelled out.
 *
 * POSIX has it and this tree builds as strict ISO C11 - the same reason the loaders use
 * stat() rather than fstat(fileno()).
 */
static inline char *kof_strdup_n(const char *s, uint64_t n)
{
	char *p = malloc((size_t)n + 1);
	if (p) {
		memcpy(p, s, (size_t)n);
		p[n] = 0;
	}
	return p;
}

static inline char *kof_strdup(const char *s)
{
	return kof_strdup_n(s, strlen(s));
}

#endif /* KOFENG_KOFCORE_H */
