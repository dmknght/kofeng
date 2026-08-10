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

/*
 * CRC-32, the usual reflected polynomial, a byte at a time.
 *
 * The bit-at-a-time version this replaces was eight shifts and a branch per byte,
 * and it was the entire cost of loading a database: 9.6ms of a 10.5ms load of a
 * 1.1MB pack, against under 1ms for mapping it, validating four thousand modules
 * and copying every table out of it. Everything the pack format was designed to
 * remove had already been removed; what was left was this loop. It is 1.9ms now.
 *
 * A nibble table was tried first, on the reasoning that 64 bytes fits one cache
 * line and this is an inline function whose table each translation unit gets its
 * own copy of. Measured, it was 3.7ms against 1.9ms for the byte table, and the
 * space it saves is 1KB in the three files that use this - the wrong side of the
 * trade in both directions.
 *
 * Same polynomial, same initial and final inversion, so the values are bit for bit
 * what the old loop produced - verified over every length to 1024 and 200000 random
 * buffers, and against the standard check value below. That is not a detail: the
 * checksum is written into every pack, and a faster CRC that disagreed would reject
 * every database already built.
 *
 * kof_crc32("123456789", 9) == 0xCBF43926
 *
 * An integrity check against corruption and wrong-file mistakes, not a security
 * boundary. Anything that must resist tampering gets signed instead.
 */
static inline uint32_t kof_crc32(const void *data, uint64_t len)
{
	static const uint32_t tab[256] = {
		0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau,
		0x076dc419u, 0x706af48fu, 0xe963a535u, 0x9e6495a3u,
		0x0edb8832u, 0x79dcb8a4u, 0xe0d5e91eu, 0x97d2d988u,
		0x09b64c2bu, 0x7eb17cbdu, 0xe7b82d07u, 0x90bf1d91u,
		0x1db71064u, 0x6ab020f2u, 0xf3b97148u, 0x84be41deu,
		0x1adad47du, 0x6ddde4ebu, 0xf4d4b551u, 0x83d385c7u,
		0x136c9856u, 0x646ba8c0u, 0xfd62f97au, 0x8a65c9ecu,
		0x14015c4fu, 0x63066cd9u, 0xfa0f3d63u, 0x8d080df5u,
		0x3b6e20c8u, 0x4c69105eu, 0xd56041e4u, 0xa2677172u,
		0x3c03e4d1u, 0x4b04d447u, 0xd20d85fdu, 0xa50ab56bu,
		0x35b5a8fau, 0x42b2986cu, 0xdbbbc9d6u, 0xacbcf940u,
		0x32d86ce3u, 0x45df5c75u, 0xdcd60dcfu, 0xabd13d59u,
		0x26d930acu, 0x51de003au, 0xc8d75180u, 0xbfd06116u,
		0x21b4f4b5u, 0x56b3c423u, 0xcfba9599u, 0xb8bda50fu,
		0x2802b89eu, 0x5f058808u, 0xc60cd9b2u, 0xb10be924u,
		0x2f6f7c87u, 0x58684c11u, 0xc1611dabu, 0xb6662d3du,
		0x76dc4190u, 0x01db7106u, 0x98d220bcu, 0xefd5102au,
		0x71b18589u, 0x06b6b51fu, 0x9fbfe4a5u, 0xe8b8d433u,
		0x7807c9a2u, 0x0f00f934u, 0x9609a88eu, 0xe10e9818u,
		0x7f6a0dbbu, 0x086d3d2du, 0x91646c97u, 0xe6635c01u,
		0x6b6b51f4u, 0x1c6c6162u, 0x856530d8u, 0xf262004eu,
		0x6c0695edu, 0x1b01a57bu, 0x8208f4c1u, 0xf50fc457u,
		0x65b0d9c6u, 0x12b7e950u, 0x8bbeb8eau, 0xfcb9887cu,
		0x62dd1ddfu, 0x15da2d49u, 0x8cd37cf3u, 0xfbd44c65u,
		0x4db26158u, 0x3ab551ceu, 0xa3bc0074u, 0xd4bb30e2u,
		0x4adfa541u, 0x3dd895d7u, 0xa4d1c46du, 0xd3d6f4fbu,
		0x4369e96au, 0x346ed9fcu, 0xad678846u, 0xda60b8d0u,
		0x44042d73u, 0x33031de5u, 0xaa0a4c5fu, 0xdd0d7cc9u,
		0x5005713cu, 0x270241aau, 0xbe0b1010u, 0xc90c2086u,
		0x5768b525u, 0x206f85b3u, 0xb966d409u, 0xce61e49fu,
		0x5edef90eu, 0x29d9c998u, 0xb0d09822u, 0xc7d7a8b4u,
		0x59b33d17u, 0x2eb40d81u, 0xb7bd5c3bu, 0xc0ba6cadu,
		0xedb88320u, 0x9abfb3b6u, 0x03b6e20cu, 0x74b1d29au,
		0xead54739u, 0x9dd277afu, 0x04db2615u, 0x73dc1683u,
		0xe3630b12u, 0x94643b84u, 0x0d6d6a3eu, 0x7a6a5aa8u,
		0xe40ecf0bu, 0x9309ff9du, 0x0a00ae27u, 0x7d079eb1u,
		0xf00f9344u, 0x8708a3d2u, 0x1e01f268u, 0x6906c2feu,
		0xf762575du, 0x806567cbu, 0x196c3671u, 0x6e6b06e7u,
		0xfed41b76u, 0x89d32be0u, 0x10da7a5au, 0x67dd4accu,
		0xf9b9df6fu, 0x8ebeeff9u, 0x17b7be43u, 0x60b08ed5u,
		0xd6d6a3e8u, 0xa1d1937eu, 0x38d8c2c4u, 0x4fdff252u,
		0xd1bb67f1u, 0xa6bc5767u, 0x3fb506ddu, 0x48b2364bu,
		0xd80d2bdau, 0xaf0a1b4cu, 0x36034af6u, 0x41047a60u,
		0xdf60efc3u, 0xa867df55u, 0x316e8eefu, 0x4669be79u,
		0xcb61b38cu, 0xbc66831au, 0x256fd2a0u, 0x5268e236u,
		0xcc0c7795u, 0xbb0b4703u, 0x220216b9u, 0x5505262fu,
		0xc5ba3bbeu, 0xb2bd0b28u, 0x2bb45a92u, 0x5cb36a04u,
		0xc2d7ffa7u, 0xb5d0cf31u, 0x2cd99e8bu, 0x5bdeae1du,
		0x9b64c2b0u, 0xec63f226u, 0x756aa39cu, 0x026d930au,
		0x9c0906a9u, 0xeb0e363fu, 0x72076785u, 0x05005713u,
		0x95bf4a82u, 0xe2b87a14u, 0x7bb12baeu, 0x0cb61b38u,
		0x92d28e9bu, 0xe5d5be0du, 0x7cdcefb7u, 0x0bdbdf21u,
		0x86d3d2d4u, 0xf1d4e242u, 0x68ddb3f8u, 0x1fda836eu,
		0x81be16cdu, 0xf6b9265bu, 0x6fb077e1u, 0x18b74777u,
		0x88085ae6u, 0xff0f6a70u, 0x66063bcau, 0x11010b5cu,
		0x8f659effu, 0xf862ae69u, 0x616bffd3u, 0x166ccf45u,
		0xa00ae278u, 0xd70dd2eeu, 0x4e048354u, 0x3903b3c2u,
		0xa7672661u, 0xd06016f7u, 0x4969474du, 0x3e6e77dbu,
		0xaed16a4au, 0xd9d65adcu, 0x40df0b66u, 0x37d83bf0u,
		0xa9bcae53u, 0xdebb9ec5u, 0x47b2cf7fu, 0x30b5ffe9u,
		0xbdbdf21cu, 0xcabac28au, 0x53b39330u, 0x24b4a3a6u,
		0xbad03605u, 0xcdd70693u, 0x54de5729u, 0x23d967bfu,
		0xb3667a2eu, 0xc4614ab8u, 0x5d681b02u, 0x2a6f2b94u,
		0xb40bbe37u, 0xc30c8ea1u, 0x5a05df1bu, 0x2d02ef8du
	};
	const uint8_t *p = (const uint8_t *)data;
	uint32_t crc = 0xFFFFFFFFu;
	uint64_t i;

	for (i = 0; i < len; i++)
		crc = (crc >> 8) ^ tab[(crc ^ p[i]) & 0xffu];
	return ~crc;
}

/*
 * strdup with an explicit length, spelled out.
 *
 * POSIX has strdup and this tree builds as strict ISO C11 - the same reason the
 * loaders use stat() rather than fstat(fileno()). The length is explicit because
 * every caller already has it and the alternative was a second wrapper that only
 * called strlen.
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


#endif /* KOFENG_KOFCORE_H */
