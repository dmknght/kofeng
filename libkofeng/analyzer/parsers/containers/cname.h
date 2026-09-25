/*
 * cname.h - what an archive member's NAME says about where it wanted to go.
 *
 * Four container parsers ask this and three of them asked it with byte-for-byte
 * the same function under three names. It is not a refusal - nothing here
 * extracts an archive - it is a FACT recorded about what the file was built to
 * do, which is why every one of them records it and none of them acts on it.
 */

#ifndef KOFENG_CONTAINERS_CNAME_H
#define KOFENG_CONTAINERS_CNAME_H

#include <stdint.h>

#include <kofcore.h>

/*
 * The length of a NUL-terminated name at `at`, INCLUDING its terminator, or 0.
 *
 * Zero for both failures a parser must treat alike: a byte that could not be
 * read, and `cap` bytes with no terminator among them. Neither is a name, and a
 * caller that told them apart would be reporting on its own read rather than on
 * the file.
 */
static inline uint32_t kof_cname_len(kof_buf f, uint64_t at, uint32_t cap)
{
	uint32_t i;

	for (i = 0; i < cap; i++) {
		uint8_t b;

		if (!kof_rd_u8(f, at + i, &b))
			return 0;
		if (!b)
			return i + 1u;      /* including the terminator */
	}
	return 0;
}

/*
 * Does the name at [at, at+len) try to leave the directory it is unpacked into?
 *
 * Two shapes count. A ".." anywhere, which walks up wherever it lands; and an
 * ABSOLUTE start - a leading slash or backslash, or a drive letter in the
 * second byte - which ignores the destination altogether.
 *
 * A byte this cannot read ends the walk with "no", because a name that runs off
 * the end of the file is a truncated header rather than a hostile one, and the
 * parser that handed the range in is the one that reports that.
 *
 * chm_parse.c asks the same question with a stricter test of the drive letter
 * and a clamp of its own, and keeps its own copy for that reason - see the note
 * there.
 */
static inline int kof_cname_traversal(kof_buf f, uint64_t at, uint32_t len)
{
	uint32_t i;

	for (i = 0; i + 1u < len; i++) {
		uint8_t a, b;

		if (!kof_rd_u8(f, at + i, &a) || !kof_rd_u8(f, at + i + 1u, &b))
			return 0;
		if (a == '.' && b == '.')
			return 1;
		if (i == 0 && (a == '\\' || a == '/' || b == ':'))
			return 1;
	}
	return 0;
}

#endif /* KOFENG_CONTAINERS_CNAME_H */
