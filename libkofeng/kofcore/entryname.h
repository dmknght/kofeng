/*
 * entryname.h - what an archive calls the things inside it.
 *
 * One question, asked by every archive format and answered the same way in each:
 * does this name escape the directory it will be extracted into? It lives here
 * rather than in a parser because it is not about a format - it is about what a
 * name means to whatever will act on it - and because it was written twice, once in
 * the zip parser and once in the tar parser, identically. Two copies of a security
 * check are two things to fix when the check turns out to be wrong.
 */

#ifndef KOFENG_ENTRYNAME_H
#define KOFENG_ENTRYNAME_H

#include <stdint.h>
#include "../core/kofcore.h"

/*
 * Does this name escape the directory it will be extracted into?
 *
 * Three ways, and all three are seen in the wild: an absolute path, a Windows
 * drive letter, and a ".." component.
 *
 * The last is checked as a COMPONENT rather than as a substring, because a file
 * honestly called "..config" contains ".." and escapes nothing - matching the
 * substring would make this fire on ordinary archives, and a warning that fires on
 * ordinary archives stops being read.
 *
 * Backslash counts as a separator as well as slash. The specification says names
 * use forward slashes, which is exactly why an attacker uses the other one: a
 * checker that only knows about "/" is bypassed by a name Windows still splits.
 *
 * This decides what to REPORT. Nothing in this engine extracts to a path - the
 * objects it produces have no filename at all - so a name that escapes is evidence
 * about the archive rather than a danger to the scanner.
 */
static inline int kof_name_escapes(kof_buf f, uint64_t off, uint32_t len)
{
	uint32_t i, start = 0;

	if (!len || !kof_in_range(f, off, len))
		return 0;
	if (f.p[off] == '/' || f.p[off] == '\\')
		return 1;
	if (len >= 2 && f.p[off + 1] == ':')
		return 1;

	for (i = 0; i <= len; i++) {
		int sep = (i == len) || f.p[off + i] == '/' || f.p[off + i] == '\\';

		if (!sep)
			continue;
		if (i - start == 2 && f.p[off + start] == '.' &&
		    f.p[off + start + 1] == '.')
			return 1;
		start = i + 1;
	}
	return 0;
}

#endif /* KOFENG_ENTRYNAME_H */
