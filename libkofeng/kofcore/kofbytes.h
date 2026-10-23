#ifndef KOFBYTES_H
#define KOFBYTES_H

/*
 * kofbytes.h - three questions about a run of bytes that a CALLER asks before it hands the bytes to an op, shared because kgenome (which decides whether a call on constants
 * is the function the language means) may not call kuncoat (which runs the op): is a byte of a set in it, is a byte in it twice, is it all ASCII. They transform nothing; the
 * answer is a refusal. The ops themselves - replace, translate, trim, split, join, repeat - are libuncoat's (libuncoat/decoders/strfn.c).
 */

#include <stdint.h>
#include <string.h>

/* Does p[0..n) hold a byte of the NUL-ended `set`? A NULL or empty set holds none. */
static inline int kof_bytes_has_any(const uint8_t *p, uint32_t n, const char *set)
{
	uint32_t i, sn = set ? (uint32_t)strlen(set) : 0u;

	if (!sn)
		return 0;
	for (i = 0; i < n; i++)
		if (memchr(set, p[i], sn))
			return 1;
	return 0;
}

/* Does p[0..n) hold the same byte twice? */
static inline int kof_bytes_has_twice(const uint8_t *p, uint32_t n)
{
	uint8_t seen[32] = { 0 };
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (seen[p[i] >> 3] >> (p[i] & 7u) & 1u)
			return 1;
		seen[p[i] >> 3] = (uint8_t)(seen[p[i] >> 3] | (1u << (p[i] & 7u)));
	}
	return 0;
}

/* Is every byte of p[0..n) below 0x80? */
static inline int kof_bytes_ascii(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (p[i] >= 0x80u)
			return 0;
	return 1;
}

/* Could an UNQUOTED expansion of this value be one word the shell hands on as it is: not empty, no byte of the default field separators (blank, tab, line break), no glob
 * character, no tilde at the front? What the shell does with an expansion outside quotes (it splits it and matches the pieces against files) is no constant. */
static inline int kof_bytes_plain_word(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	if (!n || p[0] == '~')
		return 0;
	for (i = 0; i < n; i++)
		if (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '*' || p[i] == '?' || p[i] == '[')
			return 0;
	return 1;
}

/* Does the value begin or end with white space (space, tab, line break, CR, VT, FF), or is it empty? tcl's concat trims every word and drops an empty one. */
static inline int kof_bytes_edge_blank(const uint8_t *p, uint32_t n)
{
	if (!n)
		return 1;
	return p[0] == ' ' || (p[0] >= '\t' && p[0] <= '\r') || p[n - 1u] == ' ' || (p[n - 1u] >= '\t' && p[n - 1u] <= '\r');
}

/* Is the value an option word made of the letters of `ok` after a "-" (echo -n, -nn)? 1 for one, -1 when it is a "-" and letters of `bad` (echo -e reads backslashes: the value
 * is not what it seems), 0 when it is not an option cluster of those letters at all. */
static inline int kof_bytes_option(const uint8_t *p, uint32_t n, const char *ok, const char *bad)
{
	uint32_t i;
	int has_bad = 0;

	if (n < 2u || p[0] != '-')
		return 0;
	for (i = 1; i < n; i++) {
		if (memchr(ok, p[i], strlen(ok)))
			continue;
		if (memchr(bad, p[i], strlen(bad)))
			has_bad = 1;
		else
			return 0;
	}
	return has_bad ? -1 : 1;
}

#endif /* KOFBYTES_H */
