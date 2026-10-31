/*
 * catid_oracle.h - an INDEPENDENT computation of the catalog ids, for the tests. It shares nothing with libkofeng/verdictor/catstore.c:
 * the key is built by its own loop, the hash is written out again (FNV-1a 64, then the murmur3 finaliser), the reserved range is
 * moved the way catstore.h says. A test that asks the library for an id and compares it with the library would pass whatever the
 * function was; a test that compares it with THIS cannot.
 *
 *     family  "F:" lower(name)            variant "V:" lower(family) "." lower(letters)        tag  "T:" lower(name)
 */
#ifndef KOF_TEST_CATID_ORACLE_H
#define KOF_TEST_CATID_ORACLE_H

#include <stdint.h>
#include <string.h>

static inline uint64_t oracle_fmix(uint64_t h)
{
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdull;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ull;
	h ^= h >> 33;
	return h;
}

static inline uint64_t oracle_hash(const char *key)
{
	uint64_t h = 14695981039346656037ull;

	for (; *key; key++)
		h = (h ^ (unsigned char)*key) * 1099511628211ull;
	return oracle_fmix(h);
}

/* The reserved range (below 0x10000) is left by a fixed rule. */
static inline uint64_t oracle_valid(uint64_t id)
{
	if (id < 0x10000u)
		id = ((id + 0x9e3779b97f4a7c15ull) * 0xff51afd7ed558ccdull) | 0x8000000000000000ull;
	return id;
}

static inline void oracle_lower(char *out, const char *s)
{
	for (; *s; s++)
		*out++ = *s >= 'A' && *s <= 'Z' ? (char)(*s - 'A' + 'a') : *s;
	*out = 0;
}

static inline uint64_t oracle_family(const char *name)
{
	char key[200] = "F:";

	oracle_lower(key + 2, name);
	return oracle_valid(oracle_hash(key));
}

static inline uint64_t oracle_variant(const char *family, const char *letters)
{
	char key[200] = "V:";
	size_t n;

	oracle_lower(key + 2, family);
	n = strlen(key);
	key[n++] = '.';
	oracle_lower(key + n, letters);
	return oracle_valid(oracle_hash(key));
}

static inline uint64_t oracle_tag(const char *name)
{
	char key[200] = "T:";

	oracle_lower(key + 2, name);
	return oracle_valid(oracle_hash(key));
}

#endif
