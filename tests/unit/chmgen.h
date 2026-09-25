/*
 * chmgen.h - building a CHM directory entry, for the tests that need one.
 *
 * Two tests construct the same synthetic CHM, one to walk it and one to check
 * what comes out as objects, and both had their own copy of the encoder.
 */

#ifndef KOFENG_TESTS_CHMGEN_H
#define KOFENG_TESTS_CHMGEN_H

#include <stdint.h>
#include <string.h>

/*
 * CHM's variable-length integer: seven bits a byte, MOST significant group
 * first, with the top bit set on every byte but the last. Five bytes is the
 * cap because that is what thirty two bits needs and what the format uses.
 */
static uint32_t enc(uint8_t *p, uint64_t v)
{
	uint8_t tmp[5];
	uint32_t n = 0, i;

	do {
		tmp[n++] = (uint8_t)(v & 0x7fu);
		v >>= 7;
	} while (v && n < 5u);
	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(tmp[n - 1u - i] | (i + 1u < n ? 0x80u : 0u));
	return n;
}

/* One directory entry: name length, name, then section, offset and length. */
static uint32_t put_entry(uint8_t *p, const char *name, uint64_t sect,
			  uint64_t off, uint64_t len)
{
	uint32_t n = 0;
	size_t nl = strlen(name);

	n += enc(p + n, nl);
	memcpy(p + n, name, nl);
	n += (uint32_t)nl;
	n += enc(p + n, sect);
	n += enc(p + n, off);
	n += enc(p + n, len);
	return n;
}

#endif /* KOFENG_TESTS_CHMGEN_H */
