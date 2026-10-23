/*
 * genome / core_bytes - the byte helpers of kofcore.h that the TEXT route now reads in place of <ctype.h> (which reads the locale), against references written here:
 * kof_lower_byte, kof_upper_byte, kof_is_digit, kof_is_alnum, kof_is_word_byte over all 256 bytes, and kof_hash64_slot (the Fibonacci slot of a 64-bit key).
 * The references are spelled as ranges, not as the helpers' arithmetic, so a wrong constant in either is a difference. The same table is the one the old code's
 * toupper/tolower/isdigit/isalnum gave in the "C" locale, which is the claim of the move: it changes nothing but what a non-C locale did to bytes 0x80..0xff.
 *
 * usage: core_bytes
 */

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include <kofcore.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void)
{
	unsigned c;
	uint64_t k;
	uint32_t seen = 0;

	for (c = 0; c < 256; c++) {
		uint8_t lo = (uint8_t)(c >= 'A' && c <= 'Z' ? c + 32 : c);
		uint8_t up = (uint8_t)(c >= 'a' && c <= 'z' ? c - 32 : c);
		int dg = c >= '0' && c <= '9';
		int al = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

		CK(kof_lower_byte((uint8_t)c) == lo);
		CK(kof_upper_byte((uint8_t)c) == up);
		CK(!!kof_is_digit((uint8_t)c) == dg);
		CK(!!kof_is_alnum((uint8_t)c) == (dg || al));
		CK(!!kof_is_word_byte((uint8_t)c) == (dg || al || c == '_'));
		CK(kof_upper_byte(kof_lower_byte((uint8_t)c)) == (al ? (uint8_t)(c >= 'a' ? c - 32 : c) : (uint8_t)c));
		/* the "C" locale's answer, when this process is in it (it is: nothing here calls setlocale) */
		CK((uint8_t)tolower((int)c) == lo);
		CK((uint8_t)toupper((int)c) == up);
		CK(!!isdigit((int)c) == dg);
		CK(!!isalnum((int)c) == (dg || al));
	}
	/* the slot: the top bits of key * 2^64/phi, 32 of them (G15: 24 left a table of 2^25 slots a half it never hashed into); zero maps to zero, one to the multiplier's bits 32..63, and the low bits of a counter are spread */
	CK(kof_hash64_slot(0) == 0u);
	CK(kof_hash64_slot(1) == (uint32_t)(0x9e3779b97f4a7c15ull >> 32));
	CK(kof_hash64_slot(2) == (uint32_t)((2u * 0x9e3779b97f4a7c15ull) >> 32));
	CK(kof_hash64_slot(0xffffffffffffffffull) == (uint32_t)((0ull - 0x9e3779b97f4a7c15ull) >> 32));
	CK(kof_hash64_slot(1ull << 40) == (uint32_t)((0x9e3779b97f4a7c15ull << 40) >> 32));
	for (k = 1; k <= 4096; k++)
		seen |= 1u << (kof_hash64_slot(k) & 31u);
	CK(seen == 0xffffffffu);        /* consecutive keys reach every one of 32 homes */
	CK(kof_hash64_slot(12345) == (uint32_t)((12345ull * 0x9e3779b97f4a7c15ull) >> 32));
	printf("genome core_bytes: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
