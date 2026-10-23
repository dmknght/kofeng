/*
 * uncoat / transform_defect - L10 of the lexer audit, through <uncoat.h> alone: kuncoat_transform checked a TRANSLATE step's key as `key_len != 2u * k32`, in 32
 * bits. k32 = 2^31 makes 2u * k32 zero and a key of no bytes passed, 2^31 + 1 with a key of two did the same, and translate_run then read k32 pairs from the key. Not
 * reachable from a script literal (the form passes the pair count of a strtr written in the text) but kuncoat_transform is the library's door. The pair count is
 * checked in 64 bits against the key, and a count that does not fit the key is BAD_ARG.
 *
 * Why the old tests missed it: (b) transform_status.c and hostile_transform.c give translate keys that are too short by a few bytes, never one whose doubled count
 * wraps. (The old code reads the key far past its end here: the handler below says which case did it.)
 *
 * usage: transform_defect
 */

#include <uncoat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#include <signal.h>
#include <unistd.h>

/* what is being asked, so that a fault says which case did it */
static char now[160];

static void on_fault(int sig)
{
	(void)sig;
	if (write(1, now, strlen(now)) < 0)
		_exit(139);
	_exit(139);
}

static enum kuncoat_status translate(uint32_t flags, uint32_t k32, const uint8_t *key, uint32_t key_len, uint64_t *produced)
{
	struct kuncoat_step s;
	uint8_t in[8] = "abcdefg", out[32];

	snprintf(now, sizeof now, "  FAIL (fault, signal) in kuncoat_transform: TRANSLATE flags %u k32 %u key_len %u\n", flags, k32, key_len);
	memset(&s, 0, sizeof s);
	s.algo = KUNCOAT_ALGO_TRANSLATE;
	s.dir = KUNCOAT_DECODE;
	s.flags = flags;
	s.k32 = k32;
	s.key = key;
	s.key_len = key_len;
	return kuncoat_transform(&s, in, 7, out, sizeof out, produced);
}

static void l10(void)
{
	/* a key of 8 bytes on the heap: reading past it is a finding under the sanitiser; without it the answer is the check */
	uint8_t *key = malloc(8);
	uint64_t n;
	uint32_t k, j;

	if (!key)
		abort();
	memcpy(key, "abcdwxyz", 8);
	CK(translate(0, 4, key, 8, &n) == KUNCOAT_OK);                 /* the control: four pairs */
	/* k32 whose double wraps to a key length the caller could plausibly pass: 0 for 2^31, 2 for 2^31 + 1, 4 for 2^31 + 2, 6, 8 */
	for (k = 0; k < 8; k++)
		for (j = 0; j <= 8; j++) {
			enum kuncoat_status st = translate(0, 0x80000000u + k, key, j, &n);

			if (st != KUNCOAT_BAD_ARG) {
				printf("  FAIL translate k32 = 2^31 + %u, key_len %u: status %d (a pair count that does not fit the key is BAD_ARG)\n", k, j, (int)st);
				fails++;
			}
		}
	for (k = 0; k < 8; k++) {
		enum kuncoat_status st = translate(0, 0xfffffffcu + (k & 3u), key, 8, &n);

		CK(st == KUNCOAT_BAD_ARG);
		st = translate(0, 0x40000000u + k, key, 8, &n);
		CK(st == KUNCOAT_BAD_ARG);
	}
	/* the ranges form: k32 is the length of `from`, key_len above it; a count past the key is refused as well */
	CK(translate(KUNCOAT_F_RANGES, 0xffffffffu, key, 8, &n) == KUNCOAT_BAD_ARG);
	CK(translate(KUNCOAT_F_RANGES, 8, key, 8, &n) == KUNCOAT_BAD_ARG);
	free(key);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGSEGV, on_fault);
	signal(SIGBUS, on_fault);
	l10();
	printf(fails ? "transform_defect: %d FAILED\n" : "transform_defect: ok\n", fails);
	return fails != 0;
}
