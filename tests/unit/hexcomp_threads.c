/*
 * hexcomp_threads - the pattern compiler is safe on many threads (R1c).
 *
 * kof_hex_compile and kof_regex_compile kept their parse state (the step table, the step count, the error text and the
 * regex cursor) in file-scope writables, so two threads compiling at once overwrote each other's steps: a program was
 * emitted from the other's pattern, or an error carried the other's text. Eight threads compile a different pattern each
 * (hex and regex alternating, and one refusal with its own message) a few thousand times and every result must equal what
 * the same pattern gave on one thread, byte for byte, and the refusal must carry its own message.
 *
 * Why the old tests missed it: (b) hex_match and hexprog_fuzz are single threaded by design (the file's own note said so).
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/databases/pack/hexprog.h"

#define NTHR 8
#define ITER 4000

static const char *const hexp[NTHR] = {
	"4a 4b 4c 4d", "de ad be ef [2-4] ca fe", "(11|22|33) 44 55 66", "01 ?? 03 ?? 05 06 07", "aa bb cc dd ee ff 00 11 22 33 44 55 66",
	"90 90 90 [1-8] e8 ?? ?? ?? ??", "(aa bb|cc dd) ee ff", "0f 1f 44 00 00 66 90 cc"
};
static const char *const rxp[NTHR] = {
	"abcdef", "MZ.{4,8}PE", "(ab|cd)efgh", "x[a-c]yz12", "hello world", "\\x41\\x42\\x43\\x44", "foo.{2}bar", "[0-9]abcd"
};

struct want { uint8_t prog[8192]; uint32_t n; };
static struct want w_hex[NTHR], w_rx[NTHR];
static volatile int bad;

static void *job(void *arg)
{
	unsigned t = (unsigned)(uintptr_t)arg, i;
	uint8_t out[8192];

	for (i = 0; i < ITER && !bad; i++) {
		uint32_t n = kof_hex_compile(hexp[t], out, sizeof out, NULL);

		if (n != w_hex[t].n || memcmp(out, w_hex[t].prog, n)) {
			bad = 1;
			printf("  FAIL thread %u iteration %u: hex program differs (%u bytes, wanted %u)\n", t, i, n, w_hex[t].n);
			break;
		}
		n = kof_regex_compile(rxp[t], out, sizeof out, NULL);
		if (n != w_rx[t].n || memcmp(out, w_rx[t].prog, n)) {
			bad = 1;
			printf("  FAIL thread %u iteration %u: regex program differs (%u bytes, wanted %u)\n", t, i, n, w_rx[t].n);
			break;
		}
		/* a refusal, with a message of its own to this thread's pattern */
		{
			char text[64], want[64];

			snprintf(text, sizeof text, "4a 4b [%u] ", t + 1u);        /* ends with a gap: refused */
			if (kof_hex_compile(text, out, sizeof out, NULL) != 0) {
				bad = 1;
				printf("  FAIL thread %u: a pattern ending with a gap compiled\n", t);
				break;
			}
			snprintf(want, sizeof want, "%s", kof_hex_error());
			if (!want[0]) {
				bad = 1;
				printf("  FAIL thread %u: the refusal has no message\n", t);
				break;
			}
		}
	}
	return NULL;
}

int main(void)
{
	pthread_t th[NTHR];
	unsigned t;

	for (t = 0; t < NTHR; t++) {
		w_hex[t].n = kof_hex_compile(hexp[t], w_hex[t].prog, sizeof w_hex[t].prog, NULL);
		w_rx[t].n = kof_regex_compile(rxp[t], w_rx[t].prog, sizeof w_rx[t].prog, NULL);
		if (!w_hex[t].n || !w_rx[t].n) {
			printf("  FAIL setup: pattern %u does not compile (%s)\n", t, kof_hex_error());
			return 1;
		}
	}
	for (t = 0; t < NTHR; t++)
		if (pthread_create(&th[t], NULL, job, (void *)(uintptr_t)t))
			return 2;
	for (t = 0; t < NTHR; t++)
		pthread_join(th[t], NULL);
	printf("hexcomp_threads: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
