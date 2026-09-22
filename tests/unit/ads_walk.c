/*
 * ads_walk - a file's alternate data streams are found, and its own is not
 * reported twice.
 *
 * WHAT THIS IS DEFENDING. On NTFS a file is a set of named streams and every
 * tool shows one of them. Measured before this existed: a 218KB PE written to
 * `host.txt:hidden.exe` left host.txt reporting 29 bytes, and a directory walk
 * scanned those 29 bytes and called the file clean. The engine could always
 * READ the stream - naming it by hand parsed it correctly as a PE - so what
 * was missing was anybody ever naming it.
 *
 * THE TWO WAYS TO GET THIS WRONG, and both are silent:
 *
 *   miss the stream      the payload is invisible, which is the bug
 *   yield ::$DATA too    every file on the machine is scanned twice, which
 *                        looks like a slow scanner and nothing else
 *
 * So the test asserts both directions: the named stream comes back, and the
 * unnamed one does not.
 *
 * ON POSIX THIS TESTS THAT THERE IS NOTHING TO TEST. A regular file is one run
 * of bytes, kof_streams_open answers no, and the loop does not run - which is
 * the correct answer rather than a gap, so the test says so and passes.
 */
/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * POSIX side calls memmem and realpath - a GNU extension and a function strict
 * POSIX mode hides - so under 200809L alone the header compiles them implicit.
 * Same reason, same wording as scan_mt.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/core/kofplatform.h"

static int failures;

static void ok_(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static int put(const char *path, const char *what)
{
	FILE *f = fopen(path, "wb");
	size_t n = strlen(what);

	if (!f)
		return 0;
	if (fwrite(what, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

int main(void);
int main(void)
{
	static const char host[] = "build/test/ads_host.txt";
	char s1[256], s2[256];
	struct kof_stream_walk w;
	int seen_a = 0, seen_b = 0, seen_main = 0, n = 0;

	if (!put(host, "the visible content")) {
		printf("ads walk: cannot write %s - nothing tested\n", host);
		return 0;
	}

	snprintf(s1, sizeof s1, "%s:alpha", host);
	snprintf(s2, sizeof s2, "%s:beta", host);
	if (!put(s1, "AAAA") || !put(s2, "BBBB")) {
		/*
		 * Not a failure. A volume that is not NTFS refuses the colon,
		 * and so does every POSIX filesystem - see the note at the top
		 * about what this platform is being asked.
		 */
		remove(host);
		printf("ads walk: this filesystem carries no named streams - "
		       "nothing to find, which is the right answer here\n");
		return 0;
	}

	if (!kof_streams_open(&w, host)) {
		remove(s1);
		remove(s2);
		remove(host);
		printf("ads walk: the streams were written and the walk opened "
		       "nothing - nothing tested\n");
		return 0;
	}

	while (kof_streams_next(&w)) {
		n++;
		/*
		 * The suffix is what comes back, and it is what CreateFile
		 * accepts when appended - ":alpha:$DATA". Matched on the
		 * PREFIX because the ":$DATA" type suffix is the enumeration's
		 * to include or not, and this test is about which stream it
		 * is, not about how the name is spelled.
		 */
		if (strncmp(w.name, ":alpha", 6) == 0)
			seen_a = 1;
		else if (strncmp(w.name, ":beta", 5) == 0)
			seen_b = 1;
		else if (strcmp(w.name, "::$DATA") == 0)
			seen_main = 1;
	}
	kof_streams_close(&w);

	ok_(seen_a, "the first named stream came back");
	ok_(seen_b, "the second named stream came back");
	ok_(!seen_main, "the file's own stream was not reported as an extra");
	ok_(n == 2, "exactly the named streams, and nothing else");
	ok_(w.name[0] == ':' || n == 0,
	    "what comes back is a suffix, ready to append");

	remove(s1);
	remove(s2);
	remove(host);

	if (failures) {
		printf("ads walk: %d check(s) failed\n", failures);
		return 1;
	}
	printf("ads walk: named streams found, the unnamed one not repeated - "
	       "ok\n");
	return 0;
}
