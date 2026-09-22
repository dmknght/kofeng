/*
 * path_api - the platform's own idea of a path, asserted on both platforms.
 *
 * WHY THIS EXISTS. kof_path_squash was written inside the directory walk,
 * spelled for POSIX, because the bug it fixes was found on Linux: "//" is what
 * an object name is composed with, so a filesystem path carrying one made the
 * top level file read as a CHILD - and a caller deciding "may I repair this"
 * by that test decided it wrongly.
 *
 * Windows is not POSIX with a different slash, which is the half a POSIX-only
 * author does not test and cannot see fail: two leading separators are a
 * PREFIX there - a UNC share, the extended-length form, a device - and
 * collapsing them names something else or nothing. So the Windows expectations
 * are written out here even though this host cannot run them, and the #ifdef
 * says which platform each claim belongs to rather than quietly asserting the
 * one that happens to be building.
 */

/* _GNU_SOURCE, not a bare compile: kofplatform.h reaches for memmem, lstat,
 * realpath and O_NOFOLLOW, and none of those is declared under a plain
 * -std=c11 - the same trap tests/unit/ads_walk.c fell into. */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofplatform.h"

static int fails;

static void want(const char *what, const char *in, const char *expect)
{
	char out[256];
	size_t n = kof_path_squash(in, out, sizeof out);

	if (n == strlen(expect) && !strcmp(out, expect)) {
		printf("  ok   %-42s %s\n", what, out);
		return;
	}
	printf("  FAIL %-42s got \"%s\", wanted \"%s\"\n", what, n ? out : "", expect);
	fails++;
}

int main(void)
{
	char out[8];

	printf("path api:\n");

	want("an ordinary path is left alone", "/usr/bin/ls", "/usr/bin/ls");
	want("a doubled separator collapses",  "/usr//bin/ls", "/usr/bin/ls");
	want("a long run collapses",           "/usr////bin", "/usr/bin");
	want("several runs collapse",          "/a//b///c", "/a/b/c");
	want("a trailing separator goes",      "/usr/bin/", "/usr/bin");
	want("a run of trailing ones goes",    "/usr/bin///", "/usr/bin");
	want("the root survives",              "/", "/");
	want("a relative path survives",       "a//b", "a/b");

#ifdef _WIN32
	/*
	 * THE PREFIXES THAT MUST SURVIVE. Each of these is a real Windows
	 * path shape whose leading PAIR is syntax, not repetition.
	 */
	want("a UNC share keeps its pair",     "\\\\server\\share\\f",
					       "\\\\server\\share\\f");
	want("the extended prefix survives",   "\\\\?\\C:\\a", "\\\\?\\C:\\a");
	want("a device path survives",         "\\\\.\\PhysicalDrive0",
					       "\\\\.\\PhysicalDrive0");
	want("but a doubled one inside goes",  "C:\\a\\\\b", "C:\\a\\b");
	want("and a forward slash is a separator too", "C:/a//b", "C:/a/b");
	want("three at the start is a pair and a stray",
	     "\\\\\\server\\s", "\\\\server\\s");
#else
	/*
	 * AND ON POSIX THE PAIR IS NOT SYNTAX. Linux reads "//x" as "/x", and
	 * a name this engine cannot spell unambiguously is worse than the
	 * ordinary spelling - so it collapses like any other run.
	 */
	want("a leading pair collapses here",  "//etc/passwd", "/etc/passwd");
	want("a backslash is an ordinary byte", "/a\\\\b", "/a\\\\b");
#endif

	/* And a buffer that cannot hold the answer is refused, not truncated:
	 * a truncated path names a different file. */
	if (kof_path_squash("/a/very/long/path/indeed", out, sizeof out) != 0) {
		printf("  FAIL a path that does not fit was not refused\n");
		fails++;
	} else {
		printf("  ok   a path that does not fit is refused\n");
	}

	if (fails) {
		printf("path api: %d check(s) failed\n", fails);
		return 1;
	}
	printf("path api: ok\n");
	return 0;
}
