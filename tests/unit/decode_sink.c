/*
 * decode_sink - a buffered decode writes into the sink, not into a copy of it.
 *
 * WHAT THIS GUARDS. A coding whose whole output has to stay addressable while
 * it decodes - LZMA, NRV2, aPLib, ASPack - needs a flat buffer the size of
 * what it produces. There are two places that buffer can come from and only
 * one of them is free:
 *
 *   - the SINK, when the caller is filling a declared image. It is already a
 *     flat buffer of exactly the right size, so the decode writes straight
 *     into it. kof_stats.decode_inplace counts these.
 *   - a SCRATCH allocation otherwise, copied into the sink afterwards.
 *     kof_stats.decode_scratch counts these.
 *
 * The engine took the scratch path unconditionally, which cost a second copy
 * of every decoded image: measured on a VMProtect-under-MPRESS sample, four
 * scratch buffers of about five megabytes each, peaking at 15.31 MB where the
 * two objects alive at the time are 10.21.
 *
 * WHICH DIRECTION IS DANGEROUS, because the two failures are not alike. Losing
 * the in-place path costs memory and a memcpy and nothing else. TAKING it when
 * the sink cannot hold the output - a growable sink, a spilled one, no room at
 * the cursor - writes the decode somewhere it does not belong, and that is
 * silent. So this test drives a container, whose sink grows rather than being
 * placed, and asserts BOTH that the scratch path was the one taken AND that
 * the bytes came out whole.
 *
 * WHAT IT DOES NOT COVER, said plainly: the in-place path itself. Reaching it
 * needs an object that DECLARES an image and fills it with a buffered decoder,
 * which is what a packed executable is, and this repository has no packed
 * executable to ship as a fixture. The measurements above are from samples
 * that are not here. What is here is the guard on the unsafe direction, which
 * is the half a fixture can test.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "slurp.h"

static int failures;

static void fail(const char *why)
{
	printf("  FAIL %s\n", why);
	failures++;
}

struct seen {
	const uint8_t *want;
	uint64_t       want_n;
	int            matched;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	(void)res;
	if (bytes && len == s->want_n &&
	    memcmp(bytes, s->want, (size_t)len) == 0)
		s->matched++;
	return 0;
}

int main(void)
{
	static const char *db  = "build/release/databases";
	static const char *xz  = "build/test/fixtures/sample.xz";
	static const char *raw = "build/test/fixtures/sample.tar";
	struct kof_scan_option opt;
	struct kof_engine *eng;
	struct kof_scanner *sc;
	const struct kof_stats *st;
	struct seen s;
	uint8_t *tar = NULL, *cmp = NULL;
	size_t tar_n = 0, cmp_n = 0;

	tar = slurp(raw, &tar_n);
	cmp = slurp(xz, &cmp_n);
	if (!tar || !tar_n || !cmp || !cmp_n) {
		free(tar);
		free(cmp);
		printf("decode sink: NO FIXTURE - xz or tar was missing when "
		       "the fixtures were built, nothing tested\n");
		return 0;
	}
	eng = keng_open(db);
	if (!eng) {
		free(tar);
		free(cmp);
		printf("decode sink: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		free(tar);
		free(cmp);
		printf("decode sink: out of memory\n");
		return 1;
	}

	memset(&opt, 0, sizeof opt);
	opt.heur_level = 1;
	s.want = tar;
	s.want_n = tar_n;
	s.matched = 0;
	kscan_bytes(sc, cmp, (uint64_t)cmp_n, xz, &opt, on_object, &s);

	st = kscan_stats(sc);
	/*
	 * A container's sink GROWS - it is appended to rather than placed at a
	 * cursor - so there is nothing to decode into and the scratch path is
	 * the correct one. A build that reports otherwise has taken the
	 * in-place path where it does not apply, and the assertion below about
	 * the bytes is the one that says what that costs.
	 */
	if (st->decode_scratch == 0)
		fail("a container decode did not take the scratch path");
	if (st->decode_inplace != 0)
		fail("a container decode wrote into a sink it cannot place in");
	if (!s.matched)
		fail("the decoded bytes are not what was compressed");

	printf("decode sink: scratch=%llu inplace=%llu, bytes intact - %s\n",
	       (unsigned long long)st->decode_scratch,
	       (unsigned long long)st->decode_inplace,
	       failures ? "FAILED" : "ok");

	kscan_free(sc);
	keng_close(eng);
	free(tar);
	free(cmp);
	return failures ? 1 : 0;
}
