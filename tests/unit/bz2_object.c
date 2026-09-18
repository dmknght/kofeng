/*
 * bz2_object - a .bz2 on disk becomes the file that was compressed into it.
 *
 * bunzip_diff tests the decoder against bytes; this tests the four things
 * BETWEEN a file and that decoder, which are the parts a decoder test cannot
 * reach: the sniff claims the object, the parse gives it a format, the module
 * for that format asks to unpack, and the host runs the coding the module named
 * and hands the result back as a child.
 *
 * Any one of those missing looks exactly like "the file is clean": the object is
 * scanned, nothing matches the compressed bytes - nothing ever will - and the
 * scan reports a file with no findings. That is why this asserts a CHILD was
 * produced and what its bytes are, rather than asserting a verdict.
 *
 * It needs the built database, because the unpacker is a module in it. Without
 * one it reports that it tested nothing rather than passing, on the same terms
 * as the fixture above it.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

struct seen {
	const uint8_t *want;
	uint64_t       want_n;
	int            objects;
	int            children;
	int            matched;    /* a child whose bytes are the tar */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	(void)res;
	s->objects++;
	/*
	 * The root is the .bz2 itself, so anything of a different length is
	 * something the engine produced. Compared by CONTENT rather than by
	 * counting: a child of the right size holding the wrong bytes is the
	 * failure this exists to catch.
	 */
	if (!bytes || len == 0)
		return 0;
	if (len == s->want_n && memcmp(bytes, s->want, (size_t)len) == 0) {
		s->children++;
		s->matched++;
	} else if (len != s->want_n) {
		s->children++;
	}
	return 0;
}

static uint8_t *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p;
	long n;

	*len = 0;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	p = malloc((size_t)n + 1u);
	if (!p) {
		fclose(f);
		return NULL;
	}
	if (n && fread(p, 1u, (size_t)n, f) != (size_t)n) {
		free(p);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return p;
}

int main(void)
{
	static const char *db  = "build/release/databases";
	static const char *bz  = "build/test/fixtures/sample.bz2";
	static const char *raw = "build/test/fixtures/sample.tar";
	struct kof_scan_option opt;
	struct kof_engine *eng;
	struct kof_scanner *sc;
	struct seen s;
	uint8_t *tar;
	size_t tar_n = 0;
	int n;

	tar = slurp(raw, &tar_n);
	if (!tar || !tar_n) {
		free(tar);
		printf("bz2 object: NO FIXTURE - bzip2 or tar was missing when "
		       "the fixtures were built, nothing tested\n");
		return 0;
	}
	/*
	 * AND THE .bz2 ITSELF, which is the fixture this actually opens.
	 *
	 * Guarding on the .tar alone says "bzip2 OR tar was missing" and then
	 * checks only the second of them, so a host with tar and no bzip2 - a
	 * Windows box until the fixture script learned to make one - ran the
	 * scan against a file that is not there and reported "the .bz2 was not
	 * scanned at all". That reads as a broken decoder and is a missing
	 * tool, which is the exact confusion the skip above exists to prevent.
	 */
	{
		size_t bz_n = 0;
		uint8_t *probe = slurp(bz, &bz_n);

		free(probe);
		if (!bz_n) {
			free(tar);
			printf("bz2 object: NO FIXTURE - bzip2 was missing when "
			       "the fixtures were built, nothing tested\n");
			return 0;
		}
	}

	eng = kof_engine_open(db);
	if (!eng) {
		free(tar);
		printf("bz2 object: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		free(tar);
		printf("bz2 object: could not make a scanner\n");
		return 1;
	}

	memset(&s, 0, sizeof s);
	s.want = tar;
	s.want_n = tar_n;

	/* Zeroed is the conservative setting everywhere; heur 1 is what makes a
	 * scan descend into a container at all - see kof_scan_option. */
	memset(&opt, 0, sizeof opt);
	n = kof_scan_path(sc, bz, &opt, on_object, &s);

	if (n <= 0)
		fail("scan", "the .bz2 was not scanned at all");
	else if (s.objects < 2)
		fail("unpack", "the .bz2 produced no child - the sniff, the "
		     "module or the host coding is missing");
	else if (!s.matched)
		fail("unpack", "a child was produced and it is not the file "
		     "that was compressed");

	kof_scanner_free(sc);
	kof_engine_close(eng);
	free(tar);

	if (failures) {
		printf("bz2 object: %d check(s) failed\n", failures);
		return 1;
	}
	printf("bz2 object: sniff, parse, module, host decode - %d object(s), "
	       "the child is the original - ok\n", s.objects);
	return 0;
}
