/*
 * chm_object - an entry named in a CHM's directory becomes a child object.
 *
 * chm_walk tests the parse against bytes; this tests the step AFTER it, which
 * no parser test can reach: the host opens carried files generically from the
 * entry table - see kof_objtree_declared - so a format that fills that table
 * correctly needs no module of its own, and a format that fills it WRONGLY
 * produces nothing and looks exactly like a clean file.
 *
 * That is the whole reason this exists. A CHM whose entries never become
 * children is reported scanned, with no findings, at full speed.
 *
 * The bytes are built here rather than loaded, for the reason chm_walk gives:
 * nothing on a Linux build host writes a CHM.
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

#define CHUNK 4096u
#define ITSF_LEN 0x60u
#define ITSP_LEN 0x54u
#define DIR_AT   (ITSF_LEN + ITSP_LEN)
#define CONTENT_AT (DIR_AT + CHUNK)
#define FILE_LEN (CONTENT_AT + 64u)

/* The bytes the entry points at, and what the child must turn out to be. */
static const char page[] = "<html>kofeng chm fixture page</html>";

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t *p, uint64_t v)
{
	wr32(p, (uint32_t)v);
	wr32(p + 4, (uint32_t)(v >> 32));
}

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

static uint8_t *build(size_t *len_out)
{
	uint8_t *f = calloc(1, FILE_LEN);
	uint8_t *dir, *at;

	if (!f)
		return NULL;
	memcpy(f, "ITSF", 4);
	wr32(f + 4, 3);
	wr32(f + 8, ITSF_LEN);
	wr32(f + 20, 0x409u);
	wr64(f + 56, ITSF_LEN);
	wr64(f + 64, 0x18u);
	wr64(f + 72, ITSF_LEN);
	wr64(f + 80, ITSP_LEN);
	wr64(f + 88, CONTENT_AT);

	memcpy(f + ITSF_LEN, "ITSP", 4);
	wr32(f + ITSF_LEN + 4, 1);
	wr32(f + ITSF_LEN + 8, ITSP_LEN);
	wr32(f + ITSF_LEN + 16, CHUNK);
	wr32(f + ITSF_LEN + 44, 1);

	dir = f + DIR_AT;
	memcpy(dir, "PMGL", 4);
	at = dir + 0x14u;
	at += put_entry(at, "/page.htm", 0, 0, sizeof page - 1u);
	wr32(dir + 4, (uint32_t)(CHUNK - (uint32_t)(at - dir)));

	memcpy(f + CONTENT_AT, page, sizeof page - 1u);
	*len_out = FILE_LEN;
	return f;
}

struct seen {
	int objects;
	int matched;      /* a child that is the page, by content */
	int named;        /* and that carries the name from the directory */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)res;
	s->objects++;
	if (bytes && len == sizeof page - 1u &&
	    memcmp(bytes, page, (size_t)len) == 0) {
		s->matched++;
		/*
		 * AND THE NAME CAME WITH IT. struct kof_entry carries the name
		 * as a range in the parent for exactly this - a child with no
		 * name is a row a listing shows as a number.
		 */
		if (name && strstr(name, "page.htm"))
			s->named++;
	}
	return 0;
}

int main(void)
{
	static const char *db = "build/release/databases";
	struct kof_scan_option opt;
	struct kof_engine *eng;
	struct kof_scanner *sc;
	struct seen s;
	uint8_t *f;
	size_t len = 0;
	int n;

	f = build(&len);
	if (!f) {
		printf("chm object: out of memory\n");
		return 1;
	}
	eng = kof_engine_open(db);
	if (!eng) {
		free(f);
		printf("chm object: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		free(f);
		printf("chm object: could not make a scanner\n");
		return 1;
	}

	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	n = kof_scan_bytes(sc, f, len, "fixture.chm", &opt, on_object, &s);

	if (n <= 0)
		fail("scan", "the CHM was not scanned at all");
	else if (s.objects < 2)
		fail("child", "the directory named an entry and no child was "
		     "made of it");
	else if (!s.matched)
		fail("child", "a child was made and it is not the entry's "
		     "bytes");
	else if (!s.named)
		fail("child", "the child carries no name, though the directory "
		     "has one for it");

	kof_scanner_free(sc);
	kof_engine_close(eng);
	free(f);

	if (failures) {
		printf("chm object: %d check(s) failed\n", failures);
		return 1;
	}
	printf("chm object: the directory's entry is a named child of the "
	       "right bytes - %d object(s) - ok\n", s.objects);
	return 0;
}
