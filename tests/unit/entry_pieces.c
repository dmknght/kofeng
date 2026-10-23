/*
 * entry_pieces - an entry of more than KOF_SCAN_MAX_EXTENTS pieces is opened whole, or the object
 * says it could not be.
 *
 * ctx->resolve_entry was handed a fixed array of 4096 ranges, and a resolver that fills what it is
 * given answers the same as one that dropped ranges, so a cabinet file of 5000 CFDATA blocks was
 * decoded from its first 4096 and handed on as the file: shorter, with its tail gone and nothing
 * said (scanners/scan_ext.c kof_scan_resolve_entry). Now the gather buffer grows until the answer
 * fits, and when the ledger cannot afford that the entry is not produced and the object reports a
 * limit - never a cut file under the file's name.
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include <kofmod/cab.h>

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

#define BLOCKS 5000u    /* past the 4096 a resolve used to be given */
#define PIECE  16u      /* bytes of data in each CFDATA block */

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v) { le16(p, v & 0xffffu); le16(p + 2, v >> 16); }

/* One stored folder of BLOCKS blocks, one file spanning all of them: the file is BLOCKS pieces,
 * because a header sits between every two of them. Byte i of the file is (i * 7 + i / 251) & 0xff. */
static uint8_t *build_cab(size_t *len)
{
	const size_t fsz = (size_t)BLOCKS * PIECE, hdr = 36u + 8u, file_at = hdr, name_at = file_at + 16u;
	const size_t data_at = name_at + 6u, total = data_at + (size_t)BLOCKS * (8u + PIECE);
	uint8_t *f = calloc(1, total);
	size_t at, i, k;

	if (!f)
		return NULL;
	memcpy(f, "MSCF", 4);
	le32(f + 8, (uint32_t)total);
	le32(f + 16, (uint32_t)file_at);
	le16(f + 24, 0x0301u);
	le16(f + 26, 1);
	le16(f + 28, 1);
	le32(f + 36, (uint32_t)data_at);
	le16(f + 36 + 4, BLOCKS);
	le16(f + 36 + 6, KOF_CAB_C_NONE);
	le32(f + file_at, (uint32_t)fsz);
	le32(f + file_at + 4, 0);
	le16(f + file_at + 14, 0x20u);
	memcpy(f + name_at, "big.bin", 6);
	f[name_at + 5] = 0;
	at = data_at;
	for (i = 0; i < BLOCKS; i++) {
		le16(f + at + 4, PIECE);
		le16(f + at + 6, PIECE);
		at += 8;
		for (k = 0; k < PIECE; k++) {
			size_t b = i * PIECE + k;

			f[at++] = (uint8_t)(b * 7u + b / 251u);
		}
	}
	*len = total;
	return f;
}

struct seen {
	unsigned objs, exact, top_broken, any_broken;
	uint64_t big_len;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	const uint8_t *p = bytes;

	(void)name;
	if (!s->objs)
		s->top_broken = res->broken;
	else if (len >= (uint64_t)BLOCKS * PIECE / 2u) {
		uint64_t i;

		s->big_len = len;
		for (i = 0; i < len && i < (uint64_t)BLOCKS * PIECE; i++)
			if (p[i] != (uint8_t)(i * 7u + i / 251u))
				break;
		s->exact = i == (uint64_t)BLOCKS * PIECE && len == i;
	}
	if (res->broken && !s->any_broken)
		s->any_broken = res->broken;
	s->objs++;
	return 0;
}

static void scan(kof_scanner *sc, const uint8_t *b, size_t n, uint64_t ceiling, struct seen *s)
{
	struct kof_scan_option opt;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	if (ceiling) {
		opt.max_resident_bytes = ceiling;
		opt.resident_per_scanner = 1;
	}
	(void)kscan_bytes(sc, b, n, "x.cab", &opt, on_object, s);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	static const uint64_t rungs[] = { 8u << 10, 24u << 10, 48u << 10, 96u << 10, 160u << 10, 1u << 20, 64u << 20 };
	unsigned i, whole = 0, said = 0, silent = 0;
	kof_engine *eng = keng_open(db);
	kof_scanner *sc;
	size_t len = 0;
	uint8_t *cab;
	struct seen s;

	if (!eng) {
		printf("entry_pieces: no database at %s\n", db);
		return 1;
	}
	sc = kscan_new(eng);
	cab = build_cab(&len);
	CK(sc && cab, "setup");
	if (!sc || !cab)
		return 1;

	scan(sc, cab, len, 0, &s);
	printf("  default: %u objects, the %u-piece file is %llu bytes, exact %u, broken %u/%u\n", s.objs, BLOCKS,
	       (unsigned long long)s.big_len, s.exact, s.top_broken, s.any_broken);
	CK(s.exact, "the file of %u pieces was not opened whole (%llu bytes of %u)", BLOCKS, (unsigned long long)s.big_len, BLOCKS * PIECE);
	CK(!s.any_broken, "a whole entry said %u", s.any_broken);

	/* a ladder of ceilings: every rung opens it whole or says it did not, and an entry that is
	 * there is the whole file - never the first 4096 pieces of it */
	for (i = 0; i < sizeof rungs / sizeof rungs[0]; i++) {
		scan(sc, cab, len, rungs[i], &s);
		if (s.exact && !s.any_broken)
			whole++;
		else if (s.any_broken)
			said++;
		else
			silent++;
		CK(!s.big_len || s.exact, "ceiling %llu: a file of %llu bytes was handed on, not the %u it is", (unsigned long long)rungs[i],
		   (unsigned long long)s.big_len, BLOCKS * PIECE);
		printf("  ceiling %9llu: %u objects, file %llu bytes, exact %u, broken %u\n", (unsigned long long)rungs[i], s.objs,
		       (unsigned long long)s.big_len, s.exact, s.any_broken);
	}
	printf("  ladder: %u whole, %u said, %u silent\n", whole, said, silent);
	CK(silent == 0, "%u ceiling(s) lost the file and said nothing", silent);
	CK(whole > 0 && said > 0, "the ladder must cross from said to whole (%u whole, %u said)", whole, said);

	free(cab);
	kscan_free(sc);
	keng_close(eng);
	if (fails) {
		printf("entry_pieces: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("entry_pieces: whole or said - ok\n");
	return 0;
}
