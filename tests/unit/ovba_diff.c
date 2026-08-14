/*
 * ovba_diff.c - the OVBA decoder against an independent implementation.
 *
 * Same shape as inflate_diff: the decoder is run over every plausible container
 * position in a directory of real vbaProject.bin files, and what it produced is
 * reported as a digest per position. A reference written separately from the same
 * specification prints the same lines, and the two are diffed.
 *
 * Every position is decoded, not only the ones that hold real macros - measured,
 * 94% of positions that pass the cheap signature test do not, so the disagreements
 * worth finding are mostly on input that is not a container at all. That is the
 * input a scanner meets and it is where a decoder walks off the end of something.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "../../libkofeng/kofdecomp/ovba.h"

struct acc {
	uint32_t crc;
	uint64_t n;
};

static uint32_t crc_step(uint32_t crc, uint8_t b)
{
	uint32_t k;

	crc ^= b;
	for (k = 0; k < 8u; k++)
		crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
	return crc;
}

static int sink(void *user, const uint8_t *p, uint32_t n)
{
	struct acc *a = user;
	uint32_t i;

	for (i = 0; i < n; i++)
		a->crc = crc_step(a->crc, p[i]);
	a->n += n;
	return 1;
}

static void one_file(const char *path, const char *name)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long len;
	long i;

	if (!f)
		return;
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (len <= 0) { fclose(f); return; }
	b = malloc((size_t)len);
	if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) {
		free(b); fclose(f); return;
	}
	fclose(f);

	for (i = 0; i + 3 <= len; i++) {
		struct acc a;
		uint64_t produced = 0;
		int st;

		if (!kof_ovba_plausible(b + i, (uint64_t)(len - i)))
			continue;
		a.crc = 0xffffffffu;
		a.n = 0;
		st = kof_ovba_decode(b + i, (uint64_t)(len - i), sink, &a, &produced);
		printf("%s %ld %d %llu %08x\n", name, i, st,
		       (unsigned long long)produced, a.crc ^ 0xffffffffu);
	}
	free(b);
}

/* ---- what runs when there is no sample directory ------------------------------ */

static uint64_t rng = 88172645463325252ull;

static uint32_t rnd(void)
{
	rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
	return (uint32_t)(rng >> 32);
}

static uint8_t sunk[16384];
static uint32_t sunk_n;

static int keep(void *user, const uint8_t *p, uint32_t n)
{
	uint32_t i;

	(void)user;
	for (i = 0; i < n && sunk_n < sizeof sunk; i++)
		sunk[sunk_n++] = p[i];
	return 1;
}

/*
 * Three things, and the third is the one worth having.
 *
 * A container round trips; a container that ends early is TRUNCATED and keeps what
 * it decoded; and a copy token naming an offset before the chunk began is CORRUPT
 * rather than a read of whatever the window held from the chunk before. That last
 * one is reachable from a file - the token's field is wide enough to express it -
 * and it is the only way this decoder could hand back bytes that were never in the
 * stream.
 */
static int selfcheck(void)
{
	static const char msg[] = "Sub AutoOpen()";
	uint8_t in[64];
	uint64_t produced;
	uint32_t len = (uint32_t)(sizeof msg - 1u);
	uint16_t hdr;
	int st, bad = 0, i;

	hdr = (uint16_t)((len + 2u - 3u) | (3u << 12));
	in[0] = 0x01; in[1] = (uint8_t)hdr; in[2] = (uint8_t)(hdr >> 8);
	memcpy(in + 3, msg, len);

	sunk_n = 0;
	st = kof_ovba_decode(in, 3u + len, keep, NULL, &produced);
	if (st != KOF_DEC_OK || produced != len || memcmp(sunk, msg, len) != 0) {
		printf("  FAIL raw chunk: status=%d produced=%llu\n", st,
		       (unsigned long long)produced);
		bad++;
	}

	sunk_n = 0;
	st = kof_ovba_decode(in, 3u + len - 4u, keep, NULL, &produced);
	if (st != KOF_DEC_TRUNCATED || produced != len - 4u) {
		printf("  FAIL short chunk: status=%d produced=%llu\n", st,
		       (unsigned long long)produced);
		bad++;
	}

	/* One literal, then a copy reaching further back than the chunk holds. */
	{
		uint8_t ev[16];
		uint16_t h = (uint16_t)((4u + 2u - 3u) | (3u << 12) | 0x8000u);

		ev[0] = 0x01;
		ev[1] = (uint8_t)h; ev[2] = (uint8_t)(h >> 8);
		ev[3] = 0x02;              /* token 0 literal, token 1 a copy */
		ev[4] = 'A';
		ev[5] = 0xff; ev[6] = 0xff; /* offset far past one byte produced */
		sunk_n = 0;
		st = kof_ovba_decode(ev, 7u, keep, NULL, &produced);
		if (st != KOF_DEC_CORRUPT || produced != 1u) {
			printf("  FAIL back reference bound: status=%d produced=%llu\n",
			       st, (unsigned long long)produced);
			bad++;
		}
	}

	/* And nothing crashes on rubbish that passes the cheap test. */
	for (i = 0; i < 20000; i++) {
		uint8_t b[256];
		uint32_t k, n = 8u + rnd() % (uint32_t)(sizeof b - 8u);

		for (k = 0; k < n; k++)
			b[k] = (uint8_t)rnd();
		b[0] = 0x01;
		b[2] = (uint8_t)((b[2] & 0x8fu) | 0x30u);   /* a valid signature */
		sunk_n = 0;
		kof_ovba_decode(b, n, keep, NULL, &produced);
	}

	printf("ovba: round trip, truncation, back reference bound, "
	       "20000 hostile round(s)%s\n", bad ? " - FAILED" : " ok");
	return bad;
}

int main(int argc, char **argv)
{
	DIR *d;
	struct dirent *de;
	char path[4096];

	if (argc < 2)
		return selfcheck();
	d = opendir(argv[1]);
	if (!d)
		return 2;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", argv[1],
				     de->d_name) >= sizeof path)
			continue;
		one_file(path, de->d_name);
	}
	closedir(d);
	return 0;
}
