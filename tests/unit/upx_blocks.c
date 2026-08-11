/*
 * upx_blocks - decode real UPX blocks and check the length the file declared.
 *
 * There is no zlib for NRV2. The reference implementation is UPX's own stub, which
 * is machine code inside the samples, so the differential trick that proves inflate
 * correct is not available here.
 *
 * What is available is better in one respect: UPX WRITES DOWN ITS OWN ANSWER. Every
 * compressed block in a UPX/ELF file is preceded by a b_info giving the compressed
 * size, the uncompressed size and the method. Decoding a block and getting exactly
 * sz_unc bytes out of exactly sz_cpr bytes in, with the stream ending on its own end
 * marker rather than by running out of room, is a check the file itself supplies -
 * and it can be run over every block of every sample rather than over inputs a test
 * author thought of.
 *
 * It is a strong check because the failure modes it catches are the quiet ones. A
 * decoder with a bit-reader off by one round does not crash: it produces plausible
 * bytes of the wrong length, which is precisely what "produced == sz_unc" refuses.
 * A decoder that mishandles the arithmetic shift in NRV2D and NRV2E produces
 * distances that are enormous, fails its bounds check and reports corruption on
 * every real file - which is what "status == ok" refuses.
 *
 * The corpus is a directory of samples given as an argument, or the paths below.
 * When none exists the test says it tested nothing rather than passing quietly: a
 * decoder test that silently examines zero blocks is worse than no test, because it
 * reports green.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "../../libkofeng/kofdecomp/nrv2.h"
#include "../../libkofeng/kofdecomp/lzma.h"

static uint64_t blocks, matched;

/*
 * UPX's LZMA blocks start two bytes in, and those two bytes carry pb in their low
 * three bits. lc and lp were the same in every sample this was written against, so
 * they are constants here - the same statement bases/unp/upx_elf.c makes, and the
 * same reason: the declared length below is what would catch it being wrong.
 */
#define LZMA_SKIP 2u
#define LZMA_LC   3u
#define LZMA_LP   0u
static uint64_t bad_status, bad_length;
static char first_bad[600];

/* Tallied per method, because "52 blocks failed" and "every NRV2D block failed"
 * are different findings and only the second one names the bug. */
static uint64_t seen_by[16], ok_by[16];

/*
 * UPX method numbers, from its conf.h.
 *
 * Each group of three is one coding at three bit-buffer widths - _LE32, _8, _LE16
 * in that order - not one coding with three filters. This table is where that was
 * established: with all three mapped to the same reader, every _LE32 block passed
 * and every _8 block failed.
 */
static int variant_of(unsigned method)
{
	switch (method) {
	case 2: case 3: case 4:   return KOF_NRV2B;
	case 5: case 6: case 7:   return KOF_NRV2D;
	case 8: case 9: case 10:  return KOF_NRV2E;
	default:                  return -1;
	}
}

static int bits_of(unsigned method)
{
	switch (method) {
	case 2: case 5: case 8:   return 32;   /* _LE32 */
	case 3: case 6: case 9:   return 8;    /* _8    */
	case 4: case 7: case 10:  return 16;   /* _LE16 */
	default:                  return 0;
	}
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Walk the block chain of one UPX/ELF file.
 *
 * The chain has no count and no terminator: it ends where the packed data ends, and
 * past that the next twelve bytes are whatever happened to follow. So the walk stops
 * at the first b_info that cannot be true - one whose compressed data would not fit
 * in the file, or whose sizes are absurd - rather than trusting a count. That is the
 * same rule the collectors follow, and here it is also what keeps the test honest:
 * decoding garbage and calling the failure a decoder bug would make this test report
 * red on correct code.
 */
static void one_file(const char *path, const uint8_t *f, uint64_t n)
{
	uint64_t at;
	uint32_t lsize;
	uint64_t i, magic_at = 0;
	int found = 0;

	/* l_info sits early, inside the stub. Its magic is the anchor. */
	for (i = 0; i + 4 <= n && i < 8192; i++) {
		if (f[i] == 'U' && f[i + 1] == 'P' && f[i + 2] == 'X' &&
		    f[i + 3] == '!') {
			magic_at = i;
			found = 1;
			break;
		}
	}
	if (!found || magic_at + 8 > n)
		return;

	lsize = (uint32_t)f[magic_at + 4] | ((uint32_t)f[magic_at + 5] << 8);
	(void)lsize;
	/* l_info is 12 bytes from its checksum, so 8 past the magic; p_info is the
	 * next 12; the first b_info follows. */
	at = magic_at + 8 + 12;

	while (at + 12 <= n) {
		uint32_t sz_unc = rd32(f + at);
		uint32_t sz_cpr = rd32(f + at + 4);
		unsigned method  = f[at + 8];
		uint8_t *out;
		uint64_t produced = 0;
		int variant, st;

		if (sz_cpr == 0 || sz_unc == 0)
			break;
		if ((uint64_t)sz_cpr > n - (at + 12))
			break;                       /* runs past the file: not a block */
		if (sz_unc > (256u << 20) || sz_cpr > sz_unc)
			break;                       /* not a plausible compression */

		variant = variant_of(method);
		if (variant < 0 && method != 14)
			break;                       /* an unknown method ends the walk */
		if (method == 14 && sz_cpr <= LZMA_SKIP)
			break;

		out = malloc(sz_unc);
		if (!out)
			return;
		if (method == 14)
			st = kof_lzma_decode(LZMA_LC, LZMA_LP,
					     f[at + 12] & 7u,
					     f + at + 12 + LZMA_SKIP,
					     sz_cpr - LZMA_SKIP, out, sz_unc,
					     &produced);
		else
			st = kof_nrv2_decode(variant, bits_of(method), f + at + 12,
					     sz_cpr, out, sz_unc, &produced);
		blocks++;
		if (method < 16)
			seen_by[method]++;
		if (st != KOF_DEC_OK) {
			bad_status++;
			if (!first_bad[0])
				snprintf(first_bad, sizeof first_bad,
					 "%.400s: block at %llu method %u: %s",
					 path, (unsigned long long)at, method,
					 kof_decomp_status_name(st));
		} else if (produced != sz_unc) {
			bad_length++;
			if (!first_bad[0])
				snprintf(first_bad, sizeof first_bad,
					 "%.400s: block at %llu method %u: produced %llu "
					 "of a declared %u",
					 path, (unsigned long long)at, method,
					 (unsigned long long)produced, sz_unc);
		} else {
			matched++;
			if (method < 16)
				ok_by[method]++;
		}
		free(out);

		at += 12 + sz_cpr;
	}
}

static void walk(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char path[4096];

	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		struct stat st;
		void *map;
		int fd;

		if (de->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir, de->d_name)
		    >= sizeof path)
			continue;
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 64) {
			close(fd);
			continue;
		}
		map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (map == MAP_FAILED)
			continue;
		if (memcmp(map, "\177ELF", 4) == 0)
			one_file(path, map, (uint64_t)st.st_size);
		munmap(map, (size_t)st.st_size);
	}
	closedir(d);
}

int main(int argc, char **argv)
{
	static const char *defaults[] = {
		"/mnt/games/virus_share/VirusShare_Linux_20160715",
		"tests/UPX_FILES"
	};
	int i;

	if (argc > 1)
		for (i = 1; i < argc; i++)
			walk(argv[i]);
	else
		for (i = 0; i < (int)(sizeof defaults / sizeof defaults[0]); i++)
			walk(defaults[i]);

	if (blocks == 0) {
		printf("upx blocks: no sample corpus found - nothing tested\n");
		return 0;
	}
	printf("upx blocks: %llu block(s), %llu decoded to the declared length\n",
	       (unsigned long long)blocks, (unsigned long long)matched);
	{
		static const char *const mname[16] = {
			0,0,"NRV2B_LE32","NRV2B_8","NRV2B_LE16",
			"NRV2D_LE32","NRV2D_8","NRV2D_LE16",
			"NRV2E_LE32","NRV2E_8","NRV2E_LE16",0,0,0,"LZMA",0
		};
		int m;

		for (m = 0; m < 16; m++)
			if (seen_by[m])
				printf("   %-12s %llu/%llu\n",
				       mname[m] ? mname[m] : "?",
				       (unsigned long long)ok_by[m],
				       (unsigned long long)seen_by[m]);
	}
	if (first_bad[0])
		printf("  FAIL %s\n", first_bad);
	return (bad_status || bad_length) ? 1 : 0;
}
