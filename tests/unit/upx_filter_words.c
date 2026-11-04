/*
 * upx_filter_words - the ARM (id 0x50) and PowerPC (id 0xd0) branch filters of the UPX/ELF module.
 *
 * The module is a blob, so the only way to run its inverse is the whole engine: this builds a
 * small UPX-packed ELF at run time from inert bytes (a block of NOP words with branch-with-link
 * words in it, filtered FORWARD by the rule written here, packed with a literal/match NRV2B
 * stream from tests/lib/uncoat/hostile_nrvenc.h), scans it, and requires the unpacked object to
 * be the original block exactly. No sample, no packed real file.
 *
 * The forward rule is stated independently of the module (it is the data of two `upx -d` runs,
 * see the note above upx_unfilter_words in bases/unp/upx_elf_00.c):
 *   ARM  LE word, bits 27..24 == 1011: imm24 += word index in the block (mod 2^24), any condition.
 *   PPC  BE word, (w & 0xfc000002) == 0x48000000: when displacement + byte offset is an offset
 *        inside the block, the field holds that offset; otherwise the word is left alone.
 * Words are placed at the window edges of the module's 4096-byte reads, at both ends of the block,
 * with displacements at the field's boundaries, with non-branch words beside them and with
 * branch-looking words whose target is outside the block (PPC: left alone).
 *
 * Why the old tests missed it: (a) no test ran the UPX module at all (line never executed).
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"
#include "../lib/uncoat/hostile_nrvenc.h"

#define BLK     12352u          /* three windows and a part, a multiple of 4 */
#define FILEMAX 32768u

static unsigned fails;
#define CK(c, ...)                                                               \
	do {                                                                     \
		if (!(c)) {                                                      \
			fails++;                                                 \
			printf("FAIL %s:%d ", __FILE__, __LINE__);               \
			printf(__VA_ARGS__);                                     \
			printf("\n");                                            \
		}                                                                \
	} while (0)

static uint8_t want_obj[BLK];
static uint64_t got_len;
static uint8_t got_obj[BLK + 64];
static int got_found;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)res; (void)user;
	if (strstr(name, "//") && len == BLK && !got_found) {
		memcpy(got_obj, bytes, BLK);
		got_len = len;
		got_found = 1;
	}
	return 0;
}

static void put32(uint8_t *p, uint32_t v, int be)
{
	unsigned i;

	for (i = 0; i < 4; i++)
		p[i] = (uint8_t)(v >> (be ? 24 - 8 * i : 8 * i));
}

static uint32_t get32(const uint8_t *p, int be)
{
	uint32_t v = 0;
	unsigned i;

	for (i = 0; i < 4; i++)
		v |= (uint32_t)p[i] << (be ? 24 - 8 * i : 8 * i);
	return v;
}

/* The forward filter, from the rule above. Returns 0 when the input is one the real filter
 * would not have kept (a PPC word left alone whose field is below the block length is read
 * back as filtered), so the test never asks for something the format cannot carry. */
static int forward(uint8_t *blk, int ppc)
{
	uint32_t pos;

	for (pos = 0; pos + 4u <= BLK; pos += 4) {
		uint32_t v = get32(blk + pos, ppc);

		if (!ppc) {
			if (((v >> 24) & 0xfu) == 0xbu)
				v = (v & 0xff000000u) | (((v & 0xffffffu) + (pos >> 2)) & 0xffffffu);
		} else if ((v & 0xfc000002u) == 0x48000000u) {
			uint32_t li = v & 0x03fffffcu;
			uint32_t abs = (li + pos) & 0x03fffffcu;

			if (abs < BLK)
				v = (v & 0xfc000003u) | abs;
			else if (li < BLK)
				return 0;
		}
		put32(blk + pos, v, ppc);
	}
	return 1;
}

/* Greedy NRV2B with 8-bit tag words (method 3): literal, or the longest match in 4096 back. */
static size_t pack(const uint8_t *in, uint8_t *out, size_t cap)
{
	static uint8_t hist[BLK + 16];
	struct hv_tw w;
	size_t p = 0;

	hv_tw_init(&w, out, cap, 8, hist, sizeof hist);
	while (p < BLK) {
		size_t best = 0, bd = 0, d;

		for (d = 1; d <= p && d <= 4096; d++) {
			size_t l = 0;

			while (p + l < BLK && l < 255 && in[p + l] == in[p + l - d])
				l++;
			if (l > best) {
				best = l;
				bd = d;
			}
		}
		if (best >= 4) {
			hv_nrv_match(&w, HV_NRV2B, (uint32_t)bd, (unsigned)best);
			p += best;
		} else {
			hv_nrv_lit(&w, in[p]);
			p++;
		}
	}
	hv_nrv_end(&w, HV_NRV2B);
	return w.n;
}

static uint64_t build(uint8_t *f, const uint8_t *filtered, int ppc, unsigned ftid)
{
	uint8_t z[BLK * 2];
	size_t clen;
	uint64_t at = 0x60;
	int be = ppc;

	memset(f, 0, FILEMAX);
	memcpy(f, "\x7f" "ELF", 4);
	f[4] = 1;
	f[5] = (uint8_t)(be ? 2 : 1);
	f[6] = 1;
	f[16] = be ? 0 : 2;  f[17] = be ? 2 : 0;                    /* ET_EXEC */
	f[18] = be ? 0 : (uint8_t)40; f[19] = be ? (uint8_t)20 : 0; /* machine */
	put32(f + 20, 1, be);
	f[28 + (be ? 3 : 0)] = 0x34;                                /* e_phoff: 52 */
	f[40 + (be ? 1 : 0)] = 52;                                  /* e_ehsize */
	f[42 + (be ? 1 : 0)] = 32;                                  /* e_phentsize */
	f[44 + (be ? 1 : 0)] = 1;                                   /* e_phnum */
	put32(f + 52, 1, be);                                       /* PT_LOAD */
	put32(f + 52 + 16, 0x400, be);                              /* p_filesz */
	put32(f + 52 + 20, 0x400, be);                              /* p_memsz */
	put32(f + 52 + 24, 5, be);

	memcpy(f + at + 4, "UPX!", 4);                              /* l_info */
	f[at + 10] = 14;
	f[at + 11] = (uint8_t)(be ? 23 : 22);
	at += 12;
	put32(f + at + 4, BLK, be);                                 /* p_filesize */
	at += 12;

	clen = pack(filtered, z, sizeof z);
	put32(f + at, BLK, be);                                     /* b_info */
	put32(f + at + 4, (uint32_t)clen, be);
	f[at + 8] = 3;                                              /* NRV2B, 8-bit tags */
	f[at + 9] = (uint8_t)ftid;
	f[at + 10] = 0;
	memcpy(f + at + 12, z, clen);
	return at + 12 + clen + 64;
}

static uint32_t rnd = 12345u;
static uint32_t next(void)
{
	rnd = rnd * 1664525u + 1013904223u;
	return rnd >> 8;
}

static void plant(uint8_t *blk, uint32_t pos, uint32_t v, int be)
{
	put32(blk + pos, v, be);
}

static void make_original(uint8_t *blk, int ppc, unsigned round)
{
	static const uint32_t arm_imm[] = { 0, 1, 2, 53, 0x7fffff, 0x800000, 0xfffffe, 0xffffff };
	static const uint32_t arm_cond[] = { 0xeb, 0x1b, 0x0b, 0xfb, 0x8b, 0xea, 0xe5, 0xf0, 0x0a };
	static const uint32_t ppc_li[] = { 0, 4, 0x2000, BLK - 4, BLK, 0x03fffffc, 0x03ffe000, 0x01000000, 0x02000000, 0x03fffff0 };
	static const uint32_t ppc_op[] = { 0x48000001, 0x48000000, 0x48000003, 0x48000002, 0x4c000001, 0x40000001 };
	static const uint32_t at[] = { 0, 4, 4092, 4096, 4100, 8188, 8192, 8196, BLK - 8, BLK - 4, 1000, 6000 };
	uint32_t pos, k;

	for (pos = 0; pos < BLK; pos += 4)
		put32(blk + pos, ppc ? 0x60000000u : 0xe1a00000u, ppc);
	for (k = 0; k < sizeof at / sizeof at[0]; k++) {
		uint32_t pi = at[k], v;

		if (ppc) {
			uint32_t li = ppc_li[(k + round) % (sizeof ppc_li / sizeof ppc_li[0])];

			v = ppc_op[(k * 7u + round) % (sizeof ppc_op / sizeof ppc_op[0])] & 0xfc000003u;
			v |= li & 0x03fffffcu;
		} else {
			v = (arm_cond[(k + round) % (sizeof arm_cond / sizeof arm_cond[0])] << 24) |
			    arm_imm[(k * 5u + round) % (sizeof arm_imm / sizeof arm_imm[0])];
		}
		plant(blk, pi, v, ppc);
	}
	/* a few arbitrary words, so a window is not all one value */
	for (k = 0; k < 6; k++)
		plant(blk, (next() % (BLK / 4)) * 4u, (next() << 8) ^ next(), ppc);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	char path[256];
	kof_engine *eng = keng_open(db);
	kof_scanner *sc;
	uint8_t *f = malloc(FILEMAX);
	unsigned arch, round, done = 0;

	if (!eng) {
		printf("upx filter words: no database at %s - skipped\n", db);
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc || !f)
		return 1;
	snprintf(path, sizeof path, "build/test/upx-filter-%d.bin", (int)getpid());

	for (arch = 0; arch < 2; arch++) {
		for (round = 0; round < 24; round++) {
			uint8_t filt[BLK];
			struct kof_scan_option opt;
			uint64_t flen;
			FILE *fp;
			unsigned i;

			make_original(want_obj, (int)arch, round);
			memcpy(filt, want_obj, BLK);
			if (!forward(filt, (int)arch))
				continue;               /* not carried by the real filter */
			if (!memcmp(filt, want_obj, BLK))
				continue;
			flen = build(f, filt, (int)arch, arch ? 0xd0u : 0x50u);
			fp = fopen(path, "wb");
			if (!fp || fwrite(f, 1, (size_t)flen, fp) != (size_t)flen)
				return 1;
			fclose(fp);

			memset(&opt, 0, sizeof opt);
			opt.max_produced_bytes = 1u << 20;
			opt.max_resident_bytes = 16u << 20;
			opt.max_object_bytes   = 2u << 20;
			got_found = 0;
			kscan_path(sc, path, &opt, on_object, NULL);
			CK(got_found, "%s round %u: the unpacked object (%u bytes) was not delivered",
			   arch ? "ppc" : "arm", round, BLK);
			if (got_found) {
				for (i = 0; i < BLK && got_obj[i] == want_obj[i]; i++)
					;
				CK(i == BLK, "%s round %u: first byte that is not the original: %u (%02x, want %02x)",
				   arch ? "ppc" : "arm", round, i, got_obj[i < BLK ? i : 0], want_obj[i < BLK ? i : 0]);
			}
			done++;
		}
	}
	CK(done >= 30, "only %u fixtures were carried by the forward rule", done);
	unlink(path);
	kscan_free(sc);
	keng_close(eng);
	free(f);
	printf("upx filter words: %u fixtures, %u failure(s)\n", done, fails);
	return fails ? 1 : 0;
}
