/*
 * upx_elf_stored - UPX-ELF-DYN-SHORTFALL, reproduced from simulated bytes.
 *
 * The UPX/ELF module (bases/unp/upx_elf_00.c) is a blob, so the only way to run it is the whole
 * engine: this builds small UPX-packed ELFs at run time from inert bytes (block 0 an ELF64 header
 * and its program headers, packed with a literal/match NRV2B stream from
 * tests/lib/uncoat/hostile_nrvenc.h), scans them and requires the unpacked object to be the
 * original byte for byte. No sample and no packed real file.
 *
 * The two shapes that lost bytes, measured on `upx 4.2.4` output of one test source (the PIE
 * build kept 4096 of 17144 bytes, the static one 674504 of 759432):
 *   1. a STORED block in the chain: sz_cpr == sz_unc, method byte 0 (the stub copies it). The
 *      module took method 0 for "not a coding: the chain ended" and dropped the code segment and
 *      everything after it.
 *   2. a format-22 PackHeader whose sizes are the WHOLE file's (u_len = p_filesize, c_len = the
 *      PackHeader's own offset): the tail block (section headers and what follows the last
 *      PT_LOAD) was looked for under that pair, never found, and dropped.
 *   5. the x86 branch filter (ftid 0x49): the module put back displacement = stored - (offset of the NEXT instruction), four short of the original
 *      (UPX's filter adds the offset of the displacement FIELD): measured on the static fixture, 13854 bytes of the code differed from `upx -d`.
 * And what the fix must not do:
 *   3. a record of two equal sizes AFTER the layout is filled is not a block (the chain ends where
 *      the last PT_LOAD ends);
 *   4. a record whose method the module does not run, BEFORE the layout is filled, is a short
 *      unpack and is said (kof_result.broken UNSUPPORTED on the packed object, the module's
 *      container, which is where kunp_rcstruct_broken lands), not a clean end.
 *
 * Why the old tests missed it: (a) no test ran a stored block or a format-22 tail through the
 * module (the lines were never executed), nor the x86 inverse filter (tests/unit/upx_filter_words.c
 * covers the ARM and PowerPC word filters only); the fixture pin tests/unit/upx_elf_dyn_shortfall.c
 * measured the loss and pinned it as today's behaviour (c).
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"
#include "../lib/uncoat/hostile_nrvenc.h"

#define HDR      176u            /* ELF64 header 64 + two program headers of 56 */
#define CODE_AT  0x1000u
#define CODE     3000u
#define TAIL     700u
#define ORIG     (CODE_AT + CODE + TAIL)
#define FILEMAX  65536u

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

static uint8_t orig[ORIG];
static uint8_t got_obj[ORIG + 4096];
static uint64_t got_len;
static uint32_t got_broken, root_broken;
static int got_found;

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	(void)user;
	if (!strstr(name, "//"))
		root_broken = res->broken;
	if (strstr(name, "//") && !got_found) {
		memcpy(got_obj, bytes, len < sizeof got_obj ? (size_t)len : sizeof got_obj);
		got_len = len;
		got_broken = res->broken;
		got_found = 1;
	}
	return 0;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

/* Greedy NRV2B with 8-bit tag words (method 3). */
static size_t pack(const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
	static uint8_t hist[ORIG + 16];
	struct hv_tw w;
	size_t p = 0;

	hv_tw_init(&w, out, cap, 8, hist, sizeof hist);
	while (p < len) {
		size_t best = 0, bd = 0, d;

		for (d = 1; d <= p && d <= 4096; d++) {
			size_t l = 0;

			while (p + l < len && l < 255 && in[p + l] == in[p + l - d])
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

/* The original: an ELF64 header with two PT_LOADs (the header page, the code at CODE_AT), the
 * code bytes, and a tail past the last PT_LOAD (what a section header table would be). */
static void make_original(unsigned round)
{
	uint32_t i, r = 0x9e3779b9u * (round + 1u);

	memset(orig, 0, sizeof orig);
	memcpy(orig, "\x7f" "ELF", 4);
	orig[4] = 2; orig[5] = 1; orig[6] = 1;
	orig[16] = 3;                           /* ET_DYN */
	orig[18] = 62;                          /* x86-64 */
	put32(orig + 20, 1);
	put64(orig + 24, CODE_AT);              /* e_entry */
	put64(orig + 32, 64);                   /* e_phoff */
	orig[52] = 64; orig[54] = 56; orig[56] = 2;
	put32(orig + 64, 1); put32(orig + 68, 4);                       /* PT_LOAD R */
	put64(orig + 64 + 8, 0); put64(orig + 64 + 32, HDR); put64(orig + 64 + 40, HDR);
	put32(orig + 120, 1); put32(orig + 124, 5);                     /* PT_LOAD R E */
	put64(orig + 120 + 8, CODE_AT); put64(orig + 120 + 16, CODE_AT);
	put64(orig + 120 + 32, CODE); put64(orig + 120 + 40, CODE);
	for (i = 0; i < CODE; i++) {            /* 256 random bytes, repeated with one byte changed per copy */
		if (i < 256u) {
			r ^= r << 13; r ^= r >> 17; r ^= r << 5;
			orig[CODE_AT + i] = (uint8_t)r;
		} else
			orig[CODE_AT + i] = (uint8_t)(orig[CODE_AT + i - 256u] + (i % 256u == 0u));
	}
	for (i = 0; i < TAIL; i++)              /* a section header table: records that repeat */
		orig[CODE_AT + CODE + i] = (uint8_t)((i % 64u) < 8u ? i / 64u + round : (i % 64u) == 9u ? 1u : 0u);
}

static uint32_t binfo(uint8_t *f, uint32_t at, uint32_t unc, uint32_t cpr, uint8_t method)
{
	put32(f + at, unc);
	put32(f + at + 4, cpr);
	f[at + 8] = method;
	return at + 12;
}

enum shape { S_STORED_F22, S_PACKED_F22, S_JUNK_AFTER, S_FILTER49, S_UNKNOWN_METHOD };

#define CTO 0x17u

/* THE x86 BRANCH FILTER (ftid 0x49: E8, E9 and the two-byte Jcc), forward, as UPX's filter writes it: the four bytes after the opcode become, big-endian,
 * displacement + (the block offset of the field) with the top byte the block's `cto`. The code is nops with branches planted at known places to targets
 * inside the block; the filtered copy goes in `out`. 0: a byte pair the inverse would also take for a filtered branch (not planted): the round is skipped. */
static int filter49(const uint8_t *code, uint8_t *out)
{
	uint32_t ic;

	memcpy(out, code, CODE);
	for (ic = 0; ic + 5u <= CODE; ic++) {
		uint32_t f, v;

		if (code[ic] == 0xe8u || code[ic] == 0xe9u)
			f = ic + 1u;
		else if (code[ic] == 0x0fu && (code[ic + 1u] & 0xf0u) == 0x80u && ic + 6u <= CODE)
			f = ic + 2u;
		else
			continue;
		v = (uint32_t)code[f] | (uint32_t)code[f + 1u] << 8 | (uint32_t)code[f + 2u] << 16 | (uint32_t)code[f + 3u] << 24;
		v += f;
		out[f] = (uint8_t)CTO;
		out[f + 1u] = (uint8_t)(v >> 16);
		out[f + 2u] = (uint8_t)(v >> 8);
		out[f + 3u] = (uint8_t)v;
		ic = f + 3u;
	}
	for (ic = 0; ic + 1u < CODE; ic++)              /* every marker the inverse will read is a planted one */
		if ((out[ic] == 0xe8u || out[ic] == 0xe9u || (ic && out[ic - 1u] == 0x0fu && (out[ic] & 0xf0u) == 0x80u)) && out[ic + 1u] == CTO &&
		    !(code[ic] == 0xe8u || code[ic] == 0xe9u || (ic && code[ic - 1u] == 0x0fu && (code[ic] & 0xf0u) == 0x80u)))
			return 0;
	return 1;
}

/* The code of the filter shape: nops, and a call, a jump and a jcc every 97 bytes to targets across the block. */
static void plant_branches(unsigned round)
{
	uint32_t p, k = 0;

	memset(orig + CODE_AT, 0x90, CODE);
	for (p = 16; p + 6u <= CODE; p += 97u, k++) {
		const uint32_t tgt = (p * 7u + round * 131u) % CODE;
		const unsigned kind = k % 3u;
		const uint32_t next = p + (kind == 2u ? 6u : 5u);
		const uint32_t d = tgt - next;
		uint8_t *q = orig + CODE_AT + p;

		if (kind == 2u) {
			q[0] = 0x0f;
			q[1] = (uint8_t)(0x80u + (k & 0xfu));
			q += 2;
		} else {
			q[0] = kind ? 0xe9u : 0xe8u;
			q += 1;
		}
		q[0] = (uint8_t)d; q[1] = (uint8_t)(d >> 8); q[2] = (uint8_t)(d >> 16); q[3] = (uint8_t)(d >> 24);
	}
}

/* A UPX-packed file of `orig`. Returns its length. */
static uint32_t build(uint8_t *f, enum shape sh)
{
	static uint8_t z[ORIG * 2];
	uint32_t at = 0x60, c, ph;

	memset(f, 0, FILEMAX);
	memcpy(f, "\x7f" "ELF", 4);             /* the stub: ELF32 LE, one PT_LOAD (the module reads its byte order) */
	f[4] = 1; f[5] = 1; f[6] = 1;
	f[16] = 2; f[18] = 3;
	put32(f + 20, 1);
	f[28] = 0x34; f[40] = 52; f[42] = 32; f[44] = 1;
	put32(f + 52, 1); put32(f + 52 + 16, 0x400); put32(f + 52 + 20, 0x400); put32(f + 52 + 24, 5);

	memcpy(f + at + 4, "UPX!", 4);          /* l_info: version 14, format 22 */
	f[at + 10] = 14; f[at + 11] = 22;
	at += 12;
	put32(f + at + 4, ORIG);                /* p_info: p_filesize */
	at += 12;

	c = (uint32_t)pack(orig, HDR, z, sizeof z);     /* block 0: the header, compressed */
	at = binfo(f, at, HDR, c, 3);
	memcpy(f + at, z, c);
	at += c;
	if (sh == S_PACKED_F22) {               /* the code block compressed (the static build's shape) */
		c = (uint32_t)pack(orig + CODE_AT, CODE, z, sizeof z);
		at = binfo(f, at, CODE, c, 3);
		memcpy(f + at, z, c);
		at += c;
	} else if (sh == S_FILTER49) {          /* the code block filtered (ftid 0x49, cto CTO) and compressed */
		static uint8_t filt[CODE];

		if (!filter49(orig + CODE_AT, filt))
			return 0;
		c = (uint32_t)pack(filt, CODE, z, sizeof z);
		at = binfo(f, at, CODE, c, 3);
		f[at - 3] = 0x49;
		f[at - 2] = (uint8_t)CTO;
		memcpy(f + at, z, c);
		at += c;
	} else if (sh == S_UNKNOWN_METHOD) {    /* a well formed record of a coding no build has */
		at = binfo(f, at, CODE, CODE - 1u, 0x7e);
		memcpy(f + at, orig + CODE_AT, CODE - 1u);
		at += CODE - 1u;
	} else {                                /* the code block STORED: sizes equal, method 0 */
		at = binfo(f, at, CODE, CODE, 0);
		memcpy(f + at, orig + CODE_AT, CODE);
		at += CODE;
	}
	if (sh == S_JUNK_AFTER) {               /* after the layout: a record of two equal sizes */
		at = binfo(f, at, 64, 64, 0);
		memset(f + at, 0xcc, 64);
		at += 64;
	}
	at = binfo(f, at, 0, 0, 0);             /* the chain's end */
	memset(f + at, 0x90, 200);              /* the loader's code */
	at += 200;

	/* the tail block, a b_info of its own: compressed in the static build's shape, stored otherwise */
	if (sh == S_PACKED_F22) {
		c = (uint32_t)pack(orig + CODE_AT + CODE, TAIL, z, sizeof z);
		at = binfo(f, at, TAIL, c, 3);
		memcpy(f + at, z, c);
		at += c;
	} else {
		at = binfo(f, at, TAIL, TAIL, 0);
		memcpy(f + at, orig + CODE_AT + CODE, TAIL);
		at += TAIL;
	}
	at += 13;                               /* alignment before the PackHeader, as upx 4.2.4 wrote it */

	ph = at;                                /* the format-22 PackHeader: the WHOLE file's sizes */
	memcpy(f + ph, "UPX!", 4);
	f[ph + 4] = 14; f[ph + 5] = 22; f[ph + 6] = 3; f[ph + 7] = 9;
	put32(f + ph + 16, ORIG);
	put32(f + ph + 20, ph);
	put32(f + ph + 24, ORIG);
	return ph + 36;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	char path[256];
	kof_engine *eng = keng_open(db);
	kof_scanner *sc;
	uint8_t *f = malloc(FILEMAX);
	unsigned round, sh;

	if (!eng) {
		printf("upx elf stored: no database at %s - skipped\n", db);
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc || !f)
		return 1;
	snprintf(path, sizeof path, "build/test/upx-stored-%d.bin", (int)getpid());

	for (sh = S_STORED_F22; sh <= S_UNKNOWN_METHOD; sh++) {
		for (round = 0; round < 4; round++) {
			struct kof_scan_option opt;
			uint32_t flen, i;
			FILE *fp;

			make_original(round);
			if (sh == S_FILTER49)
				plant_branches(round);
			flen = build(f, (enum shape)sh);
			if (!flen)
				continue;               /* a marker the filter could not keep: not a file UPX writes */
			fp = fopen(path, "wb");
			if (!fp || fwrite(f, 1, flen, fp) != flen)
				return 1;
			fclose(fp);

			memset(&opt, 0, sizeof opt);
			opt.max_produced_bytes = 1u << 20;
			opt.max_resident_bytes = 16u << 20;
			opt.max_object_bytes   = 2u << 20;
			got_found = 0;
			got_len = 0;
			got_broken = root_broken = 0;
			kscan_path(sc, path, &opt, on_object, NULL);
			CK(got_found, "shape %u round %u: no unpacked object", sh, round);
			if (!got_found)
				continue;
			if (sh == S_UNKNOWN_METHOD) {
				/* header page and its gap only, and SAID: the layout wants the code segment */
				CK(got_len == CODE_AT, "shape %u round %u: %llu bytes, want the header page %u",
				   sh, round, (unsigned long long)got_len, CODE_AT);
				CK(root_broken == KOF_BROKEN_UNSUPPORTED,
				   "shape %u round %u: a chain cut by a coding this build lacks is broken=%u (root %u), want UNSUPPORTED",
				   sh, round, got_broken, root_broken);
				continue;
			}
			CK(got_len == ORIG, "shape %u round %u: unpacked %llu bytes, the original is %u",
			   sh, round, (unsigned long long)got_len, ORIG);
			for (i = 0; i < ORIG && i < got_len && got_obj[i] == orig[i]; i++)
				;
			CK(i == ORIG, "shape %u round %u: first byte that is not the original: %u", sh, round, i);
			CK(got_broken == KOF_BROKEN_NONE && root_broken == KOF_BROKEN_NONE,
			   "shape %u round %u: a whole unpack is broken=%u (root %u)", sh, round, got_broken, root_broken);
		}
	}
	unlink(path);
	kscan_free(sc);
	keng_close(eng);
	free(f);
	printf("upx elf stored: %u failure(s)\n", fails);
	return fails ? 1 : 0;
}
