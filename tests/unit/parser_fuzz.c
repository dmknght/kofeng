/*
 * parser_fuzz - build hostile headers on purpose and see what the collectors do.
 *
 * Mutating real files finds what a bit flip does. This finds what a file built to
 * be wrong does, which is a different set: every field is drawn from a
 * distribution that favours the values an attacker would choose - zero, one,
 * 0xffffffff, exactly the file size, one past it, one before it - so the corners
 * get hit deliberately rather than eventually.
 *
 * What is asserted, on every generated object:
 *
 *   the parser returns, and returns something readable
 *   the regions still partition the object exactly
 *   no extent runs past the end of the object or wraps
 *
 * That last set is the real payload. A parser can survive hostile input and still
 * hand out a range that walks off the mapping, and the only thing standing
 * between that and a read past the end of an mmap is this check.
 *
 * Deterministic: the generator is seeded, so a failure names a seed and an index
 * that reproduce it exactly. A fuzzer that cannot reproduce its own findings is a
 * fuzzer that finds things once.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/gzip.h>

#include "partition_check.h"
#include "../../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../../libkofeng/kofparsers/containers/docole_parse.h"
#include "../../libkofeng/kofparsers/containers/zip_parse.h"

#define OBJ_MAX 8192
#define ROUNDS  20000

/* xorshift, so the sequence is the same on every machine and a seed is a
 * reproduction rather than a hint. */
static uint64_t rng_state = 1;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

/*
 * A value for a field that indexes or sizes something.
 *
 * Uniform random would spend nearly all its time on values so large that every
 * bounds check rejects them at the first branch, and would almost never produce
 * the interesting ones: one byte short, one byte long, exactly at the edge. The
 * boundaries are drawn far more often than they would occur by chance.
 */
static uint32_t hostile(uint64_t obj_size)
{
	switch (rnd() % 12) {
	case 0:  return 0;
	case 1:  return 1;
	case 2:  return 0xffffffffu;
	case 3:  return 0x7fffffffu;
	case 4:  return (uint32_t)obj_size;
	case 5:  return (uint32_t)obj_size - 1;
	case 6:  return (uint32_t)obj_size + 1;
	case 7:  return (uint32_t)(obj_size / 2);
	case 8:  return 0x1000;
	case 9:  return 0x200;
	case 10: return (uint32_t)(rnd() % (obj_size + 64));
	default: return (uint32_t)rnd();
	}
}

static void put16(uint8_t *b, uint64_t off, uint16_t v)
{
	if (off + 2 > OBJ_MAX)
		return;
	b[off] = (uint8_t)v;
	b[off + 1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *b, uint64_t off, uint32_t v)
{
	if (off + 4 > OBJ_MAX)
		return;
	b[off] = (uint8_t)v;
	b[off + 1] = (uint8_t)(v >> 8);
	b[off + 2] = (uint8_t)(v >> 16);
	b[off + 3] = (uint8_t)(v >> 24);
}

/* A PE image whose every interesting field is drawn from the hostile set. */
static uint64_t gen_pe(uint8_t *b)
{
	uint64_t n = 512 + rnd() % (OBJ_MAX - 512);
	uint64_t lf, opt, sectab;
	uint32_t nsec, i;
	int is64 = (rnd() % 4) == 0;

	memset(b, 0, OBJ_MAX);
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	b[0] = 'M';
	b[1] = 'Z';

	/* Usually somewhere sane, sometimes not: a stub that reaches past the end
	 * is the first thing to get right and the easiest to get wrong. */
	lf = (rnd() % 4) ? 0x40 + (rnd() % 256) : hostile(n);
	put32(b, 0x3c, (uint32_t)lf);
	if (lf + 4 + 20 > OBJ_MAX)
		return n;

	b[lf] = 'P'; b[lf + 1] = 'E'; b[lf + 2] = 0; b[lf + 3] = 0;

	nsec = (rnd() % 8) ? (uint32_t)(rnd() % 12) : hostile(n);
	put16(b, lf + 4 + 0,  (uint16_t)(rnd() % 3 ? 0x014c : rnd()));
	put16(b, lf + 4 + 2,  (uint16_t)nsec);
	put16(b, lf + 4 + 16, (uint16_t)((rnd() % 3) ? (is64 ? 240 : 224)
						     : (uint16_t)rnd()));

	opt = lf + 4 + 20;
	put16(b, opt, (uint16_t)((rnd() % 5) ? (is64 ? 0x20b : 0x10b) : rnd()));
	put32(b, opt + 4,  hostile(n));            /* SizeOfCode */
	put32(b, opt + 16, hostile(n));            /* AddressOfEntryPoint */
	put32(b, opt + 32, (rnd() % 3) ? 0x1000 : hostile(n));  /* SectionAlign */
	put32(b, opt + 36, (rnd() % 3) ? 0x200  : hostile(n));  /* FileAlign */
	put32(b, opt + 56, hostile(n));            /* SizeOfImage */
	put32(b, opt + 60, hostile(n));            /* SizeOfHeaders */
	put32(b, opt + (is64 ? 108 : 92), (rnd() % 3) ? 16 : hostile(n));

	/* The certificate directory: the one that is a file offset, and therefore
	 * the one that can point straight into a section. */
	{
		uint64_t dir = opt + (is64 ? 112 : 96);
		put32(b, dir + 4 * 8,     hostile(n));
		put32(b, dir + 4 * 8 + 4, hostile(n));
	}

	sectab = opt + ((rnd() % 3) ? (is64 ? 240u : 224u) : (uint32_t)(rnd() % 512));
	for (i = 0; i < nsec && i < 96; i++) {
		uint64_t s = sectab + (uint64_t)i * 40;
		if (s + 40 > OBJ_MAX)
			break;
		put32(b, s + 8,  hostile(n));   /* VirtualSize */
		put32(b, s + 12, hostile(n));   /* VirtualAddress */
		put32(b, s + 16, hostile(n));   /* SizeOfRawData */
		put32(b, s + 20, hostile(n));   /* PointerToRawData */
		put32(b, s + 36, (uint32_t)rnd());
	}
	return n;
}

/* An ELF object built the same way. */
static uint64_t gen_elf(uint8_t *b)
{
	uint64_t n = 128 + rnd() % (OBJ_MAX - 128);
	int is64 = rnd() % 2;
	uint64_t i;

	memset(b, 0, OBJ_MAX);
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	memcpy(b, "\177ELF", 4);
	b[4] = (uint8_t)((rnd() % 5) ? (is64 ? 2 : 1) : rnd());
	b[5] = (uint8_t)((rnd() % 5) ? 1 : rnd());
	b[6] = 1;

	put16(b, 16, (uint16_t)(rnd() % 5));            /* e_type */
	put16(b, 18, (uint16_t)((rnd() % 3) ? 62 : rnd()));

	if (is64) {
		put32(b, 24, hostile(n));               /* e_entry lo */
		put32(b, 32, hostile(n));               /* e_phoff lo */
		put32(b, 40, hostile(n));               /* e_shoff lo */
		put16(b, 54, (uint16_t)((rnd() % 3) ? 56 : rnd()));
		put16(b, 56, (uint16_t)(rnd() % 40));   /* e_phnum */
		put16(b, 58, (uint16_t)((rnd() % 3) ? 64 : rnd()));
		put16(b, 60, (uint16_t)(rnd() % 40));   /* e_shnum */
		put16(b, 62, (uint16_t)(rnd() % 40));
	} else {
		put32(b, 24, hostile(n));
		put32(b, 28, hostile(n));
		put32(b, 32, hostile(n));
		put16(b, 42, (uint16_t)((rnd() % 3) ? 32 : rnd()));
		put16(b, 44, (uint16_t)(rnd() % 40));
		put16(b, 46, (uint16_t)((rnd() % 3) ? 40 : rnd()));
		put16(b, 48, (uint16_t)(rnd() % 40));
		put16(b, 50, (uint16_t)(rnd() % 40));
	}
	return n;
}

/*
 * A gzip wrapper whose optional fields are as wrong as they can be.
 *
 * The whole attack surface of this header is the three variable fields, and it is
 * not the compressed stream: FEXTRA states its own length, FNAME and FCOMMENT run
 * to a terminator that need not be there, and each one moves the cursor the next
 * one is read from. A length one past the end, or a name with no NUL, walks that
 * cursor off the object - and since the regions are cut at the cursor, a cursor
 * past the end is a region past the end.
 *
 * So the fields are generated to land exactly on the corners: length zero, length
 * equal to what is left, one more than that, and 0xffff. Terminators are omitted
 * on purpose about half the time.
 */
/*
 * A compound file, plausible in shape and wrong in the places that matter.
 *
 * The fields corrupted here are the ones that decide whether a walk ends. The
 * sector shift decides where every structure is, so a wrong one must stop the parse
 * rather than send it reading at computed nonsense; the chain heads and the
 * directory's child and sibling links are what a cycle is made of, so they are
 * drawn from a range that includes valid sectors, invalid sectors and markers.
 *
 * Directory entries get real structure names, because the class a stream lands in
 * is decided by its name and a fuzzer that only writes noise never exercises that
 * decision - it would test the walk and never the classification.
 */
static uint64_t gen_docole(uint8_t *b)
{
	static const char *const names[] = {
		"Macros", "VBA", "ObjectPool", "WordDocument", "ThisDocument",
		"\005SummaryInformation", "_VBA_PROJECT", "Data"
	};
	uint64_t n = 512u + (rnd() % 15u) * 512u;
	uint64_t i, at;
	uint32_t nsec;

	memset(b, 0, OBJ_MAX);
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	memcpy(b, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8);
	nsec = (uint32_t)(n / 512u);

	put16(b, 0x18, 0x3e);
	put16(b, 0x1a, (rnd() % 8u) ? 3u : (uint16_t)(rnd() % 6u));
	put16(b, 0x1c, (rnd() % 8u) ? 0xfffeu : (uint16_t)rnd());
	put16(b, 0x1e, (rnd() % 8u) ? 9u : (uint16_t)(rnd() % 20u));
	put16(b, 0x20, (rnd() % 8u) ? 6u : (uint16_t)(rnd() % 20u));
	put32(b, 0x38, (rnd() % 8u) ? 4096u : (uint32_t)rnd());

	/* Chain heads: usually a sector this file has, sometimes one it does not. */
	put32(b, 0x30, (rnd() % 4u) ? (uint32_t)(rnd() % nsec) : (uint32_t)rnd());
	put32(b, 0x3c, (rnd() % 4u) ? (uint32_t)(rnd() % nsec) : (uint32_t)rnd());
	put32(b, 0x44, (rnd() % 4u) ? 0xfffffffeu : (uint32_t)(rnd() % nsec));
	for (i = 0; i < 109u; i++)
		put32(b, 0x4c + i * 4u,
		      (rnd() % 3u) ? (uint32_t)(rnd() % nsec) : 0xffffffffu);

	for (at = 512u; at + 128u <= n; at += 128u) {
		const char *nm = names[rnd() % (sizeof names / sizeof names[0])];
		uint32_t k;

		if (rnd() % 3u)
			continue;              /* left as noise, which is also a case */
		for (k = 0; nm[k]; k++)
			put16(b, at + k * 2u, (uint16_t)(uint8_t)nm[k]);
		put16(b, at + k * 2u, 0);
		put16(b, at + 0x40u, (uint16_t)((k + 1u) * 2u));
		b[at + 0x42u] = (uint8_t)((rnd() % 8u) ? ((rnd() % 2u) ? 1u : 2u)
						       : (uint8_t)rnd());
		put32(b, at + 0x44u, (uint32_t)(rnd() % 48u));
		put32(b, at + 0x48u, (uint32_t)(rnd() % 48u));
		put32(b, at + 0x4cu, (uint32_t)(rnd() % 48u));
		put32(b, at + 0x74u, (uint32_t)(rnd() % nsec));
		put32(b, at + 0x78u, (uint32_t)(rnd() % 70000u));
		put32(b, at + 0x7cu, (rnd() % 8u) ? 0u : (uint32_t)rnd());
	}
	return n;
}

/*
 * A zip, plausible in shape and wrong where it counts.
 *
 * The fields corrupted are the ones two readers can disagree about, because that
 * disagreement is the whole bug class this format has: the end record's declared
 * directory offset and size, which decide where the walk starts and whether the
 * archive is treated as shifted; each entry's local header offset, which decides
 * where its data is looked for; and the two independent name lengths, which decide
 * whether the two copies of a name line up.
 *
 * Sizes are drawn from a set that includes the saturated values, so the ZIP64 path
 * is entered on roughly one archive in eight rather than never.
 */
static uint64_t gen_zip(uint8_t *b)
{
	uint64_t n = 200u + rnd() % 3000u;
	uint64_t at = 0, cd, i;
	uint32_t nent = 1u + (uint32_t)(rnd() % 6u);
	uint32_t off[8], k;

	memset(b, 0, OBJ_MAX);
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	/* Local headers with a little data after each. */
	for (k = 0; k < nent && at + 64u < n; k++) {
		uint32_t nlen = (uint32_t)(rnd() % 12u);
		uint32_t xlen = (uint32_t)(rnd() % 8u);
		uint32_t csz  = (uint32_t)(rnd() % 40u);

		off[k] = (uint32_t)at;
		put32(b, at, 0x04034b50u);
		put16(b, at + 0x06, (uint16_t)((rnd() % 8u) ? 0 : rnd()));
		put16(b, at + 0x08, (uint16_t)((rnd() % 3u) ? (rnd() % 2u ? 0 : 8)
							    : rnd() % 100u));
		put32(b, at + 0x12, csz);
		put32(b, at + 0x16, csz);
		put16(b, at + 0x1a, (uint16_t)nlen);
		put16(b, at + 0x1c, (uint16_t)xlen);
		for (i = 0; i < nlen && at + 30u + i < n; i++)
			b[at + 30u + i] = (uint8_t)('a' + (rnd() % 26));
		at += 30u + nlen + xlen + csz;
	}
	nent = k;
	if (!nent || at + 64u >= n)
		return n;

	/* The central directory, whose copies of the lengths need not agree. */
	cd = at;
	for (k = 0; k < nent && at + 64u < n; k++) {
		uint32_t nlen = (uint32_t)(rnd() % 12u);

		put32(b, at, 0x02014b50u);
		put16(b, at + 0x08, (uint16_t)((rnd() % 8u) ? 0 : 1));
		put16(b, at + 0x0a, (uint16_t)((rnd() % 3u) ? (rnd() % 2u ? 0 : 8)
							    : 99));
		put32(b, at + 0x14, (uint32_t)((rnd() % 8u) ? rnd() % 60u
							    : 0xffffffffu));
		put32(b, at + 0x18, (uint32_t)((rnd() % 8u) ? rnd() % 900u
							    : 0xffffffffu));
		put16(b, at + 0x1c, (uint16_t)nlen);
		put16(b, at + 0x1e, (uint16_t)(rnd() % 8u));
		put16(b, at + 0x20, (uint16_t)(rnd() % 8u));
		/* Usually where a local header is, sometimes anywhere at all. */
		put32(b, at + 0x2a, (rnd() % 4u) ? off[rnd() % nent]
						 : (uint32_t)rnd());
		for (i = 0; i < nlen && at + 46u + i < n; i++)
			b[at + 46u + i] = (uint8_t)((rnd() % 8u)
						    ? 'a' + (rnd() % 26) :
						    (rnd() % 2u ? '.' : '/'));
		at += 46u + nlen;
	}

	if (at + 22u > n)
		return n;
	put32(b, at, 0x06054b50u);
	put16(b, at + 0x0a, (uint16_t)((rnd() % 8u) ? nent : 0xffffu));
	put32(b, at + 0x0c, (uint32_t)((rnd() % 8u) ? at - cd : 0xffffffffu));
	put32(b, at + 0x10, (uint32_t)((rnd() % 4u) ? cd :
				       (rnd() % 2u ? cd + 77u : 0xffffffffu)));
	put16(b, at + 0x14, (uint16_t)((rnd() % 4u) ? n - at - 22u
						    : rnd() % 200u));
	return n;
}

static uint64_t gen_gzip(uint8_t *b)
{
	uint64_t n = 4 + rnd() % 300;
	uint64_t at = 10;
	uint8_t flg = (uint8_t)(rnd() & 0x3fu);
	uint64_t i;

	memset(b, 0, OBJ_MAX);
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	b[0] = 0x1f;
	b[1] = 0x8b;
	b[2] = (uint8_t)((rnd() % 8) ? 8 : rnd());   /* CM, usually deflate */
	/* Reserved bits set sometimes: RFC 1952 says a reader must refuse those,
	 * and a scanner must still be able to look at one without falling over. */
	b[3] = (uint8_t)((rnd() % 8) ? flg : (flg | 0xe0u));

	if ((b[3] & KOF_GZIP_FEXTRA) && at + 2 <= n) {
		uint64_t left = n - at - 2;
		uint16_t xlen;

		switch (rnd() % 5) {
		case 0:  xlen = 0; break;
		case 1:  xlen = (uint16_t)left; break;
		case 2:  xlen = (uint16_t)(left + 1); break;
		case 3:  xlen = 0xffffu; break;
		default: xlen = (uint16_t)(rnd() % 64); break;
		}
		put16(b, at, xlen);
		at += 2 + xlen;
		if (at > n)
			at = n;
	}
	/* Terminate the string fields only sometimes. An unterminated one is the
	 * case that matters: the walk has to stop at the end of the object. */
	if ((b[3] & KOF_GZIP_FNAME) && at < n) {
		uint64_t len = rnd() % 40;

		for (i = 0; i < len && at + i < n; i++)
			b[at + i] = (uint8_t)('a' + (rnd() % 26));
		if ((rnd() % 2) && at + i < n)
			b[at + i] = 0;
		at += i + 1;
	}
	if ((b[3] & KOF_GZIP_FCOMMENT) && at < n) {
		uint64_t len = rnd() % 40;

		for (i = 0; i < len && at + i < n; i++)
			b[at + i] = (uint8_t)('A' + (rnd() % 26));
		if ((rnd() % 2) && at + i < n)
			b[at + i] = 0;
	}
	return n;
}

int main(int argc, char **argv)
{
	static uint8_t obj[OBJ_MAX];
	struct kof_elf_info *ei = malloc(sizeof *ei);
	struct kof_pe_info *pi = malloc(sizeof *pi);
	struct kof_gzip_info *gi = malloc(sizeof *gi);
	struct kof_docole_info *oi = malloc(sizeof *oi);
	struct kof_zip_info *zi = malloc(sizeof *zi);
	struct pc_report rep = { 0, 0, 0 };
	uint64_t rounds = ROUNDS, seed = 20240101u;
	uint64_t r, pe_parsed = 0, elf_parsed = 0, gz_parsed = 0, ole_parsed = 0,
		 zip_parsed = 0;
	char what[64];

	if (argc > 1)
		seed = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);
	if (!ei || !pi || !gi || !oi || !zi)
		return 1;

	rng_state = seed ? seed : 1;

	for (r = 0; r < rounds; r++) {
		struct kof_obj_ctx ctx;
		uint64_t n;
		int want = (int)(rnd() % 5);   /* PE, ELF, gzip, docole, zip */

		memset(&ctx, 0, sizeof ctx);
		n = want == 0 ? gen_pe(obj) : want == 1 ? gen_elf(obj)
			: want == 2 ? gen_gzip(obj)
			: want == 3 ? gen_docole(obj) : gen_zip(obj);
		{
			kof_buf buf = kof_buf_make(obj, n);

			snprintf(what, sizeof what, "seed=%llu round=%llu %s",
				 (unsigned long long)seed, (unsigned long long)r,
				 want == 0 ? "PE" : want == 1 ? "ELF"
				 : want == 2 ? "gzip"
				 : want == 3 ? "docole" : "zip");

			if (want == 0 && kof_pe_sniff(buf)) {
				if (kof_pe_parse(buf, pi, &ctx)) {
					pe_parsed++;
					pc_check(what, &ctx, n, kof_pe_region_bits,
						 KOF_PE_REGION_COUNT, &rep);
				}
			} else if (want == 1 && kof_elf_sniff(buf)) {
				if (kof_elf_parse(buf, ei, &ctx)) {
					elf_parsed++;
					pc_check(what, &ctx, n, kof_elf_region_bits,
						 KOF_ELF_REGION_COUNT, &rep);
				}
			} else if (want == 2 && kof_gzip_sniff(buf)) {
				if (kof_gzip_parse(buf, gi, &ctx)) {
					gz_parsed++;
					pc_check(what, &ctx, n, kof_gzip_region_bits,
						 KOF_GZIP_REGION_COUNT, &rep);
				}
			} else if (want == 3 && kof_docole_sniff(buf)) {
				if (kof_docole_parse(buf, oi, &ctx)) {
					ole_parsed++;
					pc_check(what, &ctx, n, kof_docole_region_bits,
						 KOF_DOCOLE_REGION_COUNT, &rep);
				}
			} else if (want == 4 && kof_zip_sniff(buf)) {
				if (kof_zip_parse(buf, zi, &ctx)) {
					zip_parsed++;
					pc_check(what, &ctx, n, kof_zip_region_bits,
						 KOF_ZIP_REGION_COUNT, &rep);
				}
			}
		}
	}

	free(ei);
	free(pi);
	free(gi);
	free(oi);
	free(zi);
	printf("hostile headers: %llu round(s), parsed ELF %llu PE %llu gzip %llu "
	       "docole %llu zip %llu, partition %llu/%llu\n",
	       (unsigned long long)rounds, (unsigned long long)elf_parsed,
	       (unsigned long long)pe_parsed, (unsigned long long)gz_parsed,
	       (unsigned long long)ole_parsed,
	       (unsigned long long)zip_parsed,
	       (unsigned long long)(rep.checked - rep.failed),
	       (unsigned long long)rep.checked);
	return rep.failed != 0;
}