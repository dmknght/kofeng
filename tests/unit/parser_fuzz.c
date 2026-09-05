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

#include "../../libkofeng/kofparsers/kofformat.h"
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
#include "../../libkofeng/kofparsers/containers/tar_parse.h"
#include "../../libkofeng/kofparsers/containers/sevenzip_parse.h"
#include "../../libkofeng/kofparsers/containers/rar_parse.h"
#include "../../libkofeng/kofparsers/containers/xz_parse.h"
#include "../../libkofeng/kofparsers/containers/rtf_parse.h"
#include "../../libkofeng/kofparsers/containers/pdf_parse.h"

/*
 * Big enough to reach the caps.
 *
 * It was 8192, which is plenty of room for a hostile header and not enough for a
 * hostile COUNT: an archive fills its entry table at 2048 entries and the fixed part
 * of a RAR file block is 32 bytes, so no object under sixty four kilobytes could ever
 * raise ENTRIES_FULL - and the anomaly report at the end read that as a bit the
 * parser never sets. This is twice the largest table in the tree, which leaves room
 * for the signature and for a swarm to start late.
 */
#define OBJ_MAX 131072
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

static uint32_t rd16(const uint8_t *b, uint64_t off)
{
	return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8);
}

static uint32_t rd32(const uint8_t *b, uint64_t off)
{
	return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
	       ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
}

static void put16(uint8_t *b, uint64_t off, uint16_t v)
{
	if (off + 2 > OBJ_MAX)
		return;
	b[off] = (uint8_t)v;
	b[off + 1] = (uint8_t)(v >> 8);
}

static void put64w(uint8_t *b, uint64_t off, uint64_t v);

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
	/*
	 * Sometimes SHORTER THAN THE HEADER IT DECLARES.
	 *
	 * The floor used to be 128 bytes, so an ELF64 header - 64 bytes - always
	 * fitted and TRUNCATED_HEADER was unreachable. A file of five bytes that
	 * begins \177ELF is a thing a scanner is handed, and the collector has
	 * to answer for it.
	 */
	uint64_t n = (rnd() % 12) ? 128 + rnd() % (OBJ_MAX - 128)
				  : 5 + rnd() % 60;
	int is64 = rnd() % 2;
	uint64_t i;

	memset(b, 0, OBJ_MAX);
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	memcpy(b, "\177ELF", 4);
	b[4] = (uint8_t)((rnd() % 5) ? (is64 ? 2 : 1) : rnd());
	b[5] = (uint8_t)((rnd() % 5) ? 1 : rnd());
	/* e_version. Nailed to 1 before, which is why BAD_VERSION was a bit the
	 * parser declared and this test could never reach. */
	b[6] = (uint8_t)((rnd() % 6) ? 1 : rnd());

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

	/*
	 * REAL PROGRAM AND SECTION HEADERS, NOT RANDOM BYTES.
	 *
	 * The tables used to be whatever noise filled the object, so p_type was
	 * PT_LOAD once in four billion and every rule about a LOAD segment - its
	 * file size against its memory size, one overlapping another, an entry
	 * point that lands outside an executable one - was unreachable. Two of
	 * those anomalies carry weight in the heuristic model, so they were
	 * scored facts that no test had ever seen raised.
	 *
	 * The tables are written where the header says they are, when it says
	 * somewhere they fit. The FIELDS stay hostile: this makes the shape
	 * plausible so the walk is entered, not the contents sane.
	 */
	{
		uint64_t phoff = is64 ? rd32(b, 32) : rd32(b, 28);
		uint64_t shoff = is64 ? rd32(b, 40) : rd32(b, 32);
		uint32_t phnum = is64 ? rd16(b, 56) : rd16(b, 44);
		uint32_t shnum = is64 ? rd16(b, 60) : rd16(b, 48);
		uint32_t pe = is64 ? 56u : 32u, se = is64 ? 64u : 40u;
		uint32_t k;

		for (k = 0; k < phnum; k++) {
			uint64_t o = phoff + (uint64_t)k * pe;

			if (o + pe > n)
				break;
			/* PT_LOAD most of the time, so the LOAD rules run. */
			put32(b, o, (rnd() % 4) ? 1u : (uint32_t)(rnd() % 8));
			if (is64) {
				put32(b, o + 4, (uint32_t)(rnd() % 8));
				put64w(b, o + 8,  hostile(n));   /* p_offset */
				put64w(b, o + 16, hostile(n));   /* p_vaddr  */
				put64w(b, o + 32, hostile(n));   /* p_filesz */
				put64w(b, o + 40, hostile(n));   /* p_memsz  */
			} else {
				put32(b, o + 4,  hostile(n));
				put32(b, o + 8,  hostile(n));
				put32(b, o + 16, hostile(n));
				put32(b, o + 20, hostile(n));
				put32(b, o + 24, (uint32_t)(rnd() % 8));
			}
		}
		for (k = 0; k < shnum; k++) {
			uint64_t o = shoff + (uint64_t)k * se;

			if (o + se > n)
				break;
			put32(b, o, hostile(n));                 /* sh_name */
			put32(b, o + 4, (uint32_t)(rnd() % 20)); /* sh_type */
			if (is64) {
				put64w(b, o + 24, hostile(n));   /* sh_offset */
				put64w(b, o + 32, hostile(n));   /* sh_size   */
			} else {
				put32(b, o + 16, hostile(n));
				put32(b, o + 20, hostile(n));
			}
		}
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
static void put64w(uint8_t *b, uint64_t off, uint64_t v)
{
	put32(b, off, (uint32_t)v);
	put32(b, off + 4, (uint32_t)(v >> 32));
}

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

/*
 * A 7z, which is 32 bytes of start header and then whatever it points at.
 *
 * Everything that matters is in those 32 bytes: the offset and size of the real
 * header, both stated relative to the end of the start header and both 64 bit. So
 * they are drawn from a set built to break the addition - past the end, at the very
 * end, and large enough that adding the two overflows.
 *
 * The bytes at the far end are then written as a header the probe will try to read:
 * a coded-header marker and a coder id, sometimes truncated mid-field, which is what
 * exercises reading LZMA properties out of a header that stops early.
 */
static void put64(uint8_t *b, uint64_t off, uint64_t v)
{
	uint32_t k;

	if (off + 8 > OBJ_MAX)
		return;
	for (k = 0; k < 8u; k++)
		b[off + k] = (uint8_t)(v >> (8u * k));
}

static uint64_t gen_7z(uint8_t *b)
{
	uint64_t n = 64u + (rnd() % (OBJ_MAX - 128u));
	uint64_t off, size;
	uint32_t k;

	for (k = 0; k < n; k++)
		b[k] = (uint8_t)((rnd() % 4u) ? 0 : rnd());

	memcpy(b, "7z\xbc\xaf\x27\x1c", 6);
	b[6] = (uint8_t)(rnd() % 4u);   /* major */
	b[7] = (uint8_t)(rnd() % 8u);   /* minor */

	switch (rnd() % 6u) {
	case 0:  off = rnd() % n; break;
	case 1:  off = n; break;                       /* exactly at the end */
	case 2:  off = 0xffffffffffffff00ull; break;   /* overflows the addition */
	case 3:  off = n - 32u; break;
	case 4:  off = 0; break;
	default: off = rnd(); break;
	}
	switch (rnd() % 5u) {
	case 0:  size = rnd() % 256u; break;
	case 1:  size = 0; break;
	case 2:  size = 0xffffffffffffffffull; break;
	case 3:  size = n; break;
	default: size = rnd() % 64u; break;
	}
	put64(b, 12, off);
	put64(b, 20, size);

	/* Something at the far end that looks like a header worth probing. */
	if (off < n - 16u) {
		uint64_t at = 32u + off;

		if (at + 16u <= n) {
			b[at] = (uint8_t)((rnd() % 4u) ? KOF_7Z_ID_ENCODED
						       : KOF_7Z_ID_HEADER);
			b[at + 1] = KOF_7Z_ID_PACKINFO;
			for (k = 2; k < 16u; k++)
				b[at + k] = (uint8_t)rnd();
		}
	}
	return n;
}

/*
 * A RAR3, which is a chain: every block says how long its own header is and how much
 * data follows, and adding the two is where the next block begins.
 *
 * So those two fields are the whole attack surface and both are made hostile. A
 * HEAD_SIZE below the seven bytes it is part of would let the walk stand still; an
 * ADD_SIZE near the 32 bit ceiling makes the addition overflow; a NAME_SIZE larger
 * than the block it sits in points a name reader past the header. The LARGE flag is
 * set at random on top, which turns two of those into 64 bit values read from
 * further into a header that may not be that long.
 */
static uint64_t gen_rar(uint8_t *b)
{
	uint64_t n = 32u + (rnd() % 4096u);
	uint64_t at;
	uint32_t k;

	for (k = 0; k < n; k++)
		b[k] = (uint8_t)((rnd() % 4u) ? 0 : rnd());

	memcpy(b, "Rar!\x1a\x07", 6);
	b[6] = (uint8_t)((rnd() % 8u) ? 0x00 : 0x01);   /* mostly RAR3 */
	if (b[6] == 0x01)
		b[7] = (uint8_t)((rnd() % 2u) ? 0x00 : rnd());

	/*
	 * Sometimes an archive of nothing but minimal file blocks.
	 *
	 * The entry and extent tables are the two bounds a RAR can push on, and
	 * they are not reached by a random walk: a block whose size field is
	 * random averages hundreds of bytes, so a few dozen of them fill the
	 * object long before two thousand of them fill the table.
	 */
	if (rnd() % 4u == 0) {
		n = OBJ_MAX;            /* the table is the point, so use the room */
		at = 7;
		while (at + 32u <= n) {
			put16(b, at + 0, (uint16_t)rnd());
			b[at + 2] = 0x74;               /* file */
			put16(b, at + 3, 0);            /* no ADD_SIZE */
			put16(b, at + 5, 32u);
			put32(b, at + 7, 0);
			put32(b, at + 11, 0);
			b[at + 25] = 0x30;
			put16(b, at + 26, 0);
			at += 32u;
		}
		return n;
	}

	at = 7;
	while (at + 32u <= n) {
		uint16_t flags = 0, size;
		uint8_t typ = (uint8_t)("\x72\x73\x74\x74\x74\x7a\x75\x7b"[rnd() % 8]);
		uint32_t add;

		if (rnd() % 3u) flags |= KOF_RAR3_F_ADD_SIZE;
		if (rnd() % 4u == 0) flags |= KOF_RAR3_F_LARGE;
		if (rnd() % 6u == 0) flags |= KOF_RAR3_F_ENCRYPTED;
		if (rnd() % 8u == 0) flags |= KOF_RAR3_F_SOLID;
		if (rnd() % 8u == 0) flags |= KOF_RAR3_F_SPLIT_AFTER;

		switch (rnd() % 6u) {
		case 0:  size = (uint16_t)(rnd() % 7u); break;     /* below the base */
		case 1:  size = 32u; break;
		case 2:  size = (uint16_t)(32u + rnd() % 64u); break;
		case 3:  size = 0xffffu; break;
		case 4:  size = 7u; break;
		default: size = (uint16_t)(rnd() % 512u); break;
		}
		switch (rnd() % 5u) {
		case 0:  add = (uint32_t)(rnd() % 256u); break;
		case 1:  add = 0; break;
		case 2:  add = 0xfffffff0u; break;                 /* overflows */
		case 3:  add = (uint32_t)n; break;
		default: add = (uint32_t)(rnd() % 4096u); break;
		}

		put16(b, at + 0, (uint16_t)rnd());                 /* HEAD_CRC */
		b[at + 2] = typ;
		put16(b, at + 3, flags);
		put16(b, at + 5, size);
		put32(b, at + 7, add);                             /* PACK_SIZE */
		put32(b, at + 11, (uint32_t)rnd());                /* UNP_SIZE */
		b[at + 25] = (uint8_t)(0x30u + rnd() % 8u);        /* METHOD */
		/* A name length that may or may not fit in the block that declared it. */
		put16(b, at + 26, (uint16_t)((rnd() % 2u) ? rnd() % 64u : rnd()));
		put32(b, at + 28, (uint32_t)rnd());
		for (k = 32u; k < 64u && at + k < n; k++)
			b[at + k] = (rnd() % 3u)
				? (uint8_t)"../\\ab"[rnd() % 6]
				: (uint8_t)rnd();

		at += (size < 7u ? 7u : size) + (rnd() % 2u ? 0 : add % 256u);
	}
	return n;
}

/*
 * An xz stream, with the two ends made hostile.
 *
 * The parse reads BACKWARDS - the footer gives the index and the index gives the
 * blocks - so the fields worth breaking are the backward size, the record counts
 * and the per-block sizes, and breaking them has to leave the magic intact or the
 * sniff refuses before anything is exercised.
 */
static uint64_t gen_xz(uint8_t *b)
{
	uint64_t n = 64u + (rnd() % (OBJ_MAX - 128u));
	uint64_t foot, k;

	for (k = 0; k < n; k++)
		b[k] = (uint8_t)((rnd() % 4u) ? 0 : rnd());

	memcpy(b, "\xfd" "7zXZ", 6);
	b[6] = 0;
	b[7] = (uint8_t)("\x00\x01\x04\x0a\x0f"[rnd() % 5]);   /* check id */
	put32(b, 8, (uint32_t)rnd());

	n &= ~(uint64_t)3u;
	if (n < 32u)
		n = 32u;
	foot = n - 12u;
	put32(b, (uint32_t)foot, (uint32_t)rnd());        /* footer CRC */
	switch (rnd() % 5u) {                             /* backward size */
	case 0:  put32(b, (uint32_t)foot + 4u, 0); break;
	case 1:  put32(b, (uint32_t)foot + 4u, 0xffffffffu); break;
	case 2:  put32(b, (uint32_t)foot + 4u, (uint32_t)(n / 4u)); break;
	case 3:  put32(b, (uint32_t)foot + 4u, (uint32_t)(rnd() % 8u)); break;
	default: put32(b, (uint32_t)foot + 4u, (uint32_t)rnd()); break;
	}
	b[foot + 8] = 0;
	b[foot + 9] = b[7];
	b[foot + 10] = 'Y';
	b[foot + 11] = 'Z';

	/* An index somewhere in the middle, with counts and sizes drawn hostile. */
	{
		uint64_t at = 12u + (rnd() % (n / 2u));

		if (at + 16u < foot) {
			b[at++] = 0;                      /* index indicator */
			b[at++] = (uint8_t)(rnd() % 0x90u);
			for (k = 0; k < 8u && at + 2u < foot; k++) {
				b[at++] = (uint8_t)((rnd() % 3u) ? rnd() % 0x80u
							        : 0xffu);
				b[at++] = (uint8_t)(rnd() % 0x80u);
			}
		}
	}
	/* And a block header where one would begin. */
	b[12] = (uint8_t)(rnd() % 8u);
	b[13] = (uint8_t)(rnd() % 0xc4u);
	return n;
}

/*
 * An RTF, which is the one format here with no offsets to break.
 *
 * So what is made hostile is the SYNTAX: unbalanced braces, control words longer
 * than any reader accepts, \bin lengths that run past the end, hex runs with junk
 * in them, and nesting deep enough to matter. The header has to stay intact or the
 * sniff refuses before any of it is reached.
 */
static uint64_t gen_rtf(uint8_t *b)
{
	uint64_t n = 32u + (rnd() % (OBJ_MAX - 64u));
	uint64_t at;
	static const char *const words[] = {
		"objdata", "objclass", "objupdate", "bin", "pict", "par", "b",
		"objemb", "datastore", "fonttbl", "colortbl", "*"
	};

	memcpy(b, "{\\rtf1", 6);
	at = 6;

	/* Nesting, objects and runs are counted rather than sized, so each gets a
	 * mode that produces nothing but the thing being counted. */
	switch (rnd() % 8u) {
	case 0:                                 /* depth */
		while (at < n)
			b[at++] = '{';
		return n;
	case 1:                                 /* objects */
		while (at + 24u < n) {
			memcpy(b + at, "{\\*\\objdata 41424344}", 21);
			at += 21u;
		}
		return at;
	case 2:                                 /* runs, alternating class */
		while (at + 16u < n) {
			memcpy(b + at, "x{\\bin4 ....}", 13);
			at += 13u;
		}
		return at;
	case 3:                                 /* a \bin that swallows what follows */
		while (at + 40u < n) {
			memcpy(b + at, "{\\bin4096 {\\*\\objdata 41424344}}", 32);
			at += 32u;
		}
		return at;
	default:
		break;
	}

	while (at < n) {
		switch (rnd() % 8u) {
		case 0:
			b[at++] = '{';
			break;
		case 1:
			b[at++] = '}';
			break;
		case 2: {                       /* a control word, maybe absurd */
			const char *w = words[rnd() % 12u];
			uint32_t k = 0, len = (uint32_t)strlen(w);

			b[at++] = '\\';
			while (k < len && at < n)
				b[at++] = (uint8_t)w[k++];
			if (rnd() % 3u == 0) {  /* an over-long word */
				uint32_t j = (uint32_t)(rnd() % 200u);

				while (j-- && at < n)
					b[at++] = (uint8_t)('a' + rnd() % 26);
			}
			if (rnd() % 2u) {       /* a parameter, sometimes huge */
				char num[24];
				int m = snprintf(num, sizeof num, "%u",
						 (unsigned)((rnd() % 2u) ? rnd()
							      : rnd() % 100u));
				int q = 0;

				while (q < m && at < n)
					b[at++] = (uint8_t)num[q++];
			}
			break;
		}
		case 3: {                       /* hex, with junk in it */
			uint32_t j = rnd() % 64u;

			while (j-- && at < n)
				b[at++] = (uint8_t)("0123456789abcdef \t\r\n"
						    [rnd() % 20]);
			break;
		}
		default:
			b[at++] = (uint8_t)(rnd() % 4u ? ('a' + rnd() % 26)
						       : rnd());
			break;
		}
	}
	return n;
}

/*
 * A tar, with the fields that decide where the next header is made hostile.
 *
 * There is only one of those and it is the size: it moves the cursor, and every
 * other field is inert. So the sizes are drawn from a set that includes an ordinary
 * value, zero, a size that runs past the end, one with the leading-space padding
 * that a first attempt at this parser read as zero, and the GNU binary form whose
 * top bit turns it into a 64 bit number.
 *
 * The checksum is left wrong most of the time on purpose: it is recorded and not
 * enforced, so a fuzzer that always wrote a correct one would never exercise the
 * path where a block is treated as a header despite disagreeing with itself.
 */
static uint64_t gen_tar(uint8_t *b)
{
	uint64_t n = 512u + (rnd() % 12u) * 512u;
	uint64_t at = 0;
	uint32_t k;

	memset(b, 0, OBJ_MAX);

	while (at + 512u <= n) {
		uint32_t sz;

		for (k = 0; k < 512u; k++)
			b[at + k] = (uint8_t)((rnd() % 4u) ? 0 : rnd());

		memcpy(b + at + 257u, (rnd() % 8u) ? "ustar" : "usTar", 5);
		for (k = 0; k < 12u && rnd() % 3u; k++)
			b[at + k] = (uint8_t)('a' + (rnd() % 26));
		b[at + 156u] = (uint8_t)("05122LxKZ"[rnd() % 9]);

		switch (rnd() % 6u) {
		case 0:  sz = 0; break;
		case 1:  sz = (uint32_t)(rnd() % 2000u); break;
		case 2:  sz = 0x7fffffffu; break;            /* past the end */
		case 3:  sz = (uint32_t)(rnd() % 512u); break;
		case 4:                                      /* GNU binary form */
			b[at + 124u] = 0x80u;
			b[at + 134u] = (uint8_t)rnd();
			b[at + 135u] = (uint8_t)rnd();
			sz = 0;
			break;
		default: sz = (uint32_t)(rnd() % 100u); break;
		}
		if (sz != 0 || (rnd() % 2u)) {
			/* Left padded with spaces, which is the spelling that broke
			 * this parser on real archives. */
			char tmp[13];
			int len = snprintf(tmp, sizeof tmp, "%11o ", sz);

			if (len == 12 && !(b[at + 124u] & 0x80u))
				memcpy(b + at + 124u, tmp, 12);
		}
		if (rnd() % 4u == 0)
			memcpy(b + at + 148u, "011234\0 ", 8);  /* a plausible sum */

		at += 512u + (uint64_t)sz;
		at += (512u - (at % 512u)) % 512u;
		if (at > n)
			break;
		if (rnd() % 5u == 0)
			break;      /* stop early: an archive with no end blocks */
	}
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

/*
 * A PDF, whose hostile fields are all text.
 *
 * A PDF says how long things are in decimal, so the values that break it are not
 * bit patterns but strings a reader has to convert: a /Length of twenty digits, a
 * negative one, an object number that is not a number at all. Those go in as often
 * as ordinary ones. The header stays intact, for the reason gen_rtf gives.
 *
 * The other half is structural - a stream with no endstream, an endobj with no
 * object, a startxref pointing anywhere in the 64 bit range - because the walk
 * looks for keywords and what matters is what it does when it finds them out of
 * order.
 */
static uint64_t gen_pdf(uint8_t *b)
{
	uint64_t n = 64u + (rnd() % (OBJ_MAX - 128u));
	uint64_t at = 0;
	uint32_t obj = 1;

	/* Readers accept junk in front of the header and malware uses that, so a
	 * quarter of these are offset. */
	if (rnd() % 4u == 0) {
		uint32_t j = (uint32_t)(rnd() % 512u);

		while (at < j && at + 16u < n)
			b[at++] = (uint8_t)(rnd() % 4u ? ' ' : rnd());
	}
	memcpy(b + at, "%PDF-1.7\n", 9);
	at += 9;

	/*
	 * Sometimes nothing but object headers.
	 *
	 * The object and extent tables are counted, not sized, and an object with a
	 * dictionary and a stream averages eighty bytes - so a random document runs
	 * out of file at a few hundred objects and the caps go untested.
	 */
	if (rnd() % 4u == 0) {
		while (at + 16u < n) {
			int m = snprintf((char *)b + at, 17u, "%u 0 obj\nendobj\n",
					 (unsigned)(obj++ % 1000u));

			if (m <= 0)
				break;
			at += (uint64_t)m;
		}
		return at;
	}

	/*
	 * Sometimes a document whose objects claim each other's bytes.
	 *
	 * A stream is ended by the next "endstream" anywhere in the file, not by
	 * the object that opened it - so an object that opens a stream and never
	 * closes it swallows whatever follows, and the object inside then claims
	 * the same bytes. That is the shape a PDF is built in to be read two ways,
	 * and it is not one a random line generator arrives at.
	 */
	if (rnd() % 4u == 0) {
		static const char pair[] =
			"1 0 obj\n<< /Length 4 >>\nstream\nendobj\n"
			"2 0 obj\n<< /Type /Action >>\nendstream\nendobj\n";

		while (at + sizeof pair - 1u < n) {
			memcpy(b + at, pair, sizeof pair - 1u);
			at += sizeof pair - 1u;
		}
		return at;
	}

	while (at + 64u < n) {
		char line[128];
		int m;

		switch (rnd() % 8u) {
		case 0:                         /* an object header, sometimes junk */
			m = snprintf(line, sizeof line,
				     (rnd() % 4u) ? "%u 0 obj\n" : "%u -1 obj\n",
				     (rnd() % 8u) ? obj++ : 0xffffffffu);
			break;
		case 1:                         /* a dictionary that declares things */
			m = snprintf(line, sizeof line,
				     "<< /Type /%s %s /Length %s /Filter /%s >>\n",
				     (const char *[]){ "EmbeddedFile", "ObjStm",
						       "Action", "Catalog" }
					     [rnd() % 4u],
				     /* The keys that say what happens when the
				      * document is opened - what a signature for
				      * a malicious PDF is actually looking at. */
				     (const char *[]){ "/Launch (cmd.exe)",
						       "/OpenAction 2 0 R",
						       "/AA 3 0 R",
						       "/JS (app.alert\\(1\\))",
						       "/URI (http://x/)",
						       "" }
					     [rnd() % 6u],
				     (const char *[]){ "8", "0", "-1",
						       "99999999999999999999",
						       "4294967295", "abc" }
					     [rnd() % 6u],
				     (const char *[]){ "FlateDecode", "LZWDecode",
						       "Crypt", "NoSuchFilter" }
					     [rnd() % 4u]);
			break;
		case 2:
			m = snprintf(line, sizeof line, "stream\n");
			break;
		case 3:                         /* often missing its opener */
			m = snprintf(line, sizeof line, "endstream\n");
			break;
		case 4:
			m = snprintf(line, sizeof line, "endobj\n");
			break;
		case 5:
			m = snprintf(line, sizeof line, "startxref\n%llu\n",
				     (unsigned long long)((rnd() % 2u)
					     ? rnd()
					     : ((uint64_t)rnd() << 32) | rnd()));
			break;
		case 6:
			m = snprintf(line, sizeof line,
				     "trailer\n<< /Size %u /Encrypt 3 0 R >>\n",
				     (unsigned)rnd());
			break;
		default: {
			uint32_t j = (uint32_t)(rnd() % 96u);

			m = 0;
			while ((uint32_t)m < j && (size_t)m < sizeof line - 1u)
				line[m++] = (rnd() % 4u)
					? (char)('A' + (char)(rnd() % 26))
					: (char)rnd();
			break;
		}
		}
		if (m < 0)
			break;
		if (at + (uint64_t)m > n)
			break;
		memcpy(b + at, line, (size_t)m);
		at += (uint64_t)m;
	}
	if ((rnd() % 2u) && at + 6u <= n) {
		memcpy(b + at, "%%EOF\n", 6);
		at += 6u;
	}
	return at;
}


/*
 * The formats, as a table.
 *
 * It used to be a chain of `want == N ?` written out three times - once to pick the
 * generator, once for the label, once for the sniff and parse - and adding a format
 * meant editing all three and getting the numbering right in each. One row is one
 * format, and the counters are an array beside it.
 */



/*
 * The anomaly word of each view.
 *
 * One accessor per format rather than a cast to a common head: the container views
 * do begin version, valid, anomalies, and ELF and PE do not - so a cast would have
 * read a segment count as an anomaly mask and reported it as coverage. It did,
 * until this replaced it.
 */


/*
 * What the engine does not publish, and only that.
 *
 * The generator is this test's own, and the anomaly COUNT is a per-format
 * constant with no runtime accessor. Everything else about a format - how to
 * sniff it, how to parse it, how big its view is, what its regions and anomaly
 * bits are called - is asked of the engine, so a format that changes there
 * changes here with it.
 */
static struct fmt {
	uint8_t  format;
	uint64_t (*gen)(uint8_t *);
	uint32_t n_anom;
	const struct kof_parser *p;
} fmts[] = {
	{ KOF_FMT_PE, gen_pe, KOF_PE_ANOM_COUNT, NULL },
	{ KOF_FMT_ELF, gen_elf, KOF_ELF_ANOM_COUNT, NULL },
	{ KOF_FMT_GZIP, gen_gzip, KOF_GZIP_ANOM_COUNT, NULL },
	{ KOF_FMT_DOCOLE, gen_docole, KOF_DOCOLE_ANOM_COUNT, NULL },
	{ KOF_FMT_ZIP, gen_zip, KOF_ZIP_ANOM_COUNT, NULL },
	{ KOF_FMT_TAR, gen_tar, KOF_TAR_ANOM_COUNT, NULL },
	{ KOF_FMT_7Z, gen_7z, KOF_7Z_ANOM_COUNT, NULL },
	{ KOF_FMT_RAR, gen_rar, KOF_RAR_ANOM_COUNT, NULL },
	{ KOF_FMT_XZ, gen_xz, KOF_XZ_ANOM_COUNT, NULL },
	{ KOF_FMT_RTF, gen_rtf, KOF_RTF_ANOM_COUNT, NULL },
	{ KOF_FMT_PDF, gen_pdf, KOF_PDF_ANOM_COUNT, NULL }
};
#define N_FMT (sizeof fmts / sizeof fmts[0])

int main(int argc, char **argv)
{
	static uint8_t obj[OBJ_MAX];
	static uint64_t parsed[N_FMT];
	static uint64_t anom[N_FMT];
	struct pc_report rep = { 0, 0, 0, 0 };
	uint64_t rounds = ROUNDS, seed = 20240101u, r;
	size_t big = 0;
	uint32_t k;
	void *view;
	char what[64];

	if (argc > 1)
		seed = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);

	/* One view buffer, sized for the largest, rather than eleven live at
	 * once: only one parse is in flight and the views run to megabytes. */
	for (k = 0; k < N_FMT; k++) {
		fmts[k].p = kof_parser_of(fmts[k].format);
		if (!fmts[k].p) {
			printf("no engine parser for format %u\n", fmts[k].format);
			return 1;
		}
	}
	for (k = 0; k < N_FMT; k++)
		if (fmts[k].p->view_size > big)
			big = fmts[k].p->view_size;
	view = malloc(big);
	if (!view)
		return 1;

	rng_state = seed ? seed : 1;

	for (r = 0; r < rounds; r++) {
		const struct fmt *f = &fmts[rnd() % N_FMT];
		struct kof_obj_ctx ctx;
		kof_buf buf;
		uint64_t n;

		memset(&ctx, 0, sizeof ctx);
		n = f->gen(obj);
		buf = kof_buf_make(obj, n);

		snprintf(what, sizeof what, "seed=%llu round=%llu %s",
			 (unsigned long long)seed, (unsigned long long)r,
			 kof_format_name(f->format));

		if (f->p->sniff(buf) && f->p->parse(buf, view, &ctx)) {
			parsed[f - fmts]++;
			anom[f - fmts] |= f->p->anomalies(view);
			pc_check(what, &ctx, n, f->p->regions, f->p->n_regions, &rep);
		}

		/*
		 * The refusal path, which is a contract of its own.
		 *
		 * Every collector answers a caller that parses WITHOUT sniffing
		 * first, and what it answers is a view marked invalid with the bit
		 * that says why - BAD_MAGIC, BAD_MZ, BAD_HEADER. The engine always
		 * sniffs, so nothing else here ever reaches those bits, and the
		 * anomaly report below read them as bits the parser never sets.
		 *
		 * It is also the one call in this file made on input nobody claims
		 * is the format, which is where a parse that reads before it checks
		 * would be caught.
		 */
		if (n) {
			/*
			 * A CORRUPTION ANYWHERE THE RECOGNISER LOOKS, NOT ONLY
			 * BYTE ZERO.
			 *
			 * Byte zero fails every sniff, so this path only ever
			 * reached each format's BAD_MAGIC bit. The bits a sniff
			 * checks BESIDES the magic - gzip's compression method,
			 * the "PE\0\0" at e_lfanew - were left unreachable from
			 * either path: the main loop cannot see them because
			 * the sniff refuses first, and this one could not
			 * produce them. Three bytes at random offsets in the
			 * head reach both.
			 */
			uint8_t save[3];
			uint64_t at[3];
			uint32_t c, n_c = 1u + (uint32_t)(rnd() % 3);
			uint64_t head = n < 512 ? n : 512;

			for (c = 0; c < n_c; c++) {
				at[c] = rnd() % head;
				save[c] = obj[at[c]];
				obj[at[c]] = (uint8_t)rnd();
			}
			memset(&ctx, 0, sizeof ctx);
			if (!f->p->sniff(kof_buf_make(obj, n)))
				f->p->parse(kof_buf_make(obj, n), view, &ctx);
			anom[f - fmts] |= f->p->anomalies(view);
			while (c--)
				obj[at[c]] = save[c];
		}
	}

	free(view);
	printf("hostile headers: %llu round(s), parsed",
	       (unsigned long long)rounds);
	for (k = 0; k < N_FMT; k++)
		printf(" %s %llu", kof_format_name(fmts[k].format),
		       (unsigned long long)parsed[k]);
	printf(", partition %llu/%llu", 
	       (unsigned long long)(rep.checked - rep.failed),
	       (unsigned long long)rep.checked);
	if (rep.capped)
		printf(" (+%llu past the extent cap, not checked)",
		       (unsigned long long)rep.capped);
	printf("\n");

	/*
	 * Which declared anomalies this run never managed to raise.
	 *
	 * The checklist asks that every bit a parser declares is actually raised
	 * somewhere, and the three times that was checked by grepping the source
	 * the grep was wrong - table driven raises and bits whose name differs from
	 * their macro both slipped through. This is the same question asked of the
	 * running parser, where neither can hide.
	 *
	 * Reported and not failed: some bits need an input a random generator will
	 * not stumble on - a file above four gigabytes, an archive that is
	 * genuinely encrypted - and a test that failed on those would be a test
	 * nobody could keep green.
	 */
	for (k = 0; k < N_FMT; k++) {
		uint32_t b, first = 1;

		for (b = 0; b < fmts[k].n_anom; b++) {
			if (anom[k] & (1ull << b))
				continue;
			if (first) {
				printf("  %s never raised:", kof_format_name(fmts[k].format));
				first = 0;
			}
			printf(" %s", fmts[k].p->anomaly_name(b));
		}
		if (!first)
			printf("\n");
	}
	return rep.failed != 0;
}
