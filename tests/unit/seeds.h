/*
 * seeds.h - valid objects to make hostile, and the byte positions worth attacking.
 *
 * Shared by the two tests that mutate structure: one drives the parsers directly
 * and one drives the whole scanner, real unpackers included. They need the same
 * seeds and the same field tables, and a second copy of either would drift - the
 * point of the tables is that they name every position a parser does arithmetic on,
 * which is a claim that has to be maintained in one place to mean anything.
 *
 * Header-only and static: two binaries, no library, no link order to think about.
 */

#ifndef KOFENG_TEST_SEEDS_H
#define KOFENG_TEST_SEEDS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <kofmod/rar.h>   /* RAR5 block types, for the vint seed below */

/*
 * A megabyte, and the size is load bearing.
 *
 * An amplification is invisible on a small object: the measured ELF bug costs one
 * pass over the string table per section, which at 8KB is a millisecond and at a
 * megabyte is a fifth of a second. The seed has to be large enough that doing
 * something once per structure is measurably different from doing it once.
 */
#define SEED_MAX (1u << 20)

/*
 * A field, and how many structures carry it.
 *
 * `stride` and `count` are what makes this find anything, and leaving them out is
 * why the first version of this found nothing. A hostile file rarely has ONE bad
 * field; it has one bad value in EVERY element of a table, because that is what
 * turns a cost per structure into a cost times the number of structures.
 *
 * stride 0 means the field appears once.
 */
struct field {
	const char *name;
	uint32_t off;
	uint8_t width;      /* 1, 2, 4 or 8 */
	uint32_t stride;    /* bytes between elements, 0 for a single field */
	uint32_t count;     /* elements, when stride is set */
};

static void poke(uint8_t *b, uint64_t n, const struct field *f, uint64_t v)
{
	uint32_t e, i, reps = f->stride ? f->count : 1u;

	for (e = 0; e < reps; e++) {
		uint64_t at = (uint64_t)f->off + (uint64_t)e * f->stride;

		if (at + f->width > n)
			return;
		for (i = 0; i < f->width; i++)
			b[at + i] = (uint8_t)(v >> (8u * i));
	}
}

/*
 * What goes into a field, and every one of these has broken something somewhere.
 *
 * Zero and one are the degenerate cases a loop divides or steps by. The maxima are
 * what wraps an addition. The signed boundaries are what a value read as unsigned
 * and used as signed becomes. The object's own length either side is the off by one
 * that turns a bounds check into a bounds miss - and it is the most productive of
 * the set, because it is the value a parser was written to accept.
 */
static uint64_t hostile(uint32_t k, uint64_t obj_len)
{
	switch (k) {
	case 0:  return 0;
	case 1:  return 1;
	case 2:  return 2;
	case 3:  return 0x7fu;
	case 4:  return 0x80u;
	case 5:  return 0x7fffu;
	case 6:  return 0x8000u;
	case 7:  return 0xffffu;
	case 8:  return 0x7fffffffu;
	case 9:  return 0x80000000u;
	case 10: return 0xffffffffu;
	case 11: return 0x7fffffffffffffffull;
	case 12: return 0xffffffffffffffffull;
	case 13: return obj_len;
	case 14: return obj_len - 1u;
	case 15: return obj_len + 1u;
	case 16: return obj_len / 2u;
	default: return 0xfffffffeu;
	}
}
#define HOSTILE_N 18u

/* ---- seeds -------------------------------------------------------------------- */

/*
 * Filler that looks like content rather than like padding.
 *
 * The first version of this test filled its seeds with zeros and could not have
 * found the bug it was written for, whatever it mutated: the ELF amplification
 * needs a stretch of bytes with no NUL in it, and a zeroed object is nothing but
 * NULs. A real file is neither - it is code and strings and tables - so the filler
 * is a deterministic stream with no zero bytes, which is what a compressed section
 * or a string table full of long names actually looks like to a parser.
 *
 * Deterministic so a failure reproduces; xorshift so it is one line.
 */
static void fill_body(uint8_t *b, uint64_t n)
{
	uint64_t st = 0x9e3779b97f4a7c15ull, i;

	for (i = 0; i < n; i++) {
		st ^= st << 13; st ^= st >> 7; st ^= st << 17;
		b[i] = (uint8_t)(st | 1u);       /* never zero */
	}
}

static void put16(uint8_t *b, uint32_t off, uint16_t v)
{
	b[off] = (uint8_t)v; b[off + 1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *b, uint32_t off, uint32_t v)
{
	uint32_t i;
	for (i = 0; i < 4u; i++) b[off + i] = (uint8_t)(v >> (8u * i));
}

static void put64(uint8_t *b, uint32_t off, uint64_t v)
{
	uint32_t i;
	for (i = 0; i < 8u; i++) b[off + i] = (uint8_t)(v >> (8u * i));
}

/*
 * A valid ELF64 with sections, a string table and a segment.
 *
 * The string table is deliberately most of the object and carries no NUL past its
 * first few names, which is the shape the amplification needs. A seed that is
 * already hostile in that one respect is the point: the mutation then only has to
 * point a name offset at it.
 */
#define ELF_SHOFF   0x1000u
#define ELF_NSEC    64u
#define ELF_STRTAB  0x10000u

static uint64_t seed_elf(uint8_t *b)
{
	uint32_t i;

	fill_body(b, SEED_MAX);
	memset(b, 0, 0x20000u);                 /* headers and a small string table */
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);                        /* ET_EXEC */
	put16(b, 18, 0x3e);                     /* x86-64 */
	put32(b, 20, 1);
	put64(b, 32, 0);                        /* e_phoff */
	put64(b, 40, ELF_SHOFF);                /* e_shoff */
	put16(b, 52, 64);                       /* e_ehsize */
	put16(b, 54, 56); put16(b, 56, 0);      /* phentsize, phnum */
	put16(b, 58, 64);                       /* e_shentsize */
	put16(b, 60, (uint16_t)ELF_NSEC);       /* e_shnum */
	put16(b, 62, 1);                        /* e_shstrndx */

	memcpy(b + ELF_STRTAB, "\0.text\0.data\0.strtab\0", 21);
	for (i = 0; i < ELF_NSEC; i++) {
		uint32_t o = ELF_SHOFF + i * 64u;

		put32(b, o + 0, 1u);                    /* sh_name */
		put32(b, o + 4, i == 1u ? 3u : 1u);     /* STRTAB for [1] */
		put64(b, o + 24, i == 1u ? ELF_STRTAB : 0x20000u);
		/*
		 * The string table is SMALL here on purpose. Making it span the
		 * object would be arranging half of the bug this test exists to
		 * find; the mutation has to reach that state on its own, which is
		 * what the pairwise pass below is for.
		 */
		put64(b, o + 32, i == 1u ? 0x100u : 0x100u);
		put64(b, o + 48, 1);                    /* sh_addralign */
	}
	return SEED_MAX;
}

static const struct field f_elf[] = {
	{ "e_shoff",     40, 8, 0, 0 }, { "e_shnum",      60, 2, 0, 0 },
	{ "e_shentsize", 58, 2, 0, 0 }, { "e_shstrndx",   62, 2, 0, 0 },
	{ "e_phoff",     32, 8, 0, 0 }, { "e_phnum",      56, 2, 0, 0 },
	{ "e_phentsize", 54, 2, 0, 0 }, { "e_ehsize",     52, 2, 0, 0 },
	{ "sh[0].name",   ELF_SHOFF +  0, 4, 0, 0 },
	{ "sh[0].off",    ELF_SHOFF + 24, 8, 0, 0 },
	{ "sh[0].size",   ELF_SHOFF + 32, 8, 0, 0 },
	{ "sh[*].name",   ELF_SHOFF +  0, 4, 64, ELF_NSEC },
	{ "sh[*].off",    ELF_SHOFF + 24, 8, 64, ELF_NSEC },
	{ "sh[*].size",   ELF_SHOFF + 32, 8, 64, ELF_NSEC },
	{ "sh[*].type",   ELF_SHOFF +  4, 4, 64, ELF_NSEC }
};

/* A PE32+ with one section and a data directory. */
#define PE_NT   0x80u
#define PE_OPT  (PE_NT + 24u)
#define PE_SEC  (PE_OPT + 240u)

static uint64_t seed_pe(uint8_t *b)
{
	memset(b, 0, SEED_MAX);
	memcpy(b, "MZ", 2);
	put32(b, 0x3c, PE_NT);
	memcpy(b + PE_NT, "PE\0\0", 4);
	put16(b, PE_NT + 4, 0x8664);            /* machine */
	put16(b, PE_NT + 6, 1);                 /* NumberOfSections */
	put16(b, PE_NT + 20, 240);              /* SizeOfOptionalHeader */
	put16(b, PE_NT + 22, 0x0002);           /* characteristics: EXECUTABLE */
	put16(b, PE_OPT, 0x20b);                /* PE32+ */
	put32(b, PE_OPT + 16, 0x1000);          /* AddressOfEntryPoint */
	put32(b, PE_OPT + 36, 0x1000);          /* SectionAlignment */
	put32(b, PE_OPT + 40, 0x200);           /* FileAlignment */
	put32(b, PE_OPT + 56, 0x4000);          /* SizeOfImage */
	put32(b, PE_OPT + 60, 0x400);           /* SizeOfHeaders */
	put32(b, PE_OPT + 108, 16);             /* NumberOfRvaAndSizes */
	memcpy(b + PE_SEC, ".text\0\0", 7);
	put32(b, PE_SEC +  8, 0x1000);          /* VirtualSize */
	put32(b, PE_SEC + 12, 0x1000);          /* VirtualAddress */
	put32(b, PE_SEC + 16, 0x200);           /* SizeOfRawData */
	put32(b, PE_SEC + 20, 0x400);           /* PointerToRawData */
	put32(b, PE_SEC + 36, 0x60000020);      /* characteristics */
	return SEED_MAX;
}

static const struct field f_pe[] = {
	{ "e_lfanew",      0x3c, 4, 0, 0 },
	{ "NumberOfSections", PE_NT + 6, 2, 0, 0 },
	{ "SizeOfOptHdr",  PE_NT + 20, 2, 0, 0 },
	{ "Magic",         PE_OPT, 2, 0, 0 },
	{ "SectionAlign",  PE_OPT + 36, 4, 0, 0 },
	{ "FileAlign",     PE_OPT + 40, 4, 0, 0 },
	{ "SizeOfImage",   PE_OPT + 56, 4, 0, 0 },
	{ "SizeOfHeaders", PE_OPT + 60, 4, 0, 0 },
	{ "NumberOfRva",   PE_OPT + 108, 4, 0, 0 },
	{ "sec.VirtualSize",  PE_SEC +  8, 4, 0, 0 },
	{ "sec[*].SizeOfRaw", PE_SEC + 16, 4, 40, 16 },
	{ "sec[*].PtrToRaw",  PE_SEC + 20, 4, 40, 16 },
	{ "sec.VirtualAddr",  PE_SEC + 12, 4, 0, 0 },
	{ "sec.SizeOfRaw",    PE_SEC + 16, 4, 0, 0 },
	{ "sec.PtrToRaw",     PE_SEC + 20, 4, 0, 0 }
};

/* A zip with one stored entry, a central directory and an end record. */
/*
 * Eight entries rather than one, so a field can be made hostile in ALL of them.
 *
 * That is what found the ELF amplification and it needs more than one structure to
 * be expressible: a cost paid once is invisible, and the same cost paid per entry
 * is the bug. A single entry seed can only ever test the first half of that.
 */
#define Z_NENT    8u
#define Z_LSTRIDE (30u + 8u + 16u)      /* local header, name, data */
#define Z_LOCAL   0u
#define Z_NAME    30u
#define Z_DATA    (Z_NAME + 8u)
#define Z_DLEN    16u
#define Z_CD      (Z_LSTRIDE * Z_NENT)
#define Z_CSTRIDE (46u + 8u)
#define Z_CDNAME  (Z_CD + 46u)
#define Z_EOCD    (Z_CD + Z_CSTRIDE * Z_NENT)

static uint64_t seed_zip(uint8_t *b)
{
	uint32_t e;

	fill_body(b, SEED_MAX);
	memset(b, 0, Z_EOCD + 64u);

	for (e = 0; e < Z_NENT; e++) {
		uint32_t l = Z_LOCAL + e * Z_LSTRIDE;
		uint32_t c = Z_CD + e * Z_CSTRIDE;

		put32(b, l, 0x04034b50);
		put16(b, l + 8, 0);                     /* stored */
		put32(b, l + 18, Z_DLEN);               /* csize */
		put32(b, l + 22, Z_DLEN);               /* usize */
		put16(b, l + 26, 8);                    /* name len */
		memcpy(b + l + 30, "file.txt", 8);
		memset(b + l + 38, 'A', Z_DLEN);

		put32(b, c, 0x02014b50);
		put16(b, c + 10, 0);
		put32(b, c + 20, Z_DLEN);
		put32(b, c + 24, Z_DLEN);
		put16(b, c + 28, 8);
		put32(b, c + 42, l);                    /* local header offset */
		memcpy(b + c + 46, "file.txt", 8);
	}

	put32(b, Z_EOCD, 0x06054b50);
	put16(b, Z_EOCD + 8, (uint16_t)Z_NENT);
	put16(b, Z_EOCD + 10, (uint16_t)Z_NENT);
	put32(b, Z_EOCD + 12, Z_EOCD - Z_CD);
	put32(b, Z_EOCD + 16, Z_CD);
	put16(b, Z_EOCD + 20, 0);
	return Z_EOCD + 22u;
}

static const struct field f_zip[] = {
	{ "eocd.entries",   Z_EOCD +  8, 2, 0, 0 },
	{ "eocd.total",     Z_EOCD + 10, 2, 0, 0 },
	{ "eocd.cd_size",   Z_EOCD + 12, 4, 0, 0 },
	{ "eocd.cd_off",    Z_EOCD + 16, 4, 0, 0 },
	{ "eocd.comment",   Z_EOCD + 20, 2, 0, 0 },
	{ "cd.method",      Z_CD + 10, 2, 0, 0 },
	{ "cd.csize",       Z_CD + 20, 4, 0, 0 },
	{ "cd.usize",       Z_CD + 24, 4, 0, 0 },
	{ "cd.namelen",     Z_CD + 28, 2, 0, 0 },
	{ "cd.extralen",    Z_CD + 30, 2, 0, 0 },
	{ "cd.cmtlen",      Z_CD + 32, 2, 0, 0 },
	{ "cd.local_off",   Z_CD + 42, 4, 0, 0 },
	{ "loc.csize",      Z_LOCAL + 18, 4, 0, 0 },
	{ "loc.usize",      Z_LOCAL + 22, 4, 0, 0 },
	{ "loc.namelen",    Z_LOCAL + 26, 2, 0, 0 },
	{ "loc.extralen",   Z_LOCAL + 28, 2, 0, 0 },
	{ "cd[*].csize",    Z_CD + 20, 4, Z_CSTRIDE, Z_NENT },
	{ "cd[*].usize",    Z_CD + 24, 4, Z_CSTRIDE, Z_NENT },
	{ "cd[*].namelen",  Z_CD + 28, 2, Z_CSTRIDE, Z_NENT },
	{ "cd[*].extralen", Z_CD + 30, 2, Z_CSTRIDE, Z_NENT },
	{ "cd[*].local_off",Z_CD + 42, 4, Z_CSTRIDE, Z_NENT },
	{ "loc[*].csize",   Z_LOCAL + 18, 4, Z_LSTRIDE, Z_NENT },
	{ "loc[*].namelen", Z_LOCAL + 26, 2, Z_LSTRIDE, Z_NENT },
	{ "loc[*].extralen",Z_LOCAL + 28, 2, Z_LSTRIDE, Z_NENT }
};

/* A tar with one entry and its terminator. */
static void tar_chksum(uint8_t *b, uint32_t at)
{
	uint32_t i, sum = 0;
	char tmp[8];

	memset(b + at + 148, ' ', 8);
	for (i = 0; i < 512u; i++)
		sum += b[at + i];
	snprintf(tmp, sizeof tmp, "%06o", sum);
	memcpy(b + at + 148, tmp, 7);
	b[at + 155] = ' ';
}

static uint64_t seed_tar(uint8_t *b)
{
	memset(b, 0, SEED_MAX);
	memcpy(b + 0, "hello.txt", 9);
	memcpy(b + 100, "0000644", 7);
	memcpy(b + 108, "0000000", 7);
	memcpy(b + 116, "0000000", 7);
	memcpy(b + 124, "00000000020", 11);     /* size: 16 octal */
	memcpy(b + 136, "00000000000", 11);
	b[156] = '0';
	memcpy(b + 257, "ustar", 5);
	memcpy(b + 263, "00", 2);
	tar_chksum(b, 0);
	memset(b + 512, 'B', 16);
	return 512u * 4u;
}

static const struct field f_tar[] = {
	{ "size",     124, 8, 0, 0 }, { "size.tail", 130, 4, 0, 0 },
	{ "chksum",   148, 8, 0, 0 }, { "typeflag",  156, 1, 0, 0 },
	{ "magic",    257, 4, 0, 0 }, { "name",        0, 8, 0, 0 },
	{ "prefix",   345, 8, 0, 0 }
};

/* A gzip member with a name and a deflate stored block. */
static uint64_t seed_gzip(uint8_t *b)
{
	memset(b, 0, SEED_MAX);
	b[0] = 0x1f; b[1] = 0x8b; b[2] = 8;
	b[3] = 0x08;                            /* FNAME */
	memcpy(b + 10, "a.txt", 6);
	b[16] = 0x01;                           /* stored, final */
	put16(b, 17, 4); put16(b, 19, (uint16_t)~4u);
	memcpy(b + 21, "ABCD", 4);
	put32(b, 25, 0);
	put32(b, 29, 4);
	return 33u;
}

static const struct field f_gzip[] = {
	{ "flg",      3, 1, 0, 0 }, { "mtime",    4, 4, 0, 0 },
	{ "xfl",      8, 1, 0, 0 }, { "os",       9, 1, 0, 0 },
	{ "name",    10, 4, 0, 0 }, { "blk.len", 17, 2, 0, 0 },
	{ "blk.nlen",19, 2, 0, 0 }, { "isize",   29, 4, 0, 0 }
};

/* A 7z signature header pointing at a plain next header. */
static uint64_t seed_7z(uint8_t *b)
{
	memset(b, 0, SEED_MAX);
	memcpy(b, "7z\xbc\xaf\x27\x1c", 6);
	b[6] = 0; b[7] = 4;
	put64(b, 12, 0x100);                    /* next header offset */
	put64(b, 20, 0x40);                     /* next header size */
	b[32 + 0x100] = 0x01;                   /* kHeader */
	return SEED_MAX;
}

static const struct field f_7z[] = {
	{ "major",       6, 1, 0, 0 }, { "minor",       7, 1, 0, 0 },
	{ "start.crc",   8, 4, 0, 0 }, { "nexthdr.off",12, 8, 0, 0 },
	{ "nexthdr.size",20, 8, 0, 0 }, { "nexthdr.crc",28, 4, 0, 0 }
};

/* A RAR3 archive: marker, archive header, one stored file. */
#define R_MARK   0u
#define R_ARC    7u
#define R_FILE   20u
#define R_NENT    8u
#define R_STRIDE 44u                    /* 36 byte header+name, 8 byte data */

static uint64_t seed_rar(uint8_t *b)
{
	uint32_t i;

	fill_body(b, SEED_MAX);
	memset(b, 0, R_FILE + R_STRIDE * R_NENT + 64u);
	memcpy(b + R_MARK, "Rar!\x1a\x07\x00", 7);

	put16(b, R_ARC + 3, 0);                 /* flags */
	b[R_ARC + 2] = 0x73;                    /* archive header */
	put16(b, R_ARC + 5, 13);                /* head size */

	for (i = 0; i < R_NENT; i++) {
		uint32_t o = R_FILE + i * R_STRIDE;

		b[o + 2] = 0x74;                        /* file header */
		put16(b, o + 3, 0x8000);                /* ADD_SIZE present */
		put16(b, o + 5, 32 + 4);                /* head size incl. name */
		put32(b, o + 7, 8);                     /* pack size */
		put32(b, o + 11, 8);                    /* unp size */
		b[o + 25] = 0x30;                       /* stored */
		put16(b, o + 26, 4);                    /* name size */
		memcpy(b + o + 32, "a.bi", 4);
		memset(b + o + 36, 'C', 8);
	}
	return R_FILE + R_STRIDE * R_NENT;
}

static const struct field f_rar[] = {
	{ "arc.headsize", R_ARC  +  5, 2, 0, 0 },
	{ "arc.flags",    R_ARC  +  3, 2, 0, 0 },
	{ "file.flags",   R_FILE +  3, 2, 0, 0 },
	{ "file.headsize",R_FILE +  5, 2, 0, 0 },
	{ "file.packsize",R_FILE +  7, 4, 0, 0 },
	{ "file.unpsize", R_FILE + 11, 4, 0, 0 },
	{ "file.method",  R_FILE + 25, 1, 0, 0 },
	{ "file.namesize",R_FILE + 26, 2, 0, 0 },
	{ "file.type",    R_FILE +  2, 1, 0, 0 },
	{ "file[*].headsize", R_FILE +  5, 2, R_STRIDE, R_NENT },
	{ "file[*].packsize", R_FILE +  7, 4, R_STRIDE, R_NENT },
	{ "file[*].unpsize",  R_FILE + 11, 4, R_STRIDE, R_NENT },
	{ "file[*].namesize", R_FILE + 26, 2, R_STRIDE, R_NENT },
	{ "file[*].flags",    R_FILE +  3, 2, R_STRIDE, R_NENT }
};

/*
 * An xz stream: header, one LZMA2 block, an index and a footer.
 *
 * Small and exact, because every offset in it is derived from another. The index
 * carries the block's unpadded size and the footer carries the index's, so a field
 * poked here moves the thing that finds the thing that finds the blocks - which is
 * the whole reason this format reads backwards and the reason it is worth fuzzing
 * from both ends.
 */
#define X_BLOCK  12u
#define X_HDRLEN 12u
#define X_DATA   (X_BLOCK + X_HDRLEN)
#define X_CLEN   16u
#define X_INDEX  (X_DATA + X_CLEN)
#define X_IDXLEN  8u
#define X_FOOT   (X_INDEX + X_IDXLEN)

static uint64_t seed_xz(uint8_t *b)
{
	memset(b, 0, SEED_MAX);
	memcpy(b, "\xfd" "7zXZ", 6);
	b[6] = 0;
	b[7] = 0;                               /* check: none */
	put32(b, 8, 0);

	b[X_BLOCK]     = 2;                     /* header size: (2+1)*4 = 12 */
	b[X_BLOCK + 1] = 0;                     /* one filter, no sizes present */
	b[X_BLOCK + 2] = 0x21;                  /* LZMA2 */
	b[X_BLOCK + 3] = 1;                     /* property size */
	b[X_BLOCK + 4] = 0;                     /* dictionary size code */
	memset(b + X_DATA, 0xa5, X_CLEN);

	b[X_INDEX]     = 0;                     /* index indicator */
	b[X_INDEX + 1] = 1;                     /* one record */
	b[X_INDEX + 2] = X_HDRLEN + X_CLEN;     /* unpadded size */
	b[X_INDEX + 3] = 32;                    /* uncompressed size */

	put32(b, X_FOOT, 0);                    /* footer CRC */
	put32(b, X_FOOT + 4, X_IDXLEN / 4u - 1u);
	b[X_FOOT + 8]  = 0;
	b[X_FOOT + 9]  = 0;
	b[X_FOOT + 10] = 'Y';
	b[X_FOOT + 11] = 'Z';
	return X_FOOT + 12u;
}

static const struct field f_xz[] = {
	{ "stream.check",  7, 1, 0, 0 },
	{ "blk.hdrsize",   X_BLOCK,     1, 0, 0 },
	{ "blk.flags",     X_BLOCK + 1, 1, 0, 0 },
	{ "blk.filter",    X_BLOCK + 2, 1, 0, 0 },
	{ "blk.propsize",  X_BLOCK + 3, 1, 0, 0 },
	{ "idx.indicator", X_INDEX,     1, 0, 0 },
	{ "idx.count",     X_INDEX + 1, 1, 0, 0 },
	{ "idx.unpadded",  X_INDEX + 2, 1, 0, 0 },
	{ "idx.uncomp",    X_INDEX + 3, 1, 0, 0 },
	{ "foot.backward", X_FOOT + 4,  4, 0, 0 },
	{ "foot.flags",    X_FOOT + 8,  2, 0, 0 },
	{ "foot.magic",    X_FOOT + 10, 2, 0, 0 }
};

/* A compound file: header, one FAT sector, one directory sector. */
#define O_SEC  512u

static uint64_t seed_docole(uint8_t *b)
{
	static const uint8_t sig[8] = {
		0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
	};
	uint32_t i;

	memset(b, 0, SEED_MAX);
	memcpy(b, sig, 8);
	put16(b, 24, 0x003e);
	put16(b, 26, 3);                        /* major */
	put16(b, 28, 0xfffe);                   /* byte order */
	put16(b, 30, 9);                        /* sector shift: 512 */
	put16(b, 32, 6);                        /* mini sector shift */
	put32(b, 44, 1);                        /* FAT sector count */
	put32(b, 48, 1);                        /* directory start */
	put32(b, 56, 4096);                     /* mini cutoff */
	put32(b, 60, 0xfffffffe);               /* miniFAT start: none */
	put32(b, 64, 0);
	put32(b, 68, 0xfffffffe);               /* DIFAT start: none */
	put32(b, 76, 0);                        /* DIFAT[0] = sector 0 */
	for (i = 1; i < 109u; i++)
		put32(b, 76 + i * 4u, 0xffffffff);

	/* FAT in sector 0: [0]=FATSECT, [1]=ENDOFCHAIN */
	put32(b, O_SEC, 0xfffffffd);
	put32(b, O_SEC + 4, 0xfffffffe);
	for (i = 2; i < 128u; i++)
		put32(b, O_SEC + i * 4u, 0xffffffff);

	/* Directory in sector 1: the root entry. */
	{
		uint32_t d = O_SEC * 2u;
		const char *nm = "Root Entry";
		uint32_t k;

		for (k = 0; nm[k]; k++)
			put16(b, d + k * 2u, (uint16_t)nm[k]);
		put16(b, d + 64, (uint16_t)((k + 1u) * 2u));
		b[d + 66] = 5;                  /* root storage */
		put32(b, d + 68, 0xffffffff);
		put32(b, d + 72, 0xffffffff);
		put32(b, d + 76, 0xffffffff);
		put32(b, d + 116, 0xfffffffe);
		put64(b, d + 120, 0);

		/*
		 * Three streams under the root, LINKED AS A TREE.
		 *
		 * A compound file's directory is a red-black tree, not an array:
		 * entries sitting next to each other in the sector are invisible
		 * unless a sibling points at them. Writing three and pointing the
		 * root at the first found exactly one, which is what the richness
		 * check below is for - a seed that silently holds one element turns
		 * every per-element field back into a single field.
		 */
		for (k = 1; k < 4u; k++) {
			uint32_t e = d + k * 128u;
			const char *sn = "Stream";
			uint32_t j;

			for (j = 0; sn[j]; j++)
				put16(b, e + j * 2u, (uint16_t)sn[j]);
			put16(b, e + 62, (uint16_t)('0' + k));   /* distinct names */
			put16(b, e + 64, (uint16_t)((j + 2u) * 2u));
			b[e + 66] = 2;                  /* stream */
			put32(b, e + 68, k == 1u ? 2u : 0xffffffffu);  /* left */
			put32(b, e + 72, k == 1u ? 3u : 0xffffffffu);  /* right */
			put32(b, e + 76, 0xffffffff);   /* child */
			put32(b, e + 116, 1);
			put64(b, e + 120, 64);
		}
		put32(b, d + 76, 1);                    /* root child -> entry 1 */
	}
	return O_SEC * 3u;
}

static const struct field f_docole[] = {
	{ "sector_shift",  30, 2, 0, 0 }, { "mini_shift",   32, 2, 0, 0 },
	{ "n_fat",         44, 4, 0, 0 }, { "dir_start",    48, 4, 0, 0 },
	{ "mini_cutoff",   56, 4, 0, 0 }, { "mfat_start",   60, 4, 0, 0 },
	{ "n_mfat",        64, 4, 0, 0 }, { "difat_start",  68, 4, 0, 0 },
	{ "n_difat",       72, 4, 0, 0 }, { "difat[0]",     76, 4, 0, 0 },
	{ "fat[0]",       O_SEC, 4, 0, 0 }, { "fat[1]",   O_SEC + 4, 4, 0, 0 },
	{ "root.type",  O_SEC * 2u + 66, 1, 0, 0 },
	{ "root.namelen", O_SEC * 2u + 64, 2, 0, 0 },
	{ "root.start", O_SEC * 2u + 116, 4, 0, 0 },
	{ "root.size",  O_SEC * 2u + 120, 8, 0, 0 },
	{ "dir[*].type",    O_SEC * 2u +  66, 1, 128, 4 },
	{ "dir[*].namelen", O_SEC * 2u +  64, 2, 128, 4 },
	{ "dir[*].start",   O_SEC * 2u + 116, 4, 128, 4 },
	{ "dir[*].size",    O_SEC * 2u + 120, 8, 128, 4 },
	{ "dir[*].left",    O_SEC * 2u +  68, 4, 128, 4 },
	{ "dir[*].right",   O_SEC * 2u +  72, 4, 128, 4 },
	{ "dir[*].child",   O_SEC * 2u +  76, 4, 128, 4 },
	{ "fat[*]",         O_SEC,             4, 4, 128 }
};


/* ---- pdf ---------------------------------------------------------------------- */

/*
 * A PDF of P_NOBJ identical objects, each with a filtered stream.
 *
 * Every number in a PDF is text, so the hostile values land on digits rather than on
 * a little endian integer - which is exactly the case worth covering, because a
 * parser that reads a length with strtoull has to decide what a length of 0xff bytes
 * of binary means. The numbers are written to a fixed width so that one stride
 * describes every object and the field list can poke all of them at once.
 *
 * The dictionary carries /Launch, /EmbeddedFile and /OpenAction because those drive
 * the object flags, and the stream is filtered so STREAM_PACKED is a region with
 * bytes in it rather than one that never appears.
 */
#define P_HDR_LEN     9u          /* "%PDF-1.7\n" */
#define P_MAJOR       5u
#define P_MINOR       7u
#define P_OBJ         P_HDR_LEN
#define P_STRIDE    137u
#define P_NOBJ        8u
#define P_O_NUM       0u          /* "0001", four digits */
#define P_O_GEN       5u
#define P_O_DICT     11u
#define P_O_LENGTH   53u          /* the digits of "/Length 00000008" */
#define P_O_STREAM  104u          /* the "stream" keyword */
#define P_O_DATA    111u
#define P_TAIL      (P_OBJ + P_STRIDE * P_NOBJ)
#define P_T_XREFCNT   7u
#define P_T_SIZE     29u
#define P_T_STARTXREF 74u
#define P_TAIL_LEN   89u

static uint64_t seed_pdf(uint8_t *b)
{
	static const char obj[] =
		"0001 0 obj\n"
		"<< /Type /EmbeddedFile /S /Launch /Length 00000008 "
		"/Filter /FlateDecode /OpenAction 2 0 R >>\n"
		"stream\n"
		"ABCDEFGH"
		"\nendstream\nendobj\n";
	static const char tail[] =
		"xref\n0 0009\n"
		"trailer\n<< /Size 0009 /Root 1 0 R /Encrypt 3 0 R >>\n"
		"startxref\n00000009\n%%EOF\n";
	uint32_t i;

	memset(b, 0, P_TAIL + P_TAIL_LEN + 64u);
	memcpy(b, "%PDF-1.7\n", P_HDR_LEN);
	for (i = 0; i < P_NOBJ; i++) {
		uint32_t o = P_OBJ + i * P_STRIDE;

		memcpy(b + o, obj, P_STRIDE);
		/* Distinct object numbers, so a walk that confuses two of them
		 * produces a visible disagreement rather than a consistent lie. */
		b[o + P_O_NUM + 3u] = (uint8_t)('1' + i);
	}
	memcpy(b + P_TAIL, tail, P_TAIL_LEN);
	return P_TAIL + P_TAIL_LEN;
}

static const struct field f_pdf[] = {
	{ "ver.major",      P_MAJOR, 1, 0, 0 },
	{ "ver.minor",      P_MINOR, 1, 0, 0 },
	{ "hdr.magic",            1, 4, 0, 0 },
	{ "obj.num",        P_OBJ + P_O_NUM,    4, 0, 0 },
	{ "obj.gen",        P_OBJ + P_O_GEN,    1, 0, 0 },
	{ "obj.dict",       P_OBJ + P_O_DICT,   4, 0, 0 },
	{ "obj.length",     P_OBJ + P_O_LENGTH, 8, 0, 0 },
	{ "obj.stream_kw",  P_OBJ + P_O_STREAM, 4, 0, 0 },
	{ "obj.data",       P_OBJ + P_O_DATA,   8, 0, 0 },
	{ "obj[*].num",     P_OBJ + P_O_NUM,    4, P_STRIDE, P_NOBJ },
	{ "obj[*].gen",     P_OBJ + P_O_GEN,    1, P_STRIDE, P_NOBJ },
	{ "obj[*].length",  P_OBJ + P_O_LENGTH, 8, P_STRIDE, P_NOBJ },
	{ "obj[*].stream_kw", P_OBJ + P_O_STREAM, 4, P_STRIDE, P_NOBJ },
	{ "obj[*].dict",    P_OBJ + P_O_DICT,   4, P_STRIDE, P_NOBJ },
	{ "xref.count",     P_TAIL + P_T_XREFCNT,   4, 0, 0 },
	{ "trailer.size",   P_TAIL + P_T_SIZE,      4, 0, 0 },
	{ "startxref",      P_TAIL + P_T_STARTXREF, 8, 0, 0 }
};

/* ---- rtf ---------------------------------------------------------------------- */

/*
 * An RTF with R_OBJ_N embedded objects and one \bin run.
 *
 * The two things a reader has to get right are the brace depth and the \bin count -
 * the count is the only field in the format that says "the next N bytes are not
 * text", so it is the one that can walk the cursor past the end or back onto itself.
 * Both are in the field list, along with the hex of an \objdata blob so that a
 * non-hex byte in a hex run is covered.
 */
#define T_HDR_LEN    17u          /* "{\rtf1\ansi\deff0" */
#define T_VER         5u
#define T_OBJ        T_HDR_LEN
#define T_STRIDE     76u
#define T_NOBJ        4u
#define T_O_CLASS    29u
#define T_O_DATA     50u
#define T_O_HEX      58u
#define T_PICT      (T_OBJ + T_STRIDE * T_NOBJ)
#define T_P_BIN      21u          /* the digits of "\bin00000008" */
#define T_P_DATA     30u
#define T_PICT_LEN   39u
#define T_TAIL      (T_PICT + T_PICT_LEN)
#define T_TAIL_LEN   10u

static uint64_t seed_rtf(uint8_t *b)
{
	static const char obj[] =
		"{\\object\\objemb\\objupdate"
		"{\\*\\objclass Package}"
		"{\\*\\objdata 0105000002000000}}";
	static const char pict[] = "{\\pict\\wmetafile8\\bin00000008 ABCDEFGH}";
	uint32_t i;

	memset(b, 0, T_TAIL + T_TAIL_LEN + 64u);
	memcpy(b, "{\\rtf1\\ansi\\deff0", T_HDR_LEN);
	for (i = 0; i < T_NOBJ; i++)
		memcpy(b + T_OBJ + i * T_STRIDE, obj, T_STRIDE);
	memcpy(b + T_PICT, pict, T_PICT_LEN);
	memcpy(b + T_TAIL, "\\par done}", T_TAIL_LEN);
	return T_TAIL + T_TAIL_LEN;
}

static const struct field f_rtf[] = {
	{ "hdr.brace",             0, 1, 0, 0 },
	{ "hdr.ctrl",              1, 4, 0, 0 },
	{ "hdr.ver",           T_VER, 1, 0, 0 },
	{ "obj.open",          T_OBJ, 1, 0, 0 },
	{ "obj.class",     T_OBJ + T_O_CLASS, 8, 0, 0 },
	{ "obj.objdata",   T_OBJ + T_O_DATA,  8, 0, 0 },
	{ "obj.hex",       T_OBJ + T_O_HEX,   8, 0, 0 },
	{ "obj[*].open",   T_OBJ,             1, T_STRIDE, T_NOBJ },
	{ "obj[*].objdata",T_OBJ + T_O_DATA,  8, T_STRIDE, T_NOBJ },
	{ "obj[*].hex",    T_OBJ + T_O_HEX,   8, T_STRIDE, T_NOBJ },
	{ "obj[*].close",  T_OBJ + T_STRIDE - 1u, 1, T_STRIDE, T_NOBJ },
	{ "pict.bin",      T_PICT + T_P_BIN,  8, 0, 0 },
	{ "pict.data",     T_PICT + T_P_DATA, 8, 0, 0 },
	{ "tail",          T_TAIL,            8, 0, 0 }
};

/* ---- rar5 --------------------------------------------------------------------- */

/*
 * RAR 5, which the existing rar seed does not reach: seed_rar builds a 1.5/2.0
 * signature and the two formats share nothing but a name.
 *
 * Everything here is a variable length integer, and each one is written in its one
 * byte form so a field poke can turn it into a continuation run - the value 0xff has
 * the high bit set in every byte, which is the shape that makes a vint reader either
 * run off the end or shift past the width of the result. hsize is the field the walk
 * trusts to say where a header ends, so it and the two sizes get the full list.
 */
#define V_MAIN        8u          /* after the eight byte signature */
#define V_MAIN_LEN    8u          /* crc(4) + hsize + type + flags */
#define V_FILE       (V_MAIN + V_MAIN_LEN)
#define V_STRIDE     26u
#define V_NENT        6u
#define V_HSIZE       4u
#define V_TYPE        5u
#define V_HFLAGS      6u
#define V_DSIZE       7u
#define V_FFLAGS      8u
#define V_USIZE       9u
#define V_ATTR       10u
#define V_COMP       11u
#define V_HOST       12u
#define V_NLEN       13u
#define V_NAME       14u
#define V_END        (V_FILE + V_STRIDE * V_NENT)
#define V_END_LEN     7u          /* crc(4) + hsize + type + flags */

static uint64_t seed_rar5(uint8_t *b)
{
	uint32_t i;

	memset(b, 0, V_END + V_END_LEN + 64u);
	memcpy(b, "Rar!\x1a\x07\x01\x00", 8);

	b[V_MAIN + 4] = 3;                 /* hsize: type, flags and itself */
	b[V_MAIN + 5] = KOF_RAR5_BLK_MAIN;
	b[V_MAIN + 6] = 0;

	for (i = 0; i < V_NENT; i++) {
		uint32_t o = V_FILE + i * V_STRIDE;

		b[o + V_HSIZE]  = 13;      /* through the name, from here */
		b[o + V_TYPE]   = KOF_RAR5_BLK_FILE;
		b[o + V_HFLAGS] = KOF_RAR5_H_DATA;
		b[o + V_DSIZE]  = 8;
		b[o + V_FFLAGS] = 0;
		b[o + V_USIZE]  = 8;
		b[o + V_ATTR]   = 0;
		b[o + V_COMP]   = 0;       /* method 0: stored */
		b[o + V_HOST]   = 0;
		b[o + V_NLEN]   = 4;
		memcpy(b + o + V_NAME, "a.bi", 4);
		memset(b + o + 18u, 'C', 8);
	}

	b[V_END + 4] = 2;
	b[V_END + 5] = KOF_RAR5_BLK_END;
	b[V_END + 6] = 0;
	return V_END + V_END_LEN;
}

static const struct field f_rar5[] = {
	{ "sig",                       4, 4, 0, 0 },
	{ "main.hsize",  V_MAIN + V_HSIZE,  1, 0, 0 },
	{ "main.type",   V_MAIN + V_TYPE,   1, 0, 0 },
	{ "main.flags",  V_MAIN + V_HFLAGS, 1, 0, 0 },
	{ "file.hsize",  V_FILE + V_HSIZE,  1, 0, 0 },
	{ "file.type",   V_FILE + V_TYPE,   1, 0, 0 },
	{ "file.hflags", V_FILE + V_HFLAGS, 1, 0, 0 },
	{ "file.dsize",  V_FILE + V_DSIZE,  1, 0, 0 },
	{ "file.fflags", V_FILE + V_FFLAGS, 1, 0, 0 },
	{ "file.usize",  V_FILE + V_USIZE,  1, 0, 0 },
	{ "file.comp",   V_FILE + V_COMP,   1, 0, 0 },
	{ "file.nlen",   V_FILE + V_NLEN,   1, 0, 0 },
	/* Eight bytes across the vint, which is how a continuation run is built. */
	{ "file.hsize.run",  V_FILE + V_HSIZE, 8, 0, 0 },
	{ "file.dsize.run",  V_FILE + V_DSIZE, 8, 0, 0 },
	{ "file[*].hsize",  V_FILE + V_HSIZE,  1, V_STRIDE, V_NENT },
	{ "file[*].hflags", V_FILE + V_HFLAGS, 1, V_STRIDE, V_NENT },
	{ "file[*].dsize",  V_FILE + V_DSIZE,  1, V_STRIDE, V_NENT },
	{ "file[*].fflags", V_FILE + V_FFLAGS, 1, V_STRIDE, V_NENT },
	{ "file[*].usize",  V_FILE + V_USIZE,  1, V_STRIDE, V_NENT },
	{ "file[*].nlen",   V_FILE + V_NLEN,   1, V_STRIDE, V_NENT },
	{ "file[*].type",   V_FILE + V_TYPE,   1, V_STRIDE, V_NENT },
	{ "end.hsize",   V_END + 4u, 1, 0, 0 },
	{ "end.type",    V_END + 5u, 1, 0, 0 }
};

#endif /* KOFENG_TEST_SEEDS_H */
