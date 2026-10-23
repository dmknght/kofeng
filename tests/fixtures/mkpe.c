/*
 * mkpe.c - writes two small PE files without a Windows toolchain: synth-pe32.exe and synth-pe64.exe.
 *
 * WHY IT EXISTS (second audit, E5). unit_pe_unmap and unit_pe_mapped walk
 * build/test/fixtures for PE files and print "no PE found - nothing tested" when there are none, and
 * mingw-w64 is not on every host: on this one both ran no check at all while reporting success. This
 * program is the toolchain the PE fixtures no longer need to wait for. It is C and not a script so
 * that `make unit` needs nothing but the compiler it already uses, and it is DETERMINISTIC: no clock, no
 * random bytes, no padding that depends on the host, so two runs write identical files and a failing
 * test names the same input everywhere.
 *
 * WHAT THE FILES CONTAIN, chosen so that every property the two tests look at is present:
 *
 *   - five sections whose file offsets differ from their RVAs (SizeOfHeaders 0x400, FileAlignment 0x200,
 *     SectionAlignment 0x1000), one with SizeOfRawData smaller than VirtualSize, so mapped and file
 *     layouts are different layouts (pe_mapped property 2);
 *   - base relocations of the kinds a loader applies: HIGHLOW (PE32) or DIR64 (PE32+) entries over
 *     absolute pointers in .text and .data, and ABSOLUTE padding entries, in two blocks (pe_unmap's
 *     round trip is byte identity with the file after the relocations were applied and undone, and it
 *     insists that relocations were really present);
 *   - an import directory (KERNEL32.dll and USER32.dll, three functions, by name) whose IAT slots are
 *     called from the code through the very pointers the relocations cover;
 *   - a data directory table of the full 16 entries, the import, base relocation and IAT ones set.
 *
 * The files are not meant to run: the code is the shape of a program, not one.
 *
 * usage: mkpe <output-dir>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_N     0x1000u
#define IMAGE_N    0x6000u
#define HDR_N      0x400u

#define TEXT_RVA   0x1000u
#define RDATA_RVA  0x2000u
#define DATA_RVA   0x3000u
#define IDATA_RVA  0x4000u
#define RELOC_RVA  0x5000u

#define TEXT_RAW   0x400u
#define RDATA_RAW  0x600u
#define DATA_RAW   0x800u
#define IDATA_RAW  0xa00u
#define RELOC_RAW  0xc00u

static void w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *p, uint32_t v) { w16(p, (uint16_t)v); w16(p + 2, (uint16_t)(v >> 16)); }
static void w64(uint8_t *p, uint64_t v) { w32(p, (uint32_t)v); w32(p + 4, (uint32_t)(v >> 32)); }

/* a section header at `s`: name, virtual size, rva, raw size, raw offset, characteristics */
static void section(uint8_t *s, const char *name, uint32_t vsize, uint32_t rva, uint32_t rsize, uint32_t raw,
		    uint32_t chars)
{
	memcpy(s, name, strlen(name));
	w32(s + 8, vsize);
	w32(s + 12, rva);
	w32(s + 16, rsize);
	w32(s + 20, raw);
	w32(s + 36, chars);
}

/* a pointer-sized absolute address and the relocation entry that covers it */
struct fix {
	uint32_t rva;
	uint16_t type;
};

static int build(const char *path, int plus)
{
	uint8_t f[FILE_N];
	const uint64_t base = plus ? 0x140000000ull : 0x400000ull;
	const uint32_t step = plus ? 8u : 4u;
	const uint16_t reloc_type = plus ? 10u : 3u;
	const uint32_t opt = 0x98u, optsz = plus ? 240u : 224u, sec = opt + optsz;
	struct fix fixes[16];
	unsigned n_fix = 0, i;
	uint32_t at;
	FILE *o;

	memset(f, 0, sizeof f);

	/* DOS header and PE signature */
	f[0] = 'M'; f[1] = 'Z';
	w16(f + 0x02, 0x90);
	w16(f + 0x04, 3);
	w16(f + 0x08, 4);
	w16(f + 0x0c, 0xffff);
	w16(f + 0x10, 0xb8);
	w16(f + 0x18, 0x40);
	w32(f + 0x3c, 0x80);
	{
		static const char stub[] = "\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
					   "This program cannot be run in DOS mode.\r\r\n$";

		memcpy(f + 0x40, stub, sizeof stub - 1u);
	}
	memcpy(f + 0x80, "PE\0\0", 4);

	/* COFF header */
	w16(f + 0x84, plus ? 0x8664u : 0x014cu);
	w16(f + 0x86, 5);                                   /* sections */
	w32(f + 0x88, 0x5f000000u);                         /* a fixed timestamp */
	w16(f + 0x94, (uint16_t)optsz);
	w16(f + 0x96, plus ? 0x0022u : 0x0102u);

	/* optional header */
	w16(f + opt, plus ? 0x20bu : 0x10bu);
	f[opt + 2] = 14;                                    /* linker version, any fixed value */
	w32(f + opt + 4, 0x200);                            /* SizeOfCode */
	w32(f + opt + 8, 0x600);                            /* SizeOfInitializedData */
	w32(f + opt + 12, 0x200);                           /* SizeOfUninitializedData */
	w32(f + opt + 16, TEXT_RVA);                        /* entry */
	w32(f + opt + 20, TEXT_RVA);                        /* BaseOfCode */
	if (plus) {
		w64(f + opt + 24, base);
	} else {
		w32(f + opt + 24, RDATA_RVA);               /* BaseOfData */
		w32(f + opt + 28, (uint32_t)base);
	}
	w32(f + opt + 32, 0x1000);                          /* SectionAlignment */
	w32(f + opt + 36, 0x200);                           /* FileAlignment */
	w16(f + opt + 40, 6);                               /* OS version */
	w16(f + opt + 48, 6);                               /* subsystem version */
	w32(f + opt + 56, IMAGE_N);
	w32(f + opt + 60, HDR_N);
	w16(f + opt + 68, 3);                               /* console */
	w16(f + opt + 70, plus ? 0x8160u : 0x0140u);        /* dynamic base, NX, (high entropy, TS aware) */
	if (plus) {
		w64(f + opt + 72, 0x100000);                /* stack reserve */
		w64(f + opt + 80, 0x1000);
		w64(f + opt + 88, 0x100000);                /* heap reserve */
		w64(f + opt + 96, 0x1000);
		w32(f + opt + 108, 16);
	} else {
		w32(f + opt + 72, 0x100000);
		w32(f + opt + 76, 0x1000);
		w32(f + opt + 80, 0x100000);
		w32(f + opt + 84, 0x1000);
		w32(f + opt + 92, 16);
	}
	{
		uint8_t *dir = f + opt + (plus ? 112u : 96u);

		w32(dir + 1 * 8, IDATA_RVA);                /* import: three descriptors, the last null */
		w32(dir + 1 * 8 + 4, 3u * 20u);
		w32(dir + 5 * 8, RELOC_RVA);                /* base relocation, sized below */
		w32(dir + 12 * 8, IDATA_RVA + 0x80u);       /* IAT */
		w32(dir + 12 * 8 + 4, 5u * step);
	}

	/* section headers: file offsets differ from RVAs, and .data is bigger in memory than on disk */
	section(f + sec + 0 * 40, ".text",  0x180, TEXT_RVA,  0x200, TEXT_RAW,  0x60000020u);
	section(f + sec + 1 * 40, ".rdata", 0x100, RDATA_RVA, 0x200, RDATA_RAW, 0x40000040u);
	section(f + sec + 2 * 40, ".data",  0x400, DATA_RVA,  0x200, DATA_RAW,  0xc0000040u);
	section(f + sec + 3 * 40, ".idata", 0x200, IDATA_RVA, 0x200, IDATA_RAW, 0xc0000040u);
	section(f + sec + 4 * 40, ".reloc", 0x40,  RELOC_RVA, 0x200, RELOC_RAW, 0x42000040u);

	/* .rdata: a string the code and the data point at */
	memcpy(f + RDATA_RAW, "kofeng-synthetic-pe-fixture", 28);
	memcpy(f + RDATA_RAW + 0x40, "H\0e\0l\0l\0o\0\0\0", 12);   /* a wide string */

	/* .idata: descriptors, lookup tables, IAT, hint/name entries. IAT slots are at IDATA_RVA + 0x80.. */
	{
		uint8_t *d = f + IDATA_RAW;
		const uint32_t ilt1 = IDATA_RVA + 0x40u, ilt2 = IDATA_RVA + 0x60u;      /* lookup tables */
		const uint32_t iat1 = IDATA_RVA + 0x80u, iat2 = IDATA_RVA + 0x80u + 3u * step;
		const uint32_t names = IDATA_RVA + 0x100u;
		uint32_t nm[3] = { names + 0x00u, names + 0x10u, names + 0x20u };
		uint8_t *t;

		/* descriptor 0: KERNEL32.dll (ExitProcess, GetLastError), descriptor 1: USER32.dll (MessageBoxA) */
		w32(d + 0, ilt1);
		w32(d + 12, names + 0x40u);
		w32(d + 16, iat1);
		w32(d + 20 + 0, ilt2);
		w32(d + 20 + 12, names + 0x50u);
		w32(d + 20 + 16, iat2);
		/* descriptor 2 stays zero: the terminator */
		for (i = 0; i < 3; i++) {
			memcpy(f + IDATA_RAW + (nm[i] - IDATA_RVA) + 2,
			       i == 0 ? "ExitProcess" : i == 1 ? "GetLastError" : "MessageBoxA",
			       i == 0 ? 12u : i == 1 ? 13u : 12u);
		}
		memcpy(f + IDATA_RAW + (names + 0x40u - IDATA_RVA), "KERNEL32.dll", 13);
		memcpy(f + IDATA_RAW + (names + 0x50u - IDATA_RVA), "USER32.dll", 11);
		/* lookup tables and the IAT hold the same hint/name RVAs before binding */
		t = f + IDATA_RAW + (ilt1 - IDATA_RVA);
		if (plus) { w64(t, nm[0]); w64(t + 8, nm[1]); } else { w32(t, nm[0]); w32(t + 4, nm[1]); }
		t = f + IDATA_RAW + (ilt2 - IDATA_RVA);
		if (plus) w64(t, nm[2]); else w32(t, nm[2]);
		t = f + IDATA_RAW + (iat1 - IDATA_RVA);
		if (plus) { w64(t, nm[0]); w64(t + 8, nm[1]); } else { w32(t, nm[0]); w32(t + 4, nm[1]); }
		t = f + IDATA_RAW + (iat2 - IDATA_RVA);
		if (plus) w64(t, nm[2]); else w32(t, nm[2]);
	}

	/* .data: absolute pointers to the code, the string and the IAT, each covered by a relocation */
	{
		uint8_t *d = f + DATA_RAW;
		const uint64_t targets[4] = { base + TEXT_RVA, base + RDATA_RVA, base + IDATA_RVA + 0x80u,
					      base + DATA_RVA + 0x100u };

		for (i = 0; i < 4; i++) {
			if (plus) w64(d + i * 8u, targets[i]); else w32(d + i * 4u, (uint32_t)targets[i]);
			fixes[n_fix].rva = DATA_RVA + i * step;
			fixes[n_fix++].type = reloc_type;
		}
		memcpy(d + 0x100, "kofeng-data", 12);
	}

	/* .text: calls through the IAT and loads of absolute data addresses */
	at = TEXT_RAW;
	if (plus) {
		/* call [rip+rel] to the IAT slot, twice, then lea/mov that need no relocation, then an abs mov */
		static const uint8_t pro[] = { 0x48, 0x83, 0xec, 0x28 };

		memcpy(f + at, pro, sizeof pro);
		at += sizeof pro;
		for (i = 0; i < 2; i++) {
			uint32_t rip = TEXT_RVA + (at - TEXT_RAW) + 6u;

			f[at] = 0xff; f[at + 1] = 0x15;
			w32(f + at + 2, (IDATA_RVA + 0x80u + i * 8u) - rip);
			at += 6;
		}
		f[at] = 0x48; f[at + 1] = 0xb8;                 /* mov rax, imm64 : an absolute pointer */
		w64(f + at + 2, base + DATA_RVA);
		fixes[n_fix].rva = TEXT_RVA + (at + 2u - TEXT_RAW);
		fixes[n_fix++].type = reloc_type;
		at += 10;
		f[at++] = 0x48; f[at++] = 0x83; f[at++] = 0xc4; f[at++] = 0x28;
		f[at++] = 0xc3;
	} else {
		f[at++] = 0x55; f[at++] = 0x8b; f[at++] = 0xec;
		for (i = 0; i < 2; i++) {
			f[at] = 0xff; f[at + 1] = 0x15;             /* call dword ptr [IAT slot] */
			w32(f + at + 2, (uint32_t)(base + IDATA_RVA + 0x80u + i * 4u));
			fixes[n_fix].rva = TEXT_RVA + (at + 2u - TEXT_RAW);
			fixes[n_fix++].type = reloc_type;
			at += 6;
		}
		f[at] = 0xa1;                                   /* mov eax, [absolute] */
		w32(f + at + 1, (uint32_t)(base + DATA_RVA));
		fixes[n_fix].rva = TEXT_RVA + (at + 1u - TEXT_RAW);
		fixes[n_fix++].type = reloc_type;
		at += 5;
		f[at] = 0x68;                                   /* push offset string */
		w32(f + at + 1, (uint32_t)(base + RDATA_RVA));
		fixes[n_fix].rva = TEXT_RVA + (at + 1u - TEXT_RAW);
		fixes[n_fix++].type = reloc_type;
		at += 5;
		f[at++] = 0x5d; f[at++] = 0xc3;
	}
	while (at < TEXT_RAW + 0x200u)
		f[at++] = 0xcc;

	/* .reloc: one block per 4 KiB page, entries sorted, padded to four bytes with an ABSOLUTE entry */
	{
		uint8_t *r = f + RELOC_RAW;
		uint32_t pos = 0, page;

		for (page = TEXT_RVA; page <= DATA_RVA; page += 0x2000u) {
			uint32_t blk = pos, ents = 0;
			unsigned k;

			pos += 8;
			for (k = 0; k < n_fix; k++)
				if ((fixes[k].rva & ~0xfffu) == page) {
					w16(r + pos, (uint16_t)((uint32_t)fixes[k].type << 12 | (fixes[k].rva & 0xfffu)));
					pos += 2;
					ents++;
				}
			if (ents & 1u) {
				w16(r + pos, 0);                /* IMAGE_REL_BASED_ABSOLUTE */
				pos += 2;
			}
			w32(r + blk, page);
			w32(r + blk + 4, pos - blk);
		}
		w32(f + opt + (plus ? 112u : 96u) + 5 * 8 + 4, pos);
	}

	o = fopen(path, "wb");
	if (!o)
		return 0;
	if (fwrite(f, 1, sizeof f, o) != sizeof f) {
		fclose(o);
		return 0;
	}
	return fclose(o) == 0;
}

int main(int argc, char **argv)
{
	char path[1024];
	int rc = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: mkpe <output-dir>\n");
		return 2;
	}
	snprintf(path, sizeof path, "%s/synth-pe32.exe", argv[1]);
	if (!build(path, 0)) {
		fprintf(stderr, "mkpe: cannot write %s\n", path);
		rc = 1;
	}
	snprintf(path, sizeof path, "%s/synth-pe64.exe", argv[1]);
	if (!build(path, 1)) {
		fprintf(stderr, "mkpe: cannot write %s\n", path);
		rc = 1;
	}
	return rc;
}
