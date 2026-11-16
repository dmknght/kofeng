/*
 * norm_elf_fx.h - the ELF counterpart of norm_pe_fx.h: a minimal, REAL ELF64
 * ET_EXEC with one or more PROGBITS code sections, each its own PT_LOAD segment
 * (so each is its own disjoint KGENOME_SCAN_ELF_CODE extent, PT_LOAD with PF_X -
 * elf_parse.c's elf_resolve_scan reads the CODE mask off segments, not sections),
 * holding a nop run, a UTF-16LE string and a zero run, plus a data section with a
 * wide string of its own. The caller picks each code section's sh_flags
 * (ELF_SHF_RX for ordinary read-only code, ELF_SHF_RWX for a section that is ALSO
 * writable - the E-RWX shape, libkofeng/scanners/scan_norm_text.c's
 * sx_norm_keep_exec, merge 149): read-only code is kept whole in the normalised
 * view: ordinary code is kept whole in the normalised view (its wide string
 * stays wide); RWX code is narrowed exactly like PE's writable .text already is
 * (sx_norm_keep_exec_pe) - a program that rewrites its own code at run time is
 * not an instruction stream only.
 *
 * This header only BUILDS the bytes; driving them through the real engine
 * (kscan_bytes -> the normalised child -> the view's bytes) is the caller's job,
 * exactly as norm_pe_fx.h's own build_pe is driven by norm_defect_engine.c's
 * vscan/view_of/count_of - which is why the ELF-RWX end-to-end case is added
 * there (erwx_elf_narrow) rather than duplicating that harness in a new file.
 */
#ifndef KOFENG_TESTS_NORM_ELF_FX_H
#define KOFENG_TESTS_NORM_ELF_FX_H

#include <stdint.h>
#include <string.h>

/* ---- an ELF64 ET_EXEC with N code sections (each its own PT_LOAD), a gap between
 * their file extents, and a data section -------------------------------------- */

#define ELF_FX_MAX (0x1000u + 16u * 0x400u)

#define ELF_EBASE   0x400000ull
#define ELF_HDR_END 0x1000u          /* first section's file offset: headers fit well inside it, the
				       * rest is padding - also clears NORM_MIN_OBJ (4 KiB) on its own,
				       * same trick build_pe's hdr=0x1000 uses */

/* sh_flags: SHF_ALLOC|SHF_EXECINSTR, and the same with SHF_WRITE added (the E-RWX shape) */
#define ELF_SHF_RX  0x6ull
#define ELF_SHF_RWX 0x7ull

static inline void ew16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void ew32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void ew64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* the body of one code section: 64 nops, 64 zeros, a UTF-16LE string, 64 zeros (224 bytes) -
 * byte-for-byte the same shape norm_pe_fx.h's sec_body builds, under its own name so the
 * two headers can be included in the same translation unit without colliding. */
#define ELFSEC_LEN 224u
#define ELF_WIDE_TXT "ABCDEFGHIJKLMNOP"

static inline void elf_sec_body(uint8_t *b)
{
	unsigned i;

	memset(b, 0, ELFSEC_LEN);
	memset(b, 0x90, 64);
	for (i = 0; i < 16u; i++)
		b[128u + 2u * i] = (uint8_t)ELF_WIDE_TXT[i];
}

/*
 * Builds the file into `out` (ELF_FX_MAX bytes), `ncode` code sections each with
 * sh_flags `shflags` (ELF_SHF_RX or ELF_SHF_RWX). Layout:
 *
 *   [0, 64)                       ELF64 header
 *   [64, 64+(ncode+1)*56)         program headers: ncode PT_LOAD R+X (or R+W+X when
 *                                 shflags carries WRITE) code segments, one PT_LOAD
 *                                 R+W data segment
 *   [.., ELF_HDR_END)             zero padding (unclaimed; also clears NORM_MIN_OBJ)
 *   N * (ELFSEC_LEN + gap)        one PT_LOAD/section per code body, non-contiguous
 *                                 file extents so each is its own CODE region, same
 *                                 as build_pe's per-section 0x100 gap
 *   data section                  zeros, a wide URL string, zeros (mirrors build_pe)
 *   .shstrtab                     section name strings
 *   section header table          null, N code sections, .data, .shstrtab
 *
 * Returns the file's total length.
 */
static inline uint32_t build_elf(uint8_t *out, unsigned ncode, uint64_t shflags)
{
	const char *dw = "http://wide.example/payload.bin";
	const uint32_t gap = 0x100u, phoff = 64u, phentsize = 56u;
	const uint32_t seg_flags = (shflags & 1u) ? 7u /* R+W+X */ : 5u /* R+X */;
	uint32_t rp = ELF_HDR_END, i, k, data_rp, datalen, shstr_off, sh_off, shstr_n;
	uint32_t name_off[64], at = 1;
	char shstrtab[64 * 8 + 32];
	uint8_t *dp;

	memset(out, 0, ELF_FX_MAX);

	/* ---- code sections and their PT_LOAD segments ---- */
	for (i = 0; i < ncode; i++) {
		const uint32_t ph = phoff + i * phentsize;
		const uint64_t vaddr = ELF_EBASE + 0x1000ull + (uint64_t)i * 0x1000ull;

		ew32(out + ph, 1);                      /* p_type: PT_LOAD */
		ew32(out + ph + 4, seg_flags);
		ew64(out + ph + 8, rp);                 /* p_offset */
		ew64(out + ph + 16, vaddr);              /* p_vaddr */
		ew64(out + ph + 24, vaddr);              /* p_paddr */
		ew64(out + ph + 32, ELFSEC_LEN);        /* p_filesz */
		ew64(out + ph + 40, ELFSEC_LEN);        /* p_memsz */
		ew64(out + ph + 48, 0x1000);              /* p_align */
		elf_sec_body(out + rp);
		rp += ELFSEC_LEN + gap;
	}

	/* ---- data section: zeros, a wide string, zeros (mirrors build_pe's .data) ---- */
	data_rp = rp;
	dp = out + data_rp + 64u;
	for (k = 0; dw[k]; k++)
		dp[2u * k] = (uint8_t)dw[k];
	datalen = 64u + 2u * k + 200u;
	{
		const uint32_t ph = phoff + ncode * phentsize;
		const uint64_t vaddr = ELF_EBASE + 0x700000ull;

		ew32(out + ph, 1);                      /* p_type: PT_LOAD */
		ew32(out + ph + 4, 6);                   /* p_flags: R+W, no X */
		ew64(out + ph + 8, data_rp);
		ew64(out + ph + 16, vaddr);
		ew64(out + ph + 24, vaddr);
		ew64(out + ph + 32, datalen);
		ew64(out + ph + 40, datalen);
		ew64(out + ph + 48, 0x1000);
	}
	rp = data_rp + datalen;

	/* ---- .shstrtab ---- */
	shstrtab[0] = 0;
	for (i = 0; i < ncode; i++) {
		int n = snprintf(shstrtab + at, sizeof shstrtab - at, ".t%02u", i);

		name_off[i] = at;
		at += (uint32_t)n + 1;
	}
	{
		int n;

		n = snprintf(shstrtab + at, sizeof shstrtab - at, ".data");
		name_off[ncode] = at;
		at += (uint32_t)n + 1u;
		n = snprintf(shstrtab + at, sizeof shstrtab - at, ".shstrtab");
		name_off[ncode + 1u] = at;
		at += (uint32_t)n + 1u;
	}
	shstr_n = at;
	shstr_off = (rp + 7u) & ~7u;
	memcpy(out + shstr_off, shstrtab, shstr_n);
	rp = shstr_off + shstr_n;

	/* ---- section header table: null, N code, .data, .shstrtab ---- */
	sh_off = (rp + 7u) & ~7u;
	{
		const uint32_t nsh = ncode + 3u;

		memset(out + sh_off, 0, nsh * 64u);
		for (i = 0; i < ncode; i++) {
			const uint32_t sh = sh_off + (1u + i) * 64u;
			const uint64_t vaddr = ELF_EBASE + 0x1000ull + (uint64_t)i * 0x1000ull;
			const uint32_t off = ELF_HDR_END + i * (ELFSEC_LEN + gap);

			ew32(out + sh, name_off[i]);
			ew32(out + sh + 4, 1);               /* sh_type: SHT_PROGBITS */
			ew64(out + sh + 8, shflags);
			ew64(out + sh + 16, vaddr);
			ew64(out + sh + 24, off);
			ew64(out + sh + 32, ELFSEC_LEN);
			ew64(out + sh + 48, 1);              /* sh_addralign */
		}
		{
			const uint32_t sh = sh_off + (1u + ncode) * 64u;
			const uint64_t vaddr = ELF_EBASE + 0x700000ull;

			ew32(out + sh, name_off[ncode]);
			ew32(out + sh + 4, 1);               /* SHT_PROGBITS */
			ew64(out + sh + 8, 3);               /* SHF_ALLOC|SHF_WRITE */
			ew64(out + sh + 16, vaddr);
			ew64(out + sh + 24, data_rp);
			ew64(out + sh + 32, datalen);
			ew64(out + sh + 48, 1);
		}
		{
			const uint32_t sh = sh_off + (2u + ncode) * 64u;

			ew32(out + sh, name_off[ncode + 1u]);
			ew32(out + sh + 4, 3);               /* SHT_STRTAB */
			ew64(out + sh + 24, shstr_off);
			ew64(out + sh + 32, shstr_n);
			ew64(out + sh + 48, 1);
		}
	}

	/* ---- ELF header ---- */
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = 2; out[5] = 1; out[6] = 1;                      /* ELFCLASS64, ELFDATA2LSB, EV_CURRENT */
	ew16(out + 16, 2);                                        /* e_type: ET_EXEC */
	ew16(out + 18, 62);                                       /* e_machine: EM_X86_64 */
	ew32(out + 20, 1);                                        /* e_version */
	ew64(out + 24, ELF_EBASE + 0x1000ull);                    /* e_entry: first code section */
	ew64(out + 32, phoff);                                    /* e_phoff */
	ew16(out + 52, 64);                                       /* e_ehsize */
	ew16(out + 54, (uint16_t)phentsize);
	ew16(out + 56, (uint16_t)(ncode + 1u));                   /* e_phnum */
	ew64(out + 40, sh_off);                                   /* e_shoff */
	ew16(out + 58, 64);                                       /* e_shentsize */
	ew16(out + 60, (uint16_t)(ncode + 3u));                   /* e_shnum */
	ew16(out + 62, (uint16_t)(ncode + 2u));                   /* e_shstrndx */

	return sh_off + (ncode + 3u) * 64u;
}

#endif
