/*
 * image_kit.h - small, honest builders for the round-2 image tests (image_defect2.c, image_pe_attack.c):
 * a PE and an ELF written from field values the test names, so the oracle of a check is the number the
 * test wrote and not what the code under test computed. Header only, every helper static.
 */
#ifndef KGENOME_TESTS_IMAGE_KIT_H
#define KGENOME_TESTS_IMAGE_KIT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline void ik_w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void ik_w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void ik_w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
static inline void ik_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void ik_be32(uint8_t *p, uint32_t v) { ik_be16(p, (uint16_t)(v >> 16)); ik_be16(p + 2, (uint16_t)v); }
static inline void ik_be64(uint8_t *p, uint64_t v) { ik_be32(p, (uint32_t)(v >> 32)); ik_be32(p + 4, (uint32_t)v); }

/* ---- PE -------------------------------------------------------------------------------------- */

struct ik_sec {
	char     name[9];
	uint32_t vsize, rva, rsize, raw, chars;
};

struct ik_pe {
	int      plus;
	uint16_t machine;               /* 0: the width's own */
	uint32_t lfanew;                /* 0: 0x80 */
	uint32_t optsz;                 /* 0: 224 / 240 */
	uint32_t nsec_claim;            /* 0: n */
	unsigned n;
	struct ik_sec s[100];
	uint32_t dir_rva[16], dir_size[16];
	uint32_t n_dirs;                /* 0: 16 */
	uint32_t entry;
	uint64_t image_base;            /* 0: 0x400000 / 0x140000000 */
	uint32_t size_of_image, size_of_headers, file_align, sec_align;
	uint16_t characteristics;       /* 0: 0x0102 / 0x0022 */
	uint16_t subsystem;             /* 0: 3 */
	uint16_t dll_chars;
	uint32_t timestamp;
	uint32_t size_of_code;
};

/* Writes the headers and the section table into `b` (zeroed by the caller, `cap` bytes). Returns the
 * offset where the section table ends. */
static inline uint32_t ik_pe_write(uint8_t *b, const struct ik_pe *p)
{
	const uint32_t nt = p->lfanew ? p->lfanew : 0x80u;
	const uint32_t optsz = p->optsz ? p->optsz : (p->plus ? 240u : 224u);
	const uint32_t opt = nt + 24u, sec = opt + optsz;
	const uint32_t cnt_off = p->plus ? 108u : 92u, dir_off = p->plus ? 112u : 96u;
	unsigned i;

	b[0] = 'M'; b[1] = 'Z';
	ik_w32(b + 0x3c, nt);
	memcpy(b + 0x40, "\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$", 53);
	memcpy(b + nt, "PE\0\0", 4);
	ik_w16(b + nt + 4, p->machine ? p->machine : (p->plus ? 0x8664u : 0x14cu));
	ik_w16(b + nt + 6, (uint16_t)(p->nsec_claim ? p->nsec_claim : p->n));
	ik_w32(b + nt + 8, p->timestamp);
	ik_w16(b + nt + 20, (uint16_t)optsz);
	ik_w16(b + nt + 22, p->characteristics ? p->characteristics : (p->plus ? 0x0022u : 0x0102u));
	ik_w16(b + opt, p->plus ? 0x20bu : 0x10bu);
	ik_w32(b + opt + 4, p->size_of_code);
	ik_w32(b + opt + 16, p->entry);
	if (p->plus)
		ik_w64(b + opt + 24, p->image_base ? p->image_base : 0x140000000ull);
	else
		ik_w32(b + opt + 28, (uint32_t)(p->image_base ? p->image_base : 0x400000ull));
	ik_w32(b + opt + 32, p->sec_align ? p->sec_align : 0x1000u);
	ik_w32(b + opt + 36, p->file_align ? p->file_align : 0x200u);
	ik_w32(b + opt + 56, p->size_of_image);
	ik_w32(b + opt + 60, p->size_of_headers);
	ik_w16(b + opt + 68, p->subsystem ? p->subsystem : 3u);
	ik_w16(b + opt + 70, p->dll_chars);
	ik_w32(b + opt + cnt_off, p->n_dirs ? p->n_dirs : 16u);
	for (i = 0; i < 16u; i++) {
		if (dir_off + 8u * (i + 1u) > optsz)
			break;
		ik_w32(b + opt + dir_off + 8u * i, p->dir_rva[i]);
		ik_w32(b + opt + dir_off + 8u * i + 4u, p->dir_size[i]);
	}
	for (i = 0; i < p->n; i++) {
		uint8_t *s = b + sec + 40u * i;

		memcpy(s, p->s[i].name, strnlen(p->s[i].name, 8));
		ik_w32(s + 8, p->s[i].vsize);
		ik_w32(s + 12, p->s[i].rva);
		ik_w32(s + 16, p->s[i].rsize);
		ik_w32(s + 20, p->s[i].raw);
		ik_w32(s + 36, p->s[i].chars);
	}
	return sec + 40u * p->n;
}

static inline void ik_sec(struct ik_pe *p, const char *name, uint32_t vsize, uint32_t rva, uint32_t rsize,
			  uint32_t raw, uint32_t chars)
{
	struct ik_sec *s = &p->s[p->n++];

	snprintf(s->name, sizeof s->name, "%s", name);
	s->vsize = vsize; s->rva = rva; s->rsize = rsize; s->raw = raw; s->chars = chars;
}

#define IK_TEXT  0x60000020u   /* code, execute, read */
#define IK_DATA  0xc0000040u   /* initialised data, read, write */
#define IK_RDATA 0x40000040u
#define IK_RELOC 0x42000040u

#endif
