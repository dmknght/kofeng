/*
 * cov_fixtures_ole.h - a writer of OLE compound documents with a VBA project (cov_docole_real.c, cov_oom_formats.c).
 *
 * Header, FAT, a directory linked as the tree the format has, a mini stream behind a mini FAT for the small streams
 * (the OVBA coded `dir`, the module with its compiled prefix, _VBA_PROJECT) and ordinary sectors for a 5000 byte
 * body. build() fills a struct doc; the pieces a test bends (first_big, sizes, links) are at fixed places.
 */
#ifndef COV_FIXTURES_OLE_H
#define COV_FIXTURES_OLE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/uncoat/hostile_enc.h"

#define SEC 512u
#define NOSTREAM 0xffffffffu
#define ENDCHAIN 0xfffffffeu
#define FATSECT  0xfffffffdu

static inline void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

struct dent {
	const char *name;
	uint8_t     type;                /* 1 storage, 2 stream, 5 root */
	uint32_t    left, right, child;
	uint32_t    start;
	uint64_t    size;
};

static inline void put_dent(uint8_t *e, const struct dent *d)
{
	size_t i, n = strlen(d->name);

	memset(e, 0, 128);
	for (i = 0; i < n; i++)
		w16(e + 2 * i, (uint8_t)d->name[i]);
	/* names that start with 0x05 are property sets: written as the bytes they are */
	w16(e + 64, (uint16_t)((n + 1) * 2));
	e[66] = d->type;
	e[67] = 1;
	w32(e + 68, d->left);
	w32(e + 72, d->right);
	w32(e + 76, d->child);
	w32(e + 116, d->start);
	w64(e + 120, d->size);
}

static const char SRC[] = "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n    MsgBox \"hello from the macro\"\r\nEnd Sub\r\n";

/* the pieces a test can bend */
struct doc {
	uint8_t  bytes[SEC * 40];
	size_t   len;
	uint8_t  dir_plain[256];
	size_t   dir_plain_len;
	uint8_t  body[5000];
	uint32_t first_big;
};

static inline size_t record(uint8_t *p, unsigned id, const void *d, uint32_t n)
{
	w16(p, (uint16_t)id);
	w32(p + 2, n);
	if (n)
		memcpy(p + 6, d, n);
	return 6u + n;
}

static inline void build(struct doc *D)
{
	uint8_t *f = D->bytes;
	uint8_t dir_c[512], mod[512], proj[16], mini[4096];
	size_t dir_c_len, mod_len = 0, n_mini = 0, i;
	uint8_t unicode_name[14];
	uint32_t off = 40;
	size_t d = 0;
	uint32_t mini_sectors, mini_bytes, ms_dir, ms_mod, ms_proj, first_big, n_big_sec;
	struct dent e[8];
	uint32_t fat[128];
	uint32_t mfat[128];

	memset(f, 0, sizeof D->bytes);
	/* dir: the module name record, the unicode form, then the offset record */
	for (i = 0; i < 7; i++) {
		unicode_name[2 * i] = (uint8_t)"Module1"[i];
		unicode_name[2 * i + 1] = 0;
	}
	d += record(D->dir_plain + d, 0x1a, "Module1", 7);
	d += record(D->dir_plain + d, 0x32, unicode_name, 14);
	d += record(D->dir_plain + d, 0x31, &off, 4);
	D->dir_plain_len = d;
	dir_c_len = hv_ovba_enc(D->dir_plain, d, dir_c, sizeof dir_c);
	/* the module: forty bytes of compiled code, then the container of the source */
	memset(mod, 0x00, 40);
	mod[0] = 0x01; mod[1] = 0x16; mod[2] = 0x01;
	mod_len = 40 + hv_ovba_enc((const uint8_t *)SRC, sizeof SRC - 1, mod + 40, sizeof mod - 40);
	memcpy(proj, "\xcc\x61\xff\xff\x00\x00\x00", 7);
	for (i = 0; i < sizeof D->body; i++)
		D->body[i] = (uint8_t)("WordDocument text body "[i % 23]);

	/* the mini stream: each stream rounded up to 64 byte mini sectors */
	ms_dir = 0;
	memset(mini, 0, sizeof mini);
	memcpy(mini, dir_c, dir_c_len);
	n_mini = (dir_c_len + 63u) / 64u;
	ms_mod = (uint32_t)n_mini;
	memcpy(mini + ms_mod * 64u, mod, mod_len);
	n_mini += (mod_len + 63u) / 64u;
	ms_proj = (uint32_t)n_mini;
	memcpy(mini + ms_proj * 64u, proj, 7);
	n_mini += 1;
	mini_bytes = (uint32_t)n_mini * 64u;
	mini_sectors = (mini_bytes + SEC - 1u) / SEC;
	first_big = 4u + mini_sectors;
	D->first_big = first_big;
	n_big_sec = (uint32_t)((sizeof D->body + SEC - 1u) / SEC);

	/* header */
	memcpy(f, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8);
	w16(f + 24, 0x3e);
	w16(f + 26, 3);
	w16(f + 28, 0xfffe);
	w16(f + 30, 9);
	w16(f + 32, 6);
	w32(f + 44, 1);                          /* one FAT sector */
	w32(f + 48, 1);                          /* the directory starts at sector 1 */
	w32(f + 56, 4096);                       /* mini cutoff */
	w32(f + 60, 3);                          /* the miniFAT at sector 3 */
	w32(f + 64, 1);
	w32(f + 68, ENDCHAIN);                   /* no DIFAT sectors */
	w32(f + 72, 0);
	w32(f + 76, 0);                          /* DIFAT[0]: the FAT is sector 0 */
	for (i = 1; i < 109; i++)
		w32(f + 76 + 4 * i, NOSTREAM);

	/* the FAT */
	for (i = 0; i < 128; i++)
		fat[i] = NOSTREAM;
	fat[0] = FATSECT;
	fat[1] = 2;
	fat[2] = ENDCHAIN;
	fat[3] = ENDCHAIN;
	for (i = 0; i < mini_sectors; i++)
		fat[4 + i] = i + 1 < mini_sectors ? 4u + (uint32_t)i + 1u : ENDCHAIN;
	for (i = 0; i < n_big_sec; i++)
		fat[first_big + i] = i + 1 < n_big_sec ? first_big + (uint32_t)i + 1u : ENDCHAIN;
	memcpy(f + SEC * 1, fat, sizeof fat);    /* sector 0 starts at file offset 512 */

	/* the miniFAT: three chains */
	for (i = 0; i < 128; i++)
		mfat[i] = NOSTREAM;
	for (i = 0; i < (dir_c_len + 63u) / 64u; i++)
		mfat[ms_dir + i] = i + 1 < (dir_c_len + 63u) / 64u ? ms_dir + (uint32_t)i + 1u : ENDCHAIN;
	for (i = 0; i < (mod_len + 63u) / 64u; i++)
		mfat[ms_mod + i] = i + 1 < (mod_len + 63u) / 64u ? ms_mod + (uint32_t)i + 1u : ENDCHAIN;
	mfat[ms_proj] = ENDCHAIN;
	memcpy(f + SEC * (3 + 1), mfat, sizeof mfat);

	/* the directory (sectors 1 and 2): the tree */
	memset(e, 0, sizeof e);
	e[0] = (struct dent){ "Root Entry", 5, NOSTREAM, NOSTREAM, 1, 4u, mini_bytes };
	e[1] = (struct dent){ "VBA", 1, NOSTREAM, 5, 2, 0, 0 };
	e[2] = (struct dent){ "dir", 2, NOSTREAM, 3, NOSTREAM, ms_dir, dir_c_len };
	e[3] = (struct dent){ "Module1", 2, NOSTREAM, 4, NOSTREAM, ms_mod, mod_len };
	e[4] = (struct dent){ "_VBA_PROJECT", 2, NOSTREAM, NOSTREAM, NOSTREAM, ms_proj, 7 };
	e[5] = (struct dent){ "WordDocument", 2, NOSTREAM, NOSTREAM, NOSTREAM, first_big, sizeof D->body };
	for (i = 0; i < 6; i++)
		put_dent(f + SEC * (1 + 1) + 128 * i, &e[i]);
	for (i = 6; i < 8; i++) {
		memset(f + SEC * (1 + 1) + 128 * i, 0, 128);
		w32(f + SEC * (1 + 1) + 128 * i + 68, NOSTREAM);
		w32(f + SEC * (1 + 1) + 128 * i + 72, NOSTREAM);
		w32(f + SEC * (1 + 1) + 128 * i + 76, NOSTREAM);
	}
	/* the mini stream's container, then the body */
	memcpy(f + SEC * (4 + 1), mini, mini_bytes);
	memcpy(f + SEC * (first_big + 1), D->body, sizeof D->body);
	D->len = SEC * (first_big + 1 + n_big_sec);
}


#endif /* COV_FIXTURES_OLE_H */
