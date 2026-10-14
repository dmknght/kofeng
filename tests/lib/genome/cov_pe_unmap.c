/*
 * cov_pe_unmap - kgenome_pe_unmap: a mapped image put back to the file it was mapped from, built in memory.
 *
 * The same round trip the unit test makes from fixture binaries (which a host without a Windows
 * toolchain does not have), here from a PE32 and a PE32+ written byte by byte:
 *
 *   file --(laid out at the section RVAs)--> image --(relocated by +D, ImageBase rewritten as the
 *   loader does)--> kgenome_pe_unmap --> the file again
 *
 * and the comparison is with the FILE, whose pointers were chosen here, so a relocation table that
 * is skipped, applied twice or applied to the wrong place shows as bytes that are still moved.
 * Asserted: byte identity of every section and of the headers (ImageBase put back), the counters
 * (what was undone, what was skipped and why), the three states of the base (told, derived from the
 * header, ambiguous), a section whose virtual size is larger than its file bytes (a relocation in the
 * zero-filled tail has no file offset and is skipped, never written to the byte after the section),
 * a cap, and hostile tables: a block that does not advance, a block longer than the table, a table that
 * is outside the image, truncated entries, an unsupported type. Every cut of the image under a guard
 * page and a few thousand flipped bits.
 */

#include <kgenome.h>

#include "hk.h"

#define HDRS  0x200u
#define TEXT_RVA 0x1000u
#define DATA_RVA 0x2000u
#define REL_RVA  0x3000u
#define IMG_SIZE 0x4000u
#define FILE_SIZE 0x800u         /* headers 0x200, .text 0x200, .data 0x200, .reloc 0x200 */
#define DELTA 0x13370000ull

struct spec {
	int      plus;
	uint64_t base;
	uint32_t n_ptr_text, n_ptr_data;
	uint32_t want_undone, want_skipped;
};

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* where the pointers sit, as offsets in the section, and how many entries of each kind the table holds */
static const uint32_t TEXT_PTR[] = { 0x10, 0x48, 0x100, 0x1f0 };     /* 0x1f0 + 8 = 0x1f8 < 0x200 */
static const uint32_t DATA_PTR[] = { 0x20, 0x40, 0x180 };
#define NTEXT (sizeof TEXT_PTR / sizeof TEXT_PTR[0])
#define NDATA (sizeof DATA_PTR / sizeof DATA_PTR[0])

static size_t put_entry(uint8_t *p, uint16_t type, uint16_t off)
{
	w16(p, (uint16_t)(type << 12 | (off & 0xfffu)));
	return 2;
}

/* build the file; fills `s` with what the table implies */
static void build_file(uint8_t *f, struct spec *s)
{
	struct hk_rng r = { 0x5ca1ab1e12345678ull ^ (uint64_t)(unsigned)s->plus };
	uint8_t *opt, *sec, *rel;
	uint32_t i, psz = s->plus ? 8u : 4u, type = s->plus ? 10u : 3u;
	size_t k;

	memset(f, 0, FILE_SIZE);
	for (i = HDRS; i < HDRS + 0x600; i++)
		f[i] = (uint8_t)hk_next(&r);
	f[0] = 'M'; f[1] = 'Z';
	w32(f + 0x3c, 0x80);
	memcpy(f + 0x80, "PE\0\0", 4);
	w16(f + 0x84, s->plus ? 0x8664 : 0x14c);
	w16(f + 0x86, 3);
	w16(f + 0x94, s->plus ? 240 : 224);
	opt = f + 0x98;
	w16(opt, s->plus ? 0x20b : 0x10b);
	if (s->plus)
		w64(opt + 24, s->base);
	else
		w32(opt + 28, (uint32_t)s->base);
	w32(opt + 32, 0x1000);
	w32(opt + 36, 0x200);
	w32(opt + 56, IMG_SIZE);
	w32(opt + 60, HDRS);
	w32(s->plus ? opt + 108 : opt + 92, 16);
	/* the base relocation directory */
	w32(opt + (s->plus ? 112 : 96) + 5 * 8, REL_RVA);
	sec = opt + (s->plus ? 240 : 224);
	memcpy(sec, ".text", 5);   w32(sec + 8, 0x800); w32(sec + 12, TEXT_RVA); w32(sec + 16, 0x200); w32(sec + 20, 0x200);
	sec += 40;
	memcpy(sec, ".data", 5);   w32(sec + 8, 0x1000); w32(sec + 12, DATA_RVA); w32(sec + 16, 0x200); w32(sec + 20, 0x400);
	sec += 40;
	memcpy(sec, ".reloc", 6);  w32(sec + 8, 0x80); w32(sec + 12, REL_RVA); w32(sec + 16, 0x200); w32(sec + 20, 0x600);

	/* the pointers: every one is base + something, as the linker wrote it */
	for (i = 0; i < NTEXT; i++) {
		uint64_t v = s->base + 0x1000u + 8u * i + 0x11u;

		if (s->plus)
			w64(f + 0x200 + TEXT_PTR[i], v);
		else
			w32(f + 0x200 + TEXT_PTR[i], (uint32_t)v);
	}
	for (i = 0; i < NDATA; i++) {
		uint64_t v = s->base + 0x2000u + 8u * i + 0x23u;

		if (s->plus)
			w64(f + 0x400 + DATA_PTR[i], v);
		else
			w32(f + 0x400 + DATA_PTR[i], (uint32_t)v);
	}
	/* the table. page 0x1000: four pointers and an ABSOLUTE padding entry; page 0x2000: three pointers, one
	 * in the zero-filled tail of .data (RVA 0x2300: no file bytes), one of a type this does not handle (HIGH,
	 * 1), one in no section at all (RVA 0x5000) */
	rel = f + 0x600;
	k = 0;
	w32(rel + k, TEXT_RVA); k += 4;
	w32(rel + k, 8u + 2u * (NTEXT + 1u)); k += 4;
	for (i = 0; i < NTEXT; i++)
		k += put_entry(rel + k, (uint16_t)type, (uint16_t)TEXT_PTR[i]);
	k += put_entry(rel + k, 0, 0);
	w32(rel + k, DATA_RVA); k += 4;
	w32(rel + k, 8u + 2u * (NDATA + 2u)); k += 4;
	for (i = 0; i < NDATA; i++)
		k += put_entry(rel + k, (uint16_t)type, (uint16_t)DATA_PTR[i]);
	k += put_entry(rel + k, (uint16_t)type, 0x300);       /* the zero-filled tail */
	k += put_entry(rel + k, 1, 0x60);                     /* IMAGE_REL_BASED_HIGH: not handled */
	w32(rel + k, 0x5000); k += 4;
	w32(rel + k, 8u + 2u * 2u); k += 4;
	k += put_entry(rel + k, (uint16_t)type, 0x10);        /* a page no section holds */
	k += put_entry(rel + k, 0, 0);
	w32(opt + (s->plus ? 112 : 96) + 5 * 8 + 4, (uint32_t)k);
	(void)psz;
	s->n_ptr_text = NTEXT;
	s->n_ptr_data = NDATA;
	s->want_undone = NTEXT + NDATA;
	s->want_skipped = 3;         /* the tail, the HIGH, the page with no section */
}

/* the image the loader would leave at base + D */
static void map_image(const uint8_t *f, uint8_t *img, const struct spec *s, uint64_t delta, int rewrite_base)
{
	uint32_t i, psz = s->plus ? 8u : 4u;
	const uint8_t *opt = f + 0x98;

	memset(img, 0, IMG_SIZE);
	memcpy(img, f, HDRS);
	memcpy(img + TEXT_RVA, f + 0x200, 0x200);
	memcpy(img + DATA_RVA, f + 0x400, 0x200);
	memcpy(img + REL_RVA, f + 0x600, 0x200);
	(void)opt;
	for (i = 0; i < NTEXT; i++) {
		uint8_t *p = img + TEXT_RVA + TEXT_PTR[i];

		if (psz == 8) { uint64_t v; memcpy(&v, p, 8); v += delta; memcpy(p, &v, 8); }
		else          { uint32_t v; memcpy(&v, p, 4); v += (uint32_t)delta; memcpy(p, &v, 4); }
	}
	for (i = 0; i < NDATA; i++) {
		uint8_t *p = img + DATA_RVA + DATA_PTR[i];

		if (psz == 8) { uint64_t v; memcpy(&v, p, 8); v += delta; memcpy(p, &v, 8); }
		else          { uint32_t v; memcpy(&v, p, 4); v += (uint32_t)delta; memcpy(p, &v, 4); }
	}
	if (rewrite_base) {
		if (s->plus)
			w64(img + 0x98 + 24, s->base + delta);
		else
			w32(img + 0x98 + 28, (uint32_t)(s->base + delta));
	}
}

static kof_buf kb(const uint8_t *p, uint64_t n)
{
	kof_buf b;

	b.p = p;
	b.n = n;
	return b;
}

static void t_roundtrip(int plus)
{
	static uint8_t file[FILE_SIZE], img[IMG_SIZE];
	struct spec s;
	uint8_t *out = NULL;
	uint64_t out_len = 0;
	struct kgenome_pe_unmap_info ui;
	const char *nm = plus ? "pe32+" : "pe32";

	memset(&s, 0, sizeof s);
	s.plus = plus;
	s.base = plus ? 0x140000000ull : 0x400000ull;
	build_file(file, &s);

	/* 1. the base is TOLD: the delta rests on it, the header base is put back, every pointer too */
	map_image(file, img, &s, DELTA, 1);
	CK(kgenome_pe_unmap(kb(img, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui));
	CK(out != NULL && out_len == FILE_SIZE);
	if (out && out_len == FILE_SIZE) {
		CK(!memcmp(out, file, HDRS));
		CK(!memcmp(out + 0x200, file + 0x200, 0x200));
		CK(!memcmp(out + 0x400, file + 0x400, 0x200));
		CK(!memcmp(out + 0x600, file + 0x600, 0x200));
	}
	CK(ui.relocs_undone == s.want_undone);
	CK(ui.relocs_skipped == s.want_skipped);
	CK(ui.sections == 3 && ui.sections_short == 0);
	CK(ui.base_told == 1 && ui.base_ambiguous == 0);
	CK(ui.image_base == s.base && ui.mapped_at == s.base + DELTA && ui.delta == (int64_t)DELTA);
	CK(ui.hdr_image_base == s.base + DELTA);
	if (hk_fails)
		printf("  (%s round trip)\n", nm);
	free(out);
	out = NULL;

	/* 2. nobody tells it and the header still holds the preferred base: the delta is derived */
	map_image(file, img, &s, DELTA, 0);
	CK(kgenome_pe_unmap(kb(img, IMG_SIZE), s.base + DELTA, 0, 1u << 20, &out, &out_len, &ui));
	CK(ui.base_told == 0 && ui.base_ambiguous == 0 && ui.delta == (int64_t)DELTA && ui.relocs_undone == s.want_undone);
	if (out && out_len == FILE_SIZE) {
		CK(!memcmp(out + 0x200, file + 0x200, 0x200));
		CK(!memcmp(out + 0x400, file + 0x400, 0x200));
	}
	free(out);
	out = NULL;

	/* 3. the loader rewrote ImageBase to where it put the image, nobody tells: zero delta that may be wrong */
	map_image(file, img, &s, DELTA, 1);
	CK(kgenome_pe_unmap(kb(img, IMG_SIZE), s.base + DELTA, 0, 1u << 20, &out, &out_len, &ui));
	CK(ui.delta == 0 && ui.relocs_undone == 0 && ui.base_told == 0 && ui.base_ambiguous == 1);
	if (out && out_len == FILE_SIZE)
		CK(memcmp(out + 0x200, file + 0x200, 0x200) != 0);      /* still relocated: and it says it cannot know */
	free(out);
	out = NULL;

	/* 4. no mapped address: nothing to undo and nothing ambiguous */
	CK(kgenome_pe_unmap(kb(img, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	CK(ui.delta == 0 && ui.relocs_undone == 0 && ui.base_ambiguous == 0);
	free(out);
	out = NULL;

	/* 5. a cap smaller than the file: refused, not truncated */
	CK(!kgenome_pe_unmap(kb(img, IMG_SIZE), s.base, s.base, FILE_SIZE - 1u, &out, &out_len, &ui));
	CK(out == NULL);
	CK(kgenome_pe_unmap(kb(img, IMG_SIZE), s.base, s.base, FILE_SIZE, &out, &out_len, &ui) && out_len == FILE_SIZE);
	free(out);
	out = NULL;
	CK(!kgenome_pe_unmap(kb(img, IMG_SIZE), 0, 0, 1u << 20, NULL, &out_len, &ui));
	CK(!kgenome_pe_unmap(kb(img, IMG_SIZE), 0, 0, 1u << 20, &out, NULL, &ui));
	CK(kgenome_pe_unmap(kb(img, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, NULL));    /* the info is optional */
	free(out);
	out = NULL;
}

/* ---- hostile tables ------------------------------------------------------------------------ */

static void t_tables(void)
{
	static uint8_t file[FILE_SIZE], img[IMG_SIZE], bad[IMG_SIZE];
	struct spec s;
	uint8_t *out = NULL;
	uint64_t out_len = 0;
	struct kgenome_pe_unmap_info ui;

	memset(&s, 0, sizeof s);
	s.plus = 0;
	s.base = 0x400000ull;
	build_file(file, &s);
	map_image(file, img, &s, DELTA, 1);

	/* a block whose size field is 0: no progress is possible, and no write happens */
	memcpy(bad, img, IMG_SIZE);
	w32(bad + REL_RVA + 4, 0);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui));
	CK(ui.relocs_undone == 0 && ui.relocs_skipped == 0);
	free(out);
	out = NULL;
	/* ... 7: smaller than its own header */
	w32(bad + REL_RVA + 4, 7);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui) && ui.relocs_undone == 0);
	free(out);
	out = NULL;
	/* a block longer than the whole table */
	memcpy(bad, img, IMG_SIZE);
	w32(bad + REL_RVA + 4, 0x7fffffffu);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui) && ui.relocs_undone == 0);
	free(out);
	out = NULL;
	/* the second block is the bad one: the first is still undone, and what follows is not read */
	memcpy(bad, img, IMG_SIZE);
	{
		uint32_t first = 8u + 2u * (NTEXT + 1u);

		w32(bad + REL_RVA + first + 4, 3);
		CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui));
		CK(ui.relocs_undone == NTEXT && ui.relocs_skipped == 0);
		if (out && out_len == FILE_SIZE)
			CK(!memcmp(out + 0x200, file + 0x200, 0x200));
		free(out);
		out = NULL;
	}
	/* a directory that is outside the image, or empty: no relocation is attempted */
	memcpy(bad, img, IMG_SIZE);
	w32(bad + 0x98 + 96 + 5 * 8, IMG_SIZE - 4);       /* starts inside, runs past the end */
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui) && ui.relocs_undone == 0);
	free(out);
	out = NULL;
	w32(bad + 0x98 + 96 + 5 * 8 + 4, 0);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui) && ui.relocs_undone == 0);
	free(out);
	out = NULL;
	/* fewer directories than the relocation one's index: none to read (the count is also clamped to 16) */
	memcpy(bad, img, IMG_SIZE);
	w32(bad + 0x98 + 92, 5);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui) && ui.relocs_undone == 0);
	free(out);
	out = NULL;
	w32(bad + 0x98 + 92, 0xffffffffu);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui) && ui.relocs_undone == s.want_undone);
	free(out);
	out = NULL;
	/* an odd tail in a block (one byte of an entry): the whole entries before it are done */
	memcpy(bad, img, IMG_SIZE);
	w32(bad + REL_RVA + 4, 8u + 2u * NTEXT + 1u);
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui));
	CK(ui.relocs_undone >= NTEXT);
	free(out);
	out = NULL;
	/* a section whose RawSize runs past the image: short, counted, not read */
	memcpy(bad, img, IMG_SIZE);
	w32(bad + 0x98 + 224 + 40 + 16, 0x3000);        /* .data raw size 0x3000, from RVA 0x2000: past 0x4000 */
	CK(kgenome_pe_unmap(kb(bad, IMG_SIZE), s.base + DELTA, s.base, 1u << 22, &out, &out_len, &ui));
	CK(ui.sections_short == 1);
	free(out);
	out = NULL;

	/* headers that are not a mapped image */
	memcpy(bad, img, IMG_SIZE);
	bad[0] = 'Z';
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	memcpy(bad, img, IMG_SIZE);
	w32(bad + 0x3c, 0x7ffffff0u);
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	memcpy(bad, img, IMG_SIZE);
	bad[0x80] = 'X';
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	memcpy(bad, img, IMG_SIZE);
	w16(bad + 0x86, 0);                              /* no sections */
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	memcpy(bad, img, IMG_SIZE);
	w16(bad + 0x94, 40);                             /* an optional header too small to hold what is read */
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	memcpy(bad, img, IMG_SIZE);
	w16(bad + 0x98, 0x1234);                         /* neither magic */
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
	memcpy(bad, img, IMG_SIZE);
	w16(bad + 0x86, 0xffff);                         /* a section table that does not fit */
	CK(!kgenome_pe_unmap(kb(bad, IMG_SIZE), 0, 0, 1u << 20, &out, &out_len, &ui));
}

/* every cut of the image under a guard page, and flipped bits: what comes back is the file or nothing, and
 * never a read past the end */
static void t_hostile(void)
{
	static uint8_t file[FILE_SIZE], img[IMG_SIZE], bad[IMG_SIZE];
	struct spec s;
	struct hk_gb g;
	struct hk_rng r = { 0x0badc0ffee123457ull };
	unsigned plus, len, k, ok = 0, refused = 0;

	gb_init(&g, IMG_SIZE);
	for (plus = 0; plus < 2; plus++) {
		memset(&s, 0, sizeof s);
		s.plus = (int)plus;
		s.base = plus ? 0x140000000ull : 0x400000ull;
		build_file(file, &s);
		map_image(file, img, &s, DELTA, 1);
		for (len = 0; len <= IMG_SIZE; len += (len < 0x400 ? 1u : 61u)) {
			uint8_t *p = gb_put(&g, img, len);
			uint8_t *out = NULL;
			uint64_t out_len = 0;
			struct kgenome_pe_unmap_info ui;

			if (kgenome_pe_unmap(kb(p, len), s.base + DELTA, s.base, 1u << 20, &out, &out_len, &ui)) {
				CK(out != NULL && out_len <= (1u << 20));
				CK(ui.sections == 3);
				ok++;
				free(out);
			} else {
				refused++;
			}
		}
		for (k = 0; k < 3000; k++) {
			uint8_t *out = NULL;
			uint64_t out_len = 0;
			unsigned at = hk_below(&r, IMG_SIZE);
			struct kgenome_pe_unmap_info ui;
			uint8_t *p;

			memcpy(bad, img, IMG_SIZE);
			bad[at] ^= (uint8_t)(1u << hk_below(&r, 8));
			if (k & 1)
				bad[0x600 + hk_below(&r, 0x40)] ^= 0x40;
			p = gb_put(&g, bad, IMG_SIZE);
			if (kgenome_pe_unmap(kb(p, IMG_SIZE), s.base + DELTA, k & 2 ? s.base : 0, 1u << 22, &out, &out_len, &ui)) {
				CK(out != NULL && out_len <= (1u << 22));
				free(out);
			}
		}
	}
	gb_free(&g);
	CK(ok > 100 && refused > 100);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_roundtrip(0);
	t_roundtrip(1);
	t_tables();
	t_hostile();
	if (hk_fails) {
		printf("cov_pe_unmap: FAILED (%d)\n", hk_fails);
		return 1;
	}
	printf("cov_pe_unmap: ok\n");
	return 0;
}
