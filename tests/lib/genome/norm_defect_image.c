/*
 * norm_defect_image - the defects of the normalise audit (2026-10-21, N1-N12) that live in
 * libgenome's image code, each pinned by an input that the older tests never gave it:
 *
 *   N1   kgenome_pe_write_imports: an IAT slot whose RVA is near 2^64. `iat_rva + step` wrapped
 *        past the bounds check and the thunk was written at img - 4. The guard bytes before and after
 *        the image are the oracle (no sanitizer needed); a slot at the last four bytes of the image
 *        and one that straddles its end are the boundary controls.
 *   N2   kgenome_funcs_remap: the work bound counted the window and not the compares, so one
 *        function of 32 KB looked for in a view of zeros cost (view x function) byte compares and the
 *        set still said OK. Counted by wrapping memcmp (bytes asked for), not by the clock.
 *   N10  kgenome_pe_unmap: NumberOfRvaAndSizes may say 16 while SizeOfOptionalHeader holds two
 *        directory entries; the base relocation directory was then read out of the section table.
 *   N11  kgenome_elf_rebuild: a section table whose second read fails was declared anyway (a header
 *        that says there is a table, over zeroes), and a PT_LOAD of more than 4 GiB was read with its
 *        length cut to 32 bits and declared whole.
 *
 * Linked against libkgenome.a alone (CLAUDE.md section 12). UNIT_LIBS_norm_defect_image wraps memcmp
 * and bcmp for the N2 counter.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"

/* ---- the N2 counter: bytes any compare in this program was asked for ------------------------- */

static uint64_t cmp_bytes;

int __real_memcmp(const void *a, const void *b, size_t n);
int __real_bcmp(const void *a, const void *b, size_t n);
int __wrap_memcmp(const void *a, const void *b, size_t n);
int __wrap_bcmp(const void *a, const void *b, size_t n);

int __wrap_memcmp(const void *a, const void *b, size_t n)
{
	cmp_bytes += n;
	return __real_memcmp(a, b, n);
}

int __wrap_bcmp(const void *a, const void *b, size_t n)
{
	cmp_bytes += n;
	return __real_bcmp(a, b, n);
}

/* ---- the N11 allocator: a request over 4 GiB is answered with a small zeroed buffer ----------- */

/* A sanitizer owns calloc and a program that defines its own would hand it memory it did not make:
 * under one the 4 GiB case is skipped (the rest of the test runs). */
#ifndef __SANITIZE_ADDRESS__
#define CAN_FAKE 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#undef CAN_FAKE
#endif
#endif

#ifdef CAN_FAKE
extern void *__libc_calloc(size_t n, size_t m);
static int fake_big_calloc;
static unsigned fake_hits;

void *calloc(size_t n, size_t m)
{
	if (fake_big_calloc && m && n > ((uint64_t)4 << 30) / m) {
		fake_hits++;
		return __libc_calloc(1, 65536u);
	}
	return __libc_calloc(n, m);
}
#endif

static void result(const char *id, const char *what, int fails_before)
{
	printf("%s %s: %s\n", id, what, hk_fails == fails_before ? "ok" : "FAILED");
}

/* ---- N1 -------------------------------------------------------------------------------------- */

struct guarded {
	uint8_t pre[64];
	uint8_t img[0x1000];
	uint8_t post[64];
};

static int guards_intact(const struct guarded *g)
{
	unsigned i;

	for (i = 0; i < sizeof g->pre; i++)
		if (g->pre[i] != 0xa5 || g->post[i] != 0xa5)
			return 0;
	return 1;
}

static void n1_iat_wrap(void)
{
	static const char pool[] = "KERNEL32.dll\0ExitProcess";
	static struct guarded g;
	const uint64_t hostile[] = {
		UINT64_MAX, UINT64_MAX - 3u, UINT64_MAX - 7u, UINT64_MAX - 11u, UINT64_MAX - 0x40u,
		0x8000000000000000ull, 0x7ffffffffffffffcull, 0xfffffffffffffffcull,
		0x100000000ull, 0xffffffffull
	};
	unsigned h, is64;
	int before = hk_fails;

	for (is64 = 0; is64 < 2u; is64++) {
		for (h = 0; h < sizeof hostile / sizeof hostile[0]; h++) {
			struct kgenome_imp_decl d;
			uint64_t r;

			memset(&g, 0, sizeof g);
			memset(g.pre, 0xa5, sizeof g.pre);
			memset(g.post, 0xa5, sizeof g.post);
			memset(&d, 0, sizeof d);
			d.iat_rva = hostile[h];
			d.dll_off = 0;
			d.fn_off = 13;
			r = kgenome_pe_write_imports(g.img, sizeof g.img, 0x100, &d, 1, pool, sizeof pool, (int)is64);
			if (!guards_intact(&g))
				printf("  iat_rva %#llx is64 %u: a byte outside the image was written\n",
				       (unsigned long long)hostile[h], is64);
			CK(guards_intact(&g));
			/* the table itself is still written whatever the slot says: the slot is skipped */
			CK(r == kgenome_pe_imports_size(&d, 1, pool, sizeof pool, (int)is64));
		}
		/* boundaries: the last whole slot is written, one that straddles the end is not */
		{
			struct kgenome_imp_decl d;
			const uint64_t step = is64 ? 8u : 4u;
			uint64_t slot;
			unsigned k;

			for (slot = sizeof g.img - step - 1u; slot <= sizeof g.img; slot++) {
				memset(&g, 0, sizeof g);
				memset(g.pre, 0xa5, sizeof g.pre);
				memset(g.post, 0xa5, sizeof g.post);
				memset(&d, 0, sizeof d);
				d.iat_rva = slot;
				d.fn_off = 13;
				(void)kgenome_pe_write_imports(g.img, sizeof g.img, 0x100, &d, 1, pool, sizeof pool, (int)is64);
				CK(guards_intact(&g));
				if (slot + step <= sizeof g.img) {
					int any = 0;

					for (k = 0; k < step; k++)
						any |= g.img[slot + k] != 0;
					CK(any);          /* a slot that fits is filled */
				}
			}
		}
	}
	result("N1 ", "pi_walk iat_rva near 2^64", before);
}

/* ---- N2 -------------------------------------------------------------------------------------- */

static void n2_find_bytes_cost(void)
{
	const size_t n = 512u << 10, len = 32u << 10;
	uint8_t *par = calloc(1, n), *view = calloc(1, n);
	struct kgenome_func f;
	struct kgenome_func_set pf, out;
	const uint64_t bound = (uint64_t)64 * n + (1u << 20);
	int before = hk_fails;

	if (!par || !view) {
		printf("N2: no memory\n");
		hk_fails++;
		return;
	}
	/* the function's body ends in a byte the view does not have: every zero of the view is a
	 * candidate and every candidate compares the whole body but the last byte */
	par[n - 1] = 1;
	view[n - 1] = 2;
	memset(&f, 0, sizeof f);
	f.off = n - len;
	f.len = len;
	f.shndx = 1;
	memset(&pf, 0, sizeof pf);
	pf.v = &f;
	pf.n = 1;
	cmp_bytes = 0;
	kgenome_funcs_remap(par, n, &pf, view, n, &out);
	printf("  compare bytes asked for %llu, bound %llu, status %d\n", (unsigned long long)cmp_bytes,
	       (unsigned long long)bound, (int)out.status);
	CK(out.status == KGENOME_OVER_BUDGET);          /* the cost bound fired and the set says so */
	CK(cmp_bytes <= 4u * bound);                    /* and it fired near the bound, not after it */
	kgenome_funcs_free(&out);

	/* the control: the same function present at a shifted offset is found, status OK */
	memset(par, 0, n);
	memset(view, 0, n);
	{
		uint8_t body[64];
		unsigned i;

		for (i = 0; i < sizeof body; i++)
			body[i] = (uint8_t)(i * 7u + 3u);
		memcpy(par + 0x400, body, sizeof body);
		memcpy(view + 0x200, body, sizeof body);
		f.off = 0x400;
		f.len = sizeof body;
		kgenome_funcs_remap(par, n, &pf, view, n, &out);
		CK(out.status == KGENOME_OK && out.n == 1u && out.v[0].off == 0x200u);
		kgenome_funcs_free(&out);
	}
	free(par);
	free(view);
	result("N2 ", "find_bytes cost counted in the work bound", before);
}

/* ---- N10 ------------------------------------------------------------------------------------- */

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/*
 * A PE32 mapped image: headers, one section .text at RVA 0x1000 holding one pointer (0x400000 + 0x1234),
 * and a base relocation block at RVA 0x1800 that would undo it. SizeOfOptionalHeader holds `ndirs_room`
 * directory entries and NumberOfRvaAndSizes claims 16. When the directory array is read past the optional
 * header, entry 5 (the relocation directory) falls into the section header's PointerToRelocations and
 * PointerToLinenumbers: planted here as the block's RVA and size.
 */
#define IMG_N 0x2000u

static void build_mapped_pe(uint8_t *img, unsigned ndirs_room, int real_dir)
{
	const uint32_t opt = 0x98, optsz = 96u + 8u * ndirs_room, sec = opt + optsz;
	uint8_t *s;

	memset(img, 0, IMG_N);
	img[0] = 'M'; img[1] = 'Z';
	w32(img + 0x3c, 0x80);
	memcpy(img + 0x80, "PE\0\0", 4);
	w16(img + 0x84, 0x14c);
	w16(img + 0x86, 1);
	w16(img + 0x94, (uint16_t)optsz);
	w16(img + opt, 0x10b);
	w32(img + opt + 28, 0x400000u);
	w32(img + opt + 56, IMG_N);
	w32(img + opt + 60, 0x200);
	w32(img + opt + 92, 16);                         /* the claim: sixteen directories */
	s = img + sec;
	memcpy(s, ".text", 5);
	w32(s + 8, 0x100);
	w32(s + 12, 0x1000);
	w32(s + 16, 0x100);
	w32(s + 20, 0x200);
	if (real_dir) {
		w32(img + opt + 96 + 5 * 8, 0x1800);
		w32(img + opt + 96 + 5 * 8 + 4, 12);
	} else {
		/* entry 5 of the array read PAST the optional header = section header offset 24 and 28 */
		w32(s + 24, 0x1800);
		w32(s + 28, 12);
	}
	w32(img + 0x1010, 0x400000u + 0x1234u + 0x10000u);   /* relocated by +0x10000 */
	/* the block: page 0x1000, one HIGHLOW at +0x10, one padding entry */
	w32(img + 0x1800, 0x1000);
	w32(img + 0x1804, 12);
	w16(img + 0x1808, (uint16_t)(3u << 12 | 0x010u));
	w16(img + 0x180a, 0);
}

static void n10_dirs_past_optsz(void)
{
	static uint8_t img[IMG_N];
	struct kgenome_pe_unmap_info info;
	uint8_t *file = NULL;
	uint64_t len = 0;
	int before = hk_fails;

	/* control: the directory is inside the optional header (room for 6 entries) and is applied */
	build_mapped_pe(img, 6, 1);
	CK(kgenome_pe_unmap(kof_buf_make(img, IMG_N), 0x400000u + 0x10000u, 0x400000u, 1u << 20, &file, &len, &info));
	CK(info.relocs_undone == 1u);
	free(file);
	file = NULL;
	/* the defect: room for two entries, so entry 5 is not part of the header and nothing is undone */
	build_mapped_pe(img, 2, 0);
	CK(kgenome_pe_unmap(kof_buf_make(img, IMG_N), 0x400000u + 0x10000u, 0x400000u, 1u << 20, &file, &len, &info));
	printf("  directory read past SizeOfOptionalHeader: %u relocation(s) undone\n", info.relocs_undone);
	CK(info.relocs_undone == 0u);
	free(file);
	result("N10", "n_dirs against SizeOfOptionalHeader", before);
}

/* ---- N11 ------------------------------------------------------------------------------------- */

struct guest {
	uint8_t mem[0x2000];
	uint64_t base;
	unsigned fail_len;          /* a read of exactly this many bytes fails (0: none) */
	unsigned big_seen;
};

static int guest_rd(void *user, uint64_t va, void *dst, uint32_t n)
{
	struct guest *g = user;
	uint64_t at;

	if (g->fail_len && n == g->fail_len)
		return 0;
	/* e_shoff is a FILE offset, read at bias + e_shoff: for this image bias is zero, so the
	 * address of the table is its file offset, and whatever sits there reads as zeroes */
	if (va >= 0x1000 && va < 0x2000) {
		memset(dst, 0, n);
		return 1;
	}
	if (va < g->base)
		return 0;
	at = va - g->base;
	if (at >= sizeof g->mem) {
		memset(dst, 0, n);               /* mapped, zero: the section table's address reads */
		return 1;
	}
	if (n > sizeof g->mem - at)
		return 0;
	memcpy(dst, g->mem + at, n);
	return 1;
}

static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* ELF64 LE header + `nph` PT_LOADs, the first one covering headers at offset zero */
static void guest_elf(struct guest *g, unsigned nph, uint64_t shoff, unsigned shnum,
		      uint64_t fsz0, uint64_t fsz1)
{
	uint8_t *h = g->mem;
	unsigned i;

	memset(g->mem, 0, sizeof g->mem);
	g->base = 0x400000;
	memcpy(h, "\177ELF\2\1\1", 7);
	w16(h + 0x10, 2);
	w16(h + 0x12, 0x3e);
	w32(h + 0x14, 1);
	put64(h + 0x18, 0x400100);
	put64(h + 0x20, 64);                     /* e_phoff */
	put64(h + 0x28, shoff);
	w16(h + 0x34, 64);
	w16(h + 0x36, 56);
	w16(h + 0x38, (uint16_t)nph);
	w16(h + 0x3a, 64);
	w16(h + 0x3c, (uint16_t)shnum);
	w16(h + 0x3e, 1);
	for (i = 0; i < nph; i++) {
		uint8_t *p = h + 64 + 56u * i;
		uint64_t fsz = i ? fsz1 : fsz0;

		w32(p, 1);                                  /* PT_LOAD */
		w32(p + 4, 5);
		put64(p + 8, i ? 0x1000u : 0u);             /* p_offset */
		put64(p + 0x10, 0x400000u + (i ? 0x1000u : 0u));
		put64(p + 0x18, 0x400000u + (i ? 0x1000u : 0u));
		put64(p + 0x20, fsz);
		put64(p + 0x28, fsz);
		put64(p + 0x30, 0x1000);
	}
}

static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

static void n11_elf_rebuild(void)
{
	static struct guest g;
	uint8_t *out = NULL;
	uint64_t len = 0, lo = 0, hi = 0;
	int before = hk_fails, ok;

	/* (a) the section table reads as section header zero (all zero: it looks like a table), then the
	 * full read of it fails. The rebuilt header must not claim a table that was not read. */
	guest_elf(&g, 1, 0x1000, 3, 0x1000, 0);
	g.fail_len = 3u * 64u;
	ok = kgenome_elf_rebuild(0x400000, guest_rd, &g, 0, &out, &len, &lo, &hi);
	CK(ok);
	if (ok) {
		printf("  after a failed table read: e_shoff %llu e_shnum %u\n",
		       (unsigned long long)rd64(out + 0x28), rd16(out + 0x3c));
		CK(rd64(out + 0x28) == 0);
		CK(rd16(out + 0x3a) == 0 && rd16(out + 0x3c) == 0 && rd16(out + 0x3e) == 0);
	}
	free(out);
	out = NULL;
	/* control: the same table read succeeds, and the header keeps saying so */
	g.fail_len = 0;
	ok = kgenome_elf_rebuild(0x400000, guest_rd, &g, 0, &out, &len, &lo, &hi);
	CK(ok);
	if (ok) {
		CK(rd64(out + 0x28) == 0x1000 && rd16(out + 0x3c) == 3);
	}
	free(out);
	out = NULL;

	/* (b) a PT_LOAD whose p_filesz is 4 GiB + 16 under a cap that allows it: the reader takes a
	 * 32-bit length, so the segment cannot be read whole. It is a hole (declared p_filesz 0) or the
	 * rebuild refuses; it is never read as 16 bytes and declared 4 GiB. calloc is faked for the one
	 * request over 4 GiB so that nothing that large is allocated here. */
#ifdef CAN_FAKE
	guest_elf(&g, 2, 0, 0, 0x1000, ((uint64_t)1 << 32) + 16u);
	fake_big_calloc = 1;
	fake_hits = 0;
	ok = kgenome_elf_rebuild(0x400000, guest_rd, &g, (uint64_t)8 << 30, &out, &len, &lo, &hi);
	fake_big_calloc = 0;
	CK(fake_hits == 1u);                            /* the request was reached */
	if (ok) {
		uint64_t declared = rd64(out + 64 + 56 + 0x20);

		printf("  4 GiB segment: rebuilt, p_filesz declared %llu\n", (unsigned long long)declared);
		CK(declared == 0);
	}
	free(out);
#else
	printf("  (a sanitizer owns calloc: the 4 GiB segment case is skipped)\n");
#endif
	result("N11", "elf_rebuild: 32-bit length cut, failed table read", before);
}

int main(void)
{
	n1_iat_wrap();
	n2_find_bytes_cost();
	n10_dirs_past_optsz();
	n11_elf_rebuild();
	if (hk_fails) {
		printf("norm_defect_image: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("norm_defect_image: ok\n");
	return 0;
}
