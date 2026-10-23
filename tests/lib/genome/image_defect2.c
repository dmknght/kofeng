/*
 * image_defect2 - round-2 defects of libgenome's image code (E1-E11 of the second audit), each pinned
 * by an input the older tests never gave it:
 *
 *   E1   kgenome_pe_image_parse: NumberOfRvaAndSizes may say 16 while SizeOfOptionalHeader holds
 *        fewer directory entries (or none, or not even the count field). The entries past the
 *        optional header are the section table; the parser read them as directories (the same
 *        defect as N10 in the unmapper, which had been fixed alone). Both layouts (PE32, PE32+),
 *        every room from 0 to 17 entries, and the sizes of the optional header that cut the count
 *        field itself; the oracle is the parser's own directory table against the bytes the test
 *        wrote, with the section header's fields set to values no real directory would have.
 *   E4   the resource directory was clipped to the object and not to its own section, as the function
 *        says it is: a directory that declares more than its section holds took the bytes of the section
 *        after it. That section's claim went to zero, the region partition called its bytes RESOURCE, and
 *        no anomaly said so (a file can hide a section from CODE/DATA rules by aiming the directory over
 *        it). File layout and mapped layout, the section after it and the section it sits in.
 *   E4b  the same clip where sections are ADJACENT (a section ends where the next begins, the layout every
 *        linker writes): the resource directory at the front of the second one belongs to the second, not
 *        to the first whose end it equals. A mutation of the boundary test survived without it.
 *   E9   kgenome_pe_write_imports: the IAT slot that ends exactly where the table starts, and the one that
 *        starts exactly where it ends, are not on the table and are written; one byte closer is refused.
 *        The boundary of the overlap test, both widths, which no case had put a slot against.
 *   E7   kgenome_elf_rebuild: a PT_LOAD whose address plus the emulator's bias plus its length wraps 2^64.
 *        The read was asked for at the wrapped address (the bytes of some other place, "read" whole), the
 *        covered range took the wrapped end, and the segment was declared whole. A segment whose range wraps
 *        is no range at all: a hole, declared as one, like a segment the reader refuses.
 *   E7b  kgenome_elf_rebuild, what the first tests did not give it (mutation: `bias + vaddr <= bias` and
 *        a section table read from `bias - shoff` both survived the suite): a position-independent image
 *        whose lowest PT_LOAD has p_vaddr 0 and a non-zero bias, which is the ordinary shape of an ET_DYN
 *        and read whole; and a guest that serves only the addresses that exist, so the section table
 *        copied into the file is the table at e_shoff and not zeroes from anywhere.
 *
 * Linked against libkgenome.a alone (CLAUDE.md section 12).
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"
#include "image_kit.h"

static void result(const char *id, const char *what, int fails_before)
{
	printf("%s %s: %s\n", id, what, hk_fails == fails_before ? "ok" : "FAILED");
}

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* ---- E1 -------------------------------------------------------------------------------------- */

#define IMG_N 0x1000u

/*
 * A PE file: DOS header, PE signature at 0x80, one section, SizeOfOptionalHeader `optsz` bytes of
 * optional header (PE32 or PE32+) with NumberOfRvaAndSizes = `claim` written only when the optional
 * header is long enough to hold it. Directory entry i, when it is inside the header, is {0x1000 + i,
 * 0x10 + i}; what follows the optional header is the section header, whose bytes at +24..+39 (the
 * fields a directory read past the header would take for entries) are 0xdeadbeef-style values.
 */
static void build_pe(uint8_t *img, int plus, uint32_t optsz, uint32_t claim)
{
	const uint32_t opt = 0x98u, cnt_off = plus ? 108u : 92u, dir_off = plus ? 112u : 96u;
	const uint32_t sec = opt + optsz;
	uint32_t i;

	memset(img, 0, IMG_N);
	img[0] = 'M'; img[1] = 'Z';
	w32(img + 0x3c, 0x80);
	memcpy(img + 0x80, "PE\0\0", 4);
	w16(img + 0x84, plus ? 0x8664u : 0x14cu);
	w16(img + 0x86, 1);
	w16(img + 0x94, (uint16_t)optsz);
	/* the optional header's own bytes: filled with a recognisable pattern so a read past the
	 * declared size is distinguishable from a real field */
	for (i = 0; i < optsz; i++)
		img[opt + i] = 0;
	w16(img + opt, plus ? 0x20bu : 0x10bu);
	if (optsz > 60u + 4u) {
		w32(img + opt + 32, 0x1000);
		w32(img + opt + 36, 0x200);
		w32(img + opt + 56, 0x2000);
		w32(img + opt + 60, 0x200);
	}
	if (optsz > cnt_off + 3u)
		w32(img + opt + cnt_off, claim);
	for (i = 0; i < 16u; i++) {
		const uint32_t at = opt + dir_off + 8u * i;

		if (dir_off + 8u * (i + 1u) <= optsz) {
			w32(img + at, 0x1000u + i);
			w32(img + at + 4u, 0x10u + i);
		}
	}
	/* the section header and, after it, the bytes that are not the optional header's */
	memcpy(img + sec, ".text", 5);
	w32(img + sec + 8, 0x100);
	w32(img + sec + 12, 0x1000);
	w32(img + sec + 16, 0x100);
	w32(img + sec + 20, 0x200);
	w32(img + sec + 24, 0x7a7a0001u);   /* PointerToRelocations: where "directory 3" would start */
	w32(img + sec + 28, 0x7a7a0002u);
	w32(img + sec + 32, 0x7a7a0003u);
	w32(img + sec + 36, 0x7a7a0004u);
}

static void e1_dirs_past_optsz(void)
{
	static uint8_t img[IMG_N];
	static struct kgenome_pe_info info;
	struct kgenome_obj obj;
	int before = hk_fails;
	unsigned plus;

	for (plus = 0; plus < 2u; plus++) {
		const uint32_t dir_off = plus ? 112u : 96u, cnt_off = plus ? 108u : 92u;
		uint32_t optsz;

		/* every size of the optional header from "cut inside the standard fields" to room for 17 entries */
		for (optsz = 0; optsz <= dir_off + 17u * 8u; optsz += 4u) {
			uint32_t room = optsz > dir_off ? (optsz - dir_off) / 8u : 0u, i;
			uint32_t want = optsz <= cnt_off ? 0u : (room > 16u ? 16u : room);
			int ok;

			build_pe(img, (int)plus, optsz, 16);
			memset(&info, 0, sizeof info);
			memset(&obj, 0, sizeof obj);
			ok = kgenome_pe_image_parse(kof_buf_make(img, IMG_N), &info, &obj);
			CK(ok);
			if (!ok)
				continue;
			if (info.n_dirs != want)
				printf("  plus %u optsz %u: n_dirs %u, the header holds %u\n", plus, optsz,
				       (unsigned)info.n_dirs, (unsigned)want);
			CK(info.n_dirs == want);
			for (i = 0; i < 16u; i++) {
				uint32_t rva = i < want ? 0x1000u + i : 0u, size = i < want ? 0x10u + i : 0u;

				if (info.dir[i].rva != rva || info.dir[i].size != size)
					printf("  plus %u optsz %u: dir[%u] = {%#x, %#x}, expected {%#x, %#x}\n", plus,
					       optsz, i, (unsigned)info.dir[i].rva, (unsigned)info.dir[i].size,
					       (unsigned)rva, (unsigned)size);
				CK(info.dir[i].rva == rva && info.dir[i].size == size);
			}
			/* a count that the header cannot hold is odd, and said */
			if (want != 16u)
				CK((info.anomalies & KGENOME_PE_ANOM_DIR_COUNT_ODD) != 0);
			else
				CK((info.anomalies & KGENOME_PE_ANOM_DIR_COUNT_ODD) == 0);
		}
	}
	/* a claim smaller than the room is kept as it is (the clamp is only for the header's end) */
	build_pe(img, 0, 96u + 8u * 16u, 3);
	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(img, IMG_N), &info, &obj));
	CK(info.n_dirs == 3u && info.dir[2].rva == 0x1002u && info.dir[3].rva == 0u);
	result("E1 ", "pe parse: directories against SizeOfOptionalHeader", before);
}

/* ---- E4 -------------------------------------------------------------------------------------- */

static int parse_layout(const uint8_t *b, uint64_t n, uint32_t layout, struct kgenome_pe_info *i)
{
	struct kgenome_obj o;

	memset(i, 0, sizeof *i);
	memset(&o, 0, sizeof o);
	i->layout = layout;
	return kgenome_pe_image_parse(kof_buf_make(b, n), i, &o);
}

static void e4_resource_clip(void)
{
	static uint8_t big[0x4000];
	static struct kgenome_pe_info i;
	struct ik_pe p;
	unsigned k, mapped;
	int before = hk_fails;

	for (mapped = 0; mapped < 2u; mapped++) {
		/* the directory's size runs from 0x100 (inside the section) to far past it */
		static const uint32_t sizes[] = { 0x100, 0x3ff, 0x400, 0x401, 0x800, 0x2000, 0xffffffffu };

		for (k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
			const uint32_t sz = sizes[k];
			const uint32_t want = sz > 0x400u ? 0x400u : sz;
			const uint64_t off = mapped ? 0x2000u : 0x800u;

			memset(&p, 0, sizeof p);
			p.entry = 0x1000; p.size_of_image = 0x4000; p.size_of_headers = 0x400; p.file_align = 0x200;
			ik_sec(&p, ".text", 0x400, 0x1000, 0x400, mapped ? 0x1000 : 0x400, IK_TEXT);
			ik_sec(&p, ".rsrc", 0x400, 0x2000, 0x400, mapped ? 0x2000 : 0x800, IK_RDATA);
			ik_sec(&p, ".reloc", 0x400, 0x3000, 0x400, mapped ? 0x3000 : 0xc00, IK_RELOC);
			p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2000;
			p.dir_size[KGENOME_PE_DIR_RESOURCE] = sz;
			memset(big, 0, sizeof big);
			ik_pe_write(big, &p);
			CK(parse_layout(big, sizeof big, mapped ? KGENOME_PE_LAYOUT_MAPPED : KGENOME_PE_LAYOUT_FILE, &i));
			if (i.res_len != want)
				printf("  %s, directory size %#x: res_len %#llx, the section holds %#x\n",
				       mapped ? "mapped" : "file", (unsigned)sz, (unsigned long long)i.res_len, (unsigned)want);
			CK(i.res_off == off && i.res_len == want);
			/* the section after it keeps what it declared, and nothing is said to be overlapping */
			CK(i.sec_count == 3u);
			CK(i.sec[2].claim_off == (mapped ? 0x3000u : 0xc00u) && i.sec[2].claim_len == 0x400u);
			CK((i.anomalies & KGENOME_PE_ANOM_SEC_OVERLAP) == 0);
		}
	}
	result("E4 ", "resource directory clipped to its own section", before);
}

/* ---- E7 -------------------------------------------------------------------------------------- */

static int eg_rd(void *user, uint64_t va, void *dst, uint32_t n)
{
	(void)user; (void)va;
	memset(dst, 0x5a, n);               /* every address reads, as a flat guest that maps everything would */
	return 1;
}

static const uint8_t *e7_hdr;

static int e7_rd(void *u, uint64_t va, void *dst, uint32_t n)
{
	if (va >= 0x400000 && va - 0x400000 + n <= 0x1000u) {
		memcpy(dst, e7_hdr + (va - 0x400000), n);
		return 1;
	}
	return eg_rd(u, va, dst, n);
}

static void e7_rebuild_wrap(void)
{
	static const uint64_t hostile[] = { 0xfffffffffffff000ull, 0xfffffffffffffff0ull, 0xffffffffffffffffull,
					    0xffffffffffffe000ull };
	uint8_t h[0x1000];
	int before = hk_fails;
	unsigned k, i;

	for (k = 0; k < sizeof hostile / sizeof hostile[0]; k++) {
		uint8_t *out = NULL;
		uint64_t len = 0, lo = 0, hi = 0;
		int ok;

		memset(h, 0, sizeof h);
		memcpy(h, "\177ELF\2\1\1", 7);
		ik_w16(h + 0x10, 2);
		ik_w16(h + 0x12, 0x3e);
		ik_w32(h + 0x14, 1);
		ik_w64(h + 0x18, 0x400100);
		ik_w64(h + 0x20, 64);
		ik_w16(h + 0x34, 64);
		ik_w16(h + 0x36, 56);
		ik_w16(h + 0x38, 2);
		for (i = 0; i < 2u; i++) {
			uint8_t *p = h + 64 + 56u * i;

			ik_w32(p, 1);
			ik_w32(p + 4, 5);
			ik_w64(p + 8, i ? 0x1000u : 0u);
			ik_w64(p + 0x10, i ? hostile[k] : 0x400000u);
			ik_w64(p + 0x20, i ? 0x2000u : 0x1000u);
			ik_w64(p + 0x28, i ? 0x2000u : 0x1000u);
		}
		/* the header is read from the guest at `base`: served from this buffer for the first 4 KiB */
		e7_hdr = h;
		ok = kgenome_elf_rebuild(0x400000, e7_rd, NULL, (uint64_t)1 << 30, &out, &len, &lo, &hi);
		CK(ok);
		if (!ok)
			continue;
		{
			uint64_t fsz1;

			memcpy(&fsz1, out + 64 + 56 + 0x20, 8);
			if (fsz1 != 0 || hi != 0x401000u)
				printf("  segment at %#llx: p_filesz declared %#llx, covered %#llx..%#llx\n",
				       (unsigned long long)hostile[k], (unsigned long long)fsz1, (unsigned long long)lo,
				       (unsigned long long)hi);
			CK(fsz1 == 0);                 /* a hole, as one the reader refuses */
			CK(lo == 0x400000u && hi == 0x401000u);
		}
		free(out);
	}
	result("E7 ", "elf rebuild: a segment whose range wraps", before);
}

/* A guest that holds exactly its image: [0x400000, +0x3000), and answers nothing outside it. */
static uint8_t e7b_mem[0x3000];

static int e7b_rd(void *u, uint64_t va, void *dst, uint32_t n)
{
	(void)u;
	if (va < 0x400000u || va - 0x400000u > sizeof e7b_mem || n > sizeof e7b_mem - (va - 0x400000u))
		return 0;
	memcpy(dst, e7b_mem + (va - 0x400000u), n);
	return 1;
}

static void e7b_pie_and_table(void)
{
	uint8_t *out = NULL;
	uint64_t len = 0, lo = 0, hi = 0, off, shoff = 0x2000;
	unsigned i;
	int before = hk_fails, ok;

	/* ET_DYN linked at 0, loaded at 0x400000: bias 0x400000, PT_LOAD p_vaddr 0, p_offset 0, 0x2000 bytes,
	 * a section table of three headers at file offset 0x2000 (header zero is all zeroes) */
	memset(e7b_mem, 0, sizeof e7b_mem);
	memcpy(e7b_mem, "\177ELF\2\1\1", 7);
	ik_w16(e7b_mem + 0x10, 3);
	ik_w16(e7b_mem + 0x12, 0x3e);
	ik_w32(e7b_mem + 0x14, 1);
	ik_w64(e7b_mem + 0x18, 0x100);
	ik_w64(e7b_mem + 0x20, 64);
	ik_w64(e7b_mem + 0x28, shoff);
	ik_w16(e7b_mem + 0x34, 64);
	ik_w16(e7b_mem + 0x36, 56);
	ik_w16(e7b_mem + 0x38, 1);
	ik_w16(e7b_mem + 0x3a, 64);
	ik_w16(e7b_mem + 0x3c, 3);
	ik_w16(e7b_mem + 0x3e, 1);
	ik_w32(e7b_mem + 64, 1);
	ik_w32(e7b_mem + 64 + 4, 5);
	ik_w64(e7b_mem + 64 + 8, 0);
	ik_w64(e7b_mem + 64 + 0x10, 0);          /* p_vaddr 0 */
	ik_w64(e7b_mem + 64 + 0x20, 0x2000);
	ik_w64(e7b_mem + 64 + 0x28, 0x2000);
	for (i = 0; i < 128u; i++)               /* headers 1 and 2: a pattern a copy from the wrong place cannot have */
		e7b_mem[shoff + 64u + i] = (uint8_t)(0x40u + i);
	ok = kgenome_elf_rebuild(0x400000, e7b_rd, NULL, (uint64_t)1 << 30, &out, &len, &lo, &hi);
	CK(ok);
	if (!ok)
		return;
	CK(len == shoff + 3u * 64u);
	/* the segment was read (not made a hole), whole */
	{
		uint64_t fsz;

		memcpy(&fsz, out + 64 + 0x20, 8);
		CK(fsz == 0x2000);
	}
	CK(lo == 0x400000u && hi == 0x402000u);
	/* the table is the guest's own bytes */
	for (off = 64; off < 192; off++)
		if (out[shoff + off] != (uint8_t)(0x40u + (off - 64u)))
			break;
	CK(off == 192);
	{
		uint64_t e_shoff;

		memcpy(&e_shoff, out + 0x28, 8);
		CK(e_shoff == shoff);
	}
	free(out);
	result("E7b", "elf rebuild: a position-independent image and its section table", before);
}

static void e4b_adjacent(void)
{
	static uint8_t big[0x4000];
	static struct kgenome_pe_info i;
	struct ik_pe p;
	unsigned mapped;
	int before = hk_fails;

	for (mapped = 0; mapped < 2u; mapped++) {
		memset(&p, 0, sizeof p);
		p.entry = 0x1000; p.size_of_image = 0x4000; p.size_of_headers = 0x400; p.file_align = 0x200;
		/* .text ends at 0x2000 = where .rsrc begins */
		ik_sec(&p, ".text", 0x1000, 0x1000, 0x400, mapped ? 0x1000 : 0x400, IK_TEXT);
		ik_sec(&p, ".rsrc", 0x400, 0x2000, 0x400, mapped ? 0x2000 : 0x800, IK_RDATA);
		p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2000;
		p.dir_size[KGENOME_PE_DIR_RESOURCE] = 0x100;
		memset(big, 0, sizeof big);
		ik_pe_write(big, &p);
		CK(parse_layout(big, sizeof big, mapped ? KGENOME_PE_LAYOUT_MAPPED : KGENOME_PE_LAYOUT_FILE, &i));
		CK(i.res_off == (mapped ? 0x2000u : 0x800u) && i.res_len == 0x100u);
	}
	result("E4b", "resource directory at the front of a section that follows another", before);
}

static void e9_slot_boundary(void)
{
	static const char pool[] = "KERNEL32.dll\0ExitProcess";
	static uint8_t g[0x1000];
	unsigned is64;
	int before = hk_fails;

	for (is64 = 0; is64 < 2u; is64++) {
		const uint64_t step = is64 ? 8u : 4u, base = 0x400;
		struct kgenome_imp_decl d;
		uint64_t size, r;
		unsigned k;
		struct { int64_t rel; int ok; } cases[] = {
			{ -(int64_t)step, 1 },        /* ends where the table starts */
			{ -(int64_t)step + 1, 0 },    /* one byte into it */
			{ 0, 0 },
			{ 1, 0 },
			{ -1, 0 },
		};

		memset(&d, 0, sizeof d);
		d.fn_off = 13;
		size = kgenome_pe_imports_size(&d, 1, pool, sizeof pool, (int)is64);
		CK(size != 0);
		for (k = 0; k < sizeof cases / sizeof cases[0]; k++) {
			memset(g, 0, sizeof g);
			d.iat_rva = (uint64_t)((int64_t)base + cases[k].rel);
			r = kgenome_pe_write_imports(g, sizeof g, base, &d, 1, pool, sizeof pool, (int)is64);
			CK((r != 0) == (cases[k].ok != 0));
		}
		/* the end of the table: the slot starting exactly there is clear of it, one byte earlier is not */
		d.iat_rva = base + size;
		memset(g, 0, sizeof g);
		CK(kgenome_pe_write_imports(g, sizeof g, base, &d, 1, pool, sizeof pool, (int)is64) == size);
		d.iat_rva = base + size - 1u;
		memset(g, 0, sizeof g);
		CK(kgenome_pe_write_imports(g, sizeof g, base, &d, 1, pool, sizeof pool, (int)is64) == 0);
		d.iat_rva = base + size + 1u;
		memset(g, 0, sizeof g);
		CK(kgenome_pe_write_imports(g, sizeof g, base, &d, 1, pool, sizeof pool, (int)is64) == size);
	}
	result("E9 ", "write_imports: the slot beside the table, not on it", before);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	e4b_adjacent();
	e9_slot_boundary();
	e7b_pie_and_table();
	e7_rebuild_wrap();
	e4_resource_clip();
	e1_dirs_past_optsz();
	if (hk_fails) {
		printf("image_defect2: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("image_defect2: ok\n");
	return 0;
}
