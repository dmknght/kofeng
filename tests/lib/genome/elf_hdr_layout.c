/*
 * elf_hdr_layout - kgenome_elf_seg_align and kgenome_elf_sec_layout: the three header fields the parse does not keep (p_align,
 * sh_addralign, sh_entsize), read back from the record the parse read.
 *
 * Model: every field is written into the image with a value unique to its record (hk_w, one spelling per class and byte order), the
 * object is parsed, and each accessor must return exactly what was written, for all four class x order shapes. Boundary inputs:
 * an index at and past the kept count, a view that is not valid, a buffer cut inside the record and cut just before it, a table
 * offset so large that base + i * size would wrap, and a clamped table (the accessor answers only for kept records). The oracle
 * for "which bytes" is a plain little/big reader written here, not kof_rd_*.
 *
 * Linked against libkgenome.a alone.
 */

#include <kgenome.h>

#include "hk.h"

static struct hk_elf E;

static uint64_t rd(const uint8_t *p, unsigned n, int be)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		v |= (uint64_t)p[be ? n - 1u - i : i] << (8u * i);
	return v;
}

static int parse(kof_buf f, struct kgenome_elf_info *i, struct kgenome_obj *o)
{
	memset(i, 0, sizeof *i);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(f, i, o))
		return 0;
	o->file_header = i;
	return 1;
}

/* A distinct value per record and per field, so a wrong stride or a wrong field shows. */
static uint64_t want_align(uint32_t i, int is64)
{
	return is64 ? 0x1000u + 0x100000000ull * (i + 1u) : 0x1000u + 0x10000u * (i + 1u);
}
static uint64_t want_addralign(uint32_t i, int is64)
{
	return is64 ? 3u + 0x200000000ull * (i + 1u) : 3u + 0x20000u * (i + 1u);
}
static uint64_t want_entsize(uint32_t i, int is64)
{
	return is64 ? 5u + 0x300000000ull * (i + 1u) : 5u + 0x30000u * (i + 1u);
}

static void stamp(struct hk_elf *e)
{
	uint32_t i;
	unsigned w = e->is64 ? 8u : 4u;

	for (i = 0; i < (e->rel ? 0u : 1u); i++) {
		uint8_t *p = e->b + e->ph + i * e->ph_ent;

		hk_w(p + (e->is64 ? 48 : 28), want_align(i, e->is64), w, e->be);
	}
	for (i = 0; i < 6; i++) {
		uint8_t *h = e->b + e->sh + i * e->sh_ent;

		hk_w(h + (e->is64 ? 48 : 32), want_addralign(i, e->is64), w, e->be);
		hk_w(h + (e->is64 ? 56 : 36), want_entsize(i, e->is64), w, e->be);
	}
}

static void shapes(void)
{
	int is64, be, rel;

	for (is64 = 0; is64 < 2; is64++)
		for (be = 0; be < 2; be++)
			for (rel = 0; rel < 2; rel++) {
				static struct kgenome_elf_info info;
				struct kgenome_obj obj;
				kof_buf f;
				uint32_t i;
				uint64_t a = 77, b = 78;

				hk_elf(&E, is64, be, rel);
				stamp(&E);
				f = kof_buf_make(E.b, E.n);
				CK(parse(f, &info, &obj));
				CK(info.seg_count == (rel ? 0u : 1u));
				CK(info.sec_count == 6u);
				for (i = 0; i < info.seg_count; i++) {
					a = 0;
					CK(kgenome_elf_seg_align(f, &info, i, &a) == 1);
					CK(a == want_align(i, is64));
					/* the oracle: the bytes, read by hand at the field's offset */
					CK(a == rd(E.b + E.ph + i * E.ph_ent + (is64 ? 48u : 28u), is64 ? 8u : 4u, be));
				}
				for (i = 0; i < info.sec_count; i++) {
					a = b = 0;
					CK(kgenome_elf_sec_layout(f, &info, i, &a, &b) == 1);
					CK(a == want_addralign(i, is64));
					CK(b == want_entsize(i, is64));
					CK(a == rd(E.b + E.sh + i * E.sh_ent + (is64 ? 48u : 32u), is64 ? 8u : 4u, be));
					CK(b == rd(E.b + E.sh + i * E.sh_ent + (is64 ? 56u : 36u), is64 ? 8u : 4u, be));
				}
				/* an index past the kept records answers 0 and writes nothing */
				a = 77; b = 78;
				CK(kgenome_elf_seg_align(f, &info, info.seg_count, &a) == 0 && a == 77);
				CK(kgenome_elf_seg_align(f, &info, 0xffffffffu, &a) == 0 && a == 77);
				CK(kgenome_elf_sec_layout(f, &info, info.sec_count, &a, &b) == 0 && a == 77 && b == 78);
				CK(kgenome_elf_sec_layout(f, &info, 0xffffffffu, &a, &b) == 0 && a == 77 && b == 78);
			}
}

/* A buffer cut inside a record, or just before it, is a refusal and not a short read. */
static void cuts(void)
{
	int is64;

	for (is64 = 0; is64 < 2; is64++) {
		static struct kgenome_elf_info info;
		struct kgenome_obj obj;
		kof_buf f;
		uint64_t a = 77, b = 78;
		uint32_t cut;
		uint32_t phe, she;

		hk_elf(&E, is64, 0, 0);
		stamp(&E);
		phe = E.ph_ent;
		she = E.sh_ent;
		f = kof_buf_make(E.b, E.n);
		CK(parse(f, &info, &obj));
		/* the segment record ends at ph + phe: every shorter cut refuses, the exact length answers */
		for (cut = E.ph; cut <= E.ph + phe + 1u; cut++) {
			kof_buf g = kof_buf_make(E.b, cut);

			a = 77;
			if (cut >= E.ph + phe)
				CK(kgenome_elf_seg_align(g, &info, 0, &a) == 1 && a == want_align(0, is64));
			else
				CK(kgenome_elf_seg_align(g, &info, 0, &a) == 0 && a == 77);
		}
		/* the same for the last section header: it ends the file */
		for (cut = E.sh + 5u * she; cut <= E.n; cut++) {
			kof_buf g = kof_buf_make(E.b, cut);

			a = 77; b = 78;
			if (cut >= E.sh + 6u * she)
				CK(kgenome_elf_sec_layout(g, &info, 5, &a, &b) == 1 && a == want_addralign(5, is64));
			else
				CK(kgenome_elf_sec_layout(g, &info, 5, &a, &b) == 0 && a == 77 && b == 78);
		}
		/* an empty buffer */
		CK(kgenome_elf_seg_align(kof_buf_make(E.b, 0), &info, 0, &a) == 0);
		CK(kgenome_elf_sec_layout(kof_buf_make(E.b, 0), &info, 0, &a, &b) == 0);
	}
}

/* A view that is not valid answers nothing, whatever its counts say. */
static void invalid_and_wrapping(void)
{
	static struct kgenome_elf_info info;
	struct kgenome_obj obj;
	kof_buf f;
	uint64_t a = 77, b = 78;

	hk_elf(&E, 1, 0, 0);
	stamp(&E);
	f = kof_buf_make(E.b, E.n);
	CK(parse(f, &info, &obj));
	info.valid = 0;
	CK(kgenome_elf_seg_align(f, &info, 0, &a) == 0 && a == 77);
	CK(kgenome_elf_sec_layout(f, &info, 0, &a, &b) == 0 && a == 77 && b == 78);
	info.valid = 1;
	/* base + i * size would wrap: the view's tables sit at the top of the 64-bit space (a forged view; the parse refuses
	 * an offset past the file, so only a caller-built view reaches this) */
	info.phoff = ~0ull - 10u;
	info.shoff = ~0ull - 10u;
	CK(kgenome_elf_seg_align(f, &info, 0, &a) == 0 && a == 77);
	CK(kgenome_elf_sec_layout(f, &info, 5, &a, &b) == 0 && a == 77 && b == 78);
	info.phoff = 0xffffffff00000000ull;
	info.sec_count = 128;
	CK(kgenome_elf_sec_layout(f, &info, 127, &a, &b) == 0);
}

/* A clamped table: the accessor answers only for the records the parse kept. */
static void clamped(void)
{
	static struct kgenome_elf_info info;
	struct kgenome_obj obj;
	kof_buf f;
	uint64_t a = 77, b = 78;

	hk_elf(&E, 1, 0, 0);
	stamp(&E);
	/* shnum claims 0xfff0 sections: the parse keeps what the file holds and says so */
	hk_w(E.b + 60, 0xfff0, 2, 0);
	f = kof_buf_make(E.b, E.n);
	CK(parse(f, &info, &obj));
	CK(info.shnum_claimed == 0xfff0u);
	CK(info.sec_count < 0xfff0u);
	CK(info.sec_count <= KGENOME_ELF_MAX_SECTIONS);
	CK(kgenome_elf_sec_layout(f, &info, info.sec_count, &a, &b) == 0 && a == 77);
	if (info.sec_count)
		CK(kgenome_elf_sec_layout(f, &info, info.sec_count - 1u, &a, &b) == 1);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	cuts();
	invalid_and_wrapping();
	clamped();
	printf("elf_hdr_layout: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
