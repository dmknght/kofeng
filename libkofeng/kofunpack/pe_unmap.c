/*
 * pe_unmap.c - see pe_unmap.h for what this is and how it differs from
 * pe_rebuild.c.
 *
 * The fields are read here rather than through the PE collector, to keep
 * kofunpack free of a dependency on kofparsers - the same property every other
 * file in this directory has. What is needed is six numbers and two tables, and
 * every one of them is read through the bounds-checking accessors, so a header
 * that lies produces a short file rather than a read outside the buffer.
 */

#include <stdlib.h>
#include <string.h>

#include "pe_unmap.h"

#define DOS_MAGIC   0x5a4du
#define SIG_LEN     4u
#define COFF_LEN    20u
#define SEC_LEN     40u
#define MIN_OPT_LEN 96u

#define OPT_MAGIC_PE32     0x10bu
#define OPT_MAGIC_PE32PLUS 0x20bu

/* Where NumberOfRvaAndSizes sits, and where the directory array starts after
 * it. The two magics differ by the eight bytes ImageBase gains and the three
 * four-byte fields that become eight. */
#define DIRCOUNT_OFF_32     92u
#define DIRCOUNT_OFF_32PLUS 108u
#define DIRBASE_OFF_32      96u
#define DIRBASE_OFF_32PLUS  112u

#define DIR_BASERELOC 5u

/* IMAGE_REL_BASED_*, and only the two that carry a pointer. HIGH and LOW split
 * one across two entries and appear on nothing this will meet; ABSOLUTE is the
 * padding a block uses to stay four-byte aligned and is meant to be skipped. */
/* "this RVA has no file offset". A local sentinel rather than KOF_BROKEN,
 * which lives in the module ABI: nothing else in kofunpack includes that, and a
 * private helper does not need a public vocabulary to say "no". */
#define NO_FILE_OFF UINT64_MAX

#define REL_ABSOLUTE 0u
#define REL_HIGHLOW  3u
#define REL_DIR64    10u

struct hdr {
	uint64_t at;          /* the PE signature */
	uint64_t opt;         /* the optional header */
	uint64_t sec_tab;
	uint64_t image_base;
	uint64_t size_of_headers;
	uint64_t dir_base;
	uint32_t n_dirs;
	uint16_t nsec;
	uint16_t optsz;
	int      plus;
};

/*
 * Read the header, refusing anything that does not describe a mapped image.
 *
 * The checks are the ones a wrong answer would be built on: the MZ and the
 * signature place the header, the section count bounds the table, and the
 * optional header size has to be large enough to hold the fields read out of
 * it. A section count of zero is refused because an image with no sections has
 * nothing to un-map.
 */
static int read_hdr(kof_buf img, struct hdr *h)
{
	uint16_t mz = 0, magic = 0;
	uint32_t lfanew = 0, sig = 0;

	memset(h, 0, sizeof *h);
	if (!kof_rd_u16(img, 0, 0, &mz) || mz != DOS_MAGIC)
		return 0;
	if (!kof_rd_u32(img, 0x3c, 0, &lfanew))
		return 0;
	h->at = lfanew;
	if (!kof_rd_u32(img, h->at, 0, &sig) || sig != 0x00004550u)
		return 0;   /* "PE\0\0" little endian */
	if (!kof_rd_u16(img, h->at + SIG_LEN + 2u, 0, &h->nsec) || !h->nsec)
		return 0;
	if (!kof_rd_u16(img, h->at + SIG_LEN + 16u, 0, &h->optsz) ||
	    h->optsz < MIN_OPT_LEN)
		return 0;

	h->opt = h->at + SIG_LEN + COFF_LEN;
	if (!kof_rd_u16(img, h->opt, 0, &magic))
		return 0;
	h->plus = magic == OPT_MAGIC_PE32PLUS;
	if (!h->plus && magic != OPT_MAGIC_PE32)
		return 0;

	if (h->plus) {
		if (!kof_rd_u64(img, h->opt + 24u, 0, &h->image_base))
			return 0;
	} else {
		uint32_t b32 = 0;

		if (!kof_rd_u32(img, h->opt + 28u, 0, &b32))
			return 0;
		h->image_base = b32;
	}
	{
		uint32_t soh = 0;

		if (!kof_rd_u32(img, h->opt + 60u, 0, &soh))
			return 0;
		h->size_of_headers = soh;
	}
	{
		uint64_t cnt_off = h->plus ? DIRCOUNT_OFF_32PLUS
					   : DIRCOUNT_OFF_32;
		uint64_t dir_off = h->plus ? DIRBASE_OFF_32PLUS
					   : DIRBASE_OFF_32;
		uint32_t n = 0;

		if (h->optsz > cnt_off &&
		    kof_rd_u32(img, h->opt + cnt_off, 0, &n))
			h->n_dirs = n > 16u ? 16u : n;
		h->dir_base = h->opt + dir_off;
	}

	h->sec_tab = h->opt + h->optsz;
	if (!kof_in_range(img, h->sec_tab, (uint64_t)h->nsec * SEC_LEN))
		return 0;
	return 1;
}

struct sec {
	uint64_t rva, vsize, raw, ptr;
};

static int read_sec(kof_buf img, const struct hdr *h, uint32_t i,
		    struct sec *s)
{
	uint64_t at = h->sec_tab + (uint64_t)i * SEC_LEN;
	uint32_t vs = 0, rva = 0, raw = 0, ptr = 0;

	if (!kof_rd_u32(img, at + 8u,  0, &vs) ||
	    !kof_rd_u32(img, at + 12u, 0, &rva) ||
	    !kof_rd_u32(img, at + 16u, 0, &raw) ||
	    !kof_rd_u32(img, at + 20u, 0, &ptr))
		return 0;
	s->vsize = vs;
	s->rva = rva;
	s->raw = raw;
	s->ptr = ptr;
	return 1;
}

/*
 * An RVA's place in the file being built, or NO_FILE_OFF.
 *
 * The span a section owns in memory is the larger of its two sizes: a section
 * with more VirtualSize than SizeOfRawData is zero-filled past the file's copy,
 * and an RVA landing in that tail has no file offset at all - which is refused
 * rather than mapped to the byte after the section, because writing a
 * relocation there would corrupt whatever follows.
 */
static uint64_t rva_to_file(const struct sec *sec, uint32_t nsec, uint64_t rva)
{
	uint32_t i;

	for (i = 0; i < nsec; i++) {
		uint64_t span = sec[i].vsize > sec[i].raw ? sec[i].vsize
							 : sec[i].raw;

		if (!span || rva < sec[i].rva || rva - sec[i].rva >= span)
			continue;
		if (rva - sec[i].rva >= sec[i].raw)
			return NO_FILE_OFF;
		return sec[i].ptr + (rva - sec[i].rva);
	}
	return NO_FILE_OFF;
}

/*
 * Undo the loader's base relocations, in the file that has just been built.
 *
 * Done here rather than on the image because the input buffer is the caller's
 * and is not written to; the relocation table names RVAs, so each one is
 * translated through the section table it was just laid out with.
 *
 * EVERY WRITE IS BOUNDED BY THE OUTPUT BUFFER. The block count, the block size,
 * the entry offsets and the RVAs all come out of the image and are all
 * attacker-controlled: a table that names an offset outside the file is one
 * entry skipped, not a write past the end.
 */
static void undo_relocs(kof_buf img, const struct hdr *h,
			const struct sec *sec, uint8_t *file, uint64_t file_len,
			int64_t delta, struct kof_pe_unmap_info *info)
{
	uint64_t dir_rva = 0, dir_len = 0, at, end;
	uint32_t a = 0, n = 0;

	if (!delta || h->n_dirs <= DIR_BASERELOC)
		return;
	if (!kof_rd_u32(img, h->dir_base + DIR_BASERELOC * 8u,     0, &a) ||
	    !kof_rd_u32(img, h->dir_base + DIR_BASERELOC * 8u + 4u, 0, &n))
		return;
	dir_rva = a;
	dir_len = n;
	if (!dir_len || !kof_in_range(img, dir_rva, dir_len))
		return;

	at = dir_rva;
	end = dir_rva + dir_len;
	while (at + 8u <= end) {
		uint32_t page = 0, blk = 0;
		uint64_t e;

		if (!kof_rd_u32(img, at, 0, &page) ||
		    !kof_rd_u32(img, at + 4u, 0, &blk))
			return;
		/* A block that does not advance would loop forever, and a block
		 * larger than the table is a block that reaches past it. */
		if (blk < 8u || at + blk > end)
			return;

		for (e = at + 8u; e + 2u <= at + blk; e += 2u) {
			uint16_t ent = 0;
			uint64_t rva, off;
			uint32_t type;

			if (!kof_rd_u16(img, e, 0, &ent))
				return;
			type = (uint32_t)(ent >> 12);
			if (type == REL_ABSOLUTE)
				continue;
			rva = (uint64_t)page + (ent & 0x0fffu);
			off = rva_to_file(sec, h->nsec, rva);
			if (off == NO_FILE_OFF) {
				if (info)
					info->relocs_skipped++;
				continue;
			}
			if (type == REL_HIGHLOW && off + 4u <= file_len) {
				uint32_t v;

				memcpy(&v, file + off, 4);
				v = (uint32_t)(v - (uint32_t)(uint64_t)delta);
				memcpy(file + off, &v, 4);
				if (info)
					info->relocs_undone++;
			} else if (type == REL_DIR64 && off + 8u <= file_len) {
				uint64_t v;

				memcpy(&v, file + off, 8);
				v = v - (uint64_t)delta;
				memcpy(file + off, &v, 8);
				if (info)
					info->relocs_undone++;
			} else if (info) {
				info->relocs_skipped++;
			}
		}
		at += blk;
	}
}

int kof_pe_unmap(kof_buf img, uint64_t mapped_at, uint64_t cap,
		 uint8_t **out, uint64_t *out_len,
		 struct kof_pe_unmap_info *info)
{
	struct hdr h;
	struct sec *sec;
	uint8_t *file;
	uint64_t file_len, hdr_copy;
	int64_t delta;
	uint32_t i;

	if (info)
		memset(info, 0, sizeof *info);
	if (!out || !out_len)
		return 0;
	if (!read_hdr(img, &h))
		return 0;

	sec = calloc(h.nsec, sizeof *sec);
	if (!sec)
		return 0;
	for (i = 0; i < h.nsec; i++)
		if (!read_sec(img, &h, i, &sec[i])) {
			free(sec);
			return 0;
		}

	/*
	 * How large the file has to be: past the last byte any section claims,
	 * and never smaller than the headers. Refused rather than clamped when
	 * it exceeds the cap, because a file smaller than the section table
	 * describes puts every later section at an offset that means something
	 * else.
	 */
	file_len = h.size_of_headers;
	if (file_len < h.sec_tab + (uint64_t)h.nsec * SEC_LEN)
		file_len = h.sec_tab + (uint64_t)h.nsec * SEC_LEN;
	for (i = 0; i < h.nsec; i++) {
		uint64_t e;

		if (!sec[i].raw)
			continue;
		e = kof_sat_add(sec[i].ptr, sec[i].raw);
		if (e > file_len)
			file_len = e;
	}
	if (!file_len || file_len > cap) {
		free(sec);
		return 0;
	}

	file = calloc(1, (size_t)file_len);
	if (!file) {
		free(sec);
		return 0;
	}

	/*
	 * The headers, straight across. In a mapped image they are where they
	 * are in the file - the loader copies SizeOfHeaders bytes to the image
	 * base and changes nothing in them - so this is the one part that needs
	 * no translation at all.
	 */
	hdr_copy = kof_clip_len(img.n, 0, h.size_of_headers);
	if (hdr_copy > file_len)
		hdr_copy = file_len;
	if (hdr_copy)
		memcpy(file, img.p, (size_t)hdr_copy);

	for (i = 0; i < h.nsec; i++) {
		uint64_t have;

		if (!sec[i].raw || sec[i].ptr >= file_len)
			continue;
		/*
		 * Short rather than refused, the same answer every reader in
		 * this tree gives: an image cut off by a read that stopped at a
		 * guard page still holds the sections before it, and those are
		 * the ones worth scanning.
		 */
		have = kof_clip_len(img.n, sec[i].rva, sec[i].raw);
		if (have < sec[i].raw && info)
			info->sections_short++;
		if (!have)
			continue;
		if (have > file_len - sec[i].ptr)
			have = file_len - sec[i].ptr;
		memcpy(file + sec[i].ptr, img.p + sec[i].rva, (size_t)have);
	}

	delta = mapped_at ? (int64_t)(mapped_at - h.image_base) : 0;
	if (info) {
		info->image_base = h.image_base;
		info->mapped_at = mapped_at;
		info->delta = delta;
		info->sections = h.nsec;
	}
	if (delta)
		undo_relocs(img, &h, sec, file, file_len, delta, info);

	free(sec);
	*out = file;
	*out_len = file_len;
	return 1;
}
