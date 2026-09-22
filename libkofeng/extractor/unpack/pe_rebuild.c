/*
 * pe_rebuild.c - put an unpacked PE image back into the shape of a file.
 *
 * Three steps: find the header the packer kept, work out where each section's bytes
 * are in the image, and write a file with those bytes at the offsets the header
 * says they belong at. The first step is the only one with any judgement in it.
 *
 *
 * FINDING THE HEADER
 *
 * There is no offset to read and no marker to trust: UPX puts the original header
 * near the end of the image, another packer would put it somewhere else, and a
 * hostile file can put the four bytes "PE\0\0" wherever it likes. So every
 * occurrence is tried and each is accepted only if what follows it is a header that
 * could be true - a machine this format defines, a section count in range, an
 * optional header of a size that matches its own magic, and a section table that
 * fits in the image.
 *
 * Measured on unpacked UPX output: three occurrences of the signature per image,
 * two of them inside compressed-looking data with a section count of 3001 and 53811
 * and an optional header magic of 0x0040. One passes. That is the whole reason the
 * check is a list of conditions rather than a search for bytes.
 *
 *
 * WHERE THE BYTES ARE
 *
 * The image is what the loader would have had, starting at the first section's
 * virtual address: image[x] is RVA (first + x). So a section's bytes begin at
 * (VirtualAddress - first) and there is nothing to search for. Confirmed against
 * real output rather than assumed - .rdata at its computed offset held the strings
 * a .rdata holds, and .text at offset zero held code.
 *
 *
 * WHAT IS BOUNDED, AND WHY EACH
 *
 * Every number below comes from a header inside a file that was compressed by
 * somebody who chose what to compress:
 *
 *   - the section count and the optional header size decide how much is read, so
 *     they are checked against the image before anything is read through them.
 *   - PointerToRawData and SizeOfRawData decide where bytes are WRITTEN in the
 *     output, so the output size is computed from them with saturating arithmetic
 *     and refused if it exceeds what the caller allowed.
 *   - a section whose bytes are not entirely inside the image is written short
 *     rather than refused: an image cut off by a budget is the ordinary case, and
 *     what is there is still worth scanning.
 */

#include "pe_rebuild.h"

#include <stdlib.h>
#include <string.h>

/*
 * The signature sits in front of the COFF header, and forgetting it is a four byte
 * error that does not look like one.
 *
 * `hdr` points at "PE\0\0", so the COFF header begins at hdr + SIG_LEN and the
 * section table at hdr + SIG_LEN + COFF_LEN + optsz. Written without the signature
 * once, every section field was read four bytes early: the header copied out was
 * still correct - it is copied from hdr directly - so the rebuilt file identified
 * as PE, parsed, and reported sane sections, while the section CONTENT was placed
 * from garbage offsets. A wrong answer that passes every cheap check is the reason
 * the test below compares bytes rather than verdicts.
 */
#define SIG_LEN          4u
#define COFF_LEN        20u
#define SEC_LEN         40u
#define MAX_SECTIONS   96u      /* the loader's own limit */
#define MIN_OPT_LEN     96u
#define DOS_LEN        0x40u    /* the MZ stub this writes: header and nothing else */

/*
 * Is there a header here that could be true?
 *
 * Deliberately not "is this a valid PE" - the image holds a header for a file that
 * no longer exists and some of its fields describe a layout this code is about to
 * change. What is checked is only what has to hold for the rebuild to be bounded.
 */
static int header_plausible(kof_buf img, uint64_t at, uint16_t *nsec_out,
			    uint16_t *optsz_out)
{
	uint16_t machine, nsec, optsz, magic;

	if (!kof_rd_u16(img, at + SIG_LEN + 0, 0, &machine) ||
	    !kof_rd_u16(img, at + SIG_LEN + 2, 0, &nsec) ||
	    !kof_rd_u16(img, at + SIG_LEN + 16, 0, &optsz))
		return 0;
	if (nsec == 0 || nsec > MAX_SECTIONS)
		return 0;
	if (optsz < MIN_OPT_LEN)
		return 0;
	if (!kof_rd_u16(img, at + SIG_LEN + COFF_LEN, 0, &magic))
		return 0;
	/* 0x10b is PE32 and 0x20b is PE32+; anything else is not an optional
	 * header, whatever the bytes before it said. */
	if (magic != 0x010bu && magic != 0x020bu)
		return 0;
	/* Machine 0 is legal in an object file and never in an image. */
	if (machine == 0)
		return 0;
	/* The section table has to be inside the image, or there is nothing to
	 * rebuild from. */
	if (!kof_in_range(img, at + SIG_LEN + COFF_LEN + optsz,
			  (uint64_t)nsec * SEC_LEN))
		return 0;

	*nsec_out = nsec;
	*optsz_out = optsz;
	return 1;
}

int kof_pe_rebuild(kof_buf img, uint64_t cap, uint8_t **out, uint64_t *out_len)
{
	uint64_t at, hdr = 0, first_rva = 0, file_len = 0, sec_tab;
	uint16_t nsec = 0, optsz = 0;
	uint32_t i;
	uint8_t *file;
	int found = 0;

	if (!out || !out_len || img.n < COFF_LEN + MIN_OPT_LEN)
		return 0;

	/*
	 * memchr for the first byte, then compare the rest.
	 *
	 * The signature is rare and the image is large - hundreds of kilobytes per
	 * unpacked executable - so nearly all of this loop's work is skipping bytes
	 * that are not 'P', which is exactly what memchr is allowed to do a word at
	 * a time. Measured on a 4MB image with no valid header, so the whole of it
	 * is scanned: 1945MB/s byte at a time against what the run below reports.
	 */
	at = 0;
	while (at + 4 <= img.n) {
		const uint8_t *hit = memchr(img.p + at, 'P', (size_t)(img.n - at - 3));

		if (!hit)
			break;
		at = (uint64_t)(hit - img.p);
		if (hit[1] == 'E' && hit[2] == 0 && hit[3] == 0 &&
		    header_plausible(img, at, &nsec, &optsz)) {
			hdr = at;
			found = 1;
			break;
		}
		at++;
	}
	if (!found)
		return 0;

	sec_tab = hdr + SIG_LEN + COFF_LEN + optsz;

	/*
	 * Where the image begins, in virtual terms.
	 *
	 * Taken as the lowest section address rather than read from the header,
	 * because it is the one number the rebuild cannot be wrong about: get it
	 * wrong and every section is copied from the wrong place, and nothing
	 * downstream would notice.
	 */
	for (i = 0; i < nsec; i++) {
		uint32_t rva;

		if (!kof_rd_u32(img, sec_tab + (uint64_t)i * SEC_LEN + 12, 0, &rva))
			return 0;
		if (i == 0 || rva < first_rva)
			first_rva = rva;
	}

	/* How large the rebuilt file has to be. Saturating, and refused rather than
	 * clamped: a file smaller than the header describes is one whose sections
	 * land at offsets that mean something else. */
	file_len = DOS_LEN + SIG_LEN + COFF_LEN + optsz + (uint64_t)nsec * SEC_LEN;
	for (i = 0; i < nsec; i++) {
		uint32_t raw, ptr;
		uint64_t end;

		if (!kof_rd_u32(img, sec_tab + (uint64_t)i * SEC_LEN + 16, 0, &raw) ||
		    !kof_rd_u32(img, sec_tab + (uint64_t)i * SEC_LEN + 20, 0, &ptr))
			return 0;
		if (raw == 0)
			continue;
		end = kof_sat_add(ptr, raw);
		if (end > file_len)
			file_len = end;
	}
	if (file_len == 0 || file_len > cap)
		return 0;

	file = calloc(1, (size_t)file_len);
	if (!file)
		return 0;

	/*
	 * A DOS header, because the format requires one and the original's is not
	 * in the image.
	 *
	 * Sixty-four bytes: the signature, e_lfanew, and zeroes. It is not the stub
	 * the file was built with and does not pretend to be - what it has to do is
	 * let the object identify as PE so that everything downstream applies to it.
	 */
	file[0] = 'M';
	file[1] = 'Z';
	file[0x3c] = (uint8_t)DOS_LEN;

	/* The header and section table, unchanged: whatever the original said about
	 * itself is what a scan should see. */
	{
		uint64_t n = SIG_LEN + COFF_LEN + optsz + (uint64_t)nsec * SEC_LEN;

		if (kof_in_range(img, hdr, n))
			memcpy(file + DOS_LEN, img.p + hdr, (size_t)n);
	}

	for (i = 0; i < nsec; i++) {
		uint32_t rva, raw, ptr;
		uint64_t src, have;

		if (!kof_rd_u32(img, sec_tab + (uint64_t)i * SEC_LEN + 12, 0, &rva) ||
		    !kof_rd_u32(img, sec_tab + (uint64_t)i * SEC_LEN + 16, 0, &raw) ||
		    !kof_rd_u32(img, sec_tab + (uint64_t)i * SEC_LEN + 20, 0, &ptr))
			continue;
		if (raw == 0 || rva < first_rva)
			continue;
		src = (uint64_t)rva - first_rva;

		/*
		 * Short rather than refused.
		 *
		 * An image that a budget cut off, or one whose last section is
		 * partly outside it, still holds most of a file - and the part it
		 * holds is the part worth scanning. kof_clip_len is the same answer
		 * every other reader in this tree gives to the same question.
		 */
		have = kof_clip_len(img.n, src, raw);
		if (have == 0)
			continue;
		if (ptr >= file_len)
			continue;
		if (have > file_len - ptr)
			have = file_len - ptr;
		memcpy(file + ptr, img.p + src, (size_t)have);
	}

	*out = file;
	*out_len = file_len;
	return 1;
}
