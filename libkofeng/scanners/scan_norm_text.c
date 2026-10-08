/*
 * scan_norm_text.c - the byte maps the normalised view is built from: which regions
 * are gathered, which bytes are kept verbatim, which are free to be rewritten.
 *
 * Pure functions over buffers and region lists; no scanner state. norm_emit
 * (scan_norm.c) is the stage that uses them.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include <celllysis/xref.h>
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


uint32_t sx_norm_gather(struct kof_obj_ctx *ctx, struct kof_src_region *r,
			    uint32_t cap)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t b, n = 0;

	if (!ctx->resolve_scan)
		return 0;
	for (b = 1; b <= NORM_RGN_BITS && n < cap; b++) {
		uint32_t mask = 1u << b, k, i;

		k = ctx->resolve_scan(ctx, mask, ext, KOF_SCAN_MAX_EXTENTS);
		for (i = 0; i < k && n < cap; i++) {
			if (!ext[i].len)
				continue;
			r[n].mask = mask;
			r[n].off = ext[i].off;
			r[n].len = ext[i].len;
			n++;
		}
	}
	return n;
}

/*
 * A RANGE OF BITS AT A TIME, NOT A BIT AT A TIME.
 *
 * All four of these maps are filled the same way - a contiguous span of an
 * object marked kept, given back or dropped - and all four were written
 * `for (j = from; j < to; j++) map[j >> 3] |= 1u << (j & 7u)`. That is a
 * shift, a mask and a read-modify-write of the same byte eight times over,
 * for a span that is usually an entire CODE region: megabytes.
 *
 * Measured with callgrind over 120 system binaries (109 MB), before this:
 * the clear inside sx_norm_keep_exec alone was 390 million instructions, 3.49%
 * of the whole scan, and sx_norm_emit's self cost - almost all of it these
 * loops - was 1.39 billion, 12.4%.
 *
 * The whole bytes in the middle are one memset; only the two partial bytes at
 * the ends need the mask. Verified against the bit-at-a-time form over every
 * from/to pair in a 200-bit map, against two different starting contents.
 */
void sx_bits_set(uint8_t *b, uint64_t from, uint64_t to)
{
	uint64_t fb, tb;

	if (!b || from >= to)
		return;
	fb = from >> 3;
	tb = (to - 1u) >> 3;
	if (fb == tb) {
		b[fb] |= (uint8_t)((0xffu << (from & 7u)) &
				   (0xffu >> (7u - ((to - 1u) & 7u))));
		return;
	}
	b[fb] |= (uint8_t)(0xffu << (from & 7u));
	if (tb > fb + 1u)
		memset(b + fb + 1u, 0xff, (size_t)(tb - fb - 1u));
	b[tb] |= (uint8_t)(0xffu >> (7u - ((to - 1u) & 7u)));
}

void sx_bits_clr(uint8_t *b, uint64_t from, uint64_t to)
{
	uint64_t fb, tb;

	if (!b || from >= to)
		return;
	fb = from >> 3;
	tb = (to - 1u) >> 3;
	if (fb == tb) {
		b[fb] &= (uint8_t)~((0xffu << (from & 7u)) &
				    (0xffu >> (7u - ((to - 1u) & 7u))));
		return;
	}
	b[fb] &= (uint8_t)~(0xffu << (from & 7u));
	if (tb > fb + 1u)
		memset(b + fb + 1u, 0x00, (size_t)(tb - fb - 1u));
	b[tb] &= (uint8_t)~(0xffu >> (7u - ((to - 1u) & 7u)));
}

void sx_norm_keep_bits(uint8_t *keep, uint64_t n,
			   const struct kof_src_region *r, uint32_t nr,
			   uint32_t keep_mask)
{
	uint32_t i;

	memset(keep, 0, (size_t)((n + 7u) / 8u));
	for (i = 0; i < nr; i++) {
		uint64_t e;

		if (!(r[i].mask & keep_mask))
			continue;
		if (r[i].off >= n)
			continue;
		e = r[i].off + r[i].len;
		if (e > n)
			e = n;
		sx_bits_set(keep, r[i].off, e);
	}
}

/*
 * CODE IS A SEGMENT, AND THE INSTRUCTIONS ARE ONLY PART OF IT.
 *
 * KOF_SCAN_ELF_CODE is the loadable segment with PF_X, and a linker puts
 * .rodata in there beside .text - so "CODE" holds every string literal the
 * program has as well as its opcodes. Kept byte for byte, as the whole region
 * was, those strings could not be rewritten: an IoT dropper's exploits are
 * percent-encoded form bodies sitting in .rodata, the decode pass rewrote them
 * and the restore put them straight back. Measured on one: the payload at
 * offset 162554, every executable section ending at 134934.
 *
 * The reason for keeping CODE is about INSTRUCTIONS - "opcodes are what a hex
 * rule is written against, byte for byte" - and it is still true of them. So
 * what is kept is the executable SECTIONS, which is what that sentence was
 * always about, and the rest of the segment is rewritten like any other data.
 *
 * ONLY WHERE THE FILE SAYS SO. A stripped object with no section table cannot
 * tell its instructions from its strings, and guessing would move opcodes. It
 * keeps the whole region, exactly as before.
 */
void sx_norm_keep_exec(uint8_t *keep, uint64_t n,
			   const struct kof_elf_info *e,
			   const struct kof_src_region *r, uint32_t nr)
{
	uint32_t i;

	if (!e || !e->sec_count)
		return;
	/* Take the whole of CODE back... */
	for (i = 0; i < nr; i++) {
		uint64_t end;

		if (r[i].mask != (uint32_t)KOF_SCAN_ELF_CODE)
			continue;
		if (r[i].off >= n)
			continue;
		end = r[i].len > n - r[i].off ? n : r[i].off + r[i].len;
		sx_bits_clr(keep, r[i].off, end);
	}
	/* ...and give back only what is instructions. */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		const struct kof_elf_sec *c = &e->sec[i];
		uint64_t end;

		if (!(c->flags & 0x4u))         /* SHF_EXECINSTR */
			continue;
		if (!c->file_size || c->file_off >= n)
			continue;
		end = c->file_size > n - c->file_off ? n
						     : c->file_off + c->file_size;
		sx_bits_set(keep, c->file_off, end);
	}
}

/*
 * THE PE HALF OF THE SAME ARGUMENT, AND IT TURNS ON ONE BIT.
 *
 * KOF_SCAN_PE_CODE is every section with IMAGE_SCN_MEM_EXECUTE, and keeping it
 * whole is about INSTRUCTIONS - "opcodes are what a hex rule is written
 * against, byte for byte". That holds for a section that is executable and NOT
 * writable, which is what a compiler emits and what a rule is written against.
 *
 * It does not hold for a section that is both. A WRITABLE executable section is
 * a section the program rewrites at run time, which is the shape of a packed
 * image and of every image an interpreter run hands back - and there the
 * "instruction stream" is the whole program, strings included. Measured on the
 * child PECompact yields from 007 Spy.exe: 8,626,176 bytes in one RWX section,
 * 7,434 runs of UTF-16LE text inside it, and not one of them narrowed in any
 * view - so an ASCII rule could not match a VB6 program whose every string is
 * a BSTR.
 *
 * WHY THIS COSTS NOTHING THAT MATTERS. kof_exe_unwide is 1:1 - it packs a wide
 * run to the left and zero-fills the rest, and moves no byte outside the run -
 * so nothing after a rewrite is displaced. And this is a VIEW: the object
 * itself is scanned whole and first, so a hex rule written on those bytes still
 * matches where it always did. A view can only ADD a match.
 *
 * The ELF side of this is sx_norm_keep_exec above, which asks the same question a
 * different way because ELF's CODE is a segment and carries .rodata with it.
 */
void sx_norm_keep_exec_pe(uint8_t *keep, uint64_t n,
			      const struct kof_pe_info *e,
			      const struct kof_src_region *r, uint32_t nr)
{
	uint32_t i;

	if (!e || !e->valid || !e->sec_count)
		return;
	for (i = 0; i < e->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *c = &e->sec[i];
		uint64_t end;

		if ((c->perm & (KOF_PE_PERM_W | KOF_PE_PERM_X)) !=
		    (KOF_PE_PERM_W | KOF_PE_PERM_X))
			continue;
		if (!c->claim_len || c->claim_off >= n)
			continue;
		end = c->claim_len > n - c->claim_off
			      ? n : c->claim_off + c->claim_len;
		sx_bits_clr(keep, c->claim_off, end);
	}
	(void)r;
	(void)nr;
}
