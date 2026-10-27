/*
 * diag_code.c - what counts as code: the executable bytes of a segment and of an object.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

/* ---- what counts as code ------------------------------------------------- */

/*
 * EXECUTABLE SEGMENTS, NOT SECTIONS.
 *
 * A section table is optional and a payload generator leaves it out:
 * msfvenom's ELF template has one PT_LOAD and no sections at all, so a
 * sweep that looked for ".text" or for an executable SHF flag would read
 * nothing out of every one of them. The program header is what the loader
 * itself reads, so it is what is here.
 */
/*
 * THE EXECUTABLE BYTES OF SEGMENT `i`: PT_LOAD with PF_X, clipped to what the
 * object holds. Zero for anything else. The ONE statement of what the loader
 * maps as code; every reader gets it through kgenome_diag_code_range, which moves
 * the start past the headers.
 */
static uint64_t kgenome_diag_code_seg(const struct kgenome_elf_info *e, uint32_t i,
				  uint64_t size, uint64_t *at)
{
	const struct kgenome_elf_seg *g = &e->seg[i];
	uint64_t have, off;

	if (!kgenome_elf_seg_is_code(g))
		return 0;               /* PT_LOAD, executable */
	have = kgenome_elf_seg_extent(g, size, &off);
	if (have)
		*at = off;
	return have;
}

/*
 * THE CODE RANGES OF AN ELF: THE BYTES OF EXECUTABLE SEGMENT `i` THAT CAN BE
 * INSTRUCTIONS - the segment, clipped to the object, past the ELF header and the
 * program headers when the segment holds them. Zero for a segment that is not
 * code. The ONE definition, and everything that reads an ELF's code starts from
 * it: the xref sweep (when the object has no executable section) reads it as it
 * is, and kgenome_diag_walk_range below refines its start for the walks that decode
 * every byte.
 *
 * THE HEADERS ARE NOT CODE. A segment usually begins at file offset zero and so
 * holds the ELF header and the program headers; read from the front,
 * `7f E L F 02 01 01 ...` is decoded as instructions. MEASURED on msfvenom's
 * x86-64 stager: the mmap at +0x8d came back with its number unreadable, because
 * the push that sets it had been swallowed by an instruction decoded across the
 * header boundary. They end at e_phoff + e_phnum * e_phentsize (never before the
 * ELF header itself).
 */
uint64_t kgenome_diag_code_range(const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at)
{
	uint64_t have, hdr, pend, from = 0;

	if (!e || i >= KGENOME_ELF_MAX_SEGMENTS)        /* the table has this many entries and no more */
		return 0;
	have = kgenome_diag_code_seg(e, i, size, &from);
	if (!have)
		return 0;
	hdr = e->elf_class == KGENOME_ELFCLASS_64 ? 64u : 52u;
	pend = e->phoff + (uint64_t)e->phnum * e->phentsize;
	if (pend > hdr && pend >= e->phoff)             /* no wrap */
		hdr = pend;
	if (from < hdr) {
		/* what is left of the segment past the headers; none when it is only headers */
		if (hdr - from >= have)
			return 0;
		have -= hdr - from;
		from = hdr;
	}
	*at = from;
	return have;
}

/*
 * WHERE A WALK THAT DECODES EVERY BYTE OF THE SEGMENT BEGINS. A linear sweep is
 * alignment sensitive: bytes that are not instructions, decoded as if they were,
 * carry their desync into the real code after them, so the start of the walk has
 * to be a place the object says instructions are. The three things that say so,
 * each used for what it is:
 *
 *   THE LINKER'S SECTION TABLE, WHERE THERE IS ONE: the first executable
 *   section inside the segment. This is the one place the segment walks need the
 *   section view, and for a reason the segments cannot give: a segment holds
 *   .interp, .dynsym, .rela, the section header table and, in a Go binary, 4 KiB
 *   of both before .text, and only the section table says none of it is code.
 *   The rule before this one started at the entry point and lost everything
 *   before it: gcc -O2 puts main in .text.startup ahead of _start (main =
 *   0x401040, _start = 0x401070 in a measured binary), a Go binary's .text starts
 *   340 KiB before its entry, a static libc has code before it too. MEASURED over
 *   the 1239 ELF files here, the nodes of 27 change and every change is code the
 *   old start never read.
 *
 *   THE ENTRY POINT, WHERE THE SECTIONS SAY NOTHING - a sectionless payload, a
 *   packer's output, a table that marks nothing in this segment executable. It is
 *   the one offset certain to be the first byte of an instruction, and everything
 *   before it is unknown: compressed data, filler, a header the code lives in.
 *   Starting after the headers instead was tried, and the unit test "deep in a
 *   big segment" (a payload after 8 KiB of bytes that are not instructions, as a
 *   packer leaves them) loses its whole node tree, because the filler's desync
 *   swallows the stub. It is also the lower bound when the entry precedes the
 *   first executable section: a table that hides the code.
 *
 *   THE HEADERS, always: kgenome_diag_code_range.
 *
 * What this cannot do: a sectionless ordinary binary whose main sits before
 * _start still loses it - nothing in the object says where its code begins, and
 * the entry is the only start that does not risk the desync. The xref sweep reads
 * the unrefined range instead (see xref_runs) because its budget counts from the
 * front and it must not report "complete" for code it never read.
 */
static uint64_t kgenome_diag_walk_range(const struct kgenome_obj *obj,
			     const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at)
{
	uint64_t have = kgenome_diag_code_range(e, i, size, at);
	uint64_t seg, from, first = UINT64_MAX, eo = obj ? obj->entry_off : KGENOME_BROKEN;
	uint32_t k;

	if (!have)
		return 0;
	seg = *at;
	from = seg;
	for (k = 0; k < e->sec_count && k < KGENOME_ELF_MAX_SECTIONS; k++) {
		uint64_t sat, shave;

		if (!kgenome_elf_sec_is_code(&e->sec[k]))
			continue;
		shave = kgenome_elf_sec_extent(&e->sec[k], size, &sat);
		if (shave && sat >= seg && sat - seg < have && sat < first)
			first = sat;
	}
	if (first != UINT64_MAX)
		from = first;
	/* The entry, when the table has no start here - or starts after it. */
	if (eo >= seg && eo - seg < have && (first == UINT64_MAX || eo < first))
		from = eo;
	have -= from - seg;
	*at = from;
	return have;
}

/*
 * THE CODE EXTENTS OF AN OBJECT, BY INDEX - the one iteration every walk over an
 * object's code makes.
 *
 * An ELF's candidates are its program headers and an executable PT_LOAD answers
 * through kgenome_diag_walk_range (the start moved to where instructions begin);
 * a PE's are its sections and an executable one answers with the raw bytes it
 * declares, from the first byte (a PE section does not contain the headers, so
 * there is no desync to avoid). The index is the segment's or the section's own,
 * which is what a walk keeps its per-segment trace by. Anything else has no
 * extents: a payload lifted out of a variable is all code and its callers read
 * the whole of it.
 *
 *     for (i = 0; i < kgenome_diag_extent_count(obj); i++)
 *         if ((have = kgenome_diag_extent(obj, i, size, &at))) walk(at, have);
 */
uint32_t kgenome_diag_extent_count(const struct kgenome_obj *obj)
{
	uint32_t n = 0, max = 0;

	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		n = e ? e->seg_count : 0;
		max = KGENOME_ELF_MAX_SEGMENTS;
	} else if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		n = p ? p->sec_count : 0;
		max = KGENOME_PE_MAX_SECTIONS;
	}
	return n < max ? n : max;
}

uint64_t kgenome_diag_extent(const struct kgenome_obj *obj, uint32_t i, uint64_t size,
			 uint64_t *at)
{
	if (obj->format == KGENOME_FMT_ELF)
		return kgenome_diag_walk_range(obj, kgenome_obj_elf(obj), i, size, at);
	if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_sec *sc = &kgenome_obj_pe(obj)->sec[i];

		return kgenome_pe_sec_is_code(sc) ? kgenome_pe_sec_extent(sc, size, at) : 0;
	}
	return 0;
}

/*
 * THE EXECUTABLE BYTES OF AN OBJECT, which is what a budget scales its limits
 * from: the loadable executable segments of an ELF as the walks read them
 * (kgenome_diag_walk_range), the code sections of a PE, and the whole object for
 * anything else - a payload lifted out of a variable has no header and is all
 * code. Never zero for a non-empty object.
 */
uint64_t kgenome_diag_code_bytes(const struct kgenome_obj *obj, uint64_t size)
{
	uint64_t total = 0;
	uint32_t i, n;
	int valid;

	if (!obj || !size)
		return size;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		valid = e && e->valid;
	} else if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		valid = p && p->valid;
	} else {
		return size;
	}
	for (i = 0, n = valid ? kgenome_diag_extent_count(obj) : 0; i < n; i++) {
		uint64_t at;

		total += kgenome_diag_extent(obj, i, size, &at);
	}
	/* KNOWN DEFECT WP9-F1 (2026-10-25, M) [sev M]: kgenome_diag_code_bytes returns the SUM of the executable
	 * extents, so overlapping segments count twice. Trigger: 3 PT_LOAD RX over the same 1 KiB. Effect:
	 * code_bytes 3 KiB for a 1 KiB file; max_insn (64 x code) and max_nodes (code/8) follow it, so a hostile
	 * file buys a bound larger than its size. Reproducer: tests/lib/genome/diag_known_misses.c f1 (green until
	 * fixed). Fix: `return total ? (total < size ? total : size) : size;` (better: the union of the extents). */
	return total ? total : size;
}
