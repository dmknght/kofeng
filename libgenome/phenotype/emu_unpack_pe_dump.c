#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_pe_dump.c - a PE image out of what a run wrote: the run in slices while it produces, and the rebuilt file.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and emu_unpack_private.h for what the
 * files share.
 */
#include "emu_unpack_private.h"

/*
 * ---- RUNNING ON WHILE THE RUN IS STILL PRODUCING --------------------------
 *
 * The budget is a guess and it is wrong in both directions - see
 * kgenome_emu_set_max_insn for the measurement that prompted this: a PECompact2
 * sample reached the ceiling having decompressed 6.5 of the 8.6 megabytes its
 * own header declares, stopped two thirds of the way through something that
 * was working.
 *
 * THREE BOUNDS, AND THE FIRST ONE ALONE MAKES A LOOP IMPOSSIBLE.
 *
 *   1. AT MOST `extensions` EXTENSIONS (KGENOME_EMU_EXTEND_MAX for a run somebody asked for). A count, not a condition. Whatever
 *      the guest does, this returns after at most that many more slices - so
 *      no behaviour, crafted or otherwise, can keep it here.
 *   2. PROGRESS MUST HAVE ADVANCED. Not "recently" but STRICTLY since the last
 *      grant: kgenome_emu_last_write is the instruction at which a page was first
 *      written, and a slice that did not raise it wrote nothing new. A guest
 *      writing one fresh page per slice still only gets EMU_EXTEND_MAX of them.
 *   3. A TOTAL CEILING, so the sum is bounded in absolute terms and not only
 *      as a multiple of an object's size.
 *
 * MEMORY IS NOT EXTENDED. max_pages and the snapshot budget are set once, so a
 * long run holds no more than a short one; what grows is time, and time is
 * what bounds 1 and 3 are for.
 */
#define EMU_EXTEND_TOTAL (2048ull << 20)   /* the sum of every slice */

enum kgenome_emu_stop kgenome_emu_unp_emu_run_while_producing(struct kgenome_emu *e,
						 uint64_t slice, int hand_back,
						 unsigned extensions)
{
	enum kgenome_emu_stop st;
	unsigned k = 0;

	for (;;) {
		/*
		 * READ BEFORE THE SLICE, NOT AFTER. The first version of this
		 * took the mark after the run and compared it with itself, so
		 * the test was always "unchanged" and no extension was ever
		 * granted - the code was there and did nothing. What the test
		 * has to ask is whether THIS slice wrote a page it had never
		 * written before.
		 */
		uint64_t before = kgenome_emu_last_write(e);
		uint64_t next;

		st = kgenome_emu_run(e);
		if (st != KGENOME_EMU_STOP_BUDGET || !slice)
			break;
		/* A module asked to be shown each slice - see `hand_back`. */
		if (hand_back)
			break;
		{
			if (k >= extensions)
				break;          /* the count, which bounds this */
			if (kgenome_emu_last_write(e) <= before)
				break;          /* the slice produced nothing */
		}
		next = kgenome_emu_insn_count(e) + slice;
		if (next > EMU_EXTEND_TOTAL)
			break;                  /* the absolute ceiling */
		/* Keep what this slice earned before risking the next one -
		 * see kgenome_emu_snap_written. */
		kgenome_emu_snap_written(e);
		kgenome_emu_set_max_insn(e, next);
		k++;
	}
	return st;
}

/* ---- putting a run's sections back into a file ---------------------------
 * See kgenome_emu_unp_pe_image in the header for what this selects and why.
 */
int kgenome_emu_unp_pe_image(struct kgenome_emu *e, const struct kgenome_pe_info *info,
			  uint64_t base, uint64_t cap,
			  uint8_t **out, uint64_t *out_len)
{
	uint64_t hdr = 0, total = 0, va, len;
	const uint8_t *bytes;
	uint8_t *b, *o, *sec;
	uint32_t i, it, placed = 0;
	unsigned pe_off = 0x80u, opt, nrva, sec_at;
	uint64_t oep = 0, oep_rva = 0;
	struct { uint64_t rva, len; } ach[KGENOME_EMU_UNP_PE_RUN_CHUNKS];
	unsigned n_ach = 0;

	if (!e || !info || !info->valid || !info->sec_count || !out || !out_len)
		return 0;

	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &info->sec[i];
		uint64_t end = (s->mem_rva + s->mem_size + KGENOME_EMU_PAGE - 1u) &
			       ~(uint64_t)(KGENOME_EMU_PAGE - 1u);

		if (!hdr || s->mem_rva < hdr)
			hdr = s->mem_rva;
		if (end > total)
			total = end;
	}
	if (hdr < KGENOME_EMU_PAGE)
		hdr = KGENOME_EMU_PAGE;
	hdr &= ~(uint64_t)(KGENOME_EMU_PAGE - 1u);

	/*
	 * MEMORY THE RUN ALLOCATED IS PART OF THE IMAGE, as a section of its
	 * own. Unipacker's imagedump.py does exactly this - chunk_to_image_
	 * section_hdr names them .ach0, .ach1 ... and gives each the chunk's
	 * address as both VirtualAddress and PointerToRawData - and its
	 * dump_image takes SizeOfImage from the highest chunk rather than from
	 * the section table. See THIRD-PARTY.md.
	 *
	 * BOUNDED BY cap, WHICH UNIPACKER DOES NOT DO. A stub that allocates at
	 * 0x20000000 from a base of 0x400000 describes an image half a gigabyte
	 * long, nearly all of it a hole - measured, that is what a PECompact2
	 * sample does. Such a chunk is left out here and still comes back on
	 * its own, as one of the regions the snapshot loop hands over: the
	 * bytes are never lost, they just do not get a section header.
	 */
	for (it = 0; kgenome_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		uint64_t rva, end;
		int is_sec = 0;

		if (va < base || !len)
			continue;
		rva = va - base;
		for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++)
			if (rva == info->sec[i].mem_rva) {
				is_sec = 1;
				break;
			}
		if (is_sec || rva < total)
			continue;
		end = (rva + len + KGENOME_EMU_PAGE - 1u) &
		      ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		if (end > cap)
			continue;
		if (n_ach >= KGENOME_EMU_UNP_PE_RUN_CHUNKS)
			break;
		ach[n_ach].rva = rva;
		ach[n_ach].len = len;
		n_ach++;
		if (end > total)
			total = end;
	}

	opt = info->pe32_plus ? 0xf0u : 0xe0u;
	nrva = info->pe32_plus ? 108u : 92u;
	sec_at = pe_off + 24u + opt;
	if (!total || total > cap ||
	    sec_at + 40u * (info->sec_count + n_ach) > hdr)
		return 0;

	b = calloc(1, (size_t)total);
	if (!b)
		return 0;

	/*
	 * THE SECTIONS, READ STRAIGHT OUT OF GUEST MEMORY.
	 *
	 * Not from the snapshot set, which is memory the run made executable.
	 * A stub that decrypts INTO pages that were already executable - which
	 * is what a packed image's own sections are - never calls mprotect and
	 * so takes no snapshot, and measured on an MPRESS sample the whole
	 * snapshot set was twelve kilobytes of scratch while the decrypted
	 * program sat in the image where it had always been.
	 *
	 * Unipacker's imagedump.py does exactly this: `pe_write(uc, base_addr,
	 * total_size, path)` reads the image range out of the emulator. See
	 * THIRD-PARTY.md. The snapshot pass below still runs, for a section the
	 * guest relocated somewhere else.
	 */
	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *sc = &info->sec[i];
		uint64_t n = sc->mem_size, at;

		if (!n || sc->mem_rva >= total)
			continue;
		if (n > total - sc->mem_rva)
			n = total - sc->mem_rva;
		for (at = 0; at < n; at += KGENOME_EMU_PAGE) {
			uint64_t k = n - at < KGENOME_EMU_PAGE ? n - at : KGENOME_EMU_PAGE;

			/* A page at a time, because an image may be mapped
			 * with holes and one unreadable page must not lose
			 * the rest of the section. */
			if (kgenome_emu_read(e, base + sc->mem_rva + at,
					 b + sc->mem_rva + at, (unsigned)k))
				placed++;
		}
	}

	/* The regions that ARE sections, each at its own address. */
	for (it = 0; kgenome_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		if (va < base)
			continue;
		for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
			const struct kgenome_pe_sec *s = &info->sec[i];
			uint64_t rva = va - base, n = len;

			if (rva != s->mem_rva)
				continue;
			if (rva >= total)
				break;
			if (n > total - rva)
				n = total - rva;
			memcpy(b + rva, bytes, (size_t)n);
			placed++;
			break;
		}
	}
	for (it = 0; kgenome_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		for (i = 0; i < n_ach; i++) {
			uint64_t n = len;

			if (va < base || va - base != ach[i].rva)
				continue;
			if (n > total - ach[i].rva)
				n = total - ach[i].rva;
			memcpy(b + ach[i].rva, bytes, (size_t)n);
			placed++;
			break;
		}
	}
	if (!placed) {
		free(b);
		return 0;
	}

	b[0] = 'M'; b[1] = 'Z';
	kof_st_le32(b + 0x3c, pe_off);
	b[pe_off] = 'P'; b[pe_off + 1] = 'E';
	kof_st_le16(b + pe_off + 4u, info->machine);
	kof_st_le16(b + pe_off + 6u, (uint16_t)((unsigned)info->sec_count + n_ach));
	kof_st_le16(b + pe_off + 20u, (uint16_t)opt);
	kof_st_le16(b + pe_off + 22u, info->pe32_plus ? 0x0022u : 0x0102u);

	o = b + pe_off + 24u;
	kof_st_le16(o, info->pe32_plus ? 0x020bu : 0x010bu);
	/*
	 * THE ENTRY POINT IS WHERE THE RUN FIRST LEFT THE STUB, not the entry
	 * point in the file - that one is the stub's. Both Unipacker
	 * (imagedump.py: AddressOfEntryPoint = EIP at dump time) and Unlicense
	 * (dump_pe's oep argument) write the dumped address, and section
	 * hopping is where Unipacker takes it. See THIRD-PARTY.md.
	 *
	 * If the run never hopped, nothing here knows the original entry, and 0
	 * says exactly that rather than pointing at the stub.
	 */
	{
		uint64_t last = 0;
		uint32_t hops = 0;

		kgenome_emu_first_hop(e, NULL, &oep);
		kgenome_emu_last_hop(e, &last, &hops);
		if (last >= base && last - base < total)
			oep = last;
		KOF_TRACE("[oep] hops=%u first=%#llx last=%#llx\n",
				hops, (unsigned long long)oep,
				(unsigned long long)last);
	}
	if (oep >= base && oep - base < total)
		oep_rva = oep - base;
	kof_st_le32(o + 16u, (uint32_t)oep_rva);
	kof_st_le32(o + 20u, (uint32_t)hdr);
	if (info->pe32_plus) {
		kof_st_le32(o + 24u, (uint32_t)info->image_base);
		kof_st_le32(o + 28u, (uint32_t)(info->image_base >> 32));
	} else {
		kof_st_le32(o + 28u, (uint32_t)info->image_base);
	}
	kof_st_le32(o + 32u, KGENOME_EMU_PAGE);
	kof_st_le32(o + 36u, KGENOME_EMU_PAGE);
	kof_st_le16(o + 40u, 6u);
	kof_st_le16(o + 48u, 6u);
	kof_st_le32(o + 56u, (uint32_t)total);
	kof_st_le32(o + 60u, (uint32_t)hdr);
	kof_st_le16(o + 68u, info->subsystem);
	kof_st_le32(o + nrva, 16u);

	sec = b + sec_at;
	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &info->sec[i];
		uint64_t span = (s->mem_size + KGENOME_EMU_PAGE - 1u) &
				~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint8_t *d = sec + 40u * i;
		unsigned k;

		for (k = 0; k < 8u; k++)
			d[k] = (uint8_t)s->name[k];
		kof_st_le32(d + 8u,  (uint32_t)s->mem_size);
		kof_st_le32(d + 12u, (uint32_t)s->mem_rva);
		kof_st_le32(d + 16u, (uint32_t)span);
		kof_st_le32(d + 20u, (uint32_t)s->mem_rva);
		kof_st_le32(d + 36u, s->characteristics | 0x40000000u);
	}
	for (i = 0; i < n_ach; i++) {
		uint64_t span = (ach[i].len + KGENOME_EMU_PAGE - 1u) &
				~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint8_t *d = sec + 40u * (info->sec_count + i);

		memcpy(d, ".ach", 4);
		d[4] = (uint8_t)('0' + (i % 10u));
		kof_st_le32(d + 8u,  (uint32_t)ach[i].len);
		kof_st_le32(d + 12u, (uint32_t)ach[i].rva);
		kof_st_le32(d + 16u, (uint32_t)span);
		kof_st_le32(d + 20u, (uint32_t)ach[i].rva);
		kof_st_le32(d + 36u, 0xe0000020u);
	}

	*out = b;
	*out_len = total;
	return 1;
}
