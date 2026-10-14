#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_map.c - laying an executable's image into the emulator, the part every format shares.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and
 * emu_unpack_private.h for what the files share.
 *
 * ONE LOADER, WITH THE FORMAT'S POLICY PASSED IN. An ELF's segments and a PE's
 * sections are the same job - map an extent at its address, remember which
 * addresses hold REAL FILE BYTES (a mapped span past them is zero fill), remember
 * the lowest address and the lowest executable one, and fall back to the whole
 * file mapped flat when the headers gave nothing to map - and the two images
 * had written it twice, down to the same entry-point rules. What differs is
 * said by a parameter: whether an extent that starts past the file is skipped or
 * mapped as zero fill, how far into an executable extent code can start, and
 * whether a flat map counts as file bytes throughout.
 */

#include "emu_unpack_private.h"

void kgenome_emu_unp_map_init(struct kgenome_emu_unp_map *m, uint64_t base_lo)
{
	memset(m, 0, sizeof *m);
	m->base_lo = base_lo;
}

int kgenome_emu_unp_map_extent(struct kgenome_emu *e, struct kgenome_emu_unp_map *m,
			       const uint8_t *file, uint64_t n,
			       struct kgenome_emu_unp_extent *x)
{
	uint64_t fsz = x->file_size, msz;

	if (x->off >= n) {
		if (x->skip_past_end)
			return 0;              /* declared past the file's end */
		fsz = 0;
	} else if (fsz > n - x->off) {
		fsz = n - x->off;              /* truncated: map what exists */
	}
	x->file_size = fsz;
	msz = x->mem_size > fsz ? x->mem_size : fsz;
	if (!msz)
		return 0;
	if (!(m->borrow ? kgenome_emu_map_borrow : kgenome_emu_map)(e, x->va, fsz ? file + x->off : NULL, fsz, msz, x->perm))
		return 0;
	m->mapped++;
	if (fsz && m->n_back < KGENOME_EMU_UNP_BACK_MAX) {
		m->back_lo[m->n_back] = x->va;
		m->back_hi[m->n_back] = x->va + fsz;
		m->n_back++;
	}
	if (x->va < m->base_lo)
		m->base_lo = x->va;
	if (x->code && (!m->lowest_x || x->va < m->lowest_x))
		m->lowest_x = x->va + x->code_skip;
	return 1;
}

/*
 * THE FAIL-SAFE: nothing could be mapped from the header.
 *
 * The object still has bytes and they still mean something - a packer that
 * overwrote its own header table did not overwrite its stub. Mapping the file
 * flat at a plausible base is what is left, and it is right often enough to be
 * worth doing: the addresses inside a self-contained stub are relative to where
 * it finds itself, which is exactly what a flat map preserves.
 */
int kgenome_emu_unp_map_flat(struct kgenome_emu *e, struct kgenome_emu_unp_map *m,
			     uint64_t at, const uint8_t *file, uint64_t n)
{
	if (!(m->borrow ? kgenome_emu_map_borrow : kgenome_emu_map)(e, at, file, n, n,
			     KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X))
		return 0;
	m->base_lo = at;
	m->lowest_x = at;
	m->improvised = 1;
	m->flat = 1;
	m->back_lo[0] = at;
	m->back_hi[0] = at + n;
	m->n_back = 1;
	return 1;
}

/*
 * WHERE TO START, in order of how much the file is trusted for it.
 *
 * `declared` is the entry the header names, already placed (0 for none). It
 * has to be ON BYTES THE FILE ACTUALLY HOLDS, and being mapped is not that: a
 * truncated object still has every address its header declares - the mapped
 * span covers them - so the declared entry reads back as sixteen zero bytes and
 * decodes as "add [rax], al". That is what a truncated UPX sample looks like
 * from here, and it is the common case rather than a corner: the UPX stub sits
 * PAST the compressed data, so a file cut short is a file whose entry point is
 * exactly the part that is missing. Refusing says the true thing - the code that
 * would have unpacked it is not present - and it is a fact about the FILE; the
 * static unpacker still recovers what the file does hold.
 *
 * `flat_is_backed` is the format's word on a flat map: an ELF's counts as file
 * bytes throughout, so any entry passes; a PE's is held to the range it mapped.
 *
 * A readable header that declares NO entry is a STATEMENT, not a gap, and
 * guessing past it would substitute a worse fact: only a header that could not
 * be read at all (m->improvised) earns the guess - the lowest executable
 * address, else the lowest one. `no_entry` is the sentence for the refusal.
 * Returns 0 with rep->refused set when the run is not worth starting.
 */
int kgenome_emu_unp_map_entry(struct kgenome_emu_unp_map *m, uint64_t declared,
			      int flat_is_backed, const char *no_entry,
			      struct kgenome_emu_unp_report *rep, uint64_t *out)
{
	uint64_t entry = declared;
	uint32_t i;

	if (entry) {
		int backed = flat_is_backed && m->flat;

		for (i = 0; !backed && i < m->n_back; i++)
			if (entry >= m->back_lo[i] && entry < m->back_hi[i])
				backed = 1;
		if (!backed) {
			if (rep)
				rep->refused = "the entry point is past the "
					       "bytes the file actually holds";
			return 0;
		}
	} else {
		if (!m->improvised) {
			if (rep)
				rep->refused = no_entry;
			return 0;
		}
		entry = m->lowest_x ? m->lowest_x : m->base_lo;
		m->improvised = 1;
	}
	*out = entry;
	return 1;
}
