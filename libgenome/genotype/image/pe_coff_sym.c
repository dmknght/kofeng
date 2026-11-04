/*
 * pe_coff_sym.c - the one walk of a PE's own COFF symbol table.
 *
 * fntab_pe_coff.c's header comment has the record layout (the file header's
 * PointerToSymbolTable/NumberOfSymbols, 18-byte records, the aux-record skip,
 * the END rule). This file is that SAME table, walked once, for the two
 * callers that each need a different slice of it: the function-boundary
 * strategy (kgenome_fntab_pe_coff, which wants off/value/shndx/size and
 * nothing of the name) and the engine's KSYM builder
 * (kof_pe_syms_with/pe_sym.c, which wants the NAME too, to put on the
 * function the boundary strategy already placed). Before this file the two
 * would have had to re-derive the bounds-checking of the same table
 * separately - exactly what rule 2 of kofeng/CLAUDE.md is against.
 *
 * THE NAME. Name[8] holds it inline when it is 8 bytes or fewer - the field
 * is not necessarily NUL-terminated, it may be full. Otherwise Name[0..3] is
 * zero and Name[4..7] is a byte offset into the string table, which follows
 * the symbol table at PointerToSymbolTable + NumberOfSymbols*18 - the
 * DECLARED count, because that is the file FORMAT's own placement rule, not
 * the (possibly smaller) count this walk actually visits when the file is
 * short. The string table's own first four bytes are its total size,
 * including itself; a name is read to the first NUL or the table's declared
 * end, whichever comes first, bounded throughout against `file.n` - an
 * offset at or past the table's end, or a string table that does not fit in
 * the file, answers the empty name rather than reading on.
 *
 * `name`/`name_len` point INTO `file` (never copied): a name is not
 * NUL-terminated by this walk (the inline case cannot promise one, so
 * neither case does, for one contract) and is valid only for the duration of
 * the callback - exactly as kgenome_pe_exports hands a caller `nameoff` into
 * the same buffer rather than a copy, for the same reason (a table of many
 * names would otherwise be a table of copies of bytes the caller already
 * has).
 *
 * HOSTILE INPUT, mirrored from fntab_pe_coff.c's own discipline for this
 * table: the record count is bounded by what the file holds; a section
 * number outside the table, a section that is not executable, a Value past
 * the section's raw bytes, and a TotalSize past them are counted in
 * `*n_bad` and not reported to `fn`; the loop advances at least one record a
 * step whatever NumberOfAuxSymbols claims.
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"

/* The inline Name[8]: up to 8 bytes, stopping at the first NUL if there is
 * one inside the field. Never past the record, which the caller already
 * bounds-checked. */
static uint32_t coff_name_inline(const uint8_t *namefield, const char **out)
{
	uint32_t i;

	*out = (const char *)namefield;
	for (i = 0; i < 8u && namefield[i]; i++)
		;
	return i;
}

/*
 * The string-table name at offset `so` (from the table's own start, per the
 * format): `*out` points at it directly; the length is bounded by the
 * table's own declared size (its first 4 bytes) AND by `file.n`, whichever
 * ends it first. 0 (and `*out` left untouched) when `so` or the table itself
 * does not lie inside the file - the empty name, not a read past either
 * bound.
 */
static uint32_t coff_name_strtab(kof_buf file, uint64_t strtab_off, uint32_t so,
				 const char **out)
{
	uint32_t tabsize, i;
	uint64_t at;

	if (so < 4u || strtab_off + 4u > file.n)
		return 0;
	tabsize = (uint32_t)file.p[strtab_off] |
		  ((uint32_t)file.p[strtab_off + 1u] << 8) |
		  ((uint32_t)file.p[strtab_off + 2u] << 16) |
		  ((uint32_t)file.p[strtab_off + 3u] << 24);
	if (so >= tabsize)
		return 0;
	at = strtab_off + so;
	if (at >= file.n)
		return 0;
	*out = (const char *)file.p + at;
	for (i = 0; so + i < tabsize && at + i < file.n && file.p[at + i]; i++)
		;
	return i;
}

void kgenome_pe_coff_syms(kof_buf file, const struct kgenome_pe_info *p,
			  kgenome_pe_coff_sym_fn fn, void *user, uint32_t *n_bad)
{
	uint32_t at, cnt;
	uint64_t n, i, strtab_off;

	if (n_bad)
		*n_bad = 0;
	if (!fn || !file.p || !p || !p->valid || p->layout != KGENOME_PE_LAYOUT_FILE)
		return;
	if (!kof_rd_u32(file, p->lfanew + 12u, 0, &at) ||
	    !kof_rd_u32(file, p->lfanew + 16u, 0, &cnt) || !at || !cnt || at >= file.n)
		return;
	n = cnt;
	if (n > (file.n - at) / 18u)
		n = (file.n - at) / 18u;
	/* The DECLARED count, not the clamped `n`: a short file still places the
	 * string table where an honest one would be, and a wrong guess here
	 * would read whatever bytes happen to sit after the records this walk
	 * actually visited. */
	strtab_off = (uint64_t)at + (uint64_t)cnt * 18u;

	for (i = 0; i < n;) {
		const uint8_t *r = file.p + at + i * 18u;
		uint32_t val;
		uint16_t type;
		int16_t sn;
		uint8_t cls, naux;
		const struct kgenome_pe_sec *s;
		struct kgenome_pe_coff_sym out;
		uint64_t aux_len = 0;
		int has_size = 0;

		memcpy(&val, r + 8, 4);
		memcpy(&sn, r + 12, 2);
		memcpy(&type, r + 14, 2);
		cls = r[16];
		naux = r[17];
		i += 1u + naux;
		if (type != 0x20u || (cls != 2u && cls != 3u) || sn <= 0)
			continue;
		if ((uint32_t)sn > p->sec_count) {
			if (n_bad)
				(*n_bad)++;
			continue;
		}
		s = &p->sec[sn - 1];
		if (!kgenome_pe_sec_is_code(s) || val >= s->file_size ||
		    s->file_off >= file.n || val >= file.n - s->file_off) {
			if (n_bad)
				(*n_bad)++;
			continue;
		}
		if (naux >= 1u && i <= n) {   /* the aux record is inside what the file holds */
			uint32_t tot;

			memcpy(&tot, r + 18 + 4, 4);
			aux_len = tot;
		}
		if (aux_len && aux_len <= s->file_size - val &&
		    s->file_off + val + aux_len <= file.n) {
			has_size = 1;
		} else if (aux_len) {
			if (n_bad)      /* a size that does not lie in the section: the symbol stays, without one */
				(*n_bad)++;
			aux_len = 0;
		}
		memset(&out, 0, sizeof out);
		out.off = s->file_off + val;
		out.value = val;
		out.shndx = (uint16_t)sn;
		out.cls = cls;
		out.has_size = (uint8_t)has_size;
		out.size = has_size ? aux_len : 0;
		if (r[0] | r[1] | r[2] | r[3])
			out.name_len = coff_name_inline(r, &out.name);
		else {
			uint32_t so;

			memcpy(&so, r + 4, 4);
			out.name_len = coff_name_strtab(file, strtab_off, so, &out.name);
		}
		if (!fn(user, &out))
			return;
	}
}
