/*
 * fntab_elf_gopcln.c - the Go function-table strategy of the ELF function table: .gopclntab, the table the Go runtime itself searches to map a PC to its function
 * (stack traces, the garbage collector's stack maps). It survives `strip`, and Go emits no .eh_frame of its own, so for a stripped Go binary it is the one exact source
 * (meta_survey/bazaar.txt, 2026-11-16: 375 of the ELF files carry it).
 *
 * THE FORMAT (the Go runtime's runtime/symtab.go, `pcHeader` and `functab`), by the magic at the start of the section:
 *   0xfffffffb  Go 1.2 .. 1.15  u32 magic, u8 0, u8 0, u8 quantum, u8 ptrsize; at 8: nfunc (ptrsize); at 8+ptrsize: nfunc rows of (entry, funcoff), both ptrsize, then the
 *                               final entry (ptrsize). Entries are addresses.
 *   0xfffffffa  Go 1.16 .. 1.17 the header holds nfunc at 8 and, 6 words further (8 + 6*ptrsize), pclnOffset: the rows (entry, funcoff, ptrsize each) start there; addresses.
 *   0xfffffff0  Go 1.18 .. 1.19 nfunc at 8, textStart at 8 + 2*ptrsize, pclnOffset at 8 + 7*ptrsize; the rows are (entryoff, funcoff) of 4 bytes each, then the final
 *   0xfffffff1  Go 1.20 ..      entryoff: an entry is textStart + entryoff. A position-independent build leaves textStart 0 in the file (a relocation fills it): the start of
 *                               .text stands for it, which is what the runtime's moduledata.text is.
 * Row i covers [entry i, entry i+1) - the function and the padding behind it, which is the range the runtime looks a PC up in - so the END is the next row's entry
 * (end_source PCTAB, exact by the format) and the last row ends at the final entry.
 *
 * HOSTILE INPUT: nfunc is bounded by what the section holds (the rows and the final entry must fit); entries must rise strictly (a row that does not is refused and counted,
 * out->n_bad; the next is read against the last accepted entry); a start or end outside one executable, file-backed segment is refused and counted; an unknown magic, a
 * pointer size other than 4 or 8, or offsets that leave the section read nothing. The list's own cap is reported (P_CAP).
 * NOT READ (limit): a PE's Go table (no section names it: the runtime finds it through a symbol that a stripped PE does not keep); NEXT: the moduledata the PE's .data holds.
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/elf_types.h>
#include "elf_image.h"
#include "fntab_private.h"

static int rd_w(kof_buf f, uint64_t off, unsigned w, int be, uint64_t *v)
{
	uint32_t x;

	if (w == 8u)
		return kof_rd_u64(f, off, be, v);
	if (!kof_rd_u32(f, off, be, &x))
		return 0;
	*v = x;
	return 1;
}

void kgenome_fntab_gopcln(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out)
{
	uint32_t k, magic;
	uint64_t at, n, nfunc = 0, rows, text = 0, prev = 0, i;
	unsigned w, row, ew;
	int be, have_prev = 0;
	kof_buf t;

	if (!file.p || !e || !e->valid || !out || e->e_type == KGENOME_ELF_REL)
		return;
	if (!kgenome_fntab_elf_section(e, KGENOME_ELF_SHT_PROGBITS, ".gopclntab", &k) || e->sec[k].file_off >= file.n)
		return;
	at = e->sec[k].file_off;
	n = e->sec[k].file_size < file.n - at ? e->sec[k].file_size : file.n - at;
	t = kof_buf_make(file.p + at, n);
	be = e->elf_data == KGENOME_ELFDATA_BE;
	if (n < 16u || !kof_rd_u32(t, 0, be, &magic) || t.p[4] || t.p[5])
		return;
	w = t.p[7];
	if (w != 4u && w != 8u)
		return;
	if (!rd_w(t, 8u, w, be, &nfunc))
		return;
	if (magic == 0xfffffffbu) {
		rows = 8u + w;
		row = 2u * w;
		ew = w;
	} else if (magic == 0xfffffffau) {
		if (!rd_w(t, 8u + 6u * w, w, be, &rows))
			return;
		row = 2u * w;
		ew = w;
	} else if (magic == 0xfffffff0u || magic == 0xfffffff1u) {
		if (!rd_w(t, 8u + 7u * w, w, be, &rows) || !rd_w(t, 8u + 2u * w, w, be, &text))
			return;
		if (!text) {
			uint32_t x;

			if (!kgenome_fntab_elf_section(e, KGENOME_ELF_SHT_PROGBITS, ".text", &x))
				return;
			text = e->sec[x].mem_addr;
		}
		row = 8u;
		ew = 4u;
	} else {
		return;
	}
	if (rows >= n || nfunc > (n - rows - ew) / row)
		return;
	for (i = 0; i <= nfunc; i++) {
		uint64_t ent;

		if (!rd_w(t, rows + i * row, ew, be, &ent))
			break;
		if (ew == 4u && w == 8u)
			ent += text;
		else if (ew == 4u)
			ent = (ent + text) & 0xffffffffu;
		if (have_prev) {
			uint64_t off, endoff;   /* endoff: the whole row must lie in one file-backed segment (va_to_off refuses a range that leaves it) */
			struct kgenome_func f;

			if (ent <= prev) {
				out->n_bad++;           /* not rising: refused, the last accepted entry stands */
				continue;
			}
			if (!kgenome_fntab_elf_code_va(e, prev, &off) || !kgenome_elf_va_to_off(e, prev, ent - prev, &endoff)) {
				out->n_bad++;
			} else {
				memset(&f, 0, sizeof f);
				f.off = off;
				f.len = ent - prev;
				f.source = KGENOME_FN_S_GOPCLN;
				f.end_source = KGENOME_FN_E_PCTAB;
				if (!kgenome_fntab_list_add(out, &f))
					return;
			}
		}
		prev = ent;
		have_prev = 1;
	}
}
