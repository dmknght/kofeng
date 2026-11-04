/*
 * fntab_fde.c - the unwind-table strategy of the function table: start AND length of every FDE of .eh_frame.
 *
 * WHY IT IS A CASE OF ITS OWN. A symbol table is gone from a stripped file, the unwind table is not (the runtime needs it): measured on the
 * 711-file oracle corpus (exp_fnsize/work/fde_table.md, agent-reported) .eh_frame gives start and length equal to the symbol table's for 93.8% of
 * the x86-64 functions and 89.4% of AArch64 ones, and the length agrees in 99.98% where the starts do. i386, PowerPC and MIPS carry far fewer
 * FDEs (8.9-19.5%): what they carry is exact all the same, and the walk strategy names the rest. The strategy reads FACTS, no guess:
 * a record is taken only when it validates, and a record it cannot take is COUNTED (list->n_bad, KGENOME_FNTAB_P_BAD_FDE), never followed.
 *
 * THE FORMAT, as far as this reads it (LSB / DWARF .eh_frame): a record is `u32 length` (0 ends the table; 0xffffffff means a u64
 * length follows), `u32 id`, body. id 0 is a CIE; otherwise it is an FDE and `id` is how far back from the id field its CIE starts.
 * A CIE gives the encoding of the addresses of its FDEs (augmentation 'R'); an FDE gives pc_begin (in that encoding, usually pcrel) and
 * pc_range (the same format, never relative).
 *
 * HOSTILE INPUT: the loop advances at least 8 bytes a record and stops at the section's end, so it is bounded by the section's size; the
 * CIE table holds KGENOME_FDE_CIE_MAX entries (a CIE past it is counted and an FDE that names it is refused, so nothing is silently
 * wrong); a CIE pointer that lands anywhere but on a CIE seen is refused; a range must lie inside ONE file-backed executable segment
 * (kgenome_elf_va_to_off) and overlapping ranges are refused (the first stands). An object file (ET_REL) has no unwind addresses (they are
 * relocations): the strategy answers nothing for it.
 */
#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <genotype/image/elf_types.h>
#include "elf_image.h"
#include "fntab_private.h"

#define KGENOME_FDE_CIE_MAX 65536u

struct cie { uint64_t pos; int enc; };   /* enc < 0: the CIE is one this reads not (version, augmentation) */

struct rd {
	const uint8_t *p;
	uint64_t n;         /* bytes of the section */
	int be;
	int wide;           /* ELFCLASS64: an absolute address is 8 bytes */
};

static int rd_u(const struct rd *r, uint64_t pos, unsigned w, uint64_t *v)
{
	uint64_t x = 0;
	unsigned i;

	if (pos > r->n || w > r->n - pos)
		return 0;
	for (i = 0; i < w; i++)
		x |= (uint64_t)r->p[pos + (r->be ? w - 1u - i : i)] << (8u * i);
	*v = x;
	return 1;
}

static int rd_uleb(const struct rd *r, uint64_t *pos, uint64_t end, uint64_t *v)
{
	uint64_t x = 0;
	unsigned sh = 0;

	while (*pos < end && *pos < r->n) {
		uint8_t b = r->p[(*pos)++];

		if (sh < 64)
			x |= (uint64_t)(b & 0x7fu) << sh;
		sh += 7u;
		if (!(b & 0x80u)) {
			*v = x;
			return 1;
		}
	}
	return 0;
}

static int rd_sleb(const struct rd *r, uint64_t *pos, uint64_t end, int64_t *v)
{
	uint64_t x = 0;
	unsigned sh = 0;

	while (*pos < end && *pos < r->n) {
		uint8_t b = r->p[(*pos)++];

		if (sh < 64)
			x |= (uint64_t)(b & 0x7fu) << sh;
		sh += 7u;
		if (!(b & 0x80u)) {
			if (sh < 64 && (b & 0x40u))
				x |= ~(uint64_t)0 << sh;
			*v = (int64_t)x;
			return 1;
		}
	}
	return 0;
}

/* The size in bytes of a fixed-width encoding format (DW_EH_PE_* low nibble); 0 for the variable ones and the ones not defined. */
static unsigned enc_width(const struct rd *r, int enc)
{
	switch (enc & 0x0f) {
	case 0x00: return r->wide ? 8u : 4u;
	case 0x02: case 0x0a: return 2u;
	case 0x03: case 0x0b: return 4u;
	case 0x04: case 0x0c: return 8u;
	}
	return 0;
}

/* One encoded value at `pos` (advancing it): the raw number, sign-extended for the signed formats. */
static int enc_read(const struct rd *r, uint64_t *pos, uint64_t end, int enc, uint64_t *v)
{
	unsigned w = enc_width(r, enc);
	uint64_t x;

	if (w) {
		if (*pos > end || w > end - *pos || !rd_u(r, *pos, w, &x))
			return 0;
		*pos += w;
		if ((enc & 0x08) && w < 8u && (x >> (8u * w - 1u) & 1u))      /* sdata2/4 */
			x |= ~(uint64_t)0 << (8u * w);
		*v = x;
		return 1;
	}
	if ((enc & 0x0f) == 0x01)
		return rd_uleb(r, pos, end, v);
	if ((enc & 0x0f) == 0x09) {
		int64_t s;

		if (!rd_sleb(r, pos, end, &s))
			return 0;
		*v = (uint64_t)s;
		return 1;
	}
	return 0;
}

/* The address encoding of a CIE's FDEs: the 'R' augmentation, 0 (absolute) without one; -1 when the CIE is not one this reads. */
static int cie_enc(const struct rd *r, uint64_t body, uint64_t end)
{
	uint64_t pos = body + 4u, v;
	int64_t sv;
	uint8_t ver;
	const char *aug;
	int enc = 0, i;
	uint64_t alen_end = 0;

	if (pos >= end)
		return -1;
	ver = r->p[pos++];
	if (ver != 1 && ver != 3)
		return -1;
	aug = (const char *)r->p + pos;
	while (pos < end && r->p[pos])
		pos++;
	if (pos >= end)
		return -1;
	pos++;
	if (aug[0] == 'e' && aug[1] == 'h') {                   /* the old GCC form: a pointer, which is not read */
		if (r->wide ? pos + 8u > end : pos + 4u > end)
			return -1;
		pos += r->wide ? 8u : 4u;
	}
	if (!rd_uleb(r, &pos, end, &v) || !rd_sleb(r, &pos, end, &sv))      /* code and data alignment */
		return -1;
	if (ver == 1) {
		if (pos >= end)
			return -1;
		pos++;                                           /* return address register */
	} else if (!rd_uleb(r, &pos, end, &v)) {
		return -1;
	}
	if (aug[0] != 'z')
		return aug[0] ? -1 : 0;                          /* an augmentation this does not know: its FDEs are not read */
	if (!rd_uleb(r, &pos, end, &v) || v > end - pos)
		return -1;
	alen_end = pos + v;
	for (i = 1; aug[i]; i++) {
		if (aug[i] == 'R') {
			if (pos >= alen_end)
				return -1;
			enc = r->p[pos++];
		} else if (aug[i] == 'L') {
			pos++;
		} else if (aug[i] == 'P') {
			uint64_t dummy;
			int penc;

			if (pos >= alen_end)
				return -1;
			penc = r->p[pos++];
			if (!enc_read(r, &pos, alen_end, penc & 0x7f, &dummy))
				return -1;
		} else if (aug[i] == 'S' || aug[i] == 'B') {
			/* signal frame, pointer authentication: no data */
		} else {
			break;                                   /* unknown: the data after it cannot be stepped over; R, if seen, stands */
		}
	}
	return enc;
}

static int cmp_fn(const void *a, const void *b)
{
	const struct kgenome_func *x = a, *y = b;

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	return x->len < y->len ? 1 : x->len > y->len ? -1 : 0;
}

/* The bytes and the address of the unwind table, or 0. */
static int eh_locate(kof_buf file, const struct kgenome_elf_info *e, struct rd *r, uint64_t *va)
{
	uint32_t i;
	uint64_t off, n;

	if (kgenome_fntab_eh_section(e, &i)) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if (s->file_off >= file.n)
			return 0;
		off = s->file_off;
		n = s->file_size < file.n - off ? s->file_size : file.n - off;
		*va = s->mem_addr;
	} else if (kgenome_fntab_eh_segment(e, &i)) {
		/* The search header: version, the encodings of three fields, then the address of .eh_frame. Without a section table
		 * the table's size is not told: it runs to the end of the segment that holds it, and its own terminator ends it. */
		const struct kgenome_elf_seg *g = &e->seg[i];
		struct rd h;
		uint64_t pos = 4u, v, hva, eva, eoff;
		const struct kgenome_elf_seg *host;
		int enc;

		if (g->file_off >= file.n)
			return 0;
		h.p = file.p + g->file_off;
		h.n = g->file_size < file.n - g->file_off ? g->file_size : file.n - g->file_off;
		h.be = e->elf_data == KGENOME_ELFDATA_BE;
		h.wide = e->elf_class == KGENOME_ELFCLASS_64;
		if (h.n < 8u || h.p[0] != 1u)
			return 0;
		enc = h.p[1];
		if ((enc & 0x70) != 0x10 && (enc & 0x70) != 0x00)       /* pcrel or absolute; the rest is not read */
			return 0;
		if (!enc_read(&h, &pos, h.n, enc & 0x8f, &v))
			return 0;
		hva = g->mem_addr + 4u;                                  /* the address of the field */
		eva = (enc & 0x70) == 0x10 ? hva + v : v;
		if (!kgenome_elf_va_to_off(e, eva, 1, &eoff) || eoff >= file.n)
			return 0;
		host = kgenome_elf_load_at_off(e, eoff);        /* never NULL: va_to_off answered with an offset inside the file half of a load segment, and that segment holds it */
		off = eoff;
		n = host->file_off + host->file_size - eoff;
		if (n > file.n - off)
			n = file.n - off;
		*va = eva;
	} else {
		return 0;
	}
	r->p = file.p + off;
	r->n = n;
	r->be = e->elf_data == KGENOME_ELFDATA_BE;
	r->wide = e->elf_class == KGENOME_ELFCLASS_64;
	return 1;
}

void kgenome_fntab_fde(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out)
{
	struct rd r;
	struct cie *cie = NULL;
	uint32_t n_cie = 0, cap_cie = 0, first = out->n, i, k;
	uint64_t pos = 0, eva = 0;

	if (!file.p || !e || !e->valid || e->e_type == KGENOME_ELF_REL)
		return;
	if (!eh_locate(file, e, &r, &eva))
		return;
	while (pos + 8u <= r.n) {
		uint64_t len, body, end, id = 0, fpos;
		unsigned hdr = 4u;

		if (!rd_u(&r, pos, 4u, &len))
			break;
		if (!len)
			break;                                  /* the terminator */
		if (len == 0xffffffffu) {
			if (!rd_u(&r, pos + 4u, 8u, &len))
				break;
			hdr = 12u;
		}
		body = pos + hdr;
		if (len < 4u || len > r.n - body) {
			out->n_bad++;                           /* a length past the section: the table ends here */
			out->partial |= KGENOME_FNTAB_P_BAD_FDE;
			break;
		}
		end = body + len;
		/* rd_u fails only for pos > n or w > n - pos; len >= 4 and body + len <= n were checked above, so body + 4 <= n and it always writes `id` (the initialiser is for the compiler: it cannot see that) */
		(void)rd_u(&r, body, 4u, &id);
		if (!id) {
			if (n_cie < KGENOME_FDE_CIE_MAX) {
				if (n_cie == cap_cie) {
					uint32_t nc = cap_cie ? cap_cie * 2u : 16u;
					struct cie *nv = realloc(cie, (size_t)nc * sizeof *nv);

					if (!nv) {
						out->status = KGENOME_NOMEM;
						goto done;
					}
					cie = nv;
					cap_cie = nc;
				}
				cie[n_cie].pos = pos;
				cie[n_cie].enc = cie_enc(&r, body, end);
				n_cie++;
			} else {
				out->n_bad++;                   /* a CIE past the table: the FDEs that name it are refused */
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
			}
		} else {
			uint64_t cpos, lo = 0, hi = n_cie, beg, rng, fva, foff, p2 = body + 4u;
			int enc, ok = 0;
			struct kgenome_func f;
			const struct kgenome_elf_seg *host;

			fpos = body;
			if (id > fpos) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				goto next;
			}
			cpos = fpos - id;
			while (lo < hi) {                       /* the CIEs are in ascending order of position */
				uint64_t mid = (lo + hi) / 2u;

				if (cie[mid].pos < cpos)
					lo = mid + 1u;
				else
					hi = mid;
			}
			if (lo >= n_cie || cie[lo].pos != cpos || cie[lo].enc < 0) {
				out->n_bad++;                   /* not a CIE seen, or one this does not read */
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				goto next;
			}
			enc = cie[lo].enc;
			if ((enc & 0x80) || (enc & 0x70 & ~0x10) || enc == 0xff || !(enc_width(&r, enc) || (enc & 0x0f) == 0x01 || (enc & 0x0f) == 0x09)) {
				out->n_bad++;                   /* indirect, datarel, textrel, omitted: not an address this reads */
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				goto next;
			}
			if (!enc_read(&r, &p2, end, enc & 0x0f, &beg) || !enc_read(&r, &p2, end, enc & 0x0f, &rng)) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				goto next;
			}
			if (enc & 0x10) {
				fva = eva + (body + 4u) + beg;          /* relative to the field's own address */
				if (!r.wide)
					fva &= 0xffffffffu;             /* an ELF32's sum is 32 bits: a table after the code is a negative delta, written pc-relative udata4 as 2^32 less (FNTAB-COV-2) */
			} else {
				fva = beg;
			}
			if (enc_width(&r, enc) && (enc & 0x08) && enc_width(&r, enc) < 8u)
				rng &= ((uint64_t)1 << (8u * enc_width(&r, enc))) - 1u;       /* a length is unsigned */
			if (!rng || !kgenome_elf_va_to_off(e, fva, rng, &foff)) {
				out->n_bad++;                   /* empty, or not inside one file-backed segment */
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				goto next;
			}
			host = kgenome_elf_load_at_off(e, foff);
			ok = host && kgenome_elf_seg_is_code(host) && !kgenome_fntab_in_stub_section(e, foff);
			if (!ok) {
				out->n_bad++;                   /* data, or a stub section (.plt: the linker's code, FNTAB-COV-3): not a function of the program's code */
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				goto next;
			}
			memset(&f, 0, sizeof f);
			f.off = foff;
			f.len = rng;
			f.value = fva;
			f.source = KGENOME_FN_S_FDE;
			f.end_source = KGENOME_FN_E_UNWIND;
			if (!kgenome_fntab_list_add(out, &f))
				goto done;
		}
next:
		pos = end;
	}
done:
	/* Sorted, overlap refused: the first range of a start stands, a range that begins inside the one before is counted. (After a refused allocation too: what was kept is sorted, FNTAB-COV-8.) */
	if (out->n > first) {
		uint64_t reach = 0;

		qsort(out->v + first, out->n - first, sizeof *out->v, cmp_fn);
		for (i = first, k = first; i < out->n; i++) {
			if (k > first && out->v[i].off < reach) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
			out->v[k++] = out->v[i];
			reach = out->v[i].off + out->v[i].len;
		}
		out->n = k;
	}
	free(cie);
}
