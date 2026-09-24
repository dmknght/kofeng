/*
 * pzero.c - see pzero.h for why this stage exists and what it may not do.
 */
#include <string.h>

#include "pzero.h"
#include "../kofeng.h"
#include "../kofcore/kofmod/kofsig.h"
#include "../kofcore/kofmod/elf.h"
#include "../kofcore/kofmod/pe.h"
#include "../analyzer/parsers/binaries/elf_parse.h"

uint64_t kof_pz_clean_end(const struct kof_obj_ctx *ctx)
{
	struct kof_range r[KOF_MAX_REGIONS];
	uint64_t end = 0;
	uint32_t n, i;

	if (!ctx || !ctx->resolve_scan)
		return KOF_BROKEN;
	/*
	 * EVERY REGION THE PARSE CLAIMS, and not the section table alone.
	 *
	 * A stripped object has no sections and still has segments; asking
	 * the region resolver covers both without this dispatching on format,
	 * which is the same reason a module never touches a parser directly.
	 */
	n = ctx->resolve_scan(ctx, KOF_SCAN_ALL, r, KOF_MAX_REGIONS);
	if (!n)
		return KOF_BROKEN;
	for (i = 0; i < n; i++) {
		uint64_t e = r[i].off + r[i].len;

		/* A region running past the object is a parse of a hostile
		 * file, not a place to cut. */
		if (r[i].off > ctx->obj_size || e < r[i].off ||
		    e > ctx->obj_size)
			continue;
		if (e > end)
			end = e;
	}
	return end ? end : KOF_BROKEN;
}

int kof_pz_is_code(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint32_t mask;
	struct kof_range r[KOF_MAX_REGIONS];
	uint32_t n, i;

	if (!ctx || !ctx->resolve_scan || off >= ctx->obj_size)
		return 0;
	/*
	 * THE EXECUTABLE REGION, NAMED PER FORMAT because the bit is the
	 * format's own - see the note in elf.h on why the values collide
	 * between formats and why that is safe when the format is tested
	 * first.
	 */
	if (ctx->format == KOF_FMT_ELF)
		mask = KOF_SCAN_ELF_CODE;
	else if (ctx->format == KOF_FMT_PE)
		mask = KOF_SCAN_PE_CODE;
	else
		return 0;
	n = ctx->resolve_scan(ctx, mask, r, KOF_MAX_REGIONS);
	for (i = 0; i < n; i++)
		if (off >= r[i].off && off - r[i].off < r[i].len)
			return 1;
	return 0;
}

uint64_t kof_pz_addr_to_off(const struct kof_obj_ctx *ctx, uint64_t addr)
{
	if (!ctx || !ctx->file_header)
		return KOF_BROKEN;
	if (ctx->format == KOF_FMT_PE) {
		const struct kof_pe_info *p = kof_pe(ctx);

		/* PE stores an RVA, so the image base comes off first when the
		 * caller handed over a virtual address. */
		if (addr >= p->image_base)
			addr -= p->image_base;
		return kof_pe_rva_to_off(p, addr);
	}
	if (ctx->format == KOF_FMT_ELF) {
		const struct kof_elf_info *e = kof_elf(ctx);
		uint32_t i;

		/*
		 * THE SEGMENT AND NOT THE SECTION.
		 *
		 * A saved entry point is an address that must be mapped, and
		 * what maps is PT_LOAD. A stripped file has no sections at
		 * all and is exactly the file a cure is most often asked
		 * about.
		 */
		for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
			const struct kof_elf_seg *s = &e->seg[i];

			if (s->type != KOF_ELF_PT_LOAD || !s->file_size)
				continue;
			if (addr >= s->mem_addr &&
			    addr - s->mem_addr < s->file_size)
				return s->file_off + (addr - s->mem_addr);
		}
	}
	return KOF_BROKEN;
}

uint32_t kof_pz_unmask(const uint8_t *in, uint32_t n, uint32_t mask,
		       uint32_t key, uint8_t *out, uint32_t cap)
{
	uint32_t i, w = n < cap ? n : cap;

	if (!in || !out || !n)
		return 0;
	switch (mask) {
	case KOF_PZ_MASK_NONE:
		memcpy(out, in, w);
		return w;
	case KOF_PZ_MASK_XOR8:
		for (i = 0; i < w; i++)
			out[i] = (uint8_t)(in[i] ^ (uint8_t)key);
		return w;
	case KOF_PZ_MASK_XOR16:
		/* The low byte masks the even positions, the high byte the
		 * odd ones - which is what a word xor does to a byte string
		 * on a little endian machine, and every host these cures were
		 * written for is one. */
		for (i = 0; i < w; i++)
			out[i] = (uint8_t)(in[i] ^
				 (uint8_t)(i & 1u ? key >> 8 : key));
		return w;
	case KOF_PZ_MASK_ADD8:
		/* Decoding ADDS, so the infector subtracted - the same
		 * direction kof_codec_run reads one. */
		for (i = 0; i < w; i++)
			out[i] = (uint8_t)(in[i] + (uint8_t)key);
		return w;
	case KOF_PZ_MASK_ROL8: {
		uint32_t k = key & 7u;

		if (!k)
			return 0;       /* a rotate of nothing is not a mask */
		for (i = 0; i < w; i++)
			out[i] = (uint8_t)((in[i] << k) |
					   (in[i] >> (8u - k)));
		return w;
	}
	default:
		return 0;
	}
}

uint32_t kof_pz_pe_checksum(const uint8_t *p, uint64_t n, uint64_t csum_off)
{
	uint64_t i;
	uint32_t sum = 0;

	if (!p || !n)
		return 0;
	/*
	 * THE FIELD READS ZERO WHILE THE SUM IS TAKEN, and it is skipped here
	 * rather than zeroed in the buffer: this stage does not write to the
	 * object it was handed. csum_off past the end means "no field", which
	 * is what a caller checksumming something that is not a PE wants.
	 */
	for (i = 0; i + 1u < n; i += 2u) {
		uint32_t w = (uint32_t)p[i] | ((uint32_t)p[i + 1u] << 8);

		if (csum_off < n && i + 1u >= csum_off && i < csum_off + 4u)
			w = 0;
		sum += w;
		sum = (sum & 0xffffu) + (sum >> 16);
	}
	if (n & 1u) {
		sum += p[n - 1u];
		sum = (sum & 0xffffu) + (sum >> 16);
	}
	sum = (sum & 0xffffu) + (sum >> 16);
	return sum + (uint32_t)n;
}
