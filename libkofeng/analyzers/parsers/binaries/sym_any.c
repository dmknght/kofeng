/*
 * sym_any.c - the one place that decides WHICH symbol builder an object gets.
 *
 * ELF and PE each have their own, and both fill the single KSYM layout that
 * kofmod/kofsym.h fixes. The choice used to be made twice - once in the
 * scanner's content accessor and once in kofviewer - which is two places to
 * keep in step for a decision that has one right answer.
 */

#include <kofmod/kofsym.h>
#include "elf/elf_sym.h"
#include "pe/pe_sym.h"
#include "funcs.h"
#include <stdlib.h>
#include <string.h>

static uint32_t kof_syms_declared(uint32_t format, const uint8_t *data, uint64_t data_n,
			   const void *info);

static uint32_t kof_syms_build_with(uint32_t format, const uint8_t *data,
			     uint64_t data_n, const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t *out, uint32_t cap);

uint32_t kof_syms_build(uint32_t format, const uint8_t *data, uint64_t data_n,
			const void *info, uint8_t *out, uint32_t cap)
{
	return kof_syms_build_with(format, data, data_n, info, NULL, out, cap);
}

static uint32_t kof_syms_build_with(uint32_t format, const uint8_t *data,
			     uint64_t data_n, const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t *out, uint32_t cap)
{
	kof_buf b = kof_buf_make(data, data_n);

	if (!info || !out || cap < KOF_SYM_HDRLEN)
		return 0;
	if (format == KOF_FMT_ELF)
		return kof_elf_syms(b, info, out, cap);
	if (format == KOF_FMT_PE)
		return kof_pe_syms_with(b, info, imports, out, cap);
	/* Any other format has no symbols to give, which a reader takes as a
	 * count of zero - the same answer a stripped ELF gives. */
	return 0;
}


/*
 * THE BLOCK FOR AN OBJECT, SIZED BY THE TABLE IT HAS AND GROWN UNTIL IT FITS.
 *
 * The records kept are max(KOF_SYM_MAX_RECS, min(declared, KOF_SYM_ABS_MAX_RECS)):
 * the floor is what every object has always had, the ceiling is the index's
 * (0xffff is reserved) and the bound against a table whose declared size is
 * hostile. The POOL is sized by plan (KOF_SYM_POOL_PER_REC a name) because its
 * length is the names' and no format says it up front; when the builder reports
 * the block was cut - the plan was short, or a format cannot say how many it will
 * write (a PE: imports are walked, not counted) - it is rebuilt at four times the
 * size, until it was not or KOF_SYM_ABS_MAX_BYTES is reached. Past that the
 * header's `truncated` byte is set and the engine reads it (kof_scan_incomplete).
 *
 * `*buf` / `*cap` are the caller's buffer and its size in bytes; it is kept and
 * only grows, so the next object reuses it. Returns the block's length, or 0 when
 * memory was not to be had.
 */
uint32_t kof_syms_build_grow(uint32_t format, const uint8_t *data, uint64_t data_n,
			     const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t **buf, uint32_t *cap)
{
	uint32_t recs = KOF_SYM_MAX_RECS, decl, need;

	decl = kof_syms_declared(format, data, data_n, info);
	if (decl > recs)
		recs = decl < KOF_SYM_ABS_MAX_RECS ? decl : KOF_SYM_ABS_MAX_RECS;
	need = KOF_SYM_BYTES_FOR(recs) < KOF_SYM_ABS_MAX_BYTES
	     ? KOF_SYM_BYTES_FOR(recs) : KOF_SYM_ABS_MAX_BYTES;
	for (;;) {
		uint32_t n;

		if (*cap < need) {
			uint8_t *g = realloc(*buf, need);

			if (!g)
				return 0;
			*buf = g;
			*cap = need;
		}
		n = kof_syms_build_with(format, data, data_n, info, imports,
					*buf, *cap);
		if (!kof_sym_truncated(*buf, n) || need >= KOF_SYM_ABS_MAX_BYTES)
			return n;
		need = need > KOF_SYM_ABS_MAX_BYTES / 4u ? KOF_SYM_ABS_MAX_BYTES
							 : need * 4u;
	}
}

/*
 * HOW MANY RECORDS THIS OBJECT'S SYMBOL TABLE DECLARES, so the caller sizes the
 * block by the table it has instead of by a constant (KOF_SYM_ABS_MAX_RECS
 * bounds it). ELF: the table's own count. Any other format: 0, which means
 * "not known up front" - the caller grows the block until the builder says it
 * was not cut.
 */
static uint32_t kof_syms_declared(uint32_t format, const uint8_t *data, uint64_t data_n,
			   const void *info)
{
	if (info && format == KOF_FMT_ELF)
		return kof_elf_syms_declared(kof_buf_make(data, data_n), info);
	return 0;
}
