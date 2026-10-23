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
#include "pe/pe_parse.h"
#include "funcs.h"
#include "../scripts/script_sym.h"
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
	/* A script: the names it calls - see script_sym.c. */
	if (format == KOF_FMT_SCRIPT)
		return kof_script_syms(b, info, out, cap);
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
 * Only a block cut for ROOM is rebuilt: a cut by a bound of the source (the PE
 * export name bound, an import table that stopped short: KOF_SYM_TRUNC_SOURCE)
 * is the same at any size, and a rebuild for it would be a pass that changes nothing.
 *
 * `*passes` (may be NULL) is how many times the builder ran, so the caller counts
 * each as a run of the product (kof_prod_ran): a rebuild is a second build of the
 * block and is not hidden by the first being counted.
 *
 * `*buf` / `*cap` are the caller's buffer and its size in bytes; it is kept and
 * only grows, so the next object reuses it. Returns the block's length, or 0 when
 * memory was not to be had.
 */
/* The grow loop, over a builder that fills `out` (`cap` bytes) with the block and answers its length: the one loop for every format, and for a script whose names come from a scan the engine made. */
typedef uint32_t (*syms_builder)(void *ctx, uint8_t *out, uint32_t cap);

static uint32_t syms_grow(syms_builder build, void *bctx, uint32_t decl, uint8_t **buf, uint32_t *cap, uint32_t *passes)
{
	uint32_t recs = KOF_SYM_MAX_RECS, need;

	if (passes)
		*passes = 0;
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
		n = build(bctx, *buf, *cap);
		if (passes)
			(*passes)++;
		if (n <= KOF_SYM_H_TRUNC ||
		    !((*buf)[KOF_SYM_H_TRUNC] & KOF_SYM_TRUNC_ROOM) ||
		    need >= KOF_SYM_ABS_MAX_BYTES)
			return n;
		need = need > KOF_SYM_ABS_MAX_BYTES / 4u ? KOF_SYM_ABS_MAX_BYTES
							 : need * 4u;
	}
}

struct build_obj {
	uint32_t format;
	const uint8_t *data;
	uint64_t data_n;
	const void *info;
	const struct kgenome_pe_imptab *imports;
};

static uint32_t build_obj_fn(void *ctx, uint8_t *out, uint32_t cap)
{
	const struct build_obj *o = ctx;

	return kof_syms_build_with(o->format, o->data, o->data_n, o->info, o->imports, out, cap);
}

uint32_t kof_syms_build_grow(uint32_t format, const uint8_t *data, uint64_t data_n,
			     const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t **buf, uint32_t *cap, uint32_t *passes)
{
	struct build_obj o = { format, data, data_n, info, imports };
	uint32_t decl = kof_syms_declared(format, data, data_n, info);

	/* A PE's imports are counted by the table the caller built; its exports
	 * are not known up front. */
	if (!decl && format == KOF_FMT_PE && imports)
		decl = imports->n;
	return syms_grow(build_obj_fn, &o, decl, buf, cap, passes);
}

struct build_script {
	kof_script_names_fn feed;
	void *user;
};

static uint32_t build_script_fn(void *ctx, uint8_t *out, uint32_t cap)
{
	const struct build_script *b = ctx;

	return kof_script_syms_with(b->feed, b->user, out, cap);
}

uint32_t kof_syms_build_grow_script(kof_script_names_fn feed, void *feed_user, uint8_t **buf, uint32_t *cap, uint32_t *passes)
{
	struct build_script b = { feed, feed_user };

	return syms_grow(build_script_fn, &b, 0u, buf, cap, passes);
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

/*
 * THE NAME OF THE SYMBOL AT AN ADDRESS, read out of a symbol block - the one
 * lookup, for everything that names a symbol from the block: the variable a
 * payload came out of, the function a block starts at, and the labels of the
 * disassembly. It is the engine's, so the viewer and the notes read the same way. `shndx` of -1 matches
 * any section; a relocatable object's values are section-relative, so there the
 * section is part of the answer. Empty when no record matches.
 */
void kof_sym_name_at(const uint8_t *blk, uint32_t n, uint64_t value,
			int shndx, char *out, size_t cap)
{
	const uint8_t *r;
	uint32_t k;

	out[0] = 0;
	if (!value)
		return;
	for (k = 0; (r = kof_sym_rec(blk, n, k)); k++) {
		uint32_t j;

		if (kof_sym_u64(r, KOF_SYM_R_VALUE) != value ||
		    (shndx >= 0 && (int)(r[KOF_SYM_R_SHNDX] |
					(r[KOF_SYM_R_SHNDX + 1u] << 8)) != shndx))
			continue;
		{
			uint32_t len = 0;
			const char *nm = kof_sym_name(blk, n, r, &len);

			for (j = 0; j + 1u < cap && j < len; j++)
				out[j] = nm[j];
		}
		out[j] = 0;
		if (j)
			return;
	}
}
