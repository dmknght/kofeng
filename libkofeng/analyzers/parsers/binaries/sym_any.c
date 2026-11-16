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
#include <stdio.h>
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

	/* A PE's imports are counted by the table the caller already built (not
	 * re-derived here) and ADDED to whatever kof_syms_declared knows from the
	 * file's own COFF table - the two are different symbols, so one does not
	 * replace the other. Exports still are not known up front. Saturating: a
	 * file would need to be implausibly large for this to wrap, but a sizing
	 * hint never gets to claim more than fits in uint32_t. */
	if (format == KOF_FMT_PE && imports) {
		uint32_t add = imports->n;

		decl = decl > 0xffffffffu - add ? 0xffffffffu : decl + add;
	}
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
 * bounds it). ELF: the table's own count. PE: the COFF table's NumberOfSymbols
 * when the file has one (kgenome_pe_coff_count) - an upper bound on the FUNCTION
 * records kof_pe_syms_with actually keeps from it, which is the right kind of
 * error for a sizing hint (fewer grow-loop passes, never a wrong result: the
 * loop still regrows on KOF_SYM_TRUNC_ROOM). The PE import count is a separate,
 * already-known addend the caller holds (kof_syms_build_grow) and is added
 * there, not re-derived here. Any other format, or a PE with neither a COFF
 * table the caller can read: 0, "not known up front" - the caller grows the
 * block until the builder says it was not cut.
 */
static uint32_t kof_syms_declared(uint32_t format, const uint8_t *data, uint64_t data_n,
			   const void *info)
{
	if (!info)
		return 0;
	if (format == KOF_FMT_ELF)
		return kof_elf_syms_declared(kof_buf_make(data, data_n), info);
	if (format == KOF_FMT_PE)
		return kgenome_pe_coff_count(kof_buf_make(data, data_n), info);
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
void kof_sym_name_at(const uint8_t *blk, uint32_t n, const uint64_t *value,
			int shndx, char *out, size_t cap)
{
	const uint8_t *r;
	uint32_t k;

	out[0] = 0;
	if (!value)
		return;
	for (k = 0; (r = kof_sym_rec(blk, n, k)); k++) {
		uint32_t j;

		if (kof_sym_u64(r, KOF_SYM_R_VALUE) != *value ||
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

void kof_fcn_name(uint64_t off, char *out, size_t cap)
{
	if (cap)
		snprintf(out, cap, "fcn_%08llx", (unsigned long long)off);
}

/*
 * THE 1-BASED LINE NUMBER of a byte offset in a script's own text: the newlines
 * strictly before it, plus one - the same convention the text pane's own gutter
 * shows for that byte (kofexamine's kv_text.c: txt_line_of returns a 0-based
 * count and every caller that puts a number on screen adds the 1 itself,
 * kv_text.c:324/434). Written from scratch rather than calling txt_line_of: that
 * function takes a `struct view *` and reads its scroll/anchor cache (kv_shared.h)
 * to avoid rescanning from the start on every redraw, which is a VIEWER'S own
 * state the engine must not reach into (check_layers.py's tool-include / core-
 * closure rules) and would be backwards anyway (rule 11: the engine decides the
 * name, a tool only shows it). Only '\n' is counted, exactly as txt_line_count
 * does: a "\r\n" pair is one line break because the '\r' byte is never itself
 * counted, and a lone '\r' (old Mac text) is not recognised as a break either -
 * the same reading the text pane already gives the same bytes, not a new gap.
 * The caller bounds `off` against the buffer first; this never reads past it.
 */
static uint64_t kof_script_line_of(const uint8_t *data, uint64_t off)
{
	uint64_t i, n = 0;

	for (i = 0; i < off; i++)
		if (data[i] == '\n')
			n++;
	return n + 1u;
}

int kof_func_name(const struct kgenome_func *f, const uint8_t *blk, uint32_t n,
		  const uint8_t *data, uint64_t data_n, char *out, size_t cap)
{
	if (!cap)
		return 0;
	out[0] = 0;
	/* An entry with section 0 carries no symbol (funcs.h: value and shndx are zero for none; no defined ELF symbol has SHN_UNDEF, a PE record is 0xffff
	 * or a COFF section number from 1). Looked up anyway, it matched an UNDEFINED record of the same value: measured on /usr/bin/ls, the walk's function
	 * at 0x74d0 (value 0) was named `__ctype_toupper_loc`, an import whose record has value 0 and section 0. */
	if (f && blk && f->shndx)
		kof_sym_name_at(blk, n, &f->value, (int)f->shndx, out, cap);
	if (out[0])
		return 1;
	/* A SCRIPT has no symbol table: its own declaration shape named it instead
	 * (kgenome_script_funcs_build, name_off/name_len - funcs.h). `data` is the object's own
	 * bytes, the span is checked against `data_n` before it is read (a mismatched caller, or a
	 * span some future producer got wrong, falls back exactly as a script with no name would,
	 * never an out-of-bounds read). */
	if (f && f->kind == KGENOME_FN_SCRIPT && f->name_len && data &&
	    f->name_off < data_n && (uint64_t)f->name_len <= data_n - f->name_off) {
		uint32_t j;

		for (j = 0; j + 1u < cap && j < f->name_len; j++)
			out[j] = (char)data[f->name_off + j];
		out[j] = 0;
		if (out[0])
			return 1;
	}
	/*
	 * A SCRIPT ENTRY WITH NO DECLARED NAME - an anonymous closure (`function (...) {}`,
	 * name_len 0) or a piece that is not a function at all (a caller's own throwaway
	 * KGENOME_FN_SCRIPT entry for the mutation cut's "remainder" between real functions,
	 * kv_mutation.c/kofexaminer_blocks.c) - is still "no function name" in the owner's own
	 * words (2026-11-06): named by the 1-based source line its `off` sits on, `block_<N>`,
	 * instead of the made-up fcn_<offset>, which never meant anything for a script anyway (a
	 * script has no "function" word for a bare file offset to imply the way a symbol-table
	 * stripped ELF/PE function does). `off` is bounds-checked against `data_n` first, exactly
	 * as the name span is above; past it, or with no `data` at all, falls to fcn_<offset> same
	 * as before - never an out-of-bounds read. ELF/PE (kind != KGENOME_FN_SCRIPT) never takes
	 * this branch and keeps fcn_<offset> exactly as it always has.
	 */
	if (f && f->kind == KGENOME_FN_SCRIPT && !f->name_len && data && f->off <= data_n) {
		uint64_t ln = kof_script_line_of(data, f->off);

		/*
		 * TODO (owner, 2026-11-07, NOTE ONLY - not implemented): `block_<line>` collides when
		 * a LINEAR fragment puts more than one remainder unit on the same source line (several
		 * statements on one line, or one-liner webshells with no line breaks at all - every
		 * unit on such a file would name itself `block_1`). The fix is to also carry the
		 * COLUMN (the byte offset back to the start of that line, what code editors call the
		 * column) and name it `block_<line>_<column>` or similar, making the name unique per
		 * position again. Needs a column-counting twin of kof_script_line_of below (distance to
		 * the nearest preceding '\n', or `off` itself when there is none before it) - not built.
		 */
		/* A MADE-UP NAME, like fcn_<offset>: returns 0, same as that fallback - neither is
		 * something the file's author wrote, both are positions dressed as names. */
		snprintf(out, cap, "block_%llu", (unsigned long long)ln);
		return 0;
	}
	kof_fcn_name(f ? f->off : 0u, out, cap);
	return 0;
}
