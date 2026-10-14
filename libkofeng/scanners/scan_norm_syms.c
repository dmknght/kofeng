/*
 * scan_norm_syms.c - the symbol view: the symbols a normalised object carries,
 * laid out as the text a rule matches against.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "../analyzers/parsers/binaries/sym_pool.h"
#include "../kofcore/kofmod/elf.h"
#include <string.h>


/*
 * THE VIEW'S SYMBOLS: THE PARENT'S, WITHOUT THE TOOLCHAIN'S.
 *
 * WHY IT CANNOT BE BUILT FROM THE VIEW. A symbol block is read out of the
 * object's own section table, and a view's headers describe the file before the
 * padding came out: every offset in them is stale wherever something collapsed
 * ahead of it. Measured on a uclibc bot - the file yields 677 records and its
 * view yields none, so the view carried no SYM_EXP and no SYM_IMP at all.
 *
 * AND WHY IT IS WORTH CARRYING. Two unrelated static binaries export the same
 * hundreds of libc names, so a symbol-set similarity between them measures the
 * toolchain exactly as a string-set one does. The view exists to be the
 * object's own content; its symbol half has to mean the same thing, or a
 * question asked of SYM_EXP on a view is answered by uclibc.
 *
 * THE SAME CLASSIFICATION AND NOT A SECOND ONE. A record is dropped when the
 * address it covers falls in the library spans sx_lib_facts already worked out -
 * see kgenome_true_has_addr. Nothing here decides what the library is.
 *
 * `_start` GOES WITH IT, and the header's index of it is cleared rather than
 * left pointing at whatever record now sits there: crt is the toolchain's, so
 * the record is dropped, and an index into a table that has moved underneath it
 * is worse than no index - a caller reads that index as a place to begin.
 */
uint32_t sx_norm_syms(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			  uint8_t *out, uint32_t cap)
{
	const struct kgenome_elf_info *e;
	const uint8_t *in;
	uint32_t n_in = 0, total, i, kept = 0, nb;
	struct kof_symw w;
	uint32_t start_at, start_new = KOF_SYM_NO_START;

	if (!ctx->content || !ctx->content->syms)
		return 0;
	if (!ctx->file_header)
		return 0;
	/*
	 * A PE'S SYMBOLS ARE CARRIED WHOLE, BECAUSE THERE IS NOTHING TO DROP.
	 *
	 * Everything below this is about ONE thing: taking the toolchain's
	 * symbols out of a statically linked ELF, so a similarity question
	 * asked of a view is not answered by uclibc. A PE has no such problem -
	 * its symbol block is the import and export tables, which are the
	 * program's own by construction and are the whole reason to have them.
	 *
	 * Written as "ELF only", every PE view came back with NO SYMBOLS AT
	 * ALL: measured on 1003b.exe, whose child carries 159 records and
	 * whose `:norm` carried none, and on 111.exe with 17 against none. The
	 * view is supposed to be the object said plainly, and it was the
	 * object said without its imports - which is most of what a reader
	 * opens it for.
	 *
	 * It is a copy and not a rebuild, for the reason in the note above:
	 * the view's own headers are stale wherever something collapsed ahead
	 * of them, so the block cannot be read out of the view and has to
	 * travel from the parent.
	 */
	if (ctx->format == KOF_FMT_PE) {
		/* THE RESOLVED IMPORTS ARE ALREADY IN THIS BLOCK: c_syms completes
		 * a PE's symbols from the analysis product, and the view carries
		 * what the object says. One source, one copy. */
		in = ctx->content->syms(ctx, &n_in);
		if (!in || !n_in || n_in > cap)
			return 0;
		memcpy(out, in, n_in);
		return n_in;
	}
	if (ctx->format != KOF_FMT_ELF || !sc->cur.lib_ok)
		return 0;
	e = kof_elf(ctx);
	in = ctx->content->syms(ctx, &n_in);
	total = kof_sym_count(in, n_in);
	if (!total || cap < KOF_SYM_HDRLEN)
		return 0;

	/* Where the parent said `_start` was, so the copy can say where it
	 * ended up - see the note below on why it is not simply cleared. */
	start_at = (uint32_t)in[KOF_SYM_H_START] |
		   ((uint32_t)in[KOF_SYM_H_START + 1] << 8);
	/* The pool is carried whole, so the room for it is the parent's: the block
	 * is rebuilt in order and a record the cut drops takes its name with it. */
	kof_symw_begin(&w, out, cap, total, n_in - (uint32_t)kof_sym_pool_at(in, n_in));
	for (i = 0; i < total; i++) {
		const uint8_t *r = kof_sym_rec(in, n_in, i);
		uint64_t va, sz;

		if (!r)
			continue;
		va = kof_sym_u64(r, KOF_SYM_R_VALUE);
		sz = kof_sym_u64(r, KOF_SYM_R_SIZE);
		if (kgenome_true_has_addr(e, &sc->cur.lib, va, sz))
			continue;
		/*
		 * AND NOTHING ELSE DECIDES THIS.
		 *
		 * A name test was here, dropping every `__CTOR_LIST__` and
		 * `__EH_FRAME_BEGIN__` the toolchain plants, because a symbol
		 * with no size covers no bytes and no span can reach it. It
		 * was wrong for a reason worth writing down: the block
		 * describes THE VIEW, and the view still contains those bytes.
		 * A record dropped here that the cut did not drop says the
		 * library was taken out where it was not - the symbol half and
		 * the byte half would be describing two different files.
		 *
		 * So the only question asked of a record is the one the bytes
		 * were asked: is what it covers inside what was cut. A symbol
		 * covering nothing was cut from nothing, and stays.
		 */
		/* After the room test, not before it: a record the cap stopped
		 * short of is not at an index, so the header must not name one
		 * for it. */
		if (!kof_symw_put_from(&w, in, n_in, r))
			break;
		if (i == start_at)
			start_new = w.n - 1u;
	}
	kept = w.n;
	if (!kept)
		return 0;
	nb = kof_symw_end(&w);
	/* The origin is the parent's, and so is a cut: the copy holds what the
	 * parent held, less what the library cut dropped. */
	out[KOF_SYM_H_ORIGIN] = in[KOF_SYM_H_ORIGIN];
	out[KOF_SYM_H_TRUNC] |= in[KOF_SYM_H_TRUNC];
	/*
	 * AND WHERE `_start` ENDED UP, WHICH IS ALSO NOT A NEW FACT.
	 *
	 * The header carries the index of the `_start` record so a reader can
	 * begin there. Filtering moves every index after the first drop, so
	 * copying the parent's number would point at whichever record now sits
	 * at it - a false statement rather than a missing one. This writes the
	 * index the SAME record landed at, or NO_START when the cut took it;
	 * both come out of what the loop above did, and nothing here decides
	 * which records those are.
	 */
	out[KOF_SYM_H_START + 0] = (uint8_t)(start_new & 0xffu);
	out[KOF_SYM_H_START + 1] = (uint8_t)((start_new >> 8) & 0xffu);
	return nb;
}
