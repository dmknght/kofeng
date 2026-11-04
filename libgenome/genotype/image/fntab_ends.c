/*
 * fntab_ends.c - the ENDS step of the function table (fntab.h): closes the entries no source could close.
 *
 * THE RULE, and what it is not. An entry whose end no source established runs to the next start of the table or to the end of the code extent
 * that holds it, whichever comes first - the extent bound is what keeps the last function of a segment from swallowing the .rodata and
 * .eh_frame that follow it (the section table ends the extent, see kgenome_diag_walk_range). The run of padding instructions (nop, int3) that
 * the walk's decode saw standing exactly at that end is then cut off: alignment padding of at most 15 bytes is 70% of the excess of the old
 * rule on x86-64 (105884 of 149684 units, exp_fnsize/work/res2.tables.md, agent-reported). It is NOT the reachable-blocks rule (R1): a function
 * whose tail is reached only by an unwinder, or a missing start inside a body, still gives a wrong end, and the entry says so (flag END_OPEN,
 * set->partial P_ENDS). A delay slot is not padding: the walk starts the run after the slot (phenotype/fntab_walk.c).
 */
#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include "fntab_private.h"

/* The run [from, to) of `pad` (pairs, ascending) that ends at `to`, or 0. */
int kgenome_fntab_pad_before(const uint64_t *pad, uint32_t n_pad, uint64_t to, uint64_t *from)
{
	uint32_t lo = 0, hi = n_pad;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (pad[2u * mid + 1u] < to)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (lo < n_pad && pad[2u * lo + 1u] == to) {
		*from = pad[2u * lo];
		return 1;
	}
	return 0;
}

uint64_t kgenome_fntab_bound(const struct kgenome_func_set *s, uint32_t i, const struct kgenome_fntab_extent *ext, uint32_t n_ext)
{
	const uint64_t off = s->v[i].off;
	uint64_t lim = 0, end;
	uint32_t x;

	for (x = 0; x < n_ext; x++)
		if (off >= ext[x].at && off - ext[x].at < ext[x].len) {
			lim = ext[x].at + ext[x].len;
			break;
		}
	if (!lim)
		return 0;
	end = i + 1u < s->n && s->v[i + 1u].off < lim ? s->v[i + 1u].off : lim;
	return end > off ? end : 0;
}

/* A run of `pad` that STARTS exactly at `at`: 1 and its start (the same value), or 0. */
int kgenome_fntab_pad_at(const uint64_t *pad, uint32_t n_pad, uint64_t at, uint64_t *from)
{
	uint32_t lo = 0, hi = n_pad;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (pad[2u * mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (lo < n_pad && pad[2u * lo] == at) {
		*from = at;
		return 1;
	}
	return 0;
}

void kgenome_fntab_ends(struct kgenome_func_set *s, const struct kgenome_fntab_extent *ext, uint32_t n_ext,
		    const uint64_t *pad, uint32_t n_pad)
{
	uint32_t i, k = 0;

	for (i = 0; i < s->n; i++) {
		struct kgenome_func f = s->v[i];
		uint64_t end, from;

		if (f.len && f.end_source != KGENOME_FN_E_NONE) {
			s->v[k++] = f;
			continue;
		}
		end = kgenome_fntab_bound(s, i, ext, n_ext);
		if (!end) {
			s->n_extra++;            /* a start that is in no code extent, or at the end of it: the entry of nothing */
			continue;
		}
		f.end_source = KGENOME_FN_E_NEXT_START;
		if (pad && kgenome_fntab_pad_before(pad, n_pad, end, &from) && from > f.off) {
			end = from;
			f.end_source = KGENOME_FN_E_TRIMMED;
		}
		f.len = end - f.off;
		f.flags |= KGENOME_FN_F_END_OPEN;
		s->partial |= KGENOME_FNTAB_P_ENDS;
		s->v[k++] = f;
	}
	s->n = k;
	if (!k) {
		free(s->v);
		s->v = NULL;
	}
}
