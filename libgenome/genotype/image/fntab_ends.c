/*
 * fntab_ends.c - the ENDS step of the function table (fntab.h). ROUND 4 (2026-11-16): an entry whose extent a source declared is a unit of trust HIGH;
 * every other entry is a declared START (kgenome_func_set.st), not a body: no format declares where a start-only function ends. The text below is the
 * rule before round 4, kept for the record (DISABLED).
 *
 * THE RULE (round 4, 2026-11-16). An entry an exact source closed (a symbol's size, an unwind length, the Go table) is a unit of trust HIGH.
 * An entry whose end no source declared (a start-only table, the entry point, a size-0 or unconfirmed NOTYPE symbol) is NOT closed: no format
 * declares where it ends (INS-1), so it becomes a declared start in the set's sorted starts and its bytes stay in the NONE unit of their gap.
 * (Before round 4 such an entry ran to the next start, trust MEDIUM: disabled below.)
 * DISABLED by the owner 2026-11-16 (decode-derived): the padding trim - the run of padding instructions (nop, int3) the walk's decode saw standing
 * exactly at the end was cut off (end_source TRIMMED); `pad` / `n_pad` are no longer read (the orchestrator passes none). To re-enable: take the
 * #if 0 out below and pass the walk's runs again (kgenome_fntab_run_walk, fntab_build.c).
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
	uint32_t i, k = 0, n_st = 0;
	struct kgenome_func_start *st = NULL;

	(void)pad;
	(void)n_pad;
	if (s->n) {
		st = malloc((size_t)s->n * sizeof *st);
		if (!st)
			s->status = KGENOME_NOMEM;      /* the starts are lost (said by the status); the units are still split from them below */
	}
	for (i = 0; i < s->n; i++) {
		const struct kgenome_func f = s->v[i];
		uint32_t x;
		int in = 0;

		/* AN EXTENT A SOURCE DECLARED: a unit of trust HIGH */
		if (f.len && kgenome_fntab_exact(&f)) {
			s->v[k] = f;
			s->v[k++].trust = KGENOME_FN_TRUST_HIGH;
			continue;
		}
		/* A DECLARED START, NOT A BODY (round 4, design "Research: what the formats and loaders declare"; INS-1): no format declares where a
		 * start-only function ends - a sparse table (frame_dummy's init_array start swallowed a, b and main), .ARM.exidx (no row for a leaf by
		 * definition, EHABI 5.3), exports, TLS, SafeSEH / CF guard, the entry, a size-0 or NOTYPE symbol. The start is kept in the table's sorted
		 * starts (kgenome_funcs_starts_in) and the code around it stays in the NONE unit of its gap, uncut. A start in no code extent: n_extra. */
		for (x = 0; x < n_ext; x++)
			if (f.off >= ext[x].at && f.off - ext[x].at < ext[x].len)
				in = 1;
		if (!in || !st) {
			s->n_extra++;
			continue;
		}
		memset(&st[n_st], 0, sizeof st[n_st]);
		st[n_st].off = f.off;
		st[n_st].value = f.value;
		st[n_st].shndx = f.shndx;
		st[n_st].source = f.source;
		st[n_st].isa_mode = f.isa_mode;
		st[n_st++].kind = f.kind;
	}
#if 0   /* DISABLED by the owner 2026-11-16 (round 4): a start-only entry closed at the next start or the end of its extent (trust MEDIUM, END_OPEN,
	 * P_ENDS) - "the next start" is no declared fact (INS-1). To re-enable: close the starts here again as before (kgenome_fntab_bound) and give them
	 * KGENOME_FN_TRUST_MEDIUM back in funcs.h. */
	end = kgenome_fntab_bound(s, i, ext, n_ext);
#endif
	s->n = k;
	if (!k) {
		free(s->v);
		s->v = NULL;
	}
	free(s->st);
	s->st = n_st ? st : NULL;
	s->n_st = n_st;
	if (!n_st)
		free(st);
}
