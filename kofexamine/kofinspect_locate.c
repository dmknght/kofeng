#define _GNU_SOURCE

/*
 * kofinspect_locate.c - the region map of an object and where a marker is, and in
 * which region (kof_locate_str). Split from kofinspect.c by job, no logic
 * changed; the reason it drives the matcher itself is at the top of kofinspect.c.
 */

#include "kofinspect_private.h"

/* ---- where a marker is, and in which region ------------------------------ */

int kof_region_map_build(struct kof_region_map *map,
			 const struct kof_obj_ctx *ctx,
			 const struct kof_parser *fmt)
{
	uint32_t k;

	memset(map, 0, sizeof *map);
	if (!ctx || !fmt)
		return 0;
	for (k = 0; k < fmt->n_regions && map->n_reg < 32u; k++) {
		struct kof_range *e = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *e);
		uint32_t n;

		if (!e)
			return 0;
		{
			struct kof_ext_buf eb = kof_ext_fixed(e, KOF_SCAN_MAX_EXTENTS);

			n = kof_scan_resolve_range(ctx, fmt->regions[k], &eb);
		}
		if (!n) {
			free(e);
			continue;
		}
		map->mask[map->n_reg] = fmt->regions[k];
		map->ext[map->n_reg]  = e;
		map->n[map->n_reg]    = n;
		map->n_reg++;
	}
	return 1;
}

void kof_region_map_free(struct kof_region_map *map)
{
	uint32_t k;

	for (k = 0; k < map->n_reg; k++)
		free(map->ext[k]);
	memset(map, 0, sizeof *map);
}

uint32_t kof_region_map_at(const struct kof_region_map *map, uint64_t off)
{
	uint32_t k, j;

	if (!map)
		return 0;
	for (k = 0; k < map->n_reg; k++)
		for (j = 0; j < map->n[k]; j++)
			if (off >= map->ext[k][j].off &&
			    off < map->ext[k][j].off + map->ext[k][j].len)
				return map->mask[k];
	return 0;
}

/*
 * How long the match at each hit actually is.
 *
 * kof_match_where says where a match starts and not where it ends, and the
 * engine keeps that to itself. Truncating the buffer is how to ask: a match
 * needs its whole length to be there, so the shortest cut it still matches
 * under IS its length. Monotonic, so it is a bisection. Skipped entirely for a
 * pattern of fixed length, which is nearly all of them.
 */
static void locate_lens(struct kof_locate *o, struct kof_match_ctx *m,
			kof_buf buf, const uint8_t *pat, uint16_t plen,
			uint8_t kind, uint8_t flags, uint32_t span_min,
			uint32_t span_max)
{
	uint32_t h;

	for (h = 0; h < o->n_hits; h++) {
		uint32_t lo = span_min, hi = span_max;

		if (span_max <= span_min) {
			o->hit_len[h] = span_min;
			continue;
		}
		if (o->hits[h] + hi > buf.n)
			hi = (uint32_t)(buf.n - o->hits[h]);
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			kof_match_begin(m, kof_buf_make(buf.p,
							o->hits[h] + mid));
			if (kof_match_at(m, o->hits[h], pat, plen, kind, flags))
				hi = mid;
			else
				lo = mid + 1u;
		}
		o->hit_len[h] = lo;
	}
	kof_match_begin(m, buf);        /* put the context back */
}

/*
 * Walk one window, recording every occurrence.
 *
 * `region` is asked for each hit so the caller can prefer one the mask names.
 * The word-boundary test is re-asked at the hit rather than trusted from the
 * windowed search: a range search treats the START of its range as a word
 * boundary, which is right when the range is a region a module named and wrong
 * when it is only "past the last hit".
 */
static void locate_walk(struct kof_locate *o, struct kof_match_ctx *m,
			uint64_t from, uint64_t end, const uint8_t *pat,
			uint16_t plen, uint8_t kind, uint8_t flags,
			uint32_t mask, const struct kof_region_map *map,
			uint32_t fixed_region, uint64_t *first,
			uint32_t *first_mask)
{
	while (from < end) {
		uint64_t at = kof_match_where(m, from, end - from, pat, plen,
					      kind, flags);
		uint32_t rm;

		if (at == KGENOME_BROKEN)
			return;
		if ((flags & KOF_STR_FULLWORD) &&
		    !kof_match_at(m, at, pat, plen, kind, flags)) {
			from = at + 1u;
			continue;
		}
		if (o->n_hits < KOF_LOCATE_HITS)
			o->hits[o->n_hits++] = at;
		else
			o->clipped = 1;
		rm = fixed_region ? fixed_region : kof_region_map_at(map, at);
		if (*first == KGENOME_BROKEN) {
			*first = at;
			*first_mask = rm;
		}
		o->seen_mask |= rm;
		if (o->at == KGENOME_BROKEN &&
		    (!mask || (mask & KOF_SCAN_ALL) || (rm & mask))) {
			o->at = at;
			o->at_mask = rm;
			o->in_rgn = 1;
			o->cur_hit = o->n_hits ? o->n_hits - 1u : 0u;
		}
		from = at + 1u;
		if (o->clipped && o->at != KGENOME_BROKEN)
			return;         /* the list is full and we have an answer */
	}
}

int kof_locate_str(struct kof_match_ctx *m, struct kof_match_ctx *msym,
		   const struct kof_region_map *map, kof_buf obj,
		   const uint8_t *sym, uint32_t sym_n, uint32_t mask,
		   const uint8_t *pat, uint16_t plen, uint8_t kind,
		   uint8_t flags, uint32_t span_min, uint32_t span_max,
		   struct kof_range *scratch, uint32_t cap,
		   struct kof_locate *out)
{
	uint64_t first = KGENOME_BROKEN;
	uint32_t first_mask = 0, h;

	memset(out, 0, sizeof *out);
	out->at = KGENOME_BROKEN;
	if (!pat || !plen)
		return 0;

	/*
	 * 1. THE SYMBOL HALVES, imports before exports.
	 *
	 * This order is kof_find_str's, so the occurrence reported is the one
	 * that decided the detection rather than a different one that happens
	 * to come first in the file.
	 */
	for (h = 0; h < 2u && sym && sym_n; h++) {
		uint32_t bit = h ? KOF_SCAN_SYM_EXP : KOF_SCAN_SYM_IMP;
		uint32_t n, e;

		if (!(mask & bit))
			continue;
		n = kof_sym_extents(sym, sym_n, bit, scratch, cap);
		if (!n)
			continue;
		kof_match_begin(msym, kof_buf_make(sym, sym_n));
		for (e = 0; e < n; e++)
			locate_walk(out, msym, scratch[e].off,
				    scratch[e].off + scratch[e].len, pat, plen,
				    kind, flags, mask, NULL, bit, &first,
				    &first_mask);
		if (out->n_hits) {
			out->sym = bit;
			locate_lens(out, msym, kof_buf_make(sym, sym_n), pat,
				    plen, kind, flags, span_min, span_max);
			return 1;
		}
	}

	/* 2. The file, preferring an occurrence the mask names. */
	if (!obj.p || plen > obj.n)
		return 0;
	kof_match_begin(m, obj);
	locate_walk(out, m, 0, obj.n, pat, plen, kind, flags, mask, map, 0,
		    &first, &first_mask);
	/*
	 * 3. Present, and nowhere the mask names. That is the finding, so the
	 * row still points at an occurrence and says the rule cannot fire on
	 * it - the union is what a widened range would have to cover.
	 */
	if (out->at == KGENOME_BROKEN && first != KGENOME_BROKEN) {
		out->at = first;
		out->at_mask = out->seen_mask ? out->seen_mask : first_mask;
		out->cur_hit = 0;
		out->off_rgn = 1;
	}
	if (out->n_hits)
		locate_lens(out, m, obj, pat, plen, kind, flags, span_min,
			    span_max);
	return out->at != KGENOME_BROKEN;
}

