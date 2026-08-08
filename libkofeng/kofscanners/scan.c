/*
 * scan.c - scan one object.
 *
 * Order of work, and it is the order that matters:
 *
 *   parse         format facts, so the filter has something to filter on
 *   derive        regions, presence set, memo - paid once for all modules
 *   filter + run  per module, cheapest test first
 *
 * The derive step is the same idea as InitCache in the old Kaspersky engine: pay a
 * small per-object precomputation so that each of very many records can be decided
 * with one instruction.
 */

#include "scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMO_UNKNOWN 0
#define MEMO_ABSENT  1
#define MEMO_PRESENT 2

/*
 * Everything mutable, one per thread.
 *
 * The engine it points at is immutable and shared. Splitting them is what keeps the
 * 32MB presence table out of the per-file path: it belongs to the thread, is allocated
 * once, and is reused for every object.
 */
struct kof_scanner {
	const struct kof_engine *eng;

	struct kof_match_ctx m;
	struct kof_elf_info *elf;          /* reused; 11.9KB, so not per object */

	struct kof_gram *gram;             /* NULL below the point where it pays */

	uint8_t  *memo;                    /* eng->memo_size bytes, cleared per object */

	/* Set while a module runs: find_str is called from inside one, and the ids it
	 * passes are module local, so the host has to know whose they are. */
	const struct kof_module *cur_mod;

	/* What the running module reported. A module cannot hold state, so a finding
	 * has to land here. */
	uint32_t rep_level, rep_name_id;
	int      rep_valid, rep_cont;

	struct kof_stats st;
};

static struct kof_scanner *sc_of(const struct kof_obj_ctx *ctx)
{
	return (struct kof_scanner *)(void *)(uintptr_t)ctx->priv;
}

struct kof_scanner *kof_scan_new(const struct kof_engine *eng)
{
	struct kof_scanner *sc = calloc(1, sizeof *sc);

	if (!sc)
		return NULL;
	sc->eng = eng;

	sc->elf = malloc(sizeof *sc->elf);
	if (!sc->elf)
		goto fail;

	/* The matcher decides whether building it pays; NULL is a normal answer. */
	sc->gram = kof_gram_new(eng->n_str);

	if (eng->memo_size) {
		sc->memo = calloc(eng->memo_size, 1);
		if (!sc->memo)
			goto fail;
	}
	return sc;

fail:
	kof_scan_free(sc);
	return NULL;
}

void kof_scan_free(struct kof_scanner *sc)
{
	if (!sc)
		return;
	free(sc->memo);
	kof_gram_free(sc->gram);
	free(sc->elf);
	free(sc);
}

void kof_scan_count_unreadable(struct kof_scanner *sc)
{
	sc->st.unreadable++;
}

const struct kof_stats *kof_scan_stats(const struct kof_scanner *sc)
{
	return &sc->st;
}

/* ---- the byte accessors handed to a module --------------------------------- */

static struct kof_match_ctx *mc(const struct kof_obj_ctx *ctx)
{
	return &sc_of(ctx)->m;
}

static uint8_t c_rd8(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint8_t v = 0;
	kof_rd_u8(mc(ctx)->data, off, &v);
	return v;
}

static uint16_t c_rd16(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint16_t v = 0;
	kof_rd_u16(mc(ctx)->data, off, 0, &v);
	return v;
}

static uint32_t c_rd32(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint32_t v = 0;
	kof_rd_u32(mc(ctx)->data, off, 0, &v);
	return v;
}

static uint64_t c_rd64(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint64_t v = 0;
	kof_rd_u64(mc(ctx)->data, off, 0, &v);
	return v;
}

static int c_memeq(const struct kof_obj_ctx *ctx, uint64_t off, const void *pat,
		   uint32_t len)
{
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return memcmp(s.p, pat, len) == 0;
}

static uint32_t c_csum(const struct kof_obj_ctx *ctx, uint64_t off, uint32_t len)
{
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return kof_crc32(s.p, s.n);
}

static void c_report(const struct kof_obj_ctx *ctx, uint32_t level,
		     uint32_t name_id)
{
	struct kof_scanner *sc = sc_of(ctx);
	sc->rep_level   = level;
	sc->rep_name_id = name_id;
	sc->rep_valid   = 1;
}

static void c_cont(const struct kof_obj_ctx *ctx)
{
	sc_of(ctx)->rep_cont = 1;
}

/* ---- searching a declared string ------------------------------------------- */

/* Resolve the range a call names into extents, then let the matcher search them. */
static int search_str(const struct kof_obj_ctx *ctx, struct kof_scanner *sc,
		      const struct kof_str_ent *e, uint32_t scan_mask)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t n = 0;

	if (scan_mask & KOF_SCAN_ALL) {
		ext[0].off = 0;
		ext[0].len = ctx->obj_size;
		n = ctx->obj_size ? 1 : 0;
	} else if (ctx->resolve_scan) {
		n = ctx->resolve_scan(ctx, scan_mask, ext, KOF_SCAN_MAX_EXTENTS);
		if (n > KOF_SCAN_MAX_EXTENTS)
			n = KOF_SCAN_MAX_EXTENTS;
	}
	return kof_match_str(&sc->m, ext, n, e->bytes, e->len, e->icase,
			     e->fullword);
}

/*
 * The module facing search, in two stages.
 *
 * The presence set says whether the string's first four bytes occur anywhere in the
 * object; only then is a search run. So a marker that is absent - nearly every marker
 * for nearly every object - costs one table lookup and no scan. That first stage does
 * not depend on the range, so absence answers every range at once.
 *
 * Answers are memoised per (string, range), so a module asking twice pays once and a
 * batched pass can fill the same table ahead of time. That is where batching will go:
 * the surviving strings of every module about to run, searched together, one pass per
 * range.
 */
static int c_find_str(const struct kof_obj_ctx *ctx, uint32_t str_id,
		      uint32_t range_id)
{
	struct kof_scanner *sc = sc_of(ctx);
	const struct kof_module *m = sc->cur_mod;
	const struct kof_str_ent *e;
	uint32_t si, ri;
	uint8_t *slot;
	int found;

	if (!m || str_id >= m->n_str || range_id >= m->n_rng)
		return 0;
	si = m->str_base + str_id;
	ri = m->rng_base + range_id;
	e = &sc->eng->str_tab[si];

	/* Module local indexing: str_id and range_id are already bounded against this
	 * module's counts above, so the result cannot leave its own slice. */
	slot = &sc->memo[m->memo_base + str_id * m->n_rng + range_id];
	if (*slot != MEMO_UNKNOWN)
		return *slot == MEMO_PRESENT;

	if (!kof_gram_may_contain(sc->gram, e->bytes, e->len, e->icase)) {
		sc->st.gram_answers++;
		*slot = MEMO_ABSENT;
		return 0;
	}
	found = search_str(ctx, sc, e, sc->eng->rng_tab[ri]);
	*slot = found ? MEMO_PRESENT : MEMO_ABSENT;
	return found;
}

static const struct kof_content content_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_csum
};

/* ---- deriving per-object facts --------------------------------------------- */

/*
 * Which regions this object has, as a mask of region bits.
 *
 * Computed once per object, not once per module. Resolving a region walks the segment
 * and section tables and sorts the result, so doing it per module would cost more than
 * running the cheap modules it is meant to save. Done once, the per-module test is a
 * single AND.
 */
static uint32_t regions_present(const struct kof_obj_ctx *ctx, uint32_t wanted)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t present = 0, bit;

	if (ctx->obj_size)
		present |= KOF_SCAN_ALL;
	if (!ctx->resolve_scan)
		return present;

	/* Only the regions some module names. A region nobody asks about does not need
	 * an answer, and one of them is expensive enough that the difference shows. */
	for (bit = 1; bit < 16; bit++) {
		if (!(wanted & (1u << bit)))
			continue;
		if (ctx->resolve_scan(ctx, 1u << bit, ext, KOF_SCAN_MAX_EXTENTS))
			present |= 1u << bit;
	}
	return present;
}

/*
 * Can this module be ruled out without calling it?
 *
 * Every test reads a field of the module's record against a fact already produced.
 * None touches the blob, which is what makes this a pre-use filter rather than the
 * same conditions written inside the module - those are correct and save nothing,
 * because reaching them costs the call.
 *
 * Absent constraints mean unconstrained, so a module with an empty record runs. The
 * default has to fall that way: over-running costs time, under-running costs
 * detections and would not show up as a failure anywhere.
 */
static int prefilter(const struct kof_module *m, const struct kof_obj_ctx *ctx,
		     uint32_t present, struct kof_stats *st)
{
	st->considered++;

	if (!(m->target_mask & (1u << ctx->format))) {
		st->by_target++;
		return 0;
	}
	if (ctx->obj_size < m->size_min) {
		st->by_size++;
		return 0;
	}
	if (m->arch_mask) {
		/* An architecture outside the bit width cannot be named by a mask, so
		 * a module that constrains architecture does not cover it. */
		if (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))) {
			st->by_arch++;
			return 0;
		}
	}
	/* A module that names regions cannot match if none exist here: every search
	 * it performs would be over an empty range. One that names none - scalar
	 * only - has nothing to be excused by, and runs. */
	if (m->scan_mask && !(m->scan_mask & present)) {
		st->by_region++;
		return 0;
	}

	st->ran++;
	return 1;
}

/* ---- naming a finding ------------------------------------------------------ */

static const char *fmt_str(uint8_t t)
{
	switch (t) {
	case KOF_FMT_ELF:    return "ELF";
	case KOF_FMT_PE:     return "PE";
	case KOF_FMT_MACHO:  return "MachO";
	case KOF_FMT_SCRIPT: return "Script";
	case KOF_FMT_TEXT:   return "Text";
	default:             return "Unknown";
	}
}

static const char *arch_name(uint8_t a)
{
	switch (a) {
	case KOF_ARCH_X86:     return "x86";
	case KOF_ARCH_X86_64:  return "x86_64";
	case KOF_ARCH_ARM:     return "arm";
	case KOF_ARCH_ARM64:   return "arm64";
	case KOF_ARCH_RISCV64: return "riscv64";
	case KOF_ARCH_MIPS:    return "mips";
	case KOF_ARCH_PPC64:   return "ppc64";
	default:               return "any";
	}
}

/*
 * <format>.<arch>.<authored family>.
 *
 * The prefix is composed rather than authored: a module cannot claim a format it was
 * not run against, and one authored name covers every architecture. The operating
 * system is absent on purpose - ELF does not say it, so "Linux" would be a guess
 * wearing the clothes of a fact.
 */
static void finding_str(const struct kof_scanner *sc,
			const struct kof_obj_ctx *ctx,
			const struct kof_module *m, char *out, size_t cap)
{
	const char *nm = kof_db_name(sc->eng, m, sc->rep_name_id);

	snprintf(out, cap, "%s.%s.%s", fmt_str(ctx->format),
		 arch_name(ctx->arch), nm ? nm : "unknown");
}

/* ---- the routine ---------------------------------------------------------- */

uint32_t kof_scan_object(struct kof_scanner *sc, kof_buf buf, const char *name,
			 struct kof_result *out)
{
	struct kof_obj_ctx ctx;
	uint32_t present, i, added = 0;

	(void)name;   /* recorded by the caller; the layer tree is its business */

	memset(&ctx, 0, sizeof ctx);
	ctx.content = &content_vtable;
	ctx.report  = c_report;
	ctx.cont    = c_cont;
	ctx.priv    = sc;

	kof_match_begin(&sc->m, buf);

	/*
	 * One parser wired in for now. This is where the format table goes: identify,
	 * then dispatch. Until there is a second parser, a table would be a table with
	 * one row and a switch with one case.
	 */
	kof_elf_parse(buf, sc->elf, &ctx);

	present = regions_present(&ctx, sc->eng->scan_mask);
	sc->st.gram_bytes += kof_gram_build(sc->gram, buf);
	if (sc->memo)
		memset(sc->memo, MEMO_UNKNOWN, sc->eng->memo_size);

	sc->st.objects++;
	sc->st.object_bytes += buf.n;

	for (i = 0; i < sc->eng->n_mods; i++) {
		const struct kof_module *m = &sc->eng->mods[i];

		if (!prefilter(m, &ctx, present, &sc->st))
			continue;

		sc->rep_valid = 0;
		sc->rep_cont  = 0;
		sc->cur_mod   = m;
		m->fn(&ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;

		/* Accumulate. Keeping only the last would drop a finding whenever two
		 * families match one object, and the cap is counted rather than
		 * silently applied. */
		if (out->n < KOF_MAX_FINDINGS) {
			struct kof_finding *f = &out->v[out->n++];
			f->level = sc->rep_level;
			finding_str(sc, &ctx, m, f->name, sizeof f->name);
		} else {
			out->dropped++;
		}
		added++;
	}

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->m.n_calls;
	sc->st.bytes_searched += sc->m.n_bytes_scanned;

	return added;
}