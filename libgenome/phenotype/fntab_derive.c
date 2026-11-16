/*
 * fntab_derive.c - PHASE 2 OF THE METADATA PARTITION: THE FUNCTIONS OF CODE NO METADATA DECLARES, derived by recursive descent from the starts the loader and ABI
 * tables declare in it (owner 2026-11-16: "thì giờ tìm cách phân hoạch đi"; design /mnt/games/normtest/design_partition_meta.md, "Phase 2").
 *
 * WHAT IT READS. The NONE units of the table (the undeclared code, fntab_build.c undeclared_fill) are the extents of ONE descent (celllysis/cfg.h, THE BLOCK
 * LAYER, kgenome_cfg_obj_build: no second traversal here); the declared starts inside them (kgenome_funcs_starts_in: the entry, init/fini arrays, exports, TLS,
 * SafeSEH, CF guard, .ARM.exidx, size-0 and NOTYPE symbols) are its seeds. A byte is decoded only when an instruction already proven code leads to it: the
 * disabled linear walk read every byte and took every call target it met in data (D6); this does not.
 *
 * WHAT A FUNCTION IS HERE, one rule each:
 *   entry   a block a seed starts (source DERIVED_SEED, beside the declared start's own bits) or a direct call's target (DERIVED_CALL), or a tail jump's target
 *           across something that is not padding (DERIVED_JUMP, promote_jumps, PM5-D1). Any other jump's target is a block of the function that reaches it.
 *   body    the blocks its entry reaches through successors without entering another entry: a jump or a fall into another entry is a TAIL CALL, not body.
 *           A call's continuation is read only when its callee is known to return (the block layer's waiting calls), so the bytes after a call to a function
 *           that does not return are in no body unless another path reaches them.
 *   extent  the union of its blocks and of the padding holes between them (hole_is_body): the run that starts at the entry is the first range (off, len),
 *           every other run (a cold part, code behind data or anything else that is not one padding run) a further range (kgenome_funcs_range); the trap
 *           behind a call that does not return is in the call's block (cfg_obj.c traps). end_source REACH, trust DERIVED (never HIGH).
 *   flags   INCOMPLETE: a block ends in an indirect jump (a switch: the jump-table reader is the next algorithm, backward slicing), or a path ran out of the
 *           undeclared code (into exact code or past an extent) or out of the work bound; BROKEN: a path ran into bytes that decode as nothing or into the
 *           middle of another instruction; ASSUMED_RET: it was resolved as returning by assumption (a recursion cycle); SHARED: a block another entry
 *           reaches too, owned by the entry with the lower offset (code two functions share is rare in compiled code: said, not resolved further).
 * A target inside an exact (HIGH) body and not at its start is outside the descent's extents (LOOSE/OUTSIDE): it is dropped and counted (n_into_high). A
 * declared start that derived nothing (Thumb: one instruction set per space - an ELF start with bit 0, every start of a PE of machine 0x1c2 / 0x1c4; not code; no
 * control-flow rules for the architecture) is counted (n_skipped).
 *
 * ONE DECODE: when the caller holds the object's walk (the scan), the descent reads the walk's trace (kgenome_diag_walk_hold) and the walk is made here when it
 * was not yet: it is the decode every later reader of the same code shares (the lineage's frames, the routes), so a derived function is not decoded twice.
 * With no walk (a tool asking for the table alone) the walk is made here, freed with the table's run: the same decode, and the same padding runs, on both paths.
 *
 * NAMED LIMITS, each with the next algorithm: a function reached only through a pointer (a callback, a vtable, a jump table's case: the relocation and
 * pointer-table readers); a switch (backward slicing of the indirect jump); a function whose only return is through what it calls via a register (assumed to
 * return); Thumb code (a space per instruction set); a hole between a function's blocks that is not one run of padding stays a NONE unit (hole_is_body).
 */
#include "fntab_build_private.h"
#include <celllysis/space.h>
#include <celllysis/cfg.h>

/* The declared start at `off`, or NULL (the starts are sorted by off). */
static const struct kgenome_func_start *start_at(const struct kgenome_func_set *s, uint64_t off);

/*
 * Which blocks are entries: a direct call's target, and a seed. A seed that only an UNWIND table declares (.ARM.exidx, an FDE start: rows of the unwinder,
 * which describe where one unwind rule holds, not where a function is entered) and that the instruction before it runs on into (KGENOME_CFG_OBJ_B_FALLEN:
 * no call, no jump, no stop between) is NOT an entry: it is the body of whatever runs into it. Measured on stripped ARM twins (2026-11-17): uClibc's
 * hand-written syscall wrappers carry an exidx row in the middle (`close+0x3c`, after `ldr r0,[sp],#8`; `close+0x2c`, the target of the wrapper's own `bne` from below), which cut the function in two (R1). The same holds
 * for such a seed a direct branch from a block BELOW it goes to (`from_below`: a branch from above is the seed's own loop back to its start). A seed some
 * other source declares (the entry point, an export, an init/fini slot, a symbol) is an entry even when fallen into (assembly that falls into the next
 * function, both entered by name).
 * TODO(owner): default applied 2026-11-17 (such a row is body: a merge is a coverage question, a cut is a precision failure); the alternative is a NONE run.
 */
/* KNOWN DEFECT FPART-D2 (2026-11-17, M) [sev M]: is_entry keeps an unwind-only seed (an .ARM.exidx row) as an entry when no read code reaches it, and a call target
 * as an entry wherever it is. Trigger: uClibc ARM close/read/write rows at +0x2c whose own start nothing names; multi-entry assembly (libgcc __aeabi_dmul,
 * glibc i386 _start's pc thunk, __memset_sse2_unaligned_erms). Effect: a derived unit starts inside a function (R1: 12 ARM twin boundaries).
 * Reproducer: /mnt/games/normtest/fix_part/h/r12.py (stripped twins, out/t4_twins/fail.txt). Fix: no metadata answers it; a symbol is the only source (owner decision). */
static int is_entry(const struct kgenome_func_set *s, const struct kgenome_cfg_obj *g, uint32_t b, const uint8_t *from_below)
{
	const struct kgenome_cfg_obj_block *x = &g->b[b];
	const struct kgenome_func_start *st;

	if (x->flags & KGENOME_CFG_OBJ_B_CALLED)
		return 1;
	if (!(x->flags & KGENOME_CFG_OBJ_B_SEED))
		return 0;
	if (!(x->flags & KGENOME_CFG_OBJ_B_FALLEN) && !from_below[b])
		return 1;
	st = start_at(s, x->off);
	return !st || (st->source & (uint16_t)~(KGENOME_FN_S_EXIDX | KGENOME_FN_S_FDE)) != 0;
}

/* The declared start at `off`, or NULL (the starts are sorted by off). */
static const struct kgenome_func_start *start_at(const struct kgenome_func_set *s, uint64_t off)
{
	uint32_t lo = 0, hi = s->n_st;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (s->st[mid].off < off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < s->n_st && s->st[lo].off == off ? &s->st[lo] : NULL;
}

/* The extents and seeds of the descent: the NONE units, and the declared starts in them that this space can read. 0 when memory was refused. */
static int gather(const struct kgenome_func_set *s, int thumb, struct kgenome_cfg_obj_ext **ext, uint32_t *n_ext, struct kgenome_cfg_obj_seed **sd,
		  uint32_t *n_sd, uint32_t *skipped)
{
	uint32_t i, ne = 0, ns = 0;

	for (i = 0; i < s->n; i++)
		if (s->v[i].trust == KGENOME_FN_TRUST_NONE)
			ne++;
	*ext = ne ? malloc((size_t)ne * sizeof **ext) : NULL;
	*sd = s->n_st ? malloc((size_t)s->n_st * sizeof **sd) : NULL;
	if ((ne && !*ext) || (s->n_st && !*sd))
		return 0;
	for (i = 0; i < s->n; i++) {
		uint32_t first, n, k;

		if (s->v[i].trust != KGENOME_FN_TRUST_NONE)
			continue;
		(*ext)[*n_ext].off = s->v[i].off;
		(*ext)[(*n_ext)++].len = s->v[i].len;
		n = kgenome_funcs_starts_in(s, i, &first);
		for (k = first; k < first + n; k++) {
			if (thumb || s->st[k].isa_mode == KGENOME_FN_ISA_THUMB) {
				(*skipped)++;           /* the space reads one instruction set: an ARM Thumb start is not read as ARM */
				continue;
			}
			(*sd)[ns].off = s->st[k].off;
			(*sd)[ns++].src = s->st[k].source;
		}
	}
	*n_sd = ns;
	return 1;
}

/* What the descent says of a function's blocks, as the table's flags. */
static uint16_t block_flags(const struct kgenome_cfg_obj_block *b)
{
	if (b->term == KGENOME_CFG_OBJ_T_INDIRECT)
		return KGENOME_FN_F_INCOMPLETE;
	if (b->term != KGENOME_CFG_OBJ_T_STOP)
		return 0;
	return b->stop == KGENOME_CFG_OBJ_W_UNDECODABLE || b->stop == KGENOME_CFG_OBJ_W_OVERLAP ? KGENOME_FN_F_BROKEN : KGENOME_FN_F_INCOMPLETE;
}

/* The bodies: each entry, in address order, owns the blocks it reaches that no entry before it owns (succ[0] the target, succ[1] the fall-through; neither
 * enters another entry, `isent`). A block an earlier entry owns is SHARED: both functions say so. `own` gets the entry's index per block (KGENOME_CFG_NONE: none). */
static int bodies(const struct kgenome_cfg_obj *g, const uint8_t *isent, const uint32_t *ent, uint32_t n_ent, uint32_t *own, uint16_t *fl)
{
	uint32_t *stk = malloc((size_t)(g->n_b ? g->n_b : 1u) * sizeof *stk);
	uint32_t e;

	if (!stk)
		return 0;
	for (e = 0; e < g->n_b; e++)
		own[e] = KGENOME_CFG_NONE;
	for (e = 0; e < n_ent; e++) {
		uint32_t n = 0;

		fl[e] = 0;
		own[ent[e]] = e;
		stk[n++] = ent[e];
		while (n) {
			const uint32_t b = stk[--n];

			for (unsigned k = 0; k < 2u; k++) {
				const uint32_t t = g->b[b].succ[k];

				if (t == KGENOME_CFG_NONE || isent[t] || own[t] == e)
					continue;
				if (own[t] != KGENOME_CFG_NONE) {
					fl[e] |= KGENOME_FN_F_SHARED;
					fl[own[t]] |= KGENOME_FN_F_SHARED;
					continue;
				}
				own[t] = e;
				stk[n++] = t;
			}
		}
	}
	free(stk);
	return 1;
}

/* Is [lo, hi) inside one extent of the descent (one NONE unit: no byte of another unit, HIGH or outside the code)? */
static int in_one_ext(const struct kgenome_cfg_obj_ext *ext, uint32_t n_ext, uint64_t lo, uint64_t hi)
{
	uint32_t a = 0, z = n_ext;

	while (a < z) {                                 /* the extents are the NONE units, sorted by off */
		const uint32_t mid = a + (z - a) / 2u;

		if (ext[mid].off <= lo)
			a = mid + 1u;
		else
			z = mid;
	}
	return a && hi <= ext[a - 1u].off + ext[a - 1u].len;
}

/*
 * AN ALIGNMENT HOLE INSIDE A BODY IS THE BODY'S (FU-PM5-3, fixed 2026-11-17). The extent of a derived function is the union of its blocks, so the padding a
 * compiler puts between two runs of ONE body (behind a jump, before a loop head or a cold block of the same function) was a small NONE unit between two ranges
 * of the function (stripped twins: 41 x86-64 functions whose symbol holds the hole; the stripped and the unstripped copy of the same bytes then differ, R2).
 * The gap [a, z) between two consecutive runs of the same body is the body's when (1) no block of any path lies in it (the blocks are in address order: the
 * two are neighbours in the descent's own block table), (2) it is inside one extent of the descent (one NONE unit: no byte of a HIGH unit or of non-code),
 * and (3) the walk's one decode saw ONE run of padding instructions (nop of any width, int3: kgenome_diag_walk_pads, the same runs the walk keeps for every
 * reader) that covers it exactly. A gap with any other byte stays outside (it may be a function nothing reached): the rule claims no code, only padding.
 * TODO(owner): FU-PM5-3 asked whether such holes are claimed; default applied 2026-11-17: claimed (R2 41 -> 0 on the twins); the alternative is NONE units.
 */
struct hole {
	const struct kgenome_cfg_obj_ext *ext;
	uint32_t n_ext;
	const uint64_t *pad;            /* the walk's padding runs [from, to), sorted; NULL: no walk, no hole is claimed */
	uint32_t n_pad;
};

static int hole_is_body(const struct hole *h, uint32_t b0, uint32_t b1, uint64_t a, uint64_t z)
{
	uint64_t from;

	if (!h->pad || b1 != b0 + 1u || z <= a || !in_one_ext(h->ext, h->n_ext, a, z))
		return 0;
	return kgenome_fntab_pad_before(h->pad, h->n_pad, z, &from) && from <= a;
}

/*
 * A TAIL JUMP ACROSS SOMETHING ELSE STARTS A FUNCTION (PM5-D1, coordinator 2026-11-16). The body rule ("a jump to another entry is a tail call, a jump to any
 * other place is body") gave a function the code of another one when that one is reached ONLY by a tail jump (stripped twins: __uClibc_init absorbed
 * _stdio_init, raise absorbed kill, _start_c absorbed __libc_start_main: 93 of 1824 ends). A block `t` of entry e's body becomes an entry of its own (source
 * DERIVED_JUMP) when (1) a direct unconditional jump of e's body goes to it, (2) nothing of e's body reaches it by a fall-through or a conditional branch, and
 * (3) the run of contiguous blocks that holds it is separated from the nearest other run of e's body by something that is not padding: a byte of another unit
 * (outside the descent's extents: HIGH, or no code), a block the descent read (it belongs to another body or to none), or a byte that is not padding by
 * the walk's decode (hole_is_body). A gap that is one padding run is a hole of the body and is the body's (alignment after a jump). Facts of the blocks only: nothing is decoded.
 * When the gap is bytes nothing read that are not padding, the run is left NONE (isent 3): see the decision at `sep` below.
 * TODO(owner): default applied 2026-11-16 (promote when another unit's byte or block separates; 2026-11-17: leave NONE when only unknown bytes do); the
 * alternative for both is leaving such a range NONE.
 * `bl`/`cnt`: every entry's blocks in address order, entry by entry (cnt[e] ends e's slice); `pos`: a block's place in its slice; `pred` scratch.
 * Answers the number of blocks promoted.
 */
struct promo {
	const struct kgenome_cfg_obj *g;
	const struct hole *h;           /* the extents and the walk's padding runs: what a gap that does not separate is */
	uint8_t *isent;                 /* per block: 1 an entry of the descent, 2 promoted here, 3 left out (NONE: neither body nor a start), 0 not an entry */
	const uint32_t *own, *bl, *cnt, *pos;
	uint8_t *pred;                  /* scratch, per block */
};

static uint32_t promote_jumps(const struct promo *q)
{
	const struct kgenome_cfg_obj *g = q->g;
	const uint32_t *own = q->own, *bl = q->bl, *cnt = q->cnt, *pos = q->pos;
	uint8_t *isent = q->isent, *pred = q->pred;
	uint32_t b, n = 0;

	for (b = 0; b < g->n_b; b++)
		pred[b] = 0;
	/* bit 1: a direct unconditional jump of the same body goes to it; bit 2: a fall-through or a conditional branch of the same body does */
	for (b = 0; b < g->n_b; b++) {
		const struct kgenome_cfg_obj_block *x = &g->b[b];

		if (own[b] == KGENOME_CFG_NONE)
			continue;
		if (x->succ[0] != KGENOME_CFG_NONE && own[x->succ[0]] == own[b])
			pred[x->succ[0]] |= x->term == KGENOME_CFG_OBJ_T_JUMP ? 1u : 2u;
		if (x->succ[1] != KGENOME_CFG_NONE && own[x->succ[1]] == own[b])
			pred[x->succ[1]] |= 2u;
	}
	for (b = 0; b < g->n_b; b++) {
		uint32_t e, lo, hi, k0, k1, first, nb, i;
		uint64_t best = UINT64_MAX;
		int sep = 0, have = 0;          /* 0 a hole of the body, 1 unknown bytes, 2 something else's */

		if (isent[b] || (e = own[b]) == KGENOME_CFG_NONE || pred[b] != 1u)
			continue;
		first = e ? cnt[e - 1u] : 0u;
		nb = cnt[e] - first;
		/* the run of e's blocks that holds b: contiguous in the file */
		k0 = k1 = pos[b];
		while (k0 && g->b[bl[first + k0 - 1u]].off + g->b[bl[first + k0 - 1u]].len == g->b[bl[first + k0]].off)
			k0--;
		while (k1 + 1u < nb && g->b[bl[first + k1]].off + g->b[bl[first + k1]].len == g->b[bl[first + k1 + 1u]].off)
			k1++;
		for (i = k0; i <= k1; i++)
			if (isent[bl[first + i]])
				break;
		if (i <= k1)
			continue;                       /* the entry's own run: range 0, never cut */
		/* the nearest other run of the body, below or above; the gap to it */
		for (unsigned side = 0; side < 2u; side++) {
			if (side == 0 && k0 == 0)
				continue;
			if (side == 1 && k1 + 1u >= nb)
				continue;
			lo = side ? bl[first + k1] : bl[first + k0 - 1u];
			hi = side ? bl[first + k1 + 1u] : bl[first + k0];
			{
				const uint64_t a = g->b[lo].off + g->b[lo].len, z = g->b[hi].off;

				if (z - a < best) {
					best = z - a;
					/* sep 2: a block another path read lies between, or a byte outside the extent (HIGH, not code): the target starts a function.
					 * sep 0: the gap is a hole of the body (hole_is_body: one run of the walk's padding): body. sep 1: bytes nothing read that are not
					 * padding (2026-11-17, ARM twins): a function nobody calls (__libc_setup_tls was absorbed into the tail of the code that jumps to it)
					 * or this function's own data (a literal pool between two of its parts: promoting cut sysconf and _Unwind_VRS_Pop). Neither is
					 * known, so the target is NEITHER: its run is left out of every body (NONE) and the jumper is INCOMPLETE. */
					sep = hi - lo > 1u || !in_one_ext(q->h->ext, q->h->n_ext, a, z) ? 2 : hole_is_body(q->h, lo, hi, a, z) ? 0 : 1;
					have = 1;
				}
			}
		}
		if (have && sep) {
			isent[b] = sep == 2 ? 2u : 3u;
			n++;
		}
	}
	return n;
}
/* One derived function: entry block `eb`, its blocks `bl` (address order, `nb` of them). 0 when memory was refused. */
/* KNOWN DEFECT FPART-D3 (2026-11-17, M) [sev M]: emit makes a derived extent of blocks and padding only, so an ARM literal pool after (or inside) a function is
 * NONE. Trigger: any ARM function that loads a constant PC-relative. Effect: the derived end is short of the symbol by the pool (R2: about 180 ARM twin
 * functions), and a body that falls into an undeclared function ends inside that one's pool (R1: 2). Reproducer: /mnt/games/normtest/fix_part/h/r12.py (stripped twins, out/t4_twins/fail.txt).
 * Fix: the descent records the PC-relative load targets of each block; words of a gap that the body loads are the body's. */
struct one_fn {
	uint32_t eb;                    /* the entry block */
	int jumped;                     /* promoted from a tail jump (DERIVED_JUMP) */
	const uint32_t *bl;             /* its blocks, address order */
	uint32_t nb;
	uint16_t flags;                 /* KGENOME_FN_F_* of its blocks */
};

static int emit(const struct kgenome_func_set *s, const struct kgenome_cfg_obj *g, const struct one_fn *fn, const struct hole *h, struct kgenome_fntab_derived *d)
{
	const uint32_t eb = fn->eb, *bl = fn->bl, nb = fn->nb;
	const int jumped = fn->jumped;
	const uint16_t flags = fn->flags;
	const struct kgenome_cfg_obj_block *e = &g->b[eb];
	const struct kgenome_func_start *st = start_at(s, e->off);
	struct kgenome_func f;
	uint32_t i = 0;

	memset(&f, 0, sizeof f);
	f.off = e->off;
	f.trust = KGENOME_FN_TRUST_DERIVED;
	f.end_source = KGENOME_FN_E_REACH;
	f.flags = flags;
	if (e->flags & KGENOME_CFG_OBJ_B_ASSUMED)
		f.flags |= KGENOME_FN_F_ASSUMED_RET;
	if ((e->flags & KGENOME_CFG_OBJ_B_SEED) && st) {
		f.source = (uint16_t)(st->source | KGENOME_FN_S_DERIVED_SEED);
		f.value = st->value;
		f.shndx = st->shndx;
		f.kind = st->kind;
	}
	if (e->flags & KGENOME_CFG_OBJ_B_CALLED)
		f.source |= KGENOME_FN_S_DERIVED_CALL;
	if (jumped)
		f.source |= KGENOME_FN_S_DERIVED_JUMP;
	/* the runs of contiguous blocks: the one that holds the entry, from the entry on, is the first range; every other run (and the part of the entry's run
	 * before the entry) is a further range */
	while (i < nb) {
		uint64_t at = g->b[bl[i]].off, end = at + g->b[bl[i]].len;
		uint32_t j = i + 1u;

		while (j < nb && (g->b[bl[j]].off == end || hole_is_body(h, bl[j - 1u], bl[j], end, g->b[bl[j]].off))) {
			end = g->b[bl[j]].off + g->b[bl[j]].len;
			j++;
		}
		if (e->off >= at && e->off < end) {
			f.len = end - e->off;
			if (e->off > at && !kgenome_fntab_parts_add(d->parts, at, e->off - at, e->off))
				return 0;
		} else if (!kgenome_fntab_parts_add(d->parts, at, end - at, e->off)) {
			return 0;
		}
		i = j;
	}
	return kgenome_fntab_list_add(&d->fn, &f);
}

/* The passes of jump promotion one derivation may make (a DoS bound of work: an honest object needs one or two; a crafted chain of tail jumps each visible only
 * after the one before is promoted could need one per jump). Hit: the derivation says so (kgenome_fntab_derived.over, P_DERIVE_CAP) and keeps what it has. */
#define PROMOTE_PASSES 32u

/* The functions, from the blocks. 0 when memory was refused. */
static int functions(const struct kgenome_func_set *s, const struct kgenome_cfg_obj *g, const struct hole *h, struct kgenome_fntab_derived *d)
{
	uint32_t *ent = NULL, *own = NULL, *cnt = NULL, *bl = NULL, *pos = NULL, n_ent = 0, b, e, pass;
	uint16_t *fl = NULL;
	uint8_t *isent = NULL, *pred = NULL;
	int ok = 0;

	if (!g->n_b)
		return 1;
	ent = malloc((size_t)g->n_b * sizeof *ent);
	own = malloc((size_t)g->n_b * sizeof *own);
	bl = malloc((size_t)g->n_b * sizeof *bl);
	pos = malloc((size_t)g->n_b * sizeof *pos);
	fl = calloc(g->n_b, sizeof *fl);
	cnt = calloc((size_t)g->n_b + 1u, sizeof *cnt);
	isent = calloc(g->n_b, 1);
	pred = calloc(g->n_b, 1);
	if (!ent || !own || !bl || !pos || !fl || !cnt || !isent || !pred)
		goto out;
	for (b = 0; b < g->n_b; b++)                    /* pred is scratch here: a direct branch from a block below goes to it */
		if (g->b[b].succ[0] != KGENOME_CFG_NONE && g->b[g->b[b].succ[0]].off > g->b[b].off)
			pred[g->b[b].succ[0]] = 1u;
	for (b = 0; b < g->n_b; b++)
		isent[b] = is_entry(s, g, b, pred) ? 1u : 0u;
	for (pass = 0;; pass++) {
		n_ent = 0;
		for (b = 0; b < g->n_b; b++)
			if (isent[b])
				ent[n_ent++] = b;
		if (!bodies(g, isent, ent, n_ent, own, fl))
			goto out;
		/* the blocks of each function in address order: a counting sort by owner keeps the blocks' own order */
		memset(cnt, 0, ((size_t)n_ent + 1u) * sizeof *cnt);
		for (b = 0; b < g->n_b; b++)
			if (own[b] != KGENOME_CFG_NONE)
				cnt[own[b] + 1u]++;
		for (e = 0; e < n_ent; e++)
			cnt[e + 1u] += cnt[e];
		for (b = 0; b < g->n_b; b++)
			if (own[b] != KGENOME_CFG_NONE) {
				pos[b] = cnt[own[b]];
				bl[cnt[own[b]]++] = b;
			}
		for (b = 0; b < g->n_b; b++)                    /* the place in the entry's own slice */
			if (own[b] != KGENOME_CFG_NONE)
				pos[b] -= own[b] ? cnt[own[b] - 1u] : 0u;
		if (pass == PROMOTE_PASSES) {
			d->over = 1;                            /* the bound of passes: what is promoted stays, said */
			break;
		}
		{
			const struct promo q = { g, h, isent, own, bl, cnt, pos, pred };

			if (!promote_jumps(&q))
				break;
		}
	}
	for (b = 0; b < g->n_b; b++) {
		if (own[b] == KGENOME_CFG_NONE)
			continue;
		fl[own[b]] |= block_flags(&g->b[b]);
		for (unsigned k = 0; k < 2u; k++) {             /* a path into a run left out (isent 3): the jumper ran out of what it may claim */
			const uint32_t t = g->b[b].succ[k];

			if (t != KGENOME_CFG_NONE && isent[t] == 3u && own[t] != own[b])
				fl[own[b]] |= KGENOME_FN_F_INCOMPLETE;
		}
	}
	for (e = 0; e < n_ent; e++) {
		const uint32_t lo = e ? cnt[e - 1u] : 0u;
		const struct one_fn fn = { ent[e], isent[ent[e]] == 2u, bl + lo, cnt[e] - lo, fl[e] };

		if (isent[ent[e]] == 3u)
			continue;                               /* left out: its blocks are no function's (the builder's NONE refill holds them) */
		if (!emit(s, g, &fn, h, d))
			goto out;
	}
	ok = 1;
out:
	free(ent);
	free(own);
	free(cnt);
	free(bl);
	free(pos);
	free(fl);
	free(isent);
	free(pred);
	return ok;
}

void kgenome_fntab_derive(struct kgenome_fntab_run *r, const struct kgenome_func_set *s, struct kgenome_fntab_derived *d)
{
	struct kgenome_cfg_obj_ext *ext = NULL;
	struct kgenome_cfg_obj_seed *sd = NULL;
	struct kgenome_cfg_obj_req rq;
	struct kgenome_cfg_obj g;
	struct kgenome_cell_space sp;
	struct kgenome_budget bud;
	struct hole hl;
	const uint32_t parts0 = d->parts->n;
	uint32_t n_ext = 0, n_sd = 0, i;
	int thumb;

	memset(&g, 0, sizeof g);
	/* a PE of machine 0x1c2 / 0x1c4 is Thumb code throughout (its arch is ARM, the space's decoder A32): every start is skipped, as a Thumb start of an ELF is */
	thumb = r->obj->format == KGENOME_FMT_PE && (((const struct kgenome_pe_info *)r->obj->file_header)->machine == 0x1c2u ||
						     ((const struct kgenome_pe_info *)r->obj->file_header)->machine == 0x1c4u);
	if (!gather(s, thumb, &ext, &n_ext, &sd, &n_sd, &d->n_skipped)) {
		d->status = KGENOME_NOMEM;
		goto out;
	}
	if (!n_sd)
		goto out;
	kgenome_cell_space_init(&sp, r->obj, r->data, r->data_n);
	sp.raw = 1;             /* the instruction as the decoder writes it: what the walk's trace holds */
	/* the walk is the one decode of the object: the caller's (the scan), or one made here for a tool asking for the table alone (kgenome_diag_funcs_of; freed
	 * by the builder). Its padding runs decide which holes of a body are the body's (hole_is_body). */
	if (!r->walk)
		r->walk = r->own = kgenome_diag_walk_new();
	if (r->walk && kgenome_diag_walk_ensure(r->walk, r->obj, r->data, r->data_n, 1)) {
		(void)kgenome_diag_walk_hold(&sp, r->walk);
		r->pad = kgenome_diag_walk_pads(r->walk, &r->n_pad);
		r->walked = 1;
	}
	memset(&rq, 0, sizeof rq);
	rq.sp = &sp;
	rq.ext = ext;
	rq.n_ext = n_ext;
	rq.seed = sd;
	rq.n_seed = n_sd;
	memset(&bud, 0, sizeof bud);
	/* KNOWN DEFECT PM5-D5 (2026-11-17, R) [sev M]: the derivation (and the function table) is bounded by KGENOME_FNTAB_DERIVE_BYTES alone, plain malloc, not charged to the scan's
	 * ledger. Trigger: a large object with much undeclared code. Effect: up to 128 MiB outside the engine's memory cap (CLAUDE.md: one number for the whole engine).
	 * Reproducer: fix_pmeta5/followups.txt FU-PM5-9. Fix: a kgenome_budget in kgenome_diag_funcs_with_walk's request from the scanner's ledger. */
	bud.max_bytes = KGENOME_FNTAB_DERIVE_BYTES;
	rq.budget = &bud;
	switch (kgenome_cfg_obj_build(&rq, &g)) {
	case KGENOME_OK:
		break;
	case KGENOME_OVER_BUDGET:       /* the bound of memory: what was read before it is true; a body it cut ends STOP/BUDGET (INCOMPLETE) */
		d->over = 1;
		break;
	case KGENOME_NOMEM:
		d->status = KGENOME_NOMEM;
		goto out;
	default:                        /* no control-flow rules for the architecture: every seed derived nothing */
		d->n_skipped += n_sd;
		goto out;
	}
	for (i = 0; i < g.n_e; i++)
		if (g.e[i].blk == KGENOME_CFG_NONE)
			d->n_skipped++;
	for (i = 0; i < g.n_loose; i++) {
		const uint32_t fi = g.loose[i].why == KGENOME_CFG_OBJ_W_OUTSIDE ? kgenome_funcs_at(s, g.loose[i].target) : KGENOME_FUNCS_NONE;

		if (fi != KGENOME_FUNCS_NONE && s->v[fi].trust == KGENOME_FN_TRUST_HIGH && s->v[fi].off != g.loose[i].target)
			d->n_into_high++;
	}
	hl.ext = ext;
	hl.n_ext = n_ext;
	hl.pad = r->walked ? r->pad : NULL;
	hl.n_pad = r->walked ? r->n_pad : 0u;
	if (!functions(s, &g, &hl, d)) {
		d->status = KGENOME_NOMEM;
		kgenome_fntab_list_free(&d->fn);
		d->parts->n = parts0;           /* nothing derived: no part either */
	}
out:
	kgenome_cfg_obj_free(&g, NULL);
	free(ext);
	free(sd);
}
