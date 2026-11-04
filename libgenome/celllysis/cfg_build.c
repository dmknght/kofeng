/*
 * cfg_build.c - the blocks and edges of one function, from instructions the caller decoded ONCE.
 *
 * Linear in the instructions, no recursion (an attacker chooses the nesting), no cap on the number of blocks
 * (rule 4: the input is bounded by the caller's extent and budget, the result is what it is). Five passes over
 * small byte/word arrays, which are the whole of the work:
 *
 *   1  classify every instruction through the ISA table (cfg_isa.c) and resolve each branch's target ONCE to an
 *      instruction index (binary search over the increasing addresses); a target that is not an instruction of
 *      the array leaves the function
 *   2  the leaders after every block end, the delay slot (when the row has one) joined to its branch
 *   3  the leaders at local targets; a target inside a delay slot is not a block start (it would split a branch
 *      from its slot): the edge is dropped, as an unaligned target is
 *   4  the block of every instruction, the blocks, and successors as BLOCK INDICES (rule 5)
 *   5  reachable blocks from the entry (an explicit stack), the degrees and the counts of what the reachable
 *      code holds
 *   6  REACH_INDIRECT (optional, cfg.h KGENOME_CFG_T_SWITCH): only when `req->switch_src.read_at` is supplied, every
 *      reachable block whose plain EXIT is an indirect jmp is tried against a switch/jump table - resolve_switches()
 *      below, run from the already-built blocks (nothing from passes 1-5 is redone). NULL switch_src (every caller
 *      today): this pass is not entered at all, so it costs nothing and nothing about passes 1-5 changes.
 *
 * Temporary memory is 9 bytes an instruction (target index 4, block index 4, class 1), one allocation, released
 * before return; the product is 24 bytes a block, one allocation, plus whatever pass 6 resolves (an opt-in cost:
 * see resolve_switches()).
 */
#include <string.h>

#include "cfg_private.h"

#define F_LEAD 0x10u
#define F_SLOT 0x20u
#define X_MASK 0x07u
/*
 * CL-3: the delay slot of an annulling MIPS branch (KGENOME_CELL_F_ANNUL: a "likely" branch, cell.h) that is NOT
 * taken does not run at all - unlike an ordinary delay slot (F_SLOT), which runs on both paths and so is merged
 * into the branch's own block. classify() decides ONCE, in pass 2, whether a particular branch gets this split
 * treatment (isa->delay_slots, a local BR_COND target, and room for a slot in the array - a branch-likely that
 * fails any of those keeps the ordinary merged-slot approximation) and records the decision as these two cls
 * bits, never re-derived from the raw `flags`/`cond` of a possibly-hostile instruction (rule 5: table lookup,
 * not re-analysis - a fuzzed `in[i].flags` with this bit set on an architecture that has no delay slots, or on
 * the very last instruction of a truncated array, must not trigger the split just because the bit is on):
 *   F_ANNUL_BR    the branch itself: kgenome_cfg_build's final pass gives its taken edge the slot's block and
 *                 its not-taken edge whatever follows the slot, instead of the target it would otherwise read.
 *   F_ANNUL_SLOT  the one-instruction block that IS the slot, reached only on the taken edge: classify() copies
 *                 the branch's resolved target into `tj[]` at its position, so the final pass can wire that
 *                 block's one successor straight to the target without re-deriving it.
 */
#define F_ANNUL_SLOT 0x08u
#define F_ANNUL_BR   0x40u

void *kgenome_cfg_alloc(const struct kgenome_cfg_mem *mem, size_t n)
{
	if (!n)
		n = 1;
	return mem && mem->alloc ? mem->alloc(mem->user, n) : malloc(n);
}

void kgenome_cfg_release(const struct kgenome_cfg_mem *mem, void *p, size_t n)
{
	if (!p)
		return;
	if (mem && mem->release)
		mem->release(mem->user, p, n ? n : 1);
	else
		free(p);
}

int kgenome_cfg_over(const struct kgenome_budget *bud, uint64_t bytes)
{
	return bud && bud->max_bytes && bytes > bud->max_bytes;
}

/* The instruction at exactly `va`, or KGENOME_CFG_NONE. */
static uint32_t find_va(const struct kgenome_cell_insn *in, uint32_t n, uint64_t va)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (in[mid].at_va < va)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < n && in[lo].at_va == va ? lo : KGENOME_CFG_NONE;
}

void kgenome_cfg_free(struct kgenome_cfg *g, const struct kgenome_cfg_mem *mem)
{
	if (!g)
		return;
	kgenome_cfg_release(mem, g->b, (size_t)g->n_all * sizeof *g->b);
	kgenome_cfg_release(mem, g->call, (size_t)g->call_cap_ * sizeof *g->call);
	kgenome_cfg_release(mem, g->switch_tgt, (size_t)g->switch_cap_ * sizeof *g->switch_tgt);
	memset(g, 0, sizeof *g);
}

/* Passes 1-3: classes, targets, leaders. Returns a status (BAD_INPUT: addresses not increasing). */
static enum kgenome_status classify(const struct kgenome_cfg_req *r, const struct kgenome_cfg_isa *isa, uint32_t *tj,
				    uint8_t *cls, int *degraded, int *slot_missing, uint32_t *n_calls_all)
{
	const struct kgenome_cell_insn *in = r->in;
	const uint32_t n = r->n_in;
	uint32_t i;

	for (i = 0; i < n; i++) {
		unsigned x = KGENOME_CFG_X_NONE;

		if (i && in[i].at_va <= in[i - 1u].at_va)
			return KGENOME_BAD_INPUT;
		tj[i] = KGENOME_CFG_NONE;
		if (in[i].op == KGENOME_CELL_CALL || kgenome_cfg_isa_is_syscall(isa, &in[i]))
			(*n_calls_all)++;
		/* FNR-1 fix (2026-11-04): a one-byte int3/hlt is the mark of a non-returning call (the MSVC
		 * "call does not return" idiom: `call X; int3`) only when it sits right after a CALL in this
		 * same instruction stream. An int3 found anywhere else in the body (instrumented or obfuscated
		 * code that carries int3 inline, e.g. `int3; jmp; mov; int3; code`) now falls through to the
		 * normal flow-class test below instead of unconditionally cutting the block. */
		/* FNR-4 (2026-11-04): the fallthrough above sends a bare int3/hlt not right after a CALL into the
		 * normal flow-class test (correct: FNR-1). What it left running past that byte - the reach walk,
		 * fntab_reach.c graph_of() - now stops at a genuine padding run (crosses_pad there) instead of
		 * crossing into whatever the decode runs on into. */
		if ((r->flags & KGENOME_CFG_F_TRAP_EXITS) && in[i].len == 1u && r->bytes && in[i].at < r->bytes_len &&
		    (r->bytes[in[i].at] == 0xccu || r->bytes[in[i].at] == 0xf4u) &&
		    i && in[i - 1u].op == KGENOME_CELL_CALL)
			x = KGENOME_CFG_X_EXIT;         /* the mark of a call that does not return (KGENOME_CFG_F_TRAP_EXITS) */
		else if (kgenome_cfg_op_is_flow(in[i].op)) {
			x = (unsigned)kgenome_cfg_isa_class(isa, &in[i], r->be, r->bytes, r->bytes_len, degraded);
			if (x == KGENOME_CFG_X_BR_COND || x == KGENOME_CFG_X_BR_JUMP) {
				const uint64_t t = in[i].target_va;

				if (t != KGENOME_BROKEN && t >= r->va_lo && t < r->va_hi)
					tj[i] = find_va(in, n, t);
				if (tj[i] == KGENOME_CFG_NONE) {        /* out of the function: a conditional exit is dropped, a jump leaves */
					if (x == KGENOME_CFG_X_BR_JUMP)
						x = KGENOME_CFG_X_EXIT;
					else
						x = (r->flags & KGENOME_CFG_F_SPLIT_EXITS) ? KGENOME_CFG_X_COND_EXIT : KGENOME_CFG_X_NONE;
				}
			}
		}
		cls[i] = (uint8_t)x;
	}
	if (!n)
		return KGENOME_OK;
	/* pass 2: ends of blocks and delay slots */
	cls[0] |= F_LEAD;
	for (i = 0; i < n;) {
		uint32_t e = i;
		const unsigned x = cls[i] & X_MASK;

		if (!x) {
			i++;
			continue;
		}
		if (isa->delay_slots) {
			if (i + 1u < n) {
				/*
				 * CL-3: an annulling branch (KGENOME_CELL_F_ANNUL) whose target is LOCAL
				 * (x == BR_COND: classify() above already turned a non-local target into
				 * COND_EXIT/NONE) does not merge its slot into this block - see F_ANNUL_SLOT's
				 * comment. Any other case (not annulling, or annulling but leaving the
				 * function - cfg-2's "no block end for an out-of-function conditional" must
				 * not change) keeps the ordinary merged-slot treatment.
				 */
				if ((in[i].flags & KGENOME_CELL_F_ANNUL) && x == KGENOME_CFG_X_BR_COND) {
					cls[i] |= F_ANNUL_BR;
					cls[i + 1u] |= F_LEAD | F_ANNUL_SLOT;
					tj[i + 1u] = tj[i];     /* may still be invalidated by pass 3 below */
					if (i + 2u < n)
						cls[i + 2u] |= F_LEAD;  /* the not-taken edge lands here */
				} else {
					cls[i + 1u] |= F_SLOT;
					e = i + 1u;
				}
			} else {
				*slot_missing = 1;
			}
		}
		if (e + 1u < n)
			cls[e + 1u] |= F_LEAD;
		i = e + 1u;
	}
	/* pass 3: local targets */
	for (i = 0; i < n; i++) {
		const unsigned x = cls[i] & X_MASK;

		if ((x != KGENOME_CFG_X_BR_COND && x != KGENOME_CFG_X_BR_JUMP) || (cls[i] & F_SLOT) || tj[i] == KGENOME_CFG_NONE)
			continue;
		if (cls[tj[i]] & F_SLOT)
			tj[i] = KGENOME_CFG_NONE;
		else
			cls[tj[i]] |= F_LEAD;
	}
	/*
	 * CL-3: an F_ANNUL_SLOT's tj[] was copied from its branch BEFORE pass 3 could invalidate the
	 * branch's own tj[i] (a target landing inside some other branch's slot); redone now that pass 3
	 * is final, from the branch that sits immediately before every such slot (classify() above never
	 * sets F_ANNUL_SLOT anywhere else).
	 */
	for (i = 1; i < n; i++)
		if (cls[i] & F_ANNUL_SLOT)
			tj[i] = tj[i - 1u];
	return KGENOME_OK;
}

/* The terminator of block [first, first + n_insn): the branch before the delay slot, if there is one. */
static uint32_t term_at(const uint8_t *cls, uint32_t first, uint32_t n_insn)
{
	uint32_t t = first + n_insn - 1u;

	return (cls[t] & F_SLOT) && t > first ? t - 1u : t;
}

/*
 * ---- REACH_INDIRECT (cfg.h, KGENOME_CFG_T_SWITCH): resolve an indirect jmp against a switch/jump table ----
 *
 * Runs ONLY when `req->switch_src.read_at` is non-NULL (resolve_switches() below is the single entry point, called
 * once from kgenome_cfg_build after blocks, successors and reach are final). Five steps, matching cfg.h's own
 * comment and the owner's design:
 *   1-2  switch_find_table(): the table's base/index/entry-size - directly from the jmp's own MEM operand (a direct
 *        `jmp [base+index*scale+disp]`), or from ONE producer found by a BACKWARD SCAN OF THE SAME BLOCK ONLY for
 *        `jmp reg` (a MOV/MOVZX/MOVSX/LEA that explicitly writes `reg` from an explicit MEM operand of the same
 *        shape). Not found in the block, or the producer's own base is a further register (a second hop): UNRESOLVED,
 *        and the block is left exactly as it was (a plain EXIT) - the fallback this whole feature must never regress.
 *   3    switch_find_bound_in(): a `cmp`/`sub index_reg, imm` in the SAME block, or - failing that - in the block's
 *        own SINGLE predecessor (switch_preds(): zero or more than one predecessor is not chased, cfg.h). Not found
 *        anywhere: KGENOME_CFG_SWITCH_MAX_CASES is the cost bound, and the block's `switch_capped` says so if every
 *        entry up to it still reads valid (rule 4: a cap is reported, never mistaken for the table's true end).
 *   4    the table is read entry by entry through `switch_src.read_at` (the caller's image/VA access - cfg_build.c
 *        has none), each candidate validated against the function's own extent [va_lo, va_hi) and against landing
 *        EXACTLY on a decoded instruction (find_va()); the first failure of either stops the site (switch_capped
 *        stays 0: this is the ordinary, expected end of a real table).
 *   5    N>=1 resolved targets make the block KGENOME_CFG_T_SWITCH with its targets in `out->switch_tgt[]`
 *        (instruction indices, exactly as `kgenome_cfg_call.insn` is - never block indices, and never folded into
 *        `succ[2]`/`reach`/`n_blk`/`n_edge`: cfg.h's own comment on the enum explains why). N==0 (nothing resolved
 *        at all): the block is untouched, still a plain EXIT - no partial, half-SWITCH state exists.
 *
 * NAMED LIMITS (rule: an algorithm is never wrong, name the limit). Not resolved by this round, falling back to the
 * existing EXIT behaviour exactly as before (verified by test: a real gcc -O2 PIC switch on ELF, AND a real
 * x86_64-w64-mingw32-gcc -O1/-O2/-O3 switch on PE - both use this shape and both stay unresolved; the x86 PE case
 * below uses the OTHER, already-resolving shape instead - M, tests/lib/genome/cfg_switch.c cases 8/9, 2026-11-05):
 *   - a base that is itself a register loaded by an EARLIER instruction (a second hop) - the common `-fPIC`/default
 *     position-independent shape (`lea base,[rip+table]; movsxd v,[base+idx*4]; add v,base; jmp v`), whose entries
 *     are 32-bit SIGNED DELTAS from the table's own base, not absolute pointers - interpreting them as absolute
 *     addresses is caught by the VA/find_va validation (small delta values essentially never equal a real VA) and
 *     falls back safely, but does not RESOLVE the common PIE case. This is NOT an ELF/Linux-only shape: measured
 *     (M) byte-for-byte identical (same `lea;mov;movslq;add;jmp`, only the argument register differs, ecx vs edi)
 *     from x86_64-w64-mingw32-gcc at -O1/-O2/-O3, with or without -fno-pic/-fPIC (all four combinations produce
 *     an identical .o on this host, gcc 14, mingw-w64 Debian cross package) - mingw's x64 switch-table codegen is
 *     this shape unconditionally, so a real x64 PE switch resolves here NO MORE OFTEN than a real default-PIC ELF
 *     one does (0 of 1 compiled fixtures, every optimisation level tried). Next algorithm: a second named shape
 *     that reads a 4-byte entry as `base + sign_extend(entry)` when scale==4 and entry size==4 but no absolute
 *     pointer validates - this is the one that would resolve x64 PE and default-PIC ELF alike.
 *   - 32-bit x86 PE, by contrast, DOES already resolve here, unchanged: i686-w64-mingw32-gcc -O1/-O2/-O3 emits the
 *     plain CASE_A shape (`jmp [idx*4+table]`, one instruction, absolute dir32 base) for the same switch, just
 *     scale/entry-size 4 instead of 8 (M, tests/lib/genome/cfg_switch.c case 9) - no new code needed for it.
 *   - the i386 GOT-relative table (`[ebx+idx*4+disp]` with ebx holding the GOT base): switch_const_base() only knows
 *     an absolute or RIP-relative base, as kgenome_cell_slot_of does for the single-slot case; the GOT base is a
 *     per-object fact (cell_slot.c's `gotbase`) this generic resolver is not given.
 *   - a chain of more than one hop (`lea`, then `add`, then `jmp`): bounded deliberately (cfg.h step 2: "a chain is
 *     not chased").
 */

/* The constant base VA of MEM operand `o`, encoded by `owner` (needed for a RIP-relative `disp`): 1 when it is one of
 * the two shapes this resolver trusts (an absolute address - truncated to what a 4-byte-wide addressing mode can
 * encode - or `[rip+disp]`), as kgenome_cell_slot_of (cell_slot.c) trusts for the single-slot case; 0 for a register
 * base (a further hop, not chased: see the NAMED LIMITS note above) or fs:/gs: (thread data, never a table). */
static int switch_const_base(const struct kgenome_cell_insn *owner, const struct kgenome_cell_operand *o, uint64_t *base_va)
{
	if (o->seg != KGENOME_CELL_REG_NONE && o->seg != KGENOME_CELL_SEG_DS)
		return 0;
	if (o->flags & KGENOME_CELL_OF_RIPREL) {
		if (owner->at_va == KGENOME_BROKEN)
			return 0;
		*base_va = owner->at_va + owner->len + (uint64_t)o->disp;
		return 1;
	}
	if (o->reg != KGENOME_CELL_REG_NONE)
		return 0;
	*base_va = o->size >= 8u ? (uint64_t)o->disp : (uint64_t)o->disp & 0xffffffffu;
	return 1;
}

/* Is `o` a packed array of pointers this resolver can read: a scaled index (a non-scaled MEM is a single slot, not a
 * table), an entry width of 4 or 8 bytes equal to the scale (a stride that does not match the read width is a shape
 * - e.g. a byte/word-indexed delta table - this round does not chase), and a constant base. */
static int switch_table_shape(const struct kgenome_cell_insn *owner, const struct kgenome_cell_operand *o, uint64_t *base_va)
{
	if (o->kind != KGENOME_CELL_O_MEM || o->index == KGENOME_CELL_REG_NONE)
		return 0;
	if (o->size != 4u && o->size != 8u)
		return 0;
	if (o->scale != o->size)
		return 0;
	return switch_const_base(owner, o, base_va);
}

/* Steps 1-2: the table of the indirect jmp at `ji` (whose own block is `[first, ji]`). Case (a): `jmp [...]` reads
 * its own operand. Case (b): `jmp reg` backward-scans [first, ji) - THIS BLOCK ONLY - for the nearest instruction
 * that writes `reg`; a MOV/MOVZX/MOVSX/LEA with an explicit destination operand naming `reg` and an explicit MEM
 * source of a table shape resolves it (one hop); anything else (an implicit write, a non-load opcode, no producer
 * in the block at all) is UNRESOLVED. */
static int switch_find_table(const struct kgenome_cell_insn *in, uint32_t first, uint32_t ji, uint64_t *base_va,
			     uint8_t *index_reg, uint32_t *entry_size)
{
	const struct kgenome_cell_insn *j = &in[ji];
	const struct kgenome_cell_operand *o = j->n_op ? &j->o[0] : NULL;
	uint32_t p;

	if (!o)
		return 0;
	if (o->kind == KGENOME_CELL_O_MEM) {
		if (!switch_table_shape(j, o, base_va))
			return 0;
		*index_reg = o->index;
		*entry_size = o->size;
		return 1;
	}
	if (o->kind != KGENOME_CELL_O_REG || o->reg == KGENOME_CELL_REG_NONE)
		return 0;
	for (p = ji; p > first;) {
		const struct kgenome_cell_insn *pi = &in[--p];
		const struct kgenome_cell_operand *mem = NULL;
		int has_dst = 0;
		uint32_t k;

		if (!(pi->wmask & (1ull << o->reg)))
			continue;
		if (pi->op != KGENOME_CELL_MOV && pi->op != KGENOME_CELL_MOVZX && pi->op != KGENOME_CELL_MOVSX && pi->op != KGENOME_CELL_LEA)
			return 0;        /* writes the register, but not a load this resolver trusts: one hop only */
		for (k = 0; k < pi->n_op; k++) {
			if (pi->o[k].kind == KGENOME_CELL_O_REG && pi->o[k].reg == o->reg)
				has_dst = 1;
			else if (pi->o[k].kind == KGENOME_CELL_O_MEM)
				mem = &pi->o[k];
		}
		if (!has_dst || !mem || !switch_table_shape(pi, mem, base_va))
			return 0;
		*index_reg = mem->index;
		*entry_size = mem->size;
		return 1;
	}
	return 0;        /* no producer in this block (cfg.h step 2: a chain across blocks is not chased) */
}

/* Step 3: a `cmp`/`sub index_reg, imm` in `in[lo, hi)`, nearest to `hi` first. 1 when found. */
static int switch_find_bound_in(const struct kgenome_cell_insn *in, uint32_t lo, uint32_t hi, uint8_t index_reg, uint64_t *bound)
{
	uint32_t p = hi;

	while (p > lo) {
		const struct kgenome_cell_insn *pi = &in[--p];

		if ((pi->op == KGENOME_CELL_CMP || pi->op == KGENOME_CELL_SUB) && pi->n_op == 2u &&
		    pi->o[0].kind == KGENOME_CELL_O_REG && pi->o[0].reg == index_reg && pi->o[1].kind == KGENOME_CELL_O_IMM) {
			*bound = pi->o[1].imm;
			return 1;
		}
	}
	return 0;
}

/* Step 3's "at most one predecessor block" (cfg.h): `pred1[k]` is the ONE block whose succ[0]/succ[1] targets `k`,
 * when there is exactly one; KGENOME_CFG_NONE for zero or several (never chased further - no chain of blocks).
 * O(n_all), one pass over the already-built, already-reachability-walked blocks; built lazily (resolve_switches()
 * below) only the first time a site's own block has no bound, so a function with no switch or whose switches are
 * all bounded in their own block never pays for it. */
static void switch_preds(const struct kgenome_cfg_block *b, uint32_t nb, uint32_t *pred1)
{
	uint32_t k;

	for (k = 0; k < nb; k++)
		pred1[k] = KGENOME_CFG_NONE;
	for (k = 0; k < nb; k++) {
		unsigned e;

		if (!b[k].reach)
			continue;
		for (e = 0; e < 2u; e++) {
			const uint32_t s = b[k].succ[e];

			if (s != KGENOME_CFG_NONE)
				pred1[s] = pred1[s] == KGENOME_CFG_NONE ? k : nb;      /* nb: never a valid index - "ambiguous" */
		}
	}
	for (k = 0; k < nb; k++)
		if (pred1[k] == nb)
			pred1[k] = KGENOME_CFG_NONE;
}

/* Append one resolved target (an instruction index) to the function's switch_tgt array, doubling it as cfg_build.c's
 * other products are grown - budget-checked by the total size, through the caller's allocator. 0 on a refusal
 * (OVER_BUDGET or NOMEM): the caller stops reading this table (cfg.h: a cap is reported, not silent), but every
 * target already pushed - for this site and any earlier one - stays. */
static int switch_tgt_push(const struct kgenome_cfg_req *r, struct kgenome_cfg *out, uint32_t v)
{
	if (out->n_switch_tgt == out->switch_cap_) {
		const uint32_t newcap = out->switch_cap_ ? out->switch_cap_ * 2u : 64u;
		uint32_t *nv;

		if (kgenome_cfg_over(r->budget, (uint64_t)newcap * sizeof *nv))
			return 0;
		nv = kgenome_cfg_alloc(&r->mem, (size_t)newcap * sizeof *nv);
		if (!nv)
			return 0;
		if (out->switch_tgt) {
			memcpy(nv, out->switch_tgt, (size_t)out->n_switch_tgt * sizeof *nv);
			kgenome_cfg_release(&r->mem, out->switch_tgt, (size_t)out->switch_cap_ * sizeof *nv);
		}
		out->switch_tgt = nv;
		out->switch_cap_ = newcap;
	}
	out->switch_tgt[out->n_switch_tgt++] = v;
	return 1;
}

/* Pass 6: see the family comment above. Reads at most KGENOME_CFG_SWITCH_MAX_CASES entries (or the found bound,
 * whichever is smaller) per site; a `switch_src.read_at` refusal, an out-of-extent target or a target that is not
 * an instruction's own address stops THAT site (not the function: the next candidate is still tried) and is the
 * expected, silent-nothing end of resolution for it. An allocation refusal while pushing a target stops ALL further
 * resolution (further allocations would likely refuse too) but never touches the blocks/reach/calls already built:
 * the function's graph is complete regardless of what this optional pass could or could not add. */
static enum kgenome_status resolve_switches(const struct kgenome_cfg_req *r, const uint8_t *cls, struct kgenome_cfg *out)
{
	struct kgenome_cfg_block *b = out->b;
	const uint32_t nb = out->n_all;
	uint32_t *pred1 = NULL;
	enum kgenome_status st = KGENOME_OK;
	int have_preds = 0, abort_all = 0;
	uint32_t k;

	if (!r->switch_src.read_at)
		return KGENOME_OK;
	for (k = 0; k < nb && !abort_all; k++) {
		const uint32_t ji = term_at(cls, b[k].first, b[k].n_insn);
		const struct kgenome_cell_insn *j = &r->in[ji];
		uint64_t base_va = 0, bound = 0;
		uint8_t index_reg = KGENOME_CELL_REG_NONE;
		uint32_t entry_size = 0, cap_cases, start, n = 0;
		int have_bound;

		if (!b[k].reach || b[k].term != KGENOME_CFG_T_EXIT)
			continue;
		if (j->op != KGENOME_CELL_JMP || !(j->flags & KGENOME_CELL_F_INDIRECT))
			continue;
		if (!switch_find_table(r->in, b[k].first, ji, &base_va, &index_reg, &entry_size))
			continue;        /* UNRESOLVED (step 1-2): left as a plain EXIT, exactly as before */
		have_bound = switch_find_bound_in(r->in, b[k].first, ji, index_reg, &bound);
		if (!have_bound) {
			if (!have_preds) {
				if (kgenome_cfg_over(r->budget, (uint64_t)nb * sizeof *pred1)) {
					st = kgenome_status_merge(st, KGENOME_OVER_BUDGET);
					break;
				}
				pred1 = kgenome_cfg_alloc(&r->mem, (size_t)nb * sizeof *pred1);
				if (!pred1) {
					st = kgenome_status_merge(st, KGENOME_NOMEM);
					break;
				}
				switch_preds(b, nb, pred1);
				have_preds = 1;
			}
			if (pred1[k] != KGENOME_CFG_NONE) {
				const uint32_t pb = pred1[k];
				const uint32_t pji = term_at(cls, b[pb].first, b[pb].n_insn);

				have_bound = switch_find_bound_in(r->in, b[pb].first, pji, index_reg, &bound);
			}
		}
		cap_cases = (have_bound && bound < (uint64_t)KGENOME_CFG_SWITCH_MAX_CASES - 1u) ? (uint32_t)bound + 1u : KGENOME_CFG_SWITCH_MAX_CASES;
		/* "capped" is reported only when the COST BOUND (not a real found bound) is what limited the read: a
		 * found bound read to its exact end is the table's true size, not a cap (rule 4: a cap is reported,
		 * a correct complete answer is not mistaken for one). */
		start = out->n_switch_tgt;
		for (n = 0; n < cap_cases; n++) {
			uint8_t raw[8];
			uint64_t tva;
			uint32_t idx;

			if (!r->switch_src.read_at(r->switch_src.user, base_va + (uint64_t)n * entry_size, raw, entry_size))
				break;
			tva = entry_size == 8u
				? (r->be ? ((uint64_t)raw[0] << 56 | (uint64_t)raw[1] << 48 | (uint64_t)raw[2] << 40 | (uint64_t)raw[3] << 32 |
					    (uint64_t)raw[4] << 24 | (uint64_t)raw[5] << 16 | (uint64_t)raw[6] << 8 | raw[7])
					 : ((uint64_t)raw[7] << 56 | (uint64_t)raw[6] << 48 | (uint64_t)raw[5] << 40 | (uint64_t)raw[4] << 32 |
					    (uint64_t)raw[3] << 24 | (uint64_t)raw[2] << 16 | (uint64_t)raw[1] << 8 | raw[0]))
				: (r->be ? ((uint64_t)raw[0] << 24 | (uint64_t)raw[1] << 16 | (uint64_t)raw[2] << 8 | raw[3])
					 : ((uint64_t)raw[3] << 24 | (uint64_t)raw[2] << 16 | (uint64_t)raw[1] << 8 | raw[0]));
			if (tva < r->va_lo || tva >= r->va_hi)
				break;
			idx = find_va(r->in, r->n_in, tva);
			if (idx == KGENOME_CFG_NONE)
				break;
			if (!switch_tgt_push(r, out, idx)) {
				st = kgenome_status_merge(st, KGENOME_NOMEM);
				abort_all = 1;
				break;
			}
		}
		if (n) {
			b[k].term = KGENOME_CFG_T_SWITCH;
			b[k].switch_first = start;
			b[k].n_switch = n;
			b[k].switch_capped = (uint8_t)(n == cap_cases && cap_cases == KGENOME_CFG_SWITCH_MAX_CASES ? 1u : 0u);
		}
	}
	kgenome_cfg_release(&r->mem, pred1, (size_t)nb * sizeof *pred1);
	return st;
}

/* CONSOLIDATION cfg-1 (2026-10-30, M): the lineage builder resolved every target by find_va and every edge by block_of ON EACH VISIT of a block;
 * here once, as indices. Same answer for instructions in address order; an array that is not strictly increasing was searched anyway and
 * answered wrongly and silently, here it is BAD_INPUT. Tests: cfg_build.c (ordering, unaligned target), diag lineage tests (identical links). */
/* CONSOLIDATION cfg-2 (2026-10-30, M): the old builder ended a block after EVERY jcc/loop, also one whose target leaves the function; the
 * signature must not (a conditional tail call is no block end, the survey's winner). KGENOME_CFG_F_SPLIT_EXITS keeps the old granularity for
 * the lineage, whose per-block predicates and stage selection follow the blocks. Test: cfg_build.c split_exits. */
/* CONSOLIDATION cfg-3 (2026-10-30, M): better here, and changing lineage on the inputs named: iret ends the flow (old: the block went on), an
 * ARM conditional bx/ldm/ldr/mov to pc keeps its fall-through (old: always an exit), AArch64 b.al/b.nv is a jump (old: also a fall edge), a MIPS
 * delay slot is in its branch's block and `b` is a jump (old: neither; the lineage reads x86 only today). Tests: cfg_isa.c rows, cfg_build.c iret. */
/* CONSOLIDATION cfg-4 (2026-10-30, R): kept in the lineage and NOT here: a call that does not return (kgenome_lineage_call_noreturn: the site
 * table, the callee's summary) cuts the rest of the block and its edges in block_run. It depends on a callee's identity, which the signature must
 * not (cfg.h). Not a block end here, so a block after `call exit` is reachable in the signature's graph. Test: the lineage tests. */
/* CONSOLIDATION cfg-6 (2026-10-30, R): carried over as is: a direct jmp with a BROKEN target (a relocation hole of an ET_REL / .ko) is not local, so it
 * leaves the function like the old tail rule; ret N (stdcall) is RET; a PE thunk (only `jmp [slot]`) is a one-block EXIT function, under the anchor.
 * Kept in the lineage: a jmp that lands on a node site is a tail jump (kgenome_lineage_jmp_is_tail asks the site table), the stdcall pop and thunk_slot
 * are state and import matters. Tests: cfg_build.c consolidation (hole, ret N), cfg_isa.c rows. */
/* CONSOLIDATION cfg-5 (2026-10-30, R): the seed stage enters blocks no walk reached, so ALL blocks are kept (n_all) and `reach` is added (the old
 * builder had none: the signature counts reachable blocks only). No cap on blocks in either; old charged n_in*6+8 bytes, here 9 n_in + 24 n_blk
 * through the caller's allocator, with OVER_BUDGET / NOMEM and nothing leaked. Test: cfg_hostile.c. */
enum kgenome_status kgenome_cfg_build(const struct kgenome_cfg_req *r, struct kgenome_cfg *out)
{
	const struct kgenome_cfg_isa *isa;
	enum kgenome_status st;
	struct kgenome_cfg_block *b;
	uint8_t *tmp, *cls;
	uint32_t *tj, *bo, nb = 0, i, k, sp, n_calls_all = 0;
	size_t tmp_n;
	int degraded = 0, slot_missing = 0;

	memset(out, 0, sizeof *out);
	if (!r || (!r->in && r->n_in)) {
		out->status = KGENOME_BAD_INPUT;
		return out->status;
	}
	isa = kgenome_cfg_isa_of(r->arch);
	if (!isa) {
		out->status = KGENOME_UNSUPPORTED;
		return out->status;
	}
	if (!r->n_in) {
		out->status = r->cut ? KGENOME_TRUNCATED : KGENOME_OK;
		return out->status;
	}
	tmp_n = (size_t)r->n_in * KGENOME_CFG_BUILD_BYTES_PER_INSN;
	if (kgenome_cfg_over(r->budget, tmp_n)) {
		out->status = KGENOME_OVER_BUDGET;
		return out->status;
	}
	tmp = kgenome_cfg_alloc(&r->mem, tmp_n);
	if (!tmp) {
		out->status = KGENOME_NOMEM;
		return out->status;
	}
	tj = (uint32_t *)(void *)tmp;
	bo = tj + r->n_in;
	cls = (uint8_t *)(bo + r->n_in);
	st = classify(r, isa, tj, cls, &degraded, &slot_missing, &n_calls_all);
	if (st != KGENOME_OK) {
		kgenome_cfg_release(&r->mem, tmp, tmp_n);
		out->status = st;
		return st;
	}
	/* pass 4: the block of every instruction */
	for (i = 0; i < r->n_in; i++) {
		if (cls[i] & F_LEAD)
			nb++;
		bo[i] = nb - 1u;
	}
	if (kgenome_cfg_over(r->budget, tmp_n + (uint64_t)nb * sizeof *b + (uint64_t)n_calls_all * sizeof *out->call)) {
		kgenome_cfg_release(&r->mem, tmp, tmp_n);
		out->status = KGENOME_OVER_BUDGET;
		return out->status;
	}
	b = kgenome_cfg_alloc(&r->mem, (size_t)nb * sizeof *b);
	if (!b) {
		kgenome_cfg_release(&r->mem, tmp, tmp_n);
		out->status = KGENOME_NOMEM;
		return out->status;
	}
	for (i = 0, k = 0; i < r->n_in; i++) {
		if (cls[i] & F_LEAD) {
			memset(&b[k], 0, sizeof b[k]);
			b[k].first = i;
			b[k].at = r->in[i].at_va < r->va_lo ? 0u : r->in[i].at_va - r->va_lo > UINT32_MAX ? UINT32_MAX : (uint32_t)(r->in[i].at_va - r->va_lo);
			b[k].succ[0] = b[k].succ[1] = KGENOME_CFG_NONE;
			if (k)
				b[k - 1u].n_insn = i - b[k - 1u].first;
			k++;
		}
	}
	b[nb - 1u].n_insn = r->n_in - b[nb - 1u].first;
	for (k = 0; k < nb; k++) {
		const uint32_t t = term_at(cls, b[k].first, b[k].n_insn);
		const unsigned x = cls[t] & X_MASK;
		const uint32_t next = k + 1u < nb ? k + 1u : KGENOME_CFG_NONE;

		b[k].term = KGENOME_CFG_T_FALL;
		if (cls[t] & F_ANNUL_SLOT) {
			/*
			 * CL-3: this one-instruction block IS the delay slot of an annulling branch,
			 * reached only on the taken edge (the branch's own block, below, points its
			 * not-taken edge past it): its one successor is the branch's already-resolved
			 * target, copied into tj[t] by classify()'s own follow-up pass.
			 */
			if (tj[t] != KGENOME_CFG_NONE) {
				b[k].term = KGENOME_CFG_T_JUMP;
				b[k].succ[0] = bo[tj[t]];
			} else {
				b[k].term = KGENOME_CFG_T_EXIT;        /* the target left the function (pass 3 dropped it) */
			}
		} else switch (x) {
		case KGENOME_CFG_X_BR_COND:
			if (cls[t] & F_ANNUL_BR) {
				/* CL-3: taken runs the slot block (wired to the target above); not-taken
				 * skips the slot entirely, straight to whatever follows it. */
				b[k].term = KGENOME_CFG_T_COND;
				b[k].succ[0] = next;
				b[k].succ[1] = (next != KGENOME_CFG_NONE && next + 1u < nb) ? next + 1u : KGENOME_CFG_NONE;
			} else if (tj[t] != KGENOME_CFG_NONE) {
				b[k].term = KGENOME_CFG_T_COND;
				b[k].succ[0] = bo[tj[t]];
				b[k].succ[1] = next;
			} else {
				b[k].succ[0] = next;
			}
			break;
		case KGENOME_CFG_X_BR_JUMP:
			if (tj[t] != KGENOME_CFG_NONE) {
				b[k].term = KGENOME_CFG_T_JUMP;
				b[k].succ[0] = bo[tj[t]];
			} else {
				b[k].term = KGENOME_CFG_T_EXIT;
			}
			break;
		case KGENOME_CFG_X_EXIT:
			b[k].term = KGENOME_CFG_T_EXIT;
			break;
		default:        /* NONE, COND_EXIT: on to the next block (none after the last: the function runs off its end) */
			b[k].succ[0] = next;
			break;
		}
		b[k].out_deg = (uint8_t)((b[k].succ[0] != KGENOME_CFG_NONE) + (b[k].succ[1] != KGENOME_CFG_NONE));
	}
	out->b = b;
	out->n_all = nb;
	if (n_calls_all) {
		out->call = kgenome_cfg_alloc(&r->mem, (size_t)n_calls_all * sizeof *out->call);
		if (!out->call) {
			kgenome_cfg_release(&r->mem, tmp, tmp_n);
			kgenome_cfg_free(out, &r->mem);
			out->status = KGENOME_NOMEM;
			return out->status;
		}
		out->call_cap_ = n_calls_all;
	}
	/* pass 5: reachable blocks, degrees, counts. The stack reuses the block-index array: edges are resolved. */
	sp = 0;
	b[0].reach = 1;
	bo[sp++] = 0;
	while (sp) {
		const struct kgenome_cfg_block *x = &b[bo[--sp]];
		unsigned e;

		for (e = 0; e < 2u; e++) {
			const uint32_t s = x->succ[e];

			if (s == KGENOME_CFG_NONE)
				continue;
			b[s].in_deg++;
			out->n_edge++;
			if (!b[s].reach) {
				b[s].reach = 1;
				bo[sp++] = s;
			}
		}
	}
	for (k = 0; k < nb; k++) {
		uint32_t q;

		if (!b[k].reach)
			continue;
		out->n_blk++;
		b[k].call_first = out->n_call;
		for (q = b[k].first; q < b[k].first + b[k].n_insn; q++) {
			const int sys = kgenome_cfg_isa_is_syscall(isa, &r->in[q]);

			out->n_sys += (uint32_t)sys;
			if (r->in[q].op == KGENOME_CELL_CALL || sys) {
				struct kgenome_cfg_call *c = &out->call[out->n_call++];

				c->insn = q;
				c->id = 0;
				c->kind = sys ? KGENOME_CFG_CK_SYSCALL : (r->in[q].flags & KGENOME_CELL_F_INDIRECT) ? KGENOME_CFG_CK_INDIRECT : KGENOME_CFG_CK_DIRECT;
				if (r->callee.id_of) {
					uint8_t kind = 0;

					c->id = r->callee.id_of(r->callee.user, q, &r->in[q], &kind);
					if (kind)
						c->kind = kind;
				}
				b[k].call_kinds |= (uint8_t)(1u << (c->kind & 7u));
				b[k].n_call++;
			}
			if (r->site && r->site[q])
				out->n_site++;
		}
	}
	/* pass 6 (REACH_INDIRECT, optional, additive): uses `cls` still, so it runs before `tmp` (which holds it) is released. */
	out->status = kgenome_status_merge((r->cut || degraded || slot_missing) ? KGENOME_TRUNCATED : KGENOME_OK,
					   resolve_switches(r, cls, out));
	kgenome_cfg_release(&r->mem, tmp, tmp_n);
	return out->status;
}
