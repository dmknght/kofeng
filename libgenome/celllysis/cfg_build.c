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
 *
 * Temporary memory is 9 bytes an instruction (target index 4, block index 4, class 1), one allocation, released
 * before return; the product is 24 bytes a block, one allocation.
 */
#include <string.h>

#include "cfg_private.h"

#define F_LEAD 0x10u
#define F_SLOT 0x20u
#define X_MASK 0x07u

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
		if (kgenome_cfg_op_is_flow(in[i].op)) {
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

		if (!(cls[i] & X_MASK)) {
			i++;
			continue;
		}
		if (isa->delay_slots) {
			if (i + 1u < n) {
				cls[i + 1u] |= F_SLOT;
				e = i + 1u;
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
	return KGENOME_OK;
}

/* The terminator of block [first, first + n_insn): the branch before the delay slot, if there is one. */
static uint32_t term_at(const uint8_t *cls, uint32_t first, uint32_t n_insn)
{
	uint32_t t = first + n_insn - 1u;

	return (cls[t] & F_SLOT) && t > first ? t - 1u : t;
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
	tmp_n = (size_t)r->n_in * (2u * sizeof *tj + 1u);
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
		switch (x) {
		case KGENOME_CFG_X_BR_COND:
			if (tj[t] != KGENOME_CFG_NONE) {
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
	kgenome_cfg_release(&r->mem, tmp, tmp_n);
	out->status = (r->cut || degraded || slot_missing) ? KGENOME_TRUNCATED : KGENOME_OK;
	return out->status;
}
