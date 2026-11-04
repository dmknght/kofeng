/*
 * fntab_reach.c - THE REACH STEP of the function table (PE x86 / x64): the end of an open entry is the end of what its entry reaches, and a gap behind a body is a function when the bytes
 * in it are code that ends.
 *
 * WHY. An entry whose end no source declared (a call target, an export, a TLS callback, a leaf with no unwind entry) was closed by the NEXT START less the padding. A start the walk did
 * not find (a function nothing calls directly) is then swallowed by the entry before it, and the data a compiler puts behind a function (a jump table, a string) is swallowed with it.
 * Measured on the PE oracle (h/oracle.c: 81 x64 images, the exception table hidden, the table's own entries as truth): of 83528 functions the ends were right for 55319 and LONG for 8089
 * (5.1 MB of other functions or data inside them). The oracle is the file's own: this step is judged against it (see STATUS.md), not against another tool.
 *
 * THE RULE. The graph of the entry is built over [start, bound) (kgenome_frame_make: the walk's trace, no second decode; the bound is kgenome_fntab_bound: the next start or the end of the
 * extent), and the end is the end of the last instruction of a block reachable from the start. On PE x86 the `int3` or `hlt` after a call is the exit of the path (the compiler's mark that the call
 * does not return: the frame sets KGENOME_CFG_F_TRAP_EXITS for a PE), so code behind a noreturn call is not "reached" through it.
 *
 * WHAT IT DOES NOT SAY, as a state on the entry and never as a silent cut (rule 4; the end stays the next start, flag END_OPEN, and the ends step closes it as before):
 *   REACH_INDIRECT  a reachable `jmp` through a register or an indexed table: the code of a switch is reached only through its table, so what is reached is a lower bound. NEXT: read the table
 *                   (the `lea` of its base and the bounded `cmp`/`ja` before the jump) and add its targets as edges.
 *   REACH_NONE      the entry has no graph (the trace holds none, the bytes do not decode, the reached code crosses bytes that decode as nothing, a bound of cost fired).
 *   REACH_OPEN      the reached code runs on into the next start: the next start may be inside this function (a false start: a call target in data), or the call before it does not return and
 *                   carries no mark. NEXT: drop a start that nothing but the walk names when the code before it flows into it with no padding between.
 * Code that only an unwinder reaches (an x86 SEH handler, reached through a scope table) is not reached either: it is cut. The PE x64 images have those as entries of their own in the exception table.
 *
 * THE GAPS. The code behind the covered end of an entry, up to the next start, is padding, data or a function with no entry. The first byte past the padding (the runs the decode saw) is a START when
 * the graph from it is made of code that ends: its first bytes are not the zero fill, every reached block decodes with nothing skipped, and the reached code ends (a `ret`, a jump out, a call that
 * does not return) before the bound. Data fails that (a jump table decodes as `add [rax],al` and junk, and does not end). What the check cannot say - a function whose code runs on into the next start
 * - is not made a start: the gap stays unnamed. A start is made inside no range the merge left out of the table (the chained fragments of an unwind table: `cover`).
 *
 * COST. Each entry is read over a window that starts at WIN0 bytes (256: most functions are shorter) and grows by 4 while the reached code runs past it (a branch beyond the window or no terminator in it), up to WIN_MAX; at that bound
 * the entry is REACH_NONE. The work is the entry's own size, not the bound's: a gap of data with many candidate starts costs each its own window.
 */
#include "fntab_build_private.h"
#include <kgenome_budget.h>
#include <genotype/image/fntab_private.h>
#include "frame.h"

#define REACH_WIN0 256ull
#define REACH_WIN_MAX (1ull << 20)

/* FNR-2: a cost cap on how many distinct real branch targets one graph_of() call records in `reach.link[]`
 * (see struct reach below), not a correctness cap - a function with more distinct forward targets than this
 * just stops gaining new linked-gap evidence past the cap, so a real absorption may be missed (conservative:
 * the gap is then left unnamed, never wrongly merged). */
#define REACH_LINK_MAX 8u

enum { R_OK = 0, R_OPEN, R_INDIRECT, R_NONE };

/* The instruction a function BEGINS with: `push r`, `sub rsp,n`, `mov rax,rsp`, or a store into [rsp+n] / [rbp+n] (the compilers' prologues; it is evidence of a start, never a proof). */
static int entry_insn(const struct kgenome_cell_insn *in)
{
	if (in->op == KGENOME_CELL_PUSH)
		return in->n_op && in->o[0].kind == KGENOME_CELL_O_REG;
	if (in->op == KGENOME_CELL_SUB)
		return in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == KGENOME_CELL_REG_SP;
	if (in->op == KGENOME_CELL_MOV && in->n_op == 2u) {
		if (in->o[0].kind == KGENOME_CELL_O_MEM && (in->o[0].reg == KGENOME_CELL_REG_SP || in->o[0].reg == KGENOME_CELL_REG_BP) && in->o[1].kind == KGENOME_CELL_O_REG)
			return 1;
		return in->o[0].kind == KGENOME_CELL_O_REG && in->o[1].kind == KGENOME_CELL_O_REG && in->o[1].reg == KGENOME_CELL_REG_SP;
	}
	return 0;
}

struct reach {
	uint64_t end;           /* the end of the last reachable instruction (file offset), with R_OK and R_OPEN */
	int st;                 /* R_* */
	int hole;               /* the reached code has bytes that decode as nothing in it */
	int has_call;           /* a reachable CALL stands in this graph: it cannot be the compiler's dead tail block (FNR-2) */
	int has_trap;           /* a reachable one-byte int3/hlt stands in this graph and is NOT right after a call (FNR-2v2): classify() exits a path on the call-marked one only
				  * (FNR-1; defect FNR-4, cfg_build.c), so this one fell through the graph as ordinary code - it is alignment padding the graph walked across,
				  * not a second body's own bytes, whatever `has_call` says of the rest of the chunk */
	int entry_like;         /* the first instruction is one a function begins with (a push, `sub rsp`, a store into the home space) */
	uint64_t open_end;      /* where the first run of padding begins that follows a reached call (or the call's mark): the end of a body that runs on into padding, or 0 */
	int nomem;              /* the graph could not be made for want of memory (a state of the table, not of the entry: it is short) */
	int fell;               /* the reached code ends by falling into an int3 (the padding of the next function) and not by a ret, a jump or a call that does not return: what stands here is not known to be a body */
	int cut_by_pad;         /* FNR-4: st==R_OK only because the walk hit a genuine padding run (crosses_pad), not because a real ret/jmp-exit/trap-exit was reached - true evidence of where a KNOWN
				  * entry's own end is (apply() uses it unconditionally), but never evidence that the bytes BEFORE it are themselves "code that ends" (plausible() must still refuse: a
				  * candidate gap start cut off by padding before any real terminator is exactly as inconclusive as one that ran off the window edge) */
	uint64_t cut;           /* the smallest target of a reached branch that stands right behind an int3 (a function the entry jumps to: its first byte), or 0 */
	uint64_t hint;          /* with `cut`: the start the entry's reach was stopped at, the first byte of the next function by the evidence of the jump */
	/* FNR-2: every distinct address, inside [off, bound), that a REACHED direct jmp/jcc/loop of this graph names as its target - the general
	 * form of `cut` with the padded_start() filter dropped, so a gap-absorption decision can ask "did this body's own control flow really
	 * point here" instead of re-decoding the candidate in isolation and trusting that it merely LOOKS like it ends (rule: a cap bounds cost,
	 * never deletes evidence - REACH_LINK_MAX just stops recording further distinct targets, it never turns a real one into a fake one). */
	uint64_t link[REACH_LINK_MAX];
	uint32_t n_link;
};

struct first_n { struct kgenome_cell_insn in[3]; uint32_t n; };

static void first_cb(void *user, const struct kgenome_cell_insn *in)
{
	struct first_n *c = user;

	if (in && c->n < 3u)
		c->in[c->n++] = *in;
}

/* The first (up to 3) instructions at `at`, read from the walk's trace (a start of the table is a record of it, and the code behind it was walked); no decode of its own. */
static uint32_t first_insns(const struct kgenome_fntab_run *r, uint64_t at, struct first_n *c)
{
	c->n = 0;
	if (at < r->data_n)
		kgenome_diag_code_run(&(const struct kgenome_diag_code_req){ .obj = r->obj, .base = r->data, .size = r->data_n, .off = at,
			.n = r->data_n - at < 32u ? r->data_n - at : 32u, .va = kgenome_image_off_to_addr(r->obj, at), .fn = first_cb, .user = c, .wk = r->walk });
	return c->n;
}

/* Is there a call and its mark (the one-byte nop or int3 right after: the compiler's sign that the call does not return) at `at`? Their length, or 0. */
static uint32_t call_mark_at(const struct kgenome_fntab_run *r, uint64_t at)
{
	struct first_n c;

	if (first_insns(r, at, &c) < 2u || c.in[0].op != KGENOME_CELL_CALL || c.in[1].len != 1u ||
	    (c.in[1].op != KGENOME_CELL_NOP && c.in[1].op != KGENOME_CELL_INT))
		return 0;
	return c.in[0].len + c.in[1].len;
}


/* The first byte at or after `at` that is not inside a run of padding instructions (the runs stand at most 15 bytes and may begin before `at`). */
static uint64_t skip_pad(const uint64_t *pad, uint32_t n_pad, uint64_t at)
{
	for (;;) {
		uint32_t lo = 0, hi = n_pad;

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (pad[2u * mid] <= at)
				lo = mid + 1u;
			else
				hi = mid;
		}
		if (lo && pad[2u * (lo - 1u) + 1u] > at)
			at = pad[2u * (lo - 1u) + 1u];
		else
			return at;
	}
}

/* FNR-4 (2026-11-04): is `at`, the next byte the reach walk is about to cross, the start of a genuine RUN of
 * int3/hlt (r->pad, longer than one byte)? classify() (FNR-1) no longer ends a block at a bare int3/hlt unless it
 * follows a CALL, so decode can run straight through such a run into whatever stands behind it - usually the next
 * function; the reach must stop at the run's first byte and never cross it.
 *
 * NARROWED TO int3/hlt ONLY, measured: the first version matched any kind of run in r->pad (nop included) and
 * regressed the PE oracle catastrophically (`ok` 45314->11360 DISTINCT, `short` 61->21421, `missed` 848->13560,
 * `split` 90->10078 on pe120 -p). r->pad also records the compiler's own multi-byte NOP alignment
 * (`0f1f8000000000`, `66(66)*0f1f84...`), which stands INSIDE a function for I$/branch alignment far more often
 * than it ever stands between two of them (real examples pulled from the regression: corp300/121_229.bin+0xa8c0,
 * +0x2b280) - a NOP is the compiler's own choice BECAUSE it is safe to fall through; an int3/hlt run is not (MSVC
 * uses it exactly because nothing should ever reach it, which is the one place FNR-1/FNR-4 ever talk about: "a
 * one-byte int3/hlt"). So only int3/hlt bytes count here; a NOP/self-lea/zero-word run, however long, is read
 * exactly as before this fix (classify()'s FNR-1 fallthrough, unmodified).
 *
 * The LENGTH, not mere membership, is what tells a genuine run from one stray trap: the walk's own padding scan
 * (diag_wrapper_walk.c) closes a run the moment a real instruction follows, so a single int3 inline in otherwise-
 * live/obfuscated code - FNR-1's own case, which must still fall through - closes as a one-byte entry in r->pad
 * exactly like a real run would if it were that short; the one-byte "call does not return" mark is excluded from
 * r->pad at its own offset already (kgenome_diag_wrapper_pe_pad_from). skip_pad (above) answers "the first byte
 * after whatever padding covers `at`", merging adjacent runs; more than one byte of it is a real run. */
static int crosses_pad(const struct kgenome_fntab_run *r, uint64_t at)
{
	return at < r->data_n && (r->data[at] == 0xccu || r->data[at] == 0xf4u) && skip_pad(r->pad, r->n_pad, at) - at > 1u;
}

/* Does a block of THIS SAME decoded graph begin exactly at `at`? classify()'s own pass 3 (cfg_build.c) makes a
 * leader - a block of its own - of every LOCAL branch target, including a backward one from code read after it
 * (a loop realignment: `nop`-pad up to the loop head, then a later `jl head` makes `head` a leader; MSVC never
 * builds that shape from int3 - measured, a NOP is what every regressing case used, see crosses_pad's own comment
 * - so this second gate costs nothing on the corpus today: 0 change, same oracle numbers, with or without it). It
 * stays as a second, independent reason never to cut a genuine branch target: an int3 run placed by something
 * other than a real compiler (obfuscated or hand-built code, this engine's own hostile-input baseline) is free to
 * put one right where classify() already resolved a local target, and a leader right there IS that resolution -
 * something in this very graph already names the address, so the run is an alignment gap of ONE body, not the
 * space between two; crosses_pad must let the walk continue exactly as it already does (FNR-1's own fallthrough)
 * and never cut there. Only a run with NO leader behind it - nothing in the function's own control flow ever
 * refers to what follows - is cut. */
static int pad_end_has_block(const struct kgenome_cfg *cfg, const struct kgenome_cell_insn *in, uint64_t padend)
{
	uint32_t lo = 0, hi = cfg->n_all;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (in[cfg->b[mid].first].at < padend)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < cfg->n_all && in[cfg->b[lo].first].at == padend;
}

/* Is a jump through memory the tail call of an import (a fixed slot) and not a switch? A fixed slot is a place the image names: an IAT entry. */
static int jump_is_table(const struct kgenome_fntab_run *r, const struct kgenome_cell_insn *in)
{
	return (in->flags & KGENOME_CELL_F_INDIRECT) && kgenome_cell_slot_of(in, r->obj->arch == KGENOME_ARCH_X86_64, 0) == KGENOME_BROKEN;
}

/* Is `t` the first byte behind the PADDING of a function: the run of int3 that ends at file offset `t` has a byte that is not the mark of a call (the one int3 right after a call is the compiler's
 * sign that the call does not return; a second noreturn call block of the same body can follow it with no padding at all)? The instructions are in order of address: a binary search for the one that
 * starts at `t`, then the run back from it. */
static int padded_start(const struct kgenome_frame *fr, const uint8_t *data, uint64_t t)
{
	uint32_t lo = 0, hi = fr->n_insn, k = 0;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (fr->in[mid].at < t)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo || lo >= fr->n_insn || fr->in[lo].at != t)
		return 0;
	while (k < lo && fr->in[lo - 1u - k].len == 1u && fr->in[lo - 1u - k].op == KGENOME_CELL_INT && data[fr->in[lo - 1u - k].at] == 0xccu &&
	       fr->in[lo - 1u - k].at + 1u == (k ? fr->in[lo - k].at : t))
		k++;
	if (!k)
		return 0;
	return k > 1u || k == lo || fr->in[lo - 1u - k].op != KGENOME_CELL_CALL;
}

/* The graph of [off, off + len) and what it says: 1 when it was made. `more` is set when the reached code needs a larger window (it runs out of it, or a reachable branch lands in [off + len, bound) or in the last 15 bytes before it, where the instruction it names may be cut by the window). */
/* KNOWN DEFECT FNR-3 (2026-11-05, M) [sev M]: an x86 SEH handler/filter named only by the fs:[0] chain has no edge in this graph (no call/jmp reaches it).
 * Trigger: a PE32 handler reached only by storing its address (the SEH install), never by call/jmp. Effect measured (i686-w64-mingw32-gcc, 3 compiled configs, stripped, no SafeSEH table):
 * the GAPS step below already recovers it with correct bounds when its own code ends in a ret before the next start - 0/3 real builds reproduced a cut or swallowed entry.
 * Reproducer: tests/lib/genome/fntab_pe.c:t_seh_handler_gap_fnr3 (confirms the measured shape). Unmeasured, narrower open case: MSVC's `_except_handler3` scope table, or a handler
 * whose own code does not end before the next start (would still be absorbed). Fix: open until that narrower case is reproduced; then read the SEH scope table / SafeSEH list as graph entries. */
static int graph_of(struct kgenome_fntab_run *r, uint64_t off, uint64_t len, uint64_t bound, struct reach *out, int *more)
{
	struct kgenome_frame_src src;
	struct kgenome_frame fr;
	const uint16_t *bits;
	uint32_t q, last = 0, i;
	int indirect = 0, runs_out = 0, off_window = 0;
	uint64_t end = off;
	uint32_t endi = 0;

	memset(&src, 0, sizeof src);
	src.obj = r->obj;
	src.base = r->data;
	src.size = r->data_n;
	src.wk = r->walk;
	*more = 0;
	out->cut = 0;
	out->nomem = 0;
	out->n_link = 0;
	out->has_call = 0;
	out->has_trap = 0;
	out->cut_by_pad = 0;
	if (kgenome_frame_make(&src, off, len, KGENOME_FRAME_KEEP_INSN, &fr) != KGENOME_FRAME_OK) {
		out->nomem = fr.state == KGENOME_FRAME_NOMEM;
		kgenome_frame_release(&fr, NULL);
		out->st = R_NONE;
		return 0;
	}
	bits = kgenome_frame_facts(&fr, fr.in);
	if (!bits) {
		out->nomem = 1;                 /* the facts are the one thing that can fail after a good graph, and only for memory */
		kgenome_frame_release(&fr, NULL);
		out->st = R_NONE;
		return 0;
	}
	for (q = 0; q < fr.cfg.n_all; q++) {
		const struct kgenome_cfg_block *b = &fr.cfg.b[q];
		const struct kgenome_cell_insn *l;
		uint32_t stop_at = 0;
		int cut_here = 0;
		uint64_t e;

		if (!b->reach)
			continue;
		/* FNR-4: find where (if at all) this block's own instructions cross a genuine padding run (crosses_pad)
		 * before touching anything that follows it - has_call/has_trap/cut/link must reflect only the bytes
		 * before the run, never the chunk a padding-crossing decode wandered into. `stop_at` is the count of
		 * this block's instructions that are really the entry's own; a branch of a reachable block that lands
		 * past the window or in its last bytes (a conditional branch out of the window is dropped by the graph
		 * and does not end its block) is still read from the untruncated range, since it does not depend on
		 * `end`/`has_call`/etc. */
		for (i = b->first; i < b->first + b->n_insn; i++) {
			const struct kgenome_cell_insn *c = &fr.in[i];

			if (crosses_pad(r, c->at) &&
			    !pad_end_has_block(&fr.cfg, fr.in, skip_pad(r->pad, r->n_pad, c->at))) {
				cut_here = 1;
				/* Call-adjacent (a call right before the run, or a call's own one-byte nop/int3 mark right
				 * before it) is exactly the existing open_end idiom below, reached here first because the
				 * run is found crossing mid-block rather than by running out of the window: a KNOWN end,
				 * not weaker evidence than open_end ever gave. Anything else that merely abuts padding - no
				 * call, nothing - stays `cut_by_pad` (struct reach): apply() may still use it for a KNOWN
				 * entry's own truncated end, but plausible() must not call it "code that ends" on that
				 * alone (see plausible()'s own comment). */
				if (!(i && fr.in[i - 1u].op == KGENOME_CELL_CALL) &&
				    !(i > 1u && fr.in[i - 1u].len == 1u && (fr.in[i - 1u].op == KGENOME_CELL_NOP || fr.in[i - 1u].op == KGENOME_CELL_INT) &&
				      fr.in[i - 2u].op == KGENOME_CELL_CALL))
					out->cut_by_pad = 1;
				break;
			}
			stop_at = i - b->first + 1u;
			if (c->op == KGENOME_CELL_CALL)
				out->has_call = 1;
			if (c->op == KGENOME_CELL_INT && c->len == 1u && !(i && fr.in[i - 1u].op == KGENOME_CELL_CALL))
				out->has_trap = 1;
			if ((c->op == KGENOME_CELL_JMP || c->op == KGENOME_CELL_JCC || c->op == KGENOME_CELL_LOOP) && !(c->flags & KGENOME_CELL_F_INDIRECT) &&
			    c->target_va != KGENOME_BROKEN && c->target_va + 15u >= fr.va + len && c->target_va - fr.va < bound - off)
				*more = 1;
			/* a jump to the byte behind an int3 run: the first byte of another function (an int3 is never executed inside a body: it is the padding between functions) */
			if ((c->op == KGENOME_CELL_JMP || c->op == KGENOME_CELL_JCC) && !(c->flags & KGENOME_CELL_F_INDIRECT) && c->target_va != KGENOME_BROKEN &&
			    c->target_va > fr.va && c->target_va - fr.va < len) {
				const uint64_t t = off + (c->target_va - fr.va);

				if ((!out->cut || t < out->cut) && padded_start(&fr, r->data, t))
					out->cut = t;
			}
			/* FNR-2: the same target, with the padded_start() filter dropped and the window edge lifted to `bound` - any address this
			 * reached branch really names, inside the entry's allowed extent. A target already inside [off, off+len) that a real edge
			 * reaches is already folded into `end` above (reachability makes its block part of `end`'s max), so recording it here costs
			 * nothing new; what this adds is the target OUTSIDE the decoded window (an unconditional tail jump classified EXIT because it
			 * left [va_lo, va_hi): classify() still keeps its raw `target_va`), which is the one case `end` cannot already reflect. */
			if ((c->op == KGENOME_CELL_JMP || c->op == KGENOME_CELL_JCC || c->op == KGENOME_CELL_LOOP) && !(c->flags & KGENOME_CELL_F_INDIRECT) &&
			    c->target_va != KGENOME_BROKEN && c->target_va > fr.va) {
				const uint64_t t2 = off + (c->target_va - fr.va);

				if (t2 > off && t2 < bound) {
					uint32_t z;
					int dup = 0;

					for (z = 0; z < out->n_link; z++)
						if (out->link[z] == t2) {
							dup = 1;
							break;
						}
					if (!dup && out->n_link < REACH_LINK_MAX)
						out->link[out->n_link++] = t2;
				}
			}
		}
		if (!stop_at) {
			if (cut_here)
				break;          /* the block is wholly a recorded padding run: none of it is this entry's, and neither is anything at a higher address (cut_by_pad already decided at the trigger site above) */
			continue;               /* an empty block (cfg_build.c gives none): nothing to contribute */
		}
		l = &fr.in[b->first + stop_at - 1u];
		e = l->at + l->len;
		if (e > end) {
			end = e;
			endi = b->first + stop_at - 1u;
		}
		if (b->first + stop_at > last)
			last = b->first + stop_at;
		if (!cut_here) {
			if (bits[q] & KGENOME_FRAME_B_RUNS_OUT)
				runs_out = 1;
			if (q + 1u == fr.cfg.n_all && b->term == KGENOME_CFG_T_FALL)
				off_window = 1;         /* the reached code goes on past the window (after a call too: whether that call returns is not known at the window's edge) */
		}
		if (l->op == KGENOME_CELL_JMP && jump_is_table(r, l))
			indirect = 1;
		if (cut_here)
			break;                  /* blocks after this one are all at a higher address (cfg_build.c builds them in address order): none of them is this entry's either (cut_by_pad already decided at the trigger site above) */
	}
	/* bytes that decode as nothing inside what is reached: the instruction after one does not start where the one before it ended */
	out->hole = 0;
	for (i = 0; i + 1u < last; i++)
		if (fr.in[i].at + fr.in[i].len != fr.in[i + 1u].at) {
			out->hole = 1;
			break;
		}
	if (off_window && len < bound - off)
		*more = 1;
	/* An int3 the path reaches by falling into it is the padding of the next function and not the body's own unless a call stands right before it (the mark of a call that does not return). */
	out->fell = 0;
	while (endi > 0 && fr.in[endi].len == 1u && fr.in[endi].op == KGENOME_CELL_INT && r->data[fr.in[endi].at] == 0xccu && fr.in[endi - 1u].op != KGENOME_CELL_CALL) {
		end = fr.in[endi].at;
		endi--;
		/* the instruction it fell from: a call (the call that does not return) or the one-byte nop after one is a body's own end; anything else is the middle of what is not known to be one */
		out->fell = !(fr.in[endi].op == KGENOME_CELL_CALL || (fr.in[endi].op == KGENOME_CELL_NOP && fr.in[endi].len == 1u && endi > 0 && fr.in[endi - 1u].op == KGENOME_CELL_CALL));
	}
	out->end = end;
	out->entry_like = entry_insn(&fr.in[0]);
	out->open_end = 0;
	if (runs_out) {
		/* the code goes on past its last instruction: it ends at the first padding that stands behind a call (a call that does not return, with or without its mark), when there is one */
		for (i = 0; i + 1u < last && !out->open_end; i++) {
			uint64_t e2, from;

			if (fr.in[i].op != KGENOME_CELL_CALL)
				continue;
			e2 = fr.in[i].at + fr.in[i].len;
			if (kgenome_fntab_pad_at(r->pad, r->n_pad, e2, &from) ||
			    (fr.in[i + 1u].len == 1u && (fr.in[i + 1u].op == KGENOME_CELL_NOP || fr.in[i + 1u].op == KGENOME_CELL_INT) && kgenome_fntab_pad_at(r->pad, r->n_pad, e2 + 1u, &from)))
				out->open_end = from;
		}
	}
	out->st = runs_out ? R_OPEN : indirect ? R_INDIRECT : R_OK;
	kgenome_frame_release(&fr, NULL);
	return 1;
}

/* What [off, bound) reaches from `off`: the window grows while the reached code needs it. */
static void reach_of(struct kgenome_fntab_run *r, uint64_t off, uint64_t bound, struct reach *out)
{
	uint64_t w = REACH_WIN0;

	memset(out, 0, sizeof *out);
	for (;;) {
		const uint64_t len = bound - off < w ? bound - off : w;
		int more;

		if (!graph_of(r, off, len, bound, out, &more))
			return;
		if (!more || len == bound - off)
			break;
		if (w >= REACH_WIN_MAX) {
			out->st = R_NONE;
			return;
		}
		w *= 4u;
	}
	/* the entry jumps to a function that has no start in the table: the window ends where that function begins, so its code is not this body's */
	if (out->cut) {
		const uint64_t cut = out->cut;
		int more;

		if (graph_of(r, off, cut - off, cut, out, &more)) {
			out->hint = cut;
			out->cut = 0;
		}
	}
	if (out->hole && out->st != R_NONE)
		out->st = R_NONE;
	/* the reached code that runs on into padding ends where the padding begins (the own mark after a call is not padding: the walk's runs start after it) */
	if (out->st == R_OPEN && out->open_end > off) {
		out->st = R_OK;
		out->end = out->open_end;
	}
}

/* The state of an entry after its reach was read: the end, or the flag that says why it has none. */
static void apply(struct kgenome_func *f, const struct reach *rc, uint64_t bound)
{
	switch (rc->st) {
	case R_OK:
		f->len = rc->end - f->off;
		f->end_source = KGENOME_FN_E_REACH;
		break;
	case R_OPEN:
		f->flags |= KGENOME_FN_F_REACH_OPEN;
		break;
	case R_INDIRECT:
		f->flags |= KGENOME_FN_F_REACH_INDIRECT;
		break;
	default:
		f->flags |= KGENOME_FN_F_REACH_NONE;
		break;
	}
	(void)bound;
}

/* Is the code at `c` (a candidate start, the bound after it) a function: not the zero fill, nothing undecodable in it, and it ends. 1 and its reach in `*rc`. */
/* FNR-4: "it ends" excludes ending ONLY because the reach ran into a genuine padding run with no real terminator (ret, jump-exit, a call's own trap-exit mark) ever found - that is exactly
 * as inconclusive, for THIS question, as running off the window edge: the bytes before the padding may be a function that ends there, or may be a jump table, a string, or anything else that
 * happens to decode and then abut real padding. The one difference from plain R_OPEN is that a KNOWN entry's own apply() (below) still uses such a truncated end unconditionally - it is the
 * entry's padding either way, never its own body - but a GAP CANDIDATE needs stronger evidence than merely reaching padding to be called a function (struct reach's `cut_by_pad`). */
static int plausible(struct kgenome_fntab_run *r, uint64_t c, uint64_t bound, struct reach *rc)
{
	if (c + 2u > r->data_n || !(r->data[c] | r->data[c + 1u]))
		return 0;
	reach_of(r, c, bound, rc);
	return (rc->st == R_OK || rc->st == R_INDIRECT) && rc->end > c && !rc->fell && !rc->cut_by_pad;
}

/* FNR-2: is `c` a target the body's own reached control flow (`blink[]`, filled from `struct reach.link` by
 * graph_of) really names? Looked up, not re-decoded (rule 5). */
static int reach_linked(const uint64_t *link, uint32_t n_link, uint64_t c)
{
	uint32_t z;

	for (z = 0; z < n_link; z++)
		if (link[z] == c)
			return 1;
	return 0;
}

/* Add `src`'s targets to `dst` (deduplicated, capped at REACH_LINK_MAX: a cost cap on how much evidence one
 * body's lookup set carries, never a reason to treat a recorded target as unreal). */
static void link_merge(uint64_t *dst, uint32_t *ndst, const uint64_t *src, uint32_t nsrc)
{
	uint32_t a;

	for (a = 0; a < nsrc && *ndst < REACH_LINK_MAX; a++) {
		uint32_t z;
		int dup = 0;

		for (z = 0; z < *ndst; z++)
			if (dst[z] == src[a]) {
				dup = 1;
				break;
			}
		if (!dup)
			dst[(*ndst)++] = src[a];
	}
}

/* Is `at` inside a range of `cover` (sorted by start)? Its end, or 0. */
static uint64_t covered_to(const struct kgenome_fntab_extent *cover, uint32_t n, uint64_t at)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (cover[mid].at <= at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo && cover[lo - 1u].at + cover[lo - 1u].len > at ? cover[lo - 1u].at + cover[lo - 1u].len : 0;
}

static int push(struct kgenome_func **v, uint32_t *n, uint32_t *cap, const struct kgenome_func *f)
{
	if (*n == *cap) {
		uint32_t nc = kgenome_grow_cap(*cap, 256u);
		struct kgenome_func *t = nc ? realloc(*v, (size_t)nc * sizeof **v) : NULL;

		if (!t)
			return 0;
		*v = t;
		*cap = nc;
	}
	(*v)[(*n)++] = *f;
	return 1;
}

static int cmp_ext(const void *a, const void *b)
{
	const struct kgenome_fntab_extent *x = a, *y = b;

	return x->at < y->at ? -1 : x->at > y->at ? 1 : 0;
}

void kgenome_fntab_reach(struct kgenome_func_set *s, struct kgenome_fntab_run *r, const struct kgenome_fntab_extent *ext, uint32_t n_ext,
			 struct kgenome_fntab_extent *cover, uint32_t n_cover)
{
	struct kgenome_func *nv = NULL;
	uint32_t n = 0, cap = 0, i;
	int short_ = 0;

	if (n_cover)
		qsort(cover, n_cover, sizeof *cover, cmp_ext);
	for (i = 0; i < s->n; i++) {
		struct kgenome_func f = s->v[i];
		const uint64_t bound = kgenome_fntab_bound(s, i, ext, n_ext);
		uint64_t cov, hint = 0;
		struct reach rc;
		uint64_t blink[REACH_LINK_MAX];                 /* FNR-2: the real edges the entry now ending at `cov` is known to name */
		uint32_t n_blink = 0;

		if (!bound) {                   /* in no code extent: the ends step drops it */
			if (!push(&nv, &n, &cap, &f))
				goto nomem;
			continue;
		}
		if (f.len && f.end_source != KGENOME_FN_E_NONE) {
			cov = f.off + f.len;
		} else {
			reach_of(r, f.off, bound, &rc);
			short_ |= rc.nomem;
			apply(&f, &rc, bound);
			cov = rc.st == R_OK ? rc.end : bound;
			hint = rc.hint;
			n_blink = rc.n_link;
			memcpy(blink, rc.link, n_blink * sizeof *blink);
		}
		if (!push(&nv, &n, &cap, &f))
			goto nomem;
		/* what lies behind the covered end up to the next start: each start the bytes hold, one after the other, and the function the entry jumped to (`hint`) when the gap before it is done */
		while (cov < bound || hint) {
			const uint64_t lim = hint ? hint : bound;
			struct kgenome_func g;
			uint64_t c, cv;
			uint32_t cm;
			int forced = 0;

			if (cov < lim) {
				c = skip_pad(r->pad, r->n_pad, cov);
				while (c < lim && (cv = covered_to(cover, n_cover, c)) != 0)
					c = skip_pad(r->pad, r->n_pad, cv);
				if (c >= lim) {
					cov = lim;
					continue;
				}
				if (c == cov && nv[n - 1u].end_source == KGENOME_FN_E_REACH && (cm = call_mark_at(r, c)) != 0 && c + cm <= lim) {
					/* behind the end of a body with NO alignment padding between: a call and its mark is the block a compiler puts after the `ret` for a call that does not return, that
					 * nothing branches to: more of that body. A function starts after padding, or with a prologue instruction. */
					nv[n - 1u].len = c + cm - nv[n - 1u].off;
					cov = c + cm;
					continue;
				}
			} else {
				c = hint;               /* a jump landed behind an int3 run: no padding to skip, and no adjacency rule (the jump is the evidence) */
				hint = 0;
				forced = 1;
			}
			/* FNR-2v2 (2026-11-04): the merged FNR-2 shape test, `!rc.has_call` alone, gave 231 DISTINCT long
			 * entries on the PE oracle (oracle_base -p pe120.txt) against 188 before FNR-2 - WORSE, not better.
			 * An exact-source table lookup (`s` is the merged symtab/PDATA/COFF table at this exact point) was
			 * tried first and is a no-op here by construction: kgenome_fntab_bound() sets `bound` to the NEXT
			 * entry of `s` (fntab_ends.c:38-53), and PE's own selector never marks a source check-only
			 * (fntab_pe_select.c), so every offset `s` or the walk's call targets could name is ALREADY a kept
			 * entry of `s` and already stops the gap before this line ever runs on it - a lookup here can only
			 * ever answer "not found". Measured instead (oracle -v): of 148 raw cases past REACH, 75% show an
			 * int3/hlt NOT right after a call inside the reached graph (`rc.has_trap`) - a run of alignment
			 * padding that classify() no longer exits on unless the call mark precedes it (FNR-1; defect
			 * FNR-4, cfg_build.c): the SAME padding-fallthrough also inflates a function's OWN first reach_of()
			 * call (apply() above, no absorption involved), so this one condition cannot close the regression -
			 * FNR-4 is the dominant cause and is out of this function's scope. What IS this function's to fix:
			 * never treat such a trap-laden chunk as the dead-tail SHAPE evidence FNR-2 meant (`has_trap` is
			 * never set by the lineage tests' LG_F_DEAD generator, which emits no raw bytes at all). */
			if (!forced && c == cov && nv[n - 1u].end_source == KGENOME_FN_E_REACH &&
			    plausible(r, c, bound, &rc) && !rc.entry_like && rc.st == R_OK &&
			    (reach_linked(blink, n_blink, c) || (!rc.has_call && !rc.has_trap))) {
				nv[n - 1u].len = rc.end - nv[n - 1u].off;
				cov = rc.end;
				link_merge(blink, &n_blink, rc.link, rc.n_link);
				continue;
			}
			if (!plausible(r, c, bound, &rc) || (!forced && c == cov && !rc.entry_like)) {
				short_ |= rc.nomem;
				cov = forced ? bound : lim;     /* what is here is not a function that ends: the rest of the gap is left unnamed */
				continue;
			}
			memset(&g, 0, sizeof g);
			g.off = c;
			g.source = KGENOME_FN_S_WALK;
			g.flags = KGENOME_FN_F_GAP;
			apply(&g, &rc, bound);
			if (g.end_source == KGENOME_FN_E_NONE)
				g.flags |= KGENOME_FN_F_END_OPEN;
			if (!push(&nv, &n, &cap, &g))
				goto nomem;
			cov = rc.st == R_OK ? rc.end : bound;
			hint = rc.hint;
			n_blink = rc.n_link;                    /* `g` is now nv[n-1]: its own reach_of recorded its real edges */
			memcpy(blink, rc.link, n_blink * sizeof *blink);
		}
	}
	free(s->v);
	s->v = nv;
	s->n = n;
	if (short_)
		s->status = KGENOME_NOMEM;      /* a graph could not be made for want of memory: an entry kept the next-start end and a start may be missing: the table says it is short */
	return;
nomem:
	free(nv);
	s->status = KGENOME_NOMEM;
}
