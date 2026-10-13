/*
 * diag_emu_gaps.c - the gap between two known sites: when a run is moved on, what is remembered, promotion of a function to a node.
 * Part of the emulate route; see diag_emu.c for what it is for and diag_emu_int.h for what the
 * files share.
 */
#include "diag_emu_int.h"






#define DIAG_REL_TOKEN 0x5A6E0000DEAD0000ull

/*
 * EVERY CALL IN THE SPAN IS SKIPPED, AND ITS RESULT IS SUPPLIED.
 *
 * Not executed. The span exists to answer "does the value this call produced
 * reach that call", and what the callee does on the way is not part of the
 * question:
 *
 *   AN INTERNAL CALL WOULD BE EXECUTED FOR REAL. Its displacement is not a
 *   hole, so stepping it jumps into the callee and runs code that has nothing
 *   to do with the relation being asked about - at best a detour, at worst a
 *   fault that ends the span.
 *   AN IMPORTED CALL CANNOT BE EXECUTED AT ALL. prepare_creds is not in the
 *   file; there is nothing at the other end. Its displacement is a hole, so
 *   stepping it merely falls through - and leaves the result register holding
 *   whatever was there, which is the one thing the span needs to be right.
 *
 * WHERE THE CALL INSTRUCTION IS, WITHOUT GUESSING AT OPCODES. The relocation
 * sits on the displacement, which the parser reports as `at` = r_offset + 4;
 * the four displacement bytes are the last four of the instruction, so it
 * begins at `at` - 5. That is read off the relocation, not off a list of
 * encodings we happen to know.
 */
#define DIAG_REL_CALLLEN 5u



void kgenome_diag_emu_gather_skip(void *user, uint64_t at, uint64_t target,
			const char *name)
{
	struct kgenome_diag_emu_skipgather *g = user;

	if (at < DIAG_REL_CALLLEN)
		return;
	if (g->n == g->cap_n) {
		uint32_t nc = g->cap_n ? g->cap_n * 2u : 64u;
		struct kgenome_diag_emu_skipsite *ns = realloc(g->site, (size_t)nc * sizeof *ns);

		if (!ns) {
			g->oom = 1;
			return;
		}
		g->site = ns;
		g->cap_n = nc;
	}
	g->site[g->n].call_at = at - DIAG_REL_CALLLEN;
	g->site[g->n].resume = at;
	g->site[g->n].callee = target;
	/* An internal call names a capability only by accident; it is here to
	 * be skipped, not to be a node. */
	g->site[g->n].cap = target ? KGENOME_NUCLEO_NONE
				   : (name ? kgenome_flow_cap_of_name(name)
					   : KGENOME_NUCLEO_NONE);
	g->n++;
}

int kgenome_diag_emu_skip_cmp(const void *a, const void *b)
{
	const struct kgenome_diag_emu_skipsite *x = a, *y = b;

	if (x->call_at != y->call_at)
		return x->call_at < y->call_at ? -1 : 1;
	if (x->callee != y->callee)
		return x->callee < y->callee ? -1 : 1;
	return (x->cap > y->cap) - (x->cap < y->cap);
}

/* First site whose call begins at or after `at`; sites are sorted by it. */
uint32_t kgenome_diag_emu_skip_first(const struct kgenome_diag_emu_skipsite *v, uint32_t n, uint64_t at)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (v[mid].call_at < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo;
}

/*
 * IS THIS VALUE AN OBJECT THIS MODULE OWNS.
 *
 * Only an address inside the mapped image or the token arena is remembered.
 * Zero, a small integer, a length and a stack address are passed by half the
 * calls in any program; remembering one would relate every call that happened
 * to use it, which is not a relation but a coincidence.
 */
int kgenome_diag_emu_worth_remembering(uint64_t v, uint64_t size)
{
	/*
	 * AN ANONYMOUS TOKEN COUNTS, BUT ONLY INSIDE ITS OWN SPAN.
	 *
	 * It stands for a call nothing here explains - kzalloc, say - and two
	 * calls in the same function receiving it ARE holding one object:
	 * copy_from_user(buf, ubuf, n) then copy_to_user(ubuf, buf, n) is the
	 * hooked getdents, and the buffer is exactly such a token.
	 *
	 * ACROSS SPANS IT IS MEANINGLESS. The pages are handed out from the
	 * top of the arena downwards starting fresh each time, so the first
	 * anonymous page of one function is the same address as the first of
	 * the next. MEASURED when the table was made to persist:
	 * hacked_getdents' buffer linked to hacked_getdents64's, two
	 * unrelated buffers in two unrelated functions, and the spurious
	 * matches pushed real links out of the four slots a node has.
	 *
	 * The table is per span, which is what keeps this sound. Anything
	 * that wants to relate two FUNCTIONS has to rest on a fixed address -
	 * a relocation - and that is known without running at all.
	 */
	if (v >= KGENOME_DIAG_TOK_BASE &&
	    v < KGENOME_DIAG_TOK_BASE + (uint64_t)KGENOME_DIAG_TOK_SPAN * KGENOME_EMU_PAGE)
		return 1;
	return v > KGENOME_DIAG_REL_BASE &&
	       v < KGENOME_DIAG_REL_BASE + size + KGENOME_DIAG_REL_SLACK;
}



/* Is this capability a head some diagnose asked to have built. */
static int is_made(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t k;

	for (k = 0; k < s->n_seq; k++)
		if (s->seq[k].made == cap)
			return 1;
	return 0;
}

/*
 * A CALLEE THIS MODULE DEFINES: PART OF THIS CHAIN, OR A FUNCTION OF ITS OWN.
 *
 * An internal call is stepped over like any other, and the question is what
 * its result should then be. Two answers and the difference matters:
 *
 *   IT CARRIES A CAPABILITY. The callee contains nodes - it resolves a
 *   symbol, it allocates, it opens something - so what it hands back is an
 *   object this chain produced, and a later site holding that object is
 *   linked to it. Diamorphine's findmyinterest is the case: the kprobe pair
 *   lives inside it and the syscall table address comes out of it.
 *   IT CARRIES NONE. Then it is an independent function. Its result relates
 *   to nothing here, the register is left undefined, and the function is
 *   examined on its own turn - every function gets one.
 *
 * WHICH NODE REPRESENTS THE CALLEE - MEASURED, NOT ASSUMED.
 *
 * The first answer was "a function with exactly one node inside it is a
 * wrapper for that node". True, and too narrow: it requires knowing which
 * functions are wrappers before looking, and a helper that does two things
 * and returns one of them -
 *
 *     int get_sock(void) { int s = socket(); connect(s, ..); return s; }
 *
 * - has two nodes, so it is refused, so the caller loses the descriptor and
 * every relation downstream of it. A function nobody steps into is invisible,
 * and what it hands back vanishes with it.
 *
 * SO THE ANSWER IS TAKEN FROM THE RUN. Each function's span already carries
 * tokens; whichever token is in the result register when the span ends is
 * what that function returns, and that is a measurement. The spans are run
 * repeatedly until the answers stop changing - a caller analysed before its
 * callee simply learns nothing that pass and learns it on the next, which is
 * a topological order without having to build one.
 *
 * `ret_node` below is that table. `kgenome_diag_emu_callee_node` remains for the first pass,
 * where nothing has been measured yet.
 *
 * ---- THE OLD RULE, KEPT FOR THE FIRST PASS ---------------------------------
 *
 * A link needs a node index and a callee is not a node, so something has to
 * stand for it. Taking the first node inside was the first answer and it is
 * a CHOICE rather than a fact: in a function that does several things the
 * first node is whichever the compiler laid out first, and attributing the
 * return value to it invents a relation.
 *
 * EXACTLY ONE NODE IS THE CASE WHERE IT IS NOT A CHOICE. A function whose
 * whole capability is one call is a wrapper for that call, and its result IS
 * that call's result - resolve_sym around the kprobe idiom is the shape, and
 * it is the shape a kernel module uses constantly. With two or more there is
 * no honest representative, so the register is left undefined and the callee
 * is examined on its own turn, where its nodes relate to each other properly.
 *
 * This is the same wrapper that defeats the static model from the other side
 * - there the node is libc's wrapper and the caller is invisible; here the
 * caller is in hand and the wrapper is what makes the attribution sound.
 */
uint16_t kgenome_diag_emu_callee_node(const struct kgenome_diag_scan *s,
			    const struct kgenome_func *fns, uint32_t n_fn,
			    uint64_t callee)
{
	uint32_t j, i, n = kgenome_diag_scan_count(s);

	for (j = 0; j < n_fn; j++) {
		uint16_t only = 0xffffu;
		uint32_t cnt = 0;

		if (fns[j].off != callee)
			continue;
		for (i = 0; i < n; i++) {
			const struct kgenome_diag_hit *p = kgenome_diag_scan_at(s, i);

			if (!p || p->at < fns[j].off ||
			    p->at >= fns[j].off + fns[j].len)
				continue;
			/* A promoted wrapper IS the function - see
			 * kgenome_diag_emu_promote_wrappers - so it answers for it however
			 * many nodes are inside. */
			if (p->at == fns[j].off && is_made(s, p->cap))
				return (uint16_t)i;
			only = (uint16_t)i;
			cnt++;
		}
		return cnt == 1u ? only : 0xffffu;
	}
	return 0xffffu;
}

/*
 * DOES THIS FUNCTION CONTAIN A CONTROL-REGISTER WRITE.
 *
 * The node count alone is the wrong gate, and it threw away the one function
 * that mattered: Diamorphine's init_module calls no import this vocabulary
 * has a word for, so it held zero nodes and was refused - while containing
 * the `mov cr0` that is the centre of the rootkit. A bound on cost must not
 * delete evidence.
 *
 * BYTES TO DECIDE WHETHER TO LOOK, THE DECODER TO DECIDE WHAT IT IS. `0f 22`
 * in a displacement answers yes and costs one walk; an instruction that is
 * not in the bytes cannot be decoded out of them. The same over-approximation
 * the syscall routine uses for `0f 05`, for the same reason.
 */
int kgenome_diag_emu_has_cr_write(const uint8_t *p, uint64_t n)
{
	uint64_t i;

	for (i = 0; i + 1u < n; i++)
		if (p[i] == 0x0fu && p[i + 1u] == 0x22u)
			return 1;
	return 0;
}

/*
 * ---- A FUNCTION THAT IS ONE ACT BECOMES ONE NODE ------------------------
 *
 * findmyinterest is three calls - register_kprobe, an indirect call, and
 * unregister_kprobe - and it is not three acts. It is ONE: resolve a name to
 * an address. The module calls it the way it would call a syscall, and its
 * caller cares about the address that comes back and nothing else.
 *
 * THE INDIRECT CALL IN THE MIDDLE IS NOT LINKED TO THE OTHER TWO, and must
 * not be. Its target was decided wherever the pointer was stored, not by
 * either probe call; what relates the three is that they are IN ONE
 * FUNCTION, which is co-location and not provenance. Forcing a link there
 * would be asserting a derivation the program does not have.
 *
 * SO THE SHAPE IS RECOGNISED, NOT FOLLOWED. A function whose capability
 * nodes are exactly the probe pair - put one on, take it off - is a symbol
 * lookup whatever happens between them, because that is the only reason to
 * do it. The node is emitted at the function's own offset, and callers then
 * see one act with a word, the same way they would see dup2.
 *
 * WHY IT MATTERS BEYOND THE NAME: a caller's `table = findmyinterest()` is
 * the start of the hook chain, and until the callee had a capability its
 * result was an anonymous token - a value belonging to no node, which no
 * link can end at. One node here gives the whole chain somewhere to begin.
 */
static void promote_sequence(struct kgenome_diag_scan *s,
			     const struct kgenome_func *fns, uint32_t n_fn,
			     const struct kgenome_diag_seq *sq)
{
	uint32_t i, n = kgenome_diag_scan_count(s);

	/*
	 * ---- THE HOOK-DECLARATION BLOCK IS FOUND FIRST, AND AS A BLOCK ----
	 *
	 * Since 5.7 the kernel stopped exporting kallsyms_lookup_name, and the
	 * way round it is to register a kprobe on the name, read kp.addr and
	 * unregister. That PAIR is the lookup. It is one act, and until it is
	 * recognised as one the analysis is looking at two unrelated calls
	 * with an address appearing between them for no reason - the read of
	 * kp.addr links to NEITHER of them, because nothing in the kernel's
	 * symbol design connects them by a value.
	 *
	 * IT IS A BLOCK, NOT A FUNCTION. This used to require that the
	 * function contain the pair AND NOTHING ELSE, which only catches an
	 * author who wrote a tidy little wrapper. What identifies it is the
	 * ORDER - a register, then an unregister, with no other capability
	 * between them - and that holds wherever the two sit.
	 *
	 * AND IT IS DONE BEFORE ANY SPAN RUNS, so that when a caller is
	 * walked, the call into this function is already known to hand back a
	 * resolved symbol rather than being one more opaque call.
	 */
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *p = kgenome_diag_scan_at(s, i);
		uint32_t t, j;
		uint64_t reg_at, unreg_at = 0;
		int paired = 0;

		if (!p || p->cap != sq->first)
			continue;
		reg_at = p->at;

		/*
		 * THE NEAREST UNREGISTER AFTER IT, and WHATEVER LIES BETWEEN.
		 *
		 * Requiring nothing in between was wrong and it was wrong in
		 * the obvious way: the thing between them is the POINT - the
		 * read of kp.addr, which is the resolved symbol the whole
		 * manoeuvre exists to get. Author code puts more there too.
		 * What identifies the block is the pair, not the gap being
		 * empty.
		 */
		for (t = 0; t < n; t++) {
			const struct kgenome_diag_hit *q = kgenome_diag_scan_at(s, t);

			if (!q || q->at <= reg_at ||
			    q->cap != sq->then)
				continue;
			if (!unreg_at || q->at < unreg_at) {
				unreg_at = q->at;
				paired = 1;
			}
		}
		if (!paired)
			continue;

		/*
		 * THE NODE GOES AT THE FUNCTION THAT HOLDS THE BLOCK, because
		 * that is the address a caller's `call` names - which is what
		 * lets the caller be told it is getting a resolved symbol.
		 * With no function covering it, the block stands where the
		 * register does.
		 */
		for (j = 0; j < n_fn; j++)
			if (reg_at >= fns[j].off &&
			    unreg_at < fns[j].off + fns[j].len)
				break;
		kgenome_diag_hit_add(s, j < n_fn ? fns[j].off : reg_at,
				 sq->made, 0);
	}
}

/* Every head a loaded diagnose asked the engine to build - see
 * KOF_DIAG_DECLARE_SEQUENCE. None asked, none built. */
void kgenome_diag_emu_promote_wrappers(struct kgenome_diag_scan *s,
			     const struct kgenome_func *fns, uint32_t n_fn)
{
	uint32_t k;

	for (k = 0; k < s->n_seq; k++)
		promote_sequence(s, fns, n_fn, &s->seq[k]);
}





/*
 * WHAT A STORE PUT THERE, when the instruction carries it - see
 * KGENOME_DIAG_H_VAL.
 *
 * ONE PLACE, because three branches below make a field node - a
 * RIP-relative object, a base register holding one, and the token region -
 * and a value recorded at two of the three is a diagnose that matches on
 * some builds of the same program.
 *
 * `mi` is the operand that is the memory: 0 for a store, and only a store
 * writes anything. The source has to be an IMMEDIATE; a register source is
 * a value the model may have lost, and a lost value reads as zero.
 */
void kgenome_diag_emu_field_value(struct kgenome_diag_hit *fh, const struct kgenome_cell_insn *ci,
			unsigned mi)
{
	if (!fh || mi != 0u || ci->n_op < 2u || ci->o[1].kind != KGENOME_CELL_O_IMM)
		return;
	fh->val = ci->o[1].imm;
	fh->bits |= KGENOME_DIAG_H_VAL;
}
