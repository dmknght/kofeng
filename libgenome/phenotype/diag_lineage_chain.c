/*
 * diag_lineage_chain.c - WHICH STAGE RUNS ON WHICH CODE, and what is left when none can help.
 * Part of the lineage stages; see diag_lineage.h (the chain, the obligations) and diag_lineage_private.h.
 *
 * THE SELECTION IS FROM THE CODE, NOT ONLY FROM THE CLASS. The class table (diag_class.c) says which stages are possible
 * for an object at all. Below it every function is a CHAIN: the cheap stage (FLOW - registers and frame slots, and the
 * sinks a callee's summary gives to its callers) runs first, everywhere, and the inputs of consumers it could not account
 * for come out of it as OBLIGATIONS, each with the reason it is unknown (KGENOME_LINEAGE_W_*, set where the value was made
 * unknown). A row of the table below names a reason, the predicate the function (and the block) must satisfy for the
 * stage to be able to discharge it, and the stage. The function is solved again with the stages whose rows its
 * obligations match - all of them at once, so a function that needs two is read twice and not three times - and not
 * otherwise. What no stage discharges is the UNRESOLVED SET (kgenome_diag_oblig_at): per input, which of the node's
 * arguments is unknown and why.
 *
 * DATA. A stage's row names predicates (what a block holds - KGENOME_LINEAGE_P_*, bits computed ONCE in the loop over the
 * instructions the solve has already decoded: no pass of its own) and a reason; a new stage or a new predicate is a
 * row and a bit, the stages do not change. The evaluator below is the only code that reads the table.
 *
 * WHAT EACH ROW IS FOR, with the measurement that put it there (the 100-file cells of the graph-research set, links
 * and time against running every stage on every function and block - the S_EAGER reference, which the tests hold to the
 * same links):
 *
 *   LOCS   reason W_MEM, function holds a store to a cell beyond the frame (MEMSTORE), active on blocks that touch
 *          one (MEMCELL). A read of such a cell can only be resolved by a store the function itself made: a function
 *          with none cannot be helped, whatever the class says.
 *   SUMM   reason W_CALL, function calls a function of the object that reaches a node, active on those blocks. This is
 *          the RETURN of a callee (what it hands back); the SINKS (what the caller's arguments do inside the callee) are
 *          applied by every run, because a MUST on the callee's consumer is only true if EVERY caller's value is
 *          accounted for - a caller that passes a constant makes it MAY, whether or not any token travels.
 *   SEED   no reason: the predicate is the obligation - a block no walk reached (UNREACHED) that holds a node whose result
 *          is a handle (PRODUCER) or a call to a function of the object that reaches a node (CALL_INT). A seeded entry knows
 *          nothing, so what it adds comes from producers in the blocks it enters; and a call in code nobody proved
 *          unreachable is a CONTEXT of the callee (its argument there is unknown), which a callee's MUST has to account for -
 *          measured: seeding only the producers made a link MUST that the seed of every block (eager) makes MAY.
 *
 * The predicates ICALL (an indirect call the constant map did not resolve), EXTCALL (a call that is no function and no node:
 * an import the vocabulary has no word for) and STACKARG (an i386 callee-pops block) are computed with the others and have
 * no stage: their reasons (W_EXT, W_STACK) go to the report and stay there - the places where a demand-driven emulator
 * reading would start.
 */
#include <string.h>
#include "diag_lineage_private.h"

#define S_LOCS KGENOME_LINEAGE_S_LOCS
#define S_SUMM KGENOME_LINEAGE_S_SUMM
#define S_SEED KGENOME_LINEAGE_S_SEED
#define P(x)   KGENOME_LINEAGE_P_##x
#define W(x)   KGENOME_LINEAGE_W_##x

/* A predicate on a block: it holds all the bits of `all`, none of `none` and, when `any` is not 0, at least one of `any`.
 * (Code no walk reaches is not looked at by the stages that follow a walk: bytes after a function's last instruction decode as
 * stores and calls too.) */
struct lineage_pred {
	unsigned all, any, none;
};

struct lineage_row {
	unsigned stage;         /* 0: no stage - the reason is reported, nothing more */
	struct lineage_pred fn; /* the function has a block this holds for (checked after each run) */
	struct lineage_pred blk;/* the stage is active on a block this holds for */
	unsigned ob;            /* the stage is asked for when the run's obligations carry one of these (0: the predicate alone) */
};

static const struct lineage_row lineage_rows[] = {
	{ S_LOCS, { 0, P(MEMSTORE), P(UNREACHED) },   { 0, P(MEMCELL), 0 },               W(MEM) },
	{ S_SUMM, { 0, P(CALL_INT), P(UNREACHED) },   { 0, P(CALL_INT), 0 },              W(CALL) },
	{ S_SEED, { P(UNREACHED), P(PRODUCER) | P(CALL_INT), 0 }, { P(UNREACHED), P(PRODUCER) | P(CALL_INT), 0 }, 0 },
	{ 0,      { 0, P(ICALL), P(UNREACHED) },      { 0, P(ICALL), 0 },                W(EXT) },
	{ 0,      { 0, P(EXTCALL), P(UNREACHED) },    { 0, P(EXTCALL), 0 },              W(EXT) },
	{ 0,      { 0, P(STACKARG), P(UNREACHED) },   { 0, P(STACKARG), 0 },             W(STACK) },
};

#define N_ROWS (sizeof lineage_rows / sizeof lineage_rows[0])

/* ---- what a block holds ---- */

/*
 * IS THE FRAME POINTER ONE? `push rbp; mov rbp, rsp` at the top and no other instruction that writes rbp but the epilogue's
 * (`pop rbp`, and `leave`, which has no operand): then `[rbp+x]` is a slot of the frame, which FLOW follows, and not a cell LOCS
 * would follow. A function that uses rbp for anything else - a pointer into an object, say - has no frame pointer here and every
 * `[rbp+x]` is a place. The test is conservative in the direction that matters: when it is not sure, the operand is a place, and
 * the stage that follows places is asked for. It is learned in the one loop over the instructions, so what the loop sees of
 * `[rbp+x]` before it knows is held apart (BPCELL, BPSTORE) and joined to the others afterwards, a block at a time.
 */
struct frame_scan {
	int pushed, framed, bad;
};

static void frame_step(struct frame_scan *f, uint32_t i, const struct kgenome_cell_insn *in)
{
	if (!f->framed && i < 4u) {
		if (in->op == KGENOME_CELL_PUSH && in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == KGENOME_CELL_REG_BP)
			f->pushed = 1;
		else if (f->pushed && in->op == KGENOME_CELL_MOV && in->n_op >= 2u && in->o[0].kind == KGENOME_CELL_O_REG &&
			 in->o[0].reg == KGENOME_CELL_REG_BP && in->o[1].kind == KGENOME_CELL_O_REG && in->o[1].reg == KGENOME_CELL_REG_SP)
			f->framed = 1;
	} else if (f->framed && (in->wmask & (1ull << KGENOME_CELL_REG_BP)) && in->op != KGENOME_CELL_POP && in->n_op) {
		f->bad = 1;
	}
}

static int pred_holds(const struct lineage_pred *p, uint16_t bpred)
{
	return (bpred & p->all) == p->all && !(bpred & p->none) && (!p->any || (bpred & p->any));
}

/* What the memory operands of one instruction add to the block's bits. */
static uint16_t mem_bits(const struct kgenome_cell_insn *in)
{
	uint16_t pr = 0;
	uint8_t k;

	if (in->op == KGENOME_CELL_LEA)
		return 0;
	for (k = 0; k < in->n_op && k < 2u; k++) {
		const struct kgenome_cell_operand *o = &in->o[k];
		const int bp = o->reg == KGENOME_CELL_REG_BP && o->index == KGENOME_CELL_REG_NONE;
		const int store = (o->flags & KGENOME_CELL_OF_WRITE) && in->op != KGENOME_CELL_CALL && in->op != KGENOME_CELL_JMP &&
				  in->op != KGENOME_CELL_CMP && in->op != KGENOME_CELL_TEST && in->op != KGENOME_CELL_PUSH;

		if (o->kind != KGENOME_CELL_O_MEM || (o->reg == KGENOME_CELL_REG_SP && o->index == KGENOME_CELL_REG_NONE))
			continue;
		/* (a call through a slot names its operand 0 too, and does not write it) */
		pr |= bp ? (uint16_t)(P(BPCELL) | (store ? P(BPSTORE) : 0u)) : (uint16_t)(P(MEMCELL) | (store ? P(MEMSTORE) : 0u));
	}
	return pr;
}

/* What a call or a jump that leaves the function adds. */
static uint16_t call_bits(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in)
{
	uint32_t node, f;

	if (kgenome_lineage_site_in(L, in, &node))
		return (uint16_t)(P(NODE) | (kgenome_lineage_hands_on(L, &L->s->hit[node]) ? P(PRODUCER) : 0u));
	if (in->flags & KGENOME_CELL_F_INDIRECT)
		return P(ICALL);
	if (in->target_va == KGENOME_BROKEN)
		return 0;
	f = kgenome_lineage_fn_of_va(L, in->target_va);
	if (f == UINT32_MAX)
		return P(EXTCALL);
	return !L->rel || L->rel[f] || (L->skipped && L->skipped[f] == 3u) ? P(CALL_INT) : P(CALL_SKIP);
}

static int fn_holds(const struct kgenome_lineage_cfg *g, const struct lineage_pred *p);

/* One loop over the decoded instructions of the function, a block at a time. */
void kgenome_lineage_preds(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g)
{
	struct frame_scan fs = { 0, 0, 0 };
	uint32_t b;

	for (b = 0; b < g->nb; b++) {
		uint16_t pr = 0;
		uint32_t i;

		for (i = g->bfirst[b]; i < g->bfirst[b + 1u]; i++) {
			const struct kgenome_cell_insn *in = &L->in[i];

			frame_step(&fs, i, in);
			if (in->op == KGENOME_CELL_CALL || (in->op == KGENOME_CELL_JMP && kgenome_lineage_jmp_is_tail(L, in)))
				pr |= call_bits(L, in);
			else if (in->op == KGENOME_CELL_JMP && (in->flags & KGENOME_CELL_F_INDIRECT))
				pr |= P(ICALL);
			pr |= mem_bits(in);
			if (in->op == KGENOME_CELL_PUSH && L->abi.callee_pops)
				pr |= P(STACKARG);
		}
		/* a push counts as a stack argument only in a block that calls */
		if ((pr & P(STACKARG)) && !(pr & (P(NODE) | P(CALL_INT) | P(CALL_SKIP) | P(EXTCALL) | P(ICALL))))
			pr &= (uint16_t)~P(STACKARG);
		g->bpred[b] = pr;
	}
	/* with no frame pointer, what went through rbp is a place like any other */
	for (b = 0; b < g->nb; b++) {
		uint16_t pr = g->bpred[b];

		if (!fs.framed || fs.bad)
			pr |= (uint16_t)((pr & P(BPCELL) ? P(MEMCELL) : 0u) | (pr & P(BPSTORE) ? P(MEMSTORE) : 0u));
		g->bpred[b] = (uint16_t)(pr & ~(P(BPCELL) | P(BPSTORE)));
	}
}

/* Does a block the walk reached store to a place beyond the frame (the LOCS row's function predicate). */
int kgenome_lineage_has_store(const struct kgenome_lineage_cfg *g)
{
	return fn_holds(g, &lineage_rows[0].fn);
}

/* The stages active on a block: FLOW always, and each row's stage where the block holds its predicate and the run has it. */
unsigned kgenome_lineage_act(const struct kgenome_lineage *L, uint16_t bpred)
{
	unsigned act = KGENOME_LINEAGE_S_FLOW, r;

	if (L->plan & KGENOME_LINEAGE_S_EAGER)
		return L->run;
	for (r = 0; r < N_ROWS; r++)
		if (lineage_rows[r].stage && (L->run & lineage_rows[r].stage) && pred_holds(&lineage_rows[r].blk, bpred))
			act |= lineage_rows[r].stage;
	return act;
}

static int fn_holds(const struct kgenome_lineage_cfg *g, const struct lineage_pred *p)
{
	uint32_t b;

	for (b = 0; b < g->nb; b++)
		if (pred_holds(p, g->bpred[b]))
			return 1;
	return 0;
}

/* After a run: mark the blocks no walk from the entry reached (the predicate SEED reads). */
void kgenome_lineage_mark_unreached(struct kgenome_lineage_cfg *g)
{
	uint32_t b;

	for (b = 0; b < g->nb; b++)
		g->bpred[b] = g->bs[b].valid ? (uint16_t)(g->bpred[b] & ~P(UNREACHED)) : (uint16_t)(g->bpred[b] | P(UNREACHED));
}

/* The stages the run's obligations ask for that it has not run: the rows whose reason is pending and whose predicate the
 * function holds, among the stages the class allows. SEED is not one of them (kgenome_lineage_seed_wanted asks for it). */
unsigned kgenome_lineage_chain_next(const struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g)
{
	unsigned next = 0, r;

	for (r = 0; r < N_ROWS; r++) {
		const struct lineage_row *w = &lineage_rows[r];

		if (!w->stage || w->stage == S_SEED || !(L->plan & w->stage) || (L->run & w->stage))
			continue;
		if (w->ob && !(L->pend & w->ob))
			continue;
		if (fn_holds(g, &w->fn))
			next |= w->stage;
	}
	return next;
}

/* Do the blocks no walk from the entry reached hold anything the seed stage can use? */
int kgenome_lineage_seed_wanted(const struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g)
{
	unsigned r;

	if (!(L->plan & S_SEED))
		return 0;
	for (r = 0; r < N_ROWS; r++)
		if (lineage_rows[r].stage == S_SEED)
			return fn_holds(g, &lineage_rows[r].fn);
	return 0;
}

/* Is this unreached block one the seed stage enters? */
int kgenome_lineage_seed_block(const struct kgenome_lineage_cfg *g, uint32_t b)
{
	unsigned r;

	for (r = 0; r < N_ROWS; r++)
		if (lineage_rows[r].stage == S_SEED)
			return pred_holds(&lineage_rows[r].blk, g->bpred[b]);
	return 0;
}

/*
 * ---- WHAT NEVER RETURNS ----
 *
 * A call the program does not come back from ends its block: the bytes after it are the next function's (or padding), and a walk
 * that went on into them would hand the state of this function to that one - MEASURED, a link from an fopen in one function to a
 * send in the next (540/f of the static stripped cell, seeded code). The knowledge is COVERAGE the decoder cannot supply: which
 * callees do not return. Two sources. IMPORTS, by name, from this ONE small table - the functions declared noreturn by C11 and
 * glibc's headers [Inference: from the declarations, not from a list the engine already holds: it holds none, grep of libgenome
 * and libkofeng for noreturn found nothing]; and FUNCTIONS OF THE OBJECT, structurally (diag_lineage_summ.c): no `ret`, no jump
 * out, no jump through a register, and at least one call or syscall - what __stack_chk_fail, abort and _exit of a static binary
 * are. A noreturn function that tail-jumps or returns on some path is not found: said, not guessed.
 */
/* KNOWN DEFECT D10 (2026-10-24, R) [sev M]: noreturn_names lists C/glibc names only; the Windows ones (ExitProcess,
 * ExitThread, TerminateProcess, RtlExitUserProcess, __fastfail) are missing. Trigger: a PE whose function ends in a
 * call to ExitProcess. Effect: the block is not ended, the walk runs into the next function and hands it this one's
 * state (the 540/f mechanism above, wrong links). Reproducer: none (read). Fix: add the names, keyed by the import
 * name the PE route reports. */
static const char *const noreturn_names[] = {
	"exit", "_exit", "_Exit", "abort", "quick_exit", "__stack_chk_fail", "__stack_chk_fail_local", "__assert_fail", "__assert",
	"__assert_perror_fail", "__chk_fail", "__fortify_fail", "__libc_fatal", "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk",
	"pthread_exit", "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast", "__cxa_bad_typeid", "_Unwind_Resume", "err", "errx", "verr",
	"verrx", "thrd_exit"
};

int kgenome_diag_name_is_noreturn(const char *name)
{
	unsigned i;

	for (i = 0; name && i < sizeof noreturn_names / sizeof noreturn_names[0]; i++)
		if (!strcmp(name, noreturn_names[i]))
			return 1;
	return 0;
}

/* Is the call at file offset `at` one to an import that does not return (the symbol route found it). */
int kgenome_diag_site_noreturn(const struct kgenome_diag_scan *s, uint64_t at)
{
	uint32_t lo = 0, hi = s->n_noret;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (s->noret_at[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < s->n_noret && s->noret_at[lo] == at;
}

/* ---- what the selection did ---- */

static unsigned stage_slot(unsigned stage)
{
	return stage == KGENOME_LINEAGE_S_FLOW ? 0u : stage == S_LOCS ? 1u : stage == S_SUMM ? 2u : 3u;
}

/* One function solved, finally: how many blocks each stage was active on. */
void kgenome_lineage_stats_fn(struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g, unsigned nruns,
			      uint32_t seeded)
{
	uint32_t b;
	unsigned r;
	struct kgenome_diag_lineage_stats *st = &L->st;

	if (L->dry)
		return;
	/* (the blocks a stage was active on are those the walk reached - the block predicates say nothing of the rest) */
	st->fns++;
	st->runs += nruns;
	if (L->fn_run)
		L->fn_run[L->cur_fn] = (uint8_t)(L->run & KGENOME_LINEAGE_S_ALL);
	st->blocks += g->nb;
	st->fns_stage[0]++;
	for (b = 0; b < g->nb; b++) {
		if (!g->bs[b].valid)
			continue;               /* a block no walk reached was not stepped by any stage */
		st->blocks_stage[0]++;
		for (r = 0; r < N_ROWS; r++)
			if (lineage_rows[r].stage && lineage_rows[r].stage != S_SEED && (L->run & lineage_rows[r].stage) &&
			    ((L->plan & KGENOME_LINEAGE_S_EAGER) || pred_holds(&lineage_rows[r].blk, g->bpred[b])))
				st->blocks_stage[stage_slot(lineage_rows[r].stage)]++;
	}
	for (r = 0; r < N_ROWS; r++)
		if (lineage_rows[r].stage && lineage_rows[r].stage != S_SEED && (L->run & lineage_rows[r].stage))
			st->fns_stage[stage_slot(lineage_rows[r].stage)]++;
	if (seeded) {
		st->fns_stage[3]++;
		st->blocks_stage[3] += seeded;
	}
}

int kgenome_diag_lineage_stats_of(const struct kgenome_diag_scan *s, struct kgenome_diag_lineage_stats *out)
{
	if (!s || !out)
		return 0;
	*out = s->lstats;
	return 1;
}

/* ---- the unresolved set ---- */

/*
 * THE NEXT STAGE OF A LIMIT, as data in the style of the block table: a reason, and the stage that reads it away. A reason that
 * has no row has none - it is a gap of coverage (a rule the model lacks, a library it does not know) or of scope (what an
 * intra-function walk, a summary, a location cannot see), and is listed as such. The report counts the unresolved inputs by what
 * the table says of them: a next stage the plan allows and the function did not run is a bug of the pipeline; none is a limit.
 *   ENTRY    SUMM   the callers' values are what the parameter is (sinks, summaries)
 *   MEM      LOCS   a global or a field followed inside the function
 *   CALL     SUMM   what a function of the object returns
 *   UNREACH  SEED   a block no walk reached, entered by itself
 *   SKIP     DEMAND a function that was not read, read after all (off in every class: +0..8 links for half again the cost)
 *   the rest none:  EXT (indirect or foreign callee: needs a target or a library model), STACK (an unknown callee pop),
 *   OPAQUE (a missing instruction rule), RET (a callee the summaries do not describe), LIMIT (a bound), ADDR (a load
 *   through a pointer: needs a points-to model), COMPUTED (arithmetic: needs value sets or evaluation), CLOBBER, NARROW
 *   (sub-register values), SLOT (stack memory filled through pointers: needs address-taken locals), CELL (memory written
 *   in other functions: needs interprocedural locations), NOCALLER (a parameter with no direct caller: needs the indirect
 *   targets), STATUS (a node's non-handle result).
 */
struct lineage_next {
	unsigned why;
	unsigned stage;
};

static const struct lineage_next lineage_next[] = {
	{ KGENOME_LINEAGE_W_ENTRY, S_SUMM },
	{ KGENOME_LINEAGE_W_MEM, S_LOCS },
	{ KGENOME_LINEAGE_W_CALL, S_SUMM },
	{ KGENOME_LINEAGE_W_UNREACH, S_SEED },
	{ KGENOME_LINEAGE_W_SKIP, KGENOME_LINEAGE_S_DEMAND },
};

/* KNOWN DEFECT WP9-F16 (2026-10-25, Inference) [sev L]: kgenome_diag_oblig_next_stage shifts 1u by `bit`
 * with no range check. Trigger: bit >= 32 (not run: the adapter stays below 19). Effect: undefined shift
 * (UBSAN stops). Reproducer: none. Fix: `if (bit >= 32u) return 0u;` first. */
unsigned kgenome_diag_oblig_next_stage(unsigned bit)
{
	unsigned i;

	for (i = 0; i < sizeof lineage_next / sizeof lineage_next[0]; i++)
		if (lineage_next[i].why == (1u << bit))
			return lineage_next[i].stage;
	return 0;
}

uint32_t kgenome_diag_oblig_count(const struct kgenome_diag_scan *s)
{
	return s ? s->n_oblig : 0;
}

const struct kgenome_diag_oblig *kgenome_diag_oblig_at(const struct kgenome_diag_scan *s, uint32_t i)
{
	return s && i < s->n_oblig ? &s->oblig[i] : NULL;
}

/* What the object's table holds for one input: the reasons it is unknown, 0 when it is accounted for. */
static unsigned input_state(const struct kgenome_lineage *L, const struct kgenome_lineage_agg *a, int *partial)
{
	unsigned unk;

	*partial = 0;
	if (!a)
		return KGENOME_LINEAGE_W_UNREACH | ((L->over_steps || L->halt) ? KGENOME_LINEAGE_W_LIMIT : 0u);
	unk = a->other ? (unsigned)a->why & ~(unsigned)KGENOME_LINEAGE_W_CONST : 0u;
	if (a->n) {
		*partial = 1;
		return unk;
	}
	if (a->other)
		return unk;                     /* none known: a constant (resolved) or an unknown (the reasons) */
	return a->param ? KGENOME_LINEAGE_W_ENTRY : KGENOME_LINEAGE_W_UNREACH;
}

/* KNOWN DEFECT REV-D7b (2026-10-24, Inference) [sev L]: glob_find (the lineage global table) is a hand-rolled open-addressing table with an unseeded multiplicative
 * hash, not the shared helper (diag_oatab.h / kof_hash64_slot): CLAUDE.md rule 2. Trigger: keys chosen by the file that
 * collide in the top bits. Effect: probe chains grow (the G1 flood in the script tables took 20.4 s for 65536 names).
 * Reproducer: none (review_arch D7, read). Fix: build it on kgenome_oatab (seeded, one probe step) like diag_text_sum. */
static struct kgenome_lineage_agg *glob_find(const struct kgenome_lineage *L, uint32_t key)
{
	uint32_t m, i;

	if (!L->glob.cap)
		return NULL;
	m = L->glob.cap - 1u;
	for (i = ((key * 0x9e3779b1u) >> 7) & m; L->glob.v[i].key; i = (i + 1u) & m)
		if (L->glob.v[i].key == key)
			return &L->glob.v[i];
	return NULL;
}

/* Every input of every consumer node, once the links are written: counted, and the unaccounted ones kept. */
void kgenome_lineage_obligations(struct kgenome_lineage *L)
{
	struct kgenome_diag_scan *s = L->s;
	struct kgenome_diag_lineage_stats *st = &L->st;
	uint32_t pass, n = 0, k, i;

	for (pass = 0; pass < 2u; pass++) {
		if (pass == 1u) {
			uint64_t bytes = (uint64_t)n * sizeof *s->oblig;

			if (!n)
				break;
			if (!kgenome_ledger_charge(&s->led, bytes)) {
				kgenome_diag_note(s, KGENOME_OVER_BUDGET);
				break;
			}
			s->oblig = malloc(bytes);
			if (!s->oblig) {
				kgenome_ledger_release(&s->led, bytes);
				kgenome_diag_note(s, KGENOME_NOMEM);
				break;
			}
			/* kept with the scan: not given back with the stage's memory */
		}
		n = 0;
		for (k = 0; k < L->n_site; k++) {
			const struct kgenome_diag_hit *h = &s->hit[L->site_node[k]];
			uint32_t f = kgenome_lineage_fn_at(L, L->site_at[k]);
			uint8_t seen[8], ns = 0;
			unsigned q;

			for (q = 0; q < 6u; q++) {
				uint8_t role = kgenome_diag_role_of_arg(h->cap, q);
				int partial, dup = 0;
				unsigned why;

				if (role == KGENOME_DIAG_ROLE_NONE)
					continue;
				for (i = 0; i < ns; i++)
					dup |= seen[i] == role;
				if (dup || ns >= 8u)
					continue;
				seen[ns++] = role;
				why = input_state(L, glob_find(L, ((L->site_node[k] + 1u) << 8) | role), &partial);
				if (pass == 0u) {
					const struct kgenome_lineage_agg *a = glob_find(L, ((L->site_node[k] + 1u) << 8) | role);

					st->inputs++;
					st->fd_inputs += role == KGENOME_DIAG_ROLE_FD;
					if (a && a->n == 1u && !a->other)
						st->must++;
					else if (a && a->n)
						st->may++;
					if (why) {
						unsigned bit, miss = 0, off = 0, ran = 0;

						for (bit = 0; bit < KGENOME_LINEAGE_W_N; bit++) {
							const unsigned nx = (why >> bit & 1u) ? kgenome_diag_oblig_next_stage(bit) : 0u;

							if (!nx)
								continue;
							if (!(L->plan & nx))
								off = 1;
							/* the parameter machinery and the consideration of unreached blocks are on wherever the plan has the
							 * stage: what is left of these reasons is a register that is no parameter, a block with nothing to seed */
							else if (bit == 1u || bit == 7u || (f != UINT32_MAX && L->fn_run && (L->fn_run[f] & nx)))
								ran = 1;
							else
								miss = 1;
						}
						if (miss)
							st->next_missing++;
						else if (ran)
							st->next_ran++;
						else if (off)
							st->next_off++;
						else
							st->next_none++;
						st->unresolved++;
						st->fd_unresolved += role == KGENOME_DIAG_ROLE_FD;
						for (i = 0; i < KGENOME_LINEAGE_W_N; i++)
							if (why & (1u << i))
								st->why[i]++;
					}
				}
				if (!why)
					continue;
				if (pass == 1u) {
					struct kgenome_diag_oblig *o = &s->oblig[n];

					o->node = L->site_node[k];
					o->role = role;
					o->partial = (uint8_t)partial;
					o->why = why;
					o->fn_va = f == UINT32_MAX ? 0u : L->fn[f].va;
				}
				n++;
			}
		}
		if (pass == 1u)
			s->n_oblig = n;
	}
}
