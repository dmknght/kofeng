/*
 * diag_apihash.c - NAMING THE APIS A PE RESOLVES FOR ITSELF.
 *
 * A program that walks the loader data to find its own functions has none of
 * them in its import table, and what stands for an API in its code is a number
 * only the program understands: a hash, with a seed, a rotation and a combining
 * step the author picked and can change tomorrow. So nothing here reads the
 * number. The environment the emulator builds has a PEB, a module list and an
 * export directory for every library it models, and the program's own resolver
 * walks THAT - whatever it does with the names, it arrives at the stub of the
 * function it meant, and the stub reports which function it is.
 *
 * THIS IS AN ANALYSIS AND NOT A ROUTE'S SIDE EFFECT. Its product is a list of
 * calls - which API, from where, with what - and TWO things read it: the graph
 * (a node per call, see kgenome_diag_run_apihash) and the object's symbols (the
 * names become imports through a module's report, merged by objctx_diag.c).
 * One result, computed once per
 * object and kept by whoever asked first; neither reader runs the program.
 * Written twice, the two would disagree about which calls were made.
 *
 * ASKED FOR, never assumed - KOF_DIAG_ANALYSIS_APIHASH for the graph, and by the engine's
 * decrypt step when it wants the names for the object description. A program that does not
 * read the loader data costs a decode and nothing else; one that does costs a
 * run.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_scan.h"
#include "diag_private.h"
#include <kofdebug.h>
#include <kofcore.h>
#include <celllysis/capability.h>
#include <celllysis/cell.h>
#include <genotype/image/pe_image.h>
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <genotype/image/image_addr.h>
#include <phenotype/emu_unpack.h>
#include <phenotype/emu.h>
#include <celllysis/space.h>

/*
 * ---- DOES THE PROGRAM READ THE LOADER DATA ---------------------------------
 *
 * A read of the thread block at the offset the PEB is at - fs:[0x30] on 32-bit
 * Windows, gs:[0x60] on 64-bit - and then, a few instructions later, a load
 * through that register at the offset of PEB.Ldr (0x18 / 0x0c). It is a SHAPE
 * with no constant of the program's own in it: the author can change the hash,
 * the seed, the rotation, the function; he cannot change where the OS put the
 * loader.
 *
 * THE PEB READ ALONE IS NOT ENOUGH. Every C runtime reads it, for the image
 * base, the heap, BeingDebugged. MEASURED on 300 PE, the read alone sent 46 of
 * them to the emulator and the walk is a fraction of those.
 */
/*
 * HOW FAR THE PEB POINTER IS FOLLOWED. It was eight instructions, and that was the whole of the
 * evidence: a program that put twelve between the read and the load was not seen. The window is
 * now the pointer's own life. What holds the PEB is tracked - the register it was read into, any
 * register it is copied to, and a stack slot it is spilled to (an unoptimised build reads
 * `mov rax, gs:[0x60] ; mov [rsp+0x48], rax ; mov rax, [rsp+0x48] ; mov rax, [rax+0x18]`) - and the
 * walk ends where nothing holds it any more, or where the straight line ends (a RET or a plain
 * jump; a call takes the volatile registers with it). Padding is not evidence of anything, so it
 * cannot end the walk.
 *
 * The only bound left is the cost: every step is charged to the scan's instruction budget, shared
 * by all the candidates of the object (which scales with its code), and a window cut by it says so
 * through the set's status.
 */
#define PEB_SLOTS 16u

struct peb_hold {
	uint16_t regs;                          /* registers that hold the PEB, one bit each */
	uint8_t  n_slot;
	uint8_t  lost;                          /* a spill was forgotten for want of a slot */
	struct { uint8_t base; int64_t disp; } slot[PEB_SLOTS];
};

static int is_volatile_reg(unsigned reg, int wide)
{
	/* rax rcx rdx everywhere; r8-r11 on 64-bit. rbx rsi rdi rbp and r12-r15 survive a call. */
	return reg == KGENOME_CELL_REG_AX || reg == KGENOME_CELL_REG_CX || reg == KGENOME_CELL_REG_DX ||
	       (wide && reg >= 8 && reg <= 11);
}

/* A stack slot as a key: rsp or rbp plus a displacement, no index. */
static int peb_slot_of(const struct kgenome_cell_operand *o)
{
	return o->kind == KGENOME_CELL_O_MEM && o->index == KGENOME_CELL_REG_NONE &&
	       !(o->flags & KGENOME_CELL_OF_RIPREL) &&
	       (o->reg == KGENOME_CELL_REG_SP || o->reg == KGENOME_CELL_REG_BP);
}

static int peb_slot_find(const struct peb_hold *h, const struct kgenome_cell_operand *o)
{
	unsigned i;

	for (i = 0; i < h->n_slot; i++)
		if (h->slot[i].base == o->reg && h->slot[i].disp == o->disp)
			return (int)i;
	return -1;
}

static void peb_slot_put(struct peb_hold *h, const struct kgenome_cell_operand *o, int on)
{
	int i = peb_slot_find(h, o);

	if (!on) {
		if (i >= 0)
			h->slot[i] = h->slot[--h->n_slot];
		return;
	}
	if (i >= 0)
		return;
	if (h->n_slot == PEB_SLOTS) {
		h->lost = 1;                    /* the oldest spill is forgotten: the caller says so */
		h->slot[0] = h->slot[--h->n_slot];
	}
	h->slot[h->n_slot].base = o->reg;
	h->slot[h->n_slot].disp = o->disp;
	h->n_slot++;
}

/* After one instruction: what holds the PEB now. */
static void peb_step(struct peb_hold *h, const struct kgenome_cell_insn *in, int wide)
{
	unsigned r;

	if (in->op == KGENOME_CELL_MOV && in->n_op >= 2u) {
		const struct kgenome_cell_operand *d = &in->o[0], *src = &in->o[1];
		int on = 0;

		if (src->kind == KGENOME_CELL_O_REG && src->reg < 16u)
			on = (h->regs >> src->reg) & 1u;
		else if (peb_slot_of(src))
			on = peb_slot_find(h, src) >= 0;
		if (d->kind == KGENOME_CELL_O_REG && d->reg < 16u) {
			h->regs = (uint16_t)(on ? h->regs | (1u << d->reg) : h->regs & ~(1u << d->reg));
			return;
		}
		if (peb_slot_of(d)) {
			peb_slot_put(h, d, on);
			return;
		}
	}
	for (r = 0; r < 16u; r++)
		if ((in->wmask >> r) & 1u)
			h->regs = (uint16_t)(h->regs & ~(1u << r));
	if ((in->wmask >> KGENOME_CELL_REG_SP) & 1u) {
		unsigned i;

		for (i = 0; i < h->n_slot;)           /* the stack pointer moved: its slots are not these */
			if (h->slot[i].base == KGENOME_CELL_REG_SP)
				h->slot[i] = h->slot[--h->n_slot];
			else
				i++;
	}
	if (in->op == KGENOME_CELL_CALL)
		for (r = 0; r < 16u; r++)
			if (is_volatile_reg(r, wide))
				h->regs = (uint16_t)(h->regs & ~(1u << r));
}

/* `src` into a field of `cap` bytes, always terminated; 1 when it did not fit. */
static int copy_name(char *dst, size_t cap, const char *src)
{
	size_t n = strlen(src);
	int cut = n >= cap;

	if (cut)
		n = cap - 1u;
	memcpy(dst, src, n);
	dst[n] = 0;
	return cut;
}

static void note_peb(struct kgenome_diag_apihash_set *a, uint64_t at)
{
	if (a->n_peb == a->cap_peb) {
		uint32_t nc = a->cap_peb ? a->cap_peb * 2u : 16u;
		uint64_t *nv = realloc(a->peb, (size_t)nc * sizeof *nv);

		if (!nv) {
			/* a loader walk that was seen (n_ldr counted it) and not kept is a node
			 * the graph will not have: said in the product's status */
			a->status = kgenome_status_merge(a->status, KGENOME_NOMEM);
			KOF_TRACE("[cut] note_peb: %u loader walks kept, growth refused\n", a->n_peb);
			return;
		}
		a->peb = nv;
		a->cap_peb = nc;
	}
	a->peb[a->n_peb++] = at;
}

/*
 * ---- FINDING THE LOADER WALK WITHOUT DECODING THE PROGRAM ------------------
 *
 * The test is about an instruction with a SEGMENT OVERRIDE, and a segment
 * override is a prefix byte: 0x65 (GS) on 64-bit, 0x64 (FS) on 32-bit. So the
 * candidates are the places that byte occurs, and the exact test - the decoded
 * operand's segment and displacement, then a load of PEB.Ldr a few instructions
 * on - is made on the instruction that starts there. About one byte in 256 is a
 * candidate; decoding every instruction of every executable section to find
 * them was 6.7 s of the 300-file corpus, and as an analysis every PE object
 * pays for (not only the few that read the loader) it made the scan of that
 * corpus 3.8 times slower.
 *
 * WHY THE LOAD IS PART OF THE TEST AND NOT A SECOND STAGE. A byte that is not
 * an instruction boundary - the 0x65 of `jne +0x65`, a displacement, a string -
 * decodes from there as SOMETHING, and 1 in a few hundred of those somethings is
 * a read at gs:[0x60]: MEASURED, the override test alone found reads in 57 of
 * 300 PE that a linear sweep does not; the five I read were all misaligned bytes.
 * A misaligned candidate followed within eight instructions by a load through
 * the register at +0x18 is another matter, and the loader-walk count is
 * IDENTICAL to the decode-everything version on all 300 files (10 with a walk,
 * 5 of them with calls resolved). A false candidate costs a run of the resolver
 * and names nothing wrong, since what it names is what the run called.
 *
 * WHAT THIS DOES NOT CATCH, said so it is not rediscovered: an override that
 * follows another legacy prefix (`66 65 ..`, `67 65 ..`) starts at the other
 * prefix and is decoded from the override, which loses the first.
 */
static int is_peb_read(const struct kgenome_cell_insn *in, int wide)
{
	unsigned q;

	for (q = 0; q < in->n_op; q++) {
		const struct kgenome_cell_operand *o = &in->o[q];

		if (o->kind == KGENOME_CELL_O_MEM &&
		    o->seg == (wide ? KGENOME_CELL_SEG_GS : KGENOME_CELL_SEG_FS) &&
		    o->disp == (wide ? 0x60 : 0x30))
			return 1;
	}
	return 0;
}

static void atoms_in(struct kgenome_diag_apihash_set *a, const struct kgenome_obj *obj,
		     const uint8_t *base, uint64_t size, uint64_t off,
		     uint64_t n, int wide, uint64_t *steps)
{
	const uint8_t seg = wide ? 0x65u : 0x64u;
	uint64_t pos = off, end = off + n;
	struct kgenome_cell_space sp;

	kgenome_cell_space_init(&sp, obj, base, size);

	while (pos < end) {
		const uint8_t *hit = memchr(base + pos, seg, end - pos);
		struct kgenome_cell_cur k;
		struct kgenome_cell_insn in;

		if (!hit)
			break;
		pos = (uint64_t)(hit - base) + 1u;
		memset(&k, 0, sizeof k);
		if (!kgenome_cell_seek(&k, (uint64_t)(hit - base), 0) ||
		    !kgenome_cell_step(&k, &sp, &in) ||
		    !is_peb_read(&in, wide))
			continue;
		/* THE LOADER DATA ITSELF, a few instructions later: a load through
		 * the register the PEB went to, at the offset of PEB.Ldr. */
		if (in.n_op && in.o[0].kind == KGENOME_CELL_O_REG) {
			int reg = in.o[0].reg;
			uint64_t at = in.at;
			int found = 0;
			struct peb_hold hold;

			memset(&hold, 0, sizeof hold);
			if (reg >= 0 && reg < 16)
				hold.regs = (uint16_t)(1u << reg);
			while (!found && k.at < end && (hold.regs || hold.n_slot)) {
				unsigned q;

				if (!*steps) {
					a->status = kgenome_status_merge(a->status, KGENOME_OVER_BUDGET);
					return;         /* the budget is spent: said, not silent */
				}
				--*steps;
				if (!kgenome_cell_step(&k, &sp, &in))
					break;
				/* a load through whatever holds the PEB, at the offset of PEB.Ldr */
				for (q = 0; q < in.n_op; q++) {
					const struct kgenome_cell_operand *o = &in.o[q];

					if (o->kind == KGENOME_CELL_O_MEM && o->reg < 16u &&
					    ((hold.regs >> o->reg) & 1u) &&
					    o->disp == (wide ? 0x18 : 0x0c)) {
						a->n_ldr++;
						note_peb(a, at);
						found = 1;
						break;
					}
				}
				if (found)
					break;
				peb_step(&hold, &in, wide);
				/* the straight line ends */
				if (in.op == KGENOME_CELL_RET ||
				    (in.op == KGENOME_CELL_JMP && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
				     !(in.flags & KGENOME_CELL_F_FAR)))
					break;
			}
			if (hold.lost)
				a->status = kgenome_status_merge(a->status, KGENOME_TRUNCATED);
		}
	}
}

/*
 * ---- RUNNING THE PROGRAM'S OWN RESOLVER -----------------------------------
 *
 * A program that finds its APIs by walking the loader data has none of them in
 * its import table, and what stands for an API in its code is a number. The
 * number is meaningful only to the program: a hash, with a seed, a rotation and
 * a combining step the author picked, any of which he can change tomorrow. So
 * nothing here reads it. The environment the emulator builds has a PEB, a
 * module list and an export directory for every library it models, and the
 * program's resolver walks THAT - whatever it does with the names, it arrives at
 * the stub of the function it meant, and the stub reports which function it is.
 *
 * MEASURED, on the plain Metasploit stager and on the same stager rebuilt with
 * `ror 14` and a new seed, with `xor` for `add`, and with `rol` for `ror`
 * (every hash recomputed): all four resolve the same seven calls in the same
 * order from the same places. A table of hash values finds the first two and
 * none of the others, which is the reason this is not one.
 *
 * ONLY FOR A PROGRAM THAT READS THE LOADER DATA, which is what
 * KGENOME_NUCLEO_SELF_RESOLVE says it does. The decode that finds the read is
 * already being made; the run is paid for by the objects that need it.
 *
 * THE LINKS COME FROM THE VALUES. A call's result is a value the program holds,
 * and a later call that takes that value as its descriptor or its buffer is the
 * same object: the socket WSASocketA returned is the first argument of the
 * connect and of both reads; the pointer VirtualAlloc returned is the buffer of
 * the second read. Each argument that has a role (kgenome_diag_role_of_arg) is
 * matched against the results so far, and a value too small to be a handle or
 * a pointer is not matched - 0x1000 is a length as often as it is anything.
 */
/*
 * THE RUN IS SLICED AND ENDS WHEN IT STOPS ANSWERING. A resolver costs about
 * twenty thousand instructions per API (it scans the modules for the hash), so
 * a stager that makes seven calls is done in 140 thousand; and a program that
 * is NOT resolving anything is the expensive case, because nothing tells the
 * run it has nothing to say. So it goes a slice at a time and stops after a few
 * slices with no new call, with the old two-million total as the ceiling.
 *
 * AND IT DOES NOT EXTEND. The default is to keep running past the budget for as
 * long as each slice writes a new page, which is right for an unpacker and
 * wrong here: MEASURED, 3 of 46 files ran 16-18 million instructions each, 87%
 * of the whole, to produce the same API calls the first million had.
 */
#define DIAG_PE_SLICE 16000ull
/*
 * THE CEILING is the caller's resolver budget (kgenome_budget.max_insn_resolve),
 * max(4M, 64 x the code's bytes) when it did not set one. It was a fixed 2M, and
 * then the emulate route's max_insn; it is its own number now because this run
 * stops when the program goes silent, which makes a bigger floor cheap here and
 * not there (see KGENOME_RESOLVE_MIN). Spent, the run ends KGENOME_OVER_BUDGET.
 *
 * THE SILENCE WINDOW IS A FRACTION OF THAT BUDGET, and not twelve slices. A run
 * that makes no new API call for a stretch is stopped, which is what kept three
 * files in forty-six from burning 87% of the whole run's instructions to repeat
 * the calls the first million had made. But a stager that waits - the busy loop
 * of sandbox evasion - is silent for as long as its author chose, so a fixed
 * window decided what an evader could hide behind: twelve slices (192000
 * instructions) was missed by a 300000-instruction wait and by a polling loop
 * that calls one API once per lap. The window is one eighth of the budget, never
 * less than the twelve slices: the budget stays the DoS bound, and the silence
 * test only has to be a fraction of it to keep its saving on the runs that
 * really are done. Ended by it the run is KGENOME_TRUNCATED, which is how a stager
 * that waits longer is reported as "cannot say" and not as clean.
 */
#define DIAG_PE_IDLE_MIN 12u

static uint32_t pe_idle_slices(const struct kgenome_budget *bud)
{
	uint64_t n = bud->max_insn_resolve / DIAG_PE_SLICE / 8u;

	if (n < DIAG_PE_IDLE_MIN)
		return DIAG_PE_IDLE_MIN;
	return n > 0xffffffffu ? 0xffffffffu : (uint32_t)n;
}


static void run_resolver(struct kgenome_diag_apihash_set *a, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size,
			 const struct kgenome_pe_imptab *imports,
			 const struct kgenome_budget *bud)
{
	struct kgenome_emu_unp_report rep;
	struct kgenome_emu *em;
	struct kgenome_budget first;
	uint32_t n_ev, i;

	memset(&first, 0, sizeof first);
	first.max_insn = DIAG_PE_SLICE;
	first.insn_spent = bud->insn_spent;
	memset(&rep, 0, sizeof rep);
	em = kgenome_emu_unp_run_pe(&(const struct kgenome_emu_unp_pe_req){
			.file = base,
			.n = size,
			.info = kgenome_obj_pe(obj),
			.imports = imports,
			.bud = &first,
			.idle = 0,
			.hand_back = 1,
			.extensions = 0u,
			.oep = NULL,
			.n_oep = 0,
			.decl = NULL,
			.rep = &rep,
		});
	if (!em) {
		a->status = KGENOME_NOMEM;
		return;
	}
	if (bud->deadline_ms)
		kgenome_emu_set_deadline(em, bud->deadline_ms);
	{
		enum kgenome_emu_stop st = rep.stop;
		uint64_t done = kgenome_emu_insn_count(em);
		uint32_t seen = kgenome_emu_win_event_count(em), idle = 0;
		const uint32_t idle_max = pe_idle_slices(bud);

		while (st == KGENOME_EMU_STOP_BUDGET && done < bud->max_insn_resolve &&
		       idle < idle_max) {
			uint32_t now;

			kgenome_emu_set_max_insn(em, done + DIAG_PE_SLICE);
			st = kgenome_emu_run(em);
			done = kgenome_emu_insn_count(em);
			now = kgenome_emu_win_event_count(em);
			idle = now > seen ? 0u : idle + 1u;
			seen = now;
		}
		/* THE BUDGET ENDED IT, said in the product: a caller told "these
		 * are the calls" when the run was cut short has no way to know
		 * there were more. */
		if (st == KGENOME_EMU_STOP_BUDGET)  /* still running when it was stopped */
			a->status = done >= bud->max_insn_resolve ? KGENOME_OVER_BUDGET
							  : KGENOME_TRUNCATED;
		else if (st == KGENOME_EMU_STOP_STALLED)
			a->status = KGENOME_TRUNCATED;
		else if (st == KGENOME_EMU_STOP_UNSUPPORTED)
			a->status = KGENOME_UNSUPPORTED;
	}
	/* A page, a table or a library the model refused is a run that is not the whole answer:
	 * the product's status says so (the emulator keeps it sticky in kgenome_emu_hit). */
	if (kgenome_emu_hit(em) & KGENOME_EMU_HIT_MEM)
		a->status = kgenome_status_merge(a->status, KGENOME_NOMEM);
	if (kgenome_emu_hit(em) & (KGENOME_EMU_HIT_LIB | KGENOME_EMU_HIT_VMA))
		a->status = kgenome_status_merge(a->status, KGENOME_TRUNCATED);
	n_ev = kgenome_emu_win_event_count(em);
	a->call = calloc(n_ev ? n_ev : 1u, sizeof *a->call);
	if (!a->call) {
		a->status = KGENOME_NOMEM;
		kgenome_emu_free(em);
		return;
	}
	for (i = 0; i < n_ev; i++) {
		struct kgenome_emu_win_event ev;
		struct kgenome_diag_apihash_call *c = &a->call[a->n_call];
		const char *nm, *dll;

		if (!kgenome_emu_win_event_at(em, i, &ev) || !ev.site)
			continue;
		nm = kgenome_emu_win_api_name(ev.api);
		dll = kgenome_emu_win_mod_name(kgenome_emu_win_api_mod(ev.api));
		if (!nm)
			continue;
		memset(c, 0, sizeof *c);
		c->site = ev.site;
		c->ret = ev.ret;
		memcpy(c->arg, ev.arg, sizeof c->arg);
		/* The names are the emulator's own stub names, which fit (tests/lib/genome/silent_cuts_genome.c
		 * walks the whole table); a name that did not would no longer be the vocabulary's word, so
		 * it is said in the product's status and not stored cut. */
		if (copy_name(c->api, sizeof c->api, nm) | copy_name(c->dll, sizeof c->dll, dll ? dll : "")) {
			a->status = kgenome_status_merge(a->status, KGENOME_TRUNCATED);
			KOF_TRACE("[cut] apihash call: a name over the %zu/%zu kept\n", sizeof c->api, sizeof c->dll);
		}
		a->n_call++;
	}
	a->end_rip = kgenome_emu_get_rip(em);
	a->end_from = kgenome_emu_last_branch_at(em);
	kgenome_emu_free(em);
}

struct kgenome_diag_apihash_set *kgenome_diag_apihash_run(const struct kgenome_obj *obj,
				    const uint8_t *base, uint64_t size,
				    const struct kgenome_pe_imptab *imports,
				    const struct kgenome_budget *budget)
{
	const struct kgenome_pe_info *p;
	struct kgenome_diag_apihash_set *a;
	struct kgenome_budget bud;
	uint64_t steps;
	uint32_t i;
	int wide;

	if (!obj || obj->format != KGENOME_FMT_PE || !base || !size)
		return NULL;
	p = kgenome_obj_pe(obj);
	if (!p || !p->valid)
		return NULL;
	a = calloc(1, sizeof *a);
	if (!a)
		return NULL;
	wide = p->pe32_plus != 0;
	/* The budget: the caller's, every zero field the default for this object. */
	kgenome_budget_default(&bud, budget && budget->obj_size ? budget->obj_size : size,
			       budget && budget->code_bytes ? budget->code_bytes
							    : kgenome_diag_code_bytes(obj, size));
	if (budget && budget->max_insn)
		bud.max_insn = budget->max_insn;
	if (budget && budget->max_insn_resolve)
		bud.max_insn_resolve = budget->max_insn_resolve;
	bud.deadline_ms = budget ? budget->deadline_ms : 0;
	bud.insn_spent = budget ? budget->insn_spent : NULL;
	steps = bud.max_insn;
	for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

		if (have)
			atoms_in(a, obj, base, size, at, have, wide, &steps);
	}
	/* Only a program that read the loader data and then loaded from it is
	 * worth a run. */
	if (a->n_ldr)
		run_resolver(a, obj, base, size, imports, &bud);
	return a;
}

void kgenome_diag_apihash_free(struct kgenome_diag_apihash_set *a)
{
	if (!a)
		return;
	free(a->peb);
	free(a->call);
	free(a);
}

/*
 * ---- THE GRAPH'S READING OF THE PRODUCT ------------------------------------
 *
 * THE ATOM FIRST, which is the detection layer and needs no resolver: a read
 * of the loader data that LEADS to the module list is a KGENOME_NUCLEO_SELF_RESOLVE
 * node at the instruction, and is there whether or not the run that follows
 * names anything. THIS IS THE ONLY PRODUCER of that node: the import walk in
 * diag_pe.c used to make one for every read of the PEB, which was the same job
 * done by a second path with a looser test, and a C runtime's read is not a
 * walk. Then a node per call, with the links from the values.
 */
void kgenome_diag_run_apihash(struct kgenome_diag_scan *s,
			  const struct kgenome_obj *obj,
			  const uint8_t *base, uint64_t size)
{
	const struct kgenome_diag_apihash_set *a;
	uint16_t *node;
	uint64_t *region, *rlen;
	uint32_t i, k;

	(void)base;
	(void)size;
	if (!obj || obj->format != KGENOME_FMT_PE)
		return;
	a = kgenome_diag_apihash(s, obj);
	if (!a) {
		/* NULL for a PE that parsed is the product's own allocation refused */
		const struct kgenome_pe_info *pi = kgenome_obj_pe(obj);

		if (pi && pi->valid) {
			kgenome_diag_note(s, KGENOME_NOMEM);
			KOF_TRACE("[cut] kgenome_diag_run_apihash: product not allocated\n");
		}
		return;
	}
	for (i = 0; i < a->n_peb; i++)
		kgenome_diag_hit_add(s, a->peb[i], KGENOME_NUCLEO_SELF_RESOLVE, 0);
	/* STOPPED WHILE THE PROGRAM WAS STILL RUNNING - at the instruction
	 * ceiling or after a silence - so calls after this point are not in the
	 * list. A bound is allowed to cost cost; it is not allowed to be silent
	 * about what it cost (CLAUDE.md 4), so the scan says it did not finish. */
	kgenome_diag_note(s, a->status);
	if (!a->n_call)
		return;
	node = calloc(a->n_call, sizeof *node);
	region = calloc(a->n_call, sizeof *region);
	rlen = calloc(a->n_call, sizeof *rlen);
	if (!node || !region || !rlen) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		KOF_TRACE("[cut] kgenome_diag_run_apihash: %u calls not turned into nodes\n", a->n_call);
		goto out;
	}

	for (i = 0; i < a->n_call; i++) {
		const struct kgenome_diag_apihash_call *c = &a->call[i];
		struct kgenome_diag_hit *h;
		uint8_t fl = 0;
		uint16_t cap;
		uint64_t at;
		uint32_t before;

		node[i] = 0xffffu;
		cap = kgenome_nucleo_cap_of_call(KGENOME_NUCLEO_T_PE, c->api, c->arg, &fl);
		if (cap == KGENOME_NUCLEO_NONE)
			continue;
		at = kgenome_image_addr_to_off(obj, c->site);
		if (at == KGENOME_BROKEN)
			continue;
		before = kgenome_diag_scan_count(s);
		h = kgenome_diag_hit_add(s, at, cap, fl);
		if (!h || kgenome_diag_scan_count(s) != before + 1u)
			continue;
		node[i] = (uint16_t)before;
		/* an allocation owns the range it returned, for the jump below */
		if (cap == KGENOME_NUCLEO_ALLOC || cap == KGENOME_NUCLEO_ALLOC_EXEC) {
			region[i] = c->ret;
			rlen[i] = c->arg[1];
		}
		for (k = 0; k < 4u; k++) {
			uint8_t role = kgenome_diag_role_of_arg(cap, k);
			uint32_t j;

			if (role == KGENOME_DIAG_ROLE_NONE || c->arg[k] < 0x100u)
				continue;
			for (j = 0; j < i; j++)
				if (node[j] != 0xffffu &&
				    a->call[j].ret == c->arg[k]) {
					kgenome_diag_note_in(s, h, node[j], role,
							 KGENOME_DIAG_KIND_PRODUCED);
					break;
				}
		}
	}

	/*
	 * THE JUMP INTO WHAT WAS ALLOCATED. The run ends where the stager hands
	 * over, and the instruction that handed over is the one that last
	 * transferred control: `jmp r15` with r15 the pointer VirtualAlloc
	 * returned. It is a node of its own - a branch into memory an earlier step
	 * produced, KGENOME_NUCLEO_EXEC_REG - and the link is from the allocation.
	 * Only the END of the run is looked at; a program that enters its buffer
	 * and carries on is not seen doing it.
	 */
	for (i = 0; i < a->n_call; i++)
		if (node[i] != 0xffffu && region[i] &&
		    a->end_rip >= region[i] &&
		    a->end_rip - region[i] < rlen[i]) {
			uint64_t at = a->end_from
				      ? kgenome_image_addr_to_off(obj, a->end_from)
				      : KGENOME_BROKEN;
			uint32_t before = kgenome_diag_scan_count(s);
			struct kgenome_diag_hit *h;

			if (at == KGENOME_BROKEN)
				break;
			h = kgenome_diag_hit_add(s, at, KGENOME_NUCLEO_EXEC_REG, 0);
			if (h && kgenome_diag_scan_count(s) == before + 1u)
				kgenome_diag_note_in(s, h, node[i], KGENOME_DIAG_ROLE_TARGET,
						 KGENOME_DIAG_KIND_PRODUCED);
			break;
		}
out:
	free(node);
	free(region);
	free(rlen);
}

uint32_t kgenome_diag_apihash_distinct(const struct kgenome_diag_apihash_set *a, const char **dll,
			      const char **name)
{
	uint32_t i, n = 0;

	if (!a)
		return 0;
	for (i = 0; i < a->n_call; i++) {
		uint32_t k;

		/* Once per API: the same function called from nine places is one
		 * thing the program uses. */
		for (k = 0; k < n; k++)
			if (!strcmp(name[k], a->call[i].api) &&
			    !strcmp(dll[k], a->call[i].dll))
				break;
		if (k < n)
			continue;
		dll[n] = a->call[i].dll;
		name[n] = a->call[i].api;
		n++;
	}
	return n;
}
