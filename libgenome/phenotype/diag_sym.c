/*
 * diag_sym.c - nodes from what an object IMPORTS, and the links between them.
 *
 * WHY A SECOND STATIC ROUTINE.
 *
 * The syscall sweep finds a node where a program enters the kernel. A
 * loadable kernel module never does: it IS the other side of a system call,
 * and it reaches everything through functions the kernel exported to it. So
 * on a .ko the sweep is not wrong, it is silent - MEASURED, Diamorphine's two
 * builds yield 0 nodes from it, and the only reason is that there is no
 * syscall instruction to find.
 *
 * WHAT IT HAS INSTEAD IS A RELOCATION TABLE. A .ko has no dynamic section, no
 * GOT and no PLT; a call to an imported function is `e8 00 00 00 00` with an
 * R_X86_64_PLT32 beside it naming the symbol. The name is not in the
 * instruction and cannot be decoded out of it - it is in `.rela.text`, which
 * kgenome_elf_relcalls already reads.
 *
 * SO THE NODE SITES ARE FREE. No sweep, no candidate scan, no decode to find
 * them: the table lists every call to every import. Decoding is needed only
 * for the part the table cannot answer, which is what was in the registers.
 *
 *
 * ---- THE LINK MODEL IS THE SAME ONE, AND HERE IT SHOULD WORK -------------
 *
 * The provenance map fails on compiled userspace malware for a reason that is
 * not about compilation: the node it extracts is libc's syscall WRAPPER, and
 * a wrapper takes its arguments from the caller's frame. MEASURED on 146
 * mirai samples - 286 link attempts, 2 successes.
 *
 * A kernel module has no wrapper in between. `call prepare_creds` is in the
 * author's own function, and what it returns is in rax where the next
 * instruction can be seen using it. Diamorphine's god_mode is the shape:
 *
 *     call prepare_creds      ; the node
 *     mov  %rax,%rdi          ; one instruction, register to register
 *     ...                     ; zero the uid and gid fields
 *     jmp  commit_creds       ; the node this links to
 *
 * 0x2d bytes, one function, and the one step between them is a move the
 * origin map already follows. If the model cannot link that, the model is
 * wrong rather than merely limited.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "diag_scan.h"
#include "diag_private.h"
#include <kofcore.h>
#include <celllysis/capability.h>
#include <genotype/image/elf_image.h>
#include <celllysis/nucleo.h>
#include <genotype/image/image_addr.h>
#include <celllysis/space.h>


/*
 * ---- WHICH SYMBOL AN INSTRUCTION'S OPERAND REALLY NAMES ------------------
 *
 * A relocatable object's operands are HOLES: `&__this_module->list` assembles
 * as `48 c7 c7 00 00 00 00`, and the symbol and the offset are in the
 * relocation beside the instruction rather than in it. Without this the walk
 * reads a register loaded with zero and the whole statement disappears.
 *
 * ONLY THE ONES A WALK CAN USE. Calls are already handled - they come through
 * kgenome_elf_relcalls and become sites - so what is read here is the rest:
 * an operand that names a symbol. The two kinds are kept apart because a call
 * relocation's `where` points at a displacement the decoder already resolves,
 * and treating it as an operand would set a register from a branch target.
 */
/*
 * A register written by an instruction whose operand a relocation names now
 * carries that symbol - see struct kgenome_diag_org.
 *
 * AFTER kgenome_diag_org_step AND NOT BEFORE, because the step clears every
 * register the instruction wrote, and this is what the instruction wrote.
 *
 * A REGISTER DESTINATION ONLY. A call's own relocation patches the
 * displacement inside the branch, which is a KGENOME_CELL_O_REL operand, so the test
 * below is what keeps a branch target from being read as a loaded address.
 */
static void note_symref(struct kgenome_diag_orgs *w, const struct kgenome_elf_relocs *t,
			const struct kgenome_cell_insn *in)
{
	const struct kgenome_elf_reloc *r;

	if (in->n_op < 1u || in->o[0].kind != KGENOME_CELL_O_REG)
		return;
	r = kgenome_elf_reloc_in(t, in->at, in->len);
	if (!r)
		return;
	kgenome_diag_org_set_sym(w, in->o[0].reg, (uint32_t)r->nameoff,
			     (int32_t)r->addend);
}

struct relsite {
	uint64_t at;            /* what a decoder computes as the target */
	uint16_t cap;
	/*
	 * The vocabulary's id for the name, not the string - see
	 * kgenome_nucleo_name_id - which is the ROW the call's shape is read
	 * from (kgenome_nucleo_call_role, kgenome_nucleo_call_hands_on): one
	 * capability covers calls that differ in which argument is which and
	 * in whether the object comes back (mmap and mprotect are both an
	 * executable mapping and only the first hands one back).
	 */
	uint16_t name;
	uint8_t  argrole[6];    /* which input each argument register is */
};

/*
 * THE SITES GROW WITH THE OBJECT. They were a static array of 512 - a bound on
 * a RESULT, silently dropping every import call after it, and shared by every
 * thread that scanned a module at once. The sites an object has are the sites
 * its relocation table lists, which its own size bounds; `oom` is the one
 * honest way to run out, and it is reported on the scan.
 */
struct relgather {
	struct relsite *site;
	uint32_t        n, cap_n;
	int             oom;
};


/* Does this call hand something on that a later one could be holding. */

static void gather(struct relgather *g, const struct kgenome_diag_rcall *rc)
{
	uint64_t at = rc->at;
	uint16_t cap = rc->cap;
	unsigned i;

	/* An internal call goes to code this object defines; it imports
	 * nothing and names no capability. */
	if (rc->target || cap == KGENOME_NUCLEO_NONE)
		return;
	if (g->n == g->cap_n) {
		uint32_t nc = kgenome_grow_cap(g->cap_n, 64u);
		struct relsite *ns = nc ? realloc(g->site, (size_t)nc * sizeof *ns) : NULL;

		if (!ns) {
			g->oom = 1;
			return;
		}
		g->site = ns;
		g->cap_n = nc;
	}
	g->site[g->n].at = at;
	g->site[g->n].cap = cap;
	g->site[g->n].name = rc->name;
	for (i = 0; i < 6u; i++)
		g->site[g->n].argrole[i] = kgenome_nucleo_call_role(cap, rc->name, i);
	g->n++;
}

/* rdi, rsi, rdx, rcx, r8, r9 - the SysV call convention, which is NOT the
 * syscall one: a call passes its fourth argument in rcx where a syscall uses
 * r10. The two tables differ in exactly that slot and the difference is the
 * reason this one is written out rather than borrowed. */
const uint8_t kgenome_diag_sysv_arg[6] = {
	KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
	KGENOME_CELL_REG_CX, 8u, 9u
};

/* A site's decoder address and where it is in the gather order, so a call can
 * be matched to its site by binary search - the walk used to scan every site
 * for every call instruction. Ordered by address THEN index, so among sites
 * that share one the lowest-numbered wins, which is what the scan chose. */
struct site_at {
	uint64_t at;
	uint32_t idx;
};

static int site_at_cmp(const void *x, const void *y)
{
	const struct site_at *a = x, *b = y;

	if (a->at != b->at)
		return a->at < b->at ? -1 : 1;
	return a->idx < b->idx ? -1 : a->idx > b->idx;
}

/*
 * A FORWARD JCC THIS WALK HAS NOT PHYSICALLY REACHED YET: the origin map as it stood when the
 * branch was taken, remembered at its target. The walk never jumps - it only ever reads the
 * fallthrough - but it does, eventually, read every byte of the function in order, so when it
 * arrives at the target the two paths are merged with kgenome_diag_org_merge (the sweep's own
 * primitive for exactly this question, diag_origin.c - not a second copy of its logic). A
 * register one path set and the other did not comes out MAY; one both paths set the same way
 * stays PROVEN. Scoped to one function at a time (reset with every entry of the outer loop
 * below), so a small fixed table is enough - SYM_JOIN_MAX is generous for one function's own
 * forward branches, and a table that fills demotes instead of guessing (reported, not silent).
 */
struct sym_join {
	uint64_t at;
	struct kgenome_diag_orgs w;
};
#define SYM_JOIN_MAX 16u

void kgenome_diag_run_symbol(struct kgenome_diag_scan *s,
			 const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size)
{
	struct relsite  *sites;
	const struct kgenome_func *fns;
	uint16_t        *node_of = NULL;
	struct site_at  *by_at = NULL;
	const struct kgenome_elf_relocs *rt;
	struct kgenome_cell_space sp;
	struct kgenome_diag_callees ce;
	struct relgather g;
	const struct kgenome_func_set *fg;
	const struct kgenome_elf_info *ei;
	struct sym_join *pj = NULL;
	uint32_t i, j;

	/* A PE has an import table and not a relocation table; its half of this
	 * route is in diag_pe.c. */
	if (obj && obj->format == KGENOME_FMT_PE) {
		kgenome_diag_run_pe_symbol(s, obj, base, size);
		return;
	}

	if (!obj || obj->format != KGENOME_FMT_ELF)
		return;
	ei = kgenome_obj_elf(obj);
	if (!ei || !ei->valid)
		return;
	/* A LINKED object has no relocation table to read its calls from: its imports are the GOT's
	 * slots, and its half of this route (x86-64 and i386) is in diag_elfimp.c. */
	if (ei->e_type != KGENOME_ELF_REL) {
		kgenome_diag_run_elf_symbol(s, obj, base, size);
		return;
	}
	/*
	 * A RELOCATABLE OBJECT IS x86-64 ONLY, and said here rather than left to fail quietly: the
	 * argument registers above are that ABI's, and i386 passes a module's arguments differently.
	 */
	if (obj->arch != KGENOME_ARCH_X86_64)
		return;

	memset(&g, 0, sizeof g);
	/* The object's relocations - one table, read by every route - see
	 * struct kgenome_elf_relocs. The call sites are the records of it flagged
	 * `call`, and kgenome_elf_reloc_in answers only for a CODE relocation with
	 * a name, which is what an operand can stand for. */
	rt = kgenome_diag_relocs(s, obj, KGENOME_ELF_RELOC_CODE);
	{
		uint32_t nrc, k;
		const struct kgenome_diag_rcall *rc = kgenome_diag_relcalls(s, obj, &nrc);

		for (k = 0; k < nrc; k++)
			gather(&g, &rc[k]);
	}
	sites = g.site;
	if (g.oom) {
		s->halt = 1;
		kgenome_diag_note(s, KGENOME_NOMEM);
	}
	if (!g.n)
		goto out;
	node_of = malloc((size_t)g.n * sizeof *node_of);
	by_at = malloc((size_t)g.n * sizeof *by_at);
	if (!node_of || !by_at) {
		s->halt = 1;
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}

	/*
	 * EVERY SITE BECOMES A NODE BEFORE ANY WALK STARTS.
	 *
	 * A node is a SITE - the same rule the emulate routine had to be
	 * taught - and a site exists because the relocation table says so,
	 * not because a walk reached it. Creating them first also means a
	 * link can name a node the walk has not arrived at yet, which is what
	 * a tail call needs: god_mode ends `jmp commit_creds`, so the last
	 * thing in the function is the node the whole chain points at.
	 */
	for (i = 0; i < g.n; i++) {
		struct kgenome_diag_hit *h;
		/* kgenome_elf_relcalls reports FILE OFFSETS, not addresses - a
		 * relocatable object has no load address to report. */
		uint64_t off = sites[i].at;

		node_of[i] = 0xffffu;
		if (off >= size)
			continue;
		/* KNOWN DEFECT SYM-DUP-1 (2026-11-12, R) [sev L]: this loop never dedupes by `off` -
		 * two relocation CALL sites sharing one r_offset each get their own hit node, but the
		 * walk below only ever links the first node found at an address, leaving the second
		 * permanently input-less.
		 * Trigger: a .ko with two relocations at one offset. Effect: an orphan node, no
		 * evidence lost, just an unlinked duplicate. Fix: fold matching `off` before this loop. */
		h = kgenome_diag_hit_add(s, off, sites[i].cap, 0);
		if (!h)
			continue;       /* full: the rest keep their 0xffff */
		h->row = sites[i].name;
		node_of[i] = (uint16_t)(s->n_hit - 1u);
	}
	for (i = 0; i < g.n; i++) {
		by_at[i].at = sites[i].at;
		by_at[i].idx = i;
	}
	qsort(by_at, g.n, sizeof *by_at, site_at_cmp);

	fg = kgenome_diag_funcs(s, obj);
	fns = fg->v;

	/*
	 * ---- ONE WALK PER FUNCTION ---------------------------------------
	 *
	 * NOT A WINDOW AROUND EACH SITE, which was the first shape and was
	 * wrong: every site re-walked from its own lead-in gets a fresh
	 * origin map, so a value one call produced is never in the map when
	 * the next call reads it, and no link can form at all.
	 *
	 * A FUNCTION IS THE RIGHT UNIT because it is the scope a register
	 * means anything in. The symbol table states where each one begins
	 * and ends, so this costs no search; and it bounds the walk, which a
	 * sweep of the section would not.
	 */
	kgenome_cell_space_init(&sp, obj, base, size);
	kgenome_diag_callees_init(&ce, &sp, obj->arch, 0, size);
	/* NULL is a valid, safe degraded state: every jcc then takes the demote fallback below,
	 * same as before this fix - reported once, not a crash and not a silent wrong answer. */
	pj = malloc((size_t)SYM_JOIN_MAX * sizeof *pj);
	if (!pj)
		kgenome_diag_note(s, KGENOME_NOMEM);
	for (j = 0; j < fg->n; j++) {
		struct kgenome_cell_cur k;
		struct kgenome_cell_insn in;
		struct kgenome_diag_orgs w;
		uint64_t lo, hi;
		uint32_t r, npj = 0;

		lo = fns[j].off;         /* a file offset, as above */
		if (lo >= size)
			continue;
		hi = lo + fns[j].len;
		if (hi > size)
			hi = size;

		memset(&k, 0, sizeof k);
		memset(&w, 0, sizeof w);
		for (r = 0; r < 16u; r++)
			w.reg[r].node = KGENOME_DIAG_ORG_NONE;
		if (!kgenome_cell_seek(&k, lo, 0))
			continue;

		while (k.at < hi && kgenome_cell_step(&k, &sp, &in)) {
			uint64_t tva;

			/* A PATH REJOINS HERE: merge what an earlier forward jcc left waiting for this
			 * address, before this address's own instruction is read at all. */
			if (npj) {
				uint32_t ji;

				for (ji = 0; ji < npj; ji++) {
					if (pj[ji].at != in.at)
						continue;
					if (kgenome_diag_org_merge(&w, &pj[ji].w))
						kgenome_diag_note(s, KGENOME_TRUNCATED);
					pj[ji] = pj[--npj];
					break;
				}
			}

			/*
			 * A CALL OR A TAIL JUMP TO AN IMPORT. The decoder
			 * computes the address of the NEXT instruction for an
			 * unlinked branch, because the displacement is a hole
			 * - and that is the address the relocation table
			 * reports, which is how the two are compared without
			 * either knowing the encoding.
			 */
			if (in.op != KGENOME_CELL_CALL && in.op != KGENOME_CELL_JMP) {
				kgenome_diag_org_step(&w, &in);
				/*
				 * A `ret` ENDS THE LINE, and the decoder writes no register for it, so nothing was
				 * cleared. What follows in the same function is reached by a branch from earlier
				 * in it, which this walk does not model: what is carried is reached, not shown -
				 * the sweep's rule for the code after a jmp that no join reaches.
				 *
				 * A `jcc` IS A FORK: its OTHER side (the target) is a path this linear walk
				 * never reads directly, so what it carries past the branch is only PROVEN
				 * when the target side agrees - which is exactly the join above, run in
				 * reverse: remember the live map at the target (pj[]), merged in once the
				 * walk's own reading reaches it. SYM-BRANCH-1 (2026-11-12, fixed): a forward,
				 * resolved target inside this function is tracked that way; anything this
				 * walk cannot place a join for (backward, indirect, unresolved, or the small
				 * table full) falls back to the same demote a ret gets - never silently
				 * PROVEN past a fork it did not account for.
				 */
				if (in.op == KGENOME_CELL_RET)
					kgenome_diag_org_demote(&w, 0xffffu);
				if (in.op == KGENOME_CELL_JCC) {
					int tracked = 0;

					if (pj && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
					    in.target != KGENOME_BROKEN &&
					    in.target > in.at && in.target < hi) {
						uint32_t ji;

						for (ji = 0; ji < npj; ji++)
							if (pj[ji].at == in.target)
								break;
						if (ji < npj) {
							if (kgenome_diag_org_merge(&pj[ji].w, &w))
								kgenome_diag_note(s, KGENOME_TRUNCATED);
							tracked = 1;
						} else if (npj < SYM_JOIN_MAX) {
							pj[npj].at = in.target;
							pj[npj].w = w;
							npj++;
							tracked = 1;
						} else {
							kgenome_diag_note(s, KGENOME_TRUNCATED);
						}
					}
					if (!tracked)
						kgenome_diag_org_demote(&w, 0xffffu);
				}
				if (w.stk_cut) {
					w.stk_cut = 0;
					kgenome_diag_note(s, KGENOME_TRUNCATED);
				}
				note_symref(&w, rt, &in);
				continue;
			}
			tva = in.target;        /* an offset, both sides */
			{
				/* the first site at this address that has a node */
				uint32_t a0 = 0, a1 = g.n;

				while (a0 < a1) {
					uint32_t mid = a0 + (a1 - a0) / 2u;

					if (by_at[mid].at < tva)
						a0 = mid + 1u;
					else
						a1 = mid;
				}
				i = g.n;
				for (; a0 < g.n && by_at[a0].at == tva; a0++)
					if (node_of[by_at[a0].idx] != 0xffffu) {
						i = by_at[a0].idx;
						break;
					}
			}
			if (i < g.n) {
				struct kgenome_diag_hit *h;
				unsigned a;

				h = kgenome_diag_hit_of(s, node_of[i]);
				for (a = 0; a < 6u && h; a++) {
					uint8_t role = sites[i].argrole[a];

					if (role == KGENOME_DIAG_ROLE_NONE)
						continue;
					/* the origin map holds only what a
					 * call RETURNED - this route states
					 * provenance and nothing else - and how sure it is: a link
					 * the walk reached but did not show is MAY (the same one
					 * place that turns an origin into links as the sweep). */
					kgenome_diag_org_link(s, h, &w, kgenome_diag_sysv_arg[a], role,
							      KGENOME_DIAG_KIND_PRODUCED);
					/*
					 * AND WHICH SYMBOL IT NAMED, if the
					 * relocation table said - see
					 * KGENOME_DIAG_H_SYMREF. The first such
					 * argument stands: a call takes one
					 * object, and a second would be a
					 * different relation wearing the
					 * same word.
					 */
					if (!(h->bits & KGENOME_DIAG_H_SYMREF)) {
						int32_t ad = 0;
						uint32_t so =
						  kgenome_diag_org_sym(&w,
						    kgenome_diag_sysv_arg[a], &ad);

						if (so) {
							h->symref = so;
							h->symadd = ad;
							h->bits |= KGENOME_DIAG_H_SYMREF;
						}
					}
				}
			}
			kgenome_diag_org_step(&w, &in);
			/*
			 * WHAT A CALL DID TO THE REGISTERS THE WALK CARRIES, which the step does not say: the decoder gives
			 * a CALL no written register (X2: the comment here claimed the step cleared rax, and it cleared
			 * nothing, so an origin survived every call that was not itself a capability). The answer is the
			 * sweep's (kgenome_diag_org_call): a callee this object resolves by itself is read, any other
			 * is unknown, and an unknown callee may have overwritten what the ABI lets it. A call that
			 * carries a relocation has a hole where its displacement is, which decodes as `call next`, so
			 * its target is not known and must not be read as the program counter being fetched.
			 */
			if (in.op == KGENOME_CELL_CALL)
				kgenome_diag_org_call(&w, &ce, &in, in.target == in.at + in.len);
			if (w.stk_cut) {
				w.stk_cut = 0;
				kgenome_diag_note(s, KGENOME_TRUNCATED);
			}
			/*
			 * AND WHAT IT HANDS BACK, after the call's effect.
			 * The result is the one thing a call does NOT
			 * clobber, and writing it last is how both facts
			 * are kept.
			 */
			if (i < g.n && node_of[i] != 0xffffu) {
				if (kgenome_nucleo_call_hands_on(sites[i].cap, sites[i].name))
					kgenome_diag_org_set(&w, KGENOME_CELL_REG_AX,
							 node_of[i]);
				else
					kgenome_diag_org_clear(&w, KGENOME_CELL_REG_AX);
			}
		}
	}
out:
	free(sites);
	free(node_of);
	free(by_at);
	free(pj);
}
