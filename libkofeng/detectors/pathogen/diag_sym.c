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
 * kof_elf_relcalls already reads.
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

#include "kofdiag.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofcap.h"
#include "../../kofcore/kofmod/elf.h"
#include "../../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../analyzers/nucleo/nucleo.h"
#include "../../disinfect/pzero.h"
#include <celllysis/space.h>


/* How far back the walk reads before a call, to see its arguments set up.
 * The same 256 bytes the syscall routine uses and for the same reason. */
#define DIAG_SYM_LEAD 256u

/*
 * ---- WHICH SYMBOL AN INSTRUCTION'S OPERAND REALLY NAMES ------------------
 *
 * A relocatable object's operands are HOLES: `&__this_module->list` assembles
 * as `48 c7 c7 00 00 00 00`, and the symbol and the offset are in the
 * relocation beside the instruction rather than in it. Without this the walk
 * reads a register loaded with zero and the whole statement disappears.
 *
 * ONLY THE ONES A WALK CAN USE. Calls are already handled - they come through
 * kof_elf_relcalls and become sites - so what is read here is the rest:
 * an operand that names a symbol. The two kinds are kept apart because a call
 * relocation's `where` points at a displacement the decoder already resolves,
 * and treating it as an operand would set a register from a branch target.
 */
/*
 * A register written by an instruction whose operand a relocation names now
 * carries that symbol - see struct org.
 *
 * AFTER kof_diag_org_step AND NOT BEFORE, because the step clears every
 * register the instruction wrote, and this is what the instruction wrote.
 *
 * A REGISTER DESTINATION ONLY. A call's own relocation patches the
 * displacement inside the branch, which is a CELL_O_REL operand, so the test
 * below is what keeps a branch target from being read as a loaded address.
 */
static void note_symref(struct walk *w, const struct kof_elf_relocs *t,
			const struct cell_insn *in)
{
	const struct kof_elf_reloc *r;

	if (in->n_op < 1u || in->o[0].kind != CELL_O_REG)
		return;
	r = kof_elf_reloc_in(t, in->at, in->len);
	if (!r)
		return;
	kof_diag_org_set_sym(w, in->o[0].reg, (uint32_t)r->nameoff,
			     (int32_t)r->addend);
}

struct relsite {
	uint64_t at;            /* what a decoder computes as the target */
	uint16_t cap;
	/*
	 * The vocabulary's id for the name, not the string - see
	 * kof_flow_name_id. Carried because one capability can cover two
	 * calls that differ in whether the object comes back: mmap and
	 * mprotect are both an executable mapping and only the first hands
	 * one back. See kof_flow_hands_on.
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

static void gather(void *user, uint64_t at, uint64_t target, const char *name)
{
	struct relgather *g = user;
	uint16_t cap;
	unsigned i;

	/* An internal call goes to code this object defines; it imports
	 * nothing and names no capability. */
	if (target || !name)
		return;
	cap = kof_flow_cap_of_name(name);
	if (cap == KOF_NUCLEO_NONE)
		return;
	if (g->n == g->cap_n) {
		uint32_t nc = g->cap_n ? g->cap_n * 2u : 64u;
		struct relsite *ns = realloc(g->site, (size_t)nc * sizeof *ns);

		if (!ns) {
			g->oom = 1;
			return;
		}
		g->site = ns;
		g->cap_n = nc;
	}
	g->site[g->n].at = at;
	g->site[g->n].cap = cap;
	g->site[g->n].name = kof_flow_name_id(name);
	for (i = 0; i < 6u; i++)
		g->site[g->n].argrole[i] = kof_diag_role_of_arg(cap, i);
	g->n++;
}

/* rdi, rsi, rdx, rcx, r8, r9 - the SysV call convention, which is NOT the
 * syscall one: a call passes its fourth argument in rcx where a syscall uses
 * r10. The two tables differ in exactly that slot and the difference is the
 * reason this one is written out rather than borrowed. */
const uint8_t kof_diag_sysv_arg[6] = {
	CELL_REG_DI, CELL_REG_SI, CELL_REG_DX,
	CELL_REG_CX, 8u, 9u
};

struct funcrange {
	uint64_t va, size;
};

struct funcgather {
	struct funcrange *fn;
	uint32_t          n, cap_n;
};

static void gather_fn(void *user, uint64_t va, uint64_t size, const char *name)
{
	struct funcgather *g = user;

	(void)name;
	if (!size)
		return;
	if (g->n == g->cap_n) {
		uint32_t nc = g->cap_n ? g->cap_n * 2u : 64u;
		struct funcrange *nf = realloc(g->fn, (size_t)nc * sizeof *nf);

		if (!nf)
			return;
		g->fn = nf;
		g->cap_n = nc;
	}
	g->fn[g->n].va = va;
	g->fn[g->n].size = size;
	g->n++;
}

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

void kof_diag_run_symbol(struct kof_diag_scan *s,
			 const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size)
{
	struct relsite  *sites;
	struct funcrange *fns = NULL;
	uint16_t        *node_of = NULL;
	struct site_at  *by_at = NULL;
	const struct kof_elf_relocs *rt;
	struct cell_space sp;
	struct relgather g;
	struct funcgather fg;
	const struct kof_elf_info *ei;
	kof_buf f;
	uint32_t i, j;

	/* A PE has an import table and not a relocation table; its half of this
	 * route is in diag_pe.c. */
	if (ctx && ctx->format == KOF_FMT_PE) {
		kof_diag_run_pe_symbol(s, ctx, base, size);
		return;
	}

	/*
	 * x86-64 ONLY, and said here rather than left to fail quietly: the
	 * argument registers above are that ABI's, and i386 passes a
	 * module's arguments differently.
	 */
	if (!ctx || ctx->format != KOF_FMT_ELF ||
	    ctx->arch != KOF_ARCH_X86_64)
		return;
	ei = kof_elf(ctx);
	if (!ei || !ei->valid)
		return;

	f.p = base;
	f.n = size;
	memset(&g, 0, sizeof g);
	memset(&fg, 0, sizeof fg);
	kof_elf_relcalls(f, ei, gather, &g);
	sites = g.site;
	if (g.oom)
		s->full = 1;
	if (!g.n)
		goto out;
	node_of = malloc((size_t)g.n * sizeof *node_of);
	by_at = malloc((size_t)g.n * sizeof *by_at);
	if (!node_of || !by_at) {
		s->full = 1;
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
		struct kof_diag_hit *h;
		/* kof_elf_relcalls reports FILE OFFSETS, not addresses - a
		 * relocatable object has no load address to report. */
		uint64_t off = sites[i].at;

		node_of[i] = 0xffffu;
		if (off >= size)
			continue;
		h = kof_diag_hit_add(s, off, sites[i].cap, 0);
		if (!h)
			break;
		node_of[i] = (uint16_t)(s->n_hit - 1u);
	}
	for (i = 0; i < g.n; i++) {
		by_at[i].at = sites[i].at;
		by_at[i].idx = i;
	}
	qsort(by_at, g.n, sizeof *by_at, site_at_cmp);

	kof_elf_funcs(f, ei, gather_fn, &fg);
	fns = fg.fn;

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
	/* The object's relocations - one table, read by every route - see
	 * struct kof_elf_relocs. kof_elf_reloc_in answers only for a CODE
	 * relocation with a name, which is what an operand can stand for. */
	rt = kof_diag_relocs(s, ctx, KOF_ELF_RELOC_CODE);

	kof_cell_space_init(&sp, ctx, base, size);
	for (j = 0; j < fg.n; j++) {
		struct kof_cell_cur k;
		struct cell_insn in;
		struct walk w;
		uint64_t lo, hi;
		uint32_t r;

		lo = fns[j].va;         /* a file offset, as above */
		if (lo >= size)
			continue;
		hi = lo + fns[j].size;
		if (hi > size)
			hi = size;

		memset(&k, 0, sizeof k);
		memset(&w, 0, sizeof w);
		for (r = 0; r < 16u; r++)
			w.reg[r].node = ORG_NONE;
		if (!kof_cell_seek(&k, lo, 0))
			continue;

		while (k.at < hi && kof_cell_step(&k, &sp, &in)) {
			uint64_t tva;

			/*
			 * A CALL OR A TAIL JUMP TO AN IMPORT. The decoder
			 * computes the address of the NEXT instruction for an
			 * unlinked branch, because the displacement is a hole
			 * - and that is the address the relocation table
			 * reports, which is how the two are compared without
			 * either knowing the encoding.
			 */
			if (in.op != CELL_CALL && in.op != CELL_JMP) {
				kof_diag_org_step(&w, &in);
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
				struct kof_diag_hit *h;
				unsigned a;

				h = kof_diag_hit_of(s, node_of[i]);
				for (a = 0; a < 6u && h; a++) {
					uint8_t role = sites[i].argrole[a];

					if (role == KOF_DIAG_ROLE_NONE)
						continue;
					/* the origin map holds only what a
					 * call RETURNED - this route states
					 * provenance and nothing else. */
					kof_diag_note_in(h,
						kof_diag_org_of(&w,
								kof_diag_sysv_arg[a]),
						role, KOF_DIAG_KIND_PRODUCED);
					/*
					 * AND WHICH SYMBOL IT NAMED, if the
					 * relocation table said - see
					 * KOF_DIAG_H_SYMREF. The first such
					 * argument stands: a call takes one
					 * object, and a second would be a
					 * different relation wearing the
					 * same word.
					 */
					if (!(h->bits & KOF_DIAG_H_SYMREF)) {
						int32_t ad = 0;
						uint32_t so =
						  kof_diag_org_sym(&w,
						    kof_diag_sysv_arg[a], &ad);

						if (so) {
							h->symref = so;
							h->symadd = ad;
							h->bits |= KOF_DIAG_H_SYMREF;
						}
					}
				}
			}
			kof_diag_org_step(&w, &in);
			/*
			 * AND WHAT IT HANDS BACK, after the step - which
			 * clears rax as a call's clobber. The result is the
			 * one thing a call does NOT clobber, and writing it
			 * second is how both facts are kept.
			 */
			if (i < g.n && node_of[i] != 0xffffu) {
				if (kof_flow_hands_on(sites[i].cap,
						      kof_flow_name_of(
							      sites[i].name)))
					kof_diag_org_set(&w, CELL_REG_AX,
							 node_of[i]);
				else
					kof_diag_org_clear(&w, CELL_REG_AX);
			}
		}
	}
out:
	free(sites);
	free(fns);
	free(node_of);
	free(by_at);
}
