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
#include <string.h>

#include "kofdiag.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofcap.h"
#include "../../kofcore/kofmod/elf.h"
#include "../../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../analyzers/parsers/binaries/disasm/nucleo.h"
#include "../../disinfect/pzero.h"

/*
 * HOW MANY IMPORTED CALL SITES ONE OBJECT MAY HAVE.
 *
 * A bound on the input, not on the results - rule 4. Diamorphine's larger
 * build has 24 undefined symbols and 94 call sites between them; 512 is far
 * past anything a module reaches, and a .ko over it is reported through
 * kof_diag_scan_full rather than quietly truncated.
 */
#define DIAG_SYM_MAX 512u

/* How far back the walk reads before a call, to see its arguments set up.
 * The same 256 bytes the syscall routine uses and for the same reason. */
#define DIAG_SYM_LEAD 256u

struct relsite {
	uint64_t at;            /* what a decoder computes as the target */
	uint16_t cap;
	uint8_t  argrole[6];    /* which input each argument register is */
};

struct relgather {
	struct relsite *site;
	uint32_t        n, cap_n;
	int             full;
};


/* Does this call hand something on that a later one could be holding. */
int kof_diag_sym_hands_on(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_CRED_PREPARE:   /* a struct cred * to edit then commit  */
	case KOF_NUCLEO_KSYM_LOOKUP:    /* the address of whatever was named    */
	case KOF_NUCLEO_SYMBOL_GET:
	case KOF_NUCLEO_ALLOC:
	case KOF_NUCLEO_HEAP:
	case KOF_NUCLEO_FILE_OPEN:
		return 1;
	default:
		return 0;
	}
}

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
	if (g->n >= g->cap_n) {
		g->full = 1;
		return;
	}
	g->site[g->n].at = at;
	g->site[g->n].cap = cap;
	for (i = 0; i < 6u; i++)
		g->site[g->n].argrole[i] = kof_diag_role_of_arg(cap, i);
	g->n++;
}

/* rdi, rsi, rdx, rcx, r8, r9 - the SysV call convention, which is NOT the
 * syscall one: a call passes its fourth argument in rcx where a syscall uses
 * r10. The two tables differ in exactly that slot and the difference is the
 * reason this one is written out rather than borrowed. */
const uint8_t kof_diag_sysv_arg[6] = {
	KDIS_REG_DI, KDIS_REG_SI, KDIS_REG_DX,
	KDIS_REG_CX, 8u, 9u
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
	if (!size || g->n >= g->cap_n)
		return;
	g->fn[g->n].va = va;
	g->fn[g->n].size = size;
	g->n++;
}

#define DIAG_SYM_FUNCS 512u

void kof_diag_run_symbol(struct kof_diag_scan *s,
			 const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size)
{
	static struct relsite  sites[DIAG_SYM_MAX];
	static struct funcrange fns[DIAG_SYM_FUNCS];
	static uint16_t        node_of[DIAG_SYM_MAX];
	struct relgather g;
	struct funcgather fg;
	const struct kof_elf_info *ei;
	kof_buf f;
	uint32_t i, j;

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
	g.site = sites;
	g.cap_n = DIAG_SYM_MAX;
	kof_elf_relcalls(f, ei, gather, &g);
	if (g.full)
		s->full = 1;
	if (!g.n)
		return;

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

	memset(&fg, 0, sizeof fg);
	fg.fn = fns;
	fg.cap_n = DIAG_SYM_FUNCS;
	kof_elf_funcs(f, ei, gather_fn, &fg);

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
	for (j = 0; j < fg.n; j++) {
		struct kof_kdis k;
		struct kdis_insn in;
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
		if (!kof_kdis_seek(&k, lo, 0))
			continue;

		while (k.at < hi && kof_kdis_next(&k, ctx, base, size, &in)) {
			uint64_t tva;

			/*
			 * A CALL OR A TAIL JUMP TO AN IMPORT. The decoder
			 * computes the address of the NEXT instruction for an
			 * unlinked branch, because the displacement is a hole
			 * - and that is the address the relocation table
			 * reports, which is how the two are compared without
			 * either knowing the encoding.
			 */
			if (in.op != KDIS_CALL && in.op != KDIS_JMP) {
				kof_diag_org_step(&w, &in);
				continue;
			}
			tva = in.target;        /* an offset, both sides */
			for (i = 0; i < g.n; i++) {
				struct kof_diag_hit *h;
				unsigned a;

				if (sites[i].at != tva ||
				    node_of[i] == 0xffffu)
					continue;
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
				}
				break;
			}
			kof_diag_org_step(&w, &in);
			/*
			 * AND WHAT IT HANDS BACK, after the step - which
			 * clears rax as a call's clobber. The result is the
			 * one thing a call does NOT clobber, and writing it
			 * second is how both facts are kept.
			 */
			if (i < g.n && node_of[i] != 0xffffu) {
				if (kof_diag_sym_hands_on(sites[i].cap))
					kof_diag_org_set(&w, KDIS_REG_AX,
							 node_of[i]);
				else
					kof_diag_org_clear(&w, KDIS_REG_AX);
			}
		}
	}
}
