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

/*
 * ---- WHICH SYMBOL AN INSTRUCTION'S OPERAND REALLY NAMES ------------------
 *
 * A relocatable object's operands are HOLES: `&__this_module->list` assembles
 * as `48 c7 c7 00 00 00 00`, and the symbol and the offset are in the
 * relocation beside the instruction rather than in it. Without this the walk
 * reads a register loaded with zero and the whole statement disappears.
 *
 * ONLY THE ONES A WALK CAN USE. Calls are already handled - they come through
 * kof_elf_relcalls and become sites - so what is gathered here is the rest:
 * an operand that names a symbol. The two kinds are kept apart because a call
 * relocation's `where` points at a displacement the decoder already resolves,
 * and treating it as an operand would set a register from a branch target.
 */
#define DIAG_SYM_REFS 512u

struct symref {
	uint64_t where;         /* file offset of the bytes the link patches */
	uint64_t nameoff;       /* file offset of the symbol's name          */
	int64_t  add;
};

struct refgather {
	struct symref *r;
	uint32_t       n, cap;
};

static int take_ref(void *user, uint64_t where, uint32_t type, uint64_t sym,
		    int defined, int64_t addend, uint64_t nameoff)
{
	struct refgather *g = user;

	(void)type;
	(void)sym;
	(void)defined;
	if (g->n >= g->cap)
		return 0;               /* full - see kof_elf_reloc_fn */
	if (!nameoff)
		return 1;
	g->r[g->n].where = where;
	g->r[g->n].nameoff = nameoff;
	g->r[g->n].add = addend;
	g->n++;
	return 1;
}

/* The relocation whose patched bytes lie inside this instruction, or NULL. */
static const struct symref *ref_in(const struct refgather *g, uint64_t at,
				   uint8_t len)
{
	uint32_t i;

	for (i = 0; i < g->n; i++)
		if (g->r[i].where >= at && g->r[i].where < at + (uint64_t)len)
			return &g->r[i];
	return NULL;
}

/*
 * A register written by an instruction whose operand a relocation names now
 * carries that symbol - see struct org.
 *
 * AFTER kof_diag_org_step AND NOT BEFORE, because the step clears every
 * register the instruction wrote, and this is what the instruction wrote.
 *
 * A REGISTER DESTINATION ONLY. A call's own relocation patches the
 * displacement inside the branch, which is a KDIS_O_REL operand, so the test
 * below is what keeps a branch target from being read as a loaded address.
 */
static void note_symref(struct walk *w, const struct refgather *g,
			const struct kdis_insn *in)
{
	const struct symref *r;

	if (in->n_op < 1u || in->o[0].kind != KDIS_O_REG)
		return;
	r = ref_in(g, in->at, in->len);
	if (!r)
		return;
	kof_diag_org_set_sym(w, in->o[0].reg, (uint32_t)r->nameoff,
			     (int32_t)r->add);
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

struct relgather {
	struct relsite *site;
	uint32_t        n, cap_n;
	int             full;
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
	if (g->n >= g->cap_n) {
		g->full = 1;
		return;
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
	static struct symref   refs[DIAG_SYM_REFS];
	struct refgather rg;
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
	/* The operand relocations, once for the object - see struct symref. */
	rg.r = refs;
	rg.n = 0;
	rg.cap = DIAG_SYM_REFS;
	kof_elf_relocs(f, ei, take_ref, &rg);

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
				note_symref(&w, &rg, &in);
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
				if (kof_flow_hands_on(sites[i].cap,
						      kof_flow_name_of(
							      sites[i].name)))
					kof_diag_org_set(&w, KDIS_REG_AX,
							 node_of[i]);
				else
					kof_diag_org_clear(&w, KDIS_REG_AX);
			}
		}
	}
}
