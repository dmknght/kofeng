/*
 * pathogen.c - building an object's SYMPTOMS, and nothing else.
 *
 * This is the half of pathogen that reads an object: it resolves the imports,
 * picks the regions, drives the sweep in analyzers/disasm, and packs what
 * comes back into the small set of chains a rule is compared against.
 * Comparing them is diagnose.c's; deciding anything at all is a rule's.
 *
 * IT LIVED IN objctx.c AND THAT WAS THE WRONG PLACE. That file is the module
 * ABI - "the entire untrusted boundary", by its own first paragraph, where a
 * mistake is a memory safety bug rather than a wrong answer, and it says of
 * itself that "nothing here decides anything". Seven hundred lines of PLT
 * walking and region selection sat inside it because kof_pth_match is a call
 * a module makes, so the thing it needed was built where it was consumed.
 * Reasonable at each step and wrong in the sum: the file that has to read end
 * to end was the file growing fastest.
 *
 * What stays there is the shim - twenty lines that bounds check and call in
 * here.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include "../../../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../../analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../../scanners/scan.h"
#include "../../../analyzers/parsers/binaries/disasm/flow.h"
#include "diagnose.h"

/* objctx.c keeps this one-liner too; it is the match context, and both
 * readers want it by the same name. */
static struct kof_match_ctx *mc(const struct kof_obj_ctx *ctx)
{
	return &kof_scan_of(ctx)->m;
}



/* How the decoder should be told to read this object's code. Anything that is
 * not one of the two architectures bddisasm has is refused rather than guessed
 * at - see analyzers/parsers/binaries/disasm/flow.h. */
static int flow_mode(const struct kof_obj_ctx *ctx, unsigned *bits,
		     unsigned *abi, uint32_t *mask, unsigned *fixed)
{
	*fixed = 0;
	if (ctx->arch == KOF_ARCH_X86_64)
		*bits = 64;
	else if (ctx->arch == KOF_ARCH_X86)
		*bits = 32;
	/*
	 * THE FIXED-WIDTH SET, which has no decoder and needs none - see the
	 * note on kof_flow_add_fixed. ELF only: these architectures reach this
	 * engine as ELF and a PE for one of them is not a thing an IoT builder
	 * produces.
	 */
	else if (ctx->format == KOF_FMT_ELF) {
		/*
		 * EVERYTHING ELSE AN IoT BUILDER SHIPS, and the list is long
		 * because a botnet's build matrix is not a list of the
		 * architectures anyone develops on. Measured over 20075
		 * executable objects: PowerPC 601, SuperH 349, m68k 345,
		 * SPARC 281, RISC-V 42 - 8.8% of the corpus, and every one
		 * refused outright before this.
		 */
		switch (ctx->arch) {
		case KOF_ARCH_MIPS:   *fixed = KOF_FLOW_A_MIPS32;  break;
		/* A different ABI, not a wider one - see KOF_FLOW_A_MIPS64.
		 * Pointing this at the o32 table cost every one of the
		 * corpus's 40 MIPS64 objects all of its capabilities. */
		case KOF_ARCH_MIPS64: *fixed = KOF_FLOW_A_MIPS64;  break;
		case KOF_ARCH_ARM:    *fixed = KOF_FLOW_A_ARM32;   break;
		case KOF_ARCH_ARM64:  *fixed = KOF_FLOW_A_ARM64;   break;
		case KOF_ARCH_PPC:    *fixed = KOF_FLOW_A_PPC32;   break;
		case KOF_ARCH_PPC64:  *fixed = KOF_FLOW_A_PPC64;   break;
		case KOF_ARCH_SPARC64:
		case KOF_ARCH_SPARC:
		/*
		 * v9 READS AS v8 ONCE ITS TRAP IS KNOWN. The instruction that
		 * sets %g1 is identical; only the trap differs - `ta 0x6d`
		 * against `ta 0x10` - which is why one decode serves both and
		 * why 0 of 25 v9 objects answered before that number was in.
		 */
			*fixed = KOF_FLOW_A_SPARC32; break;
		case KOF_ARCH_RISCV32:
		case KOF_ARCH_RISCV64: *fixed = KOF_FLOW_A_RISCV;  break;
		case KOF_ARCH_SH:     *fixed = KOF_FLOW_A_SH;      break;
		case KOF_ARCH_M68K:   *fixed = KOF_FLOW_A_M68K;    break;
		default:              return 0;
		}
		*bits = (ctx->arch == KOF_ARCH_ARM64 ||
			 ctx->arch == KOF_ARCH_PPC64 ||
			 ctx->arch == KOF_ARCH_MIPS64 ||
			 ctx->arch == KOF_ARCH_RISCV64) ? 64u : 32u;
		*abi  = KOF_FLOW_SYSV;
		*mask = KOF_SCAN_ELF_CODE;
		return 1;
	}
	else
		return 0;
	if (ctx->format == KOF_FMT_PE) {
		*abi = KOF_FLOW_MS;
		*mask = KOF_SCAN_PE_CODE;
	} else if (ctx->format == KOF_FMT_ELF) {
		*abi = KOF_FLOW_SYSV;
		*mask = KOF_SCAN_ELF_CODE;
	} else {
		return 0;
	}
	return 1;
}

/* Keep this chain if it is worth more than the weakest one held. */
/*
 * IS `b` THE SAME RUN OF STEPS AS SOMEWHERE INSIDE `a`.
 *
 * Compared on what a step SAYS - the capability, the name and the selector -
 * and not on where it was: the whole point is that these are the same calls
 * seen from two places.
 */
static int chain_inside(const struct kof_flow_node *a, uint32_t na,
			const struct kof_flow_node *b, uint32_t nb)
{
	uint32_t at;

	if (!nb || nb > na)
		return 0;
	for (at = 0; at + nb <= na; at++) {
		uint32_t k;

		for (k = 0; k < nb; k++)
			if (a[at + k].cap != b[k].cap ||
			    a[at + k].name != b[k].name ||
			    a[at + k].sel != b[k].sel)
				break;
		if (k == nb)
			return 1;
	}
	return 0;
}

static void flow_set_offer(struct kof_flow_set *fs,
			   const struct kof_flow_node *v, uint32_t n)
{
	uint32_t i, worst = 0, worst_w = 0xffffffffu;

	/* Clamped BEFORE anything reads the array, not after: kof_diag_worth
	 * walks all n of them, so the bound has to be in place first. It is
	 * the caller's cap that keeps this honest today, which is the sort of
	 * thing that stays true until a second caller appears. */
	if (n > KOF_PTH_SYMPTOM_MAX)
		n = KOF_PTH_SYMPTOM_MAX;
	if (!kof_diag_worth(v, n))
		return;
	/*
	 * AND NOT THE SAME SEQUENCE TWICE, which is what rooting a chain at
	 * EVERY function produces.
	 *
	 * chain_walk follows calls, so a callee's steps are spliced into its
	 * caller's chain - and then the callee is rooted in its turn and
	 * emits them again on their own. Measured on diamondxe.ko: a module
	 * that does three things showed SIX chains, two pairs identical and
	 * one a prefix of another. A reader counting them counted the call
	 * graph, not the program.
	 *
	 * The longer one wins because it is the one with context: the same
	 * two steps mean more under the function that reached them.
	 */
	for (i = 0; i < fs->n_chain; i++)
		if (chain_inside(fs->n[i], fs->len[i], v, n))
			return;
	for (i = 0; i < fs->n_chain; i++)
		if (chain_inside(v, n, fs->n[i], fs->len[i])) {
			memcpy(fs->n[i], v, n * sizeof *v);
			fs->len[i] = (uint8_t)n;
			/* And whatever else it swallowed goes with it. */
			{
				uint32_t j, k = i + 1u;

				for (j = i + 1u; j < fs->n_chain; j++) {
					if (chain_inside(v, n, fs->n[j],
							 fs->len[j]))
						continue;
					if (k != j) {
						memcpy(fs->n[k], fs->n[j],
						       fs->len[j] *
						       sizeof *v);
						fs->len[k] = fs->len[j];
					}
					k++;
				}
				fs->n_chain = (uint8_t)k;
			}
			return;
		}
	if (fs->n_chain < FLOW_SET_MAX) {
		memcpy(fs->n[fs->n_chain], v, n * sizeof *v);
		fs->len[fs->n_chain] = (uint8_t)n;
		fs->n_chain++;
		return;
	}
	for (i = 0; i < FLOW_SET_MAX; i++) {
		uint32_t j, w = 0;

		for (j = 0; j < fs->len[i]; j++)
			w += kof_diag_weight(fs->n[i][j].cap);
		if (w < worst_w) { worst_w = w; worst = i; }
	}
	{
		uint32_t j, w = 0;

		for (j = 0; j < n; j++)
			w += kof_diag_weight(v[j].cap);
		if (w <= worst_w)
			return;
	}
	memcpy(fs->n[worst], v, n * sizeof *v);
	fs->len[worst] = (uint8_t)n;
}
/*
 * HOW MANY IMPORTS AN OBJECT MAY HAVE, AND WHAT THE NUMBER IS FOR.
 *
 * It was a fixed 512, which is a ceiling in the wrong place: a ceiling is
 * there so that a crafted file cannot make this cost unbounded memory, and
 * 512 was instead a quiet decision that the 513th import does not exist. A
 * large C++ program reaches it on its relocations alone, and what is dropped
 * is whatever came last - which here is the PLT STUBS, the half the sweep
 * actually resolves calls against. The object then reports that its code
 * claims nothing.
 *
 * So: grown as needed, and the ceiling kept only at the size where a file
 * would have to be absurd to reach it.
 */
#define FLOW_IMP_START 256u
#define FLOW_IMP_MAX   65536u

struct flow_imp {
	uint64_t *addr;
	/* KOF_FLOW_ANSWER: the capability and the role it was named with. The
	 * role is what separates "socket" from "bind" once both have become
	 * KOF_CAP_NET_OPEN - see kof_flow_role_of_name. */
	uint32_t *what;
	uint32_t n;
	uint32_t cap;
};

static int imp_grow(struct flow_imp *im)
{
	uint32_t want = im->cap ? im->cap * 2u : FLOW_IMP_START;
	uint64_t *a;
	uint32_t *w;

	if (im->cap >= FLOW_IMP_MAX)
		return 0;
	if (want > FLOW_IMP_MAX)
		want = FLOW_IMP_MAX;
	a = (uint64_t *)realloc(im->addr, want * sizeof *a);
	if (!a)
		return 0;
	im->addr = a;
	w = (uint32_t *)realloc(im->what, want * sizeof *w);
	if (!w)
		return 0;
	im->what = w;
	im->cap = want;
	return 1;
}

static void imp_free(struct flow_imp *im)
{
	if (im) {
		free(im->addr);
		free(im->what);
		free(im);
	}
}

static void imp_add(struct flow_imp *im, uint64_t addr, uint32_t what)
{
	if ((what & 0xffu) == KOF_CAP_NONE)
		return;
	if (im->n >= im->cap && !imp_grow(im))
		return;
	im->addr[im->n] = addr;
	im->what[im->n] = what;
	im->n++;
}

/*
 * WHERE EACH UNLINKED CALL REALLY GOES.
 *
 * Built from the same relocations the import table is, and holding the other
 * half of them: a relocation against a symbol this object DEFINES is a call
 * inside the module, and 184 of diamorphine.ko's 248 are. Without them the
 * module's call graph is empty - see kof_flow_retargeter - and the chain that
 * turns write-protect off can never reach the one that writes.
 *
 * Keyed by the address the decoder WILL compute, which for a hole-filled
 * `call` is the next instruction. One entry per call site, so the bound is
 * call sites and not symbols.
 */
/* Grown rather than fixed, for the reason written above imp_grow: a module
 * with more call sites than the bound does not have fewer, and the ones the
 * old 2048 dropped were whichever the walk reached last. */
#define FLOW_RET_START 1024u
#define FLOW_RET_MAX   262144u

struct flow_ret {
	uint64_t *from;
	uint64_t *to;
	uint32_t n;
	uint32_t cap;
};

static int ret_grow(struct flow_ret *rt)
{
	uint32_t want = rt->cap ? rt->cap * 2u : FLOW_RET_START;
	uint64_t *a;

	if (rt->cap >= FLOW_RET_MAX)
		return 0;
	if (want > FLOW_RET_MAX)
		want = FLOW_RET_MAX;
	a = (uint64_t *)realloc(rt->from, want * sizeof *a);
	if (!a)
		return 0;
	rt->from = a;
	a = (uint64_t *)realloc(rt->to, want * sizeof *a);
	if (!a)
		return 0;
	rt->to = a;
	rt->cap = want;
	return 1;
}

static void ret_free(struct flow_ret *rt)
{
	if (rt) {
		free(rt->from);
		free(rt->to);
		free(rt);
	}
}

static void ret_add(struct flow_ret *rt, uint64_t from, uint64_t to)
{
	if (rt && to) {
		if (rt->n >= rt->cap && !ret_grow(rt))
			return;
		rt->from[rt->n] = from;
		rt->to[rt->n] = to;
		rt->n++;
	}
}

static uint64_t ret_lookup(uint64_t a, void *user)
{
	const struct flow_ret *rt = (const struct flow_ret *)user;
	uint32_t i;

	for (i = 0; i < rt->n; i++)
		if (rt->from[i] == a)
			return rt->to[i];
	return 0;
}

static uint32_t imp_lookup(uint64_t a, void *user)
{
	const struct flow_imp *im = (const struct flow_imp *)user;
	uint32_t i;

	for (i = 0; i < im->n; i++)
		if (im->addr[i] == a)
			return im->what[i];
	return KOF_FLOW_ANSWER(KOF_CAP_NONE, KOF_FLOW_ROLE_NONE);
}

/*
 * ---- THE VOCABULARY, APPLIED TO WHAT THE PARSER FOUND ----------------------
 *
 * Five hundred lines of import directories, r_info unpacking, symbol tables
 * and PLT stub decoding used to be here - and elf_sym.c and pe_sym.c, two
 * files away, walked the SAME tables to build the symbol block. Three
 * readers for two formats, and they had drifted apart in ways nobody chose.
 *
 * They are now kof_pe_imports, kof_elf_imports, kof_elf_relcalls,
 * kof_elf_funcs and the kof_elf_symbol_at that all of them share - see the
 * note in elf_parse.h for where the line was drawn.
 *
 * The parser answers "what is called, and from where". Everything below
 * decides what that MEANS, which is the part that is pathogen's: the
 * name-to-capability table is a vocabulary and does not belong in a parser
 * anybody else can call.
 */

/*
 * THE TEST IS NOT "IS IT A NAME", IT IS "WHO CHOSE THE VALUE".
 *
 * This was switched off for one revision on the argument that a name is
 * content, and that was the wrong line to draw. `commit_creds` is the
 * KERNEL's name and `CreateFileW` is Windows': a program that renames them
 * does not link, and a loadable module has no syscall instruction at all -
 * the symbol table is the only way it reaches the kernel. That is an ABI,
 * the same kind of fact a syscall number is, and the author cannot choose
 * either.
 *
 * What pathogen must not use is what the AUTHOR chose: his bytes, his
 * strings, his layout. A name he cannot change is not that.
 *
 * WHAT IS TRUE OF IT, and is marked on every node it produces - see
 * KOF_FLOWF_BY_NAME - is that it can be AVOIDED. A rootkit that resolves the
 * address with a kprobe and calls through a register leaves no name, and
 * diamorphine already does exactly that for the syscall table. So a step read
 * from a name is a weaker step than one read from a number or an
 * instruction, and a rule is entitled to know which it has.
 */
static void pth_import(void *user, uint64_t addr, const char *name)
{
	imp_add((struct flow_imp *)user, addr,
		KOF_FLOW_ANSWER_N(kof_flow_cap_of_name(name),
				  kof_flow_role_of_name(name),
				  kof_flow_name_id(name)));
}

/*
 * A PE SLOT, with the library it came from thrown away.
 *
 * The vocabulary is keyed on the function and not on the DLL: `CreateFileW`
 * means the same thing whether a program imports it from kernel32 or from an
 * api-ms-win-core forwarder, and the three spellings of that are a fact
 * about Windows releases rather than about the program.
 *
 * AN IMPORT BY ORDINAL IS DROPPED HERE and is right to be. There is no name
 * to look up, and guessing one from the ordinal means carrying a table of
 * every export of every version of every library - which would be a fact
 * about the researcher's machine, not about the file.
 */
static void pth_pe_import(void *user, uint64_t slot, const char *dll,
			  const char *name, uint32_t ordinal)
{
	(void)dll;
	(void)ordinal;
	if (name)
		pth_import(user, slot, name);
}

/*
 * A RELOCATABLE OBJECT'S CALLS SPLIT IN TWO, and both halves are wanted.
 *
 * An UNDEFINED symbol is a promise to the kernel and reads exactly as an
 * import does. A DEFINED one is a call inside the module - 184 of
 * diamorphine.ko's 248 are - and without those the module's call graph is
 * empty: the chain that turns write protection off could never reach the one
 * that writes.
 *
 * The capability table wants the undefined names ONLY. A local function that
 * happens to be called `list_del` is this module's own and not the kernel's.
 */
struct pth_relsink {
	struct flow_imp *im;
	struct flow_ret *rt;
};

static void pth_relcall(void *user, uint64_t at, uint64_t target,
			const char *name)
{
	const struct pth_relsink *s = (const struct pth_relsink *)user;

	if (target)
		ret_add(s->rt, at, target);
	else
		pth_import(s->im, at, name);
}

/*
 * THE FUNCTION BOUNDARIES THE OBJECT ALREADY DECLARES.
 *
 * The sweep derives them from call targets, which is all code alone can give
 * it - and it is wrong for any function nothing calls. A compiler that
 * inlines one leaves the out-of-line copy behind with no caller, and its
 * nodes are then read as belonging to whatever precedes it.
 *
 * Measured on diamorphine.ko: `give_root` is inlined into `hacked_kill`, so
 * the copy at 0x06e1 had no caller and its `prepare_creds` was attributed to
 * `get_syscall_table_bf`, three functions earlier. The page then showed
 * "register_kprobe, unregister_kprobe, prepare_creds" as one chain - two
 * unrelated functions read as one sentence.
 *
 * The symbol table names all eleven. Reading them is not inference. The name
 * is not wanted: a boundary is a fact about the code, and what the author
 * called it is his to choose.
 */
static void pth_func(void *user, uint64_t va, uint64_t size, const char *name)
{
	(void)name;
	kof_flow_head((struct kof_flow *)user, va, size);
}

/* Where these file bytes live once the image is mapped. The sweep needs the
 * virtual address and not the offset: a rip-relative operand names a slot in
 * that space, and an import resolved in offset space resolves to nothing. */
static uint64_t flow_va_of(const struct kof_obj_ctx *ctx, uint64_t off)
{
	const struct kof_pe_info *p;
	uint32_t i;

	if (ctx->format == KOF_FMT_ELF) {
		const struct kof_elf_info *e = kof_elf(ctx);
		uint32_t k;

		if (!e || !e->valid)
			return off;
		for (k = 0; k < e->sec_count; k++)
			if (e->sec[k].mem_addr && off >= e->sec[k].file_off &&
			    off - e->sec[k].file_off < e->sec[k].file_size)
				return e->sec[k].mem_addr +
				       (off - e->sec[k].file_off);
		return off;
	}
	if (ctx->format != KOF_FMT_PE)
		return off;
	p = kof_pe(ctx);
	if (!p || !p->valid)
		return off;
	if (p->layout == KOF_PE_LAYOUT_MAPPED)
		return p->image_base + off;
	for (i = 0; i < p->sec_count; i++)
		if (off >= p->sec[i].file_off &&
		    off - p->sec[i].file_off < p->sec[i].file_size)
			return p->image_base + p->sec[i].mem_rva +
			       (off - p->sec[i].file_off);
	return off;
}

/*
 * BUILD AN OBJECT'S SYMPTOMS INTO A SET THE CALLER OWNS.
 *
 * No scanner and no cache - both belong to kof_pth_chain_of below, which is
 * the scan path. This half exists because kofviewer needs the same answer and
 * had been computing its OWN: a copy that handled x86 and x86-64 and no
 * imports, written when those were all there were. By the time the engine
 * read ten architectures and a kernel module's symbol table, the viewer was
 * still answering for two - so a reader looking at an ARM bot was told there
 * was no chain while the scanner was finding eight.
 *
 * One builder, two callers, and the drift cannot come back.
 */
/*
 * THE SURVEY HOOK AND WHY IT IS A WRAPPER.
 *
 * The question "which objects get no chain, and for which of the five
 * reasons" cannot be answered from outside: four of the five returns happen
 * before anything is printed, and the reason is handed to a caller that keeps
 * it for a dialog. One wrapper gives the builder a single exit to report at
 * without moving any of them.
 *
 *   [psurvey] <bits> <abi> <chains> <reason or ->
 */
static uint32_t pth_chain_build_in(const struct kof_obj_ctx *ctx, kof_buf b,
				   struct kof_range *scratch,
				   struct kof_flow_set *out, const char **why);

uint32_t kof_pth_chain_build(const struct kof_obj_ctx *ctx, kof_buf b,
			     struct kof_range *scratch,
			     struct kof_flow_set *out, const char **why)
{
	const char *w = NULL;
	uint32_t n = pth_chain_build_in(ctx, b, scratch, out, &w);

	if (getenv("KOF_PTH_SURVEY")) {
		unsigned sb = 0, sa = 0, sf = 0;
		uint32_t sm = 0;
		const struct kof_scanner *ss = ctx ? kof_scan_of(ctx) : NULL;

		if (!ctx || !flow_mode(ctx, &sb, &sa, &sm, &sf))
			sb = sa = 0;
		/*
		 * FORMAT AND ARCHITECTURE BELONG IN THE LINE, and the region
		 * flag with them. Without the flag the first run of this read
		 * 75% of objects as "no decoder for this format and
		 * architecture" - which was true of each one and said nothing,
		 * because four of every five objects is a REGION VIEW of a
		 * file that was itself decoded fine. A survey that counts
		 * those is measuring its own hook.
		 */
		fprintf(stderr, "[psurvey] f%u a%u r%u %u %u %u %s\n",
			ctx ? (unsigned)ctx->format : 0u,
			ctx ? (unsigned)ctx->arch : 0u,
			(ss && ss->n_cur_rgn) ? 1u : 0u,
			sb, sa, n, w ? w : "-");
	}
	if (why)
		*why = w;
	return n;
}

static uint32_t pth_chain_build_in(const struct kof_obj_ctx *ctx, kof_buf b,
				   struct kof_range *scratch,
				   struct kof_flow_set *out, const char **why)
{
	unsigned bits = 0, abi = 0, fixed = 0;
	uint32_t mask = 0, nr, i;
	struct kof_flow *f;
	struct flow_imp *im = NULL;
	struct flow_ret *rt = NULL;

	if (why)
		*why = NULL;
	if (!ctx || !out || !scratch) {
		if (why)
			*why = "nothing was handed to the sweep";
		return 0;
	}
	memset(out, 0, sizeof *out);
	if (!flow_mode(ctx, &bits, &abi, &mask, &fixed))
		{ if (getenv("KOF_FCHAIN_DUMP")) fprintf(stderr,"[fchain] skip: %s\n","flow_mode");
		  if (why) *why = "no decoder for this format and architecture";
		  return 0; }
	if (!b.p || !b.n)
		{ if (getenv("KOF_FCHAIN_DUMP")) fprintf(stderr,"[fchain] skip: %s\n","nobytes");
		  if (why) *why = "the object's bytes are not here to read";
		  return 0; }
	nr = kof_scan_resolve_range(ctx, mask, scratch);
	if (!nr) {
		if (getenv("KOF_FCHAIN_DUMP"))
			fprintf(stderr, "[fchain] skip: norange\n");
		if (why)
			*why = "no code region resolved in this object";
		return 0;
	}
	f = kof_flow_new();
	if (!f)
		return 0;
	/* The names the formats carry, turned into capabilities - see
	 * pth_import for why a name is admissible evidence at all. */
	im = (struct flow_imp *)calloc(1, sizeof *im);
	if (im) {
		if (ctx->format == KOF_FMT_PE && kof_pe(ctx)) {
			kof_pe_imports(b, kof_pe(ctx), pth_pe_import, im);
		} else if (ctx->format == KOF_FMT_ELF && kof_elf(ctx)) {
			struct pth_relsink sink;

			/* One or the other, never both: an ET_REL has no
			 * dynamic table and a linked object has no `.rela`
			 * against an undefined symtab entry. */
			kof_elf_imports(b, kof_elf(ctx), pth_import, im);
			rt = (struct flow_ret *)calloc(1, sizeof *rt);
			sink.im = im;
			sink.rt = rt;
			kof_elf_relcalls(b, kof_elf(ctx), pth_relcall, &sink);
			if (rt && rt->n)
				kof_flow_retargeter(f, ret_lookup, rt);
			/* And the boundaries the object states itself, which
			 * the sweep cannot derive for a function nothing
			 * calls - see pth_func. */
			kof_elf_funcs(b, kof_elf(ctx), pth_func, f);
		}
		kof_flow_resolver(f, imp_lookup, im);
	}
	if (ctx->entry_off != KOF_NA && ctx->entry_off != KOF_BROKEN)
		kof_flow_entry(f, flow_va_of(ctx, ctx->entry_off));
	/*
	 * AND WHICH PARTS OF THE REGION ARE INSTRUCTIONS - see
	 * kof_flow_primary.
	 *
	 * The region below is the loadable segment with PF_X, which holds
	 * far more than code: on one 8 MB static ELF the segment is 7.79 MB
	 * and .text is 4.75 MB, the rest being .dynsym, .dynstr, .gnu.hash,
	 * the relocation tables, .rodata and the unwind tables. All of it
	 * was being disassembled.
	 *
	 * Saying which sections the FORMAT calls executable does not skip
	 * the others - a branch into .rodata is still followed, which is how
	 * a packer that jumps into its own data stays visible. It only stops
	 * the sweep walking them end to end when nothing points there.
	 *
	 * Declaring nothing leaves the whole region in play, which is what a
	 * stripped object gets and is the old behaviour.
	 */
	if (ctx->format == KOF_FMT_ELF && kof_elf(ctx)) {
		const struct kof_elf_info *e = kof_elf(ctx);

		for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
			if ((e->sec[i].flags & 0x4u) &&     /* SHF_EXECINSTR */
			    e->sec[i].file_size)
				kof_flow_primary(f,
					flow_va_of(ctx, e->sec[i].file_off),
					e->sec[i].file_size);
	} else if (ctx->format == KOF_FMT_PE && kof_pe(ctx)) {
		const struct kof_pe_info *pe = kof_pe(ctx);

		for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++)
			if ((pe->sec[i].perm & KOF_PE_PERM_X) &&
			    pe->sec[i].file_size)
				kof_flow_primary(f,
					flow_va_of(ctx, pe->sec[i].file_off),
					pe->sec[i].file_size);
	}
	/*
	 * AND THE WHOLE RANGE, LIBRARY CODE INCLUDED - which was tried the
	 * other way and measured badly.
	 *
	 * A statically linked bot is mostly libc, and sweeping it costs time
	 * and fills the partition with the toolchain's own `open` and
	 * `mmap`. The engine knows where the library is - kof_true_find runs
	 * during the parse and the answer sits on the scanner as cur_lib, in
	 * file offsets, ready to subtract.
	 *
	 * SUBTRACTING IT CUT THE AUTHOR'S CODE. Measured on one C++
	 * ransomware: its nodes fell from 70 to 51 and its chains from 8 to
	 * 4, and the chain that went was the one that mattered - `fopen,
	 * open, fork, execlp, file-delete`. What was left was name
	 * resolution and socket plumbing. The spans are recognised partly by
	 * the file's OWN symbols attributing bytes to the implementation,
	 * and in a C++ binary that attribution reaches code the author
	 * wrote.
	 *
	 * So the cost stands. Anything that skips bytes here has to be
	 * unable to skip the author's, and "it looked like the library" is
	 * not that; marking nodes as library-origin and preferring the rest
	 * would be, because nothing is lost when the guess is wrong.
	 */
	for (i = 0; i < nr; i++) {
		kof_buf s2 = kof_slice(b, scratch[i].off, scratch[i].len);

		if (!s2.p || !s2.n)
			continue;
		if (fixed)
			kof_flow_add_fixed(f, s2.p, (uint32_t)s2.n,
					   flow_va_of(ctx, scratch[i].off),
					   fixed,
					   kof_elf(ctx) &&
					   kof_elf(ctx)->elf_data ==
						   KOF_ELFDATA_BE);
		else
			kof_flow_add(f, s2.p, (uint32_t)s2.n,
				     flow_va_of(ctx, scratch[i].off),
				     bits, abi);
	}
	/*
	 * AND NOTHING AT ALL WHEN THE PARTITION OVERFLOWED.
	 *
	 * Past KOF_FLOW_MAX_FUNC a function has no head of its own and its
	 * nodes are attributed to the one before it, so the chains would
	 * read two unrelated bodies as one sequence. Measured: 13 of 1333
	 * checkable objects, every one of them with more functions than the
	 * array holds. A chain that says the wrong thing is worse than no
	 * chain, and the object is still covered by every other dimension.
	 */
	/*
	 * EVERY NODE, before any chain is chosen - a measurement hook, so
	 * that "the sweep did not find it" and "the set did not keep it" can
	 * be told apart from outside. See KOF_FCHAIN_DUMP for the chains.
	 */
	if (getenv("KOF_FNODE_DUMP")) {
		uint32_t q;

		for (q = 0; q < kof_flow_n_node(f); q++) {
			const struct kof_flow_node *nd = kof_flow_node_at(f, q);

			if (!nd)
				continue;
			fprintf(stderr, "[fnode] @%llx:%u f%u d%u L%u %s=%s\n",
				(unsigned long long)nd->va, nd->func,
				(unsigned)nd->flags,
				(unsigned)nd->depth, (unsigned)nd->loop,
				kof_flow_cap_name(nd->cap),
				nd->name && kof_flow_name_of(nd->name)
					? kof_flow_name_of(nd->name) : "-");
		}
	}
	if (kof_flow_heads_full(f)) {
		if (getenv("KOF_FCHAIN_DUMP"))
			fprintf(stderr, "[fchain] skip: heads-full\n");
		if (why)
			*why = "more functions than the partition holds, so "
			       "a chain would read two bodies as one";
		kof_flow_free(f);
		imp_free(im);
		ret_free(rt);
		return 0;
	}
	{
		struct kof_flow_node tmp[KOF_PTH_SYMPTOM_MAX];

		/*
		 * NO LIBRARY CUT HERE, AND IT WAS TRIED.
		 *
		 * trueline is plague's tool: two static binaries share their libc
		 * and that shared half swamps a CONTENT comparison. A capability
		 * chain is not swamped the same way - a libc wrapper holds one
		 * node, and kof_diag_worth already refuses a chain under two steps
		 * and under its weight floor, so the library's own chains never
		 * reach the set.
		 *
		 * Measured: dropping chains rooted in a trueline span moved the
		 * malware corpus from 3624 objects with a chain to 3619, left the
		 * clean corpus unchanged at 1191, and cost two objects their only
		 * chain. A dependency and a per-object allocation for that is not
		 * a trade; the gate above is already doing the work.
		 */
		for (i = 0; i < kof_flow_n_func(f); i++) {
			uint32_t m = kof_flow_chain(f, i, 6u, tmp,
						    KOF_PTH_SYMPTOM_MAX, NULL);

			if (m)
				flow_set_offer(out, tmp, m);
		}
	}
	kof_flow_free(f);
	imp_free(im);
	ret_free(rt);
	/*
	 * THE SWEPT CHAIN, ON DEMAND, FOR A CORPUS RUN.
	 *
	 * Behind an environment variable and off by default. A rule reaches
	 * this through kof_pth_match, which answers a percentage against a
	 * reference somebody already wrote - and there is no way to ask what
	 * the object's OWN chain is without writing a rule first. Measuring a
	 * corpus needs exactly that, and a researcher choosing what a rule
	 * should say needs it before there is a rule to write.
	 */
	if (out && getenv("KOF_FCHAIN_DUMP")) {
		unsigned ci, k;

		for (ci = 0; ci < out->n_chain; ci++) {
			fprintf(stderr, "[fchain] ");
			for (k = 0; k < out->len[ci]; k++) {
				const struct kof_flow_node *nd =
					&out->n[ci][k];

				/*
				 * name/flags/back - the STORED form, which is
				 * what a rule carries, so a measurement run
				 * and a rule are reading the same thing. The
				 * name is for a person; the two numbers are
				 * for whatever is counting.
				 */
				/* And the NAME it was read from, when there
				 * was one: a measurement run and a reader
				 * want the same thing here. */
				if (getenv("KOF_FCHAIN_VA"))
					fprintf(stderr, "@%llx:%u ",
						(unsigned long long)nd->va,
						(unsigned)nd->func);
				{
					uint32_t aq;

					for (aq = 0; aq < KOF_FLOW_ARGS; aq++)
						if (nd->arg_const &
						    (1u << aq))
							fprintf(stderr,
								"a%u=%llx ",
								aq,
								(unsigned long long)
								nd->arg[aq]);
				}
				if (nd->from_va[0] || nd->from_va[1] ||
				    nd->from_va[2] || nd->from_va[3])
					fprintf(stderr,
						"<-%llx,%llx,%llx,%llx ",
						(unsigned long long)
							nd->from_va[0],
						(unsigned long long)
							nd->from_va[1],
						(unsigned long long)
							nd->from_va[2],
						(unsigned long long)
							nd->from_va[3]);
				if (nd->name && kof_flow_name_of(nd->name))
					fprintf(stderr, "%s=%s/%u/%u/d%uL%u ",
						kof_flow_cap_name(nd->cap),
						kof_flow_name_of(nd->name),
						(unsigned)(nd->flags &
							   KOF_PTH_FLAG_KEEP),
						(unsigned)nd->from[0],
						(unsigned)nd->depth,
						(unsigned)nd->loop);
				else
				fprintf(stderr, "%s/%u/%u/d%uL%u ",
					kof_flow_cap_name(nd->cap),
					(unsigned)(nd->flags &
						   KOF_PTH_FLAG_KEEP),
					(unsigned)(nd->from[0] &&
						   nd->from[0] <= k
						   ? k - (nd->from[0] - 1u)
						   : 0u),
					(unsigned)nd->depth,
					(unsigned)nd->loop);
			}
			fputc('\n', stderr);
		}
	}
	/*
	 * AND THE SAME CHAINS AS A SHAPE, which is what they are.
	 *
	 * The flat dump above is the stored form - one line, comparable,
	 * what a rule carries. This one is the program: a step is indented
	 * by how many calls and loops enclose it, a loop says how many times
	 * it went round, and a step that CANNOT follow the one before it
	 * gets a bar rather than a line, because the two are alternatives
	 * and printing them one under the other asserts an order no
	 * execution takes.
	 *
	 * The dialog draws the same thing - see draw_pathogen. This exists
	 * so the shape can be read and measured over a corpus without one.
	 */
	if (out && getenv("KOF_FCHAIN_TREE")) {
		unsigned ci, k;

		for (ci = 0; ci < out->n_chain; ci++) {
			fprintf(stderr, "[ftree] chain %u\n", ci);
			for (k = 0; k < out->len[ci]; k++) {
				const struct kof_flow_node *nd =
					&out->n[ci][k];
				unsigned d = nd->depth;

				if (k && nd->rel == KOF_REL_EXCLUSIVE)
					fprintf(stderr, "[ftree] %*s-- or --\n",
						(int)(2u * (d + nd->cond)) + 2,
						"");
				/* Nothing for UNKNOWN - see the note in
				 * chain_one: it is the state of most pairs
				 * and saying it every time reads as the
				 * dump having given up. */
				fprintf(stderr, "[ftree] %*s%s%s",
					(int)(2u * (d + nd->cond)) + 2, "",
					nd->cond ? "? " : "",
					kof_flow_cap_name(nd->cap));
				if (nd->name && kof_flow_name_of(nd->name))
					fprintf(stderr, " %s",
						kof_flow_name_of(nd->name));
				if (nd->repeat > 1u)
					fprintf(stderr, " x%u",
						(unsigned)nd->repeat);
				fputc('\n', stderr);
			}
		}
	}
	/*
	 * AND THE LAST GATE, which is the one that turns a sweep that found
	 * things into a page that shows nothing: every chain the object has
	 * was offered and none of them cleared kof_diag_worth. Saying "the
	 * code asks for too little" when the sweep in fact read nothing at
	 * all, or was refused a region, sends a reader looking in the wrong
	 * place - so the four cases are told apart.
	 */
	if (why && !out->n_chain)
		*why = "the sweep read code here, but no run of it claims "
		       "enough to be worth a chain";
	return out->n_chain;
}

/*
 * THE SCAN PATH'S CACHE AROUND IT. One build per object, kept on the scanner,
 * because every rule on the object asks the same question.
 */
const struct kof_flow_set *kof_pth_chain_of(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc) {
		if (getenv("KOF_FCHAIN_DUMP"))
			fprintf(stderr, "[fchain] skip: %s\n", "nosc");
		return NULL;
	}
	if (sc->fchain_ready)
		return sc->fchain;
	sc->fchain_ready = 1;
	if (!sc->fchain)
		sc->fchain = calloc(1, sizeof *sc->fchain);
	if (!sc->fchain)
		return NULL;
	kof_pth_chain_build(ctx, mc(ctx)->data, sc->ext_gather, sc->fchain, NULL);
	return sc->fchain;
}

/*
 * SWEEP THIS OBJECT NOW, SO A CORPUS CAN BE MEASURED.
 *
 * The sweep is lazy on purpose - built by the first rule that asks, so a
 * database with no chain rule never pays for it. That is right for scanning
 * and wrong for the one job it makes impossible: finding out what the chains
 * in a corpus LOOK like, which has to happen BEFORE there is a rule that
 * would have asked.
 *
 * Does nothing unless KOF_FCHAIN_DUMP is set, and the printing is in
 * fchain_of beside the thing it prints.
 */
void kof_scan_fchain_probe(const struct kof_obj_ctx *ctx)
{
	if (getenv("KOF_FCHAIN_DUMP") || getenv("KOF_PTH_SURVEY"))
		(void)kof_pth_chain_of(ctx);
}


/*
 * THE BEST A REFERENCE SCORES AGAINST THIS OBJECT.
 *
 * Here and not in the ABI shim because struct kof_flow_set is this file's -
 * the shim should not have to know how many chains an object was reduced to,
 * only that one number comes back. Zero when the object produced none, which
 * is not the same claim as "nothing matched" and the shim says so.
 */
uint32_t kof_pth_best_pct(const struct kof_obj_ctx *ctx,
			  const struct kof_pth_symptom *ref)
{
	const struct kof_flow_set *fs = kof_pth_chain_of(ctx);
	uint32_t i, best = 0;

	if (!fs)
		return 0;
	for (i = 0; i < fs->n_chain; i++) {
		uint32_t p = kof_diag_pct(ref, fs->n[i], fs->len[i]);

		if (p > best)
			best = p;
	}
	return best;
}

/*
 * THE PROFILE, BUILT ONCE FROM THE CHAINS.
 *
 * Every step contributes three things: that its capability is present, which
 * of the kept flags were on it, and - for each argument whose producer the
 * sweep followed - an edge from that producer's capability to this one.
 *
 * ALL FOUR ARGUMENTS AND NOT JUST THE FIRST. kof_flow_node says why: "read
 * from the socket it opened" and "read into the memory it mapped" are two
 * claims carried by two different arguments of the same call, and a profile
 * that kept only one would be throwing away whichever it met second.
 *
 * The flags are masked to KOF_PTH_FLAG_KEEP so that a rule cannot ask about
 * LOW8 - how confidently the sweep read a selector is a fact about the sweep,
 * and a rule carrying it would be a rule about the decoder.
 */
static void prof_build(struct kof_pth_profile *pr,
		       const struct kof_flow_set *fs)
{
	unsigned ci, k, a;

	memset(pr, 0, sizeof *pr);
	if (!fs)
		return;
	for (ci = 0; ci < fs->n_chain; ci++) {
		for (k = 0; k < fs->len[ci]; k++) {
			const struct kof_flow_node *nd = &fs->n[ci][k];

			if (nd->cap >= KOF_CAP_COUNT)
				continue;
			pr->cap_mask |= 1ull << nd->cap;
			pr->flags[nd->cap] |= nd->flags & KOF_PTH_FLAG_KEEP;
			for (a = 0; a < KOF_FLOW_ARGS; a++) {
				unsigned f = nd->from[a];
				uint8_t src;

				if (!f || f > k)
					continue;
				src = fs->n[ci][f - 1u].cap;
				if (src && src < KOF_CAP_COUNT)
					pr->edge[nd->cap] |= 1u << src;
			}
		}
	}
}

const struct kof_pth_profile *kof_pth_profile_of(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return NULL;
	if (sc->pth_prof_ready)
		return sc->pth_prof;
	sc->pth_prof_ready = 1;
	if (!sc->pth_prof)
		sc->pth_prof = calloc(1, sizeof *sc->pth_prof);
	if (sc->pth_prof)
		prof_build(sc->pth_prof, kof_pth_chain_of(ctx));
	return sc->pth_prof;
}
