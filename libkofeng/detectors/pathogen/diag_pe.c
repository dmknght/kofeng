/*
 * diag_pe.c - nodes from what a PE IMPORTS: the calls that go through its
 * import address table.
 *
 * WHY THIS EXISTS. The syscall sweep finds a node where a program enters the
 * kernel, and a Windows program does not: it enters through ntdll, and nearly
 * everything it does is a call to an imported function. MEASURED before this
 * routine, on the 300 PE the engine is tested against: 0 files with a node that
 * has a name. 61 had nodes at all and every one was OPAQUE - a `0f 05` the
 * sweep could not give a number to, which is what bytes in a packed section
 * look like. The vocabulary already knew the names (VirtualAlloc, connect, recv,
 * WSASocketA ...); nothing connected an import to the place that calls it.
 *
 * THE TABLE LISTS THE NAMES AND THE DECODER FINDS THE SITES. kof_pe_imports
 * gives every import with the address of the slot the loader fills; a call
 * through that slot is `call [rip+disp]` on x64 and `call [abs32]` on x86, and
 * the slot address is computable from the instruction without running it. So a
 * node is found by decoding the executable sections once and asking, for each
 * indirect call, "is the slot one of the imports the vocabulary has a word for".
 *
 * THE x86 THUNK. A 32-bit toolchain usually does not call the slot directly. It
 * calls a stub, `jmp [slot]`, that lives with the import table, so a call site
 * is `call rel32` to an address that holds nothing but a jump. A direct call to
 * a stub is a call to the import, and is recorded as one, at the CALL - which is
 * where the program says what it is doing, and where one stub called from nine
 * places is nine acts and not one.
 *
 * THE TABLE'S HALF ONLY. This finds what the import table names and reads no
 * arguments: a node says "this call is `connect`" and nothing about which
 * socket. A program that reads the loader data and so resolves its own APIs - a
 * Metasploit stager, a packer's stub - has none of them in the table, and what
 * it calls is named by the analysis in diag_apihash.c, a route of its own.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofcap.h"
#include "../../kofcore/kofmod/pe.h"
#include "../../kofcore/kofmod/kdis.h"
#include "../../analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../analyzers/parsers/binaries/disasm/kdis.h"
#include "../../analyzers/parsers/binaries/disasm/nucleo.h"

struct pe_imp {
	uint64_t slot;          /* the address a call goes through            */
	uint64_t name_off;      /* where the import's name is, 0 if unknown   */
	uint16_t cap;
};

struct pe_acc {
	const uint8_t *base;
	uint64_t       size;
	struct pe_imp *v;
	uint32_t       n, cap_n;
};

/* A direct call, kept to be matched against the stubs once all are known. */
struct pe_call {
	uint64_t at;            /* file offset of the call                    */
	uint64_t target_va;
};

static void gather_import(void *user, uint64_t slot, const char *dll,
			  const char *name, uint32_t ordinal, uint64_t nameoff)
{
	struct pe_acc *a = user;
	uint16_t cap;
	struct pe_imp *e;

	(void)dll;
	(void)ordinal;
	if (!name)
		return;
	cap = kof_flow_cap_of_name(name);
	if (cap == KOF_NUCLEO_NONE)
		return;
	if (a->n == a->cap_n) {
		uint32_t nc = a->cap_n ? a->cap_n * 2u : 64u;
		struct pe_imp *nv = realloc(a->v, (size_t)nc * sizeof *nv);

		if (!nv)
			return;
		a->v = nv;
		a->cap_n = nc;
	}
	e = &a->v[a->n++];
	e->slot = slot;
	e->cap = cap;
	e->name_off = nameoff;
}

static int imp_by_slot(const void *x, const void *y)
{
	const struct pe_imp *a = x, *b = y;

	return a->slot < b->slot ? -1 : a->slot > b->slot;
}

static const struct pe_imp *imp_find(const struct pe_acc *a, uint64_t slot)
{
	struct pe_imp key;

	key.slot = slot;
	return bsearch(&key, a->v, a->n, sizeof *a->v, imp_by_slot);
}

/*
 * THE SLOT AN INDIRECT BRANCH GOES THROUGH, or KOF_BROKEN when it is not a
 * fixed address. x64 reaches the IAT RIP-relative; x86 names it absolutely.
 * Anything with a base or index register is a table lookup or a vtable call and
 * is not an import.
 */
static uint64_t slot_of(const struct kdis_insn *in, int wide)
{
	const struct kdis_operand *o = &in->o[0];

	if (o->flags & KDIS_OF_RIPREL) {
		if (in->at_va == KOF_BROKEN)
			return KOF_BROKEN;
		return in->at_va + in->len + (uint64_t)o->disp;
	}
	if (o->reg == KDIS_REG_NONE && o->index == KDIS_REG_NONE)
		return wide ? (uint64_t)o->disp : (uint64_t)o->disp & 0xffffffffu;
	return KOF_BROKEN;
}

static void add_node(struct kof_diag_scan *s, uint64_t at,
		     const struct pe_imp *im)
{
	struct kof_diag_hit *h = kof_diag_hit_add(s, at, im->cap, 0);

	if (h && im->name_off) {
		h->symref = im->name_off;
		h->bits |= KOF_DIAG_H_SYMREF;
	}
}

struct pe_walk {
	struct pe_acc  imp;
	struct pe_imp *thunk;           /* a `jmp [slot]`: .slot is ITS address */
	uint32_t       n_thunk, cap_thunk;
	struct pe_call *call;
	uint32_t       n_call, cap_call;
};

static int grow(void **v, uint32_t *cap, uint32_t n, size_t each)
{
	if (n < *cap)
		return 1;
	{
		uint32_t nc = *cap ? *cap * 2u : 256u;
		void *nv = realloc(*v, (size_t)nc * each);

		if (!nv)
			return 0;
		*v = nv;
		*cap = nc;
	}
	return 1;
}

static void walk_code(struct kof_diag_scan *s, const struct kof_obj_ctx *ctx,
		      const uint8_t *base, uint64_t size, uint64_t off,
		      uint64_t n, int wide, struct pe_walk *w)
{
	struct kof_kdis k;
	struct kdis_insn in;

	memset(&k, 0, sizeof k);
	if (!kof_kdis_seek(&k, off, 0))
		return;
	while (k.at < off + n) {
		/*
		 * A BYTE THE DECODER CANNOT READ IS STEPPED OVER, NOT THE END.
		 * kof_kdis_next answers zero and leaves the cursor where it was, so
		 * a loop that treats zero as "finished" stops at the first piece of
		 * data inside the code: MEASURED on a 180 KB MSVC .text, it stopped
		 * at offset 0x583c, a switch jump table of 32-bit offsets, with
		 * 5400 instructions decoded and the rest of the section never
		 * looked at - 98 nodes, all in the first fifth of the file.
		 * x86 resynchronises within a few instructions of garbage, and a
		 * wrong decode costs nothing here: a node needs the operand to be
		 * the address of an import slot, exactly.
		 */
		if (!kof_kdis_next(&k, ctx, base, size, &in)) {
			k.at++;
			continue;
		}
		if ((in.op == KDIS_CALL || in.op == KDIS_JMP) &&
		    (in.flags & KDIS_F_INDIRECT) && in.n_op &&
		    in.o[0].kind == KDIS_O_MEM) {
			uint64_t slot = slot_of(&in, wide);
			const struct pe_imp *im;

			if (slot == KOF_BROKEN)
				continue;
			im = imp_find(&w->imp, slot);
			if (!im)
				continue;
			if (in.op == KDIS_CALL) {
				add_node(s, in.at, im);
			} else if (in.at_va != KOF_BROKEN &&
				   grow((void **)&w->thunk, &w->cap_thunk,
					w->n_thunk, sizeof *w->thunk)) {
				struct pe_imp *t = &w->thunk[w->n_thunk++];

				*t = *im;
				t->slot = in.at_va;     /* the stub's own address */
			}
		} else if (in.op == KDIS_CALL && !(in.flags & KDIS_F_INDIRECT) &&
			   in.target_va != KOF_BROKEN &&
			   grow((void **)&w->call, &w->cap_call, w->n_call,
				sizeof *w->call)) {
			struct pe_call *c = &w->call[w->n_call++];

			c->at = in.at;
			c->target_va = in.target_va;
		}
		if (s->full)
			return;
	}
}

void kof_diag_run_pe_symbol(struct kof_diag_scan *s,
			    const struct kof_obj_ctx *ctx,
			    const uint8_t *base, uint64_t size)
{
	const struct kof_pe_info *p;
	struct pe_walk w;
	kof_buf f;
	uint32_t i;
	int wide;

	if (!ctx || ctx->format != KOF_FMT_PE)
		return;
	p = kof_pe(ctx);
	if (!p || !p->valid)
		return;
	wide = p->pe32_plus != 0;
	memset(&w, 0, sizeof w);
	w.imp.base = base;
	w.imp.size = size;
	f.p = base;
	f.n = size;
	kof_pe_imports(f, p, gather_import, &w.imp);
	/* No imports does not end it: a stager has none worth the name, and what
	 * it calls is named by the analysis in diag_apihash.c. */
	if (w.imp.n)
		qsort(w.imp.v, w.imp.n, sizeof *w.imp.v, imp_by_slot);

	/*
	 * EVERY EXECUTABLE SECTION, from its first byte. Unlike an ELF segment a PE
	 * section does not contain the headers, so there is no desync to avoid; a
	 * section is decoded where its raw data begins.
	 */
	for (i = 0; i < p->sec_count; i++) {
		const struct kof_pe_sec *sc = &p->sec[i];
		uint64_t have;

		if (!(sc->perm & KOF_PE_PERM_X))
			continue;
		have = kof_clip_len(size, sc->file_off, sc->file_size);
		if (have)
			walk_code(s, ctx, base, size, sc->file_off, have, wide, &w);
		if (s->full)
			goto out;
	}

	/* The stubs, now that all of them are known: a direct call to one is a
	 * call to the import. */
	if (w.n_thunk) {
		qsort(w.thunk, w.n_thunk, sizeof *w.thunk, imp_by_slot);
		for (i = 0; i < w.n_call; i++) {
			struct pe_imp key, *t;

			key.slot = w.call[i].target_va;
			t = bsearch(&key, w.thunk, w.n_thunk, sizeof *w.thunk,
				    imp_by_slot);
			if (t)
				add_node(s, w.call[i].at, t);
		}
	}
out:
	free(w.imp.v);
	free(w.thunk);
	free(w.call);
}
