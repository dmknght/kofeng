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
 * THE TABLE LISTS THE NAMES AND THE DECODER FINDS THE SITES. The import table
 * (kgenome_pe_imptab, one walk shared with the symbol block) gives every import with the address of the slot the loader fills; a call
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "diag_scan.h"
#include "diag_private.h"
#include <kofcore.h>
#include <kofcmp.h>
#include <celllysis/capability.h>
#include <celllysis/cell.h>
#include <genotype/image/pe_image.h>
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <celllysis/space.h>

struct pe_imp {
	uint64_t slot;          /* the address a call goes through            */
	uint64_t name_off;      /* where the import's name is, 0 if unknown   */
	uint16_t cap;
};

struct pe_acc {
	struct pe_imp *v;
	uint32_t       n, cap_n;
};

/* A direct call, kept to be matched against the stubs once all are known. */
struct pe_call {
	uint64_t at;            /* file offset of the call                    */
	uint64_t target_va;
};

/* The imports the vocabulary has a word for, out of the object's import
 * table. The table is the scanner's when it handed one over - the symbol block
 * is built from the same - and this scan's own otherwise. */
static void gather_imports(struct pe_acc *a, kof_buf f,
			   const struct kgenome_pe_imptab *t)
{
	uint32_t k;

	for (k = 0; k < t->n; k++) {
		const struct kgenome_pe_imp *im = &t->v[k];
		char name[KGENOME_PE_IMP_DLLLEN];
		uint16_t cap;
		struct pe_imp *e;

		if (!kgenome_pe_imp_name(f, im, name, sizeof name))
			continue;               /* by ordinal: no word to match */
		cap = kgenome_nucleo_cap_of_name(name);
		if (cap == KGENOME_NUCLEO_NONE)
			continue;
		if (a->n == a->cap_n) {
			uint32_t nc = a->cap_n ? a->cap_n * 2u : 64u;
			struct pe_imp *nv = realloc(a->v, (size_t)nc * sizeof *nv);

			if (!nv)
				return;
			a->v = nv;
			a->cap_n = nc;
		}
		e = &a->v[a->n++];
		e->slot = im->slot;
		e->cap = cap;
		e->name_off = im->nameoff;
	}
}

/* Ordered by `slot`, which kof_cmp_u64 reads as the first member. */
_Static_assert(offsetof(struct pe_imp, slot) == 0,
	       "kof_cmp_u64 reads the key from the start of the element");

static const struct pe_imp *imp_find(const struct pe_acc *a, uint64_t slot)
{
	struct pe_imp key;

	if (!a->n)              /* bsearch's base is nonnull, and here it is NULL */
		return NULL;
	key.slot = slot;
	return bsearch(&key, a->v, a->n, sizeof *a->v, kof_cmp_u64);
}

/*
 * THE SLOT AN INDIRECT BRANCH GOES THROUGH, or KGENOME_BROKEN when it is not a
 * fixed address. x64 reaches the IAT RIP-relative; x86 names it absolutely.
 * Anything with a base or index register is a table lookup or a vtable call and
 * is not an import.
 */
static uint64_t slot_of(const struct kgenome_cell_insn *in, int wide)
{
	const struct kgenome_cell_operand *o = &in->o[0];

	if (o->flags & KGENOME_CELL_OF_RIPREL) {
		if (in->at_va == KGENOME_BROKEN)
			return KGENOME_BROKEN;
		return in->at_va + in->len + (uint64_t)o->disp;
	}
	if (o->reg == KGENOME_CELL_REG_NONE && o->index == KGENOME_CELL_REG_NONE)
		return wide ? (uint64_t)o->disp : (uint64_t)o->disp & 0xffffffffu;
	return KGENOME_BROKEN;
}

static void add_node(struct kgenome_diag_scan *s, uint64_t at,
		     const struct pe_imp *im)
{
	struct kgenome_diag_hit *h = kgenome_diag_hit_add(s, at, im->cap, 0);

	if (h && im->name_off) {
		h->symref = im->name_off;
		h->bits |= KGENOME_DIAG_H_SYMREF;
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

static void walk_code(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
		      const uint8_t *base, uint64_t size, uint64_t off,
		      uint64_t n, int wide, struct pe_walk *w)
{
	struct kgenome_cell_cur k;
	struct kgenome_cell_space sp;
	struct kgenome_cell_insn in;

	kgenome_cell_space_init(&sp, obj, base, size);
	memset(&k, 0, sizeof k);
	if (!kgenome_cell_seek(&k, off, 0))
		return;
	while (k.at < off + n) {
		/*
		 * A BYTE THE DECODER CANNOT READ IS STEPPED OVER, NOT THE END.
		 * kgenome_cell_step answers zero and leaves the cursor where it was, so
		 * a loop that treats zero as "finished" stops at the first piece of
		 * data inside the code: MEASURED on a 180 KB MSVC .text, it stopped
		 * at offset 0x583c, a switch jump table of 32-bit offsets, with
		 * 5400 instructions decoded and the rest of the section never
		 * looked at - 98 nodes, all in the first fifth of the file.
		 * x86 resynchronises within a few instructions of garbage, and a
		 * wrong decode costs nothing here: a node needs the operand to be
		 * the address of an import slot, exactly.
		 */
		if (!kgenome_cell_step(&k, &sp, &in)) {
			k.at++;
			continue;
		}
		if ((in.op == KGENOME_CELL_CALL || in.op == KGENOME_CELL_JMP) &&
		    (in.flags & KGENOME_CELL_F_INDIRECT) && in.n_op &&
		    in.o[0].kind == KGENOME_CELL_O_MEM) {
			uint64_t slot = slot_of(&in, wide);
			const struct pe_imp *im;

			if (slot == KGENOME_BROKEN)
				continue;
			im = imp_find(&w->imp, slot);
			if (!im)
				continue;
			if (in.op == KGENOME_CELL_CALL) {
				add_node(s, in.at, im);
			} else if (in.at_va != KGENOME_BROKEN &&
				   grow((void **)&w->thunk, &w->cap_thunk,
					w->n_thunk, sizeof *w->thunk)) {
				struct pe_imp *t = &w->thunk[w->n_thunk++];

				*t = *im;
				t->slot = in.at_va;     /* the stub's own address */
			}
		} else if (in.op == KGENOME_CELL_CALL && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
			   in.target_va != KGENOME_BROKEN &&
			   grow((void **)&w->call, &w->cap_call, w->n_call,
				sizeof *w->call)) {
			struct pe_call *c = &w->call[w->n_call++];

			c->at = in.at;
			c->target_va = in.target_va;
		}
		if (s->halt)
			return;
	}
}

/*
 * THE IMPORT TABLE THIS SCAN READS: the scanner's when it handed one over,
 * otherwise built here once from the scan's own bytes and kept. The PE route and
 * the API-hash run (whose emulator fills its IAT from it) take the same one.
 */
const struct kgenome_pe_imptab *kgenome_diag_imports(struct kgenome_diag_scan *s,
					     const struct kgenome_obj *obj)
{
	if (s->imports)
		return s->imports;
	if (!s->imports_done) {
		const struct kgenome_pe_info *p = obj ? kgenome_obj_pe(obj) : NULL;

		if (p && p->valid)
			kgenome_pe_imptab_build(kof_buf_make(s->base, s->size), p,
					    &s->own_imports);
		(void)kgenome_ledger_charge(&s->led, (uint64_t)s->own_imports.n *
					    sizeof *s->own_imports.v);
		s->imports_done = 1;
	}
	return &s->own_imports;
}

void kgenome_diag_run_pe_symbol(struct kgenome_diag_scan *s,
			    const struct kgenome_obj *obj,
			    const uint8_t *base, uint64_t size)
{
	const struct kgenome_pe_info *p;
	struct pe_walk w;
	const struct kgenome_pe_imptab *tab;
	kof_buf f;
	uint32_t i;
	int wide;

	if (!obj || obj->format != KGENOME_FMT_PE)
		return;
	p = kgenome_obj_pe(obj);
	if (!p || !p->valid)
		return;
	wide = p->pe32_plus != 0;
	memset(&w, 0, sizeof w);
	f.p = base;
	f.n = size;
	tab = kgenome_diag_imports(s, obj);
	/* A table that stopped short - the thunk budget, memory - is a partial
	 * import list, whoever built it, and the scan says so. */
	kgenome_diag_note(s, tab->status);
	gather_imports(&w.imp, f, tab);
	/* No imports does not end it: a stager has none worth the name, and what
	 * it calls is named by the analysis in diag_apihash.c. */
	if (w.imp.n)
		qsort(w.imp.v, w.imp.n, sizeof *w.imp.v, kof_cmp_u64);

	/*
	 * EVERY CODE SECTION (kgenome_pe_sec_is_code), from its first byte. Unlike an ELF segment a PE
	 * section does not contain the headers, so there is no desync to avoid; a
	 * section is decoded where its raw data begins.
	 */
	for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

		if (have)
			walk_code(s, obj, base, size, at, have, wide, &w);
		if (s->halt)
			goto out;
	}

	/* The stubs, now that all of them are known: a direct call to one is a
	 * call to the import. */
	if (w.n_thunk) {
		qsort(w.thunk, w.n_thunk, sizeof *w.thunk, kof_cmp_u64);
		for (i = 0; i < w.n_call; i++) {
			struct pe_imp key, *t;

			key.slot = w.call[i].target_va;
			t = bsearch(&key, w.thunk, w.n_thunk, sizeof *w.thunk,
				    kof_cmp_u64);
			if (t)
				add_node(s, w.call[i].at, t);
		}
	}
out:
	free(w.imp.v);
	free(w.thunk);
	free(w.call);
}
