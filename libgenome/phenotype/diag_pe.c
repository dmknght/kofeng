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
#include <kofdebug.h>
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
	uint8_t  noret;         /* an import that never returns (ExitProcess ...): no node, an end of block */
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
static void gather_imports(struct kgenome_diag_scan *s, struct pe_acc *a, kof_buf f,
			   const struct kgenome_pe_imptab *t)
{
	uint32_t k;

	for (k = 0; k < t->n; k++) {
		const struct kgenome_pe_imp *im = &t->v[k];
		char name[KGENOME_PE_IMP_DLLLEN];
		uint16_t cap;
		struct pe_imp *e;
		int nr;

		if (!kgenome_pe_imp_name(f, im, name, sizeof name))
			continue;               /* by ordinal: no word to match */
		cap = kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, name);
		nr = cap == KGENOME_NUCLEO_NONE && kgenome_diag_name_is_noreturn(name);
		if (cap == KGENOME_NUCLEO_NONE && !nr)
			continue;
		if (a->n == a->cap_n) {
			uint32_t nc = kgenome_grow_cap(a->cap_n, 64u);
			struct pe_imp *nv = nc ? realloc(a->v, (size_t)nc * sizeof *nv) : NULL;

			if (!nv) {
				/* the imports from here on are not looked at: said */
				kgenome_diag_note(s, KGENOME_NOMEM);
				KOF_TRACE("[cut] gather_imports: %u imports kept, growth refused\n", a->n);
				return;
			}
			a->v = nv;
			a->cap_n = nc;
		}
		e = &a->v[a->n++];
		e->slot = im->slot;
		e->cap = cap;
		e->noret = (uint8_t)nr;
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

static void add_node(struct kgenome_diag_scan *s, uint64_t at,
		     const struct pe_imp *im)
{
	struct kgenome_diag_hit *h;

	if (im->noret) {
		(void)kgenome_diag_noret_add(s, at);
		return;
	}
	h = kgenome_diag_hit_add(s, at, im->cap, 0);
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

static int grow(struct kgenome_diag_scan *s, void **v, uint32_t *cap, uint32_t n, size_t each)
{
	if (n < *cap)
		return 1;
	{
		uint32_t nc = kgenome_grow_cap(*cap, 256u);
		void *nv = nc ? realloc(*v, (size_t)nc * each) : NULL;

		if (!nv) {
			/* a stub or a call that is not recorded is an import call never matched */
			kgenome_diag_note(s, KGENOME_NOMEM);
			KOF_TRACE("[cut] diag_pe grow: %u entries kept, growth refused\n", n);
			return 0;
		}
		*v = nv;
		*cap = nc;
	}
	return 1;
}

/* One instruction of the object's one decode (kgenome_diag_code_run: the walk's trace, the decoder where the trace is not held). A call through an import slot is a node; a direct
 * call is kept until the stubs are known, because a call to a stub is a call to the import. A byte the decoder cannot read arrives as NULL and is stepped over by the reader: a
 * switch table of 32-bit offsets inside the code is not the end of the section (measured on a 180 KB MSVC .text: a loop that stopped there saw the first fifth of the file). */
struct pe_obs {
	struct kgenome_diag_scan *s;
	struct pe_walk *w;
	int wide;
};

static void pe_observe(void *user, const struct kgenome_cell_insn *in)
{
	struct pe_obs *o = user;
	struct pe_walk *w = o->w;

	if (!in || o->s->halt)
		return;
	if (in->op == KGENOME_CELL_CALL && (in->flags & KGENOME_CELL_F_INDIRECT) && in->n_op &&
	    in->o[0].kind == KGENOME_CELL_O_MEM) {
		const uint64_t slot = kgenome_cell_slot_of(in, o->wide, 0);
		const struct pe_imp *im = slot == KGENOME_BROKEN ? NULL : imp_find(&w->imp, slot);

		if (im)
			add_node(o->s, in->at, im);
	} else if (in->op == KGENOME_CELL_CALL && !(in->flags & KGENOME_CELL_F_INDIRECT) &&
		   in->target_va != KGENOME_BROKEN &&
		   grow(o->s, (void **)&w->call, &w->cap_call, w->n_call, sizeof *w->call)) {
		struct pe_call *c = &w->call[w->n_call++];

		c->at = in->at;
		c->target_va = in->target_va;
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
	if (s->imports) {
		/* The scanner's table that stopped short is a partial import list, whoever
		 * asks: the scan says so here and not only in the route that happens to run. */
		kgenome_diag_note(s, s->imports->status);
		return s->imports;
	}
	if (!s->imports_done) {
		const struct kgenome_pe_info *p = obj ? kgenome_obj_pe(obj) : NULL;

		if (p && p->valid) {
			s->own |= KGENOME_DIAG_OWN_IMPORTS;
			kgenome_pe_imptab_build(kof_buf_make(s->base, s->size), p,
					    &s->own_imports);
			kgenome_diag_note(s, s->own_imports.status);
		}
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
	struct pe_obs ob;
	struct kgenome_diag_walk *wk;
	const struct kgenome_diag_stub *stub;
	const struct kgenome_pe_imptab *tab;
	kof_buf f;
	uint32_t i, n_stub;
	int wide;

	if (!obj || obj->format != KGENOME_FMT_PE)
		return;
	p = kgenome_obj_pe(obj);
	if (!p || !p->valid)
		return;
	wide = p->pe32_plus != 0;
	memset(&w, 0, sizeof w);
	ob = (struct pe_obs){ s, &w, wide };
	f.p = base;
	f.n = size;
	tab = kgenome_diag_imports(s, obj);
	/* (A table that stopped short is noted by kgenome_diag_imports.) */
	gather_imports(s, &w.imp, f, tab);
	/* No imports does not end it: a stager has none worth the name, and what
	 * it calls is named by the analysis in diag_apihash.c. */
	if (w.imp.n)
		qsort(w.imp.v, w.imp.n, sizeof *w.imp.v, kof_cmp_u64);

	/*
	 * EVERY CODE SECTION (kgenome_pe_sec_is_code), from its first byte, read through the object's one decode. Unlike an ELF segment a PE
	 * section does not contain the headers, so there is no desync to avoid; a section is decoded where its raw data begins.
	 */
	wk = kgenome_diag_scan_walk(s);
	if (!kgenome_diag_walk_ensure(wk, obj, base, size, 1)) {
		kgenome_diag_note(s, KGENOME_NOMEM);    /* the code could not be held: no nodes, said */
		goto out;
	}
	for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at), va;

		if (!have || (va = kgenome_image_off_to_addr(obj, at)) == KGENOME_BROKEN)
			continue;
		kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
			.obj = obj, .base = base, .size = size, .off = at, .n = have, .va = va,
			.fn = pe_observe, .user = &ob, .wk = wk });
		if (s->halt)
			goto out;
	}

	/* The stubs, now that all of them are known (the walk met every `jmp [slot]` through a fixed slot): a direct call to one whose slot is an import is a call to the import. */
	stub = kgenome_diag_walk_thunks(wk, &n_stub);
	for (i = 0; i < n_stub; i++) {
		const struct pe_imp *im = imp_find(&w.imp, stub[i].slot);
		const uint64_t va = im ? kgenome_image_off_to_addr(obj, stub[i].at) : KGENOME_BROKEN;

		if (va == KGENOME_BROKEN || !grow(s, (void **)&w.thunk, &w.cap_thunk, w.n_thunk, sizeof *w.thunk))
			continue;
		w.thunk[w.n_thunk] = *im;
		w.thunk[w.n_thunk++].slot = va;         /* the stub's own address */
	}
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
	/* the calls through thunks are noted after the code is read: the list is searched in address order */
	if (s->n_noret > 1u)
		qsort(s->noret_at, s->n_noret, sizeof *s->noret_at, kof_cmp_u64);
	free(w.imp.v);
	free(w.thunk);
	free(w.call);
}
