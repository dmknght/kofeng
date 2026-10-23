/*
 * diag_elfimp.c - nodes from what a LINKED ELF imports: the calls that go through its PLT or its GOT.
 *
 * WHY THIS EXISTS. A dynamically linked program contains no system call - the libc it loads does - so
 * the syscall sweep finds nothing in it, and the symbol route (diag_sym.c) read only the relocation
 * table of a relocatable object. MEASURED on 100 dynamic x86-64 ELF with symbols (the cell of the
 * graph-research report), 0 files had a node with a name from the engine: every `call socket@plt`
 * was invisible, and so was every link that would have run through it. The vocabulary already knew
 * the names (socket, connect, read, mmap ...); nothing connected an import to the place that calls it.
 * This is the route diag_pe.c is for a PE, and it is shaped like it on purpose.
 *
 * THE TABLE LISTS THE NAMES AND THE DECODER FINDS THE SITES (kgenome_elf_imports gives every GOT slot
 * with the symbol it is filled with). A program reaches a slot three ways, all computable from the
 * instruction without running it:
 *   - `call stub`, where the stub is `jmp [slot]` in the PLT (x86-64 lazy `.plt`, the IBT `.plt.sec`
 *     whose stub starts with `endbr64`, and i386's, which names the slot absolutely or through ebx);
 *   - `call [slot]` / `jmp [slot]` itself, which is what -fno-plt compiles to and a tail call is;
 *   - `jmp stub`, a tail call.
 * The node is at the CALL (or the tail JMP), which is where the program says what it is doing: one stub
 * called from nine places is nine acts and not one. A `jmp [slot]` that IS a stub is not a node.
 *
 * THE i386 GOT REGISTER. A position-independent i386 object reaches its slots as `[ebx + disp]` with
 * ebx the GOT's address, and the instruction does not say what ebx holds. The first three words of
 * the GOT are reserved (_DYNAMIC and the two the lazy binder uses), so the lowest JUMP_SLOT is at GOT+12
 * and `ebx = lowest slot - 12`. That is a fact about the psABI and not a guess about one binary, and it
 * is applied ONLY to a 32-bit object whose slots it explains; the test builds both forms.
 *
 * NO LINKS HERE, as in diag_pe.c: a node says "this call is `connect`" and nothing about which socket.
 * What flows into it is the lineage stage's (diag_lineage.c).
 *
 * THE CODE IS READ THROUGH THE OBJECT'S WALK (kgenome_diag_walk_ensure + kgenome_diag_code_run), twice:
 * once for the stubs, once for the sites. The decode is the walk's, made once and kept, so the second read
 * is a read of the trace and not a second decode - which is also what lets the lineage stage and the
 * xref sweep read the same instructions again.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "diag_scan_private.h"
#include <kofcmp.h>
#include <genotype/image/image_addr.h>

struct ei_imp {
	uint64_t slot;          /* the address the call goes through (the sort key) */
	uint64_t nameoff;       /* file offset of the symbol's name */
	uint16_t cap;
	uint8_t  noret;         /* an import that never returns (exit, abort ...): no node, a call that ends its block */
};

struct ei_stub {
	uint64_t va;            /* where a call to the stub lands (the sort key) */
	uint32_t imp;           /* index into the import table */
};

struct ei_ctx {
	struct kgenome_diag_scan *s;
	struct ei_imp *imp;
	uint32_t n_imp, cap_imp;
	struct ei_stub *stub;
	uint32_t n_stub, cap_stub;
	uint64_t min_jslot;     /* lowest JUMP_SLOT of the object, for the i386 GOT register */
	uint64_t gotbase;       /* the GOT's address when a 32-bit object's slots say it, else 0 */
	int      wide;
	int      oom;
	/* The code sections that are not the program's own - the PLT and the like (kgenome_elf_sec_is_stub) - by address;
	 * `no_sections` when the object has no section table to say. */
	struct { uint64_t lo, hi; } stubsec[KGENOME_ELF_MAX_SECTIONS];
	uint32_t n_stubsec;
	int      no_sections;
	/* the previous decoded instruction when it was an `endbr`, to join it to the jump after it */
	const uint8_t *base;
	uint64_t size;
	uint64_t prev_end_va;
	uint8_t  prev_endbr;
	uint64_t prev_va;
	uint64_t charged;
};

_Static_assert(offsetof(struct ei_imp, slot) == 0, "kof_cmp_u64 reads the key from the start");
_Static_assert(offsetof(struct ei_stub, va) == 0, "kof_cmp_u64 reads the key from the start");

static int ei_grow(struct ei_ctx *c, void **v, uint32_t *cap, uint32_t n, size_t each)
{
	uint32_t nc;
	void *nv;

	if (n < *cap)
		return 1;
	nc = *cap ? *cap * 2u : 256u;
	if (!kgenome_ledger_charge(&c->s->led, (uint64_t)(nc - *cap) * each)) {
		c->oom = 1;
		return 0;
	}
	c->charged += (uint64_t)(nc - *cap) * each;
	nv = realloc(*v, (size_t)nc * each);
	if (!nv) {
		/* an import or a stub that is not kept is a call that is never named: said */
		kgenome_diag_note(c->s, KGENOME_NOMEM);
		c->oom = 1;
		return 0;
	}
	*v = nv;
	*cap = nc;
	return 1;
}

static void ei_gather(void *user, uint64_t slot, uint64_t nameoff, uint32_t type, const char *name)
{
	struct ei_ctx *c = user;
	uint16_t cap;
	int nr;

	if (type == 7u && (!c->min_jslot || slot < c->min_jslot))
		c->min_jslot = slot;
	cap = kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, name);
	nr = cap == KGENOME_NUCLEO_NONE && kgenome_diag_name_is_noreturn(name);
	if ((cap == KGENOME_NUCLEO_NONE && !nr) || !ei_grow(c, (void **)&c->imp, &c->cap_imp, c->n_imp, sizeof *c->imp))
		return;
	c->imp[c->n_imp].slot = slot;
	c->imp[c->n_imp].nameoff = nameoff;
	c->imp[c->n_imp].cap = cap;
	c->imp[c->n_imp].noret = (uint8_t)nr;
	c->n_imp++;
}

static const struct ei_imp *ei_find_slot(const struct ei_ctx *c, uint64_t slot)
{
	struct ei_imp key;

	if (!c->n_imp)
		return NULL;
	key.slot = slot;
	return bsearch(&key, c->imp, c->n_imp, sizeof *c->imp, kof_cmp_u64);
}

/*
 * THE SLOT AN INDIRECT BRANCH GOES THROUGH, or KGENOME_BROKEN when it is not a fixed one: RIP-relative
 * on x86-64, absolute or ebx-relative on i386. A base or index register that is anything else is a table
 * lookup or a vtable call, not an import.
 */
static uint64_t ei_slot_of(const struct ei_ctx *c, const struct kgenome_cell_insn *in)
{
	const struct kgenome_cell_operand *o = &in->o[0];

	if (o->kind != KGENOME_CELL_O_MEM || o->index != KGENOME_CELL_REG_NONE)
		return KGENOME_BROKEN;
	if (o->seg != KGENOME_CELL_REG_NONE && o->seg != KGENOME_CELL_SEG_DS)
		return KGENOME_BROKEN;          /* fs: and gs: are thread data */
	if (o->flags & KGENOME_CELL_OF_RIPREL)
		return in->at_va == KGENOME_BROKEN ? KGENOME_BROKEN
		       : in->at_va + in->len + (uint64_t)o->disp;
	if (o->reg == KGENOME_CELL_REG_NONE)
		return c->wide ? (uint64_t)o->disp : (uint64_t)o->disp & 0xffffffffu;
	if (!c->wide && o->reg == KGENOME_CELL_REG_BX && c->gotbase)
		return (c->gotbase + (uint64_t)o->disp) & 0xffffffffu;
	return KGENOME_BROKEN;
}

static int ei_is_slot_jump(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_JMP && (in->flags & KGENOME_CELL_F_INDIRECT) && in->n_op &&
	       in->o[0].kind == KGENOME_CELL_O_MEM;
}

/* `endbr64` / `endbr32`: f3 0f 1e fa / fb. The decoder classes it OTHER (it writes nothing and has no
 * class of its own), so the bytes say it. */
static int ei_is_endbr(const struct ei_ctx *c, const struct kgenome_cell_insn *in)
{
	const uint8_t *p;

	if (in->len != 4u || in->at > c->size || c->size - in->at < 4u)
		return 0;
	p = c->base + in->at;
	return p[0] == 0xf3u && p[1] == 0x0fu && p[2] == 0x1eu && (p[3] == 0xfau || p[3] == 0xfbu);
}

/* Is this address in a section of stubs. A `jmp [slot]` there is a PLT entry; one in the program's own code is a tail
 * call and is a node. Without a section table nothing says, and every such jump is taken for a stub. */
static int ei_in_stub_area(const struct ei_ctx *c, uint64_t va)
{
	uint32_t i;

	if (c->no_sections)
		return 1;
	for (i = 0; i < c->n_stubsec; i++)
		if (va >= c->stubsec[i].lo && va < c->stubsec[i].hi)
			return 1;
	return 0;
}

/* Pass 1: the stubs, a `jmp [slot]` in a section of stubs whose slot is an import. The `endbr64` before it is part of the
 * stub - a call lands on the endbr64 of an IBT PLT entry. */
static void ei_pass_stubs(void *user, const struct kgenome_cell_insn *in)
{
	struct ei_ctx *c = user;
	const struct ei_imp *im;
	uint64_t slot;

	if (!in || c->s->halt) {
		c->prev_endbr = 0;
		return;
	}
	if (ei_is_slot_jump(in) && ei_in_stub_area(c, in->at_va) && (slot = ei_slot_of(c, in)) != KGENOME_BROKEN &&
	    (im = ei_find_slot(c, slot)) != NULL) {
		uint32_t k = (uint32_t)(im - c->imp), a;
		const uint64_t at[2] = { in->at_va,
					 c->prev_endbr && c->prev_end_va == in->at_va ? c->prev_va : KGENOME_BROKEN };

		for (a = 0; a < 2u; a++) {
			if (at[a] == KGENOME_BROKEN ||
			    !ei_grow(c, (void **)&c->stub, &c->cap_stub, c->n_stub, sizeof *c->stub))
				continue;
			c->stub[c->n_stub].va = at[a];
			c->stub[c->n_stub].imp = k;
			c->n_stub++;
		}
	}
	c->prev_endbr = (uint8_t)ei_is_endbr(c, in);
	c->prev_va = in->at_va;
	c->prev_end_va = in->at_va + in->len;
}

static const struct ei_stub *ei_find_stub(const struct ei_ctx *c, uint64_t va)
{
	struct ei_stub key;

	if (!c->n_stub)
		return NULL;
	key.va = va;
	return bsearch(&key, c->stub, c->n_stub, sizeof *c->stub, kof_cmp_u64);
}

static void ei_add_node(struct ei_ctx *c, uint64_t at, const struct ei_imp *im)
{
	struct kgenome_diag_hit *h;

	if (im->noret) {
		struct kgenome_diag_scan *s = c->s;

		if (s->n_noret == s->cap_noret) {
			uint32_t nc = s->cap_noret ? s->cap_noret * 2u : 64u;
			uint64_t *nv;

			if (!kgenome_ledger_charge(&s->led, (uint64_t)(nc - s->cap_noret) * sizeof *nv))
				return;
			nv = realloc(s->noret_at, (size_t)nc * sizeof *nv);
			if (!nv) {
				kgenome_ledger_release(&s->led, (uint64_t)(nc - s->cap_noret) * sizeof *nv);
				kgenome_diag_note(s, KGENOME_NOMEM);
				return;
			}
			s->noret_at = nv;
			s->cap_noret = nc;
		}
		s->noret_at[s->n_noret++] = at;     /* in address order: the sites pass reads the code so */
		return;
	}
	h = kgenome_diag_hit_add(c->s, at, im->cap, 0);
	if (h && im->nameoff) {
		h->symref = im->nameoff;
		h->bits |= KGENOME_DIAG_H_SYMREF;
	}
}

/* Pass 2: the sites. */
static void ei_pass_sites(void *user, const struct kgenome_cell_insn *in)
{
	struct ei_ctx *c = user;
	const struct ei_imp *im = NULL;

	if (!in || c->s->halt)
		return;
	if (in->op != KGENOME_CELL_CALL && in->op != KGENOME_CELL_JMP)
		return;
	if (in->flags & KGENOME_CELL_F_INDIRECT) {
		uint64_t slot;

		if (!in->n_op || in->o[0].kind != KGENOME_CELL_O_MEM || ei_find_stub(c, in->at_va))
			return;                 /* a register, or the stub's own jump */
		slot = ei_slot_of(c, in);
		if (slot != KGENOME_BROKEN)
			im = ei_find_slot(c, slot);
	} else if (in->target_va != KGENOME_BROKEN) {
		const struct ei_stub *st = ei_find_stub(c, in->target_va);

		if (st)
			im = &c->imp[st->imp];
	}
	if (im)
		ei_add_node(c, in->at, im);
}

static int ei_cmp_stub(const void *a, const void *b)
{
	const struct ei_stub *x = a, *y = b;

	if (x->va != y->va)
		return x->va < y->va ? -1 : 1;
	return x->imp < y->imp ? -1 : x->imp > y->imp;
}

/* One read of every code extent of the object through the shared reader. */
static void ei_read_code(struct ei_ctx *c, const struct kgenome_obj *obj, const uint8_t *base,
			 uint64_t size, struct kgenome_diag_walk *wk, kgenome_cell_insn_fn fn)
{
	uint32_t i;

	for (i = 0; i < kgenome_diag_extent_count(obj) && !c->s->halt; i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at), va;

		if (!have)
			continue;
		va = kgenome_image_off_to_addr(obj, at);
		if (va == KGENOME_BROKEN)
			continue;
		c->prev_endbr = 0;
		kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
			.obj = obj, .base = base, .size = size, .off = at, .n = have, .va = va,
			.fn = fn, .user = c, .wk = wk });
	}
}

void kgenome_diag_run_elf_symbol(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
				 const uint8_t *base, uint64_t size)
{
	const struct kgenome_elf_info *ei = kgenome_obj_elf(obj);
	struct kgenome_diag_walk *wk;
	enum kgenome_status st = KGENOME_OK;
	struct ei_ctx c;
	uint32_t i;

	if (!ei || !ei->valid || ei->e_type == KGENOME_ELF_REL ||
	    (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64))
		return;
	memset(&c, 0, sizeof c);
	c.s = s;
	c.base = base;
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	(void)kgenome_elf_imports(kof_buf_make(base, size), ei, ei_gather, &c, &st);
	kgenome_diag_note(s, st);       /* a name cut short is a call named wrongly: said */
	if (c.oom || !c.n_imp)
		goto out;               /* nothing the vocabulary has a word for is imported */
	qsort(c.imp, c.n_imp, sizeof *c.imp, kof_cmp_u64);
	for (c.n_stubsec = 0, i = 0; i < ei->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		if (kgenome_elf_sec_is_code(&ei->sec[i]) && kgenome_elf_sec_is_stub(ei, i)) {
			c.stubsec[c.n_stubsec].lo = ei->sec[i].mem_addr;
			c.stubsec[c.n_stubsec++].hi = ei->sec[i].mem_addr + ei->sec[i].file_size;
		}
	c.no_sections = ei->sec_count == 0;
	/* The i386 GOT register: only when the lowest slot is where the psABI puts the first one. */
	if (!c.wide && c.min_jslot >= 12u)
		c.gotbase = c.min_jslot - 12u;
	wk = kgenome_diag_scan_walk(s);
	if (!wk || !kgenome_diag_walk_ensure(wk, obj, base, size, 1)) {
		kgenome_diag_note(s, KGENOME_NOMEM);    /* the code could not be held: no sites, said */
		goto out;
	}
	ei_read_code(&c, obj, base, size, wk, ei_pass_stubs);
	if (c.n_stub)
		qsort(c.stub, c.n_stub, sizeof *c.stub, ei_cmp_stub);
	ei_read_code(&c, obj, base, size, wk, ei_pass_sites);
out:
	free(c.imp);
	free(c.stub);
	kgenome_ledger_release(&s->led, c.charged);
}
