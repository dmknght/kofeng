/*
 * callnames.c - kgenome_callnames_build. See callnames.h for what the table is and where it stops.
 *
 * ONE READ OF THE CODE, through the shared reader. Each instruction is classified by kgenome_cell_plt_at (a `call`/`jmp` through a slot, a stub or a
 * call site, the `endbr` in front of a stub - the one function the ELF import route uses too) and the slot is looked up in the object's imports, which
 * are the ones the lib already walks (kgenome_elf_imports, kgenome_pe_imptab_build). No second import walk and no second decoder.
 */
#include <stdlib.h>
#include <string.h>

#include <kofcmp.h>

#include "callnames.h"
#include "diag_private.h"
#include "diag_scan.h"
#include "../celllysis/cell.h"
#include "../genotype/image/elf_image.h"
#include "../genotype/image/image_addr.h"
#include "../genotype/image/pe_image.h"

struct cn_imp {
	uint64_t slot;          /* the sort key: kof_cmp_u64 reads it from the start */
	uint64_t nameoff;
	uint32_t ordinal;
	uint32_t dll;
};
_Static_assert(offsetof(struct cn_imp, slot) == 0, "kof_cmp_u64 reads the key from the start");

struct cn_ctx {
	struct kgenome_callnames *out;
	struct kgenome_ledger *led;
	struct cn_imp *imp;
	uint32_t n_imp, cap_imp;
	uint64_t charged_tmp;   /* the import list, given back at the end */
	uint64_t charged;       /* the table */
	uint64_t size;
	int fail;
	struct kgenome_cell_plt plt;
	struct kgenome_diag_code_run_stats st;
};

static void cn_elf_gather(void *user, uint64_t slot, uint64_t nameoff, uint32_t type, const char *name)
{
	struct cn_ctx *c = user;

	(void)name;
	kgenome_cell_plt_import(&c->plt, slot, type);
	if (!nameoff || nameoff >= c->size || c->fail)
		return;         /* an import with no name, or whose name is past the end of the object (a string table the file does not hold), has nothing to say */
	if (kgenome_ledger_grow(c->led, (void **)&c->imp, &c->cap_imp, c->n_imp, sizeof *c->imp, &c->charged_tmp) <= 0) {
		c->fail = 1;
		return;
	}
	c->imp[c->n_imp++] = (struct cn_imp){ slot, nameoff, 0, 0 };
}

static void cn_pe_gather(struct cn_ctx *c, kof_buf f, const struct kgenome_pe_info *pe)
{
	struct kgenome_pe_imptab t;
	uint32_t i;

	memset(&t, 0, sizeof t);
	kgenome_pe_imptab_build(f, pe, &t);
	if (t.status == KGENOME_TRUNCATED || t.status == KGENOME_NOMEM)
		c->out->status = t.status;
	for (i = 0; i < t.n && !c->fail; i++) {
		if (kgenome_ledger_grow(c->led, (void **)&c->imp, &c->cap_imp, c->n_imp, sizeof *c->imp, &c->charged_tmp) <= 0) {
			c->fail = 1;
			break;
		}
		c->imp[c->n_imp++] = (struct cn_imp){ t.v[i].slot, t.v[i].nameoff, t.v[i].ordinal, t.v[i].dll };
	}
	if (!c->fail && t.n_dll) {
		/* the library names are the table's own copy: the imptab is freed below */
		struct kgenome_callnames *o = c->out;

		if (kgenome_ledger_charge(c->led, (uint64_t)t.n_dll * KGENOME_CALLNAME_DLLLEN)) {
			o->dll = malloc((size_t)t.n_dll * KGENOME_CALLNAME_DLLLEN);
			if (o->dll) {
				memcpy(o->dll, t.dll, (size_t)t.n_dll * KGENOME_CALLNAME_DLLLEN);
				o->n_dll = t.n_dll;
				c->charged += (uint64_t)t.n_dll * KGENOME_CALLNAME_DLLLEN;
			} else {
				kgenome_ledger_release(c->led, (uint64_t)t.n_dll * KGENOME_CALLNAME_DLLLEN);
				c->fail = 1;
				c->out->status = KGENOME_NOMEM;
			}
		} else {
			c->fail = 1;
		}
	}
	kgenome_pe_imptab_free(&t);
}

static int cn_push(struct cn_ctx *c, uint64_t off, const struct cn_imp *im, unsigned kind)
{
	struct kgenome_callnames *o = c->out;
	int r = kgenome_ledger_grow(c->led, (void **)&o->v, &o->cap, o->n, sizeof *o->v, &c->charged);

	if (r <= 0) {
		c->fail = 1;
		o->status = r < 0 ? KGENOME_NOMEM : KGENOME_OVER_BUDGET;
		return 0;
	}
	o->v[o->n++] = (struct kgenome_callname){ off, im->nameoff, im->ordinal, im->dll, (uint8_t)kind, { 0 } };
	return 1;
}

static void cn_observe(void *user, const struct kgenome_cell_insn *in)
{
	struct cn_ctx *c = user;
	const struct cn_imp *im;
	struct cn_imp key;
	struct kgenome_cell_plt_site site;
	int kind;

	if (!in || c->fail) {
		kgenome_cell_plt_reset(&c->plt);
		return;
	}
	kind = kgenome_cell_plt_at(&c->plt, in, &site);
	if (kind == KGENOME_CELL_PLT_NONE)
		return;
	key.slot = site.slot;
	im = c->n_imp ? bsearch(&key, c->imp, c->n_imp, sizeof *c->imp, kof_cmp_u64) : NULL;
	if (!im)
		return;
	if (cn_push(c, in->at, im, kind == KGENOME_CELL_PLT_STUB ? KGENOME_CALLNAME_STUB : KGENOME_CALLNAME_SLOT) &&
	    site.has_endbr)
		(void)cn_push(c, site.endbr_at, im, KGENOME_CALLNAME_STUB);
}

static int cn_cmp(const void *a, const void *b)
{
	const struct kgenome_callname *x = a, *y = b;

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	return (int)x->kind - (int)y->kind;     /* a STUB before a SLOT at one offset */
}

int kgenome_callnames_applicable(const struct kgenome_obj *obj)
{
	if (!obj || !obj->file_header)
		return 0;
	if (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64)
		return 0;
	if (obj->format == KGENOME_FMT_ELF)
		return kgenome_obj_elf(obj)->valid && kgenome_obj_elf(obj)->e_type != KGENOME_ELF_REL;
	return obj->format == KGENOME_FMT_PE && kgenome_obj_pe(obj)->valid;
}

int kgenome_callnames_build(const struct kgenome_callnames_req *rq, struct kgenome_callnames *out)
{
	const struct kgenome_obj *obj = rq->obj;
	struct kgenome_ledger own;
	struct cn_ctx c;
	uint32_t i, k, w;

	memset(out, 0, sizeof *out);
	if (!obj || !obj->file_header) {
		out->status = KGENOME_BAD_INPUT;
		return 0;
	}
	if (!kgenome_callnames_applicable(obj)) {
		out->status = (obj->format == KGENOME_FMT_ELF || obj->format == KGENOME_FMT_PE) &&
			      (obj->arch == KGENOME_ARCH_X86 || obj->arch == KGENOME_ARCH_X86_64)
			      ? KGENOME_BAD_INPUT : KGENOME_UNSUPPORTED;
		return 0;
	}
	kgenome_ledger_init(&own, 0);
	memset(&c, 0, sizeof c);
	c.out = out;
	c.led = rq->led ? rq->led : &own;
	c.size = rq->file.n;
	kgenome_cell_plt_init(&c.plt, rq->file.p, rq->file.n, obj->arch == KGENOME_ARCH_X86_64);
	out->format = obj->format;
	if (obj->format == KGENOME_FMT_PE) {
		cn_pe_gather(&c, rq->file, kgenome_obj_pe(obj));
		kgenome_cell_plt_ready(&c.plt, NULL);
	} else {
		enum kgenome_status st = KGENOME_OK;
		const struct kgenome_elf_info *ei = kgenome_obj_elf(obj);

		(void)kgenome_elf_imports(rq->file, ei, cn_elf_gather, &c, &st);
		if (st != KGENOME_OK)
			out->status = st;
		kgenome_cell_plt_ready(&c.plt, ei);
	}
	if (c.fail) {
		if (out->status == KGENOME_OK || out->status == KGENOME_TRUNCATED)
			out->status = KGENOME_OVER_BUDGET;
		goto done;
	}
	if (c.n_imp) {
		qsort(c.imp, c.n_imp, sizeof *c.imp, kof_cmp_u64);
		for (k = 0; k < kgenome_diag_extent_count(obj) && !c.fail; k++) {
			uint64_t at, have = kgenome_diag_extent(obj, k, rq->file.n, &at), va;

			if (!have)
				continue;
			va = kgenome_image_off_to_addr(obj, at);
			if (va == KGENOME_BROKEN)
				continue;
			kgenome_cell_plt_reset(&c.plt);
			kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
				.obj = obj, .base = rq->file.p, .size = rq->file.n, .off = at, .n = have, .va = va,
				.fn = cn_observe, .user = &c, .st = &c.st });
		}
	}
	if (out->n > 1u) {
		qsort(out->v, out->n, sizeof *out->v, cn_cmp);
		/* One entry per offset: a code extent read twice (overlapping segments) must not list a place twice. */
		for (i = 1, w = 1; i < out->n; i++)
			if (out->v[i].off != out->v[w - 1u].off)
				out->v[w++] = out->v[i];
		out->n = w;
	}
done:
	kgenome_ledger_release(c.led, c.charged_tmp);
	free(c.imp);
	out->bytes = c.charged;
	out->insns = c.st.decoded + c.st.from_trace;
	return 1;
}

void kgenome_callnames_free(struct kgenome_callnames *t, struct kgenome_ledger *led)
{
	if (!t)
		return;
	if (led)
		kgenome_ledger_release(led, t->bytes);
	free(t->v);
	free(t->dll);
	memset(t, 0, sizeof *t);
}

const struct kgenome_callname *kgenome_callnames_at(const struct kgenome_callnames *t, uint64_t off)
{
	const uint32_t lo = kof_lower_bound_u64(t->v, t->n, sizeof *t->v, offsetof(struct kgenome_callname, off), off);

	return lo < t->n && t->v[lo].off == off ? &t->v[lo] : NULL;
}
