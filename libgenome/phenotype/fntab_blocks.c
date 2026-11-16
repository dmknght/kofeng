/*
 * fntab_blocks.c - THE BLOCK LAYER OF AN OBJECT (celllysis/cfg.h, kgenome_cfg_obj_build), seeded from what the object declares and read from the walk's
 * one decode. Partition redesign STEP B 1b (owner 2026-11-15).
 *
 * SEEDS: every start the headers declare, whatever the function table's selector chose to read for its own case - the entry point, the symbol tables
 * (.symtab and .dynsym), the unwind starts (.eh_frame), and for a PE .pdata (a chained part too: it is code that runs, D1), the exports, the TLS callbacks,
 * the load configuration's lists and the COFF symbols. The strategies are the function table's own (fntab.h): nothing here reads a header. The walk's
 * call targets are NOT seeds: they come from a linear sweep that reads data as code (D6); the descent finds the call targets of the code it reaches.
 * Indirect entries (a code pointer an API is handed, a vtable) are not seeded yet: the API row table's code-pointer arguments (fix_roles) are the next
 * source, added here as one more strategy when it lands.
 *
 * ONE DECODE: the space is held to the walk's trace (kgenome_diag_walk_hold, raw as the walk decodes), so an offset the walk decoded is read back;
 * `out->n_fresh` is what the descent had to decode because the walk had read those bytes at another alignment.
 *
 * TRANSITION (owner 2026-11-15): this runs in tests and harnesses only. It is not a second path of the shipped scan: the function table (fntab_build.c)
 * stays the scan's until STEP B 2 makes the table a view of these blocks and removes the old path in the same change (rule 10).
 */
/* DISABLED by the owner 2026-11-16: the block layer (recursive descent over the decode, STEP B 1b, tests and harnesses only) is a function finder from decoded code; the partition is made from metadata only. To re-enable: take the #if 0 out and the #if 0 of its tests (tests/lib/genome/cfg_obj_elf.c, the kgenome_fntab_blocks part of cfg_obj.c). */
#if 0
#include "fntab_build_private.h"
#include <celllysis/space.h>

/* Append every entry of `l` as a seed (its source bits kept), then free `l`. 0: memory. */
static int seeds_take(struct kgenome_fntab_list *l, struct kgenome_cfg_obj_seed **sd, uint32_t *n, uint32_t *cap)
{
	uint32_t i;

	for (i = 0; i < l->n; i++) {
		if (*n == *cap) {
			const uint32_t nc = *cap ? *cap * 2u : 256u;
			struct kgenome_cfg_obj_seed *t = realloc(*sd, (size_t)nc * sizeof **sd);

			if (!t) {
				kgenome_fntab_list_free(l);
				return 0;
			}
			*sd = t;
			*cap = nc;
		}
		(*sd)[*n].off = l->v[i].off;
		(*sd)[*n].src = l->v[i].source;
		(*n)++;
	}
	kgenome_fntab_list_free(l);
	return 1;
}

enum kgenome_status kgenome_fntab_blocks(const struct kgenome_fntab_blocks_req *rq, struct kgenome_cfg_obj *out)
{
	struct kgenome_cfg_obj_seed *sd = NULL;
	struct kgenome_cfg_obj_ext ext[KGENOME_ELF_MAX_SEGMENTS > KGENOME_PE_MAX_SECTIONS ? KGENOME_ELF_MAX_SEGMENTS : KGENOME_PE_MAX_SECTIONS];
	struct kgenome_cfg_obj_req cr;
	struct kgenome_cell_space sp;
	struct kgenome_fntab_list l;
	uint32_t n = 0, cap = 0, n_ext = 0, i;
	kof_buf file;
	int ok = 1;

	if (!out)
		return KGENOME_BAD_INPUT;
	memset(out, 0, sizeof *out);
	if (!rq || !rq->obj || !rq->obj->file_header || !rq->walk)
		return out->status = KGENOME_BAD_INPUT;
	if (rq->obj->format == KGENOME_FMT_ELF ? !((const struct kgenome_elf_info *)rq->obj->file_header)->valid :
	    rq->obj->format == KGENOME_FMT_PE ? !((const struct kgenome_pe_info *)rq->obj->file_header)->valid : 1)
		return out->status = KGENOME_BAD_INPUT;
	if (!kgenome_diag_walk_ensure(rq->walk, rq->obj, rq->data, rq->data_n, 1))
		return out->status = KGENOME_NOMEM;
	file = kof_buf_make(rq->data, rq->data_n);
	/* the seeds: the function table's metadata strategies, every one the format has */
	memset(&l, 0, sizeof l);
	if (rq->obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = rq->obj->file_header;

		kgenome_fntab_symtab(file, e, 0, &l);
		ok = seeds_take(&l, &sd, &n, &cap);
		kgenome_fntab_symtab(file, e, 1, &l);
		ok = ok && seeds_take(&l, &sd, &n, &cap);
		kgenome_fntab_fde(file, e, &l);
		ok = ok && seeds_take(&l, &sd, &n, &cap);
	} else {
		const struct kgenome_pe_info *p = rq->obj->file_header;

		kgenome_fntab_pdata(file, p, &l);
		ok = seeds_take(&l, &sd, &n, &cap);
		kgenome_fntab_pe_export(file, p, &l);
		ok = ok && seeds_take(&l, &sd, &n, &cap);
		kgenome_fntab_pe_tls(file, p, &l);
		ok = ok && seeds_take(&l, &sd, &n, &cap);
		kgenome_fntab_pe_cfg(file, p, &l);
		ok = ok && seeds_take(&l, &sd, &n, &cap);
		kgenome_fntab_pe_coff(file, p, &l);
		ok = ok && seeds_take(&l, &sd, &n, &cap);
	}
	if (ok && rq->obj->entry_off < (uint64_t)-2) {          /* not NA, not BROKEN */
		struct kgenome_func f;

		memset(&f, 0, sizeof f);
		f.off = rq->obj->entry_off;
		f.source = KGENOME_FN_S_ENTRY;
		ok = kgenome_fntab_list_add(&l, &f) && seeds_take(&l, &sd, &n, &cap);
	}
	kgenome_fntab_list_free(&l);
	if (!ok) {
		free(sd);
		return out->status = KGENOME_NOMEM;
	}
	/* the extents the walk reads (one function: kgenome_diag_extent) */
	for (i = 0; i < kgenome_diag_extent_count(rq->obj) && n_ext < sizeof ext / sizeof *ext; i++) {
		uint64_t at, have = kgenome_diag_extent(rq->obj, i, rq->data_n, &at);

		if (have) {
			ext[n_ext].off = at;
			ext[n_ext].len = have;
			n_ext++;
		}
	}
	/* the space, held to the walk's decode (raw, as the walk asks for it) */
	kgenome_cell_space_init(&sp, rq->obj, rq->data, rq->data_n);
	sp.raw = 1;
	(void)kgenome_diag_walk_hold(&sp, rq->walk);
	memset(&cr, 0, sizeof cr);
	cr.sp = &sp;
	cr.ext = ext;
	cr.n_ext = n_ext;
	cr.seed = sd;
	cr.n_seed = n;
	cr.max_insn = rq->max_insn;
	cr.budget = rq->budget;
	cr.mem = rq->mem;
	(void)kgenome_cfg_obj_build(&cr, out);
	free(sd);
	return out->status;
}
#endif
