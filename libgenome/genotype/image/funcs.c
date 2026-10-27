/*
 * funcs.c - the function extents of an object: the dispatch (kgenome_funcs_build),
 * the common finish, the remap into a view, and the two builders.
 *
 * Moved here from sym_any.c (dispatch, finish, free, remap), elf_sym.c
 * (kgenome_elf_funcs_build, kgenome_elf_funcs_from_entries) and pe_sym.c
 * (kgenome_pe_funcs_build) - the functions of an ELF or PE are read from the
 * structure, which is the genome's; the KSYM block those files build is the
 * engine's. The comments below are the originals.
 */

#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <genotype/image/elf_types.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "endian.h"
#include "elf_image.h"
#include "pe_image.h"

static void kgenome_elf_funcs_build(kof_buf file, const struct kgenome_elf_info *e,
			 struct kgenome_func_set *out);


/*
 * THE FUNCTIONS, by the same decision. ELF only for now: a PE names its
 * functions through exports and the exception directory, and which of those is
 * the source is not settled - an empty set is what it answers until then.
 */
void kgenome_funcs_build(uint32_t format, const uint8_t *data, uint64_t data_n,
		     const void *info, struct kgenome_func_set *out)
{
	memset(out, 0, sizeof *out);
	if (!info)
		return;
	if (format == KGENOME_FMT_ELF)
		kgenome_elf_funcs_build(kof_buf_make(data, data_n), info, out);
	else if (format == KGENOME_FMT_PE)
		kgenome_pe_funcs_build(kof_buf_make(data, data_n), info, out);
}

static int func_cmp(const void *a, const void *b)
{
	const struct kgenome_func *x = a, *y = b;

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	/* the longer extent first, so it is the one that stands */
	return x->len < y->len ? 1 : x->len > y->len ? -1 : 0;
}

/*
 * The last step of every format's builder, once: sort by offset, keep one
 * function per address (the longer extent stands) and no label inside another
 * body. Takes the malloc'd array `v` of `n` entries into `out`; frees it when
 * nothing is left.
 */
static void kgenome_funcs_finish(struct kgenome_func *v, uint32_t n, struct kgenome_func_set *out)
{
	uint32_t i, k = 0;

	if (!n) {
		free(v);
		return;
	}
	qsort(v, n, sizeof *v, func_cmp);
	for (i = 0; i < n; i++) {
		/* One function per address, and no label inside another body. */
		if (k && v[i].off < v[k - 1u].off + v[k - 1u].len &&
		    v[i].off + v[i].len <= v[k - 1u].off + v[k - 1u].len)
			continue;
		v[k++] = v[i];
	}
	out->v = v;
	out->n = k;
}

void kgenome_funcs_free(struct kgenome_func_set *s)
{
	if (!s)
		return;
	free(s->v);
	memset(s, 0, sizeof *s);
}

/* How many bytes of `a` and `b` agree from the start, up to `len`: what one candidate costs. */
static uint64_t common_len(const uint8_t *a, const uint8_t *b, uint64_t len)
{
	uint64_t i = 0;

	while (i + 8u <= len) {
		uint64_t x, y;

		memcpy(&x, a + i, 8);
		memcpy(&y, b + i, 8);
		if (x != y)
			break;
		i += 8u;
	}
	while (i < len && a[i] == b[i])
		i++;
	return i;
}

/*
 * The first place `len` bytes at `pat` occur in [from, from + span) of `view`: 1 found (`*at`), 0 not
 * there, -1 the work ran out.
 *
 * THE COST OF A SEARCH IS ITS COMPARES, NOT ONLY THE BYTES IT WALKS. memchr finds every place the first
 * byte occurs and each of those is compared against the body, so a body that begins with the byte a view
 * is full of (a zero) costs window x length: 1 MB x 64 KB took 1.06 s and 4 MB x 64 KB 4.69 s while the
 * bound, which counted the window alone, was nowhere near. `*work` is the caller's allowance; a candidate
 * that fails is charged the bytes it compared and the byte that differed (norm_defect_image N2).
 */
static int find_bytes(const uint8_t *view, uint64_t view_n, uint64_t from,
		      uint64_t span, const uint8_t *pat, uint64_t len,
		      uint64_t *at, uint64_t *work)
{
	uint64_t end, i;

	if (!len || from >= view_n || len > view_n - from)
		return 0;
	end = from + span;
	if (end > view_n - len + 1u)
		end = view_n - len + 1u;
	for (i = from; i < end; i++) {
		const uint8_t *q = memchr(view + i, pat[0], (size_t)(end - i));
		uint64_t c, cost;

		if (!q)
			return 0;
		i = (uint64_t)(q - view);
		c = common_len(q, pat, len);
		if (c == len) {
			*at = i;
			return 1;
		}
		cost = c + 1u;
		if (cost > *work) {
			*work = 0;
			return -1;
		}
		*work -= cost;
	}
	return 0;
}

/*
 * HOW FAR PAST THE LAST FUNCTION FOUND THE NEXT MAY BEGIN is not a constant. A view is the parent
 * with bytes REMOVED (a library cut, padding collapsed), in the same order, so a function cannot sit
 * further from the previous one in the view than it did in the parent: the window is that distance,
 * from the end of the last function FOUND to the start of this one, plus its length. A fixed 4096
 * lost every function that followed a long run of data (the parent's own gap was bigger), and a
 * function that is not within its window is not in the view: it was cut, which is an answer.
 *
 * The cost is bounded by the view: a function that is not there is searched for over its whole
 * window, and a run of them makes the windows grow, so the bytes searched AND the bytes compared in
 * all are held to REMAP_WORK per byte of the view. The set says KGENOME_OVER_BUDGET when that ran out.
 */
#define REMAP_WORK 64u

/*
 * THE SAME SEARCH, FOR A VIEW IN THE OTHER BYTE ORDER. `plan` (endian.h) names what
 * the view swapped, so the bytes looked for are the parent's function as the plan
 * leaves it - the same range of the applied object, without the object. NULL is
 * the plain search, which is what kgenome_funcs_remap is.
 */
static void funcs_remap(const uint8_t *par, uint64_t par_n,
			const struct kgenome_func_set *pf,
			const struct kgenome_endian_plan *plan, const uint8_t *view,
			uint64_t view_n, struct kgenome_func_set *out)
{
	struct kgenome_func *v;
	uint8_t *pat = NULL;
	uint64_t cursor = 0, found_end = 0, work, pat_cap = 0;
	uint32_t i, n = 0;
	enum kgenome_status st = KGENOME_OK;

	memset(out, 0, sizeof *out);
	if (!par || !view || !pf || !pf->n)
		return;
	v = malloc(pf->n * sizeof *v);
	if (!v) {
		out->status = KGENOME_NOMEM;
		return;
	}
	work = (uint64_t)REMAP_WORK * view_n + (1u << 20);
	for (i = 0; i < pf->n; i++) {
		const struct kgenome_func *f = &pf->v[i];
		uint64_t at, window;
		int found;

		if (f->off >= par_n || f->len > par_n - f->off)
			continue;
		window = (f->off > found_end ? f->off - found_end : 0u) + f->len;
		{
			uint64_t rest = view_n > cursor ? view_n - cursor : 0u;
			uint64_t charge = window < rest ? window : rest;   /* the search cannot run past the view */

			if (charge > work) {
				st = KGENOME_OVER_BUDGET;       /* the search is cut, and the set says so */
				break;
			}
			work -= charge;
		}
		{
			const uint8_t *want = par + f->off;

			if (plan && plan->n) {
				if (f->len > pat_cap) {
					uint8_t *g = realloc(pat, (size_t)f->len);

					if (!g) {
						st = kgenome_status_merge(st, KGENOME_NOMEM);
						break;
					}
					pat = g;
					pat_cap = f->len;
				}
				kgenome_endian_range(pat, par, par_n, f->off, f->len, plan);
				want = pat;
			}
			found = find_bytes(view, view_n, cursor, window, want, f->len, &at, &work);
			if (found < 0) {
				st = KGENOME_OVER_BUDGET;       /* the compares ran out of allowance: said, not dropped */
				break;
			}
			if (!found)
				continue;
		}
		v[n] = *f;
		v[n].off = at;
		n++;
		cursor = at + f->len;
		found_end = f->off + f->len;
	}
	free(pat);
	out->status = st;
	if (!n) {
		free(v);
		return;
	}
	out->v = v;
	out->n = n;
}

void kgenome_funcs_remap(const uint8_t *par, uint64_t par_n,
		     const struct kgenome_func_set *pf, const uint8_t *view,
		     uint64_t view_n, struct kgenome_func_set *out)
{
	funcs_remap(par, par_n, pf, NULL, view, view_n, out);
}

void kgenome_funcs_remap_endian(const uint8_t *par, uint64_t par_n,
			    const struct kgenome_func_set *pf,
			    const struct kgenome_endian_plan *plan, const uint8_t *view,
			    uint64_t view_n, struct kgenome_func_set *out)
{
	funcs_remap(par, par_n, pf, plan, view, view_n, out);
}


/* ---- the functions ------------------------------------------------------------ */

/*
 * The functions of an ELF - see funcs.h. Walks the table the symbol block is
 * built from, through the same reader, and keeps what is a sized FUNC in an
 * executable section.
 *
 * THE ADDRESS SPACE THE OBJECT IS READ IN. In a LINKED object st_value is the
 * virtual address and goes through the segments. In an ET_REL it is an offset
 * from the start of its section, which declares address zero, so the section's
 * place in the file is what names it. (The section's address used to be added in
 * BOTH cases, which put every function of a linked object at twice its address:
 * measured on a static Mirai, 419 declared starts and every one outside the code
 * range - see the history of the sweep that reads these.)
 */
static void kgenome_elf_funcs_build(kof_buf file, const struct kgenome_elf_info *e,
			 struct kgenome_func_set *out)
{
	struct kgenome_elf_symtab t;
	struct kgenome_func *v = NULL;
	uint32_t cap = 0, n = 0;
	uint64_t si;

	memset(out, 0, sizeof *out);
	if (!file.p || !e || !e->valid)
		return;
	if (!kgenome_elf_symtab_of(file, e, KGENOME_ELF_SYMTAB_FULL, &t))
		return;
	for (si = 1; si < t.n; si++) {
		struct kgenome_elf_symbol sy;
		const struct kgenome_elf_sec *sec;
		uint64_t off;

		if (!kgenome_elf_symbol_at(file, &t, si, &sy))
			break;
		if ((sy.info & 0xfu) != 2u || !sy.size)         /* sized STT_FUNC */
			continue;
		if (!sy.shndx || sy.shndx >= e->sec_count ||
		    sy.shndx >= KGENOME_ELF_MAX_SECTIONS)
			continue;
		sec = &e->sec[sy.shndx];
		if (!(sec->flags & KGENOME_ELF_SHF_EXEC))
			continue;
		/* By the object's type, not by whether this section has an
		 * address: a linked file's section at address zero would be read
		 * as relocatable. */
		if (e->e_type != KGENOME_ELF_REL) {
			if (!kgenome_elf_va_to_off(e, sy.value, sy.size, &off))
				continue;
		} else {
			if (sy.value > file.n || sec->file_off > file.n - sy.value)
				continue;
			off = sec->file_off + sy.value;
		}
		/* Both forms: the body lies inside the file. The segment table is
		 * the file's own claim and is not clipped by the parse. */
		if (off > file.n || sy.size > file.n - off)
			continue;
		if (n == cap) {
			/* KNOWN DEFECT REV-D8g (2026-10-25, Inference) [sev L]: the function table build (funcs.c) doubles a uint32
			 * capacity (functions) with no overflow guard and no ledger charge. Trigger: an object with 2^31 or more elements
			 * of this kind (input over 2 GiB; the engine caps an object at 512 MiB, so only a host using the lib directly).
			 * Reproducer: none (read). Fix: use kof_tab_grow (kofcore/tabgrow.h, guards the doubling) or test cap against
			 * UINT32_MAX / 2 before doubling. */
			uint32_t nc = cap ? cap * 2u : 256u;
			struct kgenome_func *nv = realloc(v, (size_t)nc * sizeof *nv);

			if (!nv) {
				out->status = KGENOME_NOMEM;
				free(v);
				return;
			}
			v = nv;
			cap = nc;
		}
		v[n].off = off;
		v[n].len = sy.size;
		v[n].value = sy.value;
		v[n].shndx = sy.shndx;
		n++;
	}
	kgenome_funcs_finish(v, n, out);
}

/*
 * THE FUNCTIONS OF AN ELF THAT KEPT NO SYMBOLS, from the entries the code has -
 * see kgenome_diag_walk_ensure, which finds them. Each entry inside an executable
 * segment starts a function that runs to the next entry or to the end of the
 * segment; the object's own entry point is one as well. No decoding here: this
 * only cuts the segments where the entries say.
 */
void kgenome_elf_funcs_from_entries(kof_buf file, const struct kgenome_elf_info *e,
				uint64_t entry_off, const uint64_t *ent,
				uint32_t n_ent, struct kgenome_func_set *out)
{
	struct kgenome_func *v;
	uint32_t i, n = 0;
	uint64_t *all;

	memset(out, 0, sizeof *out);
	if (!file.p || !e || !e->valid || !n_ent)
		return;
	all = malloc(((size_t)n_ent + 1u) * sizeof *all);
	v = malloc(((size_t)n_ent + 1u) * sizeof *v);
	if (!all || !v) {
		free(all);
		free(v);
		out->status = KGENOME_NOMEM;
		return;
	}
	memcpy(all, ent, (size_t)n_ent * sizeof *all);
	{
		uint32_t m = n_ent;

		if (entry_off < file.n) {
			uint32_t k;

			for (k = 0; k < m && all[k] != entry_off; k++)
				;
			if (k == m) {
				/* in order: the entries are sorted */
				for (k = m; k > 0 && all[k - 1u] > entry_off; k--)
					all[k] = all[k - 1u];
				all[k] = entry_off;
				m++;
			}
		}
		n_ent = m;
	}
	for (i = 0; i < n_ent; i++) {
		uint32_t s;
		uint64_t end = 0;

		for (s = 0; s < e->seg_count && s < KGENOME_ELF_MAX_SEGMENTS; s++) {
			const struct kgenome_elf_seg *g = &e->seg[s];

			if (kgenome_elf_seg_is_code(g) &&
			    g->file_off < file.n && all[i] >= g->file_off &&
			    all[i] - g->file_off < g->file_size) {
				uint64_t lim = g->file_off + g->file_size;

				end = lim < file.n ? lim : file.n;
				break;
			}
		}
		if (!end)
			continue;       /* not in code: an entry of nothing */
		if (i + 1u < n_ent && all[i + 1u] < end)
			end = all[i + 1u];
		if (end <= all[i])
			continue;
		v[n].off = all[i];
		v[n].len = end - all[i];
		v[n].value = 0;         /* recovered from the code: no symbol */
		v[n].shndx = 0;
		n++;
	}
	free(all);
	kgenome_funcs_finish(v, n, out);
}


/* ---- the functions ------------------------------------------------------------ */

#define PE_MACHINE_AMD64 0x8664u
#define UNW_FLAG_CHAININFO 0x4u

/*
 * The functions of an x64 PE - see funcs.h.
 *
 * Each RUNTIME_FUNCTION is three RVAs: where the function begins, where it ends,
 * and its unwind information. A chained entry (the unwind flags say so) is a
 * fragment of a function that has an entry of its own, so it is not listed; an
 * entry whose unwind address has the low bit set is an indirect one and is not
 * listed either. An entry that does not resolve to bytes of the file is
 * skipped, and the table is read as far as the file holds it.
 */
void kgenome_pe_funcs_build(kof_buf file, const struct kgenome_pe_info *p,
			struct kgenome_func_set *out)
{
	struct kgenome_func *v = NULL;
	uint32_t cap = 0, n = 0, i, n_ent;
	uint64_t tab;

	memset(out, 0, sizeof *out);
	if (!file.p || !p || !p->valid || p->machine != PE_MACHINE_AMD64 ||
	    !p->pe32_plus)
		return;
	if (!p->dir[KGENOME_PE_DIR_EXCEPTION].rva || !p->dir[KGENOME_PE_DIR_EXCEPTION].size)
		return;
	tab = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_EXCEPTION].rva);
	if (tab == KGENOME_BROKEN || tab >= file.n)
		return;
	/* As many entries as the directory declares and the file holds. */
	{
		uint64_t by_dir = p->dir[KGENOME_PE_DIR_EXCEPTION].size / 12u;
		uint64_t by_file = (file.n - tab) / 12u;

		n_ent = (uint32_t)(by_dir < by_file ? by_dir : by_file);
	}
	for (i = 0; i < n_ent; i++) {
		uint32_t b, e, u;
		uint64_t off, uo;
		uint8_t flags = 0;

		if (!kof_rd_u32(file, tab + (uint64_t)i * 12u, 0, &b) ||
		    !kof_rd_u32(file, tab + (uint64_t)i * 12u + 4u, 0, &e) ||
		    !kof_rd_u32(file, tab + (uint64_t)i * 12u + 8u, 0, &u))
			break;
		if (!b || e <= b || (u & 1u))
			continue;
		uo = kgenome_pe_rva_to_off(p, u);
		if (uo != KGENOME_BROKEN && uo < file.n)
			flags = (uint8_t)(file.p[uo] >> 3);
		if (flags & UNW_FLAG_CHAININFO)
			continue;
		off = kgenome_pe_rva_to_off(p, b);
		if (off == KGENOME_BROKEN || off >= file.n ||
		    (uint64_t)(e - b) > file.n - off)
			continue;
		if (n == cap) {
			/* KNOWN DEFECT REV-D8o (2026-10-25, Inference) [sev L]: the PE unwind-table function build (funcs.c) doubles a uint32 capacity (functions, bounded only by the exception directory: file size / 12)
			 * with no overflow guard and no ledger charge. Trigger: an exception directory of 2^31 or more entries (input over 24 GiB); the engine caps an object at 512 MiB,
			 * so only a host using the lib directly. Effect: the doubled capacity wraps to a smaller one and the table
			 * is overrun. Reproducer: none (read). Fix: use kof_tab_grow (kofcore/tabgrow.h) or test cap against
			 * UINT32_MAX / 2 before doubling. */
			uint32_t nc = cap ? cap * 2u : 256u;
			struct kgenome_func *nv = realloc(v, (size_t)nc * sizeof *nv);

			if (!nv) {
				out->status = KGENOME_NOMEM;
				free(v);
				return;
			}
			v = nv;
			cap = nc;
		}
		v[n].off = off;
		v[n].len = e - b;
		v[n].value = 0;         /* .pdata names nothing */
		v[n].shndx = 0;
		n++;
	}
	kgenome_funcs_finish(v, n, out);
}
