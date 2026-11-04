/*
 * funcs.c - the function extents of an object: the dispatch (kgenome_funcs_build),
 * the remap into a view, and the exact symbol-table strategy of the function table (fntab.h; .pdata is fntab_pe_pdata.c).
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
#include <kgenome_budget.h>   /* kgenome_grow_cap */
#include <genotype/image/elf_types.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "endian.h"
#include "elf_image.h"
#include "pe_image.h"
#include "fntab_private.h"



/*
 * THE FUNCTIONS, by the same decision. ELF only for now: a PE names its
 * functions through exports and the exception directory, and which of those is
 * the source is not settled - an empty set is what it answers until then.
 */
/* THE SYMBOL STRATEGIES ALONE (kgenome_fntab_symtab, kgenome_fntab_pdata), merged as every table is: the exact sources, which need no decode. The whole function table - the unwind data
 * (.eh_frame), .dynsym and the entry walk as well, chosen by the selector - is kgenome_diag_funcs_with_walk (phenotype/fntab_build.c), the one routine every consumer asks. */
void kgenome_funcs_build(uint32_t format, const uint8_t *data, uint64_t data_n,
		     const void *info, struct kgenome_func_set *out)
{
	struct kgenome_fntab_list l;

	memset(out, 0, sizeof *out);
	memset(&l, 0, sizeof l);
	if (!info)
		return;
	/* The SYMBOL strategies alone (the exact ones), merged as every table is. The whole table - the unwind data and the walk too - is
	 * kgenome_diag_funcs_with_walk (phenotype/fntab_build.c), which needs the decode this layer does not have. */
	if (format == KGENOME_FMT_ELF)
		kgenome_fntab_symtab(kof_buf_make(data, data_n), info, 0, &l);
	else if (format == KGENOME_FMT_PE)
		kgenome_fntab_pdata(kof_buf_make(data, data_n), info, &l);
	else
		return;
	kgenome_fntab_merge(&l, 0, out);
	kgenome_fntab_list_free(&l);
}

void kgenome_funcs_free(struct kgenome_func_set *s)
{
	if (!s)
		return;
	free(s->v);
	memset(s, 0, sizeof *s);
}

/* The index of the function that holds `off`: the first entry whose END is above it (the table's ends rise with its starts: the merge removes a
 * body that lies inside the body before it), when that entry starts at or below `off`. */
uint32_t kgenome_funcs_at(const struct kgenome_func_set *fs, uint64_t off)
{
	uint32_t lo, hi;

	if (!fs || !fs->n)
		return KGENOME_FUNCS_NONE;
	lo = 0;
	hi = fs->n;
	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (fs->v[mid].off + fs->v[mid].len <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < fs->n && fs->v[lo].off <= off ? lo : KGENOME_FUNCS_NONE;
}

uint32_t kgenome_funcs_start(const struct kgenome_func_set *fs, uint64_t off)
{
	uint32_t lo, hi;

	if (!fs || !fs->n)
		return KGENOME_FUNCS_NONE;
	lo = 0;
	hi = fs->n;
	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (fs->v[mid].off < off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < fs->n && fs->v[lo].off == off ? lo : KGENOME_FUNCS_NONE;
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
	out->ccase = pf->ccase;         /* the view's table is the parent's: it says what the parent's says */
	out->state = pf->state;
	out->partial = pf->partial;
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
/* THE SYMBOL-TABLE STRATEGY of the function table (fntab.h): the exact one, start and end from st_size. The loop is the one this file always had; what
 * the table of cases added to it is IFUNC, NOTYPE-with-size and size-0 symbols (CN-3), the Thumb bit (CN-2), and the choice of .symtab or .dynsym. */
#define EM_ARM_ 40u
#define STT_NOTYPE_ 0u
#define STT_FUNC_ 2u
#define STT_GNU_IFUNC_ 10u

static int offcmp(const void *a, const void *b)
{
	const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

void kgenome_fntab_symtab(kof_buf file, const struct kgenome_elf_info *e, int dyn, struct kgenome_fntab_list *out)
{
	struct kgenome_elf_symtab t;
	uint64_t si;
	const uint32_t first = out->n;
	uint32_t i, n_zero = 0;
	const uint8_t src = dyn ? KGENOME_FN_S_DYNSYM : KGENOME_FN_S_SYMTAB;

	if (!file.p || !e || !e->valid)
		return;
	if (!kgenome_elf_symtab_of(file, e, dyn ? KGENOME_ELF_SYMTAB_DYN : KGENOME_ELF_SYMTAB_FULL, &t))
		return;
	for (si = 1; si < t.n; si++) {
		struct kgenome_elf_symbol sy;
		const struct kgenome_elf_sec *sec;
		struct kgenome_func f;
		uint64_t off, value;
		if (!kgenome_elf_symbol_at(file, &t, si, &sy))
			break;
		/* WHAT IS A FUNCTION HERE (CN-3, fixed): STT_FUNC, STT_GNU_IFUNC (a resolver: its body is code), and a NOTYPE symbol that declares a size
		 * (an assembly label with .size). A FUNC or IFUNC that declares no size names a place and no body: it is listed with the flag SIZE0 and its
		 * end is the next symbol or the end of its section (below), never an exact end. */
		{
			const unsigned ty = sy.info & 0xfu;
			const int is_func = ty == STT_FUNC_ || ty == STT_GNU_IFUNC_ || (ty == STT_NOTYPE_ && sy.size);

			if (!is_func)
				continue;
			memset(&f, 0, sizeof f);
			f.kind = ty == STT_GNU_IFUNC_ ? KGENOME_FN_IFUNC : KGENOME_FN_FUNC;
		}
		if (!sy.shndx || sy.shndx >= e->sec_count ||
		    sy.shndx >= KGENOME_ELF_MAX_SECTIONS)
			continue;
		sec = &e->sec[sy.shndx];
		/* KNOWN DEFECT ELF-SEC-EXEC-CODE (2026-11-05, M) [sev M]: gates on the SECTION flag SHF_EXECINSTR
		 * alone, never cross-checked against diag_code.c's own authoritative segment-level definition of
		 * ELF code (PT_LOAD && PF_X). Trigger: a crafted ELF with a FUNC symbol in a SHF_EXECINSTR section
		 * whose VA falls outside any executable PT_LOAD segment. Effect: bytes outside real code get
		 * decoded, CFG-signed and mutation-hashed as a function - the same signature-poisoning class as
		 * PE-RSRC-EXEC-CODE. Fix: cross-check sec's VA against the segment-level code definition here. */
		if (!(sec->flags & KGENOME_ELF_SHF_EXEC))
			continue;
		value = sy.value;
		/* THUMB (CN-2, fixed): an ARM function symbol has bit 0 set when it is Thumb code; the address is the even one and the mode is a field. */
		if (e->e_machine == EM_ARM_ && (sy.info & 0xfu) == STT_FUNC_ && (value & 1u)) {
			value &= ~(uint64_t)1u;
			f.isa_mode = KGENOME_FN_ISA_THUMB;
		}
		/* By the object's type, not by whether this section has an
		 * address: a linked file's section at address zero would be read
		 * as relocatable. */
		if (e->e_type != KGENOME_ELF_REL) {
			if (!kgenome_elf_va_to_off(e, value, sy.size ? sy.size : 1u, &off))
				continue;
		} else {
			if (value > file.n || sec->file_off > file.n - value)
				continue;
			off = sec->file_off + value;
		}
		/* Both forms: the body lies inside the file. The segment table is
		 * the file's own claim and is not clipped by the parse. */
		if (off > file.n || sy.size > file.n - off)
			continue;
		f.off = off;
		f.len = sy.size;
		f.value = sy.value;
		f.shndx = sy.shndx;
		f.source = src;
		if (sy.size) {
			f.end_source = KGENOME_FN_E_SYMBOL;
		} else {
			f.flags = KGENOME_FN_F_SIZE0;
			n_zero++;
		}
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
	if (!n_zero)
		return;
	/* The end of a symbol that declares none: the next symbol of this table above it, or the end of its section, whichever is first. */
	{
		const uint32_t cnt = out->n - first;
		uint64_t *offs = malloc((size_t)cnt * sizeof *offs);

		if (!offs) {
			out->status = KGENOME_NOMEM;
			return;
		}
		for (i = 0; i < cnt; i++)
			offs[i] = out->v[first + i].off;
		qsort(offs, cnt, sizeof *offs, offcmp);
		for (i = first; i < out->n; i++) {
			struct kgenome_func *f = &out->v[i];
			uint64_t end, lo = 0, hi = cnt;
			const struct kgenome_elf_sec *sec = &e->sec[f->shndx];

			if (!(f->flags & KGENOME_FN_F_SIZE0))
				continue;
			while (lo < hi) {               /* the first start above f->off */
				uint64_t mid = (lo + hi) / 2u;

				if (offs[mid] <= f->off)
					lo = mid + 1u;
				else
					hi = mid;
			}
			end = sec->file_off + sec->file_size;
			if (lo < cnt && offs[lo] < end)
				end = offs[lo];
			if (end > file.n)
				end = file.n;
			f->len = end > f->off ? end - f->off : 0;
			f->end_source = KGENOME_FN_E_NEXT_START;
			f->flags |= KGENOME_FN_F_END_OPEN;
		}
		free(offs);
	}
}

/* The PE strategy (.pdata) and kgenome_pe_funcs_build, its wrapper, are fntab_pe_pdata.c: one file a case. */
