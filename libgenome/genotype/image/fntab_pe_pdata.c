/*
 * fntab_pe_pdata.c - the exception-table strategy of the PE function table: the RUNTIME_FUNCTION entries of an x64 image (.pdata).
 *
 * THE FORMAT, as far as this reads it. An entry is three RVAs: BeginAddress, EndAddress, UnwindData. The unwind info is `u8 version:3 | flags:5`, `u8 prolog size`,
 * `u8 count of unwind codes`, `u8 frame register:4 | offset:4`, the codes (2 bytes each, the count rounded up to even), and then - when the flag UNW_FLAG_CHAININFO is set - the
 * RUNTIME_FUNCTION of the PARENT. A chained entry is not a function: it describes a further part of the parent's body (the cold half of a function the compiler split), so the
 * parent keeps its own entry and extent and the chained one is made a FRAGMENT (kind): a mask for the merge, which stops the walk from starting a function inside it, and which
 * the merge does not keep (set->n_extra). `value` of a fragment is the parent's start (file offset). A function the format cannot hold an entry for - a LEAF, which needs no unwind
 * data - is not here: the walk, the exports and the GAPS step name it.
 *
 * WHAT IT IS EXACT FOR: START and END of every non-leaf function, by construction of the format. NOT exact: an entry's EndAddress is the end of the part the entry describes; the
 * function it belongs to has further parts only through a chained entry.
 *
 * HOSTILE INPUT, each counted and none followed: the entry count is the directory's size over 12 bounded by the file (a loop of at most that many reads, and the list's own cap
 * KGENOME_FNTAB_MAX: said by P_CAP); an entry with Begin 0 and End 0 is the table's zero fill and is skipped silently; End <= Begin, a Begin outside every executable section, an unwind
 * info that lies outside the file, whose version is not 1 or 2, whose flags hold a bit the format does not define, whose chained parent lies outside the file, are REFUSED and counted
 * (out->n_bad, P_BAD_FDE); an End past the raw bytes of its section is CLIPPED to them (flag CLIPPED); an unwind address with its low bit set is an indirection the format defines and
 * this does not follow (its info is not read; the entry's own Begin and End stand, PDATA-1). Overlapping entries are the merge's: both stand and the overlap is recorded as disagreement. The chain is never followed, so a
 * chain loop costs nothing.
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

#define PE_MACHINE_AMD64 0x8664u
#define UNW_FLAG_CHAININFO 0x4u
#define UNW_FLAG_DEFINED 0x7u

/*
 * THE CHAINED PARTS JOIN THEIR FUNCTION (PF-1, 2026-11-15). A chained entry is a further part of its parent's body; when it begins exactly where the
 * function (with the parts joined so far) ends, the function's extent runs on over it - one function, one [off, len). Measured: every chained entry of
 * sacsvr / whs32 / whs32res / DirectDBres (the APT x64 DLLs of fix_aptgap, 818 entries in 349 functions) and of pe120 (8941 in 4369) starts where an earlier
 * entry ends; the parent ended at its first part, and the parts were in no function (ServiceMain of sacsvr.dll: RVA 0x2400 len 0x53 of 0x14f, its Sleep
 * and SetServiceStatus calls in no function). A part joins the function its chain ROOTS at (`value`: the root's start, the chain followed in
 * kgenome_fntab_pdata).
 * A part that is not contiguous (a cold part far from its function) stays a FRAGMENT: a function of the table has one range (next: ranges per function).
 * The fragments stay in the list as masks either way. `from`: the first entry this call added.
 */
static int cmp_off(const void *a, const void *b)
{
	const struct kgenome_func *x = *(const struct kgenome_func *const *)a, *y = *(const struct kgenome_func *const *)b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static void pdata_join(struct kgenome_fntab_list *out, uint32_t from)
{
	struct kgenome_func **fr;
	uint32_t n = 0, i;

	for (i = from; i < out->n; i++)
		n += out->v[i].kind == KGENOME_FN_FRAGMENT;
	if (!n || !(fr = malloc((size_t)n * sizeof *fr)))
		return;                 /* no fragment, or no memory: the parts stay masks (the old answer) */
	n = 0;
	for (i = from; i < out->n; i++)
		if (out->v[i].kind == KGENOME_FN_FRAGMENT)
			fr[n++] = &out->v[i];
	qsort(fr, n, sizeof *fr, cmp_off);
	/*
	 * THE ROOT THROUGH THE TABLE (audit AUD-11, 2026-11-16, M): the read in kgenome_fntab_pdata follows a chain at most 8 parts deep, and a part deeper than
	 * that kept a `value` that is another PART's start: it joined nothing and the function stopped short, unsaid. A part whose value is the start of
	 * another fragment of this table takes that fragment's root, resolved once per fragment (a path is walked and every fragment on it given the root:
	 * linear in the fragments; a loop of parts names no function and keeps its value).
	 */
	{
		uint32_t *path = malloc((size_t)n * sizeof *path);
		uint8_t *state = calloc(n, 1);          /* 0 not seen, 1 on the path in hand, 2 resolved */

		if (path && state)
			for (i = 0; i < n; i++) {
				uint32_t np = 0, j = i, q;
				uint64_t root = 0;
				int loop = 0;

				for (;;) {
					uint32_t lo = 0, hi = n;

					if (state[j] == 2) {
						root = fr[j]->value;
						break;
					}
					if (state[j] == 1) {
						loop = 1;
						break;
					}
					state[j] = 1;
					path[np++] = j;
					while (lo < hi) {
						const uint32_t mid = lo + (hi - lo) / 2u;

						if (fr[mid]->off < fr[j]->value)
							lo = mid + 1u;
						else
							hi = mid;
					}
					if (lo == n || fr[lo]->off != fr[j]->value) {
						root = fr[j]->value;    /* the value is no fragment: the function's start */
						break;
					}
					j = lo;
				}
				for (q = 0; q < np; q++) {
					if (!loop)
						fr[path[q]]->value = root;
					state[path[q]] = 2;
				}
			}
		free(path);
		free(state);
	}
	for (i = from; i < out->n; i++) {
		struct kgenome_func *f = &out->v[i];

		if (f->kind == KGENOME_FN_FRAGMENT || !f->len)
			continue;
		for (;;) {
			const uint64_t end = f->off + f->len;
			uint32_t lo = 0, hi = n;

			while (lo < hi) {
				const uint32_t mid = lo + (hi - lo) / 2u;

				if (fr[mid]->off < end)
					lo = mid + 1u;
				else
					hi = mid;
			}
			if (lo == n || fr[lo]->off != end || fr[lo]->value != f->off)
				break;
			f->len += fr[lo]->len;
		}
	}
	free(fr);
}

void kgenome_fntab_pdata(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	uint64_t tab, n_ent, i;
	const uint32_t from = out ? out->n : 0u;

	if (!file.p || !p || !p->valid || p->machine != PE_MACHINE_AMD64 || !p->pe32_plus)
		return;
	if (!p->dir[KGENOME_PE_DIR_EXCEPTION].rva || !p->dir[KGENOME_PE_DIR_EXCEPTION].size)
		return;
	tab = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_EXCEPTION].rva);
	if (tab == KGENOME_BROKEN || tab >= file.n)
		return;
	/* As many entries as the directory declares and the file holds. */
	n_ent = p->dir[KGENOME_PE_DIR_EXCEPTION].size / 12u;
	if (n_ent > (file.n - tab) / 12u)
		n_ent = (file.n - tab) / 12u;
	for (i = 0; i < n_ent; i++) {
		uint32_t b, e, u;
		uint64_t off, send, uo, uend, len;
		uint8_t hdr, flags, ncodes;
		struct kgenome_func f;

		if (!kof_rd_u32(file, tab + i * 12u, 0, &b) || !kof_rd_u32(file, tab + i * 12u + 4u, 0, &e) ||
		    !kof_rd_u32(file, tab + i * 12u + 8u, 0, &u))
			break;
		if (!b && !e)
			continue;                       /* the zero fill of the table */
		if (e <= b || !kgenome_fntab_pe_code_rva(p, file, b, &off, &send)) {
			out->n_bad++;
			out->partial |= KGENOME_FNTAB_P_BAD_FDE;
			continue;
		}
		if (u & 1u) {
			/* UnwindData with its low bit set is an indirection to another entry's unwind info, which this does not follow: the unwind info is not read and the entry is
			 * not validated by it. What the entry says about the function (BeginAddress, EndAddress) does not depend on how the unwinder finds its info, so the body stands
			 * (PDATA-1, fixed: the entry's own Begin/End are kept, not dropped). We cannot know whether the unread unwind info would have UNW_FLAG_CHAININFO set, so an
			 * indirected entry is always kept as a plain function, never a FRAGMENT of a chained one - a narrow, untracked case if that combination occurs. */
			hdr = 0;
			flags = 0;
			ncodes = 0;
			uo = 0;
		} else {
			uo = kgenome_pe_rva_to_off(p, u);
			if (uo == KGENOME_BROKEN || uo >= file.n || file.n - uo < 4u) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
			hdr = file.p[uo];
			flags = (uint8_t)(hdr >> 3);
			ncodes = file.p[uo + 2u];
			if ((hdr & 7u) < 1u || (hdr & 7u) > 2u || (flags & ~UNW_FLAG_DEFINED)) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
		}
		memset(&f, 0, sizeof f);
		f.source = KGENOME_FN_S_PDATA;
		f.end_source = KGENOME_FN_E_UNWIND;     /* .pdata names nothing: value 0, shndx 0 */
		f.off = off;
		len = (uint64_t)e - b;
		if (len > send - off) {
			len = send - off;
			f.flags |= KGENOME_FN_F_CLIPPED;
		}
		f.len = len;
		if (flags & UNW_FLAG_CHAININFO) {
			/* the parent's RUNTIME_FUNCTION follows the codes: read as far as the file holds it, and its start must be code too */
			uint32_t pb;
			uint64_t poff, pend;

			uend = uo + 4u + (uint64_t)((ncodes + 1u) & ~1u) * 2u;
			if (!kof_rd_u32(file, uend, 0, &pb)) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
			f.kind = KGENOME_FN_FRAGMENT;
			/* A parent whose start the file holds no byte of (a section with no raw data: measured on pe120, 20 parts in 142_046, 143_190, 191_287,
			 * 199_243, audit round 3) names no function of the table: the part is kept with an unplaceable root (KGENOME_BROKEN), so the build counts
			 * it in set->n_rng_orphan and its bytes become undeclared code - never refused in silence. */
			if (!kgenome_fntab_pe_code_rva(p, file, pb, &poff, &pend)) {
				uint32_t k;
				int mapped = 0;

				/* only a parent in a code section that the file holds no byte of is an orphan; a parent RVA in no section is a bad record (refused) */
				for (k = 0; k < p->nsec && k < KGENOME_PE_MAX_SECTIONS; k++)
					if (kgenome_pe_sec_is_code(p, &p->sec[k]) && pb >= p->sec[k].mem_rva && pb - p->sec[k].mem_rva < p->sec[k].mem_size &&
					    pb - p->sec[k].mem_rva >= p->sec[k].file_size)
						mapped = 1;
				if (!mapped) {
					out->n_bad++;
					out->partial |= KGENOME_FNTAB_P_BAD_FDE;
					continue;
				}
				f.value = KGENOME_BROKEN;
				if (!kgenome_fntab_list_add(out, &f))
					return;
				continue;
			}
			f.value = poff;
			/* THE ROOT of the chain: a parent may itself be a chained part (MSVC: [48ea,4984) of whs32res.dll names [4984,4989), a part that
			 * names [48a0,48bf), the function), so its own unwind info is read and its parent taken, up to 8 parts, while the record is in the
			 * file; `value` is the function's start, which is what pdata_join asks */
			{
				uint32_t pu, hop;

				for (hop = 0; hop < 8u && kof_rd_u32(file, uend + 8u, 0, &pu); hop++) {
					const uint64_t puo = kgenome_pe_rva_to_off(p, pu);
					uint32_t qb;
					uint64_t qoff, qend;

					if (puo == KGENOME_BROKEN || puo + 4u > file.n || !((file.p[puo] >> 3) & UNW_FLAG_CHAININFO))
						break;
					uend = puo + 4u + (uint64_t)((file.p[puo + 2u] + 1u) & ~1u) * 2u;
					if (!kof_rd_u32(file, uend, 0, &qb) || !kgenome_fntab_pe_code_rva(p, file, qb, &qoff, &qend))
						break;
					f.value = qoff;
				}
			}
		}
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
	pdata_join(out, from);
}

void kgenome_pe_funcs_build(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_func_set *out)
{
	struct kgenome_fntab_list l;

	memset(out, 0, sizeof *out);
	memset(&l, 0, sizeof l);
	kgenome_fntab_pdata(file, p, &l);
	kgenome_fntab_merge(&l, 0, out);
	kgenome_fntab_list_free(&l);
}
