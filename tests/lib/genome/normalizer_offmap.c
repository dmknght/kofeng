/*
 * normalizer_offmap - the pure-genome half of the normalised view: the boundary
 * table (kgenome_offmap), the visitor that lists a description's file offsets,
 * and the functions of a view (kgenome_funcs_remap).
 *
 * A DERIVED OBJECT CARRIES THE PARENT'S DESCRIPTION, so everything that moves it
 * has to agree with the transform that moved the bytes. The engine side of that
 * is tests/unit/normalizer_engine.c; what is here needs no engine.
 *
 *   offmap_at      against a brute-force reading of its contract on random tables
 *                  (monotone, with ties, with offsets past 2^32 and near 2^63),
 *                  and against a real zero-collapse: with a mark at every offset
 *                  the table IS the transform, and with marks only at the places a
 *                  description names, those places - and every offset between two
 *                  marks that lie in a copied stretch - come out exactly
 *   visitor        which fields of kgenome_pe_info and kgenome_elf_info are file
 *                  offsets - checked by offsetof, both what must be visited and
 *                  what must not (an RVA, an address, a size of the loaded image)
 *   remap          a description carried through a collapse keeps every extent's
 *                  meaning: new length = distance between the two new ends
 *   funcs_remap    functions found again in a view that moved and shortened them:
 *                  the intact ones at exactly the offset the construction put them,
 *                  the ones a collapse rewrote and the ones a library cut took out
 *                  absent, order kept, fields kept, hostile extents skipped, the
 *                  work bound reported as a status and not as silence
 *
 * Every object is built in memory, here, from named bytes.
 */

#include <stddef.h>
#include <kgenome.h>
#include <genotype/image/funcs.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_rng rng = { 0x2545f4914f6cdd1dull };

/* ---- offmap_at, against its contract written out the long way ----------------------- */

/* "The offset in the result for an offset in the original. One of `from` answers
 * exactly; one between two answers the nearer lower mark plus the distance, held
 * below the next mark; past the end answers to_end." Linear, with no search. */
static uint64_t ref_at(const struct kgenome_offmap *m, uint64_t off)
{
	uint32_t i, last = 0;
	int found = 0;
	uint64_t r;

	if (!m || !m->n)
		return off;
	if (off >= m->from_end)
		return m->to_end;
	for (i = 0; i < m->n; i++)
		if (m->from[i] <= off) {
			last = i;
			found = 1;
		}
	if (!found)
		return off < m->to[0] ? off : m->to[0];
	r = m->to[last] + (off - m->from[last]);
	if (last + 1u < m->n && r > m->to[last + 1u])
		r = m->to[last + 1u];
	if (r > m->to_end)
		r = m->to_end;
	return r;
}

static void offmap_differential(void)
{
	unsigned round;

	for (round = 0; round < 600; round++) {
		uint64_t f[40], t[40], a = hk_below(&rng, 4) ? 0 : (1ull << 32) - 30u, b = a;
		uint32_t n = 1 + hk_below(&rng, 40), i;
		struct kgenome_offmap m;
		uint64_t probes[64], off;
		unsigned k;

		if (round % 7u == 3u) {
			a = 1ull << 62;                 /* far past 32 bits, far from 2^64 */
			b = a - hk_below(&rng, 1000);
		}
		for (i = 0; i < n; i++) {
			a += 1 + hk_below(&rng, 40);
			b += hk_below(&rng, 40);
			if (hk_below(&rng, 5) == 0)
				b -= b > 3 ? 3 : 0;
			f[i] = a;
			t[i] = b < a ? b : a - 1u;      /* a view never puts a place later */
		}
		m.from = f;
		m.to = t;
		m.n = n;
		m.from_end = a + 25u;
		m.to_end = (b < a ? b : a) + hk_below(&rng, 25);
		/* every offset around every mark, and a spread of others */
		for (k = 0; k < 64u; k++)
			probes[k] = k < 3u ? k * 7u : f[hk_below(&rng, n)] + hk_below(&rng, 5) - 2u;
		for (k = 0; k < 64u; k++) {
			off = probes[k];
			CK(kgenome_offmap_at(&m, off) == ref_at(&m, off));
		}
		CK(kgenome_offmap_at(&m, m.from_end) == m.to_end);
		CK(kgenome_offmap_at(&m, m.from_end - 1u) == ref_at(&m, m.from_end - 1u));
		CK(kgenome_offmap_at(&m, UINT64_MAX) == m.to_end);
	}
}

/*
 * THE TABLE IS THE TRANSFORM. A zero run of eight or more becomes two zeros; a
 * mark at every offset makes the table answer, for every offset, what the
 * transform does with it: the run's first byte maps to where the run begins in the
 * output, a byte inside it to the position just past what it became.
 */
static uint64_t collapse(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t *map /* n + 1 */)
{
	uint64_t i = 0, o = 0;

	while (i < n) {
		uint64_t k = 0;

		while (i + k < n && !in[i + k])
			k++;
		if (k >= 8u) {
			uint64_t j;

			for (j = 0; j < k; j++)
				map[i + j] = j ? o + 2u : o;
			out[o++] = 0;
			out[o++] = 0;
			i += k;
		} else {
			map[i] = o;
			out[o++] = in[i++];
		}
	}
	map[n] = o;
	return o;
}

static void table_is_the_transform(void)
{
	unsigned round;

	for (round = 0; round < 300; round++) {
		uint8_t in[600], out[600];
		uint64_t map[601], f[601], t[601], n = 50 + hk_below(&rng, 500), i, o;
		struct kgenome_offmap m;

		for (i = 0; i < n; i++)
			in[i] = hk_below(&rng, 3) ? (uint8_t)(1 + hk_below(&rng, 255)) : 0;
		for (i = 0; i < n; i++)
			if (hk_below(&rng, 20) == 0) {
				uint64_t k, l = hk_below(&rng, 30);

				for (k = 0; k < l && i + k < n; k++)
					in[i + k] = 0;
			}
		o = collapse(in, n, out, map);
		for (i = 0; i < n; i++) {
			f[i] = i;
			t[i] = map[i];
		}
		m.from = f; m.to = t; m.n = (uint32_t)n; m.from_end = n; m.to_end = o;
		for (i = 0; i <= n; i++)
			CK(kgenome_offmap_at(&m, i) == map[i]);
		/* sparse marks: the marked places and the stretches of plain copy between
		 * two marks come out exactly */
		{
			uint64_t sf[40], st[40], ns = 0, prev = 0;

			for (i = 0; i < n && ns < 40u; i += 1 + hk_below(&rng, 30)) {
				sf[ns] = i;
				st[ns] = map[i];
				ns++;
			}
			m.from = sf; m.to = st; m.n = (uint32_t)ns;
			for (i = 0; i < ns; i++)
				CK(kgenome_offmap_at(&m, sf[i]) == st[i]);
			for (i = 0; i + 1u < ns; i++) {
				uint64_t x, plain = 1;

				for (x = sf[i]; x < sf[i + 1u]; x++)
					plain &= map[x + 1u] == map[x] + 1u;
				if (plain && prev == 0)
					for (x = sf[i]; x < sf[i + 1u]; x++)
						CK(kgenome_offmap_at(&m, x) == map[x]);
			}
			CK(kgenome_offmap_at(&m, n) == o);
			CK(kgenome_offmap_at(&m, n + 1u) == o);
		}
	}
}

/* ---- the visitor: which fields are file offsets ---------------------------------------- */

struct seen {
	size_t   at[512];
	int      ext[512];
	unsigned n;
	const uint8_t *base;
};

static void collect(void *u, uint64_t *off, uint64_t *len)
{
	struct seen *s = u;

	if (s->n < 512u) {
		s->at[s->n] = (size_t)((const uint8_t *)off - s->base);
		s->ext[s->n] = len != NULL;
		s->n++;
	}
}

static int visited(const struct seen *s, size_t off, int ext)
{
	unsigned i;

	for (i = 0; i < s->n; i++)
		if (s->at[i] == off && s->ext[i] == ext)
			return 1;
	return 0;
}

static int visited_any(const struct seen *s, size_t off)
{
	return visited(s, off, 0) || visited(s, off, 1);
}

static void visitor_fields(void)
{
	static struct kgenome_pe_info pi;
	static struct kgenome_elf_info ei;
	struct seen s;
	unsigned i;

	memset(&pi, 0, sizeof pi);
	memset(&s, 0, sizeof s);
	s.base = (const uint8_t *)&pi;
	pi.sec_count = 3;
	kgenome_pe_info_offsets(&pi, collect, &s);
	/* the three positions and the extents the header documents */
	CK(visited(&s, offsetof(struct kgenome_pe_info, lfanew), 0));
	CK(visited(&s, offsetof(struct kgenome_pe_info, header_end), 0));
	CK(visited(&s, offsetof(struct kgenome_pe_info, size_of_headers), 0));
	CK(visited(&s, offsetof(struct kgenome_pe_info, cert_off), 1));
	CK(visited(&s, offsetof(struct kgenome_pe_info, overlay_off), 1));
	CK(visited(&s, offsetof(struct kgenome_pe_info, res_off), 1));
	CK(visited(&s, offsetof(struct kgenome_pe_info, clr_off), 1));
	CK(visited(&s, offsetof(struct kgenome_pe_info, dir) +
		   KGENOME_PE_DIR_SECURITY * sizeof pi.dir[0], 1));
	for (i = 0; i < 3u; i++) {
		CK(visited(&s, offsetof(struct kgenome_pe_info, sec) + i * sizeof pi.sec[0] +
			   offsetof(struct kgenome_pe_sec, file_off), 1));
		CK(visited(&s, offsetof(struct kgenome_pe_info, sec) + i * sizeof pi.sec[0] +
			   offsetof(struct kgenome_pe_sec, claim_off), 1));
		/* an RVA and a virtual size are not places in the file */
		CK(!visited_any(&s, offsetof(struct kgenome_pe_info, sec) + i * sizeof pi.sec[0] +
				offsetof(struct kgenome_pe_sec, mem_rva)));
	}
	/* a section beyond sec_count is not visited */
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, sec) + 3u * sizeof pi.sec[0] +
			offsetof(struct kgenome_pe_sec, file_off)));
	/* none of the loaded-image numbers */
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, entry_rva)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, image_base)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, size_of_image)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, section_align)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, file_align)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, base_of_code)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, size_of_code)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, stub_len)));
	CK(!visited_any(&s, offsetof(struct kgenome_pe_info, dir) + sizeof pi.dir[0]));  /* export dir: an RVA */

	memset(&ei, 0, sizeof ei);
	memset(&s, 0, sizeof s);
	s.base = (const uint8_t *)&ei;
	ei.seg_count = 2;
	ei.sec_count = 3;
	kgenome_elf_info_offsets(&ei, collect, &s);
	CK(visited(&s, offsetof(struct kgenome_elf_info, phoff), 0));
	CK(visited(&s, offsetof(struct kgenome_elf_info, shoff), 0));
	CK(visited(&s, offsetof(struct kgenome_elf_info, hdr_claim_off), 1));
	CK(visited(&s, offsetof(struct kgenome_elf_info, shtab_claim_off), 1));
	for (i = 0; i < 2u; i++) {
		CK(visited(&s, offsetof(struct kgenome_elf_info, seg) + i * sizeof ei.seg[0] +
			   offsetof(struct kgenome_elf_seg, file_off), 1));
		CK(visited(&s, offsetof(struct kgenome_elf_info, seg) + i * sizeof ei.seg[0] +
			   offsetof(struct kgenome_elf_seg, claim_off), 1));
	}
	for (i = 0; i < 3u; i++) {
		CK(visited(&s, offsetof(struct kgenome_elf_info, sec) + i * sizeof ei.sec[0] +
			   offsetof(struct kgenome_elf_sec, file_off), 1));
		CK(visited(&s, offsetof(struct kgenome_elf_info, sec) + i * sizeof ei.sec[0] +
			   offsetof(struct kgenome_elf_sec, claim_off), 1));
	}
	CK(!visited_any(&s, offsetof(struct kgenome_elf_info, entry_addr)));
	CK(!visited_any(&s, offsetof(struct kgenome_elf_info, seg) + offsetof(struct kgenome_elf_seg, mem_addr)));
	/* a count past the table is clamped by the visitor, not trusted */
	memset(&s, 0, sizeof s);
	s.base = (const uint8_t *)&ei;
	ei.seg_count = 0xffffffffu;
	ei.sec_count = 0xffffffffu;
	kgenome_elf_info_offsets(&ei, collect, &s);
	CK(s.n <= 4u + 2u * KGENOME_ELF_MAX_SEGMENTS + 2u * KGENOME_ELF_MAX_SECTIONS);
	memset(&s, 0, sizeof s);
	s.base = (const uint8_t *)&pi;
	pi.sec_count = 0xffffffffu;
	kgenome_pe_info_offsets(&pi, collect, &s);
	CK(s.n <= 100u + 2u * KGENOME_PE_MAX_SECTIONS);
}

/* ---- remap through a real collapse ------------------------------------------------------- */

static void remap_through_a_collapse(void)
{
	static struct hk_pe P;
	static struct hk_elf E;
	static struct kgenome_pe_info pi, pi2;
	static struct kgenome_elf_info ei, ei2;
	struct kgenome_obj o;
	unsigned round;

	hk_pe(&P, 1);
	memset(&pi, 0, sizeof pi);
	memset(&o, 0, sizeof o);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	hk_elf(&E, 1, 0, 0);
	memset(&ei, 0, sizeof ei);
	memset(&o, 0, sizeof o);
	CK(kgenome_elf_image_parse(kof_buf_make(E.b, E.n), &ei, &o));
	for (round = 0; round < 300; round++) {
		uint64_t f[8], t[8], a = 0, b = 0;
		uint32_t n = 1 + hk_below(&rng, 8), i;
		struct kgenome_offmap m;

		for (i = 0; i < n; i++) {
			a += 1 + hk_below(&rng, 0x100);
			b += hk_below(&rng, 0x100);
			f[i] = a;
			t[i] = b < a ? b : a;
		}
		m.from = f; m.to = t; m.n = n;
		m.from_end = P.n; m.to_end = P.n > 0x40 ? P.n - hk_below(&rng, 0x40) : P.n;
		if (m.to_end < t[n - 1u])
			m.to_end = t[n - 1u];
		pi2 = pi;
		kgenome_pe_info_remap(&pi2, &m);
		CK(pi2.lfanew == kgenome_offmap_at(&m, pi.lfanew));
		for (i = 0; i < pi.sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
			uint64_t o0 = kgenome_offmap_at(&m, pi.sec[i].file_off);
			uint64_t end = pi.sec[i].file_size > m.from_end - (pi.sec[i].file_off < m.from_end ?
					pi.sec[i].file_off : m.from_end) ? m.from_end :
					pi.sec[i].file_off + pi.sec[i].file_size;
			uint64_t o1 = kgenome_offmap_at(&m, end);

			CK(pi2.sec[i].file_off == o0);
			CK(pi2.sec[i].file_size == (o1 > o0 ? o1 - o0 : 0u));
			CK(pi2.sec[i].mem_rva == pi.sec[i].mem_rva);
		}
		CK(pi2.entry_rva == pi.entry_rva && pi2.image_base == pi.image_base);
		m.from_end = E.n;
		m.to_end = E.n > 0x40 ? E.n - hk_below(&rng, 0x40) : E.n;
		if (m.to_end < t[n - 1u])
			m.to_end = t[n - 1u];
		ei2 = ei;
		kgenome_elf_info_remap(&ei2, &m);
		CK(ei2.phoff == kgenome_offmap_at(&m, ei.phoff));
		CK(ei2.shoff == kgenome_offmap_at(&m, ei.shoff));
		CK(ei2.entry_addr == ei.entry_addr);
		for (i = 0; i < ei.seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			CK(ei2.seg[i].file_off == kgenome_offmap_at(&m, ei.seg[i].file_off) &&
			   ei2.seg[i].mem_addr == ei.seg[i].mem_addr);
	}
	/* a length the parse got wrong (past the end, or so large the sum wraps) does
	 * not wrap below the offset: the extent ends at the end of the view */
	{
		uint64_t f[1] = { 0 }, t[1] = { 0 };
		struct kgenome_offmap m = { f, t, 1, 0x1000, 0x800 };

		ei2 = ei;
		ei2.hdr_claim_off = 0x10;
		ei2.hdr_claim_len = UINT64_MAX - 5u;
		kgenome_elf_info_remap(&ei2, &m);
		CK(ei2.hdr_claim_off == 0x10 && ei2.hdr_claim_len == 0x800u - 0x10u);
		ei2 = ei;
		ei2.hdr_claim_off = 0x2000;                 /* past the end: nothing left of it */
		ei2.hdr_claim_len = 0x10;
		kgenome_elf_info_remap(&ei2, &m);
		CK(ei2.hdr_claim_off == 0x800u && ei2.hdr_claim_len == 0);
	}
}

/* ---- the functions of a view ---------------------------------------------------------------- */

#define NF 60u

struct built {
	uint8_t par[16384], view[16384];
	uint64_t par_n, view_n;
	struct kgenome_func f[NF];
	uint32_t n;
	int      keep[NF];          /* the function is intact in the view */
	uint64_t view_off[NF];
};

/*
 * Parent: [pad][function]... in order, each function distinct random bytes with no
 * zero in them. The view is the same sequence with a pad of eight or more zeros
 * collapsed to two, a function CUT (a library: left out of the view entirely), and
 * a function REWRITTEN (a zero run in its middle collapsed, so its bytes are not the
 * parent's). Where each intact function lands is known from the construction.
 */
static void build(struct built *b, struct hk_rng *r, unsigned allow_cut)
{
	uint64_t po = 0, vo = 0;
	uint32_t i;

	memset(b, 0, sizeof *b);
	b->n = 3 + hk_below(r, NF - 3u);
	for (i = 0; i < b->n; i++) {
		uint32_t pad = hk_below(r, 4) ? hk_below(r, 7) : 8 + hk_below(r, 20);
		uint32_t len = 16 + hk_below(r, 80), j;
		uint32_t fate = allow_cut ? hk_below(r, 6) : 5;      /* 0 cut, 1 rewritten, else intact */
		uint8_t *fp;

		memset(b->par + po, 0, pad);
		po += pad;
		/* the view's pad: collapsed when it reaches eight */
		if (pad >= 8u) {
			b->view[vo++] = 0;
			b->view[vo++] = 0;
		} else {
			vo += pad;
		}
		fp = b->par + po;
		for (j = 0; j < len; j++)
			fp[j] = (uint8_t)(1u + (hk_next(r) % 255u));
		b->f[i].off = po;
		b->f[i].len = len;
		b->f[i].value = 0x401000u + po;
		b->f[i].shndx = (uint16_t)(1u + i);
		if (fate == 0u) {
			b->keep[i] = 0;
		} else if (fate == 1u) {
			/* a zero run of 9 inside the body: the parent has it, the view has two */
			uint32_t at = 4 + hk_below(r, len - 14u);

			memset(fp + at, 0, 9);
			memcpy(b->view + vo, fp, at);
			b->view[vo + at] = b->view[vo + at + 1u] = 0;
			memcpy(b->view + vo + at + 2u, fp + at + 9u, len - at - 9u);
			vo += len - 7u;
			b->keep[i] = 0;
		} else {
			memcpy(b->view + vo, fp, len);
			b->view_off[i] = vo;
			vo += len;
			b->keep[i] = 1;
		}
		po += len;
	}
	b->par_n = po;
	b->view_n = vo;
}

static void funcs_remap_construction(void)
{
	unsigned round, found_total = 0, absent_total = 0;

	for (round = 0; round < 500; round++) {
		static struct built b;
		struct kgenome_func_set pf, out;
		uint32_t i, k = 0, want = 0;

		build(&b, &rng, 1);
		pf.v = b.f;
		pf.n = b.n;
		pf.status = KGENOME_OK;
		kgenome_funcs_remap(b.par, b.par_n, &pf, b.view, b.view_n, &out);
		for (i = 0; i < b.n; i++)
			want += (uint32_t)b.keep[i];
		CK(out.status == KGENOME_OK);
		CK(out.n == want);
		for (i = 0; i < b.n; i++) {
			if (!b.keep[i]) {
				absent_total++;
				continue;
			}
			if (k >= out.n)
				break;
			/* order kept, offset exact, fields come along, extent unchanged */
			CK(out.v[k].off == b.view_off[i]);
			CK(out.v[k].len == b.f[i].len);
			CK(out.v[k].value == b.f[i].value && out.v[k].shndx == b.f[i].shndx);
			CK(!memcmp(b.view + out.v[k].off, b.par + b.f[i].off, (size_t)b.f[i].len));
			found_total++;
			k++;
		}
		kgenome_funcs_free(&out);
		CK(out.v == NULL && out.n == 0);
	}
	CK(found_total > 5000u && absent_total > 800u);
	/* a view that is the parent: every function, where it was */
	{
		static struct built b;
		struct kgenome_func_set pf, out;
		uint32_t i;

		build(&b, &rng, 0);
		pf.v = b.f;
		pf.n = b.n;
		pf.status = KGENOME_OK;
		kgenome_funcs_remap(b.par, b.par_n, &pf, b.par, b.par_n, &out);
		CK(out.n == b.n && out.status == KGENOME_OK);
		for (i = 0; i < out.n && i < b.n; i++)
			CK(out.v[i].off == b.f[i].off);
		kgenome_funcs_free(&out);
	}
}

static void funcs_remap_hostile(void)
{
	static struct built b;
	struct kgenome_func_set pf, out;
	struct kgenome_func hostile[6];

	build(&b, &rng, 0);
	/* extents the parent cannot hold are skipped, not read */
	memset(hostile, 0, sizeof hostile);
	hostile[0].off = b.par_n; hostile[0].len = 16;
	hostile[1].off = b.par_n + 100u; hostile[1].len = 1;
	hostile[2].off = 4; hostile[2].len = UINT64_MAX;
	hostile[3].off = UINT64_MAX; hostile[3].len = 16;
	hostile[4].off = 8; hostile[4].len = 0;                         /* a name, not a body */
	hostile[5] = b.f[0];
	pf.v = hostile; pf.n = 6; pf.status = KGENOME_OK;
	kgenome_funcs_remap(b.par, b.par_n, &pf, b.par, b.par_n, &out);
	CK(out.n == 1 && out.v[0].off == b.f[0].off);
	kgenome_funcs_free(&out);
	/* no functions, no parent, no view */
	pf.n = 0;
	kgenome_funcs_remap(b.par, b.par_n, &pf, b.par, b.par_n, &out);
	CK(out.n == 0 && out.v == NULL);
	pf.v = b.f; pf.n = b.n;
	kgenome_funcs_remap(NULL, 0, &pf, b.par, b.par_n, &out);
	CK(out.n == 0);
	kgenome_funcs_remap(b.par, b.par_n, &pf, NULL, 0, &out);
	CK(out.n == 0);
	kgenome_funcs_remap(b.par, b.par_n, NULL, b.par, b.par_n, &out);
	CK(out.n == 0);
	/* an empty view holds nothing */
	kgenome_funcs_remap(b.par, b.par_n, &pf, b.par, 0, &out);
	CK(out.n == 0);
	/* a function longer than the view cannot be in it */
	kgenome_funcs_remap(b.par, b.par_n, &pf, b.par, 5, &out);
	CK(out.n == 0);
	/* a function list out of order must not break memory */
	{
		struct kgenome_func rev[NF];
		uint32_t i;

		for (i = 0; i < b.n; i++)
			rev[i] = b.f[b.n - 1u - i];
		pf.v = rev; pf.n = b.n;
		kgenome_funcs_remap(b.par, b.par_n, &pf, b.par, b.par_n, &out);
		CK(out.status == KGENOME_OK || out.status == KGENOME_OVER_BUDGET);
		kgenome_funcs_free(&out);
	}
}

/* The search for a function that is not in the view costs its window, and the
 * windows are charged against 64 bytes of work per byte of the view (plus a
 * megabyte): past that the set says OVER_BUDGET - never a quiet short answer. */
static void funcs_remap_budget(void)
{
	static uint8_t par[1u << 22], view[256];
	enum { N = 30000 };
	struct kgenome_func *f = malloc(N * sizeof *f);
	struct kgenome_func_set pf, out;
	uint32_t i;
	struct hk_rng r = { 12345 };

	for (i = 0; i < sizeof par; i++)
		par[i] = (uint8_t)(1u + hk_next(&r) % 255u);
	for (i = 0; i < sizeof view; i++)
		view[i] = (uint8_t)(1u + hk_next(&r) % 255u);
	for (i = 0; i < N; i++) {
		f[i].off = (uint64_t)i * 128u;
		f[i].len = 100;
		f[i].value = i;
		f[i].shndx = 1;
	}
	pf.v = f; pf.n = N; pf.status = KGENOME_OK;
	kgenome_funcs_remap(par, sizeof par, &pf, view, sizeof view, &out);
	CK(out.status == KGENOME_OVER_BUDGET);
	CK(out.n == 0);
	kgenome_funcs_free(&out);
	/* a smaller list on the same view stays inside the budget and says it found nothing */
	pf.n = 1000;
	kgenome_funcs_remap(par, sizeof par, &pf, view, sizeof view, &out);
	CK(out.status == KGENOME_OK && out.n == 0);
	free(f);
}

int main(void)
{
	offmap_differential();
	table_is_the_transform();
	visitor_fields();
	remap_through_a_collapse();
	funcs_remap_construction();
	funcs_remap_hostile();
	funcs_remap_budget();
	printf("normalizer_offmap: %s\n", hk_fails ? "FAILED" : "ok");
	return hk_fails != 0 || km_failed();
}
