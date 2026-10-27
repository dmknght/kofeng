/*
 * infect.c - kgenome_infect_regions: the places a file infector commonly uses, listed from the parse. See infect.h for
 * what is answered and on what bounds; this file only walks the kept tables and decides, for each region, whether
 * the engine's ranges touch it.
 */
#include <stdio.h>
#include <string.h>

#include <genotype/image/infect.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_image.h>
#include <genotype/image/image_addr.h>

#define ELF_PT_NOTE         4u
#define ELF_SHT_INIT_ARRAY  14u
#define ELF_SHT_FINI_ARRAY  15u
#define ELF_SHT_PREINIT     16u
#define PAGE_DEFAULT        0x1000u
#define TLS_CALLBACK_MAX    64u

struct ctx {
	const struct kgenome_infect_req *rq;
	struct kgenome_infect_res       *rs;
	uint64_t                         size;      /* the object's size */
	uint32_t                         n_inf;     /* ranges considered */
	uint8_t                          hit[KGENOME_INFECT_RANGE_MAX];
	int                              cut;
};

/* The end of [off, off + len), saturating. */
static uint64_t end_of(uint64_t off, uint64_t len)
{
	return kof_sat_add(off, len);
}

/* Do two ranges share a byte? A zero-length range shares none. */
static int overlaps(uint64_t a, uint64_t alen, uint64_t b, uint64_t blen)
{
	return alen && blen && a < end_of(b, blen) && b < end_of(a, alen);
}

/* A name from the file, safe to show: a byte below a space is not text. */
static void clean(char *out, size_t cap, const char *prefix, const char *s, size_t smax)
{
	size_t n = (size_t)snprintf(out, cap, "%s", prefix), i;

	if (n >= cap)
		return;
	for (i = 0; i < smax && s[i] && n + 1u < cap; i++)
		out[n++] = ((unsigned char)s[i] < 0x20u || (unsigned char)s[i] == 0x7fu) ? '?' : s[i];
	out[n] = 0;
}

static void add(struct ctx *c, enum kgenome_infect_kind kind, const char *name, uint64_t off, uint64_t len, uint64_t addr)
{
	struct kgenome_infect_row *r;
	uint32_t j, first = KGENOME_INFECT_RANGE_MAX;

	/* Which ranges touch it is decided for every region, kept or not: a region the room could not hold must still count as
	 * the home of the ranges inside it, or they would come back as rows of their own and the total would depend on the room. */
	if (off != KGENOME_NA) {
		for (j = 0; j < c->n_inf; j++) {
			const struct kgenome_infect_range *g = &c->rq->inf[j];

			if (!overlaps(off, len, g->off, g->len))
				continue;
			c->hit[j] = 1;
			if (first == KGENOME_INFECT_RANGE_MAX)
				first = j;
		}
	}
	c->rs->total++;
	if (c->rs->n >= c->rq->cap || !c->rq->out) {
		c->cut = 1;
		return;
	}
	r = &c->rq->out[c->rs->n++];
	memset(r, 0, sizeof *r);
	snprintf(r->name, sizeof r->name, "%s", name);
	r->kind = kind;
	r->off = off;
	r->len = len;
	r->addr = addr;
	if (first != KGENOME_INFECT_RANGE_MAX) {
		r->flagged = 1;
		r->inf_kind = c->rq->inf[first].kind;
		r->inf_index = first;
		c->rs->n_flagged++;
	}
}

/* A region that is a clipped file range with a name; nothing is listed for an empty one. */
static void add_range(struct ctx *c, enum kgenome_infect_kind kind, const char *name, uint64_t off, uint64_t len, uint64_t addr)
{
	uint64_t n = kof_clip_len(c->size, off, len);

	if (n)
		add(c, kind, name, off, n, addr);
}

static void add_entry(struct ctx *c, uint64_t addr)
{
	uint64_t at = c->rq->obj->entry_off, n;

	if (at == KGENOME_NA || at == KGENOME_BROKEN || at >= c->size)
		return;
	n = c->size - at < KGENOME_INFECT_ENTRY_AREA ? c->size - at : KGENOME_INFECT_ENTRY_AREA;
	add(c, KGENOME_INFECT_ENTRY, "entry point", at, n, addr);
}

/* ---- ELF ------------------------------------------------------------------------------------------------ */

/* The first byte at or after `from` that a kept segment, section or header table owns; `from` itself when one owns it,
 * the object's size when none does. What lies between `from` and the answer is padding. */
static uint64_t elf_next_claim(const struct kgenome_elf_info *e, uint64_t size, uint64_t from)
{
	uint64_t best = size, s, l;
	uint32_t i;

#define CLAIM(S, L) do { s = (S); l = (L); \
	if (l) { if (s <= from && from < end_of(s, l)) return from; if (s > from && s < best) best = s; } } while (0)
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
		CLAIM(e->seg[i].file_off, e->seg[i].file_size);
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type != KGENOME_ELF_SHT_NOBITS)
			CLAIM(e->sec[i].file_off, e->sec[i].file_size);
	CLAIM(e->phoff, (uint64_t)e->phnum * e->phentsize);
	CLAIM(e->shoff, (uint64_t)e->shnum * e->shentsize);
#undef CLAIM
	return best;
}

/* A section's address: none for one the loader does not map (no SHF_ALLOC), whose sh_addr is 0 and means nothing. */
static uint64_t sec_addr(const struct kgenome_elf_sec *s)
{
	return (s->flags & KGENOME_ELF_SHF_ALLOC) ? s->mem_addr : KGENOME_NA;
}

static int sec_has_bytes(const struct kgenome_elf_sec *s, uint64_t size)
{
	return s->type != KGENOME_ELF_SHT_NULL && s->type != KGENOME_ELF_SHT_NOBITS && s->file_off < size &&
	       kof_clip_len(size, s->file_off, s->file_size) != 0;
}

static int is_init_name(const struct kgenome_elf_sec *s)
{
	static const char *const w[] = { ".init", ".fini", ".ctors", ".dtors", ".init_array", ".fini_array", ".preinit_array" };
	size_t k;

	if (!memchr(s->name, 0, sizeof s->name))
		return 0;
	for (k = 0; k < sizeof w / sizeof w[0]; k++)
		if (strcmp(s->name, w[k]) == 0)
			return 1;
	return 0;
}

static void elf_regions(struct ctx *c, const struct kgenome_elf_info *e)
{
	uint64_t end, seg_end, bound, al = 0, stop;
	int32_t last_sec = -1, last_seg = -1;
	uint32_t i, j, si = 0, ord[KGENOME_ELF_MAX_SEGMENTS], nl = 0;
	uint64_t delta = 0;
	char nm[KGENOME_INFECT_NAME];

	add_entry(c, e->entry_addr);
	if (kgenome_elf_entry_sec(e, &si, &delta) == 0 && si < KGENOME_ELF_MAX_SECTIONS) {
		clean(nm, sizeof nm, "entry section ", e->sec[si].name, sizeof e->sec[si].name);
		add_range(c, KGENOME_INFECT_ENTRY_SECTION, nm, e->sec[si].file_off, e->sec[si].file_size, sec_addr(&e->sec[si]));
	}
	end = 0;
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		if (sec_has_bytes(&e->sec[i], c->size) && (last_sec < 0 || end_of(e->sec[i].file_off, e->sec[i].file_size) > end)) {
			last_sec = (int32_t)i;
			end = end_of(e->sec[i].file_off, e->sec[i].file_size);
		}
	if (last_sec >= 0) {
		clean(nm, sizeof nm, "last section ", e->sec[last_sec].name, sizeof e->sec[last_sec].name);
		add_range(c, KGENOME_INFECT_LAST_SECTION, nm, e->sec[last_sec].file_off, e->sec[last_sec].file_size,
			  sec_addr(&e->sec[last_sec]));
	}
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		if (!kgenome_elf_seg_is_load(&e->seg[i]) || e->seg[i].file_off >= c->size)
			continue;
		ord[nl++] = i;
		if (last_seg < 0 || end_of(e->seg[i].file_off, e->seg[i].file_size) >
				    end_of(e->seg[(uint32_t)last_seg].file_off, e->seg[(uint32_t)last_seg].file_size))
			last_seg = (int32_t)i;
	}
	if (last_seg >= 0) {
		const struct kgenome_elf_seg *g = &e->seg[last_seg];

		snprintf(nm, sizeof nm, "last segment #%d", last_seg);
		add_range(c, KGENOME_INFECT_LAST_SEGMENT, nm, g->file_off, g->file_size, g->mem_addr);
		/* The padding after it: up to the next boundary of the segment's alignment, never into what something owns. */
		seg_end = end_of(g->file_off, kof_clip_len(c->size, g->file_off, g->file_size));
		if (!kgenome_elf_seg_align(c->rq->file, e, (uint32_t)last_seg, &al) || al < 2u)
			al = PAGE_DEFAULT;
		bound = seg_end > UINT64_MAX - al ? c->size : ((seg_end + al - 1u) / al) * al;
		stop = elf_next_claim(e, c->size, seg_end);
		if (bound > c->size)
			bound = c->size;
		if (stop < bound)
			bound = stop;
		if (bound > seg_end)
			add(c, KGENOME_INFECT_SLACK, "padding after the last segment", seg_end, bound - seg_end, KGENOME_NA);
	}
	/* The gaps between loadable segments, in file order (insertion sort: at most 64). */
	for (i = 1; i < nl; i++) {
		uint32_t v = ord[i];

		for (j = i; j > 0 && e->seg[ord[j - 1u]].file_off > e->seg[v].file_off; j--)
			ord[j] = ord[j - 1u];
		ord[j] = v;
	}
	for (i = 1; i < nl; i++) {
		const struct kgenome_elf_seg *a = &e->seg[ord[i - 1u]], *b = &e->seg[ord[i]];
		uint64_t ae = end_of(a->file_off, kof_clip_len(c->size, a->file_off, a->file_size));

		if (b->file_off > ae) {
			snprintf(nm, sizeof nm, "gap between segments #%u and #%u", ord[i - 1u], ord[i]);
			add_range(c, KGENOME_INFECT_GAP, nm, ae, b->file_off - ae, KGENOME_NA);
		}
	}
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if (!sec_has_bytes(s, c->size))
			continue;
		if (s->type == ELF_SHT_INIT_ARRAY || s->type == ELF_SHT_FINI_ARRAY || s->type == ELF_SHT_PREINIT || is_init_name(s)) {
			clean(nm, sizeof nm, "init section ", s->name, sizeof s->name);
			add_range(c, KGENOME_INFECT_INIT, nm, s->file_off, s->file_size, sec_addr(s));
		}
	}
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
		if (e->seg[i].type == ELF_PT_NOTE) {
			snprintf(nm, sizeof nm, "note segment #%u", i);
			add_range(c, KGENOME_INFECT_NOTE, nm, e->seg[i].file_off, e->seg[i].file_size, e->seg[i].mem_addr);
		}
	/* The overlay: whatever follows the last byte any table, segment or section accounts for. */
	end = 0;
#define ACC(S, L) do { uint64_t cl = kof_clip_len(c->size, (S), (L)); if (cl && end_of((S), cl) > end) end = end_of((S), cl); } while (0)
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
		ACC(e->seg[i].file_off, e->seg[i].file_size);
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type != KGENOME_ELF_SHT_NOBITS)
			ACC(e->sec[i].file_off, e->sec[i].file_size);
	ACC(e->phoff, (uint64_t)e->phnum * e->phentsize);
	ACC(e->shoff, (uint64_t)e->shnum * e->shentsize);
#undef ACC
	if (c->size > end)
		add(c, KGENOME_INFECT_OVERLAY, "overlay (bytes after the last section)", end, c->size - end, KGENOME_NA);
}

/* ---- PE ------------------------------------------------------------------------------------------------- */

static int pe_dir_in(const struct kgenome_pe_info *p, uint32_t d, const struct kgenome_pe_sec *s)
{
	uint64_t span;

	if (d >= p->n_dirs || d >= KGENOME_PE_DIR_COUNT || !p->dir[d].size || !p->dir[d].rva)
		return 0;
	span = s->mem_size > s->file_size ? s->mem_size : s->file_size;
	return p->dir[d].rva >= s->mem_rva && p->dir[d].rva - s->mem_rva < span;
}

/* The TLS callback array: the pointers the loader calls before the entry point, with their terminating zero. */
static void pe_tls(struct ctx *c, const struct kgenome_pe_info *p)
{
	const struct kgenome_pe_dir *d = &p->dir[KGENOME_PE_DIR_TLS];
	uint64_t psz = p->pe32_plus ? 8u : 4u, at, va, cb, n = 0, v;
	char nm[KGENOME_INFECT_NAME];

	if (p->n_dirs <= KGENOME_PE_DIR_TLS || !d->rva || d->size < 4u * psz)
		return;
	at = kgenome_pe_rva_to_off(p, d->rva);
	if (at == KGENOME_BROKEN || !kof_in_range(c->rq->file, at, 4u * psz))
		return;
	va = 0;
	{
		uint64_t k;

		for (k = 0; k < psz; k++)
			va |= (uint64_t)c->rq->file.p[at + 3u * psz + k] << (8u * k);
	}
	if (va < p->image_base)
		return;
	cb = kgenome_pe_rva_to_off(p, va - p->image_base);
	if (cb == KGENOME_BROKEN)
		return;
	while (n < TLS_CALLBACK_MAX && kof_in_range(c->rq->file, cb + n * psz, psz)) {
		uint64_t k;

		v = 0;
		for (k = 0; k < psz; k++)
			v |= (uint64_t)c->rq->file.p[cb + n * psz + k] << (8u * k);
		if (!v)
			break;
		n++;
	}
	snprintf(nm, sizeof nm, "TLS callbacks (%u)", (unsigned)n);
	add_range(c, KGENOME_INFECT_TLS, nm, cb, (n + 1u) * psz, va - p->image_base);
}

static void pe_regions(struct ctx *c, const struct kgenome_pe_info *p)
{
	uint32_t i;
	int32_t last = -1;
	uint64_t end = 0, first = c->size, fe;
	char nm[KGENOME_INFECT_NAME];

	add_entry(c, p->entry_rva);
	if (p->entry_sec < p->sec_count && p->entry_sec < KGENOME_PE_MAX_SECTIONS) {
		const struct kgenome_pe_sec *s = &p->sec[p->entry_sec];

		clean(nm, sizeof nm, "entry section ", s->name, sizeof s->name);
		add_range(c, KGENOME_INFECT_ENTRY_SECTION, nm, s->file_off, s->file_size, s->mem_rva);
	}
	for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &p->sec[i];
		uint64_t cl = kof_clip_len(c->size, s->file_off, s->file_size);

		if (!cl)
			continue;
		if (s->file_off < first)
			first = s->file_off;
		if (last < 0 || end_of(s->file_off, cl) > end) {
			last = (int32_t)i;
			end = end_of(s->file_off, cl);
		}
	}
	if (last >= 0) {
		const struct kgenome_pe_sec *s = &p->sec[last];
		uint64_t cl = kof_clip_len(c->size, s->file_off, s->file_size);

		clean(nm, sizeof nm, "last section ", s->name, sizeof s->name);
		add(c, KGENOME_INFECT_LAST_SECTION, nm, s->file_off, cl, s->mem_rva);
		if (s->file_size > s->mem_size && cl > s->mem_size) {
			clean(nm, sizeof nm, "raw beyond virtual size in ", s->name, sizeof s->name);
			add(c, KGENOME_INFECT_SLACK, nm, s->file_off + s->mem_size, cl - s->mem_size, end_of(s->mem_rva, s->mem_size));
		} else if (s->mem_size > s->file_size) {
			clean(nm, sizeof nm, "virtual beyond raw size in ", s->name, sizeof s->name);
			add(c, KGENOME_INFECT_SLACK, nm, KGENOME_NA, s->mem_size - s->file_size, end_of(s->mem_rva, s->file_size));
		}
		if (pe_dir_in(p, KGENOME_PE_DIR_BASERELOC, s)) {
			fe = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_BASERELOC].rva);
			if (fe != KGENOME_BROKEN)
				add_range(c, KGENOME_INFECT_DIR_RELOC, "relocation directory in the last section", fe,
					  p->dir[KGENOME_PE_DIR_BASERELOC].size, p->dir[KGENOME_PE_DIR_BASERELOC].rva);
		}
		if (pe_dir_in(p, KGENOME_PE_DIR_IMPORT, s)) {
			fe = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_IMPORT].rva);
			if (fe != KGENOME_BROKEN)
				add_range(c, KGENOME_INFECT_DIR_IMPORT, "import directory in the last section", fe,
					  p->dir[KGENOME_PE_DIR_IMPORT].size, p->dir[KGENOME_PE_DIR_IMPORT].rva);
		}
	}
	/* The cave after the headers: from where the headers end to the first section's raw data. */
	if (last >= 0 && p->header_end < first)
		add_range(c, KGENOME_INFECT_HEADER_CAVE, "cave after the headers", p->header_end, first - p->header_end, p->header_end);
	pe_tls(c, p);
	if (p->overlay_len)
		add_range(c, KGENOME_INFECT_OVERLAY, "overlay (bytes after the last section)", p->overlay_off, p->overlay_len,
			  KGENOME_NA);
}

enum kgenome_status kgenome_infect_regions(const struct kgenome_infect_req *rq, struct kgenome_infect_res *rs)
{
	struct ctx c;
	enum kgenome_status st = KGENOME_OK;
	uint32_t j;

	memset(rs, 0, sizeof *rs);
	memset(&c, 0, sizeof c);
	c.rq = rq;
	c.rs = rs;
	c.size = rq->obj ? rq->obj->obj_size : 0;
	c.n_inf = rq->inf ? rq->n_inf : 0;
	if (c.n_inf > KGENOME_INFECT_RANGE_MAX) {
		c.n_inf = KGENOME_INFECT_RANGE_MAX;
		st = KGENOME_TRUNCATED;
	}
	if (rq->obj && rq->obj->file_header && c.size) {
		if (rq->obj->format == KGENOME_FMT_ELF && kgenome_obj_elf(rq->obj)->valid)
			elf_regions(&c, kgenome_obj_elf(rq->obj));
		else if (rq->obj->format == KGENOME_FMT_PE && kgenome_obj_pe(rq->obj)->valid)
			pe_regions(&c, kgenome_obj_pe(rq->obj));
		else
			st = KGENOME_BAD_INPUT;
	} else {
		st = KGENOME_BAD_INPUT;
	}
	/* What the engine said and no region holds: its own row, so nothing it reported is hidden by this list's choice. */
	for (j = 0; j < c.n_inf; j++) {
		const struct kgenome_infect_range *g = &rq->inf[j];
		struct kgenome_infect_row *r;
		uint64_t a;

		if (c.hit[j])
			continue;
		rs->total++;
		if (rs->n >= rq->cap || !rq->out) {
			c.cut = 1;
			continue;
		}
		r = &rq->out[rs->n++];
		memset(r, 0, sizeof *r);
		snprintf(r->name, sizeof r->name, "%s", "reported by the engine");
		r->kind = KGENOME_INFECT_REPORTED;
		r->flagged = 1;
		r->inf_kind = g->kind;
		r->inf_index = j;
		r->off = g->off;
		r->len = g->len;
		a = rq->obj && rq->obj->file_header ? kgenome_image_off_to_addr(rq->obj, g->off) : KGENOME_BROKEN;
		r->addr = a == KGENOME_BROKEN ? KGENOME_NA : a;
		rs->n_flagged++;
		rs->n_reported++;
	}
	if (c.cut && st == KGENOME_OK)
		st = KGENOME_TRUNCATED;
	return st;
}
