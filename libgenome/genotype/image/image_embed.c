/*
 * image_embed.c - the starts of objects held in a variable of an ELF or PE host. See image_embed.h for
 * what is measured and what is not seen.
 */

#include <stdlib.h>
#include <string.h>
#include <kofcmp.h>
#include "image_embed.h"
#include "image_addr.h"
#include "elf_image.h"
#include "pe_image.h"

/* The word size and byte order the host stores its pointers in. */
static unsigned host_words(const struct kgenome_obj *obj, int *be)
{
	*be = 0;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		*be = e->elf_data == KGENOME_ELFDATA_BE;
		return e->elf_class == KGENOME_ELFCLASS_64 ? 8u : 4u;
	}
	if (obj->format == KGENOME_FMT_PE)
		return kgenome_obj_pe(obj)->pe32_plus ? 8u : 4u;
	return 0;
}

static int host_is_big(void)
{
	const uint16_t one = 1;

	return *(const uint8_t *)&one == 0;
}

static uint32_t bswap32(uint32_t v)
{
	return (v >> 24) | ((v >> 8) & 0xff00u) | ((v << 8) & 0xff0000u) | (v << 24);
}

static uint64_t bswap64(uint64_t v)
{
	return ((uint64_t)bswap32((uint32_t)v) << 32) | bswap32((uint32_t)(v >> 32));
}

/* First word offset of a span: aligned in the FILE, as the words were measured. */
static uint64_t first_word(uint64_t off, unsigned ws)
{
	return (off + ws - 1u) & ~(uint64_t)(ws - 1u);
}

static uint64_t span_end(const struct kgenome_embed_req *rq, const struct kgenome_embed_span *s)
{
	uint64_t e = s->off + s->len;

	if (e < s->off || e > rq->file.n)
		e = rq->file.n;
	return s->off < e ? e : s->off;
}


/* ---- where the variables are ---- */

struct rng {
	uint64_t a, b;      /* [a, b) of the file */
};

#define EMB_RANGES (KGENOME_ELF_MAX_SEGMENTS + KGENOME_ELF_MAX_SECTIONS + KGENOME_PE_MAX_SECTIONS)

struct rset {
	struct rng v[EMB_RANGES];
	uint32_t   n;
};

static void rset_put(struct rset *r, uint64_t off, uint64_t len, uint64_t file_n)
{
	uint64_t e = off + len;

	if (!len || e < off || off >= file_n || r->n >= EMB_RANGES)
		return;
	r->v[r->n].a = off;
	r->v[r->n].b = e < file_n ? e : file_n;
	r->n++;
}

static int rset_has(const struct rset *r, uint64_t x)
{
	uint32_t i;

	for (i = 0; i < r->n; i++)
		if (x >= r->v[i].a && x < r->v[i].b)
			return 1;
	return 0;
}

static uint32_t spans_of(const struct kgenome_obj *obj, kof_buf file, int code, int all, struct kgenome_embed_span *out)
{
	struct rset add = { .n = 0 }, cut = { .n = 0 };
	uint64_t pt[2u * 2u * EMB_RANGES];
	uint32_t i, np = 0, n = 0;

	if (!obj || !obj->file_header || !out)
		return 0;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
			const struct kgenome_elf_seg *s = &e->seg[i];

			if (s->type == 1u && (all || !!(s->perm & KGENOME_PERM_X) == !!code))
				rset_put(&add, s->file_off, s->file_size, file.n);
		}
		for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			const struct kgenome_elf_sec *s = &e->sec[i];

			if (!(s->flags & KGENOME_ELF_SHF_ALLOC) || s->type == KGENOME_ELF_SHT_NOBITS || !s->file_size)
				continue;
			rset_put(!!(s->flags & KGENOME_ELF_SHF_EXEC) == !!code ? &add : &cut, s->file_off, s->file_size, file.n);
		}
	} else if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		for (i = 0; i < p->nsec && i < KGENOME_PE_MAX_SECTIONS; i++)
			if (!!kgenome_pe_sec_is_code(&p->sec[i]) == !!code)
				rset_put(&add, p->sec[i].file_off, p->sec[i].file_size, file.n);
	}
	if (!add.n)
		return 0;
	for (i = 0; i < add.n; i++) {
		pt[np++] = add.v[i].a;
		pt[np++] = add.v[i].b;
	}
	for (i = 0; i < cut.n; i++) {
		pt[np++] = cut.v[i].a;
		pt[np++] = cut.v[i].b;
	}
	qsort(pt, np, sizeof pt[0], kof_cmp_u64);
	/* the elementary stretches between the boundaries: data when something adds it and nothing cuts it */
	for (i = 0; i + 1u < np; i++) {
		if (pt[i] == pt[i + 1u] || !rset_has(&add, pt[i]) || rset_has(&cut, pt[i]))
			continue;
		if (n && out[n - 1u].off + out[n - 1u].len == pt[i]) {
			out[n - 1u].len += pt[i + 1u] - pt[i];
		} else if (n < KGENOME_EMBED_SPANS_MAX) {
			out[n].off = pt[i];
			out[n].len = pt[i + 1u] - pt[i];
			n++;
		}
	}
	return n;
}

/*
 * The policy of the answer: the data (see the header); and ALL the loaded bytes when the host cannot tell code from data - an ELF
 * with no section table (UPX, a stripped static bot: the Mozi arrays of ELF headers are .rodata in an R-X segment that nothing
 * names) - or has no data at all.
 */
uint32_t kgenome_image_embed_spans(const struct kgenome_obj *obj, kof_buf file, struct kgenome_embed_span *out)
{
	uint32_t n;

	if (!obj || !obj->file_header)
		return 0;
	if (obj->format == KGENOME_FMT_ELF && !kgenome_obj_elf(obj)->sec_count)
		return spans_of(obj, file, 0, 1, out);
	n = spans_of(obj, file, 0, 0, out);
	return n ? n : spans_of(obj, file, 1, 0, out);
}

/* The span that holds file offset `off`, or 0. Ascending and disjoint, so a binary search. */
static int in_data(const struct kgenome_embed_req *rq, uint64_t off)
{
	uint32_t lo = 0, hi = rq->n_data;

	while (lo < hi) {
		uint32_t m = lo + (hi - lo) / 2u;
		const struct kgenome_embed_span *s = &rq->data[m];

		if (off < s->off)
			hi = m;
		else if (off - s->off >= s->len)
			lo = m + 1u;
		else
			return 1;
	}
	return 0;
}

/* The loaded addresses the data spans occupy, as one envelope: a word outside it cannot be the
 * target of anything in the data, which is most of the words (strings, counters, zero), so the
 * per-word translation is paid only for those that fall inside. */
static int envelope(const struct kgenome_embed_req *rq, uint64_t *lo, uint64_t *hi)
{
	uint32_t i;
	int any = 0;

	*lo = UINT64_MAX;
	*hi = 0;
	for (i = 0; i < rq->n_data; i++) {
		uint64_t a = rq->data[i].off, e = span_end(rq, &rq->data[i]);

		while (a < e) {
			struct kgenome_image_seg g;
			uint64_t piece_end;

			if (!kgenome_image_seg_at(rq->obj, a, &g) || g.hi <= a)
				break;
			piece_end = g.hi < e ? g.hi : e;
			if (a + (uint64_t)g.delta < *lo)
				*lo = a + (uint64_t)g.delta;
			if (piece_end + (uint64_t)g.delta > *hi)
				*hi = piece_end + (uint64_t)g.delta;
			any = 1;
			a = piece_end;
		}
	}
	return any;
}

/* One candidate to the caller; 0 when the caller will take no more (and the answer is then partial). */
static int put(const struct kgenome_embed_req *rq, struct kgenome_embed_res *res, uint64_t off)
{
	if (!rq->emit(rq->user, off)) {
		res->status = KGENOME_TRUNCATED;
		return 0;
	}
	res->n++;
	return 1;
}

void kgenome_image_embed_starts(const struct kgenome_embed_req *rq, struct kgenome_embed_res *res)
{
	uint64_t vlo, vhi, w;
	unsigned ws;
	int be, swap;
	uint32_t i;

	res->n = 0;
	res->status = KGENOME_OK;
	if (!rq || !rq->obj || !rq->obj->file_header || !rq->emit || !(ws = host_words(rq->obj, &be))) {
		res->status = KGENOME_BAD_INPUT;
		return;
	}
	if (!envelope(rq, &vlo, &vhi))
		return;
	swap = be != host_is_big();
	for (i = 0; i < rq->n_data; i++) {
		uint64_t a = first_word(rq->data[i].off, ws), e = span_end(rq, &rq->data[i]);

		for (; a + ws <= e; a += ws) {
			const uint8_t *p = rq->file.p + a;
			uint64_t v = 0, off;

			/* the byte order of the file against the byte order of this machine: a copy when they agree */
			if (ws == 8u) {
				memcpy(&v, p, 8);
				if (swap)
					v = bswap64(v);
			} else {
				uint32_t w32;

				memcpy(&w32, p, 4);
				v = swap ? (uint64_t)bswap32(w32) : w32;
			}
			if (v < vlo || v >= vhi)
				continue;
			off = kgenome_image_addr_to_off(rq->obj, v);
			if (off == KGENOME_BROKEN || off >= rq->file.n || !in_data(rq, off))
				continue;
			if (!put(rq, res, off))
				return;
		}
	}
	if ((rq->flags & KGENOME_EMBED_SYMBOLS) && rq->obj->format == KGENOME_FMT_ELF) {
		struct kgenome_elf_symtab t;

		if (kgenome_elf_symtab_of(rq->file, kgenome_obj_elf(rq->obj), KGENOME_ELF_SYMTAB_BEST, &t)) {
			for (w = 0; w < t.n; w++) {
				struct kgenome_elf_symbol s;
				uint64_t off;

				if (!kgenome_elf_symbol_at(rq->file, &t, w, &s))
					continue;
				/* a sized OBJECT that is defined: STT_OBJECT is 1 */
				if ((s.info & 15u) != 1u || !s.size || !s.shndx)
					continue;
				off = kgenome_image_addr_to_off(rq->obj, s.value);
				if (off == KGENOME_BROKEN || off >= rq->file.n || !in_data(rq, off))
					continue;
				if (!put(rq, res, off))
					return;
			}
		}
	}
}

/*
 * THE HEADER OF AN ELF THAT IS A VARIABLE'S DATA, validated whole (embed-var-1: the four magic bytes
 * occur in libc constants, 447 of the 1617 ELF the sniff accepted in the data of 5855 hosts; the full
 * header left none of them and 1170 real ones). kgenome_elf_sniff answers "does this start like an ELF" for an
 * object handed over as a file; this answers it for bytes that merely sit at an address: class,
 * data and version of e_ident, e_type EXEC or DYN, e_ehsize, e_phentsize and a program header table, all read
 * raw, and then a machine the image parse names (an e_machine it has no architecture for is not a
 * program this engine can look at). The parse is paid only by a header that passed the raw checks.
 */
int kgenome_elf_ident_valid(const uint8_t id[8])
{
	return memcmp(id, kgenome_elf_magic, 4) == 0 && (id[4] == 1u || id[4] == 2u) && (id[5] == 1u || id[5] == 2u) && id[6] == 1u;
}

int kgenome_elf_hdr_valid(kof_buf f)
{
	struct kgenome_elf_info e;
	struct kgenome_obj obj;
	uint8_t cls, data, ver;
	uint16_t type, ehsize, phentsize, phnum;
	int is64, be;

	if (f.n < 8u || !kgenome_elf_ident_valid(f.p) || !kof_rd_u8(f, 4, &cls) || !kof_rd_u8(f, 5, &data) ||
	    !kof_rd_u8(f, 6, &ver))
		return 0;
	is64 = cls == 2u;
	be = data == 2u;
	/* a header cut short of its own size is not one (found by tests/fuzz/image/embed.c: 46 bytes of an ELF32 header passed the fields
	 * below, which all lie in the first 46, and had no extent) */
	if (f.n < (is64 ? 64u : 52u))
		return 0;
	if (!kof_rd_u16(f, 16, be, &type) || (type != KGENOME_ELF_EXEC && type != KGENOME_ELF_DYN))
		return 0;
	if (!kof_rd_u16(f, is64 ? 52 : 40, be, &ehsize) || !kof_rd_u16(f, is64 ? 54 : 42, be, &phentsize) ||
	    !kof_rd_u16(f, is64 ? 56 : 44, be, &phnum))
		return 0;
	if (ehsize != (is64 ? 64u : 52u) || phentsize != (is64 ? 56u : 32u) || !phnum)
		return 0;
	memset(&obj, 0, sizeof obj);
	return kgenome_elf_image_parse(f, &e, &obj) && e.valid && obj.arch != KGENOME_ARCH_OTHER;
}

/*
 * THE BYTES AN ELF OWNS, from its own headers (the union rule of embed-excess-1): the ELF header, the
 * program header table, every PT_LOAD file extent, the section header table and every section that
 * has bytes, each counted only when it lies whole inside `f`. 0 when `f` is not an ELF; otherwise the
 * greatest end. A claim the file cannot back is not counted, so a hostile header can shorten the
 * answer and never make it reach past the buffer.
 */
uint64_t kgenome_elf_extent(kof_buf f)
{
	struct kgenome_elf_info e;
	struct kgenome_obj obj;
	uint64_t end, t;
	uint32_t i;

	memset(&obj, 0, sizeof obj);
	if (!kgenome_elf_image_parse(f, &e, &obj) || !e.valid)
		return 0;
	end = e.elf_class == KGENOME_ELFCLASS_64 ? 64u : 52u;
	if (end > f.n)
		return 0;
	if (e.phnum && e.phentsize) {
		t = e.phoff + (uint64_t)e.phnum * e.phentsize;
		if (t >= e.phoff && t <= f.n && t > end)
			end = t;
	}
	for (i = 0; i < e.seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		t = e.seg[i].file_off + e.seg[i].file_size;
		if (e.seg[i].type == 1u && t >= e.seg[i].file_off && t <= f.n && t > end)
			end = t;
	}
	if (e.shnum && e.shentsize) {
		t = e.shoff + (uint64_t)e.shnum * e.shentsize;
		if (t >= e.shoff && t <= f.n && t > end)
			end = t;
	}
	for (i = 0; i < e.sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		t = e.sec[i].file_off + e.sec[i].file_size;
		if (e.sec[i].type == 0 || e.sec[i].type == KGENOME_ELF_SHT_NOBITS || !e.sec[i].file_size)
			continue;
		if (t >= e.sec[i].file_off && t <= f.n && t > end)
			end = t;
	}
	return end;
}

/*
 * The extent a PE owns: its headers and sections, up to the overlay (`overlay_off` is the first byte
 * no section, header or certificate claimed). 0 when the parse found none.
 */
static uint64_t pe_extent(kof_buf f)
{
	struct kgenome_pe_info p;
	struct kgenome_obj obj;

	memset(&obj, 0, sizeof obj);
	if (!kgenome_pe_image_parse(f, &p, &obj) || !p.valid)
		return 0;
	return p.overlay_off && p.overlay_off <= f.n ? p.overlay_off : 0;
}

uint64_t kgenome_image_embed_extent(uint8_t fmt, kof_buf f)
{
	if (fmt == KGENOME_FMT_ELF)
		return kgenome_elf_extent(f);
	if (fmt == KGENOME_FMT_PE)
		return pe_extent(f);
	return 0;
}
