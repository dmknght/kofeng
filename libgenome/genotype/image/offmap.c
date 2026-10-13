/*
 * offmap.c - see offmap.h.
 */
#include <string.h>

#include "offmap.h"
#include "obj.h"
#include "clr_types.h"

uint64_t kgenome_offmap_at(const struct kgenome_offmap *m, uint64_t off)
{
	uint32_t lo = 0, hi, i;
	uint64_t r;

	if (!m || !m->n)
		return off;
	if (off >= m->from_end)
		return m->to_end;
	hi = m->n;
	/* the last mark at or below `off` */
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (m->from[mid] <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo)
		return off < m->to[0] ? off : m->to[0];
	i = lo - 1u;
	r = m->to[i] + (off - m->from[i]);
	if (i + 1u < m->n && r > m->to[i + 1u])
		r = m->to[i + 1u];
	if (r > m->to_end)
		r = m->to_end;
	return r;
}

/* ---- the fields that are file offsets ---------------------------------------- */

#define EXT(o, l)  fn(user, &(o), &(l))
#define POS(o)     fn(user, &(o), NULL)

static void clr_offsets(struct kgenome_clr_meta *c, kgenome_off_fn fn, void *user)
{
	EXT(c->root_off, c->root_len);
	EXT(c->tables.off, c->tables.len);
	EXT(c->strings.off, c->strings.len);
	EXT(c->us.off, c->us.len);
	EXT(c->blob.off, c->blob.len);
	EXT(c->guid.off, c->guid.len);
	EXT(c->res_off, c->res_len);
}

void kgenome_pe_info_offsets(struct kgenome_pe_info *p, kgenome_off_fn fn, void *user)
{
	uint32_t i;

	POS(p->lfanew);
	POS(p->header_end);
	POS(p->size_of_headers);
	EXT(p->cert_off, p->cert_len);
	EXT(p->overlay_off, p->overlay_len);
	EXT(p->res_off, p->res_len);
	EXT(p->clr_off, p->clr_len);
	/* The one directory that is a file offset and not an RVA. */
	EXT(p->dir[KGENOME_PE_DIR_SECURITY].rva, p->dir[KGENOME_PE_DIR_SECURITY].size);
	for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		EXT(p->sec[i].file_off, p->sec[i].file_size);
		EXT(p->sec[i].claim_off, p->sec[i].claim_len);
	}
	clr_offsets(&p->clr, fn, user);
}

void kgenome_elf_info_offsets(struct kgenome_elf_info *e, kgenome_off_fn fn, void *user)
{
	uint32_t i;

	POS(e->phoff);
	POS(e->shoff);
	EXT(e->hdr_claim_off, e->hdr_claim_len);
	EXT(e->shtab_claim_off, e->shtab_claim_len);
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		EXT(e->seg[i].file_off, e->seg[i].file_size);
		EXT(e->seg[i].claim_off, e->seg[i].claim_len);
	}
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		EXT(e->sec[i].file_off, e->sec[i].file_size);
		EXT(e->sec[i].claim_off, e->sec[i].claim_len);
	}
}

/* ---- carrying them through ---------------------------------------------------- */

struct remap_ask {
	const struct kgenome_offmap *m;
};

static void remap_one(void *user, uint64_t *off, uint64_t *len)
{
	const struct kgenome_offmap *m = ((struct remap_ask *)user)->m;
	uint64_t a = *off, b, na;

	/* "does not apply" and "unresolved" are not positions. */
	if (a == KGENOME_NA || a == KGENOME_BROKEN)
		return;
	na = kgenome_offmap_at(m, a);
	if (len) {
		/* Held at the original's end rather than summed: a length the
		 * parse got wrong must not wrap below the offset. */
		b = *len > m->from_end - (a < m->from_end ? a : m->from_end)
		    ? m->from_end : a + *len;
		b = kgenome_offmap_at(m, b);
		*len = b > na ? b - na : 0u;
	}
	*off = na;
}

void kgenome_pe_info_remap(struct kgenome_pe_info *info, const struct kgenome_offmap *m)
{
	struct remap_ask a = { m };

	kgenome_pe_info_offsets(info, remap_one, &a);
}

void kgenome_elf_info_remap(struct kgenome_elf_info *info, const struct kgenome_offmap *m)
{
	struct remap_ask a = { m };

	kgenome_elf_info_offsets(info, remap_one, &a);
}
