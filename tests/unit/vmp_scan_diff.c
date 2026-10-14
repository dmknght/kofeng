/*
 * vmp_scan_diff - the two scans of bases/unp/vmprotect_pe.c find the table the walks they
 * replaced found, and read the object in as few host calls as the shape allows.
 *
 * THE DEFECT. The module looked for its table by reading the object through c_rd32, a call into
 * the host, at every fourth byte (vmp_find_by_props) or every byte (vmp_find_table) of EVERY PE:
 * 190 M calls over 140 PE, 59 % of the instructions on x86 PE, 19 % on x64 and 31 % on packed PE
 * (callgrind, 98, 87 and 81 PE). vmp_find_by_props now has the host search for the bytes it anchors on, and
 * vmp_find_table reads a word for five offsets and drops a source RVA that no section can hold
 * before it loops the section table for it.
 *
 * WHAT THIS HOLDS IT TO, on the module's own source (it is #included here, so the functions that
 * are tested are the ones that ship): the same answer - the return value and, when a table was
 * found, its entries, its count and its props byte - as the walk each one replaced, which is
 * written out below as ref_by_props / ref_find_table over the same fake host. The cases are
 * random PE-shaped objects (hollow sections, a section whose raw size is more than its virtual
 * one, sections with no bytes at all, an object of 0 to a few KB, and sizes at the exact edge
 * of each bound) with tables PLANTED in them: a props pair at every alignment, entries that
 * break at the first, the second and the last position, an unresolvable RVA, a 6 where the 5
 * belongs, decoys before the real one, and a 3.9 table whose entries are encrypted by the
 * rotating key with the wanted addresses in every order. EXPECT is the hash of the results the
 * unchanged walks gave over the same cases.
 *
 * AND WHAT IT COSTS, which is what the change is for: on an object with no `05 00 00 00` in it
 * the by_props scan makes one host call and reads nothing, and find_table makes a fifth of the
 * reads it did on any object (a source RVA it drops makes none of vmp_off_of's section loops).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define kof_strid_vmp_props_len 0
#ifndef VMP_SRC
#define VMP_SRC "../../bases/unp/vmprotect_pe.c"
#endif
#include VMP_SRC

#define EXPECT 0xdd204d45d0c83fe4ull

static unsigned s = 0x9e3779b1u;
static unsigned rnd(void) { s = s * 1103515245u + 12345u; return s >> 8; }
static uint64_t fold(uint64_t h, uint64_t v) { return (h ^ v) * 1099511628211ull; }
static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* The fake host: the object, and a call counter for each way a module reads it. */
static const uint8_t *obj;
static uint64_t obj_n;
static uint64_t n_rd8, n_rd32, n_rd64, n_find;

static uint8_t f_rd8(const struct kof_obj_ctx *c, uint64_t off)
{
	(void)c; n_rd8++;
	return off < obj_n ? obj[off] : 0;
}
static uint32_t f_rd32(const struct kof_obj_ctx *c, uint64_t off)
{
	uint32_t v = 0;

	(void)c; n_rd32++;
	if (off <= obj_n && obj_n - off >= 4)
		memcpy(&v, obj + off, 4);
	return v;
}
static uint64_t f_rd64(const struct kof_obj_ctx *c, uint64_t off)
{
	uint64_t v = 0;

	(void)c; n_rd64++;
	if (off <= obj_n && obj_n - off >= 8)
		memcpy(&v, obj + off, 8);
	return v;
}
/* What the host answers for the one declared string, `05 00 00 00`: where it is in
 * [off, off + len) clipped to the object, or KOF_BROKEN. */
static uint64_t f_find(const struct kof_obj_ctx *c, uint32_t id, uint64_t off, uint64_t len)
{
	static const uint8_t pat[4] = { 5, 0, 0, 0 };
	uint64_t i;

	(void)c; (void)id; n_find++;
	if (off >= obj_n)
		return KOF_BROKEN;
	if (len > obj_n - off)
		len = obj_n - off;
	for (i = 0; i + 4 <= len; i++)
		if (!memcmp(obj + off + i, pat, 4))
			return off + i;
	return KOF_BROKEN;
}

/* THE WALKS THE MODULE HAD, verbatim, over the same host. */
static int ref_by_props(const struct kof_obj_ctx *ctx, const struct kof_pe_info *pe,
			uint64_t image_end, struct vmp_tab *out)
{
	uint64_t at, end = ctx->obj_size;

	if (end < 24u)
		return 0;
	end -= 24u;
	for (at = 0; at <= end; at += 4u) {
		uint64_t po, e;
		uint32_t props, n = 0, last = 0;

		if (kof_u32(at + 4u) != VMP_PROPS_LEN)
			continue;
		po = vmp_off_of(pe, kof_u32(at));
		if (!po || !kof_in_obj(po, VMP_PROPS_LEN))
			continue;
		props = kof_u8(po);
		if (props > VMP_PROPS_MAX)
			continue;
		for (e = at + 8u; n < VMP_MAX_BLK && kof_in_obj(e, 8u); e += 8u) {
			uint32_t src = kof_u32(e);
			uint32_t dst = kof_u32(e + 4u);
			uint64_t so;

			if (dst < PEI_PAGE || (dst & (PEI_PAGE - 1u)) ||
			    dst >= image_end || (n && dst <= last))
				break;
			so = vmp_off_of(pe, src);
			if (!so || !kof_in_obj(so, 1u) || kof_u8(so) != 0u)
				break;
			if (!vmp_dst_empty(ctx, pe, dst))
				break;
			out->src[n] = src;
			out->dst[n] = dst;
			last = dst;
			n++;
		}
		if (n >= VMP_MIN_BLK) {
			out->n = n;
			out->props = props;
			return 1;
		}
	}
	return 0;
}

static int ref_find_table(const struct kof_obj_ctx *ctx, const struct kof_pe_info *pe,
			  const uint32_t *want, uint32_t n_want, struct vmp_tab *out)
{
	uint64_t at, end;

	if (n_want < VMP_MIN_BLK || n_want > VMP_MAX_BLK)
		return 0;
	end = ctx->obj_size;
	if (end < (uint64_t)n_want * 8u)
		return 0;
	end -= (uint64_t)n_want * 8u;
	for (at = 0; at <= end; at++) {
		uint32_t k, seed, ok = 0;

		if (!kof_in_obj(at, (uint64_t)n_want * 8u))
			continue;
		if (!vmp_lzma_here(ctx, pe, kof_u32(at)))
			continue;
		for (k = 1; k < n_want; k++)
			if (!vmp_lzma_here(ctx, pe, kof_u32(at + k * 8u)))
				break;
		if (k != n_want)
			continue;
		for (seed = 0; seed < n_want; seed++) {
			uint32_t key = kof_u32(at + 4u) ^ want[seed];
			uint32_t seen = 0;

			for (k = 0; k < n_want; k++) {
				uint32_t d = kof_u32(at + k * 8u + 4u) ^ vmp_rol(key, 7u * k);
				uint32_t j;

				for (j = 0; j < n_want; j++)
					if (want[j] == d)
						break;
				if (j == n_want || (seen & (1u << j)))
					break;
				if (!vmp_dst_empty(ctx, pe, d))
					break;
				seen |= 1u << j;
				out->src[k] = kof_u32(at + k * 8u);
				out->dst[k] = d;
			}
			if (k == n_want) {
				out->n = n_want;
				out->props = vmp_props_before(ctx, pe, at);
				ok = 1;
				break;
			}
		}
		if (ok)
			return 1;
	}
	return 0;
}

static struct kof_content host = { .rd8 = f_rd8, .rd32 = f_rd32, .rd64 = f_rd64, .find_str_where = f_find };

static void put32(uint8_t *b, uint64_t n, uint64_t at, uint32_t v)
{
	if (at <= n && n - at >= 4)
		memcpy(b + at, &v, 4);
}

static uint64_t fold_tab(uint64_t h, int r, const struct vmp_tab *t)
{
	uint32_t i;

	h = fold(h, (uint64_t)r);
	if (r) {
		h = fold(h, t->n);
		h = fold(h, t->props);
		for (i = 0; i < t->n && i < VMP_MAX_BLK; i++) {
			h = fold(h, t->src[i]);
			h = fold(h, t->dst[i]);
		}
	}
	return h;
}

static uint64_t pos_props, pos_table, ref_reads, new_reads, ord_find_calls, ord_cases, ft_ref32, ft_new64, ft_cases;

/* One random object, with a table planted in it of the kind `family` names. */
static uint64_t one(uint64_t n, unsigned family, uint64_t h)
{
	uint8_t *b = malloc(n + 16);
	struct kof_pe_info *pe = calloc(1, sizeof *pe);
	struct kof_obj_ctx ctx;
	struct vmp_tab t_ref, t_new;
	uint32_t want[VMP_MAX_BLK], n_want = 0, k, i;
	uint64_t image_end, i64;
	int r_ref, r_new;

	/* The sections: some hollow, some with bytes, one with a raw size over its virtual size. */
	pe->valid = 1;
	pe->sec_count = 1u + rnd() % 6u;
	for (i = 0; i < pe->sec_count; i++) {
		struct kof_pe_sec *sc = &pe->sec[i];
		unsigned kind = rnd() % 5u;

		sc->mem_rva = 0x1000u + 0x1000u * i + (rnd() % 8u == 0u ? 0x200u : 0u);
		sc->mem_size = 0x100u + rnd() % 0x2800u;
		if (kind < 2u || n < 64u) {
			sc->file_off = sc->file_size = 0;
		} else {
			sc->file_off = rnd() % (n - 8u);
			sc->file_size = 1u + rnd() % (n - sc->file_off);
			if (kind == 4u) {
				sc->file_off = rnd() % 64u;
				sc->file_size += 0x3000u;        /* more than it maps, and past the object */
			}
		}
		sc->characteristics = rnd() % 4u == 0u ? 0x80u : 0u;
		if (!sc->file_size && !sc->file_off && !(sc->characteristics & 0x80u) &&
		    sc->mem_size && n_want < VMP_MAX_BLK)
			want[n_want++] = (uint32_t)sc->mem_rva;
	}
	if (family == 4u && n >= 0x900u) {
		/* The one that makes the span matter: a section that holds more file bytes than it
		 * maps, every source RVA past its virtual size and inside its raw size. */
		pe->sec_count = 3;
		pe->sec[0].mem_rva = 0x1000; pe->sec[0].mem_size = 0x100;
		pe->sec[0].file_off = 64; pe->sec[0].file_size = 0x700; pe->sec[0].characteristics = 0;
		pe->sec[1].mem_rva = 0x3000; pe->sec[1].mem_size = 0x800;
		pe->sec[2].mem_rva = 0x5000; pe->sec[2].mem_size = 0x800;
		pe->sec[1].file_off = pe->sec[1].file_size = pe->sec[2].file_off = pe->sec[2].file_size = 0;
		pe->sec[1].characteristics = pe->sec[2].characteristics = 0;
		n_want = 2;
		want[0] = 0x3000; want[1] = 0x5000;
	}
	image_end = pei_image_end(pe);

	for (i64 = 0; i64 < n; i64++) {
		unsigned m = rnd() % 16u;

		b[i64] = family == 0u && m < 12u ? (uint8_t)(rnd() | 0x10u) & 0xfeu
		       : m < 6u ? 0 : m == 6u ? 5 : (uint8_t)rnd();
		if (family == 0u && b[i64] == 5)       /* an "ordinary" object holds no 05 at all */
			b[i64] = 0x55;
	}
	memset(&ctx, 0, sizeof ctx);
	ctx.obj_size = n;
	ctx.content = &host;
	obj = b;
	obj_n = n;

	if (family == 4u && n >= 0x900u) {
		uint32_t key = (uint32_t)rnd() * 2654435761u, srcx = 0x1000u + 0x100u + rnd() % 0x200u;
		uint64_t at = 0x300u + rnd() % 0x80u * 8u;

		memset(b + 64, 0, 0x700);
		for (k = 0; k < 2u; k++) {
			put32(b, n, at + 8u * k, srcx + k * 3u);
			put32(b, n, at + 8u * k + 4u, want[k] ^ vmp_rol(key, 7u * k));
		}
		put32(b, n, 0x100u, srcx);                  /* and a props pair with those sources */
		put32(b, n, 0x104u, 5u);
		put32(b, n, 0x108u, srcx);
		put32(b, n, 0x10cu, 0x3000u);
		put32(b, n, 0x110u, srcx + 1u);
		put32(b, n, 0x114u, 0x5000u);
		b[0x700u + 64u - 0x40u] = 0;
	}
	if (family >= 1u && family < 4u && n >= 64u) {
		/* A props pair at every alignment, with entries that are valid, or break at a place. */
		unsigned planted = 1u + rnd() % 3u;

		while (planted--) {
			uint64_t at = rnd() % (n - 24u + 1u);
			unsigned ne = 1u + rnd() % 4u, brk = rnd() % 8u;
			uint32_t last = 0;
			uint64_t po = 0, e;
			struct kof_pe_sec *sc;

			for (i = 0; i < pe->sec_count; i++) {
				sc = &pe->sec[i];
				if (sc->file_size && sc->file_off + 1u < n) {
					po = sc->file_off;
					put32(b, n, at, (uint32_t)sc->mem_rva);
					b[po] = (uint8_t)(rnd() % 8u == 0u ? 0xf0u : 0x5du);
					break;
				}
			}
			put32(b, n, at, po ? (uint32_t)pe->sec[i].mem_rva : 0xffff0000u);
			put32(b, n, at + 4u, brk == 7u ? 6u : 5u);
			for (k = 0, e = at + 8u; k < ne && e + 8u <= n; k++, e += 8u) {
				uint32_t dst = 0x1000u * (1u + k * 2u + rnd() % 2u), src = 0;

				for (i = 0; i < pe->sec_count; i++)
					if (pe->sec[i].file_size && pe->sec[i].file_off + 2u < n) {
						src = (uint32_t)pe->sec[i].mem_rva + (rnd() % 2u);
						if (pe->sec[i].file_size > pe->sec[i].mem_size && rnd() % 2u)
							src = (uint32_t)(pe->sec[i].mem_rva + pe->sec[i].mem_size + rnd() % 8u);
						if (rnd() % 4u != 0u) {
							uint64_t so = vmp_off_of(pe, src);

							if (so && so < n)
								b[so] = 0;
						}
						break;
					}
				if (brk == 3u && k == 1u)
					dst |= 0x10u;                       /* not page aligned */
				if (brk == 4u && k == 1u)
					dst = last;                         /* not ascending */
				if (brk == 5u && k + 1u == ne)
					dst = 0xfffff000u;                  /* past the image */
				put32(b, n, e, src);
				put32(b, n, e + 4u, dst);
				last = dst;
			}
		}
		/* A 3.9 table: n_want entries, each dst encrypted by the key rotated 7 bits more. */
		if (n_want >= 2u && n >= 8u * n_want + 8u) {
			uint32_t key = (uint32_t)rnd() * 2654435761u, ord[VMP_MAX_BLK];
			uint64_t at = rnd() % (n - 8u * n_want + 1u);

			for (k = 0; k < n_want; k++)
				ord[k] = k;
			for (k = n_want; k > 1u; k--) {
				uint32_t j = rnd() % k, tmp = ord[j];

				ord[j] = ord[k - 1u];
				ord[k - 1u] = tmp;
			}
			for (k = 0; k < n_want; k++) {
				uint32_t src = 0;

				for (i = 0; i < pe->sec_count; i++)
					if (pe->sec[i].file_size && pe->sec[i].file_off + 2u < n) {
						src = (uint32_t)pe->sec[i].mem_rva;
						if (pe->sec[i].file_size > pe->sec[i].mem_size && rnd() % 2u)
							src = (uint32_t)(pe->sec[i].mem_rva + pe->sec[i].mem_size + rnd() % 8u);
						break;
					}
				if (src) {
					uint64_t so = vmp_off_of(pe, src);

					if (so && so < n)
						b[so] = 0;
				}
				put32(b, n, at + 8u * k, rnd() % 9u ? src : src + 1u);
				put32(b, n, at + 8u * k + 4u,
				      (rnd() % 11u ? want[ord[k]] : want[ord[0]]) ^ vmp_rol(key, 7u * k));
			}
		}
	}

	/* The two scans against the walks they replaced. */
	memset(&t_ref, 0, sizeof t_ref);
	memset(&t_new, 0, sizeof t_new);
	n_rd8 = n_rd32 = n_rd64 = n_find = 0;
	r_ref = ref_by_props(&ctx, pe, image_end, &t_ref);
	ref_reads += n_rd32;
	n_rd8 = n_rd32 = n_rd64 = n_find = 0;
	r_new = vmp_find_by_props(&ctx, pe, image_end, &t_new);
	new_reads += n_rd32 + n_find;
	if (family == 0u && n >= 64u) {
		ord_cases++;
		ord_find_calls += n_find;
		CK(n_rd32 == 0 && n_find == 1);        /* no 05 00 00 00: one question, nothing read */
	}
	CK(r_ref == r_new);
	pos_props += r_ref != 0;
	if (r_ref == r_new && r_ref)
		CK(t_ref.n == t_new.n && t_ref.props == t_new.props &&
		   !memcmp(t_ref.src, t_new.src, t_ref.n * sizeof t_ref.src[0]) &&
		   !memcmp(t_ref.dst, t_new.dst, t_ref.n * sizeof t_ref.dst[0]));
	h = fold_tab(h, r_ref, &t_ref);

	memset(&t_ref, 0, sizeof t_ref);
	memset(&t_new, 0, sizeof t_new);
	n_rd8 = n_rd32 = n_rd64 = n_find = 0;
	r_ref = ref_find_table(&ctx, pe, want, n_want, &t_ref);
	{
		uint64_t ref32 = n_rd32;

		n_rd8 = n_rd32 = n_rd64 = n_find = 0;
		r_new = vmp_find_table(&ctx, pe, want, n_want, &t_new);
		if (n_want >= VMP_MIN_BLK && n >= 1000u && !r_ref) {
			ft_cases++;
			ft_ref32 += ref32;
			ft_new64 += n_rd64 + n_rd32;
		}
	}
	CK(r_ref == r_new);
	pos_table += r_ref != 0;
	if (r_ref == r_new && r_ref)
		CK(t_ref.n == t_new.n && t_ref.props == t_new.props &&
		   !memcmp(t_ref.src, t_new.src, t_ref.n * sizeof t_ref.src[0]) &&
		   !memcmp(t_ref.dst, t_new.dst, t_ref.n * sizeof t_ref.dst[0]));
	h = fold_tab(h, r_ref, &t_ref);

	free(b);
	free(pe);
	return h;
}

int main(void)
{
	uint64_t h = 1469598103934665603ull;
	unsigned f, i;
	static const uint64_t sizes[] = { 0, 1, 7, 8, 23, 24, 25, 31, 32, 40, 63, 64, 65, 100, 200, 513, 1000, 1001, 4096, 9000 };

	for (f = 0; f < 5u; f++)
		for (i = 0; i < 20u * 40u; i++) {
			uint64_t n = sizes[i % 20u];

			if (i % 20u >= 12u)
				n += rnd() % 700u;
			h = one(n, f, h);
		}
	printf("vmp_scan_diff: hash %016llx  by_props reads %llu -> %llu, find_table reads %llu -> %llu over %llu objects; tables found: by_props %llu, find_table %llu\n",
	       (unsigned long long)h, (unsigned long long)ref_reads, (unsigned long long)new_reads,
	       (unsigned long long)ft_ref32, (unsigned long long)ft_new64, (unsigned long long)ft_cases,
	       (unsigned long long)pos_props, (unsigned long long)pos_table);
	CK(ord_cases > 100 && ord_find_calls == ord_cases);
	CK(pos_props > 20 && pos_table > 40);          /* the planted tables are found, not only refused */
	CK(ft_cases > 50 && ft_new64 * 4u <= ft_ref32 + ft_ref32 / 8u);   /* about a fifth of the reads */
	CK(new_reads * 2u < ref_reads);
	if (EXPECT)
		CK(h == EXPECT);
	printf("%s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
