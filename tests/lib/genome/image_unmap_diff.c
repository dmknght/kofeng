/*
 * image_unmap_diff - kgenome_pe_unmap against an independent second implementation (round 2, fix_engine2).
 *
 * The unmapper was covered 92% by the suite and 86% of its branches, and the half that was not is the half
 * a hostile image reaches: a section table that does not fit, headers longer than the file they describe,
 * a relocation directory outside the image, a block that does not advance, entries in no section, types
 * the unmapper does not handle, a preferred base that does not fit the header it is written into. A table of
 * hand-picked cases cannot say it ran them all, so this runs the function and a second one - written below
 * from the documented behaviour (pe_unmap.h and the notes in pe_unmap.c), sharing no code with it - over
 * images drawn from a fixed-seed generator: the output bytes, the length and every counter of the info
 * must agree, for every image, whether the call succeeds or refuses.
 *
 * The generator draws header fields near their plausible values most of the time and at hostile values the
 * rest (a count of zero, 96 sections, an optional header of 95 bytes, a size of headers of 2^32 - 1, a
 * relocation block of 7 bytes, an RVA at the end of the image), in both widths, so each refusal and each
 * clip of the function is hit by many images.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"
#include "image_kit.h"

#define IMG_N 0x3000u

static struct hk_rng rng;

static uint32_t rnd(uint32_t n) { return hk_below(&rng, n); }

/* ---- the second implementation -------------------------------------------------------------- */

struct ref_info {
	uint64_t image_base, hdr_image_base, mapped_at;
	int64_t delta;
	uint32_t undone, skipped, sections, sections_short;
	uint8_t base_told, base_ambiguous;
};

static int r16(const uint8_t *b, uint64_t n, uint64_t at, uint32_t *v)
{
	if (at > n || n - at < 2u) return 0;
	*v = (uint32_t)b[at] | (uint32_t)b[at + 1] << 8;
	return 1;
}

static int r32(const uint8_t *b, uint64_t n, uint64_t at, uint32_t *v)
{
	if (at > n || n - at < 4u) return 0;
	*v = (uint32_t)b[at] | (uint32_t)b[at + 1] << 8 | (uint32_t)b[at + 2] << 16 | (uint32_t)b[at + 3] << 24;
	return 1;
}

static int r64(const uint8_t *b, uint64_t n, uint64_t at, uint64_t *v)
{
	uint32_t lo, hi;

	if (!r32(b, n, at, &lo) || !r32(b, n, at + 4u, &hi)) return 0;
	*v = (uint64_t)hi << 32 | lo;
	return 1;
}

struct rsec { uint64_t rva, vsize, raw, ptr; };

/* returns 1 and fills `out`/`out_len` (malloc'd), or 0 for a refusal */
static int ref_unmap(const uint8_t *img, uint64_t n, uint64_t mapped_at, uint64_t pref, uint64_t cap, uint8_t **out,
		     uint64_t *out_len, struct ref_info *ri)
{
	uint32_t v, nsec, optsz, soh, claim, i;
	uint64_t lfanew, at, opt, base_img, sec_tab, dir_base = 0, file_len, hdr_copy, base;
	int plus;
	struct rsec *sec;
	uint8_t *file;
	int64_t delta;
	uint32_t ndirs = 0;

	memset(ri, 0, sizeof *ri);
	if (!r16(img, n, 0, &v) || v != 0x5a4d) return 0;
	if (!r32(img, n, 0x3c, &v)) return 0;
	lfanew = v;
	if (!r32(img, n, lfanew, &v) || v != 0x4550) return 0;
	at = lfanew;
	if (!r16(img, n, at + 6, &nsec) || !nsec) return 0;
	if (!r16(img, n, at + 20, &optsz) || optsz < 96) return 0;
	opt = at + 24;
	if (!r16(img, n, opt, &v)) return 0;
	if (v != 0x20b && v != 0x10b) return 0;
	plus = v == 0x20b;
	if (plus) { if (!r64(img, n, opt + 24, &base_img)) return 0; }
	else { if (!r32(img, n, opt + 28, &v)) return 0; base_img = v; }
	if (!r32(img, n, opt + 60, &soh)) return 0;
	{
		const uint64_t cnt = plus ? 108 : 92, db = plus ? 112 : 96;

		if (optsz > cnt && r32(img, n, opt + cnt, &claim)) {
			uint64_t room = optsz > db ? (optsz - db) / 8u : 0u;
			uint64_t c = claim > 16u ? 16u : claim;

			ndirs = (uint32_t)(c > room ? room : c);
		}
		dir_base = opt + db;
	}
	sec_tab = opt + optsz;
	if (sec_tab > n || (uint64_t)nsec * 40u > n - sec_tab) return 0;
	sec = calloc(nsec, sizeof *sec);
	if (!sec) return 0;
	for (i = 0; i < nsec; i++) {
		uint32_t a, b, c, d;
		uint64_t s = sec_tab + 40ull * i;

		if (!r32(img, n, s + 8, &a) || !r32(img, n, s + 12, &b) || !r32(img, n, s + 16, &c) || !r32(img, n, s + 20, &d)) { free(sec); return 0; }
		sec[i].vsize = a; sec[i].rva = b; sec[i].raw = c; sec[i].ptr = d;
	}
	file_len = soh;
	if (file_len < sec_tab + 40ull * nsec) file_len = sec_tab + 40ull * nsec;
	for (i = 0; i < nsec; i++) {
		uint64_t e;

		if (!sec[i].raw) continue;
		e = sec[i].ptr + sec[i].raw;                    /* both 32-bit: no wrap in 64 */
		if (e > file_len) file_len = e;
	}
	if (!file_len || file_len > cap) { free(sec); return 0; }
	file = calloc(1, (size_t)file_len);
	if (!file) { free(sec); return 0; }
	hdr_copy = soh > n ? n : soh;
	if (hdr_copy > file_len) hdr_copy = file_len;
	memcpy(file, img, (size_t)hdr_copy);
	for (i = 0; i < nsec; i++) {
		uint64_t have;

		if (!sec[i].raw || sec[i].ptr >= file_len) continue;
		have = sec[i].rva >= n ? 0 : (n - sec[i].rva < sec[i].raw ? n - sec[i].rva : sec[i].raw);
		if (have < sec[i].raw) ri->sections_short++;
		if (!have) continue;
		if (have > file_len - sec[i].ptr) have = file_len - sec[i].ptr;
		memcpy(file + sec[i].ptr, img + sec[i].rva, (size_t)have);
	}
	base = pref ? pref : base_img;
	delta = mapped_at ? (int64_t)(mapped_at - base) : 0;
	if (pref) {
		uint64_t pos = plus ? opt + 24 : opt + 28;
		uint32_t w = plus ? 8u : 4u, k;

		if (pos + w <= file_len && pos + w <= hdr_copy)
			for (k = 0; k < w; k++) file[pos + k] = (uint8_t)(pref >> (8u * k));
	}
	ri->image_base = base; ri->hdr_image_base = base_img; ri->mapped_at = mapped_at; ri->delta = delta;
	ri->sections = nsec; ri->base_told = pref ? 1 : 0;
	{
		int has = 0;

		if (ndirs > 5) {
			uint32_t a, l;

			if (r32(img, n, dir_base + 40, &a) && r32(img, n, dir_base + 44, &l))
				has = l != 0 && (a <= n && l <= n - a);
		}
		ri->base_ambiguous = (!pref && mapped_at && mapped_at == base_img && has) ? 1 : 0;
	}
	if (delta && ndirs > 5) {
		uint32_t a, l;

		if (r32(img, n, dir_base + 40, &a) && r32(img, n, dir_base + 44, &l) && l && a <= n && l <= n - a) {
			uint64_t p = a, end = (uint64_t)a + l;

			while (p + 8 <= end) {
				uint32_t page, blk;
				uint64_t e;

				if (!r32(img, n, p, &page) || !r32(img, n, p + 4, &blk)) break;
				if (blk < 8 || p + blk > end) break;
				for (e = p + 8; e + 2 <= p + blk; e += 2) {
					uint32_t ent, type, k;
					uint64_t rva, off = UINT64_MAX;

					if (!r16(img, n, e, &ent)) goto done;
					type = ent >> 12;
					if (type == 0) continue;
					rva = (uint64_t)page + (ent & 0xfff);
					for (k = 0; k < nsec; k++) {
						uint64_t span = sec[k].vsize > sec[k].raw ? sec[k].vsize : sec[k].raw;

						if (!span || rva < sec[k].rva || rva - sec[k].rva >= span) continue;
						if (rva - sec[k].rva >= sec[k].raw) break;
						off = sec[k].ptr + (rva - sec[k].rva);
						break;
					}
					if (off == UINT64_MAX) { ri->skipped++; continue; }
					if (type == 3 && off + 4 <= file_len) {
						uint32_t x;

						memcpy(&x, file + off, 4);
						x = x - (uint32_t)(uint64_t)delta;
						memcpy(file + off, &x, 4);
						ri->undone++;
					} else if (type == 10 && off + 8 <= file_len) {
						uint64_t x;

						memcpy(&x, file + off, 8);
						x = x - (uint64_t)delta;
						memcpy(file + off, &x, 8);
						ri->undone++;
					} else {
						ri->skipped++;
					}
				}
				p += blk;
			}
		}
	}
done:
	free(sec);
	*out = file;
	*out_len = file_len;
	return 1;
}

/* ---- the generator --------------------------------------------------------------------------- */

static uint8_t img[IMG_N];
static uint64_t gen_base;      /* the ImageBase the generator wrote */

static uint32_t pick32(uint32_t plausible)
{
	switch (rnd(12)) {
	case 0: return 0;
	case 1: return 0xffffffffu;
	case 2: return plausible + 1u;
	case 3: return plausible ? plausible - 1u : 0;
	case 4: return rnd(IMG_N * 2u);
	default: return plausible;
	}
}

static void gen(int plus)
{
	struct ik_pe p;
	uint32_t i, ns = 1u + rnd(5), optsz, rec;

	memset(&p, 0, sizeof p);
	p.plus = plus;
	p.n_dirs = rnd(8) ? 16u : rnd(20);
	optsz = rnd(5) ? (plus ? 240u : 224u) : 90u + rnd(170);
	p.optsz = optsz;
	p.lfanew = rnd(6) ? 0x80u : 0x40u + 8u * rnd(40);
	p.image_base = rnd(3) ? 0 : ((uint64_t)rnd(0x7fffffffu) << (plus ? 8 : 0)) & (plus ? ~0ull : 0xffffffffull);
	p.size_of_headers = pick32(0x400);
	p.size_of_image = IMG_N;
	p.entry = 0x1000;
	for (i = 0; i < ns; i++) {
		uint32_t rva = 0x400u + 0x400u * i;

		ik_sec(&p, ".s", pick32(0x200), pick32(rva), pick32(0x200), pick32(rva), rnd(2) ? IK_TEXT : IK_DATA);
		p.s[i].name[1] = (char)('a' + i);
	}
	if (rnd(10) == 0) p.nsec_claim = 1u + rnd(200);
	memset(img, 0, sizeof img);
	gen_base = p.image_base ? p.image_base : (plus ? 0x140000000ull : 0x400000ull);
	if (!plus)
		gen_base &= 0xffffffffull;
	/* a table past the buffer is a refusal both sides agree on; the writer is bounded by the buffer's slack */
	if (p.lfanew + 24u + optsz + 40u * ns + 40u < IMG_N)
		(void)ik_pe_write(img, &p);
	/* a relocation table in the image: one to three blocks, entries of every type, some outside any section */
	rec = 0x2000u;
	if (rnd(8)) {
		uint32_t blocks = 1u + rnd(3), at = rec, b;
		uint8_t *dir = img + p.lfanew + 24u + (plus ? 112u : 96u);

		for (b = 0; b < blocks && at + 8u + 2u * 12u < IMG_N; b++) {
			uint32_t cnt = 1u + rnd(10), k, blk = 8u + 2u * cnt;

			ik_w32(img + at, 0x400u * (1u + rnd(5)));
			ik_w32(img + at + 4, rnd(10) ? blk : rnd(12));
			for (k = 0; k < cnt; k++) {
				static const uint16_t types[] = { 3, 10, 0, 1, 2, 4, 5, 9, 15 };
				uint16_t t = rnd(4) ? types[rnd(3)] : types[rnd(9)];

				ik_w16(img + at + 8 + 2u * k, (uint16_t)((uint32_t)t << 12 | rnd(0x1000)));
			}
			at += blk + (rnd(6) ? 0u : 2u);
		}
		if (p.lfanew + 24u + (plus ? 112u : 96u) + 8u * 6u <= IMG_N) {
			ik_w32(dir + 5 * 8, rec);
			ik_w32(dir + 5 * 8 + 4, rnd(10) ? at - rec : pick32(at - rec));
		}
	}
	/* bytes in the sections: the relocated words */
	for (i = 0x400; i + 8 < 0x2000; i += 4)
		if (rnd(5) == 0) ik_w32(img + i, rnd(0x7fffffffu));
}

static int same(const struct kgenome_pe_unmap_info *a, const struct ref_info *b)
{
	return a->image_base == b->image_base && a->hdr_image_base == b->hdr_image_base && a->mapped_at == b->mapped_at &&
	       a->delta == b->delta && a->relocs_undone == b->undone && a->relocs_skipped == b->skipped &&
	       a->sections == b->sections && a->sections_short == b->sections_short && a->base_told == b->base_told &&
	       a->base_ambiguous == b->base_ambiguous;
}

int main(int argc, char **argv)
{
	unsigned it, total, ok_n = 0, refused = 0, with_relocs = 0, short_n = 0, ambiguous = 0, trimmed = 0;
	int before;

	hk_args(argc, argv);
	rng.s = 0x2468ace013579bdfull;
	total = 20000u * hk_scale();
	before = hk_fails;
	for (it = 0; it < total; it++) {
		const int plus = (int)rnd(2);
		uint64_t mapped = rnd(4) ? (0x10000000u + 0x1000u * rnd(0x100)) : (rnd(2) ? 0 : 0xffffffffffff0000ull);
		uint64_t pref = rnd(3) ? 0 : (0x400000u + 0x1000u * rnd(0x40));
		const uint64_t cap = rnd(6) ? (1ull << 30) : (uint64_t)(0x400 + rnd(0x3000));
		struct kgenome_pe_unmap_info ui;
		struct ref_info ri;
		uint8_t *got = NULL, *want = NULL;
		uint64_t got_n = 0, want_n = 0;
		int a, b;

		gen(plus);
		/* the Windows loader writes the address it mapped at into the header's ImageBase: draw that often */
		if (rnd(3) == 0) {
			mapped = gen_base;
			if (rnd(3) == 0)
				pref = 0;
		}
		a = kgenome_pe_unmap(kof_buf_make(img, IMG_N), mapped, pref, cap, &got, &got_n, &ui);
		b = ref_unmap(img, IMG_N, mapped, pref, cap, &want, &want_n, &ri);
		if (a != b) {
			printf("  image %u: unmap answered %d, the reference %d\n", it, a, b);
			CK(a == b);
			free(got); free(want);
			continue;
		}
		if (!a) {
			refused++;
			continue;
		}
		ok_n++;
		if (got_n != want_n || memcmp(got, want, (size_t)want_n)) {
			printf("  image %u: output differs (len %llu vs %llu)\n", it, (unsigned long long)got_n, (unsigned long long)want_n);
			CK(0);
		}
		if (!same(&ui, &ri)) {
			printf("  image %u: info differs: undone %u/%u skipped %u/%u short %u/%u base_told %u/%u amb %u/%u delta %lld/%lld\n", it,
			       ui.relocs_undone, ri.undone, ui.relocs_skipped, ri.skipped, ui.sections_short, ri.sections_short,
			       ui.base_told, ri.base_told, ui.base_ambiguous, ri.base_ambiguous, (long long)ui.delta, (long long)ri.delta);
			CK(0);
		}
		with_relocs += ri.undone != 0;
		short_n += ri.sections_short != 0;
		ambiguous += ri.base_ambiguous;
		trimmed += ri.skipped != 0;
		free(got);
		free(want);
		if (hk_fails > before + 10)
			break;
	}
	printf("image_unmap_diff: %u images, %u unmapped, %u refused; %u with relocations undone, %u with skipped entries, "
	       "%u with short sections, %u ambiguous\n", it, ok_n, refused, with_relocs, trimmed, short_n, ambiguous);
	/* the generator has to reach what it is for: every one of these happens in a fair share of the images */
	CK(ok_n > total / 10u && refused > total / 20u);
	CK(with_relocs > total / 50u && trimmed > total / 50u && short_n > total / 100u);
	if (hk_fails) {
		printf("image_unmap_diff: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("image_unmap_diff: ok\n");
	return 0;
}
