#define _GNU_SOURCE
/*
 * normalizer_view_state - the pieces a view is made of and what it inherits, one
 * at a time and without a scan.
 *
 *   BIT MAPS       sx_bits_set against a bit-at-a-time loop over every (from, to)
 *                  of a 200-bit map and two starting contents; sx_norm_keep_bits
 *                  against the regions it is given, a region that runs past the
 *                  object, one that starts past it, and one whose end wraps
 *   KEEP           what a real parse of the objects of normalizer_fx.h keeps:
 *                  headers, and of code only the executable SECTIONS (an ELF with
 *                  a section table) or the whole segment (stripped), and of a PE
 *                  the sections that are not writable. The regions come out of the
 *                  parser as a partition of the object (sx_norm_gather).
 *   WHAT A SOURCE  declares: a description, regions, symbols, functions, a kind, a
 *   CARRIES        language, a label - copied (the caller's buffer is free to move),
 *                  replaced by a second declaration, refused for a NULL
 *   WHAT A VIEW    kof_prod_publish gives the parent's analysis to every normalised
 *   INHERITS       child that has a description, and only to those; adopt points
 *                  the scanner at it and latches every product so nothing is
 *                  derived from the view's bytes; unadopt lets go and leaves the
 *                  scanner's own state alone
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "normalizer_ref.h"
#include "normalizer_fx.h"
#include "../../libkofeng/scanners/scan_int.h"
#include "../../libkofeng/scanners/objprod.h"
#include "../../libkofeng/scanners/objsrc.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"
#include "../../libkofeng/kofcore/kofmod/pe.h"

/* ---- bit maps -------------------------------------------------------------------- */

static void bits_set_every_pair(void)
{
	unsigned from, to, init;

	for (init = 0; init < 3u; init++) {
		for (from = 0; from <= 200u; from += 1) {
			for (to = from; to <= 200u; to++) {
				uint8_t a[32], b[32];
				unsigned i;

				memset(a, init == 0 ? 0x00 : init == 1 ? 0xff : 0xa5, sizeof a);
				memcpy(b, a, sizeof a);
				sx_bits_set(a, from, to);
				for (i = from; i < to; i++)
					b[i >> 3] |= (uint8_t)(1u << (i & 7u));
				NCKF(!memcmp(a, b, sizeof a), "init %u [%u,%u)", init, from, to);
			}
		}
	}
	/* an empty or reversed range, and no map, change nothing */
	{
		uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, b[8];

		memcpy(b, a, sizeof a);
		sx_bits_set(a, 20, 20);
		sx_bits_set(a, 30, 10);
		sx_bits_set(NULL, 0, 64);
		NCK(!memcmp(a, b, sizeof a));
	}
}

static void keep_bits_regions(void)
{
	struct kof_src_region r[6];
	uint8_t keep[16];
	unsigned i;

	memset(keep, 0xaa, sizeof keep);               /* it clears what it is given */
	r[0].mask = 1u << 1; r[0].off = 8;  r[0].len = 16;      /* headers */
	r[1].mask = 1u << 2; r[1].off = 40; r[1].len = 10;      /* code */
	r[2].mask = 1u << 3; r[2].off = 60; r[2].len = 10;      /* data: not kept */
	r[3].mask = 1u << 2; r[3].off = 100; r[3].len = 1000;   /* runs past the object (n = 128) */
	r[4].mask = 1u << 2; r[4].off = 200; r[4].len = 5;      /* starts past it */
	r[5].mask = 1u << 1; r[5].off = 0;  r[5].len = 0;       /* empty */
	sx_norm_keep_bits(keep, 128, r, 6, NORM_KEEP_MASK);
	for (i = 0; i < 128u; i++) {
		int want = (i >= 8u && i < 24u) || (i >= 40u && i < 50u) || (i >= 100u);

		NCKF(((keep[i >> 3] >> (i & 7u)) & 1u) == (unsigned)want, "byte %u", i);
	}
	/* a mask of zero keeps nothing */
	sx_norm_keep_bits(keep, 128, r, 6, 0u);
	for (i = 0; i < 16u; i++)
		NCK(keep[i] == 0);
	/* an object of 0 bytes touches no map byte */
	memset(keep, 0x77, sizeof keep);
	sx_norm_keep_bits(keep, 0, r, 6, NORM_KEEP_MASK);
	NCK(keep[0] == 0x77);
	/*
	 * A region whose end wraps 2^64 is kept to the end of the object. The clip is by
	 * the room left, as sx_norm_keep_exec and the library cut beside it do; it was
	 * `e = off + len`, which a length near 2^64 wraps to a small number - the range
	 * was then empty and a hostile extent kept nothing. The regions come from the
	 * parser, which clamps them to the object, so no scan reached it.
	 */
	r[0].mask = 1u << 2; r[0].off = 64; r[0].len = UINT64_MAX - 10u;
	sx_norm_keep_bits(keep, 128, r, 1, NORM_KEEP_MASK);
	NCK(((keep[10] >> 0) & 1u) && ((keep[15] >> 7) & 1u) && !((keep[7] >> 7) & 1u));
	r[0].off = 127; r[0].len = UINT64_MAX;
	sx_norm_keep_bits(keep, 128, r, 1, NORM_KEEP_MASK);
	NCK(((keep[15] >> 7) & 1u) && !((keep[15] >> 6) & 1u));
}

/* ---- the regions of a parsed object, and what is kept of them -------------------------- */

static unsigned char view_buf[1u << 22];
static uint8_t img2[1u << 16];

static int parse_ctx(const uint8_t *b, uint64_t n, struct kof_obj_ctx *ctx)
{
	const struct kof_parser *pl;
	uint32_t np, i;

	memset(ctx, 0, sizeof *ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(kof_buf_make(b, n)) && pl[i].parse &&
		    pl[i].parse(kof_buf_make(b, n), view_buf, ctx))
			return 1;
	return 0;
}

static int bit(const uint8_t *m, uint64_t i)
{
	return (m[i >> 3] >> (i & 7u)) & 1u;
}

/* the regions are a partition of the object: every byte in exactly one */
static void partition(const struct kof_src_region *r, uint32_t nr, uint64_t n, const char *what)
{
	static uint8_t cover[1u << 16];
	uint32_t i;
	uint64_t b;
	unsigned over = 0, gaps = 0;

	memset(cover, 0, (size_t)n);
	for (i = 0; i < nr; i++)
		for (b = r[i].off; b < r[i].off + r[i].len && b < n; b++)
			cover[b]++;
	for (b = 0; b < n; b++) {
		over += cover[b] > 1u;
		gaps += cover[b] == 0u;
	}
	NCKF(!over && !gaps, "%s: %u bytes in two regions, %u in none", what, over, gaps);
}

static void keep_of_real_objects(void)
{
	struct kof_obj_ctx ctx;
	struct kof_src_region r[KOF_SRC_MAX_REGIONS];
	uint8_t keep[1u << 13];
	struct fx f;
	struct fx_at at;
	uint64_t n, i;
	uint32_t nr;
	unsigned fmt;

	for (fmt = 0; fmt < 5u; fmt++) {
		/* 0 ELF with sections, 1 ELF stripped, 2 PE (.text R+X), 3 PE (.text RWX), 4 PE (.text R+X, no data zeros) */
		memset(&f, 0, sizeof f);
		f.code_extra = 100;
		f.sections = fmt == 0u;
		f.gap_text = 50; f.gap_code = 30; f.data_zeros = 20; f.gap_end = 40;
		f.text_flags = fmt == 3u ? 0xe0000020u : 0u;
		n = fmt < 2u ? fx_elf(img2, &f, &at) : fx_pe(img2, &f, &at);
		NCKF(parse_ctx(img2, n, &ctx), "fmt %u: no parse", fmt);
		nr = sx_norm_gather(&ctx, r, KOF_SRC_MAX_REGIONS);
		NCK(nr >= 4u && nr <= KOF_SRC_MAX_REGIONS);
		partition(r, nr, n, fmt == 0u ? "ELF+sections" : fmt == 1u ? "ELF stripped" : "PE");
		/* a capacity smaller than the answer is a short answer, not a write past it */
		{
			struct kof_src_region two[2];

			NCK(sx_norm_gather(&ctx, two, 2u) <= 2u);
			NCK(sx_norm_gather(&ctx, two, 0u) == 0u);
		}
		memset(keep, 0, sizeof keep);
		sx_norm_keep_bits(keep, n, r, nr, NORM_KEEP_MASK);
		if (fmt < 2u && ctx.file_header)
			sx_norm_keep_exec(keep, n, kof_elf(&ctx), r, nr);
		if (fmt >= 2u && ctx.file_header)
			sx_norm_keep_exec_pe(keep, n, kof_pe(&ctx), r, nr);
		for (i = 0; i < n; i++) {
			int want;

			if (fmt == 0u)           /* headers; of code only .text; the section table */
				want = i < 0xb0u || (i >= at.code_off && i < at.code_off + at.code_n) ||
				       (i >= at.sh_off && i < at.sh_off + 256u);
			else if (fmt == 1u)      /* headers and the whole code segment */
				want = i < at.code_off + at.code_n;
			else if (fmt == 3u)      /* headers only: a writable section is rewritten */
				want = i < 472u;
			else                     /* headers and the code section (raw size, padding too) */
				want = i < 472u || (i >= at.code_off && i < at.code_off + 512u);
			NCKF(bit(keep, i) == want, "fmt %u byte %llu: kept %d, expected %d", fmt,
			     (unsigned long long)i, bit(keep, i), want);
		}
		/* the rule that matters for the collapse: zeros before the code are free
		 * only where something other than the code owns them */
		if (fmt == 0u)
			NCK(!bit(keep, 0xb0u + 10u) && bit(keep, at.code_off));
		if (fmt == 1u)
			NCK(bit(keep, 0xb0u + 10u));
	}
	/* a hostile segment (p_filesz and p_memsz of 2^64-1) is clamped by the parse
	 * before it reaches the maps: nothing kept past the object, nothing missed */
	memset(&f, 0, sizeof f);
	f.code_extra = 100;
	n = fx_elf(img2, &f, &at);
	fx_put64(img2, 64 + 32, UINT64_MAX);
	fx_put64(img2, 64 + 40, UINT64_MAX);
	if (parse_ctx(img2, n, &ctx)) {
		nr = sx_norm_gather(&ctx, r, KOF_SRC_MAX_REGIONS);
		for (i = 0; i < nr; i++)
			NCKF(r[i].off + r[i].len >= r[i].off && r[i].off + r[i].len <= n,
			     "region %llu+%llu of an object of %llu bytes", (unsigned long long)r[i].off,
			     (unsigned long long)r[i].len, (unsigned long long)n);
	}
}

/* The edges of the two keep passes: a code region smaller than a map byte, one past the
 * object, one whose length is 2^64-1, a section the table puts past the end or gives
 * a size no object holds, no section table at all, an unparsed PE. */
static void keep_exec_edges(void)
{
	static struct kgenome_elf_info ei;
	static struct kgenome_pe_info pi;
	struct kof_obj_ctx ctx;
	struct kof_src_region r[3];
	uint8_t keep[1u << 8];
	struct fx f;
	struct fx_at at;
	uint64_t n;
	unsigned i;

	memset(&f, 0, sizeof f);
	f.code_extra = 100;
	f.sections = 1;
	n = fx_elf(img2, &f, &at);
	NCK(parse_ctx(img2, n, &ctx));
	ei = *kof_elf(&ctx);
	NCK(ei.sec_count >= 3u);
	/* a code region of two bytes, inside one map byte: cleared, then .text given back */
	memset(keep, 0xff, sizeof keep);
	r[0].mask = (uint32_t)KGENOME_SCAN_ELF_CODE; r[0].off = 3; r[0].len = 2;
	sx_norm_keep_exec(keep, n, &ei, r, 1);
	NCK(!bit(keep, 3) && !bit(keep, 4) && bit(keep, 2) && bit(keep, 5));
	NCK(bit(keep, at.code_off) && bit(keep, at.code_off + at.code_n - 1u));
	/* a region past the object is skipped; one that runs to 2^64-1 clears to the end */
	memset(keep, 0xff, sizeof keep);
	r[0].off = n + 10u; r[0].len = 5;
	r[1].mask = (uint32_t)KGENOME_SCAN_ELF_CODE; r[1].off = 600; r[1].len = UINT64_MAX;
	r[2].mask = (uint32_t)KGENOME_SCAN_ELF_DATA; r[2].off = 0; r[2].len = 100;     /* not code */
	sx_norm_keep_exec(keep, n, &ei, r, 3);
	for (i = 0; i < n; i++)
		NCKF(bit(keep, i) == (i < 600u || (i >= at.code_off && i < at.code_off + at.code_n)),
		     "byte %u", i);
	/* no section table: the whole of CODE stays as it was */
	{
		struct kgenome_elf_info none = ei;

		none.sec_count = 0;
		memset(keep, 0xff, sizeof keep);
		sx_norm_keep_exec(keep, n, &none, r, 3);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i));
		sx_norm_keep_exec(keep, n, NULL, r, 3);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i));
	}
	/* a section that cannot be placed gives nothing back, one of size 2^64-1 is clipped */
	{
		struct kgenome_elf_info hs = ei;
		unsigned k;

		for (k = 0; k < hs.sec_count && k < KGENOME_ELF_MAX_SECTIONS; k++) {
			if (!kgenome_elf_sec_is_code(&hs.sec[k]))
				continue;
			hs.sec[k].file_off = n + 50u;
			hs.sec[k].claim_off = n + 50u;
		}
		memset(keep, 0xff, sizeof keep);
		r[0].mask = (uint32_t)KGENOME_SCAN_ELF_CODE; r[0].off = 176; r[0].len = 163;
		sx_norm_keep_exec(keep, n, &hs, r, 1);
		for (i = 176; i < 339u; i++)
			NCKF(!bit(keep, i), "byte %u of a code region whose section is past the object", i);
		hs = ei;
		for (k = 0; k < hs.sec_count && k < KGENOME_ELF_MAX_SECTIONS; k++)
			if (kgenome_elf_sec_is_code(&hs.sec[k]))
				hs.sec[k].file_size = UINT64_MAX;
		memset(keep, 0, sizeof keep);
		sx_norm_keep_exec(keep, n, &hs, r, 1);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i) == (i >= at.code_off));
	}

	/* the PE half */
	memset(&f, 0, sizeof f);
	f.code_extra = 100;
	f.text_flags = 0xe0000020u;                /* .text is writable: its bytes are rewritten */
	n = fx_pe(img2, &f, &at);
	NCK(parse_ctx(img2, n, &ctx));
	pi = *kof_pe(&ctx);
	memset(keep, 0xff, sizeof keep);
	sx_norm_keep_exec_pe(keep, n, &pi, NULL, 0);
	for (i = 0; i < n; i++)
		NCKF(bit(keep, i) == !(i >= at.code_off && i < at.code_off + 512u), "pe byte %u", i);
	{
		struct kgenome_pe_info hp = pi;
		unsigned k;

		for (k = 0; k < hp.sec_count && k < KGENOME_PE_MAX_SECTIONS; k++)
			if (hp.sec[k].perm & KGENOME_PE_PERM_W) {
				hp.sec[k].claim_len = UINT64_MAX;
				hp.sec[k].claim_off = at.code_off;
			}
		memset(keep, 0xff, sizeof keep);
		sx_norm_keep_exec_pe(keep, n, &hp, NULL, 0);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i) == (i < at.code_off));
		for (k = 0; k < hp.sec_count && k < KGENOME_PE_MAX_SECTIONS; k++)
			hp.sec[k].claim_off = n + 5u;
		memset(keep, 0xff, sizeof keep);
		sx_norm_keep_exec_pe(keep, n, &hp, NULL, 0);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i));
		for (k = 0; k < hp.sec_count && k < KGENOME_PE_MAX_SECTIONS; k++) {
			hp.sec[k].claim_off = 100;
			hp.sec[k].claim_len = 0;
		}
		sx_norm_keep_exec_pe(keep, n, &hp, NULL, 0);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i));
		hp.valid = 0;
		sx_norm_keep_exec_pe(keep, n, &hp, NULL, 0);
		sx_norm_keep_exec_pe(keep, n, NULL, NULL, 0);
		for (i = 0; i < n; i++)
			NCK(bit(keep, i));
	}
	/* nothing to resolve regions with: nothing gathered */
	memset(&ctx, 0, sizeof ctx);
	NCK(sx_norm_gather(&ctx, r, 3) == 0);
}

/* ---- what a source carries ------------------------------------------------------------- */

static void source_declarations(void)
{
	struct kof_objsrc *s = kof_src_heap(malloc(64), 64), *none = NULL;
	uint8_t info[48], syms[32];
	struct kof_src_desc d, *got;
	const struct kof_src_desc *g2;
	struct kof_src_region reg[3];
	const struct kof_src_region *rp = NULL;
	struct kgenome_func fn[2], *fp;
	uint32_t n;
	uint8_t st = 9, sf = 9;
	const uint8_t *sp;
	unsigned i;

	CK(s != NULL);
	if (!s)
		return;
	/* a fresh source: no description, no regions, no kind, entry NONE */
	CK(kof_src_desc_of(s) == NULL);
	CK(kof_src_regions_of(s, &rp) == 0);
	CK(kof_src_kind_of(s) == 0 && kof_src_fmt_of(s) == 0 && kof_src_region_fmt_of(s) == 0);
	CK(kof_src_entry_of(s) == KOF_ENTRY_NONE);
	CK(!kof_src_lang_of(s, &st, &sf));
	CK(!strcmp(kof_src_label_of(s), ""));
	CK(kof_src_prod_of(s) == NULL);
	CK(kof_src_syms_of(s, &n) == NULL && n == 0);
	CK(kof_src_funcs_of(s, &n) == NULL && n == 0);
	/* every call takes a NULL source and says nothing */
	kof_src_declare_desc(none, NULL);
	kof_src_declare_regions(none, 1, NULL, 0);
	kof_src_declare_kind(none, 3);
	kof_src_declare_fmt(none, 3);
	kof_src_declare_entry(none, 3);
	kof_src_declare_lang(none, 1, 2);
	kof_src_declare_syms(none, syms, 4);
	kof_src_declare_funcs(none, fn, 1);
	kof_src_label(none, (const uint8_t *)"x", 1);
	CK(kof_src_desc_of(none) == NULL && kof_src_kind_of(none) == 0 && kof_src_entry_of(none) == KOF_ENTRY_NONE);
	CK(kof_src_label_of(none)[0] == 0 && kof_src_buf(none).p == NULL);

	/* a description is COPIED: the caller's struct and its info may change after */
	for (i = 0; i < sizeof info; i++)
		info[i] = (uint8_t)(i * 3u + 1u);
	memset(&d, 0, sizeof d);
	d.fmt = KOF_FMT_ELF;
	d.arch = 5;
	d.subtype = 2;
	d.entry_off = 0x1234;
	d.info = info;
	d.info_len = sizeof info;
	kof_src_declare_desc(s, &d);
	got = (struct kof_src_desc *)(void *)(uintptr_t)kof_src_desc_of(s);
	CK(got != NULL && got->fmt == KOF_FMT_ELF && got->arch == 5 && got->subtype == 2);
	CK(got && got->entry_off == 0x1234u && got->info_len == sizeof info);
	CK(got && got->info != (const void *)info && !memcmp(got->info, info, sizeof info));
	memset(info, 0xee, sizeof info);
	CK(got && ((const uint8_t *)got->info)[0] == 1u);
	/* a second declaration REPLACES it, a malformed one is ignored */
	d.entry_off = 99;
	d.info_len = 16;
	kof_src_declare_desc(s, &d);
	g2 = kof_src_desc_of(s);
	CK(g2 && g2->entry_off == 99u && g2->info_len == 16u);
	d.info = NULL;
	kof_src_declare_desc(s, &d);
	CK(kof_src_desc_of(s) && kof_src_desc_of(s)->entry_off == 99u);
	d.info = info;
	d.info_len = 0;
	kof_src_declare_desc(s, &d);
	CK(kof_src_desc_of(s)->entry_off == 99u);
	kof_src_declare_desc(s, NULL);
	CK(kof_src_desc_of(s)->entry_off == 99u);

	/* regions: copied, whatever their number, with the vocabulary they are in */
	for (i = 0; i < 3u; i++) {
		reg[i].mask = 1u << (i + 1u);
		reg[i].off = 10u * i;
		reg[i].len = 5u;
	}
	kof_src_declare_regions(s, KOF_FMT_PE, reg, 3);
	reg[0].off = 777;
	n = kof_src_regions_of(s, &rp);
	CK(n == 3 && rp && rp[0].off == 0 && rp[2].off == 20u && kof_src_region_fmt_of(s) == KOF_FMT_PE);
	{
		struct kof_src_region many[40];

		for (i = 0; i < 40u; i++) {
			many[i].mask = 2u;
			many[i].off = i;
			many[i].len = 1;
		}
		/* a table is as long as the producer's: it used to be clipped to sixteen, silently, and the
		 * extents past them were not in the view (norm_defect_engine N3) */
		CK(kof_src_declare_regions(s, KOF_FMT_ELF, many, 40) == 1);
		CK(kof_src_regions_of(s, &rp) == 40u && rp[39].off == 39u && rp[0].off == 0u);
		CK(kof_src_declare_regions(s, KOF_FMT_PE, NULL, 3) == 1);       /* no table: unchanged */
		CK(kof_src_regions_of(s, NULL) == 40u && kof_src_region_fmt_of(s) == KOF_FMT_ELF);
	}

	/* symbols and functions: copied, replaced, refused when empty */
	for (i = 0; i < sizeof syms; i++)
		syms[i] = (uint8_t)i;
	kof_src_declare_syms(s, syms, sizeof syms);
	syms[0] = 0xff;
	sp = kof_src_syms_of(s, &n);
	CK(sp && n == sizeof syms && sp[0] == 0 && sp[31] == 31u);
	kof_src_declare_syms(s, syms, 0);
	kof_src_declare_syms(s, NULL, 8);
	CK(kof_src_syms_of(s, &n) == sp && n == sizeof syms);
	kof_src_declare_syms(s, syms, 16);
	CK(kof_src_syms_of(s, &n) && n == 16u);
	memset(fn, 0, sizeof fn);
	fn[0].off = 5; fn[0].len = 9; fn[1].off = 50; fn[1].len = 20; fn[1].shndx = 3;
	kof_src_declare_funcs(s, fn, 2);
	fn[0].off = 0;
	fp = (struct kgenome_func *)(void *)(uintptr_t)kof_src_funcs_of(s, &n);
	CK(fp && n == 2u && fp[0].off == 5u && fp[1].shndx == 3u);
	kof_src_declare_funcs(s, fn, 0);
	kof_src_declare_funcs(s, NULL, 2);
	CK(kof_src_funcs_of(s, &n) == fp && n == 2u);

	/* kind, format, language, entry */
	kof_src_declare_kind(s, KOF_ENT_NORMALIZED);
	kof_src_declare_fmt(s, KOF_FMT_DECLARED_RAW);
	kof_src_declare_entry(s, 7);
	kof_src_declare_lang(s, KOF_SCRIPT_SHELL, 4);
	CK(kof_src_kind_of(s) == KOF_ENT_NORMALIZED && kof_src_fmt_of(s) == KOF_FMT_DECLARED_RAW);
	CK(kof_src_entry_of(s) == 7u);
	CK(kof_src_lang_of(s, &st, &sf) && st == KOF_SCRIPT_SHELL && sf == 4u);
	CK(kof_src_lang_of(s, NULL, NULL));
	/* the language of subtype 0 is still a language: "declared" is not "non-zero" */
	kof_src_declare_lang(s, 0, 0);
	CK(kof_src_lang_of(s, &st, &sf) && st == 0 && sf == 0);

	/* the label: the last path component, printable, whole, no "." or ".." */
	kof_src_label(s, (const uint8_t *)"dir/sub\\name.bin", 16);
	CK(!strcmp(kof_src_label_of(s), "name.bin"));
	kof_src_label(s, (const uint8_t *)"a\x01\x7f\xffz", 5);
	CK(!strcmp(kof_src_label_of(s), "a...z"));
	kof_src_label(s, (const uint8_t *)"dir/..", 6);
	CK(!strcmp(kof_src_label_of(s), ""));
	kof_src_label(s, (const uint8_t *)"///", 3);
	CK(!strcmp(kof_src_label_of(s), ""));
	kof_src_label(s, (const uint8_t *)".", 1);
	CK(!strcmp(kof_src_label_of(s), ""));
	{
		uint8_t longname[300];

		memset(longname, 'q', sizeof longname);
		kof_src_label(s, longname, sizeof longname);
		/* allocated to its length (it was cut to KOF_SRC_LABEL_MAX - 1), and its cost is what a
		 * caller charges */
		CK(strlen(kof_src_label_of(s)) == sizeof longname && kof_src_label_cost(s) == sizeof longname + 1u);
		/* the widest name any standard allows is kept; one byte more is invalid, not cut */
		{
			static uint8_t widest[KOF_SRC_NAME_MAX + 1u];

			memset(widest, 'w', sizeof widest);
			kof_src_label(s, widest, KOF_SRC_NAME_MAX);
			CK(strlen(kof_src_label_of(s)) == KOF_SRC_NAME_MAX && !kof_src_name_bad(s));
			kof_src_label(s, widest, KOF_SRC_NAME_MAX + 1u);
			CK(!strcmp(kof_src_label_of(s), "") && kof_src_label_cost(s) == 0 && kof_src_name_bad(s));
		}
		/* UTF-16LE names are narrowed first */
		kof_src_label(s, (const uint8_t *)"a\0b\0c\0.\0t\0x\0t\0", 14);
		CK(!strcmp(kof_src_label_of(s), "abc.txt"));
		kof_src_label(s, NULL, 5);
		CK(!strcmp(kof_src_label_of(s), ""));
		kof_src_label(s, longname, 0);
		CK(!strcmp(kof_src_label_of(s), ""));
	}
	kof_src_unref(s);                /* frees the description, symbols and functions */
}

/* ---- what a view inherits ------------------------------------------------------------------ */

static struct kof_objsrc *normalised_child(int with_desc, uint32_t kind)
{
	struct kof_objsrc *k = kof_src_heap(calloc(1, 32), 32);
	uint8_t info[16] = { 1, 2, 3, 4 };
	struct kof_src_desc d;

	kof_src_declare_kind(k, kind);
	if (with_desc) {
		memset(&d, 0, sizeof d);
		d.fmt = KOF_FMT_ELF;
		d.info = info;
		d.info_len = sizeof info;
		kof_src_declare_desc(k, &d);
	}
	return k;
}

static void products_published_and_adopted(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_objsrc *list[4], **old_list;
	uint32_t old_n, old_views, bm, n_diag, k;
	const struct kof_prod *p0, *p1;
	uint8_t hit0, gate0, unk0;

	CK(sc != NULL);
	if (!sc)
		return;
	old_list = sc->child.list;
	old_n = sc->child.n;
	old_views = sc->child.n_views;
	bm = sc->diag.bm ? sc->diag.bm : 1u;
	n_diag = sc->diag.cap ? sc->diag.cap : 1u;
	CK(sc->diag.hit && sc->diag.gate && sc->diag.unk && sc->diag.n_bind && sc->diag.bind);
	if (!sc->diag.hit || !sc->diag.gate || !sc->diag.unk || !sc->diag.n_bind || !sc->diag.bind) {
		kscan_free(sc);
		return;
	}
	/* the parent's answers, as its pipeline left them */
	sc->diag.hit[0] = hit0 = 0x05;
	sc->diag.gate[0] = gate0 = 0x03;
	sc->diag.unk[0] = unk0 = 0x01;
	sc->diag.n_bind[0] = 2;
	sc->diag.bind[0][0] = 11;
	sc->diag.bind[0][1] = 22;
	/* four children: two views with a description, a view without one, and content */
	list[0] = normalised_child(1, KOF_ENT_NORMALIZED);
	list[1] = normalised_child(0, KOF_ENT_NORMALIZED);
	list[2] = normalised_child(1, KOF_ENT_UNKNOWN);
	list[3] = normalised_child(1, KOF_ENT_NORMALIZED);
	sc->child.list = list;
	sc->child.n = 4;
	kof_prod_publish(sc);
	p0 = kof_src_prod_of(list[0]);
	p1 = kof_src_prod_of(list[3]);
	CK(p0 != NULL && p0 == p1);                               /* one record, shared */
	CK(kof_src_prod_of(list[1]) == NULL);                      /* no description: nothing to inherit */
	CK(kof_src_prod_of(list[2]) == NULL);                      /* not a view */
	/* the scanner's own diagnose state is left for the next object to reset */
	CK(sc->diag.hit[0] == hit0);
	/* publishing with no view at all is a no-op */
	sc->child.n = 0;
	kof_prod_publish(sc);
	sc->child.n = 4;

	/* the view's scan begins: the answers are the parent's, every product is latched */
	sc->diag.hit[0] = 0;
	sc->diag.gate[0] = 0;
	sc->diag.unk[0] = 0;
	sc->diag.n_bind[0] = 0;
	sc->diag.bind[0][0] = 0;
	sc->obj.latch[KOF_OL_DIAG] = 0;
	sc->obj.latch[KOF_OL_DIAG_GATE] = 0;
	sc->obj.latch[KOF_OL_APIHASH] = 0;
	kof_prod_adopt(sc, p0);
	CK(sc->cur.prod == p0 && sc->cur.prod_borrowed == 1);
	CK(sc->diag.hit[0] == hit0 && sc->diag.gate[0] == gate0 && sc->diag.unk[0] == unk0);
	CK(sc->diag.n_bind[0] == 2 && sc->diag.bind[0][0] == 11 && sc->diag.bind[0][1] == 22);
	CK(sc->obj.latch[KOF_OL_DIAG] && sc->obj.latch[KOF_OL_DIAG_GATE] && sc->obj.latch[KOF_OL_APIHASH]);
	/* what it adopted is borrowed, not owned: the scanner's graph is the parent's pointer */
	CK(sc->obj.diag.graph == NULL && sc->obj.diag.apihash == NULL);   /* this parent made none */
	kof_prod_unadopt(sc);
	CK(sc->cur.prod == NULL && sc->cur.prod_borrowed == 0);
	CK(sc->obj.diag.graph == NULL && sc->obj.diag.apihash == NULL);
	/* unadopting what was not adopted leaves the scanner's own products alone */
	sc->cur.prod = p0;
	sc->cur.prod_borrowed = 0;
	kof_prod_unadopt(sc);
	CK(sc->cur.prod == p0);
	sc->cur.prod = NULL;
	/* a database of another size is another scanner's analysis: the answers are not
	 * taken, and every product is latched all the same */
	sc->diag.hit[0] = 0x40;
	sc->diag.cap += 1u;
	sc->obj.latch[KOF_OL_DIAG] = 0;
	kof_prod_adopt(sc, p0);
	CK(sc->diag.hit[0] == 0x40 && sc->obj.latch[KOF_OL_DIAG] == 1 && sc->cur.prod_borrowed == 1);
	kof_prod_unadopt(sc);
	sc->diag.cap -= 1u;
	(void)bm;
	(void)n_diag;

	/* the record outlives the parent's scanner state: it is held by the views, and
	 * the last one to go frees it */
	kof_src_unref(list[0]);
	CK(kof_src_prod_of(list[3]) == p1);
	kof_src_unref(list[3]);
	kof_src_unref(list[1]);
	kof_src_unref(list[2]);
	kof_prod_unref(NULL);
	for (k = 0; k < 4u; k++)
		list[k] = NULL;
	sc->child.list = old_list;
	sc->child.n = old_n;
	sc->child.n_views = old_views;
	kscan_free(sc);
}

int main(void)
{
	if (!e2e_open(NULL)) {
		printf("normalizer_view_state: cannot open the test database\n");
		return 2;
	}
	bits_set_every_pair();
	keep_bits_regions();
	keep_of_real_objects();
	keep_exec_edges();
	source_declarations();
	products_published_and_adopted();
	printf("normalizer_view_state: %u checks, %u failed, %d old-style failed\n",
	       nr_ok + nr_bad, nr_bad, fails);
	return nr_bad != 0 || fails != 0;
}
