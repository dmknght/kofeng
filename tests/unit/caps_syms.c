/*
 * caps_syms - limits of what the ELF symbol block and the library-span finder
 * keep: evidence just INSIDE and just OUTSIDE each limit.
 *
 * WHAT THIS CATCHES:
 *
 *   KOF_SYM_MAX_RECS (4096)   the block holds the FIRST 4096 records of the
 *                             table, in table order. A symbol after the 4096th
 *                             - an imported prepare_creds in a module or a
 *                             binary with 43912 symbols, which elf.h says is
 *                             real - is not in the block, so a diagnose on the
 *                             symbol route (kmod_give_root) cannot see it.
 *                             The header's `truncated` byte says so; nothing
 *                             reads it (flag_readers.c). Miss class: "symbol
 *                             dropped by a cap".
 *   KOF_SYM_NAME_MAX (4096)   the NAME of a record is kept whole: it was 40 bytes
 *                             inline and a longer one (a mangled C++ or Rust
 *                             symbol, __x64_sys_...) was cut to 39 characters, so
 *                             a rule on it could never match its tail. The record
 *                             now points into a pool of names; a 41, a 70 and a
 *                             1000 character name come back whole. 4096 is the
 *                             DoS bound, and a name past it is cut AND SAYS SO
 *                             (KOF_SYM_R_NAMECUT). The pool's entry for a symbol is
 *                             the run a rule's pattern is matched against
 *                             (attributes, name, NUL) and is checked to be what
 *                             the record says, for every record.
 *   KGENOME_TRUE_MAX_SPANS_ALL    the symbol tier of the library cut keeps 2048
 *      (2048)                 spans and drops the rest silently, so the
 *                             normalised view keeps library code the symbols
 *                             name - the view then differs from the file by
 *                             where the library happens to lie. Miss class:
 *                             "view not equivalent to parent" (see
 *                             view_equiv.c).
 *   KGENOME_TRUE_MAX_SPANS (16)   the same for the marker tier: more than 16 runs
 *                             of library strings in one object.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "../../libkofeng/scanners/scan.h"
#include "known_miss.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"
#include <celllysis/trueline.h>
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"

static unsigned char view[1u << 22];
static uint8_t img[1u << 23];
static struct kof_obj_ctx ctx;

static int parse_img(uint64_t len)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	memset(view, 0, sizeof view);
	memset(&ctx, 0, sizeof ctx);
	buf.p = img;
	buf.n = len;
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, &ctx))
			return 1;
	return 0;
}

/* ---- an x86-64 ELF with a symbol table ------------------------------------- */

struct sym_in {
	const char *name;
	uint8_t     info;           /* bind << 4 | type */
	uint16_t    shndx;
	uint64_t    value, size;
};

#define VB       0x400000u
#define TEXT_OFF 0x1000u

static void shdr(uint8_t *p, uint32_t name, uint32_t type, uint64_t flags,
		 uint64_t addr, uint64_t off, uint64_t size, uint32_t link,
		 uint64_t entsz)
{
	put32(p, 0, name); put32(p, 4, type);
	put64(p, 8, flags); put64(p, 16, addr); put64(p, 24, off);
	put64(p, 32, size); put32(p, 40, link); put32(p, 44, 0);
	put64(p, 48, 1); put64(p, 56, entsz);
}

/* `text_len` bytes of code, `n` symbols (after the null one). */
static uint64_t elf_syms(const struct sym_in *sy, unsigned n, unsigned text_len)
{
	static const char shstr[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
	static char str[1u << 20];
	unsigned strn = 1, i;
	uint64_t sym_off = (TEXT_OFF + text_len + 15u) & ~15ull, str_off, sh_str_off,
		 sh_off, len;
	uint8_t *p;

	memset(img, 0, 64);
	str[0] = 0;
	for (i = 0; i < n; i++) {
		unsigned l = (unsigned)strlen(sy[i].name) + 1u;

		if (strn + l >= sizeof str)
			return 0;
		memcpy(str + strn, sy[i].name, l);
		strn += l;
	}
	str_off = sym_off + (uint64_t)(n + 1u) * 24u;
	sh_str_off = str_off + strn;
	sh_off = (sh_str_off + sizeof shstr + 7u) & ~7ull;
	len = sh_off + 5u * 64u;
	memset(img, 0, (size_t)len);
	memcpy(img, "\177ELF\2\1\1", 7);
	put16(img, 16, 2); put16(img, 18, 62); put32(img, 20, 1);
	put64(img, 24, VB + TEXT_OFF); put64(img, 32, 64); put64(img, 40, sh_off);
	put16(img, 52, 64); put16(img, 54, 56); put16(img, 56, 1);
	put16(img, 58, 64); put16(img, 60, 5); put16(img, 62, 4);
	p = img + 64;
	put32(p, 0, 1); put32(p, 4, 5);
	put64(p, 8, 0); put64(p, 16, VB); put64(p, 24, VB);
	put64(p, 32, TEXT_OFF + text_len); put64(p, 40, TEXT_OFF + text_len);
	put64(p, 48, 0x1000);
	memset(img + TEXT_OFF, 0x90, text_len);
	/* symbols: index 0 is the null one */
	{
		unsigned at = 1;

		for (i = 0; i < n; i++) {
			uint8_t *q = img + sym_off + (uint64_t)(i + 1u) * 24u;

			put32(q, 0, at);
			q[4] = sy[i].info;
			put16(q, 6, sy[i].shndx);
			put64(q, 8, sy[i].value);
			put64(q, 16, sy[i].size);
			at += (unsigned)strlen(sy[i].name) + 1u;
		}
	}
	memcpy(img + str_off, str, strn);
	memcpy(img + sh_str_off, shstr, sizeof shstr);
	p = img + sh_off;
	shdr(p + 64 * 0, 0, 0, 0, 0, 0, 0, 0, 0);
	shdr(p + 64 * 1, 1, 1, 6, VB + TEXT_OFF, TEXT_OFF, text_len, 0, 0);
	shdr(p + 64 * 2, 7, 2, 0, 0, sym_off, (uint64_t)(n + 1u) * 24u, 3, 24);
	shdr(p + 64 * 3, 15, 3, 0, 0, str_off, strn, 0, 0);
	shdr(p + 64 * 4, 23, 3, 0, 0, sh_str_off, sizeof shstr, 0, 0);
	return len;
}

static uint8_t blk[KOF_SYM_ABS_MAX_BYTES];
static uint8_t *gblk;                   /* the engine's grown buffer: see block_for */
static uint32_t gcap, gn;               /* ... its size, and the block's length    */
static int last_cut;                    /* the record found had its name cut */

/*
 * The block built for the object in `img`; the record index of `want`, or -1.
 * Built the way the engine builds it (kof_syms_build_grow, which oc_syms calls):
 * sized by the table the object declares and grown until the block was not cut.
 * The block is left in gblk/gn for the checks that read it.
 */
static int block_for(uint64_t len, const char *want, unsigned *trunc, unsigned *count)
{
	uint32_t i, wl = (uint32_t)strlen(want);
	const uint8_t *r;

	last_cut = 0;
	if (!parse_img(len))
		return -2;
	gn = kof_syms_build_grow(KOF_FMT_ELF, img, len, kof_elf(&ctx), NULL, &gblk, &gcap, NULL);
	*trunc = (unsigned)kof_sym_truncated(gblk, gn);
	*count = kof_sym_count(gblk, gn);
	for (i = 0; (r = kof_sym_rec(gblk, gn, i)) != NULL; i++) {
		uint32_t nl = 0;
		const char *nm = kof_sym_name(gblk, gn, r, &nl);

		if (nl == wl && !memcmp(nm, want, wl)) {
			last_cut = kof_sym_name_cut(r);
			return (int)i;
		}
	}
	return -1;
}

static struct sym_in tab[6000];
static char names[6000][24];

static void fill_table(unsigned n, unsigned target, const char *target_name)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		snprintf(names[i], sizeof names[i], "sym_%05u", i);
		tab[i].name = names[i];
		tab[i].info = (uint8_t)((1u << 4) | 2u);        /* GLOBAL FUNC */
		tab[i].shndx = 1;
		tab[i].value = VB + TEXT_OFF + (uint64_t)(i & 0xffu);
		tab[i].size = 1;
	}
	/* the symbol a diagnose wants: an UNDEFINED function, an import */
	tab[target].name = target_name;
	tab[target].shndx = 0;
	tab[target].value = 0;
	tab[target].size = 0;
}

static void sym_recs(void)
{
	unsigned trunc, count;
	int at;
	uint64_t len;

	/* The table's own null symbol is record 0, so 4095 symbols after it fill
	 * the block exactly: the last of them is the 4096th record, kept. */
	fill_table(4095, 4094, "prepare_creds");
	len = elf_syms(tab, 4095, 0x400);
	at = block_for(len, "prepare_creds", &trunc, &count);
	CK(at == 4095 && !trunc && count == 4096u);

	/* one more: the 4097th record is in the block - the engine sizes it by the
	 * table, so a symbol past 4096 is no longer lost. */
	fill_table(4096, 4095, "prepare_creds");
	len = elf_syms(tab, 4096, 0x400);
	at = block_for(len, "prepare_creds", &trunc, &count);
	CK(at == 4096 && !trunc && count == 4097u);

	/* and a caller that gives the OLD size still gets a block that SAYS it was
	 * cut: the builder keeps what the cap holds, and sets the byte. */
	{
		uint32_t bn = kof_syms_build(KOF_FMT_ELF, img, len, kof_elf(&ctx), blk,
					     KOF_SYM_MAX_BYTES);

		CK(kof_sym_truncated(blk, bn) == 1 && kof_sym_count(blk, bn) == 4096u);
	}

	/* a binary with symbols by the ten thousand (static glibc has 4000+, a
	 * Go binary 10000+): the import is the last */
	fill_table(5900, 5899, "commit_creds");
	len = elf_syms(tab, 5900, 0x400);
	at = block_for(len, "commit_creds", &trunc, &count);
	CK(at == 5900 && !trunc && count == 5901u);
}

/*
 * THE POOL ENTRY IS WHAT THE RECORD SAYS, for every record of a block: the four
 * attribute bytes in front of the name are the record's own, the name is followed
 * by its NUL, and the extents the engine hands the matcher cover exactly those
 * runs - last record first, joined where adjacent.
 */
static void entries_agree(void)
{
	uint32_t i, n = kof_sym_count(gblk, gn), runs = 0;
	struct kof_range ext[8];
	uint32_t k;

	for (i = 0; i < n; i++) {
		const uint8_t *r = kof_sym_rec(gblk, gn, i);
		uint64_t at = 0, l = 0;
		uint32_t nl = 0;
		const char *nm = kof_sym_name(gblk, gn, r, &nl);

		CK(r && kof_sym_run(gblk, gn, i, &at, &l));
		if (!r || !kof_sym_run(gblk, gn, i, &at, &l))
			continue;
		CK(l == KOF_SYM_KEYLEN + nl + 1u);
		CK(gblk[at] == r[KOF_SYM_R_TYPE] && gblk[at + 1] == r[KOF_SYM_R_BIND] &&
		   gblk[at + 2] == r[KOF_SYM_R_VIS] && gblk[at + 3] == r[KOF_SYM_R_FLAGS]);
		CK((const uint8_t *)nm == gblk + at + KOF_SYM_KEYLEN && nm[nl] == 0);
		CK(kof_sym_index_at(gblk, gn, at) == i);
	}
	/* Both halves of this fixture: the UNDEFINED target is the import half, and
	 * the whole table is `n` runs of one half or the other. Adjacent runs of a half
	 * join, so there are never more extents than records. */
	k = kof_sym_extents(gblk, gn, KOF_SCAN_SYM, ext, 8);
	for (i = 0; i < k; i++)
		runs += kof_sym_extent_recs(gblk, gn, &ext[i], NULL);
	CK(k > 0 && k <= 8u && runs == n);
}

static void name_len(void)
{
	static char n39[40], n41[42], n70[71], n1000[1001], n4096[4097], n5000[5001], cut[4097];
	unsigned trunc, count;
	uint64_t len;
	uint32_t i;
	const uint8_t *r;

	memset(n39, 'a', 39); memset(n41, 'b', 41); memset(n70, 'c', 70);
	memset(n1000, 'd', 1000); memset(n4096, 'e', 4096); memset(n5000, 'f', 5000);
	memset(cut, 'f', 4096);
	n39[39] = n41[41] = n70[70] = n1000[1000] = n4096[4096] = n5000[5000] = cut[4096] = 0;

	fill_table(8, 7, n39);
	len = elf_syms(tab, 8, 0x400);
	CK(block_for(len, n39, &trunc, &count) == 8);   /* 39 fits */
	CK(!last_cut);
	entries_agree();
	/* A 41 and a 70 character name were cut to 39 and said so; they are kept
	 * whole, and say nothing, because nothing was cut. */
	fill_table(8, 7, n41);
	len = elf_syms(tab, 8, 0x400);
	CK(block_for(len, n41, &trunc, &count) == 8 && !last_cut);
	entries_agree();
	fill_table(8, 7, n70);
	len = elf_syms(tab, 8, 0x400);
	CK(block_for(len, n70, &trunc, &count) == 8 && !last_cut);
	/* A name a thousand characters long: a mangled symbol of a large C++ or Rust
	 * program is in the hundreds, and its tail is where its identity is. */
	fill_table(8, 7, n1000);
	len = elf_syms(tab, 8, 0x400);
	CK(block_for(len, n1000, &trunc, &count) == 8 && !last_cut && !trunc);
	entries_agree();
	/* Exactly the bound is whole; past it is cut at the bound, and SAYS SO. */
	fill_table(8, 7, n4096);
	len = elf_syms(tab, 8, 0x400);
	CK(block_for(len, n4096, &trunc, &count) == 8 && !last_cut);
	fill_table(8, 7, n5000);
	len = elf_syms(tab, 8, 0x400);
	CK(block_for(len, cut, &trunc, &count) == 8 && last_cut == 1);
	CK(block_for(len, n5000, &trunc, &count) == -1);
	r = kof_sym_rec(gblk, gn, 8);
	CK(r && kof_sym_name_cut(r));
	/* The other records of that table are untouched by the cut one. */
	for (i = 0; i < 8; i++) {
		uint32_t nl = 0;

		r = kof_sym_rec(gblk, gn, i);
		(void)kof_sym_name(gblk, gn, r, &nl);
		if (i && i != 8)
			CK(!kof_sym_name_cut(r) && nl == 9u);
	}
	/* A name written into a hostile block is read as empty, never past it: the
	 * pool offset of the last record pointed outside the block. */
	{
		static uint8_t evil[KOF_SYM_HDRLEN + KOF_SYM_RECLEN + 8];
		uint32_t nl = 99;

		memset(evil, 0, sizeof evil);
		memcpy(evil, "KSYM", 4);
		evil[KOF_SYM_H_COUNT] = 1;
		evil[KOF_SYM_HDRLEN + KOF_SYM_R_NAMEOFF] = 200;
		evil[KOF_SYM_HDRLEN + KOF_SYM_R_NAMELEN] = 3;
		r = kof_sym_rec(evil, sizeof evil, 0);
		CK(r && *kof_sym_name(evil, sizeof evil, r, &nl) == 0 && nl == 0);
	}
}

/* ---- library spans --------------------------------------------------------- */

static int covers(const struct kgenome_true_all *r, uint64_t off, uint64_t len)
{
	uint32_t i;

	for (i = 0; i < r->n; i++)
		if (r->span[i].off <= off && off + len <= r->span[i].off + r->span[i].len)
			return 1;
	return 0;
}

static struct kgenome_true_all lib;
static char fnames[4200][24], gnames[4200][24], sfiles[4200][24];
static struct sym_in libtab[3 * 4200 + 4];

/*
 * `n` library functions, each its own STT_FILE group naming a library source
 * and defining one reserved-namespace function (`__libfn_i`) - the shape the
 * symbol tier convicts - with an author GLOBAL function between each pair, so
 * no gap can be closed and the spans stay disjoint. Library function i sits at
 * text offset i * 0x80.
 */
static uint64_t lib_object(unsigned n)
{
	unsigned i, k = 0;

	for (i = 0; i < n; i++) {
		snprintf(sfiles[i], sizeof sfiles[i], "libc-%04u.c", i);
		snprintf(fnames[i], sizeof fnames[i], "__libfn_%04u", i);
		snprintf(gnames[i], sizeof gnames[i], "author_%04u", i);
		libtab[k].name = sfiles[i]; libtab[k].info = 4; libtab[k].shndx = 0xfff1u;
		libtab[k].value = 0; libtab[k].size = 0; k++;
		libtab[k].name = fnames[i]; libtab[k].info = 2; libtab[k].shndx = 1;
		libtab[k].value = VB + TEXT_OFF + (uint64_t)i * 0x80u; libtab[k].size = 0x20;
		k++;
		libtab[k].name = gnames[i]; libtab[k].info = (uint8_t)((1u << 4) | 2u);
		libtab[k].shndx = 1;
		libtab[k].value = VB + TEXT_OFF + (uint64_t)i * 0x80u + 0x40u;
		libtab[k].size = 0x20;
		k++;
	}
	return elf_syms(libtab, k, n * 0x80u + 0x100u);
}

static void sym_spans(void)
{
	uint64_t len = lib_object(100);
	kof_buf f;

	CK(parse_img(len));
	f.p = img; f.n = len;
	kgenome_true_find_all(f, kof_elf(&ctx), &lib);
	CK(lib.n >= 90);                        /* the fixture is read as a library */
	CK(covers(&lib, TEXT_OFF + 99u * 0x80u, 0x20));

	len = lib_object(2040);
	CK(parse_img(len));
	f.n = len;
	kgenome_true_find_all(f, kof_elf(&ctx), &lib);
	CK(covers(&lib, TEXT_OFF + 2039u * 0x80u, 0x20));       /* inside */

	len = lib_object(2100);
	CK(parse_img(len));
	f.n = len;
	kgenome_true_find_all(f, kof_elf(&ctx), &lib);
	printf("  symbol tier: 2100 library functions -> %u spans, last covered %d\n",
	       (unsigned)lib.n, covers(&lib, TEXT_OFF + 2099u * 0x80u, 0x20));
	KM_CHECK(covers(&lib, TEXT_OFF + 2099u * 0x80u, 0x20),
		 "the 2100th library function is cut from the view",
		 "KOF_TRUE_MAX_SPANS_ALL");
	CK(lib.n <= KGENOME_TRUE_MAX_SPANS_ALL);
}

/*
 * The marker tier: `runs` clusters of three "Permission denied" strings, each
 * cluster 100 bytes across and the clusters 120 KB apart, in one segment. One
 * span from the first to the last is refused (it would need 5120 bytes of span
 * per marker and has 2 MB for 3 markers per run), so the clusters are judged
 * one by one - which is the path the cap is on.
 */
static uint64_t marker_object(unsigned runs)
{
	static const char m[] = "Permission denied";
	unsigned r, k;
	uint64_t seg = 0x1000u + (uint64_t)runs * 0x20000u;

	memset(img, 0, (size_t)seg + 128u);
	memcpy(img, "\177ELF\2\1\1", 7);
	put16(img, 16, 2); put16(img, 18, 62); put32(img, 20, 1);
	put64(img, 24, VB + 0x1000u); put64(img, 32, 64);
	put16(img, 52, 64); put16(img, 54, 56); put16(img, 56, 1);
	put32(img, 64, 1); put32(img, 68, 5);
	put64(img, 72, 0); put64(img, 80, VB); put64(img, 88, VB);
	put64(img, 96, seg); put64(img, 104, seg); put64(img, 112, 0x1000);
	for (r = 0; r < runs; r++)
		for (k = 0; k < 3u; k++)
			memcpy(img + 0x1000u + (uint64_t)r * 0x20000u + k * 40u, m, sizeof m - 1u);
	return seg;
}

static void marker_spans(void)
{
	unsigned runs[] = { 12, 16, 17, 40 }, i;
	kof_buf f;

	for (i = 0; i < 4; i++) {
		uint64_t len = marker_object(runs[i]);
		struct kgenome_true_result r;
		unsigned r_i, got = 0;

		CK(parse_img(len));
		f.p = img; f.n = len;
		kgenome_true_find(f, kof_elf(&ctx), &r);
		for (r_i = 0; r_i < runs[i]; r_i++) {
			uint64_t at = 0x1000u + (uint64_t)r_i * 0x20000u;
			unsigned k;

			for (k = 0; k < r.n; k++)
				if (r.span[k].off <= at && at + 60u <= r.span[k].off + r.span[k].len)
					got++;
		}
		printf("  marker tier: %u runs of library strings -> %u spans, %u cut\n",
		       runs[i], (unsigned)r.n, got);
		if (runs[i] <= 16u)
			CK(got == runs[i]);
		else
			KM_CHECK(got == runs[i],
				 runs[i] == 17u ? "17 runs of library strings are all cut"
					        : "40 runs of library strings are all cut",
				 "KOF_TRUE_MAX_SPANS");
	}
}

/*
 * A TABLE WHOSE NAMES OUTRUN THE POOL'S PLAN is rebuilt larger, and each pass is a build
 * of the product that the run count sees: kof_syms_build_grow reports its passes and
 * sym_build ticks kof_prod_ran for every one (it ticked once, before the loop, so the
 * rebuild was invisible to prod_once). 3000 names of 150 characters are 450 KB of pool
 * against the 144 KB planned (48 a record), so the first pass is cut for ROOM and a
 * later one holds it all; an ordinary table is ONE pass.
 */
static char longnames[3000][160];

static void rebuild_passes(void)
{
	unsigned i, trunc, count;
	uint32_t passes = 0;
	uint64_t len;
	struct e2e r;

	fill_table(100, 99, "commit_creds");
	len = elf_syms(tab, 100, 0x400);
	(void)block_for(len, "commit_creds", &trunc, &count);
	gn = kof_syms_build_grow(KOF_FMT_ELF, img, len, kof_elf(&ctx), NULL, &gblk, &gcap, &passes);
	CK(passes == 1u && !kof_sym_truncated(gblk, gn));

	for (i = 0; i < 3000u; i++) {
		memset(longnames[i], 'n', 150);
		snprintf(longnames[i] + 140, 20, "%010u", i);
		tab[i].name = longnames[i];
		tab[i].info = (uint8_t)((1u << 4) | 2u);
		tab[i].shndx = 1;
		tab[i].value = VB + TEXT_OFF;
		tab[i].size = 1;
	}
	tab[2999].name = "commit_creds";
	tab[2999].shndx = 0;
	tab[2999].value = tab[2999].size = 0;
	len = elf_syms(tab, 3000, 0x400);
	CK(parse_img(len));
	passes = 0;
	gn = kof_syms_build_grow(KOF_FMT_ELF, img, len, kof_elf(&ctx), NULL, &gblk, &gcap, &passes);
	CK(passes >= 2u);                               /* the plan was short: it grew */
	CK(!kof_sym_truncated(gblk, gn) && kof_sym_count(gblk, gn) == 3001u);

	/* through the engine: the passes are runs of the product */
	if (e2e_open(NULL)) {
		unsigned before = kof_scan_prod_repeats(e2e_sc, KOF_PROD_SYMS);

		(void)e2e_scan(img, len, &r);
		CK(kof_scan_prod_repeats(e2e_sc, KOF_PROD_SYMS) >= before + 1u);
	}
}

int main(void)
{
	sym_recs();
	rebuild_passes();
	name_len();
	sym_spans();
	marker_spans();
	printf("caps syms: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
