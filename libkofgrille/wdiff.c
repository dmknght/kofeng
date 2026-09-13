/*
 * wdiff.c - see wdiff.h for what this is, what it excludes, and the
 * measurement that decided its shape.
 *
 * THE SHAPE, IN ONE PARAGRAPH. A distinct file is parsed once and kept: its
 * section table, its relocation directory, its IAT range, the base it asks
 * for. Then for each process that mapped it, only the pages that have stopped
 * being shared are read out of the process, only the matching bytes are read
 * off the disk, and the two are compared. A byte that differs is checked
 * against the relocation table: inside a relocation target it must equal the
 * file's value plus the load delta, and if it does the loader put it there.
 * Anything else is a run.
 *
 * Nothing here reads a whole module, a whole file, or builds a whole un-mapped
 * image, and the reason is in wdiff.h: doing all three cost 1514 MB a sweep to
 * find 167 KB.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofeng.h"
#include <kofmod/pe.h>
#include "kofparsers/binaries/pe_parse.h"

#include "wdiff.h"

#define RUNS_DEFAULT 256u

/* A file bigger than this is not compared at all. */
#define FILE_MAX (256ull * 1024ull * 1024ull)

/*
 * And a file bigger than THIS is not parsed, because parsing needs the whole
 * of it in memory at once - see cfile_fill. Every module a Windows process
 * maps is far under it; something that is not is not a module worth holding
 * 64MB for.
 */
#define PARSE_MAX (64ull * 1024ull * 1024ull)

/* The relocation directory is held whole, because it is the one part of the
 * file every page lookup needs. Past this it is not held and the module's
 * relocations are treated as unknown - which reports more, never less. */
#define RELOC_MAX (4u * 1024u * 1024u)

/* ------------------------------------------------------------- the cache */

/*
 * WHAT IS KEPT PER DISTINCT FILE.
 *
 * Keyed by PATH here rather than by file identity, and that is a deliberate
 * narrowing rather than an oversight: this cache lives for one walk, a walk is
 * seconds, and a system DLL replaced underneath one is a case the identity
 * check in koffridge already covers for the VERDICT. What this holds is a
 * section table; being one sweep stale about that is not a wrong answer about
 * malware, it is a wrong answer about where .text starts, and the comparison
 * that follows would disagree with the file it just read either way.
 */
struct cfile {
	char     path[512];
	int      valid;         /* the parse succeeded */

	struct kof_pe_info info;
	uint64_t image_base;
	uint64_t iat_lo, iat_hi;

	/* The relocation directory, as file bytes, and where it starts. */
	uint8_t *reloc;
	uint32_t reloc_len;
	/* Where the last lookup found its block - a hint, never trusted. */
	uint32_t rel_hint;

	/*
	 * WHAT THE IMAGE REWRITES IN ITSELF AT LOAD TIME - see dv_load.
	 *
	 * Sorted by rva so a lookup is a binary search. `unknown` counts the
	 * entries under a dynamic relocation kind this build does not decode:
	 * those are NOT covered, so their bytes still get reported, which is
	 * the direction an unrecognised thing has to fail in.
	 */
	struct dvcover {
		uint32_t rva;
		uint8_t  len;
	} *dv;
	uint32_t dv_n;
	uint32_t dv_unknown;

	FILE    *fp;            /* held open: the ranges are read through it */
};

struct kofw_diff_cache {
	struct cfile *f;
	uint32_t      cap, n;
	uint32_t      next;     /* round-robin victim */
	uint64_t      asked, parsed;
};

struct kofw_diff_cache *kofw_diff_cache_open(uint32_t max_files)
{
	struct kofw_diff_cache *c = calloc(1, sizeof *c);

	if (!c)
		return NULL;
	c->cap = max_files ? max_files : 64u;
	c->f = calloc(c->cap, sizeof *c->f);
	if (!c->f) {
		free(c);
		return NULL;
	}
	return c;
}

static void cfile_drop(struct cfile *e)
{
	if (e->fp)
		fclose(e->fp);
	free(e->reloc);
	free(e->dv);
	memset(e, 0, sizeof *e);
}

void kofw_diff_cache_close(struct kofw_diff_cache *c)
{
	uint32_t i;

	if (!c)
		return;
	for (i = 0; i < c->n; i++)
		cfile_drop(&c->f[i]);
	free(c->f);
	free(c);
}

void kofw_diff_cache_stats(const struct kofw_diff_cache *c, uint32_t *held,
			   uint64_t *asked, uint64_t *parsed)
{
	if (held)
		*held = c ? c->n : 0;
	if (asked)
		*asked = c ? c->asked : 0;
	if (parsed)
		*parsed = c ? c->parsed : 0;
}

/* Read `len` bytes at `off` from the file this entry holds open. */
static int cfile_read(struct cfile *e, uint64_t off, void *buf, uint32_t len)
{
	if (!e->fp || !len)
		return 0;
	if (fseek(e->fp, (long)off, SEEK_SET) != 0)
		return 0;
	return fread(buf, 1, len, e->fp) == len;
}

/*
 * WHAT THE IMAGE REWRITES IN ITSELF, out of its own dynamic relocation table.
 *
 * THE NOISE THIS EXISTS TO REMOVE, measured before it did. A whole-machine
 * sweep reported 359 differing runs of which 275 were four bytes long, in the
 * .text of Microsoft DLLs, at regular spacing. Dumped, one pair read:
 *
 *     file: 90 03 00 d0     ADRP x16, <page A>
 *     mem:  70 02 00 f0     ADRP x16, <page B>
 *
 * The same instruction with a different page. That is not a base relocation -
 * ADRP is PC-relative and a base relocation would not move it - and it is not
 * tampering. It is the loader SUBSTITUTING an instruction, which is what an
 * ARM64X image is: one file carrying both an ARM64 and an ARM64EC form, with a
 * table saying which bytes to swap for which form. mscoree.dll and ntdll.dll
 * both carry one, and both have a CHPEMetadataPointer, which is what makes
 * them ARM64X.
 *
 * VERIFIED BEFORE IT WAS BUILT, because a filter resting on a wrong theory
 * hides real differences - which is far worse than the noise it removes. The
 * table was parsed and asked about the actual differing addresses:
 *
 *     rva 0x44690  COVERED (by symbol=6)
 *     rva 0x446b4  COVERED (by symbol=6)
 *     rva 0x44774  COVERED (by symbol=6)
 *     rva 0x12345  NOT covered          <- the control
 *
 * The control matters as much as the hits: a table that "covered" everything
 * would have suppressed everything and looked like success.
 *
 * THE FIRST ATTEMPT AT THIS READ THE WRONG FIELD. DynamicValueRelocTableOffset
 * is at offset 224 of the 64-bit load configuration; 240 is HotPatchTableOffset
 * and reads 0 on these images. That produced a confident "these modules have no
 * such table" and would have closed the question.
 *
 * ONLY SYMBOL 6 IS DECODED. The others are counted in dv_unknown and cover
 * nothing, so their bytes keep being reported. An entry kind this does not
 * understand must not become a licence to ignore bytes.
 */
#define DV_ARM64X 6u

/* The whole table, bounded - a Size read out of the file cannot be trusted to
 * be sane, and 1MB is far past any real one. */
#define DV_MAX (1u * 1024u * 1024u)

static int dv_cmp(const void *a, const void *b)
{
	const struct dvcover *x = a, *y = b;

	return x->rva < y->rva ? -1 : (x->rva > y->rva ? 1 : 0);
}

static int dv_covers(const struct cfile *e, uint64_t rva)
{
	uint32_t lo = 0, hi = e->dv_n;

	if (!e->dv || !e->dv_n || rva > 0xffffffffull)
		return 0;
	/* The greatest entry whose rva is <= this one. */
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (e->dv[mid].rva <= (uint32_t)rva)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo)
		return 0;
	lo--;
	return (uint64_t)e->dv[lo].rva + e->dv[lo].len > rva;
}

static void dv_load(struct cfile *e, uint64_t flen)
{
	uint8_t *tbl = NULL;
	uint8_t cfg[256];
	uint64_t lc_off, at, end, p;
	uint32_t dv_off = 0, tsize, n = 0, cap = 0;
	uint16_t dv_sec = 0;
	uint32_t cfg_size = 0;

	if (e->info.n_dirs <= KOF_PE_DIR_LOAD_CONFIG ||
	    !e->info.dir[KOF_PE_DIR_LOAD_CONFIG].size)
		return;
	lc_off = kof_pe_rva_to_off(&e->info,
				   e->info.dir[KOF_PE_DIR_LOAD_CONFIG].rva);
	if (lc_off == KOF_BROKEN)
		return;
	if (!cfile_read(e, lc_off, cfg, (uint32_t)sizeof cfg))
		return;
	memcpy(&cfg_size, cfg, 4);
	/* The two fields sit at 224 and 228, so the structure has to reach
	 * them - an older, shorter load configuration simply has no table. */
	if (cfg_size < 232u)
		return;
	memcpy(&dv_off, cfg + 224, 4);
	memcpy(&dv_sec, cfg + 228, 2);
	if (!dv_off || !dv_sec || dv_sec > e->info.sec_count)
		return;

	/* The offset is relative to the START OF A SECTION, named by index. */
	at = e->info.sec[dv_sec - 1u].file_off + dv_off;
	if (at + 8u > flen)
		return;
	{
		uint8_t hd[8];
		uint32_t ver;

		if (!cfile_read(e, at, hd, 8))
			return;
		memcpy(&ver, hd, 4);
		memcpy(&tsize, hd + 4, 4);
		if (ver != 1u || !tsize || tsize > DV_MAX ||
		    at + 8u + tsize > flen)
			return;
	}

	tbl = malloc(tsize);
	if (!tbl)
		return;
	if (!cfile_read(e, at + 8u, tbl, tsize)) {
		free(tbl);
		return;
	}

	p = 0;
	end = tsize;
	while (p + 12u <= end) {
		uint64_t sym;
		uint32_t brs;
		uint64_t bp, bend;

		memcpy(&sym, tbl + p, 8);
		memcpy(&brs, tbl + p + 8, 4);
		bp = p + 12u;
		bend = bp + brs;
		/*
		 * A size that reaches past the table ends the walk. It used to
		 * be read anyway in the probe that worked this out, and the
		 * result was two invented entries with a claimed size of half a
		 * megabyte - and a coverage answer computed from them.
		 */
		if (bend > end || bend < bp)
			break;

		if (sym != DV_ARM64X) {
			e->dv_unknown++;
			p = bend;
			continue;
		}

		while (bp + 8u <= bend) {
			uint32_t page, blk;
			uint64_t k;

			memcpy(&page, tbl + bp, 4);
			memcpy(&blk, tbl + bp + 4, 4);
			if (blk < 8u || bp + blk > bend)
				break;
			for (k = bp + 8u; k + 2u <= bp + blk; k += 2u) {
				uint16_t x;
				uint32_t sz;

				memcpy(&x, tbl + k, 2);
				if (n == cap) {
					uint32_t want = cap ? cap * 2u : 256u;
					struct dvcover *nx =
						realloc(e->dv,
							want * sizeof *nx);

					if (!nx)
						goto done;
					e->dv = nx;
					cap = want;
				}
				/* offset:12, type:2, size:2 - and the covered
				 * width is 1 << size. */
				sz = 1u << ((x >> 14) & 3u);
				e->dv[n].rva = page + (x & 0x0fffu);
				e->dv[n].len = (uint8_t)sz;
				n++;
			}
			bp += blk;
		}
		p = bend;
	}

done:
	free(tbl);
	e->dv_n = n;
	if (n > 1u)
		qsort(e->dv, n, sizeof *e->dv, dv_cmp);
}

/* Parse what the comparison needs out of the file, once - see below. */
static int cfile_fill(struct cfile *e, const char *path)
{
	struct kof_obj_ctx ctx;
	unsigned char *head;
	uint64_t flen, ro, rl;
	uint32_t want;
	long n;

	snprintf(e->path, sizeof e->path, "%s", path);

	e->fp = fopen(path, "rb");
	if (!e->fp)
		return 0;
	if (fseek(e->fp, 0, SEEK_END) != 0)
		return 0;
	n = ftell(e->fp);
	if (n <= 0 || (uint64_t)n > FILE_MAX)
		return 0;
	flen = (uint64_t)n;

	/*
	 * THE WHOLE FILE, ONCE, AND THEN THE BYTES ARE THROWN AWAY.
	 *
	 * This read a 64KB prefix instead, on the reasoning that the section
	 * table and the directories both live inside SizeOfHeaders and are
	 * exact there. The section table is exact; what the PARSE reports about
	 * it is not. kof_pe_parse CLIPS each section's file_size to the buffer
	 * it was handed, so against a prefix ntdll.dll comes back as:
	 *
	 *     whole file    .text file_size=3098112   .specffs=4608
	 *     64KB prefix   .text file_size=64000     .specffs=0
	 *
	 * and the comparison below, which walks forward while rva is inside
	 * mem_rva + file_size, then stops after the first 64KB of .text and
	 * silently examines nothing else. It did not report less; it reported
	 * almost nothing, and did it fast enough to look like an optimisation.
	 * 35 runs in one process became 3.
	 *
	 * So the file is read whole to be parsed, and the bytes are freed
	 * immediately after - what is KEPT is the parsed info and the
	 * relocation directory, both small. That is one full read per DISTINCT
	 * file for the whole walk, which is what this cache exists to make
	 * true: 31 reads rather than the 561 comparisons that need them.
	 */
	if (flen > PARSE_MAX)
		return 0;
	want = (uint32_t)flen;
	head = malloc(want);
	if (!head)
		return 0;
	rewind(e->fp);
	if (fread(head, 1, want, e->fp) != want) {
		free(head);
		return 0;
	}

	memset(&e->info, 0, sizeof e->info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(kof_buf_make(head, want), &e->info, &ctx) ||
	    !e->info.valid) {
		free(head);
		return 0;
	}
	e->image_base = e->info.image_base;
	free(head);

	if (!e->image_base)
		return 0;   /* no delta can be computed - see base_unknown */

	/* The IAT, as a file range to step over. */
	if (e->info.n_dirs > KOF_PE_DIR_IAT && e->info.dir[KOF_PE_DIR_IAT].size) {
		uint64_t o = kof_pe_rva_to_off(&e->info,
					       e->info.dir[KOF_PE_DIR_IAT].rva);

		if (o != KOF_BROKEN) {
			e->iat_lo = o;
			e->iat_hi = o + e->info.dir[KOF_PE_DIR_IAT].size;
		}
	}

	/* The relocation directory, held whole. */
	if (e->info.n_dirs > KOF_PE_DIR_BASERELOC &&
	    e->info.dir[KOF_PE_DIR_BASERELOC].size) {
		rl = e->info.dir[KOF_PE_DIR_BASERELOC].size;
		ro = kof_pe_rva_to_off(&e->info,
				       e->info.dir[KOF_PE_DIR_BASERELOC].rva);
		if (ro != KOF_BROKEN && rl && rl <= RELOC_MAX &&
		    ro + rl <= flen) {
			e->reloc = malloc((size_t)rl);
			if (e->reloc) {
				if (cfile_read(e, ro, e->reloc, (uint32_t)rl))
					e->reloc_len = (uint32_t)rl;
				else {
					free(e->reloc);
					e->reloc = NULL;
				}
			}
		}
	}

	/* What the image rewrites in itself at load - see dv_load. */
	dv_load(e, flen);

	e->valid = 1;
	return 1;
}

static struct cfile *cache_get(struct kofw_diff_cache *c, const char *path,
			       struct cfile *scratch)
{
	uint32_t i;
	struct cfile *e;

	if (!c) {
		memset(scratch, 0, sizeof *scratch);
		if (!cfile_fill(scratch, path)) {
			cfile_drop(scratch);
			return NULL;
		}
		return scratch;
	}

	c->asked++;
	for (i = 0; i < c->n; i++)
		if (strcmp(c->f[i].path, path) == 0)
			return c->f[i].valid ? &c->f[i] : NULL;

	if (c->n < c->cap) {
		e = &c->f[c->n++];
	} else {
		/*
		 * ROUND ROBIN, not least-recently-used. The set this holds is
		 * the machine's loaded system DLLs - a few dozen, met over and
		 * over - so the table does not fill in practice and the
		 * eviction policy is never exercised. A real LRU here would be
		 * bookkeeping on every hit to serve a case that does not occur.
		 */
		e = &c->f[c->next++ % c->cap];
		cfile_drop(e);
	}
	c->parsed++;
	if (!cfile_fill(e, path)) {
		/* Kept as an invalid entry so the next process that maps the
		 * same unreadable file does not try again. */
		if (e->fp) {
			fclose(e->fp);
			e->fp = NULL;
		}
		snprintf(e->path, sizeof e->path, "%s", path);
		e->valid = 0;
		return NULL;
	}
	return e;
}

/* ------------------------------------------------------- the relocations */

/*
 * IS THIS RVA A RELOCATION TARGET, and how wide.
 *
 * The relocation directory is a list of per-page blocks, each naming a page
 * RVA and then the offsets inside it - so finding the entries for one page is
 * a scan of block HEADERS, not of entries. A module has a few hundred blocks
 * and the pages this asks about are a handful, so the scan is nothing.
 *
 * Returns the width in bytes - 4 for HIGHLOW, 8 for DIR64 - or 0 when the RVA
 * is not a relocation target, which includes every case where the table could
 * not be read.
 */
#define REL_ABSOLUTE 0u
#define REL_HIGHLOW  3u
#define REL_DIR64   10u

static uint32_t reloc_width(struct cfile *e, uint64_t rva, uint64_t *start)
{
	uint32_t at = 0;

	if (!e->reloc || !e->reloc_len)
		return 0;

	/*
	 * START FROM THE BLOCK THE LAST LOOKUP LANDED IN.
	 *
	 * This is called once per DIFFERING BYTE, and differing bytes come in
	 * runs - so consecutive calls ask about the same 4KB page, or the next
	 * one. Scanning from the front each time made the inner loop O(blocks)
	 * per byte: ntdll has hundreds of blocks and a module can differ in
	 * thousands of places, which is a six-figure block walk for an answer
	 * that was one comparison away.
	 *
	 * Remembering where the last one hit turns the common case into a
	 * single header compare. It is a hint and nothing more - a miss simply
	 * restarts from the front below, so a wrong remembered position costs
	 * one extra scan and can never produce a wrong answer.
	 */
	if (e->rel_hint + 8u <= e->reloc_len) {
		uint32_t page = 0, blk = 0;

		memcpy(&page, e->reloc + e->rel_hint, 4);
		memcpy(&blk, e->reloc + e->rel_hint + 4, 4);
		if (blk >= 8u && e->rel_hint + blk <= e->reloc_len &&
		    rva >= page && rva < (uint64_t)page + 0x1000u)
			at = e->rel_hint;
	}

	while (at + 8u <= e->reloc_len) {
		uint32_t page, blk, k;

		memcpy(&page, e->reloc + at, 4);
		memcpy(&blk, e->reloc + at + 4, 4);
		if (blk < 8u || at + blk > e->reloc_len)
			return 0;
		/* Entries name offsets within one 4KB page. */
		if (rva < page || rva >= (uint64_t)page + 0x1000u) {
			at += blk;
			/* Past the page in hand and the table is in ascending
			 * page order, so a hint that overshot must restart. */
			if (at >= e->reloc_len && e->rel_hint) {
				at = 0;
				e->rel_hint = 0;
			}
			continue;
		}
		e->rel_hint = at;
		for (k = at + 8u; k + 2u <= at + blk; k += 2u) {
			uint16_t ent;
			uint32_t type;
			uint64_t target;

			memcpy(&ent, e->reloc + k, 2);
			type = (uint32_t)(ent >> 12);
			if (type == REL_ABSOLUTE)
				continue;
			target = (uint64_t)page + (ent & 0x0fffu);
			if (type == REL_HIGHLOW && rva >= target &&
			    rva < target + 4u) {
				*start = target;
				return 4u;
			}
			if (type == REL_DIR64 && rva >= target &&
			    rva < target + 8u) {
				*start = target;
				return 8u;
			}
		}
		return 0;       /* the page's block held no entry covering it */
	}
	return 0;
}

/* --------------------------------------------------------- the comparison */

/* Which section a file offset falls in, for naming a run. */
static void section_of(const struct kof_pe_info *p, uint64_t off, char *buf,
		       size_t cap)
{
	uint32_t i;

	buf[0] = '\0';
	for (i = 0; i < p->sec_count; i++) {
		if (!p->sec[i].file_size)
			continue;
		if (off < p->sec[i].file_off ||
		    off >= p->sec[i].file_off + p->sec[i].file_size)
			continue;
		snprintf(buf, cap, "%.8s", p->sec[i].name);
		return;
	}
}

/* The section an RVA belongs to, or NULL. */
static const struct kof_pe_sec *sec_of_rva(const struct kof_pe_info *p,
					   uint64_t rva)
{
	uint32_t i;

	for (i = 0; i < p->sec_count; i++) {
		uint64_t span = p->sec[i].mem_size > p->sec[i].file_size
			      ? p->sec[i].mem_size : p->sec[i].file_size;

		if (!span || rva < p->sec[i].mem_rva ||
		    rva >= p->sec[i].mem_rva + span)
			continue;
		return &p->sec[i];
	}
	return NULL;
}

/*
 * THE NEXT SECTION THAT STARTS ABOVE `rva`, or 0 when there is none.
 *
 * This exists because a dirty range does not respect section boundaries and
 * the gaps between them are real. A section's file-backed part usually ends
 * before its virtual extent does - the tail is zero-filled by the loader and
 * has no file bytes to compare against - and the sections themselves are
 * page-aligned with gaps in between.
 *
 * The walk used to BREAK out of the whole range on reaching either, which was
 * a silent and total loss of everything above it. Measured on mscoree.dll: a
 * dirty range of 598016 bytes read 6144 of them, stopped at the end of .text's
 * file-backed part, and never reached RVA 0x44690 where every one of that
 * module's thirty-five differing runs lives. The comparison reported the module
 * clean, quickly.
 */
static uint64_t next_sec_rva(const struct kof_pe_info *p, uint64_t rva)
{
	uint64_t best = 0;
	uint32_t i;

	for (i = 0; i < p->sec_count; i++) {
		if (!p->sec[i].file_size || p->sec[i].mem_rva <= rva)
			continue;
		if (!best || p->sec[i].mem_rva < best)
			best = p->sec[i].mem_rva;
	}
	return best;
}

struct cmp_ctx {
	struct cfile *e;
	int64_t       delta;
	const struct kofw_diff_option *o;
	kofw_diff_cb  cb;
	void         *user;
	struct kofw_diff_stat *st;
	uint64_t      mapped_at;
};

/*
 * Compare one contiguous piece that lies inside ONE section.
 *
 * Returns non-zero when the caller asked to stop.
 */
static int cmp_piece(struct cmp_ctx *c, const struct kof_pe_sec *s,
		     uint64_t rva, const uint8_t *mem, const uint8_t *file,
		     uint32_t len)
{
	uint64_t base_off = s->file_off + (rva - s->mem_rva);
	uint32_t i, run_lo = 0, run_hi = 0;
	int      in_run = 0, exec = (s->perm & KOF_PE_PERM_X) != 0;

	for (i = 0; i <= len; i++) {
		int differs = 0;

		if (i < len) {
			uint64_t off = base_off + i;

			if (off >= c->e->iat_lo && off < c->e->iat_hi) {
				differs = 0;
			} else if (mem[i] != file[i] &&
				   dv_covers(c->e, rva + i)) {
				/*
				 * THE IMAGE SAYS IT REWRITES THIS BYTE ITSELF.
				 *
				 * An ARM64X image carries both forms of its own
				 * code and a table naming which bytes the
				 * loader swaps; a byte the table names is the
				 * loader doing what the file asked. Counted
				 * rather than dropped, because "275 of these
				 * were the image's own doing" and "there were
				 * none" have to look different in a report.
				 */
				differs = 0;
				if (c->st)
					c->st->dvrt_explained++;
			} else if (mem[i] != file[i]) {
				uint64_t start = 0;
				uint32_t w = reloc_width(c->e, rva + i, &start);

				if (!w) {
					differs = 1;
				} else {
					/*
					 * A RELOCATION IS VERIFIED, NOT
					 * ASSUMED.
					 *
					 * The loader added the load delta to
					 * this pointer, so the memory value
					 * must be the file's plus that delta.
					 * When it is, the difference is the
					 * loader's and there is nothing here.
					 * When it is NOT, somebody changed a
					 * pointer - and the old approach, which
					 * subtracted the delta from every
					 * reloc target before comparing, turned
					 * exactly that case into a clean byte.
					 *
					 * The whole target has to be inside
					 * this piece to be checked; one that
					 * straddles the end is reported rather
					 * than guessed at.
					 */
					uint64_t soff = start - rva;
					uint64_t mv = 0, fv = 0;
					uint32_t k;

					if (start < rva || soff + w > len) {
						differs = 1;
					} else {
						for (k = 0; k < w; k++) {
							mv |= (uint64_t)mem[soff + k] << (8u * k);
							fv |= (uint64_t)file[soff + k] << (8u * k);
						}
						if (w == 4u)
							differs = ((uint32_t)mv !=
								   (uint32_t)(fv + (uint64_t)c->delta));
						else
							differs = (mv != fv + (uint64_t)c->delta);
						if (c->st) {
							if (differs)
								c->st->reloc_wrong++;
							else
								c->st->reloc_explained++;
						}
					}
				}
			}
		}

		if (differs) {
			if (!in_run) {
				run_lo = i;
				in_run = 1;
			}
			run_hi = i + 1;
			continue;
		}
		if (!in_run)
			continue;
		if (i < run_hi + KOFW_DIFF_GAP && i < len)
			continue;               /* inside the joining gap */

		{
			struct kofw_diff_run r;
			uint32_t rl = run_hi - run_lo;

			memset(&r, 0, sizeof r);
			r.rva      = rva + run_lo;
			r.addr     = c->mapped_at + r.rva;
			r.file_off = base_off + run_lo;
			r.len      = rl;
			section_of(&c->e->info, r.file_off, r.section,
				   sizeof r.section);

			if (c->st) {
				c->st->runs++;
				c->st->bytes += rl;
				if (exec && rl <= KOFW_DIFF_SMALL)
					c->st->small_runs++;
			}
			if (c->st && c->st->runs > c->o->max_runs)
				c->st->capped = 1;
			else if (c->cb(&r, mem + run_lo, file + run_lo,
				       c->user))
				return 1;
		}
		in_run = 0;
	}
	return 0;
}

int kofw_diff_module(struct kofw_pmem *m, const struct kofw_module *md,
		     const struct kofw_diff_range *ranges, uint32_t n_ranges,
		     struct kofw_diff_cache *cache,
		     const struct kofw_diff_option *opt,
		     kofw_diff_cb cb, void *user, struct kofw_diff_stat *st)
{
	struct kofw_diff_option o;
	struct cfile scratch;
	struct cfile *e;
	struct cmp_ctx c;
	uint8_t *mbuf = NULL, *fbuf = NULL;
	uint32_t i, cap = 0;
	int rc = 0;

	if (st)
		memset(st, 0, sizeof *st);
	if (!m || !md || !md->path[0] || !ranges || !n_ranges || !cb)
		return 0;

	memset(&o, 0, sizeof o);
	if (opt)
		o = *opt;
	if (!o.max_runs)
		o.max_runs = RUNS_DEFAULT;

	e = cache_get(cache, md->path, &scratch);
	if (!e) {
		if (st)
			st->base_unknown = 1;
		return 0;
	}

	memset(&c, 0, sizeof c);
	c.e         = e;
	c.delta     = (int64_t)(md->base - e->image_base);
	c.o         = &o;
	c.cb        = cb;
	c.user      = user;
	c.st        = st;
	c.mapped_at = md->base;

	for (i = 0; i < n_ranges; i++) {
		uint64_t rva = ranges[i].addr - md->base;
		uint64_t left = ranges[i].len;

		if (ranges[i].addr < md->base || !left)
			continue;

		/*
		 * A RANGE IS CUT AT EVERY SECTION BOUNDARY, because a section
		 * is the unit that decides both the file offset and whether to
		 * compare at all - a writable section is skipped, and a range
		 * that spanned into one would otherwise carry its bytes along.
		 */
		while (left) {
			const struct kof_pe_sec *s = sec_of_rva(&e->info, rva);
			uint64_t room;
			uint32_t take;

			/*
			 * OUTSIDE A SECTION, OR PAST ITS FILE-BACKED PART:
			 * SKIP FORWARD, DO NOT STOP.
			 *
			 * Both cases mean "no file bytes correspond to this
			 * RVA" and neither says anything about the rest of the
			 * range. See next_sec_rva for what stopping cost.
			 */
			if (!s || rva >= s->mem_rva + s->file_size) {
				uint64_t nx = next_sec_rva(&e->info, rva);
				uint64_t skip;

				if (!nx || nx <= rva)
					break;          /* nothing above */
				skip = nx - rva;
				if (skip >= left)
					break;
				rva  += skip;
				left -= skip;
				continue;
			}
			room = s->mem_rva + s->file_size - rva;
			take = (uint32_t)(left < room ? left : room);
			if (!take)
				break;
			if (take > 0x10000u)
				take = 0x10000u;

			if (!o.with_writable && (s->perm & KOF_PE_PERM_W))
				goto advance;
			if (s->characteristics & 0x02000000u)   /* DISCARDABLE */
				goto advance;

			if (take > cap) {
				uint8_t *nm = realloc(mbuf, take);
				uint8_t *nf = realloc(fbuf, take);

				if (!nm || !nf) {
					free(nm ? nm : mbuf);
					free(nf ? nf : fbuf);
					mbuf = fbuf = NULL;
					goto done;
				}
				mbuf = nm;
				fbuf = nf;
				cap = take;
			}

			if (kofw_pmem_read(m, md->base + rva, mbuf, take) !=
			    take)
				goto advance;   /* short read: skip, not fail */
			if (!cfile_read(e, s->file_off + (rva - s->mem_rva),
					fbuf, take))
				goto advance;
			if (st) {
				st->mem_read  += take;
				st->file_read += take;
			}
			rc = 1;
			if (cmp_piece(&c, s, rva, mbuf, fbuf, take))
				goto done;
advance:
			rva  += take;
			left -= take;
		}
	}

done:
	free(mbuf);
	free(fbuf);
	if (e == &scratch)
		cfile_drop(&scratch);
	return rc;
}
