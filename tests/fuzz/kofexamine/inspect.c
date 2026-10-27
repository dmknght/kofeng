/*
 * kofexamine/inspect - kofinspect.c over corrupt objects: kof_inspect_identify and kof_inspect_declare (every format number),
 * kof_inspect_free, the region map, the region entropy, kof_dump_dir_for, and (one iteration in 64) kof_dump_object /
 * kof_dump_walk into a scratch directory.
 *
 * Seeds are the objects the unit tests build: ELF 32/64, both byte orders, REL and EXEC (tests/lib/genome/hk.h), PE32 and PE32+,
 * one archive of each container format the writers know (tests/lib/ctr_writers.h) and a shell script. ELF and PE bring a field
 * map (the header offsets, the section and program header records), so the mutators aim at e_shoff, the counts, the sizes.
 *
 * Held: identify answers a row or NULL and the view agrees (`ctx.format` is the row's format); every extent of every region is
 * inside the object; the region map answers what the resolver says, at sampled offsets; entropy is at most 8 bits (64 eighths);
 * a dump writes only what the extents name, clipped to the object; the directory name is made of safe characters. The call twice
 * gives one digest; with the k-th allocation refused nothing leaks (the map is freed after a failed build: its caller does).
 * KNOWN DEFECTS carved out and COUNTED in the digest, not held: EX-1 (an identify NULL where the engine's loop would have gone on;
 * not reached by this input family, see tests/unit/kx_inspect.c) and EX-5 (a ".." segment in the name of kof_dump_walk: such a name
 * is not written, because the call would create files above the scratch root).
 */
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../../kofexamine/kofinspect_private.h"
#include "../../lib/ctr_writers.h"
#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"

static struct fz_field fld[8][32];
static struct fz_map map[8];

static void fadd(unsigned v, uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &fld[v][map[v].n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seeds(struct fz_corpus *c)
{
	static struct hk_elf e;
	static struct hk_pe p;
	static const char *const fmts[] = { "zip", "tar", "rar", "lha", "arj", "cab", "chm", "7z", "ole", "pdf", "gzip", "rar5" };
	static const char *const names[] = { "elf32le", "elf64le", "elf32be", "elf64be", "elf32rel", "elf64rel" };
	unsigned i, v, k;

	for (i = 0; i < 6; i++) {
		int is64 = i & 1;

		hk_elf(&e, is64, i >= 2 && i < 4, i >= 4);
		v = i;
		map[v].f = fld[v];
		map[v].n = 0;
		fadd(v, is64 ? 0x20 : 0x1c, is64 ? 8 : 4, FZ_OFFSET);
		fadd(v, is64 ? 0x28 : 0x20, is64 ? 8 : 4, FZ_OFFSET);
		fadd(v, is64 ? 0x38 : 0x2c, 2, FZ_COUNT);
		fadd(v, is64 ? 0x3a : 0x2e, 2, FZ_LEN);
		fadd(v, is64 ? 0x3c : 0x30, 2, FZ_COUNT);
		fadd(v, is64 ? 0x3e : 0x32, 2, FZ_COUNT);
		for (k = 0; k < 4; k++) {
			fadd(v, e.sh + k * e.sh_ent + (is64 ? 24u : 16u), is64 ? 8 : 4, FZ_OFFSET);
			fadd(v, e.sh + k * e.sh_ent + (is64 ? 32u : 20u), is64 ? 8 : 4, FZ_LEN);
		}
		fadd(v, e.ph + (is64 ? 8u : 4u), is64 ? 8 : 4, FZ_OFFSET);
		fadd(v, e.ph + (is64 ? 32u : 16u), is64 ? 8 : 4, FZ_LEN);
		map[v].rec_off = e.sh;
		map[v].rec_size = e.sh_ent;
		map[v].rec_n = 5;
		fz_corpus_add_map(c, names[i], e.b, e.n, &map[v]);
	}
	for (i = 0; i < 2; i++) {
		hk_pe(&p, (int)i);
		v = 6 + i;
		map[v].f = fld[v];
		map[v].n = 0;
		fadd(v, 0x3c, 4, FZ_OFFSET);
		fadd(v, p.lfanew + 6u, 2, FZ_COUNT);
		fadd(v, p.lfanew + 20u, 2, FZ_LEN);
		fadd(v, p.opt + 16u, 4, FZ_RVA);
		fadd(v, p.opt + 56u, 4, FZ_LEN);
		for (k = 0; k < 4; k++)
			fadd(v, p.dirs + 4u * k, 4, k % 2u ? FZ_LEN : FZ_RVA);
		for (k = 0; k < 3; k++) {
			fadd(v, p.sec + 40u * k + 8u, 4, FZ_LEN);
			fadd(v, p.sec + 40u * k + 12u, 4, FZ_RVA);
			fadd(v, p.sec + 40u * k + 16u, 4, FZ_LEN);
			fadd(v, p.sec + 40u * k + 20u, 4, FZ_OFFSET);
		}
		map[v].rec_off = p.sec;
		map[v].rec_size = 40;
		map[v].rec_n = 3;
		fz_corpus_add_map(c, i ? "pe32plus" : "pe32", p.b, p.n, &map[v]);
	}
	for (k = 0; k < sizeof fmts / sizeof fmts[0]; k++) {
		static const char inner[] = "hello inner member, hello inner member, hello inner member";
		struct cw in, w;
		unsigned f = cw_find(fmts[k]);

		if (f >= CW_NFORMATS)
			continue;
		memset(&in, 0, sizeof in);
		cw_put(&in, inner, sizeof inner - 1u);
		w = cw_wrap(f, &in);
		if (!w.oom && w.n)
			fz_corpus_add(c, fmts[k], w.p, w.n);
		cw_free(&w);
		cw_free(&in);
	}
	fz_corpus_add(c, "script", "#!/bin/sh\necho hello\nexit 0\n", 28);
}

static const char *const dict[] = { "MZ", "PE\0\0", "\177ELF", "PK\3\4", "%PDF-", "ustar", ".text", "BSJB", NULL };

struct st {
	struct kof_obj_ctx       ctx;
	void                    *view;
	const struct kof_parser *p;
};

static struct st state;
static char scratch[128];

static void *parse(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_buf buf = kof_buf_make(in, n);
	struct kof_obj_ctx dctx;
	void *dview = NULL;
	const struct kof_parser *dp;
	unsigned f;

	memset(&state, 0, sizeof state);
	state.p = kof_inspect_identify(buf, &state.ctx, &state.view);
	if (!state.p) {
		/* declared as every format number (a declaration is not a sniff): a row parses or refuses, and a refusal leaves no view.
		 * FINDING EX-12 (tests_kx/findings/EX-12): the process-record row (KOF_EVT_PROC, libkofeng/analyzers/parsers/processes/
		 * proc_parse.c:118) reads `struct kof_proc_rec` (8-byte aligned) straight out of the object's bytes, so a declaration over a
		 * buffer that is not 8-aligned is undefined behaviour (UBSAN aborts). The declared objects are therefore handed a malloc'd
		 * copy here, which is aligned; the unaligned case is the finding, not what this row looks for. */
		uint8_t *al = malloc(n ? n : 1u);

		if (al)
			memcpy(al, in, n);
		buf = kof_buf_make(al ? al : in, n);
		for (f = 0; al && f < 256; f++) {
			dp = kof_inspect_declare(buf, (uint8_t)f, &dctx, &dview);
			FZ_CHECK(c, (dp != NULL) == (dview != NULL), "kof_inspect_declare: a row and no view, or a view and no row");
			if (dp) {
				FZ_CHECK(c, dp->format == f, "kof_inspect_declare answered another format's row");
				kof_inspect_free(dp, dview);
			}
		}
		free(al);
		fz_digest(c, 0xdec1a4e);
		return NULL;
	}
	FZ_CHECK(c, state.view != NULL, "kof_inspect_identify answered a row and no view");
	return &state;
}

static int rm_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	(void)st; (void)flag; (void)f;
	return remove(p);
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct st *s = h;
	const struct kof_parser *p = s->p;
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS > 4096 ? 4096 : KOF_SCAN_MAX_EXTENTS];
	uint32_t k, e, got;
	uint64_t sum = 0;
	struct kof_region_map m;
	int ok;

	FZ_CHECK(c, s->ctx.format == p->format, "the object's format is not the row identify answered");
	FZ_CHECK(c, p->n_regions <= 32, "a parser row with more than 32 regions: the region map cannot hold them");
	fz_digest(c, ((uint64_t)p->format << 32) ^ p->n_regions);
	if (s->ctx.resolve_scan)
		for (k = 0; k < p->n_regions; k++) {
			got = s->ctx.resolve_scan(&s->ctx, p->regions[k], ext, (uint32_t)(sizeof ext / sizeof ext[0]));
			FZ_CHECK(c, got <= sizeof ext / sizeof ext[0], "resolve_scan reported more extents than it was given room for");
			for (e = 0; e < got && e < sizeof ext / sizeof ext[0]; e++) {
				fz_step(&c->steps, 1);
				FZ_CHECK(c, ext[e].off <= n && ext[e].len <= n - ext[e].off, "a region extent outside the object");
				sum += ext[e].len + ext[e].off;
			}
			fz_digest(c, got);
			FZ_CHECK(c, kof_inspect_region_entropy(&s->ctx, kof_buf_make(in, n), p->regions[k]) <= 64u, "entropy above 8 bits");
			fz_digest(c, kof_inspect_region_entropy(&s->ctx, kof_buf_make(in, n / 2u), p->regions[k]));
		}
	fz_digest(c, sum);

	/* the map: built (it may fail under a refused allocation) and ALWAYS freed, as its one caller does */
	ok = kof_region_map_build(&m, &s->ctx, p);
	if (ok) {
		uint64_t off;
		uint32_t cnt = 0;

		FZ_CHECK(c, m.n_reg <= 32, "region map with more than 32 regions");
		for (off = 0; off < n && cnt < 64; off += 1u + n / 64u, cnt++) {
			uint32_t want = 0, bit = kof_region_map_at(&m, off);

			if (s->ctx.resolve_scan)
				for (k = 0; k < p->n_regions && !want; k++) {
					got = s->ctx.resolve_scan(&s->ctx, p->regions[k], ext, (uint32_t)(sizeof ext / sizeof ext[0]));
					for (e = 0; e < got && e < sizeof ext / sizeof ext[0]; e++)
						if (off >= ext[e].off && off - ext[e].off < ext[e].len) {
							want = p->regions[k];
							break;
						}
				}
			FZ_CHECK(c, bit == want, "the region map and the parser's resolver disagree on the region of a byte");
			fz_digest(c, bit);
		}
	}
	kof_region_map_free(&m);
	FZ_CHECK(c, m.n_reg == 0, "kof_region_map_free left a region in the map");

	/* a name made from the object's first bytes, every iteration: the directory name is safe */
	{
		char path[300], out[KOF_DUMP_PATH_ROOM + 64];
		size_t i, l = n < 200 ? n : 200;

		memcpy(path, "/d/", 3);
		for (i = 0; i < l; i++)
			path[3 + i] = in[i] ? (char)in[i] : 'z';
		path[3 + l] = 0;
		if (kof_dump_dir_for(path, out, sizeof out)) {
			const char *nm = strrchr(out, '/');

			FZ_CHECK(c, nm && strlen(nm + 1) <= 255 && !strchr(nm + 1, '\\'), "a dump directory name past the 255 bytes a component holds");
			for (i = 1; nm && nm[i]; i++) {
				unsigned char ch = (unsigned char)nm[i];

				FZ_CHECK(c, (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' ||
					 ch == '-' || ch == '_', "an unsafe byte in a dump directory name");
			}
			fz_digest(c, strlen(out));
		}
	}

	/* one iteration in 64 writes: the dump of the object into the scratch directory, and removes it */
	if ((c->iter & 63u) == 0 && !c->failk) {
		char dir[200], path[400], err[200];
		struct kof_dump_stat dst;
		struct stat sb;
		int r;

		snprintf(scratch, sizeof scratch, "build/fuzz/kx_dump_%d", (int)getpid());
		mkdir("build", 0777);
		mkdir("build/fuzz", 0777);
		snprintf(dir, sizeof dir, "%s", scratch);
		r = kof_dump_object(dir, kof_buf_make(in, n), p, &s->ctx, &dst, err, sizeof err);
		fz_digest(c, (uint64_t)r);
		if (r) {
			snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", dir);
			FZ_CHECK(c, n == 0 || (stat(path, &sb) == 0 && (uint64_t)sb.st_size == n), "the whole-object file is not the object");
			FZ_CHECK(c, dst.whole_bytes == n, "whole_bytes is not the object's size");
			FZ_CHECK(c, dst.region_bytes <= (uint64_t)n * 32u, "region bytes beyond what 32 clipped regions can hold");
			snprintf(path, sizeof path, "%s/LAYOUT", dir);
			FZ_CHECK(c, stat(path, &sb) == 0, "no LAYOUT file after a successful dump");
		}
		(void)nftw(scratch, rm_cb, 8, FTW_DEPTH | FTW_PHYS);
	}
}

static void drop(void *h)
{
	struct st *s = h;

	kof_inspect_free(s->p, s->view);
	s->view = NULL;
}

FZ_ADAPTER(kx_inspect,
	   .name = "kofexamine/inspect",
	   .covers = "kof_inspect_identify kof_inspect_declare kof_inspect_free kof_region_map_build kof_region_map_free kof_region_map_at "
		     "kof_inspect_region_entropy kof_dump_dir_for kof_dump_object",
	   .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = seeds, .dict = dict, .parse = parse, .walk = walk, .drop = drop);
