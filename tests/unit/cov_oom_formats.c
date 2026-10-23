/*
 * cov_oom_formats - memory refused must not change an answer in silence, for the formats silent_oom_sweep does not reach.
 *
 * THE PROPERTY, as silent_oom_sweep.c states it (CLAUDE.md rule 4): when an allocation inside a scan is refused the scan
 * either gives the answer it gives with memory or it SAYS it did not - an object marked broken, a counter that moved, a
 * non-zero return. The lie is a different answer (a child never opened, content missing) with every signal at zero.
 *
 * silent_oom_sweep covers ELF, PE and zip. This covers the two that hold content behind a decoder:
 *
 *   7Z    an archive whose folder is LZMA2 behind the x86 filter (a chain, a decoder with a large model, a solid block),
 *         and the same archive with its header coded with LZMA (a second decode before the first can start)
 *   OLE   a compound document with a VBA project: the FAT, the mini FAT, the OVBA coded directory and module, the gathered body
 *
 * The method: scan once to count the allocations, then again with the n-th refused for every n (a fresh scanner each time).
 * A run whose answer differs from the control and whose signals are all zero is a SILENT LOSS, and none is allowed: the
 * OLE sweep used to find three (a refused allocation for a child's label dropped its name with every signal at zero,
 * kof_src_label in scanners/objsrc.c; the child now carries KOF_BROKEN_LIMIT).
 *
 * Under a sanitizer there is no interposed allocator and the sweep is skipped (reported).
 */


#include "failalloc.h"
#include "hostile_engine.h"
#include "notes.h"

#include "cov_fixtures_7z.h"
#include "cov_fixtures_ole.h"

#define SIG_MAX 4096u

/* What the test modules said while the object was scanned - see notes.h. */
static struct note_list pend;

struct run {
	char     sig[SIG_MAX];
	unsigned n_obj, signalled;
	int      rc;
};

static int on_obj(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct run *r = user;
	size_t at = strlen(r->sig);
	struct note_list got;
	uint32_t i;

	(void)bytes;
	notes_take(&pend, &got);
	r->n_obj++;
	if (res->broken || res->verdict_incomplete)
		r->signalled++;
	if (at + 256u < SIG_MAX)
		at += (size_t)snprintf(r->sig + at, SIG_MAX - at, "[%s|%llu|%u]", name ? name : "", (unsigned long long)len, got.n);
	for (i = 0; i < got.n; i++)
		if (at + 160u < SIG_MAX)
			at += (size_t)snprintf(r->sig + at, SIG_MAX - at, "{%s}", got.name[i]);
	return 0;
}

static struct run scan_once(kof_engine *eng, const uint8_t *b, uint64_t n, long nth, long *count, int *reached, int *stat_moved)
{
	struct run r;
	kof_scanner *sc;
	struct kof_scan_option opt;
	const struct kof_stats *st;

	memset(&r, 0, sizeof r);
	*reached = 0;
	if (stat_moved)
		*stat_moved = 0;
	sc = kscan_new(eng);
	if (!sc) {
		r.rc = -1;
		return r;
	}
	kscan_on_debug(sc, notes_on, &pend);
	memset(&pend, 0, sizeof pend);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	fa_arm_nth(nth);
	r.rc = kscan_bytes(sc, b, n, "sweep", &opt, on_obj, &r);
	if (count)
		*count = fa_count();
	*reached = fa_disarm_hit();
	st = kscan_stats(sc);
	if (st && stat_moved)
		*stat_moved = st->limit_hits || st->names_invalid || st->spill_ceiling || st->spill_full || st->trace_capped ||
			      st->mutation_trunc_objects;
	kscan_free(sc);
	return r;
}

struct sweep_out {
	long allocs, refused, lossy, silent, empty;
};

static struct sweep_out sweep(kof_engine *eng, const char *what, const uint8_t *b, uint64_t n, long stride_after, int verbose)
{
	struct sweep_out o;
	struct run ctl;
	long count = 0, i;
	int reached, moved;

	memset(&o, 0, sizeof o);
	(void)scan_once(eng, b, n, 0, &count, &reached, &moved);
	ctl = scan_once(eng, b, n, 0, &count, &reached, &moved);
	o.allocs = count;
	CK(ctl.rc >= 1 && ctl.n_obj >= 1u, "%s: the control scan answers (rc %d, %u objects)", what, ctl.rc, ctl.n_obj);
	for (i = 1; i <= count; i += (i > stride_after ? 1 + i / stride_after : 1)) {
		struct run r;
		int sm = 0;

		r = scan_once(eng, b, n, i, NULL, &reached, &sm);
		if (!reached)
			continue;
		o.refused++;
		if (strcmp(r.sig, ctl.sig) == 0 && r.n_obj == ctl.n_obj)
			continue;
		o.lossy++;
		if (r.rc < 0 || r.signalled > ctl.signalled || sm)
			continue;
		if (r.n_obj == 0) {
			o.empty++;
			continue;
		}
		o.silent++;
		if (verbose) {
			printf("  silent [%s] allocation %ld of %ld refused, answer changed:\n      control %s\n      refused %s\n      frames:", what,
			       i, count, ctl.sig, r.sig);
			fa_print_site();
			printf("\n");
		}
	}
	return o;
}

static uint8_t g_plain[4][8192], g_pack[1 << 16], g_arc[1 << 17], g_hdr[4096], g_coded_hdr[4096], g_all[1 << 15];
static struct doc g_doc;

static void report(const char *what, const struct sweep_out *s)
{
	printf("  %-26s %5ld allocations, %5ld refused, %4ld changed the answer, %ld silently (+%ld with no object at all)\n", what,
	       s->allocs, s->refused, s->lossy, s->silent, s->empty);
	CK(s->silent == 0, "%s: no refused allocation changed an answer in silence (%ld did; run with -v for the sites)", what, s->silent);
}

/* ---- the fixtures ---------------------------------------------------------------------------- */

static size_t sevenzip_chain(uint8_t *out, size_t cap, int coded_header)
{
	static const struct afile files[2] = { { "prog.bin", 0, 0 }, { "notes.txt", 0, 0 } };
	struct folder fo;
	size_t n0 = x86_file(g_plain[0], 300), n1 = text_file(g_plain[1], 3, 12), total, packed, hdr;

	memcpy(g_all, g_plain[0], n0);
	memcpy(g_all + n0, g_plain[1], n1);
	total = n0 + n1;
	packed = via_tool("/usr/bin/xz -c --format=raw --x86 --lzma2=preset=6,dict=1MiB", g_all, total, g_pack, sizeof g_pack);
	if (!packed)
		return 0;
	memset(&fo, 0, sizeof fo);
	fo.coder[0] = &C_LZMA2;
	fo.coder[1] = &C_BCJ;
	fo.n_coders = 2;
	fo.packed_len = packed;
	fo.unpack_len = total;
	fo.n_files = 2;
	fo.file_len[0] = n0;
	fo.file_len[1] = n1;
	hdr = build_header(g_hdr, sizeof g_hdr, &fo, 1, files, 2);
	if (!coded_header)
		return assemble(out, cap, g_pack, packed, g_hdr, hdr);
	{
		static uint8_t data[1 << 16], enc_hdr[256];
		struct wb e = { enc_hdr, 0, sizeof enc_hdr };
		size_t hp = via_tool("/usr/bin/xz -c --format=raw --lzma1=lc=3,lp=0,pb=2,dict=1MiB", g_hdr, hdr, g_coded_hdr, sizeof g_coded_hdr);

		if (!hp)
			return 0;
		memcpy(data, g_pack, packed);
		memcpy(data + packed, g_coded_hdr, hp);
		wb_u8(&e, ID_ENCODED);
		wb_u8(&e, ID_PACKINFO);
		wb_num(&e, packed);
		wb_num(&e, 1);
		wb_u8(&e, ID_SIZE);
		wb_num(&e, hp);
		wb_u8(&e, ID_END);
		wb_u8(&e, ID_UNPACK);
		wb_u8(&e, ID_FOLDER);
		wb_num(&e, 1);
		wb_u8(&e, 0);
		wb_num(&e, 1);
		wb_coder(&e, &C_LZMA);
		wb_u8(&e, ID_CODERSSIZE);
		wb_num(&e, hdr);
		wb_u8(&e, ID_END);
		wb_u8(&e, ID_END);
		return assemble(out, cap, data, packed + hp, enc_hdr, e.n);
	}
}

int main(int argc, char **argv)
{
	int verbose = argc > 1 && !strcmp(argv[1], "-v");
	kof_engine *rel;
	struct sweep_out s;
	size_t n;

	fa_init();
#if !FA_AVAILABLE
	printf("cov_oom_formats: a sanitizer owns malloc: the failing-allocation sweep is skipped\n");
	(void)verbose; (void)rel; (void)s; (void)n;
	return 0;
#else
	rel = keng_open("build/release/databases");
	if (!rel) {
		printf("cov_oom_formats: no database - nothing tested\n");
		return 0;
	}
	if (access("/usr/bin/xz", X_OK) == 0) {
		n = sevenzip_chain(g_arc, sizeof g_arc, 0);
		CK(n > 0, "the 7z with a plain header was written");
		s = sweep(rel, "7z, plain header", g_arc, n, 800, verbose);
		report("7z, plain header", &s);
		n = sevenzip_chain(g_arc, sizeof g_arc, 1);
		CK(n > 0, "the 7z with a coded header was written");
		s = sweep(rel, "7z, coded header", g_arc, n, 800, verbose);
		report("7z, coded header", &s);
	} else {
		printf("  (xz is not installed: the 7z sweeps are skipped)\n");
	}
	build(&g_doc);
	s = sweep(rel, "ole with a vba project", g_doc.bytes, g_doc.len, 800, verbose);
	report("ole with a vba project", &s);
	keng_close(rel);
	printf("cov_oom_formats: %u check(s), %u failed\n", he_checks, he_fails);
	return he_fails != 0;
#endif
}
