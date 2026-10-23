/*
 * silent_oom_sweep - memory refused must not change an answer in silence.
 *
 * THE PROPERTY (CLAUDE.md rule 4, QUALITY_AUDIT II.3: "failure to allocate is a verdict,
 * not a crash"): when an allocation inside a scan is refused, the scan either gives the same
 * answer it gives with memory, or it SAYS it did not - an object marked broken
 * (KOF_BROKEN_*), a counter of kof_stats that moved (limit_hits and the others), a verdict
 * flagged incomplete, a non-zero return. The one answer that is a lie is a DIFFERENT result
 * (a finding gone, a child never opened) with every signal at zero: "examined, clean".
 *
 * HOW IT LOOKS FOR THE LIE. A fixture is scanned once to count its allocations, then again
 * with the n-th allocation refused, for every n (a fresh scanner each time, so the caches the
 * scan builds lazily are allocated inside the window). The result of a run is a signature
 * (per object: name, findings, children); a run whose signature differs from the control and
 * whose signals are all zero is a SILENT LOSS, and the frames above the refused allocation
 * are printed so the site is found with addr2line. That is the audit made by running the
 * code instead of reading 300 allocation sites.
 *
 * WHAT IT PINS. `silent` for each fixture is held to the number the engine has today - a
 * site fixed lowers it and turns the marker red (FIXED-UNEXPECTEDLY) until the number is
 * lowered, exactly as known_miss.h does for every other cap. The sites that are fixed have
 * their own cases in silent_cuts_*.c.
 *
 * Under a sanitizer there is no interposed allocator (failalloc.h): the sweep is reported as
 * skipped and nothing is asserted.
 */

#define _GNU_SOURCE

/* the big-endian objects of the endian tests: the view whose plan, canonical bytes and functions are the
 * allocations of scan_norm_endian.c (fix_engine2: the sweep had no object that reaches them). Sized as
 * endian_view.c sizes them - a smaller object is under the normaliser's floor and gets no view - and
 * included first: the kit's CK is the lib tests' and is dropped for this file's. */
#define EK_MAX 16384u
#define EK_CODE_UNITS 1500u
#include "../lib/genome/endian_kit.h"
#undef CK
#include "norm_pe_fx.h"

#include "caps_fix.h"
#include "caps_pe_fix.h"
#include "failalloc.h"
#include "known_miss.h"
#include "notes.h"

#include <stdarg.h>

#define SIG_MAX 4096u

struct run {
	char     sig[SIG_MAX];
	unsigned n_obj;
	unsigned signalled;     /* objects with broken != 0 or verdict_incomplete */
	int      rc;
};

static int on_obj(const char *name, const void *bytes, uint64_t len,
		  const struct kof_result *res, void *user)
{
	struct run *r = user;
	size_t at = strlen(r->sig);
	struct note_list got;
	uint32_t i;

	(void)bytes;
	notes_here(&got);
	r->n_obj++;
	if (res->broken || res->verdict_incomplete)
		r->signalled++;
	if (at + 256u < SIG_MAX)
		at += (size_t)snprintf(r->sig + at, SIG_MAX - at, "[%s|%llu|%u]", name ? name : "",
				       (unsigned long long)len, got.n);
	for (i = 0; i < got.n; i++)
		if (at + 160u < SIG_MAX)
			at += (size_t)snprintf(r->sig + at, SIG_MAX - at, "{%s}", got.name[i]);
	return 0;
}

static kof_engine *eng;
static long nomem_seen;           /* runs whose answer was KOF_ERR_NOMEM: the walk's root record refused */

/* One scan with a fresh scanner. `nth` > 0 refuses that allocation; 0 only counts. */
static struct run scan_once(const uint8_t *b, uint64_t n, long nth, long *count, int *reached,
			    int *stat_moved)
{
	struct run r;
	kof_scanner *sc;
	struct kof_scan_option opt;
	const struct kof_stats *st;

	memset(&r, 0, sizeof r);
	*reached = 0;
	if (stat_moved)
		*stat_moved = 0;
	sc = notes_scanner(eng);
	if (!sc) {
		r.rc = -1;
		return r;
	}
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
		*stat_moved = st->limit_hits || st->names_invalid || st->spill_ceiling || st->spill_full ||
			      st->trace_capped || st->mutation_trunc_objects;
	kscan_free(sc);
	return r;
}

struct sweep_out {
	long allocs, refused, lossy, silent, empty;
};

static struct sweep_out sweep(const char *what, const uint8_t *b, uint64_t n, long stride_after,
			      int verbose)
{
	struct sweep_out o;
	struct run ctl;
	long count = 0, i;
	int reached, moved;

	memset(&o, 0, sizeof o);
	(void)scan_once(b, n, 0, &count, &reached, &moved);      /* warm: any one-time table */
	ctl = scan_once(b, n, 0, &count, &reached, &moved);
	o.allocs = count;
	if (verbose)
		printf("  control [%s]: %u object(s) %s\n", what, ctl.n_obj, ctl.sig);
	CK(ctl.rc >= 1 && ctl.n_obj >= 1u);
	for (i = 1; i <= count; i += (i > stride_after ? 1 + i / stride_after : 1)) {
		struct run r;
		int sm = 0;

		r = scan_once(b, n, i, NULL, &reached, &sm);
		if (!reached)
			continue;
		o.refused++;
		if (strcmp(r.sig, ctl.sig) == 0 && r.n_obj == ctl.n_obj)
			continue;
		o.lossy++;
		if (r.rc == KOF_ERR_NOMEM)
			nomem_seen++;
		if (r.rc < 0 || r.signalled > ctl.signalled || sm)
			continue;               /* it said so */
		/* No object delivered to the callback, and no error code: the walk's root record was refused. scan_walk.c
		 * answers that KOF_ERR_NOMEM (walk_result), which is the `rc < 0` above, so a run that lands here is the
		 * lie again; counted and held to zero below. */
		if (r.n_obj == 0) {
			o.empty++;
			continue;
		}
		o.silent++;
		if (verbose) {
			printf("  silent [%s] allocation %ld of %ld refused, answer changed:\n"
			       "      control %s\n      refused %s\n      frames:", what, i, count, ctl.sig, r.sig);
			fa_print_site();
			printf("\n");
		}
	}
	return o;
}

/* ---- fixtures, in memory ------------------------------------------------------------------ */

static uint8_t elf_img[1u << 16], pe_img[1u << 16], zip_img[1u << 14];

static uint64_t elf_stager(void)
{
	uint8_t code[256];
	unsigned at = 0;

	at = cf_filler64(code, at, 1);
	at = cf_stager64(code, at);
	return cf_elf64(elf_img, sizeof elf_img, code, at);
}

/* The large object of silent_cuts_engine.c: 30 reads, a stager and the marker tests/sigs/
 * sig_graph_grow_00.c wants - its finding exists only if the graph block was built. */
static uint64_t elf_graph(void)
{
	uint8_t code[2048];
	unsigned at = 0, i;
	static const char marker[] = "GRAPHGROW-MARK";

	for (i = 0; i < 30u; i++)
		at = cf_filler64(code, at, i + 1u);
	at = cf_stager64(code, at);
	memcpy(code + at, marker, sizeof marker);
	return cf_elf64(elf_img, sizeof elf_img, code, at + sizeof marker);
}

/* A stager followed by a long run of zero bytes inside the segment: the shape the normaliser
 * makes a view of (a child object), so the view's own tables are inside the sweep. */
static uint64_t elf_padded(void)
{
	static uint8_t code[24000];
	unsigned at = 0, i;

	memset(code, 0, sizeof code);
	for (i = 0; i < 4u; i++)
		at = cf_filler64(code, at, i + 1u);
	at = cf_stager64(code, at);
	return cf_elf64(elf_img, sizeof elf_img, code, sizeof code);
}

static uint64_t pe_stager(void)
{
	uint8_t code[2048];
	unsigned n = pe32_stager(code, 100);

	return pe32_code(pe_img, sizeof pe_img, code, n);
}

static void put32le(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void put16le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

/* A zip of `n` stored members, each a different line of text. */
static uint64_t zip_of(unsigned n)
{
	uint8_t *p = zip_img;
	uint32_t cd_at, cd_len;
	unsigned i;

	for (i = 0; i < n; i++) {
		char name[16], body[48];
		size_t nl, bl;

		nl = (size_t)snprintf(name, sizeof name, "m%u.txt", i);
		bl = (size_t)snprintf(body, sizeof body, "member %u of the sweep archive\n", i);
		put32le(p, 0x04034b50u); put16le(p + 4, 20); put16le(p + 6, 0); put16le(p + 8, 0);
		put32le(p + 10, 0); put32le(p + 14, 0);
		put32le(p + 18, (uint32_t)bl); put32le(p + 22, (uint32_t)bl);
		put16le(p + 26, (uint16_t)nl); put16le(p + 28, 0);
		memcpy(p + 30, name, nl); memcpy(p + 30 + nl, body, bl);
		p += 30 + nl + bl;
	}
	cd_at = (uint32_t)(p - zip_img);
	/* central directory, rebuilt with the same offsets */
	{
		uint32_t off = 0;

		for (i = 0; i < n; i++) {
			char name[16], body[48];
			size_t nl = (size_t)snprintf(name, sizeof name, "m%u.txt", i);
			size_t bl = (size_t)snprintf(body, sizeof body, "member %u of the sweep archive\n", i);

			put32le(p, 0x02014b50u); put16le(p + 4, 20); put16le(p + 6, 20);
			put16le(p + 8, 0); put16le(p + 10, 0); put32le(p + 12, 0); put32le(p + 16, 0);
			put32le(p + 20, (uint32_t)bl); put32le(p + 24, (uint32_t)bl);
			put16le(p + 28, (uint16_t)nl); put16le(p + 30, 0); put16le(p + 32, 0);
			put16le(p + 34, 0); put16le(p + 36, 0); put32le(p + 38, 0); put32le(p + 42, off);
			memcpy(p + 46, name, nl);
			p += 46 + nl;
			off += (uint32_t)(30 + nl + bl);
		}
	}
	cd_len = (uint32_t)((p - zip_img) - cd_at);
	put32le(p, 0x06054b50u); put16le(p + 4, 0); put16le(p + 6, 0);
	put16le(p + 8, (uint16_t)n); put16le(p + 10, (uint16_t)n);
	put32le(p + 12, cd_len); put32le(p + 16, cd_at); put16le(p + 20, 0);
	return (uint64_t)(p + 22 - zip_img);
}

/* A big-endian MIPS object: a rule cut from the little-endian build can use its view, so the scan makes
 * one, and the view's endian plan is built, applied, described and its functions remapped. */
static uint64_t elf_be_mips(void)
{
	static struct ek_obj be;

	ek_build(&be, &ek_archs[0], 1, 1);
	memcpy(elf_img, be.b, be.n);
	return be.n;
}

/* A PE of four writable code sections, each with a wide string, and a data section: the view narrows the
 * strings and keeps the code, and its region table, boundary table and image description are the
 * allocations of scan_norm.c (norm_defect_engine N3, N5-N7 found refusals there one at a time). */
static uint64_t pe_wide_view(void)
{
	static uint8_t big[PE_MAX];
	uint32_t n = build_pe(big, 4, 0xe0000020u);

	memcpy(pe_img, big, n);
	return n;
}

int main(int argc, char **argv)
{
	struct sweep_out s;
	uint64_t n;
	long empty = 0;
	int verbose = argc > 1 && !strcmp(argv[1], "-v");

	(void)argc;
	fa_init();
	eng = keng_open(argc > 2 ? argv[2] : "build/test/databases-sigs");
	if (!eng) {
		printf("silent_oom_sweep: no database - nothing tested\n");
		return 0;
	}
#if !FA_AVAILABLE
	printf("silent_oom_sweep: a sanitizer owns malloc: the failing-allocation sweep is skipped\n");
	keng_close(eng);
	return 0;
#else
	n = elf_stager();
	s = sweep("elf stager", elf_img, n, 1500, verbose);
	printf("  elf stager: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	n = elf_graph();
	s = sweep("graph rule", elf_img, n, 1500, verbose);
	printf("  graph rule: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	n = elf_padded();
	s = sweep("padded elf", elf_img, n, 1500, verbose);
	printf("  padded elf: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	n = elf_be_mips();
	s = sweep("big-endian mips elf", elf_img, n, 1500, verbose);
	printf("  big-endian mips elf: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	n = pe_wide_view();
	s = sweep("pe with a narrowing view", pe_img, n, 1500, verbose);
	printf("  pe with a narrowing view: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	n = pe_stager();
	s = sweep("pe stager", pe_img, n, 1500, verbose);
	printf("  pe stager: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	n = zip_of(24);
	s = sweep("zip", zip_img, n, 1500, verbose);
	printf("  zip of 24 members: %ld allocations, %ld refused, %ld changed the answer, %ld silently (+%ld with no object at all)\n",
	       s.allocs, s.refused, s.lossy, s.silent, s.empty);
	CK(s.silent == 0);
	empty += s.empty;

	/* a refused allocation of the walk's root record delivers no object and no error: 0 runs */
	CK(nomem_seen > 0);     /* the refusal is reachable, and says KOF_ERR_NOMEM */
	if (empty)
		printf("  %ld run(s) with no object and no error\n", empty);
	CK(empty == 0);
	keng_close(eng);
	if (fails) {
		printf("silent_oom_sweep: %d check(s) failed\n", fails);
		return 1;
	}
	printf("silent_oom_sweep: done\n");
	return km_failed();
#endif
}
