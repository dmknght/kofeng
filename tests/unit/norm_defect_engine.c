#define _GNU_SOURCE
/*
 * norm_defect_engine - the defects of the normalise audit (2026-10-21, N1-N12) that live in the
 * engine's view stage, each with the input the older tests never gave it.
 *
 *   N3   a PE with more disjoint code extents than the region table held (KOF_SRC_MAX_REGIONS, 16) lost
 *        the later ones from the view: the later code sections were not protected as code and the view's
 *        own region table had no DATA region. A cap must not delete evidence: 15, 16, 17, 20 and 40 code
 *        sections, each with a wide string and a zero run in it, plus a data section with a wide string.
 *        The oracle is the view's bytes (every code section intact, every wide string of a writable section
 *        narrowed) and the region table the scanner holds for the view while its callback runs.
 *   N5   norm_alloc failed and the stage returned with nothing said: a view lost to the allocator.
 *   N6   the remap of the parent's functions into the view could fail (NOMEM, OVER_BUDGET) and the status
 *        was never read: the view carried a function set cut short, and nothing said so.
 *   N7   kof_prod_publish could not allocate the shared record and the views came out with none of the
 *        parent's analysis, silently.
 *   N8   the escape pass zeroed the whole run when the decode of the run answered "nothing", and said
 *        nothing changed: evidence deleted. (kof_exe_decode_run is wrapped at link time to answer 0 for
 *        one call; the same line exists for the hex and percent passes, which no input can reach.)
 *
 * N5-N7 inject the failure at the allocation that matters (malloc of a size the code asks for, or the
 * next calloc) and ask one thing: a failure that was hit must be REPORTED - the object broken = LIMIT, or
 * kof_stats.limit_hits - never silent. Under a sanitizer, which owns malloc, they are skipped.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "normalizer_ref.h"
#include "../../libkofeng/scanners/scan_int.h"
#include "../../libkofeng/scanners/objprod.h"
#include "../../libkofeng/scanners/objsrc.h"
#include <genotype/image/funcs.h>

#ifndef __SANITIZE_ADDRESS__
#define CAN_FAIL 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#undef CAN_FAIL
#endif
#endif

/* ---- the failing allocator ------------------------------------------------------------------- */

#ifdef CAN_FAIL
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);

static int fail_on;
static size_t fail_size[2];
static unsigned fail_nth, fail_seen, fail_hit;
static int fail_calloc_next;

void *malloc(size_t n)
{
	if (fail_on && (n == fail_size[0] || n == fail_size[1]) && ++fail_seen == fail_nth) {
		fail_hit++;
		return NULL;
	}
	return __libc_malloc(n);
}

void *calloc(size_t n, size_t m)
{
	if (fail_calloc_next) {
		fail_calloc_next = 0;
		fail_hit++;
		return NULL;
	}
	return __libc_calloc(n, m);
}

static void arm(size_t a, size_t b, unsigned nth)
{
	fail_size[0] = a;
	fail_size[1] = b;
	fail_nth = nth;
	fail_seen = 0;
	fail_hit = 0;
	fail_on = 1;
}

static void disarm(void)
{
	fail_on = 0;
}
#endif

/* the collector's own copies are not the engine's allocations and are never refused */
#ifdef CAN_FAIL
#define RAW_MALLOC __libc_malloc
#else
#define RAW_MALLOC malloc
#endif

/* ---- a collector that keeps the bytes and the region table of every object -------------------- */

#define MAXO  6u
#define MAXR  160u

struct vobj {
	char     name[96];
	uint32_t kind, broken;
	uint8_t *bytes;
	uint64_t len;
	uint32_t n_rgn;
	struct kof_src_region rgn[MAXR];
};

struct vres {
	unsigned n;
	struct vobj o[MAXO];
};

static int vcollect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res,
		    void *user)
{
	struct vres *r = user;
	struct vobj *o;
	const struct kof_scanner *sc = (const struct kof_scanner *)e2e_sc;
	uint32_t i;

	if (r->n >= MAXO)
		return 0;
	o = &r->o[r->n++];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name ? name : "");
	o->kind = res->entry_kind;
	o->broken = res->broken;
	if (len && len < (8u << 20)) {
		o->bytes = RAW_MALLOC((size_t)len);
		if (o->bytes) {
			memcpy(o->bytes, bytes, (size_t)len);
			o->len = len;
		}
	}
	for (i = 0; i < sc->cur.n_rgn && i < MAXR; i++)
		o->rgn[i] = sc->cur.rgn[i];
	o->n_rgn = sc->cur.n_rgn < MAXR ? sc->cur.n_rgn : MAXR;
	return 0;
}

static void vfree(struct vres *r)
{
	unsigned i;

	for (i = 0; i < r->n; i++)
		free(r->o[i].bytes);
	r->n = 0;
}

static unsigned vscan(const uint8_t *b, uint64_t n, struct vres *r)
{
	struct kof_scan_option opt;

	memset(r, 0, sizeof *r);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	notes_clear();
	(void)kscan_bytes(e2e_sc, b, n, "ndef", &opt, vcollect, r);
	return r->n;
}

static const struct vobj *view_of(const struct vres *r)
{
	unsigned i;

	for (i = 0; i < r->n; i++)
		if (r->o[i].kind == KOF_ENT_NORMALIZED)
			return &r->o[i];
	return NULL;
}

static unsigned count_of(const uint8_t *hay, uint64_t n, const uint8_t *pat, size_t m)
{
	unsigned k = 0;
	uint64_t i;

	if (!hay || m == 0 || n < m)
		return 0;
	for (i = 0; i + m <= n; i++)
		if (hay[i] == pat[0] && !memcmp(hay + i, pat, m))
			k++;
	return k;
}

#include "norm_pe_fx.h"

static void n3_regions(void)
{
	static uint8_t pe[PE_MAX];
	static const unsigned counts[] = { 15, 16, 17, 20, 40 };
	uint8_t pat[SEC_LEN];
	unsigned c, v;

	sec_body(pat);
	for (v = 0; v < 2u; v++) {
		for (c = 0; c < sizeof counts / sizeof counts[0]; c++) {
			const unsigned n = counts[c];
			const uint32_t chars = v ? 0xe0000020u : 0x60000020u;     /* writable code, or not */
			uint32_t len = build_pe(pe, n, chars);
			struct vres r;
			const struct vobj *w;
			unsigned code_rgn = 0, data_rgn = 0, i;
			uint8_t ascii[16];
			int ok;

			memcpy(ascii, WIDE_TXT, 16);
			ok = vscan(pe, len, &r) >= 2u && (w = view_of(&r)) != NULL;
			CK(ok);
			if (!ok) {
				vfree(&r);
				continue;
			}
			if (!v) {
				/* read-only code is kept verbatim: all N sections intact, zero runs and all */
				unsigned intact = count_of(w->bytes, w->len, pat, sizeof pat);

				printf("  %2u read-only code sections: %u intact in the view\n", n, intact);
				CK(intact == n);
			} else {
				/* writable code is the shape of a packed image: every wide string is narrowed */
				unsigned narrow = count_of(w->bytes, w->len, ascii, 16);
				uint8_t wide[32];
				unsigned j;

				for (j = 0; j < 16u; j++) {
					wide[2u * j] = ascii[j];
					wide[2u * j + 1u] = 0;
				}
				printf("  %2u writable code sections: %u narrowed, %u still wide\n", n, narrow,
				       count_of(w->bytes, w->len, wide, sizeof wide));
				CK(narrow == n);
				CK(count_of(w->bytes, w->len, wide, sizeof wide) == 0u);
			}
			/* the region table the view carries: every code extent and the data section */
			for (i = 0; i < w->n_rgn; i++) {
				code_rgn += w->rgn[i].mask == (uint32_t)KGENOME_SCAN_PE_CODE;
				data_rgn += w->rgn[i].mask == (uint32_t)KGENOME_SCAN_PE_DATA;
			}
			printf("      view region table: %u regions, %u CODE, %u DATA\n", w->n_rgn, code_rgn, data_rgn);
			CK(code_rgn == n);
			CK(data_rgn >= 1u);
			vfree(&r);
		}
	}
}

/* ---- N5 -------------------------------------------------------------------------------------- */

static void n5_alloc_refusal(void)
{
#ifdef CAN_FAIL
	static uint8_t pe[PE_MAX];
	uint32_t len = build_pe(pe, 3, 0xe0000020u);
	size_t sizes[3] = { len, ((size_t)len + 7u) / 8u, 0 };
	unsigned s, k, reached = 0;
	struct vres r;

	CK(vscan(pe, len, &r) >= 2u && view_of(&r) && r.o[0].broken == 0);     /* the control: a view, nothing broken */
	vfree(&r);
	for (s = 0; s < 2u; s++) {
		for (k = 1; k <= 4u; k++) {
			unsigned i, has_view;
			uint32_t worst = 0;

			arm(sizes[s], sizes[2], k);
			(void)vscan(pe, len, &r);
			disarm();
			if (!fail_hit) {
				vfree(&r);
				continue;
			}
			has_view = view_of(&r) != NULL;
			for (i = 0; i < r.n; i++)
				if (r.o[i].broken > worst)
					worst = r.o[i].broken;
			if (!has_view) {
				reached++;
				printf("  malloc(%zu) #%u refused: no view, worst broken = %u\n", sizes[s], k, worst);
				CK(worst == KOF_BROKEN_LIMIT);              /* a view lost to the allocator is said */
			}
			vfree(&r);
		}
	}
	CK(reached >= 1u);                                          /* the refusal path was reached */
#else
	printf("  (a sanitizer owns malloc: N5 is skipped)\n");
#endif
}

/* ---- N6 -------------------------------------------------------------------------------------- */

static void n6_remap_status(void)
{
#ifdef CAN_FAIL
	static uint8_t buf[1u << 20];
	FILE *f = fopen("build/test/fixtures/plain-elf64", "rb");
	size_t n;
	struct kgenome_elf_info info;
	struct kgenome_obj g;
	struct kgenome_func_set fs;
	struct vres r;
	unsigned reached = 0, k;

	if (!f) {
		printf("  N6: no plain-elf64 fixture\n");
		CK(0);
		return;
	}
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);
	memset(&info, 0, sizeof info);
	memset(&g, 0, sizeof g);
	CK(kgenome_elf_image_parse(kof_buf_make(buf, n), &info, &g));
	g.file_header = &info;
	kgenome_funcs_build(KGENOME_FMT_ELF, buf, n, &info, &fs);
	printf("  parent functions: %u\n", fs.n);
	CK(fs.n >= 2u);
	CK(vscan(buf, n, &r) >= 2u && view_of(&r) != NULL);                /* the control: the view is made */
	{
		unsigned i;

		for (i = 0; i < r.n; i++)
			CK(r.o[i].broken == 0);
	}
	vfree(&r);
	for (k = 1; k <= 3u; k++) {
		unsigned i;
		uint32_t worst = 0;

		arm((size_t)fs.n * sizeof(struct kgenome_func), 0, k);
		(void)vscan(buf, n, &r);
		disarm();
		if (!fail_hit) {
			vfree(&r);
			continue;
		}
		reached++;
		for (i = 0; i < r.n; i++)
			if (r.o[i].broken > worst)
				worst = r.o[i].broken;
		printf("  malloc(%zu) #%u refused: %u object(s), worst broken = %u\n",
		       (size_t)fs.n * sizeof(struct kgenome_func), k, r.n, worst);
		CK(worst == KOF_BROKEN_LIMIT);                      /* a function set cut short is said */
		vfree(&r);
	}
	CK(reached >= 1u);
	kgenome_funcs_free(&fs);
#else
	printf("  (a sanitizer owns malloc: N6 is skipped)\n");
#endif
}

/* ---- N7 -------------------------------------------------------------------------------------- */

static struct kof_objsrc *view_child(void)
{
	struct kof_objsrc *k = kof_src_heap(calloc(1, 32), 32);
	uint8_t info[16] = { 1, 2, 3, 4 };
	struct kof_src_desc d;

	kof_src_declare_kind(k, KOF_ENT_NORMALIZED);
	memset(&d, 0, sizeof d);
	d.fmt = KOF_FMT_ELF;
	d.info = info;
	d.info_len = sizeof info;
	kof_src_declare_desc(k, &d);
	return k;
}

static void n7_publish_refused(void)
{
#ifdef CAN_FAIL
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_objsrc *list[1], **old_list;
	uint32_t old_n, old_views;
	uint64_t hits0;

	CK(sc != NULL);
	if (!sc)
		return;
	old_list = sc->child.list;
	old_n = sc->child.n;
	old_views = sc->child.n_views;
	list[0] = view_child();
	sc->child.list = list;
	sc->child.n = 1;
	hits0 = sc->st.limit_hits;
	sc->obj.open.cut = 0;
	fail_calloc_next = 1;                       /* the shared record is the first thing publish allocates */
	fail_hit = 0;
	kof_prod_publish(sc);
	fail_calloc_next = 0;
	CK(fail_hit == 1u);                         /* the allocation was reached */
	CK(kof_src_prod_of(list[0]) == NULL);       /* so the view arrives with none of the parent's analysis ... */
	printf("  limit_hits %llu -> %llu, cut %d\n", (unsigned long long)hits0,
	       (unsigned long long)sc->st.limit_hits, sc->obj.open.cut);
	CK(sc->st.limit_hits == hits0 + 1u && sc->obj.open.cut);   /* ... and that is said */
	kof_src_unref(list[0]);
	sc->child.list = old_list;
	sc->child.n = old_n;
	sc->child.n_views = old_views;
	kscan_free(sc);
#else
	printf("  (a sanitizer owns calloc: N7 is skipped)\n");
#endif
}

/* ---- N8 -------------------------------------------------------------------------------------- */

static int decode_fail;

uint64_t __real_kof_exe_decode_run(uint32_t algo, uint32_t flags, uint32_t k32, uint8_t *p, uint64_t n);
uint64_t __wrap_kof_exe_decode_run(uint32_t algo, uint32_t flags, uint32_t k32, uint8_t *p, uint64_t n);

uint64_t __wrap_kof_exe_decode_run(uint32_t algo, uint32_t flags, uint32_t k32, uint8_t *p, uint64_t n)
{
	if (decode_fail)
		return 0;
	return __real_kof_exe_decode_run(algo, flags, k32, p, n);
}

static void n8_decode_nothing(void)
{
	/* eight escapes of one separator: a run the pass decodes ("ABCDEFGH") */
	const char *text = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48";
	uint8_t a[64], b[64];
	size_t n = strlen(text);
	int changed;

	memset(a, 'q', sizeof a);
	memcpy(a + 8, text, n);
	memcpy(b, a, sizeof b);
	decode_fail = 0;
	changed = kof_exe_unesc(a, sizeof a);
	CK(changed == 1);                                   /* the control: decoded in place */
	CK(!memcmp(a + 8, "ABCDEFGH", 8));
	/* the decode of the run answers nothing: the run is left exactly as written */
	memcpy(a, b, sizeof a);
	decode_fail = 1;
	changed = kof_exe_unesc(a, sizeof a);
	decode_fail = 0;
	CK(changed == 0);
	printf("  decode answered nothing: run %s\n", memcmp(a, b, sizeof a) ? "ALTERED" : "left as it was");
	CK(!memcmp(a, b, sizeof a));
}

int main(void)
{
	if (!e2e_open(NULL)) {
		printf("norm_defect_engine: cannot open the test database\n");
		return 2;
	}
	printf("N3 regions of a PE with many code extents\n");
	n3_regions();
	printf("N5 norm_alloc refused\n");
	n5_alloc_refusal();
	printf("N6 funcs_remap status\n");
	n6_remap_status();
	printf("N7 kof_prod_publish refused\n");
	n7_publish_refused();
	printf("N8 decode of a run answers nothing\n");
	n8_decode_nothing();
	if (fails) {
		printf("norm_defect_engine: %d check(s) failed\n", fails);
		return 1;
	}
	printf("norm_defect_engine: ok\n");
	return 0;
}
