#define _GNU_SOURCE
/*
 * engine_defect2 - round-2 defects of the engine's child declarations (E2-E11 of the second audit).
 *
 *   E2   kof_src_declare_syms / _funcs / _fixed / _desc could not allocate their copy and returned
 *        with nothing said: the view arrived without the parent's symbols, functions, fixed units or
 *        image description, and the object was reported complete (the class of N5-N7). The failure is
 *        injected at the one allocation of the exact size the code asks for, through oc_kid_push
 *        with the product pending, and the child must say so.
 *
 *   E3   the import declaration a module makes while it builds a PE child (oc_import, oc_import_at,
 *        oc_import_bytes, oc_image, oc_section, objctx_child_image.c), which no test ran. A module is
 *        written here (a real unpacker's calls through the module ABI, driven by the walk) and the
 *        child it produces is read back with the library's own import reader:
 *          - the declared imports are what the child holds, thunks included (control);
 *          - a hostile iat_rva (2^64 - 1, 2^63, 4 GiB, a value whose low 32 bits are a valid slot,
 *            a slot that straddles or lies past the end of the image, a slot on the table itself)
 *            is refused where it is declared or where the table is placed, never stored and written
 *            as FirstThunk, and the rest of the child is byte for byte the child without imports;
 *          - the 1025th import and a name that cannot fit the pool are refused and said;
 *          - an allocation refused inside oc_import is said, and the next call neither crashes on a
 *            half-made table nor leaks the half that was made;
 *          - a table that grows after its place was reserved is not written, and that is said.
 *
 *   E6   the sections a module declares for the child it builds (oc_section, oc_image, oc_layout_of_produced,
 *        the header written at the close). Documented as "ordered and disjoint" and enforced only when a
 *        declaration REPLACES one: a descending or overlapping append was accepted, the span of the image
 *        was taken from the LAST section declared and not the largest end, a rva + size that wraps 2^64 was
 *        stored, and the header writer was given sec[0].rva as the room it may zero in the child's buffer.
 *        A section table recovered from the decoded payload (UPX, kunp_rcstruct_layout_of_image) is the
 *        payload's own claim: one whose first section starts at 0x30000000 made the engine zero 768 MB
 *        of a 12 KB buffer when the child closed. The case runs in a forked child, so a crash is a result.
 *
 *   E11  what a module says the child IS (kunp_rcstruct_as): an ELF header written from the declaration
 *        (class, machine, entry, one PT_LOAD over the image), and a PE whose width and base are the
 *        module's and not the parent's - a 64-bit payload under a 32-bit container, and the reverse, with
 *        the import table's thunks as wide as the child's own width. Read back by the library's parsers.
 *   E10  an allocation sweep of the whole module path: the scan of a parent whose module builds a PE child with
 *        imports is run once to count its allocations and then once for each, that allocation refused. A
 *        refusal is survived to the same answer (the same objects, the same bytes) or it is SAID (an
 *        object broken, a limit counted, an error returned); a different answer with every signal at zero
 *        is a silent loss, and each is a failure. The sweep that silent_oom_sweep runs over the
 *        fixtures of the detectors, here over the producer's calls (section, image, import, import_at,
 *        close, the child's declarations).
 *
 * Failure injection needs the test to own malloc; under a sanitizer, which owns it, those cases are
 * skipped and the rest runs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/scanners/scan_int.h"
#include "../../libkofeng/scanners/objctx_int.h"
#include "../../libkofeng/scanners/objsrc.h"
#include <genotype/image/pe_image.h>
#include <genotype/image/pe_rebuild.h>
#include <genotype/image/funcs.h>
#include "../lib/genome/image_kit.h"

static int fails;

#define CK(cond) do { if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

#ifndef __SANITIZE_ADDRESS__
#define CAN_FAIL 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#undef CAN_FAIL
#endif
#endif

/* ---- the failing allocator ---------------------------------------------------------------- */

#ifdef CAN_FAIL
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void  __libc_free(void *);

enum { KM = 1, KC = 2, KR = 4 };

static struct {
	int on;
	unsigned kinds;
	size_t size;            /* the exact size the request must have (n * m for calloc) */
	int any;                /* every allocation counts, whatever its size (the sweep) */
	unsigned nth, seen, hit;
} inj;

/* live allocations of the two sizes oc_import makes: a leak is one still here after the scanner is freed */
#define TRACK_N 16
static struct { void *p; size_t n; } live[TRACK_N];
static size_t track_a, track_b;

static void track_add(void *p, size_t n)
{
	unsigned i;

	if (!p || !track_a || (n != track_a && n != track_b))
		return;
	for (i = 0; i < TRACK_N; i++)
		if (!live[i].p) {
			live[i].p = p;
			live[i].n = n;
			return;
		}
}

static void track_del(void *p)
{
	unsigned i;

	if (!p || !track_a)
		return;
	for (i = 0; i < TRACK_N; i++)
		if (live[i].p == p)
			live[i].p = NULL;
}

static unsigned track_live(void)
{
	unsigned i, n = 0;

	for (i = 0; i < TRACK_N; i++)
		n += live[i].p != NULL;
	return n;
}

static int refuse(unsigned kind, size_t n)
{
	if (inj.on && (inj.kinds & kind) && (inj.any || n == inj.size) && ++inj.seen == inj.nth) {
		inj.hit++;
		return 1;
	}
	return 0;
}

void *malloc(size_t n)
{
	void *p;

	if (refuse(KM, n))
		return NULL;
	p = __libc_malloc(n);
	track_add(p, n);
	return p;
}

void *calloc(size_t n, size_t m)
{
	void *p;

	if (refuse(KC, n * m))
		return NULL;
	p = __libc_calloc(n, m);
	track_add(p, n * m);
	return p;
}

void *realloc(void *q, size_t n)
{
	void *p;

	if (refuse(KR, n))
		return NULL;
	track_del(q);
	p = __libc_realloc(q, n);
	track_add(p, n);
	return p;
}

void free(void *p)
{
	track_del(p);
	__libc_free(p);
}

static void arm(unsigned kinds, size_t size, unsigned nth)
{
	inj.any = 0;
	inj.kinds = kinds;
	inj.size = size;
	inj.nth = nth;
	inj.seen = 0;
	inj.hit = 0;
	inj.on = 1;
}

static void disarm(void)
{
	inj.on = 0;
}

/* count (nth 0 never matches) or refuse the nth allocation of ANY size, of any kind */
static void arm_any(unsigned nth)
{
	inj.any = 1;
	inj.kinds = KM | KC | KR;
	inj.size = 0;
	inj.nth = nth ? nth : ~0u;
	inj.seen = 0;
	inj.hit = 0;
	inj.on = 1;
}
#define RAW_MALLOC __libc_malloc
#else
#define RAW_MALLOC malloc
#endif

/* ---- E2 ----------------------------------------------------------------------------------- */

static struct kof_scanner *push_scanner(void)
{
	struct kof_engine *eng = calloc(1, sizeof *eng);
	struct kof_scanner *sc = eng ? kof_scan_new(eng) : NULL;

	if (!sc)
		return NULL;
	sc->ledger.kids_left = 8;
	sc->ledger.resident_max = (uint64_t)1 << 30;
	sc->ledger.obj_cap = (uint64_t)1 << 30;
	sc->ledger.budget = (uint64_t)1 << 30;
	return sc;
}

/* what the scanner says about an object it could not finish: the cut report or the broken reason */
static int said(const struct kof_scanner *sc, uint64_t hits0)
{
	return sc->st.limit_hits > hits0 || sc->obj.open.cut || sc->obj.open.broken;
}

static void e2_declare_refused(void)
{
#ifdef CAN_FAIL
	enum { SYMS, FUNCS, FIXED, DESC, N_KINDS };
	static const char *what[N_KINDS] = { "syms", "funcs", "fixed", "desc" };
	int k, control;

	for (control = 1; control >= 0; control--) {
		for (k = 0; k < N_KINDS; k++) {
			struct kof_scanner *sc = push_scanner();
			struct kof_objsrc *kid;
			struct kgenome_func f[3];
			struct kof_range r[5];
			uint8_t syms[77], info[91];
			size_t want;
			uint64_t hits0;
			int product;

			CK(sc != NULL);
			if (!sc)
				return;
			memset(syms, 7, sizeof syms);
			memset(info, 9, sizeof info);
			memset(f, 0, sizeof f);
			memset(r, 0, sizeof r);
			f[0].len = 16; f[1].off = 64; f[1].len = 16; f[2].off = 128; f[2].len = 16;
			r[0].len = 4; r[1].off = 8; r[1].len = 4; r[2].off = 16; r[2].len = 4;
			r[3].off = 24; r[3].len = 4; r[4].off = 32; r[4].len = 4;
			kid = kof_src_heap(__libc_calloc(1, 32), 32);
			CK(kid != NULL);
			switch (k) {
			case SYMS:
				sc->pend.syms = RAW_MALLOC(sizeof syms);
				memcpy(sc->pend.syms, syms, sizeof syms);
				sc->pend.syms_cap = sizeof syms;
				sc->pend.n_syms = sizeof syms;
				want = sizeof syms;
				break;
			case FUNCS:
				sc->pend.funcs.v = RAW_MALLOC(sizeof f);
				memcpy(sc->pend.funcs.v, f, sizeof f);
				sc->pend.funcs.n = 3;
				want = 3u * sizeof(struct kgenome_func);
				break;
			case FIXED:
				sc->pend.fixed = RAW_MALLOC(sizeof r);
				memcpy(sc->pend.fixed, r, sizeof r);
				sc->pend.fixed_cap = 5;
				sc->pend.n_fixed = 5;
				want = 5u * sizeof(struct kof_range);
				break;
			default:
				memset(&sc->pend.desc, 0, sizeof sc->pend.desc);
				sc->pend.desc.fmt = KOF_FMT_ELF;
				sc->pend.desc_buf = RAW_MALLOC(sizeof info);
				memcpy(sc->pend.desc_buf, info, sizeof info);
				sc->pend.desc.info = sc->pend.desc_buf;
				sc->pend.desc.info_len = sizeof info;
				sc->pend.desc_cap = sizeof info;
				sc->pend.desc_set = 1;
				want = sizeof info;
				break;
			}
			hits0 = sc->st.limit_hits;
			if (!control)
				arm(KM, want, 1);
			(void)oc_kid_push(sc, NULL, kid);
			disarm();
			CK(sc->child.n == 1u);
			if (sc->child.n != 1u) {
				kof_scan_free(sc);
				continue;
			}
			switch (k) {
			case SYMS:  { uint32_t n = 0; product = kof_src_syms_of(sc->child.list[0], &n) != NULL; break; }
			case FUNCS: { uint32_t n = 0; product = kof_src_funcs_of(sc->child.list[0], &n) != NULL; break; }
			case FIXED: { uint32_t n = 0; product = kof_src_fixed_of(sc->child.list[0], &n) != NULL; break; }
			default:    product = kof_src_desc_of(sc->child.list[0]) != NULL; break;
			}
			if (control) {
				CK(product);                     /* the control: the declaration is kept */
				CK(!said(sc, hits0));            /* and nothing is reported */
			} else {
				CK(inj.hit == 1u);               /* the allocation was reached */
				CK(!product);                    /* so the child carries none ... */
				printf("  %-5s refused: child carries it %d, said %d\n", what[k], product,
				       said(sc, hits0));
				CK(said(sc, hits0));             /* ... and that is reported, never silent */
			}
			kof_scan_free(sc);
		}
	}
#else
	printf("  (a sanitizer owns malloc: E2 is skipped)\n");
#endif
}

/* ---- E3: the module, the parent and the readback ------------------------------------------- */

#define PE_FILE_N 0x800u
#define TEXT_RVA  0x1000u
#define IMP_RVA   0x2000u
#define IMG_END   0x3000u

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* The parent: a valid PE the engine parses and hands to the module as its template. */
static void write_parent(const char *path, int plus)
{
	uint8_t img[PE_FILE_N];
	const uint32_t opt = 0x98u, optsz = plus ? 240u : 224u, sec = opt + optsz;
	FILE *f;

	memset(img, 0, sizeof img);
	img[0] = 'M'; img[1] = 'Z';
	w32(img + 0x3c, 0x80);
	memcpy(img + 0x80, "PE\0\0", 4);
	w16(img + 0x84, plus ? 0x8664u : 0x14cu);
	w16(img + 0x86, 1);
	w16(img + 0x94, (uint16_t)optsz);
	w16(img + 0x96, 0x0102u);
	w16(img + opt, plus ? 0x20bu : 0x10bu);
	w32(img + opt + 16, TEXT_RVA);
	w32(img + opt + 20, TEXT_RVA);
	if (plus) {
		w32(img + opt + 24, 0x400000u);
	} else {
		w32(img + opt + 28, 0x400000u);
	}
	w32(img + opt + 32, 0x1000);
	w32(img + opt + 36, 0x200);
	w32(img + opt + 56, 0x2000);
	w32(img + opt + 60, 0x400);
	w16(img + opt + 68, 3);
	w32(img + opt + (plus ? 108u : 92u), 16);
	memcpy(img + sec, ".text", 5);
	w32(img + sec + 8, 0x200);
	w32(img + sec + 12, TEXT_RVA);
	w32(img + sec + 16, 0x200);
	w32(img + sec + 20, 0x400);
	w32(img + sec + 36, 0x60000020u);
	memset(img + 0x400, 0x90, 0x200);
	f = fopen(path, "wb");
	if (f) {
		fwrite(img, 1, sizeof img, f);
		fclose(f);
	}
}

/* what the module does, and what it was told */
static void (*steps)(const struct kof_obj_ctx *);
static unsigned runs;
static int rv[64];                      /* answers of the calls the case wants to look at */
static unsigned nrv;

static void note_rv(int v)
{
	if (nrv < sizeof rv / sizeof rv[0])
		rv[nrv++] = v;
}

static void mod_run(const struct kof_obj_ctx *ctx)
{
	if (runs++ == 0 && steps)
		steps(ctx);
}

#define MAXO 4u

struct got {
	unsigned n;
	struct {
		char name[96];
		uint32_t kind, broken;
		uint8_t *bytes;
		uint64_t len;
		unsigned n_region;
		struct { uint32_t mask; uint64_t off, len; } rgn[KOF_MAX_REGIONS];
	} o[MAXO];
};

static int collect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct got *g = user;
	unsigned i;

	if (g->n >= MAXO)
		return 0;
	i = g->n++;
	snprintf(g->o[i].name, sizeof g->o[i].name, "%s", name ? name : "");
	g->o[i].kind = res->entry_kind;
	g->o[i].broken = res->broken;
	g->o[i].bytes = NULL;
	g->o[i].len = 0;
	g->o[i].n_region = res->n_region < KOF_MAX_REGIONS ? res->n_region : KOF_MAX_REGIONS;
	{
		unsigned r;

		for (r = 0; r < g->o[i].n_region; r++) {
			g->o[i].rgn[r].mask = res->region[r].mask;
			g->o[i].rgn[r].off = res->region[r].off;
			g->o[i].rgn[r].len = res->region[r].len;
		}
	}
	if (len && len < (8u << 20)) {
		g->o[i].bytes = RAW_MALLOC((size_t)len);
		if (g->o[i].bytes) {
			memcpy(g->o[i].bytes, bytes, (size_t)len);
			g->o[i].len = len;
		}
	}
	return 0;
}

static void got_free(struct got *g)
{
	unsigned i;

	for (i = 0; i < g->n; i++)
#ifdef CAN_FAIL
		__libc_free(g->o[i].bytes);
#else
		free(g->o[i].bytes);
#endif
	memset(g, 0, sizeof *g);
}

struct run_out {
	struct got g;
	uint64_t limit_hits;
	unsigned live_after;
	int rc;                 /* what the walk answered */
	unsigned seen;          /* allocations the walk made (sweep) */
	unsigned hit;           /* the refused one was reached (sweep) */
};

static int sweep_on;            /* run_case arms the any-allocation sweep around the walk */
static unsigned sweep_nth;      /* 0: count only */

static char root[256], parent_path[2][300];

static void run_case(void (*s)(const struct kof_obj_ctx *), int plus, struct run_out *out)
{
	struct kof_scan_option opt;
	struct kof_engine eng;
	struct kof_module m;
	struct kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	memset(&eng, 0, sizeof eng);
	memset(&m, 0, sizeof m);
	memset(out, 0, sizeof *out);
	m.fn = mod_run;
	m.n_target = 0;
	eng.unp = &m;
	eng.n_unp = 1;
	steps = s;
	runs = 0;
	nrv = 0;
	sc = kof_scan_new(&eng);
	CK(sc != NULL);
	if (!sc)
		return;
#ifdef CAN_FAIL
	if (sweep_on)
		arm_any(sweep_nth);
#endif
	out->rc = kof_scan_walk(sc, parent_path[plus], &opt, collect, &out->g);
#ifdef CAN_FAIL
	if (sweep_on) {
		out->seen = inj.seen;
		out->hit = inj.hit;
		disarm();
	}
#endif
	out->limit_hits = sc->st.limit_hits;
	kof_scan_free(sc);
#ifdef CAN_FAIL
	out->live_after = track_live();
#endif
}

/* ---- the child's imports, read back --------------------------------------------------------- */

#define MAXI 64u
struct imp_rec {
	uint64_t slot;
	uint32_t ordinal;
	char name[40];
	char dll[40];
};
struct imps {
	unsigned n;
	struct imp_rec v[MAXI];
	const uint8_t *file;
	uint64_t len;
};

static void imp_cb(void *user, uint64_t slot, const char *dll, const char *name, uint32_t ordinal, uint64_t nameoff)
{
	struct imps *r = user;

	(void)nameoff;
	if (r->n >= MAXI)
		return;
	r->v[r->n].slot = slot;
	r->v[r->n].ordinal = ordinal;
	snprintf(r->v[r->n].name, sizeof r->v[r->n].name, "%s", name ? name : "");
	snprintf(r->v[r->n].dll, sizeof r->v[r->n].dll, "%s", dll ? dll : "");
	r->n++;
}

/* Parse the child as a PE and list its imports; returns 0 when it is not a PE at all. */
static int read_imports(const uint8_t *b, uint64_t n, struct imps *r, struct kgenome_pe_info *info)
{
	struct kgenome_obj obj;
	enum kgenome_status st;

	memset(r, 0, sizeof *r);
	memset(info, 0, sizeof *info);
	memset(&obj, 0, sizeof obj);
	if (!b || !kgenome_pe_image_parse(kof_buf_make(b, n), info, &obj) || !info->valid)
		return 0;
	obj.file_header = info;
	r->file = b;
	r->len = n;
	(void)kgenome_pe_imports(kof_buf_make(b, n), info, imp_cb, r, &st);
	return 1;
}

static const struct imp_rec *find_imp(const struct imps *r, const char *dll, const char *name, uint32_t ord)
{
	unsigned i;

	for (i = 0; i < r->n; i++)
		if (!strcmp(r->v[i].dll, dll) && r->v[i].ordinal == ord && !strcmp(r->v[i].name, name))
			return &r->v[i];
	return NULL;
}

static unsigned rd_thunk(const uint8_t *b, uint64_t n, uint64_t slot, int plus, uint64_t *v)
{
	const uint32_t step = plus ? 8u : 4u;

	if (slot > n || n - slot < step)
		return 0;
	*v = 0;
	memcpy(v, b + slot, step);
	return 1;
}

/* the object the module produced: the one reached through the parent (a name with "//") */
static int child_of(const struct got *g)
{
	unsigned i;

	for (i = 0; i < g->n; i++)
		if (strstr(g->o[i].name, "//"))
			return (int)i;
	return -1;
}

/* the common prologue of a producer: sections, then the image */
static void declare_image(const struct kof_obj_ctx *ctx)
{
	note_rv(kunp_rcstruct_section(".text", TEXT_RVA, 0x1000, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE));
	note_rv(kunp_rcstruct_section(".kofimp", IMP_RVA, 0x1000, KUNP_PERM_R, KOF_SECF_DATA | KOF_SECF_SYNTHETIC));
	note_rv(kunp_rcstruct_image());
}

/* ---- the producers, one per case ------------------------------------------------------------- */

static int g_plus;                      /* the width of the slots the case declares */
static uint64_t g_hostile;              /* the slot the hostile case declares */

static void step_none(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_done());
}

static void step_good(const struct kof_obj_ctx *ctx)
{
	const uint64_t st = g_plus ? 8u : 4u, s0 = 0x1100u;

	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, s0));
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "Sleep", 0, s0 + st));
	note_rv(kunp_rcstruct_import("KERNEL32.dll", NULL, 5, s0 + 2u * st));
	note_rv(kunp_rcstruct_import("USER32.dll", "MessageBoxA", 0, s0 + 4u * st));
	note_rv(kunp_rcstruct_import("USER32.dll", "NoSlot", 0, 0));            /* a declared import with no slot */
	note_rv((int)(kunp_rcstruct_import_bytes() != 0));
	note_rv(kunp_rcstruct_import_at(IMP_RVA));
	note_rv(kunp_rcstruct_done());
}

/* the image is declared first, then a hostile slot, then the good imports */
static void step_hostile_after_image(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "Hostile", 0, g_hostile));  /* rv[3] */
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, 0x1100u));
	note_rv((int)(kunp_rcstruct_import_bytes() != 0));
	note_rv(kunp_rcstruct_import_at(IMP_RVA));
	note_rv(kunp_rcstruct_done());
}

/* the hostile slot is declared BEFORE the image exists: it can only be refused where the table is placed */
static void step_hostile_before_image(const struct kof_obj_ctx *ctx)
{
	note_rv(kunp_rcstruct_section(".text", TEXT_RVA, 0x1000, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE));
	note_rv(kunp_rcstruct_section(".kofimp", IMP_RVA, 0x1000, KUNP_PERM_R, KOF_SECF_DATA | KOF_SECF_SYNTHETIC));
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "Hostile", 0, g_hostile));   /* rv[2] */
	note_rv(kunp_rcstruct_image());
	note_rv((int)(kunp_rcstruct_import_bytes() != 0));
	note_rv(kunp_rcstruct_import_at(IMP_RVA));                                /* rv[5] */
	note_rv(kunp_rcstruct_done());
}

/* a slot that lies on the table the declaration reserves */
static void step_slot_on_table(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, IMP_RVA + 4u));   /* rv[3] */
	note_rv(kunp_rcstruct_import_at(IMP_RVA));                                       /* rv[4] */
	note_rv(kunp_rcstruct_done());
}

/* the table grows after its place was reserved: it no longer fits where it was put */
static void step_grown_after_at(const struct kof_obj_ctx *ctx)
{
	unsigned i;
	char fn[32];

	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, 0x1100u));
	note_rv(kunp_rcstruct_import_at(IMG_END - 0x30u));          /* room for the small table only */
	for (i = 0; i < 40; i++) {
		snprintf(fn, sizeof fn, "Api%u_with_a_long_name", i);
		(void)kunp_rcstruct_import("KERNEL32.dll", fn, 0, 0);
	}
	note_rv(kunp_rcstruct_done());
}

/* the table is placed past the image: the sink grows to hold it (control) */
static void step_at_past_end(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, 0x1100u));
	note_rv(kunp_rcstruct_import_at(IMG_END + 0x100u));
	note_rv(kunp_rcstruct_done());
}

/* the placement wraps: rva + size overflows */
static void step_at_wraps(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, 0x1100u));
	note_rv(kunp_rcstruct_import_at(UINT64_MAX - 8u));
	note_rv(kunp_rcstruct_import_at(UINT64_MAX));
	note_rv(kunp_rcstruct_done());
}

/* argument checks: every one of these is refused and stores nothing */
static void step_args(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_import(NULL, "F", 0, 0x1100u));                 /* rv[3] no dll */
	note_rv(kunp_rcstruct_import("", "F", 0, 0x1100u));                   /* rv[4] empty dll */
	note_rv(kunp_rcstruct_import("K.dll", "F", 3, 0x1100u));              /* rv[5] a name and an ordinal */
	note_rv(kunp_rcstruct_import("K.dll", NULL, 0, 0x1100u));             /* rv[6] neither */
	note_rv(kunp_rcstruct_import("K.dll", "", 0, 0x1100u));               /* rv[7] an empty name, no ordinal */
	note_rv(kunp_rcstruct_import("K.dll", NULL, 0x10000u, 0x1100u));      /* rv[8] ordinal past 16 bits */
	note_rv(kunp_rcstruct_import_at(IMP_RVA));                            /* rv[9] nothing declared */
	note_rv((int)(kunp_rcstruct_import_bytes() != 0));                    /* rv[10] */
	note_rv(kunp_rcstruct_import("K.dll", "Ok", 0, 0x1100u));             /* rv[11] one good entry */
	note_rv(kunp_rcstruct_import_at(IMP_RVA));
	note_rv(kunp_rcstruct_done());
}

/* the 1025th import, and the pool */
static void step_fill(const struct kof_obj_ctx *ctx)
{
	unsigned i;
	char fn[32];
	int last = 1;

	declare_image(ctx);
	for (i = 0; i < 1030 && last; i++) {
		snprintf(fn, sizeof fn, "f%u", i);
		last = kunp_rcstruct_import("K.dll", fn, 0, 0);
		if (!last)
			note_rv((int)i);          /* the index at which it refused */
	}
	note_rv(kunp_rcstruct_done());
}

static char bigname[70000];

static void step_pool(const struct kof_obj_ctx *ctx)
{
	unsigned i;
	char fn[80];
	int last = 1;

	declare_image(ctx);
	/* one name that cannot fit the pool at all */
	memset(bigname, 'N', sizeof bigname - 1u);
	note_rv(kunp_rcstruct_import("K.dll", bigname, 0, 0));                 /* rv[3] */
	/* then names of 63 characters until the pool of 64 KiB is full */
	for (i = 0; i < 1100 && last; i++) {
		memset(fn, 'a', 63);
		snprintf(fn + 56, sizeof fn - 56u, "%07u", i);
		fn[63] = 0;
		last = kunp_rcstruct_import("K.dll", fn, 0, 0);
		if (!last)
			note_rv((int)i);
	}
	note_rv(kunp_rcstruct_done());
}

/* two imports declared with the same slot start (a module that lists one IAT slot twice) */
static void step_dup_slot(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "A", 0, 0x1100u));
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "B", 0, 0x1100u));
	note_rv(kunp_rcstruct_import_at(IMP_RVA));
	note_rv(kunp_rcstruct_done());
}

/* the sections are cleared and declared again; a directory is rebuilt; an entry point set */
static void step_reset(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	note_rv(kunp_rcstruct_reset());
	note_rv(kunp_rcstruct_section(".text", TEXT_RVA, 0x1000, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE));
	note_rv(kunp_rcstruct_section(".text", TEXT_RVA, 0x800, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE)); /* replaced */
	note_rv(kunp_rcstruct_dir(3, 0x1200, 0x40));
	note_rv(kunp_rcstruct_dir(16, 1, 1));                                        /* refused */
	note_rv(kunp_rcstruct_entry(0x1010));
	note_rv(kunp_rcstruct_done());
}

/* ---- E11: kunp_rcstruct_as ------------------------------------------------------------------ */

static int as_fmt, as_arch;
static uint64_t as_base;

static void step_as(const struct kof_obj_ctx *ctx)
{
	note_rv(kunp_rcstruct_section(".text", TEXT_RVA, 0x1000, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE));
	note_rv(kunp_rcstruct_section(".kofimp", IMP_RVA, 0x1000, KUNP_PERM_R, KOF_SECF_DATA | KOF_SECF_SYNTHETIC));
	kunp_rcstruct_as(as_fmt, as_arch, as_base);
	note_rv(kunp_rcstruct_image());
	if (as_fmt == KOF_FMT_PE) {
		const uint64_t st = as_arch == KGENOME_ARCH_X86_64 ? 8u : 4u;

		note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, 0x1100u));
		note_rv(kunp_rcstruct_import("KERNEL32.dll", "Sleep", 0, 0x1100u + st));
		note_rv((int)(kunp_rcstruct_import_bytes() != 0));
		note_rv(kunp_rcstruct_import_at(IMP_RVA));
	}
	kunp_rcstruct_entry(0x1010);
	note_rv(kunp_rcstruct_done());
}

static void e11_as(void)
{
	struct run_out o;
	struct kgenome_pe_info pi;
	struct kgenome_elf_info ei;
	struct kgenome_obj ob;
	struct imps r;
	int ci, parent;

	/* ELF x86-64 */
	as_fmt = KOF_FMT_ELF; as_arch = KGENOME_ARCH_X86_64; as_base = 0x400000;
	g_plus = 0;
	run_case(step_as, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		memset(&ei, 0, sizeof ei);
		memset(&ob, 0, sizeof ob);
		CK(kgenome_elf_image_parse(kof_buf_make(o.g.o[ci].bytes, o.g.o[ci].len), &ei, &ob));
		CK(ei.valid && ei.elf_class == KGENOME_ELFCLASS_64 && ei.e_machine == 62);
		CK(ei.entry_addr == 0x400000u + 0x1010u && ei.load_count == 1u);
		CK(ob.arch == KGENOME_ARCH_X86_64);
	}
	got_free(&o.g);
	/* ELF 32-bit */
	as_arch = KGENOME_ARCH_X86; as_base = 0x08048000u;
	run_case(step_as, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		memset(&ei, 0, sizeof ei);
		memset(&ob, 0, sizeof ob);
		CK(kgenome_elf_image_parse(kof_buf_make(o.g.o[ci].bytes, o.g.o[ci].len), &ei, &ob));
		CK(ei.elf_class == KGENOME_ELFCLASS_32 && ei.e_machine == 3 && ei.entry_addr == 0x08048000u + 0x1010u);
	}
	got_free(&o.g);
	/* PE: 64-bit declared under a 32-bit parent, 32-bit under a 64-bit one; the thunks are the child's width */
	for (parent = 0; parent < 2; parent++) {
		as_fmt = KOF_FMT_PE;
		as_arch = parent ? KGENOME_ARCH_X86 : KGENOME_ARCH_X86_64;
		as_base = parent ? 0x10000000u : 0x140000000ull;
		g_plus = parent;
		run_case(step_as, parent, &o);
		ci = child_of(&o.g);
		CK(ci >= 0);
		if (ci < 0) {
			got_free(&o.g);
			continue;
		}
		CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &pi));
		CK(pi.pe32_plus == (parent ? 0u : 1u));
		CK(pi.machine == (parent ? 0x14cu : 0x8664u));
		CK(pi.image_base == as_base);
		CK(pi.entry_rva == 0x1010u);
		CK(r.n == 2u);
		if (r.n == 2u) {
			const uint64_t st = parent ? 4u : 8u;

			CK(r.v[0].slot == as_base + 0x1100u && r.v[1].slot == as_base + 0x1100u + st);
		}
		got_free(&o.g);
	}
}

/* ---- E13: the region table a declared image gets, exactly --------------------------------------- */

static void step_regions(const struct kof_obj_ctx *ctx)
{
	/* header | CODE CODE (adjacent: one region) | DATA | PAD | gap | DATA | HOLLOW adjacent to it */
	note_rv(kunp_rcstruct_section(".t1", 0x1000, 0x800, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE));
	note_rv(kunp_rcstruct_section(".t2", 0x1800, 0x800, KUNP_PERM_R | KUNP_PERM_X, KOF_SECF_CODE));
	note_rv(kunp_rcstruct_section(".d1", 0x2000, 0x400, KUNP_PERM_R | KUNP_PERM_W, KOF_SECF_DATA));
	note_rv(kunp_rcstruct_section(".pad", 0x2400, 0x100, KUNP_PERM_R, KOF_SECF_PAD));
	note_rv(kunp_rcstruct_section(".d2", 0x3000, 0x100, KUNP_PERM_R | KUNP_PERM_W, KOF_SECF_DATA));
	note_rv(kunp_rcstruct_section(".hol", 0x3100, 0x100, KUNP_PERM_R | KUNP_PERM_W, KOF_SECF_DATA | KOF_SECF_HOLLOW));
	note_rv(kunp_rcstruct_image());
	note_rv(kunp_rcstruct_done());
}

static void step_layout_overlap(const struct kof_obj_ctx *ctx);

static void e13_regions(void)
{
	static const struct { uint32_t mask; uint64_t off, len; } want[] = {
		{ KGENOME_SCAN_PE_HEADERS, 0, 0x1000 },
		{ KGENOME_SCAN_PE_CODE, 0x1000, 0x1000 },
		{ KGENOME_SCAN_PE_DATA, 0x2000, 0x400 },
		{ KGENOME_SCAN_PE_UNCLAIMED, 0x2400, 0x100 },
		{ KGENOME_SCAN_PE_DATA, 0x3000, 0x100 },
		{ KGENOME_SCAN_PE_UNCLAIMED, 0x3100, 0x100 },
	};
	struct run_out o;
	int ci;
	unsigned k;

	g_plus = 0;
	run_case(step_regions, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		CK(o.g.o[ci].n_region == sizeof want / sizeof want[0]);
		for (k = 0; k < sizeof want / sizeof want[0] && k < o.g.o[ci].n_region; k++) {
			if (o.g.o[ci].rgn[k].mask != want[k].mask || o.g.o[ci].rgn[k].off != want[k].off ||
			    o.g.o[ci].rgn[k].len != want[k].len)
				printf("  region %u: mask %#x [%#llx,+%#llx), expected %#x [%#llx,+%#llx)\n", k,
				       (unsigned)o.g.o[ci].rgn[k].mask, (unsigned long long)o.g.o[ci].rgn[k].off,
				       (unsigned long long)o.g.o[ci].rgn[k].len, (unsigned)want[k].mask,
				       (unsigned long long)want[k].off, (unsigned long long)want[k].len);
			CK(o.g.o[ci].rgn[k].mask == want[k].mask && o.g.o[ci].rgn[k].off == want[k].off &&
			   o.g.o[ci].rgn[k].len == want[k].len);
		}
	}
	got_free(&o.g);
	/* the overlapping table of a payload: the earlier section keeps the bytes, exactly */
	run_case(step_layout_overlap, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		CK(o.g.o[ci].n_region >= 3u);
		if (o.g.o[ci].n_region >= 3u) {
			CK(o.g.o[ci].rgn[0].mask == KGENOME_SCAN_PE_HEADERS && o.g.o[ci].rgn[0].len == 0x1000);
			CK(o.g.o[ci].rgn[1].mask == KGENOME_SCAN_PE_CODE && o.g.o[ci].rgn[1].off == 0x1000 && o.g.o[ci].rgn[1].len == 0x800);
			CK(o.g.o[ci].rgn[2].mask == KGENOME_SCAN_PE_DATA && o.g.o[ci].rgn[2].off == 0x1800 && o.g.o[ci].rgn[2].len == 0x400);
		}
	}
	got_free(&o.g);
}

/* the slot against the 32 bits of an RVA, and against the table it may not sit on, at the exact edges */
static void step_slot_edges(const struct kof_obj_ctx *ctx)
{
	static const uint64_t v[] = { 0xfffffffbu, 0xfffffffcu, 0xfffffff7u, 0xfffffff8u, 0xffffffffull, 0x100000000ull };
	unsigned i;

	for (i = 0; i < sizeof v / sizeof v[0]; i++)
		note_rv(kunp_rcstruct_import("K.dll", "F", 0, v[i]));      /* before the image: only the 32 bits are known */
	(void)ctx;
}

static void step_slot_beside(const struct kof_obj_ctx *ctx)
{
	declare_image(ctx);
	/* the table for one import: the slot that ends where it begins and the one that begins where it ends */
	note_rv(kunp_rcstruct_import("KERNEL32.dll", "ExitProcess", 0, IMP_RVA - (g_plus ? 8u : 4u)));
	note_rv(kunp_rcstruct_import_at(IMP_RVA));
	note_rv(kunp_rcstruct_done());
}

static void e13_edges(void)
{
	struct run_out o;
	struct imps r;
	struct kgenome_pe_info info;
	unsigned plus;
	int ci;

	for (plus = 0; plus < 2u; plus++) {
		const uint64_t w = plus ? 8u : 4u, top = 0xffffffffull - w;

		g_plus = (int)plus;
		run_case(step_slot_edges, (int)plus, &o);
		/* declared before the image: <= 0xffffffff - width is a 32-bit RVA the table may still refuse
		 * later, above it is not an RVA at all */
		CK(rv[0] == (0xfffffffbu <= top) && rv[1] == (0xfffffffcu <= top));
		CK(rv[2] == (0xfffffff7u <= top) && rv[3] == (0xfffffff8u <= top));
		CK(rv[4] == 0 && rv[5] == 0);
		got_free(&o.g);
		run_case(step_slot_beside, (int)plus, &o);
		ci = child_of(&o.g);
		CK(ci >= 0 && rv[3] == 1 && rv[4] == 1);
		if (ci >= 0) {
			CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
			CK(r.n == 1u && r.v[0].slot == info.image_base + IMP_RVA - w);
		}
		got_free(&o.g);
	}
}

/* ---- E12: derive ----------------------------------------------------------------------------- */

static void step_derive(const struct kof_obj_ctx *ctx)
{
	static const uint8_t patch[4] = { 0xde, 0xad, 0xbe, 0xef };

	note_rv(kunp_rcstruct_derive());                          /* rv[0] 1: the parent, as the start of the child */
	note_rv(kunp_rcstruct_derive());                          /* rv[1] 0: not onto a sink that is not empty */
	note_rv((int)kunp_rcstruct_poke(0x10, patch, sizeof patch));
	note_rv(kunp_rcstruct_at(UINT64_MAX));                    /* rv[3] 0: past the extent */
	note_rv(kunp_rcstruct_done());
}

static void e12_derive(void)
{
	struct run_out o;
	int ci;
	FILE *f;
	uint8_t par[PE_FILE_N];

	g_plus = 0;
	run_case(step_derive, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0 && rv[0] == 1 && rv[1] == 0 && rv[3] == 0);
	f = fopen(parent_path[0], "rb");
	if (f && ci >= 0 && fread(par, 1, sizeof par, f) == sizeof par) {
		static const uint8_t patch[4] = { 0xde, 0xad, 0xbe, 0xef };

		memcpy(par + 0x10, patch, 4);
		CK(o.g.o[ci].len == PE_FILE_N && !memcmp(o.g.o[ci].bytes, par, PE_FILE_N));
	} else {
		CK(0);
	}
	if (f)
		fclose(f);
	got_free(&o.g);
}

/* ---- E6: sections ---------------------------------------------------------------------------- */

static void step_sec_order(const struct kof_obj_ctx *ctx)
{
	(void)ctx;
	note_rv(kunp_rcstruct_section("A", 0x2000, 0x100, KUNP_PERM_R, KOF_SECF_DATA));            /* rv[0] ok */
	note_rv(kunp_rcstruct_section("B", 0x1000, 0x100, KUNP_PERM_R, KOF_SECF_DATA));            /* rv[1] descending */
	note_rv(kunp_rcstruct_section("C", 0x2080, 0x100, KUNP_PERM_R, KOF_SECF_DATA));            /* rv[2] overlaps A */
	note_rv(kunp_rcstruct_section("W", UINT64_MAX - 0x10u, 0x100, KUNP_PERM_R, KOF_SECF_DATA)); /* rv[3] wraps */
	note_rv(kunp_rcstruct_section("Z", 0x4000, 0, KUNP_PERM_R, KOF_SECF_DATA));                /* rv[4] empty */
	note_rv(kunp_rcstruct_section("D", 0x2100, 0x100, KUNP_PERM_R, KOF_SECF_DATA));            /* rv[5] touches A: ok */
	note_rv(kunp_rcstruct_section("A", 0x2000, 0x200, KUNP_PERM_R, KOF_SECF_DATA));            /* rv[6] grows over D: no */
	note_rv(kunp_rcstruct_section("A", 0x2000, 0x80, KUNP_PERM_R, KOF_SECF_DATA));             /* rv[7] shrinks: ok */
	note_rv(kunp_rcstruct_section("A", 0x2000, UINT64_MAX, KUNP_PERM_R, KOF_SECF_DATA));       /* rv[8] wraps: no */
}

/* the 97th section: the table is full, and that is said */
static void step_sec_full(const struct kof_obj_ctx *ctx)
{
	unsigned i;
	int last = 0;

	(void)ctx;
	for (i = 0; i < 100u; i++) {
		last = kunp_rcstruct_section("s", 0x1000u + 0x100u * i, 0x100, KUNP_PERM_R, KOF_SECF_DATA);
		if (last < 0) {
			note_rv((int)i);          /* the index at which it refused */
			break;
		}
	}
	note_rv(last);
}

/* the largest end, not the last section declared: declared ascending, the first reaches furthest only
 * through the layout of a produced image, so the case is built the way UPX builds it */
static void step_layout_hostile(const struct kof_obj_ctx *ctx)
{
	static uint8_t hdr[0x400];
	struct ik_pe p;

	note_rv(kunp_rcstruct_section("", 0x1000, 0x2000, KUNP_PERM_R, KOF_SECF_DATA | KOF_SECF_REBUILT));
	note_rv(kunp_rcstruct_image());
	note_rv(kunp_rcstruct_at(0));
	/* the decoded payload carries a header of its own: one section, far beyond the payload */
	memset(&p, 0, sizeof p);
	p.entry = 0x30000000u;
	p.size_of_image = 0x30001000u;
	p.size_of_headers = 0x400;
	ik_sec(&p, ".far", 0x1000, 0x30000000u, 0x200, 0x200, IK_TEXT);
	memset(hdr, 0, sizeof hdr);
	(void)ik_pe_write(hdr, &p);
	note_rv((int)kunp_rcstruct_write(hdr, sizeof hdr));
	note_rv((int)(kunp_rcstruct_layout_of_image() != 0));
	note_rv(kunp_rcstruct_done());                                                      /* rv[5]: refused, not a crash */
}

/* ---- E10: the sweep -------------------------------------------------------------------------- */

#ifdef CAN_FAIL
static uint64_t hash_bytes(const uint8_t *b, uint64_t n)
{
	uint64_t h = 1469598103934665603ull, i;

	for (i = 0; b && i < n; i++)
		h = (h ^ b[i]) * 1099511628211ull;
	return h;
}

/* what an answer is: every object's name, length, bytes and reason */
static uint64_t signature(const struct run_out *o)
{
	uint64_t h = 1469598103934665603ull;
	unsigned i, k;

	for (i = 0; i < o->g.n; i++) {
		h = (h ^ hash_bytes((const uint8_t *)o->g.o[i].name, strlen(o->g.o[i].name))) * 1099511628211ull;
		h = (h ^ o->g.o[i].len) * 1099511628211ull;
		h = (h ^ hash_bytes(o->g.o[i].bytes, o->g.o[i].len)) * 1099511628211ull;
		h = (h ^ o->g.o[i].broken) * 1099511628211ull;
	}
	(void)k;
	return h ^ (uint64_t)o->g.n;
}

static unsigned said_of(const struct run_out *o, const struct run_out *ctl)
{
	unsigned i, k = 0;

	if (o->rc != ctl->rc || o->limit_hits > ctl->limit_hits)
		return 1;
	for (i = 0; i < o->g.n; i++)
		k += o->g.o[i].broken != 0;
	return k > 0;
}

static void e10_sweep_case(void (*s)(const struct kof_obj_ctx *), int plus, const char *what)
{
	struct run_out ctl, o;
	unsigned n, count, refused = 0, changed = 0, silent = 0;
	uint64_t want;

	g_plus = plus;
	sweep_on = 1;
	sweep_nth = 0;
	run_case(s, plus, &ctl);                       /* warm: the one-time tables */
	got_free(&ctl.g);
	run_case(s, plus, &ctl);
	count = ctl.seen;
	want = signature(&ctl);
	CK(count > 10u && ctl.g.n >= 2u && ctl.rc >= 0);
	for (n = 1; n <= count; n++) {
		sweep_nth = n;
		run_case(s, plus, &o);
		if (!o.hit) {
			got_free(&o.g);
			continue;
		}
		refused++;
		if (signature(&o) != want) {
			changed++;
			if (!said_of(&o, &ctl) && o.g.n) {
				silent++;
				printf("  silent [%s, PE%s] allocation %u of %u refused: %u object(s) instead of %u, nothing said\n", what,
				       plus ? "32+" : "32", n, count, o.g.n, ctl.g.n);
			}
		}
		got_free(&o.g);
	}
	got_free(&ctl.g);
	sweep_on = 0;
	printf("  %s, PE%s: %u allocations, %u refused, %u changed the answer, %u silently\n", what, plus ? "32+" : "32", count,
	       refused, changed, silent);
	CK(silent == 0);
}

static void e10_sweep(void)
{
	unsigned plus;

	for (plus = 0; plus < 2u; plus++) {
		e10_sweep_case(step_good, (int)plus, "module builds a PE child with imports");
		e10_sweep_case(step_at_past_end, (int)plus, "the table placed past the image");
		e10_sweep_case(step_none, (int)plus, "module builds a PE child, no imports");
	}
}
#endif

/* ---- the checks ------------------------------------------------------------------------------ */

/* the child of a run, or NULL after saying why not */
static const struct got *the_child(const struct run_out *o, int *ci)
{
	*ci = child_of(&o->g);
	CK(*ci >= 0);
	return *ci >= 0 ? &o->g : NULL;
}

static int bytes_equal(const struct got *a, int ia, const struct got *b, int ib)
{
	return a->o[ia].len == b->o[ib].len && a->o[ia].bytes && b->o[ib].bytes &&
	       !memcmp(a->o[ia].bytes, b->o[ib].bytes, (size_t)a->o[ia].len);
}

static void e3_good(int plus)
{
	struct run_out o;
	struct imps r;
	struct kgenome_pe_info info;
	const uint64_t st = plus ? 8u : 4u, s0 = 0x1100u;
	const struct imp_rec *e;
	int ci;
	uint64_t t = 0;

	g_plus = plus;
	run_case(step_good, plus, &o);
	CK(the_child(&o, &ci) != NULL);
	if (ci < 0)
		return;
	CK(rv[3] == 1 && rv[4] == 1 && rv[5] == 1 && rv[6] == 1 && rv[7] == 1);   /* every declaration answered 1 */
	CK(rv[8] == 1 && rv[9] == 1);                                              /* import_bytes, import_at, done */
	CK(o.limit_hits == 0 && o.g.o[ci].broken == 0 && o.g.o[0].broken == 0);
	CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
	CK(r.n == 5u);
	e = find_imp(&r, "KERNEL32.dll", "ExitProcess", 0);
	CK(e && e->slot == info.image_base + s0);
	e = find_imp(&r, "KERNEL32.dll", "Sleep", 0);
	CK(e && e->slot == info.image_base + s0 + st);
	e = find_imp(&r, "KERNEL32.dll", "", 5);
	CK(e && e->slot == info.image_base + s0 + 2u * st);
	e = find_imp(&r, "USER32.dll", "MessageBoxA", 0);
	CK(e && e->slot == info.image_base + s0 + 4u * st);
	/* the thunk holds its own lookup entry (a name entry points at the name, an ordinal at 0x80000000|n) */
	CK(rd_thunk(o.g.o[ci].bytes, o.g.o[ci].len, s0 + 2u * st, plus, &t));
	CK(t == (plus ? 0x8000000000000005ull : 0x80000005ull));
	CK(rd_thunk(o.g.o[ci].bytes, o.g.o[ci].len, s0, plus, &t) && t != 0 && (t >> 31 & 1u) == 0 && t >= IMP_RVA);
	/* the directory entry points at the table */
	CK(info.n_dirs > KGENOME_PE_DIR_IMPORT && info.dir[KGENOME_PE_DIR_IMPORT].rva == IMP_RVA &&
	   info.dir[KGENOME_PE_DIR_IMPORT].size != 0);
	got_free(&o.g);
}

static void e3_hostile(int plus)
{
	static const struct { uint64_t v; const char *what; } hostile[] = {
		{ UINT64_MAX, "2^64-1" }, { UINT64_MAX - 3u, "2^64-4" }, { UINT64_MAX - 7u, "2^64-8" },
		{ 0x8000000000000000ull, "2^63" }, { 0x7ffffffffffffff8ull, "2^63-8" },
		{ 0x100000000ull, "4 GiB" }, { 0x100001100ull, "4 GiB + a valid slot" },
		{ 0xffffffffull, "2^32-1" }, { 0xfffffffcull, "2^32-4" },
		{ IMG_END, "the end of the image" }, { IMG_END - 1u, "one byte before the end" },
		{ IMG_END - 3u, "straddles the end (32)" }, { IMG_END - 7u, "straddles the end (64)" },
		{ IMG_END + 0x1000u, "past the image" },
	};
	unsigned h, phase;
	struct run_out base;
	int bi;

	g_plus = plus;
	run_case(step_none, plus, &base);
	bi = child_of(&base.g);
	CK(bi >= 0);
	if (bi < 0)
		return;
	for (phase = 0; phase < 2u; phase++) {
		for (h = 0; h < sizeof hostile / sizeof hostile[0]; h++) {
			const uint64_t step = plus ? 8u : 4u;
			/* a slot is fine when its whole thunk lies inside the image: 2^64-1 .. 4 GiB are not, and the
			 * ones around the end are, or are not, according to the width of the thunk */
			const int fits = hostile[h].v <= IMG_END - step;
			struct run_out o;
			struct imps r;
			struct kgenome_pe_info info;
			int ci;

			g_hostile = hostile[h].v;
			run_case(phase ? step_hostile_before_image : step_hostile_after_image, plus, &o);
			ci = child_of(&o.g);
			CK(ci >= 0);
			if (ci < 0) {
				got_free(&o.g);
				continue;
			}
			if (phase == 0) {
				if (rv[3] != fits)
					printf("  slot %s (%#llx) declared into the image: answered %d\n", hostile[h].what,
					       (unsigned long long)hostile[h].v, rv[3]);
				CK(rv[3] == fits);                 /* refused where it is declared, unless it fits */
				CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
				CK(r.n == (fits ? 2u : 1u) && find_imp(&r, "KERNEL32.dll", "ExitProcess", 0) != NULL);
				CK((find_imp(&r, "KERNEL32.dll", "Hostile", 0) != NULL) == fits);
			} else {
				/* declared before the image existed: the table is refused where it is placed */
				if (rv[5] != fits)
					printf("  slot %s (%#llx) declared before the image: import_at answered %d\n",
					       hostile[h].what, (unsigned long long)hostile[h].v, rv[5]);
				CK(rv[5] == fits);
				if (!fits)
					CK(bytes_equal(&o.g, ci, &base.g, bi));   /* exactly the child with no imports */
				else
					CK(!bytes_equal(&o.g, ci, &base.g, bi));
			}
			CK(o.g.o[ci].broken == 0);
			got_free(&o.g);
		}
	}
	got_free(&base.g);
}

/* the last whole slot is accepted and written; the boundary of the check, both widths */
static void e3_boundary(int plus)
{
	struct run_out o;
	struct imps r;
	struct kgenome_pe_info info;
	const uint64_t step = plus ? 8u : 4u;
	uint64_t t = 0;
	int ci;

	g_plus = plus;
	g_hostile = IMG_END - step;
	run_case(step_hostile_after_image, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci < 0)
		return;
	CK(rv[3] == 1);
	CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
	CK(r.n == 2u && find_imp(&r, "KERNEL32.dll", "Hostile", 0) != NULL);
	CK(rd_thunk(o.g.o[ci].bytes, o.g.o[ci].len, IMG_END - step, plus, &t) && t != 0);
	got_free(&o.g);
}

static void e3_table_and_slots(int plus)
{
	struct run_out base, o;
	int bi, ci;
	struct imps r;
	struct kgenome_pe_info info;

	g_plus = plus;
	run_case(step_none, plus, &base);
	bi = child_of(&base.g);
	CK(bi >= 0);
	if (bi < 0)
		return;

	/* a slot on the table itself is refused where the table is placed */
	run_case(step_slot_on_table, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		CK(rv[4] == 0);
		CK(bytes_equal(&o.g, ci, &base.g, bi));
		CK(o.limit_hits == 0 && o.g.o[ci].broken == 0);
	}
	got_free(&o.g);

	/* a table that grows after its place was reserved is not written, and that is said */
	run_case(step_grown_after_at, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		int said_it = o.limit_hits > 0 || o.g.o[0].broken == KOF_BROKEN_LIMIT || o.g.o[ci].broken == KOF_BROKEN_LIMIT;

		CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
		printf("  grown table: child holds %u import(s), said %d\n", r.n, said_it);
		CK(r.n == 0u);
		CK(said_it);
	}
	got_free(&o.g);

	/* the table placed past the image: the sink grows, the table is written there (control) */
	run_case(step_at_past_end, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		const uint8_t *b = o.g.o[ci].bytes;
		uint32_t name_rva = 0;

		CK(rv[4] == 1);
		CK(o.g.o[ci].len > IMG_END + 0x100u + 40u);
		/* the child has no section over the table (the module declared none), so the parser cannot map it:
		 * the bytes are read where they were placed. Descriptor 0: Name at +12 is the library's name. */
		if (b && o.g.o[ci].len > IMG_END + 0x100u + 40u) {
			memcpy(&name_rva, b + IMG_END + 0x100u + 12u, 4);
			CK(name_rva >= IMG_END + 0x100u && name_rva + 13u <= o.g.o[ci].len &&
			   !memcmp(b + name_rva, "KERNEL32.dll", 13));
		}
		(void)r; (void)info;
	}
	got_free(&o.g);

	/* a placement that wraps is refused */
	run_case(step_at_wraps, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	CK(rv[4] == 0 && rv[5] == 0);
	got_free(&o.g);

	/* two imports that share one slot: the second overwrites the first, and the table still parses */
	run_case(step_dup_slot, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
		CK(r.n == 2u || r.n == 0u);          /* either both are listed or the table is refused whole */
	}
	got_free(&o.g);
	got_free(&base.g);
}

static void e3_args(int plus)
{
	struct run_out o;
	struct imps r;
	struct kgenome_pe_info info;
	int ci;
	unsigned i;

	g_plus = plus;
	run_case(step_args, plus, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	for (i = 3; i <= 8u; i++)
		CK(rv[i] == 0);
	CK(rv[9] == 0 && rv[10] == 0);               /* import_at / import_bytes with nothing declared */
	CK(rv[11] == 1);
	if (ci >= 0) {
		CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
		CK(r.n == 1u && find_imp(&r, "K.dll", "Ok", 0) != NULL);
	}
	got_free(&o.g);
}

static void e3_caps(int plus)
{
	struct run_out o;
	int ci;

	g_plus = plus;
	run_case(step_fill, plus, &o);
	CK(rv[3] == 1024);                           /* the 1025th (index 1024) is the first refused */
	CK(o.limit_hits > 0 || o.g.o[0].broken == KOF_BROKEN_LIMIT);
	got_free(&o.g);

	run_case(step_pool, plus, &o);
	CK(rv[3] == 0);                              /* the name that cannot fit the pool */
	CK(nrv >= 5u && rv[4] > 0 && rv[4] < 1100);  /* the pool filled before the entries did */
	ci = child_of(&o.g);
	(void)ci;
	CK(o.limit_hits > 0 || o.g.o[0].broken == KOF_BROKEN_LIMIT);
	got_free(&o.g);
}

static void e6_sections(void)
{
	struct run_out o;

	g_plus = 0;
	run_case(step_sec_order, 0, &o);
	CK(rv[0] == 0);
	if (rv[1] != -1 || rv[2] != -1 || rv[3] != -1 || rv[4] != -1 || rv[5] != 1 || rv[6] != -1 || rv[7] != 0 || rv[8] != -1)
		printf("  section answers: %d %d %d %d %d %d %d %d %d\n", rv[0], rv[1], rv[2], rv[3], rv[4], rv[5], rv[6], rv[7], rv[8]);
	CK(rv[1] == -1);                    /* descending: refused */
	CK(rv[2] == -1);                    /* overlapping the one before it: refused */
	CK(rv[3] == -1);                    /* rva + size wraps: refused */
	CK(rv[4] == -1);                    /* empty: refused */
	CK(rv[5] == 1);                     /* touching it is fine, and gets the next index */
	CK(rv[6] == -1);                    /* a correction may not grow over its neighbour */
	CK(rv[7] == 0);                     /* and may shrink */
	CK(rv[8] == -1);                    /* a correction that wraps */
	got_free(&o.g);
}

static void e6_full(void)
{
	struct run_out o;

	g_plus = 0;
	run_case(step_sec_full, 0, &o);
	CK(rv[0] == 96);                    /* the 97th (index 96) is the first refused */
	CK(o.limit_hits > 0 || o.g.o[0].broken == KOF_BROKEN_LIMIT);   /* a table that is full is said, like the imports */
	got_free(&o.g);
}

/* a payload whose own header declares two sections that overlap: the layout keeps both, as the image says,
 * and the regions of the child must still be a partition - no byte in two of them */
static void step_layout_overlap(const struct kof_obj_ctx *ctx)
{
	static uint8_t hdr[0x400];
	struct ik_pe p;

	note_rv(kunp_rcstruct_section("", 0x1000, 0x2000, KUNP_PERM_R, KOF_SECF_DATA | KOF_SECF_REBUILT));
	note_rv(kunp_rcstruct_image());
	note_rv(kunp_rcstruct_at(0));
	memset(&p, 0, sizeof p);
	p.entry = 0x1000;
	p.size_of_image = 0x3000;
	p.size_of_headers = 0x400;
	ik_sec(&p, ".a", 0x800, 0x1000, 0x200, 0x200, IK_TEXT);
	ik_sec(&p, ".b", 0x800, 0x1400, 0x200, 0x400, IK_DATA);      /* starts inside .a */
	memset(hdr, 0, sizeof hdr);
	(void)ik_pe_write(hdr, &p);
	note_rv((int)kunp_rcstruct_write(hdr, sizeof hdr));
	note_rv((int)(kunp_rcstruct_layout_of_image() != 0));
	note_rv(kunp_rcstruct_done());
}

static void e6_overlap(void)
{
	struct run_out o;
	int ci;
	unsigned a, b;

	g_plus = 0;
	run_case(step_layout_overlap, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		const unsigned n = o.g.o[ci].n_region;

		CK(n >= 2u);
		for (a = 0; a < n; a++)
			for (b = a + 1u; b < n; b++) {
				const uint64_t ae = o.g.o[ci].rgn[a].off + o.g.o[ci].rgn[a].len;
				const uint64_t be = o.g.o[ci].rgn[b].off + o.g.o[ci].rgn[b].len;
				int overlap = o.g.o[ci].rgn[a].len && o.g.o[ci].rgn[b].len &&
					      o.g.o[ci].rgn[a].off < be && o.g.o[ci].rgn[b].off < ae;

				if (overlap)
					printf("  regions %u and %u overlap: [%#llx,+%#llx) [%#llx,+%#llx)\n", a, b,
					       (unsigned long long)o.g.o[ci].rgn[a].off, (unsigned long long)o.g.o[ci].rgn[a].len,
					       (unsigned long long)o.g.o[ci].rgn[b].off, (unsigned long long)o.g.o[ci].rgn[b].len);
				CK(!overlap);
			}
	}
	got_free(&o.g);
}

static void e6_layout_child(unsigned unused)
{
	struct run_out o;
	int ci;

	(void)unused;
	g_plus = 0;
	run_case(step_layout_hostile, 0, &o);
	ci = child_of(&o.g);
	printf("  layout from the payload with a first section at 0x30000000: close answered %d, child %s\n", rv[5],
	       ci >= 0 ? "made" : "refused");
	CK(rv[0] >= 0 && rv[1] == 1 && rv[2] == 1 && rv[4] == 1);
	CK(rv[5] == 0);                              /* the child is refused (the header cannot be written in front of it) ... */
	CK(ci < 0);
	CK(o.g.o[0].broken != 0);                    /* ... and the parent says it was damaged or cut, not clean */
	got_free(&o.g);
}

static void e3_reset(void)
{
	struct run_out o;
	struct kgenome_pe_info info;
	struct imps r;
	int ci;

	g_plus = 0;
	run_case(step_reset, 0, &o);
	ci = child_of(&o.g);
	CK(ci >= 0);
	CK(rv[3] == 1);                              /* sections_reset */
	CK(rv[4] == 0 && rv[5] == 0);                /* the first declaration after it, and the replacing one */
	CK(rv[6] == 1 && rv[7] == 0 && rv[8] == 1);  /* dir 3 accepted, dir 16 refused, entry accepted */
	if (ci >= 0) {
		CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
		CK(info.n_dirs > 3u && info.dir[3].rva == 0x1200u && info.dir[3].size == 0x40u);
		CK(info.entry_rva == 0x1010u);
	}
	got_free(&o.g);
}

#ifdef CAN_FAIL
/* an allocation refused inside oc_import: said, no crash on the next call, no leak at the end */
static void e3_alloc_child(unsigned which)
{
	struct run_out o;
	struct imps r;
	struct kgenome_pe_info info;
	int ci;
	const size_t a = 1024u * sizeof(struct kgenome_imp_decl), b = 65536u;

	g_plus = 0;
	track_a = a;
	track_b = b;
	arm(KC, which ? b : a, 1);
	run_case(step_good, 0, &o);
	disarm();
	CK(inj.hit == 1u);
	CK(rv[3] == 0);                              /* the first import is refused */
	CK(o.limit_hits > 0 || o.g.o[0].broken == KOF_BROKEN_LIMIT);   /* and that is said */
	ci = child_of(&o.g);
	CK(ci >= 0);
	if (ci >= 0) {
		CK(rv[4] == 1);                      /* the next call allocates again and works */
		CK(read_imports(o.g.o[ci].bytes, o.g.o[ci].len, &r, &info));
	}
	printf("  calloc(%s) refused: first import answered %d, live big allocations after the scan %u\n",
	       which ? "pool" : "table", rv[3], o.live_after);
	CK(o.live_after == 0u);                      /* a half-made table is given back, not leaked */
	got_free(&o.g);
	track_a = track_b = 0;
}

/* run in a child with an alarm: the case that dereferenced a NULL pool must be a result, not the end */
static int isolated(void (*fn)(unsigned), unsigned arg)
{
	pid_t p;
	int st = 0;

	fflush(stdout);
	p = fork();
	if (p == 0) {
		alarm(60);
		fails = 0;
		fn(arg);
		fflush(stdout);
		_exit(fails ? 1 : 0);
	}
	if (p < 0 || waitpid(p, &st, 0) != p)
		return 0;
	if (WIFSIGNALED(st)) {
		printf("  the case was killed by signal %d\n", WTERMSIG(st));
		return 0;
	}
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static void e3_alloc(void)
{
	unsigned which;

	for (which = 0; which < 2u; which++)
		CK(isolated(e3_alloc_child, which));
}

/* the realloc that grows the sink for a table placed past the image is refused: the limit is said and sticky */
static void e3_realloc_refused(void)
{
	struct run_out o;

	static const char pool[] = "KERNEL32.dll\0ExitProcess";
	struct kgenome_imp_decl d;
	uint64_t need;

	g_plus = 0;
	memset(&d, 0, sizeof d);
	d.iat_rva = 0x1100u;
	d.fn_off = 13;
	need = kgenome_pe_imports_size(&d, 1, pool, sizeof pool, 0);
	CK(need != 0);
	arm(KR, (size_t)(IMG_END + 0x100u + need), 1);   /* the growth of the sink is the one realloc of this size */
	run_case(step_at_past_end, 0, &o);
	disarm();
	CK(inj.hit == 1u);
	CK(rv[4] == 0);                                  /* the module is told */
	CK(o.limit_hits > 0 || o.g.o[0].broken == KOF_BROKEN_LIMIT || o.g.o[1].broken == KOF_BROKEN_LIMIT);   /* and so is the host */
	got_free(&o.g);
}
#endif

int main(void)
{
	unsigned plus;
	const char *tmp = getenv("TMPDIR");

	snprintf(root, sizeof root, "%s/kof_e2_XXXXXX", tmp && *tmp ? tmp : "build");
	if (!mkdtemp(root)) {
		printf("engine_defect2: cannot make a work directory\n");
		return 2;
	}
	for (plus = 0; plus < 2u; plus++) {
		snprintf(parent_path[plus], sizeof parent_path[plus], "%s/parent%u.exe", root, plus);
		write_parent(parent_path[plus], (int)plus);
	}

	printf("E2 declarations the allocator refuses\n");
	e2_declare_refused();
	for (plus = 0; plus < 2u; plus++) {
		printf("E3 imports a module declares, PE%s parent\n", plus ? "32+" : "32");
		e3_good((int)plus);
		e3_hostile((int)plus);
		e3_boundary((int)plus);
		e3_table_and_slots((int)plus);
		e3_args((int)plus);
		e3_caps((int)plus);
	}
	e3_reset();
	e11_as();
	e12_derive();
	e13_regions();
	e13_edges();
	e6_sections();
	e6_full();
	e6_overlap();
	{
		pid_t cp;
		int stt = 0;

		/* forked: the unfixed engine zeroes 768 MB of a 12 KB buffer, and a crash is the result */
		fflush(stdout);
		cp = fork();
		if (cp == 0) {
			alarm(60);
			fails = 0;
			e6_layout_child(0);
			fflush(stdout);
			_exit(fails ? 1 : 0);
		}
		if (cp < 0 || waitpid(cp, &stt, 0) != cp)
			stt = 1;
		if (WIFSIGNALED(stt))
			printf("  the layout case was killed by signal %d\n", WTERMSIG(stt));
		CK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
	}
#ifdef CAN_FAIL
	printf("E10 allocation sweep of the producer's path\n");
	e10_sweep();
	e3_alloc();
	e3_realloc_refused();
#else
	printf("  (a sanitizer owns malloc: the allocation cases are skipped)\n");
#endif
	for (plus = 0; plus < 2u; plus++) {
		char p[320];

		snprintf(p, sizeof p, "%s/parent%u.exe", root, plus);
		unlink(p);
	}
	rmdir(root);
	if (fails) {
		printf("engine_defect2: %d check(s) failed\n", fails);
		return 1;
	}
	printf("engine_defect2: ok\n");
	return 0;
}
