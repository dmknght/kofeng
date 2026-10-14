/*
 * fnprint_adv_stream - the window stream and the library table under an author who edits the file.
 *
 * The exclusion ground of the stream is the BYTES: a window in the library table is credited to the
 * LIB side, every other window to the USER side. The cases below are the edits an author can make to
 * hide his code or to forge credit, each on an object built in memory:
 *   - his payload placed inside a copy of a library function, or behind a library prologue;
 *   - marker strings (malloc(): , __libc_, GLIBC_) written into his code, symbol-like strings added;
 *   - his functions reordered, put after the library, put before the entry;
 *   - junk functions added to dilute;
 * and, in the other direction, a library function copied verbatim (which IS library code and is
 * treated as such: the one thing the table is for).
 */
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

static struct fk_var V0 = { 0x1000, 0x2000, 0x12345678u };

struct world {
	struct fk_obj lib_src;                 /* the "library": what the table is built from */
	struct kgenome_fnprint_libtab lib;
	uint64_t libfn[4], liblen[4];
};

static void world_init(struct world *w)
{
	uint32_t i;

	fk_init(&w->lib_src);
	for (i = 0; i < 4; i++) {
		w->libfn[i] = fk_func(&w->lib_src, 800 + i, 120, &V0);
		w->liblen[i] = w->lib_src.n - w->libfn[i];
	}
	kgenome_fnprint_libtab_init(&w->lib, 0, NULL);
	kgenome_fnprint_libtab_add(&w->lib, w->lib_src.b, w->lib_src.n);
}

static void world_free(struct world *w)
{
	kgenome_fnprint_libtab_free(&w->lib);
	fk_free(&w->lib_src);
}

/* The block of a payload (bytes the library does not have) and its credit on an object. */
struct probe {
	struct kgenome_fnprint_wblock blk[1];
	uint32_t pool[32];
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c;
};

static int probe_init(struct probe *pr, const uint8_t *payload, uint64_t n, const struct kgenome_fnprint_libtab *lib)
{
	struct kgenome_fnprint_wdb_opts o;
	uint32_t m = kgenome_fnprint_wsketch(payload, n, lib, pr->pool, 32);

	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	pr->blk[0].first = 0; pr->blk[0].n = m; pr->blk[0].side = KGENOME_MUTATION_SIDE_USER; pr->blk[0].tag = 0;
	if (m < 16 || !kgenome_fnprint_wdb_build(&pr->d, pr->blk, 1, pr->pool, m, &o))
		return 0;
	return kgenome_fnprint_wctx_init(&pr->c, &pr->d, NULL);
}

static void probe_done(struct probe *pr)
{
	kgenome_fnprint_wctx_done(&pr->c);
	kgenome_fnprint_wdb_free(&pr->d);
}

/* Credit, in percent of the block's hashes, of the whole object bytes with the table (or without). */
static uint32_t credit(struct probe *pr, const struct fk_obj *o, const struct kgenome_fnprint_libtab *lib)
{
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	struct kof_range ext;

	ext.off = 0; ext.len = o->n;
	memset(&rq, 0, sizeof rq);
	rq.p = o->b; rq.n = o->n; rq.ext = &ext; rq.n_ext = 1; rq.lib = lib; rq.c = &pr->c; rq.stat = &st;
	kgenome_fnprint_wctx_begin(&pr->c);
	kgenome_fnprint_wpass(&rq);
	return kgenome_fnprint_wctx_count(&pr->c, 0) * 100u / pr->blk[0].n;
}

/* The payload: author code the library does not contain. */
static uint32_t make_payload(struct fk_obj *p, uint32_t seed, uint32_t nins)
{
	fk_init(p);
	fk_func(p, seed, nins, &V0);
	return (uint32_t)p->n;
}

/* 1. The payload inside a copy of a library function: library bytes round it, his windows in the middle. */
static void t_payload_inside_library_function(void)
{
	struct world w;
	struct fk_obj pay, o;
	struct probe pr;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	uint64_t at, half;

	world_init(&w);
	make_payload(&pay, 4001, 40);
	fk_init(&o);
	/* [first half of libfn 0][payload][second half of libfn 0]: one function, mostly library */
	half = w.liblen[0] / 2u;
	at = o.n;
	fk_raw(&o, w.lib_src.b + w.libfn[0], half);
	fk_raw(&o, pay.b, pay.n);
	fk_raw(&o, w.lib_src.b + w.libfn[0] + half, w.liblen[0] - half);
	fk_mark(&o, at, o.n - at);
	CK(probe_init(&pr, pay.b, pay.n, &w.lib));
	CK(credit(&pr, &o, &w.lib) >= 90u);                      /* the payload's own windows are not in the table: credited */
	probe_done(&pr);
	/* the function-level view: LIB by its windows, and the residual is still evidence */
	fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.hint.libtab = &w.lib;
	kgenome_fnprint_collect(&rq, &s);
	CK(s.n == 1 && (s.fn[0].reason & KGENOME_FNP_R_LIBWIN) && s.fn[0].cls == KGENOME_FNP_LIB);
	CK(s.fn[0].weight > 0 && s.fn[0].n_win_lib < s.fn[0].n_win);   /* the residual weighs as author code */
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o); fk_free(&pay);
	world_free(&w);
}

/* 2. Behind a libc-looking prologue: the function begins with 24 library bytes. */
static void t_library_prologue(void)
{
	struct world w;
	struct fk_obj pay, o;
	struct probe pr;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	uint64_t at;

	world_init(&w);
	make_payload(&pay, 4002, 60);
	fk_init(&o);
	at = o.n;
	fk_raw(&o, w.lib_src.b + w.libfn[1], 24);
	fk_raw(&o, pay.b, pay.n);
	fk_mark(&o, at, o.n - at);
	CK(probe_init(&pr, pay.b, pay.n, &w.lib));
	CK(credit(&pr, &o, &w.lib) >= 90u);
	probe_done(&pr);
	fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.hint.libtab = &w.lib;
	kgenome_fnprint_collect(&rq, &s);
	CK(s.n == 1 && !(s.fn[0].reason & KGENOME_FNP_R_LIBWIN) && s.fn[0].cls != KGENOME_FNP_LIB && s.fn[0].weight > 0);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o); fk_free(&pay);
	world_free(&w);
}

/* 3. Marker strings and symbol-looking strings in his code, reorder, junk: the credit does not move. */
static void t_markers_reorder_junk(void)
{
	struct world w;
	struct fk_obj pay, o1, o2, o3;
	struct probe pr;
	static const char *const junk[] = { "malloc(): corrupted", "free(): invalid pointer", "__libc_start_main", "GLIBC_2.2.5", "_dl_relocate_static_pie", "uClibc" };
	uint32_t i, base;

	world_init(&w);
	make_payload(&pay, 4003, 80);
	CK(probe_init(&pr, pay.b, pay.n, &w.lib));
	/* the bare object: [payload] */
	fk_init(&o1);
	fk_raw(&o1, pay.b, pay.n);
	base = credit(&pr, &o1, &w.lib);
	CK(base == 100u);
	/* marker strings (and names) round the payload, in the same range */
	fk_init(&o2);
	for (i = 0; i < 6; i++)
		fk_raw(&o2, junk[i], strlen(junk[i]) + 1u);
	fk_raw(&o2, pay.b, pay.n);
	for (i = 0; i < 6; i++)
		fk_raw(&o2, junk[i], strlen(junk[i]) + 1u);
	CK(credit(&pr, &o2, &w.lib) == base);
	/* reordered: the library first, the payload after it, a hundred junk functions behind */
	fk_init(&o3);
	for (i = 0; i < 4; i++)
		fk_raw(&o3, w.lib_src.b + w.libfn[i], w.liblen[i]);
	fk_raw(&o3, pay.b, pay.n);
	for (i = 0; i < 100; i++)
		fk_func(&o3, 6000 + i, 50, &V0);
	CK(credit(&pr, &o3, &w.lib) == base);                    /* neither order nor dilution lowers a block's containment */
	probe_done(&pr);
	fk_free(&o1); fk_free(&o2); fk_free(&o3); fk_free(&pay);
	world_free(&w);
}

/* 4. A library function copied verbatim IS library: the table excludes it, and says so. */
static void t_verbatim_library_is_library(void)
{
	struct world w;
	struct fk_obj o;
	struct kgenome_fnprint_wblock blk[1];
	uint32_t sk[32], n;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts op;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	struct kof_range ext;

	world_init(&w);
	fk_init(&o);
	fk_raw(&o, w.lib_src.b + w.libfn[2], w.liblen[2]);
	n = kgenome_fnprint_wsketch(o.b, o.n, NULL, sk, 32);         /* a block cut WITHOUT the table: it holds library windows */
	memset(&op, 0, sizeof op);
	op.n_tag = 1;
	blk[0].first = 0; blk[0].n = n; blk[0].side = KGENOME_MUTATION_SIDE_USER; blk[0].tag = 0;
	CK(n == 32 && kgenome_fnprint_wdb_build(&d, blk, 1, sk, n, &op) && kgenome_fnprint_wctx_init(&c, &d, NULL));
	ext.off = 0; ext.len = o.n;
	memset(&rq, 0, sizeof rq);
	rq.p = o.b; rq.n = o.n; rq.ext = &ext; rq.n_ext = 1; rq.lib = &w.lib; rq.c = &c; rq.stat = &st;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_wpass(&rq);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 0 && st.n_lib >= 32);   /* library windows are not USER evidence */
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	fk_free(&o);
	world_free(&w);
}

/* 5. The exploit that remains: the author edits the LIBRARY copy's bytes, one in a few, to leave the table. */
static void t_patched_library_leaves_the_table(void)
{
	struct world w;
	struct fk_obj o;
	struct kgenome_fnprint_libvote v;
	uint64_t i;

	world_init(&w);
	fk_init(&o);
	fk_raw(&o, w.lib_src.b + w.libfn[0], w.liblen[0]);
	for (i = 4; i < o.n; i += 6)
		o.b[i] ^= 0x55u;                                   /* every 6th byte: no 8-byte window survives */
	kgenome_fnprint_libvote(&w.lib, o.b, o.n, &v);
	/* A patched copy is not library bytes any more; it is kept as evidence. That is the correct
	 * direction (nothing is hidden) and the cost: the same patch makes library code look like the
	 * author's, so it is credited as USER. The table cannot know it was library. */
	KM_CHECK(v.n_hit * 2u > v.n_win,
		 "a library function patched every sixth byte is still recognised as library",
		 "PATCHED_LIBRARY_COPY_LOOKS_LIKE_AUTHOR_CODE");
	fk_free(&o);
	world_free(&w);
}

/* 6. What the function-level weights lose to dead padding, tiny functions or a bogus symbol extent, the window stream keeps. */
static void t_stream_ignores_function_shape(void)
{
	struct world w;
	struct fk_obj pay, o;
	struct probe pr;
	uint32_t i;
	uint64_t half;

	world_init(&w);
	make_payload(&pay, 4010, 120);
	CK(probe_init(&pr, pay.b, pay.n, &w.lib));
	/* the payload split by 120 bytes of zeros after a jump, and again by 120 undecodable bytes: no function extents given at all */
	fk_init(&o);
	half = pay.n / 2u;
	fk_raw(&o, pay.b, half);
	fk_raw(&o, "\xeb\x78", 2);
	fk_fill(&o, 0x00, 120);
	fk_raw(&o, pay.b + half, pay.n - half);
	CK(credit(&pr, &o, &w.lib) >= 80u);
	fk_free(&o);
	fk_init(&o);
	fk_raw(&o, pay.b, half);
	fk_raw(&o, "\xeb\x78", 2);
	fk_fill(&o, 0x06, 120);
	fk_raw(&o, pay.b + half, pay.n - half);
	CK(credit(&pr, &o, &w.lib) >= 80u);
	fk_free(&o);
	/* the payload cut into 4-instruction pieces (what an author does to make every function tiny): the windows are the bytes */
	fk_init(&o);
	for (i = 0; i < pay.n; i += 16)
		fk_raw(&o, pay.b + i, pay.n - i < 16 ? pay.n - i : 16);
	CK(credit(&pr, &o, &w.lib) == 100u);
	fk_free(&o);
	probe_done(&pr);
	fk_free(&pay);
	world_free(&w);
}

int main(void)
{
	t_payload_inside_library_function();
	t_library_prologue();
	t_markers_reorder_junk();
	t_verbatim_library_is_library();
	t_patched_library_leaves_the_table();
	t_stream_ignores_function_shape();
	printf("fnprint_adv_stream: %s (known-miss %u)\n", hk_fails ? "FAIL" : "ok", km_known());
	return hk_fails != 0 || km_failed();
}
