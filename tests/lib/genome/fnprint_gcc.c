/*
 * fnprint_gcc - the shapes a gcc/ld/glibc link gives an object, built in memory, and what
 * the fnprint walk makes of each. Measured on a controlled corpus (a gcc 15.2 matrix of
 * ten programs: -O0..-Os, static, static-pie, dynamic, stripped or not, -flto, -fcf-protection,
 * link orders); the numbers are in fnprint_gcc_eval.md. Nothing here needs gcc: every object is
 * x86-64 machine code laid out byte by byte.
 *
 *   - the layout of a static link: cold parts and .text.startup of the libraries first, the entry,
 *     the crtbegin helpers, the program, the start-up code of libc behind it (libc-start.o: static
 *     helpers and then __libc_start_main, the target of the entry's call), the rest of libc;
 *   - what the walk does with them: main and what it reaches is the program's, the crt helpers and
 *     the runtime's start-up code lie between and behind and are not, the PLT is thunks;
 *   - code the function set does not enter: an extent that holds a second function behind padding,
 *     main cut out of an extent, a jump table whose blocks are not functions;
 *   - what does not change a fingerprint: an ENDBR, the length of an alignment nop;
 *   - what the rules cannot do, as KM_CHECK with the cause: a function only a data table names, an
 *     author cold part before the entry, a function behind a switch with no bounds check.
 */
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

static struct fk_var V = { 0x100, 0x200, 0x30405060u };

/* ---- a function written byte by byte ----------------------------------------- */

struct fb {
	uint8_t b[1024];
	uint32_t n;
};

static void fb_raw(struct fb *f, const uint8_t *p, uint32_t n)
{
	memcpy(f->b + f->n, p, n);
	f->n += n;
}

#define FB(f, ...) do { static const uint8_t t_[] = { __VA_ARGS__ }; fb_raw((f), t_, sizeof t_); } while (0)

/* `call rel32` to a place not known yet; *site is the offset of the rel32 inside the function. */
static void fb_call(struct fb *f, uint32_t *site)
{
	FB(f, 0xe8, 0, 0, 0, 0);
	*site = f->n - 4;
}

static void fb_jmp(struct fb *f, uint32_t *site)
{
	FB(f, 0xe9, 0, 0, 0, 0);
	*site = f->n - 4;
}

/* The function's bytes are the object's from here: returns its offset. */
static uint64_t place(struct fk_obj *o, const struct fb *f)
{
	uint64_t at = o->n;

	fk_raw(o, f->b, f->n);
	fk_mark(o, at, f->n);
	return at;
}

/* push rbp; mov rbp,rsp; xor eax,eax; add eax,1; pop rbp; ret - six instructions, a small function of its own. */
static uint64_t small_fn(struct fk_obj *o, uint8_t seed)
{
	struct fb f = { { 0 }, 0 };

	FB(&f, 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x83, 0xc0);
	f.b[f.n++] = seed;
	FB(&f, 0x5d, 0xc3);
	return place(o, &f);
}

/* An alignment pad of `n` bytes between functions, as a linker or as: 0 nops, 1 int3, 2 multi-byte nop. */
static void pad(struct fk_obj *o, int kind, uint32_t n)
{
	static const uint8_t nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (kind == 0) fk_fill(o, 0x90, 1);
		else if (kind == 1) fk_fill(o, 0xcc, 1);
		else if (kind == 2) fk_raw(o, nop6, 6);
		else fk_fill(o, 0x00, 1);
	}
}

/* The entry stub: lea rdi,[rip+main]; call start; hlt (ind: the call is `call *[rip+x]`, static-pie's). Patched by entry_set. */
static int stub_ind;

static uint64_t entry_stub(struct fk_obj *o)
{
	static const uint8_t c[13] = { 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xf4 };
	static const uint8_t ci[14] = { 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xff, 0x15, 0, 0, 0, 0, 0xf4 };
	uint64_t at = o->n;

	if (stub_ind) {
		fk_raw(o, ci, 14);
		fk_mark(o, at, 14);
	} else {
		fk_raw(o, c, 13);
		fk_mark(o, at, 13);
	}
	return at;
}

static void entry_set(struct fk_obj *o, uint64_t e, uint64_t main_off, uint64_t start_off)
{
	int32_t d1 = (int32_t)((int64_t)main_off - (int64_t)(e + 7));
	int32_t d2 = (int32_t)((int64_t)start_off - (int64_t)(e + 12));

	memcpy(o->b + e + 3, &d1, 4);
	if (!stub_ind)
		memcpy(o->b + e + 8, &d2, 4);
}

/* A main that calls the given functions. Returns its offset; the calls are patched at once. */
static uint64_t main_calls(struct fk_obj *o, const uint64_t *to, uint32_t n)
{
	struct fb f = { { 0 }, 0 };
	uint32_t site[16], i;
	uint64_t at = o->n;

	FB(&f, 0x55, 0x48, 0x89, 0xe5);
	for (i = 0; i < n; i++)
		fb_call(&f, &site[i]);
	FB(&f, 0x5d, 0xc3);
	place(o, &f);
	for (i = 0; i < n; i++)
		fk_call_to(o, at + site[i], to[i]);
	return at;
}

static void walk(struct fk_obj *o, enum kgenome_fnprint_link link, uint64_t entry, struct kgenome_fnprint_set *s,
		 struct kgenome_fnprint_stat *st, struct kgenome_func_set *fs, uint32_t off_bits)
{
	struct kgenome_fnprint_req rq;

	fk_req(&rq, o, link, st, fs);
	rq.entry_off = entry;
	rq.opt.off = off_bits;
	rq.extents = KGENOME_FNP_EXT_ENTRY_WALK;       /* the extents here are what an entry walk hands over */
	kgenome_fnprint_collect(&rq, s);
}

static const struct kgenome_fnprint_fn *at_off(const struct kgenome_fnprint_set *s, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < s->n; i++)
		if (s->fn[i].off == off)
			return &s->fn[i];
	return NULL;
}

static int is_at(const struct kgenome_fnprint_set *s, uint64_t off, int cls, uint32_t reasons)
{
	const struct kgenome_fnprint_fn *f = at_off(s, off);

	return f && f->cls == cls && (f->reason & reasons) == reasons;
}

static int cls_at(const struct kgenome_fnprint_set *s, uint64_t off)
{
	const struct kgenome_fnprint_fn *f = at_off(s, off);

	return f ? (int)f->cls : -1;
}

static uint32_t weight_at(const struct kgenome_fnprint_set *s, uint64_t off)
{
	const struct kgenome_fnprint_fn *f = at_off(s, off);

	return f ? f->weight : 0xffffffffu;
}

/* ---- 1. the layout of a static gcc link -------------------------------------- */

struct slink {
	struct fk_obj o;
	uint64_t cold, entry, crt[3], mn, a1, isl, a2, pre[2], start, libc[3], noret;
};

/*
 * [libc cold part: ends in a call that does not return] [entry] [three crtbegin helpers] [main]
 * [author A1] [island: author code nothing calls] [author A2] [two static helpers of libc-start.o]
 * [__libc_start_main, the target of the entry's call] [libc]. main reaches A1 and A2.
 */
static void build_static(struct slink *l)
{
	struct fb f = { { 0 }, 0 };
	uint32_t site, i;
	uint64_t to[2];

	fk_init(&l->o);
	FB(&f, 0xbf, 1, 0, 0, 0);                        /* mov edi,1 */
	fb_call(&f, &site);                              /* call abort: no return, no terminal */
	l->cold = place(&l->o, &f);
	fk_call_to(&l->o, l->cold + site, l->cold);
	l->entry = entry_stub(&l->o);
	for (i = 0; i < 3; i++)
		l->crt[i] = small_fn(&l->o, (uint8_t)(i + 1));
	{
		/* main is built once its callees exist; reserve its place now by building the callees first is not
		 * possible (address order), so main calls forward: patch after */
		struct fb m = { { 0 }, 0 };
		uint32_t s1, s2;

		FB(&m, 0x55, 0x48, 0x89, 0xe5);
		fb_call(&m, &s1);
		fb_call(&m, &s2);
		FB(&m, 0x5d, 0xc3);
		l->mn = place(&l->o, &m);
		l->a1 = fk_func(&l->o, 11, 40, &V);
		l->isl = fk_func(&l->o, 12, 40, &V);
		l->a2 = fk_func(&l->o, 13, 40, &V);
		to[0] = l->a1; to[1] = l->a2;
		fk_call_to(&l->o, l->mn + s1, to[0]);
		fk_call_to(&l->o, l->mn + s2, to[1]);
	}
	l->pre[0] = fk_func(&l->o, 21, 40, &V);
	l->pre[1] = fk_func(&l->o, 22, 40, &V);
	l->start = fk_func(&l->o, 23, 60, &V);
	for (i = 0; i < 3; i++)
		l->libc[i] = fk_func(&l->o, 30 + i, 40, &V);
	entry_set(&l->o, l->entry, l->mn, l->start);
}

static void t_static_layout(void)
{
	struct slink l;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	uint32_t i;

	build_static(&l);
	walk(&l.o, KGENOME_FNP_LINK_STATIC, l.entry, &s, &st, &fs, 0);
	CK(st.main_off == l.mn);
	CK(is_at(&s, l.cold, KGENOME_FNP_LIB, KGENOME_FNP_R_PRE_ENTRY));           /* before the entry, not main */
	CK(is_at(&s, l.entry, KGENOME_FNP_LIB, KGENOME_FNP_R_STARTUP));
	for (i = 0; i < 3; i++)                                                           /* crtbegin helpers: nothing reaches them */
		CK(is_at(&s, l.crt[i], KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	CK(is_at(&s, l.mn, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_MAIN));
	CK(is_at(&s, l.a1, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
	CK(is_at(&s, l.a2, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
	CK(is_at(&s, l.isl, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_ISLAND));              /* between two reached: the program's */
	for (i = 0; i < 2; i++)                                                           /* libc-start.o's helpers lie before __libc_start_main */
		CK(is_at(&s, l.pre[i], KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	CK(is_at(&s, l.start, KGENOME_FNP_LIB, KGENOME_FNP_R_LIB_START | KGENOME_FNP_R_BEYOND));
	for (i = 0; i < 3; i++)
		CK(is_at(&s, l.libc[i], KGENOME_FNP_LIB, KGENOME_FNP_R_BEYOND));
	CK(st.frontier_off == l.start);
	CK(st.n_reached == 2 && st.n_island == 1 && st.n_region == 10);       /* held until the frontier: the entry up to libc-start's helpers */
	CK(st.status == KGENOME_OK && st.n_region_over == 0);
	/* only the program's functions weigh: the library part adds nothing to a signature */
	{
		uint64_t wa = 0, wl = 0;

		for (i = 0; i < s.n; i++) {
			if (s.fn[i].cls == KGENOME_FNP_AUTHOR) wa += s.fn[i].weight; else wl += s.fn[i].weight;
		}
		CK(wa > 100 && wl == 0);
	}
	kgenome_fnprint_set_free(&s, NULL);

	/* the same object, the rules of the pristine tree: the helpers and libc-start's start-up code weigh as the program */
	walk(&l.o, KGENOME_FNP_LINK_STATIC, l.entry, &s, &st, &fs, KGENOME_FNP_OFF_ENTRY_ORDER | KGENOME_FNP_OFF_REACH);
	CK(cls_at(&s, l.cold) == KGENOME_FNP_AUTHOR && cls_at(&s, l.crt[0]) == KGENOME_FNP_AUTHOR);
	CK(cls_at(&s, l.pre[0]) == KGENOME_FNP_AUTHOR && cls_at(&s, l.start) == KGENOME_FNP_AUTHOR);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&l.o);
}

/* The same layout with the entry's call indirect (static-pie: call *__libc_start_main@GOT): no lib0, the seeds latch. */
static void t_static_pie_entry(void)
{
	struct slink l;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	uint64_t w[3];
	uint32_t i;

	stub_ind = 1;
	build_static(&l);
	for (i = 0; i < 3; i++)
		w[i] = fk_wrapper(&l.o, 1 + i);
	for (i = 0; i < 3; i++)
		fk_func(&l.o, 40 + i, 40, &V);
	walk(&l.o, KGENOME_FNP_LINK_STATIC, l.entry, &s, &st, &fs, 0);
	stub_ind = 0;
	CK(st.main_off == l.mn);                         /* the lea names main whatever the call is */
	CK(is_at(&s, l.mn, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_MAIN));
	CK(is_at(&s, l.a1, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
	CK(is_at(&s, l.crt[0], KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	/* nothing names the runtime's start: libc-start's code lies before the wrappers, unreached and behind the program */
	CK(is_at(&s, l.pre[0], KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	CK(is_at(&s, l.start, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	CK(is_at(&s, w[0], KGENOME_FNP_LIB, KGENOME_FNP_R_WRAPPER));
	CK(st.frontier_off == w[2]);
	CK(st.status == KGENOME_OK);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&l.o);
}

/* ---- 2. dynamic: the libraries are not in the file ---------------------------- */

static void t_dynamic(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	uint64_t plt0, plt1, e, mn, crt0, crt1, a1, isl, a2, tail, to[2];
	struct fb f = { { 0 }, 0 };

	fk_init(&o);
	/* .text.startup: main (O2 puts it first) is placed after the PLT and before the entry in a dynamic link */
	FB(&f, 0xff, 0x25, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0);     /* a lazy PLT slot: jmp *got; push n; jmp plt0 */
	plt0 = place(&o, &f);
	f.n = 0;
	FB(&f, 0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0, 0, 0, 0);          /* PLT.sec: endbr64; bnd jmp *got */
	plt1 = place(&o, &f);
	e = entry_stub(&o);
	crt0 = small_fn(&o, 1);
	crt1 = small_fn(&o, 2);
	{
		struct fb m = { { 0 }, 0 };
		uint32_t s1, s2;

		FB(&m, 0x55, 0x48, 0x89, 0xe5);
		fb_call(&m, &s1);
		fb_call(&m, &s2);
		FB(&m, 0x5d, 0xc3);
		mn = place(&o, &m);
		a1 = fk_func(&o, 11, 40, &V);
		isl = fk_func(&o, 12, 40, &V);
		a2 = fk_func(&o, 13, 40, &V);
		to[0] = a1; to[1] = a2;
		fk_call_to(&o, mn + s1, to[0]);
		fk_call_to(&o, mn + s2, to[1]);
	}
	tail = fk_func(&o, 14, 40, &V);                  /* the program's, nothing calls it, behind the last reached function */
	entry_set(&o, e, mn, plt0);                      /* the entry's call lands in the PLT in a dynamic link: not a runtime start */
	walk(&o, KGENOME_FNP_LINK_DYNAMIC, e, &s, &st, &fs, 0);
	CK(st.main_off == mn);                           /* found in a dynamic object too */
	CK(is_at(&s, plt0, KGENOME_FNP_LIB, KGENOME_FNP_R_THUNK));
	CK(is_at(&s, plt1, KGENOME_FNP_LIB, KGENOME_FNP_R_THUNK));
	CK(is_at(&s, e, KGENOME_FNP_LIB, KGENOME_FNP_R_STARTUP));
	CK(is_at(&s, crt0, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	CK(is_at(&s, crt1, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	CK(is_at(&s, mn, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_MAIN));
	CK(is_at(&s, a1, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
	CK(is_at(&s, isl, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_ISLAND));
	CK(is_at(&s, a2, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
	CK(is_at(&s, tail, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_DYNAMIC));              /* the libraries are not in the file: what follows is the program's */
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/* main reaches nothing it can see (it calls through the PLT): the startup helpers cannot be told from callbacks */
	fk_init(&o);
	f.n = 0;
	FB(&f, 0xff, 0x25, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0);
	plt0 = place(&o, &f);
	e = entry_stub(&o);
	crt0 = small_fn(&o, 1);
	mn = main_calls(&o, &plt0, 1);
	entry_set(&o, e, mn, plt0);
	walk(&o, KGENOME_FNP_LINK_DYNAMIC, e, &s, &st, &fs, 0);
	CK(is_at(&s, mn, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_MAIN));
	CK(is_at(&s, crt0, KGENOME_FNP_UNKNOWN, KGENOME_FNP_R_UNREACHED));            /* said so, at the UNKNOWN weight */
	CK(weight_at(&s, crt0) > 0 && weight_at(&s, crt0) < 6);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* ---- 3. edges: tail calls, addresses taken ------------------------------------ */

static void t_edges(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct fb m = { { 0 }, 0 }, a = { { 0 }, 0 };
	uint32_t sm_call, sm_lea, sm_imm, sa_jmp;
	uint64_t e, mn, a1, b, h1, h2, lib0, far_fn;

	fk_init(&o);
	e = entry_stub(&o);
	FB(&m, 0x55, 0x48, 0x89, 0xe5);
	fb_call(&m, &sm_call);                           /* call A1 */
	FB(&m, 0x48, 0x8d, 0x35, 0, 0, 0, 0);            /* lea rsi,[rip+H1]: a handler handed to signal() */
	sm_lea = m.n - 4;
	FB(&m, 0xbe, 0, 0, 0, 0);                        /* mov esi,H2: its absolute address (non-PIE) */
	sm_imm = m.n - 4;
	FB(&m, 0x5d, 0xc3);
	mn = place(&o, &m);
	FB(&a, 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x83, 0xc0, 0x01, 0x5d);          /* A1: ..., pop rbp, jmp B: a tail call */
	fb_jmp(&a, &sa_jmp);
	a1 = place(&o, &a);
	b = small_fn(&o, 7);
	h1 = small_fn(&o, 8);
	h2 = small_fn(&o, 9);
	far_fn = small_fn(&o, 10);                       /* nothing refers to it */
	lib0 = fk_func(&o, 50, 50, &V);
	fk_call_to(&o, mn + sm_call, a1);
	{
		int32_t d = (int32_t)((int64_t)h1 - (int64_t)(mn + sm_lea + 4));
		uint32_t imm = (uint32_t)h2;

		memcpy(o.b + mn + sm_lea, &d, 4);
		memcpy(o.b + mn + sm_imm, &imm, 4);
	}
	fk_call_to(&o, a1 + sa_jmp, b);
	entry_set(&o, e, mn, lib0);
	walk(&o, KGENOME_FNP_LINK_STATIC, e, &s, &st, &fs, 0);
	CK(is_at(&s, a1, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
	CK(is_at(&s, b, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));                /* a tail call is an edge */
	CK(is_at(&s, h1, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));               /* an address taken by lea */
	CK(is_at(&s, h2, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));               /* ... by mov imm */
	CK(is_at(&s, far_fn, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));            /* behind the last reached one: startup code */
	CK(is_at(&s, lib0, KGENOME_FNP_LIB, KGENOME_FNP_R_LIB_START));
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* ---- 4. what the rules cannot do ---------------------------------------------- */

static void t_known_misses(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	uint64_t e, cb, mn, a1, lib0, cold;
	struct fb f = { { 0 }, 0 };
	uint32_t sjc;

	/* a callback only a data table names (const handler_t table[] = { h_add, ... }), first in the program's text */
	fk_init(&o);
	e = entry_stub(&o);
	cb = fk_func(&o, 60, 30, &V);
	{
		struct fb m = { { 0 }, 0 };
		uint32_t s1;

		FB(&m, 0x55, 0x48, 0x89, 0xe5);
		fb_call(&m, &s1);
		FB(&m, 0x5d, 0xc3);
		mn = place(&o, &m);
		a1 = fk_func(&o, 61, 40, &V);
		fk_call_to(&o, mn + s1, a1);
	}
	lib0 = fk_func(&o, 62, 40, &V);
	entry_set(&o, e, mn, lib0);
	walk(&o, KGENOME_FNP_LINK_STATIC, e, &s, &st, &fs, 0);
	KM_CHECK(cls_at(&s, cb) == KGENOME_FNP_AUTHOR,
		 "a function only a data table refers to, before the first function main reaches, is the program's",
		 "DATA_POINTER_ONLY_CALLBACK_AT_THE_EDGE_IS_LIB");
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/* an author cold part (.text.unlikely) is placed before the entry, and the parent jumps to it */
	fk_init(&o);
	f.n = 0;
	FB(&f, 0xbf, 1, 0, 0, 0, 0xf4);                    /* the cold part: ends in hlt, as a call to a noreturn function */
	cold = place(&o, &f);
	e = entry_stub(&o);
	{
		struct fb m = { { 0 }, 0 };
		uint32_t s1;

		FB(&m, 0x55, 0x48, 0x89, 0xe5);
		fb_call(&m, &s1);
		FB(&m, 0x5d, 0xc3);
		mn = place(&o, &m);
		f.n = 0;
		FB(&f, 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x85, 0xff, 0x0f, 0x84, 0, 0, 0, 0);   /* test edi,edi; je cold */
		sjc = f.n - 4;
		FB(&f, 0x83, 0xc0, 0x01, 0x5d, 0xc3);
		a1 = place(&o, &f);
		fk_call_to(&o, mn + s1, a1);
		fk_call_to(&o, a1 + sjc, cold);
	}
	lib0 = fk_func(&o, 62, 40, &V);
	entry_set(&o, e, mn, lib0);
	walk(&o, KGENOME_FNP_LINK_STATIC, e, &s, &st, &fs, 0);
	KM_CHECK(cls_at(&s, cold) == KGENOME_FNP_AUTHOR,
		 "the cold part of a reached function, placed before the entry, is the program's",
		 "AUTHOR_COLD_PART_BEFORE_THE_ENTRY_IS_LIB");
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* A function whose last instruction is a call that does not return has no terminal: its body is read on into the next function. */
static void t_noreturn_tail(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct fb f = { { 0 }, 0 };
	uint32_t site;
	uint64_t fo, flen;

	fk_init(&o);
	FB(&f, 0x55, 0x48, 0x89, 0xe5, 0xbf, 1, 0, 0, 0);
	fb_call(&f, &site);                                /* call __stack_chk_fail / abort: the function ends here */
	fo = o.n;
	fk_raw(&o, f.b, f.n);
	flen = f.n;
	fk_call_to(&o, fo + site, fo);
	pad(&o, 0, 11);
	{
		struct fb g = { { 0 }, 0 };

		FB(&g, 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x83, 0xc0, 0x01, 0x5d, 0xc3);
		fk_raw(&o, g.b, g.n);
	}
	fk_mark(&o, 0, o.n);                               /* one extent, as an entry walk makes it */
	walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
	KM_CHECK(s.n >= 1 && s.fn[0].body_len == flen,
		 "a function that ends in a call that does not return keeps its own body when the extent runs on",
		 "NORETURN_TAIL_READS_INTO_THE_NEXT_FUNCTION");
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* ---- 5. code the function set did not enter ---------------------------------- */

/* A loop: push rbp; mov rbp,rsp; xor eax,eax; <padding>; L: add eax,1; cmp eax,n; jl L; pop rbp; ret - with an optional ENDBR first. */
static uint64_t loop_fn(struct fk_obj *o, int endbr, const uint8_t *padb, uint32_t padn, uint8_t n)
{
	struct fb f = { { 0 }, 0 };
	uint32_t l;
	int8_t d;

	if (endbr)
		FB(&f, 0xf3, 0x0f, 0x1e, 0xfa);
	FB(&f, 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0);
	if (padn)
		fb_raw(&f, padb, padn);
	l = f.n;
	FB(&f, 0x83, 0xc0, 0x01, 0x83, 0xf8);
	f.b[f.n++] = n;
	d = (int8_t)((int32_t)l - (int32_t)(f.n + 2));
	f.b[f.n++] = 0x7c;
	f.b[f.n++] = (uint8_t)d;
	FB(&f, 0x5d, 0xc3);
	return place(o, &f);
}

static uint64_t fp_of(struct fk_obj *o, uint64_t fn_idx_off, struct kgenome_fnprint_fn *out)
{
	static struct kgenome_fnprint_set s;
	static struct kgenome_fnprint_stat st;
	static struct kgenome_func_set fs;

	kgenome_fnprint_set_free(&s, NULL);
	walk(o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
	{
		const struct kgenome_fnprint_fn *f = at_off(&s, fn_idx_off);

		if (out && f)
			*out = *f;                       /* a copy: the set is freed by the next call */
		return f ? f->fp : 0;
	}
}

/* The same function with and without -fcf-protection's ENDBR, and with another alignment pad before the loop head. */
static void t_endbr_and_alignment_pad(void)
{
	static const uint8_t nopl4[] = { 0x0f, 0x1f, 0x40, 0x00 };
	static const uint8_t nopw6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	struct fk_obj o1, o2, o3, o4;
	struct kgenome_fnprint_fn f1, f2, f3, f4;
	struct kgenome_fnprint_req ra, rb;
	struct kgenome_fnprint_stat sa, sb;
	struct kgenome_func_set fa, fb2;
	uint64_t p1, p2, p3, p4, fp1, fp2, fp3, fp4, w1, w2, w3;

	fk_init(&o1); fk_init(&o2); fk_init(&o3); fk_init(&o4);
	p1 = loop_fn(&o1, 0, NULL, 0, 10);
	p2 = loop_fn(&o2, 1, nopl4, 4, 10);                /* ENDBR, a 4-byte pad */
	p3 = loop_fn(&o3, 1, nopw6, 6, 10);                /* ENDBR, a 6-byte pad */
	p4 = loop_fn(&o4, 0, NULL, 0, 11);                 /* a different constant: a different function */
	memset(&f1, 0, sizeof f1); f2 = f3 = f4 = f1;
	fp1 = fp_of(&o1, p1, &f1); w1 = f1.fw;
	fp2 = fp_of(&o2, p2, &f2); w2 = f2.fw;
	fp3 = fp_of(&o3, p3, &f3); w3 = f3.fw;
	fp4 = fp_of(&o4, p4, &f4);
	CK(fp1 && fp1 == fp2 && fp1 == fp3);               /* the landing pad and the pad are not content */
	CK(w1 == w2 && w1 == w3);
	CK(fp4 != fp1);
	CK(f2.n_insn == f1.n_insn && f3.n_insn == f1.n_insn && f1.n_insn > 0);                 /* neither is counted as an instruction */
	/* and the exact comparison, token by token, says the same */
	fk_req(&ra, &o1, KGENOME_FNP_LINK_UNKNOWN, &sa, &fa);
	fk_req(&rb, &o3, KGENOME_FNP_LINK_UNKNOWN, &sb, &fb2);
	{
		struct kgenome_fnprint_set s1, s3;

		kgenome_fnprint_collect(&ra, &s1);
		kgenome_fnprint_collect(&rb, &s3);
		CK(kgenome_fnprint_equal(&ra, &s1.fn[0], &rb, &s3.fn[0]));
		kgenome_fnprint_set_free(&s1, NULL);
		kgenome_fnprint_set_free(&s3, NULL);
	}
	fk_free(&o1); fk_free(&o2); fk_free(&o3); fk_free(&o4);
}

/* Two functions in one extent, an alignment pad between them: both are read, the second as a piece of its own. */
static void t_tail_pieces(void)
{
	static const uint8_t nopw6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	struct fk_obj o, ref;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	uint64_t a, b, bref, ext_start;
	int kind;

	for (kind = 0; kind < 4; kind++) {
		fk_init(&o);
		fk_init(&ref);
		ext_start = o.n;
		a = loop_fn(&o, 0, NULL, 0, 10);
		pad(&o, kind, kind == 2 ? 2 : 5);               /* nops, int3, multi-byte nops, zeros */
		b = o.n;
		loop_fn(&o, 0, nopw6, 6, 20);
		o.nf = 0;                                       /* forget the two marks ... */
		fk_mark(&o, ext_start, o.n - ext_start);        /* ... and give one extent: what an entry walk hands over */
		small_fn(&o, 99);                               /* the next entry: the extent is not the last */
		walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
		CK(s.n == 3 && st.n_split == 1 && st.n_funcs == 2 && st.n_visited == 2);
		CK(s.fn[0].off == a && !(s.fn[0].reason & KGENOME_FNP_R_SPLIT));
		CK(s.fn[1].off == b && (s.fn[1].reason & KGENOME_FNP_R_SPLIT));
		bref = loop_fn(&ref, 0, nopw6, 6, 20);
		CK(fp_of(&ref, bref, NULL) == s.fn[1].fp);        /* the piece is the function it would have been, listed */
		kgenome_fnprint_set_free(&s, NULL);
		(void)fp_of;
		fk_free(&o); fk_free(&ref);
	}
	/* the same extent from a symbol table (the size is the producer's, the bytes after the first return are the function's): nothing is cut */
	{
		struct kgenome_fnprint_req rq;

		fk_init(&o);
		ext_start = o.n;
		loop_fn(&o, 0, NULL, 0, 10);
		pad(&o, 0, 5);
		loop_fn(&o, 0, NULL, 0, 20);
		o.nf = 0;
		fk_mark(&o, ext_start, o.n - ext_start);
		fk_req(&rq, &o, KGENOME_FNP_LINK_UNKNOWN, &st, &fs);
		rq.extents = KGENOME_FNP_EXT_SIZED;
		kgenome_fnprint_collect(&rq, &s);
		CK(s.n == 1 && st.n_split == 0);
		kgenome_fnprint_set_free(&s, NULL);
		rq.extents = KGENOME_FNP_EXT_UNKNOWN;
		kgenome_fnprint_collect(&rq, &s);
		CK(s.n == 1 && st.n_split == 0);                    /* not told: taken as they are */
		kgenome_fnprint_set_free(&s, NULL);
		fk_free(&o);
	}
	/* the same extent with the rule off: one function, the second hidden in its tail */
	fk_init(&o);
	ext_start = o.n;
	loop_fn(&o, 0, NULL, 0, 10);
	pad(&o, 0, 5);
	loop_fn(&o, 0, NULL, 0, 20);
	o.nf = 0;
	fk_mark(&o, ext_start, o.n - ext_start);
	small_fn(&o, 99);
	walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, KGENOME_FNP_OFF_SPLIT_TAILS);
	CK(s.n == 2 && st.n_split == 0 && s.fn[0].body_len < s.fn[0].len);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/*
	 * the LAST extent of the set is not cut: nothing bounds it but the end of the code, and what follows its first return may be
	 * data in the same segment - here the relocation entries of a static-pie (24 bytes each: offset, R_X86_64_RELATIVE, addend),
	 * which decode as 80-odd plausible instructions.
	 */
	fk_init(&o);
	ext_start = o.n;
	loop_fn(&o, 0, NULL, 0, 10);
	{
		uint8_t rela[24 * 8];
		uint32_t r;

		for (r = 0; r < 8; r++) {
			uint64_t off = 0x4c0000 + r * 8, info = 8, add = 0x401000 + r * 0x40;

			memcpy(rela + r * 24, &off, 8);
			memcpy(rela + r * 24 + 8, &info, 8);
			memcpy(rela + r * 24 + 16, &add, 8);
		}
		fk_raw(&o, rela, sizeof rela);
	}
	o.nf = 0;
	fk_mark(&o, ext_start, o.n - ext_start);
	walk(&o, KGENOME_FNP_LINK_DYNAMIC, KGENOME_BROKEN, &s, &st, &fs, 0);
	CK(s.n == 1 && st.n_split == 0);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
	/* with the end of the code section known, the last extent is cut there: the second function is found, the data is not read */
	{
		struct kgenome_fnprint_req rq;
		uint64_t code_end, b2;
		uint8_t junk[96];

		fk_init(&o);
		ext_start = o.n;
		loop_fn(&o, 0, NULL, 0, 10);
		pad(&o, 0, 5);
		b2 = loop_fn(&o, 0, NULL, 0, 20);
		code_end = o.n;
		memset(junk, 0x01, sizeof junk);
		fk_raw(&o, junk, sizeof junk);
		o.nf = 0;
		fk_mark(&o, ext_start, o.n - ext_start);
		fk_req(&rq, &o, KGENOME_FNP_LINK_UNKNOWN, &st, &fs);
		rq.extents = KGENOME_FNP_EXT_ENTRY_WALK;
		rq.code_end = code_end;
		kgenome_fnprint_collect(&rq, &s);
		CK(s.n == 2 && st.n_split == 1 && s.fn[1].off == b2 && s.fn[1].off + s.fn[1].len == code_end);
		kgenome_fnprint_set_free(&s, NULL);
		fk_free(&o);
	}
	/* ... and the same data followed by another entry is between two entries: read as what the walk found, a piece */
	fk_init(&o);
	ext_start = o.n;
	loop_fn(&o, 0, NULL, 0, 10);
	{
		uint8_t rela[24 * 8];
		uint32_t r;

		for (r = 0; r < 8; r++) {
			uint64_t off = 0x4c0000 + r * 8, info = 8, add = 0x401000 + r * 0x40;

			memcpy(rela + r * 24, &off, 8);
			memcpy(rela + r * 24 + 8, &info, 8);
			memcpy(rela + r * 24 + 16, &add, 8);
		}
		fk_raw(&o, rela, sizeof rela);
	}
	o.nf = 0;
	fk_mark(&o, ext_start, o.n - ext_start);
	small_fn(&o, 98);
	walk(&o, KGENOME_FNP_LINK_DYNAMIC, KGENOME_BROKEN, &s, &st, &fs, 0);
	KM_CHECK(st.n_split == 0,
		 "data between the last return of an extent and the next entry (relocation entries in the code segment) is not read as a function",
		 "DATA_BETWEEN_ENTRIES_DECODES_AS_CODE");
	/* but it weighs nothing and is not the program's: a quarter of what it decodes to is `add [rax],al` */
	CK(s.n >= 3 && (s.fn[1].reason & KGENOME_FNP_R_ZEROES) && s.fn[1].weight == 0 && s.fn[1].cls != KGENOME_FNP_AUTHOR);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/* a forward branch past a return keeps the function whole: `test edi,edi; je L2; ret; L2: xor eax,eax; ret` is one function */
	fk_init(&o);
	{
		struct fb f = { { 0 }, 0 };

		FB(&f, 0x85, 0xff, 0x74, 0x01, 0xc3, 0x31, 0xc0, 0xc3);
		place(&o, &f);
	}
	walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
	CK(s.n == 1 && st.n_split == 0 && s.fn[0].body_len == 8);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* A switch through a jump table: the blocks behind `jmp *%rax` are the same function and not new ones. */
static void t_jump_table(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct fb f = { { 0 }, 0 };
	uint64_t sw, next;

	/* with the bounds check: cmp edi,3; ja DEF; lea rdx,[rip+tab]; movsxd rax,[rdx+rdi*4]; add rax,rdx; jmp rax;
	 * case blocks; DEF: xor eax,eax; ret */
	fk_init(&o);
	FB(&f, 0x83, 0xff, 0x03, 0x77, 0x00);              /* ja DEF (patched below) */
	FB(&f, 0x48, 0x8d, 0x15, 0, 0, 0, 0);              /* lea rdx,[rip+0] */
	FB(&f, 0x48, 0x63, 0x04, 0xba, 0x48, 0x01, 0xd0, 0xff, 0xe0);
	FB(&f, 0xb8, 10, 0, 0, 0, 0xc3, 0xb8, 21, 0, 0, 0, 0xc3, 0xb8, 33, 0, 0, 0, 0xc3);
	f.b[4] = (uint8_t)(f.n - 5);
	FB(&f, 0x31, 0xc0, 0xc3);
	sw = place(&o, &f);
	walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
	CK(s.n == 1 && st.n_split == 0 && s.fn[0].body_len == s.fn[0].len);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/* without it (the cases cover every value): jmp rax is the first terminal, the blocks behind it are not cut out */
	fk_init(&o);
	f.n = 0;
	FB(&f, 0x48, 0x8d, 0x15, 0, 0, 0, 0, 0x48, 0x63, 0x04, 0xba, 0x48, 0x01, 0xd0, 0xff, 0xe0);
	FB(&f, 0xb8, 10, 0, 0, 0, 0xc3, 0xb8, 21, 0, 0, 0, 0xc3, 0xb8, 33, 0, 0, 0, 0xc3);
	sw = place(&o, &f);
	walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
	CK(s.n == 1 && st.n_split == 0);                   /* no function is invented out of a case block */
	CK(s.fn[0].body_len < s.fn[0].len);                /* ... the body is read to the jump, the blocks are the tail */
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/* and a real function behind the same blocks, in the same extent, is not found: the cost of that rule */
	fk_init(&o);
	f.n = 0;
	FB(&f, 0x48, 0x8d, 0x15, 0, 0, 0, 0, 0x48, 0x63, 0x04, 0xba, 0x48, 0x01, 0xd0, 0xff, 0xe0);
	FB(&f, 0xb8, 10, 0, 0, 0, 0xc3, 0xb8, 21, 0, 0, 0, 0xc3);
	place(&o, &f);
	o.nf = 0;
	pad(&o, 0, 6);
	next = o.n;
	loop_fn(&o, 0, NULL, 0, 10);
	o.nf = 0;
	fk_mark(&o, 0, o.n);
	small_fn(&o, 97);
	walk(&o, KGENOME_FNP_LINK_UNKNOWN, KGENOME_BROKEN, &s, &st, &fs, 0);
	KM_CHECK(at_off(&s, next) != NULL,
		 "a function behind the blocks of a switch with no bounds check, in the same extent, is found",
		 "INDIRECT_JMP_BLOCKS_HIDE_THE_NEXT_FUNCTION");
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
	(void)sw;
}

/* main inside an extent: the entry stub names it, so it is an entry whether or not a call enters it. */
static void t_main_cut(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct fb x = { { 0 }, 0 };
	uint64_t e, xo, mn, lib0;
	uint32_t site;

	fk_init(&o);
	e = entry_stub(&o);
	xo = o.n;
	FB(&x, 0x55, 0x48, 0x89, 0xe5, 0xbf, 1, 0, 0, 0);
	fb_call(&x, &site);                                /* a function that ends in a call that does not return */
	fk_raw(&o, x.b, x.n);
	pad(&o, 0, 11);
	mn = o.n;
	{
		struct fb m = { { 0 }, 0 };

		FB(&m, 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x83, 0xc0, 0x03, 0x5d, 0xc3);
		fk_raw(&o, m.b, m.n);
	}
	fk_mark(&o, xo, o.n - xo);                         /* ONE extent: the walk's set has no entry at main */
	fk_call_to(&o, xo + site, xo);
	lib0 = fk_func(&o, 70, 40, &V);
	entry_set(&o, e, mn, lib0);
	walk(&o, KGENOME_FNP_LINK_STATIC, e, &s, &st, &fs, 0);
	CK(st.main_off == mn && st.n_split == 1);
	CK(is_at(&s, mn, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_MAIN | KGENOME_FNP_R_SPLIT));
	CK(cls_at(&s, xo) == KGENOME_FNP_LIB);                                 /* what lies before main in the extent: nothing reaches it */
	kgenome_fnprint_set_free(&s, NULL);
	/* with the cut off, main is inside a function that starts before it and nothing is the program's */
	walk(&o, KGENOME_FNP_LINK_STATIC, e, &s, &st, &fs, KGENOME_FNP_OFF_SPLIT_MAIN);
	CK(st.n_split == 0 && !at_off(&s, mn) && st.n_author == 0);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* ---- 6. thunks, PLT, ifunc resolvers ------------------------------------------ */

static void t_thunks(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct fb f = { { 0 }, 0 };
	uint64_t jmpstub, accessor, e, mn, lib0, resolver, getpc;
	uint32_t site;

	/* x86-64: `jmp rel32` is a thunk; `lea eax,[rdi+rsi]; ret` is a leaf, an accessor or a handler, and not */
	fk_init(&o);
	FB(&f, 0xe9, 0, 0, 0, 0);
	jmpstub = place(&o, &f);
	f.n = 0;
	FB(&f, 0x8d, 0x04, 0x37, 0xc3);
	accessor = place(&o, &f);
	walk(&o, KGENOME_FNP_LINK_DYNAMIC, KGENOME_BROKEN, &s, &st, &fs, 0);
	CK(is_at(&s, jmpstub, KGENOME_FNP_LIB, KGENOME_FNP_R_THUNK));
	CK(cls_at(&s, accessor) == KGENOME_FNP_AUTHOR && !(0 & KGENOME_FNP_R_THUNK));
	kgenome_fnprint_set_free(&s, NULL);
	walk(&o, KGENOME_FNP_LINK_DYNAMIC, KGENOME_BROKEN, &s, &st, &fs, KGENOME_FNP_OFF_THUNK_RET);
	CK(is_at(&s, accessor, KGENOME_FNP_LIB, KGENOME_FNP_R_THUNK));              /* the pristine rule: a leaf is a thunk */
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);

	/* 32-bit x86: `mov ebx,[esp]; ret` is the get-pc thunk of position-independent code, and stays one */
	fk_init(&o);
	f.n = 0;
	FB(&f, 0x8b, 0x1c, 0x24, 0xc3);
	getpc = place(&o, &f);
	{
		struct kgenome_fnprint_req rq;

		fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
		rq.arch = KGENOME_ARCH_X86;
		kgenome_fnprint_collect(&rq, &s);
		CK(is_at(&s, getpc, KGENOME_FNP_LIB, KGENOME_FNP_R_THUNK));
		kgenome_fnprint_set_free(&s, NULL);
	}
	fk_free(&o);

	/* a static link: an ifunc resolver (lea rax,[rip+impl]; ret) behind the program is startup code, whatever its size */
	fk_init(&o);
	e = entry_stub(&o);
	mn = main_calls(&o, &e, 0);
	f.n = 0;
	FB(&f, 0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3);
	resolver = place(&o, &f);
	lib0 = fk_func(&o, 80, 40, &V);
	entry_set(&o, e, mn, lib0);
	walk(&o, KGENOME_FNP_LINK_STATIC, e, &s, &st, &fs, 0);
	CK(is_at(&s, resolver, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED));
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
	(void)site;
}

/* ---- 7. the region is bounded and says so ------------------------------------- */

static void t_region_bounds(void)
{
	struct slink l;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_req rq;
	struct kgenome_ledger led;
	uint32_t i;
	uint64_t last;

	/* a program of 3000 small functions, each called by main: all reached, none dropped, memory charged and given back */
	{
		struct fk_obj *o = &l.o;
		uint64_t e, mn, lib0, *to = malloc(3000 * sizeof *to);
		struct fb m = { { 0 }, 0 };
		uint32_t *sites = malloc(3000 * sizeof *sites);
		struct fb big;
		uint8_t *bb = malloc(3000 * 5 + 16);

		(void)m; (void)big;
		fk_init(o);
		e = entry_stub(o);
		mn = o->n;
		bb[0] = 0x55;
		for (i = 0; i < 3000; i++) {
			bb[1 + i * 5] = 0xe8; memset(bb + 2 + i * 5, 0, 4);
			sites[i] = (uint32_t)(1 + i * 5 + 1);
		}
		bb[1 + 3000 * 5] = 0x5d; bb[2 + 3000 * 5] = 0xc3;
		fk_raw(o, bb, 3 + 3000 * 5);
		fk_mark(o, mn, o->n - mn);
		for (i = 0; i < 3000; i++) {
			to[i] = small_fn(o, (uint8_t)i);
			fk_call_to(o, mn + sites[i], to[i]);
		}
		last = to[2999];
		lib0 = fk_func(o, 90, 40, &V);
		entry_set(o, e, mn, lib0);
		kgenome_ledger_init(&led, 0);
		fk_req(&rq, o, KGENOME_FNP_LINK_STATIC, &st, &fs);
		rq.entry_off = e;
		rq.led = &led;
		kgenome_fnprint_collect(&rq, &s);
		CK(is_at(&s, last, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED));
		CK(st.n_reached == 3000 && st.n_region_over == 0 && st.region_peak >= 3000);
		CK(st.status == KGENOME_OK);
		kgenome_fnprint_set_free(&s, &led);
		CK(led.used == 0);                                       /* the region and the position scratch were given back */
		CK(led.peak > 3000 * 80);                                /* ... and were charged while held */

		/* an allowance that cannot hold the region: the functions are decided by the layout rule, and it is said */
		kgenome_ledger_init(&led, 60000);
		rq.visit = NULL;
		kgenome_fnprint_walk(&rq);
		CK(st.n_region_over > 0 && st.status != KGENOME_OK);
		CK(st.n_visited == st.n_funcs && led.used == 0);

		/* the cost bound of the region itself (no ledger): the same, and the first 100 are decided with the rest */
		rq.led = NULL;
		rq.opt.region_max = 100;
		kgenome_fnprint_collect(&rq, &s);
		CK(st.n_region_over > 0 && st.status == KGENOME_TRUNCATED && st.region_peak <= 100);
		CK(s.n == st.n_visited + st.n_split && st.n_visited == st.n_funcs);
		kgenome_fnprint_set_free(&s, NULL);
		free(to); free(sites); free(bb);
		fk_free(o);
	}
}

int main(void)
{
	t_static_layout();
	t_static_pie_entry();
	t_dynamic();
	t_edges();
	t_known_misses();
	t_noreturn_tail();
	t_endbr_and_alignment_pad();
	t_tail_pieces();
	t_jump_table();
	t_main_cut();
	t_thunks();
	t_region_bounds();
	printf("fnprint_gcc: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
