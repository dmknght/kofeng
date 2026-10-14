/*
 * fnprint_adv_names - an author who patches the file cannot blind the evidence.
 *
 * THE RULE UNDER TEST. Code leaves the evidence only on grounds the author cannot change without
 * changing the function's own bytes. A symbol's name, a marker string, the link order, the shape of
 * the entry stub, a size, a raw kernel entry and the presence of symbols are all things the author
 * controls; a function is "LIB" (and weighs nothing as author code) in the default rules only when its
 * fingerprint or most of its windows are in a table built from library BYTES. Everything else is advice:
 * f->advice says what the old rule would have said, the function stays UNKNOWN, kept, and counted
 * (stat.n_advised).
 *
 * EVERY CASE BELOW is hand-built in memory and runs twice: in the default rules, where the author code
 * must still be credited, and with KGENOME_FNP_OPT_LEGACY_EXCLUDE, where the same patch DOES hide it.
 * The second half is what makes the first one a test: a case whose legacy run did not hide the code
 * would prove nothing. The cases that are not fixed are KM_CHECKs that name the exploit.
 */
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

static struct fk_var V0 = { 0x1000, 0x2000, 0x12345678u };

#define N_AUTH 3
#define N_LIB  5

struct prog {
	struct fk_obj o;
	uint64_t entry, main_off, auth[N_AUTH], lib[N_LIB];
	uint32_t n_funcs;
};

/* The name an overriding patch gives: 0 none, 1 "library", 2 "author's", per function index. */
struct names {
	int v[64];
	int use;
};

static int name_cb(void *u, uint32_t i)
{
	const struct names *n = (const struct names *)u;

	return n->use && i < 64 ? n->v[i] : 0;
}

/* The layout: entry, main (calls the author's), the author's, then the library; or the library first. */
static void build(struct prog *p, int author_after_lib)
{
	uint64_t site[N_AUTH];
	uint32_t i;

	fk_init(&p->o);
	p->entry = fk_entry(&p->o, 0);
	p->main_off = fk_stub(&p->o, N_AUTH, site);
	if (!author_after_lib)
		for (i = 0; i < N_AUTH; i++)
			p->auth[i] = fk_func(&p->o, 10 + i, 40, &V0);
	for (i = 0; i < N_LIB; i++)
		p->lib[i] = i < 3 ? fk_wrapper(&p->o, 1 + i) : fk_func(&p->o, 500 + i, 40, &V0);
	if (author_after_lib)
		for (i = 0; i < N_AUTH; i++)
			p->auth[i] = fk_func(&p->o, 10 + i, 40, &V0);
	for (i = 0; i < N_AUTH; i++)
		fk_call_to(&p->o, site[i], p->auth[i]);
	{
		int32_t d = (int32_t)((int64_t)p->main_off - (int64_t)(p->entry + 7));

		memcpy(p->o.b + p->entry + 3, &d, 4);
	}
	p->n_funcs = p->o.nf;
}

struct res {
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
};

static void run(struct prog *p, const struct names *nm, uint32_t flags, struct res *r)
{
	struct kgenome_fnprint_req rq;
	struct kgenome_func_set fs;

	fk_req(&rq, &p->o, KGENOME_FNP_LINK_STATIC, &r->st, &fs);
	rq.entry_off = p->entry;
	rq.opt.flags = flags;
	if (nm) {
		rq.hint.name = name_cb;
		rq.hint.name_user = (void *)(uintptr_t)nm;
	}
	kgenome_fnprint_collect(&rq, &r->s);
}

/* The record at `off`; a zeroed one (class UNKNOWN, no weight) when the walk did not emit one, so a check on it fails and does not crash. */
static const struct kgenome_fnprint_fn *at(const struct res *r, uint64_t off)
{
	static const struct kgenome_fnprint_fn none;
	uint32_t i;

	for (i = 0; i < r->s.n; i++)
		if (r->s.fn[i].off == off)
			return &r->s.fn[i];
	CK(0 && "a record for the function");
	return &none;
}

/* Is the function still evidence: not LIB, and it weighs something. */
static int kept(const struct res *r, uint64_t off)
{
	const struct kgenome_fnprint_fn *f = at(r, off);

	return f->cls != KGENOME_FNP_LIB && f->weight > 0;
}

static int all_author_kept(const struct prog *p, const struct res *r)
{
	uint32_t i;

	for (i = 0; i < N_AUTH; i++)
		if (!kept(r, p->auth[i]))
			return 0;
	return 1;
}

static int same_result(const struct res *a, const struct res *b)
{
	uint32_t i;

	if (a->s.n != b->s.n)
		return 0;
	for (i = 0; i < a->s.n; i++)
		if (a->s.fn[i].cls != b->s.fn[i].cls || a->s.fn[i].weight != b->s.fn[i].weight ||
		    a->s.fn[i].fp != b->s.fn[i].fp)
			return 0;
	return 1;
}

static void done(struct res *r)
{
	kgenome_fnprint_set_free(&r->s, NULL);
}

/* The base line: the program as the compiler laid it out. */
static void t_baseline(void)
{
	struct prog p;
	struct res r;
	uint32_t i;

	build(&p, 0);
	run(&p, NULL, 0, &r);
	CK(all_author_kept(&p, &r));
	CK(at(&r, p.main_off)->cls == KGENOME_FNP_AUTHOR);
	for (i = 0; i < N_LIB; i++) {
		const struct kgenome_fnprint_fn *f = at(&r, p.lib[i]);

		/* the layout says library: advice, and the function is kept and counted */
		CK(f->advice == KGENOME_FNP_LIB && f->cls == KGENOME_FNP_UNKNOWN);
	}
	CK(r.st.n_advised >= N_LIB);
	done(&r);
	fk_free(&p.o);
}

/* 1. Rename the author's functions to reserved and libc names. */
static void t_rename_author_to_library_names(void)
{
	struct prog p;
	struct res base, def, leg;
	struct names nm;
	uint32_t i;

	build(&p, 0);
	memset(&nm, 0, sizeof nm);
	nm.use = 1;
	for (i = 0; i < p.n_funcs; i++)
		nm.v[i] = 1;                       /* every function is called "__libc_..." */
	run(&p, NULL, 0, &base);
	run(&p, &nm, 0, &def);
	run(&p, &nm, KGENOME_FNP_OPT_LEGACY_EXCLUDE, &leg);
	CK(same_result(&base, &def));              /* the default does not read the name */
	CK(all_author_kept(&p, &def));
	CK(!all_author_kept(&p, &leg) && !kept(&leg, p.auth[0]));   /* the exploit: the legacy rule hides it */
	done(&base); done(&def); done(&leg);
	fk_free(&p.o);
}

/* 2. Rename libc's functions to author-like names: no forged credit. */
static void t_rename_library_to_author_names(void)
{
	struct prog p;
	struct res base, def, leg;
	struct names nm;
	uint32_t i;

	build(&p, 0);
	memset(&nm, 0, sizeof nm);
	nm.use = 1;
	for (i = 0; i < p.n_funcs; i++)
		nm.v[i] = 2;
	run(&p, NULL, 0, &base);
	run(&p, &nm, 0, &def);
	run(&p, &nm, KGENOME_FNP_OPT_LEGACY_EXCLUDE, &leg);
	CK(same_result(&base, &def));
	CK(at(&def, p.lib[3])->cls != KGENOME_FNP_AUTHOR);                  /* not credited as author code by its name */
	CK(at(&leg, p.lib[3])->cls == KGENOME_FNP_AUTHOR);                   /* the legacy rule believed the name */
	done(&base); done(&def); done(&leg);
	fk_free(&p.o);
}

/* 3. Strip, mix, invert: the result is the same whatever the names say. */
static void t_names_are_irrelevant(void)
{
	struct prog p;
	struct res base, other;
	struct names nm;
	uint32_t i, mode;

	build(&p, 0);
	run(&p, NULL, 0, &base);
	for (mode = 0; mode < 4; mode++) {
		memset(&nm, 0, sizeof nm);
		nm.use = 1;
		for (i = 0; i < p.n_funcs; i++)
			nm.v[i] = mode == 0 ? 0 : mode == 1 ? 1 : mode == 2 ? 2 : (int)(i % 3u);
		run(&p, &nm, 0, &other);
		CK(same_result(&base, &other));
		done(&other);
	}
	done(&base);
	fk_free(&p.o);
}

/* 4. Reorder: the author's code after the library. */
static void t_author_after_library(void)
{
	struct prog p;
	struct res def, leg;

	build(&p, 1);
	run(&p, NULL, 0, &def);
	run(&p, NULL, KGENOME_FNP_OPT_LEGACY_EXCLUDE, &leg);
	CK(all_author_kept(&p, &def));
	CK(!kept(&leg, p.auth[1]));                /* the legacy frontier cut it */
	done(&def); done(&leg);
	fk_free(&p.o);
}

/* The author's function with a raw kernel entry inside: the old wrapper rule called it library. */
static uint64_t syscall_fn(struct fk_obj *o, uint32_t seed)
{
	uint8_t code[2048];
	uint64_t at = o->n;
	uint32_t n = fk_code(code, seed, 30, &V0);

	fk_raw(o, code, n - 2);
	fk_raw(o, "\x0f\x05", 2);
	fk_raw(o, code + n - 2, 2);
	fk_mark(o, at, o->n - at);
	return at;
}

/* 5. Put a syscall in every author function: the wrapper rule. */
static void t_syscall_in_author_code(void)
{
	struct prog p;
	struct res def, leg;
	uint64_t site[N_AUTH];
	uint32_t i;

	fk_init(&p.o);
	p.entry = fk_entry(&p.o, 0);
	p.main_off = fk_stub(&p.o, N_AUTH, site);
	for (i = 0; i < N_AUTH; i++)
		p.auth[i] = syscall_fn(&p.o, 20 + i);
	for (i = 0; i < 3; i++)
		fk_wrapper(&p.o, 1 + i);
	fk_func(&p.o, 900, 40, &V0);
	for (i = 0; i < N_AUTH; i++)
		fk_call_to(&p.o, site[i], p.auth[i]);
	{
		int32_t d = (int32_t)((int64_t)p.main_off - (int64_t)(p.entry + 7));

		memcpy(p.o.b + p.entry + 3, &d, 4);
	}
	run(&p, NULL, 0, &def);
	run(&p, NULL, KGENOME_FNP_OPT_LEGACY_EXCLUDE, &leg);
	CK(all_author_kept(&p, &def));
	CK(at(&leg, p.auth[0])->cls == KGENOME_FNP_LIB && at(&leg, p.auth[0])->weight == 0);
	done(&def); done(&leg);
	fk_free(&p.o);
}

/* 6. A custom entry stub (no main handed to a runtime): everything is UNKNOWN and kept. */
static void t_no_entry_stub(void)
{
	struct prog p;
	struct res def;
	struct kgenome_fnprint_req rq;
	struct kgenome_func_set fs;
	uint32_t i;

	build(&p, 0);
	fk_req(&rq, &p.o, KGENOME_FNP_LINK_STATIC, &def.st, &fs);
	rq.entry_off = KGENOME_BROKEN;
	kgenome_fnprint_collect(&rq, &def.s);
	for (i = 0; i < N_AUTH; i++)
		CK(kept(&def, p.auth[i]));
	CK(def.st.main_off == KGENOME_BROKEN);
	done(&def);
	fk_free(&p.o);
}

/* 7. A forged entry stub that names a library function as main: the author's code is still kept. */
static void t_forged_entry_stub(void)
{
	struct prog p;
	struct res def;
	struct kgenome_fnprint_req rq;
	struct kgenome_func_set fs;
	int32_t d;
	uint32_t i;

	build(&p, 0);
	d = (int32_t)((int64_t)p.lib[4] - (int64_t)(p.entry + 7));
	memcpy(p.o.b + p.entry + 3, &d, 4);                 /* main is now a libc-looking function */
	fk_req(&rq, &p.o, KGENOME_FNP_LINK_STATIC, &def.st, &fs);
	rq.entry_off = p.entry;
	kgenome_fnprint_collect(&rq, &def.s);
	for (i = 0; i < N_AUTH; i++)
		CK(kept(&def, p.auth[i]));
	done(&def);
	fk_free(&p.o);
}

/* 8. The author's code placed BEFORE the entry stub (the legacy rule: startup groups of the libraries come first). */
static void t_author_before_entry(void)
{
	struct prog p;
	struct res def, leg;
	uint64_t site[N_AUTH];
	uint32_t i;

	fk_init(&p.o);
	for (i = 0; i < N_AUTH; i++)
		p.auth[i] = fk_func(&p.o, 40 + i, 40, &V0);
	p.entry = fk_entry(&p.o, 0);
	p.main_off = fk_stub(&p.o, N_AUTH, site);
	for (i = 0; i < 3; i++)
		fk_wrapper(&p.o, 1 + i);
	for (i = 0; i < N_AUTH; i++)
		fk_call_to(&p.o, site[i], p.auth[i]);
	{
		int32_t d = (int32_t)((int64_t)p.main_off - (int64_t)(p.entry + 7));

		memcpy(p.o.b + p.entry + 3, &d, 4);
	}
	run(&p, NULL, 0, &def);
	run(&p, NULL, KGENOME_FNP_OPT_LEGACY_EXCLUDE, &leg);
	CK(all_author_kept(&p, &def));
	CK(!kept(&leg, p.auth[0]));
	done(&def); done(&leg);
	fk_free(&p.o);
}

/* 9. Tiny functions. A function of under six instructions weighs nothing: the author splits his code. */
static void t_tiny_functions(void)
{
	struct prog p;
	struct res def;
	struct kgenome_fnprint_req rq;
	struct kgenome_func_set fs;
	uint64_t w = 0;
	uint32_t i;

	fk_init(&p.o);
	p.entry = fk_entry(&p.o, 0);
	p.main_off = fk_stub(&p.o, 1, p.auth);
	for (i = 0; i < 40; i++)
		fk_func(&p.o, 3000 + i, 0, &V0);            /* 40 functions of 4 instructions */
	fk_call_to(&p.o, p.auth[0], p.o.v[2].off);
	{
		int32_t d = (int32_t)((int64_t)p.main_off - (int64_t)(p.entry + 7));

		memcpy(p.o.b + p.entry + 3, &d, 4);
	}
	fk_req(&rq, &p.o, KGENOME_FNP_LINK_STATIC, &def.st, &fs);
	rq.entry_off = p.entry;
	kgenome_fnprint_collect(&rq, &def.s);
	for (i = 2; i < def.s.n; i++)
		w += def.s.fn[i].weight;
	/* none of them is LIB: they are kept. But their weights add up to nothing. */
	for (i = 2; i < def.s.n; i++)
		CK(def.s.fn[i].cls != KGENOME_FNP_LIB);
	KM_CHECK(w > 0, "author code split into functions of under six instructions still weighs something at function level (the window stream is the defence)",
		 "TINY_FUNCTIONS_WEIGH_NOTHING");
	done(&def);
	fk_free(&p.o);
}

/* 10. A callback only a data table names (no direct edge from main): the legacy reachability rule called it library. */
static void t_data_pointer_only(void)
{
	struct prog p;
	struct res def, leg;
	uint64_t site[1], cb, a1;

	fk_init(&p.o);
	p.entry = fk_entry(&p.o, 0);
	cb = fk_func(&p.o, 70, 40, &V0);                    /* between the entry and main: nothing calls it */
	p.main_off = fk_stub(&p.o, 1, site);
	a1 = fk_func(&p.o, 71, 40, &V0);
	fk_wrapper(&p.o, 1); fk_wrapper(&p.o, 2); fk_wrapper(&p.o, 3);
	fk_call_to(&p.o, site[0], a1);
	{
		int32_t d = (int32_t)((int64_t)p.main_off - (int64_t)(p.entry + 7));

		memcpy(p.o.b + p.entry + 3, &d, 4);
	}
	run(&p, NULL, 0, &def);
	run(&p, NULL, KGENOME_FNP_OPT_LEGACY_EXCLUDE, &leg);
	CK(kept(&def, cb) && kept(&def, a1));
	CK(!kept(&leg, cb));                                /* the legacy rule: UNREACHED, LIB */
	done(&def); done(&leg);
	fk_free(&p.o);
}

/* A function body with `n_pad` bytes of `pad` placed after an unconditional jump inside it (dead code the author chose). */
static uint64_t padded_fn(struct fk_obj *o, uint32_t seed, uint32_t nins, uint8_t pad, uint32_t n_pad)
{
	uint8_t code[2048];
	uint64_t at = o->n;
	uint32_t n = fk_code(code, seed, nins, &V0);
	static const uint8_t jmp[2] = { 0xeb, 0 };           /* jmp +N over the padding */
	uint8_t j[2];

	fk_raw(o, code, n - 2);
	j[0] = jmp[0]; j[1] = (uint8_t)n_pad;
	fk_raw(o, j, 2);
	fk_fill(o, pad, n_pad);
	fk_raw(o, code + n - 2, 2);
	fk_mark(o, at, o->n - at);
	return at;
}

/* 11. Dead padding of zero bytes, or of bytes that do not decode, inside the author's function body. */
static void t_padding_in_body(void)
{
	struct prog p;
	struct res def;
	uint64_t site[2], z, u;

	fk_init(&p.o);
	p.entry = fk_entry(&p.o, 0);
	p.main_off = fk_stub(&p.o, 2, site);
	z = padded_fn(&p.o, 80, 30, 0x00, 120);              /* about a third of the instructions are `add [rax],al` */
	u = padded_fn(&p.o, 81, 10, 0x06, 120);              /* push es: not an instruction in 64-bit mode */
	fk_call_to(&p.o, site[0], z);
	fk_call_to(&p.o, site[1], u);
	{
		int32_t d = (int32_t)((int64_t)p.main_off - (int64_t)(p.entry + 7));

		memcpy(p.o.b + p.entry + 3, &d, 4);
	}
	run(&p, NULL, 0, &def);
	CK(at(&def, z)->cls != KGENOME_FNP_LIB && at(&def, u)->cls != KGENOME_FNP_LIB);
	KM_CHECK(kept(&def, z),
		 "an author function with dead zero padding inside its body weighs something at function level (the window stream is the defence)",
		 "ZERO_PADDING_MAKES_FUNCTION_WEIGH_NOTHING");
	KM_CHECK(kept(&def, u),
		 "an author function with dead undecodable bytes inside its body weighs something at function level (the window stream is the defence)",
		 "UNDECODABLE_PADDING_MAKES_FUNCTION_WEIGH_NOTHING");
	done(&def);
	fk_free(&p.o);
}

/* 12. A symbol size that runs past the end of the file: the extent is BAD, weight 0 (the producer of the function set is the author's symbol table). */
static void t_bogus_symbol_extent(void)
{
	struct prog p;
	struct res def;
	struct kgenome_fnprint_req rq;
	struct kgenome_func_set fs;
	uint64_t site[1], a1;

	fk_init(&p.o);
	p.entry = fk_entry(&p.o, 0);
	p.main_off = fk_stub(&p.o, 1, site);
	a1 = fk_func(&p.o, 90, 40, &V0);
	fk_call_to(&p.o, site[0], a1);
	{
		int32_t d = (int32_t)((int64_t)p.main_off - (int64_t)(p.entry + 7));

		memcpy(p.o.b + p.entry + 3, &d, 4);
	}
	fk_req(&rq, &p.o, KGENOME_FNP_LINK_STATIC, &def.st, &fs);
	rq.entry_off = p.entry;
	p.o.v[p.o.nf - 1u].len = 1u << 20;                  /* st_size of the author's function: a megabyte in a file of a few hundred bytes */
	kgenome_fnprint_collect(&rq, &def.s);
	CK(at(&def, a1)->cls != KGENOME_FNP_LIB);
	KM_CHECK(kept(&def, a1),
		 "an author function whose symbol size runs past the end of the file weighs something at function level",
		 "BOGUS_SYMBOL_EXTENT_HIDES_FUNCTION");
	done(&def);
	fk_free(&p.o);
}

int main(void)
{
	t_baseline();
	t_rename_author_to_library_names();
	t_rename_library_to_author_names();
	t_names_are_irrelevant();
	t_author_after_library();
	t_syscall_in_author_code();
	t_no_entry_stub();
	t_forged_entry_stub();
	t_author_before_entry();
	t_tiny_functions();
	t_data_pointer_only();
	t_padding_in_body();
	t_bogus_symbol_extent();
	printf("fnprint_adv_names: %s (known-miss %u)\n", hk_fails ? "FAIL" : "ok", km_known());
	return hk_fails != 0 || km_failed();
}
