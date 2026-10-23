/*
 * lineage_check.h - the lineage tests' comparison: a program of the model is generated, compiled to a target,
 * scanned by the engine with a named set of stages, and the links the scan holds are compared link for link
 * with the ones the oracle says the program has - which producer reaches which argument of which call, MUST
 * or MAY.
 *
 * WHAT A FAILURE PRINTS: the seed, the target, the stages, and the first link that differs, as (child offset,
 * parent offset, role, strength): enough to rebuild the program and read it.
 */
#ifndef KGENOME_TESTS_LINEAGE_CHECK_H
#define KGENOME_TESTS_LINEAGE_CHECK_H

#include <kgenome.h>
#include <phenotype/diag_private.h>

#include "hk.h"
#include "lineage_img.h"

struct lg_link {
	uint32_t child, parent;
	uint8_t role, must;
};

#define LG_MAXLINK 512

struct lg_links {
	struct lg_link v[LG_MAXLINK];
	int n;
};

static LA_UNUSED int lg_link_cmp(const void *a, const void *b)
{
	const struct lg_link *x = a, *y = b;

	if (x->child != y->child)
		return x->child < y->child ? -1 : 1;
	if (x->parent != y->parent)
		return x->parent < y->parent ? -1 : 1;
	if (x->role != y->role)
		return x->role < y->role ? -1 : 1;
	return x->must < y->must ? -1 : x->must > y->must;
}

static const char *lg_import_name(int target, int imp)
{
	return target == LG_T_PE64 || target == LG_T_PE32 ? lg_pe_names[imp] : lg_elf_names[imp];
}

static LA_UNUSED unsigned lg_namespace(int target)
{
	return target == LG_T_PE64 || target == LG_T_PE32 ? KGENOME_NUCLEO_T_PE : KGENOME_NUCLEO_T_ELF;
}

/* The vocabulary the model assumes, asserted before anything is compared: which import is which
 * capability, which argument has a role, which call hands a value on. A change to the vocabulary then fails
 * here, naming what moved, and not as an unexplained difference of links. */
static LA_UNUSED void lg_assert_vocabulary(int target)
{
	static const struct { int api; int produces; unsigned roled; } want[] = {
		{ LG_SOCKET, 1, 0 }, { LG_ACCEPT, 1, 1 }, { LG_MALLOC, 1, 0 }, { LG_CONNECT, 0, 1 }, { LG_LISTEN, 0, 1 },
		{ LG_BIND, 0, 1 }, { LG_READ, 0, 3 }, { LG_WRITE, 0, 3 }
	};
	unsigned i, q;

	for (i = 0; i < sizeof want / sizeof want[0]; i++) {
		const char *nm = lg_import_name(target, want[i].api);
		uint16_t cap = kgenome_nucleo_cap_of_name(lg_namespace(target), nm);
		unsigned roles = 0;

		CK(cap != KGENOME_NUCLEO_NONE);
		CK((kgenome_nucleo_hands_on(cap, nm) != 0) == (want[i].produces != 0));
		for (q = 0; q < 3u; q++)
			if (kgenome_diag_role_of_arg(cap, q) != KGENOME_DIAG_ROLE_NONE)
				roles |= 1u << q;
		CK(roles == want[i].roled);
		CK(lg_api[want[i].api].produces == want[i].produces);
		CK((unsigned)lg_api[want[i].api].roled == want[i].roled);
	}
	CK(kgenome_nucleo_cap_of_name(lg_namespace(target), lg_import_name(target, LG_IMP_COND)) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_name(lg_namespace(target), lg_import_name(target, LG_IMP_VAL)) == KGENOME_NUCLEO_NONE);
}

static LA_UNUSED unsigned lg_cap_of_site(const struct lg_prog *p, int target, int s)
{
	return kgenome_nucleo_cap_of_name(lg_namespace(target), lg_import_name(target, p->site_api[s]));
}

/* The links the oracle says the program has. */
static LA_UNUSED void lg_expected(struct lg_links *out, const struct lg_oracle *o, const struct lg_prog *p,
			const struct lg_cg *c, const struct lg_img *g, int target)
{
	int s, q, pr;

	out->n = 0;
	for (s = 0; s < p->nsite; s++)
		for (q = 0; q < lg_api[p->site_api[s]].nargs; q++) {
			const uint64_t m = o->obs[s][q];
			const uint8_t role = kgenome_diag_role_of_arg((uint16_t)lg_cap_of_site(p, target, s), (unsigned)q);

			if (role == KGENOME_DIAG_ROLE_NONE)
				continue;
			for (pr = 0; pr < p->nsite; pr++) {
				if (!(m >> pr & 1u) || pr == s || out->n >= LG_MAXLINK)
					continue;
				out->v[out->n].child = g->code_off + c->site_off[s];
				out->v[out->n].parent = g->code_off + c->site_off[pr];
				out->v[out->n].role = role;
				out->v[out->n++].must = m == (1ull << pr) && !o->unc[s][q];
			}
		}
	qsort(out->v, (size_t)out->n, sizeof out->v[0], lg_link_cmp);
}

/* Programs not compared: the generator ran out of room, the oracle out of paths, the assembler out of space. */
static long lg_skip[3];
/* Compare as the stripped twins are: no link the engine holds may be one the oracle lacks (for programs the engine is
 * specified to lose links in) - set by the test that wants it. */
static int lg_soft;

struct lg_scan {
	struct kgenome_elf_info ei;
	struct kgenome_pe_info pi;
	struct kgenome_obj obj;
	struct kgenome_diag_scan *s;
	int parsed;
};

/* Scan an image with the symbol route and the named lineage stages. */
static LA_UNUSED int lg_scan(struct lg_scan *sc, const struct lg_img *g, int target, unsigned stages)
{
	struct kgenome_diag_inputs in;
	const int pe = target == LG_T_PE64 || target == LG_T_PE32;

	memset(sc, 0, sizeof *sc);
	if (pe) {
		if (!kgenome_pe_image_parse(kof_buf_make(g->b, g->n), &sc->pi, &sc->obj))
			return 0;
		sc->obj.file_header = &sc->pi;
	} else {
		if (!kgenome_elf_image_parse(kof_buf_make(g->b, g->n), &sc->ei, &sc->obj))
			return 0;
		sc->obj.file_header = &sc->ei;
	}
	memset(&in, 0, sizeof in);
	in.lineage_stages = stages;
	sc->s = kgenome_diag_scan_with_inputs(&sc->obj, g->b, g->n, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE, &in);
	sc->parsed = 1;
	return sc->s != NULL;
}

static LA_UNUSED void lg_actual(struct lg_links *out, const struct lg_scan *sc)
{
	uint32_t i, k, n = kgenome_diag_scan_count(sc->s);

	out->n = 0;
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc->s, i);

		for (k = 0; k < h->n_in && out->n < LG_MAXLINK; k++) {
			if (h->in[k].from >= n)
				continue;
			out->v[out->n].child = (uint32_t)h->at;
			out->v[out->n].parent = (uint32_t)kgenome_diag_scan_at(sc->s, h->in[k].from)->at;
			out->v[out->n].role = h->in[k].role;
			out->v[out->n++].must = h->in[k].how != KGENOME_DIAG_LINK_MAY;
		}
	}
	qsort(out->v, (size_t)out->n, sizeof out->v[0], lg_link_cmp);
}

/*
 * 1 when every link the engine holds is one the oracle has, and no MUST of the engine's is a MAY of the oracle's: the
 * comparison for an object whose functions the engine had to find for itself. A stripped ELF is cut where its calls
 * and jumps say a function begins, and a loop's back edge that follows a jump looks like the thunk a libc starts a
 * function with - so the partition is the engine's to get wrong, a link is found or lost with it, and what must hold is
 * that no link the engine does hold is false.
 */
static LA_UNUSED int lg_subset(const struct lg_links *want, const struct lg_links *dead, const struct lg_links *got, const char *what,
		     int *found)
{
	int i, j, ok = 1;

	for (i = 0; i < got->n; i++) {
		int hit = 0;

		for (j = 0; j < want->n; j++)
			if (want->v[j].child == got->v[i].child && want->v[j].parent == got->v[i].parent &&
			    want->v[j].role == got->v[i].role && (!got->v[i].must || want->v[j].must))
				hit = 1;
		/* Code nothing reaches that the cut made the start of a "function" is read as one, and what it holds is
		 * true of it: a link of such a region, whichever strength, is not a false one. */
		for (j = 0; j < dead->n; j++)
			if (dead->v[j].child == got->v[i].child && dead->v[j].parent == got->v[i].parent &&
			    dead->v[j].role == got->v[i].role)
				hit = 1;
		if (!hit) {
			printf("  %s: a link the oracle does not have: child %x parent %x role %u %s\n", what, got->v[i].child,
			       got->v[i].parent, got->v[i].role, got->v[i].must ? "MUST" : "MAY");
			ok = 0;
		} else {
			(*found)++;
		}
	}
	return ok;
}

/*
 * A NODE HOLDS FOUR INPUTS (kgenome_diag_hit.in), and a fifth distinct link is not kept and says so: KGENOME_TRUNCATED on the
 * scan (diag_hit.c). A consumer a program feeds from more than four producers is therefore compared as the bound says: the
 * engine holds four links of it, all of them the oracle's, and the scan says it cut. The links are written sure ones first, so
 * a MUST of the oracle's that is missing while a MAY is held is a failure. The rest are compared link for link.
 */
static LA_UNUSED int lg_same(const struct lg_links *want, const struct lg_links *got, const char *what);
static LA_UNUSED int lg_compare(struct lg_links *want, struct lg_links *got, enum kgenome_status st, const char *what)
{
	static struct lg_links w2, g2;
	int i, j, ok = 1;

	w2.n = g2.n = 0;
	for (i = 0; i < want->n; i++) {
		int cnt = 0;

		for (j = 0; j < want->n; j++)
			cnt += want->v[j].child == want->v[i].child;
		if (cnt <= 4) {
			w2.v[w2.n++] = want->v[i];
			continue;
		}
		if (i && want->v[i - 1].child == want->v[i].child)
			continue;                       /* the node was judged at its first link */
		{
			int held = 0, musts = 0, musts_held = 0;

			for (j = 0; j < got->n; j++)
				if (got->v[j].child == want->v[i].child) {
					int k, in = 0;

					held++;
					for (k = 0; k < want->n; k++)
						in |= lg_link_cmp(&got->v[j], &want->v[k]) == 0;
					if (!in) {
						printf("  %s: a link the oracle does not have on a node past the bound: child %x parent %x\n",
						       what, got->v[j].child, got->v[j].parent);
						ok = 0;
					}
					musts_held += got->v[j].must;
				}
			for (j = 0; j < want->n; j++)
				musts += want->v[j].child == want->v[i].child && want->v[j].must;
			if (held != 4 || musts_held < (musts < 4 ? musts : 4) || (st == KGENOME_OK && musts > 4)) {   /* a dropped MAY link is not a limit of the reading (diag_hit.c); a dropped proven one is */
				printf("  %s: node %x has %d links, the bound is 4: held %d (%d sure of %d), scan status %d\n", what,
				       want->v[i].child, cnt, held, musts_held, musts, (int)st);
				ok = 0;
			}
		}
	}
	for (i = 0; i < got->n; i++) {
		int cnt = 0;

		for (j = 0; j < want->n; j++)
			cnt += want->v[j].child == got->v[i].child;
		if (cnt <= 4)
			g2.v[g2.n++] = got->v[i];
	}
	return ok & lg_same(&w2, &g2, what);
}

/* 1 when the two sets are one; else prints the first difference. */
static LA_UNUSED int lg_same(const struct lg_links *want, const struct lg_links *got, const char *what)
{
	int i;

	if (want->n == got->n && !memcmp(want->v, got->v, (size_t)want->n * sizeof want->v[0]))
		return 1;
	printf("  %s: want %d links, got %d\n", what, want->n, got->n);
	for (i = 0; i < want->n; i++) {
		int j;

		for (j = 0; j < got->n && lg_link_cmp(&want->v[i], &got->v[j]); j++)
			;
		if (j == got->n) {
			printf("    missing  child %x parent %x role %u %s\n", want->v[i].child, want->v[i].parent,
			       want->v[i].role, want->v[i].must ? "MUST" : "MAY");
			break;
		}
	}
	for (i = 0; i < got->n; i++) {
		int j;

		for (j = 0; j < want->n && lg_link_cmp(&got->v[i], &want->v[j]); j++)
			;
		if (j == want->n) {
			printf("    spurious child %x parent %x role %u %s\n", got->v[i].child, got->v[i].parent,
			       got->v[i].role, got->v[i].must ? "MUST" : "MAY");
			break;
		}
	}
	return 0;
}

static const char *lg_target_name(int t)
{
	static const char *const n[4] = { "elf64", "elf32", "pe64", "pe32" };

	return n[t];
}

/*
 * THE OBLIGATIONS the engine reports, against what the oracle knows. For an input (a consumer's argument with a role) the
 * oracle has the producers that reached it (a bit each), whether some execution brought a constant (LG_CONSTV) and whether some
 * brought something nothing names (LG_OTHER). The engine's unresolved set must hold the input exactly when the second is
 * true: an unknown part is never reported as resolved, and a constant or a producer is never reported as unknown.
 * Checked on the image that keeps its symbols (the engine's functions are the program's); on a stripped one the engine's
 * partition is its own and so is what it cannot see. An input the oracle never saw reached (a bit for nothing) is code nothing
 * runs - dead - and may be listed or not.
 */
static LA_UNUSED unsigned lg_oblig_why(const struct lg_scan *sc, uint32_t at_off, uint8_t role, int *listed)
{
	uint32_t i, n = kgenome_diag_oblig_count(sc->s);

	*listed = 0;
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_oblig *o = kgenome_diag_oblig_at(sc->s, i);
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc->s, o->node);

		if (h && (uint32_t)h->at == at_off && o->role == role) {
			*listed = 1;
			return o->why;
		}
	}
	return 0;
}

/* Does the expression hold one of this kind. */
static LA_UNUSED int lg_has_kind(const struct lg_prog *p, int e, int kind)
{
	return e >= 0 && (p->ex[e].kind == kind || lg_has_kind(p, p->ex[e].arg[0], kind) || lg_has_kind(p, p->ex[e].arg[1], kind));
}

/* The expression of argument `q` of call site `s`, or -1. */
static LA_UNUSED int lg_site_arg(const struct lg_prog *p, int s, int q)
{
	int e;

	for (e = 0; e < p->nex; e++)
		if (p->ex[e].kind == LG_E_API && p->ex[e].site == s)
			return p->ex[e].arg[q];
	return -1;
}

static LA_UNUSED int lg_check_oblig(const struct lg_oracle *o, const struct lg_prog *p, const struct lg_cg *c,
				    const struct lg_img *g, int target, const struct lg_scan *sc, const char *what)
{
	int s, q, fails = 0;

	for (s = 0; s < p->nsite; s++)
		for (q = 0; q < lg_api[p->site_api[s]].nargs; q++) {
			const uint64_t m = o->obs[s][q];
			const uint8_t role = kgenome_diag_role_of_arg((uint16_t)lg_cap_of_site(p, target, s), (unsigned)q);
			const uint32_t at = (uint32_t)(g->code_off + c->site_off[s]);
			const int unknown = (m >> LG_OTHER & 1u) != 0;
			int listed;
			const unsigned why = lg_oblig_why(sc, at, role, &listed);

			/* a value the program leaves undefined (a function with no return): the machine has one, the oracle does not */
			if (role == KGENOME_DIAG_ROLE_NONE || !m || o->unc[s][q] || (m >> LG_UNDEF & 1u))
				continue;
			/* A stale argument word on a stack-argument target is what an earlier push left there - the machine reads
			 * it, and so does the engine (a constant here) - and the oracle calls it nothing to count on: not compared. */
			if ((target == LG_T_ELF32 || target == LG_T_PE32) && lg_has_kind(p, lg_site_arg(p, s, q), LG_E_STALE))
				continue;
			/* A call to a function that reaches no node is not solved (diag_lineage_summ.c), so what it returns is unknown to the
			 * engine whatever the program says - and the reason is W_SKIP: reported, not hidden. */
			if (unknown != listed && !(listed && (why & KGENOME_LINEAGE_W_SKIP))) {
				printf("  %s: site %d argument %d (role %u): the oracle says %s, the engine %s it\n", what, s, q, role,
				       unknown ? "unknown" : "known", listed ? "lists" : "does not list");
				fails++;
			}
		}
	return fails;
}

/*
 * HAND-WRITTEN PROGRAMS in the model: the tests that name one thing a random program cannot say build the IR here, compile it
 * for a target and look at the scan.
 */
static LA_UNUSED int lg_h_api(struct lg_prog *p, int a, int a0, int a1)
{
	int e = lg_ex(p, LG_E_API, a, a0, a1, lg_api[a].nargs);

	p->ex[e].site = p->nsite;
	p->site_api[p->nsite++] = a;
	return e;
}

static LA_UNUSED void lg_h_st(struct lg_prog *p, int blk, int kind, int x, int e, int a, int b)
{
	lg_add(p, blk, lg_st(p, kind, x, e, a, b));
}

/* An empty program of `nf` functions, each with a body block of its own (function 0 allocates the object when `obj`). */
static LA_UNUSED void lg_h_new(struct lg_prog *p, int nf, int obj)
{
	int i;

	memset(p, 0, sizeof *p);
	p->nf = nf;
	p->has_obj = obj;
	for (i = 0; i < nf; i++) {
		p->fn[i].body = lg_newblk(p);
		p->fn[i].dead = -1;
	}
}

/* Compile the program for `target`, build the image (with symbols), scan it with `stages`: 1 when there is a scan to read
 * (free it with kgenome_diag_scan_free(sc->s)). */
static LA_UNUSED int lg_h_scan(struct lg_scan *sc, struct lg_img *g, struct lg_cg *c, const struct lg_prog *p, int target,
			       unsigned stages)
{
	struct lg_rng r = { 7u };

	return lg_codegen(c, p, &r, target) && lg_build(g, c, &r, 1) && lg_scan(sc, g, target, stages);
}

/* What a campaign's programs went through, for the tests that read it. */
struct lg_camp {
	unsigned stages;
	long *links_seen, *links_stripped;
	int *found;
	int summ, mem, seed;
};

/*
 * EVERY PROGRAM of a campaign, for each target and each image (with symbols, stripped): `fn` is called with the program, its
 * code, its image, and the oracle's account of it when `oracle` names the stages it has. The programs the generator, the oracle
 * or the assembler could not do are skipped and counted. Returns the failures `fn` reported.
 */
typedef int (*lg_each_fn)(void *user, const struct lg_prog *p, const struct lg_cg *c, const struct lg_img *g,
			  const struct lg_oracle *o, int target, int strip, uint64_t seed);

static HK_UNUSED int lg_each(unsigned feat, int n, uint64_t seed0, const unsigned *oracle, long *programs, lg_each_fn fn,
			     void *user)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	static struct lg_oracle o;
	int target, i, strip, fails = 0;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++) {
		lg_assert_vocabulary(target);
		for (i = 0; i < n; i++) {
			struct lg_rng r;
			uint64_t s = seed0 + (uint64_t)i * 7919u + (uint64_t)target * 104729u;

			r.s = s * 0x9e3779b97f4a7c15ull + 1u;
			lg_generate(&p, &r, feat);
			if (p.bad) {
				lg_skip[0]++;
				continue;
			}
			if (oracle) {
				lg_oracle(&o, &p, (*oracle & KGENOME_LINEAGE_S_SUMM) != 0, (*oracle & KGENOME_LINEAGE_S_LOCS) != 0,
					  (*oracle & KGENOME_LINEAGE_S_SEED) != 0);
				if (o.runs >= 400000) {
					lg_skip[1]++;
					continue;
				}
			}
			if (!lg_codegen(&c, &p, &r, target)) {
				lg_skip[2]++;
				continue;
			}
			for (strip = 0; strip < (target == LG_T_PE64 || target == LG_T_PE32 ? 1 : 2); strip++) {
				if (!lg_build(&g, &c, &r, !strip)) {
					lg_skip[2]++;
					break;
				}
				fails += fn(user, &p, &c, &g, oracle ? &o : NULL, target, strip, s);
			}
			(*programs)++;
		}
	}
	return fails;
}

static int lg_camp_one(void *user, const struct lg_prog *p, const struct lg_cg *c, const struct lg_img *g,
		       const struct lg_oracle *o, int target, int strip, uint64_t s)
{
	static struct lg_links want, got, dead;
	static struct lg_oracle od;
	struct lg_camp *k = user;
	struct lg_scan sc;
	char what[96];
	int fails = 0;

	lg_expected(&want, o, p, c, g, target);
	if (!lg_scan(&sc, g, target, k->stages)) {
		printf("  seed %llu %s: no scan\n", (unsigned long long)s, lg_target_name(target));
		return 1;
	}
	lg_actual(&got, &sc);
	snprintf(what, sizeof what, "seed %llu %s%s stages %u", (unsigned long long)s, lg_target_name(target),
		 strip ? " stripped" : "", k->stages);
	if (strip || lg_soft) {
		/* what the dead regions hold, read as the functions a stripped cut may make of them */
		lg_oracle(&od, p, k->summ, k->mem, 1);
		lg_expected(&dead, &od, p, c, g, target);
		if (!lg_subset(&want, &dead, &got, what, k->found))
			fails++;
		*k->links_stripped += want.n;
	} else {
		if (!lg_compare(&want, &got, kgenome_diag_scan_status(sc.s), what))
			fails++;
		fails += lg_check_oblig(o, p, c, g, target, &sc, what);
	}
	if (kgenome_diag_scan_count(sc.s) != (uint32_t)p->nsite) {
		printf("  %s: %u nodes, the program has %d call sites\n", what, kgenome_diag_scan_count(sc.s), p->nsite);
		fails++;
	}
	if (!strip)
		*k->links_seen += want.n;
	kgenome_diag_scan_free(sc.s);
	return fails;
}

/* The campaign: `n` programs for each target, the features given, scanned with `stages`, compared with the
 * oracle that has `summ`, `mem` and `seed` as the stages have. Returns the failures. */
static HK_UNUSED int lg_campaign(unsigned feat, unsigned stages, int n, uint64_t seed0, long *programs, long *links_seen,
		       long *links_stripped, int *found)
{
	struct lg_camp k = { stages, links_seen, links_stripped, found, (stages & KGENOME_LINEAGE_S_SUMM) != 0,
			     (stages & KGENOME_LINEAGE_S_LOCS) != 0, (stages & KGENOME_LINEAGE_S_SEED) != 0 };

	return lg_each(feat, n, seed0, &stages, programs, lg_camp_one, &k);
}

#endif /* KGENOME_TESTS_LINEAGE_CHECK_H */
