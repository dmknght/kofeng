#define _GNU_SOURCE
/*
 * cfg_sig_match - the CFG signature of a function, from the object to the verdict, through the ONE matcher.
 *
 * WHAT IT PINS (CFG step 2c: the shape of a function replaces the window hash for function units):
 *   engine    an inert function of 24 blocks, assembled at run time as an ELF64 x86-64 object with a symbol table (cfg_scene.h), is signed by
 *             kof_cfgsign_function: its 24 keys are what an INDEPENDENT oracle (the survey's algorithm spelled out in this file: degrees, the
 *             label, one WL round, the multiset made a set by occurrence, the domain-separated element, the bottom 32) computes, bit for bit
 *   verdict   a diagnose source holding that block (KOF_MUTATION_BLOCK in region CODE, norm RAW, the 24 keys) at the thresholds 5, 10, ... 100 is
 *             built into a pack by ksigbuilder; the scan of the object fires every diagnose (pct 100), carries a verdict name, the matched
 *             diagnose ids, the part's pct and need (kdet_block_part / kdet_part_need), and the unit's id equals the block's
 *   ladder    variants whose true Jaccard of sketches is known by construction (blocks added, removed; pads and a lead gap that change no shape):
 *             the percentage the engine reports equals kgenome_cfg_pct of the two sketches AND the oracle's, and the set of diagnoses that fire
 *             is exactly {T : T <= pct}: detection flips AT the threshold, not near it
 *   small     a function of 11 reachable blocks IS signed (the floor of 12 is gone, owner 2026-11-01; it was unsigned and fired nothing): it fires exactly
 *             {T : T <= pct} of the oracle's pct against the 24-block block, and the object is not counted unsigned
 *   moved     the same function after a lead gap, in the middle of three functions, at another address: the same sketch, the same diagnoses
 *   clean     a function of another shape fires what the oracle says and nothing else; an object with no function fires nothing
 *   archive   the object inside a stored zip: the member fires the same diagnoses as the loose file
 *   library   a function the library's span owns is not a unit, so it is never signed (kgenome_mutation_units): pinned in mutation_units.c
 *   memory    kof_cfgsign_function through a counting allocator frees everything it took, with the graph kept and not; a refusing allocator
 *             gives NOMEM and leaks nothing; the allowance of one call gives OVER_BUDGET
 * Why the old tests missed it: (a) no function unit was ever signed (the switch said "no function signature"), so no line of the CFG feed or of the
 * matcher's second scoring kind executed; (b) a pack with a CODE block of 12..15 hashes was refused by every loader, so the case was unreachable;
 * (c) the old CODE rows asserted only that the object said it had unsigned units.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "../../libkofeng/analyzers/cfgsign.h"
#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include <celllysis/mutation.h>
#include <celllysis/cfg.h>
#include <kofmod/elf.h>

#include "cfg_scene.h"

static int failures;
static char root[300];
static const char *builder = "build/release/bin/ksigbuilder";
static const char *dbdir = "build/test/databases-sigs";

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

/* ---- the independent oracle: the survey's algorithm on the SPEC, no decoder, no lib code ---------------------------------------------- */

static uint64_t omix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	h *= 0xff51afd7ed558ccdull;
	return h ^ (h >> 33);
}

struct ora {
	uint32_t n_key, key[32];
	uint32_t n_reach;
};

static int ocmp(const void *a, const void *b)
{
	const uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static void ora_sign(const struct cs_spec *g, struct ora *o)
{
	uint32_t succ[CS_MAXB][2], nout[CS_MAXB], term[CS_MAXB], indeg[CS_MAXB] = { 0 }, stack[CS_MAXB], sp = 0, b, i, nr = 0;
	uint8_t reach[CS_MAXB] = { 0 };
	uint64_t cur[CS_MAXB], nxt[CS_MAXB], lab[CS_MAXB];
	uint32_t el[CS_MAXB], m = 0;

	memset(o, 0, sizeof *o);
	for (b = 0; b < g->nb; b++) {
		succ[b][0] = succ[b][1] = 0xffffffffu;
		nout[b] = 0;
		switch (g->kind[b]) {
		case CS_COND: succ[b][0] = g->t[b]; succ[b][1] = b + 1u < g->nb ? b + 1u : 0xffffffffu; term[b] = 1; break;
		case CS_JUMP: succ[b][0] = g->t[b]; term[b] = 2; break;
		case CS_FALL: succ[b][0] = b + 1u < g->nb ? b + 1u : 0xffffffffu; term[b] = 0; break;
		default: term[b] = 3; break;
		}
		nout[b] = (uint32_t)(succ[b][0] != 0xffffffffu) + (uint32_t)(succ[b][1] != 0xffffffffu);
	}
	stack[sp++] = 0;
	reach[0] = 1;
	while (sp) {
		b = stack[--sp];
		for (i = 0; i < 2; i++) {
			const uint32_t t = succ[b][i];

			if (t != 0xffffffffu && !reach[t]) {
				reach[t] = 1;
				stack[sp++] = t;
			}
		}
	}
	for (b = 0; b < g->nb; b++)
		if (reach[b]) {
			nr++;
			for (i = 0; i < 2; i++)
				if (succ[b][i] != 0xffffffffu)
					indeg[succ[b][i]]++;
		}
	for (b = 0; b < g->nb; b++)
		cur[b] = reach[b] ? omix(omix(omix(7u, indeg[b]), nout[b]), term[b]) : 0;
	{
		uint64_t sps[CS_MAXB] = { 0 }, ss[CS_MAXB] = { 0 };

		for (b = 0; b < g->nb; b++)
			if (reach[b])
				for (i = 0; i < 2; i++)
					if (succ[b][i] != 0xffffffffu) {
						ss[b] += omix(cur[succ[b][i]], 2u);
						sps[succ[b][i]] += omix(cur[b], 1u);
					}
		for (b = 0; b < g->nb; b++)
			nxt[b] = reach[b] ? omix(omix(cur[b], sps[b]), ss[b]) : 0;
	}
	for (b = 0, i = 0; b < g->nb; b++)
		if (reach[b])
			lab[i++] = nxt[b];
	for (b = 0; b < nr; b++) {
		uint32_t run = 0, k;

		for (k = 0; k < b; k++)
			run += lab[k] == lab[b];
		el[b] = (uint32_t)(omix(omix(KGENOME_CFG_KEY_SEED, lab[b]), run) >> 32);
	}
	qsort(el, nr, sizeof *el, ocmp);
	for (i = 0; i < nr && m < 32u; i++)
		if (!i || el[i] != el[i - 1u])
			o->key[m++] = el[i];
	o->n_key = m;
	o->n_reach = nr;
}

/* The estimate of the Jaccard of two sketches, in percent, floored: the matches among the 32 smallest elements of the union. */
static uint32_t ora_pct(const struct ora *a, const struct ora *b)
{
	uint32_t i = 0, j = 0, taken = 0, hit = 0;

	if (!a->n_key || !b->n_key)
		return 0;
	while (taken < 32u && (i < a->n_key || j < b->n_key)) {
		if (i < a->n_key && j < b->n_key && a->key[i] == b->key[j]) {
			hit++; i++; j++;
		} else if (j >= b->n_key || (i < a->n_key && a->key[i] < b->key[j])) {
			i++;
		} else {
			j++;
		}
		taken++;
	}
	return hit * 100u / taken;
}

/* ---- specs ------------------------------------------------------------------------------------------------------------------------- */

/* A chain: block i jumps to i+2 on a condition (to the last at the end) and falls into i+1; the last block returns. */
static void chain(struct cs_spec *g, uint32_t nb)
{
	uint32_t i;

	memset(g, 0, sizeof *g);
	g->nb = nb;
	for (i = 0; i + 1u < nb; i++) {
		g->kind[i] = CS_COND;
		g->t[i] = i + 2u < nb ? i + 2u : nb - 1u;
	}
	g->kind[nb - 1u] = CS_EXIT;
}

/* A function of another shape: pairs of blocks, a diamond each, joined by jumps. */
static void other(struct cs_spec *g, uint32_t nb)
{
	uint32_t i;

	memset(g, 0, sizeof *g);
	g->nb = nb;
	for (i = 0; i + 1u < nb; i++) {
		g->kind[i] = (i % 3u == 2u) ? CS_JUMP : CS_COND;
		g->t[i] = (i % 3u == 2u) ? (i + 1u < nb ? i + 1u : nb - 1u) : (i + 3u < nb ? i + 3u : nb - 1u);
	}
	g->kind[nb - 1u] = CS_EXIT;
}

static void pads(struct cs_spec *g, uint32_t seed)
{
	uint32_t i;

	for (i = 0; i < g->nb; i++)
		g->pad[i] = (uint8_t)((seed * 7u + i * 13u) % 5u);
}

#define N_THRESH 99u        /* thresholds 1, 2, ... 99: one diagnose each; a value run of 99 blocks is past the matcher's once-per-object memo (MTN_HOT 64) */

#include "cfg_pack.h"

/* ---- scanning ----------------------------------------------------------------------------------------------------------------------- */

struct seen {
	uint8_t  fired[N_THRESH + 1u];  /* fired[t]: the diagnose of threshold t matched */
	uint32_t n_fired;
	char     verdict[160];
	unsigned n_diag;
	int      has_part;
	unsigned pct, need, matched, n, unit_id_found;
	uint32_t unit_id;
};

static unsigned thresh_of(const char *name)
{
	const char *p = strrchr(name, '_');

	return p ? (unsigned)atoi(p + 1) : 0u;
}

/* Scan `p` with explain on; fill what the verdict path returned for the object whose name ends with `leaf` ("" = the root). */
static kof_engine *G_eng;

static void scan(kof_scanner *sc, const void *p, size_t n, const char *leaf, struct seen *out)
{
	kdet_run *run;
	const struct kdet_object *o;
	uint32_t i, nd = 0;
	const struct kof_diag_report *dr;

	memset(out, 0, sizeof *out);
	run = kscan_explain(sc, p, n, "sample", NULL);
	if (!run)
		return;
	if (leaf[0]) {
		uint32_t q;

		o = NULL;
		for (q = 0; q < kdet_run_count(run); q++) {
			const struct kdet_object *c = kdet_run_at(run, q);
			const size_t l = strlen(leaf), nl = strlen(c->name);

			if (nl >= l && !strcmp(c->name + nl - l, leaf))
				o = c;

		}
	} else {
		o = kdet_run_find(run, "sample");
	}
	if (o) {
		struct kdet_info info;

		kdet_info(G_eng, &o->res, &info);
		if (info.verdict)
			snprintf(out->verdict, sizeof out->verdict, "%s", info.verdict);
		out->n_diag = info.n_diag;
		for (i = 0; i < o->res.n_diag; i++) {
			const struct kof_diag_report *d = &o->res.diag[i];

			if (d->state == KOF_DIAG_ST_MATCH) {
				const unsigned t = thresh_of(d->name);

				if (t >= 1u && t <= N_THRESH && !out->fired[t]) {
					out->fired[t] = 1;
					out->n_fired++;
				}
				if (d->n_part && !out->has_part) {
					out->has_part = 1;
					out->pct = d->part[0].pct;
					out->matched = d->part[0].matched;
					out->n = d->part[0].n;
					out->unit_id = d->part[0].unit_id;
				}
			}
		}
		dr = kdet_run_decided(run, o, &nd);
		(void)dr;
	}
	kdet_run_free(run);
}

/* ---- a stored zip of one member ---------------------------------------------------------------------------------------------------- */

static uint32_t crc32_of(const uint8_t *p, size_t n)
{
	uint32_t c = 0xffffffffu, i, k;

	for (i = 0; i < n; i++) {
		c ^= p[i];
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
	}
	return ~c;
}

static size_t make_zip(uint8_t *out, const char *name, const uint8_t *data, size_t n)
{
	const size_t nl = strlen(name);
	const uint32_t crc = crc32_of(data, n);
	size_t at = 0, cd;

	cs_p32(out + at, 0x04034b50u); cs_p16(out + at + 4, 20); cs_p16(out + at + 6, 0); cs_p16(out + at + 8, 0); cs_p16(out + at + 10, 0); cs_p16(out + at + 12, 0x21);
	cs_p32(out + at + 14, crc); cs_p32(out + at + 18, (uint32_t)n); cs_p32(out + at + 22, (uint32_t)n); cs_p16(out + at + 26, (uint16_t)nl); cs_p16(out + at + 28, 0);
	memcpy(out + at + 30, name, nl);
	memcpy(out + at + 30 + nl, data, n);
	at += 30 + nl + n;
	cd = at;
	cs_p32(out + at, 0x02014b50u); cs_p16(out + at + 4, 20); cs_p16(out + at + 6, 20); cs_p16(out + at + 8, 0); cs_p16(out + at + 10, 0); cs_p16(out + at + 12, 0);
	cs_p16(out + at + 14, 0x21); cs_p32(out + at + 16, crc); cs_p32(out + at + 20, (uint32_t)n); cs_p32(out + at + 24, (uint32_t)n); cs_p16(out + at + 28, (uint16_t)nl);
	cs_p16(out + at + 30, 0); cs_p16(out + at + 32, 0); cs_p16(out + at + 34, 0); cs_p16(out + at + 36, 0); cs_p32(out + at + 38, 0); cs_p32(out + at + 42, 0);
	memcpy(out + at + 46, name, nl);
	at += 46 + nl;
	cs_p32(out + at, 0x06054b50u); cs_p16(out + at + 4, 0); cs_p16(out + at + 6, 0); cs_p16(out + at + 8, 1); cs_p16(out + at + 10, 1);
	cs_p32(out + at + 12, (uint32_t)(at - cd)); cs_p32(out + at + 16, (uint32_t)cd); cs_p16(out + at + 20, 0);
	return at + 22;
}

/* ---- the engine's signature against the oracle ----------------------------------------------------------------------------------- */

static struct kof_obj_ctx ctx_of(struct kgenome_elf_info *ei, const struct cs_obj *o)
{
	struct kof_obj_ctx c;

	memset(&c, 0, sizeof c);
	memset(ei, 0, sizeof *ei);
	ei->elf_data = 1;
	c.format = KOF_FMT_ELF;
	c.arch = KGENOME_ARCH_X86_64;
	c.obj_size = o->n;
	c.file_header = ei;
	return c;
}

static struct cs_obj O1, O2;

/* The unit's id and sketch as the engine's one signing function makes them. */
static enum kof_cfgsign_state sign_fn(const struct cs_obj *o, uint32_t k, struct kof_cfgsign *cs)
{
	struct kgenome_elf_info ei;
	struct kof_obj_ctx c = ctx_of(&ei, o);
	struct kof_cfgsign_req rq;

	memset(&rq, 0, sizeof rq);
	rq.ctx = &c;
	rq.data.p = o->b;
	rq.data.n = o->n;
	rq.off = o->f_off[k];
	rq.len = o->f_len[k];
	return kof_cfgsign_function(&rq, cs);
}

static void signature_vs_oracle(void)
{
	struct cs_spec g;
	struct kof_cfgsign cs;
	struct ora o;
	uint32_t nb;

	for (nb = 1; nb <= 60; nb++) {
		chain(&g, nb);
		pads(&g, nb);
		OKF(cs_build(&O1, &g, 1, nb % 7u), "build %u", nb);
		ora_sign(&g, &o);
		(void)sign_fn(&O1, 0, &cs);
		OKF(cs.sign.n_blk == nb && cs.sign.n_key == o.n_key && !memcmp(cs.sign.key, o.key, o.n_key * sizeof o.key[0]),
		    "a chain of %u blocks: the engine's sketch is not the oracle's (blocks %u/%u keys %u/%u)", nb, cs.sign.n_blk, nb, cs.sign.n_key, o.n_key);
		/* every function with a reachable block is signed: there is no floor of 12 any more */
		OKF(cs.state == KOF_CFGSIGN_SIGNED, "a chain of %u blocks is %s", nb, kof_cfgsign_state_name(cs.state));
		OKF(o.n_key >= KGENOME_CFG_MIN_KEYS && o.n_key == (nb < KGENOME_CFG_KEYS ? nb : KGENOME_CFG_KEYS), "a signed function holds at least KGENOME_CFG_MIN_KEYS keys, one a block (%u)", o.n_key);
	}
	/* another shape */
	other(&g, 30);
	OKF(cs_build(&O1, &g, 1, 0), "build other");
	ora_sign(&g, &o);
	(void)sign_fn(&O1, 0, &cs);
	OKF(cs.state == KOF_CFGSIGN_SIGNED && cs.sign.n_key == o.n_key && !memcmp(cs.sign.key, o.key, o.n_key * sizeof o.key[0]), "the other shape: the engine's sketch is the oracle's");
}

/* ---- memory ---------------------------------------------------------------------------------------------------------------------- */

struct counting {
	uint32_t n_alloc, n_free, fail_at;
	uint64_t held, peak;
};

static void *c_alloc(void *u, size_t n)
{
	struct counting *c = u;

	if (c->fail_at && ++c->n_alloc == c->fail_at)
		return NULL;
	if (!c->fail_at)
		c->n_alloc++;
	c->held += n;
	if (c->held > c->peak)
		c->peak = c->held;
	return malloc(n);
}

static void c_release(void *u, void *p, size_t n)
{
	struct counting *c = u;

	if (!p)
		return;
	c->n_free++;
	c->held -= n;
	free(p);
}

static void memory(void)
{
	struct cs_spec g;
	struct kgenome_elf_info ei;
	struct kof_obj_ctx c;
	uint32_t keep, at;

	chain(&g, 40);
	OKF(cs_build(&O1, &g, 1, 0), "build");
	c = ctx_of(&ei, &O1);
	for (keep = 0; keep < 2; keep++) {
		struct counting cnt = { 0 };
		struct kof_cfgsign_host host;
		struct kof_cfgsign cs;
		struct kof_cfgsign_req rq;

		memset(&host, 0, sizeof host);
		host.mem.alloc = c_alloc;
		host.mem.release = c_release;
		host.mem.user = &cnt;
		memset(&rq, 0, sizeof rq);
		rq.ctx = &c; rq.data.p = O1.b; rq.data.n = O1.n; rq.off = O1.f_off[0]; rq.len = O1.f_len[0]; rq.keep = (int)keep; rq.host = &host;
		OKF(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_SIGNED, "signed (keep %u)", keep);
		OKF(keep ? cnt.held > 0 : cnt.held == 0, "the graph is held only when asked for (keep %u, held %llu)", keep, (unsigned long long)cnt.held);
		kof_cfgsign_release(&cs, &host.mem);
		OKF(cnt.held == 0 && cnt.n_alloc == cnt.n_free && cnt.n_alloc > 0, "everything the call took is released (keep %u: %u taken, %u given back)", keep, cnt.n_alloc, cnt.n_free);
	}
	/* an allocator that refuses the k-th request: NOMEM, nothing leaks, whichever k */
	for (at = 1; at < 40; at++) {
		struct counting cnt = { 0 };
		struct kof_cfgsign_host host;
		struct kof_cfgsign cs;
		struct kof_cfgsign_req rq;
		enum kof_cfgsign_state st;

		cnt.fail_at = at;
		memset(&host, 0, sizeof host);
		host.mem.alloc = c_alloc;
		host.mem.release = c_release;
		host.mem.user = &cnt;
		memset(&rq, 0, sizeof rq);
		rq.ctx = &c; rq.data.p = O1.b; rq.data.n = O1.n; rq.off = O1.f_off[0]; rq.len = O1.f_len[0]; rq.keep = (int)(at & 1u); rq.host = &host;
		st = kof_cfgsign_function(&rq, &cs);
		kof_cfgsign_release(&cs, &host.mem);
		OKF(cnt.held == 0, "the %u-th allocation refused: %llu bytes still held (state %d)", at, (unsigned long long)cnt.held, (int)st);
		OKF(st == KOF_CFGSIGN_SIGNED || st == KOF_CFGSIGN_NOMEM, "the %u-th allocation refused: state %d", at, (int)st);
	}
	/* the allowance of one call */
	{
		struct kof_cfgsign_host host;
		struct kof_cfgsign cs;
		struct kof_cfgsign_req rq;

		memset(&host, 0, sizeof host);
		host.max_bytes = 256;
		memset(&rq, 0, sizeof rq);
		rq.ctx = &c; rq.data.p = O1.b; rq.data.n = O1.n; rq.off = O1.f_off[0]; rq.len = O1.f_len[0]; rq.host = &host;
		OKF(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_OVER_BUDGET, "an allowance of 256 bytes cannot hold the function: OVER_BUDGET, nothing claimed");
		OKF(cs.sign.n_key == 0, "no sketch is claimed over the allowance");
	}
}

/* ---- the verdict path ------------------------------------------------------------------------------------------------------------- */

static void check_set(const char *what, const struct seen *s, uint32_t pct)
{
	uint32_t t, wrong = 0, first = 0;

	for (t = 1; t <= N_THRESH; t++)
		if ((s->fired[t] != 0) != (t <= pct)) {
			if (!wrong++)
				first = t;
		}
	OKF(!wrong, "%s: pct %u, the diagnoses that fired differ from {T <= pct} at %u threshold(s), the first T=%u (%u fired)", what, pct, wrong, first, s->n_fired);
}

static void verdict_path(void)
{
	struct cs_spec ref, g;
	struct ora oref, ov;
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	struct seen s;
	static uint8_t zipb[CS_MAX_OBJ + 1024];
	size_t zn;
	uint32_t id_ref, v, nb;
	struct kof_cfgsign cs;

	chain(&ref, 24);
	pads(&ref, 3);
	OKF(cs_build(&O1, &ref, 1, 0), "build the reference");
	ora_sign(&ref, &oref);
	OKF(oref.n_key == 24u, "24 reachable blocks make 24 keys (%u)", oref.n_key);
	OKF(make_pack(&sc, "ladder", oref.key, oref.n_key, N_THRESH, 1u) == 0, "the pack builds from %u CODE keys (see %s)", oref.n_key, sc.err);
	eng = keng_open(sc.db);
	G_eng = eng;
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the pack does not open");
		return;
	}
	OKF(kdb_diagnoses(eng) >= N_THRESH && kdb_diag_refused(eng) == 0u, "%u diagnoses loaded, none refused (%u, refused %u)", N_THRESH, (unsigned)kdb_diagnoses(eng),
	    (unsigned)kdb_diag_refused(eng));
	(void)sign_fn(&O1, 0, &cs);
	id_ref = kof_mutation_fold(cs.sign.key, cs.sign.n_key);

	/* THE OBJECT ITSELF: every diagnose fires, pct 100, a verdict, the matched ids, the unit's id is the block's */
	scan(scn, O1.b, O1.n, "", &s);
	check_set("the reference", &s, 100u);
	OKF(s.has_part && s.pct == 100u && s.matched == s.n && s.n == 24u, "the part says 100%% (pct %u matched %u of %u)", s.pct, s.matched, s.n);
	OKF(strncmp(s.verdict, "Infected#", 9) == 0 && strstr(s.verdict, "Botnet") != NULL, "the verdict name is made of the diseases: \"%s\"", s.verdict);
	OKF(s.n_diag >= 1u, "the verdict lists the matched diagnoses (%u)", s.n_diag);
	OKF(s.unit_id == id_ref, "the place's unit id is the id the table and --blocks carry: %08x vs %08x", s.unit_id, id_ref);

	/* THE LADDER: blocks added and removed; the engine's pct = kgenome_cfg_pct = the oracle's, and detection flips exactly at the threshold */
	for (v = 0; v < 33; v++) {
		struct kgenome_cfg_sign a, b;
		uint32_t pct_oracle, pct_lib;

		nb = 8u + v;                                  /* 8 .. 40 blocks around the reference's 24, the small ones signed too */
		chain(&g, nb);
		pads(&g, v + 1u);
		OKF(cs_build(&O2, &g, 1, 16), "build %u", nb);
		ora_sign(&g, &ov);
		pct_oracle = ora_pct(&oref, &ov);
		(void)sign_fn(&O2, 0, &cs);
		{
			struct kof_cfgsign cr;

			(void)sign_fn(&O1, 0, &cr);
			a = cr.sign;
			b = cs.sign;
			pct_lib = kgenome_cfg_pct(&a, &b);
		}
		scan(scn, O2.b, O2.n, "", &s);
		OKF(cs.state == KOF_CFGSIGN_SIGNED, "%u blocks: signed (no floor)", nb);
		OKF(pct_lib == pct_oracle, "%u blocks: kgenome_cfg_pct %u, the oracle %u", nb, pct_lib, pct_oracle);
		check_set("a variant", &s, pct_oracle);
		if (s.has_part) {
			OKF(s.pct == pct_oracle, "%u blocks: the part's pct %u is the oracle's %u", nb, s.pct, pct_oracle);
			OKF(s.n && s.matched * 100u / s.n == s.pct, "%u blocks: the part's matched %u of %u is its pct %u", nb, s.matched, s.n, s.pct);
		}
		printf("  variant %u blocks: pct %u%%, fired %u of %u\n", nb, pct_oracle, s.n_fired, N_THRESH);
	}

	/* SMALL: 11 blocks is the first 11 of the chain; it used to be below the floor, unsigned, firing nothing */
	chain(&g, 11);
	OKF(cs_build(&O2, &g, 1, 0), "build 11");
	{
		const uint64_t before = kscan_stats(scn)->mutation_unsigned_objects;
		struct ora o11;

		ora_sign(&g, &o11);
		scan(scn, O2.b, O2.n, "", &s);
		check_set("a function of 11 blocks", &s, ora_pct(&oref, &o11));
		OKF(s.n_fired > 0, "a function of 11 blocks fires (%u fired)", s.n_fired);
		OKF(kscan_stats(scn)->mutation_unsigned_objects == before, "and the object is not counted as having an unsigned function unit");
	}

	/* MOVED: the same function after a lead gap and between two others */
	{
		struct cs_spec trio[3];
		struct kof_cfgsign cm;

		chain(&trio[0], 14);
		trio[1] = ref;
		other(&trio[2], 30);
		OKF(cs_build(&O2, trio, 3, 0x123), "build the trio");
		(void)sign_fn(&O2, 1, &cm);
		{
			struct kof_cfgsign cr;

			(void)sign_fn(&O1, 0, &cr);
			OKF(cm.sign.canon == cr.sign.canon && cm.sign.n_key == cr.sign.n_key && !memcmp(cm.sign.key, cr.sign.key, cr.sign.n_key * sizeof cr.sign.key[0]),
			    "the same function at another offset and address has the same sketch");
		}
		scan(scn, O2.b, O2.n, "", &s);
		/* three functions: the reference fires every diagnose; the others may add nothing (the union is the reference's own set) */
		OKF(s.n_fired == N_THRESH, "moved into a trio the diagnoses all fire (%u of %u)", s.n_fired, N_THRESH);
	}

	/* GROUPED (pins the wrong behaviour of CS2-1 while it exists, comment at by_function): the reference and a larger function less than 32 bytes apart are ONE unit, signed by the
	 * larger one, so the object that holds the reference does not fire the diagnoses of the reference: only those the larger function reaches. */
	{
		struct cs_spec pair[2];

		pair[0] = ref;
		chain(&pair[1], 33);
		OKF(cs_build_gap(&O2, pair, 2, 0, 0), "build the pair");
		ora_sign(&pair[1], &ov);
		scan(scn, O2.b, O2.n, "", &s);
		check_set("grouped small functions (CS2-1: the unit is signed by its largest function)", &s, ora_pct(&oref, &ov));
		OKF(s.n_fired < N_THRESH, "CS2-1 is fixed: the reference, which is in the object, fires every diagnose: flip this row");
	}

	/* CLEAN: another shape fires what the oracle says; an object with no function fires nothing */
	other(&g, 30);
	OKF(cs_build(&O2, &g, 1, 0), "build other");
	ora_sign(&g, &ov);
	scan(scn, O2.b, O2.n, "", &s);
	check_set("another shape", &s, ora_pct(&oref, &ov));
	memset(&g, 0, sizeof g);
	g.nb = 0;
	{
		static const uint8_t junk[200] = { 1, 2, 3 };

		scan(scn, junk, sizeof junk, "", &s);
		OKF(s.n_fired == 0 && !s.verdict[0], "an object with no function fires nothing");
	}

	/* ARCHIVE: the same object as the member of a stored zip fires the same diagnoses as the loose file */
	zn = make_zip(zipb, "inner.elf", O1.b, O1.n);
	scan(scn, zipb, zn, "inner.elf", &s);
	check_set("the zip member", &s, 100u);

	kscan_free(scn);
	keng_close(eng);
}

/* ---- the matcher alone, over a set built in memory (what the viewer scores its table with) ------------------------------------------------------ */

static void memory_set(void)
{
	struct kof_mutation_block b;
	struct kgenome_cfg_sign unit;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	uint32_t keys[24], i;
	struct cs_spec g;
	struct ora o;

	chain(&g, 24);
	ora_sign(&g, &o);
	memcpy(keys, o.key, sizeof keys);
	memset(&b, 0, sizeof b);
	b.n_hash = 24;
	b.scan_mask = KOF_SCAN_ELF_CODE;
	b.side = KGENOME_MUTATION_SIDE_USER;
	set = kof_mutation_build(&b, 1, keys, 24);
	OKF(set != NULL, "a set of one CODE block of 24 keys is built in memory");
	if (!set)
		return;
	OKF(kof_mutation_ctx_init(&c, set), "ctx");
	/* the block's own sketch: 100 */
	memset(&unit, 0, sizeof unit);
	unit.n_key = 24;
	memcpy(unit.key, keys, sizeof keys);
	kof_mutation_begin(&c);
	kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &unit, 100);
	OKF(kof_mutation_pct(&c, 0) == 100u && kof_mutation_matched(&c, 0) == 24u, "its own sketch holds the block entirely: %u%%", kof_mutation_pct(&c, 0));
	/* a sketch of 12 of its 24 keys: the union is the block's 24, 12 are shared: 50 */
	kof_mutation_begin(&c);
	memset(&unit, 0, sizeof unit);
	unit.n_key = 12;
	memcpy(unit.key, keys, 12u * sizeof keys[0]);
	kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &unit, 100);
	OKF(kof_mutation_pct(&c, 0) == 50u, "12 of 24 keys: %u%% (want 50)", kof_mutation_pct(&c, 0));
	/* the best of two units counts, and a unit in another region or on the other side counts for nothing */
	kof_mutation_begin(&c);
	{
		struct kgenome_cfg_sign weak = unit, strong;

		for (i = 0; i < weak.n_key; i++)
			weak.key[i] = keys[i + 12u];
		memset(&strong, 0, sizeof strong);
		strong.n_key = 24;
		memcpy(strong.key, keys, sizeof keys);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &strong, 100);
		OKF(kof_mutation_pct(&c, 0) == 100u, "the strong unit first");
		kof_mutation_begin(&c);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &weak, 100);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &strong, 100);
		OKF(kof_mutation_pct(&c, 0) == 100u, "the best of two units counts (weak then strong): %u%%", kof_mutation_pct(&c, 0));
		kof_mutation_begin(&c);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_DATA, KGENOME_MUTATION_SIDE_USER, &strong, 100);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_LIB, &strong, 100);
		OKF(kof_mutation_pct(&c, 0) == 0u, "another region and the other side hold nothing: %u%%", kof_mutation_pct(&c, 0));
		/* two units do not add: the sketches are not merged (a block is held by ONE function) */
		kof_mutation_begin(&c);
		unit.n_key = 12;
		memcpy(unit.key, keys, 12u * sizeof keys[0]);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &unit, 100);
		kof_mutation_cfg_unit(&c, KOF_SCAN_ELF_CODE, KGENOME_MUTATION_SIDE_USER, &weak, 100);
		OKF(kof_mutation_pct(&c, 0) == 50u, "two halves of the block in two functions are not the block: %u%%", kof_mutation_pct(&c, 0));
	}
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
}

/* ---- units of one object that share keys: a value walked for the first is walked again for the next ------------------------------------------------ */

/* The first function's sketch holds the keys of the second (a 24-block chain and the 12-block chain: the shorter one's elements are the longer one's first twelve).
 * The pack's block is the SHORT chain's sketch: the short function holds it entirely (100), the long one half (50). A matcher that remembered the values it had
 * already walked for the long function (the once-per-object memo of a value in more than 64 blocks) would not credit the short function at all and the object
 * would score 50. */
static void shared_keys(void)
{
	struct cs_spec two[2], g12;
	struct ora o12;
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	struct seen s;

	chain(&two[0], 24);
	chain(&two[1], 12);
	g12 = two[1];
	ora_sign(&g12, &o12);
	OKF(o12.n_key == 12u, "12 reachable blocks make 12 keys (%u)", o12.n_key);
	{
		struct ora o24;
		uint32_t i, j, in = 0;

		ora_sign(&two[0], &o24);
		for (i = 0; i < o12.n_key; i++)
			for (j = 0; j < o24.n_key; j++)
				in += o12.key[i] == o24.key[j];
		OKF(in == o12.n_key, "precondition: all 12 keys of the short chain are keys of the long one (%u of 12)", in);
	}
	OKF(make_pack(&sc, "shared", o12.key, o12.n_key, N_THRESH, 1u) == 0, "the pack of the 12-key block builds (see %s)", sc.err);
	eng = keng_open(sc.db);
	G_eng = eng;
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the pack does not open");
		return;
	}
	OKF(cs_build(&O2, two, 2, 0), "build the pair");
	scan(scn, O2.b, O2.n, "", &s);
	check_set("two functions, the first holding the second's keys: the second counts in full", &s, 100u);
	kscan_free(scn);
	keng_close(eng);
}

int main(void)
{
	if (access(builder, X_OK) != 0) {
		printf("cfg_sig_match: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_cfgsig_XXXXXX");
	if (!mkdtemp(root)) {
		printf("cfg_sig_match: cannot make a scratch directory\n");
		return 2;
	}
	signature_vs_oracle();
	memory();
	memory_set();
	verdict_path();
	shared_keys();
	if (!failures) {
		char cmd[400];

		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	if (failures) {
		printf("cfg_sig_match: %d FAIL\n", failures);
		return 1;
	}
	printf("cfg_sig_match: ok\n");
	return 0;
}
