/*
 * ctr_seeds.h - the seed corpus of the container adapters: for each format the writers of tests/lib/ctr_writers.h make a
 * valid archive, the same archive with each header lie the format has a field for, one with hostile member names, and (for the
 * walk) nested and polyglot files. Every seed carries the field map its writer published, so a mutator aims at the declared
 * sizes, counts and offsets first and the rest of the bytes second.
 *
 * Static and header-only: each adapter file includes it and owns its own copy of the pools.
 */
#ifndef KOF_FUZZ_CTR_SEEDS_H
#define KOF_FUZZ_CTR_SEEDS_H

#include "../../lib/ctr_writers.h"
#include "../../lib/fuzz_drv.h"

#define CSD_MAX 260u

static struct fz_field csd_f[CSD_MAX][CW_MAXF];
static struct fz_map   csd_m[CSD_MAX];
static unsigned        csd_n;
static char            csd_name[CSD_MAX][40];

static __attribute__((unused)) void csd_add(struct fz_corpus *c, const char *fmt, const char *what, const struct cw *w, const struct cw_map *m)
{
	unsigned i;
	struct fz_map *fm;

	if (csd_n >= CSD_MAX || w->oom || !w->n)
		return;
	fm = &csd_m[csd_n];
	memset(fm, 0, sizeof *fm);
	if (m)
		for (i = 0; i < m->n; i++) {
			csd_f[csd_n][i].off = m->f[i].off;
			csd_f[csd_n][i].size = m->f[i].size;
			csd_f[csd_n][i].be = 0;
			csd_f[csd_n][i].kind = m->f[i].kind;
		}
	fm->f = csd_f[csd_n];
	fm->n = m ? m->n : 0;
	snprintf(csd_name[csd_n], sizeof csd_name[csd_n], "%s-%s", fmt, what);
	fz_corpus_add_map(c, csd_name[csd_n], w->p, w->n, fm);
	csd_n++;
}

/* The archives of one format: clean, each lie, hostile names. */
static __attribute__((unused)) void csd_format(struct fz_corpus *c, unsigned f)
{
	static uint8_t d[3][700];
	static char long_name[301];
	const struct cw_format *F = &cw_formats[f];
	unsigned n = F->max_members == 1 ? 1u : 3u, k, v;
	struct cw_ent e[3];
	struct cw_lies l;
	struct cw w;
	struct cw_map m;
	static const char *const nm[3] = { "a.txt", "b.bin", "c" };
	static const unsigned lie_bits[] = { CW_L_COUNT, CW_L_OFFSET, CW_L_CYCLE, CW_L_NOEND, CW_L_EXTRA, CW_L_CRYPT };
	static const char *const lie_name[] = { "count", "offset", "cycle", "noend", "extra", "crypt" };

	for (k = 0; k < 3; k++)
		for (v = 0; v < sizeof d[k]; v++)
			d[k][v] = (uint8_t)('a' + (k * 7u + v * 13u) % 26u);
	memset(long_name, 'N', 300);
	for (v = 0; v < 12; v++) {                       /* 0 clean, 1..3 size claims, 4 share, 5..10 the structure lies, 11 names */
		memset(e, 0, sizeof e);
		memset(&l, 0, sizeof l);
		memset(&w, 0, sizeof w);
		memset(&m, 0, sizeof m);
		for (k = 0; k < 3; k++) {
			e[k].name = nm[k];
			e[k].data = d[k];
			e[k].len = 100u + 200u * k;
		}
		if (v == 1) { e[1].claimed = 1; e[1].claim_packed = e[1].claim_unpacked = 0xfffffff0u; }
		if (v == 2) { e[1].claimed = 1; e[1].claim_packed = 0xfffffff0u; e[1].claim_unpacked = e[1].len; }
		if (v == 3) { e[1].claimed = 1; e[1].claim_packed = e[1].len; e[1].claim_unpacked = 0xfffffff0u; }
		if (v == 4) { e[2].share = 1; }
		if (v >= 5 && v <= 10) {
			if (!(F->lies & lie_bits[v - 5]))
				continue;
			l.mask = lie_bits[v - 5];
			l.count_claim = 60000;
			l.off_claim = 0x7ffffff0u;
		}
		if (v == 11) {
			e[0].name = "../../../../etc/x";
			e[1].name = long_name; e[1].name_len = 300;
			e[2].name = "a\0b"; e[2].name_len = 3;
		}
		if (n == 1) {
			e[0].len = e[0].len > 700 ? 700 : e[0].len;
		}
		F->write(&w, e, n, &l, &m);
		csd_add(c, F->name, v == 0 ? "clean" : v == 1 ? "claim-both" : v == 2 ? "claim-pack" : v == 3 ? "claim-unp" : v == 4 ? "share" :
			v == 11 ? "names" : lie_name[v - 5], &w, &m);
		cw_free(&w);
	}
}

#endif
