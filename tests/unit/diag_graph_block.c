/*
 * diag_graph_block.c - the diagnose graph block (kof_diag_graph_build), against a model.
 *
 * The serialiser once wrote four links into a record that holds KOF_GR_IN_FIT = 2: links 2
 * and 3 landed on the next record's `at`, and on the last node past the block (objctx_diag.c
 * allocates exactly HDR + n * RECLEN). api_engine_detect.c pins the two cases it was found in.
 * This test closes the family:
 *
 *   SHAPE     graphs of N nodes where ONE node, at every position (first, middle, last), has
 *             0, 1, 2, 3, 4 inputs and the rest have every other count, and graphs where all
 *             nodes have k inputs.
 *   HOSTILE   the block is built into a buffer of EXACTLY the size it is allowed (a guard-page
 *             buffer that ends on a PROT_NONE page, or an exact-size malloc, which is what
 *             AddressSanitizer's red zone checks) - and, in a second buffer with room,
 *             into one whose tail is a canary that must come back unchanged.
 *   READBACK  every field of every record is read through kof_gr_rec / kof_gr_u64 / kof_gr_u16
 *             / kof_gr_in and compared with the model; the raw bytes beyond the two links, the
 *             reserved byte and the header's reserved word are zero.
 *   TRUNCATED the scan is noted KGENOME_TRUNCATED exactly when a node has more than
 *             KOF_GR_IN_FIT inputs, never otherwise.
 *   READERS   kof_gr_linked / kof_gr_has / kof_gr_entries (the inline readers a module uses)
 *             run on the exact-size block and equal a model computed from the hits; then the
 *             same readers run on a block whose count, link count and link indexes are
 *             hostile, in the guard buffer: a read past a record would fault.
 *   PROPERTY  several thousand random graphs against the model.
 *
 * Each group runs in a forked child (hostile_engine.h) so that a fault is a result.
 */

#include "hostile_engine.h"

#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include <kofmod/kofsig.h>
#include <kofmod/kofdiagtree.h>
#include <phenotype/diag_scan_state.h>

#define MAXN 70u
#define CANARY 0xa5u

/* the model: what the scan holds, which is all the block is a function of */
struct model {
	struct kgenome_diag_hit hit[MAXN];
	uint32_t n;
};

static unsigned child_fails;

#define CF(cond, ...) do { \
	he_checks++; \
	if (!(cond)) { \
		if (child_fails < 20u) { \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
		child_fails++; \
	} \
} while (0)

static void mk_hit(struct kgenome_diag_hit *h, uint32_t i, uint32_t n_nodes, unsigned n_in, uint32_t seed)
{
	unsigned k;

	memset(h, 0, sizeof *h);
	h->at = 0x100000000ull * (i + 1u) + seed;
	h->attr = (uint64_t)(seed % 5u) << (8u * (i % 7u));
	h->cap = (uint16_t)(1u + (i + seed) % 3u);
	h->flags = (uint16_t)((i * 7u + seed) & 7u);
	h->n_in = (uint8_t)n_in;
	for (k = 0; k < n_in && k < 4u; k++) {
		uint32_t pick = (i + k + seed) % 6u;

		/* a parent inside the graph, or the stack region, or none */
		h->in[k].from = pick == 4u ? (uint16_t)KOF_GR_FROM_STACK
			      : pick == 5u ? (uint16_t)KOF_GR_FROM_NONE
			      : (uint16_t)((i * 3u + k + seed) % n_nodes);
		h->in[k].role = (uint8_t)(1u + (i + k) % 3u);
		h->in[k].kind = ((i + k + seed) & 1u) ? KGENOME_DIAG_KIND_SHARED : KGENOME_DIAG_KIND_PRODUCED;
	}
}

static int any_cut(const struct model *m)
{
	uint32_t i;

	for (i = 0; i < m->n; i++)
		if (m->hit[i].n_in > KOF_GR_IN_FIT)
			return 1;
	return 0;
}

/* the model of the three readers, written from the hits and not from the block */
static int m_linked(const struct model *m, uint16_t pc, uint16_t cc, uint8_t role, uint16_t flags)
{
	uint32_t i;

	for (i = 0; i < m->n; i++) {
		const struct kgenome_diag_hit *h = &m->hit[i];
		unsigned k;

		if (h->cap != cc)
			continue;
		for (k = 0; k < h->n_in && k < KOF_GR_IN_FIT; k++) {
			uint16_t from = h->in[k].from;

			if (from >= KOF_GR_FROM_STACK || h->in[k].role != role || from >= m->n)
				continue;
			if (m->hit[from].cap != pc || (m->hit[from].flags & flags) != flags)
				continue;
			return 1;
		}
	}
	return 0;
}

static uint32_t m_entries(const struct model *m, uint16_t pc, uint16_t cc, uint8_t role, uint32_t cap_max)
{
	uint64_t seen[16];
	uint32_t ns = 0, i;

	if (cap_max > 16u)
		cap_max = 16u;
	for (i = 0; i < m->n && ns < cap_max; i++) {
		const struct kgenome_diag_hit *h = &m->hit[i];
		unsigned k, t;

		if (h->cap != cc || !h->attr)
			continue;
		for (k = 0; k < h->n_in && k < KOF_GR_IN_FIT; k++) {
			uint16_t from = h->in[k].from;

			if (from >= KOF_GR_FROM_STACK || h->in[k].role != role || from >= m->n ||
			    m->hit[from].cap != pc)
				continue;
			for (t = 0; t < ns; t++)
				if (seen[t] == h->attr)
					break;
			if (t == ns)
				seen[ns++] = h->attr;
			break;
		}
	}
	return ns;
}

static void check_readers(const struct model *m, const uint8_t *b, uint32_t n)
{
	uint16_t pc, cc;
	uint8_t role;

	for (pc = 1; pc <= 3u; pc++)
		for (cc = 1; cc <= 3u; cc++)
			for (role = 1; role <= 3u; role++) {
				uint16_t fl;

				for (fl = 0; fl < 8u; fl += 3u)
					CF(kof_gr_linked(b, n, pc, cc, role, fl) == m_linked(m, pc, cc, role, fl),
					   "kof_gr_linked(%u,%u,%u,%u) disagrees with the model", pc, cc, role, fl);
				CF(kof_gr_entries(b, n, pc, cc, role, 3) == m_entries(m, pc, cc, role, 3) &&
				   kof_gr_entries(b, n, pc, cc, role, 99) == m_entries(m, pc, cc, role, 99),
				   "kof_gr_entries(%u,%u,%u) disagrees with the model", pc, cc, role);
			}
	for (cc = 0; cc <= 4u; cc++) {
		int want = 0;
		uint32_t i;

		for (i = 0; i < m->n; i++)
			want |= m->hit[i].cap == cc;
		CF(kof_gr_has(b, n, cc) == want, "kof_gr_has(%u)", cc);
	}
}

/*
 * Build the graph `m` into a buffer of exactly the size the block needs (`mode` 0: guard page,
 * 1: exact malloc), read it back, compare every record.
 */
static void check_graph(const struct model *m, int mode, const char *what)
{
	struct kgenome_diag_scan s;
	struct he_guard g;
	uint8_t *buf, *spare = NULL;
	uint32_t need = KOF_GR_HDRLEN + m->n * KOF_GR_RECLEN, n, i;
	int cut = any_cut(m);

	memset(&s, 0, sizeof s);
	s.hit = (struct kgenome_diag_hit *)(uintptr_t)m->hit;
	s.n_hit = m->n;
	s.cap_hit = m->n;

	memset(&g, 0, sizeof g);
	if (mode == 0) {
		if (!he_guard_make(&g, NULL, need)) {
			CF(0, "no guard buffer");
			return;
		}
		buf = g.p;
		memset(buf, CANARY, need);      /* stale bytes the builder must overwrite */
	} else {
		buf = malloc(need);
		if (!buf) {
			CF(0, "no memory");
			return;
		}
		memset(buf, CANARY, need);
	}
	n = kof_diag_graph_build(&s, buf, need);
	CF(n == need, "%s: built %u bytes, need %u", what, n, need);
	CF(kgenome_diag_scan_status(&s) == (cut ? KGENOME_TRUNCATED : KGENOME_OK),
	   "%s: status %d, a cut was %s", what, (int)kgenome_diag_scan_status(&s), cut ? "present" : "absent");
	CF(kof_gr_count(buf, n) == m->n, "%s: count %u", what, kof_gr_count(buf, n));
	for (i = 4; i < KOF_GR_HDRLEN; i++)
		CF(buf[i] == 0, "%s: header reserved byte %u", what, i);

	for (i = 0; i < m->n && n == need; i++) {
		const struct kgenome_diag_hit *h = &m->hit[i];
		const uint8_t *r = kof_gr_rec(buf, n, i);
		unsigned k, want_in = h->n_in > KOF_GR_IN_FIT ? KOF_GR_IN_FIT : h->n_in;

		CF(r == buf + KOF_GR_HDRLEN + i * KOF_GR_RECLEN, "%s: record %u address", what, i);
		if (!r)
			continue;
		CF(kof_gr_u64(r, KOF_GR_R_AT) == h->at, "%s: record %u `at` (a neighbour's link wrote it?)", what, i);
		CF(kof_gr_u64(r, KOF_GR_R_ATTR) == h->attr, "%s: record %u `attr`", what, i);
		CF(kof_gr_u16(r, KOF_GR_R_CAP) == h->cap, "%s: record %u cap", what, i);
		CF(kof_gr_u16(r, KOF_GR_R_FLAGS) == h->flags, "%s: record %u flags", what, i);
		CF(r[KOF_GR_R_BITS] == 0, "%s: record %u reserved bits byte", what, i);
		CF(r[KOF_GR_R_NIN] == want_in, "%s: record %u NIN %u, wanted %u", what, i, r[KOF_GR_R_NIN], want_in);
		for (k = 0; k < KOF_GR_IN_FIT; k++) {
			uint8_t role = 0xee, kind = 0xee;
			uint16_t from = kof_gr_in(r, k, &role, &kind);

			if (k < want_in) {
				CF(from == h->in[k].from && role == h->in[k].role && kind == (uint8_t)h->in[k].kind,
				   "%s: record %u link %u read back (from %u role %u kind %u)", what, i, k, from, role,
				   kind);
			} else {
				CF(from == KOF_GR_FROM_NONE && role == 0xee && kind == 0xee,
				   "%s: record %u unused link %u is NONE and writes nothing through the pointers", what,
				   i, k);
				CF(r[KOF_GR_R_IN + k * KOF_GR_IN_STRIDE] == 0 &&
				   r[KOF_GR_R_IN + k * KOF_GR_IN_STRIDE + 1u] == 0 &&
				   r[KOF_GR_R_IN + k * KOF_GR_IN_STRIDE + 2u] == 0 &&
				   r[KOF_GR_R_IN + k * KOF_GR_IN_STRIDE + 3u] == 0,
				   "%s: record %u unused link %u bytes are not zero", what, i, k);
			}
		}
		CF(kof_gr_in(r, KOF_GR_IN_FIT, NULL, NULL) == KOF_GR_FROM_NONE &&
		   kof_gr_in(r, 3, NULL, NULL) == KOF_GR_FROM_NONE, "%s: record %u link 2/3 are not in the block", what, i);
		CF(r[KOF_GR_R_IN + KOF_GR_IN_FIT * KOF_GR_IN_STRIDE] == 0 &&
		   r[KOF_GR_RECLEN - 1u] == 0, "%s: record %u tail bytes", what, i);
	}
	if (n == need)
		check_readers(m, buf, n);

	/* a block with room to spare: nothing beyond `need` is touched */
	if (mode == 1) {
		uint32_t extra = 96u, j;
		struct kgenome_diag_scan s2;

		spare = malloc(need + extra);
		if (spare) {
			memset(spare, CANARY, need + extra);
			memset(&s2, 0, sizeof s2);
			s2.hit = s.hit;
			s2.n_hit = s.n_hit;
			CF(kof_diag_graph_build(&s2, spare, need + extra) == need, "%s: with room to spare", what);
			for (j = need; j < need + extra; j++)
				if (spare[j] != CANARY) {
					CF(0, "%s: byte %u past the block was written", what, j - need);
					break;
				}
			CF(memcmp(spare, buf, need) == 0, "%s: the same block in a larger buffer", what);
			free(spare);
		}
	}
	/* a buffer one byte short refuses the whole block and writes nothing */
	if (need > 1u) {
		struct kgenome_diag_scan s3;
		uint8_t *sh = malloc(need - 1u);

		if (sh) {
			memset(sh, CANARY, need - 1u);
			memset(&s3, 0, sizeof s3);
			s3.hit = s.hit;
			s3.n_hit = s.n_hit;
			CF(kof_diag_graph_build(&s3, sh, need - 1u) == 0 && kgenome_diag_scan_status(&s3) == KGENOME_OK,
			   "%s: one byte short", what);
			{
				uint32_t j, dirty = 0;

				for (j = 0; j < need - 1u; j++)
					dirty += sh[j] != CANARY;
				CF(dirty == 0, "%s: a refused block still wrote %u bytes", what, dirty);
			}
			free(sh);
		}
	}
	if (mode == 0)
		he_guard_free(&g);
	else
		free(buf);
}

/* ---- group 1: every position x every input count ------------------------------------------------ */

static int group_positions(void *arg)
{
	static const uint32_t sizes[] = { 1, 2, 3, 4, 5, 9, 33, 64 };
	uint32_t si;
	struct model *m = calloc(1, sizeof *m);

	(void)arg;
	child_fails = 0;
	if (!m)
		return 9;
	for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
		uint32_t n = sizes[si], pos;
		unsigned nin, base;

		/* one node (first, middle, last, every one) has nin inputs, the others have `base` */
		for (base = 0; base <= 4u; base++)
			for (pos = 0; pos < n; pos++)
				for (nin = 0; nin <= 4u; nin++) {
					uint32_t i;
					char what[64];

					m->n = n;
					for (i = 0; i < n; i++)
						mk_hit(&m->hit[i], i, n, i == pos ? nin : base, 1u + si);
					snprintf(what, sizeof what, "n=%u pos=%u nin=%u base=%u", n, pos, nin, base);
					check_graph(m, (int)((pos + nin) & 1u), what);
				}
		/* and the pattern 0,1,2,3,4,0,1... along the graph, from every start */
		for (base = 0; base < 5u; base++) {
			uint32_t i;
			char what[64];

			m->n = n;
			for (i = 0; i < n; i++)
				mk_hit(&m->hit[i], i, n, (i + base) % 5u, 7u * base);
			snprintf(what, sizeof what, "n=%u cycle from %u", n, base);
			check_graph(m, (int)(base & 1u), what);
		}
	}
	free(m);
	printf("  positions: %u checks in the child, %u failed\n", he_checks, child_fails);
	fflush(stdout);
	return child_fails ? 1 : 0;
}

/* ---- group 2: random graphs against the model ------------------------------------------------- */

static int group_random(void *arg)
{
	unsigned it, iters = *(unsigned *)arg, n_cut = 0;
	struct model *m = calloc(1, sizeof *m);

	child_fails = 0;
	if (!m)
		return 9;
	he_seed(0x6a09e667f3bcc908ull);
	for (it = 0; it < iters; it++) {
		uint32_t n = 1u + he_below(it % 7u == 0 ? MAXN : 12u), i;
		char what[48];

		m->n = n;
		for (i = 0; i < n; i++) {
			struct kgenome_diag_hit *h = &m->hit[i];
			unsigned k, nin = he_below(5u);

			memset(h, 0, sizeof *h);
			h->at = he_next();
			h->attr = he_below(3u) ? he_next() % 4u : 0;
			h->cap = (uint16_t)(1u + he_below(3u));
			h->flags = (uint16_t)he_below(8u);
			h->n_in = (uint8_t)nin;
			for (k = 0; k < 4u; k++) {
				uint32_t pick = he_below(8u);

				h->in[k].from = pick == 0 ? (uint16_t)KOF_GR_FROM_STACK
					      : pick == 1 ? (uint16_t)KOF_GR_FROM_NONE
					      : (uint16_t)he_below(n);
				h->in[k].role = (uint8_t)(1u + he_below(3u));
				h->in[k].kind = he_below(2u) ? KGENOME_DIAG_KIND_SHARED : KGENOME_DIAG_KIND_PRODUCED;
			}
		}
		n_cut += (unsigned)any_cut(m);
		snprintf(what, sizeof what, "random %u", it);
		check_graph(m, (int)(it & 1u), what);
	}
	CF(n_cut > iters / 4u && n_cut < iters, "the random graphs exercise both cut and no cut (%u of %u)", n_cut,
	   iters);
	free(m);
	printf("  random: %u graphs, %u of them with a cut, %u checks, %u failed\n", iters, n_cut, he_checks,
	       child_fails);
	fflush(stdout);
	return child_fails ? 1 : 0;
}

/* ---- group 3: hostile bytes under the readers ------------------------------------------------- */

static int group_readers(void *arg)
{
	struct he_guard g;
	uint32_t it;
	unsigned reps = *(unsigned *)arg;

	child_fails = 0;
	he_seed(0xbb67ae8584caa73bull);
	for (it = 0; it < reps; it++) {
		uint32_t nrec = he_below(6u), need = KOF_GR_HDRLEN + nrec * KOF_GR_RECLEN, i, cut;
		uint8_t *b;
		uint16_t pc, cc;

		if (!he_guard_make(&g, NULL, need))
			return 9;
		b = g.p;
		for (i = 0; i < need; i++)
			b[i] = (uint8_t)he_next();
		/* the header count: honest, short, or wild */
		switch (he_below(4u)) {
		case 0:
			b[0] = (uint8_t)nrec;
			b[1] = b[2] = b[3] = 0;
			break;
		case 1:
			b[0] = (uint8_t)(nrec ? nrec - 1u : 0);
			b[1] = b[2] = b[3] = 0;
			break;
		case 2:
			b[0] = b[1] = b[2] = b[3] = 0xff;
			break;
		default:
			b[0] = (uint8_t)(nrec + 1u + he_below(200u));
			b[1] = b[2] = b[3] = 0;
		}
		/* any NIN, any from, any role: nothing may be read past the record that holds it */
		cut = need;
		for (cc = 0; cc < 4u; cc++)
			for (pc = 0; pc < 4u; pc++) {
				volatile int sink = kof_gr_linked(b, cut, pc, cc, (uint8_t)(1u + he_below(3u)), 0) +
						    (int)kof_gr_entries(b, cut, pc, cc, 1, 99) + kof_gr_has(b, cut, cc);
				(void)sink;
			}
		for (i = 0; i < 8u; i++) {
			const uint8_t *r = kof_gr_rec(b, need, i);
			unsigned k;

			if (!r)
				continue;
			CF(r >= b && r + KOF_GR_RECLEN <= b + need, "record %u lies inside the block", i);
			for (k = 0; k < 10u; k++)
				(void)kof_gr_in(r, k, NULL, NULL);
			(void)kof_gr_u64(r, KOF_GR_R_AT);
			(void)kof_gr_u64(r, KOF_GR_R_ATTR);
			(void)kof_gr_u16(r, KOF_GR_R_CAP);
			(void)kof_gr_u16(r, KOF_GR_R_FLAGS);
		}
		/* a length that holds fewer records than the count says: refused, not read */
		if (nrec) {
			uint32_t cnt = kof_gr_count(b, need);

			CF(kof_gr_rec(b, need - 1u, nrec - 1u) == NULL || cnt <= nrec - 1u,
			   "a block cut by one byte does not hand out its last record");
		}
		he_guard_free(&g);
	}
	printf("  readers: %u hostile blocks, %u checks, %u failed\n", reps, he_checks, child_fails);
	fflush(stdout);
	return child_fails ? 1 : 0;
}

static void run_group(const char *name, int (*fn)(void *), void *arg, unsigned secs)
{
	struct he_status st = he_child(fn, arg, secs);

	he_checks++;
	if (!he_ok(st)) {
		printf("  FAIL %s: %s\n", name, he_how(st));
		he_fails++;
	}
}

int main(void)
{
	unsigned rnd = 4000, rdr = 3000;

	/* the geometry the builder relies on, stated once */
	CK(KOF_GR_IN_FIT == 2 && KOF_GR_IN_MAX == 4, "KOF_GR_IN_FIT %u, KOF_GR_IN_MAX %u", KOF_GR_IN_FIT, KOF_GR_IN_MAX);
	CK(KOF_GR_R_IN + KOF_GR_IN_FIT * KOF_GR_IN_STRIDE <= KOF_GR_RECLEN, "the links the record holds end inside it");
	CK(KOF_GR_R_IN + (KOF_GR_IN_FIT + 1u) * KOF_GR_IN_STRIDE > KOF_GR_RECLEN, "a third link would not");
	CK(sizeof(((struct kgenome_diag_hit *)0)->in) / sizeof(((struct kgenome_diag_hit *)0)->in[0]) == KOF_GR_IN_MAX,
	   "a node of the scan keeps KOF_GR_IN_MAX inputs");

	run_group("every position x every input count", group_positions, NULL, 20);
	run_group("random graphs against the model", group_random, &rnd, 20);
	run_group("hostile bytes under the inline readers", group_readers, &rdr, 20);

	/* a node with MORE than four inputs claimed (n_in is a byte): only the two that fit are read */
	{
		struct kgenome_diag_scan s;
		struct kgenome_diag_hit h[2];
		struct he_guard g;
		uint32_t need = KOF_GR_HDRLEN + 2u * KOF_GR_RECLEN;

		memset(&s, 0, sizeof s);
		mk_hit(&h[0], 0, 2, 1, 1);
		mk_hit(&h[1], 1, 2, 4, 1);
		h[1].n_in = 200;
		s.hit = h;
		s.n_hit = 2;
		CK(he_guard_make(&g, NULL, need) && kof_diag_graph_build(&s, g.p, need) == need &&
		   g.p[KOF_GR_HDRLEN + KOF_GR_RECLEN + KOF_GR_R_NIN] == KOF_GR_IN_FIT &&
		   kgenome_diag_scan_status(&s) == KGENOME_TRUNCATED, "n_in 200 is clamped to what fits and noted");
		he_guard_free(&g);
	}
	printf("diag_graph_block: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
