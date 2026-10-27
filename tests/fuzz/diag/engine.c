/*
 * diag/engine - the engine's side of the diagnose graph: the record a pack carries (kof_diag_load), the matcher that walks it over a scan
 * (kof_diag_match_known, kof_diag_scan_name, kof_diag_flow_join) and the graph block a rule reads (kof_diag_graph_build, the kof_gr_* readers
 * of kofmod/kofdiagtree.h).
 *
 * The two rows are the "round trip of the graph block layout, corrupted blocks give a status and never a crash" row of the stage:
 *
 *   engine/diag_record   the input is a diag-<kind>.kdig RECORD. Raw mode: the bytes are loaded as they are (the mutators bend lengths, parents,
 *                        roles, the attribute runs and the tagged sections); held: the load answers 0 or a diagnose that satisfies everything the
 *                        loader says it checks (one root, parents inside, roles in the enum, strings inside the stores, the users window inside
 *                        the record, counts inside the arrays), a record that loads is matched against the scans without a fault and loading it again
 *                        gives the same diagnose. Spec mode (first byte >= 0x80): a diagnose built from the bytes is ENCODED by the model writer
 *                        below (written from the format's comments, not from the loader) and must LOAD, field for field (ROUND TRIP).
 *   engine/diag_block    the input is a scan the adapter makes of its bytes (a node per 8 bytes: cap, flags, up to four inputs); the block is built
 *                        in buffers of exactly the size, one less and one more, read back through the kofmod readers against a model of the hits,
 *                        then the SAME block is corrupted (count, link count, link indexes, truncation at every length class) and every reader is
 *                        run on it: a read past the end of the buffer is a fault of the exact-size allocation.
 *
 * The loader is called with the store the pack loader gives it (64 nodes, a 256-byte name, a string store the size of the record).
 */
#include "diag_seed.h"

#include "../../../libkofeng/detectors/linkage/kofdiag.h"
#include <kofmod/kofdiagtree.h>
#include <phenotype/diag_scan_state.h>

/* ---- the model writer ---------------------------------------------------------------------------------------------------------- */

struct wr {
	uint8_t  b[2048];
	unsigned n;
};

static void w8(struct wr *w, unsigned v)
{
	if (w->n < sizeof w->b)
		w->b[w->n++] = (uint8_t)v;
}

static void w16(struct wr *w, unsigned v)
{
	w8(w, v & 0xffu);
	w8(w, v >> 8);
}

static void w64(struct wr *w, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		w8(w, (unsigned)(v >> (8u * i)) & 0xffu);
}

static void wn(struct wr *w, const void *p, unsigned n)
{
	if (w->n + n <= sizeof w->b) {
		memcpy(w->b + w->n, p, n);
		w->n += n;
	}
}

struct nspec {
	uint16_t cap, flags;
	uint8_t  parent, role, bits;
	int      has_val, has_sym;
	uint64_t val;
	char     sym[24];
};

struct spec {
	unsigned     n_node;
	uint8_t      analysis;
	char         name[40];
	struct nspec node[8];
	unsigned     n_need;            /* the sign words of the old section: skipped */
	unsigned     n_needcap;
	uint16_t     needcap[4];
	int          has_seq;
	uint16_t     seq_first, seq_then;
	int          has_dis;
	uint32_t     disease;
	uint8_t      dtype;
	unsigned     n_when;
	uint16_t     when_fact[4];
	uint64_t     when_val[4];
	int          has_users;
	unsigned     n_ref;
	char         ref[3][16];
};

static void encode(struct wr *w, const struct spec *s)
{
	unsigned i;
	unsigned nl = (unsigned)strlen(s->name);

	w->n = 0;
	w16(w, s->n_node);
	w8(w, s->analysis);
	w8(w, nl);
	wn(w, s->name, nl);
	for (i = 0; i < s->n_node; i++) {
		const struct nspec *p = &s->node[i];
		struct wr a = { { 0 }, 0 };

		if (p->has_sym) {
			w8(&a, KDIG_ATTR_SYM);
			w8(&a, (unsigned)strlen(p->sym));
			wn(&a, p->sym, (unsigned)strlen(p->sym));
		}
		if (p->has_val) {
			w8(&a, KDIG_ATTR_VALUE);
			w8(&a, 8);
			w64(&a, p->val);
		}
		w16(w, p->cap);
		w16(w, p->flags);
		w8(w, p->parent);
		w8(w, p->role);
		w8(w, p->bits);
		w8(w, a.n);
		wn(w, a.b, a.n);
	}
	/* the sign words of the old section (a count, then length-prefixed names) and the tagged sections after them */
	w8(w, s->n_need);
	for (i = 0; i < s->n_need; i++) {
		w8(w, 3);
		wn(w, "abc", 3);
	}
	if (s->n_needcap) {
		w8(w, KDIG_SEC_NEEDS);
		w8(w, 2u * s->n_needcap);
		for (i = 0; i < s->n_needcap; i++)
			w16(w, s->needcap[i]);
	}
	if (s->has_seq) {
		w8(w, KDIG_SEC_SEQUENCE);
		w8(w, 4);
		w16(w, s->seq_first);
		w16(w, s->seq_then);
	}
	if (s->has_dis) {
		w8(w, KDIG_SEC_DISEASE);
		w8(w, 5);
		w16(w, s->disease & 0xffffu);
		w16(w, s->disease >> 16);
		w8(w, s->dtype);
	}
	if (s->n_when) {
		w8(w, KDIG_SEC_WHEN);
		w8(w, 10u * s->n_when);
		for (i = 0; i < s->n_when; i++) {
			w16(w, s->when_fact[i]);
			w64(w, s->when_val[i]);
		}
	}
	if (s->has_users) {
		w8(w, KDIG_SEC_USERS);
		w8(w, 2);
		w8(w, 1);
		w8(w, 0);
	}
	if (s->n_ref) {
		struct wr a = { { 0 }, 0 };

		w8(&a, s->n_ref);
		for (i = 0; i < s->n_ref; i++) {
			w8(&a, (unsigned)strlen(s->ref[i]));
			wn(&a, s->ref[i], (unsigned)strlen(s->ref[i]));
		}
		w8(w, KDIG_SEC_REFS);
		w8(w, a.n);
		wn(w, a.b, a.n);
	}
	w8(w, 0x7f);                              /* a tag this build does not know: skipped by its length */
	w8(w, 3);
	wn(w, "xyz", 3);
}

/* the next byte of the input, then random ones: one call a statement, so that the order the bytes are read in is the code's and not the compiler's */
static uint8_t nxt(const uint8_t *in, size_t n, unsigned *k, struct fz_rng *r) FZ_UNUSED;
static uint8_t nxt(const uint8_t *in, size_t n, unsigned *k, struct fz_rng *r)
{
	return *k < n ? in[(*k)++] : (uint8_t)fz_below(r, 256);
}

/* a spec from the bytes of the input (after the mode byte): always one the loader must accept */
static void spec_of(struct spec *s, const uint8_t *in, size_t n, struct fz_rng *r)
{
	unsigned i, k = 1;
	static const uint16_t caps[] = { KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_WRITE, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_EXEC_IMAGE, 1, 2, 3, 40 };
#define NEXT() nxt(in, n, &k, r)

	memset(s, 0, sizeof *s);
	s->n_node = 1u + NEXT() % 8u;
	s->analysis = (uint8_t)(NEXT() & 0x1fu);
	{
		unsigned a = NEXT(), b2 = NEXT();

		snprintf(s->name, sizeof s->name, "d%02x%02x", a, b2);
	}
	for (i = 0; i < s->n_node; i++) {
		struct nspec *p = &s->node[i];

		p->cap = caps[NEXT() % (sizeof caps / sizeof caps[0])];
		p->flags = (uint16_t)(NEXT() & 7u);
		p->parent = (uint8_t)(i ? (unsigned)NEXT() % i : (unsigned)KOF_DIAG_NO_PARENT);
		p->role = (uint8_t)(NEXT() % KGENOME_DIAG_ROLE_COUNT);
		p->bits = (uint8_t)(NEXT() & 0xfu);
		if (NEXT() & 1u) {
			uint64_t hi = NEXT(), lo = NEXT();

			p->has_val = 1;
			p->val = (hi << 8) | lo;
		}
		if (NEXT() & 1u) {
			p->has_sym = 1;
			snprintf(p->sym, sizeof p->sym, "sym_%u", NEXT());
		}
	}
	s->n_need = NEXT() % 3u;
	s->n_needcap = NEXT() % 4u;
	for (i = 0; i < s->n_needcap; i++)
		s->needcap[i] = caps[NEXT() % (sizeof caps / sizeof caps[0])];
	if (NEXT() & 1u) {
		s->has_seq = 1;
		s->seq_first = 1u + (uint16_t)(NEXT() % 20u);
		s->seq_then = 1u + (uint16_t)(NEXT() % 20u);
	}
	if (NEXT() & 1u) {
		s->has_dis = 1;
		{
			uint32_t hi = NEXT(), lo = NEXT();

			s->disease = 1u + ((hi << 8) | lo);
		}
		s->dtype = (uint8_t)(NEXT() % KOF_MALTYPE_COUNT);
	}
	s->n_when = NEXT() % 4u;
	for (i = 0; i < s->n_when; i++) {
		s->when_fact[i] = (uint16_t)(1u + NEXT() % (KOF_FACT_COUNT - 1u));
		s->when_val[i] = NEXT();
	}
	s->has_users = NEXT() & 1u;
	s->n_ref = NEXT() % 3u;
	for (i = 0; i < s->n_ref; i++)
		snprintf(s->ref[i], sizeof s->ref[i], "ref_%u", NEXT());
#undef NEXT
}

/* ---- the scans a loaded diagnose is matched against (made once, outside the armed region) ---------------------------------------- */

static struct kgenome_diag_scan *scans[3];
static struct kgenome_obj sobj;
static struct kgenome_elf_info sei;
static uint8_t simg[DS_CODE_MAX + 0x100];

static void make_scans(void)
{
	static struct ds_code code;
	static const char php[] = "<?php $x = $_GET[0]; system($x); eval($x);\n";
	struct kgenome_diag_text_req rq;
	unsigned n;

	if (scans[0])
		return;
	ds_prog(&code, 0);
	n = ds_elf64(simg, &code, 0x3e);
	if (kgenome_elf_image_parse(kof_buf_make(simg, n), &sei, &sobj)) {
		sobj.file_header = &sei;
		scans[0] = kgenome_diag_scan_with(&sobj, simg, n, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL);
	}
	ds_prog(&code, 2);
	n = ds_elf64(simg + 0x400, &code, 0x3e);
	memset(&rq, 0, sizeof rq);
	rq.base = (const uint8_t *)php;
	rq.size = sizeof php - 1u;
	rq.lang = KGENOME_TEXTUAL_LANG_PHP;
	scans[1] = kgenome_diag_scan_text(&rq);
	(void)n;
	/* the matcher keeps a flow index on the scan it first joins over (built once, freed with the scan): built here, outside the armed region,
	 * so that the leak check of the row sees the allocations of the CALL and not the scan's own cache */
	{
		unsigned k;
		uint16_t b0[1] = { 0 };

		for (k = 0; k < 2u; k++)
			if (scans[k])
				(void)kof_diag_flow_join(scans[k], KGENOME_NUCLEO_WRITE, b0, 1, b0, 1);
	}
}

/* ---- the record row ------------------------------------------------------------------------------------------------------------ */

/* A record whose tagged sections repeat: `reps` WHEN sections of `each` conditions (each section is under the bound, the sum is not). */
static unsigned rec_when_twice(uint8_t *b, unsigned reps, unsigned each)
{
	struct wr w;
	unsigned i, r;

	w.n = 0;
	w16(&w, 1); w8(&w, 1); w8(&w, 1); w8(&w, 'a');
	w16(&w, KGENOME_NUCLEO_NET_OPEN); w16(&w, 0); w8(&w, KOF_DIAG_NO_PARENT); w8(&w, 0); w8(&w, 0); w8(&w, 0);
	w8(&w, 0);                                                /* no sign words: the tagged sections follow */
	for (r = 0; r < reps; r++) {
		w8(&w, KDIG_SEC_WHEN);
		w8(&w, 10u * each);
		for (i = 0; i < each; i++) {
			w16(&w, 1);
			w64(&w, i);
		}
	}
	memcpy(b, w.b, w.n);
	return w.n;
}

static void seeds_rec(struct fz_corpus *c)
{
	uint8_t two[1024];
	unsigned tn;

	struct spec s;
	struct wr w;
	uint8_t src[320];
	unsigned i;

	make_scans();
	tn = rec_when_twice(two, 1, 16);
	fz_corpus_add(c, "when-1x16", two, tn);
	for (i = 0; i < 24u; i++) {
		memset(src, 0, sizeof src);
		src[0] = 0x80u;
		src[1] = (uint8_t)(i % 8u);
		memset(src + 2, (int)(i * 11u + 3u), sizeof src - 2u);
		spec_of(&s, src, sizeof src, NULL);
		/* a diagnose that matches the socket/write seed: net-open, a write below it by the descriptor */
		if (i % 3u == 0) {
			s.n_node = 2;
			s.node[0].cap = KGENOME_NUCLEO_NET_OPEN; s.node[0].parent = KOF_DIAG_NO_PARENT; s.node[0].role = 0;
			s.node[1].cap = KGENOME_NUCLEO_NET_WRITE; s.node[1].parent = 0; s.node[1].role = KGENOME_DIAG_ROLE_FD;
		}
		encode(&w, &s);
		fz_corpus_add(c, "rec", w.b, w.n);
	}
}

static const char *const dict_rec[] = { "\x01\x00", "\xff\xff", "\x00\x00\x00\x00", "\x08\x05", "\x07\x04", "\x02\x0a", "\x06\x04", "\x03\x02", "\x04\x08", "\xfe", "\xff", NULL };

static int same_diag(const struct kof_diag *a, const struct kof_diag *b)
{
	uint8_t i;

	if (a->analysis != b->analysis || a->n_node != b->n_node || a->n_needcap != b->n_needcap || a->seq_first != b->seq_first ||
	    a->seq_then != b->seq_then || a->n_when != b->n_when || a->users_known != b->users_known || a->n_users != b->n_users ||
	    a->users_off != b->users_off || a->users_len != b->users_len || a->n_ref != b->n_ref || a->disease != b->disease ||
	    a->disease_type != b->disease_type || strcmp(a->name, b->name))
		return 0;
	for (i = 0; i < a->n_node; i++)
		if (a->node[i].cap != b->node[i].cap || a->node[i].flags != b->node[i].flags || a->node[i].parent != b->node[i].parent ||
		    a->node[i].role != b->node[i].role || a->node[i].bits != b->node[i].bits || a->node[i].val != b->node[i].val ||
		    !!a->node[i].sym != !!b->node[i].sym || (a->node[i].sym && strcmp(a->node[i].sym, b->node[i].sym)))
			return 0;
	return 1;
}

/*
 * THE CONDITIONS A RECORD STATES IN ALL, read by a second parser of the record grammar that follows the loader's own order (nodes with their
 * attribute runs, the sign words, the tagged sections) and counts the pairs of every WHEN section. -1 when the record is one the loader refuses
 * on its structure before the tagged sections end. It exists because of F12: kofdiag.c bounds ONE WHEN section by KOF_DIAG_MAX_WHEN and appends
 * the pairs of each section to the same array, so two sections of sixteen write 32 entries into 16 (tests/unit/diag_load_known_misses.c). The row
 * does not hand such a record to the loader (the sanitised build stops there, and so does a real one with a sufficiently unlucky neighbour),
 * and counts it in the digest, so that the row goes on exercising everything else and a change of the loader's behaviour shows as a change of digest.
 */
static int model_when_total(const uint8_t *b, size_t n)
{
	size_t at;
	unsigned n_node, nlen, i, total = 0, cnt, k;

	if (n < 4u)
		return -1;
	n_node = (unsigned)b[0] | ((unsigned)b[1] << 8);
	nlen = b[3];
	if (!n_node || n_node > KOF_DIAG_MAX_NODE || nlen + 1u > 256u)
		return -1;
	at = 4u + nlen;
	if (n < at || (n - at) / 8u < n_node)
		return -1;
	for (i = 0; i < n_node; i++) {
		unsigned alen;

		if (at + 8u > n)
			return -1;
		alen = b[at + 7u];
		at += 8u;
		if (at + alen > n)
			return -1;
		at += alen;
	}
	if (at >= n)
		return 0;
	cnt = b[at++];
	if (cnt > KOF_DIAG_MAX_NEED)
		return -1;
	for (k = 0; k < cnt; k++) {
		unsigned L;

		if (at >= n)
			return -1;
		L = b[at++];
		if (!L || L >= KOF_DIAG_NEED_LEN || at + L > n)
			return -1;
		at += L;
	}
	while (at + 2u <= n) {
		unsigned tag = b[at], len = b[at + 1u];

		at += 2u;
		if (at + len > n)
			return (int)total;                /* the loader has written the pairs of the sections before this one by now */
		if (tag == KDIG_SEC_WHEN) {
			if (len % 10u)
				return (int)total;
			total += len / 10u;
			if (total > KOF_DIAG_MAX_WHEN)
				return (int)total;        /* the loader writes the pairs as it reads them: past the array before it can refuse */
		}
		at += len;
	}
	return (int)total;
}

static int run_rec(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static struct kof_diag_node node[2][KOF_DIAG_MAX_NODE];
	static char name[2][256], needs[2][4096];
	struct kof_diag d[2];
	struct kof_diag_store st[2];
	struct wr w;
	struct spec sp;
	int ok, k, spec_mode = n && (in[0] & 0x80u);
	const uint8_t *rec = in;
	size_t rl = n;

	memset(d, 0, sizeof d);
	memset(node, 0, sizeof node);             /* the pack loader's stores are calloc'd and each slice is used once: the loader does not clear a node's val and sym (finding F13) */
	memset(name, 0, sizeof name);
	memset(needs, 0, sizeof needs);
	for (k = 0; k < 2; k++) {
		st[k].node = node[k];
		st[k].name = name[k];
		st[k].needs = needs[k];
		st[k].name_cap = sizeof name[k];
		st[k].needs_cap = (uint32_t)(rl < sizeof needs[k] - 1u ? rl + 1u : sizeof needs[k]);
		st[k].max_node = KOF_DIAG_MAX_NODE;
	}
	if (spec_mode) {
		spec_of(&sp, in, n, c->rng);
		encode(&w, &sp);
		rec = w.b;
		rl = w.n;
		for (k = 0; k < 2; k++)
			st[k].needs_cap = (uint32_t)(rl + 1u);
	}
	if (model_when_total(rec, rl) > (int)KOF_DIAG_MAX_WHEN) {
		fz_digest(c, 0xf12u);                     /* F12: not handed to the loader */
		return 3;
	}
	ok = kof_diag_load(kof_buf_make(rec, rl), &d[0], &st[0]);
	if (spec_mode) {
		unsigned i;

		FZ_CHECK(c, ok == 1, "ROUND TRIP: the model writer's record is refused by the loader");
		if (ok == 1) {
			FZ_CHECK(c, d[0].n_node == sp.n_node && d[0].analysis == sp.analysis && !strcmp(d[0].name, sp.name), "ROUND TRIP: header fields changed");
			for (i = 0; i < sp.n_node && ok == 1; i++) {
				const struct kof_diag_node *q = &d[0].node[i];

				FZ_CHECK(c, q->cap == sp.node[i].cap && q->flags == sp.node[i].flags && q->parent == sp.node[i].parent &&
					 q->role == sp.node[i].role && q->bits == sp.node[i].bits, "ROUND TRIP: a node's fields changed");
				FZ_CHECK(c, !sp.node[i].has_val || q->val == sp.node[i].val, "ROUND TRIP: a node's value changed");
				FZ_CHECK(c, !sp.node[i].has_sym || (q->sym && !strcmp(q->sym, sp.node[i].sym)), "ROUND TRIP: a node's symbol changed");
			}
			FZ_CHECK(c, d[0].n_needcap == sp.n_needcap, "ROUND TRIP: the needed capabilities changed");
			for (i = 0; i < sp.n_needcap; i++)
				FZ_CHECK(c, d[0].needcap[i] == sp.needcap[i], "ROUND TRIP: a needed capability changed");
			FZ_CHECK(c, d[0].seq_first == (sp.has_seq ? sp.seq_first : 0u) && d[0].seq_then == (sp.has_seq ? sp.seq_then : 0u), "ROUND TRIP: the sequence changed");
			FZ_CHECK(c, d[0].disease == (sp.has_dis ? sp.disease : 0u) && (!sp.has_dis || d[0].disease_type == sp.dtype), "ROUND TRIP: the disease changed");
			FZ_CHECK(c, d[0].n_when == sp.n_when, "ROUND TRIP: the conditions changed in number");
			for (i = 0; i < sp.n_when && i < d[0].n_when; i++)
				FZ_CHECK(c, d[0].when[i].fact == sp.when_fact[i] && d[0].when[i].val == sp.when_val[i], "ROUND TRIP: a condition changed");
			FZ_CHECK(c, d[0].users_known == (sp.has_users ? 1u : 0u), "ROUND TRIP: the users section changed");
			FZ_CHECK(c, d[0].n_ref == sp.n_ref, "ROUND TRIP: the references changed in number");
			for (i = 0; i < sp.n_ref && i < d[0].n_ref; i++)
				FZ_CHECK(c, d[0].ref[i] && !strcmp(d[0].ref[i], sp.ref[i]), "ROUND TRIP: a reference changed");
		}
	}
	if (ok != 1) {
		FZ_CHECK(c, ok == 0, "kof_diag_load answered neither 0 nor 1");
		fz_digest(c, 0xd0d0u);
		return 1;
	}
	{
		uint8_t i, roots = 0;
		uint32_t q;

		FZ_CHECK(c, d[0].n_node >= 1 && d[0].n_node <= KOF_DIAG_MAX_NODE, "a loaded diagnose with a node count outside 1..max");
		for (i = 0; i < d[0].n_node; i++) {
			const struct kof_diag_node *p = &d[0].node[i];

			roots = (uint8_t)(roots + (p->parent == KOF_DIAG_NO_PARENT));
			FZ_CHECK(c, p->parent == KOF_DIAG_NO_PARENT || (p->parent < d[0].n_node && p->parent != i), "a loaded node with a parent that is not a node, or itself");
			FZ_CHECK(c, p->role < KGENOME_DIAG_ROLE_COUNT, "a loaded node with a role outside the enum");
			if (p->sym)
				FZ_CHECK(c, p->sym >= needs[0] && p->sym < needs[0] + sizeof needs[0] && strlen(p->sym) < sizeof needs[0], "a node's symbol outside the string store");
		}
		FZ_CHECK(c, roots == 1u, "a loaded diagnose without exactly one root");
		FZ_CHECK(c, strlen(d[0].name) < sizeof name[0], "a loaded name without its terminator");
		FZ_CHECK(c, d[0].n_needcap <= KOF_DIAG_MAX_NEED, "more needed capabilities than the array");
		FZ_CHECK(c, d[0].n_when <= KOF_DIAG_MAX_WHEN, "more conditions than the array holds");
		FZ_CHECK(c, d[0].n_ref <= KOF_DIAG_MAX_NEED, "more references than the array");
		FZ_CHECK(c, !d[0].users_known || (d[0].users_off + (uint64_t)d[0].users_len <= rl), "the users window leaves the record");
		for (q = 0; q < d[0].n_when && q < KOF_DIAG_MAX_WHEN; q++)
			FZ_CHECK(c, d[0].when[q].fact && d[0].when[q].fact < KOF_FACT_COUNT, "a condition on a fact that does not exist");
		for (q = 0; q < d[0].n_ref && q < KOF_DIAG_MAX_NEED; q++)
			FZ_CHECK(c, d[0].ref[q] >= needs[0] && d[0].ref[q] < needs[0] + sizeof needs[0], "a reference outside the string store");
		FZ_CHECK(c, !d[0].disease || d[0].disease_type < KOF_MALTYPE_COUNT, "a disease type outside the enum");
	}
	/* loading again gives the same diagnose */
	if (kof_diag_load(kof_buf_make(rec, rl), &d[1], &st[1]) == 1)
		FZ_CHECK(c, same_diag(&d[0], &d[1]), "loading one record twice gave two diagnoses");
	else
		FZ_CHECK(c, 0, "a record that loaded does not load the second time");
	/* the matcher on what loaded */
	for (k = 0; k < 2; k++) {
		uint16_t bind[KOF_DIAG_MAX_NODE];
		uint8_t nb = 0;
		int r;

		if (!scans[k])
			continue;
		r = kof_diag_match_known(scans[k], &d[0], bind, &nb);
		FZ_CHECK(c, r == KOF_DIAG_MATCH_YES || r == KOF_DIAG_MATCH_NO || r == KOF_DIAG_MATCH_UNKNOWN, "kof_diag_match_known answered outside -1/0/1");
		if (r == KOF_DIAG_MATCH_YES) {
			uint8_t i;

			FZ_CHECK(c, nb <= d[0].n_node, "more bound nodes than the diagnose has");
			for (i = 0; i < nb && i < KOF_DIAG_MAX_NODE; i++)
				FZ_CHECK(c, bind[i] < kgenome_diag_scan_count(scans[k]), "a bound node that is not a node of the scan");
			FZ_CHECK(c, kof_diag_match(scans[k], &d[0], NULL, NULL) == 1, "kof_diag_match says no where kof_diag_match_known said yes");
			(void)kof_diag_flow_join(scans[k], KGENOME_NUCLEO_WRITE, bind, nb, bind, nb);
		}
		(void)kof_diag_scan_name(scans[k], &d[0], "system");
		fz_digest(c, (uint64_t)(unsigned)(r + 1) + ((uint64_t)nb << 8));
	}
	fz_digest(c, d[0].n_node + ((uint64_t)d[0].n_when << 8) + ((uint64_t)d[0].n_ref << 16));
	return 0;
}

FZ_ADAPTER(diag_record, .name = "engine/diag_record", .covers = "", .flags = FZ_NO_FAILK, .backstop_s = 3000, .shape = FZ_REQ,
	   .seeds = seeds_rec, .dict = dict_rec, .run = run_rec);

/* ---- the block row ------------------------------------------------------------------------------------------------------------- */

static void seeds_blk(struct fz_corpus *c)
{
	uint8_t b[260];
	unsigned i;

	for (i = 0; i < 16u; i++) {
		memset(b, (int)(i * 17u + 5u), sizeof b);
		b[0] = (uint8_t)(1u + i % 9u);          /* the node count */
		fz_corpus_add(c, "blk", b, sizeof b);
	}
}

#define BMAX 64u

struct bmodel {
	struct kgenome_diag_hit hit[BMAX];
	uint32_t n;
};

static unsigned nb(const uint8_t *in, size_t n, size_t *at) FZ_UNUSED;
static unsigned nb(const uint8_t *in, size_t n, size_t *at)
{
	return *at < n ? in[(*at)++] : 0u;
}

static void model_of(struct bmodel *m, const uint8_t *in, size_t n)
{
	uint32_t i, k;
	size_t at = 1;
#define NB() nb(in, n, &at)

	memset(m, 0, sizeof *m);
	m->n = 1u + (n ? in[0] : 0u) % BMAX;
	for (i = 0; i < m->n; i++) {
		struct kgenome_diag_hit *h = &m->hit[i];

		{
			uint64_t hi = NB(), lo = NB(), a = NB(), sh = NB() % 8u;

			h->at = (hi << 8) | lo;
			h->attr = a << (8u * sh);
		}
		h->cap = (uint16_t)(1u + NB() % 4u);
		h->flags = (uint16_t)(NB() & 7u);
		h->n_in = (uint8_t)(NB() % 5u);
		for (k = 0; k < h->n_in; k++) {
			unsigned pick = NB() % 8u;

			h->in[k].from = (uint16_t)(pick == 6u ? (unsigned)KOF_GR_FROM_STACK : pick == 7u ? (unsigned)KOF_GR_FROM_NONE : (unsigned)NB() % m->n);
			h->in[k].role = (uint8_t)(1u + NB() % 3u);
			h->in[k].kind = (NB() & 1u) ? KGENOME_DIAG_KIND_SHARED : KGENOME_DIAG_KIND_PRODUCED;
		}
	}
#undef NB
}

static int m_linked(const struct bmodel *m, uint16_t pc, uint16_t cc, uint8_t role, uint16_t flags)
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

/* every reader on a buffer of exactly n bytes; the answers are read, not compared: the point is that none of them reads past it */
static void readers(struct fz_ctx *c, const uint8_t *b, uint32_t n)
{
	uint32_t cnt = kof_gr_count(b, n), i, k;
	uint16_t pc, cc;

	for (i = 0; i < cnt && i < 80u; i++) {
		const uint8_t *r = kof_gr_rec(b, n, i);

		if (!r) {
			FZ_CHECK(c, (uint64_t)KOF_GR_HDRLEN + (uint64_t)(i + 1u) * KOF_GR_RECLEN > n || i >= cnt, "kof_gr_rec refused a record that lies inside the buffer");
			break;
		}
		FZ_CHECK(c, r >= b && r + KOF_GR_RECLEN <= b + n, "kof_gr_rec answered a record that is not inside the buffer");
		(void)kof_gr_u64(r, KOF_GR_R_AT);
		(void)kof_gr_u64(r, KOF_GR_R_ATTR);
		(void)kof_gr_u16(r, KOF_GR_R_CAP);
		for (k = 0; k < 5u; k++) {
			uint8_t ro = 0, kind = 0;
			uint16_t from = kof_gr_in(r, k, &ro, &kind);

			FZ_CHECK(c, k < KOF_GR_IN_FIT || from == KOF_GR_FROM_NONE, "an input past the record's fit");
		}
	}
	FZ_CHECK(c, kof_gr_rec(b, n, cnt) == NULL, "a record past the count");
	for (pc = 0; pc < 5u; pc++)
		for (cc = 0; cc < 5u; cc += 2u) {
			(void)kof_gr_linked(b, n, pc, cc, 1, 0);
			(void)kof_gr_linked(b, n, pc, cc, 3, 7);
			(void)kof_gr_entries(b, n, pc, cc, 2, 16);
			(void)kof_gr_entries(b, n, pc, cc, 2, 1000);
		}
	(void)kof_gr_has(b, n, 1);
	(void)kof_gr_has(b, n, 0xffff);
	(void)kof_gr_count(NULL, 0);
	(void)kof_gr_rec(NULL, 0, 0);
	(void)kof_gr_in(NULL, 0, NULL, NULL);
}

static int run_blk(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct bmodel m;
	struct kgenome_diag_scan s;
	uint32_t need, k, cap;
	uint8_t *buf;
	int any_cut = 0;
	uint32_t i;

	if (n < 2)
		return 1;
	model_of(&m, in, n);
	for (i = 0; i < m.n; i++)
		any_cut |= m.hit[i].n_in > KOF_GR_IN_FIT;
	memset(&s, 0, sizeof s);
	s.hit = m.hit;
	s.n_hit = m.n;
	s.cap_hit = m.n;
	need = KOF_GR_HDRLEN + m.n * KOF_GR_RECLEN;
	/* the builder: exactly the size it needs, one less (refused whole), one more (the tail is not touched) */
	for (k = 0; k < 3u; k++) {
		uint32_t got;

		cap = k == 0 ? need : k == 1 ? need - 1u : need + 1u;
		buf = (uint8_t *)malloc(cap);
		if (!buf)
			return 2;
		memset(buf, 0xa5, cap);
		s.status = KGENOME_OK;
		got = kof_diag_graph_build(&s, buf, cap);
		if (k == 1) {
			FZ_CHECK(c, got == 0, "the builder wrote a block into a buffer one byte short");
		} else {
			FZ_CHECK(c, got == need, "the builder did not write the block it needs");
			if (got == need) {
				uint32_t q;

				FZ_CHECK(c, kof_gr_count(buf, got) == m.n, "the block's count is not the node count");
				FZ_CHECK(c, (s.status == KGENOME_TRUNCATED) == (any_cut != 0), "the cut is said exactly when a node has more inputs than a record holds");
				for (q = 0; q < 8u; q++) {
					uint16_t pc = (uint16_t)(1u + q % 4u), cc = (uint16_t)(1u + (q / 2u) % 4u);

					FZ_CHECK(c, kof_gr_linked(buf, got, pc, cc, (uint8_t)(1u + q % 3u), (uint16_t)(q & 7u)) ==
						 m_linked(&m, pc, cc, (uint8_t)(1u + q % 3u), (uint16_t)(q & 7u)), "ROUND TRIP: kof_gr_linked disagrees with the model of the hits");
				}
				readers(c, buf, got);
				if (k == 0) {
					/* the same block, corrupted: bytes bent in the header and the records, then cut at a length the rng picks */
					uint8_t *cb;
					uint32_t flips = 1u + (uint32_t)fz_below(c->rng, 12), cut;

					for (q = 0; q < flips; q++) {
						uint32_t at = fz_below(c->rng, 2) ? (uint32_t)fz_below(c->rng, KOF_GR_HDRLEN + 32u) : (uint32_t)fz_below(c->rng, got);

						if (at < got)
							buf[at] = (uint8_t)fz_below(c->rng, 256);
					}
					cut = (uint32_t)fz_below(c->rng, got + 1u);
					cb = (uint8_t *)malloc(cut ? cut : 1u);
					if (cb) {
						memcpy(cb, buf, cut);
						readers(c, cb, cut);       /* an exact-size allocation: a read past `cut` is a fault */
						free(cb);
					}
					readers(c, buf, got);
				}
			}
		}
		free(buf);
	}
	fz_digest(c, need + ((uint64_t)any_cut << 32));
	return 0;
}

FZ_ADAPTER(diag_block, .name = "engine/diag_block", .covers = "", .flags = FZ_NO_FAILK, .backstop_s = 3000, .shape = FZ_REQ, .seeds = seeds_blk, .run = run_blk);
