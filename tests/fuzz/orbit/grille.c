/*
 * orbit/grille - the Windows collector's pure parts (the ones that build here and that tests/unit/grille_host.c and
 * orbit_evt already attack with fixed rows): text conversion against an independent decoder, the event ring, the process
 * and file-name tables.
 *
 *   wtext       kofw_utf16_to_utf8, kofw_ansi_to_text, kofw_bytes_to_text at every capacity: the output is compared with a
 *               second implementation written here, byte for byte, and the cut flag with it
 *   wring       the ring as a script: claim / commit / take against a counter model (what is held is what was committed
 *               and not yet taken, in order; a full ring refuses and counts)
 *   wtab        the process table and the file-name table as a script: add / find / recycle / resolve; every name that
 *               comes back is a string inside the pool; nothing finds a pid that was not added
 */
#include "orbit_fx.h"

#include "kofgrille.h"
#include "wevt_ring.h"
#include "wfilter.h"
#include "wtext.h"

/* ------------------------------------------------------------------------------------------------- wtext */

static void seeds_wtext(struct fz_corpus *c)
{
	static const uint16_t u[] = { 'a', 'b', 0xd83d, 0xde00, 0xd800, 'c', 0xdc00, 0x0a, 0x7f, 0xe9, 0x20ac, 0 };

	fz_corpus_add(c, "utf16", u, sizeof u);
	fz_corpus_add(c, "ansi", "C:\\Windows\\x\x01\xff.exe\0tail", 22);
}

/* the oracle: the same decision, written again */
static size_t ref_utf16(const uint16_t *s, size_t n, char *d, size_t cap, int *cut)
{
	size_t i = 0, o = 0;

	*cut = 0;
	if (!cap)
		return 0;
	while (i < n) {
		uint32_t cp = s[i++];
		unsigned len;
		uint8_t b[4];

		if (!cp)
			break;
		if (cp >= 0xd800 && cp <= 0xdbff) {
			if (i < n && s[i] >= 0xdc00 && s[i] <= 0xdfff) {
				cp = 0x10000u + ((cp - 0xd800u) << 10) + (uint32_t)(s[i] - 0xdc00u);
				i++;
			} else
				cp = 0xfffd;
		} else if (cp >= 0xdc00 && cp <= 0xdfff)
			cp = 0xfffd;
		if (cp < 0x20 || cp == 0x7f)
			cp = '.';
		if (cp < 0x80) {
			b[0] = (uint8_t)cp;
			len = 1;
		} else if (cp < 0x800) {
			b[0] = (uint8_t)(0xc0 | (cp >> 6));
			b[1] = (uint8_t)(0x80 | (cp & 0x3f));
			len = 2;
		} else if (cp < 0x10000) {
			b[0] = (uint8_t)(0xe0 | (cp >> 12));
			b[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
			b[2] = (uint8_t)(0x80 | (cp & 0x3f));
			len = 3;
		} else {
			b[0] = (uint8_t)(0xf0 | (cp >> 18));
			b[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3f));
			b[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
			b[3] = (uint8_t)(0x80 | (cp & 0x3f));
			len = 4;
		}
		if (o + len >= cap) {
			*cut = 1;
			break;
		}
		memcpy(d + o, b, len);
		o += len;
	}
	d[o] = '\0';
	return o;
}

static size_t ref_bytes(const uint8_t *s, size_t n, char *d, size_t cap, int *cut, int stop_at_nul)
{
	size_t i, o = 0;

	*cut = 0;
	if (!cap)
		return 0;
	for (i = 0; i < n; i++) {
		uint8_t b = s[i];

		if (stop_at_nul && !b)
			break;
		if (o + 1 >= cap) {
			*cut = 1;
			break;
		}
		d[o++] = (char)(b < 0x20 || b == 0x7f ? '.' : b >= 0x80 ? '?' : b);
	}
	d[o] = '\0';
	return o;
}

static int run_wtext(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char got[400], want[400];
	size_t cap = 1u + (size_t)fz_below(c->rng, sizeof got - 1u), g, w;
	int cg, cw;
	uint16_t *u = NULL;
	size_t nu = n / 2u;

	if (nu) {
		u = (uint16_t *)malloc(nu * 2u);
		if (!u)
			return 0;
		memcpy(u, in, nu * 2u);
	}
	memset(got, 0x55, sizeof got);
	g = kofw_utf16_to_utf8(u, nu, got, cap, &cg);
	w = ref_utf16(u, nu, want, cap, &cw);
	FZ_CHECK(c, g == w && cg == cw && !memcmp(got, want, w + 1u), "UTF-16 to UTF-8 differs from the second implementation");
	FZ_CHECK(c, g < cap && got[g] == '\0' && (cap >= sizeof got || got[cap] == 0x55), "UTF-16 output not terminated inside the capacity");
	fz_digest(c, g ^ ((uint64_t)cg << 40));
	memset(got, 0x55, sizeof got);
	g = kofw_ansi_to_text(in, n, got, cap, &cg);
	w = ref_bytes(in, n, want, cap, &cw, 1);
	FZ_CHECK(c, g == w && cg == cw && !memcmp(got, want, w + 1u), "ANSI to text differs from the second implementation");
	FZ_CHECK(c, g < cap && (cap >= sizeof got || got[cap] == 0x55), "ANSI output not bounded");
	memset(got, 0x55, sizeof got);
	g = kofw_bytes_to_text(in, n, got, cap, &cg);
	w = ref_bytes(in, n, want, cap, &cw, 0);
	FZ_CHECK(c, g == w && cg == cw && !memcmp(got, want, w + 1u), "bytes to text differs from the second implementation");
	FZ_CHECK(c, g < cap && (cap >= sizeof got || got[cap] == 0x55), "bytes output not bounded");
	fz_digest(c, g ^ ((uint64_t)cg << 40));
	free(u);
	return 0;
}

FZ_ADAPTER(wtext, .name = "orbit/wtext", .covers = "kofw_utf16_to_utf8 kofw_ansi_to_text kofw_bytes_to_text", .shape = FZ_REQ, .seeds = seeds_wtext, .run = run_wtext);

/* ------------------------------------------------------------------------------------------------- wring */

static void seeds_script(struct fz_corpus *c)
{
	uint8_t b[10 * 64];
	unsigned i;

	for (i = 0; i < 64; i++) {
		memset(b + 10 * i, 0, 10);
		b[10 * i] = (uint8_t)(i % 6u == 5u ? 2u : i % 3u == 0u ? 1u : 0u);
		b[10 * i + 1] = (uint8_t)i;
	}
	fz_corpus_add(c, "script", b, sizeof b);
}

struct rg {
	struct kofw_ring r;
	uint64_t         next_seq, take_seq, held, dropped;
	int              ok;
};

static void *ring_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct rg *g = (struct rg *)calloc(1, sizeof *g);

	(void)c;
	(void)in;
	(void)n;
	if (!g)
		return NULL;
	if (kofw_ring_init(&g->r, 256) != 0) {
		free(g);
		return NULL;
	}
	return g;
}

static int ring_op(struct fz_ctx *c, void *h, unsigned op, uint64_t a, uint64_t b)
{
	struct rg *g = (struct rg *)h;

	(void)b;
	if (op == 0) {
		unsigned k, times = 1u + (unsigned)(a % 40u);

		for (k = 0; k < times; k++) {
			struct kofw_evt *e = kofw_ring_claim(&g->r);

			if (!e) {
				FZ_CHECK(c, g->held == g->r.mask + 1u, "a claim was refused with room left");
				g->dropped++;
				continue;
			}
			FZ_CHECK(c, g->held <= g->r.mask, "a claim was granted on a full ring");
			memset(e, 0, sizeof *e);
			e->seq = g->next_seq++;
			(void)kofw_ring_commit(&g->r);
			g->held++;
		}
	} else if (op == 1) {
		unsigned k, times = 1u + (unsigned)(a % 40u);

		for (k = 0; k < times; k++) {
			struct kofw_evt out;
			int got = kofw_ring_take(&g->r, &out);

			FZ_CHECK(c, got == (g->held > 0), "take disagrees with the model about whether the ring is empty");
			if (!got)
				break;
			FZ_CHECK(c, out.seq == g->take_seq, "a record came out of order or twice");
			g->take_seq++;
			g->held--;
		}
	} else {
		FZ_CHECK(c, g->r.dropped == g->dropped && g->r.produced == g->next_seq, "the ring's counters differ from the model");
		FZ_CHECK(c, g->r.high_water <= g->r.mask + 1u, "the high-water mark is above the capacity");
	}
	fz_digest(c, op ^ (g->held << 8) ^ (g->dropped << 24));
	return 0;
}

static void ring_close(void *h)
{
	struct rg *g = (struct rg *)h;

	kofw_ring_free(&g->r);
	free(g);
}

FZ_ADAPTER(wring, .name = "orbit/wring", .covers = "kofw_ring_init kofw_ring_free kofw_ring_claim kofw_ring_commit kofw_ring_take", .shape = FZ_SEQ, .n_kinds = 3,
	   .seeds = seeds_script, .open = ring_open, .op = ring_op, .close = ring_close);

/* ------------------------------------------------------------------------------------------------- wtab */

struct tabs {
	struct kofw_ptab *p;
	struct kofw_ftab *f;
	uint8_t           pids[64];      /* which of 64 pids were added and not recycled out */
};

static void *tab_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct tabs *t = (struct tabs *)calloc(1, sizeof *t);

	(void)c;
	(void)in;
	(void)n;
	if (!t)
		return NULL;
	t->p = (struct kofw_ptab *)calloc(1, sizeof *t->p);
	t->f = (struct kofw_ftab *)calloc(1, sizeof *t->f);
	if (!t->p || !t->f) {
		free(t->p);
		free(t->f);
		free(t);
		return NULL;
	}
	kofw_ptab_init(t->p);
	kofw_ftab_init(t->f);
	return t;
}

static int tab_op(struct fz_ctx *c, void *h, unsigned op, uint64_t a, uint64_t b)
{
	struct tabs *t = (struct tabs *)h;
	uint32_t pid = 100u + (uint32_t)(a % 64u);
	char name[320];
	size_t k, len = (size_t)(b % 300u);
	struct kofw_pent *e;

	for (k = 0; k < len; k++)
		name[k] = (char)('a' + (a + k) % 26u);
	name[len] = '\0';
	switch (op) {
	case 0:
		e = kofw_ptab_add(t->p, pid, 1000u + a, len ? name : NULL, 0);
		if (e) {
			const char *img = kofw_pent_image(t->p, e);

			t->pids[pid - 100u] = 1;
			FZ_CHECK(c, e->pid == pid, "an entry for the wrong pid");
			FZ_CHECK(c, img != NULL && strlen(img) <= KOFW_IMAGE_MAX, "an image longer than its bound, or NULL");
		}
		break;
	case 1:
		e = kofw_ptab_find(t->p, pid);
		FZ_CHECK(c, e == NULL || (e->pid == pid && t->pids[pid - 100u]), "find returned a pid that was not added");
		if (e)
			(void)kofw_ptab_of(t->p, pid, e->create_time);
		break;
	case 2:
		e = kofw_ptab_add(t->p, pid, 5000u + a, name, 1);
		if (e)
			t->pids[pid - 100u] = 1;
		break;
	case 3:
		kofw_ftab_add(t->f, a * 2654435761u + 1u, len ? name : NULL);
		break;
	default: {
		struct kofw_evt ev;
		int rc;

		memset(&ev, 0, sizeof ev);
		ev.off_object = KOF_TEXT_NONE;
		ev.off_image = KOF_TEXT_NONE;
		ev.off_cmdline = KOF_TEXT_NONE;
		rc = kofw_ftab_resolve(t->f, &ev);
		(void)rc;
		FZ_CHECK(c, kofw_evt_object(&ev) != NULL, "an object accessor returned NULL");
		break;
	}
	}
	FZ_CHECK(c, t->p->names_used <= KOFW_NAME_POOL && t->f->names_used <= KOFW_FPOOL, "a name pool is over its size");
	FZ_CHECK(c, t->p->n <= KOFW_PTAB_MAX && t->f->n <= KOFW_FTAB_MAX, "a table is over its size");
	fz_digest(c, op ^ ((uint64_t)t->p->n << 8) ^ ((uint64_t)t->f->n << 24));
	return 0;
}

static void tab_close(void *h)
{
	struct tabs *t = (struct tabs *)h;

	free(t->p);
	free(t->f);
	free(t);
}

FZ_ADAPTER(wtab, .name = "orbit/wtab",
	   .covers = "kofw_ptab_init kofw_ptab_find kofw_ptab_add kofw_ptab_of kofw_pent_image kofw_ftab_init kofw_ftab_add kofw_ftab_resolve kofw_evt_object",
	   .shape = FZ_SEQ, .n_kinds = 5, .seeds = seeds_script, .open = tab_open, .op = tab_op, .close = tab_close);
