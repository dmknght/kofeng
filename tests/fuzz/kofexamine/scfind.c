/*
 * kofexamine/scfind - the shellcode-loader finder (kofexamine/kofscfind.c) on corrupt ELF objects: kofscfind_find (the whole
 * analysis, with the genome's own sweep), kofscfind_run (the same search with the caller's answer to "how does the code refer to
 * this range", drawn from the iteration's rng so every gate is reached) and kofscfind_image (the payload as an object).
 *
 * Seeds are the loaders of tests/lib/scf_img.h (the builder tests/unit/kofscfind.c uses): an inline blob called by the code, the
 * same as base64 text (the b64 path), and a pointer to a clear blob that makes a syscall. The field map aims at the ELF header, the
 * section headers (offset, size, link) and the payload symbol's value and size.
 *
 * Held: an answer inside the object (at + len <= n), a length in [16, 8192] and a decoded count of at most 8192, the width is 0,
 * 32 or 64; found = 0 is the whole answer when nothing is found; an image fits its room and starts with the ELF magic, carries
 * the payload where the header says (the decoded bytes when the text was base64), and is refused (0) when `found` is 0. The
 * known defects D18 / EX-9 (the second base64 decoder) are COUNTED in the digest through dec_n, not held.
 */
#include "../../unit/caps_fix.h"
#include <celllysis/xref.h>

#include "../../../kofexamine/kofscfind.h"
#include "../../lib/scf_img.h"
#include "../../lib/fuzz_drv.h"

static struct fz_field fld[3][32];
static struct fz_map map[3];

static void fadd(unsigned v, uint64_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &fld[v][map[v].n++];

	f->off = (uint32_t)off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seeds(struct fz_corpus *c)
{
	static uint8_t b[1u << 14];
	static const enum shape sh[] = { INLINE_CALLED, INLINE_BASE64, POINTER_CALLED };
	static const char *const nm[] = { "inline", "base64", "pointer" };
	unsigned s, k;

	for (s = 0; s < 3; s++) {
		uint64_t len = build(b, sh[s]);

		map[s].f = fld[s];
		map[s].n = 0;
		fadd(s, 24, 8, FZ_RVA);                 /* e_entry */
		fadd(s, 32, 8, FZ_OFFSET);              /* e_phoff */
		fadd(s, 40, 8, FZ_OFFSET);              /* e_shoff */
		fadd(s, 56, 2, FZ_COUNT);               /* e_phnum */
		fadd(s, 60, 2, FZ_COUNT);               /* e_shnum */
		fadd(s, 62, 2, FZ_COUNT);               /* e_shstrndx */
		for (k = 1; k < 6; k++) {
			fadd(s, scf_sh_off + 64u * k + 16u, 8, FZ_RVA);
			fadd(s, scf_sh_off + 64u * k + 24u, 8, FZ_OFFSET);
			fadd(s, scf_sh_off + 64u * k + 32u, 8, FZ_LEN);
		}
		fadd(s, scf_sym_off + 48u + 6u, 2, FZ_COUNT);   /* the payload symbol: shndx, value, size */
		fadd(s, scf_sym_off + 48u + 8u, 8, FZ_RVA);
		fadd(s, scf_sym_off + 48u + 16u, 8, FZ_LEN);
		map[s].rec_off = (uint32_t)scf_sh_off;
		map[s].rec_size = 64;
		map[s].rec_n = 7;
		fz_corpus_add_map(c, nm[s], b, (size_t)len, &map[s]);
	}
}

static const char *const dict[] = { "\177ELF", ".text", ".symtab", "payload", NULL };

struct st {
	struct kof_obj_ctx ctx;
	struct kgenome_obj gobj;
	uint8_t            view[1u << 16];
};

static struct st state;

static void *parse(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf = kof_buf_make(in, n);
	int ok = 0;

	(void)c;
	memset(&state.ctx, 0, sizeof state.ctx);
	memset(state.view, 0, sizeof state.view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].view_size <= sizeof state.view && pl[i].parse &&
		     pl[i].parse(buf, state.view, &state.ctx);
	if (!ok)
		return NULL;
	kof_genome_obj(&state.ctx, &state.gobj);
	return &state;
}

struct xr {
	uint64_t rng;
	uint32_t calls;
};

static uint32_t xref_rng(void *user, uint64_t va, uint64_t size)
{
	struct xr *x = user;

	(void)va; (void)size;
	x->calls++;
	x->rng = x->rng * 6364136223846793005ull + 1442695040888963407ull;
	/* a flag word: any subset of the real flags, now and then none and now and then all */
	switch ((x->rng >> 60) & 3u) {
	case 0: return 0;
	case 1: return 0xffu;
	default: return (uint32_t)(x->rng >> 32) & 0xffu;
	}
}

static void answer(struct fz_ctx *c, const struct kofscfind *f, uint64_t n, const char *how)
{
	(void)how;
	if (!f->found)
		return;
	FZ_CHECK(c, f->len >= 16u && f->len <= KOFSCFIND_SIZE_MAX, "a payload length outside [16, 8192]");
	FZ_CHECK(c, f->at <= n && f->len <= n - f->at, "a payload outside the object");
	FZ_CHECK(c, f->dec_n <= KOFSCFIND_SIZE_MAX, "a decoded count past the buffer");
	FZ_CHECK(c, f->bits == 0 || f->bits == 32 || f->bits == 64, "a width that is neither 0, 32 nor 64");
	FZ_CHECK(c, f->dec_n == 0 || f->len >= 8u, "a decoded payload from fewer than 8 bytes of text");
}

/* the list of where shellcode could sit, on the same object, with the answer the finder cached (or none) */
static void list_check(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, uint64_t n, const struct kofscfind *f)
{
	static struct kofscfind_row rows[KOFSCFIND_ROWS_MAX + 1u];
	struct kofscfind_list_in li;
	struct kofscfind_list_res rs, rs2;
	enum kgenome_status st;
	uint32_t i;

	memset(&li, 0, sizeof li);
	li.obj = obj;
	li.file = kof_buf_make(in, n);
	li.payload_va = f->found ? f->va : 0u;
	li.payload_len = f->found ? f->len : 0u;
	li.payload_bits = f->found ? f->bits : 0u;
	li.out = rows;
	li.cap = KOFSCFIND_ROWS_MAX;
	st = kofscfind_list(&li, &rs);
	FZ_CHECK(c, (unsigned)st <= (unsigned)KGENOME_NOMEM, "kofscfind_list: status outside the enum");
	FZ_CHECK(c, rs.n <= rs.total && rs.n <= li.cap, "kofscfind_list: more rows than the total or the room");
	FZ_CHECK(c, !li.payload_len || (rs.n >= 1u && rows[0].what == KOFSCFIND_W_FINDER && rows[0].flagged), "a finder answer without its first row");
	for (i = 0; i < rs.n; i++) {
		fz_step(&c->steps, 1);
		FZ_CHECK(c, rows[i].what >= KOFSCFIND_W_FINDER && rows[i].what <= KOFSCFIND_W_RANGE, "a row of no kind");
		FZ_CHECK(c, memchr(rows[i].name, 0, sizeof rows[i].name) && memchr(rows[i].verdict, 0, sizeof rows[i].verdict),
			 "a row text without its terminator");
		if (rows[i].off != KGENOME_NA)
			FZ_CHECK(c, rows[i].off <= n && rows[i].size <= n - rows[i].off,
				 "a row outside the object");
		FZ_CHECK(c, rows[i].what == KOFSCFIND_W_FINDER || !rows[i].flagged == !rows[i].strong, "a flag on a row that is neither the finder's nor strong");
		FZ_CHECK(c, !rows[i].facts_ok || (rows[i].facts.shape >= KGENOME_RANGE_EMPTY && rows[i].facts.shape <= KGENOME_RANGE_MIXED &&
						 rows[i].facts.decode_pct <= 100u && rows[i].facts.entropy_centi <= 800u),
			 "facts out of range");
		FZ_CHECK(c, !rows[i].strong || (rows[i].facts.refs_known && rows[i].facts.syscall && rows[i].facts.shape == KGENOME_RANGE_CODE_LIKE),
			 "a strong row without its three parts");
		FZ_CHECK(c, i == 0 || rows[i - 1u].flagged || !rows[i].flagged, "a flagged row after one that is not");
		fz_digest(c, rows[i].va ^ (rows[i].size << 5) ^ ((uint64_t)rows[i].what << 58));
	}
	li.cap = 1;
	(void)kofscfind_list(&li, &rs2);
	FZ_CHECK(c, rs2.n <= 1u && rs2.total == rs.total, "kofscfind_list: a cap of one changed the total or overran");
	li.cap = 0;
	li.out = NULL;
	(void)kofscfind_list(&li, &rs2);
	FZ_CHECK(c, rs2.n == 0 && rs2.total == rs.total, "kofscfind_list: a cap of zero wrote or changed the total");
	fz_digest(c, ((uint64_t)rs.total << 20) ^ (uint64_t)st);
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct st *s = h;
	static struct kofscfind f, g;
	struct kofscfind_in req;
	struct xr xr;
	enum kgenome_status st;
	uint8_t out[KOFSCFIND_IMAGE_MAX + 32];
	uint64_t cap, w;
	unsigned round;

	memset(&f, 0x5a, sizeof f);
	st = kofscfind_find(&s->gobj, in, n, &f);
	FZ_CHECK(c, (unsigned)st <= (unsigned)KGENOME_NOMEM, "kofscfind_find: status outside the enum");
	if (st == KGENOME_OK) {
		FZ_CHECK(c, f.found == 0 || f.found == 1, "found is neither 0 nor 1");
		answer(c, &f, n, "find");
		fz_digest(c, ((uint64_t)f.found << 40) ^ f.at ^ f.len << 8 ^ f.dec_n ^ (uint64_t)f.bits << 56);
	}

	list_check(c, &s->gobj, in, n, &f);

	/* the search on its own, with an answer from the rng: every gate */
	for (round = 0; round < 4; round++) {
		memset(&req, 0, sizeof req);
		req.obj = &s->gobj;
		req.data = in;
		req.n = n;
		req.xref = round == 3 ? NULL : xref_rng;
		xr.rng = c->seed * 31u + round + 1u;
		xr.calls = 0;
		req.xref_user = &xr;
		memset(&g, 0x5a, sizeof g);
		st = kofscfind_run(&req, &g);
		FZ_CHECK(c, (unsigned)st <= (unsigned)KGENOME_NOMEM, "kofscfind_run: status outside the enum");
		if (st == KGENOME_OK) {
			answer(c, &g, n, "run");
			fz_digest(c, ((uint64_t)g.found << 40) ^ g.at ^ g.len << 8 ^ g.dec_n);
		}
		fz_step(&c->steps, 1);
	}

	/* the image of what was found: every room from nothing to one past the need */
	if (f.found) {
		for (cap = 0; cap <= KOFSCFIND_IMAGE_MAX + 8u; cap += cap < 4u ? 1u : (cap < 200u ? 37u : 997u)) {
			memset(out, 0xcc, sizeof out);
			w = kofscfind_image(&f, in, n, (int)(c->seed & 1u), out, cap);
			FZ_CHECK(c, w <= cap, "kofscfind_image wrote more than its room");
			for (uint64_t i = cap; i < sizeof out; i++)
				if (out[i] != 0xcc) {
					FZ_CHECK(c, 0, "kofscfind_image wrote past its room");
					break;
				}
			if (w) {
				uint64_t body = f.dec_n ? f.dec_n : f.len;

				FZ_CHECK(c, w == KOFSCFIND_HDR_ROOM + body, "image size is not the header room plus the payload");
				FZ_CHECK(c, !memcmp(out, "\177ELF", 4), "image without the ELF magic");
				FZ_CHECK(c, !memcmp(out + KOFSCFIND_HDR_ROOM, f.dec_n ? (const void *)f.dec : (const void *)(in + f.at), (size_t)body),
					 "image body is not the payload");
			}
			fz_digest(c, w);
		}
	}
	{
		struct kofscfind none;

		memset(&none, 0, sizeof none);
		FZ_CHECK(c, kofscfind_image(&none, in, n, 1, out, sizeof out) == 0, "an image of nothing");
	}
}

FZ_ADAPTER(kx_scfind,
	   .name = "kofexamine/scfind",
	   .covers = "kofscfind_find kofscfind_run kofscfind_image kofscfind_list",
	   .shape = FZ_PARSE, .seeds = seeds, .dict = dict, .parse = parse, .walk = walk);
