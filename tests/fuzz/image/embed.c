/*
 * image/embed - where objects held in a host's variables start: kgenome_image_embed_starts and the
 * two checks the sniff chain asks of an ELF there (kgenome_elf_hdr_valid, kgenome_elf_extent), with the PE's extent.
 *
 * Seeds are the ELF objects (both classes and byte orders) and the PE32 / PE32+ objects tests/lib/genome/hk.h builds.
 * The bytes are the host; the data spans are the file past its first 64 bytes, in two halves, so a pointer that lands in
 * the first 64 bytes or in the gap is refused. Held: every candidate is inside a span and inside the file, a caller that refuses
 * the walk gets TRUNCATED and the front of the full answer, an extent never reaches past the buffer, and a header that is valid has an extent of at
 * least its own header.
 */
#include <kgenome.h>

#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"

static void seed_elf(struct fz_corpus *c, const char *name, int is64, int be)
{
	static struct hk_elf e[4];
	struct hk_elf *q = &e[is64 * 2 + be];

	hk_elf(q, is64, be, 0);
	fz_corpus_add(c, name, q->b, q->n);
}

static void seed_pe(struct fz_corpus *c, const char *name, int plus)
{
	static struct hk_pe p[2];
	struct hk_pe *q = &p[plus];

	hk_pe(q, plus);
	fz_corpus_add(c, name, q->b, q->n);
}

static void seeds(struct fz_corpus *c)
{
	seed_elf(c, "elf32le", 0, 0);
	seed_elf(c, "elf32be", 0, 1);
	seed_elf(c, "elf64le", 1, 0);
	seed_elf(c, "elf64be", 1, 1);
	seed_pe(c, "pe32", 0);
	seed_pe(c, "pe32plus", 1);
}

struct st {
	struct kgenome_elf_info elf;
	struct kgenome_pe_info  pe;
	struct kgenome_obj      obj;
};

static struct st state;

static void *parse(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_buf f = kof_buf_make(in, n);
	int ok;

	memset(&state, 0, sizeof state);
	ok = kgenome_elf_sniff(f) ? kgenome_elf_image_parse(f, &state.elf, &state.obj)
			       : kgenome_pe_image_parse(f, &state.pe, &state.obj);
	if (!ok) {
		fz_digest(c, 0xdead);
		return NULL;
	}
	return &state;
}

struct sink {
	uint64_t v[4096];
	uint64_t n;
	uint64_t refuse_at;
};

static int emit(void *u, uint64_t off)
{
	struct sink *k = (struct sink *)u;

	if (k->n >= k->refuse_at || k->n >= sizeof k->v / sizeof k->v[0])
		return 0;
	k->v[k->n++] = off;
	return 1;
}

static struct sink full, part;

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct st *s = (struct st *)h;
	kof_buf f = kof_buf_make(in, n);
	struct kgenome_embed_span sp[2], dsp[KGENOME_EMBED_SPANS_MAX];
	struct kgenome_embed_req rq;
	struct kgenome_embed_res rs, rt;
	uint32_t nd;
	uint64_t i, ext;
	uint64_t half = n > 64u ? (n - 64u) / 2u : 0;

	ext = kgenome_image_embed_extent(s->obj.format, f);
	FZ_CHECK(c, ext <= n, "an extent past the buffer");
	if (s->obj.format == KGENOME_FMT_ELF) {
		FZ_CHECK(c, kgenome_elf_extent(f) == ext, "the two spellings of the ELF extent differ");
		if (kgenome_elf_hdr_valid(f))
			FZ_CHECK(c, ext >= (s->elf.elf_class == KGENOME_ELFCLASS_64 ? 64u : 52u), "a valid header with an extent below itself");
	}
	fz_digest(c, ext);
	if (n >= 8u && kgenome_elf_hdr_valid(f))
		FZ_CHECK(c, kgenome_elf_ident_valid(in), "a valid header whose first 8 bytes fail the cheap half of the check");
	/* the data spans the lib names: ascending, disjoint, inside the file */
	nd = kgenome_image_embed_spans(&s->obj, f, dsp);
	FZ_CHECK(c, nd <= KGENOME_EMBED_SPANS_MAX, "more spans than the table holds");
	for (i = 0; i < nd; i++) {
		FZ_CHECK(c, dsp[i].len && dsp[i].off < n && dsp[i].len <= n - dsp[i].off, "a span outside the file");
		FZ_CHECK(c, !i || dsp[i].off > dsp[i - 1].off + dsp[i - 1].len, "spans not ascending and disjoint (adjacent ones are one)");
	}
	fz_digest(c, nd);
	if (n < 128u)
		return;
	sp[0].off = 64u;
	sp[0].len = half;
	sp[1].off = 64u + half + 8u;
	sp[1].len = n - (64u + half + 8u);
	memset(&rq, 0, sizeof rq);
	rq.obj = &s->obj;
	rq.file = f;
	rq.data = sp;
	rq.n_data = 2;
	rq.flags = KGENOME_EMBED_SYMBOLS;
	rq.emit = emit;
	rq.user = &full;
	memset(&full, 0, sizeof full);
	full.refuse_at = UINT64_MAX;
	kgenome_image_embed_starts(&rq, &rs);
	FZ_CHECK(c, rs.status == KGENOME_OK || full.n >= sizeof full.v / sizeof full.v[0], "a walk that nobody refused was cut");
	FZ_CHECK(c, rs.n == full.n, "the count is not the candidates emitted");
	for (i = 0; i < full.n; i++) {
		fz_step(&c->steps, 1);
		FZ_CHECK(c, full.v[i] < n, "a candidate outside the file");
		FZ_CHECK(c, (full.v[i] >= sp[0].off && full.v[i] - sp[0].off < sp[0].len) ||
			 (full.v[i] >= sp[1].off && full.v[i] - sp[1].off < sp[1].len), "a candidate outside the data spans");
	}
	if (full.n > 1u && full.n < sizeof full.v / sizeof full.v[0]) {
		/* a caller that stops after half: the walk says it was cut, and what it emitted is the front of the full answer */
		rq.user = &part;
		memset(&part, 0, sizeof part);
		part.refuse_at = full.n / 2u;
		kgenome_image_embed_starts(&rq, &rt);
		FZ_CHECK(c, rt.status == KGENOME_TRUNCATED && part.n == full.n / 2u, "a refused candidate was not said to be a cut");
		for (i = 0; i < part.n; i++)
			FZ_CHECK(c, part.v[i] == full.v[i], "the walk is not deterministic");
	}
	fz_digest(c, rs.n);
}

FZ_ADAPTER(embed, .name = "kgenome/embed", .covers = "kgenome_image_embed_starts kgenome_image_embed_spans kgenome_image_embed_extent "
	   "kgenome_elf_hdr_valid kgenome_elf_ident_valid kgenome_elf_extent",
	   .shape = FZ_PARSE, .seeds = seeds, .parse = parse, .walk = walk);
