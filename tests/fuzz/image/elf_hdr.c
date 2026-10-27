/*
 * image/elf_hdr - the three ELF header fields the parse does not keep, read back by kgenome_elf_seg_align and kgenome_elf_sec_layout.
 *
 * Seeds are the ELF objects tests/lib/genome/hk.h builds (ELF32 and ELF64, both byte orders, relocatable and executable), with the
 * offsets of the header table, its counts and entry sizes published to the mutators. Held: for every record the parse kept, the
 * accessor answers (the record is inside the object the view was parsed from); for the first index past the kept ones it answers
 * 0 and writes nothing; and the same accessors on a buffer cut short of the table never read outside it (the guard page of the
 * driver's buffer faults) and answer a subset of what the whole buffer answered.
 */
#include <kgenome.h>

#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"
#include "infect_check.h"

static struct fz_field fld[4][16];
static struct fz_map map[4];

static void field(unsigned v, uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &fld[v][map[v].n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seed_one(struct fz_corpus *c, const char *name, int is64, int be)
{
	static struct hk_elf e[4];
	unsigned v = (unsigned)(is64 * 2 + be);
	struct hk_elf *q = &e[v];

	hk_elf(q, is64, be, 0);
	map[v].f = fld[v];
	map[v].n = 0;
	field(v, is64 ? 0x20u : 0x1cu, is64 ? 8 : 4, FZ_OFFSET);      /* e_phoff */
	field(v, is64 ? 0x28u : 0x20u, is64 ? 8 : 4, FZ_OFFSET);      /* e_shoff */
	field(v, is64 ? 0x38u : 0x2cu, 2, FZ_COUNT);                  /* e_phnum */
	field(v, is64 ? 0x3cu : 0x30u, 2, FZ_COUNT);                  /* e_shnum */
	field(v, q->ph + (is64 ? 48u : 28u), is64 ? 8 : 4, FZ_LEN);   /* p_align */
	field(v, q->sh + (is64 ? 48u : 32u), is64 ? 8 : 4, FZ_LEN);   /* sh_addralign of section 0 */
	field(v, q->sh + q->sh_ent + (is64 ? 56u : 36u), is64 ? 8 : 4, FZ_LEN);  /* sh_entsize of section 1 */
	map[v].rec_off = q->sh;
	map[v].rec_size = q->sh_ent;
	map[v].rec_n = 6;
	fz_corpus_add_map(c, name, q->b, q->n, &map[v]);
}

static void seeds(struct fz_corpus *c)
{
	seed_one(c, "elf32le", 0, 0);
	seed_one(c, "elf32be", 0, 1);
	seed_one(c, "elf64le", 1, 0);
	seed_one(c, "elf64be", 1, 1);
}

struct st {
	struct kgenome_elf_info info;
	struct kgenome_obj      obj;
};

static struct st state;

static void *parse(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_buf f = kof_buf_make(in, n);

	memset(&state, 0, sizeof state);
	if (!kgenome_elf_image_parse(f, &state.info, &state.obj)) {
		fz_digest(c, 0xdead);
		return NULL;
	}
	return &state;
}

static enum kgenome_status infect_call(const struct kgenome_infect_req *q, struct kgenome_infect_res *r)
{
	return kgenome_infect_regions(q, r);
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct st *s = (struct st *)h;
	kof_buf f = kof_buf_make(in, n);
	uint32_t i, got_seg = 0, got_sec = 0;
	uint64_t a = 0, b = 0;

	for (i = 0; i < s->info.seg_count; i++) {
		fz_step(&c->steps, 1);
		if (kgenome_elf_seg_align(f, &s->info, i, &a)) {
			got_seg++;
			fz_digest(c, a);
		}
	}
	for (i = 0; i < s->info.sec_count; i++) {
		fz_step(&c->steps, 1);
		if (kgenome_elf_sec_layout(f, &s->info, i, &a, &b)) {
			got_sec++;
			fz_digest(c, a ^ (b << 7));
		}
	}
	/* the parse kept only records that lie inside the object, so the accessors answer for every one of them */
	FZ_CHECK(c, got_seg == s->info.seg_count, "a kept program header the accessor cannot read");
	FZ_CHECK(c, got_sec == s->info.sec_count, "a kept section header the accessor cannot read");
	/* one past the kept records: refused, and nothing written */
	a = 0x5a5a; b = 0xa5a5;
	FZ_CHECK(c, !kgenome_elf_seg_align(f, &s->info, s->info.seg_count, &a) && a == 0x5a5a, "an index past the segments answered");
	FZ_CHECK(c, !kgenome_elf_sec_layout(f, &s->info, s->info.sec_count, &a, &b) && a == 0x5a5a && b == 0xa5a5,
		 "an index past the sections answered");
	/* a buffer cut short of the tables: never an answer the whole buffer did not give, never a read outside */
	if (n > 8u) {
		kof_buf g = kof_buf_make(in, n / 2u);

		for (i = 0; i < s->info.sec_count; i++) {
			uint64_t x = 0, y = 0, u = 0, w = 0;

			fz_step(&c->steps, 1);
			if (kgenome_elf_sec_layout(g, &s->info, i, &x, &y))
				FZ_CHECK(c, kgenome_elf_sec_layout(f, &s->info, i, &u, &w) && u == x && w == y,
					 "the cut buffer answered what the whole one did not");
		}
	}
	fz_digest(c, ((uint64_t)got_seg << 32) | got_sec);
	infect_check(c, &s->obj, f, infect_call);
}

FZ_ADAPTER(elf_hdr, .name = "kgenome/elf_hdr", .covers = "kgenome_elf_seg_align kgenome_elf_sec_layout kgenome_infect_regions",
	   .shape = FZ_PARSE, .seeds = seeds, .parse = parse, .walk = walk);
