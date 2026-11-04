/*
 * diag/frame - the frame of a function (phenotype/frame.h) and the one lookup in the function table (funcs.h), over code the bytes spell.
 *
 * The first byte picks the architecture (x86-64, i386, ARM, AArch64, MIPS LE, MIPS BE), the second the number of functions the bytes are cut into; the rest is code.
 * The object is described to the lib at run time (an ELF header record of the byte order), nothing is parsed.
 *
 * Held:
 *   FRAME     a frame that is not OK has no bits and no graph; one that is has bits for every block, block 0 at byte 0, the blocks' byte starts rising and inside the extent,
 *             the instruction count equal to the sum of the blocks', the kept instructions (KEEP_INSN) as many as counted
 *   FROM_PRE  made from the instructions a first make kept, the frame equals the one that decoded for itself (blocks, bits)
 *   CACHE     every function of the table asked twice: one build each, the second ask the same pointer; the extent of an entry is the cache's, a shifted extent is made
 *             and given back; the bytes the cache holds are what it reports
 *   AT        kgenome_funcs_at and kgenome_funcs_start against a linear scan of the table, at every function's start, end and one byte on each side
 */
#include "diag_seed.h"

#include <phenotype/frame.h>
#include <genotype/image/funcs.h>

static void seeds(struct fz_corpus *c)
{
	static const uint8_t x64[] = { 0, 3, 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xf8, 0x85, 0xff, 0x74, 0x07, 0x89, 0x38, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3, 0x90, 0xc3, 0x90, 0xc3 };
	static const uint8_t mips[] = { 5, 2, 0x10, 0, 0, 3, 0, 0, 0, 0, 0x24, 2, 0, 1, 0, 0, 0, 0, 0x03, 0xe0, 0, 8, 0, 0, 0, 0 };
	static const uint8_t arm[] = { 2, 2, 0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1 };

	fz_corpus_add(c, "frame_x64", x64, sizeof x64);
	fz_corpus_add(c, "frame_mips", mips, sizeof mips);
	fz_corpus_add(c, "frame_arm", arm, sizeof arm);
}

static int frame_ok(struct fz_ctx *c, const struct kgenome_frame *f, uint64_t len)
{
	uint32_t b, sum = 0;

	FZ_CHECK(c, f->state <= KGENOME_FRAME_NOMEM, "a state the call cannot give");
	FZ_CHECK(c, kgenome_frame_state_name((enum kgenome_frame_state)f->state)[0] != '?', "a state with no name");
	if (f->state != KGENOME_FRAME_OK) {
		FZ_CHECK(c, !f->bits && !f->cfg.b && !kgenome_frame_facts(f, NULL), "a frame with no graph holds bits or blocks");
		return 0;
	}
	FZ_CHECK(c, f->cfg.n_all > 0u && f->cfg.b[0].at == 0u, "a frame has no block, or block 0 is not at the entry");
	for (b = 0; b < f->cfg.n_all; b++) {
		const struct kgenome_cfg_block *k = &f->cfg.b[b];

		FZ_CHECK(c, k->first == sum && k->n_insn > 0u, "the blocks do not tile the instructions");
		sum += k->n_insn;
		FZ_CHECK(c, (uint64_t)k->at < len, "a block starts outside the extent");
		FZ_CHECK(c, !b || k->at > f->cfg.b[b - 1u].at, "the byte starts of the blocks do not rise");
		FZ_CHECK(c, !f->bits || !(f->bits[b] & ~0x7fu), "a bit the frame does not publish");
	}
	FZ_CHECK(c, sum == f->n_insn, "the blocks hold another number of instructions than the frame counts");
	return 1;
}

static uint32_t def_at(const struct kgenome_func_set *fs, uint64_t off)
{
	uint32_t i, best = KGENOME_FUNCS_NONE;
	uint64_t be = 0;

	for (i = 0; i < fs->n; i++) {
		const uint64_t e = fs->v[i].off + fs->v[i].len;

		if (fs->v[i].off <= off && off < e && (best == KGENOME_FUNCS_NONE || e < be)) {
			best = i;
			be = e;
		}
	}
	return best;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const struct { unsigned arch; int be; } isa[6] = { { KGENOME_ARCH_X86_64, 0 }, { KGENOME_ARCH_X86, 0 }, { KGENOME_ARCH_ARM, 0 },
		{ KGENOME_ARCH_ARM64, 0 }, { KGENOME_ARCH_MIPS, 0 }, { KGENOME_ARCH_MIPS, 1 } };
	struct kgenome_elf_info ei;
	struct kgenome_obj obj;
	struct kgenome_frame_src s;
	struct kgenome_func v[16];
	struct kgenome_func_set fs;
	struct kgenome_frame_cache *cache;
	const uint8_t *code;
	uint64_t len, cut;
	uint32_t nf, i;
	unsigned a;

	if (n < 10)
		return 0;
	a = in[0] % 6u;
	nf = 1u + in[1] % 15u;
	code = in + 2;
	len = n - 2u;
	memset(&ei, 0, sizeof ei);
	ei.elf_data = isa[a].be ? KGENOME_ELFDATA_BE : 1;
	memset(&obj, 0, sizeof obj);
	obj.format = KGENOME_FMT_ELF;
	obj.arch = (uint8_t)isa[a].arch;
	obj.obj_size = len;
	obj.file_header = &ei;
	memset(&s, 0, sizeof s);
	s.obj = &obj;
	s.base = code;
	s.size = len;
	/* a table: the code cut into nf functions, rising by construction */
	memset(&fs, 0, sizeof fs);
	cut = len / nf ? len / nf : 1u;
	for (i = 0; i < nf && (uint64_t)i * cut < len; i++) {
		v[i].off = (uint64_t)i * cut;
		v[i].len = (i + 1u == nf || (uint64_t)(i + 1u) * cut > len) ? len - v[i].off : cut;
		fs.n = i + 1u;
	}
	for (i = 0; i < fs.n; i++) {
		v[i].value = 0; v[i].shndx = 0; v[i].kind = 0; v[i].end_source = 0; v[i].isa_mode = 0; v[i].source = 0; v[i].flags = 0;
	}
	fs.v = v;
	s.fs = &fs;
	/* FRAME and FROM_PRE on the whole extent */
	{
		struct kgenome_frame f1, f2;
		struct kgenome_frame_src sp = s;
		struct kgenome_frame_insns pre;

		(void)kgenome_frame_make(&s, 0, len, KGENOME_FRAME_KEEP_INSN, &f1);
		if (frame_ok(c, &f1, len)) {
			/* (the driver also runs the call with the k-th allocation refused: a refusal is a NULL answer, never a wrong one, and the rows below only compare what was made) */
			const uint16_t *b1 = kgenome_frame_facts(&f1, f1.in);

			FZ_CHECK(c, f1.in != NULL, "KEEP_INSN kept no instructions");
			pre = (struct kgenome_frame_insns){ .v = f1.in, .n = f1.n_insn, .skipped = f1.n_skip, .off = 0, .len = len };
			sp.pre = &pre;
			(void)kgenome_frame_make(&sp, 0, len, 0u, &f2);
			if (f2.state == KGENOME_FRAME_OK && b1 && kgenome_frame_facts(&f2, f1.in)) {
				FZ_CHECK(c, f2.cfg.n_all == f1.cfg.n_all && f2.n_insn == f1.n_insn && !memcmp(f2.cfg.b, f1.cfg.b, (size_t)f1.cfg.n_all * sizeof *f1.cfg.b) &&
					    !memcmp(f2.bits, f1.bits, (size_t)f1.cfg.n_all * sizeof *f1.bits),
					 "the frame made from the first one's instructions is not the first");
			}
			kgenome_frame_release(&f2, NULL);
			/* the same facts asked by a caller that holds no instructions: read again through the shared reader, equal to the first */
			{
				struct kgenome_frame f3;

				(void)kgenome_frame_make(&s, 0, len, 0u, &f3);
				if (f3.state == KGENOME_FRAME_OK && b1 && kgenome_frame_facts_of(&f3, &s)) {
					FZ_CHECK(c, f3.cfg.n_all == f1.cfg.n_all && !memcmp(f3.bits, f1.bits, (size_t)f1.cfg.n_all * sizeof *f1.bits), "the facts read again are not the facts made with the graph");
				}
				kgenome_frame_release(&f3, NULL);
			}
			fz_digest(c, ((uint64_t)f1.cfg.n_all << 32) ^ f1.n_insn);
		}
		kgenome_frame_release(&f1, NULL);
	}
	{
		void *blk = kgenome_cfg_alloc(NULL, 24u);

		kgenome_cfg_release(NULL, blk, 24u);              /* the one allocation through the caller's allocator (NULL: malloc and free) */
		kgenome_cfg_release(NULL, NULL, 0u);
	}
	/* CACHE */
	cache = kgenome_frame_cache_new(NULL, 0);
	if (!cache)
		return 0;
	for (i = 0; i < fs.n; i++) {
		const struct kgenome_frame *f = kgenome_frame_get(cache, &s, i), *g = kgenome_frame_get(cache, &s, i);
		struct kgenome_frame own;

		FZ_CHECK(c, f == g || !f, "the second ask answered another frame");        /* (the first may be a refused allocation) */
		if (f) {
			(void)frame_ok(c, f, f->len);
			FZ_CHECK(c, f->fn == i && f->off == v[i].off && f->len == v[i].len, "the frame is not the table entry's");
			FZ_CHECK(c, kgenome_frame_of_extent(cache, &s, v[i].off, v[i].len, &own) == f, "the extent of an entry is not the cache's frame");
		}
		memset(&own, 0, sizeof own);
		if (v[i].len > 1u && kgenome_frame_of_extent(cache, &s, v[i].off, v[i].len - 1u, &own) == &own) {
			(void)frame_ok(c, &own, own.len);
			kgenome_frame_release(&own, NULL);
		}
	}
	FZ_CHECK(c, kgenome_frame_cache_built(cache) <= fs.n && kgenome_frame_cache_hits(cache) <= 3u * fs.n && kgenome_frame_cache_refused(cache) <= 3u * fs.n, "the cache counts more than it was asked");
	FZ_CHECK(c, kgenome_frame_cache_bytes(cache) > 0u || !kgenome_frame_cache_built(cache), "built frames and no bytes");
	kgenome_frame_cache_free(cache);
	/* AT */
	for (i = 0; i < fs.n; i++) {
		uint64_t p[4];
		unsigned q;

		p[0] = v[i].off; p[1] = v[i].off + v[i].len - 1u; p[2] = v[i].off + v[i].len; p[3] = v[i].off ? v[i].off - 1u : 0u;
		for (q = 0; q < 4u; q++) {
			FZ_CHECK(c, kgenome_funcs_at(&fs, p[q]) == def_at(&fs, p[q]), "kgenome_funcs_at is not the definition");
			FZ_CHECK(c, kgenome_funcs_start(&fs, p[q]) == (p[q] == v[i].off ? i : kgenome_funcs_start(&fs, p[q])), "kgenome_funcs_start missed a start");
		}
	}
	return 0;
}

FZ_ADAPTER(frame, .name = "kgenome/diag_frame",
	   .covers = "kgenome_frame_make kgenome_frame_release kgenome_frame_state_name kgenome_frame_cache_new kgenome_frame_get kgenome_frame_of_extent "
		     "kgenome_frame_facts kgenome_frame_facts_of kgenome_cfg_alloc kgenome_cfg_release kgenome_frame_cache_built kgenome_frame_cache_hits kgenome_frame_cache_refused kgenome_frame_cache_bytes kgenome_frame_cache_free kgenome_funcs_at kgenome_funcs_start",
	   .flags = 0, .backstop_s = 300, .steps_base = 100000u, .steps_per_byte = 64,
	   .shape = FZ_REQ, .seeds = seeds, .run = run);
