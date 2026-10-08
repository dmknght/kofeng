/*
 * arm32_equiv - the ARM state and Thumb state decoders, new against frozen.
 *
 * A DEV TOOL, NOT A TEST: the reference is the decoder as it was BEFORE the split
 * into genotype (a decode table) and celllysis (the adapter), copied out of the
 * tree with every external symbol renamed (ref_decode_a32, ref_decode_t32,
 * ref_arm_*). The new pipeline is cell_decode_arm32 / cell_decode_thumb as they
 * are in the tree. Both decode the same bytes at the same address and EVERY
 * field of struct cell_insn is compared - op, len, n_op, cond, flags, wmask, at,
 * at_va, target, target_va, and for each of the three operands kind, reg, index,
 * scale, size, flags, seg, disp, imm. The padding is not defined and is not
 * compared. The returned length is compared too.
 *
 * Build by hand (the reference is in the scratch directory, not in the tree):
 *
 *   R=/mnt/games/kofscratch/arm/ref_a32
 *   gcc -O2 -std=gnu11 -pthread -Ilibkofeng/kofcore -Ilibgenome -Ilibgenome/genotype -I$R \
 *       tools/celllysis/arm32_equiv.c $R/ref_a32.c $R/ref_t32.c $R/ref_arm_common.c \
 *       libgenome/celllysis/decode_arm32.c libgenome/celllysis/decode_thumb.c \
 *       libgenome/celllysis/decode_arm32_common.c \
 *       libgenome/genotype/arm32/arm32_rows.c libgenome/genotype/arm32/thumb_rows.c \
 *       libgenome/genotype/arm32/arm32_index.c -o arm32_equiv
 *
 *   arm32_equiv arm exh                  every 32-bit word, both byte orders
 *   arm32_equiv arm rand <millions> [seed]   uniformly random words, both orders
 *   arm32_equiv arm sys [fills]          bits 27..20 x 7..4 x cond in {E,F}, random fill
 *   arm32_equiv arm elf <file>...        every aligned word of the executable code
 *   arm32_equiv thumb exh                every first halfword x every second, both
 *                                        parities of the address, both byte orders
 *   arm32_equiv thumb rand <millions> [seed]
 *   arm32_equiv thumb elf <file>...      every halfword start of the executable code
 *   arm32_equiv bench arm|thumb <file>...   ns per instruction, three paths
 *   arm32_equiv bench1 <0|1|2> <reps> arm|thumb <file>...   one of them (0 genotype, 1 adapter, 2 reference)
 *
 * Exit status 0 only when there were no differences.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kofmod/cell.h"
#include "celllysis/decode.h"
#include <arm32/arm32.h>
#include <arm32/thumb.h>

uint32_t ref_decode_a32(const uint8_t *p, uint32_t n, uint64_t va, int be,
			struct cell_insn *out);
uint32_t ref_decode_t32(const uint8_t *p, uint32_t n, uint64_t va, int be,
			struct cell_insn *out);

#define NTHREADS 16

/* ELF fields in the file's own byte order */
#define SW16(v) (be ? (uint16_t)(((v) >> 8) | ((v) << 8)) : (v))
#define SW32(v) (be ? __builtin_bswap32(v) : (v))

static uint32_t arm_h_(const uint8_t *p, int be)
{
	return be ? ((uint32_t)p[0] << 8 | p[1]) : ((uint32_t)p[1] << 8 | p[0]);
}

static uint32_t arm_w_(const uint8_t *p, int be)
{
	return be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3])
		  : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]);
}

static uint64_t g_diffs;
static uint64_t g_shown;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static uint64_t rng_next(uint64_t *s)
{
	uint64_t z = (*s += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

/* The first field that differs, as a name; NULL when they are equal. */
static const char *cmp_insn(const struct cell_insn *a, const struct cell_insn *b)
{
	unsigned i;

#define F(x) do { if (a->x != b->x) return #x; } while (0)
	F(op); F(len); F(n_op); F(cond); F(flags); F(wmask); F(at); F(at_va);
	F(target); F(target_va);
	for (i = 0; i < 3u; i++) {
		static const char *const nm[3][9] = {
			{ "o0.kind", "o0.reg", "o0.index", "o0.scale", "o0.size", "o0.flags", "o0.seg", "o0.disp", "o0.imm" },
			{ "o1.kind", "o1.reg", "o1.index", "o1.scale", "o1.size", "o1.flags", "o1.seg", "o1.disp", "o1.imm" },
			{ "o2.kind", "o2.reg", "o2.index", "o2.scale", "o2.size", "o2.flags", "o2.seg", "o2.disp", "o2.imm" },
		};
		const struct cell_operand *x = &a->o[i], *y = &b->o[i];

		if (x->kind != y->kind) return nm[i][0];
		if (x->reg != y->reg) return nm[i][1];
		if (x->index != y->index) return nm[i][2];
		if (x->scale != y->scale) return nm[i][3];
		if (x->size != y->size) return nm[i][4];
		if (x->flags != y->flags) return nm[i][5];
		if (x->seg != y->seg) return nm[i][6];
		if (x->disp != y->disp) return nm[i][7];
		if (x->imm != y->imm) return nm[i][8];
	}
#undef F
	return NULL;
}

static void report(const char *what, const uint8_t *b, unsigned nb, uint64_t va,
		   int be, uint32_t ra, uint32_t rb, const struct cell_insn *x,
		   const struct cell_insn *y)
{
	pthread_mutex_lock(&g_mu);
	g_diffs++;
	if (g_shown < 20) {
		g_shown++;
		printf("DIFF %s bytes", what);
		for (unsigned i = 0; i < nb; i++)
			printf(" %02x", b[i]);
		printf(" va %#" PRIx64 " be %d: ret ref %u new %u; ref op %u len %u nop %u cond %u fl %u wm %#" PRIx64
		       " tgt %#" PRIx64 " | new op %u len %u nop %u cond %u fl %u wm %#" PRIx64 " tgt %#" PRIx64 "\n",
		       va, be, ra, rb, x->op, x->len, x->n_op, x->cond, x->flags, x->wmask, x->target,
		       y->op, y->len, y->n_op, y->cond, y->flags, y->wmask, y->target);
	}
	pthread_mutex_unlock(&g_mu);
}

static uint64_t g_count[NTHREADS];

/* Decode `b` (nb bytes available) both ways at `va`, compare. */
static inline void one(int thumb, const uint8_t *b, unsigned nb, uint64_t va, int be,
		       uint64_t *cnt)
{
	struct cell_insn x, y;
	uint32_t ra, rb;
	const char *d;

	memset(&x, 0xa5, sizeof x);
	memset(&y, 0x5a, sizeof y);
	if (thumb) {
		ra = ref_decode_t32(b, nb, va, be, &x);
		rb = cell_decode_thumb(b, nb, va, be, &y);
	} else {
		ra = ref_decode_a32(b, nb, va, be, &x);
		rb = cell_decode_arm32(b, nb, va, be, &y);
	}
	(*cnt)++;
	if (ra != rb) {
		report("return", b, nb, va, be, ra, rb, &x, &y);
		return;
	}
	if (!ra)
		return;
	d = cmp_insn(&x, &y);
	if (d) {
		report(d, b, nb, va, be, ra, rb, &x, &y);
	}
}

static void put_word(uint8_t *b, uint32_t w, int be)
{
	if (be) {
		b[0] = (uint8_t)(w >> 24); b[1] = (uint8_t)(w >> 16);
		b[2] = (uint8_t)(w >> 8); b[3] = (uint8_t)w;
	} else {
		b[3] = (uint8_t)(w >> 24); b[2] = (uint8_t)(w >> 16);
		b[1] = (uint8_t)(w >> 8); b[0] = (uint8_t)w;
	}
}

static void put_half(uint8_t *b, uint32_t h, int be)
{
	if (be) {
		b[0] = (uint8_t)(h >> 8); b[1] = (uint8_t)h;
	} else {
		b[1] = (uint8_t)(h >> 8); b[0] = (uint8_t)h;
	}
}

/* ---- the work, split over threads ---------------------------------------- */

struct job {
	int id;
	int mode;               /* see run_job */
	int thumb;
	uint64_t a, b;          /* the range */
	uint64_t n, seed;       /* random mode: how many per thread, and the seed */
	uint32_t fills;
	const uint8_t *code;    /* elf mode */
	uint64_t clen, cva;
	int be;
};

enum { M_EXH, M_RAND, M_SYS, M_ELF };

static void *run_job(void *arg)
{
	struct job *j = arg;
	uint64_t *cnt = &g_count[j->id];
	uint8_t b[4];
	uint64_t s = j->seed * 0x100000001b3ull + (uint64_t)j->id * 7919u + 1u;
	uint64_t i;

	switch (j->mode) {
	case M_EXH:
		if (!j->thumb) {
			/* every word, in order; the address a function of the word so
			 * branches see many bases, high bits included (the target wraps) */
			for (i = j->a; i < j->b; i++) {
				uint32_t w = (uint32_t)i;
				uint64_t va = ((uint64_t)((w * 2654435761u) ^ (w >> 7)) << 2) |
					      ((i & 0x80000) ? 0x100000000ull : 0);

				put_word(b, w, 0);
				one(0, b, 4, va, 0, cnt);
				put_word(b, w, 1);
				one(0, b, 4, va ^ 0x1234u * 4u, 1, cnt);
			}
		} else {
			/* a is the first halfword range. A 16-bit one is decoded with the
			 * second halfword's bytes present and absent; a 32-bit one against
			 * every second halfword. Both parities of the address. */
			for (i = j->a; i < j->b; i++) {
				uint32_t h0 = (uint32_t)i;

				if (gt_thumb_len(h0) == 2u) {
					unsigned k;

					for (k = 0; k < 8u; k++) {
						uint32_t h1 = (uint32_t)rng_next(&s) & 0xffffu;
						uint64_t va = (rng_next(&s) & 0xfffffffeull) | (k & 1u ? 0 : 0);

						put_half(b, h0, k & 1u);
						put_half(b + 2, h1, k & 1u);
						one(1, b, 4, va, k & 1u, cnt);
						one(1, b, 2, va, k & 1u, cnt);
					}
				} else {
					uint32_t h1;

					for (h1 = 0; h1 < 65536u; h1++) {
						uint64_t va0 = 0x8000u + ((h1 & 1u) << 1);
						uint64_t va1 = 0xfffffff0ull + ((h1 & 1u) << 1);

						put_half(b, h0, h1 & 1u);
						put_half(b + 2, h1, h1 & 1u);
						one(1, b, 4, va0, h1 & 1u, cnt);
						one(1, b, 4, va1 ^ ((h1 >> 4) & 0xff0u) << 8,
						    (h1 >> 1) & 1u, cnt);
					}
					one(1, b, 2, 0x8000u, 0, cnt);          /* truncated: 0 */
				}
			}
		}
		break;
	case M_RAND:
		for (i = 0; i < j->n; i++) {
			uint64_t r = rng_next(&s);
			uint64_t va = (rng_next(&s) & 0x3ffffffffull) & ~1ull;

			if (!j->thumb) {
				put_word(b, (uint32_t)r, 0);
				one(0, b, 4, va & ~3ull, 0, cnt);
				put_word(b, (uint32_t)r, 1);
				one(0, b, 4, va & ~3ull, 1, cnt);
			} else {
				put_half(b, (uint32_t)r, 0);
				put_half(b + 2, (uint32_t)(r >> 32), 0);
				one(1, b, 4, va, 0, cnt);
				put_half(b, (uint32_t)r, 1);
				put_half(b + 2, (uint32_t)(r >> 32), 1);
				one(1, b, 4, va, 1, cnt);
			}
		}
		break;
	case M_SYS: {
		/* every combination of bits 27..20 and 7..4, with cond E and F; the rest
		 * random; a few fills of zeros and ones as well */
		uint64_t k;

		for (k = j->a; k < j->b; k++) {
			uint32_t hi = (uint32_t)(k & 0xff), lo = (uint32_t)((k >> 8) & 15u);
			uint32_t cond = (k >> 12) & 1u ? 0xFu : 0xEu;
			uint32_t f;

			for (f = 0; f < j->fills; f++) {
				uint32_t fill = (uint32_t)rng_next(&s);
				uint32_t w;

				if (f == 0)
					fill = 0;
				else if (f == 1)
					fill = 0xffffffffu;
				w = (fill & 0x000fff0fu) | cond << 28 | hi << 20 | lo << 4;
				put_word(b, w, 0);
				one(0, b, 4, (rng_next(&s) & 0xfffffffcull), 0, cnt);
			}
		}
		break;
	}
	case M_ELF:
		if (!j->thumb) {
			for (i = j->a; i + 4 <= j->b; i += 4)
				one(0, j->code + i, (unsigned)(j->clen - i < 4 ? j->clen - i : 4),
				    j->cva + i, j->be, cnt);
		} else {
			for (i = j->a; i + 2 <= j->b; i += 2)
				one(1, j->code + i, (unsigned)(j->clen - i < 4 ? j->clen - i : 4),
				    j->cva + i, j->be, cnt);
		}
		break;
	}
	return NULL;
}

static void run_all(struct job *tpl, uint64_t lo, uint64_t hi, uint64_t step_align)
{
	pthread_t th[NTHREADS];
	struct job j[NTHREADS];
	uint64_t chunk = (hi - lo + NTHREADS - 1) / NTHREADS;
	int t;

	chunk = (chunk + step_align - 1) / step_align * step_align;
	for (t = 0; t < NTHREADS; t++) {
		j[t] = *tpl;
		j[t].id = t;
		j[t].a = lo + (uint64_t)t * chunk;
		j[t].b = j[t].a + chunk;
		if (j[t].a > hi)
			j[t].a = hi;
		if (j[t].b > hi)
			j[t].b = hi;
		pthread_create(&th[t], NULL, run_job, &j[t]);
	}
	for (t = 0; t < NTHREADS; t++)
		pthread_join(th[t], NULL);
}

static uint64_t total(void)
{
	uint64_t n = 0;
	int t;

	for (t = 0; t < NTHREADS; t++)
		n += g_count[t];
	return n;
}

/* ---- ELF ----------------------------------------------------------------- */

struct blob {
	uint8_t *p;
	size_t n;
};

static int slurp(const char *path, struct blob *b)
{
	FILE *f = fopen(path, "rb");
	long n;

	if (!f)
		return 0;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	b->p = malloc((size_t)n);
	b->n = fread(b->p, 1, (size_t)n, f);
	fclose(f);
	return 1;
}

static int do_elf(int thumb, int argc, char **argv)
{
	int a;
	uint64_t words = 0;

	for (a = 0; a < argc; a++) {
		struct blob b;
		const Elf32_Ehdr *eh;
		int be;
		unsigned i;

		if (!slurp(argv[a], &b) || b.n < sizeof *eh)
			continue;
		eh = (const Elf32_Ehdr *)b.p;
		if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS32)
			continue;
		be = eh->e_ident[EI_DATA] == ELFDATA2MSB;
		/* program headers of an ELF in the other byte order: swap the three fields */
		{
			uint32_t phoff = SW32(eh->e_phoff);
			unsigned phn = SW16(eh->e_phnum), phes = SW16(eh->e_phentsize);

			for (i = 0; i < phn; i++) {
				const Elf32_Phdr *ph;
				uint32_t type, off, filesz, vaddr, flags;
				struct job tpl;

				if (phoff + (size_t)(i + 1) * phes > b.n)
					break;
				ph = (const Elf32_Phdr *)(b.p + phoff + (size_t)i * phes);
				type = SW32(ph->p_type);
				off = SW32(ph->p_offset);
				filesz = SW32(ph->p_filesz);
				vaddr = SW32(ph->p_vaddr);
				flags = SW32(ph->p_flags);
				if (type != PT_LOAD || !(flags & PF_X) || off + (uint64_t)filesz > b.n)
					continue;
				memset(&tpl, 0, sizeof tpl);
				tpl.mode = M_ELF;
				tpl.thumb = thumb;
				tpl.code = b.p + off;
				tpl.clen = filesz;
				tpl.cva = vaddr;
				tpl.be = be;
				run_all(&tpl, 0, filesz, 4);
				words += filesz / (thumb ? 2u : 4u);
			}
		}
		free(b.p);
	}
	printf("elf: %" PRIu64 " positions, %" PRIu64 " decodes compared, %" PRIu64 " differences\n", words, total(), g_diffs);
	return 0;
}

/* ---- speed --------------------------------------------------------------- */

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/*
 * Walk the executable code of the files the way a sweep walks it - ARM state by
 * 4, Thumb state by the length the decoder reports - through each of three
 * paths, and say ns per instruction. Single thread; pin it with taskset.
 */
static int g_reps = 60;

static int do_bench(int thumb, int only, int argc, char **argv)
{
	uint8_t **codes = calloc((size_t)argc, sizeof *codes);
	uint64_t *lens = calloc((size_t)argc, sizeof *lens), *vas = calloc((size_t)argc, sizeof *vas);
	int *bes = calloc((size_t)argc, sizeof *bes);
	int a, n = 0, path, rep;
	uint64_t cnt = 0;
	volatile uint64_t sink = 0;

	for (a = 0; a < argc; a++) {
		struct blob b;
		const Elf32_Ehdr *eh;
		int be;
		unsigned i;

		if (!slurp(argv[a], &b) || b.n < sizeof *eh)
			continue;
		eh = (const Elf32_Ehdr *)b.p;
		if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS32)
			continue;
		be = eh->e_ident[EI_DATA] == ELFDATA2MSB;
		{
			uint32_t phoff = SW32(eh->e_phoff);
			unsigned phn = SW16(eh->e_phnum), phes = SW16(eh->e_phentsize);

			for (i = 0; i < phn; i++) {
				const Elf32_Phdr *ph;

				if (phoff + (size_t)(i + 1) * phes > b.n)
					break;
				ph = (const Elf32_Phdr *)(b.p + phoff + (size_t)i * phes);
				if (SW32(ph->p_type) != PT_LOAD || !(SW32(ph->p_flags) & PF_X) ||
				    SW32(ph->p_offset) + (uint64_t)SW32(ph->p_filesz) > b.n)
					continue;
				codes = realloc(codes, (size_t)(n + 1) * sizeof *codes);
				lens = realloc(lens, (size_t)(n + 1) * sizeof *lens);
				vas = realloc(vas, (size_t)(n + 1) * sizeof *vas);
				bes = realloc(bes, (size_t)(n + 1) * sizeof *bes);
				codes[n] = b.p + SW32(ph->p_offset);
				lens[n] = SW32(ph->p_filesz);
				vas[n] = SW32(ph->p_vaddr);
				bes[n] = be;
				n++;
			}
		}
	}
	{
		/* the first decode builds the index: what that costs, once */
		double t0 = now(), t1;

		gt_arm32_build();
		t1 = now();
		gt_thumb_build();
		printf("index build: ARM state %.0f us, Thumb state %.0f us\n", (t1 - t0) * 1e6,
		       (now() - t1) * 1e6);
	}
	for (path = 0; path < 3; path++) {
		static const char *const nm[3] = { "genotype decode alone", "full adapter path", "frozen reference" };
		double best = 1e30;

		if (only >= 0 && path != only)
			continue;
		for (rep = 0; rep < g_reps; rep++) {
			double t0 = now();
			int c;

			cnt = 0;
			for (c = 0; c < n; c++) {
				uint64_t off = 0;

				while (off + (thumb ? 2u : 4u) <= lens[c]) {
					struct cell_insn k;
					uint32_t len;
					const uint8_t *p = codes[c] + off;
					uint32_t avail = (uint32_t)(lens[c] - off < 4 ? lens[c] - off : 4);

					if (path == 0) {
						if (thumb) {
							struct gt_thumb_insn t;
							uint32_t h0 = arm_h_(p, bes[c]), h1 = 0;

							len = gt_thumb_len(h0);
							if (len == 4u) {
								if (avail < 4u)
									break;
								h1 = arm_h_(p + 2, bes[c]);
							}
							(void)gt_thumb_decode(&t, h0, h1);
							sink += t.id;
						} else {
							struct gt_arm32_insn t;

							(void)gt_arm32_decode(&t, arm_w_(p, bes[c]));
							sink += t.id;
							len = 4;
						}
					} else if (path == 1) {
						len = thumb ? cell_decode_thumb(p, avail, vas[c] + off, bes[c], &k)
							    : cell_decode_arm32(p, avail, vas[c] + off, bes[c], &k);
						sink += k.op;
					} else {
						len = thumb ? ref_decode_t32(p, avail, vas[c] + off, bes[c], &k)
							    : ref_decode_a32(p, avail, vas[c] + off, bes[c], &k);
						sink += k.op;
					}
					if (!len)
						break;
					off += len;
					cnt++;
				}
			}
			t0 = now() - t0;
			if (t0 < best)
				best = t0;
		}
		printf("%-24s %s: %" PRIu64 " insns, best of %d %.3f s = %.2f ns/insn\n", nm[path],
		       thumb ? "thumb" : "arm  ", cnt, g_reps, best, best * 1e9 / (double)cnt);
	}
	(void)sink;
	return 0;
}

int main(int argc, char **argv)
{
	struct job tpl;
	int thumb;

	if (argc >= 4 && !strcmp(argv[1], "bench")) {
		return do_bench(!strcmp(argv[2], "thumb"), -1, argc - 3, argv + 3);
	}
	/* bench1 <0|1|2> arm|thumb files: one path only, for a profiler */
	if (argc >= 6 && !strcmp(argv[1], "bench1")) {
		g_reps = atoi(argv[3]);
		return do_bench(!strcmp(argv[4], "thumb"), atoi(argv[2]), argc - 5, argv + 5);
	}
	if (argc < 3) {
		fprintf(stderr, "usage: see the top of the file\n");
		return 2;
	}
	thumb = !strcmp(argv[1], "thumb");
	memset(&tpl, 0, sizeof tpl);
	tpl.thumb = thumb;
	if (!strcmp(argv[2], "exh")) {
		tpl.mode = M_EXH;
		if (thumb)
			run_all(&tpl, 0, 65536u, 1);
		else
			run_all(&tpl, 0, 1ull << 32, 1);
	} else if (!strcmp(argv[2], "rand")) {
		uint64_t m = argc > 3 ? strtoull(argv[3], NULL, 10) : 1;

		tpl.mode = M_RAND;
		tpl.seed = argc > 4 ? strtoull(argv[4], NULL, 10) : 1;
		tpl.n = m * 1000000ull / NTHREADS;
		run_all(&tpl, 0, NTHREADS, 1);          /* the range is only the thread split */
	} else if (!strcmp(argv[2], "sys")) {
		tpl.mode = M_SYS;
		tpl.fills = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 10) : 1000;
		run_all(&tpl, 0, 8192, 1);
	} else if (!strcmp(argv[2], "elf")) {
		return do_elf(thumb, argc - 3, argv + 3) || g_diffs ? 1 : 0;
	} else {
		fprintf(stderr, "unknown mode\n");
		return 2;
	}
	printf("%s %s: %" PRIu64 " decodes compared, %" PRIu64 " differences\n", argv[1], argv[2],
	       total(), g_diffs);
	return g_diffs ? 1 : 0;
}
