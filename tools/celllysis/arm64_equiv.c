/*
 * arm64_equiv - the AArch64 decoder (genotype table + celllysis adapter) against
 * the decoder it replaced, field for field.
 *
 * A DEV TOOL, NOT A TEST: it needs the replaced decoder, which is not in the
 * tree any more. Keep a copy with its one external symbol renamed
 * (cell_decode_a64 -> ref_decode_a64) and build by hand, e.g.
 *
 *   gcc -O2 -std=gnu11 -pthread -Ilibkofeng/kofcore -Ilibgenome \
 *       -Ilibgenome/genotype -Ilibgenome/celllysis tools/celllysis/arm64_equiv.c \
 *       <ref_a64.c> libgenome/celllysis/decode_arm64.c \
 *       libgenome/genotype/arm64/arm64.c libgenome/genotype/arm64/arm64_tab.c -o arm64_equiv
 *
 * WHAT IS COMPARED. Both decoders are given the same four bytes at the same
 * address and every field of struct cell_insn is compared - op, len, n_op, cond,
 * flags, wmask, at, at_va, target, target_va, and for each of the three operands
 * kind, reg, index, scale, size, flags, seg, disp and imm. The fields, not the
 * bytes: _pad is undefined and is not looked at. The return value is compared
 * too. The first difference found in a word is the one counted and printed.
 *
 * INPUTS.
 *   -x          every one of the 2^32 words, at each address given with -a
 *   -a VA       an address to decode at (repeatable; default 0x400000). What
 *               depends on it is every branch target and adr/adrp, so values
 *               near 2^64 are the ones that matter: the target wraps.
 *   -r N        N random words per thread at a random address each (16 threads)
 *   -e FILE     every four-byte word of every executable section of the
 *               AArch64 ELF files named in FILE (one path per line), decoded at
 *               each -a address plus the word's FILE OFFSET
 *   -t          speed: ns per instruction for gt_arm64_decode alone, the
 *               whole adapter path and the replaced decoder, over the -e words
 *
 * Exit status is 0 only when no difference was found.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kofmod/cell.h"
#include "decode.h"
#include <arm64/arm64.h>

/* the replaced decoder, symbol renamed */
uint32_t ref_decode_a64(const uint8_t *p, uint32_t n, uint64_t va,
			struct cell_insn *out);

#define NTHR 16
#define MAXVA 16
#define MAXEX 24

static uint64_t g_va[MAXVA];
static unsigned g_nva;

struct ex {
	uint32_t w;
	uint64_t va;
	const char *field;
};

struct res {
	uint64_t words, diffs;
	struct ex ex[MAXEX];
	unsigned nex;
};

/* The first field in which two decodes differ, or NULL. */
static const char *diff(uint32_t ra, const struct cell_insn *a,
			uint32_t rb, const struct cell_insn *b)
{
	unsigned i;
	static const char *const opn[3] = { "o[0].", "o[1].", "o[2]." };

	(void)opn;
	if (ra != rb) return "return";
	if (a->op != b->op) return "op";
	if (a->len != b->len) return "len";
	if (a->n_op != b->n_op) return "n_op";
	if (a->cond != b->cond) return "cond";
	if (a->flags != b->flags) return "flags";
	if (a->wmask != b->wmask) return "wmask";
	if (a->at != b->at) return "at";
	if (a->at_va != b->at_va) return "at_va";
	if (a->target != b->target) return "target";
	if (a->target_va != b->target_va) return "target_va";
	for (i = 0; i < 3; i++) {
		const struct cell_operand *x = &a->o[i], *y = &b->o[i];

		if (x->kind != y->kind) return i == 0 ? "o0.kind" : i == 1 ? "o1.kind" : "o2.kind";
		if (x->reg != y->reg) return i == 0 ? "o0.reg" : i == 1 ? "o1.reg" : "o2.reg";
		if (x->index != y->index) return i == 0 ? "o0.index" : i == 1 ? "o1.index" : "o2.index";
		if (x->scale != y->scale) return i == 0 ? "o0.scale" : i == 1 ? "o1.scale" : "o2.scale";
		if (x->size != y->size) return i == 0 ? "o0.size" : i == 1 ? "o1.size" : "o2.size";
		if (x->flags != y->flags) return i == 0 ? "o0.flags" : i == 1 ? "o1.flags" : "o2.flags";
		if (x->seg != y->seg) return i == 0 ? "o0.seg" : i == 1 ? "o1.seg" : "o2.seg";
		if (x->disp != y->disp) return i == 0 ? "o0.disp" : i == 1 ? "o1.disp" : "o2.disp";
		if (x->imm != y->imm) return i == 0 ? "o0.imm" : i == 1 ? "o1.imm" : "o2.imm";
	}
	return NULL;
}

static inline void check(struct res *r, uint32_t w, uint64_t va)
{
	uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8), (uint8_t)(w >> 16), (uint8_t)(w >> 24) };
	struct cell_insn a, c;
	uint32_t ra, rc;
	const char *f;

	/* poison both, so a field a decoder forgets to write cannot match by luck of the stack */
	memset(&a, 0xa5, sizeof a);
	memset(&c, 0x5a, sizeof c);
	ra = ref_decode_a64(b, 4, va, &a);
	rc = cell_decode_arm64(b, 4, va, &c);
	r->words++;
	f = diff(ra, &a, rc, &c);
	if (f) {
		r->diffs++;
		if (r->nex < MAXEX) {
			r->ex[r->nex].w = w;
			r->ex[r->nex].va = va;
			r->ex[r->nex].field = f;
			r->nex++;
		}
	}
}

static uint64_t splitmix(uint64_t *s)
{
	uint64_t z = (*s += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

struct job {
	unsigned id;
	int mode;                       /* 0 exhaustive at one va, 1 random */
	uint64_t va, n;
	struct res r;
};

static void *worker(void *arg)
{
	struct job *j = arg;
	uint64_t i;

	if (j->mode == 0) {
		uint64_t lo = (uint64_t)j->id << 28;

		for (i = lo; i < lo + (1ull << 28); i++)
			check(&j->r, (uint32_t)i, j->va);
	} else {
		uint64_t s = 0x4b4f464e47ull + (uint64_t)j->id * 0x100000001b3ull;

		for (i = 0; i < j->n; i++) {
			uint64_t r1 = splitmix(&s), r2 = splitmix(&s);
			/* a random address, a quarter of them within a page of the top of the space */
			uint64_t va = (r1 & 3u) == 0 ? ~0ull - (r2 & 0xfffffu) : r2;  /* r1's low bits are not the word's */

			check(&j->r, (uint32_t)(r1 >> 32), va & ~3ull);
		}
	}
	return NULL;
}

static uint64_t run(int mode, uint64_t va, uint64_t n, const char *what)
{
	pthread_t th[NTHR];
	struct job *jobs = calloc(NTHR, sizeof *jobs);
	uint64_t words = 0, diffs = 0;
	unsigned i, k;

	for (i = 0; i < NTHR; i++) {
		jobs[i].id = i;
		jobs[i].mode = mode;
		jobs[i].va = va;
		jobs[i].n = n;
		pthread_create(&th[i], NULL, worker, &jobs[i]);
	}
	for (i = 0; i < NTHR; i++) {
		pthread_join(th[i], NULL);
		words += jobs[i].r.words;
		diffs += jobs[i].r.diffs;
	}
	printf("%s: %llu words, %llu differences\n", what,
	       (unsigned long long)words, (unsigned long long)diffs);
	for (i = 0, k = 0; i < NTHR && k < 12; i++) {
		unsigned e;

		for (e = 0; e < jobs[i].r.nex && k < 12; e++, k++)
			printf("  DIFF %08x at %016llx: %s\n", jobs[i].r.ex[e].w,
			       (unsigned long long)jobs[i].r.ex[e].va, jobs[i].r.ex[e].field);
	}
	free(jobs);
	return diffs;
}

/* ---- real code ------------------------------------------------------------ */

static uint8_t *g_code;
static uint64_t *g_off;                 /* file offset of each word, within its file's address space */
static size_t g_ncode;

static void load_elf(const char *path, uint64_t *fileno_base)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	long len;
	const Elf64_Ehdr *eh;
	int i;

	if (!f)
		return;
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)len);
	if (!buf || fread(buf, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		free(buf);
		return;
	}
	fclose(f);
	eh = (const Elf64_Ehdr *)buf;
	if ((size_t)len < sizeof *eh || memcmp(buf, ELFMAG, 4) || eh->e_machine != 183 ||
	    buf[EI_CLASS] != ELFCLASS64)
		goto out;
	if (eh->e_shoff && eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) <= (uint64_t)len) {
		const Elf64_Shdr *sh = (const Elf64_Shdr *)(buf + eh->e_shoff);

		for (i = 0; i < eh->e_shnum; i++) {
			uint64_t o;

			if (!(sh[i].sh_flags & SHF_EXECINSTR) || sh[i].sh_type != SHT_PROGBITS ||
			    sh[i].sh_offset + sh[i].sh_size > (uint64_t)len)
				continue;
			for (o = 0; o + 4 <= sh[i].sh_size; o += 4) {
				if ((g_ncode & 0xfffff) == 0) {
					g_code = realloc(g_code, (g_ncode + 0x100000) * 4);
					g_off = realloc(g_off, (g_ncode + 0x100000) * sizeof *g_off);
				}
				memcpy(g_code + g_ncode * 4, buf + sh[i].sh_offset + o, 4);
				g_off[g_ncode++] = sh[i].sh_offset + o;
			}
		}
	}
out:
	(void)fileno_base;
	free(buf);
}

static void load_list(const char *list)
{
	FILE *f = fopen(list, "r");
	char line[1024];
	unsigned n = 0;

	while (f && fgets(line, sizeof line, f)) {
		line[strcspn(line, "\n")] = 0;
		load_elf(line, NULL);
		n++;
	}
	if (f)
		fclose(f);
	printf("real code: %u files listed, %zu words loaded\n", n, g_ncode);
}

struct ejob {
	unsigned id;
	uint64_t base;
	struct res r;
};

static void *eworker(void *arg)
{
	struct ejob *j = arg;
	size_t i;

	for (i = j->id; i < g_ncode; i += NTHR) {
		uint32_t w;

		memcpy(&w, g_code + i * 4, 4);
		check(&j->r, w, j->base + g_off[i]);
	}
	return NULL;
}

static uint64_t run_elf(uint64_t base)
{
	pthread_t th[NTHR];
	struct ejob *jobs = calloc(NTHR, sizeof *jobs);
	uint64_t words = 0, diffs = 0;
	unsigned i, k;
	char what[80];

	for (i = 0; i < NTHR; i++) {
		jobs[i].id = i;
		jobs[i].base = base;
		pthread_create(&th[i], NULL, eworker, &jobs[i]);
	}
	for (i = 0; i < NTHR; i++) {
		pthread_join(th[i], NULL);
		words += jobs[i].r.words;
		diffs += jobs[i].r.diffs;
	}
	snprintf(what, sizeof what, "real code at base %#llx", (unsigned long long)base);
	printf("%s: %llu words, %llu differences\n", what,
	       (unsigned long long)words, (unsigned long long)diffs);
	for (i = 0, k = 0; i < NTHR && k < 12; i++) {
		unsigned e;

		for (e = 0; e < jobs[i].r.nex && k < 12; e++, k++)
			printf("  DIFF %08x at %016llx: %s\n", jobs[i].r.ex[e].w,
			       (unsigned long long)jobs[i].r.ex[e].va, jobs[i].r.ex[e].field);
	}
	free(jobs);
	return diffs;
}

/* ---- speed ---------------------------------------------------------------- */

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* Same words, same order, one thread, three paths. Each is run `reps` times and the best pass is reported. */
static void speed(void)
{
	size_t i, n = g_ncode;
	int reps = 7, r;
	uint64_t sink = 0;
	double t0, best[3] = { 1e9, 1e9, 1e9 };
	struct cell_insn k;
	struct gt_arm64_insn g;

	if (!n) {
		printf("speed: no real code loaded\n");
		return;
	}
	for (r = 0; r < reps; r++) {
		t0 = now();
		for (i = 0; i < n; i++) {
			uint32_t w;

			memcpy(&w, g_code + i * 4, 4);
			(void)gt_arm64_decode(&g, w);
			sink += g.id;
		}
		if (now() - t0 < best[0]) best[0] = now() - t0;
		t0 = now();
		for (i = 0; i < n; i++) {
			cell_decode_arm64(g_code + i * 4, 4, 0x400000 + g_off[i], &k);
			sink += k.wmask + k.op;
		}
		if (now() - t0 < best[1]) best[1] = now() - t0;
		t0 = now();
		for (i = 0; i < n; i++) {
			ref_decode_a64(g_code + i * 4, 4, 0x400000 + g_off[i], &k);
			sink += k.wmask + k.op;
		}
		if (now() - t0 < best[2]) best[2] = now() - t0;
	}
	printf("speed over %zu real words, best of %d passes, one thread:\n", n, reps);
	printf("  gt_arm64_decode alone      %6.2f ns/insn\n", best[0] * 1e9 / (double)n);
	printf("  cell_decode_arm64 (new)    %6.2f ns/insn\n", best[1] * 1e9 / (double)n);
	printf("  replaced decoder           %6.2f ns/insn\n", best[2] * 1e9 / (double)n);
	if (sink == 42)
		puts("");
}

int main(int argc, char **argv)
{
	int a, exh = 0, dospeed = 0;
	uint64_t nrand = 0, diffs = 0;
	const char *elf = NULL;
	unsigned i;

	for (a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "-x")) exh = 1;
		else if (!strcmp(argv[a], "-t")) dospeed = 1;
		else if (!strcmp(argv[a], "-r") && a + 1 < argc) nrand = strtoull(argv[++a], 0, 0);
		else if (!strcmp(argv[a], "-e") && a + 1 < argc) elf = argv[++a];
		else if (!strcmp(argv[a], "-a") && a + 1 < argc && g_nva < MAXVA) g_va[g_nva++] = strtoull(argv[++a], 0, 0);
	}
	if (!g_nva)
		g_va[g_nva++] = 0x400000;
	if (exh) {
		for (i = 0; i < g_nva; i++) {
			char w[64];

			snprintf(w, sizeof w, "exhaustive at %#llx", (unsigned long long)g_va[i]);
			diffs += run(0, g_va[i], 0, w);
		}
	}
	if (nrand)
		diffs += run(1, 0, nrand, "random words, random addresses");
	if (elf) {
		load_list(elf);
		for (i = 0; i < g_nva; i++)
			diffs += run_elf(g_va[i]);
	}
	if (dospeed)
		speed();
	printf("TOTAL differences: %llu\n", (unsigned long long)diffs);
	return diffs != 0;
}
