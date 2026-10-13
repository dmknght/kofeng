/*
 * hk.h - the shared kit of the hostile_*.c and api_*.c tests of libgenome.
 *
 * Header only, included by exactly the tests that need it; every helper is
 * static, so a test that does not use one pays nothing and -Wunused is quiet
 * through HK_UNUSED. Nothing here is a fixture file: every object a test
 * analyses is BUILT IN MEMORY by the builders below, from the field values the
 * test names, so a reader sees the hostile value next to the check it breaks.
 *
 *   guard buffer   gb_put() copies an object so that its LAST byte is the last
 *                  byte before a PROT_NONE page. Any read past the length the
 *                  caller handed in faults at once, in the test process, with no
 *                  sanitizer needed. Call it with every length 0..N to turn
 *                  "reads only inside the buffer" into something that is run.
 *   isolation      hk_isolated() runs one case in a forked child with an alarm,
 *                  so a crash or a hang in the product is a RESULT, not the end
 *                  of the test run (HK_OK / HK_FAILED / HK_CRASHED / HK_HUNG).
 *   builders       hk_elf() and hk_pe() make small valid objects (ELF32/64, LE
 *                  and BE, ET_REL and ET_EXEC; PE32 and PE32+) whose fields the
 *                  test then corrupts at a named offset.
 *   hk_rng         a fixed-seed xorshift: every "random" run is reproducible.
 */
#ifndef KGENOME_TESTS_HK_H
#define KGENOME_TESTS_HK_H

#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__GNUC__)
#define HK_UNUSED __attribute__((unused))
#else
#define HK_UNUSED
#endif

static int hk_fails HK_UNUSED;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		hk_fails++; \
	} \
} while (0)

/* ---- the deterministic generator ----------------------------------------- */

struct hk_rng { uint64_t s; };

static inline uint64_t hk_next(struct hk_rng *r) HK_UNUSED;
static inline uint64_t hk_next(struct hk_rng *r)
{
	r->s ^= r->s << 13;
	r->s ^= r->s >> 7;
	r->s ^= r->s << 17;
	return r->s;
}

static inline uint32_t hk_below(struct hk_rng *r, uint32_t n) HK_UNUSED;
static inline uint32_t hk_below(struct hk_rng *r, uint32_t n)
{
	return n ? (uint32_t)(hk_next(r) % n) : 0u;
}

/* Switches of a campaign run outside the suite (a test does not read the environment):
 *   --scale=N         multiplies the iteration counts of the random families (the suite runs at 1)
 *   --inline          runs each isolated case in this process, so a debugger sees the crash
 *   --threads-only    hostile_lifetime: just the parallel instances, for a ThreadSanitizer run */
static unsigned hk_scale_v = 1;
static int hk_inline_v, hk_threads_only_v;

static unsigned hk_scale(void) HK_UNUSED;
static unsigned hk_scale(void)
{
	return hk_scale_v;
}

static void hk_args(int argc, char **argv) HK_UNUSED;
static void hk_args(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--scale=", 8)) {
			long v = strtol(argv[i] + 8, NULL, 10);
			hk_scale_v = v > 0 && v < 100000 ? (unsigned)v : 1u;
		} else if (!strcmp(argv[i], "--inline")) {
			hk_inline_v = 1;
		} else if (!strcmp(argv[i], "--threads-only")) {
			hk_threads_only_v = 1;
		}
	}
}

/* Is the process built with UBSAN? A weak reference to one of its runtime entry points: non-null
 * only when the sanitizer's runtime is linked. The hostile families use it to leave out the few
 * INPUTS that reach undefined behaviour the library is KNOWN to have (each is named at its gate and
 * listed in the defect report): in a plain build those inputs run, and wrap as they always have; in
 * a UBSAN build they would abort the whole family and hide everything after them. */
extern void __ubsan_handle_add_overflow(void) __attribute__((weak));

static int hk_ubsan(void) HK_UNUSED;
static int hk_ubsan(void)
{
	return &__ubsan_handle_add_overflow != NULL;
}

/* ---- the clock ----------------------------------------------------------- */

static double hk_now(void) HK_UNUSED;
static double hk_now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* ---- the guard-page buffer ------------------------------------------------ */

struct hk_gb {
	uint8_t *map;
	size_t   len;     /* the whole mapping */
	size_t   page;
	size_t   cap;     /* the most bytes a put may hold */
};

static void gb_init(struct hk_gb *g, size_t cap) HK_UNUSED;
static void gb_init(struct hk_gb *g, size_t cap)
{
	size_t pg = (size_t)sysconf(_SC_PAGESIZE);
	size_t body = (cap + pg - 1u) / pg * pg + pg;   /* one spare page in front */

	g->page = pg;
	g->cap = cap;
	g->len = body + pg;
	g->map = (uint8_t *)mmap(NULL, g->len, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g->map == MAP_FAILED) {
		perror("mmap");
		exit(2);
	}
	/* the page after the buffer: no access at all */
	if (mprotect(g->map + body, pg, PROT_NONE) != 0) {
		perror("mprotect");
		exit(2);
	}
}

/* Copy n bytes so the last one abuts the guard page; returns where. n == 0
 * returns the guard page's own address: any dereference faults. */
static uint8_t *gb_put(struct hk_gb *g, const void *src, size_t n) HK_UNUSED;
static uint8_t *gb_put(struct hk_gb *g, const void *src, size_t n)
{
	uint8_t *end = g->map + g->len - g->page;
	uint8_t *p = end - n;

	if (n > g->cap) {
		fprintf(stderr, "gb_put: %zu > cap %zu\n", n, g->cap);
		exit(2);
	}
	if (n && src)
		memmove(p, src, n);
	return p;
}

static void gb_free(struct hk_gb *g) HK_UNUSED;
static void gb_free(struct hk_gb *g)
{
	munmap(g->map, g->len);
	g->map = NULL;
}

/* ---- the isolated case ----------------------------------------------------- */

enum hk_result { HK_OK = 0, HK_FAILED, HK_CRASHED, HK_HUNG };

typedef int (*hk_case_fn)(void *arg);

/* Run fn(arg) in a child. The child's return value is its verdict: 0 is a pass.
 * A signal is HK_CRASHED (the signal is stored in *sig when given), the alarm is
 * HK_HUNG. The child inherits the parent's stdio buffers emptied. */
static enum hk_result hk_isolated(hk_case_fn fn, void *arg, unsigned secs,
				  int *sig) HK_UNUSED;
static enum hk_result hk_isolated(hk_case_fn fn, void *arg, unsigned secs, int *sig)
{
	int st = 0;
	pid_t pid;

	/* --inline runs the case in this process, so a debugger sees the crash */
	if (hk_inline_v) {
		if (sig)
			*sig = 0;
		return fn(arg) ? HK_FAILED : HK_OK;
	}
	fflush(NULL);
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(2);
	}
	if (pid == 0) {
		int rc;
		signal(SIGALRM, SIG_DFL);
		alarm(secs);
		hk_fails = 0;
		rc = fn(arg);
		fflush(NULL);
		_exit(rc ? 1 : 0);
	}
	if (waitpid(pid, &st, 0) < 0)
		return HK_FAILED;
	if (sig)
		*sig = 0;
	if (WIFSIGNALED(st)) {
		if (sig)
			*sig = WTERMSIG(st);
		return WTERMSIG(st) == SIGALRM ? HK_HUNG : HK_CRASHED;
	}
	return WEXITSTATUS(st) == 0 ? HK_OK : HK_FAILED;
}

/* ---- little-endian / either-endian writers ---------------------------------- */

static void hk_w(uint8_t *p, uint64_t v, unsigned n, int be) HK_UNUSED;
static void hk_w(uint8_t *p, uint64_t v, unsigned n, int be)
{
	unsigned i;
	for (i = 0; i < n; i++)
		p[be ? n - 1u - i : i] = (uint8_t)(v >> (8u * i));
}

static uint64_t hk_r(const uint8_t *p, unsigned n, int be) HK_UNUSED;
static uint64_t hk_r(const uint8_t *p, unsigned n, int be)
{
	uint64_t v = 0;
	unsigned i;
	for (i = 0; i < n; i++)
		v |= (uint64_t)p[be ? n - 1u - i : i] << (8u * i);
	return v;
}

/* ---- the ELF builder --------------------------------------------------------
 *
 * One object: .text .symtab .strtab .rela.text .shstrtab, optionally under one
 * PT_LOAD. Offsets are published in struct hk_elf so a test can aim a corrupt
 * value at "the symtab's sh_size" by name. */

#define HK_ELF_MAX 4096u

struct hk_elf {
	uint8_t  b[HK_ELF_MAX];
	uint32_t n;
	int      is64, be, rel, machine;
	uint32_t ehdr, ph, text, symtab, strtab, rela, shstr, sh;
	uint32_t sh_ent, ph_ent, sym_ent, rela_ent, nsym, nrela;
};

static void hk_elf(struct hk_elf *e, int is64, int be, int rel) HK_UNUSED;
static void hk_elf(struct hk_elf *e, int is64, int be, int rel)
{
	/* the sections' names, in one string table */
	static const char shn[] = "\0.text\0.symtab\0.strtab\0.rela.text\0.shstrtab";
	static const char str[] = "\0main\0puts\0helper";
	uint8_t *b = e->b;
	unsigned w = is64 ? 8u : 4u;
	uint32_t at, i;

	memset(e, 0, sizeof *e);
	e->is64 = is64; e->be = be; e->rel = rel;
	e->machine = is64 ? 62 : 3;
	e->ehdr = 0;
	e->ph_ent = is64 ? 56u : 32u;
	e->sh_ent = is64 ? 64u : 40u;
	e->sym_ent = is64 ? 24u : 16u;
	e->rela_ent = is64 ? 24u : 12u;
	e->nsym = 4; e->nrela = 2;
	e->ph = is64 ? 64u : 52u;
	at = e->ph + (rel ? 0u : e->ph_ent);
	e->text = (at + 15u) & ~15u;
	at = e->text + 32u;
	e->symtab = (at + 7u) & ~7u;
	at = e->symtab + e->nsym * e->sym_ent;
	e->strtab = at;
	at += (uint32_t)sizeof str;
	e->rela = (at + 7u) & ~7u;
	at = e->rela + e->nrela * e->rela_ent;
	e->shstr = at;
	at += (uint32_t)sizeof shn;
	e->sh = (at + 7u) & ~7u;
	e->n = e->sh + 6u * e->sh_ent;

	/* ELF header */
	b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
	b[4] = is64 ? 2 : 1; b[5] = be ? 2 : 1; b[6] = 1;
	hk_w(b + 16, rel ? 1 : 2, 2, be);
	hk_w(b + 18, (uint64_t)e->machine, 2, be);
	hk_w(b + 20, 1, 4, be);
	if (is64) {
		hk_w(b + 24, rel ? 0 : 0x400000u + e->text, 8, be);
		hk_w(b + 32, rel ? 0 : e->ph, 8, be);
		hk_w(b + 40, e->sh, 8, be);
		hk_w(b + 52, 64, 2, be);
		hk_w(b + 54, rel ? 0 : e->ph_ent, 2, be);
		hk_w(b + 56, rel ? 0 : 1, 2, be);
		hk_w(b + 58, e->sh_ent, 2, be);
		hk_w(b + 60, 6, 2, be);
		hk_w(b + 62, 5, 2, be);
	} else {
		hk_w(b + 24, rel ? 0 : 0x400000u + e->text, 4, be);
		hk_w(b + 28, rel ? 0 : e->ph, 4, be);
		hk_w(b + 32, e->sh, 4, be);
		hk_w(b + 40, 52, 2, be);
		hk_w(b + 42, rel ? 0 : e->ph_ent, 2, be);
		hk_w(b + 44, rel ? 0 : 1, 2, be);
		hk_w(b + 46, e->sh_ent, 2, be);
		hk_w(b + 48, 6, 2, be);
		hk_w(b + 50, 5, 2, be);
	}
	/* one PT_LOAD over the whole file, R+X */
	if (!rel) {
		uint8_t *p = b + e->ph;
		hk_w(p, 1, 4, be);
		if (is64) {
			hk_w(p + 4, 5, 4, be);
			hk_w(p + 8, 0, 8, be);
			hk_w(p + 16, 0x400000, 8, be);
			hk_w(p + 24, 0x400000, 8, be);
			hk_w(p + 32, e->n, 8, be);
			hk_w(p + 40, e->n + 0x100u, 8, be);
			hk_w(p + 48, 0x1000, 8, be);
		} else {
			hk_w(p + 4, 0, 4, be);
			hk_w(p + 8, 0x400000, 4, be);
			hk_w(p + 12, 0x400000, 4, be);
			hk_w(p + 16, e->n, 4, be);
			hk_w(p + 20, e->n + 0x100u, 4, be);
			hk_w(p + 24, 5, 4, be);
			hk_w(p + 28, 0x1000, 4, be);
		}
	}
	/* .text: xor eax,eax ; call rel32 (hole) ; ret, then nops */
	{
		static const uint8_t code[] = { 0x31, 0xc0, 0xe8, 0, 0, 0, 0, 0xc3,
						0x90, 0x90, 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
		memset(b + e->text, 0x90, 32);
		memcpy(b + e->text, code, sizeof code);
	}
	memcpy(b + e->strtab, str, sizeof str);
	memcpy(b + e->shstr, shn, sizeof shn);
	/* symbols: null, main (func, defined, .text), puts (undef), helper (func) */
	for (i = 0; i < e->nsym; i++) {
		uint8_t *s = b + e->symtab + i * e->sym_ent;
		static const uint32_t nm[4] = { 0, 1, 6, 11 };
		static const uint64_t val[4] = { 0, 0, 0, 10 };
		static const uint16_t shn_[4] = { 0, 1, 0, 1 };
		static const uint8_t info[4] = { 0, 0x12, 0x12, 0x12 };
		if (!i)
			continue;
		if (is64) {
			hk_w(s, nm[i], 4, be);
			s[4] = info[i];
			hk_w(s + 6, shn_[i], 2, be);
			hk_w(s + 8, val[i] ? 0x400000u + e->text + val[i] : (shn_[i] ? 0x400000u + e->text : 0), 8, be);
			hk_w(s + 16, shn_[i] ? 6 : 0, 8, be);
		} else {
			hk_w(s, nm[i], 4, be);
			hk_w(s + 4, val[i] ? 0x400000u + e->text + val[i] : (shn_[i] ? 0x400000u + e->text : 0), 4, be);
			hk_w(s + 8, shn_[i] ? 6 : 0, 4, be);
			s[12] = info[i];
			hk_w(s + 14, shn_[i], 2, be);
		}
	}
	/* relocations: a call at text+3 against puts (sym 2), one against helper (sym 3) */
	for (i = 0; i < e->nrela; i++) {
		uint8_t *r = b + e->rela + i * e->rela_ent;
		uint64_t where = i ? 11u : 3u, sym = i ? 3u : 2u;
		if (is64) {
			hk_w(r, where, 8, be);
			hk_w(r + 8, (sym << 32) | 4u, 8, be);      /* R_X86_64_PLT32 */
			hk_w(r + 16, (uint64_t)-4, 8, be);
		} else {
			hk_w(r, where, 4, be);
			hk_w(r + 4, (sym << 8) | 4u, 4, be);
			hk_w(r + 8, (uint64_t)-4, 4, be);
		}
	}
	/* section headers: null, .text, .symtab, .strtab, .rela.text, .shstrtab */
	{
		struct { uint32_t name, type; uint64_t flags; uint32_t off, size, link, info, ent; } s[6] = {
			{ 0, 0, 0, 0, 0, 0, 0, 0 },
			{ 1, 1, 6, e->text, 32, 0, 0, 0 },
			{ 7, 2, 0, e->symtab, e->nsym * e->sym_ent, 3, 1, e->sym_ent },
			{ 15, 3, 0, e->strtab, (uint32_t)sizeof str, 0, 0, 0 },
			{ 23, 4, 0x40, e->rela, e->nrela * e->rela_ent, 2, 1, e->rela_ent },
			{ 34, 3, 0, e->shstr, (uint32_t)sizeof shn, 0, 0, 0 }
		};
		for (i = 0; i < 6; i++) {
			uint8_t *h = b + e->sh + i * e->sh_ent;
			hk_w(h, s[i].name, 4, be);
			hk_w(h + 4, s[i].type, 4, be);
			if (is64) {
				hk_w(h + 8, s[i].flags, 8, be);
				hk_w(h + 16, s[i].type == 1 && !rel ? 0x400000u + s[i].off : 0, 8, be);
				hk_w(h + 24, s[i].off, 8, be);
				hk_w(h + 32, s[i].size, 8, be);
				hk_w(h + 40, s[i].link, 4, be);
				hk_w(h + 44, s[i].info, 4, be);
				hk_w(h + 48, 8, 8, be);
				hk_w(h + 56, s[i].ent, 8, be);
			} else {
				hk_w(h + 8, s[i].flags, 4, be);
				hk_w(h + 12, s[i].type == 1 && !rel ? 0x400000u + s[i].off : 0, 4, be);
				hk_w(h + 16, s[i].off, 4, be);
				hk_w(h + 20, s[i].size, 4, be);
				hk_w(h + 24, s[i].link, 4, be);
				hk_w(h + 28, s[i].info, 4, be);
				hk_w(h + 32, 4, 4, be);
				hk_w(h + 36, s[i].ent, 4, be);
			}
		}
	}
	(void)w;
}

/* ---- the PE builder -----------------------------------------------------------
 *
 * Three sections: .text (rva 0x1000), .idata (rva 0x2000: the import table and
 * the export table both live here) and .reloc (rva 0x3000). File alignment 0x200
 * so file offset = rva - 0x1000 * k + 0x200 * k... the offsets are published. */

#define HK_PE_MAX 0x1000u

struct hk_pe {
	uint8_t  b[HK_PE_MAX];
	uint32_t n;
	int      plus;
	uint32_t lfanew, opt, dirs, sec, text_off, idata_off, reloc_off;
	uint32_t imp_off, exp_off;      /* file offsets of the two directories */
};

static void hk_pe(struct hk_pe *p, int plus) HK_UNUSED;
static void hk_pe(struct hk_pe *p, int plus)
{
	uint8_t *b = p->b;
	uint32_t o, i, ps = plus ? 8u : 4u;
	uint32_t ilt, iat, hn;

	memset(p, 0, sizeof *p);
	p->plus = plus;
	p->lfanew = 0x80;
	p->opt = p->lfanew + 24u;
	p->dirs = p->opt + (plus ? 112u : 96u);
	p->sec = p->dirs + 16u * 8u;
	p->text_off = 0x200; p->idata_off = 0x400; p->reloc_off = 0x600;
	p->n = 0x800;
	p->imp_off = p->idata_off;
	p->exp_off = p->idata_off + 0x180;

	b[0] = 'M'; b[1] = 'Z';
	hk_w(b + 0x3c, p->lfanew, 4, 0);
	memcpy(b + p->lfanew, "PE\0\0", 4);
	hk_w(b + p->lfanew + 4, plus ? 0x8664 : 0x14c, 2, 0);
	hk_w(b + p->lfanew + 6, 3, 2, 0);
	hk_w(b + p->lfanew + 20, plus ? 240u : 224u, 2, 0);
	hk_w(b + p->lfanew + 22, 0x22, 2, 0);
	o = p->opt;
	hk_w(b + o, plus ? 0x20b : 0x10b, 2, 0);
	hk_w(b + o + 4, 0x200, 4, 0);            /* SizeOfCode */
	hk_w(b + o + 16, 0x1000, 4, 0);          /* entry rva */
	hk_w(b + o + 20, 0x1000, 4, 0);          /* BaseOfCode */
	if (plus) {
		hk_w(b + o + 24, 0x140000000ull, 8, 0);
		hk_w(b + o + 32, 0x1000, 4, 0);
		hk_w(b + o + 36, 0x200, 4, 0);
		hk_w(b + o + 56, 0x4000, 4, 0);
		hk_w(b + o + 60, 0x200, 4, 0);
		hk_w(b + o + 68, 3, 2, 0);
		hk_w(b + o + 108, 16, 4, 0);
	} else {
		hk_w(b + o + 28, 0x400000, 4, 0);
		hk_w(b + o + 32, 0x1000, 4, 0);
		hk_w(b + o + 36, 0x200, 4, 0);
		hk_w(b + o + 56, 0x4000, 4, 0);
		hk_w(b + o + 60, 0x200, 4, 0);
		hk_w(b + o + 68, 3, 2, 0);
		hk_w(b + o + 92, 16, 4, 0);
	}
	/* sections */
	{
		static const char nm[3][8] = { ".text", ".idata", ".reloc" };
		static const uint32_t rva[3] = { 0x1000, 0x2000, 0x3000 };
		static const uint32_t ch[3] = { 0x60000020u, 0xc0000040u, 0x42000040u };
		uint32_t raw[3];
		raw[0] = p->text_off; raw[1] = p->idata_off; raw[2] = p->reloc_off;
		for (i = 0; i < 3; i++) {
			uint8_t *s = b + p->sec + i * 40u;
			memcpy(s, nm[i], 8);
			hk_w(s + 8, 0x200, 4, 0);
			hk_w(s + 12, rva[i], 4, 0);
			hk_w(s + 16, 0x200, 4, 0);
			hk_w(s + 20, raw[i], 4, 0);
			hk_w(s + 36, ch[i], 4, 0);
		}
	}
	/* code at .text: a few instructions */
	{
		static const uint8_t code[] = { 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3 };
		memset(b + p->text_off, 0xcc, 0x200);
		memcpy(b + p->text_off, code, sizeof code);
	}
	/* imports: kernel32!ExitProcess, kernel32!#5 ; user32!MessageBoxA */
	{
		uint32_t d0 = p->idata_off;            /* descriptors: 3 (last all zero) */
		uint32_t rva0 = 0x2000;
		ilt = d0 + 0x60; iat = d0 + 0xa0; hn = d0 + 0x100;
		/* descriptor 0 */
		hk_w(b + d0 + 0, rva0 + (ilt - d0), 4, 0);
		hk_w(b + d0 + 12, rva0 + 0x140u - 0u, 4, 0);     /* name rva: set below */
		hk_w(b + d0 + 16, rva0 + (iat - d0), 4, 0);
		/* descriptor 1 */
		hk_w(b + d0 + 20, rva0 + (ilt - d0) + 3u * ps, 4, 0);
		hk_w(b + d0 + 36, rva0 + (iat - d0) + 3u * ps, 4, 0);
		/* thunks: ExitProcess (hint/name), ordinal 5, 0 ; MessageBoxA, 0 */
		if (plus) {
			hk_w(b + ilt, rva0 + (hn - d0), 8, 0);
			hk_w(b + ilt + 8, 0x8000000000000005ull, 8, 0);
			hk_w(b + ilt + 24, rva0 + (hn - d0) + 16u, 8, 0);
			memcpy(b + iat, b + ilt, 40);
		} else {
			hk_w(b + ilt, rva0 + (hn - d0), 4, 0);
			hk_w(b + ilt + 4, 0x80000005u, 4, 0);
			hk_w(b + ilt + 12, rva0 + (hn - d0) + 16u, 4, 0);
			memcpy(b + iat, b + ilt, 20);
		}
		memcpy(b + hn + 2, "ExitProcess", 12);
		memcpy(b + hn + 16 + 2, "MessageBoxA", 12);
		memcpy(b + d0 + 0x140, "kernel32.dll", 13);
		memcpy(b + d0 + 0x150, "user32.dll", 11);
		hk_w(b + d0 + 12, 0x2000u + 0x140u, 4, 0);
		hk_w(b + d0 + 20 + 12, 0x2000u + 0x150u, 4, 0);
	}
	/* exports at idata+0x180: 2 functions, 2 names */
	{
		uint32_t x = p->exp_off, xr = 0x2000u + 0x180u - 0u;
		hk_w(b + x + 12, xr + 0x60, 4, 0);        /* name rva */
		hk_w(b + x + 16, 1, 4, 0);                /* base */
		hk_w(b + x + 20, 2, 4, 0);                /* NumberOfFunctions */
		hk_w(b + x + 24, 2, 4, 0);                /* NumberOfNames */
		hk_w(b + x + 28, xr + 0x28, 4, 0);        /* AddressOfFunctions */
		hk_w(b + x + 32, xr + 0x30, 4, 0);        /* AddressOfNames */
		hk_w(b + x + 36, xr + 0x38, 4, 0);        /* AddressOfNameOrdinals */
		hk_w(b + x + 0x28, 0x1000, 4, 0);
		hk_w(b + x + 0x2c, 0x1004, 4, 0);
		hk_w(b + x + 0x30, xr + 0x68, 4, 0);
		hk_w(b + x + 0x34, xr + 0x70, 4, 0);
		hk_w(b + x + 0x38, 0, 2, 0);
		hk_w(b + x + 0x3a, 1, 2, 0);
		memcpy(b + x + 0x60, "hk.dll", 7);
		memcpy(b + x + 0x68, "Alpha", 6);
		memcpy(b + x + 0x70, "Beta", 5);
	}
	/* base relocations: one block of 4 entries for page 0x1000 */
	{
		uint32_t r = p->reloc_off;
		hk_w(b + r, 0x1000, 4, 0);
		hk_w(b + r + 4, 16, 4, 0);
		hk_w(b + r + 8, (plus ? 0xa000u : 0x3000u) | 0x010, 2, 0);
		hk_w(b + r + 10, (plus ? 0xa000u : 0x3000u) | 0x020, 2, 0);
		hk_w(b + r + 12, 0, 2, 0);
		hk_w(b + r + 14, 0, 2, 0);
	}
	/* a CLI header at .text+0x40 (rva 0x1040) over a metadata root at .text+0x100 */
	{
		uint8_t *c = b + p->text_off + 0x40, *m = b + p->text_off + 0x100;
		hk_w(c, 72, 4, 0);
		hk_w(c + 4, 2, 2, 0);
		hk_w(c + 8, 0x1100, 4, 0);
		hk_w(c + 12, 0x60, 4, 0);
		memcpy(m, "BSJB", 4);
		hk_w(m + 4, 1, 2, 0); hk_w(m + 6, 1, 2, 0);
		hk_w(m + 12, 12, 4, 0);
		memcpy(m + 16, "v4.0.30319", 11);
		hk_w(m + 30, 1, 2, 0);
		hk_w(m + 32, 0x40, 4, 0); hk_w(m + 36, 8, 4, 0); memcpy(m + 40, "#~", 3);
	}
	/* x64 exception table: two RUNTIME_FUNCTIONs at idata+0x300, unwind info after */
	{
		uint8_t *x = b + p->idata_off + 0x300;
		hk_w(x, 0x1000, 4, 0); hk_w(x + 4, 0x1004, 4, 0); hk_w(x + 8, 0x2340, 4, 0);
		hk_w(x + 12, 0x1004, 4, 0); hk_w(x + 16, 0x1008, 4, 0); hk_w(x + 20, 0x2340, 4, 0);
		b[p->idata_off + 0x340] = 1;
	}
	/* a resource tree at idata+0x380: root -> one subdirectory -> one data entry */
	{
		uint8_t *r = b + p->idata_off + 0x380;
		hk_w(r + 12, 0, 2, 0); hk_w(r + 14, 1, 2, 0);              /* root: 1 id entry */
		hk_w(r + 16, 3, 4, 0); hk_w(r + 20, 0x80000000u | 0x20u, 4, 0);
		hk_w(r + 0x20 + 14, 1, 2, 0);                              /* subdir: 1 id entry */
		hk_w(r + 0x30, 1, 4, 0); hk_w(r + 0x34, 0x40, 4, 0);       /* -> data entry */
		hk_w(r + 0x40, 0x2400, 4, 0); hk_w(r + 0x44, 8, 4, 0);     /* a data entry */
	}
	/* directories: export [0], import [1], basereloc [5] */
	hk_w(b + p->dirs + 0, 0x2180, 4, 0);
	hk_w(b + p->dirs + 4, 0x80, 4, 0);
	hk_w(b + p->dirs + 8, 0x2000, 4, 0);
	hk_w(b + p->dirs + 12, 0x60, 4, 0);
	hk_w(b + p->dirs + 40, 0x3000, 4, 0);
	hk_w(b + p->dirs + 44, 16, 4, 0);
	hk_w(b + p->dirs + 16, 0x2300, 4, 0);       /* exception [3] */
	hk_w(b + p->dirs + 20, 24, 4, 0);
	hk_w(b + p->dirs + 8 * 2, 0x2380, 4, 0);     /* resource [2] */
	hk_w(b + p->dirs + 8 * 2 + 4, 0x60, 4, 0);
	hk_w(b + p->dirs + 8 * 3, 0x2300, 4, 0);
	hk_w(b + p->dirs + 8 * 3 + 4, 24, 4, 0);
	hk_w(b + p->dirs + 8 * 4, 0x700, 4, 0);      /* security [4]: a FILE offset */
	hk_w(b + p->dirs + 8 * 4 + 4, 0x40, 4, 0);
	hk_w(b + p->dirs + 8 * 14, 0x1040, 4, 0);    /* COM descriptor [14] */
	hk_w(b + p->dirs + 8 * 14 + 4, 72, 4, 0);
}

/* ---- a growing set of lengths to try ----------------------------------------- */

/* The values a size/offset/count field is set to: both ends of every width, the
 * sign bit, the file's own length and its neighbours (the off-by-one cases). */
static unsigned hk_extremes(uint64_t *out, uint64_t n) HK_UNUSED;
static unsigned hk_extremes(uint64_t *out, uint64_t n)
{
	unsigned k = 0;
	out[k++] = 0;
	out[k++] = 1;
	out[k++] = 0x7fffffffu;
	out[k++] = 0x80000000u;
	out[k++] = 0xfffffffeu;
	out[k++] = 0xffffffffu;
	out[k++] = 0x7fffffffffffffffull;
	out[k++] = 0x8000000000000000ull;
	out[k++] = 0xffffffffffffffffull;
	out[k++] = 0xfffffffffffffffeull;
	out[k++] = n;
	out[k++] = n + 1u;
	out[k++] = n ? n - 1u : 0u;
	out[k++] = 0x10000u;
	out[k++] = 0xffffu;
	return k;
}
#define HK_NEXTREME 15u

#endif /* KGENOME_TESTS_HK_H */
