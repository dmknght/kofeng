/*
 * hostile_mem.c - the memory comparison, given a file that lies about itself.
 *
 * WHY THIS IS A REAL THREAT AND NOT ONLY A FUZZ HARNESS.
 *
 * kofw_diff_module compares what a module holds in MEMORY against the FILE it
 * was mapped from, and decides where they differ. The memory side comes from a
 * process this tool opened. The file side is a path off the disk - and that
 * file is exactly as trustworthy as whoever can write it.
 *
 * That is not hypothetical here. KOFW_MDF_NO_FILE exists in wproc.h because a
 * dropper DELETES its own file after the load; a dropper that replaces it
 * instead, with a PE whose header lies, is the same move with a better payoff:
 * a section table claiming impossible sizes, a relocation directory pointing
 * outside itself, blocks that do not advance. If any of that turns into a read
 * past a buffer, an allocation from a field, or a loop that does not end, then
 * a file somebody controls has reached the scanner's own address space.
 *
 * The mapping stays REAL throughout - this opens its own process and uses a
 * genuinely loaded module. Only the file is mutated, which is the half an
 * attacker actually has.
 *
 *
 * WHAT IS ASSERTED, AND WHY EACH ONE IS SEPARATE
 *
 *   TIME       Every case is timed and a slow one fails. A relocation walk
 *              whose exit depends on a field, or a section loop that does not
 *              advance, returns perfectly correct results - eventually - and no
 *              other check here would notice.
 *
 *   CONTAINMENT Every run handed to the callback must lie inside the module it
 *              claims to be about, must be non-empty, and must not be longer
 *              than the range it came from. A run outside those is arithmetic
 *              that disagreed with itself, whatever it computed.
 *
 *   ACCOUNTING The stats must be consistent with what the callback saw: as many
 *              runs as calls, bytes summing to the same total, and never more
 *              runs than the cap allowed.
 *
 *   MEMORY     Out of bounds reads and writes, use after free and integer
 *              overflow are not hand-checked here. They are found by building
 *              this same binary under AddressSanitizer and
 *              UndefinedBehaviorSanitizer, where each one aborts - the same
 *              division hostile_fields.c makes and for the same reason.
 *
 *
 * WINDOWS ONLY, because the thing under test is. See UNIT_SKIP_POSIX.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <windows.h>

#include "wproc.h"
#include "wdiff.h"

static int fails;

static void ck(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL: %s\n", what);
		fails++;
	}
}

/*
 * A case that takes longer than this has found a loop whose end depends on a
 * field. Generous on purpose: the comparison reads pages out of a process and
 * off a disk, and a slow machine must not fail a correctness test. What it
 * catches is the runaway, which is orders out rather than a factor.
 */
#define SLOW_MS 2000.0

static double now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

/* Deterministic, so a failure can be run again. */
static uint64_t rng_s = 0x2026091301ull;

static uint32_t rnd(uint32_t n)
{
	rng_s ^= rng_s << 13;
	rng_s ^= rng_s >> 7;
	rng_s ^= rng_s << 17;
	return n ? (uint32_t)(rng_s % n) : 0;
}

/* ------------------------------------------------- what the callback sees */

struct seen {
	uint64_t base, size;    /* the module the runs must lie inside */
	uint64_t range_bytes;   /* the total the ranges covered */
	uint32_t runs;
	uint64_t bytes;
	int      bad_addr, bad_len, bad_null;
};

static int on_run(const struct kofw_diff_run *r, const uint8_t *mem,
		  const uint8_t *file, void *user)
{
	struct seen *s = user;

	if (!r || !mem || !file) {
		s->bad_null = 1;
		return 1;
	}
	if (!r->len || r->len > s->range_bytes)
		s->bad_len = 1;
	if (r->addr < s->base || r->addr + r->len > s->base + s->size)
		s->bad_addr = 1;
	/* Touch both copies, so a pointer that is wrong rather than merely
	 * odd is a read the sanitiser can see. */
	if (mem[0] == file[0] && r->len > 1u &&
	    mem[r->len - 1u] == file[r->len - 1u])
		s->runs += 0;
	s->runs++;
	s->bytes += r->len;
	return 0;
}

/* ------------------------------------------------------ the file, mutated */

static unsigned char *g_good;      /* a pristine copy of the module's file */
static uint64_t       g_good_len;
static char           g_tmp[1024];

static int write_tmp(const unsigned char *b, uint64_t n)
{
	FILE *f = fopen(g_tmp, "wb");
	int ok;

	if (!f)
		return 0;
	ok = n ? (fwrite(b, 1, (size_t)n, f) == (size_t)n) : 1;
	fclose(f);
	return ok;
}

/*
 * THE DANGEROUS BYTES, named rather than found at random.
 *
 * A whole-file random mutation almost never lands on a length or an offset -
 * it lands in code, and the comparison reports a difference and moves on,
 * which proves nothing. These are the fields the code does ARITHMETIC on, and
 * the values are the ones that historically break it: zero, one, the maxima,
 * and the file's own length either side.
 */
static const uint32_t BREAK_U32[] = {
	0u, 1u, 2u, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu,
	0x1000u, 0x10000u
};

static void patch_u32(unsigned char *b, uint64_t n, uint64_t at, uint32_t v)
{
	if (at + 4u <= n)
		memcpy(b + at, &v, 4);
}

static void patch_u16(unsigned char *b, uint64_t n, uint64_t at, uint16_t v)
{
	if (at + 2u <= n)
		memcpy(b + at, &v, 2);
}

/*
 * One mutated copy of the file: the PE header's own arithmetic fields, the
 * section table, and the two directories this code reads.
 */
static void mutate(unsigned char *b, uint64_t n, uint32_t round)
{
	uint32_t lfanew = 0, opt, nsec = 0, dirbase, i;
	uint16_t magic = 0, optsz = 0, nsec16 = 0;
	uint32_t v = BREAK_U32[rnd((uint32_t)(sizeof BREAK_U32 /
					      sizeof BREAK_U32[0]))];

	if (n < 0x400)
		return;

	switch (round % 6u) {
	case 0:
		/* e_lfanew: where the PE header is claimed to be. */
		patch_u32(b, n, 0x3c, v);
		return;
	case 1:
		/* The DOS magic, so the parse must refuse rather than walk. */
		patch_u16(b, n, 0, (uint16_t)(v & 0xffffu));
		return;
	default:
		break;
	}

	memcpy(&lfanew, b + 0x3c, 4);
	if (lfanew < 0x40u || lfanew + 0x108u > n)
		return;
	opt = lfanew + 4u + 20u;
	memcpy(&nsec16, b + lfanew + 4u + 2u, 2);
	memcpy(&optsz, b + lfanew + 4u + 16u, 2);
	memcpy(&magic, b + opt, 2);
	nsec = nsec16;

	switch (round % 6u) {
	case 2:
		/* NumberOfSections and SizeOfOptionalHeader - both bound the
		 * section table's position and length. */
		patch_u16(b, n, lfanew + 4u + 2u, (uint16_t)(v & 0xffffu));
		patch_u16(b, n, lfanew + 4u + 16u, (uint16_t)(v & 0xffffu));
		return;
	case 3: {
		/* One section's four arithmetic fields. */
		uint64_t sec = (uint64_t)opt + optsz;
		uint64_t at;

		if (!nsec || sec + 40u > n)
			return;
		at = sec + (uint64_t)(rnd(nsec) % (nsec ? nsec : 1u)) * 40u;
		if (at + 40u > n)
			return;
		patch_u32(b, n, at + 8u,  v);   /* VirtualSize    */
		patch_u32(b, n, at + 12u, v);   /* VirtualAddress */
		patch_u32(b, n, at + 16u, v);   /* SizeOfRawData  */
		patch_u32(b, n, at + 20u, v);   /* PointerToRawData */
		return;
	}
	case 4: {
		/* The two directories this code reads: IAT and BASERELOC. */
		uint32_t which = rnd(2) ? 5u : 12u;   /* reloc : IAT */

		dirbase = opt + (magic == 0x20b ? 112u : 96u);
		patch_u32(b, n, (uint64_t)dirbase + which * 8u,      v);
		patch_u32(b, n, (uint64_t)dirbase + which * 8u + 4u, v);
		return;
	}
	default: {
		/*
		 * Inside the relocation directory: a block whose size does not
		 * advance, or claims to reach past the table. This is the walk
		 * with a loop in it, so it is the one worth aiming at.
		 */
		uint32_t rva = 0, len = 0;
		uint64_t off;

		dirbase = opt + (magic == 0x20b ? 112u : 96u);
		if ((uint64_t)dirbase + 5u * 8u + 8u > n)
			return;
		memcpy(&rva, b + dirbase + 5u * 8u, 4);
		memcpy(&len, b + dirbase + 5u * 8u + 4u, 4);
		if (!rva || !len)
			return;
		/* The directory's file offset is not resolved here - the RVA is
		 * used directly, which for most system DLLs is close enough to
		 * land inside the file and is in any case a mutation. */
		off = rva;
		if (off + 8u > n)
			return;
		patch_u32(b, n, off,      v);   /* the page this block covers */
		patch_u32(b, n, off + 4u, v);   /* and its size - 0 never ends */
		for (i = 0; i < 8u && off + 8u + i * 2u + 2u <= n; i++)
			patch_u16(b, n, off + 8u + i * 2u,
				  (uint16_t)(v >> (i & 15u)));
		return;
	}
	}
}

/* ------------------------------------------------------------- the driver */

int main(void);

int main(void)
{
	struct kofw_pmem *m;
	struct kofw_module md, pick;
	struct kofw_diff_option dopt;
	struct kofw_diff_stat st;
	struct kofw_diff_range rg;
	struct seen s;
	struct kofw_diff_cache *cache;
	char pickpath[512];
	FILE *f;
	int err = 0, have = 0;
	uint32_t round, rounds = 900, slow = 0, ran = 0;
	/*
	 * HOW MUCH OF THE CODE THE MUTATIONS ACTUALLY REACHED.
	 *
	 * A fuzz test whose every input is refused at the front door passes
	 * without executing the thing it is about, and looks identical to one
	 * that exercised everything. So the reach is counted and asserted: a
	 * good share of rounds must get PAST the parse and produce a
	 * comparison, and some must reach the relocation walk.
	 */
	uint32_t accepted = 0, saw_reloc = 0;
	uint64_t total_runs = 0;
	double worst = 0.0;

	/*
	 * ITS OWN PROCESS, because the memory half has to be real and because a
	 * test may not go rummaging in somebody else's.
	 */
	m = kofw_pmem_open((uint32_t)GetCurrentProcessId(), 0, NULL, &err);
	if (!m) {
		/* The number, not kofw_err_name: that lives in the ETW
		 * collector, and linking a trace session into a test about
		 * memory would pull in a dependency the test does not have. */
		printf("hostile mem: cannot open self (err %d) - nothing "
		       "tested\n", err);
		return 1;
	}

	/*
	 * A module with a file and enough of it to have a section table worth
	 * breaking. The first that qualifies; which one does not matter,
	 * because what is under test is the arithmetic and not the DLL.
	 */
	memset(&pick, 0, sizeof pick);
	while (kofw_pmem_next_module(m, &md)) {
		if (!md.path[0] || md.size < 0x20000u)
			continue;
		if (md.flags & (KOFW_MDF_NO_FILE | KOFW_MDF_UNNAMED))
			continue;
		pick = md;
		snprintf(pickpath, sizeof pickpath, "%s", md.path);
		pick.path = pickpath;
		have = 1;
		break;
	}
	ck(have, "a loaded module with a file behind it");
	if (!have) {
		kofw_pmem_close(m);
		return 1;
	}

	f = fopen(pickpath, "rb");
	if (f) {
		long n;

		fseek(f, 0, SEEK_END);
		n = ftell(f);
		rewind(f);
		if (n > 0 && n < (64L << 20)) {
			g_good = malloc((size_t)n);
			if (g_good &&
			    fread(g_good, 1, (size_t)n, f) == (size_t)n)
				g_good_len = (uint64_t)n;
			else {
				free(g_good);
				g_good = NULL;
			}
		}
		fclose(f);
	}
	ck(g_good != NULL, "the module's file could be read");
	if (!g_good) {
		kofw_pmem_close(m);
		return 1;
	}

	{
		const char *tmp = getenv("TEMP");

		snprintf(g_tmp, sizeof g_tmp, "%s\\kof_hostile_mem.tmp",
			 tmp ? tmp : ".");
	}

	cache = kofw_diff_cache_open(4);
	memset(&dopt, 0, sizeof dopt);
	dopt.max_runs = 64;

	for (round = 0; round < rounds; round++) {
		unsigned char *bad;
		double t0, dt;
		uint64_t len = g_good_len;

		/*
		 * Three shapes of file besides the mutated one, because a
		 * parse that refuses is as much a path as a parse that walks:
		 * empty, a stub too short to hold a header, and a truncation
		 * in the middle of the section table.
		 */
		if (round % 97u == 1u)
			len = 0;
		else if (round % 97u == 2u)
			len = 64;
		else if (round % 97u == 3u)
			len = g_good_len / 2u;

		bad = malloc(len ? (size_t)len : 1u);
		if (!bad)
			break;
		if (len)
			memcpy(bad, g_good, (size_t)len);
		mutate(bad, len, round);
		if (!write_tmp(bad, len)) {
			free(bad);
			continue;
		}
		free(bad);

		/*
		 * The range is real memory of the real module, and every so
		 * often a hostile one - below the module, longer than it, or
		 * empty - because the caller is code too.
		 */
		memset(&rg, 0, sizeof rg);
		switch (round % 23u) {
		case 5:  rg.addr = pick.base - 0x1000; rg.len = 0x4000; break;
		case 11: rg.addr = pick.base; rg.len = 0xffffffffull;   break;
		case 17: rg.addr = pick.base + 0x1000; rg.len = 0;      break;
		default: rg.addr = pick.base + 0x1000;
			 rg.len = pick.size > 0x9000u ? 0x8000u
						      : pick.size / 2u;
			 break;
		}

		memset(&s, 0, sizeof s);
		s.base = pick.base;
		s.size = pick.size;
		s.range_bytes = rg.len ? rg.len : 1u;

		memset(&st, 0, sizeof st);
		pick.path = g_tmp;

		t0 = now_ms();
		if (kofw_diff_module(m, &pick, &rg, 1, cache, &dopt,
				     on_run, &s, &st))
			accepted++;
		dt = now_ms() - t0;
		ran++;
		total_runs += s.runs;
		if (st.reloc_explained)
			saw_reloc++;
		if (dt > worst)
			worst = dt;
		if (dt > SLOW_MS) {
			slow++;
			printf("  SLOW round %u: %.0f ms\n", round, dt);
		}

		ck(!s.bad_null, "a run came with a null buffer");
		ck(!s.bad_len, "a run was empty or longer than its range");
		ck(!s.bad_addr, "a run fell outside the module");
		ck(st.runs >= s.runs, "the stat counted fewer runs than the "
				      "callback was handed");
		ck(s.runs <= dopt.max_runs + 1u,
		   "more runs were handed over than the cap allows");
		ck(st.bytes >= s.bytes, "the stat's byte total is short");
		if (s.bad_null || s.bad_len || s.bad_addr)
			break;          /* one report is enough */

		/*
		 * The cache is dropped periodically so cfile_fill runs against
		 * a mutated file rather than only the first one being cached.
		 */
		if (round % 7u == 0u) {
			kofw_diff_cache_close(cache);
			cache = kofw_diff_cache_open(4);
		}
	}

	ck(slow == 0, "every case finished promptly");
	ck(accepted > rounds / 4u,
	   "most mutated files were refused before anything was compared");
	ck(total_runs > 0, "no mutation ever produced a differing run");
	ck(saw_reloc > 0, "the relocation walk was never reached");

	/* ------------------------------------------------ the pure surface */

	/*
	 * kofw_region_describe writes into a caller's buffer from values a
	 * caller supplies, so it is given impossible ones and no room.
	 */
	{
		struct kofw_region r;
		char buf[8];
		size_t k;

		memset(&r, 0, sizeof r);
		r.base = 0xffffffffffffffffull;
		r.size = 0xffffffffffffffffull;
		r.kind = 0xff;
		r.use  = 0xff;
		r.flags = 0xffffffffu;
		r.path = NULL;

		ck(kofw_region_describe(NULL, buf, sizeof buf) == 0,
		   "describe refuses a null region");
		ck(kofw_region_describe(&r, NULL, 16) == 0,
		   "describe refuses a null buffer");
		ck(kofw_region_describe(&r, buf, 0) == 0,
		   "describe refuses a zero cap");
		for (k = 1; k <= sizeof buf; k++) {
			size_t n = kofw_region_describe(&r, buf, k);

			ck(n < k, "describe wrote past the cap it was given");
			ck(buf[k - 1u] == '\0' || n < k - 1u,
			   "describe left the buffer unterminated");
		}
		/* Names must never be NULL, whatever the value. */
		ck(kofw_rgn_kind_name(0xff) != NULL, "kind name is never null");
		ck(kofw_rgn_use_name(0xff) != NULL, "use name is never null");
		ck(kofw_integrity_name(0xff) != NULL,
		   "integrity name is never null");
	}

	/* And the entry points, given nothing. */
	ck(kofw_diff_module(NULL, &pick, &rg, 1, cache, &dopt, on_run, &s,
			    &st) == 0, "diff refuses a null process");
	ck(kofw_diff_module(m, &pick, NULL, 0, cache, &dopt, on_run, &s,
			    &st) == 0, "diff refuses no ranges");
	ck(kofw_diff_module(m, &pick, &rg, 1, cache, &dopt, NULL, &s,
			    &st) == 0, "diff refuses a null callback");
	ck(kofw_pmem_read(m, 0, NULL, 16) == 0, "read refuses a null buffer");
	ck(kofw_pmem_read(NULL, pick.base, &err, 4) == 0,
	   "read refuses a null process");

	kofw_diff_cache_close(cache);
	kofw_pmem_close(m);
	free(g_good);
	remove(g_tmp);

	printf("  %u round(s), %u compared, %llu run(s) seen, %u reached the "
	       "relocation walk;\n  worst case %.0f ms\n", ran, accepted,
	       (unsigned long long)total_runs, saw_reloc, worst);
	printf("hostile mem: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
