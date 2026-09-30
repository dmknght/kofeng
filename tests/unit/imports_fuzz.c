/*
 * imports_fuzz - the import directory the engine writes from a module's
 * declarations, against declarations that make no sense.
 *
 * WHY IT IS FUZZED AT ALL. `kof_pe_write_imports` is fed by a module reading a
 * PACKER'S OWN TABLE - MPRESS's hint list - so every library name, every
 * function name, every ordinal and every thunk address in it came out of a file
 * somebody else wrote. The module bounds what it reads; this bounds what is
 * done with it, and the two are different jobs.
 *
 * THE ONE THAT MATTERS IS THE PAIR AGREEING. Sizing and writing are two walks
 * of the same declarations, and the caller reserves room from the first and
 * fills it with the second - so a disagreement of one byte is a write past a
 * section boundary into whatever the child had there. They are written as one
 * function with the stores switched off for exactly that reason, and this is
 * what holds them to it.
 *
 * WHAT IS ASSERTED:
 *
 *   - size and write return the same number. The bound above.
 *   - nothing outside [base, base + size) changes, except the declared thunks.
 *     The image is filled with a marker and swept afterwards; a thunk is four
 *     bytes and is allowed to move, everything else is not.
 *   - the table PARSES BACK to the declarations it was written from. Descriptor
 *     count, the name of each, and for every entry either the ordinal or the
 *     function name that was declared, in order. This is the test that would
 *     catch a table which is internally consistent and describes something
 *     else - the failure a byte sweep cannot see.
 *   - every declared thunk holds its own lookup entry, which is what a loader
 *     writes there before binding and what the engine's IAT filler reads.
 *   - a refusal writes nothing. A declaration that cannot be turned into a
 *     table must leave the image alone, because the caller's answer to a
 *     refusal is to hand the child over WITHOUT imports rather than to stop.
 *
 * Names are drawn from a small pool with deliberate collisions - the same
 * library over and over, which is what a real hint list looks like, and the
 * same function name under two libraries - because the descriptor boundary is
 * decided by comparing a name with the one before it and that is where an
 * off-by-one lives.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/extractors/unpack/pe_rebuild.h"

#define IMG_N    (1u << 20)
#define MAX_IMP  256u
#define POOL_N   8192u
#define MARKER   0x5A

static uint64_t rng_state = 1;
static uint64_t failures, rounds_done, refused, wrote;
/* PE32 and PE32+ alike: a lookup entry is pointer sized, and writing four
 * bytes where eight are read is a table no parser can walk. */
static int is64;
static uint32_t step;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static void fail(uint64_t r, const char *why)
{
	if (failures < 20)
		fprintf(stderr, "round %llu: %s\n", (unsigned long long)r, why);
	failures++;
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* The pool, built per round: a handful of names, some of them repeated. */
static char pool[POOL_N];
static uint32_t pool_n;
static uint32_t name_off[32];
static uint32_t n_names;

static void pool_build(void)
{
	static const char *base[] = {
		"kernel32.dll", "user32.dll", "a", "kernel32.dll",
		"CreateFileW", "CreateFileW", "x",
		"a_very_long_name_that_goes_on_and_on_and_on_for_a_while"
	};
	uint32_t i;

	pool_n = 0;
	n_names = 0;
	for (i = 0; i < sizeof base / sizeof base[0] && n_names < 32; i++) {
		uint32_t len = (uint32_t)strlen(base[i]);

		if (pool_n + len + 1u > POOL_N)
			break;
		name_off[n_names++] = pool_n;
		memcpy(pool + pool_n, base[i], len + 1u);
		pool_n += len + 1u;
	}
}

/*
 * A name offset, and one in sixty-four is NOT one.
 *
 * Two offsets a module cannot produce: into the middle of a string, and past
 * the pool entirely. A writer that trusts the offset it is handed walks off the
 * pool on both, so they have to turn up - but RARELY. Drawn at the same rate as
 * the good ones they were, with up to 256 entries a round, nineteen rounds in
 * twenty contained at least one and were refused before anything was written:
 * 3803 of 4000, and the table itself was barely exercised. A fuzzer whose
 * inputs are almost all rejected at the door is testing the door.
 */
static uint32_t pick_name(void)
{
	if ((rnd() % 64u) == 0)
		return (rnd() % 2u) ? 1u : POOL_N + 100u;
	return name_off[rnd() % n_names];
}

static uint8_t img[IMG_N], copy[IMG_N];
static struct kof_imp_decl imp[MAX_IMP];

/*
 * Walk the written table and check it says what was declared.
 *
 * Returns 0 and complains on the first disagreement. `n` is how many
 * declarations went in; every one of them has to come back, in order.
 */
static uint64_t rdptr(const uint8_t *p)
{
	uint64_t v = rd32(p);

	if (is64)
		v |= (uint64_t)rd32(p + 4) << 32;
	return v;
}

static int verify(uint64_t r, uint64_t base, uint64_t size, uint32_t n)
{
	uint32_t i = 0, d = 0;
	const char *prev = NULL;

	for (;;) {
		uint64_t desc = base + (uint64_t)d * 20u;
		uint32_t olt, name, ft, k;
		const char *dll;

		if (desc + 20u > base + size) {
			fail(r, "descriptor array runs past the table");
			return 0;
		}
		olt  = rd32(img + desc);
		name = rd32(img + desc + 12u);
		ft   = rd32(img + desc + 16u);
		if (!name)
			break;                          /* the terminator */
		if (name >= IMG_N) {
			fail(r, "a descriptor names a string outside the image");
			return 0;
		}
		dll = (const char *)img + name;
		if (i >= n) {
			fail(r, "more descriptors than declarations");
			return 0;
		}
		if (strcmp(dll, pool + imp[i].dll_off) != 0) {
			fail(r, "a descriptor names the wrong library");
			return 0;
		}
		if (prev && strcmp(dll, prev) == 0) {
			fail(r, "two descriptors in a row for one library");
			return 0;
		}
		if (ft != (uint32_t)imp[i].iat_rva) {
			fail(r, "FirstThunk is not the run's first thunk");
			return 0;
		}

		for (k = 0; ; k++) {
			uint64_t at = (uint64_t)olt + (uint64_t)k * step;
			uint64_t ent;

			if (at + step > IMG_N) {
				fail(r, "a lookup entry lies outside the image");
				return 0;
			}
			ent = rdptr(img + at);
			if (!ent)
				break;                  /* end of this run */
			if (i >= n) {
				fail(r, "more entries than declarations");
				return 0;
			}
			if (strcmp((const char *)img + name,
				   pool + imp[i].dll_off) != 0) {
				fail(r, "an entry fell into the wrong run");
				return 0;
			}
			if (imp[i].ordinal) {
				if (ent != ((is64 ? 0x8000000000000000ull
						   : 0x80000000ull) |
					    imp[i].ordinal)) {
					fail(r, "an ordinal came back wrong");
					return 0;
				}
			} else {
				if (ent & (is64 ? 0x8000000000000000ull
						: 0x80000000ull)) {
					fail(r, "a by-name import came back "
					        "as an ordinal");
					return 0;
				}
				if (ent + 2u >= IMG_N ||
				    strcmp((const char *)img + (size_t)ent + 2u,
					   pool + imp[i].fn_off) != 0) {
					fail(r, "a function name came back "
					        "wrong");
					return 0;
				}
			}
			/*
			 * And the thunk, which is what a loader reads.
			 *
			 * imp[i].iat_rva IS this entry's own slot - the caller
			 * declares one per entry - and FirstThunk is the first
			 * of the run, so the two have to agree at offset k.
			 */
			if (imp[i].iat_rva) {
				if (imp[i].iat_rva !=
				    (uint64_t)ft + (uint64_t)k * step) {
					fail(r, "a slot is not FirstThunk plus "
					        "its index");
					return 0;
				}
				/*
				 * THE LAST DECLARATION OF A SLOT WINS, which
				 * is what a loader does with an import table
				 * that binds one thunk twice. Two runs whose
				 * slot ranges overlap is not something a
				 * container this module reads produces, but a
				 * hostile one could say it - and the writer
				 * stores in declaration order, so the answer
				 * is defined rather than arbitrary. Only the
				 * entry nothing later overwrites is checked.
				 */
				uint32_t q;
				int overwritten = 0;

				/*
				 * OVERLAPPING, not merely equal. A slot is
				 * four bytes and the addresses a packed file
				 * states need not be aligned, so a later run
				 * starting one byte into this one rewrites
				 * part of it. Comparing addresses for equality
				 * missed exactly that: one round in a thousand.
				 */
				for (q = i + 1u; q < n; q++)
					if (imp[q].iat_rva &&
					    imp[q].iat_rva < imp[i].iat_rva + step &&
					    imp[i].iat_rva < imp[q].iat_rva + step) {
						overwritten = 1;
						break;
					}
				if (!overwritten &&
				    imp[i].iat_rva + step <= IMG_N &&
				    rdptr(img + imp[i].iat_rva) != ent) {
					fail(r, "a thunk was not filled with "
					        "its lookup entry");
					return 0;
				}
			}
			i++;
		}
		prev = dll;
		d++;
		if (d > MAX_IMP) {
			fail(r, "the descriptor array does not terminate");
			return 0;
		}
	}
	if (i != n) {
		fail(r, "the table describes fewer entries than were declared");
		return 0;
	}
	return 1;
}

static void one(uint64_t r)
{
	uint32_t n, i;
	uint64_t base, size, got, k;
	int valid = 1;

	pool_build();
	is64 = (rnd() % 2u) != 0;
	step = is64 ? 8u : 4u;

	n = 1u + (uint32_t)(rnd() % MAX_IMP);
	base = (rnd() % (IMG_N / 2u)) & ~(uint64_t)3u;

	for (i = 0; i < n; i++) {
		/*
		 * Libraries in runs, because that is the shape a hint list has
		 * and the shape the descriptor boundary is decided from. One
		 * declaration in eight starts a new run at random, so runs of
		 * every length turn up including runs of one.
		 */
		static uint32_t cur;

		if (!i || (rnd() % 8u) == 0)
			cur = pick_name();
		imp[i].dll_off = cur;
		imp[i].ordinal = (rnd() % 3u) == 0
				 ? (uint16_t)(1u + (rnd() % 0xffffu)) : 0u;
		imp[i].fn_off = imp[i].ordinal ? 0u : pick_name();
		imp[i]._pad = 0;
		/* A thunk anywhere, including past the image and unaligned:
		 * the address came out of a packed file. */
		imp[i].iat_rva = (rnd() % 4u) == 0 ? 0u
						   : rnd() % (IMG_N + 4096u);

		if (imp[i].dll_off >= pool_n || !pool[imp[i].dll_off])
			valid = 0;
		if (!imp[i].ordinal &&
		    (imp[i].fn_off >= pool_n || !pool[imp[i].fn_off]))
			valid = 0;
	}
	/*
	 * FirstThunk is the FIRST thunk of a run, and the verifier holds the
	 * writer to that - so the declarations have to be consistent with it:
	 * within a run the slots are consecutive. A real module declares them
	 * that way because the packer's own table is laid out that way.
	 */
	{
		uint64_t run_at = imp[0].iat_rva;
		uint32_t run_k = 0;

		for (i = 0; i < n; i++) {
			/*
			 * BY CONTENT, NOT BY OFFSET, because that is what the
			 * writer does - a run ends where the library NAME
			 * changes. The pool holds "kernel32.dll" at two
			 * offsets on purpose, and grouping by offset here
			 * split a run the writer kept whole: FirstThunk then
			 * belonged to a descriptor that had never started.
			 * Only valid offsets are compared; an invalid one is
			 * refused before any of this matters.
			 */
			int same = 0;

			if (i && imp[i].dll_off < pool_n &&
			    imp[i - 1u].dll_off < pool_n)
				same = strcmp(pool + imp[i].dll_off,
					      pool + imp[i - 1u].dll_off) == 0;
			if (i && !same) {
				run_at = imp[i].iat_rva;
				run_k = 0;
			}
			imp[i].iat_rva = run_at ? run_at + run_k * step : 0u;
			run_k++;
		}
	}

	memset(img, MARKER, IMG_N);
	memcpy(copy, img, IMG_N);

	size = kof_pe_imports_size(imp, n, pool, pool_n, is64);
	got = kof_pe_write_imports(img, IMG_N, base, imp, n, pool, pool_n,
				   is64);
	rounds_done++;

	if (size && got && size != got) {
		fail(r, "sizing and writing disagree");
		return;
	}
	if (!got) {
		refused++;
		/* A refusal must leave the image exactly as it was. */
		if (memcmp(img, copy, IMG_N) != 0)
			fail(r, "a refused write changed the image");
		return;
	}
	if (!valid) {
		fail(r, "a declaration naming nothing was accepted");
		return;
	}
	wrote++;
	if (base + got > IMG_N) {
		fail(r, "the table was written past the image");
		return;
	}

	/* Nothing outside the table changed, except a declared thunk. */
	for (k = 0; k < IMG_N; k++) {
		if (k >= base && k < base + got)
			continue;
		if (img[k] == MARKER)
			continue;
		{
			int is_slot = 0;

			for (i = 0; i < n; i++)
				if (imp[i].iat_rva && k >= imp[i].iat_rva &&
				    k < imp[i].iat_rva + step) {
					is_slot = 1;
					break;
				}
			if (!is_slot) {
				fail(r, "a byte outside the table and outside "
				        "every declared thunk was changed");
				return;
			}
		}
	}

	verify(r, base, got, n);
}

int main(int argc, char **argv)
{
	uint64_t rounds = 4000, r;

	if (argc > 1)
		rng_state = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);
	if (!rng_state)
		rng_state = 1;

	for (r = 0; r < rounds; r++)
		one(r);

	printf("imports fuzz: %llu round(s), %llu written, %llu refused\n",
	       (unsigned long long)rounds_done, (unsigned long long)wrote,
	       (unsigned long long)refused);
	if (failures) {
		printf("FAILED: %llu\n", (unsigned long long)failures);
		return 1;
	}
	return 0;
}
