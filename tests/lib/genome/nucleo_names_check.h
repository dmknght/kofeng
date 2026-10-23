/*
 * nucleo_names_check.h - what every test of a script language's table of names asks, written once.
 *
 * The tables (libgenome/celllysis/nucleo_names_<language>.c) are data in one shape, so the questions a test puts to one are the
 * same questions: a row resolves to its capability, a name the table keeps out resolves to nothing, case is the table's
 * `fold` and not anything else, a name that belongs to another platform is not in this table, a lookup is the same every time and
 * cannot be fooled by a longer name that starts with a row, and every id the table hands out gives its name back. The test of a
 * language holds what is specific to it - which rows, which names are kept out and the count measured for each - and calls these.
 *
 * `census` is how the capability of EVERY row is pinned without writing the table a second time: the test says how many rows
 * each capability has, the ids of the table (kgenome_nucleo_name_of over all of them, which is the public way to walk it) are
 * counted, and a row moved to another capability, added or dropped changes a count.
 */

#ifndef NUCLEO_NAMES_CHECK_H
#define NUCLEO_NAMES_CHECK_H

#include <kgenome.h>
#include <celllysis/nucleo.h>
#include <celllysis/capability_ids.h>

#include <stdio.h>
#include <string.h>

static int nn_fails;

#define NN_CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		nn_fails++; \
	} \
} while (0)

struct nn_is  { const char *name; uint16_t cap; };
struct nn_out { const char *name; const char *why; };
struct nn_cen { uint16_t cap; unsigned n; };

static inline const char *nn_capname(uint16_t cap)
{
	return cap == KGENOME_NUCLEO_NONE ? "none" : kgenome_nucleo_cap_name(cap);
}

/* Rows of the table that must resolve, each to its capability, and give back their own name through the id. */
static inline void nn_check_is(unsigned target, const struct nn_is *r, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint16_t got = kgenome_nucleo_cap_of_name(target, r[i].name);
		uint16_t id = kgenome_nucleo_name_id(target, r[i].name);

		if (got != r[i].cap) {
			printf("  FAIL %s is %s, wanted %s\n", r[i].name, nn_capname(got), nn_capname(r[i].cap));
			nn_fails++;
		}
		if (!id || !kgenome_nucleo_name_of(id) || strcmp(kgenome_nucleo_name_of(id), r[i].name)) {
			printf("  FAIL %s does not give its name back through its id (%u)\n", r[i].name, (unsigned)id);
			nn_fails++;
		}
	}
}

/* Names the table keeps out on purpose: a row for one would put a node in every program there is. */
static inline void nn_check_out(unsigned target, const struct nn_out *o, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint16_t got = kgenome_nucleo_cap_of_name(target, o[i].name);

		if (got != KGENOME_NUCLEO_NONE || kgenome_nucleo_name_id(target, o[i].name) != 0) {
			printf("  FAIL %s has a row (%s) and the table keeps it out: %s\n", o[i].name, nn_capname(got), o[i].why);
			nn_fails++;
		}
	}
}

/* Names of another platform or language, which this table must not answer for - in the targets it is NOT meant for. */
static inline void nn_check_absent(unsigned target, const char *const *names, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (kgenome_nucleo_cap_of_name(target, names[i]) != KGENOME_NUCLEO_NONE) {
			printf("  FAIL %s is in the table of target %u and does not belong there\n", names[i], target);
			nn_fails++;
		}
}

/* The same name asked of every other target: a name in this table is not thereby in another language's. */
static inline void nn_check_only_here(unsigned target, const char *name)
{
	unsigned t;

	for (t = KGENOME_NUCLEO_T_ELF; t <= KGENOME_NUCLEO_T_CFML; t++)
		if (t != target && kgenome_nucleo_cap_of_name(t, name) != KGENOME_NUCLEO_NONE) {
			printf("  FAIL %s is in the table of target %u as well\n", name, t);
			nn_fails++;
		}
}

/*
 * CASE is the table's `fold`. `name` is a row spelled with letters of both cases; the table that folds answers to the other
 * spelling, the table that does not answers to nothing but the spelling it has.
 */
static inline void nn_check_fold(unsigned target, int fold, const char *name)
{
	char alt[128];
	size_t i, n = strlen(name);
	uint16_t cap = kgenome_nucleo_cap_of_name(target, name);

	NN_CK(cap != KGENOME_NUCLEO_NONE);
	NN_CK(n < sizeof alt);
	for (i = 0; i < n; i++)
		alt[i] = (char)(name[i] >= 'a' && name[i] <= 'z' ? name[i] - 32 : name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]);
	alt[n] = 0;
	if (fold) {
		NN_CK(kgenome_nucleo_cap_of_name(target, alt) == cap);
		NN_CK(kgenome_nucleo_name_id(target, alt) == kgenome_nucleo_name_id(target, name));
	} else {
		NN_CK(kgenome_nucleo_cap_of_name(target, alt) == KGENOME_NUCLEO_NONE);
	}
}

/*
 * A lookup is the same every time, and a name that is longer than a row is not that row: "evalx" is not "eval", the row followed by
 * a long tail is not the row, and a name too long for any buffer is refused and not cut down to one that fits.
 */
static inline void nn_check_stable(unsigned target, const char *name)
{
	static char big[5000];
	uint16_t cap = kgenome_nucleo_cap_of_name(target, name);
	uint16_t id = kgenome_nucleo_name_id(target, name);
	size_t n = strlen(name), i;

	for (i = 0; i < 1000; i++) {
		if (kgenome_nucleo_cap_of_name(target, name) != cap || kgenome_nucleo_name_id(target, name) != id) {
			printf("  FAIL %s changed on repetition %zu\n", name, i);
			nn_fails++;
			break;
		}
	}
	memcpy(big, name, n);
	memset(big + n, 'x', sizeof big - 1u - n);
	big[sizeof big - 1u] = 0;
	NN_CK(kgenome_nucleo_cap_of_name(target, big) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_name_id(target, big) == 0);
	big[n + 3u] = 0;                       /* the row and three more bytes */
	NN_CK(kgenome_nucleo_cap_of_name(target, big) == KGENOME_NUCLEO_NONE);
	memset(big, 'a', 4999);
	big[4999] = 0;
	NN_CK(kgenome_nucleo_cap_of_name(target, big) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(target, "") == KGENOME_NUCLEO_NONE && kgenome_nucleo_cap_of_name(target, NULL) == KGENOME_NUCLEO_NONE);
}

/*
 * Every id the table hands out. The ids of all the tables are one run, so the rows of this one are the ids that give THIS target
 * their own name back; each has a capability, and the count of rows per capability is `cen` - which pins the capability of every
 * row without writing the table out again. Returns the number of rows.
 */
static inline unsigned nn_census(unsigned target, const struct nn_cen *cen, size_t ncen)
{
	unsigned id, rows = 0, first = 0, last = 0, seen = 0;
	unsigned count[64] = { 0 };
	size_t i;

	NN_CK(ncen <= 64);
	for (id = 1; id < 0x10000u; id++) {
		const char *nm = kgenome_nucleo_name_of((uint16_t)id);
		uint16_t cap;

		if (!nm)
			break;
		if (kgenome_nucleo_name_id(target, nm) != id)
			continue;
		cap = kgenome_nucleo_cap_of_name(target, nm);
		if (cap == KGENOME_NUCLEO_NONE) {
			printf("  FAIL id %u (%s) is a row of the table and has no capability\n", id, nm);
			nn_fails++;
		}
		for (i = 0; i < ncen; i++)
			if (cen[i].cap == cap)
				count[i]++;
		if (!first)
			first = id;
		last = id;
		rows++;
	}
	/* the rows of one table are consecutive ids: the tables are laid end to end */
	NN_CK(rows && last - first + 1u == rows);
	for (i = 0; i < ncen; i++) {
		if (count[i] != cen[i].n) {
			printf("  FAIL %u rows are %s, the census says %u\n", count[i], nn_capname(cen[i].cap), cen[i].n);
			nn_fails++;
		}
		seen += count[i];
	}
	if (seen != rows) {
		printf("  FAIL the census accounts for %u of %u rows\n", seen, rows);
		nn_fails++;
	}
	return rows;
}

#define NN_DONE(label) do { \
	if (nn_fails) { \
		printf("%s: %d failed\n", label, nn_fails); \
		return 1; \
	} \
	printf("%s - ok\n", label); \
	return 0; \
} while (0)

#endif
