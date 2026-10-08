/*
 * diag_str - the names the engine keeps for the calls it saw, and WHICH
 * DIAGNOSE each one belongs to.
 *
 * A call to a kernel resolver is handed the NAME of what to find, and the
 * name is the one part of a hook that survives every change of how it is
 * reached. The store behind it is where several things go quietly wrong, so
 * each has its own assertion:
 *
 *   DEDUPLICATION  four calls handing the resolver the same word are one
 *                  statement. A store that counted them four times would
 *                  fill its bound on a loop.
 *   THE KEY IS (CAPABILITY, NODE, NAME)  the same word at two different call
 *                  sites is two facts, because which diagnose it follows
 *                  depends on the site. A key that ignored the node would
 *                  merge them and give one diagnose the other's names.
 *   GROWTH AND THE BOUND  the table is rebuilt every time the entries are
 *                  reallocated, and a rebuild that dropped or double-listed
 *                  an entry would make a name vanish only once a module had
 *                  enough of them - which no small test ever has. The bound
 *                  must mark the scan full rather than refuse silently.
 *   A NAME FOLLOWS ITS DIAGNOSE  two diagnoses with a node of the SAME
 *                  capability, matching two DIFFERENT calls, each carry only
 *                  the names read at the call they matched. This is the one
 *                  the capability-keyed store could not tell apart, and it is
 *                  asserted in both directions: what a diagnose has, and what
 *                  it must not have.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/detectors/pathogen/diag_int.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"

/* any and all over the ONE-name call a module reaches: `||` and `&&`, which is
 * what kof_diag_str_any and _all expand to. */
static int names_all(const struct kof_diag_scan *s, const struct kof_diag *d,
		     const char *const *v, uint32_t n)
{
	uint32_t i;

	if (!v || !n)
		return 0;
	for (i = 0; i < n; i++)
		if (!kof_diag_scan_name(s, d, v[i]))
			return 0;
	return 1;
}

static int names_any(const struct kof_diag_scan *s, const struct kof_diag *d,
		     const char *const *v, uint32_t n)
{
	uint32_t i;

	if (!v || !n)
		return 0;
	for (i = 0; i < n; i++)
		if (kof_diag_scan_name(s, d, v[i]))
			return 1;
	return 0;
}

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, \
	__LINE__, #c); fails++; } } while (0)

#define NONE 0xffffu

/* Add a hit and return its index. */
static uint16_t hit(struct kof_diag_scan *s, uint16_t cap)
{
	kof_diag_hit_add(s, 0x1000u + s->n_hit * 0x10u, cap, 0);
	return (uint16_t)(s->n_hit - 1u);
}

int main(void)
{
	struct kof_diag_scan s;
	char nm[48];
	uint32_t i;
	const uint16_t A = KOF_NUCLEO_KPROBE_REG, B = KOF_NUCLEO_KSYM_LOOKUP;

	memset(&s, 0, sizeof s);

	/* DEDUPLICATION, and the answer to "was it new". */
	CK(kof_diag_str_add(&s, A, 0, "kallsyms_lookup_name") == 1);
	CK(kof_diag_str_add(&s, A, 0, "kallsyms_lookup_name") == 0);
	CK(kof_diag_str_add(&s, A, 0, "kallsyms_lookup_name") == 0);
	CK(kof_diag_str_count(&s, A) == 1);

	/* THE KEY IS (CAPABILITY, NODE, NAME): the same word elsewhere is new. */
	CK(kof_diag_str_add(&s, B, 0, "kallsyms_lookup_name") == 1);
	CK(kof_diag_str_add(&s, A, 1, "kallsyms_lookup_name") == 1);
	CK(kof_diag_str_count(&s, A) == 2 && kof_diag_str_count(&s, B) == 1);

	/* ORDER IS THE ORDER FIRST SEEN, within a capability. */
	CK(kof_diag_str_add(&s, A, 1, "do_exit") == 1);
	CK(!strcmp(kof_diag_str_at(&s, A, 0), "kallsyms_lookup_name"));
	CK(!strcmp(kof_diag_str_at(&s, A, 1), "kallsyms_lookup_name"));
	CK(!strcmp(kof_diag_str_at(&s, A, 2), "do_exit"));
	CK(kof_diag_str_at(&s, A, 3) == NULL);

	/* GROWTH. Far past the first capacity of 16, so the table is rebuilt
	 * several times, and every entry must still dedupe afterwards. */
	for (i = 0; i < 700u; i++) {
		snprintf(nm, sizeof nm, "sym_%u", i);
		CK(kof_diag_str_add(&s, A, (uint16_t)(i % 7u), nm) == 1);
	}
	for (i = 0; i < 700u; i++) {
		snprintf(nm, sizeof nm, "sym_%u", i);
		CK(kof_diag_str_add(&s, A, (uint16_t)(i % 7u), nm) == 0);
	}
	CK(kof_diag_str_count(&s, A) == 703u);

	/* THE BOUND marks the scan full and refuses the name - it does not
	 * pretend, and it does not corrupt what is there. */
	for (i = 0; i < 700u; i++) {
		snprintf(nm, sizeof nm, "more_%u", i);
		kof_diag_str_add(&s, A, 2, nm);
	}
	CK(kof_diag_scan_full(&s) == 1);
	CK(kof_diag_str_add(&s, A, 0, "kallsyms_lookup_name") == 0);

	/* A name longer than a symbol can be is not kept. */
	{
		char big[200];

		memset(big, 'a', sizeof big - 1u);
		big[sizeof big - 1u] = 0;
		CK(kof_diag_str_add(&s, B, 0, big) == 0);
	}
	free(s.str);
	free(s.str_tab);

	/*
	 * A NAME FOLLOWS ITS DIAGNOSE.
	 *
	 * Three hits: two calls of the SAME capability (probe registrations),
	 * and a field read that hangs off the second only.
	 *
	 *     hit 0  kprobe-register   name "kallsyms_lookup_name"
	 *     hit 1  kprobe-register   name "do_exit"
	 *     hit 2  field-read        <- source of hit 1
	 *
	 * D_ANY is one node of that capability and matches BOTH calls.
	 * D_ONE adds a child, and only hit 1 has one, so it matches the second
	 * call alone. Both name the same capability; a store keyed by it could
	 * not give them different answers.
	 */
	{
		struct kof_diag_scan t;
		struct kof_diag_hit hits[4];
		struct kof_diag_node n_any[1], n_one[2];
		struct kof_diag d_any, d_one;
		const char *both[2] = { "kallsyms_lookup_name", "do_exit" };
		const char *x[1] = { "kallsyms_lookup_name" };
		const char *y[1] = { "do_exit" };
		const char *miss[1] = { "sys_call_table" };
		const char *mixed[2] = { "do_exit", "sys_call_table" };

		memset(&t, 0, sizeof t);
		memset(hits, 0, sizeof hits);
		t.hit = hits;
		t.cap_hit = 4u;
		(void)hit(&t, A);
		(void)hit(&t, A);
		(void)hit(&t, KOF_NUCLEO_ACTION_READ);
		kof_diag_note_in(kof_diag_hit_of(&t, 2u), 1u,
				 KOF_DIAG_ROLE_SOURCE, KOF_DIAG_KIND_PRODUCED);
		CK(kof_diag_str_add(&t, A, 0, "kallsyms_lookup_name") == 1);
		CK(kof_diag_str_add(&t, A, 1, "do_exit") == 1);

		memset(&d_any, 0, sizeof d_any);
		memset(n_any, 0, sizeof n_any);
		n_any[0].cap = A;
		n_any[0].parent = KOF_DIAG_NO_PARENT;
		d_any.n_node = 1;
		d_any.node = n_any;

		memset(&d_one, 0, sizeof d_one);
		memset(n_one, 0, sizeof n_one);
		n_one[0].cap = A;
		n_one[0].parent = KOF_DIAG_NO_PARENT;
		n_one[1].cap = KOF_NUCLEO_ACTION_READ;
		n_one[1].parent = 0;
		n_one[1].role = KOF_DIAG_ROLE_SOURCE;
		d_one.n_node = 2;
		d_one.node = n_one;

		/* the one that matches both calls carries both names */
		CK(names_all(&t, &d_any, x, 1) == 1);
		CK(names_all(&t, &d_any, y, 1) == 1);
		CK(names_all(&t, &d_any, both, 2) == 1);

		/* the one that matches the second call carries ITS name ... */
		CK(names_all(&t, &d_one, y, 1) == 1);
		/* ... and NOT the first call's, though it names the same
		 * capability. This is the assertion the capability-keyed store
		 * failed. */
		CK(names_all(&t, &d_one, x, 1) == 0);
		CK(names_all(&t, &d_one, both, 2) == 0);

		/* AND over the list: one missing name is a miss. */
		CK(names_all(&t, &d_any, miss, 1) == 0);
		CK(names_all(&t, &d_any, mixed, 2) == 0);
		/* ANY is the other half of the pair: one name present is enough,
		 * none is not, and it is the same walk with the opposite stop. */
		CK(names_any(&t, &d_any, mixed, 2) == 1);
		CK(names_any(&t, &d_any, miss, 1) == 0);
		CK(names_any(&t, &d_any, both, 2) == 1);
		CK(names_any(&t, &d_one, both, 2) == 1);   /* y is there */
		CK(names_any(&t, &d_one, x, 1) == 0);

		/* A diagnose that does not match carries nothing. */
		n_one[1].role = KOF_DIAG_ROLE_FD;
		CK(names_all(&t, &d_one, y, 1) == 0);
		n_one[1].role = KOF_DIAG_ROLE_SOURCE;

		/* Degenerate calls are a plain no. */
		CK(names_all(&t, &d_any, NULL, 1) == 0);
		CK(names_all(&t, &d_any, y, 0) == 0);
		CK(names_all(NULL, &d_any, y, 1) == 0);
		CK(names_all(&t, NULL, y, 1) == 0);

		free(t.str);
		free(t.str_tab);
	}

	printf("diag str: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
