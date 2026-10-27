/*
 * diag_load_known_misses - the defects of kof_diag_load (the record a diag-<kind>.kdig pack carries) that the fuzz of work package 9 found,
 * each a deterministic row written as the EXPECTATION and recorded with KM_CHECK (known_miss.h): green while the engine has the defect, red the
 * day it does not. The loader is run in a forked child (hostile_engine.h), because the first of them is a write past an array: the child's
 * result is "intact", "damaged" or a signal (a sanitised build stops at the write: the same row, the same defect).
 *
 *   F12  (FIXED: the row is a plain check now; the load refuses a record whose WHEN conditions, summed over its sections, exceed the array.)
 *        kofdiag.c kof_diag_load bounded ONE WHEN section by KOF_DIAG_MAX_WHEN (16) and appends the pairs of EVERY WHEN section to `out->when`:
 *        two sections of sixteen write 32 pairs into an array of 16, past the array into the rest of the struct and beyond it (the pack loader
 *        hands it an element of a heap array, so the next diagnose's record is the neighbour). Found by engine/diag_record (the row of
 *        tests/fuzz/diag/engine.c): "index 16 out of bounds for type 'kof_diag_when [16]'". Why the old tests missed it: (b) tests/unit/diag_pack.c
 *        damages the header and the table, never the tagged sections of a record that is otherwise well formed.
 *   F13  the loader does not clear a node's `val` and `sym` when the record has no such attribute: a node array that was used before keeps the old
 *        value and a pointer into a string store that may be gone. The pack loader's arrays are calloc'd and each slice is used once, so it is
 *        not reached there; the function's own contract ("the caller owns node and name") does not say the caller must clear them.
 *
 * usage: diag_load_known_misses
 */
#include "hostile_engine.h"
#include "known_miss.h"

#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include <kofmod/kofdiagtree.h>

static void le16(uint8_t *b, unsigned *n, unsigned v)
{
	b[(*n)++] = (uint8_t)v;
	b[(*n)++] = (uint8_t)(v >> 8);
}

/* one node (net-open, no parent), no sign words, then `reps` WHEN sections of `each` conditions on fact 1 */
static unsigned rec_when(uint8_t *b, unsigned reps, unsigned each)
{
	unsigned n = 0, r, i, j;

	le16(b, &n, 1); b[n++] = KOF_DIAG_ANALYSIS_SYSCALL; b[n++] = 1; b[n++] = 'a';
	le16(b, &n, (unsigned)KGENOME_NUCLEO_NET_OPEN); le16(b, &n, 0);
	b[n++] = KOF_DIAG_NO_PARENT; b[n++] = 0; b[n++] = 0; b[n++] = 0;
	b[n++] = 0;
	for (r = 0; r < reps; r++) {
		b[n++] = KDIG_SEC_WHEN;
		b[n++] = (uint8_t)(10u * each);
		for (i = 0; i < each; i++) {
			le16(b, &n, 1);
			for (j = 0; j < 8u; j++)
				b[n++] = (uint8_t)(j ? 0u : i);
		}
	}
	return n;
}

/* the diagnose with room after it: what a diagnose that is not the last of an array has next to it */
struct wrap {
	struct kof_diag d;
	uint8_t         canary[1024];
};

static struct wrap W;
static struct kof_diag_node node[KOF_DIAG_MAX_NODE];
static char name[256], needs[4096];

static struct kof_diag_store store(unsigned rl)
{
	struct kof_diag_store st = { node, name, needs, sizeof name, rl + 1u, KOF_DIAG_MAX_NODE };

	return st;
}

static int f12_child(void *arg)
{
	uint8_t rec[512];
	unsigned n = rec_when(rec, *(unsigned *)arg, 16), i;
	struct kof_diag_store st = store(n);

	memset(&W, 0, sizeof W);
	memset(W.canary, 0xa5, sizeof W.canary);
	(void)kof_diag_load(kof_buf_make(rec, n), &W.d, &st);
	for (i = 0; i < sizeof W.canary; i++)
		if (W.canary[i] != 0xa5)
			return 1;                                  /* damaged: the load wrote past the diagnose */
	return W.d.n_when <= KOF_DIAG_MAX_WHEN ? 0 : 2;            /* more conditions than the array holds */
}

static void f12(void)
{
	unsigned one = 1, two = 2;
	struct he_status a = he_child(f12_child, &one, 20), b = he_child(f12_child, &two, 20);

	CK(a.exited && a.code == 0, "the control: one WHEN section of sixteen loads intact (exited %d code %d signal %d)", a.exited, a.code, a.sig);
	CK(b.exited && b.code == 0, "F12 two WHEN sections of sixteen conditions are refused or loaded within the array (exited %d code %d signal %d)", b.exited, b.code, b.sig);
}

static int f13_child(void *arg)
{
	uint8_t a[64], b[64];
	unsigned na = 0, nb = 0;
	struct kof_diag d;
	struct kof_diag_store st;

	(void)arg;
	/* record A: one node with a value attribute and a symbol attribute */
	le16(a, &na, 1); a[na++] = 0; a[na++] = 1; a[na++] = 'a';
	le16(a, &na, (unsigned)KGENOME_NUCLEO_NET_OPEN); le16(a, &na, 0);
	a[na++] = KOF_DIAG_NO_PARENT; a[na++] = 0; a[na++] = 0;
	a[na++] = 10u + 5u;                                    /* the attribute run: (kind, 8, value) and (kind, 3, name) */
	a[na++] = KDIG_ATTR_VALUE; a[na++] = 8; { unsigned j; for (j = 0; j < 8u; j++) a[na++] = (uint8_t)(j ? 0u : 7u); }
	a[na++] = KDIG_ATTR_SYM; a[na++] = 3; a[na++] = 'x'; a[na++] = 'y'; a[na++] = 'z';
	/* record B: the same node, no attributes */
	le16(b, &nb, 1); b[nb++] = 0; b[nb++] = 1; b[nb++] = 'b';
	le16(b, &nb, (unsigned)KGENOME_NUCLEO_NET_OPEN); le16(b, &nb, 0);
	b[nb++] = KOF_DIAG_NO_PARENT; b[nb++] = 0; b[nb++] = 0; b[nb++] = 0;
	memset(node, 0, sizeof node);
	st = store(na);
	if (!kof_diag_load(kof_buf_make(a, na), &d, &st) || node[0].val != 7u || !node[0].sym)
		return 3;                                          /* the control failed: A did not load as written */
	st = store(nb);
	if (!kof_diag_load(kof_buf_make(b, nb), &d, &st))
		return 4;
	return node[0].val == 0 && node[0].sym == NULL ? 0 : 1;
}

static void f13(void)
{
	struct he_status s = he_child(f13_child, NULL, 20);

	CK(s.exited && s.code != 3 && s.code != 4, "the controls of F13: A loads with its attributes, B loads (code %d signal %d)", s.code, s.sig);
	/* KNOWN DEFECT WP9-F13 (2026-10-25, M): this row pins it, green until fixed. */
	KM_CHECK(s.exited && s.code == 0, "F13 a node array that held a value and a symbol is clean after a record with neither", "kofdiag.c kof_diag_load leaves val and sym");
}

int main(void)
{
	f12();
	f13();
	km_summary();
	printf("diag_load_known_misses: %u check(s), %u failure(s), %u known, %u fixed unexpectedly\n", he_checks, he_fails, km_known_n, km_fixed_n);
	return he_fails != 0 || km_failed();
}
