/*
 * famcat_pick - the DELETED variant names of a family and adding a variant under a CHOSEN one (libkofeng/verdictor/famcat.c:
 * kof_famcat_free_letter, kof_famcat_variant_name / kof_famcat_add_variant with a letter). The Add variant dialog of Manage > Pathogens
 * offers these names in a menu; a click picks one.
 *
 *   EXHAUSTIVE  one family that issued the letters A..F (counter 7); every one of the 64 subsets of them deleted: the list has exactly
 *               kof_famcat_free_letters entries, is ascending and equals an oracle written here; k past the end, a family that is not
 *               there and another family give 0. Then every letter number 0..12 asked for: it is taken exactly when it is 0 (the counter) or
 *               in the deleted set, with the name the oracle spells; every other number (declared, the counter itself, above it) is
 *               NO_FREE_LETTER and nothing changes
 *   CHOSEN      an add with a chosen deleted letter creates that name, keeps the counter, removes that letter from the list and no other,
 *               and a snapshot / restore round trip brings the list back; the file text lists the variants in letter order
 *   OTHER       a letter deleted in one family is refused in another family that still uses it, and the other family's list is its own
 *   REFUSALS    the checks of a plain add apply to a chosen letter and leave the catalog as it was (revision included): no type, a bad
 *               comment, the table full (FULL), an id clash (hash seam), the family at its longest name (63 characters; VARIANT_NAME
 *               cannot come from a chosen letter: the counter is refused first when its suffix would not fit)
 *   SPARSE      a counter loaded far above the variants (a file): the list is the gaps, found without walking the counter's range
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/verdictor/famcat.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define BOT (1u << KOF_MALTYPE_BOTNET)
#define TRO (1u << KOF_MALTYPE_TROJAN)

static struct kof_famcat_fam F[4], SF[4];
static struct kof_famcat_var V[64], SV[64];
static struct kof_famcat C, S;

static void fresh(uint32_t nf, uint32_t nv)
{
	memset(F, 0, sizeof F);
	memset(V, 0, sizeof V);
	kof_famcat_init(&C, F, nf, V, nv);
}

static uint32_t var_of(const char *name)
{
	uint32_t i;

	for (i = 0; i < C.n_var; i++)
		if (!strcmp(C.var[i].name, name))
			return i;
	return UINT32_MAX;
}

/* A family "Mirai" that issued letters 1..6 and had the letters of `mask` (bit n-1 = letter n) deleted afterwards. Letter 6 deleted still
 * leaves the counter at 7: nothing but the counter says it was ever there. */
static void build(uint32_t mask)
{
	uint32_t n, i;
	char name[16];

	fresh(4, 64);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	for (n = 2; n <= 6; n++)
		CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	for (n = 1; n <= 6; n++) {
		if (!(mask >> (n - 1u) & 1u))
			continue;
		snprintf(name, sizeof name, "Mirai_%c", (char)('A' + n - 1u));
		i = var_of(name);
		CK(i != UINT32_MAX && kof_famcat_delete_variant(&C, i) == KOF_FAMCAT_OK);
	}
	CK(C.fam[0].next == 7u);
}

static uint32_t pop(uint32_t m)
{
	uint32_t c = 0u;

	for (; m; m >>= 1)
		c += m & 1u;
	return c;
}

static void exhaustive(void)
{
	uint32_t mask, k, n, v, want, i;
	char nm[KOF_FAMCAT_NAME_MAX + 1], exp[32];

	for (mask = 0; mask < 64u; mask++) {
		uint32_t oracle[6], no = 0u;

		build(mask);
		for (n = 1; n <= 6; n++)
			if (mask >> (n - 1u) & 1u)
				oracle[no++] = n;
		CK(kof_famcat_free_letters(&C, 0) == no);
		for (k = 0; k < no; k++)
			CK(kof_famcat_free_letter(&C, 0, k) == oracle[k]);
		CK(kof_famcat_free_letter(&C, 0, no) == 0u && kof_famcat_free_letter(&C, 0, no + 1u) == 0u &&
		   kof_famcat_free_letter(&C, 0, UINT32_MAX) == 0u);
		CK(kof_famcat_free_letter(&C, 1, 0) == 0u && kof_famcat_free_letter(&C, UINT32_MAX, 0) == 0u);
		/* every number a caller may hand over */
		for (n = 0; n <= 12; n++) {
			int deleted = n >= 1u && n <= 6u && (mask >> (n - 1u) & 1u);
			uint32_t rev, nvar = C.n_var, next = C.fam[0].next;
			enum kof_famcat_status st;

			snprintf(exp, sizeof exp, "Mirai_%c", n ? (char)('A' + (n - 1u)) : 'G');
			st = kof_famcat_variant_name(&C, 0, n, nm, sizeof nm);
			if (n == 0u || deleted)
				CK(st == KOF_FAMCAT_OK && !strcmp(nm, exp));
			else
				CK(st == KOF_FAMCAT_NO_FREE_LETTER);
			rev = C.rev;
			st = kof_famcat_add_variant(&C, 0, NULL, TRO, n, NULL);
			if (n == 0u || deleted) {
				CK(st == KOF_FAMCAT_OK && C.n_var == nvar + 1u && var_of(exp) != UINT32_MAX);
				CK(C.fam[0].next == (n == 0u ? next + 1u : next));
				/* undo for the next number: delete the new one (the counter stays: that is the rule) */
				CK(kof_famcat_delete_variant(&C, var_of(exp)) == KOF_FAMCAT_OK);
				if (n == 0u) {
					/* the counter moved, so rebuild the case */
					build(mask);
				}
			} else {
				CK(st == KOF_FAMCAT_NO_FREE_LETTER && C.n_var == nvar && C.rev == rev && C.fam[0].next == next);
			}
		}
		/* the list is a function of the catalog: ask twice, same answer; the count never exceeds the counter's gaps */
		want = pop(mask);
		CK(kof_famcat_free_letters(&C, 0) == want);
		for (i = 0; i + 1u < want; i++)
			CK(kof_famcat_free_letter(&C, 0, i) < kof_famcat_free_letter(&C, 0, i + 1u));
		(void)v;
	}
}

static void chosen(void)
{
	uint32_t mask, k, v, rev;
	char nm[KOF_FAMCAT_NAME_MAX + 1];

	/* first, middle, last deleted letter, with the counter above the last one */
	for (mask = 1; mask < 64u; mask++) {
		uint32_t no = pop(mask);

		for (k = 0; k < no; k++) {
			uint32_t letter, j, next, want[6], nw = 0u;

			build(mask);
			letter = kof_famcat_free_letter(&C, 0, k);
			next = C.fam[0].next;
			for (j = 0; j < no; j++)
				if (j != k)
					want[nw++] = kof_famcat_free_letter(&C, 0, j);
			rev = C.rev;
			CK(kof_famcat_add_variant(&C, 0, "picked", BOT | TRO, letter, &v) == KOF_FAMCAT_OK);
			snprintf(nm, sizeof nm, "Mirai_%c", (char)('A' + letter - 1u));
			CK(!strcmp(C.var[v].name, nm) && C.var[v].letter == letter && C.var[v].types == (BOT | TRO) &&
			   !strcmp(kof_famcat_comment(&C, v), "picked") && C.rev != rev);
			CK(C.fam[0].next == next);
			CK(kof_famcat_free_letters(&C, 0) == nw);
			for (j = 0; j < nw; j++)
				CK(kof_famcat_free_letter(&C, 0, j) == want[j]);
			/* the same letter again is no longer deleted */
			CK(kof_famcat_add_variant(&C, 0, NULL, TRO, letter, NULL) == KOF_FAMCAT_NO_FREE_LETTER);
			/* the next plain add is still the counter's */
			CK(kof_famcat_variant_name(&C, 0, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_G"));
		}
	}
	/* snapshot / restore: a chosen add undone by Discard gives the list back, and the pair is dirty in between */
	memset(SF, 0, sizeof SF);
	memset(SV, 0, sizeof SV);
	kof_famcat_init(&S, SF, 4, SV, 64);
	build(0x0a);                                /* B and D deleted */
	CK(kof_famcat_snapshot(&C, &S) == KOF_FAMCAT_OK && !kof_famcat_dirty(&C, &S));
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 4u, NULL) == KOF_FAMCAT_OK && kof_famcat_dirty(&C, &S));
	CK(kof_famcat_free_letters(&C, 0) == 1u && kof_famcat_free_letter(&C, 0, 0) == 2u);
	CK(kof_famcat_restore(&C, &S) == KOF_FAMCAT_OK && !kof_famcat_dirty(&C, &S));
	CK(kof_famcat_free_letters(&C, 0) == 2u && kof_famcat_free_letter(&C, 0, 0) == 2u && kof_famcat_free_letter(&C, 0, 1) == 4u);
	CK(var_of("Mirai_D") == UINT32_MAX && C.fam[0].next == 7u);
	/* add, then the file text lists it in letter order */
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 4u, NULL) == KOF_FAMCAT_OK);
	{
		char t[2048];
		const char *a, *b;

		CK(kof_famcat_family_text(&C, 0, t, sizeof t) < sizeof t);
		a = strstr(t, "KOF_MALWARE_VARIANT(\"C\"");
		b = strstr(t, "KOF_MALWARE_VARIANT(\"D\"");
		CK(a && b && a < b && strstr(t, "KOF_MALWARE_NEXT_VARIANT(\"G\")") != NULL);
	}
}

static void other_family(void)
{
	uint32_t v;

	fresh(4, 16);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);      /* Mirai_B */
	CK(kof_famcat_add_family(&C, "Gafgyt", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);      /* Gafgyt_B */
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);      /* Gafgyt_C */
	CK(kof_famcat_delete_variant(&C, var_of("Mirai_B")) == KOF_FAMCAT_OK);
	CK(kof_famcat_free_letters(&C, 0) == 1u && kof_famcat_free_letter(&C, 0, 0) == 2u);
	CK(kof_famcat_free_letters(&C, 1) == 0u && kof_famcat_free_letter(&C, 1, 0) == 0u);
	CK(kof_famcat_free_letters(&C, 2) == 0u && kof_famcat_free_letters(&C, UINT32_MAX) == 0u);   /* no such family */
	/* letter 2 is deleted in Mirai and in use in Gafgyt */
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 2u, NULL) == KOF_FAMCAT_NO_FREE_LETTER);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 2u, &v) == KOF_FAMCAT_OK && !strcmp(C.var[v].name, "Mirai_B") && C.var[v].family == 0u);
	CK(kof_famcat_add_variant(&C, 7, NULL, TRO, 2u, NULL) == KOF_FAMCAT_NO_FAMILY);
	/* deleting Gafgyt_B now frees 2 there too, and Mirai's use of it does not matter */
	CK(kof_famcat_delete_variant(&C, var_of("Gafgyt_B")) == KOF_FAMCAT_OK);
	CK(kof_famcat_free_letters(&C, 1) == 1u && kof_famcat_free_letter(&C, 1, 0) == 2u && kof_famcat_free_letters(&C, 0) == 0u);
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 2u, &v) == KOF_FAMCAT_OK && !strcmp(C.var[v].name, "Gafgyt_B"));
}

static uint64_t hash_len(void *ud, const char *key, size_t len)
{
	(void)ud; (void)key;
	return 0x1000u + len;
}

static void refusals(void)
{
	char big[KOF_FAMCAT_NAME_MAX + 1], nm[KOF_FAMCAT_NAME_MAX + 1];
	uint32_t rev, nvar, i;
	size_t fm;

	/* no type, a bad comment: nothing changes, the deleted letter stays on offer */
	build(0x02);
	rev = C.rev;
	nvar = C.n_var;
	CK(kof_famcat_add_variant(&C, 0, NULL, 0u, 2u, NULL) == KOF_FAMCAT_NO_TYPE);
	CK(kof_famcat_add_variant(&C, 0, "a*b", TRO, 2u, NULL) == KOF_FAMCAT_BAD_COMMENT);
	CK(kof_famcat_add_variant(&C, 0, NULL, 1u << KOF_MALTYPE_PACKER, 2u, NULL) == KOF_FAMCAT_BAD_TYPE);
	CK(C.rev == rev && C.n_var == nvar && kof_famcat_free_letters(&C, 0) == 1u && kof_famcat_free_letter(&C, 0, 0) == 2u);
	/* the table full: cap 2 holds B and C after A is deleted, so deleted letter A has no room */
	fresh(2, 2);
	CK(kof_famcat_add_family(&C, "Q", NULL, BOT, NULL) == KOF_FAMCAT_OK && kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_delete_variant(&C, 0) == KOF_FAMCAT_OK && kof_famcat_add_variant(&C, 0, NULL, BOT, 0, NULL) == KOF_FAMCAT_OK);
	CK(C.n_var == 2u && kof_famcat_free_letters(&C, 0) == 1u);
	rev = C.rev;
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO | BOT, 1u, NULL) == KOF_FAMCAT_FULL && C.n_var == 2u && C.rev == rev);
	/* an id clash: the hash gives every variant key of the family one id; A is deleted, B exists, so A clashes with B */
	build(0x01);
	kof_famcat_set_idhash(&C, hash_len, NULL);
	rev = C.rev;
	nvar = C.n_var;
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 1u, NULL) == KOF_FAMCAT_ID_CLASH && C.n_var == nvar && C.rev == rev);
	CK(C.fam[0].next == 7u && kof_famcat_free_letter(&C, 0, 0) == 1u);
	/* 63 characters: the family at the longest name the table accepts. A chosen deleted letter spells a name of at most 63 characters;
	 * VARIANT_NAME cannot come from a chosen letter, because the counter itself is refused when its suffix would not fit (load_next),
	 * and a deleted letter is always below the counter. */
	fresh(2, 16);
	fm = kof_famcat_family_max(&C);
	CK(fm == 61u);
	memset(big, 'f', fm);
	big[fm] = 0;
	CK(kof_famcat_add_family(&C, big, NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_delete_variant(&C, 0) == KOF_FAMCAT_OK);              /* letter A is deleted, B exists */
	CK(kof_famcat_variant_name(&C, 0, 1u, nm, sizeof nm) == KOF_FAMCAT_OK && strlen(nm) == fm + 2u);
	CK(kof_famcat_load_next(&C, 0, 30u) == KOF_FAMCAT_VARIANT_NAME);    /* the counter itself keeps the 63 rule */
	CK(C.fam[0].next == 3u);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 27u, NULL) == KOF_FAMCAT_NO_FREE_LETTER);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 1u, &i) == KOF_FAMCAT_OK && strlen(C.var[i].name) == fm + 2u);
}

static void sparse(void)
{
	uint32_t k;

	/* a family of 60 characters under a table of 702 would be needed for a counter of 700; here the counter is raised through a
	 * short name so the gaps are many and the variants few */
	fresh(2, 16);
	CK(kof_famcat_add_family(&C, "Z", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_load_next(&C, 0, 26u) == KOF_FAMCAT_OK && C.fam[0].next == 26u);
	CK(kof_famcat_free_letters(&C, 0) == 24u);                       /* 2..25: A is declared, Z (26) was never issued */
	for (k = 0; k < 24u; k++)
		CK(kof_famcat_free_letter(&C, 0, k) == k + 2u);
	CK(kof_famcat_free_letter(&C, 0, 24u) == 0u);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 25u, NULL) == KOF_FAMCAT_OK && !strcmp(C.var[1].name, "Z_Y"));
	CK(kof_famcat_free_letters(&C, 0) == 23u && kof_famcat_free_letter(&C, 0, 22u) == 24u);
	/* a letter at the counter and above it is not deleted */
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 26u, NULL) == KOF_FAMCAT_NO_FREE_LETTER);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 27u, NULL) == KOF_FAMCAT_NO_FREE_LETTER);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, UINT32_MAX, NULL) == KOF_FAMCAT_NO_FREE_LETTER);
}

int main(void)
{
	exhaustive();
	chosen();
	other_family();
	refusals();
	sparse();
	if (fails) {
		printf("famcat_pick: %d failure(s)\n", fails);
		return 1;
	}
	printf("famcat_pick: ok\n");
	return 0;
}
