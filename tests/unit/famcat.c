/*
 * famcat - the malware family catalog (libkofeng/verdictor/famcat.c), with hand-built cases:
 *   NAMES     valid, empty, 64 and 65 characters, every byte value against the rule (letters, digits, '_' and '-' only),
 *             case-sensitive comparison
 *   FAMILY    add creates the family AND its first variant "<name>_A" carrying the types; a type set is required (NO_TYPE);
 *             the longest name the table can reach must fit 63 characters (KOF_FAMCAT_VARIANT_NAME); duplicate family
 *   LETTERING the library names variants <family>_A .. _Z, _AA .. (bijective base 26) against an independent spreadsheet-column
 *             oracle, the add creates the name variant_name shows, and the 64-character rule counts the longest suffix of the table
 *   VARIANT   add inside a family, a set equal to a sibling's is refused (DUP_TYPES) and allowed in another family, no type, Packer, a bit
 *             past the list; set_types follows the same rules
 *   COMMENT   kof_comment_char on every byte, 120/121 characters, empty/NULL ok, the comment of a variant only (add_family's is the first variant's), add and
 *             set_comment share the check and refuse without changing anything
 *   TYPES     the selectable list is the engine's minus Packer, spelled by kof_maltype_name; the all-mask
 *   LIMITS    the caller's two tables: the add past either answers KOF_FAMCAT_FULL and nothing is dropped
 *   ORDER     families in creation order, each followed by its variants in creation order, whatever order they were made in;
 *             a short buffer is seen in the returned total
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/verdictor/famcat.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static struct kof_famcat_fam F[8];
static struct kof_famcat_var V[16];
static struct kof_famcat C;

static void fresh(uint32_t nf, uint32_t nv)
{
	memset(F, 0, sizeof F);
	memset(V, 0, sizeof V);
	kof_famcat_init(&C, F, nf, V, nv);
}

static void names(void)
{
	char s[128];
	int b, ok = 0;

	CK(kof_famcat_name_check("Mirai") == KOF_FAMCAT_OK);
	CK(kof_famcat_name_check("a-b_C9") == KOF_FAMCAT_OK);
	CK(kof_famcat_name_check("") == KOF_FAMCAT_EMPTY);
	CK(kof_famcat_name_check(NULL) == KOF_FAMCAT_EMPTY);
	/* the engine's rule (kofname.h): 63 characters, not 64 */
	CK(KOF_FAMCAT_NAME_MAX == 63u && KOF_NAME_MAX == 63u);
	memset(s, 'a', 63);
	s[63] = 0;
	CK(kof_famcat_name_check(s) == KOF_FAMCAT_OK && kof_name_ok(s));
	s[63] = 'a';
	s[64] = 0;
	CK(kof_famcat_name_check(s) == KOF_FAMCAT_TOO_LONG && !kof_name_ok(s));
	/* characters the rule refuses on purpose */
	CK(kof_famcat_name_check("a.b") == KOF_FAMCAT_BAD_CHAR && kof_famcat_name_check("a*") == KOF_FAMCAT_BAD_CHAR &&
	   kof_famcat_name_check("a/b") == KOF_FAMCAT_BAD_CHAR && kof_famcat_name_check("a b") == KOF_FAMCAT_BAD_CHAR &&
	   kof_famcat_name_check(".") == KOF_FAMCAT_BAD_CHAR && kof_famcat_name_check("..") == KOF_FAMCAT_BAD_CHAR);
	memset(s, 'a', 127);
	s[127] = 0;
	CK(kof_famcat_name_check(s) == KOF_FAMCAT_TOO_LONG);
	for (b = 1; b < 256; b++) {
		char t[3] = { 'x', (char)b, 0 };
		int want = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-';

		CK(kof_famcat_name_check(t) == (want ? KOF_FAMCAT_OK : KOF_FAMCAT_BAD_CHAR));
		CK(kof_name_char(b) == want);
		ok += want;
	}
	CK(ok == 64);
	/* too long is decided before the character check, and a bad character past 63 is still too long */
	memset(s, 'a', 70);
	s[70] = 0;
	s[3] = ' ';
	CK(kof_famcat_name_check(s) == KOF_FAMCAT_TOO_LONG);
	/* the status words are not empty */
	for (b = KOF_FAMCAT_OK; b <= KOF_FAMCAT_NO_FREE_LETTER; b++)
		CK(kof_famcat_status_text((enum kof_famcat_status)b)[0] != 0);
}

#define BOT (1u << KOF_MALTYPE_BOTNET)
#define TRO (1u << KOF_MALTYPE_TROJAN)
#define VIR (1u << KOF_MALTYPE_VIRUS)

static void family(void)
{
	uint32_t f = 99;
	char s[80];

	fresh(8, 16);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK && f == 0);
	CK(C.n_fam == 1 && C.n_var == 1);
	CK(!strcmp(F[0].name, "Mirai") && !strcmp(V[0].name, "Mirai_A") && V[0].family == 0 && V[0].types == BOT);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_DUP_FAMILY);
	CK(kof_famcat_add_family(&C, "mirai", NULL, BOT, &f) == KOF_FAMCAT_DUP_FAMILY);   /* letter case is ignored: one lower-case file name */
	CK(kof_famcat_add_family(&C, "MIRAI", NULL, BOT, &f) == KOF_FAMCAT_DUP_FAMILY && C.n_fam == 1u);
	CK(kof_famcat_add_family(&C, "", NULL, BOT, &f) == KOF_FAMCAT_EMPTY);
	CK(kof_famcat_add_family(&C, "a b", NULL, BOT, &f) == KOF_FAMCAT_BAD_CHAR);
	CK(kof_famcat_add_family(&C, "X", NULL, 0, &f) == KOF_FAMCAT_NO_TYPE);
	CK(kof_famcat_add_family(&C, "X", NULL, 1u << KOF_MALTYPE_PACKER, &f) == KOF_FAMCAT_BAD_TYPE);
	CK(kof_famcat_add_family(&C, "X", NULL, BOT | (1u << KOF_MALTYPE_COUNT), &f) == KOF_FAMCAT_BAD_TYPE);
	CK(C.n_fam == 1 && C.n_var == 1);
	/* a table of 16 variants has 1-letter suffixes: a 61-character family gives 63-character names and fits, 62 does not */
	CK(kof_famcat_family_max(&C) == 61);
	memset(s, 'z', 61);
	s[61] = 0;
	CK(kof_famcat_add_family(&C, s, NULL, BOT, &f) == KOF_FAMCAT_OK && strlen(V[C.n_var - 1u].name) == 63);
	memset(s, 'y', 62);
	s[62] = 0;
	CK(kof_famcat_add_family(&C, s, NULL, BOT, &f) == KOF_FAMCAT_VARIANT_NAME);
	memset(s, 'y', 63);
	s[63] = 0;
	CK(kof_famcat_add_family(&C, s, NULL, BOT, &f) == KOF_FAMCAT_VARIANT_NAME);
	memset(s, 'y', 64);
	s[64] = 0;
	CK(kof_famcat_add_family(&C, s, NULL, BOT, &f) == KOF_FAMCAT_TOO_LONG);
	CK(C.n_fam == 2 && C.n_var == 2);
}

static void variant(void)
{
	uint32_t f, v = 99, all = kof_famcat_type_mask_all();
	char nm[KOF_FAMCAT_NAME_MAX + 1];

	fresh(8, 16);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "Gafgyt", NULL, BOT, &f) == KOF_FAMCAT_OK);
	/* the next name is the library's, and is the one add creates */
	CK(kof_famcat_variant_name(&C, 0, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_B"));
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, &v) == KOF_FAMCAT_OK && v == 2 && !strcmp(V[2].name, "Mirai_B"));
	CK(V[2].family == 0 && V[2].types == TRO);
	CK(kof_famcat_variant_name(&C, 0, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_C"));
	CK(kof_famcat_variant_name(&C, 1, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Gafgyt_B"));
	CK(kof_famcat_variant_name(&C, 2, 0, nm, sizeof nm) == KOF_FAMCAT_NO_FAMILY);
	/* the first name of a family that does not exist yet is numbered by the same function */
	CK(kof_famcat_first_variant_name(&C, "Zed", nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Zed_A"));
	{
		char big[70];

		memset(big, 'k', 62);
		big[62] = 0;
		CK(kof_famcat_first_variant_name(&C, big, nm, sizeof nm) == KOF_FAMCAT_VARIANT_NAME);
	}
	/* the same set in the same family is refused, in another family it is fine */
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, &v) == KOF_FAMCAT_DUP_TYPES);
	CK(kof_famcat_add_variant(&C, 0, NULL, BOT, 0, &v) == KOF_FAMCAT_DUP_TYPES);     /* the first variant's set */
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 0, &v) == KOF_FAMCAT_OK && !strcmp(V[v].name, "Gafgyt_B"));
	CK(kof_famcat_add_variant(&C, 0, NULL, BOT | TRO, 0, &v) == KOF_FAMCAT_OK && !strcmp(V[v].name, "Mirai_C"));
	CK(kof_famcat_add_variant(&C, 2, NULL, TRO, 0, &v) == KOF_FAMCAT_NO_FAMILY);
	CK(kof_famcat_add_variant(&C, 0, NULL, 0, 0, &v) == KOF_FAMCAT_NO_TYPE);
	CK(kof_famcat_add_variant(&C, 0, NULL, 1u << KOF_MALTYPE_PACKER, 0, &v) == KOF_FAMCAT_BAD_TYPE);
	CK(kof_famcat_add_variant(&C, 0, NULL, 1u << KOF_MALTYPE_COUNT, 0, &v) == KOF_FAMCAT_BAD_TYPE);
	CK(kof_famcat_add_variant(&C, 0, NULL, 0x80000000u, 0, &v) == KOF_FAMCAT_BAD_TYPE);
	CK(kof_famcat_add_variant(&C, 0, NULL, all, 0, &v) == KOF_FAMCAT_OK);
	CK(C.n_var == 6);
	/* set types: replace, not empty, not a sibling's set, Packer refused; a refusal changes nothing */
	CK(kof_famcat_set_types(&C, 0, VIR) == KOF_FAMCAT_OK && V[0].types == VIR);
	CK(kof_famcat_set_types(&C, 0, all | (1u << KOF_MALTYPE_PACKER)) == KOF_FAMCAT_BAD_TYPE && V[0].types == VIR);
	CK(kof_famcat_set_types(&C, 0, 0) == KOF_FAMCAT_NO_TYPE && V[0].types == VIR);
	CK(kof_famcat_set_types(&C, 0, TRO) == KOF_FAMCAT_DUP_TYPES && V[0].types == VIR);
	CK(kof_famcat_set_types(&C, 0, VIR) == KOF_FAMCAT_OK);                   /* its own set is not a duplicate */
	CK(kof_famcat_set_types(&C, 6, VIR) == KOF_FAMCAT_NO_FAMILY);
}

/* The k-th non-empty set of selectable types (k = 1..1023): the bits of k spread over the engine's list. */
static uint32_t mask_of(uint32_t k)
{
	uint32_t i, m = 0;

	for (i = 0; i < kof_famcat_type_count(); i++)
		if (k >> i & 1u)
			m |= 1u << kof_famcat_type_value(i);
	return m;
}

/* Independent oracle: the spreadsheet column name of n (1 = A, 26 = Z, 27 = AA, 702 = ZZ, 703 = AAA). */
static void column(uint32_t n, char *out)
{
	char t[8];
	int k = 0, i;

	while (n) {
		n--;
		t[k++] = (char)('A' + n % 26u);
		n /= 26u;
	}
	for (i = 0; i < k; i++)
		out[i] = t[k - 1 - i];
	out[k] = 0;
}

/* Lettering: the names against the oracle, the boundaries, and the 64-character rule against the longest suffix of the table. */
static void lettering(void)
{
	static struct kof_famcat_fam BF[3];
	static struct kof_famcat_var BV[800];
	struct kof_famcat B;
	char nm[KOF_FAMCAT_NAME_MAX + 1], want[80], col[8], s[80];
	uint32_t f, v, k;

	kof_famcat_init(&B, BF, 3, BV, 800);
	CK(kof_famcat_add_family(&B, "A", NULL, mask_of(1), &f) == KOF_FAMCAT_OK && !strcmp(BV[0].name, "A_A"));
	for (k = 2; k <= 703; k++) {
		CK(kof_famcat_add_variant(&B, 0, NULL, mask_of(k), 0, &v) == KOF_FAMCAT_OK);
		column(k, col);
		snprintf(want, sizeof want, "A_%s", col);
		CK(!strcmp(BV[v].name, want));
	}
	CK(!strcmp(BV[25].name, "A_Z") && !strcmp(BV[26].name, "A_AA") && !strcmp(BV[51].name, "A_AZ") && !strcmp(BV[52].name, "A_BA"));
	CK(!strcmp(BV[701].name, "A_ZZ") && !strcmp(BV[702].name, "A_AAA"));
	CK(kof_famcat_variant_name(&B, 0, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "A_AAB"));
	/* 800 variants need 3 letters: a family of 59 characters is accepted (63 with "_AAA"), 60 is refused */
	kof_famcat_init(&B, BF, 3, BV, 800);
	CK(kof_famcat_family_max(&B) == 59);
	memset(s, 'q', 59);
	s[59] = 0;
	CK(kof_famcat_add_family(&B, s, NULL, mask_of(1), &f) == KOF_FAMCAT_OK);
	s[59] = 'q';
	s[60] = 0;
	CK(kof_famcat_add_family(&B, s, NULL, mask_of(1), &f) == KOF_FAMCAT_VARIANT_NAME && B.n_fam == 1);
	CK(kof_famcat_first_variant_name(&B, s, nm, sizeof nm) == KOF_FAMCAT_VARIANT_NAME);
	/* 256 variants (the viewer's table) need 2 letters: 60 characters fit, 61 do not, and the 256th name is 63 characters */
	kof_famcat_init(&B, BF, 3, BV, 256);
	CK(kof_famcat_family_max(&B) == 60);
	memset(s, 'r', 60);
	s[60] = 0;
	CK(kof_famcat_add_family(&B, s, NULL, mask_of(1), &f) == KOF_FAMCAT_OK);
	for (k = 2; k <= 256; k++)
		CK(kof_famcat_add_variant(&B, 0, NULL, mask_of(k), 0, &v) == KOF_FAMCAT_OK && strlen(BV[v].name) <= 63);
	CK(strlen(BV[255].name) == 63 && !strcmp(BV[255].name + 61, "IV"));      /* 256 = 9 * 26 + 22 */
	CK(kof_famcat_add_variant(&B, 0, NULL, mask_of(257), 0, &v) == KOF_FAMCAT_FULL);
	memset(s, 'r', 61);
	s[61] = 0;
	CK(kof_famcat_add_family(&B, s, NULL, mask_of(1), &f) == KOF_FAMCAT_VARIANT_NAME);
	/* a buffer too small for the name: refused, not cut */
	kof_famcat_init(&B, BF, 3, BV, 16);
	CK(kof_famcat_add_family(&B, "Z", NULL, mask_of(1), &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_variant_name(&B, 0, 0, nm, 3) == KOF_FAMCAT_VARIANT_NAME);
	CK(kof_famcat_variant_name(&B, 0, 0, nm, 4) == KOF_FAMCAT_OK && !strcmp(nm, "Z_B"));
}

/* COMMENT: the engine's rule (kof_comment_char) and the named length; family and variant comments are separate and listed. */
static void comments(void)
{
	char s[KOF_FAMCAT_COMMENT_MAX + 8];
	uint32_t f, v;
	int b;

	fresh(8, 16);
	CK(KOF_FAMCAT_COMMENT_MAX == 120u);
	CK(kof_famcat_comment_check(NULL) == KOF_FAMCAT_OK && kof_famcat_comment_check("") == KOF_FAMCAT_OK);
	/* every byte against the engine's rule, '*' and '/' refused */
	for (b = 1; b < 256; b++) {
		char t[3] = { 'x', (char)b, 0 };

		CK(kof_famcat_comment_check(t) == (kof_comment_char(b) ? KOF_FAMCAT_OK : KOF_FAMCAT_BAD_COMMENT));
	}
	CK(kof_famcat_comment_check("a*b") == KOF_FAMCAT_BAD_COMMENT && kof_famcat_comment_check("a/b") == KOF_FAMCAT_BAD_COMMENT);
	CK(kof_famcat_comment_check("first seen, 2016 (v1.2)") == KOF_FAMCAT_OK);
	memset(s, 'c', 120);
	s[120] = 0;
	CK(kof_famcat_comment_check(s) == KOF_FAMCAT_OK);
	s[120] = 'c';
	s[121] = 0;
	CK(kof_famcat_comment_check(s) == KOF_FAMCAT_COMMENT_TOO_LONG);
	/* too long is decided before the character check */
	s[3] = '*';
	CK(kof_famcat_comment_check(s) == KOF_FAMCAT_COMMENT_TOO_LONG);
	CK(kof_famcat_status_text(KOF_FAMCAT_BAD_COMMENT)[0] && kof_famcat_status_text(KOF_FAMCAT_COMMENT_TOO_LONG)[0]);
	/* add_family: the comment is the FIRST VARIANT's (a family has none); a refusal adds nothing */
	CK(kof_famcat_add_family(&C, "Mirai", "a*b", BOT, &f) == KOF_FAMCAT_BAD_COMMENT && C.n_fam == 0 && C.n_var == 0);
	CK(kof_famcat_add_family(&C, "Mirai", "first one", BOT, &f) == KOF_FAMCAT_OK && !strcmp(V[0].comment, "first one"));
	CK(kof_famcat_add_family(&C, "Gafgyt", NULL, BOT, &f) == KOF_FAMCAT_OK && !V[1].comment[0]);
	CK(kof_famcat_add_variant(&C, 0, "x/y", TRO, 0, &v) == KOF_FAMCAT_BAD_COMMENT && C.n_var == 2);
	CK(kof_famcat_add_variant(&C, 0, "the variant", TRO, 0, &v) == KOF_FAMCAT_OK && !strcmp(V[v].comment, "the variant") &&
	   !strcmp(V[0].comment, "first one"));
	/* the comment of every variant, by index */
	CK(!strcmp(kof_famcat_comment(&C, 0), "first one") && !kof_famcat_comment(&C, 1)[0] &&
	   !strcmp(kof_famcat_comment(&C, v), "the variant") && !kof_famcat_comment(&C, 99)[0]);
	/* set_comment: same rules, nothing else changes */
	CK(kof_famcat_set_comment(&C, v, "new variant text") == KOF_FAMCAT_OK && !strcmp(V[v].comment, "new variant text") &&
	   !strcmp(V[0].comment, "first one") && V[v].types == TRO && !strcmp(V[v].name, "Mirai_B"));
	CK(kof_famcat_set_comment(&C, v, "a*b") == KOF_FAMCAT_BAD_COMMENT && !strcmp(V[v].comment, "new variant text"));
	memset(s, 'c', 121);
	s[121] = 0;
	CK(kof_famcat_set_comment(&C, v, s) == KOF_FAMCAT_COMMENT_TOO_LONG && !strcmp(V[v].comment, "new variant text"));
	CK(kof_famcat_set_comment(&C, v, "") == KOF_FAMCAT_OK && !V[v].comment[0]);
	CK(kof_famcat_set_comment(&C, v, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_set_comment(&C, 99, "x") == KOF_FAMCAT_NO_FAMILY);
}

/* EDIT: the counter, reuse, rename, delete, set_variant. */
static void edit(void)
{
	char nm[KOF_FAMCAT_NAME_MAX + 1];
	uint32_t f, v, i;

	fresh(8, 16);
	CK(kof_famcat_add_family(&C, "Mirai", "one", BOT, &f) == KOF_FAMCAT_OK && F[0].next == 2u && V[0].letter == 1u);
	CK(kof_famcat_add_variant(&C, 0, "two", TRO, 0, &v) == KOF_FAMCAT_OK && V[v].letter == 2u && F[0].next == 3u);
	CK(kof_famcat_add_variant(&C, 0, NULL, VIR, 0, &v) == KOF_FAMCAT_OK && !strcmp(V[v].name, "Mirai_C") && F[0].next == 4u);
	CK(kof_famcat_add_variant(&C, 0, NULL, VIR | TRO, 0, &v) == KOF_FAMCAT_OK && !strcmp(V[v].name, "Mirai_D") && F[0].next == 5u);
	CK(kof_famcat_free_letters(&C, 0) == 0u && kof_famcat_variant_name(&C, 0, 1, nm, sizeof nm) == KOF_FAMCAT_NO_FREE_LETTER);
	/* delete Mirai_B: the default never reuses its letter, the option takes the smallest free one */
	CK(kof_famcat_delete_variant(&C, 1) == KOF_FAMCAT_OK && C.n_var == 3u && F[0].next == 5u);
	CK(kof_famcat_free_letters(&C, 0) == 1u);
	CK(kof_famcat_variant_name(&C, 0, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_E"));
	CK(kof_famcat_variant_name(&C, 0, 1, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_B"));
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 1, &v) == KOF_FAMCAT_OK && !strcmp(V[v].name, "Mirai_B") && F[0].next == 5u);
	CK(kof_famcat_free_letters(&C, 0) == 0u);
	/* deleting the LAST letter does not lower the counter either */
	for (i = 0; i < C.n_var; i++)
		if (!strcmp(V[i].name, "Mirai_D"))
			CK(kof_famcat_delete_variant(&C, i) == KOF_FAMCAT_OK);
	CK(F[0].next == 5u && kof_famcat_variant_name(&C, 0, 0, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_E"));
	CK(kof_famcat_variant_name(&C, 0, 1, nm, sizeof nm) == KOF_FAMCAT_OK && !strcmp(nm, "Mirai_D"));
	CK(kof_famcat_delete_variant(&C, 99) == KOF_FAMCAT_NO_FAMILY);
	/* a family with no variant left stays and still takes a variant, with the counter going on */
	fresh(8, 16);
	CK(kof_famcat_add_family(&C, "Solo", NULL, BOT, &f) == KOF_FAMCAT_OK && kof_famcat_delete_variant(&C, 0) == KOF_FAMCAT_OK);
	CK(C.n_fam == 1u && C.n_var == 0u && kof_famcat_add_variant(&C, 0, NULL, BOT, 0, &v) == KOF_FAMCAT_OK && !strcmp(V[v].name, "Solo_B"));
	/* rename: the variants follow, the letters stay, the rules are add_family's, a rename to the same name with another case is fine */
	fresh(8, 16);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK && kof_famcat_add_family(&C, "Gafgyt", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, &v) == KOF_FAMCAT_OK && kof_famcat_delete_variant(&C, 0) == KOF_FAMCAT_OK);
	CK(kof_famcat_rename_family(&C, 0, "Mirai2") == KOF_FAMCAT_OK && !strcmp(F[0].name, "Mirai2"));
	for (i = 0; i < C.n_var; i++)
		if (C.var[i].family == 0u)
			CK(!strcmp(C.var[i].name, "Mirai2_B") && C.var[i].letter == 2u);
	CK(kof_famcat_rename_family(&C, 0, "gafgyt") == KOF_FAMCAT_DUP_FAMILY && !strcmp(F[0].name, "Mirai2"));
	CK(kof_famcat_rename_family(&C, 0, "MIRAI2") == KOF_FAMCAT_OK && !strcmp(F[0].name, "MIRAI2"));
	CK(kof_famcat_rename_family(&C, 0, "") == KOF_FAMCAT_EMPTY && kof_famcat_rename_family(&C, 0, "a b") == KOF_FAMCAT_BAD_CHAR);
	CK(kof_famcat_rename_family(&C, 7, "x") == KOF_FAMCAT_NO_FAMILY);
	{
		char big[70];

		memset(big, 'k', 63);
		big[63] = 0;
		CK(kof_famcat_rename_family(&C, 0, big) == KOF_FAMCAT_VARIANT_NAME && !strcmp(F[0].name, "MIRAI2"));
	}
	/* delete a family: its variants go with it, the others keep their order and point at the right family */
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 0, &v) == KOF_FAMCAT_OK);
	CK(kof_famcat_delete_family(&C, 0) == KOF_FAMCAT_OK && C.n_fam == 1u && C.n_var == 2u && !strcmp(F[0].name, "Gafgyt"));
	CK(C.var[0].family == 0u && C.var[1].family == 0u && !strcmp(C.var[1].name, "Gafgyt_B") && kof_famcat_delete_family(&C, 1) == KOF_FAMCAT_NO_FAMILY);
	/* set_variant: types and comment together, or neither */
	CK(kof_famcat_set_variant(&C, 1, "note", VIR) == KOF_FAMCAT_OK && !strcmp(C.var[1].comment, "note") && C.var[1].types == VIR);
	CK(kof_famcat_set_variant(&C, 1, "a*b", TRO) == KOF_FAMCAT_BAD_COMMENT && C.var[1].types == VIR && !strcmp(C.var[1].comment, "note"));
	CK(kof_famcat_set_variant(&C, 1, "x", 0) == KOF_FAMCAT_NO_TYPE && !strcmp(C.var[1].comment, "note"));
	CK(kof_famcat_set_variant(&C, 1, "x", BOT) == KOF_FAMCAT_DUP_TYPES && C.var[1].types == VIR);
	CK(kof_famcat_set_variant(&C, 9, "x", BOT) == KOF_FAMCAT_NO_FAMILY);
}

static void types(void)
{
	uint32_t i, seen = 0;

	CK(kof_famcat_type_count() == (uint32_t)KOF_MALTYPE_COUNT - 1u);
	for (i = 0; i < kof_famcat_type_count(); i++) {
		uint32_t val = kof_famcat_type_value(i);

		CK(val != (uint32_t)KOF_MALTYPE_PACKER && val < (uint32_t)KOF_MALTYPE_COUNT);
		CK(!(seen >> val & 1u));
		seen |= 1u << val;
		CK(kof_famcat_type_name(i) == kof_maltype_name(val));
		CK(strcmp(kof_famcat_type_name(i), "Packer") != 0 && strcmp(kof_famcat_type_name(i), "Malware") != 0);
	}
	CK(seen == kof_famcat_type_mask_all());
	CK(!(kof_famcat_type_mask_all() >> KOF_MALTYPE_PACKER & 1u));
	CK(!strcmp(kof_famcat_type_name(0), "Virus") && !strcmp(kof_famcat_type_name(9), "Hacktool"));
}

static void limits(void)
{
	uint32_t f, v;
	struct kof_famcat_item it[1];

	/* variants: two families need two variants, the third add of a variant to a catalog of 3 slots is refused */
	fresh(8, 3);
	CK(kof_famcat_cap_family(&C) == 8 && kof_famcat_cap_variant(&C) == 3);
	CK(kof_famcat_add_family(&C, "A", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "B", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, &v) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, VIR, 0, &v) == KOF_FAMCAT_FULL);
	CK(kof_famcat_add_family(&C, "C", NULL, BOT, &f) == KOF_FAMCAT_FULL);
	CK(C.n_fam == 2 && C.n_var == 3);
	/* families */
	fresh(2, 16);
	CK(kof_famcat_add_family(&C, "A", NULL, BOT, &f) == KOF_FAMCAT_OK && kof_famcat_add_family(&C, "B", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "C", NULL, BOT, &f) == KOF_FAMCAT_FULL && C.n_fam == 2 && C.n_var == 2);
	/* a catalog with no tables takes nothing */
	kof_famcat_init(&C, NULL, 5, NULL, 5);
	CK(kof_famcat_cap_family(&C) == 0 && kof_famcat_add_family(&C, "A", NULL, BOT, &f) == KOF_FAMCAT_FULL);
	CK(kof_famcat_list(&C, it, 1) == 0);
}

static void order(void)
{
	struct kof_famcat_item it[16];
	uint32_t f, n, i;
	static const char *const want[] = { "A", "A_A", "A_B", "A_C", "B", "B_A", "B_B" };

	fresh(8, 16);
	CK(kof_famcat_add_family(&C, "A", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "B", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);   /* made after B's, shown under A */
	CK(kof_famcat_add_variant(&C, 0, NULL, VIR, 0, NULL) == KOF_FAMCAT_OK);
	n = kof_famcat_list(&C, it, 16);
	CK(n == 7);
	for (i = 0; i < n && i < 7; i++) {
		const char *got = it[i].variant < 0 ? F[it[i].family].name : V[it[i].variant].name;

		CK(!strcmp(got, want[i]));
		CK(it[i].variant < 0 || V[it[i].variant].family == it[i].family);
	}
	/* a short buffer: the total is still returned and nothing is written past it */
	memset(it, 0xee, sizeof it);
	CK(kof_famcat_list(&C, it, 2) == 7);
	CK(it[0].variant == -1 && it[1].variant == 0 && it[2].family == 0xeeeeeeeeu);
	CK(kof_famcat_list(&C, it, 0) == 7);
}

/* The revision: every call that changes the catalog moves it, a refused call and a read do not (the dialog keeps what it derived
 * while the number stands still). */
static void revision(void)
{
	static struct kof_famcat_fam sf[8];
	static struct kof_famcat_var sv[8];
	struct kof_famcat S;
	uint32_t r, v = 0u;

	fresh(8, 8);
	CK(C.rev == 0u);
	r = C.rev;
#define MOVED(call) do { CK((call) == KOF_FAMCAT_OK); CK(C.rev != r); r = C.rev; } while (0)
#define STILL(call, st) do { CK((call) == (st)); CK(C.rev == r); } while (0)
	MOVED(kof_famcat_add_family(&C, "Mirai", "c", 1u << KOF_MALTYPE_BOTNET, NULL));
	STILL(kof_famcat_add_family(&C, "Mirai", "c", 1u << KOF_MALTYPE_BOTNET, NULL), KOF_FAMCAT_DUP_FAMILY);
	MOVED(kof_famcat_add_variant(&C, 0, "", 1u << KOF_MALTYPE_TROJAN, 0, &v));
	STILL(kof_famcat_add_variant(&C, 0, "a*b", 1u << KOF_MALTYPE_VIRUS, 0, NULL), KOF_FAMCAT_BAD_COMMENT);
	MOVED(kof_famcat_set_comment(&C, v, "x"));
	STILL(kof_famcat_set_comment(&C, v, "a*b"), KOF_FAMCAT_BAD_COMMENT);
	MOVED(kof_famcat_set_types(&C, v, 1u << KOF_MALTYPE_VIRUS));
	STILL(kof_famcat_set_types(&C, v, 0u), KOF_FAMCAT_NO_TYPE);
	MOVED(kof_famcat_set_variant(&C, v, "y", 1u << KOF_MALTYPE_ROOTKIT));
	MOVED(kof_famcat_rename_family(&C, 0, "Gafgyt"));
	STILL(kof_famcat_rename_family(&C, 5, "Zed"), KOF_FAMCAT_NO_FAMILY);
	(void)kof_famcat_comment(&C, v);
	(void)kof_famcat_dirty(&C, &C);
	CK(C.rev == r);
	kof_famcat_init(&S, sf, 8, sv, 8);
	CK(kof_famcat_snapshot(&C, &S) == KOF_FAMCAT_OK && S.rev != 0u && C.rev == r);   /* the destination moves, the source does not */
	MOVED(kof_famcat_delete_variant(&C, v));
	MOVED(kof_famcat_restore(&C, &S));
	MOVED(kof_famcat_delete_family(&C, 0));
	STILL(kof_famcat_delete_variant(&C, 9), KOF_FAMCAT_NO_FAMILY);
#undef MOVED
#undef STILL
}

int main(void)
{
	names();
	family();
	variant();
	lettering();
	types();
	limits();
	comments();
	edit();
	order();
	revision();
	printf("famcat: %d failure(s)\n", fails);
	return fails != 0;
}
