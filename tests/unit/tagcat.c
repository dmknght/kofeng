/*
 * tagcat - the tag catalog (libkofeng/verdictor/tagcat.c): a name, a set of activities (at least one), a set of objects (optional).
 *
 *   NAMES     valid, empty, NULL, 63 and 64 characters, every byte value against the tag rule (lower-case letters, digits and '-' only)
 *   DUPLICATE the same name ignoring letter case is refused by add, rename and edit; a tag may keep its own name or change only its case
 *   SETS      no activity is refused (NO_ACTIVITY), objects are optional, a bit outside either list is refused, every value of both lists
 *             is accepted alone; the lists are the engine's (diseaselist.h) in the engine's order and words
 *   CHANGE    rename, set_acts and set_objs change one thing, edit changes the three or none; a refused call changes nothing
 *   DELETE    the others keep their creation order and shift down; a bad index is refused
 *   REVISION  every successful change bumps it, a refusal does not
 *   LIMITS    the caller's table: the add past it answers KOF_TAGCAT_FULL and nothing is dropped; a NULL table holds nothing
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/verdictor/tagcat.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static struct kof_tagcat_tag T[8];
static struct kof_tagcat C;

#define SCAN (1u << KOF_DISEASE_ACT_SCAN)
#define STEAL (1u << KOF_DISEASE_ACT_STEAL)
#define NET (1u << KOF_DISEASE_OBJ_NETWORK)
#define FILE_ (1u << KOF_DISEASE_OBJ_FILE)

static void fresh(uint32_t cap)
{
	memset(T, 0, sizeof T);
	kof_tagcat_init(&C, T, cap);
}

static void names(void)
{
	char s[128];
	int b, ok = 0;

	CK(kof_tagcat_name_check("recon") == KOF_TAGCAT_OK);
	CK(kof_tagcat_name_check("a-b9") == KOF_TAGCAT_OK && kof_tagcat_name_check("0-z") == KOF_TAGCAT_OK);
	/* upper case is a name character now (owner, 2026-10-28); space, '_' and '.' are still refused, with the status that says "character" */
	CK(kof_tagcat_name_check("Recon") == KOF_TAGCAT_OK && kof_tagcat_name_check("reCon") == KOF_TAGCAT_OK &&
	   kof_tagcat_name_check("A") == KOF_TAGCAT_OK && kof_tagcat_name_check("C2-Beacon") == KOF_TAGCAT_OK &&
	   kof_tagcat_name_check("a_b") == KOF_TAGCAT_BAD_CHAR && kof_tagcat_name_check("a b") == KOF_TAGCAT_BAD_CHAR &&
	   kof_tagcat_name_check("a.b") == KOF_TAGCAT_BAD_CHAR);
	CK(kof_tag_name_ok("abc-9") && kof_tag_name_ok("Abc") && !kof_tag_name_ok("") && !kof_tag_name_ok(NULL) && !kof_tag_name_ok("a_b"));
	CK(kof_tag_name_char('a') && kof_tag_name_char('z') && kof_tag_name_char('0') && kof_tag_name_char('9') && kof_tag_name_char('-') &&
	   kof_tag_name_char('A') && kof_tag_name_char('Z') && !kof_tag_name_char('_') && !kof_tag_name_char(' ') && !kof_tag_name_char('.') &&
	   !kof_tag_name_char('`') && !kof_tag_name_char('{') && !kof_tag_name_char('/') && !kof_tag_name_char(':') &&
	   !kof_tag_name_char('@') && !kof_tag_name_char('[') && !kof_tag_name_char('\0'));
	CK(strstr(kof_tagcat_status_text(KOF_TAGCAT_BAD_CHAR), "letters, digits and - only") != NULL);
	CK(kof_tagcat_name_check("") == KOF_TAGCAT_EMPTY && kof_tagcat_name_check(NULL) == KOF_TAGCAT_EMPTY);
	CK(KOF_TAGCAT_NAME_MAX == 63u);
	memset(s, 'a', 63);
	s[63] = 0;
	CK(kof_tagcat_name_check(s) == KOF_TAGCAT_OK);
	s[63] = 'a';
	s[64] = 0;
	CK(kof_tagcat_name_check(s) == KOF_TAGCAT_TOO_LONG);
	CK(kof_tagcat_name_check("a.b") == KOF_TAGCAT_BAD_CHAR && kof_tagcat_name_check("a b") == KOF_TAGCAT_BAD_CHAR &&
	   kof_tagcat_name_check("a/b") == KOF_TAGCAT_BAD_CHAR && kof_tagcat_name_check("..") == KOF_TAGCAT_BAD_CHAR);
	/* every byte value alone: the verdict is the engine's kof_name_ok */
	for (b = 1; b < 256; b++) {
		s[0] = (char)b;
		s[1] = 0;
		CK((kof_tagcat_name_check(s) == KOF_TAGCAT_OK) == (kof_tag_name_ok(s) != 0));
		ok += kof_tagcat_name_check(s) == KOF_TAGCAT_OK;
	}
	CK(ok == 26 + 26 + 10 + 1);       /* a-z, A-Z, 0-9 and the hyphen */
	/* add refuses the same names and says the same status */
	fresh(8);
	CK(kof_tagcat_add(&C, "", SCAN, 0, NULL) == KOF_TAGCAT_EMPTY && kof_tagcat_add(&C, "a b", SCAN, 0, NULL) == KOF_TAGCAT_BAD_CHAR);
	memset(s, 'a', 64);
	s[64] = 0;
	CK(kof_tagcat_add(&C, s, SCAN, 0, NULL) == KOF_TAGCAT_TOO_LONG);
	s[63] = 0;
	CK(kof_tagcat_add(&C, s, SCAN, 0, NULL) == KOF_TAGCAT_OK && C.n == 1u);
}

static void sets(void)
{
	uint32_t i, idx = 99;

	fresh(8);
	CK(kof_tagcat_act_count() == (uint32_t)KOF_DISEASE_ACT_COUNT - 1u && kof_tagcat_obj_count() == (uint32_t)KOF_DISEASE_OBJ_COUNT - 1u);
	CK(kof_tagcat_act_count() == 9u && kof_tagcat_obj_count() == 8u);
	for (i = 0; i < kof_tagcat_act_count(); i++)
		CK(kof_tagcat_act_value(i) == i + 1u && !strcmp(kof_tagcat_act_name(i), kof_disease_act_name(i + 1u)) &&
		   strcmp(kof_tagcat_act_name(i), "none") != 0);
	for (i = 0; i < kof_tagcat_obj_count(); i++)
		CK(kof_tagcat_obj_value(i) == i + 1u && !strcmp(kof_tagcat_obj_name(i), kof_disease_obj_name(i + 1u)) &&
		   strcmp(kof_tagcat_obj_name(i), "none") != 0);
	/* no activity: refused, with or without objects; objects are optional */
	CK(kof_tagcat_add(&C, "t", 0, 0, NULL) == KOF_TAGCAT_NO_ACTIVITY);
	CK(kof_tagcat_add(&C, "t", 0, NET, NULL) == KOF_TAGCAT_NO_ACTIVITY && C.n == 0u && C.rev == 0u);
	CK(kof_tagcat_add(&C, "t", SCAN, 0, &idx) == KOF_TAGCAT_OK && idx == 0u && C.tag[0].objs == 0u);
	CK(kof_tagcat_add(&C, "u", SCAN | STEAL, NET | FILE_, &idx) == KOF_TAGCAT_OK && idx == 1u);
	/* a bit outside the list: NONE (bit 0), one past the list, the high bits */
	CK(kof_tagcat_add(&C, "v", 1u, 0, NULL) == KOF_TAGCAT_BAD_ACTIVITY);
	CK(kof_tagcat_add(&C, "v", 1u << kof_tagcat_act_count() << 1, 0, NULL) == KOF_TAGCAT_BAD_ACTIVITY);
	CK(kof_tagcat_add(&C, "v", SCAN | 0x80000000u, 0, NULL) == KOF_TAGCAT_BAD_ACTIVITY);
	CK(kof_tagcat_add(&C, "v", SCAN, 1u, NULL) == KOF_TAGCAT_BAD_OBJECT);
	CK(kof_tagcat_add(&C, "v", SCAN, 1u << (kof_tagcat_obj_count() + 1u), NULL) == KOF_TAGCAT_BAD_OBJECT);
	CK(C.n == 2u);
	CK(kof_tagcat_act_mask_all() == 0x3FEu && kof_tagcat_obj_mask_all() == 0x1FEu);
	/* every value of both lists alone is accepted */
	fresh(8);
	for (i = 0; i < kof_tagcat_act_count(); i++) {
		C.n = 0;
		CK(kof_tagcat_add(&C, "x", 1u << kof_tagcat_act_value(i), 0, NULL) == KOF_TAGCAT_OK);
	}
	for (i = 0; i < kof_tagcat_obj_count(); i++) {
		C.n = 0;
		CK(kof_tagcat_add(&C, "x", SCAN, 1u << kof_tagcat_obj_value(i), NULL) == KOF_TAGCAT_OK);
	}
}

static void duplicates(void)
{
	fresh(8);
	CK(kof_tagcat_add(&C, "recon", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "recon", SCAN, 0, NULL) == KOF_TAGCAT_DUPLICATE);
	CK(kof_tagcat_add(&C, "recon", STEAL, NET, NULL) == KOF_TAGCAT_DUPLICATE && C.n == 1u);
	CK(kof_tagcat_add(&C, "recon2", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_rename(&C, 1, "recon") == KOF_TAGCAT_DUPLICATE && !strcmp(C.tag[1].name, "recon2"));
	CK(kof_tagcat_rename(&C, 1, "recon2") == KOF_TAGCAT_OK);                 /* its own name is not a duplicate */
	CK(kof_tagcat_edit(&C, 0, "recon2", SCAN, 0) == KOF_TAGCAT_DUPLICATE);
	/* the comparison ignores letter case, whichever side holds the capitals */
	CK(kof_tagcat_add(&C, "RECON", SCAN, 0, NULL) == KOF_TAGCAT_DUPLICATE && kof_tagcat_add(&C, "Recon2", SCAN, 0, NULL) == KOF_TAGCAT_DUPLICATE);
	memcpy(C.tag[0].name, "Recon", 6);
	CK(kof_tagcat_add(&C, "recon", SCAN, 0, NULL) == KOF_TAGCAT_DUPLICATE);
	CK(kof_tagcat_rename(&C, 1, "recon") == KOF_TAGCAT_DUPLICATE);
	/* a tag may change only the case of its own name; the lookup by name ignores case (the id is made from the folded name) and a rename is not a clash with itself */
	CK(kof_tagcat_rename(&C, 0, "RECON") == KOF_TAGCAT_OK && !strcmp(C.tag[0].name, "RECON") && kof_tagcat_id(&C, "recon") != 0u &&
	   kof_tagcat_id(&C, "recon") == kof_tagcat_id(&C, "RECON"));
}

/* The comment: one rule for add/edit/set, bounded by the shared constant, part of dirty/snapshot/restore. */
static void comments(void)
{
	static struct kof_tagcat_tag S0[8];
	struct kof_tagcat S;
	struct kof_tagcat_fields f = { "a", "why it exists", SCAN, 0 };
	char big[KOF_TAGCAT_COMMENT_MAX + 2];
	int b;

	CK(KOF_TAGCAT_COMMENT_MAX == 120 && KOF_TAGCAT_COMMENT_MAX == KOF_CATSTORE_COMMENT_MAX);
	fresh(8);
	kof_tagcat_init(&S, S0, 8);
	CK(kof_tagcat_add_fields(&C, &f, NULL) == KOF_TAGCAT_OK && !strcmp(kof_tagcat_comment(&C, 0), "why it exists"));
	CK(kof_tagcat_comment(&C, 5)[0] == 0);
	CK(kof_tagcat_add(&C, "b", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_comment(&C, 1)[0] == 0);   /* add has none */
	/* edit and the single changes keep the comment */
	CK(kof_tagcat_edit(&C, 0, "a2", STEAL, NET) == KOF_TAGCAT_OK && !strcmp(kof_tagcat_comment(&C, 0), "why it exists"));
	CK(kof_tagcat_rename(&C, 0, "a") == KOF_TAGCAT_OK && kof_tagcat_set_acts(&C, 0, SCAN) == KOF_TAGCAT_OK &&
	   !strcmp(kof_tagcat_comment(&C, 0), "why it exists"));
	/* the comment rule: every byte alone (kof_comment_char), the bound, nothing changes on a refusal */
	for (b = 1; b < 256; b++) {
		char one[2] = { (char)b, 0 };

		CK((kof_tagcat_comment_check(one) == KOF_TAGCAT_OK) == (kof_comment_char(b) != 0));
	}
	CK(kof_tagcat_comment_check(NULL) == KOF_TAGCAT_OK && kof_tagcat_comment_check("") == KOF_TAGCAT_OK);
	memset(big, 'x', sizeof big);
	big[KOF_TAGCAT_COMMENT_MAX] = 0;
	CK(kof_tagcat_comment_check(big) == KOF_TAGCAT_OK);
	big[KOF_TAGCAT_COMMENT_MAX] = 'x';
	big[KOF_TAGCAT_COMMENT_MAX + 1] = 0;
	CK(kof_tagcat_comment_check(big) == KOF_TAGCAT_COMMENT_TOO_LONG);
	{
		uint32_t rev = C.rev;

		CK(kof_tagcat_set_comment(&C, 0, big) == KOF_TAGCAT_COMMENT_TOO_LONG && kof_tagcat_set_comment(&C, 0, "a/b") == KOF_TAGCAT_BAD_COMMENT &&
		   kof_tagcat_set_comment(&C, 0, "a*b") == KOF_TAGCAT_BAD_COMMENT && C.rev == rev && !strcmp(kof_tagcat_comment(&C, 0), "why it exists"));
		f.name = "z";
		f.comment = "a\nb";
		CK(kof_tagcat_add_fields(&C, &f, NULL) == KOF_TAGCAT_BAD_COMMENT && kof_tagcat_edit_fields(&C, 0, &f) == KOF_TAGCAT_BAD_COMMENT && C.n == 2u);
	}
	CK(kof_tagcat_set_comment(&C, 9, "x") == KOF_TAGCAT_NO_TAG);
	/* dirty, snapshot, restore carry it */
	CK(kof_tagcat_snapshot(&C, &S) == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_set_comment(&C, 0, "changed") == KOF_TAGCAT_OK && kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_restore(&C, &S) == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S) && !strcmp(kof_tagcat_comment(&C, 0), "why it exists"));
	CK(kof_tagcat_set_comment(&C, 0, "") == KOF_TAGCAT_OK && kof_tagcat_dirty(&C, &S));
}

static void change(void)
{
	uint32_t rev;

	fresh(8);
	CK(kof_tagcat_add(&C, "a", SCAN, NET, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "b", STEAL, 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_rename(&C, 0, "c") == KOF_TAGCAT_OK && !strcmp(C.tag[0].name, "c") && C.tag[0].acts == SCAN && C.tag[0].objs == NET);
	CK(kof_tagcat_set_acts(&C, 0, STEAL | SCAN) == KOF_TAGCAT_OK && C.tag[0].acts == (STEAL | SCAN) && C.tag[0].objs == NET &&
	   !strcmp(C.tag[0].name, "c"));
	CK(kof_tagcat_set_objs(&C, 0, 0) == KOF_TAGCAT_OK && C.tag[0].objs == 0u && C.tag[0].acts == (STEAL | SCAN));
	CK(kof_tagcat_set_objs(&C, 0, FILE_ | NET) == KOF_TAGCAT_OK && C.tag[0].objs == (FILE_ | NET));
	/* the last activity cannot be taken away; nothing moves */
	rev = C.rev;
	CK(kof_tagcat_set_acts(&C, 1, 0) == KOF_TAGCAT_NO_ACTIVITY && C.tag[1].acts == STEAL && C.rev == rev);
	CK(kof_tagcat_set_acts(&C, 1, 1u) == KOF_TAGCAT_BAD_ACTIVITY && C.tag[1].acts == STEAL);
	CK(kof_tagcat_set_objs(&C, 1, 1u) == KOF_TAGCAT_BAD_OBJECT && C.tag[1].objs == 0u);
	/* edit: all three, or none (a bad set after a good name leaves the old name) */
	CK(kof_tagcat_edit(&C, 1, "d", SCAN, NET) == KOF_TAGCAT_OK && !strcmp(C.tag[1].name, "d") && C.tag[1].acts == SCAN && C.tag[1].objs == NET);
	CK(kof_tagcat_edit(&C, 1, "e", 0, NET) == KOF_TAGCAT_NO_ACTIVITY && !strcmp(C.tag[1].name, "d"));
	CK(kof_tagcat_edit(&C, 1, "e f", SCAN, NET) == KOF_TAGCAT_BAD_CHAR && !strcmp(C.tag[1].name, "d"));
	/* a bad index */
	CK(kof_tagcat_rename(&C, 2, "x") == KOF_TAGCAT_NO_TAG && kof_tagcat_set_acts(&C, 9, SCAN) == KOF_TAGCAT_NO_TAG &&
	   kof_tagcat_set_objs(&C, 9, 0) == KOF_TAGCAT_NO_TAG && kof_tagcat_edit(&C, 2, "x", SCAN, 0) == KOF_TAGCAT_NO_TAG &&
	   kof_tagcat_delete(&C, 2) == KOF_TAGCAT_NO_TAG);
	CK(kof_tagcat_get(&C, 0) == &C.tag[0] && kof_tagcat_get(&C, 2) == NULL);
}

static void order_and_delete(void)
{
	fresh(8);
	CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "b", SCAN, 0, NULL) == KOF_TAGCAT_OK &&
	   kof_tagcat_add(&C, "c", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	CK(!strcmp(kof_tagcat_get(&C, 0)->name, "a") && !strcmp(kof_tagcat_get(&C, 1)->name, "b") && !strcmp(kof_tagcat_get(&C, 2)->name, "c"));
	CK(kof_tagcat_delete(&C, 1) == KOF_TAGCAT_OK && C.n == 2u && !strcmp(C.tag[0].name, "a") && !strcmp(C.tag[1].name, "c"));
	CK(kof_tagcat_add(&C, "b", SCAN, 0, NULL) == KOF_TAGCAT_OK && !strcmp(C.tag[2].name, "b"));   /* a deleted name is free again */
	CK(kof_tagcat_delete(&C, 0) == KOF_TAGCAT_OK && !strcmp(C.tag[0].name, "c") && !strcmp(C.tag[1].name, "b") && C.n == 2u);
	CK(kof_tagcat_delete(&C, 1) == KOF_TAGCAT_OK && kof_tagcat_delete(&C, 0) == KOF_TAGCAT_OK && C.n == 0u);
}

static void revision(void)
{
	uint32_t r;

	fresh(2);
	CK(C.rev == 0u);
	CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK && C.rev == 1u);
	CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_DUPLICATE && C.rev == 1u);
	CK(kof_tagcat_rename(&C, 0, "b") == KOF_TAGCAT_OK && C.rev == 2u);
	CK(kof_tagcat_set_acts(&C, 0, STEAL) == KOF_TAGCAT_OK && C.rev == 3u);
	CK(kof_tagcat_set_objs(&C, 0, NET) == KOF_TAGCAT_OK && C.rev == 4u);
	CK(kof_tagcat_edit(&C, 0, "b", STEAL, NET) == KOF_TAGCAT_OK && C.rev == 5u);   /* an unchanged value is still a change call */
	r = C.rev;
	CK(kof_tagcat_set_acts(&C, 0, 0) != KOF_TAGCAT_OK && kof_tagcat_delete(&C, 5) != KOF_TAGCAT_OK && C.rev == r);
	CK(kof_tagcat_delete(&C, 0) == KOF_TAGCAT_OK && C.rev == r + 1u);
}

static void limits(void)
{
	char nm[8];
	struct kof_tagcat none;

	fresh(2);
	CK(kof_tagcat_cap(&C) == 2u);
	CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "b", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "c", SCAN, 0, NULL) == KOF_TAGCAT_FULL && C.n == 2u && !strcmp(C.tag[1].name, "b"));
	/* the name and set rules are answered before FULL, and a delete makes room */
	CK(kof_tagcat_add(&C, "", SCAN, 0, NULL) == KOF_TAGCAT_EMPTY && kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_DUPLICATE);
	CK(kof_tagcat_delete(&C, 0) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "c", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	/* a long list of tags up to the cap, then FULL */
	fresh(8);
	{
		uint32_t i;

		for (i = 0; i < 8; i++) {
			snprintf(nm, sizeof nm, "t%u", (unsigned)i);
			CK(kof_tagcat_add(&C, nm, SCAN, 0, NULL) == KOF_TAGCAT_OK);
		}
		CK(kof_tagcat_add(&C, "t8", SCAN, 0, NULL) == KOF_TAGCAT_FULL && C.n == 8u);
	}
	kof_tagcat_init(&none, NULL, 5);
	CK(kof_tagcat_cap(&none) == 0u && kof_tagcat_add(&none, "a", SCAN, 0, NULL) == KOF_TAGCAT_FULL);
	/* every status has its own text */
	{
		int a, b;

		for (a = 0; a <= (int)KOF_TAGCAT_NO_TAG; a++) {
			CK(strcmp(kof_tagcat_status_text((enum kof_tagcat_status)a), "unknown status") != 0);
			for (b = a + 1; b <= (int)KOF_TAGCAT_NO_TAG; b++)
				CK(strcmp(kof_tagcat_status_text((enum kof_tagcat_status)a), kof_tagcat_status_text((enum kof_tagcat_status)b)) != 0);
		}
	}
}

int main(void)
{
	names();
	sets();
	duplicates();
	comments();
	change();
	order_and_delete();
	revision();
	limits();
	printf("tagcat: %d failure(s)\n", fails);
	return fails != 0;
}
