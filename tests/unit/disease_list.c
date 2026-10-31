/*
 * disease_list - kofmod/diseaselist.h: the two lists of the new disease (ACT, OBJ). Oracle: the words are written out here by hand,
 * the counts are fixed, the round trip name <-> value holds for every value, a word is a whole word, a value outside the list says "none".
 */
#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>

static int fails;
#define CK(c) do { if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static const char *const act_words[] = { "scan", "steal", "execution", "persistence", "escalation", "evasion", "hidden", "c2",
					  "destruction" };
static const char *const act_shown[] = { "Scan", "Steal", "Execution", "Persistence", "Escalation", "Evasion", "Hidden", "C2",
					 "Destruction" };
static const char *const obj_words[] = { "network", "file", "memory", "process", "registry", "kernel", "system", "input" };

static int word_ok(const char *w)
{
	size_t i;

	if (!w[0])
		return 0;
	for (i = 0; w[i]; i++)
		if (!((w[i] >= 'a' && w[i] <= 'z') || (w[i] >= '0' && w[i] <= '9') || w[i] == '-'))
			return 0;
	return w[0] != '-' && w[i - 1] != '-';
}

int main(void)
{
	unsigned i, j;
	uint8_t v = 0;

	CK(KOF_DISEASE_ACT_COUNT == 10u && KOF_DISEASE_OBJ_COUNT == 9u);        /* 9 activities and 8 objects, value 0 is NONE */
	CK(KOF_DISEASE_ACT_COUNT == 1u + sizeof act_words / sizeof act_words[0]);
	CK(KOF_DISEASE_OBJ_COUNT == 1u + sizeof obj_words / sizeof obj_words[0]);
	CK(KOF_DISEASE_ACT_NONE == 0 && KOF_DISEASE_OBJ_NONE == 0);
	for (i = 1; i < KOF_DISEASE_ACT_COUNT; i++) {
		const char *w = kof_disease_act_name(i);

		CK(strcmp(w, act_words[i - 1]) == 0);
		CK(word_ok(w));
		CK(kof_disease_act_from_name(w, &v) && v == i);
		for (j = i + 1; j < KOF_DISEASE_ACT_COUNT; j++)
			CK(strcmp(w, kof_disease_act_name(j)) != 0);
	}
	for (i = 1; i < KOF_DISEASE_OBJ_COUNT; i++) {
		const char *w = kof_disease_obj_name(i);

		CK(strcmp(w, obj_words[i - 1]) == 0);
		CK(word_ok(w));
		CK(kof_disease_obj_from_name(w, &v) && v == i);
		for (j = i + 1; j < KOF_DISEASE_OBJ_COUNT; j++)
			CK(strcmp(w, kof_disease_obj_name(j)) != 0);
	}
	/* NONE and values from outside the list */
	CK(strcmp(kof_disease_act_name(0), "none") == 0 && strcmp(kof_disease_obj_name(0), "none") == 0);
	CK(strcmp(kof_disease_act_name(KOF_DISEASE_ACT_COUNT), "none") == 0 && strcmp(kof_disease_obj_name(255), "none") == 0);
	CK(strcmp(kof_disease_act_name(0xffffffffu), "none") == 0);
	/* a whole word: a prefix, a longer word, the empty word, another case and the other list's word are refused */
	CK(!kof_disease_act_from_name("sca", &v) && !kof_disease_act_from_name("scans", &v) && !kof_disease_act_from_name("", &v));
	CK(!kof_disease_act_from_name("brute-force", &v) && !kof_disease_act_from_name("flood", &v) &&
	   !kof_disease_act_from_name("privilege-escalation", &v) && kof_disease_act_from_name("escalation", &v) &&
	   v == KOF_DISEASE_ACT_ESCALATION && kof_disease_act_from_name("destruction", &v) && v == KOF_DISEASE_ACT_DESTRUCTION);
	CK(!kof_disease_act_from_name("Scan", &v) && !kof_disease_act_from_name("network", &v) && !kof_disease_act_from_name("none", &v));
	CK(!kof_disease_obj_from_name("fil", &v) && !kof_disease_obj_from_name("files", &v) && !kof_disease_obj_from_name("scan", &v));
	CK(!kof_disease_obj_from_name("Network", &v) && !kof_disease_obj_from_name("none", &v));
	/* the display of a word: first letter upper case, a word with a digit upper-cased whole, the hyphen kept, the stored word untouched */
	{
		char b[16];

		for (i = 1; i < KOF_DISEASE_ACT_COUNT; i++)
			CK(kof_disease_display(kof_disease_act_name(i), b, sizeof b) == strlen(act_shown[i - 1]) && !strcmp(b, act_shown[i - 1]));
		CK(kof_disease_display("network", b, sizeof b) == 7 && !strcmp(b, "Network"));
		CK(kof_disease_display("c2", b, sizeof b) == 2 && !strcmp(b, "C2"));
		CK(kof_disease_display("a1-b", b, sizeof b) == 4 && !strcmp(b, "A1-B"));
		CK(kof_disease_display("two-words", b, sizeof b) == 9 && !strcmp(b, "Two-words"));
		CK(kof_disease_display("", b, sizeof b) == 0 && b[0] == 0 && kof_disease_display(NULL, b, sizeof b) == 0 && b[0] == 0);
		CK(kof_disease_display("Scan", b, sizeof b) == 4 && !strcmp(b, "Scan"));
		CK(kof_disease_display("destruction", b, 4) == 3 && !strcmp(b, "Des"));          /* cut and terminated */
		CK(kof_disease_display("scan", b, 1) == 0 && b[0] == 0 && kof_disease_display("scan", b, 0) == 0);
		CK(!strcmp(kof_disease_act_name(KOF_DISEASE_ACT_C2), "c2"));
	}
	printf("disease_list: %d failure(s)\n", fails);
	return fails != 0;
}
