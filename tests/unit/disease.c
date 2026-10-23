/*
 * disease - what a well-formed disease is, decided in one place for the diagnose
 * reader, the detectors that declare one and the engine that compares the two.
 */
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/analyzers/diseases/kofdisease.h"
#include <kofmod/kofsig.h>

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

int main(void)
{
	char longest[KOF_DIAG_DISEASE_LEN + 2u];

	check(!kof_disease_check("cnc/recv-syscall"), "a layer/behaviour path is well formed");
	check(!kof_disease_check("kernel"), "a layer alone is well formed");
	check(!kof_disease_check("a_b-c/d9"), "digits, - and _ are allowed");
	check(kof_disease_check("") != NULL, "empty is refused");
	check(kof_disease_check("Cnc/recv") != NULL, "upper case is refused");
	check(kof_disease_check("cnc recv") != NULL, "a space is refused");
	check(kof_disease_check("/recv") != NULL, "a leading slash is refused");
	check(kof_disease_check("recv/") != NULL, "a trailing slash is refused");
	check(kof_disease_check("cnc//recv") != NULL, "a doubled slash is refused");
	memset(longest, 'a', sizeof longest);
	longest[KOF_DIAG_DISEASE_LEN] = 0;
	check(!kof_disease_check(longest), "the longest allowed is accepted");
	longest[KOF_DIAG_DISEASE_LEN] = 'a';
	longest[KOF_DIAG_DISEASE_LEN + 1u] = 0;
	check(kof_disease_check(longest) != NULL, "one more is refused");
	check(kof_disease_id("cnc/recv") == kof_disease_id("cnc/recv"), "an id is a function of the name");
	check(kof_disease_id("cnc/recv") != kof_disease_id("cnc/send"), "different names, different ids");
	check(kof_disease_id("") != 0 && kof_disease_id("a") != 0, "zero is never an id");
	/* the declaration: read, written, read back */
	{
		struct kof_disease_decl d, e;
		char line[160];
		const char *src = "KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"flood-network/raw-header\");";

		check(!kof_disease_decl_parse(src, &d), "a declaration is read");
		check(d.type == KOF_MALTYPE_BOTNET && !strcmp(d.name, "flood-network/raw-header"),
		      "with its type and its name");
		check(kof_disease_decl_print(&d, line, sizeof line) == strlen(src) && !strcmp(line, src),
		      "written as it was read");
		check(!kof_disease_decl_parse(line, &e) && kof_disease_decl_same(&d, &e),
		      "and read back the same");
		check(!kof_disease_decl_parse("KOF_DECLARE_DISEASE(\n\tKOF_MALTYPE_MINER,\n\t\"a/b\"\n);", &e) &&
		      e.type == KOF_MALTYPE_MINER, "a declaration wrapped over lines is read");
		check(!kof_disease_decl_same(&d, &e), "different declarations are not the same");
		check(kof_disease_decl_parse("KOF_DECLARE_DISEASE(KOF_MALTYPE_NOPE, \"a/b\")", &e) != NULL,
		      "an unknown type is refused");
		check(kof_disease_decl_parse("KOF_DECLARE_DISEASE(\"a/b\")", &e) != NULL, "a missing type is refused");
		check(kof_disease_decl_parse("KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, a/b)", &e) != NULL,
		      "an unquoted name is refused");
		check(kof_disease_decl_parse("KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"A/b\")", &e) != NULL,
		      "a name that is not well formed is refused");
		check(kof_disease_decl_parse("KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"a/b\", 1)", &e) != NULL,
		      "a third argument is refused");
		check(kof_disease_decl_parse("KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"a/b\"", &e) != NULL,
		      "an unclosed declaration is refused");
		d.type = (uint8_t)KOF_MALTYPE_COUNT;
		check(kof_disease_decl_print(&d, line, sizeof line) == 0, "a type that is no maltype is not written");
	}
	if (failures) {
		printf("disease: %d failure(s)\n", failures);
		return 1;
	}
	printf("disease: one spelling rule for every reader, the longest allowed and "
	       "one past it - ok\n");
	return 0;
}
