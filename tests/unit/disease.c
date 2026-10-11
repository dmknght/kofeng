/*
 * disease - what a well-formed disease is, decided in one place for the diagnose
 * reader, the syndrome reader and the engine that compares the two.
 */
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/detectors/pathogen/diseases/kofdisease.h"

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
	if (failures) {
		printf("disease: %d failure(s)\n", failures);
		return 1;
	}
	printf("disease: one spelling rule for every reader, the longest allowed and "
	       "one past it - ok\n");
	return 0;
}
