/*
 * arch_title - kgenome_arch_title. Oracle: every value of the list has a title that ends in its width, a title is
 * never empty, and OTHER and values outside the list answer NULL. Linked against libkgenome.a alone.
 */
#include <kgenome.h>

#include "hk.h"

static void titles(void)
{
	unsigned a;
	unsigned named = 0;

	CK(strcmp(kgenome_arch_title(KGENOME_ARCH_ARM), "ARM 32-bit") == 0);
	CK(strcmp(kgenome_arch_title(KGENOME_ARCH_ARM64), "AArch64 64-bit") == 0);
	CK(strcmp(kgenome_arch_title(KGENOME_ARCH_X86_64), "x86-64 64-bit") == 0);
	CK(strcmp(kgenome_arch_title(KGENOME_ARCH_ANY), "any") == 0);
	for (a = 0; a < 256; a++) {
		const char *t = kgenome_arch_title((uint8_t)a);
		size_t n = t ? strlen(t) : 0;

		if (!t)
			continue;
		named++;
		CK(n > 0);
		if (a != KGENOME_ARCH_ANY)
			CK(n > 7 && (strcmp(t + n - 6, "32-bit") == 0 || strcmp(t + n - 6, "64-bit") == 0));
	}
	CK(named == KGENOME_ARCH_COUNT);               /* every member of the list, nothing else */
	CK(kgenome_arch_title(KGENOME_ARCH_OTHER) == NULL && kgenome_arch_title(20) == NULL);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	titles();
	printf("arch_title: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
