/*
 * emu_ctype - the guest-name checks of the Windows environment do not follow the host's locale
 * (S2-CTYPE-a: kgenome_emu_win_resolve, S2-CTYPE-b: the modelled-library key). A guest name is bytes of
 * the sample, so what is a letter in it is ASCII and the same on every host.
 *
 * Old tests missed it: (b) nothing ever ran with a locale other than "C", and the engine never calls
 * setlocale; a host that does (a viewer, a tool) changed which names were imports. This test enters a
 * single-byte locale when the machine has one, and says SKIPPED (not ok) when it has none.
 */
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#include <phenotype/emu_private.h>

static int fails;
#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

int main(void)
{
	static const char *const loc[] = { "en_US.ISO-8859-1", "en_US.iso88591", "de_DE.ISO-8859-1", "de_DE", "fr_FR", "en_AG", "en_AU", "en_CA", "en_DK" };
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned i;
	int have = 0;

	for (i = 0; i < sizeof loc / sizeof loc[0] && !have; i++)
		if (setlocale(LC_CTYPE, loc[i])) {
			/* a locale that makes 0xE9 a letter, or it is no use here */
			have = isalpha(0xe9) != 0;
		}
	memset(&cfg, 0, sizeof cfg);
	cfg.bits = 32;
	cfg.max_insn = 1000;
	e = kgenome_emu_new(&cfg);
	if (!e) {
		printf("emu_ctype: out of memory\n");
		return 1;
	}
	/* in every locale: a name with a byte of 0x80 or more is no import and no library key */
	CK(kgenome_emu_win_resolve(e, "caf\xe9x") == 0, "an import name with 0xE9 is refused (locale %s)", have ? "single-byte" : "C");
	CK(kgenome_emu_win_resolve(e, "\xe9" "abc") == 0, "an import name that starts with 0xE9 is refused");
	CK(kgenome_emu_win_fake_lib(e, "caf\xe9x.dll") == 0, "a library name with 0xE9 is no modelled library");
	CK(kgenome_emu_win_resolve(e, "SomeImportName") != 0, "an ASCII import name is still given a miss thunk");
	CK(kgenome_emu_win_fake_lib(e, "COMCTL32.DLL") != 0 && kgenome_emu_win_fake_find(e, "comctl32") != 0,
	   "an ASCII library name still keys case-insensitively");
	kgenome_emu_free(e);
	if (fails) {
		printf("emu_ctype: %d check(s) failed\n", fails);
		return 1;
	}
	printf("emu_ctype: %s\n", have ? "ok (single-byte locale entered)" : "SKIPPED the locale half: no single-byte locale on this machine (the C-locale half ran)");
	return 0;
}
