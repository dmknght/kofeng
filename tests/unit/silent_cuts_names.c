/*
 * silent_cuts_names - a name the symbol block cut says so on the record.
 *
 * The block spells a PE import "dll!func" and keeps at most DLL_ROOM (16) bytes of the module
 * name; a longer one - every "api-ms-win-core-...-l1-2-0.dll" - was cut with the record's cut
 * byte (kof_sym_name_cut, KOF_SYM_R_NAMECUT) at zero, so a rule comparing against the whole
 * module name saw a mismatch that looked like "the program does not import it". The record
 * now says the name was cut. The function part keeps its own bound (KOF_SYM_NAME_MAX) and its
 * own report, tested by caps_syms.c.
 *
 * Control: the ordinary module names of the same object are not marked.
 */

#define _GNU_SOURCE

#include "../lib/genome/hk.h"
#include <genotype/image/pe_image.h>
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"

static struct hk_pe P;

static const uint8_t *find(const uint8_t *b, uint32_t n, const char *needle, uint32_t *cut)
{
	uint32_t i, l;
	const uint8_t *r;

	for (i = 0; (r = kof_sym_rec(b, n, i)) != NULL; i++) {
		const char *nm = kof_sym_name(b, n, r, &l);

		if (strstr(nm, needle)) {
			*cut = (uint32_t)kof_sym_name_cut(r);
			return r;
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	static uint8_t blk[1u << 16];
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	uint32_t n, cut = 9;
	uint8_t *at;

	hk_args(argc, argv);
	hk_pe(&P, 1);
	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	n = kof_pe_syms(kof_buf_make(P.b, P.n), &pi, blk, sizeof blk);
	CK(find(blk, n, "ExitProcess", &cut) != NULL && cut == 0u);     /* the control */
	CK(find(blk, n, "MessageBoxA", &cut) != NULL && cut == 0u);

	/* the second descriptor's module becomes a name longer than the 16 the block keeps */
	at = (uint8_t *)memmem(P.b, P.n, "user32.dll", 11);
	CK(at != NULL);
	if (at)
		memcpy(at, "api-ms-win-core-synch-l1-2-0.dll", 33);
	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	n = kof_pe_syms(kof_buf_make(P.b, P.n), &pi, blk, sizeof blk);
	CK(find(blk, n, "MessageBoxA", &cut) != NULL);
	CK(cut == 1u);                                                  /* before: 0, the cut was silent */
	CK(find(blk, n, "ExitProcess", &cut) != NULL && cut == 0u);     /* kernel32 is untouched */
	printf("silent_cuts_names: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
