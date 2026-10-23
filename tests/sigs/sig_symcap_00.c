#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>

/*
 * sig_symcap_00.c - a fixture: a rule that reads the symbol block, so a test can
 * watch what the block's 4096-record cap does to a verdict.
 *
 * It infects an ELF that has a symbol named commit_creds, and nothing else. The
 * rule is the ordinary way a module reads symbols (kof_syms, the canonical
 * reader) and checks nothing but the name - exactly what a heuristic in bases/
 * does - so whether it fires on a file that has the symbol past record 4096 is
 * the question tests/unit/flag_readers.c asks.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, "SymCapTest");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	static const char want[] = "commit_creds";
	uint32_t n = 0, i, k;
	const uint8_t *b = kof_syms(&n), *r;

	for (i = 0; b && (r = kof_sym_rec(b, n, i)) != 0; i++) {
		const char *nm = kof_sym_name(b, n, r, 0);

		for (k = 0; k < sizeof want; k++)
			if (nm[k] != want[k])
				break;
		if (k == sizeof want)
			{ kof_debug("SymCapTest#00", 0); return; }
	}
}
