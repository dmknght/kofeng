#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>

/*
 * sig_pe_syms_00.c - a fixture: a rule that reads a PE's symbol block, which is what
 * makes the engine walk the import and export directories (oc_pe_imports, sym_build).
 * tests/unit/status_routes.c scans hostile directories with it and reads what the
 * verdict path said about the object. It never reports.
 */

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, "PeSymProbeTest");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	uint32_t n = 0;
	const uint8_t *b = kof_syms(&n);

	(void)ctx;
	if (b && n == 0xfffffffeu)      /* never: the call is what the fixture is for */
		{ kof_debug("PeSymProbeTest#00", 0); return; }
}
