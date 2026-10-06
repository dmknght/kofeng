#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * sig_diag_rwx_00.c - the one thing that reads the rwx_exec fixture diagnose.
 *
 * WHY IT EXISTS. tests/unit/diag_db.c proves the chain from a diagnose
 * SOURCE file to a scan result: ksigbuilder reads the macros as text,
 * kof_diag_load reads the .kdig back, the loader gives it an id, the scanner
 * runs the walk on demand. Every one of those is a place where a capability
 * id or a parent index turns a working diagnose into silence.
 *
 * The test used to watch that chain through kof_result.diag, a listing of
 * which diagnoses an object carried. That listing is gone - a diagnose is a
 * step and not an answer, and publishing the step gave a second, weaker way
 * to ask what a file does. So the observable is the thing a diagnose is FOR:
 * a rule that reads one and concludes.
 *
 * It is also what makes the walk run at all. The analysis is demand driven,
 * and the fixture declares no signs of its own, so without a rule asking,
 * the result would correctly carry nothing and the test would prove it.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_UNKNOWN);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "DiagRwxTest");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_diag(rwx_exec))
		KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
