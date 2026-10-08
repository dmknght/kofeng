#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * trojan_meterp_08.c - a Windows stager, read off the graph instead of off bytes.
 *
 * THE PE HALF OF trojan_meterp_00, and a separate verdict because it asks for a
 * different analysis: a Windows stager finds its APIs by walking the loader's
 * module list, so what it calls is named by the apihash route and gated by a W+X
 * section, neither of which the ELF diagnoses declare. It replaced the x86 and
 * x64 byte-pattern rules for the same reason the ELF verdict replaced its own:
 * the bytes are what an encoder changes, what the program does once it runs is
 * not.
 *
 * WHAT IT SAYS IS THE ELF VERDICT'S SENTENCE with the Windows diagnoses. A W+X
 * allocation that a read fills and a call enters; a connected socket whose
 * descriptor a read uses; and THE READ IS THE SAME READ. Each alone is ordinary.
 *
 * NOT YET ANSWERED, said so it is not mistaken for coverage: a stager whose body
 * is encoded (xor_context, xor_dynamic, zutto_dekiru) shows the resolver only
 * after it has been decoded, and the run that names the calls starts at the
 * entry point.
 */

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	/*
	 * THE JOIN STARTS AT THE SOCKET, not at the read, and that is the one
	 * place this differs from the ELF verdict. A Windows stager reads twice
	 * from the same socket - four bytes of length, then the stage into the
	 * allocation - and a diagnose binds the FIRST read that satisfies it, so
	 * the net diagnose binds the length read and the memory diagnose binds
	 * the stage read: two reads, no node in common, and the join asked at the
	 * read said no on every plain stager. Starting at the socket asks what
	 * was meant - the bytes of THIS connection flow into the region that is
	 * entered - and is indifferent to how many reads carried them.
	 */
	if (kof_diag(DIAG_MEM_EXECAPIHASH) &&
	    kof_diag(DIAG_NET_RECVAPIHASH) &&
	    kof_diag_share(KOF_NUCLEO_NET_OPEN, DIAG_MEM_EXECAPIHASH,
			   DIAG_NET_RECVAPIHASH))
		KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
