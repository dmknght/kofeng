#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * trojan_meterp_08.c - a stager, read off the graph instead of off bytes.
 *

 * THE EVIDENCE IT USES CANNOT BE EDITED AWAY. shikata_ga_nai builds a
 * different decoder and a different key per build, so the bytes a pattern
 * matches are the one thing it is designed to change; what the payload does
 * once decoded is not.
 *
 * IT REPLACED TWO BYTE PATTERNS, and that is the point of it rather than a
 * side effect: trojan_meterp_00 and _02 matched the x64 and x86 stagers by
 * their bytes, which is the one thing a per-build encoder changes.
 *
 * IT READS THE GRAPH AND NAMES NO OTHER RULE. The engine answers what the
 * code did; the algorithm is here, where the family name is.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	/*
	 * ONE READ, DOING BOTH JOBS.
	 *
	 * DIAG_SYSCALL_MEMEXEC is a W+X region that a read fills and a call
	 * enters. DIAG_SYSCALL_NETRECV is a connected socket whose
	 * descriptor a read uses. Each on its own is ordinary - the first is
	 * every self-unpacking loader, the second is every downloader - and
	 * what makes the pair a stager is that THE READ IS THE SAME READ:
	 * the bytes that were executed are the bytes that came off the wire.
	 *
	 * BOTH BEHAVIOURS FIRST, THEN THE JOIN. The two questions are not
	 * the same one: the share is about a node, and a node proves
	 * nothing about the tree it came from unless that tree matched.
	 * Writing the join alone would also be a rule whose failure has two
	 * meanings - no socket, or a socket feeding a different read.
	 *
	 * THE CAPABILITY IS NAMED because that is the claim. Asking only
	 * whether the two behaviours have some node in common would be
	 * satisfied by a shared allocation or a shared resolve, which a
	 * packed binary is full of.
	 */
	if (kof_diag(DIAG_SYSCALL_MEMEXEC) &&
	    kof_diag(DIAG_SYSCALL_NETRECV) &&
	    kof_diag_share(KOF_NUCLEO_MEM_READ, DIAG_SYSCALL_MEMEXEC,
			   DIAG_SYSCALL_NETRECV))
		KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
