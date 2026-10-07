#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * botnet_mirai_00.c - a bot read off its two habits: it dials its controller on
 * a non-blocking socket, and it sends packets whose IP header it wrote.
 *
 * Neither alone is a verdict. A non-blocking connect is every event-loop
 * client, and a raw socket with IP_HDRINCL is every packet tool. A program
 * that does both is a client of a controller that also forges traffic, which is
 * what a flooding bot is and an ordinary program is not.
 *
 * WHAT IT COSTS AND WHAT IT BUYS, measured on 1636 Linux malware samples (the
 * Mirai/Gafgyt/other Bazaar sets plus the elf255 collection): one rule matches
 * 457 samples that the pattern and similarity rules reach with 70, and 129 of
 * them are samples those rules do not match. It names a behaviour and not a
 * family, so it does not replace them where the family is wanted. 0 verdicts on
 * 1200 system ELF files; nmap and hping3 were tried by hand with none.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, "Mirai");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_diag(DIAG_NET_CNCNONBLOCK) && kof_diag(DIAG_NET_SENDRAWHEADER))
		KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
