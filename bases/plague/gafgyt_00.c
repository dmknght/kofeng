/*
 * Gafgyt - a similarity rule.
 *
 * Generated from /home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/1fce1d5b977c38e491fe84e529a3eb5730d099a4966c753b551209f4a24524f3_detected. The blocks were carved by the engine
 * and chosen by hand; the thresholds are the author's, set
 * against what each block scored on that sample.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofplague.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, "Gafgyt");

/* +0xf9ce, 1586 bytes, 27 hash(es) */
KOF_PLAGUE_BLOCK(blk_dded9322, KOF_SCAN_ELF_CODE, KOF_PLAGUE_RAW,
	0x00000000u, 0x00971326u, 0x011f24e1u, 0x01bb313bu,
	0x01ccad6du, 0x0274c605u, 0x02d3fe52u, 0x02e24672u,
	0x03521ad7u, 0x035bfd29u, 0x03db3bbfu, 0x03e439a7u,
	0x03e530f9u, 0x03f8e6a8u, 0x04472ff9u, 0x04afb2e7u,
	0x04bccb31u, 0x050b3348u, 0x056d09f1u, 0x060d0c38u,
	0x0680bd38u, 0x06c77548u, 0x06fd72e2u, 0x070be5edu,
	0x0770313du, 0x07d2ed24u, 0x07f11245u);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_plague_score(blk_dded9322) >= 70u)
		KOF_SCAN_INFECT("Gafgyt");
}
