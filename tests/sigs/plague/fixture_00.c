/*
 * fixture_00.c - a similarity rule, and the only one in this tree that a test
 * can check end to end.
 *
 * WHY A FIXTURE RULE SHIPS. Every other rule here measures a block taken from a
 * real sample, and no test can carry one of those: the sample is not in the
 * repository and the hashes mean nothing without it. This one measures a block
 * a test can BUILD - a deterministic byte sequence - so the whole path from
 * KOF_PLAGUE_BLOCK through the packer, the loader, the prepass and back out
 * through kof_plague_score is exercised by something that runs on every build.
 *
 * It cannot fire on anything real. The block is four kilobytes of a named
 * generator's output; nothing but the test produces those bytes.
 *
 * HOW A REAL ONE IS WRITTEN: the researcher picks the block in kofviewer and
 * the hashes are generated. Nobody types them, here or anywhere.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofplague.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "KofengPlagueFixture");

/* 128 hash(es) from a 4096 byte fixture block */
KOF_PLAGUE_BLOCK(fixture, KOF_SCAN_ALL, KOF_PLAGUE_RAW,
	0x00032e31u, 0x0003b4afu, 0x00082bd9u, 0x000b2353u,
	0x000b4876u, 0x001f32beu, 0x00386890u, 0x004606beu,
	0x0066d838u, 0x008c68f3u, 0x008ebd4bu, 0x00d8d168u,
	0x00d8f082u, 0x00da5d1fu, 0x00ddce0du, 0x00f42e08u,
	0x010fbd9du, 0x0110f73du, 0x011244a9u, 0x01261b21u,
	0x01267587u, 0x013edb56u, 0x0147d9c2u, 0x0152b764u,
	0x01547e51u, 0x0159609cu, 0x01599625u, 0x0168432au,
	0x016f86d8u, 0x01724817u, 0x0183f19cu, 0x018556ebu,
	0x01a1c15au, 0x01aebe76u, 0x01bd1b9eu, 0x01c48e72u,
	0x01d034c3u, 0x01d4104au, 0x01d6bed4u, 0x01e67e91u,
	0x01f336f6u, 0x02004a2eu, 0x0203f4a8u, 0x020acde7u,
	0x0210d4b9u, 0x0217ac72u, 0x021a8671u, 0x02201363u,
	0x0239aec8u, 0x024c2912u, 0x024cde07u, 0x0250cdc4u,
	0x026bc86cu, 0x026c26feu, 0x026eddffu, 0x02721d0du,
	0x0272a777u, 0x0295afefu, 0x029c268du, 0x02a04156u,
	0x02b05419u, 0x02d6ab22u, 0x02dabed5u, 0x0316b020u,
	0x031f25afu, 0x0325f861u, 0x032f637bu, 0x03595d6eu,
	0x0361c293u, 0x0379e080u, 0x0383252fu, 0x03871db4u,
	0x03885ca1u, 0x038beb79u, 0x03ae0c92u, 0x03d38a14u,
	0x03deb381u, 0x03e20ad5u, 0x03f06a71u, 0x042a06d9u,
	0x045956b9u, 0x0481f4d9u, 0x0484f854u, 0x04b81682u,
	0x04bcd388u, 0x04c9c925u, 0x04ca8ef4u, 0x04f3b446u,
	0x051fc666u, 0x052ba436u, 0x052ca409u, 0x0531acd6u,
	0x053c8344u, 0x054f5623u, 0x054f6daau, 0x0550ef20u,
	0x05536cabu, 0x056d7d68u, 0x057ca51au, 0x05822cf5u,
	0x0590f9e6u, 0x05bc3428u, 0x05c3119au, 0x05c6ad21u,
	0x05efdc34u, 0x05f05a89u, 0x05f23fbbu, 0x0602a4e5u,
	0x0626e801u, 0x0654eb81u, 0x06625610u, 0x06ad8ac7u,
	0x06b9758cu, 0x06c264f8u, 0x06cee95du, 0x06dfad7du,
	0x06fc00fbu, 0x07095994u, 0x070d1a5du, 0x07124e56u,
	0x071c025fu, 0x071d7573u, 0x0724fa8fu, 0x072cf564u,
	0x0730439eu, 0x0736b855u, 0x073931fcu, 0x0748ff87u);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	/*
	 * Fifty, not a hundred. A rule that demanded the block whole would pass
	 * this test and fail on the first variant that changed anything - and
	 * measuring how much is present is the entire reason a block is not a
	 * pattern. The test feeds a damaged copy as well for that reason.
	 */
	if (kof_plague_score(fixture) >= 50u)
		KOF_SCAN_INFECT("Fixture");
}
