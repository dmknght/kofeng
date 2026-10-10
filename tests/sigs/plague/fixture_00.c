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

/* 32 hash(es): the sketch of a 2048 byte fixture block */
KOF_PLAGUE_BLOCK(fixture, KOF_SCAN_ALL, KOF_PLAGUE_RAW,
	0x0003b4afu, 0x00082bd9u, 0x000b4876u, 0x001f32beu,
	0x00386890u, 0x00da5d1fu, 0x00ddce0du, 0x00f42e08u,
	0x010fbd9du, 0x01261b21u, 0x01267587u, 0x013edb56u,
	0x0152b764u, 0x01547e51u, 0x01724817u, 0x018556ebu,
	0x01a1c15au, 0x01c48e72u, 0x01d034c3u, 0x01d4104au,
	0x01d6bed4u, 0x01f336f6u, 0x0210d4b9u, 0x021a8671u,
	0x024c2912u, 0x024cde07u, 0x029c268du, 0x02d6ab22u,
	0x02dabed5u, 0x0316b020u, 0x0325f861u, 0x0379e080u);

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
