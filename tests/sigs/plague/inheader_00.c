/*
 * A block declared IN THE HEADER REGION, which the whole-object pass leaves
 * out on purpose.
 *
 * An object's headers describe it rather than being part of what it does, so
 * hashing them for a rule that named no region can only produce accidental
 * matches - see the note in plague_prepass. That is a rule about the pass, not
 * about the region: an author who declares a block in the headers has said
 * where to look, and the engine must look there. This is the case that says
 * the two are still separable.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofplague.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "InHeader");

KOF_PLAGUE_BLOCK(blk_hdr, KOF_SCAN_ELF_HEADERS, KOF_PLAGUE_RAW,
	0x00762988u, 0x00ad294eu, 0x00f3774eu, 0x013e08e0u,
	0x0183f214u, 0x02beb4f4u, 0x0391b898u, 0x0398be96u,
	0x03fc60d5u, 0x040e39b8u, 0x04a77145u, 0x04f78cc9u,
	0x05e18c3bu, 0x05ee27d4u, 0x062e89d5u, 0x0658299cu,
	0x0684fcf8u, 0x0698f331u, 0x0728f0bfu, 0x07b15fafu,
	0x07c08a41u, 0x07edac3eu);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_plague_score(blk_hdr) >= 90u)
		KOF_SCAN_INFECT("InHeader");
}
