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
	0x0183f214u, 0x03fc60d5u, 0x040e39b8u, 0x0461e72bu,
	0x05147fe0u, 0x061831a1u, 0x0658299cu, 0x0698f331u,
	0x089cdf8cu, 0x0945c3ecu, 0x09525428u, 0x09811068u,
	0x098e6013u, 0x0a02b6cfu, 0x0a7be957u, 0x0b2a6a08u,
	0x0cf52dd4u, 0x0cfa1072u, 0x0d09438au, 0x0d7108e7u,
	0x0d951873u, 0x0e243861u, 0x0e278738u, 0x0f8d9e1au,
	0x12a4a851u, 0x15834014u, 0x1693ae2cu, 0x16a9080fu,
	0x17a07f4au, 0x17bc8e7cu, 0x185a4d53u, 0x186d2ed2u);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_plague_score(blk_hdr) >= 90u)
		KOF_SCAN_INFECT("InHeader");
}
