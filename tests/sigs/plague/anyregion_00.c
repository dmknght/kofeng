/*
 * A block declared over the WHOLE OBJECT, which is a different path through
 * the prepass from an anchored one.
 *
 * KOF_SCAN_ALL has no region to resolve, so the pass that serves it walks the
 * object's regions instead and leaves out the ones nothing is ever cut from -
 * headers and symbols - and whatever of NOLOAD and UNCLAIMED is not worth
 * hashing. The block below sits in NOLOAD, which is one of the two that walk
 * gates, so a rule naming no region at all must still reach it: the gate is
 * about padding and this span is not padding.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofplague.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "AnyRegion");

KOF_PLAGUE_BLOCK(blk_any, KOF_SCAN_ALL, KOF_PLAGUE_RAW,
	0x001c9407u, 0x002bb1c2u, 0x0038341au, 0x00e34820u,
	0x012c6dedu, 0x013d0eaeu, 0x0153af12u, 0x0188ae7fu,
	0x01e82a16u, 0x02293d64u, 0x0243d445u, 0x02de73b0u,
	0x02e76811u, 0x02ef0a59u, 0x031e4e73u, 0x0368c12fu,
	0x038dc762u, 0x03a93847u, 0x03fb1b54u, 0x04744d49u,
	0x04b6d7e9u, 0x04da2bfau, 0x05201a01u, 0x055b6807u,
	0x0563ba37u, 0x05a2405bu, 0x05a70a9fu, 0x05b2f36eu,
	0x05b577beu, 0x05d11c4du, 0x05df8573u, 0x0630aedfu,
	0x06718d2fu, 0x0698f331u, 0x069e05a1u, 0x06cdc729u,
	0x06d9d8d0u, 0x0700a655u, 0x074915cfu, 0x07d22e2bu);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_plague_score(blk_any) >= 90u)
		KOF_SCAN_INFECT("AnyRegion");
}
