/*
 * A block whose region is a SET, and the bytes are in the second member of it.
 *
 * The pack field is a bitmask and the engine credits a block from any region it
 * names, so a block made from data that one build keeps in CODE and another in
 * DATA (a static build keeps .rodata in the executable segment, a dynamic one does
 * not) is one block declared over both. The bytes sit in NOLOAD here; the rule
 * names CODE and NOLOAD and must fire.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofplague.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "MaskOr");

KOF_PLAGUE_BLOCK(blk_maskor, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_NOLOAD, KOF_PLAGUE_RAW,
	0x001c9407u, 0x002bb1c2u, 0x0038341au, 0x00e34820u,
	0x012c6dedu, 0x013d0eaeu, 0x0153af12u, 0x0188ae7fu,
	0x01e82a16u, 0x02293d64u, 0x0243d445u, 0x02de73b0u,
	0x02e76811u, 0x02ef0a59u, 0x031e4e73u, 0x0368c12fu,
	0x038dc762u, 0x03a93847u, 0x03fb1b54u, 0x04744d49u,
	0x04b6d7e9u, 0x04da2bfau, 0x05201a01u, 0x055b6807u,
	0x0563ba37u, 0x05a2405bu, 0x05a70a9fu, 0x05b2f36eu,
	0x05b577beu, 0x05d11c4du, 0x05df8573u, 0x0630aedfu);


void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_plague_score(blk_maskor) >= 90u)
		KOF_SCAN_INFECT("MaskOr");
}
