/*
 * endian_00.c - the fixture block of fixture_00.c, for ELF objects.
 *
 * The same 2048 bytes of the named generator, so the same 32 hashes, aimed at an
 * ELF: tests/unit/endian_view.c writes them as the instruction words of one function
 * of a little-endian and a big-endian MIPS object (and PowerPC64) and expects the
 * block scored on the first, not on the second, and on the second's canonical view.
 * It cannot fire on anything real.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofmutation.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "EndianBlock");

/* 32 hash(es): the sketch of a 2048 byte fixture block */
KOF_MUTATION_BLOCK(block, KOF_SCAN_ALL, KOF_MUTATION_RAW,
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
	(void)ctx;
	if (kof_mutation_score(block) >= 50u)
		KOF_SCAN_INFECT("EndianBlock");
}
