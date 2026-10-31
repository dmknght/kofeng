/*
 * disasm_dispatch - the architecture dispatch of kgenome_disasm (celllysis/disasm.h): which architectures have text,
 * which instruction set an object is read in, alignment and length bounds, what a direct branch answers, and the
 * Thumb and byte-order questions an object's header decides. Oracle: the table of what each architecture is
 * documented to support, and instruction bytes whose meaning is fixed by the architecture's own manual.
 */
#include <kgenome.h>
#include <genotype/x86/x86.h>

#include "hk.h"

static void levels(void)
{
	unsigned a;

	for (a = 0; a < 256; a++) {
		unsigned want = (a == KGENOME_ARCH_X86 || a == KGENOME_ARCH_X86_64 || a == KGENOME_ARCH_ARM || a == KGENOME_ARCH_ARM64)
				? KGENOME_DISASM_TEXT : KGENOME_DISASM_NONE;

		CK(kgenome_disasm_level(a) == want);
		CK((kgenome_disasm_name(a) != NULL) == (want == KGENOME_DISASM_TEXT));
		CK(kgenome_disasm_align(a) == (a == KGENOME_ARCH_ARM || a == KGENOME_ARCH_ARM64 ? 4u : 1u));
		CK(kgenome_disasm_max_len(a) >= 1u && kgenome_disasm_max_len(a) <= 16u);
	}
	CK(strcmp(kgenome_disasm_name(KGENOME_ARCH_X86), "x86") == 0 && strcmp(kgenome_disasm_name(KGENOME_ARCH_X86_64), "x64") == 0);
	CK(strcmp(kgenome_disasm_name(KGENOME_ARCH_ARM), "a32") == 0 && strcmp(kgenome_disasm_name(KGENOME_ARCH_ARM64), "a64") == 0);
	CK(kgenome_disasm_max_len(KGENOME_ARCH_X86) == 16u && kgenome_disasm_max_len(KGENOME_ARCH_ARM64) == 4u);
	/* MIPS decodes (cell form) but has no text: the level says so */
	CK(kgenome_disasm_level(KGENOME_ARCH_MIPS) == KGENOME_DISASM_NONE && kgenome_disasm_level(KGENOME_ARCH_MIPS64) == KGENOME_DISASM_NONE);
}

static struct kgenome_elf_info g_elf;

static struct kgenome_obj elf_obj(unsigned arch, uint64_t entry, unsigned data, uint32_t flags)
{
	struct kgenome_obj o;

	memset(&g_elf, 0, sizeof g_elf);
	g_elf.entry_addr = entry;
	g_elf.elf_data = (uint8_t)data;
	g_elf.e_flags = flags;
	memset(&o, 0, sizeof o);
	o.format = KGENOME_FMT_ELF;
	o.arch = (uint8_t)arch;
	o.file_header = &g_elf;
	return o;
}

static void objects(void)
{
	struct kgenome_obj o;

	/* ARM: ARM state yes, Thumb entry no (the low bit of the entry is the instruction set) */
	o = elf_obj(KGENOME_ARCH_ARM, 0x8190, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_level_obj(&o) == KGENOME_DISASM_TEXT);
	o = elf_obj(KGENOME_ARCH_ARM, 0x10981, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_level_obj(&o) == KGENOME_DISASM_NONE);
	o = elf_obj(KGENOME_ARCH_ARM64, 0x400431, KGENOME_ELFDATA_LE, 0);      /* an odd AArch64 entry is nothing special */
	CK(kgenome_disasm_level_obj(&o) == KGENOME_DISASM_TEXT);
	o = elf_obj(KGENOME_ARCH_MIPS, 0x400000, KGENOME_ELFDATA_BE, 0);
	CK(kgenome_disasm_level_obj(&o) == KGENOME_DISASM_NONE);
	CK(kgenome_disasm_level_obj(NULL) == KGENOME_DISASM_NONE);

	/* which architecture to read in: the object's when it has text, x86 at the asked width otherwise */
	CK(kgenome_disasm_arch(NULL, 32) == KGENOME_ARCH_X86 && kgenome_disasm_arch(NULL, 64) == KGENOME_ARCH_X86_64);
	CK(kgenome_disasm_arch(NULL, 0) == KGENOME_ARCH_X86_64);
	o = elf_obj(KGENOME_ARCH_ARM, 0x8190, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_arch(&o, 64) == KGENOME_ARCH_ARM && kgenome_disasm_arch(&o, 32) == KGENOME_ARCH_ARM);
	o = elf_obj(KGENOME_ARCH_ARM64, 0x400430, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_arch(&o, 32) == KGENOME_ARCH_ARM64);
	o = elf_obj(KGENOME_ARCH_X86_64, 0x401000, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_arch(&o, 32) == KGENOME_ARCH_X86 && kgenome_disasm_arch(&o, 64) == KGENOME_ARCH_X86_64);
	o = elf_obj(KGENOME_ARCH_MIPS, 0x400000, KGENOME_ELFDATA_BE, 0);
	CK(kgenome_disasm_arch(&o, 64) == KGENOME_ARCH_X86_64);               /* no text for MIPS: the caller is never handed an architecture it cannot read */
	o = elf_obj(KGENOME_ARCH_ARM, 0x10981, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_arch(&o, 64) == KGENOME_ARCH_X86_64);               /* Thumb: not offered, so not an ARM reading either */

	/* byte order of the CODE: big-endian data with BE8 keeps little-endian instructions */
	o = elf_obj(KGENOME_ARCH_ARM, 0x8190, KGENOME_ELFDATA_BE, 0);
	CK(kgenome_disasm_code_be(&o) == 1);
	o = elf_obj(KGENOME_ARCH_ARM, 0x100fc, KGENOME_ELFDATA_BE, KGENOME_ELF_EF_ARM_BE8);
	CK(kgenome_disasm_code_be(&o) == 0);
	o = elf_obj(KGENOME_ARCH_ARM, 0x8190, KGENOME_ELFDATA_LE, 0);
	CK(kgenome_disasm_code_be(&o) == 0);
	CK(kgenome_disasm_code_be(NULL) == 0);
}

static struct kgenome_x86_insn g_ix;
static int g_want_x86;

static struct kgenome_disasm_res one(unsigned arch, int be, const uint8_t *p, size_t n, uint64_t va, char *text, size_t cap)
{
	struct kgenome_disasm_req rq;
	struct kgenome_disasm_res rs;

	memset(&rq, 0, sizeof rq);
	rq.arch = arch;
	rq.be = be;
	rq.p = p;
	rq.n = n;
	rq.va = va;
	rq.text = text;
	rq.cap = cap;
	rq.x86 = g_want_x86 ? &g_ix : NULL;
	kgenome_disasm(&rq, &rs);
	return rs;
}

static void flows(void)
{
	char t[KGENOME_DISASM_TEXT_MAX];
	struct kgenome_disasm_res r;
	static const uint8_t call[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 }, jmp[] = { 0xeb, 0xfe }, jcc[] = { 0x74, 0x05 },
		ret[] = { 0xc3 }, sysc[] = { 0x0f, 0x05 }, nop[] = { 0x90 }, half[] = { 0xe8, 0x00 }, jmpr[] = { 0xff, 0xe0 };
	/* AArch64: bl .+8, b .-4, b.ne .+12, cbz x0 .+8, ret, br x16, svc #0, nop */
	static const uint8_t bl[] = { 0x02, 0x00, 0x00, 0x94 }, bb[] = { 0xff, 0xff, 0xff, 0x17 }, bne[] = { 0x61, 0x00, 0x00, 0x54 },
		cbz[] = { 0x40, 0x00, 0x00, 0xb4 }, aret[] = { 0xc0, 0x03, 0x5f, 0xd6 }, br16[] = { 0x00, 0x02, 0x1f, 0xd6 },
		svc[] = { 0x01, 0x00, 0x00, 0xd4 }, anop[] = { 0x1f, 0x20, 0x03, 0xd5 };
	/* ARM: bl .+8 (cond al, pc+8 rule), bx lr, beq .+8, ldr r0,[pc,#4] */
	static const uint8_t abl[] = { 0x00, 0x00, 0x00, 0xeb }, bxlr[] = { 0x1e, 0xff, 0x2f, 0xe1 }, beq[] = { 0x00, 0x00, 0x00, 0x0a },
		ldrpc[] = { 0x04, 0x00, 0x9f, 0xe5 }, abe[] = { 0xeb, 0x00, 0x00, 0x00 };

	r = one(KGENOME_ARCH_X86_64, 0, call, sizeof call, 0x1000, t, sizeof t);
	CK(r.status == KGENOME_OK && r.len == 5 && r.flow == KGENOME_GT_FLOW_CALL && r.has_target && r.target == 0x1005 && !r.has_x86);
	CK(strncmp(t, "CALL", 4) == 0);
	g_want_x86 = 1;
	r = one(KGENOME_ARCH_X86_64, 0, call, sizeof call, 0x1000, t, sizeof t);
	CK(r.has_x86 && g_ix.len == 5 && kgenome_x86_cat(&g_ix) == KGENOME_X86_C_CALL);   /* the decoded instruction is handed back when asked for */
	r = one(KGENOME_ARCH_ARM64, 0, call, 4, 0, t, sizeof t);
	CK(!r.has_x86);                                                      /* and only x86 has one */
	g_want_x86 = 0;
	r = one(KGENOME_ARCH_X86, 0, jmp, sizeof jmp, 0x2000, t, sizeof t);
	CK(r.len == 2 && r.flow == KGENOME_GT_FLOW_JUMP && r.has_target && r.target == 0x2000);
	r = one(KGENOME_ARCH_X86_64, 0, jcc, sizeof jcc, 0x10, t, sizeof t);
	CK(r.len == 2 && r.flow == KGENOME_GT_FLOW_COND && r.has_target && r.target == 0x17);
	r = one(KGENOME_ARCH_X86_64, 0, ret, sizeof ret, 0, t, sizeof t);
	CK(r.len == 1 && r.flow == KGENOME_GT_FLOW_RET && !r.has_target);
	r = one(KGENOME_ARCH_X86_64, 0, sysc, sizeof sysc, 0, t, sizeof t);
	CK(r.len == 2 && r.flow == KGENOME_GT_FLOW_TRAP && !r.has_target);
	r = one(KGENOME_ARCH_X86_64, 0, nop, sizeof nop, 0, t, sizeof t);
	CK(r.len == 1 && r.flow == KGENOME_GT_FLOW_NEXT && !r.has_target && strcmp(t, "NOP") == 0);
	r = one(KGENOME_ARCH_X86_64, 0, jmpr, sizeof jmpr, 0, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_JUMP && !r.has_target);                 /* indirect: a jump with nowhere to point */
	r = one(KGENOME_ARCH_X86_64, 0, half, sizeof half, 0, t, sizeof t);
	CK(r.status == KGENOME_TRUNCATED && r.len == 1);

	r = one(KGENOME_ARCH_ARM64, 0, bl, 4, 0x1000, t, sizeof t);
	CK(r.status == KGENOME_OK && r.len == 4 && r.flow == KGENOME_GT_FLOW_CALL && r.has_target && r.target == 0x1008 && !r.has_x86);
	r = one(KGENOME_ARCH_ARM64, 0, bb, 4, 0x1000, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_JUMP && r.has_target && r.target == 0xffc);
	r = one(KGENOME_ARCH_ARM64, 0, bne, 4, 0x1000, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_COND && r.has_target && r.target == 0x100c && strncmp(t, "B.NE", 4) == 0);
	r = one(KGENOME_ARCH_ARM64, 0, cbz, 4, 0x1000, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_COND && r.has_target && r.target == 0x1008);
	r = one(KGENOME_ARCH_ARM64, 0, aret, 4, 0, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_RET && !r.has_target && strcmp(t, "RET") == 0);
	r = one(KGENOME_ARCH_ARM64, 0, br16, 4, 0, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_JUMP && !r.has_target);
	r = one(KGENOME_ARCH_ARM64, 0, svc, 4, 0, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_TRAP);
	r = one(KGENOME_ARCH_ARM64, 0, anop, 4, 0, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_NEXT && strcmp(t, "NOP") == 0);
	/* a short tail is a short answer and not a read past the end */
	r = one(KGENOME_ARCH_ARM64, 0, bl, 3, 0, t, sizeof t);
	CK(r.status == KGENOME_TRUNCATED && r.len == 3);

	r = one(KGENOME_ARCH_ARM, 0, abl, 4, 0x1000, t, sizeof t);
	CK(r.status == KGENOME_OK && r.flow == KGENOME_GT_FLOW_CALL && r.has_target && r.target == 0x1008);
	r = one(KGENOME_ARCH_ARM, 0, bxlr, 4, 0, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_RET && !r.has_target && strcmp(t, "BX        lr") == 0);
	r = one(KGENOME_ARCH_ARM, 0, beq, 4, 0x1000, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_COND && r.has_target && r.target == 0x1008);
	r = one(KGENOME_ARCH_ARM, 0, ldrpc, 4, 0x1000, t, sizeof t);
	CK(r.flow == KGENOME_GT_FLOW_NEXT && r.has_target && r.target == 0x100c);    /* the literal's address, the pipeline's +8 included */
	r = one(KGENOME_ARCH_ARM, 1, abe, 4, 0x1000, t, sizeof t);
	CK(r.status == KGENOME_OK && r.flow == KGENOME_GT_FLOW_CALL && r.target == 0x1008);   /* the same word, big-endian */

	/* the length-only form: ARM and AArch64 answer the word, with no text and no buffer; a word that is not an instruction is BAD_INPUT */
	{
		struct kgenome_disasm_req lq;
		struct kgenome_disasm_res lr;
		static const uint8_t udfa32[] = { 0x00, 0x00, 0x10, 0x01 };     /* 01100000: not an instruction of the integer space */

		memset(&lq, 0, sizeof lq);
		lq.arch = KGENOME_ARCH_ARM64;
		lq.p = aret;
		lq.n = 4;
		lq.len_only = 1;
		kgenome_disasm(&lq, &lr);
		CK(lr.status == KGENOME_OK && lr.len == 4 && !lr.has_target);
		lq.arch = KGENOME_ARCH_ARM;
		lq.p = bxlr;
		kgenome_disasm(&lq, &lr);
		CK(lr.status == KGENOME_OK && lr.len == 4);
		lq.p = udfa32;
		kgenome_disasm(&lq, &lr);
		CK(lr.len == 4);
	}
	/* what has no decoder says so, and says it without a length */
	r = one(KGENOME_ARCH_MIPS, 0, nop, 4, 0, t, sizeof t);
	CK(r.status == KGENOME_UNSUPPORTED && r.len == 0 && t[0] == 0);
	r = one(KGENOME_ARCH_ARM, 0, nop, 0, 0, t, sizeof t);
	CK(r.status == KGENOME_TRUNCATED && r.len == 0);
	/* a word of a space the formatter does not spell: an instruction, with the right length and no claimed mnemonic */
	{
		static const uint8_t vfp[] = { 0x00, 0x0a, 0xd1, 0xed };         /* vldr s1, [r1] (VFP): the coprocessor space */

		r = one(KGENOME_ARCH_ARM, 0, vfp, 4, 0, t, sizeof t);
		CK(r.status == KGENOME_UNSUPPORTED && r.len == 4 && strncmp(t, ".INST", 5) == 0);
	}
	/* a word that is not an instruction: BAD_INPUT, still four bytes, so the alignment survives data */
	{
		static const uint8_t zero[] = { 0, 0, 0, 0 }, udf[] = { 0xf0, 0x00, 0xf0, 0xe7 };

		r = one(KGENOME_ARCH_ARM64, 0, zero, 4, 0, t, sizeof t);
		CK(r.status == KGENOME_OK && strncmp(t, "UDF", 3) == 0);        /* udf #0 is an instruction that always faults */
		r = one(KGENOME_ARCH_ARM, 0, udf, 4, 0, t, sizeof t);
		CK(r.len == 4 && r.flow == KGENOME_GT_FLOW_TRAP);
	}
}

/* the x86 path is the decoder and formatter the viewer used before the entry existed: same length, same text, same verdict on random bytes */
static void x86_unchanged(void)
{
	struct hk_rng r;
	unsigned long it;
	unsigned bits;

	fz_rng_seed(&r, 0x86d15a5eedull);
	for (bits = 32; bits <= 64; bits += 32) {
		for (it = 0; it < 60000ul * hk_scale(); it++) {
			uint8_t b[16];
			size_t k, n = 1u + hk_below(&r, 16u);
			struct kgenome_x86_insn ix;
			char want[KGENOME_X86_TEXT], got[KGENOME_DISASM_TEXT_MAX];
			struct kgenome_disasm_res rs;
			uint64_t va = hk_next(&r);
			enum kgenome_status st;

			for (k = 0; k < sizeof b; k++)
				b[k] = (uint8_t)hk_next(&r);
			st = kgenome_x86_decode(&ix, b, n, (int)bits);
			rs = one(bits == 32 ? KGENOME_ARCH_X86 : KGENOME_ARCH_X86_64, 0, b, n, va, got, sizeof got);
			if (st != KGENOME_OK) {
				CK(rs.status != KGENOME_OK && rs.len == 1u);
				continue;
			}
			want[0] = 0;
			if (!kgenome_x86_format(&ix, va, want, sizeof want))
				want[0] = 0;
			kgenome_x86_shorten(want);
			CK(rs.status == KGENOME_OK && rs.len == ix.len && strcmp(got, want) == 0);
			{
				/* a length-only walk gets the same length and no text, and needs no buffer */
				struct kgenome_disasm_req lq;
				struct kgenome_disasm_res lr;

				memset(&lq, 0, sizeof lq);
				lq.arch = bits == 32 ? KGENOME_ARCH_X86 : KGENOME_ARCH_X86_64;
				lq.p = b;
				lq.n = n;
				lq.len_only = 1;
				kgenome_disasm(&lq, &lr);
				CK(lr.status == KGENOME_OK && lr.len == ix.len);
			}
		}
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	x86_unchanged();
	levels();
	objects();
	flows();
	printf("disasm_dispatch: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
