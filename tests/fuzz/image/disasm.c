/*
 * image/disasm - kgenome_disasm and the questions that go with it (celllysis/disasm.h): the one entry from bytes and an
 * architecture to text, length and branch target, for x86, x86-64, ARM, AArch64 and the architectures it has no text for.
 *
 * The input bytes are the instruction bytes; the iteration's rng picks the architecture, the byte order, the address, the
 * size of the text buffer (including zero) and how many bytes may be read. Held: the status is one of the entry's four;
 * the length is 1..max and no more than what was handed (a short buffer is TRUNCATED), 4 for a word architecture whenever four
 * bytes were there; the text is terminated inside the buffer it was given; a direct branch has a flow that has a target and
 * an architecture without text has length 0; a length-only call writes no text; the same input twice gives one answer. The object questions are asked of an
 * object built from the bytes (an ELF header with any entry, either byte order, any flags): the answers are the documented
 * ones whatever the header says.
 */
#include <kgenome.h>
#include <genotype/x86/x86.h>

#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"

static void seeds(struct fz_corpus *c)
{
	static const uint8_t x86[] = { 0xe8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe5, 0xc3, 0x0f, 0x05, 0x74, 0x05 };
	static const uint8_t a64[] = { 0xfd, 0x7b, 0xbf, 0xa9, 0x02, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6 };
	static const uint8_t a32[] = { 0x10, 0x40, 0x2d, 0xe9, 0x00, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1 };

	fz_corpus_add(c, "x86", x86, sizeof x86);
	fz_corpus_add(c, "a64", a64, sizeof a64);
	fz_corpus_add(c, "a32", a32, sizeof a32);
}

/* the instruction an x86 caller asked for is its own storage */
static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const unsigned archs[] = { KGENOME_ARCH_X86, KGENOME_ARCH_X86_64, KGENOME_ARCH_ARM, KGENOME_ARCH_ARM64,
					  KGENOME_ARCH_MIPS, KGENOME_ARCH_ANY, 200u };
	static const size_t caps[] = { 0, 1, 3, 9, 30, KGENOME_DISASM_TEXT_MAX };
	unsigned arch = archs[fz_below(c->rng, sizeof archs / sizeof archs[0])];
	size_t cap = caps[fz_below(c->rng, sizeof caps / sizeof caps[0])];
	size_t k, take = n ? (size_t)fz_below(c->rng, n + 1u) : 0;
	struct kgenome_disasm_req rq;
	struct kgenome_disasm_res a, b;
	struct kgenome_x86_insn ix;
	char text[KGENOME_DISASM_TEXT_MAX + 1u], again[KGENOME_DISASM_TEXT_MAX + 1u];
	unsigned max = kgenome_disasm_max_len(arch), align = kgenome_disasm_align(arch), level = kgenome_disasm_level(arch);
	struct kgenome_elf_info info;
	struct kgenome_obj obj;
	uint64_t h = 0;

	memset(text, 0xa5, sizeof text);
	memset(again, 0xa5, sizeof again);
	memset(&rq, 0, sizeof rq);
	rq.arch = arch;
	rq.be = (int)fz_below(c->rng, 2);
	rq.p = in;
	rq.n = take;
	rq.va = fz_rng_next(c->rng);
	rq.text = text;
	rq.cap = cap;
	rq.x86 = fz_below(c->rng, 2) ? &ix : NULL;
	rq.len_only = fz_below(c->rng, 4) == 0;
	kgenome_disasm(&rq, &a);
	rq.text = again;
	kgenome_disasm(&rq, &b);
	FZ_CHECK(c, a.status == b.status && a.len == b.len && a.flow == b.flow && a.has_target == b.has_target && a.target == b.target,
		 "two calls on one input differ");
	FZ_CHECK(c, rq.len_only || cap == 0 || memchr(text, 0, cap) != NULL, "the text is not terminated inside the buffer");
	FZ_CHECK(c, !rq.len_only || cap == 0 || (unsigned char)text[0] == 0xa5, "a length-only call wrote text");
	FZ_CHECK(c, !rq.len_only || a.status != KGENOME_UNSUPPORTED || !level, "a length-only call called a supported word unsupported");
	for (k = cap; k < sizeof text; k++)
		FZ_CHECK(c, (unsigned char)text[k] == 0xa5, "a byte past the text buffer was written");
	FZ_CHECK(c, level == KGENOME_DISASM_NONE || level == KGENOME_DISASM_TEXT, "a level outside the enum");
	FZ_CHECK(c, max >= 1u && max <= 16u && align >= 1u && align <= 4u, "a length bound or alignment out of range");
	if (!level) {
		FZ_CHECK(c, a.len == 0 && a.status == (take ? KGENOME_UNSUPPORTED : KGENOME_TRUNCATED), "an architecture without text answered");
	} else if (take) {
		FZ_CHECK(c, a.len >= 1u && a.len <= max, "a length outside 1..max");
		if (align > 1u)
			FZ_CHECK(c, a.len == (take >= 4u ? 4u : (uint32_t)take), "a word architecture advanced by other than the word");
		else
			FZ_CHECK(c, a.status != KGENOME_OK || a.len <= take, "an x86 instruction longer than the bytes handed");
		FZ_CHECK(c, !a.has_target || a.flow == KGENOME_GT_FLOW_JUMP || a.flow == KGENOME_GT_FLOW_COND || a.flow == KGENOME_GT_FLOW_CALL ||
			    a.flow == KGENOME_GT_FLOW_NEXT, "a target with a flow that has none");
	} else {
		FZ_CHECK(c, a.status == KGENOME_TRUNCATED && a.len == 0, "no bytes is not a truncated nothing");
	}
	FZ_CHECK(c, a.has_x86 == 0 || (rq.x86 && (arch == KGENOME_ARCH_X86 || arch == KGENOME_ARCH_X86_64) &&
							 (a.status == KGENOME_OK || a.status == KGENOME_TRUNCATED)),
		 "has_x86 without an x86 instruction");
	h = ((uint64_t)a.status << 32) ^ ((uint64_t)a.len << 8) ^ a.flow ^ (a.has_target ? a.target : 0);

	/* the questions asked of an object whose header is the bytes: documented answers whatever they hold */
	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	for (k = 0; k < n && k < 8u; k++)
		info.entry_addr = (info.entry_addr << 8) | in[k];
	info.elf_data = (uint8_t)(n > 8u ? in[8] & 1u : 0u);
	info.e_flags = n > 12u ? (uint32_t)in[9] << 23 : 0u;
	obj.format = KGENOME_FMT_ELF;
	obj.arch = (uint8_t)arch;
	obj.file_header = &info;
	FZ_CHECK(c, kgenome_disasm_level_obj(&obj) <= kgenome_disasm_level(arch), "an object has more text than its architecture");
	FZ_CHECK(c, kgenome_disasm_level_obj(NULL) == KGENOME_DISASM_NONE, "NULL has text");
	{
		unsigned want = kgenome_disasm_arch(&obj, 32u), other = kgenome_disasm_arch(NULL, 64u);

		FZ_CHECK(c, kgenome_disasm_level(want) == KGENOME_DISASM_TEXT && other == KGENOME_ARCH_X86_64,
			 "kgenome_disasm_arch handed back an architecture without text");
		FZ_CHECK(c, kgenome_disasm_name(want) != NULL, "an architecture with text has no name");
		h ^= want;
	}
	h ^= (uint64_t)(kgenome_disasm_code_be(&obj) != 0) << 20;
	fz_digest(c, h);
	return 0;
}

FZ_ADAPTER(disasm, .name = "kgenome/disasm",
	   .covers = "kgenome_disasm kgenome_disasm_align kgenome_disasm_arch kgenome_disasm_code_be kgenome_disasm_level "
		     "kgenome_disasm_level_obj kgenome_disasm_max_len kgenome_disasm_name",
	   .shape = FZ_REQ, .seeds = seeds, .run = run);
