/*
 * range_facts - kgenome_range_xref_build, kgenome_range_facts and kgenome_xref_refs on hand-built images. Linked against
 * libkgenome.a alone.
 *
 * Oracle: the image is built here from numbers the test writes down. An x86-64 .text holds `lea rax,[rip+disp]; call rax; ret`
 * naming a payload variable in .data; the variables are: the payload (real instructions with a syscall, referenced from code and
 * from a pointer table), a string, a pointer table, zeros, a second code-like variable nobody refers to, and 256 bytes in which
 * every value occurs once (8 bits a byte exactly). Every expected number is computed from those bytes. Then the other
 * architectures' decoders (AArch64, ARM, x86-32 int 0x80, MIPS), hostile requests (offsets and sizes), the budget and the cap.
 */
#include <kgenome.h>

#include "hk.h"

#define FILE_SIZE 0x5000u
#define TEXT_OFF  0x100u
#define TEXT_VA   0x400100u
#define DATA_OFF  0x300u
#define DATA_VA   0x600300u

#define PAY   0x500u        /* the payload variable: file offsets in .data */
#define STR   0x520u
#define TBL   0x540u
#define ZER   0x580u
#define UNR   0x5a0u
#define RND   0x600u

static uint8_t file[FILE_SIZE];
static struct kgenome_elf_info E;
static struct kgenome_obj      O;

static uint64_t va_of(uint32_t off)
{
	return DATA_VA + (off - DATA_OFF);
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

static void build(void)
{
	static const uint8_t pay[] = { 0x48, 0x31, 0xc0, 0xb0, 0x3b, 0x0f, 0x05, 0xc3 };    /* xor rax,rax; mov al,0x3b; syscall; ret */
	static const char str[] = "hello world, hello world";
	uint32_t i;

	memset(file, 0, sizeof file);
	memset(&E, 0, sizeof E);
	memset(&O, 0, sizeof O);
	/* .text: lea rax,[rip+disp] -> the payload ; call rax ; ret ; nops */
	file[TEXT_OFF] = 0x48; file[TEXT_OFF + 1] = 0x8d; file[TEXT_OFF + 2] = 0x05;
	put32(file + TEXT_OFF + 3, (uint32_t)(va_of(PAY) - (TEXT_VA + 7u)));
	file[TEXT_OFF + 7] = 0xff; file[TEXT_OFF + 8] = 0xd0; file[TEXT_OFF + 9] = 0xc3;
	memset(file + TEXT_OFF + 10, 0x90, 0x76);
	memcpy(file + PAY, pay, sizeof pay);
	memset(file + PAY + sizeof pay, 0x90, 8);                               /* 16 bytes of code */
	memcpy(file + STR, str, 24);
	for (i = 0; i < 8; i++)                                                 /* a table of addresses, the first one the payload's */
		put64(file + TBL + 8u * i, i ? 0x401000u + 8u * i : va_of(PAY));
	memset(file + ZER, 0, 32);
	memcpy(file + UNR, pay, sizeof pay);
	memset(file + UNR + sizeof pay, 0x90, 8);
	for (i = 0; i < 256; i++)
		file[RND + i] = (uint8_t)(i * 37u + 11u);                       /* a permutation of 0..255 */
	E.valid = 1;
	E.elf_class = KGENOME_ELFCLASS_64;
	E.elf_data = KGENOME_ELFDATA_LE;
	E.e_type = 2;
	E.entry_addr = TEXT_VA;
	E.seg_count = 2;
	E.sec_count = 2;
	E.seg[0].type = 1; E.seg[0].perm = KGENOME_PERM_R | KGENOME_PERM_X; E.seg[0].file_off = 0; E.seg[0].file_size = 0x300;
	E.seg[0].mem_addr = 0x400000; E.seg[0].mem_size = 0x300;
	E.seg[1].type = 1; E.seg[1].perm = KGENOME_PERM_R | KGENOME_PERM_W; E.seg[1].file_off = DATA_OFF;
	E.seg[1].file_size = FILE_SIZE - DATA_OFF; E.seg[1].mem_addr = DATA_VA; E.seg[1].mem_size = FILE_SIZE - DATA_OFF;
	snprintf(E.sec[0].name, sizeof E.sec[0].name, ".text");
	E.sec[0].type = 1; E.sec[0].flags = 6; E.sec[0].file_off = TEXT_OFF; E.sec[0].file_size = 0x80; E.sec[0].mem_addr = TEXT_VA;
	snprintf(E.sec[1].name, sizeof E.sec[1].name, ".data");
	E.sec[1].type = 1; E.sec[1].flags = 3; E.sec[1].file_off = DATA_OFF; E.sec[1].file_size = FILE_SIZE - DATA_OFF;
	E.sec[1].mem_addr = DATA_VA;
	O.format = KGENOME_FMT_ELF;
	O.arch = KGENOME_ARCH_X86_64;
	O.subtype = 2;
	O.obj_size = FILE_SIZE;
	O.entry_off = TEXT_OFF;
	O.file_header = &E;
}

static struct kgenome_xref *MAP;
static enum kgenome_status XS;

static enum kgenome_status facts(uint64_t off, uint64_t size, uint64_t va, struct kgenome_xref *map, const struct kgenome_budget *b,
				 struct kgenome_range_facts *f)
{
	struct kgenome_range_req rq;

	memset(&rq, 0, sizeof rq);
	rq.obj = &O;
	rq.file = kof_buf_make(file, FILE_SIZE);
	rq.off = off;
	rq.size = size;
	rq.va = va;
	rq.xref = map;
	rq.xref_status = XS;
	rq.budget = b;
	return kgenome_range_facts(&rq, f);
}

static uint32_t refs_sum(const struct kgenome_range_facts *f)
{
	return f->refs.call + f->refs.jump + f->refs.read + f->refs.write + f->refs.arg + f->refs_ptr;
}

static void ordinary_variables(void)
{
	struct kgenome_range_facts f;

	build();
	XS = kgenome_range_xref_build(&O, kof_buf_make(file, FILE_SIZE), NULL, &MAP);
	CK(XS == KGENOME_OK && MAP != NULL);

	/* the payload: code refers to it (lea, then call through the register), a table points at it, it decodes, it has a syscall */
	CK(facts(PAY, 16, va_of(PAY), MAP, NULL, &f) == KGENOME_OK);
	CK(f.refs_known && !f.refs_partial && f.refs.read >= 1u && f.refs.call >= 1u && f.refs_ptr == 1u);
	CK(f.decodes && f.decode_pct == 100u && f.syscall && f.shape == KGENOME_RANGE_CODE_LIKE && f.analysed == 16u);
	/* 8 distinct bytes of 16 (0x90 eight times, seven others once each... the oracle counts them): entropy from the histogram */
	{
		uint32_t h[256] = { 0 }, i;
		double e = 0;

		for (i = 0; i < 16; i++)
			h[file[PAY + i]]++;
		for (i = 0; i < 256; i++)
			if (h[i])
				e -= (h[i] / 16.0) * (__builtin_log2(h[i] / 16.0));
		CK(f.entropy_centi >= (uint32_t)(e * 100.0) - 1u && f.entropy_centi <= (uint32_t)(e * 100.0) + 1u);
	}

	/* text: nobody refers to it, it is text, it decodes as little as text does and has no system call */
	CK(facts(STR, 24, va_of(STR), MAP, NULL, &f) == KGENOME_OK);
	CK(f.refs_known && refs_sum(&f) == 0u && f.shape == KGENOME_RANGE_TEXT && !f.syscall);
	/* the table: eight address words (one of them the payload's) */
	CK(facts(TBL, 64, va_of(TBL), MAP, NULL, &f) == KGENOME_OK);
	CK(f.shape == KGENOME_RANGE_TABLE && !f.syscall && refs_sum(&f) == 0u);
	/* zeros */
	CK(facts(ZER, 32, va_of(ZER), MAP, NULL, &f) == KGENOME_OK);
	CK(f.shape == KGENOME_RANGE_EMPTY && f.entropy_centi == 0u && refs_sum(&f) == 0u);
	/* the same instructions as the payload, referred to by nothing: the facts differ only in the references */
	CK(facts(UNR, 16, va_of(UNR), MAP, NULL, &f) == KGENOME_OK);
	CK(f.refs_known && refs_sum(&f) == 0u && f.decode_pct == 100u && f.syscall && f.shape == KGENOME_RANGE_CODE_LIKE);
	/* 256 bytes in which every value occurs once: exactly 8 bits a byte, random */
	CK(facts(RND, 256, va_of(RND), MAP, NULL, &f) == KGENOME_OK);
	CK(f.entropy_centi == 800u && f.shape == KGENOME_RANGE_RANDOM);
	/* without a map the references are not asked and say so */
	CK(facts(PAY, 16, va_of(PAY), NULL, NULL, &f) == KGENOME_OK);
	CK(!f.refs_known && f.refs.call == 0u && f.refs.read == 0u && f.decode_pct == 100u);
	/* a cut map says "partial" through its status */
	XS = KGENOME_TRUNCATED;
	CK(facts(UNR, 16, va_of(UNR), MAP, NULL, &f) == KGENOME_OK && f.refs_partial);
	XS = KGENOME_OK;
}

static void bounds_and_hostile(void)
{
	struct kgenome_range_facts f;
	struct kgenome_budget b;
	struct kgenome_range_req rq;

	/* a range over the default cap (8 KiB): judged by its first bytes, said TRUNCATED */
	CK(facts(0x700, 0x4000, va_of(0x700), MAP, NULL, &f) == KGENOME_TRUNCATED && f.analysed == KGENOME_RANGE_BYTES);
	/* the caller's budget, in steps: OVER_BUDGET, and exactly that many bytes read */
	memset(&b, 0, sizeof b);
	b.max_steps = 4;
	CK(facts(PAY, 16, va_of(PAY), MAP, &b, &f) == KGENOME_OVER_BUDGET && f.analysed == 4u);
	b.max_steps = 16;
	CK(facts(PAY, 16, va_of(PAY), MAP, &b, &f) == KGENOME_OK && f.analysed == 16u);
	/* a size past the end of the file is clipped to it; an offset past the end, a size of zero and an offset of -1 are BAD_INPUT */
	CK(facts(FILE_SIZE - 8u, 0x1000, 0, MAP, NULL, &f) == KGENOME_OK && f.analysed == 8u);
	CK(facts(FILE_SIZE, 8, 0, MAP, NULL, &f) == KGENOME_BAD_INPUT && f.analysed == 0u);
	CK(facts(~0ull, 8, 0, MAP, NULL, &f) == KGENOME_BAD_INPUT);
	CK(facts(PAY, 0, 0, MAP, NULL, &f) == KGENOME_BAD_INPUT);
	CK(facts(PAY, ~0ull, va_of(PAY), MAP, NULL, &f) == KGENOME_TRUNCATED && f.analysed == KGENOME_RANGE_BYTES);
	CK(facts(PAY, 16, ~0ull - 4u, MAP, NULL, &f) == KGENOME_OK);        /* an address that wraps: no read outside */
	/* no object, an object with no parsed view, a format that is neither */
	memset(&rq, 0, sizeof rq);
	rq.file = kof_buf_make(file, FILE_SIZE);
	rq.off = PAY;
	rq.size = 16;
	CK(kgenome_range_facts(&rq, &f) == KGENOME_BAD_INPUT);
	O.file_header = NULL;
	CK(facts(PAY, 16, 0, NULL, NULL, &f) == KGENOME_BAD_INPUT);
	O.file_header = &E;
	O.format = KGENOME_FMT_NONE;
	CK(facts(PAY, 16, 0, NULL, NULL, &f) == KGENOME_BAD_INPUT);
	O.format = KGENOME_FMT_ELF;
	/* the xref build refuses what is not parsed, and says UNSUPPORTED for an architecture the sweep does not track */
	{
		struct kgenome_xref *m = (struct kgenome_xref *)1;

		CK(kgenome_range_xref_build(NULL, kof_buf_make(file, FILE_SIZE), NULL, &m) == KGENOME_BAD_INPUT && m == NULL);
		O.arch = KGENOME_ARCH_RISCV64;
		CK(kgenome_range_xref_build(&O, kof_buf_make(file, FILE_SIZE), NULL, &m) == KGENOME_UNSUPPORTED && m == NULL);
		CK(facts(PAY, 16, va_of(PAY), NULL, NULL, &f) == KGENOME_OK && !f.decodes && f.decode_pct == 0u && !f.syscall);
		O.arch = KGENOME_ARCH_X86_64;
		/* the code bound: the caller says 4 bytes of code, the sweep is cut and the map says so */
		{
			struct kgenome_budget bb;

			memset(&bb, 0, sizeof bb);
			bb.max_steps = 4;
			CK(kgenome_range_xref_build(&O, kof_buf_make(file, FILE_SIZE), &bb, &m) == KGENOME_OVER_BUDGET && m != NULL);
			kgenome_xref_free(m);
		}
	}
	/* kgenome_xref_refs on a range that wraps, at address zero and on an empty map */
	{
		struct kgenome_xref_refs z;
		struct kgenome_xref *empty = kgenome_xref_new();

		kgenome_xref_refs(MAP, ~0ull - 3u, ~0ull, &z);
		CK(z.call == 0u && z.read == 0u);
		kgenome_xref_refs(MAP, 0, 100, &z);
		CK(z.call == 0u && z.read == 0u);
		kgenome_xref_refs(empty, va_of(PAY), 16, &z);
		CK(z.call == 0u && z.read == 0u && z.write == 0u && z.jump == 0u && z.arg == 0u);
		kgenome_xref_free(empty);
	}
}

/* Each decoder the library has: a few instructions of that architecture with a system call. */
static void architectures(void)
{
	static const struct {
		unsigned arch; int be; const uint8_t code[16]; unsigned n; const char *name;
	} t[] = {
		{ KGENOME_ARCH_ARM64, 0, { 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6 }, 12, "aarch64: mov x8,#93; svc #0; ret" },
		{ KGENOME_ARCH_ARM, 0, { 0x01, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x1e, 0xff, 0x2f, 0xe1 }, 12, "arm: mov r7,#1; svc 0; bx lr" },
		{ KGENOME_ARCH_X86, 0, { 0x31, 0xc0, 0x40, 0xcd, 0x80, 0xc3 }, 6, "x86: xor eax,eax; inc eax; int 0x80; ret" },
		{ KGENOME_ARCH_X86_64, 0, { 0x0f, 0x05, 0xc3, 0x90 }, 4, "x86-64: syscall; ret; nop" },
	};
	struct kgenome_range_facts f;
	unsigned i;

	build();
	for (i = 0; i < sizeof t / sizeof t[0]; i++) {
		memcpy(file + 0x800, t[i].code, t[i].n);
		O.arch = (uint8_t)t[i].arch;
		CK(facts(0x800, t[i].n, va_of(0x800), NULL, NULL, &f) == KGENOME_OK);
		if (!(f.decodes && f.decode_pct == 100u && f.syscall))
			printf("  architecture %s: decodes %u pct %u syscall %u\n", t[i].name, f.decodes, f.decode_pct, f.syscall);
		CK(f.decodes && f.decode_pct == 100u && f.syscall);
		/* a decode share proves nothing on a fixed-width ISA: without a reference from code the class is MIXED, never code-like */
		if (t[i].arch == KGENOME_ARCH_ARM || t[i].arch == KGENOME_ARCH_ARM64)
			CK(f.shape == KGENOME_RANGE_MIXED);
		else
			CK(f.shape == KGENOME_RANGE_CODE_LIKE);
		/* the same bytes with no system call in them: the bit is the instruction's and not the file's */
	}
	memcpy(file + 0x800, "\x90\x90\x90\x90\xc3", 5);
	O.arch = KGENOME_ARCH_X86_64;
	CK(facts(0x800, 5, va_of(0x800), NULL, NULL, &f) == KGENOME_OK && f.decode_pct == 100u && !f.syscall);
	/* an int that is not 0x80 is not a system call */
	memcpy(file + 0x800, "\xcd\x21\xc3", 3);
	CK(facts(0x800, 3, va_of(0x800), NULL, NULL, &f) == KGENOME_OK && !f.syscall);
}

/* A PE: the same facts over an image whose addresses are image base + RVA. */
static void pe_image(void)
{
	static struct kgenome_pe_info P;
	static struct kgenome_obj PO;
	struct kgenome_xref *m = NULL;
	struct kgenome_range_facts f;
	struct kgenome_range_req rq;

	memset(file, 0, sizeof file);
	memset(&P, 0, sizeof P);
	memset(&PO, 0, sizeof PO);
	P.valid = 1;
	P.pe32_plus = 1;
	P.image_base = 0x140000000ull;
	P.sec_count = 2;
	P.nsec = 2;
	P.entry_rva = 0x1000;
	snprintf(P.sec[0].name, sizeof P.sec[0].name, ".text");
	P.sec[0].mem_rva = 0x1000; P.sec[0].mem_size = 0x100; P.sec[0].file_off = 0x400; P.sec[0].file_size = 0x200;
	P.sec[0].perm = KGENOME_PE_PERM_R | KGENOME_PE_PERM_X;
	snprintf(P.sec[1].name, sizeof P.sec[1].name, ".data");
	P.sec[1].mem_rva = 0x2000; P.sec[1].mem_size = 0x200; P.sec[1].file_off = 0x800; P.sec[1].file_size = 0x200;
	P.sec[1].perm = KGENOME_PE_PERM_R | KGENOME_PE_PERM_W;
	/* .text: lea rax,[rip+disp] to the data at RVA 0x2010 ; call rax ; ret */
	file[0x400] = 0x48; file[0x401] = 0x8d; file[0x402] = 0x05;
	put32(file + 0x403, (uint32_t)(0x2010u - (0x1000u + 7u)));
	file[0x407] = 0xff; file[0x408] = 0xd0; file[0x409] = 0xc3;
	memset(file + 0x40a, 0x90, 0x50);
	memcpy(file + 0x810, "\x0f\x05\xc3\x90\x90\x90\x90\x90", 8);
	put64(file + 0x900, 0x140002010ull);                       /* a pointer to it in the data */
	PO.format = KGENOME_FMT_PE;
	PO.arch = KGENOME_ARCH_X86_64;
	PO.obj_size = 0xc00;
	PO.entry_off = 0x400;
	PO.file_header = &P;
	CK(kgenome_range_xref_build(&PO, kof_buf_make(file, 0xc00), NULL, &m) == KGENOME_OK && m != NULL);
	memset(&rq, 0, sizeof rq);
	rq.obj = &PO;
	rq.file = kof_buf_make(file, 0xc00);
	rq.off = 0x810;
	rq.size = 8;
	rq.va = 0x140002010ull;
	rq.xref = m;
	CK(kgenome_range_facts(&rq, &f) == KGENOME_OK);
	CK(f.refs_known && f.refs.read >= 1u && f.refs.call >= 1u && f.refs_ptr == 1u && f.decode_pct == 100u && f.syscall &&
	   f.shape != KGENOME_RANGE_TEXT);
	kgenome_xref_free(m);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	ordinary_variables();
	bounds_and_hostile();
	kgenome_xref_free(MAP);
	architectures();
	pe_image();
	printf("range_facts: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
