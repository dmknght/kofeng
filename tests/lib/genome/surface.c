/*
 * genome / surface - every part of libgenome reached through <kgenome.h> alone,
 * linked against libkgenome.a and nothing else.
 *
 * budget_status.c proves the lib stands without the engine for the budget, the
 * ledger, one diagnose scan, the emulator and the x86 front end. A static
 * archive links only the members a test reaches, so a symbol of the ENGINE
 * referenced from a part nothing in that file touches is not an undefined
 * reference there - the gap this file closes. It reaches the rest of the surface:
 *
 *   genotype   the ARM, Thumb, AArch64, MIPS and x86 decoders (each through its
 *              own entry and through the one way in, kgenome_cell_decode), the ELF
 *              image parse, the PE and CLR readers and the PE layout reader (on
 *              bytes that are not one: they refuse)
 *   celllysis  the cross-reference sweep, the library-span finder, the mutation
 *              window (pool, minhash)
 *
 * Each call is checked for what it must answer, so the file is also a test that
 * a part works when it is the only thing in the process - but the point is the
 * link: one engine symbol reached from any of these is an undefined reference
 * here, at build time.
 */

#include <kgenome.h>

#include <stdio.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void decoders(void)
{
	struct kgenome_cell_insn in;
	/* xor eax,eax ; syscall */
	static const uint8_t x86[] = { 0x31, 0xc0, 0x0f, 0x05 };
	/* mov r0,#1 (ARM, little-endian) */
	static const uint8_t a32[] = { 0x01, 0x00, 0xa0, 0xe3 };
	/* bx lr (Thumb) */
	static const uint8_t thb[] = { 0x70, 0x47 };
	/* movz x0,#1 ; ret */
	static const uint8_t a64[] = { 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6 };
	/* addiu a0,zero,1 (MIPS, little-endian) */
	static const uint8_t mip[] = { 0x01, 0x00, 0x04, 0x24 };

	memset(&in, 0, sizeof in);
	CK(kgenome_cell_decode_x86(x86, sizeof x86, 0x1000, 64, &in) == 2u);
	CK(in.op == KGENOME_CELL_XOR);
	CK(kgenome_cell_decode_x86(x86 + 2, 2, 0x1002, 64, &in) == 2u);
	CK(in.op == KGENOME_CELL_SYSCALL);
	/* the one way in agrees with the entry it dispatches to */
	CK(kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, x86 + 2, 2, 0x1002, &in) == 2u);
	CK(in.op == KGENOME_CELL_SYSCALL);

	CK(kgenome_cell_decode_arm32(a32, sizeof a32, 0x8000, 0, &in) == 4u);
	CK(in.op == KGENOME_CELL_MOV);
	CK(kgenome_cell_decode_thumb(thb, sizeof thb, 0x8000, 0, &in) == 2u);
	CK(in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_JMP);
	CK(kgenome_cell_decode_arm64(a64, sizeof a64, 0x10000, &in) == 4u);
	CK(in.op == KGENOME_CELL_MOV);
	CK(kgenome_cell_decode_arm64(a64 + 4, 4, 0x10004, &in) == 4u);
	CK(in.op == KGENOME_CELL_RET);
	CK(kgenome_cell_decode_mips(mip, sizeof mip, 0x400000, 0, &in) == 4u);

	/* too short is "not an instruction", never a read past the end */
	CK(kgenome_cell_decode_arm64(a64, 3, 0, &in) == 0u);
	CK(kgenome_cell_decode_arm32(a32, 2, 0, 0, &in) == 0u);
	CK(kgenome_cell_decode_x86(x86, 0, 0, 64, &in) == 0u);
}

/* An x86-64 ELF: one RWX PT_LOAD from offset zero, entry at +0x78, `n` code bytes. */
static uint64_t elf64(uint8_t *b, const uint8_t *code, uint64_t n)
{
	uint64_t v;
	unsigned i;

	memset(b, 0, 0x78u + n);
	memcpy(b, "\177ELF\2\1\1", 7);
	b[16] = 2; b[18] = 0x3e; b[20] = 1;                     /* ET_EXEC, x86-64 */
	v = 0x400078u;
	for (i = 0; i < 8; i++) b[24 + i] = (uint8_t)(v >> (8 * i));
	b[32] = 64;                                             /* e_phoff         */
	b[52] = 64; b[54] = 56; b[56] = 1;                      /* ehsize, phentsize, phnum */
	b[64] = 1; b[68] = 7;                                   /* PT_LOAD, RWX    */
	v = 0x400000u;
	for (i = 0; i < 8; i++) b[80 + i] = (uint8_t)(v >> (8 * i));
	v = 0x78u + n;
	for (i = 0; i < 8; i++) { b[96 + i] = (uint8_t)(v >> (8 * i)); b[104 + i] = (uint8_t)(v >> (8 * i)); }
	memcpy(b + 0x78, code, (size_t)n);
	return 0x78u + n;
}

static void image_and_sweeps(void)
{
	static uint8_t file[512];
	/* mov eax,60 ; xor edi,edi ; syscall */
	static const uint8_t code[] = { 0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05 };
	struct kgenome_elf_info info;
	struct kgenome_obj obj;
	struct kgenome_true_result tr;
	struct kgenome_true_all ta;
	struct kgenome_xref *x;
	struct kgenome_cell_insn in;
	kof_buf buf;
	uint64_t len = elf64(file, code, sizeof code);

	buf.p = file;
	buf.n = len;
	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_elf_sniff(buf));
	CK(kgenome_elf_image_parse(buf, &info, &obj));
	CK(info.valid);
	CK(info.seg_count == 1);
	CK(obj.arch == KGENOME_ARCH_X86_64);

	/* the library-span finders never fail: a file with none yields nothing */
	memset(&tr, 0xff, sizeof tr);
	kgenome_true_find(buf, &info, &tr);
	CK(tr.n == 0);
	memset(&ta, 0xff, sizeof ta);
	kgenome_true_find_all(buf, &info, &ta);
	CK(ta.n == 0);

	/* the cross-reference sweep: a new map, a run begun and fed, freed */
	x = kgenome_xref_new();
	CK(x != NULL);
	if (x) {
		memset(&in, 0, sizeof in);
		kgenome_xref_begin(x, KGENOME_ARCH_X86_64);
		CK(kgenome_cell_decode_x86(code, sizeof code, 0x400078, 64, &in) == 5u);
		in.at_va = 0x400078;
		kgenome_xref_feed(x, &in);
		CK(!kgenome_xref_full(x));
		CK(kgenome_xref_in(x, 0x400000, 0x1000) == 0u);   /* nothing is named */
		kgenome_xref_free(x);
	}
}

static uint64_t no_rva(const void *user, uint64_t rva)
{
	(void)user; (void)rva;
	return (uint64_t)-1;
}

/* The PE, CLR and rewrite parts, on bytes that are none of them: each says so. */
static void formats_refuse_garbage(void)
{
	static uint8_t junk[256];
	struct kgenome_pe_info pe;
	struct kgenome_obj obj;
	struct kgenome_clr_meta meta;
	struct kgenome_sec_decl sec[4];
	struct kgenome_dir_decl dir;
	uint64_t entry = 1, base = 1;
	kof_buf buf;
	unsigned i;

	for (i = 0; i < sizeof junk; i++)
		junk[i] = (uint8_t)(i * 29u + 3u);
	buf.p = junk;
	buf.n = sizeof junk;
	memset(&pe, 0, sizeof pe);
	memset(&obj, 0, sizeof obj);
	memset(&meta, 0, sizeof meta);
	memset(&dir, 0, sizeof dir);
	CK(!kgenome_pe_image_parse(buf, &pe, &obj));
	CK(!kgenome_clr_read(buf, 0, no_rva, NULL, &meta));
	CK(kgenome_pe_layout_of(buf, sec, 4, &entry, &base, &dir) == 0u);
}

static void mutation_window(void)
{
	uint8_t p[4096];
	uint32_t a[KGENOME_MUTATION_MINHASH_K], b[KGENOME_MUTATION_MINHASH_K];
	uint32_t s = 0x1234567u, na, nb, i;

	for (i = 0; i < sizeof p; i++) {
		s ^= s << 13; s ^= s >> 17; s ^= s << 5;
		p[i] = (uint8_t)s;
	}
	na = kgenome_mutation_minhash(p, sizeof p, 0, a);
	nb = kgenome_mutation_minhash(p, sizeof p, 0, b);
	CK(na > 0 && na == nb);
	CK(!memcmp(a, b, na * sizeof a[0]));
	for (i = 1; i < na; i++)
		CK(a[i - 1] < a[i]);                    /* ascending, distinct */
}

int main(void)
{
	decoders();
	image_and_sweeps();
	formats_refuse_garbage();
	mutation_window();
	printf("genome surface: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
