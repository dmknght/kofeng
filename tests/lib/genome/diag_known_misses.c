/*
 * genome / diag_known_misses - the defects of the diagnose / graph stage that the fuzz and the sweeps of work package 9 found, each as ONE
 * deterministic row built by hand, written as the EXPECTATION and recorded with KM_CHECK (known_miss.h): green while the engine has the defect,
 * red the day it does not (then the row becomes a CK). No row here is a guess: each was measured on this tree; the reproducer is the builder
 * below, and the fuzz input that found it is in tests_wp9/findings/.
 *
 *   F1   kgenome_diag_code_bytes SUMS the extents, so overlapping segments count a byte once each: a file of N bytes claims 3 N of code, and
 *        the budget is scaled from it (max_insn = 64 x code_bytes, max_nodes = code / 8). Why the old tests missed it: (b) they build one
 *        segment, never two that overlap.
 *   F2   kgenome_diag_apihash_run's first slice is 16000 instructions whatever max_insn_resolve says (DIAG_PE_SLICE), so a budget below the
 *        slice is overshot; the engine passes "what the tree's allowance has left" as that budget. (b) no test gave it a budget under the slice.
 *   F3   kgenome_codemap_free(NULL) dereferences NULL; every other free of the stage (scan, walk, apihash, names, xref) takes NULL. (a) the line
 *        was never executed with NULL.
 *   F4   kgenome_cell_next reports a branch target past the end of the buffer when a segment's size is past the file, or when the ELF has no
 *        program header (read as one flat space): the header says KGENOME_BROKEN for "outside the object". (b)
 *   F5   kgenome_codemap_build appends the refs extent by extent in the object's order, so they are NOT in order of `at` when two code segments
 *        come in descending file order, and kgenome_codemap_at (a binary search) misses a ref that is there. (b)
 *
 * usage: diag_known_misses
 */
#include <sys/wait.h>

#include "../../fuzz/diag/diag_seed.h"
#include "../../unit/known_miss.h"

#include <phenotype/codemap.h>
#include <celllysis/xref.h>
#include <phenotype/diag_text_names.h>

/* An ELF64 with `nseg` PT_LOAD segments, each described by {offset, filesz, memsz, flags}; `code` at `code_at`. Returns the file size. */
struct seg {
	uint64_t off, filesz, memsz;
	uint32_t flags;
};

static unsigned elf64_segs(uint8_t *b, unsigned size, const struct seg *sg, unsigned nseg, unsigned phnum_claim)
{
	unsigned i;

	memset(b, 0, size);
	memcpy(b, "\177ELF\2\1\1", 7);
	b[16] = 2; b[18] = 0x3e; b[20] = 1;
	ds_p64(b, 24, 0x400000u + 0x100u);
	ds_p64(b, 32, 64);
	b[52] = 64; b[54] = 56; b[56] = (uint8_t)phnum_claim;
	for (i = 0; i < nseg; i++) {
		uint8_t *p = b + 64u + 56u * i;

		ds_p32(p, 0, 1);
		ds_p32(p, 4, sg[i].flags);
		ds_p64(p, 8, sg[i].off);
		ds_p64(p, 16, 0x400000u + sg[i].off);
		ds_p64(p, 24, 0x400000u + sg[i].off);
		ds_p64(p, 32, sg[i].filesz);
		ds_p64(p, 40, sg[i].memsz);
		ds_p64(p, 48, 0x1000);
	}
	return size;
}

static uint8_t img[0x1000];
static struct kgenome_elf_info ei;
static struct kgenome_obj obj;

static int parse_elf(unsigned n)
{
	memset(&ei, 0, sizeof ei);
	memset(&obj, 0, sizeof obj);
	if (!kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &obj))
		return 0;
	obj.file_header = &ei;
	return 1;
}

/* ---- F1 --------------------------------------------------------------------------------------------------------------------- */

static void f1(void)
{
	struct seg one[1] = { { 0, 0x400, 0x400, 5 } }, three[3] = { { 0, 0x400, 0x400, 5 }, { 0, 0x400, 0x400, 5 }, { 0, 0x400, 0x400, 5 } };
	uint64_t a, b;

	elf64_segs(img, 0x400, one, 1, 1);
	CK(parse_elf(0x400));
	a = kgenome_diag_code_bytes(&obj, 0x400);
	CK(a <= 0x400u);                                   /* the control: one segment, at most the file */
	elf64_segs(img, 0x400, three, 3, 3);
	CK(parse_elf(0x400));
	b = kgenome_diag_code_bytes(&obj, 0x400);
	/* KNOWN DEFECT WP9-F1 (2026-10-25, M): this row pins it, green until fixed. */
	KM_CHECK(b <= 0x400u, "F1 three overlapping executable segments claim more code bytes than the file holds", "diag_code.c kgenome_diag_code_bytes sums extents");
}

/* ---- F2 --------------------------------------------------------------------------------------------------------------------- */

static void f2(void)
{
	static struct hk_pe p;
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_budget bud;
	struct kgenome_diag_apihash_set *a;
	uint64_t spent = 0, big = 0;

	ds_pe(&p, 2u | 8u);                                /* the loader-data read, then a spin: the run ends only by its budget */
	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &pi, &o));
	o.file_header = &pi;
	kgenome_budget_default(&bud, p.n, kgenome_diag_code_bytes(&o, p.n));
	bud.max_insn = bud.max_insn_resolve = 100;
	bud.insn_spent = &spent;
	a = kgenome_diag_apihash_run(&o, p.b, p.n, NULL, &bud);
	CK(a != NULL);
	if (a) {
		CK(a->n_ldr > 0);                          /* the run did happen: the control of the row */
		kgenome_diag_apihash_free(a);
	}
	bud.max_insn = bud.max_insn_resolve = 1000000;
	bud.insn_spent = &big;
	a = kgenome_diag_apihash_run(&o, p.b, p.n, NULL, &bud);
	CK(a != NULL);
	if (a)
		kgenome_diag_apihash_free(a);
	printf("  F2 row: budget 100, spent %llu; budget 1000000, spent %llu\n", (unsigned long long)spent, (unsigned long long)big);
	/* KNOWN DEFECT WP9-F2 (2026-10-25, M): this row pins it, green until fixed. */
	KM_CHECK(spent <= 100u, "F2 a resolver budget of 100 instructions is spent past 100", "diag_apihash.c DIAG_PE_SLICE first slice");
	CK(big <= 1000000u + 16000u);                      /* a budget over the slice is kept to within a slice */
}

/* ---- F3 --------------------------------------------------------------------------------------------------------------------- */

static int free_null(void *arg)
{
	switch (*(int *)arg) {
	case 0: kgenome_diag_scan_free(NULL); break;
	case 1: kgenome_diag_walk_free(NULL); break;
	case 2: kgenome_diag_apihash_free(NULL); break;
	case 3: kgenome_diag_text_names_free(NULL); break;
	case 4: kgenome_xref_free(NULL); break;
	default: kgenome_codemap_free(NULL); break;
	}
	return 0;
}

static void f3(void)
{
	static const char *const what[] = { "diag_scan_free", "diag_walk_free", "diag_apihash_free", "diag_text_names_free", "xref_free", "codemap_free" };
	int i;

	for (i = 0; i < 6; i++) {
		int sig = 0, which = i;
		enum hk_result r = hk_isolated(free_null, &which, 10, &sig);

		if (i < 5) {
			if (r != HK_OK)
				printf("  FAIL kgenome_%s(NULL) did not return (result %d, signal %d)\n", what[i], (int)r, sig);
			CK(r == HK_OK);
		} else {
			/* KNOWN DEFECT WP9-F3 (2026-10-25, M): this row pins it, green until fixed. */
			KM_CHECK(r == HK_OK, "F3 kgenome_codemap_free(NULL) returns", "codemap.c kgenome_codemap_free dereferences its argument");
		}
	}
}

/* ---- F4 --------------------------------------------------------------------------------------------------------------------- */

static void run_jmp_far(const char *what, struct seg *sg, unsigned nseg, unsigned phnum, const char *cap)
{
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	unsigned n = 0x400;

	elf64_segs(img, n, sg, nseg, phnum);
	img[0x100] = 0xe9;                                  /* jmp rel32: +0x2000, far past the 0x400 bytes of the file */
	ds_p32(img, 0x101, 0x2000);
	CK(parse_elf(n));
	memset(&sp, 0, sizeof sp);
	kgenome_cell_space_init(&sp, &obj, img, n);
	memset(&k, 0, sizeof k);
	(void)kgenome_cell_seek(&k, 0x100, 0);
	memset(&in, 0, sizeof in);
	CK(kgenome_cell_next(&k, &sp, &in) == 1);
	CK(in.op == KGENOME_CELL_JMP);
	CK(in.target_va != KGENOME_BROKEN || in.target == KGENOME_BROKEN);
	/* KNOWN DEFECT WP9-F4 (2026-10-25, M): this row pins it, green until fixed. */
	KM_CHECK(in.target == KGENOME_BROKEN || in.target < n, what, cap);
}

static void f4(void)
{
	struct seg lie = { 0, 0x4000, 0x4000, 5 };         /* a segment that says it is 16 KiB in a file of 1 KiB */
	struct seg ok = { 0, 0x400, 0x400, 5 };
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;

	run_jmp_far("F4 a jump out of the file through a segment whose size is past the file has a target that is not BROKEN", &lie, 1, 1, "cursor.c va_to_off, no clamp to the buffer");
	/* the control: the honest segment makes the same jump BROKEN */
	elf64_segs(img, 0x400, &ok, 1, 1);
	img[0x100] = 0xe9;
	ds_p32(img, 0x101, 0x2000);
	CK(parse_elf(0x400));
	memset(&sp, 0, sizeof sp);
	kgenome_cell_space_init(&sp, &obj, img, 0x400);
	memset(&k, 0, sizeof k);
	(void)kgenome_cell_seek(&k, 0x100, 0);
	memset(&in, 0, sizeof in);
	CK(kgenome_cell_next(&k, &sp, &in) == 1);
	CK(in.target == KGENOME_BROKEN);
	/* an ELF with no program header: the file is one flat space */
	run_jmp_far("F4 the same jump in an ELF with no program header has a target that is not BROKEN", &ok, 0, 0, "space.c elf_seg flat space [0, 2^64)");
}

/* ---- F5 --------------------------------------------------------------------------------------------------------------------- */

static void f5(void)
{
	/* two executable segments, the second one EARLIER in the file: each holds `call +0 ; ret` */
	struct seg two[2] = { { 0x200, 0x40, 0x40, 5 }, { 0x100, 0x40, 0x40, 5 } };
	struct kgenome_codemap m;
	uint32_t i, found = 0;

	elf64_segs(img, 0x300, two, 2, 2);
	img[0x200] = 0xe8; ds_p32(img, 0x201, 0); img[0x205] = 0xc3;
	img[0x100] = 0xe8; ds_p32(img, 0x101, 0); img[0x105] = 0xc3;
	CK(parse_elf(0x300));
	memset(&m, 0, sizeof m);
	CK(kgenome_codemap_build(&obj, img, 0x300, NULL, &m) == 1);
	CK(m.n == 4);                                      /* both extents were read: four refs */
	for (i = 0; i < m.n; i++)
		found += kgenome_codemap_at(&m, m.v[i].at) == &m.v[i];
	/* KNOWN DEFECT WP9-F5 (2026-10-25, M): this row pins it, green until fixed. */
	KM_CHECK(found == m.n, "F5 kgenome_codemap_at finds every ref of a map whose code segments come in descending file order", "codemap.c refs appended extent by extent, not sorted");
	{
		int ordered = 1;

		for (i = 1; i < m.n; i++)
			ordered &= m.v[i - 1u].at < m.v[i].at;
		/* KNOWN DEFECT WP9-F5 (2026-10-25, M): this row pins it, green until fixed. */
		KM_CHECK(ordered, "F5 the refs are in strictly ascending order of at (codemap.h)", "codemap.c refs appended extent by extent, not sorted");
	}
	kgenome_codemap_free(&m);
	/* the control: ascending extents are found */
	{
		struct seg up[2] = { { 0x100, 0x40, 0x40, 5 }, { 0x200, 0x40, 0x40, 5 } };

		elf64_segs(img, 0x300, up, 2, 2);
		img[0x200] = 0xe8; ds_p32(img, 0x201, 0); img[0x205] = 0xc3;
		img[0x100] = 0xe8; ds_p32(img, 0x101, 0); img[0x105] = 0xc3;
		CK(parse_elf(0x300));
		memset(&m, 0, sizeof m);
		CK(kgenome_codemap_build(&obj, img, 0x300, NULL, &m) == 1);
		found = 0;
		for (i = 0; i < m.n; i++)
			found += kgenome_codemap_at(&m, m.v[i].at) == &m.v[i];
		CK(m.n == 4 && found == m.n);
		kgenome_codemap_free(&m);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	f1();
	f2();
	f3();
	f4();
	f5();
	km_summary();
	printf("diag_known_misses: %d failure(s), %u known, %u fixed unexpectedly\n", hk_fails, km_known_n, km_fixed_n);
	return hk_fails != 0 || km_failed();
}
