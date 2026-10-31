/*
 * genome / diag_code_run_be - kgenome_diag_code_run reads a big-endian object in its own byte order (CN-1).
 *
 * THE DEFECT. The run decoded the bytes it had no trace for with kgenome_cell_decode(obj->arch, 0, ...): always little-endian. A MIPS-BE or
 * ARM-BE object was therefore read byte-reversed by every walk that goes through the run (codemap, lineage, the xref feed, callnames, elfimp,
 * the CFG of a function): `sw $v0,12($fp)` (the word 0xafc2000c, bytes af c2 00 0c) read as 0x0c00c2af, which is a `jal`; 21084 of 21390 direct
 * call references of 11 MIPS-BE files had no target (fix_consol/matrix.md).
 *
 * WHAT IS PINNED, with no engine and no file: objects described to the lib at run time (an ELF header record of either byte order), code
 * assembled by the cfg kit's writer (abstract programs spelled in MIPS-BE, ARM-BE, MIPS-LE, ARM-LE, x86-64: random graphs, 3000 words of each), and
 *   HAND      the one word 0xafc2000c in a MIPS-BE object is a store, not a call (and has no target); the word 0x0c000100 in a MIPS-BE object
 *             is a `jal` whose target is 0x400 (index 0x100 << 2), the same words little-endian read the other way round;
 *   RUN       the instruction stream the run delivers equals the stream the lib's decoder gives DIRECTLY on the same bytes with the object's
 *             byte order (op, length, offset, address, branch target, flags), for every architecture and both byte orders;
 *   BE8       an ARM object whose code is little-endian although its data is big-endian (EF_ARM_BE8) is decoded little-endian.
 * Why the old tests missed it: (a) no test ran the run's untraced branch on a non-x86 object, so its decode line was never executed with be set;
 * (b) the cfg tests decoded with the lib directly, never through the run; (c) the engine rows asked only that a graph exists.
 */
#include "cfg_kit.h"

#include <phenotype/diag_scan.h>
#include <genotype/image/obj.h>

struct got {
	struct kgenome_cell_insn *v;
	uint32_t n, cap, skipped;
};

static void collect(void *user, const struct kgenome_cell_insn *in)
{
	struct got *g = user;

	if (!in) {
		g->skipped++;
		return;
	}
	if (g->n == g->cap) {
		g->cap = g->cap ? g->cap * 2u : 64u;
		g->v = realloc(g->v, (size_t)g->cap * sizeof *g->v);
	}
	g->v[g->n++] = *in;
}

static const struct isa_t ISA_ARM_BE = { KGENOME_ARCH_ARM, 1, "arm-be" };

/* The run over `code` as an object of this architecture and byte order. */
static void run(unsigned arch, int be, uint32_t e_flags, const uint8_t *code, uint32_t len, uint64_t va, struct got *g)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj obj;

	memset(g, 0, sizeof *g);
	memset(&ei, 0, sizeof ei);
	memset(&obj, 0, sizeof obj);
	ei.elf_data = be ? KGENOME_ELFDATA_BE : 1;
	ei.e_flags = e_flags;
	obj.format = KGENOME_FMT_ELF;
	obj.arch = (uint8_t)arch;
	obj.obj_size = len;
	obj.file_header = &ei;
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){ .obj = &obj, .base = code, .size = len, .off = 0, .n = len, .va = va,
		.fn = collect, .user = g });
}

static void hand(void)
{
	/* sw $v0,12($fp) = 0xafc2000c; jal 0x400 = 0x0c000100; both written big-endian */
	static const uint8_t sw[4] = { 0xaf, 0xc2, 0x00, 0x0c }, jal[4] = { 0x0c, 0x00, 0x01, 0x00 };
	struct got g;

	run(KGENOME_ARCH_MIPS, 1, 0, sw, 4, 0x400000u, &g);
	CKM(g.n == 1u && g.v[0].op != KGENOME_CELL_CALL, "a big-endian `sw` word read as op %d: a call", g.n ? (int)g.v[0].op : -1);
	CKM(g.n == 1u && g.v[0].target_va == KGENOME_BROKEN, "a store has no branch target (got %llx)", g.n ? (unsigned long long)g.v[0].target_va : 0ull);
	free(g.v);
	run(KGENOME_ARCH_MIPS, 1, 0, jal, 4, 0x400000u, &g);
	CKM(g.n == 1u && g.v[0].op == KGENOME_CELL_CALL, "a big-endian `jal` word is not a call (op %d)", g.n ? (int)g.v[0].op : -1);
	CKM(g.n == 1u && g.v[0].target_va == 0x400u, "the target of the `jal` is %llx, not 0x400", g.n ? (unsigned long long)g.v[0].target_va : 0ull);
	free(g.v);
	/* the same four bytes in a little-endian object are the OTHER instruction: the byte order is the object's, not a constant */
	run(KGENOME_ARCH_MIPS, 0, 0, sw, 4, 0x400000u, &g);
	CKM(g.n == 1u && g.v[0].op == KGENOME_CELL_CALL, "the bytes of the `sw` in a little-endian object are a `jal`");
	free(g.v);
}

static int same(const struct kgenome_cell_insn *a, const struct kgenome_cell_insn *b)
{
	return a->op == b->op && a->len == b->len && a->at == b->at && a->at_va == b->at_va && a->target_va == b->target_va && a->flags == b->flags;
}

static void stream(const struct isa_t *isa, uint32_t e_flags, unsigned seeds)
{
	struct crng rng;
	unsigned s, k;
	uint32_t total = 0, bad = 0, first_bad = 0;

	crng_seed(&rng, 31001u + isa->arch * 7u + (unsigned)isa->be);
	for (s = 0; s < seeds; s++) {
		struct prog p;
		struct blob x;
		struct kgenome_cell_insn *ref = NULL;
		struct got g;
		uint32_t n;

		prog_random(isa, &rng, 8u + s % 40u, &p);
		if (!blob_make(isa, &p, 0x400000u, &x)) {
			prog_free(&p);
			continue;
		}
		n = blob_decode(isa, &x, &ref);
		run(isa->arch, isa->be, e_flags, x.b, x.len, 0x400000u, &g);
		if (g.n != n || g.skipped) {
			if (!bad++)
				first_bad = s;
		} else {
			for (k = 0; k < n; k++)
				if (!same(&ref[k], &g.v[k])) {
					if (!bad++)
						first_bad = s;
					break;
				}
		}
		total += n;
		free(g.v);
		free(ref);
		blob_free(&x);
		prog_free(&p);
	}
	CKM(total > 0, "%s: nothing was compared", isa->name);
	CKM(!bad, "%s: the run's stream differs from the lib's decode of the same bytes in %u of %u programs (first: seed %u)", isa->name, bad, seeds, first_bad);
}

/* BE8: the data is big-endian, the instruction words are not. The stream must be the little-endian one. */
static void be8(void)
{
	struct crng rng;
	unsigned s;
	static const struct isa_t arm_le = { KGENOME_ARCH_ARM, 0, "arm-le" };

	crng_seed(&rng, 777u);
	for (s = 0; s < 40u; s++) {
		struct prog p;
		struct blob x;
		struct kgenome_cell_insn *ref = NULL;
		struct got g;
		uint32_t n, k;

		prog_random(&arm_le, &rng, 10u + s % 20u, &p);
		if (!blob_make(&arm_le, &p, 0x400000u, &x)) {
			prog_free(&p);
			continue;
		}
		n = blob_decode(&arm_le, &x, &ref);
		run(KGENOME_ARCH_ARM, 1, KGENOME_ELF_EF_ARM_BE8, x.b, x.len, 0x400000u, &g);
		CKM(g.n == n, "be8 seed %u: %u instructions, the little-endian decoder %u", s, g.n, n);
		for (k = 0; k < n && k < g.n; k++)
			CKM(same(&ref[k], &g.v[k]), "be8 seed %u: instruction %u differs", s, k);
		free(g.v);
		free(ref);
		blob_free(&x);
		prog_free(&p);
	}
}

int main(void)
{
	unsigned i;

	hand();
	for (i = 0; i < N_ISAS; i++)
		stream(&ISAS[i], 0, 3000u);
	stream(&ISA_ARM_BE, 0, 3000u);
	be8();
	if (fails) {
		printf("diag_code_run_be: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_code_run_be: ok\n");
	return 0;
}
