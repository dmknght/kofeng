/*
 * lineage_class - the class of an object and the plan of lineage stages for it.
 *
 * THE CLASS is read off the parse (kgenome_diag_class_of): the format, a relocatable object, a PT_INTERP, a symbol table, the
 * width, managed code. Each fact is checked on an object built to have it and without it - parsed ones where a builder exists
 * (a generated dynamic ELF with and without .symtab, a PE; a relocatable ELF), crafted parse results where none does (managed
 * code, a PE with a debug directory). THE PLAN is a table; what is checked is its contract and not its rows (the rows are the
 * measurement's, written in the graph-research report): an object the stages cannot read has none, and a plan only ever names
 * stages that exist.
 */
#include <stddef.h>
#include <kofcmp.h>
#include "lineage_check.h"

static unsigned class_of_image(const struct lg_img *g, int target)
{
	struct lg_scan sc;
	unsigned c;

	memset(&sc, 0, sizeof sc);
	if (target >= LG_T_PE64) {
		CK(kgenome_pe_image_parse(kof_buf_make(g->b, g->n), &sc.pi, &sc.obj));
		sc.obj.file_header = &sc.pi;
	} else {
		CK(kgenome_elf_image_parse(kof_buf_make(g->b, g->n), &sc.ei, &sc.obj));
		sc.obj.file_header = &sc.ei;
	}
	c = kgenome_diag_class_of(&sc.obj);
	return c;
}

static void t_generated(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	int target;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++) {
		struct lg_rng r = { 5u + (uint64_t)target };
		unsigned k, want = KGENOME_CLASS_X86 | (target == LG_T_ELF64 || target == LG_T_PE64 ? KGENOME_CLASS_WIDE : 0u) |
				   (target >= LG_T_PE64 ? KGENOME_CLASS_PE : KGENOME_CLASS_ELF);
		int sym;

		memset(&p, 0, sizeof p);
		p.nf = 1;
		p.fn[0].body = lg_newblk(&p);
		p.fn[0].dead = -1;
		CK(lg_codegen(&c, &p, &r, target));
		for (sym = 0; sym < (target >= LG_T_PE64 ? 1 : 2); sym++) {
			CK(lg_build(&g, &c, &r, sym));
			k = class_of_image(&g, target);
			CK(k == (want | (target < LG_T_PE64 ? KGENOME_CLASS_DYNAMIC : 0u) | (sym ? KGENOME_CLASS_SYMBOLS : 0u)));
		}
	}
}

static void t_crafted(void)
{
	struct kgenome_obj o;
	struct kgenome_elf_info e;
	struct kgenome_pe_info p;

	memset(&o, 0, sizeof o);
	CK(kgenome_diag_class_of(&o) == 0u);                     /* nothing parsed */
	CK(kgenome_diag_class_of(NULL) == 0u);
	/* an ELF: relocatable, no segment of type PT_INTERP, no symbol table, 32-bit x86 */
	memset(&e, 0, sizeof e);
	e.valid = 1;
	e.e_type = KGENOME_ELF_REL;
	o.format = KGENOME_FMT_ELF;
	o.arch = KGENOME_ARCH_X86;
	o.file_header = &e;
	CK(kgenome_diag_class_of(&o) == (KGENOME_CLASS_ELF | KGENOME_CLASS_REL | KGENOME_CLASS_X86 | KGENOME_CLASS_NOSECT));
	e.valid = 0;
	CK(kgenome_diag_class_of(&o) == 0u);                     /* an invalid parse says nothing */
	e.valid = 1;
	/* a PT_INTERP among the segments, found wherever it is in the table */
	e.e_type = KGENOME_ELF_EXEC;
	e.seg_count = 3;
	e.seg[2].type = 3;
	o.arch = KGENOME_ARCH_X86_64;
	CK(kgenome_diag_class_of(&o) == (KGENOME_CLASS_ELF | KGENOME_CLASS_DYNAMIC | KGENOME_CLASS_X86 | KGENOME_CLASS_WIDE | KGENOME_CLASS_NOSECT));
	/* a segment past the count the object has is not looked at */
	e.seg_count = 2;
	CK(kgenome_diag_class_of(&o) == (KGENOME_CLASS_ELF | KGENOME_CLASS_X86 | KGENOME_CLASS_WIDE | KGENOME_CLASS_NOSECT));
	/* a symbol table: SHT_SYMTAB, and not SHT_DYNSYM */
	CK(kgenome_diag_class_of(&o) & KGENOME_CLASS_NOSECT);
	e.sec_count = 2;
	CK(!(kgenome_diag_class_of(&o) & KGENOME_CLASS_NOSECT));
	e.sec[1].type = KGENOME_ELF_SHT_DYNSYM;
	CK(!(kgenome_diag_class_of(&o) & KGENOME_CLASS_SYMBOLS));
	e.sec[1].type = KGENOME_ELF_SHT_SYMTAB;
	CK(kgenome_diag_class_of(&o) & KGENOME_CLASS_SYMBOLS);
	/* a PE: managed code, a debug directory */
	memset(&p, 0, sizeof p);
	p.valid = 1;
	o.format = KGENOME_FMT_PE;
	o.arch = KGENOME_ARCH_X86;
	o.file_header = &p;
	CK(kgenome_diag_class_of(&o) == (KGENOME_CLASS_PE | KGENOME_CLASS_X86));
	p.clr_off = 0x200;
	CK(kgenome_diag_class_of(&o) & KGENOME_CLASS_MANAGED);
	p.clr_off = 0;
	p.dir[KGENOME_PE_DIR_DEBUG].rva = 0x3000;
	CK(!(kgenome_diag_class_of(&o) & KGENOME_CLASS_SYMBOLS));        /* an address with no size is nothing */
	p.dir[KGENOME_PE_DIR_DEBUG].size = 0x1c;
	CK(kgenome_diag_class_of(&o) & KGENOME_CLASS_SYMBOLS);
	/* any other architecture: no flag of x86, so no plan */
	o.arch = KGENOME_ARCH_ARM;
	CK(!(kgenome_diag_class_of(&o) & KGENOME_CLASS_X86));
}

static void t_plan(void)
{
	unsigned c;

	CK(kgenome_diag_lineage_plan(0) == 0u);                  /* an unknown object */
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_DYNAMIC) == 0u);     /* not x86 */
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_X86 | KGENOME_CLASS_REL) == 0u);
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_PE | KGENOME_CLASS_X86 | KGENOME_CLASS_MANAGED) == 0u);
	/* every class of object the stages read has a plan that names stages and only stages */
	for (c = 0; c < 512u; c++) {
		unsigned plan = kgenome_diag_lineage_plan(c | KGENOME_CLASS_X86);

		CK((plan & ~(unsigned)KGENOME_LINEAGE_S_ALL) == 0u);
	}
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_DYNAMIC | KGENOME_CLASS_X86 | KGENOME_CLASS_WIDE) != 0u);
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_X86 | KGENOME_CLASS_WIDE) != 0u);
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_PE | KGENOME_CLASS_X86 | KGENOME_CLASS_WIDE) != 0u);
	/* every plan that names a stage names FLOW: the others read what it leaves */
	for (c = 0; c < 512u; c++) {
		unsigned plan = kgenome_diag_lineage_plan(c | KGENOME_CLASS_X86);

		CK(!plan || (plan & KGENOME_LINEAGE_S_FLOW));
	}
	/* the rows the measurements put there (diag_class.c): what a class runs, and what it does not and why */
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_DYNAMIC | KGENOME_CLASS_SYMBOLS | KGENOME_CLASS_X86) ==
	   (KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | KGENOME_LINEAGE_S_SUMM));                /* no SEED: +0 links */
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_DYNAMIC | KGENOME_CLASS_X86) == KGENOME_LINEAGE_S_ALL);
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_SYMBOLS | KGENOME_CLASS_X86) == KGENOME_LINEAGE_S_ALL);
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_X86) == KGENOME_LINEAGE_S_ALL);
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_ELF | KGENOME_CLASS_NOSECT | KGENOME_CLASS_X86) ==
	   (KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS));                                        /* no SUMM, no SEED: 1.5 and 4.5 links/s */
	CK(kgenome_diag_lineage_plan(KGENOME_CLASS_PE | KGENOME_CLASS_X86) == (KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM));
}

/* The names of imports that never return: the table in diag_lineage_chain.c, one name at a time, and what must not be in it. */
static void t_noreturn_names(void)
{
	static const char *const yes[] = { "exit", "_exit", "abort", "__stack_chk_fail", "__assert_fail", "longjmp", "pthread_exit" };
	static const char *const no[] = { "socket", "connect", "printf", "exitx", "Exit", "", "_ex", "longjmp2", "malloc", "read" };
	unsigned i;

	for (i = 0; i < sizeof yes / sizeof yes[0]; i++)
		CK(kgenome_diag_name_is_noreturn(yes[i]));
	for (i = 0; i < sizeof no / sizeof no[0]; i++)
		CK(!kgenome_diag_name_is_noreturn(no[i]));
	CK(!kgenome_diag_name_is_noreturn(NULL));
}

/* The lower bound the lookups of the stages share (kofcmp.h): every size up to 9, every key around the elements, a struct whose key
 * is not first, duplicates, and the ends. Against a linear scan. */
struct lb_el {
	uint32_t pad;
	uint64_t key;
	uint8_t tail;
};

static void t_lower_bound(void)
{
	struct lb_el v[9];
	uint32_t n, k, i;
	uint64_t key;

	CK(kof_lower_bound_u64(v, 0, sizeof v[0], offsetof(struct lb_el, key), 5) == 0u);
	for (n = 1; n <= 9u; n++)
		for (k = 0; k < (1u << n); k++) {           /* every pattern of duplicates in a sorted array */
			uint64_t cur = 10;

			for (i = 0; i < n; i++) {
				cur += (k >> i & 1u) ? 0u : 5u;
				v[i].key = cur;
				v[i].pad = 0xdeadbeefu;
				v[i].tail = 0xee;
			}
			for (key = 0; key < cur + 8u; key++) {
				uint32_t want = 0;

				while (want < n && v[want].key < key)
					want++;
				CK(kof_lower_bound_u64(v, n, sizeof v[0], offsetof(struct lb_el, key), key) == want);
			}
			CK(kof_lower_bound_u64(v, n, sizeof v[0], offsetof(struct lb_el, key), UINT64_MAX) == n);
		}
}

/* ... and the extent lookup: disjoint extents with gaps, every x around them, against a linear scan. */
static void t_first_ending_above(void)
{
	struct { uint32_t pad; uint64_t off, len; } v[6];
	uint32_t n, i;
	uint64_t x;

	for (n = 0; n <= 6u; n++) {
		uint64_t at = 4;

		for (i = 0; i < n; i++) {
			v[i].pad = 7;
			v[i].off = at + (i % 2u);           /* a gap of 0 or 1 before it */
			v[i].len = 3u + i;
			at = v[i].off + v[i].len;
		}
		for (x = 0; x < at + 4u; x++) {
			uint32_t want = 0;

			while (want < n && v[want].off + v[want].len <= x)
				want++;
			CK(kof_first_ending_above_u64(v, n, sizeof v[0], offsetof(__typeof__(v[0]), off), offsetof(__typeof__(v[0]), len), x) == want);
		}
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_generated();
	t_crafted();
	t_plan();
	t_noreturn_names();
	t_lower_bound();
	t_first_ending_above();
	printf("lineage_class: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
