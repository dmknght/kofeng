/*
 * diag/callnames - kgenome_callnames_build, _at, _applicable, _free and kgenome_cell_slot_of, over the ELF and PE objects the diag seeds build plus two
 * images whose table is known (tests/lib/genome/callnames_img.h: a lazy .plt, an IBT .plt.sec, calls through GOT and IAT slots).
 *
 * Held:
 *   TABLE   ordered strictly by file offset (one entry per offset), every offset inside the object, a kind that exists, a PE entry's library index inside the
 *           library list, an ELF entry's name inside the object, a status inside the enum; kgenome_callnames_at finds every entry and nothing at an offset
 *           with none; the free gives the ledger every byte back
 *   LEDGER  the same object under a random allowance: OK, or OVER_BUDGET / NOMEM with a table that is a prefix-complete subset (never longer than the unlimited one)
 *   SLOT    kgenome_cell_slot_of over every instruction the cursor decodes answers BROKEN or an address, never reads an operand an instruction does not have
 *   PLT     kgenome_cell_plt_* over the same instructions, 64- and 32-bit: a kind inside the enum, a STUB only for a `jmp`, a slot that is the one
 *           kgenome_cell_slot_of gives, an `endbr` only for a STUB, and the same answers when the state is fed the stream twice after a reset
 *   TWICE   building twice gives the same table (the digest takes it): the build is a pure function of the bytes
 */
#include "diag_seed.h"

#include <phenotype/callnames.h>
#include <phenotype/diag_private.h>

#include "../../lib/genome/callnames_img.h"

static void seeds(struct fz_corpus *c)
{
	static uint8_t elf[CI_ELF_SIZE];
	static struct hk_pe pe;

	ci_elf(elf);
	fz_corpus_add(c, "callnames_elf", elf, CI_ELF_SIZE);
	hk_pe(&pe, 1);
	ci_pe_code(&pe);
	fz_corpus_add(c, "callnames_pe64", pe.b, pe.n);
	hk_pe(&pe, 0);
	ci_pe_code(&pe);
	fz_corpus_add(c, "callnames_pe32", pe.b, pe.n);
	diag_seeds_bin(c);
}

static void plt_check(struct fz_ctx *c, struct kgenome_cell_plt *p, const struct kgenome_cell_insn *ins)
{
	struct kgenome_cell_plt_site site;
	int kind;

	memset(&site, 0, sizeof site);
	kind = kgenome_cell_plt_at(p, ins, &site);
	FZ_CHECK(c, kind >= KGENOME_CELL_PLT_NONE && kind <= KGENOME_CELL_PLT_SLOT, "a plt kind outside the enum");
	if (kind == KGENOME_CELL_PLT_NONE)
		return;
	FZ_CHECK(c, site.kind == (uint8_t)kind, "the site's kind is not the returned one");
	FZ_CHECK(c, kind != KGENOME_CELL_PLT_STUB || ins->op == KGENOME_CELL_JMP, "a stub that is not a jmp");
	FZ_CHECK(c, site.slot == kgenome_cell_slot_of(ins, p->wide, p->gotbase) && site.slot != KGENOME_BROKEN, "the slot is not the one kgenome_cell_slot_of gives");
	FZ_CHECK(c, !site.has_endbr || kind == KGENOME_CELL_PLT_STUB, "an endbr joined to something that is not a stub");
	FZ_CHECK(c, !site.has_endbr || site.endbr_va + 4u == ins->at_va, "an endbr that does not end where the stub starts");
	fz_digest(c, site.slot ^ ((uint64_t)kind << 62));
}

static void slots(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n)
{
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn ins;
	struct kgenome_cell_plt plt64, plt32;
	const struct kgenome_elf_info *ei = obj->format == KGENOME_FMT_ELF ? kgenome_obj_elf(obj) : NULL;
	unsigned steps;

	kgenome_cell_plt_init(&plt64, in, n, 1);
	kgenome_cell_plt_init(&plt32, in, n, 0);
	kgenome_cell_plt_import(&plt32, 0x2000u, 7u);
	kgenome_cell_plt_import(&plt32, 0x2004u, 7u);
	kgenome_cell_plt_ready(&plt64, ei && ei->valid ? ei : NULL);
	kgenome_cell_plt_ready(&plt32, ei && ei->valid ? ei : NULL);
	memset(&sp, 0, sizeof sp);
	memset(&k, 0, sizeof k);
	kgenome_cell_space_init(&sp, obj, in, n);
	(void)kgenome_cell_seek(&k, 0, 0);
	for (steps = 0; steps < 2000u; steps++) {
		uint64_t s1, s2;

		memset(&ins, 0, sizeof ins);
		if (!kgenome_cell_step(&k, &sp, &ins))
			break;
		s1 = kgenome_cell_slot_of(&ins, 1, 0);
		s2 = kgenome_cell_slot_of(&ins, 0, 0x1000u);
		fz_digest(c, s1 ^ (s2 << 1));
		plt_check(c, &plt64, &ins);
		plt_check(c, &plt32, &ins);
		fz_step(&c->steps, 1);
	}
	kgenome_cell_plt_reset(&plt64);
	(void)kgenome_cell_plt_at(&plt32, NULL, NULL);
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	const struct kgenome_obj *obj = &((struct diag_st *)h)->obj;
	struct kgenome_callnames a, b, lim;
	struct kgenome_ledger led, ledlim;
	uint32_t i;
	int ok;

	kgenome_ledger_init(&led, 0);
	ok = kgenome_callnames_build(&(const struct kgenome_callnames_req){ .obj = obj, .file = kof_buf_make(in, n), .led = &led }, &a);
	FZ_CHECK(c, ok == kgenome_callnames_applicable(obj), "build and applicable disagree");
	FZ_CHECK(c, (unsigned)a.status <= (unsigned)KGENOME_NOMEM, "callnames status outside the enum");
	if (!ok) {
		FZ_CHECK(c, a.n == 0 && a.v == NULL && led.used == 0, "a refused build owns something");
		fz_digest(c, 0xca11);
		kgenome_callnames_free(&a, &led);
		return;
	}
	FZ_CHECK(c, led.used == a.bytes, "the table's bytes are not what the ledger holds");
	for (i = 0; i < a.n; i++) {
		const struct kgenome_callname *e = &a.v[i];

		FZ_CHECK(c, i == 0 || a.v[i - 1u].off < e->off, "entries are not strictly ascending by offset");
		FZ_CHECK(c, e->off < n, "an entry outside the object");
		FZ_CHECK(c, e->kind == KGENOME_CALLNAME_STUB || e->kind == KGENOME_CALLNAME_SLOT, "a kind outside the enum");
		FZ_CHECK(c, a.format != KGENOME_FMT_PE || e->dll < a.n_dll, "a library index past the list");
		FZ_CHECK(c, a.format != KGENOME_FMT_ELF || (e->nameoff != 0 && e->nameoff < n), "an ELF entry whose name is outside the object");
		FZ_CHECK(c, kgenome_callnames_at(&a, e->off) == e, "kgenome_callnames_at does not find an entry that is there");
		if (i && (i % 5u) == 0u && a.v[i - 1u].off + 1u < e->off)
			FZ_CHECK(c, kgenome_callnames_at(&a, e->off - 1u) == NULL || a.v[i - 1u].off == e->off - 1u, "an entry at an offset with none");
		fz_digest(c, e->off ^ (e->nameoff << 8) ^ ((uint64_t)e->kind << 60));
		fz_step(&c->steps, 1);
	}
	FZ_CHECK(c, kgenome_callnames_at(&a, UINT64_MAX) == NULL, "an entry at UINT64_MAX");
	/* the same object under a random allowance */
	kgenome_ledger_init(&ledlim, 1u + fz_below(c->rng, 4096u));
	if (kgenome_callnames_build(&(const struct kgenome_callnames_req){ .obj = obj, .file = kof_buf_make(in, n), .led = &ledlim }, &lim)) {
		FZ_CHECK(c, lim.status != KGENOME_OK || lim.n == a.n, "a build with a ledger that was not refused has another table");
		FZ_CHECK(c, lim.n <= a.n || a.status != KGENOME_OK, "a refused build holds more entries than the full one");
		FZ_CHECK(c, ledlim.used <= ledlim.limit || ledlim.limit == 0, "the ledger went over its limit");
	}
	kgenome_callnames_free(&lim, &ledlim);
	FZ_CHECK(c, ledlim.used == 0, "the free of a limited build left bytes on the ledger");
	slots(c, obj, in, n);
	fz_digest(c, a.n);
	kgenome_callnames_free(&a, &led);
	FZ_CHECK(c, led.used == 0, "the free left bytes on the ledger");
	kgenome_callnames_free(NULL, NULL);
	/* twice: the same bytes, the same table */
	FZ_CHECK(c, kgenome_callnames_build(&(const struct kgenome_callnames_req){ .obj = obj, .file = kof_buf_make(in, n), .led = NULL }, &b) == ok,
		 "a second build answers differently");
	fz_digest(c, b.n);
	kgenome_callnames_free(&b, NULL);
}

FZ_ADAPTER(callnames, .name = "kgenome/diag_callnames",
	   .covers = "kgenome_callnames_build kgenome_callnames_free kgenome_callnames_at kgenome_callnames_applicable kgenome_cell_slot_of "
		   "kgenome_cell_plt_init kgenome_cell_plt_import kgenome_cell_plt_ready kgenome_cell_plt_reset kgenome_cell_plt_at",
	   .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000, .steps_base = 1000000u, .steps_per_byte = 64,
	   .shape = FZ_PARSE, .seeds = seeds, .dict = diag_dict_bin, .parse = diag_parse_bin, .walk = walk);
