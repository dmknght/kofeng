/*
 * genome / budget_status - the budget, the ledger and the status of kgenome,
 * through <kgenome.h> alone, linked against libkgenome.a and nothing else.
 *
 * This file is the proof that the lib stands without the engine: it is built
 * with no engine archive on the link line, so one symbol of the engine reached
 * from anywhere in libgenome is an undefined reference here. What it checks:
 *
 *   - the budget's defaults scale with the input and never decrease
 *   - the ledger charges, refuses, releases and notes OVER_BUDGET
 *   - the status order is severity and merge keeps the worse
 *   - a diagnose scan (a hand-built ELF object, no parser) reads its budget:
 *     a node limit says TRUNCATED, a memory allowance too small for the nodes
 *     says OVER_BUDGET and the bytes charged are readable back
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

static void budget_scales(void)
{
	struct kgenome_budget a, b;
	static const uint64_t sizes[] = { 0, 1, 4096, 1u << 20, 64u << 20, 1ull << 34, UINT64_MAX };
	unsigned i;

	kgenome_budget_default(&a, 100, 0);
	CK(a.max_nodes == KGENOME_NODES_MIN && a.max_insn == KGENOME_INSN_MIN);
	CK(a.max_insn_resolve == KGENOME_RESOLVE_MIN);
	CK(a.code_bytes == 100u && a.obj_size == 100u);
	/* monotone in both the object's and the code's size, saturating at the top */
	kgenome_budget_default(&a, sizes[0], 0);
	for (i = 1; i < sizeof sizes / sizeof sizes[0]; i++) {
		kgenome_budget_default(&b, sizes[i], 0);
		CK(b.max_nodes >= a.max_nodes && b.max_insn >= a.max_insn);
		CK(b.max_steps >= a.max_steps && b.max_bytes >= a.max_bytes);
		CK(b.max_nodes <= KGENOME_MAX_INDEX);
		a = b;
	}
	/* a big object is allowed a bigger product than a small one */
	kgenome_budget_default(&a, 1u << 10, 0);
	kgenome_budget_default(&b, 8u << 20, 0);
	CK(b.max_nodes > a.max_nodes && b.max_insn > a.max_insn);
	CK(kgenome_budget_sat_mul(UINT64_MAX, 2) == UINT64_MAX);
}

static void ledger(void)
{
	struct kgenome_ledger l;

	kgenome_ledger_init(&l, 1000);
	CK(kgenome_ledger_room(&l) == 1000u);
	CK(kgenome_ledger_charge(&l, 600) && l.used == 600u && l.status == KGENOME_OK);
	/* a refusal charges nothing and says OVER_BUDGET, once and for good */
	CK(!kgenome_ledger_charge(&l, 600) && l.used == 600u);
	CK(l.status == KGENOME_OVER_BUDGET);
	/* the soft charge for a cache: refused without a status of its own */
	kgenome_ledger_init(&l, 100);
	CK(!kgenome_ledger_try(&l, 200) && l.status == KGENOME_OK && l.used == 0u);
	CK(kgenome_ledger_try(&l, 100) && l.peak == 100u);
	/* a release saturates: a mispaired one cannot wrap the count */
	kgenome_ledger_release(&l, 1u << 30);
	CK(l.used == 0u && l.peak == 100u);
	/* no allowance (a zeroed ledger) is unlimited */
	memset(&l, 0, sizeof l);
	CK(kgenome_ledger_room(&l) == UINT64_MAX && kgenome_ledger_charge(&l, 1ull << 40));
}

static void status_order(void)
{
	CK(kgenome_status_merge(KGENOME_OK, KGENOME_TRUNCATED) == KGENOME_TRUNCATED);
	CK(kgenome_status_merge(KGENOME_OVER_BUDGET, KGENOME_TRUNCATED) == KGENOME_OVER_BUDGET);
	CK(kgenome_status_merge(KGENOME_NOMEM, KGENOME_OK) == KGENOME_NOMEM);
	CK(kgenome_status_complete(KGENOME_OK) && !kgenome_status_complete(KGENOME_TRUNCATED));
	CK(!strcmp(kgenome_status_name(KGENOME_OVER_BUDGET), "over-budget"));
	CK(kgenome_diag_scan_status(NULL) == KGENOME_BAD_INPUT);
	CK(kgenome_diag_scan_bytes(NULL, NULL) == 0u);
}

/*
 * An x86-64 ELF object made by hand: one RX segment over the code, no section
 * table. `n` fillers (mov edi,k ; mov eax,9 ; syscall) are nodes of the sweep.
 */
static uint8_t image[1u << 16];
static struct kgenome_elf_info info;

static uint64_t build(unsigned n_calls, struct kgenome_obj *obj)
{
	static const uint8_t one[] = { 0xbf, 0, 0, 0, 0, 0xb8, 9, 0, 0, 0, 0x0f, 0x05 };
	uint64_t at = 0x100, i;

	memset(image, 0, sizeof image);
	memset(&info, 0, sizeof info);
	for (i = 0; i < n_calls; i++) {
		memcpy(image + at, one, sizeof one);
		image[at + 1] = (uint8_t)i;
		at += sizeof one;
	}
	image[at++] = 0xc3;
	info.version = KGENOME_ELF_INFO_VERSION;
	info.valid = 1;
	info.elf_class = 2;
	info.elf_data = 1;
	info.e_type = KGENOME_ELF_EXEC;
	info.e_machine = 62;
	info.entry_addr = 0x400100;
	info.seg_count = 1;
	info.load_count = 1;
	info.min_vaddr = 0x400000;
	info.max_vaddr = 0x400000 + at;
	info.seg[0].file_off = 0;
	info.seg[0].file_size = at;
	info.seg[0].mem_addr = 0x400000;
	info.seg[0].mem_size = at;
	info.seg[0].type = 1;                   /* PT_LOAD */
	info.seg[0].perm = KGENOME_PERM_R | KGENOME_PERM_X;
	info.seg[0].claim_off = 0;
	info.seg[0].claim_len = at;
	memset(obj, 0, sizeof *obj);
	obj->format = KGENOME_FMT_ELF;
	obj->arch = KGENOME_ARCH_X86_64;
	obj->subtype = KGENOME_ELF_EXEC;
	obj->obj_size = at;
	obj->entry_off = 0x100;
	obj->file_header = &info;
	return at;
}

static struct kgenome_diag_scan *scan(unsigned n_calls, const struct kgenome_budget *b)
{
	struct kgenome_obj obj;
	struct kgenome_diag_inputs in;
	uint64_t len = build(n_calls, &obj);

	memset(&in, 0, sizeof in);
	in.budget = b;
	return kgenome_diag_scan_with_inputs(&obj, image, len, KGENOME_DIAG_RUN_SYSCALL, &in);
}

static void diag_budget(void)
{
	struct kgenome_budget b;
	struct kgenome_diag_scan *s;
	uint64_t used, peak;

	/* whole: every node found, the status OK, and the bytes the ledger holds are
	 * readable so a caller can charge its own scan for them */
	s = scan(40, NULL);
	CK(s != NULL);
	CK(kgenome_diag_scan_count(s) == 40u);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK && kgenome_diag_scan_full(s) == 0);
	used = kgenome_diag_scan_bytes(s, &peak);
	CK(used > 0u && peak >= used);
	kgenome_diag_scan_free(s);

	/* the node limit is the budget's: exactly 40 fit, 39 cut the last and say so */
	memset(&b, 0, sizeof b);
	b.max_nodes = 40;
	s = scan(40, &b);
	CK(kgenome_diag_scan_count(s) == 40u && kgenome_diag_scan_status(s) == KGENOME_OK);
	kgenome_diag_scan_free(s);
	b.max_nodes = 39;
	s = scan(40, &b);
	CK(kgenome_diag_scan_count(s) == 39u);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED && kgenome_diag_scan_full(s) == 1);
	kgenome_diag_scan_free(s);

	/* a memory allowance too small for the nodes: the ledger refuses, the scan
	 * keeps what it has and says OVER_BUDGET - never a silent shorter graph */
	memset(&b, 0, sizeof b);
	b.max_bytes = 512;
	s = scan(40, &b);
	CK(s != NULL);
	CK(kgenome_diag_scan_count(s) < 40u);
	CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET);
	used = kgenome_diag_scan_bytes(s, &peak);
	CK(used <= 512u && peak <= 512u);       /* the allowance was never exceeded */
	kgenome_diag_scan_free(s);
}

/* the decoders and the emulator come from the same archive */
static void decoders_and_emulator(void)
{
	struct kgenome_cell_insn in;
	static const uint8_t nop[] = { 0x90 };
	/* mov rax,1 ; jmp $ (an infinite loop) */
	static const uint8_t spin[] = { 0x48, 0xc7, 0xc0, 1, 0, 0, 0, 0xeb, 0xfe };
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&in, 0, sizeof in);
	CK(kgenome_cell_decode_x86(nop, 1, 0x1000, 64u, &in) == 1u && in.op == KGENOME_CELL_NOP);

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = 1000;
	e = kgenome_emu_new(&cfg);
	CK(e != NULL);
	if (e) {
		CK(kgenome_emu_map(e, 0x1000, spin, sizeof spin, 0x1000,
				   KGENOME_EMU_R | KGENOME_EMU_X));
		kgenome_emu_set_rip(e, 0x1000);
		/* the budget ends the run and the run says that is what ended it */
		CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_BUDGET);
		CK(kgenome_emu_insn_count(e) >= 1000u);
		CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 1u);
		kgenome_emu_free(e);
	}
}

int main(void)
{
	budget_scales();
	ledger();
	status_order();
	diag_budget();
	decoders_and_emulator();
	printf("genome budget_status: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
