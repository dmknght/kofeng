/*
 * fntab_build.c - THE FUNCTION TABLE OF AN OBJECT, built once: the probe, the selector's answer, the strategies it names, the merge and the ends.
 * This file is the run and what every format ends with (extents, ends, trust, the parts, the object with no metadata, the state); the strategies a case runs are the
 * format's own (fntab_build_elf.c, fntab_build_pe.c). See genotype/image/fntab.h for the shape and fntab_select.c / fntab_pe_select.c for the decision tables.
 *
 * FROM LOADER / ABI METADATA ONLY (owner 2026-11-16: "apply the information we have to implement the algorithm; do not use heuristics or disassembly analysis that is
 * error-prone and lacks coverage"; design: /mnt/games/normtest/design_partition_meta.md). No strategy of the table decodes code; the table decodes nothing.
 *
 * INVENTORY of what the table did on main before this change, each step classified (METADATA: kept; DECODE-DERIVED: disabled, code in #if 0 with its head comment):
 *   METADATA        kgenome_fntab_probe / kgenome_fntab_select / kgenome_pe_probe / kgenome_pe_select  (fntab_select.c, fntab_pe_select.c): read headers only. KEPT, rows rewritten.
 *   METADATA        kgenome_fntab_symtab (.symtab, .dynsym; funcs.c): start and st_size. KEPT.
 *   METADATA        kgenome_fntab_fde (.eh_frame by section, or through PT_GNU_EH_FRAME / .eh_frame_hdr with no section table; fntab_fde.c). KEPT.
 *   METADATA        kgenome_fntab_pdata (x64 .pdata incl. chained entries; fntab_pe_pdata.c), kgenome_fntab_pdata_arm (ARM64 / Thumb-2 .pdata). KEPT; a chained part that
 *                   does not continue its function is now a RANGE of the function (kgenome_funcs_range), not dropped.
 *   METADATA        kgenome_fntab_pe_coff (COFF symbols, aux size), kgenome_fntab_pe_export (export address table), kgenome_fntab_pe_tls (TLS callbacks),
 *                   kgenome_fntab_pe_cfg (CF guard function table, x86 SafeSEH handler table). KEPT.
 *   METADATA        kgenome_fntab_merge (fntab_merge.c): rank, one start one function, DISAGREE recorded, check-only. KEPT.
 *   METADATA        kgenome_fntab_ends (fntab_ends.c): the end of a start-only entry is the next start or the end of its code extent (END_OPEN). KEPT; it now sets the trust.
 *   METADATA        the entry point: was taken by the walk strategy; now its own strategy (genotype/image/fntab_entry.c).
 *   DECODE-DERIVED  kgenome_fntab_walk (fntab_walk.c): the direct call targets the walk's linear decode found. DISABLED.
 *   DECODE-DERIVED  kgenome_fntab_pe_thunk (fntab_pe_thunk.c): the import stubs `jmp [iat]` the walk's decode recognised (kind THUNK, end_source INSN). DISABLED: it is found
 *                   by decoding, not declared by any table (the import table names the slots, not the stubs).
 *   DECODE-DERIVED  kgenome_fntab_reach (fntab_reach.c): ends from the blocks an entry reaches, the GAPS starts behind bodies (flag GAP), the prologue recognisers. DISABLED.
 *   DECODE-DERIVED  the padding trim of the ends step (kgenome_fntab_ends' `pad`, the walk's runs of nop / int3; end_source TRIMMED). DISABLED (fntab_ends.c).
 *   DECODE-DERIVED  kgenome_fntab_run_walk (below): the walk asked by the table. DISABLED: the walk is still made by the readers that need its decode (the routes, the
 *                   lineage, the signing), on their own demand; the table no longer asks for it.
 *   DECODE-DERIVED  kgenome_fntab_blocks (fntab_blocks.c, the block layer of STEP B 1b, tests and harnesses only, never on the scan path). DISABLED.
 * NEW METADATA SOURCES (2026-11-16): .init_array / .fini_array / .preinit_array (fntab_elf_initarr.c), .ARM.exidx rows (fntab_elf_exidx.c), the Go function table
 * .gopclntab (fntab_elf_gopcln.c). The SafeSEH table and the CF guard table were already read (fntab_pe_cfg.c).
 *
 * THE ALGORITHM. 1. every source the selector names appends its entries; 2. the entry point is added only when another source named a function (an entry alone does not
 * split an object); 3. one merge (exact over start-only, DISAGREE recorded); 4. the ends: an exact entry is a unit of trust HIGH; a start-only entry is a DECLARED START
 * (the set's starts, round 4: no format declares its end) and the code no exact source declares is one NONE unit per gap, not cut at those starts; 5. the chained .pdata parts become ranges of their
 * root; 6. an object for which nothing gave an entry (no metadata at all: stripped static with no unwind table, packed code, shellcode) is ONE entry of trust NONE per code
 * extent, case NO_META, state PARTIAL with P_NO_META ("no function metadata"). No guess fills it: the next route is the emulator, not a heuristic.
 * 7. (round 2) every byte of a code extent that no declared function holds is an entry of trust NONE, source UNDECLARED (P_UNDECLARED, n_undeclared):
 * step 6 is its special case, one function (undeclared_fill).
 * ROUND 4 (2026-11-16, design "Research: what the formats and loaders declare"): only an EXTENT source (symbol with a size, FDE, .pdata, COFF aux size,
 * Go table) makes a unit (trust HIGH). A start-only source (the entry, init/fini arrays, exports, TLS, SafeSEH, CF guard, .ARM.exidx, a size-0 or NOTYPE
 * symbol) declares a START: it is kept in the sorted starts of the set (kgenome_funcs_starts_in) inside the NONE unit of its gap, which it does not cut.
 * MEDIUM (a start closed at the next start) is removed: no format declares that end. The entry point is always recorded as a start.
 * PHASE 2 (2026-11-16, design "Phase 2"; fntab_derive.c, derive_into below): the undeclared code is read by ONE recursive descent from its declared starts
 * (celllysis/cfg_obj.c); every entry it reaches (a declared start, a direct call's target) is a function of trust DERIVED, its extent the blocks it reaches;
 * the NONE units are then made again around them by the same undeclared_fill. HIGH units are never touched.
 * (2026-11-17, owner decision on FPART-D1, option b) between the ends and the undeclared fill, every FDE no symbol confirms is checked by the same descent
 * (fntab_derive.c kgenome_fntab_fde_check): an FDE whose code leaves it, or that holds two entries, gives no unit (n_fde_refused); its bytes are undeclared.
 * LIMITS, named: a function nothing declares and no descent reaches (address-taken, a jump table's case, dead code) stays in a NONE unit; a PIE's init_array slot filled by a relocation is not read (fntab_elf_initarr.c); a PE's Go table is not read (fntab_elf_gopcln.c); a view's table (the
 * normalised view, kgenome_funcs_remap) carries the first range of a function only.
 */
#include "fntab_build_private.h"

	/* IMPROVE func-size-1 (owner, 2026-11-03 "phân tách function phải chính xác, không thừa không thiếu size"; reason: a reverse engineer picks THE focus function to sign it, so a wrong unit is a wrong signature).
	 * STATUS AFTER THE FUNCTION TABLE (phase A1): the table is one product (struct kgenome_func_set), built once, case by case (genotype/image/fntab.h): the symbol table (exact), the unwind table (FDE: start and length),
	 * and the entry walk with the padding trim, merged in one place. Measured on the 711-file oracle corpus (exp_fnsize/work; the report of the change has the numbers). OPEN, with the named limit and the next
	 * algorithm: (1) an object with no symbol table and no unwind data (MIPS, ARM EHABI, packed children): starts are call targets only, so a function nothing calls directly is inside the body before it
	 * (partial, P_STARTS); next: .ARM.exidx starts, init/fini arrays and pointer tables into code (image_embed.c), a prologue FACT; (2) the END of such an entry is the next start less the padding (END_OPEN, P_ENDS):
	 * the reachable-blocks rule (R1, cfg_isa.c driven) is not built; its measured tail is a tail call into an unknown entry giving a giant extent, so start recall comes first; (3) PE (phase A2, below).
	 * The measurements before the change: symtab path exact (339429 of 339496 x86-64, the misses were IFUNC: fixed); stripped, start exact 55%, end exact 18% (x86-64 52% / 7%, MIPS < 8%: the walk found no
	 * entries); 39% of the functions were inside the body before them; 70% of the excess was alignment of 15 bytes or less (agent-reported, exp_fnsize/work/res.tables.md). */
	/* STATE OF THE PE CASES (phase A2, 2026-11-03; measured on the PE oracle of exp: .pdata hidden in memory, 20% held out by sha1; the report of the change has the numbers). The PE rows of the selector: managed (empty, P_MANAGED), x64 with an exception table
	 * (exact for non-leaf functions; the exports, the TLS callbacks, the COFF symbols, the walk, the import stubs and the GAPS step name the rest), a COFF symbol table, and x86 / x64 with neither (the walk). OPEN, each with its limit and the next
	 * algorithm: (1) starts of the walk-only cases are call targets, exports and callbacks: a function reached only through a pointer (a vtable, a callback table) is inside the body before it; measured 73% of the .pdata starts are found with
	 * .pdata hidden; the base-relocation table names 8% more at 43% precision, and a RIP-relative `lea` of a code address is also a jump-table base (data in .text), so neither was added: next, a prologue fact checked by the decode; (2) a `jmp X`
	 * after a ret or a jmp is not taken as a thunk in a PE (it is a basic block as often as a function: 9000 splits of 180000 functions against 0.9 point of starts): next, take X only when the jmp is itself a call target (incremental-link thunks);
	 * (3) a function that ends in its own jump table keeps it only when a start follows (the table is data the decode reads as code); (4) the PE route (diag_pe.c) reads the walk's trace: one decode, as the ELF routes. */
	/* IMPROVE func-part-1 (owner, 2026-11-01; measured on ONE file, do not generalise): HEUR-Backdoor.Linux.Mirai.b-036f5b0c (ELF x86-64 static, stripped, 77992 bytes, /mnt/games/virus_share/Bazaar.2026.08/).
	 * rizin (flatpak-spawn --host rizin -q -c 'aaa; afl') finds 228 functions, kofexaminer --blocks lists 132 units; VA = file offset + 0x400000 on both sides (no shift). 114 rizin starts coincide with a unit start; 114 do not:
	 * 107 inside another unit, 7 in no unit; their rizin sizes: <16 bytes 9, 16-63 bytes 56, >=64 bytes 49. The 65 under 64 bytes: units are made only from FN_MIN = 64 bytes and runs within FN_GAP = 32 bytes are one unit (CS2-1, mutation_units.c);
	 * the 49 of 64 bytes or more are entries the walk did not find (CN-4, since fixed by the unwind strategy where the object has unwind data); how rizin finds them was not checked. 18 unit starts have no rizin function (not examined).
	 * Case 0x4004b0: `jmp 0x408fc0` + 11 nops (5 bytes of code, called from 6 places). rizin follows the jmp: one 8-block function spanning 0x4004b0..0x40910f (35935 bytes); the engine does not follow jumps: unit off=0x4b0 len=224 holds the
	 * trampoline and the function at 0x4c0, and the jump target is its own unit (off=0x8fc0 len=336). Not measured: whether that unit's CFG is the 0x4c0 function's. */
	/* IMPROVE func-norm-1 (owner, 2026-11-01): when a function is NORMALISED into the representation that is hashed/compared, the NOPs must be dropped too (padding between functions and alignment fill: e.g. the 11 nops after the
	 * 5-byte `jmp 0x408fc0` at 0x4004b0 in the file above), so that a function's representation does not depend on how much padding follows it or on whether a run of padding makes a function look bigger or a unit swallow its neighbour.
	 * Not done: the CFG builder and the extent code take the bytes/instructions as they come (NOP is the opcode class KGENOME_CELL_NOP, celllysis/cell.h: the place to drop it once, where the instructions are decoded). */
	/* IMPROVE func-data-1 (owner, 2026-11-01; ONE file, measured): HEUR-Backdoor.Linux.Mirai.mr-2c1f3e99 (/mnt/games/virus_share/Bazaar.2026.08/; ELF ARM 32-bit static, no section headers, packed: object //0 390484 bytes, its normalised view //0//0:norm 373064 bytes,
	 * one R-X PT_LOAD of 371740 bytes, so with no sections the whole segment is region CODE). `kofexaminer --db D --blocks` lists a unit off=0x57e04 len=292 cfg_blocks=2 block_id=27bd1ce8 (the viewer row `fcn_00057e04`): it is NOT a function.
	 * Bytes there (words): 0x75f9 0x8c3e 0x6ef0 0x2000 0x1856 0xff28 0x8ef4d7a3 0x65733a33 (ASCII `3:se` inside): a table/text mixed with constants; rizin decodes it as nonsense (andeq/invalid/.dword) and reports DATA XREFs to it from fcn.000233f8
	 * (0x23404..0x23420): code reads it as data. rizin also makes a 40-byte fcn.0005fe04 there (it lists a CALL XREF from fcn.000340cc +0x140): the same wrong function in both tools. Not determined: which branch/entry makes the engine's walk start a function at 0x57e04.
	 * Rule to find: a unit/function whose bytes do not decode as a plausible instruction run (invalid opcodes, conditional-execute junk) and that is referenced as DATA is data in an executable segment: a start found by a call target must be checked against that before it becomes a function. */
	/* IMPROVE func-part-2 (owner order 2026-11-01 "kiểm tra lại logic chia hàm với các sample đã đưa ra"; measured, ONE run each, rizin = `aaa; afl` on the host; engine = CODE units of
	 * `kofexaminer --blocks`; VA from the PT_LOAD map; script /mnt/games/normtest/inv_cmp/cmp.py; the unpacked packed samples are the dumped //0 objects). rizin counts stubs and thunks too.
	 *   Mirai.b   x86-64 static stripped : rizin 228, engine 128, starts in common 114 (the case of func-part-1).
	 *   run1      x86-64 dynamic, symbols : rizin 119, engine 34, common 34 (every engine unit is a rizin start; of the 85 others 59 are under 16 bytes).
	 *   Ark       i386 dynamic stripped   : rizin 21, engine 7, common 4.
	 *   Mirai.mr  ARM 32 (UPX, //0)       : rizin 3097, engine 841, common 789, engine-only 52, 44 rizin starts in no unit.
	 *   Mirai.gen ARM 32 LE (UPX, //0)    : rizin 1287, engine 72, common 62, 977 rizin starts in no unit. CORRECTION (measured 2026-11-01): this object is NOT stripped (it keeps .symtab, 555 FUNC with a size), its
	 *             function set comes from the symtab, not from the walk; NOLOAD (63970 bytes) is the tail past every PT_LOAD (.comment, .debug_*, .symtab, .strtab) and holds NO start; of the 347 symtab starts 75 become units (156 under FN_MIN; 323 of 64 bytes or more are libc functions, probably excluded as library spans: not confirmed).
	 *   Mirai.r   PowerPC 32 BE (UPX, //0): rizin 936, engine 22, common 0: the 22 unit offsets are NOT 4-aligned (0x3e3 0x7f5 0x19e2 0x2912 ...) for 4-byte-aligned code: those units are not functions (measured 2026-11-01, when
	 *             celllysis had no PowerPC decoder; it has one now, with a cfg_isa row, and the walk decodes PowerPC: the row is stale, re-measured by the function table's PPC rows).
	 * Not measured: which of the engine-only starts are real; the effect of FN_MIN/FN_GAP per sample; why Mirai.gen leaves 977 starts in no unit. */
	/* IMPROVE func-part-3 (owner order 2026-11-01 items 1-3; MEASURED by the exp_funcdet harness /mnt/games/normtest/exp_funcdet/, 96 symtab ELF as ground truth (x86-64 19 files 21363 functions, i386 17, ARM 40, MIPS 19, AArch64 1),
	 * the symtab ignored by the detectors; one run each; the two independent harnesses agree on the old numbers: E 64.3%, FDE 88.7%, E+FDE 97.4% on x86-64):
	 *  1. The walk already decodes every code byte (decoded bytes = code bytes, within 4): every rule that runs on its trace costs 0 extra decode.
	 *  2. The biggest loss today is the FN_MIN/FN_GAP grouping, not the walk: on Mirai.b the walk finds 228 of 228 rizin starts and only 114 stay units. Start recall without the grouping (E) versus with it (U):
	 *     x86-64 64% vs 38%, ARM 77% vs 42%, i386 80% vs 38%, Mirai.mr 86% vs 26%, Mirai.gen 73% vs 18%, Mirai.b 100% vs 50%.
	 *  3. Adding FDE (when the object has .eh_frame): x86-64 97.4% (precision 96.2%), AArch64 100%; 13 of 19 x86-64 files have it, 3 of 17 i386, 5 of 19 MIPS; of the six samples only run1 (59 FDE) and Mirai.gen (36 exidx entries) have unwind data.
	 *     Adding a prologue FACT after a terminator (D; endbr64, push of a callee-saved register, sub rsp for x86; stmdb sp!, sub sp for ARM; addiu sp,sp,-N for MIPS; manual-defined, not in cfg_isa.c): x86-64 80%, i386 90%, ARM 84%, AArch64 84%, MIPS 45%,
	 *     precision 81-96%. Tail-call targets (C) add ~0.1%: not worth it; gap fill (F) helps x86/MIPS (+13 points recall, -8 precision) and hurts ARM (precision 24%).
	 *  4. Not found by any rule: ARM Thumb functions (1078; only .ARM.exidx gets 20.6%), MIPS PIC functions that begin `lui gp` (the walk finds almost no entry: indirect jalr, CS-4), PowerPC (no decoder: it needs an arch row, 4-byte big-endian
	 *     classes b/bl/bc/blr/sc, a cfg_isa row, prologue mflr r0 / stwu r1).
	 *  5. Hash side: with the floor gone, 1-block functions (22-31% of all) share ONE canonical hash (89.8% of them on x86-64) and 3-block functions are near-identical: their hash has no separating power; from 8 blocks up nearly every hash is its own.
	 *  6. Is a function worth hashing: no single predicate (size, entropy, printable fraction, instruction count, blocks, reachable fraction, invalid/data-like fraction) separates real functions from non-functions without overlap on the symtab corpus; the
	 *     distributions are in /mnt/games/normtest/exp_funcdet/results/pred_sym.md. Two counted cases lose no real function: ARM printable fraction above 500 per mille (94 non-functions, 0 functions); the table at Mirai.mr 0x57e04 (292 bytes, 73 insns, no terminator, 705 per mille printable).
	 *  7. Decode count (wrap on kgenome_cell_decode, Mirai.b 23780 offsets): walk 1.00, codemap alone 2.05, RUN_ALL 4.22; the readers: walk 23780, codemap/code_run 23780, codemap second pass (syscall numbers) 23780, sweep_region 13392, lineage 12997, call_facts 1835, callee_getpc 620.
	 *     The walk's trace records carry the whole decoded instruction (immediates, targets, rip-relative slots): no value was found that needs a re-decode (not every reader tried). The trace holds every architecture (trace_arch.c) and is read through the one reader kgenome_diag_code_run. */


/* DISABLED by the owner 2026-11-16: the table asked the walk (the linear decode) for call targets and padding runs, which is disassembly analysis the owner ruled out for the
 * partition (error-prone, lacks coverage); to re-enable: take this #if 0 out, set KGENOME_FNTAB_X_WALK in the selector rows and call it from the format's collector. */
#if 0
int kgenome_fntab_run_walk(struct kgenome_fntab_run *r)
{
	if (!r->walk)
		r->walk = r->own = kgenome_diag_walk_new();
	/* The walk is asked WITH the trace: it is the decode every later reader shares, and a walk made without it is made again when one asks (FP-9). */
	if (r->walk && kgenome_diag_walk_ensure(r->walk, r->obj, r->data, r->data_n, 1)) {
		kgenome_fntab_walk(r->obj, r->walk, &r->l);
		r->pad = kgenome_diag_walk_pads(r->walk, &r->n_pad);
		r->walked = 1;
		return 1;
	}
	r->l.status = KGENOME_NOMEM;            /* the walk could not be held: a table that is short, said */
	return 0;
}
#endif

int kgenome_fntab_parts_add(struct kgenome_fntab_parts *p, uint64_t at, uint64_t len, uint64_t root)
{
	if (p->n == p->cap) {
		const uint32_t nc = p->cap ? p->cap * 2u : 256u;
		struct kgenome_fntab_extent *t = nc > p->cap ? realloc(p->at, (size_t)nc * sizeof *p->at) : NULL;
		uint64_t *u;

		if (!t)
			return 0;
		p->at = t;
		if (!(u = realloc(p->root, (size_t)nc * sizeof *p->root)))
			return 0;
		p->root = u;
		p->cap = nc;
	}
	p->at[p->n].at = at;
	p->at[p->n].len = len;
	p->root[p->n++] = root;
	return 1;
}

/* The parts of a function (a chained .pdata entry that does not continue its root's body, a derived function's block run apart from its entry's): a range of the
 * root. A fragment wholly inside its root's first range was joined by kgenome_fntab_pdata already. A part whose root is no function of the table is counted
 * (n_rng_orphan). */
static void parts_attach(struct kgenome_func_set *out, const struct kgenome_fntab_parts *pt)
{
	struct kgenome_func_range *pv;
	uint32_t i, n = 0;

	if (!pt->n || !out->n)
		return;
	pv = malloc((size_t)pt->n * sizeof *pv);
	if (!pv) {
		out->status = KGENOME_NOMEM;
		return;
	}
	for (i = 0; i < pt->n; i++) {
		const uint32_t fn = kgenome_funcs_start(out, pt->root[i]);
		const struct kgenome_func *f;

		if (fn == KGENOME_FUNCS_NONE) {
			out->n_rng_orphan++;
			continue;
		}
		f = &out->v[fn];
		if (pt->at[i].at >= f->off && pt->at[i].at - f->off < f->len)
			continue;               /* the body already holds it (contiguous, joined) */
		pv[n].off = pt->at[i].at;
		pv[n].len = pt->at[i].len;
		pv[n++].fn = fn;
	}
	(void)kgenome_funcs_set_ranges(out, pv, n);
	free(pv);
}

/*
 * THE UNDECLARED CODE (coordinator round 2, 2026-11-16): after the ends, every byte of every code extent belongs to exactly one entry. A run of the extent that
 * no declared function holds (no first range, no chained part whose root is in the table) is ONE entry of trust NONE, source UNDECLARED, end_source
 * NEXT_START: "not declared by metadata". It is not a guessed function: it is not split by the entry point or by anything else, and its padding is not
 * trimmed (no decode). An object with no metadata at all is the special case of one gap equal to each whole extent: this is the ONE function for both.
 * Measured cause (coordinator, readelf): static musl and hand-written asm carry no CFI (057_1794: 312 FDEs, the old walk 714 functions), and the syscall
 * wrappers sit in exactly these gaps. Overlapping extents (two sections over the same bytes) are taken as their union. Returns the gaps made.
 */
struct cov_iv { uint64_t at, end; };

static int iv_cmp(const void *a, const void *b)
{
	const struct cov_iv *x = a, *y = b;

	return x->at < y->at ? -1 : x->at > y->at;
}

static int fn_cmp_off(const void *a, const void *b)
{
	const struct kgenome_func *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static uint32_t undeclared_fill(struct kgenome_func_set *out, const struct kgenome_fntab_extent *ext, uint32_t n_ext,
				const struct kgenome_fntab_parts *pt)
{
	struct cov_iv *cov, *ex;
	struct kgenome_func *nv;
	uint32_t n_cov = 0, n_ex = 0, i, k, n_gap = 0, cap_gap = 0;
	struct cov_iv *gap = NULL;

	if (!n_ext)
		return 0;
	cov = malloc(((size_t)out->n + pt->n + 1u) * sizeof *cov);
	ex = malloc((size_t)n_ext * sizeof *ex);
	if (!cov || !ex) {
		free(cov);
		free(ex);
		out->status = KGENOME_NOMEM;
		return 0;
	}
	for (i = 0; i < out->n; i++)
		if (out->v[i].len) {
			cov[n_cov].at = out->v[i].off;
			cov[n_cov++].end = out->v[i].off + out->v[i].len;
		}
	for (i = 0; i < pt->n; i++)                     /* a part is code of its root (declared: a chained part; derived), when the root is in the table */
		if (pt->at[i].len && kgenome_funcs_start(out, pt->root[i]) != KGENOME_FUNCS_NONE) {
			cov[n_cov].at = pt->at[i].at;
			cov[n_cov++].end = pt->at[i].at + pt->at[i].len;
		}
	for (i = 0; i < n_ext; i++)
		if (ext[i].len) {
			ex[n_ex].at = ext[i].at;
			ex[n_ex++].end = ext[i].at + ext[i].len;
		}
	qsort(cov, n_cov, sizeof *cov, iv_cmp);
	qsort(ex, n_ex, sizeof *ex, iv_cmp);
	/* the union of the extents */
	for (i = 0, k = 0; i < n_ex; i++) {
		if (k && ex[i].at <= ex[k - 1u].end) {
			if (ex[i].end > ex[k - 1u].end)
				ex[k - 1u].end = ex[i].end;
			continue;
		}
		ex[k++] = ex[i];
	}
	n_ex = k;
	/* the gaps: each extent swept against the covered intervals (sorted by start; `reach` is the furthest covered byte so far) */
	for (i = 0, k = 0; i < n_ex; i++) {
		uint64_t pos = ex[i].at;

		while (k < n_cov && cov[k].end <= pos)
			k++;
		for (uint32_t j = k; pos < ex[i].end; j++) {
			const uint64_t nxt = j < n_cov && cov[j].at < ex[i].end ? cov[j].at : ex[i].end;

			if (nxt > pos) {
				if (n_gap == cap_gap) {
					const uint32_t nc = cap_gap ? cap_gap * 2u : 16u;
					struct cov_iv *t = realloc(gap, (size_t)nc * sizeof *gap);

					if (!t) {
						out->status = KGENOME_NOMEM;
						goto done;
					}
					gap = t;
					cap_gap = nc;
				}
				gap[n_gap].at = pos;
				gap[n_gap++].end = nxt;
			}
			if (j >= n_cov || cov[j].at >= ex[i].end)
				break;
			if (cov[j].end > pos)
				pos = cov[j].end;
		}
	}
	if (n_gap) {
		nv = realloc(out->v, ((size_t)out->n + n_gap) * sizeof *nv);
		if (!nv) {
			out->status = KGENOME_NOMEM;
			n_gap = 0;
			goto done;
		}
		out->v = nv;
		for (i = 0; i < n_gap; i++) {
			struct kgenome_func *f = &out->v[out->n + i];

			memset(f, 0, sizeof *f);
			f->off = gap[i].at;
			f->len = gap[i].end - gap[i].at;
			f->source = KGENOME_FN_S_UNDECLARED;
			f->end_source = KGENOME_FN_E_NEXT_START;
			f->trust = KGENOME_FN_TRUST_NONE;
		}
		out->n += n_gap;
		qsort(out->v, out->n, sizeof *out->v, fn_cmp_off);    /* starts are unique: a gap begins where no entry does */
	}
done:
	free(gap);
	free(cov);
	free(ex);
	return n_gap;
}

/*
 * THE CODE EXTENTS OF THE FUNCTION TABLE (round 3, audit PMA-1 / PMA-2 / PMA-4): the bytes the object DECLARES executable, every one of which ends in exactly
 * one entry of the table. Metadata only, no decode:
 *   ELF with executable sections (SHF_EXECINSTR, file bytes): every such section - .init, .plt, .plt.got, .fini, a custom section, not only the one holding
 *       the entry. A linked object's section counts when an executable file-backed PT_LOAD holds its first byte (the loader's claim checks the linker's);
 *       an ET_REL object (.o, .ko) has no segments, so its sections are taken as they are.
 *   ELF with none of those (no section table, or one that names no executable section): every executable PT_LOAD's file bytes, less the ELF header and the
 *       program header table when they lie inside it. The entry point splits and cuts nothing.
 *       TODO(owner): default applied 2026-11-16 for a lying section table (no executable section the loader maps, e.g. set356 107_6ad596...): trust the
 *       executable PT_LOAD, as the loader does (one NONE unit of 350500 bytes there); the alternative is declaring no code.
 *   PE: the executable sections as kgenome_diag_extent reads them (raw bytes, cut at VirtualSize).
 * WHY NOT kgenome_diag_extent FOR AN ELF: that is where a DECODE starts (the first executable section or the entry, the segment cut at the last executable
 * section), the walk's question; this is which bytes are declared code, the table's. Measured (audit, set356): 51 ELF files without a section table lost
 * the code below the entry (6.1 MB); every gcc/ld executable lost the PLT's FDEs. Overlapping extents are merged by the caller's gap step.
 */
#define FNTAB_EXT_MAX (KGENOME_ELF_MAX_SECTIONS > KGENOME_ELF_MAX_SEGMENTS ? (KGENOME_ELF_MAX_SECTIONS > KGENOME_PE_MAX_SECTIONS ? KGENOME_ELF_MAX_SECTIONS : KGENOME_PE_MAX_SECTIONS) : \
		       (KGENOME_ELF_MAX_SEGMENTS > KGENOME_PE_MAX_SECTIONS ? KGENOME_ELF_MAX_SEGMENTS : KGENOME_PE_MAX_SECTIONS))

static uint32_t fntab_code_extents(const struct kgenome_obj *obj, uint64_t size, struct kgenome_fntab_extent *ext, uint32_t cap)
{
	uint32_t i, n = 0;

	if (obj->format == KGENOME_FMT_PE) {
		for (i = 0; i < kgenome_diag_extent_count(obj) && n < cap; i++) {
			uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

			if (have) {
				ext[n].at = at;
				ext[n++].len = have;
			}
		}
		return n;
	}
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
		const int rel = e->e_type == KGENOME_ELF_REL;
		uint64_t hdr;

		for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS && n < cap; i++) {
			const struct kgenome_elf_sec *s = &e->sec[i];
			const struct kgenome_elf_seg *g = NULL;

			if (!(s->flags & KGENOME_ELF_SHF_EXEC) || s->type == KGENOME_ELF_SHT_NOBITS || !s->file_size || s->file_off >= size)
				continue;
			if (!rel && (!(g = kgenome_elf_load_at_off(e, s->file_off)) || !kgenome_elf_seg_is_code(g)))
				continue;
			ext[n].at = s->file_off;
			ext[n].len = s->file_size < size - s->file_off ? s->file_size : size - s->file_off;
			/* a linked object's section never runs past the executable segment that holds it (a lying section table claims what the loader does not map) */
			if (!rel && ext[n].len > g->file_off + g->file_size - s->file_off)
				ext[n].len = g->file_off + g->file_size - s->file_off;
			n++;
		}
		if (n || rel)
			return n;
		hdr = e->elf_class == KGENOME_ELFCLASS_64 ? 64u : 52u;
		if (e->phnum && e->phoff + (uint64_t)e->phnum * e->phentsize > hdr)
			hdr = e->phoff + (uint64_t)e->phnum * e->phentsize;
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS && n < cap; i++) {
			const struct kgenome_elf_seg *g = &e->seg[i];
			uint64_t at = g->file_off, end;

			if (!kgenome_elf_seg_is_code(g) || at >= size)
				continue;
			end = g->file_size < size - at ? at + g->file_size : size;
			if (at < hdr)
				at = hdr < end ? hdr : end;
			if (end > at) {
				ext[n].at = at;
				ext[n++].len = end - at;
			}
		}
	}
	return n;
}

/*
 * PHASE 2: THE FUNCTIONS OF THE UNDECLARED CODE (fntab_derive.c, run after the first fill). The descent reads the NONE units from their declared starts; what it
 * derives replaces the NONE units, and the NONE units are made again around the derived bodies by the same undeclared_fill (one function for both fills): the
 * code no traversal reached (address-taken functions, data, dead code) stays NONE and is counted (n_undeclared). Exact metadata is untouched: the descent reads
 * only the NONE units, so a derived body never covers a HIGH one.
 */
static void derive_into(struct kgenome_fntab_run *r, struct kgenome_func_set *out, const struct kgenome_fntab_extent *ext, uint32_t n_ext,
			struct kgenome_fntab_parts *pt)
{
	struct kgenome_fntab_derived d;
	struct kgenome_func *nv;
	uint32_t i, k = 0;

	memset(&d, 0, sizeof d);
	d.parts = pt;
	kgenome_fntab_derive(r, out, &d);
	out->n_derive_into_high = d.n_into_high;
	out->n_derive_skipped = d.n_skipped;
	if (d.over)
		out->partial |= KGENOME_FNTAB_P_DERIVE_CAP;
	if (d.status == KGENOME_NOMEM)
		out->status = KGENOME_NOMEM;
	if (!d.fn.n) {
		kgenome_fntab_list_free(&d.fn);
		return;
	}
	nv = realloc(out->v, ((size_t)out->n + d.fn.n) * sizeof *nv);
	if (!nv) {
		out->status = KGENOME_NOMEM;    /* the table keeps its NONE units: short of the derivation, said */
		kgenome_fntab_list_free(&d.fn);
		return;
	}
	out->v = nv;
	for (i = 0; i < out->n; i++)
		if (out->v[i].trust != KGENOME_FN_TRUST_NONE)
			out->v[k++] = out->v[i];
	memcpy(out->v + k, d.fn.v, (size_t)d.fn.n * sizeof *d.fn.v);
	out->n = k + d.fn.n;
	kgenome_fntab_list_free(&d.fn);
	qsort(out->v, out->n, sizeof *out->v, fn_cmp_off);
	out->n_undeclared = undeclared_fill(out, ext, n_ext, pt);
}

void kgenome_diag_funcs_with_walk(const struct kgenome_obj *obj, const uint8_t *data,
			      uint64_t data_n, struct kgenome_diag_walk *walk,
			      struct kgenome_func_set *out)
{
	struct kgenome_fntab_run r;
	struct kgenome_fntab_extent ext[FNTAB_EXT_MAX];
	struct kgenome_fntab_parts pt;
	uint32_t n_ext = 0, i;
	int has_meta;

	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (!obj) {
		out->status = KGENOME_BAD_INPUT;
		return;
	}
	/* nothing parsed, or a format with no table of functions: an empty table, case NONE, state COMPLETE (there is nothing to be missing) */
	if (!obj->file_header)
		return;
	if (obj->format == KGENOME_FMT_ELF ? !((const struct kgenome_elf_info *)obj->file_header)->valid :
	    obj->format == KGENOME_FMT_PE ? !((const struct kgenome_pe_info *)obj->file_header)->valid : 1)
		return;
	memset(&r, 0, sizeof r);
	memset(&pt, 0, sizeof pt);
	r.obj = obj;
	r.data = data;
	r.data_n = data_n;
	r.file = kof_buf_make(data, data_n);
	r.walk = walk;          /* not a source of the table (the walk's call targets are DISABLED); the derivation reads its trace, the one decode every later reader shares */
	kgenome_fntab_probe(obj->format, r.file, obj->file_header, &r.meta);
	/* THE CASE'S STRATEGIES: the selector of the format (the decision table is at the head of its file) chooses, the format's own function runs them */
	if (obj->format == KGENOME_FMT_ELF)
		kgenome_fntab_collect_elf(&r);
	else
		kgenome_fntab_collect_pe(&r);
	/* THE ENTRY POINT is a declared start like any other (round 4: nothing cuts the code at a start, so the entry is recorded always); an object whose one
	 * fact is its entry still has no function metadata (case NO_META) */
	has_meta = r.l.n != 0;
	if (r.plan.run & KGENOME_FNTAB_X_ENTRY)
		kgenome_fntab_entry(obj->entry_off, obj->format == KGENOME_FMT_ELF && ((const struct kgenome_elf_info *)obj->file_header)->e_machine == 40u &&
				    (((const struct kgenome_elf_info *)obj->file_header)->entry_addr & 1u), &r.l);
	/* the chained parts: masks for the merge, then ranges of their root */
	for (i = 0; i < r.l.n; i++)
		if (r.l.v[i].kind == KGENOME_FN_FRAGMENT && r.l.v[i].len && !kgenome_fntab_parts_add(&pt, r.l.v[i].off, r.l.v[i].len, r.l.v[i].value)) {
			r.l.status = KGENOME_NOMEM;
			break;
		}
	kgenome_fntab_merge(&r.l, r.plan.check_only, out);
	kgenome_fntab_list_free(&r.l);
	out->ccase = r.plan.ccase;
	/* THE CODE EXTENTS of the table (fntab_code_extents: every executable section, or every executable PT_LOAD less the headers) */
	n_ext = fntab_code_extents(obj, data_n, ext, (uint32_t)(sizeof ext / sizeof *ext));
	/* THE ENDS: a declared extent is a HIGH unit; every other entry is a declared START (out->st), not a body (round 4) */
	if (out->n)
		kgenome_fntab_ends(out, ext, n_ext, NULL, 0u);
	/* AN FDE NO SYMBOL CONFIRMS IS CHECKED (owner decision 2026-11-17, option b): it gives no unit when code leaves it or it holds two entries */
	if (obj->format == KGENOME_FMT_ELF && out->n)
		kgenome_fntab_fde_check(&r, out);
	/* THE UNDECLARED CODE: every byte of the extents in one entry; with no declared function at all, the whole extent (NO_META). The managed image and the
	 * image with no code in the file keep their empty answer (their own P_ bit says why). Then PHASE 2 derives functions in it from its declared starts. The
	 * parts are attached after: the indices are final then. */
	if (r.plan.ccase != KGENOME_FNTAB_C_PE_CLR && r.plan.ccase != KGENOME_FNTAB_C_PE_NOCODE && r.plan.ccase != KGENOME_FNTAB_C_NONE) {
		out->n_undeclared = undeclared_fill(out, ext, n_ext, &pt);
		if (out->n_undeclared && out->n_st)
			derive_into(&r, out, ext, n_ext, &pt);
		if (!has_meta) {
			out->ccase = KGENOME_FNTAB_C_NO_META;
			out->partial |= KGENOME_FNTAB_P_NO_META;
		}
		if (out->n_undeclared)
			out->partial |= KGENOME_FNTAB_P_UNDECLARED;
	}
	parts_attach(out, &pt);
	/* THE STATE, as a value: what the case says, and what the run found */
	out->partial |= r.add_partial;
	out->state = (out->partial & (KGENOME_FNTAB_P_CAP | KGENOME_FNTAB_P_DERIVE_CAP)) ? KGENOME_FNTAB_OVER_BUDGET :
		     out->partial ? KGENOME_FNTAB_PARTIAL : KGENOME_FNTAB_COMPLETE;
	free(pt.at);
	free(r.outer);
	free(pt.root);
	kgenome_diag_walk_free(r.own);          /* the walk the derivation made when the caller had none */
}
