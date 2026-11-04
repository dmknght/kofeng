/*
 * fntab_build.c - THE FUNCTION TABLE OF AN OBJECT, built once: the probe, the selector's answer, the strategies it names, the merge and the ends.
 * This file is the run and what every format ends with (extents, GAPS, ends, the state); the strategies a case runs are the format's own (fntab_build_elf.c, fntab_build_pe.c).
 * See genotype/image/fntab.h for the shape and fntab_select.c for the decision table.
 *
 * ONE DECODE. The walk strategy reads the walk (kgenome_diag_walk_ensure: the one decode of the code, whose entries and padding runs it takes), asked with the
 * trace WANTED so that the readers after the table (the signing of a function, the codemap) read the trace and decode nothing again; the symbol and unwind
 * strategies read the headers and decode nothing.
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

void kgenome_diag_funcs_with_walk(const struct kgenome_obj *obj, const uint8_t *data,
			      uint64_t data_n, struct kgenome_diag_walk *walk,
			      struct kgenome_func_set *out)
{
	struct kgenome_fntab_run r;
	struct kgenome_fntab_extent ext[KGENOME_ELF_MAX_SEGMENTS > KGENOME_PE_MAX_SECTIONS ? KGENOME_ELF_MAX_SEGMENTS : KGENOME_PE_MAX_SECTIONS];
	struct kgenome_fntab_extent *frag = NULL;
	uint32_t n_frag = 0, cap_frag = 0, n_ext = 0, i;

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
	r.obj = obj;
	r.data = data;
	r.data_n = data_n;
	r.file = kof_buf_make(data, data_n);
	r.walk = walk;
	kgenome_fntab_probe(obj->format, r.file, obj->file_header, &r.meta);
	/* THE CASE'S STRATEGIES: the selector of the format (the decision table is at the head of its file) chooses, the format's own function runs them */
	if (obj->format == KGENOME_FMT_ELF)
		kgenome_fntab_collect_elf(&r);
	else
		kgenome_fntab_collect_pe(&r);
	/* the chained fragments the merge will leave out are bodies still: the GAPS step is told where they are */
	for (i = 0; i < r.l.n; i++)
		if (r.l.v[i].kind == KGENOME_FN_FRAGMENT && r.l.v[i].len) {
			struct kgenome_fntab_extent *t = n_frag == cap_frag ? realloc(frag, (size_t)(cap_frag ? cap_frag * 2u : 256u) * sizeof *frag) : frag;

			if (!t) {
				r.l.status = KGENOME_NOMEM;
				break;
			}
			frag = t;
			cap_frag = n_frag == cap_frag ? (cap_frag ? cap_frag * 2u : 256u) : cap_frag;
			frag[n_frag].at = r.l.v[i].off;
			frag[n_frag++].len = r.l.v[i].len;
		}
	kgenome_fntab_merge(&r.l, r.plan.check_only, out);
	kgenome_fntab_list_free(&r.l);
	out->ccase = r.plan.ccase;
	/* THE ENDS, over the code extents the walk reads (one function: kgenome_diag_extent). */
	for (i = 0; i < kgenome_diag_extent_count(obj) && n_ext < sizeof ext / sizeof *ext; i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, data_n, &at);

		if (have) {
			ext[n_ext].at = at;
			ext[n_ext].len = have;
			n_ext++;
		}
	}
	/* THE REACH (PE x86/x64: the end of what an entry reaches, the functions behind it that no source names), then the ends close what no source closed. */
	if (out->n && r.walked && (r.plan.run & KGENOME_FNTAB_X_PE_REACH))
		kgenome_fntab_reach(out, &r, ext, n_ext, frag, n_frag);
	if (out->n)
		kgenome_fntab_ends(out, ext, n_ext, r.walked ? r.pad : NULL, r.walked ? r.n_pad : 0u);
	/* THE STATE, as a value: what the run knows (a walk finds call targets only), and what the case says. */
	if (r.walked)
		out->partial |= KGENOME_FNTAB_P_STARTS;
	out->partial |= r.add_partial;
	out->state = (out->partial & KGENOME_FNTAB_P_CAP) ? KGENOME_FNTAB_OVER_BUDGET :
		     out->partial ? KGENOME_FNTAB_PARTIAL : KGENOME_FNTAB_COMPLETE;
	free(frag);
	kgenome_diag_walk_free(r.own);
}
