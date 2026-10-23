# Writing code in kofeng

These are not style preferences. Each one is here because breaking it cost
something measurable, and the measurement is named.

These rules apply to **every** change and are loaded with every session, so
there is no point at which they stop applying - not after an hour, not after
the twentieth edit, not when something else is urgent.

`QUALITY_AUDIT.txt` at the repository root is the other half: the checklist
for a particular KIND of thing - a parser, an unpacker, a signature module,
the pack format - plus ten classes of hostile input. Read it when building
one of those.

`make check-rules` fails the build on the one of these a grep can see. It
runs as part of `make`. The rest are checked in review.

## 1. No `getenv`. None.

The engine reads nothing from its environment. Not a trace switch, not a
limit, not a path.

Two things are wrong with it. It puts a lookup of the process environment on
paths that run millions of times - one such switch was measured costing four
times the work it guarded. And it means a shipped scanner carries, and can be
talked into running, code that exists only for whoever was debugging it: one
of these removed every work bound from the interpreter, and a single scan
started with it ran for **four days**.

**Diagnostics are a build choice.** `libkofeng/kofcore/kofdebug.h`:

```c
KOF_TRACE("[emu] stop=%d insn=%llu\n", st, n);   /* nothing in a release build */
if (KOF_TRACING) { ... }                          /* a whole block */
```

`make` ships without them. `make DEBUG=1` compiles them in. The arguments are
type-checked in both, because the release form keeps the call inside a
`sizeof` - which an `#ifdef`'d-out block cannot promise.

**Settings are arguments.** ksigbuilder takes `--cc`, `--ld`, `--include`,
`--ldscript`, `--triple`, `--tmpdir`; the Makefile passes them. A command and
its arguments is the one shape sh and PowerShell agree on.

**The one exception, stated so it is not mistaken for a lapse:**
`kofwatcher/kofmontrace.c` reads `PATH` because it is reproducing `execvp`'s
own search and has to look where the exec will look. Reading the environment
IS the specified behaviour there. Nothing else qualifies.

## 2. Use the API. Do not write the logic a second time.

If the engine already answers a question, ask it. A second implementation of
the same logic is a second thing to keep correct, and it will drift.

Measured in this tree:

- A detection's name was spelled in the engine and again in the examiner. The
  separator moved from "-" to "#" in the engine, the examiner's copy kept the
  "-", and every detected sample showed no verdict in the examiner while the
  scanner called the same file infected. One spelling now, `kof_verdict_name`
  (`libkofeng/verdictor/verdict.h`), and the tools quote `kof_result.verdict`.
- The scanner's own name-matching guess at "did a packer produce this" was
  retired by the engine publishing `from_packer`.
- A verdict was composed in the tool and in the engine; the tool's copy went.

When a caller needs something the API nearly gives, **change the API**. Do not
reimplement it next to the call.

## 3. One fact, one carrier.

A property of an object lives in exactly one field, on the object.

"Has this been normalised" was stored three ways at once: `entry_kind ==
KOF_ENT_NORMALIZED`, a boolean `is_view`, and the word `norm` in the name -
with the scanner keeping a fourth copy in `cur_is_view`. They drifted, and an
object came back labelled `NORMALIZED norm`. The kind is the carrier; the
others are gone.

Scanner state is a step of the scan. Whether an object has been normalised,
unpacked, or emulated is a property of the **object**, not of the pass that
happened to be running.

## 4. A cap bounds COST. It must never delete evidence.

Limits exist against a hostile file - a decompression bomb, a DoS loop, an
allocation driven by a file-supplied size. They do not exist to keep tables
small.

`MAX_LOOP` was a fixed 4096. One 7.7 MB binary filled it exactly, **11806
further loops were dropped**, and the overflow flag then switched off loop
pruning and branch-arm marking for the whole object - so the page had no
`loop {`, no `if {` and no `} else {` anywhere.

Bound the **input**, let the **results** grow:

- RetDec's decoder has no MAX_BLOCK, no MAX_NODE, no code-size cap. It bounds
  which bytes are candidates - executable sections only, each byte read once -
  and lets what comes out be what it is.
- kofeng had it the other way round and paid for it everywhere.

Where a limit really is a DoS bound, say so at the definition, and make the
degradation honest: `reaches()` answers UNKNOWN when it runs out of budget,
which is "this graph cannot establish it" and not a wrong answer.

**An entry's own bound is not the tree's.** A container is walked entry by entry,
and two kinds of bound meet there. A bound of ONE entry - the object cap, the
declared-ratio clamp - cuts that entry: the bytes decoded so far are its object,
it carries `KOF_BROKEN_LIMIT` itself (`kof_src_mark_cut`, read back by the walk as
the object's result), `limit_hits` counts it, and the parent's loop goes on to the
next entry (`oc_entry_cut`, `oc_entry_cut_close`; the sink refuses only the rest of
that entry, `sink.refuse`, and the module's own close of it answers "made"). When
nothing of the entry was kept there is no child to say so, and the PARENT reports it
(`oc_scan_limit`: a report, no control flow). A bound of the WHOLE tree - the
produced-bytes budget, the resident ceiling, the child quota, the window allowance
(`ledger.window_left`: the root plus the produced-bytes budget, charged by
`oc_window` for every container), an allocation - is sticky (`oc_scan_broken`:
`open.stop`) and ends the walk, and the parent says Limit. One sticky stop for both
was the defect: an 84 MB archive with one 91 MB member lost the 5700 entries after
it. A module's loop ends on a refusal of the HOST's (`kunp_rcstruct_done` or
`_window` answering 0 because the tree will take no more), never on one entry's cut.

**A bound of WORK is the tree's too, sized from the ROOT.** A per-object limit with a floor restarts
for every child, and a file chooses how many children it has: a zip of 100 one-KB spinning PEs cost
26 s. Emulated instructions are charged to `ledger.emu_insn_left` (64 Mi + 512 per root byte, at most
4 Gi, or the host's `max_emu_insn`; a child's size buys nothing, it came from the root); a run gets the
smaller of its own limit and what is left (`oc_emu_afford`, `oc_emu_charge`, objctx_emu.c). Optional
evidence (the diagnose emulating routes, the API-resolution run) goes first, the first
`KOF_SCAN_EMU_FLOOR_RUNS` unpack runs keep their floor, and a refusal is said (KOF_BROKEN_LIMIT,
`limit_hits`, `emu_budget_denied`). A new per-child pass with a floor takes its allowance from the tree.

## 5. Table lookup, not re-analysis.

Decide a thing once, where the information is, and store it. Do not re-derive
it per use.

- `blk[].succ` held addresses, so every graph walk re-resolved address to
  block with a binary search. One PE spent **67 seconds** inside that lookup;
  resolving once into indices made it 6.5.
- `node.loop` was recomputed by scanning the whole span table five times per
  step per chain. It depends on the step, not on the chain, so `finish()`
  decides it once.
- An argument's producer is recorded when the value is made, and read by
  index - never found by walking back.

## 6. Measure, and say what the gate is.

Every claim about cost or coverage carries a number from this tree.

- State the gate **before** the change. For a change to the analysis (the
  diagnose scan, the emulator, the parsers) the gate is what the analysis
  produced - nodes, links, what a parser recovered - and time. For anything
  else it is the verdicts on a frozen corpus: identical, or the differences
  listed. A detection count that cannot move proves nothing, so do not quote
  one as a result.
- Change one variable at a time. Two at once is not a measurement.
- Freeze the binary and the corpus. Scan copies and `chmod a-w` them: the scanner
  no longer repairs a file, but a corpus that moves under a measurement is not one.
- Check for a runaway from an earlier run before trusting a timing - two were
  found here holding a core, one with four days of CPU.

## 7. Say what the code does, and what it does not.

A comment states the decision and the evidence for it, not the mechanics. If
a measurement chose the number, give the number. If a thing was tried and
rejected, say so where the next reader would otherwise try it again.

And on the screen: a row says what the program did. It does not repeat what
the page already shows - a step inside a drawn `if { }` does not need a
comment saying it is conditional, and `via-register` is a fact about the
engine, not about the program.

## 8. The scope you were given is the work. Not more, not less.

Asked to change how a variant name is generated, this renamed 141 signature
files. All of it had to be reverted. If a change seems to need a wider one,
say so in a sentence and then do the one that was asked.

The reverse too: finish it. "The chain is built" is not the task when the
task was "the chain is wrong"; say plainly which part is done and which is
not, and never call something fixed that has not been measured.

## 9. A rename is not a fix.

`Virus:Infected` printed the word virus twice, and renaming the rule to
`Patched` was offered as the fix. It changed a string. The duplication was
in the verdict composer, which was still there.

When a symptom is reported, find what produces it. If the honest answer is
that the cause is elsewhere and this is cosmetic, say that.

## 10. Never leave two paths doing one job.

A traversal was rewritten and the old one left running beside it - the file
was then read twice per scan, by two mechanisms, and the new one's whole
point was to read it once. Half a refactor is worse than none: the cost of
both, the correctness of neither, and nobody can tell which one produced a
given result.

Finish the swap in the same change, or do not start it.

## 11. The engine decides. A tool shows.

`kofscanner` and `kofviewer` take input from the person and display what the
engine returned. They do not compose verdicts, re-derive what a module meant,
or filter the engine's results by logic of their own. When a tool needs something the
engine does not expose, add it to the engine - including the callback the
tool registers to be told.

## 12. Where code lives

The lib split is built; what is still open is at the end of this section. The
tree ships one archive (`libkofeng.a`) holding the engine and the two libs, and
ALSO builds each lib as an archive of its own from the same objects -
`libkgenome.a` (libgenome, plus the one foundation object it calls,
`kofentropy.o`) and `libkuncoat.a` (libuncoat) in `build/temp`. They are not
shipped; they exist so that `tests/lib/genome/*.c` and `tests/lib/uncoat/*.c` are
linked against ONE lib's archive and nothing else, which is the test that the
lib does not reach the engine (an engine symbol is an undefined reference there).
`make unit` runs them; `make unit-asan` runs them against the sanitised twins.
**A test that needs only one lib belongs in `tests/lib/<lib>/`**, not in
`tests/unit/` (which links the whole engine); a test that needs the object
context, the parsers or a database stays in `tests/unit/`. A new file in
`libgenome/`, `libuncoat/`, `libkofeng/` or `tests/lib/<lib>/` is picked up by
wildcard. `libuncoat/` (kuncoat) has the parts `decompressors/`, `decryptors/`,
`decoders/`, one umbrella header `<uncoat.h>`, one transform API `transform.h`
and the status enum `kuncoat_status` in `status.h`; `libgenome/` has `genotype/`,
`celllysis/` and `phenotype/` (below). Do not move code to match the rest without
being asked; do not add code that contradicts it.

**Three parts and a foundation, one dependency direction.**

    libkofeng (the engine, the kernel)  -> kuncoat, kgenome, core
    kuncoat   (decompress/decrypt/decode algorithms) -> kgenome, core
    kgenome   (analysis of executables)  -> core
    core      (kof_buf, bounds helpers, hash, rangelist, platform)

- Semantically `kgenome` is the foundation of everything that is about a file;
  unpacking is the process after it; the engine runs the pipeline. So `kuncoat`
  may include `kgenome`'s public header and use its types (the structure of a
  PE or ELF is defined once, in `kgenome`). The one forbidden edge is `kgenome`
  calling `kuncoat`: if analysis ever needs a decode, it gets a primitive of
  its own (in `core`) or the engine hands it the decoded bytes. Neither lib
  depends on the engine, and a lib never reaches the engine's objects
  (`kof_scanner`, `kof_obj_ctx`).
- `core` is the foundation directory (today `libkofeng/kofcore`, the module
  ABI under `kofmod/` stays where it is). It is not `bases/`.
- No cycles, and no lib includes the engine. A dependency that points up the
  list above is a defect.
- The engine (`libkofeng`) controls the pipeline: stages, the object tree,
  budgets, the per-object products and their lifetime, detection, verdicts and
  the module ABI. It calls the libs through their API and takes results.

**What each lib is for.**

- `kgenome` is the analysis of executable code and, later, of other formats
  that are NOT containers (.NET, AMSI buffers, script files): genotype (which
  instruction), celllysis (the analysis), phenotype (the emulator and the
  dynamic analysis), the structure of PE and ELF, the library-span table, the
  diagnose walk and its products. It defines its own structs.
- `kuncoat` is the algorithms that grow without a forecast, in three parts:
  `decompressors`, `decryptors`, `decoders`. Buffers and a budget in, bytes and
  a status out. There is no `unpackers` part: unpacking a packer statically is a
  ROUTINE in `bases/` (it identifies the packer, reads its parameters, and calls
  these algorithms), and unpacking that RUNS the sample is `kgenome`'s.
- A container (zip, rar, OLE, PDF...) is opened by the engine into child
  objects, and a child re-enters the pipeline. A lib analyses ONE object.

**Rules every lib follows.**

- Names: `kgenome_` and `kuncoat_` on every public function, type and macro
  (`KGENOME_`, `KUNCOAT_` on macros). The engine keeps `kof_`, with these
  exceptions, which are written down so they are not mistaken for lapses:
  the PUBLIC API a host links keeps the family of its header - `keng_`, `kscan_`,
  `kdb_`, `kmatch_` (`kofeng.h`), `kverdict_` (`verdictor/verdict.h`,
  `koftypes.h`), `khash_` (`kofhash.h`), `kentropy_` (`kofentropy.h`) - and these
  are not renamed, because a rename is a break for every host. What the engine
  declares for its own units is `kof_<unit>_` (`kof_scan_*` in `scanners/scan.h`),
  and three internal families mark a helper that is private to its directory:
  `sx_` (one stage of the scan, `scanners/scan_int.h`), `oc_` (the object
  context, `scanners/objctx_int.h`) and `pdf_` (the PDF parser's units,
  `analyzers/parsers/containers/pdf_int.h`; its `static inline` helpers carry it
  too). A new internal function takes one of those, not a new prefix. What the
  API file (`kofeng.c`) or another directory calls is not private to a directory:
  it is `kof_<unit>_` (`kof_scan_bytes`), not `sx_`.
- One request, one result. A stage takes ONE struct describing its input and
  fills or returns ONE struct (or a status) - not a list of loose scalars that
  are really one concept. Group by concept (an input window, an output sink,
  options, a budget), name the struct next to the function's header in the
  lib's own prefix, and use one spelling per family: `kgenome_<family>_req` /
  `_res` (`kgenome_emu_unp_pe_req`, `kgenome_mutation_req`,
  `kgenome_diag_code_req`, `kgenome_elf_hdr_req`), `kof_<unit>_req` / `_res` in
  the engine (`kof_match_req`, `kof_exe_norm_req`/`_res`, `kof_diag_store`),
  `ksn_<unit>_req` in the scanner. The budget, the ledger and the status
  counters belong to the CALLER and arrive as a member of the request (a
  pointer), never as a trailing parameter. The struct is passed by `const`
  pointer and read once at the top of the function into locals, so a hot path
  pays nothing per byte; measure it (callgrind Ir) when the function is hot.
  `make check-rules` fails a function with more than 8 parameters (the
  `parameter count` pass of `tools/check_layers.py`; its EXEMPT table names the
  one positional wrapper kept for kofexamine). In `kuncoat` the decoder
  convention is a type: `struct kuncoat_io` (`uncoat_io.h`) is the input window
  (`struct kuncoat_span`), the sink and its user pointer, and the two counters
  (`consumed`, `produced`) a decoder always sets; `kuncoat_inflate`,
  `kuncoat_inflate_seeded` and `kuncoat_lzx_decode` take it, with the
  algorithm's own extras (`kuncoat_lzx_req`, a seed span) beside it. A decoder
  that writes into a buffer rather than a sink takes the spans in a struct of its
  own (`kuncoat_bcj2_io`).
- Words: one concept has one word in new text, and the old spellings stay where
  the ABI fixes them. SIMILARITY is `mutation` (`detectors/mutations/`,
  `kofmod/kofmutation.h`, `kgenome_mutation_*`); what a program DOES is a
  DIAGNOSE (a generated `.c` under `diagnoses/` of a content tree; `kofmod/kofdiagtree.h` holds its graph layout); a
  module asking
  the host to undo a coding says `kunp_*` (the unpack ABI) while the algorithm it
  asks for lives in kuncoat. Rename the file or directory when it is free to
  move; leave an ABI name until the ABI version moves.
- Errors: each lib has its own status enum - what fails in an unpacker is not
  what fails in a disassembler. A status says whether the answer is complete;
  "truncated" and "over budget" are values, never a silent "none" (rule 4).
- Budget: the caller passes it. Limits scale with the input and the global
  budget is the DoS bound; a lib never reads engine state to find it. The engine
  passes a `kgenome_budget` whose `max_bytes` is what its own memory ceiling has
  left, and reads the answer back: `kgenome_diag_scan_status` says whether a
  limit fired (the allowance included) and `kgenome_diag_scan_bytes` is what the
  lib's ledger holds, which the engine charges to its own ceiling for as long as
  the product lives (`kof_scan_diag_drop` gives it back). A floor on a limit
  (`KGENOME_INSN_MIN`, `W_BODY_MIN`) is what a small object gets; the limit
  itself follows the object (a wait before a stager does not shrink with the
  file, so the DoS bound is the budget and not a flat per-stage number).
- Memory: the caller owns the output, either a buffer it supplies or an
  allocation it asked for through a callback, so that it is charged to the
  scan's budget.
- No writable global state; a lib is safe on many threads.
- One public SURFACE per lib: the umbrella (`<kgenome.h>`, `<uncoat.h>`) and the part
  headers it lists. Everything else is private to the lib - every `_private.h`, and any
  header the umbrella does not name. A file outside the lib includes the umbrella, or, when
  it uses one part, that part's header by its part path (`<celllysis/nucleo.h>`,
  `<decompressors/inflate.h>`); it never includes a `_private.h`. This was "one public
  header per lib" and the engine had never obeyed it to the letter (33 include lines of 19
  part headers): routing them all through the umbrella would make every engine unit
  compile the whole of kgenome for one type, so the rule names what the headers already
  were. `tools/check_layers.py` enforces it (LIB PUBLIC HEADERS); `libkofeng/kofcore/kofmod/` re-exports the libs' types by
  design and `tests/` includes private headers for white-box tests, so neither is checked.
- Modules are freestanding blobs: they reach a lib only through a slot of the
  module ABI, which the engine owns and implements by calling the lib.
- `bases/` is case routines that use the module API. Anything two routines
  share, or that is big enough to need its own tests, graduates into a lib or
  the engine; `bases/` does not carry shared code. What two MODULES share is a
  module-side helper header under `libkofeng/kofcore/kofmod/` (`ep_shape.h`,
  `pe_reassemble.h`, `upx_method.h`, `stub_pat.h`), which a module includes after
  `<kofmod/kofsig.h>` and which stays freestanding. **A shared function there is
  a macro that DEFINES it, invoked where the module had the function**
  (`KOF_STUB_DEFINE_IS`, `KOF_UPX_DEFINE_METHOD_OF`): a blob is linked with
  `-ffunction-sections`, so its bytes follow the order the functions were emitted
  in, and every report (`kof_debug`, `kof_mark_infected`) carries the source line it
  was made on. Moving a function up into a header, or deleting lines above a
  report, changes the pack with no change of behaviour - measured, and the packs
  were no longer byte-identical. The analysis that is specific
  to one kind of malware lives as a disease unit with the other analysis, not
  in `bases/`: the msfvenom wrapper declarations (`msf_*.h`, SDK `kofshared/`)
  are such a unit. Shellcode in general cannot be covered by the engine; a
  loader is detected by a hand-written signature. The loader payload finder is
  a tool-side analysis of the examiner (`kofexamine/kofscfind.c`, `kofexaminer
  --scfind`), not engine, ABI or library code.
- A derived object (today the normalised view) is not a second program and is
  not re-analysed. It inherits the parent's analysis product by product: what is
  a PLACE (regions, the image description, the entry, the functions) is carried
  through the transform's own boundary table (`kgenome_offmap`,
  `genotype/image/offmap.h`; the visitor that lists every file offset of a PE/ELF
  description is the one walk used both to ask the transform and to remap), and
  what is an ANSWER (the diagnoses that matched, the graph, what a PE resolves)
  is shared in the parent's coordinates (`scanners/objprod.c`, published when
  the parent's pipeline ends, adopted when the view's begins). The view's header
  is never parsed: it is the parent's header over bytes that moved. A new
  per-object product needs a line in one of those two lists, not a re-run.
- Parsers keep their engine-facing API. The body that does the work moves into
  `kgenome`; the engine-side function stays as the adapter and says so. The PE import
  AND export directories are walked in `kgenome` (`kgenome_pe_imports`,
  `kgenome_pe_exports`, `genotype/image/pe_image.c`); `analyzers/parsers/binaries/pe/pe_sym.c`
  only decides how an import or an export is spelled in a KSYM record.

**Memory: one number for the whole engine.** The engine never holds more than 512 MiB
(`KOF_ENGINE_MEM_CAP`, `kofcore/kofbudget.h`; a host may set another with `keng_set_memory_cap`,
zero means the default, there is no "unlimited"). The database is charged first at load (its index
and filters; record payloads stay in the mapped read-only pack and are touched on demand); each
scanner reserves its fixed cost when made (`kscan_new` answers NULL when it cannot be afforded);
when it starts an object it takes its share, (cap - database) / scanners alive less its fixed cost
and presence table, and that share is the ledger ceiling everything produced, decoded, emulated or
copied for the object is charged to. When something does not fit it degrades in this order, each
step reported and none silent: caches shrink (decode trace, presence table), copies become borrows
(emulator image pages), optional products are skipped with a status (the view, the emulate route:
`KOF_BROKEN_LIMIT`, `limit_hits`), the object is refused last. A builder of a big table asks first
(`kof_budget_ask`) and picks its layout from the answer. **The input file is inside the cap and is
never mapped**: `kof_src_file` (`scanners/objsrc.c`) reads it with `read(2)` into a buffer charged to
the budget, so a file truncated while it is scanned is a short read at that call (the object is
`KOF_BROKEN_DAMAGED`, with the bytes that were read) and not a SIGBUS, and the engine installs and
chains no signal handler at all: a handler is process-global state (a host's own would be replaced or
ours would swallow its signals), it would depend on the fault address the OS reports, and it cannot
tell this fault from a genuine bug, which must kill the process. A file may take a third of the
scanner's share in the heap (`kof_scan_file_room`); a larger one is copied to the engine's own unnamed
spill file when one may be made (a real disk or a directory the host named, never a RAM filesystem
it did not), and otherwise held up to the whole share and, past that, read as far as it goes and
reported `KOF_BROKEN_LIMIT`. The one map left over input is the engine's own anonymous spill file
(`kof_src_fd`), which has no name and so no writer. The database packs are mapped by the loader and
are the remaining exposure (see `dbloader_packs.c`).
**The block (similarity) index and the pattern table are the model of it: their memory does not follow
the database.** A pack's tail is one container (`databases/pack/dbkix.h`): a chain of parts that each end
in the same 64-byte footer (`[old pack][pattern table, KPXF][block index, KIXF]`, either optional, probed
by `kof_tail_probe`), read with `pread` and never mapped through one sliced reader (`struct kof_slices`: a
CRC a 64 KiB, checked the first time a slice is read by `kof_crc32_fast_cont` (`dbcrc.c`: eight bytes a step, bit
for bit `kof_crc32`, which also checks the old part at load), the verdict shared; a short read is `KOF_KIX_E_IO`,
a wrong byte `KOF_KIX_E_CRC`, never a signal). Both footers carry where the old pack ends and its CRC, so
an engine that knows only the block index reads the pattern part as a gap, and one that knows neither loads
the pack as one with a long tail; no record changed and no version moved. **Blocks**: the engine holds only
the directory (257 KB) and a filter whose size the ledger grants (16 bits a hash by default, at most 16 MiB,
halved under pressure and reported as `KOF_MTN_B_FILTER_DEGRADED`); 80 hashes and 32,000,000 cost the same
few megabytes plus that filter. A pack from before the trailer is indexed in memory under half of what the
ledger has left, or refused with `KOF_MTN_B_OVER_BUDGET` and a stderr line (the engine loads, similarity
rules do not score). The matcher's per-scanner state follows what the object touches, is capped by the
scanner's ledger and charged to it (`kof_mutation_limit`, `sc->mutation.ledgered`). A damaged or shortened
pack file is a status on the object (`KOF_MTN_S_SLICE_CRC`, `KOF_MTN_S_IO_ERROR`, `KOF_MTN_S_IO_BUDGET`),
never a signal. **Patterns** (`detectors/pattern/kofpix.h`; it replaced five table shapes that were 484
bytes a rule and a word a marker per scanner): a pack whose table is at least `KOFPIX_EMBED_MIN` (256 KiB,
about 7000 markers) carries it as a part; the loader opens it, and what is resident is the exact key set (2
bytes a distinct key), the directory and a filter the ledger grants (8 MiB over every region at most, a
quarter of what is left; `KOF_PIX_B_DEGRADED`); 8,000, 800,000 and 8,000,000 rules cost 0.07, 5.3 and 21.8 MB
(`kdb_pattern_status`). The tables of every pack are swept together (`kofpix_set`: a region is read once
whatever the pack count, the filters merged). A pack without a part - a smaller table, or an older pack -
has the same table built in memory from its own sections under half of what the ledger leaves
(`KOF_PIX_B_IN_RAM` when it was big enough to deserve a part, `KOF_PIX_B_OVER_BUDGET` when refused, and then
that pack's markers are searched one at a time, exactly; an unopenable table is `KOF_PIX_B_OPEN_FAILED`).
Per scanner: a fixed context (3.1 MB when a table is read from a pack, 0.2 MB when every table is in
memory: `kofpix_ctx_fixed`), a sparse table of what was found that is bounded by the object's ledger share and
charged to it (`sc->match.pix_ledgered`), and a memo that is a direct-mapped cache of at most 65536 cells; none
of it follows the marker count. A sweep that reaches its read bound, its record-visit bound (a base whose
markers share a key), a full found-table, a short read or a bad checksum STOPS and says so
(`KOFPIX_S_*`, `kof_stats.multi_degraded`); the region is then not swept and its masks are answered by the
per-marker path, which is exact. What loading touched of the pack's old part is given back as it goes
(`kof_map_drop`: after the checksum, every 128K modules while the tables are copied, and at the end of the
load), so the peak follows the pack no more than the steady state does. **Not yet inside the cap, and the
largest thing left: the module table**, about 155 bytes a rule at 8,000,000 rules: `struct kof_module` 136
(`mods`), the code copy (the blob, 16-aligned: 16 here, 75 to 170 in the shipping detector packs),
`rng_uid` 1 a range, `mod_by_target` 4 a target a module names (and 4 for one that names none: one list,
`mod_any`, merged with a format's own by `kof_mod_walk`; it was 116, a copy in every format), and
`blk_tab` 16 a block when several packs carry blocks (`kofexamine/kofinspect.c` reads `e->blk_tab[b]` and
`e->mods[i]`, so neither can leave memory while it does). The per-object walk over a format's modules is
O(modules) whatever is resident: past a few million rules the fix is a marker-driven selection (a module
runs because a declared marker was found), not a smaller record. A host that lives long calls
`kscan_trim` between objects; the engine never calls `mallopt`. A new allocation class is charged to
the scanner's ledger (`scan_charge`) or reserved in `kof_scan_fixed`, not added beside them.
The parsed views of zip, pdf, tar, lha, arj, cab, chm, docole, rar and 7z are the example of a table that follows the file and not a
constant: their entries, objects, folders, streams and runs are allocated to what the structure holds (bounded by the object's length over the smallest record, and
by the ledger: `struct kof_view_mem` in `range.h`, `kof_tab_grow` in `tabgrow.h`), charged when the parse ends and given
back at the end of the object (`sx_views_release`); a table the ledger cannot grow stops the walk and the format's own
"full" bit says so. The extents a region resolves into start at `KOF_SCAN_MAX_EXTENTS` and grow the same way
(`scanners/scan_ext.c`). A module walks those tables with `kof_zip_next` / `kof_pdf_next` / `kof_<format>_next`, one vtable slot (`view_next`, the
format is the object's), so the host sees that it did (`sx_walk_check`): a module that returns before its walk
must still make one call. What a table's bound is, per format, is written at its `KOF_*_MIN` constant in `kofmod/<format>.h`
(a cabinet's folder blocks are listed once per folder and searched, and the work of listing them is budgeted at twice the blocks
the file can hold; a 7z header may decode to sixteen times the bytes it is stored in).

**Names inside libgenome (built, not provisional).** A file name says what the
file is: `<family>_<part>.c`. The family is the subject (what the symbols in it
are called), the part is the job of that file in it.

- Directories: `genotype/` (one instruction: decoders and tables per
  architecture, the PE/ELF image), `celllysis/` (reading code without running
  it), `phenotype/` (running code and diagnosing what it does).
- Families in `phenotype/`, and the part words they use:
  `emu` - the interpreter (`emu_interp`, `emu_api`, `emu_mem`, `emu_ops`,
  `emu_sys`, `emu_vec`, `emu_x87`, `emu_win*`; public header `emu.h`);
  `emu_unpack` - running a sample to take its code out (`emu_unpack_gate`,
  `_map` the image loader both formats share, `_elf`, `_pe`, `_pe_teb`,
  `_pe_module`, `_pe_dump`; public header `emu_unpack.h`);
  `diag` - the diagnose scan (`diag_scan` the scan object, `diag_origin`,
  `diag_hit`, `diag_site`, `diag_sweep`, `diag_sweep_cand`, `diag_code`,
  `diag_str`), its routes (`diag_emu*` emulate, `diag_sym` symbol, `diag_pe`
  PE imports, `diag_apihash`) and the syscall-wrapper analysis
  (`diag_wrapper*`; "wrapper" is a libc function whose job is one syscall, and
  is spelled out for that reason); public headers `diag_scan.h`, `diag_vocab.h`
  and `diag_scan_state.h` (the open scan object, which the engine's matcher
  reads). `diag` is the one family with several private headers, because it is
  four jobs under one prefix: `diag_private.h` (what one analysis routine needs from
  the scan it fills), `diag_scan_private.h` (the scan object, its hits and the sweep),
  `diag_emu_private.h` (the emulate route's stages) and `diag_wrapper_private.h` (the
  syscall-wrapper analysis); the last three include the first.
- Families in `genotype/image/` and `celllysis/` where the file names differ from
  the old ones: `image` (the file-offset/address translation, `image_addr`),
  `nucleo` (the capability vocabulary and the syscall tables: `kgenome_nucleo_*`,
  `KGENOME_NUCLEO_*`, one family and no longer `flow` beside it), `mutation`
  (`mutation_units`, `mutation_pool`, public header `mutation.h`). In libuncoat the
  MPRESS call filter is `mpress` and the bzip2 decoder is `bunzip`, as their symbols say.
- A family that is split across files has ONE private header,
  `<family>_private.h` (never `_int.h`: `int` says nothing). It holds the types
  the parts share and the prototypes of what one part offers another; it is not
  installed and not part of the surface. Small functions on the hot path that
  more than one part calls are `static inline` in it, so the split costs no call.
- Symbols: `kgenome_<family>_...` for functions and types,
  `KGENOME_<FAMILY>_...` for macros and enumerators, the same family as the file.
  When the family has routes or parts that need telling apart the part comes
  next (`kgenome_diag_emu_...`, `kgenome_diag_wrapper_...`). No `kof` in a name
  inside libgenome; the module-facing spelling is an alias in `kofmod/` and keeps
  its old name (`#define kof_diag_str kgenome_diag_str`).
- Object files: `build/temp/gt_*` (genotype), `cl_*` (celllysis), `ph_*`
  (phenotype), `uc_*` (uncoat), `lib_*` (engine).
- Splitting a big file: cut at a responsibility, name the pieces `<family>_<part>`,
  move the types and macros two pieces share to the private header, give the
  statics they share the family prefix. A function longer than about 400 lines is
  a sequence of named static steps.
- One spelling is still two: the emulated-unpack API is `kgenome_emu_unp_*` /
  `KGENOME_EMU_UNP_*` (the examiner reads it) while the files say `emu_unpack`.
  The private names follow the API. Spell it out the next time the examiner is open.
- `libuncoat/` has `transform_private.h`; the same rule applies there.
- A thing both the lib and the engine need (a comparator, a hash step, a byte
  histogram) lives once in core and the lib includes it: `kofcmp.h`, `kofcore.h`'s
  `kof_hash_step`, `kofentropy.h`'s `kentropy_count`. A lib header does not include
  the engine.

**Decided with it.** The PE/ELF rebuild writers live in `kgenome`, next to the
code that reads the same layout. `kuncoat` does not rebuild a file: a routine
identifies the packer and extracts its parameters, `kuncoat` runs the
algorithm on bytes, and the engine asks `kgenome` to write the file back. So
`kuncoat` needs no PE or ELF structure: it runs algorithms on bytes. A
packer-specific algorithm (ASPack's block decoder, MPRESS's call filter, UPX's
unfilter) is still just an algorithm and lives with the decompressors; what
interprets the packer's own layout stays in the `bases/` routine.

**Not decided yet.** The open method-id space for new algorithms; whether
decrypt splits from decompress when it grows.

**Where the rest of the tree lives.**

- `libkoforbit/` is the collectors and what they produce. `antarc/` is the Linux
  collector and `grille/` the Windows one; `evt/` is the event record both fill,
  `fridge/` the clean-file cache, `report/` the trace report, `chan/` the channel
  between a sensor and its consumer. `mon/` and `walk/` hold only a header each -
  `kofmon.h` the sensor contract and `kofwalk.h` the process walk - which `antarc/`
  and `grille/` implement; they are contracts, not unfinished code.
- `ksigbuilder/` is one program with several modes (a module build, `--tree`,
  the pack, `--diagnose`, `--extract`, `--image`), in `ksb_*.c` units behind one
  private header, `ksb.h`: a unit is a mode or one responsibility inside it
  (`ksb_read` reads a declaration's arguments, `ksb_scan` finds the macros,
  `ksb_artefact` / `ksb_group` / `ksb_pack` are the pack, `ksb_tree` / `ksb_uses`
  the tree walk, `ksb_diag*` / `ksb_disease` the diagnoses and diseases). The state
  of a run is one `struct ksb_ctx`, allocated in `ksb_main.c` and passed as the first
  parameter, `ksb`: a function that takes none touches no run state. What one unit
  offers another is declared in `ksb.h` with a `ksb_` prefix; everything else is
  `static`. A new `ksb_*.c` is picked up by the Makefile's wildcard.
- `analyzers/diseases/` is the disease units - name checks, the id, the `msf_*.h`
  declarations - which the loader, the builder and the modules share.
- `bases/` now holds the unpackers, decompressors and decoders only (`bases/unp`,
  `bases/decomp`, `bases/decoders`). The signatures, the diagnoses and the heuristic rules
  were written against a verdict model that named an object from what ONE module reported
  (`KOF_SCAN_INFECT`/`SUSPECT`/`HEUR` and their levels); that model is removed, and the
  verdict is made from the diseases the matched diagnoses declare (the diagnoses are
  generated, by kofviewer/kofeditor). A module's whole voice is a note (`kof_debug`) and
  a mark (`kof_mark_infected`); a module that names a packer or a cure through the old
  macros has no place in `bases/`.
- `bases/syndromes/` holds the TAG SOURCES: the unit of classification is the tag, a tag has a
  name, activities, types and a family with file attributes, and each of those is an entity with
  an id of its own (a 64-bit random number the tool generates once and never changes; ids below
  0x10000 are the seeds'), written in a file of its own named `<kind>_<name>_<first 8 hex of
  id>.c`. They are DATA: no pack carries them, `ksigbuilder --tree` skips the directory, and the
  verdictor and the engine do not read them. The tools do, through `databases/tagsrc.h` and
  nothing else (it patches a file by the same loop as a diagnose source, `kof_dsrc_patch_with`):
  kofviewer's Analysis > Syndrome table and the diagnose panel's Tag cells, and `ksigbuilder
  --tags <dir>`, which prints the Check and exits non-zero on an error. **The only place for the
  word "syndrome" is this directory's name**: so in a path that names it (`bases/syndromes`,
  kofviewer's `--syndromes`) and in the menu item `Syndrome table`; every other name,
  comment and document says tag, activity, type or family. `make check-rules` fails on any other
  use (the retired pack name `syndromes.kdig` is the one older exception, named in the check).
- `docs/disabled/` holds what is switched off: a `.c` whose first lines say why, kept out
  of `bases/` so that nothing walking `bases/` has to know to skip it. It has one
  subdirectory per kind - `signatures/`, `diagnoses/`, `heur/` - and each file opens with
  `Disabled <date>: <why>; copy back to bases/ to enable`. The old signatures and heur rules
  also say that enabling them needs the removed macros back. Nothing builds from here, and
  nothing here is a test fixture (those are `tests/sigs` and `tests/shape`). To turn one on,
  copy it back.
- The Makefile is a short list of `include mk/<part>.mk` lines, in dependency order
  (platform, shell, flags, entry, stamp, libs, sdk, sources, tools, grille, packs, tests,
  deps, asan, misc, checks); a variable is set by an earlier fragment than the first rule
  that names it, so a new source list goes in `mk/sources.mk`, a new tool in `mk/tools.mk`.
- `docs/exports_kept.txt` lists what is exported, defined or named and has no engine caller
  (tests-only exports, the emulator's diagnostic API, ABI vocabulary, members of a set), with the
  reason each stays. A new such name is added there, or it is deleted or made static.
- `tools/` is for developer tools that are not part of a build (the layer check,
  the x86 table generator, the decoder differential tools). A tool that needs
  something outside this tree to run says so in its header and is not built by
  `make`; one that needs nothing outside is built by a target.
- Object files go to `build/temp/<prefix>_...`: `lib_` the engine, `gt_`/`cl_`/`ph_`
  genotype/celllysis/phenotype, `uc_` libuncoat. The prefixes are the build's
  spelling (`OBJ_RULE` in `mk/libs.mk`); they predate the lib names and are not API.

`make check-rules` runs `tools/check_layers.py`, which checks the include
direction between these parts (`libgenome/` is `kgenome`, `libuncoat/` is
`kuncoat`, `libkofeng/kofcore` is core). An upward include fails. There are no
baseline files: every rule passes with no violation, and what cannot be cut today is
in the `EXEMPT` table of `check_layers.py`, each entry with its reason (an entry whose
violation is gone is reported so the line can be deleted).

The same script checks more things (described below).
**The engine's own order**, bottom to top: `core` (`libkofeng/kofcore`) <
`analyzers` (`analyzers/`) < `pack` (`databases/pack/`: the
layout of a loaded pack and its accessors, which the matchers read) <
`detectors` < `databases` (the loader and packer, which BUILD matchers) <
`verdictor` (`verdictor/`: the names, `verdict.h`) < `scanners` < the public API
(`libkofeng/kofeng.{c,h}`); a file may include its own class and lower ones
(the scan's types live in `libkofeng/kofcore/koftypes.h`, which `kofeng.h` includes, and the verdictor is handed a `struct kof_verdict_in` by the scanners). **The core closure**: no file of core proper
may reach `libgenome/` or `libuncoat/` through a chain of includes, because
a direct-include check cannot see `rangelist.h -> kofsig.h -> libgenome`
(`kofmod/` re-exports the libs' types on
purpose and is only an intermediate node, never a source).
**Tool includes**: a program under `kofscanner/`,
`ksigbuilder/`, `kofwatcher/` or `tools/` names the engine by an include root
(`<kofeng.h>`, `<databases/dbpacker.h>`, `<kofmod/kofsig.h>`), never by a relative
path out of its own directory. `kofscanner` is written against the SDK headers
(`kofeng.h` and the core headers the SDK ships beside it); `ksigbuilder` is the
one program that reads the engine's inner headers, and says so with `-Ilibkofeng`.
**Include guards**: a header's guard macro contains the
header's file name, so a guard cannot be copied from another file unchanged
(`libgenome/` and `libuncoat/` guards are covered by the prefix pass, which also
requires the lib's prefix).
**Five more** (module includes, lib public headers, headers compile alone, tests and
`/tmp`, and the orbit rule inside the part check). **Lib public headers**: see "One public SURFACE per lib"
above - a file outside a lib includes only what its umbrella names. **Module includes**: everything a file under `bases/` includes is
`<kofmod/...>` or `<kofshared/...>` - a module is a freestanding blob that reaches the
engine and the libs only through the module ABI, and a module's file is included by no
other (`bases/` carries no shared code, so this is that rule too). **Orbit**:
`libkoforbit/` is classed `orbit`, above the engine; no engine or lib file includes it
(the standard says nothing about what orbit may include, so it may include anything).
**Headers compile alone**: every header of `libkofeng/`, `libgenome/` and `libuncoat/`
is compiled by itself with `-fsyntax-only` (`_GNU_SOURCE` set, as a translation unit
sets it; a header of the module ABI after `<kofmod/kofsig.h>`, which is how a module
meets it; `analyzers/diseases/msf_*.h` skipped, they include `<kofshared/...>`, which
exists only in the staged SDK) - under a second, 16 threads. **Tests and /tmp**: a test
creates its files beside the build output (`build/kof_<name>_XXXXXX`), never under
`/tmp`; what is flagged is a creating call given a `/tmp` path (or a path built from
one), and `tmpfile`, `tmpnam`, `tempnam`, `P_tmpdir`, `kof_tmpdir` - a `/tmp` string that
is only text in a record under test is not. Honouring `TMPDIR` is allowed; defaulting to
`/tmp` is not.
**Five more (orbit headers, function length, file size, kof names in libgenome, getenv in tests).** *Orbit headers compile alone*: the
18 non-Windows headers of `libkoforbit/` are compiled by themselves with the orbit
include roots (the Windows ones need `windows.h` and are not tested). *Function
length*: no function over 400 lines; `EXEMPT` names the ones that cannot move
today - `kgenome_emu_run` (one interpreter switch over shared register state) and the
unpackers under `bases/` (a module's pack bytes follow its functions' order and source
lines, see "bases/" above). *File size*: a hand-written `.c` over 1500 lines or a header
over 1000 is a prompt to look, not an order to split. Size is not the fault; mixing jobs a
reader would look for separately is. A file over the ceiling needs a recorded reason: split
it by purpose (one private header per family), or put it in `EXEMPT` with a one-line
reason `cohesive: <what it is>` (one decoder, one interpreter loop). Judge it by what it
is for, and when it is one job the fix is smaller - name the steps of an over-long
function - or none. The module ABI's `kofmod/kofcontent.h` is exempt by name: it is ONE
struct whose member order is the ABI, there is no cut by purpose that is not an ABI move.
`libgenome/`, `libuncoat/` and the non-Windows orbit are in the pass; `kofexamine/` is
not. *No kof name in libgenome*: the lib defines `kgenome_` /
`KGENOME_` names, including its static helpers' macros and tags; it may use core's
`kof_` names. *getenv in tests*: a test reads the environment only for scratch space
(`TMPDIR`, `TMP`, `TEMP`); the four that exist today are in `EXEMPT`. *Parameter
count*: no function definition in `libkofeng/`,
`libgenome/`, `libuncoat/`, `ksigbuilder/`, `kofscanner/` or `kofwatcher/` takes more than 8
parameters (see "One request, one result" above); the one `EXEMPT` entry is the
positional `kgenome_elf_write_hdr` wrapper kept for kofexamine. A new check goes in `check_layers.py` (an `EXEMPT` entry needs a stated reason), and is
shown to fail on a deliberate violation before it is trusted.
Which rules a grep or this script cannot see - "no writable global state", "a tool
does not compose verdicts" - are checked in review.

**Nothing a module says stops the scan.** A module's note and mark are EVIDENCE: they go to the
debug callback and to `kof_result.infected` and are not the answer, so nothing they say ends a stage.
There is no first-hit option: a detection does not end the detect stage, the open chain (the normalised
view and block similarity run on an object a detector marked), the heuristic pass or the unpacking of
its object. The one stop that remains is the chain's own: a step that PRODUCED a child (not a carve)
ends it. A disease a diagnose needs from a later module is therefore always reached, which is the
point: the verdict is read off the whole set of what matched.

**The module ABI is several headers behind one umbrella.** `libkofeng/kofcore/kofmod/kofsig.h`
is the only ABI header a signature module includes (`bases/*.c` also names the module-side
helper headers beside it, below); it holds
the module contract, the alias block for the libs' types, and `#include`s the parts, each of which
has one purpose and carries its own docs: `kofabi.h` (ABI version), `kofobjfmt.h`
(format enum, target axis, format and arch names), `kofname.h` (what a name or comment may hold),
`kofregion.h` (region masks, extent bound, region shape), `kofcontent.h` (`struct kof_content`, the
vtable), `kofentry.h` (decoder ids, entry kinds, `struct kof_entry`), `kofctx.h` (`struct
kof_obj_ctx`), `kofdefine.h` (`kof_scan`/`kof_unpack` and the macros defining them),
`kofsearch.h`, `kofmeasure.h`, `kofdiagnose.h`, `kofread.h`, `kofchild.h`, `kofmodemu.h` (the macros a
module calls, by what they ask the host), `kofverdict.h` (engine, verdict, malware type lists),
`kofdeclare.h` (what the build reads out of a source), `kofhit.h` (the note and the mark a module may leave). A new
macro goes in the part whose question it asks, not in the umbrella; a new part is added to
`SDK_HDR` (`mk/sdk.mk`) and to the list in the umbrella's header comment. The parts are not
included by modules directly, so the freestanding-blob rule is unchanged.

**`struct kof_scanner` is a set of sub-structs, one per lifetime or stage**
(`scanners/scan_state.h`; the types in `scan_state_life.h`, `scan_state_child.h`,
`scan_state_stage.h`, the constants and enums in `scan_types.h`, the functions in
`scan.h`). It was 193 fields in one struct and "which stage owns this" was not
written anywhere. Now: `sc->obj` is everything wiped for each object - **`sx_obj_begin`
(`scan.c`) is the one place per-object state is reset**: it releases what the fields own
and then does one `memset` of `sc->obj`, so a field added to `struct kof_scan_obj` is
reset without anyone naming it; `sc->mod` is wiped by `sx_mod_begin` (by hand, because
three of its fields are arrays whose clearing every module of every object would pay
for); `sc->cur` is the object in hand (set by the walk and FACTS); `sc->pend` is what a
producer declared for its next child (`oc_pend_clear` is the one list); `sc->child` is
the children collected; `sc->emu`, `sc->sink`, `sc->ledger` (the budget, per tree),
`sc->cache`, `sc->match`, `sc->syms`, `sc->diag` and `sc->subject` are the per-stage
and per-scanner state. Each sub-struct's comment says which unit owns it and which
files touch it. A new field gets the lifetime it has; if it has none of these it is a new
stage and gets a struct with the same header comment. `mutation` stays at the top level
because `kofexamine` reads it; it moves into `sc->match` with that tool's upgrade.

**The verdict is made of diseases, not of findings** (`kof_result.verdict`, `scanners/scan_verdict.c`,
`verdictor/verdict.c`). A DISEASE is what a diagnose finds, `(maltype, behaviour)`
(`KOF_DECLARE_DISEASE`, in a diagnose only: a module that declares one is refused by the build). An object's verdict exists when at least one disease matched (an OR: one matched
diagnose is enough) and its name is a function of the diseases alone, `kof_verdict_make`: the LEAD disease
is the most specific one (the behaviour path with the most `/` parts, then the lower type, then the lower
id); the name is `<verdict word>#<target>/<Type of the lead>:<its behaviour, '/' written '.'>` and
`!Diagnose` when a diagnose matched, with the types the other diseases carry as the reason, `?A+B`;
the verdict word is Infected. The finding carries what
it was made of - the ids of the matched diagnoses (`diag[]`) and of the diseases (`disease[]`), each
bounded by `KOF_VERDICT_TRACE` with its true total beside it - and `kdb_diagnose_name`,
`kdb_diagnose_disease`, `kdb_disease_name` and `kdb_disease_type` turn an id back into what a person
reads (kofscanner `-v` prints one `diagnose <name>` line per matched diagnose under the verdict).
`on_event_detected` fires once per object that has a verdict; the evidence never reaches it.
`kof_result.verdict_incomplete` says the set may be missing a disease; with nothing else found the object
is marked broken instead. **One verdict per top-level file is the engine's** (`kverdict_filemap_*` in
`verdictor/verdict.h`): a host calls `kverdict_filemap_fold(map, object_name, result, keep_clean)` from
its on-object callback; the file's verdict is the first made in its tree, the name-to-file split (the
first `//`) and the "examined" OR are in it, so a tool does not compose one. `kof_stats.verdict_lost`
(files counted with a verdict and no event) is the engine's own check that the two read one fact, and
`tests/unit/verdict_delivery.c` runs it over any corpus. An analysis route that ran out on an object that
OPENED into a child is `kof_result.analysis_moot`, not `KOF_BROKEN_LIMIT`. The shipped database
holds no diagnose, so it reports no verdict.

**Which diagnose was called** is said by the engine, not by a diagnose (they are generated and carry no code): one
line per diagnose and event, `[diag] <name> id=<hex> asked-by=<module|-> gate=<open|closed:<signs>> routes=<declared>
route=<static|emulate|-> insn=- stop=<scan status> answer=<yes|no|unknown>` (`scanners/objctx_diag_trace.c`), as
`KOF_TRACE` in a DEBUG build and, in any build, as the debug-callback fact `kverdict_fact_id("diag")` (`what` is the
line after `[diag] `, `value` 1/0/2) when the host registered `kscan_on_debug`; `tests/unit/diag_trace.c` pins it.

**The big engine units are split by what they serve, with a private header.** `scanners/objctx_decomp.c`
(sinks and the streaming dispatch) shares `objctx_decomp.h` with `objctx_decomp_buf.c` (codings whose
whole output must be addressable), `objctx_decomp_text.c`, `objctx_decomp_folder.c` (BCJ2, MSZIP, LZX),
`objctx_decomp_entry.c` (an entry, a coding chain) and `objctx_decrypt.c`. The PDF parser in
`analyzers/parsers/containers/` shares `pdf_int.h` between `pdf_parse.c` (the parse), `pdf_walk.c`
(objects), `pdf_xref.c` (trailer, cross reference), `pdf_dict.c` (one dictionary), `pdf_entries.c`
(the entry table), `pdf_index.c` (lookups by object number), `pdf_docinfo.c` and `pdf_names.c`. The small helpers a hot loop calls stay
`static inline` in the private header; what two units call is an extern with the family's prefix
(`oc_`, `pdf_`). A new file in either family is picked up by the wildcard.

**Splits by responsibility, each with one private header (no logic moved).** The child
declaration unit is `scanners/objctx_child.c` (close, gather, produced reads, the budget),
`objctx_child_sink.c` (the pending set, the claims a pushed child spends, the sink) and
`objctx_child_image.c` (what a module declares about the child's image); the interpreter
unit is `objctx_emu.c` and `objctx_emu_gather.c` (what a run produced); the diagnose unit
`objctx_diag.c` and `objctx_diag_query.c`; all share `objctx_int.h`. The pack loader is
`databases/dbloader.c`, `dbpackcheck.c` (validation) and `dbloader_packs.c` (mapping and
the side tables), sharing `dbloader_int.h` (`kof_db_`); the pack's tail container (the block index, the
pattern part's footer and the sliced reader both parts are read through) is `databases/pack/dbkix.c`, below
the detectors because the matchers read it; the pattern table is `detectors/pattern/kofpix.c` (open, the set,
the sweep), `kofpix_build.c` (the packer's side, and a pack's markers from its own sections) and
`kofpix_private.h` (the layout), with `kofmultimatch.{c,h}` as what a marker is to it (keyable, the key, the
verification); the diagnose source reader is
`diagsrc.c`, `diagsrc_parse.c` and `diagsrc_resolve.c`, sharing `diagsrc_int.h`
(`kof_dsrc_`). The tools: `kofscanner/` is `kofscanner.c` (arguments, the run),
`kofscan_out.c` (output) and `kofscan_procs.c` (`--scan-procs`), sharing `kofscanner_int.h`
(`ksn_`); `kofwatcher/kofmontrace*.c` is the run, the scan and spill half and the tracer,
sharing `kofmontrace_int.h` (`kmt_`); `libkoforbit/antarc/aproc.c` is the process list and
`aproc_pmem.c` one process opened, sharing `aproc_int.h` (`kofa_`). A header over 1000 lines
is an umbrella over parts that sit beside it: `koftypes.h` (`kofobjname.h`, `kofresult.h`,
`kofoption.h`), `kofplatform.h` (`kofplatform_os.h`, `kofplatform_file.h`), `kofevt.h`
(`kofevt_vocab.h`, `kofevt_record.h`), `aproc.h` (`aproc_proc.h`, `aproc_region.h`,
`aproc_pmem.h`), `kofgrille.h` and `wproc.h` (three parts each); an includer keeps the
umbrella. `kofmod/kofcontent.h` stays one header: it is ONE struct (the module vtable) whose
member order is the ABI, so no cut by purpose exists that is not an ABI move.

## Working in this tree

- **Scratch files go in `/mnt/games/`, never `/tmp`.** `/tmp` is a 3.2 GB
  tmpfs here and filling it has broken the build twice.
- **Scan copies.** The scanner repaired infected files in place until the cure
  stage was removed with the old verdict, and four originals were destroyed
  learning that. It writes nothing now; keep copying a sample and `chmod a-w` the
  copy, because the habit is cheaper than the next mistake.
- **`make tui-test` and `make population` are not part of `make unit`.** The
  first drives the real viewer (python3 and pyte); the second writes N synthetic
  signature sources for a scale measurement - not evidence about detection.
- **`make unit` builds a different database** from `make`. Running a test
  binary by hand afterwards measures the wrong pack, and a corpus measurement
  in the same command as a build measures the build too.
- **Look for a runaway before trusting a timing.** Two were found here
  holding a core, one with four days of CPU, quietly making every number on
  the machine worse.
- **Write to the person in the language they are using.** The notes in the
  code stay in English, because that is what the rest of the tree is in.
