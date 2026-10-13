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
  family/variant separator moved from "-" to "#" in the engine, the examiner's
  copy kept the "-", and every detected sample showed no verdict in the examiner
  while the scanner called the same file infected. One spelling now,
  `kverdict_compose` (`libkofeng/verdictor/verdict.h`).
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
- Freeze the binary and the corpus. The scanner repairs in place, so scan
  copies and `chmod a-w` them.
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
or filter findings by logic of their own. When a tool needs something the
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
  DIAGNOSE (`bases/diagnoses/`; `kofmod/kofdiagtree.h` holds its graph layout;
  `KOF_ENGINE_PATHOGEN` and `KOF_ENG_USE_PATHOGEN` are aliases of
  `KOF_ENGINE_DIAGNOSE` / `KOF_ENG_USE_DIAGNOSE`, same values, kept for
  kofexamine and old module sources); a module asking
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
  in, and every report (`KOF_SCAN_INFECT`, `kof_debug`) carries the source line it
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
- `scanners/pzero.{c,h}` is the cure stage (what a file was before it was
  infected). It is a stage of the pipeline: it takes the object context and the
  cure request, so it lives with `scanners/` and not in `analyzers/`.
  `analyzers/diseases/` is the disease units - name checks, the id, the `msf_*.h`
  declarations - which the loader, the builder and the modules share.
- `docs/disabled/` holds a module that is switched off: a `.c` whose header says
  why, kept out of `bases/` so that nothing walking `bases/` has to know to skip
  it. To turn one on, copy it back.
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
(the scan's types live in `libkofeng/kofcore/koftypes.h`, which `kofeng.h` includes, the syndrome set the loader builds is `databases/pack/kofsyndrome.*`, and the verdictor is handed a `struct kof_verdict_in` by the scanners). **The core closure**: no file of core proper
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

**The module ABI is several headers behind one umbrella.** `libkofeng/kofcore/kofmod/kofsig.h`
is the only ABI header a signature module includes (`bases/*.c` also names the module-side
helper headers beside it, below); it holds
the module contract, the alias block for the libs' types, and `#include`s the parts, each of which
has one purpose and carries its own docs: `kofabi.h` (ABI version, finding level), `kofobjfmt.h`
(format enum, target axis, format and arch names), `kofname.h` (what a name or comment may hold),
`kofregion.h` (region masks, extent bound, region shape), `kofcontent.h` (`struct kof_content`, the
vtable), `kofentry.h` (decoder ids, entry kinds, `struct kof_entry`), `kofctx.h` (`struct
kof_obj_ctx`), `kofdefine.h` (`kof_scan`/`kof_unpack`/`kof_cure` and the macros defining them),
`kofsearch.h`, `kofmeasure.h`, `kofdiagnose.h`, `kofread.h`, `kofchild.h`, `kofmodemu.h` (the macros a
module calls, by what they ask the host), `kofverdict.h` (engine, verdict, malware type lists),
`kofdeclare.h` (what the build reads out of a source), `kofhit.h` (report, mark, cure). A new
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

**One verdict per top-level file is the engine's** (`kverdict_filemap_*` in
`verdictor/verdict.h`, reached through `kofeng.h`): a host calls
`kverdict_filemap_fold(map, object_name, result, keep_clean)` from its on-object
callback and reads the files back with `_at` / `_count` / `_files`. The name-to-file
split (the first `//`), the rank of the three levels and the "examined" OR are in it, so
a tool does not compose a file's verdict; `kofscanner` only prints.

**The big engine units are split by what they serve, with a private header.** `scanners/objctx_decomp.c`
(sinks and the streaming dispatch) shares `objctx_decomp.h` with `objctx_decomp_buf.c` (codings whose
whole output must be addressable), `objctx_decomp_text.c`, `objctx_decomp_folder.c` (BCJ2, MSZIP, LZX),
`objctx_decomp_entry.c` (an entry, a coding chain) and `objctx_decrypt.c`. The PDF parser in
`analyzers/parsers/containers/` shares `pdf_int.h` between `pdf_parse.c` (the parse), `pdf_walk.c`
(objects), `pdf_xref.c` (trailer, cross reference), `pdf_dict.c` (one dictionary), `pdf_entries.c`
(the entry table), `pdf_docinfo.c` and `pdf_names.c`. The small helpers a hot loop calls stay
`static inline` in the private header; what two units call is an extern with the family's prefix
(`oc_`, `pdf_`). A new file in either family is picked up by the wildcard.

**Splits by responsibility, each with one private header (no logic moved).** The child
declaration unit is `scanners/objctx_child.c` (close, gather, produced reads, the budget),
`objctx_child_sink.c` (the pending set, the claims a pushed child spends, the sink) and
`objctx_child_image.c` (what a module declares about the child's image); the interpreter
unit is `objctx_emu.c` and `objctx_emu_gather.c` (what a run produced); the diagnose unit
`objctx_diag.c` and `objctx_diag_query.c`; all share `objctx_int.h`. The pack loader is
`databases/dbloader.c`, `dbpackcheck.c` (validation) and `dbloader_packs.c` (mapping and
the side tables), sharing `dbloader_int.h` (`kof_db_`); the diagnose source reader is
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
- **A scan is not read-only.** The scanner repairs infected files in place.
  Copy a sample before scanning it and `chmod a-w` the copy; four originals
  were destroyed learning this.
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
