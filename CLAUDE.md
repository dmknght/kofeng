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

- A chain was rendered as pseudo code in the viewer and as a flat list in the
  examiner - two spellings of one chain, and the flat one was wrong. One
  renderer now, `kof_chain_render`.
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

- State the gate **before** the change. For analysis work it is chains,
  links, loop coverage and time - **not** detections: there is no pathogen
  matcher yet, so the detection count cannot move and quoting it proves
  nothing.
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

## 12. Where code lives (PROVISIONAL - moves to README and the wiki)

This is the target model decided 2026-10-12. Most of it is NOT built yet: the
tree today ships one archive (`libkofeng.a`) with the layers below as directories,
and ALSO builds the two libs as archives of their own from the same objects -
`libkgenome.a` (libgenome, plus the one foundation object it calls,
`kofentropy.o`) and `libkuncoat.a` (libuncoat) in `build/temp`. They are not
shipped; they exist so that `tests/lib/genome/*.c` and `tests/lib/uncoat/*.c`
are linked against ONE lib's archive and nothing else, which is the test that
the lib does not reach the engine (an engine symbol is an undefined reference
there). `make unit` runs them; `make unit-asan` runs them against the
sanitised twins. A new file in either directory is picked up by wildcard.
`libuncoat/`
(kuncoat) is built as its own top-level directory (parts `decompressors/`,
`decryptors/`, `decoders/`; one umbrella header `<uncoat.h>`, one transform API
`transform.h`, status enum `kuncoat_status` in `status.h`); the part
of libgenome that exists is `libgenome/`. Do not move code to match the rest
without being asked; do not add code that contradicts it.

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
  lineage walk and its products. It defines its own structs.
- `kuncoat` is the algorithms that grow without a forecast, in three parts:
  `decompressors`, `decryptors`, `decoders`. Buffers and a budget in, bytes and
  a status out. There is no `unpackers` part: unpacking a packer statically is a
  ROUTINE in `bases/` (it identifies the packer, reads its parameters, and calls
  these algorithms), and unpacking that RUNS the sample is `kgenome`'s.
- A container (zip, rar, OLE, PDF...) is opened by the engine into child
  objects, and a child re-enters the pipeline. A lib analyses ONE object.

**Rules every lib follows.**

- Names: `kgenome_` and `kuncoat_` on every public function, type and macro
  (`KGENOME_`, `KUNCOAT_` on macros). The engine keeps `kof_`.
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
- One public header per lib. Everything else is private to it.
- Modules are freestanding blobs: they reach a lib only through a slot of the
  module ABI, which the engine owns and implements by calling the lib.
- `bases/` is case routines that use the module API. Anything two routines
  share, or that is big enough to need its own tests, graduates into a lib or
  the engine; `bases/` does not carry shared code. The analysis that is specific
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
  `kgenome`; the engine-side function stays as the adapter and says so.

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

`make check-rules` runs `tools/check_layers.py`, which checks the include
direction between these parts. The parts are classed by where their code is
GOING (the lineage backend, now in `libgenome/phenotype`, counts as
`kgenome`; `libuncoat/` is `kuncoat`), so the edges in `tools/layers.baseline`
are the list of cuts the move still has to make. A new upward include fails;
the baseline only shrinks.

The same script checks two more things, each with its own baseline file.
**The engine's own order**, bottom to top: `core` (`libkofeng/kofcore`) <
`analyzers` (`analyzers/`, and `extractors/`, which holds only thin files that forward to the lib APIs) < `pack` (`databases/pack/`: the
layout of a loaded pack and its accessors, which the matchers read) <
`detectors` < `databases` (the loader and packer, which BUILD matchers) <
`verdictor` < `scanners` < the public API
(`libkofeng/kofeng.{c,h}`); a file may include its own class and lower ones
(`tools/layers_engine.baseline`, now empty: the scan's types live in `libkofeng/kofcore/koftypes.h`, which `kofeng.h` includes, the syndrome set the loader builds is `databases/pack/kofsyndrome.*`, and the verdictor is handed a `struct kof_verdict_in` by the scanners). **The core closure**: no file of core proper
may reach `libgenome/` or `libuncoat/` through a chain of includes, because
a direct-include check cannot see `rangelist.h -> kofsig.h -> libgenome`
(`tools/layers_closure.baseline`; `kofmod/` re-exports the libs' types on
purpose and is only an intermediate node, never a source). Both baselines only
shrink.

## Working in this tree

- **Scratch files go in `/mnt/games/`, never `/tmp`.** `/tmp` is a 3.2 GB
  tmpfs here and filling it has broken the build twice.
- **A scan is not read-only.** The scanner repairs infected files in place.
  Copy a sample before scanning it and `chmod a-w` the copy; four originals
  were destroyed learning this.
- **`make unit` builds a different database** from `make`. Running a test
  binary by hand afterwards measures the wrong pack, and a corpus measurement
  in the same command as a build measures the build too.
- **Look for a runaway before trusting a timing.** Two were found here
  holding a core, one with four days of CPU, quietly making every number on
  the machine worse.
- **Write to the person in the language they are using.** The notes in the
  code stay in English, because that is what the rest of the tree is in.
