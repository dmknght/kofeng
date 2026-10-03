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
