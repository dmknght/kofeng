# The object pipeline: one description, declared at every stage

Status: design, not built. Written 2026-09-29 from what the modules in
`bases/unp/` actually demand, measured on `111.exe` (MPRESS over VMProtect over
an XOR string table), `explorer.exe` (VMProtect), `update_v103.exe` (MPRESS, x64
build), `vdr.exe`/`telvm.exe` (Themida) and `007 Spy.exe` (PECompact 2).

Read `QUALITY_AUDIT.txt` beside this: section 7 states which of its boxes this
work has to tick, and two of them are the reason for design decisions here.

---

## 1. The pipeline

```
sniff  ->  parse  ->  decompress  ->  unpack  ->  normalize  ->  matcher
             |            |             |            |
             +------------+-------------+------------+--> all write the SAME
                                                          object description
```

Matchers are not only at the end. Some run before normalize, and some are
stage-specific - `zipslip` is a matcher over an UNWRAP's entry names and means
nothing anywhere else. So a stage is not a phase of the program; it is **what a
module is doing to the description**, and matchers attach to stages.

`enum kof_analyze` in `kofsig.h` already has UNWRAP, UNPACK, DECRYPT, CARVE,
NORMZ, with a note that `KOF_UNP_CONTAINER`/`KOF_UNP_PACKER` are the old
spelling of the first two. What is missing is the front of the pipeline (sniff,
parse, decompress as declared stages rather than engine internals) and any
statement of **which object is final**.

The engine supplies the mechanisms and the structure: declare a child object,
declare its regions, declare the data inside a region, declare which object is
final, declare what a later stage should do. Parsers, decompressors, unpackers
and normalizers fill and change that description in their own context. A module
says what it used, what came out, and what still needs changing. Reconstructing a
PE or an ELF is not writing a header - it is asking the engine to restore a
region, or to stand one up and mark it as invented.

---

## 2. Unpacking is a SEQUENCE OF STEPS, not a choice between two methods

This is the part the current engine cannot express at all, and it is the
requirement that shapes everything else.

Today unpacking is a fork: either a static module opens an object, or the
interpreter runs it. `unpack_object` in `scan.c` stops at the first module that
produces a child, "on the reading that the child replaces its parent as the
subject". So one layer is one method, and the two halves never meet inside a
single object.

Real samples are not like that. They are:

> static decodes the outer container -> the stub inside is a coding nothing here
> has -> run it until it has written the image -> now the image's own structure
> is readable again, so static takes over -> inside THAT is a string table with
> a decryptor that is plain to read -> static -> and a virtualised remainder that
> only running can touch.

`111.exe` is exactly three of those steps (MPRESS static, VMProtect static,
StrXor static) and stops where the fourth would be. `007 Spy.exe` needs step two
and has no way to get there cheaply.

**So unpacking is a loop over one object description**, and each turn is a step
contributed by whoever can take it:

```
  loop:
    offer the description to every module that declares it can act
    a module takes a step:
        - says what it consumed  (a region, an extent, an entry state)
        - says what it produced or changed  (regions, content, attributes)
        - says where it got to  (a resume point, if it is not finished)
        - says what it is blocked on, if anything
    the engine applies the changes and goes round again
    until no module takes a step, or a budget stops it
```

What that needs, that does not exist:

**The description survives a step.** Today a module's product is a new object
and the old one is done with. A step has to be able to leave the object changed
and still open.

**The emulator is a step like any other, and it is already resumable.**
`kof_emu_run(e)` returns a stop reason with the machine intact and is called in a
loop today (`emu_unpack.c:546`, `:1463`). What is missing is that nothing
re-offers the object to the static modules between those stops. A stop reason -
HANDOFF, FAULT, STALLED, BUDGET - is a natural point to ask "can anyone read
this statically now?", and on a packed image the answer changes the moment the
stub has finished writing.

**A step can be BLOCKED, and say on what.** "I need the region at 0x1000 to hold
content before I can continue" is a schedulable statement: the engine runs the
interpreter until that region is written, then comes back. Today VMProtect
expresses the same idea as a silent `return` and the object is simply never
opened.

**A step can be PARTIAL without being a failure.** Themida decompresses what it
can and asks for the interpreter; `KOF_UNP_BROKEN` is the only spelling and it
reads as a defect. "Finished this part, could not start that part, here is why"
is a different statement.

**A resume point is a declaration.** For the interpreter it is the machine
state, which it already holds. For a static decoder it is an offset and a
decoder state. Both are the module's, and both have to be storable on the
description so the next turn does not start over.

**Budgets are the engine's, and the loop is where they are spent.** Per
`QUALITY_AUDIT.txt` I.A: every budget is enforced by the host, never by the
module, and exhaustion is reported rather than silently truncating. A step loop
makes that easier, not harder - there is one place that decides whether to go
round again.

---

## 3. The flow of one unpack, and what it demands at each point

Six questions have to be answered to get from a packed object to plaintext. A
static module answers them by reading; a run answers them by executing. They are
the SAME six, which is what makes section 2's loop possible.

Today all six are answered in ONE place - `emu_unpack.c` - generically, from the
PE parse, for every packer at once. A module reaches two of them. Section 3.7
says where the answers should live instead, and it is not a wider parameter list
on the generic runner.

### 3.1 Start - where does the work begin

| | static | run |
|---|---|---|
| has | the header. MPRESS reads the build from the dword at EP+8; VMProtect finds its table by an `{RVA, 5}` anchor; StrXor votes on call targets and takes the busiest | `kof_emu_set_rip`, `kof_emu_set_reg`, `kof_emu_map`, `kof_emu_win_setup(image_base)` |
| module can say | nothing - each module finds its own start by searching | nothing. The entry point is the one the header declares, decided in `emu_unpack.c` |
| missing | - | "start at this RVA, not the declared entry" - which is what a resumed step needs, and what a module that has already located the second-stage entry statically would give |

MPRESS's x64 gap is this question going unanswered: the build table is keyed on
EP+8, which is inside the `lea rax, [rip+disp32]` operand on an x64 stub, so
`build == NULL` and everything downstream is skipped. Measured on
`update_v103.exe`: the child is one 8 MB RWX blob.

### 3.2 Environment - what must exist before the first instruction

The emulator builds a Windows that is enough: a stack, a TEB with the segment
base set, module images for nine DLLs including a separate kernelbase (a Themida
loader patches kernelbase, and aliasing it to kernel32 put those writes on
kernel32's export directory), a process heap, and an argv.

A module declares none of it, and mostly should not. The one thing it does know
and cannot pass: **which libraries the stub is going to want**. MPRESS rebuilds
an import table from a hint list it has already parsed - that list names the
DLLs, and the run rediscovers them.

### 3.3 Skip - traps, anti-analysis, and work not worth doing

The emulator answers the usual checks itself: `IsDebuggerPresent`,
`NtQueryInformationProcess`, `GetTickCount`, `QueryPerformanceCounter`,
`QueryPerformanceFrequency`, `GetSystemTimeAsFileTime`, `Sleep`,
`RaiseException`, the vectored and unhandled exception handlers,
`VirtualAlloc`/`Protect`/`Query`. An import this build does not export reads as
a null page and the call is counted - `kof_emu_null_calls` - so "a high number
is a list to extend" rather than a silent wrong answer. Unhandled exceptions and
null-pointer field reads are counted the same way.

None of that is family-specific and all of it should stay where it is. What has
no home at all is the part that IS family-specific - **skip this**:

- "this range is an anti-VM loop, its result does not matter" - PECompact's
  stub deliberately faults at a null pointer and continues through its own
  handler; the run follows it correctly and pays for it;
- "this call always returns X in this build";
- "do not spend budget before address A" - which is the cheap form of a resume
  point, and the one that would have cut most of PECompact's 168.5 M
  instructions;
- "this region is `CIPHERTEXT` and running over it teaches nothing" - Themida,
  whose program sections stay at 8.00 bits for 267 M instructions.

Idle detection (`kof_emu_set_idle`) is the only generic form of this and it is
about spinning, not about relevance. The rest cannot be generic: what to skip in
a PECompact stub says nothing about a Themida one.

### 3.4 Stop - what counts as done

The emulator has the widest vocabulary of the six, and every bit of it is set
inside `emu_unpack.c`:

`kof_emu_set_oep_watch`, `kof_emu_watch_exec`, `kof_emu_watch_write`,
`kof_emu_set_image_range`, `kof_emu_set_stub_range`, `kof_emu_set_stack_range`,
`kof_emu_hop_add`, `kof_emu_set_max_insn`, `kof_emu_set_idle`,
`kof_emu_set_deadline` - and the stop reasons BUDGET, EXIT, HANDOFF, FAULT,
UNSUPPORTED, DECODE, STALLED.

**A module reaches exactly two of these, indirectly.** `kof_oep_range(rva, len)`
becomes a `watch_exec` plus a `watch_write` over that range
(`emu_unpack.c:2117`, `:2130`); `kof_child_want(KOF_ENG_USE_EMU, lvl)` decides
whether to run at all. Everything else - the image range, the stub range, the
idle limit, the deadline, what a hand-over looks like - is decided generically
from the PE parse.

PECompact is the case that shows the cost. The module knows the compressed
extent, the output size, the section the image lands in, and - from the
per-version tails, `ret` / `ret 4` / `jmp eax` with the stack balanced - what
the hand-over will look like. It can pass none of it. Measured on
`007 Spy.exe`: 168,558,592 instructions, 13.7 seconds.

The counter-measurement is what a narrow stop is worth: adding the balanced-stack
hand-over test took `telvm.exe` from 27.5 s to 1.8 s. That test is generic. The
tails it should be paired with are not - they are three byte patterns per
PECompact version range, and they mean nothing to any other builder.

### 3.5 Snapshot - when to say "this is the image"

The engine has a real answer here and it is worth keeping: a packer that means
to run what it unpacked has to make those bytes executable, so the automatic
snapshot is taken at the `mprotect` that grants EXEC over memory the run itself
wrote. That instant is the payload's complete form, and the end of the run is
not - measured on a UPX-packed PyInstaller binary, the unpacked bootloader ran,
opened a file and mapped a second image over its own text, so the final memory
held the packed header again.

`kof_emu_snap_written` takes one on demand, and `emu_unpack.c:1477` calls it
before every budget extension - because a PECompact2 sample decompressed 6.5 MB,
was granted more budget, faulted in the extra slice, and the 6.5 MB went with
it.

`kof_emu_next_snapshot` and `kof_emu_next_written` harvest both sets.

What a module cannot say: **"snap here"**. Not at an mprotect, but at a point it
recognises - the instruction after the decompressor's loop, the moment the
import table is complete, the address the header told it the image would be
assembled at. Nor can it say which of several snapshots is the image and which
are scratch: that is the same "which object is final" question from section 6,
one level down.

### 3.6 Hand back - what comes out and who takes over

Static: `kof_child()` closes a byte stream and the object is done with. A module
cannot hand back a partial result and stay open.

Run: `emu_label` names each child `emu:image@0x400000`, `emu:exec@0x20002000`
and that is the whole description - no regions, no format, no origin, no entry,
no statement of which is the image. It is a duplicate of memory offered as a new
object, which is the pattern section 5 opens by ruling out: the run knows which
region of which object it filled and should say that instead.

Neither can say "I got this far, the rest is now readable statically" - which is
the step loop, and the only reason the six questions above matter one at a time
instead of once per object.

### 3.7 Where the answers live: `bases/emu/`, one module per family

The wrong fix is a hint ABI - a way for `bases/unp/pecompact_pe.c` to pass
parameters into a generic runner. Every family's peculiarity then becomes a
parameter that has to mean something for every other family, and the runner
grows a switch it can never close. PECompact's hand-over is three byte patterns
per version range; Themida's difficulty is that its sections stay ciphertext for
267 M instructions; MPRESS's is a build table keyed on a dword that moves between
x86 and x64. Those do not generalise into one parameter set. They generalise into
**one interface with one implementation each**.

So emulation policy becomes a module kind of its own, beside the five that exist:

```
bases/decomp/   containers
bases/unp/      static unpackers          <- one per family
bases/emu/      emulation policy          <- one per family, NEW
bases/heur/     heuristics
bases/signatures/
bases/plague/
```

This is the shape XVolkolak uses and it is worth copying deliberately:
`dep/XEmulUnpacker/packers/` has forty files, one per packer, and
`xemulunpacker_pecompact.cpp` overrides exactly two things - the step budget and
`matchOEP` - and inherits everything else.

**What stays in the emulator, and is right where it is.** The anti-analysis
work belongs to the machine, not to a family: `IsDebuggerPresent`,
`NtQueryInformationProcess`, `GetTickCount`, `QueryPerformanceCounter`,
`QueryPerformanceFrequency`, `GetSystemTimeAsFileTime`, `Sleep`,
`RaiseException`, the vectored and unhandled exception handlers, the x64 table
SEH dispatch, the null page an unexported import reads as and the counter that
says how often that happened. Every guest asks those questions and they all get
the same answer, so a per-family copy would be a per-family bug. They stay in
`libkofemu`.

**What comes out of it** is the part that is one builder's and is sitting in the
generic runner today: which jump counts as the hand-over, where the stage-two
entry is, what the image range is for THIS packer. PECompact's `ret` /
`ret 4` / `jmp eax` with a balanced stack is a `matchOEP`, not an engine rule.

**What stays in the engine**, because it is true of every object:

- the machine itself (`libkofemu`);
- the Windows environment - stack, TEB, the nine module images, heap, argv;
- every budget and its enforcement, per `QUALITY_AUDIT.txt` I.A;
- the snapshot rule at `mprotect`+EXEC, which is generic and measured right;
- the anti-analysis answers that every builder uses the same way -
  `IsDebuggerPresent`, `GetTickCount`, `QueryPerformanceCounter`, the exception
  handlers;
- **the fallback policy** for an object no `bases/emu/` module claims: today's
  DENSE / BROKEN / LOADER / APPENDED gates and the generic OEP watch. That path
  is "nobody recognised this, run it and see", and it should keep being exactly
  that rather than being deleted in favour of per-family modules.

**What moves to `bases/emu/<family>.c`**, because it is true of one builder:

- start: an entry override, or the second-stage entry the static module found;
- environment: the libraries this stub will ask for, values worth pre-seeding;
- **skip**: ranges to fast-forward over, calls to answer with a constant, the
  specific anti-VM this builder ships;
- stop: the per-version hand-over tails, the image range, the stub range;
- **dump**: where THIS family's payload is complete and what to take - which is
  not always an `mprotect`, and is not always all of written memory;
- **navigation**: run on, jump forward past a stretch, go back to a checkpoint
  and take it differently, re-run with a different answer;
- verdict: what the result is - an image, a payload, or nothing worth keeping.

### 3.8 The emu module is a DRIVER, not a table of constants

The three in bold are what make this a module rather than a settings struct.
Dumping, skipping and moving the run backwards and forwards are decisions taken
DURING a run, at each stop, with what has happened so far in hand - and what is
worth doing differs per family, not per object.

So the shape is: the engine runs until it stops, hands the stop to the family's
module, and the module says what happens next.

```
  kof_emu_run(e) -> stop reason
      bases/emu/<family>.c is asked, and answers one of:
          carry on
          jump to <address>, with these registers          (skip)
          go back to checkpoint <k> and continue there      (rewind)
          dump <these ranges> - this is the payload
          done / give up, and why
```

What exists for that today, and what does not:

| | today |
|---|---|
| run until it stops | `kof_emu_run(e)` returns a stop reason with the machine intact, already called in a loop (`emu_unpack.c:546`, `:1463`) |
| **forward**: jump past a stretch | `kof_emu_set_rip`, `kof_emu_set_reg`, `kof_emu_write` - everything needed, and nothing outside the engine may use it |
| **backward**: go back and take it differently | **nothing.** `kof_emu_snap_written` copies written memory OUT into a harvest set; there is no way to put it back. No checkpoint, no restore |
| dump | `kof_emu_next_snapshot` / `kof_emu_next_written`, harvested by the engine on its own terms at the end |

The backward move is the one real primitive this design adds to the machine: a
checkpoint that can be RESTORED - machine state and the memory that has changed
since - so a driver can try a path, see it go nowhere, and take the other one.
Anti-VM is the obvious use (run the check, watch it fail, go back and answer it
the other way) and the PECompact fault-and-continue stub is the other.

Everything else is already in `libkofemu` and is simply not reachable from
outside the engine, which is the same finding as section 3.4.

**And then the static module stops asking for the emulator.** Today
`themida_pe.c` calls `kof_child_want(KOF_ENG_USE_EMU, 2)` and `mpress_pe.c`
consults `kof_emu_unp_gate_pe`. That coupling exists only because there is
nowhere else for emulation policy to live: the static module is the one thing
that recognised the family, so it has to be the thing that asks for a run.

With `bases/emu/<family>.c` the emu module recognises the family ITSELF, the way
a static unpacker does, and the engine routes to it. Static and emulated become
two independent modules for one family, and either can exist without the other:

- PECompact is today a static module that can only answer "unsupported", plus a
  generic run that costs 168.5 M instructions. It becomes `bases/emu/pecompact.c`
  and needs no static partner at all;
- Themida keeps both, and neither has to name the other;
- MPRESS keeps its static module and loses the gate call.

**If a "want" survives, it is not "use the emulator".** The general form is
"this object needs engine E" - an interpreter for this architecture, a different
machine, a different execution backend. That is a routing statement about the
OBJECT, true across families, and it is the only shape worth keeping in a static
module's vocabulary. "Run the emulator on my child" is not that; it is a module
reaching for a specific tool because the tool had no way to speak for itself.

**Pairing with `bases/unp/`.** Same family, two methods, and they pass each
other what they found - the build version, the compressed extent, where the
image will land, how far the run got - through the object description from
section 5. Not a private channel between two modules, and not a dependency
either way.

**Cost.** Four families would have one today: mpress, pecompact, themida,
vmprotect. Everything else uses the fallback, which is what it uses now.

---

## 4. What the modules actually demand

Counted from the sources. The right-hand column is what the module cannot say
today, which is why it does what it does.

### MPRESS - `bases/unp/mpress_pe.c`

`kof_unp_poke` x13, `kof_unp_read` x11, `kof_unpack_form` x3, `kof_child` x2,
`kof_oep_range` x2, `kof_emu_unp_gate_pe` x1.

Thirteen pokes is the whole argument. The module writes a header, then patches
it back thirteen times as facts arrive: the real entry point (readable only
after the content exists), `SizeOfImage`, `NumberOfSections`, the whole section
table rewritten by `mp_split`, and an appended `.kofimp`.

| demands | today |
|---|---|
| declare a region AFTER its content exists | writes a header, reads its own output back, pokes the header |
| re-draw the region layout once landmarks are known (`mp_split`) | rewrites 40 bytes per section through `kof_unp_poke` |
| declare an entry point late | pokes offset 0xa8 - and got 0x98 wrong once, which overwrote the optional header's Magic and made every child read `magic=0xfb2b` |
| declare an INVENTED import directory | appends `.kofimp` and points a data directory at it; nothing records that it was invented |
| say "this build is unknown" without losing everything else | `build == NULL` also disables `mp_split`, so `update_v103.exe`'s child is one 8 MB RWX blob: CODE 8187904, DATA 388 |

### VMProtect - `bases/unp/vmprotect_pe.c`

`kof_unpack_form` per block, `kof_unp_read` x1, `kof_unp_poke` x1.

| demands | today |
|---|---|
| write content **at an address**, not at a stream position | blocks land at 0x1000, 0x1a000, 0x1d000, 0x1e000 - mid-section, not at section starts - so the emit loop had to be rewritten address-driven |
| ask whether a destination is still empty | tests sixteen bytes itself; that test doubles as its recursion guard |
| know a region is hollow | the outer unpacker's header erased it, so the module anchors on an `{RVA, 5}` pair in the data instead |
| correct a region's permission after filling it | pokes the characteristics: 102400 bytes of real code (`55 8b ec`, entropy 5.70) were filed under DATA because `mp_split` drew that region while it was still zeros |
| say "the rest is virtualised, not mine" | `KOF_UNP_ENCRYPTED` on the parent - which marked the FINISHED parent "not finished" until it was removed |

### PECompact 2 - `bases/unp/pecompact_pe.c`

`kof_pe` x1, `kof_debug` x2. **Produces nothing on purpose** - the codec is a
builder-chosen plugin and is none of the ones this engine has.

The sharpest demand in the tree, and it is about the handoff:

| demands | today |
|---|---|
| say "I recognise this and cannot decode this coding" | `KOF_UNP_UNSUPPORTED`, which works |
| hand the interpreter what it already worked out | **nothing**. The module has read the header: the compressed extent, the expected output size, the section the image is rebuilt into. None of it reaches the emulator |
| say what the hand-over will look like | XEmulUnpacker's table is known - `ret` (1.00-1.10), `ret 4` (1.50-1.76), `jmp eax` (2.40), `ret` from a heap buffer (0.90), all with the stack balanced. A module cannot declare it |
| take over again once the image is written | no mechanism; the run finishes and the static module is never re-offered |

Cost of not having it, measured on `007 Spy.exe`: 168,558,592 instructions,
13.7 seconds, the whole ceiling - to rediscover what the module read out of the
header in microseconds.

### Themida - `bases/unp/themida_pe.c`

`kof_child_want(KOF_ENG_USE_EMU)` x2, `kof_oep_range` x1, `kof_unpack_form` x1.

The only module that already does static-then-interpreter, with the two
declarations that exist. It shows the shape is right and the vocabulary is too
small: it can say "run this" and "the entry will be in this range", and nothing
else. Its program sections measure 8.00 bits per byte and the loader never
writes into them across 267 M instructions - so what it most needs to declare is
"these regions are still ciphertext", which has no spelling.

### XOR string table - `bases/unp/strxor_tab_00.c`

`kof_emit` x2, `kof_child` x1. A pure editor: 7799 bytes changed in 5353472.

| demands | today |
|---|---|
| "the parent, with these ranges replaced" | re-emits all 5.3 MB, sorts its own edits, resolves its own overlaps - both got wrong once (114353 bytes dropped; an over-long record swallowed its neighbour) |
| name what it recovered | 259 records, including the C2 and six SQL queries, and nothing downstream can scope to them |
| not be offered its own output | invents a guard; the first was wrong because six records have ciphertext that is printable by chance |

### Hollow PE - `bases/unp/hollow_pe.c`

Recognises and produces nothing. Its whole job is a verdict about a SHAPE, and it
has to be a module because there is nowhere else to say it - itself an argument
for the description carrying "this object is an image this build cannot rebuild".

---

## 5. The mechanisms that follow

Every line exists because of a row above it.

**Before any of them: a change NAMES THE REGION IT CHANGES, on the object it
changes.** Producing a new object is not the mechanism for "the same program,
further along" - it is the mechanism for a genuinely different file.

That is the rule the tree breaks everywhere today. `111.exe` yields four objects
of 5353472 bytes: the same program four times, because MPRESS, VMProtect and
StrXor each had to duplicate it in order to say anything about it. The emulator
is the worst case - it hands back whole memory ranges as anonymous blobs,
`emu:image@0x400000` and `emu:exec@0x20002000`, and the engine re-parses each
from scratch to rediscover a structure the run already knew. PECompact would be
the same again: run, copy out memory, re-parse, and hope the regions come back.

So:

- **a new object** is for a container member, a carved appendix, a payload that
  is its own program - something that was not this object;
- **a region edit** is for everything else: "this region of THAT object now holds
  this content", "this region's permissions are these", "this region is now
  PLAIN and was CIPHERTEXT".

The second has to be the default, or every layer costs a copy of the program and
a re-parse, and the description is rebuilt by inference at each step instead of
being carried forward.

**Declare a child object.** Its stage, its producer, its parent. Consequence:
the engine knows an object is a module's own product and never offers it back -
the three hand-written recursion guards go.

**Declare a region.** Name, address, extent, permissions, kind - code, data,
padding, headers, resource, symbols - and **origin**:

- `READ` - parsed from the file as written;
- `REBUILT` - recovered from evidence the module found;
- `SYNTHETIC` - stood up because the region must exist and the evidence to
  recover it does not.

`SYNTHETIC` is MPRESS's `.kofimp`, and a page of zeros standing in for content
nobody could recover. They are legitimate; what is not is being unable to tell
them from what was observed. `padding` as a kind ends the 3972 NULL bytes in
DATA; `hollow` as an attribute ends VMProtect's anchoring on `{RVA, 5}`;
writable permissions end the 102400 bytes of code called DATA.

Per `QUALITY_AUDIT.txt` I.B: every byte in exactly one region, and UNCLAIMED is
the honest answer for the rest. That invariant has to hold after every step, not
only after a parse - which is a thing to test, not to assume.

**Change a region after the fact.** Permissions, extent, kind, origin, state.
That is thirteen pokes and a section-table rewrite, said once.

**Declare a region's STATE.** `CIPHERTEXT`, `COMPRESSED`, `PLAIN`,
`VIRTUALISED`. Themida needs the first, VMProtect the last, and a step loop
needs all of them to know whether anything is left to do.

**Write content by address.** The engine places it; no module sorts anything or
resolves its own overlaps.

**Derive.** "The parent, with these ranges replaced", held as that rather than
copied.

**Declare data inside a region.** Symbols, entries, and named findings with an
extent: "the decrypted strings are here", "the import table is here", "the C2 is
here".

**Declare a step's outcome.** Consumed, produced, resume point, blocked-on,
finished-or-partial. Section 2.

**Declare the final object.** Section 6.

---

## 6. Static and interpreter, one description

The two halves are lopsided today.

**Static -> interpreter.** A module can say `kof_child_want(KOF_ENG_USE_EMU,
lvl)` and `kof_oep_range(rva, len)`. That is the entire vocabulary - and per
section 3.7 most of what it is used for should not be a message between modules
at all, but a `bases/emu/` module of its own. What is left that genuinely IS a
handoff, because one module found it and the other needs it:

- the compressed extent and the expected output size (PECompact reads both);
- which region the image will be rebuilt into, so a write there is the signal to
  stop rather than something to discover;
- what the hand-over instruction looks like and that the stack will be balanced
  at it - the `nSpDelta` rule is in `libkofemu/kofemu.c` but is the emulator's
  own, not something a module can narrow;
- a deadline earned from the above instead of a global ceiling.

**Interpreter -> description.** Worse. `emu_label` in `objctx.c` gives an
emulator child a NAME - `emu:image@0x400000`, `emu:exec@0x20002000` - and nothing
else. No regions, no format, no origin, no entry point, no statement of which of
several children is the image and which are scratch pages. A reader gets a row of
blobs distinguished by an address in a label.

The interpreter is a producer like any other and has MORE to declare, not less:
it knows which pages were written, which became executable, where control was
handed over, and which image it assembled. All of that is `REBUILT` origin with
an evidence note. A run should fill the same description a static module fills,
so the two differ in provenance and in nothing else - which is also what makes
section 2's loop possible, because a step cannot hand over to the next kind of
step if the two speak different languages.

---

## 7. Which object is final

**Half of this now exists: a module can say an object is only a wrapper.**
`kunp_rcstruct_supersedes()` says "the child I just produced is what I WAS",
and the walk then scans that object exactly as before - every rule runs on it -
but does not REPORT it as a thing recovered. Never at the top level: the file
the caller handed over comes out whatever any module says, and the engine checks
that rather than trusting each module to.

Measured on `samples/msfvenom-encr/rc4_1`, wrapped three deep: **three reported
objects became one**. The two that went were a forty-six byte decryptor in front
of ciphertext.

What is still missing is the other half - the REASON. A wrapper knows it is a
wrapper; a packer's child knows it is final for the packing layer and not for
the virtualised one, and that is the declaration the rest of this section is
about.

Nothing says it today. `111.exe` yields four objects and the one that matters is
the third - MPRESS's image, with VMProtect's blocks decrypted, with the string
table read. A reader sees four rows of 5353472 bytes; a rule writer has no way to
say "the finished one".

The producing module is the only thing that knows, and it knows it per layer:
MPRESS's child is not final if a packer still matches it; VMProtect's child is
final for the packing layer and not for the virtualised one; StrXor's child is
final. So it is a declaration with a reason - and "not final, because this region
is still `VIRTUALISED`" is the same statement section 4 already needs.

The matcher stage then has a target: the final object by default, every object
when asked, and stage-specific matchers at the stage they belong to.

---

## 8. What this has to satisfy

From `QUALITY_AUDIT.txt`. These are not general good manners; each one bites
this design somewhere specific.

**I.A - core engine.** Every budget enforced by the host, never by the module;
exhaustion reported, never silent truncation. The step loop is where a runaway
lives, so the loop owns: steps per object, total produced bytes, resident bytes,
and wall clock. A step that declares itself blocked and is scheduled again
forever is the new failure mode and needs its own cap.

**I.A - immutability.** Nothing the scan path writes lives in the engine; all
mutable per-scan state belongs to the scanner, per thread. The description is
per-object scanner state and must not become a global.

**I.B - parser.** Every byte in exactly one region; UNCLAIMED is the honest
answer for the rest. This has to survive every step, not just the parse - so it
is an invariant to check after each one, and a test that would fail if the check
were deleted.

**I.C - unpacker/decompressor.** Output bounded by a ratio cap, never by the
declared size alone; block count capped; each step must consume input or produce
output. In a step loop that last one becomes the termination argument: a step
that consumes nothing and produces nothing is not a step, and saying so is what
stops the loop.

**I.C - differential validation.** Validated against an independent reference on
real samples. Three of the decoders here were: MPRESS against Avast's own
unpacked output (1263 of 1265 pages byte-identical), VMProtect against VMPStatic
(all 8 sections byte-identical on `explorer.exe`), StrXor against a Python port
of its own call-site reader. Whatever replaces them has to keep those comparisons
runnable.

**III - performance.** Every filter has a measured earn-versus-cost and results
identical with it on and off. The step loop's re-offer is a filter by that
definition: the numbers to beat are PECompact's 168.5 M instructions / 13.7 s,
and `telvm.exe`'s 27.5 s -> 1.8 s from the hand-over test.

**IV - hygiene.** Every declared bit raised somewhere; no comment describing in
the present tense a mechanism that is not wired. A description with region
kinds, origins and states that nothing ever sets is exactly the failure this
line is about - so each new value lands with the module that sets it and the
consumer that reads it, or it does not land.

---

## 9. Gaps found on review

Four things the sections above assume and do not state.

### 9.1 A derived object is not offered to the module that derived it - and a NEW object still is

"Never hand a module its own product" is too strong and would break the nested
case: a zip inside a zip must be opened by the zip module again, and MPRESS's
rebuilt image is a different program that a second MPRESS layer should be
unpacked from.

The rule is narrower and it is what makes the three guards removable:

- a **derived** object - the parent with ranges replaced - is never offered back
  to the module that derived it;
- a **new** object - a container member, a rebuilt image, a carved appendix - is
  offered to everyone, including its producer.

So self-recognition is not a separate feature. It is a property of derivation,
which is why they are one step in section 10.

### 9.2 Two modules editing the same region

The step loop invites it: module A rewrites a region, module B had already
declared an edit over part of it. Today this cannot happen because a module
produces a whole object and the last one wins silently.

The rule has to be stated rather than discovered: an edit that overlaps a region
another module has already changed in this step round is REFUSED, and the
refusal is reported - the same treatment a budget gets. Silently taking one is
how `strxor_tab_00.c` lost 114353 bytes when it was resolving overlaps itself.

### 9.3 What a region edit invalidates

A matcher that ran over a region before an edit has a result about bytes that no
longer exist. Either matchers run only at the stage boundaries the pipeline
declares - which is the cheap answer and probably right - or every edit carries
an invalidation, which is a cache to get wrong.

Stated choice: **matchers run at stage boundaries, not inside the step loop.**
`zipslip` runs when UNWRAP is finished, not while it is running. The step loop is
for building the description; matching is what happens once a stage says it is
done.

### 9.4 What the tools show for a sequence of steps

This is the complaint that started the work. Today `111.exe` shows four rows of
5353472 bytes because four modules each produced a whole object. With edits,
there is one object with a HISTORY: MPRESS rebuilt it, VMProtect filled four
regions, StrXor changed 259 ranges.

The tree should show the object, and the history should be readable on it -
which step did what, and to which region. Four identical rows is the symptom;
one row with four steps under it is what the description already knows.

---

## 10. Order of work

1. **Derive + self-recognition.** Cheapest; deletes three guards and two classes
   of bug. `strxor_tab_00.c` first - the only pure editor.
2. **Regions with kind, origin, state and late change.** Settles MPRESS's
   thirteen pokes, VMProtect's permission fix, the padding, the hollowness.
   Retires `pe_reassemble.h` - three modules include it.
3. **Final object.** Gives the matcher stage a target.
4. **The step loop.** Static and interpreter alternating on one description.
   PECompact is the measurement to beat.
5. ~~**Interpreter declares regions and origin.**~~ **DONE, AND INVERTED.** The
   interpreter declares nothing. It gathers what a run wrote and reports it -
   `kunp_emu_region` to look, `kunp_emu_take` to copy - and the *module* is what
   declares regions, layout and origin, because a component that executes
   hostile bytes must not also be able to create objects. The receiver for a
   file no family module claimed is `bases/unp/emu_generic_00.c`, which folds an
   assembled image and the surplus pages around it into ONE object rather than a
   row of anonymous `emu:exec@...` blobs.

   What this moved, and where it had to go: a run is asked for through
   `kunp_emu_run(vouched)`, and every ceiling is the host's - one run at a time,
   the packer depth, `KOF_SCAN_EMU_MAX`, `--emu never`. A *family* module vouches
   because it recognised its packer. The generic receiver cannot, so what speaks
   for its object is the DATABASE: a heuristic rule that declared
   `KOF_ENG_USE_EMU`, or the producer that made the object. Both are host
   knowledge, both are unreachable from a module, so both are resolved once in
   `unpack_object` (`sc->emu_ask`) and or-ed into the module's vouch inside
   `c_emu_run`. Dropping that ask is what silently ended shellcode unpacking:
   the entropy gate refuses a meterpreter payload for being smaller than its
   estimate needs, which is exactly the object the rule fires on.

   A rule's ask does not read `emu_use`, and that is deliberate - the option
   word cannot tell an explicit `--emu never` apart from the zero a default
   leaves behind, and `kofexaminer` sets it nowhere at all. `emu_forbidden` is
   the refusal somebody actually wrote.

   And the module loop's `if (sc->broken) break` had to narrow to
   `KOF_BROKEN_LIMIT`, for the reason the interpreter's own gate narrowed
   earlier: PECompact reporting `UNSUPPORTED` on `007 Spy.exe` is true and is
   not a reason to stop the module whose whole job is the object nothing static
   could open.

### The ELF a decoder's output becomes

`msf_elf32.h` assembled a fifty-two byte ELF header and a thirty-two byte
program header field by field and handed them over with
`kunp_rcstruct_write`, as ordinary content. That is exactly the round trip
`section` exists to end, and it failed the way that argument predicts: nothing
in the engine knew those bytes were a header, so the child's first fifty-two
bytes were content like the rest, and the layout the module knew exactly had to
be recovered by parsing back what the module had just written.

Two things were missing, and both are now there:

- `kof_elf_write_hdr` in `extractors/unpack/elf_rebuild.c`, the ELF twin of
  `kof_pe_write_hdr`: one PT_LOAD over the whole file, permissions the OR of the
  declared sections', refused rather than truncated when the header will not fit
  in front of the first section.
- `kunp_rcstruct_as(fmt, arch, base)`. A packer's child is the parent's own
  image and the parent's header is the template, which needs no asking. A
  DECODER's child is shellcode, which is no format at all until somebody says
  which one it should become - and after the first layer the parent is
  FORMATLESS, so only the module can say.

Measured on `x86_opt_sub`: the child is `ELF32 ET_EXEC machine=3`, entry
`0x8048054`, one `PT_LOAD RWX` - the same file as before, and now it partitions
as `HEADERS=84 CODE=124` instead of 208 bytes of undifferentiated content.

**The same declaration, for what a run leaves and no static reader can name.**
`emu_harvest.h`'s no-image branch asks for a header too, and the address tells
it which of two things it has. A page that starts where the parent is LOADED is
the program's own image with a header the run damaged - `poly` overwrites the
first sixteen bytes of its own `e_ident` - so the content is written from offset
0 and the engine's header lands on top of the broken one. A page anywhere else
is payload with no header at all, and the header goes in front of it with the
load address chosen so the payload still sits where it ran. Measured: `poly`,
`x86_alpha_mixed`, `x86_bloxor`, `x86_single_static_bit`, `x86_poly`,
`x64_zutto_dekiru` all went from "unrecognised, 4096 bytes" to a parsed ELF with
`HEADERS` and `CODE`.

`msf_pe.h` still writes its own PE header. It is the same change and it needs
one more thing: `kof_pe_write_hdr` takes the parent's `kof_pe_info` as a
template, and a formatless intermediate layer has none.

The eleven modules that call `kof_emit` for a flat payload (`ezuri`, the msf
decoders, `upx_elf_*`, `scpayload`) describe nothing and keep the old call. Old
and new coexist: `kof_emit` + `kof_child` stays exactly as it is, and a module
that declares nothing gets the behaviour it has now.

### What proves each step

`QUALITY_AUDIT.txt` V asks of every passing test: would it fail if the feature
were deleted? These are chosen so the answer is yes.

| step | passes when |
|---|---|
| 1. derive | `strxor_tab_00.c` keeps decoding 259 records on `111.exe` with its blanked-key guard DELETED, and produces one child, not eleven |
| 1. derive | `vmprotect_pe.c` keeps its 8/8 byte-identical sections on `explorer.exe` with its destination-must-be-empty guard DELETED |
| 2. regions | `update_v103.exe`'s child has no DATA region of pure padding, and `111.exe`'s decrypted child reports the recovered 102400 bytes as CODE without any module poking a header |
| 2. regions | MPRESS still matches Avast's own unpacked `111.exe` at 1263 of 1265 pages |
| 3. final | `111.exe` names exactly one object final, and says why the others are not |
| 4. step loop | `007 Spy.exe` costs materially less than 168,558,592 instructions and still yields the same image; `telvm.exe` stays at 1.8 s |
| 4. family driver | `pecompact_pe.c` vouches for its own run and folds it: `007 Spy.exe` yields one 8,663,040-byte object under `--heur 2` and costs 0.004 s under `--heur 1`, where it used to be `Unsupported by this build` at both levels |
| 5. emu declares | `007 Spy.exe` under `--heur 2` yields ONE child with declared sections, not a row of `emu:exec@...`; `shikata_ga_nai`, `poly` and `win_x64_xor_dynamic` still yield one each with the interpreter's producer role deleted |

The six-sample set stays the regression gate throughout: `111.exe`,
`explorer.exe`, `update_v103.exe`, `1003b.exe`, `vdr.exe`, `telvm.exe` - object
counts 4 / 1 / 2 / 2 / 2 / 2 today.

---

### What the PECompact driver settled, and what it did not

**A family module driving its own run is the first half of §3.7 and it works.**
`pecompact_pe.c` recognises the packer, knows statically that the codec is a
plugin this build lacks, and is therefore the one thing in the engine that can
say with certainty rather than by estimate that running it is the only way in.
So it vouches - `kunp_emu_run(2)` - and folds the result through
`emu_harvest.h`, the same procedure `emu_generic_00.c` uses. The harvest is a
shared header and not engine code on purpose: deciding that a written page IS an
image, and that an image plus four heap pages is ONE program, is a judgement
about meaning, which is exactly what the component that executes hostile bytes
must not be allowed to make.

**A vouch carries a --heur level, not a flag.** A vouch skips the entropy gate,
and the gate is the only thing between a directory of one family's samples and
minutes of interpretation. PECompact costs 168,558,592 instructions and 17.3
seconds per file. Measured: `--heur 1` 0.004 s and no run, `--heur 2` 17.4 s and
one 8.6 MB object. The module knows what its family costs; it does not know what
the caller asked for, and comparing the two is the host's job.

**A handover range is a FETCH, not a hop, and PECompact has none.** An attempt to
give the module a way to declare where its program will land - an `emu_watch`
for the object in hand rather than for the next child - was written, measured and
removed. Both ways of naming a range are wrong for this packer:

| named | result |
|---|---|
| the entry section, the one that grows and is decompressed into | the entry point is IN it, so the run ends at instruction 0 |
| every other section, guessing the stub lives where the run starts | it does not - PECompact leaves a jump at the entry and puts its loader in `.rsrc`; the run ends 6 instructions in, 4 written pages, nothing decompressed |

Loader and program share a section here and no address separates them. The
mechanism was deleted rather than kept unused: what it would serve is a packer
whose program sits where the loader never executes, which is MPRESS and Oreans,
and both of those already say it about their CHILD through `kunp_emu_oep_range`.

**Three defects the first working version had, all found by looking at the
child rather than at the count.**

| what | why it happened | evidence |
|---|---|---|
| every surplus section had `SizeOfRawData` 0 and the child carried `SEC_PAST_EOF` | `layout_of_produced` cuts the child back to where the image's own header says it ends, and the surplus had been written PAST that point first | five sections, 53,248 bytes, gone |
| writing behind the image was refused outright once the order was fixed | a fixed sink was bounded by `sink_len`, which the cut had just lowered - but the extent is `sink_cap`, which is what the module declared and paid for | the child came back with the image alone |
| two sections named `.e020000`, same address, same size | one guest range made executable twice; the gathering drops the pair only when the BYTES match too, and these differ - the same page before and after a decode | nothing could tell them apart |

So `layout_of_produced` now answers WHERE the image ends instead of a flag, a
fixed sink is bounded by what was allocated rather than by what currently counts
as the child, and a surplus section is named by page AND by a sequence letter.

**And one that the counts hid completely, found by looking at a child's bytes.**

`kof_emu_next_written` hands back a buffer the emulator owns and **replaces on
the next call** - it says so, beside itself. That was safe while the interpreter
emitted each run as it walked them. It is not safe now that the regions are
GATHERED first and handed to a module afterwards: every pointer but the last is
freed before the module ever sees it, and the allocator hands the memory to
whatever asks next.

Measured on msfvenom's `poly`: the region the module was handed read
`7f 45 4c 46` when it was gathered and `2e 74 65 78` - the scanner's own
`.text` section name - by the time the module copied it. The child came out as a
correct ELF header in front of 4012 zero bytes, and every count in the scan said
it had worked.

So a gathered region is COPIED unless its bytes outlive the module. A snapshot
lives in the machine and the machine outlives the call, so that one is still
borrowed; a written run is copied, and `emu_rgn[i].own` is what frees it. This
is the price of the gather-then-hand-over split and it is worth naming: the
moment a producer stops emitting as it walks, every pointer it keeps has to have
its lifetime stated.

**And one the sanitizer found, which no count would have.** The machine a run
leaves behind was never freed: `kof_scan_emu_release` existed and nothing called
it. 1,207,552 bytes in 263 allocations per run, under `make unit-asan`. The fix
is where the note on `emu_live` already said it belonged - the machine is
released the moment the module that drove it returns, because its regions point
into that machine's memory and are not valid past that. Which then needs
`emu_ran`: with the machine released, `emu_live` is clear again when the next
module is offered the same object, and without a per-object flag every module
that declined it in turn would pay for a run of its own.

**And one that was not about pecompact at all.** The child is one 8.6 MB RWX
section, so every byte of it is `KOF_SCAN_PE_CODE`, and CODE is kept out of the
normaliser - which meant 7,446 runs of UTF-16LE text were never narrowed in any
view. `norm_keep_exec` had solved the same problem for ELF by keeping only
`SHF_EXECINSTR` sections; the PE half of it is `norm_keep_exec_pe`, and it turns
on the WRITE bit: a section that is both writable and executable is a program
that rewrites itself, which is every unpacked image, and there the instruction
stream is the whole program. Measured: 7,446 wide runs down to 607, `login` from
0 narrow occurrences to 78. Nothing is lost because unwide is 1:1 and because a
view can only add a match - the object itself is scanned whole and first.

**What is still open for this family, and now it is known what is missing.**
The 17.3 seconds is the whole instruction ceiling - the run never stops on its
own. Three ways of declaring where it should were written and measured on
007 Spy.exe, all wrong (the table is in `pecompact_pe.c`), and the third one is
the informative failure: the public OllyDbg scripts break on the stub's last ten
bytes, `8B C6 5A 5E 5F 59 5B 5D FF E0`, which match this file exactly once - and
a watch declared at that address is never reached, because **the loader copies
itself to 0x20000000 and finishes there**.

So the handover's address is not a fact about the file, and no range mechanism
can express it. What would find it is a SEARCH OF GUEST MEMORY at the moment a
range becomes executable - which is what those scripts do from the outside, and
what this engine has no mechanism for. That is the next thing to write for this
family, and it is more general than PECompact: any loader that relocates itself
defeats every static declaration in the same way.

One thing did come out of the attempt. `kof_emu_watch_exec` now ends a run when
execution CROSSES INTO a range rather than when it is inside one. For a range
the loader never runs in - MPRESS, Oreans, every case the mechanism was written
for - the two readings are identical. They part company exactly where PECompact
is, and the old reading ended the run at instruction 0 when a module named the
section its own entry point was in, which is a trap the mechanism no longer
has.

---

## 11. Open

- Does a derived object of a derived object collapse to one edit list or chain?
  Chaining keeps provenance per layer and costs a lookup per read.
- `padding` as a region kind changes what UNCLAIMED means. Check against the
  measurements in `libkofeng/analyzers/normalize/executables.h` first.
- Should `SYNTHETIC` carry a reason? "No hint list survived" and "the format
  requires a header" are different inventions.
- Where do sniff and parse sit in `enum kof_analyze`? They are stages by the
  definition in section 1 - they fill the description - but no module declares
  them today; the engine does it inline.
- A restorable checkpoint is memory the engine has to hold. How many, how
  large, and charged against which budget - `QUALITY_AUDIT.txt` I.A says the
  host enforces it, and a driver that checkpoints every stop is the new way to
  exhaust a machine.
- What stops a step loop that makes progress by a byte a turn? A minimum
  progress rule, or a step budget, or both - and whichever it is has to be
  stated where I.C's "must consume or produce" is stated.
