# Third-party code in kofeng

The project's own terms are MIT; see [LICENSE](LICENSE), which also carries the
summary of everything below. This file is the detail.

## Previously used: bddisasm 3.0.1 — Apache License 2.0

Nothing of it remains in the repository. Earlier versions vendored it under
`libgenome/genotype/bddisasm/` as the x86 and x86-64 decoder beneath the emulator, with one
patched file (a 16-bit addressing displacement guard, marked `KOFENG PATCH`). The
tree was removed when `libgenome/genotype/x86/` replaced it.

Copyright (c) Bitdefender. Licensed under the Apache License, Version 2.0; the
licence text is kept at `LICENSES/Apache-2.0.txt`.

**The replacement is a complete rewrite**: table format, runtime decoder, lazy
operand builder and text formatter are this project's own, and no bddisasm source
file is in the tree. What is NOT code but did come from it:

- `x86_tab.c` and `x86_ids.h` (one table set for both 32- and 64-bit mode) are written by `tools/genotype/x86_gen.c`, which
  decodes enumerated encodings with bddisasm and records the answers - opcode
  structure, operand shapes, instruction identities, and the id numbering.
- The text formatter's conventions (prefix order, column, size keywords) were
  learned from bddisasm's output and implemented independently.
- `tools/genotype/x86_diff.c` compares the two decoders on random encodings.

[Unverified] Whether data of that kind is subject to Apache 2.0 is a legal
question this project has not had answered. The conservative reading is
followed: the attribution is kept, and so is the licence text.

The patch that was carried is now a rule in the generator's data and is pinned by
`tests/unit/insn_addr16.c`, which stays as the regression test.

Re-running the generator or the comparison needs a bddisasm checkout, which is
not shipped: `make genotype-x86 REF=<dir>`, `make genotype-x86-diff REF=<dir>`.

## Previously consulted: iced — MIT, and yaxpeax-x86 — 0BSD

`github.com/icedland/iced` and `github.com/iximeow/yaxpeax-x86`. Read for how a
fast decoder is organised: indexing by opcode map and prefix, operand building
kept apart from length decoding, validity carried by the table. Nothing is
copied from either - no code, table or text - and neither is a dependency of the
build or of the binaries.

## Read, not taken

Nothing below is in this repository. These are projects whose source was read
to understand a format or a technique, and from which no code is reproduced.
They are listed because the debt is real even when the licence does not follow
it, and because a reader who recognises an idea should be able to find where it
came from rather than wonder.

Copyright in an idea does not pass with the idea, so none of these terms attach
to kofeng. That is a statement about what was done, not a licence argument: if
any line here were copied, the licence WOULD attach, and the remedy would be to
remove the line rather than to reword this paragraph.

### ClamAV — GPL-2.0

`clamav/libclamav/upx.c` decodes the same NRV2B/NRV2D/NRV2E codings that
`libkofeng/extractors/decomp/nrv2.c` does. It was read to understand the coding.
The structure of the decoder here is its own - one decode loop with the two
points the variants differ at, rather than three near-copies - and no part of
ClamAV's is reproduced. The note in `nrv2.h` says the same thing beside the
code.

### TinyAntivirus — GPL-2.0

`github.com/develbranch/TinyAntivirus`, read for its **Sality disinfector**,
which is the clearest small example of a cure that needs an interpreter.

What it does, in order: emulate from the entry point with a per-instruction
hook; wait for a one-byte `0xC3`; read `[ESP]` to find where the RET was going,
which is the virus body; verify two byte signatures there; read the original
entry point out of the body at a fixed displacement; read the host's original
first bytes out of a table the virus keeps inside itself, with a flag and a
length in front of them; write those bytes back at the file offset the entry
maps to, set the entry point to the recovered value, and truncate the file to
drop the virus.

WHAT IT SHOWED FIRST was a gap in this engine's ABI: every step after the stop
is a read of a register or of guest memory, `kof_emu_get_reg` and
`kof_emu_read` existed, and nothing carried them across to a module. `emu_reg`
and `emu_read` are that crossing.

THERE IS NOW A SALITY MODULE - `bases/unp/sality_pe.c` - and the debt has to be
stated more precisely than "the shape". Four numbers in it are TinyAntivirus's
measurements and not this project's: the displacements at which a Sality body
keeps the flag, the length and the bytes of the host code it overwrote
(`+0x1773`, `+0x1774`, `+0x1778`) and the distance back to the start of the
virus body (`-0x1116`). They are reproduced as constants because they are facts
about the virus rather than lines of a program; each is verified here before it
is used - the entry point the module computes from them has to equal the entry
the file's own header declares, on every sample, or no repair is described.

AND TWO OF ITS DECISIONS WERE MEASURED AND REJECTED, which is the more useful
half of reading it:

  - ITS BYTE SIGNATURE NAMES ONE GENERATION. TinyAntivirus's README says it had
    one Sality sample, and its two signature runs match exactly one of the four
    here. Diffing all four decrypted bodies leaves a different 49-byte run -
    the virus's own PEB walk, which is code it executes - and that matches all
    four. The lesson is in the sources under "Polymorphic virus detection, read
    only": a signature over bytes identifies a generation, not a family.
  - ITS STOPPING RULE LOOKS IN THE WRONG PLACE. It pauses on every one-byte
    `0xC3` and reads `[ESP]` for the body. Measured, the body turned up at
    0x13116, 0x2316 and 0xb8716 in three runs and at no address any single
    `ret` pointed at; a polymorphic stub has as many hand-overs as its
    generator felt like emitting. What replaced it is periodic scanning - see
    the Nachenberg entry below - which also removed the need for the body to
    execute at all.

### OllyDbg unpacking scripts for PECompact 2.x/3.x — no licence stated

`github.com/ThomasThelen/OllyDbg-Scripts` and
`github.com/dubuqingfeng/ollydbg-script` both break on the same ten bytes at the
end of a PECompact stub - `8B C6 5A 5E 5F 59 5B 5D FF E0`, which is
`mov eax,esi; pop edx; pop esi; pop edi; pop ecx; pop ebx; pop ebp; jmp eax` -
and take EIP at that jump as the original entry point. Their authors report it
against 2.08 and 3.02.2.

Read, and what was learned from it is written into `bases/unp/pecompact_pe.c`:
the sequence is exact and matches once in the sample here, and it is still not
usable as a static declaration, because those scripts search it in the debugged
process's MEMORY. Measured on 007 Spy.exe, the loader copies itself to
0x20000000 and finishes there, so the bytes at that address in the FILE are
never fetched - a watch declared on them ran the full instruction ceiling. That
measurement is the contribution: it says what a mechanism would have to do, not
what this one does.

No code is reproduced; nothing here searches a pattern in guest memory yet.

### Unlicense — GPL-3.0

`github.com/ergrelet/unlicense` unpacks Themida/WinLicense by running the
target under Frida and making the expected original-entry-point ranges
inaccessible, so that the loader's first jump into decrypted code raises a
fault that can be caught and dumped at.

One idea was taken from reading it: that the handover is found by watching
WHERE the program will be rather than by following what the loader does. In
kofeng that became `kof_emu_watch_exec` - regions a PE declares and supplies no
bytes for, where a fetch ends the run as `KOF_EMU_STOP_HANDOFF`. The two share
nothing else: Unlicense instruments a live Windows process and executes the
sample, and this stops an interpreter that never runs anything.

Its version detection was also read and confirmed two facts used in
`bases/unp/themida_pe.c`: that a `.themida` OR `.winlice` section marks
Themida/WinLicense 3.x, and that 2.x is a different container this engine does
not handle.

No code is reproduced.

### Unipacker — GPL-2.0

`github.com/unipacker/unipacker` emulates a packed PE from its entry point and
dumps when it detects either SECTION HOPPING - execution entering a section it
has not been in before - or write-and-execute.

Three things were taken from reading it. The first two are corrections to what
this engine was about to do:

  - write-and-execute is OFF by default there, and is enabled only for named
    packers. kofeng had it off for the same reason and an experiment here
    turned it on globally; measured, a PECompact2 sample then stopped
    eighteen instructions in and a Themida sample lost a stage.
  - section hopping DUMPS AND CONTINUES rather than stopping. The section is
    added to the seen set and the run carries on, so a sample with several
    stages yields all of them instead of the first.

In kofeng those became kof_emu_hop_add and the snapshot in the run loop.

The third is how `imagedump.py` turns a finished run back into a FILE, which is
a separate problem from producing the bytes and one kofeng had been getting
wrong - it was handing the run's memory regions over as they stood, so nothing
identified as a PE and no rule scoped to a region could run. Four of its rules
are used:

  - the entry point written into the dump is where execution HAD GOT TO, not
    the entry point in the file, which belongs to the stub. Unipacker takes it
    from EIP at dump time and dumps on a section hop; kofeng takes the last
    hop, which is the same address. Unlicense passes the same thing to Scylla
    as its `oep` argument.
  - a dump is a FLAT IMAGE: `PointerToRawData = VirtualAddress` and
    `SizeOfRawData` runs to the next section, so file offsets and RVAs
    coincide and there is no file alignment to collapse.
  - memory the run ALLOCATED becomes sections of its own -
    `chunk_to_image_section_hdr`, naming them `.ach0`, `.ach1` ... - because a
    stage a stub built at a fresh address is part of the program and would
    otherwise be lost. kofeng bounds this by the object cap, which Unipacker
    does not: a chunk half a gigabyte above the base would make an image that
    is almost entirely hole, and such a chunk is handed over as its own object
    instead.
  - `SizeOfImage` comes from what the run actually produced, not from the
    original header.

Unlicense's `dump_utils.py` answers the last part of the same question and two
of its rules are used: name the section holding the entry point `.text` and the
one the resource directory points into `.rsrc`, and truncate the file to the
end of its highest section rather than to the image size. kofeng keeps the
original section names where it has them, which is strictly more information.

No code is reproduced from either.

### RetDec — MIT

`github.com/avast/retdec`, its `unpackertool/plugins/mpress` and
`unpacker/decompression/lzmat`. MPRESS writes no version string anywhere in
the file, and this is where the rest of what a scanner needs about it came
from:

  - THE BUILD IS THE DWORD AT EP+8, which is the offset of the fix-up stub and
    is different in every release. RetDec keeps a table of the seven it knows
    and rejects anything above 0xC00 as a corrupted stub. Measured against the
    seven MPRESS files here, six match: four are 0xb5a (2.12-2.19 LZMA) and two
    are 0x29f (2.12-2.19 LZMAT). The seventh is PE32+, which RetDec does not
    handle at all, so its table has no entry for it.
  - WHERE THE FIX-UP STUB IS, and that it comes in three shapes told apart by
    one byte seven bytes into it, each saying where the import hints and the
    original entry point are written relative to its own start.
  - THE IMPORT HINT LIST, which is what MPRESS leaves in place of the import
    directory: per library a delta to its IAT slot, its name, then its
    functions by name or by ordinal, and -1 at the end.
  - LZMAT, the coding MPRESS used before LZMA. A byte oriented LZ77 with a
    nibble stream running through it, so every read is either aligned or
    shifted four bits and the shift changes as it goes.

Two things this gets differently. The long run - the one item that copies
dwords straight out of the stream - ENDS the control byte it was under;
treating the remaining bits as items desynchronises the stream, and measured
that decoded 5618 of 98304 bytes and then asked for a distance of 252736. And
the end of the input is not an error: a decoder that guards itself with "five
bytes left" because a dword read by an odd reader touches five stopped five
bytes early, at 97781 of 98304. Here every read clamps and the OUTPUT reaching
the declared size is what ends the decode.

  - AND THE ONE BIG SECTION CUT BACK INTO SEVERAL. What a decompressor
    produces is the original image's bytes in one span, and describing them
    as one section is wrong in a way a scanner feels: the region partition is
    what decides which rules run over what. RetDec cuts it from four landmarks
    - the import hints, the IAT, the fix-up stub and the entry point - on the
    rule that the hints and the stub sit at the END of the original sections
    and the IAT is a section of its own, then walks the code piece at section
    alignment splitting wherever the preceding 64 bytes are all zero.
    Measured on one sample, that turned a single 5.18 MB RWX span, 3.4 MB of
    it zero, into a 1.2 MB .text with the entry point in it and the rest data.

No code is reproduced: the decoder is C against this engine's interface, and
the bounds are its own.

AND SEPARATELY, ITS DECODER - which is a debt of a different size, because it
is not one format's details but the shape of how this engine reads code at
all. `src/bin2llvmir/optimizations/decoder/`.

The sweep used to run from one end of a region to the other, decoding every
byte whether or not anything could reach it. RetDec does not, and the five
things it does instead are now what kofeng does:

  - CANDIDATE BYTES COME FROM SECTIONS, IN TWO TIERS. Executable sections are
    "primary" and everything else in the segment is "alternative": the second
    is read only where control actually branches into it, never walked end to
    end. Measured here on an 8 MB static ELF: the PF_X segment is 7.79 MB and
    `.text` is 4.75 MB, so 3.04 MB of symbol tables, relocations, `.rodata`
    and unwind data was being disassembled - 39% of the work, producing
    nothing but phantom blocks and loop spans. See `kof_flow_primary`.
  - A WORKLIST OF JUMP TARGETS, not a cursor. Seeded from the entry and the
    function starts the format declares, grown as branches are decoded, and
    control-flow discoveries taken before anything else - RetDec ranks them
    that way in `JumpTarget::eType` and a stack gives the same order.
  - EVERY BYTE READ ONCE. A decoded stretch is struck off the pending set, so
    a target already covered is dropped at once and the linear scan is the
    LAST resort rather than the method - what RetDec calls LEFTOVER, and it
    only ever covers primary ranges.
  - A DRY RUN BEFORE A GUESS IS BELIEVED. A leftover target is the sweep's own
    idea, so the bytes are read once recording nothing and the run is taken
    only if it ends in a return or a transfer. What counts as plausible is
    kofeng's own - RetDec's x86 test is built around `mov eax,1; int 0x80`
    and this engine already answers that question better with
    `kof_sys_noreturn`.
  - RUNS OF ZERO STRUCK OUT FIRST. Alignment is not code, and on x86 it
    decodes to a stream of `add [rax], al` - each of which counted as an
    instruction and so stretched the distance between the two real steps
    either side of it.

AND THE BOUNDS ARE THE POINT OF IT. RetDec's decoder has no MAX_BLOCK, no
MAX_NODE, no MAX_LOOP and no cap on the code size; what it bounds is WHICH
BYTES ARE CANDIDATES, and the results then grow to fit. kofeng had it the
other way round - every byte a candidate, every result capped - and the
measured cost of that was a 4096-entry loop table that a single file filled
exactly, throwing away 11806 further loops and setting the flag that switches
off loop pruning and branch-arm marking for the whole object.

No code is reproduced from any of it. The traversal is C against this
engine's own structures, the per-architecture decoding is unchanged, and
where RetDec's rules are about producing a decompilation rather than reading
capabilities they are deliberately not followed.

### Capstone — BSD-3-Clause, with LLVM-derived files under the NCSA licence

`github.com/capstone-engine/capstone`. NOT LINKED, and not shipped. It was
evaluated as a replacement for this engine's fixed-width decoders and rejected:
linking the ten non-x86 architectures costs 31 MB of binary where kofscanner is
2.8 MB, and `CAPSTONE_DIET` (240 KB) strips the detail - groups come back empty and
`cs_regs_access` fails - which removes the reason to want it.

It is used OFFLINE, on a developer machine, as an ORACLE for the ARM and AArch64
decoders in `libgenome/celllysis/` (`decode_a32.c`, `decode_t32.c`,
`decode_a64.c`): those are written from the architecture's encoding structure,
and `tools/celllysis/arm_diff.c` / `a64_diff.c` run them against Capstone over
random, systematic and real-binary input (`make celllysis-arm-diff`,
`celllysis-a64-diff`; the library is passed in, never shipped). Where the two
disagree the decision is made from the architecture, not by the oracle, and the
decoders say which disagreements are by design. Nothing is reproduced from
Capstone: no table, no code.

### Unpacker — MIT

`github.com/anpa1200/Unpacker` is a detection and routing front end that
delegates the hard cases to Unipacker and Qiling. Its README is what named the
"section hopping or write+execute" rule and sent this work to Unipacker's
source to read it properly. Nothing else was taken, and no code.

### VMPStatic — MIT

`github.com/.../VMPStatic`, copyright (c) 2026 Brian Walker, is where the
VMProtect packer layout in `bases/unp/vmprotect_pe.c` comes from, and it is the
largest single debt in this file. Read from it:

  - that a packed section is a hollow one that is NOT uninitialised data -
    SizeOfRawData and PointerToRawData both zero with the BSS characteristic
    clear, which is what tells a packed section from a real `.bss`;
  - PACKER_INFO: an array of eight-byte `{Src, Dst}` entries, one per packed
    section, the source an RVA where an LZMA stream begins;
  - that from 3.9 the destination is stored exclusive-ored with a key the
    loader rotates left seven bits before each entry, and the argument that
    recovers it - seed the key from entry zero against each candidate section
    and require the rest to decrypt to the OTHER destinations, each exactly
    once, which over five entries only closes on the real table;
  - that the older layout keeps the destinations in plaintext and puts an
    `{RVA, 5}` pair in front of the table naming the five LZMA property bytes;
  - that a raw LZMA stream opens with the range coder's zero byte, which is
    the cheap filter that kills almost every candidate offset;
  - that a block is decompressed to wherever it fits rather than to its
    section's VirtualSize.

What is not from it: the `{RVA, 5}` pair is used here as the ANCHOR the table
is found by, rather than as a place to read properties from once the table is
already located. That difference is what lets this module unpack a VMProtect
image one layer in - 111.exe is VMProtect under MPRESS - where the section
table has been reconstructed by the outer unpacker and no section is hollow any
more. The destination-must-be-empty test and the address-driven emit that goes
with it are this project's, and so is every bound.

No code is reproduced: VMPStatic is Go against its own PE reader and the
`ulikunitz/xz` decoder, and this is a freestanding C module against kofeng's
own decoders and PE writer.

### XVolkolak / XEmulUnpacker — MIT

`github.com/horsicq/XVolkolak`, copyright (c) 2026 hors and contributors.
Read for how an emulator decides that a packer's stub has handed control to the
program, which is `OEP_CONTEXT` in `dep/XEmulUnpacker/`:

  - `nSpDelta`, the stack pointer measured against where it was at the entry
    point, and the rule that a real hand-over happens with it BALANCED. That
    is the single most useful thing in the file and it is what
    `libgenome/phenotype/kofemu.c` now tests;
  - the per-packer tails: PECompact hands over with `ret` (1.00-1.10),
    `ret 4` (1.50-1.76) or `jmp eax` (2.40), and 0.90 does it with a `ret`
    from a heap buffer into the image;
  - that the undefined region of 16-bit `SHRD`/`SHLD` is NOT derivable and
    has to be taken from the host CPU. A formula was guessed here first and
    was wrong; the note in `kofemu.c` says so beside the inline assembly that
    replaced it.

No code is reproduced from XEmulUnpacker: it is C++ against Qt and Unicorn.

`dep/XStaticUnpacker/xaspack.cpp` and `dep/SpecAbstract/modules/nfd_pe.cpp` ARE
sources this engine took structure from, under the MIT terms above:

  - THE ASPACK CODING, which is not documented anywhere else this project could
    find: the bit reader, the four alphabets, the delta-coded code lengths, the
    repeat-offset history, and the 114-byte table the decoder indexes three ways.
    `libkofeng/extractors/decomp/aspack.c` is C against this engine's decoder
    interface rather than a transcription, and every bound in it is this
    engine's own - the original decodes into an image it owns, and this decodes
    into a caller's buffer with a hostile file behind it. It reports what it
    wrote on failure, which the original has no need to.
  - THE PER-BUILD STUB LAYOUTS, `g_aspackLayouts`: where each ASPack generation
    keeps its block table, its decoder tables, its call/jmp marker byte and the
    original entry point, all measured from the entry point minus one. Those
    offsets were derived there from a packed corpus this project does not have;
    `bases/unp/aspack_pe.c` carries six of the eight rows and says in the file
    which one is measured here and which are borrowed. The two left out are
    2.11 and 2.11c, whose stub head is encrypted per file.
  - THE DETECTION RULE that makes those rows safe to act on: require the
    114-byte decoder table at the row's own offset, not just the entry-point
    signature. `nfd_pe.cpp` carries ASPack's 2.12 signature a SECOND time under
    the name FAKESIGNATURE, because other packers stamp it at their own entry
    points; that warning is why `aspack_pe.c` never acts on a signature alone.
  - THE ENTRY-POINT TABLES for Petite (`2.2-2.3`, `1.3-1.4`, `2.4`, `1.2`) and
    kkrunchy (`0.23 alpha 1`, `alpha 2`, `alpha 3-4`), and kkrunchy's fused
    DOS/PE header signatures `MZfarbrausch` / `MZconspiracy`. Rewritten as
    `struct eps_row` tables; the byte patterns are the same facts about those
    builds.
  - UPX's PE IMPORT FORMAT, from `xupx.cpp`: the payload's trailer - its last
    four bytes are the trailer's own offset, and the trailer holds the original
    NT headers, the original section headers and then where the compact import
    list is - and the list's own encoding, whose library names are offsets into
    the PACKED file's import directory rather than into anything decompressed.
    `upx_imports` in `bases/unp/upx_pe.c` reads it; the declaration it turns
    into is this engine's own.
  - PETITE'S COMPRESSION LEVEL, from `_detect` in `xpetite.cpp`: the entry
    point is `mov eax, imm32` and the immediate is imageBase plus the
    VirtualAddress of the section holding the loader, which Petite puts LAST at
    its higher level and second-to-last at the lower one. `pet_level` in
    `bases/unp/petite_pe.c` is a restatement of that comparison. It is a
    version rather than a detail because three constants in the static path are
    chosen by it - how much loader tail to strip, the skew it may sit at, and
    where the op table is when the loader cannot be read for it.
  - AND WHERE THE STATIC ROAD ENDS. `xpetite.cpp` recovers Petite's op table
    statically and then runs the build's own embedded decoder under an
    emulator, and there is no `xkkrunchy.cpp` at all - kkrunchy is under
    XEmulUnpacker. Both are why `bases/unp/petite_pe.c` and
    `bases/unp/kkrunchy_pe.c` drive the interpreter instead of decoding, and
    both files say so.

### Polymorphic virus detection, read only

Four sources, read together because they answer one question - how a scanner
recognises a family whose every copy is encoded differently - and because they
agree with each other and disagreed with what this engine was doing.

Nothing is reproduced from any of them. Two are published research, one is a
vendor's blog post and one is an expired US patent, which is a public
disclosure by design.

**US 5,696,822 - "Polymorphic virus detection module", Carey Nachenberg,
Symantec, filed 1995, granted 1997 (expired).** The control structure this
engine now uses for Sality is its, in three parts:

  - a STATIC EXCLUSION phase that rules candidates out from the file's gross
    structure before any emulation, so that most files are never emulated at
    all. Here that is `bases/heur/peinfect_00.c`.
  - a bounded emulation - its figure is 1.5 MILLION instructions - during which
    the scan may be entered PERIODICALLY, "to attempt to identify a virus that
    has been partially decrypted". That sentence is the whole saving: this
    engine was waiting for the decrypted body to finish AND to be given
    control, which measured 186 million instructions and 40 seconds on one
    file, where what a repair needs is in memory after about twenty million.
    `emu_slice` in the module ABI is that periodic entry, and the same four
    samples now finish in 0.3 to 4.6 seconds.
  - PAGE TAGGING: scan the pages an instruction was fetched from or wrote to,
    and only those. kofeng already had this - `page->written` and the region
    gathering are the same idea - so nothing changed for it.

ITS FOURTH PART IS NOT IMPLEMENTED AND THE REASON IS MEASURED. The patent's
dynamic exclusion keeps a 256-bit INSTRUCTION USAGE PROFILE per mutation engine
- one bit per first opcode byte - and delists a virus the moment an instruction
appears that its engine never emits, stopping when the candidate list empties.
That is an exclusion mechanism over MANY families; with one family it excludes
nothing. Measured on the four decryptors here, the opcode histograms are
dominated by MOV, TEST, CMP and JCC, which is every program ever compiled. It
becomes worth building when there is a second and a third profile to narrow
against.

**"Bytecode signatures for polymorphic malware", Alberto Wu, ClamAV blog, 2011.**
A worked example of detecting Xpaj - a polymorphic infector with entry-point
obfuscation - with NO emulation: find a small static anchor, then walk the
DISASSEMBLY, checking each instruction's opcode class and the KIND of its
operands (a register from a set, a displacement inside the stack frame), eating
the generator's junk because junk is itself a recognisable class of
instruction, and following the relative `call`/`jmp` the chunks are chained
with.

`libkofeng/kofcore/kofmod/cell.h` and `libgenome/celllysis/cursor.c` are
that mechanism made available to a module - decode without executing, keep a
constant map over the registers, resolve a branch back to a file offset. The
one thing its example makes explicit and this had to add is the modelled stack:
their walker saves the return address when it follows a call, because
`call $+5; pop reg` is how every position-independent decryptor learns where it
is, and a walker without it loses the register at the first pop.

IT DOES NOT CURRENTLY DETECT SALITY, and that is a measurement rather than an
omission: the walk reaches the delta-get on three of the four samples and never
reaches the decrypt loop within twenty thousand instructions. Xpaj's routine is
near its entry and chained by unconditional jumps; Sality's is not that shape.

**"Static analysis of executables to detect malicious patterns", Christodorescu
and Jha, 12th USENIX Security Symposium, 2003.** The theory of why the above
works: malicious-code detection as an obfuscation/deobfuscation game, and an
abstract representation - a malicious-code automaton over UNINTERPRETED SYMBOLS
- that survives the four transformations it names: dead-code insertion, code
transposition, register reassignment and instruction substitution. The
uninterpreted symbols are the answer to register reassignment, and in celllysis that
is left to the rule: a rule binds a register number in a local and requires the
same one later, which is unification done by hand.

ITS IMPLEMENTATION IS DELIBERATELY NOT FOLLOWED. SAFE builds control-flow
graphs with IDA Pro and CodeSurfer and decides by language containment; the
paper measures 1.4 to 9.1 seconds for the annotator and 0.5 to 1.6 for the
detector, per file per automaton, and calls its own times on benign code
"unacceptably large". What was taken is the vocabulary and the list of
transformations a rule has to survive.

**"Polymorphic shellcode engine using spectrum analysis", CLET team, Phrack 61
phile 9, 2003.** The generator's side, read to know what the detector faces.
Two things in it are load-bearing here:

  - it explains a measurement that failed. An encryption that is a SINGLE XOR
    with a FIXED-SIZE key leaves `C[i] xor C[i+N]` independent of the key, which
    would be a signature on the encrypted body. Tried here at every stride from
    1 to 16 across the four Sality bodies: 0.0% agreement at all of them. The
    article says why - real engines vary the key AND the key size and use
    several reversible operations - so the bodies genuinely share nothing, and
    a byte rule on the encrypted half is not a gap in this project's research
    but a thing that does not exist.
  - its authors name their own weakness: "the main frame of our routine is
    rather the same (this is maybe a weakness) but we use three registers...
    chosen at random", and they note that junk which cancels out is "easily
    recognizable by an IDS which would make code emulation". The invariant is
    the frame and a small set of reversible operations, which is exactly what a
    usage profile or a shape rule is written against.

**"How do AV vendors create signatures for polymorphic viruses?", Reverse
Engineering Stack Exchange, 2013.** Not a source of technique, and listed
because one sentence in it is quoted in several places in this tree as the
reason a whole approach was abandoned: a signature over a stream of bytes "or a
stream of mnemonics" identifies one GENERATION of a generator rather than the
malware, so vendors write detection CODE against the semantics. It also names
the evidence for Sality and Virut that `peinfect_00.c` is built from.

### Emulator design patents, read only

Ten further patents, read as scans of the printed grants. They are expired or
published disclosures; nothing is reproduced from any of them, and several are
listed precisely because they were read and then NOT followed.

**US 5,964,889 - "Examining the opcode for faults before emulating"
(Nachenberg / Symantec, 1999).** A FAULT MANAGER between fetch and decode: the
opcode is checked against a list of faulting instructions held in an UPDATABLE
DATA FILE, and a match saves the machine's state and interrupts to a handler
which may examine and CHANGE the virtual machine before resuming. Two details
are worth recording even though the mechanism is not copied:

  - its fault stack is deliberately NOT the guest's own SS:SP, because
    polymorphic viruses keep temporary data below the stack pointer and a
    scanner using that stack corrupts them - making the virus malfunction under
    emulation and not on real hardware.
  - its dummy-loop handler is loop acceleration done narrowly: fault on
    E0/E1/E2/E3, and ONLY after 500 instructions so clean files never pay;
    check the one shape whose meaning is certain - a loop back to an
    immediately preceding ONE-BYTE instruction - and if it matches, zero CX and
    step the instruction pointer past it. If it does not match, disable the
    check for the rest of the file.

WHAT WAS TAKEN IS THE CAPABILITY, NOT THE DESIGN. A module here could already
stop a run on an instruction and READ the machine; it could not change one. The
three accessors `emu_set_reg`, `emu_set_ip` and `emu_write` are that gap
closed - a paused run can now be corrected and resumed, which is what every
"circumvent the trick" technique in these patents rests on.

AND THE DUMMY-LOOP HANDLER DOES NOT FIRE HERE. Disassembled, the Sality
decryptor's junk contains no LOOP or JCXZ at all - the seven E0..E3 bytes in
its loop body are operands. Its junk is meaningless `rep` prefixes on
non-string instructions, which the hardware ignores and which cost a decode
and nothing else.

**US 6,971,019 - "Histogram-based virus detection" (Nachenberg / Symantec,
2005).** The mature form of the 1995 usage profile: emulate while building a
histogram of instruction characteristics named by a definition file, stop when
"active instructions" stop appearing, then let interpreted P-code decide from
the histogram - and let it ask for more emulation. An ACTIVE INSTRUCTION is
defined as decryption-like memory behaviour: a read of an address followed by a
write back to it, at addresses stepping through a buffer.

THE IDEA IS RIGHT AND THAT DEFINITION DOES NOT FIT THIS FAMILY, measured. Of
408,441 guest writes in one Sality run, 350,346 WERE writes back to something
just read - and every one was the stack, push and pop touching the same slot.
The decryption reads from one place and writes to another, so it never made the
pattern once in twenty million instructions. What it does make is a sequential
write stream: 58,076 writes landing within eight bytes of the one before,
against 58,066 loop iterations counted independently, and every one of them
inside the decrypted body.

THE STOP RULE IS NOT SHIPPED, AND THE REASON IS A NUMBER. The signal is
implemented and sound; the threshold is not. Measured across samples, the
largest gap between two actives inside a decryption that had NOT finished runs
from 335 to 1,209,199 instructions - three and a half orders of magnitude, with
PECompact at the top. No single figure separates "finished" from "still
working", so it sits behind a flag with the measurements written beside it.
See KOF_EMU_QUIET.

**US 9,740,864 - "Emulation of files using multiple images of the emulator
state" (Kaspersky, 2017).** A tree of saved emulator states; termination is
classed CORRECT (harmful behaviour seen, or a budget reached) or INCORRECT (a
missing library, an unhandled exception); on an incorrect one, reload an
earlier image and resume with the state CHANGED to get past the trick - a
different branch at a conditional jump, a different return value, a reversal.

NOT BUILT, AND THE EVIDENCE IS AGAINST IT HERE. By that taxonomy nearly every
run on a Windows corpus ends incorrectly - 125 of 129 end in a fault - so the
technique looks like it should pay. It was tested from the cheap end first: let
the run survive the fault instead of rolling back to avoid it, by answering an
unmapped data read with zero and by giving an unmapped write a page. Measured
over 300 samples, that took the instructions executed from 135 million to 2,208
million and produced THREE more objects and NOT ONE more detection, for seven
times the scan time. A run that continues past its fault finds nothing, so a
run that rolls back and avoids the fault would arrive at the same place. Both
tolerances stay behind flags - KOF_EMU_SOFTREAD and KOF_EMU_SOFTWRITE - with
those numbers recorded at the site.

**US 8,473,931 - "Optimizing emulation" (IBM, 2013).** Recognise a long loop -
by iteration count, execution count or elapsed time - hash its contents
cheaply, look the hash up in a database of known long loops, and on a match
confirm with a second, unique hash before substituting a known result for the
loop.

NOT APPLICABLE, TWICE. The lookup is byte-exact, and a polymorphic decryptor
has a different body in every sample, so no database entry can match twice. For
the case it does fit - a packer whose decompression loop is fixed - this engine
already has a better answer: recognise the packer statically and decompress it
with a decoder, emulating nothing at all.

**US 7,603,713 and US 8,122,509 (Kaspersky) and US 8,943,596 - accelerating an
emulator with real hardware.** All three run the suspect code, or its
uninteresting parts, on the actual CPU with the state saved and restored around
it. Out of scope by construction: this engine never executes a sample.

**US 5,999,723 - "State-based cache for antivirus software" (Nachenberg /
Symantec, 1999).** Emulate a fixed number of instructions, suspend, build a
state record and compare it against a cache of records already seen; a match
means this prefix has been emulated before and found clean. Nothing to gain
here for a different reason: this engine starts 35 interpreter runs across
4,712 files, so there is no repeated prefix to cache.

**US 8,341,743 - "Detection of viral code using emulation of operating system"
(Symantec).** An artificial memory region spanning operating-system components,
and a monitor that detects the guest reaching into it. This engine already
builds a synthetic PEB, LDR and module images and counts reads into them - see
`count_mod_reads` in kofemu.c and the thread-block builder in emu_unpack.c.

**US 6,907,396 - "Detecting computer viruses by patching" (Networks Associates,
2005).** Emulator extensions - program instructions loaded INTO the emulator to
help detection. That is what a module is here, so the idea arrives already
implemented.

### The Themida and VMProtect research projects — read only

None of these is in the repository and none of their terms attach. They are
listed because each answered a question, and a reader who recognises a shape
should be able to find it.

  - `themida-unmutate` (GPL-3.0) and `UnpackThemida` (GPL-3.0) - what Themida's
    mutation layer is, and why a STATIC pass over it does not apply to the
    samples here: their program sections measure 8.00 bits per byte, so there
    is nothing to un-mutate until something decrypts them.
  - `themida-dumper` (MIT, nelj14) and `Themida-Research` - the `.themida` /
    `.winlice` plus `.boot` section pair and the aPLib coding, which is what
    `bases/unp/themida_pe.c` looks for.
  - `VMProtectDumper` (PolyForm Noncommercial 1.0.0) - read for the dumping
    strategy only. Its terms are restrictive and nothing from it is used; the
    licence is named here so that anyone who later wants to take code from it
    sees the condition first.
  - `OreansCrack` (MIT, Ren), `vmp2` (MIT, Back Engineering Labs) and `vid`
    (MIT) - VMProtect's virtual machine: its handler layout and bytecode. That
    layer is NOT undone by anything in this repository, and these were read to
    establish that rather than to implement it.
  - `UnSafengine64` - Safengine's shape, which is why `dense_code_unread` in
    `libkofeng/scanners/scan.c` exists: a sample whose `.text` is 794,624
    bytes at 8.00 bits with the entry point elsewhere used to be reported
    clean.

### The OllyDbg and x64dbg script collections — read only

Two collections of debugger scripts, carrying no licence file:
`ollydbg-script/` (187 directories, one per packer) and `Scripts/` (27 files).
Read as DOCUMENTATION of where each packer keeps things - a script that sets a
breakpoint at `entry + 0x2b6` is a statement about that build's layout. Two
things were taken as facts and both were checked against samples here before
being used:

  - MPRESS keeps a per-build offset at EP+8, which is what `mp_builds` in
    `bases/unp/mpress_pe.c` is keyed on;
  - the Themida "Exception Information" script runs after two `ZwContinue`
    breaks, which is why reading a version out of that region STATICALLY
    produced garbage. That is recorded in `themida_pe.c` as a thing that was
    tried and did not work.

No script is reproduced and none is shipped.
