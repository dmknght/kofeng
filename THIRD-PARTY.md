# Third-party code in kofeng

The project's own terms are MIT; see [LICENSE](LICENSE), which also carries the
summary of everything below. This file is the detail.

## bddisasm 3.0.1 — Apache License 2.0

    libkofemu/bddisasm/

Copyright (c) Bitdefender. Licensed under the Apache License, Version 2.0.
The full licence text is at `libkofemu/bddisasm/LICENSE`; provenance and the
exact subset taken are recorded in `libkofemu/bddisasm/README.kofeng.md`.

The files are unmodified. Apache 2.0 requires that a copy of the licence travel
with the code, that existing copyright and attribution notices are kept, and
that modified files be marked as changed - there are none, and the README says
so explicitly so that a later reader does not have to diff a release to find
out.

This applies to any distribution of kofeng, source or binary.

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
    `libkofemu/kofemu.c` now tests;
  - the per-packer tails: PECompact hands over with `ret` (1.00-1.10),
    `ret 4` (1.50-1.76) or `jmp eax` (2.40), and 0.90 does it with a `ret`
    from a heap buffer into the image;
  - that the undefined region of 16-bit `SHRD`/`SHLD` is NOT derivable and
    has to be taken from the host CPU. A formula was guessed here first and
    was wrong; the note in `kofemu.c` says so beside the inline assembly that
    replaced it.

No code is reproduced: XEmulUnpacker is C++ against Qt and Unicorn.

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
