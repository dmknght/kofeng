# bddisasm, vendored

Upstream: Bitdefender bddisasm, release **3.0.1**
<https://github.com/bitdefender/bddisasm>

Licence: **Apache License 2.0** — the full text is in `LICENSE` beside this file.

## What was taken

The x86/x64 **instruction decoder** and nothing else.

    inc/          the public headers, minus bdshemu.h and bdshemu_x86.h
    src/          bddisasm_crt.c  bdx86_decoder.c  bdx86_formatter.c
                  bdx86_helpers.c  bdx86_idbe.c    bdx86_operand.c
    src/include/  the decoder's private headers and instruction tables

## What was NOT taken, and why

`bdshemu` — Bitdefender's shellcode emulator — is deliberately absent. It is
built to *detect* shellcode and reports indicators; it emulates a small window
of memory and stubs nothing of the environment. kofeng needs the opposite: run
a packer stub far enough that it writes its payload, then hand those bytes to
the scanner. That is a different program, so it is written here rather than
bent out of bdshemu. The decoder is the part worth reusing, and it is the part
that would be least wise to write again.

Also absent: `disasmtool`, `bindings`, `isagenerator`, the test suites and the
build files for other systems. None of them are needed to decode an
instruction.

## What was changed

**One line, in `src/bdx86_decoder.c`.** Every other file is byte for byte as
released. The directory layout keeps `src/` and `inc/` siblings so the upstream
`#include "../inc/bddisasm.h"` and `#include "include/..."` paths resolve
unaltered - which is the whole reason the layout looks like this rather than
flattened.

Upgrading is therefore a **merge of one hunk**, not a copy. Check first whether
upstream has fixed it; if so, take theirs and delete this section.

### The hunk: a 16-bit displacement that was never fetched

In `NdFetchModrmAndDisplacement`, the guard that decides whether an instruction
carries a displacement reads

    if ((ModRm.mod == 0 && base == NDR_RBP) || mod == 1 || mod == 2)

`NDR_RBP` is 5, which is the right register for 32- and 64-bit addressing. In
**16-bit** addressing the mod=0 form that carries a bare displacement is
**rm=6**, not rm=5 - rm=5 is `[di]` and takes none. The file's own
`gDispsizemap16[0]` says exactly this (`{0,0,0,0,0,0,2,0}`); the guard did not,
so the `disp16` was never fetched and the instruction came back short.

The patch makes the compared register depend on the addressing mode. It is
marked `KOFENG PATCH` at the site.

**What it broke.** `64 67 8B 1E 30 00` - `mov ebx, fs:[0x30]`, the PEB fetch
every Windows stub that resolves its own imports begins with, written with an
address-size prefix. bddisasm 3.0.1 decoded it as **four** bytes with no
displacement and rendered it `fs:[]`; objdump and ndisasm both give six bytes
and `fs:0x30`. The emulator read address `0x30` instead of `fs:0x30`, which is
in the first page, which answers zero - so the guest was handed a null PEB and
took whatever path it had for "this is not Windows NT".

Measured on a Sality sample: the virus fell through to its Win9x arm, failed
its `cmp word [ebx],'MZ'` check and gave up after **25 instructions** of its
body. With the patch the same sample runs on past seven million. Covered by
`tests/unit/insn_addr16.c`.
