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

**Nothing.** Every file is byte for byte as released. The directory layout keeps
`src/` and `inc/` siblings so the upstream `#include "../inc/bddisasm.h"` and
`#include "include/..."` paths resolve unaltered - which is the whole reason the
layout looks like this rather than flattened.

Upgrading is therefore a copy, not a merge. If that ever stops being true, say
so here in this section rather than leaving the claim standing.
