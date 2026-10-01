# KOFENG — a malware scanner whose signatures are compiled code

Each signature is a **raw, headerless, position-independent blob**: no
relocations, no undefined symbols, no writable data, no object header. Loading a
database is a `memcpy` into one arena and a single `mprotect` — there is no
object format to parse at run time, and the build refuses any module that would
need one.

A signature is therefore not a byte string. It is a function that can follow a
header, resolve an offset out of the file, walk a structure, and decide for
itself what it has found.

```c
KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, "Mirai");
KOF_TARGET_RANGE(scan_range_data, KOF_SCAN_ELF_DATA);

KOF_DEFINE_STR(s0, "4r3s b0tn3t", KOF_CASE_EXACT, KOF_WORD_FULLWORD);

void kof_scan(const struct kof_obj_ctx *ctx)
{
        if (kof_find_str_any(scan_range_data, s0))
                KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
```

📖 **[Full documentation is in the wiki](../../wiki)** — everything below is a
map to it.

## Engine's structure overview

```
                         ┌─────────────┐
                         │    Sniff    │
                         │  File Type  │
                         └──────┬──────┘
                                ↓
                ┌─────────────────────────────────┐
                |         Decompress              │
                │ + Heuristic (Exploit detection) │
                └───────────────┬─────────────────┘
                                ↓
                         ┌─────────────┐
                         │   Parser    │
                         └──────┬──────┘
                                ↓
                    ┌──────────────────────┐
                    │       Metadata       │
                    │      + Heuristic     │
                    └──────────┬───────────┘
                               ↓
                         ┌─────────────┐
                         │   Unpacker  │
                         └──────┬──────┘
                                │
                       ┌────────┴────────┐
                       ↓                 ↓
                 ┌───────────┐     ┌───────────┐
                 │  Static   │     │  Emulator │
                 └─────┬─────┘     └─────┬─────┘
                       └────────┬────────┘
                                ↓
                         ┌─────────────┐
                         │  Decryptor  │
                         └──────┬──────┘
                                ↓
                         ┌─────────────┐
                         │  Normalizer │
                         └──────┬──────┘
                                ↓
                         ┌─────────────┐
                         │   Matcher   │
                         └──────┬──────┘
                                │
                    ┌───────────┴───────────┐
                    ↓                       ↓
              ┌───────────┐          ┌────────────┐
              │  Pattern  │          │  Overlord  │──────────────┐
              └───────────┘          └──────┬─────┘              |
                                            ↓                    ↓
                                      ┌───────────┐   ┌────────────────────┐
                                      │   Plague  │   │  Struct similarity |
                                      └───────────┘   └────────────────────┘
                                ↓
                         ┌─────────────┐
                         │    Cure     │
                         │  (planned)  │
                         └─────────────┘
```

## Start here

| | |
|---|---|
| [Overview](../../wiki/Overview) | what the engine is, in one page |
| [Build and run](../../wiki/Build-and-run) | `make`, then scan something |
| [Generating a signature](../../wiki/Generating-a-signature) | from a sample to a shipped rule |
| [Architecture](../../wiki/Architecture) | how the pieces fit |

## Writing signatures

| | |
|---|---|
| [Module anatomy](../../wiki/Module-anatomy) | what a `.c` in `bases/` contains |
| [Target declarations](../../wiki/Target-declarations) | format, size, arch — the preconditions the host checks without calling you |
| [Markers](../../wiki/Markers) · [Matchers and ranges](../../wiki/Matchers-and-ranges) | the bytes to look for, and where |
| [Conditions](../../wiki/Conditions) | what a combination of markers means, and at what confidence |
| [Regions](../../wiki/Regions) | CODE, DATA, NOLOAD — scanning part of a file instead of all of it |
| [Shellcode signatures](../../wiki/Shellcode-signatures) | when the payload is not a file |
| [Heuristic rules](../../wiki/Heuristic-rules) | scoring what the parse found wrong, when no signature names it |

## Inside the engine

| | |
|---|---|
| [Scan pipeline](../../wiki/Scan-pipeline) | what happens to one object, and what work is avoided |
| [String matching engine](../../wiki/String-matching-engine) | one sweep per region for all of its markers; how the routine is chosen |
| [Parsers and formats](../../wiki/Parsers-and-formats) | ELF, PE, the containers, and how a script is identified |
| [Scan objects](../../wiki/Scan-objects) | a file is one object; an archive is many |
| [Normalisation](../../wiki/Normalisation) | decoding base64, hex and percent so a rule can be written against what the program means |
| [Unpackers](../../wiki/Unpackers) · [Decompressors](../../wiki/Decompressors) | getting to the bytes that matter |
| [Emulator](../../wiki/Emulator) · [recovered objects](../../wiki/Emulator-recovered-objects) | when static unpacking is not enough |
| [Disassembly and xref](../../wiki/Disassembly-and-xref) | which code refers to which data |
| [Symbols and region search](../../wiki/Symbols-and-region-search) | searching something other than raw bytes |
| [Database format](../../wiki/Database-format) · [Building a database](../../wiki/Building-a-database) | what a `.ksig` is and how one is made |
| [Caching](../../wiki/Caching) | the clean-file set, what a key is, and when it can lie |

## Similarity, for rules that must survive a rebuild

| | |
|---|---|
| [Plague signatures](../../wiki/Plague-signatures) | how much of one declared block of code is present, as a percentage |
| [Overlord signatures](../../wiki/Overlord-signatures) | is this the same program as that one — shape, string set, call chain |

## Beyond files

| | |
|---|---|
| [Real-time collection](../../wiki/Real-time-collection) | `libkoforbit` — fanotify, the process connector, and the `/proc` snapshot |

## Tools

| | |
|---|---|
| `kofscanner` | scan a file or a tree |
| `kofexamine` | what the engine sees in one object: regions, markers, what each module made of it |
| `kofviewer` | a terminal UI over the same facts, and where signatures are drafted |
| `ksigbuilder` | pack compiled modules into a database; `--module` compiles one |
| `kofwatchtower` | print what the machine is doing, and what it cost to find out |
| `kofwatchman` | the half that decides: those records against a database |
| `kofmontrace` | run a program and show only what it did |

[Command-line reference](../../wiki/Command-line-reference) ·
[Reading results](../../wiki/Reading-results) ·
[A quick look at kofviewer](../../wiki/A-quick-look-at-kofviewer)

## Building and testing

`make` needs a C11 compiler and nothing else.

```sh
make                # engine, tools, and the signature database
make unit           # differential and fuzzing tests
make unit-asan      # the same under AddressSanitizer and UBSan
```

The tests are differential where they can be — inflate against zlib, the three
matcher entry points against each other — because a corpus run passes while the
code is still wrong on an input the corpus does not happen to contain.

## What this is exploring

Traditional signature engines commonly build **one structure over the whole
database** — an Aho-Corasick automaton, typically. It is fast and its memory
grows with the database.

KOFENG asks what happens if the per-signature logic stays in the signature. The
matcher still builds tables, because reading a region once for all of its markers
is the only way the cost stops growing with the base — but they are built from
the markers of **one region**, their size is derived from the marker count and
bounded, and `--stats` prints it. The shipping database's tables are 0.08 MB.
What is *not* built is a structure that has to hold every pattern at once, and
what is not given up is a signature's ability to run code.

Whether that trade is worth it is the experiment. The
[String matching engine](../../wiki/String-matching-engine) page has the
measurements, including the approaches that were tried and rejected.

## Background

Inspired by, and an independent implementation of ideas from:

* [Objective-See — Security Research](https://objective-see.org/blog/blog_0x22.html)
* [The Antivirus Hacker's Handbook](https://www.amazon.com/Antivirus-Hackers-Handbook-Joxean-Koret/dp/1119028752)
* **z0mbie / 29a** — author of several classic antivirus and unpacking tools
* Historical antivirus engine techniques used by **Kaspersky**

It contains no Kaspersky source or proprietary engine code.

## Status

A research and hobby project, still experimental. Not a replacement for a
production antivirus, and not audited for use as one.

## Thanks to

Projects whose source was read while building this, and what was learned from
each. **No code from any of them is in this repository** — the debt is to an
idea or to a format, and it is recorded because a reader who recognises one
should be able to find where it came from. The detail, and why these licences
do not attach to kofeng, is under "Read, not taken" in
[THIRD-PARTY.md](THIRD-PARTY.md).

| project | what it gave |
|---------|--------------|
| [ClamAV](https://github.com/Cisco-Talos/clamav) (GPL-2.0) | the NRV2B/NRV2D/NRV2E codings UPX packs with, read to understand the format |
| [Unlicense](https://github.com/ergrelet/unlicense) (GPL-3.0) | that a packer's handover is found by watching **where the program will be**, not by following what the loader does — this engine's `kof_emu_watch_exec`. Also that `.themida` or `.winlice` marks Themida/WinLicense 3.x, and that a dump is finished by naming its sections from the entry point and the resource directory and truncating to the last section |
| [RetDec](https://github.com/avast/retdec) (MIT) | that MPRESS says which build wrote a file in the **dword at EP+8**, where its fix-up stub is and the three shapes it comes in, the import hint list it leaves in place of an import directory — so the original entry point and the imports are recoverable **without running anything** — and the LZMAT coding it used before LZMA |
| [Unipacker](https://github.com/unipacker/unipacker) (GPL-2.0) | that a packed sample is dumped when execution first enters a section it has not run in before — and that the run should **continue** afterwards, so every stage is caught rather than the first. Also how a finished run is rebuilt into a *file*: the entry point is where execution got to rather than the one in the header, raw offsets equal RVAs, and memory the run allocated becomes sections of its own |
| [Unpacker](https://github.com/anpa1200/Unpacker) (MIT) | named the rule above and pointed at where to read it |
| [TinyAntivirus](https://github.com/develbranch/TinyAntivirus) (GPL-2.0) | where a Sality body keeps the host bytes it overwrote, and the length and flag in front of them — the four displacements `bases/unp/sality_pe.c` repairs from. Its byte signature and its `ret`/`[ESP]` stopping rule were both measured here and **rejected**: each names one generation of a polymorphic family |
| [US 5,696,822](https://patents.google.com/patent/US5696822A/en), Nachenberg / Symantec (expired patent) | that a polymorphic family is found by excluding candidates from the file's gross structure **before** emulating, by scanning **periodically** during the decryption rather than waiting for it to finish, and by scanning only the pages the run touched. The periodic scan is `emu_slice` — it took one sample from 40 seconds to 4.6 |
| [ClamAV bytecode signatures](https://blog.clamav.net/2011/11/bytecode-signatures-for-polymorphic.html) (GPL-2.0) | that a polymorphic decryptor can be recognised with **no emulation at all** — anchor, then walk the disassembly checking opcode classes and operand kinds, eat the junk, follow the relative branches. That mechanism is `kofmod/kdis.h` |
| [SAFE](https://www.usenix.org/legacy/events/sec03/tech/christodorescu.html), Christodorescu & Jha, USENIX Security '03 | the four obfuscations such a rule must survive — dead code, code transposition, register reassignment, instruction substitution — and that register reassignment is answered by binding a register as a *variable* rather than naming it |
| [Phrack 61:9](http://phrack.org/issues/61/9.html), CLET team | the generator's side: why a key-independent transform of the encrypted body does **not** exist for real engines, and that the invariant they leave is the *frame* plus a small set of reversible operations |
| [Bitdefender bddisasm](https://github.com/bitdefender/bddisasm) (Apache-2.0) | the x86 decoder, which unlike the above **is** vendored — see the table below |


## Licence

The code written for this project is under the **MIT License** — see
[LICENSE](LICENSE). The repository is not single-licensed:

| what | terms |
|------|-------|
| engine, tools, tests | MIT |
| `libkofemu/bddisasm/` | Apache License 2.0, Bitdefender — one file patched and marked, see [THIRD-PARTY.md](THIRD-PARTY.md) |
