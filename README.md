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
| [String matching engine](../../wiki/String-matching-engine) | one sweep per region for all of its markers; how the routine is chosen |
| [Parsers and formats](../../wiki/Parsers-and-formats) | ELF, PE, and the containers |
| [Scan objects](../../wiki/Scan-objects) | a file is one object; an archive is many |
| [Unpackers](../../wiki/Unpackers) · [Decompressors](../../wiki/Decompressors) | getting to the bytes that matter |
| [Emulator](../../wiki/Emulator) · [recovered objects](../../wiki/Emulator-recovered-objects) | when static unpacking is not enough |
| [Disassembly and xref](../../wiki/Disassembly-and-xref) | which code refers to which data |
| [Symbols and region search](../../wiki/Symbols-and-region-search) | searching something other than raw bytes |
| [Database format](../../wiki/Database-format) · [Building a database](../../wiki/Building-a-database) | what a `.ksig` is and how one is made |

## Tools

| | |
|---|---|
| `kofscanner` | scan a file or a tree |
| `kofexamine` | what the engine sees in one object: regions, markers, what each module made of it |
| `kofviewer` | a terminal UI over the same facts, and where signatures are drafted |
| `ksigbuilder` | pack compiled modules into a database; `--module` compiles one |

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

## Licence

The code written for this project is under the **MIT License** — see
[LICENSE](LICENSE). The repository is not single-licensed:

| what | terms |
|------|-------|
| engine, tools, tests | MIT |
| `libkofemu/bddisasm/` | Apache License 2.0, Bitdefender — see [THIRD-PARTY.md](THIRD-PARTY.md) |
