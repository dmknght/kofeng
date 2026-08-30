# KOFENG — Malware Scanner Engine Using Executable Signature Modules

KOFENG is an experimental malware scanning engine that uses **compiled code modules as individual detection signatures**.

Each signature is compiled and linked into a **raw, headerless, position-independent blob**: no relocations, no undefined symbols, no writable data, and no object-file header of any kind. Loading a signature database is a `memcpy` into one arena followed by a single `mprotect` — there is no object format to parse at runtime, and the build refuses any module that would need one.

The project explores an alternative approach to traditional signature database architectures, with a particular focus on **memory usage, signature scalability, and per-signature scanning logic**.

## Background

The design and ideas behind KOFENG were inspired by research and existing antivirus technologies, including:

* [Objective-See — Security Research](https://objective-see.org/blog/blog_0x22.html)
* [The Antivirus Hacker's Handbook](https://www.amazon.com/Antivirus-Hackers-Handbook-Joxean-Koret/dp/1119028752)
* **z0mbie / 29a** — author of several classic antivirus and unpacking tools, including the old-school AVP unpacker
* Historical antivirus engine techniques used by **Kaspersky**

KOFENG is an **independent implementation**. It does not contain Kaspersky source code or proprietary engine code.

## Why executable signatures?

Popular malware scanning solutions such as **ClamAV** and **YARA** provide highly capable signature engines and have proven that large-scale pattern matching can be practical.

However, traditional signature engines commonly rely on centralized pattern-matching structures such as **Aho–Corasick**. As the signature database grows, these structures can consume a significant amount of memory.

KOFENG experiments with a different model:

> **Each signature is compiled into its own code blob containing its own scanning logic.**

Instead of building one large global matching structure containing every signature, signatures can remain independent compilation units.

This allows KOFENG to explore different trade-offs between:

* Memory consumption
* Signature database size
* Scan time
* Signature complexity
* Pre-filtering
* Runtime execution cost

## Design

### Executable Signature Modules

The core idea is to represent each malware signature as an **executable module** containing its own scanning logic.

The build compiles the signature to an object file, links it with a linker script that places the entry point at offset zero, and emits the result as a raw binary. It then verifies on the linked image that there are no relocations, no undefined symbols, no unexpected sections and no `.data` or `.bss`. A module that fails any of those checks does not become a signature.

Those constraints are what make the runtime cheap: with the entry point at offset zero the loader needs no symbol table, with no relocations there is nothing to resolve when a database is loaded, and with no writable data one mapped copy serves every thread.

The architecture is inspired by techniques historically used in older antivirus engines, including Kaspersky's engine designs.

KOFENG is an independent implementation of this concept and does not attempt to reproduce the original Kaspersky engine.

Each signature can contain its own:

* Detection logic
* Static data
* String definitions
* Pre-filtering logic
* Match conditions

This makes a signature more similar to a small scanning module than a simple entry in a centralized pattern database.

### String Definitions

KOFENG also provides a string-definition mechanism inspired by features found in **YARA** and **ClamAV**.

A signature can define strings that are used as cheap pre-filters before executing more expensive detection logic.

The current design explores several matching attributes:

* **Fullword matching**

  * Match only when the string appears as a complete word.
* **Non-fullword matching**

  * Allow the string to match as part of a larger sequence.
* **Exact / case-sensitive matching**

  * The string must match with the same character casing.
* **Case-insensitive matching**

  * Character casing is ignored during matching.

For example, a signature could conceptually define:

```text
STRING malware_marker {
    value      = "CreateRemoteThread"
    fullword   = true
    ignorecase = true
}
```

The string definitions can then be used to perform inexpensive filtering before invoking the module's full detection logic.

This allows a signature to use a combination of:

```text
String pre-filter
        ↓
Additional conditions
        ↓
Module detection logic
        ↓
Match / No Match
```

The goal is to avoid executing every signature's full detection logic against every input when a cheap string check can eliminate most candidates first.

## Architecture Goals

KOFENG is primarily experimenting with **how the cost of a malware signature database scales**.

The main goals are:

### 1. Predictable Memory Usage

Avoid requiring a single large global matching structure containing the entire signature database.

Signatures remain independent, allowing the engine to load and process them in smaller units.

### 2. Signature-Level Logic

A signature is not limited to a static byte sequence.

Because the signature is executable code, it can implement detection logic that a static pattern cannot express — following a header, resolving an offset out of the file, walking a structure.

### 3. Cheap Pre-Filtering

String definitions can be used to quickly eliminate signatures that are unlikely to match before executing their complete detection logic.

### 4. Database Modularity

The database can be split into independent signature objects rather than requiring one monolithic matching structure.

This also makes it possible to experiment with different loading strategies and memory limits.

## What is in the engine

The signature format above is the oldest part of the project and no longer the
largest. A scanner that only matched patterns against whole files would find
almost nothing: the interesting bytes are usually inside something - an archive,
a compressed stream, a packed executable - and getting to them is most of the
work. Roughly 58 000 lines of C, none of it depending on anything but a C11
compiler.

### Collectors

One per format, and they **read structure and change nothing**: ELF, PE, gzip,
zip, tar, 7z, RAR, XZ, OLE compound files, RTF, PDF. A collector never fails.
On hostile or truncated input it reports what it recovered plus a bitmask of
what was wrong with the header, because "this file is broken, and here is how"
is a fact worth having rather than a reason to stop - the heuristic scores those
bits, and so does the decision about whether to run the file.

Each format also partitions the object into named regions - for ELF: headers,
code, data, non-loaded, unclaimed - so a rule can say *where* to look. Every
byte belongs to exactly one region, which is what makes searching a union of
them cost one pass.

### Decoders

Written rather than linked: DEFLATE, LZMA, LZMA2, the BCJ and BCJ2 branch
filters, NRV2B/D/E, RAR3 including its PPMd model, RAR5, and the OVBA
compression used by Office macros. They live in the host rather than in the
signature modules because one implementation shared by every caller is one
place for a bug to be, and because a module is a freestanding blob with no
writable state - which is not where a decompressor belongs.

The inflate implementation is checked against zlib on random and hostile inputs
in the test suite rather than trusted.

### Unpackers

Modules like any other signature, declaring what they recognise: UPX for ELF and
PE, Ezuri, and the container readers. What comes out is handed back to the
scanner as a child object and scanned like a file, so a payload's own format is
parsed, its regions partitioned, and its children unpacked in turn.

Two of them rebuild rather than extract. A packer hands back an IMAGE - sections
at their virtual addresses, no file header - and an image is not a file: it
identifies as nothing, gets no regions, and no rule scoped to code or data can
run on it. `pe_rebuild.c` and `elf_rebuild.c` put the file back together.

### Heuristic

Scores what the parse and the unpackers already produced - structural anomalies,
whether a packer opened the object, whether it opened only part of it - and
reports a level of its own, never a family name. It costs no extra pass, which
is why it is on by default.

What it is NOT is a second opinion about content. Every scoring approach that
tried to be one was measured and dropped; the ceiling for this evidence was 7 %
of malware at zero false positives, and a number that small is worth reporting
honestly rather than inflating.

### Emulator

`libkofemu` is an x86-64 interpreter, used for one thing: **running an object
that no unpacker could open, and keeping what it writes**. A packer nobody has
written a module for still has to unpack itself before it runs, and that is the
one thing it cannot avoid doing.

It is a memory dumper with a budget, not a sandbox. The design decisions worth
stating:

* **Nothing reaches the host.** The interpreter makes no system call, opens no
  file, starts no process or thread; a guest instruction is decoded and
  simulated, never executed. Every descriptor the guest opens refers to the
  buffer it was handed. Isolation is a property of interpretation rather than of
  a policy that could be wrong.
* **The boundary is the syscall, not the API.** A guest's calls into libc are
  just more instructions to interpret; only what it asks the kernel for has to
  be answered, and that is a small, stable surface.
* **The clock advances with instructions retired.** A run is reproducible, the
  ratio a timing check measures stays plausible, and a delay loop - the cheapest
  anti-emulation trick there is - is recognised and granted its wait in jumps
  instead of being sat through. A sleep is granted in full and waited for not at
  all: a sleep that took no time is a louder signal than a slow machine.
* **The payload is caught where it is finished**, at the `mprotect` that makes
  it executable, not at the end of the run - by then a program can have mapped
  something else over it.
* **Everything is bounded**: instructions, pages, live mappings, snapshots, and
  how many layers of packing deep it will go.

It runs only at `--heur 2`, because it is the one part of a scan that costs real
time. The gate that selects candidates - executable segments too dense to be
code, or a header that cannot be loaded as written - selects nothing across
1 246 clean binaries.

## Tools

| | |
|---|---|
| `kofscanner` | scan a file or a tree |
| `kofexamine` | what the engine sees in one object: regions, markers, what each module made of it |
| `kofviewer` | a terminal UI over the same facts, and where signatures are drafted |
| `ksigbuilder` | pack compiled modules into a database; `ksigcompiler.sh` compiles one |

## Building and testing

`make` needs a C11 compiler and nothing else. `make unit` runs 25 differential
and fuzzing tests; `make unit-asan` runs the same under AddressSanitizer and
UBSan, with the engine, the emulator and the vendored disassembler all
instrumented.

The tests are differential where they can be - inflate against zlib, the three
matcher entry points against each other - because a corpus run passes while the
code is still wrong on an input the corpus does not happen to contain.

## Third-party code

The only vendored dependency is **bddisasm 3.0.1** by Bitdefender, under the
**Apache License 2.0**, in `libkofemu/bddisasm/`. It is the instruction decoder
the emulator is built on. The files are unmodified; the licence text travels
with them and the exact subset taken is recorded beside it. See
[THIRD-PARTY.md](THIRD-PARTY.md).

Everything else is written for this project.


## Current Status

KOFENG is a **research / hobby project** and is still experimental.

The project is primarily intended to explore:

* Alternative antivirus engine architectures
* Memory characteristics of large signature databases
* Executable detection signatures as position-independent code blobs
* String-based pre-filtering
* Malware scanning performance and trade-offs
* Signature database scalability
* The practical capabilities of LLM-assisted development

The code that generates the signature blobs was developed with assistance from **Claude Code**.

This project is also used as an experiment in evaluating how effectively an LLM can assist with implementing a relatively specialized malware-detection architecture.

## Inspiration vs. Implementation

KOFENG combines ideas from several existing technologies and research projects.

In particular:

* **Kaspersky** — inspiration for the concept of using executable modules as signatures.
* **YARA** — inspiration for expressive string definitions and matching attributes such as fullword and case-insensitive matching.
* **ClamAV** — inspiration for practical antivirus signature matching and string-based pre-filtering.
* **Objective-See / The Antivirus Hacker's Handbook / historical AV research** — background and research material.

The implementation itself is independent and does not contain proprietary source code from these projects or vendors.

## Disclaimer

KOFENG is **not intended to replace production antivirus engines** such as ClamAV, commercial antivirus products, YARA, or other mature malware-detection frameworks.

It is a learning and research project. Performance, detection quality, portability, and security properties should not be assumed to be production-ready.

The primary goal is to explore how an alternative signature architecture behaves in practice, particularly when the signature database becomes large and memory consumption becomes an important constraint.

> **This is an experiment, not a production antivirus engine.**
