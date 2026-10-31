#!/usr/bin/env python3
"""
check_rules.py - the three rules of CLAUDE.md that a grep can check, as one program.

They were `grep` pipelines inside mk/checks.mk, which a make driving cmd.exe or
PowerShell cannot run: no grep, no backticks, no `if [ ... ]; fi`. A program runs the
same on every host, so the rule lives here and the Makefile only starts it.

  1. getenv() is not allowed in the engine (kofwatcher/kofmontrace is the one stated
     exception: it reproduces execvp's search). Lines that are comment continuations
     (` * ...`) are not code.
  2. Every module under bases/unp, bases/decomp and bases/decoders declares
     KOF_TARGET_CONTENT.
  3. The word "syndrome" names only the directory bases/syndromes (and the few
     spellings the allowlist below lists).
  4. A GENERATED source is what its generator makes of its pinned input
     (libgenome/celllysis/nucleo_index.c, nucleo_sysnames.c): a hand edit or a stale
     table is a build failure and not something only a test notices.

Usage: check_rules.py [root]   (default: the directory above tools/). Exit 1 on a violation.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ENGINE_DIRS = ["libkofeng", "libgenome", "libuncoat", "libkoforbit", "kofexamine",
               "kofscanner", "kofwatcher", "ksigbuilder"]
SYNDROME_DIRS = ENGINE_DIRS + ["tools", "mk", "tests", "bases", "docs", "CLAUDE.md"]
MODULE_DIRS = ["bases/unp", "bases/decomp", "bases/decoders"]

SYNDROME_ALLOW = re.compile(r"bases/syndromes|--syndromes|/syndromes|.syndromes.|"
                            r"Syndrome table|syndromes\.kdig|only place for the|"
                            # The button and the form titles of Manage > Syndromes: the owner asked for "Add Syndrome" (2026-10-28), "Edit Syndrome" is its other
                            # form; no other use of the singular.
                            r"(Add|Edit) Syndrome", re.I)


def walk(root, rels):
    """Files under each of `rels`, in sorted order, as (relative path, absolute path).
    A symlink met while recursing is skipped, as grep -r does."""
    for rel in rels:
        top = os.path.join(root, rel)
        if os.path.isfile(top):
            yield rel, top
            continue
        for d, dirs, files in os.walk(top):
            dirs[:] = sorted(x for x in dirs if not os.path.islink(os.path.join(d, x)))
            for f in sorted(files):
                p = os.path.join(d, f)
                if not os.path.islink(p):
                    yield os.path.relpath(p, root).replace(os.sep, "/"), p


def lines_of(path):
    """(number, text) of each line, or nothing for a binary or unreadable file."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return
    if b"\0" in data[:8192]:
        return
    for n, raw in enumerate(data.decode("utf-8", "replace").split("\n"), 1):
        yield n, raw.rstrip("\r")


def check_getenv(root):
    pat = re.compile(r"getenv *\(")
    bad = []
    for rel, p in walk(root, ENGINE_DIRS):
        if not rel.endswith((".c", ".h")):
            continue
        for n, t in lines_of(p):
            line = "%s:%d:%s" % (rel, n, t)
            if pat.search(t) and "kofwatcher/kofmontrace" not in line and \
               not re.match(r"^[^:]*:[0-9]*: *\*", line):
                bad.append(line)
    return bad, "getenv() is not allowed in the engine - see CLAUDE.md:", \
        "no getenv in the engine"


def check_content(root):
    bad = []
    for d in MODULE_DIRS:
        top = os.path.join(root, d)
        for f in sorted(os.listdir(top)) if os.path.isdir(top) else []:
            if f.endswith(".c"):
                with open(os.path.join(top, f), "rb") as fh:
                    if b"KOF_TARGET_CONTENT" not in fh.read():
                        bad.append("%s/%s" % (d, f))
    return bad, "a module must declare what it takes out (KOF_TARGET_CONTENT) - see CLAUDE.md:", \
        "every unpack and unwrap module declares its content"


def check_syndrome(root):
    bad = []
    for rel, p in walk(root, SYNDROME_DIRS):
        for n, t in lines_of(p):
            if "syndrome" not in t.lower():
                continue
            line = "%s:%d:%s" % (rel, n, t)
            if line.startswith(("bases/syndromes/", "mk/checks.mk", "tools/check_rules.py")):
                continue
            if SYNDROME_ALLOW.search(line):
                continue
            bad.append(line)
    return bad, "the word syndrome is allowed only as the directory bases/syndromes - see CLAUDE.md:", \
        "the word syndrome only names bases/syndromes"


# (generated file, generator, its arguments after the output path); paths are relative to the root.
GENERATED = [
    ("libgenome/celllysis/nucleo_index.c", "tools/gen_nucleo_index.py", ["libgenome/celllysis"]),
    ("libgenome/celllysis/nucleo_sysnames.c", "tools/gen_sysnames.py",
     ["tools/sysnames_x86_64.txt", "tools/sysnames_i386.txt"]),
]


def check_generated(root):
    bad = []
    scratch = os.path.join(root, "build")
    os.makedirs(scratch, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="check_gen_", dir=scratch)
    try:
        for out, gen, args in GENERATED:
            made = os.path.join(tmp, os.path.basename(out))
            r = subprocess.run([sys.executable, os.path.join(root, gen), made] + [os.path.join(root, a) for a in args],
                               capture_output=True, text=True)
            if r.returncode != 0:
                bad.append("%s: the generator failed: %s" % (gen, r.stderr.strip().splitlines()[-1:] or r.returncode))
                continue
            with open(made, "rb") as a, open(os.path.join(root, out), "rb") as b:
                if a.read() != b.read():
                    bad.append("%s is not what %s makes of its input" % (out, gen))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return bad, "a generated source differs from its generator's output (regenerate it, never edit it):", \
        "generated sources are what their generators make"


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    for check in (check_getenv, check_content, check_syndrome, check_generated):
        bad, why, ok = check(root)
        if bad:
            print(why)
            print("\n".join(bad))
            return 1
        print("check-rules: " + ok)
    return 0


if __name__ == "__main__":
    sys.exit(main())
