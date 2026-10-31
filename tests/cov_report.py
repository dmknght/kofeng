#!/usr/bin/env python3
"""cov_report.py - line AND branch coverage per function from gcov's JSON, for `make cov-report` (mk/tests_cov.mk).

usage: cov_report.py <dir of the .gcda/.gcno objects> <source file>... [--uncovered] [--json out.json]

One row per function of each named source file: lines executed / lines, branches taken at least once / branches. A branch is a gcov branch of a
line (both arms of an `if`, each case of a `switch`, each operand of `&&`); it counts as taken when its counter is not zero. `--uncovered`
lists, under every function that has one, the line numbers whose branches are not all taken (the work list: a test, or a proof the arm is
dead or defensive). `--json` writes the per-function figures so a before/after table can be built by diffing two runs.
Run with -I (nothing in the build directory is imported).
"""
import glob, gzip, json, os, subprocess, sys, tempfile


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    out_json = None
    if "--json" in argv:
        i = argv.index("--json")
        out_json = argv[i + 1]
        args = [a for a in args if a != out_json]
    objdir, srcs = os.path.abspath(args[0]), args[1:]
    show_unc = "--uncovered" in flags
    rows = []
    with tempfile.TemporaryDirectory(dir=os.path.dirname(os.path.abspath(objdir))) as tmp:
        for src in srcs:
            stem = os.path.splitext(os.path.relpath(src, "libkofeng"))[0]
            gcda = os.path.join(objdir, stem + ".gcda")
            if not os.path.exists(gcda):
                rows.append((src, "(never executed: no counters)", 0, 0, 0, 0, []))
                continue
            subprocess.run(["gcov", "--json-format", "-b", "-o", os.path.dirname(gcda), gcda], cwd=tmp,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            for jz in glob.glob(os.path.join(tmp, "*.gcov.json.gz")):
                with gzip.open(jz, "rt") as f:
                    doc = json.load(f)
                os.unlink(jz)
                for fil in doc["files"]:
                    if os.path.normpath(fil["file"]) != os.path.normpath(src):
                        continue
                    lines = {l["line_number"]: l for l in fil["lines"]}
                    for fn in fil["functions"]:
                        a, b = fn["start_line"], fn["end_line"]
                        ls = [l for n, l in lines.items() if a <= n <= b]
                        nl = len(ls)
                        el = sum(1 for l in ls if l["count"] > 0)
                        nb = sum(len(l["branches"]) for l in ls)
                        eb = sum(1 for l in ls for br in l["branches"] if br["count"] > 0)
                        unc = [l["line_number"] for l in ls if any(br["count"] == 0 for br in l["branches"])]
                        unl = [l["line_number"] for l in ls if l["count"] == 0]
                        rows.append((src, fn["demangled_name"], el, nl, eb, nb, sorted(unc), sorted(unl)))
    print("%-44s %-34s %9s %9s" % ("file", "function", "line %", "branch %"))
    tot = [0, 0, 0, 0]
    per_file = {}
    out = []
    for r in rows:
        src, name, el, nl, eb, nb = r[:6]
        unc = r[6] if len(r) > 6 else []
        unl = r[7] if len(r) > 7 else []
        tot[0] += el; tot[1] += nl; tot[2] += eb; tot[3] += nb
        pf = per_file.setdefault(src, [0, 0, 0, 0])
        pf[0] += el; pf[1] += nl; pf[2] += eb; pf[3] += nb
        lp = 100.0 * el / nl if nl else 100.0
        bp = 100.0 * eb / nb if nb else 100.0
        print("%-44s %-34s %5.1f%%    %5.1f%%   (%d/%d lines, %d/%d branches)" % (src, name, lp, bp, el, nl, eb, nb))
        if show_unc and (unc or unl):
            if unl:
                print("      lines not executed: %s" % " ".join(map(str, unl)))
            if unc:
                print("      branches not all taken at lines: %s" % " ".join(map(str, unc)))
        out.append({"file": src, "function": name, "lines": [el, nl], "branches": [eb, nb], "uncovered_branch_lines": unc, "unexecuted_lines": unl})
    print()
    for src, v in per_file.items():
        print("%-44s %-34s %5.1f%%    %5.1f%%   (%d/%d lines, %d/%d branches)" % (
            src, "TOTAL", 100.0 * v[0] / v[1] if v[1] else 100.0, 100.0 * v[2] / v[3] if v[3] else 100.0, v[0], v[1], v[2], v[3]))
    print("%-44s %-34s %5.1f%%    %5.1f%%   (%d/%d lines, %d/%d branches)" % (
        "ALL", "TOTAL", 100.0 * tot[0] / tot[1] if tot[1] else 100.0, 100.0 * tot[2] / tot[3] if tot[3] else 100.0, tot[0], tot[1], tot[2], tot[3]))
    if out_json:
        with open(out_json, "w") as f:
            json.dump(out, f)
    return 0


sys.exit(main(sys.argv))
