#!/bin/sh
# merge_gate.sh BASE TREE MANIFEST [PATCH] - the three mechanical checks of a merge, one verdict.
#
#   1. tools/patch_gate.py   what the change adds or removes (functions, api, ui, keys, trace, files, removed tests),
#                            every item the MANIFEST does not allow is UNREQUESTED
#   2. tests/tui/t_golden.py golden screens of the real viewer built from TREE: any difference from tests/tui/golden fails
#   3. tools/api_surface.py  the frozen export list of libkofeng.a / libkgenome.a / libkuncoat.a and the public headers
#
# BASE is the untouched copy of the main tree the agent started from (`base/`), TREE the tree with the change, MANIFEST the
# file the author wrote from the task as the owner worded it (see the header of tools/patch_gate.py). TREE must be built:
#   make -j2 kofviewer databases && make build/temp/libkgenome.a build/temp/libkuncoat.a
# The golden screens start the viewer: they run under ulimit -v 4194304 and timeout -s KILL, as every process of this tree does.
# Before anything is run, the FILE LIST is checked (tools/patch_gate.py, THE FILE LIST): the manifest must carry `allow touch` lines,
# every file that differs between BASE and TREE must be named by the manifest, every `touch` line must match a file that differs,
# and with PATCH (the `diff -ruN base tree` that is being delivered) the files the patch names must be exactly the files that
# differ. Any mismatch is REFUSED (exit 3) and the viewer is never started.
# Exit 0 only when all three pass. Nothing here writes into BASE or TREE.
BASE=$1; TREE=$2; MAN=$3; PATCH=$4
[ -d "$BASE" ] && [ -d "$TREE" ] && [ -f "$MAN" ] || { echo "usage: merge_gate.sh BASE TREE MANIFEST [PATCH]" >&2; exit 2; }
[ -z "$PATCH" ] || [ -f "$PATCH" ] || { echo "merge_gate: no patch file $PATCH" >&2; exit 2; }
BASE=$(cd "$BASE" && pwd); TREE=$(cd "$TREE" && pwd); MAN=$(cd "$(dirname "$MAN")" && pwd)/$(basename "$MAN")
[ -z "$PATCH" ] || PATCH=$(cd "$(dirname "$PATCH")" && pwd)/$(basename "$PATCH")
PY=${PYTHON:-python3}
rc=0; r1=0; r2=0; r3=0
grep -q '^allow touch ' "$MAN" || { echo "REFUSED: the manifest has no 'allow touch <file>' line: the file list is part of the gate" >&2; exit 3; }

echo "=== 1. patch_gate ==="
PGOUT=$TREE/build/patch_gate.out
mkdir -p "$TREE/build"
$PY -B "$TREE/tools/patch_gate.py" "$BASE" "$TREE" "$MAN" ${PATCH:+--patch "$PATCH"} > "$PGOUT" 2>&1 || r1=$?
cat "$PGOUT"
if grep -q '^\(FILELIST\|PATCHLIST\|UNREQUESTED: touched-file\)' "$PGOUT"; then
	echo
	echo "REFUSED: the files of the patch are not the files the manifest names (exit 3); nothing else was run"
	exit 3
fi

echo
echo "=== 2. golden screens ==="
VIEWER=$TREE/build/release/bin/kofviewer
if [ ! -x "$VIEWER" ]; then
	echo "no viewer at $VIEWER (make -j2 kofviewer databases)"; r2=2
else
	( ulimit -v 4194304; cd "$TREE/tests/tui" && KOF_REPO=$TREE KOFVIEWER=$VIEWER timeout -s KILL 900 $PY -B run_all.py -j 2 golden ) > "$TREE/build/golden.out" 2>&1 || r2=$?
	# one page: the first three diffs whole, the rest as a list of names (the full output stays in build/golden.out)
	$PY -B - "$TREE/build/golden.out" <<'PYEOF'
import re, sys
t = open(sys.argv[1]).read()
fails = re.findall(r'^(?:FAIL|ERROR)\s+golden\s+golden_(\S+)', t, re.M)
npass = len(re.findall(r'^PASS', t, re.M))
seen = {}
for b in re.finditer(r'--- DIFF (\S+) .*?--- END DIFF', t, re.S):
    sig = tuple(l[1:] for l in b.group(0).split('\n') if l and l[:1] in '+-' and l[:3] not in ('+++', '---') and not l.startswith('--- '))
    seen.setdefault(sig, []).append(b)
for sig, bl in list(seen.items())[:3]:
    print(bl[0].group(0))
    if len(bl) > 1:
        print('(the same change in %d screens)' % len(bl))
if len(seen) > 3:
    print('... %d more distinct diffs in build/golden.out' % (len(seen) - 3))
if fails:
    print('golden: %d screen(s) differ (%d identical): %s' % (len(fails), npass, ', '.join(fails)))
else:
    print('golden: %d screens identical' % npass)
PYEOF
	[ $r2 -eq 0 ] || tail -3 "$TREE/build/golden.out" | cut -c1-200
fi

echo
echo "=== 3. api surface ==="
$PY -B "$TREE/tools/api_surface.py" check "$BASE" "$TREE" "$MAN" || r3=$?

echo
[ $r1 -eq 0 ] && [ $r2 -eq 0 ] && [ $r3 -eq 0 ] || rc=1
echo "MERGE GATE: $([ $rc -eq 0 ] && echo PASS || echo FAIL)  (patch_gate rc=$r1, golden rc=$r2, api_surface rc=$r3)"
exit $rc
