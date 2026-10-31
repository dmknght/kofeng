#!/usr/bin/env python3
"""Self-test of tools/merge_gate.sh: it REFUSES (exit 3, nothing else run, no viewer started) a change whose file list is not the
manifest's, and a manifest with no `allow touch` line. The all-clear path (golden screens and api surface) needs a built viewer
and is `make gate`; here only the refusals, which are decided before anything heavy is started.

    python3 tests/gate/test_merge_gate.py
"""
import os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SH = os.path.join(ROOT, 'tools', 'merge_gate.sh')


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        f.write(text)


class Merge(unittest.TestCase):
    def setUp(self):
        os.makedirs(os.path.join(ROOT, 'build'), exist_ok=True)
        self.d = tempfile.mkdtemp(dir=os.path.join(ROOT, 'build'), prefix='kof_mgate_')
        self.base, self.tree = os.path.join(self.d, 'base'), os.path.join(self.d, 'tree')
        for r in (self.base, self.tree):
            write(r, 'kofexamine/kv_view.c', 'int f(void) { return 1; }\n')
            write(r, 'tools/patch_gate.py', open(os.path.join(ROOT, 'tools', 'patch_gate.py')).read())
        write(self.tree, 'kofexamine/kv_view.c', 'int f(void) { return 2; }\n')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def gate(self, manifest, patch=None):
        write(self.d, 'm.txt', manifest)
        cmd = ['sh', SH, self.base, self.tree, os.path.join(self.d, 'm.txt')] + ([patch] if patch else [])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr

    def test_manifest_without_touch_is_refused(self):
        rc, out = self.gate('allow function f\n')
        self.assertEqual(rc, 3, out)
        self.assertIn('REFUSED', out)
        self.assertNotIn('golden screens', out)

    def test_a_file_the_manifest_does_not_name_is_refused(self):
        write(self.tree, 'kofscanner/stray.c', 'int s;\n')
        rc, out = self.gate('allow touch kofexamine/kv_view.c\nallow file nothing/*\n')
        self.assertEqual(rc, 3, out)
        self.assertIn('touched-file kofscanner/stray.c', out)
        self.assertIn('REFUSED', out)
        self.assertNotIn('golden screens', out)

    def test_a_manifest_file_the_patch_does_not_touch_is_refused(self):
        rc, out = self.gate('allow touch kofexamine/kv_view.c\nallow touch kofexamine/never.c\n')
        self.assertEqual(rc, 3, out)
        self.assertIn('FILELIST: manifest names kofexamine/never.c', out)

    def test_a_patch_with_another_file_list_is_refused(self):
        write(self.d, 'p.patch', 'diff -ruN base/kofscanner/other.c tree/kofscanner/other.c\n')
        rc, out = self.gate('allow touch kofexamine/kv_view.c\n', os.path.join(self.d, 'p.patch'))
        self.assertEqual(rc, 3, out)
        self.assertIn('PATCHLIST', out)

    def test_files_agree_goes_on_to_the_next_step(self):
        # the file list is right, so the gate proceeds to the golden step; with no built viewer in this fixture that step says so
        rc, out = self.gate('allow touch kofexamine/kv_view.c\nallow function f\n')
        self.assertNotEqual(rc, 3, out)
        self.assertIn('=== 2. golden screens ===', out)
        self.assertIn('no viewer at', out)
        self.assertIn('MERGE GATE: FAIL', out)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    unittest.main(verbosity=2)
