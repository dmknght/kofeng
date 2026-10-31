#!/usr/bin/env python3
"""Self-test of tools/api_surface.py on two tiny trees with real archives (cc + ar): a symbol or header name that appears or
goes must fail unless the manifest allows it, and a stale docs/api_surface.txt must fail. Written under build/, never /tmp.

    python3 tests/gate/test_api_surface.py
"""
import os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SURF = os.path.join(ROOT, 'tools', 'api_surface.py')

HDR = 'struct kof_thing { int a; int b; };\nint keng_open(void);\n'
SRC = '#include "kofeng.h"\nint keng_open(void) { return 0; }\n'


def put(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        f.write(text)


def build(root):
    """Compile libkofeng/kofeng.c into the three archives the check reads (the two small libs hold one object each)."""
    for lib, rel in (('libkofeng', 'build/release/lib/libkofeng.a'), ('libgenome', 'build/temp/libkgenome.a'),
                     ('libuncoat', 'build/temp/libkuncoat.a')):
        obj = os.path.join(root, 'build', lib + '.o')
        src = os.path.join(root, lib, 'x.c')
        put(root, lib + '/x.c', SRC if lib == 'libkofeng' else 'int %s_f(void) { return 1; }\n' % lib)
        os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
        if os.path.exists(os.path.join(root, rel)):
            os.remove(os.path.join(root, rel))
        subprocess.run(['cc', '-c', '-I', os.path.join(root, 'libkofeng'), src, '-o', obj], check=True)
        subprocess.run(['ar', 'rcs', os.path.join(root, rel), obj], check=True)


class Surface(unittest.TestCase):
    def setUp(self):
        os.makedirs(os.path.join(ROOT, 'build'), exist_ok=True)
        self.d = tempfile.mkdtemp(dir=os.path.join(ROOT, 'build'), prefix='kof_surf_')
        self.base, self.tree = os.path.join(self.d, 'base'), os.path.join(self.d, 'tree')
        for r in (self.base, self.tree):
            put(r, 'libkofeng/kofeng.h', HDR)
            build(r)
            put(r, 'docs/exports_kept.txt', 'nothing\n')
            self.assertEqual(subprocess.run([sys.executable, '-B', SURF, 'write', r], capture_output=True).returncode, 0)
        put(self.d, 'm.txt', '')
        self.man = os.path.join(self.d, 'm.txt')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def check(self, manifest=''):
        put(self.d, 'm.txt', manifest)
        r = subprocess.run([sys.executable, '-B', SURF, 'check', self.base, self.tree, self.man], capture_output=True, text=True)
        return r.returncode, r.stdout

    def regen(self):
        subprocess.run([sys.executable, '-B', SURF, 'write', self.tree], check=True, capture_output=True)

    def test_unchanged_passes(self):
        rc, out = self.check()
        self.assertEqual(rc, 0, out)

    def test_a_new_export_fails_until_allowed_and_the_doc_is_regenerated(self):
        with open(os.path.join(self.tree, 'libkofeng/x.c'), 'a') as f:
            f.write('int keng_extra(int x) { return x; }\n')
        with open(os.path.join(self.tree, 'libkofeng/kofeng.h'), 'a') as f:
            f.write('int keng_extra(int x);\n')
        build_tree = self.tree
        for lib, rel in (('libkofeng', 'build/release/lib/libkofeng.a'),):
            os.remove(os.path.join(build_tree, rel))
            obj = os.path.join(build_tree, 'build', 'x.o')
            subprocess.run(['cc', '-c', '-I', os.path.join(build_tree, 'libkofeng'), os.path.join(build_tree, 'libkofeng/x.c'), '-o', obj], check=True)
            subprocess.run(['ar', 'rcs', os.path.join(build_tree, rel), obj], check=True)
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: api-added libkofeng.a keng_extra', out)
        self.assertIn('UNREQUESTED: api-added header-func keng_extra', out)
        self.assertIn('STALE', out)
        self.regen()
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertNotIn('STALE', out)
        rc, out = self.check('allow api keng_extra\n')
        self.assertEqual(rc, 0, out)

    def test_a_new_struct_member_fails(self):
        p = os.path.join(self.tree, 'libkofeng/kofeng.h')
        with open(p) as f:
            s = f.read()
        with open(p, 'w') as f:
            f.write(s.replace('int b;', 'int b; int c;'))
        self.regen()
        rc, out = self.check()
        self.assertIn('UNREQUESTED: api-added header-member kof_thing.c', out)
        self.assertEqual(rc, 1)

    def test_a_removed_declaration_fails_until_allowed(self):
        p = os.path.join(self.tree, 'libkofeng/kofeng.h')
        with open(p) as f:
            s = f.read()
        with open(p, 'w') as f:
            f.write(s.replace('int keng_open(void);\n', ''))
        self.regen()
        rc, out = self.check()
        self.assertIn('UNREQUESTED: api-removed header-func keng_open', out)
        rc, out = self.check('allow remove-api keng_open\n')
        self.assertEqual(rc, 0, out)

    def test_a_stale_document_fails(self):
        p = os.path.join(self.tree, 'docs/api_surface.txt')
        with open(p) as f:
            s = f.read()
        with open(p, 'w') as f:
            f.write(s.replace('keng_open', 'keng_other', 1))
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn('STALE', out)

    def test_verify_alone_passes_when_current_and_fails_when_stale(self):
        def verify():
            r = subprocess.run([sys.executable, '-B', SURF, 'verify', self.tree], capture_output=True, text=True)
            return r.returncode, r.stdout
        rc, out = verify()
        self.assertEqual(rc, 0, out)
        p = os.path.join(self.tree, 'docs/api_surface.txt')
        with open(p, 'a') as f:
            f.write('keng_invented\n')
        rc, out = verify()
        self.assertEqual(rc, 1, out)
        self.assertIn('STALE', out)

    def test_unbuilt_archives_are_reported_not_passed(self):
        os.remove(os.path.join(self.tree, 'build/temp/libkuncoat.a'))
        rc, out = self.check()
        self.assertEqual(rc, 2, out)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    unittest.main(verbosity=2)
