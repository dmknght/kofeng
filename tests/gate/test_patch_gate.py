#!/usr/bin/env python3
"""Self-test of tools/patch_gate.py: each kind of unrequested addition must produce its FAIL line, and an allowance in the
manifest must clear exactly that line. Fixtures are two tiny trees written under build/ (never /tmp).

    python3 tests/gate/test_patch_gate.py
"""
import os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GATE = os.path.join(ROOT, 'tools', 'patch_gate.py')

VIEW_BASE = r'''
#include "kv.h"
struct view { int n_obj; struct object *obj; };
static int show_row(struct out *o, struct view *v, int r)
{
	out_str(o, "Detection");
	sec_bar(o, v, r, " Matchers");
	hit_add(v, r, 0, 10, hit_row_none, 0);
	return r + 1;
}
int key_handler(struct view *v, int k)
{
	switch (k) {
	case K_UP: return 1;
	default: return 0;
	}
}
'''

ENGINE_H_BASE = '''
#ifndef KOFENG_H
#define KOFENG_H
struct kof_thing { int a; int b; };
int keng_open(void);
#endif
'''


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        f.write(text)


class Gate(unittest.TestCase):
    def setUp(self):
        os.makedirs(os.path.join(ROOT, 'build'), exist_ok=True)
        self.d = tempfile.mkdtemp(dir=os.path.join(ROOT, 'build'), prefix='kof_gate_')
        self.base, self.tree = os.path.join(self.d, 'base'), os.path.join(self.d, 'tree')
        for r in (self.base, self.tree):
            write(r, 'kofexamine/kv_view.c', VIEW_BASE)
            write(r, 'libkofeng/kofeng.h', ENGINE_H_BASE)
            write(r, 'libkofeng/kofeng.c', 'int keng_open(void) { return 0; }\n')
            write(r, 'tests/tui/t_x.py', '@case(A)\ndef old_case():\n    check(1)\n    check(2)\n')
        self.man = os.path.join(self.d, 'manifest.txt')
        write(self.d, 'manifest.txt', '')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_gate(self, manifest=''):
        write(self.d, 'manifest.txt', manifest)
        r = subprocess.run([sys.executable, '-B', GATE, self.base, self.tree, self.man], capture_output=True, text=True)
        return r.returncode, r.stdout

    def edit(self, rel, old, new):
        p = os.path.join(self.tree, rel)
        with open(p) as f:
            s = f.read()
        assert old in s, old
        with open(p, 'w') as f:
            f.write(s.replace(old, new, 1))

    def test_identical_trees_pass(self):
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn('RESULT: PASS', out)

    # (a) a copy of a viewer function that derives a verdict from the object list
    def test_a_function_that_derives_a_verdict_from_the_object_list(self):
        self.edit('kofexamine/kv_view.c', 'int key_handler', r'''static int child_with_verdict(const struct view *v)
{
	int k;
	for (k = 0; k < v->n_obj; k++)
		if (v->obj[k].heur.has_verdict)
			return k;
	return -1;
}
int key_handler''')
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: function child_with_verdict', out)
        self.assertIn('UNREQUESTED: derive child_with_verdict [verdict-from-objects]', out)
        rc, out = self.run_gate('allow function child_with_verdict\nallow derive child_with_verdict\n')
        self.assertEqual(rc, 0, out)

    # (b) a new menu item
    def test_b_new_menu_item(self):
        for r in (self.base, self.tree):
            write(r, 'kofexamine/kv_bar.c', 'static const struct { const char *label; int menu; } bar_item[2] = {\n\t{ "Next File", 0 },\n\t{ "Quit", 0 },\n};\n')
        write(self.tree, 'kofexamine/kv_bar.c', 'static const struct { const char *label; int menu; } bar_item[3] = {\n\t{ "Next File", 0 },\n\t{ "Statistics", 0 },\n\t{ "Quit", 0 },\n};\n')
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: ui-menu Statistics', out)
        rc, out = self.run_gate('allow ui "Statistics"\n')
        self.assertEqual(rc, 0, out)

    # (c) a new section title
    def test_c_new_section_title(self):
        self.edit('kofexamine/kv_view.c', 'sec_bar(o, v, r, " Matchers");', 'sec_bar(o, v, r, " Matchers");\n\tsec_bar(o, v, r + 1, " Conditions (on hold)");')
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: ui-section  Conditions (on hold)', out)
        rc, out = self.run_gate('allow ui "Conditions (on hold)"\n')
        self.assertEqual(rc, 0, out)

    # (d) a new exported function, and the declaration of it
    def test_d_new_exported_function(self):
        self.edit('libkofeng/kofeng.h', 'int keng_open(void);', 'int keng_open(void);\nint keng_extra(int x);')
        self.edit('libkofeng/kofeng.c', 'int keng_open(void) { return 0; }', 'int keng_open(void) { return 0; }\nint keng_extra(int x) { return x; }')
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: api keng_extra', out)
        rc, out = self.run_gate('allow api keng_extra\n')
        self.assertEqual(rc, 0, out)

    # a member added to an existing public struct
    def test_d2_new_struct_member(self):
        self.edit('libkofeng/kofeng.h', 'int b;', 'int b; int c;')
        rc, out = self.run_gate()
        self.assertIn('UNREQUESTED: api-member kof_thing.c', out)
        self.assertEqual(rc, 1)

    # (e) a changed status-bar string: the old one is reported as removed, the new one is unrequested
    def test_e_changed_status_bar_string(self):
        self.edit('kofexamine/kv_view.c', 'out_str(o, "Detection");', 'out_str(o, "Detection  (no verdict in file)");')
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: ui-text Detection  (no verdict in file)', out)
        self.assertIn('- ui-text', out)
        rc, out = self.run_gate('allow ui "no verdict in file"\n')
        self.assertEqual(rc, 0, out)

    def test_new_key_binding_and_hit_zone(self):
        self.edit('kofexamine/kv_view.c', 'case K_UP: return 1;', 'case K_UP: return 1;\n\tcase K_F5: return 2;')
        self.edit('kofexamine/kv_view.c', 'hit_add(v, r, 0, 10, hit_row_none, 0);', 'hit_add(v, r, 0, 10, hit_row_none, 0);\n\thit_add(v, r, 11, 20, hit_new_zone, 0);')
        rc, out = self.run_gate()
        self.assertIn('UNREQUESTED: key K_F5', out)
        self.assertIn('UNREQUESTED: ui-hit hit_new_zone', out)
        rc, out = self.run_gate('allow key K_F5\nallow hit hit_new_zone\n')
        self.assertEqual(rc, 0, out)

    def test_tool_including_an_engine_internal_header(self):
        self.edit('kofexamine/kv_view.c', '#include "kv.h"', '#include "kv.h"\n#include <scanners/scan_state.h>')
        rc, out = self.run_gate()
        self.assertIn('UNREQUESTED: include-internal scanners/scan_state.h', out)
        self.assertEqual(rc, 1)

    def test_removed_test_and_new_file_and_golden(self):
        write(self.tree, 'tests/tui/t_x.py', '@case(A)\ndef other_case():\n    check(1)\n')
        write(self.tree, 'tests/unit/new_probe.c', 'int main(void) { return 0; }\n')
        write(self.tree, 'tests/tui/golden/screen_a.txt', 'x\n')
        rc, out = self.run_gate()
        self.assertIn('UNREQUESTED: removed-test old_case', out)
        self.assertIn('UNREQUESTED: file tests/unit/new_probe.c', out)
        self.assertIn('UNREQUESTED: golden screen_a new', out)
        self.assertIn('assertions in touched test files 2 -> 1', out)
        rc, out = self.run_gate('allow remove-test old_case\nallow file tests/unit/*\nallow golden screen_a\n')
        self.assertEqual(rc, 0, out)

    def test_golden_change_needs_its_name(self):
        write(self.base, 'tests/tui/golden/screen_a.txt', 'x\n')
        write(self.tree, 'tests/tui/golden/screen_a.txt', 'y\n')
        rc, out = self.run_gate()
        self.assertIn('UNREQUESTED: golden screen_a changed', out)
        rc, out = self.run_gate('allow golden screen_a\n')
        self.assertEqual(rc, 0, out)

    def test_a_moved_function_is_not_an_addition(self):
        self.edit('kofexamine/kv_view.c', 'int key_handler', 'static int helper(int x) { return x; }\nint key_handler')
        for r in (self.base,):
            write(r, 'kofexamine/kv_other.c', 'static int helper(int x) { return x; }\n')
        rc, out = self.run_gate()
        self.assertNotIn('function helper', out.split('RESULT')[0].split('\n\n')[-1], out)

    def test_an_allowance_of_everything_is_refused_and_unused_is_reported(self):
        r = subprocess.run([sys.executable, '-B', GATE, self.base, self.tree, self._manifest('allow function *\n')], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        rc, out = self.run_gate('allow function nothing_like_it\n')
        self.assertIn('UNUSED: allow function nothing_like_it', out)

    # a plain added function, nothing else about it is special
    def test_f_plain_added_function_and_the_allowance_clears_only_it(self):
        self.edit('kofexamine/kv_view.c', 'int key_handler', 'static int extra_logic(int x) { return x * 2; }\nint key_handler')
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: function extra_logic', out)
        rc, out = self.run_gate('allow function other_name\n')
        self.assertEqual(rc, 1, out)
        rc, out = self.run_gate('allow function extra_*\n')
        self.assertEqual(rc, 0, out)

    # the file list: a file nobody listed, a listed file nobody touched
    def test_file_list_touched_file_not_in_manifest(self):
        self.edit('kofexamine/kv_view.c', 'return r + 1;', 'return r + 2;')
        write(self.tree, 'kofscanner/side.c', '/* a stray edit */\n')
        rc, out = self.run_gate('allow touch kofexamine/kv_view.c\n')
        self.assertEqual(rc, 1, out)
        self.assertIn('UNREQUESTED: touched-file kofscanner/side.c', out)
        self.assertNotIn('touched-file kofexamine/kv_view.c', out)
        rc, out = self.run_gate('allow touch kofexamine/kv_view.c\nallow touch kofscanner/side.c\nallow file kofscanner/side.c\n')
        self.assertEqual(rc, 0, out)

    def test_file_list_manifest_names_a_file_the_patch_does_not_touch(self):
        self.edit('kofexamine/kv_view.c', 'return r + 1;', 'return r + 2;')
        rc, out = self.run_gate('allow touch kofexamine/kv_view.c\nallow touch libkofeng/kofeng.c\n')
        self.assertEqual(rc, 1, out)
        self.assertIn('FILELIST: manifest names libkofeng/kofeng.c', out)

    def test_file_list_off_without_touch_lines_and_removed_file_counts(self):
        self.edit('kofexamine/kv_view.c', 'return r + 1;', 'return r + 2;')
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        os.remove(os.path.join(self.tree, 'libkofeng/kofeng.c'))
        rc, out = self.run_gate('allow touch kofexamine/kv_view.c\n')
        self.assertIn('UNREQUESTED: touched-file libkofeng/kofeng.c', out)
        self.assertIn('UNREQUESTED: removed-file libkofeng/kofeng.c', out)

    def test_patch_list_must_equal_the_files_that_differ(self):
        self.edit('kofexamine/kv_view.c', 'return r + 1;', 'return r + 2;')
        man = 'allow touch kofexamine/kv_view.c\n'
        good = subprocess.run(['diff', '-ruN', 'base', 'tree'], cwd=self.d, capture_output=True, text=True).stdout
        write(self.d, 'good.patch', good)
        write(self.d, 'manifest.txt', man)

        def gate(patch):
            r = subprocess.run([sys.executable, '-B', GATE, self.base, self.tree, self.man, '--patch', os.path.join(self.d, patch)],
                               capture_output=True, text=True)
            return r.returncode, r.stdout
        rc, out = gate('good.patch')
        self.assertEqual(rc, 0, out)
        # a patch cut with one file more (it differs nowhere), and one with a file missing
        write(self.d, 'more.patch', good + 'diff -ruN base/libkofeng/kofeng.h tree/libkofeng/kofeng.h\n')
        rc, out = gate('more.patch')
        self.assertEqual(rc, 1, out)
        self.assertIn('PATCHLIST: libkofeng/kofeng.h is in the patch but base and tree do not differ there', out)
        write(self.d, 'less.patch', '')
        rc, out = gate('less.patch')
        self.assertEqual(rc, 1, out)
        self.assertIn('PATCHLIST: kofexamine/kv_view.c differs between base and tree but is not in the patch', out)

    def _manifest(self, text):
        write(self.d, 'manifest.txt', text)
        return self.man


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    unittest.main(verbosity=2)
