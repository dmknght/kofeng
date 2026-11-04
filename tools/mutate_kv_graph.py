#!/usr/bin/env python3
"""Mutation test of the graph drawing (kofexamine/kv_graph.c and its parts kv_graph_rank.c, kv_graph_route.c, kv_graph_paint.c): each mutant changes one decision of the layout (rank,
order, placement, routing, labels, caps, side of the lanes, kinds, arrowheads, glyphs) in a copy of the part that holds it, builds tests/unit/kx_graph.c against the copy (the
KV_GRAPH_SRC* macro of that part) and must turn it red. A mutant that survives is a missing assertion.

Usage: tools/mutate_kv_graph.py [scratch-dir]      (run from the tree root; scratch defaults to build/mutate_kv_graph; nothing outside it is written)
A developer's tool, not part of a build: it needs a C compiler and runs one build of the test per mutant (a second each).
"""
import os
import subprocess
import sys

# the parts of the drawing and the macro of tests/unit/kx_graph.c that names each
PARTS = [('kofexamine/kv_graph.c', 'KV_GRAPH_SRC'), ('kofexamine/kv_graph_rank.c', 'KV_GRAPH_SRC_RANK'),
         ('kofexamine/kv_graph_route.c', 'KV_GRAPH_SRC_ROUTE'), ('kofexamine/kv_graph_paint.c', 'KV_GRAPH_SRC_PAINT')]
TEST = 'tests/unit/kx_graph.c'

MUTANTS = [
    ('rank: a forward edge spans two ranks', 'wk->lvl[s] = wk->lvl[u] + 1u;', 'wk->lvl[s] = wk->lvl[u] + 2u;', 1),
    ('order: the barycenter sweeps do nothing', 'static void order_rank(struct kv_graph_lay *L, uint32_t l, int down)\n{', 'static void order_rank(struct kv_graph_lay *L, uint32_t l, int down)\n{\n\treturn;', 1),
    ('order: the first order of a rank is the walk reversed', 'L->key[i] = i * 4u + 2u;', 'L->key[i] = (P - i) * 4u + 2u;', 1),
    ('placement: no spine weight', '#define W_SPINE 32', '#define W_SPINE 1', 1),
    ('placement: a box does not stand over its first child', '#define W_FIRST 32', '#define W_FIRST 1', 1),
    ('placement: boxes are packed with no gap', '#define GAP_BOX 3', '#define GAP_BOX 0', 1),
    ('routing: two runs may share a track and a stretch', 'L->hp[i0 + pick].lo <= L->hp[i0 + b].hi + 1;', 'L->hp[i0 + pick].lo <= L->hp[i0 + b].hi - 5;', 1),
    ('routing: a virtual node is as wide as a box', 'L->bw[P + D + q] = 1u;', 'L->bw[P + D + q] = 20u;', 1),
    ('labels: T and F swapped', "o->letter = w->cond == KV_GC_T ? 'T' : w->cond == KV_GC_F ? 'F' : 0;", "o->letter = w->cond == KV_GC_T ? 'F' : w->cond == KV_GC_F ? 'T' : 0;", 1),
    ('caps: the canvas is not checked', 'if (c.width > max_cols || c.height > max_rows ||', 'if (0 && c.width > max_cols || c.height > max_rows ||', 1),
    ('side: the lanes are on the right', 'L->wr[e].lane_col = c->M - 2 - 2 * (int32_t)L->wr[e].lane;', 'L->wr[e].lane_col = c->M + c->Wb + 1 + 2 * (int32_t)L->wr[e].lane;', 1),
    ('kinds: cond and loop swapped in the cell kind', 'const uint8_t k = (uint8_t)(1u + o->loop * 3u + o->cond);', 'const uint8_t k = (uint8_t)(1u + o->cond * 3u + o->loop);', 1),
    ('kinds: an edge the walk found going back is called a loop link', 'w->loop = KV_GL_RETREAT;        /* the walk', 'w->loop = KV_GL_LOOP;        /* the walk', 1),
    ('arrows: a back edge ends in `v`', "o->arrow = '^';", "o->arrow = 'v';", 2),
    ('glyphs: a loop link is drawn solid', 'return ascii ? ":" : "\\xe2\\x94\\x86";', 'return ascii ? "|" : "\\xe2\\x94\\x82";', 1),
    ('hook: a self-loop is not a hook', 'w->self = w->from == w->to;', 'w->self = 0;', 1),
    ('ports: an edge ignores where its other end is', 'while (k + 1 < nfree && fr[k] < L->port[a + (uint32_t)q].other)', 'while (k + 1 < nfree && fr[k] < -1)', 1),
]


def main():
    scratch = sys.argv[1] if len(sys.argv) > 1 else 'build/mutate_kv_graph'
    os.makedirs(scratch, exist_ok=True)
    srcs = [open(f).read() for f, _ in PARTS]
    bad = 0
    for i, (name, old, new, count) in enumerate(MUTANTS):
        found = [k for k, t in enumerate(srcs) if t.count(old)]
        total = sum(t.count(old) for t in srcs)
        if total != count or len(found) != 1:
            print('mutant %2d: the pattern occurs %d times in %d parts, expected %d in one: %s' % (i, total, len(found), count, name))
            bad += 1
            continue
        part = found[0]
        mut = os.path.join(scratch, 'm%02d_%s' % (i, os.path.basename(PARTS[part][0])))
        open(mut, 'w').write(srcs[part].replace(old, new))
        exe = os.path.join(scratch, 'm%02d' % i)
        cc = subprocess.run(['gcc', '-std=gnu11', '-O1', '-w', '-Ikofexamine', '-D%s="%s"' % (PARTS[part][1], os.path.abspath(mut)), TEST, '-Wl,--wrap=malloc', '-Wl,--wrap=calloc',
                             '-Wl,--wrap=free', '-o', exe], capture_output=True, text=True)
        if cc.returncode:
            print('mutant %2d: does not build (%s): %s' % (i, name, cc.stderr.strip().split('\n')[-1][:100]))
            bad += 1
            continue
        try:
            r = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            red = r.returncode != 0
            first = next((l.strip() for l in r.stdout.split('\n') if 'FAIL' in l), r.stderr.strip()[:80])
        except subprocess.TimeoutExpired:
            red, first = True, 'timeout (hung)'
        print('mutant %2d: %-8s %s%s' % (i, 'killed' if red else 'SURVIVED', name, ('   <- ' + first[:100]) if red else ''))
        bad += not red
        os.remove(exe)
    print('%d mutants, %d not killed' % (len(MUTANTS), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
