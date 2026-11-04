/*
 * kx_graph_chain - the picture of a function made from REAL BYTES: a function whose control flow is that of attack_kill_all (the Mirai function the owner's picture is of: a jump
 * into a loop head B2, a conditional exit B1 and B3, a conditional call in B3) is assembled for x86-64 by the cfg kit, decoded by the lib's decoder, turned into the engine's graph
 * (kof_cfgview_build: blocks, edges with cond and loop, loop head, calls) and drawn by the viewer's kv_graph module. Held: the engine's edges equal the hand-built graph's (the
 * same cond and loop on every edge, F before T), and the picture is frozen. Nothing stored: the bytes are assembled at run time.
 */
#include "../lib/genome/cfg_kit.h"
#include "../../libkofeng/analyzers/cfgview.h"
#include "../../libkofeng/analyzers/genome_obj.h"
#include "../../kofexamine/kofview.h"
#include "../../kofexamine/kv_graph.h"
#include "../../kofexamine/kv_graph_rank.c"
#include "../../kofexamine/kv_graph_route.c"
#include "../../kofexamine/kv_graph_paint.c"
#include "../../kofexamine/kv_graph.c"

#define BASE_OFF 0x40u

struct scene {
	uint8_t *obj;
	uint64_t n;
	struct kof_obj_ctx ctx;
	struct kgenome_elf_info ei;
	struct kgenome_func_set fs;
};

static const char *box_text(void *user, uint32_t node, uint32_t i)
{
	static char buf[64];

	return kgenome_gv_box_line((const struct kgenome_gv *)user, node, i, buf, sizeof buf);
}

#include "kx_graph_chain_gold.h"

int main(void)
{
	struct gspec g;
	struct prog p;
	struct blob x;
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;
	struct kv_graph_in in;
	struct kv_graph kg;
	struct kv_graph_edge *e;
	struct kv_graph_style st = kv_graph_style_default();
	uint32_t i, r;
	static const struct { uint32_t f, t; uint8_t cond, loop; } want[] = {
		{ 0, 2, 0, 0 }, { 1, 2, 2, 1 }, { 1, 4, 1, 0 }, { 2, 3, 2, 0 }, { 2, 1, 1, 0 }, { 3, 4, 2, 0 }, { 3, 2, 1, 1 } };

	memset(&g, 0, sizeof g);
	g.nb = 5;
	g.kind[0] = G_JUMP; g.t[0] = 2;
	g.kind[1] = G_COND; g.t[1] = 4;
	g.kind[2] = G_COND; g.t[2] = 1;
	g.kind[3] = G_COND; g.t[3] = 2; g.calls[3] = 1;
	g.kind[4] = G_EXIT;
	gspec_prog(&g, &p, NULL);
	CK(blob_make(&ISAS[0], &p, BASE_OFF, &x));
	memset(&s, 0, sizeof s);
	s.n = (uint64_t)BASE_OFF + x.len + 0x30u;
	s.obj = calloc((size_t)s.n, 1);
	memcpy(s.obj + BASE_OFF, x.b, x.len);
	s.ei.elf_data = 1;
	s.ctx.format = KOF_FMT_ELF;
	s.ctx.arch = (uint8_t)ISAS[0].arch;
	s.ctx.obj_size = s.n;
	s.ctx.file_header = &s.ei;
	s.fs.v = calloc(2, sizeof *s.fs.v);
	s.fs.v[0].off = BASE_OFF;
	s.fs.v[0].len = x.len;
	s.fs.n = 1;
	memset(&rq, 0, sizeof rq);
	rq.ctx = &s.ctx;
	rq.data = kof_buf_make(s.obj, s.n);
	rq.func_off = BASE_OFF;
	rq.func_len = x.len;
	rq.funcs = &s.fs;
	CK(kof_cfgview_build(&rq, &v) == 1 && v.gv.n_node == 5 && v.gv.n_edge == 7);
	for (i = 0; i < 7 && i < v.gv.n_edge; i++)
		CKM(v.gv.edge[i].from == want[i].f && v.gv.edge[i].to == want[i].t && v.gv.edge[i].cond == want[i].cond && v.gv.edge[i].loop == want[i].loop,
		    "edge %u is B%u -> B%u cond %u loop %u, want B%u -> B%u cond %u loop %u", i, v.gv.edge[i].from, v.gv.edge[i].to, v.gv.edge[i].cond, v.gv.edge[i].loop,
		    want[i].f, want[i].t, want[i].cond, want[i].loop);
	CK((v.gv.node[2].flags & KGENOME_GV_NF_LOOP_HEAD) && strstr(v.gv.node[2].line[0], "B2 @ ") != NULL);
	e = calloc(v.gv.n_edge, sizeof *e);
	for (i = 0; i < v.gv.n_edge; i++) {
		e[i].from = v.gv.edge[i].from;
		e[i].to = v.gv.edge[i].to;
		e[i].cond = v.gv.edge[i].cond;
		e[i].loop = v.gv.edge[i].loop;
	}
	memset(&in, 0, sizeof in);
	in.n_node = v.gv.n_node;
	in.n_edge = v.gv.n_edge;
	in.edge = e;
	in.text = box_text;
	in.user = &v.gv;
	CK(kv_graph_layout(&in, &kg) == KV_GS_OK && kg.n_box == 5 && kg.n_wire == 7);
	st.ascii = 1;
	{
		char row[2048], *pic = calloc(1, 16384);

		for (r = 0; r < kg.height; r++) {
			size_t n = kv_graph_window(&kg, r, 0, kg.width, &st, row, sizeof row);

			while (n && row[n - 1u] == ' ')
				n--;
			row[n] = 0;
			strcat(pic, row);
			strcat(pic, "\n");
		}
		CKM(!strcmp(pic, GOLD_KILL), "the picture of the function made from bytes changed:\n%s", pic);
		free(pic);
	}
	kv_graph_free(&kg);
	free(e);
	kof_cfgview_free(&v);
	free(s.obj);
	free(s.fs.v);
	blob_free(&x);
	prog_free(&p);
	if (fails) {
		printf("kx_graph_chain: %d failure(s)\n", fails);
		return 1;
	}
	printf("kx_graph_chain: ok\n");
	return 0;
}
