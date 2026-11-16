/*
 * lineageview - kof_lineageview_build (analyzers/lineageview.c): one function's slice of an
 * object's whole value-flow graph (kof_result.lineage) as a generic graph (struct kgenome_gv).
 *
 * NEW CODE, NEW COVERAGE (owner, 2026-11-11: new features need test cases). What this pins:
 *
 *   EXTENT FILTER   a record is a node of the graph exactly when its `at` falls inside
 *                   [off, off+len); local indices are DENSE (no gaps) even when an excluded
 *                   record sits between two kept ones in the global array.
 *   EVERY KIND      every link is an edge, whatever its `how`: PROVEN, MAY, UNKNOWN and BROKEN
 *                   each carry their own `sure` (owner, 2026-11-14: the tab drew PROVEN only,
 *                   which was the viewer deciding what a reader may see).
 *   EVERY INPUT     a node's inputs are kof_result.lineage_in's (the request's lin_in), not its
 *                   four-input view in[]: a system call's NUMBER is only there (cleartext's
 *                   connect -> read at 0xf1 was not drawn). Without lin_in, the view, and the
 *                   head says so.
 *   ONE ROW A LINK  every input of a node inside is one row (gv.note): from, to, role, how,
 *                   kind in the engine's words; a row drawn as an edge names it (note.link,
 *                   right after the edges are sorted). A link whose producer is outside the
 *                   extent or the stack has no edge and still a row that says where it came
 *                   from - the cap bounding cost must never delete evidence (CLAUDE.md rule 4);
 *                   there is no aside list beside the rows.
 *   HOSTILE `from`   a `from` the upstream scan never produces (past n_lin, not the stack
 *                   sentinel) is read defensively: no edge, no crash, and a row that says so.
 *   HOSTILE RANGE   a record whose [in_first, in_first + n_all) is not inside lin_in is read
 *                   from its view, never past the array.
 *   NULL/EMPTY      out=NULL is refused without touching memory; a request with n_lin=0 (or
 *                   NULL) answers an empty, OK graph with a head line saying so.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/analyzers/lineageview.h"
#include <phenotype/diag_scan.h>
#include <phenotype/diag_vocab.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static struct kof_diag_lineage_rec rec(uint64_t at, uint16_t cap)
{
	struct kof_diag_lineage_rec r;

	memset(&r, 0, sizeof r);
	r.at = at;
	r.cap = cap;
	return r;
}

static void add_in(struct kof_diag_lineage_rec *r, uint16_t from, uint8_t how)
{
	r->in[r->n_in].from = from;
	r->in[r->n_in].role = KGENOME_DIAG_ROLE_BUFFER;
	r->in[r->n_in].how = how;
	r->in[r->n_in].kind = KGENOME_DIAG_KIND_PRODUCED;
	r->n_in++;
}

static void add_in_kind(struct kof_diag_lineage_rec *r, uint16_t from, uint8_t how, uint8_t kind)
{
	add_in(r, from, how);
	r->in[r->n_in - 1u].kind = kind;
}

/* The box's own extra lines of `node` (kgenome_gv_box_line's rows past the fixed two), joined with
 * '|' for an easy substring check - empty when the node has none. */
static void xtext(const struct kgenome_gv *gv, uint32_t node, char *out, size_t cap)
{
	char buf[KGENOME_GV_LINE];
	uint32_t i;
	size_t n = 0;

	out[0] = 0;
	for (i = 2; ; i++) {
		const char *s = kgenome_gv_box_line(gv, node, i, buf, sizeof buf);

		if (!s)
			break;
		if (n && n + 1u < cap)
			out[n++] = '|', out[n] = 0;
		n += (size_t)snprintf(out + n, n < cap ? cap - n : 0, "%s", s);
	}
}

static int32_t find_node(const struct kgenome_gv *gv, uint64_t at)
{
	uint32_t i;

	for (i = 0; i < gv->n_node; i++)
		if (gv->node[i].off == at)
			return (int32_t)i;
	return -1;
}

static int has_edge(const struct kgenome_gv *gv, uint32_t from, uint32_t to)
{
	uint32_t i;

	for (i = 0; i < gv->n_edge; i++)
		if (gv->edge[i].from == from && gv->edge[i].to == to)
			return 1;
	return 0;
}

int main(void)
{
	/* NULL out: refused, nothing touched. */
	CK(kof_lineageview_build(NULL, NULL) == KGENOME_BAD_INPUT);
	{
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		memset(&rq, 0, sizeof rq);
		CK(kof_lineageview_build(NULL, &gv) == KGENOME_BAD_INPUT);
		/* n_lin set but lin NULL: bad input, out zeroed rather than left stack garbage */
		rq.n_lin = 3;
		rq.lin = NULL;
		memset(&gv, 0xAA, sizeof gv);
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_BAD_INPUT);
		CK(gv.n_node == 0 && gv.n_edge == 0);
	}

	/* Empty request: an empty, OK graph with a head line. */
	{
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		memset(&rq, 0, sizeof rq);
		rq.off = 0;
		rq.len = 0x1000;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 0 && gv.n_edge == 0 && gv.n_aside == 0);
		CK(gv.n_head >= 1);
		kgenome_gv_free(&gv, NULL);
	}

	/* EXTENT FILTER + EVERY KIND: 4 records - [0] producer kept, [1] a decoy OUTSIDE the
	 * extent sitting between the two kept records in the array (so local indices must
	 * compact), [2] consumer kept with a MUST link from [0], [3] consumer kept with a MAY
	 * link from [0] (an edge too, drawn MAY). */
	{
		struct kof_diag_lineage_rec lin[4];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		int32_t n0, n2, n3;

		lin[0] = rec(0x100, 10);                                  /* kept: inside [0x100, 0x200) */
		lin[1] = rec(0x5000, 11);                                 /* decoy: outside the extent */
		lin[2] = rec(0x110, 12);
		add_in(&lin[2], 0, KGENOME_DIAG_LINK_PROVEN);              /* MUST, from a kept node */
		lin[3] = rec(0x120, 13);
		add_in(&lin[3], 0, KGENOME_DIAG_LINK_MAY);                 /* MAY: an edge of its own kind */

		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 4;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 3);         /* the decoy at 0x5000 is not a node at all */
		n0 = find_node(&gv, 0x100);
		n2 = find_node(&gv, 0x110);
		n3 = find_node(&gv, 0x120);
		CK(n0 >= 0 && n2 >= 0 && n3 >= 0);
		CK(find_node(&gv, 0x5000) < 0);
		CK(gv.n_edge == 2 && gv.n_note == 2);
		if (n0 >= 0 && n2 >= 0)
			CK(has_edge(&gv, (uint32_t)n0, (uint32_t)n2));
		if (n0 >= 0 && n3 >= 0)
			CK(has_edge(&gv, (uint32_t)n0, (uint32_t)n3));     /* the MAY link is drawn (base: it drew nothing) */
		CK(gv.n_edge == 2 && gv.edge[0].sure == KGENOME_GV_SURE && gv.edge[1].sure == KGENOME_GV_SURE_MAY);
		CK(gv.n_aside == 0);
		kgenome_gv_free(&gv, NULL);
	}

	/* NOT LOST: a MUST link whose producer is outside the extent is a row, not dropped, and
	 * the row names it; a second MUST link from the stack sentinel is its own row. Neither has
	 * an edge to light. */
	{
		struct kof_diag_lineage_rec lin[2];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		lin[0] = rec(0x5000, 20);                                 /* the producer, outside the extent */
		lin[1] = rec(0x110, 21);
		add_in(&lin[1], 0, KGENOME_DIAG_LINK_PROVEN);              /* MUST, but [0] is outside */
		add_in(&lin[1], KGENOME_DIAG_FROM_STACK, KGENOME_DIAG_LINK_PROVEN);

		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 2;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 1);                 /* only the consumer is inside the extent */
		CK(gv.n_edge == 0);                 /* neither input had a kept producer */
		CK(gv.n_note == 2 && gv.n_aside == 0);
		CK(gv.n_note == 2 && strstr(gv.note[0].text, "0x5000 (outside)") && gv.note[0].link == 0);
		CK(gv.n_note == 2 && strstr(gv.note[1].text, "the stack") && gv.note[1].link == 0);
		kgenome_gv_free(&gv, NULL);
	}

	/* HOSTILE `from`: a value the upstream scan never produces (past n_lin, and not the
	 * stack sentinel) is neither an edge nor a crash - read defensively, bounds-checked. */
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		lin[0] = rec(0x110, 30);
		add_in(&lin[0], 0xdeadu, KGENOME_DIAG_LINK_PROVEN);        /* no record 0xdead exists, not the stack sentinel either */

		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 1 && gv.n_edge == 0 && gv.n_aside == 0);   /* out of range: not drawn */
		CK(gv.n_note == 1 && strstr(gv.note[0].text, "none such") && !gv.note[0].link);    /* and said (base: dropped without a word) */
		kgenome_gv_free(&gv, NULL);
	}

	/* VAL: a node that wrote a constant shows it in its box, only when the bit says the field
	 * is valid - the owner's own "does action-write keep the value" question. attr==0: no
	 * struct-offset to name, just the constant. */
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[128];

		lin[0] = rec(0x110, 40);
		lin[0].bits |= KGENOME_DIAG_H_VAL;
		lin[0].val = 0;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 1 && gv.node[0].xtotal == 1);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "wrote = 0x0") != NULL);
		kgenome_gv_free(&gv, NULL);
	}

	/* VAL + ATTR: the struct offset goes with the constant ("wrote +0x4 = 0x0" - give_root's
	 * own shape: a uid field zeroed). */
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[128];

		lin[0] = rec(0x110, 40);
		lin[0].bits |= KGENOME_DIAG_H_VAL;
		lin[0].attr = 4;
		lin[0].val = 0;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "wrote +0x4 = 0x0") != NULL);
		kgenome_gv_free(&gv, NULL);
	}

	/* VAL FIELDS SET BUT THE BIT IS NOT: a mutant of the real bug this pins - printing val=0
	 * just because the field happens to be zero would be indistinguishable from "wrote 0" on
	 * a node that never wrote anything. No bit, no line. */
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[128];

		lin[0] = rec(0x110, 40);
		lin[0].attr = 4;          /* set, but bits has neither flag */
		lin[0].val = 0x1234;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.node[0].xtotal == 0);
		xtext(&gv, 0, xl, sizeof xl);
		CK(xl[0] == 0);
		kgenome_gv_free(&gv, NULL);
	}

	/* SYMREF, resolvable: the object's own bytes are handed in, and the name is read out of
	 * them - a .ko's operand is a hole, the relocation table is the only place its name lives
	 * (diag_sym.c's note_symref), and this is that name reaching the display at last. */
	{
		static const uint8_t SYMBUF[] = "XXXXcommit_creds";    /* symref=4, NUL from the literal */
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[128];

		lin[0] = rec(0x110, 40);
		lin[0].bits |= KGENOME_DIAG_H_SYMREF;
		lin[0].symref = 4;
		lin[0].symadd = 0;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		rq.base = SYMBUF;
		rq.size = sizeof SYMBUF;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "@commit_creds+0") != NULL);
		kgenome_gv_free(&gv, NULL);
	}

	/* SYMREF with a nonzero offset into the symbol (symadd): "+5" and not "+05" or "-5". */
	{
		static const uint8_t SYMBUF[] = "XXXXcommit_creds";
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[128];

		lin[0] = rec(0x110, 40);
		lin[0].bits |= KGENOME_DIAG_H_SYMREF;
		lin[0].symref = 4;
		lin[0].symadd = 5;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		rq.base = SYMBUF;
		rq.size = sizeof SYMBUF;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "@commit_creds+5") != NULL);
		kgenome_gv_free(&gv, NULL);
	}

	/* SYMREF, NOT resolvable three ways: no object bytes handed in; symref at or past size;
	 * and a run with no terminator before the end - none of the three may read past `size`
	 * (asan/valgrind would say so on the gate build) and all three fall back to the bare
	 * offset rather than showing nothing. */
	{
		static const uint8_t SYMBUF[] = "XXXXcommit_creds";
		static const uint8_t NOTERM[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };   /* no zero byte anywhere */
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[128];

		lin[0] = rec(0x110, 40);
		lin[0].bits |= KGENOME_DIAG_H_SYMREF;
		lin[0].symref = 4;

		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		rq.base = NULL;                 /* no object bytes at all */
		rq.size = sizeof SYMBUF;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "@0x4+0") != NULL);
		kgenome_gv_free(&gv, NULL);

		rq.base = SYMBUF;
		rq.size = 4;                     /* symref == size: out of range, not a lucky in-bounds read */
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "@0x4+0") != NULL);
		kgenome_gv_free(&gv, NULL);

		rq.base = NOTERM;
		rq.size = sizeof NOTERM;
		lin[0].symref = 0;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "@0x0+0") != NULL);  /* unterminated: not a name, the offset stands */
		kgenome_gv_free(&gv, NULL);
	}

	/* VAL AND SYMREF TOGETHER: two xlines, in a fixed order (wrote, then symbol), xtotal==2 -
	 * the one shape that would show a stale line from the wrong field if the two were ever
	 * confused (a node that both wrote a value and named a symbol: diag_sym.c's own object can
	 * do both on one instruction, e.g. `mov [rax+N], &a_symbol`). */
	{
		static const uint8_t SYMBUF[] = "XXXXcommit_creds";
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl[160];

		lin[0] = rec(0x110, 40);
		lin[0].bits |= (uint8_t)(KGENOME_DIAG_H_VAL | KGENOME_DIAG_H_SYMREF);
		lin[0].val = 7;
		lin[0].symref = 4;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		rq.base = SYMBUF;
		rq.size = sizeof SYMBUF;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.node[0].xtotal == 2);
		xtext(&gv, 0, xl, sizeof xl);
		CK(strstr(xl, "wrote = 0x7|@commit_creds+0") != NULL);   /* fixed order, not swapped */
		kgenome_gv_free(&gv, NULL);
	}

	/* TWO NODES, EACH WITH XLINES: node 1's box must not show node 0's line and vice versa -
	 * xline[] is one flat array shared by every node, and an off-by-one here leaks across
	 * boxes instead of crashing, which is the kind of bug a human reading one box at a time
	 * would not catch. */
	{
		struct kof_diag_lineage_rec lin[2];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		char xl0[128], xl1[128];
		int32_t n0, n1;

		lin[0] = rec(0x110, 40);
		lin[0].bits |= KGENOME_DIAG_H_VAL;
		lin[0].val = 1;
		lin[1] = rec(0x120, 41);
		lin[1].bits |= KGENOME_DIAG_H_VAL;
		lin[1].val = 2;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 2;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		n0 = find_node(&gv, 0x110);
		n1 = find_node(&gv, 0x120);
		CK(n0 >= 0 && n1 >= 0);
		if (n0 >= 0 && n1 >= 0) {
			xtext(&gv, (uint32_t)n0, xl0, sizeof xl0);
			xtext(&gv, (uint32_t)n1, xl1, sizeof xl1);
			CK(strstr(xl0, "= 0x1") != NULL && strstr(xl0, "= 0x2") == NULL);
			CK(strstr(xl1, "= 0x2") != NULL && strstr(xl1, "= 0x1") == NULL);
		}
		kgenome_gv_free(&gv, NULL);
	}

	/* KIND: SHARED vs PRODUCED on a row with no edge (the stack sentinel, and a producer outside
	 * the extent) - "a buffer produced once and received twice" is the exact confusion this
	 * field exists to prevent (CLAUDE.md), so a SHARED input must read differently from a
	 * PRODUCED one even when both are MUST and neither is drawn. */
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		lin[0] = rec(0x110, 50);
		add_in_kind(&lin[0], KGENOME_DIAG_FROM_STACK, KGENOME_DIAG_LINK_PROVEN, KGENOME_DIAG_KIND_PRODUCED);
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_note == 1);
		CK(gv.n_note == 1 && strstr(gv.note[0].text, "shared") == NULL && strstr(gv.note[0].text, "produced"));
		kgenome_gv_free(&gv, NULL);
	}
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		lin[0] = rec(0x110, 50);
		add_in_kind(&lin[0], KGENOME_DIAG_FROM_STACK, KGENOME_DIAG_LINK_PROVEN, KGENOME_DIAG_KIND_SHARED);
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_note == 1);
		CK(gv.n_note == 1 && strstr(gv.note[0].text, "shared") != NULL);
		kgenome_gv_free(&gv, NULL);
	}
	{
		struct kof_diag_lineage_rec lin[2];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;

		lin[0] = rec(0x5000, 51);                 /* producer, outside the extent */
		lin[1] = rec(0x110, 52);
		add_in_kind(&lin[1], 0, KGENOME_DIAG_LINK_PROVEN, KGENOME_DIAG_KIND_SHARED);
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 2;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_note == 1);
		CK(gv.n_note == 1 && strstr(gv.note[0].text, "shared") != NULL);
		CK(gv.n_note == 1 && strstr(gv.note[0].text, "outside") != NULL);     /* both facts, not one at the cost of the other */
		kgenome_gv_free(&gv, NULL);
	}

	/*
	 * EDGES SORTED BY `from` (gview.h's contract, which the drawing reads: kv_graph_walk_make refuses a list that is not, and the Lineage tab then drew
	 * nothing at all). Links are found per CONSUMER, so a consumer whose producer comes later in the array put a larger `from` first: here 2->1 before
	 * 0->2, 0->3 and 1->3. Every link must still be there, once.
	 */
	{
		struct kof_diag_lineage_rec lin[4];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		static const uint32_t want[4][2] = { { 0, 2 }, { 0, 3 }, { 1, 3 }, { 2, 1 } };
		uint32_t i, k, sorted = 1, found = 0;

		lin[0] = rec(0x100, 51);
		lin[1] = rec(0x110, 52);
		add_in(&lin[1], 2, KGENOME_DIAG_LINK_PROVEN);
		lin[2] = rec(0x120, 53);
		add_in(&lin[2], 0, KGENOME_DIAG_LINK_PROVEN);
		lin[3] = rec(0x130, 54);
		add_in(&lin[3], 0, KGENOME_DIAG_LINK_PROVEN);
		add_in(&lin[3], 1, KGENOME_DIAG_LINK_PROVEN);
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 4;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 4 && gv.n_edge == 4);
		for (i = 1; i < gv.n_edge; i++)
			sorted &= gv.edge[i - 1u].from <= gv.edge[i].from;
		CK(sorted);
		for (k = 0; k < 4u; k++)
			for (i = 0; i < gv.n_edge; i++)
				found += gv.edge[i].from == want[k][0] && gv.edge[i].to == want[k][1];
		CK(found == 4u);
		kgenome_gv_free(&gv, NULL);
	}

	/*
	 * EVERY INPUT (cleartext's shape, 2026-11-14): L0 mmap, L1 socket, L2 connect (fd <- L1), L3 read whose view in[] holds buffer <- L0 and fd <- L1
	 * and whose NUMBER <- L2 is only in lin_in. With lin_in: three edges into L3, the number among them, and four rows; without: the view's two, and the
	 * head says the links were read from the view. The rows are in node order, each names the edge it is drawn as, and that edge goes into its node.
	 */
	{
		struct kof_diag_lineage_rec lin[4];
		struct kof_diag_lineage_in all[4];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		uint32_t i, ok = 1, view_said = 0;

		lin[0] = rec(0x8d, 258);
		lin[1] = rec(0xa3, 769);
		lin[2] = rec(0xc0, 771);
		add_in(&lin[2], 1, KGENOME_DIAG_LINK_PROVEN);
		lin[2].in[0].role = KGENOME_DIAG_ROLE_FD;
		lin[3] = rec(0xf1, 4097);
		add_in(&lin[3], 0, KGENOME_DIAG_LINK_PROVEN);
		add_in(&lin[3], 1, KGENOME_DIAG_LINK_PROVEN);
		lin[3].in[1].role = KGENOME_DIAG_ROLE_FD;
		all[0] = lin[2].in[0];
		all[1] = lin[3].in[0];
		all[2] = lin[3].in[1];
		all[3] = (struct kof_diag_lineage_in){ .from = 2, .role = KGENOME_DIAG_ROLE_NUMBER, .how = KGENOME_DIAG_LINK_PROVEN, .kind = KGENOME_DIAG_KIND_PRODUCED };
		lin[2].in_first = 0;
		lin[2].n_all = 1;
		lin[3].in_first = 1;
		lin[3].n_all = 3;
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 4;
		rq.off = 0x78;
		rq.len = 130;
		rq.lin_in = all;
		rq.n_lin_in = 4;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_node == 4 && gv.n_edge == 4 && gv.n_note == 4);
		CK(has_edge(&gv, 2, 3));                                     /* connect -> read: the NUMBER (base: not drawn) */
		CK(gv.n_note == 4 && strstr(gv.note[3].text, "L2 net-connect 0xc0") && strstr(gv.note[3].text, "-> L3") && strstr(gv.note[3].text, "number"));
		for (i = 0; i < gv.n_note; i++)
			ok &= gv.note[i].link >= 1u && gv.note[i].link <= gv.n_edge && gv.edge[gv.note[i].link - 1u].to == gv.note[i].node;
		CK(ok);
		for (i = 0; i < gv.n_head; i++)
			view_said |= strstr(gv.head[i], "four-input view") != NULL;
		CK(!view_said);
		kgenome_gv_free(&gv, NULL);
		rq.lin_in = NULL;
		rq.n_lin_in = 0;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_edge == 3 && !has_edge(&gv, 2, 3) && gv.n_note == 3);
		for (i = 0; i < gv.n_head; i++)
			view_said |= strstr(gv.head[i], "four-input view") != NULL;
		CK(view_said);
		kgenome_gv_free(&gv, NULL);
		/* HOSTILE RANGE: in_first + n_all past lin_in: the view is read, nothing past the array (a bounds error under ASan otherwise) */
		lin[3].in_first = 3;
		lin[3].n_all = 0xffffffffu;
		rq.lin_in = all;
		rq.n_lin_in = 4;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_edge == 3 && gv.n_note == 3);
		kgenome_gv_free(&gv, NULL);
	}

	/* THE FOUR KINDS, each its own `sure`, and the row's word; the head counts them. */
	{
		static const uint8_t how[4] = { KGENOME_DIAG_LINK_PROVEN, KGENOME_DIAG_LINK_MAY, KGENOME_DIAG_LINK_UNKNOWN, KGENOME_DIAG_LINK_BROKEN };
		static const uint8_t sure[4] = { KGENOME_GV_SURE, KGENOME_GV_SURE_MAY, KGENOME_GV_SURE_UNKNOWN, KGENOME_GV_SURE_BROKEN };
		static const char *const word[4] = { " proven ", " may ", " unknown ", " broken " };
		struct kof_diag_lineage_rec lin[5];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		uint32_t k, counted = 0;

		lin[0] = rec(0x100, 10);
		for (k = 0; k < 4u; k++) {
			lin[1u + k] = rec(0x110u + 0x10u * k, 11);
			add_in(&lin[1u + k], 0, how[k]);
		}
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 5;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_edge == 4 && gv.n_note == 4);
		for (k = 0; k < 4u && gv.n_edge == 4; k++) {
			CK(gv.edge[k].from == 0 && gv.edge[k].to == 1u + k && gv.edge[k].sure == sure[k]);
			CK(strstr(gv.note[k].text, word[k]) != NULL);
		}
		for (k = 0; k < gv.n_head; k++)
			counted |= strstr(gv.head[k], "links=4  proven=1 may=1 unknown=1 broken=1") != NULL;
		CK(counted);
		kgenome_gv_free(&gv, NULL);
	}

	/* THE HEAD'S from-outside (lin_truth audit, 2026-11-17): a node with ONE input, from the stack, and no producer outside the function.
	 * The head (the Overview's only row) says from-outside=1: the stack and a record that does not exist are counted as "outside". Why the
	 * old tests missed it: (c) the rows with the stack sentinel checked the row's words, never the head's count. */
	{
		struct kof_diag_lineage_rec lin[1];
		struct kof_lineageview_req rq;
		struct kgenome_gv gv;
		uint32_t k;
		int said = 0;

		lin[0] = rec(0x110, 52);
		add_in(&lin[0], KGENOME_DIAG_FROM_STACK, KGENOME_DIAG_LINK_PROVEN);
		memset(&rq, 0, sizeof rq);
		rq.lin = lin;
		rq.n_lin = 1;
		rq.off = 0x100;
		rq.len = 0x100;
		CK(kof_lineageview_build(&rq, &gv) == KGENOME_OK);
		CK(gv.n_note == 1 && strstr(gv.note[0].text, "the stack") != NULL);
		for (k = 0; k < gv.n_head; k++)
			said |= strstr(gv.head[k], "from-outside=1") != NULL;
		/* KNOWN DEFECT LV-D2 (2026-11-17, M): this row pins it, green until fixed (flip to from-outside=0 and the stack said apart). */
		CK(said);
		kgenome_gv_free(&gv, NULL);
	}

	printf("lineageview: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
