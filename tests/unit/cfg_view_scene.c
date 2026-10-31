/*
 * cfg_view_scene - the CFG view on a REAL object: an ELF64 x86-64 executable WRITTEN BY THIS TEST (nothing stored, nothing run: the code is
 * inert, it is only ever read), parsed by the engine's own parser, its functions found by the engine's own function table and named by the
 * engine's own symbol block, and each asked of kof_cfgview_build the way the viewer's press on a function row's name asks.
 *
 * THE SCENE. Four functions of known shape, each padded to 256 bytes with int3 so that every one is a unit of its own in the blocks table,
 * and a read-only data segment of strings (a data row with a hash, which has no cell):
 *   cv_small   a branch, a call to cv_loop, a syscall, an indirect call, a ret: 4 blocks, hashed (the anchor is one block: the floor of 12 is gone)
 *   cv_loop    two counted loops, one with a branch inside: hashed, has BACK edges
 *   cv_switch  a chain of compares fanning out to nine small blocks that meet at one exit
 *   cv_big     seventy blocks with a back edge every ten: the graph holds every block
 *
 * THREE USES, ONE FILE. Run with no argument it is the unit test. `--write <path>` writes the scene's ELF to <path> (the tui test opens it in the
 * viewer: its fixture comes from this writer). `<path> <hex offset>` prints what the engine says of the function at that offset, with the
 * the facts text the engine returns; `<path> <hex offset> --body <overview|graph>` prints the rows of that tab of the CFG dialog (kv_cfgbody.c: the Overview's facts and calls table, or the
 * Graph's drawing and what it left out), so a screen can be compared with them; `<path> <hex offset> --calls` prints the engine's calls of the function as fields (the table's oracle, one
 * line each: block, offset, kind number, target or -, name); `<path> <hex offset> --insn` prints the function's instructions as the library's own disassembler spells them (the oracle of
 * the Disasm tab, which the viewer draws through the panel's formatter): `<offset> <text>`, one line each.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"
#include "../../libkofeng/analyzers/cfgview.h"
#include "../../libkofeng/analyzers/codenotes.h"
#include "../../libkofeng/analyzers/genome_obj.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include <phenotype/diag_scan.h>
#include <celllysis/disasm.h>

#include "../../kofexamine/kofview.h"
#include "../../kofexamine/kv_graph.c"
#include "../../kofexamine/kv_cfgbody.c"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)
#define CKM(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* ---- a tiny assembler: bytes, labels, rel32 fixups ---- */
#define MAXL 160
struct asm_t {
	uint8_t code[8192];
	uint32_t n;
	int32_t lab[MAXL];              /* label -> offset, -1 = unbound */
	struct { uint32_t at; int lab; } fix[MAXL * 2];
	uint32_t nfix;
};

static void ab(struct asm_t *a, int n, ...)
{
	__builtin_va_list ap;
	int i;

	__builtin_va_start(ap, n);
	for (i = 0; i < n; i++)
		a->code[a->n++] = (uint8_t)__builtin_va_arg(ap, int);
	__builtin_va_end(ap);
}

static void a_rel(struct asm_t *a, int lab)
{
	a->fix[a->nfix].at = a->n;
	a->fix[a->nfix++].lab = lab;
	ab(a, 4, 0, 0, 0, 0);
}

static void a_bind(struct asm_t *a, int lab) { a->lab[lab] = (int32_t)a->n; }
static void a_jz(struct asm_t *a, int lab) { ab(a, 2, 0x0f, 0x84); a_rel(a, lab); }
static void a_jnz(struct asm_t *a, int lab) { ab(a, 2, 0x0f, 0x85); a_rel(a, lab); }
static void a_jmp(struct asm_t *a, int lab) { ab(a, 1, 0xe9); a_rel(a, lab); }
static void a_call(struct asm_t *a, int lab) { ab(a, 1, 0xe8); a_rel(a, lab); }
static void a_cmp(struct asm_t *a, int imm) { ab(a, 3, 0x83, 0xf8, imm); }                     /* cmp eax, imm8 */
static void a_nop(struct asm_t *a) { ab(a, 1, 0x90); }
static void a_ret(struct asm_t *a) { ab(a, 1, 0xc3); }

/* Pad with int3 to a multiple of 256 from `start`, at least 256 long: one unit of its own. */
static void a_pad(struct asm_t *a, uint32_t start)
{
	uint32_t want = start + 256u;

	while (want < a->n)
		want += 256u;
	while (a->n < want)
		ab(a, 1, 0xcc);
}

enum { L_SMALL = 150, L_LOOP, L_SWITCH, L_BIG };

static uint32_t f_off[6], f_len[6];
/* the fifth is a function NO SYMBOL NAMES (an empty name: the engine calls it fcn_<offset>); the sixth, written only by the unit test, has a name that carries an escape sequence */
static const char *f_name[6] = { "cv_small", "cv_loop", "cv_switch", "cv_big", "", "cv\033[31m\007evil" };
static int n_funcs = 5;

static void build_code(struct asm_t *a)
{
	uint32_t s0;
	int i, L = 0;

	memset(a, 0, sizeof *a);
	for (i = 0; i < MAXL; i++)
		a->lab[i] = -1;
	/* cv_small: B0 cmp, jz; B1 nop, call cv_loop, syscall, call rax, cmp, jz; B2 nop; B3 ret */
	a_bind(a, L_SMALL);
	s0 = a->n;
	a_cmp(a, 1); a_jz(a, 1);
	a_nop(a); a_call(a, L_LOOP); ab(a, 2, 0x0f, 0x05); ab(a, 2, 0xff, 0xd0);
	a_nop(a); a_cmp(a, 2); a_jz(a, 2);
	a_nop(a);
	a_bind(a, 1); a_bind(a, 2);
	a_ret(a);
	a_pad(a, s0);
	f_off[0] = s0; f_len[0] = a->n - s0;
	/* cv_loop: two counted loops, a branch inside the second, a branch before the ret */
	a_bind(a, L_LOOP);
	s0 = a->n;
	ab(a, 2, 0x31, 0xc9);                                       /* xor ecx, ecx */
	a_bind(a, 10);                                              /* top of loop 1 */
	a_cmp(a, 10); a_jz(a, 11);
	a_nop(a); a_cmp(a, 3); a_jz(a, 12);
	a_nop(a); a_nop(a);
	a_bind(a, 12);
	ab(a, 2, 0xff, 0xc9); a_jnz(a, 10);                         /* dec ecx; jnz top1: a back edge */
	a_bind(a, 11);
	ab(a, 2, 0x31, 0xd2);                                       /* xor edx, edx */
	a_bind(a, 13);                                              /* top of loop 2 */
	a_cmp(a, 5); a_jz(a, 14);
	a_nop(a); a_cmp(a, 4); a_jz(a, 15);
	a_nop(a);
	a_bind(a, 15);
	a_nop(a); ab(a, 2, 0xff, 0xca); a_jnz(a, 13);               /* dec edx; jnz top2: a back edge */
	a_bind(a, 14);
	a_cmp(a, 9); a_jz(a, 16);
	a_nop(a);
	a_bind(a, 16);
	a_ret(a);
	a_pad(a, s0);
	f_off[1] = s0; f_len[1] = a->n - s0;
	/* cv_switch: a chain of nine compares fanning out to nine blocks that meet at one exit */
	a_bind(a, L_SWITCH);
	s0 = a->n;
	for (i = 0; i < 9; i++) {
		a_cmp(a, i); a_jz(a, 30 + i);
	}
	a_jmp(a, 40);
	for (i = 0; i < 9; i++) {
		a_bind(a, 30 + i);
		a_nop(a); a_nop(a); a_jmp(a, 41);
	}
	a_bind(a, 40);
	a_nop(a);
	a_bind(a, 41);
	a_ret(a);
	a_pad(a, s0);
	f_off[2] = s0; f_len[2] = a->n - s0;
	/* cv_big: seventy blocks (compare, branch to the one after next, nop), a loop back every ten */
	a_bind(a, L_BIG);
	s0 = a->n;
	ab(a, 2, 0x31, 0xc9);
	for (i = 0; i < 70; i++) {
		L = 50 + i;
		a_bind(a, L);
		a_cmp(a, i & 0x3f);
		if (i % 10 == 9) {
			ab(a, 2, 0xff, 0xc9);
			a_jnz(a, L - 5);
		} else {
			a_jz(a, L + 2 < 120 ? L + 2 : 120);
			a_nop(a);
		}
	}
	a_bind(a, 120);
	a_ret(a);
	a_pad(a, s0);
	f_off[3] = s0; f_len[3] = a->n - s0;
	for (i = 4; i < n_funcs; i++) {                             /* two more: a nop and a ret each; only their NAMES are the point */
		s0 = a->n;
		a_nop(a); a_ret(a);
		a_pad(a, s0);
		f_off[i] = s0; f_len[i] = a->n - s0;
	}
	/* the fixups: rel32 from the end of the field to the label */
	for (i = 0; i < (int)a->nfix; i++) {
		const int32_t rel = a->lab[a->fix[i].lab] - (int32_t)(a->fix[i].at + 4u);

		a->code[a->fix[i].at] = (uint8_t)rel;
		a->code[a->fix[i].at + 1u] = (uint8_t)(rel >> 8);
		a->code[a->fix[i].at + 2u] = (uint8_t)(rel >> 16);
		a->code[a->fix[i].at + 3u] = (uint8_t)(rel >> 24);
	}
}

static void p16(uint8_t *b, uint64_t o, uint64_t v) { b[o] = (uint8_t)v; b[o + 1] = (uint8_t)(v >> 8); }
static void p32(uint8_t *b, uint64_t o, uint64_t v) { p16(b, o, v); p16(b, o + 2, v >> 16); }
static void p64(uint8_t *b, uint64_t o, uint64_t v) { p32(b, o, v); p32(b, o + 4, v >> 32); }

#define TEXT_OFF 0x100u
#define TEXT_VA  0x400000u

static const char *const strs[] = {
	"GET /cfgview/index.html HTTP/1.1", "Host: scene.example.invalid", "User-Agent: cfgview-fixture/1.0", "Accept: text/plain",
	"Connection: close", "X-Scene: inert test data", "usage: scene [-v] [-n count] file",
};

/* The whole object. Returns its size; `out` is malloc'd. */
static uint64_t write_scene(uint8_t **out)
{
	struct asm_t a;
	uint8_t *b;
	uint64_t text_end, ro_off, ro_n = 0, sym_off, str_off, shstr_off, sh_off, n, o, i;
	char strtab[256] = "", shstr[64];
	uint32_t name_at[6], str_n = 1;
	static const char sh_names[] = "\0.text\0.rodata\0.symtab\0.strtab\0.shstrtab";

	build_code(&a);
	text_end = TEXT_OFF + a.n;
	ro_off = (text_end + 15u) & ~15ull;
	for (i = 0; i < sizeof strs / sizeof *strs; i++)
		ro_n += strlen(strs[i]) + 1u;
	sym_off = (ro_off + ro_n + 7u) & ~7ull;
	for (i = 0; i < (uint64_t)n_funcs; i++) {
		if (!f_name[i][0]) {                                    /* no name: the symbol points at the empty string at the start of the table */
			name_at[i] = 0;
			continue;
		}
		name_at[i] = str_n;
		memcpy(strtab + str_n, f_name[i], strlen(f_name[i]) + 1u);
		str_n += (uint32_t)strlen(f_name[i]) + 1u;
	}
	str_off = sym_off + (uint64_t)(n_funcs + 1) * 24u;
	shstr_off = str_off + str_n;
	memcpy(shstr, sh_names, sizeof sh_names);
	sh_off = (shstr_off + sizeof sh_names + 7u) & ~7ull;
	n = sh_off + 6u * 64u;
	b = calloc((size_t)n, 1);
	memcpy(b, "\177ELF\2\1\1", 7);
	p16(b, 16, 2); p16(b, 18, 0x3e); p32(b, 20, 1);
	p64(b, 24, TEXT_VA + TEXT_OFF + f_off[0]); p64(b, 32, 64); p64(b, 40, sh_off);
	p16(b, 52, 64); p16(b, 54, 56); p16(b, 56, 2); p16(b, 58, 64); p16(b, 60, 6); p16(b, 62, 5);
	/* PT_LOAD 0: the file's first bytes and the code, R+X */
	p32(b, 64, 1); p32(b, 68, 5); p64(b, 72, 0); p64(b, 80, TEXT_VA); p64(b, 88, TEXT_VA); p64(b, 96, text_end); p64(b, 104, text_end); p64(b, 112, 0x1000);
	/* PT_LOAD 1: the data, R */
	p32(b, 120, 1); p32(b, 124, 4); p64(b, 128, ro_off); p64(b, 136, 0x500000u + (ro_off & 0xfffu)); p64(b, 144, 0x500000u + (ro_off & 0xfffu));
	p64(b, 152, ro_n); p64(b, 160, ro_n); p64(b, 168, 0x1000);
	memcpy(b + TEXT_OFF, a.code, a.n);
	for (o = ro_off, i = 0; i < sizeof strs / sizeof *strs; i++) {
		memcpy(b + o, strs[i], strlen(strs[i]) + 1u);
		o += strlen(strs[i]) + 1u;
	}
	for (i = 0; i < (uint64_t)n_funcs; i++) {               /* symbol 0 is the null symbol */
		const uint64_t s = sym_off + (i + 1u) * 24u;

		p32(b, s, name_at[i]); b[s + 4] = 0x12; p16(b, s + 6, 1);
		p64(b, s + 8, TEXT_VA + TEXT_OFF + f_off[i]); p64(b, s + 16, f_len[i]);
	}
	memcpy(b + str_off, strtab, str_n);
	memcpy(b + shstr_off, sh_names, sizeof sh_names);
	{
		/* sections: null, .text, .rodata, .symtab, .strtab, .shstrtab */
		struct { uint32_t name, type; uint64_t flags, addr, off, size; uint32_t link, info; uint64_t align, ent; } sh[6] = {
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
			{ 1, 1, 6, TEXT_VA + TEXT_OFF, TEXT_OFF, a.n, 0, 0, 16, 0 },
			{ 7, 1, 2, 0x500000u + (ro_off & 0xfffu), ro_off, ro_n, 0, 0, 1, 0 },
			{ 15, 2, 0, 0, sym_off, (uint64_t)(n_funcs + 1) * 24u, 4, 1, 8, 24 },
			{ 23, 3, 0, 0, str_off, str_n, 0, 0, 1, 0 },
			{ 31, 3, 0, 0, shstr_off, sizeof sh_names, 0, 0, 1, 0 },
		};

		for (i = 0; i < 6; i++) {
			const uint64_t h = sh_off + i * 64u;

			p32(b, h, sh[i].name); p32(b, h + 4, sh[i].type); p64(b, h + 8, sh[i].flags); p64(b, h + 16, sh[i].addr);
			p64(b, h + 24, sh[i].off); p64(b, h + 32, sh[i].size); p32(b, h + 40, sh[i].link); p32(b, h + 44, sh[i].info);
			p64(b, h + 48, sh[i].align); p64(b, h + 56, sh[i].ent);
		}
	}
	*out = b;
	return n;
}

/* ---- the engine's own reading of the object ---- */
struct obj {
	uint8_t *bytes;
	uint64_t n;
	struct kof_obj_ctx ctx;
	void *view;
	struct kgenome_func_set fs;
	uint8_t *sym;
	uint32_t sym_n;
};

static int obj_open(struct obj *o, uint8_t *bytes, uint64_t n)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf = kof_buf_make(bytes, n);
	struct kgenome_obj g;

	memset(o, 0, sizeof *o);
	o->bytes = bytes;
	o->n = n;
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++) {
		void *view = calloc(1, pl[i].view_size ? pl[i].view_size : 1u);

		memset(&o->ctx, 0, sizeof o->ctx);
		if (pl[i].sniff && pl[i].sniff(buf) && pl[i].parse && pl[i].parse(buf, view, &o->ctx)) {
			o->view = view;
			break;
		}
		free(view);
	}
	if (!o->view)
		return 0;
	kof_genome_obj(&o->ctx, &g);
	kgenome_diag_funcs_of(&g, bytes, n, &o->fs);
	o->sym = malloc(KOF_SYM_MAX_BYTES);
	o->sym_n = o->sym ? kof_syms_build(o->ctx.format, bytes, n, o->view, o->sym, KOF_SYM_MAX_BYTES) : 0;
	return 1;
}

static void obj_close(struct obj *o)
{
	kgenome_funcs_free(&o->fs);
	free(o->sym);
	free(o->view);
}

static void request(struct kof_cfgview_req *rq, const struct obj *o, uint64_t off, uint64_t len)
{
	memset(rq, 0, sizeof *rq);
	rq->ctx = &o->ctx;
	rq->data = kof_buf_make(o->bytes, o->n);
	rq->func_off = off;
	rq->func_len = len;
	rq->funcs = &o->fs;
	rq->sym = o->sym;
	rq->sym_n = o->sym_n;
}

static const struct kgenome_func *func_by_off(const struct obj *o, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < o->fs.n; i++)
		if (o->fs.v[i].off == off)
			return &o->fs.v[i];
	return NULL;
}

static double now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* THE COLOURS OF THE GRAPH TAB are data: an edge's attribute is a function of the engine's (cond, loop) alone, a box's marks of the engine's node flags. */
static const char *tag_text(void *user, uint32_t node, uint32_t i)
{
	static char t[16];

	(void)user;
	if (i)
		return NULL;
	snprintf(t, sizeof t, "node %u", (unsigned)node);
	return t;
}

static void colour_tests(struct kof_cfgview_req *rq, uint64_t off, uint64_t len)
{
	/* the table the viewer states, written out here as an independent oracle: [loop][cond] */
	static const char *const want[3][3] = {
		{ NULL, A_SIZE, A_BAD },        /* forward: none, T, F */
		{ A_WARN, A_SIZE, A_BAD },      /* loop link */
		{ A_HEUR, A_SIZE, A_BAD },      /* retreating */
	};
	struct kv_graph_style st = kv_cfgbody_style();
	unsigned loop, cond, m;

	for (loop = 0; loop < 3u; loop++)
		for (cond = 0; cond < 3u; cond++) {
			const char *a = st.attr[1u + loop * 3u + cond];

			CKM(a == want[loop][cond] || (a && want[loop][cond] && !strcmp(a, want[loop][cond])), "edge attr loop %u cond %u", loop, cond);
			CK(a == kv_cfgbody_edge_attr(cond, loop));
		}
	CK(st.attr[0] == NULL && st.off && !strcmp(st.off, A_OFF));
	for (m = 1; m <= KV_CFG_MK_CALL; m++)
		CKM(st.attr[KV_GRAPH_MARK0 - 1u + m] && kv_cfgbody_mark_attr(m) && !strcmp(st.attr[KV_GRAPH_MARK0 - 1u + m], kv_cfgbody_mark_attr(m)), "mark %u", m);
	CK(kv_cfgbody_mark_attr(KV_CFG_MK_NONE) == NULL && kv_cfgbody_mark_attr(99) == NULL);
	/* one colour per kind: the four hues of the table are different strings */
	CK(strcmp(A_SIZE, A_BAD) && strcmp(A_BAD, A_WARN) && strcmp(A_WARN, A_HEUR) && strcmp(A_SIZE, A_WARN));
	/* every combination as a graph: seven boxes, an edge of each (cond, loop) kind, and every kind is on the canvas */
	{
		struct kv_graph_edge e[12];
		struct kv_graph_in in;
		struct kv_graph g;
		uint32_t n = 0, i, seen = 0;

		memset(e, 0, sizeof e);
		e[n].from = 0; e[n].to = 1; n++;
		e[n].from = 0; e[n].to = 2; e[n].cond = KV_GC_T; n++;
		e[n].from = 0; e[n].to = 3; e[n].cond = KV_GC_F; n++;
		e[n].from = 0; e[n].to = 4; n++;
		e[n].from = 0; e[n].to = 5; n++;
		e[n].from = 0; e[n].to = 6; n++;
		e[n].from = 1; e[n].to = 0; e[n].loop = KV_GL_LOOP; n++;
		e[n].from = 2; e[n].to = 0; e[n].loop = KV_GL_LOOP; e[n].cond = KV_GC_T; n++;
		e[n].from = 3; e[n].to = 0; e[n].loop = KV_GL_LOOP; e[n].cond = KV_GC_F; n++;
		e[n].from = 4; e[n].to = 0; e[n].loop = KV_GL_RETREAT; n++;
		e[n].from = 5; e[n].to = 0; e[n].loop = KV_GL_RETREAT; e[n].cond = KV_GC_T; n++;
		e[n].from = 6; e[n].to = 0; e[n].loop = KV_GL_RETREAT; e[n].cond = KV_GC_F; n++;
		memset(&in, 0, sizeof in);
		in.n_node = 7;
		in.n_edge = n;
		in.edge = e;
		in.text = tag_text;
		if (kv_graph_layout(&in, &g) == KV_GS_OK || g.n_wire) {
			for (i = 0; i < g.n_wire; i++) {
				const struct kv_graph_wire *w = &g.wire[i];
				const unsigned k = 1u + w->loop * 3u + w->cond;

				CKM(w->cond == e[w->edge].cond && (w->loop == e[w->edge].loop), "wire %u carries the edge's own cond and loop", i);
				seen |= 1u << k;
			}
			CKM(seen == 0x3feu, "the kinds of the wires: 0x%x", seen);
			for (i = 0; i < (uint32_t)g.width * g.height; i++) {
				const unsigned a = kv_graph_cell_attr(&g.cell[i]);

				CK(a < KV_GRAPH_KINDS);
				CK(a == 0 || a >= KV_GRAPH_MARK0 || g.cell[i].g == KV_GG_LINE || g.cell[i].g == KV_GG_LABEL || g.cell[i].g == KV_GG_ARROW);
			}
		} else {
			CKM(0, "the kind graph did not lay out");
		}
		kv_graph_free(&g);
	}
	/* the real graph of a function with loops, T/F branches and calls: the marks are the engine's flags */
	{
		struct kv_cfg_body bd;
		const struct kgenome_gv *gv;
		uint32_t i, heads = 0, entry_cells = 0, head_cells = 0, call_cells = 0;

		rq->func_off = off;
		rq->func_len = len;
		kv_cfgbody_make(&bd, rq);
		gv = &bd.cf.gv;
		for (i = 0; i < bd.g.n_box; i++) {
			const struct kv_graph_box *b = &bd.g.box[i];
			const struct kv_graph_cell *c = &bd.g.cell[(size_t)b->y * bd.g.width + (uint32_t)b->x];       /* the corner */
			const struct kv_graph_cell *t = &bd.g.cell[(size_t)(b->y + 1) * bd.g.width + (uint32_t)b->x + 2u];   /* the first character of row 0 */
			const int is_entry = b->node == gv->entry, is_head = (gv->node[b->node].flags & KGENOME_GV_NF_LOOP_HEAD) != 0;

			CKM(kv_graph_cell_attr(c) == (is_entry ? KV_GRAPH_MARK0 - 1u + KV_CFG_MK_ENTRY : 0u), "box %u corner", b->node);
			CKM(kv_graph_cell_attr(t) == (is_head ? KV_GRAPH_MARK0 - 1u + KV_CFG_MK_LOOP_HEAD : 0u), "box %u row 0", b->node);
			entry_cells += (uint32_t)is_entry;
			head_cells += (uint32_t)is_head;
			heads += (uint32_t)is_head;
			/* the row 1 is never marked; the rows past it only for a node that holds calls */
			CK(kv_graph_cell_attr(&bd.g.cell[(size_t)(b->y + 2) * bd.g.width + (uint32_t)b->x + 2u]) == 0);
			if (b->h > 4u)
				call_cells += kv_graph_cell_attr(&bd.g.cell[(size_t)(b->y + 3) * bd.g.width + (uint32_t)b->x + 2u]) == KV_GRAPH_MARK0 - 1u + KV_CFG_MK_CALL;
		}
		CKM(entry_cells == 1 && head_cells >= 1, "marked: entry %u, loop heads %u", entry_cells, head_cells);
		(void)heads;
		(void)call_cells;
		/* the rows of the drawing, from the window, carry the escapes of the table */
		{
			static char row[16384];
			uint32_t r, esc_T = 0, esc_F = 0, esc_loop = 0;

			bd.tab = KV_CFG_TAB_GRAPH;
			for (r = 0; r < bd.g.height; r++) {
				kv_cfgbody_row(&bd, r, 0, 4000, row, sizeof row);
				esc_T += strstr(row, A_SIZE) != NULL;
				esc_F += strstr(row, A_BAD) != NULL;
				esc_loop += strstr(row, A_WARN) != NULL;
			}
			CKM(esc_T && esc_F && esc_loop, "colours on the rows: T %u, F %u, loop %u", esc_T, esc_F, esc_loop);
		}
		kv_cfgbody_free(&bd);
	}
}

/* ONE NAME FOR A FUNCTION, on a real object. The disassembly notes (codenotes) said `sub_<offset>` where the CFG dialog said `fcn_<offset>`. Bytes of the
 * scene's int3 padding after the sixth function are patched into `call <unnamed>; jmp <unnamed>; call cv_small`; the notes, the xref and the dialog's
 * callee name must all be kof_func_name's word for the unnamed one and the symbol for the named one. Old tests missed it: (a) no test read codenotes
 * and cfgview from one object, (c) each pinned its own spelling. */
static const char *note_text(const struct kof_codenotes *n, uint64_t at, unsigned kind)
{
	uint32_t cnt, i;
	const struct kof_note *x = kof_codenotes_at(n, at, &cnt);

	for (i = 0; i < cnt; i++)
		if (x[i].kind == kind)
			return kof_codenotes_text(n, &x[i]);
	return NULL;
}

static void one_name(void)
{
	uint8_t *img, *cp;
	uint64_t n;
	struct obj o;
	struct kof_codenotes cn;
	struct kof_cfgview v;
	struct kof_cfgview_req rq;
	const struct kgenome_func *f4, *f0, *f5, *f1;
	char want[48], sym[48], mid[48], t[128];
	uint64_t at;
	uint32_t i;

	n_funcs = 6;
	n = write_scene(&img);
	cp = malloc(n);
	CK(cp != NULL);
	if (!cp) {
		free(img);
		return;
	}
	memcpy(cp, img, n);
	CK(obj_open(&o, img, n));
	f4 = func_by_off(&o, TEXT_OFF + f_off[4]);
	f0 = func_by_off(&o, TEXT_OFF + f_off[0]);
	f5 = func_by_off(&o, TEXT_OFF + f_off[5]);
	f1 = func_by_off(&o, TEXT_OFF + f_off[1]);
	if (!f4 || !f0 || !f5 || !f1) {
		CK(0);
		goto out;
	}
	{
		/* patch the copy at the sixth function's padding: its own code is nop; ret */
		const uint64_t p = f5->off + 1u;
		const uint64_t f1o = f1->off;
		const int32_t r[4] = { (int32_t)((int64_t)f4->off - (int64_t)(p + 5u)), (int32_t)((int64_t)f0->off - (int64_t)(p + 10u)),
				       (int32_t)((int64_t)(f1o + 4u) - (int64_t)(p + 15u)),
				       (int32_t)((int64_t)f4->off - (int64_t)(p + 20u)) };

		obj_close(&o);
		cp[p] = 0xe8; memcpy(cp + p + 1u, &r[0], 4);
		cp[p + 5u] = 0xe8; memcpy(cp + p + 6u, &r[1], 4);                /* call cv_small */
		cp[p + 10u] = 0xe8; memcpy(cp + p + 11u, &r[2], 4);              /* call into the MIDDLE of cv_loop: no table entry */
		cp[p + 15u] = 0xe9; memcpy(cp + p + 16u, &r[3], 4);              /* jmp the unnamed one: a tail call */
		CK(obj_open(&o, cp, n));
		f4 = func_by_off(&o, TEXT_OFF + f_off[4]);
		f0 = func_by_off(&o, TEXT_OFF + f_off[0]);
		f5 = func_by_off(&o, TEXT_OFF + f_off[5]);
		f1 = func_by_off(&o, TEXT_OFF + f_off[1]);
		if (!f4 || !f0 || !f5 || !f1) {
			CK(0);
			goto out;
		}
		at = p;
	}
	CK(kof_func_name(f4, o.sym, o.sym_n, want, sizeof want) == 0);
	CK(kof_func_name(f0, o.sym, o.sym_n, sym, sizeof sym) == 1 && !strcmp(sym, "cv_small"));
	CK(kof_codenotes_build(&o.ctx, kof_buf_make(o.bytes, o.n), &o.fs, o.sym, o.sym_n, 0, NULL, &cn) == 1);
	snprintf(t, sizeof t, "-> %s", want);
	CKM(note_text(&cn, at, KOF_NOTE_COMMENT) && !strcmp(note_text(&cn, at, KOF_NOTE_COMMENT), t), "call comment '%s' want '%s'", note_text(&cn, at, KOF_NOTE_COMMENT), t);
	snprintf(t, sizeof t, "-> %s (backward)", want);
	CKM(note_text(&cn, at + 15u, KOF_NOTE_COMMENT) && !strcmp(note_text(&cn, at + 15u, KOF_NOTE_COMMENT), t), "jmp comment '%s'", note_text(&cn, at + 15u, KOF_NOTE_COMMENT));
	kof_fcn_name(f1->off + 4u, mid, sizeof mid);                    /* an address that is no table entry: the made-up name alone */
	snprintf(t, sizeof t, "-> %s", mid);
	CKM(note_text(&cn, at + 10u, KOF_NOTE_COMMENT) && !strcmp(note_text(&cn, at + 10u, KOF_NOTE_COMMENT), t), "mid call comment '%s'", note_text(&cn, at + 10u, KOF_NOTE_COMMENT));
	snprintf(t, sizeof t, "%s:", want);
	{
		const char *fn = note_text(&cn, f4->off, KOF_NOTE_FUNC);

		CKM(fn && !strncmp(fn, t, strlen(t)) && strstr(fn, "xrefs") != NULL, "FUNC note '%s' want '%s...'", fn ? fn : "(none)", t);
	}
	snprintf(t, sizeof t, "-> %s", sym);
	CKM(note_text(&cn, at + 5u, KOF_NOTE_COMMENT) && !strcmp(note_text(&cn, at + 5u, KOF_NOTE_COMMENT), t), "symbol call comment '%s'", note_text(&cn, at + 5u, KOF_NOTE_COMMENT));
	for (i = 0; i < cn.n; i++)
		CK(strstr(kof_codenotes_text(&cn, &cn.v[i]), "sub_") == NULL);
	/* the dialog: its own name, and the callee names of the same function, are the same words */
	request(&rq, &o, f4->off, f4->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(!strcmp(v.name, want), "dialog name '%s' want '%s'", v.name, want);
	kof_cfgview_free(&v);
	request(&rq, &o, f5->off, f5->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	{
		int seen_un = 0, seen_sym = 0, seen_mid = 0;

		for (i = 0; i < v.n_call; i++) {
			seen_un += !strcmp(v.call[i].name, want);
			seen_sym += !strcmp(v.call[i].name, sym);
			seen_mid += !strcmp(v.call[i].name, mid);
		}
		CKM(seen_un >= 1 && seen_sym == 1 && seen_mid == 1, "dialog callees: unnamed %d symbol %d mid %d", seen_un, seen_sym, seen_mid);
	}
	kof_cfgview_free(&v);
	kof_codenotes_free(&cn);
out:
	obj_close(&o);
	free(cp);
	free(img);
}

static void self_test(void)
{
	uint8_t *img;
	uint64_t n;
	struct obj o;
	struct kof_cfgview v;
	struct kof_cfgview_req rq;
	uint32_t i;
	const struct kgenome_func *f[6];
	double t0, ms[6];

	n_funcs = 6;
	n = write_scene(&img);
	CK(obj_open(&o, img, n));
	CKM(o.ctx.format == KOF_FMT_ELF && o.ctx.arch == KGENOME_ARCH_X86_64, "format %d arch %d", o.ctx.format, o.ctx.arch);
	CKM(o.fs.n == 6, "the engine lists %u functions", o.fs.n);
	CK(o.sym_n > 0);
	for (i = 0; i < 6; i++) {
		f[i] = func_by_off(&o, TEXT_OFF + f_off[i]);
		CKM(f[i] && f[i]->len == f_len[i], "function %s in the engine's table", f_name[i]);
	}
	if (fails)
		goto out;
	/* a function no symbol names is `fcn_<offset>`, in ONE place (kof_func_name): the name of the view, its title line, and what a call to it is called */
	request(&rq, &o, f[4]->off, f[4]->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	{
		char want[40];

		snprintf(want, sizeof want, "fcn_%08llx", (unsigned long long)f[4]->off);
		CKM(!strcmp(v.name, want) && !strncmp(v.text, "function fcn_", 13) && strstr(v.text, want) != NULL, "unnamed function: name '%s' want '%s'", v.name, want);
		CK(kof_func_name(f[4], o.sym, o.sym_n, want, sizeof want) == 0 && !strcmp(want, v.name));            /* the same word from the engine's API */
		CK(kof_func_name(f[0], o.sym, o.sym_n, want, sizeof want) == 1 && !strcmp(want, "cv_small"));
		CK(kof_func_name(f[4], NULL, 0, want, 8) == 0 && !strcmp(want, "fcn_000"));                          /* a short buffer is cut and NUL-ended */
		want[0] = 'x';
		CK(kof_func_name(f[4], NULL, 0, want, 0) == 0 && want[0] == 'x');                                     /* no room: nothing written */
	}
	kof_cfgview_free(&v);
	/* a name with an escape sequence and a bell reaches the dialog as printable ASCII */
	request(&rq, &o, f[5]->off, f[5]->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(!strcmp(v.name, "cv?[31m?evil") && strncmp(v.text, "function cv?[31m?evil\n", 22) == 0, "name '%s' text '%.30s'", v.name, v.text);
	CK(strchr(v.text, 0x1b) == NULL && strchr(v.text, 7) == NULL);
	kof_cfgview_free(&v);
	/* every function: a graph, named by the engine's symbol block, the head says what a researcher decides by */
	for (i = 0; i < 4; i++) {
		char want[96];

		request(&rq, &o, f[i]->off, f[i]->len);
		t0 = now_ms();
		CK(kof_cfgview_build(&rq, &v) == 1);
		ms[i] = now_ms() - t0;
		snprintf(want, sizeof want, "function %s\n", f_name[i]);
		CKM(!strncmp(v.text, want, strlen(want)) && !strcmp(v.name, f_name[i]), "name '%s' text '%.40s'", v.name, v.text);
		snprintf(want, sizeof want, "extent  0x%llx +%llu bytes", (unsigned long long)f[i]->off, (unsigned long long)f[i]->len);
		CK(strstr(v.text, want) != NULL && v.mapped && v.func_va == TEXT_VA + f[i]->off);
		CK(strstr(v.text, "x86-64") != NULL && v.n_insn > 0);
		/* a 256-byte function holds its code then int3 padding: one unreachable block, listed apart */
		CKM(v.view.n_unr == 1 && strstr(v.text, "unreachable blocks: 1") != NULL && strstr(v.text, "not part of the shape") == NULL, "%s: %u unreachable", f_name[i], v.view.n_unr);
		CK(v.status == KGENOME_OK || v.status == KGENOME_TRUNCATED);
		printf("  %-9s extent %u bytes, %u instructions, %u reachable blocks, %u edges, anchor %s, %u call(s), %.3f ms\n", f_name[i], (unsigned)f_len[i], v.n_insn, v.view.n_blk,
		       v.view.n_edge, v.anchor_pass ? "PASS" : "below", v.n_call, ms[i]);
		kof_cfgview_free(&v);
	}
	/* cv_small: 4 blocks, hashed now, a call named by the symbol block, a syscall, an indirect call */
	request(&rq, &o, f[0]->off, f[0]->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.view.n_blk == 4 && v.anchor_pass && v.view.n_key == 4 && strstr(v.text, ": PASS\n") != NULL && strstr(v.text, "is hashed") == NULL, "cv_small: %u blocks", v.view.n_blk);
	CKM(v.n_call == 3, "cv_small: %u calls", v.n_call);
	if (v.n_call == 3) {
		CKM(v.call[0].kind == KGENOME_CFG_CK_DIRECT && !strcmp(v.call[0].name, "cv_loop") && v.call[0].target == f[1]->off, "call 0 -> '%s'", v.call[0].name);
		CK(v.call[1].kind == KGENOME_CFG_CK_SYSCALL && v.call[2].kind == KGENOME_CFG_CK_INDIRECT);
		CK(v.call[0].blk == 1 && v.call[1].blk == 1 && v.call[2].blk == 1);
	}
	CK(strstr(v.text, "-> cv_loop") != NULL && strstr(v.text, "calls: 3") != NULL);
	/* THE TABS' ROWS (kv_cfgbody.c) of the same function: the Overview is the engine's head lines, then the calls as a table whose cells are the fields of struct kof_cfgview_call, then the
	 * unreachable blocks; the Graph is the drawing and nothing of the facts. Both are made from the one build above's inputs (one decode). */
	if (v.n_call == 3) {
		struct kv_cfg_body bd;
		static char row[4096];
		char cell[128];
		uint32_t r, found = 0, hdr = 0, nr, nc;

		kv_cfgbody_make(&bd, &rq);
		kv_cfgbody_size(&bd, KV_CFG_TAB_OVERVIEW, &nr, &nc);
		bd.tab = KV_CFG_TAB_OVERVIEW;
		CKM(bd.n_head >= 3 && nr > bd.n_head + 4u, "overview: %u rows, head %u", nr, bd.n_head);
		kv_cfgbody_row(&bd, 0, 0, 4000, row, sizeof row);
		CKM(!strcmp(row, " function cv_small"), "overview row 0 '%s'", row);
		for (r = 0; r < nr; r++) {
			kv_cfgbody_row(&bd, r, 0, 4000, row, sizeof row);
			hdr += strstr(row, "block") != NULL && strstr(row, "offset") && strstr(row, "kind") && strstr(row, "target") && strstr(row, "name");
			CK(strstr(row, "nucleo") == NULL && strstr(row, "activit") == NULL);      /* no column for what the engine does not expose on a call */
		}
		CKM(hdr == 1, "overview: %u table header rows", hdr);
		for (r = 0; r < 3; r++) {
			const char *kw = v.call[r].kind == KGENOME_CFG_CK_SYSCALL ? "syscall" : v.call[r].kind == KGENOME_CFG_CK_INDIRECT ? "call indirect" : "call";

			char tg[40];

			snprintf(cell, sizeof cell, " B%u ", (unsigned)v.call[r].blk);
			if (v.call[r].target == KGENOME_BROKEN)
				snprintf(tg, sizeof tg, " - ");
			else
				snprintf(tg, sizeof tg, " 0x%llx ", (unsigned long long)v.call[r].target);
			{
				char at[40];

				snprintf(at, sizeof at, " 0x%llx ", (unsigned long long)v.call[r].at);
				for (nr = 0; nr < bd.n_ol; nr++) {
					char t[600];

					snprintf(t, sizeof t, "%s ", bd.ol[nr]);
					const char *pk = strstr(t, kw), *pt = strstr(t, tg);

					/* the kind cell stands before the target cell (a name may repeat the word: the syscall of the scene is named `syscall`) */
					if (t[0] == ' ' && t[1] == ' ' && strstr(t, cell) && strstr(t, at) && pk && pt && pk < pt &&
					    (!v.call[r].name[0] || strstr(t, v.call[r].name)))
						found++;
				}
			}
		}
		CKM(found >= 3, "overview: %u of 3 call rows hold their fields", found);
		bd.tab = KV_CFG_TAB_GRAPH;
		kv_cfgbody_size(&bd, KV_CFG_TAB_GRAPH, &nr, &nc);
		CKM(nr == bd.g.height + bd.n_xl && nr > 4u, "graph: %u rows, drawing %u", nr, bd.g.height);
		for (r = 0; r < nr; r++) {
			kv_cfgbody_row(&bd, r, 0, 4000, row, sizeof row);
			CK(strstr(row, "extent  0x") == NULL && strstr(row, "canon  0x") == NULL && strstr(row, "kind") == NULL);
		}
		kv_cfgbody_free(&bd);
	}
	kof_cfgview_free(&v);
	/* cv_loop: passes the anchor and has loop links (back edges into a node that dominates its source) */
	request(&rq, &o, f[1]->off, f[1]->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.view.n_blk >= 12 && v.anchor_pass && strstr(v.text, ": PASS\n") != NULL && strstr(v.text, "is hashed") == NULL, "cv_loop: %u blocks", v.view.n_blk);
	{
		uint32_t k, links = 0, heads = 0;

		for (k = 0; k < v.gv.n_edge; k++)
			links += v.gv.edge[k].loop == KGENOME_GV_LOOP_LINK;
		for (k = 0; k < v.gv.n_node; k++)
			heads += (v.gv.node[k].flags & KGENOME_GV_NF_LOOP_HEAD) != 0 && strstr(v.gv.node[k].line[0], " @ ") != NULL;
		CKM(links >= 2 && heads >= 1, "cv_loop: %u loop links, %u marked heads", links, heads);
	}
	kof_cfgview_free(&v);
	/* cv_switch: nine blocks reached from nine compares: the fan-out is in the graph */
	request(&rq, &o, f[2]->off, f[2]->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.view.n_blk >= 20 && v.anchor_pass, "cv_switch: %u blocks", v.view.n_blk);
	kof_cfgview_free(&v);
	/* cv_big: seventy-odd blocks: the graph holds every one (what is drawn of it is the viewer's bound: tests/unit/kx_graph.c) */
	request(&rq, &o, f[3]->off, f[3]->len);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.view.n_blk >= 60 && v.gv.n_node == v.view.n_blk && v.gv.n_edge == v.view.n_edge, "cv_big: %u blocks, graph nodes %u", v.view.n_blk, v.gv.n_node);
	kof_cfgview_free(&v);
	/* the data rows: strings in a read-only segment are not a function, whatever offset they are asked at */
	{
		const uint64_t ro = (TEXT_OFF + f_off[5] + f_len[5] + 15u) & ~15ull;

		request(&rq, &o, ro, 64);
		CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT && strstr(v.text, "not a function") != NULL);
		kof_cfgview_free(&v);
	}
	/* the same function twice gives the same bytes; the text is printable ASCII and newlines and nothing else */
	{
		struct kof_cfgview v2;
		const char *p;

		request(&rq, &o, f[1]->off, f[1]->len);
		CK(kof_cfgview_build(&rq, &v) == 1 && kof_cfgview_build(&rq, &v2) == 1 && !strcmp(v.text, v2.text));
		for (p = v.text; *p; p++)
			if (*p != '\n' && (*p < 0x20 || *p > 0x7e)) {
				CKM(0, "a control or non-ASCII byte 0x%02x in the text", (unsigned char)*p);
				break;
			}
		kof_cfgview_free(&v2);
		kof_cfgview_free(&v);
	}
	colour_tests(&rq, f[1]->off, f[1]->len);
out:
	obj_close(&o);
	free(img);
}

/* The function's instructions as the library spells them: the walk the panel makes (a word that is not an instruction is one byte, `(data)`). */
static void print_insns(const struct obj *o, uint64_t off, uint64_t len)
{
	uint64_t at = 0;

	while (at < len && off + at < o->n) {
		char text[160];
		struct kgenome_disasm_req q;
		struct kgenome_disasm_res rs;
		const uint64_t room = o->n - (off + at);

		memset(&q, 0, sizeof q);
		q.arch = kgenome_disasm_arch(NULL, 64);
		q.p = o->bytes + off + at;
		q.n = room < 16u ? (size_t)room : 16u;
		q.va = off + at;
		q.text = text;
		q.cap = sizeof text;
		kgenome_disasm(&q, &rs);
		if (rs.status != KGENOME_OK && rs.status != KGENOME_UNSUPPORTED) {
			printf("%08llx (data)\n", (unsigned long long)(off + at));
			at += rs.len ? rs.len : 1u;
			continue;
		}
		printf("%08llx %s\n", (unsigned long long)(off + at), text);
		at += rs.len ? rs.len : 1u;
	}
}

/* mode: 0 the engine's text, 1 the Overview rows, 2 the Graph rows, 3 the calls as fields, 4 the instructions */
static int dump(const char *path, const char *hex, int mode)
{
	FILE *fp = fopen(path, "rb");
	uint8_t *b;
	long sz;
	struct obj o;
	struct kof_cfgview v;
	struct kof_cfgview_req rq;
	const struct kgenome_func *f;
	const uint64_t off = strtoull(hex, NULL, 16);

	if (!fp)
		return 2;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	b = malloc((size_t)sz);
	if (!b || fread(b, 1, (size_t)sz, fp) != (size_t)sz) {
		fclose(fp);
		return 2;
	}
	fclose(fp);
	if (!obj_open(&o, b, (uint64_t)sz))
		return 3;
	f = func_by_off(&o, off);
	request(&rq, &o, off, f ? f->len : 0);
	if (mode == 4) {
		print_insns(&o, off, f ? f->len : 0);
	} else if (mode == 3) {
		uint32_t i;

		(void)kof_cfgview_build(&rq, &v);
		for (i = 0; i < v.n_call; i++)
			if (v.call[i].target == KGENOME_BROKEN)
				printf("B%u 0x%llx %u - %s\n", (unsigned)v.call[i].blk, (unsigned long long)v.call[i].at, (unsigned)v.call[i].kind, v.call[i].name);
			else
				printf("B%u 0x%llx %u 0x%llx %s\n", (unsigned)v.call[i].blk, (unsigned long long)v.call[i].at, (unsigned)v.call[i].kind,
				       (unsigned long long)v.call[i].target, v.call[i].name);
		kof_cfgview_free(&v);
	} else if (mode == 1 || mode == 2) {
		/* the rows of the CFG dialog (kv_cfgbody.c) from column 0, 4000 columns wide: a screen is compared with a window of them */
		struct kv_cfg_body bd;
		static char row[16384];
		uint32_t r, n_row, n_col;

		kv_cfgbody_make(&bd, &rq);
		bd.tab = mode == 1 ? KV_CFG_TAB_OVERVIEW : KV_CFG_TAB_GRAPH;
		kv_cfgbody_size(&bd, bd.tab, &n_row, &n_col);
		printf("%u %u\n", n_row, n_col);
		for (r = 0; r < n_row; r++) {
			char *e;

			char *w, *q;

			kv_cfgbody_row(&bd, r, 0, 4000, row, sizeof row);
			for (w = q = row; *q; q++) {            /* the rows are compared as text: the colour escapes the Graph rows carry are taken out */
				if (*q == 0x1b) {
					while (*q && *q != 'm')
						q++;
					if (!*q)
						break;
					continue;
				}
				*w++ = *q;
			}
			*w = 0;
			for (e = row + strlen(row); e > row && e[-1] == ' '; e--)
				;
			*e = 0;
			puts(row);
		}
		kv_cfgbody_free(&bd);
	} else {
		(void)kof_cfgview_build(&rq, &v);
		fputs(v.text ? v.text : "", stdout);
		kof_cfgview_free(&v);
	}
	obj_close(&o);
	free(b);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "--write")) {
		uint8_t *img;
		const uint64_t n = write_scene(&img);
		FILE *fp = fopen(argv[2], "wb");

		if (!fp || fwrite(img, 1, (size_t)n, fp) != (size_t)n)
			return 2;
		fclose(fp);
		free(img);
		return 0;
	}
	if (argc == 3)
		return dump(argv[1], argv[2], 0);
	if (argc == 5 && !strcmp(argv[3], "--body"))
		return dump(argv[1], argv[2], !strcmp(argv[4], "overview") ? 1 : 2);
	if (argc == 4 && !strcmp(argv[3], "--calls"))
		return dump(argv[1], argv[2], 3);
	if (argc == 4 && !strcmp(argv[3], "--insn"))
		return dump(argv[1], argv[2], 4);
	self_test();
	one_name();
	if (fails) {
		printf("cfg_view_scene: %d failure(s)\n", fails);
		return 1;
	}
	printf("cfg_view_scene: ok\n");
	return 0;
}
