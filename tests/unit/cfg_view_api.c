/*
 * cfg_view_api - the engine's answer to "what is the shape of this function" (kof_cfgview_build, analyzers/cfgview.c), which the viewer's
 * press on the name of a function row asks and shows without computing anything of its own.
 *
 * WHAT IT PINS. For functions ASSEMBLED AT RUN TIME (the kit of the cfg lib tests: abstract programs spelled in x86-64, i386, ARM, ARM big-endian,
 * AArch64, MIPS and MIPS big-endian; random graphs and hand-shaped ones; nothing stored, nothing malware-shaped) placed inside an object at an
 * offset of their own, the engine's answer equals what kgenome_cfg_* gives DIRECTLY on the same bytes decoded by the lib's decoder: the canonical
 * hash, the 32 keys, the block, edge and total counts, every block's offset, instruction count, terminator, successors, degrees and label, and the
 * anchor. A big-endian stream is decoded big-endian (the engine's untraced reader used to read it byte-reversed: CV-1). Around that: a row that is
 * not a function, an extent that leaves the object, a function cut inside its last instruction (TRUNCATED, a graph all the same), a function below
 * and above the anchor, a huge function against a budget (OVER_BUDGET, nothing claimed) and against the default (answered, time printed), the call
 * table (kinds, blocks, names that are the object's own and `fcn_<offset>` where nothing names), the text equal to the lib's own drawing of the
 * same view, and the time of the ask for a small and a large function.
 */
#define _POSIX_C_SOURCE 200809L
#include "../lib/genome/cfg_kit.h"
#include "../../libkofeng/analyzers/cfgview.h"
#include "../../libkofeng/analyzers/genome_obj.h"

#define BASE_OFF 0x40u          /* where the function sits in the object */
#define PAD_AFTER 0x30u

static const struct isa_t ISA_ARM_BE = { KGENOME_ARCH_ARM, 1, "arm-be" };

struct scene {
	uint8_t *obj;
	uint64_t n;
	struct kof_obj_ctx ctx;
	struct kgenome_elf_info ei;
	struct kgenome_func_set fs;
	uint64_t f_off, f_len;
};

static void scene_free(struct scene *s)
{
	free(s->obj);
	free(s->fs.v);
	memset(s, 0, sizeof *s);
}

/* An object holding `len` bytes of code at BASE_OFF, described as an ELF of this architecture and byte order, with its one function listed. */
static void scene_make(struct scene *s, const struct isa_t *isa, const uint8_t *code, uint32_t len)
{
	memset(s, 0, sizeof *s);
	s->n = (uint64_t)BASE_OFF + len + PAD_AFTER;
	s->obj = calloc((size_t)s->n, 1);
	memcpy(s->obj + BASE_OFF, code, len);
	s->ei.elf_data = isa->be ? KGENOME_ELFDATA_BE : 1;
	s->ctx.format = KOF_FMT_ELF;
	s->ctx.arch = (uint8_t)isa->arch;
	s->ctx.obj_size = s->n;
	s->ctx.file_header = &s->ei;
	s->fs.v = calloc(2, sizeof *s->fs.v);
	s->fs.v[0].off = s->f_off = BASE_OFF;
	s->fs.v[0].len = s->f_len = len;
	s->fs.n = 1;
}

static void request(struct kof_cfgview_req *rq, const struct scene *s)
{
	memset(rq, 0, sizeof *rq);
	rq->ctx = &s->ctx;
	rq->data = kof_buf_make(s->obj, s->n);
	rq->func_off = s->f_off;
	rq->func_len = s->f_len;
	rq->funcs = &s->fs;
}

/* The lib's answer on the same bytes, straight: decode with the lib's decoder at the address the engine uses (the file offset: the scene maps nothing). */
struct direct {
	struct kgenome_cell_insn *in;
	struct kgenome_cfg g;
	struct kgenome_cfg_sign s;
	uint64_t *label;
	uint32_t n_in;
};

static int direct_make(struct direct *d, const struct isa_t *isa, const struct prog *p)
{
	struct blob x;
	struct kgenome_cfg_req rq;
	struct kgenome_cfg_sign_req sq;

	memset(d, 0, sizeof *d);
	if (!blob_make(isa, p, BASE_OFF, &x))
		return 0;
	d->n_in = blob_decode(isa, &x, &d->in);
	memset(&rq, 0, sizeof rq);
	rq.in = d->in; rq.n_in = d->n_in; rq.arch = isa->arch; rq.be = isa->be;
	rq.va_lo = BASE_OFF; rq.va_hi = BASE_OFF + x.len; rq.bytes = x.b; rq.bytes_len = x.len;
	CK(kgenome_cfg_build(&rq, &d->g) == KGENOME_OK);
	d->label = calloc(d->g.n_all, sizeof *d->label);
	memset(&sq, 0, sizeof sq);
	sq.g = &d->g; sq.label = d->label;
	CK(kgenome_cfg_sign(&sq, &d->s) == KGENOME_OK);
	blob_free(&x);
	return 1;
}

static void direct_free(struct direct *d)
{
	kgenome_cfg_free(&d->g, NULL);
	free(d->in);
	free(d->label);
}

/* The engine's view is the lib's graph, field for field. `where` names the case for a failure line. */
static void same_as_direct(const struct kof_cfgview *v, const struct direct *d, const char *where)
{
	uint32_t i, k = 0;

	CKM(v->status == KGENOME_OK, "%s: status %d", where, (int)v->status);
	CKM(v->view.canon == d->s.canon && v->view.n_key == d->s.n_key && !memcmp(v->view.key, d->s.key, sizeof d->s.key), "%s: signature differs", where);
	CKM(v->view.n_blk == d->g.n_blk && v->view.n_edge == d->g.n_edge && v->n_all == d->g.n_all && v->view.n_unr == d->g.n_all - d->g.n_blk,
	    "%s: counts differ (blk %u/%u edge %u/%u all %u/%u)", where, v->view.n_blk, d->g.n_blk, v->view.n_edge, d->g.n_edge, v->n_all, d->g.n_all);
	CKM(v->n_insn == d->n_in, "%s: decoded %u instructions, direct %u", where, v->n_insn, d->n_in);
	CKM(v->anchor_pass == (d->g.n_blk >= KGENOME_CFG_ANCHOR_MIN) && v->anchor_min == KGENOME_CFG_ANCHOR_MIN, "%s: anchor", where);
	for (i = 0; i < d->g.n_all; i++) {
		const struct kgenome_cfg_block *b = &d->g.b[i];

		if (!b->reach)
			continue;
		if (k >= v->view.n_blk)
			break;
		{
			const struct kgenome_cfg_view_block *o = &v->view.blk[k];
			uint32_t s0 = b->succ[0] == KGENOME_CFG_NONE ? KGENOME_CFG_NONE : 0, s1 = b->succ[1] == KGENOME_CFG_NONE ? KGENOME_CFG_NONE : 0, j, r = 0;

			for (j = 0; j < d->g.n_all; j++) {
				if (j == b->succ[0])
					s0 = r;
				if (j == b->succ[1])
					s1 = r;
				r += d->g.b[j].reach;
			}
			CKM(o->off == BASE_OFF + d->in[b->first].at, "%s: block %u offset %llx", where, k, (unsigned long long)o->off);
			CKM(o->n_insn == b->n_insn && o->term == b->term && o->succ[0] == s0 && o->succ[1] == s1 && o->in_deg == b->in_deg && o->out_deg == b->out_deg &&
			    o->label == (uint32_t)d->label[i] && o->n_call == b->n_call && o->call_kinds == b->call_kinds, "%s: block %u differs", where, k);
		}
		k++;
	}
	CKM(k == v->view.n_blk, "%s: %u reachable blocks walked of %u", where, k, v->view.n_blk);
}

/* a graph the generator makes: random kinds and targets, the last block a ret */
static void rgraph(struct gspec *g, struct crng *r, uint32_t nb)
{
	uint32_t i;

	memset(g, 0, sizeof *g);
	g->nb = nb;
	for (i = 0; i < nb; i++) {
		const uint32_t roll = crng_below(r, 100);

		g->kind[i] = i + 1u == nb ? G_EXIT : roll < 15 ? G_EXIT : roll < 45 ? G_FALL : roll < 65 ? G_JUMP : G_COND;
		g->t[i] = crng_below(r, nb);
		g->pad[i] = (uint8_t)crng_below(r, 3);
		g->calls[i] = (uint8_t)(crng_below(r, 10) == 0);
	}
}

static void equal_to_direct(void)
{
	static const struct isa_t *const isas[] = { &ISAS[0], &ISAS[1], &ISAS[2], &ISA_ARM_BE, &ISAS[3], &ISAS[4], &ISAS[5] };
	struct crng rng;
	uint32_t a, seed;

	crng_seed(&rng, 20261030);
	for (a = 0; a < sizeof isas / sizeof *isas; a++) {
		const struct isa_t *isa = isas[a];

		for (seed = 0; seed < 40; seed++) {
			struct gspec g;
			struct prog p;
			struct blob x;
			struct scene s;
			struct kof_cfgview_req rq;
			struct kof_cfgview v;
			struct direct d;
			char where[64];

			rgraph(&g, &rng, 4u + seed % 28u);
			gspec_prog(&g, &p, NULL);
			snprintf(where, sizeof where, "%s seed %u", isa->name, seed);
			if (!blob_make(isa, &p, BASE_OFF, &x)) {
				prog_free(&p);
				continue;
			}
			scene_make(&s, isa, x.b, x.len);
			request(&rq, &s);
			CKM(kof_cfgview_build(&rq, &v) == 1, "%s: no graph (%s)", where, v.text ? v.text : "?");
			if (direct_make(&d, isa, &p)) {
				same_as_direct(&v, &d, where);
				CKM(v.be == isa->be, "%s: decoded %s", where, v.be ? "big-endian" : "little-endian");
				direct_free(&d);
			}
			kof_cfgview_free(&v);
			scene_free(&s);
			blob_free(&x);
			prog_free(&p);
		}
	}
}

static void not_a_function(void)
{
	struct gspec g;
	struct prog p;
	struct blob x;
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;

	memset(&g, 0, sizeof g);
	g.nb = 3;
	g.kind[0] = G_COND; g.t[0] = 2; g.kind[1] = G_FALL; g.kind[2] = G_EXIT;
	gspec_prog(&g, &p, NULL);
	CK(blob_make(&ISAS[0], &p, BASE_OFF, &x));
	scene_make(&s, &ISAS[0], x.b, x.len);
	request(&rq, &s);
	CK(kof_cfgview_build(&rq, &v) == 1 && v.status == KGENOME_OK);
	kof_cfgview_free(&v);
	/* an offset or a size that is not an entry of the function table: a data row, a window inside a function, the right offset with another size */
	rq.func_off = BASE_OFF + 1u;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT && v.text && strstr(v.text, "not a function") && !v.view.blk && !v.call);
	kof_cfgview_free(&v);
	rq.func_off = BASE_OFF; rq.func_len = s.f_len - 1u;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT && strstr(v.text, "not a function"));
	kof_cfgview_free(&v);
	/* an extent that leaves the object, one of size 0, an offset past the end, no object */
	rq.func_len = s.n;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT && strstr(v.text, "not inside the object"));
	kof_cfgview_free(&v);
	rq.func_off = s.n; rq.func_len = 1;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT);
	kof_cfgview_free(&v);
	rq.func_off = BASE_OFF; rq.func_len = 0;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT);
	kof_cfgview_free(&v);
	rq.func_len = s.f_len; rq.data.p = NULL;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_BAD_INPUT);
	kof_cfgview_free(&v);
	rq.data = kof_buf_make(s.obj, s.n);
	CK(kof_cfgview_build(NULL, &v) == 0 && v.status == KGENOME_BAD_INPUT);
	kof_cfgview_free(&v);
	/* without a function table the extent is the caller's word */
	rq.funcs = NULL; rq.func_off = BASE_OFF; rq.func_len = s.f_len;
	CK(kof_cfgview_build(&rq, &v) == 1 && v.status == KGENOME_OK);
	kof_cfgview_free(&v);
	/* an architecture the cfg table has no row for */
	rq.funcs = &s.fs; s.ctx.arch = (uint8_t)KGENOME_ARCH_OTHER;
	CK(kof_cfgview_build(&rq, &v) == 0 && v.status == KGENOME_UNSUPPORTED && v.text && strstr(v.text, "no control-flow rules"));
	kof_cfgview_free(&v);
	scene_free(&s);
	blob_free(&x);
	prog_free(&p);
}

/* A function cut inside its last instruction: TRUNCATED, and the graph of what decoded is still made. */
static void truncated(void)
{
	static const uint8_t code[] = { 0x90, 0x74, 0x02, 0x90, 0x90, 0xc3, 0xb8, 0x11, 0x22 };     /* nop; jz +2; nop; nop; ret; mov eax, imm32 (cut after 3 of 5) */
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;

	scene_make(&s, &ISAS[0], code, sizeof code);
	request(&rq, &s);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.status == KGENOME_TRUNCATED, "status %d", (int)v.status);
	CK(v.view.n_blk >= 3 && v.n_skip == 1 && v.view.canon != 0 && strstr(v.text, "skipped-bytes=1") != NULL && v.text && strstr(v.text, "status=truncated"));
	kof_cfgview_free(&v);
	/* the same function with its last instruction whole: complete */
	{
		static const uint8_t whole[] = { 0x90, 0x74, 0x02, 0x90, 0x90, 0xc3, 0xb8, 0x11, 0x22, 0x33, 0x44 };

		scene_free(&s);
		scene_make(&s, &ISAS[0], whole, sizeof whole);
		request(&rq, &s);
		CK(kof_cfgview_build(&rq, &v) == 1 && v.status == KGENOME_OK && v.n_insn == 6 && v.n_skip == 0);
		kof_cfgview_free(&v);
	}
	scene_free(&s);
}

static void anchor(void)
{
	uint32_t nb;

	for (nb = 8; nb <= 16; nb += 4) {
		struct gspec g;
		struct prog p;
		struct blob x;
		struct scene s;
		struct kof_cfgview_req rq;
		struct kof_cfgview v;
		uint32_t i;

		/* nb blocks in a chain of conditional branches: every block is reachable */
		memset(&g, 0, sizeof g);
		g.nb = nb;
		for (i = 0; i < nb; i++) {
			g.kind[i] = i + 1u == nb ? G_EXIT : G_COND;
			g.t[i] = i + 1u == nb ? 0 : nb - 1u;
		}
		gspec_prog(&g, &p, NULL);
		CK(blob_make(&ISAS[0], &p, BASE_OFF, &x));
		scene_make(&s, &ISAS[0], x.b, x.len);
		request(&rq, &s);
		CK(kof_cfgview_build(&rq, &v) == 1);
		CKM(v.view.n_blk == nb, "blocks %u of %u", v.view.n_blk, nb);
		CKM(v.anchor_pass == (v.view.n_blk >= KGENOME_CFG_ANCHOR_MIN), "nb %u: pass %d at %u reachable blocks", nb, v.anchor_pass, v.view.n_blk);
		if (!v.anchor_pass)
			CK(strstr(v.text, ": BELOW\n") != NULL && strstr(v.text, "is not hashed") == NULL);
		else
			CK(strstr(v.text, ": PASS\n") != NULL && strstr(v.text, "is hashed") == NULL);
		kof_cfgview_free(&v);
		/* the caller's own anchor: min 3 passes anything above it, min 1000 passes nothing */
		rq.anchor_min = 3;
		CK(kof_cfgview_build(&rq, &v) == 1 && v.anchor_pass == 1 && v.anchor_min == 3);
		kof_cfgview_free(&v);
		rq.anchor_min = 1000;
		CK(kof_cfgview_build(&rq, &v) == 1 && v.anchor_pass == 0 && strstr(v.text, "< 1000: BELOW") != NULL);
		kof_cfgview_free(&v);
		scene_free(&s);
		blob_free(&x);
		prog_free(&p);
	}
}

/* The call table: kinds, blocks, and names from the object's own tables. */
static void calls(void)
{
	/* nop; call +5 (to the next function); call [rax-style indirect: ff d0]; jz +1; syscall; ret ; the callee at +? is an entry of the table */
	uint8_t code[64];
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;
	uint32_t at = 0, i;
	char want[64];

	memset(code, 0x90, sizeof code);
	code[at++] = 0x90;
	code[at++] = 0xe8; code[at++] = 0x20; code[at++] = 0; code[at++] = 0; code[at++] = 0;      /* call +0x20: a function of the table that nothing names */
	code[at++] = 0xff; code[at++] = 0xd0;                                                       /* call rax */
	code[at++] = 0x74; code[at++] = 0x01;                                                       /* jz +1 */
	code[at++] = 0x90;
	code[at++] = 0x0f; code[at++] = 0x05;                                                       /* syscall */
	code[at++] = 0xe8; code[at++] = 0xf0; code[at++] = 0xff; code[at++] = 0xff; code[at++] = 0x7f;   /* call far outside the object */
	code[at++] = 0xc3;
	scene_make(&s, &ISAS[0], code, 48);
	s.fs.v[1].off = BASE_OFF + 0x20u + 6u + 0u;      /* the target of the first call: 0x40 + 1 + 5 + 0x20 */
	s.fs.v[1].off = BASE_OFF + 1u + 5u + 0x20u;
	s.fs.v[1].len = 8;
	s.fs.n = 2;
	request(&rq, &s);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.n_call == 4, "n_call %u", v.n_call);
	if (v.n_call == 4) {
		CK(v.call[0].kind == KGENOME_CFG_CK_DIRECT && v.call[0].at == BASE_OFF + 1u && v.call[0].target == s.fs.v[1].off);
		snprintf(want, sizeof want, "fcn_%08llx", (unsigned long long)s.fs.v[1].off);
		CKM(!strcmp(v.call[0].name, want), "name '%s' want '%s'", v.call[0].name, want);
		CK(v.call[1].kind == KGENOME_CFG_CK_INDIRECT && !strcmp(v.call[1].name, "indirect") && v.call[1].target == KGENOME_BROKEN);
		CK(v.call[2].kind == KGENOME_CFG_CK_SYSCALL && !strcmp(v.call[2].name, "syscall"));
		CK(v.call[3].kind == KGENOME_CFG_CK_DIRECT && !strcmp(v.call[3].name, "outside the object") && v.call[3].target == KGENOME_BROKEN);
		/* the block of each: the calls before the jz are in block 0, the ones after it in the blocks the view lists next */
		CK(v.call[0].blk == 0 && v.call[1].blk == 0 && v.call[2].blk > 0 && v.call[3].blk >= v.call[2].blk);
		for (i = 0; i < 4; i++)
			CK(v.call[i].blk < v.view.n_blk);
	}
	CK(v.text && strstr(v.text, "calls: 4") && strstr(v.text, "-> fcn_") && strstr(v.text, "syscall") && !strstr(v.text, "not evidence") && strstr(v.text, "calls: 4\n"));
	kof_cfgview_free(&v);
	scene_free(&s);
}

/* Calls after an UNREACHABLE block: the block a call is in is its place in the view (reachable blocks only), not its place in the extent; and a
 * function with more calls than the graph holds notes for lists the first and counts the rest. */
static uint32_t count_lines_with(const char *t, const char *prefix)
{
	uint32_t n = 0;
	const char *p = t;

	while (*p) {
		if (!strncmp(p, prefix, strlen(prefix)))
			n++;
		p = strchr(p, '\n');
		if (!p)
			break;
		p++;
	}
	return n;
}

static void calls_blocks_and_counts(void)
{
	uint8_t code[1024];
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;
	uint32_t at = 0, i;
	char want[64];

	memset(code, 0x90, sizeof code);
	/* jmp +4 over four int3 (a block nothing reaches), then a call, a ret; then 100 calls and a ret in a block of their own after a jz */
	code[at++] = 0xeb; code[at++] = 0x04;
	for (i = 0; i < 4; i++)
		code[at++] = 0xcc;
	code[at++] = 0xe8; code[at++] = 0x00; code[at++] = 0x00; code[at++] = 0x00; code[at++] = 0x00;          /* call +0: to the next instruction */
	code[at++] = 0x74; code[at++] = 0x00;                                                                   /* jz +0 */
	for (i = 0; i < 100; i++) {
		code[at++] = 0xe8; code[at++] = 0x00; code[at++] = 0x00; code[at++] = 0x00; code[at++] = 0x00;
	}
	code[at++] = 0xc3;
	scene_make(&s, &ISAS[0], code, at);
	request(&rq, &s);
	CK(kof_cfgview_build(&rq, &v) == 1);
	CKM(v.view.n_unr == 1 && v.n_call == 101, "unreachable %u calls %u", v.view.n_unr, v.n_call);
	if (v.n_call == 101) {
		/* layout: block 0 = jmp, block 1 = the int3s (unreachable), block 2 = call + jz, block 3 = the 100 calls: view indices 0, -, 1, 2 */
		CKM(v.call[0].blk == 1, "the first call is in view block %u, want 1 (layout block 2)", v.call[0].blk);
		CKM(v.call[1].blk == 2 && v.call[100].blk == 2, "the 100 calls are in view block %u / %u, want 2", v.call[1].blk, v.call[100].blk);
	}
	/* 48 notes are held, the rest counted: 24 listed, the other 77 said in a line */
	CKM(v.gv.n_note == KOF_CFGVIEW_NOTES && v.gv.note_total == 101, "notes held %u total %u", v.gv.n_note, v.gv.note_total);
	snprintf(want, sizeof want, "... %u more note(s) not listed", 101u - KOF_CFGVIEW_CALL_LINES);
	CKM(strstr(v.text, want) != NULL, "no '%s' in the text", want);
	CK(strstr(v.text, "calls: 101") != NULL && count_lines_with(v.text, "  B") >= KOF_CFGVIEW_CALL_LINES);
	kof_cfgview_free(&v);
	scene_free(&s);
}

/* The facts text and THE GRAPH the engine returned (v.gv): the function's own lines first, the counts, the hashes, the anchor, the calls; the graph's edges carry cond and loop
 * as the engine decided them, a loop head is marked in its first row, and no legend or letters line is there. */
static void text_is_the_facts(void)
{
	struct gspec g;
	struct prog p;
	struct blob x;
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;
	uint32_t i, k, links = 0, heads = 0;

	memset(&g, 0, sizeof g);
	g.nb = 14;
	for (i = 0; i < 14; i++) {
		g.kind[i] = i == 13 ? G_EXIT : (i % 3 == 2 ? G_COND : G_FALL);
		g.t[i] = i % 3 == 2 && i > 3 ? i - 3u : 13u;
		g.calls[i] = i == 4;
	}
	gspec_prog(&g, &p, NULL);
	CK(blob_make(&ISAS[0], &p, BASE_OFF, &x));
	scene_make(&s, &ISAS[0], x.b, x.len);
	request(&rq, &s);
	CK(kof_cfgview_build(&rq, &v) == 1 && v.text);
	CK(!strncmp(v.text, "function ", 9) && strstr(v.text, "x86-64") && strstr(v.text, "little-endian") && strstr(v.text, "instructions="));
	CK(strstr(v.text, "extent  0x40 +") != NULL && strstr(v.text, "calls=1") != NULL);
	CK(strstr(v.text, "legend") == NULL && strstr(v.text, "letters") == NULL);
	CK(v.n_top == 3 && v.n_lines >= 6);
	/* the head carries what the researcher decides by: counts, anchor, canon, keys, status */
	{
		char want[64];

		snprintf(want, sizeof want, "canon  0x%016llx", (unsigned long long)v.view.canon);
		CK(strstr(v.text, want) != NULL);
		snprintf(want, sizeof want, "keys   %08x", (unsigned)v.view.key[0]);
		CK(strstr(v.text, want) != NULL);
		snprintf(want, sizeof want, "CFG  reachable=%u  edges=%u  unreachable=%u  all=%u  status=ok", v.view.n_blk, v.view.n_edge, v.view.n_unr, v.n_all);
		CKM(strstr(v.text, want) != NULL, "no counts line '%s'", want);
		snprintf(want, sizeof want, "anchor  %u reachable blocks %s %u: %s", v.view.n_blk, v.view.n_blk >= KGENOME_CFG_ANCHOR_MIN ? ">=" : "<", KGENOME_CFG_ANCHOR_MIN,
			 v.view.n_blk >= KGENOME_CFG_ANCHOR_MIN ? "PASS" : "BELOW");
		CKM(strstr(v.text, want) != NULL && v.anchor_pass == (v.view.n_blk >= KGENOME_CFG_ANCHOR_MIN), "anchor line '%s' (blocks %u)", want, v.view.n_blk);
	}
	CK(v.gv.n_node == v.view.n_blk && v.gv.n_edge == v.view.n_edge);
	CK(v.gv.n_note == 1 && v.gv.note_total == 1 && strstr(v.gv.note[0].text, "call") != NULL && !strcmp(v.gv.note_title, "calls: 1"));
	CK(v.gv.n_aside == v.view.n_unr && v.gv.id_prefix == 'B');
	/* the kinds: a branch's edges stand fall-through first and taken second (T F as cond), the others have no cond; blocks 5, 8, 11 jump back to 2, 5, 8 */
	for (i = 0; i < v.gv.n_node; i++) {
		const struct kgenome_gv_edge *e0 = NULL;
		uint32_t n = 0;

		for (k = 0; k < v.gv.n_edge; k++)
			if (v.gv.edge[k].from == i) {
				if (!n++)
					e0 = &v.gv.edge[k];
				else
					CK(v.gv.edge[k].cond == KGENOME_GV_COND_T && e0->cond == KGENOME_GV_COND_F);
			}
		if (n == 1)
			CK(e0->cond == KGENOME_GV_COND_NONE);
	}
	for (k = 0; k < v.gv.n_edge; k++)
		links += v.gv.edge[k].loop == KGENOME_GV_LOOP_LINK;
	for (i = 0; i < v.gv.n_node; i++)
		heads += (v.gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0 && strstr(v.gv.node[i].line[0], " @ ") != NULL;
	CKM(links == 3 && heads == 3, "loop links %u (want 3), marked heads %u (want 3)", links, heads);
	CK(v.gv.n_xline == 1 && v.gv.xline[0].node < v.gv.n_node && strstr(v.gv.xline[0].text, "call") != NULL);
	/* the same ask twice: the same bytes (nothing in the text depends on time or on an address of the process) */
	{
		struct kof_cfgview v2;

		CK(kof_cfgview_build(&rq, &v2) == 1 && v2.text_len == v.text_len && !strcmp(v.text, v2.text));
		kof_cfgview_free(&v2);
	}
	kof_cfgview_free(&v);
	scene_free(&s);
	blob_free(&x);
	prog_free(&p);
}

static double va_now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* A huge function against a budget and against the default, and the time of the ask. */
static void budget_and_time(void)
{
	enum { REPEAT = 20000 };
	const uint32_t len = REPEAT * 4u;
	uint8_t *code = malloc(len);
	struct scene s;
	struct kof_cfgview_req rq;
	struct kof_cfgview v;
	uint32_t i;
	double t0, small_ms, big_ms;
	uint64_t max_ok = 0, m;
	uint32_t big_blk = 0, big_drawn = 0;

	/* 20000 times `jz +1; nop; nop`: three blocks every four bytes, every one reachable */
	for (i = 0; i < REPEAT; i++) {
		code[4u * i] = 0x74; code[4u * i + 1u] = 0x01; code[4u * i + 2u] = 0x90; code[4u * i + 3u] = 0x90;
	}
	code[len - 1u] = 0xc3;
	scene_make(&s, &ISAS[0], code, len);
	request(&rq, &s);
	/* the default allowance answers with every block in the graph (the viewer's drawing bounds what is drawn, and counts the rest) */
	t0 = va_now_ms();
	CK(kof_cfgview_build(&rq, &v) == 1);
	big_ms = va_now_ms() - t0;
	CKM(v.status <= KGENOME_TRUNCATED && v.view.n_blk > 40000 && v.gv.n_node == v.view.n_blk && v.n_insn == REPEAT * 3u,
	    "default: status %d blocks %u graph nodes %u insn %u", (int)v.status, v.view.n_blk, v.gv.n_node, v.n_insn);
	big_blk = v.view.n_blk;
	big_drawn = v.gv.n_edge;
	kof_cfgview_free(&v);
	/* a budget below what the instructions need: OVER_BUDGET, no graph claimed, nothing held (the free is a no-op on what was never made) */
	for (m = 1u << 12; m <= (8u << 20); m <<= 1) {
		rq.max_bytes = m;
		if (kof_cfgview_build(&rq, &v)) {
			if (!max_ok)
				max_ok = m;
			CKM(v.view.n_blk > 0 && v.view.canon != 0, "budget %llu: answered with no blocks", (unsigned long long)m);
		} else {
			CKM(v.status == KGENOME_OVER_BUDGET && !max_ok && v.text && strstr(v.text, "allowance") && !v.view.blk && !v.call && v.view.n_blk == 0,
			    "budget %llu: status %d", (unsigned long long)m, (int)v.status);
		}
		kof_cfgview_free(&v);
	}
	CK(max_ok > (1u << 12));
	rq.max_bytes = 0;
	scene_free(&s);
	free(code);
	/* a small function, 14 blocks: the time of the ask (the viewer pays it at the click) */
	{
		struct gspec g;
		struct prog p;
		struct blob x;
		uint32_t rep;

		memset(&g, 0, sizeof g);
		g.nb = 14;
		for (i = 0; i < 14; i++) {
			g.kind[i] = i == 13 ? G_EXIT : (i % 3 == 2 ? G_COND : G_FALL);
			g.t[i] = i % 3 == 2 && i > 3 ? i - 3u : 13u;
		}
		gspec_prog(&g, &p, NULL);
		CK(blob_make(&ISAS[0], &p, BASE_OFF, &x));
		scene_make(&s, &ISAS[0], x.b, x.len);
		request(&rq, &s);
		t0 = va_now_ms();
		for (rep = 0; rep < 200; rep++) {
			CK(kof_cfgview_build(&rq, &v) == 1);
			kof_cfgview_free(&v);
		}
		small_ms = (va_now_ms() - t0) / 200.0;
		scene_free(&s);
		blob_free(&x);
		prog_free(&p);
	}
	CKM(small_ms < 20.0 && big_ms < 2000.0, "small %.3f ms big %.1f ms", small_ms, big_ms);
	printf("  ask time: 14-block function %.3f ms, %u-block function (%u bytes, %u edges in the graph) %.1f ms\n", small_ms, big_blk, len, big_drawn, big_ms);
}

int main(void)
{
	equal_to_direct();
	not_a_function();
	truncated();
	anchor();
	calls();
	calls_blocks_and_counts();
	text_is_the_facts();
	budget_and_time();
	if (fails) {
		printf("cfg_view_api: %d failure(s)\n", fails);
		return 1;
	}
	printf("cfg_view_api: ok\n");
	return 0;
}
