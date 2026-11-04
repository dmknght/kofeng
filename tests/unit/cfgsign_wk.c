/*
 * cfgsign_wk - kof_cfgsign_function reads the object's walk (req.wk) instead of decoding again, and gives the same answer either way.
 *
 * Phase A1 passes the walk of the object to the signing of a function (scan_feed.c: `rq.wk = ...obj.diag.walk`). Its claim: on a walk that holds a trace the function is READ from the
 * trace and no instruction is decoded. Rows: (1) the answer is identical with and without the walk, for every function of an x86-64 object, in 3 fixtures; (2) with the walk the
 * decoder is called 0 times, without it more than 0 (the decoder is wrapped: UNIT_LIBS_cfgsign_wk); (3) a walk that holds no trace, or was built over other bytes (the view), is NOT
 * read (the decoder is called) and the answer is the same; (4) every state of the answer and every allocation of the call failing once.
 * Why the old tests missed a wrong read: (a) the trace branch of kgenome_diag_code_run ran only through the codemap, never through this caller; (c) the signing tests compared
 * "state == SIGNED", not the signature against the decode path.
 */
#include "../lib/genome/fntab_kit.h"

#include <kofmod/kofsig.h>
#include "../../libkofeng/analyzers/cfgsign.h"
#include "../../libkofeng/analyzers/genome_obj.h"

static unsigned long n_decode;
uint32_t __wrap_kgenome_cell_decode(int arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out);
uint32_t __real_kgenome_cell_decode(int arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out);
uint32_t __wrap_kgenome_cell_decode(int arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out)
{
	n_decode++;
	return __real_kgenome_cell_decode(arch, be, p, n, va, out);
}

/* a host allocator that fails the Nth call */
struct fhost { unsigned n, fail_at, live; };
static void *h_alloc(void *u, size_t n) { struct fhost *h = u; if (++h->n == h->fail_at) return NULL; h->live++; return malloc(n); }
static void h_release(void *u, void *p, size_t n) { struct fhost *h = u; (void)n; if (p) { h->live--; free(p); } }

/* a richer x86-64 function set than x86_text: a loop, a branch, two calls */
static uint32_t rich(uint8_t *t)
{
	memset(t, 0xcc, 0x80);
	/* 0x00: push rbp; mov rbp,rsp; xor eax,eax; L: inc eax; cmp eax,5; jl L; call 0x40; pop rbp; ret */
	memcpy(t, "\x55\x48\x89\xe5\x31\xc0\xff\xc0\x83\xf8\x05\x7c\xf9", 13);
	t[13] = 0xe8; { int32_t d = 0x40 - 18; memcpy(t + 14, &d, 4); }
	t[18] = 0x5d; t[19] = 0xc3;
	/* 0x20: test edi,edi; je +3; mov eax,1; ret; xor eax,eax; ret */
	memcpy(t + 0x20, "\x85\xff\x74\x06\xb8\x01\x00\x00\x00\xc3\x31\xc0\xc3", 13);
	/* 0x40: the callee: mov eax,7; ret */
	memcpy(t + 0x40, "\xb8\x07\x00\x00\x00\xc3", 6);
	/* 0x60: a function of data: not instructions */
	memset(t + 0x60, 0x06, 0x10);
	return 0x80;
}

struct fixture { const char *name; const struct fde *f; unsigned nf; uint32_t (*text)(uint8_t *); };
static const struct fde ff_x86[4] = { { 0, 11 }, { 0x10, 6 }, { 0x20, 8 }, { 0x30, 6 } };
static const struct fde ff_rich[4] = { { 0, 20 }, { 0x20, 13 }, { 0x40, 6 }, { 0x60, 16 } };

static void sign_cmp(const struct kof_obj_ctx *ctx, const uint8_t *file, uint32_t n, uint64_t off, uint64_t len, struct kgenome_diag_walk *wk, const char *what)
{
	struct kof_cfgsign_req rq;
	struct kof_cfgsign a, b;
	unsigned long da, db;

	memset(&rq, 0, sizeof rq);
	rq.ctx = ctx; rq.data = kof_buf_make(file, n); rq.off = off; rq.len = len;
	n_decode = 0; rq.wk = NULL;
	(void)kof_cfgsign_function(&rq, &a);
	db = n_decode;
	n_decode = 0; rq.wk = wk;
	(void)kof_cfgsign_function(&rq, &b);
	da = n_decode;
	if (a.state != b.state || a.n_insn != b.n_insn || a.n_skip != b.n_skip || a.func_va != b.func_va || a.status != b.status ||
	    memcmp(&a.sign, &b.sign, sizeof a.sign) != 0) {
		printf("  [%s off=%llx] differs: state %d/%d insn %u/%u skip %llu/%llu\n", what, (unsigned long long)off, a.state, b.state, a.n_insn, b.n_insn,
		       (unsigned long long)a.n_skip, (unsigned long long)b.n_skip);
		fails++;
	}
	/* with a trace walk the decoder is not called for a function the walk decoded; without a walk it always is */
	CK(db > 0 || a.state == KOF_CFGSIGN_UNDECODABLE);
	if (wk && a.state == KOF_CFGSIGN_SIGNED && b.n_insn)
		CK(da == 0 || da < db);
}

static void t_same_answer(void)
{
	static const struct fixture fx[] = { { "x86", ff_x86, 4, NULL }, { "rich", ff_rich, 4, rich } };
	unsigned i, k;

	for (i = 0; i < 2; i++) {
		static uint8_t TX[0x100];
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		struct kof_obj_ctx ctx;
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		struct kgenome_func_set fs;
		uint32_t n;

		memset(&in, 0, sizeof in);
		in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = fx[i].text ? fx[i].text(TX) : x86_text(TX); in.sections = 1;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		memset(&ctx, 0, sizeof ctx); kof_genome_obj_store(&ctx, &o);
		kgenome_diag_funcs_with_walk(&o, B, n, wk, &fs);
		CK(fs.n >= 2);
		for (k = 0; k < fx[i].nf; k++)
			sign_cmp(&ctx, B, n, TEXT_OFF + fx[i].f[k].off, fx[i].f[k].len, wk, fx[i].name);
		for (k = 0; k < fs.n; k++)                                       /* the table's own entries, as the feed asks */
			sign_cmp(&ctx, B, n, fs.v[k].off, fs.v[k].len, wk, "table");
		/* a walk with NO trace is not read: the decoder runs, the answer is the same */
		{
			struct kgenome_diag_walk *w0 = kgenome_diag_walk_new();
			CK(kgenome_diag_walk_ensure(w0, &o, B, n, 0));
			for (k = 0; k < fx[i].nf; k++) {
				struct kof_cfgsign_req rq;
				struct kof_cfgsign cs;
				memset(&rq, 0, sizeof rq);
				rq.ctx = &ctx; rq.data = kof_buf_make(B, n); rq.off = TEXT_OFF + fx[i].f[k].off; rq.len = fx[i].f[k].len; rq.wk = w0;
				n_decode = 0;
				(void)kof_cfgsign_function(&rq, &cs);
				CK(n_decode > 0);
			}
			kgenome_diag_walk_free(w0);
		}
		/* a walk built over OTHER bytes (a view of the object is another buffer): not read */
		{
			static uint8_t copy[MAXB];
			struct kof_cfgsign_req rq;
			struct kof_cfgsign cs;

			memcpy(copy, B, n);
			memset(&rq, 0, sizeof rq);
			rq.ctx = &ctx; rq.data = kof_buf_make(copy, n); rq.off = TEXT_OFF + fx[i].f[0].off; rq.len = fx[i].f[0].len; rq.wk = wk;
			n_decode = 0;
			(void)kof_cfgsign_function(&rq, &cs);
			CK(n_decode > 0);
			rq.data = kof_buf_make(B, n - 1u);                       /* the same bytes, another size */
			n_decode = 0;
			(void)kof_cfgsign_function(&rq, &cs);
			CK(n_decode > 0);
		}
		kgenome_funcs_free(&fs);
		kgenome_diag_walk_free(wk);
	}
}

static void t_states(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kof_obj_ctx ctx;
	struct kof_cfgsign_req rq;
	struct kof_cfgsign cs;
	struct kof_cfgsign_host host;
	struct fhost fh;
	uint32_t n;
	unsigned k, hit;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = rich(TX); in.sections = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	memset(&ctx, 0, sizeof ctx); kof_genome_obj_store(&ctx, &o);
	memset(&rq, 0, sizeof rq);
	rq.ctx = &ctx; rq.data = kof_buf_make(B, n); rq.off = TEXT_OFF; rq.len = 20;

	CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_SIGNED && cs.sign.n_blk > 0 && cs.n_insn >= 8);
	/* a higher floor than the function has blocks: BELOW_FLOOR, the signature still made */
	rq.floor = 1000;
	CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_BELOW_FLOOR && cs.sign.n_blk > 0);
	rq.floor = 0;
	/* not in the object: undecodable */
	rq.off = n; CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_UNDECODABLE);
	rq.off = TEXT_OFF; rq.len = 0; CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_UNDECODABLE);
	rq.len = (uint64_t)n; CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_UNDECODABLE);       /* past the end */
	rq.len = 20;
	CK(kof_cfgsign_function(NULL, &cs) == KOF_CFGSIGN_UNDECODABLE);
	{ struct kof_cfgsign_req z = rq; z.ctx = NULL; CK(kof_cfgsign_function(&z, &cs) == KOF_CFGSIGN_UNDECODABLE); z = rq; z.data = kof_buf_make(NULL, 0); CK(kof_cfgsign_function(&z, &cs) == KOF_CFGSIGN_UNDECODABLE); }
	/* data: no instruction decodes at the entry */
	rq.off = TEXT_OFF + 0x60; rq.len = 0x10; CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_UNDECODABLE);
	/* an architecture with no rules: unsupported */
	{
		unsigned a;
		const unsigned unsupported[] = { 0, 5, 10, 11, 19, 255 };           /* no decoder / no control-flow row (the architecture list of celllysis/arch.h) */

		for (a = 0; a < sizeof unsupported / sizeof *unsupported; a++) {
			struct kof_obj_ctx c2 = ctx;

			c2.arch = (uint8_t)unsupported[a]; rq.ctx = &c2; rq.off = TEXT_OFF; rq.len = 11;
			CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_UNSUPPORTED);
		}
		rq.ctx = &ctx;
	}
	/* the allowance of one call is smaller than the function needs */
	rq.off = TEXT_OFF; rq.len = 20;
	memset(&host, 0, sizeof host); host.max_bytes = 16;
	rq.host = &host;
	CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_OVER_BUDGET);
	host.max_bytes = 64 * 1024;
	{ const enum kof_cfgsign_state s = kof_cfgsign_function(&rq, &cs); CK(s == KOF_CFGSIGN_SIGNED || s == KOF_CFGSIGN_OVER_BUDGET); }
	host.max_bytes = 0;
	/* keep: the graph and the labels are handed back and released */
	rq.keep = 1;
	CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_SIGNED && cs.in && cs.label && cs.g.n_all > 0);
	kof_cfgsign_release(&cs, NULL);
	CK(cs.in == NULL && cs.label == NULL);
	kof_cfgsign_release(&cs, NULL);
	kof_cfgsign_release(NULL, NULL);
	/* every allocation of the call fails once: a state that says no memory, nothing leaked */
	for (rq.keep = 0; rq.keep < 2; rq.keep++) {
		hit = 0;
		for (k = 1; k < 100; k++) {
			memset(&fh, 0, sizeof fh); fh.fail_at = k;
			memset(&host, 0, sizeof host);
			host.mem.alloc = h_alloc; host.mem.release = h_release; host.mem.user = &fh;
			rq.host = &host;
			{
				const enum kof_cfgsign_state s = kof_cfgsign_function(&rq, &cs);

				if (fh.n >= k) { hit++; CK(s == KOF_CFGSIGN_NOMEM); }
				else CK(s == KOF_CFGSIGN_SIGNED);
				if (rq.keep && s == KOF_CFGSIGN_SIGNED) kof_cfgsign_release(&cs, &host.mem);
			}
			CK(fh.live == 0);                                        /* what the call took, it gave back */
			if (fh.n < k) break;
		}
		CK(hit >= 2 && k < 100);
	}
	CK(!strcmp(kof_cfgsign_state_name(KOF_CFGSIGN_SIGNED), "signed"));
	{ int s; for (s = 0; s < 8; s++) CK(kof_cfgsign_state_name((enum kof_cfgsign_state)s)[0] != 0); }
}

/* a function of more than 256 instructions: the instruction array grows by doubling inside the allowance; every allocation of the growth failing once */
static void t_long_function(void)
{
	static uint8_t TX[0x800];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kof_obj_ctx ctx;
	struct kof_cfgsign_req rq;
	struct kof_cfgsign cs;
	struct kof_cfgsign_host host;
	struct fhost fh;
	uint32_t n;
	unsigned k, hit = 0;

	memset(TX, 0x90, 0x700); TX[0x6ff] = 0xc3;
	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = 0x700; in.sections = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	memset(&ctx, 0, sizeof ctx); kof_genome_obj_store(&ctx, &o);
	memset(&rq, 0, sizeof rq);
	rq.ctx = &ctx; rq.data = kof_buf_make(B, n); rq.off = TEXT_OFF; rq.len = 0x700;
	CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_SIGNED && cs.n_insn == 0x700);
	memset(&host, 0, sizeof host); host.max_bytes = 64;             /* the second doubling does not fit the allowance */
	rq.host = &host;
	CK(kof_cfgsign_function(&rq, &cs) == KOF_CFGSIGN_OVER_BUDGET);
	for (k = 1; k < 100; k++) {
		memset(&fh, 0, sizeof fh); fh.fail_at = k;
		memset(&host, 0, sizeof host);
		host.mem.alloc = h_alloc; host.mem.release = h_release; host.mem.user = &fh;
		rq.host = &host;
		{
			const enum kof_cfgsign_state st = kof_cfgsign_function(&rq, &cs);

			if (fh.n >= k) { hit++; CK(st == KOF_CFGSIGN_NOMEM); } else CK(st == KOF_CFGSIGN_SIGNED);
		}
		CK(fh.live == 0);
		if (fh.n < k) break;
	}
	CK(hit >= 3 && k < 100);          /* the first block, the doubling to 512, the doubling to 1024 */
}

int main(void)
{
	t_long_function();
	t_same_answer();
	t_states();
	printf("cfgsign_wk: %lu checks, %d failure(s)\n", checks, fails);
	return fails != 0;
}
