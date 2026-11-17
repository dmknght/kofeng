/*
 * lineage_sites - THE SITE DISPATCHER and the shapes the generated programs of lineage_ir.h cannot make, each written out as
 * bytes from the instruction set manual (constructed here, no sample's bytes) with its links written by hand from the program:
 *
 *   STAGER    a system-call program of the stager shape: mmap, socket, a connect retried through nanosleep with pushes and pops
 *             that balance on both paths, an exit on every error, then a `syscall` whose NUMBER is connect's result and a `jmp`
 *             into the mmap'd region. Every link is on every path: PROVEN. The number of the read is connect's RESULT (the node's
 *             own carrier: class RESULT, nr_from connect); the jump's TARGET is the region (pushed before the loop, popped after).
 *             Variants: an unbalanced loop, a returning kernel entry (no MUST may come of either), a loop closed by an unconditional
 *             jump, the number through a stack slot, and an exit the sweep misreads in address order (LG-5: the stage must not trust it).
 *             LG-3: a system call was no site of the stage (no input read at all); LG-4: `exit` fell through into the next block,
 *             its stack pointer differed, the region came out MAY; LG-2: a branch node's TARGET was no input of the stage.
 *   I386      the same over `int 0x80`: mmap2's region is read's buffer and the jump's target, the number a CONST.
 *   CLASSES   the number classes: a constant (CONST), arithmetic on a constant (UNKNOWN: the stage computes no value).
 *   CQO       LG-1: `cqo` writes rdx with the sign of rax; a producer left in rdx does not survive it.
 *   OVERWRITE a value overwritten on one path only is MAY, never a wrong PROVEN.
 *   NODES     no node of these routes has an offset outside the object.
 *
 * Why the old tests did not see these: (a) no lineage test held a kernel entry or a branch node (lineage_cg.h generates calls only), so
 * the dispatcher's lines were never executed; (b) the one `cqo` was never in a program with a producer left in rdx.
 *   ORDER     idempotence: the same object scanned twice gives the same links.
 */
#include "lineage_check.h"
#include "lineage_raw.h"


struct rscan {
	struct kgenome_elf_info ei;
	struct kgenome_obj obj;
	struct kgenome_diag_scan *s;
};

static int re_scan_run(struct rscan *r, const struct rawelf *e, unsigned run)
{
	struct kgenome_diag_inputs in;

	memset(r, 0, sizeof *r);
	if (!kgenome_elf_image_parse(kof_buf_make(e->b, e->n), &r->ei, &r->obj))
		return 0;
	r->obj.file_header = &r->ei;
	memset(&in, 0, sizeof in);
	r->s = kgenome_diag_scan_with_inputs(&r->obj, e->b, e->n, run, &in);
	return r->s != NULL;
}

static int re_scan(struct rscan *r, const struct rawelf *e)
{
	return re_scan_run(r, e, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_LINEAGE);
}

static const struct kgenome_diag_hit *node_at(const struct rscan *r, uint64_t at, uint32_t *idx)
{
	uint32_t i, n = kgenome_diag_scan_count(r->s);

	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(r->s, i);

		if (h->at == at && h->cap != KGENOME_NUCLEO_NONE && !(h->bits & KGENOME_DIAG_H_SUPERSEDED)) {
			if (idx)
				*idx = i;
			return h;
		}
	}
	return NULL;
}

/* how the link (from the node at `pat`, role) into the node at `cat` was said: -1 none, else KGENOME_DIAG_LINK_* */
static int link_how(const struct rscan *r, uint64_t cat, uint64_t pat, unsigned role)
{
	const struct kgenome_diag_hit *c = node_at(r, cat, NULL);
	uint32_t pi, k;

	uint32_t ci;

	if (!c || !node_at(r, pat, &pi) || !node_at(r, cat, &ci))
		return -2;
	/* every input of the node, not only its four-input view (kgenome_diag_in_at) */
	for (k = 0; k < kgenome_diag_in_count(r->s, ci); k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(r->s, ci, k);

		if (x && x->from == pi && x->role == role && x->kind == KGENOME_DIAG_KIND_PRODUCED)
			return x->how;
	}
	return -1;
}

/* the node at `at` says its number is of class `cls`, and (for a RESULT) the node at `pat` returned it, `how` sure, `n` producers */
static int nr_is(const struct rscan *r, uint64_t at, unsigned cls, uint64_t pat, unsigned how, unsigned n)
{
	const struct kgenome_diag_hit *h = node_at(r, at, NULL);
	uint32_t pi;

	if (!h) {
		printf("  (no node at 0x%llx)\n", (unsigned long long)at);
		return 0;
	}
	if (h->nr != cls) {
		printf("  (class %u, wanted %u)\n", h->nr, cls);
		return 0;
	}
	if (cls != KGENOME_DIAG_NR_RESULT)
		return 1;
	if (!node_at(r, pat, &pi) || h->nr_from != pi || h->nr_how != how || h->nr_n != n) {
		printf("  (from %u how %u n %u)\n", h->nr_from, h->nr_how, h->nr_n);
		return 0;
	}
	return 1;
}

/* every node is inside the object, and every link names a node or the stack */
static void nodes_inside(const struct rscan *r, uint32_t size, const char *what)
{
	uint32_t i, k, n = kgenome_diag_scan_count(r->s);

	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(r->s, i);

		if (h->at >= size) {
			printf("FAIL %s: node %u at 0x%llx is outside the object (%u bytes)\n", what, i, (unsigned long long)h->at, size);
			hk_fails++;
		}
		for (k = 0; k < h->n_in; k++)
			if (h->in[k].from >= n && h->in[k].from != KGENOME_DIAG_FROM_STACK) {
				printf("FAIL %s: node %u has a link from %u, no node\n", what, i, h->in[k].from);
				hk_fails++;
			}
	}
}

#define EXPECT(cond, ...) do { if (!(cond)) { printf("FAIL " __VA_ARGS__); printf("\n"); hk_fails++; } } while (0)

/* ---- STAGER (x86-64 syscalls) ---- */

struct stager_at {
	uint32_t mmap, sock, conn, sleep, read, jmp;
};

/* The stager and its variants (each a shape that can break a relation):
 *   0  as described above
 *   1  UNBALANCED: the retry path leaves one word more on the stack - the depth at the loop head is not one number
 *   2  RETURNING: the exit replaced by getpid, which returns - control falls into `pop rsi` from a path that never pushed the region
 *   3  JMP LOOP: the retry loop closed by an unconditional jump back
 *   4  NUMBER THROUGH THE STACK: connect's result pushed and popped round a `xor eax, eax` before the branch
 *   5  MISREAD EXIT: the same push/xor/pop AFTER the exit block, at the read: the sweep, reading in address order, takes the exit's 60
 *      for the read's number (no read node), and must not make the stage stop there
 *   6  TWO NUMBERS: a nanosleep that succeeds goes straight to the read - its number is connect's result on one path, nanosleep's on
 *      the other
 *   7  PUSHED EXIT: the exit's number is `push 60; pop rax` (what msfvenom writes) in a block reached at two stack depths - the stage
 *      must still see a constant there (LG-9: the join left the stack pointer unknown, the pop was unknown, the exit was not trusted
 *      and the error path fell through into `pop rsi`) */
static void build_stager_v(struct rawelf *e, struct stager_at *o, int variant)
{
	uint32_t js1, js2, jns_ok, jns_retry, retry, fail, ok, js3;

	re_init(e, 1);
	/* mmap(0, 0x1000, 7, 0x22, -1, 0) */
	re_b(e, "31 ff");                       /* xor edi, edi */
	re_b(e, "be 00 10 00 00");              /* mov esi, 0x1000 */
	re_b(e, "ba 07 00 00 00");              /* mov edx, 7 */
	re_b(e, "41 ba 22 00 00 00");           /* mov r10d, 0x22 */
	re_b(e, "49 c7 c0 ff ff ff ff");        /* mov r8, -1 */
	re_b(e, "45 31 c9");                    /* xor r9d, r9d */
	re_b(e, "b8 09 00 00 00");              /* mov eax, 9 */
	o->mmap = re_here(e);
	re_b(e, "0f 05");                       /* syscall */
	re_b(e, "48 85 c0");                    /* test rax, rax */
	re_b(e, "78 00");                       /* js fail */
	js1 = re_here(e) - 1u;
	re_b(e, "50");                          /* push rax: the region, kept across what follows */
	/* socket(2, 1, 0) */
	re_b(e, "bf 02 00 00 00");              /* mov edi, 2 */
	re_b(e, "be 01 00 00 00");              /* mov esi, 1 */
	re_b(e, "31 d2");                       /* xor edx, edx */
	re_b(e, "b8 29 00 00 00");              /* mov eax, 41 */
	o->sock = re_here(e);
	re_b(e, "0f 05");
	re_b(e, "48 85 c0");
	re_b(e, "78 00");                       /* js fail */
	js2 = re_here(e) - 1u;
	re_b(e, "48 89 c7");                    /* mov rdi, rax: the socket */
	retry = re_here(e);
	re_b(e, "6a 00");                       /* push 0: the address, on the stack */
	re_b(e, "48 89 e6");                    /* mov rsi, rsp */
	re_b(e, "ba 10 00 00 00");              /* mov edx, 16 */
	re_b(e, "b8 2a 00 00 00");              /* mov eax, 42 */
	o->conn = re_here(e);
	re_b(e, "0f 05");                       /* connect */
	re_b(e, "59");                          /* pop rcx */
	if (variant == 4)
		re_b(e, "50 31 c0 58");         /* push rax; xor eax, eax; pop rax */
	re_b(e, "48 85 c0");
	re_b(e, "79 00");                       /* jns ok: connect returned 0 */
	jns_ok = re_here(e) - 1u;
	re_b(e, "57");                          /* push rdi */
	re_b(e, "6a 00");                       /* push 0 */
	re_b(e, "6a 05");                       /* push 5 */
	re_b(e, "48 89 e7");                    /* mov rdi, rsp: the timespec */
	re_b(e, "31 f6");                       /* xor esi, esi */
	re_b(e, "b8 23 00 00 00");              /* mov eax, 35 */
	o->sleep = re_here(e);
	re_b(e, "0f 05");                       /* nanosleep */
	re_b(e, variant == 1 ? "59" : "59 59");  /* pop rcx; pop rcx (variant 1 leaves a word) */
	re_b(e, "5f");                          /* pop rdi: the socket again */
	if (variant == 3) {
		re_b(e, "eb 00");               /* jmp retry */
	} else {
		re_b(e, "48 85 c0");
		re_b(e, "79 00");               /* jns retry (variant 6: jns ok, patched below) */
	}
	jns_retry = re_here(e) - 1u;
	fail = re_here(e);
	re_b(e, variant == 2 ? "b8 27 00 00 00" : variant == 7 ? "6a 3c 58" : "b8 3c 00 00 00");   /* getpid / push 60; pop rax / mov eax, 60 */
	re_b(e, "bf 01 00 00 00");              /* mov edi, 1 */
	re_b(e, "0f 05");                       /* exit: never returns */
	ok = re_here(e);
	if (variant == 8)
		re_b(e, "48 89 e6");            /* mov rsi, rsp: variant 8 reads into the stack, the region stays on top of it */
	else
		re_b(e, "5e");                  /* pop rsi: the region */
	re_b(e, "ba 00 01 00 00");              /* mov edx, 0x100 */
	if (variant == 5)
		re_b(e, "50 31 c0 58");         /* push rax; xor eax, eax; pop rax */
	o->read = re_here(e);
	re_b(e, "0f 05");                       /* syscall: the number is connect's 0, `read` */
	re_b(e, "48 85 c0");
	re_b(e, "78 00");                       /* js fail */
	js3 = re_here(e) - 1u;
	if (variant == 8)
		re_b(e, "5e");                  /* pop rsi: the region, for the jump */
	o->jmp = re_here(e);
	re_b(e, "ff e6");                       /* jmp rsi */
	re_fix8(e, js1, fail);
	re_fix8(e, js2, fail);
	re_fix8(e, jns_ok, ok);
	re_fix8(e, jns_retry, variant == 6 ? ok : retry);
	re_fix8(e, js3, fail);
	re_finish(e);
}

static void build_stager(struct rawelf *e, struct stager_at *o)
{
	build_stager_v(e, o, 0);
}

static void t_stager(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r;
	build_stager(&e, &o);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	nodes_inside(&r, e.n, "stager");
	EXPECT(node_at(&r, o.mmap, NULL) && node_at(&r, o.sock, NULL) && node_at(&r, o.conn, NULL) && node_at(&r, o.read, NULL) &&
	       node_at(&r, o.jmp, NULL), "stager: the nodes (mmap socket connect read jmp) %d %d %d %d %d", !!node_at(&r, o.mmap, NULL),
	       !!node_at(&r, o.sock, NULL), !!node_at(&r, o.conn, NULL), !!node_at(&r, o.read, NULL), !!node_at(&r, o.jmp, NULL));
	EXPECT(link_how(&r, o.conn, o.sock, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "stager: connect fd <- socket PROVEN (%d)",
	       link_how(&r, o.conn, o.sock, KGENOME_DIAG_ROLE_FD));
	EXPECT(link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "stager: read fd <- socket PROVEN (%d)",
	       link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD));
	EXPECT(link_how(&r, o.read, o.mmap, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_PROVEN, "stager: read buf <- mmap PROVEN (%d)",
	       link_how(&r, o.read, o.mmap, KGENOME_DIAG_ROLE_BUFFER));
	/* LG-4 + LG-2: the region is popped on the one path that reaches the jump, whose pushes and pops balance */
	EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "stager: jmp target <- mmap PROVEN (%d)",
	       link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET));
	/* LG-3: the number of the read is connect's result, on every path, and nothing else (not nanosleep's: its result loops back to
	 * connect, not to the read) */
	EXPECT(nr_is(&r, o.read, KGENOME_DIAG_NR_RESULT, o.conn, KGENOME_DIAG_LINK_PROVEN, 1), "stager: read's number is connect's RESULT, PROVEN");
	/* ... and the relation is an input of the read like its descriptor and its buffer: role NUMBER, from connect */
	EXPECT(link_how(&r, o.read, o.conn, KGENOME_DIAG_ROLE_NUMBER) == KGENOME_DIAG_LINK_PROVEN, "stager: read number <- connect PROVEN (%d)",
	       link_how(&r, o.read, o.conn, KGENOME_DIAG_ROLE_NUMBER));
	EXPECT(link_how(&r, o.read, o.sleep, KGENOME_DIAG_ROLE_NUMBER) == -1, "stager: the number is not nanosleep's");
	/* the NUMBER is an input past the node's view: no pack names the role, the view the graph block reads stays the pack's roles */
	{
		const struct kgenome_diag_hit *hr = node_at(&r, o.read, NULL);
		uint8_t q;

		for (q = 0; hr && q < hr->n_in; q++)
			EXPECT(hr->in[q].role != KGENOME_DIAG_ROLE_NUMBER, "stager: NUMBER is not in the four-input view");
	}
	EXPECT(nr_is(&r, o.conn, KGENOME_DIAG_NR_CONST, 0, 0, 0), "stager: connect's number is CONST");
	/* nothing the oracle refutes: the socket is no buffer, the region no descriptor */
	EXPECT(link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_BUFFER) == -1 && link_how(&r, o.read, o.mmap, KGENOME_DIAG_ROLE_FD) == -1,
	       "stager: no crossed link");
	EXPECT(link_how(&r, o.jmp, o.sock, KGENOME_DIAG_ROLE_TARGET) == -1, "stager: the jump's target is not the socket");
	kgenome_diag_scan_free(r.s);
	/*
	 * THE SAME STAGER DECLARING NOTHING, as a real one does (owner 2026-11-16: the function table is made from loader/ABI metadata only). Round 4 left the
	 * object one unpartitioned unit of trust NONE, which the static lineage does not solve (no link). Phase 2 (2026-11-16): the entry is a declared start, the
	 * descent derives the stager's function from it (trust DERIVED), and the lineage solves a DERIVED function (TODO(owner) at kgenome_lineage_fn_get): the
	 * link is made as with metadata.
	 */
	e.no_meta = 1;
	build_stager(&e, &o);
	e.no_meta = 0;
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(node_at(&r, o.sock, NULL) && node_at(&r, o.read, NULL), "stager, no metadata: the nodes are still made");
		EXPECT(link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "stager, no metadata: the derived function is solved (%d)",
		       link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD));
		kgenome_diag_scan_free(r.s);
	}
}

/* ---- the variants: what can break the stager's relations, and what must then hold ---- */

static void t_stager_variants(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r;
	int v;

	for (v = 1; v <= 7; v++) {
		build_stager_v(&e, &o, v);
		CK(re_scan(&r, &e));
		if (!r.s)
			continue;
		nodes_inside(&r, e.n, "stager variant");
		switch (v) {
		case 1:         /* unbalanced: no MUST may come of a word whose slot differs between paths */
		case 2:         /* a returning kernel entry: the region is not popped on every path */
			EXPECT(link_how(&r, o.read, o.mmap, KGENOME_DIAG_ROLE_BUFFER) != KGENOME_DIAG_LINK_PROVEN,
			       "variant %d: read's buffer must not be PROVEN", v);
			EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) != KGENOME_DIAG_LINK_PROVEN,
			       "variant %d: the jump's target must not be PROVEN", v);
			if (v == 1)
				EXPECT(link_how(&r, o.conn, o.sock, KGENOME_DIAG_ROLE_FD) != KGENOME_DIAG_LINK_PROVEN,
				       "variant 1: connect's descriptor on later passes is what the unbalanced pop takes");
			break;
		case 3:
			/* the read's relations are whole. The jump: LIMIT LG-L1 - the EXEC_REG node is made only by the sweep's linear origins,
			 * which lose the region across a loop closed by an unconditional jump; the stage links nodes and makes none. Pinned as
			 * it is: when the node is made, the link must be PROVEN */
			EXPECT(link_how(&r, o.read, o.mmap, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_PROVEN, "variant 3: read buf PROVEN");
			EXPECT(link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "variant 3: read fd PROVEN");
			EXPECT(nr_is(&r, o.read, KGENOME_DIAG_NR_RESULT, o.conn, KGENOME_DIAG_LINK_PROVEN, 1), "variant 3: number RESULT");
			EXPECT(!node_at(&r, o.jmp, NULL) ||
			       link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "variant 3: jump");
			break;
		case 4:         /* the number survives a push/pop through the stack */
			EXPECT(nr_is(&r, o.read, KGENOME_DIAG_NR_RESULT, o.conn, KGENOME_DIAG_LINK_PROVEN, 1), "variant 4: number RESULT");
			EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "variant 4: jump PROVEN");
			break;
		case 6: {       /* two producers of the number: RESULT, MAY, two of them, the lead the lower node index (connect, made first) */
			uint32_t ic, is;

			EXPECT(node_at(&r, o.conn, &ic) && node_at(&r, o.sleep, &is) && ic < is, "variant 6: connect is the lower index");
			EXPECT(nr_is(&r, o.read, KGENOME_DIAG_NR_RESULT, o.conn, KGENOME_DIAG_LINK_MAY, 2), "variant 6: number RESULT MAY of two");
			EXPECT(link_how(&r, o.read, o.conn, KGENOME_DIAG_ROLE_NUMBER) == KGENOME_DIAG_LINK_MAY &&
			       link_how(&r, o.read, o.sleep, KGENOME_DIAG_ROLE_NUMBER) == KGENOME_DIAG_LINK_MAY, "variant 6: both number links MAY");
			break;
		}
		case 7:
			EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "variant 7: jump PROVEN (%d)",
			       link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET));
			EXPECT(link_how(&r, o.read, o.mmap, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_PROVEN, "variant 7: read buf PROVEN");
			break;
		case 5:         /* the sweep's misread exit does not stop the stage: the jump after it is still linked */
			EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN,
			       "variant 5: a misread exit is not trusted, the jump is PROVEN (%d)", link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET));
			break;
		}
		kgenome_diag_scan_free(r.s);
	}
}

/* ---- I386 over int 0x80 ---- */

static void t_i386(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t mm, rd, jm;
	const struct kgenome_diag_hit *h;

	re_init(&e, 0);
	re_b(&e, "31 db");                      /* xor ebx, ebx */
	re_b(&e, "b9 00 10 00 00");             /* mov ecx, 0x1000 */
	re_b(&e, "ba 07 00 00 00");             /* mov edx, 7 */
	re_b(&e, "be 22 00 00 00");             /* mov esi, 0x22 */
	re_b(&e, "bf ff ff ff ff");             /* mov edi, -1 */
	re_b(&e, "31 ed");                      /* xor ebp, ebp */
	re_b(&e, "b8 c0 00 00 00");             /* mov eax, 192: mmap2 */
	mm = re_here(&e);
	re_b(&e, "cd 80");
	re_b(&e, "89 c1");                      /* mov ecx, eax: the buffer */
	re_b(&e, "31 db");                      /* xor ebx, ebx: fd 0 */
	re_b(&e, "ba 00 01 00 00");             /* mov edx, 0x100 */
	re_b(&e, "b8 03 00 00 00");             /* mov eax, 3: read */
	rd = re_here(&e);
	re_b(&e, "cd 80");
	jm = re_here(&e);
	re_b(&e, "ff e1");                      /* jmp ecx */
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	nodes_inside(&r, e.n, "i386");
	EXPECT(link_how(&r, rd, mm, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_PROVEN, "i386: read buf <- mmap2 PROVEN (%d)",
	       link_how(&r, rd, mm, KGENOME_DIAG_ROLE_BUFFER));
	EXPECT(link_how(&r, jm, mm, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "i386: jmp target <- mmap2 PROVEN (%d)",
	       link_how(&r, jm, mm, KGENOME_DIAG_ROLE_TARGET));
	h = node_at(&r, rd, NULL);
	EXPECT(h && h->nr == KGENOME_DIAG_NR_CONST, "i386: read's number CONST (%u)", h ? h->nr : 99u);
	kgenome_diag_scan_free(r.s);
}

/* ---- CLASSES: a number made by arithmetic is UNKNOWN (no value is computed), one loaded is CONST ---- */

static void t_classes(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t a, b;
	const struct kgenome_diag_hit *h;

	re_init(&e, 1);
	re_b(&e, "bf 01 00 00 00");             /* mov edi, 1 */
	re_b(&e, "31 f6");                      /* xor esi, esi */
	re_b(&e, "31 d2");                      /* xor edx, edx */
	re_b(&e, "b8 01 00 00 00");             /* mov eax, 1: write */
	a = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "31 c0");                      /* xor eax, eax */
	re_b(&e, "ff c0");                      /* inc eax: 1, by arithmetic */
	re_b(&e, "bf 01 00 00 00");             /* mov edi, 1 */
	b = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "b8 3c 00 00 00 0f 05");       /* exit */
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	h = node_at(&r, a, NULL);
	EXPECT(h && h->nr == KGENOME_DIAG_NR_CONST, "classes: a loaded number is CONST (%u)", h ? h->nr : 99u);
	h = node_at(&r, b, NULL);
	EXPECT(h && h->nr == KGENOME_DIAG_NR_UNKNOWN, "classes: a number made by arithmetic is UNKNOWN (%u)", h ? h->nr : 99u);
	kgenome_diag_scan_free(r.s);
}

/* ---- OVERWRITE on one path, and the CQO rule (LG-1), over system calls ---- */

static void t_overwrite_and_cqo(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t mm, sk, rd, rd2, jz, join;

	re_init(&e, 1);
	/* mmap A; socket B; if (eax & 1) rsi = B; read(0, rsi = A or B) -> buffer: A MAY, B MAY */
	re_b(&e, "31 ff be 00 10 00 00 ba 07 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00");
	mm = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "49 89 c4");                   /* mov r12, rax: A */
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	sk = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "4c 89 e6");                   /* mov rsi, r12: A */
	re_b(&e, "a8 01");                      /* test al, 1 */
	re_b(&e, "74 00");                      /* jz join */
	jz = re_here(&e) - 1u;
	re_b(&e, "48 89 c6");                   /* mov rsi, rax: B, on this path only */
	join = re_here(&e);
	re_b(&e, "31 ff");                      /* xor edi, edi */
	re_b(&e, "ba 00 01 00 00");             /* mov edx, 0x100 */
	re_b(&e, "31 c0");                      /* xor eax, eax: read */
	rd = re_here(&e);
	re_b(&e, "0f 05");
	/* LG-1: rdx holds A, `cqo` replaces it by the sign of rax; read's buffer is then no producer's */
	re_b(&e, "4c 89 e2");                   /* mov rdx, r12: A */
	re_b(&e, "48 99");                      /* cqo */
	re_b(&e, "48 89 d6");                   /* mov rsi, rdx */
	re_b(&e, "31 ff");                      /* xor edi, edi */
	re_b(&e, "ba 00 01 00 00");             /* mov edx, 0x100 */
	re_b(&e, "31 c0");
	rd2 = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "b8 3c 00 00 00 0f 05");
	re_fix8(&e, jz, join);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	EXPECT(link_how(&r, rd, mm, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_MAY, "overwrite: buf <- mmap MAY (%d)",
	       link_how(&r, rd, mm, KGENOME_DIAG_ROLE_BUFFER));
	EXPECT(link_how(&r, rd, sk, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_MAY, "overwrite: buf <- socket MAY (%d)",
	       link_how(&r, rd, sk, KGENOME_DIAG_ROLE_BUFFER));
	EXPECT(link_how(&r, rd2, mm, KGENOME_DIAG_ROLE_BUFFER) == -1, "cqo: no buffer link through rdx after cqo (%d)",
	       link_how(&r, rd2, mm, KGENOME_DIAG_ROLE_BUFFER));
	kgenome_diag_scan_free(r.s);
}

/* ---- the CQO rule at a CALL site (LG-1 where the base stage did read inputs: an import's arguments) ---- */

static void t_cqo_call(int keep)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	struct lg_rng rng = { 4242u };
	struct lg_scan sc;
	uint32_t at_m, at_r, i, n;
	int got = -1;

	memset(&p, 0, sizeof p);
	p.nf = 1;
	memset(&c, 0, sizeof c);
	c.p = &p;
	c.wide = 1;
	c.word = 8;
	c.target = LG_T_ELF64;
	la_init(&c.a, 1);
	at_m = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(3));      /* malloc */
	la_mov(&c.a, LA_DX, LA_AX);             /* mov rdx, rax */
	if (!keep) {
		la_b(&c.a, 0x48);
		la_b(&c.a, 0x99);               /* cqo */
	}
	la_mov(&c.a, LA_SI, LA_DX);             /* mov rsi, rdx */
	la_zero(&c.a, LA_DI);
	at_r = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(7));      /* read(0, rsi) */
	la_ret(&c.a);
	c.fn_off[0] = 0;
	c.fn_end[0] = c.a.n;
	CK(la_resolve_labels(&c.a));
	CK(lg_build(&g, &c, &rng, 1));
	CK(lg_scan(&sc, &g, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW));
	if (!sc.s)
		return;
	n = kgenome_diag_scan_count(sc.s);
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc.s, i);
		uint32_t k;

		if (h->at != g.code_off + at_r)
			continue;
		for (k = 0; k < h->n_in; k++)
			if (h->in[k].role == KGENOME_DIAG_ROLE_BUFFER && h->in[k].from < n &&
			    kgenome_diag_scan_at(sc.s, h->in[k].from)->at == g.code_off + at_m)
				got = h->in[k].how;
	}
	if (keep)
		EXPECT(got == KGENOME_DIAG_LINK_PROVEN, "cqo(call): without cqo read's buffer <- malloc PROVEN (%d)", got);
	else
		EXPECT(got == -1, "cqo(call): after cqo read's buffer is not malloc's (%d)", got);
	kgenome_diag_scan_free(sc.s);
}

/* ---- a kernel entry DESTROYS rcx and r11 (`syscall` keeps the return address and the flags there); a STATUS is no descriptor ---- */

static void t_clobber_and_status(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t mm, sk, cn, rd, wr;

	re_init(&e, 1);
	re_b(&e, "31 ff be 00 10 00 00 ba 07 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00");
	mm = re_here(&e);
	re_b(&e, "0f 05");                      /* mmap */
	re_b(&e, "48 89 c1");                   /* mov rcx, rax: the region, in a register `syscall` destroys */
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	sk = re_here(&e);
	re_b(&e, "0f 05");                      /* socket */
	re_b(&e, "48 89 c7");                   /* mov rdi, rax */
	re_b(&e, "48 89 ce");                   /* mov rsi, rcx: NOT the region any more */
	re_b(&e, "ba 10 00 00 00 b8 2a 00 00 00");
	cn = re_here(&e);
	re_b(&e, "0f 05");                      /* connect(socket, rsi, 16) */
	re_b(&e, "31 ff");                      /* xor edi, edi */
	re_b(&e, "ba 00 01 00 00 31 c0");
	rd = re_here(&e);
	re_b(&e, "0f 05");                      /* read(0, rsi, 0x100): rsi is what rcx held after the socket call */
	re_b(&e, "48 89 c7");                   /* mov rdi, rax: read's byte count, a STATUS */
	re_b(&e, "ba 00 01 00 00 b8 01 00 00 00");
	wr = re_here(&e);
	re_b(&e, "0f 05");                      /* write(count, ...): the descriptor is no producer's handle */
	re_b(&e, "b8 3c 00 00 00 0f 05");
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	EXPECT(link_how(&r, cn, sk, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "clobber: connect fd <- socket PROVEN");
	EXPECT(link_how(&r, rd, mm, KGENOME_DIAG_ROLE_BUFFER) == -1, "clobber: rcx does not carry the region across a syscall (%d)",
	       link_how(&r, rd, mm, KGENOME_DIAG_ROLE_BUFFER));
	EXPECT(link_how(&r, wr, rd, KGENOME_DIAG_ROLE_FD) == -1 && link_how(&r, wr, sk, KGENOME_DIAG_ROLE_FD) == -1,
	       "status: a byte count is no descriptor's producer");
	kgenome_diag_scan_free(r.s);
}

/*
 * LG-8 (formerly the comment D8): a function the loader enters - the entry point - is also called directly by one function of the program
 * with a socket in its first argument; the parameter reaches connect. Its direct callers are not all its callers, so the link is MAY.
 * Control: the same callee when it is NOT the entry keeps the link MUST.
 */
static void t_outside_caller(int callee_is_entry)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	struct lg_rng rng = { 777u };
	struct lg_scan sc;
	uint32_t at_s = 0, at_c = 0, i, n, f_callee, lb;
	int got = -1;

	memset(&p, 0, sizeof p);
	p.nf = 2;
	memset(&c, 0, sizeof c);
	c.p = &p;
	c.wide = 1;
	c.word = 8;
	c.target = LG_T_ELF64;
	la_init(&c.a, 1);
	lb = (uint32_t)la_label(&c.a);
	/* function 0 is the image's entry (lg_build_elf: the entry is fn_off[0]) */
	f_callee = callee_is_entry ? 0u : 1u;
	for (i = 0; i < 2u; i++) {
		c.fn_off[i] = c.a.n;
		if (i == f_callee) {
			la_bind(&c.a, (int)lb);
			at_c = c.a.n;
			la_call_sym(&c.a, LG_SYM_STUB(4));      /* connect(rdi = the parameter) */
			la_ret(&c.a);
		} else {
			at_s = c.a.n;
			la_call_sym(&c.a, LG_SYM_STUB(1));      /* socket */
			la_mov(&c.a, LA_DI, LA_AX);
			la_call_label(&c.a, (int)lb);
			la_ret(&c.a);
		}
		c.fn_end[i] = c.a.n;
		la_align(&c.a, 16);
	}
	CK(la_resolve_labels(&c.a));
	CK(lg_build(&g, &c, &rng, 1));
	CK(lg_scan(&sc, &g, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM));
	if (!sc.s)
		return;
	n = kgenome_diag_scan_count(sc.s);
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc.s, i);
		uint32_t k;

		if (h->at != g.code_off + at_c)
			continue;
		for (k = 0; k < h->n_in; k++)
			if (h->in[k].role == KGENOME_DIAG_ROLE_FD && h->in[k].from < n &&
			    kgenome_diag_scan_at(sc.s, h->in[k].from)->at == g.code_off + at_s)
				got = h->in[k].how;
	}
	if (callee_is_entry)
		EXPECT(got == KGENOME_DIAG_LINK_MAY, "outside caller: the entry's parameter link is MAY (%d)", got);
	else
		EXPECT(got == KGENOME_DIAG_LINK_PROVEN, "outside caller control: one direct caller only, PROVEN (%d)", got);
	kgenome_diag_scan_free(sc.s);
}

/* ---- a STATUS names no object: a store and a load through connect's zero are no field of anything (place_resolve) ---- */

static void t_status_no_field(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t sk, wr;

	re_init(&e, 1);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	sk = re_here(&e);
	re_b(&e, "0f 05");                      /* socket */
	re_b(&e, "48 89 c7");                   /* mov rdi, rax */
	re_b(&e, "6a 00 48 89 e6 ba 10 00 00 00 b8 2a 00 00 00");
	re_b(&e, "0f 05");                      /* connect(socket, rsp, 16): rax = its status */
	re_b(&e, "48 89 c3");                   /* mov rbx, rax: the status */
	re_b(&e, "48 89 7b 08");                /* mov [rbx+8], rdi */
	re_b(&e, "48 8b 7b 08");                /* mov rdi, [rbx+8]: no field of an object, the stage cannot name it */
	re_b(&e, "31 f6 31 d2 b8 01 00 00 00");
	wr = re_here(&e);
	re_b(&e, "0f 05");                      /* write */
	re_b(&e, "b8 3c 00 00 00 0f 05");
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	EXPECT(link_how(&r, wr, sk, KGENOME_DIAG_ROLE_FD) != KGENOME_DIAG_LINK_PROVEN, "status: a store through connect's result is no field (%d)",
	       link_how(&r, wr, sk, KGENOME_DIAG_ROLE_FD));
	kgenome_diag_scan_free(r.s);
}

/*
 * ---- A NODE HAS AS MANY INPUTS AS THE PROGRAM GIVES IT (LG-10): three sockets on three paths reach a read's descriptor and two
 * regions on two paths its buffer - five inputs, all MAY - and connect's status its number. The node's view held four and the fifth was
 * dropped with KGENOME_TRUNCATED (kgenome_diag_note_in_how). Every one is an input now, and the scan says nothing was cut.
 */
static void t_many_inputs(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t sk[3], mm[2], rd, jz1, jz2, jz3, l1, l2, l3, ri, k, n;
	int i;
	unsigned f = 0, b = 0;

	re_init(&e, 1);
	for (i = 0; i < 3; i++) {
		re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
		sk[i] = re_here(&e);
		re_b(&e, "0f 05");              /* socket */
		re_b(&e, i == 0 ? "49 89 c4" : i == 1 ? "49 89 c5" : "49 89 c6");      /* mov r12 / r13 / r14, rax */
	}
	for (i = 0; i < 2; i++) {
		re_b(&e, "31 ff be 00 10 00 00 ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00");
		mm[i] = re_here(&e);
		re_b(&e, "0f 05");              /* mmap */
		re_b(&e, i == 0 ? "49 89 c7" : "48 89 c3");     /* mov r15 / rbx, rax */
	}
	re_b(&e, "4c 89 e7");                   /* mov rdi, r12 */
	re_b(&e, "4c 89 fe");                   /* mov rsi, r15 */
	re_b(&e, "a8 01 74 00");                /* test al, 1; jz l1 */
	jz1 = re_here(&e) - 1u;
	re_b(&e, "4c 89 ef");                   /* mov rdi, r13 */
	l1 = re_here(&e);
	re_b(&e, "a8 02 74 00");                /* test al, 2; jz l2 */
	jz2 = re_here(&e) - 1u;
	re_b(&e, "4c 89 f7");                   /* mov rdi, r14 */
	l2 = re_here(&e);
	re_b(&e, "a8 04 74 00");                /* test al, 4; jz l3 */
	jz3 = re_here(&e) - 1u;
	re_b(&e, "48 89 de");                   /* mov rsi, rbx */
	l3 = re_here(&e);
	re_b(&e, "ba 00 01 00 00 31 c0");       /* mov edx, 0x100; xor eax, eax: read */
	rd = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "b8 3c 00 00 00 0f 05");
	re_fix8(&e, jz1, l1);
	re_fix8(&e, jz2, l2);
	re_fix8(&e, jz3, l3);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	EXPECT(node_at(&r, rd, &ri) != NULL, "many: the read is a node");
	n = node_at(&r, rd, &ri) ? kgenome_diag_in_count(r.s, ri) : 0u;
	for (k = 0; k < n; k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(r.s, ri, k);
		uint32_t q;

		for (q = 0; q < 3u; q++)
			f += x->role == KGENOME_DIAG_ROLE_FD && x->how == KGENOME_DIAG_LINK_MAY && kgenome_diag_scan_at(r.s, x->from)->at == sk[q];
		for (q = 0; q < 2u; q++)
			b += x->role == KGENOME_DIAG_ROLE_BUFFER && x->how == KGENOME_DIAG_LINK_MAY && kgenome_diag_scan_at(r.s, x->from)->at == mm[q];
	}
	EXPECT(f == 3u && b == 2u, "many: 3 descriptor and 2 buffer producers, all MAY (%u, %u of %u inputs)", f, b, n);
	EXPECT(kgenome_diag_scan_status(r.s) != KGENOME_TRUNCATED, "many: nothing was cut (status %d)", (int)kgenome_diag_scan_status(r.s));
	kgenome_diag_scan_free(r.s);
}

/*
 * ---- THE LOCAL STACK (LG-9): after a join of two depths the stack pointer is lost, and the words pushed from there are followed - a pop
 * takes the top one and the next pop the one below it. Two paths that meet with different counts of such words pending lose them.
 */
static void t_local_stack(int differ)
{
	/* at CALL sites (imports through the PLT): the routes make the nodes and link nothing, so what is linked is the stage's alone */
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	struct lg_rng rng = { 4343u };
	struct lg_scan sc;
	uint32_t at_m, at_r, i, n;
	int l1, l2, got = -1;

	memset(&p, 0, sizeof p);
	p.nf = 1;
	memset(&c, 0, sizeof c);
	c.p = &p;
	c.wide = 1;
	c.word = 8;
	c.target = LG_T_ELF64;
	la_init(&c.a, 1);
	l1 = la_label(&c.a);
	l2 = la_label(&c.a);
	at_m = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(3));      /* malloc */
	la_mov(&c.a, LA_BX, LA_AX);             /* the object, in rbx */
	if (differ == 3) {
		la_b(&c.a, 0x48);
		la_b(&c.a, 0x29);
		la_b(&c.a, 0xcc);               /* sub rsp, rcx: the stack pointer lost by an amount the code does not say (kills M26: two
						 * pending counts kept as the first arrival's gave the object as PROVEN) */
		la_bind(&c.a, l1);
	} else {
		la_test(&c.a, LA_AX);
		la_jcc_label(&c.a, 4u, l1);     /* jz l1: one path a word shallower */
		la_push(&c.a, LA_CX);
		la_bind(&c.a, l1);              /* the stack pointer is lost here: two depths */
	}
	la_push(&c.a, LA_BX);                   /* the object, pushed after it was lost */
	if (differ == 1 || differ == 3) {
		la_test(&c.a, LA_DX);
		la_jcc_label(&c.a, 4u, l2);     /* jz l2: one path with one more word pending (on the fall-through) */
		la_pushi(&c.a, 0);
		la_bind(&c.a, l2);
	} else if (differ == 2) {
		const int l3 = la_label(&c.a);

		la_test(&c.a, LA_DX);
		la_jcc_label(&c.a, 4u, l3);     /* the same with the word pending on the TAKEN side: whichever path a join meets first */
		la_jmp_label(&c.a, l2);
		la_bind(&c.a, l3);
		la_pushi(&c.a, 0);
		la_bind(&c.a, l2);
	} else {
		la_pushi(&c.a, 0);
		la_pop(&c.a, LA_DX);            /* the top word, taken */
	}
	la_pop(&c.a, LA_SI);                    /* the object (where the paths differ, not on every path) */
	la_zero(&c.a, LA_DI);
	at_r = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(7));      /* read(0, rsi) */
	la_ret(&c.a);
	c.fn_off[0] = 0;
	c.fn_end[0] = c.a.n;
	CK(la_resolve_labels(&c.a));
	CK(lg_build(&g, &c, &rng, 1));
	CK(lg_scan(&sc, &g, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW));
	if (!sc.s)
		return;
	n = kgenome_diag_scan_count(sc.s);
	for (i = 0; i < n; i++) {
		uint32_t k;

		if (kgenome_diag_scan_at(sc.s, i)->at != g.code_off + at_r)
			continue;
		for (k = 0; k < kgenome_diag_in_count(sc.s, i); k++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(sc.s, i, k);

			if (x->role == KGENOME_DIAG_ROLE_BUFFER && x->from < n && kgenome_diag_scan_at(sc.s, x->from)->at == g.code_off + at_m)
				got = x->how;
		}
	}
	if (differ)
		EXPECT(got != KGENOME_DIAG_LINK_PROVEN, "local stack: two pending counts are not one stack, no PROVEN (%d)", got);
	else
		EXPECT(got == KGENOME_DIAG_LINK_PROVEN, "local stack: the second pop takes the word below the first (%d)", got);
	kgenome_diag_scan_free(sc.s);
}

/*
 * ---- LG-12: A VALUE HOLDS EVERY PRODUCER. Twenty mallocs, each kept in rbx on one path only (`test rax; jz skip; mov rbx, rax`), then
 * read(0, rbx): rbx is any of the twenty, so read's buffer has twenty MAY producers. The value's sixteen tokens dropped four of them,
 * widened to W_LIMIT and said TRUNCATED.
 */
static void t_wide_value(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	struct lg_rng rng = { 4545u };
	struct lg_scan sc;
	uint32_t at_m[20], at_r, i, n, k, found = 0;
	int lab;

	memset(&p, 0, sizeof p);
	p.nf = 1;
	memset(&c, 0, sizeof c);
	c.p = &p;
	c.wide = 1;
	c.word = 8;
	c.target = LG_T_ELF64;
	la_init(&c.a, 1);
	la_zero(&c.a, LA_BX);
	for (i = 0; i < 20u; i++) {
		lab = la_label(&c.a);
		at_m[i] = c.a.n;
		la_call_sym(&c.a, LG_SYM_STUB(3));      /* malloc */
		la_test(&c.a, LA_AX);
		la_jcc_label(&c.a, 4u, lab);            /* jz: this path keeps what rbx held */
		la_mov(&c.a, LA_BX, LA_AX);
		la_bind(&c.a, lab);
	}
	la_mov(&c.a, LA_SI, LA_BX);
	la_zero(&c.a, LA_DI);
	at_r = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(7));      /* read(0, rbx) */
	la_ret(&c.a);
	c.fn_off[0] = 0;
	c.fn_end[0] = c.a.n;
	CK(la_resolve_labels(&c.a));
	CK(lg_build(&g, &c, &rng, 1));
	CK(lg_scan(&sc, &g, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW));
	if (!sc.s)
		return;
	n = kgenome_diag_scan_count(sc.s);
	for (i = 0; i < n; i++) {
		if (kgenome_diag_scan_at(sc.s, i)->at != g.code_off + at_r)
			continue;
		for (k = 0; k < kgenome_diag_in_count(sc.s, i); k++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(sc.s, i, k);
			uint32_t q;

			for (q = 0; q < 20u; q++)
				found += x->role == KGENOME_DIAG_ROLE_BUFFER && x->how == KGENOME_DIAG_LINK_MAY && x->from < n &&
					 kgenome_diag_scan_at(sc.s, x->from)->at == g.code_off + at_m[q];
		}
	}
	EXPECT(found == 20u, "wide value: read's buffer has all twenty producers, MAY (%u)", found);
	EXPECT(kgenome_diag_scan_status(sc.s) == KGENOME_OK, "wide value: nothing was cut (%d)", (int)kgenome_diag_scan_status(sc.s));
	kgenome_diag_scan_free(sc.s);
}

/*
 * ---- THE NO-RETURN LIST IS READ IN ORDER (kgenome_diag_noret_settle). The routes add to it as they read: the sweep (first) the `exit` system
 * call at the HIGH address, then the symbol route a `call _exit@plt` at a LOW one - the list is [high, low], and a binary search over it
 * misses the high one. Then the error path's `exit` falls into the success path's `pop rsi` (reached at two depths) and read's buffer, the
 * malloc'd object on every real path, is no longer PROVEN. (Kills M19: the list not put in order.)
 */
static void t_noret_order(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	struct lg_rng rng = { 4646u };
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_diag_inputs in;
	struct kgenome_diag_scan *ds;
	uint32_t at_m, at_r, i, n, k;
	int lskip, lfail, lok, got = -1;
	uint8_t *q;

	memset(&p, 0, sizeof p);
	p.nf = 1;
	memset(&c, 0, sizeof c);
	c.p = &p;
	c.wide = 1;
	c.word = 8;
	c.target = LG_T_ELF64;
	la_init(&c.a, 1);
	lskip = la_label(&c.a);
	lfail = la_label(&c.a);
	lok = la_label(&c.a);
	la_test(&c.a, LA_DI);
	la_jcc_label(&c.a, 4u, lskip);
	la_call_sym(&c.a, LG_SYM_STUB(9));      /* the 9th import, renamed _exit below: a call that does not return, LOW in the code */
	la_bind(&c.a, lskip);
	at_m = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(3));      /* malloc */
	la_test(&c.a, LA_AX);
	la_jcc_label(&c.a, 4u, lfail);          /* depth 0 */
	la_push(&c.a, LA_AX);
	la_test(&c.a, LA_AX);
	la_jcc_label(&c.a, 4u, lfail);          /* depth 8 */
	la_jmp_label(&c.a, lok);
	la_bind(&c.a, lfail);
	la_b(&c.a, 0xb8); la_d(&c.a, 60u);      /* mov eax, 60 */
	la_b(&c.a, 0x0f); la_b(&c.a, 0x05);     /* syscall: exit, HIGH in the code */
	la_bind(&c.a, lok);
	la_pop(&c.a, LA_SI);                    /* the object: reached only from the jump, at depth 8 */
	la_zero(&c.a, LA_DI);
	at_r = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(7));      /* read(0, rsi) */
	la_ret(&c.a);
	c.fn_off[0] = 0;
	c.fn_end[0] = c.a.n;
	CK(la_resolve_labels(&c.a));
	CK(lg_build(&g, &c, &rng, 1));
	/* rename the import: "getpid" becomes "_exit" (a name of the no-return table) */
	for (q = g.b; q + 7 <= g.b + g.n; q++)
		if (!memcmp(q, "getpid", 7)) {
			memcpy(q, "_exit\0\0", 7);
			break;
		}
	memset(&o, 0, sizeof o);
	memset(&in, 0, sizeof in);
	CK(kgenome_elf_image_parse(kof_buf_make(g.b, g.n), &ei, &o));
	o.file_header = &ei;
	in.lineage_stages = KGENOME_LINEAGE_S_FLOW;
	ds = kgenome_diag_scan_with_inputs(&o, g.b, g.n, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE, &in);
	CK(ds != NULL);
	if (!ds)
		return;
	n = kgenome_diag_scan_count(ds);
	for (i = 0; i < n; i++) {
		if (kgenome_diag_scan_at(ds, i)->at != g.code_off + at_r)
			continue;
		for (k = 0; k < kgenome_diag_in_count(ds, i); k++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(ds, i, k);

			if (x->role == KGENOME_DIAG_ROLE_BUFFER && x->from < n && kgenome_diag_scan_at(ds, x->from)->at == g.code_off + at_m)
				got = x->how;
		}
	}
	EXPECT(got == KGENOME_DIAG_LINK_PROVEN, "noret order: both exits are known, read's buffer is the object on every path (%d)", got);
	kgenome_diag_scan_free(ds);
}

/* ---- ORDER: the same object twice gives the same links (no state carried between scans) ---- */

static void t_idempotent(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r1, r2;
	uint32_t i, n;

	build_stager(&e, &o);
	CK(re_scan(&r1, &e) && re_scan(&r2, &e));
	if (!r1.s || !r2.s)
		return;
	n = kgenome_diag_scan_count(r1.s);
	CK(n == kgenome_diag_scan_count(r2.s));
	for (i = 0; i < n && i < kgenome_diag_scan_count(r2.s); i++) {
		const struct kgenome_diag_hit *a = kgenome_diag_scan_at(r1.s, i), *b = kgenome_diag_scan_at(r2.s, i);

		uint32_t k;

		CK(a->at == b->at && a->cap == b->cap && a->n_in == b->n_in && a->nr == b->nr && a->nr_from == b->nr_from && a->nr_how == b->nr_how &&
		   !memcmp(a->in, b->in, (size_t)a->n_in * sizeof a->in[0]));
		CK(kgenome_diag_in_count(r1.s, i) == kgenome_diag_in_count(r2.s, i));
		for (k = 0; k < kgenome_diag_in_count(r1.s, i) && k < kgenome_diag_in_count(r2.s, i); k++)
		{
			const struct kgenome_diag_in *x = kgenome_diag_in_at(r1.s, i, k), *y = kgenome_diag_in_at(r2.s, i, k);

			CK(x->from == y->from && x->role == y->role && x->how == y->how && x->kind == y->kind);
		}
	}
	kgenome_diag_scan_free(r1.s);
	kgenome_diag_scan_free(r2.s);
}

/*
 * ---- TRUTH (lin_truth audit, 2026-11-17): shapes a C compiler makes of a static program, checked against what the program does ----
 *
 * The wrappers are written the way a static C library writes them (the parameters read from the stack, the number a constant, `int 0x80`, `ret`),
 * so the nodes are the wrapper route's, at the CALLS (diag_wrapper.c). Found by lin_truth's generated programs (gcc -O2 -m32 -static, the
 * gdb trace as the oracle): the wrapper route's caller walk carried a register across the end of one function into the next one, and wrote a
 * link it made in address order, taking no branch, as PROVEN. Why the old tests missed it: (b) no program here had a function reached only
 * by a jump that reads a register its caller left (GCC's local i386 functions take their first argument in eax), nor two arms that each make
 * the value a later call consumes.
 */
static void rel32(struct rawelf *e, uint32_t at, uint32_t to)
{
	lg_p32(e->b, at, to - (at + 4u));
}

struct wrap_at {
	uint32_t sock_w, open_w, write_w;       /* the wrappers' first bytes */
};

/* socket (359), open (5), write (4): the parameters from the stack, as a C library's wrapper reads them */
static void put_wrappers(struct rawelf *e, struct wrap_at *w)
{
	w->sock_w = re_here(e);
	re_b(e, "8b 5c 24 04 8b 4c 24 08 8b 54 24 0c b8 67 01 00 00 cd 80 c3");
	w->open_w = re_here(e);
	re_b(e, "8b 5c 24 04 8b 4c 24 08 b8 05 00 00 00 cd 80 c3");
	w->write_w = re_here(e);
	re_b(e, "8b 5c 24 04 8b 4c 24 08 8b 54 24 0c b8 04 00 00 00 cd 80 c3");
}

/*
 * A FUNCTION REACHED ONLY BY A JUMP. The entry calls sc7 (an open), makes a socket and JUMPS to `use` with the socket in eax; `use` lies right
 * after sc7 and writes on eax. The descriptor the write gets is the socket's; the open's never reaches it (sc7 returns before `use` runs).
 */
static void t_truth_tail_jump_carry(void)
{
	static struct rawelf e;
	struct rscan r;
	struct wrap_at w;
	uint32_t c_sc7, c_sock, j_use, sc7, c_open, use, c_write, p_path, p_buf, path, buf;
	const uint32_t va = 0x08048000u;
	int how;

	e.no_meta = 1;                                  /* the image declares nothing, as a stripped static program's code does not */
	re_init(&e, 0);
	c_sc7 = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call sc7 */
	re_b(&e, "6a 00 6a 01 6a 02");                  /* push 0; push 1; push 2 */
	c_sock = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call sock_w: the socket */
	re_b(&e, "83 c4 0c");                           /* add esp, 12 */
	j_use = re_here(&e);
	re_b(&e, "e9 00 00 00 00");                     /* jmp use, the socket in eax */
	put_wrappers(&e, &w);
	/* sc7 ends in a jump back to its own `ret`, as GCC lays a function out when the return is shared (the generated program's sc7 did) */
	sc7 = re_here(&e);
	re_b(&e, "eb 01 c3");                           /* jmp body; ret */
	re_b(&e, "6a 02");                              /* body: push 2 */
	p_path = re_here(&e) + 1u;
	re_b(&e, "68 00 00 00 00");                     /* push path */
	c_open = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call open_w */
	re_b(&e, "83 c4 08");                           /* add esp, 8 */
	re_b(&e, "eb 00");                              /* jmp back to the ret */
	e.b[re_here(&e) - 1u] = (uint8_t)(int8_t)((int32_t)(sc7 + 2u) - (int32_t)re_here(&e));
	use = re_here(&e);
	re_b(&e, "89 c6 6a 08");                        /* mov esi, eax; push 8 */
	p_buf = re_here(&e) + 1u;
	re_b(&e, "68 00 00 00 00 56");                  /* push buf; push esi */
	c_write = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call write_w: fd = the socket */
	re_b(&e, "83 c4 0c b8 01 00 00 00 31 db cd 80"); /* add esp, 12; exit(0) */
	path = re_here(&e);
	re_b(&e, "2f 64 65 76 2f 6e 75 6c 6c 00");      /* "/dev/null" */
	buf = re_here(&e);
	re_b(&e, "00 00 00 00 00 00 00 00");
	rel32(&e, c_sc7 + 1u, sc7);
	rel32(&e, c_sock + 1u, w.sock_w);
	rel32(&e, j_use + 1u, use);
	rel32(&e, c_open + 1u, w.open_w);
	rel32(&e, c_write + 1u, w.write_w);
	lg_p32(e.b, p_path, va + path);
	lg_p32(e.b, p_buf, va + buf);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	/* the open and the write are nodes; the socket is a node too where the wrapper route reads a direct socket (359) wrapper (printed, not held:
	 * the i386 socket of a static C library goes through socketcall's array, lin_truth found no socket node there at all) */
	EXPECT(node_at(&r, c_open, NULL) && node_at(&r, c_write, NULL), "truth-tail: the open and the write are nodes");
	how = link_how(&r, c_write, c_open, KGENOME_DIAG_ROLE_FD);
	/* LE-D1 (fixed 2026-11-17): the open's descriptor never reaches the write - `use` is a piece of its own in the function table and starts with no carried value */
	EXPECT(how == -1, "truth-tail: no link write fd <- the open of the function laid out before (%d)", how);
	printf("truth-tail: write fd <- socket %d, <- open %d (truth: the socket's, by the jump)\n", link_how(&r, c_write, c_sock, KGENOME_DIAG_ROLE_FD), how);
	kgenome_diag_scan_free(r.s);
}

/*
 * TWO ARMS. f(k) opens one file on one arm and another file on the other and writes on what it opened: the write's descriptor is the first
 * open's OR the second's (MAY, both), never one of them on every path. (Two opens and not a socket: the i386 table has no word for the direct
 * socket call, 359, so a socket arm makes no node - LIN-D1.)
 */
static void t_truth_two_arms(void)
{
	static struct rawelf e;
	struct rscan r;
	struct wrap_at w;
	uint32_t c_f, f, je_at, c_open1, jmp_at, els, c_open2, join, c_write, p_path1, p_path2, p_buf, path1, path2, buf;
	const uint32_t va = 0x08048000u;
	int h1, h2;

	e.no_meta = 1;                                  /* the image declares nothing, as a stripped static program's code does not */
	re_init(&e, 0);
	re_b(&e, "6a 01");                              /* push 1 */
	c_f = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call f */
	re_b(&e, "6a 00");                              /* push 0 */
	re_b(&e, "e8 00 00 00 00");                     /* call f (both arms run) */
	re_b(&e, "b8 01 00 00 00 31 db cd 80");         /* exit(0) */
	put_wrappers(&e, &w);
	f = re_here(&e);
	re_b(&e, "83 7c 24 04 00");                     /* cmp dword [esp+4], 0 */
	je_at = re_here(&e) + 1u;
	re_b(&e, "74 00");                              /* je else */
	re_b(&e, "6a 02");
	p_path1 = re_here(&e) + 1u;
	re_b(&e, "68 00 00 00 00");
	c_open1 = re_here(&e);
	re_b(&e, "e8 00 00 00 00 83 c4 08");            /* call open_w (path1); add esp, 8 */
	jmp_at = re_here(&e) + 1u;
	re_b(&e, "eb 00");                              /* jmp join */
	els = re_here(&e);
	re_b(&e, "6a 02");
	p_path2 = re_here(&e) + 1u;
	re_b(&e, "68 00 00 00 00");
	c_open2 = re_here(&e);
	re_b(&e, "e8 00 00 00 00 83 c4 08");            /* call open_w (path2); add esp, 8 */
	join = re_here(&e);
	re_b(&e, "89 c6 6a 08");
	p_buf = re_here(&e) + 1u;
	re_b(&e, "68 00 00 00 00 56");
	c_write = re_here(&e);
	re_b(&e, "e8 00 00 00 00 83 c4 0c c3");         /* call write_w; add esp, 12; ret */
	path1 = re_here(&e);
	re_b(&e, "2f 64 65 76 2f 6e 75 6c 6c 00");      /* "/dev/null" */
	path2 = re_here(&e);
	re_b(&e, "2f 65 74 63 2f 78 00");               /* "/etc/x" */
	buf = re_here(&e);
	re_b(&e, "00 00 00 00 00 00 00 00");
	rel32(&e, c_f + 1u, f);
	rel32(&e, c_f + 8u, f);
	re_fix8(&e, je_at, els);
	re_fix8(&e, jmp_at, join);
	rel32(&e, c_open1 + 1u, w.open_w);
	rel32(&e, c_open2 + 1u, w.open_w);
	rel32(&e, c_write + 1u, w.write_w);
	lg_p32(e.b, p_path1, va + path1);
	lg_p32(e.b, p_path2, va + path2);
	lg_p32(e.b, p_buf, va + buf);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	h1 = link_how(&r, c_write, c_open1, KGENOME_DIAG_ROLE_FD);
	h2 = link_how(&r, c_write, c_open2, KGENOME_DIAG_ROLE_FD);
	/* LE-D2 (fixed 2026-11-17): the arm laid out last was PROVEN and the other had no link */
	EXPECT(h1 == KGENOME_DIAG_LINK_MAY && h2 == KGENOME_DIAG_LINK_MAY, "truth-arms: write fd <- each open MAY (open1 %d, open2 %d)", h1, h2);
	kgenome_diag_scan_free(r.s);
}

/*
 * A WRAPPER IS A FUNCTION WHOSE JOB IS ONE SYSTEM CALL (diag_wrapper.c). x86-64, the wrappers as a C library writes them (`mov eax, nr;
 * syscall; ret`, the parameters left in their registers). f makes a socket and connects on it; g makes a socket and hands it to `use`, which
 * connects (`use` is a wrapper of the connect: its job is that one call); h is a wrapper of the socket that calls a helper after it which
 * enters no kernel (what musl's __syscall_ret is); k is one whose failure arm calls a function that never comes back (the stack protector's
 * check). The calls of f and g are no system call: their nodes are at their own calls of the wrappers. The calls of h and k are the socket. (LE-D3: f and g were wrappers
 * of their first call - the socket wrapper's summary maps r8 and r9, which f never sets, to the kernel's arguments 4 and 5, so f's own r8
 * and r9 were "parameters" that made it a wrapper - and their callers held a socket node each: lin_truth, 830 net-open nodes in main.)
 */
static void t_truth_wrapper_job(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t c_f, c_g, c_h, c_k, sock_w, conn_w, f, f_sock, f_conn, g, g_sock, g_use, use, use_conn, h, h_sock, h_quiet, quiet, k, k_sock, k_js, k_chk, chk;

	e.no_meta = 1;
	re_init(&e, 1);
	c_f = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call f */
	c_g = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call g */
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2"); /* mov edi, 2; mov esi, 1; xor edx, edx */
	c_h = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call h: socket(2, 1, 0) */
	c_k = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call k: socket(2, 1, 0) again */
	re_b(&e, "b8 3c 00 00 00 31 ff 0f 05");         /* exit(0) */
	sock_w = re_here(&e);
	re_b(&e, "b8 29 00 00 00 0f 05 c3");            /* socket: mov eax, 41; syscall; ret */
	conn_w = re_here(&e);
	re_b(&e, "b8 2a 00 00 00 0f 05 c3");            /* connect: mov eax, 42; syscall; ret */
	f = re_here(&e);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2");
	f_sock = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call socket */
	re_b(&e, "89 c7 be 00 00 00 00 ba 10 00 00 00"); /* mov edi, eax; mov esi, 0; mov edx, 16 */
	f_conn = re_here(&e);
	re_b(&e, "e8 00 00 00 00 c3");                  /* call connect; ret */
	g = re_here(&e);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2");
	g_sock = re_here(&e);
	re_b(&e, "e8 00 00 00 00 89 c7");               /* call socket; mov edi, eax */
	g_use = re_here(&e);
	re_b(&e, "e8 00 00 00 00 c3");                  /* call use; ret */
	use = re_here(&e);
	re_b(&e, "be 00 00 00 00 ba 10 00 00 00");
	use_conn = re_here(&e);
	re_b(&e, "e8 00 00 00 00 c3");                  /* call connect; ret */
	h = re_here(&e);
	h_sock = re_here(&e);
	re_b(&e, "e8 00 00 00 00 48 89 c7");            /* call socket (the parameters as they came); mov rdi, rax */
	h_quiet = re_here(&e);
	re_b(&e, "e8 00 00 00 00 c3");                  /* call quiet; ret */
	quiet = re_here(&e);
	re_b(&e, "48 89 f8 c3");                        /* quiet: mov rax, rdi; ret */
	chk = re_here(&e);
	re_b(&e, "b8 3c 00 00 00 0f 05 0f 0b");         /* chk: exit; ud2 - it enters a kernel and never comes back */
	/* k: a socket wrapper whose failure arm calls a function that never comes back (what the stack protector's check is) */
	k = re_here(&e);
	k_sock = re_here(&e);
	re_b(&e, "e8 00 00 00 00 85 c0");               /* call socket; test eax, eax */
	k_js = re_here(&e) + 1u;
	re_b(&e, "78 00 c3");                           /* js fail; ret */
	k_chk = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* fail: call chk */
	re_b(&e, "48 89 f8 48 89 f7 0f 05 c3");         /* a syscall(nr, ...) the sweep cannot read the number of: what starts the wrapper route */
	rel32(&e, c_f + 1u, f);
	rel32(&e, c_g + 1u, g);
	rel32(&e, c_h + 1u, h);
	rel32(&e, f_sock + 1u, sock_w);
	rel32(&e, f_conn + 1u, conn_w);
	rel32(&e, g_sock + 1u, sock_w);
	rel32(&e, g_use + 1u, use);
	rel32(&e, use_conn + 1u, conn_w);
	rel32(&e, h_sock + 1u, sock_w);
	rel32(&e, h_quiet + 1u, quiet);
	rel32(&e, c_k + 1u, k);
	rel32(&e, k_sock + 1u, sock_w);
	re_fix8(&e, k_js, k_chk);
	rel32(&e, k_chk + 1u, chk);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	EXPECT(!node_at(&r, c_f, NULL), "truth-job: no node at the call of f, which makes a socket and connects");
	EXPECT(!node_at(&r, c_g, NULL), "truth-job: no node at the call of g, which makes a socket and hands it to a function that connects");
	EXPECT(node_at(&r, f_sock, NULL) && node_at(&r, f_conn, NULL) && node_at(&r, g_sock, NULL),
	       "truth-job: the nodes are at the calls of the wrappers inside f and g");
	/* `use` connects and returns: its job is one system call, it is a wrapper, and the node is at its call */
	EXPECT(node_at(&r, g_use, NULL) && node_at(&r, g_use, NULL)->cap == KGENOME_NUCLEO_NET_CONNECT && !node_at(&r, use_conn, NULL),
	       "truth-job: the call of use, a connect wrapper, is the connect");
	EXPECT(node_at(&r, c_h, NULL) && node_at(&r, c_h, NULL)->cap == KGENOME_NUCLEO_NET_OPEN,
	       "truth-job: the call of h, a socket wrapper with a helper after it that enters no kernel, is the socket");
	EXPECT(node_at(&r, c_k, NULL) && node_at(&r, c_k, NULL)->cap == KGENOME_NUCLEO_NET_OPEN,
	       "truth-job: the call of k, a socket wrapper whose failure arm calls a function that never comes back, is the socket");
	kgenome_diag_scan_free(r.s);
}

/*
 * ONE `syscall` FOR EVERY CANCELLABLE CALL (x86-64, the shape of a static glibc 2.34+): open and write each push their NUMBER as the seventh
 * argument of a helper (`push 2` / `push 1`; call cancel), which pushes it again for the one that enters the kernel (`mov rax, [rsp+0x10];
 * syscall` after its own push). What each call of the program is is the caller's number: the call of open is the open, the call of write
 * the write, and the write's descriptor is the open's. The shared `syscall` is no one call: no capability node there. (LE-D4: the summary
 * read no parameter from the stack, so the number was unknown at every level, the program's calls had no node, and the sweep's node at the
 * shared instruction stood for all of them: lin_truth, 34 sites with two nodes, 31 self links, 144 static builds.)
 */
static void t_truth_shared_syscall(void)
{
	static struct rawelf e;
	struct rscan r;
	uint32_t c_open, c_write, p_path, p_buf, open_w, write_w, cancel, c_isc, c_cancel1, c_cancel2, isc, sys, path, buf;
	const uint32_t va = 0x400000u;
	uint32_t i, n;
	int how;

	e.no_meta = 1;
	re_init(&e, 1);
	p_path = re_here(&e) + 1u;
	re_b(&e, "bf 00 00 00 00 be 02 00 00 00");      /* mov edi, path; mov esi, 2 */
	c_open = re_here(&e);
	re_b(&e, "e8 00 00 00 00 89 c7");               /* call open; mov edi, eax */
	p_buf = re_here(&e) + 1u;
	re_b(&e, "be 00 00 00 00 ba 08 00 00 00");      /* mov esi, buf; mov edx, 8 */
	c_write = re_here(&e);
	re_b(&e, "e8 00 00 00 00");                     /* call write */
	re_b(&e, "b8 3c 00 00 00 31 ff 0f 05");         /* exit(0) */
	open_w = re_here(&e);
	re_b(&e, "48 83 ec 10 45 31 c9 45 31 c0 6a 02 31 c9"); /* sub rsp, 16; xor r9d, r9d; xor r8d, r8d; push 2; xor ecx, ecx */
	c_cancel1 = re_here(&e);
	re_b(&e, "e8 00 00 00 00 48 83 c4 18 c3");      /* call cancel; add rsp, 24; ret */
	write_w = re_here(&e);
	re_b(&e, "48 83 ec 10 45 31 c9 45 31 c0 6a 01 31 c9");
	c_cancel2 = re_here(&e);
	re_b(&e, "e8 00 00 00 00 48 83 c4 18 c3");
	cancel = re_here(&e);
	re_b(&e, "48 83 ec 10 ff 74 24 18");            /* sub rsp, 16; push qword [rsp+0x18]: the number again */
	c_isc = re_here(&e);
	re_b(&e, "e8 00 00 00 00 48 83 c4 18 c3");      /* call isc; add rsp, 24; ret */
	isc = re_here(&e);
	re_b(&e, "53 49 89 ca 48 8b 44 24 10");         /* push rbx; mov r10, rcx; mov rax, [rsp+0x10] */
	sys = re_here(&e);
	re_b(&e, "0f 05 5b c3");                        /* syscall; pop rbx; ret */
	path = re_here(&e);
	re_b(&e, "2f 64 65 76 2f 6e 75 6c 6c 00");
	buf = re_here(&e);
	re_b(&e, "00 00 00 00 00 00 00 00");
	rel32(&e, c_open + 1u, open_w);
	rel32(&e, c_write + 1u, write_w);
	rel32(&e, c_cancel1 + 1u, cancel);
	rel32(&e, c_cancel2 + 1u, cancel);
	rel32(&e, c_isc + 1u, isc);
	lg_p32(e.b, p_path, va + path);
	lg_p32(e.b, p_buf, va + buf);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (!r.s)
		return;
	EXPECT(node_at(&r, c_open, NULL) && node_at(&r, c_open, NULL)->cap == KGENOME_NUCLEO_FILE_OPEN,
	       "truth-shared: the call of open is the open");
	EXPECT(node_at(&r, c_write, NULL) && node_at(&r, c_write, NULL)->cap == KGENOME_NUCLEO_MEM_WRITE,
	       "truth-shared: the call of write is the write");
	how = link_how(&r, c_write, c_open, KGENOME_DIAG_ROLE_FD);
	EXPECT(how == KGENOME_DIAG_LINK_PROVEN, "truth-shared: write fd <- open, on the one path (%d)", how);
	n = kgenome_diag_scan_count(r.s);
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(r.s, i);

		EXPECT(!(h->at == sys && h->cap != KGENOME_NUCLEO_NONE && !(h->bits & KGENOME_DIAG_H_SUPERSEDED)),
		       "truth-shared: no capability node at the shared syscall (node %u, cap %u)", i, h->cap);
	}
	kgenome_diag_scan_free(r.s);
}

/*
 * ---- THE WORD OF A DESCRIPTOR CALL FOLLOWS ITS PROVEN DESCRIPTOR (CLR-D1, 2026-11-17) ----
 *
 * A read(2)/write(2) node was mem-read/mem-write whatever its descriptor was, while the scan held a PROVEN link from a socket to that
 * descriptor: the node said "memory" for a receive from the network. The word is decided once, after the links are final
 * (caps_settle, diag_scan.c), from kgenome_nucleo_cap_on_handle: a socket's is net-recv/net-send, an opened file's file-read/
 * file-write, and anything less than proof - MAY, a constant, a producer with no case (a mapping, dup2's number) - keeps the generic word.
 * Why no test saw it: (c) every lineage test checked the LINKS of a read and none its capability after the links were made.
 */
static void exit_tail(struct rawelf *e)
{
	re_b(e, "b8 3c 00 00 00 31 ff 0f 05");  /* mov eax, 60; xor edi, edi; syscall: exit */
}

static unsigned cap_at(const struct rscan *r, uint32_t at)
{
	const struct kgenome_diag_hit *h = node_at(r, at, NULL);

	return h ? h->cap : 0xffffu;
}

#define CAP_IS(r, at, want, what) \
	EXPECT(cap_at(r, at) == (unsigned)(want), "%s: %s, got %s", what, kgenome_nucleo_cap_name((uint16_t)(want)), \
	       cap_at(r, at) == 0xffffu ? "(no node)" : kgenome_nucleo_cap_name((uint16_t)cap_at(r, at)))

static void t_cap_by_handle(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r;
	uint32_t s, rd, wr, op, d2;
	uint32_t js, jm;

	/* the stager: the socket reaches the read through `mov rdi, rax`, the loop's back edge, and push rdi / pop rdi round nanosleep */
	build_stager(&e, &o);
	CK(re_scan(&r, &e));
	if (r.s) {
		CAP_IS(&r, o.read, KGENOME_NUCLEO_NET_READ, "stager: the read's descriptor is the socket on every path");
		CAP_IS(&r, o.sock, KGENOME_NUCLEO_NET_OPEN, "stager: the producer keeps its word");
		kgenome_diag_scan_free(r.s);
	}
	/* variant 1 (unbalanced): on the retry path the pop takes the pushed 0, so the read's descriptor is not proven */
	build_stager_v(&e, &o, 1);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(link_how(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD) != KGENOME_DIAG_LINK_PROVEN, "unbalanced: the fd is not PROVEN");
		CAP_IS(&r, o.read, KGENOME_NUCLEO_MEM_READ, "unbalanced: an unproven descriptor keeps the generic word");
		kgenome_diag_scan_free(r.s);
	}

	/* XCHG: socket; xchg rax, rdi; write(rdi, rsp, 16); read(rdi, rsp, 16) */
	re_init(&e, 1);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	s = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 97");                      /* xchg rax, rdi */
	re_b(&e, "48 89 e6 ba 10 00 00 00 b8 01 00 00 00");
	wr = re_here(&e);
	re_b(&e, "0f 05");                      /* write */
	re_b(&e, "31 c0");                      /* xor eax, eax */
	rd = re_here(&e);
	re_b(&e, "0f 05");                      /* read */
	exit_tail(&e);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(link_how(&r, rd, s, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "xchg: read fd <- socket PROVEN (%d)",
		       link_how(&r, rd, s, KGENOME_DIAG_ROLE_FD));
		CAP_IS(&r, wr, KGENOME_NUCLEO_NET_WRITE, "xchg: write to the socket");
		CAP_IS(&r, rd, KGENOME_NUCLEO_NET_READ, "xchg: read from the socket");
		kgenome_diag_scan_free(r.s);
	}

	/* STACK: socket; push rax; mov edi, 5; pop rdi; read */
	re_init(&e, 1);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	s = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "50 bf 05 00 00 00 5f");       /* push rax; mov edi, 5; pop rdi */
	re_b(&e, "48 89 e6 ba 10 00 00 00 31 c0");
	rd = re_here(&e);
	re_b(&e, "0f 05");
	exit_tail(&e);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		CAP_IS(&r, rd, KGENOME_NUCLEO_NET_READ, "stack: the socket comes back off the stack");
		kgenome_diag_scan_free(r.s);
	}

	/* FILE: open; mov rdi, rax; read; write - an opened file stays a file */
	re_init(&e, 1);
	re_b(&e, "bf 00 00 40 00 31 f6 b8 02 00 00 00");    /* mov edi, path; xor esi, esi; mov eax, 2 */
	op = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 89 c7 48 89 e6 ba 10 00 00 00 31 c0");
	rd = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "b8 01 00 00 00");
	wr = re_here(&e);
	re_b(&e, "0f 05");
	exit_tail(&e);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(link_how(&r, rd, op, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "file: read fd <- open PROVEN");
		CAP_IS(&r, rd, KGENOME_NUCLEO_READ, "file: read from an opened file");
		CAP_IS(&r, wr, KGENOME_NUCLEO_WRITE, "file: write to an opened file");
		kgenome_diag_scan_free(r.s);
	}

	/* MAY: the descriptor is the socket on one arm and an opened file on the other */
	re_init(&e, 1);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	s = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 85 c0 78 00");             /* test rax, rax; js open */
	js = re_here(&e) - 1u;
	re_b(&e, "48 89 c7 eb 00");             /* mov rdi, rax; jmp join */
	jm = re_here(&e) - 1u;
	re_fix8(&e, js, re_here(&e));
	re_b(&e, "bf 00 00 40 00 31 f6 b8 02 00 00 00");
	op = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 89 c7");
	re_fix8(&e, jm, re_here(&e));
	re_b(&e, "48 89 e6 ba 10 00 00 00 31 c0");
	rd = re_here(&e);
	re_b(&e, "0f 05");
	exit_tail(&e);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(link_how(&r, rd, s, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_MAY &&
		       link_how(&r, rd, op, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_MAY, "two arms: both fd links MAY (%d %d)",
		       link_how(&r, rd, s, KGENOME_DIAG_ROLE_FD), link_how(&r, rd, op, KGENOME_DIAG_ROLE_FD));
		CAP_IS(&r, rd, KGENOME_NUCLEO_MEM_READ, "two arms: a MAY descriptor keeps the generic word");
		kgenome_diag_scan_free(r.s);
	}

	/* CONSTANT and DUP2: dup2(socket, 0); read(0, ...) - the number 0 is no producer (LIMIT: dup2's answer is not handed on) */
	re_init(&e, 1);
	re_b(&e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	s = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 89 c7 31 f6 b8 21 00 00 00");  /* mov rdi, rax; xor esi, esi; mov eax, 33 */
	d2 = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "31 ff 48 89 e6 ba 10 00 00 00 31 c0");
	rd = re_here(&e);
	re_b(&e, "0f 05");
	exit_tail(&e);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(link_how(&r, d2, s, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "dup2: its fd <- socket PROVEN");
		CAP_IS(&r, d2, KGENOME_NUCLEO_FD_REDIR, "dup2: keeps its word");
		CAP_IS(&r, rd, KGENOME_NUCLEO_MEM_READ, "a constant descriptor keeps the generic word");
		kgenome_diag_scan_free(r.s);
	}

	/* NO CASE: the descriptor is a mapping's address (a producer the vocabulary has no case for) */
	re_init(&e, 1);
	re_b(&e, "31 ff be 00 10 00 00 ba 07 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00");
	s = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 89 c7 48 89 e6 ba 10 00 00 00 31 c0");
	rd = re_here(&e);
	re_b(&e, "0f 05");
	exit_tail(&e);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		CAP_IS(&r, rd, KGENOME_NUCLEO_MEM_READ, "a mapping as descriptor keeps the generic word");
		kgenome_diag_scan_free(r.s);
	}
}

/* The vocabulary's half: every case is a case of the word it refines, and nothing else has one. */
static void t_cap_on_handle_vocab(void)
{
	static const uint16_t gen[] = { KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_MEM_WRITE };
	static const uint16_t mk[] = { KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_NET_RAW, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_FILE_OPEN };
	unsigned g, m;
	uint32_t c;

	for (g = 0; g < 2u; g++)
		for (m = 0; m < 4u; m++) {
			const uint16_t w = kgenome_nucleo_cap_on_handle(gen[g], mk[m]);

			EXPECT(w != KGENOME_NUCLEO_NONE && kgenome_nucleo_cap_generic(w) == gen[g], "vocab: case of %s on %s",
			       kgenome_nucleo_cap_name(gen[g]), kgenome_nucleo_cap_name(mk[m]));
		}
	EXPECT(kgenome_nucleo_cap_on_handle(KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_NET_OPEN) == KGENOME_NUCLEO_NET_READ &&
	       kgenome_nucleo_cap_on_handle(KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_NET_ACCEPT) == KGENOME_NUCLEO_NET_WRITE &&
	       kgenome_nucleo_cap_on_handle(KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_FILE_OPEN) == KGENOME_NUCLEO_READ &&
	       kgenome_nucleo_cap_on_handle(KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_FILE_OPEN) == KGENOME_NUCLEO_WRITE, "vocab: the four words");
	/* exhaustive over the 16-bit space on the producer side for the generic words, and on the call side for a socket */
	for (c = 0; c < 0x10000u; c++) {
		int known = 0;

		for (m = 0; m < 4u; m++)
			known |= c == mk[m];
		if (!known)
			EXPECT(kgenome_nucleo_cap_on_handle(KGENOME_NUCLEO_MEM_READ, (uint16_t)c) == KGENOME_NUCLEO_NONE &&
			       kgenome_nucleo_cap_on_handle(KGENOME_NUCLEO_MEM_WRITE, (uint16_t)c) == KGENOME_NUCLEO_NONE, "vocab: no case on %#x", c);
		if (c != KGENOME_NUCLEO_MEM_READ && c != KGENOME_NUCLEO_MEM_WRITE)
			EXPECT(kgenome_nucleo_cap_on_handle((uint16_t)c, KGENOME_NUCLEO_NET_OPEN) == KGENOME_NUCLEO_NONE,
			       "vocab: %#x is not refined", c);
	}
}

/*
 * The same rule through the SYMBOL route (libc `read`/`write` by name; a PE's recv/send are net words already), against the
 * generator's oracle: a read/write node says net-recv/net-send only when the oracle has its descriptor from ONE socket/accept call on
 * every path (sound), and it says so whenever the engine itself holds every descriptor input PROVEN from a socket (the rule applied).
 */
struct capgen { unsigned stages; long nodes, refined; };

static int capgen_one(void *user, const struct lg_prog *p, const struct lg_cg *c, const struct lg_img *g, const struct lg_oracle *o,
		      int target, int strip, uint64_t seed)
{
	struct capgen *k = user;
	struct lg_scan sc;
	uint32_t i, q, n;
	int s, fails = 0;

	(void)strip;
	if (target != LG_T_ELF64 && target != LG_T_ELF32)
		return 0;
	if (!lg_scan(&sc, g, target, k->stages))
		return 1;
	n = kgenome_diag_scan_count(sc.s);
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc.s, i);
		int api = -1, site = -1, eng_sock = 1, nfd = 0, orc_sock = 0, is_net;

		for (s = 0; s < p->nsite; s++)
			if (h->at == g->code_off + c->site_off[s]) {
				api = p->site_api[s];
				site = s;
			}
		if (api != LG_READ && api != LG_WRITE)
			continue;
		s = site;
		k->nodes++;
		for (q = 0; q < kgenome_diag_in_count(sc.s, i); q++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(sc.s, i, q);
			uint16_t pc;

			if (!x || x->role != KGENOME_DIAG_ROLE_FD)
				continue;
			nfd++;
			pc = x->from < n ? kgenome_diag_scan_at(sc.s, x->from)->cap : 0;
			if (x->how != KGENOME_DIAG_LINK_PROVEN || (pc != KGENOME_NUCLEO_NET_OPEN && pc != KGENOME_NUCLEO_NET_ACCEPT))
				eng_sock = 0;
		}
		eng_sock = eng_sock && nfd;
		if (o) {
			const uint64_t m = o->obs[s][0];
			int pr;

			for (pr = 0; pr < p->nsite; pr++)
				if (m == (1ull << pr) && !o->unc[s][0] && (p->site_api[pr] == LG_SOCKET || p->site_api[pr] == LG_ACCEPT))
					orc_sock = 1;
		}
		is_net = h->cap == KGENOME_NUCLEO_NET_READ || h->cap == KGENOME_NUCLEO_NET_WRITE;
		k->refined += is_net;
		if (is_net != eng_sock) {
			printf("  seed %llu: node at %#llx is %s, its descriptor inputs %s\n", (unsigned long long)seed, (unsigned long long)h->at,
			       kgenome_nucleo_cap_name(h->cap), eng_sock ? "all PROVEN from a socket" : "not all PROVEN from a socket");
			fails++;
		}
		if (is_net && o && !orc_sock) {
			printf("  seed %llu: node at %#llx says %s, the oracle has no single socket for its descriptor\n", (unsigned long long)seed,
			       (unsigned long long)h->at, kgenome_nucleo_cap_name(h->cap));
			fails++;
		}
	}
	kgenome_diag_scan_free(sc.s);
	return fails;
}

static void t_cap_generated(void)
{
	struct capgen k = { KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | KGENOME_LINEAGE_S_SUMM, 0, 0 };
	long programs = 0;

	CK(lg_each(LG_F_CALL | LG_F_LOOP, (int)(60 * hk_scale()), 9100, &k.stages, &programs, capgen_one, &k) == 0);
	/* the rule must have fired: a campaign where no read is refined proves nothing */
	EXPECT(k.refined > 0 && k.refined < k.nodes, "generated: %ld of %ld read/write nodes refined (want some, not all)", k.refined, k.nodes);
}

/*
 * ---- NO NODE WITHOUT A SITE: the emulate route's hop is placed at the branch that entered (CLR-D2, 2026-11-17) ----
 *
 * The emulate route published "control entered a region a call produced" at KGENOME_BROKEN (the arrival, in produced bytes, has no
 * file offset): a node no function held, beside the static route's node of the same `jmp`. It is placed at the transfer's own
 * instruction now and folds with that node. Why no test saw it: (a) no lineage test ran the emulate route (re_scan asked for the
 * syscall route and the stage), so nodes_inside never met a hop.
 */
static void t_hop_site(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r;
	uint32_t i, n, exec = 0;

	build_stager(&e, &o);
	CK(re_scan_run(&r, &e, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_EMULATE | KGENOME_DIAG_RUN_LINEAGE));
	if (!r.s)
		return;
	nodes_inside(&r, e.n, "stager emulated");
	n = kgenome_diag_scan_count(r.s);
	for (i = 0; i < n; i++)
		exec += kgenome_diag_scan_at(r.s, i)->cap == KGENOME_NUCLEO_EXEC_REG;
	EXPECT(exec == 1u, "stager emulated: one exec-memory node, the jump's (%u)", exec);
	CAP_IS(&r, o.jmp, KGENOME_NUCLEO_EXEC_REG, "stager emulated: the node is at the jump");
	EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "stager emulated: jmp target <- mmap PROVEN");
	CAP_IS(&r, o.read, KGENOME_NUCLEO_NET_READ, "stager emulated: the read is a receive");
	kgenome_diag_scan_free(r.s);
}

/* how the CONTENT link (the bytes the node at `cat` executes are what the node at `pat` wrote) was said: -1 none, -2 no such node */
static int content_how(const struct rscan *r, uint64_t cat, uint64_t pat)
{
	uint32_t ci, pi, k;

	if (!node_at(r, cat, &ci) || !node_at(r, pat, &pi))
		return -2;
	for (k = 0; k < kgenome_diag_in_count(r->s, ci); k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(r->s, ci, k);

		if (x && x->from == pi && x->role == KGENOME_DIAG_ROLE_CONTENT)
			return x->kind == KGENOME_DIAG_KIND_SHARED ? x->how : -3;
	}
	return -1;
}

/*
 * WRITTEN, THEN EXECUTED (owner 2026-11-17: "mem-alloc-exec, then net-recv, and only then exec-memory"). The stager reads into the mmap'd region and
 * jumps into it: the engine links the read to the jump (role CONTENT, kind SHARED, PROVEN), on the static route and on the emulate route, and keeps the
 * region's own target link. A read into ANOTHER buffer (variant 8: the stack) gives none, nor does a region the stage proves on no path (variant 1:
 * unbalanced, the target is not PROVEN). Never in the four-input view. Why missed: (a) no stage made the relation; no test asked for it.
 */
static void t_written_exec(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r;
	unsigned run;

	for (run = 0; run < 2u; run++) {
		build_stager(&e, &o);
		CK(re_scan_run(&r, &e, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_LINEAGE | (run ? KGENOME_DIAG_RUN_EMULATE : 0u)));
		if (!r.s)
			continue;
		EXPECT(content_how(&r, o.jmp, o.read) == KGENOME_DIAG_LINK_PROVEN, "written-exec run %u: jmp content <- read PROVEN SHARED (%d)", run,
		       content_how(&r, o.jmp, o.read));
		EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "written-exec run %u: the target link stays", run);
		EXPECT(content_how(&r, o.jmp, o.mmap) == -1 && content_how(&r, o.jmp, o.sock) == -1, "written-exec run %u: content from nothing else", run);
		{
			const struct kgenome_diag_hit *hj = node_at(&r, o.jmp, NULL);
			uint8_t q;

			for (q = 0; hj && q < hj->n_in; q++)
				EXPECT(hj->in[q].role != KGENOME_DIAG_ROLE_CONTENT, "written-exec: CONTENT is not in the four-input view");
		}
		kgenome_diag_scan_free(r.s);
	}
	build_stager_v(&e, &o, 8);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "variant 8: jmp target <- mmap PROVEN (%d)",
		       link_how(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET));
		EXPECT(content_how(&r, o.jmp, o.read) < 0, "variant 8: a read into the stack is not what the jump runs (%d)", content_how(&r, o.jmp, o.read));
		kgenome_diag_scan_free(r.s);
	}
	build_stager_v(&e, &o, 1);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(content_how(&r, o.jmp, o.read) < 0, "variant 1: no PROVEN region, no content link (%d)", content_how(&r, o.jmp, o.read));
		kgenome_diag_scan_free(r.s);
	}
}

/* the input of the node at `cat` from the node at `pat` with this role and kind: its flags (KGENOME_DIAG_IN_*) + 0x100 with its how in bits 8.., -1 none */
static int in_of(const struct rscan *r, uint64_t cat, uint64_t pat, unsigned role, unsigned kind, unsigned *flags)
{
	uint32_t ci, pi, k;

	if (!node_at(r, cat, &ci) || !node_at(r, pat, &pi))
		return -2;
	for (k = 0; k < kgenome_diag_in_count(r->s, ci); k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(r->s, ci, k);

		if (x && x->from == pi && x->role == role && x->kind == kind) {
			if (flags)
				*flags = x->flags;
			return x->how;
		}
	}
	return -1;
}

/*
 * THE USE CHAIN (owner 2026-11-17: "net-open linked DIRECTLY to net-recv?"). Several consumers of one PROVEN value, the earlier dominating the later, are
 * drawn as a chain: the later one gets a link from the earlier one (kind SHARED, its own role, PROVEN) and its direct link from the producer stays as a fact
 * with KGENOME_DIAG_IN_UNDRAWN. In the stager: socket -> connect -> read (fd), mmap -> read -> jmp (the region: the jump already has the content link
 * from the read, so no second one is made). A second use on ANOTHER ARM (connect on one, write on the other) is not dominated: no chain, the direct link
 * stays drawn. Why missed: (a) no stage decided which of the facts is the relation to draw; the filler drew every input from its producer.
 */
static void t_use_chain(void)
{
	static struct rawelf e;
	struct stager_at o;
	struct rscan r;
	unsigned fl = 0;
	uint32_t js, jend, l2, end, sock, conn, clos;

	build_stager(&e, &o);
	CK(re_scan(&r, &e));
	if (r.s) {
		EXPECT(in_of(&r, o.read, o.conn, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_SHARED, NULL) == KGENOME_DIAG_LINK_PROVEN,
		       "use chain: read fd <- connect SHARED PROVEN (%d)", in_of(&r, o.read, o.conn, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_SHARED, NULL));
		EXPECT(in_of(&r, o.read, o.sock, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED, &fl) == KGENOME_DIAG_LINK_PROVEN && (fl & KGENOME_DIAG_IN_UNDRAWN),
		       "use chain: read fd <- socket is kept, undrawn (flags %u)", fl);
		fl = 0;
		EXPECT(in_of(&r, o.conn, o.sock, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED, &fl) == KGENOME_DIAG_LINK_PROVEN && !(fl & KGENOME_DIAG_IN_UNDRAWN),
		       "use chain: the first use is drawn from the producer (flags %u)", fl);
		fl = 0;
		EXPECT(in_of(&r, o.jmp, o.mmap, KGENOME_DIAG_ROLE_TARGET, KGENOME_DIAG_KIND_PRODUCED, &fl) == KGENOME_DIAG_LINK_PROVEN && (fl & KGENOME_DIAG_IN_UNDRAWN),
		       "use chain: jmp target <- mmap is kept, undrawn (flags %u)", fl);
		EXPECT(in_of(&r, o.jmp, o.read, KGENOME_DIAG_ROLE_TARGET, KGENOME_DIAG_KIND_SHARED, NULL) == -1 && content_how(&r, o.jmp, o.read) == KGENOME_DIAG_LINK_PROVEN,
		       "use chain: the read -> jmp relation is the content link, not a second one");
		kgenome_diag_scan_free(r.s);
	}
	/* two arms: socket; js L2; connect(fd); jmp end; L2: write(fd); end: exit */
	re_init(&e, 1);
	re_b(&e, "bf 02 00 00 00");
	re_b(&e, "be 01 00 00 00");
	re_b(&e, "31 d2");
	re_b(&e, "b8 29 00 00 00");
	sock = re_here(&e);
	re_b(&e, "0f 05");
	re_b(&e, "48 89 c7");                   /* mov rdi, rax */
	re_b(&e, "48 85 c0");
	re_b(&e, "78 00");                      /* js L2 */
	js = re_here(&e) - 1u;
	re_b(&e, "6a 00");
	re_b(&e, "48 89 e6");
	re_b(&e, "ba 10 00 00 00");
	re_b(&e, "b8 2a 00 00 00");
	conn = re_here(&e);
	re_b(&e, "0f 05");                      /* connect */
	re_b(&e, "eb 00");                      /* jmp end */
	jend = re_here(&e) - 1u;
	l2 = re_here(&e);
	re_b(&e, "b8 01 00 00 00");             /* write(fd, ...) */
	clos = re_here(&e);
	re_b(&e, "0f 05");                      /* write */
	end = re_here(&e);
	re_b(&e, "b8 3c 00 00 00");
	re_b(&e, "31 ff");
	re_b(&e, "0f 05");
	re_fix8(&e, js, l2);
	re_fix8(&e, jend, end);
	re_finish(&e);
	CK(re_scan(&r, &e));
	if (r.s) {
		fl = 0;
		EXPECT(in_of(&r, clos, sock, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED, &fl) == KGENOME_DIAG_LINK_PROVEN && !(fl & KGENOME_DIAG_IN_UNDRAWN),
		       "two arms: the write fd <- socket stays drawn (how %d flags %u)", in_of(&r, clos, sock, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED, NULL), fl);
		EXPECT(in_of(&r, clos, conn, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_SHARED, NULL) < 0, "two arms: no chain from the connect on the other arm");
		kgenome_diag_scan_free(r.s);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_use_chain();
	t_written_exec();
	t_cap_on_handle_vocab();
	t_cap_by_handle();
	t_cap_generated();
	t_hop_site();
	t_stager();
	t_stager_variants();
	t_i386();
	t_classes();
	t_overwrite_and_cqo();
	t_cqo_call(1);
	t_cqo_call(0);
	t_clobber_and_status();
	t_status_no_field();
	t_many_inputs();
	t_local_stack(0);
	t_local_stack(1);
	t_local_stack(2);
	t_local_stack(3);
	t_outside_caller(0);
	t_outside_caller(1);
	t_wide_value();
	t_noret_order();
	t_idempotent();
	t_truth_tail_jump_carry();
	t_truth_two_arms();
	t_truth_wrapper_job();
	t_truth_shared_syscall();
	printf("lineage_sites: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
