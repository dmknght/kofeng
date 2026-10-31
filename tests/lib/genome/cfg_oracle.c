/*
 * genome / cfg_oracle - the blocks and edges of x86 code against GNU objdump's listing, an oracle that shares
 * nothing with the lib: not the decoder (objdump decodes), not the table (the mnemonic text decides what a branch
 * is), not the builder (a short leader rule written here over the listing).
 *
 *   GENERATED   random programs assembled for x86-64 and i386, written to an anonymous memory file (nothing on disk),
 *               listed by objdump -D -b binary, and compared with the graph of the lib's own decode of the same bytes
 *   REAL        up to 400 functions of each of four libraries of this machine (code other people's compilers wrote),
 *               split where objdump's listing starts a symbol; a function whose instruction lengths objdump and the
 *               decoder disagree on is counted and left out (that is the decoder's own test, cov_x86_objdump), and so
 *               is one with jrcxz/jecxz/jcxz in it: the decoder reports those as OTHER, defect CL-1
 *
 * THE LEADER DEFINITION is the lib's (cfg_isa.c): block starts are the entry, a local branch target and the
 * instruction after ret / iret / ud2 / jmp / a local conditional branch; a conditional branch out of the function
 * is no block end; an indirect jump is an exit. Compared: block count, reachable count, edge count, and for every
 * block its start address and the start addresses of its successors.
 *
 * Skipped, visibly, when objdump is not installed.
 */
#define _GNU_SOURCE
#include "cfg_kit.h"
#include "objdump_kit.h"

#include <sys/mman.h>
#include <unistd.h>

struct oi {
	uint64_t addr;
	unsigned n;
	uint8_t  b[16];
	char     m[24];
	char     opd[96];
};

struct oc {
	uint32_t nb, n_blk, n_edge;
	uint64_t start[4096];
	uint32_t term[4096];
	uint64_t succ[4096][2];         /* start addresses, 0 = none */
	uint8_t  reach[4096];
};

static void split_text(const char *text, char *m, size_t mcap, char *opd, size_t ocap)
{
	const char *p = text;

	for (;;) {
		size_t i = 0;

		while (p[i] && p[i] != ' ' && i + 1 < mcap) {
			m[i] = (char)tolower((unsigned char)p[i]);
			i++;
		}
		m[i] = 0;
		p += i;
		while (*p == ' ')
			p++;
		if (!is_prefix(m) || !*p)
			break;
	}
	snprintf(opd, ocap, "%s", p);
}

enum { C_NONE, C_EXIT, C_JUMP, C_COND };

static int class_of_mnemonic(const char *m, const char *opd)
{
	const char *sym = strchr(opd, '<');     /* a symbol's name may hold a '*' (<*ABS*+0x..@plt>): look only before it */
	const char *star = strchr(opd, '*');
	const int direct = isxdigit((unsigned char)opd[0]) && !(star && (!sym || star < sym));

	if (!strncmp(m, "ret", 3) || !strncmp(m, "lret", 4) || !strncmp(m, "iret", 4) || !strcmp(m, "ud2") || !strcmp(m, "ud1") || !strcmp(m, "ud0"))
		return C_EXIT;
	if (!strcmp(m, "jmp"))
		return direct ? C_JUMP : C_EXIT;
	if (!strcmp(m, "ljmp") || !strcmp(m, "jmpf"))
		return C_EXIT;
	if (!strncmp(m, "loop", 4) || !strcmp(m, "jrcxz") || !strcmp(m, "jecxz") || !strcmp(m, "jcxz"))
		return direct ? C_COND : C_NONE;
	if (m[0] == 'j' && m[1] && strcmp(m, "jmp"))
		return direct ? C_COND : C_NONE;
	return C_NONE;
}

static int find_addr(const struct oi *v, uint32_t n, uint64_t a)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		const uint32_t mid = (lo + hi) / 2;

		if (v[mid].addr < a) lo = mid + 1; else hi = mid;
	}
	return lo < n && v[lo].addr == a ? (int)lo : -1;
}

/* The oracle graph from the listing. */
static void oracle(const struct oi *v, uint32_t n, struct oc *o)
{
	uint8_t *lead = calloc(n + 1u, 1);
	int *tj = malloc((size_t)(n + 1u) * sizeof *tj);
	uint8_t *cls = calloc(n + 1u, 1);
	uint32_t i, *blk = malloc((size_t)(n + 1u) * sizeof *blk), b, stk[4096], sp = 0;

	memset(o, 0, sizeof *o);
	for (i = 0; i < n; i++) {
		tj[i] = -1;
		cls[i] = (uint8_t)class_of_mnemonic(v[i].m, v[i].opd);
		if (cls[i] == C_JUMP || cls[i] == C_COND) {
			tj[i] = find_addr(v, n, strtoull(v[i].opd, NULL, 16));
			if (tj[i] < 0)
				cls[i] = cls[i] == C_JUMP ? C_EXIT : C_NONE;
		}
	}
	lead[0] = 1;
	for (i = 0; i < n; i++) {
		if (cls[i] != C_NONE && i + 1u < n)
			lead[i + 1u] = 1;
		if (tj[i] >= 0 && (cls[i] == C_JUMP || cls[i] == C_COND))
			lead[tj[i]] = 1;
	}
	for (i = 0; i < n; i++) {
		if (lead[i]) {
			if (o->nb >= 4096) { o->nb = 4097; break; }
			o->start[o->nb++] = v[i].addr;
		}
		blk[i] = o->nb - 1u;
	}
	if (o->nb > 4096)
		goto out;
	for (b = 0; b < o->nb; b++) {
		const uint32_t first = (uint32_t)find_addr(v, n, o->start[b]);
		const uint32_t end = b + 1u < o->nb ? (uint32_t)find_addr(v, n, o->start[b + 1u]) : n;
		const uint32_t t = end - 1u;
		const uint64_t next = b + 1u < o->nb ? o->start[b + 1u] : 0;

		(void)first;
		o->term[b] = KGENOME_CFG_T_FALL;
		switch (cls[t]) {
		case C_COND: o->term[b] = KGENOME_CFG_T_COND; o->succ[b][0] = o->start[blk[tj[t]]]; o->succ[b][1] = next; break;
		case C_JUMP: o->term[b] = KGENOME_CFG_T_JUMP; o->succ[b][0] = o->start[blk[tj[t]]]; break;
		case C_EXIT: o->term[b] = KGENOME_CFG_T_EXIT; break;
		default: o->succ[b][0] = next; break;
		}
	}
	o->reach[0] = 1;
	stk[sp++] = 0;
	while (sp) {
		const uint32_t x = stk[--sp];
		unsigned e;

		for (e = 0; e < 2; e++) {
			uint32_t s;

			if (!o->succ[x][e])
				continue;
			for (s = 0; s < o->nb && o->start[s] != o->succ[x][e]; s++)
				;
			o->n_edge++;
			if (!o->reach[s]) {
				o->reach[s] = 1;
				stk[sp++] = s;
			}
		}
	}
	for (b = 0; b < o->nb; b++)
		o->n_blk += o->reach[b];
out:
	free(lead); free(tj); free(cls); free(blk);
}

/* Compare the lib's graph of `in` (the lib's own decode) with the oracle's. Returns 1 when equal. */
static int same(const struct kgenome_cfg *g, const struct kgenome_cell_insn *in, const struct oc *o, char *why, size_t cap)
{
	uint32_t b;

	if (g->n_all != o->nb || g->n_blk != o->n_blk || g->n_edge != o->n_edge) {
		snprintf(why, cap, "n_all %u/%u n_blk %u/%u n_edge %u/%u", g->n_all, o->nb, g->n_blk, o->n_blk, g->n_edge, o->n_edge);
		return 0;
	}
	for (b = 0; b < o->nb; b++) {
		const struct kgenome_cfg_block *k = &g->b[b];
		uint64_t s0 = k->succ[0] == KGENOME_CFG_NONE ? 0 : in[g->b[k->succ[0]].first].at_va;
		uint64_t s1 = k->succ[1] == KGENOME_CFG_NONE ? 0 : in[g->b[k->succ[1]].first].at_va;

		if (in[k->first].at_va != o->start[b] || k->term != o->term[b] || s0 != o->succ[b][0] || s1 != o->succ[b][1] || k->reach != o->reach[b]) {
			snprintf(why, cap, "block %u at %llx/%llx term %u/%u succ %llx,%llx/%llx,%llx", b, (unsigned long long)in[k->first].at_va,
				 (unsigned long long)o->start[b], k->term, o->term[b], (unsigned long long)s0, (unsigned long long)s1,
				 (unsigned long long)o->succ[b][0], (unsigned long long)o->succ[b][1]);
			return 0;
		}
	}
	return 1;
}

/* Decode the listing's bytes with the lib, instruction by instruction. 0 when a length disagrees. */
static int lib_decode(const struct oi *v, uint32_t n, unsigned arch, struct kgenome_cell_insn *in)
{
	uint8_t buf[1 << 16];
	uint32_t i, pos = 0;

	for (i = 0; i < n; i++) {
		if (pos + v[i].n > sizeof buf)
			return 0;
		memcpy(buf + pos, v[i].b, v[i].n);
		pos += v[i].n;
	}
	pos = 0;
	for (i = 0; i < n; i++) {
		const uint32_t l = kgenome_cell_decode(arch, 0, buf + pos, pos + 16u <= sizeof buf ? 16u : (uint32_t)sizeof buf - pos, v[i].addr, &in[i]);

		if (l != v[i].n)
			return 0;
		in[i].at = pos;
		pos += l;
	}
	return 1;
}

static int compare_function(const struct oi *v, uint32_t n, unsigned arch, char *why, size_t cap)
{
	struct kgenome_cell_insn *in = malloc((size_t)n * sizeof *in);
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g;
	struct oc *o = malloc(sizeof *o);
	int rc;

	if (!lib_decode(v, n, arch, in)) {
		free(in); free(o);
		return -1;      /* the decoder and objdump disagree about where an instruction ends: not this test's finding */
	}
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = arch; rq.va_lo = v[0].addr; rq.va_hi = v[n - 1u].addr + v[n - 1u].n;
	if (kgenome_cfg_build(&rq, &g) != KGENOME_OK) {
		snprintf(why, cap, "build failed");
		rc = 0;
	} else {
		oracle(v, n, o);
		rc = o->nb <= 4096 ? same(&g, in, o, why, cap) : -1;
	}
	kgenome_cfg_free(&g, NULL);
	free(in);
	free(o);
	return rc;
}

static int have_objdump(void) { return access("/usr/bin/objdump", X_OK) == 0; }

static void generated(void)
{
	static const struct { unsigned isa; const char *m; } K[] = { { 0, "i386:x86-64" }, { 1, "i386" } };
	unsigned k, compared = 0, bad = 0;
	struct crng rg;

	crng_seed(&rg, 555);
	for (k = 0; k < 2; k++) {
		unsigned round;

		for (round = 0; round < 60; round++) {
			struct prog p;
			struct blob x;
			char cmd[300], ln[512];
			FILE *f;
			int fd;
			struct oi *v = NULL;
			uint32_t n = 0;

			prog_random(&ISAS[K[k].isa], &rg, 6u + crng_below(&rg, 50), &p);
			if (!blob_make(&ISAS[K[k].isa], &p, 0x400000u, &x)) { prog_free(&p); continue; }
			fd = memfd_create("kofeng-cfg", 0);
			if (fd < 0 || write(fd, x.b, x.len) != (ssize_t)x.len) {
				printf("  (no anonymous file: skipped)\n");
				if (fd >= 0) close(fd);
				blob_free(&x); prog_free(&p);
				return;
			}
			snprintf(cmd, sizeof cmd, "/usr/bin/objdump -D -w -b binary -m %s --adjust-vma=0x400000 /proc/%d/fd/%d 2>/dev/null", K[k].m, (int)getpid(), fd);
			f = popen(cmd, "r");
			while (f && fgets(ln, sizeof ln, f)) {
				struct ins i;

				if (!parse(ln, &i) || i.addr < 0x400000u || i.addr >= 0x400000u + x.len)
					continue;
				v = realloc(v, (size_t)(n + 1u) * sizeof *v);
				v[n].addr = i.addr; v[n].n = i.n; memcpy(v[n].b, i.b, i.n);
				split_text(i.text, v[n].m, sizeof v[n].m, v[n].opd, sizeof v[n].opd);
				n++;
			}
			if (f)
				pclose(f);
			close(fd);
			if (n) {
				char why[200];
				const int rc = compare_function(v, n, ISAS[K[k].isa].arch, why, sizeof why);

				CKM(rc != 0, "%s round %u: %s", ISAS[K[k].isa].name, round, why);
				if (rc == 0) bad++;
				if (rc > 0) compared++;
				CKM(rc != -1, "%s round %u: objdump and the decoder disagree on a length in generated code", ISAS[K[k].isa].name, round);
			}
			free(v);
			blob_free(&x);
			prog_free(&p);
		}
	}
	printf("  generated: %u programs compared with objdump, %u differ\n", compared, bad);
	CK(compared > 90);
}

static void real(void)
{
	static const char *const files[] = { "/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3" };
	unsigned f, funcs = 0, same_n = 0, bad = 0, skipped_len = 0, skipped_cl1 = 0, blocks = 0;

	for (f = 0; f < sizeof files / sizeof files[0]; f++) {
		char cmd[300], ln[1024];
		FILE *p;
		struct oi *v = NULL;
		uint32_t n = 0, cap = 0;
		unsigned nf = 0;
		int in_fn = 0;

		if (access(files[f], R_OK))
			continue;
		snprintf(cmd, sizeof cmd, "/usr/bin/objdump -d -w -j .text %s 2>/dev/null", files[f]);
		p = popen(cmd, "r");
		if (!p)
			continue;
		for (;;) {
			const int got = fgets(ln, sizeof ln, p) != NULL;
			int header = got && strchr(ln, '<') && strstr(ln, ">:") && isxdigit((unsigned char)ln[0]);

			if ((!got || header) && in_fn && n >= 3 && nf < 400) {
				char why[200];
				unsigned q;
				int cl1 = 0, rc;

				for (q = 0; q < n; q++)
					cl1 |= !strcmp(v[q].m, "jrcxz") || !strcmp(v[q].m, "jecxz") || !strcmp(v[q].m, "jcxz");
				if (cl1) {
					skipped_cl1++;
				} else {
					rc = compare_function(v, n, KGENOME_ARCH_X86_64, why, sizeof why);
					if (rc < 0) {
						skipped_len++;
					} else {
						funcs++;
						nf++;
						if (rc) same_n++; else { bad++; printf("    %s function at %llx: %s\n", files[f], (unsigned long long)v[0].addr, why); }
					}
				}
			}
			if (!got)
				break;
			if (header) {
				n = 0;
				in_fn = 1;
				continue;
			}
			if (in_fn) {
				struct ins i;

				if (!parse(ln, &i))
					continue;
				if (n == cap) { cap = cap ? cap * 2 : 256; v = realloc(v, cap * sizeof *v); }
				if (n && v[n - 1u].addr + v[n - 1u].n != i.addr) {      /* a gap in the listing: a function of its own */
					n = 0;
				}
				v[n].addr = i.addr; v[n].n = i.n; memcpy(v[n].b, i.b, i.n);
				split_text(i.text, v[n].m, sizeof v[n].m, v[n].opd, sizeof v[n].opd);
				n++;
			}
		}
		pclose(p);
		free(v);
	}
	blocks = same_n;
	printf("  real code: %u functions compared (%u equal, %u differ); left out: %u decoder/objdump length disagreements, %u with jrcxz (CL-1)\n",
	       funcs, same_n, bad, skipped_len, skipped_cl1);
	(void)blocks;
	CKM(bad == 0, "%u functions of real code differ from objdump's reading", bad);
	CKM(funcs > 300, "only %u functions compared", funcs);
}

int main(void)
{
	if (!have_objdump()) {
		printf("cfg_oracle: SKIPPED (/usr/bin/objdump is not installed)\n");
		return 0;
	}
	generated();
	real();
	if (fails)
		printf("cfg_oracle: %d FAILED\n", fails);
	else
		printf("cfg_oracle: ok\n");
	return fails != 0;
}
