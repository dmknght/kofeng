/*
 * diag_stager_join - the stager's two halves as ONE diagnose of two blocks that meet, from the source to a match on bytes.
 *
 * The disabled precedent (docs/disabled): mem_execsyscall_00 (a W+X region a read fills and a jump enters) and net_recvsyscall_00
 * (a connected socket whose descriptor a read uses), joined by a signature on "the read is the same read"
 * (kof_diag_share(KOF_NUCLEO_MEM_READ, ...), trojan_meterp_00). Owner, 2026-11-14: a signature must be able to state the shared
 * node as required, identified by its nucleo capability. Here the two halves are the two blocks of one source, the join is
 * KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ), ksigbuilder writes the record, kof_diag_load reads it, and the syscall route reads
 * the nodes out of bytes built here:
 *
 *   the stager   socket -> r12, connect(r12), mmap(RWX) -> r13, read(r12, r13, n), jmp r13
 *   the decoy    socket -> r12, connect(r12), open(path) -> r14, mmap(RWX) -> r13, read(r12, rsp, 16), read(r14, r13, n), jmp r13
 *                (both halves are there; the socket's read fills the stack and the file's read fills the region)
 *
 * The bytes are written instruction by instruction below (no sample's bytes). The one-block halves are built too: each matches
 * the decoy, so it is the join that says no; and a star a single block expresses builds and matches as it always did.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caps_fix.h"

static const char *builder = "build/release/bin/ksigbuilder";
static char root[256];

#define HALF_MEM \
	"#include <kofmod/kofdiagtree.h>\n" \
	"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n" \
	"KOF_DIAG_HAS_ATTRB(KOF_FACT_MAP_PERM, KOF_PERM_W | KOF_PERM_X);\n" \
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n" \
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n" \
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);\n"
#define HALF_NET \
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\n" \
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_CONNECT);\n" \
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"

static const char src_join[] = "KOF_DIAG_NAME(stager_join);\n" HALF_MEM HALF_NET
	"KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n";
static const char src_mem[] = "KOF_DIAG_NAME(stager_mem);\n" HALF_MEM;
static const char src_net[] = "KOF_DIAG_NAME(stager_net);\n"
	"#include <kofmod/kofdiagtree.h>\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n" HALF_NET;

/* Build one source into a record with the real builder and load it. 1 and the diagnose, or 0. */
static struct kof_diag_node rec_node[3][KOF_DIAG_MAX_NODE];
static char rec_name[3][256], rec_needs[3][1024];

/* `slot` is the storage the loaded diagnose keeps pointing into: one each. */
static int build(int slot, const char *leaf, const char *text, struct kof_diag *d, uint8_t **rec_out, size_t *n_out)
{
	char src[400], out[400], cmd[1200];
	struct kof_diag_store st;
	FILE *f;
	uint8_t *b;
	long L;

	snprintf(src, sizeof src, "%s/%s.c", root, leaf);
	snprintf(out, sizeof out, "%s/%s.rec", root, leaf);
	f = fopen(src, "wb");
	if (!f || fwrite(text, 1, strlen(text), f) != strlen(text)) {
		if (f)
			fclose(f);
		return 0;
	}
	fclose(f);
	snprintf(cmd, sizeof cmd, "%s --diagnose '%s' '%s' >/dev/null 2>&1", builder, src, out);
	if (system(cmd) != 0)
		return 0;
	f = fopen(out, "rb");
	if (!f)
		return 0;
	fseek(f, 0, SEEK_END);
	L = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)L + 1u);
	if (!b || fread(b, 1, (size_t)L, f) != (size_t)L) {
		free(b);
		fclose(f);
		return 0;
	}
	fclose(f);
	st.node = rec_node[slot];
	st.name = rec_name[slot];
	st.needs = rec_needs[slot];
	st.name_cap = sizeof rec_name[slot];
	st.needs_cap = sizeof rec_needs[slot];
	st.max_node = (uint8_t)KOF_DIAG_MAX_NODE;
	if (!kof_diag_load(kof_buf_make(b, (uint64_t)L), d, &st)) {
		free(b);
		return 0;
	}
	*rec_out = b;
	*n_out = (size_t)L;
	return 1;
}

/* The instructions, as bytes. */
#define I_SOCKET   0xb8, 0x29, 0, 0, 0,  0xbf, 2, 0, 0, 0,  0xbe, 1, 0, 0, 0,  0x31, 0xd2,  0x0f, 0x05,  0x49, 0x89, 0xc4
#define I_CONNECT  0x4c, 0x89, 0xe7,  0x48, 0x89, 0xe6,  0xba, 0x10, 0, 0, 0,  0xb8, 0x2a, 0, 0, 0,  0x0f, 0x05
#define I_MMAP     0x31, 0xff,  0xbe, 0, 0x10, 0, 0,  0xba, 7, 0, 0, 0,  0x41, 0xba, 0x22, 0, 0, 0, \
		   0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,  0x45, 0x31, 0xc9,  0xb8, 9, 0, 0, 0,  0x0f, 0x05,  0x49, 0x89, 0xc5
#define I_OPEN     0x48, 0x89, 0xe7,  0x31, 0xf6,  0xb8, 2, 0, 0, 0,  0x0f, 0x05,  0x49, 0x89, 0xc6
#define I_READ_SOCK_REGION 0x4c, 0x89, 0xe7,  0x4c, 0x89, 0xee,  0xba, 0, 0x10, 0, 0,  0x31, 0xc0,  0x0f, 0x05
#define I_READ_SOCK_STACK  0x4c, 0x89, 0xe7,  0x48, 0x89, 0xe6,  0xba, 0x10, 0, 0, 0,  0x31, 0xc0,  0x0f, 0x05
#define I_READ_FILE_REGION 0x4c, 0x89, 0xf7,  0x4c, 0x89, 0xee,  0xba, 0, 0x10, 0, 0,  0x31, 0xc0,  0x0f, 0x05
#define I_JMP_REGION       0x41, 0xff, 0xe5

static const uint8_t stager[] = { I_SOCKET, I_CONNECT, I_MMAP, I_READ_SOCK_REGION, I_JMP_REGION };
static const uint8_t decoy[] = { I_SOCKET, I_CONNECT, I_OPEN, I_MMAP, I_READ_SOCK_STACK, I_READ_FILE_REGION, I_JMP_REGION };

static struct kgenome_diag_scan *scan_of(const uint8_t *code, uint64_t n, uint8_t *img, struct kof_obj_ctx *ctx, void *view)
{
	uint64_t len = cf_elf64(img, 4096u, code, n);

	return cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, ctx, view);
}

int main(void)
{
	static uint8_t img_s[4096], img_d[4096];
	static unsigned char view_s[1u << 20], view_d[1u << 20];
	struct kof_obj_ctx ctx_s, ctx_d;
	struct kgenome_diag_scan *ss, *sd;
	struct kof_diag dj, dm, dn;
	uint8_t *rj = NULL, *rm = NULL, *rn = NULL;
	size_t nj = 0, nm = 0, nn = 0;
	uint16_t b[KOF_DIAG_MAX_NODE];
	uint8_t nb = 0;

	if (access(builder, X_OK) != 0) {
		printf("diag_stager_join: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_stagerjoin_XXXXXX");
	if (!mkdtemp(root)) {
		printf("diag_stager_join: cannot make a scratch directory\n");
		return 2;
	}
	/* The record: six nodes, two roots, the join on the second block's read. */
	CK(build(0, "stager_join", src_join, &dj, &rj, &nj));
	CK(dj.n_node == 6);
	if (dj.n_node == 6) {
		CK(dj.node[0].parent == KOF_DIAG_NO_PARENT && dj.node[3].parent == KOF_DIAG_NO_PARENT);
		CK(dj.node[4].parent == 3 && dj.node[5].parent == 3 && (dj.node[5].bits & KOF_DIAG_B_JOIN));
		CK(!(dj.node[1].bits & KOF_DIAG_B_JOIN));
	}
	CK(build(1, "stager_mem", src_mem, &dm, &rm, &nm));
	CK(build(2, "stager_net", src_net, &dn, &rn, &nn));
	/* a star writes the bytes it always wrote: head parent 0xff, tails 0, no join bit (the record layout did not move) */
	CK(rm && nm > 4u + 10u + 24u && rm[4 + 10 + 4] == KOF_DIAG_NO_PARENT && rm[4 + 10 + 8 + 4] == 0 && rm[4 + 10 + 16 + 4] == 0 &&
	   rm[4 + 10 + 8 + 6] == 0 && rm[4 + 10 + 16 + 6] == 0);

	ss = scan_of(stager, sizeof stager, img_s, &ctx_s, view_s);
	sd = scan_of(decoy, sizeof decoy, img_d, &ctx_d, view_d);
	CK(ss != NULL && sd != NULL);
	if (ss && sd) {
		/* the shape: the stager's read takes the socket AND the region; the join diagnose matches it, and binds one read for both blocks */
		CK(kof_diag_match_known(ss, &dj, b, &nb) == KOF_DIAG_MATCH_YES);
		CK(nb == 6 && b[1] == b[5]);
		CK(kof_diag_match_known(ss, &dm, b, &nb) == KOF_DIAG_MATCH_YES);
		CK(kof_diag_match_known(ss, &dn, b, &nb) == KOF_DIAG_MATCH_YES);
		/* the decoy: each half is there, and the two do not meet */
		CK(kof_diag_match_known(sd, &dm, b, &nb) == KOF_DIAG_MATCH_YES);
		CK(kof_diag_match_known(sd, &dn, b, &nb) == KOF_DIAG_MATCH_YES);
		CK(kof_diag_match_known(sd, &dj, b, &nb) == KOF_DIAG_MATCH_NO);
		{
			uint32_t i;

			printf("  stager nodes:");
			for (i = 0; i < kgenome_diag_scan_count(ss); i++)
				printf(" %04x", kgenome_diag_scan_at(ss, i)->cap);
			printf("\n  decoy nodes:");
			for (i = 0; i < kgenome_diag_scan_count(sd); i++)
				printf(" %04x", kgenome_diag_scan_at(sd, i)->cap);
			printf("\n");
		}
	}
	kgenome_diag_scan_free(ss);
	kgenome_diag_scan_free(sd);
	free(rj);
	free(rm);
	free(rn);
	{
		char cmd[400];

		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	printf("diag_stager_join: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
