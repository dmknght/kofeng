/*
 * diag_report - what each diagnose made of an object, for a tool.
 *
 * Three things are pinned. The report is OFF unless asked for - a scan that did
 * not ask pays nothing and sees nothing. Asked for, it says MATCH for the
 * diagnose the object carries and a state short of MATCH for the one it does
 * not, so the answer is not "everything matched" or "nothing did". And asking
 * changes no verdict: the findings are the same with and without it, because
 * the report is built after they are final.
 *
 * Same fixtures and database as diag_db.c, for the reason that one gives: the
 * stager is the shape the msfvenom generator emits, and the second payload has
 * every ingredient but the one that makes it a match.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

static int fails;

#define CHECK(c, ...) do { \
	if (!(c)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put16(uint8_t *b, unsigned at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}

/* The msfvenom x86-64 ELF template: one PT_LOAD from file offset zero, entry
 * at +0x78. Same shape as diag_nodes.c, for the same reason - it is what the
 * generator emits. */
static uint64_t wrap(uint8_t *b, uint64_t cap, const uint8_t *code, uint64_t n)
{
	memset(b, 0, (size_t)cap);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);                /* ET_EXEC    */
	put16(b, 18, 0x3e);             /* EM_X86_64  */
	put32(b, 20, 1);
	put64(b, 24, 0x400078u);        /* e_entry    */
	put64(b, 32, 64);               /* e_phoff    */
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 1);
	put32(b, 64, 1);                /* PT_LOAD    */
	put32(b, 68, 7);                /* RWX        */
	put64(b, 72, 0);
	put64(b, 80, 0x400000u);
	put64(b, 96, 0x78u + n);
	put64(b, 104, 0x78u + n);
	memcpy(b + 0x78, code, (size_t)n);
	return 0x78u + n;
}


struct got {
	int      n_obj;
	uint32_t n_find;
	uint32_t n_diag;
	int      state;                 /* of rwx_exec, 0 when absent */
	int      n_bound, n_node;
	uint64_t at0;
	int      unread_seen;           /* a diagnose no verdict reads was reported */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct got *g = user;
	uint32_t i;

	(void)name;
	(void)bytes;
	(void)len;
	if (g->n_obj++)
		return 0;               /* the top-level object only */
	g->n_find = res->n;
	g->n_diag = res->n_diag;
	for (i = 0; i < res->n_diag; i++) {
		const struct kof_diag_report *r = &res->diag[i];

		if (r->name && !strcmp(r->name, "rwx_exec")) {
			g->state = r->state;
			g->n_bound = r->n_bound;
			g->n_node = r->n_node;
			g->at0 = r->at[0];
		}
		CHECK(r->state >= KOF_DIAG_ST_SHAPE && r->state <= KOF_DIAG_ST_MATCH,
		      "report %u has state %d", i, r->state);
		CHECK(r->state == KOF_DIAG_ST_MATCH ? r->n_bound == r->n_node
						    : r->n_bound == 0,
		      "report %u: %d of %d nodes bound in state %d", i,
		      r->n_bound, r->n_node, r->state);
	}
	return 0;
}

static struct got run(kof_scanner *sc, const uint8_t *b, uint64_t n, int report)
{
	struct kof_scan_option opt;
	struct got g;

	memset(&opt, 0, sizeof opt);
	memset(&g, 0, sizeof g);
	opt.report_diag = report;
	kscan_bytes(sc, b, n, "x", &opt, on_object, &g);
	return g;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine *eng;
	kof_scanner *sc;
	static uint8_t b[0x200];
	uint64_t n;
	struct got off, on, other;

	static const uint8_t stager[] = {
		0x31, 0xff, 0x6a, 0x09, 0x58, 0x99, 0xb6, 0x10, 0x48, 0x89,
		0xd6, 0x4d, 0x31, 0xc9, 0x6a, 0x22, 0x41, 0x5a, 0x6a, 0x07,
		0x5a, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x51, 0x6a, 0x0a,
		0x41, 0x59, 0x50, 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f,
		0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x3b,
		0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0x27, 0x0f, 0x7f, 0x00,
		0x00, 0x01, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a,
		0x2a, 0x58, 0x0f, 0x05, 0x59, 0x48, 0x85, 0xc0, 0x79, 0x25,
		0x49, 0xff, 0xc9, 0x74, 0x18, 0x57, 0x6a, 0x23, 0x58, 0x6a,
		0x00, 0x6a, 0x05, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0x0f,
		0x05, 0x59, 0x59, 0x5f, 0x48, 0x85, 0xc0, 0x79, 0xc7, 0x6a,
		0x3c, 0x58, 0x6a, 0x01, 0x5f, 0x0f, 0x05, 0x5e, 0x6a, 0x7e,
		0x5a, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0xed, 0xff, 0xe6
	};

	/*
	 * AND THE OTHER ANSWER. Syscalls, a loop, an exit - everything the
	 * walk looks at EXCEPT an allocation that is writable and executable
	 * at once. An engine that reports rwx_exec here is one whose matcher
	 * is counting capabilities instead of following the tree, which is
	 * the version this whole design replaced.
	 */
	static const uint8_t plain[] = {
		0x6a, 0x01, 0x5f,             /* push 1 ; pop rdi        */
		0x48, 0x8d, 0x35, 0x10, 0x00,
		0x00, 0x00,                   /* lea rsi,[rip+0x10]      */
		0x6a, 0x05, 0x5a,             /* push 5 ; pop rdx        */
		0x6a, 0x01, 0x58,             /* push 1 ; pop rax  write */
		0x0f, 0x05,                   /* syscall                 */
		0x6a, 0x3c, 0x58,             /* push 0x3c ; pop rax     */
		0x31, 0xff,                   /* xor edi,edi             */
		0x0f, 0x05,                   /* syscall  - exit         */
		'h', 'e', 'l', 'l', 'o'
	};

	eng = keng_open(db);
	if (!eng) {
		printf("diagnose report: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		return 2;
	}

	n = wrap(b, sizeof b, stager, sizeof stager);
	off = run(sc, b, n, 0);
	on = run(sc, b, n, 1);
	CHECK(off.n_obj && off.n_diag == 0, "a scan that did not ask got %u reports",
	      off.n_diag);
	CHECK(on.n_diag == kdb_diagnoses(eng), "asked for %u diagnoses, got %u",
	      kdb_diagnoses(eng), on.n_diag);
	CHECK(on.state == KOF_DIAG_ST_MATCH, "stager: rwx_exec is state %d, want MATCH",
	      on.state);
	CHECK(on.n_node >= 2 && on.n_bound == on.n_node, "stager: %d of %d nodes",
	      on.n_bound, on.n_node);
	CHECK(on.at0 != 0, "stager: the head has no offset");
	CHECK(off.n_find == on.n_find, "asking changed the verdicts: %u findings "
	      "without, %u with", off.n_find, on.n_find);

	n = wrap(b, sizeof b, plain, sizeof plain);
	other = run(sc, b, n, 1);
	CHECK(other.state != 0 && other.state != KOF_DIAG_ST_MATCH,
	      "plain: rwx_exec is state %d, want one short of MATCH", other.state);

	/* and the next object is not marked by the last - the flag is per object */
	n = wrap(b, sizeof b, stager, sizeof stager);
	off = run(sc, b, n, 0);
	CHECK(off.n_diag == 0, "the report leaked into the next scan");

	kscan_free(sc);
	keng_close(eng);
	if (fails) {
		printf("diagnose report: %d failure(s)\n", fails);
		return 1;
	}
	printf("diagnose report: off unless asked, MATCH with nodes and offsets, "
	       "short of MATCH where it does not, no verdict changed - ok\n");
	return 0;
}
