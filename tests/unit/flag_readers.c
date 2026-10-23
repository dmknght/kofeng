/*
 * flag_readers - when a limit is reached, the VERDICT PATH must say "cannot say".
 *
 * THE FINDING THIS IS ABOUT. Seven places set a flag when a limit drops
 * evidence, and none has a reader on the way to a verdict:
 *
 *     kgenome_diag_scan_full()   scan->full     called only by a unit test
 *     kof_sym_truncated()    KSYM header    called by nobody
 *     kof_engine.diag_full   the loader     read by nobody
 *     kgenome_diag_apihash_set.budget     PE run         becomes scan->full, read by nobody
 *
 * so an object whose evidence was cut comes back exactly as /usr/bin/ls does:
 * no finding, broken == 0, examined > 0. CLAUDE.md rule 4 says the degradation
 * must be honest ("reaches() answers UNKNOWN when it runs out of budget"); the
 * verdict path has no UNKNOWN.
 *
 * WHAT THESE TESTS CATCH: the silent MISS (a detection that is absent because a
 * limit was hit) being reported as CLEAN. They do not ask the engine to detect
 * what a cap hides - caps_*.c record that - only to NOT CLAIM CLEAN.
 *
 * THE EXPECTED BEHAVIOUR, which is what each check below asserts:
 *
 *   per object   kof_result.broken == KOF_BROKEN_LIMIT whenever a limit
 *                reduced what the object's analysis could see and no detection
 *                was made. The field exists, is documented as "do not know",
 *                and is today set only by the container budgets.
 *   the matcher  a 0 from kof_diag_match is an answer only if the scan is
 *                whole - and kof_diag_match is the plain boolean "found", on
 *                purpose, for the callers that ask nothing else. The three-way
 *                answer is its sibling (libkofeng/detectors/linkage/kofdiag.h):
 *
 *                    #define KOF_DIAG_MATCH_NO       0
 *                    #define KOF_DIAG_MATCH_YES      1
 *                    #define KOF_DIAG_MATCH_UNKNOWN (-1)   // scan limited: cannot say
 *                    int kof_diag_match_known(const struct kgenome_diag_scan *,
 *                                             const struct kof_diag *,
 *                                             uint16_t *bind_out, uint8_t *n_bind);
 *
 *                the engine's verdict path asks it, and the checks below hold
 *                both halves: kof_diag_match says 0, kof_diag_match_known says
 *                -1 on the same scan, from the library's own status.
 *   the engine   a database that did not load every diagnose says so through
 *                the public API. Expected:
 *
 *                    int kdb_diag_full(const kof_engine *);  // 1: some diagnose
 *                                                            // was not loaded
 *
 *                (kdb_diagnoses() counts what loaded and cannot tell 256 from
 *                "256 of 300".)
 *
 * Each object that is meant to be detected has its inside case beside it as a
 * normal check, so a KNOWN-MISS cannot be a fixture that never worked.
 */

#define _GNU_SOURCE

#include <unistd.h>

#include "caps_fix.h"
#include "caps_pe_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/kofcore/kofplatform.h"

static uint8_t img[1u << 22];
static uint8_t code[1u << 20];
static unsigned char view[1u << 22];

/* "said it": detected, or the object is marked as not fully examined */
static int said(const struct e2e_obj *o, const char *word)
{
	return e2e_verdict_is(o, word) || o->broken == KOF_BROKEN_LIMIT;
}

/* ---- ELF: the node store is full -------------------------------------------- */

static uint64_t elf_fillers(unsigned k)
{
	static const uint8_t keep[] = {
		0x31, 0xff, 0xb8, 9, 0, 0, 0, 0xbe, 0, 0x10, 0, 0,
		0xba, 3, 0, 0, 0, 0x41, 0xba, 0x22, 0, 0, 0,
		0x45, 0x31, 0xc9, 0x0f, 0x05, 0x49, 0x89, 0xc4
	};
	unsigned n = cf_emit(code, 0, keep, sizeof keep), i;

	for (i = 0; i < k; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	return cf_elf64(img, sizeof img, code, n);
}

static void node_store(void)
{
	struct e2e r;
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	int m;

	/* inside (1 + 4092 + 3 = 4096 nodes): the verdict is Dropper */
	CK(e2e_scan(img, elf_fillers(4092), &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));

	/* the old limit (4096) is inside now - the node limit scales with the code
	 * (max(4096, code / 8)) - and so is the last placement before the 16-bit
	 * node index (1 + 65530 + 3 = 65534 nodes) */
	CK(e2e_scan(img, elf_fillers(4093), &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));
	CK(e2e_scan(img, elf_fillers(65530), &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));

	/* outside: the stager's last node is the 65535th, past what a node index
	 * can name (KGENOME_MAX_INDEX): detected, or marked not fully examined */
	CK(e2e_scan(img, elf_fillers(65531), &r));
	CK(said(&r.o[0], "Dropper"));
	printf("    measured: verdict '%s', broken=%u, examined=%u\n",
	       r.o[0].verdict, r.o[0].broken, r.o[0].examined);

	/* the matcher, on the same object */
	memset(view, 0, sizeof view);
	s = cf_scan(img, elf_fillers(65531), KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	CK(s && kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);   /* the status IS set */
	m = cf_match_rwx(s);
	/* kof_diag_match is the plain boolean: it says "not found" (0) on a scan that
	 * is limited, and the three-way answer is kof_diag_match_known, below. What
	 * must hold is that the two disagree only by the scan's status. */
	CK(m == 0 && kgenome_diag_scan_full(s));
	kgenome_diag_scan_free(s);

	{
		static const struct kof_diag_node nd[] = {
			{ KGENOME_NUCLEO_ALLOC_EXEC, KGENOME_NUCLEO_F_WX, KOF_DIAG_NO_PARENT,
			  KGENOME_DIAG_ROLE_NONE, 0, 0, 0, NULL },
			{ KGENOME_NUCLEO_MEM_READ, 0, 0, KGENOME_DIAG_ROLE_BUFFER, 0, 0, 0, NULL },
			{ KGENOME_NUCLEO_EXEC_REG, 0, 0, KGENOME_DIAG_ROLE_TARGET, 0, 0, 0, NULL },
		};
		static const struct kof_diag dg = {
			.id = 1, .analysis = KOF_DIAG_ANALYSIS_SYSCALL, .n_node = 3,
			.name = "rwx_exec", .node = nd
		};
		uint16_t bind[4];
		uint8_t nb = 0;

		memset(view, 0, sizeof view);
		s = cf_scan(img, elf_fillers(65531), KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
		CK(kof_diag_match_known(s, &dg, bind, &nb) == KOF_DIAG_MATCH_UNKNOWN);   /* cannot say */
		kgenome_diag_scan_free(s);
		memset(view, 0, sizeof view);
		s = cf_scan(img, elf_fillers(10), KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
		CK(kof_diag_match_known(s, &dg, bind, &nb) == KOF_DIAG_MATCH_YES);
		kgenome_diag_scan_free(s);
	}
}

/* ---- PE: the run was stopped while still going ------------------------------ */

static void pe_budget(void)
{
	uint8_t c[480];
	struct e2e r;
	unsigned cn;
	uint64_t len;

	cn = pe32_stager(c, 50000);
	len = pe32_code(img, sizeof img, c, cn);
	CK(e2e_scan(img, len, &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));

	/* 300000 instructions of waiting: past the old fixed 12-slice window, inside the
	 * one that follows the budget - detected. */
	cn = pe32_stager(c, 150000);
	len = pe32_code(img, sizeof img, c, cn);
	CK(e2e_scan(img, len, &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));
	/* 800000 is past that window too: the run is stopped while the program is still
	 * going, and the object is detected or marked not fully examined. */
	cn = pe32_stager(c, 400000);
	len = pe32_code(img, sizeof img, c, cn);
	CK(e2e_scan(img, len, &r));
	/* NOT CLAIMED CLEAN: no verdict and no broken mark is fine when the object
	 * carries a finding of its own (an object with a detection is not made
	 * "unfinished" by a diagnose that could not add to it - see
	 * sx_verdict_make); what must not happen is no finding AND no mark. */
	CK(said(&r.o[0], "Dropper") || r.o[0].n > 0);
	printf("    measured: verdict '%s', broken=%u, examined=%u, findings=%u\n",
	       r.o[0].verdict, r.o[0].broken, r.o[0].examined, r.o[0].n);
}

/* ---- the symbol block: a rule that reads it, past the cap ------------------- */

static void symbol_block(void)
{
	struct e2e r;
	uint64_t len;
	unsigned i;
	int hit_in = 0, hit_out = 0;

	len = cf_kmod(img, sizeof img, 100, 0);
	CK(e2e_scan(img, len, &r));
	for (i = 0; i < r.o[0].n; i++)
		hit_in |= strstr(r.o[0].find[i], "SymCapTest") != NULL;
	CK(hit_in);                             /* symbol 102 of 103: read */

	len = cf_kmod(img, sizeof img, 5000, 0);
	CK(e2e_scan(img, len, &r));
	for (i = 0; i < r.o[0].n; i++)
		hit_out |= strstr(r.o[0].find[i], "SymCapTest") != NULL;
	/* the block is sized by the table (5000 symbols), so the rule fires */
	CK(hit_out || r.o[0].broken == KOF_BROKEN_LIMIT);
	printf("    measured: findings %u, broken=%u\n", r.o[0].n, r.o[0].broken);
	/* THE ROUTE THAT READS RELOCATIONS IS NOT THE BLOCK: the kernel-module
	 * diagnose is not touched by the cap, which is a measurement and not a
	 * promise - it is what keeps the symbol route from being the problem. */
	CK(e2e_verdict_is(&r.o[0], "Rootkit"));
}

/* ---- the database: a diagnose that did not load ----------------------------- */

static void put32d(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void db_full(const char *dbdir)
{
	static uint8_t pk[8u + 300u * 40u], good[1u << 20];
	static char name[300][12];
	static unsigned char used[65536];
	char dir[200], path[260];
	unsigned n = 0, k = 0, at;
	FILE *f;
	size_t gl;
	kof_engine *e;

	snprintf(dir, sizeof dir, "build/test/flagdb_%d", (int)getpid());
	CK(kof_mkdir(dir, 0700) == 0);
	snprintf(path, sizeof path, "%s/sigs-any.ksig", dbdir);
	f = fopen(path, "rb");
	CK(f != NULL);
	if (!f)
		return;
	gl = fread(good, 1, sizeof good, f);
	fclose(f);
	snprintf(path, sizeof path, "%s/sigs-any.ksig", dir);
	f = fopen(path, "wb");
	CK(f != NULL);
	if (!f)
		return;
	fwrite(good, 1, gl, f);
	fclose(f);

	while (n < 300u) {
		uint16_t id;

		snprintf(name[n], sizeof name[n], "fd_%04u", k++);
		id = kof_diag_id_(name[n]);
		if (used[id])
			continue;
		used[id] = 1;
		n++;
	}
	memcpy(pk, "KDGP", 4);
	pk[4] = 1;
	pk[6] = (uint8_t)n; pk[7] = (uint8_t)(n >> 8);
	at = 8u + n * 8u;
	for (k = 0; k < n; k++) {
		size_t nl = strlen(name[k]), a = at;

		pk[a++] = 1; pk[a++] = 0;
		pk[a++] = KOF_DIAG_ANALYSIS_SYSCALL;
		pk[a++] = (uint8_t)nl;
		memcpy(pk + a, name[k], nl); a += nl;
		pk[a++] = (uint8_t)KGENOME_NUCLEO_NET_OPEN; pk[a++] = (uint8_t)(KGENOME_NUCLEO_NET_OPEN >> 8);
		pk[a++] = 0; pk[a++] = 0; pk[a++] = KOF_DIAG_NO_PARENT;
		pk[a++] = 0; pk[a++] = 0; pk[a++] = 0;
		put32d(pk + 8u + k * 8u, at);
		put32d(pk + 12u + k * 8u, (uint32_t)(a - at));
		at = (unsigned)a;
	}
	snprintf(path, sizeof path, "%s/diag-x.kdig", dir);
	f = fopen(path, "wb");
	CK(f != NULL);
	if (!f)
		return;
	fwrite(pk, 1, at, f);
	fclose(f);

	e = keng_open(dir);
	CK(e != NULL);
	if (e) {
		unsigned have = kdb_diagnoses(e);

		/* all 300 load now (the table is sized by the packs); were any not
		 * loaded, kdb_diag_full says so */
		CK(have == 300u || kdb_diag_full(e));
		printf("    measured: kdb_diagnoses() = %u of 300\n", have);
		keng_close(e);
	}
	{
		char cmd[300];

		snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
		(void)system(cmd);
	}
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";

	if (!e2e_open(db)) {
		printf("flag readers: cannot open %s\n", db);
		return 2;
	}
	node_store();
	pe_budget();
	symbol_block();
	db_full(db);
	printf("flag readers: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
