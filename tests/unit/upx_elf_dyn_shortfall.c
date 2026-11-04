/*
 * upx_elf_dyn_shortfall.c - PINS the measured UPX-ELF-DYN-SHORTFALL shortfall (STATUS.md,
 * "Symbol-route audit, groups 23-28", 2026-11-04 and the 2026-11-04 architecture-measurement
 * audit before it), as a regression-tracking test ONLY. This does not fix, and does not
 * investigate, bases/unp/upx_elf_00.c `kof_unpack`: the owner ruled that OUT OF SCOPE for now
 * ("investigate as its own task with dedicated test cases later"). It pins what the real
 * unpack+analysis pipeline, run exactly as a host would, produces TODAY for the frozen fixture
 * pair, so a later fix - or a silent regression - changes a number here instead of going
 * unnoticed: same spirit as tests/lib/genome/t_seh_handler_gap_fnr3 (merge 140) and
 * t_walk_mips_indirect_jalr before CN-5 fixed it (merge 132).
 *
 * No existing test exercises bases/unp/upx_elf_00.c (grep of tests/, 2026-11-05, for "upx_elf"
 * finds only this file), so there is no established UPX-ELF harness to follow; this instead
 * follows the general "scan a real fixture through the real engine and inspect what it opens"
 * pattern of tests/unit/cov_sevenzip_real.c (kscan_bytes against the release database, an
 * on_object callback collecting each produced child by name/bytes/kof_result), the only
 * difference being the input is two REAL files from disk (the compiled+packed fixtures) rather
 * than archives this file assembles, since a hostile/synthetic UPX stream is not what the
 * defect is about - the defect is what the shipped unpacker does to a REAL `upx` output.
 *
 * The CODE-byte and function-unit measurement reuses the engine's own function-table API
 * (kgenome_elf_image_parse + kgenome_diag_funcs_with_walk, the same calls
 * tests/lib/genome/fntab_cov.c differentials against) on the produced child's bytes - not a
 * second, test-local analysis of what "recovered" means (CLAUDE.md "use the API, do not write
 * the logic a second time").
 *
 * FIXTURES (read-only, shared scratch, not part of this tree): g21_packer's calc_elf_x64_gcc_O2
 * built twice from one source (dynamic and static glibc) and packed with the same `upx`. If the
 * fixture directory is absent (a tree copied without /mnt/games/normtest/pe_elf_fixtures/, or a
 * different machine), the test says so and passes with nothing measured - it is not this
 * package's job to regenerate them.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../../libkofeng/kofeng.h"
#include <kgenome.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/fntab.h>
#include <phenotype/diag_scan.h>

#define DB_RELEASE "build/release/databases"
#define FIX_DIR "/mnt/games/normtest/pe_elf_fixtures/samples/g21_packer"

static int fails;
#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint8_t *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long sz;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	b = malloc((size_t)sz ? (size_t)sz : 1u);
	if (!b) {
		fclose(f);
		return NULL;
	}
	if (sz && fread(b, 1, (size_t)sz, f) != (size_t)sz) {
		free(b);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*n = (size_t)sz;
	return b;
}

/* ---- the scan: every child the module produces, kept whole (a packed ELF unpacks to one child
 * here, but the test does not assume that - it counts and reports what actually comes back) ---- */

#define MAXKIDS 4
#define MAXKID_BYTES (1u << 20)

struct kid { uint8_t *data; uint64_t len; uint32_t broken; };
struct scan {
	struct kid kid[MAXKIDS];
	unsigned n;
	uint32_t root_broken;
};

static int on_obj(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *user)
{
	struct scan *s = user;

	(void)name;
	if (s->n == 0) {
		s->root_broken = r->broken;
	} else if (s->n <= MAXKIDS) {
		struct kid *k = &s->kid[s->n - 1u];
		uint64_t keep = n < MAXKID_BYTES ? n : MAXKID_BYTES;

		k->data = malloc(keep ? keep : 1u);
		if (k->data)
			memcpy(k->data, b, keep);
		k->len = n;
		k->broken = r->broken;
	}
	s->n++;
	return 0;
}

static void scan_free(struct scan *s)
{
	unsigned i;

	for (i = 0; i + 1u < s->n && i < MAXKIDS; i++)
		free(s->kid[i].data);
}

/* The CODE-byte and function-unit measurement of one decoded child, through the function-table
 * API every ELF test in tests/lib/genome asks (not a second analysis of what "recovered" means). */
struct measure { int parsed; uint32_t n_funcs; uint64_t code_bytes; };

static void measure_child(const uint8_t *b, uint64_t n, struct measure *m)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;

	memset(m, 0, sizeof *m);
	memset(&ei, 0, sizeof ei);
	memset(&o, 0, sizeof o);
	if (n > (uint64_t)0xffffffffu || !kgenome_elf_image_parse(kof_buf_make(b, (uint32_t)n), &ei, &o))
		return;
	o.file_header = &ei;
	m->parsed = 1;
	m->code_bytes = kgenome_diag_code_bytes(&o, n);
	{
		struct kgenome_func_set fs;

		kgenome_diag_funcs_with_walk(&o, b, (uint32_t)n, NULL, &fs);
		m->n_funcs = fs.n;
		kgenome_funcs_free(&fs);
	}
}

/*
 * THE MODULE'S OWN NOTE. bases/unp/upx_elf_00.c reports the shortfall itself, exactly as
 * STATUS.md says - `kof_debug("UPX.ELF.shortfall", want > got ? want - got : 0)` - but a note
 * is CLAUDE.md's "diagnostics, not results" channel (kofoption.h: "costs nothing to ignore...
 * leave it unset, which is the default"): a host that does not call kscan_on_debug never sees
 * it, and kof_result.broken (read below) stays KOF_BROKEN_NONE regardless. So "not silent" in
 * the existing STATUS.md entry is true of the debug-note channel and NOT of kof_result - a
 * distinction worth pinning precisely, since a host driven only by kof_result (most of them;
 * kofscanner needs -v to surface notes) sees this shortfall as a CLEAN, COMPLETE object today. */
struct dbg_catch { int seen_shortfall; uint64_t shortfall; };
static uint32_t g_fact_shortfall;   /* kverdict_fact_id("shortfall"), resolved once in main() */

static void on_dbg_catch(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct dbg_catch *c = user;

	(void)what;
	if (fact == g_fact_shortfall) {
		c->seen_shortfall = 1;
		c->shortfall = value;
	}
}

static unsigned do_scan(kof_scanner *sc, const uint8_t *file, size_t n, const char *name, struct scan *out, struct dbg_catch *dbg)
{
	struct kof_scan_option op;

	memset(out, 0, sizeof *out);
	memset(dbg, 0, sizeof *dbg);
	memset(&op, 0, sizeof op);
	op.heur_level = 1;
	op.max_resident_bytes = 256ull << 20;
	op.max_produced_bytes = 64ull << 20;
	op.max_object_bytes = 64ull << 20;
	kscan_on_debug(sc, on_dbg_catch, dbg);
	(void)kscan_bytes(sc, file, n, name, &op, on_obj, out);
	kscan_on_debug(sc, NULL, NULL);
	return out->n ? out->n - 1u : 0u;
}

/* One fixture: load it, scan it, measure the produced child(ren), print what was measured
 * (the owner reads the report; this printf is the evidence, not a side effect). */
struct onefix { uint64_t child_len; uint32_t funcs; uint32_t root_broken, child_broken; int saw_shortfall; uint64_t shortfall; };

static void t_one(kof_scanner *sc, const char *fname, const char *label, struct onefix *out)
{
	char path[512];
	uint8_t *file;
	size_t n;
	struct scan s;
	struct dbg_catch dbg;
	unsigned made;

	memset(out, 0, sizeof *out);
	snprintf(path, sizeof path, "%s/%s", FIX_DIR, fname);
	file = slurp(path, &n);
	if (!file) {
		printf("  (fixture missing: %s - skipped)\n", path);
		return;
	}
	made = do_scan(sc, file, n, fname, &s, &dbg);
	CK(made >= 1, "%s: the module opens at least one child of the packed file (%u)", label, made);
	if (made >= 1) {
		struct measure m;

		measure_child(s.kid[0].data, s.kid[0].len, &m);
		printf("  %s: packed %zu B -> child %llu B (root broken=%u, child broken=%u, debug"
		       " shortfall=%s%llu), parsed=%d code_bytes=%llu func_units=%u\n",
		       label, n, (unsigned long long)s.kid[0].len, s.root_broken, s.kid[0].broken,
		       dbg.seen_shortfall ? "" : "NONE REPORTED/", (unsigned long long)dbg.shortfall,
		       m.parsed, (unsigned long long)m.code_bytes, m.n_funcs);
		out->child_len = s.kid[0].len;
		out->funcs = m.n_funcs;
		out->root_broken = s.root_broken;
		out->child_broken = s.kid[0].broken;
		out->saw_shortfall = dbg.seen_shortfall;
		out->shortfall = dbg.shortfall;
	} else {
		out->root_broken = s.root_broken;
	}
	scan_free(&s);
	free(file);
}

int main(void)
{
	struct stat sb;
	kof_engine *e;
	kof_scanner *sc;
	struct onefix dyn, stat_;

	if (stat(DB_RELEASE, &sb) != 0) {
		printf("upx_elf_dyn_shortfall: no database at %s (make databases) - nothing tested\n", DB_RELEASE);
		return 0;
	}
	if (stat(FIX_DIR, &sb) != 0) {
		printf("upx_elf_dyn_shortfall: no fixture directory %s - nothing tested\n", FIX_DIR);
		return 0;
	}
	g_fact_shortfall = kverdict_fact_id("shortfall");
	e = keng_open(DB_RELEASE);
	CK(e != NULL, "the engine opens the release database");
	if (!e)
		return 1;
	sc = kscan_new(e);
	CK(sc != NULL, "a scanner is made");
	if (!sc) {
		keng_close(e);
		return 1;
	}

	t_one(sc, "calc_elf_x64_gcc_O2_dyn.upx", "DYNAMIC", &dyn);
	t_one(sc, "calc_elf_x64_gcc_O2_static.upx", "STATIC", &stat_);

	if (dyn.child_len || stat_.child_len) {
		/*
		 * THE PIN. UPX-ELF-DYN-SHORTFALL (STATUS.md, module sink bases/unp/upx_elf_00.c
		 * `kof_unpack`): the DYNAMIC build's decoded child is a small, near-empty prefix with
		 * no recognisable function - measured here at well under a quarter of the packed
		 * file's own size and 0 function-table units; the STATIC build of the SAME source,
		 * packed the same way, decodes to a child several times the packed size (the embedded
		 * libc unpacks to much more than the stub) holding hundreds of function-table units.
		 * The exact byte counts are deliberately NOT pinned (a build's exact size is a
		 * toolchain/UPX-version detail, not the defect); the RATIO and the zero-vs-nonzero
		 * function count are the shortfall itself and are what a fix - or a silent regression
		 * in either direction - would change.
		 */
		CK(dyn.child_len > 0, "DYNAMIC: a child was produced at all");
		CK(dyn.child_len < 8192, "DYNAMIC: the decoded child stays tiny (today: %llu B) - a fix that recovers"
		   " the program would grow this well past one page", (unsigned long long)dyn.child_len);
		CK(dyn.funcs == 0, "DYNAMIC: the decoded child yields NO function-table unit today (got %u) - this is"
		   " the '0 CODE units' half of the shortfall; a fix must move this off zero", dyn.funcs);

		CK(stat_.child_len > 50000u, "STATIC: the decoded child is the bulk of the program (today: %llu B)",
		   (unsigned long long)stat_.child_len);
		CK(stat_.funcs > 100u, "STATIC: the decoded child yields hundreds of function-table units (today: %u)",
		   stat_.funcs);

		/*
		 * REFINED FINDING (M, this test, 2026-11-05), narrower than the existing STATUS.md
		 * sentence "Engine reports the shortfall itself (not silent)": that is true of the
		 * module's OWN debug note (kof_debug("UPX.ELF.shortfall", ...), caught here by fact id)
		 * and NOT of kof_result.broken, which this measurement finds at KOF_BROKEN_NONE (0) on
		 * BOTH the root and the produced child, for BOTH fixtures, dynamic (massive shortfall)
		 * and static (minor one) alike. A host that does not register kscan_on_debug - which is
		 * most of them; kofscanner needs -v - sees the dynamic object as a CLEAN, COMPLETE scan
		 * today. This is not fixed here (out of scope, same as the shortfall itself); it is
		 * pinned so a future change to either the note or kof_result.broken shows up as a
		 * number changing here, in either direction.
		 */
		CK(dyn.saw_shortfall, "DYNAMIC: the module's own debug note (UPX.ELF.shortfall) fires");
		CK(dyn.saw_shortfall && dyn.shortfall > 10000u, "DYNAMIC: the note's own shortfall value is"
		   " substantial today (%llu bytes) - the module knows the gap", (unsigned long long)dyn.shortfall);
		CK(dyn.root_broken == 0 && dyn.child_broken == 0, "DYNAMIC: kof_result.broken is 0 (root %u, child %u)"
		   " on BOTH objects today, despite the shortfall - the debug note is the only channel that"
		   " carries it, not kof_result; a fix SHOULD be expected to change this too", dyn.root_broken,
		   dyn.child_broken);
	}

	kscan_free(sc);
	keng_close(e);
	printf("upx_elf_dyn_shortfall: %d failure(s)\n", fails);
	return fails != 0;
}
