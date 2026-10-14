/*
 * api_engine_detect.c - the detectors' own API: the heuristic model
 * (kofheur.h), the hex program walker and the match memo (kofmatch.h), the
 * multi-pattern tables (kofmultimatch.h), the mutation block names
 * (kofmutation.h) and the diagnose graph block (kofdiag.h).
 *
 * The multi-pattern tables are built the only honest way: a pack with known
 * literals is made in memory (kof_pack_build), written under build/test, loaded,
 * and the engine's own table (`e->multi`) is asked directly. What is asserted is
 * that a sweep finds exactly the patterns the buffer holds, that answer() reads
 * the sweep's bitmap and refuses an id that is not in it, and that fold() writes
 * one memo cell per pattern - found or absent - so a later question is never
 * asked of the data twice.
 *
 * The graph block: kof_diag_graph_build serialises the input links of a node at a
 * stride of four bytes from byte 22 of a 32 byte record, which holds two
 * (KOF_GR_IN_FIT); a node of the scan keeps four and the rest are reported as a cut.
 */

#include "hostile_engine.h"

#include <stddef.h>
#include <sys/stat.h>

#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include "../../libkofeng/detectors/heur/kofheur.h"
#include "../../libkofeng/detectors/pattern/kofmatch.h"
#include "../../libkofeng/detectors/pattern/kofmultimatch.h"
#include "../../libkofeng/detectors/pattern/kofpix.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include <kofmod/kofsig.h>
#include <kofmod/kofdiagtree.h>
#include <phenotype/diag_scan_state.h>
#include <kofmod/pe.h>
#include <kofmod/elf.h>
#include <kofmod/zip.h>

static char tmp[300];

/* ---- the heuristic model ------------------------------------------------------------ */

static void t_heur(void)
{
	const struct kof_heur_model *m = kof_heur_default();
	struct kof_heur_facts f;
	int32_t s = 12345;
	const char *g = "unset";
	uint32_t i;

	CK(m != NULL && m == kof_heur_default(), "the default model is one static table");
	CK(m->n_anom > 0 && m->n_flag > 0 && m->bar_centinats > 0, "it has terms and a bar");
	CK((m->formats & (1u << KOF_FMT_ELF)) && (m->formats & (1u << KOF_FMT_PE)), "it covers ELF and PE");
	CK(!(m->formats & (1u << KOF_FMT_ZIP)), "and nothing else");
	for (i = 0; i < m->n_anom; i++)
		CK(m->anom[i].mask != 0 && m->anom[i].guess && m->anom[i].guess[0] &&
		   (m->formats & (1u << m->anom[i].format)), "anomaly term %u is for a covered format and names a guess", i);
	for (i = 0; i < m->n_flag; i++)
		CK(m->flag[i].fact < KOF_HEUR_F_COUNT && m->flag[i].guess, "flag term %u is a known fact", i);

	memset(&f, 0, sizeof f);
	f.format = KOF_FMT_PE;
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 0, "no anomalies, no flags: the score is 0");
	f.anomalies = KGENOME_PE_ANOM_SEC_WRITE_EXEC;
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 864 && strcmp(g, "WriteExec") == 0,
	   "one anomaly scores its weight and names its guess (%d %s)", (int)s, g);
	f.anomalies |= KGENOME_PE_ANOM_SEC_PAST_EOF;
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 864 + 110 && strcmp(g, "WriteExec") == 0,
	   "weights add, the guess is the heaviest term (%d %s)", (int)s, g);
	f.flags = KOF_HEUR_FL(KOF_HEUR_F_PACKED);
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 864 + 110 + 111, "a flag adds its weight (%d)", (int)s);
	f.anomalies = 0;
	f.flags = KOF_HEUR_FL(KOF_HEUR_F_UNPACK_PARTIAL);
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 324 && strcmp(g, "PackTamper") == 0, "a flag can be the guess");
	f.flags = 0;
	f.anomalies = ~(uint64_t)0;
	CK(kof_heur_score(m, &f, &s, NULL) == 1 && s > m->bar_centinats, "every anomaly bit clears the bar; guess is optional");
	f.anomalies = 0x8000000000000000ull;
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 0, "a bit no term names scores nothing");

	f.format = KOF_FMT_ELF;
	f.anomalies = KGENOME_ELF_ANOM_SECTAB_MISSING;
	CK(kof_heur_score(m, &f, &s, &g) == 1 && s == 275 && strcmp(g, "Stripped") == 0, "an ELF term");
	f.anomalies = KGENOME_PE_ANOM_SEC_WRITE_EXEC;
	CK(kof_heur_score(m, &f, &s, &g) == 1, "a term of the wrong format's mask is not scored for this format");

	f.format = KOF_FMT_ZIP;
	f.anomalies = ~(uint64_t)0;
	CK(kof_heur_score(m, &f, &s, &g) == 0, "a format the model does not cover has no score");
	f.format = 32;
	CK(kof_heur_score(m, &f, &s, &g) == 0, "format 32: the shift would leave the mask, refused first");
	f.format = 255;
	CK(kof_heur_score(m, &f, &s, &g) == 0, "format 255");
	f.format = KOF_FMT_PE;
	CK(kof_heur_score(NULL, &f, &s, &g) == 0 && kof_heur_score(m, NULL, &s, &g) == 0 &&
	   kof_heur_score(m, &f, NULL, &g) == 0, "NULL model, facts, out");

	/* A model of the caller's own: weights that overflow int32 are clamped. */
	{
		static const struct kof_heur_anom_term big[] = {
			{ KOF_FMT_PE, 1, 2000000000, "A" }, { KOF_FMT_PE, 2, 2000000000, "B" },
			{ KOF_FMT_PE, 4, -2000000000, "C" }, { KOF_FMT_PE, 8, -2000000000, "D" },
			{ KOF_FMT_PE, 16, -2000000000, "E" }
		};
		struct kof_heur_model mm;

		memset(&mm, 0, sizeof mm);
		mm.anom = big;
		mm.n_anom = 5;
		mm.formats = 1u << KOF_FMT_PE;
		f.format = KOF_FMT_PE;
		f.flags = 0;
		f.anomalies = 3;
		CK(kof_heur_score(&mm, &f, &s, &g) == 1 && s == 0x7fffffff, "a sum past int32 max clamps, not wraps (%d)", (int)s);
		f.anomalies = 4 | 8 | 16;
		CK(kof_heur_score(&mm, &f, &s, &g) == 1 && s == -0x7fffffff, "and so does the other end (%d)", (int)s);
	}
}

static void t_heur_anomalies(void)
{
	struct kof_obj_ctx ctx;
	struct kof_pe_info *pe = calloc(1, sizeof *pe);
	struct kof_elf_info *elf = calloc(1, sizeof *elf);
	struct kof_zip_info *zip = calloc(1, sizeof *zip);

	if (!pe || !elf || !zip) {
		CK(0, "memory");
		free(pe); free(elf); free(zip);
		return;
	}
	memset(&ctx, 0, sizeof ctx);
	CK(kof_heur_anomalies(NULL) == 0, "NULL ctx");
	CK(kof_heur_anomalies(&ctx) == 0, "no view");
	pe->anomalies = 0x1111;
	elf->anomalies = 0x2222;
	zip->anomalies = 0x3333;
	ctx.format = KOF_FMT_PE;
	ctx.file_header = pe;
	CK(kof_heur_anomalies(&ctx) == 0x1111, "PE view");
	ctx.format = KOF_FMT_ELF;
	ctx.file_header = elf;
	CK(kof_heur_anomalies(&ctx) == 0x2222, "ELF view");
	ctx.format = KOF_FMT_ZIP;
	ctx.file_header = zip;
	CK(kof_heur_anomalies(&ctx) == 0x3333, "zip view");
	ctx.format = KOF_FMT_DOCZIP;
	CK(kof_heur_anomalies(&ctx) == 0x3333, "a zip-based document reads the zip view");
	ctx.format = KOF_FMT_UNKNOWN;
	CK(kof_heur_anomalies(&ctx) == 0, "a format with no anomaly word");
	ctx.format = 250;
	CK(kof_heur_anomalies(&ctx) == 0, "an unknown format");
	free(pe);
	free(elf);
	free(zip);
}

/* ---- hex programs, the match memo --------------------------------------------------------- */

static void t_hex(void)
{
	static const uint8_t hay[] = { 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x41, 0x7a, 0x43, 0x00 };
	uint8_t prog[1024];
	struct kof_hex_stat st;
	kof_buf d = kof_buf_make(hay, sizeof hay);
	uint32_t n;

	n = kof_hex_compile("41 ?? 43", prog, sizeof prog, &st);
	CK(n > 0 && st.n_steps >= 1, "compile");
	CK(kof_hex_walk(d, 1, prog) == 1, "a wildcard step matches at the start offset");
	CK(kof_hex_walk(d, 6, prog) == 1, "and at the second place");
	CK(kof_hex_walk(d, 2, prog) == 0, "and not where the bytes differ");
	CK(kof_hex_walk(d, sizeof hay, prog) == 0 && kof_hex_walk(d, UINT64_MAX, prog) == 0, "a start past the end");
	CK(kof_hex_walk(d, 8, prog) == 0, "a walk that runs off the end fails, it does not read on");
	CK(kof_hex_walk_flags(d, 1, prog, 0) == kof_hex_walk(d, 1, prog), "no flags is the plain walk");
	CK(kof_hex_walk_flags(d, 1, prog, KOF_STR_ICASE) == 1, "icase still matches what matched");
	n = kof_hex_compile("61 62 63", prog, sizeof prog, &st);
	CK(n > 0, "compile lower case bytes");
	CK(kof_hex_walk_flags(d, 1, prog, 0) == 0, "case sensitive: abc is not ABC");
	CK(kof_hex_walk_flags(d, 1, prog, KOF_STR_ICASE) == 1, "icase: abc is ABC");
	CK(kof_hex_walk(kof_buf_make(NULL, 0), 0, prog) == 0, "an empty object");
	CK(kof_hex_compile("zz", prog, sizeof prog, &st) == 0 && kof_hex_error() != NULL, "a bad program is refused with a reason");
}

static void t_memo(void)
{
	struct kof_match_ctx m;
	static const uint8_t data[64] = { 1 };
	uint32_t s, gen;

	memset(&m, 0, sizeof m);
	kof_match_begin(&m, kof_buf_make(data, sizeof data));
	CK(kof_match_state_init(&m, 4, 16) == 1, "state init with a memo");
	for (s = 0; s < 16; s++)
		CK(kof_match_memo_get(&m, s) == -1, "a fresh memo knows nothing (slot %u)", s);
	kof_match_memo_put(&m, 3, 1);
	kof_match_memo_put(&m, 5, 0);
	CK(kof_match_memo_get(&m, 3) == 1 && kof_match_memo_get(&m, 5) == 0 && kof_match_memo_get(&m, 4) == -1,
	   "put then get: present is 1, absent is 0, unknown is -1");
	kof_match_memo_put(&m, 3, 0);
	CK(kof_match_memo_get(&m, 3) == 0, "a later put replaces");
	CK(kof_match_memo_get(&m, 16) == -1 && kof_match_memo_get(&m, 0xffffffffu) == -1,
	   "a slot past the table is unknown, not read");
	kof_match_memo_put(&m, 16, 1);
	kof_match_memo_put(&m, 0xffffffffu, 1);
	CK(kof_match_memo_get(&m, 15) == -1, "a put past the table writes nothing");
	kof_match_begin(&m, kof_buf_make(data, sizeof data));
	CK(kof_match_memo_get(&m, 3) == -1 && kof_match_memo_get(&m, 5) == -1, "begin on a new object forgets the answers");

	/* trim gives back the presence table and leaves the answers: a scanner trimmed between objects keeps its memo */
	kof_match_memo_put(&m, 9, 1);
	kof_match_state_trim(&m);
	kof_match_state_trim(&m);
	CK(m.gram == NULL && m.gram_use == NULL && m.memo != NULL && kof_match_memo_get(&m, 9) == 1,
	   "trim drops the presence table and keeps the memo, and twice is the same");
	{
		struct kof_match_ctx z;

		memset(&z, 0, sizeof z);
		kof_match_state_trim(&z);
		CK(z.gram == NULL && z.memo == NULL, "trim of a state that was never made is nothing");
	}

	/* The generation is 14 bits: a cell written under one generation is never read under
	 * another, including across the wrap, where the whole table has to be cleared. */
	for (gen = 0; gen < 0x4400u; gen++) {
		int stale;

		kof_match_memo_put(&m, 7, 1);
		kof_match_begin(&m, kof_buf_make(data, sizeof data));
		stale = kof_match_memo_get(&m, 7);
		if (stale != -1) {
			CK(0, "an answer leaked into generation %u (read %d)", gen, stale);
			break;
		}
	}
	CK(gen == 0x4400u, "no answer survived 0x4400 begins");
	kof_match_state_free(&m);
	kof_match_state_free(&m);
	CK(m.memo == NULL && m.memo_len == 0, "free twice, and the memo is gone");

	/* No memo at all: the questions are answered by search, the table is simply absent. */
	memset(&m, 0, sizeof m);
	kof_match_begin(&m, kof_buf_make(data, sizeof data));
	CK(kof_match_state_init(&m, 4, 0) == 1 && kof_match_memo_get(&m, 0) == -1, "memo_len 0 is a valid, empty table");
	kof_match_memo_put(&m, 0, 1);
	CK(kof_match_memo_get(&m, 0) == -1, "and a put into it is dropped");
	kof_match_state_free(&m);
}

/* ---- the multi-pattern tables ---------------------------------------------------------------- */

#define NPAT 12u
#define SCANBIT 2u

static char pat_text[NPAT][12];

static uint8_t *build_pack_lits(const char *const *txt, uint32_t n, size_t *len)
{
	static uint8_t code[] = { 0x90, 0xc3 };
	static struct kof_pw_str strs[NPAT * 2u];
	static struct kof_pw_name names[1];
	struct kof_pw_mod m;
	uint32_t i;
	static const uint32_t rng[1] = { 1u << SCANBIT };

	if (n > sizeof strs / sizeof strs[0])
		return NULL;
	for (i = 0; i < n; i++) {
		strs[i].bytes = (const uint8_t *)txt[i];
		strs[i].len = (uint16_t)strlen(txt[i]);
		strs[i].kind = KOF_STR_LITERAL;
		strs[i].flags = 0;
	}
	names[0].id = 1;
	names[0].text = "Test.Multi";
	memset(&m, 0, sizeof m);
	m.code = code;
	m.code_len = sizeof code;
	m.n_target = 1;
	m.target[0] = KOF_FMT_UNKNOWN;
	m.scan_mask = 1u << SCANBIT;
	m.size_min = 1;
	m.str = strs;
	m.n_str = n;
	m.rng = rng;
	m.n_rng = 1;
	m.name = names;
	m.n_names = 1;
	return kof_pack_build(KOF_PACK_DETECT, &m, 1, len);
}

static uint8_t *build_pack(size_t *len)
{
	const char *txt[NPAT];
	uint32_t i;

	for (i = 0; i < NPAT; i++) {
		snprintf(pat_text[i], sizeof pat_text[i], "kof%02uZ-pat", i);
		txt[i] = pat_text[i];
	}
	return build_pack_lits(txt, NPAT, len);
}

static struct kof_engine *load_image(uint8_t *img, size_t len, const char *sub)
{
	char dir[400], path[500];
	FILE *f;
	struct kof_engine *e;

	if (!img)
		return NULL;
	snprintf(dir, sizeof dir, "%s/%s", tmp, sub);
	mkdir(dir, 0700);
	snprintf(path, sizeof path, "%s/%s.ksig", dir, sub);
	f = fopen(path, "wb");
	if (!f) {
		free(img);
		return NULL;
	}
	fwrite(img, 1, len, f);
	fclose(f);
	free(img);
	e = kof_db_load(dir);
	return e;
}

static struct kof_engine *load_pack(void)
{
	size_t len = 0;
	uint8_t *img = build_pack(&len);

	return load_image(img, len, "mm");
}

/* What a sweep of one region found, for the marker with this pack-local id, as region bits. */
static uint32_t found_bits(const struct kofpix_ctx *c, uint32_t uid)
{
	return kofpix_found_get(c, uid);
}

static void t_pattern(void)
{
	struct kof_engine *e = load_pack();
	struct kofpix_ctx ctx;
	struct kof_match_ctx m;
	uint8_t buf[512];
	struct kof_range ext = { 0, sizeof buf };
	uint32_t i, uid_of[NPAT], have = 0;
	const struct kof_str_ent *d;
	uint64_t bytes = 0, markers = 0;

	if (!e) {
		CK(0, "the in-memory pack did not load");
		return;
	}
	if (!e->pix_set || !e->packs[0].pix) {
		CK(0, "no pattern table");
		kof_db_free(e);
		return;
	}
	CK(e->pix_markers == NPAT, "the table holds the %u literals (%llu)", NPAT, (unsigned long long)e->pix_markers);
	CK(kofpix_region_n(e->packs[0].pix, SCANBIT) == NPAT, "all of them under the region bit they were declared for");
	CK(e->pix_regions == (1u << SCANBIT) && kofpix_set_regions(e->pix_set) == e->pix_regions, "and only that region has a table");
	CK(kdb_pattern_status(e, &bytes, &markers) == 0 && bytes > 0 && markers == NPAT, "the status is clean and the footprint is reported");
	CK(kdb_pattern_status(NULL, &bytes, &markers) == 0 && bytes == 0 && markers == 0, "no engine: nothing, and no status");
	CK(kmatch_tables(e, &bytes, NULL) == 0 && bytes > 0, "kmatch_tables reports the same footprint");
	CK(KOF_MULTIMATCH_MIN_LIVE == 8u, "a region with fewer live markers than this is answered one at a time");

	/* which id holds which literal: the pack's own descriptors say */
	d = e->packs[0].desc;
	CK(d != NULL && e->packs[0].n_desc == NPAT, "the pack's string table is the twelve literals");
	for (i = 0; i < NPAT; i++) {
		uint32_t s;

		uid_of[i] = 0xffffffffu;
		for (s = 0; d && s < e->packs[0].n_desc; s++)
			if (d[s].len == strlen(pat_text[i]) && !memcmp(e->packs[0].pool + d[s].off, pat_text[i], d[s].len))
				uid_of[i] = d[s].uid;
		have += uid_of[i] != 0xffffffffu;
	}
	CK(have == NPAT, "every literal has an id");
	if (have != NPAT || !kofpix_ctx_init(&ctx, e->pix_set, 0)) {
		kof_db_free(e);
		return;
	}

	/* a buffer holding patterns 3 and 7 only */
	memset(buf, '.', sizeof buf);
	memcpy(buf + 100, pat_text[3], strlen(pat_text[3]));
	memcpy(buf + 400, pat_text[7], strlen(pat_text[7]));
	memset(&m, 0, sizeof m);
	kof_match_begin(&m, kof_buf_make(buf, sizeof buf));
	kofpix_ctx_begin(&ctx);
	{
		uint64_t walked = kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &ext, 1);

		CK(walked == sizeof buf, "the sweep reports the bytes it walked (%llu)", (unsigned long long)walked);
		CK(ctx.last == 0 && ctx.status == 0, "and finished");
	}
	for (i = 0; i < NPAT; i++) {
		int want = i == 3 || i == 7;

		CK(((found_bits(&ctx, uid_of[i]) >> SCANBIT) & 1u) == (uint32_t)want, "pattern %u %s", i, want ? "found" : "absent");
	}
	CK(found_bits(&ctx, 0xfffffffeu) == 0 && ctx.found.n == 2, "an id nobody has is absent; two markers were found");

	/* extents: a window that excludes the second pattern, a window clipped at the end, empty and wild ones */
	{
		struct kof_range w = { 0, 300 };

		kofpix_ctx_begin(&ctx);
		kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &w, 1);
		CK(((found_bits(&ctx, uid_of[3]) >> SCANBIT) & 1u) && !((found_bits(&ctx, uid_of[7]) >> SCANBIT) & 1u),
		   "only the pattern inside the extent");
		w.off = 0;
		w.len = UINT64_MAX;
		kofpix_ctx_begin(&ctx);
		CK(kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &w, 1) == sizeof buf, "a length of 2^64-1 is clipped to the object");
		w.off = UINT64_MAX - 3;
		w.len = 100;
		CK(kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &w, 1) == 0, "an extent starting at 2^64-4 walks nothing");
		w.off = sizeof buf;
		w.len = 1;
		CK(kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &w, 1) == 0, "an extent at the end walks nothing");
		CK(kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, NULL, 0) == 0, "no extents");
		CK(kofpix_sweep(e->pix_set, &ctx, 31, &m, &ext, 1) == 0 && kofpix_sweep(NULL, &ctx, SCANBIT, &m, &ext, 1) == 0 &&
		   kofpix_sweep(e->pix_set, &ctx, SCANBIT + 1u, &m, &ext, 1) == 0 && ctx.last == 0,
		   "a bit past the table, a NULL set, an empty region: nothing walked, nothing reported");
	}
	kofpix_ctx_free(&ctx);
	kof_db_free(e);
	{
		struct kofpix_set *none = kofpix_set_make(NULL, 0);

		CK(none != NULL && kofpix_set_regions(none) == 0, "a set of nothing is a set with no region");
		kofpix_set_free(none);
	}
	kofpix_set_free(NULL);
	CK(1, "free of NULL");
}


/*
 * A BIG REGION WHOSE MARKERS ALL SHARE A FOUR-BYTE PREFIX. The table keys every marker on the four
 * bytes the fewest others contain, `koff` bytes in, so a marker begins koff bytes EARLIER than the hit
 * on its key - which the verification has to subtract. It once did not (the rekey table: a real marker
 * was found only if its key happened to sit at offset 0), so this plants markers and asks for them.
 * Markers are "SHRD" + eight hex digits: the shared prefix is the worst key, and the digits give the
 * rarest gram some offset past 0. The pack is large enough that its table is written into it
 * (KOFPIX_EMBED_MIN) and read with pread: the same answers as in memory.
 */
#define BIG_N 400000u
#define BIG_LEN 12u

static void big_text(uint32_t i, char *out)
{
	snprintf(out, BIG_LEN + 1u, "SHRD%08x", i);
}

static uint8_t *build_big_pack(size_t *len)
{
	static uint8_t code[] = { 0x90, 0xc3 };
	static struct kof_pw_name names[1];
	static const uint32_t rng[1] = { 1u << SCANBIT };
	/* a module declares at most KOF_MAX_STR_PER_MODULE strings, so the region's
	 * literals come from many modules, as a real base's do */
	const uint32_t per = KOF_MAX_STR_PER_MODULE, nm = (BIG_N + per - 1u) / per;
	struct kof_pw_str *strs = malloc((size_t)BIG_N * sizeof *strs);
	char *txt = malloc((size_t)BIG_N * (BIG_LEN + 1u));
	struct kof_pw_mod *mods = calloc(nm, sizeof *mods);
	uint8_t *img = NULL;
	uint32_t i;

	if (!strs || !txt || !mods)
		goto out;
	for (i = 0; i < BIG_N; i++) {
		big_text(i, txt + (size_t)i * (BIG_LEN + 1u));
		strs[i].bytes = (const uint8_t *)txt + (size_t)i * (BIG_LEN + 1u);
		strs[i].len = BIG_LEN;
		strs[i].kind = KOF_STR_LITERAL;
		strs[i].flags = 0;
	}
	names[0].id = 1;
	names[0].text = "Test.Rekey";
	for (i = 0; i < nm; i++) {
		struct kof_pw_mod *m = &mods[i];

		m->code = code;
		m->code_len = sizeof code;
		m->n_target = 1;
		m->target[0] = KOF_FMT_UNKNOWN;
		m->scan_mask = 1u << SCANBIT;
		m->size_min = 1;
		m->str = strs + (size_t)i * per;
		m->n_str = i + 1u == nm ? BIG_N - i * per : per;
		m->rng = rng;
		m->n_rng = 1;
		m->name = names;
		m->n_names = 1;
	}
	img = kof_pack_build(KOF_PACK_DETECT, mods, nm, len);
out:
	free(mods);
	free(strs);
	free(txt);
	return img;
}

/*
 * What the table will key: a literal needs KOF_MULTIMATCH_KEY bytes, a shorter one is left to the lazy path by not
 * being in the table (its answer is searched for, and that is an answer, not a loss).
 */
static void t_pattern_keys(void)
{
	/* ten keyable literals (a set of fewer than KOF_MULTIMATCH_MIN_LIVE is not worth a pass) and three that are not */
	static const char *const txt[] = { "kof-key-00", "kof-key-01", "kof-key-02", "kof-key-03", "kof-key-04", "kof-key-05",
					   "kof-key-06", "kof-key-07", "abcd", "wxyz1234", "abc", "ab", "q" };
	const uint32_t n_txt = sizeof txt / sizeof txt[0];
	size_t len = 0;
	uint8_t *img = build_pack_lits(txt, n_txt, &len);       /* its own statement: `len` is an argument of the next call */
	struct kof_engine *e = load_image(img, len, "keys");

	CK(KOF_MULTIMATCH_KEY == 4u, "the key is four bytes");
	CK(KOF_MULTIMATCH_BITS == 30u, "the region bits stop below the symbol halves (30, 31)");
	CK(KOF_MULTIMATCH_HEX_MIN >= KOF_MULTIMATCH_KEY, "a hex anchor is at least a key");
	CK(e && e->packs[0].pix != NULL, "the pack loads and has a table");
	if (!e || !e->packs[0].pix) {
		if (e)
			kof_db_free(e);
		return;
	}
	CK(kofpix_region_n(e->packs[0].pix, SCANBIT) == 10u && e->pix_markers == 10u,
	   "of thirteen literals, the ten of 4+ bytes are keyed and the three shorter are not (%u in the table)",
	   kofpix_region_n(e->packs[0].pix, SCANBIT));
	CK(kof_multimatch_keyable(KOF_STR_LITERAL, 4, (const uint8_t *)"abcd") && !kof_multimatch_keyable(KOF_STR_LITERAL, 3, (const uint8_t *)"abc"),
	   "the predicate the build and the question share says the same");
	kof_db_free(e);
}

static void t_pattern_prefix(void)
{
	static const uint32_t present[] = { 0u, 1u, 123457u, 250000u, BIG_N - 1u };
	size_t len = 0;
	uint8_t *img = build_big_pack(&len);
	struct kof_engine *e = load_image(img, len, "rekey");
	struct kofpix_ctx ctx;
	struct kof_match_ctx m;
	uint8_t buf[2048];
	struct kof_range ext = { 0, sizeof buf };
	uint32_t i, k;
	uint64_t at[sizeof present / sizeof present[0]];

	if (!e || !e->pix_set) {
		CK(0, "the %u-literal pack did not load with a table", BIG_N);
		if (e)
			kof_db_free(e);
		return;
	}
	CK(e->packs[0].has_pix && !e->packs[0].pix_in_ram, "the table was written into the pack and is read from it");
	CK(kofpix_region_n(e->packs[0].pix, SCANBIT) == BIG_N, "the region holds all %u literals (%u)", BIG_N,
	   kofpix_region_n(e->packs[0].pix, SCANBIT));
	CK(e->pix_bytes < 8u * 1024u * 1024u, "and holds %llu bytes in memory for them, not a table of them", (unsigned long long)e->pix_bytes);
	if (!kofpix_ctx_init(&ctx, e->pix_set, 0)) {
		CK(0, "out of memory");
		kof_db_free(e);
		return;
	}
	/* five real markers, the last one ending exactly at the end of the region */
	memset(buf, '.', sizeof buf);
	for (k = 0; k < sizeof present / sizeof present[0]; k++) {
		char txt[BIG_LEN + 1u];

		at[k] = k + 1u == sizeof present / sizeof present[0] ? sizeof buf - BIG_LEN : (uint64_t)k * 300u;
		big_text(present[k], txt);
		memcpy(buf + at[k], txt, BIG_LEN);
	}
	memset(&m, 0, sizeof m);
	kof_match_begin(&m, kof_buf_make(buf, sizeof buf));
	kofpix_ctx_begin(&ctx);
	kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &ext, 1);
	CK(ctx.last == 0, "the sweep finished");
	/* the id of marker i is i: the packer numbers distinct strings in the order they are declared */
	for (k = 0; k < sizeof present / sizeof present[0]; k++)
		CK((kofpix_found_get(&ctx, present[k]) >> SCANBIT) & 1u, "marker %u at %llu is found", present[k],
		   (unsigned long long)at[k]);
	CK(ctx.found.n == sizeof present / sizeof present[0], "and nothing else: %u found of %u present", ctx.found.n,
	   (unsigned)(sizeof present / sizeof present[0]));
	/* a marker that starts before the region's base is not found by its key alone */
	{
		struct kof_range w = { at[2] + 2u, BIG_LEN };
		uint32_t before = (kofpix_found_get(&ctx, present[2]) >> SCANBIT) & 1u;

		kofpix_ctx_begin(&ctx);
		kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &w, 1);
		CK(before && !((kofpix_found_get(&ctx, present[2]) >> SCANBIT) & 1u),
		   "a window that starts inside a marker does not report it");
	}
	(void)i;
	kofpix_ctx_free(&ctx);
	kof_db_free(e);
}

/* ---- mutation block names ----------------------------------------------------------------------- */

static void t_mutation_name(void)
{
	static uint32_t pool[32];
	struct kof_mutation_block b[2];
	struct kof_mutation_set *set;
	uint32_t id0, id1, n = 0, i;
	const uint32_t *h;

	for (i = 0; i < 32; i++)
		pool[i] = 1000u + i * 37u;
	memset(b, 0, sizeof b);
	b[0].first_hash = 0;
	b[0].n_hash = 16;
	b[0].scan_mask = 1;
	b[1].first_hash = 16;
	b[1].n_hash = 16;
	b[1].scan_mask = 1;
	set = kof_mutation_build(b, 2, pool, 32);
	if (!set) {
		CK(0, "mutation set did not build");
		return;
	}
	id0 = kof_mutation_block_id(set, 0);
	id1 = kof_mutation_block_id(set, 1);
	CK(id0 != 0 && id1 != 0 && id0 != id1, "two blocks of different hashes have different ids");
	CK(id0 == kof_mutation_fold(pool, 16) && id1 == kof_mutation_fold(pool + 16, 16), "the id is the fold of the block's hashes");
	CK(kof_mutation_block_id(set, 2) == 0 && kof_mutation_block_id(set, 0xffffffffu) == 0,
	   "a block past the set has id 0");
	CK(kof_mutation_block_id(NULL, 0) == 0, "NULL set");
	h = kof_mutation_block_hashes(set, 1, &n);
	CK(h && n == 16 && h[0] == pool[16], "block hashes");
	n = 99;
	CK(kof_mutation_block_hashes(set, 2, &n) == NULL, "a block past the set has no hashes");
	kof_mutation_set_free(set);
	kof_mutation_set_free(NULL);
	CK(1, "free of NULL");

	/* a block too small to carry a similarity, and one pointing outside the pool, are refused */
	b[0].n_hash = 15;
	CK(kof_mutation_build(b, 2, pool, 32) == NULL, "15 hashes is under the minimum");
	b[0].n_hash = 16;
	b[1].first_hash = 20;
	CK(kof_mutation_build(b, 2, pool, 32) == NULL, "a block running past the pool");
	b[1].first_hash = 0xfffffff0u;
	CK(kof_mutation_build(b, 2, pool, 32) == NULL, "a first_hash near 2^32 does not wrap into range");
	b[1].first_hash = 16;
	CK(kof_mutation_build(NULL, 2, pool, 32) == NULL && kof_mutation_build(b, 2, NULL, 32) == NULL, "NULL blocks or pool");
}

/* ---- the diagnose graph block ---------------------------------------------------------------------- */

static void fill_hit(struct kgenome_diag_hit *h, uint64_t at, uint8_t n_in)
{
	uint8_t k;

	memset(h, 0, sizeof *h);
	h->at = at;
	h->attr = at ^ 0xabcdull;
	h->cap = 7;
	h->flags = 5;
	h->n_in = n_in;
	for (k = 0; k < n_in; k++) {
		h->in[k].from = (uint16_t)(k + 1u);
		h->in[k].role = (uint8_t)(0x30u + k);
		h->in[k].kind = k & 1u ? KGENOME_DIAG_KIND_SHARED : KGENOME_DIAG_KIND_PRODUCED;
	}
}

static void t_graph_basic(void)
{
	struct kgenome_diag_scan s;
	struct kgenome_diag_hit hit[3];
	uint8_t out[8 + 3 * 32 + 64];
	uint32_t n, role_seen = 0;
	uint8_t role, kind;

	memset(&s, 0, sizeof s);
	fill_hit(&hit[0], 0x1111, 2);
	fill_hit(&hit[1], 0x2222, 0);
	fill_hit(&hit[2], 0x3333, 1);
	s.hit = hit;
	s.n_hit = 3;
	s.cap_hit = 3;

	CK(kof_diag_graph_build(NULL, out, sizeof out) == 0 && kof_diag_graph_build(&s, NULL, sizeof out) == 0, "NULL scan, NULL out");
	s.n_hit = 0;
	CK(kof_diag_graph_build(&s, out, sizeof out) == 0, "no hits, no block");
	s.n_hit = 3;
	CK(kof_diag_graph_build(&s, out, 8 + 3 * 32 - 1) == 0, "a buffer one byte short refuses the whole block");
	n = kof_diag_graph_build(&s, out, sizeof out);
	CK(n == 8 + 3 * 32, "the block is a header and one record per hit (%u)", n);
	CK(kof_gr_count(out, n) == 3, "the count");
	{
		const uint8_t *r = kof_gr_rec(out, n, 0);

		CK(r && kof_gr_u64(r, KOF_GR_R_AT) == 0x1111 && kof_gr_u64(r, KOF_GR_R_ATTR) == (0x1111 ^ 0xabcd) &&
		   kof_gr_u16(r, KOF_GR_R_CAP) == 7 && kof_gr_u16(r, KOF_GR_R_FLAGS) == 5 && r[KOF_GR_R_NIN] == 2 &&
		   r[KOF_GR_R_BITS] == 0, "record 0 reads back");
		CK(kof_gr_in(r, 0, &role, &kind) == 1 && role == 0x30 && kind == KGENOME_DIAG_KIND_PRODUCED, "link 0");
		CK(kof_gr_in(r, 1, &role, &kind) == 2 && role == 0x31 && kind == KGENOME_DIAG_KIND_SHARED, "link 1");
		CK(kof_gr_in(r, 2, &role, &kind) == KOF_GR_FROM_NONE, "a link not in use is NONE");
		CK(kof_gr_in(r, 4, &role, &kind) == KOF_GR_FROM_NONE && kof_gr_in(r, 100, NULL, NULL) == KOF_GR_FROM_NONE,
		   "a link index past the format's four");
		CK(kof_gr_rec(out, n, 3) == NULL && kof_gr_rec(out, n, 0xffffffffu) == NULL && kof_gr_rec(NULL, n, 0) == NULL,
		   "a record past the count");
		CK(kof_gr_rec(out, 8 + 32 + 31, 1) == NULL, "a record the length does not hold");
		/* what kof_gr_rec answers past the last record goes straight into kof_gr_in: NONE, and the
		 * out parameters untouched, not a read of address 0 */
		{
			uint8_t ro = 0xAA, ki = 0xBB;

			CK(kof_gr_in(kof_gr_rec(out, n, 3), 0, &ro, &ki) == KOF_GR_FROM_NONE && ro == 0xAA && ki == 0xBB &&
			   kof_gr_in(NULL, 0, NULL, NULL) == KOF_GR_FROM_NONE, "kof_gr_in of a NULL record is NONE");
		}
		(void)role_seen;
	}
	CK(kof_gr_has(out, n, 7) == 1 && kof_gr_has(out, n, 8) == 0 && kof_gr_has(out, 4, 7) == 0, "has");
	CK(kof_gr_count(NULL, 100) == 0 && kof_gr_count(out, 7) == 0, "count of nothing / a short header");
}

/*
 * A node with three or four inputs. A node of the scan keeps four; the record is
 * 32 bytes with the links at byte 22 + 4k, so it holds two (KOF_GR_IN_FIT). The
 * serialiser used to write links 2 and 3 regardless: into the next record's `at`
 * and, for the last node, past the block the engine allocates (objctx_diag.c:
 * exactly HDR + nn * RECLEN). It now writes the first two, and the cut is said on
 * the scan (KGENOME_TRUNCATED) instead of being a heap overflow.
 */
struct graph_job {
	int n_in;
	int variant;
};

static int graph_overflow_child(void *arg)
{
	struct graph_job *j = (struct graph_job *)arg;
	struct kgenome_diag_scan s;
	struct kgenome_diag_hit hit[2];
	struct he_guard g;
	uint32_t need = 8 + 2 * 32, n;

	memset(&s, 0, sizeof s);
	fill_hit(&hit[0], 0x1111, 1);
	fill_hit(&hit[1], 0x2222, (uint8_t)j->n_in);
	s.hit = hit;
	s.n_hit = 2;
	if (!he_guard_make(&g, NULL, need))
		return 9;
	n = kof_diag_graph_build(&s, g.p, need);
	he_guard_free(&g);
	return n == need ? 0 : 1;
}

static void t_graph_links(void)
{
	struct graph_job j;
	struct he_status st;
	struct kgenome_diag_scan s;
	struct kgenome_diag_hit hit[3];
	uint8_t out[8 + 3 * 32 + 64];
	uint32_t n;
	uint8_t role = 0, kind = 0;
	const uint8_t *r0, *r1;

	CK(KOF_GR_IN_FIT == 2 && KOF_GR_R_IN + KOF_GR_IN_FIT * KOF_GR_IN_STRIDE <= KOF_GR_RECLEN &&
	   KOF_GR_R_IN + (KOF_GR_IN_FIT + 1u) * KOF_GR_IN_STRIDE > KOF_GR_RECLEN,
	   "the record holds exactly the links that end inside it");

	/* the last node with 3 and with 4 inputs: no byte past the exact-size block */
	j.n_in = 3;
	j.variant = 0;
	st = he_child(graph_overflow_child, &j, 10);
	CK(he_ok(st), "kof_diag_graph_build stays inside a block of exactly header + n records (last node, 3 inputs)");
	j.n_in = 4;
	st = he_child(graph_overflow_child, &j, 10);
	CK(he_ok(st), "the same with 4 inputs");

	/* a node with 3 inputs: two links written whole, the third reported as a cut, the next record intact */
	memset(&s, 0, sizeof s);
	fill_hit(&hit[0], 0x1111, 3);
	fill_hit(&hit[1], 0x2222, 0);
	s.hit = hit;
	s.n_hit = 2;
	memset(out, 0, sizeof out);
	n = kof_diag_graph_build(&s, out, sizeof out);
	r0 = kof_gr_rec(out, n, 0);
	r1 = kof_gr_rec(out, n, 1);
	CK(n == 8 + 2 * 32 && r0 != NULL && r1 != NULL, "block built with room to spare");
	if (r0 && r1) {
		CK(r0[KOF_GR_R_NIN] == KOF_GR_IN_FIT, "the record says how many links it holds (%u)", r0[KOF_GR_R_NIN]);
		CK(kof_gr_in(r0, 0, &role, &kind) == 1 && role == 0x30 && kind == KGENOME_DIAG_KIND_PRODUCED, "link 0 whole");
		CK(kof_gr_in(r0, 1, &role, &kind) == 2 && role == 0x31 && kind == KGENOME_DIAG_KIND_SHARED, "link 1 whole");
		CK(kof_gr_in(r0, 2, &role, &kind) == KOF_GR_FROM_NONE, "a link the record cannot hold is NONE, not the next record's bytes");
		CK(kof_gr_u64(r1, KOF_GR_R_AT) == 0x2222 && kof_gr_u64(r1, KOF_GR_R_ATTR) == (0x2222 ^ 0xabcd),
		   "the next record's `at` and `attr` are not written over by the links");
	}
	CK(kgenome_diag_scan_status(&s) == KGENOME_TRUNCATED, "the cut is reported on the scan");

	/* two inputs fit: nothing is cut, nothing is reported */
	memset(&s, 0, sizeof s);
	fill_hit(&hit[0], 0x1111, 2);
	fill_hit(&hit[1], 0x2222, 1);
	s.hit = hit;
	s.n_hit = 2;
	n = kof_diag_graph_build(&s, out, sizeof out);
	CK(n == 8 + 2 * 32 && kgenome_diag_scan_status(&s) == KGENOME_OK, "a node with two inputs is not a cut");
}

/* ---- the run ----------------------------------------------------------------------------------------- */

int main(void)
{
	snprintf(tmp, sizeof tmp, "build/test/api_engine_detect_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("api_engine_detect: no build/test directory - nothing tested\n");
		return 0;
	}
	t_heur();
	t_heur_anomalies();
	t_hex();
	t_memo();
	t_pattern();
	t_pattern_keys();
	t_pattern_prefix();
	t_mutation_name();
	t_graph_basic();
	t_graph_links();
	he_rmtree(tmp);
	printf("api_engine_detect: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
