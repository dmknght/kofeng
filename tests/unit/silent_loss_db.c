/*
 * silent_loss_db - the limits of the DATABASE side (pack builder, pack loader,
 * diagnose packs, hex programs, mutation set, source readers) held to
 * one invariant: a database or rule that is over a limit gives the FULL result
 * or a SIGNAL a caller can see. "Nothing there" must be told from "we stopped
 * looking".
 *
 * Every case builds its fixture in memory (a pack through kof_pack_build, a
 * diagnose pack byte by byte, a source text) and writes it under build/test.
 * The row for every limit is in the report that came with this file; the cases:
 *
 *   builder_limits      KOF_MAX_STR_PER_MODULE, KOF_MAX_RANGE_PER_MODULE,
 *                       KOF_STR_MAX_LEN, KOF_HEX_MAX_PROG, KOF_BLOB_MAX_CODE:
 *                       kof_pack_build answers NULL, at build time.
 *   distinct_masks      KOF_MAX_DISTINCT_MASKS: 256 load, the 257th refuses the
 *                       WHOLE database (kof_db_load NULL).
 *   mutation_limits     KOF_MUTATION_MAX_HASH / MIN_HASH / a slice outside the
 *                       pool: kof_mutation_build NULL.
 *   hex_compile_limits  KOF_HEX_MAX_STEPS / ALTS / ALT_LEN / GAP_TOTAL: the
 *                       compiler refuses, with a message.
 *   hex_reach           KOF_HEX_MAX_REACH: a walk past 512 distinct end
 *                       positions drops the high end, with no signal.
 *   memo_wrap           KOF_MEMO_GEN_MAX: the generation wraps and nothing stale
 *                       answers.
 *   diag_record_caps    KOF_DIAG_MAX_NEED / MAX_WHEN / DB_DIAG_NAME / NEEDS store
 *                       / KOF_DIAG_PACK_MAX: a diagnose record or pack over a
 *                       limit is refused WITH A LINE ON STDERR and no counter.
 *   source_limits       KOF_SSRC_MAX_DIS, KOF_DSRC_MAX_ITEM/TERM/STR: errors
 *                       counted; KOF_DSRC_MAX_NODE (64) is wider than what the
 *                       loader reads (KOF_DB_MAX_DIAG_NODE, 32).
 *
 * KM_CHECK is for a limit that loses something with no signal. A test returns
 * fails != 0 || km_failed(): the day a cap is fixed the marker goes red.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "known_miss.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include "../../libkofeng/detectors/pattern/kofmatch.h"
#include "../../libkofeng/detectors/pattern/kofmultimatch.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofdiagtree.h"

static int fails;
static char root[256];

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* ---- small helpers --------------------------------------------------------- */

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static int write_file(const char *dir, const char *leaf, const void *p, size_t n)
{
	char path[640];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static void rm_all(const char *dir)
{
	char cmd[700];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

static int new_dir(const char *tag, char *dir, size_t cap)
{
	snprintf(dir, cap, "%s/%s", root, tag);
	rm_all(dir);
	return kof_mkdir(dir, 0700) == 0;
}

/* What the loader says on stderr while `load` runs: the signal a database that
 * is over a limit has today, since no counter exists for it. */
static char errtext[8192];
static int saved_fd = -1;

static void err_begin(void)
{
	char path[300];
	int fd;

	fflush(stderr);
	snprintf(path, sizeof path, "%s/stderr.txt", root);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	saved_fd = dup(2);
	if (fd >= 0) {
		(void)dup2(fd, 2);
		close(fd);
	}
}

static void err_end(void)
{
	char path[300];
	FILE *f;
	size_t n = 0;

	fflush(stderr);
	if (saved_fd >= 0) {
		(void)dup2(saved_fd, 2);
		close(saved_fd);
		saved_fd = -1;
	}
	snprintf(path, sizeof path, "%s/stderr.txt", root);
	errtext[0] = 0;
	f = fopen(path, "rb");
	if (f) {
		n = fread(errtext, 1, sizeof errtext - 1u, f);
		fclose(f);
	}
	errtext[n] = 0;
}

/* One module that does nothing: an entry point and a return. */
static const uint8_t code_ret[] = { 0xc3u };

static void put_mod(struct kof_pw_mod *m)
{
	memset(m, 0, sizeof *m);
	m->code = code_ret;
	m->code_len = (uint32_t)sizeof code_ret;
	m->scan_mask = KOF_SCAN_ALL;
}

/* A pack of `n` plain modules in `dir`, so a database exists to hang a diagnose
 * pack on. Returns 1 when written. */
static int plain_pack(const char *dir, const char *leaf)
{
	struct kof_pw_mod m;
	size_t len = 0;
	uint8_t *img;
	int ok;

	put_mod(&m);
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	if (!img)
		return 0;
	ok = write_file(dir, leaf, img, len);
	free(img);
	return ok;
}

/* ---- 1. the pack builder's own limits ---------------------------------------- */

static void builder_limits(void)
{
	static uint8_t big[KOF_BLOB_MAX_CODE + 1u];
	static uint8_t lit[KOF_STR_MAX_LEN + 1u];
	static uint8_t hexb[KOF_HEX_MAX_PROG + 1u];
	static struct kof_pw_str strs[KOF_MAX_STR_PER_MODULE + 1u];
	static uint32_t rngs[KOF_MAX_RANGE_PER_MODULE + 1u];
	struct kof_pw_mod m;
	size_t len = 0;
	uint8_t *img;
	unsigned i;

	memset(big, 0xc3, sizeof big);
	memset(lit, 'a', sizeof lit);
	memset(hexb, 0, sizeof hexb);

	/* code: the ceiling is a size bound, and over it the build says no */
	put_mod(&m);
	m.code = big;
	m.code_len = KOF_BLOB_MAX_CODE;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img != NULL);
	free(img);
	m.code_len = KOF_BLOB_MAX_CODE + 1u;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img == NULL);
	free(img);

	/* strings per module */
	for (i = 0; i < KOF_MAX_STR_PER_MODULE + 1u; i++) {
		strs[i].bytes = lit;
		strs[i].len = (uint16_t)(4u + i % 7u);
		strs[i].kind = KOF_STR_LITERAL;
		strs[i].flags = 0;
	}
	put_mod(&m);
	m.str = strs;
	m.n_str = KOF_MAX_STR_PER_MODULE;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img != NULL);
	free(img);
	m.n_str = KOF_MAX_STR_PER_MODULE + 1u;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img == NULL);
	free(img);

	/* ranges per module */
	for (i = 0; i < KOF_MAX_RANGE_PER_MODULE + 1u; i++)
		rngs[i] = KOF_SCAN_ALL;
	put_mod(&m);
	m.rng = rngs;
	m.n_rng = KOF_MAX_RANGE_PER_MODULE;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img != NULL);
	free(img);
	m.n_rng = KOF_MAX_RANGE_PER_MODULE + 1u;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img == NULL);
	free(img);

	/* one literal: KOF_STR_MAX_LEN fits, one more does not */
	put_mod(&m);
	strs[0].bytes = lit;
	strs[0].kind = KOF_STR_LITERAL;
	m.str = strs;
	m.n_str = 1;
	strs[0].len = (uint16_t)KOF_STR_MAX_LEN;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img != NULL);
	free(img);
	strs[0].len = (uint16_t)(KOF_STR_MAX_LEN + 1u);
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img == NULL);
	free(img);

	/* a hex program over KOF_HEX_MAX_PROG */
	strs[0].bytes = hexb;
	strs[0].kind = KOF_STR_HEX;
	strs[0].len = (uint16_t)(KOF_HEX_MAX_PROG + 1u);
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img == NULL);
	free(img);
	printf("  builder_limits: five size bounds refuse at build time (NULL)\n");
}

/* ---- 2. KOF_MAX_DISTINCT_MASKS ----------------------------------------------- */

static struct kof_engine *load_masks(const char *tag, unsigned n)
{
	static struct kof_pw_mod mods[KOF_MAX_DISTINCT_MASKS + 1u];
	static uint32_t mask[KOF_MAX_DISTINCT_MASKS + 1u];
	char dir[640];
	struct kof_engine *e = NULL;
	uint8_t *img;
	size_t len = 0;
	unsigned i;

	for (i = 0; i < n; i++) {
		put_mod(&mods[i]);
		mask[i] = i + 1u;               /* n distinct vocabularies */
		mods[i].rng = &mask[i];
		mods[i].n_rng = 1;
	}
	img = kof_pack_build(KOF_PACK_DETECT, mods, n, &len);
	if (!img || !new_dir(tag, dir, sizeof dir)) {
		free(img);
		return NULL;
	}
	if (write_file(dir, "m.ksig", img, len)) {
		err_begin();
		e = kof_db_load(dir);
		err_end();
	}
	free(img);
	rm_all(dir);
	return e;
}

static void distinct_masks(void)
{
	struct kof_engine *e;

	e = load_masks("mask256", KOF_MAX_DISTINCT_MASKS);
	CK(e != NULL && e->n_mods == KOF_MAX_DISTINCT_MASKS);
	if (e)
		kof_db_free(e);
	/* the 257th vocabulary refuses the whole database: loud, an error return
	 * (NULL), not a database that quietly shares a slot between two masks */
	e = load_masks("mask257", KOF_MAX_DISTINCT_MASKS + 1u);
	CK(e == NULL);
	if (e)
		kof_db_free(e);
	printf("  distinct_masks: 256 load, 257 refuses the whole database\n");
}

/* ---- 3. the mutation set ------------------------------------------------------ */

static void mutation_limits(void)
{
	static uint32_t pool[KOF_MUTATION_MAX_HASH + 2u];
	struct kof_mutation_block b;
	struct kof_mutation_set *s;
	uint32_t i;

	for (i = 0; i < KOF_MUTATION_MAX_HASH + 2u; i++)
		pool[i] = i * 977u + 5u;
	memset(&b, 0, sizeof b);
	b.scan_mask = 1u;

	b.n_hash = KOF_MUTATION_MAX_HASH;
	s = kof_mutation_build(&b, 1, pool, KOF_MUTATION_MAX_HASH);
	CK(s != NULL);
	kof_mutation_set_free(s);

	b.n_hash = KOF_MUTATION_MAX_HASH + 1u;
	s = kof_mutation_build(&b, 1, pool, KOF_MUTATION_MAX_HASH + 1u);
	CK(s == NULL);                 /* over the per-block ceiling: refused */
	kof_mutation_set_free(s);

	b.n_hash = KGENOME_MUTATION_MIN_HASH - 1u;
	s = kof_mutation_build(&b, 1, pool, KGENOME_MUTATION_MIN_HASH);
	CK(s == NULL);                 /* too few to say anything: refused */
	kof_mutation_set_free(s);

	b.n_hash = 20u;
	b.first_hash = KOF_MUTATION_MAX_HASH;  /* slice runs past the pool */
	s = kof_mutation_build(&b, 1, pool, KOF_MUTATION_MAX_HASH);
	CK(s == NULL);
	kof_mutation_set_free(s);
	printf("  mutation_limits: an inconsistent or oversized block is refused (NULL)\n");
}

/* ---- 4. hex programs ----------------------------------------------------------- */

static int hex_refused(const char *pat)
{
	static uint8_t prog[KOF_HEX_MAX_PROG];
	uint32_t n = kof_hex_compile(pat, prog, sizeof prog, NULL);

	return n == 0 && kof_hex_error() && *kof_hex_error();
}

static int hex_ok(const char *pat)
{
	static uint8_t prog[KOF_HEX_MAX_PROG];

	return kof_hex_compile(pat, prog, sizeof prog, NULL) != 0;
}

static void hex_compile_limits(void)
{
	static char t[20000];
	size_t at;
	unsigned i, k;

	/* steps: 24 alternations fit, 25 do not */
	for (k = 0; k < 2; k++) {
		unsigned n_steps = k ? KOF_HEX_MAX_STEPS + 1u : KOF_HEX_MAX_STEPS;

		/* a concrete first step is the anchor; then n_steps - 1 groups */
		at = (size_t)snprintf(t, sizeof t, "de ad be ef ");
		for (i = 0; i + 1u < n_steps; i++)
			at += (size_t)snprintf(t + at, sizeof t - at, "( 41 | 42 ) ");
		if (k)
			CK(hex_refused(t));
		else
			CK(hex_ok(t));
	}

	/* alternatives in one step: 8 fit, 9 do not */
	for (k = 0; k < 2; k++) {
		unsigned n_alt = k ? KOF_HEX_MAX_ALTS + 1u : KOF_HEX_MAX_ALTS;

		at = (size_t)snprintf(t, sizeof t, "de ad be ef ( ");
		for (i = 0; i < n_alt; i++)
			at += (size_t)snprintf(t + at, sizeof t - at, "%s%02x 55",
					       i ? " | " : "", 0x10u + i);
		at += (size_t)snprintf(t + at, sizeof t - at, " )");
		if (k)
			CK(hex_refused(t));
		else
			CK(hex_ok(t));
	}

	/* one alternative's length: 256 bytes fit, 257 do not */
	for (k = 0; k < 2; k++) {
		unsigned n = k ? KOF_HEX_MAX_ALT_LEN + 1u : KOF_HEX_MAX_ALT_LEN;

		at = 0;
		for (i = 0; i < n; i++)
			at += (size_t)snprintf(t + at, sizeof t - at, "41 ");
		if (k)
			CK(hex_refused(t));
		else
			CK(hex_ok(t));
	}

	/* summed gap variance: 256 fits, 257 does not */
	CK(hex_ok("41 42 43 44 [0-256] 45 46 47 48"));
	CK(hex_refused("41 42 43 44 [0-257] 45 46 47 48"));
	CK(hex_refused("41 42 43 44 [0-200] 45 46 47 48 [0-60] 49 4a 4b 4c"));
	printf("  hex_compile_limits: steps, alts, alt length and gap total refuse at compile\n");
}

/*
 * KOF_HEX_MAX_REACH. A hex walk carries the END positions of the match so far;
 * past KOF_HEX_MAX_REACH distinct ones the rest are dropped (`goto reach_full`)
 * with nothing said, and a walk that needed a dropped one reports "no match" on
 * input that holds the pattern. The ends are DISTINCT (an exact bitmap dedups
 * them), so a pattern needs genuinely many different ways to be this long: 21
 * steps, each of five alternatives of different lengths, over a run of 'A'.
 * The highest end - every step taking its longest alternative - is the one that
 * is dropped, and the data is built so that only that path reaches the final B.
 */
/* The pattern of `steps` groups, and whether the walk finds the B that only the
 * longest path (every group taking its 120-byte alternative) reaches. */
static int reach_walk(unsigned steps, int with_b)
{
	static const unsigned lens[5] = { 1u, 30u, 60u, 90u, 120u };
	static char t[40000];
	static uint8_t prog[KOF_HEX_MAX_PROG];
	static uint8_t data[4 + 21 * 120 + 8];
	size_t at;
	unsigned i, j, k, n_data;

	at = (size_t)snprintf(t, sizeof t, "de ad be ef ");
	for (i = 0; i < steps; i++) {
		at += (size_t)snprintf(t + at, sizeof t - at, "( ");
		for (j = 0; j < 5; j++) {
			if (j)
				at += (size_t)snprintf(t + at, sizeof t - at, "| ");
			for (k = 0; k < lens[j]; k++)
				at += (size_t)snprintf(t + at, sizeof t - at, "41 ");
		}
		at += (size_t)snprintf(t + at, sizeof t - at, ") ");
	}
	at += (size_t)snprintf(t + at, sizeof t - at, "42");
	if (!kof_hex_compile(t, prog, sizeof prog, NULL)) {
		printf("  hex_reach: the fixture pattern does not compile: %s\n",
		       kof_hex_error());
		return -1;
	}
	n_data = 4u + steps * 120u;
	memset(data, 0x41, sizeof data);
	memcpy(data, "\xde\xad\xbe\xef", 4);
	data[n_data] = with_b ? 0x42 : 0x43;
	return kof_hex_walk(kof_buf_make(data, n_data + 1u), 0, prog);
}

/*
 * KOF_HEX_MAX_REACH. A hex walk carries the END positions of the match so far;
 * past KOF_HEX_MAX_REACH distinct ones the rest are dropped (`goto reach_full`)
 * with nothing said, and a walk that needed a dropped one reports "no match" on
 * input that holds the pattern. The ends are DISTINCT (an exact bitmap dedups
 * them), so it takes genuinely many ways to be this long: N steps, each of five
 * alternatives of different lengths, over a run of 'A'. The number of distinct
 * ends after N steps is about 1.5 N^2, so 10 steps stay under the cap and 21
 * pass it. The highest end - every step taking its longest alternative - is the
 * one that is dropped, and the data is built so that only that path reaches the
 * final B.
 */
static void hex_reach(void)
{
	CK(reach_walk(10, 1) == 1);    /* well under the cap: found */
	/* The pattern IS in the data: 21 steps of 120 bytes, then B - found through
	 * the wide walk, which is sized by the program and drops no end. */
	CK(reach_walk(21, 1) == 1);
	/* and the same data without the B is still a no, by the same walk */
	CK(reach_walk(21, 0) == 0);
}

/*
 * KOF_HEX_GAP_OPEN. "[4-]" compiles to "[4-256]": a pattern whose parts are far
 * apart is documented as two patterns. The compile succeeds with no message, so
 * the author who wrote an unbounded gap is told nothing when the second half sits
 * 300 bytes on and the pattern does not match.
 */
static void hex_open_gap(void)
{
	static uint8_t prog[KOF_HEX_MAX_PROG];
	static uint8_t data[400];
	struct kof_match_ctx m;
	struct kof_hex_stat st;
	uint32_t plen;
	int found;

	plen = kof_hex_compile("de ad be ef [4-] ca fe ba be", prog, sizeof prog, &st);
	CK(plen != 0);
	memset(data, 0x11, sizeof data);
	memcpy(data, "\xde\xad\xbe\xef", 4);
	memcpy(data + 4 + 300, "\xca\xfe\xba\xbe", 4);       /* 300 bytes apart */
	memset(&m, 0, sizeof m);
	CK(kof_match_state_init(&m, 0, 0));
	kof_match_begin(&m, kof_buf_make(data, sizeof data));
	found = plen ? kof_match_in(&m, 0, sizeof data, prog, (uint16_t)plen,
				    KOF_STR_HEX, 0) : 0;
	kof_match_state_free(&m);
	/* The meaning is kept (a clip at 256, as documented) and the clip is SAID:
	 * the compile counts the open jump for the build tool to warn about. */
	CK(found == 1 || st.open_gaps == 1u);
	CK(found == 0 && st.open_gaps == 1u);
	plen = kof_hex_compile("de ad be ef [4-8] ca fe ba be", prog, sizeof prog, &st);
	CK(plen != 0 && st.open_gaps == 0u);
	plen = kof_hex_compile("de ad [250-] be ef [250-] ca", prog, sizeof prog, &st);
	CK(plen != 0 && st.open_gaps == 2u);
}

/* ---- 5. the memo's generation wraps -------------------------------------------- */

static void memo_wrap(void)
{
	static const uint8_t needle[] = "SILENT-LOSS-NEEDLE";
	static uint8_t obj[64];
	struct kof_match_ctx m;
	struct kof_range all;
	struct kof_match_req rq;
	unsigned i, bad = 0, n = 2u * KOF_MEMO_GEN_MAX + 40u;

	memset(&m, 0, sizeof m);
	CK(kof_match_state_init(&m, 0, 4));
	memset(&rq, 0, sizeof rq);
	rq.slot = 1;
	rq.next = 1;
	rq.ext = &all;
	rq.pat.bytes = needle;
	rq.pat.len = (uint16_t)(sizeof needle - 1u);
	rq.pat.kind = KOF_STR_LITERAL;
	all.off = 0;
	all.len = sizeof obj;
	for (i = 0; i < n; i++) {
		int want = (i % 3u) == 0;

		memset(obj, 'x', sizeof obj);
		if (want)
			memcpy(obj + 7, needle, sizeof needle - 1u);
		kof_match_begin(&m, kof_buf_make(obj, sizeof obj));
		if (kof_match_lookup(&m, &rq) != want)
			bad++;
		/* and asked again, from the memo */
		if (kof_match_lookup(&m, &rq) != want)
			bad++;
	}
	kof_match_state_free(&m);
	CK(bad == 0);
	printf("  memo_wrap: %u objects across two wraps of the generation, %u wrong\n", n, bad);
}

/* ---- 6. a diagnose record or pack over a limit ---------------------------------- */

/* A diagnose of one node plus the given tail, then a second plain one: the
 * count that loads says whether the first was refused. */
static size_t rec_base(uint8_t *b, const char *name, unsigned n_node,
		       unsigned sym_len)
{
	size_t nl = strlen(name), at = 0;
	unsigned i;

	b[at++] = (uint8_t)n_node; b[at++] = 0;
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, name, nl); at += nl;
	for (i = 0; i < n_node; i++) {
		uint16_t cap = (uint16_t)(i ? KGENOME_NUCLEO_MEM_READ : KGENOME_NUCLEO_NET_OPEN);
		unsigned alen = sym_len ? 2u + sym_len : 0u;

		b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
		b[at++] = 0; b[at++] = 0;
		b[at++] = i ? 0 : KOF_DIAG_NO_PARENT;
		b[at++] = 0;
		b[at++] = 0;
		b[at++] = (uint8_t)alen;
		if (alen) {
			b[at++] = KDIG_ATTR_SYM;
			b[at++] = (uint8_t)sym_len;
			memset(b + at, 's', sym_len);
			at += sym_len;
		}
	}
	return at;
}

enum variant { V_NEEDS9, V_WHEN9, V_REFS9, V_NAME48, V_SYMS, V_COUNT };

static size_t rec_variant(uint8_t *b, enum variant v)
{
	size_t at;
	unsigned i;

	switch (v) {
	case V_NEEDS9:
		at = rec_base(b, "dg_needs", 1, 0);
		b[at++] = 0;                    /* the old sign count */
		b[at++] = KDIG_SEC_NEEDS;
		b[at++] = (uint8_t)(2u * (KOF_DIAG_MAX_NEED + 1u));
		for (i = 0; i < KOF_DIAG_MAX_NEED + 1u; i++) {
			b[at++] = (uint8_t)KGENOME_NUCLEO_MEM_READ;
			b[at++] = (uint8_t)(KGENOME_NUCLEO_MEM_READ >> 8);
		}
		return at;
	case V_WHEN9:
		at = rec_base(b, "dg_when", 1, 0);
		b[at++] = 0;
		b[at++] = KDIG_SEC_WHEN;
		b[at++] = (uint8_t)(10u * (KOF_DIAG_MAX_WHEN + 1u));
		for (i = 0; i < KOF_DIAG_MAX_WHEN + 1u; i++) {
			b[at++] = 1; b[at++] = 0;           /* fact 1 */
			memset(b + at, 0, 8); at += 8;
		}
		return at;
	case V_REFS9:
		at = rec_base(b, "dg_refs", 1, 0);
		b[at++] = 0;
		b[at++] = KDIG_SEC_REFS;
		b[at++] = (uint8_t)(1u + (KOF_DIAG_MAX_NEED + 1u) * 3u);
		b[at++] = (uint8_t)(KOF_DIAG_MAX_NEED + 1u);
		for (i = 0; i < KOF_DIAG_MAX_NEED + 1u; i++) {
			b[at++] = 2; b[at++] = 'a'; b[at++] = (uint8_t)('a' + i);
		}
		return at;
	case V_NAME48: {
		char nm[64];

		/* 48 characters, which the store held 47 of; the record's own length
		 * byte is the bound now (255) and the store is sized to it */
		memset(nm, 'n', 48);
		nm[48] = 0;
		return rec_base(b, nm, 1, 0);
	}
	default: {
		/* more nodes than there were signs, each naming a 47-character symbol:
		 * a store sized per record holds them whatever their number */
		at = rec_base(b, "dg_syms", KOF_DIAG_MAX_NEED + 1u, KOF_DIAG_NEED_LEN - 1u);
		return at;
	}
	}
}

/* A pack of the bad record and a plain one. `pad` extra bytes of tail. */
static uint8_t *diag_pack(size_t *len, enum variant v, size_t pad)
{
	static uint8_t rec_a[4096], rec_b[256];
	size_t la = rec_variant(rec_a, v), lb = rec_base(rec_b, "dg_plain", 1, 0);
	size_t head = 8u + 2u * 8u;
	uint8_t *p = calloc(1, head + la + lb + pad);

	if (!p)
		return NULL;
	memcpy(p, "KDGP", 4);
	p[4] = 1;
	p[6] = 2;
	put32(p + 8, (uint32_t)head);               put32(p + 12, (uint32_t)la);
	put32(p + 16, (uint32_t)(head + la));       put32(p + 20, (uint32_t)lb);
	memcpy(p + head, rec_a, la);
	memcpy(p + head + la, rec_b, lb);
	*len = head + la + lb + pad;
	return p;
}

static struct kof_engine *load_diag(const char *tag, uint8_t *pk, size_t len)
{
	char dir[640];
	struct kof_engine *e = NULL;

	if (!new_dir(tag, dir, sizeof dir) || !plain_pack(dir, "m.ksig") ||
	    !write_file(dir, "diag-x.kdig", pk, len))
		return NULL;
	err_begin();
	e = kof_db_load(dir);
	err_end();
	rm_all(dir);
	return e;
}

static void diag_record_caps(void)
{
	/*
	 * A record over a bound the loader keeps (more signs, symbols or conditions
	 * than the array holds) is refused AND COUNTED - kdb_diag_refused, which a host
	 * can read - and one that only the old fixed slots refused (a long name, many
	 * long symbols) now loads.
	 */
	static const struct {
		const char *what;
		int loads;
	} row[V_COUNT] = {
		{ "a diagnose past the bound of needed capabilities is refused and counted", 0 },
		{ "a diagnose past the bound of conditions is refused and counted", 0 },
		{ "a diagnose past the bound of declared symbols is refused and counted", 0 },
		{ "a diagnose with a 48-character name is loaded", 1 },
		{ "a diagnose whose node symbols filled the old string store is loaded", 1 },
	};
	char tag[32];
	int v;

	for (v = 0; v < V_COUNT; v++) {
		size_t len = 0;
		uint8_t *pk = diag_pack(&len, (enum variant)v, 0);
		struct kof_engine *e;

		snprintf(tag, sizeof tag, "dv%d", v);
		e = pk ? load_diag(tag, pk, len) : NULL;
		free(pk);
		CK(e != NULL);
		if (!e)
			continue;
		/* the plain record always loads */
		CK(e->n_diag >= 1u);
		if (row[v].loads) {
			CK(e->n_diag == 2u && kdb_diag_refused(e) == 0u);
		} else {
			/* a line on stderr for a person, and a count a host can read */
			CK(strstr(errtext, "not one this build can read") != NULL);
			CK(e->n_diag == 1u && kdb_diag_refused(e) == 1u);
		}
		printf("  diag_record_caps: %s\n", row[v].what);
		kof_db_free(e);
	}
}

static void diag_pack_size(void)
{
	size_t len = 0, pad = ((size_t)4u << 20);
	uint8_t *pk = NULL;
	struct kof_engine *e;

	/* one valid record and 4 MiB of tail the table does not reference */
	{
		static uint8_t rec_a[256];
		size_t la = rec_base(rec_a, "dg_big_a", 1, 0);
		size_t head = 8u + 8u;
		size_t total = head + la + pad;

		pk = calloc(1, total);
		if (!pk)
			return;
		memcpy(pk, "KDGP", 4);
		pk[4] = 1;
		pk[6] = 1;
		put32(pk + 8, (uint32_t)head);
		put32(pk + 12, (uint32_t)la);
		memcpy(pk + head, rec_a, la);
		len = total;
	}
	e = load_diag("bigpack", pk, len);
	free(pk);
	CK(e != NULL);
	if (!e)
		return;
	/* No size bound for one pack: a valid pack past the old 4 MiB loads. */
	CK(e->n_diag == 1u && kdb_diag_packs_refused(e) == 0u);
	kof_db_free(e);
}

/* A file that is not a diagnose pack at all is refused whole and COUNTED. */
static void diag_pack_refused(void)
{
	uint8_t junk[32];
	struct kof_engine *e;

	memset(junk, 'x', sizeof junk);
	e = load_diag("junkpack", junk, sizeof junk);
	CK(e != NULL);
	if (!e)
		return;
	CK(strstr(errtext, "is not a diagnose pack") != NULL);   /* for a person */
	CK(kdb_diag_packs_refused(e) == 1u);                    /* for a host */
	kof_db_free(e);
}

/* ---- 7. the source readers ------------------------------------------------------- */

static void source_limits(void)
{
	static const struct kof_dsrc_report quiet = { NULL, NULL, NULL };
	static char text[16384];
	static struct kof_dsrc d;
	static struct kof_dsrc_view v;
	size_t at;
	unsigned i, k;

	/* a diagnose source: tails to the node bound, the node count past it */
	for (k = 0; k < 3; k++) {
		unsigned n_tail = k == 0 ? KOF_DB_MAX_DIAG_NODE - 1u
				: k == 1 ? KOF_DSRC_MAX_NODE - 1u
					 : KOF_DSRC_MAX_NODE;
		int errs;

		at = (size_t)snprintf(text, sizeof text,
			"KOF_DIAG_NAME(DIAG_X);\n"
			"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
			"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n");
		for (i = 0; i < n_tail; i++)
			at += (size_t)snprintf(text + at, sizeof text - at,
					       "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n");
		memset(&d, 0, sizeof d);
		CK(kof_dsrc_parse(text, at, &d, &quiet) == 0);
		errs = kof_dsrc_resolve(&d, &v, &quiet);
		if (k == 0)
			CK(errs == 0 && v.n_nd == (int)KOF_DB_MAX_DIAG_NODE);
		else if (k == 1)
			/* the source layer takes exactly what the loader reads: one carrier */
			CK(errs == 0 && v.n_nd == (int)KOF_DB_MAX_DIAG_NODE &&
			   KOF_DSRC_MAX_NODE == KOF_DB_MAX_DIAG_NODE);
		else
			CK(errs > 0);          /* ... and its own bound is an error */
	}

	/* 97 declarations: the 97th is an error, not dropped */
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(DIAG_Y);\n");
	for (i = 0; i < KOF_DSRC_MAX_ITEM + 1u; i++)
		at += (size_t)snprintf(text + at, sizeof text - at,
				       "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n");
	memset(&d, 0, sizeof d);
	CK(kof_dsrc_parse(text, at, &d, &quiet) > 0);
	printf("  source_limits: diagnose source bounds are counted errors\n");
}

int main(void)
{
	snprintf(root, sizeof root, "build/test/silentdb_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("silent loss db: cannot make a work directory\n");
		return 1;
	}
	builder_limits();
	distinct_masks();
	mutation_limits();
	hex_compile_limits();
	hex_reach();
	hex_open_gap();
	memo_wrap();
	diag_record_caps();
	diag_pack_size();
	diag_pack_refused();
	source_limits();
	rm_all(root);
	printf("silent loss db: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
