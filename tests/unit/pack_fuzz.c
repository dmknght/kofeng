/*
 * pack_fuzz - damage a database at random and load it.
 *
 * pack_load breaks one thing at a time and names what it broke, which is how a
 * check is shown to be load bearing. This does the opposite and is the other half:
 * it breaks whatever it lands on, thousands of times, and asserts only that the
 * loader survives and that anything it accepts is coherent.
 *
 * The checksum is repaired after most mutations, and that is the whole point. A
 * mutation that leaves the checksum wrong is rejected at step five and never
 * reaches the structural checks - so a fuzzer that did not reseal would be testing
 * CRC-32, over and over, forever. Resealing puts every offset, count, stride and
 * slice in the file under the fuzzer instead.
 *
 * Two things are asserted:
 *
 *   the loader returns. It may refuse - most mutants are refused, and being
 *   refused is a correct answer - but it does not crash, hang, or read outside
 *   the mapping. Under SAN=1 that last part is what this test is really for.
 *
 *   whatever it accepts can then be used. Every module's table slices lie inside
 *   the tables, every string lies inside the pool, every entry point lies inside
 *   the code arena - and then every pattern it accepted is actually matched
 *   against a buffer. The last part is the one that matters: the loader exists to
 *   make the scan path safe, so checking the tables and stopping there tests half
 *   of it. Deleting the whole hex validator went unnoticed until the fuzzer
 *   started matching, because a malformed program is harmless until it is walked.
 *
 * The code section is never mutated. It is opaque native code that the loader
 * cannot validate and the scanner calls, so damaging it and then running is not a
 * finding about the engine - it is the threat model kofpack.h already states, where
 * write access to the database is write access to the process. What is fuzzed is
 * everything the loader does claim to check.
 *
 * Deterministic: a failure names a seed and a round.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofdb/kofdb.h"
#include "../../libkofeng/kofdb/kofpack.h"
#include "../../libkofeng/kofdb/kofpackw.h"
#include "../../libkofeng/kofmatchers/hexprog.h"
#include "../../libkofeng/kofmatchers/kofmatch.h"

static int failures;
static char root[256];
static char pack_path[512];
static char log_path[512];

static uint64_t rng_state = 1;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static void fail(uint64_t round, const char *why)
{
	printf("  FAIL round %llu: %s\n", (unsigned long long)round, why);
	failures++;
}

/* ---- something worth breaking ---------------------------------------------- */

/*
 * A pack with one of everything the loader validates: two modules of different
 * shape, literals with both flags, ranges, names, and a compiled hex program - so
 * that the hex validator is fuzzed too rather than only the parts a literal uses.
 */
static uint8_t *build_good(size_t *len)
{
	static uint8_t hexprog[KOF_HEX_MAX_PROG];
	static const uint8_t code_a[] = { 0x90, 0x90, 0xc3 };
	static const uint8_t code_b[] = { 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
	static const uint8_t lit1[] = "a-literal-to-find";
	static const uint8_t lit2[] = "another";
	static struct kof_pw_str str_a[2];
	static struct kof_pw_str str_b[1];
	static const uint32_t rng_a[] = { 1u << 2, 1u << 3 };
	static const struct kof_pw_name name_a[] = {
		{ 11, "Test.Alpha" }, { 22, "Test.Beta" }
	};
	static const struct kof_pw_name name_b[] = { { 33, "Test.Gamma" } };
	struct kof_pw_mod m[2];
	uint32_t hlen;

	hlen = kof_hex_compile("E8 ?? ?? ?? ?? 5D [2-4] C3", hexprog,
			       sizeof hexprog, NULL);
	if (hlen == 0) {
		printf("pack fuzz: the test's own hex pattern will not compile: %s\n",
		       kof_hex_error());
		return NULL;
	}

	str_a[0].bytes = lit1;
	str_a[0].len   = (uint16_t)(sizeof lit1 - 1);
	str_a[0].kind  = KOF_STR_LITERAL;
	str_a[0].flags = KOF_STR_FULLWORD;
	str_a[1].bytes = hexprog;
	str_a[1].len   = (uint16_t)hlen;
	str_a[1].kind  = KOF_STR_HEX;
	str_a[1].flags = 0;

	str_b[0].bytes = lit2;
	str_b[0].len   = (uint16_t)(sizeof lit2 - 1);
	str_b[0].kind  = KOF_STR_LITERAL;
	str_b[0].flags = KOF_STR_ICASE;

	memset(m, 0, sizeof m);
	m[0].code = code_a;
	m[0].code_len = (uint32_t)sizeof code_a;
	m[0].target_mask = 1;
	m[0].scan_mask = (1u << 2) | (1u << 3);
	m[0].size_min = 64;
	m[0].str = str_a;
	m[0].n_str = 2;
	m[0].rng = rng_a;
	m[0].n_rng = 2;
	m[0].name = name_a;
	m[0].n_names = 2;

	m[1].code = code_b;
	m[1].code_len = (uint32_t)sizeof code_b;
	m[1].target_mask = 1;
	m[1].scan_mask = 1u << 2;
	m[1].str = str_b;
	m[1].n_str = 1;
	m[1].rng = rng_a;
	m[1].n_rng = 1;
	m[1].name = name_b;
	m[1].n_names = 1;

	return kof_pack_build(KOF_PACK_DETECT, m, 2, len);
}

/* ---- what an accepted pack has to be --------------------------------------- */

/*
 * Every index the engine will use, checked against the table it indexes.
 *
 * These are the invariants the scan path assumes without testing - it walks
 * str_tab[m->str_base + i] with no bounds check, because the loader promised. This
 * is where that promise is verified.
 *
 * Both module lists, because the memo is shared by them: a pack of unpackers loads
 * into e->unp and its modules still take memo slices, so checking only e->mods
 * reports a total that does not add up.
 */
static void check_mods(const struct kof_engine *e, const struct kof_module *mods,
		       uint32_t n, uint64_t *memo, uint64_t round, int *bad);
static void use_engine(const struct kof_engine *e);

static void check_engine(const struct kof_engine *e, uint64_t round)
{
	uint64_t memo = 0;
	uint32_t i;
	int bad = 0;

	check_mods(e, e->mods, e->n_mods, &memo, round, &bad);
	check_mods(e, e->unp,  e->n_unp,  &memo, round, &bad);
	if (bad)
		return;
	if (memo != e->memo_size) {
		fail(round, "the memo total is not the sum of the slices");
		return;
	}

	for (i = 0; i < e->n_str; i++) {
		const struct kof_str_ent *s = &e->str_tab[i];

		if (s->kind != KOF_STR_LITERAL && s->kind != KOF_STR_HEX) {
			fail(round, "a string has a kind the engine cannot walk");
			return;
		}
		if ((uint64_t)s->off + s->len > e->str_pool_len) {
			fail(round, "a string lies outside the pool");
			return;
		}
		if (s->kind == KOF_STR_HEX && s->off % KOF_HEX_PROG_ALIGN) {
			fail(round, "a hex program is misaligned");
			return;
		}
	}

	for (i = 0; i < e->n_name; i++)
		if (memchr(e->name_tab[i].text, 0, sizeof e->name_tab[i].text)
		    == NULL) {
			fail(round, "a detection name is not terminated");
			return;
		}

	use_engine(e);
}

static void check_mods(const struct kof_engine *e, const struct kof_module *mods,
		       uint32_t n, uint64_t *memo, uint64_t round, int *bad)
{
	uint32_t i;

	for (i = 0; i < n && !*bad; i++) {
		const struct kof_module *m = &mods[i];
		const uint8_t *fn = (const uint8_t *)(void *)(uintptr_t)m->fn;

		if ((uint64_t)m->str_base + m->n_str > e->n_str ||
		    (uint64_t)m->rng_base + m->n_rng > e->n_rng ||
		    (uint64_t)m->name_base + m->n_names > e->n_name) {
			fail(round, "a module names a table slice that is not there");
			*bad = 1;
			return;
		}
		if ((uint64_t)m->memo_base + (uint64_t)m->n_str * m->n_rng >
		    e->memo_size) {
			fail(round, "a module's memo slice is outside the memo");
			*bad = 1;
			return;
		}
		if (fn < e->code || fn >= e->code + e->code_cap) {
			fail(round, "a module's entry point is outside the arena");
			*bad = 1;
			return;
		}
		*memo += (uint64_t)m->n_str * m->n_rng;
	}
}

/*
 * Now use it: every pattern the loader accepted, matched against a buffer, the way
 * the scan path would. Structural checks alone say the tables are consistent; this
 * says the contents can be walked, which is the part a malformed hex program only
 * fails at.
 *
 * The buffer is heap allocated and the matcher is given the real thing - no module
 * is entered, because the module code is opaque and calling it proves nothing about
 * the loader.
 */
static void use_engine(const struct kof_engine *e)
{
	struct kof_match_ctx m;
	uint8_t *obj = malloc(256);
	uint32_t i;

	if (!obj)
		return;
	for (i = 0; i < 256; i++)
		obj[i] = (uint8_t)(i * 7u + 0xe8u);

	memset(&m, 0, sizeof m);
	if (kof_match_state_init(&m, 0, 0)) {
		kof_match_begin(&m, kof_buf_make(obj, 256));
		for (i = 0; i < e->n_str; i++) {
			const struct kof_str_ent *s = &e->str_tab[i];
			const uint8_t *b = e->str_pool + s->off;

			(void)kof_match_in(&m, 0, 256, b, s->len, s->kind, s->flags);
			(void)kof_match_at(&m, 0, b, s->len, s->kind, s->flags);
			(void)kof_match_at(&m, 250, b, s->len, s->kind, s->flags);
		}
		kof_match_state_free(&m);
	}
	free(obj);
}

/* ---- the mutations ---------------------------------------------------------- */

/*
 * Where to write.
 *
 * Uniformly over the file would put nearly every byte in the code arena, which
 * nothing validates, and the run would measure the random number generator. The
 * numbers the loader acts on are in the header and in the descriptor tables, and
 * those tables are a few hundred bytes in a file of several thousand.
 *
 * So the section table is used to aim. This matters more than it looks: with a
 * header-or-anywhere split, deleting the check that a string lies inside its pool
 * went unnoticed for sixty thousand rounds on three seeds out of four - the fuzzer
 * simply never landed on a string descriptor. Aiming at the tables turns that into
 * a hit within a few hundred rounds on every seed.
 */
static uint64_t code_lo, code_hi;   /* the one region left alone */

static uint64_t pick_off(const uint8_t *img, size_t len)
{
	const struct kof_pack_hdr *h = (const void *)img;
	uint32_t r = (uint32_t)(rnd() % 100), try;
	uint64_t at;

	if (len < sizeof *h)
		return rnd() % len;

	for (try = 0; try < 16; try++) {
		if (r < 35) {
			at = rnd() % sizeof *h;
		} else if (r < 90) {
			uint32_t i = (uint32_t)(rnd() % KOF_SEC_COUNT);
			uint64_t off = h->sec[i].off, n = h->sec[i].len;

			/* Most sections are empty in a pack this small, so this
			 * is retried rather than weighted. */
			if (!n || off > len || n > len - off)
				continue;
			at = off + rnd() % n;
		} else {
			at = rnd() % len;
		}
		if (at < code_lo || at >= code_hi)
			return at;
	}
	return rnd() % sizeof *h;
}

static uint8_t pick_byte(void)
{
	switch (rnd() % 8) {
	case 0: return 0x00;
	case 1: return 0xff;
	case 2: return 0x01;
	case 3: return 0x80;
	default: return (uint8_t)rnd();
	}
}

static int write_file(const uint8_t *img, size_t len)
{
	FILE *f = fopen(pack_path, "wb");
	size_t w;

	if (!f)
		return 0;
	w = fwrite(img, 1, len, f);
	return fclose(f) == 0 && w == len;
}

int main(int argc, char **argv)
{
	uint8_t *good, *img;
	size_t good_len = 0, len;
	uint64_t rounds = 20000, r, loaded = 0, refused = 0;
	uint64_t seed = 20240101u;
	const char *tmp = getenv("TMPDIR");

	if (argc > 1)
		seed = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);
	rng_state = seed ? seed : 1;

	snprintf(root, sizeof root, "%s/kof_pack_fuzz_XXXXXX",
		 tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(root)) {
		printf("pack fuzz: cannot make a work directory\n");
		return 1;
	}
	snprintf(pack_path, sizeof pack_path, "%s/f.ksig", root);

	good = build_good(&good_len);
	if (!good) {
		rmdir(root);
		return 1;
	}
	{
		const struct kof_pack_hdr *gh = (const void *)good;

		code_lo = gh->sec[KOF_SEC_CODE].off;
		code_hi = code_lo + gh->sec[KOF_SEC_CODE].len;
	}

	img = malloc(good_len + 64);
	if (!img) {
		free(good);
		rmdir(root);
		return 1;
	}

	/* The unmutated pack has to load, or every refusal below is meaningless. */
	if (!write_file(good, good_len)) {
		printf("pack fuzz: cannot write the pack\n");
		free(good);
		free(img);
		rmdir(root);
		return 1;
	}
	{
		struct kof_engine *e = kof_db_load(root);

		if (!e) {
			printf("pack fuzz: the unmutated pack does not load\n");
			failures++;
		} else {
			check_engine(e, 0);
			kof_db_free(e);
		}
	}

	/*
	 * The refusals below are expected and each one names the file, so they are
	 * sent to a file rather than to the terminal - and to a file rather than to
	 * /dev/null, because a sanitizer writes its report to stderr too. Pointing
	 * this at /dev/null hid a real heap overflow behind a bare exit code, which
	 * is a fine way to make a fuzzer useless.
	 */
	snprintf(log_path, sizeof log_path, "%s/stderr.log", root);
	if (!freopen(log_path, "w", stderr)) {
		printf("pack fuzz: cannot silence the expected diagnostics\n");
		free(good);
		free(img);
		unlink(pack_path);
		rmdir(root);
		return 1;
	}

	for (r = 1; r <= rounds; r++) {
		struct kof_engine *e;
		uint32_t k, n_mut;

		len = good_len;
		memcpy(img, good, good_len);

		switch (rnd() % 8) {
		case 0:
			/* Truncated somewhere, anywhere. */
			len = (size_t)(rnd() % good_len);
			break;
		case 1:
			/* Longer than it says it is. */
			len = good_len + (size_t)(rnd() % 64);
			memset(img + good_len, (int)pick_byte(), len - good_len);
			break;
		default:
			break;
		}
		if (len == 0)
			len = 1;

		n_mut = 1 + (uint32_t)(rnd() % 6);
		for (k = 0; k < n_mut; k++) {
			uint64_t at = pick_off(img, len);

			if (at < len)
				img[at] = pick_byte();
		}

		/*
		 * Reseal most of the time. Without this the checksum rejects
		 * everything and nothing past it is ever reached; with it, the
		 * structural checks are what the fuzzer is actually exercising.
		 * The remainder is left broken so the checksum path stays covered.
		 */
		if (rnd() % 8) {
			struct kof_pack_hdr *h = (struct kof_pack_hdr *)img;

			if (len > KOF_PACK_CRC_FROM)
				h->crc32 = kof_crc32(img + KOF_PACK_CRC_FROM,
						     (uint64_t)len -
						     KOF_PACK_CRC_FROM);
		}

		if (!write_file(img, len)) {
			fail(r, "cannot write the mutant");
			break;
		}

		e = kof_db_load(root);
		if (e) {
			loaded++;
			check_engine(e, r);
			kof_db_free(e);
		} else {
			refused++;
		}
		if (failures > 8)
			break;
	}

	free(good);
	free(img);
	unlink(pack_path);
	if (failures) {
		/* Left behind on failure: the log holds the loader's own account of
		 * every refusal, and a sanitizer report if there was one. */
		printf("  (diagnostics kept in %s)\n", log_path);
	} else {
		unlink(log_path);
		rmdir(root);
	}

	printf("pack fuzz: %llu round(s), %llu loaded, %llu refused%s\n",
	       (unsigned long long)rounds, (unsigned long long)loaded,
	       (unsigned long long)refused, failures ? "  FAILED" : "");
	return failures != 0;
}
