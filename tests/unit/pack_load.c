/*
 * pack_load - what the loader does with a pack, and with a pack that is wrong.
 *
 * The loader maps a file and then reads offsets out of it. Every one of those
 * offsets is attacker controlled in the only sense that matters here: a database
 * directory is a directory, files in it can be corrupt, half written, truncated by
 * a full disk, or simply not packs at all. If a bad offset is believed, the first
 * symptom is a read outside the mapping or a module entered at the wrong address,
 * and neither is something a scan result would show.
 *
 * So the property under test is not "a good pack loads" - that is checked by every
 * scan - but that each individual check in the loader is load bearing. Each case
 * below breaks exactly one thing and repairs the checksum afterwards, because a
 * mutation that leaves the checksum wrong only ever proves the checksum works.
 *
 * The last case is the one with a policy in it: a directory holding one good pack
 * and one corrupt one must load the good one. A database that refuses to load
 * because one file in it is damaged is a scanner that stops working entirely for a
 * reason that cost it one signature.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../../libkofeng/kofdb/kofdb.h"
#include "../../libkofeng/kofdb/kofpack.h"
#include "../../libkofeng/kofdb/kofpackw.h"

static int failures;
static char root[256];

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- a pack to work from ------------------------------------------------- */

/*
 * Two modules, deliberately unequal: different string counts, one with no ranges,
 * one with two names. A single uniform module would make several index errors
 * indistinguishable from each other - a slice that starts one early and one that is
 * one too long land on the same bytes when every slice is the same size.
 */
static uint8_t *build_good(size_t *len)
{
	static const uint8_t code_a[] = { 0x90, 0x90, 0xc3 };
	static const uint8_t code_b[] = { 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
	static const uint8_t lit1[] = "this-is-a-literal";
	static const uint8_t lit2[] = "another";
	static const uint8_t lit3[] = "third-one";

	static const struct kof_pw_str str_a[] = {
		{ lit1, (uint16_t)(sizeof lit1 - 1), KOF_STR_LITERAL, 0 },
		{ lit2, (uint16_t)(sizeof lit2 - 1), KOF_STR_LITERAL, KOF_STR_ICASE }
	};
	static const struct kof_pw_str str_b[] = {
		{ lit3, (uint16_t)(sizeof lit3 - 1), KOF_STR_LITERAL,
		  KOF_STR_FULLWORD }
	};
	static const uint32_t rng_a[] = { 1u << 2, 1u << 3 };
	static const struct kof_pw_name name_a[] = {
		{ 11, "Test.Alpha" },
		{ 22, "Test.Beta" }
	};
	static const struct kof_pw_name name_b[] = { { 33, "Test.Gamma" } };

	struct kof_pw_mod m[2];

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
	m[1].name = name_b;
	m[1].n_names = 1;

	return kof_pack_build(KOF_PACK_DETECT, m, 2, len);
}

/* ---- files --------------------------------------------------------------- */

static int write_pack(const char *dir, const char *leaf, const uint8_t *img,
		      size_t len)
{
	char path[640];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	if (fwrite(img, 1, len, f) != len) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

/* One directory per case, so a case never sees another case's files. */
static int case_dir(char *out, size_t cap, const char *tag)
{
	snprintf(out, cap, "%s/%s", root, tag);
	return mkdir(out, 0700) == 0;
}

/* Remove the case's files, then the case's directory. Variadic in spirit: a case
 * may have written one pack or two. */
static void rm_dir(const char *dir, const char *leaf, const char *leaf2)
{
	char path[640];

	if (leaf) {
		snprintf(path, sizeof path, "%s/%s", dir, leaf);
		unlink(path);
	}
	if (leaf2) {
		snprintf(path, sizeof path, "%s/%s", dir, leaf2);
		unlink(path);
	}
	rmdir(dir);
}

/* The checksum is repaired after every mutation. Without this a case would only
 * ever be testing the checksum again, whatever it claimed to be testing. */
static void reseal(uint8_t *img, size_t len)
{
	struct kof_pack_hdr *h = (struct kof_pack_hdr *)img;

	h->crc32 = kof_crc32(img + KOF_PACK_CRC_FROM,
			     (uint64_t)len - KOF_PACK_CRC_FROM);
}

/*
 * Apply one mutation, load, and expect nothing back.
 *
 * `len` is passed by the caller rather than taken from the header, so truncation
 * is expressible: it is the one mutation that changes the file rather than its
 * contents.
 */
static void expect_refused(const char *tag, const uint8_t *good, size_t good_len,
			   void (*mutate)(uint8_t *, size_t *), int seal)
{
	uint8_t *img = malloc(good_len);
	size_t len = good_len;
	char dir[512];
	struct kof_engine *e;

	if (!img) {
		fail(tag, "out of memory");
		return;
	}
	memcpy(img, good, good_len);
	mutate(img, &len);
	if (seal)
		reseal(img, len);

	if (!case_dir(dir, sizeof dir, tag)) {
		fail(tag, "cannot make a directory for the case");
		free(img);
		return;
	}
	if (!write_pack(dir, "bad.ksig", img, len)) {
		fail(tag, "cannot write the pack");
		free(img);
		rm_dir(dir, NULL, NULL);
		return;
	}
	free(img);

	e = kof_db_load(dir);
	if (e) {
		fail(tag, "loaded a pack it should have refused");
		kof_db_free(e);
	}
	rm_dir(dir, "bad.ksig", NULL);
}

/* ---- the mutations ------------------------------------------------------- */

#define HDR(img) ((struct kof_pack_hdr *)(img))

static void mut_magic(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->magic ^= 0xffu;
}

static void mut_version(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->version = KOF_PACK_VERSION + 1u;
}

/*
 * A pack whose modules were compiled against a newer module ABI than this host.
 *
 * The one refusal here that is not about the FILE being wrong: the layout is
 * perfect, the checksum matches, every offset is in range. What is wrong is that
 * the code inside expects a bigger vtable than the host has, and calling it would
 * be a call through a slot that was never filled - out of a file, into whatever
 * follows the struct.
 *
 * This case exists because for a long time there was nothing to test: kofsig.h
 * promised that the host refuses such a pack, the constant it promised it with was
 * read by nothing, and the pack header had nowhere to carry the number.
 */
static void mut_abi(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->abi_version = KOFSIG_ABI_VERSION + 1u;
}

static void mut_machine(uint8_t *img, size_t *len)
{
	(void)len;
	/* Any value that is not the host's. The point is that a pack of foreign
	 * native code is refused rather than mapped and called. */
	HDR(img)->machine = (uint32_t)KOF_PACK_MACH_HOST + 1u;
}

/* A kind the engine has no dispatch list for. KOF_PACK_UNPACK is legal now, so
 * this has to be a value that is not - the check under test is "do I know where
 * these modules go", not "is this a detector". */
static void mut_kind(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->kind = 42;
}

/* Truncated: the file shrinks, and the length in the header no longer matches what
 * fstat reports. Nothing inside may be believed after that. */
static void mut_truncate(uint8_t *img, size_t *len)
{
	(void)img;
	*len -= 64;
}

/* The other half of the same check: the file is intact and the header lies. */
static void mut_file_len(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->file_len += 4096;
}

/* A flipped bit in the body, checksum left alone: this is the case the checksum
 * exists for, and the only one not resealed. */
static void mut_bitflip(uint8_t *img, size_t *len)
{
	img[*len / 2] ^= 0x40u;
}

static void mut_sec_off(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->sec[KOF_SEC_STR_POOL].off += HDR(img)->file_len;
}

static void mut_sec_align(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->sec[KOF_SEC_MODS].off += 1;
}

/* A section one entry longer than its count. Caught by the exact stride test and
 * by nothing else: every offset in it is still inside the file. */
static void mut_stride(uint8_t *img, size_t *len)
{
	(void)len;
	HDR(img)->n_mods -= 1;
}

static void mut_mod_code(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_mod *m = (void *)(img + h->sec[KOF_SEC_MODS].off);

	(void)len;
	m[0].code_off = (uint32_t)h->sec[KOF_SEC_CODE].len;
}

static void mut_mod_slice(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_mod *m = (void *)(img + h->sec[KOF_SEC_MODS].off);

	(void)len;
	m[1].n_str = h->n_str + 1;
}

static void mut_mod_align(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_mod *m = (void *)(img + h->sec[KOF_SEC_MODS].off);

	(void)len;
	m[0].code_off = 1;
}

static void mut_str_off(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_str *s = (void *)(img + h->sec[KOF_SEC_STR_DESC].off);

	(void)len;
	s[0].off = (uint32_t)h->sec[KOF_SEC_STR_POOL].len;
}

static void mut_str_len(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_str *s = (void *)(img + h->sec[KOF_SEC_STR_DESC].off);

	(void)len;
	s[0].len = 0;
}

/* A kind the engine does not know: it decides which matcher walks the bytes, so
 * an unknown one must be refused rather than defaulted. */
static void mut_str_kind(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_str *s = (void *)(img + h->sec[KOF_SEC_STR_DESC].off);

	(void)len;
	s[0].kind = 42;
}

/* A literal relabelled as a compiled hex program. Its bytes are a perfectly good
 * literal and complete nonsense as a program, which is exactly what the loader's
 * structural validation is for. */
static void mut_str_fake_hex(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_str *s = (void *)(img + h->sec[KOF_SEC_STR_DESC].off);

	(void)len;
	s[0].kind = KOF_STR_HEX;
}

static void mut_name_off(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	struct kof_pack_name *n = (void *)(img + h->sec[KOF_SEC_NAME_DESC].off);

	(void)len;
	n[0].off = (uint32_t)h->sec[KOF_SEC_NAME_POOL].len;
}

/*
 * A name whose terminator is outside its own pool.
 *
 * Every NUL in the pool is overwritten, so the last name runs to the end of the
 * section. Nothing about the offsets is wrong; only strlen would walk out, which is
 * exactly the kind of error a bounds check on offsets does not catch.
 */
static void mut_name_unterminated(uint8_t *img, size_t *len)
{
	struct kof_pack_hdr *h = HDR(img);
	uint8_t *pool = img + h->sec[KOF_SEC_NAME_POOL].off;
	uint64_t i;

	(void)len;
	for (i = 0; i < h->sec[KOF_SEC_NAME_POOL].len; i++)
		if (pool[i] == 0)
			pool[i] = 'x';
}

/* Not a pack at all: what a stray file in the database directory looks like. */
static void mut_junk(uint8_t *img, size_t *len)
{
	size_t i;

	for (i = 0; i < *len; i++)
		img[i] = (uint8_t)(i * 7u + 13u);
}

/* ---- the good case ------------------------------------------------------- */

static void check_good(const uint8_t *good, size_t good_len)
{
	struct kof_engine *e;
	char dir[512];
	const char *nm;

	if (!case_dir(dir, sizeof dir, "good")) {
		fail("good", "cannot make a directory for the case");
		return;
	}
	if (!write_pack(dir, "a.ksig", good, good_len)) {
		fail("good", "cannot write the pack");
		rm_dir(dir, NULL, NULL);
		return;
	}

	e = kof_db_load(dir);
	if (!e) {
		fail("good", "refused a pack it built itself");
		rm_dir(dir, "a.ksig", NULL);
		return;
	}

	if (e->n_mods != 2)
		fail("good", "wrong number of modules");
	if (e->n_str != 3 || e->n_rng != 2 || e->n_name != 3)
		fail("good", "wrong table sizes");

	/* The slices, which is what the loader rebases and therefore what it can get
	 * wrong without any pointer being invalid. */
	if (e->n_mods == 2) {
		if (e->mods[0].n_str != 2 || e->mods[1].n_str != 1)
			fail("good", "string slices did not survive the load");
		if (e->mods[0].str_base != 0 || e->mods[1].str_base != 2)
			fail("good", "string slices were not rebased");
		if (e->mods[0].n_rng != 2 || e->mods[1].n_rng != 0)
			fail("good", "range slices did not survive the load");
		if (e->mods[0].size_min != 64 || e->mods[1].size_min != 0)
			fail("good", "preconditions did not survive the load");
		if (e->mods[0].memo_base != 0 || e->mods[1].memo_base != 4)
			fail("good", "memo bases are not consecutive");

		nm = kof_db_name(e, &e->mods[1], 33);
		if (!nm || strcmp(nm, "Test.Gamma") != 0)
			fail("good", "a name did not resolve to its own module's text");
		if (kof_db_name(e, &e->mods[1], 11) != NULL)
			fail("good", "a name resolved outside its module's slice");
	}
	if (e->n_str == 3 &&
	    (e->str_tab[0].len != 17 ||
	     !(e->str_tab[1].flags & KOF_STR_ICASE) ||
	     !(e->str_tab[2].flags & KOF_STR_FULLWORD)))
		fail("good", "string flags did not survive the load");
	/* The pool is the part the descriptors index, so a load that got the
	 * rebasing wrong shows up here rather than as a wrong match much later. */
	if (e->n_str == 3 &&
	    memcmp(e->str_pool + e->str_tab[0].off, "this-is-a-literal", 17) != 0)
		fail("good", "a literal did not survive the load");
	if (e->memo_size != 4)
		fail("good", "memo total is not the sum of the slices");
	if (e->scan_mask != ((1u << 2) | (1u << 3)))
		fail("good", "scan mask is not the union of the modules'");

	kof_db_free(e);
	rm_dir(dir, "a.ksig", NULL);
}

/*
 * One good pack and one corrupt one in the same directory.
 *
 * The corrupt one must be refused and the good one must still load. The opposite
 * policy - refuse the database - turns one damaged file into a scanner that detects
 * nothing at all, which is a far worse outcome than the one signature that was
 * actually lost.
 */
static void check_mixed(const uint8_t *good, size_t good_len)
{
	struct kof_engine *e;
	uint8_t *bad = malloc(good_len);
	char dir[512];

	if (!bad) {
		fail("mixed", "out of memory");
		return;
	}
	memcpy(bad, good, good_len);
	mut_junk(bad, &good_len);

	if (!case_dir(dir, sizeof dir, "mixed")) {
		fail("mixed", "cannot make a directory for the case");
		free(bad);
		return;
	}
	if (!write_pack(dir, "a.ksig", good, good_len) ||
	    !write_pack(dir, "b.ksig", bad, good_len)) {
		fail("mixed", "cannot write the packs");
		free(bad);
		rm_dir(dir, NULL, NULL);
		return;
	}
	free(bad);

	e = kof_db_load(dir);
	if (!e)
		fail("mixed", "one corrupt pack took the whole database with it");
	else {
		if (e->n_mods != 2)
			fail("mixed", "the good pack did not load whole");
		kof_db_free(e);
	}

	rm_dir(dir, "a.ksig", "b.ksig");
}

/*
 * The order packs load in must come from their names, not from the filesystem.
 *
 * A scan stops at the first module that matches unless the caller asked for
 * everything, so the order modules sit in decides WHICH finding is reported when an
 * object matches more than one. Taking that order from readdir makes it a property
 * of how the directory happens to be laid out - and it changes when the database is
 * rebuilt, with no change to any signature.
 *
 * That is not hypothetical and this test exists because of it. Before the load was
 * sorted, four rebuilds of one byte-identical database over one 12GB corpus gave
 * 4637, 4820, 4637 and 4682 objects reported at the higher severity, the balance
 * moving to a lower one each time.
 *
 * The packs are written in the REVERSE of their sorted order, and the directory is
 * made next to the build output rather than in the system temporary directory.
 * Both details are load-bearing, and both were learned by the test failing to fail.
 *
 * Five packs in /tmp was the first attempt: it passed with the sort deleted. /tmp is
 * tmpfs here and hands entries back already ordered, so there was nothing for the
 * sort to correct. Thirty-two packs in /tmp passed too, for the same reason.
 *
 * Since no portable code can make a filesystem produce an adverse order, the test
 * checks whether it GOT one and says so when it did not. A case that cannot
 * distinguish the fix from its absence is worth less than no case at all, because it
 * reports green either way - so this one reports what it actually exercised.
 */
#define ORDER_PACKS 32u

static int order_exercised;   /* did readdir hand back an order worth sorting? */

static void check_order(void)
{
	char names[ORDER_PACKS][16];
	const uint32_t n = ORDER_PACKS;
	struct kof_engine *e;
	char dir[512];
	uint32_t i;
	int wrote = 1;
	DIR *d;

	for (i = 0; i < n; i++)
		snprintf(names[i], sizeof names[i], "p%02u.ksig", i);

	/*
	 * Beside the build output, not in TMPDIR. The order that matters is the one
	 * a real database directory produces, and a real one lives with the build.
	 */
	snprintf(dir, sizeof dir, "build/kof_order_XXXXXX");
	if (!mkdtemp(dir)) {
		snprintf(dir, sizeof dir, "%s/kof_order_XXXXXX",
			 getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
		if (!mkdtemp(dir)) {
			fail("order", "cannot make a directory for the case");
			return;
		}
	}

	/* Written from the last name to the first, so creation order is the reverse
	 * of the order the loader has to produce. */
	for (i = 0; i < n && wrote; i++) {
		static const uint8_t code[] = { 0x90, 0xc3 };
		uint32_t k = n - 1u - i;
		struct kof_pw_mod m;
		uint8_t *img;
		size_t len = 0;

		memset(&m, 0, sizeof m);
		m.code = code;
		m.code_len = (uint32_t)sizeof code;
		m.target_mask = 1;
		m.size_min = (uint64_t)k + 1u;   /* the marker is the name */

		img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
		if (!img) {
			wrote = 0;
			break;
		}
		wrote = write_pack(dir, names[k], img, len);
		free(img);
	}
	if (!wrote) {
		fail("order", "cannot write the packs");
		return;
	}

	/* What order does this filesystem actually give? If it is already sorted,
	 * nothing here can tell a sorted load from an unsorted one. */
	d = opendir(dir);
	if (d) {
		struct dirent *de;
		char prev[256] = "";

		order_exercised = 0;
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.')
				continue;
			if (prev[0] && strcmp(de->d_name, prev) < 0) {
				order_exercised = 1;
				break;
			}
			snprintf(prev, sizeof prev, "%s", de->d_name);
		}
		closedir(d);
	}

	e = kof_db_load(dir);
	if (!e) {
		fail("order", "the database did not load");
	} else {
		if (e->n_mods != n) {
			fail("order", "not every pack loaded");
		} else {
			for (i = 0; i < n; i++)
				if (e->mods[i].size_min != (uint64_t)i + 1u) {
					fail("order", "packs loaded in an order "
					     "that is not their names'");
					break;
				}
		}
		kof_db_free(e);
	}

	for (i = 0; i < n; i++) {
		char path[640];

		snprintf(path, sizeof path, "%.480s/%.32s", dir, names[i]);
		unlink(path);
	}
	rmdir(dir);
}

int main(void)
{
	static const struct {
		const char *tag;
		void (*fn)(uint8_t *, size_t *);
		int seal;
	} cases[] = {
		{ "magic",         mut_magic,             1 },
		{ "version",       mut_version,           1 },
		{ "abi",           mut_abi,               1 },
		{ "machine",       mut_machine,           1 },
		{ "kind",          mut_kind,              1 },
		{ "truncated",     mut_truncate,          1 },
		{ "file_len",      mut_file_len,          1 },
		{ "bitflip",       mut_bitflip,           0 },
		{ "sec_off",       mut_sec_off,           1 },
		{ "sec_align",     mut_sec_align,         1 },
		{ "stride",        mut_stride,            1 },
		{ "mod_code",      mut_mod_code,          1 },
		{ "mod_slice",     mut_mod_slice,         1 },
		{ "mod_align",     mut_mod_align,         1 },
		{ "str_off",       mut_str_off,           1 },
		{ "str_len",       mut_str_len,           1 },
		{ "str_kind",      mut_str_kind,          1 },
		{ "str_fake_hex",  mut_str_fake_hex,      1 },
		{ "name_off",      mut_name_off,          1 },
		{ "name_unterm",   mut_name_unterminated, 1 },
		{ "junk",          mut_junk,              1 }
	};
	const size_t n_cases = sizeof cases / sizeof cases[0];
	uint8_t *good;
	size_t good_len = 0, i;
	const char *tmp = getenv("TMPDIR");

	snprintf(root, sizeof root, "%s/kof_pack_load_XXXXXX",
		 tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(root)) {
		printf("pack load: cannot make a work directory\n");
		return 1;
	}

	good = build_good(&good_len);
	if (!good) {
		printf("pack load: the builder would not build a pack\n");
		rmdir(root);
		return 1;
	}

	check_good(good, good_len);

	/* The refusals are noisy by design - the loader names the file and what is
	 * wrong with it - and here every one of them is expected. */
	if (!freopen("/dev/null", "w", stderr)) {
		printf("pack load: cannot silence the expected diagnostics\n");
		free(good);
		rmdir(root);
		return 1;
	}
	for (i = 0; i < n_cases; i++)
		expect_refused(cases[i].tag, good, good_len, cases[i].fn,
			       cases[i].seal);

	check_mixed(good, good_len);
	check_order();

	free(good);
	rmdir(root);

	printf("pack load: %zu/%zu refusal(s), load order %s, good pack %s\n",
	       n_cases - (size_t)failures, n_cases,
	       order_exercised ? "sorted" : "NOT EXERCISED (fs gave sorted order)",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
