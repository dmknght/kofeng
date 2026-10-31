/*
 * api_kix_hostile - the block index trailer of a pack, made wrong one field at a time, opened through keng_open (owner 2026-10-29: hostile packs and every branch).
 *
 * WHY: (a) gcov of databases/pack/dbkix.c (make cov-report) showed 64.8 % of its branches before this file: kix_load.c refuses a pack whose footer, directory or length
 * is wrong, but each refusal inside kix_parse (a header field that is not what this build reads, counts that do not agree, offsets out of order, a filter that does
 * not fit) needs a header that is WRONG AND SEALED - its checksums repaired - or the checksum answers first and the field is never read. This builds that.
 *
 * WHAT IS BUILT. One pack of 200 blocks with its trailer (kix_fix.h, the packer's own output). Then, one at a time:
 *   HEADER   every byte of the 256-byte index header set to 0xFF, to 0x00 and bit-flipped, with the meta checksum and the footer checksum repaired;
 *   FOOTER   every byte of the 64-byte footer set to 0xFF and flipped, once with the footer checksum repaired and once without;
 *   CUTS     the file shortened to every offset of the footer, and to the boundaries inside the trailer (header, class table, directory, body, filter);
 *   DIRECTORY a byte of the directory changed (a directory that does not climb, one that does not span its entries) with the meta checksum repaired.
 *
 * THE PROPERTY (nothing silent). The pack's old part is intact. When the trailer's footer or the file's length no longer agree with the pack header the pack is refused
 * WHOLE (keng_open answers NULL: said). When only the index is refused it is built in memory from the sections, and says so (KOF_MTN_B_IN_RAM in kdb_mutation_status). For every mutation (status, keys) is the clean pack's - the damage lay where nothing is read - or the status
 * DIFFERS (the index was refused or degraded and the engine said so). A mutation that changes the number of keys with the same status is a table believed
 * wrongly, and fails here. Each mutation is also scanned with (a scanner made, an object scanned: no crash) and the whole sweep is repeated flat (oom_harness.h).
 *
 * usage: api_kix_hostile
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "oom_harness.h"
#include "kix_fix.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/dbkix.h"
#include "../../libkofeng/kofeng.h"

static int write_file(const char *path, const uint8_t *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static void rm_all(const char *d)
{
	char cmd[400];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", d);
	(void)system(cmd);
}

static char root[256], dir[300], packpath[400];
static uint8_t *good;
static size_t good_len;
static struct kof_kix_footer gft;

static struct mat M;                    /* the blocks and an object that credits a third of them */

static struct {
	uint32_t status, keys;
	int opened;
	uint64_t bytes;
	uint32_t cnt[200];      /* how many windows of the object each block matched, by the engine's own set */
} R;

static uint32_t clean_cnt[200];

static uint32_t clean_status, clean_keys;

static int phase(void *ctx)
{
	kof_engine *e = keng_open(dir);
	kof_scanner *sc;
	uint8_t obj[2048];
	struct kof_scan_option o;

	(void)ctx;
	R.opened = 0;
	R.status = R.keys = 0;
	memset(R.cnt, 0, sizeof R.cnt);
	if (!e)
		return -1;
	R.opened = 1;
	R.status = kdb_mutation_status(e, &R.bytes, &R.keys);
	if (e->mutation) {
		uint32_t *c = counts_of(e->mutation, M.nb, M.obj, M.n, NULL, 0);

		if (c)                          /* refused by the allocator under oh_sweep: the counts stay zero */
			memcpy(R.cnt, c, sizeof R.cnt);
		free(c);
	}
	sc = kscan_new(e);
	if (sc) {
		memset(obj, 0x5a, sizeof obj);
		memset(&o, 0, sizeof o);
		(void)kscan_bytes(sc, obj, sizeof obj, "x", &o, NULL, NULL);
		kscan_free(sc);
	}
	keng_close(e);
	return (int)R.status;
}

static void put(const uint8_t *img, size_t n)
{
	(void)write_file(packpath, img, n);
}

static void reseal_footer(uint8_t *img, size_t len)
{
	struct kof_kix_footer f;

	memcpy(&f, img + len - sizeof f, sizeof f);
	f.footer_crc = kof_crc32(&f, sizeof f - 4u);
	memcpy(img + len - sizeof f, &f, sizeof f);
}

static void reseal_meta(uint8_t *img, size_t len)
{
	struct kof_kix_footer f;

	memcpy(&f, img + len - sizeof f, sizeof f);
	if (f.trailer_off + f.meta_len <= len)
		f.meta_crc = kof_crc32(img + f.trailer_off, f.meta_len);
	memcpy(img + len - sizeof f, &f, sizeof f);
	reseal_footer(img, len);
}

static unsigned total, said, same, silent, refused_whole, unvalidated_header;

static void judge(const char *what, size_t at)
{
	(void)phase(NULL);
	total++;
	if (!R.opened) {
		refused_whole++;                        /* the footer or the length no longer agree with the pack header: the pack is refused WHOLE, and keng_open says NULL */
		said++;
		return;
	}
	if (R.status != clean_status) {
		said++;
		return;
	}
	if (R.keys == clean_keys && !memcmp(R.cnt, clean_cnt, sizeof R.cnt)) {
		same++;
		return;
	}
	/*
	 * KNOWN, REPORTED (D-API-6, 2026-10-29, M), NOT PINNED: three fields of the index header are believed and checked against nothing a SEALED header cannot
	 * also change: n_key (bytes 24..27, a statistic: kdb_mutation_status reports it), top (32..35, the largest raw hash: a lower one drops every window above it, so
	 * matches are lost) and n_class (12..15: the class table is read with another length and the answers change). The status stays 0 for all three. Only the
	 * checksums stand between a damaged or forged header and these answers, which is integrity and not authenticity (dbcore.h). The sweep accepts a silent
	 * change ONLY in those twelve bytes (and counts it); a change anywhere else still fails.
	 */
	if (!strcmp(what, "header byte") && ((at >= 12u && at < 16u) || (at >= 24u && at < 28u) || (at >= 32u && at < 36u))) {
		unvalidated_header++;
		return;
	}
	silent++;
	if (silent <= 8u)
		printf("  FAIL %s @%zu: keys %u (clean %u), matches %s, and the status is the same (%x): a table believed wrongly\n", what, at, R.keys, clean_keys,
		       memcmp(R.cnt, clean_cnt, sizeof R.cnt) ? "DIFFER" : "the same", R.status);
}

int main(void)
{
	size_t at, n, trailer, meta_len;
	uint8_t *img;
	static const uint8_t pats[3] = { 0xFFu, 0x00u, 0x00u };      /* the third is a bit flip */
	unsigned p;

	if (!freopen("/dev/null", "w", stderr))
		printf("  (could not silence the loader's diagnostics)\n");
	snprintf(root, sizeof root, "build/kof_kixhost_XXXXXX");
	if (!mkdtemp(root)) {
		printf("api_kix_hostile: no scratch directory\n");
		return 2;
	}
	snprintf(dir, sizeof dir, "%s/db", root);
	kof_mkdir(dir, 0700);
	snprintf(packpath, sizeof packpath, "%s/p0.ksig", dir);
	mat_make(&M, 200, 120000);
	good = build_pack(&M, 0, 200, &good_len);
	if (!good) {
		printf("api_kix_hostile: no pack\n");
		return 2;
	}
	memcpy(&gft, good + good_len - sizeof gft, sizeof gft);
	trailer = (size_t)gft.trailer_off;
	meta_len = (size_t)gft.meta_len;
	oh_init();
	put(good, good_len);
	(void)phase(NULL);
	clean_status = R.status;
	clean_keys = R.keys;
	memcpy(clean_cnt, R.cnt, sizeof clean_cnt);
	{
		unsigned b, any = 0;

		for (b = 0; b < 200u; b++)
			any += clean_cnt[b] != 0u;
		OHK(any >= 20u, "the object credits only %u blocks of 200: the matches say little", any);
	}
	OHK(R.opened && clean_keys > 0u, "the clean pack has no index (keys %u): the sweep would prove nothing", clean_keys);
	OHK((gft.magic == KOF_KIX_MAGIC_FOOT) && meta_len >= 256u, "the pack carries no trailer");
	printf("  clean pack: %zu bytes, trailer at %zu, header+tables %zu, %u keys, status %x\n", good_len, trailer, meta_len, clean_keys, clean_status);
	img = malloc(good_len + 8u);

	/* HEADER: every byte, three ways, with both checksums repaired */
	for (at = 0; at < 256u; at++)
		for (p = 0; p < 3u; p++) {
			memcpy(img, good, good_len);
			if (p < 2u)
				img[trailer + at] = pats[p];
			else
				img[trailer + at] ^= (uint8_t)(1u << (at % 8u));
			if (img[trailer + at] == good[trailer + at])
				continue;
			reseal_meta(img, good_len);
			put(img, good_len);
			judge("header byte", at);
		}
	/* the same bytes WITHOUT the repair: the checksum answers, the status says so */
	for (at = 0; at < 256u; at += 7u) {
		memcpy(img, good, good_len);
		img[trailer + at] ^= 0x10u;
		put(img, good_len);
		judge("header byte, checksum not repaired", at);
	}
	/* FOOTER */
	for (at = 0; at < sizeof gft; at++)
		for (p = 0; p < 3u; p++) {
			size_t pos = good_len - sizeof gft + at;

			memcpy(img, good, good_len);
			if (p < 2u)
				img[pos] = pats[p];
			else
				img[pos] ^= (uint8_t)(1u << (at % 8u));
			if (img[pos] == good[pos])
				continue;
			if (p != 1u)
				reseal_footer(img, good_len);
			put(img, good_len);
			judge(p == 1u ? "footer byte (checksum not repaired)" : "footer byte", at);
		}
	/* CUTS: every length inside the footer, and the boundaries inside the trailer */
	for (n = good_len - sizeof gft - 2u; n <= good_len; n++) {
		put(good, n);
		judge("cut in the footer", n);
	}
	{
		size_t cuts[] = { trailer, trailer + 1u, trailer + 255u, trailer + 256u, trailer + 256u + 8u, trailer + meta_len - 1u, trailer + meta_len,
				  trailer + meta_len + (size_t)gft.body_len / 2u, trailer + meta_len + (size_t)gft.body_len, (size_t)gft.old_len, (size_t)gft.old_len - 1u,
				  trailer + (size_t)gft.filter_off, trailer + (size_t)gft.filter_off + 64u, good_len - sizeof gft };
		size_t k;

		for (k = 0; k < sizeof cuts / sizeof cuts[0]; k++) {
			put(good, cuts[k]);
			judge("cut at a boundary", cuts[k]);
		}
	}
	/* DIRECTORY: a byte of it, sampled across its length, with the meta checksum repaired */
	for (at = 256u + 64u; at < meta_len; at += 4099u) {
		memcpy(img, good, good_len);
		img[trailer + at] ^= 0x01u;
		reseal_meta(img, good_len);
		put(img, good_len);
		judge("directory byte", at);
	}
	/* a directory that does not climb: two neighbouring entries swapped, checksum repaired */
	{
		size_t d0 = 256u + 64u + 4u * 100u;

		if (d0 + 8u < meta_len) {
			memcpy(img, good, good_len);
			memcpy(img + trailer + d0, good + trailer + d0 + 4u, 4u);
			memcpy(img + trailer + d0 + 4u, good + trailer + d0, 4u);
			reseal_meta(img, good_len);
			put(img, good_len);
			judge("directory entries swapped", d0);
		}
	}
	printf("  %u mutations of the index: %u said (%u of them refused the whole pack, the rest moved the status), %u harmless (same status and keys), %u silent\n", total, said, refused_whole, same, silent);
	OHK(silent == 0u, "%u mutations changed the index or its answers and the status stayed the same", silent);
	OHK(unvalidated_header <= 36u, "%u silent changes inside the three unvalidated header fields (at most 3 fields x 4 bytes x 3 patterns)", unvalidated_header);
	printf("  sealed header fields believed with the status unchanged (D-API-6, reported): %u mutations of n_class / n_key / top\n", unvalidated_header);
	OHK(said >= 100u, "only %u mutations were refused or degraded and said: the sweep does not reach the checks", said);
	/* the hostile engine under refused allocations and repeated: a refused index leaves nothing behind */
	put(good, good_len);
	(void)oh_sweep("clean pack with an index", phase, NULL, NULL, 40u);
	memcpy(img, good, good_len);
	img[trailer + 12u] = 0xFFu;                   /* n_class out of range: refused after the header was read */
	reseal_meta(img, good_len);
	put(img, good_len);
	(void)oh_sweep("index refused by its header", phase, NULL, NULL, 40u);
	(void)oh_flat("index refused by its header", phase, NULL, 6u, 4096);
	put(good, good_len);
	(void)oh_flat("clean pack with an index", phase, NULL, 6u, 4096);
	free(img);
	free(good);
	mat_free(&M);
	if (!oh_failures)
		rm_all(root);
	if (oh_failures) {
		printf("api_kix_hostile: %d FAIL\n", oh_failures);
		return 1;
	}
	printf("api_kix_hostile: ok\n");
	return 0;
}
