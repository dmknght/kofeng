/*
 * kofexamine/locate - where a marker is (kof_locate_str, kofinspect_locate.c) against a brute-force oracle, and the name of a dump
 * directory for a child (kof_dump_walk) against the rules of its own comment.
 *
 *   kofexamine/locate    byte 0 the pattern length (1..16), byte 1 the flags (bit 0 case-insensitive), then the pattern and the
 *                        haystack. The oracle scans every offset. Held: at is the first occurrence (or nowhere); hits are the first
 *                        64 occurrences, in order, each an occurrence; `clipped` is set exactly when there were more than 64;
 *                        a fixed pattern's hit length is its own; the call leaves no state (the matcher's tables are freed here).
 *   kofexamine/dumpname  the bytes are an object name: kof_dump_dir_for on it as a path, and, one iteration in 16 and when no
 *                        segment is dots (EX-5: a ".." segment would write above the scratch root, so such names are only COUNTED),
 *                        kof_dump_walk into a scratch root: the directory it answers is inside the root and the file `object`
 *                        is there; the scratch is removed after.
 */
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../../kofexamine/kofinspect_private.h"
#include "../../lib/fuzz_drv.h"

static void seeds(struct fz_corpus *c)
{
	static const char *const s[] = { "\x06" "\x00" "NEEDLEaaNEEDLEbbbNEEDLE", "\x04" "\x01" "AbCdxxabcDxxABCD", "\x01" "\x00" "aaaaaaaa",
		"\x03" "\x00" "abxxxxxx", "\x10" "\x00" "0123456789abcdef0123456789abcdef" };
	static const size_t n[] = { 22, 16, 10, 8, 34 };
	unsigned i;

	for (i = 0; i < sizeof s / sizeof s[0]; i++)
		fz_corpus_add(c, "locate", s[i], n[i]);
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static struct kof_match_ctx m, ms;
	static struct kof_range scratch[8];
	struct kof_region_map map;
	struct kof_locate out;
	size_t plen, hn, i, j;
	const uint8_t *pat, *hay;
	uint8_t flags;
	uint64_t occ[80], first = 0;
	unsigned no = 0, hits64 = 0;
	int r, icase;

	if (n < 3)
		return 0;
	plen = 1u + in[0] % 16u;
	flags = (uint8_t)(in[1] & 1u);
	icase = flags & 1;
	if (n < 2 + plen)
		return 0;
	pat = in + 2;
	hay = in + 2 + plen;
	hn = n - 2 - plen;
	memset(&map, 0, sizeof map);
	memset(&m, 0, sizeof m);
	memset(&ms, 0, sizeof ms);
	kof_match_begin(&m, kof_buf_make(hay, hn));
	for (i = 0; i + plen <= hn; i++) {
		int eq = 1;

		for (j = 0; j < plen && eq; j++) {
			unsigned char a = hay[i + j], b = pat[j];

			if (icase) {
				if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
				if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
			}
			eq = a == b;
		}
		if (eq) {
			if (no < 80)
				occ[no] = i;
			no++;
		}
	}
	first = no ? occ[0] : KGENOME_BROKEN;
	r = kof_locate_str(&m, &ms, &map, kof_buf_make(hay, hn), NULL, 0, 0, pat, (uint16_t)plen, KOF_STR_LITERAL, flags, (uint32_t)plen,
			   (uint32_t)plen, scratch, 8, &out);
	FZ_CHECK(c, r == (no != 0), "kof_locate_str: found / not found disagrees with a scan of every offset");
	FZ_CHECK(c, out.at == first, "kof_locate_str: `at` is not the first occurrence");
	FZ_CHECK(c, out.n_hits == (no < KOF_LOCATE_HITS ? no : KOF_LOCATE_HITS), "kof_locate_str: the hit count is not min(occurrences, 64)");
	FZ_CHECK(c, out.clipped == (no > KOF_LOCATE_HITS) || (no > KOF_LOCATE_HITS && out.n_hits == KOF_LOCATE_HITS),
		 "kof_locate_str: clipped is not set exactly when there are more than 64 occurrences");
	for (i = 0; i < out.n_hits && i < KOF_LOCATE_HITS; i++) {
		hits64++;
		FZ_CHECK(c, i >= 80 || out.hits[i] == occ[i], "kof_locate_str: hit is not the i-th occurrence");
		FZ_CHECK(c, out.hit_len[i] == plen, "kof_locate_str: the length of a fixed pattern's hit is not its own");
	}
	fz_digest(c, (uint64_t)no ^ (uint64_t)hits64 << 20 ^ first << 32);
	kof_match_state_free(&m);
	kof_match_state_free(&ms);
	return r;
}

FZ_ADAPTER(kx_locate, .name = "kofexamine/locate", .covers = "kof_locate_str", .shape = FZ_REQ, .seeds = seeds, .run = run);

/* ---------------------------------------------------------------------------------------------- dumpname */

static void name_seeds(struct fz_corpus *c)
{
	static const char *const s[] = { "f", "f//0", "f//0//1:norm", "dir/file.zip//3:bin/x86//2", "f//a\\b//\x01\xe9", "f//", "//", "f////x" };
	unsigned i;

	for (i = 0; i < sizeof s / sizeof s[0]; i++)
		fz_corpus_add(c, s[i], s[i], strlen(s[i]));
}

static int rm_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	(void)st; (void)flag; (void)f;
	return remove(p);
}

static int name_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char name[400], out[KOF_DUMP_PATH_ROOM + 64];
	size_t l = n < 380 ? n : 380, i;
	int dots = 0;

	for (i = 0; i < l; i++)
		name[i] = in[i] ? (char)in[i] : 'z';
	name[l] = 0;
	if (kof_dump_dir_for(name, out, sizeof out)) {
		const char *base = strrchr(out, '/');

		base = base ? base + 1 : out;
		FZ_CHECK(c, strlen(base) <= 255, "a dump directory name past 255 bytes");
		fz_digest(c, strlen(out));
	}
	for (i = 0; i + 1 < l; i++)
		if (name[i] == '.' && name[i + 1] == '.')
			dots = 1;
	fz_digest(c, (uint64_t)dots << 7);
	if ((c->iter & 15u) == 0 && !c->failk && !dots) {
		char root[160], dir[400], err[160], path[480];
		static const uint8_t b[] = { 1, 2, 3, 4 };
		struct kof_dump_stat st;
		struct stat sb;
		int r;

		mkdir("build", 0777);
		mkdir("build/fuzz", 0777);
		snprintf(root, sizeof root, "build/fuzz/kx_walk_%d", (int)getpid());
		dir[0] = 0;
		r = kof_dump_walk(root, name, kof_buf_make(b, 4), NULL, NULL, &st, dir, sizeof dir, err, sizeof err);
		fz_digest(c, (uint64_t)r);
		if (r) {
			FZ_CHECK(c, !strncmp(dir, root, strlen(root)), "kof_dump_walk answered a directory outside its root");
			FZ_CHECK(c, !strstr(dir, "/../"), "kof_dump_walk answered a path with a '..' segment");
			fz_digest(c, strstr(dir, "//") != NULL);     /* an empty segment of the name stays as `//`: harmless to the file system, counted */
			if (strcmp(dir, root)) {
				snprintf(path, sizeof path, "%s/object", dir);
				FZ_CHECK(c, stat(path, &sb) == 0 && sb.st_size == 4, "kof_dump_walk: no `object` file of the object's bytes below the top");
			}
		}
		(void)nftw(root, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	}
	return 0;
}

FZ_ADAPTER(kx_dumpname, .name = "kofexamine/dumpname", .covers = "kof_dump_walk", .shape = FZ_REQ, .seeds = name_seeds, .run = name_run);
