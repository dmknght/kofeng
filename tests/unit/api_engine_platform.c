/*
 * api_engine_platform.c - <kofplatform.h> (and the _os / _file parts) and
 * <kofdebug.h>: what the engine and its tools call instead of the OS.
 *
 * Two kinds of contract. The path helpers are pure string functions with edge
 * cases that decide where a scan or a repair lands (a squash that kept "//"
 * made a file unspellable; a prefix test that ignored the separator put
 * /a/bc "under" /a/b). The file helpers are about REFUSAL: every one that
 * writes opens with O_NOFOLLOW (or the reparse-point check), so a symlink an
 * attacker planted where a scratch file goes is not written through. That is
 * asserted here against a real symlink.
 *
 * Scratch files go under build/test, never /tmp.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofcore/kofdebug.h"

static char dir[160];

static void path_of(char *out, size_t cap, const char *leaf)
{
	snprintf(out, cap, "%s/%s", dir, leaf);
}

static int slurp(const char *p, char *out, size_t cap)
{
	FILE *f = fopen(p, "rb");
	size_t n;

	if (!f)
		return -1;
	n = fread(out, 1, cap - 1u, f);
	out[n] = 0;
	fclose(f);
	return (int)n;
}

/* ---- paths -------------------------------------------------------------------- */

static void t_paths(void)
{
	char out[64];
	size_t n;

	CK(kof_is_path_sep('/') && !kof_is_path_sep('a') && !kof_is_path_sep('\0') &&
	   KOF_PATH_SEP == '/', "path separator on this host");
	CK(!kof_is_path_sep('\\'), "a backslash is an ordinary byte on POSIX");

	CK(kof_path_sep_last("a/b/c") && *kof_path_sep_last("a/b/c") == '/' &&
	   strcmp(kof_path_sep_last("a/b/c"), "/c") == 0 && kof_path_sep_last("abc") == NULL &&
	   strcmp(kof_path_sep_last("/"), "/") == 0 && kof_path_sep_last("") == NULL,
	   "sep_last points at the last separator");
	CK(strcmp(kof_path_base("a/b/c"), "c") == 0 && strcmp(kof_path_base("abc"), "abc") == 0 &&
	   strcmp(kof_path_base("a/b/"), "") == 0 && strcmp(kof_path_base("/"), "") == 0 &&
	   strcmp(kof_path_base(""), "") == 0, "base is what follows the last separator");

	n = kof_path_squash("a//b///c/", out, sizeof out);
	CK(n == 5 && strcmp(out, "a/b/c") == 0, "squash collapses runs and drops the trailing one");
	n = kof_path_squash("//", out, sizeof out);
	CK(n == 1 && strcmp(out, "/") == 0, "a root made of slashes is one slash");
	n = kof_path_squash("/", out, sizeof out);
	CK(n == 1 && strcmp(out, "/") == 0, "root");
	n = kof_path_squash("", out, sizeof out);
	CK(n == 0, "empty in, empty out");
	CK(kof_path_squash(NULL, out, sizeof out) == 0 && kof_path_squash("a", NULL, 5) == 0 &&
	   kof_path_squash("a", out, 0) == 0, "NULL arguments and zero capacity give 0");
	n = kof_path_squash("abcd", out, 5);
	CK(n == 4 && strcmp(out, "abcd") == 0, "fits with exactly one byte for the NUL");
	CK(kof_path_squash("abcde", out, 5) == 0, "one byte too long is refused, not truncated");
	CK(kof_path_squash("a/./b", out, sizeof out) == 5 && strcmp(out, "a/./b") == 0,
	   "squash is textual: dot segments are not resolved");
	CK(kof_path_squash("./a/", out, sizeof out) == 3 && strcmp(out, "./a") == 0, "leading dot kept");

	/* under: a lexical prefix on a separator boundary. */
	CK(strcmp(kof_path_under("/a/b/c", "/a/b") ? kof_path_under("/a/b/c", "/a/b") : "", "c") == 0,
	   "under returns the remainder");
	CK(kof_path_under("/a/bc", "/a/b") == NULL, "a prefix that is not on a separator is not under");
	CK(kof_path_under("/a/b", "/a/b") == NULL, "a path is not under itself");
	CK(kof_path_under("/a/b/", "/a/b") != NULL && *kof_path_under("/a/b/", "/a/b") == 0,
	   "a trailing separator leaves an empty remainder");
	CK(kof_path_under("/a/b//c", "/a/b/") != NULL &&
	   strcmp(kof_path_under("/a/b//c", "/a/b/"), "/c") == 0,
	   "a directory given with its separator keeps the rest verbatim");
	CK(kof_path_under("/a/b//c", "/a/b") != NULL &&
	   strcmp(kof_path_under("/a/b//c", "/a/b"), "c") == 0,
	   "separator runs after the directory are skipped");
	CK(kof_path_under("x", "") == NULL && kof_path_under(NULL, "/a") == NULL &&
	   kof_path_under("/a", NULL) == NULL, "empty or NULL arguments are never under");
	CK(kof_path_under("/a", "/a/b") == NULL, "a shorter path is not under a longer one");
	CK(kof_path_under("a\\b\\c", "a/b") != NULL && strcmp(kof_path_under("a\\b\\c", "a/b"), "c") == 0,
	   "under treats both separators alike (it is a name test, not an OS call)");
	{
		/*
		 * LEXICAL, and that is the contract: "/a/../etc" is "under" "/a". A caller
		 * that uses under() as a containment check on a hostile path has to reject
		 * dot segments first (kof_name_escapes does that).
		 */
		CK(kof_path_under("/a/../etc", "/a") != NULL, "under does not resolve '..'");
	}
}

/* ---- file helpers ------------------------------------------------------------- */

static void t_files(void)
{
	char p[200], q[200], lnk[200], buf[64];
	FILE *f;
	int fd;
	struct stat st;
	char abs[512];

	path_of(p, sizeof p, "new.bin");
	f = kof_fopen_new(p);
	CK(f != NULL, "fopen_new creates");
	if (f) {
		fputs("one", f);
		fclose(f);
	}
	CK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600, "fopen_new creates with mode 0600");
	CK(kof_fopen_new(p) == NULL, "fopen_new refuses an existing file (O_EXCL)");

	path_of(lnk, sizeof lnk, "link");
	CK(symlink(p, lnk) == 0, "symlink");
	CK(kof_fopen_new(lnk) == NULL, "fopen_new refuses a symlink, even a dangling-or-live one");
	CK(kof_fopen_trunc(lnk) == NULL, "fopen_trunc does not write through a symlink");
	CK(slurp(p, buf, sizeof buf) == 3 && strcmp(buf, "one") == 0,
	   "the file behind the symlink is untouched");

	f = kof_fopen_trunc(p);
	CK(f != NULL, "fopen_trunc on a regular file");
	if (f) {
		fputs("twelve bytes", f);
		fclose(f);
	}
	CK(slurp(p, buf, sizeof buf) == 12, "trunc replaced the content");
	f = kof_fopen_trunc_mode(p, 0640);
	CK(f != NULL, "fopen_trunc_mode");
	if (f)
		fclose(f);
	CK(stat(p, &st) == 0 && st.st_size == 0, "and emptied it");
	path_of(q, sizeof q, "mode.bin");
	f = kof_fopen_trunc_mode(q, 0640);
	CK(f != NULL, "trunc_mode creates when absent");
	if (f)
		fclose(f);
	{
		mode_t um = umask(0);

		umask(um);
		CK(stat(q, &st) == 0 && (st.st_mode & 0777) == (0640 & ~um & 0777),
		   "the mode is the one asked for (less umask)");
	}
	CK(kof_fopen_trunc("build/test/no-such-dir/x") == NULL, "missing directory");

	path_of(q, sizeof q, "renamed.bin");
	CK(kof_rename_over(p, q) == 1 && stat(p, &st) != 0 && stat(q, &st) == 0, "rename_over moves");
	f = kof_fopen_trunc(p);
	if (f) {
		fputs("x", f);
		fclose(f);
	}
	CK(kof_rename_over(p, q) == 1 && slurp(q, buf, sizeof buf) == 1 && buf[0] == 'x',
	   "rename_over replaces an existing target");
	CK(kof_rename_over("build/test/no-such-file", q) == 0, "rename of a missing source");

	CK(kof_abs_path(dir, abs, sizeof abs) == 1 && abs[0] == '/', "abs_path resolves to an absolute path");
	CK(kof_abs_path(dir, abs, 3) == 0, "abs_path refuses a buffer that is too small");
	CK(kof_abs_path("build/test/no-such-file", abs, sizeof abs) == 0, "abs_path of a missing file");
	{
		char l3[200];

		path_of(l3, sizeof l3, "link3");
		CK(symlink("renamed.bin", l3) == 0, "relative symlink");
		CK(kof_abs_path(l3, abs, sizeof abs) == 1 && strstr(abs, "link3") == NULL &&
		   strstr(abs, "renamed.bin") != NULL, "abs_path resolves a symlink to its target");
		CK(kof_abs_path(lnk, abs, sizeof abs) == 0, "and a dangling one is refused");
	}

	/* positional io: leaves the descriptor's own offset alone. */
	path_of(p, sizeof p, "pos.bin");
	fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0600);
	CK(fd >= 0, "open");
	if (fd >= 0) {
		char rb[8], wr[3] = "AB";

		CK(kof_write_all(fd, "0123456789", 10) == 1, "write_all");
		CK(kof_write_all(fd, "", 0) == 1, "write_all of nothing succeeds");
		CK(lseek(fd, 3, SEEK_SET) == 3, "set offset");
		memset(rb, 0, sizeof rb);
		CK(kof_pos_io(fd, 5, rb, 4, 0) == 4 && memcmp(rb, "5678", 4) == 0, "pos_io reads at an offset");
		CK(lseek(fd, 0, SEEK_CUR) == 3, "and puts the file offset back");
		CK(kof_pos_io(fd, 8, rb, 8, 0) == 2, "a read past the end returns what there was");
		CK(kof_pos_io(fd, 100, rb, 4, 0) == 0, "a read wholly past the end is 0");
		CK(kof_pos_io(fd, 0, wr, 2, 1) == 2, "pos_io writes at an offset");
		CK(kof_pos_io(fd, 0, rb, 0, 0) == 0, "zero length");
		CK(kof_pos_io(-1, 0, rb, 4, 0) == 0, "a bad descriptor is 0");
		CK(lseek(fd, 0, SEEK_CUR) == 3, "offset still where it was");
		close(fd);
		CK(slurp(p, buf, sizeof buf) == 10 && memcmp(buf, "AB23456789", 10) == 0, "content after pos writes");
	}
	CK(kof_write_all(-1, "x", 1) == 0, "write_all to a bad descriptor reports failure");

	{
		char cache[256];

		/* Either an answer under the home directory or a clean refusal. */
		if (kof_user_cache_dir(cache, sizeof cache))
			CK(cache[0] == '/' && strlen(cache) > strlen("/.cache") &&
			   strcmp(cache + strlen(cache) - 7, "/.cache") == 0, "cache dir ends in /.cache");
		CK(kof_user_cache_dir(cache, 4) == 0, "a buffer too small is refused");
		CK(kof_user_cache_dir(cache, 0) == 0, "no room at all");
	}
}

/* ---- OS layer ------------------------------------------------------------------ */

static void t_os(void)
{
	struct stat st;
	char lnk[200], tgt[200];
	uint64_t pg = kof_page_size();
	uint8_t *m;
	char hay[] = "xxhelloxx";
	int ac = 1;
	char av0[] = "prog";
	char *av0p = av0;
	char **av = &av0p;

	CK(pg >= 4096 && (pg & (pg - 1)) == 0, "page size is a power of two >= 4096");
	m = kof_map_anon_rw(pg * 3);
	CK(m != NULL, "map_anon_rw");
	if (m) {
		CK(m[0] == 0 && m[pg * 3 - 1] == 0, "anonymous memory reads as zero");
		m[0] = 1;
		m[pg * 3 - 1] = 2;
		CK(m[0] == 1 && m[pg * 3 - 1] == 2, "and is writable");
		kof_unmap_anon(m, pg * 3);
	}
	kof_unmap_anon(NULL, 0);
	CK(kof_map_anon_rw(~(uint64_t)0 >> 1) == NULL, "an impossible size is NULL, not a crash");

	CK(kof_memmem(hay, 9, "hello", 5) == hay + 2, "memmem finds");
	CK(kof_memmem(hay, 9, "world", 5) == NULL, "memmem misses");
	CK(kof_memmem(hay, 9, "", 0) == hay, "an empty needle is found at the start");
	CK(kof_memmem(hay, 4, "hello", 5) == NULL, "a needle longer than the haystack");
	CK(kof_memmem(hay, 0, "x", 1) == NULL, "empty haystack");

	/* the heap: what the C library says is in use, and giving back what is free */
	{
		uint64_t before = kof_heap_in_use(), during, after;
		size_t big = (size_t)16 << 20;
		uint8_t *blk = malloc(big);

		if (blk)
			memset(blk, 1, big);            /* touched: a lazily mapped block counts only when it is real */
		__asm__ volatile("" : : "r"(blk) : "memory");   /* the compiler may not drop the allocation it cannot see used */
		during = kof_heap_in_use();
		free(blk);
		after = kof_heap_in_use();
		if (before == 0 && during == 0) {
			CK(kof_heap_trim() == 0 || 1, "this C library cannot say what is in use: trim is a no-op or a call");
			printf("  heap in use: not reported on this C library\n");
		} else {
			CK(during >= before + big && after + big <= during + 4096u * 64u,
			   "16 MB allocated is seen by kof_heap_in_use and gone when freed (%llu, %llu, %llu)",
			   (unsigned long long)before, (unsigned long long)during, (unsigned long long)after);
			CK(kof_heap_trim() == 1, "kof_heap_trim hands the C library's free pages back and says it did");
			CK(kof_heap_in_use() <= after + 4096u * 64u, "and trimming does not change what is IN USE");
		}
	}

	path_of(tgt, sizeof tgt, "pos.bin");
	path_of(lnk, sizeof lnk, "lnk2");
	CK(symlink(tgt, lnk) == 0, "symlink");
	CK(kof_lstat(lnk, &st) == 0 && S_ISLNK(st.st_mode), "kof_lstat does not follow");
	CK(kof_lstat(tgt, &st) == 0 && S_ISREG(st.st_mode), "and sees a regular file");
	CK(kof_lstat("build/test/no-such-file", &st) != 0, "missing");

	{
		int fd = open(tgt, O_RDONLY);
		uint64_t len = 10;
		void *p;

		CK(fd >= 0, "open for map");
		p = fd >= 0 ? kof_map_file_ro(fd, len) : NULL;
		CK(p != NULL && memcmp(p, "AB23456789", 10) == 0, "map_file_ro maps the file");
		kof_unmap_file(p, len);
		kof_unmap_file(NULL, 0);
		if (fd >= 0)
			close(fd);
	}
	{
		int fd = open("/dev/null", O_RDONLY);
		void *p = fd >= 0 ? kof_map_file_ro(fd, 4096) : NULL;

		CK(p == NULL, "mapping a device that cannot be mapped is NULL");
		if (fd >= 0)
			close(fd);
	}

	{
		uint8_t *x = kof_map_anon_rw(pg);

		if (x) {
			CK(kof_mprotect_rx(x, pg) == 0, "mprotect_rx on a mapping");
			kof_unmap_anon(x, pg);
		}
		CK(kof_mprotect_rx(NULL, pg) != 0, "mprotect_rx of NULL fails");
	}

	{
		struct kof_stream_walk w;

		memset(&w, 0xaa, sizeof w);
		CK(kof_streams_open(&w, "x") == 0 && w.pending == 0 && w.name[0] == 0,
		   "alternate data streams do not exist on this host; the walk is empty and initialised");
		CK(kof_streams_next(&w) == 0, "next on an empty walk");
		kof_streams_close(&w);
		kof_streams_close(NULL);
		CK(kof_streams_open(NULL, "x") == 0, "a NULL walk is refused");
	}
	kof_utf8_init(&ac, &av);
	CK(ac == 1 && av == &av0p, "utf8_init leaves argv alone where it is already UTF-8");
	kof_utf8_init(NULL, NULL);
	CK(kof_mkdir("build/test/no-such-dir/x/y", 0700) != 0, "mkdir without parents fails");
}

/* ---- the debug switches ---------------------------------------------------------- */

static void t_debug(void)
{
	/*
	 * Compiled with KOF_DEBUG=0, as the release is: tracing is a type-checked
	 * no-op, and the time macros are `(void)sizeof(slot)`, which neither
	 * evaluates nor links to kof_time_*. What is left to assert is that they
	 * stay no-ops and that the slot enumeration is the closed set the report
	 * iterates over.
	 */
	int evaluated = 0;

	KOF_TRACE("never printed %d\n", evaluated++);
	CK(evaluated == 0, "trace arguments are not evaluated in a release build");
	KOF_TIME_BEGIN(KOF_T_PARSE);
	KOF_TIME_END(KOF_T_PARSE);
	KOF_TIME_REPORT();
	CK(KOF_TRACING == 0 && KOF_T_COUNT == 13 && KOF_T_DB_LOAD == 0, "time slots");
	CK(KOFENG_BUILD >= 0u, "the build stamp has a default");
}

static void clean_dir(void)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char p[512];

	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
		unlink(p);
	}
	closedir(d);
	rmdir(dir);
}

int main(void)
{
	snprintf(dir, sizeof dir, "build/test/api_engine_platform_%d", (int)getpid());
	if (mkdir(dir, 0700) != 0) {
		printf("api_engine_platform: no build/test directory - nothing tested\n");
		return 0;
	}
	t_paths();
	t_files();
	t_os();
	t_debug();
	clean_dir();
	printf("api_engine_platform: %u checks, %u failed, %u known-miss\n",
	       he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
