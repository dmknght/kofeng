/*
 * lzx_cab - LZX as a CABINET uses it, against cabinets this build did not make.
 *
 * WHY THIS IS SEPARATE FROM lzx_chm, which already exercises the same decoder.
 * The two containers hand it the same coding in two different shapes, and the
 * shapes are what is under test here:
 *
 *   - a help file RESTARTS the stream every few frames and says where, so its
 *     pieces are separate streams;
 *   - a cabinet compresses a whole folder as ONE stream and then cuts it into
 *     blocks with a header between them, so its pieces are one stream and have
 *     to be joined back together.
 *
 * Running either one the other way decodes the first piece and produces refuse
 * from the second - a failure that looks like a corrupt archive rather than
 * like a bug here, which is why it gets its own test.
 *
 * AND THE ORACLE IS BETTER THAN THE HELP FILE'S. A cabinet carries executables,
 * and a PE CARRIES A CHECKSUM OF ITSELF - a sixteen bit sum over every byte of
 * the file, written by the linker. It is not a length claim and not a
 * plausibility check: one byte wrong anywhere in the file and it does not
 * match. That makes it the only place in this tree where LZX output is checked
 * byte for byte against something an independent implementation produced.
 *
 * It is also the only check that can see E8 TRANSLATION. A cabinet's folders
 * are compressed with x86 call targets rewritten, and undoing that wrongly
 * changes four bytes after each 0xE8 - a handful per frame, in a file that
 * otherwise decodes perfectly and is the right length. Nothing else here would
 * notice.
 *
 * WITHOUT A CORPUS THIS TEST REPORTS THAT IT DID NOTHING, on the same terms
 * lzx_chm does.
 */

/* _DEFAULT_SOURCE and not _POSIX_C_SOURCE: the walk below needs d_type, which
 * is not in POSIX, and a case-insensitive compare, which is not either. Both
 * are here because a cabinet is a Windows artefact and its name is as likely to
 * be .CAB as .cab. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofparsers/containers/cab_parse.h"
#include "../../libkofeng/kofdecomp/lzx.h"

static int failures;
static int cabinets;       /* cabinets with an LZX folder */
static int files;          /* files decoded out of them */
static int checksummed;    /* of those, PEs whose own checksum agreed */

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- the sink ---------------------------------------------------------------- */

struct out {
	uint8_t *dst;
	uint64_t cap, n;
};

static int out_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct out *o = user;

	if (o->n < o->cap) {
		uint64_t room = o->cap - o->n;

		memcpy(o->dst + o->n, p, (size_t)(n < room ? n : room));
	}
	o->n += n;
	return 1;
}

static uint8_t *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p;
	long n;

	*len = 0;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	p = malloc((size_t)n);
	if (!p) {
		fclose(f);
		return NULL;
	}
	if (fread(p, 1u, (size_t)n, f) != (size_t)n) {
		free(p);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return p;
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- the oracle -------------------------------------------------------------- */

/*
 * THE CHECKSUM A LINKER WROTE INTO A PE, recomputed.
 *
 * A sixteen bit one's complement sum over the whole file with the checksum
 * field itself read as zero, plus the file's length. Every byte is in it, so it
 * is an equality test against bytes this build never saw.
 *
 * Zero means the linker did not write one - common for an application and
 * required for a driver - and such a file is skipped rather than failed.
 */
static uint32_t pe_checksum(const uint8_t *d, uint64_t n, uint64_t at)
{
	uint64_t sum = 0, i;

	for (i = 0; i + 1u < n; i += 2u) {
		uint32_t w = (uint32_t)d[i] | ((uint32_t)d[i + 1u] << 8);

		if (i == at || i == at + 2u)
			w = 0;
		sum += w;
		sum = (sum & 0xffffu) + (sum >> 16);
	}
	if (n & 1u) {
		sum += d[n - 1u];
		sum = (sum & 0xffffu) + (sum >> 16);
	}
	sum = (sum & 0xffffu) + (sum >> 16);
	return (uint32_t)sum + (uint32_t)n;
}

/* Where the checksum field is, or zero when this is not a PE that has one. */
static uint64_t pe_checksum_at(const uint8_t *d, uint64_t n)
{
	uint64_t nt;

	if (n < 0x40u || d[0] != 'M' || d[1] != 'Z')
		return 0;
	nt = rd32(d + 0x3c);
	/* The optional header begins 24 bytes into the NT headers and the
	 * checksum is 64 bytes into that. */
	if (nt < 0x40u || nt + 0x5cu > n)
		return 0;
	if (memcmp(d + nt, "PE\0\0", 4) != 0)
		return 0;
	return nt + 0x58u;
}

/* ---- one cabinet ------------------------------------------------------------- */

static void examine(const char *path, struct kof_cab_info *c,
		    struct kof_lzx *lz)
{
	struct kof_obj_ctx ctx;
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	kof_buf b;
	uint8_t *f, *in = NULL, *outbuf = NULL;
	size_t len = 0;
	uint64_t in_cap = 0, out_cap = 0;
	uint32_t i, done = 0;
	int any_lzx = 0;

	f = slurp(path, &len);
	if (!f)
		return;
	b.p = f;
	b.n = len;
	memset(&ctx, 0, sizeof ctx);
	if (!kof_cab_sniff(b) || !kof_cab_parse(b, c, &ctx)) {
		free(f);
		return;
	}
	for (i = 0; i < c->n_folders; i++)
		if (c->folder[i].compress == KOF_CAB_C_LZX)
			any_lzx = 1;
	if (!any_lzx) {
		free(f);
		return;
	}
	cabinets++;

	for (i = 0; i < c->n_entries && done < 8u; i++) {
		const struct kof_entry *e = &c->entry[i];
		uint64_t skip, take, total = 0, at = 0, got = 0;
		uint32_t n, k, bits;
		struct out o;
		enum kof_decomp_status st;

		if (!KOF_UNP_IS_LZX(e->coding[0]))
			continue;
		bits = (uint32_t)e->coding[0] - (uint32_t)KOF_UNP_LZX_BASE;
		skip = e->out_hint >> 32;
		take = e->out_hint & 0xffffffffu;
		if (!take || take > (64u << 20))
			continue;

		n = ctx.resolve_entry(&ctx, e->index, ext, KOF_SCAN_MAX_EXTENTS);
		if (!n)
			continue;
		for (k = 0; k < n; k++)
			total += ext[k].len;
		if (!total || total > (64u << 20))
			continue;

		/*
		 * THE PIECES ARE ONE STREAM - joined, which is exactly what the
		 * engine does for a cabinet and the opposite of what it does
		 * for a help file.
		 */
		if (total > in_cap) {
			uint8_t *g = realloc(in, (size_t)total);

			if (!g)
				break;
			in = g;
			in_cap = total;
		}
		for (k = 0; k < n; k++) {
			memcpy(in + at, f + ext[k].off, (size_t)ext[k].len);
			at += ext[k].len;
		}
		if (take > out_cap) {
			uint8_t *g = realloc(outbuf, (size_t)take);

			if (!g)
				break;
			outbuf = g;
			out_cap = take;
		}
		memset(&o, 0, sizeof o);
		o.dst = outbuf;
		o.cap = take;
		st = kof_lzx_decode(lz, bits, in, at, skip, take, out_sink, &o,
				    &got);
		if (st != KOF_DEC_OK && st != KOF_DEC_TRUNCATED) {
			fail(path, "an LZX folder did not decode");
			break;
		}
		if (o.n != take) {
			char why[160];

			snprintf(why, sizeof why,
				 "a file came back %llu bytes and the "
				 "directory says %llu",
				 (unsigned long long)o.n,
				 (unsigned long long)take);
			fail(path, why);
			break;
		}
		files++;
		done++;

		{
			uint64_t cs_at = pe_checksum_at(outbuf, take);
			uint32_t want;

			if (!cs_at)
				continue;
			want = rd32(outbuf + cs_at);
			if (!want)
				continue;   /* the linker wrote none */
			if (pe_checksum(outbuf, take, cs_at) != want) {
				fail(path, "a PE out of an LZX folder does not "
				     "match its own checksum - the bytes are "
				     "not the ones that went in");
				break;
			}
			checksummed++;
		}
	}

	free(in);
	free(outbuf);
	free(f);
}

/* ---- and through the engine --------------------------------------------------- */

struct fed {
	int objects;
	int pe;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct fed *fd = user;
	const uint8_t *p = bytes;

	(void)name;
	(void)res;
	fd->objects++;
	if (p && len > 2u && p[0] == 'M' && p[1] == 'Z')
		fd->pe++;
	return 0;
}

static int engine_pass(const char *path, struct kof_engine *eng)
{
	struct kof_scan_option opt;
	struct kof_scanner *sc;
	struct fed fd;
	uint8_t *f;
	size_t len = 0;
	int got;

	f = slurp(path, &len);
	if (!f)
		return 0;
	sc = kof_scanner_new(eng);
	if (!sc) {
		free(f);
		return 0;
	}
	memset(&fd, 0, sizeof fd);
	memset(&opt, 0, sizeof opt);
	if (kof_scan_bytes(sc, f, len, "cabinet.cab", &opt, on_object, &fd) <= 0)
		fail(path, "the engine did not scan the cabinet at all");
	else if (fd.objects < 2)
		fail(path, "the engine made no child of a cabinet whose files "
		     "are all in LZX folders");
	got = fd.objects - 1;
	kof_scanner_free(sc);
	free(f);
	return got;
}

/* ---- walking a corpus ---------------------------------------------------------- */

static void walk(const char *dir, struct kof_cab_info *c, struct kof_lzx *lz,
		 struct kof_engine *eng, int depth, int *children)
{
	DIR *dp = opendir(dir);
	struct dirent *de;

	if (!dp)
		return;
	while ((de = readdir(dp)) != NULL && cabinets < 6) {
		char path[2048];
		size_t n = strlen(de->d_name);

		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
		{
			struct stat st;

			if (stat(path, &st) != 0)
				continue;
			if (S_ISDIR(st.st_mode)) {
				if (depth > 0)
					walk(path, c, lz, eng, depth - 1,
					     children);
				continue;
			}
		}
		if (n < 5u)
			continue;
		if (strcasecmp(de->d_name + n - 4u, ".cab") != 0)
			continue;
		{
			int was = cabinets;

			examine(path, c, lz);
			if (eng && cabinets != was)
				*children += engine_pass(path, eng);
		}
	}
	closedir(dp);
}

int main(void)
{
	/*
	 * WHERE A CABINET WITH AN LZX FOLDER MIGHT BE. Installers, which is
	 * what a cabinet is for - the exploit corpora carry cabinets too, but
	 * the ones in them are small and stored, so they exercise the join and
	 * not the coding.
	 */
	static const char *dirs[] = {
		"/home/dmknght/Desktop/AV/Norton_AntiVirus/Consumer",
		"/home/dmknght/Desktop/AV/pcAnywhere",
		"/var/run/host/usr/share/exploitdb-bin-sploits/bin-sploits",
		"/usr/share/exploitdb-bin-sploits/bin-sploits",
		"samples"
	};
	static const char *db = "build/release/databases";
	struct kof_cab_info *c = malloc(sizeof *c);
	struct kof_lzx *lz = malloc(sizeof *lz);
	struct kof_engine *eng;
	int children = 0;
	size_t d;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!c || !lz) {
		free(c);
		free(lz);
		printf("lzx cab: out of memory\n");
		return 1;
	}
	eng = kof_engine_open(db);

	for (d = 0; d < sizeof dirs / sizeof dirs[0] && cabinets < 6; d++)
		walk(dirs[d], c, lz, eng, 6, &children);

	if (eng)
		kof_engine_close(eng);
	free(c);
	free(lz);

	if (failures) {
		printf("lzx cab: %d check(s) failed over %d cabinet(s)\n",
		       failures, cabinets);
		return 1;
	}
	if (!cabinets) {
		printf("lzx cab: NO LZX CABINET - the joined shape was not "
		       "exercised against a stream this build did not make\n");
		return 0;
	}
	printf("lzx cab: %d cabinet(s) with LZX folders - %d file(s) decoded "
	       "to the length the directory gives, %d of them are PEs that "
	       "match their own checksum byte for byte; the engine opened %d "
	       "child(ren) of them - ok\n",
	       cabinets, files, checksummed, children);
	return 0;
}
