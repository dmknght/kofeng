/*
 * lzhuf_arj - LHA's and ARJ's shared coding, against an archive this build did
 * not make.
 *
 * WHY THE ORACLE IS THE ARCHIVE'S OWN CHECKSUM. There is no ARJ and no LHA on a
 * Linux build host, so a fixture built here would be this code checking its own
 * opinion. What an ARJ file carries instead is better than that and as strong
 * as a reference implementation: EVERY LOCAL HEADER HOLDS A CRC-32 OF THE
 * ORIGINAL FILE, written by the compressor. One byte wrong anywhere in the
 * decoded output and it does not match.
 *
 * So this walks the archive's headers ITSELF - a second, independent reader in
 * thirty lines - takes the CRC and the original size from there, and checks
 * both against what the engine's parse and decoder produce. The point of doing
 * the walk twice is that the oracle must not come from the thing under test.
 *
 * WHAT THIS ALSO COVERS FOR LHA, and what it does not. The coding is one
 * decoder and the variants differ in three numbers - a dictionary size, how
 * many position buckets, and the width of one length count. This exercises the
 * ARJ set of them end to end. The LHA sets are the same code with a different
 * row of that table, and no .lzh on this machine exercises them; that is stated
 * here rather than left to be assumed from a passing test.
 *
 * WITHOUT THE ARCHIVE THIS TEST REPORTS THAT IT DID NOTHING, on the same terms
 * lzx_chm does.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofparsers/containers/arj_parse.h"
#include "../../libkofeng/kofdecomp/lzhuf.h"

static int failures;
static int checked;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- CRC-32, the one an ARJ header carries ----------------------------------- */

static uint32_t crc32_of(const uint8_t *p, uint64_t n)
{
	static uint32_t tab[256];
	static int built;
	uint32_t c = 0xffffffffu;
	uint64_t i;

	if (!built) {
		uint32_t k, j;

		for (k = 0; k < 256u; k++) {
			uint32_t v = k;

			for (j = 0; j < 8u; j++)
				v = (v & 1u) ? 0xedb88320u ^ (v >> 1) : v >> 1;
			tab[k] = v;
		}
		built = 1;
	}
	for (i = 0; i < n; i++)
		c = tab[(c ^ p[i]) & 0xffu] ^ (c >> 8);
	return c ^ 0xffffffffu;
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
	if (!p || fread(p, 1u, (size_t)n, f) != (size_t)n) {
		free(p);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return p;
}

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const uint8_t *p)
{
	return rd16(p) | (rd16(p + 2) << 16);
}

/*
 * THE INDEPENDENT WALK, which is the oracle and nothing else.
 *
 * "\x60\xea", a header size, then a fixed part whose first byte says how long
 * it is; the method is at +5, the sizes and the CRC at +12, +16 and +20, and
 * the name follows the fixed part. Extended headers come after, each a length
 * and four bytes of its own checksum, ending with a zero length.
 */
struct row {
	char     name[128];
	uint64_t body, csize, osize;
	uint32_t crc, method;
};

static uint32_t oracle(const uint8_t *f, uint64_t n, struct row *out,
		       uint32_t max_out)
{
	uint64_t at = 0;
	uint32_t got = 0;

	while (at + 4u < n && got < max_out) {
		uint32_t hsize, first, method, ftype;
		uint64_t base, i;

		if (f[at] != 0x60u || f[at + 1u] != 0xeau)
			break;
		hsize = rd16(f + at + 2u);
		if (!hsize)
			break;                 /* the end marker */
		base = at + 4u;
		if (base + hsize > n)
			break;
		first  = f[base];
		method = f[base + 5u];
		ftype  = f[base + 6u];
		at = base + hsize + 4u;        /* past the header's own CRC */
		while (at + 2u <= n) {
			uint32_t ext = rd16(f + at);

			at += 2u;
			if (!ext)
				break;
			at += (uint64_t)ext + 4u;
		}
		if (at > n)
			break;
		if (ftype == 2u)
			continue;              /* a volume label has no body */
		out[got].csize  = rd32(f + base + 12u);
		out[got].osize  = rd32(f + base + 16u);
		out[got].crc    = rd32(f + base + 20u);
		out[got].method = method;
		out[got].body   = at;
		out[got].name[0] = 0;
		for (i = 0; i + 1u < sizeof out[got].name; i++) {
			uint64_t k = base + first + i;

			if (k >= n || !f[k])
				break;
			out[got].name[i] = (char)f[k];
			out[got].name[i + 1u] = 0;
		}
		at += out[got].csize;
		if (at > n)
			break;
		if (ftype == 3u)
			continue;              /* a directory */
		got++;
	}
	return got;
}

/* ---- and through the engine --------------------------------------------------- */

struct fed {
	int objects;
	int matched;
};

struct want {
	const struct row *rows;
	uint32_t n;
};

static struct want g_want;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct fed *fd = user;
	uint32_t i;

	(void)name;
	(void)res;
	fd->objects++;
	if (!bytes)
		return 0;
	for (i = 0; i < g_want.n; i++)
		if (g_want.rows[i].osize == len &&
		    g_want.rows[i].crc == crc32_of(bytes, len)) {
			fd->matched++;
			break;
		}
	return 0;
}

int main(void)
{
	static const char *paths[] = {
		"/home/dmknght/Desktop/AV/Norton_AntiVirus/avis/trunk/source/"
		"src/avis100/pm/typemanager/test/test.arj",
		"samples/test.arj"
	};
	static const char *db = "build/release/databases";
	struct kof_arj_info *a = NULL;
	struct kof_lzhuf *lz = NULL;
	struct kof_obj_ctx ctx;
	struct row *rows = NULL;
	uint8_t *f = NULL, *outbuf = NULL;
	size_t len = 0;
	uint64_t out_cap = 0;
	uint32_t nrows = 0, i, coded = 0;
	kof_buf b;
	size_t p;

	setvbuf(stdout, NULL, _IONBF, 0);
	for (p = 0; p < sizeof paths / sizeof paths[0] && !f; p++)
		f = slurp(paths[p], &len);
	if (!f) {
		printf("lzhuf arj: NO ARJ ARCHIVE - the coding was not "
		       "exercised against a stream this build did not make\n");
		return 0;
	}

	a = malloc(sizeof *a);
	lz = malloc(sizeof *lz);
	rows = malloc(sizeof *rows * 256u);
	if (!a || !lz || !rows) {
		free(a); free(lz); free(rows); free(f);
		printf("lzhuf arj: out of memory\n");
		return 1;
	}

	b.p = f;
	b.n = len;
	nrows = oracle(f, len, rows, 256u);
	if (!nrows) {
		fail("oracle", "the archive's own headers did not walk");
		goto done;
	}

	memset(&ctx, 0, sizeof ctx);
	if (!kof_arj_sniff(b) || !kof_arj_parse(b, a, &ctx)) {
		fail("parse", "the archive would not parse");
		goto done;
	}

	/*
	 * FIRST: every coded entry the parse offered, decoded and checked
	 * against the CRC the archive states for it.
	 */
	for (i = 0; i < a->n_entries; i++) {
		const struct kof_entry *e = &a->entry[i];
		struct out o;
		enum kof_decomp_status st;
		uint64_t got = 0;
		uint32_t k, row = nrows;

		if (!e->coding[0])
			continue;
		coded++;
		if (e->coding[0] != KOF_UNP_LZHUF_ARJ) {
			fail("entry", "a coded entry names a coding ARJ does "
			     "not use");
			break;
		}
		/* Which row of the independent walk this is - matched on where
		 * its bytes are, which both readers worked out separately. */
		for (k = 0; k < nrows; k++)
			if (rows[k].body == e->off && rows[k].csize == e->len) {
				row = k;
				break;
			}
		if (row == nrows) {
			fail("entry", "an entry points somewhere the archive's "
			     "own headers do not");
			break;
		}
		if (e->out_hint != rows[row].osize) {
			fail("entry", "an entry declares a different original "
			     "size from the one in its header");
			break;
		}
		if (rows[row].osize > (32u << 20))
			continue;

		if (rows[row].osize > out_cap) {
			uint8_t *g = realloc(outbuf, (size_t)rows[row].osize);

			if (!g)
				break;
			outbuf = g;
			out_cap = rows[row].osize;
		}
		memset(&o, 0, sizeof o);
		o.dst = outbuf;
		o.cap = rows[row].osize;
		st = kof_lzhuf_decode(lz, KOF_LZHUF_ARJ, f + e->off, e->len,
				      rows[row].osize, out_sink, &o, &got);
		if (st != KOF_DEC_OK) {
			fail(rows[row].name, "the file did not decode");
			break;
		}
		if (o.n != rows[row].osize) {
			fail(rows[row].name, "the file came back a different "
			     "length from the one its header gives");
			break;
		}
		if (crc32_of(outbuf, o.n) != rows[row].crc) {
			fail(rows[row].name, "the file decoded to the right "
			     "length and the wrong bytes - its own CRC-32 "
			     "does not match");
			break;
		}
		checked++;
	}
	if (!coded)
		fail("entries", "the archive's files are all compressed and "
		     "the parse offered none of them");

	/*
	 * SECOND: the same archive through the engine, which is what decides
	 * whether any of it reaches a scan. A child is accepted only when its
	 * bytes hash to a CRC the archive declares.
	 */
	if (!failures) {
		struct kof_engine *eng = kof_engine_open(db);

		if (eng) {
			struct kof_scanner *sc = kof_scanner_new(eng);
			struct fed fd;
			struct kof_scan_option opt;

			g_want.rows = rows;
			g_want.n = nrows;
			memset(&fd, 0, sizeof fd);
			memset(&opt, 0, sizeof opt);
			if (sc) {
				if (kof_scan_bytes(sc, f, len, "test.arj", &opt,
						   on_object, &fd) <= 0)
					fail("engine", "the archive was not "
					     "scanned at all");
				else if (fd.matched < 1)
					fail("engine", "the engine produced no "
					     "child whose bytes the archive's "
					     "own checksums recognise");
				kof_scanner_free(sc);
			}
			printf("       engine: %d object(s), %d child(ren) "
			       "matched a declared CRC\n", fd.objects,
			       fd.matched);
			kof_engine_close(eng);
		}
	}

done:
	free(outbuf);
	free(rows);
	free(lz);
	free(a);
	free(f);

	if (failures) {
		printf("lzhuf arj: %d check(s) failed\n", failures);
		return 1;
	}
	printf("lzhuf arj: %d compressed file(s) decode to the length and the "
	       "CRC-32 the archive declares for each - ok (LHA's variants are "
	       "the same code with another row of constants and have no "
	       "corpus here)\n", checked);
	return 0;
}
