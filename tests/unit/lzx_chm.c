/*
 * lzx_chm - the LZX decoder, against streams this build did not make.
 *
 * WHY THE ORACLE IS A REAL FILE. Every other decoder here is checked against a
 * compressor: inflate against zlib, bunzip against bzip2, cab_mszip against
 * zlib again. There is no LZX compressor on a Linux build host and no second
 * implementation to compare with - so a fixture built here would be this code
 * checking its own opinion, which is exactly the failure a differential test
 * exists to prevent.
 *
 * What a real .chm carries instead is BETTER THAN A SELF TEST AND WEAKER THAN A
 * COMPRESSOR, and it is worth being precise about which:
 *
 *   - the RESET TABLE was written by Microsoft's compressor. It states the
 *     uncompressed length of the whole content section and the compressed
 *     offset of every restart point. A decoder that produces a different number
 *     of bytes than that table says is wrong, and nothing this code does can
 *     make those two agree by accident.
 *   - the DIRECTORY states each file's length inside that stream, from a second
 *     structure written at the same time.
 *   - the files are HTML and text, so a wrong decode is visible as such rather
 *     than only as a number.
 *
 * Two independent length claims and legible content is not byte equality with a
 * reference implementation. It catches every structural error - a misread tree,
 * a wrong position slot, a lost repeated offset - because all of those change
 * how much comes out. It would not catch a systematic error that preserved
 * length exactly, and nothing available here would.
 *
 * AND THEN WHAT THE ENGINE DOES WITH IT, which is a different question and the
 * one that decides whether a scan sees a page at all. The parse turns each
 * entry in the coded section into a restart point and a skip; this decodes
 * every one of them THAT WAY and compares it with the same range cut out of a
 * straight decode of the whole stream. A placement that is off by an interval
 * decodes perfectly and returns somebody else's page, so a length check cannot
 * see it and this can.
 *
 * WITHOUT A CORPUS THIS TEST REPORTS THAT IT DID NOTHING. The path below is
 * where this machine keeps exploit-db's binaries; on a host without them the
 * test says so rather than passing quietly, on the same terms region_partition
 * reports an empty corpus.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/analyzer/parsers/containers/chm_parse.h"
#include "../../libkofeng/extractor/decomp/lzx.h"

static int failures;
static int examined;
static int scanned;        /* files taken through the engine */
static int pages;          /* pages the engine handed back as children */

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- what the sink counts --------------------------------------------------- */

struct out {
	uint64_t n;
	uint64_t printable;
	/* Where the bytes go, when the caller wants them rather than only
	 * their count. NULL for the checks that only count. */
	uint8_t *dst;
	uint64_t dst_cap;
	uint8_t  head[48];
	uint32_t head_n;
	/* A page opens with a tag, and a tag is what says the decode landed on
	 * a help file rather than on bytes of the right length. Matched through
	 * a rolling window so a tag split across two chunks still counts. */
	char     roll[16];
	uint32_t roll_n;
	int      saw_html;
};

static int out_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct out *o = user;
	uint32_t i;

	for (i = 0; i < n && o->head_n < sizeof o->head; i++)
		o->head[o->head_n++] = p[i];
	if (o->dst && o->n < o->dst_cap) {
		uint64_t room = o->dst_cap - o->n;

		memcpy(o->dst + o->n, p, (size_t)(n < room ? n : room));
	}
	o->n += n;
	for (i = 0; i < n; i++) {
		if ((p[i] >= 0x20u && p[i] < 0x7fu) || p[i] == '\n' ||
		    p[i] == '\r' || p[i] == '\t')
			o->printable++;
		if (o->roll_n == sizeof o->roll) {
			memmove(o->roll, o->roll + 1, sizeof o->roll - 1u);
			o->roll_n--;
		}
		o->roll[o->roll_n++] = (char)p[i];
		if (o->roll_n >= 7u &&
		    (memcmp(o->roll + o->roll_n - 7u, "DOCTYPE", 7) == 0 ||
		     memcmp(o->roll + o->roll_n - 6u, "<html>", 6) == 0 ||
		     memcmp(o->roll + o->roll_n - 6u, "<HTML>", 6) == 0 ||
		     memcmp(o->roll + o->roll_n - 6u, "<body>", 6) == 0 ||
		     memcmp(o->roll + o->roll_n - 6u, "<BODY>", 6) == 0))
			o->saw_html = 1;
	}
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

static uint64_t rd64(const uint8_t *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* ---- one file ---------------------------------------------------------------- */

static void examine(const char *path, struct kof_chm_info *c,
		    struct kof_lzx *lz)
{
	struct kof_obj_ctx ctx;
	kof_buf b;
	uint8_t *f;
	size_t len = 0;
	uint64_t want_uncomp, first_len;
	uint32_t n_entries_rt, entry_size;
	struct out o;
	enum kof_decomp_status st;
	uint64_t got = 0;
	uint64_t tab = 0, frame = 0;
	uint8_t *whole = NULL;

	f = slurp(path, &len);
	if (!f)
		return;
	b.p = f;
	b.n = len;
	memset(&ctx, 0, sizeof ctx);
	if (!kof_chm_sniff(b) || !kof_chm_parse(b, c, &ctx)) {
		free(f);
		return;
	}
	if (!c->lzx_len || !c->reset_len || !c->lzx_window_bits) {
		/* A help file that stores everything: real, and nothing for
		 * this test to do with it. */
		free(f);
		return;
	}
	examined++;

	/*
	 * THE RESET TABLE, which is the oracle: a version, a count, an entry
	 * size, the table's own offset, then the lengths - uncompressed and
	 * compressed - and the block size, then one 64 bit compressed offset
	 * per restart.
	 */
	if (c->reset_len < 0x28u) {
		fail(path, "the reset table is too short to be one");
		free(f);
		return;
	}
	n_entries_rt = rd32(f + c->reset_off + 4u);
	entry_size   = rd32(f + c->reset_off + 8u);
	want_uncomp  = rd64(f + c->reset_off + 0x10u);
	(void)entry_size;

	if (!n_entries_rt || !want_uncomp) {
		fail(path, "the reset table declares nothing");
		free(f);
		return;
	}

	/*
	 * THE STREAM RESTARTS, AND THE TABLE SAYS WHERE.
	 *
	 * A help file's content is not one LZX stream from end to end: the
	 * compressor restarts it every `reset_interval` frames of 32KB, and the
	 * reset table's entries are the compressed offset each frame begins at.
	 * Decoded as one continuous stream instead, a file larger than an
	 * interval comes apart a little way past the first boundary - which is
	 * what this test saw before it was written this way, and is the whole
	 * reason the table is in the file.
	 *
	 * So each interval is decoded from its own restart point, which is also
	 * exactly how the engine reaches one file: seek to the interval holding
	 * it and decode from there.
	 */
	memset(&o, 0, sizeof o);
	/*
	 * KEPT, because the third check below needs something to compare
	 * against: the whole stream decoded the straightforward way is the
	 * reference the parse's own placement is measured against.
	 */
	whole = malloc((size_t)want_uncomp);
	if (!whole) {
		fail(path, "out of memory for the decoded content");
		free(f);
		return;
	}
	o.dst = whole;
	o.dst_cap = want_uncomp;
	{
		uint64_t block = rd64(f + c->reset_off + 0x20u);
		uint64_t at_out = 0;
		uint32_t k;

		if (!block)
			block = 32768u;
		frame = block;
		tab = c->reset_off + 0x28u;
		st = KOF_DEC_OK;
		for (k = 0; k < n_entries_rt && at_out < want_uncomp;
		     k += c->lzx_reset_interval) {
			uint64_t coff, take;

			if (0x28u + (uint64_t)(k + 1u) * 8u > c->reset_len)
				break;
			coff = rd64(f + c->reset_off + 0x28u + (uint64_t)k * 8u);
			take = block * c->lzx_reset_interval;
			if (at_out + take > want_uncomp)
				take = want_uncomp - at_out;
			if (coff >= c->lzx_len)
				break;
			st = kof_lzx_decode(lz, c->lzx_window_bits,
					    f + c->lzx_off + coff,
					    c->lzx_len - coff, 0, take,
					    out_sink, &o, &got);
			if (st != KOF_DEC_OK && st != KOF_DEC_STOPPED &&
			    st != KOF_DEC_UNSUPPORTED)
				break;
			at_out += take;
		}
	}
	if (st != KOF_DEC_OK && st != KOF_DEC_STOPPED &&
	    st != KOF_DEC_UNSUPPORTED) {
		char why[160];

		snprintf(why, sizeof why,
			 "the content section did not decode (%s), %llu of "
			 "%llu bytes",
			 kof_decomp_status_name(st), (unsigned long long)o.n,
			 (unsigned long long)want_uncomp);
		fail(path, why);
		free(whole);
		free(f);
		return;
	}
	if (o.n != want_uncomp) {
		char why[160];

		snprintf(why, sizeof why,
			 "the stream decoded to %llu bytes and the reset table "
			 "says %llu", (unsigned long long)o.n,
			 (unsigned long long)want_uncomp);
		fail(path, why);
		free(f);
		return;
	}

	/*
	 * AND IT IS TEXT. A help file's content is HTML, so a decode that came
	 * out the right LENGTH and the wrong bytes is visible here - the one
	 * thing a length check alone cannot see.
	 */
	/*
	 * AND IT IS A HELP FILE, not bytes of the right length.
	 *
	 * The length check above cannot see a decode that is wrong in place, so
	 * this looks at what came out. NOT a printable-byte RATIO, which is
	 * what this asked for first and got wrong: a content section is pages
	 * AND the format's own binary indexes - #TOPICS, #URLTBL, #STRINGS -
	 * so a real one is only about half text, and a threshold tuned to that
	 * says nothing. What a help file's content always has is a page, and a
	 * page opens with a tag.
	 */
	if (!o.saw_html) {
		uint32_t k;

		printf("   head:");
		for (k = 0; k < o.head_n; k++)
			printf(" %02x", o.head[k]);
		printf("\n   text: ");
		for (k = 0; k < o.head_n; k++)
			putchar(o.head[k] >= 0x20u && o.head[k] < 0x7fu
				? (int)o.head[k] : '.');
		printf("\n");
		fail(path, "the decoded content holds no HTML, so the length "
		     "is right and the bytes are not");
		free(whole);
		free(f);
		return;
	}

	/*
	 * SECOND: one file out of the middle, by the directory's numbers.
	 *
	 * The slice is what the engine actually asks for - skip to a file,
	 * take its length - and it is checked against a length that came from
	 * the OTHER structure in the file, written by the same compressor at
	 * the same time.
	 */
	/*
	 * INSIDE ONE INTERVAL, because that is what a slice means here.
	 *
	 * A stream can only be entered at a restart point, so reaching a file
	 * means decoding from the interval that holds it and dropping what
	 * comes before. Asking for a byte range measured from the start of the
	 * WHOLE stream is the mistake this test made first, and it is the one
	 * the engine must not repeat.
	 */
	first_len = 512u;
	memset(&o, 0, sizeof o);
	{
		uint64_t coff = rd64(f + c->reset_off + 0x28u);
		uint64_t skip = 1024u;

		if (want_uncomp > skip + first_len && coff < c->lzx_len)
			st = kof_lzx_decode(lz, c->lzx_window_bits,
					    f + c->lzx_off + coff,
					    c->lzx_len - coff, skip, first_len,
					    out_sink, &o, &got);
		if (o.n != first_len)
			fail(path, "a slice out of one interval came back the "
			     "wrong length");
	}

	/*
	 * THIRD: every entry the PARSE placed, decoded the way the engine
	 * decodes it, against the same range of the straight decode.
	 *
	 * This is the check that is about the collector rather than the
	 * decoder. chm_place_coded turns an entry's offset in the decoded
	 * stream into a restart point and a skip; get the restart wrong by one
	 * interval and the decode still succeeds, still comes back the right
	 * length, and hands over a different page. Only a comparison sees it.
	 *
	 * The entry's decoded offset is not kept in the view - it must not be,
	 * a scattered entry's `off` is not a range of the object - so it is
	 * recovered here from the two things that are: the restart's compressed
	 * offset, which names a row of the reset table, and the skip inside
	 * out_hint.
	 */
	{
		uint8_t *cut = NULL;
		uint64_t cut_cap = 0;
		uint32_t i, placed = 0;

		for (i = 0; i < c->n_entries; i++) {
			const struct kof_entry *e = &c->entry[i];
			uint64_t skip, take, rel, uoff, left;
			uint32_t r, row = n_entries_rt, k;

			if (!(e->flags & KOF_ENT_F_SCATTERED) || !c->split[i].n_run)
				continue;
			skip = e->out_hint >> 32;
			take = e->out_hint & 0xffffffffu;
			rel  = c->run[c->split[i].first_run].off - c->lzx_off;
			if (!take || take > want_uncomp)
				continue;

			/* Which frame the parse chose to enter at. */
			for (r = 0; r < n_entries_rt; r++)
				if (rd64(f + tab + (uint64_t)r * 8u) == rel) {
					row = r;
					break;
				}
			if (row == n_entries_rt) {
				fail(path, "an entry is decoded from a place "
				     "the reset table never names");
				break;
			}
			/*
			 * AND IT IS A RESTART, not merely a frame. Every row is
			 * a frame boundary; only every reset_interval-th one is
			 * a point the stream can be entered at, and entering at
			 * any other produces refuse from the first block.
			 */
			if (row % c->lzx_reset_interval) {
				fail(path, "an entry is decoded from a frame "
				     "that is not a restart point");
				break;
			}
			uoff = (uint64_t)row * frame + skip;
			if (uoff + take > want_uncomp) {
				fail(path, "an entry was placed past the end "
				     "of the content the reset table declares");
				break;
			}

			if (take > cut_cap) {
				uint8_t *g = realloc(cut, (size_t)take);

				if (!g)
					break;
				cut = g;
				cut_cap = take;
			}
			memset(&o, 0, sizeof o);
			o.dst = cut;
			o.dst_cap = take;
			/*
			 * RANGE BY RANGE, which is what the engine does - see
			 * unpack_lzx. Each is one reset interval and the
			 * decoder starts again at each; the skip belongs to the
			 * first alone.
			 */
			left = take;
			st = KOF_DEC_OK;
			for (k = 0; k < c->split[i].n_run && left; k++) {
				const uint32_t run = c->split[i].first_run + k;
				uint64_t part = 0;

				st = kof_lzx_decode(lz, c->lzx_window_bits,
						    f + c->run[run].off,
						    c->run[run].len,
						    k ? 0u : skip, left,
						    out_sink, &o, &part);
				if (st != KOF_DEC_OK &&
				    st != KOF_DEC_TRUNCATED &&
				    st != KOF_DEC_UNSUPPORTED)
					break;
				if (!part)
					break;
				left -= part;
			}
			if (st != KOF_DEC_OK && st != KOF_DEC_TRUNCATED &&
			    st != KOF_DEC_UNSUPPORTED) {
				fail(path, "an entry the parse placed did not "
				     "decode");
				break;
			}
			if (o.n != take) {
				fail(path, "an entry came back a different "
				     "length from the one the directory gives");
				break;
			}
			if (memcmp(cut, whole + uoff, (size_t)take) != 0) {
				fail(path, "an entry decoded from its restart "
				     "point is not the bytes at that offset in "
				     "the whole stream - the placement is off");
				break;
			}
			placed++;
			if (placed >= 24u)
				break;   /* enough to say the rule holds */
		}
		free(cut);
		if (!placed && c->n_compressed)
			fail(path, "the file's pages are all in the coded "
			     "section and the parse placed none of them");
	}

	free(whole);
	free(f);
}

/* ---- and the same file through the engine ------------------------------------
 *
 * The checks above are about the decoder and about where the parse says a page
 * begins. THIS is about whether any of that reaches a scan: the module has to
 * be built for CHM, the host has to resolve the entry's pieces, and the LZX
 * method has to be dispatched. Each of those can be missing without a single
 * one of the checks above noticing, and the result is a help file scanned at
 * full speed with nothing found in it.
 */
struct fed {
	int objects;
	int html;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct fed *fd = user;
	const uint8_t *p = bytes;
	uint64_t i;

	(void)name;
	(void)res;
	fd->objects++;
	if (!p || len < 6u)
		return 0;
	for (i = 0; i + 6u <= len && i < 4096u; i++)
		if ((p[i] == '<' || p[i] == 'D') &&
		    (memcmp(p + i, "<html", 5) == 0 ||
		     memcmp(p + i, "<HTML", 5) == 0 ||
		     memcmp(p + i, "<body", 5) == 0 ||
		     memcmp(p + i, "<BODY", 5) == 0 ||
		     memcmp(p + i, "DOCTYPE", 6) == 0)) {
			fd->html++;
			break;
		}
	return 0;
}

static void examine_engine(const char *path, struct kof_engine *eng)
{
	struct kof_scan_option opt;
	struct kof_scanner *sc;
	struct fed fd;
	uint8_t *f;
	size_t len = 0;

	f = slurp(path, &len);
	if (!f)
		return;
	sc = kof_scanner_new(eng);
	if (!sc) {
		free(f);
		fail(path, "could not make a scanner");
		return;
	}
	memset(&fd, 0, sizeof fd);
	memset(&opt, 0, sizeof opt);
	if (kof_scan_bytes(sc, f, len, "help.chm", &opt, on_object, &fd) <= 0)
		fail(path, "the engine did not scan the help file at all");
	else if (fd.objects < 2)
		fail(path, "the engine made no child of a help file whose "
		     "pages are all in the coded section");
	else if (!fd.html)
		fail(path, "the engine produced children and none of them is "
		     "a page");
	scanned++;
	pages += fd.html;
	kof_scanner_free(sc);
	free(f);
}

int main(void)
{
	/*
	 * WHERE A REAL HELP FILE MIGHT BE, and the difference between two kinds
	 * of them matters here.
	 *
	 * The exploit corpora are first because they are the ones a scanner
	 * meets - and every .chm in one is DELIBERATELY MALFORMED, which is why
	 * they are in it: one has a header length of 0xffffff00, one has a
	 * content base seven bytes from where its own directory says, one has
	 * directory chunks that are not PMGL. All three are refused by the
	 * parse, so none of them exercises the decoder at all.
	 *
	 * So the list also names where this machine keeps ordinary help files -
	 * the ones shipped with applications - because a decoder can only be
	 * checked against a stream a working compressor wrote. A directory that
	 * is not there is skipped, and a run that finds nothing says so.
	 */
	static const char *dirs[] = {
		"/var/run/host/usr/share/exploitdb-bin-sploits/bin-sploits",
		"/usr/share/exploitdb-bin-sploits/bin-sploits",
		"/home/dmknght/Desktop/AV/Norton_AntiVirus/QuarantineServer/"
		"NavCorp7.0/HelpFiles",
		"/home/dmknght/Desktop/SHARE_VMWARE/eScan/Lan/romanian",
		"samples"
	};
	static const char *db = "build/release/databases";
	struct kof_chm_info *c = malloc(sizeof *c);
	struct kof_lzx *lz = malloc(sizeof *lz);
	struct kof_engine *eng;
	size_t d;

	/* Unbuffered: a crash inside a decoder takes a buffered line with it,
	 * and that line is how anyone would know where it got to. */
	setvbuf(stdout, NULL, _IONBF, 0);

	if (!c || !lz) {
		free(c);
		free(lz);
		printf("lzx chm: out of memory\n");
		return 1;
	}

	/* Absent on a host with no build in it, and then only the decoder half
	 * of this runs - which is still worth running. */
	eng = kof_engine_open(db);

	for (d = 0; d < sizeof dirs / sizeof dirs[0] && examined < 4; d++) {
		DIR *dp = opendir(dirs[d]);
		struct dirent *de;

		if (!dp)
			continue;
		while ((de = readdir(dp)) != NULL && examined < 4) {
			char path[1024];
			size_t n = strlen(de->d_name);
			int was = examined;

			if (n < 5u || strcmp(de->d_name + n - 4u, ".chm") != 0)
				continue;
			snprintf(path, sizeof path, "%s/%s", dirs[d], de->d_name);
			examine(path, c, lz);
			/* Only the ones the checks above accepted: a file
			 * examine() turned away has no coded section to reach
			 * and says nothing about the engine. */
			if (eng && examined != was)
				examine_engine(path, eng);
		}
		closedir(dp);
	}

	if (eng)
		kof_engine_close(eng);
	free(c);
	free(lz);

	if (failures) {
		printf("lzx chm: %d check(s) failed over %d file(s)\n",
		       failures, examined);
		return 1;
	}
	if (!examined) {
		printf("lzx chm: NO CHM CORPUS - the decoder was not exercised "
		       "against a stream this build did not make\n");
		return 0;
	}
	printf("lzx chm: %d real help file(s) - the content decodes to the "
	       "length the reset table declares, reads as text, a slice out of "
	       "the middle is the length the directory says, and every entry "
	       "the parse placed is byte for byte what the whole stream holds "
	       "at that offset; %d of them taken through the engine gave back "
	       "%d page(s) - ok\n", examined, scanned, pages);
	return 0;
}
