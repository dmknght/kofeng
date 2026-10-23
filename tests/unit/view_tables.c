/*
 * view_tables - the zip and pdf views are tables the size of the FILE, and what bounds them is
 * the file and the ledger, never a count the file states.
 *
 * WHAT THIS GUARDS. The views carried fixed arrays - 4096 entries, 4096 objects, 1024 stream
 * rows, 16384 runs - and the scan resolved a region into a buffer of 4096 ranges. Two thousand
 * and a hundred members were enough to lose all of a zip's, and a PDF padded past its 4096th
 * object lost whatever came after. A cap that deletes evidence is the defect CLAUDE.md rule 4
 * names; the tables now follow the structure and the caps that are left are bounds on COST:
 * what the file can physically hold (its length over the smallest record) and the per-object
 * ledger. This file asserts the three things that change with that:
 *
 *   WHOLE     a zip of 2100 ... 65535 entries and a pdf of 4200 ... 20000 objects parse to every
 *             row, the regions still partition the file byte for byte (no byte in two regions,
 *             none in none), and the names region - two extents an entry - comes back whole.
 *   BOUNDED   a hostile file allocates a stated multiple of its own length (QUALITY_AUDIT I.B:
 *             "does not allocate more than a stated multiple of N"), whatever it claims:
 *             a count of 65535 with three records, ZIP64 claiming 2^40, an end record in its
 *             own comment sixty-five thousand times, entries that point at themselves or all at
 *             one blob, objects that reference each other in a ring, an object number defined
 *             twenty thousand times, a /Size of four billion. And the work is linear: the
 *             passes that looked an object up by number are indexed, so 20000 objects cost
 *             ten times 2000 and not a hundred.
 *   REPORTED  when the ledger cannot afford a table the parse stops and the format's own "full"
 *             bit is raised - never fewer rows with nothing said. An allocation sweep (every
 *             allocation of a parse, and of a whole scan, refused in turn) proves it: a refused
 *             allocation is either survived to the same answer or it is SAID.
 *
 * The engine half (a database from this tree): the same archives through a scanner, the
 * overlapping-entry bomb that the window bound stops and reports, and the big archives'
 * children counted.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "failalloc.h"
#include "asking_db.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/pdf_parse.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* The stated multiple: a table is at most this many times the bytes of the file that made it,
 * plus a floor for the file too small to say. See the note in QUALITY_AUDIT.txt I.B. */
#define HELD_MULT  32u
#define HELD_FLOOR (64u * 1024u)
#define HELD_OK(held, n) ((held) <= (uint64_t)HELD_MULT * (n) + HELD_FLOOR)

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v) { le16(p, v & 0xffffu); le16(p + 2, v >> 16); }
static void le64(uint8_t *p, uint64_t v) { le32(p, (uint32_t)v); le32(p + 4, (uint32_t)(v >> 32)); }

/* ---- fixtures: zip ---------------------------------------------------------------------------- */

#define MARKER "KOFMARK!"

/*
 * n stored members of eight bytes, the last the marker. `eocd_n` is what the end record says (the
 * real n when 0), `local_of` makes entry i point at that entry's local header instead of its own
 * (an array of n offsets, or NULL), `sig_count` appends that many end-record signatures after the
 * real one (inside its comment, which is where an archive may put them).
 */
struct zspec {
	unsigned n;
	unsigned eocd_n;         /* 0: n */
	int      all_same_local; /* every entry's local_off is entry 0's */
	int      self_local;     /* every entry's local_off is the directory's own start */
	unsigned fake_eocds;     /* "PK\5\6" signatures stuffed into the comment */
};

static uint8_t *zip_build(const struct zspec *sp, size_t *len)
{
	unsigned n = sp->n, i;
	size_t cap = (size_t)n * 128u + 64u + (size_t)sp->fake_eocds * 4u + 22u, at = 0, cd, lo = 0;
	uint8_t *f = calloc(1, cap);
	char name[16];
	unsigned en = sp->eocd_n ? sp->eocd_n : n;

	if (!f)
		return NULL;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", i);

		le32(f + at, 0x04034b50u);
		le16(f + at + 4, 10);
		le32(f + at + 18, 8);
		le32(f + at + 22, 8);
		le16(f + at + 26, nl);
		memcpy(f + at + 30, name, nl);
		memcpy(f + at + 30 + nl, i + 1u == n ? MARKER : "DATADATA", 8);
		at += 30u + nl + 8u;
	}
	cd = at;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", i);

		le32(f + at, 0x02014b50u);
		le16(f + at + 4, 20);
		le16(f + at + 6, 10);
		le32(f + at + 20, 8);
		le32(f + at + 24, 8);
		le16(f + at + 28, nl);
		le32(f + at + 42, sp->self_local ? (uint32_t)cd : sp->all_same_local ? 0u : (uint32_t)lo);
		memcpy(f + at + 46, name, nl);
		at += 46u + nl;
		lo += 30u + nl + 8u;
	}
	{
		size_t eocd = at;

		le32(f + at, 0x06054b50u);
		le16(f + at + 8, en > 0xffffu ? 0xffffu : en);
		le16(f + at + 10, en > 0xffffu ? 0xffffu : en);
		le32(f + at + 12, (uint32_t)(at - cd));
		le32(f + at + 16, (uint32_t)cd);
		le16(f + at + 20, sp->fake_eocds * 4u);
		at += 22u;
		for (i = 0; i < sp->fake_eocds; i++, at += 4)
			le32(f + at, 0x06054b50u);
		(void)eocd;
	}
	*len = at;
	return f;
}

static struct kof_zip_info *zparse(const uint8_t *f, size_t n, int *ok)
{
	struct kof_zip_info *z = calloc(1, sizeof *z);
	struct kof_obj_ctx ctx;

	memset(&ctx, 0, sizeof ctx);
	if (!z) {
		*ok = 0;
		return NULL;
	}
	*ok = kof_zip_parse(kof_buf_make(f, n), z, &ctx);
	return z;
}

static void zfree(struct kof_zip_info *z)
{
	if (z) {
		kof_zip_release(z);
		free(z);
	}
}

/*
 * THE PARTITION: every byte of the object is in exactly one region of the view. Each mask is
 * resolved on its own, the ranges are laid over a count per byte, and a byte with a count other
 * than one is a region that overlaps or a gap nothing owns. `cap` is how many ranges a mask may
 * come back with - generous, because what is being tested is that none is cut.
 */
static int partition(const struct kof_obj_ctx *ctx, const uint32_t *bits, unsigned nbits, uint64_t size,
		     uint32_t cap, uint64_t *ranges_of_first)
{
	uint8_t *cover = calloc(1, (size_t)size + 1u);
	struct kof_range *out = malloc((size_t)cap * sizeof *out);
	unsigned b;
	uint64_t i, k;
	int good = 1;

	if (!cover || !out) {
		free(cover);
		free(out);
		return 0;
	}
	for (b = 0; b < nbits; b++) {
		uint32_t n = ctx->resolve_scan(ctx, bits[b], out, cap);

		if (n >= cap) {
			good = 0;               /* cut: the cap was meant to be out of reach */
			break;
		}
		if (b == 0 && ranges_of_first)
			*ranges_of_first = n;
		for (k = 0; k < n; k++)
			for (i = out[k].off; i < out[k].off + out[k].len && i < size; i++)
				if (cover[i] < 255u)
					cover[i]++;
	}
	for (i = 0; i < size && good; i++)
		if (cover[i] != 1u)
			good = 0;
	free(cover);
	free(out);
	return good;
}

/* ---- zip: whole ------------------------------------------------------------------------------- */

static void zip_whole(unsigned n)
{
	struct zspec sp = { n, 0, 0, 0, 0 };
	size_t len;
	uint8_t *f = zip_build(&sp, &len);
	struct kof_obj_ctx ctx;
	struct kof_zip_info *z;
	int ok;
	uint64_t names = 0;
	uint32_t i;
	uint32_t bits[5] = { KOF_SCAN_ZIP_NAMES, KOF_SCAN_ZIP_HEADERS, KOF_SCAN_ZIP_STORED, KOF_SCAN_ZIP_PACKED,
			     KOF_SCAN_ZIP_UNCLAIMED };
	int part = 0;

	CK(f != NULL, "fixture");
	if (!f)
		return;
	memset(&ctx, 0, sizeof ctx);
	z = calloc(1, sizeof *z);
	ok = z && kof_zip_parse(kof_buf_make(f, len), z, &ctx);
	CK(ok && z->valid && z->n_entries == n, "zip %u entries: %u rows", n, z ? z->n_entries : 0u);
	CK(z && !(z->anomalies & (KOF_ZIP_ANOM_ENTRIES_FULL | KOF_ZIP_ANOM_EXTENTS_FULL)),
	   "zip %u entries: nothing is full (anomalies %#llx)", n, z ? (unsigned long long)z->anomalies : 0ull);
	if (z && ok) {
		CK(HELD_OK(z->mem.held, len), "zip %u entries: the tables hold %llu bytes of a %zu byte file (limit %ux)", n,
		   (unsigned long long)z->mem.held, len, HELD_MULT);
		part = partition(&ctx, bits, 5, len, 8u * n + 64u, &names);
		CK(part, "zip %u entries: the regions partition the file byte for byte", n);
		CK(names == 2ull * n, "zip %u entries: the names region is two extents an entry, whole (%llu)", n,
		   (unsigned long long)names);
		/* the rows are the archive's, in directory order */
		for (i = 0; i < z->n_entries && i < n; i += (n > 50u ? n / 50u : 1u)) {
			char want[16];

			snprintf(want, sizeof want, "e%05u", i);
			CK(z->entry[i].name_len == 6u && !memcmp(f + z->entry[i].name_off, want, 6) &&
			   z->entry[i].data_off && z->entry[i].csize == 8u, "zip %u entries: row %u is entry %u", n, i, i);
		}
	}
	zfree(z);
	free(f);
}

/* ---- zip: hostile ----------------------------------------------------------------------------- */

static void zip_hostile(void)
{
	size_t len;
	uint8_t *f;
	struct kof_zip_info *z;
	int ok;
	double t0;

	/* an end record that says 65535 over a directory of three */
	{
		struct zspec sp = { 3, 65535, 0, 0, 0 };

		f = zip_build(&sp, &len);
		z = f ? zparse(f, len, &ok) : NULL;
		CK(z && ok && z->n_entries == 3u && z->declared_entries == 0xffffu && (z->anomalies & KOF_ZIP_ANOM_CD_SHORT),
		   "count 65535, three records: three rows and CD_SHORT");
		CK(z && z->mem.held < 8192u, "...and the allocation follows the three, not the 65535 (%llu bytes)",
		   z ? (unsigned long long)z->mem.held : 0ull);
		zfree(z);
		free(f);
	}
	/* a real archive with a directory CLAIMING more than the file can hold */
	{
		struct zspec sp = { 5, 0, 0, 0, 0 };

		f = zip_build(&sp, &len);
		if (f) {
			/* ZIP64 end record claiming 2^40 entries, a directory of 2^50 bytes at 2^50: the 32-bit
			 * fields are saturated so the 64-bit ones are read, as a real extractor does */
			uint8_t *g = calloc(1, len + 56u + 20u);
			size_t eocd = len - 22u, z64 = eocd;

			memcpy(g, f, eocd);
			le32(g + z64, 0x06064b50u);
			le64(g + z64 + 4, 44);
			le64(g + z64 + 0x20, 1ull << 40);
			le64(g + z64 + 0x28, 1ull << 50);
			le64(g + z64 + 0x30, 1ull << 50);
			le32(g + z64 + 56, 0x07064b50u);
			le64(g + z64 + 56 + 8, z64);
			le32(g + z64 + 56 + 16, 1);
			memcpy(g + z64 + 56 + 20, f + eocd, 22);
			le16(g + z64 + 56 + 20 + 8, 0xffffu);
			le16(g + z64 + 56 + 20 + 10, 0xffffu);
			le32(g + z64 + 56 + 20 + 12, 0xffffffffu);
			le32(g + z64 + 56 + 20 + 16, 0xffffffffu);
			z = zparse(g, len + 56u + 20u - 0u, &ok);
			CK(z && ok && z->valid, "zip64 claiming 2^40 entries: parses, valid");
			CK(z && HELD_OK(z->mem.held, len + 76u), "zip64 claiming 2^40 entries: allocation bounded by the file (%llu)",
			   z ? (unsigned long long)z->mem.held : 0ull);
			CK(z && z->n_entries <= 5u, "zip64 claiming 2^40 entries: no more rows than records (%u)", z ? z->n_entries : 0u);
			zfree(z);
			free(g);
		}
		free(f);
	}
	/* zip64 with a believable directory and a claimed count of 2^32 - 1 */
	{
		struct zspec sp = { 4, 0, 0, 0, 0 };

		f = zip_build(&sp, &len);
		if (f) {
			uint8_t *g = calloc(1, len + 76u);
			size_t eocd = len - 22u;
			uint64_t cd = (uint64_t)((f[eocd + 16]) | (f[eocd + 17] << 8) | (f[eocd + 18] << 16));

			memcpy(g, f, eocd);
			le32(g + eocd, 0x06064b50u);
			le64(g + eocd + 4, 44);
			le64(g + eocd + 0x20, 0xffffffffull);
			le64(g + eocd + 0x28, eocd - cd);
			le64(g + eocd + 0x30, cd);
			le32(g + eocd + 56, 0x07064b50u);
			le64(g + eocd + 56 + 8, eocd);
			memcpy(g + eocd + 76, f + eocd, 22);
			le16(g + eocd + 76 + 8, 0xffffu);
			le16(g + eocd + 76 + 10, 0xffffu);
			z = zparse(g, eocd + 76u + 22u, &ok);
			CK(z && ok && z->n_entries == 4u && z->mem.held < 8192u,
			   "zip64 count 2^32-1 over four records: four rows, a small allocation (%llu)",
			   z ? (unsigned long long)z->mem.held : 0ull);
			zfree(z);
			free(g);
		}
		free(f);
	}
	/* sixty-five thousand end-record signatures in one comment */
	{
		struct zspec sp = { 3, 0, 0, 0, 16000u };

		f = zip_build(&sp, &len);
		t0 = now();
		z = f ? zparse(f, len, &ok) : NULL;
		CK(z && ok && z->n_entries == 3u && now() - t0 < 1.0, "16000 end-record signatures in the comment: three rows, under a second");
		zfree(z);
		free(f);
	}
	{
		/* the file IS signatures: 16384 of them back to back, nothing else */
		size_t n = 65536u;
		uint8_t *g = calloc(1, n);
		unsigned i;

		for (i = 0; g && i + 4u <= n; i += 4u)
			le32(g + i, 0x06054b50u);
		t0 = now();
		z = g ? zparse(g, n, &ok) : NULL;
		CK(z && now() - t0 < 1.0 && HELD_OK(z ? z->mem.held : 0ull, n), "a file of end-record signatures: parsed, bounded, fast");
		zfree(z);
		free(g);
	}
	/* entries that point at the directory itself, and entries that all point at one local header */
	{
		struct zspec sp = { 3000, 0, 0, 1, 0 };

		f = zip_build(&sp, &len);
		z = f ? zparse(f, len, &ok) : NULL;
		CK(z && ok && z->n_entries == 3000u && (z->anomalies & KOF_ZIP_ANOM_BAD_LOCAL), "3000 entries aimed at the directory: rows kept, BAD_LOCAL raised");
		CK(z && HELD_OK(z->mem.held, len), "...and the allocation is bounded (%llu of %zu)", z ? (unsigned long long)z->mem.held : 0ull, len);
		zfree(z);
		free(f);
	}
	{
		struct zspec sp = { 5000, 0, 1, 0, 0 };

		f = zip_build(&sp, &len);
		z = f ? zparse(f, len, &ok) : NULL;
		CK(z && ok && z->n_entries == 5000u && (z->anomalies & KOF_ZIP_ANOM_OVERLAP), "5000 entries all on one local header: OVERLAP raised");
		CK(z && HELD_OK(z->mem.held, len), "...and the allocation is bounded (%llu of %zu)", z ? (unsigned long long)z->mem.held : 0ull, len);
		zfree(z);
		free(f);
	}
	/* cut in the middle of the directory */
	{
		struct zspec sp = { 100, 0, 0, 0, 0 };

		f = zip_build(&sp, &len);
		z = f ? zparse(f, len - 22u - 300u, &ok) : NULL;
		CK(z && z->n_entries < 100u, "a directory cut short: fewer rows, no crash");
		zfree(z);
		free(f);
	}
}

/* ---- pdf fixtures ----------------------------------------------------------------------------- */

enum { PDF_RING_JS, PDF_RING_FONT, PDF_SAME_NUMBER, PDF_MINIMAL, PDF_PLAIN, PDF_SELF_LENGTH };

static uint8_t *pdf_build(unsigned n, int kind, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 160u);
	size_t at = 0;
	unsigned i;

	if (!f)
		return NULL;
	at += (size_t)sprintf((char *)f, "%%PDF-1.4\n");
	for (i = 1; i <= n; i++) {
		switch (kind) {
		case PDF_MINIMAL:
			at += (size_t)sprintf((char *)f + at, "0 0 obj\nendobj\n");
			continue;
		case PDF_SAME_NUMBER:
			at += (size_t)sprintf((char *)f + at, "1 0 obj\n<< /Length 8 /JS 1 0 R >>\nstream\n");
			break;
		case PDF_RING_JS:
			at += (size_t)sprintf((char *)f + at, "%u 0 obj\n<< /Length 8 /JS %u 0 R >>\nstream\n", i, i % n + 1u);
			break;
		case PDF_RING_FONT:
			at += (size_t)sprintf((char *)f + at, "%u 0 obj\n<< /Length 8 /FontFile2 %u 0 R >>\nstream\n", i, i % n + 1u);
			break;
		case PDF_SELF_LENGTH:
			at += (size_t)sprintf((char *)f + at, "%u 0 obj\n<< /Length %u 0 R >>\nstream\n", i, i);
			break;
		default:
			at += (size_t)sprintf((char *)f + at, "%u 0 obj\n<< /Length 8 >>\nstream\n", i);
			break;
		}
		memcpy(f + at, i == n ? MARKER : "01234567", 8);
		at += 8;
		at += (size_t)sprintf((char *)f + at, "\nendstream\nendobj\n");
	}
	at += (size_t)sprintf((char *)f + at, "trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n0\n%%%%EOF\n", n + 1u);
	*len = at;
	return f;
}

static struct kof_pdf_info *pparse(const uint8_t *f, size_t n, struct kof_obj_ctx *ctx, int *ok)
{
	struct kof_pdf_info *p = calloc(1, sizeof *p);

	memset(ctx, 0, sizeof *ctx);
	if (!p) {
		*ok = 0;
		return NULL;
	}
	*ok = kof_pdf_parse(kof_buf_make(f, n), p, ctx);
	return p;
}

static void pfree(struct kof_pdf_info *p)
{
	if (p) {
		kof_pdf_release(p);
		free(p);
	}
}

/* ---- pdf: whole ------------------------------------------------------------------------------- */

static void pdf_whole(unsigned n, int kind, const char *what)
{
	size_t len;
	uint8_t *f = pdf_build(n, kind, &len);
	struct kof_obj_ctx ctx;
	struct kof_pdf_info *p;
	int ok, part;
	uint32_t bits[KOF_PDF_REGION_COUNT];
	unsigned i;

	CK(f != NULL, "fixture");
	if (!f)
		return;
	p = pparse(f, len, &ctx, &ok);
	CK(p && ok && p->valid && p->n_objects == n && p->n_streams == n && p->declared_objects == n,
	   "pdf %u objects (%s): every object and every stream is a row (%u, %u)", n, what, p ? p->n_objects : 0u, p ? p->n_streams : 0u);
	CK(p && p->n_entries == n, "pdf %u objects (%s): an entry for every stream (%u)", n, what, p ? p->n_entries : 0u);
	CK(p && !(p->anomalies & (KOF_PDF_ANOM_OBJECTS_FULL | KOF_PDF_ANOM_EXTENTS_FULL)),
	   "pdf %u objects (%s): nothing is full (anomalies %#llx)", n, what, p ? (unsigned long long)p->anomalies : 0ull);
	if (p && ok) {
		const struct kof_entry *tab = NULL;
		uint32_t ne = ctx.entries(&ctx, &tab);

		CK(HELD_OK(p->mem.held, len), "pdf %u objects (%s): the tables hold %llu bytes of a %zu byte file (limit %ux)", n, what,
		   (unsigned long long)p->mem.held, len, HELD_MULT);
		for (i = 0; i < KOF_PDF_REGION_COUNT; i++)
			bits[i] = kof_pdf_region_bits[i];
		part = partition(&ctx, bits, KOF_PDF_REGION_COUNT, len, 6u * n + 64u, NULL);
		CK(part, "pdf %u objects (%s): the regions partition the file byte for byte", n, what);
		CK(ne == n && tab && tab[ne - 1u].index == n - 1u && tab[0].index == 0u, "pdf %u objects (%s): the entry table is the host's, one row a stream, indexes ascending",
		   n, what);
		/* categories came through the reference pass, and the whole ring was resolved */
		if (kind == PDF_RING_JS)
			CK(p->object[0].cat == KOF_PDF_CAT_SCRIPT && p->object[n - 1u].cat == KOF_PDF_CAT_SCRIPT,
			   "pdf %u objects (%s): the references were followed (first %u, last %u)", n, what, p->object[0].cat,
			   p->object[n - 1u].cat);
		if (kind == PDF_RING_FONT)
			CK(p->object[0].cat == KOF_PDF_CAT_FONT && p->object[n - 1u].cat == KOF_PDF_CAT_FONT,
			   "pdf %u objects (%s): the font references were followed", n, what);
		if (kind == PDF_SAME_NUMBER)
			CK((p->anomalies & KOF_PDF_ANOM_OBJ_REDEFINED) && !(p->object[0].flags & KOF_PDF_OBJ_REDEFINED) &&
			   (p->object[1].flags & KOF_PDF_OBJ_REDEFINED) && (p->object[n - 1u].flags & KOF_PDF_OBJ_REDEFINED),
			   "pdf %u objects (%s): all but the first definition are flagged redefined", n, what);
	}
	pfree(p);
	free(f);
}

/* ---- pdf: hostile, and linear ------------------------------------------------------------------ */

static double pdf_time(unsigned n, int kind)
{
	size_t len;
	uint8_t *f = pdf_build(n, kind, &len);
	struct kof_obj_ctx ctx;
	struct kof_pdf_info *p;
	int ok;
	double t0, t;
	int rep;

	if (!f)
		return 1e9;
	t0 = now();
	for (rep = 0; rep < 3; rep++) {
		p = pparse(f, len, &ctx, &ok);
		pfree(p);
	}
	t = (now() - t0) / 3.0;
	free(f);
	return t;
}

static void pdf_hostile(void)
{
	size_t len;
	uint8_t *f;
	struct kof_obj_ctx ctx;
	struct kof_pdf_info *p;
	int ok;
	static const struct { int kind; const char *name; } kinds[] = {
		{ PDF_RING_JS, "ring of /JS references" }, { PDF_RING_FONT, "ring of /FontFile2 references" },
		{ PDF_SAME_NUMBER, "one object number defined every time" }, { PDF_SELF_LENGTH, "/Length naming the object itself" },
		{ PDF_MINIMAL, "the smallest object there is" }
	};
	unsigned k;

	for (k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
		double t2 = pdf_time(2000, kinds[k].kind), t20 = pdf_time(20000, kinds[k].kind);

		/* Linear is ten times; a pass that scans the table per object is a hundred. The bound is
		 * generous (30x) and the absolute one is what a scanner can afford per document. */
		CK(t20 < 0.5, "pdf, %s: 20000 objects parse in %.3fs", kinds[k].name, t20);
		CK(t20 < 30.0 * t2 + 0.005, "pdf, %s: 20000 objects cost %.1fx of 2000 (%.4fs, %.4fs)", kinds[k].name,
		   t20 / (t2 > 1e-9 ? t2 : 1e-9), t2, t20);
		f = pdf_build(20000, kinds[k].kind, &len);
		p = f ? pparse(f, len, &ctx, &ok) : NULL;
		CK(p && HELD_OK(p->mem.held, len), "pdf, %s: the tables hold %llu bytes of a %zu byte file", kinds[k].name,
		   p ? (unsigned long long)p->mem.held : 0ull, len);
		pfree(p);
		free(f);
	}
	/* an xref that claims four billion entries and a /Size to match, over a file of a few hundred bytes */
	{
		static const char doc[] =
			"%PDF-1.4\n1 0 obj\n<< /Type /ObjStm /N 4294967295 /First 99999999 /Length 3 >>\nstream\nabc\nendstream\nendobj\n"
			"xref\n0 4294967295\n0000000000 65535 f \ntrailer\n<< /Size 4294967295 /Prev 0 /Root 1 0 R >>\n"
			"startxref\n9\n%%EOF\nstartxref\n9\n%%EOF\n";

		p = pparse((const uint8_t *)doc, sizeof doc - 1u, &ctx, &ok);
		CK(p && ok && p->mem.held < 8192u && p->n_objects == 1u, "pdf claiming four billion objects over one: one row, %llu bytes",
		   p ? (unsigned long long)p->mem.held : 0ull);
		pfree(p);
	}
	/* startxref pointing at itself, and a /Prev loop the parse is not asked to follow */
	{
		static const char doc[] =
			"%PDF-1.4\n1 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n"
			"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 2 /Prev 70 /Root 1 0 R >>\nstartxref\n70\n%%EOF\n";

		p = pparse((const uint8_t *)doc, sizeof doc - 1u, &ctx, &ok);
		CK(p && ok && p->n_objects == 1u, "pdf whose startxref and /Prev point at the table: not followed, parsed");
		pfree(p);
	}
}

/* ---- the allocation sweeps: a refused allocation is survived or said ---------------------------- */

#if FA_AVAILABLE
static void sweep_parse_zip(void)
{
	struct zspec sp = { 3000, 0, 0, 0, 0 };
	size_t len;
	uint8_t *f = zip_build(&sp, &len);
	long count, nth, hits = 0, said = 0, same = 0;

	if (!f)
		return;
	fa_init();
	{
		int ok;
		struct kof_zip_info *z;

		fa_arm_nth(0);
		z = zparse(f, len, &ok);
		zfree(z);
		count = fa_count();
		(void)fa_disarm_hit();
	}
	CK(count > 3, "zip parse: allocations to sweep (%ld)", count);
	for (nth = 1; nth <= count; nth++) {
		int ok, reached;
		struct kof_zip_info *z;

		fa_arm_nth(nth);
		z = zparse(f, len, &ok);
		reached = fa_disarm_hit();
		if (!reached) {
			zfree(z);
			continue;
		}
		hits++;
		if (!z) {
			said++;                 /* the view itself was refused: nothing was built and the caller knows */
			continue;
		}
		if (ok && z->n_entries == 3000u && !(z->anomalies & (KOF_ZIP_ANOM_ENTRIES_FULL | KOF_ZIP_ANOM_EXTENTS_FULL)))
			same++;
		else if (z->anomalies & (KOF_ZIP_ANOM_ENTRIES_FULL | KOF_ZIP_ANOM_EXTENTS_FULL))
			said++;
		else
			CK(0, "zip parse, allocation %ld refused: %u of 3000 rows and nothing said (anomalies %#llx)", nth, z->n_entries,
			   (unsigned long long)z->anomalies);
		zfree(z);
	}
	printf("  zip parse sweep: %ld allocations, %ld refused in turn: %ld survived to the same answer, %ld said\n", count, hits, same, said);
	CK(hits == count && same + said == hits, "zip parse: every refusal survived or said");
	free(f);
}

static void sweep_parse_pdf(void)
{
	size_t len;
	uint8_t *f = pdf_build(3000, PDF_RING_FONT, &len);
	long count, nth, hits = 0, said = 0, same = 0;
	struct kof_obj_ctx ctx;
	const uint64_t full = KOF_PDF_ANOM_OBJECTS_FULL | KOF_PDF_ANOM_EXTENTS_FULL;

	if (!f)
		return;
	fa_init();
	{
		int ok;
		struct kof_pdf_info *p;

		fa_arm_nth(0);
		p = pparse(f, len, &ctx, &ok);
		pfree(p);
		count = fa_count();
		(void)fa_disarm_hit();
	}
	CK(count > 3, "pdf parse: allocations to sweep (%ld)", count);
	for (nth = 1; nth <= count; nth++) {
		int ok, reached;
		struct kof_pdf_info *p;

		fa_arm_nth(nth);
		p = pparse(f, len, &ctx, &ok);
		reached = fa_disarm_hit();
		if (!reached) {
			pfree(p);
			continue;
		}
		hits++;
		if (!p) {
			said++;
			continue;
		}
		if (ok && p->n_objects == 3000u && p->n_entries == 3000u && !(p->anomalies & full))
			same++;
		else if (p->anomalies & full)
			said++;
		else
			CK(0, "pdf parse, allocation %ld refused: %u objects, %u entries of 3000 and nothing said (anomalies %#llx)", nth,
			   p->n_objects, p->n_entries, (unsigned long long)p->anomalies);
		pfree(p);
	}
	printf("  pdf parse sweep: %ld allocations, %ld refused in turn: %ld survived to the same answer, %ld said\n", count, hits, same, said);
	CK(hits == count && same + said == hits, "pdf parse: every refusal survived or said");
	free(f);
}
#endif

/* ---- the engine ------------------------------------------------------------------------------- */

struct seen {
	unsigned objs, marker, top_broken, any_broken;
	double secs;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	if (!s->objs)
		s->top_broken = res->broken;
	s->objs++;
	if (bytes && len == 8u && memcmp(bytes, MARKER, 8) == 0)
		s->marker++;
	if (res->broken && !s->any_broken)
		s->any_broken = res->broken;
	return 0;
}

static kof_engine *eng;
static kof_scanner *sc;

static void scan(const uint8_t *b, uint64_t n, struct seen *s)
{
	struct kof_scan_option opt;
	double t0 = now();

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	(void)kscan_bytes(sc, b, n, "x", &opt, on_object, s);
	s->secs = now() - t0;
}

static void engine_cases(void)
{
	struct seen s;
	size_t len;
	uint8_t *f;
	unsigned k;
	static const unsigned zn[] = { 2100, 4096, 40000, 65535 };

	/* every member, every stream; and the one count the engine does not take whole - the names quota -
	 * is the only reason for less, and it says so */
	for (k = 0; k < sizeof zn / sizeof zn[0]; k++) {
		struct zspec sp = { zn[k], 0, 0, 0, 0 };

		f = zip_build(&sp, &len);
		if (!f)
			continue;
		scan(f, len, &s);
		printf("  engine, zip %u entries: %u children, marker %u, top broken=%u, %.2fs\n", zn[k], s.objs ? s.objs - 1u : 0u,
		       s.marker, s.top_broken, s.secs);
		CK((s.objs - 1u == zn[k] && !s.top_broken && s.marker == 1u) || s.top_broken,
		   "engine, zip %u entries: all of them, or the object says it was cut (%u children, broken %u)", zn[k],
		   s.objs ? s.objs - 1u : 0u, s.top_broken);
		if (zn[k] <= 40000u)
			CK(s.objs - 1u == zn[k] && !s.top_broken, "engine, zip %u entries: all of them, not broken", zn[k]);
		CK(s.secs < 5.0, "engine, zip %u entries: %.2fs", zn[k], s.secs);
		free(f);
	}
	/* a pdf of 20000 objects that reference each other in a ring */
	f = pdf_build(20000, PDF_RING_JS, &len);
	if (f) {
		scan(f, len, &s);
		printf("  engine, pdf 20000 objects in a /JS ring: %u children, marker %u, top broken=%u, %.2fs\n", s.objs ? s.objs - 1u : 0u,
		       s.marker, s.top_broken, s.secs);
		CK(s.objs - 1u == 20000u && !s.top_broken && s.marker == 1u && s.secs < 5.0,
		   "engine, pdf 20000 objects in a ring: every stream opened, not broken, in time");
		free(f);
	}
	/*
	 * THE OVERLAP BOMB. 5000 entries, every one a stored window over the same blob, which is most of
	 * the file. A window costs no produced byte, so what stops it is the tree's allowance of windows
	 * (kof_scan_ledger.window_left: the root plus the produced-bytes budget, 64x the archive here, the
	 * same figure that bounds a bomb of decoded bytes): the 80th window stops the walk, and the object
	 * says so - Limit reached, not examined. (It was twice the archive, in zip.c alone: three
	 * children, and a zip that listed every member three times was refused.)
	 */
	{
		size_t blob = 1u << 20, at = 0, cd, i;
		uint8_t *g = calloc(1, blob + 5000u * 64u + 64u);

		if (g) {
			le32(g, 0x04034b50u);
			le16(g + 4, 10);
			le32(g + 18, (uint32_t)blob);
			le32(g + 22, (uint32_t)blob);
			le16(g + 26, 1);
			g[30] = 'a';
			at = 31u + blob;
			cd = at;
			for (i = 0; i < 5000u; i++) {
				le32(g + at, 0x02014b50u);
				le16(g + at + 4, 20);
				le16(g + at + 6, 10);
				le32(g + at + 20, (uint32_t)blob);
				le32(g + at + 24, (uint32_t)blob);
				le16(g + at + 28, 1);
				le32(g + at + 42, 0);
				g[at + 46] = 'a';
				at += 47u;
			}
			le32(g + at, 0x06054b50u);
			le16(g + at + 8, 5000);
			le16(g + at + 10, 5000);
			le32(g + at + 12, (uint32_t)(at - cd));
			le32(g + at + 16, (uint32_t)cd);
			at += 22u;
			scan(g, at, &s);
			printf("  engine, 5000 entries over one 1 MB blob: %u children, top broken=%u, %.2fs\n", s.objs ? s.objs - 1u : 0u,
			       s.top_broken, s.secs);
			CK(s.objs - 1u > 3u && s.objs - 1u <= (at + (at * 64u > (64u << 20) ? at * 64u : (64u << 20))) / blob &&
			   s.top_broken == KOF_BROKEN_LIMIT && s.secs < 2.0,
			   "overlapping entries: stopped when the windows span the root plus the produced budget, and said so (%u children, broken %u, %.2fs)",
			   s.objs ? s.objs - 1u : 0u, s.top_broken, s.secs);
			free(g);
		}
	}
}

/*
 * THE LEDGER AT EVERY SIZE. The engine decides what a table may hold from what its per-object
 * ledger has left (struct kof_view_mem.room), and the ceiling is the host's to set
 * (kof_scan_option.max_resident_bytes). So the sweep that matters end to end is over the
 * CEILING: the same archive scanned under each of a ladder of them, from one that cannot hold
 * the file's tables to one that holds everything, and at every rung the answer is either
 * the archive whole or an object that says it was cut. A rung with fewer members and no word
 * is the silence this change exists to rule out.
 *
 * (A malloc that fails is swept one level down, over the parse, above: the walk's own records -
 * the layer stack, the names - are the walk's, and refusing those is a different report, see
 * silent_oom_sweep.c and OOM_WALK_ROOT.)
 */
static void ledger_sweep(const char *what, const uint8_t *f, size_t len, unsigned want)
{
	static const uint64_t ladder[] = { 1u << 18, 1u << 19, 1u << 20, 3u << 19, 2u << 20, 3u << 20, 4u << 20, 6u << 20,
					   8u << 20, 12u << 20, 16u << 20, 24u << 20, 32u << 20, 64u << 20, 256u << 20 };
	unsigned k, whole = 0, said = 0, silent = 0;

	for (k = 0; k < sizeof ladder / sizeof ladder[0]; k++) {
		struct kof_scan_option opt;
		struct seen s;
		unsigned kids;

		memset(&s, 0, sizeof s);
		memset(&opt, 0, sizeof opt);
		opt.max_resident_bytes = ladder[k];
		opt.resident_per_scanner = 1;
		(void)kscan_bytes(sc, f, len, "x", &opt, on_object, &s);
		kids = s.objs ? s.objs - 1u : 0u;
		if (kids == want && !s.any_broken)
			whole++;
		else if (s.any_broken)
			said++;
		else {
			silent++;
			printf("  silent: ceiling %llu: %u of %u children, nothing said\n", (unsigned long long)ladder[k], kids, want);
		}
		printf("    %s, ceiling %9llu: %5u of %u children, broken=%u\n", what, (unsigned long long)ladder[k], kids, want, s.any_broken);
	}
	CK(silent == 0, "%s: %u ceiling(s) lost members and said nothing", what, silent);
	CK(whole > 0 && said > 0, "%s: the ladder spans both answers (%u whole, %u said)", what, whole, said);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : ad_db_script();
	static const unsigned zn[] = { 2100, 4096, 5000, 20000, 65535 };
	static const unsigned pn[] = { 4200, 5000, 20000 };
	unsigned i;

	printf("== zip and pdf views: the size of the file, bounded by the file and the ledger\n");
	for (i = 0; i < sizeof zn / sizeof zn[0]; i++)
		zip_whole(zn[i]);
	for (i = 0; i < sizeof pn / sizeof pn[0]; i++) {
		pdf_whole(pn[i], PDF_PLAIN, "plain streams");
		pdf_whole(pn[i], PDF_RING_JS, "ring of /JS");
	}
	pdf_whole(5000, PDF_RING_FONT, "ring of /FontFile2");
	pdf_whole(5000, PDF_SAME_NUMBER, "one number, redefined");
	zip_hostile();
	pdf_hostile();
#if FA_AVAILABLE
	sweep_parse_zip();
	sweep_parse_pdf();
#else
	printf("  allocation sweeps skipped: a sanitizer owns malloc here\n");
#endif

	eng = keng_open(db);
	if (!eng) {
		printf("view_tables: no database at %s - the engine half was not run\n", db);
	} else {
		sc = kscan_new(eng);
		CK(sc != NULL, "scanner");
		if (sc) {
			engine_cases();
			{
				struct zspec sp = { 20000, 0, 0, 0, 0 };
				size_t len;
				uint8_t *f = zip_build(&sp, &len);

				if (f) {
					ledger_sweep("zip, 20000 entries", f, len, 20000u);
					free(f);
				}
				f = pdf_build(20000, PDF_RING_JS, &len);
				if (f) {
					ledger_sweep("pdf, 20000 objects", f, len, 20000u);
					free(f);
				}
			}
			kscan_free(sc);
		}
		keng_close(eng);
	}
	if (fails) {
		printf("view_tables: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("view_tables: whole, bounded, linear, reported - ok\n");
	return 0;
}
