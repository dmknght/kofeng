/*
 * view_oldpack - a database built BEFORE the zip and pdf views became tables the size of the
 * file, loaded by an engine AFTER it.
 *
 * WHAT CHANGED MEANING. `struct kof_zip_info` and `struct kof_pdf_info` ended in fixed arrays
 * (`entry[4096]`, `object[4096]`, ...) and a module indexed them below a count it read from the
 * header. Now they end in pointers to tables the parse allocates, and the module walks them
 * through a vtable slot. A module blob built for the first layout and run on the second would,
 * if the count still meant "rows in the array", read whatever lies at the array's old offset:
 * no crash, no refusal, a scan deciding on the wrong bytes (kofabi.h says exactly this about a
 * view that changes shape, and what refuses it - KOFSIG_ABI_MIN - is the owner's to raise).
 *
 * WHAT THIS PINS, in two halves that need each other:
 *
 *   LAYOUT   every field a version 1 module can read has the offset it had; the one that counted
 *            the rows (`n_entries`, `n_objects`) is still there and reads ZERO, so the module's
 *            loop does not run and it never touches the old array. A valid empty table is the
 *            only thing it can see.
 *   DETECT   and the engine does not take that for an archive with nothing in it: the module's
 *            table has rows and it never walked them (struct kof_view_mem.walked), so the object
 *            is reported - Unsupported by this build, the reason a rebuild closes. The proof is
 *            the real thing: the two packs of the shipped database as they were before the change
 *            (oldview_packs.h) are loaded by this engine and scan an archive and a document.
 *
 * The control is the same archive and the same document through the database built from this
 * tree: every member opened, nothing broken.
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/pdf_parse.h"
#include "oldview_packs.h"
#include "oldview44_packs.h"
#include "arch_fixtures.h"
#include <kofmod/tar.h>
#include <kofmod/lha.h>
#include <kofmod/arj.h>
#include <kofmod/chm.h>
#include <kofmod/docole.h>
#include <kofmod/rar.h>
#include <kofmod/sevenzip.h>

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

/*
 * The head of each view as a version 1 module reads it: everything before the first array. Written
 * out here, field for field, from the version 1 headers - the point is that it is NOT the current
 * struct, so the offsets below are a statement about two layouts and not about one.
 */
struct v1_zip_head {
	uint32_t version, valid;
	uint64_t anomalies;
	uint32_t kind, n_entries, declared_entries, n_encrypted;
	uint64_t eocd_off, cd_off, cd_size;
	int64_t  base_delta;
	uint64_t comment_off, comment_len;
	uint64_t total_csize, total_usize;
	uint64_t region_bytes[KOF_ZIP_CLS_COUNT];
	uint32_t n_runs, reserved0;
};

struct v1_pdf_head {
	uint32_t version, valid;
	uint64_t anomalies;
	uint64_t header_off;
	uint8_t  ver_major, ver_minor, reserved0, reserved1;
	uint64_t startxref, eof_off;
	uint32_t n_objects, n_streams, declared_objects;
	uint64_t region_bytes[12];
	uint32_t n_runs, reserved2;
};

#define SAME(NEW, OLD, F) \
	_Static_assert(offsetof(NEW, F) == offsetof(OLD, F), "a version 1 field moved: " #F)

SAME(struct kof_zip_info, struct v1_zip_head, version);
SAME(struct kof_zip_info, struct v1_zip_head, valid);
SAME(struct kof_zip_info, struct v1_zip_head, anomalies);
SAME(struct kof_zip_info, struct v1_zip_head, kind);
SAME(struct kof_zip_info, struct v1_zip_head, declared_entries);
SAME(struct kof_zip_info, struct v1_zip_head, n_encrypted);
SAME(struct kof_zip_info, struct v1_zip_head, eocd_off);
SAME(struct kof_zip_info, struct v1_zip_head, cd_off);
SAME(struct kof_zip_info, struct v1_zip_head, cd_size);
SAME(struct kof_zip_info, struct v1_zip_head, base_delta);
SAME(struct kof_zip_info, struct v1_zip_head, comment_off);
SAME(struct kof_zip_info, struct v1_zip_head, comment_len);
SAME(struct kof_zip_info, struct v1_zip_head, total_csize);
SAME(struct kof_zip_info, struct v1_zip_head, total_usize);
SAME(struct kof_zip_info, struct v1_zip_head, region_bytes);
SAME(struct kof_zip_info, struct v1_zip_head, n_runs);
/* the row count: same offset, new name, always zero */
_Static_assert(offsetof(struct kof_zip_info, legacy_n_entries) == offsetof(struct v1_zip_head, n_entries),
	       "the version 1 row count is not where it was");
/* and the new tables start exactly where the old arrays did */
_Static_assert(offsetof(struct kof_zip_info, mem) == sizeof(struct v1_zip_head),
	       "the new tail does not begin where the version 1 arrays did");

SAME(struct kof_pdf_info, struct v1_pdf_head, version);
SAME(struct kof_pdf_info, struct v1_pdf_head, valid);
SAME(struct kof_pdf_info, struct v1_pdf_head, anomalies);
SAME(struct kof_pdf_info, struct v1_pdf_head, header_off);
SAME(struct kof_pdf_info, struct v1_pdf_head, startxref);
SAME(struct kof_pdf_info, struct v1_pdf_head, eof_off);
SAME(struct kof_pdf_info, struct v1_pdf_head, n_streams);
SAME(struct kof_pdf_info, struct v1_pdf_head, declared_objects);
SAME(struct kof_pdf_info, struct v1_pdf_head, region_bytes);
SAME(struct kof_pdf_info, struct v1_pdf_head, n_runs);
_Static_assert(offsetof(struct kof_pdf_info, legacy_n_objects) == offsetof(struct v1_pdf_head, n_objects),
	       "the version 1 object count is not where it was");
_Static_assert(offsetof(struct kof_pdf_info, mem) == sizeof(struct v1_pdf_head),
	       "the new tail does not begin where the version 1 arrays did");

/* ---- the fixtures ---------------------------------------------------------------------------- */


/* n stored members "eN" holding "DATAN"; the last holds the marker. */
static uint8_t *make_zip(unsigned n, size_t *len)
{
	size_t at = 0, cd, lo = 0;
	uint8_t *f = calloc(1, (size_t)n * 128u + 64u);
	char name[16];
	unsigned i;

	if (!f)
		return NULL;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%u", i);

		le32(f + at, 0x04034b50u);
		le16(f + at + 4, 10);
		le32(f + at + 18, 8);
		le32(f + at + 22, 8);
		le16(f + at + 26, nl);
		memcpy(f + at + 30, name, nl);
		memcpy(f + at + 30 + nl, i + 1u == n ? "KOFMARK!" : "DATADATA", 8);
		at += 30u + nl + 8u;
	}
	cd = at;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%u", i);

		le32(f + at, 0x02014b50u);
		le16(f + at + 4, 20);
		le16(f + at + 6, 10);
		le32(f + at + 20, 8);
		le32(f + at + 24, 8);
		le16(f + at + 28, nl);
		le32(f + at + 42, (uint32_t)lo);
		memcpy(f + at + 46, name, nl);
		at += 46u + nl;
		lo += 30u + nl + 8u;
	}
	le32(f + at, 0x06054b50u);
	le16(f + at + 8, n);
	le16(f + at + 10, n);
	le32(f + at + 12, (uint32_t)(at - cd));
	le32(f + at + 16, (uint32_t)cd);
	*len = at + 22u;
	return f;
}

static const char PDF[] =
	"%PDF-1.4\n"
	"1 0 obj\n<< /Length 8 >>\nstream\nABCDEFGH\nendstream\nendobj\n"
	"2 0 obj\n<< /Length 8 >>\nstream\nKOFMARK!\nendstream\nendobj\n"
	"trailer\n<< /Size 3 >>\nstartxref\n0\n%%EOF\n";

/* ---- layout ---------------------------------------------------------------------------------- */

static void layout(void)
{
	size_t zl;
	uint8_t *zf = make_zip(3, &zl);
	struct kof_zip_info *z = calloc(1, sizeof *z);
	struct kof_pdf_info *p = calloc(1, sizeof *p);
	struct kof_obj_ctx ctx;

	CK(zf && z && p, "fixtures");
	if (!zf || !z || !p)
		goto out;
	memset(&ctx, 0, sizeof ctx);
	CK(kof_zip_parse(kof_buf_make(zf, zl), z, &ctx) == 1 && z->n_entries == 3u, "the archive parses to three rows");
	/* what a version 1 module reads: the count it loops on is zero, the rest is the truth */
	CK(((const struct v1_zip_head *)z)->n_entries == 0u, "a version 1 zip module reads a row count of zero");
	CK(((const struct v1_zip_head *)z)->valid == 1u && ((const struct v1_zip_head *)z)->declared_entries == 3u &&
	   ((const struct v1_zip_head *)z)->n_encrypted == 0u, "and the fields beside it are still the parse's answers");
	CK(z->mem.rows == 3u && z->mem.walked == 0u, "the view says it has rows and that nobody walked them");
	{
		uint32_t cur = 0, k = 0;

		while (kof_zip_row(z, &cur))
			k++;
		CK(k == 3u && z->mem.walked == 4u, "the walk gives every row and counts its calls (%u rows, %u calls)", k, z->mem.walked);
	}

	memset(&ctx, 0, sizeof ctx);
	CK(kof_pdf_parse(kof_buf_make(PDF, sizeof PDF - 1u), p, &ctx) == 1 && p->n_objects == 2u && p->n_streams == 2u,
	   "the document parses to two objects");
	CK(((const struct v1_pdf_head *)p)->n_objects == 0u, "a version 1 pdf module reads an object count of zero");
	CK(((const struct v1_pdf_head *)p)->valid == 1u && ((const struct v1_pdf_head *)p)->n_streams == 2u,
	   "and the fields beside it are still the parse's answers");
out:
	if (z)
		kof_zip_release(z);
	if (p)
		kof_pdf_release(p);
	free(z);
	free(p);
	free(zf);
}

/* ---- the old packs, in the new engine ---------------------------------------------------------- */

struct seen {
	unsigned objs, marker, top_broken;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	if (!s->objs)
		s->top_broken = res->broken;
	s->objs++;
	if (bytes && len == 8u && memcmp(bytes, "KOFMARK!", 8) == 0)
		s->marker++;
	return 0;
}

static void scan(kof_scanner *sc, const void *b, uint64_t n, struct seen *s)
{
	struct kof_scan_option opt;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	(void)kscan_bytes(sc, b, n, "x", &opt, on_object, s);
}

static int put(const char *dir, const char *name, const uint8_t *b, size_t n)
{
	char path[256];
	FILE *f;
	int ok;

	snprintf(path, sizeof path, "%s/%s", dir, name);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	ok = fwrite(b, 1, n, f) == n;
	return fclose(f) == 0 && ok;
}

static void old_packs(const char *db)
{
	char dir[64], path[256];
	kof_engine *old, *cur;
	kof_scanner *so = NULL, *sn = NULL;
	size_t zl;
	uint8_t *zf = make_zip(3, &zl);
	struct seen s;

	snprintf(dir, sizeof dir, "build/kof_oldview_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("  FAIL cannot make a work directory\n");
		fails++;
		free(zf);
		return;
	}
	CK(put(dir, "unpack-archive.ksig", old_archive_pack, sizeof old_archive_pack) &&
	   put(dir, "unpack-doc.ksig", old_doc_pack, sizeof old_doc_pack), "the old packs are written");

	old = keng_open(dir);
#if KOFSIG_ABI_MIN > 4
	/*
	 * THE FLOOR WAS RAISED (the owner's bump, see kofabi.h): the loader refuses a pack built before it,
	 * which is the answer this test exists to prefer - a refusal at load, never a misread. The engine
	 * either does not open at all or opens with nothing from those packs; the detection half below has
	 * nothing left to prove and is skipped.
	 */
	so = old ? kscan_new(old) : NULL;
	if (so)
		scan(so, zf, zl, &s);
	CK(old == NULL || (so && s.objs == 1u && s.marker == 0u && s.top_broken == 0u),
	   "ABI floor raised: a pack from before the view change is refused at load - no module of it runs");
	goto done;
#else
	CK(old != NULL, "an engine after the change LOADS a pack from before it (the ABI floor is not raised)");
	so = old ? kscan_new(old) : NULL;
	CK(zf && so, "scanner");
	if (!zf || !so)
		goto done;
#endif

	scan(so, zf, zl, &s);
	CK(s.objs == 1u && s.marker == 0u && s.top_broken == KOF_BROKEN_UNSUPPORTED,
	   "OLD zip module, 3-entry archive: no member opened and the object says Unsupported (objs %u, broken %u)",
	   s.objs, s.top_broken);
	scan(so, PDF, sizeof PDF - 1u, &s);
	CK(s.objs == 1u && s.marker == 0u && s.top_broken == KOF_BROKEN_UNSUPPORTED,
	   "OLD pdf module, 2-stream document: no stream opened and the object says Unsupported (objs %u, broken %u)",
	   s.objs, s.top_broken);
	/* an archive with no entries is not mistaken for one: nothing to walk, nothing to report */
	{
		uint8_t empty[22] = { 0x50, 0x4b, 0x05, 0x06 };

		scan(so, empty, sizeof empty, &s);
		CK(s.objs == 1u && s.top_broken == 0u, "an empty archive is clean under the old module (objs %u, broken %u)",
		   s.objs, s.top_broken);
	}

	/* the control: the same bytes, the database of this tree */
	cur = keng_open(db);
	sn = cur ? kscan_new(cur) : NULL;
	if (!sn) {
		printf("view_oldpack: no database at %s - the control was not run\n", db);
	} else {
		scan(sn, zf, zl, &s);
		CK(s.objs == 4u && s.marker == 1u && s.top_broken == 0u,
		   "CURRENT zip module, same archive: three members, the marker one of them, not broken (objs %u, marker %u, broken %u)",
		   s.objs, s.marker, s.top_broken);
		scan(sn, PDF, sizeof PDF - 1u, &s);
		CK(s.objs == 3u && s.marker == 1u && s.top_broken == 0u,
		   "CURRENT pdf module, same document: two streams, the marker one of them, not broken (objs %u, marker %u, broken %u)",
		   s.objs, s.marker, s.top_broken);
	}
	if (sn)
		kscan_free(sn);
	if (cur)
		keng_close(cur);
done:
	if (so)
		kscan_free(so);
	if (old)
		keng_close(old);
	snprintf(path, sizeof path, "%s/unpack-archive.ksig", dir);
	unlink(path);
	snprintf(path, sizeof path, "%s/unpack-doc.ksig", dir);
	unlink(path);
	rmdir(dir);
	free(zf);
}

/* ---- tar, lha, arj, cab, chm, docole, rar, 7z: the same change, the same promise ---------------------
 *
 * LAYOUT   the row count a version 1 module of each reads is where it was and reads ZERO, and the
 *          tail that replaced the arrays begins where they did (the offsets are the version 1
 *          struct's, measured from the tree before the change). The cabinet is the one whose count
 *          sat AFTER two of its arrays, at byte 135272, so its view is padded to hold the word: a
 *          module reading it must find zero inside the view and not the heap beyond it.
 */
#define V1(T, F, OFF) _Static_assert(offsetof(struct T, F) == (OFF), #T "." #F " is not where version 1 had it")
V1(kof_tar_info, legacy_n_entries, 16);
V1(kof_tar_info, mem, 72);
V1(kof_lha_info, legacy_n_entries, 16);
V1(kof_lha_info, mem, 64);
V1(kof_arj_info, legacy_n_entries, 20);
V1(kof_arj_info, mem, 64);
V1(kof_cab_info, legacy_n_entries, 135272);
V1(kof_cab_info, mem, 104);
V1(kof_chm_info, legacy_n_entries, 144);
V1(kof_chm_info, mem, 168);
V1(kof_docole_info, legacy_n_entries, 136);
V1(kof_docole_info, mem, 152);
V1(kof_rar_info, legacy_n_entries, 20);
V1(kof_rar_info, mem, 88);
V1(kof_7z_info, legacy_n_folders, 96);
V1(kof_7z_info, mem, 104);
_Static_assert(sizeof(struct kof_cab_info) >= 135276, "the cabinet view does not hold version 1's count");

static const struct {
	const char *name;
	struct made (*build)(unsigned n, int kind);
	int doc;                 /* the module is in the document pack, not the archive one */
} oldfmt[] = {
	{ "tar", b_tar, 0 }, { "lha", b_lha, 0 }, { "arj", b_arj, 0 }, { "cab", b_cab, 0 },
	{ "chm", b_chm, 0 }, { "rar", b_rar, 0 }, { "7z", b_7z, 0 }, { "docole", b_ole, 1 }
};

/*
 * DETECT   the old modules of the eight formats, as they were shipped (oldview44_packs.h), loaded by
 *          this engine: an archive of three members opens nothing and the object says Unsupported by
 *          this build - never a clean object, never a misread. The control is the same archive through
 *          the database of this tree: every member a child, the marker one of them, nothing broken.
 */
static void old_formats(const char *db)
{
	char dir[64], path[256];
	kof_engine *old, *cur = NULL;
	kof_scanner *so = NULL, *sn = NULL;
	unsigned i;

	snprintf(dir, sizeof dir, "build/kof_oldview44_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("  FAIL cannot make a work directory\n");
		fails++;
		return;
	}
	CK(put(dir, "unpack-archive.ksig", old44_archive_pack, sizeof old44_archive_pack) &&
	   put(dir, "unpack-doc.ksig", old44_doc_pack, sizeof old44_doc_pack), "the old packs are written");
	old = keng_open(dir);
#if KOFSIG_ABI_MIN > 4
	so = old ? kscan_new(old) : NULL;
	CK(old == NULL || so != NULL, "ABI floor raised: a pack from before the view change is refused at load");
	goto done;
#else
	CK(old != NULL, "an engine after the change LOADS the packs from before it (the ABI floor is not raised)");
	so = old ? kscan_new(old) : NULL;
	cur = keng_open(db);
	sn = cur ? kscan_new(cur) : NULL;
	for (i = 0; so && i < sizeof oldfmt / sizeof oldfmt[0]; i++) {
		struct made m = oldfmt[i].build(3, K_CLEAN);
		struct seen s;

		CK(m.p != NULL, "%s: fixture", oldfmt[i].name);
		if (!m.p)
			continue;
		scan(so, m.p, m.len, &s);
		CK(s.marker == 0u && s.top_broken == KOF_BROKEN_UNSUPPORTED,
		   "OLD %s module, 3-member archive: no member opened and the object says Unsupported (objs %u, marker %u, broken %u)",
		   oldfmt[i].name, s.objs, s.marker, s.top_broken);
		if (sn) {
			scan(sn, m.p, m.len, &s);
			CK(s.marker == 1u && s.top_broken == 0u,
			   "CURRENT %s module, same archive: the marker is a member and nothing is broken (objs %u, marker %u, broken %u)",
			   oldfmt[i].name, s.objs, s.marker, s.top_broken);
		}
		free(m.p);
	}
	/* an archive with no entries is not mistaken for one: nothing to walk, nothing to report */
	if (so) {
		struct made m = b_tar(0, K_CLEAN);
		struct seen s;

		if (m.p) {
			scan(so, m.p, m.len, &s);
			CK(s.top_broken == 0u, "an empty tar is clean under the old module (broken %u)", s.top_broken);
			free(m.p);
		}
	}
	if (!sn)
		printf("view_oldpack: no database at %s - the controls were not run\n", db);
#endif
#if KOFSIG_ABI_MIN > 4
done:
#endif
	if (sn)
		kscan_free(sn);
	if (so)
		kscan_free(so);
	if (cur)
		keng_close(cur);
	if (old)
		keng_close(old);
	snprintf(path, sizeof path, "%s/unpack-archive.ksig", dir);
	unlink(path);
	snprintf(path, sizeof path, "%s/unpack-doc.ksig", dir);
	unlink(path);
	rmdir(dir);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";

	printf("== a pack from before the view change, in the engine after it\n");
	layout();
	old_packs(db);
	old_formats(db);
	if (fails) {
		printf("view_oldpack: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("view_oldpack: version 1 fields where they were, the row counts zero, old modules reported not trusted - ok\n");
	return 0;
}
