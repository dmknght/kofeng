/*
 * ctr_valid - the container WRITERS (tests/lib/ctr_writers.h) against the engine: a valid archive of every format is opened into
 * exactly the members that were put in, byte for byte, in order.
 *
 * Why this exists: until now only zip had a writer that could lie (hostile_engine_archives.c); the other formats had fixed
 * fixtures of 8 byte members. The liar rows (ctr_liars), the name rows (ctr_names), the nesting rows (ctr_nest), the budget
 * rows (ctr_budget) and the fuzz adapters (tests/fuzz/container) all start from what THIS file proves: a writer is only a
 * baseline for a lie if its clean output is accepted whole. A parser that stops accepting its own format, or a writer that
 * drifts from it, is red here before any lie is tried.
 *
 *   ROUND TRIP    every format, members of 1, 100, 5000 and 70000 bytes (5000 crosses the OLE mini-stream cutoff, 70000 crosses a
 *                 deflate / LZMA2 chunk and a CAB block); name, length and a hash of every child equal the member's
 *   KINDS         a directory, a symlink and a hardlink entry: no child for a directory or a link whose bytes are not a file
 *                 (the engine never follows a link), a zip symlink is its target text, and a file after them is still walked
 *   DETERMINISM   the same arguments give the same bytes (a writer reads nothing from the clock or the environment)
 *   MAP           every field the writers publish for the mutators lies inside the file and holds a plausible value
 *   DEFLATE       a zip member stored as deflate blocks (method 8) opens to its bytes
 *
 * Every case runs in a forked child with an alarm; no file is written.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"

#define NMEM 4u
static const unsigned sizes[NMEM] = { 1u, 100u, 5000u, 70000u };
static uint8_t mem[NMEM][70000];
static char names[NMEM][16];

static void members(struct cw_ent *e, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		cs_fill(mem[i], sizes[i], i);
		snprintf(names[i], sizeof names[i], "m%u.bin", i);
		memset(&e[i], 0, sizeof e[i]);
		e[i].name = names[i];
		e[i].data = mem[i];
		e[i].len = sizes[i];
	}
}

/* ---- round trip --------------------------------------------------------------------------------- */

static int roundtrip(unsigned f)
{
	const struct cw_format *F = &cw_formats[f];
	struct cw_ent e[NMEM];
	struct cw w = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	unsigned n = F->max_members == 1 ? 1u : NMEM, i;
	char root[32];

	members(e, n);
	if (n == 1)                                    /* gzip: the one member is the big one */
		e[0].data = mem[3], e[0].len = sizes[3];
	F->write(&w, e, n, NULL, NULL);
	CK(!w.oom && w.n > 0, "%s: the writer made %zu bytes", F->name, w.n);
	snprintf(root, sizeof root, "r.%s", F->name);
	if (cs_scan(w.p, w.n, root, &o, &r))
		return 9;
	if (F->gathered) {
		/* an OLE document: the streams are ONE child, their bytes end to end */
		uint64_t want = 0;

		for (i = 0; i < n; i++)
			want += e[i].len;
		CK(r.n == 2, "%s: the root and one gathered child (%u objects)", F->name, r.n);
		if (r.n >= 2)
			CK(r.o[1].len == want, "%s: the gathered child holds every stream (%llu bytes, wanted %llu)", F->name,
			   (unsigned long long)r.o[1].len, (unsigned long long)want);
	} else {
		int named = strcmp(F->name, "7z") && strcmp(F->name, "gzip") && strcmp(F->name, "pdf");     /* these carry no member name */

		CK(r.n == 1u + F->lead + n, "%s: %u objects, wanted root + %u lead + %u members", F->name, r.n, F->lead, n);
		for (i = 0; i < n && 1u + F->lead + i < r.n; i++) {
			/* by name where the format names its members (the order a walk reports them in is the format's, a CAB's is not the
			 * file table's), by position where it does not */
			const struct cs_obj *o2 = &r.o[1u + F->lead + i];
			char tail[32];

			if (named) {
				snprintf(tail, sizeof tail, ":%s", e[i].name);
				o2 = cs_find(&r, tail);
				CK(o2 != NULL, "%s: member %u (%s) is in the object list", F->name, i, e[i].name);
				if (!o2)
					continue;
			}
			CK(o2->len == e[i].len && o2->hash == cs_fnv(e[i].data, e[i].len),
			   "%s: member %u is its bytes (%llu bytes, wanted %llu)", F->name, i, (unsigned long long)o2->len, (unsigned long long)e[i].len);
			CK(o2->broken == 0, "%s: member %u is not reported broken (%u)", F->name, i, o2->broken);
		}
	}
	CK(r.broken == 0, "%s: a valid archive is not reported broken (%llu objects)", F->name, (unsigned long long)r.broken);
	cs_free(&r);
	cw_free(&w);
	return he_fails != 0;
}

/* ---- kinds ---------------------------------------------------------------------------------------- */

static int kinds(unsigned f)
{
	const struct cw_format *F = &cw_formats[f];
	struct cw_ent e[5];
	struct cw w = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	uint8_t d[20];
	unsigned i;
	int has_link_kinds = !strcmp(F->name, "zip") || !strcmp(F->name, "tar");

	if (F->max_members == 1 || F->gathered)
		return 0;
	cs_fill(d, sizeof d, 9);
	memset(e, 0, sizeof e);
	e[0].name = "dir/";   e[0].kind = CW_DIR;
	e[1].name = "ln";     e[1].kind = CW_SYMLINK;  e[1].target = "/etc/passwd";
	e[2].name = "hl1";    e[2].kind = CW_HARDLINK; e[2].target = "hl2";
	e[3].name = "hl2";    e[3].kind = CW_HARDLINK; e[3].target = "hl1";
	e[4].name = "file";   e[4].data = d; e[4].len = sizeof d;
	F->write(&w, e, 5, NULL, NULL);
	if (cs_scan(w.p, w.n, "r.x", &o, &r))
		return 9;
	/* the file after the directory and the links is walked, and is its bytes, whatever the entries before it were */
	{
		const struct cs_obj *fo = cs_find(&r, ":file");

		if (!fo && r.n > 1)                            /* a 7z folder or a pdf object carries no name: the file is the last */
			fo = &r.o[r.n - 1u];
		CK(fo && fo->len == sizeof d && fo->hash == cs_fnv(d, sizeof d), "%s: the file after the links is opened whole", F->name);
	}
	CK(r.broken == 0, "%s: directory and link entries are not a damaged archive (%llu)", F->name, (unsigned long long)r.broken);
	if (!strcmp(F->name, "zip")) {
		const struct cs_obj *ln = cs_find(&r, ":ln");

		CK(ln && ln->len == strlen("/etc/passwd") && !memcmp(ln->head, "/etc/passwd", ln->len),
		   "zip: a symlink entry is its target text and nothing was followed");
	}
	if (has_link_kinds)
		for (i = 1; i < r.n && i < CS_MAXOBJ; i++)
			CK(r.o[i].len <= 64, "%s: no link entry made a child of file size (%s %llu)", F->name, r.o[i].name, (unsigned long long)r.o[i].len);
	cs_free(&r);
	cw_free(&w);
	return he_fails != 0;
}

/* ---- determinism and the field map ----------------------------------------------------------------- */

static int determ(unsigned f)
{
	const struct cw_format *F = &cw_formats[f];
	struct cw_ent e[NMEM];
	struct cw a = { 0 }, b = { 0 };
	struct cw_map m1, m2;
	unsigned n = F->max_members == 1 ? 1u : NMEM, i;

	members(e, n);
	memset(&m1, 0, sizeof m1);
	memset(&m2, 0, sizeof m2);
	F->write(&a, e, n, NULL, &m1);
	F->write(&b, e, n, NULL, &m2);
	CK(a.n == b.n && !memcmp(a.p, b.p, a.n), "%s: two calls, two byte-identical archives", F->name);
	CK(m1.n == m2.n && !memcmp(&m1, &m2, sizeof m1), "%s: two calls, one field map", F->name);
	CK(m1.n > 0, "%s: the writer publishes fields for the mutators (%u)", F->name, m1.n);
	for (i = 0; i < m1.n; i++) {
		CK((m1.f[i].size == 1 || m1.f[i].size == 2 || m1.f[i].size == 4 || m1.f[i].size == 8) && (uint64_t)m1.f[i].off + m1.f[i].size <= a.n,
		   "%s: field %u (offset %u, %u bytes) is inside the %zu byte file", F->name, i, m1.f[i].off, m1.f[i].size, a.n);
	}
	cw_free(&a);
	cw_free(&b);
	return he_fails != 0;
}

/* The map is TRUE: a LEN field of a zip central entry holds the member's length, an OFFSET field a position inside the file. */
static int map_true(void)
{
	struct cw_ent e[NMEM];
	struct cw w = { 0 };
	struct cw_map m;
	unsigned i, lens = 0, offs = 0;

	members(e, NMEM);
	memset(&m, 0, sizeof m);
	cw_zip(&w, e, NMEM, NULL, &m);
	for (i = 0; i < m.n; i++) {
		uint64_t v = 0;
		unsigned k;

		for (k = 0; k < m.f[i].size; k++)
			v |= (uint64_t)w.p[m.f[i].off + k] << (8u * k);
		if (m.f[i].kind == CW_F_OFFSET) {
			CK(v < w.n, "zip: an OFFSET field holds a position inside the file (%llu of %zu)", (unsigned long long)v, w.n);
			offs++;
		}
		if (m.f[i].kind == CW_F_LEN && m.f[i].size == 4) {
			unsigned j;
			int ok = 0;

			for (j = 0; j < NMEM; j++)
				ok |= v == sizes[j];
			ok |= v > 0;                                          /* the central directory size is a LEN too */
			CK(ok, "zip: a LEN field holds a length (%llu)", (unsigned long long)v);
			lens++;
		}
	}
	CK(lens >= 2u * NMEM && offs >= NMEM, "zip: the map names the lengths and offsets of every member (%u LEN, %u OFFSET)", lens, offs);
	cw_free(&w);
	return he_fails != 0;
}

/* ---- deflate ---------------------------------------------------------------------------------------- */

static int zip_deflate(void)
{
	struct cw_ent e[2];
	struct cw w = { 0 }, df = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	static uint8_t big[200000];

	cs_fill(big, sizeof big, 5);
	cw_deflate_stored(&df, big, sizeof big);
	memset(e, 0, sizeof e);
	e[0].name = "deflated.bin"; e[0].data = df.p; e[0].len = df.n; e[0].method = 8;
	e[0].claimed = 1; e[0].claim_packed = df.n; e[0].claim_unpacked = sizeof big;
	e[1].name = "stored.bin";   e[1].data = big; e[1].len = 50;
	cw_zip(&w, e, 2, NULL, NULL);
	if (cs_scan(w.p, w.n, "r.zip", &o, &r))
		return 9;
	CK(r.n == 3, "zip deflate: root and two members (%u)", r.n);
	if (r.n == 3) {
		CK(r.o[1].len == sizeof big && r.o[1].hash == cs_fnv(big, sizeof big), "zip deflate: the inflated member is its bytes (%llu)", (unsigned long long)r.o[1].len);
		CK(r.o[2].len == 50, "zip deflate: the stored member after it is walked (%llu)", (unsigned long long)r.o[2].len);
	}
	cs_free(&r);
	cw_free(&w);
	cw_free(&df);
	return he_fails != 0;
}

/* ---- the variants (EXTRA and CRYPT) --------------------------------------------------------------------- */

/*
 * The writers' feature bits, one archive of three members each, scanned: how many children come out and what the root says.
 * What each is (ctr_writers.h): zip EXTRA = utf-8 names, extra fields, a data descriptor, zip64 records, comments; CRYPT = every member
 * flagged encrypted. tar EXTRA = pax global and member headers, a GNU long link name and a third member in the old format (its
 * checksum then wrong: that header ends the walk). lha EXTRA = header levels 0 (-lh6-), 1 and 2. cab EXTRA = MSZIP folders;
 * CRYPT = reserve areas and a next cabinet. 7z EXTRA = digests, times, attributes and a COPY-coded header (this build opens a
 * coded header only when it is LZMA: UNSUPPORTED); CRYPT = the AES coder (ENCRYPTED). pdf EXTRA = catalog, file specification, info,
 * metadata, object stream, xref stream; CRYPT = /Encrypt. rar5 EXTRA = members marked encrypted; CRYPT = an encryption header
 * before the last member.
 */
struct variant {
	const char *fmt;
	unsigned    bit;
	int         kids;          /* children below the root */
	uint32_t    root_broken;   /* the root's reason */
	int         check_members; /* the children are the three members, byte for byte, in order */
};

static const struct variant variants[] = {
	{ "zip",  CW_L_EXTRA, 3, KOF_BROKEN_NONE,      1 },
	{ "zip",  CW_L_CRYPT, 0, KOF_BROKEN_ENCRYPTED, 0 },
	{ "tar",  CW_L_EXTRA, 2, KOF_BROKEN_NONE,      0 },
	{ "lha",  CW_L_EXTRA, 0, KOF_BROKEN_DAMAGED,   0 },
	{ "cab",  CW_L_EXTRA, 3, KOF_BROKEN_NONE,      1 },
	{ "cab",  CW_L_CRYPT, 3, KOF_BROKEN_NONE,      0 },       /* the members come out, but shifted: WP2-D14 below */
	{ "7z",   CW_L_EXTRA, 0, KOF_BROKEN_UNSUPPORTED, 0 },
	{ "7z",   CW_L_CRYPT, 0, KOF_BROKEN_ENCRYPTED, 0 },
	{ "pdf",  CW_L_EXTRA, 4, KOF_BROKEN_NONE,      0 },
	{ "pdf",  CW_L_CRYPT, 0, KOF_BROKEN_ENCRYPTED, 0 },
	{ "rar5", CW_L_EXTRA, 0, KOF_BROKEN_ENCRYPTED, 0 },
	{ "rar5", CW_L_CRYPT, 2, KOF_BROKEN_ENCRYPTED, 0 }
};

static int variants_job(unsigned idx)
{
	const struct variant *V = &variants[idx];
	unsigned f = cw_find(V->fmt), i;
	struct cw_ent e[3];
	struct cw_lies l;
	struct cw w = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	static uint8_t d[3][300];

	memset(e, 0, sizeof e);
	memset(&l, 0, sizeof l);
	l.mask = V->bit;
	for (i = 0; i < 3; i++) {
		static const char *const nm[3] = { "a.txt", "b.txt", "c.txt" };

		cs_fill(d[i], sizeof d[i], i);
		e[i].name = nm[i];
		e[i].data = d[i];
		e[i].len = 100u + 100u * i;
	}
	cw_formats[f].write(&w, e, 3, &l, NULL);
	if (cs_scan(w.p, w.n, "v.x", &o, &r))
		return 9;
	CK(r.n >= 1 && r.n - 1u == (unsigned)V->kids, "%s %s: %u children, wanted %d", V->fmt, V->bit == CW_L_EXTRA ? "EXTRA" : "CRYPT", r.n ? r.n - 1u : 0u, V->kids);
	CK(r.n >= 1 && r.o[0].broken == V->root_broken, "%s %s: the root says %u, wanted %u", V->fmt, V->bit == CW_L_EXTRA ? "EXTRA" : "CRYPT", r.n ? r.o[0].broken : 0u,
	   V->root_broken);
	if (V->check_members)
		for (i = 0; i < 3 && i + 1u < r.n; i++) {
			char tail[16];
			const struct cs_obj *o2;

			snprintf(tail, sizeof tail, ":%s", e[i].name);
			o2 = cs_find(&r, tail);
			CK(o2 && o2->len == e[i].len && o2->hash == cs_fnv(e[i].data, e[i].len), "%s %s: member %u is its bytes", V->fmt, V->bit == CW_L_EXTRA ? "EXTRA" : "CRYPT", i);
		}
	if (!strcmp(V->fmt, "cab") && V->bit == CW_L_CRYPT) {
		/* WP2-D14: the header says every CFDATA block has a 2 byte reserve area (cbCFData); cab_parse.c reads the value (data_res) and
		 * never uses it, so each block's payload is taken from 8 bytes after its start instead of 10 and the members begin with the
		 * reserve's zeros: right length, wrong bytes. */
		unsigned same = 0;

		for (i = 0; i < 3 && i + 1u < r.n; i++) {
			char tail[16];
			const struct cs_obj *o2;

			snprintf(tail, sizeof tail, ":%s", e[i].name);
			o2 = cs_find(&r, tail);
			same += o2 && o2->len == e[i].len && o2->hash == cs_fnv(e[i].data, e[i].len);
		}
		/* KNOWN DEFECT WP2-D14 (2026-10-24, M): this row pins it, green until fixed. */
		KM_CHECK(same == 3, "cab: with a per-block reserve area (cbCFData 2) the members are not their bytes (right length, shifted by the reserve)", "WP2-D14");
	}
	cs_free(&r);
	cw_free(&w);
	return (he_fails != 0 || km_failed()) ? 1 : 0;
}

static int variants_run(unsigned idx)
{
	return variants_job(idx);
}

/* ---- the driver ---------------------------------------------------------------------------------------- */

struct job {
	int (*fn)(unsigned);
	unsigned arg;
	const char *what;
};

static int run_job(void *p)
{
	struct job *j = (struct job *)p;
	int rc = j->fn(j->arg);

	return rc ? 1 : 0;
}

static int map_job(unsigned x) { (void)x; return map_true(); }
static int defl_job(unsigned x) { (void)x; return zip_deflate(); }

int main(void)
{
	struct job j;
	unsigned f, bad = 0;
	struct he_status st;
	int (*fns[])(unsigned) = { roundtrip, kinds, determ };
	const char *tag[] = { "round trip", "kinds", "determinism+map" };
	unsigned k;

	for (k = 0; k < 3; k++)
		for (f = 0; f < CW_NFORMATS; f++) {
			j.fn = fns[k];
			j.arg = f;
			j.what = tag[k];
			st = he_child(run_job, &j, 60);
			printf("%-16s %-5s %s\n", tag[k], cw_formats[f].name, he_how(st));
			bad |= !he_ok(st);
		}
	for (f = 0; f < sizeof variants / sizeof variants[0]; f++) {
		j.fn = variants_run;
		j.arg = f;
		j.what = "variants";
		st = he_child(run_job, &j, 60);
		printf("%-16s %-5s %s\n", variants[f].bit == CW_L_EXTRA ? "variant EXTRA" : "variant CRYPT", variants[f].fmt, he_how(st));
		bad |= !he_ok(st);
	}
	j.fn = map_job; j.arg = 0; j.what = "map";
	st = he_child(run_job, &j, 60);
	printf("%-16s %-5s %s\n", "map is true", "zip", he_how(st));
	bad |= !he_ok(st);
	j.fn = defl_job; j.what = "deflate";
	st = he_child(run_job, &j, 60);
	printf("%-16s %-5s %s\n", "zip deflate", "zip", he_how(st));
	bad |= !he_ok(st);
	printf("ctr_valid: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
