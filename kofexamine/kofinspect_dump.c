#define _GNU_SOURCE

/*
 * kofinspect_dump.c - writing an object out: the directory name, one file per
 * region, the LAYOUT file and the walk over a recovered tree. Split from
 * kofinspect.c by job, no logic changed; see kofinspect.h for the API.
 */

#include "kofinspect_private.h"

/* ---- writing an object out ------------------------------------------------ */

#define DUMP_NAME_MAX  255            /* what a filesystem component usually holds */
#define DUMP_KEEP_MAX  48             /* readable prefix retained when shortening */

/* Bytes a dump name may carry as they are: anything else is replaced, so a name
 * out of a file cannot become a separator or a parent reference. */
static int name_char_ok(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

static const char *base_of(const char *path)
{
	return kof_path_base(path);
}

static void dump_dir_name(const char *base, char *out, size_t cap)
{
	size_t n = strlen(base), i, keep = 0;
	int clean = 1;

	for (i = 0; i < n; i++)
		if (!name_char_ok((unsigned char)base[i])) {
			clean = 0;
			break;
		}

	if (clean && n + sizeof "__dump" - 1 <= DUMP_NAME_MAX &&
	    n + sizeof "__dump" < cap) {
		snprintf(out, cap, "_%s_dump", base);
		return;
	}

	/* Dropping to a bare checksum would be simpler and would make every
	 * result unrecognisable. */
	while (keep < n && keep < DUMP_KEEP_MAX &&
	       name_char_ok((unsigned char)base[keep]))
		keep++;
	snprintf(out, cap, "_%.*s%s%08x_dump", (int)keep, base, keep ? "-" : "",
		 kof_crc32(base, n));
}

int kof_dump_dir_for(const char *path, char *out, uint32_t cap)
{
	const char *base = base_of(path);
	size_t lead = (size_t)(base - path);
	char name[DUMP_NAME_MAX + 1];

	dump_dir_name(base, name, sizeof name);
	if (lead + strlen(name) + 1 > cap)
		return 0;
	memcpy(out, path, lead);
	memcpy(out + lead, name, strlen(name) + 1);
	return 1;
}

/* One sentence for the caller to show, and 0, in one statement at every site
 * that has something to say. */
static int dump_fail(char *err, uint32_t cap, const char *what, const char *at)
{
	if (err && cap)
		snprintf(err, cap, "%s %.200s", what, at);
	return 0;
}

/*
 * EVERY FILE A DUMP WRITES IS OPENED THROUGH kof_fopen_trunc, AND NOT fopen.
 *
 * The dump directory's name is derived from the sample's own - see
 * kof_dump_dir_for - so every path under it is predictable by whoever put the
 * sample there, and a sample is routinely examined where it was found: an
 * extracted archive, a shared drop directory, somebody else's tree. fopen(,"wb")
 * follows a symlink and takes its mode from the umask, so a planted
 * "_sample_dump/01.KGENOME_SCAN_ELF_CODE" pointing elsewhere makes the dumper write
 * the sample's bytes through it.
 *
 * kof_fopen_trunc is O_CREAT|O_TRUNC|O_NOFOLLOW at 0600 - the same create-or-
 * truncate this had, refusing the link, and not readable by the rest of the
 * machine. It is what kofevt_log_create already uses, for a file that is also
 * rewritten on purpose; kof_fopen_new is the wrong one here, because re-dumping
 * a sample must overwrite the last dump rather than fail.
 *
 * On Windows the LAYOUT file below loses its CRLF translation with the mode
 * change, which is the whole cost: it is written LF-only, like every other text
 * this toolset emits.
 */
static int dump_write(const char *path, const void *bytes, uint64_t len,
		      char *err, uint32_t err_cap)
{
	FILE *f = kof_fopen_trunc(path);

	if (!f)
		return dump_fail(err, err_cap, "cannot write", path);
	if (len && fwrite(bytes, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		return dump_fail(err, err_cap, "short write to", path);
	}
	if (fclose(f) != 0)
		return dump_fail(err, err_cap, "cannot write", path);
	return 1;
}

/*
 * Every extent of every region, in file order.
 *
 * The numbered files say where each region begins; this says where each run of
 * each region is, which is the layout itself. It is also where the partition
 * claim becomes checkable line by line: consecutive rows are adjacent, the first
 * starts at zero and the last ends at the object size, or one of those is not
 * true and the row it breaks on says which region got it wrong.
 */
struct layout_row {
	uint64_t    off, len;
	const char *name;
};

uint32_t kof_declared_regions(const struct kof_scan_region *rgn, uint32_t n_rgn,
			      uint32_t scan_mask, struct kof_range *out,
			      uint32_t max_out)
{
	uint32_t i, n = 0;

	if (!rgn || !out || !max_out)
		return 0;
	for (i = 0; i < n_rgn && n < max_out; i++) {
		/* A row of no length says the region is not in this object,
		 * which is the same answer as no row at all - see
		 * declared_resolve_scan in the engine, which drops them too. */
		if (!(rgn[i].mask & scan_mask) || !rgn[i].len)
			continue;
		out[n].off = rgn[i].off;
		out[n].len = rgn[i].len;
		n++;
	}
	return n;
}

static int dump_layout(const char *dir, const struct kof_parser *f,
		       const struct kof_obj_ctx *ctx, char *err, uint32_t err_cap)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	static struct layout_row row[KOF_SCAN_MAX_EXTENTS * 8];
	char path[KOF_DUMP_PATH_ROOM];
	uint32_t nrow = 0, i, k, j;
	FILE *out;

	for (i = 0; i < f->n_regions; i++) {
		const char *rn = f->region_name(f->regions[i]);
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, f->regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS) : 0;
		for (k = 0; k < n && nrow < sizeof row / sizeof row[0]; k++) {
			row[nrow].off = ext[k].off;
			row[nrow].len = ext[k].len;
			row[nrow].name = rn ? rn : "?";
			nrow++;
		}
	}
	for (i = 1; i < nrow; i++) {
		struct layout_row t = row[i];
		for (j = i; j > 0 && row[j - 1].off > t.off; j--)
			row[j] = row[j - 1];
		row[j] = t;
	}

	if ((size_t)snprintf(path, sizeof path, "%s/LAYOUT", dir) >= sizeof path)
		return dump_fail(err, err_cap, "path too long under", dir);
	out = kof_fopen_trunc(path);   /* see dump_write */
	if (!out)
		return dump_fail(err, err_cap, "cannot write", path);
	fprintf(out, "%-12s %-12s %s\n", "offset", "length", "region");
	for (i = 0; i < nrow; i++)
		fprintf(out, "%-12llu %-12llu %s\n",
			(unsigned long long)row[i].off,
			(unsigned long long)row[i].len, row[i].name);
	if (fclose(out) != 0)
		return dump_fail(err, err_cap, "cannot write", path);
	return 1;
}

static int dump_region(const char *dir, uint32_t rank, const char *region,
		       const struct kof_obj_ctx *ctx, kof_buf buf, uint32_t bit,
		       uint64_t *out_len, char *err, uint32_t err_cap)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	char name[KOF_DUMP_PATH_ROOM];
	uint32_t n, i;
	FILE *f;

	*out_len = 0;
	n = ctx->resolve_scan ? ctx->resolve_scan(ctx, bit, ext,
						  KOF_SCAN_MAX_EXTENTS) : 0;
	if (n == 0)
		return 1;                /* an empty region is not a failure */

	/* The directory already names the object, and the region's enum identifier
	 * already names the format, so the file is just the region. */
	if ((size_t)snprintf(name, sizeof name, "%s/%02u.%s", dir, rank, region)
	    >= sizeof name)
		return dump_fail(err, err_cap, "path too long under", dir);
	f = kof_fopen_trunc(name);     /* see dump_write */
	if (!f)
		return dump_fail(err, err_cap, "cannot write", name);
	for (i = 0; i < n; i++) {
		/*
		 * CLIPPED TO THE OBJECT, because an extent is not a promise.
		 *
		 * resolve_scan is a FUNCTION POINTER, and the thing behind it
		 * is not always a format parser that bounded its own answer.
		 * kof_declared_regions is one of the producers - it copies the
		 * off/len an unpacked child DECLARED, and it is handed no
		 * object size to check them against - so an extent arriving
		 * here can run past the bytes it claims to describe.
		 *
		 * Unclipped, this fwrite reads whatever follows the object in
		 * memory and writes it into a file on disk: a crash on the good
		 * day, and somebody else's heap in the dump on the bad one.
		 *
		 * This is the engine's own rule and not a new one. match_ranges
		 * clips every extent before searching it and says why: "an
		 * extent is produced by a format collector and describes the
		 * object it was parsed from, so it should already fit - but the
		 * two ad-hoc entry points do not trust that either."
		 * kof_inspect_region_entropy, in this file, clips for the same
		 * reason. This was the one reader that took the length on
		 * trust.
		 */
		uint64_t len = kof_clip_len(buf.n, ext[i].off, ext[i].len);

		if (!len)
			continue;
		if (fwrite(buf.p + ext[i].off, 1, (size_t)len, f)
		    != (size_t)len) {
			fclose(f);
			return dump_fail(err, err_cap, "short write to", name);
		}
		*out_len += len;
	}
	if (fclose(f) != 0)
		return dump_fail(err, err_cap, "cannot write", name);
	return 1;
}

int kof_dump_object(const char *dir, kof_buf buf,
		    const struct kof_parser *f,
		    const struct kof_obj_ctx *ctx,
		    struct kof_dump_stat *st, char *err, uint32_t err_cap)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	char path[KOF_DUMP_PATH_ROOM];
	uint64_t first[16];
	uint32_t order[16], nord = 0, i, k;

	if (st)
		memset(st, 0, sizeof *st);
	if (err && err_cap)
		err[0] = 0;
	if (kof_mkdir(dir, 0777) != 0 && errno != EEXIST)
		return dump_fail(err, err_cap, "cannot create", dir);

	/*
	 * The whole object, numbered 00 so it sorts before the regions and reads
	 * as what it is: the thing the others are parts of. Named KOF_SCAN_ALL
	 * rather than "full" or the object's own filename because that is what
	 * the engine calls the whole of an object - one vocabulary in the
	 * directory rather than two.
	 *
	 * Worth having even though the caller usually has the file, because a
	 * dump is often taken of something that never was a file: for a
	 * recovered child this is the only copy outside the scan.
	 */
	if (buf.n) {
		if ((size_t)snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", dir)
		    >= sizeof path)
			return dump_fail(err, err_cap, "path too long under", dir);
		if (!dump_write(path, buf.p, buf.n, err, err_cap))
			return 0;
		if (st)
			st->whole_bytes = buf.n;
	}

	if (!f || !ctx)
		return 1;

	/* Ordered by where each one begins. A region with no extents is not
	 * written and does not take a number, so the numbers are contiguous over
	 * what is actually there. */
	for (i = 0; i < f->n_regions && nord < 16; i++) {
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, f->regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS) : 0;
		if (n == 0)
			continue;
		first[nord] = ext[0].off;
		order[nord] = i;
		nord++;
	}
	for (i = 1; i < nord; i++) {
		uint64_t fo = first[i];
		uint32_t oi = order[i];

		for (k = i; k > 0 && first[k - 1] > fo; k--) {
			first[k] = first[k - 1];
			order[k] = order[k - 1];
		}
		first[k] = fo;
		order[k] = oi;
	}

	for (i = 0; i < nord; i++) {
		uint64_t len;

		if (!dump_region(dir, i + 1,
				 f->region_name(f->regions[order[i]]),
				 ctx, buf, f->regions[order[i]], &len,
				 err, err_cap))
			return 0;
		if (len && st) {
			st->regions++;
			st->region_bytes += len;
		}
	}

	return dump_layout(dir, f, ctx, err, err_cap);
}


/*
 * WHERE AN OBJECT'S DUMP BELONGS, as a path under the dump root.
 *
 * HERE AND NOT IN THE ENGINE, although it reads the engine's names. A dump
 * directory is a thing a TOOL makes on a disk, and the engine has no business
 * with it - the same line kofscanner's own usage draws when it says what to
 * keep is policy. What the engine publishes is the VOCABULARY - KOF_OBJ_SEP,
 * kobj_toplevel_len, KOF_OBJ_LABEL_NORM - and this spells a path out of it.
 *
 * THE ENGINE ALREADY KNOWS THE TREE AND THE TOOLS WERE THROWING IT AWAY. An
 * object's name carries its whole descent - "f//0//1:norm" is the normalised
 * view of the second child of the first child - and both front ends dumped
 * with a FLAT counter instead, so every object in a file landed in one
 * directory as siblings. Measured on 111.exe, which is VMProtect under MPRESS:
 * four objects three levels deep came out as `unpacked.1`, `unpacked.2`,
 * `unpacked.3` and `unpacked.4.norm` beside one another, and the last is a
 * rendering OF the third. A reader cannot tell what came out of what, which is
 * the one thing the tree was for.
 *
 * So the placement is computed here, from the engine's own name, and both
 * tools ask rather than each inventing a scheme. "f//0//1:norm" gives
 * "0/1.norm"; the file itself gives "", which is the dump root.
 *
 * A VIEW IS NOT A CHILD AND IS NOT GIVEN A LEVEL OF ITS OWN. `norm` is the
 * same bytes seen another way - see KOF_OBJ_LABEL_NORM - so it hangs off its
 * object's own name rather than becoming a directory beneath it. A label that
 * is not a view names the child and does the same, because a label is a word
 * about the child rather than a step down.
 *
 * Returns the length written, or 0 when it would not fit.
 */
static uint32_t dump_rel_dir(const char *name, char *out, uint32_t cap)
{
	const char *p = name;
	uint32_t n = 0;

	if (!out || !cap)
		return 0;
	out[0] = 0;
	if (!name)
		return 0;
	/* Past the file's own name: everything before the first separator is
	 * the root and is the caller's to place. */
	p = name + kobj_toplevel_len(name);
	while (p[0] == KOF_OBJ_SEP[0] && p[1] == KOF_OBJ_SEP[1]) {
		const char *seg = p + KOF_OBJ_SEP_LEN;
		const char *e = seg;

		while (*e && !(e[0] == KOF_OBJ_SEP[0] &&
			       e[1] == KOF_OBJ_SEP[1]))
			e++;
		if (n && n + 1u < cap)
			out[n++] = '/';
		while (seg < e) {
			char c = *seg++;

			/*
			 * The ':' between an index and its label becomes a
			 * '.', and anything a path should not carry becomes
			 * '_'. A label is the engine's word and is not a file
			 * name - "3:bin/x86" holds a separator of its own, and
			 * left alone it would make a directory nobody asked
			 * for.
			 */
			if (c == ':')
				c = '.';
			else if (c == '/' || c == '\\' || c < 0x20 ||
				 (unsigned char)c > 0x7e)
				c = '_';
			if (n + 1u < cap)
				out[n++] = c;
		}
		p = e;
	}
	out[n] = 0;
	return n;
}

/*
 * ---- ONE OBJECT OF A SCAN, WRITTEN WHERE THE TREE SAYS ---------------------
 *
 * THE ONE PLACE A DUMP TREE IS LAID OUT, and there used to be two. kofexaminer
 * wrote from inside the engine's per-object callback; kofviewer kept its own
 * array of objects and looped over that afterwards. Two walks, two naming
 * schemes - `unpacked.N` against `N.label` - over one tree, and neither
 * carried the DEPTH: every object of a file landed in the dump root as
 * siblings. Measured on 111.exe, which is VMProtect under MPRESS: four objects
 * three levels apart came out as `unpacked.1` through `unpacked.4.norm`, and
 * the last is a rendering OF the third.
 *
 * The engine already knows the shape - it names an object by its whole descent
 * - so the placement is asked of it, with dump_rel_dir, and this is the only
 * caller either tool needs.
 *
 * WHAT THE ENGINE DOES AND WHAT THIS DOES. The engine answers WHERE; this
 * creates the directories and writes the bytes. That split is not tidiness: a
 * scanner that writes files is a scanner deciding what to keep, and
 * kofscanner's own usage text says that is policy and the wrong place for it.
 *
 * `root` is the dump directory for the FILE - kof_dump_dir_for's answer.
 * `name` is the engine's name for this object. The object's own bytes are
 * written as `object` at every level below the top, because at the top they
 * are already `00.KOF_SCAN_ALL`.
 */
static int dump_mkpath(const char *path, char *err, uint32_t err_cap)
{
	char tmp[KOF_DUMP_PATH_ROOM];
	size_t n = strlen(path), i;

	if (n + 1u > sizeof tmp)
		return dump_fail(err, err_cap, "path too long", path);
	memcpy(tmp, path, n + 1u);
	/* Each component in turn, so a tree three deep does not need the
	 * caller to have made the levels above it. */
	for (i = 1; i < n; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = 0;
		if (kof_mkdir(tmp, 0777) != 0 && errno != EEXIST)
			return dump_fail(err, err_cap, "cannot create", tmp);
		tmp[i] = '/';
	}
	if (kof_mkdir(tmp, 0777) != 0 && errno != EEXIST)
		return dump_fail(err, err_cap, "cannot create", tmp);
	return 1;
}

int kof_dump_walk(const char *root, const char *name, kof_buf buf,
		  const struct kof_parser *f,
		  const struct kof_obj_ctx *ctx,
		  struct kof_dump_stat *st,
		  char *dir_out, uint32_t dir_cap,
		  char *err, uint32_t err_cap)
{
	char rel[KOF_DUMP_PATH_ROOM], dir[KOF_DUMP_PATH_ROOM];

	if (err && err_cap)
		err[0] = 0;
	if (!root || !name)
		return dump_fail(err, err_cap, "no dump root for", name ? name : "?");

	dump_rel_dir(name, rel, sizeof rel);
	if (rel[0]) {
		char path[KOF_DUMP_PATH_ROOM];

		if ((size_t)snprintf(dir, sizeof dir, "%s/%s", root, rel) >=
		    sizeof dir)
			return dump_fail(err, err_cap, "path too long under",
					 root);
		if (!dump_mkpath(dir, err, err_cap))
			return 0;
		/*
		 * The bytes themselves, beside the regions rather than in
		 * them: a reader wants the recovered file whole, and a region
		 * is a view of it.
		 */
		if ((size_t)snprintf(path, sizeof path, "%s/object", dir) >=
		    sizeof path)
			return dump_fail(err, err_cap, "path too long under",
					 dir);
		if (!dump_write(path, buf.p, buf.n, err, err_cap))
			return 0;
	} else {
		if ((size_t)snprintf(dir, sizeof dir, "%s", root) >= sizeof dir)
			return dump_fail(err, err_cap, "path too long", root);
		if (!dump_mkpath(dir, err, err_cap))
			return 0;
	}
	if (dir_out && dir_cap &&
	    (size_t)snprintf(dir_out, dir_cap, "%s", dir) >= dir_cap)
		return dump_fail(err, err_cap, "path too long", dir);
	/*
	 * AND THE REGIONS, WHEN THE CALLER HAS THE PARSE IN HAND.
	 *
	 * A caller with `ctx` is one the engine has just handed an object to,
	 * and its regions are on that. A caller without it - kofexaminer, which
	 * re-identifies the bytes so it can DESCRIBE them - takes the directory
	 * back and dumps the regions from its own parse. Both write the same
	 * files in the same place; only who parsed differs.
	 */
	if (!ctx)
		return 1;
	return kof_dump_object(dir, buf, f, ctx, st, err, err_cap);
}

