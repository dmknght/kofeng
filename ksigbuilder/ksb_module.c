/*
 * ksb_module.c - --module: one signature source in, one artefact set out.
 */

#include "ksb.h"

/*
 * ---------------------------------------------------------------------------
 * --module: one signature source in, one artefact set out.
 *
 *     ksigbuilder --module <src.c> <artefact-dir>
 *
 * Everything the old shell driver used to do. The environment carries what a build
 * system already decides for every C project - CC, LD, KOF_INCLUDE for the SDK
 * headers, KOF_BASEDIR for the tree the source was found in - and nothing else
 * is read from anywhere.
 *
 * KOF_BASEDIR exists for one reason worth stating: two sources with the same
 * basename in different kind directories - bases/decomp/zip.c and a zip.c in
 * another kind directory - must not overwrite each other's artefacts, so the artefact
 * name carries the directory. That prefix is disambiguation, not identity; the
 * label written into the .meta is the basename, because that is what a pack is
 * named after.
 * ---------------------------------------------------------------------------
 */
/*
 * EVERY PER-MODULE FIELD, BACK TO NOTHING.
 *
 * The declarations, the pattern and range tables, the name pool and the error
 * count live in the context, and the context outlives a module: it was
 * harmless while one process compiled one module and exited. --tree with one
 * job compiles a whole tree in one process, and without this the second module
 * inherits the first's: "KOF_TARGET_NAME declared more than once", "a range
 * with this name is already declared", on a source that declares each exactly
 * once.
 *
 * Listed rather than memset over ksb->decl, because that struct also holds what
 * is not per module - the declaration names ksb_decl_init set up, and the type
 * the file name gives, which nameform_read sets right after this. Naming the
 * fields is also what makes it visible that a new one has to be added here.
 */
static void module_reset(struct ksb_ctx *ksb)
{
	int i;

	for (i = 0; i < SD_COUNT; i++) {
		ksb->decl.simple[i].count = 0;
		ksb->decl.simple[i].line = 0;
		ksb->decl.simple[i].arg[0] = 0;
	}
	/*
	 * THE COUNTS ARE NOT THE STATE.
	 *
	 * npats/nrngs/nnames going back to zero makes the next module's
	 * pattern 0 reuse uses[0] - and uses[] was never cleared, so it still
	 * held the PREVIOUS module's range list, its line numbers and its
	 * source offsets. --module runs ksb_extract_main in this process once per
	 * source, so every module after the first inherited whatever the one
	 * before it left behind.
	 *
	 * What it produced was warnings about code that does not exist. An
	 * unpacker declaring no ranges at all and searching once with
	 * kof_find_str_where was reported as "searched in 2 ranges
	 * (scan_range_code, scan_range_sym_exp)" - a pair no source in the tree
	 * contains, because the two names came from two different files - at
	 * line numbers that landed on declarations rather than on calls. And
	 * `used_unranged` persisting the other way would have SUPPRESSED the
	 * "never searched" warning for a marker that really is never searched.
	 *
	 * So the arrays are cleared, not just their counters. They are static
	 * because they are large, which is a reason to reset them here and not
	 * a reason to trust them.
	 */
	memset(ksb->lint.uses, 0, sizeof ksb->lint.uses);
	memset(ksb->lint.rng_used, 0, sizeof ksb->lint.rng_used);
	memset(ksb->decl.pats, 0, sizeof ksb->decl.pats);
	memset(ksb->decl.rngs, 0, sizeof ksb->decl.rngs);
	memset(ksb->decl.names, 0, sizeof ksb->decl.names);
	ksb->decl.npats = ksb->decl.nrngs = ksb->decl.nnames = ksb->errors = 0;
	ksb->decl.scan_mask = 0;
	ksb->decl.arch_mask = ksb->decl.subtype_mask = 0;
	ksb->decl.n_targets = ksb->decl.any_target = 0;
	memset(ksb->decl.target, 0, sizeof ksb->decl.target);
	ksb->decl.size_min = 0;
	ksb->decl.step = ksb->decl.heur_phase = ksb->decl.heur_level = ksb->decl.heur_want = 0;
	ksb->decl.n_targets = 0;
	ksb->decl.heur_name[0] = ksb->decl.heur_predict[0] = ksb->decl.content[0] = 0;
	ksb->decl.family[0] = 0;
	ksb->decl.maltype = 0;
	ksb->decl.have_name = 0;
	ksb->decl.dis_name[0] = 0;
	ksb->decl.dis_type = 0;
	ksb->decl.have_dis = 0;
	ksb->decl.scan_mask_out = 0;
	ksb->decl.nstr_out = 0;
	ksb->decl.src_text = NULL;
	ksb->decl.src_len = 0;
}

/*
 * WHAT A SIGNATURE SOURCE'S NAME MAY LOOK LIKE, AND WHAT IT IS FOR.
 *
 * One row per form. The new one is
 *
 *     virus_sality_01.c      <type>_<family>_<id>.c, all lower case
 *
 * and it is a CROSS-CHECK, not a second place to declare things. The family
 * a verdict prints still comes from KOF_TARGET_NAME in the source, where an
 * author can spell it the way it should read; a file name cannot, because
 * file names here are lower case and no rule about case tells an acronym
 * from a word - deriving the family turned "RST" into "Rst".
 *
 * WHAT THE TYPE IS DOING THERE IS MAKING THE TREE READABLE. A directory of
 * family names is a list nobody can review - they are arbitrary words, and
 * nothing about `gafgyt_00.c` next to `camfrog_00.c` says which is a botnet
 * and which is adware. With the type in front, the listing sorts into the
 * kinds of thing it holds and a reviewer can see what is covered and what is
 * not.
 *
 * So the name must AGREE with the source rather than replace it: the type in
 * front is checked against the declared one, and a signature filed under
 * virus_ that declares itself a trojan fails the build instead of sitting in
 * the wrong group for ever. The id at the end is what makes two signatures
 * over one sample distinct without anyone choosing a number by hand.
 *
 * The old form carries nothing and is accepted while the tree is moved over.
 * Retiring it is deleting `legacy_ok` and the one test that reads it.
 */
static void nameform_read(struct ksb_ctx *ksb, const char *base)
{
	char word[32];
	const char *u1, *u2, *p, *d;
	size_t n;
	int type_idx;

	ksb->decl.name_type = -1;
	ksb->decl.name_id[0] = 0;

	/*
	 * THE ID IS THE TRAILING NUMBER, AND EVERY NAME ALREADY HAS ONE.
	 *
	 * Both forms end in _<digits>.c - rst_01.c as much as
	 * virus_sality_01.c - so the id does not wait on the rename. Tying
	 * it to the new form was a mistake that would have held the variant
	 * change hostage to a hundred and forty-one files being moved.
	 */
	d = strrchr(base, '_');
	if (d) {
		for (p = d + 1; *p && *p != '.'; p++)
			if (*p < '0' || *p > '9')
				break;
		if (*p == '.' && p > d + 1 && !strcmp(p, ".c")) {
			n = (size_t)(p - d - 1);
			if (n < sizeof ksb->decl.name_id) {
				memcpy(ksb->decl.name_id, d + 1, n);
				ksb->decl.name_id[n] = 0;
			}
		}
	}

	u1 = strchr(base, '_');
	if (!u1)
		return;
	u2 = strchr(u1 + 1, '_');
	if (!u2 || u2 == u1 + 1)
		return;
	/* The tail is digits and then ".c", which is what tells this form
	 * from a legacy name that happens to have two words. */
	for (p = u2 + 1; *p && *p != '.'; p++)
		if (*p < '0' || *p > '9')
			return;
	if (p == u2 + 1 || strcmp(p, ".c") != 0)
		return;

	n = (size_t)(u1 - base);
	if (n == 0 || n >= sizeof word)
		return;
	memcpy(word, base, n);
	word[n] = 0;
	if (!kof_maltype_from_word(word, &type_idx))
		return;         /* two words, but not a type: a legacy name */

	/*
	 * LOWER CASE, ALWAYS. The name is read by people and by this parser
	 * and sorted by the shell; one file in a different case is a file
	 * that sorts somewhere else and matches nothing a reader greps for.
	 */
	for (p = base; *p; p++)
		if (*p >= 'A' && *p <= 'Z') {
			/* Named here rather than through err(), which wants a
			 * line in a source that has not been opened yet. */
			fprintf(stderr, "FAIL: %s: a signature file name is "
					"lower case throughout\n", base);
			ksb->errors++;
			return;
		}
	ksb->decl.name_type = type_idx;
}

/* The files of one module build, and the names it is known by. */
struct module_paths {
	char name[200], label[128];
	char pat[800], namefile[800], pre[800], strs[800];
	char obj[800], img[800], raw[800], blob[800], meta[800];
	const char *rel;              /* the path below the content tree */
	char target_line[128];        /* the target list, as the .meta writes it */
};

/* The artefact name and every file the build writes. */
static void module_paths(struct ksb_ctx *ksb, const char *src,
			 const char *outdir, struct module_paths *m)
{
	const char *basedir = ksb->opt.basedir;
	char work[512];
	const char *rel;

	/*
	 * The artefact name: the path below the content tree, flattened.
	 * Without a tree to be below, the basename alone - which is what a
	 * one-off build of a single file wants.
	 */
	{
		/* Resolved first, because the caller names sources relatively
		 * and KOF_BASEDIR absolutely - comparing them as given would
		 * never match and every artefact would lose its directory
		 * prefix, which is what keeps two sources of the same basename
		 * from overwriting each other. */
		static char abs[4096];
		const char *under = NULL;

		if (basedir && basedir[0] && kof_abs_path(src, abs, sizeof abs))
			under = kof_path_under(abs, basedir);
		rel = under && under[0] ? under : kof_path_base(src);
	}
	m->rel = rel;
	{
		size_t i, n = 0;

		for (i = 0; rel[i] && n + 1u < sizeof m->name; i++) {
			char c = rel[i];

			if (c == '/' || c == '\\')
				c = '_';
			m->name[n++] = c;
		}
		m->name[n] = 0;
		if (n > 2u && !strcmp(m->name + n - 2u, ".c"))
			m->name[n - 2u] = 0;
	}
	snprintf(m->label, sizeof m->label, "%s", kof_path_base(src));
	{
		size_t n = strlen(m->label);

		if (n > 2u && !strcmp(m->label + n - 2u, ".c"))
			m->label[n - 2u] = 0;
	}

	snprintf(work, sizeof work, "%s", outdir);
	snprintf(m->pat, sizeof m->pat, "%s/%s.pat.h", work, m->name);
	snprintf(m->namefile, sizeof m->namefile, "%s/%s.names", outdir, m->name);
	snprintf(m->strs, sizeof m->strs, "%s/%s.strs", outdir, m->name);
	snprintf(m->pre, sizeof m->pre, "%s/%s.pre", work, m->name);
	snprintf(m->obj, sizeof m->obj, "%s/%s.o", work, m->name);
	snprintf(m->img, sizeof m->img, "%s/%s.elf", work, m->name);
	snprintf(m->raw, sizeof m->raw, "%s/%s.raw", work, m->name);
	snprintf(m->blob, sizeof m->blob, "%s/%s.blob", outdir, m->name);
	snprintf(m->meta, sizeof m->meta, "%s/%s.meta", outdir, m->name);
}

/* The declarations, the patterns and the name table, in this process. */
static int module_extract(struct ksb_ctx *ksb, char *argv0, const char *src,
			  struct module_paths *m)
{
	char *xargv[6];

	xargv[0] = argv0;
	{
		static char x_extract[] = "--extract";

		xargv[1] = x_extract;
	}
	xargv[2] = (char *)(size_t)src;   /* ksb_extract_main does not write it */
	xargv[3] = m->pat;
	xargv[4] = m->namefile;
	xargv[5] = m->pre;
	{
		char *xa[7];

		xa[0] = xargv[0]; xa[1] = xargv[1]; xa[2] = xargv[2];
		xa[3] = xargv[3]; xa[4] = m->namefile; xa[5] = xargv[5];
		xa[6] = m->strs;
		ksb->src_name = src;
		if (ksb_extract_main(ksb, 7, xa) != 0)
			return 0;
	}
	return 1;
}

/* The blob is what the linker wrote; copying it is the only step that
 * moves bytes, and it moves them unchanged. Zero, or the exit code. */
static int module_copy_blob(const struct module_paths *m, long *blob_len)
{
	char *bytes;
	size_t n;
	FILE *o;

	bytes = ksb_slurp(m->raw, &n);
	if (!bytes) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", m->raw);
		return 1;
	}
	o = fopen(m->blob, "wb");
	if (!o) {
		free(bytes);
		fprintf(stderr, "ksigbuilder: cannot write %s\n", m->blob);
		return 2;
	}
	fwrite(bytes, 1, n, o);
	fclose(o);
	free(bytes);
	*blob_len = (long)n;
	return 0;
}

/* The .meta record the pack reads back. Zero, or the exit code. */
static int module_write_meta(struct ksb_ctx *ksb, struct module_paths *m,
			     const char *src, int kind, long blob_len)
{
	FILE *f;

	f = fopen(m->meta, "w");
	if (!f) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", m->meta);
		return 2;
	}
	ksb_target_text(ksb, m->target_line, sizeof m->target_line);
	fprintf(f, "target=%s\n", m->target_line);
	fprintf(f, "anytarget=%d\n", ksb->decl.any_target);
	fprintf(f, "scan_mask=%lu\n", ksb->decl.scan_mask_out);
	fprintf(f, "size_min=%llu\n", (unsigned long long)ksb->decl.size_min);
	fprintf(f, "arch_mask=%u\n", ksb->decl.arch_mask);
	fprintf(f, "subtype_mask=%u\n", ksb->decl.subtype_mask);
	fprintf(f, "step=%d\n", ksb->decl.step);
	fprintf(f, "heur_phase=%d\n", ksb->decl.heur_phase);
	fprintf(f, "heur_want=%d\n", ksb->decl.heur_want);
	fprintf(f, "heur_level=%d\n", ksb->decl.heur_level);
	fprintf(f, "cure_off=%llu\n", (unsigned long long)ksb->kept.cure);
	fprintf(f, "heur_predict=%s\n", ksb->decl.heur_predict);
	fprintf(f, "content=%s\n", ksb->decl.content);
	/* A heuristic rule has no family; its word goes in the same slot, and
	 * the engine writes "Heur" where a maltype would be. */
	fprintf(f, "family=%s\n", kind == 2 ? ksb->decl.heur_name
					    : (ksb->decl.have_name ? ksb->decl.family : ""));
	fprintf(f, "maltype=%d\n", kind == 2 ? 0
					     : (ksb->decl.have_name ? ksb->decl.maltype : 0));
	fprintf(f, "disease=%s\n", ksb->decl.have_dis ? ksb->decl.dis_name : "");
	fprintf(f, "disease_type=%d\n", ksb->decl.have_dis ? ksb->decl.dis_type : 0);
	fprintf(f, "nstr=%d\n", ksb->decl.nstr_out);
	fprintf(f, "blob_len=%ld\n", blob_len);
	fprintf(f, "kind=%d\n", kind);
	fprintf(f, "label=%s\n", m->label);
	/* The path INSIDE the content tree, which is what a tool holding a scan
	 * result opens to find the source. Empty when the source was not under
	 * one, because then there is no tree-relative name to give. */
	fprintf(f, "srcpath=%s\n", m->rel != src ? m->rel : "");
	fclose(f);
	return 0;
}

/*
 * THE SCAFFOLDING GOES, AND THE FOUR FILES THE PACK READS STAY.
 *
 * A module leaves nine files behind: .blob, .meta, .strs and .names,
 * which ksb_pack_main reads, and .pat.h, .pre, .o, .elf and .raw, which
 * nothing reads once the blob exists - they are the compiler's and the
 * linker's working copies.
 *
 * At the shipping size that is 181 files nobody notices. At 200 000 it
 * is 1,801,629 files and 6.9 GB on a LUKS-backed filesystem, and it is
 * why the build took 2317 seconds when the work itself is 20 ms a rule
 * (334 s across twelve jobs): the time went into creating, writing and
 * later deleting a million files that exist for no reader.
 *
 * Removing them cannot lose anything - they are regenerated by building
 * the source again, which is what anyone debugging a module does
 * anyway. KOF_KEEP_WORK keeps them for exactly that.
 */
static void module_cleanup(const struct ksb_ctx *ksb,
			   const struct module_paths *m)
{
	if (!ksb->opt.keep_work) {
		remove(m->pat);
		remove(m->pre);
		remove(m->obj);
		remove(m->img);
		remove(m->raw);
	}
}

int ksb_module_main(struct ksb_ctx *ksb, int argc, char **argv)
{
	const char *src = argc > 2 ? argv[2] : NULL;
	const char *outdir = argc > 3 ? argv[3] : NULL;
	const char *lds = ksb->opt.ldscript;
	struct module_paths m;
	const char *entry = NULL;
	long blob_len;
	int kind, rc;

	if (argc != 4 || !src || !outdir) {
		fprintf(stderr, "usage: %s --module <src.c> <artefact-dir>\n",
			argv[0]);
		return 2;
	}
	if (!lds || !lds[0]) {
		fprintf(stderr, "ksigbuilder: KOF_LDSCRIPT is not set\n");
		return 2;
	}

	module_paths(ksb, src, outdir, &m);

	module_reset(ksb);
	/*
	 * AFTER the reset, because the reset is what clears it, and BEFORE
	 * the source is read, so a KOF_TARGET_NAME line in a file whose name
	 * already gives the type and family is caught as the duplication it
	 * is - see nameform_typed.
	 */
	nameform_read(ksb, kof_path_base(src));
	printf("== %s\n", src);

	if (!module_extract(ksb, argv[0], src, &m))
		return 1;

	if (!ksb_check_format_headers(ksb))
		return 1;
	if (!ksb_check_size_body(ksb))
		return 1;

	if (!ksb_do_build(ksb, src, m.pat, m.obj, m.img, m.raw, lds, &entry))
		return 1;

	if (!strcmp(entry, "kof_heur"))
		kind = 2;
	else if (!strcmp(entry, "kof_unpack"))
		kind = 1;
	else
		kind = 0;
	if (!ksb_kind_checks(ksb, kind))
		return 1;

	rc = module_copy_blob(&m, &blob_len);
	if (rc)
		return rc;
	rc = module_write_meta(ksb, &m, src, kind, blob_len);
	if (rc)
		return rc;
	module_cleanup(ksb, &m);

	printf("== ok  %s  %ld bytes  kind=%s  strs=%d  target=%s scan=0x%lx\n",
	       m.blob, blob_len,
	       kind == 2 ? "heur" : kind == 1 ? "unpack" : "detect",
	       ksb->decl.nstr_out, ksb->decl.any_target ? "any" : m.target_line,
	       ksb->decl.scan_mask_out);
	return 0;
}
