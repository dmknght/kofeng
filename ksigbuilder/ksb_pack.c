/*
 * ksb_pack.c - The default mode: artefacts to packs; and the small modes that
 *    dispatch before it.
 */

#include "ksb.h"

#include <dirent.h>

#include <databases/dbpacker.h>

/*
 * GROUPING
 *
 * One pack per (kind, target set, arch_mask). Every part of that key is derived
 * from an artefact - kind from which entry point the module exported, the rest from
 * the .meta record - so nobody decides where a module goes and there is nowhere for
 * a decision to be wrong.
 *
 * By the exact mask value, not by "a format". A pack holding exactly the modules
 * whose targets are M has any_target == M, so testing an object against the pack
 * gives the same answer as testing it against every module in it: the pack-level
 * test skips exactly what the per-module test would have skipped, at one comparison
 * instead of N. Any coarser grouping - by platform, by family, by category - forces
 * the union wider than its members and starts losing modules it should have run.
 *
 * A module targeting PE and ELF together therefore gets its own pack with
 * any_target = PE|ELF, which still rules out Mach-O, script and text. That is not
 * an exception to the rule; it is the rule applied to a mask with two bits set.
 *
 *
 * WHY SUBTYPE IS NOT PART OF THE KEY
 *
 * It was, and it bought nothing, because the pack header has no field for it. There
 * is any_target, any_scan and any_arch, and no any_subtype - so a pack can never be
 * ruled out by subtype however it is grouped, and splitting by one only produced two
 * files where one would do. ELF and ELF-relocatable were separate packs of four
 * kilobytes each for a test that could not be performed.
 *
 * The filtering itself is untouched: every module carries its own subtype_mask into
 * the pack and the per-module precondition test reads it there, exactly as before.
 * What was dropped is a directory entry, not a check.
 *
 * Measured on 4004 modules, this produces 4 packs and skips almost nothing for an
 * ELF object. That is the honest result: grouping is a coarse cut and does not
 * carry scale. What carries scale is the inverted index, which is built here too
 * once it exists - see dbcore.h.
 *
 *
 * FAILURE IS FATAL
 *
 * Any artefact that cannot be read stops the run. Skipping it would produce a
 * database missing a signature, and nothing downstream can tell that from a
 * database that was never meant to have it - a detection that does not happen is
 * not something a test notices.
 */

/* The state of one pack run: the artefacts read, the groups they fall into, and
 * every path written so far this run, so a second pack cannot take a name a
 * first one already has. See the naming block above ksb_format_list. */
struct pack_run {
	struct artefact *arts;
	uint32_t n_arts, cap_arts;
	struct group *groups;
	uint32_t n_groups, cap_groups;
	char **taken;
	uint32_t n_taken;
};

	/*
	 * --image: everything the build needs to know about a linked module,
	 * in one call and from one parser.
	 *
	 * It replaces four programs - readelf twice, nm three times, size once
	 * - whose answers had to be recovered from their printed text with grep
	 * and awk. Those tools are also the ones a Windows host does not have
	 * without installing a POSIX toolchain, so this is what lets the build
	 * run with nothing but a compiler and a linker.
	 */
	/*
	 * --object is the same reader with the image-only refusals off.
	 *
	 * An OBJECT legitimately has .text, .rodata and a relocation section -
	 * that is what linking consumes. Only the LINKED IMAGE must have none
	 * of them, so applying the image's rules to an object refuses every
	 * module. What an object is asked here is the one thing that must be
	 * true before linking: that it holds no writable state.
	 */
static int pack_image_main(int argc, char **argv)
{
	int strict = strcmp(argv[1], "--image") == 0;
	struct img_facts f;

	if (argc != 4) {
		fprintf(stderr, "usage: %s --image <linked.elf> "
				"<out.blob>\n", argv[0]);
		return 2;
	}
	/*
	 * ELF or COFF, decided by what the file is rather than by a
	 * flag the caller has to pass: the build already knows which
	 * platform it is on, and a mode argument that can disagree with
	 * the file is one more thing to get wrong.
	 */
	{
		size_t n = 0;
		char *head = ksb_slurp(argv[2], &n);
		int is_elf = head && n >= 4 &&
			     (unsigned char)head[0] == 0x7f &&
			     head[1] == 'E' && head[2] == 'L' &&
			     head[3] == 'F';

		free(head);
		if (is_elf ? !ksb_img_read(argv[2], ".blob", &f)
			   : !ksb_coff_read(argv[2], &f)) {
			fprintf(stderr, "ksigbuilder: cannot read %s "
					"as ELF or COFF\n", argv[2]);
			return 2;
		}
		/* A COFF object carries no linked image to check for
		 * leftover sections, and its blob is produced by the
		 * linker rather than extracted here. */
		if (!is_elf)
			f.blob_len = 1;
	}
	if (strict && f.have_reloc) {
		fprintf(stderr, "FAIL: relocations remain (%s)\n",
			f.extra_sec);
		return 1;
	}
	if (strict && f.undef[0]) {
		fprintf(stderr, "FAIL: undefined symbol (module "
				"reached outside its blob): %s\n",
			f.undef);
		return 1;
	}
	if (strict && f.extra_sec[0]) {
		fprintf(stderr, "FAIL: unexpected section in image: "
				"%s\n", f.extra_sec);
		return 1;
	}
	if (strict && f.n_entry != 1) {
		fprintf(stderr, "FAIL: image exports %d of kof_scan, "
				"kof_unpack, kof_heur; a module is "
				"one kind\n", f.n_entry);
		return 1;
	}
	if (strict && f.entry_off != 0) {
		fprintf(stderr, "FAIL: entry point is at 0x%llx, "
				"expected 0; check module.ld\n",
			(unsigned long long)f.entry_off);
		return 1;
	}
	if (strict && !f.blob_len) {
		fprintf(stderr, "FAIL: image has no .blob section\n");
		return 1;
	}
	if (strcmp(argv[3], "/dev/null") != 0) {
		char *img;
		size_t n;
		FILE *o;

		img = ksb_slurp(argv[2], &n);
		if (!img || f.blob_off + f.blob_len > n) {
			free(img);
			fprintf(stderr, "FAIL: .blob runs past the "
					"image\n");
			return 1;
		}
		o = fopen(argv[3], "wb");
		if (!o) {
			free(img);
			fprintf(stderr, "ksigbuilder: cannot write "
					"%s\n", argv[3]);
			return 2;
		}
		fwrite(img + f.blob_off, 1, (size_t)f.blob_len, o);
		fclose(o);
		free(img);
	}
	/* What the caller still needs, on stdout so a shell can read it
	 * without a temporary file. */
	printf("entry=%s\n", f.entry_name);
	printf("blob_len=%llu\n", (unsigned long long)f.blob_len);
	printf("data=%llu\n", (unsigned long long)f.data_bytes);
	printf("bss=%llu\n", (unsigned long long)f.bss_bytes);
	return 0;
}

/* --build, whose arguments are all paths. */
/*
 * --build: compile, link, validate and emit one module.
 *
 * The middle of what the old shell driver did, moved here so the only shell
 * left in a build is the one that chose to run it. The compiler and the
 * linker are still separate programs - they have to be - but nothing
 * between them is a program any more.
 *
 *   ksigbuilder --build <src.c> <pat.h> <obj> <img> <raw> <ldscript>
 *
 * The tools come from CC and LD in the environment, defaulting to the
 * names a POSIX toolchain uses, so a caller that has already decided
 * which compiler to use - the Makefile, a cross build - says so the same
 * way every other C project does.
 */
static int pack_build_main(struct ksb_ctx *ksb, int argc, char **argv)
{
	const char *entry = NULL;

	if (argc != 8) {
		fprintf(stderr, "usage: %s --build <src.c> <pat.h> "
				"<obj> <img> <raw> <ldscript>\n",
			argv[0]);
		return 2;
	}
	if (!ksb_do_build(ksb, argv[2], argv[3], argv[4], argv[5], argv[6],
			  argv[7], &entry))
		return 1;
	printf("entry=%s\n", entry);
	return 0;
}

/* The two paths of the default mode. Zero when the command line is wrong, with
 * the usage already printed. */
static int pack_args(int argc, char **argv, const char **workdir,
		     const char **outdir)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			ksb_usage(argv[0]);
			return 0;
		} else if (!*workdir)
			*workdir = argv[i];
		else if (!*outdir)
			*outdir = argv[i];
		else {
			ksb_usage(argv[0]);
			return 0;
		}
	}
	if (!*workdir || !*outdir) {
		ksb_usage(argv[0]);
		return 0;
	}
	return 1;
}

/* Every .blob in the directory, loaded. Zero when one cannot be, or none is
 * there. */
static int pack_load(const char *workdir, struct pack_run *r)
{
	DIR *d;
	struct dirent *de;

	d = opendir(workdir);
	if (!d) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", workdir);
		return 0;
	}
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char *p;

		if (l < 6 || strcmp(de->d_name + l - 5, ".blob") != 0)
			continue;
		if (r->n_arts == r->cap_arts) {
			uint32_t nc = r->cap_arts ? r->cap_arts * 2 : 64;
			struct artefact *nv = realloc(r->arts, nc * sizeof *nv);
			if (!nv)
				goto fail;
			r->arts = nv;
			r->cap_arts = nc;
		}
		p = ksb_join_path(workdir, de->d_name);
		if (!p)
			goto fail;
		if (!ksb_artefact_load(&r->arts[r->n_arts], p)) {
			ksb_artefact_free(&r->arts[r->n_arts]);
			free(p);
			goto fail;
		}
		free(p);
		r->n_arts++;
	}
	closedir(d);

	if (r->n_arts == 0) {
		fprintf(stderr, "ksigbuilder: no .blob artefacts in %s\n", workdir);
		return 0;
	}
	return 1;
fail:
	closedir(d);
	return 0;
}

/* Sort the artefacts, gather them into groups, order the groups and say how
 * many there are. Zero when memory runs out. */
static int pack_group(struct pack_run *r)
{
	uint32_t a, j;

	/*
	 * SORTED, BECAUSE readdir ORDER IS NOT AN ORDER.
	 *
	 * The artefacts arrive in whatever sequence the filesystem hands them
	 * back, which depends on how the directory was written and is not the
	 * same twice - a rebuild after rm -rf, a different filesystem, another
	 * machine. That order survives into the pack, and the scan loop stops
	 * at the FIRST module that names a family, so it decides which of two
	 * matching signatures is the one reported.
	 *
	 * Measured while moving the build off the shell: the same 62 sources,
	 * the same 62 blobs byte for byte, packed from two directories written
	 * in different orders - 11 files came back suspected from one database
	 * and infected from the other. Nothing about that was visible in the
	 * build, which succeeded both times.
	 *
	 * Sorting by the artefact name makes the database a function of its
	 * sources and nothing else.
	 */
	qsort(r->arts, r->n_arts, sizeof *r->arts, ksb_artefact_cmp);

	ksb_warn_duplicate_patterns(r->arts, r->n_arts);

	/* Linear scan over the groups: the number of distinct precondition tuples
	 * is small and does not grow with the number of signatures, which is the
	 * property that makes this cheap however large the set gets. */
	for (a = 0; a < r->n_arts; a++) {
		struct group *g = NULL;
		int ab = ksb_bucket_of_targets(r->arts[a].target, r->arts[a].n_target,
					       r->arts[a].any_target);

		/*
		 * BY BUCKET, AND ARCHITECTURE IS NOT PART OF THE KEY.
		 *
		 * It used to be one pack per exact (kind, target set,
		 * arch_mask), on the reasoning that a pack whose any_target is
		 * exactly M lets the scanner skip the whole file in one
		 * comparison instead of N.
		 *
		 * That comparison does not exist. any_target, any_scan and
		 * any_arch are written into every pack header by the writer and
		 * are read by NOTHING - grep the tree. What actually filters is
		 * KOF_SEC_PRE_TARGET and KOF_SEC_PRE_ARCH, the per-module
		 * columns the scanner sweeps at dbloader.c:569. So the split was
		 * buying a skip that was never wired up, and charging a whole
		 * file for it: sigs-elf-x86.ksig held ONE module and cost 4164
		 * bytes, of which 3132 were zeros.
		 *
		 * If a pack-level prefilter is ever implemented, the header
		 * fields are still there and still correct - the writer unions
		 * them from the members, so a merged pack gets a wider union and
		 * skips less, which costs sweeps and never a detection.
		 */
		for (j = 0; j < r->n_groups; j++)
			if (r->groups[j].kind == r->arts[a].kind &&
			    ((ab != BUCKET_NONE && r->groups[j].bucket == ab) ||
			     (ab == BUCKET_NONE &&
			      r->groups[j].bucket == BUCKET_NONE &&
			      r->groups[j].target_set ==
			      ksb_target_set_of(&r->arts[a])))) {
				g = &r->groups[j];
				break;
			}
		if (!g) {
			if (r->n_groups == r->cap_groups) {
				uint32_t nc = r->cap_groups ? r->cap_groups * 2 : 8;
				struct group *nv = realloc(r->groups, nc * sizeof *nv);
				if (!nv)
					return 0;
				r->groups = nv;
				r->cap_groups = nc;
			}
			g = &r->groups[r->n_groups++];
			memset(g, 0, sizeof *g);
			g->kind        = r->arts[a].kind;
			g->bucket      = ab;
			g->target_set  = ksb_target_set_of(&r->arts[a]);
			g->arch_mask   = r->arts[a].arch_mask;
		} else {
			/*
			 * The union, for the name. arch_mask 0 means ANY, so
			 * it absorbs rather than being absorbed - a pack
			 * holding one arch-any module is an arch-any pack, and
			 * OR-ing 0 into a specific mask would claim the
			 * opposite.
			 */
			g->target_set |= ksb_target_set_of(&r->arts[a]);
			if (g->arch_mask == 0u || r->arts[a].arch_mask == 0u)
				g->arch_mask = 0u;
			else
				g->arch_mask |= r->arts[a].arch_mask;
		}
		if (!ksb_group_add(g, a))
			return 0;
	}

	/*
	 * Order the packs by their key before any of them is named.
	 *
	 * Naming reads the names already taken, so which pack gets the plain
	 * general name and which gets the mask suffix depends on the order they are
	 * visited in - and that order was readdir's, which is the filesystem's and
	 * not the same on two machines. Same sources, same modules, "sigs-elf.ksig"
	 * holding different packs. Nothing would detect it: both databases load and
	 * both scan correctly, because the loader takes every .ksig in the directory
	 * and does not care what they are called.
	 *
	 * Sorting by the key makes it the key's order, which is the same everywhere.
	 * It also decides the tie the right way round: the smallest mask is the most
	 * specific pack, so the plain "elf" goes to the ELF pack and ELF|PE takes the
	 * suffix, rather than the other way about.
	 */
	qsort(r->groups, r->n_groups, sizeof *r->groups, ksb_group_cmp);

	printf("%u module(s) -> %u pack(s)\n", r->n_arts, r->n_groups);

	r->taken = calloc(r->n_groups, sizeof *r->taken);
	if (!r->taken)
		return 0;
	return 1;
}

/* The modules of one group, as the pack writer takes them. Zero when a disease
 * is refused. */
static int pack_fill(struct ksb_ctx *ksb, const struct pack_run *r,
		     const struct group *g, struct kof_pw_mod *pm)
{
	uint32_t a;

	for (a = 0; a < g->n; a++) {
			const struct artefact *s = &r->arts[g->member[a]];
			pm[a].code        = s->code;
			pm[a].code_len    = s->code_len;
			/* Zero targets is ANY, which is what the engine reads
			 * an empty list as - see n_target in dbloader.h. */
			pm[a].n_target    = s->any_target ? 0 : s->n_target;
			memcpy(pm[a].target, s->target, sizeof pm[a].target);
			pm[a].scan_mask   = s->scan_mask;
			pm[a].arch_mask   = s->arch_mask;
			pm[a].subtype_mask = s->subtype_mask;
			pm[a].step         = s->step;
			pm[a].heur_phase   = s->heur_phase;
			pm[a].heur_want    = s->heur_want;
			pm[a].heur_level   = s->heur_level;
			pm[a].cure_off     = s->cure_off;
			pm[a].src          = s->srcpath;
			pm[a].size_min    = s->size_min;
			pm[a].str         = s->str;
			pm[a].n_str       = s->n_str;
			pm[a].rng         = s->rng;
			pm[a].n_rng       = s->n_rng;
			pm[a].blk         = s->blk;
			pm[a].n_blk       = s->n_blk;
			pm[a].pool        = s->pool;
			pm[a].n_pool      = s->n_pool;
			pm[a].name        = s->name;
			pm[a].n_names     = s->n_names;
			pm[a].family      = s->family;
			pm[a].maltype     = s->maltype;
			/* THE DISEASE, registered here where the whole database is seen:
			 * the same name with two types, or two names that hash alike, are
			 * caught across detectors of every kind - see ksb_disease_note. */
			if (s->disease && s->disease[0]) {
				if (!ksb_disease_note(ksb, s->disease, s->disease_type, DIS_BY_DETECTOR))
					return 0;
				pm[a].disease      = kof_disease_id(s->disease);
				pm[a].disease_type = s->disease_type;
			}
			pm[a].heur_predict = s->heur_predict;
			pm[a].content = s->content;
	}
	return 1;
}

/* The path a group is written to. */
static void pack_path(const struct pack_run *r, const struct group *g,
		      const char *outdir, char *path, size_t cap)
{
	uint32_t a;

	/*
	 * The name says what is in the pack - the tools by label for an
	 * unpack pack, the formats for a sigs pack. See the block above
	 * ksb_format_list for why the two differ, and name_clash for what keeps
	 * the result unique now that it no longer is by construction.
	 *
	 * The architecture is appended only when it constrains something: an
	 * unconstrained one is the ordinary case and writing "-any" on every
	 * pack would be noise in the place a reader looks first. It stays in
	 * the name because it is the one part of the key a reader cannot
	 * infer from the contents.
	 */
	{
		char fmt[PACK_NAME_MAX], arch[PACK_NAME_MAX];
		size_t aat = 0;

		if (g->kind != KOF_PACK_UNPACK ||
		    !ksb_label_one(r->arts, g->member, g->n, fmt, sizeof fmt)) {
			/*
			 * The bucket names the pack when there is one:
			 * "archive" rather than "zip+tar+gzip+xz+rar+
			 * sevenzip", which is what the union spells and
			 * which nobody can read. The format list stays
			 * for a mask whose bits do not agree on a
			 * bucket, because there the exact set IS the
			 * only honest name.
			 */
			const char *bn = ksb_bucket_name(g->bucket);

			if (*bn)
				snprintf(fmt, sizeof fmt, "%s", bn);
			else if (!ksb_format_list(g->target_set, fmt,
						  sizeof fmt))
				snprintf(fmt, sizeof fmt, "x%llx",
					 (unsigned long long)
					 g->target_set);
		}

		/*
		 * ARCHITECTURE IS NEVER IN THE NAME ANY MORE, because
		 * it is no longer in the key: an x86-only module and an
		 * arch-any one share a pack, so a suffix naming one of
		 * them would describe the pack wrongly. Which
		 * architectures a pack covers is in its header and in
		 * the per-module column, where it is read.
		 */
		arch[0] = 0;
		if (0) {
			uint32_t ab;

			for (ab = 0; ab < 32u; ab++) {
				if (!(g->arch_mask & (1u << ab)))
					continue;
				if (aat && aat + 1u < sizeof arch)
					arch[aat++] = '+';
				ksb_name_append(arch, sizeof arch, &aat,
						kof_arch_name((uint8_t)ab));
			}
			if (!aat)
				snprintf(arch, sizeof arch, "a%x",
					 g->arch_mask);
		}

		snprintf(path, cap, "%s/%s-%s%s%s.ksig",
			 outdir, ksb_group_name(g), fmt,
			 arch[0] ? "-" : "", arch);

		/*
		 * The general name, made specific only where it has to
		 * be.
		 *
		 * A general name collides by design: "elf" is the name
		 * of the ELF pack and of the ELF|PE pack, and both are
		 * correct answers to what is in them. Refusing the build
		 * would be refusing a legitimate database over a
		 * filename, so the second one earns a suffix instead and
		 * the common case stays short.
		 *
		 * The suffix is the target mask, which makes the name a
		 * one to one image of the whole key - kind, formats,
		 * architecture - so one retry is always enough and there
		 * is no loop here. Ugly on purpose: it should read as a
		 * pack that wanted a plain name and could not have one.
		 */
		for (a = 0; a < r->n_taken; a++) {
			if (strcmp(r->taken[a], path) != 0)
				continue;
			snprintf(path, cap,
				 "%s/%s-%s-x%llx%s%s.ksig", outdir,
				 ksb_group_name(g), fmt,
				 (unsigned long long)g->target_set,
				 arch[0] ? "-" : "", arch);
			break;
		}
	}
}

/* Take the path, or refuse it. Zero when it is already taken or memory runs
 * out; the caller frees the pack. */
static int pack_claim(struct pack_run *r, const char *path)
{
	uint32_t a;

	/*
	 * Refuse rather than overwrite.
	 *
	 * The retry above resolves a collision between two general names, and
	 * a name that survives it is unique by construction. This catches the
	 * case where that reasoning is wrong - because ksb_write_file would
	 * happily replace the pack written a moment ago and the build would
	 * succeed with one database missing, which is the failure this whole
	 * file is arranged to make impossible.
	 */
	for (a = 0; a < r->n_taken; a++) {
		if (strcmp(r->taken[a], path) != 0)
			continue;
		fprintf(stderr, "ksigbuilder: two packs would both be "
				"%s; rename one of the modules in it\n",
			path);
		return 0;
	}
	r->taken[r->n_taken] = strdup(path);
	if (!r->taken[r->n_taken]) {
		return 0;
	}
	r->n_taken++;
	return 1;
}

/* One group: its modules, the pack built from them, its name, and the file. */
static int pack_write_group(struct ksb_ctx *ksb, struct pack_run *r,
			    uint32_t j, const char *outdir)
{
	struct group *g = &r->groups[j];
	struct kof_pw_mod *pm;
	uint8_t *img;
	size_t img_len = 0;
	char path[4096];

	pm = calloc(g->n, sizeof *pm);
	if (!pm)
		return 0;
	if (!pack_fill(ksb, r, g, pm)) {
		free(pm);
		return 0;
	}

	img = kof_pack_build(g->kind, pm, g->n, &img_len);
	free(pm);
	if (!img) {
		fprintf(stderr, "ksigbuilder: cannot build pack %u\n", j);
		return 0;
	}

	pack_path(r, g, outdir, path, sizeof path);
	if (!pack_claim(r, path)) {
		free(img);
		return 0;
	}

	if (!ksb_write_file(path, img, img_len)) {
		free(img);
		return 0;
	}
	printf("  %-44s %5u module(s)  %8zu bytes\n", path, g->n, img_len);
	free(img);
	return 1;
}

/* The whole run, from the artefact directory to the packs and the table of
 * diseases. Zero on the first failure. */
static int pack_run(struct ksb_ctx *ksb, const char *workdir,
		    const char *outdir, struct pack_run *r)
{
	uint32_t j;

	if (!pack_load(workdir, r) || !pack_group(r))
		return 0;
	for (j = 0; j < r->n_groups; j++)
		if (!pack_write_group(ksb, r, j, outdir))
			return 0;

	/*
	 * THE TABLE OF DISEASES, LAST: the modules register theirs while their packs
	 * are made - above - and the diagnoses and syndromes registered before this
	 * ran, so only here is the whole registry known. Written before it, a
	 * detector's disease had no entry and a syndrome's showed no type.
	 */
	if (!ksb_write_diseases(ksb, outdir))
		return 0;
	return 1;
}

/* Everything the run owns. */
static void pack_free(struct pack_run *r)
{
	uint32_t a;

	for (a = 0; a < r->n_arts; a++)
		ksb_artefact_free(&r->arts[a]);
	free(r->arts);
	for (a = 0; a < r->n_groups; a++)
		free(r->groups[a].member);
	free(r->groups);
	for (a = 0; a < r->n_taken; a++)
		free(r->taken[a]);
	free(r->taken);
}

/* The pack path, and the modes that dispatch before it. Called from main below,
 * and from --tree once it has compiled everything. */
int ksb_pack_main(struct ksb_ctx *ksb, int argc, char **argv)
{
	const char *workdir = NULL, *outdir = NULL;
	struct pack_run r;
	int rc;

	if (argc > 1 && (strcmp(argv[1], "--image") == 0 ||
			 strcmp(argv[1], "--object") == 0))
		return pack_image_main(argc, argv);
	if (argc > 1 && (strcmp(argv[1], "--help") == 0 ||
			 strcmp(argv[1], "-h") == 0)) {
		ksb_usage(argv[0]);
		return 0;
	}
	if (argc > 1 && strcmp(argv[1], "--build") == 0)
		return pack_build_main(ksb, argc, argv);

	if (argc > 1 && strcmp(argv[1], "--module") == 0)
		return ksb_module_main(ksb, argc, argv);
	if (argc > 1 && strcmp(argv[1], "--extract") == 0)
		return ksb_extract_main(ksb, argc, argv);
	if (argc > 1 && strcmp(argv[1], "--arch-mask") == 0)
		return ksb_arch_mask_main(argc, argv);
	if (argc > 1 && strcmp(argv[1], "--subtype-mask") == 0)
		return ksb_subtype_mask_main(argc, argv);

	if (!pack_args(argc, argv, &workdir, &outdir))
		return 2;
	memset(&r, 0, sizeof r);
	rc = pack_run(ksb, workdir, outdir, &r) ? 0 : 1;
	pack_free(&r);
	return rc;
}
