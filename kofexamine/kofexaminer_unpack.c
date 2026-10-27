#define _GNU_SOURCE

/*
 * kofexaminer_unpack.c - what the unpackers recover: the engine callbacks the
 * examiner registers, the verdict line and the unpack pass over one file. Split
 * from kofexaminer.c by stage, no logic changed.
 */

#include "kofexaminer_private.h"

/* ---- what the unpackers recover -------------------------------------------- */

/*
 * The one thing here that is not a parse.
 *
 * Everything else in this tool reads structure out of the file in front of it.
 * Whether a file is packed is not structure - it is a verdict, and verdicts come
 * from modules. So this runs the engine rather than answering on its own: a
 * database is loaded, its unpackers are given the object, and what they produced
 * is reported. A second implementation of "does this look like UPX" living in a
 * tool would be a thing to keep in step with the modules, and it would disagree
 * with them exactly when it mattered.
 *
 * It needs --db for that reason, and says so rather than guessing when it has none.
 */
/*
 * What a module worked out, on its way to working it out.
 *
 * Two audiences and they want it differently, so it goes to both.
 *
 * --debug prints it as it happens, because a note that arrives before the module
 * returns is a note about work in progress and buffering it would lose that
 * ordering.
 *
 * The unpack report keeps it instead. "recovered 90796 bytes" does not say WHAT
 * unpacked it, and that is not detail - a signature written against a recovered
 * object only ever runs when that same unpacker still claims the sample, so the
 * packer is part of what the object IS. The engine does not name the producing
 * module on the callback, but the module names itself here, and it does so while
 * running and therefore before the object it produces arrives. That ordering is
 * what makes the association sound rather than a guess.
 */
/* What the last unpacker said about itself, for the object it is about to
 * produce. See on_debug and on_unpacked. */
struct unp_run {
	const char *dump_dir;     /* NULL when not dumping */
	/*
	 * The producing module's name, and only that.
	 *
	 * A module reports "UPX.ELF.version 13", "UPX.ELF.method 14" - its own
	 * name, a field, a value. The name is what a recovered object needs
	 * beside it; the fields are detail and --debug already prints them as
	 * they happen. Sticky rather than cleared per object, because a zip
	 * opener says its piece once and then yields forty entries, and every
	 * one of them came from it.
	 */
	/* And which build of it - see kof_result.packer_build. */
	char        build[48];
	/* The engine, to turn the ids a verdict lists back into names. */
	const kof_engine *eng;
	uint32_t    produced;
	uint32_t    partial;
	/*
	 * Whether the FILE ITSELF was finished, which is a different fact from
	 * `partial` and was the one missing.
	 *
	 * `partial` counts recovered children whose own scan broke. An unpack that
	 * stopped part way through is not that: the child it produced is intact and
	 * was scanned to the end - it is simply not all of the original. The reason
	 * for that lives on the parent's result, because the parent is the object
	 * the unpacker was working on.
	 *
	 * Without this a file cut in half reported "unpacked 1 object(s)" with
	 * nothing to say the recovery was a fragment, and the only clue was a
	 * shortfall printed under --debug.
	 */
	uint32_t    root_broken;
	int         err;
};

static int g_debug;


static void on_debug(uint32_t fact, const char *what, uint64_t value,
		     void *user)
{
	struct unp_run *u = user;

	(void)fact;             /* this one prints; it does not match */
	/* The fact takes the column, not the word "debug".
	 *
	 * Three facts printed three "debug"s and one of them was never the thing
	 * being read - the name a module chose IS the label, and it says which
	 * module said it. Same rule the scanner's result lines follow. */
	if (g_debug)
		printf("  %-24s %10llu\n", what, (unsigned long long)value);
	/*
	 * THE GUESS THIS USED TO MAKE IS GONE.
	 *
	 * It remembered the name in front of the last debug note anybody
	 * emitted and used it as "what opened this object". That is now a fact
	 * the engine reports - kof_result.packer_build, filled wherever
	 * something opened the object and carrying the build as well - so a
	 * debug note is a debug note again.
	 */
	(void)u;
}


/*
 * THE VERDICT THE ENGINE MADE OF AN OBJECT, and what it was made of: the diagnoses
 * that matched and the diseases, each named by the engine (kdb_diagnose_name,
 * kdb_disease_name) from the ids the verdict carries. Nothing is composed here.
 */
static void print_verdict(const struct unp_run *u, const struct kof_result *res)
{
	const struct kof_finding *f = &res->verdict;
	uint32_t i;

	if (!res->has_verdict)
		return;
	printf("  verdict   %s%s%s\n", kex_C_BAD, f->name, kex_C_OFF);
	for (i = 0; i < f->n_diag; i++) {
		const char *nm = kdb_diagnose_name(u->eng, f->diag[i]);

		printf("    diagnose %s\n", nm ? nm : "?");
	}
	if (f->diag_total > f->n_diag)
		printf("    diagnose (%u more not listed)\n",
		       (unsigned)(f->diag_total - f->n_diag));
	for (i = 0; i < f->n_disease; i++) {
		const char *nm = kdb_disease_name(u->eng, f->disease[i]);
		int ty = kdb_disease_type(u->eng, f->disease[i]);

		printf("    disease  %s (%s)\n", nm ? nm : "?",
		       ty >= 0 ? kof_maltype_name((uint32_t)ty) : "?");
	}
	if (f->disease_total > f->n_disease)
		printf("    disease  (%u more not listed)\n",
		       (unsigned)(f->disease_total - f->n_disease));
}

static int on_unpacked(const char *name, const void *bytes, uint64_t len,
		       const struct kof_result *res, void *user)
{
	struct unp_run *u = user;
	const char *tail = strstr(name, KOF_OBJ_SEP);
	char tag[128], sub[KOF_DUMP_PATH_ROOM];

	/* The first object is the file itself, which the rest of this tool has
	 * already described in far more detail - except for one thing, which is
	 * only on this result: whether the engine got to the end of it. */
	if (!tail) {
		u->root_broken = res->broken;
		/*
		 * AND WHICH PACKER THE FILE ITSELF IS, which the description
		 * above cannot know: it comes from the module that recognised
		 * it, and the modules run after the parse. Printed here rather
		 * than remembered, because this is the only point that has it
		 * and the file's own block has already been written.
		 */
		if (res->opened_by && res->opened_by[0]) {
			/* The build when there is one, the module's own name
			 * when there is not - see the same choice below. */
			printf("  packer    %s%s%s\n", kex_C_BAD,
			       res->packer_build ? res->packer_build
						 : res->opened_by, kex_C_OFF);
		}
		print_verdict(u, res);
		return 0;
	}

	u->produced++;
	if (res->broken)
		u->partial++;
	/*
	 * WHAT THE ENGINE SAYS, IN PLACE OF WHAT THIS GUESSED.
	 *
	 * See the note in on_debug: `via` was inferred from the prefix of the
	 * last debug note, which is wrong whenever the producer emits none or
	 * another module speaks after it. The engine now records the producing
	 * module where the child is pushed, so when it has an answer that is
	 * the answer. The guess is kept only for a module the engine could not
	 * name.
	 */
	/*
	 * THE ENGINE'S ANSWER, INCLUDING WHEN IT IS "NOBODY".
	 *
	 * Set AND cleared from it. Left sticky, an object nothing opened kept
	 * the previous one's name: on 111.exe the last child - the one with
	 * its strings already decrypted and no layer left on it - read
	 * "StrXor.tab", which is the thing that had just been taken OFF it.
	 */
	/*
	 * ONE FIELD FROM THE ENGINE AND NOTHING ASSEMBLED HERE.
	 * kof_result.packer_build is the whole answer - format, name, and the
	 * build where the module could tell one. It is filled whenever anything
	 * opened the object, so there is no second field to fall back to.
	 */
	if (res->packer_build && res->packer_build[0])
		snprintf(u->build, sizeof u->build, "%s", res->packer_build);
	else
		u->build[0] = 0;
	/*
	 * <number>.<name>, or <number> alone.
	 *
	 * The number is what makes it unique and is the whole identity; the name is
	 * there so a directory listing is readable, and it is the label the engine
	 * already reduced to a bare basename of printable ASCII.
	 *
	 * THE LAST COMPONENT'S LABEL, AND NOT THE FIRST COLON IN THE WHOLE PATH.
	 *
	 * A composed name is `parent//<i>:<label>` repeated once per layer, so a
	 * GRANDCHILD's tail carries its parent's label AND the separator after it.
	 * Read from the first colon, the tag became `3.EmbeddedFile//0` - a path
	 * with a directory component in it - and the write then failed. It said so
	 * rather than dropping the object quietly, which is the only reason this was
	 * ever visible; but a reported failure is still a recovered object that did
	 * not get written.
	 *
	 * It needed a NAMED PARENT to happen at all, which is why it survived: the
	 * label comes from a container that names its entries, and until the host
	 * began naming carried files from the entry table the layer above a
	 * grandchild was usually anonymous. It was never PDF-specific - a zip entry
	 * called "a.exe" that itself unpacks reaches the same line.
	 *
	 * So the separator IS decided about here, once, by walking to the last one.
	 * What still cannot have survived is a ".." or a path separator INSIDE a
	 * label - kof_src_label reduces those where the label is made - so an entry
	 * called "../" arrives with no label and gets the number by itself.
	 *
	 * snprintf into a buffer sized from KOF_SRC_LABEL_MAX is what bounds it. A
	 * name is attacker chosen and archives carry long ones; the label is capped
	 * when it is made, and this is capped again where it becomes a path, because
	 * the two caps protect different things and only one of them is here.
	 */
	{
		const char *last = tail, *p = tail, *lab;

		while ((p = strstr(p + KOF_OBJ_SEP_LEN, KOF_OBJ_SEP)) != NULL)
			last = p;
		lab = strchr(last, ':');

		if (lab)
			snprintf(tag, sizeof tag, "%u.%s", u->produced, lab + 1);
		else
			snprintf(tag, sizeof tag, "%u", u->produced);
	}
	printf("  recovered %s%-18s%s %s%10llu%s bytes", kex_C_ID, tag, kex_C_OFF,
	       kex_C_SIZE, (unsigned long long)len, kex_C_OFF);
	if (u->build[0]) {
		int packed = kex_g_parent_format == KOF_FMT_ELF ||
			     kex_g_parent_format == KOF_FMT_PE ||
			     kex_g_parent_format == KOF_FMT_MACHO;

		/* "is", not "via": the name says what this object IS - the
		 * layer still on it - and not what it came out of. See
		 * kof_result.packer_build. */
		printf("   is %s%s%s", packed ? kex_C_BAD : kex_C_NOTE, u->build,
		       kex_C_OFF);
	}
	if (res->broken)
		printf("   %s%s%s", kex_C_BAD, kverdict_broken_name(res->broken), kex_C_OFF);
	/*
	 * What the heuristic made of it, on the line that says what it is.
	 *
	 * The score is the engine's own - it is in the result, not recomputed -
	 * and the depth beside it is how many EXECUTABLE PACKER layers stand
	 * above this object. Printed for every recovered object rather than only
	 * for the ones that report, because the useful question about a sample
	 * that got away is how far short it came.
	 */
	if (g_debug && res->heur_scored)
		printf("   %sheur %d%s%s d%u%s", kex_C_NOTE, res->heur_score, kex_C_OFF,
		       kex_C_DIM, res->heur_depth, kex_C_OFF);
	printf("\n");
	print_verdict(u, res);

	/*
	 * Writing is what needs a directory. Looking does not: a recovered
	 * object is examined whether or not it is dumped, with the regions, the
	 * symbols and the language the engine just handed over - see
	 * kof_result.region and .lang_known.
	 */
	kex_g_decl_syms = res->syms;
	kex_g_decl_syms_n = res->n_syms;
	kex_g_decl_fixed = res->fixed;
	kex_g_decl_fixed_n = res->n_fixed;
	kex_g_decl_view = res->entry_kind == KOF_ENT_NORMALIZED;
	kex_g_decl_lang = res->lang_known;
	kex_g_decl_subtype = res->subtype;
	kex_g_decl_subfam = res->subfamily;
	kex_g_decl_rgn_n = res->n_region < KOF_MAX_REGIONS ? res->n_region
						       : KOF_MAX_REGIONS;
	if (kex_g_decl_rgn_n)
		memcpy(kex_g_decl_rgn, res->region,
		       kex_g_decl_rgn_n * sizeof kex_g_decl_rgn[0]);

	if (!u->dump_dir) {
		if (kex_g_blocks || kex_g_scfind) {
			printf("\n");
			if (kex_examine_bytes(kof_buf_make(bytes, len), name, 0) < 0)
				u->err = 1;
		}
		kex_g_decl_syms = NULL;
		kex_g_decl_syms_n = 0;
		kex_g_decl_rgn_n = 0;
		kex_g_decl_lang = 0;
		kex_g_decl_view = 0;
		return 0;
	}
	/*
	 * And then examine what came out, exactly as though it had been the file.
	 *
	 * Stopping at the raw bytes would leave the job half done for the one person
	 * this tool is for. A signature is written against a REGION - the author has
	 * to see what CODE and DATA are once the packer is off, and those are
	 * properties of the recovered object, not of the packed one. Writing the
	 * bytes and making somebody run the tool again on them would be handing over
	 * the input to the question rather than the answer.
	 *
	 * Recursion is the engine's job and it has already done it: an object nested
	 * two layers down arrives here as its own callback, so each one gets its own
	 * directory and nothing here has to walk anything.
	 */
	{
		char why[256];

		/*
		 * WHERE IT GOES IS THE ENGINE'S ANSWER, not a counter's.
		 *
		 * This wrote `unpacked.<tag>` in the dump root, with `tag`
		 * built from u->produced - so every object of a file landed as
		 * a sibling whatever its depth, and kofviewer's own loop did
		 * the same thing by a different name. One call now, and the
		 * placement comes from the name the engine gave the object.
		 * See kof_dump_walk.
		 */
		if (!kof_dump_walk(u->dump_dir, name,
				   kof_buf_make(bytes, len), NULL, NULL, NULL,
				   sub, sizeof sub, why, sizeof why)) {
			fprintf(stderr, "kofexaminer: %s\n", why);
			u->err = 1;
			return 0;
		}
	}
	printf("\n");
	if (kex_examine_bytes(kof_buf_make(bytes, len), name, sub) < 0)
		u->err = 1;
	kex_g_decl_syms = NULL;
	kex_g_decl_syms_n = 0;
	kex_g_decl_rgn_n = 0;
	kex_g_decl_lang = 0;
	kex_g_decl_view = 0;
	return 0;
}

/*
 * Run the database's unpackers over one file and report what came out.
 */
int kex_unpack_pass(kof_engine *eng, const char *path, const char *dump_dir,
		       int verbose)
{
	struct kof_scan_option opt;
	struct unp_run u;
	kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	memset(&u, 0, sizeof u);
	/*
	 * The most this build's heuristic can be asked for.
	 *
	 * A tool that examines one named file is not a scanner walking a
	 * filesystem: the reason a level is optional there - it costs a pass
	 * over every object - is not a reason here, where there is one object
	 * and somebody is sitting in front of it waiting to be told about it.
	 * Named rather than numbered so this keeps meaning "the most" as levels
	 * are added.
	 */
	opt.heur_level = KOF_HEUR_LEVEL_MAX;
	u.dump_dir = dump_dir;
	u.eng = eng;
	g_debug = verbose;
	kex_g_root_path = path;

	sc = kscan_new(eng);
	if (!sc) {
		fprintf(stderr, "kofexaminer: out of memory\n");
		return 0;
	}
	kscan_on_debug(sc, on_debug, &u);
	kscan_path(sc, path, &opt, on_unpacked, &u);
	kscan_free(sc);

	if (u.produced == 0 && !u.root_broken)
		printf("  unpacked  nothing - no unpacker in the database claimed it\n");
	else if (u.produced == 0)
		printf("  unpacked  nothing - %s\n", kverdict_broken_name(u.root_broken));
	else
		/*
		 * Three facts on one line, and each is only worth printing when it
		 * is true: how many objects came out, whether the original was
		 * fully recovered, and whether any of what came out was itself
		 * unfinished. The middle one is the file being short of bytes the
		 * unpacker needed; the last is a recovered object that broke on
		 * its own account.
		 */
		printf("  unpacked  %u object(s)%s%s%s\n", u.produced,
		       u.root_broken ? "  - not all of it: " : "",
		       u.root_broken ? kverdict_broken_name(u.root_broken) : "",
		       u.partial ? "  (some only in part)" : "");
	return !u.err;
}

