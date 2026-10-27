#define _GNU_SOURCE

/*
 * kofexaminer.c - main and the per-file driver of the examiner. What it prints and
 * how is in the kofexaminer_*.c units (see kofexaminer_private.h); this file keeps
 * the command line, examine() of a file, examine_bytes() of one object's bytes and
 * the event-log path. The long note below says what the tool is for.
 */

#include "kofexaminer_private.h"

/*
 * kofexamine - show what the engine sees in a file.
 *
 *   kofexamine <file>...
 *   kofexamine --dump <file>...
 *
 * The collectors recover a great deal about an object and the scanner uses almost
 * none of it directly - it hands the view to modules and prints their verdicts.
 * This prints the view itself, which is what you want when a signature does not
 * fire and the question is whether the module is wrong or the parse is.
 *
 * With --dump, each file gets a directory of its own holding one file per region,
 * created beside the file it came from - /samples/wget.exe produces
 * /samples/_wget.exe_dump/ - not in whatever directory the tool happened to be run
 * from. Results belong next to their input: a run over three directories otherwise
 * piles everything into one, and the only thing left saying where a region came
 * from is a name that is already being shortened when it gets long.
 *
 * The naming is binwalk's _<name>.extracted convention: already the shape people
 * expect, and the leading underscore keeps results sorted together and away from
 * what was being examined.
 *
 * A directory that cannot be created stops the run rather than skipping that file.
 * A dump missing some of its inputs looks exactly like a dump of fewer inputs, and
 * nothing downstream can tell the difference.
 *
 * Region files are named after the region's enum identifier, so
 * _wget.exe_dump/02.KGENOME_SCAN_PE_CODE is exactly the bytes a module asking for
 * that region would have been searched over, and the name is one somebody can
 * grep for to find where it came from.
 *
 * The number is the order the regions start in, in this object. Not the order of
 * the enum: on a normal ELF the first PT_LOAD is read-only, so DATA begins right
 * after the headers and CODE does not start until well into the file, and
 * numbering by the enum would put them the wrong way round. Numbering by where
 * each region actually begins says something true about the file in front of you.
 *
 * It orders starts, not layout - regions interleave, and CODE and DATA alternate
 * section by section. The LAYOUT file in the directory has every extent in offset
 * order, which is the layout itself rather than a hint at it. Their sizes sum to
 * the object because the regions partition it - which is printed on the summary
 * line so it can be read rather than assumed.
 *
 * 00.KOF_SCAN_ALL is the object entire, which is what the numbered files are
 * parts of. It takes the number below all of them so it sorts first, and the
 * engine's own name for the whole of an object so the directory speaks one
 * vocabulary. For a recovered child it is the only copy that exists outside the
 * scan, which is the case it is really there for.
 *
 * Two inputs with the same basename share a directory and the second overwrites
 * the first. That is the same thing binwalk does and the same thing a shell does
 * with a redirect; making it an error would be surprising more often than it
 * would be useful.
 *
 * They do not reassemble into the original by concatenation. Each file holds one
 * region's bytes in offset order, but the regions themselves interleave, and the
 * dump does not record where each run came from. Sizes summing is the property
 * that holds; byte-for-byte reassembly is not offered and should not be inferred.
 *
 *
 * WHY THIS REACHES INTO INTERNAL HEADERS
 *
 * kofscanner is built against the staged SDK and nothing else, deliberately. This
 * is not, and the difference is worth stating rather than treating as a lapse.
 *
 * The public host surface answers one question - what did you find - and the
 * format views belong to the other public surface, the one a signature module is
 * written against. Neither offers "parse this and hand me the view", because no
 * host has needed it. Adding it to kofeng.h to serve this tool would be designing
 * a public API for a consumer that lives in the same tree, and would put the
 * module ABI in front of hosts that have no business with it.
 *
 * So this links the internal collectors, the way a debugger links the thing it
 * debugs. If a consumer outside this tree ever wants the same thing, that is the
 * moment to design an inspect surface, and the shape of it is already visible
 * here.
 */

int kex_examine_bytes(kof_buf buf, const char *display, const char *dir)
{
	struct kof_obj_ctx ctx;
	void *view = 0;
	const struct kof_parser *f = 0;
	uint64_t total = 0;
	uint32_t i;
	int rc = 0;
	const int dump = dir != 0;

	{
		printf("%s%s%s\n", kex_C_NAME, display, kex_C_OFF);
		f = kof_inspect_identify(buf, &ctx, &view);
		/* And the engine's answer beats this one - see kex_g_decl_lang. */
		if (kex_g_decl_lang) {
			ctx.subtype = kex_g_decl_subtype;
			ctx.subfamily = kex_g_decl_subfam;
		}
		kex_g_parent_format = ctx.format;
		/*
		 * WHAT THE PRODUCER SAID THIS OBJECT'S REGIONS ARE beats what
		 * its bytes can be parsed into - see kex_g_decl_rgn. Installed
		 * after the identify, which is what sets the parser's own.
		 */
		if (kex_g_decl_rgn_n)
			ctx.resolve_scan = kex_declared_regions;
		if (!f) {
			printf("  format    %sunrecognised%s, %s%llu%s bytes\n",
			       kex_C_WARN, kex_C_OFF, kex_C_SIZE,
			       (unsigned long long)buf.n, kex_C_OFF);
			rc = 1;
			goto out;
		}

		/*
		 * The subtype spelled in the format's own vocabulary, because that is
		 * what a module declares. A number would be no use: the same value
		 * means REL for an ELF and DLL for a PE, and which one it is is
		 * exactly what the reader is here to find out.
		 */
		/*
		 * AND FOR A SCRIPT, THE FAMILY WHERE THE ARCHITECTURE WOULD BE.
		 *
		 * Every script is KGENOME_ARCH_ANY, so that column printed "any"
		 * on every one of them and carried no information. The family
		 * does: kof_module_precond declines a module whose declared
		 * subtypes all sit in another one, and a reader looking at
		 * "targets another kind of this format" had nothing on screen
		 * to explain it - the language shown agreed with the rule, and
		 * the axis that actually declined it was not displayed at all.
		 * A php page and a shell script that mentions "<?php" both
		 * read "Script any Shell" and only one of them runs shell
		 * rules.
		 *
		 * A script with no family still prints "any", which is what it
		 * means here too: nothing declines.
		 */
		{
			const char *ax = ctx.format == KOF_FMT_SCRIPT
				? kof_script_fam_name(ctx.subfamily)
				: kof_arch_name(ctx.arch);

			if (!ax)
				ax = "any";
			printf("  format    %s %s%s%s%s%s  %s%llu%s bytes\n",
			       kof_format_name(ctx.format),
			       kex_C_ID, ax,
			       kof_inspect_subtype_name(ctx.format, ctx.subtype) ? " " : "",
			       kof_inspect_subtype_name(ctx.format, ctx.subtype)
			       ? kof_inspect_subtype_name(ctx.format, ctx.subtype) : "",
			       kex_C_OFF, kex_C_SIZE, (unsigned long long)buf.n, kex_C_OFF);
		}
		kex_print_view(ctx.format, view, &ctx, buf);

		/* Regions last: they are the summary the rest explains, and with
		 * --dump they are also the manifest of what was written. */
		printf("  regions  ");
		for (i = 0; i < f->n_regions; i++) {
			static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
			const char *rn = f->region_name(f->regions[i]);
			uint64_t len = 0;
			uint32_t n, k;

			n = ctx.resolve_scan
			  ? ctx.resolve_scan(&ctx, f->regions[i], ext,
					     KOF_SCAN_MAX_EXTENTS) : 0;
			/*
			 * CLIPPED, so this number and the entropy beside it
			 * are measured over the same bytes.
			 *
			 * kof_inspect_region_entropy clips each extent to the
			 * object before counting, and dump_region now writes
			 * the clipped length - so a raw sum here was the one
			 * figure on the line derived from a length nothing had
			 * checked. An extent is not a promise: resolve_scan
			 * may be kof_declared_regions, which copies what a
			 * child DECLARED and is handed no size to check it
			 * against.
			 */
			for (k = 0; k < n; k++)
				len += kof_clip_len(buf.n, ext[k].off,
						    ext[k].len);
			total += len;
			/*
			 * The size, then how random those bytes are - the one
			 * extra number that says what KIND of bytes a region
			 * holds. Written "name=bytes/H" so a row stays one
			 * token, and taken from kof_inspect_region_entropy so
			 * the viewer's dashboard reports the same figure.
			 *
			 * Only for a region that HAS bytes: "H 0.0" on an empty
			 * region is a measurement of nothing, and a column of
			 * them buries the rows that mean something.
			 */
			printf(" %s%s%s=%s%llu%s", kex_C_ID, short_region(rn), kex_C_OFF,
			       kex_C_SIZE, (unsigned long long)len, kex_C_OFF);
			if (len)
				printf("%s/%.1f%s", kex_C_LOC,
				       (double)kof_inspect_region_entropy(
					       &ctx, buf, f->regions[i]) / 8.0,
				       kex_C_OFF);
		}
		/* The partition, stated rather than assumed: if these do not add
		 * up, every region-scoped search on this object is looking at the
		 * wrong bytes and this is where it shows. */
		printf("  (sum %llu of %llu", (unsigned long long)total,
		       (unsigned long long)buf.n);
		if (total != buf.n)
			printf("%s MISMATCH%s", kex_C_BAD, kex_C_OFF);
		printf(")\n");

		{
			uint64_t anom = f->anomalies(view);
			if (anom) {
				printf("  anomalies%s", kex_C_BAD);
				for (i = 0; i < 64; i++) {
					const char *an;
					if (!(anom >> i & 1))
						continue;
					an = f->anomaly_name(i);
					if (an)
						printf(" %s", an);
					else
						printf(" bit%u", i);
				}
				printf("%s\n", kex_C_OFF);
			}
		}

		if (dump) {
			struct kof_dump_stat ds;
			char why[256];

			if (!kof_dump_object(dir, buf, f, &ctx, &ds, why,
					     sizeof why)) {
				fprintf(stderr, "kofexaminer: %s\n", why);
				rc = -1;
				goto out;
			}
			/* The whole object is counted apart from the regions: it
			 * is not one of them, and adding it to the total would
			 * double every byte the regions cover. */
			printf("  dumped    %u region(s), %llu byte(s)"
			       " + whole %llu -> %s/\n",
			       ds.regions, (unsigned long long)ds.region_bytes,
			       (unsigned long long)ds.whole_bytes, dir);
		}
		if (kex_g_blocks)
			kex_print_blocks(buf, &ctx);
		if (kex_g_scfind)
			kex_print_scfind(buf, &ctx);
		rc = 1;
	}
out:
	kof_inspect_free(f, view);
	return rc;
}

/* One finished line, straight out. */
static void line_sink(void *user, const char *text)
{
	(void)user;
	printf("%s\n", text);
}

/*
 * AN EVENT LOG IS NOT A FILE TO PARSE, so it is answered before the parsers
 * are asked.
 *
 * Everything below this walks regions, and a log has none - it is a stream of
 * records. Handed to the sniff chain it would come out "Raw, no parser divides
 * this object", which is true and useless. Recognised here it gets the same
 * description the viewer's dashboard shows, from the same composer.
 *
 * Recognised by OPENING it, not by sniffing bytes: kofevt_log_open validates
 * the header, the record size and the head size, and refuses anything that is
 * not one. Zero when the file is not a log, and then nothing has been printed
 * and the caller carries on.
 */
static int examine_event_log(const char *path, int colour)
{
	static const struct kof_inspect_style plain = { 0, 0, 0, 0 };
	static const struct kof_inspect_style lit = {
		"\033[36m", "\033[90m", "\033[33m", "\033[0m"
	};
	const struct kof_inspect_style *st = colour ? &lit : &plain;
	const struct kofevt_log_hdr *h;
	struct kofevt_log_r *r;
	const char *why = 0;
	uint64_t n, events = 0, i;
	uint64_t verbs[32];
	struct kof_evt e;

	r = kofevt_log_open(path, 0, KOFEVT_REC_NONE, &why);
	if (!r)
		return 0;
	h = kofevt_log_header(r);
	n = kofevt_log_count(r);

	/* Counted rather than taken from the header: a continuation is a record
	 * and is not an event, and the header holds only the record count. */
	memset(verbs, 0, sizeof verbs);
	for (i = 0; i < n; i++) {
		if (!kofevt_log_read(r, &e, (uint32_t)sizeof e))
			break;
		if (e.verb == KOF_EVT_CONT)
			continue;
		events++;
		if (e.verb < 32u)
			verbs[e.verb]++;
	}

	printf("== %s\n", path);
	kof_inspect_event_log(h, events, n, st, line_sink, 0);
	kof_inspect_event_verbs(verbs, ~0u, st, line_sink, 0);

	if (kofevt_log_seek(r, 0)) {
		for (i = 0; i < n; i++) {
			if (!kofevt_log_read(r, &e, (uint32_t)sizeof e))
				break;
			if (e.verb == KOF_EVT_CONT)
				continue;
			printf("\n  -- %llu %s\n", (unsigned long long)i,
			       kof_evt_verb_name(e.verb));
			kof_inspect_event(&e, st, line_sink, 0);
		}
	}
	kofevt_log_free(r);
	return 1;
}

/*
 * The file on disk, mapped and handed to the same routine as everything else.
 */
static int examine(const char *path, int dump)
{
	struct stat st;
	void *map;
	char dir[PATH_ROOM];
	int fd, rc;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "kofexaminer: cannot open %s\n", path);
		return 0;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		fprintf(stderr, "kofexaminer: %s is not a regular non-empty file\n",
			path);
		close(fd);
		return 0;
	}
	map = kof_map_file_ro(fd, (uint64_t)st.st_size);
	close(fd);
	if (!map) {
		fprintf(stderr, "kofexaminer: cannot map %s\n", path);
		return 0;
	}
	if (dump && !kof_dump_dir_for(path, dir, sizeof dir)) {
		fprintf(stderr, "kofexaminer: path too long to place a dump beside "
				"%s\n", path);
		kof_unmap_file(map, (uint64_t)st.st_size);
		return -1;
	}
	rc = kex_examine_bytes(kof_buf_make(map, (uint64_t)st.st_size), path,
			   dump ? dir : 0);
	kof_unmap_file(map, (uint64_t)st.st_size);
	return rc;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--dump] [--blocks|--hashes] [--scfind] [--db <dir>] <file>...\n"
		"\n"
		"  --dump     also write each region of each file into a directory\n"
		"             beside it: <path>/_<name>_dump/<region enum name>\n"
		"  --db <dir> run that database's unpackers too, and report what\n"
		"             they recovered. With --dump the recovered objects are\n"
		"             written beside the regions as unpacked.<n>\n"
		"  --debug    also print what modules worked out along the way -\n"
		"             versions, methods, counts. Needs --db.\n"
		"  --color    force colour on; --no-color forces it off. The default\n"
		"             is colour when stdout is a terminal and NO_COLOR is unset.\n"
		"  --blocks   list the units the similarity matcher reads - the same cut\n"
		"             the scanner makes - with region, offset, length, side,\n"
		"             function, window count, and each unit's block (its\n"
		"             smallest window hashes, the values a rule carries). With\n"
		"             --db, the normalised view of a file is listed too.\n"
		"  --scfind   where a shellcode loader keeps its payload, for an ELF\n"
		"             object: a place and how it was found, not a verdict.\n"
		"  --hashes   as --blocks, and also every distinct window hash of each\n"
		"             unit (the pool), ascending: the full set, for comparing\n"
		"             two samples. Large; redirect it to a file.\n",
		argv0);
}

/*
 * Arguments in any order.
 *
 * Two passes, and the reason is a bug rather than a preference: with one pass a
 * file was examined AT THE MOMENT IT WAS SEEN, so an option written after it had
 * not been read yet. "kofexamine a.elf --dump" examined a.elf without dumping and
 * then set a flag nothing went on to use - no error, no output missing, just
 * silently the wrong thing. Collecting the options first makes where they sit stop
 * mattering.
 */
int main(int argc, char **argv)
{
	const char *db = NULL;
	kof_engine *eng = NULL;
	int dump = 0, verbose = 0, colour = -1;
	int i, files = 0, bad = 0;

	/* Before argv is read: on Windows it has already lost anything outside
	 * the ANSI codepage, and a path it cannot spell is a file this could
	 * not open. See kof_utf8_init. */
	kof_utf8_init(&argc, &argv);

	/* First pass: the options, wherever they are. */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dump") == 0) {
			dump = 1;
		} else if (strcmp(argv[i], "--debug") == 0) {
			verbose = 1;
		} else if (strcmp(argv[i], "--blocks") == 0) {
			kex_g_blocks = 1;
		} else if (strcmp(argv[i], "--scfind") == 0) {
			kex_g_scfind = 1;
		} else if (strcmp(argv[i], "--hashes") == 0) {
			kex_g_blocks = 1;
			kex_g_hashes = 1;
		} else if (strcmp(argv[i], "--color") == 0 ||
			   strcmp(argv[i], "--colour") == 0) {
			colour = 1;
		} else if (strcmp(argv[i], "--no-color") == 0 ||
			   strcmp(argv[i], "--no-colour") == 0) {
			colour = 0;
		} else if (strcmp(argv[i], "--db") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "%s: --db needs a directory\n",
					argv[0]);
				return 2;
			}
			db = argv[i];
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else if (argv[i][0] == '-' && argv[i][1]) {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	/* Auto unless said otherwise: this output gets piped into grep and
	 * diffed against itself, and an escape sequence in either is a bug
	 * rather than a preference - which is what the tty test answers.
	 *
	 * It also honoured $NO_COLOR, and that is gone. Nothing in this tree
	 * takes behaviour from the environment (see trace_on in
	 * libkoforbit/grille/wwalk.c), and the variable said nothing the tty
	 * test and --no-colour did not already say between them. */
	if (colour < 0)
		colour = kex_stdout_is_tty();
	kex_colour_enable(colour);

	if (db) {
		eng = keng_open(db);
		if (!eng) {
			fprintf(stderr, "%s: cannot load a database from %s\n",
				argv[0], db);
			return 2;
		}
	}

	/* Second pass: everything that was not an option is a file, and by now every
	 * option has been read whether it was written before or after it. */
	for (i = 1; i < argc; i++) {
		int r;

		if (strcmp(argv[i], "--db") == 0) {
			i++;               /* its value, already taken */
			continue;
		}
		if (argv[i][0] == '-' && argv[i][1])
			continue;

		/* A log answers itself and skips the parsers - see
		 * examine_event_log. */
		if (examine_event_log(argv[i], colour))
			continue;
		r = examine(argv[i], dump);
		if (r >= 0 && eng) {
			char dir[PATH_ROOM];
			const char *d = NULL;

			if (dump && kof_dump_dir_for(argv[i], dir, sizeof dir))
				d = dir;
			if (!kex_unpack_pass(eng, argv[i], d, verbose))
				r = -1;
		}

		files++;
		if (r < 0) {
			keng_close(eng);
			return 2;          /* could not write: see above */
		}
		if (!r)
			bad = 1;
	}

	keng_close(eng);
	if (files == 0) {
		usage(argv[0]);
		return 2;
	}
	return bad ? 1 : 0;
}
