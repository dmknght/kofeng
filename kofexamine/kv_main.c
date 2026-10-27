#define _GNU_SOURCE
#include "kv.h"


/* ---- main ----------------------------------------------------------------- */

/* One line a flag - see the note on kofscanner's usage. */
static void usage(void)
{
	fprintf(stderr,
	"kofviewer - the engine's view of a file, navigable\n"
	"\n"
	"  kofviewer [--db <dir>] [--heur 0|1|2] <file|folder>\n"
	"  kofviewer [--db <dir>] --pid <N>\n"
	"\n"
	"  --db D      load that database; without it there is one object\n"
	"              and no markers\n"
	"  --bases D   the content source tree, for Analysis > Rebuild database\n"
	"  --syndromes D  the tag sources (default: <bases>/syndromes, or\n"
	"              bases/syndromes), for Analysis > Syndrome table\n"
	"  --pathogens D  where Manage > Pathogens keeps its files (default:\n"
	"              <bases>/pathogens; without either Save is refused)\n"
	"  --pid N     open a RUNNING PROCESS instead of a file, as a snapshot\n"
	"  --heur N    0 do not separate what a file carries  1 score and\n"
	"              descend  2 also interpret (default)\n"
	"\n"
	"? in the viewer lists the keys.\n");
}

/*
 * Everything one FILE owns, and nothing the session owns.
 *
 * Deliberately not view_free: the engine, the two extent buffers and the bases
 * directory outlive any one file, and freeing them here is what would make a
 * file switch cost a database load again.
 */
static void file_close(struct view *v);

/*
 * OPEN A RUNNING PROCESS. 1 when there is something to look at.
 *
 * Shaped like file_open deliberately: it resets the view the same way, sets
 * v->map to the bytes the ROOT object is made of, and leaves the rest to the
 * same two passes - proc_collect instead of objects_collect, then
 * objects_examine unchanged. Everything after this point in the program does
 * not know a process from a file, which is the property that makes the panes,
 * the jumps, the dumps and the drafting work without a second implementation.
 *
 * v->map IS THE PROCESS RECORD and not a mapping, so file_close must not
 * unmap it - see the owned flag there.
 */
static int proc_open(struct view *v, uint32_t pid, kof_engine *eng)
{
	struct kof_walk_option wo;
	struct kof_walk_api   *w;
	struct kof_proc_build  b;
	static uint8_t rec[KOF_PROC_REC_MAX];
	uint32_t n = 0, pids[1];
	int err = 0;
	struct kof_range *ext   = v->ext;
	struct kof_range *ext2  = v->ext2;
	/*
	 * The blocks a reader TICKED, and the mode they are in.
	 *
	 * Compacted to the front here rather than after the clear, because the
	 * clear is what takes the count with it. What was not ticked was the
	 * engine's suggestion about the file being closed and goes with it.
	 */
	struct mtn_block *plg   = v->ed.dr.blk;
	uint32_t n_plg = 0;
	struct kof_range *probe = v->probe;
	uint32_t          cap   = v->ed.dr.decl_cap;
	struct kv_syn    *syn   = v->syn;
	char basedir[sizeof v->basedir];
	char dbdir[sizeof v->dbdir];
	char pathdir[sizeof v->pathdir];
	struct kv_fam_ui *fam = v->fam;     /* the Pathogens catalog is the session's: it outlives the file */
	int  heur_off = v->heur_off;

	/*
	 * ASKED ONCE HERE, BEFORE ANYTHING IS TORN DOWN. A pid that cannot be
	 * opened must leave the view the reader already had, not an empty one:
	 * stepping to the next pid over a process that exited between the list
	 * and the open is the ordinary case, not an error.
	 */
	memset(&wo, 0, sizeof wo);
	pids[0] = pid;
	wo.pids = pids;
	wo.n_pids = 1;
	/* A reader, not a scan - see enum kof_walk_intent. */
	wo.intent = KOF_WALK_MAP;
	w = kof_walk_open(&wo, &err);
	if (w) {
		if (w->next_proc(w->self, &b))
			n = kof_proc_build_rec(&b, rec, sizeof rec);
		w->close(w->self);
	}
	if (!n) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "pid %lu cannot be opened", (unsigned long)pid);
		return 0;
	}

	snprintf(basedir, sizeof basedir, "%s", v->basedir);
	snprintf(dbdir, sizeof dbdir, "%s", v->dbdir);
	snprintf(pathdir, sizeof pathdir, "%s", v->pathdir);

	if (plg) {
		uint32_t pi;

		for (pi = 0; pi < v->ed.dr.n_blk; pi++)
			if (plg[pi].picked)
				plg[n_plg++] = plg[pi];
	}

	file_close(v);
	memset(v, 0, sizeof *v);

	v->eng   = eng;
	v->ext   = ext;
	v->ext2  = ext2;
	v->probe = probe;
	v->ed.dr.blk   = plg;
	v->ed.dr.n_blk = n_plg;
	v->ed.dr.decl_cap = cap;
	v->syn   = syn;
	editor_attach(v);
	snprintf(v->basedir, sizeof v->basedir, "%s", basedir);
	snprintf(v->dbdir, sizeof v->dbdir, "%s", dbdir);
	snprintf(v->pathdir, sizeof v->pathdir, "%s", pathdir);
	v->fam = fam;
	v->heur_off = heur_off;

	v->sel_a = v->sel_b = KGENOME_BROKEN;
	v->find_at = KGENOME_BROKEN;
	v->bar_open = -1;
	v->bar_sel = -1;
	v->bar_sub = -1;
	v->into_obj = -1;

	v->proc_pid = pid;
	snprintf(v->pathbuf, sizeof v->pathbuf, "pid:%lu", (unsigned long)pid);
	v->path = v->pathbuf;
	v->map = rec;
	v->map_len = n;

	if (v->eng)
		proc_collect(v, v->eng, pid);
	/*
	 * SAID ON THE STATUS LINE AS WELL AS ON THE PAGE. A short list is only
	 * misleading while nobody knows it is short, and the page is two
	 * keystrokes away - this is the line a reader is already looking at.
	 */
	if (v->proc_skipped) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "pid %lu: %lu mapping(s) not collected - too large, "
			 "or past the time this may take",
			 (unsigned long)pid, (unsigned long)v->proc_skipped);
	}
	if (!v->n_obj) {
		struct object *o = &v->obj[0];

		/* See the reset loop for what an object owns. */
		free(o->carve);
		memset(o, 0, sizeof *o);
		snprintf(o->name, sizeof o->name, "%s", v->path);
		o->buf = kof_buf_make(v->map, v->map_len);
		v->n_obj = 1;
	}
	objects_examine(v, v->eng);
	/*
	 * THE PROCESS IS THE ARCHITECTURE OF WHAT IT IS RUNNING.
	 *
	 * AFTER objects_examine AND NOT BEFORE: that pass identifies every
	 * object, and identifying one memsets its ctx - so an arch written
	 * ahead of it is zeroed again before anything draws it. Found by the
	 * panel still reading "any" with the assignment plainly there.
	 *
	 * The record carries no machine word - it is pids and counts - so the
	 * object came out "any", which is true of the RECORD and says nothing
	 * about the process. The first child with a format is the executable
	 * the walk reported first, and its arch is the process's: a 64-bit
	 * program is a 64-bit process.
	 *
	 * Copied rather than parsed again, so the two can never disagree.
	 */
	if (v->n_obj > 1 && v->obj[0].ctx.format == KOF_EVT_PROC) {
		uint32_t k;

		for (k = 1; k < v->n_obj; k++)
			if (v->obj[k].fmt && v->obj[k].ctx.arch) {
				v->obj[0].ctx.arch = v->obj[k].ctx.arch;
				break;
			}
	}
	/* The rows the reader sees are built from the objects, not the same
	 * thing - see tree_build. Missed at first, and the shape of the miss
	 * is worth keeping: twenty-seven objects were collected, examined and
	 * correct, and the tree pane was empty because nothing had turned them
	 * into rows. */
	tree_build(v);
	view_select(v);
	return 1;
}

static void file_close(struct view *v)
{
	uint32_t i;

	/*
	 * The draft goes with the file, and its declarations own heap.
	 *
	 * Missed at first, and the shape of the miss is worth keeping: the
	 * declarations were freed by draft_clear on every path that REPLACED a
	 * draft, and by nothing at all on the path that abandoned one. That
	 * cost a few bytes at exit for as long as moving to another file meant
	 * re-execing - and became a leak per file the moment it did not.
	 */
	draft_wipe(v);
	/*
	 * The log's reader goes with the file, and so do the two buffers that
	 * gather a submission out of it.
	 *
	 * AN OBJECT DOES OWN HEAP, and this said it did not.
	 *
	 * The note here read "the objects themselves own no heap - their bytes
	 * are the mapping - so there is nothing else to undo", which is the
	 * same sentence log_window's reset loop already corrected about itself:
	 * "it stopped being true the moment anything was." The loop below grew
	 * the frees for info, sym and own; carve
	 * was never added to it, and it is heap the object keeps so
	 * that coming back to a row does not re-read it.
	 *
	 * WHAT THAT LEAKED, and it needs two files to see. The invariant every
	 * other path keeps is that a slot at or past n_obj holds nothing:
	 * on_object clears the slot it is about to fill, and log_window clears
	 * the whole of the OLD n_obj before setting the new one. This broke it
	 * by dropping n_obj to zero with those three pointers still in the
	 * slots - so opening a large file and then a smaller one left every
	 * slot the smaller one does not reach holding the larger one's overlay
	 * strings, blocks and carvings, unreachable and never freed. It repeats
	 * per file, which for a viewer somebody leaves open all day is the kind
	 * of leak that only shows up as "it got slow".
	 *
	 * THE memset IS WHAT MAKES THE EXTRA FREES SAFE. Every reuse path -
	 * on_object, and both "no objects, so the file is the object" branches
	 * - frees these three before it claims a slot. Freeing them here and
	 * leaving the pointers behind would turn this fix into a double free;
	 * zeroing the slot makes those frees no-ops, and clears the dangling
	 * sym/own the loop was already leaving in the struct.
	 */
	if (v->log) {
		kofevt_log_free(v->log);
		v->log = NULL;
	}
	free(v->evt_join);
	free(v->evt_text);
	v->evt_join = v->evt_text = NULL;
	v->evt_join_len = v->evt_text_len = 0;
	v->evt_have = 0;
	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];

		free(o->diag);
		kgenome_funcs_free(&o->funcs);
		kof_codenotes_free(&o->notes);
		kof_inspect_free(o->fmt, o->info);
		free(o->sym);
		dash_drop(o);
		free(o->fixed);
		free(o->own);
		free(o->carve);
		if (o->mapped)
			kof_unmap_file(o->mapped, o->mapped_len);
		memset(o, 0, sizeof *o);
	}
	v->n_obj = 0;
	/*
	 * ONLY A MAPPING IS UNMAPPED. A process view's v->map is the process
	 * RECORD - static storage in proc_open, not a file this ever mapped -
	 * and handing that to munmap is a page it does not own. proc_pid is
	 * what tells the two apart, because it is the one field that is set
	 * for one and clear for the other.
	 */
	if (v->map && !v->proc_pid) {
		kof_unmap_file(v->map, v->map_len);
		v->map = NULL;
		v->map_len = 0;
	}
}

/*
 * EVERY BUFFER main ALLOCATED, and the struct they hang off.
 *
 * This freed two of the four and the view itself was never freed at all, so a
 * clean exit leaked 1,840,656 bytes in three allocations - the view, ext2 and
 * the mutation block table. It cost nothing at run time, since the process was
 * about to end, and it cost every sanitizer run afterwards: a real leak
 * elsewhere arrives in the same report as these and has to be picked out of
 * them by hand.
 *
 * The view is freed HERE rather than at the one call site, so the early exit
 * paths that also have to let it go cannot each get a different subset right.
 */
static void view_free(struct view *v)
{
	if (!v)
		return;
	file_close(v);
	free(v->ext);
	free(v->ext2);
	free(v->probe);
	free(v->ed.dr.blk);
	syn_free(v->syn);
	fam_free(v);
	free(v);
}

/*
 * Point the whole view at another file, keeping the session.
 *
 * The new file is opened and mapped BEFORE the old one is let go, so a path
 * that cannot be read leaves the reader looking at what they already had with
 * a message saying why - rather than at an empty screen.
 *
 * Then the view is cleared wholesale and the session's four fields are put
 * back. Clearing wholesale rather than resetting the per-file fields by name is
 * the point: this struct has upwards of eighty members and a switch that
 * enumerated them would go stale the first time one was added, silently, in
 * whichever pane happened to hold the field that was missed.
 *
 * Returns 0 with act_msg set on failure.
 */
int file_open(struct view *v, const char *path, kof_engine *eng)
{
	struct stat st;
	void       *map;
	uint64_t    len;
	int         fd;
	/* The session. */
	struct kof_range *ext   = v->ext;
	struct kof_range *ext2  = v->ext2;
	/*
	 * The blocks a reader TICKED, and the mode they are in.
	 *
	 * Compacted to the front here rather than after the clear, because the
	 * clear is what takes the count with it. What was not ticked was the
	 * engine's suggestion about the file being closed and goes with it.
	 */
	struct mtn_block *plg   = v->ed.dr.blk;
	uint32_t n_plg = 0;
	struct kof_range *probe = v->probe;
	uint32_t          cap   = v->ed.dr.decl_cap;
	struct kv_syn    *syn   = v->syn;
	char basedir[sizeof v->basedir];
	char dbdir[sizeof v->dbdir];
	char pathdir[sizeof v->pathdir];
	struct kv_fam_ui *fam = v->fam;     /* the Pathogens catalog is the session's: it outlives the file */
	char keep[KOF_DUMP_PATH_ROOM];
	/*
	 * Kept only when this is the same file being rebuilt - which is what
	 * the menu item does - and dropped when it is a different one.
	 */
	int  emu_mode;
	/*
	 * Kept ACROSS files as well, unlike emu_mode: it is how the reader
	 * asked to be shown a document, not an answer about one object, and a
	 * researcher stepping through a directory with it set means it.
	 */
	int  heur_off = v->heur_off;

	snprintf(keep, sizeof keep, "%s", path);
	emu_mode = (v->path && strcmp(v->path, keep) == 0) ? v->emu_mode : 0;

	fd = open(keep, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0) {
		if (fd >= 0)
			close(fd);
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "%.60s is empty or not a regular file",
			 base_name(keep));
		return 0;
	}
	len = (uint64_t)st.st_size;
	map = kof_map_file_ro(fd, len);
	close(fd);
	if (!map) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg, "Cannot map %.60s",
			 base_name(keep));
		return 0;
	}

	snprintf(basedir, sizeof basedir, "%s", v->basedir);
	snprintf(dbdir, sizeof dbdir, "%s", v->dbdir);
	snprintf(pathdir, sizeof pathdir, "%s", v->pathdir);

	if (plg) {
		uint32_t pi;

		for (pi = 0; pi < v->ed.dr.n_blk; pi++)
			if (plg[pi].picked)
				plg[n_plg++] = plg[pi];
	}

	file_close(v);
	memset(v, 0, sizeof *v);

	v->eng   = eng;
	v->ext   = ext;
	v->ext2  = ext2;
	v->probe = probe;
	v->ed.dr.blk   = plg;
	v->ed.dr.n_blk = n_plg;
	v->ed.dr.decl_cap = cap;
	v->syn   = syn;
	editor_attach(v);       /* the clear above zeroed what it borrows */
	snprintf(v->basedir, sizeof v->basedir, "%s", basedir);
	snprintf(v->dbdir, sizeof v->dbdir, "%s", dbdir);
	snprintf(v->pathdir, sizeof v->pathdir, "%s", pathdir);
	v->fam = fam;
	v->emu_mode = emu_mode;
	v->heur_off = heur_off;

	/* The fields whose cleared value is not their resting value. */
	v->sel_a = v->sel_b = KGENOME_BROKEN;
	v->find_at = KGENOME_BROKEN;
	v->bar_open = -1;
	v->bar_sel = -1;
	v->bar_sub = -1;
	/*
	 * -1 IS NOWHERE, AND ZERO IS OBJECT ZERO.
	 *
	 * main says exactly this where it first builds the view, and the clear
	 * above undid it - so it has to be said again here, which is what this
	 * whole block is for.
	 *
	 * What it cost: on_object takes its first branch whenever into_obj is
	 * not negative, and that branch folds only the VERDICT into a row that
	 * already exists. It sets no name, no bytes and no parse, and it does
	 * not count the object. So the first thing the engine reported - which
	 * is THE FILE ITSELF - went into an empty row 0 and was then
	 * overwritten by the first child.
	 *
	 * The file therefore had no row of its own, and with no row for the
	 * file there were no REGION rows either: every one of them hangs off
	 * the object whose extents they are. A PDF opened with a database
	 * showed its children and nothing else - forty-seven rows of "Raw"
	 * where the format and the regions belonged. Opened WITHOUT a database
	 * there is no scan, on_object never runs, into_obj is never read, and
	 * the same file came up perfectly. That difference is why this read as
	 * the PDF parser having lost its regions rather than as the viewer
	 * having lost the file.
	 */
	v->into_obj = -1;

	snprintf(v->pathbuf, sizeof v->pathbuf, "%s", keep);
	v->path = v->pathbuf;
	v->map = map;
	v->map_len = len;

	/*
	 * AN EVENT LOG IS NOT A SCAN TARGET, and saying so beats a hex dump.
	 *
	 * A .ktr written by kofwatchtower or kofmontrace is a stream of fixed
	 * records, and dropping one on this viewer used to map it and show its
	 * bytes - technically correct and useless. It is a format this toolset
	 * writes for itself, so the viewer recognises it and says what it is
	 * holding rather than pretending it is a sample.
	 *
	 * Recognised here rather than added to the engine's format list on
	 * purpose: kof_format answers "what is this scanned object", and an
	 * event log is not one. Same reason kofevt is not under core/kofmod.
	 *
	 * The full browser - a scrollable event list, one event's fields on the
	 * properties panel - is a mode of its own and is not this. What this
	 * does is stop the confusing answer and name the tool that reads it.
	 */
	if (len >= sizeof(struct kofevt_log_hdr)) {
		const struct kofevt_log_hdr *lh = map;

		if (lh->magic == KOFEVT_LOG_MAGIC) {
			const char *why = "";

			/*
			 * A SECOND HANDLE, for asking where records are.
			 *
			 * The bytes come from the mapping above; this one
			 * answers "where is event N" using the log's own
			 * sparse index. Two handles because the questions are
			 * different and neither wants the other's file
			 * position.
			 */
			v->log = kofevt_log_open(keep, 0, KOFEVT_REC_NONE,
						 &why);
			if (v->log) {
				v->log_n     = kofevt_log_count(v->log);
				v->log_first = 0;
				/*
				 * OPEN FROM THE START, because a log is opened
				 * to read events and the bytes on their own do
				 * not say what one is. The panel is where the
				 * record becomes readable, so making a reader
				 * find a menu item first would be hiding the
				 * point of the view behind a switch.
				 *
				 * It is still closable, and closing it sticks
				 * for the rest of the file - a reader working
				 * on the bytes themselves said what they
				 * wanted.
				 */
				v->evt_open = 1;
				v->evt_sel = -1;
				/*
				 * A failed allocation is not fatal: the panel
				 * then shows what the record itself holds,
				 * which is what it showed before continuations
				 * existed. It is not worth refusing to open a
				 * log over.
				 */
				v->evt_join = malloc(EVT_JOIN_MAX);
				v->evt_text = malloc(EVT_TEXT_MAX);
				log_scan_verbs(v);
				log_window(v);
			} else {
				snprintf(v->act_msg, sizeof v->act_msg,
					 "event log: %s", why);
			}
			snprintf(v->act_msg, sizeof v->act_msg,
				 "event log: %s/%s, sensor build %lu, "
				 "%llu event(s)",
				 kof_evt_platform_name((uint8_t)lh->platform),
				 kof_evt_arch_name((uint8_t)lh->arch),
				 (unsigned long)lh->build,
				 (unsigned long long)v->log_events);
			v->act_ok = 1;
		}
	}

	/*
	 * A LOG IS NOT SCANNED, and its objects are already built.
	 *
	 * objects_collect runs the engine over the file to find what is in it,
	 * which is the right question for a sample and the wrong one for a
	 * stream of records: it would find nothing, and then the fallback
	 * below would replace the event window with one object holding the
	 * whole file.
	 */
	if (v->eng && !v->log)
		objects_collect(v, v->eng);
	if (!v->n_obj) {
		/*
		 * No database, or a scan that produced nothing. The file is
		 * still an object and is still worth looking at - the tree is
		 * just one deep.
		 */
		struct object *o = &v->obj[0];

		/* See the reset loop for what an object owns. */
		free(o->carve);
		memset(o, 0, sizeof *o);
		snprintf(o->name, sizeof o->name, "%s", v->path);
		o->buf = kof_buf_make(v->map, v->map_len);
		v->n_obj = 1;
	}
	objects_examine(v, v->eng);
	tree_build(v);
	view_select(v);

	v->ed.dr.saved_hash = draft_hash(&v->ed);
	return 1;
}

int main(int argc, char **argv)
{
	/*
	 * NO DEFAULT BASES DIRECTORY: a rebuild writes into a tree, and one nobody
	 * named is one nobody expects to be written.
	 *
	 * Empty rather than NULL: v->basedir is a fixed buffer and every reader
	 * of it already tests basedir[0], so "not given" stays one convention
	 * instead of two.
	 */
	const char *path = NULL, *db = NULL, *base = "", *syn_dir = NULL, *path_dir = NULL;
	/* The process to open instead of a file, or 0. */
	uint32_t    want_pid = 0;
	uint64_t last_paint = 0;
	/*
	 * ON THE HEAP, BECAUSE IT DOES NOT FIT ON THE STACK.
	 *
	 * struct view is 1.2MB - almost all of it the row array and the object
	 * array - and the default stack for a thread on Windows is 1MB. As a
	 * local it overflowed before main had done anything: the process exited
	 * with 0xC00000FD and printed nothing, which reads exactly like a
	 * missing library rather than like what it was.
	 *
	 * It was ALREADY at three quarters of the stack before the row array
	 * grew, so this is not a fix for one number - a local of that size is
	 * one deep call chain away from the same crash whatever the constants
	 * say. On the heap the constants are free to be sized for the job, and
	 * the failure mode of a too-large one becomes a NULL from calloc, which
	 * is a message rather than a silent exit.
	 */
	struct view *v;
	struct stat st;
	int i, rc = 0;

	/*
	 * Before argv is read and before the console is touched.
	 *
	 * Two things on Windows: argv gets the name the command line actually
	 * carried rather than what the ANSI codepage could spell, and the
	 * console output page becomes UTF-8 so the bytes this prints are the
	 * characters a reader sees. See kof_utf8_init.
	 */
	kof_utf8_init(&argc, &argv);

	v = calloc(1, sizeof *v);
	if (!v) {
		fprintf(stderr, "kofviewer: out of memory\n");
		return 1;
	}
	/* -1 is "nowhere", and zero is a real object index - see into_obj. A
	 * memset alone would have aimed every scan's root at the file. */
	v->into_obj = -1;
	/* The process to open instead of a file, or 0. */
	/* The one preference that is not zero at rest. Everything else file_open
	 * sets, for the first file and for every one after it. */
	v->ed.dr.decl_cap = 12;
	/*
	 * The editor borrows what it needs and owns the draft.
	 *
	 * Pointers rather than copies for anything that changes while the
	 * session runs - the object count grows as children are found -
	 * because a copy of a number that changes is a number that goes stale.
	 */
	editor_attach(v);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--pid") && i + 1 < argc)
			want_pid = (uint32_t)strtoul(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--db") && i + 1 < argc)
			db = argv[++i];
		/*
		 * Three values, refused rather than clamped - the same
		 * contract kofscanner's --heur has, and for its reason: a tool
		 * that quietly did less than it was told to is the one result
		 * worth never producing. Only 0 is a MODE here; 1 and 2 differ
		 * in what the heuristics cost, and this tool has one file and
		 * somebody waiting in front of it, so 2 is the default.
		 */
		else if (!strcmp(argv[i], "--heur") && i + 1 < argc) {
			const char *hv = argv[++i];

			if (!strcmp(hv, "0")) {
				v->heur_off = 1;
			} else if (strcmp(hv, "1") && strcmp(hv, "2")) {
				fprintf(stderr, "kofviewer: --heur takes 0, "
					"1 or 2, not '%s'\n", hv);
				free(v);
				return 2;
			}
		}
		else if (!strcmp(argv[i], "--bases") && i + 1 < argc)
			base = argv[++i];
		else if (!strcmp(argv[i], "--syndromes") && i + 1 < argc)
			syn_dir = argv[++i];
		else if (!strcmp(argv[i], "--pathogens") && i + 1 < argc)
			path_dir = argv[++i];
		/* Asked for by name, and answered with 0: a reader who typed
		 * --help did not make a mistake. */
		else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage();
			return 0;
		}
		else if (argv[i][0] == '-') {
			usage();
			return 2;
		} else if (!path) {
			path = argv[i];
		} else {
			usage();
			return 2;
		}
	}
	if (!path && !want_pid) {
		usage();
		return 2;
	}

	/*
	 * The tree a drafted signature is written into.
	 *
	 * Checked here rather than at the moment of writing, because the moment
	 * of writing is after the work: a researcher who has spent an hour on a
	 * draft should not be told then that the directory they named does not
	 * exist. A path that is not a directory is refused; one that does not
	 * exist yet is accepted, and a researcher naming a new tree means it.
	 */
	if (stat(base, &st) == 0 && !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "kofviewer: --bases %s is not a directory\n",
			base);
		return 1;
	}
	snprintf(v->basedir, sizeof v->basedir, "%s", base);
	/* Manage > Pathogens: --pathogens, else <bases>/pathogens; with neither known the dialog's Save refuses. */
	if (path_dir)
		snprintf(v->pathdir, sizeof v->pathdir, "%s", path_dir);
	else if (base[0])
		snprintf(v->pathdir, sizeof v->pathdir, "%s/pathogens", base);
	if (db)
		snprintf(v->dbdir, sizeof v->dbdir, "%s", db);
	/*
	 * THE TAG SOURCES, loaded once for the session: the directory is
	 * `<bases>/syndromes` unless --syndromes names another, and the
	 * diagnose sources a tag is counted in are `<bases>/diagnoses`. With no
	 * --bases the tree is the one in the working directory.
	 */
	{
		char sdir[256], ddir[256];

		snprintf(sdir, sizeof sdir, "%s/syndromes",
			 base[0] ? base : "bases");
		snprintf(ddir, sizeof ddir, "%s/diagnoses",
			 base[0] ? base : "bases");
		v->syn = syn_new(syn_dir ? syn_dir : sdir, ddir);
		editor_attach(v);
	}

	/*
	 * A DIRECTORY IS A REASONABLE THING TO POINT THIS AT.
	 *
	 * Samples arrive in folders, and the first thing anybody does with one
	 * is open a file in it and start stepping. Resolving the folder here
	 * means Ctrl+] and Ctrl+\ work from the first frame, on the same
	 * ordering they will use for the rest of the session.
	 *
	 * An empty folder is FATAL rather than an empty window. A viewer with no
	 * object shows three empty panes and a status line about nothing, which
	 * reads as the program having failed to load a file it never had; a line
	 * on stderr says what is actually true.
	 */
	if (path && stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		static char first[KOF_DUMP_PATH_ROOM];

		if (!dir_pick(path, NULL, PICK_FIRST, first, sizeof first)) {
			fprintf(stderr, "kofviewer: %s holds no file to open\n",
				path);
			return 1;
		}
		path = first;
	}

	v->ext = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v->ext);
	v->ext2 = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v->ext2);
	v->probe = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v->probe);
	v->ed.dr.blk = calloc(MTN_MAX_BLOCK, sizeof *v->ed.dr.blk);
	if (!v->ext || !v->ext2 || !v->probe || !v->ed.dr.blk) {
		fprintf(stderr, "kofviewer: out of memory\n");
		return 1;
	}

	if (db) {
		v->eng = keng_open(db);
		if (!v->eng)
			fprintf(stderr, "kofviewer: cannot load a database from "
					"%s\n", db);
	}
	/* A pid and a path are two ways of naming what to look at; the pid
	 * wins when both are given, because it is the more specific ask. */
	if (want_pid ? !proc_open(v, want_pid, v->eng)
		     : !file_open(v, path, v->eng)) {
		fprintf(stderr, "kofviewer: %s\n", v->act_msg);
		keng_close(v->eng);
		view_free(v);
		return 1;
	}

	/*
	 * SAY SO WHEN THERE IS NO DATABASE, because every silence that follows
	 * looks like an answer.
	 *
	 * Without one there is no scanner at all - kscan_new refuses a
	 * null engine - so nothing is unpacked, no script is normalised, no
	 * rule is asked and the tree holds one node. All of which is exactly
	 * what a clean file looks like. It cost a reader a round trip of
	 * "nothing changed" against a build where the thing they were looking
	 * for was working, so the one frame that can still explain it does.
	 */
	if (!v->eng) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "No database: pass --db to unpack, normalise and "
			 "match");
	}

	if (!term_setup()) {
		rc = 1;
		goto out;
	}
	last_paint = now_ms();
	redraw(v);
	for (;;) {
		int k = read_key();

		if (k == K_NONE)
			break;
		if (!handle(v, k) || v->quit)
			break;
		/*
		 * One frame per batch of input, not one per key.
		 *
		 * A held page key repeats faster than a screen can be painted,
		 * and painting every repeat means the terminal is always partway
		 * through a frame - which is what the flash is. Skipping the
		 * paint while more input is already waiting collapses a burst
		 * into a single frame at the position it ends at, and the
		 * intermediate positions were never worth drawing: nobody can
		 * read a pane that is moving.
		 *
		 * The clock is the guard. Without it a key repeating forever
		 * would postpone the frame forever, so anything older than a
		 * frame time gets painted whether or not more is queued.
		 */
		if (key_pending() && now_ms() - last_paint < 33u)
			continue;
		/* redraw decides for itself whether anything changed. */
		redraw(v);
		last_paint = now_ms();
	}
	term_restore();

out:
	{
		/* The engine outlives the view by one line: view_free releases
		 * the view, so its `eng` cannot be read after it. */
		kof_engine *eng = v->eng;

		view_free(v);
		keng_close(eng);
	}
	return rc;
}
