#define _GNU_SOURCE
#include "kv.h"


/*
 * Write the file and everything recovered from it, the way kofexamine --dump
 * would have.
 *
 * The objects are the ones already collected and already parsed, so nothing is
 * scanned again: object 0 is the file and gets the dump directory itself; every
 * other one is something an unpacker produced and gets unpacked.<n>[.<label>]
 * beside it, plus a .regions directory of its own. That numbering is
 * kofexamine's, and it is the same because a researcher who dumps from both
 * should not have to learn where the same bytes went twice.
 *
 * An object the session could not keep - past the budget, so `too_big` - has no
 * bytes here to write. It is counted and named rather than skipped silently,
 * because a dump missing one of its objects looks exactly like a dump of an
 * object that was never there.
 */
/* The status bar has one line and a dump directory sits beside a path that can
 * be any length, so the message names the directory and not the road to it. */
const char *base_name(const char *path)
{
	return kof_path_base(path);
}

/*
 * Point the editor at what it borrows.
 *
 * A FUNCTION and not a run of assignments in main, because there are two places
 * that need it: startup, and the whole-view clear that opening another file
 * does. Written inline the first time, the second place did not do it - the
 * clear zeroed the borrowed pointers and the first repaint dereferenced NULL.
 * One place to call means there cannot be a third that forgets.
 */
void editor_attach(struct view *v)
{
	v->ed.obj      = v->obj;
	v->ed.n_obj    = &v->n_obj;
	v->ed.edit     = &v->edit;
	v->ed.scratch  = v->probe;
	v->ed.eng      = v->eng;
	v->ed.tags     = v->syn ? &v->syn->set : NULL;
}

/*
 * See the note on BI_UNPACKER: the interpreter, on the selected object.
 *
 * The children it produces are named under that object's own name, so the
 * engine's "//n" convention puts them in the tree exactly where they belong and
 * tree_build needs to know nothing about where they came from.
 */
void emu_here(struct view *v)
{
	struct object *o = cur_obj(v);
	struct kof_scan_option opt;
	kof_scanner *sc;
	uint32_t before = v->n_obj;

	v->act_ok = 0;
	if (!v->eng) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "No database to unpack with");
		return;
	}
	if (!o->buf.p || !o->buf.n) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Object bytes were not kept");
		return;
	}
	if (o->emu_done) {
		/*
		 * Not an error and not silence: the reader pressed a button and
		 * is owed an answer, and the answer is that this one has been
		 * asked already. Whatever it produced is in the tree below.
		 *
		 * The wording no longer names the emulator, because the action
		 * no longer does - see emu_here's opt.emu_use. What has been
		 * spent is an unpack pass over these bytes, whichever way it
		 * came apart.
		 */
		snprintf(v->act_msg, sizeof v->act_msg,
			 "This object has already been unpacked");
		return;
	}
	sc = kscan_new(v->eng);
	if (!sc) {
		snprintf(v->act_msg, sizeof v->act_msg, "Out of memory");
		return;
	}
	/*
	 * AND THE GATE, HERE, BECAUSE THIS IS WHERE IT WAS ASKED FOR.
	 *
	 * It reads every executable segment to decide whether emulating is
	 * worth it, and it used to run when an object was merely selected -
	 * which faulted a spilled object in whole for a status-line tag, and
	 * put the word "emu" on screen about a file nobody had asked to
	 * emulate. Once per object; obj_emu_why only reports what this left.
	 */
	if (!o->emu_why_done && o->fmt && o->info &&
	    o->ctx.format == KOF_FMT_ELF) {
		struct kgenome_obj gobj;

		o->emu_why_done = 1;
		kof_genome_obj(&o->ctx, &gobj);
		o->emu_why = (uint8_t)kgenome_emu_unp_gate(&gobj, o->info,
						       o->buf.p, o->buf.n);
	}
	/*
	 * SAID BEFORE IT STARTS, AND WRITTEN STRAIGHT TO THE STATUS ROW.
	 *
	 * Interpreting an object takes as long as it takes - seconds on
	 * anything large - and the loop does not come back round until it is
	 * over, so without this the screen sits unchanged and the reader cannot
	 * tell a slow answer from a program that has stopped responding.
	 *
	 * Not a redraw. A full frame is a few kilobytes of escape sequences to
	 * say one thing that fits in the corner, and the frame it would paint
	 * is the one already on the screen. Just the notice, where the result
	 * will appear a moment later.
	 */
	{
		char note[64];
		int at;

		snprintf(note, sizeof note, " Unpacking... ");
		at = g_cols - (int)strlen(note);
		if (at < 1)
			at = 1;
		{
			char seq[128];
			int n = snprintf(seq, sizeof seq,
					 "\033[%d;%dH" A_WARN "%s" A_OFF,
					 mark_row(), at, note);

			if (n > 0)
				term_write_n(seq, (size_t)n);
		}
	}
	memset(&opt, 0, sizeof opt);
	opt.report_diag = 1;
	/* The same level as the ordinary collect - see the note there. A node
	 * re-examined through the interpreter must not lose the heuristics the
	 * first pass would have run on it. */
	opt.heur_level = KOF_HEUR_LEVEL_MAX;
	/*
	 * AUTO, AND THE ENGINE'S MODULES DECIDE - not this tool.
	 *
	 * It was ONLY, which the flag's own description calls "interprets
	 * INSTEAD OF the packer modules": pressing this spent a run even on an
	 * object a static unpacker opens in milliseconds. The argument for it
	 * was that AUTO declines once a packer has claimed the object, "which
	 * on this node it already has" - true of the PARENT's scan, and this
	 * is a fresh scan of these bytes, where nothing has claimed anything
	 * yet. So AUTO does exactly what is wanted: every module is offered
	 * the object first, and the interpreter runs only where none of them
	 * opened it and something says it is worth a run.
	 *
	 * That is also the only honest reading of the button. A reader asking
	 * to unpack an object is asking for it to come apart, not for a
	 * particular mechanism; which mechanism worked is the engine's answer
	 * and is reported afterwards.
	 */
	opt.emu_use = KOF_EMU_AUTO;
	v->skip_root = 1;
	/* Everything already in the list belongs to the first pass - see the
	 * dedup in on_object. Zero afterwards, because an ordinary collect
	 * starts from an empty list and has nothing to compare against. */
	v->dedup_from = v->n_obj;
	v->scan_sc = sc;
	kscan_bytes(sc, o->buf.p, o->buf.n, o->name, &opt, on_object, v);
	kscan_free(sc);
	v->dedup_from = 0;
	v->skip_root = 0;
	/*
	 * Marked whatever came of it. A run that recovered nothing has still
	 * been made, and repeating it would spend the same instructions to
	 * print the same sentence.
	 *
	 * Re-read rather than kept from before the scan: on_object may have
	 * grown v->obj, and a realloc'd array leaves the old pointer dangling.
	 */
	o = &v->obj[v->node[v->sel_node].obj];
	o->emu_done = 1;

	if (v->n_obj == before) {
		/*
		 * A reason, and a short one. Which header field disagreed with
		 * which is a question for the dashboard; here there is one line
		 * and the reader wants to know whether to try something else.
		 */
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Nothing came out of this object");
		return;
	}
	objects_examine_from(v, v->eng, before);
	tree_build(v);
	view_select(v);
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg,
		 "Unpacked %u object(s)", v->n_obj - before);
}

/*
 * SAY WHAT THE REOPEN ACTUALLY PRODUCED, not that a reopen happened.
 *
 * "reopened, unpacked by the emulator" is true of a file the emulator could not
 * touch and of one it took apart, and on the first the reader is left looking
 * at a tree one deep with nothing to say why. The engine already worked out the
 * why - it is on the object, in the same field a truncated archive uses - so
 * this reads it back rather than inventing a second account of it.
 *
 * The common case is worth spelling out: a UPX sample cut short has no entry
 * point left in it, because the stub sits past the compressed data. The static
 * unpacker still recovers the prefix by reading structure; there is nothing for
 * an interpreter to start.
 */
static void say_unpacked(struct view *v)
{
	const char *who = v->emu_mode ? "emulator" : "static unpacker";
	uint32_t kids = v->n_obj ? v->n_obj - 1u : 0;

	v->act_ok = kids != 0;
	/*
	 * No "reopened" prefix. The tree changing under the reader is the one
	 * part they can already see, and the status line is narrow enough that
	 * spending ten columns on it truncated away the REASON - which is the
	 * only part they cannot work out for themselves.
	 */
	if (kids) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "%s: recovered %u object(s)", who, kids);
		return;
	}
	if (v->n_obj && v->obj[0].broken) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "%s: nothing (%s)", who,
			 kverdict_broken_name(v->obj[0].broken));
		return;
	}
	snprintf(v->act_msg, sizeof v->act_msg,
		 "%s: nothing to open", who);
}

/*
 * SEPARATE NOW, having opened without separating.
 *
 * THE WHOLE FILE AND NOT THE SELECTED ROW, which is a decision and not a
 * shortcut. A scan of one object's bytes APPENDS what it finds to the end of
 * the object list, and the tree works out a child's parent by looking back for
 * the nearest shallower object above it - see child_of_entry. That holds for
 * objects arriving in walk order, and an append breaks it the moment the row
 * asked about is not the deepest thing in the list: the children would hang
 * off whichever object happened to be last. Re-collecting the file produces the
 * walk in order, the way opening it does, so the tree is right by the same
 * argument it is right on open.
 *
 * Through file_open, which is how the other mode that changes what a scan does
 * - the emulator - already rebuilds. The draft is why the item is disabled
 * while one is edited: a rebuild throws it away.
 */
void separate_now(struct view *v)
{
	char keep[KOF_DUMP_PATH_ROOM];
	uint32_t before = v->n_obj;

	v->act_ok = 0;
	if (!v->path || !v->path[0])
		return;
	snprintf(keep, sizeof keep, "%s", v->path);
	v->heur_off = 0;
	if (!file_open(v, keep, v->eng))
		return;                 /* file_open left the reason */
	/*
	 * Counted rather than assumed. A document whose every entry is an
	 * image nothing opens separates into nothing, and that is an answer -
	 * the entry rows are still there, and they now say so having been
	 * tried rather than having been skipped.
	 */
	v->act_ok = v->n_obj > before;
	if (v->n_obj > before)
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Separated %u object(s)", v->n_obj - before);
	else
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Nothing separated: no entry could be opened");
}

/*
 * Write the object tree out, from the unpacker named.
 *
 * The tree on screen is what one unpacker made of the file, so dumping the
 * OTHER one's view means rebuilding the tree first - and then what was written
 * is what is on screen, which is the only version of this a reader can check.
 * Producing a directory that does not match the view would be worse than
 * making them ask twice.
 *
 * The directories differ by an _emu suffix so both can exist at once. That is
 * the point of having two: the static unpacker and the interpreter disagreeing
 * about the same file is a finding, and it cannot be seen if one overwrites the
 * other.
 */
/*
 * Has the interpreter already run on anything in this tree?
 *
 * "Unpack with emulator" runs it on ONE object and marks that object; opening
 * the file in emu mode runs it on the walk. Either way the answer the reader is
 * looking at came from the interpreter, and a dump should write THAT answer.
 */
int tree_has_emu(const struct view *v)
{
	uint32_t i;

	if (v->emu_mode)
		return 1;
	for (i = 0; i < v->n_obj; i++)
		if (v->obj[i].emu_done)
			return 1;
	return 0;
}

/*
 * WOULD THIS DUMP HAVE TO REBUILD THE TREE?
 *
 * One predicate, because two places ask it and they were answering
 * differently. `enabled` refused both dump items whenever a draft was open, on
 * the grounds that either MIGHT rebuild and a rebuild throws the draft away;
 * dump_all then decided for itself whether it actually would. So a reader with
 * a draft open could not dump a tree that needed no rebuilding at all.
 *
 * Now that kof_result.emu_unpacked reports honestly - it never did before, see
 * the note in dump_all - the common case is that no rebuild is needed: the
 * tree on screen already came from a run, and dumping it writes what the
 * reader is looking at.
 */

void dump_all(struct view *v, int use_emu)
{
	int rebuilt = 0;
	char dir[KOF_DUMP_PATH_ROOM], sub[KOF_DUMP_PATH_ROOM], why[256];
	struct kof_dump_stat ds;
	uint32_t i, files = 0, kids = 0, skipped = 0;
	uint64_t bytes = 0;

	v->act_ok = 0;
	/*
	 * THE TREE ON SCREEN IS THE ANSWER, WHEN IT ALREADY CAME FROM THE
	 * INTERPRETER.
	 *
	 * This compared against emu_mode alone, which is set by OPENING the
	 * file in emu mode and not by "Unpack with emulator" - so after that
	 * button the file was reopened and the interpreter ran a second time
	 * from the beginning. Two costs, and the second is the one that
	 * matters: 17 seconds and 207 million instructions on a PECompact2
	 * sample, and a run that need not agree with the first. The
	 * interpreter carries state a second pass does not reproduce - the
	 * idle counter, which snapshots it took, null calls, unhandled
	 * exceptions - so the dump could hold something the reader never saw.
	 *
	 * AND THE OTHER HALF OF THAT WAS IN THE ENGINE. tree_has_emu also
	 * reads kof_result.emu_unpacked, which a tool uses to know that a tree
	 * ALREADY came from a run - and the flag behind it,
	 * kof_scanner.emu_produced, was never set by anything. It was cleared
	 * per object and read as zero for the life of the object, so a
	 * PECompact sample the interpreter had just unpacked reported that it
	 * had not, and this re-ran on it every time. Set now where it means
	 * something: a child pushed while the machine is live - see kid_push.
	 *
	 * Going the other way still reopens: a reader asking for the STATIC
	 * dump of a tree that came from the interpreter is asking for
	 * something this tree does not contain.
	 */
	if (dump_needs_rebuild(v, use_emu)) {
		char keep[KOF_DUMP_PATH_ROOM];

		snprintf(keep, sizeof keep, "%s", v->path);
		v->emu_mode = use_emu;
		if (!file_open(v, keep, v->eng))
			return;         /* file_open left the reason */
		rebuilt = 1;
	}
	/*
	 * Whatever the dump goes on to say, the reader has just had the tree
	 * replaced under them and is owed the reason it looks the way it does.
	 * Written first so a dump message overwrites it - the dump is what they
	 * asked for - and left standing when the dump writes nothing at all.
	 */
	say_unpacked(v);
	if (!kof_dump_dir_for(v->path, dir, sizeof dir)) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Dump failed: path too long");
		return;
	}
	if (use_emu) {
		size_t at = strlen(dir);

		if (at + 5 > sizeof dir) {
			snprintf(v->act_msg, sizeof v->act_msg,
				 "Dump failed: path too long");
			return;
		}
		memcpy(dir + at, "_emu", 5);
	}
	/*
	 * ONE CALL PER OBJECT, AND THE PLACEMENT IS THE ENGINE'S.
	 *
	 * This built a tag out of the LIST INDEX - "1", "2.norm" - and wrote
	 * every object into the dump root as a sibling, so a tree three layers
	 * deep came out flat and a normalised view sat beside the object it is
	 * a view of. kofexaminer had a second loop doing the same thing by
	 * another name. The engine names an object by its whole descent and
	 * kof_dump_walk asks it; both tools call that and neither lays a tree
	 * out any more.
	 */
	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];

		if (o->too_big || !o->buf.n) {
			skipped++;
			continue;
		}
		if (!kof_dump_walk(dir, o->name, o->buf, o->fmt, &o->ctx, &ds,
				   sub, sizeof sub, why, sizeof why)) {
			snprintf(v->act_msg, sizeof v->act_msg,
				 "Dump stopped: %.120s", why);
			return;
		}
		if (i)
			kids++;
		files += ds.regions;
		bytes += ds.region_bytes;
	}

	/*
	 * AND WHETHER THE TREE WAS THE ONE ON SCREEN, which is the answer to
	 * the question a reader asks after pressing this twice: the second
	 * press used to cost a full interpreter run and say nothing about it.
	 */
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg,
		 "Dumped %u region(s), %llu B, %u recovered -> %.60s%s%s",
		 files, (unsigned long long)bytes, kids, base_name(dir),
		 rebuilt ? "  (tree rebuilt)" : "  (tree as shown)",
		 skipped ? "  some too large to hold" : "");
}

/*
 * THE NEXT FILE IN THE SAME DIRECTORY, BY RE-EXEC.
 *
 * Reading a directory of samples one after another is how this tool is used, and
 * quitting and retyping a path between each one is most of the work. This is that
 * loop.
 *
 * Re-exec rather than tearing the view down and rebuilding it, and that is a
 * deliberate trade. Every pointer in the view - the mapping, the object tree, the
 * touch lists, the draft - belongs to one file, and unwinding them in the right
 * order to load another is a page of code whose bugs would all be use-after-free.
 * exec hands the problem to the kernel: the process is replaced, nothing leaks,
 * and every option the viewer was started with survives because argv does.
 *
 * The cost is honest and small: the database is loaded again. That is a second on
 * a large one, against a rewrite that could lose somebody's draft.
 */
/* Defined with the rest of the session's lifetime, at the foot of this file. */


/*
 * The file next to this one in its directory, in either direction.
 *
 * `dir` is +1 for the next name and -1 for the one before it. Ordering is by
 * name rather than by whatever readdir hands back, so stepping forward and then
 * back returns to where it started - which is the only property that makes a
 * pair of these usable as a way of walking a sample directory.
 *
 * Directories, empty files and anything that cannot be stat'ed are skipped
 * rather than ending the walk: a sample directory routinely holds a README and
 * a subdirectory of notes, and stopping at one would put the rest out of reach.
 *
 * Returns 0 and leaves a message when there is nothing that way.
 */
/*
 * What counts as a file this viewer will step to.
 *
 * NOT the same test the scanner's directory walk uses, and the difference is
 * deliberate. That one lstats and takes empty files, because scanning one is a
 * question with an answer - "zero findings on an object is a result". This is
 * navigation: an empty file opens a window on nothing, and a directory or a
 * socket is not an object at all. A sample directory routinely holds a README
 * and a subdirectory of notes, and stepping into either is a dead end.
 */
static int walkable_file(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
}

int dir_pick(const char *folder, const char *from, int which,
		    char *out, size_t cap)
{
	DIR *d = opendir(folder);
	struct dirent *e;
	char best[KOF_DUMP_PATH_ROOM], dir[KOF_DUMP_PATH_ROOM];
	size_t dn;
	int found = 0;

	if (!d)
		return 0;
	/*
	 * A TRAILING SLASH WOULD PUT "//" IN THE PATH, AND "//" MEANS SOMETHING.
	 *
	 * It is KOF_OBJ_SEP: the engine joins a container to what it holds with
	 * it, so "dir//file.tar" does not name a file in a directory, it names
	 * an object inside a container called "dir". Opening a folder written
	 * with its trailing slash made the FILE read as a child of the folder -
	 * the tree indented the root and labelled it "//paths.tar Tar-any", and
	 * the dashboard called it a nested object.
	 *
	 * The scanner's own directory walk trims this for exactly the same
	 * reason; see scan.c. One more place that has to know, because the
	 * separator is shared and a caller building a path is a caller that can
	 * spell it wrong.
	 */
	dn = strlen(folder);
	while (dn > 1 && folder[dn - 1] == '/')
		dn--;
	if (dn >= sizeof dir)
		dn = sizeof dir - 1u;
	memcpy(dir, folder, dn);
	dir[dn] = 0;
	while ((e = readdir(d)) != NULL) {
		char cand[KOF_DUMP_PATH_ROOM];

		if (which != PICK_FIRST) {
			int rel = strcmp(e->d_name, from);

			/* On the wrong side of where we are, or where we
			 * already are. */
			if (which > 0 ? rel <= 0 : rel >= 0)
				continue;
		}
		/*
		 * Further away than the best so far. Nearest wins, which for
		 * NEXT is the smallest name above and for PREV the largest
		 * below - and for FIRST, the smallest of all.
		 *
		 * `>= 0` and not `> 0`: FIRST wants the smallest name, which is
		 * the same comparison NEXT uses. Written as `which > 0` it fell
		 * in with PREV and opened a folder on its LAST file.
		 */
		if (found) {
			int cmp = strcmp(e->d_name, base_name(best));

			if (which >= 0 ? cmp >= 0 : cmp <= 0)
				continue;
		}
		/* "/" is the one directory whose name already ends in the
		 * separator and must keep it, or the join would be "/name"
		 * spelled "//name". */
		if ((size_t)snprintf(cand, sizeof cand, "%s%s%s", dir,
				     dir[0] == '/' && !dir[1] ? "" : "/",
				     e->d_name) >= sizeof cand)
			continue;
		if (!walkable_file(cand))
			continue;
		snprintf(best, sizeof best, "%s", cand);
		found = 1;
	}
	closedir(d);
	if (found)
		snprintf(out, cap, "%s", best);
	return found;
}

/*
 * The directory a path lives in, as a string dir_pick can open.
 *
 * "." for a bare name, and the separator dropped from anything else - which is
 * the one piece of string work both callers were doing separately.
 */
static void dir_of(const char *path, char *out, size_t cap)
{
	const char *base = base_name(path);
	size_t lead = (size_t)(base - path);

	if (!lead || lead + 1 >= cap) {
		snprintf(out, cap, ".");
		return;
	}
	memcpy(out, path, lead);
	out[lead - 1] = 0;              /* drop the separator */
	if (!out[0])
		snprintf(out, cap, "/");   /* the path was "/name" */
}

/*
 * The file next to this one in its directory, in either direction.
 *
 * Returns 0 and leaves a message when there is nothing that way.
 */
static int neighbour_file(struct view *v, int dir, char *out, size_t cap)
{
	char folder[KOF_DUMP_PATH_ROOM];

	dir_of(v->path, folder, sizeof folder);
	if (dir_pick(folder, base_name(v->path), dir, out, cap))
		return 1;
	v->act_ok = 0;
	snprintf(v->act_msg, sizeof v->act_msg, "No %s file in this folder",
		 dir > 0 ? "next" : "previous");
	return 0;
}

/*
 * Step to the neighbouring file.
 *
 * This used to re-exec the program, because the view was full of pointers whose
 * lifetime was one file. It now hands the path to file_open, which keeps the
 * engine - so stepping through a directory of samples no longer reloads the
 * database once per file, and the terminal never leaves raw mode.
 */
void open_step(struct view *v, int dir)
{
	char next[KOF_DUMP_PATH_ROOM];

	if (!neighbour_file(v, dir, next, sizeof next))
		return;
	if (!file_open(v, next, v->eng))
		return;                 /* file_open left the reason */
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg, "Opened %.60s",
		 base_name(v->path));
}

/*
 * Rebuild the signature database and pick it up, without leaving.
 *
 *
 * WHY IT SHELLS OUT TO make
 *
 * Building a database is two stages and neither is small. Each source is
 * compiled freestanding, then checked for relocations and for writable state,
 * then linked to raw bytes - that is ksigbuilder --module, seven hundred lines of it
 * wrapped around five tools - and only then does ksigbuilder pack the artefacts.
 * A second implementation of that inside a viewer would be a second thing to
 * keep in step with the first, and the first is where the checks live.
 *
 * So this runs the build that already exists, in the tree it belongs to.
 *
 *
 * FINDING THE TREE
 *
 * Upwards from the bases directory, to the first level holding a Makefile. That
 * is the directory the sources are part of, which is a better answer than the
 * working directory: a viewer started from somewhere else would otherwise
 * rebuild whatever tree it happened to be standing in, or nothing at all.
 *
 *
 * WHAT IT DOES AFTERWARDS
 *
 * Closes the engine, opens the new one, and re-opens the file. Re-opening is
 * the point rather than a side effect: the reason to rebuild from in here is to
 * see whether the rule just written fires, and an engine swapped in under a
 * result computed against the old one would still show the old answer.
 *
 * The build's own output goes to a file and only its last line is shown - a
 * compiler diagnostic is what the reader needs, and the rest of a build log is
 * not, on a status line one row tall.
 */
static int tree_root_of(const char *bases, char *out, size_t cap)
{
	char at[KOF_DUMP_PATH_ROOM];

	if (!kof_abs_path(bases, at, sizeof at)) {
		/* A bases directory that does not exist yet is legal - generate
		 * creates it - so fall back to where this was started. */
		if (!kof_getcwd(at, sizeof at))
			return 0;
	}
	for (;;) {
		char mk[KOF_DUMP_PATH_ROOM];
		struct stat st;
		const char *sep;

		if ((size_t)snprintf(mk, sizeof mk, "%s/Makefile", at) <
		    sizeof mk && stat(mk, &st) == 0 && S_ISREG(st.st_mode)) {
			size_t n = strlen(at);

			if (n >= cap)
				return 0;
			memcpy(out, at, n + 1u);
			return 1;
		}
		/* Indexed rather than cast: the helper answers about any
		 * string and says so with const, while `at` is this function's
		 * own buffer and trimming it in place is the point. */
		sep = kof_path_sep_last(at);
		if (!sep || sep == at)
			return 0;
		at[sep - at] = 0;
	}
}

static void build_last_line(const char *log, char *out, size_t cap)
{
	FILE *f = fopen(log, "r");
	char line[200];

	out[0] = 0;
	if (!f)
		return;
	while (fgets(line, sizeof line, f)) {
		size_t n = strlen(line);

		while (n && (line[n - 1u] == 10 || line[n - 1u] == 13))
			line[--n] = 0;
		if (n)
			snprintf(out, cap, "%s", line);
	}
	fclose(f);
}

void rebuild_db(struct view *v)
{
	char root[KOF_DUMP_PATH_ROOM];
	char log[KOF_DUMP_PATH_ROOM];
	char here[KOF_DUMP_PATH_ROOM];
	kof_engine *fresh, *old;
	int fd, ok = 0;

	{
		/* A NAMED file, so it cannot use kof_src_tmpfile: the build
		 * writes it, make exits, and only then is it read back for the
		 * line to show. The directory is the engine's answer either
		 * way - one search for a writable place, not two. */
		const char *td = kof_src_tmpdir();

		if (!td) {
			v->act_ok = 0;
			snprintf(v->act_msg, sizeof v->act_msg,
				 "No writable temporary directory");
			return;
		}
		snprintf(log, sizeof log, "%s%ckofviewer-build-XXXXXX",
			 td, KOF_PATH_SEP);
	}

	if (!tree_root_of(v->basedir, root, sizeof root)) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "No Makefile above %.50s", v->basedir);
		return;
	}
	/* The path to reopen, taken before the file is closed under us. */
	snprintf(here, sizeof here, "%s", v->path);

	fd = mkstemp(log);
	if (fd < 0) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Cannot create log file");
		return;
	}

	{
		static const char *const args[] = { "make", "databases", NULL };

		ok = kof_run_to_fd(root, args, fd);
	}
	close(fd);

	if (!ok) {
		char last[200];

		build_last_line(log, last, sizeof last);
		unlink(log);
		v->act_ok = 0;
		if (last[0])
			snprintf(v->act_msg, sizeof v->act_msg,
				 "Build failed: %.130s", last);
		else
			snprintf(v->act_msg, sizeof v->act_msg, "Build failed");
		return;
	}
	unlink(log);

	/*
	 * THE ORDER HERE IS THE WHOLE OF THE CARE.
	 *
	 * The old engine must outlive everything derived from it, and the swap
	 * must not leave the view holding either half of a torn state.
	 *
	 * So: build the new engine first; hand it to file_open, which tears the
	 * old view down only after it has successfully mapped the new file; and
	 * close the old engine last, when nothing points into it any more. Each
	 * failure returns with the session exactly as it was - the old engine,
	 * the old file, and a message.
	 */
	fresh = keng_open(v->dbdir);
	if (!fresh) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Built, but %.50s will not load", v->dbdir);
		return;
	}
	old = v->eng;
	if (!file_open(v, here, fresh)) {
		keng_close(fresh);
		return;                 /* file_open left the reason */
	}
	keng_close(old);
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg, "Database rebuilt from %.60s",
		 root);
}
