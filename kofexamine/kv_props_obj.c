#define _GNU_SOURCE

/*
 * kv_props_obj.c - the per-format rows of the properties page: ELF, PDF, PE, the
 * toolchain line, the ancestry of an object and the rows every object has.
 * Split from kv_props.c by what is described (a parsed file), no logic changed.
 */

#include "kv_props_private.h"

/*
 * WHAT A PDF SAYS ABOUT ITSELF, which is the first thing a reader wants.
 *
 * Six strings from the /Info dictionary: who wrote it, with what, and what it
 * claims to be about. They are the top of the dashboard for the same reason
 * they are the top of a document's own properties dialog - a researcher
 * deciding whether a file is worth an hour reads them before any byte of it.
 *
 * A PRODUCER STRING IS ALSO EVIDENCE, not just provenance. Builders leave
 * theirs in, and one that names a tool which does not lay objects out the way
 * this document does is a disagreement worth seeing beside the anomalies.
 *
 * LOOPED OVER THE ENUM rather than six named lines, so a field added to the
 * parse appears here without this function being touched - the same reason the
 * regions and the anomalies below are drawn from the registry rather than
 * listed. The label comes from the parse too, so the two cannot disagree about
 * what a field is called.
 *
 * Nothing is drawn for a key the document does not carry, which is most of
 * them in most files. A row reading "author -" teaches nothing and pushes the
 * rows that do say something off a short pane.
 */
void prop_pdf(const struct object *ob)
{
	/*
	 * ob->info IS the view. kof_pdf() takes a CONTEXT and reads
	 * ctx->file_header out of it, so handing it the view made it read some
	 * field of the view as a pointer and follow it - which crashed the
	 * dashboard the first time it was opened on a PDF.
	 *
	 * Nothing caught it at compile time because ob->info is void *, which
	 * converts to any object pointer silently. The other blocks here assign
	 * it directly for the same reason, and this one now matches them.
	 */
	const struct kof_pdf_info *p = ob->info;
	unsigned k;

	/* `valid` as well as non-NULL: a view that a refused parse left zeroed
	 * is a view whose ranges mean nothing, and every field below is a range
	 * this function is about to read with. */
	if (!p || !p->valid)
		return;
	for (k = 0; k < KOF_PDF_DOCINFO_COUNT; k++) {
		char val[96];

		if (!p->docinfo[k].len || !ob->buf.p)
			continue;
		/* Bounded by what the object actually holds: the range came out
		 * of the file, and this is a read. */
		if (p->docinfo[k].off >= ob->buf.n ||
		    p->docinfo[k].len > ob->buf.n - p->docinfo[k].off)
			continue;
		if (!kof_pdf_text(ob->buf.p + p->docinfo[k].off,
				  p->docinfo[k].len, p->docinfo[k].hex,
				  val, sizeof val))
			continue;
		prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
			 kof_pdf_docinfo_name(k), val);
	}
}

/*
 * The chain an object hangs from, above the object itself.
 *
 * A child's name is a path INSIDE its containers - "sample.zip//0:a.rar//1:x" -
 * so the enclosing objects are its own name's prefixes, cut at each "//". That
 * makes the walk a string operation and not a second tree: whatever the tree
 * pane shows, this reads the same names.
 *
 * NUMBERED BY DEPTH, from the file down. The file is 0, what it produced is 1,
 * and so on to the object in focus - the same direction the engine reached them
 * and the same direction the panel is read in. It counted the other way at
 * first, up from the object being looked at, and that put the highest number at
 * the top of the screen: the two blocks read as a chain and their numbers ran
 * against it.
 */
static int obj_by_name(const struct view *v, const char *name, size_t n)
{
	uint32_t i;

	for (i = 0; i < v->n_obj; i++)
		if (strlen(v->obj[i].name) == n &&
		    strncmp(v->obj[i].name, name, n) == 0)
			return (int)i;
	return -1;
}

/* The enclosing objects, outermost first. Returns how many were found. */
uint32_t obj_ancestors(const struct view *v, const struct object *ob,
			      const struct object **out, uint32_t cap)
{
	const char *name = ob->name;
	size_t cut[MAX_OBJ];
	uint32_t n = 0, k, w = 0;
	const char *p;

	/* Every "//" in the name is one container boundary. */
	for (p = strstr(name, "//"); p && n < MAX_OBJ; p = strstr(p + 2, "//"))
		cut[n++] = (size_t)(p - name);

	for (k = 0; k < n && w < cap; k++) {
		int idx = obj_by_name(v, name, cut[k]);

		if (idx >= 0)
			out[w++] = &v->obj[idx];
	}
	return w;
}

/* The page's sink: one finished line becomes one row. */
void prop_sink(void *user, const char *text)
{
	(void)user;
	prop_add("%s", text);
}

/*
 * WHAT BUILT IT, on the identity block rather than in the format block.
 *
 * "Is this .NET", "was it linked statically", "which compiler" are questions
 * about the SAMPLE, asked in the same breath as its format and architecture -
 * so they belong beside those and not three headings down among the header
 * offsets. The PE and ELF blocks below are the header, and a reader who has
 * scrolled to them is already past the point of asking what the thing is.
 *
 * The rows themselves come from kof_inspect_toolchain, so kofexamine says the
 * same things in the same words. What stays here is the palette, which is this
 * tool's and not the library's.
 */
static void prop_size_row(uint64_t n)
{
	char sz[80];

	dash_size_text(sz, sizeof sz, n);
	prop_add(A_DIM "  %-11s " A_OFF A_SIZE "%s" A_OFF, "size", sz);
}

static void prop_toolchain(const struct object *ob)
{
	static const struct kof_inspect_style style = {
		A_ID, A_LOC, A_WARN, A_OFF
	};

	if (!ob->fmt || !ob->info)
		return;
	kof_inspect_toolchain(&ob->ctx, ob->info, ob->buf, &style,
			      prop_sink, NULL);
	/*
	 * And where its metadata is, when it is managed. Beside the toolchain
	 * rows because the two answer the same reader's next two questions -
	 * what built this, and what is in it - and because a heap offset is
	 * useless without knowing the image is .NET at all.
	 */
	kof_inspect_dotnet(&ob->ctx, ob->info, &style, prop_sink, NULL);
}

void prop_object_rows(struct view *v, const struct object *ob, int full)
{
	const char *base = kof_path_sep_last(ob->name);
	const char *sub = ob->fmt ? kof_inspect_subtype_name(ob->ctx.format,
							     ob->ctx.subtype)
				  : NULL;
	/* "Raw", capitalised like every name kof_format_name returns - it sits
	 * in the same column as "ELF" and "PE" and was the only lower-case one
	 * there. */
	const char *fmt = ob->fmt ? kof_format_name(ob->ctx.format) : "Raw";
	int top = strstr(ob->name, "//") == NULL;

	/*
	 * What to call it, which differs by where it came from.
	 *
	 * A file is its basename. A CHILD has no basename worth printing: its
	 * name is a path inside a container and the last slash-separated piece
	 * of it is often the bare index - the enclosing block for a UPX payload
	 * read "name 0", which tells a reader nothing at all. The piece after
	 * the last "//" is the entry as the tree pane spells it, index and
	 * label together, so the two panes name the same object the same way.
	 */
	{
		const char *sep = NULL, *q;

		for (q = strstr(ob->name, "//"); q; q = strstr(q + 2, "//"))
			sep = q;
		base = sep ? sep : (base ? base + 1 : ob->name);
	}
	/*
	 * The name, and for a reconstructed payload the VARIABLE it came out of
	 * on the same row.
	 *
	 * Same row rather than a section of its own, which is where it started:
	 * "//Shellcode" leaves most of the line empty, and the symbol is the
	 * one thing a reader of that row wants next - which of the parent's
	 * globals this was. A whole section for one short fact cost three lines
	 * to say what fits beside the name.
	 *
	 * `from` rather than `variable`, because the row already has a label
	 * and the word only has to say how the two halves relate.
	 */
	/*
	 * WHAT IT IS - and for the file itself, WHAT IT IS CALLED.
	 *
	 * A CHILD is spelled by obj_label, the same function the tree pane
	 * uses, so the two panes cannot come to different words for one row.
	 * That was made true of the file as well, and for the file it was
	 * wrong: the row read "ELF-x64" while the two rows under it already
	 * said format ELF and arch x64, and the name was nowhere. The note
	 * that used to stand here claimed the name was "the folder row's other
	 * half" - it is not. The folder row ends at the last separator, so the
	 * basename appeared in no row at all, only inside the copy button.
	 *
	 * So the file gets its basename. In the full view that is the whole
	 * row, because format and arch have rows of their own below. On an
	 * ENCLOSING row (full == 0) it carries the type too: those rows have no
	 * format or arch line, which is what the note beside the size row
	 * below is about.
	 */
	{
		char id[64];

		if (top && ob->ctx.format == KOF_EVT_PROC && ob->info) {
			/*
			 * A PROCESS IS NAMED BY WHAT IT IS RUNNING, and then
			 * by which instance of it.
			 *
			 * "pid:185262" is the object's internal name and says
			 * nothing a reader wants: the interesting half is the
			 * program, and the number only distinguishes one run
			 * of it from another. So the binary leads and the pid
			 * qualifies it, which is the order a person says it in.
			 */
			const struct kof_proc_info *pi = ob->info;
			const char *exe = prop_proc_str(ob, pi->off_exe);

			snprintf(id, sizeof id, "%.36s [pid %lu]",
				 exe[0] ? kof_path_base(exe) : "?",
				 (unsigned long)pi->pid);
		} else if (top) {
			/* `nm` and not `base`: there is a basedir-ish `base`
			 * further out in this function's scope. */
			const char *nm = kof_path_base(ob->name);
			char what[24];

			snprintf(what, sizeof what, "%s%s%s",
				 ob->fmt ? kof_format_name(ob->ctx.format)
					 : "Raw",
				 ob->fmt ? "-" : "",
				 ob->fmt ? kof_arch_name(ob->ctx.arch) : "");
			/* The cut is written into the format rather than left
			 * to the buffer, the way obj_label writes its own: a
			 * file name has no length limit and the row has a
			 * column count, so a reader of the format string can
			 * see where it stops. */
			if (full)
				snprintf(id, sizeof id, "%.60s", nm);
			else
				snprintf(id, sizeof id, "%.36s  %.18s", nm,
					 what);
		} else {
			obj_label(ob, id, sizeof id);
		}
		if (ob->payload_of && ob->payload_sym[0])
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF
				 A_DIM "  from " A_OFF A_ID "%s" A_OFF "%s",
				 "name", id, ob->payload_sym, "");
		else
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "name", id);
	}

	/*
	 * Only the object that came off the disk has a folder.
	 *
	 * The name of a child is a path inside its container, so its directory
	 * is the container's; printing one would suggest the child has a place
	 * of its own on the filesystem. Which object that is is decided from the
	 * NAME rather than from the selection, so an enclosing block gets it
	 * right too - the top of the chain is the file, wherever the reader
	 * happens to be standing.
	 */
	if (top && v->path && v->path[0]) {
		char dir[KOF_DUMP_PATH_ROOM];
		/*
		 * FOR A PROCESS, THE FOLDER IS WHERE THE BINARY LIVES.
		 *
		 * v->path is "pid:185262", which has no separator, so this row
		 * said "./" - a directory that exists and is not the one the
		 * program was started from. The record carries the executable's
		 * full path, and that is the only filesystem location a
		 * process has.
		 */
		const char *from = v->path;
		const char *slash;

		if (ob->ctx.format == KOF_EVT_PROC && ob->info) {
			const char *exe =
				prop_proc_str(ob, ((const struct kof_proc_info *)
					      ob->info)->off_exe);

			if (exe[0])
				from = exe;
		}
		slash = kof_path_sep_last(from);

		/* Ending in a separator, always: a directory row and a name row
		 * sit one above the other in the same column, and without it the
		 * last component reads as another file name. */
		if (!slash) {
			snprintf(dir, sizeof dir, "./");
		} else {
			size_t n = (size_t)(slash - from) + 1u;

			if (n >= sizeof dir)
				n = sizeof dir - 1u;
			memcpy(dir, from, n);
			dir[n] = 0;
		}
		/*
		 * AND A WAY TO TAKE THE WHOLE PATH IN ONE GESTURE.
		 *
		 * The folder and the name are two rows, so copying the thing a
		 * person actually needs - the path to hand to another tool -
		 * meant selecting one row, copying, selecting the other,
		 * copying, and joining them by hand. The button copies
		 * v->path, which is exactly that join.
		 *
		 * Only on this row, which is only drawn for the object that
		 * came off the disk - see the note above. A child's name is a
		 * path inside its container and has no filesystem path to copy,
		 * and in a nested view the row belongs to the outermost parent,
		 * so the button follows the same rule without a second test.
		 */
		prop_add(A_DIM "  %-11s " A_OFF A_LOC "%s" A_OFF
			 "  \033[47;30m%s" A_OFF, "folder", dir,
			 PROP_CP_LABEL);
	}

	/*
	 * Under the folder and above the size, which is where a reader looks
	 * for it: the rows above say WHICH object this is by name and place,
	 * and this says which object it is in the only way that survives being
	 * renamed, moved, or copied off the machine.
	 */
	if (full && ob->sha256[0])
		prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
			 "sha256", ob->sha256);

	if (full) {
		prop_size_row(ob->buf.n);
		/* An ELF or a PE says its format and its architecture in its own format block
		 * (dash_header): said here too they would be one fact on two rows. */
		if (!dash_has_header(ob))
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s%s%s" A_OFF,
				 "format", fmt, sub ? " " : "", sub ? sub : "");
		/*
		 * THE FAMILY FOR A SCRIPT, WHERE THE ARCHITECTURE GOES FOR
		 * everything else.
		 *
		 * Every script is KGENOME_ARCH_ANY, so this row said "any" on all
		 * of them. What a reader of a script needs here is the family,
		 * because kof_module_precond declines a module whose declared
		 * subtypes all sit in another one - and with only the language
		 * on screen, a shell script that reads as a php page looks
		 * identical to one that does not, while only the second runs
		 * shell rules.
		 */
		if (dash_has_header(ob)) {
			/* in the format block */
		} else if (ob->fmt && ob->ctx.format == KOF_FMT_SCRIPT) {
			const char *fa = kof_script_fam_name(ob->ctx.subfamily);

			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "family", fa ? fa : "any");
		} else if (ob->fmt) {
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "arch", kof_arch_name(ob->ctx.arch));
		}
		prop_toolchain(ob);
	} else {
		/* Bytes and nothing else. The format and the architecture are
		 * on the identity row above, and saying them twice on two
		 * adjacent rows is how a reader learns to skip one of them. */
		prop_size_row(ob->buf.n);
	}

	/*
	 * The module beside this object, and WHICH RELATION it names.
	 *
	 * On a child it is the module that PRODUCED it - "unpacked by". On the
	 * file itself it is the module that OPENED it - "opened by" - and the
	 * two are not the same statement. It read "unpacked by" for both, which
	 * was merely odd while one block was on screen and is wrong now that the
	 * chain is stacked: the top of the chain came off the disk, and a panel
	 * saying it was unpacked by something invents a layer above the file.
	 */
	/*
	 * AND NOT TWICE FOR ONE EVENT.
	 *
	 * "MPRESS.PE opened this file" and "MPRESS.PE unpacked that child" are
	 * the two ends of ONE edge, and the chain panel stacks them one line
	 * apart. Read together they say MPRESS twice and a reader counts two
	 * layers of it - which is what happened on 111.exe, where there is one
	 * MPRESS layer and one VMProtect layer under it:
	 *
	 *     111.exe      opened by   MPRESS.PE      <- the same edge
	 *     //0          unpacked by MPRESS.PE      <- said again
	 *     //0          unpacked by VMProtect.PE
	 *
	 * So the file's own line is dropped when a child below it already
	 * names that module. It is kept when none does - a module that opens
	 * an object and produces nothing, like Hollow.PE, has no other line to
	 * appear on, and that is the case the row exists for.
	 */
	if (ob->packer[0])
		prop_add(A_DIM "  %-11s " A_OFF "%s%s" A_OFF,
			 top ? "opened by" : "unpacked by",
			 (ob->heur.from_packer ||
			  (ob->heur.heur_flags &
			   KOF_HEUR_FL(KOF_HEUR_F_PACKED))) ? A_BAD : A_WARN,
			 ob->packer);
}
