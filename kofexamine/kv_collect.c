#define _GNU_SOURCE
#include "kv.h"
#include "kofscfind.h"


/*
 * A RUNNING PROCESS AS A THING TO LOOK AT.
 *
 * WHY THIS IS A SNAPSHOT AND NOT AN ATTACH. Everything above and below assumes
 * the bytes are stable and re-readable: the hex pane re-reads as it scrolls,
 * the disassembler re-reads, a dump writes them out, "scan this object again"
 * scans them again. A live process changes underneath all of that - two reads
 * of one address differ, and the pane would show a frame that never existed in
 * the process while the dump beside it showed a third thing. So each region is
 * read ONCE, here, and everything afterwards is an ordinary object.
 *
 * Nothing stops the process while this runs. process_vm_readv does not need
 * the target stopped, and ptrace-attach - which would - changes the thing
 * being observed. A region read while it is being written is torn, and that is
 * the honest cost of not stopping it.
 *
 * THE ROOT IS THE PROCESS RECORD, not one of its regions. kofmod/proc.h is
 * already a scannable object with META, CMDLINE and FD regions, so the
 * dashboard gets the pid, the parent, the user, the command line and the
 * standard descriptors by the same path every other format's panel is filled -
 * no second way of showing facts.
 *
 * THE REGIONS ARE CHILDREN, named "<root>//<address>" so kobj_depth reads
 * them as one level down and every existing row, jump and dump works on them
 * unchanged. on_object already decides what to KEEP - small on the heap, large
 * spilled to a temporary file and mapped, nothing past OBJ_BUDGET - so the
 * memory bound a process needs is the bound the viewer already has.
 */

/*
 * Have these bytes already been listed under this process? 1 the first time a
 * path is offered, 0 afterwards. A fixed table, because a process with more
 * mapped files than this has more rows than anybody reads.
 */
/*
 * WHAT A PROCESS VIEW MAY READ OFF THE DISK.
 *
 * 64MB for one mapped file, matching the per-region ceiling so the two halves
 * of an address space are cut at the same size, and 512MB for the whole view.
 * Guards against a pathological process rather than budgets anybody measured -
 * the same honesty the collector's own ceilings are written with.
 */
/* Defined with the input loop; the status line ages a message with it and the
 * process collection below bounds itself with it. */

/*
 * AND A CLOCK, WHICH THE BYTE BUDGETS ARE NOT A SUBSTITUTE FOR.
 *
 * The budgets bound how MUCH is read; they say nothing about how long reading
 * it takes. Measured here: a 350 MB python with 162 mappings takes 6.3 seconds
 * to open, all of it before the first frame is drawn, because every anonymous
 * region is copied out of the other process and run through the engine. A
 * browser tab with thousands of mappings is minutes of that, and a viewer that
 * draws nothing for minutes is a viewer that has hung - there is no way for the
 * reader to tell the difference, and no way to stop it.
 *
 * So the collection stops taking new items after this, and says how many it
 * left. Three seconds is long enough that an ordinary process finishes whole -
 * the sleep and the python above both do - and short enough that the worst case
 * is a page that opens and tells you it is incomplete rather than one that
 * never opens at all.
 *
 * STOPPED AND COUNTED, not truncated: what was collected was collected in full,
 * and the count is the honest statement that there was more.
 */
#define PROC_COLLECT_MS  3000u

#define PROC_FILE_MAX    (64ull * 1024ull * 1024ull)
#define PROC_FILE_BUDGET (512ull * 1024ull * 1024ull)


/*
 * REGIONS THE ENGINE DECLARED, answered the way a parser would answer them.
 *
 * Same shape as every resolver so that everything already written against
 * ctx->resolve_scan - the region rows, the hex highlighting, the range submenu -
 * works on a normalised view without knowing there is anything special about
 * it. The table is on the object and the object is reached through ctx->priv,
 * which is the field a host uses for exactly this and which nothing else in the
 * viewer sets.
 */
/*
 * THE REGION KINDS THIS OBJECT HAS, from whichever side knows.
 *
 * Normally the parser: a format declares which region bits it can answer and
 * everything here walks that list. An object whose regions were DECLARED has no
 * parser - see where the objects are identified - so the list has to come from
 * the table itself, distinct bits in the order they were declared.
 *
 * Written as one call because there were two walks over fmt->regions and a
 * third that asked whether a bit was in it, and a view that had regions but no
 * parser drew nothing in all three: the panel came back empty for an object the
 * engine had just described in full.
 */
uint32_t obj_region_bits(const struct object *o, uint32_t *out,
				uint32_t cap)
{
	uint32_t i, n = 0;

	if (!o || !out || !cap)
		return 0;
	if (o->n_rgn) {
		for (i = 0; i < o->n_rgn && n < cap; i++) {
			uint32_t k;

			for (k = 0; k < n; k++)
				if (out[k] == o->rgn[i].mask)
					break;
			if (k == n)
				out[n++] = o->rgn[i].mask;
		}
		return n;
	}
	if (!o->fmt || !o->fmt->regions)
		return 0;
	for (i = 0; i < o->fmt->n_regions && n < cap; i++)
		out[n++] = o->fmt->regions[i];
	return n;
}

static uint32_t declared_regions(const struct kof_obj_ctx *ctx,
				 uint32_t scan_mask, struct kof_range *out,
				 uint32_t max_out)
{
	/*
	 * THE OBJECT IS FOUND FROM THE CONTEXT'S OWN ADDRESS, not from
	 * ctx->priv.
	 *
	 * priv looks like the field for this and is not: kof_scan_of casts it
	 * to a struct kof_scanner, so anything else stored there is a wrong
	 * pointer waiting for the one caller that asks - and
	 * kof_scan_resolve_range is such a caller, on the path it takes when a
	 * region overflows the extent buffer.
	 *
	 * The context is a MEMBER of the object, so its address gives the
	 * object back exactly, with nothing stored and nothing to keep in step.
	 */
	const struct object *o = ctx
		? (const struct object *)((const char *)ctx
					  - offsetof(struct object, ctx))
		: NULL;

	if (!o)
		return 0;
	/* The filtering is shared with the examiner - see
	 * kof_declared_regions. This function's own job is finding the table. */
	return kof_declared_regions(o->rgn, o->n_rgn, scan_mask, out, max_out);
}

struct object *cur_obj(struct view *v)
{
	return &v->obj[v->node[v->sel_node].obj];
}

/* Names a region mask - defined with the range menu it belongs to, declared
 * here because locating a string needs it to say where the string turned up. */

/* ---- collecting the objects ------------------------------------------------ */

/*
 * THE ENGINE'S REPORT OF WHAT EACH DIAGNOSE MADE OF THIS OBJECT, copied: it is
 * lent for the callback and the table under Strings is drawn long after. The
 * names inside belong to the database, which outlives every object here.
 *
 * `heur` is a shallow copy of the whole result, so its pointer is cleared - a
 * borrowed pointer left in a record that is kept is a use after the callback.
 */
static void diag_keep(struct object *o, const struct kof_result *res)
{
	free(o->diag);
	o->diag = NULL;
	o->n_diag = 0;
	o->heur.diag = NULL;
	o->heur.n_diag = 0;
	if (!res->diag || !res->n_diag)
		return;
	o->diag = malloc(res->n_diag * sizeof *o->diag);
	if (!o->diag)
		return;
	memcpy(o->diag, res->diag, res->n_diag * sizeof *o->diag);
	o->n_diag = res->n_diag;
}

int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct view *v = user;
	struct object *o;

	if (v->n_obj >= MAX_OBJ || !len)
		return 0;
	/*
	 * A scan of one object's bytes reports that object first, and it is
	 * already in the tree - it is the row the reader picked. Dropped here
	 * rather than filtered by name, because two objects can share a name
	 * and only this one is the echo.
	 */
	if (v->skip_root) {
		v->skip_root = 0;
		return 0;
	}

	/*
	 * A RERUN'S DUPLICATES, dropped.
	 *
	 * emu_here rescans the SELECTED OBJECT'S OWN BYTES to put the
	 * interpreter in front of them, and a scan runs every producer rather
	 * than only the one that was asked for - so a child another module had
	 * already carved out of those bytes on the first pass is reported again
	 * and appended beside itself. Measured: an ELF carrying a "base64 -d"
	 * command showed two identical "//0:SCRIPT base64" rows after one press
	 * of Unpack with emulator.
	 *
	 * NOT FIXED BY ASKING THE ENGINE FOR EMULATOR OUTPUT ONLY. It already
	 * is asked that - opt.emu_use is KOF_EMU_ONLY - and that governs which
	 * UNPACKER runs, not which producers do; and a child the interpreter
	 * genuinely recovers may be one another module could also have found,
	 * so producer is the wrong thing to filter on anyway. What makes a row
	 * a duplicate is that the same object is already in the list: same
	 * engine name, same length, same bytes.
	 */
	if (v->dedup_from) {
		uint32_t k;

		for (k = 0; k < v->dedup_from && k < v->n_obj; k++) {
			const struct object *e = &v->obj[k];

			if (e->buf.n != len || strcmp(e->name, name) != 0)
				continue;
			if (!e->buf.p ||
			    memcmp(e->buf.p, bytes, (size_t)len) != 0)
				continue;
			return 0;
		}
	}

	/*
	 * INTO A ROW THAT ALREADY EXISTS - see view.into_obj. Only the verdict
	 * is taken: the name, the bytes and the parse are the row's own and
	 * were settled before the scan ran.
	 */
	if (v->into_obj >= 0) {
		o = &v->obj[v->into_obj];
		v->into_obj = -1;
		o->heur = *res;
		diag_keep(o, res);
		o->broken = res->broken;
		o->emu_done |= res->emu_unpacked;
		return 0;
	}

	o = &v->obj[v->n_obj];
	/* The slot may have held an object before - see the reset loop for what
	 * one owns. */
	free(o->carve);
	free(o->diag);
	kgenome_funcs_free(&o->funcs);
	kof_codenotes_free(&o->notes);
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name);
	o->broken = res->broken;
	/* The engine runs the interpreter by itself when an unpacker declares
	 * its child needs it, so "already done" is not only what this panel
	 * asked for. See kof_result.emu_unpacked. */
	o->emu_done |= res->emu_unpacked;
	/*
	 * The heuristic, as the ENGINE computed it.
	 *
	 * Copied rather than reconstructed. This panel used to build its own
	 * facts out of what it could see - the tree depth, the module name it
	 * had been handed - and that was a second implementation of the
	 * engine's, which drifted the moment the engine learned to tell a
	 * packer from a container.
	 */
	o->heur = *res;
	diag_keep(o, res);
	/*
	 * WHICH MODULE MADE THIS, FROM THE ENGINE - see kof_result.produced_by.
	 *
	 * `v->pending` is this panel's own inference from the prefix of the
	 * last debug note anybody emitted, and it is wrong whenever the
	 * producer says nothing or another module speaks after it. On 111.exe,
	 * which is VMProtect under MPRESS, it labelled BOTH children
	 * VMProtect - the MPRESS image and the decrypted one - so the two rows
	 * read identically for objects whose bytes differ by 1.6 MB. The
	 * engine records the producer where the child is pushed; that is used
	 * when it has one, and the guess only when it does not.
	 */
	/*
	 * ONE FIELD, FROM THE ENGINE, AND NOTHING WORKED OUT HERE.
	 *
	 * kof_result.packer_build is the whole answer - format, name and build
	 * where the module could tell one: "PE:MPRESS 2.12-2.19 LZMA". It was
	 * shown beside opened_by, which is the same fact in fewer words, and
	 * the row read "MPRESS.PE PE:MPRESS 2.12-2.19 LZMA".
	 *
	 * The guess this replaces was worse than redundant. It remembered the
	 * last debug note anybody emitted and pinned it on whichever object
	 * arrived next, so a version reported by one module was shown against
	 * another module's object - and the engine has known which module
	 * opened what since opened_by existed.
	 */
	if (res->packer_build && res->packer_build[0])
		snprintf(o->packer, sizeof o->packer, "%s", res->packer_build);
	/*
	 * AND WHERE THE INFECTION IS, straight off the result - see
	 * struct kof_infected. It has a channel of its own, so nothing has to
	 * be remembered between callbacks and pinned on whichever object
	 * arrives next.
	 */
	if (res && res->n_infected) {
		uint32_t q;

		o->n_infected = res->n_infected < KOF_MAX_INFECTED
			      ? res->n_infected : KOF_MAX_INFECTED;
		for (q = 0; q < o->n_infected; q++)
			o->infected[q] = res->infected[q];
	}
	o->depth = kobj_depth(name);
	o->entry_of = res ? res->entry_of : KOF_ENTRY_NONE;
	o->entry_kind = res ? res->entry_kind : 0u;
	/*
	 * And the regions, when the engine declared them - see struct object.
	 * Copied here rather than pointed at: `res` is the engine's own record
	 * for one object and does not outlive this call.
	 */
	/*
	 * THE SYMBOLS THE ENGINE HANDED OVER, copied for the same reason the
	 * regions below are: `res` is the engine's record for one object and
	 * does not outlive this call. Only a rendering carries any.
	 */
	o->sym_declared = 0;
	if (res && res->syms && res->n_syms) {
		free(o->sym);
		o->sym = malloc(res->n_syms);
		if (o->sym) {
			memcpy(o->sym, res->syms, res->n_syms);
			o->sym_n = res->n_syms;
			o->sym_declared = 1;
		} else {
			o->sym_n = 0;
		}
	}
	free(o->fixed);
	o->fixed = NULL;
	o->n_fixed = 0;
	if (res && res->fixed && res->n_fixed) {
		o->fixed = malloc(res->n_fixed * sizeof *o->fixed);
		if (o->fixed) {
			memcpy(o->fixed, res->fixed, res->n_fixed * sizeof *o->fixed);
			o->n_fixed = res->n_fixed;
		}
	}
	o->n_rgn = 0;
	if (res && res->n_region) {
		uint32_t g;

		for (g = 0; g < res->n_region && g < KOF_MAX_REGIONS; g++)
			o->rgn[g] = res->region[g];
		o->n_rgn = g;
		o->rgn_fmt = res->region_fmt;
	}
	/*
	 * AND THE LANGUAGE THE ENGINE SCANNED IT AS - see
	 * kof_result.lang_known.
	 *
	 * Outside the region block on purpose: a view can be declared a
	 * language without carrying a region table, and the panel must not
	 * contradict the verdict either way. Applied to the context after
	 * identify, below, for the same reason the region table is.
	 */
	o->lang_known = 0;
	if (res && res->lang_known) {
		o->lang_known = 1;
		o->subtype = res->subtype;
		o->subfamily = res->subfamily;
	}

	/*
	 * The top level is already mapped; anything else exists only inside
	 * this call and has to be kept if it is to be looked at.
	 *
	 * Kept three ways, by size. Small children go on the heap, which is
	 * every child in practice. A large one is spilled to a temporary file
	 * and mapped, so the pages it is not being looked at cost nothing -
	 * a hex pane shows twenty rows however big the object is, and holding
	 * a decompressed installer resident to show twenty rows of it is how a
	 * viewer gets killed by an archive somebody chose.
	 *
	 * Past a total budget nothing more is kept at all. Those objects were
	 * still scanned - that happened before this is called - so nothing is
	 * missed; they simply cannot be browsed, and the tree says so.
	 */
	if (o->depth == 0 && v->map && len == v->map_len) {
		o->buf = kof_buf_make(v->map, len);
	} else if (v->obj_held + len > OBJ_BUDGET) {
		o->buf = kof_buf_make(NULL, 0);
		o->too_big = 1;
	} else if (len >= OBJ_SPILL) {
		int fd = kof_src_tmpfile();

		if (fd < 0)
			return 0;
		if (!kof_write_all(fd, bytes, len)) {
			close(fd);
			return 0;
		}
		o->mapped = kof_map_file_ro(fd, len);
		close(fd);
		if (!o->mapped) {
			o->buf = kof_buf_make(NULL, 0);
			o->too_big = 1;
		} else {
			o->mapped_len = len;
			o->buf = kof_buf_make(o->mapped, len);
			v->obj_held += len;
		}
	} else {
		o->own = malloc((size_t)len);
		if (!o->own)
			return 0;
		memcpy(o->own, bytes, (size_t)len);
		o->buf = kof_buf_make(o->own, len);
		v->obj_held += len;
	}

	v->n_obj++;
	return 0;
}

static int proc_seen_path(struct view *v, const char *path)
{
	uint32_t i;

	for (i = 0; i < v->n_seen; i++)
		if (!strcmp(v->seen_path[i], path))
			return 0;
	if (v->n_seen >= PROC_SEEN_MAX)
		return 0;
	snprintf(v->seen_path[v->n_seen], sizeof v->seen_path[0], "%s", path);
	v->n_seen++;
	return 1;
}

void proc_collect(struct view *v, kof_engine *eng, uint32_t pid)
{
	struct kof_scan_option opt;
	struct kof_walk_option wo;
	struct kof_walk_api   *w;
	struct kof_proc_build  b;
	struct kof_walk_item   it;
	kof_scanner *sc;
	uint32_t     pids[1];
	int          err = 0;
	uint64_t     t0;

	memset(&opt, 0, sizeof opt);
	opt.heur_level = v->heur_off ? 0u : KOF_HEUR_LEVEL_MAX;
	opt.heur_off = v->heur_off ? 1u : 0u;
	opt.emu_use = KOF_EMU_NEVER;

	sc = kscan_new(eng);
	if (!sc)
		return;
	v->scan_sc = sc;

	memset(&wo, 0, sizeof wo);
	pids[0] = pid;
	wo.pids = pids;
	wo.n_pids = 1;
	/* A reader, not a scan - see enum kof_walk_intent. */
	wo.intent = KOF_WALK_MAP;
	w = kof_walk_open(&wo, &err);
	if (!w) {
		v->scan_sc = NULL;
		kscan_free(sc);
		return;
	}
	t0 = now_ms();
	if (w->next_proc(w->self, &b)) {
		/*
		 * The record first, as the object the file would have been.
		 * v->map already points at it - see proc_open - so on_object
		 * takes its depth-0 branch and does not copy it again.
		 */
		struct kof_scan_option po = opt;

		po.as_format = KOF_EVT_PROC;
		(void)kscan_bytes(sc, v->map, v->map_len, v->path, &po,
				     on_object, v);

		while (w->next_item(w->self, &it)) {
			char nm[KOF_DUMP_PATH_ROOM];

			/*
			 * Out of time. Every remaining item is counted so the
			 * panel can say the list is short, and the ones
			 * already taken are whole.
			 */
			if (now_ms() - t0 > PROC_COLLECT_MS) {
				v->proc_skipped++;
				continue;
			}

			/*
			 * THE FILES BEHIND THE MAPPINGS ARE OBJECTS TOO - the
			 * program and every library it loaded, each one row.
			 *
			 * DEDUPED BY PATH, and that is not tidiness. Measured
			 * on this machine: 5795 file-backed mappings behind
			 * 335 distinct files, with libc mapped a hundred
			 * times. One row per mapping would be a tree nobody
			 * can read, listing the same library over and over.
			 *
			 * The FILE is opened rather than the mapped copy being
			 * read back. On Linux they are the same bytes - the
			 * EXEC pages measured 0% different from the file - and
			 * the file is cheaper, cacheable, and is what a
			 * signature was written against.
			 */
			if (it.kind == KOF_WALK_FILE && it.path && it.path[0]) {
				if (!proc_seen_path(v, it.path))
					continue;
				snprintf(nm, sizeof nm, "%s//%.80s", v->path,
					 base_name(it.path));
				{
					struct stat fst;
					void *fm;
					int   ffd = open(it.path, O_RDONLY);

					if (ffd < 0)
						continue;
					if (fstat(ffd, &fst) != 0 ||
					    !S_ISREG(fst.st_mode) ||
					    fst.st_size <= 0) {
						close(ffd);
						continue;
					}
					/*
					 * AND A CEILING, WHICH THIS PATH HAD
					 * NONE OF.
					 *
					 * Every distinct mapped file was
					 * mapped and run through the WHOLE
					 * engine - every module, every
					 * unpacker - on nothing but "is it a
					 * regular file with bytes in it". A
					 * process that maps a database, a
					 * model file or a large archive
					 * therefore scanned it in full before
					 * the first frame was drawn, which is
					 * a viewer that does not open.
					 *
					 * The memory regions grew a bound when
					 * MAP took EXEC_ONLY away from them;
					 * this one never had one, because a
					 * mapped file looked like a small
					 * thing until somebody mapped
					 * something that was not.
					 *
					 * SKIPPED AND COUNTED, not truncated:
					 * half a library is not a library,
					 * and a partial scan reported as a
					 * scan is the answer this tree refuses
					 * everywhere else.
					 */
					if ((uint64_t)fst.st_size >
					    PROC_FILE_MAX ||
					    v->proc_skipped_bytes +
					    (uint64_t)fst.st_size >
					    PROC_FILE_BUDGET) {
						close(ffd);
						v->proc_skipped++;
						continue;
					}
					v->proc_skipped_bytes +=
						(uint64_t)fst.st_size;
					fm = kof_map_file_ro(ffd,
						(uint64_t)fst.st_size);
					close(ffd);
					if (!fm)
						continue;
					/* on_object keeps its own copy - heap
					 * or a spill file - so the mapping is
					 * only needed for the call. */
					{
					uint32_t first = v->n_obj;

					(void)kscan_bytes(sc, fm,
						(uint64_t)fst.st_size, nm,
						&opt, on_object, v);
					kof_unmap_file(fm,
						(uint64_t)fst.st_size);
					/*
					 * WHICH PATH THIS ROW CAME FROM,
					 * plus one so that zero still means
					 * "not a mapped file".
					 *
					 * The object's own name carries only
					 * the basename - it is a tree row and
					 * a full path would not fit one - so
					 * the panel would have had to guess
					 * the directory back. seen_path
					 * already holds the whole thing, in
					 * the order the process mapped them.
					 */
					/*
					 * ON THE OBJECT THAT IS THE FILE, and
					 * that is the FIRST one the scan added
					 * - not the last.
					 *
					 * A scan of one file can produce
					 * several objects: an ELF with
					 * something appended to it declares
					 * the carried object as a child, and
					 * an archive declares its members. The
					 * last of those is not the mapping.
					 * Stamping it gave the CHILD the
					 * file's path and left the file itself
					 * without one, so the panel showed the
					 * path twice over - once against the
					 * file's own row under its bare name,
					 * once against a child that was never
					 * mapped at all.
					 */
					if (v->n_obj > first)
						v->obj[first].proc_path =
							v->n_seen;
					}
				}
				if (v->n_obj >= MAX_OBJ)
					break;
				continue;
			}
			if (it.kind != KOF_WALK_BYTES || !it.p || !it.len)
				continue;
			/*
			 * THE WORD, AND ONLY THE WORD - see
			 * kof_walk_item.label. "00007fce21b7f000" is where it
			 * is, not what it is, and a tree of addresses reads as
			 * a list of numbers nobody can act on.
			 *
			 * NO ADDRESS APPENDED EITHER. Two heaps then share a
			 * row name, which is the objection to dropping it and
			 * is worth less than it looks: the rows carry their
			 * sizes, they are listed in the order the address
			 * space has them, and the address itself is one key
			 * away on the object. A name that is half a word and
			 * half a hex number is neither.
			 */
			if (it.label && it.label[0])
				snprintf(nm, sizeof nm, "%s//%s", v->path,
					 it.label);
			else
				snprintf(nm, sizeof nm, "%s//%016llx",
					 v->path,
					 (unsigned long long)it.addr);
			/*
			 * The walk's declaration goes with the bytes: on
			 * Windows a region that is a loader-mapped PE says so,
			 * and resolving its regions from the file layout would
			 * point every one of them at another section's bytes.
			 * Zero on Linux, where nothing needs declaring.
			 */
			{
				struct kof_scan_option ro = opt;

				if (it.as_format) {
					ro.as_format   = it.as_format;
					ro.as_view     = it.as_view;
					ro.as_view_len = it.as_view_len;
				}
				(void)kscan_bytes(sc, it.p, it.len, nm,
						     &ro, on_object, v);
			}
			if (v->n_obj >= MAX_OBJ)
				break;
		}
	}
	w->close(w->self);
	v->scan_sc = NULL;
	kscan_free(sc);
}

void objects_collect(struct view *v, kof_engine *eng)
{
	struct kof_scan_option opt;
	kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	/* The table under Strings - see draw_decl_diag. */
	opt.report_diag = 1;
	/*
	 * LEVEL 2, and this is only expressible because the level and the
	 * emulator became separate fields.
	 *
	 * A viewer wants every heuristic that has anything to say about the
	 * object in front of the reader - that is what the panel is for - and a
	 * rule gated to level 2 is gated on COST, not on confidence. It does
	 * NOT want the interpreter, which is the other half of what --heur 2
	 * means on the command line. Before these were two fields, asking for
	 * one without the other was not possible.
	 */
	opt.heur_level = v->heur_off ? 0u : KOF_HEUR_LEVEL_MAX;
	/*
	 * AND WHETHER THE CHILDREN ARE SEPARATED AT ALL - see view.heur_off.
	 *
	 * Zero at rest, so the default is what it has always been: everything
	 * the parse declared is opened before the tree is drawn.
	 */
	opt.heur_off = v->heur_off ? 1u : 0u;
	/*
	 * NEVER rather than the zeroed AUTO, and ONLY when asked for.
	 *
	 * A scanner wants AUTO: interpret whatever no module could open, since
	 * a missed payload is a missed detection. A viewer wants neither half
	 * of that silently. Opening a file must show what the unpackers make of
	 * it, so that what is on screen is what a scan would have matched
	 * against; and when a reader asks for the interpreter they want its
	 * answer for THIS object, not only for the objects the modules gave up
	 * on. So the two settings here are the two ends, and the middle one -
	 * useful to a scan - would be the one setting whose output nobody could
	 * attribute to either.
	 */
	opt.emu_use = v->emu_mode ? KOF_EMU_ONLY : KOF_EMU_NEVER;
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
	/* -1 rather than the zeroed view's 0, because 0 is a version a container
	 * can carry. Set here so the first module to speak cannot inherit it. */
	sc = kscan_new(eng);
	if (!sc)
		return;
	v->scan_sc = sc;
	kscan_path(sc, v->path, &opt, on_object, v);
	kscan_free(sc);
}

/* Parse each object and ask the database about it. Done after the scan rather
 * than inside it: the callback runs while the engine holds the object, and
 * driving the matcher over the same engine from in there is a re-entry nobody
 * has designed for. */
/* ---- the symbol table, as records ------------------------------------------
 *
 * The KSYM block kofsym.h defines, read back for the screen. The viewer does
 * NOT re-walk the symbol table to draw it: the engine builds the block, this
 * file only lays the fields out, so the table a reader sees and the bytes a
 * signature matches are the same bytes. A second walk here would be a second
 * chance to disagree with the first.
 */

/*
 * WHICH FIELD A BYTE OF THE BLOCK BELONGS TO, as a colour.
 *
 * This replaces byte_colour for the two symbol rows, and the reason is that
 * byte_colour answers the wrong question here. It asks "what KIND of byte is
 * this" - the only question worth asking of an extent of a file, where nothing
 * marks where one value ends and the next begins. In a KSYM block every field
 * is at a known offset, so that question is already answered, and asking it
 * anyway produced a screen of magenta: A_B_CTRL fires on everything under 0x20,
 * which is every type, bind, vis, flags and shndx byte in the block, plus every
 * small value and size. The palette was spending itself saying "control byte"
 * about two thirds of the block and saying nothing about the structure.
 *
 * The bytes are still BYTES - nothing here decodes them, which is the whole
 * point of these two rows - but the colour now says which field each one is in,
 * so a record's boundaries and its fields can be read off the hex directly.
 * A record is 32 bytes and the pane draws 8 or 16 to a row, so records always
 * start on a row boundary and the bands line up down the pane. The pane of a
 * symbol row shows the POOL ENTRIES (what the engine matches - the attribute
 * bytes, the whole name, its NUL), and these are coloured the same way: the four
 * attribute bytes as the record's own, then the name.
 *
 * The zeros stay visible rather than being dimmed away: a zero in the value
 * field is a fact worth seeing, not padding to be hidden.
 */
const char *sym_byte_colour(const uint8_t *b, uint32_t n, uint64_t off)
{
	uint64_t pool = kof_sym_pool_at(b, n);
	uint32_t lo = 0, hi = kof_sym_count(b, n);

	if (off < KOF_SYM_HDRLEN)
		return A_S_HDR;
	if (off < pool) {
		/* The record table: a fixed stride, every field at a constant offset. */
		uint64_t r = (off - KOF_SYM_HDRLEN) % KOF_SYM_RECLEN;

		if (r == KOF_SYM_R_TYPE)
			return A_S_TYPE;
		if (r == KOF_SYM_R_BIND)
			return A_S_BIND;
		if (r == KOF_SYM_R_VIS)
			return A_S_VIS;
		if (r == KOF_SYM_R_FLAGS)
			return A_S_FLAG;
		/*
		 * EACH FIELD AS ITS OWN RANGE, start and length, not "below the next
		 * one's offset".
		 *
		 * It was a chain of `r < KOF_SYM_R_VALUE`, `r < KOF_SYM_R_SIZE`,
		 * `r < KOF_SYM_R_NAME` - which reads as if it follows the macros but
		 * silently assumes they are in ascending order. Reordering the record
		 * so the name sits next to the attributes made every one of those tests
		 * false about a different field, and nothing would have failed to
		 * compile: the pane would simply have coloured the wrong bytes. Written
		 * this way the tests do not care what order the fields are in.
		 */
		if (r >= KOF_SYM_R_NAMEOFF && r < KOF_SYM_R_NAMEOFF + 4u)
			return A_S_NAME;
		if (r >= KOF_SYM_R_NAMELEN && r < KOF_SYM_R_NAMELEN + 2u)
			return A_S_NAME;
		if (r >= KOF_SYM_R_SHNDX && r < KOF_SYM_R_SHNDX + 2u)
			return A_S_SHN;
		if (r >= KOF_SYM_R_SIZE && r < KOF_SYM_R_SIZE + 8u)
			return A_S_SIZE;
		if (r >= KOF_SYM_R_VALUE && r < KOF_SYM_R_VALUE + 8u)
			return A_S_VAL;
		/* The cut byte and the reserved ones, which belong to no field. Dim,
		 * like the record number, because that is what they are: structure,
		 * not data. */
		return A_S_IDX;
	}
	/*
	 * THE POOL: each entry is the four attribute bytes, the name and its NUL
	 * (KOF_SYM_KEYLEN), in record order, so the entry holding `off` is the
	 * last one that starts at or before it.
	 */
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		uint64_t at = 0, len = 0;

		if (!kof_sym_run(b, n, mid, &at, &len) || at > off)
			hi = mid;
		else
			lo = mid + 1u;
	}
	if (lo) {
		uint64_t at = 0, len = 0;

		if (kof_sym_run(b, n, lo - 1u, &at, &len) && off < at + len) {
			uint64_t k = off - at;

			if (k == 0)
				return A_S_TYPE;
			if (k == 1)
				return A_S_BIND;
			if (k == 2)
				return A_S_VIS;
			if (k == 3)
				return A_S_FLAG;
			return k + 1u == len ? A_S_IDX : A_S_NAME;
		}
	}
	return A_S_IDX;
}

/* Is the row the cursor is on a symbol row rather than a region. */
int sym_view(const struct view *v)
{
	return v->sel_node < v->n_node && v->node[v->sel_node].sym != 0;
}

/*
 * The block the selected row names, and its length.
 *
 * This is what makes the two rows show BYTES. A symbol row is not an extent of
 * the file, so the pane cannot read the object's buffer for it - but the block
 * is a run of bytes like any other, so once the pane is pointed at it every
 * column it draws is the column it always drew. The alternative was a second
 * pane that happened to look like a hex dump, and two hex panes drift.
 */
const uint8_t *sym_block(const struct view *v, uint64_t *n)
{
	const struct object *o = &v->obj[v->node[v->sel_node].obj];

	if (n)
		*n = o->sym_n;
	return o->sym;
}

/*
 * ONE HALF OF THE BLOCK, described the way the engine describes it.
 *
 * A thin wrapper and deliberately nothing more: the membership test, the run
 * coalescing and the order are all kof_sym_extents', and this only adds up what
 * it returned so a row can show a size. Anything else computed here would be
 * the second opinion this file just stopped having.
 *
 * Returns how many RECORDS the half holds; *bytes gets how many bytes.
 */
uint32_t sym_half(const struct object *o, uint32_t mask,
			 struct kof_range *ext, uint32_t cap, uint64_t *bytes)
{
	uint32_t n, i, recs = 0;
	uint64_t t = 0;

	n = kof_sym_extents(o->sym, o->sym_n, mask, ext, cap);
	for (i = 0; i < n; i++) {
		t += ext[i].len;
		recs += kof_sym_extent_recs(o->sym, o->sym_n, &ext[i], NULL);
	}
	if (bytes)
		*bytes = t;
	return recs;
}

/* The mask for a row's half. SYMN_* is the viewer's own tag for the two rows;
 * the scan targets are the engine's names for the same two things. */
uint32_t sym_row_mask(uint8_t which)
{
	return which == SYMN_IMP ? KOF_SCAN_SYM_IMP : KOF_SCAN_SYM_EXP;
}

/* And back: which row shows the half a scan target names. Zero for a mask that
 * names none, which is what "the object's own bytes" reads as. */
uint8_t sym_which_of(uint32_t mask)
{
	if (mask & KOF_SCAN_SYM_IMP)
		return SYMN_IMP;
	if (mask & KOF_SCAN_SYM_EXP)
		return SYMN_EXP;
	return 0;
}

/*
 * The block-record indices of one half, ASCENDING, for a table to scroll.
 *
 * Derived from the engine's extents rather than by testing the flag byte again:
 * an extent covers consecutive records, the first of which is the one whose pool
 * entry starts at its offset (kof_sym_extent_recs), so the membership question is
 * already answered. The extents come back
 * last-run-first, so they are walked in reverse to read forwards.
 */
uint32_t sym_half_recs(const struct object *o, uint32_t mask,
			      struct kof_range *ext, uint32_t cap,
			      uint32_t *idx, uint32_t idx_cap)
{
	uint32_t n = kof_sym_extents(o->sym, o->sym_n, mask, ext, cap);
	uint32_t k = 0, e;

	for (e = n; e-- > 0; ) {
		uint32_t first = 0;
		uint32_t cnt = kof_sym_extent_recs(o->sym, o->sym_n, &ext[e], &first), c;

		for (c = 0; c < cnt && k < idx_cap; c++)
			idx[k++] = first + c;
	}
	return k;
}

/*
 * The object's symbol block, built once.
 *
 * One call, because which builder a format gets is kof_syms_build's decision
 * and the scanner makes it the same way - see sym_any.c. This file used to
 * choose between kof_elf_syms and kof_pe_syms itself and then split the result
 * in two; both of those were copies of something the engine already does.
 *
 * A block with no records is dropped rather than kept as a header alone: every
 * reader would have to test the count anyway, and NULL says it once. That is
 * also what a stripped file gives, which is the right answer for it.
 */
static void sym_build(struct object *o)
{
	/* The engine already said what this object's symbols are, because the
	 * object cannot say it itself - see kof_result.syms. */
	if (o->sym_declared)
		return;
	free(o->sym);
	o->sym = NULL;
	o->sym_n = 0;
	o->sym = malloc(KOF_SYM_MAX_BYTES);
	if (!o->sym)
		return;
	o->sym_n = kof_syms_build(o->ctx.format, o->buf.p, o->buf.n, o->info,
				  o->sym, KOF_SYM_MAX_BYTES);
	if (!kof_sym_count(o->sym, o->sym_n)) {
		free(o->sym);
		o->sym = NULL;
		o->sym_n = 0;
	}
}

const char *sc_kind(const uint8_t *b, uint32_t n)
{
	if (n >= 6 && b[0] == 0xfc && b[1] == 0x48 && b[2] == 0x83 &&
	    b[3] == 0xe4 && b[4] == 0xf0 && b[5] == 0xe8)
		return "msf x64 block_api (Windows, raw)";
	if (n >= 9 && b[0] == 0xfc && b[1] == 0xe8 && b[2] == 0x82 &&
	    b[3] == 0x00 && b[4] == 0x00 && b[5] == 0x00 && b[6] == 0x60)
		return "msf x86 block_api (Windows, raw)";
	if (n >= 6 && b[0] == 0x48 && b[1] == 0x31 && b[2] == 0xc9 &&
	    b[3] == 0x48 && b[4] == 0x81 && b[5] == 0xe9)
		return "msf x64/xor decoder stub";
	if (n >= 4 && b[0] == 0xd9 && b[1] == 0x74 && b[2] == 0x24)
		return "msf x86 fnstenv GetPC (shikata family)";
	if (n >= 8 && (b[4] == 0xd9 || b[5] == 0xd9) &&
	    (b[5] == 0x74 || b[6] == 0x74))
		return "msf x86 fnstenv GetPC (shikata family)";
	if (n >= 4 && b[0] == 0x48 && b[1] == 0x31 && b[2] == 0xc0)
		return "x86-64 shellcode, no decoder in front";
	if (n >= 2 && b[0] == 0xeb)
		return "jmp/pop/xor decoder stub";
	return "?";
}

/*
 * THE TOOL'S OWN ANALYSIS OF AN OBJECT'S LOADER, run once and kept on it.
 *
 * The engine does not search for loaders - they are detected by signatures
 * somebody wrote - so where a shellcode loader keeps its payload is something
 * the examiner works out for itself, with kofscfind, over the object's bytes
 * and the parse the engine already gave it. ONE run per object, here, when the
 * object is examined: the symbols dialog, the menu and the status line read
 * payload_at / payload_len / payload_bits off the object and none of them
 * searches. The result is a place and how it was found, never a verdict.
 *
 * `f` is the caller's, static, because it carries the decoded payload and is
 * the size of the largest one. Returns non-zero when this call found one.
 */
static int scfind_object(struct object *o, struct kofscfind *f)
{
	struct kgenome_obj gobj;

	if (o->sc_done || !o->fmt || !o->info ||
	    o->ctx.format != KOF_FMT_ELF || !o->ctx.file_header)
		return 0;
	o->sc_done = 1;
	kof_genome_obj(&o->ctx, &gobj);
	if (kofscfind_find(&gobj, o->buf.p, o->buf.n, f) != KGENOME_OK ||
	    !f->found)
		return 0;
	o->payload_at = f->va;
	o->payload_len = f->len;
	o->payload_bits = f->bits;
	return 1;
}

/*
 * WHICH OBJECT IS THE PAYLOAD A LOADER CARRIES, for naming the row.
 *
 * The object is the viewer's own: payload_derive below builds it from what
 * kofscfind located, so that every pane that works on an object works on the
 * payload. What is left here is naming the row, and that is a display
 * question: a reader wants "Shellcode-x86", not "//payload ELF-x86".
 *
 * Recognised by the SHAPE OF THE IMAGE kofscfind_image writes - no section
 * table at all, one segment - under a parent that has a payload_at.
 */
static void payload_tag(struct view *v, uint32_t at)
{
	struct object *o = &v->obj[at];
	const struct kgenome_elf_info *e = o->info;
	uint32_t p;

	if (!o->depth || o->ctx.format != KOF_FMT_ELF || !e || !e->valid)
		return;
	if (e->sec_count != 0 || e->seg_count != 1)
		return;
	for (p = 0; p < at; p++) {
		const struct object *par = &v->obj[p];
		size_t pn = strlen(par->name);

		if (par->depth + 1u != o->depth || !par->payload_at)
			continue;
		if (strncmp(o->name, par->name, pn) != 0 ||
		    o->name[pn] != '/')
			continue;
		o->payload_of = 1;
		/*
		 * WHICH VARIABLE IT CAME OUT OF, read back from the parent's
		 * symbol block rather than remembered, so the name shown here
		 * and the row marked in the symbols dialog can only ever be the
		 * same symbol. The address is kofscfind's and the block is
		 * the engine's.
		 */
		kof_sym_name_at(par->sym, par->sym_n, par->payload_at, -1,
			    o->payload_sym, sizeof o->payload_sym);
		return;
	}
}

/*
 * Parse and look up the objects from `from` onward.
 *
 * A range rather than the whole list, because objects arrive twice now: once
 * when the file is opened, and again when the reader runs the interpreter on a
 * node and it produces more. Re-examining the earlier ones would allocate a
 * second view for each and leak the first.
 */
/* `eng` is the view's, taken as an argument only so the two call sites read
 * the same. */
/* Returns non-zero when kofscfind found a payload in this very call, which is
 * the only time `sc_find` holds it. */
static struct kofscfind sc_find;

static int examine_one(struct view *v, uint32_t i)
{
	int found = 0;

	{
		struct object *o = &v->obj[i];

		/*
		 * AN OBJECT WITH NO BYTES YET IS LEFT ALONE.
		 *
		 * A PE carried inside an event is materialised when its row is
		 * picked, not when the window is built - so between the two it
		 * is a row with a declared size and an empty buffer. Running
		 * identify over that answers nothing and costs something: it
		 * memsets ctx, which is where the declared size lives, so the
		 * row went from "45992 bytes" to "0 bytes" before it was ever
		 * drawn.
		 *
		 * Nothing else reaches here empty - every other object is bytes
		 * out of the mapping or out of an unpacker.
		 */
		if (!o->buf.p || !o->buf.n)
			return 0;

		/*
		 * THE PROCESS RECORD IS DECLARED, NOT SNIFFED. It carries no
		 * magic a sniff could accept - see kof_inspect_declare - so
		 * identify answers Raw for it, and the root row of a process
		 * view then reads as unidentified bytes with no panel.
		 * Object 0 of a process view is the only object this applies
		 * to: everything else in the tree is a file or a region.
		 */
		/*
		 * AN OBJECT WHOSE REGIONS WERE DECLARED IS NOT SNIFFED, and
		 * that is the same decision the engine makes about it.
		 *
		 * A normalised view keeps its parent's header byte for byte, so
		 * a sniff succeeds and is wrong: the offsets in that header
		 * describe the file before the padding came out. Identified, it
		 * drew a data region at the parent's offset that ran into the
		 * kept code and showed padding the view no longer holds.
		 *
		 * So it is shown as what the engine says it is - raw bytes with
		 * a region table - and the table comes from the producer, which
		 * is the only side that could know.
		 */
		if (i == 0 && v->proc_pid) {
			o->fmt = kof_inspect_declare(o->buf, KOF_EVT_PROC,
						     &o->ctx, &o->info);
		} else {
			o->fmt = kof_inspect_identify(o->buf, &o->ctx,
						      &o->info);
		}
		if (!o->fmt)
			o->ctx.obj_size = o->buf.n;
		/*
		 * A DECLARED REGION TABLE BEATS THE PARSED ONE, and only the
		 * table - the rest of the parse stands.
		 *
		 * This used to skip identify altogether for a view, on the
		 * ground that a sniff succeeds and is wrong: the view keeps its
		 * parent's header byte for byte, so the offsets in it describe
		 * the file before the padding came out. The regions were the
		 * part that mattered and they are now overridden here, so the
		 * rest of the parse - what format it is, its class, its panels -
		 * is worth having and the engine relies on the same thing: it
		 * declares the view as its parent's format so rules written for
		 * that format can reach it at all.
		 *
		 * Left unidentified, the viewer said "raw" about an object the
		 * engine was scanning as an ELF, and the two screens disagreed
		 * about one file.
		 */
		if (o->n_rgn)
			o->ctx.resolve_scan = declared_regions;
		/* The engine's reading of what language this is beats a reading
		 * of the bytes - see struct object.lang_known. */
		if (o->lang_known) {
			o->ctx.subtype = o->subtype;
			o->ctx.subfamily = o->subfamily;
		}

		/*
		 * THE DIGEST AND THE EMULATOR GATE ARE NOT COMPUTED HERE ANY
		 * MORE, AND THAT IS THE WHOLE POINT OF SPILLING AN OBJECT.
		 *
		 * Both read every byte: the digest by definition, the gate by
		 * walking the executable segments for their byte histogram. Run
		 * on touch, they faulted a spilled object into memory in full -
		 * a 16MB view read end to end to fill two lines of a properties
		 * pane the reader may never open, when the hex pane beside it
		 * shows twenty rows and needs twenty rows' worth of pages.
		 * That undoes the reason a large child is written to a file and
		 * mapped rather than copied; see the note on o->mapped.
		 *
		 * So each is worked out where it is SHOWN - obj_sha256 and
		 * obj_emu_why below - and cached in the object exactly as
		 * before, so it still happens once and still never happens
		 * while drawing a row that does not ask for it.
		 */
		if (o->fmt && o->info &&
		    (o->ctx.format == KOF_FMT_ELF ||
		     o->ctx.format == KOF_FMT_PE))
			sym_build(o);
		found = scfind_object(o, &sc_find);
		payload_tag(v, i);
	}
	return found;
}

/*
 * THE PAYLOAD, AS AN OBJECT OF THE VIEWER'S OWN.
 *
 * Where kofscfind located a payload the examiner derives an object from it -
 * the decoded bytes where the loader keeps them base64, the bytes as they sit
 * otherwise, under the header kofscfind_image writes - and puts it in the
 * object list one level under the loader. From there the tree, the hex pane,
 * the disassembly, Find, Go to and the draft all work on it unchanged; a dialog
 * showing the bytes would be a second, worse copy of them.
 *
 * NOTHING OF THIS IS THE ENGINE'S. It is not scanned, it has no verdict, and no
 * signature sees it: it is something the person looking at the file asked the
 * tool to lay out. It is stored by on_object like every child - that is the one
 * place that decides heap, spill or too big - and then moved to where a child
 * sits, directly after the loader's subtree, because the tree is built from the
 * list in walk order. Called for object `p` right after it was examined, while
 * sc_find still holds ITS answer; the move only touches objects after `p`,
 * none of which has been examined yet, so the loop in objects_examine_from
 * reaches the derived object as it would any other.
 */
static void payload_derive(struct view *v, uint32_t p)
{
	static uint8_t img[KOFSCFIND_IMAGE_MAX];
	static struct kof_result none;
	const struct object *par = &v->obj[p];
	struct object saved;
	char name[sizeof par->name];
	uint64_t n;
	uint32_t at, end;
	int into = v->into_obj, skip = v->skip_root;
	uint32_t dedup = v->dedup_from;

	if (v->n_obj >= MAX_OBJ)
		return;
	n = kofscfind_image(&sc_find, par->buf.p, par->buf.n,
			    par->ctx.arch == KGENOME_ARCH_X86_64, img,
			    sizeof img);
	if (!n)
		return;
	if (snprintf(name, sizeof name, "%s%s", par->name,
		     KOF_OBJ_SEP "payload") >= (int)sizeof name)
		return;
	/* What a scan leaves for on_object must not steer this call. */
	v->into_obj = -1;
	v->dedup_from = 0;
	v->skip_root = 0;
	none.entry_of = KOF_ENTRY_NONE;
	at = v->n_obj;
	on_object(name, img, n, &none, v);
	v->into_obj = into;
	v->dedup_from = dedup;
	v->skip_root = skip;
	if (v->n_obj == at)
		return;
	/* After the whole subtree of the loader: what follows it and is deeper. */
	end = p + 1;
	while (end < at && v->obj[end].depth > v->obj[p].depth)
		end++;
	saved = v->obj[at];
	memmove(&v->obj[end + 1], &v->obj[end],
		(size_t)(at - end) * sizeof v->obj[0]);
	v->obj[end] = saved;
}

void objects_examine_from(struct view *v, kof_engine *eng, uint32_t from)
{
	uint32_t i;

	(void)eng;
	for (i = from; i < v->n_obj; i++)
		if (examine_one(v, i))
			payload_derive(v, i);
}

void objects_examine(struct view *v, kof_engine *eng)
{
	objects_examine_from(v, eng, 0);
	}



int decl_top(void) { return g_rows - g_decl_rows; }
