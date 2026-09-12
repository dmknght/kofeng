/*
 * wwalk.c - libkofgrille's answer to libkoforbit/kofwalk/kofwalk.h.
 *
 * THE MEMORY SCAN'S LOGIC LIVES HERE, not in the scanner - the same division
 * awalk.c makes on Linux and for the same reason. A host asks "what is running
 * and what should I look at"; deciding that a loaded module is scanned as its
 * FILE, that an unbacked executable allocation is scanned as BYTES, and that a
 * manually mapped image has to be put back into file layout first are answers
 * about Windows memory, and Windows memory is this library's subject.
 *
 * This file REPLACES kofwatcher/kofmemscan.c, which was a whole second tool
 * holding the same decisions. What it does not carry over is named at the
 * bottom of this comment, so the omission is a decision rather than a gap
 * somebody finds later.
 *
 *
 * THREE THINGS IT DOES THAT THE LINUX WALK DOES NOT HAVE TO.
 *
 * 1. RUNS ARE GROUPED BACK INTO ALLOCATIONS. Windows reports runs of identical
 *    protection, so one hand-mapped DLL comes back as four or five of them -
 *    header read-only, .text RX, .data RW. Handing each over separately
 *    reports one payload five times and hands the PE parser a fragment that
 *    starts nowhere near a PE header. kofw_region.alloc_base is what groups
 *    them, and the walk is in address order, so a run whose alloc_base differs
 *    ends the span.
 *
 * 2. A MAPPED PE IS DECLARED AS ONE. See kof_walk_item.as_format: the loader's
 *    layout is not the file's, and resolving the scan regions from the wrong
 *    one is silent. Linux needs nothing here - an ELF's PT_LOAD segments are
 *    mapped at the file's own offsets, and the EXEC bytes measured 0% different
 *    from the file.
 *
 * 3. AND THEN IT IS UN-MAPPED, because the loader also CHANGED bytes on the way
 *    in: it applied base relocations, so every absolute pointer differs from
 *    the file by the load delta. A signature whose literal crosses one matches
 *    the file and not the image, and there is no way to tell that from a miss.
 *    See pe_unmap.h. The mapped form is handed over as well as the un-mapped
 *    one, because the un-map can fail and because a span that is not a PE at
 *    all still has to reach the rules written for unidentified bytes.
 *
 *
 * IT INCLUDES ENGINE HEADERS, AND THAT IS WHY IT IS NOT IN libkofgrille.a.
 *
 * kofantarc.h's rule - collect, do not judge - holds for the archive, which is
 * cross-built with mingw and linked by kofwatchtower, a tool with no engine in
 * it. This file calls kof_pe_unmap, so it is compiled INTO the scanner instead,
 * exactly as libkofantarc/awalk.c is on Linux. Adding it to the archive would
 * make every collector consumer link the engine.
 *
 *
 * WHAT kofmemscan DID THAT THIS DOES NOT: the image-against-its-file diff. At
 * its level 2 it read a module whose pages had gone private, read the file
 * behind it, and reported WHICH bytes differed - which is how hollowing and an
 * inline patch are told apart from each other and from a relocated image. That
 * is a comparison producing a finding, not a source of bytes to scan, so it
 * does not fit behind next_item at all; it belongs in a rule that is given both
 * copies. Said here rather than quietly dropped.
 */

#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "kofeng.h"
#include <kofmod/pe.h>
#include "kofunpack/pe_unmap.h"

#include "wproc.h"
#include "kofwalk.h"

/*
 * THE READ BOUND, and it is a bound on ONE allocation rather than on the sweep.
 *
 * 64MB reaches every payload anybody maps by hand and stops short of the
 * multi-gigabyte reservations a JIT or a database makes, which are the
 * allocations that would otherwise decide how long a sweep takes. A span over
 * it is read up to the bound and scanned - truncated rather than skipped,
 * because a payload at the front of a huge reservation is still a payload.
 */
#define W_MAX_SPAN (64u * 1024u * 1024u)

/* Under this a span cannot hold a PE header, so there is nothing to un-map and
 * the un-map would only report a failure nobody can act on. */
#define W_MIN_IMAGE 0x400u

/* Where next_item is in its walk of one process. */
enum w_stage {
	W_STAGE_SPANS = 0,   /* unbacked and stomped executable memory */
	W_STAGE_MODULES,     /* the files behind the loaded modules */
	W_STAGE_DONE
};

struct wwalk {
	struct kof_walk_api    api;
	struct kof_walk_option o;

	struct kofw_plist *list;
	struct kofw_proc   proc;
	int                have_proc;

	/* Where we are in the caller's pid list, when there is one. */
	uint32_t idx;

	struct kofw_pmem  *mem;
	struct kofw_region rg;
	int                have_rg;    /* w->rg holds a run not yet folded in */
	int                stage;

	/* The span being accumulated out of consecutive runs. */
	uint64_t span_base, span_end;
	int      span_pe, have_span;

	/*
	 * THE UN-MAPPED COPY, held so it can be handed over as the item AFTER
	 * the mapped one. next_item returns a single item, and a mapped image
	 * is worth scanning twice - as the loader left it, and as its file
	 * would have been.
	 */
	uint8_t *back;
	uint64_t back_len;
	uint64_t back_addr;
	int      back_pending;

	/* One read buffer, grown and reused for the whole walk. */
	uint8_t *buf;
	size_t   cap;

	/* Declared alongside a mapped image; borrowed by the item, so it has
	 * to outlive the call that returns it. */
	struct kof_pe_info hint;

	uint64_t procs, refused, regions, bytes;
};

/*
 * Fill the engine's record form from what the snapshot found. The two are
 * different vocabularies for the same facts and this is the only place that
 * knows both - the mirror of awalk.c's to_build.
 */
static void to_build(const struct kofw_proc *p, struct kof_proc_build *b)
{
	memset(b, 0, sizeof *b);
	b->os = KOF_PLAT_WINDOWS;
	b->pid = p->pid;
	b->ppid = p->ppid;
	b->start_time = p->create_time;

	/* The per-platform tail, in the order kof_proc_rec's union expects for
	 * Windows: session then integrity. */
	b->plat_a = p->session_id;
	b->plat_b = p->integrity;

	/*
	 * NO FD COUNTS, and that is a fact about Windows rather than an
	 * omission. The reverse-shell rule these feed on Linux joins stdin and
	 * stdout to one socket by reading /proc/<pid>/fd; a Windows process's
	 * handle table is not enumerable without a driver, and the standard
	 * handles are not numbered 0, 1 and 2. A rule that asked would get
	 * zeroes, so the record says zero rather than guessing.
	 */

	b->exe = p->image;
	{
		const char *slash = strrchr(p->image, '\\');

		b->comm = slash ? slash + 1 : p->image;
	}
	b->cmdline = p->cmdline;

	/*
	 * WITH KOFW_PF_NO_PATH the `image` is a name the snapshot carried, not
	 * a location - nothing can be opened at it, which is exactly what
	 * EXE_ON_DISK asserts. There is no neutral flag for "refused": a
	 * process this walk could not open never reaches next_proc at all, the
	 * way it does not on Linux either, and it is counted in stats()
	 * instead.
	 */
	if (!(p->flags & (KOFW_PF_NO_PATH | KOFW_PF_REFUSED)))
		b->flags |= KOF_PROC_F_EXE_ON_DISK;
}

static int grow(struct wwalk *w, size_t n)
{
	uint8_t *nb;

	if (n <= w->cap)
		return 1;
	nb = realloc(w->buf, n);
	if (!nb)
		return 0;
	w->buf = nb;
	w->cap = n;
	return 1;
}

static void drop_back(struct wwalk *w)
{
	free(w->back);
	w->back = NULL;
	w->back_len = 0;
	w->back_pending = 0;
}

static void close_mem(struct wwalk *w)
{
	if (w->mem) {
		kofw_pmem_close(w->mem);
		w->mem = NULL;
	}
	drop_back(w);
	w->have_rg = 0;
	w->have_span = 0;
	w->stage = W_STAGE_DONE;
}

static int wanted(const struct wwalk *w, uint32_t pid)
{
	uint32_t i;

	if (!w->o.pids || !w->o.n_pids)
		return 1;
	for (i = 0; i < w->o.n_pids; i++)
		if (w->o.pids[i] == pid)
			return 1;
	return 0;
}

static int open_mem_for(struct wwalk *w, const struct kofw_proc *p)
{
	struct kofw_pmem_option po;
	int err = 0;

	memset(&po, 0, sizeof po);
	/*
	 * PATHS so a module can be handed over as a file rather than as bytes,
	 * DIRTY so a stomped image is distinguishable from a clean one, and
	 * EXEC_ONLY because everything this walk hands over as BYTES is
	 * executable. The heap is not asked for: see the note in
	 * KOFW_MW_HEAP, and the measurement on the Linux side that a parent
	 * shell's heap matched a string that had merely passed through it.
	 */
	/* The purpose decides the set - see enum kof_walk_intent and the note
	 * beside the same choice in awalk.c. MAP adds the heap and drops
	 * EXEC_ONLY, because a reader opened this to look at it. */
	if (w->o.intent == KOF_WALK_MAP)
		po.want = KOFW_MW_PATHS | KOFW_MW_DIRTY | KOFW_MW_HEAP;
	else
		po.want = KOFW_MW_PATHS | KOFW_MW_DIRTY | KOFW_MW_EXEC_ONLY;
	po.max_region = W_MAX_SPAN;

	w->mem = kofw_pmem_open(p->pid, p->create_time, &po, &err);
	if (!w->mem) {
		w->refused++;
		return 0;
	}
	w->stage = W_STAGE_SPANS;
	w->have_rg = 0;
	w->have_span = 0;
	return 1;
}

static int w_next_proc(void *self, struct kof_proc_build *out)
{
	struct wwalk *w = self;

	if (!w || !out)
		return 0;
	close_mem(w);
	w->have_proc = 0;

	/* The caller named its pids: open each by number, and never take the
	 * snapshot at all. */
	if (w->o.pids && w->o.n_pids) {
		while (w->idx < w->o.n_pids) {
			struct kofw_plist_option lo;
			struct kofw_plist *one;
			uint32_t pid = w->o.pids[w->idx++];
			int err = 0;

			memset(&lo, 0, sizeof lo);
			lo.only_pid = pid;
			one = kofw_plist_open(&lo, &err);
			if (!one) {
				w->refused++;
				continue;
			}
			if (!kofw_plist_next(one, &w->proc)) {
				kofw_plist_close(one);
				w->refused++;
				continue;
			}
			/*
			 * COPIED OUT BEFORE THE LIST CLOSES. kofw_proc's two
			 * strings are borrowed from the handle that produced
			 * them, and this handle is closed on the next line -
			 * so the pmem session is opened first, which is what
			 * republishes them for the rest of this process's
			 * walk.
			 */
			if (w->proc.flags & KOFW_PF_SELF) {
				kofw_plist_close(one);
				continue;
			}
			if (!open_mem_for(w, &w->proc)) {
				kofw_plist_close(one);
				continue;
			}
			{
				const struct kofw_proc *live =
					kofw_pmem_proc(w->mem);

				if (live)
					w->proc = *live;
			}
			kofw_plist_close(one);
			w->procs++;
			w->have_proc = 1;
			to_build(&w->proc, out);
			return 1;
		}
		return 0;
	}

	if (!w->list)
		return 0;

	while (kofw_plist_next(w->list, &w->proc)) {
		/*
		 * NEVER ITSELF. The database is in this address space, and a
		 * scanner that scans its own pattern tables reports every
		 * family it knows.
		 */
		if (w->proc.flags & KOFW_PF_SELF)
			continue;
		if (!wanted(w, w->proc.pid))
			continue;

		/*
		 * A PROCESS THAT WILL NOT OPEN IS COUNTED AND SKIPPED, which
		 * is what awalk.c does and therefore what a caller of this
		 * contract already handles. Protected processes and anything
		 * at a higher integrity than this one are the ordinary case,
		 * not an error - stats() is where "never looked at" is told
		 * apart from "clean".
		 */
		if (!open_mem_for(w, &w->proc))
			continue;
		w->procs++;
		w->have_proc = 1;
		to_build(&w->proc, out);
		return 1;
	}
	return 0;
}

/* Read one span and hand it over. 0 when there was nothing readable in it. */
static int take_span(struct wwalk *w, struct kof_walk_item *out)
{
	uint64_t size = w->span_end - w->span_base;
	size_t want, got;

	w->have_span = 0;
	if (!size)
		return 0;
	want = size > W_MAX_SPAN ? (size_t)W_MAX_SPAN : (size_t)size;
	if (!grow(w, want))
		return 0;

	/*
	 * SHORT IS NORMAL AND IS NOT AN ERROR. A guard page in the way, a
	 * module unloaded mid-walk, a page decommitted between the query and
	 * the read - kofw_pmem_read stops at the first refusal and returns
	 * what it got, and thirty-nine pages of forty are still worth
	 * scanning.
	 */
	got = kofw_pmem_read(w->mem, w->span_base, w->buf, want);
	if (!got)
		return 0;
	w->bytes += got;

	out->kind = KOF_WALK_BYTES;
	out->addr = w->span_base;
	out->p    = w->buf;
	out->len  = (uint64_t)got;

	if (w->span_pe) {
		/*
		 * DECLARED, because the bytes cannot say it - see
		 * kof_walk_item.as_format. The whole view is passed rather
		 * than a prefix: `layout` sits at the end of it, where adding
		 * a field cannot move the fields a database compiled earlier
		 * reads by offset.
		 */
		memset(&w->hint, 0, sizeof w->hint);
		w->hint.layout  = KOF_PE_LAYOUT_MAPPED;
		out->as_format  = KOF_FMT_PE;
		out->as_view    = &w->hint;
		out->as_view_len = (uint32_t)sizeof w->hint;

		/*
		 * AND THE FILE IT WOULD HAVE BEEN, queued for the next call.
		 *
		 * NO PREFERRED BASE TO GIVE, and that is right rather than a
		 * gap: this path is an allocation that begins with a PE header
		 * and is backed by no file, so there IS no file to read a base
		 * out of and the header in front of us is the only account of
		 * one. Which is also the case where that account is usually
		 * right - a reflective loader applies the relocations and does
		 * not trouble itself to rewrite ImageBase afterwards.
		 */
		if (got >= W_MIN_IMAGE &&
		    kof_pe_unmap(kof_buf_make(w->buf, (uint64_t)got),
				 w->span_base, 0, W_MAX_SPAN,
				 &w->back, &w->back_len, NULL)) {
			w->back_addr = w->span_base;
			w->back_pending = 1;
		}
	}
	return 1;
}

/*
 * The bytes of a module that no file holds. At this point the mapped copy is
 * the ONLY copy, so it is un-mapped into a file and handed over as one - which
 * is what makes the file corpus reach a module that was never written to disk.
 */
static int take_nameless_module(struct wwalk *w, const struct kofw_module *md,
				struct kof_walk_item *out)
{
	size_t got;

	if (!md->size || md->size > W_MAX_SPAN)
		return 0;
	if (!grow(w, (size_t)md->size))
		return 0;
	got = kofw_pmem_read(w->mem, md->base, w->buf, (size_t)md->size);
	if (got < W_MIN_IMAGE)
		return 0;
	w->bytes += got;

	out->kind = KOF_WALK_BYTES;
	out->addr = md->base;
	out->p    = w->buf;
	out->len  = (uint64_t)got;

	memset(&w->hint, 0, sizeof w->hint);
	w->hint.layout   = KOF_PE_LAYOUT_MAPPED;
	out->as_format   = KOF_FMT_PE;
	out->as_view     = &w->hint;
	out->as_view_len = (uint32_t)sizeof w->hint;

	if (kof_pe_unmap(kof_buf_make(w->buf, (uint64_t)got), md->base, 0,
			 W_MAX_SPAN, &w->back, &w->back_len, NULL)) {
		w->back_addr = md->base;
		w->back_pending = 1;
	}
	return 1;
}

static int w_next_item(void *self, struct kof_walk_item *out)
{
	struct wwalk *w = self;
	struct kofw_module md;

	if (!w || !out || !w->mem)
		return 0;

	/* The un-mapped copy of whatever was handed over last. */
	if (w->back_pending) {
		memset(out, 0, sizeof *out);
		out->kind = KOF_WALK_BYTES;
		out->addr = w->back_addr;
		out->p    = w->back;
		out->len  = w->back_len;
		w->back_pending = 0;
		return 1;
	}
	drop_back(w);
	memset(out, 0, sizeof *out);

	while (w->stage == W_STAGE_SPANS) {
		int want_it;

		if (w->have_rg) {
			w->have_rg = 0;
		} else if (!kofw_pmem_next_region(w->mem, &w->rg)) {
			w->stage = W_STAGE_MODULES;
			if (w->have_span && take_span(w, out))
				return 1;
			w->have_span = 0;
			break;
		}
		w->regions++;

		/*
		 * WHAT IS WORTH READING, and the set is small on purpose.
		 * Unbacked executable memory is where a reflective loader, a
		 * manually mapped module and plain shellcode all end up.
		 * Executable memory behind a file mapped as DATA is module
		 * stomping and is not something a compiler or a JIT produces.
		 *
		 * A dirty image region is NOT read here. Its bytes are almost
		 * entirely identical to the file, which the module stage below
		 * hands over anyway; what "this page changed" is worth is the
		 * diff against that file, and that is a comparison rather than
		 * a source of bytes - see the note at the top of this file.
		 */
		want_it = (w->rg.use == KOFW_USE_CODE) ||
			  (w->rg.flags & KOFW_RGF_DATA_EXEC) != 0;
		if (w->rg.flags & KOFW_RGF_GUARD)
			want_it = 0;

		/* A run belonging to a different allocation ends the span in
		 * hand. The run itself is kept for the next turn. */
		if (w->have_span && w->rg.alloc_base != w->span_base) {
			w->have_rg = 1;
			if (take_span(w, out))
				return 1;
			continue;
		}
		if (!want_it)
			continue;

		if (!w->have_span) {
			w->span_base = w->rg.alloc_base;
			w->span_end  = w->rg.base + w->rg.size;
			w->span_pe   = (w->rg.flags & KOFW_RGF_PE) != 0;
			w->have_span = 1;
		} else {
			if (w->rg.base + w->rg.size > w->span_end)
				w->span_end = w->rg.base + w->rg.size;
			w->span_pe |= (w->rg.flags & KOFW_RGF_PE) != 0;
		}
	}

	while (w->stage == W_STAGE_MODULES &&
	       kofw_pmem_next_module(w->mem, &md)) {
		if (md.flags & (KOFW_MDF_UNNAMED | KOFW_MDF_NO_FILE)) {
			if (take_nameless_module(w, &md, out))
				return 1;
			continue;
		}
		if (md.path && md.path[0]) {
			/*
			 * THE FILE, NOT THE MAPPING. Its pages are shared with
			 * every other process that mapped it precisely BECAUSE
			 * they are identical to it, and the file has an
			 * identity a cache can key on while a mapping has none.
			 */
			out->kind = KOF_WALK_FILE;
			out->path = md.path;
			return 1;
		}
	}
	w->stage = W_STAGE_DONE;
	return 0;
}

static void w_stats(void *self, uint64_t *procs, uint64_t *refused,
		    uint64_t *regions, uint64_t *bytes)
{
	struct wwalk *w = self;

	if (!w)
		return;
	if (procs)   *procs = w->procs;
	if (refused) *refused = w->refused;
	if (regions) *regions = w->regions;
	if (bytes)   *bytes = w->bytes;
}

static void w_close(void *self)
{
	struct wwalk *w = self;

	if (!w)
		return;
	close_mem(w);
	if (w->list)
		kofw_plist_close(w->list);
	free(w->buf);
	free(w);
}

struct kof_walk_api *kof_walk_open(const struct kof_walk_option *opt, int *err)
{
	struct wwalk *w = calloc(1, sizeof *w);
	int e = 0;

	if (!w) {
		if (err) *err = KOFW_ERR_MEM;
		return NULL;
	}
	if (opt)
		w->o = *opt;
	w->stage = W_STAGE_DONE;

	/* No snapshot is taken when the caller named its pids: the whole point
	 * of naming them is not to walk the table. */
	if (!w->o.pids || !w->o.n_pids) {
		struct kofw_plist_option lo;

		memset(&lo, 0, sizeof lo);
		/* PATHS and the command line, because the process record the
		 * engine scans carries both - see kofmod/proc.h. */
		lo.want = KOFW_PW_ALL;
		w->list = kofw_plist_open(&lo, &e);
		if (!w->list) {
			free(w);
			if (err) *err = e;
			return NULL;
		}
	}

	w->api.self      = w;
	w->api.next_proc = w_next_proc;
	w->api.next_item = w_next_item;
	w->api.stats     = w_stats;
	w->api.close     = w_close;

	if (err) *err = 0;
	return &w->api;
}
