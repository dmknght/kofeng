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
 * 4. AND A MODULE THAT WAS WRITTEN TO IS COMPARED AGAINST ITS FILE. See
 *    wdiff.h. This was kofmemscan's level 2 and was lost in the merge that
 *    produced this file; the note here used to say it did not fit behind
 *    next_item, which was only true of the REPORT. The bytes fit perfectly
 *    well: each differing run is handed over as ordinary KOF_WALK_BYTES,
 *    labelled MEM_PATCH, so every rule in the database reaches an inline hook
 *    without anything new being taught to the scanner. What genuinely does not
 *    fit - which section, how far from its file, how many runs - goes to the
 *    callback in wdiff.h instead.
 *
 *    It runs only for modules the region walk saw a written-to page in, and
 *    reads only THOSE PAGES. Both halves are needed: a written-to image page
 *    is not rare on Windows - the loader's import optimisation writes into
 *    .text, so ntdll is written to in every process on the machine - and the
 *    first version of this read whole modules for it, which cost 1676MB a
 *    sweep. Reading the dirty extents instead costs 62MB and finds more. See
 *    wdiff.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "kofeng.h"
#include <kofmod/pe.h>
#include "kofunpack/pe_unmap.h"

#include "wproc.h"
#include "wdiff.h"
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

/*
 * How many written-to modules one process may have noted, and how many
 * differing runs one module may hand back.
 *
 * Both are small on purpose and both report their own overflow rather than
 * silently truncating - see wwalk.dirty_over and kofw_diff_stat.capped. A
 * module with more than thirty-two differing runs has been rewritten rather
 * than hooked, and THAT is the finding; the list stops being what a reader
 * needs long before the count does.
 */
#define W_DIRTY_MAX 64u

/*
 * 256, and it was 32.
 *
 * The cap bounds how many runs are handed out as items to scan, and at 32 it
 * was also silently bounding what the SUMMARY said: one mscoree.dll produced
 * 119 differing runs and the line read "33". A number that is the smaller of
 * what was found and an internal array size is not a count of anything.
 *
 * Raising it is nearly free because a run is a few bytes - 119 of them in that
 * module came to 190 bytes in total - so the cost of scanning them all is
 * nothing next to the reads that found them. Past 256 the module has been
 * rewritten rather than patched, and THAT is the finding.
 */
#define W_PATCH_MAX 256u

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
	 * WHAT THE SPAN IS, carried so the item can be NAMED.
	 *
	 * A span is several runs of one allocation, and the caller showing it
	 * to somebody needs a word rather than an address - see
	 * kof_walk_item.label. `use` is taken from the run that opened the
	 * span, because that run is the allocation's base and is what the
	 * allocation was made for; `flags` is OR-ed across every run, because
	 * a PE header in the first page and executable code in the third are
	 * both facts about the one thing.
	 */
	uint8_t  span_use;
	uint32_t span_flags;

	/*
	 * WHERE THE FIRST WANTED RUN OF THE SPAN ACTUALLY BEGINS.
	 *
	 * `span_base` is the ALLOCATION base, deliberately: for a hand-mapped
	 * image the PE header sits there and the executable runs do not, so a
	 * span that began at the first executable run would hand the parser a
	 * fragment starting nowhere near a header. Reaching back is the point.
	 *
	 * But an allocation base is not always readable. A thread stack is one
	 * allocation whose lowest pages are RESERVED and never committed, so
	 * the read at span_base returns nothing and take_span dropped the whole
	 * span - measured, every stack in the process: 29 threads, 0 MEM_STACK
	 * rows. This is what it falls back to, so an allocation whose base
	 * cannot be read still yields the part that can.
	 */
	uint64_t span_first;

	/*
	 * THE MODULES WITH A WRITTEN-TO PAGE IN THEM, gathered in the span
	 * stage and read in the module stage - see the note where it is filled.
	 *
	 * A FIXED SET, because it is small by construction: a process with more
	 * than a few dozen written-to modules is not a process this list would
	 * help with, and a walk must not start allocating per process. `over`
	 * says the set filled up, so a caller learns the comparison was skipped
	 * for some rather than that they were clean.
	 */
	struct kofw_diff_range dirty[W_DIRTY_MAX];
	uint64_t dirty_mod[W_DIRTY_MAX];
	uint32_t n_dirty;
	uint32_t dirty_over;

	/* Parsed once per distinct file, reused across every process that
	 * mapped it - see wdiff.h. */
	struct kofw_diff_cache *dcache;

	/* The runs the last comparison produced, handed out one per item. */
	struct kofw_diff_run patch[W_PATCH_MAX];
	uint32_t n_patch, i_patch;
	uint64_t patch_at;      /* the module they belong to */

	/* What the comparisons came to, for whoever reports the walk. */
	uint64_t diff_modules, diff_runs, diff_bytes, diff_small, diff_unknown;
	/* Differing bytes the image's own dynamic relocation table accounts
	 * for. Shown, not hidden - see kofw_diff_stat.dvrt_explained. */
	uint64_t diff_dvrt;
	/* Dirty extents the fixed set could not hold, summed over every
	 * process - each one is a module that was NOT compared. */
	uint64_t diff_skipped;

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

	/*
	 * THE DIRTY SET BELONGS TO THE PROCESS THAT FILLED IT.
	 *
	 * It was not cleared here, and the consequence was not a leak - it was
	 * a WRONG ANSWER, because of ASLR. A system DLL sits at the same
	 * address in every process on the machine for the life of a boot, so
	 * an entry left behind by process A matched the same module in process
	 * B by base, and B's copy was then compared over a range that nothing
	 * had established was written to in B.
	 *
	 * Measured: 9 regions were ever recorded, and 174 modules matched one -
	 * so all but nine of those comparisons were run on another process's
	 * evidence. The reads were real, the ranges were real, and the
	 * attribution was not.
	 */
	w->diff_skipped += w->dirty_over;
	w->n_dirty = 0;
	w->dirty_over = 0;
	w->n_patch = 0;
	w->i_patch = 0;
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
	/*
	 * DIRTY IS ASKED FOR ONLY WHERE SOMETHING READS THE ANSWER.
	 *
	 * It costs a working-set query per executable image region - one array
	 * entry per page - and it was being asked for on every walk. A MAP
	 * walk reads it: the viewer labels such a region MEM_IMAGE_DIRTY. A
	 * SCAN walk reads it only when the module comparison is on, which is
	 * heur 2; below that the flag was computed, paid for, and looked at by
	 * nobody.
	 */
	if (w->o.intent == KOF_WALK_MAP)
		po.want = KOFW_MW_PATHS | KOFW_MW_DIRTY | KOFW_MW_HEAP;
	else
		po.want = KOFW_MW_PATHS | KOFW_MW_EXEC_ONLY |
			  (w->o.compare_modules ? KOFW_MW_DIRTY : 0u);
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
/*
 * The word for a region, in this tree's region vocabulary - see
 * kof_walk_item.label, and a_label() in libkofantarc/awalk.c, which this
 * deliberately mirrors.
 *
 * THE SAME WORDS ON BOTH PLATFORMS, and that is the whole point of writing it
 * here rather than letting the caller invent them. A viewer showing a Linux
 * process and a Windows one is one panel; if the two collectors spell the heap
 * differently then a reader has to learn which machine they are looking at
 * before they can read the tree, and every rule or filter written against the
 * word has to know both spellings.
 *
 * This did not exist, so `label` was NULL on Windows and every region row fell
 * back to being named by its address - which is the thing kof_walk_item.label
 * says in as many words is useless to a reader: "a row reading
 * 00007fce21b7f000 tells a reader nothing they can act on".
 *
 * The three flag cases come first because they are what is worth seeing: a
 * module laid out by hand, code running out of a data mapping, and an image
 * page somebody wrote to. Each of those is a fact about HOW the memory got
 * that way, which outranks what it is nominally for.
 */
static const char *w_label(uint8_t use, uint32_t flags)
{
	if (flags & KOFW_RGF_PE)
		return "MEM_MANUALMAP";
	if (flags & KOFW_RGF_DATA_EXEC)
		return "MEM_DATAEXEC";
	/*
	 * An executable image page that has stopped being shared is one
	 * somebody WROTE - an inline hook, a blown-away AMSI stub, a hollowed
	 * section. wproc only computes this for executable image regions, so
	 * the word is never spent on ordinary copy-on-write in .data.
	 */
	if (flags & KOFW_RGF_DIRTY_IMAGE)
		return "MEM_IMAGE_DIRTY";

	switch (use) {
	case KOFW_USE_HEAP:  return "MEM_HEAP";
	case KOFW_USE_STACK: return "MEM_STACK";
	case KOFW_USE_CODE:  return "MEM_CODE";
	case KOFW_USE_DATA:  return "MEM_DATA";
	case KOFW_USE_IMAGE: return "MEM_IMAGE";
	default:             return "MEM_ANON";
	}
}

/*
 * THE EXTENT, NOT JUST THE MODULE.
 *
 * This kept only the allocation base, so the comparison knew WHICH module had
 * been written to and nothing about WHERE - and then read the whole module to
 * find out. Keeping the region's own base and length is what lets the
 * comparison read a few pages instead of two megabytes; see wdiff.h for the
 * measurement that forced it.
 *
 * Several regions of one module are several entries, deliberately. Merging
 * them into one bounding range would put every clean page between two dirty
 * ones back into the read.
 */
/*
 * The trace, resolved once. It found three of the four bugs this walk had, so
 * it stays - but getenv sits in a path called per dirty region and per module,
 * and a lookup per call to answer a question that cannot change mid-run is the
 * kind of cost that arrives without anybody choosing it.
 */
static int trace_on(void)
{
	static int v = -1;

	if (v < 0)
		v = getenv("KOFW_DIFF_TRACE") ? 1 : 0;
	return v;
}

static void dirty_add(struct wwalk *w, uint64_t mod_base, uint64_t base,
		      uint64_t len)
{
	uint32_t i;

	if (!mod_base || !len)
		return;
	for (i = 0; i < w->n_dirty; i++)
		if (w->dirty[i].addr == base && w->dirty[i].len == len)
			return;
	if (w->n_dirty >= W_DIRTY_MAX) {
		w->dirty_over++;
		return;
	}
	if (trace_on())
		fprintf(stderr, "DIRTY mod=%llx base=%llx len=%llu\n",
			(unsigned long long)mod_base,
			(unsigned long long)base, (unsigned long long)len);
	w->dirty_mod[w->n_dirty]    = mod_base;
	w->dirty[w->n_dirty].addr   = base;
	w->dirty[w->n_dirty].len    = len;
	w->n_dirty++;
}

/* The dirty extents belonging to one module, gathered for the comparison. */
static uint32_t dirty_of(const struct wwalk *w, uint64_t mod_base,
			 struct kofw_diff_range *out, uint32_t cap)
{
	uint32_t i, n = 0;

	for (i = 0; i < w->n_dirty && n < cap; i++)
		if (w->dirty_mod[i] == mod_base)
			out[n++] = w->dirty[i];
	return n;
}

/*
 * THE CALLBACK THE COMPARISON REPORTS THROUGH, and all it does is keep the
 * runs so the walk can hand them out one item at a time.
 *
 * It does not scan and does not decide. next_item returns ONE item, and a
 * module may differ in several places, so the runs are collected here and
 * drained by w_next_item on the following calls - the same shape back_pending
 * already uses for the un-mapped copy of a span.
 */
static int patch_seen(const struct kofw_diff_run *r, const uint8_t *mem,
		      const uint8_t *file, void *user)
{
	struct wwalk *w = user;

	(void)file;
	(void)mem;
	if (w->n_patch >= W_PATCH_MAX)
		return 1;               /* enough: stop the comparison */
	w->patch[w->n_patch++] = *r;
	return 0;
}

/*
 * Hand over the next differing run as bytes to be scanned.
 *
 * THE BYTES COME OUT OF THE PROCESS, not out of the un-mapped copy the
 * comparison built. What a rule should be run over is what is actually
 * executing in that address space - the un-map exists to make the COMPARISON
 * possible by putting the loader's relocations back, and a scan of its output
 * would be a scan of a reconstruction.
 *
 * Undeclared, so it reaches the modules written for unidentified bytes. A
 * sixty-byte patch is not a PE and declaring it one would send it to a parser
 * that will refuse it.
 */
static int take_patch(struct wwalk *w, struct kof_walk_item *out)
{
	const struct kofw_diff_run *r;
	size_t got;

	while (w->i_patch < w->n_patch) {
		r = &w->patch[w->i_patch++];
		if (!r->len || r->len > W_MAX_SPAN)
			continue;
		if (!grow(w, r->len))
			continue;
		got = kofw_pmem_read(w->mem, r->addr, w->buf, r->len);
		if (!got)
			continue;
		w->bytes += got;

		out->kind  = KOF_WALK_BYTES;
		out->addr  = r->addr;
		out->p     = w->buf;
		out->len   = (uint64_t)got;
		out->label = "MEM_PATCH";
		return 1;
	}
	w->n_patch = 0;
	w->i_patch = 0;
	return 0;
}

static int take_span(struct wwalk *w, struct kof_walk_item *out)
{
	uint64_t at = w->span_base;
	uint64_t size;
	size_t want, got;

	w->have_span = 0;
	if (w->span_end <= at)
		return 0;
	size = w->span_end - at;
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
	got = kofw_pmem_read(w->mem, at, w->buf, want);

	/*
	 * NOTHING AT THE ALLOCATION BASE IS NOT AN EMPTY SPAN.
	 *
	 * The lowest pages of an allocation can be reserved rather than
	 * committed - every thread stack is shaped that way - and then the read
	 * above returns zero for a span that has perfectly readable bytes
	 * further up. Dropping it was silent: 29 threads in this process and
	 * not one MEM_STACK row, because each stack's span started at a base
	 * that cannot be read.
	 *
	 * So the first WANTED run is the second attempt. It is only a fallback
	 * and not the first choice, because starting there loses the reach back
	 * to a PE header that span_base exists for.
	 */
	if (!got && w->span_first > at && w->span_first < w->span_end) {
		at   = w->span_first;
		size = w->span_end - at;
		want = size > W_MAX_SPAN ? (size_t)W_MAX_SPAN : (size_t)size;
		if (!grow(w, want))
			return 0;
		got = kofw_pmem_read(w->mem, at, w->buf, want);
	}
	if (!got)
		return 0;
	w->bytes += got;

	out->kind  = KOF_WALK_BYTES;
	out->addr  = at;
	out->p     = w->buf;
	out->len   = (uint64_t)got;
	out->label = w_label(w->span_use, w->span_flags);

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
	/*
	 * A module the loader lists and no file holds - it was deleted or
	 * renamed after the load, or it never had a name. Its own word, because
	 * it is neither ordinary image memory nor an anonymous allocation, and
	 * because that is a fact worth seeing in a tree. awalk.c spells the
	 * same shape MEM_DELETED.
	 */
	out->label = (md->flags & KOFW_MDF_NO_FILE) ? "MEM_DELETED"
						    : "MEM_UNNAMED";

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

/*
 * Read the module out of the process and compare it against its file.
 *
 * The runs land in w->patch and are drained by w_next_item. Nothing is
 * reported here, because a difference is not a verdict: see wdiff.h.
 */
static void diff_dirty_module(struct wwalk *w, const struct kofw_module *md)
{
	struct kofw_diff_option dopt;
	struct kofw_diff_stat   dst;
	struct kofw_diff_range  rg[W_DIRTY_MAX];
	uint32_t n;

	w->n_patch = 0;
	w->i_patch = 0;

	n = dirty_of(w, md->base, rg, W_DIRTY_MAX);
	if (trace_on()) {
		uint64_t tot = 0;
		uint32_t k;

		for (k = 0; k < n; k++)
			tot += rg[k].len;
		fprintf(stderr, "DIFF base=%llx ranges=%u bytes=%llu over=%u"
			" ndirty=%u %s\n",
			(unsigned long long)md->base, n,
			(unsigned long long)tot, w->dirty_over, w->n_dirty,
			md->path);
	}
	if (!n)
		return;

	memset(&dopt, 0, sizeof dopt);
	dopt.max_runs = W_PATCH_MAX;
	memset(&dst, 0, sizeof dst);
	(void)kofw_diff_module(w->mem, md, rg, n, w->dcache, &dopt,
			       patch_seen, w, &dst);
	if (trace_on())
		fprintf(stderr, "  -> runs=%u mem=%llu file=%llu relok=%llu"
			" relbad=%llu\n", dst.runs,
			(unsigned long long)dst.mem_read,
			(unsigned long long)dst.file_read,
			(unsigned long long)dst.reloc_explained,
			(unsigned long long)dst.reloc_wrong);

	/*
	 * The bytes the comparison read count toward the walk's own total, so
	 * the summary's "read out of them" stays the truth about what this
	 * walk actually pulled out of processes.
	 */
	w->bytes        += dst.mem_read;
	w->patch_at      = md->base;
	w->diff_modules += (dst.runs != 0);
	w->diff_runs    += dst.runs;
	w->diff_bytes   += dst.bytes;
	w->diff_small   += dst.small_runs;
	w->diff_dvrt    += dst.dvrt_explained;
	w->diff_unknown += (uint64_t)(dst.base_unknown != 0);
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

	/*
	 * The runs a comparison found, one per call. Drained BEFORE the stage
	 * loop, because the module that produced them was handed over on the
	 * previous call and the walk has already moved past it.
	 */
	if (w->i_patch < w->n_patch && take_patch(w, out))
		return 1;

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
		 * WHICH MODULES HAVE BEEN WRITTEN TO, NOTED NOW BECAUSE THE
		 * REGION WALK IS GONE BY THE TIME THE MODULES ARE.
		 *
		 * The two stages share one pass over the process: by the time
		 * W_STAGE_MODULES runs, kofw_pmem_next_region is exhausted and
		 * there is no second chance to ask which image pages had stopped
		 * being shared. So the answer is carried across in a small set.
		 *
		 * It is what makes the comparison affordable at all. Reading and
		 * diffing every module against its file would be eight thousand
		 * file reads a sweep; diffing only the ones with a written-to
		 * page is a handful - measured, 2 of 77 in one powershell.exe.
		 */
		if (w->o.compare_modules &&
		    (w->rg.flags & KOFW_RGF_DIRTY_IMAGE))
			dirty_add(w, w->rg.alloc_base, w->rg.base, w->rg.size);

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

		/*
		 * MAPPING THE ADDRESS SPACE IS A DIFFERENT QUESTION FROM
		 * SCANNING IT, and the set above is the answer to the second
		 * one only.
		 *
		 * A reader who opened a process wants to see what is IN it -
		 * the heap, the stacks, the private data - not just the two
		 * kinds of memory a rule would be run over. awalk.c makes
		 * exactly this distinction on Linux and says why: "every region
		 * with bytes in it is worth a row, not only the ones with no
		 * file behind them... which is what view the memory map means".
		 *
		 * Windows had no such branch, so the viewer opening a process
		 * here got the files behind the mappings and the unbacked
		 * executable spans and NOTHING ELSE - no heap, no stack, no
		 * memory map. The same panel on Linux showed all three.
		 *
		 * The test is "nothing on disk accounts for these bytes", which
		 * is `path` being empty - the Windows counterpart of awalk's
		 * `!rg.inode`. A file-backed region is already offered as a
		 * FILE item, so including it here would list it twice.
		 *
		 * IT COSTS NOTHING ON A SWEEP. A scan asks for KOF_WALK_SCAN
		 * and never reaches this line; only a caller that asked to map
		 * one process pays for it, and that caller has its own time
		 * bound - see PROC_COLLECT_MS in kofviewer.
		 */
		if (w->o.intent == KOF_WALK_MAP && !w->rg.path[0])
			want_it = 1;

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
			w->span_base  = w->rg.alloc_base;
			w->span_first = w->rg.base;
			w->span_end   = w->rg.base + w->rg.size;
			w->span_pe    = (w->rg.flags & KOFW_RGF_PE) != 0;
			w->span_use   = w->rg.use;
			w->span_flags = w->rg.flags;
			w->have_span  = 1;
		} else {
			if (w->rg.base + w->rg.size > w->span_end)
				w->span_end = w->rg.base + w->rg.size;
			w->span_pe |= (w->rg.flags & KOFW_RGF_PE) != 0;
			/* OR-ed, not replaced: see span_flags. `use` stays the
			 * opening run's, which is the allocation's base. */
			w->span_flags |= w->rg.flags;
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
			 * A MODULE SOMEBODY WROTE TO IS COMPARED AGAINST ITS
			 * FILE, and only that module.
			 *
			 * The file is offered below whatever happens, because
			 * the file is what the module mostly IS. What the
			 * comparison adds is the part the file does not have -
			 * the inline hook, the blown-away stub, the hollowed
			 * section - and those bytes exist in no file, so
			 * nothing else in this walk would ever reach them.
			 *
			 * Only for modules the region walk saw a written-to
			 * page in. A module whose pages are all still shared is
			 * byte-identical to its file by construction, so the
			 * comparison could only report nothing at the cost of
			 * reading the file twice.
			 */
			if (w->o.compare_modules)
				diff_dirty_module(w, &md);

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

/*
 * The module comparison's own numbers, which the four in w_stats cannot hold.
 *
 * Empty when the comparison did not run, so a sweep below heur 2 prints no
 * line about a thing it did not do rather than a line of zeroes - a zero there
 * would read as "compared, nothing found".
 */
static size_t w_describe(void *self, char *buf, size_t cap)
{
	struct wwalk *w = self;
	uint32_t held = 0;
	uint64_t asked = 0, parsed = 0;
	int n;

	if (!buf || !cap)
		return 0;
	buf[0] = '\0';
	if (!w || !w->o.compare_modules)
		return 0;

	kofw_diff_cache_stats(w->dcache, &held, &asked, &parsed);
	n = snprintf(buf, cap,
		     "compare: %llu module(s) differ, %llu run(s), %llu byte(s)"
		     ", %llu short; %llu byte(s) the image rewrites itself;"
		     " %llu unreadable; file info %llu asked "
		     "%llu parsed (%u held)",
		     (unsigned long long)w->diff_modules,
		     (unsigned long long)w->diff_runs,
		     (unsigned long long)w->diff_bytes,
		     (unsigned long long)w->diff_small,
		     (unsigned long long)w->diff_dvrt,
		     (unsigned long long)(w->diff_unknown + w->diff_skipped),
		     (unsigned long long)asked, (unsigned long long)parsed,
		     held);
	if (n < 0)
		return 0;
	return (size_t)n < cap ? (size_t)n : cap - 1u;
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
	kofw_diff_cache_close(w->dcache);
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

	/*
	 * ONE PARSE PER DISTINCT FILE FOR THE WHOLE WALK.
	 *
	 * The same thirty or so system DLLs are mapped by every process on the
	 * machine, and what the comparison needs from a file - its section
	 * table, its relocation directory - is the same in all of them.
	 * Measured before this existed: 561 comparisons over 31 distinct files.
	 *
	 * A failure is not fatal. Every comparison then parses for itself,
	 * which is slower and identical in what it concludes.
	 */
	if (w->o.compare_modules)
		w->dcache = kofw_diff_cache_open(0);

	w->api.self      = w;
	w->api.next_proc = w_next_proc;
	w->api.next_item = w_next_item;
	w->api.describe  = w_describe;
	w->api.stats     = w_stats;
	w->api.close     = w_close;

	if (err) *err = 0;
	return &w->api;
}
