/* SPDX-License-Identifier: Apache-2.0 */
/*
 * awalk.c - libkofantarc's answer to libkoforbit/kofwalk/kofwalk.h.
 *
 * THE MEMORY SCAN'S LOGIC LIVES HERE, not in the scanner. A host asks "what is
 * running and what should I look at"; deciding that a file-backed mapping is
 * scanned as its FILE, that an anonymous executable region is scanned as
 * BYTES, and that a kernel mapping is neither - those are answers about
 * /proc, and /proc is this library's subject. The scanner was doing it, which
 * meant the same decisions would have had to be made a second time, slightly
 * differently, for Windows.
 *
 *
 * IT INCLUDES kofproc.h, WHICH IS AN ENGINE-SIDE HEADER, AND THAT IS ALLOWED.
 *
 * The rule at the top of kofantarc.h is that this library collects and does
 * not judge: no kofeng.h, no scanning, no verdict. A RECORD LAYOUT is not a
 * judgement - filling one is the same thing libkofgrille's wtext.c does when
 * it converts its own record into kof_evt, and for the same reason: the layout
 * is the meeting point, and a collector that could not fill it would need
 * somebody else to copy its fields one at a time.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "aproc.h"
#include "kofwalk.h"

struct awalk {
	struct kof_walk_api api;
	struct kof_walk_option o;

	struct kofa_plist *list;
	struct kofa_proc   proc;
	int                have_proc;

	/* The pid list, when there is one, and how far through it we are. */
	uint32_t idx;

	struct kofa_pmem  *mem;
	struct kofa_region rg;
	int                have_rg;

	struct kofa_sweep  sweep;
	uint64_t procs, refused, regions, bytes;
};

/* Fill the engine's record form from what the /proc walk found. The two are
 * different vocabularies for the same facts and this is the only place that
 * knows both. */
static void to_build(const struct kofa_proc *p, struct kof_proc_build *b)
{
	memset(b, 0, sizeof *b);
	b->os = 2;                      /* KOF_PLAT_LINUX */
	b->pid = p->pid;
	b->ppid = p->ppid;
	b->start_time = p->start_time;
	b->n_fd = p->n_fd;
	b->n_socket = p->n_socket;
	b->n_like_stdin = p->n_like_stdin;
	b->plat_a = p->uid;
	b->plat_b = p->gid;
	b->exe = p->exe;
	b->comm = p->comm;
	b->cmdline = p->cmdline;
	b->environ = p->environ;
	b->net = p->net;
	b->fd0 = p->fd_stdin;
	b->fd1 = p->fd_stdout;
	b->fd2 = p->fd_stderr;

	if (p->flags & KOFA_PF_EXE_GONE)
		b->flags |= KOF_PROC_F_EXE_GONE;
	if (p->flags & KOFA_PF_EXE_MEMFD)
		b->flags |= KOF_PROC_F_EXE_MEMFD;
	if (p->fds_read)
		b->flags |= KOF_PROC_F_FDS_READ;
	if (p->is_kthread)
		b->flags |= KOF_PROC_F_KTHREAD;
	if (p->exe_on_disk)
		b->flags |= KOF_PROC_F_EXE_ON_DISK;
}

/* Is this pid one the caller asked for? With no list, every one is. */
static int wanted(const struct awalk *w, uint32_t pid)
{
	uint32_t i;

	if (!w->o.pids || !w->o.n_pids)
		return 1;
	for (i = 0; i < w->o.n_pids; i++)
		if (w->o.pids[i] == pid)
			return 1;
	return 0;
}

static void close_mem(struct awalk *w)
{
	if (w->mem) {
		struct kofa_pmem_stat st;

		kofa_pmem_stats(w->mem, &st);
		w->regions += st.regions_seen;
		w->bytes += st.bytes_read;
		kofa_pmem_close(w->mem);
		w->mem = NULL;
	}
	w->have_rg = 0;
}

static int open_mem_for(struct awalk *w, const struct kofa_proc *p)
{
	struct kofa_pmem_option po;
	int err = 0;

	memset(&po, 0, sizeof po);
	/*
	 * EXECUTABLE ONLY. What a memory scan is looking for is code with no
	 * file behind it; the rest of an address space is the process's own
	 * working data, and see the note on KOFA_MW_HEAP for why searching it
	 * says what a process TOUCHED rather than what it is.
	 */
	/*
	 * THE PURPOSE DECIDES THE SET - see enum kof_walk_intent.
	 *
	 * SCAN: executable only. What a memory scan is looking for is code
	 * with no file behind it; the rest of an address space is the
	 * process's own working data, and see KOFA_MW_HEAP for why searching
	 * it says what a process TOUCHED rather than what it is.
	 *
	 * MAP: the heap as well, and no EXEC_ONLY. Somebody looking at a
	 * process has opened it to read the heap - a decrypted configuration
	 * lives there - and the false positives that keep a SCAN out of it are
	 * not a reason to hide it from a reader.
	 *
	 * KOFA_MW_RESERVED stays off in both. A `---p` reservation cannot be
	 * read and holds nothing, there are 9.1 TB of them on a desktop
	 * running a browser, and an object with no bytes is a row that opens
	 * onto an empty pane.
	 */
	if (w->o.intent == KOF_WALK_MAP) {
		po.want = KOFA_MW_DEFAULT | KOFA_MW_HEAP;
		/*
		 * AND A CEILING, BECAUSE MAP TOOK THE ONE THAT SCAN HAD.
		 *
		 * EXEC_ONLY is what kept the scan path small: a program's
		 * executable memory is megabytes whatever else it is holding.
		 * Dropping it to show the heap drops that bound with it, and
		 * nothing else was set - w->sweep is zeroed, and zero means NO
		 * LIMIT. A process with a gigabyte of heap was therefore read
		 * in full, scanned in full by every module, and then spilled
		 * to a temporary file by the caller keeping it. Three
		 * expensive things, none of them bounded, on a tool that shows
		 * twenty rows at a time.
		 *
		 * 64MB per region matches W_MAX_SPAN in wwalk.c so the two
		 * platforms cut at the same place. 512MB for the process is
		 * the same kind of number: a guard against a pathological
		 * address space, not a budget anybody measured - the header's
		 * own words about the defaults it replaces, and still true.
		 *
		 * What is cut is REPORTED: a region over the ceiling comes
		 * back flagged KOFA_RGF_UNEXAMINED and the sweep counts the
		 * bytes it refused, so a caller can say what it did not look
		 * at instead of implying it looked at everything.
		 */
		po.max_region = 64ull * 1024ull * 1024ull;
		if (!w->sweep.max_bytes)
			w->sweep.max_bytes = 512ull * 1024ull * 1024ull;
	} else {
		po.want = KOFA_MW_DEFAULT | KOFA_MW_EXEC_ONLY;
	}
	po.sweep = &w->sweep;

	w->mem = kofa_pmem_open(p->pid, p->start_time, &po, &err);
	return w->mem != NULL;
}

static int a_next_proc(void *self, struct kof_proc_build *out)
{
	struct awalk *w = self;

	if (!w || !out)
		return 0;
	close_mem(w);
	w->have_proc = 0;

	/*
	 * A PID LIST IS WALKED DIRECTLY, not filtered out of the whole table.
	 * Filtering would open and read /proc for four hundred processes to
	 * reach one, which is exactly the cost the list exists to avoid - see
	 * kof_walk_option.
	 */
	if (w->o.pids && w->o.n_pids) {
		while (w->idx < w->o.n_pids) {
			uint32_t pid = w->o.pids[w->idx++];
			struct kofa_pmem *m;
			int err = 0;

			/* start_time 0: the caller named a pid and means
			 * whatever holds it now - see kofa_pmem_open. */
			/*
			 * THE DETAIL COMES FROM THE LIST, NOT FROM THE MEMORY
			 * HANDLE.
			 *
			 * kofa_pmem_open fills pid, ppid, start_time, comm and
			 * exe - what a MEMORY handle needs - and nothing else.
			 * A caller asking for one pid used to take its whole
			 * process record from there and got one with no
			 * cmdline, no descriptors and no ownership: the fields
			 * a process panel is made of, all absent, with nothing
			 * saying they had not been asked for.
			 *
			 * only_pid reads exactly this entry, so the table is
			 * still not walked - see the note on kof_walk_option.
			 */
			{
				struct kofa_plist_option lo;
				int lerr = 0;
				int got = 0;

				/*
				 * HELD IN w->list, NOT CLOSED HERE.
				 *
				 * kofa_proc's strings - exe, comm, cmdline,
				 * the descriptor links - are BORROWED from the
				 * handle that produced them. Closing it here
				 * and handing w->proc on was the same
				 * use-after-free this file already had once,
				 * reintroduced from the other end: the fields
				 * came back as garbage instead of as nothing,
				 * which is the worse of the two failures.
				 *
				 * One handle per pid, replaced on the way to
				 * the next and closed by a_close.
				 */
				if (w->list) {
					kofa_plist_close(w->list);
					w->list = NULL;
				}
				memset(&lo, 0, sizeof lo);
				lo.only_pid = pid;
				w->list = kofa_plist_open(&lo, &lerr);
				if (w->list)
					got = kofa_plist_next(w->list,
							      &w->proc);
				if (!got) {
					w->refused++;
					continue;
				}
			}
			m = kofa_pmem_open(pid, w->proc.start_time, NULL,
					   &err);
			if (!m) {
				w->refused++;
				continue;
			}
			/*
			 * COPIED OUT, THEN THE SESSION THAT OWNS THE STRINGS
			 * IS REOPENED AND READ AGAIN.
			 *
			 * kofa_proc carries BORROWED pointers - image, cmdline,
			 * the standard descriptors - into the handle that
			 * produced them. This used to copy the struct and then
			 * close that handle, which left every string in
			 * w->proc pointing at freed memory; to_build then
			 * handed them to the record builder. Found by
			 * AddressSanitizer as a heap-use-after-free in
			 * kofproc.c's put(), reached the moment a caller asked
			 * for a pid by name rather than walking the table - so
			 * it was latent in kofscanner --pid and in every
			 * kof_walk_open with a pid list.
			 *
			 * The struct is still copied first, because
			 * open_mem_for needs the pid and start_time out of it;
			 * what is HANDED OUT comes from the session that stays
			 * open.
			 */
			kofa_pmem_close(m);

			if (!open_mem_for(w, &w->proc)) {
				w->refused++;
				continue;
			}
			w->procs++;
			w->have_proc = 1;
			to_build(&w->proc, out);
			return 1;
		}
		return 0;
	}

	while (kofa_plist_next(w->list, &w->proc)) {
		if (w->proc.flags & (KOFA_PF_REFUSED | KOFA_PF_KERNEL)) {
			if (w->proc.flags & KOFA_PF_REFUSED)
				w->refused++;
			continue;
		}
		if (!wanted(w, w->proc.pid))
			continue;
		if (!open_mem_for(w, &w->proc)) {
			w->refused++;
			continue;
		}
		w->procs++;
		w->have_proc = 1;
		to_build(&w->proc, out);
		return 1;
	}
	return 0;
}

/*
 * The word for a region, in this tree's region vocabulary - see
 * kof_walk_item.label. Capitals because a capitalised name means REGION here,
 * and MEM_ because these came from the running process rather than a file.
 */
static const char *a_label(const struct kofa_region *rg)
{
	if (rg->flags & KOFA_RGF_MEMFD)
		return "MEM_MEMFD";
	if (rg->flags & KOFA_RGF_DELETED)
		return "MEM_DELETED";
	switch (rg->use) {
	case KOFA_USE_HEAP:  return "MEM_HEAP";
	case KOFA_USE_STACK: return "MEM_STACK";
	case KOFA_USE_CODE:  return "MEM_CODE";
	case KOFA_USE_DATA:  return "MEM_DATA";
	case KOFA_USE_IMAGE: return "MEM_IMAGE";
	default:             return "MEM_ANON";
	}
}

static int a_next_item(void *self, struct kof_walk_item *out)
{
	struct awalk *w = self;

	if (!w || !out || !w->mem)
		return 0;
	memset(out, 0, sizeof *out);

	for (;;) {
		struct kofa_chunk c;

		/* Still handing out the pieces of the region in hand. */
		if (w->have_rg && kofa_pmem_next_chunk(w->mem, &w->rg, &c)) {
			out->kind = KOF_WALK_BYTES;
			out->addr = c.addr;
			out->p = c.p;
			out->len = c.len;
			out->label = a_label(&w->rg);
			return 1;
		}
		w->have_rg = 0;

		if (!kofa_pmem_next_region(w->mem, &w->rg))
			return 0;

		/*
		 * MAPPING THE ADDRESS SPACE: every region with bytes in it is
		 * worth a row, not only the ones with no file behind them. The
		 * file-backed ones are already offered as FILE items below, so
		 * what this adds is the heap, the stack and the anonymous
		 * mappings - which is what "view the memory map" means.
		 */
		if (w->o.intent == KOF_WALK_MAP && !w->rg.inode) {
			w->have_rg = 1;
			continue;
		}
		if (w->rg.flags & KOFA_RGF_UNBACKED) {
			/* Nothing on disk holds these bytes, so they are read
			 * out of the process - chunk by chunk, skipping pages
			 * that are entirely zero. */
			w->have_rg = 1;
			continue;
		}

		/*
		 * AN INODE IS WHAT MAKES A PATH A FILE. [vdso] has a path and
		 * no inode; treating it as one meant a stat that could never
		 * succeed and an open that could never work, 31 times a sweep
		 * on this machine. See KOFA_RGF_KERNEL_MAPPED.
		 */
		if (w->rg.inode && w->rg.path && w->rg.path[0]) {
			out->kind = KOF_WALK_FILE;
			out->path = w->rg.path;
			return 1;
		}
		/* A region with neither: nothing to scan, and not an error. */
	}
}

static void a_stats(void *self, uint64_t *procs, uint64_t *refused,
		    uint64_t *regions, uint64_t *bytes)
{
	struct awalk *w = self;

	if (!w)
		return;
	if (procs)   *procs = w->procs;
	if (refused) *refused = w->refused;
	if (regions) *regions = w->regions;
	if (bytes)   *bytes = w->bytes;
}

static void a_close(void *self)
{
	struct awalk *w = self;

	if (!w)
		return;
	close_mem(w);
	if (w->list)
		kofa_plist_close(w->list);
	free(w);
}

struct kof_walk_api *kof_walk_open(const struct kof_walk_option *opt, int *err)
{
	struct awalk *w = calloc(1, sizeof *w);
	int e = 0;

	if (!w) {
		if (err) *err = KOFA_ERR_NOMEM;
		return NULL;
	}
	if (opt)
		w->o = *opt;

	/* No process table is opened when the caller named its pids: the whole
	 * point of naming them is not to walk it. */
	if (!w->o.pids || !w->o.n_pids) {
		w->list = kofa_plist_open(NULL, &e);
		if (!w->list) {
			free(w);
			if (err) *err = e;
			return NULL;
		}
	}

	w->api.self      = w;
	w->api.next_proc = a_next_proc;
	w->api.next_item = a_next_item;
	w->api.stats     = a_stats;
	w->api.close     = a_close;

	if (err) *err = KOFA_OK;
	return &w->api;
}
