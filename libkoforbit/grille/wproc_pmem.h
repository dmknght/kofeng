/*
 * wproc_pmem.h - one process, opened: threads, the options, the cache, the handle,
 * modules, regions and reads. *
 * A part of <wproc.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFGRILLE_WPROC_PMEM_H
#define KOFGRILLE_WPROC_PMEM_H

#include <stdint.h>
#include <stddef.h>
#include "kofgrille.h"
#include "wproc_proc.h"
#include "wproc_region.h"

/* --------------------------------------------------- one process, opened */

/* kofw_pmem_option.want */
enum {
	/* Resolve the file behind each mapped region. One kernel query and one
	 * path conversion per named region. */
	KOFW_MW_PATHS     = 1u << 0,

	/* Ask which image pages have gone private - KOFW_RGF_DIRTY_IMAGE. One
	 * query per executable image region, over an array of one entry per
	 * page. */
	KOFW_MW_DIRTY     = 1u << 1,

	/* What kofw_pmem_open gives a caller that passes NULL. */
	KOFW_MW_DEFAULT   = KOFW_MW_PATHS | KOFW_MW_DIRTY,

	/*
	 * ONLY REGIONS THAT CAN EXECUTE.
	 *
	 * Off by default, because "what is in this process" is a different
	 * question from "what could run in it", and only the caller knows
	 * which one it is asking. On, it is the difference between three
	 * thousand regions and forty on a browser, and a scanner looking for
	 * code has no use for the other two thousand nine hundred and sixty.
	 */
	KOFW_MW_EXEC_ONLY = 1u << 2,

	/*
	 * REPORT KOFW_USE_HEAP REGIONS AT ALL. Off by default, and the default
	 * is the one every real-time product on the market ships.
	 *
	 * Not because a payload is never there - it very often is, staged in a
	 * buffer before anything makes it executable - but because of what a
	 * match there would MEAN. Every byte a process has ever read passes
	 * through its writable private memory: an installer holds its own
	 * payload there, a browser holds a download there, and a scanner holds
	 * whatever it was just scanning there. A pattern found in a heap says
	 * the process TOUCHED those bytes, and the process that touched a
	 * payload is very often the one that was handling it legitimately.
	 *
	 * So this is the bit that turns a memory scan from "what is running in
	 * here" into "what has been through here", and those are different
	 * questions with different answers and very different false-positive
	 * rates. The caller says which one it is asking.
	 *
	 * KOFW_MW_EXEC_ONLY excludes these whatever this says: a heap that can
	 * execute is KOFW_USE_CODE and was never a heap by this library's
	 * reading.
	 */
	KOFW_MW_HEAP      = 1u << 3,

	/*
	 * FILL A MODULE'S SIZE AND ENTRY POINT - off by default, and it is the
	 * most expensive thing in a module walk by a wide margin.
	 *
	 * It costs one GetModuleInformation per module, measured at 57
	 * MICROSECONDS each over 4323 modules on this machine - 247ms, which
	 * was a fifth of a whole warm sweep. That is the same order as the
	 * loader path query beside it and is paid for the same reason: it is a
	 * cross-process query into somebody else's loader data.
	 *
	 * AND NOTHING IN THE PRODUCT READ THE RESULT. wwalk.c - the one
	 * consumer of the module walk - uses `flags` and `path` and neither
	 * `size` nor `entry`. The fields were being computed for every module
	 * of every process so that a unit test could pick a module big enough
	 * to be worth mutating.
	 *
	 * `base` IS NOT BEHIND THIS BIT, because it costs nothing: on Windows
	 * an HMODULE IS the base address, and the enumeration already returned
	 * it. Only the size and the entry point need the call.
	 *
	 * This is the rule the top of this header states - every field that
	 * costs a syscall is behind a bit - applied to the one place it had
	 * not been.
	 */
	KOFW_MW_MOD_EXTENT = 1u << 4,

	/*
	 * WHERE EACH THREAD STARTED, and it is the one thing this walk could
	 * not say.
	 *
	 * The walk already finds executable memory that no file backs -
	 * KOFW_RGF_UNBACKED, MEM_CODE, a manual map. What it could not say is
	 * whether anything is RUNNING there, and that is the difference
	 * between an injection and a buffer somebody forgot to free. A process
	 * that decoded a payload into a private page an hour ago and never
	 * jumped to it looks identical, from memory alone, to one executing
	 * out of it right now.
	 *
	 * struct kofw_proc carries `threads` and it is a COUNT - a number from
	 * the toolhelp snapshot, with no thread in it. This bit is what turns
	 * that into addresses.
	 *
	 * IT COSTS AN OpenThread AND AN NtQueryInformationThread PER THREAD,
	 * which is why it is a bit rather than always on: a busy machine has
	 * thousands of threads and most walks do not need one of them. The
	 * event collector sees thread starts live under KOFW_SUB_THREAD and
	 * pays nothing per thread; this is the point-in-time answer for a host
	 * where no sensor was running.
	 */
	KOFW_MW_THREADS    = 1u << 5
};

/*
 * ONE THREAD, AND ONLY WHAT SAYS WHERE IT CAME FROM.
 *
 * No priority, no state, no times: this exists to be correlated against the
 * region table, so it carries the address that correlation is on and the id a
 * reader needs to go and look for themselves.
 */
struct kofw_thread {
	uint32_t tid;
	uint32_t flags;        /* KOFW_TF_* */
	/*
	 * Win32StartAddress - where the thread was told to begin.
	 *
	 * NOT the current instruction pointer, and the difference matters both
	 * ways. A thread that started in a loaded module and was then hijacked
	 * still reports that module here; a thread created to run a payload
	 * reports the payload even after it has moved on. This is the CREATION
	 * fact, which is the one that survives.
	 *
	 * Zero when the query was refused - a protected process, or a thread
	 * that exited between the snapshot and the open. Zero is not an
	 * address and a caller must not correlate on it.
	 */
	uint64_t start;
};

enum {
	/*
	 * The start address is in no module the loader lists - so the thread
	 * began somewhere that is not a mapped image. Set by whoever has the
	 * module table to compare against, not by the enumeration.
	 */
	KOFW_TF_UNBACKED_START = 1u << 0
};

/*
 * How many threads a correlating walk keeps per process.
 *
 * A FILTER, NOT AN INVENTORY. The question asked of this table is "did any
 * thread start inside this region", and a process with more than this many
 * threads has more than any injection needs. Threads past the cap are not
 * correlated, which loses a signal and never invents one.
 */
#define KOFW_MAX_THREADS 256u

struct kofw_pmem_option {
	/* A mask of KOFW_MW_*. Zero takes KOFW_MW_DEFAULT. */
	uint32_t want;

	/*
	 * Regions bigger than this are REPORTED AND NOT EXAMINED - they come
	 * back with KOFW_RGF_UNEXAMINED and without the flags that need their
	 * contents read.
	 *
	 * It exists because a single committed region can be gigabytes: a
	 * database's buffer pool, a .NET GC heap, a VM's guest memory. Reading
	 * a header out of one is free; asking the working-set query about one
	 * is an array of a quarter of a million entries. 0 takes the default,
	 * which is stated in the .c beside the reasoning.
	 *
	 * It does NOT limit kofw_pmem_read, which does exactly what it is
	 * asked.
	 */
	uint64_t max_region;

	/*
	 * THE ANSWERS THAT ARE THE MACHINE'S, NOT THIS PROCESS'S - shared by
	 * every process in one sweep, or NULL to let each one work them out
	 * again. See kofw_pcache below. Optional: a NULL here changes nothing
	 * but the time.
	 */
	struct kofw_pcache *cache;
};

/*
 * WHAT EVERY PROCESS IN A SWEEP ASKS AND GETS THE SAME ANSWER TO.
 *
 * Two questions in a module walk do not depend on which process is being
 * walked, and both were being asked once per process - or once per MODULE -
 * for an answer that could not differ:
 *
 *   - the device-to-drive-letter map, rebuilt from 26 QueryDosDeviceW calls
 *     in every process opened. Measured: 83 processes, 2158 calls, for one
 *     table that describes the machine. Those calls are 1.1us each, so this
 *     half is worth about 2ms and is here because the map had to be shared
 *     for the other half to have somewhere to live - not because it was
 *     costing anything.
 *
 *   - does the file behind this module still exist. 4696 modules are 660
 *     distinct paths, because a system DLL is mapped into most of them: 7.1 of
 *     every 8 calls asked a question that had already been answered, to find
 *     the three modules whose file was gone.
 *
 *     WORTH 40ms OF A 700ms SWEEP, AND THE ISOLATED FIGURE SAYS 230ms. Both
 *     numbers are real and the difference is the point: GetFileAttributesW
 *     measures at 48 MICROSECONDS in a loop that calls it on 4696 paths, but
 *     Windows caches attribute lookups itself, so most of what this skips was
 *     already cheap. 6% for a 32KB table is worth having and it is not the
 *     order of magnitude the per-call cost suggests - which is why the end to
 *     end A/B is the number written down here.
 *
 * OWNED BY THE CALLER AND PASSED IN, not a static in this file. A sweep opens
 * one, hands it to every kofw_pmem_open, and closes it: the lifetime is
 * visible, the memory is the caller's, and two sweeps running at once do not
 * share a table. Its size is fixed and small; when the path table fills it
 * stops memoising and the queries go through, which is slower and never wrong.
 *
 * NOT A VERDICT CACHE. Nothing here survives the sweep - see koffridge.h for
 * the one that does, and for why that one is keyed on a file's identity and
 * stamped with the database it was decided under.
 */
struct kofw_pcache;

struct kofw_pcache *kofw_pcache_open(void);
void kofw_pcache_close(struct kofw_pcache *);

struct kofw_pmem;

/*
 * Open one process for inspection. NULL on failure, and *err is a KOFW_ERR_*.
 * `err` may be NULL.
 *
 * `create_time` is the value kofw_plist_next or an event reported, and it is
 * CHECKED: if the pid now belongs to a different process the open fails with
 * KOFW_ERR_GONE rather than succeeding against the wrong one. Pass 0 only when
 * there is genuinely no discriminator to be had - it means "whatever holds this
 * number now", which is a decision and should look like one at the call site.
 *
 * Needs PROCESS_QUERY_INFORMATION and PROCESS_VM_READ, so in practice it needs
 * elevation for anything outside the caller's own session, and it is refused
 * outright for a protected process however elevated the caller is.
 */
struct kofw_pmem *kofw_pmem_open(uint32_t pid, uint64_t create_time,
				 const struct kofw_pmem_option *, int *err);

/*
 * Who it opened, filled in as far as the handle allowed. Never NULL, and its
 * strings live as long as the handle rather than until the next call.
 *
 * The way to ask about ONE process without enumerating every one of them.
 */
const struct kofw_proc *kofw_pmem_proc(const struct kofw_pmem *);

/*
 * The next mapped module. 1 if one was filled in, 0 at the end.
 *
 * THE LOADER'S OWN LIST, which means it is exactly as honest as the loader. A
 * module unlinked from the PEB list by whoever loaded it - two stores, and the
 * oldest trick in the file - is not here, and the region walk is where it still
 * shows up. The two are worth running together for that reason, and not because
 * either is incomplete on its own.
 *
 *
 * HOW A MODULE LINES UP WITH ITS REGIONS, since a caller needs both walks.
 *
 * An image region's `alloc_base` IS the module's `base`. One module is several
 * regions - the header read-only, the code RX, the data RW - and that field is
 * what joins them back up, exactly as it does for a hand-laid-out allocation.
 *
 *
 * WHY MOST MODULE MEMORY IS NOT WORTH SCANNING, which is the thing that decides
 * what a caller does with this walk.
 *
 * A module's pages are shared with every other process that mapped the same
 * file, and they are shared BECAUSE they are identical to it. Scanning them
 * finds what scanning the file would have found, on a machine where two hundred
 * processes have mapped the same forty DLLs - so the work is repeated hundreds
 * of times to reach an answer that was already available from one file read.
 *
 * The exception is the whole point: a page that has STOPPED being shared is one
 * somebody wrote, and it is the only part of a module that differs from its
 * file. KOFW_RGF_DIRTY_IMAGE marks the regions where that has happened.
 *
 * So the two halves are scanned differently and only one of them is cacheable:
 *
 *   clean module   scan the FILE, and remember the answer against the file's
 *                  identity - not its path, which is chosen by whoever put it
 *                  there and stays the same when the file behind it does not.
 *   dirty region   scan the MEMORY, because that is where the difference is.
 *                  Nothing to cache: this copy exists in one process only,
 *                  which is also why there is so little of it.
 */
int kofw_pmem_next_module(struct kofw_pmem *, struct kofw_module *out);

/*
 * ONE MODULE'S SizeOfImage, for a caller that needs it after deciding it cares.
 *
 * Zero when it could not be asked. The walk leaves kofw_module.size zero unless
 * KOFW_MW_MOD_EXTENT was set - see that bit for why - so this is how the few
 * callers that genuinely need an extent get one without every module on the
 * machine paying a cross-process query for it.
 */
uint64_t kofw_pmem_module_size(struct kofw_pmem *, uint64_t base);

/*
 * The process's threads, one call. Returns how many were written, at most
 * `max`; zero when KOFW_MW_THREADS was not asked for, when the snapshot could
 * not be taken, or when the process has none left.
 *
 * ALL AT ONCE RATHER THAN AN ITERATOR, because the source is one toolhelp
 * snapshot of EVERY thread on the machine and the walk has to filter it by
 * owning pid. Handing that back a thread at a time would mean holding the
 * snapshot open across the caller's work or retaking it per thread, and the
 * table this fills is tens of entries for a normal process.
 *
 * `flags` comes back zero: KOFW_TF_UNBACKED_START is for whoever holds the
 * module table to set, and this call deliberately does not - see the note on
 * that flag.
 *
 * A kofw_pcache IS REQUIRED, and without one this returns zero rather than
 * working slowly. The thread snapshot is machine-wide - Windows has no
 * per-process form of it - so a session with nowhere to keep it would take one
 * per process and walk every thread on the machine each time. Measured: 23ms
 * for one snapshot, 2495ms for a hundred. Nothing about that is worth doing
 * silently, so it is not done at all.
 */
uint32_t kofw_pmem_threads(struct kofw_pmem *, struct kofw_thread *out,
			   uint32_t max);

/*
 * The next committed region. 1 if one was filled in, 0 at the end.
 *
 * COMMITTED ONLY: reserved and free address space is not reported, because
 * there is nothing in it. A 64-bit process reserves terabytes it has never
 * touched, and reporting those would make the walk about the address space
 * rather than about the memory.
 *
 *
 * HOW `use` IS DECIDED, SAID IN FULL, BECAUSE IT IS WHAT A RULE WILL REST ON
 *
 * Four of the six come straight from what the kernel already said, and are as
 * reliable as the kernel is:
 *
 *   IMAGE   Type is MEM_IMAGE.
 *   CODE    the protection allows execution and no file backs it.
 *   DATA    committed, not executable, and something does back it.
 *   UNKNOWN nothing committed here.
 *
 * The other two are told apart by ONE THING - a PAGE_GUARD run immediately
 * below, inside the same allocation, which is how Windows makes a stack grow
 * and is not something a heap has. A private writable allocation with that
 * beneath it is STACK; a private writable allocation without it is HEAP.
 *
 * WHAT THAT TEST CANNOT DO, and it is worth knowing before writing a rule that
 * assumes otherwise:
 *
 *   - A stack whose guard page has already been consumed - a thread that ran
 *     itself close to the end - looks like a heap.
 *   - A fibre's stack, or a stack somebody allocated by hand, has no guard
 *     page and is a heap by this test.
 *   - Nothing stops a program allocating a guard page under a buffer.
 *
 * The alternative is reading every thread's own record of where its stack is,
 * which is exact and needs a structure Windows does not document the layout
 * of. That is a refinement worth having and it is not a foundation worth
 * standing on: whoever is being looked for here can edit those structures, and
 * a walk that DEPENDED on them would report nothing at all about a process
 * that had messed with them - which is the worst possible failure for this
 * particular walk. So the guard-page test decides `use`, from what the memory
 * manager itself reports, and anything read out of the process's own
 * bookkeeping can only ever ADD to what is already there.
 */
int kofw_pmem_next_region(struct kofw_pmem *, struct kofw_region *out);

/*
 * Read from the process. Returns bytes read, which is 0 or short whenever the
 * process refuses, exits, or has an unreadable page in the way.
 *
 * SHORT RATHER THAN FAILED, deliberately. A region with a guard page in the
 * middle of it is normal - every thread stack has one - and a read that
 * returned nothing because the last page of forty refused would throw away the
 * thirty-nine that are the point. So it reads page by page and stops at the
 * first refusal, and the caller scans what came back and knows how much that
 * was.
 *
 * The bytes are a COPY OF A MOVING TARGET. The process keeps running while this
 * reads, so a large read can return a first page from before some write and a
 * last page from after it. That is inherent - there is no way to suspend a
 * process from here that is not worse - and it matters for exactly one thing: a
 * scan of live memory that finds nothing has not proved anything was not there.
 */
size_t kofw_pmem_read(struct kofw_pmem *, uint64_t addr, void *buf, size_t n);

void kofw_pmem_close(struct kofw_pmem *);

#endif /* KOFGRILLE_WPROC_PMEM_H */
