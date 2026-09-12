/* SPDX-License-Identifier: Apache-2.0 */
/*
 * aproc.h - what is running right now on Linux, and what is inside it.
 *
 * THE SNAPSHOT HALF, AND IT LOOKS THE OPPOSITE WAY FROM A STREAM.
 *
 * A collector sees things that happen, in the order they happen, from the
 * moment it opened. That has one property it can never fix - it cannot see
 * backwards. A machine compromised on Tuesday with a sensor installed on
 * Thursday produces a perfectly clean stream, because everything that mattered
 * happened before anything was watching, and the payload that is still
 * resident has not raised an event since.
 *
 * This answers "what is here" instead. Every process that exists at this
 * instant, every region of its address space, and the bytes in any of them.
 *
 * Shape:
 *
 *	struct kofa_plist *l = kofa_plist_open(NULL, &err);
 *	struct kofa_proc   p;
 *
 *	while (kofa_plist_next(l, &p)) {
 *		struct kofa_pmem  *m = kofa_pmem_open(p.pid, p.start_time,
 *						      NULL, &err);
 *		struct kofa_region r;
 *
 *		if (!m)
 *			continue;
 *		while (kofa_pmem_next_region(m, &r))
 *			if (r.flags & KOFA_RGF_UNBACKED)
 *				... kofa_pmem_read(m, r.base, buf, n) ...
 *		kofa_pmem_close(m);
 *	}
 *	kofa_plist_close(l);
 *
 *
 * STILL NO JUDGING, and this is the file where it is tempting to break.
 *
 * "Anonymous, executable, and an ELF header in it" is three facts away from a
 * verdict, and a library that shipped the verdict would be one nobody can
 * tune, test against a corpus, or disagree with. So every flag below is
 * something that is TRUE of a region, never something that is WRONG with it.
 *
 * The measured example, on the machine this was written on: SEVEN anonymous
 * rwxp regions of 512 MB each, in seven different processes. Every one of them
 * is V8 - Electron, VS Code, node. An rwx region is not a finding on Linux and
 * anything that treats it as one will spend its life explaining itself.
 *
 *
 * ================================================================
 * THE MEASUREMENTS THIS FILE IS BUILT ON
 * ================================================================
 *
 * Taken 2026-09-12 on the development machine as an ordinary user: 34 readable
 * processes, 10182 VMAs. Running as root reaches roughly ten times as many
 * processes, but the SHAPE below does not change, and the shape is what the
 * design rests on.
 *
 *	region class               VMAs      virtual     RESIDENT
 *	-------------------------------------------------------------
 *	exec, file-backed          1076      2736 MB     scanned as FILES
 *	exec, ANONYMOUS              43      3777 MB     ~12 MB
 *	rw anonymous (heap)        2478     19346 MB     1867 MB
 *	mappings marked (deleted)    94
 *	memfd mappings                8
 *
 * READ THAT SECOND ROW AGAIN. The set this library exists to find - code with
 * no file behind it - looks like 3777 MB and IS 12 MB. The difference is not
 * an optimisation opportunity, it is the difference between a sweep that
 * finishes and one that does not.
 *
 * Where the lie comes from, measured on five real processes:
 *
 *	pid 748  code    512.0 MB virtual ->  4.76 MB resident (0.93%), 11 runs
 *	pid 575  code    512.0 MB virtual ->  0.15 MB resident (0.03%), 13 runs
 *	pid 383  code    512.0 MB virtual ->  1.92 MB resident (0.38%),  2 runs
 *	pid  22  code    512.0 MB virtual ->  3.52 MB resident (0.69%),  5 runs
 *	pid 660  claude   64.0 MB virtual ->  1.61 MB resident (2.51%), 30 runs
 *
 * A VMA is a RESERVATION. Windows distinguishes reserved from committed and
 * VirtualQuery reports which; Linux does not, and /proc/<pid>/maps reports the
 * reservation with no hint of how much of it exists. Anything that sizes its
 * work from maps alone is sizing it from a number two orders of magnitude too
 * big.
 *
 *
 * SO THE WALK IS GUIDED BY /proc/<pid>/pagemap, and here is what that buys:
 *
 *	pid 748: pagemap 0.4 ms | blind readv 80.7 ms | guided 0.5 ms -> 148x
 *	pid 575: pagemap 0.5 ms | blind readv 80.8 ms | guided 0.1 ms -> 887x
 *	pid 383: pagemap 0.5 ms | blind readv 81.1 ms | guided 0.3 ms -> 308x
 *	pid  22: pagemap 0.5 ms | blind readv 78.8 ms | guided 0.7 ms -> 120x
 *	pid 660: pagemap 0.1 ms | blind readv  8.5 ms | guided 0.2 ms ->  37x
 *
 * Eight bytes per page buys the right to skip the other 4088. A 512 MB region
 * costs a 1 MB pagemap read and yields between 2 and 13 contiguous runs, so
 * the number of process_vm_readv calls is small as well as the number of bytes.
 *
 * Three things were verified with purpose-built programs rather than assumed,
 * because each would have been a silent wrong answer:
 *
 *   - /proc/<pid>/pagemap IS readable as an ordinary user for one's own
 *     processes, and bit 63 (PRESENT) is correct. Without CAP_SYS_ADMIN the
 *     PFN field reads as zero, which does not matter: nothing here wants the
 *     PFN.
 *
 *   - A BLIND READ DESTROYS THE SIGNAL THAT MAKES THE FAST PATH POSSIBLE, and
 *     this was measured the wrong way round first, so the wrong conclusion is
 *     recorded here beside the right one.
 *
 *     What was measured first: a child mapped 64 MB, touched four pages, and
 *     had all 64 MB read out of it with process_vm_readv; its RSS was 2908 KB
 *     before and 2908 KB after. The conclusion drawn was "reading does not
 *     perturb the target", and it is HALF TRUE in the way that matters least.
 *
 *     What was measured after the region walk started disagreeing with smaps:
 *     the same child, counting PRESENT pages in its pagemap rather than its
 *     RSS.
 *
 *         after the child wrote 4 pages : 512 present, RSS 2996 KB
 *         after 64 MB was read from it  : 16384 present, RSS 2996 KB
 *
 *     Every page became present and not one byte became resident. A READ fault
 *     on an untouched anonymous page maps THE SHARED ZERO PAGE: the PTE is
 *     installed, so pagemap reports the page present forever after, and the
 *     zero page is not charged to anyone, so RSS does not move.
 *
 *     Three consequences, and the third is the one that bites:
 *
 *       a) PRESENT DOES NOT MEAN "HAS CONTENT". It means a PTE exists, and
 *          for an anonymous page that PTE may point at 4096 shared zeroes.
 *
 *       b) So `rss` cannot come from pagemap alone. It comes from smaps, whose
 *          Rss excludes the zero page - see KOFA_MW_SMAPS. pagemap says WHERE
 *          content can be; smaps says HOW MUCH there is. Neither answers the
 *          other's question.
 *
 *       c) A SCANNER THAT READS BLIND ONCE POISONS EVERY LATER SCAN, its own
 *          and every other tool's, because the page tables it populated stay
 *          populated. This is not a theory: three of the five V8 processes
 *          measured at the top of this file came back 100% present on the
 *          second day, and the thing that had read them was the benchmark
 *          written to prove blind reads were merely slow.
 *
 *     Which is why KOFA_MW_PAGEMAP is on by default and the option to turn it
 *     off is documented as DESTRUCTIVE rather than merely slow.
 *
 *   - TRANSPARENT HUGE PAGES MAKE pagemap AN UPPER BOUND, not an exact
 *     answer. Measured: a child touched 100 scattered pages across 512 MB and
 *     came back with 205 MB resident and AnonHugePages: 204800 kB - the
 *     granularity is 2 MB, not 4 KB. On real processes, whose allocations are
 *     not scattered on purpose, the overshoot is small; the five rows above
 *     are real processes. But a caller must read `rss` below as "no more than
 *     this", and nothing here may treat it as a byte count.
 *
 * ================================================================
 *
 *
 * WHAT LINUX CANNOT ANSWER THAT WINDOWS CAN, said here rather than papered
 * over. These are the reasons this is not a port of wproc.h.
 *
 *   - NO KERNEL ACCOUNT OF WHAT A REGION IS. Windows records MEM_PRIVATE,
 *     MEM_MAPPED and MEM_IMAGE, and wproc.h keeps that as `kind` SEPARATELY
 *     from its own reading in `use`, so that a classification which can be
 *     wrong sits beside the fact it was derived from. Linux records only
 *     whether a file is behind the mapping. There is therefore NO `kind` field
 *     here. It was not renamed or approximated - a field that claims the
 *     kernel's authority for this library's guess is worse than no field.
 *
 *   - RESERVED VERSUS COMMITTED EXISTS AFTER ALL, AND IT IS SPELT PROT_NONE.
 *     Windows says MEM_RESERVE outright. Linux says it by mapping a range with
 *     no permissions at all, and the first walk written against this file
 *     found out how much of it there is the hard way: SEVEN regions of
 *     roughly 1.3 TB each, one per Chromium process, `---p`, 9.1 TB of
 *     address space in total on an ordinary desktop. A walk that sums region
 *     sizes without excluding them reports ten terabytes of memory on a
 *     machine with sixteen gigabytes, and a walk that reads their pagemap asks
 *     for 2.7 GB of entries describing pages that cannot exist.
 *
 *     So a region with no access at all is KOFA_USE_UNKNOWN and is filtered
 *     out by default. It holds nothing, it cannot be read, and it is not a
 *     place anything can hide.
 *
 *   - NO ALLOCATION GROUPING. Windows gives every region an AllocationBase, so
 *     the four runs of one hand-mapped DLL group back into one thing. Linux
 *     has no such concept: a VMA is what mmap made and nothing records that
 *     three adjacent VMAs were one request. Runs are grouped here by adjacency
 *     and by backing file, in the .c, and that is a heuristic - so a caller
 *     that reports per-region will report one payload two or three times
 *     unless it groups by `group_id` below.
 *
 *   - A PROCESS IS NAMED BY (pid, start_time), NOT BY pid. Same argument
 *     wproc.h makes with create_time and a stronger one here: pid_max is 4194304
 *     by default but the numbers are handed out sequentially from a small
 *     space and wrap in minutes on a busy machine. Every call below that takes
 *     a pid takes the pair, and checks it.
 */

#ifndef KOFANTARC_APROC_H
#define KOFANTARC_APROC_H

#include <stdint.h>
#include <stddef.h>

#include "kofantarc.h"

/*
 * The longest /proc/<pid>/fd link this walk keeps. A socket link is about
 * twenty bytes and a path can be any length; 256 holds every real one and
 * bounds the plist handle, which carries three of them.
 */
#define KOFA_FDLINK_MAX 256u

/* ---------------------------------------------------------------- a process */

/* kofa_proc.flags */
enum {
	/*
	 * /proc/<pid>/maps could not be opened. The process is still listed,
	 * carrying this, for the reason wproc.h states about protected
	 * processes: a caller must be able to tell "clean" from
	 * "never looked at". hidepid=2 and another user's processes both land
	 * here.
	 */
	KOFA_PF_REFUSED = 1u << 0,

	/*
	 * A KERNEL THREAD. No address space at all: /proc/<pid>/maps is empty
	 * and there is nothing to scan. Recognised by an empty exe link plus
	 * no maps, and skipped by default - see kofa_plist_option.want_kernel.
	 */
	KOFA_PF_KERNEL  = 1u << 1,

	/*
	 * THE EXECUTABLE LINK ENDED IN " (deleted)".
	 *
	 * A FACT READ OFF THE LINK, not a judgement about it. Every package
	 * upgrade leaves every still-running process in this state, and a
	 * desktop has dozens at any moment; a dropper that unlinked itself is
	 * in it too. Which of the two this is, is a question for a rule - see
	 * `exe_on_disk` for the other half of it.
	 */
	KOFA_PF_EXE_GONE = 1u << 2,

	/*
	 * THE EXECUTABLE LINK NAMED A memfd.
	 *
	 * Also read off the link: "/memfd:<name>". memfd_create(2) gives an
	 * anonymous file that lives only in memory, so a program run from one
	 * was never on any filesystem. Kept separate from EXE_GONE because a
	 * memfd never had a file and the "(deleted)" the kernel appends to it
	 * does not mean what it means anywhere else.
	 */
	KOFA_PF_EXE_MEMFD = 1u << 3
};

struct kofa_proc {
	uint32_t pid;
	uint32_t ppid;

	/*
	 * WHAT MAKES THE pid MEAN SOMETHING: field 22 of /proc/<pid>/stat,
	 * in clock ticks since boot.
	 *
	 * Not a wall clock and deliberately not converted into one. Its whole
	 * job is to be compared against itself - "is the process holding pid
	 * 1234 now the same one I listed a moment ago" - and a conversion that
	 * goes through boot time and USER_HZ introduces rounding into the one
	 * comparison that has to be exact.
	 */
	uint64_t start_time;

	uint32_t uid;
	uint32_t gid;
	uint32_t flags;        /* KOFA_PF_* */

	/*
	 * Borrowed, valid until the next call on this handle. Never NULL;
	 * "" when it could not be read.
	 *
	 * `comm` is the kernel's 15-character name, which is what shows in ps
	 * and what a caller recognises. `exe` is the resolved target of
	 * /proc/<pid>/exe with any " (deleted)" suffix REMOVED - the suffix is
	 * reported in flags instead, because a path that ends in " (deleted)"
	 * is not a path anything can open, and every caller would otherwise
	 * strip it separately and disagree about how.
	 */
	const char *comm;
	const char *exe;

	/*
	 * THE COMMAND LINE, with the NULs that separate its arguments turned
	 * into spaces. Borrowed, "" when it could not be read.
	 *
	 * WHY IT IS WORTH READING HERE AND NOT LATER. /proc/<pid>/cmdline is
	 * only readable while the process exists, and the processes worth
	 * reading are the ones that do not last. kofw_evt carries the same
	 * field and had to go to the new process's PEB to get it, with a race
	 * it flags - see KOFW_EF_CMDLINE_RACED. A snapshot walk has no race
	 * because it is not chasing a notification, but it has the same
	 * deadline: the answer is gone when the process is.
	 *
	 * It earns its cost the same way it does on Windows: "bash started" is
	 * not a fact anybody can act on, and `bash -c 'exec 5<>/dev/tcp/...'`
	 * is the whole event. Every living-off-the-land technique looks
	 * identical without this field.
	 *
	 * THE NULs ARE REPLACED AND THAT LOSES SOMETHING. Argument boundaries
	 * are real - an argument containing a space is indistinguishable from
	 * two arguments once this is done - and a caller that needs them back
	 * has to read the file itself. Done anyway because every consumer here
	 * wants one string to print or match against, and each doing the
	 * conversion privately is four chances to disagree about the trailing
	 * NUL. Needs kofa_plist_option.want_cmdline.
	 */
	const char *cmdline;

	/*
	 * THE ENVIRONMENT, NULs turned into spaces exactly like the command
	 * line above, and "" when it could not be read.
	 *
	 * WORTH READING FOR THE SAME REASON THE COMMAND LINE IS, and one more.
	 * It is attacker-controlled text that travels with the process, so the
	 * same searching applies - LD_PRELOAD naming a path nobody shipped, a
	 * payload somebody passed in a variable to keep it off the command
	 * line, credentials a dropper left behind.
	 *
	 * IT IS A SNAPSHOT OF THE INITIAL environ AND NOT THE LIVE ONE. The
	 * kernel exposes the block the process was STARTED with; a program
	 * that calls setenv afterwards changes its own copy and not this. That
	 * is a limit worth stating rather than a failure: what it shows is how
	 * the process was launched, which is the half an analyst is asking
	 * about.
	 *
	 * READABLE ONLY BY SOMEBODY WHO COULD PTRACE IT - same permission as
	 * the command line, so on another user's process this is "" and the
	 * flag below says which.
	 */
	const char *environ;
	/*
	 * ITS LENGTH, BECAUSE THE PIECES ARE SEPARATED BY NUL.
	 *
	 * The command line beside it has its NULs turned into spaces and is
	 * read as one string; this one keeps them, because a value may contain
	 * a space and there is no character that may not, so anything else
	 * loses a boundary. strlen therefore names the FIRST assignment and
	 * not the block - this is how long the block is. 0 when there is none.
	 */
	uint32_t    environ_len;

	/*
	 * THE PROCESS'S OWN CONNECTIONS, one per line:
	 *
	 *     TCP 10.0.0.5:54321 -> 93.184.216.34:443 ESTABLISHED
	 *
	 * "" when there are none, when the descriptors could not be read, or
	 * when the tables were not asked for.
	 *
	 * READ THROUGH /proc/<pid>/net, which is that process's NETWORK
	 * NAMESPACE. Joining against the host's /proc/net instead matches
	 * nothing for a process in a container - or matches an unrelated
	 * socket that happens to share an inode number, which is worse.
	 */
	const char *net;

	/*
	 * WHAT ITS FILE DESCRIPTORS ARE, counted rather than listed.
	 *
	 * `n_fd` is how many it has open; `n_socket` how many of those are
	 * sockets; `n_like_stdin` how many point at the same object as fd 0.
	 *
	 * THE THIRD IS THE ONE A RULE CANNOT COMPUTE FOR ITSELF. A caller sees
	 * three link strings below and could compare those, but it cannot see
	 * fd 7 or fd 255 - and whether anything BEYOND stdio points at the same
	 * object is exactly what separates a shell holding one connection from
	 * a program holding a working set. Counting it costs nothing here,
	 * because the descriptor walk is already running to produce n_fd.
	 *
	 * All zero when the walk did not ask or was refused. A count of zero
	 * and a question nobody asked look the same, so a rule that cares
	 * checks `fds_read`.
	 *
	 * Needs kofa_plist_option.no_fds unset.
	 */
	uint32_t n_fd;
	uint32_t n_socket;
	uint32_t n_like_stdin;

	/* The descriptor walk ran and its answers are meaningful. */
	uint8_t fds_read;

	/*
	 * THE EXECUTABLE PATH RESOLVES ON THE FILESYSTEM RIGHT NOW.
	 *
	 * Only meaningful with KOFA_PF_EXE_GONE: together they say the file
	 * was unlinked and nothing has taken its place, which is the shape of
	 * a program that deleted itself rather than of a package upgrade. Two
	 * facts, reported separately, because joining them is a rule's job.
	 *
	 * Costs one access() and only for a process whose link said
	 * "(deleted)", so it is a handful per sweep.
	 */
	uint8_t exe_on_disk;

	/*
	 * THE KERNEL SAYS THIS IS A KERNEL THREAD: PF_KTHREAD, field 9 of
	 * /proc/<pid>/stat.
	 *
	 * The kernel's own bit and never the name. That is what makes the
	 * disagreement between the two observable at all - a process may call
	 * itself "[kworker/0:2]" and this still says what it is - and it is
	 * why this walk has never classified from the name.
	 */
	uint8_t is_kthread;

	uint8_t _pad;

	/*
	 * WHAT stdin, stdout AND stderr POINT AT, verbatim as the kernel
	 * spells it: "socket:[14899490]", "/dev/pts/3", "pipe:[123]",
	 * "/dev/null", or a path. Borrowed, "" when the link could not be read.
	 *
	 * The raw strings, because a flag is a decision that can be wrong and
	 * the text is the only thing that lets anybody check it - or ask a
	 * question this library did not think of. Comparing two of them for
	 * equality is how a rule asks whether one object is on both ends.
	 */
	const char *fd_stdin;
	const char *fd_stdout;
	const char *fd_stderr;
};

struct kofa_plist_option {
	/* List kernel threads too. Off by default: they have no address space,
	 * so a memory scan has nothing to do with them, and they are about
	 * half the process table. */
	int want_kernel;

	/* Report processes whose /proc entry could not be read, carrying
	 * KOFA_PF_REFUSED. ON by default - see the flag. */
	int want_refused;

	/*
	 * Read /proc/<pid>/cmdline. ON by default: one open and one read per
	 * process, for the field without which the process rows say nothing.
	 */
	int no_cmdline;

	/*
	 * Look at /proc/<pid>/fd. ON by default.
	 *
	 * Three readlinks for stdin, stdout and stderr - which is what
	 * KOFA_PF_STDIO_SOCKET needs - plus one readdir to count the rest.
	 * The readdir is what makes this cost scale with a process's fd table
	 * rather than being constant, so it is the half worth turning off on a
	 * machine full of busy daemons.
	 *
	 * NEGATIVE SENSE, like no_cmdline above, so that a zeroed option
	 * struct asks for everything. A caller that fills this struct field by
	 * field and forgets one should get MORE information than it expected
	 * and never less: the opposite default hides facts from whoever did
	 * not know to ask, which is exactly who needs them.
	 */
	/*
	 * Read /proc/<pid>/environ. ON by default, negative sense like the two
	 * above, for the reason stated there: a caller who did not know to ask
	 * should get more and never less.
	 */
	int no_environ;

	/*
	 * Join the descriptor list against /proc/<pid>/net. ON by default,
	 * negative sense like the rest.
	 *
	 * The cost is four sequential reads of that process's namespace
	 * tables and a linear probe per row - NOT a read per socket, which is
	 * the quadratic version of the same join. It rides on the descriptor
	 * walk, so turning off no_fds turns this off with it: there are no
	 * inodes to join on.
	 */
	int no_net;

	int no_fds;

	/*
	 * JUST THIS PROCESS, and nothing else. 0 walks every one of them.
	 *
	 * WHY IT IS HERE AND NOT LEFT TO THE CALLER FILTERING. A caller that
	 * wants one pid is answering "something already decided this process
	 * is interesting" - an event arrived, an operator asked - and walking
	 * four hundred entries to reach one is the whole cost of a sweep paid
	 * for nothing. It is also what kofw_plist_option has had all along,
	 * so the two collectors now answer the same question the same way.
	 *
	 * THE POINT IS THE DETAIL, NOT THE SPEED. kofa_pmem_open fills a
	 * kofa_proc with pid, ppid, start_time, comm and exe, because that is
	 * all a MEMORY handle needs - no cmdline, no descriptors, no uid. A
	 * caller that asked for one pid through pmem therefore got a process
	 * record with the interesting half missing, which is what a process
	 * panel drawn from it looked like.
	 */
	uint32_t only_pid;
};

struct kofa_plist;

/*
 * Open a walk of /proc. NULL on failure with *err set.
 *
 * `opt` NULL takes the defaults above.
 */
struct kofa_plist *kofa_plist_open(const struct kofa_plist_option *opt,
				   int *err);

/*
 * Next process, 1 on success and 0 at the end.
 *
 * Strings in *out are borrowed from the handle and are replaced by the next
 * call. A process that exits between being listed and being read is skipped
 * silently: that is not an error, it is what a process table does.
 */
int kofa_plist_next(struct kofa_plist *, struct kofa_proc *out);

void kofa_plist_close(struct kofa_plist *);

/* ----------------------------------------------------------------- a region */

/*
 * WHAT THE MEMORY IS FOR - this library's reading, and it is the only
 * classification here because Linux offers no second opinion. See the top of
 * this file on why there is no `kind`.
 *
 * NOT A REGION VOCABULARY FOR THE ENGINE, and the difference matters. There is
 * no memory format: a region carrying an ELF goes to the engine AS an ELF, so
 * every ELF rule in the database runs on it unchanged; anything else goes as
 * bytes. Declaring a new format would not ADD a way to look at these bytes, it
 * would REPLACE the one that already has rules written for it. This enum
 * decides which of those two a region is and whether it is worth handing over
 * at all - a scan policy, not a partition for a rule author to name.
 */
enum kofa_rgn_use {
	/*
	 * NO ACCESS AT ALL - `---p`. Linux's way of saying MEM_RESERVE: an
	 * address range claimed so nothing else takes it, holding nothing and
	 * readable by no one. Measured at 9.1 TB across seven Chromium
	 * processes on an ordinary desktop, which is why it is filtered out by
	 * default rather than merely classified. See the top of this file.
	 *
	 * Also the value for a region this library could not work out.
	 */
	KOFA_USE_UNKNOWN = 0,

	/* Executable and file-backed: a mapped shared object or the main
	 * executable. Comparable against the file it came from, which is what
	 * makes scanning the FILE instead the right move - see
	 * kofa_pmem_next_region on why. */
	KOFA_USE_IMAGE,

	/*
	 * EXECUTABLE WITH NO FILE BEHIND IT, and the reason this half exists.
	 *
	 * Shellcode, a payload mmap'd and mprotect'd into place, a JIT's
	 * output. Measured at 43 regions and about 12 MB across this machine,
	 * which is small enough to scan all of, every time.
	 */
	KOFA_USE_CODE,

	/*
	 * Private, writable, not executable, not a stack. See the long note on
	 * KOFA_MW_HEAP - this is the weakest place in this enum to match and
	 * the most expensive to read.
	 */
	KOFA_USE_HEAP,

	/* A thread stack: [stack], or an anonymous mapping carrying the guard
	 * page pattern below it. */
	KOFA_USE_STACK,

	/* Everything else mapped: file-backed data, [vdso], [vvar], the
	 * read-only tail of a loaded object. */
	KOFA_USE_DATA,

	KOFA_USE_COUNT
};

/* "image", "code", "heap", "stack", "data", or "?". Never NULL. */
const char *kofa_rgn_use_name(uint8_t use);

/* kofa_region.flags */
enum {
	KOFA_RGF_READ  = 1u << 0,
	KOFA_RGF_WRITE = 1u << 1,
	KOFA_RGF_EXEC  = 1u << 2,

	/*
	 * WRITABLE AND EXECUTABLE AT ONCE, and on Linux this is much weaker
	 * evidence than the equivalent bit on Windows.
	 *
	 * Measured on this machine: seven anonymous rwxp regions of 512 MB,
	 * in seven processes, every one of them V8. Electron put them there.
	 * A rule that fires on rwx alone fires on every developer workstation
	 * and every machine running a browser.
	 *
	 * It is carried because combined with size, with what is IN it, and
	 * with what else the process looks like, it still contributes. Alone
	 * it contributes nothing.
	 */
	KOFA_RGF_WX = 1u << 3,

	/*
	 * EXECUTABLE AND NOTHING IS BEHIND IT. The single most useful bit
	 * here, and the reason to walk regions rather than trust the loader's
	 * own list of mapped objects - which is exactly as honest as the
	 * loader, and an object unlinked from it is invisible there and still
	 * shows up as a region.
	 */
	KOFA_RGF_UNBACKED = 1u << 4,

	/*
	 * THE FILE BEHIND IT HAS BEEN UNLINKED: maps says "(deleted)".
	 *
	 * The bytes are still here and there is nothing on disk to scan, so
	 * this is the case where reading them out of the process is the ONLY
	 * way to see them. Also what every in-place package upgrade leaves
	 * behind, which is why it is a fact and not a finding. Measured: 94
	 * such mappings on an ordinary desktop.
	 */
	KOFA_RGF_DELETED = 1u << 5,

	/*
	 * BACKED BY A memfd. Fileless execution, in the only form Linux has -
	 * see KOFA_PF_EXE_MEMFD. Distinguished from KOFA_RGF_DELETED because
	 * a deleted file once existed and a memfd never did, and only one of
	 * those has an innocent explanation that happens daily.
	 */
	KOFA_RGF_MEMFD = 1u << 6,

	/*
	 * The backing file lives somewhere that does not survive a reboot -
	 * tmpfs, /dev/shm, /run. Not evidence; a great deal of legitimate
	 * software stages there. It is carried because "executed from a
	 * filesystem that keeps no history" is a fact worth having when
	 * something else has already made the process interesting.
	 */
	KOFA_RGF_VOLATILE = 1u << 7,

	/*
	 * RESIDENT IS FAR BELOW VIRTUAL - under a tenth. Set from the pagemap
	 * pass, so only on regions that had one.
	 *
	 * Recorded because it is the thing that surprised everyone who has
	 * built this: it says the reservation is a reservation. A caller
	 * printing region sizes without it reports 512 MB of executable
	 * anonymous memory that does not exist.
	 */
	KOFA_RGF_SPARSE = 1u << 8,

	/*
	 * THE REGION WAS NOT EXAMINED: it is larger than
	 * kofa_pmem_option.max_region, or a byte budget ran out before it.
	 *
	 * Said rather than left as an absence. A region that was skipped and a
	 * region that was read and found uninteresting are different facts,
	 * and a scanner that cannot tell them apart reports "checked
	 * everything" over a set it never saw.
	 */
	KOFA_RGF_UNEXAMINED = 1u << 9,

	/*
	 * pagemap could not be read for this region, so `rss` is the region
	 * size and the read was blind. Happens without privilege on another
	 * user's process, and on kernels built without CONFIG_PROC_PAGE_MONITOR.
	 */
	KOFA_RGF_NO_PAGEMAP = 1u << 10,

	/*
	 * `rss` WAS ACTUALLY MEASURED, rather than being the region size
	 * standing in for an answer nobody asked for.
	 *
	 * This flag exists because leaving it out was a real bug in the first
	 * working version, and the shape of that bug is the reason this tree
	 * distinguishes "checked and found nothing" from "never looked". Every
	 * region under `pagemap_min` was given rss = size - a defensible upper
	 * bound - and the walk then SUMMED those into its resident total. The
	 * summary reported 10.5 TB resident on a machine with 16 GB, and it
	 * reported it confidently, because nothing in the record said which of
	 * those numbers had been measured and which had been assumed.
	 *
	 * An upper bound is a fine thing to carry and a terrible thing to add
	 * up. So: `rss` is ALWAYS an upper bound, this flag says whether it is
	 * a tight one, and kofa_pmem_stat keeps the two sums apart.
	 */
	KOFA_RGF_RSS_MEASURED = 1u << 11,

	/*
	 * PAGEMAP CLAIMS FAR MORE PRESENT THAN smaps CHARGES AS RESIDENT: the
	 * difference is shared zero pages, so most of what pagemap points at
	 * is 4096 zeroes.
	 *
	 * It means one of two things and a caller cannot tell which:
	 * something read the whole region once - a debugger, a core dumper,
	 * another scanner, or an earlier run of this one - or the process
	 * itself read across a reservation it never wrote.
	 *
	 * Either way the runs from pagemap are nearly all empty, and a caller
	 * that reads them is reading zeroes at full price. Carried so that it
	 * can decide not to, and so the divergence is visible rather than
	 * showing up as a region that is somehow always fully resident.
	 */
	KOFA_RGF_ZERO_HEAVY = 1u << 12,

	/*
	 * AN EXECUTABLE FILE-BACKED REGION WITH PRIVATE DIRTY PAGES: somebody
	 * WROTE to code that came from a file.
	 *
	 * Windows needs a working-set query per region to learn this
	 * (KOFW_RGF_DIRTY_IMAGE). Linux gives it away in smaps' Private_Dirty,
	 * which this walk already reads for Rss - so it costs nothing at all.
	 *
	 * WHY IT IS A STRONG SIGNAL HERE AND ONLY A HINT ON WINDOWS. A mapped
	 * ELF's executable segment is BYTE-IDENTICAL to its file: measured at
	 * 42.8 MB across 592 file-backed executable regions of one Chromium
	 * process, and 3.0 MB across a shell, with ZERO bytes differing in
	 * either. x86-64 PIE code is RIP-relative, so no dynamic relocation
	 * lands in .text - they all go to .got, .got.plt and .data.rel.ro,
	 * which is exactly why those pages are shareable between processes in
	 * the first place. A PE's .text is rewritten by base relocations and
	 * has no such property, which is why pe_unmap.h has to exist and why
	 * nothing like it is needed here.
	 *
	 * So code pages are identical to the file unless something changed
	 * them, and the machine agrees: 0 kB of private-dirty across all 1079
	 * executable file-backed regions on this desktop. An inline hook, a
	 * patched GOT resolver stub, a stomped function - each is the only
	 * thing that moves this off zero.
	 *
	 * STILL NOT A VERDICT. A debugger's breakpoint is a written code page,
	 * and so is any legitimate runtime patching. It is a fact at the
	 * strength of a fact that is normally zero.
	 */
	KOFA_RGF_DIRTY_CODE = 1u << 13,

	/*
	 * THE KERNEL PUT THIS HERE, not the program: [vdso], [vsyscall],
	 * [vvar] and their relatives.
	 *
	 * [vdso] IS EXECUTABLE AND HAS NO FILE, which is the exact shape of
	 * the thing this library exists to find - measured, 31 of them on this
	 * machine, one per process. What separates them from shellcode is not
	 * anything about the bytes: it is that the kernel maps them into
	 * everybody, identically, and no program chose their contents.
	 *
	 * Carried as a flag rather than left to whoever looks at the path,
	 * because the alternative is every consumer testing for a leading '['
	 * privately, and one of them forgetting. A rule that means "executable
	 * with no file behind it" has to exclude these, and now it can say so.
	 */
	KOFA_RGF_KERNEL_MAPPED = 1u << 14
};

struct kofa_region {
	uint64_t base;
	uint64_t size;          /* the RESERVATION. See the top of this file. */

	/*
	 * HOW MUCH OF IT EXISTS, IN BYTES, AND ALWAYS AN UPPER BOUND.
	 *
	 * Two separate reasons it is a bound rather than a count, and a caller
	 * has to respect both:
	 *
	 *   - Transparent huge pages make pagemap's granularity 2 MB, so a
	 *     single touched page can be reported as 512 present ones.
	 *   - When pagemap was not consulted at all - the region is under
	 *     `pagemap_min`, over `max_region`, or pagemap is unavailable -
	 *     this is simply `size`, which is the loosest bound there is.
	 *
	 * KOFA_RGF_RSS_MEASURED says which of those two it is. NEVER SUM THIS
	 * ACROSS REGIONS WITHOUT CHECKING THAT FLAG; see the note on it for
	 * what happens when you do.
	 *
	 * This is the number that decides how much work there is. `size`
	 * decides nothing.
	 */
	uint64_t rss;

	uint64_t file_off;
	uint64_t inode;
	uint64_t dev;

	/*
	 * WHICH GROUP OF ADJACENT REGIONS THIS BELONGS TO - Linux's
	 * substitute for an AllocationBase, and it is this library's guess.
	 *
	 * One mapped shared object arrives as three or four VMAs, split where
	 * the protection changes: r--p for the headers, r-xp for the text,
	 * rw-p for the data. A caller that treats each as a find reports one
	 * object three times and scans its header separately from its code.
	 *
	 * Regions sharing a group_id are adjacent and either share a backing
	 * inode or are all anonymous. It is the base address of the first
	 * region in the group, so it is stable and comparable without a table.
	 */
	uint64_t group_id;

	uint32_t flags;         /* KOFA_RGF_* */
	uint8_t  use;           /* enum kofa_rgn_use */
	uint8_t  loc;           /* enum kof_evt_loc, of `path` */
	uint8_t  _pad[2];

	/*
	 * The backing file, or "" when nothing backs it. Never NULL. Borrowed,
	 * valid until the next call on this handle.
	 *
	 * The " (deleted)" suffix is STRIPPED and reported in flags instead,
	 * and a "/memfd:name" pseudo-path is left as it is and flagged. Both
	 * for the same reason kofa_proc.exe does it: a caller that has to
	 * decide whether a path is openable by looking for a magic suffix is a
	 * caller that will one day forget.
	 */
	const char *path;
};

/* One line: address, size, resident, protection, use, and what backs it.
 * Here rather than in each tool, so two tools cannot print it differently.
 * Returns bytes written excluding the NUL and never writes past `cap`. */
size_t kofa_region_describe(const struct kofa_region *, char *buf, size_t cap);

/* ------------------------------------------------------- walking one process */

/* kofa_pmem_option.want */
enum {
	/*
	 * ONLY REGIONS THAT CAN EXECUTE.
	 *
	 * On, it is the difference between ten thousand regions and about
	 * eleven hundred on this machine, and a scanner looking for code has
	 * no use for the rest. Off by default because "what is in this
	 * process" is a different question from "what could run in it", and
	 * only the caller knows which it is asking.
	 */
	KOFA_MW_EXEC_ONLY = 1u << 0,

	/*
	 * USE pagemap TO FIND OUT WHAT IS RESIDENT. On by default, and turning
	 * it off makes every read blind - see the measurements at the top for
	 * what that costs. The option exists so the cost can be measured
	 * again rather than believed.
	 */
	KOFA_MW_PAGEMAP = 1u << 1,

	/*
	 * TAKE `rss` FROM smaps INSTEAD OF FROM pagemap. On by default, and it
	 * is a correctness switch rather than a thoroughness one.
	 *
	 * pagemap's PRESENT bit counts pages that have a PTE, and an untouched
	 * anonymous page that anything has ever READ has a PTE pointing at the
	 * shared zero page - see the long note at the top of this file. smaps
	 * Rss does not count those, because the kernel does not charge them to
	 * anybody. So smaps is the only in-box answer to "how much of this is
	 * real".
	 *
	 * IT COSTS THE DIFFERENCE BETWEEN READING maps AND READING smaps:
	 * measured at 1 ms against 7 ms for a process with 1343 regions, since
	 * the kernel walks the page tables to produce it. That is the price of
	 * not reporting half a gigabyte of shared zeroes as a payload.
	 *
	 * Off, `rss` comes from pagemap and is a much looser upper bound. A
	 * caller that only wants to know WHERE to look, and will read and
	 * judge the bytes anyway, can afford that.
	 */
	KOFA_MW_SMAPS = 1u << 4,

	/*
	 * REPORT KOFA_USE_HEAP REGIONS AT ALL. Off by default, and the default
	 * is not a compromise - it is the measured answer twice over.
	 *
	 * THE COST. Heap is 1867 MB resident on this machine against 12 MB for
	 * every anonymous executable region put together: one hundred and
	 * fifty-five times the bytes, to look in the place where a match means
	 * least.
	 *
	 * THE FALSE POSITIVES, which are not a tuning problem but a property
	 * of what the memory IS. Every byte a process has ever read passes
	 * through its writable private memory: an installer holds its payload
	 * there, a browser holds a download there, and a scanner holds
	 * whatever it just scanned there. The case that settled it, from a
	 * YARA deployment: a CLI tool ran a test binary that contained a
	 * signature string; the test binary matched, and so did the PARENT
	 * shell's heap, because the child's output had passed through the
	 * parent's stdio buffer on its way to the terminal. The parent was
	 * not infected with anything. It had READ something.
	 *
	 * So a match here says the process TOUCHED those bytes and says
	 * nothing whatever about the process being the thing that made them.
	 * A miss says even less: the buffer that would have matched was very
	 * probably freed before anything came to look.
	 *
	 * WHAT TURNING IT OFF ACTUALLY MISSES, since "off" is not free either
	 * and the misses are real:
	 *
	 *   - A DECRYPTED CONFIGURATION. Domain lists, keys, campaign ids.
	 *     Encrypted on disk, plaintext only here, never executable. This
	 *     is what commodity Linux bots keep, and it is a genuine miss.
	 *   - AN INTERPRETED PAYLOAD. A script pulled over a socket and passed
	 *     to exec() lives in the interpreter's heap and nowhere else. No
	 *     page of it is ever executable and no file ever holds it.
	 *
	 * Both are DATA rather than code, which is why no amount of looking at
	 * executable memory finds them.
	 *
	 * THE ANSWER IS NOT A SWITCH, IT IS A SIZE. See max_heap_region below:
	 * 90.4% of heap regions on this machine are under 1 MB and hold 9.3%
	 * of the bytes. A decrypted configuration is kilobytes. A browser's JS
	 * heap - which is where both the cost and most of the noise live - is
	 * tens of megabytes. Capping per region recovers the misses above for
	 * a tenth of the cost, which a switch cannot do in either position.
	 *
	 * KOFA_MW_EXEC_ONLY excludes heap whatever this says: a heap that can
	 * execute is KOFA_USE_CODE and was never a heap by this library's
	 * reading.
	 */
	KOFA_MW_HEAP = 1u << 2,

	/*
	 * REPORT INACCESSIBLE RESERVATIONS (`---p`, KOFA_USE_UNKNOWN).
	 *
	 * Off by default. They cannot be read and hold nothing, and there are
	 * 9.1 TB of them on a desktop running a browser. On, for a caller that
	 * is mapping out an address space rather than scanning it.
	 */
	KOFA_MW_RESERVED = 1u << 3,

	/* What kofa_pmem_open gives a caller that passes NULL. */
	KOFA_MW_DEFAULT = KOFA_MW_PAGEMAP | KOFA_MW_SMAPS
};

/*
 * A BUDGET SHARED BY A WHOLE SWEEP, and the reason it is a separate object.
 *
 * kofa_pmem is per process, so a per-process ceiling bounds one process and
 * nothing else: four hundred processes at 256 MB each is a hundred gigabytes,
 * which is not a bound, it is arithmetic. What a caller actually needs bounded
 * is the WALK, and the walk is many handles.
 *
 * So the caller owns one of these and points every handle at it. Nothing here
 * allocates it and nothing here locks it - a walk is single threaded for the
 * same reason a kof_scanner is, and a caller running several shares nothing
 * between them.
 *
 * RUNNING OUT IS REPORTED, NEVER SILENT. A region that could not be read comes
 * back flagged KOFA_RGF_UNEXAMINED and counted in `regions_refused`, because a
 * scanner that quietly stopped reading would report "checked everything" over
 * a set it abandoned half way.
 */
struct kofa_sweep {
	/* What the whole walk may read. 0 means no limit, which is a choice a
	 * caller makes rather than a default it falls into. */
	uint64_t max_bytes;

	uint64_t used;             /* read so far */
	uint64_t refused;          /* bytes a region wanted and did not get */
	uint32_t regions_refused;  /* regions flagged UNEXAMINED for it */
	uint32_t _pad;
};

struct kofa_pmem_option {
	/* A mask of KOFA_MW_*. Zero takes KOFA_MW_DEFAULT. */
	uint32_t want;

	/*
	 * Regions whose RESERVATION exceeds this are reported with
	 * KOFA_RGF_UNEXAMINED and not read.
	 *
	 * Compared against `size` rather than `rss` on purpose: it is a guard
	 * against a pathological mapping, and the pagemap read needed to learn
	 * rss is itself proportional to size. 0 takes the default stated in
	 * the .c.
	 */
	uint64_t max_region;

	/*
	 * WHAT A HEAP REGION MAY COST, and the whole reason heap is not simply
	 * off. Only consulted when KOFA_MW_HEAP is set; compared against
	 * `rss`, because for heap the resident size IS the work.
	 *
	 * 0 takes the default stated in the .c, which is 1 MB and is chosen
	 * from the distribution in the note on KOFA_MW_HEAP.
	 */
	uint64_t max_heap_region;

	/*
	 * Total bytes read out of this one process. 0 takes the default.
	 * Reaching it flags the remaining regions KOFA_RGF_UNEXAMINED rather
	 * than ending the walk, so the caller still learns they exist.
	 *
	 * THE DEFAULT IS NOT MEASURED, AND SAYING SO IS THE POINT. Every other
	 * number in this file came from a measurement on this machine, taken
	 * as an ordinary user - which sees 34 processes. A privileged sweep
	 * sees roughly ten times as many, and the shape of what it finds is
	 * not known: the per-process ceiling and kofa_sweep.max_bytes were
	 * both picked to be obviously large rather than to be right.
	 *
	 * What would settle them is one run of the walk as root, reporting
	 * bytes_resident and bytes_read per process. Until that exists these
	 * two are guards against a pathological process, not a budget anybody
	 * measured.
	 */
	uint64_t max_bytes;

	/*
	 * Regions smaller than this are read without consulting pagemap: one
	 * pread of the pagemap costs more than reading the region would.
	 *
	 * 0 takes the default stated in the .c. THE BREAK-EVEN POINT HAS NOT
	 * BEEN MEASURED - the current value is reasoned, not observed, and is
	 * one of the open questions in PLAN.md.
	 */
	uint64_t pagemap_min;

	/*
	 * Bytes one CHUNK may be - see kofa_pmem_next_chunk. A resident run
	 * can be hundreds of megabytes and a caller that wanted it in one
	 * piece would be asking this library to allocate it. 0 takes the
	 * default stated in the .c.
	 */
	uint64_t chunk_max;

	/*
	 * The walk's shared budget, or NULL for none. Borrowed; the caller
	 * owns it and reads it when the walk is done.
	 */
	struct kofa_sweep *sweep;
};

struct kofa_pmem;

/*
 * Open one process for reading. NULL on failure with *err set.
 *
 * `start_time` is checked against /proc/<pid>/stat and the open FAILS with
 * KOFA_ERR_GONE if it differs - the pid has been reused and this is a
 * different process. Pass 0 to skip the check, which is what a caller that
 * genuinely means "whatever holds this pid now" does, and it should be rare
 * enough to look odd at the call site.
 */
struct kofa_pmem *kofa_pmem_open(uint32_t pid, uint64_t start_time,
				 const struct kofa_pmem_option *opt, int *err);

/* The process this handle is for. Borrowed, valid for the handle's life. */
const struct kofa_proc *kofa_pmem_proc(const struct kofa_pmem *);

/*
 * Next region, 1 on success and 0 at the end.
 *
 * REGIONS ARE FILTERED BY THE OPTIONS, so a caller that asked for
 * KOFA_MW_EXEC_ONLY does not see the others at all and does not pay for them.
 * What it does still see is the accounting: kofa_pmem_stat reports how many
 * were skipped, so "I looked at forty regions" never gets confused with
 * "there were forty regions".
 *
 * `rss` is filled from pagemap unless the region is under `pagemap_min` or
 * pagemap could not be read - see KOFA_RGF_NO_PAGEMAP.
 *
 * WHY A FILE-BACKED EXECUTABLE REGION IS STILL REPORTED even though the right
 * move is almost always to scan its FILE instead: the region walk is what tells
 * a caller the file is there. Its pages are shared with every other process
 * that mapped the same object precisely BECAUSE they are identical to it, so
 * reading eight thousand mappings to reach an answer that fifty file reads
 * already give is what makes a memory scan take an hour. The caller decides;
 * this reports. See koffridge.h for the cache that makes those fifty reads
 * happen once.
 */
int kofa_pmem_next_region(struct kofa_pmem *, struct kofa_region *out);

/*
 * Read bytes out of the process. Returns how many were read, which may be
 * short and may be 0 - the process can exit at any point and a region can be
 * unmapped between being listed and being read.
 *
 * IT DOES NOT CONSULT pagemap. A caller that wants only resident bytes asks
 * for the runs - see kofa_pmem_runs - and reads those. This does exactly what
 * it is asked, including reading a hole, which comes back as zeroes without
 * disturbing the target (measured; see the top of this file).
 */
size_t kofa_pmem_read(struct kofa_pmem *, uint64_t addr, void *buf, size_t n);

/*
 * THE RESIDENT RUNS INSIDE A REGION, which is how a caller turns 512 MB of
 * reservation into the 4.76 MB that exists.
 *
 * Fills up to `max` runs and returns how many. A return equal to `max` means
 * there may be more and the caller should either take a bigger array or accept
 * that it is reading a prefix - it is told which by `more`, which is set
 * non-zero when runs were left undescribed.
 *
 * Returns 0 and sets *more to 0 when pagemap is unavailable, which is NOT the
 * same as a region with nothing resident. The region's KOFA_RGF_NO_PAGEMAP
 * flag is what separates them.
 */
struct kofa_run {
	uint64_t addr;
	uint64_t len;
};

int kofa_pmem_runs(struct kofa_pmem *, const struct kofa_region *,
		   struct kofa_run *out, int max, int *more);

/*
 * ONE PIECE OF A REGION THAT IS WORTH LOOKING AT, already read.
 *
 * `p` is borrowed and valid until the next call on this handle.
 */
struct kofa_chunk {
	uint64_t    addr;   /* where it is in the process */
	const void *p;
	uint64_t    len;
};

/*
 * WALK A REGION'S CONTENT, one chunk at a time. 1 and *out filled, or 0 at the
 * end of the region.
 *
 * THIS IS THE WAY TO READ A REGION, and kofa_pmem_read is the way to read an
 * address. The difference matters because reading an address is how a caller
 * accidentally reads BLIND, and a blind read is not merely slow - it
 * instantiates a zero-page PTE for every untouched page it touches, so the
 * pagemap of that process reports them present from then on, for this scanner
 * and for every other tool on the machine. See the note at the top of this
 * file. A caller that only ever uses this cannot do that.
 *
 * IT SKIPS PAGES THAT ARE ENTIRELY ZERO, and that is the larger half of what
 * it is for. Measured across every anonymous executable region of 64 KB or
 * more on this machine: 1132.54 MB came back resident by pagemap, and 1086.71
 * MB of it - 96.0% - was nothing but zeroes. The 45.8 MB left is the code. A
 * caller handing the engine the unfiltered set would be asking it to search
 * twenty-four times what is there.
 *
 * WHY DROPPING THEM CANNOT LOSE A MATCH. The longest pattern the database can
 * hold is KOF_STR_MAX_LEN, 512 bytes; a page is 4096. A match that began
 * before a dropped page and ended after it would have to span eight times the
 * longest pattern, so there is no such match. One lying entirely inside a
 * dropped page would have to BE 4096 zero bytes, which is not a signature
 * anybody would write and which would match every zero page on the machine if
 * they did.
 *
 * CHUNKS ARE NEVER CONCATENATED. Two runs that are not adjacent in the process
 * are two chunks, because joining them would create a byte sequence that never
 * existed at any address - and a signature matching across that splice is a
 * detection of something that is not there.
 *
 * The cost of the test itself, measured: 3.67 GB/s, against a saving of 24x in
 * what the engine is then asked to search.
 */
int kofa_pmem_next_chunk(struct kofa_pmem *, const struct kofa_region *,
			 struct kofa_chunk *out);

void kofa_pmem_close(struct kofa_pmem *);

/*
 * WHAT THE WALK DID, AND WHY IT IS NOT OPTIONAL.
 *
 * The numbers that say whether the design above is working on THIS machine
 * rather than on the one it was measured on. `bytes_virtual` against
 * `bytes_resident` is the ratio the whole thing rests on; if it is near 1 the
 * pagemap pass is buying nothing and is pure cost. `regions_skipped` climbing
 * means the budgets are below the working set and the caller is being told it
 * checked things it did not.
 */
struct kofa_pmem_stat {
	uint64_t regions_seen;      /* matched the filter */
	uint64_t regions_filtered;  /* excluded by `want` */
	uint64_t regions_skipped;   /* KOFA_RGF_UNEXAMINED */
	uint64_t bytes_virtual;     /* sum of size over regions_seen */

	/*
	 * THE TWO RESIDENT SUMS, KEPT APART ON PURPOSE - see
	 * KOFA_RGF_RSS_MEASURED for the bug that made this necessary.
	 *
	 * `bytes_resident` is the sum over regions whose pagemap was actually
	 * read, and is the only one of these that means what it says.
	 * `bytes_unmeasured` is the sum of `size` over the rest: an upper
	 * bound on what is still unaccounted for. They are never added
	 * together by anything here, and a caller that adds them is producing
	 * the same wrong number by hand.
	 */
	uint64_t bytes_resident;
	uint64_t bytes_unmeasured;
	uint64_t regions_measured;

	uint64_t bytes_read;        /* what was moved out of the process */

	/*
	 * WHAT THE ZERO FILTER REMOVED, so its earn is visible rather than
	 * assumed - the audit asks every filter for this. `bytes_zero` is
	 * what was read and dropped; bytes_read minus it is what a caller was
	 * handed.
	 */
	uint64_t bytes_zero;
	uint64_t chunks;

	uint64_t pagemap_reads;
	uint64_t pagemap_failed;
};

void kofa_pmem_stats(const struct kofa_pmem *, struct kofa_pmem_stat *);

#endif /* KOFANTARC_APROC_H */
