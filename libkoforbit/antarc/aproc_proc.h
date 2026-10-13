/*
 * aproc_proc.h - a process: the record, the options of a list and the list walk. *
 * A part of <aproc.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFANTARC_APROC_PROC_H
#define KOFANTARC_APROC_PROC_H

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

#endif /* KOFANTARC_APROC_PROC_H */
