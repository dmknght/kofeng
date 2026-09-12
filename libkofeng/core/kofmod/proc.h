/*
 * proc.h - one running process, presented as a scannable object.
 *
 * WHY A PROCESS IS AN OBJECT AT ALL.
 *
 * Because the rules about one have to live where every other rule lives. The
 * facts that say a process is a reverse shell - one socket on both ends of its
 * stdio, nothing else open, a shell behind it - were written in C inside the
 * collector first, and that is the shape this file exists to undo: a rule
 * compiled into a library is a rule nobody can add, tune, version or disagree
 * with without a build of the product.
 *
 * So the collector COLLECTS and the database DECIDES, which is the same split
 * every format here already has. libkofantarc reads /proc and fills the record
 * below; a rule in bases/heur joins those facts and says what they mean.
 *
 *
 * IT IS AN EVENT TARGET AND NOT A FILE FORMAT, and kofsig.h explains the axis:
 * the low half of the target space is file formats and the high half is verbs,
 * so an ELF rule is never offered a process and a process rule is never
 * offered an ELF. The prefilter is one byte - that is the whole reason a rule
 * about a process costs an ELF scan nothing.
 *
 *
 * WHAT THE OBJECT'S BYTES ARE. A fixed head followed by a text arena, in the
 * order the regions below need: the head and the identity first, the command
 * line next, the descriptor links last. Nothing about it is sniffable - it is
 * integers and strings, like every kof_evt - so the parse is reached only when
 * a caller DECLARES what it is holding, exactly as amsi_parse.h describes.
 */

#ifndef KOFMOD_PROC_H
#define KOFMOD_PROC_H

#include <kofmod/kofsig.h>

#define KOF_PROC_REC_MAGIC   0x434f5250u   /* "PROC", little-endian */
/* 2: the arena gained the environment between the command line and the
 * descriptors - see off_environ. The parse refuses a version it does not
 * know, so an old record never reads as a new one. */
#define KOF_PROC_REC_VERSION 3u
#define KOF_PROC_INFO_VERSION 1

/*
 * THE THREE REGIONS, AND THEY PARTITION THE RECORD.
 *
 * That is the contract kofsig.h asks of every format: OR-ing any set of these
 * must scan no byte twice and leave none unreachable. It matters here for the
 * same reason it matters for AMSI - a rule that matched "bash" without saying
 * WHICH of these it meant would fire on the image name of every shell on the
 * machine, forever.
 *
 * Bit 0 is left alone, as everywhere else: KOF_SCAN_ALL means "everything" and
 * a region sharing its bit could not be told apart from it.
 */
enum kof_scan_proc {
	/*
	 * WHO IT IS: the fixed head, the executable path, and the kernel's
	 * short name for it.
	 *
	 * Facts the KERNEL supplies about the process. A rule keyed here is
	 * making a claim about identity, which a process controls only as far
	 * as it controls what it exec'd.
	 */
	KOF_SCAN_PROC_META = 1u << 1,

	/*
	 * WHAT IT WAS ASKED TO DO: the command line, NULs already turned into
	 * spaces by the collector.
	 *
	 * The attacker-controlled half, and the one worth searching. Every
	 * living-off-the-land technique is identical in META and obvious here:
	 * "bash started" is not a fact anybody can act on, and
	 * `bash -c 'exec 5<>/dev/tcp/...'` is the whole event.
	 */
	KOF_SCAN_PROC_CMDLINE = 1u << 2,

	/*
	 * THE ENVIRONMENT IT WAS STARTED WITH, NULs already spaces.
	 *
	 * Attacker-controlled text like the command line, and reached by the
	 * same searching: LD_PRELOAD naming a path nobody shipped, a payload
	 * passed in a variable precisely to keep it off the command line where
	 * everybody looks.
	 *
	 * THE INITIAL BLOCK, NOT THE LIVE ONE. The kernel exposes what the
	 * process was started with; setenv afterwards changes the process's
	 * own copy and not this. A rule keyed here is making a claim about how
	 * the process was LAUNCHED.
	 */
	KOF_SCAN_PROC_ENV = 1u << 4,

	/*
	 * WHO IT IS TALKING TO: one line per connection, joined from the
	 * process's own network namespace.
	 *
	 * Worth searching for the address itself - a signature naming a
	 * command-and-control host matches here and nowhere else in a process
	 * record - and worth showing whatever a rule does with it.
	 */
	KOF_SCAN_PROC_NET = 1u << 5,

	/*
	 * WHAT ITS STANDARD DESCRIPTORS POINT AT: the three link targets
	 * verbatim - "socket:[14899490]", "/dev/pts/3", "pipe:[123]".
	 *
	 * Separate from META because these are not identity and not intent -
	 * they are the process's connection to the world, and the one place a
	 * reverse shell is visible without any byte of it being unusual.
	 */
	KOF_SCAN_PROC_FD = 1u << 3
};

/*
 * ONE REGION, AND THE OTHER TWO ARE NOT SCANNED.
 *
 * A REGION EXISTS SO A PATTERN SEARCH CAN BE SCOPED. META is the fixed head -
 * pid, ppid, start_time, counts, flags - which is to say a packed struct of
 * INTEGERS, and searching bytes in one is searching for a pattern in a
 * layout. The two rules that use these facts, proc_revshell and proc_kthread,
 * read them as FIELDS through kof_proc(ctx) and never as bytes; they would not
 * notice if the region vanished, which is the test that decided this.
 *
 * FD is three link targets - "socket:[14899490]", "/dev/pts/3" - and it is
 * weak for the same reason with an extra cost: to be worth searching it would
 * have to carry EVERY descriptor rather than the standard three, which means a
 * table like the symbol block and a lookup written for it. That is real work
 * for a detection nobody has asked for, so the three stay FIELDS.
 *
 * CMDLINE stays, and it is the one that earns it: the attacker-controlled
 * half, where every living-off-the-land technique is visible as text, and
 * where a decoder can later be run over what somebody base64'd into an
 * argument.
 *
 * THE HEAD AND THE DESCRIPTORS ARE STILL SHOWN - they are on the dashboard,
 * where a reader wants them. Not being a scan region is a statement about
 * what a SIGNATURE can target, not about what is worth knowing.
 */
#define KOF_SCAN_PROC_CLAIMED \
	(KOF_SCAN_PROC_CMDLINE | KOF_SCAN_PROC_ENV | KOF_SCAN_PROC_NET)

#define KOF_SCAN_PROC_LIST(X) \
	X(KOF_SCAN_PROC_CMDLINE)  \
	X(KOF_SCAN_PROC_ENV)      \
	X(KOF_SCAN_PROC_NET)

/*
 * WHAT THE COLLECTOR OBSERVED AND COULD NOT INFER - the flags half.
 *
 * Every one of these is read off something the kernel said, never worked out
 * by comparing two things. The comparing is what a rule does.
 */
enum {
	/* readlink of /proc/<pid>/exe ended in " (deleted)". */
	KOF_PROC_F_EXE_GONE  = 1u << 0,

	/* ... and it named a memfd, which never had a file at all. */
	KOF_PROC_F_EXE_MEMFD = 1u << 1,

	/* The descriptor table was walked, so the counts below mean something.
	 * Without it a zero count and a question nobody asked look the same. */
	KOF_PROC_F_FDS_READ  = 1u << 2,

	/* PF_KTHREAD in field 9 of /proc/<pid>/stat: the KERNEL's own bit, and
	 * never the process's name. That is what makes the disagreement
	 * between the two observable - see the masquerade rule. */
	KOF_PROC_F_KTHREAD   = 1u << 3,

	/* The executable path resolves on the filesystem right now. With
	 * EXE_GONE this separates a package upgrade, which replaces the file,
	 * from a program that unlinked itself and left nothing. */
	KOF_PROC_F_EXE_ON_DISK = 1u << 4
};

/*
 * THE RECORD. This IS the object's bytes.
 *
 * Layout rule, as everywhere in this directory: APPEND ONLY. New fields go at
 * the end, existing fields never move or change meaning - a recorded snapshot
 * outlives the build that wrote it.
 */
struct kof_proc_rec {
	uint32_t magic;        /* KOF_PROC_REC_MAGIC */
	uint16_t version;      /* KOF_PROC_REC_VERSION */
	uint16_t head_len;     /* where the text arena starts */

	/*
	 * WHICH COLLECTOR FILLED THIS - enum kof_evt_platform, one byte.
	 *
	 * It is here so that a rule can be written for one platform, for the
	 * other, or for both, and so that a second collector can fill this
	 * record WITHOUT the engine changing. That is the whole point of the
	 * field: libkofgrille and libkofantarc are meant to be developed in
	 * parallel, and the first version of this struct had POSIX ids sitting
	 * in the fixed head, which would have forced a core change the day a
	 * Windows process was first handed over.
	 *
	 * The fields above and below are the ones BOTH platforms have. A
	 * process has a pid, a parent, a start time, an image, a command line
	 * and three standard streams on either system - a Windows reverse
	 * shell puts a socket on cmd.exe's handles exactly as a Linux one puts
	 * it on bash's. What differs goes in the per-platform tail, the way
	 * kof_evt already keeps a union per verb rather than a flat head with
	 * everybody's fields in it.
	 */
	uint8_t  os;
	uint8_t  _pad0[3];

	uint32_t pid;
	uint32_t ppid;
	uint64_t start_time;   /* Linux: field 22 of stat. Windows: the creation
				* time. Either way it is what makes the pid name
				* one process rather than one slot. */

	/*
	 * THE HANDLE TABLE, counted. Descriptors on Linux, handles on Windows;
	 * the question "how many does it hold, how many are sockets, and how
	 * many name the same object as its stdin" has the same meaning and the
	 * same evidential weight on both.
	 */
	uint32_t n_fd;
	uint32_t n_socket;
	uint32_t n_like_stdin;

	uint32_t flags;        /* KOF_PROC_F_* */

	/* Offsets into the record, from its start. Zero means absent - the
	 * head is never at zero, so zero cannot be a real string offset. */
	uint16_t off_exe, off_comm, off_cmdline;
	/*
	 * THE ENVIRONMENT, written between the command line and the
	 * descriptors so the arena stays in region order - see the partition
	 * in proc_parse.c, which takes its boundaries from these offsets
	 * rather than assuming them.
	 */
	uint16_t off_environ;
	/* After the environment, before the descriptors - region order. */
	uint16_t off_net;
	uint16_t off_fd0, off_fd1, off_fd2;
	uint16_t total_len;    /* head_len + the arena */
	uint16_t _pad;

	/*
	 * WHAT ONLY ONE PLATFORM HAS.
	 *
	 * Read it only after checking `os`. A union rather than both sets laid
	 * flat, for the reason kof_evt gives about its own per-verb union: laid
	 * flat, every record pays for every platform's fields, and a reader
	 * that forgets to check which one it is holding gets four bytes of
	 * somebody else's meaning rather than a value it must handle.
	 */
	union {
		struct {
			uint32_t uid;
			uint32_t gid;
		} linux_;
		struct {
			/* Session, and the integrity level a token carries.
			 * Reserved: no Windows collector fills this yet, and
			 * the space is here so that the one that does needs no
			 * change to this file. */
			uint32_t session_id;
			uint32_t integrity;
		} windows;
		uint8_t _reserved[16];
	} plat;
};

/*
 * THE VIEW A RULE READS, filled by the parse.
 *
 * It carries the scalars plus the handful of STRING COMPARISONS a rule cannot
 * make for itself - see fd_same_01. Those are facts ("these two strings are
 * equal"), not decisions ("therefore it is a reverse shell"); the parse is
 * allowed to compute a fact for the same reason the ELF parse is allowed to
 * report that a PT_INTERP exists.
 */
struct kof_proc_info {
	uint32_t version;      /* KOF_PROC_INFO_VERSION */
	uint32_t valid;        /* the record parsed and its offsets are inside it */

	uint32_t pid, ppid;
	uint64_t start_time;
	uint32_t n_fd, n_socket, n_like_stdin;
	uint32_t flags;        /* KOF_PROC_F_* , copied through */

	/*
	 * enum kof_evt_platform. A rule that applies to one platform tests
	 * this; a rule about a shape both share - a shell holding one socket
	 * on both ends of its stdio - does not, and should not.
	 */
	uint8_t  os;
	uint8_t  _pad0[3];

	/* The per-platform tail, already selected by `os`. */
	uint32_t plat_a, plat_b;

	/*
	 * fd 0 AND fd 1 NAME THE SAME OBJECT.
	 *
	 * A rule cannot compute this: it would need the two strings, and a
	 * heuristic reads a view rather than bytes. The parse holds both and
	 * compares them once.
	 *
	 * Kept as its own field rather than left to a string rule because the
	 * question is EQUALITY of two attacker-independent kernel strings, and
	 * a pattern cannot express "these two are equal" at all.
	 */
	uint8_t fd_same_01;

	/* The three links start with "socket:". */
	uint8_t fd0_socket, fd1_socket, fd2_socket;

	/* The three links are the same /dev/pts entry. On its own this is
	 * every login shell on the machine; it is here so a rule can say so
	 * rather than having to discover it. */
	uint8_t fd_same_tty;

	/*
	 * The kernel's short name is bracketed - "[kworker/0:2]".
	 *
	 * A fact about the SHAPE of a string. What it means depends entirely
	 * on KOF_PROC_F_KTHREAD, and putting the two together is the rule's
	 * job, not this one's.
	 */
	uint8_t comm_bracketed;

	uint8_t _pad[2];

	/* Where the arena's strings are, for a rule that wants to scope a
	 * search rather than read a scalar. */
	uint32_t off_exe, off_comm, off_cmdline, off_fd0;
	/* Appended, not inserted: a field added at the TAIL cannot move the
	 * ones a database compiled earlier reads by offset. */
	uint32_t off_env;
	uint32_t off_net;
	uint32_t len_meta, len_cmdline, len_fd;
	uint32_t len_env;
	uint32_t len_net;
};

/*
 * A plain cast, not a checked one - see the note on kof_elf() for why. The
 * guarantee is that the host does not invoke a module whose declared target
 * does not cover the object in hand, and that the build refuses a module which
 * includes two format headers.
 */
static inline const struct kof_proc_info *
kof_proc(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_proc_info *)ctx->file_header;
}

#endif /* KOFMOD_PROC_H */
