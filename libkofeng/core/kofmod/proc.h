/* SPDX-License-Identifier: Apache-2.0 */
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
#define KOF_PROC_REC_VERSION 1u
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
	 * WHAT ITS STANDARD DESCRIPTORS POINT AT: the three link targets
	 * verbatim - "socket:[14899490]", "/dev/pts/3", "pipe:[123]".
	 *
	 * Separate from META because these are not identity and not intent -
	 * they are the process's connection to the world, and the one place a
	 * reverse shell is visible without any byte of it being unusual.
	 */
	KOF_SCAN_PROC_FD = 1u << 3
};

#define KOF_SCAN_PROC_CLAIMED \
	(KOF_SCAN_PROC_META | KOF_SCAN_PROC_CMDLINE | KOF_SCAN_PROC_FD)

#define KOF_SCAN_PROC_LIST(X) \
	X(KOF_SCAN_PROC_META)     \
	X(KOF_SCAN_PROC_CMDLINE)  \
	X(KOF_SCAN_PROC_FD)

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

	uint32_t pid;
	uint32_t ppid;
	uint64_t start_time;   /* field 22 of stat: what makes the pid mean one
				* process rather than one slot */
	uint32_t uid;
	uint32_t gid;

	uint32_t n_fd;         /* descriptors open */
	uint32_t n_socket;     /* of those, sockets */
	uint32_t n_like_stdin; /* of those, naming the same object as fd 0 */

	uint32_t flags;        /* KOF_PROC_F_* */

	/* Offsets into the record, from its start. Zero means absent - the
	 * head is never at zero, so zero cannot be a real string offset. */
	uint16_t off_exe, off_comm, off_cmdline;
	uint16_t off_fd0, off_fd1, off_fd2;
	uint16_t total_len;    /* head_len + the arena */
	uint16_t _pad;
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
	uint32_t uid, gid;
	uint32_t n_fd, n_socket, n_like_stdin;
	uint32_t flags;        /* KOF_PROC_F_* , copied through */

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
	uint32_t len_meta, len_cmdline, len_fd;
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
