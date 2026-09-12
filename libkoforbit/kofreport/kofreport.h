/*
 * kofreport.h - what a run LEFT BEHIND, as evidence and as signature material.
 *
 * WHAT IT OWNS: the fingerprints a traced program produced. The commands it
 * ran, the files it created and what is in them, the ranges it wrote into
 * files that already existed and what is at those ranges, the registry values
 * it set, the names it looked up, the peers it talked to, the pipes it opened.
 * Each one deduplicated, stamped with when it was first seen, and pointed back
 * at the record in the log that established it.
 *
 * WHAT IT DOES NOT OWN: collecting, rendering an event, and deciding whether
 * something is malicious. It consumes struct kof_evt, so a live Windows
 * session and a replayed log produce the same report from the same code - the
 * property kofevtfmt.h exists for, one level up.
 *
 *
 * WHY THIS IS A LIBRARY IN ORBIT AND NOT A FUNCTION IN kofmontrace
 *
 * Because the tracer is not the only thing that will want it, and a report
 * that lives inside one tool is a report the next tool writes again slightly
 * differently. That already happened once in this tree, to the event renderer,
 * and the note at the top of kofevtfmt.h is the receipt.
 *
 * It lives in orbit rather than in libkofeng for the reason koffridge.h gives
 * about itself: orbit may know the engine's types, the engine must never know
 * orbit's. A report hashes artefacts and asks the engine what a dropped file
 * is, so it depends on libkofeng - and libkofeng must be able to ship without
 * knowing that anything called a report exists.
 *
 *
 * THE TWO PHASES, AND THE LINE BETWEEN THEM IS THE WHOLE DESIGN
 *
 *   FEED    once per kept event, on the consumer thread. Bounded work over
 *           bounded memory: hash a string, look it up, bump a count. No file
 *           is opened, nothing is hashed, no process is asked anything.
 *   FINISH  once, after the traced tree is DEAD. Everything expensive: copy
 *           the files that were created, read back the ranges that were
 *           written, hash them, hand them to the engine.
 *
 * That line is not tidiness. Unbounded I/O on the drain path is the exact
 * failure the kofwatchtower/kofwatchman split exists to prevent - a slow scan
 * there does not cost a queue, it costs a full ring, and the events dropped
 * are everybody else's. And it is not only about cost: a file being written
 * while it is read hashes to a value that was never on the disk, and a file
 * whose writer is still running can change between the hash and the scan. The
 * artefacts are only final once the tree is not running, which is the same
 * instant the job object is closed.
 *
 *
 * WHY THE BYTES, AND NOT ONLY THE PATHS
 *
 * Because a path is a claim and bytes are evidence, and because the second job
 * of this report is to be the input to a signature.
 *
 * "The sample created C:\Users\x\AppData\Local\Temp\a8f31.tmp" cannot be
 * turned into a detection by anybody. The CONTENT of that file can: it is
 * either the next stage, in which case it is a sample with a digest and a
 * verdict, or it is a configuration blob whose strings are exactly the
 * literals a signature should look for. The same is true one level down for a
 * write into a file that already existed - what was appended to hosts, what
 * was patched into an existing binary.
 *
 * NO EVENT ON EITHER PLATFORM CARRIES FILE CONTENT. So the bytes are read back
 * off the disk afterwards, and this library says so everywhere it reports
 * them: `struct kof_fp_bytes.at_finish` marks a range as "what was there when
 * the run ended", which is not provably what the write put there. A report
 * that blurred those two would be inventing evidence.
 *
 *
 * GROUPED, NEVER FILTERED
 *
 * Most observed strings are useless as signature material because they hold
 * something that changes every run - a random temp name, a pid, a user
 * profile, a timestamp. The obvious thing to do is drop them, and it is wrong:
 * a dropped candidate is a decision the reader cannot see, cannot check and
 * cannot overrule, and the filter WILL be wrong - "a8f31.tmp" is noise and
 * "nssm.exe" is not, and no amount of pattern matching reliably tells a random
 * name from a short deliberate one.
 *
 * So every fingerprint is kept, and each one carries a GROUP and the REASON it
 * is in that group:
 *
 *   KOF_RG_STABLE     nothing about it looks run-specific. Signature material.
 *   KOF_RG_VOLATILE   it holds something that will differ next run, and the
 *                     reason names what. Its `norm` field holds the part that
 *                     would survive, which is the half worth a string.
 *   KOF_RG_AMBIENT    every program on the machine does this. A system module
 *                     load, a write under the tool's own directory.
 *
 * A reader sees three sections instead of one list, sorted so the first is the
 * one to read. Nothing is hidden, and the classification is auditable because
 * the reason is printed beside it.
 *
 *
 * NO SCORE, AND NOT ONE COUNTED FINDING
 *
 * Same rule as kofevt.h states for events and kofeng.h for objects. This
 * counts fingerprints; it does not weigh them and it does not add them up.
 * Twelve stable fingerprints is twelve things to look at, which a reader can
 * act on. A 73 is not.
 */

#ifndef KOFREPORT_H
#define KOFREPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "kofevt.h"

/*
 * The engine, opaquely, and the include is deliberately NOT here.
 *
 * A host that has no database still wants a report - it will have no digests
 * and no verdicts, and it says so rather than showing blanks. Taking
 * kofeng.h's type by name means this header costs nothing to include and the
 * .c files that do the scanning are the only ones that need the engine's
 * declarations.
 */
typedef struct kof_engine kof_engine;
typedef struct kof_scanner kof_scanner;

/* ------------------------------------------------------------------- kinds */

/*
 * WHAT KIND OF TRACE A PROGRAM LEFT.
 *
 * The list is what a machine can be asked about afterwards, which is a shorter
 * list than the verbs: several verbs land in one kind (every registry mutation
 * is a registry write from a reader's point of view), and one verb can produce
 * two kinds (a file create in \Device\NamedPipe\ is a pipe, not a file).
 *
 * The test applied to each: can this be the subject of a sentence in a report
 * AND the seed of a string in a signature. KOF_FP_MODULE passes - a DLL loaded
 * out of a temp directory is both. "A thread started" does not, which is why
 * the only thread entry here is the unbacked one, where the FACT is the
 * finding and there is no string.
 */
enum kof_fp_kind {
	KOF_FP_NONE = 0,

	/* A process in the tree, with its image and its command line. The
	 * spine of the report: everything else is attributed to one of these. */
	KOF_FP_PROCESS,

	/* A file that came into existence. The one kind whose bytes can be
	 * collected whole, because there is a whole file to collect. */
	KOF_FP_FILE_NEW,

	/* A range written into a file that already existed. Bytes read back
	 * from the range, never the whole file: the file is somebody else's
	 * and the write is the event. */
	KOF_FP_FILE_WRITE,

	KOF_FP_FILE_DELETE,
	KOF_FP_FILE_RENAME,

	/* A registry key or value. The VALUE NAME is the durable half and the
	 * data is often not - see the grouping. */
	KOF_FP_REGISTRY,

	/* A peer: an address and a port. */
	KOF_FP_PEER,

	/* A name that was looked up. Worth more than the address it resolved
	 * to and kept separately for that reason. */
	KOF_FP_DNS,

	/* A named pipe, which is how one process gets another to act for it. */
	KOF_FP_PIPE,

	/* A module mapped into a process in the tree. */
	KOF_FP_MODULE,

	/* What a script actually said - an AMSI submission. The only kind
	 * whose text is CONTENT rather than a name, and the only one that
	 * arrives already cut. */
	KOF_FP_SCRIPT,

	/* A thread whose entry point is in memory no file backs. No string,
	 * and it is here because it is the one shape a report must not omit:
	 * it is what a manually mapped payload looks like from outside. */
	KOF_FP_UNBACKED,

	KOF_FP_KIND_COUNT
};

/* "process", "file-new", "registry", ... Never NULL. */
const char *kof_fp_kind_name(uint8_t kind);

/*
 * WHICH GROUP A FINGERPRINT IS IN - see the header note on grouping rather
 * than filtering.
 *
 * Ordered by how much attention the first one deserves, because that is the
 * order the emitters print in and the order is the only guidance a reader
 * gets. Nothing sums these and nothing is dropped for being in one.
 */
enum kof_rep_group {
	KOF_RG_STABLE = 0,
	KOF_RG_VOLATILE,
	KOF_RG_AMBIENT,
	KOF_RG_GROUP_COUNT
};

/* "stable", "volatile", "ambient". Never NULL. */
const char *kof_rep_group_name(uint8_t group);

/* ------------------------------------------------------ bytes, when we have them */

/* How much of a range is previewed inline in the report. Enough to recognise a
 * header, a magic number or the first line of a script; not enough to turn the
 * report into the file. */
#define KOF_FP_PREVIEW 64u

/*
 * THE BYTES BEHIND ONE FINGERPRINT, and every field here exists to stop the
 * report claiming more than it knows.
 */
struct kof_fp_bytes {
	/* Where in the file the range starts and how long the WRITE said it
	 * was. From the event, so this much is what the kernel reported. */
	uint64_t offset;
	uint64_t claimed;

	/* How many bytes were actually read back, which is not `claimed` when
	 * the file shrank, was truncated, or ended early. */
	uint64_t got;

	/* sha256 of what was read, or "" - of the RANGE for a write, of the
	 * whole file for a created one. */
	char     sha256[65];

	/* The whole file's size and digest, for a created file. Zero and ""
	 * for a write into somebody else's file, where the file's own digest
	 * would be a fact about a file the sample did not create. */
	uint64_t file_size;
	char     file_sha256[65];

	/* Where the collected copy went, relative to the report directory, or
	 * "" - "files/<digest>". Content addressed, so two paths holding the
	 * same bytes are collected once and a name chosen by the sample can
	 * never decide a filename on the analyst's disk. */
	char     stored[96];

	uint8_t  preview[KOF_FP_PREVIEW];
	uint32_t preview_len;

	/*
	 * READ AT THE END OF THE RUN, WHICH IS NOT WHEN IT WAS WRITTEN.
	 *
	 * Always 1 today, and it is a field rather than a constant because it
	 * is the caveat the whole byte-capture half rests on: between the write
	 * and this read, the same process may have written the range again,
	 * another process may have, or the file may have been replaced. The
	 * bytes are what was there at the end. A report that presented them as
	 * "the bytes written" would be asserting something no event says.
	 */
	uint8_t  at_finish;

	/* Why there are no bytes, when there are none: KOF_FP_WHY_*. */
	uint8_t  why_not;
};

/* Why a range or a file has no bytes in the report. Named rather than left
 * blank, because "gone before we looked" and "we never looked" send a reader
 * to two different places. */
enum {
	KOF_FP_WHY_OK = 0,
	KOF_FP_WHY_GONE,        /* the path did not exist at finish */
	KOF_FP_WHY_DENIED,      /* it exists and could not be opened */
	KOF_FP_WHY_TOO_BIG,     /* over the caller's per-file ceiling */
	KOF_FP_WHY_BUDGET,      /* the run's total evidence budget was spent */
	KOF_FP_WHY_NOT_ASKED,   /* collection was off */
	KOF_FP_WHY_SHORT        /* the range is past the end of the file now */
};

/* A sentence for one of those. Never NULL. */
const char *kof_fp_why_not(uint8_t why);

/* --------------------------------------------------- what the engine said */

/*
 * WHAT THE ENGINE MADE OF A COLLECTED ARTEFACT.
 *
 * Three separate answers, and a report must not merge them: what the object
 * IS (a PE, packed with UPX 4.02), what the database CALLS it (a finding), and
 * whether anybody ASKED (no database, no answer). The third is why every field
 * here has an "unanswered" state rather than a zero that reads as "clean".
 */
struct kof_fp_verdict {
	uint8_t  asked;         /* 0: no engine was given, so nothing below means
				 * anything */

	/*
	 * AN UNPACKER PRODUCED SOMETHING FROM IT - kof_result.from_packer on a
	 * child, or a non-zero heur_depth on this object.
	 *
	 * Taken from the engine rather than guessed from a name, because the
	 * engine already had to decide it and a second opinion here would drift
	 * from the first. That drift is not hypothetical: kofeng.h records that
	 * kofviewer used to guess packer-ness from names and stopped agreeing
	 * with the scanner, and that the field exists to retire the guess.
	 */
	uint8_t  packed;
	uint8_t  depth;         /* executable packer layers above the payload */

	/* kof_entropy_eighths over the object as scanned. A SHAPE and never a
	 * verdict - 7.9 bits is a packed stage, an archive and a JPEG - and it
	 * is in the report because it is the cheapest thing that says which
	 * artefact to look at first. */
	uint32_t entropy8;

	/* The engine's composed name, "PE-x64/Trojan:Emotet#Gen", or "" for an
	 * object with no finding - which is a RESULT and not a failure. */
	char     finding[224];

	/*
	 * WHAT AN UNPACKER SAID ABOUT ITSELF - "UPX.PE" and its version, from
	 * the note channel (kof_scanner_on_debug).
	 *
	 * Diagnostics rather than a verdict, and the half a report about a
	 * packed dropper is actually read for: "packed, and nothing came out"
	 * and "packed with UPX 4.02, one child" send a researcher to two
	 * different places.
	 */
	char     packer[48];
	uint64_t packer_version;

	/* How many children came out of it - an archive's members, an unpacked
	 * payload. Zero on a packed object is worth seeing: it means the
	 * engine knew it was packed and could not get inside. */
	uint32_t children;

	/*
	 * HOW MANY MODULES RAN, and whether the engine finished.
	 *
	 * Both from kof_result, and both are here because "no finding" has
	 * three meanings that a report must not merge: everything applicable
	 * ran and found nothing (examined > 0, broken == 0), nothing was
	 * applicable (examined == 0 - a formatless blob), or a limit ran out
	 * (broken != 0). kofeng.h is explicit that reporting the last two as
	 * clean is how a decompression bomb becomes a way of not being
	 * scanned.
	 */
	uint32_t examined;
	uint32_t broken;
};

/* ------------------------------------------------------- one fingerprint */

/*
 * ONE THING THE RUN LEFT BEHIND.
 *
 * Deduplicated on (kind, text): a program that writes the same registry value
 * forty times produced one fingerprint with a count of forty, because forty
 * identical lines are one fact and thirty-nine of them are noise. The stamps
 * are of the FIRST and LAST time it was seen, which is how a reader tells a
 * one-off from something that ran in a loop.
 */
struct kof_fingerprint {
	uint8_t  kind;          /* enum kof_fp_kind */
	uint8_t  group;         /* enum kof_rep_group */
	uint8_t  loc;           /* enum kof_evt_loc, of the object */
	uint8_t  flags;         /* KOF_FP_F_* */
	uint16_t attack;        /* enum kof_attack - see the note below */

	uint64_t first_seen, last_seen;   /* kof_evt stamps */
	uint64_t first_index;             /* the record in the log that
					   * established it, so a report points
					   * at replayable evidence */
	uint32_t count;
	uint32_t actor_pid;               /* who did it, the first time */

	/*
	 * THE OBSERVABLE ITSELF. A path, a registry key, "93.184.216.34:443",
	 * a command line, a script's first bytes.
	 *
	 * Owned by the report and valid until it is closed. Never NULL.
	 */
	const char *text;

	/*
	 * THE PART THAT WOULD SURVIVE ANOTHER RUN, for a volatile fingerprint -
	 * "\AppData\Local\Temp\*.tmp" for a random temp name, the value name
	 * without its data, the domain without its label.
	 *
	 * "" when `text` is already stable, which is the normal case. This is
	 * the field a signature draft takes its string from when the group is
	 * volatile, and having it means a volatile fingerprint is still usable
	 * rather than merely labelled.
	 */
	const char *norm;

	/* WHY it is in its group, in a few words: "random 8-hex basename",
	 * "under a user profile", "a system module". "" for stable. Printed
	 * beside the fingerprint so the grouping can be overruled by whoever
	 * reads it. */
	const char *why;

	/* The bytes, for the file kinds. `why_not` says why not, when not. */
	struct kof_fp_bytes   bytes;
	struct kof_fp_verdict verdict;

	/*
	 * WAS THIS STRING ACTUALLY IN THE SAMPLE'S BYTES - the answer that
	 * turns an observation into signature material.
	 *
	 * KOF_FP_SEEN_*. A trace says which strings are worth looking for; the
	 * engine says whether they are there. "Absent" is not a null result: it
	 * means the string was BUILT at runtime or decrypted, which tells a
	 * researcher to go and find the decryptor instead of writing a string
	 * that will never match.
	 */
	uint8_t  in_sample;
};

/* kof_fingerprint.flags */
enum {
	/* The text was cut - the record's arena filled, or a script is longer
	 * than a record. A signature written from a truncated string matches a
	 * prefix, which is a different rule than the author thinks. */
	KOF_FP_F_CUT      = 1u << 0,

	/* The path is the one the report itself, or the tool that made it,
	 * wrote. Its own flag rather than being dropped: a reader has to be
	 * able to see that the tool's own log is not the sample's work. */
	KOF_FP_F_OURS     = 1u << 1,

	/* Seen in more than one process of the tree. */
	KOF_FP_F_SHARED   = 1u << 2,

	/* For a created file: it was deleted again before the run ended. The
	 * shape of a dropper cleaning up, and the reason the bytes are gone. */
	KOF_FP_F_SELF_DEL = 1u << 3,

	/*
	 * WHATEVER MATCHED IN THE SAMPLE MATCHED AS UTF-16.
	 *
	 * A flag as well as KOF_FP_SEEN_WIDE, because the two answer different
	 * questions and the pair is not redundant: `in_sample` says HOW MUCH of
	 * the string is there, and this says HOW IT IS ENCODED. A path whose
	 * basename alone is present, as UTF-16, is KOF_FP_SEEN_PART with this
	 * set - and without the flag a signature draft would declare that
	 * basename with KOF_DEFINE_STR and match nothing.
	 */
	KOF_FP_F_WIDE     = 1u << 4
};

/* kof_fingerprint.in_sample */
enum {
	KOF_FP_SEEN_UNASKED = 0,  /* no engine, or nothing to search */
	KOF_FP_SEEN_PRESENT,      /* found as bytes in the subject */
	KOF_FP_SEEN_WIDE,         /* found as UTF-16 - KOF_DEFINE_STR_WIDE */
	KOF_FP_SEEN_PART,         /* only a fragment of it is there */
	KOF_FP_SEEN_ABSENT        /* not there: constructed or decrypted */
};

/* "present", "wide", "absent", ... Never NULL. */
const char *kof_fp_seen_name(uint8_t in_sample);

/* ------------------------------------------------------------- the process */

/*
 * ONE PROCESS OF THE TREE, kept apart from the fingerprints because it is what
 * they are attributed TO.
 *
 * (pid, create_time) and not pid: a pid is reused, sometimes within seconds,
 * and a report that merged two processes because the number came round again
 * would attribute one program's writes to another. The same pair kofevt.h
 * insists on.
 */
struct kof_rep_proc {
	uint32_t pid, ppid;
	uint64_t create_time;
	uint64_t started, stopped;   /* stamps; stopped 0 = still running */
	uint32_t exit_code;
	uint8_t  exited;
	uint8_t  cmd_raced;          /* the command line was lost, not absent */
	const char *image;
	const char *cmdline;

	/* Where this process sits under the root, so a text report can indent
	 * the tree without walking it twice. 0 is the root. */
	uint32_t depth;
};

/* ------------------------------------------------------------ the run */

/*
 * WHAT THE RUN WAS - filled by the caller at open, printed at the top of the
 * report, and the half that makes everything below it readable.
 *
 * The completeness fields are not an appendix. A report whose trace dropped
 * four thousand events is a report with holes, and a reader who does not know
 * that will read an absence as evidence. They are printed high up for that
 * reason.
 */
struct kof_report_info {
	const char *tool;          /* "kofmontrace" */
	const char *subject;       /* the program that was launched */
	const char *subject_cmd;   /* with its arguments */
	uint32_t    root_pid;
	uint32_t    build;         /* KOFENG_BUILD */
	uint8_t     platform;      /* enum kof_evt_platform */
	uint8_t     arch;          /* enum kof_evt_arch */
	uint32_t    sub_asked;     /* KOFW_SUB_* the run requested */
	uint32_t    sub_enabled;   /* what the providers accepted */
	uint64_t    started;       /* kof_evt_now() at launch */

	/* The case directory. Collected files and evidence go under it, and
	 * the report's own paths are relative to it so a directory can be
	 * moved or sent somewhere and still read. */
	const char *dir;

	/* The recorded log, relative or absolute, or NULL. What makes every
	 * `first_index` in the report a pointer at something replayable. */
	const char *log;
};

/* How the run ended, because it decides how to read a trace that shows
 * nothing after a point. */
enum kof_rep_end {
	KOF_END_UNKNOWN = 0,
	KOF_END_INTERRUPT,      /* Ctrl-C */
	KOF_END_TIMEOUT,
	KOF_END_TREE_EXIT,      /* --until-exit, and the tree emptied */
	KOF_END_ERROR
};

/* ------------------------------------------------------------ the API */

struct kof_report;

/*
 * Open a report over a run. Copies everything it needs out of `info`, so the
 * caller's strings need not outlive the call.
 *
 * Returns NULL only if it could not allocate. A report with no directory is
 * legal and collects nothing - which is what a caller who only wants the
 * summary asks for.
 */
struct kof_report *kof_report_open(const struct kof_report_info *info);
void kof_report_close(struct kof_report *);

/*
 * MAKE THE REPORT DIRECTORY, AND EVERY LEVEL ABOVE IT. Returns 0, or
 * KOF_ERR_OPEN.
 *
 * Exposed because the moment to find out that a path cannot be written is
 * BEFORE the sample runs, not after. kof_report_finish makes the directory too
 * - it has to, since it writes into it - but by then a live sample has been
 * executed, its artefacts have been collected, and the only thing left to do
 * with a failure is print it. A host that intends to write a report calls this
 * while it can still decline to run anything.
 *
 * Content with the directory already existing, so it is safe to call twice.
 */
int kof_report_mkpath(const char *dir);

/*
 * ONE EVENT. Called once per event the run KEPT, before it is rendered.
 *
 * `index` is the record's position in the log, or KOF_REP_NO_INDEX when
 * nothing is being recorded. It is not the event count: a caller that skipped
 * recording some events must pass what the log actually holds, because the
 * whole value of the number is that `kofviewer <log>` can be pointed at it.
 *
 * BEFORE RENDERING AND NOT AFTER, and not inside a quiet check either. A
 * report that was fed from the printing path would differ between a --quiet
 * run and a loud one, which is the bug kofevtfmt.h was split to fix - the
 * tally used to be counted inside the print switch, so the numbers were a side
 * effect of somebody looking at them.
 *
 * Bounded: hashes the strings it stores, bumps counters, and returns. It opens
 * no file and asks the OS nothing.
 */
#define KOF_REP_NO_INDEX 0xffffffffffffffffull
void kof_report_feed(struct kof_report *, const struct kof_evt *,
		     uint64_t index);

/* How the run ended, and how long it lasted. Told rather than inferred: only
 * the caller knows whether Ctrl-C arrived or a deadline passed. */
void kof_report_ended(struct kof_report *, enum kof_rep_end, double seconds);

/* The trace's own health, so the report can say what it did not see. Both
 * structures come from the collector; a replay from a log passes what the log
 * header recorded. */
void kof_report_health(struct kof_report *, const struct kof_evt_health *,
		       uint64_t filtered_out_of_tree);

/*
 * WHAT THE EXPENSIVE HALF IS ALLOWED TO DO.
 *
 * Every ceiling is here rather than compiled in, because the right answer
 * differs between an interactive run on one sample and an unattended one over
 * a corpus, and because a tool that copies without a ceiling is one bad sample
 * away from filling a disk.
 */
struct kof_report_stage {
	/* Copy files the tree created into <dir>/files/<digest>. Off means
	 * they are still hashed and reported, just not kept. */
	unsigned collect;

	/* Per collected file. A file over this is hashed if it can be and
	 * reported as KOF_FP_WHY_TOO_BIG rather than copied. 0 takes a
	 * built-in ceiling. */
	uint64_t max_file_bytes;

	/* Total bytes read back for write ranges, over the whole run. The
	 * ranges are read in first-seen order, so what is dropped when this
	 * runs out is the least interesting end. 0 takes a built-in ceiling. */
	uint64_t max_evidence_bytes;

	/*
	 * The engine, or NULL. NULL is a legal, useful report: no digest gets
	 * a verdict, no dropped file gets a format, no string gets checked
	 * against the sample's bytes, and every one of those says
	 * "unanswered" rather than showing an empty column.
	 *
	 * The scanner is the caller's because it carries the caller's options
	 * and its stats; this borrows it for the duration of the call.
	 */
	kof_engine  *engine;
	kof_scanner *scanner;
};

/*
 * THE SECOND PHASE. Call once, AFTER the traced tree is dead.
 *
 * Collects, hashes, reads back write ranges, and asks the engine about what it
 * collected. Returns the number of artefacts it looked at, or a negative
 * KOF_ERR_*. Every per-artefact failure is recorded on the fingerprint rather
 * than returned, because one unreadable file must not cost the report.
 *
 * Idempotent-ish by design: calling it twice does the work twice and reports
 * what it finds the second time. Nothing depends on that; it is stated so that
 * a caller retrying after mounting something is not surprised.
 */
int kof_report_finish(struct kof_report *, const struct kof_report_stage *);

/* ------------------------------------------------------------- reading it */

/* How many fingerprints the report holds, and the i'th of them - in
 * (group, kind, first_seen) order, which is reading order. NULL past the end. */
size_t kof_report_count(struct kof_report *);
const struct kof_fingerprint *kof_report_at(struct kof_report *, size_t i);

/* The processes, in tree order: a parent always precedes its children, so a
 * printer can indent by `depth` in one pass. */
size_t kof_report_procs(struct kof_report *);
const struct kof_rep_proc *kof_report_proc_at(struct kof_report *, size_t i);

/*
 * HOW MANY WERE NOT KEPT, per kind.
 *
 * The tables are bounded, so a program that writes ten thousand distinct
 * registry values overflows. Reported per kind and never silently: a report
 * that listed 512 registry writes without saying there were more would be
 * telling a reader the list is the whole story.
 */
uint64_t kof_report_dropped(struct kof_report *, uint8_t kind);

/* --------------------------------------------------------------- writing it */

/*
 * THE HUMAN REPORT.
 *
 * `color` asks for ANSI attributes - pass it only for a terminal. It is a
 * parameter and not a detection, because this library does not know whether
 * `out` is a console: a report written to a file with escapes in it is a
 * report nobody can grep, and the caller is the one holding the FILE.
 */
int kof_report_write_text(struct kof_report *, FILE *out, int color);

/*
 * THE MACHINE REPORT - the same model, nothing summarised away.
 *
 * One walker feeds both emitters, so the two cannot disagree about what the
 * run found. That is the same argument kofevtfmt.h makes about two renderers
 * of one event, and it drifted there once already.
 */
int kof_report_write_json(struct kof_report *, FILE *out);

/*
 * THE SIGNATURE DRAFT - candidate strings in the vocabulary kofeditor already
 * writes .c files from.
 *
 * NOT A .c FILE, ON PURPOSE. kofeditor is the signature generator - see
 * kofeditor.c, which writes KOF_DEFINE_STR and KOF_TARGET_RANGE today - and a
 * second generator here would be a second generator to drift. This writes the
 * candidates: bytes, whether they were found wide, the range they were found
 * in, the group and the reason. A one-way dependency, and no shared code.
 *
 * Every candidate carries its verification state, so the draft distinguishes
 * a string that is in the sample from one the sample built at runtime. A
 * signature written from the second matches nothing, and nothing else in the
 * output would have said so.
 */
int kof_report_write_candidates(struct kof_report *, FILE *out);

#endif /* KOFREPORT_H */
