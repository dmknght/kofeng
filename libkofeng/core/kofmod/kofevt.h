/*
 * kofevt.h - deciding whether what a machine DID was malicious.
 *
 * THIS IS A DESIGN, NOT AN IMPLEMENTATION. Nothing includes it yet. It is
 * written as a header because in this tree the header is where the reasoning
 * lives, and because the types below are the part that has to be agreed before
 * any of it can be built.
 *
 *
 * WHERE IT SITS
 *
 *     libkofgrille (Windows)  ---\
 *                                 >--- struct kof_evt ---> bases/evts rules
 *     a Linux collector       ---/
 *
 * libkofeng takes bytes and says what they are. This takes a machine's own
 * activity and says the same thing about it. The two meet at a caller, not at
 * an #include: kofgrille.h does not include kofeng.h and must not start.
 *
 * So the record below is NOT struct kofw_evt. kofw_evt is what one collector on
 * one operating system produces; this is what a rule is written against, and a
 * rule that names an ETW event id is a rule that cannot fire on Linux. The
 * translation happens once, in each collector, at the edge - the same argument
 * kofgrille.h already makes for classifying a path there rather than in every
 * consumer.
 *
 *
 * THE ONE FACT THAT SHAPES EVERY DECISION BELOW
 *
 * EVENTS DO NOT ARRIVE IN ORDER. kofgrille.h says it plainly: ETW buffers are
 * per processor, so records cross CPUs out of order and a consumer that needs a
 * sequence has to sort over a window. Linux is no kinder - a perf ring is per
 * CPU too.
 *
 * Every "sequence matching" design collapses on that sentence. A rule engine
 * that matches A-then-B-then-C against the arrival order is not matching what
 * the machine did, it is matching how the buffers drained, and it will miss on
 * a loaded machine and hit on an idle one. It is also the failure mode nobody
 * notices, because the rule still fires sometimes.
 *
 * So the model here is NOT a sequence automaton. It is a set of FACTS per
 * subject, each stamped with when it was first true, and a rule is a predicate
 * over that set. Order, where a rule genuinely needs it, is asked for
 * explicitly as a comparison between two stamps with a tolerance - which is a
 * question the data can actually answer.
 *
 *
 * WHAT IS DELIBERATELY NOT HERE
 *
 * NO SCORE. Not an oversight and not a stage to be added later: every scoring
 * approach over this engine's findings was measured and rejected, the depth
 * term and the heuristic levels were removed after measuring them, and nothing
 * here reopens that. A rule fires or it does not. Two rules firing is two
 * findings, not a bigger number - a reader can see two findings and cannot see
 * what went into a 73.
 */

#ifndef KOFMOD_KOFEVT_H
#define KOFMOD_KOFEVT_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------- verbs */

/*
 * WHAT HAPPENED, in words that mean the same thing on both operating systems.
 *
 * Chosen so that each one is a fact a rule is actually written against. The
 * test applied to every candidate was: can somebody state a detection in one
 * sentence using it? "A file appeared" passes. "A file was opened" does not,
 * which is why the read side of the file API is absent here exactly as it is
 * absent from KOFW_SUB_FILE.
 *
 * The Windows column is what libkofgrille already produces. The Linux column is
 * what a collector would have to produce, and is listed here rather than left
 * to that collector because a verb only one platform can raise is a verb that
 * makes rules unportable without saying so.
 */
enum kof_evt_verb {
	KOF_EVT_NONE = 0,

	/*                          Windows                 Linux            */
	KOF_EVT_PROC_START,   /* Kernel-Process 1      execve               */
	KOF_EVT_PROC_STOP,    /* Kernel-Process 2      exit_group           */

	/*
	 * A module was mapped as an IMAGE.
	 *
	 * The word "mapped" is load-bearing and is the honest limit of this
	 * verb: it fires when the kernel maps an image section, so a library
	 * that was manually mapped into private memory raises nothing at all.
	 * That is not a gap in a collector, it is the absence of the event, and
	 * a rule written on this verb alone cannot see a reflectively loaded
	 * payload. KOF_EVT_MEM_EXEC below is the verb for that, and it costs
	 * more to collect.
	 */
	KOF_EVT_IMAGE_LOAD,   /* Kernel-Process 5      mmap PROT_EXEC, file */

	KOF_EVT_FILE_NEW,     /* Kernel-File 30        creat/openat O_CREAT */
	KOF_EVT_FILE_WRITE,   /* Kernel-File WRITE     write to existing    */
	KOF_EVT_FILE_DELETE,  /* Kernel-File 26        unlink               */
	KOF_EVT_FILE_RENAME,  /* Kernel-File 27        rename               */

	/*
	 * A FILE BECAME EXECUTABLE, which has no Windows half and is not a
	 * defect in this table.
	 *
	 * On Linux it is the single highest-value file event there is: a
	 * dropper writes a payload and then has to chmod +x it, and that second
	 * step is a narrower signal than the write. Windows has no equivalent
	 * because executability is not a file attribute there - the analogous
	 * fact is that the written file PARSES as a PE, which is a question for
	 * libkofeng and not for a collector.
	 */
	KOF_EVT_FILE_EXEC_BIT,/*  -                    chmod +x             */

	KOF_EVT_NET_CONNECT,  /* Kernel-Network 12     connect              */
	KOF_EVT_NET_SEND,     /* Kernel-Network 10     send                 */
	KOF_EVT_NET_RECV,     /* Kernel-Network 11     recv                 */
	KOF_EVT_NET_LISTEN,   /* Kernel-Network        listen - a backdoor  */
	KOF_EVT_NET_CLOSE,    /* Kernel-Network 13     close                */

	/*
	 * PERSISTENCE WAS WRITTEN, and this is one verb rather than eight on
	 * purpose.
	 *
	 * A Run key, a Startup shortcut, a service, a scheduled task, a systemd
	 * unit, a crontab, an authorized_keys line and a shell profile are the
	 * same claim - "this will run again without anybody asking" - expressed
	 * in eight file systems. The DIFFERENCE between them is not what a rule
	 * branches on; it is what a reader needs in the finding, and it travels
	 * in kof_evt.loc.
	 */
	KOF_EVT_PERSIST,

	/*
	 * PRIVILEGE OR IDENTITY CHANGED. setuid, a token stolen, a group
	 * added, a sudoers line written.
	 */
	KOF_EVT_PRIV,

	/*
	 * CODE WAS PUT SOMEWHERE IT COULD RUN, without a file behind it.
	 *
	 * Private memory made executable, a thread started at an address that
	 * is not in any mapped image, a write into another process. This is the
	 * verb that sees a reflectively loaded DLL, a .NET assembly loaded from
	 * a byte array, and shellcode staged over a socket - none of which
	 * raises KOF_EVT_IMAGE_LOAD, because none of them maps an image.
	 *
	 * IT IS ALSO THE EXPENSIVE ONE AND THE ONE A COLLECTOR MAY NOT BE ABLE
	 * TO RAISE AT ALL. On Linux it is reachable (a uprobe, or an LSM/eBPF
	 * hook on mprotect). On Windows the in-box provider that reports it is
	 * Microsoft-Windows-Threat-Intelligence, which is gated behind a
	 * protected-process signature an ordinary tool does not have. A design
	 * that pretends otherwise produces rules that never fire on half the
	 * fleet, so the limitation is written into the verb rather than
	 * discovered later.
	 */
	KOF_EVT_MEM_EXEC,

	/* A kernel module was loaded. Both platforms; on Linux it is what
	 * bases/signatures/diamorphine_*.c is about at rest. */
	KOF_EVT_MODULE_LOAD,

	/* Arrived, and this build has no verb for it. Kept for the same reason
	 * KOFW_EVT_RAW is kept: a collector that silently discarded what it
	 * could not name could not be used to find out what it should name. */
	KOF_EVT_RAW,

	KOF_EVT_VERB_COUNT
};

/* -------------------------------------------------------------- where */

/*
 * WHAT ROLE A PATH PLAYS - the same idea as enum kofw_loc, extended to the
 * places a technique cares about and to both operating systems.
 *
 * This is where MITRE ATT&CK is actually used, and the use is not what people
 * expect. The matrix is NOT a rule source: a technique is a name for a class of
 * behaviour, not a predicate, and a "rule" transcribed from a technique
 * description is a rule with no false-positive measurement behind it. What the
 * matrix is good for is deciding WHAT THE COLLECTOR MUST BE ABLE TO SEE - and
 * the persistence and defence-evasion columns turn almost entirely into paths.
 * So the matrix is read once, into this enum and the tables behind it, and
 * never again at match time.
 *
 * Classified in the collector, once, on the consumer thread - never by the
 * rule. A rule that matched paths as text would have to know about device
 * paths, 8.3 names, junctions, SysWOW64 redirection, symlinks, bind mounts and
 * /proc/self/root, in every rule, and would be evaded by respelling the same
 * location for free.
 */
enum kof_evt_loc {
	KOF_LOC_UNKNOWN = 0,  /* nothing to classify - not "nowhere interesting" */

	KOF_LOC_SYSTEM,       /* System32, WinSxS   | /usr/lib, /lib          */
	KOF_LOC_PROGRAMS,     /* Program Files      | /usr/bin, /opt          */
	KOF_LOC_TEMP,         /* AppData\Local\Temp | /tmp, /var/tmp, /dev/shm */
	KOF_LOC_USER,         /* a profile          | $HOME                    */

	/* ---- the ones the matrix put here, all of them "this runs again" ---- */

	KOF_LOC_AUTOSTART,    /* Run keys, Startup  | ~/.config/autostart      */
	KOF_LOC_SERVICE,      /* Services, IFEO     | systemd units, init.d    */
	KOF_LOC_SCHEDULE,     /* Scheduled Tasks    | cron.*, at, systemd timer */
	KOF_LOC_SHELL_INIT,   /* profile.ps1        | .bashrc, .profile, rc.local */
	KOF_LOC_PRELOAD,      /* AppInit_DLLs, KnownDLLs | /etc/ld.so.preload  */
	KOF_LOC_SSH,          /*  -                 | ~/.ssh/authorized_keys   */
	KOF_LOC_CREDENTIAL,   /* SAM, LSASS dump    | /etc/shadow, /etc/sudoers */
	KOF_LOC_KERNEL_MOD,   /* drivers            | /lib/modules             */
	KOF_LOC_WEB_ROOT,     /* inetpub            | /var/www - a webshell    */
	KOF_LOC_CONTAINER,    /*  -                 | /var/run/docker.sock     */

	/* Classified, and it is none of the above - which is a fact, not a
	 * failure to decide. */
	KOF_LOC_OTHER,

	KOF_LOC_COUNT
};

/*
 * THE WATCHER TABLE IS DATA, PER OPERATING SYSTEM, AND IT LIVES IN THE
 * COLLECTOR.
 *
 *     static const struct kof_loc_rule WIN_LOCS[] = {
 *         { KOF_LOC_PRELOAD,   "\\AppInit_DLLs" },
 *         { KOF_LOC_AUTOSTART, "\\CurrentVersion\\Run" },
 *         { KOF_LOC_AUTOSTART, "\\Start Menu\\Programs\\Startup\\" },
 *         { KOF_LOC_SCHEDULE,  "\\System32\\Tasks\\" },
 *         ...
 *     };
 *     static const struct kof_loc_rule LNX_LOCS[] = {
 *         { KOF_LOC_PRELOAD,   "/etc/ld.so.preload" },
 *         { KOF_LOC_SSH,       "/.ssh/authorized_keys" },
 *         { KOF_LOC_SCHEDULE,  "/etc/cron" },
 *         { KOF_LOC_SHELL_INIT,"/.bashrc" },
 *         ...
 *     };
 *
 * Longest and most specific wins, and the ORDER OF THE TABLE IS ITS
 * CORRECTNESS - kofw_classify_path already learned this the hard way with
 * temp-inside-a-profile. A generic \Users\ or $HOME entry that ran before
 * KOF_LOC_SSH would file every authorized_keys write as ordinary user
 * activity.
 *
 * Note /etc/ld.so.preload appears above and bases/signatures/ldpre_00.c
 * already exists: the same technique seen at rest and in motion. That pairing
 * is the point of building this at all.
 */
struct kof_loc_rule {
	uint8_t     loc;
	const char *needle;
};

/* ------------------------------------------------------------- the record */

/*
 * ONE EVENT, AS A RULE SEES IT.
 *
 * Fixed size for the same reason kofw_evt is: it is what a collector writes
 * into a ring without allocating, and it is what a recorded trace REPLAYS
 * from. The replay path is not a nice-to-have here - a detection rule that
 * cannot be run against a recorded trace cannot be regression tested, and a
 * false positive nobody can reproduce cannot be fixed.
 */
#define KOF_EVT_SIZE 512u

/* Everything above text[]; see the assertions below the struct. */
#define KOF_EVT_HEAD 72u

struct kof_evt {
	uint64_t stamp;        /* 100ns since 1601 on both, normalised in the
				* collector, so a rule never asks which clock */
	uint64_t seq;          /* arrival order; a gap is a dropped record */
	uint64_t create_time;  /* of the subject - (pid, create_time) names a
				* process, a pid alone does not */

	uint32_t pid;          /* the subject */
	uint32_t ppid;
	uint32_t actor_pid;    /* who caused it, which is not who it is about */
	uint32_t tid;

	uint32_t net_daddr, net_saddr;   /* v4; v6 in the tail when it lands */
	uint32_t net_size;
	uint16_t net_dport, net_sport;   /* network byte order, as the packet had */

	uint16_t verb;         /* enum kof_evt_verb */
	uint16_t raw_id;       /* the source's own id, for a RAW event */
	uint8_t  loc;          /* enum kof_evt_loc, of the OBJECT */
	uint8_t  os;           /* enum kof_evt_os - which collector made it */
	uint8_t  flags;
	uint8_t  miss;         /* fields the collector could not fill */

	uint16_t off_image;    /* what the subject IS */
	uint16_t off_object;   /* what the event ACTED ON */
	uint16_t text_len;
	uint8_t  reserved[2];

	char     text[KOF_EVT_SIZE - KOF_EVT_HEAD];
};

/*
 * ASSERTED HERE RATHER THAN DESCRIBED IN A COMMENT.
 *
 * libkofgrille's header said its equivalent constant was "asserted against the
 * real offset in the .c", and it was not, for the whole life of the file. A
 * sentence claiming an assertion exists is worth nothing; the assertion costs
 * one line and fails the build.
 */
_Static_assert(offsetof(struct kof_evt, text) == KOF_EVT_HEAD,
	       "KOF_EVT_HEAD no longer matches the record layout");
_Static_assert(sizeof(struct kof_evt) == KOF_EVT_SIZE,
	       "struct kof_evt is not KOF_EVT_SIZE bytes");

enum kof_evt_os { KOF_OS_WINDOWS = 1u << 0, KOF_OS_LINUX = 1u << 1 };

/* ------------------------------------------------------------------ facts */

/*
 * WHAT IS TRUE OF ONE SUBJECT SO FAR.
 *
 * A fact is derived from a single event by a pure function of (verb, loc,
 * flags) - see kof_evt_facts_of() - and then STAYS TRUE for the life of the
 * process, with the stamp of when it first became true.
 *
 * WHY FACTS AND NOT A SEQUENCE LANGUAGE, restated because it is the whole
 * design: the input is unordered within a window, so an automaton over arrival
 * order is matching the wrong thing. A fact bitmap is order-free by
 * construction. It is also what makes the cost sane - a rule's precondition
 * becomes one AND of two 64-bit words, so the engine can decide not to run a
 * rule without running any of it, exactly as heur_phase and heur_level are
 * prefilter fields the scan tests before loading a heuristic.
 *
 * Facts are deliberately COARSE. "Wrote an executable into temp" is a fact;
 * "wrote C:\Users\bob\AppData\Local\Temp\a.exe" is evidence, and evidence stays
 * on the record where a reader can see it. A fact set that grows a bit per path
 * is a fact set that stops fitting in a word and stops being cheap.
 */
enum {
	KOF_FACT_EXEC_FROM_TEMP     = 1ull << 0,  /* ran an image out of temp   */
	KOF_FACT_EXEC_FROM_USER     = 1ull << 1,
	KOF_FACT_DROPPED_EXEC       = 1ull << 2,  /* created a file that parses
						   * as an executable          */
	KOF_FACT_DROPPED_IN_TEMP    = 1ull << 3,
	KOF_FACT_MADE_EXECUTABLE    = 1ull << 4,  /* chmod +x, Linux            */
	KOF_FACT_WROTE_PERSISTENCE  = 1ull << 5,
	KOF_FACT_WROTE_PRELOAD      = 1ull << 6,
	KOF_FACT_WROTE_SSH_KEY      = 1ull << 7,
	KOF_FACT_READ_CREDENTIALS   = 1ull << 8,
	KOF_FACT_NET_EGRESS         = 1ull << 9,  /* connected outward          */
	KOF_FACT_NET_LISTEN         = 1ull << 10, /* accepted inward - backdoor */
	KOF_FACT_NET_BULK_IN        = 1ull << 11, /* received more than a
						   * configuration's worth      */
	KOF_FACT_LOADED_UNSIGNED    = 1ull << 12,
	KOF_FACT_LOADED_FROM_TEMP   = 1ull << 13, /* mapped a module out of temp */
	KOF_FACT_MEM_EXEC           = 1ull << 14, /* private memory made runnable */
	KOF_FACT_MODULE_LOADED      = 1ull << 15,
	KOF_FACT_PRIV_RAISED        = 1ull << 16,
	KOF_FACT_DELETED_SELF       = 1ull << 17,
	KOF_FACT_MASS_DELETE        = 1ull << 18, /* ransomware's own shape      */
	KOF_FACT_MASS_REWRITE       = 1ull << 19,
	KOF_FACT_SPAWNED_SHELL      = 1ull << 20,
	KOF_FACT_SPAWNED_LOLBIN     = 1ull << 21  /* an interpreter, by name     */
};

/*
 * THE ONLY PLACE A VERB BECOMES A FACT.
 *
 * One function, pure, no OS in it - so it replays, and so two rules can never
 * disagree about whether something counted. A rule that computed its own facts
 * would be the second implementation, and the two would drift.
 */
uint64_t kof_evt_facts_of(const struct kof_evt *);

/*
 * PER-SUBJECT STATE, and it is fixed size for the same reason as everything
 * else here: a collector under load must not be able to allocate.
 *
 * Keyed on (pid, create_time). A pid alone is reused, sometimes within seconds,
 * and a table keyed on the number confidently answers for another process.
 */
struct kof_evt_track {
	uint32_t pid;
	uint64_t create_time;
	uint32_t root_pid;      /* the tree this belongs to, 0 if none */

	uint64_t facts;
	/*
	 * WHEN EACH FACT FIRST BECAME TRUE.
	 *
	 * This is what buys back ordering without an automaton. A rule that
	 * genuinely needs "the drop happened before the execution" asks
	 * kof_evt_ordered(), which compares two of these with a tolerance -
	 * and the tolerance is not a fudge, it is the width of the reordering
	 * the transport is documented to produce.
	 */
	uint64_t at[64];

	/* Counters a threshold is computed over. Kept apart from facts because
	 * a count is not a boolean and rounding it into one at collection time
	 * throws away the only thing a threshold could have used. */
	uint32_t n_files_deleted, n_files_rewritten, n_children, n_connects;
	uint64_t bytes_in, bytes_out;
};

/*
 * Did `first` become true before `then`, within `window_ms`?
 *
 * Non-zero when both are set and the stamps agree, with the transport's
 * reordering tolerance already applied. A rule must never subtract .at[]
 * entries itself - that is how a tolerance ends up spelled three ways.
 */
int kof_evt_ordered(const struct kof_evt_track *, uint64_t first,
		    uint64_t then, uint32_t window_ms);

/* -------------------------------------------------------- the matching loop */

/*
 * WHAT RUNS PER RECORD, AND WHAT DOES NOT.
 *
 * Per record, always:
 *
 *   1. facts = kof_evt_facts_of(e)           one switch, no allocation
 *   2. t = track_of(e->pid, e->create_time)  open-addressed, as kofw_ptab is
 *   3. new = facts & ~t->facts               what this record actually added
 *      if (!new) return                      NOTHING ELSE RUNS. This is the
 *                                            common case by a wide margin -
 *                                            the hundredth write into temp
 *                                            tells no rule anything the first
 *                                            one did not.
 *   4. t->facts |= new; stamp each new bit
 *   5. candidates = 0
 *      for each bit b in new: candidates |= rules_wanting[b]
 *                                            a precomputed 64-entry table of
 *                                            rule bitmaps, built once at load
 *   6. for each rule r in candidates:
 *          if ((t->facts & r->needs) != r->needs) continue
 *          run r
 *
 * Step 3 is what makes this affordable and it is the step a naive design
 * leaves out. Step 5 is the same shape as the engine's existing pattern
 * presence index, and it is worth what that one is worth for the same reason:
 * it decides which rules CANNOT match without touching any of them.
 *
 * A rule body therefore runs only when every fact it named is already true.
 * The body exists for the things a bitmask cannot say - a threshold, an
 * ordering, a look at the actual path - and for producing the finding.
 */

/* ------------------------------------------------------------- bases/evts */

/*
 * A RULE IS A COMPILED MODULE, like every other kind in bases/.
 *
 * Not a text DSL, and the reason is the same one that keeps bases/signatures
 * in C: a declarative format needs a parser, the parser needs its own tests,
 * and the first rule that wants a threshold or a substring needs an escape
 * hatch that the format then has to grow. The macros below are declarative
 * where declaring is enough and get out of the way where it is not - which is
 * exactly the split KOF_HEUR_PHASE / KOF_DEFINE_HEUR already make.
 *
 *
 *     bases/evts/dropper_temp_exec_00.c
 *
 *         #include <kofmod/kofevt.h>
 *
 *         KOF_EVT_NAME("Dropper.TempExec");
 *         KOF_EVT_MALTYPE(KOF_MALTYPE_DROPPER);
 *         KOF_EVT_PLATFORM(KOF_OS_WINDOWS | KOF_OS_LINUX);
 *
 *         // The prefilter. The body does not run until all of these are true,
 *         // so this line is what keeps the rule off the hot path entirely.
 *         KOF_EVT_NEEDS(KOF_FACT_DROPPED_EXEC | KOF_FACT_DROPPED_IN_TEMP |
 *                       KOF_FACT_EXEC_FROM_TEMP);
 *
 *         // Reporting only. Never matched on, never summed. See the note on
 *         // enum kof_evt_loc for why the matrix is an input to the collector
 *         // and not to the matcher.
 *         KOF_EVT_ATTACK("T1204.002");
 *
 *         KOF_DEFINE_EVT
 *         {
 *                 // The one thing the bitmask cannot say: that the drop came
 *                 // FIRST. Without it this also fires on a program that runs
 *                 // from temp and later writes something there, which is what
 *                 // an installer does.
 *                 if (!kof_evt_ordered(t, KOF_FACT_DROPPED_EXEC,
 *                                      KOF_FACT_EXEC_FROM_TEMP, 30000))
 *                         return;
 *                 KOF_EVT_HIT();
 *         }
 *
 *
 *     bases/evts/persist_preload_00.c
 *
 *         KOF_EVT_NAME("Persist.Preload");
 *         KOF_EVT_MALTYPE(KOF_MALTYPE_ROOTKIT);
 *         KOF_EVT_PLATFORM(KOF_OS_LINUX);
 *         KOF_EVT_NEEDS(KOF_FACT_WROTE_PRELOAD);
 *         KOF_EVT_ATTACK("T1574.006");
 *
 *         // One fact is the whole rule, and that is allowed. Writing
 *         // /etc/ld.so.preload is not ambiguous, and a rule that added
 *         // conditions to look more thorough would only add ways to miss.
 *         KOF_DEFINE_EVT { KOF_EVT_HIT(); }
 *
 *
 * The macros expand to nothing in the module and are read out of the compiled
 * object by ksigbuilder, exactly as KOF_HEUR_PHASE is - so a field that gates
 * whether the rule runs is in the PACK, where the engine can test it without
 * loading the module.
 */
#define KOF_EVT_NAME(word)
#define KOF_EVT_MALTYPE(m)
#define KOF_EVT_PLATFORM(mask)     /* enum kof_evt_os, prefilter */
#define KOF_EVT_NEEDS(facts)       /* enum KOF_FACT_*, prefilter */
#define KOF_EVT_ATTACK(technique)  /* reporting only, never matched on */

#define KOF_DEFINE_EVT \
	void kof_evt_rule(const struct kof_evt *e, const struct kof_evt_track *t)

/* ----------------------------------------------------------- what is needed */

/*
 * THE ORDER THIS HAS TO BE BUILT IN, and it is not the interesting-first
 * order.
 *
 *   1. THE REPLAY PATH, BEFORE ANY RULE EXISTS.
 *      A recorded stream of struct kof_evt, read back through the same fact
 *      and match code a live collector uses. Everything below is untestable
 *      without it, and libkofgrille has already demonstrated what happens when
 *      the recorder is left for later: kofgrille.h presents replayability as
 *      the reason its record is normalised at all, and there is no recorder
 *      in it.
 *
 *   2. THE FACT FUNCTION AND THE TRACK TABLE. Pure C, no OS, unit tested on
 *      the host - the same side of the line as wfilter.c and wtext.c.
 *
 *   3. THE LINUX COLLECTOR, second rather than first, because the design above
 *      is only proven portable once something other than ETW has produced a
 *      kof_evt. fanotify gives the file verbs without a kernel module; the
 *      process verbs come from a netlink connector or from eBPF where it is
 *      available. Whichever it is, it produces struct kof_evt and nothing
 *      above it learns which.
 *
 *   4. RULES, LAST, AND MEASURED THE WAY THE HEURISTICS WERE. A rule ships
 *      with a false-positive count over a recorded clean-machine trace, or it
 *      does not ship. The shellcode heuristic in this tree carries "0 false
 *      positives in 5252 clean objects" because somebody counted; an event
 *      rule without that number is a guess with a technique id next to it.
 */

#endif /* KOFMOD_KOFEVT_H */
