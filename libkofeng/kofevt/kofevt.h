/*
 * kofevt.h - deciding whether what a machine DID was malicious.
 *
 * WHAT THIS OWNS, and it is one job stated three ways: an event, normalised
 * to bytes. The verb it happened under, where it happened, which technique
 * that location IS, the record those go in, and the log those records are
 * written to.
 *
 * WHAT IT DOES NOT OWN: collecting. libkofgrille reads ETW and a Linux twin
 * will read whatever Linux offers; both of them produce what is defined here
 * and neither defines any of it. A tool then picks a collector by what it was
 * built for and reads the same record either way.
 *
 * THE ENUMS ARE HERE AND NOWHERE ELSE. They used to be declared in
 * kofgrille.h and mirrored here, which is a shape that works exactly until the
 * two copies disagree - and then a conversion between them compiles, runs, and
 * silently files every module load as a process start. One definition, included
 * by the collector, is the only version of this that cannot rot.
 *
 *
 * WHY IT IS HERE AND NOT IN core/kofmod/
 *
 * It was in core/kofmod/, and that was wrong. That directory is elf.h, pe.h,
 * zip.h, pdf.h, tar.h - descriptions of what a SCANNED TARGET looks like, which
 * a compiled module in bases/ includes in order to read one. An event record is
 * none of those things: it is a format this toolset defines for itself, in the
 * same sense kofdb/kofpack.h defines .ksig, and filing it beside the target
 * parsers makes both harder to find.
 *
 * The rule, stated so the next file lands correctly: core/kofmod/ is what a
 * compiled module in bases/ includes. Everything else the toolset defines for
 * its own use goes with the code that owns it.
 *
 * NOTHING HERE INCLUDES ANYTHING ELSE FROM libkofeng, and that is structural
 * rather than a promise. This directory is under libkofeng because events are
 * the engine's business eventually, but the files use stdint, stddef and stdio
 * and nothing more - so libkofgrille can include them without acquiring a
 * dependency on the engine, and kofgrille.h's rule that it never includes
 * kofeng.h stays true.
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

#ifndef KOFEVT_H
#define KOFEVT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ------------------------------------------------------------------- verbs */

/*
 * WHAT HAPPENED, in words that mean the same thing on every platform.
 *
 * The test applied to every candidate was: can somebody state a detection in
 * one sentence using it? "A file appeared" passes. "A file was opened" does
 * not - which is why the read side of the file API is absent, and why the one
 * exception (a named pipe) is a pipe rather than a file.
 */
enum kof_evt_verb {
	KOF_EVT_NONE = 0,

	/*
	 * A process began or ended.
	 *
	 * The lowest volume of anything worth having - single digits per second on
	 * an idle desktop, a few hundred during a build - and the highest value,
	 * which is why it is the only pair the first version subscribes to.
	 */
	KOF_EVT_PROC_START = 1,
	KOF_EVT_PROC_STOP  = 2,

	/*
	 * A module was mapped into a process. Medium volume - it bursts when an
	 * application starts and is quiet otherwise - and it is where a DLL
	 * loaded out of a temporary directory becomes visible.
	 */
	KOF_EVT_IMAGE_LOAD = 3,

	/*
	 * THE FILE EVENTS, AND THE ONES DELIBERATELY MISSING.
	 *
	 * A file APPEARED, was unlinked, or was renamed. Not opened, not read,
	 * not written-to. That distinction is the whole reason file tracing is
	 * affordable at all: Kernel-File's CREATE keyword fires on every open a
	 * machine performs, while CREATE_NEW_FILE fires only when a file comes
	 * into existence, and the ratio between them is orders of magnitude on
	 * any machine doing work.
	 *
	 * Nothing is lost for the evidence this is collected for. "Something
	 * read a file" is not a fact anybody writes a rule against; "an
	 * executable appeared in a startup directory" is.
	 */
	KOF_EVT_FILE_NEW    = 4,
	KOF_EVT_FILE_DELETE = 5,
	KOF_EVT_FILE_RENAME = 6,

	/*
	 * Something arrived that this build has no type for.
	 *
	 * Kept rather than dropped, and this is not laziness. Event ids differ
	 * between Windows builds, and an id nobody typed yet is exactly what a
	 * discovery run is looking for - so it carries its provider, id and
	 * version, and whatever strings its payload held. A collector that
	 * silently discarded these could not be used to find out what it should
	 * be collecting.
	 */
	KOF_EVT_RAW = 7,

	/*
	 * TCP, and the four that carry the evidence.
	 *
	 * CONNECT and DISCONNECT are low volume and name the other end, which is
	 * the fact worth keeping - a C2 address is a connect, not a payload.
	 * SEND and RECV fire per operation and are the high-volume pair; they
	 * are here because their SIZES are what a threshold is eventually
	 * computed over, not because every one of them needs to be stored.
	 *
	 * IPv6 has its own ids and is not typed yet, so it still arrives as RAW.
	 */
	KOF_EVT_NET_CONNECT    = 8,
	KOF_EVT_NET_SEND       = 9,
	KOF_EVT_NET_RECV       = 10,
	KOF_EVT_NET_DISCONNECT = 11,

	/*
	 * A module was unmapped. Low value on its own and typed anyway, because
	 * the id was already being let through the provider filter and was
	 * arriving as RAW - which cost the same and told nobody anything.
	 */
	KOF_EVT_IMAGE_UNLOAD = 12,

	/*
	 * DATA WAS WRITTEN INTO A FILE THAT ALREADY EXISTED.
	 *
	 * Separate from FILE_NEW because they answer different questions: one
	 * says a file APPEARED, the other says data LANDED in one. A payload
	 * written over something innocuous creates nothing and raises no
	 * FILE_NEW at all.
	 */
	KOF_EVT_FILE_WRITE = 13,

	/*
	 * THE REGISTRY, and it is three verbs rather than one.
	 *
	 * A key being created, a value being set and either being deleted are
	 * different claims and a rule branches on which. The autorun case wants
	 * VALUE_SET; a rootkit hiding a service wants DELETE; a key appearing
	 * under a hive that has none is CREATE.
	 *
	 * The path travels in `object`, as every other object path does, so
	 * nothing downstream needs a registry-shaped field.
	 */
	KOF_EVT_REG_CREATE    = 14,
	KOF_EVT_REG_SET_VALUE = 15,
	KOF_EVT_REG_DELETE    = 16,

	/*
	 * A THREAD STARTED, AND WHY IT IS HERE AFTER BEING REFUSED ONCE.
	 *
	 * The THREAD keyword was left off with the note that it is an order of
	 * magnitude more traffic than the others and nothing reads it. The
	 * first half is true. The second stopped being true the moment the
	 * question became "why do we not see a DLL that was loaded in memory".
	 *
	 * IMAGE_LOAD fires when the kernel maps an image SECTION. A payload
	 * that was allocated, copied, relocated and had its imports resolved by
	 * hand never maps one, so there is no image event to miss - the event
	 * does not exist.
	 *
	 * WHAT THIS CATCHES, AND WHAT IT DOES NOT. It catches execution that
	 * arrives on a NEW thread: a remote injection, and a reflective load
	 * whose payload starts a thread of its own.
	 *
	 * It does not catch the transfer itself in the common Metasploit shape,
	 * and that was a wrong claim here until somebody ran one. A stager
	 * receives its payload into a buffer, casts the buffer to a function
	 * pointer and CALLS it - on the thread it already had. No thread is
	 * created, so no event of any kind marks the moment control passes into
	 * memory that was never a file. There is no in-box event for a call,
	 * and no arrangement of these providers produces one.
	 *
	 * The signal survives that only because of what happens AFTER: the
	 * reflective loader resolves its imports through LoadLibrary, which
	 * does map sections and does raise IMAGE_LOAD - see KOFW_EF_LATE_LOAD -
	 * and a payload like meterpreter goes on to start threads of its own,
	 * which is when KOFW_EF_UNBACKED finally fires. Both are late relative
	 * to the transfer. Neither is the transfer.
	 *
	 * ESTABLISHED, and the answer is yes. Kernel-Process ThreadStart is
	 * event 3 version 1 and carries ten properties, two of which are
	 * addresses:
	 *
	 *     StartAddr        where the kernel begins the thread - the same
	 *                      ntdll stub for every ordinary thread
	 *     Win32StartAddr   the routine the thread was created to run
	 *
	 * Only the second can answer the question, because the first is inside
	 * ntdll for injected and innocent threads alike. It is what lands in
	 * kofw_evt.addr, and KOFW_EF_UNBACKED is set when it falls in no image
	 * the process was watched mapping.
	 */
	KOF_EVT_THREAD_START = 17,
	KOF_EVT_THREAD_STOP  = 18,

	/*
	 * AN APPLICATION SUBMITTED A BUFFER TO AmsiScanBuffer.
	 *
	 * The only CONTENT this collector ever sees. Every other event says that
	 * something happened - a file appeared, a connection opened, a thread
	 * started somewhere odd. This one says what a script actually contained,
	 * after the scripting host expanded it: a decoded -EncodedCommand, a
	 * script block a downloader built at run time, a macro body.
	 *
	 * THE CONTENT IS A PREFIX, NOT THE WHOLE BUFFER. A record is 512 bytes,
	 * of which the text arena is the tail, and a submitted script block is
	 * routinely kilobytes - so what lands in `object` is the beginning of it
	 * and KOFW_EF_TRUNCATED is set. That is enough to see WHAT a thing is
	 * and not enough to scan it; anything wanting the whole buffer needs a
	 * path that does not go through a fixed record, and there is not one
	 * here yet.
	 *
	 * NOT DELIVERED BY THE ID TABLE YET - see type_of() in wevt_decode.c.
	 * Until the ids are established on a machine that actually produces
	 * these, they arrive as KOF_EVT_RAW with their real id visible, which
	 * is what a discovery run needs.
	 */
	KOF_EVT_AMSI_SCAN = 19,

	/*
	 * THE REST OF THE RECORD BEFORE IT, when what it carried did not fit.
	 *
	 * A record is 512 bytes and a submitted script block is routinely
	 * kilobytes, so a content event used to store a prefix, set
	 * KOF_EF_TRUNCATED, and drop the rest on the floor - inside the
	 * collector, before anything that could scan it existed. That is the
	 * one field the AMSI subscription is FOR, and a scanner given its first
	 * four hundred bytes is a scanner that cannot see a payload assembled
	 * past that point, which is where a downloader puts it.
	 *
	 * So the rest follows, in as many of these as it takes. Each carries
	 * one chunk in `text` with `content_len` bytes of it, and nothing else
	 * of its own: no path, no ports, no technique. It is not an event and
	 * must never be counted, matched or shown as one - it is the tail of
	 * the record in front of it.
	 *
	 * WHICH RECORD IT CONTINUES IS THE ORDER, not a field. Every transport
	 * here preserves it - the ring is single-producer, the channel is a
	 * ring, the log is append-only - so a chunk belongs to the last
	 * non-continuation record seen. That is deliberately not a parent-id
	 * field: an id would have to be believed, and a consumer that believed
	 * one could be handed chunks that claim to continue a record it never
	 * saw. Order cannot be forged by a producer that only appends.
	 *
	 * WHAT A LOST CHUNK LOOKS LIKE: `seq` is the arrival counter, so a
	 * chunk whose seq is not one past the record before it has a hole in
	 * front of it, and kof_evt_join refuses to concatenate across the hole.
	 * A short reassembly is reported as short; it is never quietly joined.
	 */
	KOF_EVT_CONT = 20,

	KOF_EVT_TYPE_COUNT
};

/* "ProcStart", "RegSet", ... Never NULL, so a record written by a build that
 * knew one more verb still prints as something. */
const char *kof_evt_verb_name(uint16_t verb);


/* ------------------------------------------------------------------- where */

/*
 * WHAT ROLE A PATH PLAYS, decided once here rather than by whoever is looking.
 *
 * A consumer that matched paths as text would have to know about device paths,
 * 8.3 short names, junctions, SysWOW64 redirection, the two extra system
 * directories an ARM64 machine has, symlinks and bind mounts - and would have
 * to know all of it again in every place it asks. Worse, a rule written
 * against text is evaded by spelling the same location differently, which
 * costs an attacker nothing.
 */
enum kof_evt_loc {
	/* Nothing matched, or there was no path to classify. Distinct from
	 * "classified, and it is nowhere interesting". */
	KOF_LOC_UNKNOWN = 0,

	/* The directories every process draws its modules from. */
	KOF_LOC_SYSTEM,

	/* Installed software. */
	KOF_LOC_PROGRAMS,

	/* Scratch space, and the first place a dropper writes. */
	KOF_LOC_TEMP,

	/* Somewhere under a user profile that is not scratch space. */
	KOF_LOC_USER,

	/*
	 * THE PLACES THE MATRIX PUT HERE.
	 *
	 * Everything from KOF_LOC_AUTOSTART down is an ATT&CK technique that
	 * turned out to BE a path. That is most of the persistence column and a
	 * good part of defence evasion: T1547.001 is a Run value, T1053.005 is
	 * a file under System32\Tasks, T1546.010 is AppInit_DLLs, T1574.006 is
	 * /etc/ld.so.preload. None of them needs a chain of events or a window
	 * - one write to one place is the whole finding.
	 *
	 * They are LOCATIONS rather than rules on purpose. The classification
	 * already happens once per event, on the consumer thread, in one pass
	 * over one table - so tagging the technique there costs nothing beyond
	 * the table row. A rule engine that matched twenty path patterns per
	 * record would be doing that work again per rule, and with the registry
	 * subscribed there are six figures of records a second to do it to.
	 */
	KOF_LOC_AUTOSTART,    /* Run keys, Startup  | ~/.config/autostart     */
	KOF_LOC_SERVICE,      /* Services, IFEO     | systemd units, init.d   */
	KOF_LOC_SCHEDULE,     /* Tasks              | cron, at, timers        */
	KOF_LOC_SHELL_INIT,   /* profile.ps1        | .bashrc, rc.local       */
	KOF_LOC_PRELOAD,      /* AppInit_DLLs       | /etc/ld.so.preload      */
	KOF_LOC_SSH,          /*  -                 | authorized_keys         */
	KOF_LOC_CREDENTIAL,   /* SAM, SECURITY      | /etc/shadow, sudoers    */
	KOF_LOC_KERNEL_MOD,   /* drivers            | /lib/modules            */
	KOF_LOC_WEB_ROOT,     /* inetpub            | /var/www - a webshell   */
	KOF_LOC_HOSTS,        /* drivers\etc\hosts  | /etc/hosts              */

	/*
	 * A NAMED PIPE, which is a file object and is why it is a location.
	 *
	 * \Device\NamedPipe\<name> on Windows; a fifo anywhere on Linux. It
	 * is here because the pipe is how one process gets another to act on
	 * its behalf - Meterpreter's getsystem creates a pipe, has a SYSTEM
	 * service connect to it, and impersonates the token that arrives. The
	 * pipe's CREATION is the observable half of that, and it is a file
	 * event with a recognisable path.
	 */
	KOF_LOC_PIPE,

	/* Classified, and it is none of the above - which is a fact, not a
	 * failure to decide. */
	KOF_LOC_OTHER,

	/* Bounded because kofw_filter.drop_loc is 1u << this. */
	KOF_LOC_COUNT
};

/* "system", "temp", "autostart", ... Never NULL. */
const char *kof_loc_name(uint8_t loc);

/* ---------------------------------------------------------------- technique */

/*
 * THE TECHNIQUES A PATH ALONE ESTABLISHES.
 *
 * An X-macro for the same reason KOF_MALTYPE_LIST is one: the enum, the
 * ATT&CK id and the finding name are three views of one list, and a list
 * expanded three ways cannot disagree with itself. Adding a technique is one
 * row.
 *
 * WHAT THE TAG IS FOR, AND WHAT IT IS NOT.
 *
 * It is an INPUT to detection, not an output of it. A path classified as
 * KOF_ATT_RUN_KEY says the write landed in a place the matrix has a name for -
 * and every installer on the machine writes there. Nothing about the tag makes
 * an event a finding, and an event line that printed it like one would be
 * announcing a detection that nobody performed.
 *
 * What consumes it is the fact layer: a location and a technique tag are two
 * cheap, already-computed facts that a rule can require alongside the ones that
 * carry the actual weight - who wrote it, what they wrote, what else they did
 * in the same window. The finding is what the RULE produces, and the technique
 * id belongs on that line because there it names a decision rather than a
 * directory.
 *
 * So: no rule branches on the id STRING, nothing sums the tags, no callback
 * surfaces one as an event name, and NOTHING PRINTS ONE ON AN EVENT LINE.
 * Giving a taxonomy any other job is how it becomes a detection engine by
 * accident.
 *
 * The tactic each one belongs to is a trailing comment on its row. It is a
 * comment and not a field on purpose: nothing reads it, it is there so that
 * whoever adds the next row can see which column of the matrix they are
 * filling in and which are still empty.
 */
#define KOF_ATTACK_LIST(X)                                                   \
	/*  enum                 technique     finding name              */  \
	X(KOF_ATT_NONE,         "",           "")                           \
	X(KOF_ATT_RUN_KEY,      "T1547.001",  "Persist.RunKey") /* persistence, privesc */ \
	X(KOF_ATT_STARTUP_DIR,  "T1547.001",  "Persist.StartupFolder") /* persistence, privesc */ \
	X(KOF_ATT_WINLOGON,     "T1547.004",  "Persist.Winlogon") /* persistence, privesc */ \
	X(KOF_ATT_APPINIT,      "T1546.010",  "Persist.AppInitDlls") /* persistence, privesc */ \
	X(KOF_ATT_IFEO,         "T1546.012",  "Persist.Ifeo") /* persistence, privesc */ \
	X(KOF_ATT_SERVICE,      "T1543.003",  "Persist.Service") /* persistence, privesc */ \
	X(KOF_ATT_SCHED_TASK,   "T1053.005",  "Persist.ScheduledTask") /* execution, persistence */ \
	X(KOF_ATT_CRON,         "T1053.003",  "Persist.Cron") /* execution, persistence */ \
	X(KOF_ATT_SYSTEMD,      "T1543.002",  "Persist.SystemdService") /* persistence, privesc */ \
	X(KOF_ATT_RC_SCRIPT,    "T1037.004",  "Persist.RcScript") /* persistence, privesc */ \
	X(KOF_ATT_SHELL_PROFILE,"T1546.004",  "Persist.ShellProfile") /* persistence, privesc */ \
	X(KOF_ATT_LD_PRELOAD,   "T1574.006",  "Hijack.LdPreload") /* persistence, privesc, evasion */ \
	X(KOF_ATT_SSH_KEY,      "T1098.004",  "Persist.SshKey") /* persistence */ \
	X(KOF_ATT_ACCOUNT_FILE, "T1136.001",  "Account.LocalFile") /* persistence */ \
	X(KOF_ATT_SUDOERS,      "T1548.003",  "Privilege.Sudoers") /* privesc, evasion */ \
	X(KOF_ATT_CRED_STORE,   "T1003",      "Credential.Store") /* credential access */ \
	X(KOF_ATT_HOSTS,        "T1562.001",  "Evade.HostsFile") /* defense evasion */ \
	X(KOF_ATT_KERNEL_MOD,   "T1014",      "Rootkit.KernelModule") /* defense evasion */ \
	X(KOF_ATT_WEB_SHELL,    "T1505.003",  "Persist.WebShell") /* persistence */ \
	X(KOF_ATT_PIPE_IMPERSONATE, "T1134.001", "Privilege.PipeImpersonation") /* privesc, evasion */ \
	/* Added by walking Metasploit's windows/persistence modules against
	 * this table and writing down what nothing matched. That is the only
	 * way a coverage claim means anything - the four below were each a
	 * module that ran and produced no finding. */                        \
	X(KOF_ATT_ACCESSIBILITY, "T1546.008", "Persist.AccessibilityFeature") /* persistence, privesc */ \
	X(KOF_ATT_ACTIVE_SETUP,  "T1547.014", "Persist.ActiveSetup") /* persistence, privesc */ \
	X(KOF_ATT_BITS_JOB,      "T1197",     "Persist.BitsJob") /* defense evasion, persistence */ \
	X(KOF_ATT_PS_PROFILE,    "T1546.013", "Persist.PowerShellProfile") /* persistence, privesc */ \

enum kof_attack {
#define KOF_ATT_X_ENUM(name, tech, word) name,
	KOF_ATTACK_LIST(KOF_ATT_X_ENUM)
#undef KOF_ATT_X_ENUM
	KOF_ATT_COUNT
};

/* "T1547.001", or "" for KOF_ATT_NONE and for a value from a newer build.
 * Never NULL. */
const char *kof_attack_id(uint16_t att);

/* "Persist.RunKey", or "". Never NULL. */
const char *kof_attack_name(uint16_t att);

/*
 * Classify a path: the location, and the technique that location IS.
 *
 * One pass over one table, because it runs per event and with a registry
 * subscribed that is six figures a second. `att` may be NULL when a caller
 * only wants the location.
 *
 * Exposed because it is plain string work with no OS in it, so it is the part
 * worth testing directly - and because a caller holding a path from somewhere
 * other than an event should get the same answer this library would give.
 */
uint8_t kof_classify(const char *path, uint16_t *att);
uint8_t kof_classify_path(const char *path);

/* ------------------------------------------------------------- the record */

/* Absent, for the text offsets below. Zero is a legal offset into text[], so
 * it cannot double as the sentinel. */
#define KOF_TEXT_NONE 0xffffu

/* One record. Fixed, so a producer that cannot allocate cannot fail, and so a
 * recorded log is a fixed-record file - see kofevtlog.h. */
#define KOF_EVT_SIZE 512u
#define KOF_EVT_HEAD 104u

/* kof_evt.flags */
enum {
	/* The text arena was full and something was cut. Recorded rather than
	 * silently tolerated: a truncated path still looks like a path, and a
	 * rule would match it and be wrong without knowing why. */
	KOF_EF_TRUNCATED = 1u << 0,

	/* A field this verb normally carries was not supplied. See kof_evt.miss. */
	KOF_EF_PARTIAL   = 1u << 1,

	/*
	 * The code this event is about was in memory that no file backs.
	 *
	 * The shape of a manually mapped payload and of a remote injection.
	 * Neutral because it is a fact about the event, not about how it was
	 * collected - a Linux collector reading /proc/<pid>/maps establishes
	 * the same thing by a different route.
	 */
	KOF_EF_UNBACKED  = 1u << 2,

	/* A module arrived long after its process started, rather than in the
	 * loader's opening burst. */
	KOF_EF_LATE_LOAD = 1u << 3,

	/*
	 * The command line could not be read before the process was gone.
	 *
	 * Its own flag rather than an empty string, because "it had none" and
	 * "we lost the race" are different facts and a rule that treated them
	 * alike would report the second as the first.
	 */
	KOF_EF_CMDLINE_RACED = 1u << 4
};

/* Which normalised field a collector could not supply. Reported rather than
 * zero-filled, because zero is a legal pid, exit code and session id. */
enum {
	KOF_F_PID         = 1u << 0,
	KOF_F_PPID        = 1u << 1,
	KOF_F_CREATE_TIME = 1u << 2,
	KOF_F_SESSION     = 1u << 3,
	KOF_F_EXIT_CODE   = 1u << 4,
	KOF_F_IMAGE       = 1u << 5,
	KOF_F_OBJECT      = 1u << 6,
	KOF_F_CMDLINE     = 1u << 7
};

/* Which collector produced a record. A MASK, because a caller asks "does this
 * rule apply to Windows, Linux, or both". */
enum kof_evt_os { KOF_OS_WINDOWS = 1u << 0, KOF_OS_LINUX = 1u << 1 };

/*
 * WHICH MACHINE PRODUCED A LOG - one byte each, and they are not the masks
 * above.
 *
 * A record's `os` is a mask because a rule is written for one platform or
 * both. A LOG was produced by exactly one machine, so its header wants an
 * identity rather than a set, and one byte says it without inviting anyone to
 * OR two together.
 *
 * These describe the COLLECTOR HOST and deliberately do not reuse the engine's
 * arch taxonomy: that one answers "what architecture is this scanned object",
 * which is a different question with a different set of answers, and tying
 * them together would mean a new object format could not be added without
 * touching the log format.
 */
enum kof_evt_platform {
	KOF_PLAT_UNKNOWN = 0,
	KOF_PLAT_WINDOWS = 1,
	KOF_PLAT_LINUX   = 2,
	KOF_PLAT_MACOS   = 3
};

enum kof_evt_arch {
	KOF_EARCH_UNKNOWN = 0,
	KOF_EARCH_X86     = 1,
	KOF_EARCH_X86_64  = 2,
	KOF_EARCH_ARM     = 3,
	KOF_EARCH_ARM64   = 4
};

/*
 * "windows", "linux", ... and "x86_64", "arm64", ... Never NULL.
 *
 * PREFIXED kof_evt_ AND NOT kof_, because the engine already has a
 * kof_arch_name and it answers a different question: what architecture is this
 * SCANNED OBJECT. This one says which machine produced a log. Two concepts,
 * two names - the collision was a linker warning today and would have been a
 * silent wrong answer the day somebody included both headers and got whichever
 * came first.
 */
const char *kof_evt_platform_name(uint8_t plat);
const char *kof_evt_arch_name(uint8_t arch);

/*
 * What THIS build was compiled for, so a collector does not have to work it
 * out and two collectors cannot disagree about how to spell it.
 */
uint8_t kof_evt_platform_self(void);
uint8_t kof_evt_arch_self(void);

struct kof_evt {
	/*
	 * WHEN, as 100ns units since 1601 on every platform.
	 *
	 * Normalised by the collector, not by a reader, so a rule never has to
	 * ask which clock it is holding. Mixing two epochs subtracts to a
	 * number that looks like a duration and is not one, and that mistake is
	 * invisible until somebody acts on it.
	 */
	uint64_t stamp;

	/*
	 * The producer's own arrival count. A GAP IS A DROPPED RECORD - the
	 * counter advances on arrival, before anything can refuse the event, so
	 * a hole means something was lost and not that something was filtered.
	 */
	uint64_t seq;

	/*
	 * The subject's creation time. Not decoration: a pid is reused,
	 * sometimes within seconds, so (pid, create_time) is what identifies a
	 * process and a pid alone does not.
	 */
	uint64_t create_time;

	/* An address the event named - a thread entry point, a mapped base -
	 * and how much. Zero means it named none. */
	uint64_t addr, addr_size;

	uint32_t pid;          /* the subject */
	uint32_t ppid;

	/*
	 * WHO CAUSED IT, which is not who it is about.
	 *
	 * For a file event the actor IS the subject. For a process event they
	 * differ: a ProcStart is ABOUT the new process and is raised by whoever
	 * created it. For an injection the actor is the whole answer - see the
	 * note in kofevt.h's header on attributing by source rather than by
	 * which process ends up running the code.
	 */
	uint32_t actor_pid;

	uint32_t tid;
	uint32_t session_id;
	uint32_t exit_code;    /* PROC_STOP only */
	uint32_t miss;         /* KOF_F_* the collector could not fill */

	uint32_t net_daddr, net_saddr;
	uint32_t net_size;
	uint16_t net_dport, net_sport;   /* network byte order, as the packet had */

	uint16_t verb;         /* enum kof_evt_verb */
	uint16_t attack;       /* enum kof_attack, of the object path */
	uint16_t raw_id;       /* the source's own event id, for a RAW event */

	uint16_t off_image;    /* what the subject IS */
	uint16_t off_object;   /* what the event ACTED ON */
	uint16_t off_cmdline;  /* how the subject was invoked */
	uint16_t text_len;

	/*
	 * The length of the CONTENT at off_object, when the object is content
	 * rather than a path - an AMSI submission. Raw and unsanitised: see
	 * the note on kofw_evt.content_len for why a collector that cleaned it
	 * up would be destroying the evidence before the half that scans it
	 * ever saw it. Sanitising is the PRINTER's job.
	 *
	 * Zero for every ordinary path, which is NUL terminated as before.
	 */
	uint16_t content_len;

	uint8_t  loc;          /* enum kof_evt_loc, of the object */
	uint8_t  os;           /* enum kof_evt_os */
	uint8_t  flags;        /* KOF_EF_* */
	uint8_t  reserved;

	char     text[KOF_EVT_SIZE - KOF_EVT_HEAD];
};

/*
 * THE SIZE AND THE LAYOUT, ASSERTED RATHER THAN DESCRIBED.
 *
 * This record is written to a file and read back by a different build, so a
 * field added above text[] without moving KOF_EVT_HEAD makes every string in
 * every record start at the wrong offset - and a path read from the wrong
 * offset still looks like a path. libkofgrille's header claimed an equivalent
 * assertion existed and it did not, for the whole life of the file.
 */
_Static_assert(offsetof(struct kof_evt, text) == KOF_EVT_HEAD,
	       "KOF_EVT_HEAD no longer matches the record layout");
_Static_assert(sizeof(struct kof_evt) == KOF_EVT_SIZE,
	       "struct kof_evt is not KOF_EVT_SIZE bytes");

/* ------------------------------------------------- putting a record together
 *
 * WHY A CONSUMER HAS TO DO THIS AT ALL.
 *
 * A content event whose payload does not fit one record is followed by
 * KOF_EVT_CONT records carrying the rest - see the verb. Every transport
 * between here and the collector is ordered and append-only, so the chunks
 * arrive in front of nothing and behind their parent, and reassembly is
 * concatenation in arrival order.
 *
 * It is still not something each consumer should write for itself. There are
 * three of them - the matcher, the log reader, the viewer - and the part that
 * is easy to get wrong is not the copying, it is REFUSING TO COPY: a chunk
 * that arrived after a drop is a chunk with a hole in front of it, and joining
 * across it yields a buffer that reads as one script and is two halves of two.
 * That is the failure this codebase spends its comments on: a plausible
 * fabrication is worse than a short answer, because nothing downstream can
 * tell it from a fact.
 *
 * So: one implementation, which stops at the hole and says it stopped.
 */
struct kof_evt_join {
	uint8_t *buf;      /* the caller's, never owned here */
	size_t   cap;
	size_t   len;      /* bytes gathered so far */
	uint64_t seq;      /* the last record accepted */

	/*
	 * A CHUNK WAS LOST, so what is in `buf` is a PREFIX of the submission
	 * and the rest is not coming. Set once and never cleared: a later
	 * chunk arriving on the far side of the hole does not repair it, and
	 * appending it would be the fabrication described above.
	 */
	uint8_t  holed;

	/* The caller's buffer filled first. Also a prefix, but for a reason the
	 * caller can fix by passing more room - which is why it is a separate
	 * flag and not folded into `holed`. */
	uint8_t  full;

	/* The parent had nothing to continue - kof_evt_join_add was called on a
	 * join that was never started, or started from a record with no
	 * content. */
	uint8_t  idle;
};

/*
 * Begin a reassembly at `parent`, copying whatever content it already holds.
 *
 * `buf`/`cap` are the caller's and must outlive the join. Non-zero when the
 * record has content worth gathering; zero for every other verb, and then the
 * join is inert and kof_evt_join_add will refuse everything.
 */
int kof_evt_join_start(struct kof_evt_join *, const struct kof_evt *parent,
		       void *buf, size_t cap);

/*
 * Add one record, which should be the next one the transport delivered.
 *
 * Non-zero when its bytes were appended. Zero when they were not, and the
 * reason is in the flags: `idle` (not a continuation, or nothing was started),
 * `holed` (its seq is not one past the last accepted, so a chunk was lost) or
 * `full` (no room left). A caller that ignores the return value gets a short
 * buffer rather than a wrong one.
 */
int kof_evt_join_add(struct kof_evt_join *, const struct kof_evt *chunk);

/*
 * Is what was gathered the whole submission.
 *
 * Zero when a chunk was lost, when the buffer filled, or when the parent said
 * it was truncated and no continuation ever arrived to finish it.
 */
int kof_evt_join_whole(const struct kof_evt_join *,
		       const struct kof_evt *parent);

/*
 * Ticks per second in an event stamp.
 *
 * A constant rather than something to query, because it is the unit's own
 * definition and not a property of any machine. It is here so that everything
 * comparing a stamp against a clock takes the SAME one - see kof_evt_now.
 */
#define KOF_TICKS_PER_SEC 10000000ull

/*
 * Seconds between two stamps, signed and clamped at zero.
 *
 * An event's stamp is when it HAPPENED and is routinely older than a wall
 * clock read while waiting for it; unsigned subtraction there yields 1.8e19
 * seconds, which prints and is wrong.
 */
double kof_evt_secs_since(uint64_t t0, uint64_t t);

/* The last component of a path, either separator. Never NULL. */
const char *kof_path_leaf(const char *path);

/*
 * Now, in the same units an event's stamp uses.
 *
 * Per-platform inside, which is the ONE thing in this directory that has to
 * be - a clock is not arithmetic. It is still here rather than in a collector
 * because every consumer needs it and they must all take the SAME clock:
 * comparing a stamp against a different epoch subtracts to a number that looks
 * like a duration and is not one, and that mistake has already cost this tree
 * a debugging session once.
 */
uint64_t kof_evt_now(void);

/* ------------------------------------------------------------- health */

/*
 * HOW MUCH WAS LOST, in terms every collector has.
 *
 * A verdict computed over a stream that dropped records is a different claim
 * from one computed over a whole stream, and that difference has to reach
 * whoever reads the verdict. Each collector has losses of its own shape - ETW
 * counts buffers, a Linux one will count something else - so it fills this in
 * from its own counters rather than this describing any of them.
 *
 * Neutral because watchmen has to print it, and watchmen does not know what an
 * ETW buffer is.
 */
struct kof_evt_health {
	uint64_t produced;       /* records the collector wrote */
	uint64_t dropped;        /* its own queue was full */
	uint64_t high_water;     /* the deepest that queue has been */
	uint64_t undecoded;      /* arrived, could not be read */
	uint64_t filtered;       /* handed over to nobody, on purpose */
	uint64_t seq_gaps;       /* holes in the arrival counter */
	uint64_t upstream_lost;  /* lost BEFORE the collector saw it */
	uint32_t sub_asked;      /* what was requested */
	uint32_t sub_enabled;    /* what is actually running */
};

/* Print it, and name what is incomplete rather than only counting it. */
void kof_evt_health_print(FILE *out, const struct kof_evt_health *,
			  double secs);

/*
 * THE BUILD STAMP, AND WHY EVERY BANNER CARRIES IT.
 *
 * "I rebuilt and the output is identical" has two causes that look the same
 * from a terminal: nothing changed, or the binary being run is not the one
 * just built - an old copy earlier on PATH, a build that failed after the
 * tools step, a machine that did not pull. Guessing between those costs an
 * afternoon; reading a number off the banner costs a second. It has already
 * paid for itself once here.
 *
 * The Makefile passes the real stamp. The fallback keeps a stray compilation
 * building and says so rather than printing a zero that looks like an answer.
 */
#ifndef KOFENG_BUILD
#define KOFENG_BUILD 0u
#endif

/* Name, build stamp, and a one-line description of what is being collected. */
void kof_evt_banner(FILE *out, const char *tool, uint32_t build,
		    const char *collects);

/* The subject's image path, what the event acted on, and how the subject was
 * invoked. "" when the record carries none. Never NULL. */
const char *kof_evt_image(const struct kof_evt *);
const char *kof_evt_object(const struct kof_evt *);
const char *kof_evt_cmdline(const struct kof_evt *);

#endif /* KOFEVT_H */
