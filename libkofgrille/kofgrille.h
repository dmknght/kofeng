/*
 * kofgrille.h - collecting what Windows is doing, as seen from outside.
 *
 * THE NAME. A grille is the barred lattice over a window: the thing you watch
 * through, and the thing that decides what gets through. Both halves are the
 * job - the library watches Windows, and since classification and filtering
 * moved in here it is also what everything passes through on the way out. A
 * consumer sees what the grille let by, and kofw_health says how much it did
 * not.
 *
 * This is a sibling of libkofeng, not a part of it. The engine takes bytes and
 * says what they are; this takes the machine's own activity and turns it into
 * records. The two meet only where a caller decides to hand one to the other,
 * and nothing in this header includes kofeng.h - the first version collects, it
 * does not judge.
 *
 * The symbols stay `kofw_`, deliberately. The pun names the library; the prefix
 * says which platform it collects from, and that is what somebody reading a
 * call site needs to know.
 *
 * Shape:
 *
 *     struct kofw_mon *m = kofw_mon_open(&opt, &err);
 *
 *     struct kofw_evt e;
 *     while (kofw_mon_next(m, &e, 200))
 *             ... e.type, e.pid, kofw_evt_image(&e) ...
 *
 *     kofw_mon_close(m);
 *
 *
 * WHY THE RECORD IS NORMALISED AND NOT AN EVENT_RECORD
 *
 * Three reasons, and the third is the one that pays for the other two.
 *
 *   - An ETW record is only meaningful while its buffer is live, and that
 *     buffer belongs to a callback which must not block. Copying into a fixed
 *     record is what lets the callback return immediately.
 *   - The provider's field layout differs by Windows build. Deciding what a
 *     field MEANS once, at the edge, keeps that difference out of everything
 *     downstream.
 *   - A fixed record can be WRITTEN TO A FILE AND REPLAYED. That is what makes
 *     any of this testable: a detection rule that cannot be run against a
 *     recorded trace cannot be regression tested, and a false positive nobody
 *     can reproduce cannot be fixed. The replay path needs no Windows API at
 *     all, so it also builds and runs on the CI this library could not
 *     otherwise have.
 *
 *
 * WHAT THIS DELIBERATELY DOES NOT DO YET
 *
 * No autologger, so activity before it starts is not seen. No file, registry or
 * network provider. No detection of any kind. The point of the first version is
 * to find out what the stream actually looks like and what it costs, and every
 * one of those additions changes both.
 */

#ifndef KOFGRILLE_H
#define KOFGRILLE_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ events */

enum kofw_evt_type {
	KOFW_EVT_NONE = 0,

	/*
	 * A process began or ended.
	 *
	 * The lowest volume of anything worth having - single digits per second on
	 * an idle desktop, a few hundred during a build - and the highest value,
	 * which is why it is the only pair the first version subscribes to.
	 */
	KOFW_EVT_PROC_START = 1,
	KOFW_EVT_PROC_STOP  = 2,

	/*
	 * A module was mapped into a process. Medium volume - it bursts when an
	 * application starts and is quiet otherwise - and it is where a DLL
	 * loaded out of a temporary directory becomes visible.
	 */
	KOFW_EVT_IMAGE_LOAD = 3,

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
	KOFW_EVT_FILE_NEW    = 4,
	KOFW_EVT_FILE_DELETE = 5,
	KOFW_EVT_FILE_RENAME = 6,

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
	KOFW_EVT_RAW = 7,

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
	KOFW_EVT_NET_CONNECT    = 8,
	KOFW_EVT_NET_SEND       = 9,
	KOFW_EVT_NET_RECV       = 10,
	KOFW_EVT_NET_DISCONNECT = 11,

	/*
	 * A module was unmapped. Low value on its own and typed anyway, because
	 * the id was already being let through the provider filter and was
	 * arriving as RAW - which cost the same and told nobody anything.
	 */
	KOFW_EVT_IMAGE_UNLOAD = 12,

	/*
	 * DATA WAS WRITTEN INTO A FILE THAT ALREADY EXISTED.
	 *
	 * Separate from FILE_NEW because they answer different questions: one
	 * says a file APPEARED, the other says data LANDED in one. A payload
	 * written over something innocuous creates nothing and raises no
	 * FILE_NEW at all.
	 */
	KOFW_EVT_FILE_WRITE = 13,

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
	KOFW_EVT_REG_CREATE    = 14,
	KOFW_EVT_REG_SET_VALUE = 15,
	KOFW_EVT_REG_DELETE    = 16,

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
	 * does not exist. What such a payload almost always does next is START
	 * A THREAD, and a thread whose start address lies in private memory
	 * rather than inside any mapped image is the shape of a reflective load
	 * and of a remote injection.
	 *
	 * That test needs the start address, and whether Kernel-Process's
	 * ThreadStart payload carries one is NOT established here - it is
	 * exactly what `--schema` is for. If it does, kofw_evt.addr holds it.
	 * If it does not, this subscription is volume for nothing and should go
	 * back off.
	 */
	KOFW_EVT_THREAD_START = 17,
	KOFW_EVT_THREAD_STOP  = 18,

	KOFW_EVT_TYPE_COUNT
};

/*
 * WHAT ROLE A PATH PLAYS, decided once by this library rather than by whoever
 * happens to be looking at the record.
 *
 * A consumer that matches paths as text has to know about device paths, 8.3
 * short names, junctions, SysWOW64 redirection and the two extra system
 * directories an ARM64 machine has - and it has to know all of that again in
 * every place it asks the question. Worse, a rule written against text is
 * evaded by spelling the same location differently, which costs an attacker
 * nothing.
 *
 * So the classification happens at the edge, on the consumer thread, and the
 * record carries the answer alongside the original string. Never instead of it:
 * a classification is a decision that can be wrong, and the raw path is the
 * only thing that lets somebody check.
 */
enum kofw_loc {
	/* Nothing matched, or there was no path to classify. Distinct from
	 * "classified, and it is nowhere interesting". */
	KOFW_LOC_UNKNOWN = 0,

	/* The directories every process draws its modules from. */
	KOFW_LOC_SYSTEM,

	/* Installed software. */
	KOFW_LOC_PROGRAMS,

	/* Scratch space, and the first place a dropper writes. */
	KOFW_LOC_TEMP,

	/* Somewhere under a user profile that is not scratch space. */
	KOFW_LOC_USER,

	/*
	 * THE PLACES THE MATRIX PUT HERE.
	 *
	 * Everything from KOFW_LOC_AUTOSTART down is an ATT&CK technique that
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
	KOFW_LOC_AUTOSTART,    /* Run keys, Startup  | ~/.config/autostart     */
	KOFW_LOC_SERVICE,      /* Services, IFEO     | systemd units, init.d   */
	KOFW_LOC_SCHEDULE,     /* Tasks              | cron, at, timers        */
	KOFW_LOC_SHELL_INIT,   /* profile.ps1        | .bashrc, rc.local       */
	KOFW_LOC_PRELOAD,      /* AppInit_DLLs       | /etc/ld.so.preload      */
	KOFW_LOC_SSH,          /*  -                 | authorized_keys         */
	KOFW_LOC_CREDENTIAL,   /* SAM, SECURITY      | /etc/shadow, sudoers    */
	KOFW_LOC_KERNEL_MOD,   /* drivers            | /lib/modules            */
	KOFW_LOC_WEB_ROOT,     /* inetpub            | /var/www - a webshell   */
	KOFW_LOC_HOSTS,        /* drivers\etc\hosts  | /etc/hosts              */

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
	KOFW_LOC_PIPE,

	/* Classified, and it is none of the above - which is a fact, not a
	 * failure to decide. */
	KOFW_LOC_OTHER,

	/* Bounded because kofw_filter.drop_loc is 1u << this. */
	KOFW_LOC_COUNT
};

/*
 * THE TECHNIQUES THIS BUILD RECOGNISES BY PATH ALONE.
 *
 * An X-macro for the same reason KOF_MALTYPE_LIST is one: the enum, the
 * technique id and the finding name are three views of one list, and a list
 * expanded three ways cannot disagree with itself. Adding a technique is one
 * row.
 *
 * The technique string is REPORTING ONLY. Nothing matches on it, nothing sums
 * it, and no rule branches on it - it is what a reader needs to look the
 * finding up, and giving it any other job is how a taxonomy becomes a
 * detection engine by accident.
 */
#define KOFW_ATTACK_LIST(X)                                                   \
	/*  enum                 technique     finding name              */  \
	X(KOFW_ATT_NONE,         "",           "")                           \
	X(KOFW_ATT_RUN_KEY,      "T1547.001",  "Persist.RunKey")             \
	X(KOFW_ATT_STARTUP_DIR,  "T1547.001",  "Persist.StartupFolder")      \
	X(KOFW_ATT_WINLOGON,     "T1547.004",  "Persist.Winlogon")           \
	X(KOFW_ATT_APPINIT,      "T1546.010",  "Persist.AppInitDlls")        \
	X(KOFW_ATT_IFEO,         "T1546.012",  "Persist.Ifeo")               \
	X(KOFW_ATT_SERVICE,      "T1543.003",  "Persist.Service")            \
	X(KOFW_ATT_SCHED_TASK,   "T1053.005",  "Persist.ScheduledTask")      \
	X(KOFW_ATT_CRON,         "T1053.003",  "Persist.Cron")               \
	X(KOFW_ATT_SYSTEMD,      "T1543.002",  "Persist.SystemdService")     \
	X(KOFW_ATT_RC_SCRIPT,    "T1037.004",  "Persist.RcScript")           \
	X(KOFW_ATT_SHELL_PROFILE,"T1546.004",  "Persist.ShellProfile")       \
	X(KOFW_ATT_LD_PRELOAD,   "T1574.006",  "Hijack.LdPreload")           \
	X(KOFW_ATT_SSH_KEY,      "T1098.004",  "Persist.SshKey")             \
	X(KOFW_ATT_ACCOUNT_FILE, "T1136.001",  "Account.LocalFile")          \
	X(KOFW_ATT_SUDOERS,      "T1548.003",  "Privilege.Sudoers")          \
	X(KOFW_ATT_CRED_STORE,   "T1003",      "Credential.Store")           \
	X(KOFW_ATT_HOSTS,        "T1562.001",  "Evade.HostsFile")            \
	X(KOFW_ATT_KERNEL_MOD,   "T1014",      "Rootkit.KernelModule")       \
	X(KOFW_ATT_WEB_SHELL,    "T1505.003",  "Persist.WebShell")           \
	X(KOFW_ATT_PIPE_IMPERSONATE, "T1134.001", "Privilege.PipeImpersonation")

enum kofw_attack {
#define KOFW_ATT_X_ENUM(name, tech, word) name,
	KOFW_ATTACK_LIST(KOFW_ATT_X_ENUM)
#undef KOFW_ATT_X_ENUM
	KOFW_ATT_COUNT
};

/* "T1547.001", or "" for KOFW_ATT_NONE and for a value from a newer build.
 * Never NULL. */
const char *kofw_attack_id(uint16_t att);

/* "Persist.RunKey", or "". Never NULL. */
const char *kofw_attack_name(uint16_t att);

/* "system", "temp", ... Never NULL. */
const char *kofw_loc_name(uint8_t loc);

/*
 * Classify a path on its own. Exposed because it is plain string work with no
 * Windows API in it, so it is the part worth testing directly - and because a
 * caller holding a path from somewhere other than an event should get the same
 * answer this library would give.
 */
uint8_t kofw_classify_path(const char *path);

/*
 * The same pass, answering both questions.
 *
 * Separate entry point rather than two functions, because walking the table
 * twice to get two fields off the same row is the cost this design exists to
 * avoid. `att` may be NULL when a caller only wants the location.
 */
uint8_t kofw_classify(const char *path, uint16_t *att);

/* "process", "file", "net". Never NULL. */
const char *kofw_provider_name(uint8_t prov);

/* Which provider a record came from. */
enum kofw_provider {
	KOFW_PROV_NONE = 0,
	KOFW_PROV_PROCESS,
	KOFW_PROV_FILE,
	KOFW_PROV_NET,
	KOFW_PROV_REGISTRY,
	KOFW_PROV_COUNT
};

/* kofw_evt.flags */
enum {
	/*
	 * The text arena was full and something was cut. Recorded rather than
	 * silently tolerated: a truncated image path still looks like a path, and
	 * a later rule would match against it and be wrong without knowing why.
	 */
	KOFW_EF_TRUNCATED = 1u << 0,

	/*
	 * A field this event type normally carries was not in the payload, so what
	 * arrived did not match the schema this build learned. See kofw_evt.miss
	 * for which ones.
	 */
	KOFW_EF_PARTIAL   = 1u << 1
};

/* Absent, for the text offsets below. Zero is a legal offset into text[], so it
 * cannot double as the sentinel. */
#define KOFW_TEXT_NONE 0xffffu

/*
 * The size of one record, and the whole reason it is fixed.
 *
 * The ring is an array of these, so a producer that cannot allocate cannot
 * fail, and the memory the monitor uses is settled at open() rather than by
 * whatever the machine does next. What is left for text after the fields below
 * is what an image path gets; a longer one is cut and flagged.
 */
#define KOFW_EVT_SIZE 512u

/* Everything above text[], so the arena can be sized to fill the record
 * exactly. Asserted against the real offset in the .c. */
#define KOFW_EVT_HEAD 96u

struct kofw_evt {
	/*
	 * WHEN, AS A FILETIME: 100ns units since 1601, which is both a wall clock
	 * and fine enough to order by.
	 *
	 * Those two are usually a trade and here they are not, because they come
	 * from different decisions. The session asks for QPC as its CLOCK SOURCE,
	 * so the resolution is the hardware counter's rather than the system
	 * clock's ~15ms tick - which matters because that tick is coarser than the
	 * whole lifetime of the short-lived processes this exists to catch. What
	 * ProcessTrace then DELIVERS is that same instant converted to 100ns
	 * FILETIME units.
	 *
	 * Getting this wrong is easy and was: raw counter ticks are what arrives
	 * only if the consumer asks for PROCESS_TRACE_MODE_RAW_TIMESTAMP, and a
	 * consumer that assumes them without asking ends up comparing these values
	 * against QueryPerformanceCounter - two clocks with different epochs, which
	 * subtract to a number that is not a duration at all.
	 *
	 * Still not ordered on arrival: ETW buffers are per processor, so records
	 * cross CPUs out of order and a consumer that needs a sequence has to sort
	 * over a window. The resolution here is what makes that sort meaningful.
	 */
	uint64_t stamp;

	/*
	 * The producer's own count, and the ONLY way a consumer learns that this
	 * library dropped something.
	 *
	 * A gap here is a dropped record. ETW's own EventsLost is a second,
	 * separate loss further upstream, reported by kofw_mon_health(). Both
	 * matter, neither implies the other, and they are never summed.
	 */
	uint64_t seq;

	/*
	 * The subject's creation time, as the kernel recorded it.
	 *
	 * This is not decoration. A pid is reused, sometimes within seconds, so a
	 * pid alone does not name a process - and anything acting on a pid it
	 * looked up later (opening it, scanning it, attributing a child to it) is
	 * acting on whatever holds that number NOW. The pair (pid, create_time) is
	 * what identifies a process, and every consumer here compares both.
	 */
	uint64_t create_time;

	uint32_t pid;          /* the subject */
	uint32_t ppid;         /* its parent, or absent - see miss */

	/*
	 * WHO CAUSED THIS EVENT, which is not who it is about, and conflating
	 * the two is a mistake with two separate consequences.
	 *
	 * For a file event the raiser IS the actor, and this column is the
	 * answer to "who wrote that" - the single most important fact in the
	 * evidence. For a process event they differ: a ProcessStart is ABOUT
	 * the new process and is raised by whoever created it.
	 *
	 * It is also what the self-filter has to be careful with. Refusing
	 * every event this process raised is right for the feedback loop that
	 * filter exists to break, and wrong for a tool that DELIBERATELY
	 * launches something and wants to watch it - there, the event it most
	 * needs is the one its own CreateProcess raised. See
	 * kofw_mon_option.trace_self.
	 */
	uint32_t raiser_pid;

	uint32_t tid;          /* the thread that raised the event */
	uint32_t session_id;
	uint32_t exit_code;    /* PROC_STOP only */

	/*
	 * WHICH FIELDS THE DECODE COULD NOT FILL, as a mask of KOFW_F_*.
	 *
	 * Reported rather than zero-filled, because zero is a legal pid, a legal
	 * exit code and a legal session id. A consumer that cannot tell "absent"
	 * from "zero" will eventually decide something on a field nobody supplied.
	 */
	uint32_t miss;

	uint16_t type;         /* enum kofw_evt_type */
	uint16_t raw_id;       /* the provider's own event id */

	uint8_t  cpu;          /* whose per-processor buffer it came out of */
	uint8_t  flags;        /* KOFW_EF_* */
	uint8_t  provider;     /* enum kofw_provider */
	uint8_t  raw_version;  /* the payload version that was decoded */

	/*
	 * TWO STRINGS, AND THEY ANSWER DIFFERENT QUESTIONS.
	 *
	 * `image` is what the SUBJECT is - the program behind the pid. `object`
	 * is what the event ACTED ON: the file that appeared, the module that
	 * was mapped, the path that was unlinked.
	 *
	 * One field would have been enough right up until file events arrived,
	 * and then every consumer would have had to know which meaning it was
	 * holding based on the event type. That is a thing to get wrong once per
	 * consumer instead of never.
	 */
	uint16_t off_image;    /* into text[], or KOFW_TEXT_NONE */
	uint16_t off_object;   /* into text[], or KOFW_TEXT_NONE */
	uint16_t text_len;

	/*
	 * What kofw_classify_path made of the object path, or of the image when
	 * there is no object. Filled on the consumer side, never in the
	 * callback: classifying is string work and the callback is the one piece
	 * of code the whole machine pays for.
	 */
	uint8_t  obj_loc;      /* enum kofw_loc */
	uint8_t  reserved;

	/*
	 * WHICH ATT&CK TECHNIQUE THE OBJECT PATH IS, or KOFW_ATT_NONE.
	 *
	 * An index rather than a string, so the record stays fixed size and a
	 * recorded trace stays replayable. Filled by the same single pass that
	 * fills obj_loc - see kofw_classify.
	 */
	uint16_t attack;

	/*
	 * THE OTHER END, for a network event and nothing else.
	 *
	 * IPv4 only so far: the addresses arrive as UINT32 on the ids this build
	 * has typed, and the IPv6 events are separate ids that have not been
	 * established the same way. Ports arrive in NETWORK byte order and are
	 * kept that way here, because swapping them at the edge would make the
	 * record disagree with the packet it describes; whoever prints one swaps
	 * it.
	 */
	uint32_t net_daddr, net_saddr;
	uint16_t net_dport, net_sport;
	uint32_t net_size;

	/*
	 * AN ADDRESS THE EVENT NAMED, when it named one.
	 *
	 * A thread's start address today. 64 bits because a 32-bit field would
	 * silently truncate every address on the platform this actually runs
	 * on, and a truncated address does not look wrong - it looks like an
	 * address, which is the failure mode this record's design exists to
	 * refuse.
	 *
	 * Zero means the event carried none. Not KOFW_NA: zero is not a legal
	 * thread entry point, so it is unambiguous here in a way it is not for
	 * a pid.
	 */
	uint64_t addr;

	char     text[KOFW_EVT_SIZE - KOFW_EVT_HEAD];
};

/* Which normalised field a decode failed to supply. */
enum {
	KOFW_F_PID         = 1u << 0,
	KOFW_F_PPID        = 1u << 1,
	KOFW_F_CREATE_TIME = 1u << 2,
	KOFW_F_SESSION     = 1u << 3,
	KOFW_F_EXIT_CODE   = 1u << 4,
	KOFW_F_IMAGE       = 1u << 5,
	KOFW_F_OBJECT      = 1u << 6
};

/* kofw_mon_option.providers */
enum {
	/*
	 * Process start and stop. Cheapest thing worth having and the only one
	 * on by default, because everything else is scoped BY a process and a
	 * collector without this cannot attribute what it sees.
	 */
	KOFW_SUB_PROCESS = 1u << 0,

	/* Module loads, from the same provider under a second keyword. */
	KOFW_SUB_IMAGE   = 1u << 1,

	/*
	 * Files appearing, being unlinked and being renamed - and NOT being
	 * opened, read or written to. See KOFW_EVT_FILE_NEW for why that line is
	 * drawn where it is, and why almost nothing of value is on the far side
	 * of it.
	 */
	KOFW_SUB_FILE    = 1u << 2,

	/*
	 * WRITES INTO FILES THAT ALREADY EXIST, which KOFW_SUB_FILE does not
	 * see and which matters more than it first looks.
	 *
	 * CREATE_NEW_FILE fires when a file comes into existence. A payload
	 * written into a file that is already there - an upload over an open
	 * session, an overwrite of something innocuous, an append - never
	 * creates anything, so it produces no event at all under KOFW_SUB_FILE.
	 * "Nothing of value is on the far side of that line" was too strong:
	 * whether data LANDED in a file is a different question from whether a
	 * file APPEARED, and only the second one was being asked.
	 *
	 * The cost is real and is why this is separate. WRITE fires per
	 * operation rather than per file, and it names its target by
	 * FileObject - a kernel pointer - not by path, so FILENAME has to be
	 * enabled alongside it just to turn those pointers back into names.
	 * That pair is the expensive half of file tracing.
	 */
	KOFW_SUB_FILE_WRITE = 1u << 3,

	/*
	 * Connections, and the bytes over them.
	 *
	 * The provider offers only IPv4 and IPv6 as keywords - there is no way
	 * to ask for connects without sends - so volume control here has to be
	 * an event-id filter, and this build does not have that table yet. For
	 * a trace scoped to one subtree that costs nothing, because everything
	 * outside it is discarded anyway. For an always-on collector it would
	 * matter, and that is the point at which the ids have to be established.
	 */
	KOFW_SUB_NET     = 1u << 4,

	/*
	 * THE REGISTRY, AND WHY IT IS WORTH ITS VOLUME.
	 *
	 * It is the most expensive provider here by a wide margin - a busy
	 * desktop reads and writes the registry thousands of times a second -
	 * and it is subscribed anyway, because persistence on Windows is a
	 * registry write far more often than it is a file. A Run value, a
	 * service, an IFEO debugger, AppInit_DLLs and a COM hijack are all one
	 * value being set, and none of them touches a file the collector would
	 * otherwise see.
	 *
	 * The keyword asks for CREATE, SETVALUE and DELETE only. Reads are the
	 * bulk of the traffic and carry nothing: "something read a key" is not
	 * a fact anybody writes a rule against, exactly as with files.
	 */
	KOFW_SUB_REGISTRY = 1u << 5,

	/*
	 * Thread create and exit, from the process provider under a third
	 * keyword. The most expensive thing in this list per unit of evidence,
	 * and the only in-box way an unelevated-of-PPL consumer can see code
	 * start running somewhere that is not a mapped image. See
	 * KOFW_EVT_THREAD_START.
	 */
	KOFW_SUB_THREAD   = 1u << 6,

	/*
	 * FILES BEING OPENED - THE KEYWORD THIS LIBRARY SPENT ITS WHOLE LIFE
	 * REFUSING, AND THE ONE THING THAT MAKES IT WORTH IT.
	 *
	 * Kernel-File's CREATE (0x80) fires on every open a machine performs.
	 * That is the keyword that makes file tracing famous for being
	 * unaffordable, and the comment in wevt_etw.c saying nothing of value
	 * is on the far side of it was true for FILES.
	 *
	 * It is not true for PIPES. A named pipe is a file object, it is never
	 * "created new" in the sense CREATE_NEW_FILE means, and it is how one
	 * process makes another act for it: getsystem creates a pipe, gets a
	 * SYSTEM service to connect to it, and impersonates the token that
	 * arrives. Nothing under any other keyword sees that.
	 *
	 * So this is off by default and will stay off by default. Turn it on to
	 * watch pipes, expect the volume, and use --quiet or a redirect rather
	 * than a console.
	 */
	KOFW_SUB_FILE_OPEN = 1u << 7,

	/* Everything this build can collect. What kofwintrace takes by default
	 * - see the note there on why a discovery tool defaults to loud. */
	KOFW_SUB_ALL = KOFW_SUB_PROCESS | KOFW_SUB_IMAGE | KOFW_SUB_FILE |
		       KOFW_SUB_FILE_WRITE | KOFW_SUB_NET |
		       KOFW_SUB_REGISTRY | KOFW_SUB_THREAD |
		       KOFW_SUB_FILE_OPEN
};

/* "process", "image", "file", ... for one KOFW_SUB_* bit. "" for anything
 * else. Never NULL - it is used to print which subscriptions were refused. */
const char *kofw_sub_name(uint32_t one_bit);

/* The subject's image path, or "" when the event carried none. Never NULL. */
const char *kofw_evt_image(const struct kofw_evt *);

/* What the event acted on - the file that appeared, the module mapped, the
 * path unlinked - or "" when there is none. Never NULL. */
const char *kofw_evt_object(const struct kofw_evt *);

/* "ProcStart", "ProcStop", ... Never NULL, so a record written by a build that
 * knew one more type still prints as something. */
const char *kofw_evt_type_name(uint16_t type);

/* ----------------------------------------------------------------- monitor */

struct kofw_mon;

struct kofw_mon_option {
	/*
	 * How many records may be in flight, rounded up to a power of two.
	 *
	 * This is the collector's whole memory budget: capacity * 512 bytes, taken
	 * once at open. 0 asks for the default.
	 */
	uint32_t ring_capacity;

	/*
	 * The session's name, which OUTLIVES THIS PROCESS.
	 *
	 * An ETW session is a kernel object owned by nobody: if this process dies
	 * without stopping it, the session keeps running and keeps buffering. The
	 * name is how the next run finds the leftover one and stops it - and two
	 * builds that pick the same name will fight over it. NULL takes the
	 * default.
	 */
	const char *session_name;

	/* Per-buffer size in KB, and the buffer count handed to ETW. 0 takes the
	 * defaults, whose reasoning lives beside them in the .c. */
	uint32_t buffer_kb;
	uint32_t min_buffers, max_buffers;

	/* A mask of KOFW_SUB_*. Zero takes KOFW_SUB_PROCESS alone. */
	uint32_t providers;

	/*
	 * KEEP THE EVENTS THIS PROCESS RAISES.
	 *
	 * Off by default, and the default is the safe one: reading a file to
	 * scan it raises file events, which are handled, which causes more of
	 * the same, and on a loaded machine that loop does not converge.
	 *
	 * On is for a tool that LAUNCHES something and wants to watch it. There
	 * the most important event in the whole run - the ProcessStart of the
	 * thing it just launched - is raised by this process, and the filter
	 * that protects a service is exactly what would hide it.
	 *
	 * A caller that turns this on takes on the loop itself, and the way to
	 * carry that is to consume a bounded subtree rather than everything -
	 * which is what kofwintrace does.
	 */
	int trace_self;

	/*
	 * START AN ORDINARY SESSION, NOT A SYSTEM LOGGER.
	 *
	 * Off by default, so the session carries EVENT_TRACE_SYSTEM_LOGGER_MODE
	 * as it always has - some kernel providers deliver nothing without it,
	 * with no error anywhere, which is why the flag went in.
	 *
	 * It is exposed because the converse is also possible and is not
	 * something this code can settle by reasoning: a system-logger session
	 * may be what a manifest provider refuses to deliver into on a given
	 * build, or another anti-malware product may already hold the one the
	 * machine allows. Both look identical from here - the session starts,
	 * EnableTraceEx2 succeeds, and one provider is silent. Turning this on
	 * and comparing is a thirty-second experiment; deducing it is not
	 * possible at all.
	 */
	int no_system_logger;
};

#define KOFW_ERR_ARG      (-1)
#define KOFW_ERR_MEM      (-2)
#define KOFW_ERR_ACCESS   (-3)   /* not elevated: a real-time session needs it */
#define KOFW_ERR_SESSION  (-4)   /* the session could not be started */
#define KOFW_ERR_PROVIDER (-5)   /* the session started, the provider refused */
#define KOFW_ERR_CONSUMER (-6)   /* the session started, it could not be opened */
#define KOFW_ERR_THREAD   (-7)
#define KOFW_ERR_PLATFORM (-8)   /* built without the Windows collector */

const char *kofw_err_name(int err);

/*
 * Start collecting. NULL on failure, and *err is a KOFW_ERR_*.
 *
 * Requires elevation. Nothing here degrades gracefully without it - an
 * unelevated process cannot start a real-time ETW session at all - so that is
 * reported rather than worked around.
 */
struct kofw_mon *kofw_mon_open(const struct kofw_mon_option *, int *err);

/*
 * Take the next record, waiting up to `wait_ms`. 1 if one was taken, 0 if the
 * wait expired with nothing there.
 *
 * ONE consumer. The ring is single-producer single-consumer by construction -
 * that is what lets the producer be wait-free, which is what keeps the ETW
 * callback from ever blocking - so calling this from two threads is not a race
 * to be locked around, it is outside what the structure can express.
 */
int kofw_mon_next(struct kofw_mon *, struct kofw_evt *out, uint32_t wait_ms);

/*
 * HOW MUCH WAS LOST, AND WHERE.
 *
 * Not a log line. A verdict computed over a stream that dropped records is a
 * different claim from one computed over a whole stream, and that difference
 * has to reach whoever reads the verdict - the same reason a scan carries
 * enum kof_broken rather than quietly returning what it managed.
 *
 * The three losses are distinct and are never added together:
 *
 *   etw_events_lost   the provider wrote faster than the session drained.
 *   etw_rt_buf_lost   real-time buffers lost between the session and here.
 *   ring_dropped      this library's ring was full when the callback arrived.
 *
 * The first two mean the collector never saw it. The third means it saw it and
 * chose dropping over stalling the callback - which is the only choice there
 * is, since blocking there stops ProcessTrace draining and turns a bounded,
 * counted loss into an unbounded, invisible one.
 */
struct kofw_health {
	uint64_t produced;         /* records the callback wrote */
	uint64_t ring_dropped;
	uint64_t ring_high_water;  /* the deepest the ring has ever been */
	uint64_t decode_failed;    /* payload the learned schema did not fit */

	/*
	 * Events dropped whole because the schema cache had no slot left.
	 *
	 * Its own line rather than part of decode_failed, because it is not a
	 * count of bad events - it is the collector announcing that it has
	 * stopped learning new shapes. Non-zero means every event id first seen
	 * from here on is discarded, permanently, and kofw_mon_describe() names
	 * the shapes it filled up on.
	 */
	uint64_t schema_full;
	uint64_t skipped_self;     /* our own events, refused at the callback */

	/* Records the consumer-side filter refused. Counted rather than
	 * silently dropped: "the sample did nothing" and "everything it did was
	 * filtered out" are different results. */
	uint64_t filtered;

	/*
	 * The same number broken out by WHICH test refused, because the three
	 * call for three different next steps and one total tells a reader to
	 * take none of them. `filtered_loc` in particular is the default
	 * suppression of system module loads, which looks like a bug the first
	 * time somebody meets it.
	 */
	uint64_t filtered_loc;    /* the object's location was being dropped */
	uint64_t filtered_scope;  /* the subject was outside the tracked tree */
	uint64_t filtered_type;   /* the caller did not ask for that type */

	/* Processes a tracked tree could not admit because its table was full.
	 * Non-zero means the scoped view is INCOMPLETE. */
	uint64_t untracked;

	/*
	 * Holes in kofw_evt.seq, counted BEFORE the filter runs.
	 *
	 * This has to live here rather than in a consumer, and the reason is
	 * exactly why it moved: once the library refuses records, the sequence
	 * numbers a consumer SEES are legitimately not contiguous, so a consumer
	 * counting its own gaps reports every filtered record as a lost one. A
	 * scoped trace on a busy machine then claims hundreds of losses and has
	 * had none.
	 */
	uint64_t seq_gaps;

	/*
	 * WHICH SUBSCRIPTIONS THE PROVIDER ACCEPTED, and which it refused.
	 *
	 * Masks of KOFW_SUB_*. `sub_asked & ~sub_enabled` is the set that was
	 * asked for and is not running, and it belongs in this struct for the
	 * same reason every other field here does: it is a reason the stream is
	 * incomplete, and a reader about to conclude "the sample did no network
	 * activity" has to be told the network provider never started.
	 *
	 * This used to be invisible in the worst possible way. One provider
	 * refusing aborted kofw_mon_open entirely, so the only two outcomes
	 * were "everything" and "nothing" - and when the session DID start,
	 * nothing anywhere said whether a provider had delivered a single
	 * record. A subscription that quietly is not running looks exactly like
	 * a machine that is not doing that thing.
	 */
	uint32_t sub_asked;
	uint32_t sub_enabled;

	uint32_t etw_events_lost;
	uint32_t etw_buffers_lost;
	uint32_t etw_rt_buf_lost;
};

/* ------------------------------------------------------------- filtering */

/*
 * WHAT A CONSUMER WANTS TO SEE, as data.
 *
 * Here rather than in each tool, because every one of these decisions needs
 * knowledge that belongs to the collector - which module paths are the ones
 * every process loads, which pid belongs to a tracked tree, what a location id
 * means. A tool that reimplemented them would be reimplementing them slightly
 * differently, and the day a rule engine becomes the consumer it would have to
 * be written a third time.
 *
 * Zeroing the struct means "everything", which is the answer a caller who
 * forgot a field should get: less filtering, never more.
 *
 * Filtering happens in kofw_mon_next on the consumer thread. It is NOT a
 * substitute for the keyword and event-id filters the session applies at the
 * provider - those stop an event being produced at all, and this only stops one
 * being handed over. Both counters are reported, and a record refused here is
 * counted in kofw_health.filtered rather than vanishing.
 */
struct kofw_filter {
	/*
	 * Types to keep, as 1u << enum kofw_evt_type. Zero keeps all of them.
	 */
	uint32_t types;

	/*
	 * Locations to REFUSE, as 1u << enum kofw_loc, tested against
	 * kofw_evt.obj_loc.
	 *
	 * The one that earns its keep is KOFW_LOC_SYSTEM against module loads:
	 * `cmd.exe /c` maps 27 modules before running a command and all 27 are
	 * the loader's own furniture, so a view that prints them prints almost
	 * nothing else. Note this refuses by the OBJECT's location - a process
	 * started from System32 is not affected, only a module loaded from it.
	 */
	uint32_t drop_loc;

	/*
	 * Only events of this process and its descendants. Zero means no
	 * scoping.
	 *
	 * The set grows from ProcessStart events whose parent is already in it,
	 * so a grandchild is included and an unrelated process is not. Seed it
	 * with kofw_mon_track() BEFORE the process can run - see that function.
	 *
	 * WHAT THIS CANNOT FOLLOW, and it matters: parentage. Code injected into
	 * an existing process, or a payload that migrates into one, is running
	 * somewhere that is not a descendant of anything tracked, and no amount
	 * of care here will attribute it. That is a property of the method, not
	 * a gap to be fixed later, and a scoped trace that comes back empty may
	 * mean the subject left the tree rather than that it did nothing.
	 */
	uint32_t root_pid;
};

/*
 * Apply a filter from now on. NULL clears it back to "everything".
 *
 * Copied, not referenced, so the caller's struct need not outlive the call.
 */
void kofw_mon_filter(struct kofw_mon *, const struct kofw_filter *);

/*
 * Put a pid into the tracked set by hand, before any event mentions it.
 *
 * A caller that LAUNCHED the process has to do this, and has to do it while the
 * process is still suspended: otherwise the target can create a child, write a
 * file and exit before the first record is drained, and every one of those
 * events belongs to a pid the set has never heard of.
 *
 * `image` is only for reporting and may be NULL. Non-zero on failure, which
 * means the set is full - see kofw_health.untracked.
 */
int kofw_mon_track(struct kofw_mon *, uint32_t pid, const char *image);

/* How many tracked processes have not yet stopped. Zero once a tracked tree has
 * finished, which is what a trace waits for. Meaningless without a root_pid. */
uint32_t kofw_mon_tracked_alive(const struct kofw_mon *);

/*
 * What this pid is, for reporting. "" when the collector has not seen it start.
 * Never NULL.
 *
 * `create_time` of 0 means the caller has no discriminator and the pid alone
 * has to do; pass the record's when it has one, because a pid is reused and a
 * table keyed on the number alone will confidently return another process's
 * name.
 */
const char *kofw_mon_name_of(struct kofw_mon *, uint32_t pid,
			     uint64_t create_time);

void kofw_mon_health(struct kofw_mon *, struct kofw_health *);

/*
 * THE PAYLOAD SHAPES THIS RUN ACTUALLY LEARNED, as text.
 *
 * A field arriving absent - kofw_evt.miss - has two causes that look identical
 * from the outside: the provider on this Windows build does not carry it, or
 * the walk stopped before reaching it. They call for opposite responses, and
 * nothing else here can tell them apart.
 *
 * Returns bytes written, excluding the NUL, and never writes past `cap`.
 */
size_t kofw_mon_describe(struct kofw_mon *, char *buf, size_t cap);

/*
 * kofw_evt.stamp units per second.
 *
 * A constant rather than something to query, because it is FILETIME's own
 * definition and not a property of this machine. It is here so that a consumer
 * comparing a stamp against a wall clock takes the SAME clock - mixing this
 * with QueryPerformanceCounter subtracts two different epochs and yields a
 * number that looks like a duration and is not one.
 */
#define KOFW_TICKS_PER_SEC 10000000ull

void kofw_mon_close(struct kofw_mon *);

#endif /* KOFGRILLE_H */
