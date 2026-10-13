/*
 * kofevt_vocab.h - the words an event is said in: the verbs, the sources, where
 * a thing happened, and which technique that location is (the ATT&CK list). *
 * A part of <kofevt.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFEVT_VOCAB_H
#define KOFEVT_VOCAB_H

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

	/*
	 * A NAME WAS LOOKED UP - the one network fact worth more than the
	 * address it resolves to.
	 *
	 * An IP is a rented thing. The domain is what the operator chose, what
	 * they paid for, what they reuse across campaigns and what is still
	 * searchable a year later when the address has been handed to somebody
	 * else. A trace that has the connection and not the name has the least
	 * durable half of the evidence.
	 *
	 * The object is the name that was asked about. The addresses that came
	 * back go in the net payload when the record carries them, so one
	 * lookup can say "this name is now this address" - which is the join a
	 * report needs to attribute a connection to a domain, and which no
	 * amount of looking at connections alone can reconstruct.
	 *
	 * TWENTY-ONE AND NOT BESIDE THE OTHER NETWORK VERBS, which is where it
	 * belongs conceptually. Renumbering 8..11 to make room would silently
	 * reinterpret every recorded trace in existence as something else, and
	 * a verb's number is not worth that. The kind table below is what
	 * groups it with them.
	 */
	KOF_EVT_DNS_QUERY = 21,

	/*
	 * A PROCESS AS IT IS RIGHT NOW - a snapshot, not something that
	 * happened.
	 *
	 * Every other verb here names an EVENT: a thing the machine did, at an
	 * instant, which a collector witnessed. This one names a STATE, and it
	 * is a verb anyway for one mechanical reason - the target axis a rule
	 * declares is the verb's own number (see KOF_TARGET_FIRST_EVENT in
	 * kofsig.h), so a shape worth writing rules against has to have one.
	 *
	 * It is the snapshot half of libkoforbit/antarc: a machine compromised on
	 * Tuesday with a sensor installed on Thursday produces a perfectly
	 * clean event stream, because everything that mattered happened before
	 * anything was watching. What is still RESIDENT has raised no event
	 * since and is only visible by looking.
	 *
	 * TWENTY-TWO AND NOT BESIDE KOF_EVT_PROC_START, which is where it
	 * belongs conceptually. PROC_START is 1, and 1 is KOF_FMT_ELF on the
	 * target axis - the low half belongs to file formats - so it can never
	 * be a target until the boundary moves. The same argument DNS_QUERY
	 * makes two entries up: a verb's number is not worth renumbering a
	 * recorded trace for.
	 */
	KOF_EVT_PROC_INFO = 22,

	/*
	 * ============================================================
	 * WHAT A PROCESS DID TO ITSELF OR TO ANOTHER
	 * ============================================================
	 *
	 * Five things the Linux process connector reports that had no verb.
	 * They arrived as KOF_EVT_RAW with an id and a dictionary entry, which
	 * is what RAW is for - it let a discovery run see what was actually
	 * coming out before anybody decided which of it was worth naming. This
	 * is that decision.
	 *
	 * ONLY LINUX FILLS THEM TODAY, AND THAT IS ALLOWED. The registry verbs
	 * above are Windows-only and always will be; the rule kofantarc.h
	 * states - do not add without the same thing being true on the other
	 * platform - is about enum kof_evt_loc, where a location that exists
	 * on one side and not the other makes the two columns disagree. A verb
	 * names a thing that happened, and a machine that cannot do the thing
	 * simply never raises it.
	 *
	 * Where Windows HAS a counterpart it is named below, because the day
	 * somebody wires it up the question will be which verb it is - and the
	 * answer should already be written down.
	 *
	 * TWENTY-THREE AND UP, WHICH MEANS THEY CANNOT BE RULE TARGETS. An
	 * event target's value IS its verb - see KOF_TARGET_FIRST_EVENT in
	 * kofsig.h - and the target axis reserved only 19 to 22 for verbs;
	 * file formats own everything above, starting with CHM at 23. So these
	 * can be filtered, counted, logged and correlated, and a module cannot
	 * declare itself to be about one. That is the same position
	 * KOF_EVT_PROC_START has been in since the beginning, and the fix if it
	 * ever matters is to widen the axis rather than to renumber records
	 * already on disk.
	 */

	/*
	 * ONE PROCESS ATTACHED TO ANOTHER to inspect or control it.
	 * Linux: ptrace. Windows: OpenProcess with the debug or VM-write
	 * rights, which Kernel-Audit-API-Calls reports.
	 * The ACTOR is the one attaching and the subject is the one attached
	 * to - see kof_evt.actor_pid, which for this verb is the whole point.
	 * T1055 is decided by a rule, not here: a debugger is the same event.
	 */
	KOF_EVT_PROC_ATTACH = 23,

	/*
	 * A PROCESS CHANGED THE IDENTITY IT RUNS AS.
	 * Linux: setuid, setgid and their real/effective halves. Windows: a
	 * token adjusted or impersonated.
	 * One verb for both halves because the fact is one - the identity
	 * moved - and which ids it moved between is detail the record carries
	 * in its text rather than a second verb.
	 */
	KOF_EVT_PROC_PRIVILEGE = 24,

	/*
	 * A PROCESS LEFT ITS SESSION AND LED A NEW ONE.
	 * Linux: setsid, which is how a thing daemonises - it is the step that
	 * detaches from the terminal that started it. No Windows counterpart:
	 * a session there is assigned at logon and a process does not leave
	 * one.
	 */
	KOF_EVT_PROC_SESSION = 25,

	/*
	 * A PROCESS CHANGED THE NAME IT REPORTS AS.
	 * Linux: comm, which every tool from ps to a sensor reads as the
	 * process's name while the image on disk is unchanged. No Windows
	 * counterpart for a process; the nearest thing is naming a thread,
	 * which is a different object.
	 */
	KOF_EVT_PROC_RENAME = 26,

	/*
	 * A PROCESS DUMPED CORE.
	 * Linux: coredump. Windows: the error-reporting path.
	 * Low value alone and typed anyway, for the reason IMAGE_UNLOAD gives
	 * two entries up: the id is already being let through, and arriving as
	 * RAW it cost the same and told nobody anything. A burst of them is
	 * also what an exploit that is not working yet looks like.
	 */
	KOF_EVT_PROC_CRASH = 27,

	/*
	 * A FILE'S METADATA CHANGED - its mode, its owner, its extended
	 * attributes, its link count.
	 *
	 * THE MIDDLE OF THE CHAIN, and it was the one link nothing reported.
	 * The Linux dropper shape is three steps - write a payload, make it
	 * executable, run it - and this collector saw the first and the third
	 * while the second was invisible. Each of the other two alone is
	 * ordinary; a write followed by a chmod +x followed by an exec of the
	 * same path is not, and a chain cannot be joined through a link that
	 * raises no record.
	 *
	 * WHAT CHANGED IS NOT IN THE EVENT. fanotify's FAN_ATTRIB says that
	 * metadata moved and not which field, so the collector reads the mode
	 * back and puts it in the record's text - see afan.c. That read is a
	 * race it can lose, and losing it is reported rather than guessed.
	 *
	 * Windows has the counterpart - a DACL or attribute set through
	 * Kernel-File's SetInformation - so this is not a Linux-only verb the
	 * way PROC_SESSION is; nothing fills it there yet.
	 */
	KOF_EVT_FILE_ATTRIB = 28,

	KOF_EVT_TYPE_COUNT
};

/*
 * WHICH SUBSYSTEM AN EVENT CAME FROM.
 *
 * The values are the collector's, and there is one collector - see kof_evt.source
 * for why this is not a second vocabulary.
 */
enum kof_evt_source {
	KOF_SRC_NONE = 0,
	KOF_SRC_PROCESS,
	KOF_SRC_FILE,
	KOF_SRC_NET,
	KOF_SRC_REGISTRY,
	KOF_SRC_AMSI,

	/* The resolver. Its own subsystem and not KOF_SRC_NET, because the two
	 * answer different questions and a raw id is only unique within one of
	 * these - see kof_evt.source. */
	KOF_SRC_DNS,
	KOF_SRC_COUNT
};

/* "process", "file", ... Never NULL. */
const char *kof_evt_source_name(uint8_t src);


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

#endif /* KOFEVT_VOCAB_H */
