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
#include <stdio.h>

/*
 * THE VOCABULARY COMES FROM THERE, NOT FROM HERE.
 *
 * Verbs, locations and techniques are defined once in libkoforbit/kofevt and
 * this file uses them. They were declared here and mirrored there for one
 * afternoon, which is a shape that works exactly until the two copies
 * disagree - and then the conversion between them compiles, runs, and files
 * every module load as a process start.
 *
 * This is not a dependency on the engine. kofevt includes stdio, stdint,
 * stddef and nothing else - no kofeng.h, no OS header - which is the property
 * that lets this collector include it and keeps the rule at the top of this
 * file true.
 */
#include "kofevt.h"

/* ------------------------------------------------------------------ events */



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




/* "process", "file", "net". Never NULL. */
const char *kofw_provider_name(uint8_t prov);

/* Which provider a record came from. */
/*
 * THE COLLECTOR'S OWN VERSION.
 *
 * Separate from the engine's, because this is a separate component: it can be
 * built, shipped and replaced without libkofeng changing, and a reader of a log
 * wants to know which COLLECTOR produced it - the engine that reads the log had
 * nothing to do with writing it.
 *
 * Not the build stamp either. That is a date, and a date answers "is this the
 * binary I just made". This answers "which contract do these records follow",
 * which is what somebody opening a six-month-old trace needs.
 */
#define KOFW_MAJOR 1u
#define KOFW_MINOR 0u

enum kofw_provider {
	KOFW_PROV_NONE = 0,
	KOFW_PROV_PROCESS,
	KOFW_PROV_FILE,
	KOFW_PROV_NET,
	KOFW_PROV_REGISTRY,
	KOFW_PROV_AMSI,

	/*
	 * The resolver - Microsoft-Windows-DNS-Client, which is neither a
	 * kernel provider nor the network one. Its own entry and not folded
	 * into KOFW_PROV_NET because a raw id is only unique within a
	 * subsystem, which is the whole reason kof_evt carries `source`.
	 */
	KOFW_PROV_DNS,
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
	KOFW_EF_PARTIAL   = 1u << 1,

	/*
	 * A THREAD WHOSE ENTRY POINT IS IN NO MAPPED IMAGE.
	 *
	 * Set on KOF_EVT_THREAD_START when Win32StartAddr falls outside every
	 * range this collector watched being mapped into that process. That is
	 * the shape of a reflectively loaded DLL and of a remote injection, and
	 * it is the only in-box way to see either: a payload that allocates
	 * memory, copies an image into it, fixes its own relocations and
	 * resolves its own imports never maps an image section, so there is no
	 * IMAGE_LOAD to miss - the event does not exist. What it does next is
	 * start a thread, and that thread's entry point is in private memory.
	 *
	 * ONLY SET WHEN THE ANSWER IS KNOWABLE. It requires that this session
	 * saw the process START, so that every module it ever mapped was
	 * witnessed - see kofw_pent.mods_whole. For a process that predates the
	 * session, or one whose module list overflowed the pool, the flag is
	 * never set, because a list that begins in the middle cannot support
	 * "in none of them".
	 *
	 * NOT A VERDICT. JIT compilers do exactly this, and so do several
	 * legitimate loaders. It is a fact worth carrying, at the strength of
	 * one fact.
	 */
	KOFW_EF_UNBACKED  = 1u << 2,

	/*
	 * A MODULE MAPPED LONG AFTER THE PROCESS STARTED.
	 *
	 * A program's imports are mapped in a burst before it runs a line of
	 * its own code, and that burst is over in well under a second. A module
	 * arriving much later was asked for at run time.
	 *
	 * It is here because of the one case the thread test cannot see. A
	 * stager that calls its payload through a function pointer creates no
	 * thread, so nothing marks the transfer - but the reflective loader it
	 * hands control to resolves ITS imports through LoadLibrary, and those
	 * do map sections. ws2_32 or wininet appearing in a process that has
	 * been running for a minute and never needed a socket is the visible
	 * consequence of an invisible event.
	 *
	 * NOISY ON ITS OWN, and more so than KOFW_EF_UNBACKED. COM activation,
	 * plugin hosts, .NET and every shell extension load modules late and
	 * legitimately. This is a timing fact and nothing more; it earns its
	 * keep combined with WHICH module, in WHICH process, and with what else
	 * that process did - never alone.
	 *
	 * Set only where the answer is knowable: it needs the process's own
	 * start to have been seen, for the same reason KOFW_EF_UNBACKED does.
	 */
	KOFW_EF_LATE_LOAD = 1u << 3,

	/*
	 * THE COMMAND LINE WAS WANTED AND COULD NOT BE READ.
	 *
	 * It is read from the new process's own memory, so it can only be read
	 * while that process still exists - and the processes worth reading are
	 * exactly the ones that do not last. A stager runs for milliseconds.
	 *
	 * Flagged rather than left empty, because an empty command line and a
	 * command line nobody managed to read are different facts and only one
	 * of them is about the program. Without this, every lost race would
	 * look like a process that was started with no arguments.
	 */
	KOFW_EF_CMDLINE_RACED = 1u << 4
};

/* Absent, for the text offsets below. Zero is a legal offset into text[], so it
 * cannot double as the sentinel. */
#define KOF_TEXT_NONE 0xffffu

/*
 * The size of one record, and the whole reason it is fixed.
 *
 * The ring is an array of these, so a producer that cannot allocate cannot
 * fail, and the memory the monitor uses is settled at open() rather than by
 * whatever the machine does next. What is left for text after the fields below
 * is what an image path gets; a longer one is cut and flagged.
 *
 * 640 AND NOT 512, AND THE REASON IS WHAT IT WOULD HAVE COME OUT OF.
 *
 * Sixteen-byte addresses for IPv6 and a write's offset cost 32 bytes above
 * text[]. Held at 512 those bytes come out of the arena - so IPv6 support
 * would have been bought with more truncated PATHS, in a record collected for
 * evidence whose evidence is largely paths. The ring costs 25% more per record
 * for it, which is a number `--ring` can answer, and kofevtlog.h's header
 * carries rec_size so that a reader refuses an unfamiliar size rather than
 * decoding every field from the wrong offset.
 */
#define KOFW_REC_SIZE 640u

/* Everything above text[], so the arena can be sized to fill the record
 * exactly. Asserted against the real offset in the .c. */
/*
 * If the _Static_assert in wevt_decode.c fires, the compiler is right and this
 * is wrong: set it to the offset it reports. It exists so that adding a field
 * above text[] cannot silently move every string in every record - and it has
 * now earned its place twice.
 *
 * The second time was off_cmdline. Two more bytes obviously make the header two
 * bytes bigger, so this went to 106 and the assert refused it: the uint16 landed
 * in two bytes of padding that were already sitting before the addresses,
 * waiting for their 4-byte alignment. The field was free and the header did not
 * move at all.
 *
 * That padding is gone now, because the addresses became byte arrays and a
 * byte array has no alignment to pad for. Which is the third lesson from the
 * same assert: the free space a field lands in is a property of the fields
 * AROUND it, so a later change can take it away and nothing says so.
 *
 * Which is the argument for the assert rather than for arithmetic. Nobody
 * tracks padding by hand across a struct this size, and the failure it prevents
 * is not a crash - it is every string in every record starting two bytes off,
 * which reads as data.
 */
#define KOFW_REC_HEAD 144u

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

	uint16_t type;         /* enum kof_evt_verb */
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
	uint16_t off_image;    /* into text[], or KOF_TEXT_NONE */
	uint16_t off_object;   /* into text[], or KOF_TEXT_NONE */

	/*
	 * THE COMMAND LINE, on a PROC_START, when it could be read in time.
	 *
	 * Not from ETW: Kernel-Process's ProcessStart carries sixteen properties
	 * and none of them is this. It is read out of the new process's PEB
	 * instead, which is why it is the only field here that can lose a race -
	 * see KOFW_EF_CMDLINE_RACED.
	 *
	 * It earns that trouble because without it the process events cannot
	 * name what happened. "powershell.exe started" is not a fact anybody can
	 * act on; "powershell.exe -nop -w hidden -enc <...>" is the whole event.
	 * Every living-off-the-land technique looks identical without this
	 * field and obvious with it.
	 */
	uint16_t off_cmdline;  /* into text[], or KOF_TEXT_NONE */

	uint16_t text_len;

	/*
	 * HOW LONG THE CONTENT AT off_object IS, when it is CONTENT and not a
	 * path - which today means an AMSI submission and nothing else.
	 *
	 * WHY IT CANNOT BE A NUL-TERMINATED STRING. A submitted script block
	 * is a length-delimited buffer that may contain NULs; UTF-16 text read
	 * as bytes has one at index 1. Stored as a string it comes back as
	 * exactly one character, which is what the string conversion did.
	 *
	 * WHY IT IS RAW AND NO LONGER SANITISED. Replacing control characters
	 * with '.' and high bytes with '?' was justified by the record being
	 * PRINTED - a terminal escape in a name chosen by whoever made the
	 * file is a report that lies about what it says. That is still true of
	 * printing and it is now the printer's job. This record goes over a
	 * channel to kofwatchman, whose entire purpose is to SCAN what is in
	 * it, and a lossy conversion at the collector destroys the evidence
	 * before the half that needs it ever sees it.
	 *
	 * Zero when the object is an ordinary path, which every other verb's
	 * is.
	 */
	uint16_t content_len;

	/*
	 * What kof_classify_path made of the object path, or of the image when
	 * there is no object. Filled on the consumer side, never in the
	 * callback: classifying is string work and the callback is the one piece
	 * of code the whole machine pays for.
	 */
	uint8_t  obj_loc;      /* enum kof_evt_loc */
	uint8_t  reserved;

	/*
	 * WHICH ATT&CK TECHNIQUE THE OBJECT PATH IS, or KOF_ATT_NONE.
	 *
	 * An index rather than a string, so the record stays fixed size and a
	 * recorded trace stays replayable. Filled by the same single pass that
	 * fills obj_loc - see kof_classify.
	 */
	uint16_t attack;

	/*
	 * THE OTHER END, for a network event and for a lookup's answer.
	 *
	 * SIXTEEN BYTES EACH, IN THE ONE REPRESENTATION kof_evt USES: an IPv4
	 * address is stored IPv4-mapped, ::ffff:a.b.c.d, which is what
	 * kof_evt_ip_set_v4 writes and what kof_evt_ip_str reads back.
	 *
	 * These were UINT32, which is what the ids this build has typed deliver
	 * - and it made every IPv6 peer unrepresentable. That is the worst
	 * shape a gap can have: nothing errors, no field is missing, the trace
	 * simply shows a process that talked to nobody. The decode now takes
	 * the address by the SIZE the provider declared, so a 16-byte daddr
	 * lands here whole whether or not its event id has been typed yet -
	 * which means a v6 connection is visible as a RAW record with the peer
	 * on it, instead of not being visible at all.
	 *
	 * Ports arrive in NETWORK byte order and are kept that way, because
	 * swapping them at the edge would make the record disagree with the
	 * packet it describes; whoever prints one swaps it.
	 */
	uint8_t  net_daddr[16], net_saddr[16];
	uint16_t net_dport, net_sport;
	uint32_t net_size;

	/*
	 * WHERE IN THE FILE A WRITE LANDED - FileIo Write's ByteOffset.
	 *
	 * Its own field rather than borrowed space, and the borrowing is the
	 * mistake this pair already made once: a write's LENGTH lived in
	 * net_size, where nothing named after the network could be expected to
	 * hold it. `addr` was the obvious second place to put this - it is a
	 * spare uint64 on any file event - and it would have been the same
	 * mistake with a different field.
	 *
	 * With the length, a write is a range, and a range can be read back off
	 * the file afterwards. That is what makes "what did it write into
	 * hosts" a question with an answer.
	 */
	uint64_t file_offset;

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

	/*
	 * HOW BIG THE THING AT `addr` IS, when the event said.
	 *
	 * An ImageLoad's ImageSize today, and it exists for one reason: with the
	 * base and the size, a module occupies a RANGE, and a range is what lets
	 * a later thread's entry point be tested against it. Without the size
	 * there is a list of addresses and no way to ask whether something falls
	 * inside a module.
	 *
	 * Zero when the event named none.
	 */
	uint64_t addr_size;

	char     text[KOFW_REC_SIZE - KOFW_REC_HEAD];
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
	 * opened, read or written to. See KOF_EVT_FILE_NEW for why that line is
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
	 * KOF_EVT_THREAD_START.
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

	/*
	 * WHAT A SCRIPT ACTUALLY SAID.
	 *
	 * Microsoft-Antimalware-Scan-Interface reports the buffers applications
	 * hand to AmsiScanBuffer: an expanded PowerShell command, a macro body, a
	 * script block on its way to being executed. Everything else this
	 * collector gathers is the FACT of something - a file appeared, a
	 * connection opened. This is the only source of CONTENT, which is what
	 * makes it worth a provider of its own despite being small.
	 *
	 * Low volume: it fires only when a scripting host asks, so an idle
	 * machine produces none at all. Cheap to leave on.
	 *
	 * Not a substitute for anything. It is a user-mode provider, so a process
	 * can silence its own submissions, and a payload that never uses a
	 * scripting host was never going to appear here.
	 */
	KOFW_SUB_AMSI    = 1u << 8,

	/*
	 * WHICH NAMES WERE LOOKED UP - the most durable network evidence there
	 * is, and the one thing the network provider cannot tell anybody.
	 *
	 * An address is rented and reassigned. The domain is what the operator
	 * chose, paid for, reuses between campaigns, and what is still
	 * searchable a year later when the address belongs to a shop. A trace
	 * that has the connections and not the lookups kept the half that
	 * expires.
	 *
	 * Microsoft-Windows-DNS-Client, and it is a USER-MODE provider like
	 * AMSI, with the same consequence: it reports what went through the
	 * client's resolver, so a payload that speaks DNS itself over a raw
	 * socket, or uses DNS-over-HTTPS, does not appear here. That is a
	 * reason to keep the network subscription and not a reason to skip
	 * this one - the connection is still visible either way, and this is
	 * what turns an address into a name when the resolver was used.
	 *
	 * Low volume: a lookup per distinct name per TTL, which on a busy
	 * desktop is single digits a second.
	 */
	KOFW_SUB_DNS     = 1u << 9,

	/* Everything this build can collect. What kofmontrace takes by default
	 * - see the note there on why a discovery tool defaults to loud. */
	/*
	 * WHAT A SENSOR SUBSCRIBES TO, decided here and not on a command line.
	 *
	 * A sensor is not a tracer. A tracer is pointed at one program by
	 * somebody who knows what they are looking for, so choosing providers
	 * belongs to it. A sensor runs on every machine, all the time, and its
	 * subscription is a PROPERTY OF THE PRODUCT: if it is wrong it is wrong
	 * everywhere, and a flag only means the wrong thing gets set by
	 * somebody who did not know what it cost.
	 *
	 * So this is the set, and what is absent is absent on purpose:
	 *
	 *   KOFW_SUB_THREAD    the only in-box view of an in-memory load, and
	 *                      an order of magnitude more traffic than
	 *                      everything else here combined. Off until there
	 *                      is a measurement of what it costs on a real
	 *                      machine - see kofmontrace --thread, which is
	 *                      where that measurement is taken.
	 *   KOFW_SUB_FILE_OPEN the only way a named pipe is visible, and it
	 *                      fires on every file the machine opens. Same
	 *                      answer for the same reason.
	 *
	 * Both are reachable from the tracer, which is where an expensive
	 * subscription belongs: on a tool somebody ran on purpose.
	 */
	KOFW_SUB_SENSOR = KOFW_SUB_PROCESS | KOFW_SUB_IMAGE | KOFW_SUB_FILE |
			  KOFW_SUB_FILE_WRITE | KOFW_SUB_NET |
			  KOFW_SUB_REGISTRY | KOFW_SUB_AMSI |
			  KOFW_SUB_DNS,

	KOFW_SUB_ALL = KOFW_SUB_PROCESS | KOFW_SUB_IMAGE | KOFW_SUB_FILE |
		       KOFW_SUB_FILE_WRITE | KOFW_SUB_NET |
		       KOFW_SUB_REGISTRY | KOFW_SUB_THREAD |
		       KOFW_SUB_FILE_OPEN | KOFW_SUB_AMSI |
		       KOFW_SUB_DNS
};

/* "process", "image", "file", ... for one KOFW_SUB_* bit. "" for anything
 * else. Never NULL - it is used to print which subscriptions were refused. */
const char *kofw_sub_name(uint32_t one_bit);

/* The subject's image path, or "" when the event carried none. Never NULL. */
const char *kofw_evt_image(const struct kofw_evt *);

/* What the event acted on - the file that appeared, the module mapped, the
 * path unlinked - or "" when there is none. Never NULL. */
const char *kofw_evt_object(const struct kofw_evt *);

/* The command line of a process that just started, or "" - which means either
 * that there was none or that the race was lost. KOFW_EF_CMDLINE_RACED tells
 * the two apart. Never NULL. */
const char *kofw_evt_cmdline(const struct kofw_evt *);


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
	 * which is what kofmontrace does.
	 */
	int trace_self;

	/*
	 * NO OPTION TO RUN WITHOUT EVENT_TRACE_SYSTEM_LOGGER_MODE.
	 *
	 * There was one, as an escape hatch for "the provider enabled and then
	 * delivered nothing". It is removed because for a SENSOR the escape
	 * hatch is the failure: several of the kernel providers deliver nothing
	 * into an ordinary private session, so a sensor running that way
	 * collects nothing and reports success. An option whose only effect is
	 * to make the collector silently useless is not a diagnostic, it is a
	 * way of shipping a broken machine.
	 *
	 * If a provider enables and delivers nothing, that is a GUID or a
	 * keyword to check with `logman query providers <name>`, not a session
	 * mode to flip.
	 */
};

#define KOFW_ERR_ARG      (-1)
#define KOFW_ERR_MEM      (-2)
#define KOFW_ERR_ACCESS   (-3)   /* not elevated: a real-time session needs it */
#define KOFW_ERR_SESSION  (-4)   /* the session could not be started */
#define KOFW_ERR_PROVIDER (-5)   /* the session started, the provider refused */
#define KOFW_ERR_CONSUMER (-6)   /* the session started, it could not be opened */
#define KOFW_ERR_THREAD   (-7)
#define KOFW_ERR_PLATFORM (-8)   /* built without the Windows collector */

/*
 * THE PID NAMES A DIFFERENT PROCESS NOW.
 *
 * The snapshot half's own failure - see wproc.h - and it is separate from
 * KOFW_ERR_ACCESS because the two call for opposite responses. Refused means
 * try again with more rights; this means the pid was reused between being
 * observed and being acted on, and trying again is precisely the wrong thing.
 */
#define KOFW_ERR_GONE     (-9)

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

	/* Threads whose entry point was in no mapped image - see
	 * KOFW_EF_UNBACKED. A count of facts, not of verdicts. */
	uint64_t unbacked_threads;

	/* Modules mapped long after their process started - see
	 * KOFW_EF_LATE_LOAD. Expect a non-zero count on any real machine; it is
	 * a population to look through, not an alarm. */
	uint64_t late_loads;

	/*
	 * Command lines read, and lost to the race.
	 *
	 * The ratio is the useful number and it is expected to be poor: the
	 * processes worth reading are the short-lived ones. A high `lost` is
	 * the method's limit showing, not a fault - but it also bounds what any
	 * conclusion drawn from command lines can claim.
	 */
	uint64_t cmdline_got, cmdline_lost;

	/* Times a process' module list could not be extended because the range
	 * pool was empty. Non-zero means KOFW_EF_UNBACKED is being withheld for
	 * those processes, so a zero unbacked count is less meaningful. */
	uint64_t mod_pool_exhausted;

	/*
	 * Module loads whose base or size did not decode, so at least one
	 * process's module list is incomplete.
	 *
	 * It matters for one reason: KOFW_EF_UNBACKED is a claim that an
	 * address is in NO mapped image, and a list with a hole in it cannot
	 * support that. Non-zero here means the collector stopped answering
	 * for those processes rather than answering wrongly - and a reader
	 * seeing no unbacked threads needs to know which of the two happened.
	 */
	uint64_t mod_undecoded;

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
	 * Types to keep, as 1u << enum kof_evt_verb. Zero keeps all of them.
	 */
	uint32_t types;

	/*
	 * Locations to REFUSE, as 1u << enum kof_evt_loc, tested against
	 * kofw_evt.obj_loc.
	 *
	 * The one that earns its keep is KOF_LOC_SYSTEM against module loads:
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

	/*
	 * PROVIDERS EXEMPT FROM THE SUBTREE SCOPE, as 1u << enum kofw_provider.
	 *
	 * Scoping to a process tree is what turns a stream into evidence, and it
	 * is wrong for exactly one kind of record: the ones whose value does not
	 * depend on whose tree they came from.
	 *
	 * AMSI is that kind. It reports the CONTENT an application submitted,
	 * it is low volume enough to be free, and the moment it matters most is
	 * the moment the scope has already lost the subject - a payload that
	 * migrated is running in a process that is nobody's descendant, and its
	 * script submissions are attributed to a pid outside the tree and
	 * dropped. The trace then shows a clean subtree and says nothing about
	 * the thing that walked out of it.
	 *
	 * Exempting a provider BREAKS the tool's promise that everything shown
	 * belongs to one tree, so it is never a default: a caller asks, and the
	 * caller says so in its own output.
	 *
	 * By provider and not by event type on purpose - a type only exists
	 * once its ids have been established, and the records this is for are
	 * still arriving as KOF_EVT_RAW.
	 */
	uint32_t scope_exempt_prov;
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
 * WHICH tracked processes have not stopped - not just how many.
 *
 * The count alone turns "the trace will not finish" into a number, and a number
 * is not a diagnosis. A tracer waits for the tracked tree to empty, so a count
 * stuck above zero has exactly two causes and they call for opposite responses:
 * a descendant really is still running, or a ProcessStop was never matched to
 * its entry and the counter is wrong about the world. Naming the processes
 * separates them in one glance - a familiar long-lived child is the first, a
 * process that visibly exited is the second.
 *
 * Walks the entries: `i` from 0 upward until it returns NULL. Fills *pid when
 * non-NULL. The name is borrowed and valid until the next kofw_mon_next.
 */
const char *kofw_mon_tracked_nth(struct kofw_mon *, uint32_t i, uint32_t *pid);

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
 * The same, in the terms every collector has - see struct kof_evt_health.
 *
 * This direction and not the other: kofevt must not learn what an ETW buffer
 * is, so each collector maps its own counters onto the neutral ones. What is
 * ETW-specific (buffers lost versus events lost, self-skipped, untracked)
 * stays in struct kofw_health for anything that wants it.
 */
void kofw_mon_health_neutral(struct kofw_mon *, struct kof_evt_health *);

/*
 * Print what the NEUTRAL line cannot say.
 *
 * kof_evt_health_print covers what every collector has - kept, dropped, lost,
 * gaps. These are this collector's own: how many threads it called unbacked,
 * how many module lists it stopped being able to answer for, how many loads
 * arrived late, how much it refused and why.
 *
 * Two lines rather than one struct, because the day a Linux collector exists
 * it will have its own second line and neither of them should have to know
 * about the other's counters. Call it after the neutral one.
 */
void kofw_health_print_extra(FILE *out, const struct kofw_health *);

/*
 * Print that health, and say which build and which subscriptions produced it.
 *
 * Here rather than in a tool because these are THIS collector's counters -
 * ETW's own losses, this ring, this filter - and a Linux collector will have
 * different ones to print. It is not shared vocabulary, it is one platform's
 * bookkeeping, so it lives with the platform.
 */
void kofw_health_print(FILE *out, const struct kofw_health *, double secs);

/* Name, build stamp, and what this build collects. */
void kofw_banner(FILE *out, const char *tool, uint32_t build);

/* Now, in the same units kofw_evt.stamp uses. */
uint64_t kofw_now(void);

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

/* The stamp's unit is KOF_TICKS_PER_SEC, defined once in kofevt.h - see
 * there for why it is a constant and not a query. */

/*
 * THE COLLECTOR'S RECORD, TURNED INTO THE ONE EVERYTHING ELSE READS.
 *
 * struct kofw_evt is this library's internal transport: it carries what ETW
 * gave, including the things only ETW has - which provider, which per-processor
 * buffer, which payload version. struct kof_evt is what a log, a viewer, a
 * rule and a Linux collector all speak.
 *
 * The conversion lives HERE and not in kofevt, and that direction is the whole
 * design: kofevt must not know what an ETW record looks like or it stops being
 * neutral, so each collector is responsible for producing the neutral form.
 * The Linux twin will have its own function with the same shape and kofevt will
 * not learn about either.
 *
 * What is dropped is named rather than quietly lost: cpu, provider and
 * raw_version are ETW's own bookkeeping and have no meaning on another
 * platform. raw_id survives because a discovery run needs it.
 */
void kofw_evt_to_kof(const struct kofw_evt *in, struct kof_evt *out);

/*
 * NO AUTOLOGGER, AND THAT IS A DECISION RATHER THAN A GAP.
 *
 * An autologger is a session described in the registry that the kernel starts
 * during boot, so a consumer attaching later receives everything since. It is
 * the obvious way to see what ran before anything was watching, and there was
 * an implementation of it here for about an hour.
 *
 * It is removed because it puts this library in the business of installing
 * something. A registry-described session needs administrator to write, it
 * OUTLIVES the process, the product and the uninstaller, and a session nobody
 * ever attaches to keeps buffering forever with no process anywhere aware of
 * it. Those are lifecycle problems that belong to whatever installs and
 * removes the product, designed once and carefully - not to a collector, and
 * not decided as a side effect of wanting boot coverage.
 *
 * So the sensor is started by a system service, which is a thing the operating
 * system already knows how to start early and stop cleanly, and this library
 * does exactly one thing: collect while it is asked to.
 */

void kofw_mon_close(struct kofw_mon *);

#endif /* KOFGRILLE_H */
