/*
 * kofgrille_evt.h - the collector's event record: providers, the record layout and
 * its field names. *
 * A part of <kofgrille.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFGRILLE_EVT_H
#define KOFGRILLE_EVT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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

/* KOF_TEXT_NONE, the absent text offset, is defined in kofevt.h. */

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
#define KOFW_REC_HEAD 156u

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

	/*
	 * WHAT WAS WRITTEN INTO A REGISTRY VALUE, and why it is a second
	 * variable-length slot rather than the one `content_len` describes.
	 *
	 * A registry set names TWO things and neither substitutes for the
	 * other: WHERE it wrote - a path, which belongs in `object` like every
	 * other path - and WHAT it wrote, which for the autorun case IS the
	 * detection. `...\CurrentVersion\Run\Updater` says persistence was
	 * established; only the data says what it persists, and a rule that
	 * cannot read it reports that something happened and never what.
	 *
	 * An AMSI submission needed one slot because its metadata is
	 * deliberately not carried. This is the first event where a path and a
	 * payload are both evidence, so it is the first that needs both -
	 * and borrowing `addr` or `net_size` would repeat the mistake
	 * file_offset above already records.
	 *
	 * APPENDED HERE, AT THE END, AND THAT IS NOT COSMETIC. Fields added in
	 * the middle move every field below them, and a recorded trace read
	 * back by this build would then decode at the wrong offsets - the
	 * failure KOFW_REC_HEAD's note describes, which does not look like an
	 * error because a path read from the wrong place still looks like a
	 * path. Appended, every older field keeps the offset it had.
	 *
	 * RAW BYTES, NOT A STRING, for the reason content_len gives: a REG_SZ
	 * is UTF-16 and has a NUL at index 1, a REG_BINARY is arbitrary, and
	 * either read as a string comes back as one character. `data_len` is
	 * the length; a NUL is written after it anyway so that anything walking
	 * the arena as strings cannot run off the end.
	 */
	uint16_t off_data;     /* into text[], or KOF_TEXT_NONE */
	uint16_t data_len;     /* bytes at off_data; the NUL is not counted */

	/* REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD... the small enum
	 * winnt.h defines, so a rule can ask "a string was written here"
	 * without parsing the bytes to find out. */
	uint8_t  reg_type;

	/*
	 * DID THE KEY ACTUALLY GET CREATED - Kernel-Registry's Disposition,
	 * and it is what makes KOF_EVT_REG_CREATE mean anything at all.
	 *
	 * RegCreateKeyEx opens an existing key as readily as it makes a new
	 * one and the kernel raises CreateKey either way, so without this every
	 * key a program merely TOUCHED arrived as a registry change. 0 is "the
	 * event did not say", 1 REG_CREATED_NEW_KEY, 2 REG_OPENED_EXISTING_KEY.
	 */
	uint8_t  reg_disp;
	uint16_t reg_reserved;

	/*
	 * THE VALUE'S FULL SIZE AS THE KERNEL REPORTED IT, which is not
	 * data_len: one is what was written, the other is what reached this
	 * record. The provider captures a bounded prefix and this record bounds
	 * it again, so a consumer that needs to know it saw all of it compares
	 * the two - and KOFW_EF_TRUNCATED is set when they differ.
	 */
	uint32_t reg_data_size;

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

#endif /* KOFGRILLE_EVT_H */
