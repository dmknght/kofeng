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

	/* Classified, and it is none of the above - which is a fact, not a
	 * failure to decide. */
	KOFW_LOC_OTHER,

	KOFW_LOC_COUNT
};

/* "system", "temp", ... Never NULL. */
const char *kofw_loc_name(uint8_t loc);

/*
 * Classify a path on its own. Exposed because it is plain string work with no
 * Windows API in it, so it is the part worth testing directly - and because a
 * caller holding a path from somewhere other than an event should get the same
 * answer this library would give.
 */
uint8_t kofw_classify_path(const char *path);

/* Which provider a record came from. */
enum kofw_provider {
	KOFW_PROV_NONE = 0,
	KOFW_PROV_PROCESS,
	KOFW_PROV_FILE,
	KOFW_PROV_NET,
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
#define KOFW_EVT_HEAD 84u

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
	KOFW_SUB_NET     = 1u << 4
};

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
	uint64_t skipped_self;     /* our own events, refused at the callback */

	/* Records the consumer-side filter refused. Counted rather than
	 * silently dropped: "the sample did nothing" and "everything it did was
	 * filtered out" are different results. */
	uint64_t filtered;

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
