/*
 * kofevt_record.h - the record: addresses, struct kof_evt and what each kind of
 * event carries, joining chunks, the health counters, the banner and the text
 * accessors. *
 * A part of <kofevt.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFEVT_RECORD_H
#define KOFEVT_RECORD_H

#include <stdint.h>
#include "../../libkofeng/kofcore/kofdebug.h"   /* KOFENG_BUILD fallback */
#include <stddef.h>
#include <stdio.h>
#include "kofevt_vocab.h"

/* --------------------------------------------------------------- addresses */

/* Enough for the longest IPv6 text form plus a NUL. */
#define KOF_IP_STR_MAX 46u

/*
 * ONE ADDRESS, AS TEXT, and it is here rather than in the renderer because
 * three consumers need the same spelling.
 *
 * A trace line, a report's IOC table and whatever reads a recorded log all
 * have to produce the SAME string for the same sixteen bytes, or the same
 * connection appears as two indicators and a text search for one misses the
 * other. That is the identical argument kofevtfmt.h makes for rendering an
 * event, one level down.
 *
 * An IPv4-mapped address prints as a dotted quad and not as ::ffff:1.2.3.4,
 * because that is what an operator pastes into a search box. IPv6 is
 * lower-case hex with the longest run of zero groups collapsed once, as RFC
 * 5952 requires - a canonical form exists precisely so two tools agree.
 *
 * Returns `out`, always NUL terminated, "" for a NULL address. Never NULL, so
 * it can be used directly as a printf argument.
 */
const char *kof_evt_ip_str(const uint8_t addr[16], char *out, size_t cap);

/* Is this address IPv6 proper, rather than an IPv4 one carried IPv4-mapped. */
int kof_evt_ip_is_v6(const uint8_t addr[16]);

/* Is this address all zero - which is "the event named none", and is also the
 * legal unspecified address. The caller's context decides which; the record
 * cannot. */
int kof_evt_ip_is_unset(const uint8_t addr[16]);

/* Put an IPv4 address, in network byte order, into the 16-byte field in the
 * one representation the record uses. What a collector holding a UINT32 from
 * a provider calls. */
void kof_evt_ip_set_v4(uint8_t addr[16], uint32_t be_v4);

/* ------------------------------------------------------------- the record */

/* Absent, for the text offsets below. Zero is a legal offset into text[], so
 * it cannot double as the sentinel. */
#define KOF_TEXT_NONE 0xffffu

/*
 * One record. Fixed, so a producer that cannot allocate cannot fail, and so a
 * recorded log is a fixed-record file - see kofevtlog.h.
 *
 * 640 AND NOT 512, AND THE EXTRA 128 BYTES BOUGHT A DECISION RATHER THAN ROOM.
 *
 * Sixteen-byte addresses and a write's offset cost 32 bytes of head. Held at
 * 512 that came out of text[], which is where the paths are - so supporting
 * IPv6 would have been paid for with more truncated paths, in a record whose
 * whole evidence IS the paths. That trade is backwards, and it is the kind that
 * looks free because KOF_EF_TRUNCATED reports the damage honestly.
 *
 * Growing instead costs 25% more per record in the ring and in a log, which is
 * a number a `--ring` argument can answer. kofevtlog.h's header carries
 * `rec_size` precisely so that this can happen without orphaning a reader:
 * growth is the anticipated change, and a reader that finds a size it does not
 * know refuses the file instead of decoding every field from the wrong offset.
 */
#define KOF_EVT_SIZE 640u
#define KOF_EVT_HEAD 100u

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
 * PREFIXED kof_evt_ AND NOT kgenome_, because the engine already has a
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

/* ------------------------------------------- what a KIND of event carries
 *
 * WHY THE TAIL OF THE RECORD IS PER-VERB.
 *
 * Everything above the payload is true of every event: when, who, what verb,
 * where the strings are. Below it, almost nothing is. A file write has no
 * ports; a connection has no exit code; an AMSI submission has neither, and no
 * addresses either. Laid out flat, all of them were present in all of them,
 * and a FileNew carried forty-eight bytes of zero in a hundred-and-four byte
 * head - which is paid for on every record, in the ring, over the channel, and
 * on disk.
 *
 * They were ALREADY overlapping, just not on paper: `addr` has been a FileKey
 * on a file event, a thread entry point on a thread event and a module base on
 * an image load for as long as those events have existed. This says so, which
 * is the actual improvement - the size is a consequence.
 *
 * READ THEM THROUGH THE ACCESSORS, never through the union directly. Each one
 * checks the verb and returns NULL when the event is not of that kind, so
 * asking a registry event for its ports is a NULL a caller must handle and not
 * four bytes of somebody else's address. That is the whole risk of a union in
 * a record like this, and it is the reason the members are not spelled in any
 * caller.
 */

/* A process appearing or leaving. */
struct kof_evt_proc {
	/*
	 * The subject's creation time. Not decoration: a pid is reused,
	 * sometimes within seconds, so (pid, create_time) is what identifies a
	 * process and a pid alone does not.
	 */
	uint64_t create_time;
	uint32_t session_id;
	uint32_t exit_code;    /* PROC_STOP only */
};

/* Something mapped or started at an address - an image load, a thread. */
struct kof_evt_mem {
	/* A thread entry point, a mapped base. Zero means the event named
	 * none. */
	uint64_t addr;
	uint64_t addr_size;
};

/* A connection or a transfer. The addresses and ports are the provider's own
 * - see the property names in wevt_decode.c - and the ports are in NETWORK
 * byte order, as the packet had them. */
struct kof_evt_net {
	/*
	 * SIXTEEN BYTES EACH, AND ONE REPRESENTATION FOR BOTH FAMILIES.
	 *
	 * These were uint32_t, which made every IPv6 destination
	 * unrepresentable - and an address that cannot be recorded is a C2 that
	 * does not appear in the evidence at all. That is not a gap a reader
	 * can notice: the trace simply shows a process that talked to nobody.
	 *
	 * An IPv4 address is stored IPv4-MAPPED - ::ffff:a.b.c.d, as RFC 4291
	 * writes it - rather than in the first four bytes with the rest zero.
	 * The difference matters because it makes "is this v6" a test on the
	 * bytes instead of a flag somebody has to remember to set, and because
	 * the all-zero prefix is itself a legal v6 address (:: is the
	 * unspecified one), so the alternative encoding cannot tell an IPv4
	 * address from an unset one.
	 *
	 * Network byte order, like the ports, and for the same reason: the
	 * record agrees with the packet it describes, and whoever prints one
	 * converts. kof_evt_ip_str is that printer.
	 */
	uint8_t  daddr[16], saddr[16];
	uint32_t size;
	uint16_t dport, sport;
};

/*
 * A file the event acted on, named by the kernel's own handle for it.
 *
 * FileIo carries FileObject and FileKey - kernel pointers - and no path, so
 * the collector resolves them to one. The key is kept because a write that
 * arrives before its own create is a key with no path yet, and the resolution
 * happens later on the consumer side.
 */
struct kof_evt_file {
	uint64_t key;

	/*
	 * WHERE IN THE FILE THE WRITE LANDED, for FILE_WRITE.
	 *
	 * FileIo Write carries ByteOffset beside IOSize and the collector was
	 * dropping it, which left every write saying how much without saying
	 * where. With both, a write is a RANGE, and a range is the difference
	 * between "this process modified hosts" and "this process wrote these
	 * bytes at this place in hosts" - the second is evidence and can be
	 * read back, the first is a sentence.
	 *
	 * Note what it does NOT make available: the bytes. No event on either
	 * platform carries file content. A consumer that wants the data reads
	 * the range back off disk afterwards and must say that it did - the
	 * bytes there at the end of a run are not provably the bytes this write
	 * put there.
	 */
	uint64_t offset;

	/*
	 * Bytes written, for FILE_WRITE.
	 *
	 * This lived in `net_size` - a file write reporting its length in a
	 * field named after the network, because both were u32 and both were
	 * free. Nothing was wrong with the number; what was wrong is that
	 * nobody reading the struct could have known where to find it.
	 */
	uint32_t size;
	uint32_t reserved;
};

/*
 * A REGISTRY WRITE, WHICH USED TO OWN NO PAYLOAD AT ALL.
 *
 * The three registry verbs carried a path and nothing else, and that made the
 * one Windows persistence event the collector sees say less than a file write
 * does. What was missing was not detail - it was the difference between
 * reporting that persistence was established and reporting WHAT was persisted.
 *
 * The data itself is not here. It is bytes of arbitrary length, so it lives in
 * the text arena at off_data like every other variable-length thing; these are
 * the scalars that say how to read it.
 */
struct kof_evt_reg {
	/*
	 * THE VALUE'S FULL SIZE, WHICH IS NOT data_len. The provider captures a
	 * bounded prefix and the record bounds it again, so a rule that matched
	 * the bytes can still tell whether it saw all of them - compare the two
	 * and read KOF_EF_TRUNCATED.
	 */
	uint32_t data_size;

	/* REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD - winnt.h's small enum,
	 * so "a string was written here" is a question about a number rather
	 * than about the bytes. */
	uint8_t  type;

	/*
	 * WHETHER THE KEY WAS ACTUALLY CREATED, and it is what makes the CREATE
	 * verb mean anything.
	 *
	 * RegCreateKeyEx opens an existing key as readily as it makes a new one
	 * and Windows raises CreateKey either way, so without this every key a
	 * program merely touched arrived as a registry change - and a report
	 * that lists those is a report nobody reads twice. 0 says the event did
	 * not state it; 1 is created-new, 2 is opened-existing.
	 */
	uint8_t  disp;
	uint16_t reserved;
};

/* Which payload a verb owns. */
enum kof_evt_kind {
	KOF_EK_NONE = 0,   /* AMSI, continuation, raw - no payload */
	KOF_EK_PROC,
	KOF_EK_MEM,
	KOF_EK_NET,
	KOF_EK_FILE,
	KOF_EK_REG
};

/* Never guesses: a verb this build does not know is KOF_EK_NONE, so its
 * payload is unreadable rather than read as the wrong kind. */
enum kof_evt_kind kof_evt_kind_of(uint16_t verb);


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

	uint16_t verb;         /* enum kof_evt_verb */
	uint16_t attack;       /* enum kof_attack, of the object path */
	uint16_t raw_id;       /* the source's own event id, for a RAW event */

	/*
	 * KOF_F_* the collector could not fill.
	 *
	 * Sixteen bits, not thirty-two: there are seven of these flags and
	 * there is no prospect of nine more, so the other half was zero on
	 * every record ever written.
	 */
	uint16_t miss;

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

	/*
	 * WHICH SUBSYSTEM RAISED IT - enum kof_evt_source.
	 *
	 * WITHOUT THIS, `raw_id` MEANS NOTHING. An untyped event carries the
	 * source's own event id so a discovery run can name it later, and that
	 * id is only unique WITHIN a subsystem: on Windows, id 12 is a file
	 * event from Kernel-File and a connection from Kernel-Network. The
	 * collector knows which - it dispatches on it - and the conversion to
	 * this record used to drop it, so every raw event in a log said "id 12"
	 * with no way to tell those two apart. A trace full of them could not
	 * be used to type anything, which is the one job a raw event has.
	 *
	 * Taken from a reserved byte, so the record does not grow.
	 *
	 * Neutral, like every other field here: the numbers happen to match the
	 * Windows collector's enum today because it is the only collector, and
	 * a Linux one maps its own subsystems onto the same list rather than
	 * adding a second vocabulary.
	 */
	uint8_t  source;

	uint8_t  reserved[2];

	/*
	 * THE PER-VERB PAYLOAD. Read it with kof_evt_as_*, which check the
	 * verb; write it with kof_evt_set_*, which check it too and therefore
	 * require the verb to be set FIRST.
	 */
	union {
		struct kof_evt_proc proc;
		struct kof_evt_mem  mem;
		struct kof_evt_net  net;
		struct kof_evt_file file;
		struct kof_evt_reg  reg;
	} u;

	/*
	 * WHAT A REGISTRY WRITE WROTE - a second variable-length slot, and the
	 * first event here to need one.
	 *
	 * `object` holds WHERE and this holds WHAT, and neither substitutes for
	 * the other: the path says persistence was established, the data says
	 * what it persists. An AMSI submission needed only one slot because its
	 * metadata is deliberately not carried - see content_len.
	 *
	 * APPENDED AFTER THE UNION, WHICH IS NOT COSMETIC. This record is
	 * written to a file and read back by a different build; a field added
	 * anywhere above moves every field below it, and a path decoded at the
	 * wrong offset still looks like a path. Appended, every older field
	 * keeps the offset it had, and KOF_EVT_HEAD's assertion catches it if
	 * this claim ever stops being true.
	 *
	 * RAW BYTES: a REG_SZ is UTF-16 and has a NUL at index 1, so `data_len`
	 * is the length and the NUL written after it is only so that anything
	 * walking the arena as strings cannot run off the end.
	 */
	uint16_t off_data;     /* into text[], or KOF_TEXT_NONE */
	uint16_t data_len;

	char     text[KOF_EVT_SIZE - KOF_EVT_HEAD];
};

/*
 * THE SIZE AND THE LAYOUT, ASSERTED RATHER THAN DESCRIBED.
 *
 * This record is written to a file and read back by a different build, so a
 * field added above text[] without moving KOF_EVT_HEAD makes every string in
 * every record start at the wrong offset - and a path read from the wrong
 * offset still looks like a path. libkoforbit/grille's header claimed an equivalent
 * assertion existed and it did not, for the whole life of the file.
 */
_Static_assert(offsetof(struct kof_evt, text) == KOF_EVT_HEAD,
	       "KOF_EVT_HEAD no longer matches the record layout");
/*
 * THE PAYLOAD, IF THE VERB OWNS IT.
 *
 * NULL otherwise, and that is the point: a caller cannot reach a member
 * belonging to another kind of event without noticing. Reading a registry
 * event's `ports` used to be four bytes of whatever the flat layout happened
 * to leave there, which is a number, and a number is indistinguishable from a
 * fact once it is on screen.
 */
const struct kof_evt_proc *kof_evt_as_proc(const struct kof_evt *);
const struct kof_evt_mem  *kof_evt_as_mem(const struct kof_evt *);
const struct kof_evt_net  *kof_evt_as_net(const struct kof_evt *);
const struct kof_evt_file *kof_evt_as_file(const struct kof_evt *);
const struct kof_evt_reg  *kof_evt_as_reg(const struct kof_evt *);

/*
 * The same, to write - so a producer cannot fill in a payload the verb does
 * not have.
 *
 * THE VERB MUST BE SET FIRST. These read it to decide what to hand back, so a
 * producer that fills the payload before naming the event gets NULL, which is
 * a bug it will see immediately rather than a record whose bytes mean nothing.
 */
struct kof_evt_proc *kof_evt_set_proc(struct kof_evt *);
struct kof_evt_mem  *kof_evt_set_mem(struct kof_evt *);
struct kof_evt_net  *kof_evt_set_net(struct kof_evt *);
struct kof_evt_file *kof_evt_set_file(struct kof_evt *);
struct kof_evt_reg  *kof_evt_set_reg(struct kof_evt *);

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
 * ============================================================
 * A COMMAND LINE, IN THE ONE FORM A RULE IS WRITTEN AGAINST
 * ============================================================
 *
 * HERE RATHER THAN IN A COLLECTOR, and that is the whole point. Both platforms
 * report command lines - Linux out of /proc, Windows out of the process
 * event - and a rule that matched one spelling and not the other would be a
 * rule that works on one operating system by accident. One normaliser means
 * one form.
 *
 * WHAT IT DOES. Every run of whitespace becomes a single space, the ends are
 * trimmed, and a NUL is treated as an argument separator - which is how Linux
 * hands argv over and is harmless for a platform that hands over one string.
 * Control bytes become spaces too.
 *
 * WHY FLATTENING IS RIGHT HERE AND WRONG IN A SCRIPT. kof_script_norm guards
 * what is inside a string literal, because in source `"a   b"` is content a
 * signature may be taken from. A command line has no literals left to guard:
 * the shell parsed the quotes before exec, so what remains is the arguments
 * and the spacing between and inside them is formatting. An obfuscated command
 * pads with runs of spaces and tabs precisely because they survive into argv,
 * and flattening them is the purpose rather than a risk.
 *
 * AND CONTROL BYTES ARE A CORRECTNESS FIX, not tidying. A newline inside an
 * argument splits a live log line in two, and the second half is whatever the
 * attacker put after it: a forged record, written by the thing being watched.
 *
 * IT IS LOSSY AND SAYS SO. Two arguments and one argument containing a space
 * come out the same. A record carries one text arena shared between the image
 * and the command line, so the raw form is not kept beside it; what is stored
 * is what a rule matches.
 *
 * Answers the length written, and writes "" when there was nothing.
 */
size_t kof_cmdline_norm(const void *raw, size_t n, char *out, size_t cap);

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
 * The Makefile passes the real stamp; the fallback for a stray compilation is
 * kofdebug.h's, shared with kofeng.h.
 */

/* Name, build stamp, and a one-line description of what is being collected. */
void kof_evt_banner(FILE *out, const char *tool, uint32_t build,
		    const char *collects);

/* The subject's image path, what the event acted on, and how the subject was
 * invoked. "" when the record carries none. Never NULL. */
const char *kof_evt_image(const struct kof_evt *);
const char *kof_evt_object(const struct kof_evt *);
const char *kof_evt_cmdline(const struct kof_evt *);

/*
 * AND THE OTHER DIRECTION, which a COLLECTOR needs and nothing else does.
 *
 * Appends a string to the record's own text block and returns the offset one
 * of the off_* fields is set to, or KOF_TEXT_NONE when it does not fit - and
 * then the record is marked KOF_EF_TRUNCATED, because a path that was cut is
 * not the same claim as a path nobody supplied.
 *
 * Here rather than inside a collector: it was a static in libkoforbit/antarc's
 * fanotify half, and the process half needed the same fifteen lines. Two
 * copies of the code that decides what a record's text block looks like is
 * two places for the truncation flag to be forgotten in.
 */
uint16_t kof_evt_text_put(struct kof_evt *, const char *);

#endif /* KOFEVT_RECORD_H */
