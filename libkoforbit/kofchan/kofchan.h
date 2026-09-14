/*
 * kofchan.h - the channel from a sensor to whoever is deciding.
 *
 * IT MOVED HERE FROM libkofgrille, AND THE MOVE IS THE POINT.
 *
 * The CONTRACT is platform-neutral and always was: a ring of kof_evt over
 * shared memory, the data section read-only in the subscriber and the cursor
 * in a section of its own. Only the BACKEND is not - chan_win.c maps it with
 * CreateFileMapping and wakes with an event, chan_posix.c with shm_open and a
 * named semaphore.
 *
 * Left in the Windows collector it was a Linux sensor's choice between copying
 * four hundred lines and depending on a library full of ETW. Neither of those
 * produces one channel that both ends agree about, which is the only thing a
 * channel is for.
 *
 * NOTE WHAT DID NOT MOVE WITH IT. wevt_ring.c, wfilter.c and wtext.c compile
 * without a Windows header and look neutral for that reason - they are not.
 * They operate on struct kofw_evt, the WINDOWS COLLECTOR'S record, and
 * kofw_evt_to_kof is the conversion from it to the neutral one. Moving them
 * here would move Windows-shaped code into the shared library, which is the
 * wrong direction: each platform keeps its own collector record and converts
 * into kof_evt, and kof_evt is what travels down this channel.
 *
 * kofwatchtower publishes; kofwatchman subscribes. This is the thing that
 * makes them two programs instead of one, so it is worth saying what it is and
 * what each of its parts is defending against.
 *
 *
 * A SHARED-MEMORY RING, NOT MESSAGES
 *
 * With the registry subscribed the stream is six figures a second. A syscall
 * per event - a pipe write, a socket send - is not a slow implementation of
 * this, it is a different product. The records are already fixed-size, POD,
 * pointer-free and byte-stable, which is what makes a mapped array of them
 * possible; that was the whole reason kof_evt was normalised.
 *
 *
 * TWO SECTIONS, AND THIS IS THE SECURITY OF IT
 *
 *   DATA    the header and the records.  READ-ONLY in the subscriber.
 *   CURSOR  one number: `tail`.          read-write in the subscriber.
 *
 * The subscriber has to advance `tail` or the publisher can never reclaim a
 * slot. If that lived in the data section, the section would have to be
 * writable - and then a compromised subscriber could overwrite live records:
 * forge events to blame another process, or flood benign ones to dilute a real
 * sequence. Writing history is a worse power than reading it.
 *
 * Split, the worst a subscriber can do is corrupt one 32-bit number, and the
 * publisher does not trust it: kof_chan_publish CLAMPS the tail it reads, so
 * a bogus value costs that subscriber its own events and nothing else. Event
 * injection stops being forbidden and becomes unrepresentable.
 *
 *
 * FULL MEANS DROP, AND THE PUBLISHER NEVER WAITS
 *
 * The publisher is the sensor. A sensor that blocked because a subscriber
 * stopped draining would be a sensor a subscriber can switch off - and the
 * subscriber is the lower-privilege half. So a full ring drops, counts, and
 * carries on, exactly as the in-process ring does and for a stronger reason.
 *
 *
 * THIS RING IS BETWEEN TWO PRIVILEGED PROCESSES, AND THAT IS THE ANSWER TO
 * THE QUESTION IT USED TO BE STUCK ON.
 *
 * What stood here said the channel was "not yet fit to run as a service with
 * user-level subscribers", and proposed a per-session ring so an unprivileged
 * client could see only its own session. That was solving the wrong problem.
 *
 * Raw telemetry is not something an unprivileged process should hold ANY of.
 * It carries process starts across every session, command lines - which are
 * where credentials turn up - and AMSI submissions, which are literally what
 * other users are executing. Slicing it per session narrows the disclosure
 * without changing its kind, and it blinds the client to session 0, where a
 * service-borne payload lives.
 *
 * So there are THREE tiers, not two, because there are two different
 * boundaries and one of them cannot do the other's job:
 *
 *   SENSOR    a service, SYSTEM. Collects, normalises, publishes. Never
 *             scans, so its work stays bounded and the drain never stalls -
 *             see the stability argument at the top of kofwatchman.c, which
 *             is why the sensor and the decider are two programs.
 *   DECIDER   privileged. Subscribes to THIS ring, scans files, will evaluate
 *             rules. Unbounded work, behind a boundary, so a slow scan costs
 *             a queue and not a stream.
 *   AGENT     an ordinary user. Receives VERDICTS about its own session over
 *             a different channel, and sends requests up over a third. Never
 *             touches this ring.
 *
 * Which is why this ring's access control is now simple: a private namespace
 * bound to Administrators, a DACL of SYSTEM and Administrators, and an owner
 * check on the subscriber - see chan_win.c. There is no group to administer
 * and no per-session slicing, because there is no unprivileged reader.
 *
 *
 * WHAT THIS VERSION DOES NOT DO, SAID PLAINLY
 *
 * The other two channels do not exist. The verdict channel down to an agent
 * and the control channel back up from it are designed and not built, and the
 * second is the one to be careful with: a request path from an unprivileged
 * process into a privileged one is where a protection product gets turned off.
 * It wants a named pipe rather than this ring - request/response, and a
 * caller that can be impersonated - a closed command set rather than strings,
 * and a privileged side that acts AS THE CALLER whenever a caller-supplied
 * path is involved. Settings that weaken protection must be gated on the
 * impersonated token, not on the pipe's DACL.
 *
 *
 * AND THE ONE THAT BITES EVERY PRODUCT THAT GETS THIS FAR: REMOVAL.
 *
 * There is no disinfection feature yet, and this is written before there is
 * one because it is a constraint on the PROTOCOL, which is decided first. The
 * request "this file is malware, delete it" arriving from an unprivileged
 * agent at a privileged decider is the confused deputy in its classic form -
 * the caller chooses the target and the deputy supplies the privilege - and
 * arbitrary-delete-as-SYSTEM is the single most recurring CVE class in
 * security products. Deleting is not the gentle end of writing; a file the
 * caller could not open is a file it must not be able to unlink either.
 *
 * Two rules, and the second is the one that is easy to miss:
 *
 *   A PATH IS NOT AN IDENTITY. The agent must not name the target at all. It
 *   references a VERDICT the decider itself issued - an opaque id for a scan
 *   this side performed - and the decider removes the object it convicted, not
 *   a string it was handed. A protocol that carries a path has already lost,
 *   because every check on that path happens before the delete rather than to
 *   the thing deleted.
 *
 *   IMPERSONATION ALONE IS NOT ENOUGH, because the filesystem moves. Between
 *   the scan that convicted a file and the unlink that removes it, the
 *   directory is writable by the attacker in exactly the case that matters -
 *   their own temp directory - and a junction, symlink or rename put there in
 *   the gap redirects the unlink onto something else. So: impersonate the
 *   caller for the open, refuse to follow reparse points on the way, and
 *   verify the opened object is the SAME OBJECT that was scanned - volume and
 *   file index, the identity koffridge already computes - before anything is
 *   removed. Act on the handle from then on, never on the name again.
 */

#ifndef KOFORBIT_KOFCHAN_H
#define KOFORBIT_KOFCHAN_H

#include <stdint.h>

#include "kofevt.h"

/* "KCHN". Checked before anything in the mapping is believed. */
#define KOF_CHAN_MAGIC   0x4e48434bu
#define KOF_CHAN_VERSION 1u

/*
 * The default base name.
 *
 * On Windows it is a stem inside the PRIVATE NAMESPACE, not in Local\: the
 * namespace is bound to Administrators, so the name cannot be created - or
 * squatted - by an unprivileged process, and it is not a name the rest of the
 * session can even enumerate. On POSIX it becomes /<name>-d and /<name>-c
 * under shm, created 0600, so the containment is the owning user.
 *
 * Neither is a per-session ring, and neither needs to be: both ends of this
 * channel are privileged. The unprivileged reader this once tried to serve is
 * the AGENT, and it is served by a different channel - see the three tiers
 * above.
 */
#define KOF_CHAN_NAME "kofwatchtower"

/*
 * The head of the data section.
 *
 * Every field a subscriber needs in order to REFUSE a mapping it cannot read
 * is here, for the same reason the log header carries them: a record that grew,
 * or a record from a different collector, decodes at plausible offsets and
 * means something else. A subscriber that trusted the layout would produce a
 * stream that is entirely wrong and entirely believable.
 */
struct kof_chan_hdr {
	uint32_t magic;
	uint32_t version;

	uint32_t rec_size;      /* stride of one slot */
	uint32_t head_size;     /* the record's fixed part */
	uint32_t len_off;       /* where its uint16 text length sits */
	uint32_t rec_kind;      /* enum kofevt_rec_kind */

	uint32_t capacity;      /* slots, a power of two */
	uint32_t pid;           /* the publisher, for reporting */

	/*
	 * The publisher's counters, readable by a subscriber so it can tell
	 * "the machine was quiet" from "we could not keep up". Written by the
	 * publisher only.
	 */
	uint64_t produced;
	uint64_t dropped;

	/*
	 * Free running, not wrapped, so full and empty are told apart by
	 * (head - tail) rather than by a spare slot. Unsigned wraparound at
	 * 2^32 is defined and the difference stays right across it.
	 */
	uint32_t head;
	uint32_t reserved;
};

/* The cursor section, alone, so the data section can be read-only. */
struct kof_chan_cursor {
	uint32_t tail;
	uint32_t reserved;
};

/* ------------------------------------------------------------- publishing */

struct kof_chan_pub;

/*
 * Create the channel. `name` NULL takes KOF_CHAN_NAME; `capacity` is rounded
 * up to a power of two and 0 takes a default.
 *
 * NULL on failure. Creating one that already exists fails rather than
 * attaching: two publishers on one ring would interleave into it, and the
 * records that came out would belong to neither.
 */
struct kof_chan_pub *kof_chan_publish_open(const char *name,
					     uint32_t capacity);

/*
 * Publish one record. Non-zero when the ring was full and it was dropped -
 * counted in the header, so a subscriber learns about it too.
 *
 * Never blocks. See the note above on why a sensor must not wait for a
 * subscriber.
 */
int kof_chan_publish(struct kof_chan_pub *, const struct kof_evt *);

void kof_chan_publish_close(struct kof_chan_pub *);

/* ------------------------------------------------------------ subscribing */

struct kof_chan_sub;

/*
 * Attach to a channel a publisher created. NULL when there is none, or when
 * its record is not one this build can decode - `why` gets a short reason and
 * may be NULL.
 */
/*
 * LET ONE GROUP SUBSCRIBE, on the hosts where a channel has an owner.
 *
 * A channel is created private to the account that published it. That is right
 * for a sensor and a consumer running as the same user, and wrong the moment
 * the sensor is a root service and the consumer is a CLI - the subscriber is
 * refused by a channel that is working. This widens it to one named group, and
 * it is a call rather than a default because the widening has a price: the
 * group can READ every path the sensor reports, and can WRITE the cursor and
 * so make the sensor believe records were consumed. It still cannot forge a
 * record; the data section stays read-only to a subscriber, which is the one
 * property this design exists to hold. The implementation says the rest.
 *
 * 0 on success, -1 with errno set. On Windows this returns -1/ENOSYS: an
 * access decision there is an ACL on the mapping, which is a different
 * mechanism and not a group name.
 */
int kof_chan_publish_grant(struct kof_chan_pub *, const char *group);

/*
 * THE SAME WIDENING, AIMED AT WHOEVER IS AT THE CONTROLLING TERMINAL, and
 * their login name written into `who` so a caller can say what it did.
 *
 * `sudo kofwatchtower` and then `kofwatchman` as yourself is how this is
 * actually run, and without this it does not work: the channel belongs to
 * root. A flag that has to be passed every time is a default in disguise, so
 * the default does it - and says so.
 *
 * 0 on success. -1 with errno ENOTTY when there is no controlling terminal,
 * which is the case for a service and is exactly when the channel SHOULD stay
 * private; EPERM when the terminal belongs to root already.
 *
 * Windows returns -1/ENOSYS, as with the group form.
 */
int kof_chan_publish_grant_console(struct kof_chan_pub *, char *who,
				   size_t who_cap);

/*
 * WHY AN ATTACH FAILED, as a code rather than only as prose.
 *
 * Because the ADVICE differs and a caller was giving the wrong one: told that
 * a channel exists but is not readable, it still printed "start kofwatchtower
 * first", which is the one thing that cannot help - the sensor is already
 * running. A string is for a human to read; this is for the caller to branch
 * on.
 */
enum kof_chan_why {
	KOF_CHAN_WHY_NONE = 0,
	KOF_CHAN_WHY_ABSENT,    /* nothing is published under that name */
	KOF_CHAN_WHY_DENIED,    /* it is there and this account may not use it */
	KOF_CHAN_WHY_BROKEN     /* it is there and is not usable by this build */
};

/* `reason` may be NULL; it gets a kof_chan_why. */
struct kof_chan_sub *kof_chan_sub_open(const char *name, const char **why,
				       int *reason);

/* The publisher's header, for a subscriber reporting what it is attached to. */
const struct kof_chan_hdr *kof_chan_sub_header(const struct kof_chan_sub *);

/*
 * Take the next record, waiting up to `wait_ms`. 1 if one was taken, 0 if the
 * wait expired with nothing there.
 */
int kof_chan_next(struct kof_chan_sub *, struct kof_evt *out,
		   uint32_t wait_ms);

void kof_chan_sub_close(struct kof_chan_sub *);

#endif /* KOFORBIT_KOFCHAN_H */
