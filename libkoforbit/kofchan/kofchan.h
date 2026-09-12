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
 * WHAT THIS VERSION DOES NOT DO, SAID PLAINLY
 *
 * One ring, and every subscriber sees all of it. A per-session ring, so that a
 * subscriber running as one logged-on user sees only that session's events, is
 * the thing that makes this safe to expose to a user-level process at all -
 * kof_evt.session_id is collected and ready for it - and it is not built. The
 * names are in the Local\ namespace, so today publisher and subscriber must
 * share a session, which contains the exposure by accident rather than by
 * design. Read that as: not yet fit to run as a service with user-level
 * subscribers.
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
 * On Windows it goes in the Local\ namespace - see the note above on why that
 * contains the exposure by accident rather than by design. On POSIX it becomes
 * /<name>-d and /<name>-c under shm, created 0600, so the containment is the
 * owning user rather than the session. Neither is a per-session ring, which is
 * what this still needs before a service may expose it to user-level
 * subscribers.
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
struct kof_chan_sub *kof_chan_sub_open(const char *name, const char **why);

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
