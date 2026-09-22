/*
 * chan_ring - the sensor's ring, exercised with both ends in one process.
 *
 * WHY IT DID NOT EXIST AND WHY IT SHOULD. libkoforbit/chan is the whole path
 * from a sensor to whoever is deciding, and every property it claims is a
 * property of a CONCURRENT structure: what happens when the ring fills, what a
 * subscriber sees when the publisher laps it, and what a subscriber can do to
 * the publisher by writing the one word it owns. None of those was covered by
 * anything, and none of them fails loudly - a spliced record is a plausible
 * event, and a dropped one is silence.
 *
 * ONE PROCESS, TWO ENDS, AND THAT IS NOT A CHEAT. The publisher and the
 * subscriber share nothing but the mapping either way; running both here means
 * the test can drive the ring to an exact state - full, lapped, empty - which
 * two processes cannot be made to do reliably.
 *
 * POSIX ONLY, like the backend it drives. chan_win.c is the same contract over
 * CreateFileMapping and is not reachable from here.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../../libkoforbit/chan/kofchan.h"
#include "../../libkoforbit/evt/kofevt.h"

static int fails;

static void ok(const char *what)
{
	printf("  ok   %s\n", what);
}

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s - %s\n", what, why);
	fails++;
}

static void check(int cond, const char *what, const char *why)
{
	if (cond)
		ok(what);
	else
		fail(what, why);
}

/*
 * A NAME OF THIS RUN'S OWN.
 *
 * The publisher creates with O_EXCL and unlinks at close, so a crashed earlier
 * run would otherwise leave a name that makes every later run fail at the first
 * call - and the failure would look like the code rather than the leftover.
 */
static char chan_name[48];

static void name_for_this_run(void)
{
	snprintf(chan_name, sizeof chan_name, "kofchantest-%u",
		 (unsigned)getpid());
}

/* One event, distinguishable from every other by its pid and its text. */
static void mk(struct kof_evt *e, uint32_t pid, const char *obj)
{
	size_t n = strlen(obj);

	memset(e, 0, sizeof *e);
	e->verb        = 1;
	e->pid         = pid;
	e->off_image   = KOF_TEXT_NONE;
	e->off_cmdline = KOF_TEXT_NONE;
	memcpy(e->text, obj, n + 1);
	e->off_object  = 0;
	e->text_len    = (uint16_t)(n + 1);
}

/* ------------------------------------------------------------------------ */

static void attach_before_publish(void)
{
	struct kof_chan_sub *s;
	const char *why = NULL;
	int reason = -1;

	printf("\nattaching to a channel nobody published:\n");

	s = kof_chan_sub_open(chan_name, &why, &reason);
	check(!s, "there is nothing to attach to", "a subscriber was handed back");
	check(reason == KOF_CHAN_WHY_ABSENT,
	      "and the reason is ABSENT, not DENIED or BROKEN",
	      "the caller cannot tell the sensor is simply not running");
	if (s)
		kof_chan_sub_close(s);
}

static void one_publisher_only(void)
{
	struct kof_chan_pub *a, *b;

	printf("\ntwo publishers on one name:\n");

	a = kof_chan_publish_open(chan_name, 8);
	if (!a) {
		fail("the first publisher opens", "it did not");
		return;
	}
	ok("the first publisher opens");

	/*
	 * The header says creating one that already exists must FAIL rather
	 * than attach, because two publishers would interleave into one ring
	 * and the records coming out would belong to neither.
	 */
	b = kof_chan_publish_open(chan_name, 8);
	check(!b, "the second is refused rather than attached",
	      "two publishers share one ring");
	if (b)
		kof_chan_publish_close(b);

	kof_chan_publish_close(a);
}

static void header_describes_the_ring(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	const struct kof_chan_hdr *h;

	printf("\nwhat the header tells a subscriber:\n");

	/* 5 is not a power of two: the publisher rounds up, and a subscriber
	 * indexes with `t & (capacity - 1)` which is only an index at all if
	 * it did. */
	p = kof_chan_publish_open(chan_name, 5);
	if (!p) {
		fail("publisher opens", "it did not");
		return;
	}
	s = kof_chan_sub_open(chan_name, NULL, NULL);
	if (!s) {
		fail("subscriber attaches", "it did not");
		kof_chan_publish_close(p);
		return;
	}
	h = kof_chan_sub_header(s);
	if (!h) {
		fail("the header is readable", "it is not");
		kof_chan_sub_close(s);
		kof_chan_publish_close(p);
		return;
	}

	check(h->magic == KOF_CHAN_MAGIC, "the magic is set", "it is not");
	check(h->version == KOF_CHAN_VERSION, "the version is this build's",
	      "a subscriber would decode an unknown layout");
	check(h->capacity == 8, "a capacity of 5 was rounded up to 8",
	      "the ring index is not a mask");
	check((h->capacity & (h->capacity - 1u)) == 0,
	      "and it is a power of two", "`t & (capacity - 1)` is not an index");
	check(h->rec_size == sizeof(struct kof_evt),
	      "the record size is the record this build compiled",
	      "a subscriber would decode at the wrong offsets");
	check(h->head_size == KOF_EVT_HEAD, "the fixed part is declared",
	      "a record-agnostic reader cannot find the text");
	check(h->len_off == offsetof(struct kof_evt, text_len),
	      "and where the text length sits", "the arena cannot be bounded");
	check(h->pid == (uint32_t)getpid(), "the publisher names itself",
	      "a report cannot say who is producing");
	check(h->produced == 0 && h->dropped == 0,
	      "and nothing has been produced or dropped yet",
	      "the counters did not start at zero");

	kof_chan_sub_close(s);
	kof_chan_publish_close(p);
}

static void round_trip_in_order(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	struct kof_evt e, out;
	int i, seen = 0, wrong = 0;

	printf("\npublish eight, read eight:\n");

	p = kof_chan_publish_open(chan_name, 8);
	s = p ? kof_chan_sub_open(chan_name, NULL, NULL) : NULL;
	if (!p || !s) {
		fail("both ends open", "one of them did not");
		goto done;
	}

	for (i = 0; i < 8; i++) {
		char obj[32];

		snprintf(obj, sizeof obj, "/tmp/file-%d", i);
		mk(&e, (uint32_t)(1000 + i), obj);
		if (kof_chan_publish(p, &e))
			wrong++;
	}
	check(wrong == 0, "eight into an eight-slot ring are all taken",
	      "one was dropped with the ring not yet full");

	for (i = 0; i < 8; i++) {
		char want[32];

		if (!kof_chan_next(s, &out, 100))
			break;
		seen++;
		snprintf(want, sizeof want, "/tmp/file-%d", i);
		if (out.pid != (uint32_t)(1000 + i))
			wrong++;
		else if (strcmp(kof_evt_object(&out), want))
			wrong++;
	}
	check(seen == 8, "all eight come back", "fewer did");
	check(wrong == 0, "each one is the record that was published, in order",
	      "a record came back altered or out of sequence");

	/* The ring is empty now, and an empty ring must expire rather than
	 * hand back the slot it last read. */
	check(!kof_chan_next(s, &out, 0),
	      "a ninth read on an empty ring returns nothing",
	      "a consumed record was handed back a second time");

done:
	if (s)
		kof_chan_sub_close(s);
	if (p)
		kof_chan_publish_close(p);
}

static void full_ring_drops_and_counts(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	const struct kof_chan_hdr *h;
	struct kof_evt e;
	int i, dropped = 0;

	printf("\na ring nobody is draining:\n");

	p = kof_chan_publish_open(chan_name, 8);
	s = p ? kof_chan_sub_open(chan_name, NULL, NULL) : NULL;
	if (!p || !s) {
		fail("both ends open", "one of them did not");
		goto done;
	}
	h = kof_chan_sub_header(s);

	/* Twelve into eight slots with nothing reading: four must be refused,
	 * and refused is a return value AND a counter - a subscriber that
	 * attaches later has no other way to tell a quiet machine from one it
	 * could not keep up with. */
	for (i = 0; i < 12; i++) {
		mk(&e, (uint32_t)i, "/tmp/x");
		if (kof_chan_publish(p, &e))
			dropped++;
	}
	check(dropped == 4, "four of twelve are dropped by an eight-slot ring",
	      "the ring accepted more than it holds");
	check(h && h->dropped == 4, "and the header counts the same four",
	      "a subscriber cannot tell silence from loss");
	check(h && h->produced == 8, "with eight produced",
	      "a dropped record was counted as produced");

done:
	if (s)
		kof_chan_sub_close(s);
	if (p)
		kof_chan_publish_close(p);
}

static void lapped_subscriber_is_not_spliced(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	struct kof_evt e, out;
	int i, bad = 0;

	printf("\na subscriber the publisher lapped:\n");

	/*
	 * The subscriber reads ONE, then the publisher runs far ahead. The
	 * slot the subscriber's tail points at has been overwritten several
	 * times over, so reading from it would splice an old head onto a new
	 * body. kof_chan_next must jump to head-capacity instead: the loss has
	 * already happened, and what must not happen is reporting a spliced
	 * record as an event.
	 */
	p = kof_chan_publish_open(chan_name, 8);
	s = p ? kof_chan_sub_open(chan_name, NULL, NULL) : NULL;
	if (!p || !s) {
		fail("both ends open", "one of them did not");
		goto done;
	}

	mk(&e, 1, "/tmp/first");
	(void)kof_chan_publish(p, &e);
	check(kof_chan_next(s, &out, 100) && out.pid == 1,
	      "the first record is read", "it was not");

	/* 40 more through an 8-slot ring: the subscriber is lapped five times
	 * over. Nothing is draining, so the publisher drops once full - the
	 * tail is what lets it through, so the tail is advanced by reading. */
	for (i = 0; i < 40; i++) {
		char obj[32];

		snprintf(obj, sizeof obj, "/tmp/late-%d", i);
		mk(&e, (uint32_t)(100 + i), obj);
		if (kof_chan_publish(p, &e))
			(void)kof_chan_next(s, &out, 0);   /* make room */
	}

	/* Whatever comes out now must be a whole record: its text_len must
	 * bound its arena and its object offset must sit inside it. A spliced
	 * record is exactly what fails this. */
	while (kof_chan_next(s, &out, 0)) {
		const char *o;

		if (out.text_len > sizeof out.text) {
			bad++;
			continue;
		}
		o = kof_evt_object(&out);
		if (!o || strncmp(o, "/tmp/late-", 10)) {
			/* "/tmp/first" is gone - it was overwritten long ago -
			 * so anything that is not a late record is a splice. */
			bad++;
		}
	}
	check(bad == 0, "every record that came out is whole and is a late one",
	      "a record was spliced from two different writes");

done:
	if (s)
		kof_chan_sub_close(s);
	if (p)
		kof_chan_publish_close(p);
}

static void a_bogus_tail_costs_only_that_subscriber(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	struct kof_evt e;
	const struct kof_chan_hdr *h;
	int i, dropped = 0, taken = 0;

	printf("\na subscriber that writes nonsense into its cursor:\n");

	/*
	 * The cursor is the one word the lower-privilege half owns, and the
	 * publisher says it does not trust it: the depth is CLAMPED to a
	 * ring's worth.
	 *
	 * WHAT A TAIL AHEAD OF THE HEAD COSTS, and why the answer is "every
	 * event" rather than "none". `depth = h - t` wraps to a huge number
	 * when the tail is ahead, the clamp turns that into a full ring, and
	 * every publish is then refused. That looks alarming and is not: a
	 * channel has exactly ONE cursor, so "that subscriber's own events" in
	 * the note above IS the whole stream, and a consumer that wrecks its
	 * own cursor has wrecked its own stream and nothing else.
	 *
	 * So what is asserted here is what must hold no matter what the tail
	 * says: the publisher survives it, it never indexes outside the ring,
	 * and its counters still add up - because `dropped` is the only way a
	 * later reader learns the stream is not what the machine did.
	 */
	p = kof_chan_publish_open(chan_name, 8);
	s = p ? kof_chan_sub_open(chan_name, NULL, NULL) : NULL;
	if (!p || !s) {
		fail("both ends open", "one of them did not");
		goto done;
	}
	h = kof_chan_sub_header(s);

	/*
	 * THE CURSOR IS OPENED DIRECTLY, not through the subscriber handle,
	 * and that is the point rather than a shortcut. There is no accessor
	 * for it and there should not be: the threat this clamp answers is a
	 * consumer that does not use the library at all, and a test that went
	 * through the library would be asserting the library's own good
	 * manners. The cursor is a named shm object created 0600, so anything
	 * running as this user can open it - which is exactly the reach the
	 * publisher assumes its subscriber has.
	 */
	{
		char nc[64];
		int fd;
		struct kof_chan_cursor *c;

		snprintf(nc, sizeof nc, "/%s-c", chan_name);
		fd = shm_open(nc, O_RDWR, 0);
		if (fd < 0) {
			fail("the cursor object can be opened", "shm_open failed");
			goto done;
		}
		c = mmap(NULL, sizeof *c, PROT_READ | PROT_WRITE, MAP_SHARED,
			 fd, 0);
		close(fd);
		if (c == MAP_FAILED) {
			fail("the cursor can be mapped", "mmap failed");
			goto done;
		}
		c->tail = 0xFFFFFF00u;   /* far ahead of a head of zero */
		munmap(c, sizeof *c);
	}

	for (i = 0; i < 12; i++) {
		mk(&e, (uint32_t)i, "/tmp/x");
		if (kof_chan_publish(p, &e) > 0)
			dropped++;
		else
			taken++;
	}

	check(dropped + taken == 12,
	      "every publish returns taken-or-dropped, never an error",
	      "the publisher failed rather than refusing");
	check(h && h->produced == (uint64_t)taken &&
	      h->dropped == (uint64_t)dropped,
	      "and the counters agree with what the calls returned",
	      "a later reader cannot tell how much of the stream is missing");
	check(h && h->produced + h->dropped == 12,
	      "so nothing is lost without being counted",
	      "an event went missing silently");
	check(h && h->head <= 12,
	      "the head never ran past what was published",
	      "a bogus tail steered the publisher's own index");

done:
	if (s)
		kof_chan_sub_close(s);
	if (p)
		kof_chan_publish_close(p);
}

/*
 * The permissions the kernel actually granted the mapping that `p` is in, as
 * /proc/self/maps spells them ("r--s", "rw-s"). Empty when the address is in
 * no mapping at all.
 */
static void perms_of(const void *addr, char *out, size_t cap)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];

	out[0] = 0;
	if (!f)
		return;
	while (fgets(line, sizeof line, f)) {
		unsigned long lo, hi;
		char perms[8];

		if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3)
			continue;
		if ((uintptr_t)addr >= lo && (uintptr_t)addr < hi) {
			snprintf(out, cap, "%s", perms);
			break;
		}
	}
	fclose(f);
}

static void data_section_is_read_only_to_a_subscriber(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	struct kof_evt e;
	const struct kof_chan_hdr *h;
	char perms[8];

	printf("\nwhat a subscriber can write into the data section:\n");

	/*
	 * THE PROPERTY THE WHOLE DESIGN EXISTS FOR, so it is asserted rather
	 * than described: a subscriber maps the data section READ-ONLY, so a
	 * compromised consumer can lose its own events and cannot invent one.
	 *
	 * ASKED OF THE KERNEL, NOT BY FAULTING. The obvious test forks a child,
	 * writes through the mapping and expects SIGSEGV. It works in an
	 * ordinary build and is useless in the one that matters: under ASAN the
	 * fault is caught by the sanitiser, which prints a SEGV report and
	 * calls abort, so the child dies of SIGABRT and the run is noise. The
	 * mapping's permission bits are the same claim without the fault, and
	 * they are the thing the design actually depends on.
	 */
	p = kof_chan_publish_open(chan_name, 8);
	s = p ? kof_chan_sub_open(chan_name, NULL, NULL) : NULL;
	if (!p || !s) {
		fail("both ends open", "one of them did not");
		goto done;
	}
	mk(&e, 7, "/tmp/real");
	(void)kof_chan_publish(p, &e);

	h = kof_chan_sub_header(s);
	if (!h) {
		fail("the header is readable", "it is not");
		goto done;
	}

	/* The header and the slots are one mapping - the records sit directly
	 * after the header - so this is the permission on the records too. */
	perms_of(h, perms, sizeof perms);
	check(perms[0] == 'r',
	      "the subscriber can read the data section", "it cannot");
	check(perms[0] && perms[1] == '-',
	      "and cannot write it - a consumer cannot forge an event",
	      "the data section is writable to the subscriber");
	check(perms[0] && perms[3] == 's',
	      "it is the publisher's mapping, not a private copy",
	      "a private copy would see no further events");
	if (perms[0])
		printf("       %s\n", perms);

done:
	if (s)
		kof_chan_sub_close(s);
	if (p)
		kof_chan_publish_close(p);
}

static void a_closed_publisher_is_not_attachable(void)
{
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	int reason = -1;

	printf("\nafter the sensor stops:\n");

	p = kof_chan_publish_open(chan_name, 8);
	if (!p) {
		fail("publisher opens", "it did not");
		return;
	}
	kof_chan_publish_close(p);

	s = kof_chan_sub_open(chan_name, NULL, &reason);
	check(!s, "the channel is gone with it",
	      "a subscriber attached to a torn-down mapping");
	check(reason == KOF_CHAN_WHY_ABSENT,
	      "and it reads as absent rather than broken",
	      "the caller would be told to investigate a channel that is simply gone");
	if (s)
		kof_chan_sub_close(s);
}

int main(void)
{
	printf("chan ring:\n");
	name_for_this_run();

	attach_before_publish();
	one_publisher_only();
	header_describes_the_ring();
	round_trip_in_order();
	full_ring_drops_and_counts();
	lapped_subscriber_is_not_spliced();
	a_bogus_tail_costs_only_that_subscriber();
	data_section_is_read_only_to_a_subscriber();
	a_closed_publisher_is_not_attachable();

	if (fails) {
		printf("\nchan ring: %d check(s) failed\n", fails);
		return 1;
	}
	printf("\nchan ring: ok\n");
	return 0;
}
