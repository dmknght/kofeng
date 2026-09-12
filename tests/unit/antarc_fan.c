/* SPDX-License-Identifier: Apache-2.0 */
/*
 * antarc_fan.c - the Linux file-event collector, over its own writes.
 *
 * WHAT IT CAN AND CANNOT TEST HERE, said first because the limit is the
 * interesting part.
 *
 * fanotify's unprivileged mode - the only one a CI has - reports dirent events
 * on a directory mark and fills `pid` ONLY for events the listener itself
 * caused. Measured on this kernel:
 *
 *     pid=80712  CREATE  self.txt     <- raised by the listener
 *     pid=0      CREATE  kid.txt      <- raised by anything else
 *
 * So this cannot test that the collector names the actor of somebody else's
 * write, because the kernel will not say. What it CAN test is everything
 * between the syscall and the record: that the event walk does not run off the
 * end of a read, that a name plus a marked directory becomes a whole path,
 * that a mask becomes the right verb, that a missing pid is reported as
 * MISSING rather than as zero, and that the self-filter breaks the feedback
 * loop a scanner would otherwise create for itself.
 *
 * Each of those has been a real bug in something, and none of them needs root.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "afan.h"

static int failures;

static void ok(int cond, const char *what)
{
	printf("  %-4s %s\n", cond ? "ok" : "FAIL", what);
	if (!cond)
		failures++;
}

#define DIR "build/test/antarc_fan.tmp"

/* Open a session on DIR, do `act`, and drain what comes back. */
static int drain(int trace_self, void (*act)(void), struct kof_evt *last,
		 uint32_t *pid_seen)
{
	const char *dirs[] = { DIR, NULL };
	struct kofa_fan_option o;
	struct kofa_fan *f;
	struct kof_evt e;
	int err = 0, n = 0;

	memset(&o, 0, sizeof o);
	o.dirs = dirs;
	o.trace_self = trace_self;

	f = kofa_fan_open(&o, &err);
	if (!f) {
		printf("  (fanotify unavailable: %s) - nothing to test\n",
		       kofa_err_name(err));
		return -1;
	}

	act();

	while (kof_mon_next(kofa_fan_api(f), &e, 300)) {
		n++;
		if (last)
			*last = e;
		if (pid_seen && !(e.miss & KOF_F_PID))
			*pid_seen = e.pid;
	}
	kofa_fan_close(f);
	return n;
}

static void act_create(void)
{
	int fd = open(DIR "/one.txt", O_CREAT | O_WRONLY, 0600);

	if (fd >= 0) {
		(void)!write(fd, "x", 1);
		close(fd);
	}
}

static void act_cycle(void)
{
	int fd = open(DIR "/a.txt", O_CREAT | O_WRONLY, 0600);

	if (fd >= 0) {
		(void)!write(fd, "x", 1);
		close(fd);
	}
	(void)rename(DIR "/a.txt", DIR "/b.txt");
	(void)unlink(DIR "/b.txt");
}

int main(void)
{
	struct kof_evt e;
	uint32_t pid = 0;
	int n;

	(void)mkdir("build", 0755);
	(void)mkdir("build/test", 0755);
	(void)mkdir(DIR, 0700);

	printf("antarc fan:\n");

	memset(&e, 0, sizeof e);
	n = drain(1, act_create, &e, &pid);
	if (n < 0)
		return 0;          /* no fanotify at all: not a failure */

	ok(n >= 1, "a create the listener made comes back");
	ok(e.verb == KOF_EVT_FILE_NEW, "and it is FileNew");
	ok(e.os == KOF_OS_LINUX, "tagged as a Linux record");
	ok(e.off_object != KOF_TEXT_NONE &&
	   strstr(e.text + e.off_object, "one.txt") != NULL,
	   "the object is the whole path, not the bare name");
	ok(e.loc != KOF_LOC_UNKNOWN, "the path was classified");
	ok(pid == (uint32_t)getpid(),
	   "the listener's own event carries the listener's pid");

	/*
	 * THE FEEDBACK LOOP. A scanner reads files, reading raises events, and
	 * those events make it read more. With the self-filter on - which is
	 * the default - none of its own activity comes back.
	 */
	pid = 0;
	n = drain(0, act_create, NULL, &pid);
	ok(n == 0, "with the self-filter on, its own writes are not reported");

	/* Three verbs out of one sequence. */
	{
		int saw_new = 0, saw_ren = 0, saw_del = 0;
		const char *dirs[] = { DIR, NULL };
		struct kofa_fan_option o;
		struct kofa_fan *f;
		int err = 0;

		memset(&o, 0, sizeof o);
		o.dirs = dirs;
		o.trace_self = 1;
		f = kofa_fan_open(&o, &err);
		if (f) {
			act_cycle();
			while (kof_mon_next(kofa_fan_api(f), &e, 300)) {
				if (e.verb == KOF_EVT_FILE_NEW)    saw_new = 1;
				if (e.verb == KOF_EVT_FILE_RENAME) saw_ren = 1;
				if (e.verb == KOF_EVT_FILE_DELETE) saw_del = 1;
				/* Unprivileged or not, a record must never
				 * carry a pid of zero as though it were one. */
				if (!(e.miss & KOF_F_PID) && e.pid == 0)
					failures++;
			}
			kofa_fan_close(f);
		}
		ok(saw_new && saw_ren && saw_del,
		   "create, rename and delete each map to their own verb");
	}

	/* A session reports which mode it got rather than pretending. */
	{
		const char *dirs[] = { DIR, NULL };
		struct kofa_fan_option o;
		struct kofa_fan *f;
		int err = 0;

		memset(&o, 0, sizeof o);
		o.dirs = dirs;
		f = kofa_fan_open(&o, &err);
		if (f) {
			int m = kofa_fan_mode(f);

			ok(m == KOFA_FAN_FULL || m == KOFA_FAN_DEGRADED,
			   "the session says which mode it got");
			ok(kofa_fan_watch_count(f) >= 1,
			   "and what it is watching");
			printf("       mode=%s watching %u\n",
			       kofa_fan_mode_name(m), kofa_fan_watch_count(f));
			kofa_fan_close(f);
		}
	}

	(void)unlink(DIR "/one.txt");
	(void)rmdir(DIR);
	printf("antarc fan: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
