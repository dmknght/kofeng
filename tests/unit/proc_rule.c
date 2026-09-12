/* SPDX-License-Identifier: Apache-2.0 */
/*
 * proc_rule.c - the process path, end to end, over synthetic records.
 *
 * WHAT IT IS ACTUALLY TESTING, which is not the two rules.
 *
 * It is testing that a collector can hand the engine a process and have a rule
 * in the database decide about it, with no C in between. Every link has to
 * hold for that: the builder writes the arena in region order, the parser
 * validates the offsets and fills the view, the target byte routes the object
 * to modules that declared KOF_EVT_PROC and to no others, and the rule reads
 * the view and reports. A break anywhere comes back as silence, which is why
 * this asserts on the NEGATIVE cases as hard as on the positive ones - a
 * rule that fires on everything passes any test that only checks it fires.
 *
 * SYNTHETIC AND NOT OVER A LIVE PROCESS, deliberately. The shapes here are the
 * ones measured on a real desktop and on a controlled reverse shell (see
 * libkofantarc/aproc.h), written down as numbers so the test runs on a host
 * with no /proc, no sensor and nothing malicious on it - which is what a CI is.
 */

#include <stdio.h>
#include <string.h>

#include "kofeng.h"
#include "kofmod/proc.h"
#include "kofproc.h"
#include "../../libkofeng/kofparsers/events/proc_parse.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

struct seen {
	char name[224];
	int  n, examined, broken, rc;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = (struct seen *)user;

	(void)name; (void)bytes; (void)len;
	s->examined = res ? (int)res->examined : -1;
	s->broken = res ? (int)res->broken : -1;
	if (res && res->n) {
		snprintf(s->name, sizeof s->name, "%s", res->v[0].name);
		s->n += (int)res->n;
	}
	return 0;
}

/* Scan one built record and return the first finding's name, or "". */
static const char *scan_rec(kof_scanner *sc, const struct kof_proc_build *b,
			    struct seen *s)
{
	unsigned char rec[KOF_PROC_REC_MAX];
	struct kof_scan_option opt;
	uint32_t n;

	memset(s, 0, sizeof *s);
	s->examined = -99;   /* so "callback never fired" is visible */
	n = kof_proc_build_rec(b, rec, sizeof rec);
	if (!n) {
		fail("the record would not build");
		return "";
	}

	memset(&opt, 0, sizeof opt);
	opt.as_format = KOF_EVT_PROC;   /* DECLARED - a process never sniffs */
	s->rc = kof_scan_bytes(sc, rec, n, "proc", &opt, on_object, s);
	return s->name;
}

static int said(const char *got, const char *want)
{
	return strstr(got, want) != NULL;
}

/* The shape measured on a controlled `bash -i >& /dev/tcp/...`: one socket on
 * fd 0 and fd 1, and every descriptor it holds names that same socket - four
 * of them, because bash keeps fd 255 for job control. */
static void base_revshell(struct kof_proc_build *b)
{
	memset(b, 0, sizeof *b);
	b->os = 2 /* KOF_PLAT_LINUX */;
	b->pid = 4242; b->ppid = 1;
	b->start_time = 99;
	b->exe = "/usr/bin/bash";
	b->comm = "bash";
	b->cmdline = "bash -i";
	b->fd0 = b->fd1 = b->fd2 = "socket:[14899490]";
	b->n_fd = 4; b->n_socket = 4; b->n_like_stdin = 4;
	b->flags = KOF_PROC_F_FDS_READ | KOF_PROC_F_EXE_ON_DISK;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	kof_engine  *eng;
	kof_scanner *sc;
	struct kof_proc_build b;
	struct seen s;

	eng = kof_engine_open(db);
	if (!eng) {
		printf("proc rule: cannot open %s\n", db);
		return 2;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		return 2;
	}

	printf("proc rule:\n");

	/* ---- the reverse shell shape ---- */
	base_revshell(&b);
	{
		const char *g = scan_rec(sc, &b, &s);

		printf("  bash, one socket on 0/1, nothing else open -> %s"
		       "  [rc=%d examined=%d]\n",
		       said(g, "RevShell") ? "RevShell" : "SILENT",
		       s.rc, s.examined);
	}
	if (!said(s.name, "RevShell"))
		fail("the shape the rule exists for was not reported");

	/*
	 * A SPAWNED CHILD WITH SOCKET STDIO - the eight processes measured on
	 * an idle desktop. A socketpair is two objects, so fd 0 and fd 1
	 * differ, and this must stay silent or the rule is worthless.
	 */
	base_revshell(&b);
	b.fd0 = "socket:[14376315]";
	b.fd1 = "socket:[14376317]";
	b.exe = "/usr/lib/code/code"; b.comm = "code";
	b.n_fd = 41; b.n_socket = 6; b.n_like_stdin = 1;
	printf("  a socketpair child (the eight FPs)         -> %s\n",
	       said(scan_rec(sc, &b, &s), "RevShell") ? "RevShell" : "silent");
	if (said(s.name, "RevShell"))
		fail("two different sockets were read as one");

	/* A relay: same socket on stdio, but it holds its listening socket
	 * too - so not every descriptor is that object. netcat and socat are
	 * this shape and are deliberately out of scope. */
	base_revshell(&b);
	b.n_fd = 6; b.n_like_stdin = 4;
	printf("  a relay holding a listening socket as well -> %s\n",
	       said(scan_rec(sc, &b, &s), "RevShell") ? "RevShell" : "silent");
	if (said(s.name, "RevShell"))
		fail("a process holding more than the connection was reported");

	/* The descriptor walk never ran: every count is zero and zero must not
	 * satisfy "every descriptor names fd 0" by accident. */
	base_revshell(&b);
	b.flags &= ~(uint32_t)KOF_PROC_F_FDS_READ;
	b.n_fd = 0; b.n_socket = 0; b.n_like_stdin = 0;
	printf("  the same process, descriptors not read     -> %s\n",
	       said(scan_rec(sc, &b, &s), "RevShell") ? "RevShell" : "silent");
	if (said(s.name, "RevShell"))
		fail("a question nobody asked was answered");

	/* ---- the kernel-thread masquerade ---- */
	memset(&b, 0, sizeof b);
	b.os = 2; b.pid = 77; b.ppid = 1;
	b.exe = "/tmp/x"; b.comm = "[kworker/0:9]";
	b.flags = KOF_PROC_F_EXE_ON_DISK;
	printf("  \"[kworker/0:9]\" with a file on disk        -> %s\n",
	       said(scan_rec(sc, &b, &s), "KThreadMasq") ? "KThreadMasq"
							: "SILENT");
	if (!said(s.name, "KThreadMasq"))
		fail("a bracketed name without PF_KTHREAD was not reported");

	/* A REAL kernel thread: the kernel's own bit agrees with the name. */
	memset(&b, 0, sizeof b);
	b.os = 2; b.pid = 12; b.comm = "[kworker/0:1]";
	b.flags = KOF_PROC_F_KTHREAD;
	printf("  a real kernel thread                       -> %s\n",
	       said(scan_rec(sc, &b, &s), "KThreadMasq") ? "KThreadMasq"
							: "silent");
	if (said(s.name, "KThreadMasq"))
		fail("the kernel's own bit was ignored");

	/* Bracketed, not a kernel thread, but nothing resolves on disk -
	 * which is a readlink that failed, not a masquerade. */
	memset(&b, 0, sizeof b);
	b.os = 2; b.pid = 13; b.comm = "[kworker/0:2]";
	printf("  bracketed, but no executable resolves      -> %s\n",
	       said(scan_rec(sc, &b, &s), "KThreadMasq") ? "KThreadMasq"
							: "silent");
	if (said(s.name, "KThreadMasq"))
		fail("a failed readlink was read as a masquerade");

	/* ---- the record itself ---- */
	{
		unsigned char rec[KOF_PROC_REC_MAX];
		const struct kof_proc_rec *r;
		uint32_t n;

		base_revshell(&b);
		n = kof_proc_build_rec(&b, rec, sizeof rec);
		r = (const struct kof_proc_rec *)rec;

		/* The partition: identity, then command line, then links. Out
		 * of order the regions overlap and a scoped rule reads the
		 * wrong bytes - see kofproc.h. */
		if (!(r->off_exe < r->off_cmdline &&
		      r->off_cmdline < r->off_fd0 && r->off_fd0 < n))
			fail("the arena is not in region order");

		if (kof_proc_build_rec(&b, rec, (uint32_t)sizeof *r) != 0)
			fail("a record that cannot fit was written anyway");
	}

	/* ---- the regions partition the arena, sections missing or not ---- */
	/*
	 * WHAT BROKE AND HOW IT LOOKED.
	 *
	 * The boundaries were read forwards, each absent section falling back
	 * to the END of the record. A process with no connections has no
	 * off_net, so MEM_ENV ran from the environment to the last byte of the
	 * arena - the descriptor links included. Nothing crashed and nothing
	 * overlapped, so the partition check above still passed; what happened
	 * is that a panel listing the environment listed three descriptor
	 * paths as variables, and a rule scoped to the environment searched
	 * bytes that were not it.
	 *
	 * It was invisible while the environment was one space-separated
	 * string, because everything read it with strlen and stopped at the
	 * first NUL. It became visible the moment the environment kept its
	 * NULs - a value may contain a space, so it had to - and the extent
	 * became the thing that says where it ends.
	 */
	{
		unsigned char rec[KOF_PROC_REC_MAX];
		struct kof_obj_ctx ctx;
		struct kof_proc_info pi;
		static const char env[] = "A=x y z\0DEBFULLNAME=Dm Knght";
		uint32_t n;

		memset(&b, 0, sizeof b);
		b.os = 2; b.pid = 5; b.ppid = 1;
		b.exe = "/usr/bin/sleep"; b.comm = "sleep";
		b.cmdline = "sleep 60";
		b.environ = env;
		b.environ_len = (uint32_t)(sizeof env - 1u);
		b.net = "";                    /* no connections - the case */
		b.fd0 = "/dev/null";
		b.fd1 = "/dev/null";
		b.fd2 = "pipe:[1234]";
		n = kof_proc_build_rec(&b, rec, sizeof rec);
		if (!n)
			fail("the record would not build");

		memset(&ctx, 0, sizeof ctx);
		memset(&pi, 0, sizeof pi);
		if (!kof_proc_parse(kof_buf_make(rec, n), &pi, &ctx))
			fail("the record would not parse");

		if (pi.len_env != sizeof env)
			fail("MEM_ENV is not the environment block - an "
			     "absent section gave it the rest of the arena");
		if (pi.len_meta + pi.len_cmdline + pi.len_env +
		    pi.len_net + pi.len_fd != n)
			fail("the regions do not cover the record");
		if (pi.len_fd == 0)
			fail("the descriptor links fell into another region");
		/*
		 * And the block itself still holds both assignments, the one
		 * with a space in its value included. A space separator turned
		 * "DEBFULLNAME=Dm Knght" into two rows, the second unnamed.
		 */
		if (memcmp(rec + pi.off_env, env, sizeof env - 1u))
			fail("the environment was not stored verbatim");
	}

	kof_scanner_free(sc);
	kof_engine_close(eng);
	printf("proc rule: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
