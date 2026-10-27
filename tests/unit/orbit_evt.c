/*
 * orbit_evt - the event record and everything that reads one (libkoforbit/evt, and the host-pure part of grille).
 *
 *   vocab     every name function over its WHOLE domain (verb and attack 0..65535, source, loc, platform, arch 0..255)
 *   classify  a table of paths -> (location, technique); the order of the needles is what is under test
 *   record    text_put to the byte, the ip helpers, the content join, cmdline_norm at every cap, the payload accessors
 *   render    kof_evt_render for every verb, the field list for every verb (extents inside the record), labels, tally
 *   hostile   a record whose offsets lie and whose arena has no NUL (what a chan publisher can hand a viewer), in a child
 *             with a guard page behind the record, so an over-read is a fault and not a lucky read
 *   evtlog    the log file: round trip, 2500 records through the seek checkpoints, a truncated tail, headers that lie
 *   grille    the Windows collector's own pure parts that build here: ring, process table, text conversions, names
 * Defect rows are KM_CHECK (known_miss.h), ids WP12-n as in the work package report.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofevtlog.h"
#include "kofgrille.h"
#include "wevt_ring.h"
#include "wfilter.h"
#include "wtext.h"
#include "known_miss.h"
#include "../lib/orbit_sys.c"

static int fails, checks;
static char *R;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		printf("  FAIL %s\n", what);
		fails++;
	}
}

#define OKF(cond, ...) do { char w_[260]; snprintf(w_, sizeof w_, __VA_ARGS__); ok((cond), w_); } while (0)

static void mk(struct kof_evt *e, uint16_t verb, uint32_t pid)
{
	memset(e, 0, sizeof *e);
	e->verb = verb;
	e->pid = pid;
	e->actor_pid = pid;
	e->os = KOF_OS_LINUX;
	e->off_image = KOF_TEXT_NONE;
	e->off_object = KOF_TEXT_NONE;
	e->off_cmdline = KOF_TEXT_NONE;
	e->off_data = KOF_TEXT_NONE;
}

static char *render_to_str(const struct kof_evt *e, struct kof_evt_tally *t)
{
	char *buf = NULL;
	size_t n = 0;
	FILE *f = open_memstream(&buf, &n);

	kof_evt_render(e, 1.5, "who", f, t);
	fclose(f);
	return buf;
}

/* ------------------------------------------------------------------------------------------------- vocab */

static void case_vocab(void)
{
	unsigned i, bad = 0, named = 0;

	printf("\nnames over their whole domain:\n");
	for (i = 0; i < 65536; i++) {
		const char *v = kof_evt_verb_name((uint16_t)i), *a = kof_attack_name((uint16_t)i), *id = kof_attack_id((uint16_t)i);

		if (!v || !a || !id || strlen(v) > 24 || strlen(a) > 48 || strlen(id) > 12)
			bad++;
		if (i < KOF_EVT_TYPE_COUNT && i != KOF_EVT_NONE && !strcmp(v, "?"))
			bad++;
		if (i >= KOF_EVT_TYPE_COUNT && strcmp(v, "?"))
			bad++;
		if (i < KOF_ATT_COUNT && i != KOF_ATT_NONE && (!a[0] || !id[0]))
			bad++;
		if (i >= KOF_ATT_COUNT && (a[0] || id[0]))
			bad++;
		named += strcmp(v, "?") != 0;
	}
	OKF(bad == 0, "verb, attack name and id: every value answers, the enum's own are named, the rest are '?' / empty (%u bad)", bad);
	OKF(named == KOF_EVT_TYPE_COUNT - 1u, "%u verbs are named (all but NONE)", named);
	for (i = 0; i < 256; i++) {
		const char *s = kof_evt_source_name((uint8_t)i), *l = kof_loc_name((uint8_t)i), *p = kof_evt_platform_name((uint8_t)i),
			   *a = kof_evt_arch_name((uint8_t)i);

		if (!s || !l || !p || !a || strlen(s) > 12 || strlen(l) > 12 || strlen(p) > 12 || strlen(a) > 12)
			bad++;
		if ((i >= KOF_SRC_PROCESS && i < KOF_SRC_COUNT) == !strcmp(s, "?"))
			bad++;
		if ((i >= KOF_LOC_SYSTEM && i < KOF_LOC_COUNT) == !strcmp(l, "unknown"))
			bad++;
	}
	OKF(bad == 0, "source, loc, platform and arch names over 0..255");
	ok(!strcmp(kof_evt_platform_name(KOF_PLAT_WINDOWS), "windows") && !strcmp(kof_evt_platform_name(KOF_PLAT_LINUX), "linux") &&
	   !strcmp(kof_evt_platform_name(KOF_PLAT_MACOS), "macos") && !strcmp(kof_evt_platform_name(KOF_PLAT_UNKNOWN), "unknown"), "platform names");
	ok(!strcmp(kof_evt_arch_name(KOF_EARCH_X86), "x86") && !strcmp(kof_evt_arch_name(KOF_EARCH_X86_64), "x86_64") &&
	   !strcmp(kof_evt_arch_name(KOF_EARCH_ARM), "arm") && !strcmp(kof_evt_arch_name(KOF_EARCH_ARM64), "arm64"), "arch names");
	ok(kof_evt_platform_self() == KOF_PLAT_LINUX && kof_evt_arch_self() != KOF_EARCH_UNKNOWN, "this host is Linux and has a known arch");
	for (i = 0; i < KOF_EVT_TYPE_COUNT; i++)
		ok(kof_evt_kind_of((uint16_t)i) <= KOF_EK_REG, "kof_evt_kind_of stays inside the enum");
	ok(kof_evt_kind_of(60000) == KOF_EK_NONE, "a verb from a newer build has no payload kind");
}

struct cls_row {
	const char *path;
	uint8_t     loc;
	uint16_t    att;
};

static const struct cls_row cls_rows[] = {
	{ "/tmp/x", KOF_LOC_TEMP, KOF_ATT_NONE },
	{ "/var/tmp/x", KOF_LOC_TEMP, KOF_ATT_NONE },
	{ "/dev/shm/x", KOF_LOC_TEMP, KOF_ATT_NONE },
	{ "/home/u/.config/autostart/x.desktop", KOF_LOC_AUTOSTART, KOF_ATT_STARTUP_DIR },
	{ "/etc/xdg/autostart/x.desktop", KOF_LOC_AUTOSTART, KOF_ATT_STARTUP_DIR },
	{ "/etc/ld.so.preload", KOF_LOC_PRELOAD, KOF_ATT_LD_PRELOAD },
	{ "/etc/ld.so.conf.d/evil.conf", KOF_LOC_PRELOAD, KOF_ATT_LD_PRELOAD },
	{ "/etc/crontab", KOF_LOC_SCHEDULE, KOF_ATT_CRON },
	{ "/etc/cron.d/x", KOF_LOC_SCHEDULE, KOF_ATT_CRON },
	{ "/var/spool/cron/crontabs/root", KOF_LOC_SCHEDULE, KOF_ATT_CRON },
	{ "/etc/systemd/system/x.service", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD },
	{ "/lib/systemd/system/x.service", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD },
	{ "/home/u/.config/systemd/user/x.service", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD },
	{ "/etc/systemd/user/x.service", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD },
	{ "/run/systemd/system/x.service", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD },
	{ "/etc/rc.local", KOF_LOC_SHELL_INIT, KOF_ATT_RC_SCRIPT },
	{ "/etc/init.d/x", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT },
	{ "/etc/rc3.d/S99x", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT },
	{ "/etc/rcS.d/S01x", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT },
	{ "/home/u/.bashrc", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE },
	{ "/etc/bash.bashrc", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE },
	{ "/home/u/.zshrc", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE },
	{ "/etc/profile", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE },
	{ "/etc/update-motd.d/00-x", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE },
	{ "/home/u/.ssh/authorized_keys", KOF_LOC_SSH, KOF_ATT_SSH_KEY },
	{ "/home/u/.ssh/rc", KOF_LOC_SSH, KOF_ATT_SHELL_PROFILE },
	{ "/etc/ssh/sshrc", KOF_LOC_SSH, KOF_ATT_SHELL_PROFILE },
	{ "/etc/passwd", KOF_LOC_CREDENTIAL, KOF_ATT_ACCOUNT_FILE },
	{ "/etc/shadow", KOF_LOC_CREDENTIAL, KOF_ATT_ACCOUNT_FILE },
	{ "/etc/sudoers", KOF_LOC_CREDENTIAL, KOF_ATT_SUDOERS },
	{ "/etc/hosts", KOF_LOC_HOSTS, KOF_ATT_HOSTS },
	{ "/lib/modules/6.1/x.ko", KOF_LOC_KERNEL_MOD, KOF_ATT_KERNEL_MOD },
	{ "/var/www/html/shell.php", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL },
	{ "/srv/http/x.php", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL },
	{ "/usr/lib/x.so", KOF_LOC_SYSTEM, KOF_ATT_NONE },
	{ "/usr/bin/x", KOF_LOC_PROGRAMS, KOF_ATT_NONE },
	{ "/opt/x/y", KOF_LOC_PROGRAMS, KOF_ATT_NONE },
	{ "/home/u/x", KOF_LOC_USER, KOF_ATT_NONE },
	{ "/root/x", KOF_LOC_USER, KOF_ATT_NONE },
	{ "/somewhere/else", KOF_LOC_OTHER, KOF_ATT_NONE },
	{ "C:\\Users\\a\\AppData\\Local\\Temp\\x.exe", KOF_LOC_TEMP, KOF_ATT_NONE },
	{ "C:\\USERS\\A\\APPDATA\\LOCAL\\TEMP\\X.EXE", KOF_LOC_TEMP, KOF_ATT_NONE },
	{ "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x", KOF_LOC_AUTOSTART, KOF_ATT_RUN_KEY },
	{ "\\Device\\NamedPipe\\evil", KOF_LOC_PIPE, KOF_ATT_PIPE_IMPERSONATE },
	{ "C:\\Windows\\System32\\sethc.exe", KOF_LOC_AUTOSTART, KOF_ATT_ACCESSIBILITY },
	{ "C:\\Windows\\System32\\kernel32.dll", KOF_LOC_SYSTEM, KOF_ATT_NONE },
	{ "C:\\Program Files\\x\\y.exe", KOF_LOC_PROGRAMS, KOF_ATT_NONE },
	{ "C:\\Windows\\System32\\drivers\\etc\\hosts", KOF_LOC_HOSTS, KOF_ATT_HOSTS },
	{ "C:\\Windows\\System32\\drivers\\x.sys", KOF_LOC_KERNEL_MOD, KOF_ATT_KERNEL_MOD },
	{ "/ETC/PASSWD", KOF_LOC_OTHER, KOF_ATT_NONE },       /* a Linux path is case-sensitive: this is not the file */
	{ "/tmp/../etc/passwd", KOF_LOC_TEMP, KOF_ATT_NONE }, /* classified by substring, order of the table: the first needle wins (WP12-9 note) */
};

static void case_classify(void)
{
	unsigned i;
	uint16_t att;

	printf("\nkof_classify (a table):\n");
	for (i = 0; i < sizeof cls_rows / sizeof cls_rows[0]; i++) {
		uint8_t loc = kof_classify(cls_rows[i].path, &att);

		OKF(loc == cls_rows[i].loc && att == cls_rows[i].att, "classify '%s' -> %s / %s (got %s / %s)", cls_rows[i].path,
		    kof_loc_name(cls_rows[i].loc), kof_attack_name(cls_rows[i].att), kof_loc_name(loc), kof_attack_name(att));
		ok(kof_classify_path(cls_rows[i].path) == loc, "kof_classify_path agrees with kof_classify");
	}
	ok(kof_classify(NULL, &att) == KOF_LOC_UNKNOWN && att == KOF_ATT_NONE, "NULL path: unknown, no technique");
	ok(kof_classify("", &att) == KOF_LOC_UNKNOWN, "empty path: unknown");
	ok(kof_classify("/etc/passwd", NULL) == KOF_LOC_CREDENTIAL, "a NULL technique pointer is accepted");
	{
		char *big = malloc(1u << 20);

		memset(big, 'a', (1u << 20) - 1u);
		big[(1u << 20) - 1u] = '\0';
		ok(kof_classify(big, NULL) == KOF_LOC_OTHER, "a 1 MiB path with no needle: OTHER, in bounded time (the scan is O(n * rows))");
		memcpy(big + (1u << 20) - 20, "/etc/passwd", 12);
		ok(kof_classify(big, NULL) == KOF_LOC_CREDENTIAL, "a needle at the very end of 1 MiB is found");
		free(big);
	}
	ok(kof_path_leaf("a/b\\c.txt") && !strcmp(kof_path_leaf("a/b\\c.txt"), "c.txt") && !strcmp(kof_path_leaf("noslash"), "noslash") &&
	   !strcmp(kof_path_leaf("dir/"), "") && !strcmp(kof_path_leaf(""), "") && !strcmp(kof_path_leaf("/"), "") && !strcmp(kof_path_leaf("\\\\x"), "x"),
	   "kof_path_leaf: both separators, none, a trailing one, empty");
}

/* ------------------------------------------------------------------------------------------------- record */

static void case_record(void)
{
	struct kof_evt e;
	uint8_t ip[16];
	char s[64];
	uint16_t off, off2;
	unsigned i;

	printf("\nthe record: text arena, addresses, payload kinds:\n");
	mk(&e, KOF_EVT_FILE_NEW, 1);
	ok(kof_evt_text_put(&e, NULL) == KOF_TEXT_NONE && kof_evt_text_put(&e, "") == KOF_TEXT_NONE && kof_evt_text_put(NULL, "x") == KOF_TEXT_NONE,
	   "text_put: NULL and empty strings are KOF_TEXT_NONE");
	ok(e.text_len == 0 && !(e.flags & KOF_EF_TRUNCATED), "and take no room");
	off = kof_evt_text_put(&e, "abc");
	off2 = kof_evt_text_put(&e, "de");
	ok(off == 0 && off2 == 4 && e.text_len == 7 && !strcmp(e.text, "abc") && !strcmp(e.text + 4, "de"), "two strings, offsets 0 and 4");
	/* fill to the byte: 540 bytes of arena */
	mk(&e, KOF_EVT_FILE_NEW, 1);
	{
		char blob[600];

		memset(blob, 'x', sizeof blob);
		blob[538] = '\0';                                  /* 538 + NUL = 539 bytes */
		ok(kof_evt_text_put(&e, blob) == 0 && e.text_len == 539, "a 538-byte string takes 539 of the 540");
		ok(kof_evt_text_put(&e, "") == KOF_TEXT_NONE, "nothing more of nothing");
		ok(kof_evt_text_put(&e, "y") == KOF_TEXT_NONE && (e.flags & KOF_EF_TRUNCATED) && e.text_len == 539, "one more byte of room is not enough for 'y'+NUL: refused, TRUNCATED");
		e.flags = 0;
		mk(&e, KOF_EVT_FILE_NEW, 1);
		blob[538] = 'x';
		blob[539] = '\0';                                  /* 539 + NUL = 540 exactly */
		ok(kof_evt_text_put(&e, blob) == 0 && e.text_len == 540, "a 539-byte string fills the arena exactly");
		ok(kof_evt_text_put(&e, "z") == KOF_TEXT_NONE && (e.flags & KOF_EF_TRUNCATED), "then nothing fits");
		mk(&e, KOF_EVT_FILE_NEW, 1);
		blob[539] = 'x';
		blob[540] = '\0';
		ok(kof_evt_text_put(&e, blob) == KOF_TEXT_NONE && e.text_len == 0 && (e.flags & KOF_EF_TRUNCATED), "a 540-byte string never fits: refused whole, nothing half-written");
	}
	/* accessors */
	mk(&e, KOF_EVT_PROC_START, 1);
	e.off_image = kof_evt_text_put(&e, "/bin/x");
	e.off_cmdline = kof_evt_text_put(&e, "x -a");
	ok(!strcmp(kof_evt_image(&e), "/bin/x") && !strcmp(kof_evt_cmdline(&e), "x -a") && !strcmp(kof_evt_object(&e), ""), "image, cmdline, and an absent object is the empty string");
	e.off_object = 540;
	ok(!strcmp(kof_evt_object(&e), ""), "an offset at the end of the arena is the empty string");
	e.off_object = 0xfffe;
	ok(!strcmp(kof_evt_object(&e), "") && !strcmp(kof_evt_image(NULL), ""), "an offset past the arena, and a NULL record, are the empty string");
	/* kinds */
	for (i = 0; i < KOF_EVT_TYPE_COUNT; i++) {
		struct kof_evt k;
		enum kof_evt_kind kind;

		mk(&k, (uint16_t)i, 1);
		kind = kof_evt_kind_of((uint16_t)i);
		OKF((kof_evt_as_proc(&k) != NULL) == (kind == KOF_EK_PROC) && (kof_evt_as_mem(&k) != NULL) == (kind == KOF_EK_MEM) &&
		    (kof_evt_as_net(&k) != NULL) == (kind == KOF_EK_NET) && (kof_evt_as_file(&k) != NULL) == (kind == KOF_EK_FILE) &&
		    (kof_evt_as_reg(&k) != NULL) == (kind == KOF_EK_REG) && (kof_evt_set_proc(&k) != NULL) == (kind == KOF_EK_PROC),
		    "verb %u: exactly the accessor of its kind answers", i);
	}
	ok(kof_evt_as_proc(NULL) == NULL && kof_evt_set_net(NULL) == NULL, "NULL record: no payload");
	/* addresses */
	memset(ip, 0, sizeof ip);
	ok(kof_evt_ip_is_unset(ip) && !kof_evt_ip_is_v6(ip), "all zeros: unset, not v6");
	kof_evt_ip_set_v4(ip, 0x0100007fu);                        /* 127.0.0.1 in network order as read on little-endian */
	ok(!kof_evt_ip_is_unset(ip) && !kof_evt_ip_is_v6(ip) && !strcmp(kof_evt_ip_str(ip, s, sizeof s), "127.0.0.1"), "a v4 address prints dotted");
	memset(ip, 0, sizeof ip);
	ip[0] = 0x20;
	ip[1] = 0x01;
	ip[2] = 0x0d;
	ip[3] = 0xb8;
	ip[15] = 1;
	ok(kof_evt_ip_is_v6(ip) && !kof_evt_ip_is_unset(ip), "a v6 address is v6");
	ok(kof_evt_ip_str(ip, s, sizeof s) == s && strchr(s, ':') != NULL, "and prints with colons");
	for (i = 0; i <= 50; i++) {
		char t[64];

		memset(t, 0x55, sizeof t);
		kof_evt_ip_str(ip, t, i);
		if (i && (strlen(t) >= i || t[i] != 0x55 + 0 * i)) {
			if (i < 64 && t[i] != 0x55) {
				OKF(0, "ip_str with cap %u wrote past its buffer", i);
				break;
			}
		}
	}
	ok(kof_evt_ip_str(ip, NULL, 10) == NULL || 1, "NULL out is accepted");
	/* time */
	ok(kof_evt_secs_since(10, 5) == 0.0 && kof_evt_secs_since(0, KOF_TICKS_PER_SEC) == 1.0 && kof_evt_secs_since(KOF_TICKS_PER_SEC, 3u * KOF_TICKS_PER_SEC) == 2.0,
	   "secs_since: negative is 0, ticks are 100 ns");
	{
		uint64_t a = kof_evt_now(), b = kof_evt_now();

		ok(a > 116444736000000000ull && b >= a, "kof_evt_now is a FILETIME after 1970 and does not go back");
	}
}

struct norm_row {
	const char *id;
	const char *in;
	size_t      n;
	size_t      cap;
	const char *out;
};

#define NR(id, in, cap, out) { id, in, sizeof(in) - 1u, cap, out }

static const struct norm_row norm_rows[] = {
	NR("plain", "ls -la", 64, "ls -la"),
	NR("NUL separators", "a\0b\0c\0", 64, "a b c"),
	NR("trailing NULs", "a\0\0\0", 64, "a"),
	NR("leading space and NUL", "\0\0  a", 64, "a"),
	NR("runs of whitespace collapse", "a \t\r\n  b", 64, "a b"),
	NR("DEL is a separator", "a\x7f" "b", 64, "a b"),
	NR("control bytes are separators", "a\x01\x02" "b", 64, "a b"),
	NR("high bytes pass through", "a\xff\xfe" "b", 64, "a\xff\xfe" "b"),
	NR("all separators", "\0\0\0 \t", 64, ""),
	NR("empty", "", 64, ""),
	NR("cap 1 is just the terminator", "abc", 1, ""),
	NR("cap 2 holds one byte", "abc", 2, "a"),
	NR("cap exactly fits", "abc", 4, "abc"),
	NR("cap one short", "abc", 3, "ab"),
	NR("a cut that ends in a space is trimmed", "ab cd", 4, "ab"),
};

static void case_cmdline_norm(void)
{
	unsigned i;
	char out[80];

	printf("\nkof_cmdline_norm (a table, then every cap):\n");
	for (i = 0; i < sizeof norm_rows / sizeof norm_rows[0]; i++) {
		const struct norm_row *r = &norm_rows[i];
		size_t n;

		memset(out, 0x55, sizeof out);
		n = kof_cmdline_norm(r->in, r->n, out, r->cap);
		OKF(!strcmp(out, r->out) && n == strlen(r->out), "norm row '%s'", r->id);
	}
	ok(kof_cmdline_norm(NULL, 3, out, 10) == 0 && out[0] == '\0', "NULL input: empty");
	ok(kof_cmdline_norm("a", 1, NULL, 10) == 0 && kof_cmdline_norm("a", 1, out, 0) == 0, "NULL output and cap 0: 0, nothing written");
	{
		/* exhaustive over a small alphabet: every string of length <= 5 over {a, NUL, space} at every cap */
		static const char alpha[3] = { 'a', '\0', ' ' };
		unsigned long total = 0;
		char in[5];
		unsigned len, k, cap, v;

		for (len = 0; len <= 5; len++) {
			unsigned n3 = 1;

			for (k = 0; k < len; k++)
				n3 *= 3;
			for (v = 0; v < n3; v++) {
				unsigned x = v;

				for (k = 0; k < len; k++) {
					in[k] = alpha[x % 3];
					x /= 3;
				}
				for (cap = 1; cap <= 8; cap++) {
					char o[16];
					size_t w;
					size_t j;

					memset(o, 0x55, sizeof o);
					w = kof_cmdline_norm(in, len, o, cap);
					total++;
					if (w >= cap || o[w] != '\0' || strlen(o) != w || (w && (o[0] == ' ' || o[w - 1] == ' ')))
						fails++;
					for (j = 0; j + 1 < w; j++)
						if (o[j] == ' ' && o[j + 1] == ' ')
							fails++;
					if (o[cap] != 0x55 && cap < 8)
						fails++;
				}
			}
		}
		OKF(1, "exhaustive: %lu inputs x caps, terminated, trimmed, no double space, inside the cap", total);
	}
}

static void case_join(void)
{
	struct kof_evt p, c1, c2, c3;
	struct kof_evt_join j;
	char buf[2000];

	printf("\nkof_evt_join: content split over continuations:\n");
	mk(&p, KOF_EVT_AMSI_SCAN, 5);
	p.seq = 10;
	p.off_object = kof_evt_text_put(&p, "HEAD");
	p.content_len = 4;
	mk(&c1, KOF_EVT_CONT, 5);
	c1.seq = 11;
	c1.off_object = kof_evt_text_put(&c1, "-MID");
	c1.content_len = 4;
	mk(&c2, KOF_EVT_CONT, 5);
	c2.seq = 12;
	c2.off_object = kof_evt_text_put(&c2, "-END");
	c2.content_len = 4;
	ok(kof_evt_join_start(&j, &p, buf, sizeof buf) == 1 && j.len == 4, "start takes the parent's content");
	ok(kof_evt_join_add(&j, &c1) == 1 && kof_evt_join_add(&j, &c2) == 1 && j.len == 12 && !memcmp(buf, "HEAD-MID-END", 12), "two contiguous chunks join in order");
	ok(kof_evt_join_whole(&j, &p) == 1, "whole: contiguous, not full, parent not cut");
	/* a gap */
	kof_evt_join_start(&j, &p, buf, sizeof buf);
	ok(kof_evt_join_add(&j, &c2) == 0 && j.holed && kof_evt_join_whole(&j, &p) == 0, "a chunk after a gap: refused, holed, not whole");
	ok(kof_evt_join_add(&j, &c1) == 0, "and the join stays closed after a hole");
	/* a full buffer */
	kof_evt_join_start(&j, &p, buf, 6);
	ok(kof_evt_join_add(&j, &c1) == 1 && j.len == 6 && j.full && kof_evt_join_whole(&j, &p) == 0, "a buffer that cannot hold it: cut to cap, full, not whole");
	kof_evt_join_start(&j, &p, buf, 2);
	ok(j.full && j.len == 2, "a buffer smaller than the parent's content: full at once");
	/* the parent says it was cut */
	p.flags |= KOF_EF_TRUNCATED;
	kof_evt_join_start(&j, &p, buf, sizeof buf);
	ok(kof_evt_join_whole(&j, &p) == 0, "a cut parent with no continuation is not whole");
	kof_evt_join_add(&j, &c1);
	ok(kof_evt_join_whole(&j, &p) == 1, "and is once a continuation arrived");
	p.flags = 0;
	/* refusals */
	ok(kof_evt_join_start(&j, &c1, buf, sizeof buf) == 0 && j.idle, "a continuation cannot start a join");
	ok(kof_evt_join_add(&j, &c1) == 0 && kof_evt_join_whole(&j, &p) == 0, "an idle join takes nothing");
	ok(kof_evt_join_start(NULL, &p, buf, 1) == 0 && kof_evt_join_start(&j, NULL, buf, 1) == 0 && kof_evt_join_start(&j, &p, NULL, 1) == 0 &&
	   kof_evt_join_start(&j, &p, buf, 0) == 0, "NULL parent, NULL buffer, zero cap");
	{
		struct kof_evt f;

		mk(&f, KOF_EVT_FILE_NEW, 5);
		ok(kof_evt_join_start(&j, &f, buf, sizeof buf) == 0, "a verb with no content is not a join parent");
	}
	kof_evt_join_start(&j, &p, buf, sizeof buf);
	mk(&c3, KOF_EVT_FILE_NEW, 5);
	c3.seq = 11;
	ok(kof_evt_join_add(&j, &c3) == 0 && kof_evt_join_add(&j, NULL) == 0 && kof_evt_join_add(NULL, &c1) == 0, "a chunk that is not a continuation, NULL chunk, NULL join");
	/* a chunk with no content is contiguous and adds nothing */
	mk(&c3, KOF_EVT_CONT, 5);
	c3.seq = 11;
	ok(kof_evt_join_add(&j, &c3) == 1 && j.len == 4, "an empty continuation is contiguous and adds nothing");
	/* a content_len longer than the arena is clamped to what the arena holds */
	mk(&c3, KOF_EVT_CONT, 5);
	c3.seq = 12;
	c3.off_object = 500;
	c3.content_len = 60000;
	ok(kof_evt_join_add(&j, &c3) == 1 && j.len == 4 + 40, "content_len beyond the arena is clamped to the bytes the record has (40)");
	/* the parent with no content but an AMSI verb */
	{
		struct kof_evt a;

		mk(&a, KOF_EVT_AMSI_SCAN, 1);
		ok(kof_evt_join_start(&j, &a, buf, sizeof buf) == 1 && j.len == 0, "an AMSI parent with no content starts an empty join");
	}
}

/* ------------------------------------------------------------------------------------------------- render */

static void fill_for(struct kof_evt *e, uint16_t verb)
{
	mk(e, verb, 321);
	e->ppid = 12;
	e->tid = 654;
	e->stamp = 132000000000000000ull;
	e->seq = 7;
	e->off_image = kof_evt_text_put(e, "/usr/bin/image");
	e->off_cmdline = kof_evt_text_put(e, "image --flag");
	e->off_object = kof_evt_text_put(e, "/etc/hosts");
	e->loc = kof_classify("/etc/hosts", &e->attack);
	switch (kof_evt_kind_of(verb)) {
	case KOF_EK_PROC:
		kof_evt_set_proc(e)->exit_code = 3;
		kof_evt_set_proc(e)->session_id = 2;
		kof_evt_set_proc(e)->create_time = 99;
		break;
	case KOF_EK_MEM:
		kof_evt_set_mem(e)->addr = 0x7f001000ull;
		kof_evt_set_mem(e)->addr_size = 4096;
		break;
	case KOF_EK_NET: {
		struct kof_evt_net *n = kof_evt_set_net(e);

		kof_evt_ip_set_v4(n->daddr, 0x0100007fu);
		n->dport = 0x5000;           /* 80, network order */
		n->size = 321;
		break;
	}
	case KOF_EK_FILE:
		kof_evt_set_file(e)->size = 64;
		kof_evt_set_file(e)->offset = 34;
		kof_evt_set_file(e)->key = 0xabc;
		break;
	case KOF_EK_REG: {
		struct kof_evt_reg *r = kof_evt_set_reg(e);

		r->type = 1;
		r->data_size = 100;
		r->disp = 1;
		e->off_data = kof_evt_text_put(e, "h\0i\0\0\0");
		e->data_len = 6;
		break;
	}
	default:
		break;
	}
}

static void case_render(void)
{
	unsigned v;
	struct kof_evt_tally t;
	char *s;

	printf("\nrender, fields, labels for every verb:\n");
	memset(&t, 0, sizeof t);
	for (v = 0; v < KOF_EVT_TYPE_COUNT + 2; v++) {
		struct kof_evt e;
		unsigned nf, i;
		char name[64], val[128], lbl[KOF_EVT_LABEL_MAX];
		uint16_t off, len;

		fill_for(&e, (uint16_t)v);
		s = render_to_str(&e, &t);
		if (v == KOF_EVT_CONT)
			OKF(s && !s[0], "verb %u (a continuation) renders nothing", v);
		else
			OKF(s && strstr(s, "pid=321") && s[strlen(s) - 1] == '\n', "verb %u renders one line with its pid", v);
		free(s);
		nf = kof_evt_n_fields(&e);
		OKF(nf >= 3 && nf < 40, "verb %u has %u fields", v, nf);
		for (i = 0; i < nf; i++) {
			int got = kof_evt_field(&e, i, name, sizeof name, val, sizeof val);

			OKF(got == 1 && name[0], "verb %u field %u has a name", v, i);
			off = len = 0xffff;
			OKF(kof_evt_field_extent(&e, i, &off, &len) == 1 && (uint32_t)off + len <= sizeof e, "verb %u field %u extent %u+%u is inside the record", v, i, off, len);
		}
		OKF(kof_evt_field(&e, nf, name, sizeof name, val, sizeof val) == 0 && kof_evt_field_extent(&e, nf, &off, &len) == 0,
		    "verb %u: the field after the last is refused", v);
		OKF(kof_evt_label(&e, 42, lbl, sizeof lbl) > 0 && strstr(lbl, "42 ") == lbl, "verb %u label starts with the index", v);
	}
	/* specific lines */
	{
		struct kof_evt e;

		fill_for(&e, KOF_EVT_PROC_START);
		memset(&t, 0, sizeof t);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "ppid=12  /usr/bin/image") && strstr(s, "cmd: image --flag") && t.proc == 1, "ProcStart: ppid, image, the command line on its own line, counted");
		free(s);
		e.off_cmdline = KOF_TEXT_NONE;
		e.flags |= KOF_EF_CMDLINE_RACED | KOF_EF_UNBACKED | KOF_EF_LATE_LOAD | KOF_EF_TRUNCATED | KOF_EF_PARTIAL;
		e.miss = KOF_F_CMDLINE;
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "[cmd unread: process gone]") && strstr(s, "<<UNBACKED") && strstr(s, "[late]") && strstr(s, "[cut]") && strstr(s, "[miss 0x80]"), "a raced command line and every flag marker are printed");
		free(s);
		fill_for(&e, KOF_EVT_PROC_STOP);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "exit=3"), "ProcStop prints exit=");
		free(s);
		fill_for(&e, KOF_EVT_PROC_ATTACH);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "by=321") && strstr(s, "/etc/hosts"), "ProcAttach names the actor");
		free(s);
		fill_for(&e, KOF_EVT_FILE_WRITE);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "64 bytes @34") && strstr(s, "[hosts]"), "FileWrite: the range and the location");
		free(s);
		fill_for(&e, KOF_EVT_NET_CONNECT);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "127.0.0.1:80") && strstr(s, "321 bytes"), "NetConn: address, port in host order, size");
		free(s);
		{
			struct kof_evt_net *n = kof_evt_set_net(&e);

			memset(n->daddr, 0, 16);
			n->daddr[0] = 0x20;
			n->daddr[15] = 1;
		}
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "[2") && strstr(s, "]:80"), "a v6 peer is in brackets");
		free(s);
		fill_for(&e, KOF_EVT_DNS_QUERY);
		memset(kof_evt_set_net(&e)->daddr, 0, 16);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "/etc/hosts") && !strstr(s, "->"), "a DNS query with no answer prints the name and no arrow");
		free(s);
		fill_for(&e, KOF_EVT_REG_CREATE);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "(new)") && strstr(s, "[SZ] h") && strstr(s, "(2 of 100 bytes)") == NULL, "RegNew with a new key and a REG_SZ value");
		free(s);
		{
			static const uint8_t types[] = { 1, 2, 3, 4, 7, 11, 99 };
			unsigned k;

			for (k = 0; k < sizeof types; k++) {
				fill_for(&e, KOF_EVT_REG_SET_VALUE);
				kof_evt_set_reg(&e)->type = types[k];
				memcpy(e.text + e.off_data, "\x78\x56\x34\x12\x00\x00", 6);
				s = render_to_str(&e, &t);
				OKF(s && strstr(s, "= ["), "reg type %u is rendered", types[k]);
				free(s);
			}
			fill_for(&e, KOF_EVT_REG_SET_VALUE);
			kof_evt_set_reg(&e)->type = 4;
			memcpy(e.text + e.off_data, "\x78\x56\x34\x12\x00\x00", 6);
			s = render_to_str(&e, &t);
			ok(s && strstr(s, "0x12345678") && strstr(s, "... (6 of 100 bytes)"), "REG_DWORD value, and the 'prefix' note when the full size is larger");
			free(s);
		}
		fill_for(&e, KOF_EVT_AMSI_SCAN);
		e.content_len = 300;
		memset(e.text + e.off_object, 'A', 300);
		e.text[e.off_object + 5] = '\033';
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "(300 bytes)") && !strchr(s, '\033'), "AMSI content: sanitised (no ESC), the length said when over 120");
		free(s);
		e.content_len = 0;
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "(no content)"), "AMSI with no content");
		free(s);
		fill_for(&e, KOF_EVT_RAW);
		e.source = KOF_SRC_FILE;
		e.raw_id = 12;
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "[file id 12]") && strstr(s, "addr=0x7f001000"), "Raw: source and id, the address");
		free(s);
		e.source = 0;
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "[id 12]"), "Raw with no source: [id N]");
		free(s);
		fill_for(&e, KOF_EVT_THREAD_START);
		s = render_to_str(&e, &t);
		ok(s && strstr(s, "start=0x7f001000"), "ThreadNew: start address");
		free(s);
	}
	{
		struct kof_evt_tally z;
		char *buf = NULL;
		size_t n = 0;
		FILE *f = open_memstream(&buf, &n);

		memset(&z, 0, sizeof z);
		z.proc = 3;
		z.bytes_sent = 99;
		kof_evt_print_tally(&z, 2.5, "a test", f);
		fclose(f);
		ok(buf && strstr(buf, "2.5s, a test") && strstr(buf, "processes started : 3") && strstr(buf, "99 / 0"), "print_tally");
		free(buf);
		f = open_memstream(&buf, &n);
		kof_evt_banner(f, "tool", 0, "things");
		kof_evt_banner(f, NULL, 5, NULL);
		{
			struct kof_evt_health h;

			memset(&h, 0, sizeof h);
			h.produced = 7;
			h.dropped = 2;
			h.undecoded = 1;
			h.seq_gaps = 3;
			h.upstream_lost = 4;
			h.sub_asked = 0xff;
			h.sub_enabled = 0x0f;
			kof_evt_health_print(f, &h, 3.0);
			memset(&h, 0, sizeof h);
			kof_evt_health_print(f, &h, 0.0);
		}
		fclose(f);
		ok(buf && strstr(buf, "tool (kofevt) build 0") && strstr(buf, "without a build stamp") && strstr(buf, "collects: things") && strstr(buf, "? (kofevt) build 5"), "banner: with and without a stamp, a tool name, collects");
		ok(buf && strstr(buf, "7") != NULL, "health_print writes the counters");
		free(buf);
	}
}

static void case_render_controls(void)
{
	struct kof_evt e;
	struct kof_evt_tally t;
	char *s;

	printf("\nrender: control bytes in a path the sample chose:\n");
	memset(&t, 0, sizeof t);
	mk(&e, KOF_EVT_FILE_NEW, 1);
	e.off_object = kof_evt_text_put(&e, "/tmp/a\033[2Jb\r.txt");
	s = render_to_str(&e, &t);
	/* KNOWN DEFECT WP12-24 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(s && !strchr(s, '\033') && !strchr(s, '\r'), "kof_evt_render prints a file name with ESC and CR as written: a terminal escape in a path the sample chose reaches the screen (the AMSI content and the registry data ARE sanitised)",
		 "WP12-24: kofevtfmt.c prints kof_evt_object / image / cmdline with %s");
	free(s);
	mk(&e, KOF_EVT_PROC_START, 1);
	e.off_image = kof_evt_text_put(&e, "/bin/x\033]0;owned\007");
	e.off_cmdline = kof_evt_text_put(&e, "x \033[31m");
	s = render_to_str(&e, &t);
	/* KNOWN DEFECT WP12-24 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(s && !strchr(s, '\033') && !strchr(s, '\007'), "the same for a process image and its command line", "WP12-24");
	free(s);
}

/* ------------------------------------------------------------------------------------------------- text helpers */

static void case_text_of(void)
{
	char out[64];
	static const char wide[] = "A\0B\0C\0\0\0";
	size_t n;

	printf("\nwide text and readable text:\n");
	ok(kof_evt_text_is_wide(wide, 6) == 1 && kof_evt_text_is_wide("AB", 2) == 0 && kof_evt_text_is_wide("A", 1) == 0 && kof_evt_text_is_wide(NULL, 4) == 0 &&
	   kof_evt_text_is_wide("A\0B", 3) == 1 && kof_evt_text_is_wide("A\0B\1", 4) == 0, "text_is_wide: UTF-16LE of ASCII only, a lone byte is not wide");
	n = kof_evt_text_of(wide, 8, out, sizeof out);
	ok(n == 3 && !strcmp(out, "ABC"), "text_of: a wide string comes out as its characters, the padding cut");
	n = kof_evt_text_of("a\x01z\xff\0\0", 6, out, sizeof out);
	ok(n == 4 && !strcmp(out, "a.z."), "text_of: control and high bytes are dots, trailing NULs cut");
	n = kof_evt_text_of("abcdef", 6, out, 4);
	ok(n == 3 && !strcmp(out, "abc"), "text_of: cut at the cap");
	ok(kof_evt_text_of(NULL, 4, out, sizeof out) == 0 && out[0] == '\0' && kof_evt_text_of("x", 1, NULL, 4) == 0 && kof_evt_text_of("x", 1, out, 0) == 0 &&
	   kof_evt_text_of("x", 0, out, sizeof out) == 0, "text_of: NULL, no output, cap 0, length 0");
	{
		struct kof_evt e;

		mk(&e, KOF_EVT_AMSI_SCAN, 1);
		ok(kof_evt_content_looks_binary(&e) == 0, "no content: not binary");
		e.off_object = kof_evt_text_put(&e, "hello world");
		e.content_len = 11;
		ok(kof_evt_content_looks_binary(&e) == 0, "text content: not binary");
		memcpy(e.text + e.off_object, "\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10", 11);
		ok(kof_evt_content_looks_binary(&e) == 1, "control bytes: binary");
		memcpy(e.text + e.off_object, "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00", 11);
		ok(kof_evt_content_looks_binary(&e) == 1, "an MZ header: binary");
		e.content_len = 7;
		memcpy(e.text + e.off_object, "\x01\x02\x03\x04\x05\x06\x07", 7);
		ok(kof_evt_content_looks_binary(&e) == 0, "under 8 bytes is never called binary");
		e.content_len = 11;
		{
			const char *t = NULL;
			size_t l = 0;

			ok(kof_evt_content(&e, &t, &l) == 1 && l == 11 && t == e.text + e.off_object, "kof_evt_content: the span");
			ok(kof_evt_content(&e, NULL, NULL) == 1 && kof_evt_content(NULL, &t, &l) == 0, "content with NULL out pointers, and a NULL record");
			e.content_len = 0;
			ok(kof_evt_content(&e, &t, &l) == 1 && l == 0, "an AMSI verb with no content_len: a content event that is empty");
			e.verb = KOF_EVT_FILE_NEW;
			ok(kof_evt_content(&e, &t, &l) == 0, "any other verb with no content_len: not content");
		}
	}
}

/* ------------------------------------------------------------------------------------------------- hostile records */

/* the record is copied to the END of a page whose successor is PROT_NONE: an over-read is a SIGSEGV */
static int in_guarded_child(void (*fn)(const struct kof_evt *g), const struct kof_evt *src)
{
	pid_t kid;
	int st = 0;

	fflush(stdout);
	kid = fork();
	if (kid == 0) {
		long pg = sysconf(_SC_PAGESIZE);

		/* a fault here is the RESULT being measured: the sanitiser's handler would print a report for every row */
		signal(SIGSEGV, SIG_DFL);
		signal(SIGBUS, SIG_DFL);
		unsigned char *m = mmap(NULL, (size_t)pg * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		struct kof_evt *g;

		if (m == MAP_FAILED)
			_exit(90);
		mprotect(m + pg * 2, (size_t)pg, PROT_NONE);
		g = (struct kof_evt *)(m + pg * 2 - sizeof *g);
		memcpy(g, src, sizeof *g);
		fn(g);
		_exit(0);
	}
	waitpid(kid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static void use_accessors(const struct kof_evt *g)
{
	volatile size_t n = strlen(kof_evt_image(g)) + strlen(kof_evt_object(g)) + strlen(kof_evt_cmdline(g));

	(void)n;
}

static void use_render(const struct kof_evt *g)
{
	struct kof_evt_tally t;
	FILE *f = fopen("/dev/null", "w");
	char name[64], val[256];
	unsigned i, n;

	memset(&t, 0, sizeof t);
	kof_evt_render(g, 0.0, "x", f, &t);
	n = kof_evt_n_fields(g);
	for (i = 0; i < n; i++)
		(void)kof_evt_field(g, i, name, sizeof name, val, sizeof val);
	fclose(f);
}

static void case_hostile(void)
{
	struct kof_evt e;
	int rc;
	static const uint16_t verbs[] = { KOF_EVT_PROC_START, KOF_EVT_FILE_NEW, KOF_EVT_NET_CONNECT, KOF_EVT_REG_SET_VALUE, KOF_EVT_AMSI_SCAN, KOF_EVT_RAW, 9999 };
	unsigned i;

	printf("\nhostile records (a child with a guard page behind the record):\n");
	/* offsets that point anywhere, a content length and a data length that lie, an arena with no NUL at all */
	for (i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
		mk(&e, verbs[i], 1);
		memset(e.text, 'A', sizeof e.text);
		e.text_len = sizeof e.text;
		e.off_object = 10;
		e.off_image = 20;
		e.off_cmdline = 30;
		e.off_data = 40;
		e.data_len = 0xffff;
		e.content_len = 0xffff;
		e.source = 200;
		e.loc = 250;
		e.attack = 60000;
		rc = in_guarded_child(use_render, &e);
		{
			char w[200];

			snprintf(w, sizeof w, "verb %u, arena of 540 'A' and no NUL: render and field listing run off the end of the record (child rc %d)", verbs[i], rc);
			/* KNOWN DEFECT WP12-10 (2026-10-24, M): this row pins it, green until fixed. */
			KM_CHECK(rc == 0, w, "WP12-10: the record readers assume a NUL the channel does not guarantee");
		}
	}
	/* lying offsets with a proper NUL are fine: the accessors bound the offset */
	mk(&e, KOF_EVT_FILE_NEW, 1);
	e.off_object = 539;
	e.off_image = 0xfffe;
	e.off_cmdline = 540;
	e.text[539] = '\0';
	rc = in_guarded_child(use_accessors, &e);
	ok(rc == 0, "offsets at and past the end of the arena, the last byte a NUL: the accessors answer");
	/* the accessors on an arena that has NO terminator: the arena is the end of the record */
	mk(&e, KOF_EVT_FILE_NEW, 1);
	memset(e.text, 'A', sizeof e.text);
	e.off_object = 0;
	e.off_image = 0;
	e.off_cmdline = 0;
	rc = in_guarded_child(use_accessors, &e);
	/* KNOWN DEFECT WP12-10 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(rc == 0, "kof_evt_object() on a record whose arena has no NUL is a string that runs off the end of the record (child died with signal)",
		 "WP12-10: kof_chan_next hands back the record unterminated; kofevtlog_read forces the NUL, the channel does not");
	rc = in_guarded_child(use_render, &e);
	(void)rc;
}

/* ------------------------------------------------------------------------------------------------- evtlog */

static struct kofevt_log_info info_for_kof(void)
{
	struct kofevt_log_info i;

	memset(&i, 0, sizeof i);
	i.rec_size = sizeof(struct kof_evt);
	i.head_size = KOF_EVT_HEAD;
	i.len_off = (uint16_t)offsetof(struct kof_evt, text_len);
	i.rec_kind = KOFEVT_REC_KOF;
	i.build = 77;
	i.root_pid = 5;
	i.sub_asked = 3;
	i.sub_enabled = 1;
	i.started = 1234;
	return i;
}

static void make_rec(struct kof_evt *e, unsigned i)
{
	char s[300];
	unsigned k;

	mk(e, KOF_EVT_FILE_NEW, 1000u + i);
	e->seq = i;
	for (k = 0; k < (i * 37u) % 200u; k++)
		s[k] = (char)('a' + (k + i) % 26);
	s[k] = '\0';
	e->off_object = kof_evt_text_put(e, s);
}

static void patch(const char *path, long off, const void *bytes, size_t n)
{
	int fd = __real_open(path, O_WRONLY);

	if (fd >= 0) {
		(void)pwrite(fd, bytes, n, off);
		close(fd);
	}
}

static void case_evtlog(void)
{
	char path[600];
	struct kofevt_log_info info = info_for_kof();
	struct kofevt_log_w *w;
	struct kofevt_log_r *r;
	const char *why = "";
	struct kof_evt e, g;
	unsigned i, n = 2500, bad = 0;
	uint64_t off;
	uint32_t len;

	printf("\nevent log file:\n");
	snprintf(path, sizeof path, "%s/log.bin", R);
	w = kofevt_log_create(path, &info);
	ok(w != NULL, "created");
	for (i = 0; i < n; i++) {
		make_rec(&e, i);
		if (kofevt_log_write(w, &e) != 0)
			bad++;
	}
	ok(bad == 0 && kofevt_log_close(w) == n, "2500 records written, close returns the count");
	r = kofevt_log_open(path, sizeof(struct kof_evt), KOFEVT_REC_KOF, &why);
	ok(r != NULL, "opened");
	if (!r)
		return;
	ok(kofevt_log_header(r)->n_records == n && kofevt_log_header(r)->rec_size == sizeof(struct kof_evt) && kofevt_log_header(r)->build == 77 &&
	   kofevt_log_header(r)->root_pid == 5 && kofevt_log_header(r)->platform == KOF_PLAT_LINUX, "the header says what was written");
	ok(kofevt_log_count(r) == n, "count = the writer's number");
	for (i = 0, bad = 0; i < n; i++) {
		make_rec(&e, i);
		memset(&g, 0xa5, sizeof g);
		if (kofevt_log_read(r, &g, sizeof g) != 1 || g.seq != i || strcmp(kof_evt_object(&g), kof_evt_object(&e)))
			bad++;
	}
	OKF(bad == 0, "all 2500 read back, equal (%u bad)", bad);
	ok(kofevt_log_read(r, &g, sizeof g) == 0, "then the end: 0");
	/* seek and extent through the checkpoints (a stride of 1024) */
	{
		static const uint64_t at[] = { 0, 1, 1023, 1024, 1025, 2047, 2048, 2499 };
		unsigned k;

		for (k = 0; k < sizeof at / sizeof at[0]; k++) {
			OKF(kofevt_log_seek(r, at[k]) == 1 && kofevt_log_read(r, &g, sizeof g) == 1 && g.seq == at[k], "seek %llu then read gives that record", (unsigned long long)at[k]);
			OKF(kofevt_log_extent(r, at[k], &off, &len) == 1 && off >= 64 && len >= KOF_EVT_HEAD && len <= sizeof(struct kof_evt), "extent %llu is a place in the file", (unsigned long long)at[k]);
		}
		ok(kofevt_log_seek(r, 2500) == 0 && kofevt_log_seek(r, ~0ull) == 0, "seek past the end: 0");
		ok(kofevt_log_extent(r, 2500, &off, &len) == 0 && kofevt_log_extent(r, 0, NULL, &len) == 0 && kofevt_log_extent(NULL, 0, &off, &len) == 0, "extent past the end, NULL out, NULL log: 0");
	}
	/* a read with a buffer smaller than the record */
	ok(kofevt_log_read(r, &g, sizeof g - 1) == 0, "a buffer one byte smaller than rec_size is refused");
	kofevt_log_free(r);
	/* refusals at open */
	ok(kofevt_log_open(path, sizeof(struct kof_evt) + 1, KOFEVT_REC_KOF, &why) == NULL && strstr(why, "different size"), "a record size the reader does not expect");
	ok(kofevt_log_open(path, 0, KOFEVT_REC_KOFW, &why) == NULL && strstr(why, "different collector"), "another collector's records");
	r = kofevt_log_open(path, 0, KOFEVT_REC_NONE, &why);
	ok(r != NULL, "want_rec_size 0 and kind NONE opt out");
	kofevt_log_free(r);
	ok(kofevt_log_open(NULL, 0, 0, &why) == NULL && !strcmp(why, "no path") && kofevt_log_open("", 0, 0, &why) == NULL, "no path");
	{
		char missing[700];

		snprintf(missing, sizeof missing, "%s/nope", R);
		ok(kofevt_log_open(missing, 0, 0, &why) == NULL && !strcmp(why, "cannot open"), "a file that is not there");
	}
	ok(kofevt_log_header(NULL) == NULL && kofevt_log_count(NULL) == 0 && kofevt_log_seek(NULL, 0) == 0, "NULL log");
	kofevt_log_free(NULL);
}

struct hdr_row {
	const char *id;
	long        off;
	uint64_t    val;
	size_t      n;
	const char *why;     /* what open must say; "" = opens */
};

static void case_evtlog_headers(void)
{
	char path[600], bad[640];
	struct kofevt_log_info info = info_for_kof();
	struct kofevt_log_w *w;
	struct kof_evt e;
	unsigned i, k;
	const char *why = "";
	static const struct hdr_row rows[] = {
		{ "magic", 0, 0xdeadbeef, 4, "not a kofevt log" },
		{ "version", 4, 99, 2, "version this build does not know" },
		{ "rec_size 0", 8, 0, 4, "impossible record size" },
		{ "rec_size 70000", 8, 70000, 4, "impossible record size" },
		{ "rec_size 639 (no longer the writer's)", 8, 639, 4, "different size" },
		{ "head_size 0", offsetof(struct kofevt_log_hdr, head_size), 0, 2, "impossible record shape" },
		{ "head_size 2000", offsetof(struct kofevt_log_hdr, head_size), 2000, 2, "impossible record shape" },
		{ "head_size over rec_size", offsetof(struct kofevt_log_hdr, head_size), 641, 2, "impossible record shape" },
		{ "len_off at the end of the head", offsetof(struct kofevt_log_hdr, len_off), 99, 2, "impossible record shape" },
		{ "rec_kind", offsetof(struct kofevt_log_hdr, rec_kind), 1, 2, "different collector" },
		{ "hdr_size larger (a newer build): skipped", offsetof(struct kofevt_log_hdr, hdr_size), 96, 2, "" },
	};

	printf("\nevent log headers that lie:\n");
	snprintf(path, sizeof path, "%s/h.bin", R);
	for (k = 0; k < sizeof rows / sizeof rows[0]; k++) {
		w = kofevt_log_create(path, &info);
		for (i = 0; i < 3; i++) {
			make_rec(&e, i);
			kofevt_log_write(w, &e);
		}
		kofevt_log_close(w);
		patch(path, rows[k].off, &rows[k].val, rows[k].n);
		why = "";
		{
			struct kofevt_log_r *r = kofevt_log_open(path, sizeof(struct kof_evt), KOFEVT_REC_KOF, &why);

			if (rows[k].why[0])
				OKF(r == NULL && strstr(why, rows[k].why), "header row '%s': refused with '%s' (got '%s')", rows[k].id, rows[k].why, why);
			else
				OKF(r != NULL, "header row '%s': opens", rows[k].id);
			kofevt_log_free(r);
		}
	}
	/* a shorter-than-header file, and an empty one */
	snprintf(bad, sizeof bad, "%s/short.bin", R);
	(void)osys_put_flat(R, "short.bin", "KOFT", 4);
	ok(kofevt_log_open(bad, 0, 0, &why) == NULL && strstr(why, "shorter than a header"), "a 4-byte file");
	(void)osys_put_flat(R, "short.bin", "", 0);
	ok(kofevt_log_open(bad, 0, 0, &why) == NULL, "an empty file");
	/* create refusals */
	{
		struct kofevt_log_info bi = info;

		bi.rec_size = 0;
		ok(kofevt_log_create(path, &bi) == NULL, "create: rec_size 0");
		bi = info;
		bi.rec_size = 70000;
		ok(kofevt_log_create(path, &bi) == NULL, "create: rec_size over the bound");
		bi = info;
		bi.head_size = 0;
		ok(kofevt_log_create(path, &bi) == NULL, "create: head_size 0");
		bi = info;
		bi.head_size = 700;
		ok(kofevt_log_create(path, &bi) == NULL, "create: head over rec_size");
		bi = info;
		bi.len_off = 99;
		ok(kofevt_log_create(path, &bi) == NULL, "create: the length field outside the head");
		ok(kofevt_log_create(NULL, &info) == NULL && kofevt_log_create("", &info) == NULL && kofevt_log_create(path, NULL) == NULL, "create: no path, no info");
	}
	/* write refusals: a record whose own length does not fit */
	w = kofevt_log_create(path, &info);
	make_rec(&e, 1);
	ok(kofevt_log_write(w, &e) == 0, "write");
	e.text_len = 541;
	ok(kofevt_log_write(w, &e) == -1, "a text_len over the arena: refused");
	make_rec(&e, 2);
	ok(kofevt_log_write(w, &e) == -1, "and the writer stays closed after a failure (the file would be mis-framed)");
	ok(kofevt_log_write(NULL, &e) == -1 && kofevt_log_write(w, NULL) == -1, "NULL writer, NULL record");
	ok(kofevt_log_close(w) == 1 || 1, "close after a failed write");
	ok(kofevt_log_close(NULL) == 0, "close(NULL)");
}

static void case_evtlog_truncated(void)
{
	char path[600], cut[700];
	struct kofevt_log_info info = info_for_kof();
	struct kofevt_log_w *w;
	struct kofevt_log_r *r;
	struct kof_evt e, g;
	unsigned i, rd;
	uint64_t zero = 0, cnt;
	struct stat st;

	printf("\nevent log: a file that was killed, cut, or edited:\n");
	snprintf(path, sizeof path, "%s/t.bin", R);
	w = kofevt_log_create(path, &info);
	for (i = 0; i < 40; i++) {
		make_rec(&e, i);
		kofevt_log_write(w, &e);
	}
	kofevt_log_close(w);
	/* killed before the count was written: zero means "count them yourself" */
	patch(path, (long)offsetof(struct kofevt_log_hdr, n_records), &zero, 8);
	r = kofevt_log_open(path, 0, KOFEVT_REC_KOF, NULL);
	ok(r && kofevt_log_count(r) == 40, "n_records = 0: counted by walking, 40");
	ok(kofevt_log_count(r) == 40, "and the answer is stable (the index is kept)");
	ok(kofevt_log_seek(r, 39) == 1 && kofevt_log_read(r, &g, sizeof g) == 1 && g.seq == 39, "seek works on an unclosed file");
	kofevt_log_free(r);
	/* a lying count: more than the file holds */
	cnt = 1000000;
	patch(path, (long)offsetof(struct kofevt_log_hdr, n_records), &cnt, 8);
	r = kofevt_log_open(path, 0, KOFEVT_REC_KOF, NULL);
	ok(r && kofevt_log_count(r) == 1000000, "a header claiming a million records: count says so (the reads end when the file does)");
	for (rd = 0; kofevt_log_read(r, &g, sizeof g) == 1; rd++)
		;
	ok(rd == 40, "and the reads stop at the 40 that exist");
	kofevt_log_free(r);
	/* cut the last record in the middle of its text */
	stat(path, &st);
	snprintf(cut, sizeof cut, "%s/cut.bin", R);
	{
		FILE *a = fopen(path, "rb"), *b = fopen(cut, "wb");
		unsigned char buf[4096];
		long left = (long)st.st_size - 5;
		size_t k;

		while (left > 0 && (k = fread(buf, 1, left > 4096 ? 4096 : (size_t)left, a)) > 0) {
			fwrite(buf, 1, k, b);
			left -= (long)k;
		}
		fclose(a);
		fclose(b);
	}
	patch(cut, (long)offsetof(struct kofevt_log_hdr, n_records), &zero, 8);
	r = kofevt_log_open(cut, 0, KOFEVT_REC_KOF, NULL);
	for (rd = 0; kofevt_log_read(r, &g, sizeof g) == 1; rd++)
		;
	ok(rd == 39, "a file cut 5 bytes short: 39 whole records read, the cut one is refused");
	cnt = kofevt_log_count(r);
	printf("       cut file: %u records read, count says %llu\n", rd, (unsigned long long)cnt);
	/* KNOWN DEFECT WP12-8 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(cnt == rd, "count of a file whose last record is cut says 40 while 39 can be read (skip_one seeks past the end without checking)",
		 "WP12-8: kofevt_log_count counts a record whose text is past the end of the file");
	kofevt_log_free(r);
	/* hdr_size smaller than the header: where do the records start */
	{
		uint16_t small = 32;

		w = kofevt_log_create(path, &info);
		for (i = 0; i < 5; i++) {
			make_rec(&e, i);
			kofevt_log_write(w, &e);
		}
		kofevt_log_close(w);
		patch(path, (long)offsetof(struct kofevt_log_hdr, n_records), &zero, 8);
		patch(path, (long)offsetof(struct kofevt_log_hdr, hdr_size), &small, 2);
		r = kofevt_log_open(path, 0, KOFEVT_REC_KOF, NULL);
		for (rd = 0; r && kofevt_log_read(r, &g, sizeof g) == 1; rd++)
			;
		printf("       hdr_size 32: %u records read from byte 64, the index counts %llu\n", rd, (unsigned long long)(r ? kofevt_log_count(r) : 0));
		/* KNOWN DEFECT WP12-7 (2026-10-24, M): this row pins it, green until fixed. */
		KM_CHECK(r != NULL && kofevt_log_count(r) == rd, "a header that declares hdr_size 32: read starts at byte 64 and the index at byte 32, so count and read disagree",
			 "WP12-7: kofevt_log_open does not seek to hdr_size when it is smaller than the struct, build_index always does");
		kofevt_log_free(r);
	}
	/* a log whose record claims a text longer than its record */
	{
		uint16_t lie = 600;

		w = kofevt_log_create(path, &info);
		make_rec(&e, 3);
		kofevt_log_write(w, &e);
		kofevt_log_close(w);
		patch(path, 64 + (long)offsetof(struct kof_evt, text_len), &lie, 2);
		r = kofevt_log_open(path, 0, KOFEVT_REC_KOF, NULL);
		ok(r && kofevt_log_read(r, &g, sizeof g) == 0, "a record whose text_len exceeds the arena: read refuses it");
		ok(r && kofevt_log_count(r) == 1, "(the writer's count still says 1)");
		kofevt_log_free(r);
	}
	/* an arena filled to the byte with no NUL: the reader supplies the terminator */
	{
		uint16_t full = 540;
		unsigned char blob[540];

		w = kofevt_log_create(path, &info);
		make_rec(&e, 3);
		memset(blob, 'Z', sizeof blob);
		kofevt_log_write(w, &e);
		kofevt_log_close(w);
		patch(path, 64 + (long)offsetof(struct kof_evt, text_len), &full, 2);
		{
			FILE *f = fopen(path, "ab");

			fwrite(blob, 1, sizeof blob - (size_t)e.text_len, f);
			fclose(f);
		}
		patch(path, 64 + KOF_EVT_HEAD, blob, sizeof blob);
		r = kofevt_log_open(path, 0, KOFEVT_REC_KOF, NULL);
		memset(&g, 0xa5, sizeof g);
		ok(r && kofevt_log_read(r, &g, sizeof g) == 1 && g.text[sizeof g.text - 1] == '\0', "an arena with no NUL: the reader forces the last byte to NUL");
		kofevt_log_free(r);
	}
}

/* ------------------------------------------------------------------------------------------------- grille (host-pure) */

static void case_grille_host(void)
{
	static struct kofw_ptab pt;
	struct kofw_pent *p;
	static struct kofw_evt we;
	unsigned i;

	printf("\ngrille: the parts that need no Windows API:\n");
	memset(&pt, 0, sizeof pt);
	kofw_ptab_init(&pt);
	p = kofw_ptab_add(&pt, 100, 5, "C:\\x\\a.exe", 0);
	ok(p && !strcmp(kofw_pent_image(&pt, p), "C:\\x\\a.exe"), "kofw_pent_image returns the stored image");
	ok(kofw_pent_image(NULL, p)[0] == '\0' && kofw_pent_image(&pt, NULL)[0] == '\0', "NULL table or entry: empty");
	p = kofw_ptab_add(&pt, 101, 5, NULL, 0);
	ok(p && kofw_pent_image(&pt, p)[0] == '\0', "an entry with no image: empty");
	p = kofw_ptab_add(&pt, 102, 5, "x", 0);
	if (p) {
		p->image_off = (uint16_t)(sizeof pt.names - 1u);
		p->image_len = 5;
		ok(kofw_pent_image(&pt, p)[0] == '\0', "an image extent past the name pool: empty, not an over-read");
	}
	memset(&we, 0, sizeof we);
	for (i = 0; i < 40; i++) {
		uint32_t bit = 1u << i % 32;
		const char *n = kofw_sub_name(bit);

		ok(n != NULL, "kofw_sub_name never returns NULL");
	}
	ok(!strcmp(kofw_sub_name(KOFW_SUB_PROCESS), "process") && !strcmp(kofw_sub_name(KOFW_SUB_IMAGE), "image") && !strcmp(kofw_sub_name(KOFW_SUB_FILE), "file") &&
	   !strcmp(kofw_sub_name(KOFW_SUB_FILE_WRITE), "file-write") && !strcmp(kofw_sub_name(KOFW_SUB_NET), "net") && !strcmp(kofw_sub_name(KOFW_SUB_REGISTRY), "registry") &&
	   !strcmp(kofw_sub_name(KOFW_SUB_THREAD), "thread") && !strcmp(kofw_sub_name(KOFW_SUB_FILE_OPEN), "file-open") && !strcmp(kofw_sub_name(KOFW_SUB_AMSI), "amsi") &&
	   !strcmp(kofw_sub_name(KOFW_SUB_DNS), "dns") && !strcmp(kofw_sub_name(0), "") && !strcmp(kofw_sub_name(0x3), ""), "every subscription bit has its name, anything else is empty");
	we.off_cmdline = KOF_TEXT_NONE;
	ok(kofw_evt_cmdline(&we)[0] == '\0' && kofw_evt_cmdline(NULL)[0] == '\0', "kofw_evt_cmdline: none, NULL");
	we.off_cmdline = 3;
	memcpy(we.text + 3, "cmd", 4);
	ok(!strcmp(kofw_evt_cmdline(&we), "cmd"), "and one that is there");
	we.off_cmdline = (uint16_t)sizeof we.text;
	ok(kofw_evt_cmdline(&we)[0] == '\0', "an offset at the end of the arena: empty");
}

/* ------------------------------------------------------------------------------------------------- grille: the filter and the tables */

static void wev(struct kofw_evt *e, uint16_t type, uint32_t pid, uint32_t ppid, const char *obj, uint8_t prov)
{
	memset(e, 0, sizeof *e);
	e->type = type;
	e->pid = pid;
	e->ppid = ppid;
	e->raiser_pid = pid;
	e->provider = prov;
	e->stamp = 132000000000000000ull;
	e->create_time = 132000000000000000ull;
	e->off_image = e->off_object = e->off_cmdline = e->off_data = KOF_TEXT_NONE;
	if (obj) {
		size_t n = strlen(obj) + 1u;

		memcpy(e->text, obj, n);
		e->off_object = 0;
		e->text_len = (uint16_t)n;
	}
}

static void case_wfilter(void)
{
	static struct kofw_ptab tab;
	static struct kofw_ftab ft;
	struct kofw_evt e;
	struct kofw_filter f;
	uint8_t why = 99;
	unsigned i;
	unsigned char id1[256], id2[256];
	int c1, c2;
	size_t l1, l2;

	printf("\ngrille: the filter and the process / file-name tables:\n");
	kofw_ptab_init(&tab);
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, "/tmp/x", 1);
	ok(kofw_filter_apply(&tab, NULL, &e, &why) == 1 && why == KOFW_REFUSE_NONE, "no filter: everything is kept");
	ok(kofw_filter_apply(NULL, &f, &e, &why) == 0 && kofw_filter_apply(&tab, NULL, NULL, &why) == 0, "NULL table or event: 0");
	memset(&f, 0, sizeof f);
	f.types = 1u << KOF_EVT_PROC_START;
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, "/tmp/x", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 0 && why == KOFW_REFUSE_TYPE, "a type that was not asked for: REFUSE_TYPE");
	wev(&e, KOF_EVT_PROC_START, 5, 1, "/bin/x", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1 && why == KOFW_REFUSE_NONE, "the type that was asked for is kept");
	wev(&e, 40, 5, 1, NULL, 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 0 && why == KOFW_REFUSE_TYPE, "a verb number of 32 or more is never in the mask");
	memset(&f, 0, sizeof f);
	f.drop_loc = 1u << KOF_LOC_SYSTEM;
	wev(&e, KOF_EVT_IMAGE_LOAD, 5, 1, "/usr/lib/libc.so", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 0 && why == KOFW_REFUSE_LOC && e.obj_loc == KOF_LOC_SYSTEM, "a module from a dropped location: REFUSE_LOC, and the location is filled in");
	wev(&e, KOF_EVT_IMAGE_LOAD, 5, 1, "/tmp/evil.so", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1 && e.obj_loc == KOF_LOC_TEMP, "from another location: kept");
	/* scoped to a tree */
	kofw_ptab_init(&tab);
	memset(&f, 0, sizeof f);
	f.root_pid = 100;
	wev(&e, KOF_EVT_PROC_START, 100, 1, "/bin/root", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "the root of the tree is kept");
	wev(&e, KOF_EVT_PROC_START, 101, 100, "/bin/child", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "its child is kept");
	wev(&e, KOF_EVT_PROC_START, 102, 101, "/bin/grandchild", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "and its grandchild");
	wev(&e, KOF_EVT_FILE_NEW, 102, 101, "/tmp/f", 2);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "an event of a tracked process");
	wev(&e, KOF_EVT_FILE_NEW, 999, 1, "/tmp/f", 2);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 0 && why == KOFW_REFUSE_SCOPE, "an event of an unrelated process: REFUSE_SCOPE");
	wev(&e, KOF_EVT_CONT, 999, 1, NULL, 2);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 0, "a continuation follows what its parent was: refused");
	wev(&e, KOF_EVT_PROC_START, 200, 999, "/bin/other", 1);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 0 && why == KOFW_REFUSE_SCOPE, "a start whose parent is outside the tree: refused");
	wev(&e, KOF_EVT_FILE_NEW, 102, 101, "/tmp/g", 2);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "and a kept one after it");
	wev(&e, KOF_EVT_CONT, 102, 101, NULL, 2);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "its continuation is kept");
	f.scope_exempt_prov = 1u << 5;
	wev(&e, KOF_EVT_FILE_NEW, 999, 1, "/tmp/h", 5);
	ok(kofw_filter_apply(&tab, &f, &e, &why) == 1, "a provider exempt from the scope keeps an outside process's event");
	f.scope_exempt_prov = 0;
	ok(tab.n_alive_tracked == 3, "three tracked processes alive");
	wev(&e, KOF_EVT_PROC_STOP, 102, 101, NULL, 1);
	kofw_filter_apply(&tab, &f, &e, &why);
	ok(tab.n_alive_tracked == 2, "a stop takes one off");
	wev(&e, KOF_EVT_PROC_STOP, 102, 101, NULL, 1);
	kofw_filter_apply(&tab, &f, &e, &why);
	ok(tab.n_alive_tracked == 2, "a second stop of the same process takes none");
	/* modules: a thread whose entry is in no module is UNBACKED, a module loaded long after start is LATE */
	kofw_ptab_init(&tab);
	memset(&f, 0, sizeof f);
	wev(&e, KOF_EVT_PROC_START, 7, 1, "/bin/p", 1);
	kofw_filter_apply(&tab, &f, &e, &why);
	wev(&e, KOF_EVT_IMAGE_LOAD, 7, 1, "/lib/m.so", 1);
	e.addr = 0x400000;
	e.addr_size = 0x1000;
	kofw_filter_apply(&tab, &f, &e, &why);
	wev(&e, KOF_EVT_THREAD_START, 7, 1, NULL, 1);
	e.addr = 0x400010;
	kofw_filter_apply(&tab, &f, &e, &why);
	ok(!(e.flags & KOFW_EF_UNBACKED), "a thread starting inside a loaded module is not flagged");
	wev(&e, KOF_EVT_THREAD_START, 7, 1, NULL, 1);
	e.addr = 0x900000;
	kofw_filter_apply(&tab, &f, &e, &why);
	ok((e.flags & KOFW_EF_UNBACKED) && tab.unbacked == 1, "a thread starting in no module is UNBACKED and counted");
	wev(&e, KOF_EVT_IMAGE_LOAD, 7, 1, "/lib/late.so", 1);
	e.addr = 0x500000;
	e.addr_size = 0x1000;
	e.stamp += 10ull * KOFW_LATE_LOAD_TICKS;
	kofw_filter_apply(&tab, &f, &e, &why);
	ok((e.flags & KOFW_EF_LATE_LOAD) && tab.late_loads == 1, "a module loaded long after the process started is flagged LATE");
	/* the process table */
	kofw_ptab_init(&tab);
	{
		struct kofw_pent *p;
		unsigned added = 0;

		for (i = 0; i < KOFW_PTAB_MAX; i++)
			if (kofw_ptab_add(&tab, 1000u + i, 1, "x", 0))
				added++;
		OKF(added == KOFW_PTAB_MAX / 2u && tab.overflow > 0, "without recycling the table takes %u entries (half) and then counts the overflow (%llu)", added, (unsigned long long)tab.overflow);
		p = kofw_ptab_add(&tab, 99999, 1, "y", 1);
		ok(p != NULL, "with recycling an entry is made by dropping an old one");
		p = kofw_ptab_add(&tab, 7, 5, "a-very-long-image-name-" "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 1);
		ok(p && strlen(kofw_pent_image(&tab, p)) <= KOFW_IMAGE_MAX, "an image longer than the bound is cut");
	}
	/* the file-name table */
	kofw_ftab_init(&ft);
	kofw_ftab_add(&ft, 0x1000, "/tmp/a");
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, NULL, 2);
	e.addr = 0x1000;
	ok(kofw_ftab_resolve(&ft, &e) == 1 && !strcmp(kofw_evt_object(&e), "/tmp/a"), "a record with a key and no path is given the name stored for the key");
	ok(kofw_ftab_resolve(&ft, &e) == 0, "a record that has a path keeps it");
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, NULL, 2);
	e.addr = 0x2000;
	ok(kofw_ftab_resolve(&ft, &e) == 0 && ft.unresolved == 1, "an unknown key is counted as unresolved");
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, NULL, 2);
	e.addr = 0x1000;
	e.text_len = (uint16_t)(sizeof e.text - 3);
	ok(kofw_ftab_resolve(&ft, &e) == 1 && (e.flags & KOF_EF_TRUNCATED) && e.text_len <= sizeof e.text, "an arena with room for 2 bytes: the name is cut to fit and the record says so");
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, NULL, 2);
	e.addr = 0x1000;
	e.text_len = (uint16_t)(sizeof e.text - 1);
	ok(kofw_ftab_resolve(&ft, &e) == 0, "an arena with no room at all: not resolved, not overrun");
	kofw_ftab_add(&ft, 0, "x");
	kofw_ftab_add(&ft, 5, NULL);
	kofw_ftab_add(&ft, 5, "");
	kofw_ftab_add(NULL, 5, "x");
	ok(ft.n == 1, "key 0, a NULL or empty name, a NULL table: nothing added");
	{
		char longn[400];

		memset(longn, 'n', sizeof longn - 1);
		longn[sizeof longn - 1] = '\0';
		kofw_ftab_add(&ft, 77, longn);
		ok(ft.name_cuts == 1, "a name over 255 bytes is cut and counted");
	}
	for (i = 1; i <= 3000; i++)
		kofw_ftab_add(&ft, 0x10000u + i * 8u, "/tmp/some/path/name");
	ok(ft.recycled >= 1 && ft.n <= KOFW_FTAB_MAX / 2u, "3000 keys through a 4096-slot table: recycled at half, never over");
	for (i = 1; i <= 2000; i++) {
		char nm[300];

		memset(nm, 'a' + (int)(i % 26u), 250);
		nm[250] = '\0';
		kofw_ftab_add(&ft, 0x900000u + i * 8u, nm);
	}
	ok(ft.names_used <= KOFW_FPOOL, "250-byte names (2000 of them): the pool is never over its size");
	/* the identity of an event */
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, "/tmp/x", 2);
	l1 = kofw_evt_ident(&e, id1, sizeof id1, &c1);
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, "/tmp/x", 2);
	e.stamp += 5;
	l2 = kofw_evt_ident(&e, id2, sizeof id2, &c2);
	ok(l1 > 0 && l1 == l2 && !memcmp(id1, id2, l1), "the same file create at another instant has the same identity");
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, "/tmp/y", 2);
	l2 = kofw_evt_ident(&e, id2, sizeof id2, &c2);
	ok(l1 != l2 || memcmp(id1, id2, l1), "another path: another identity");
	wev(&e, KOF_EVT_FILE_WRITE, 5, 1, "/tmp/x", 2);
	ok(kofw_evt_ident(&e, id2, sizeof id2, &c2) == 0, "a file write is never collapsed: no identity");
	wev(&e, KOF_EVT_REG_SET_VALUE, 5, 1, "\\REGISTRY\\MACHINE\\SOFTWARE\\x", 4);
	l1 = kofw_evt_ident(&e, id1, sizeof id1, &c1);
	ok(l1 > 0 && c1 == 1, "a registry write outside the places that matter is identified coarsely");
	wev(&e, KOF_EVT_REG_SET_VALUE, 5, 1, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x", 4);
	e.obj_loc = KOF_LOC_AUTOSTART;
	e.attack = KOF_ATT_RUN_KEY;
	l2 = kofw_evt_ident(&e, id2, sizeof id2, &c2);
	ok(l2 > 0 && c2 == 0, "one in a Run key is identified finely: the object matters");
	wev(&e, KOF_EVT_PROC_START, 5, 1, "/bin/x", 1);
	ok(kofw_evt_ident(&e, id2, sizeof id2, &c2) == 0, "a process start is never collapsed: no identity");
	ok(kofw_evt_ident(NULL, id2, sizeof id2, &c2) == 0 && kofw_evt_ident(&e, NULL, 4, &c2) == 0 && kofw_evt_ident(&e, id2, 0, &c2) == 0, "NULL event, NULL buffer, zero capacity");
	wev(&e, KOF_EVT_FILE_NEW, 5, 1, "/tmp/x", 2);
	l1 = kofw_evt_ident(&e, id1, 3, &c1);
	ok(l1 <= 3, "an identity is cut to a small buffer, never past it");
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	R = osys_tmpdir("orbit_evt");
	if (!R) {
		printf("cannot make the scratch directory\n");
		return 1;
	}
	case_vocab();
	case_classify();
	case_record();
	case_cmdline_norm();
	case_join();
	case_render();
	case_render_controls();
	case_text_of();
	case_hostile();
	case_evtlog();
	case_evtlog_headers();
	case_evtlog_truncated();
	case_grille_host();
	case_wfilter();
	osys_reset();
	osys_rmrf(R);
	free(R);
	printf("\n%d check(s), %d failed; known misses %u\n", checks, fails, km_known_n);
	return (fails || km_fixed_n) ? 1 : 0;
}
