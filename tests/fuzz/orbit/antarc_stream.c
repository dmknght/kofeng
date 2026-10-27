/*
 * orbit/antarc_stream - the Linux event collectors fed by a fake kernel (tests/lib/orbit_sys.c): bytes become datagrams
 * on a fake process connector, or records on a fake fanotify descriptor, and every record the collector makes of them is read
 * back and held to what a record is.
 *
 *   pev_stream   the connector: random bytes as one to three datagrams after the open's probe; the /proc the exec handler
 *                reads is a fixture of four processes (pids 4242..4245: exe, cmdline, stat)
 *   fan_stream   fanotify, in degraded mode over a watched directory and in full mode with the handle-to-path cache (the
 *                privileged open_by_handle_at answered by the fake)
 *   mon_stream   both at once through the merged monitor: the input is cut in two, one half to each
 * Seeds are well-formed datagrams and records built the way the kernel builds them, with the length fields mapped so the
 * mutators lie about exactly those. Held: every record satisfies ofx_evt_ok (verb, offsets, arena inside the record), its
 * strings are strings, the stream ends (a step bound), health counts what was produced, and nothing leaks.
 */
#include "orbit_fx.h"

#include <sys/fanotify.h>
#include <sys/socket.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include "afan.h"
#include "amon.h"
#include "apev.h"

static char *root;

static const char *rootdir(void)
{
	if (!root) {
		unsigned p;

		root = ofx_dir();
		for (p = 4242; p < 4246; p++) {
			char st[200];

			snprintf(st, sizeof st, "%u (fix) S 7 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55 1 1\n", p);
			osys_put(root, p, "stat", st, strlen(st));
			osys_link(root, p, "exe", "/usr/bin/true");
			osys_put(root, p, "cmdline", "true\0--flag\0", 12);
		}
	}
	return root;
}

/* ---- the check every record gets ---- */

static void check_evt(struct fz_ctx *c, const struct kof_evt *e, uint8_t want_source)
{
	FZ_CHECK(c, ofx_evt_ok(e), "a record with a verb or an offset outside its enum or arena");
	FZ_CHECK(c, strlen(kof_evt_image(e)) < sizeof e->text && strlen(kof_evt_object(e)) < sizeof e->text && strlen(kof_evt_cmdline(e)) < sizeof e->text,
		 "a string of the record is not terminated inside its arena");
	FZ_CHECK(c, e->text_len <= sizeof e->text, "text_len past the arena");
	if (want_source)
		FZ_CHECK(c, e->source == want_source, "a record of the wrong source");
	FZ_CHECK(c, e->os == KOF_OS_LINUX, "a record that does not say it is Linux");
	fz_digest(c, e->verb ^ ((uint64_t)e->pid << 16) ^ ((uint64_t)e->ppid << 40) ^ ((uint64_t)e->miss << 8));
	{
		const char *o = kof_evt_object(e);
		size_t k;

		for (k = 0; o[k]; k++)
			fz_digest(c, (unsigned char)o[k]);
	}
}

static void drain(struct fz_ctx *c, const struct kof_mon_api *a, uint8_t want_source, unsigned *n_out)
{
	struct kof_evt e;
	unsigned n = 0;

	while (n < 600 && kof_mon_next(a, &e, 0) == 1) {
		check_evt(c, &e, want_source);
		n++;
		if (!fz_step(&c->steps, 1))
			break;
	}
	*n_out = n;
}

static char *capture(const struct kof_mon_api *a, size_t *len)
{
	char *buf = NULL;
	FILE *f = open_memstream(&buf, len);

	if (f) {
		a->print_extra(a->self, f);
		fclose(f);
	}
	return buf;
}

/* ---- pev ---- */

struct nlb {
	struct nlmsghdr nl;
	struct cn_msg   cn;
	struct proc_event ev;
} __attribute__((packed));

static void nlb_make(struct nlb *b, uint32_t what, uint64_t ts)
{
	memset(b, 0, sizeof *b);
	b->nl.nlmsg_len = sizeof *b;
	b->nl.nlmsg_type = NLMSG_DONE;
	b->cn.id.idx = CN_IDX_PROC;
	b->cn.id.val = CN_VAL_PROC;
	b->cn.len = sizeof b->ev;
	b->ev.what = what;
	b->ev.timestamp_ns = ts;
}

static struct fz_field pf[16];
static struct fz_map pmap;

static void pfield(uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &pf[pmap.n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seeds_pev(struct fz_corpus *c)
{
	struct nlb b;
	static struct { struct nlb a, b; } two;
	static const uint32_t whats[] = { PROC_EVENT_EXEC, PROC_EVENT_EXIT, PROC_EVENT_FORK, PROC_EVENT_PTRACE, PROC_EVENT_UID, PROC_EVENT_GID, PROC_EVENT_COMM,
					  PROC_EVENT_SID, PROC_EVENT_COREDUMP };
	unsigned i;

	pmap.f = pf;
	pmap.n = 0;
	pfield(0, 4, FZ_LEN);                                      /* nlmsg_len */
	pfield(4, 2, FZ_COUNT);                                    /* nlmsg_type */
	pfield(16, 4, FZ_COUNT);                                   /* cn id idx */
	pfield(32, 2, FZ_LEN);                                     /* cn len */
	pfield(36, 4, FZ_COUNT);                                   /* proc_event.what */
	pfield(44, 8, FZ_LEN);                                     /* timestamp */
	pfield(52, 4, FZ_RVA);                                     /* pid */
	pfield(56, 4, FZ_RVA);                                     /* tgid */
	pfield(60, 4, FZ_COUNT);
	pfield(64, 4, FZ_COUNT);
	for (i = 0; i < sizeof whats / sizeof whats[0]; i++) {
		nlb_make(&b, whats[i], 1000u + i);
		b.ev.event_data.exec.process_pid = 4242;
		b.ev.event_data.exec.process_tgid = 4242;
		if (whats[i] == PROC_EVENT_EXIT)
			b.ev.event_data.exit.exit_code = 0x0100;
		fz_corpus_add_map(c, "nl", &b, sizeof b, &pmap);
	}
	{
		static struct { struct nlb a, b; } dup;

		nlb_make(&dup.a, PROC_EVENT_EXEC, 77);
		dup.a.ev.event_data.exec.process_tgid = 4244;
		dup.b = dup.a;                                           /* the same exec delivered twice, same timestamp */
		fz_corpus_add_map(c, "dup", &dup, sizeof dup, &pmap);
	}
	nlb_make(&two.a, PROC_EVENT_EXEC, 5);
	two.a.ev.event_data.exec.process_tgid = 4243;
	nlb_make(&two.b, PROC_EVENT_EXIT, 6);
	two.b.ev.event_data.exit.process_tgid = 4243;
	fz_corpus_add_map(c, "two", &two, sizeof two, &pmap);
}

static int pev_send_parts(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	int peer = osys_nl_peer();
	size_t cut1, cut2;

	if (peer < 0)
		return 0;
	if (n > 60000)
		n = 60000;
	cut1 = n ? (size_t)fz_below(c->rng, n + 1u) : 0u;
	cut2 = cut1 < n ? cut1 + (size_t)fz_below(c->rng, n - cut1 + 1u) : n;
	if (cut1)
		(void)write(peer, in, cut1);
	if (cut2 > cut1)
		(void)write(peer, in + cut1, cut2 - cut1);
	if (n > cut2)
		(void)write(peer, in + cut2, n - cut2);
	return 1;
}

static int run_pev(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kofa_pev_option o;
	struct kofa_pev *p;
	const struct kof_mon_api *a;
	struct nlb fork;
	unsigned got = 0;
	struct kof_evt_health h;
	size_t len = 0;
	char *txt;

	osys_reset();
	osys_proc_root(rootdir());
	osys_fork(1);
	osys_nl(1);
	nlb_make(&fork, PROC_EVENT_FORK, 1);
	osys_nl_preload(&fork, sizeof fork);
	memset(&o, 0, sizeof o);
	o.trace_self = (int)fz_below(c->rng, 2);
	o.probe_ms = 20;
	p = kofa_pev_open(&o, NULL);
	if (!p) {
		FZ_CHECK(c, c->failk, "the open failed with no allocation failing");
		osys_reset();
		return 0;
	}
	a = kofa_pev_api(p);
	{
		struct kof_evt e;

		while (kof_mon_next(a, &e, 0) == 1)               /* the probe's FORK is not an event, anything else would be */
			check_evt(c, &e, KOF_SRC_PROCESS);
	}
	pev_send_parts(c, in, n);
	drain(c, a, KOF_SRC_PROCESS, &got);
	if (n >= 8) {
		uint32_t pid = 4242u + (uint32_t)fz_below(c->rng, 6);

		kofa_pev_hint_image(p, pid, "/hinted/image");
		(void)kofa_pev_is_own_image(p, pid, "/hinted/image", 0);
		(void)a->name_of(a->self, pid, 0);
	}
	memset(&h, 0, sizeof h);
	a->health(a->self, &h);
	FZ_CHECK(c, h.produced >= got, "health counts fewer records than were produced");
	txt = capture(a, &len);
	FZ_CHECK(c, txt && strlen(txt) < 4096u, "print_extra is unbounded");
	free(txt);
	fz_digest(c, got);
	if (fz_below(c->rng, 2))
		kofa_pev_close(p);
	else
		kof_mon_close(a);
	osys_reset();
	return (int)got;
}

FZ_ADAPTER(pev_stream, .name = "orbit/pev_stream",
	   .covers = "kofa_pev_open kofa_pev_api kofa_pev_close kofa_pev_hint_image kofa_pev_is_own_image kof_mon_next kof_mon_close",
	   .shape = FZ_REQ, .backstop_s = 1800, .seeds = seeds_pev, .run = run_pev);

/* ---- fan ---- */

#define FANBUF 16384

static size_t fan_rec(unsigned char *out, uint64_t mask, int pid, int info_type, const unsigned char *fh, uint32_t fh_bytes, int fh_type, const char *name)
{
	struct fanotify_event_metadata md;
	size_t at = sizeof md, info_at;
	struct fanotify_event_info_header ih;
	uint32_t hb = fh_bytes;

	memset(&md, 0, sizeof md);
	md.vers = FANOTIFY_METADATA_VERSION;
	md.metadata_len = sizeof md;
	md.mask = mask;
	md.fd = FAN_NOFD;
	md.pid = pid;
	if (info_type) {
		size_t nm = name ? strlen(name) + 1u : 0u;

		info_at = at;
		memset(&ih, 0, sizeof ih);
		ih.info_type = (uint8_t)info_type;
		at += sizeof ih;
		memset(out + at, 0, 8);
		at += 8;
		memcpy(out + at, &hb, 4);
		memcpy(out + at + 4, &fh_type, 4);
		at += 8;
		if (fh_bytes && fh)
			memcpy(out + at, fh, fh_bytes);
		at += fh_bytes;
		if (nm) {
			memcpy(out + at, name, nm);
			at += nm;
		}
		while (at & 3u)
			out[at++] = 0;
		ih.len = (uint16_t)(at - info_at);
		memcpy(out + info_at, &ih, sizeof ih);
	}
	md.event_len = (uint32_t)at;
	memcpy(out, &md, sizeof md);
	return at;
}

static unsigned char fan_fh[MAX_HANDLE_SZ];
static uint32_t fan_fhb;
static int fan_fht;
static char fan_watch[600], fan_resolved[600];
static struct fz_field ff[16];
static struct fz_map fmap;

static void ffield(uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &ff[fmap.n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static int fan_fixture(void)
{
	struct { struct file_handle h; unsigned char sp[MAX_HANDLE_SZ]; } fh;
	int mnt = 0;

	if (fan_watch[0])
		return fan_fhb != 0;
	snprintf(fan_watch, sizeof fan_watch, "%s/watch", ofx_dir());
	snprintf(fan_resolved, sizeof fan_resolved, "%s/resolved", ofx_dir());
	mkdir(fan_watch, 0755);
	mkdir(fan_resolved, 0755);
	fh.h.handle_bytes = MAX_HANDLE_SZ;
	if (name_to_handle_at(AT_FDCWD, fan_watch, &fh.h, &mnt, 0) != 0)
		return 0;
	fan_fhb = fh.h.handle_bytes;
	fan_fht = fh.h.handle_type;
	memcpy(fan_fh, fh.h.f_handle, fan_fhb);
	return 1;
}

static void seeds_fan(struct fz_corpus *c)
{
	static unsigned char buf[FANBUF];
	static const uint64_t masks[] = { FAN_CREATE, FAN_OPEN_EXEC, FAN_MODIFY | FAN_CLOSE_WRITE, FAN_MOVED_FROM | FAN_MOVED_TO, FAN_DELETE, FAN_ATTRIB,
					  FAN_CREATE | FAN_ATTRIB | FAN_DELETE, FAN_Q_OVERFLOW };
	unsigned i;
	size_t n;

	if (!fan_fixture())
		return;
	fmap.f = ff;
	fmap.n = 0;
	ffield(0, 4, FZ_LEN);                                       /* event_len */
	ffield(6, 2, FZ_LEN);                                       /* metadata_len */
	ffield(8, 8, FZ_COUNT);                                     /* mask */
	ffield(20, 4, FZ_RVA);                                      /* pid */
	ffield(24, 1, FZ_COUNT);                                    /* info_type */
	ffield(26, 2, FZ_LEN);                                      /* info len */
	ffield(36, 4, FZ_LEN);                                      /* handle_bytes */
	for (i = 0; i < sizeof masks / sizeof masks[0]; i++) {
		n = fan_rec(buf, masks[i], 4321, FAN_EVENT_INFO_TYPE_DFID_NAME, fan_fh, fan_fhb, fan_fht, "file.txt");
		fz_corpus_add_map(c, "fan", buf, n, &fmap);
	}
	n = fan_rec(buf, FAN_CREATE, 4321, FAN_EVENT_INFO_TYPE_DFID, fan_fh, fan_fhb, fan_fht, NULL);
	fz_corpus_add_map(c, "fan-dfid", buf, n, &fmap);
	n = fan_rec(buf, FAN_CREATE, 0, 0, NULL, 0, 0, NULL);
	fz_corpus_add_map(c, "fan-bare", buf, n, &fmap);
	{
		unsigned char two[256];
		size_t a = fan_rec(two, FAN_CREATE, 1, FAN_EVENT_INFO_TYPE_DFID_NAME, fan_fh, fan_fhb, fan_fht, "a");

		a += fan_rec(two + a, FAN_DELETE, 2, FAN_EVENT_INFO_TYPE_DFID_NAME, fan_fh, fan_fhb, fan_fht, "b");
		fz_corpus_add_map(c, "fan-two", two, a, &fmap);
	}
}

static struct kofa_fan *fan_open_for(struct fz_ctx *c, int *full)
{
	static const char *dirs[2];
	struct kofa_fan_option o;

	osys_reset();
	osys_proc_root(NULL);
	osys_fan(1);
	*full = (int)fz_below(c->rng, 2);
	memset(&o, 0, sizeof o);
	o.trace_self = (int)fz_below(c->rng, 2);
	if (*full) {
		osys_obh_dir(fan_resolved);
	} else {
		dirs[0] = fan_watch;
		dirs[1] = NULL;
		o.dirs = dirs;
	}
	return kofa_fan_open(&o, NULL);
}

static int run_fan(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kofa_fan *f;
	const struct kof_mon_api *a;
	int full, peer;
	unsigned got = 0;
	struct kof_evt_health h;
	size_t len = 0;
	char *txt;

	if (!fan_fixture())
		return 0;
	f = fan_open_for(c, &full);
	if (!f) {
		FZ_CHECK(c, c->failk, "the open failed with no allocation failing");
		osys_reset();
		return 0;
	}
	FZ_CHECK(c, kofa_fan_mode(f) == (full ? KOFA_FAN_FULL : KOFA_FAN_DEGRADED) && kofa_fan_watch_count(f) == 1, "the mode or the watch count is not what the open asked for");
	FZ_CHECK(c, kofa_fan_mode_name(kofa_fan_mode(f))[0] != '?', "the mode has no name");
	a = kofa_fan_api(f);
	peer = osys_fan_peer();
	if (peer >= 0 && n <= 100000) {
		size_t cut = n ? (size_t)fz_below(c->rng, n + 1u) : 0u;

		if (cut)
			(void)write(peer, in, cut);
		if (n > cut)
			(void)write(peer, in + cut, n - cut);
	}
	drain(c, a, KOF_SRC_FILE, &got);
	memset(&h, 0, sizeof h);
	a->health(a->self, &h);
	FZ_CHECK(c, h.produced >= got, "health counts fewer records than were produced");
	txt = capture(a, &len);
	FZ_CHECK(c, txt && strlen(txt) < 4096u, "print_extra is unbounded");
	free(txt);
	fz_digest(c, got);
	if (fz_below(c->rng, 2))
		kofa_fan_close(f);
	else
		kof_mon_close(a);
	osys_reset();
	return (int)got;
}

FZ_ADAPTER(fan_stream, .name = "orbit/fan_stream",
	   .covers = "kofa_fan_open kofa_fan_api kofa_fan_close kofa_fan_mode kofa_fan_mode_name kofa_fan_watch_count",
	   .shape = FZ_REQ, .backstop_s = 1800, .seeds = seeds_fan, .run = run_fan);

/* ---- mon ---- */

static int run_mon(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const char *dirs[2];
	struct kofa_mon_option o;
	struct kofa_mon *m;
	const struct kof_mon_api *a;
	struct nlb fork;
	struct kof_evt e;
	unsigned got = 0;
	size_t half = n / 2u;
	int pf_peer, ff_peer;

	if (!fan_fixture())
		return 0;
	osys_reset();
	osys_proc_root(rootdir());
	osys_fork(1);
	osys_nl(1);
	nlb_make(&fork, PROC_EVENT_FORK, 1);
	osys_nl_preload(&fork, sizeof fork);
	osys_fan(1);
	osys_obh_dir(fan_resolved);
	dirs[0] = fan_watch;
	dirs[1] = NULL;
	memset(&o, 0, sizeof o);
	o.fan.dirs = fz_below(c->rng, 2) ? dirs : NULL;
	o.fan.trace_self = (int)fz_below(c->rng, 2);
	m = kofa_mon_open(&o, NULL);
	if (!m) {
		FZ_CHECK(c, c->failk, "the monitor did not open with no allocation failing");
		osys_reset();
		return 0;
	}
	a = kofa_mon_api(m);
	FZ_CHECK(c, c->failk || (kofa_mon_fan(m) != NULL && kofa_mon_pev(m) != NULL && kofa_mon_pev_err(m) == KOFA_OK), "one of the two streams is missing");
	pf_peer = osys_nl_peer();
	ff_peer = osys_fan_peer();
	if (n <= 100000) {
		if (half && pf_peer >= 0)
			(void)write(pf_peer, in, half);
		if (n > half && ff_peer >= 0)
			(void)write(ff_peer, in + half, n - half);
	}
	while (got < 800 && kof_mon_next(a, &e, 0) == 1) {
		check_evt(c, &e, 0);
		got++;
		if (!fz_step(&c->steps, 1))
			break;
	}
	{
		struct kof_evt_health h;

		memset(&h, 0, sizeof h);
		a->health(a->self, &h);
		(void)a->name_of(a->self, 4242, 0);
	}
	fz_digest(c, got);
	kofa_mon_free(m);
	osys_reset();
	return (int)got;
}

FZ_ADAPTER(mon_stream, .name = "orbit/mon_stream", .covers = "kofa_mon_open kofa_mon_api kofa_mon_free kofa_mon_fan kofa_mon_pev kofa_mon_pev_err",
	   .shape = FZ_REQ, .backstop_s = 1800, .seeds = seeds_pev, .run = run_mon);
