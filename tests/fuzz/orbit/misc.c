/*
 * orbit/misc - the rest of the surface: the verdict cache as a script, the record helpers and the names, the channel with a real
 * publisher, the file identity, the report directory, and the Windows collector's own record (the part that builds here).
 *
 *   fridge_ops   put / get / skip / clear / default path against a model (a table of what was put): a get returns what the
 *                last put stored while nothing was evicted, skip says "present and clean", clear forgets all
 *   evt_misc     the names over their domain, the record builders (text_put to the byte, the payload setters), the tally,
 *                the clock, the address setter
 *   chan_ring    one publisher and one subscriber on a real channel as a script: order, the refusal and the count of a full
 *                ring, the cursor
 *   fid          kof_fid_key (a hash of an identity: never 0, stable, field-sensitive) and kof_fid_of on files, links and
 *                directories made from the input
 *   mkpath       kof_report_mkpath on a path made from the input, below a scratch root
 *   wevt         a kofw_evt of anything: converted to the neutral record, its identity, and the filter against a process
 *                table, with the arena sealed as the log reader seals it
 */
#include "orbit_fx.h"

#include <dirent.h>
#include <ftw.h>
#include <sys/stat.h>

#include "fidset.h"
#include "kofchan.h"
#include "kofgrille.h"
#include "koffridge.h"
#include "kofeng.h"
#include "kofreport.h"
#include "kofevtfmt.h"
#include "wfilter.h"
#include "wtext.h"
#include "aproc.h"

/* ------------------------------------------------------------------------------------------------- fridge_ops */

static void seeds_ops(struct fz_corpus *c)
{
	uint8_t b[10 * 60];
	unsigned i;

	for (i = 0; i < 60; i++) {
		memset(b + 10 * i, 0, 10);
		b[10 * i] = (uint8_t)(i % 5u);
		b[10 * i + 1] = (uint8_t)(i * 5u);
		b[10 * i + 5] = (uint8_t)(i % 3u);
	}
	fz_corpus_add(c, "ops", b, sizeof b);
}

struct frs {
	struct koffridge *f;
	uint8_t           have[64], bad[64];     /* id k was put; it was put as an infected verdict */
	char              name[64][16];
};

static void *fr_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct frs *s = (struct frs *)calloc(1, sizeof *s);

	(void)c;
	(void)in;
	(void)n;
	if (!s)
		return NULL;
	s->f = koffridge_open(1024, 0x55);
	if (!s->f) {
		free(s);
		return NULL;
	}
	return s;
}

static int fr_op(struct fz_ctx *c, void *h, unsigned op, uint64_t a, uint64_t b)
{
	struct frs *s = (struct frs *)h;
	unsigned k = (unsigned)(a % 64u);
	char id[16];
	int l = snprintf(id, sizeof id, "id-%u", k);
	struct koffridge_verdict v;
	struct koffridge_stat st;

	koffridge_stats(s->f, &st);
	switch (op) {
	case 0: {
		struct kof_result res;

		memset(&res, 0, sizeof res);
		if (b & 1u) {
			res.has_verdict = 1;
			snprintf(res.verdict.name, sizeof res.verdict.name, "Infected#%u", k);
		}
		if (koffridge_put(s->f, id, (uint32_t)l, &res)) {
			s->have[k] = 1;
			s->bad[k] = (uint8_t)(b & 1u);
		}
		break;
	}
	case 1: {
		int got = koffridge_get(s->f, id, (uint32_t)l, &v);

		if (got) {
			FZ_CHECK(c, s->have[k], "a get found an id that was never put");
			FZ_CHECK(c, (v.findings != 0) == (s->bad[k] != 0), "the verdict that came back is not the one that went in");
			FZ_CHECK(c, strlen(v.name) < sizeof v.name, "a verdict name that is not terminated");
		} else if (s->have[k]) {
			FZ_CHECK(c, st.evictions > 0 || st.refused > 0, "an id that was put is gone with nothing evicted");
		}
		break;
	}
	case 2: {
		int sk = koffridge_skip(s->f, id, (uint32_t)l);

		FZ_CHECK(c, !sk || (s->have[k] && !s->bad[k]), "skip answered yes for an id that is absent or infected");
		break;
	}
	case 3:
		koffridge_clear(s->f);
		memset(s->have, 0, sizeof s->have);
		break;
	default: {
		char buf[1200];
		char home[700];

		FZ_CHECK(c, koffridge_db_stamp(s->f) == 0x55, "the database stamp changed");
		snprintf(home, sizeof home, "%s/home", ofx_dir());
		mkdir(home, 0755);
		snprintf(buf, sizeof buf, "%s/.cache", home);
		mkdir(buf, 0755);
		osys_home(home);
		{
			int ok = koffridge_default_path(buf, sizeof buf);

			FZ_CHECK(c, ok == (buf[0] != '\0'), "default_path says yes with no path, or no with one");
			FZ_CHECK(c, !ok || strstr(buf, "kofscan.fridge") != NULL, "a default path that is not the cache file");
		}
		osys_home(NULL);
		(void)koffridge_describe(s->f, buf, 64);
		break;
	}
	}
	fz_digest(c, op ^ ((uint64_t)k << 8));
	return 0;
}

static void fr_close(void *h)
{
	struct frs *s = (struct frs *)h;

	koffridge_close(s->f);
	free(s);
}

FZ_ADAPTER(fridge_ops, .name = "orbit/fridge_ops", .covers = "koffridge_skip koffridge_clear koffridge_db_stamp koffridge_default_path", .shape = FZ_SEQ, .n_kinds = 5,
	   .seeds = seeds_ops, .open = fr_open, .op = fr_op, .close = fr_close);

/* ------------------------------------------------------------------------------------------------- evt_misc */

static void seeds_u64(struct fz_corpus *c)
{
	static const uint64_t v[8] = { 0, 1, 10000000ull, 132000000000000000ull, ~0ull, 0x7fff, 5, 9 };

	fz_corpus_add(c, "u64", v, sizeof v);
	fz_corpus_add(c, "text", "/etc/passwd\0C:\\Windows\\x\0cmd /c ls\0", 34);
}

static int run_evt_misc(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kof_evt e;
	struct kof_evt_tally t;
	size_t at = 0, i;
	unsigned puts = 0;
	uint64_t t0 = 0, t1 = 0, a, b;
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;

	/* the names, over the values the input gives */
	for (i = 0; i < n && i < 64; i++) {
		FZ_CHECK(c, kof_evt_arch_name(in[i]) && kof_evt_platform_name(in[i]) && kofa_err_name((int)in[i] - 10) && kof_fp_kind_name(in[i]) &&
			 kof_fp_seen_name(in[i]) && kof_fp_why_not(in[i]) && kof_rep_group_name(in[i]), "a name function answered NULL");
		FZ_CHECK(c, strlen(kof_fp_kind_name(in[i])) < 32 && strlen(kof_rep_group_name(in[i])) < 32 && strlen(kofa_err_name((int)in[i])) < 16, "a name is unbounded");
	}
	FZ_CHECK(c, kof_evt_platform_self() == KOF_PLAT_LINUX && kof_evt_arch_self() != KOF_EARCH_UNKNOWN, "this host is not Linux, or has no arch");
	/* the record: strings from the input, one by one, until the arena says no */
	memset(&e, 0, sizeof e);
	e.off_image = e.off_object = e.off_cmdline = e.off_data = KOF_TEXT_NONE;
	while (at < n && puts < 400) {
		const char *s = (const char *)in + at;
		size_t l = strnlen(s, n - at), room = sizeof e.text - e.text_len;
		uint16_t off, before = e.text_len;
		char tmp[700];

		if (l >= sizeof tmp)
			l = sizeof tmp - 1;
		memcpy(tmp, s, l);
		tmp[l] = '\0';
		off = kof_evt_text_put(&e, tmp);
		if (!l)
			FZ_CHECK(c, off == KOF_TEXT_NONE && e.text_len == before, "an empty string was stored");
		else if (l + 1u <= room) {
			FZ_CHECK(c, off == before && e.text_len == before + l + 1u && !memcmp(e.text + off, tmp, l + 1u), "a string that fits was not stored where it said");
		} else {
			FZ_CHECK(c, off == KOF_TEXT_NONE && e.text_len == before && (e.flags & KOF_EF_TRUNCATED), "a string that does not fit changed the record or did not say so");
		}
		at += strnlen(s, n - at) + 1u;
		puts++;
		if (!fz_step(&c->steps, 1))
			break;
	}
	FZ_CHECK(c, e.text_len <= sizeof e.text, "text_len over the arena");
	/* the payload setters, for every verb */
	for (i = 0; i < KOF_EVT_TYPE_COUNT + 2; i++) {
		struct kof_evt k;
		enum kof_evt_kind kind = kof_evt_kind_of((uint16_t)i);

		memset(&k, 0, sizeof k);
		k.verb = (uint16_t)i;
		FZ_CHECK(c, (kof_evt_set_proc(&k) != NULL) == (kind == KOF_EK_PROC) && (kof_evt_set_mem(&k) != NULL) == (kind == KOF_EK_MEM) &&
			 (kof_evt_set_net(&k) != NULL) == (kind == KOF_EK_NET) && (kof_evt_set_file(&k) != NULL) == (kind == KOF_EK_FILE) &&
			 (kof_evt_set_reg(&k) != NULL) == (kind == KOF_EK_REG), "a payload setter does not match the verb's kind");
		memset(&t, 0, sizeof t);
		kof_evt_count(&k, &t);
		FZ_CHECK(c, t.proc + t.image + t.thread + t.file_new + t.file_del + t.file_ren + t.file_wr + t.reg + t.amsi + t.dns + t.conn + t.raw <= 1u,
			 "one record counted twice");
	}
	{
		uint8_t ip[16];
		uint32_t v4 = n >= 4 ? (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24) : 0u;
		char s[KOF_IP_STR_MAX];

		kof_evt_ip_set_v4(ip, v4);
		FZ_CHECK(c, !kof_evt_ip_is_v6(ip) && kof_evt_ip_str(ip, s, sizeof s) == s, "a v4 address was stored as v6 or did not print");
	}
	/* the clock and the interval */
	if (n >= 16) {
		memcpy(&t0, in, 8);
		memcpy(&t1, in + 8, 8);
	}
	a = kof_evt_now();
	b = kof_evt_now();
	FZ_CHECK(c, b >= a, "the clock went back");
	FZ_CHECK(c, kof_evt_secs_since(t0, t1) >= 0.0, "a negative interval");
	FZ_CHECK(c, t1 < t0 || t1 - t0 > (1ull << 62) || kof_evt_secs_since(t0, t1) * (double)KOF_TICKS_PER_SEC <= (double)(t1 - t0) * 1.0000001 + 1.0, "an interval longer than its ticks");
	f = open_memstream(&buf, &blen);
	if (f) {
		struct kof_evt_health h;

		memset(&h, 0, sizeof h);
		if (n >= 48)
			memcpy(&h, in + 16, 32);
		kof_evt_banner(f, n && in[0] ? "tool" : NULL, (uint32_t)(n >= 4 ? in[0] : 0), n > 1 && in[1] ? "things" : NULL);
		kof_evt_health_print(f, &h, 2.0);
		fclose(f);
		FZ_CHECK(c, blen < 4096u, "banner and health text unbounded");
		free(buf);
	}
	fz_digest(c, e.text_len ^ ((uint64_t)puts << 16));
	return 0;
}

FZ_ADAPTER(evt_misc, .name = "orbit/evt_misc",
	   .covers = "kof_evt_arch_name kof_evt_arch_self kof_evt_banner kof_evt_count kof_evt_health_print kof_evt_ip_set_v4 kof_evt_kind_of kof_evt_now kof_evt_platform_name "
		     "kof_evt_platform_self kof_evt_secs_since kof_evt_set_file kof_evt_set_mem kof_evt_set_net kof_evt_set_proc kof_evt_set_reg kof_evt_text_put kof_fp_kind_name "
		     "kof_fp_seen_name kof_fp_why_not kof_rep_group_name kofa_err_name",
	   .shape = FZ_REQ, .seeds = seeds_u64, .run = run_evt_misc);

/* ------------------------------------------------------------------------------------------------- chan_ring */

struct chs {
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	char                 name[64];
	uint64_t             next, expect, held, refused;
	uint32_t             cap;
};

static void *ch_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct chs *h = (struct chs *)calloc(1, sizeof *h);
	const char *why;
	int reason;

	(void)in;
	(void)n;
	if (!h)
		return NULL;
	snprintf(h->name, sizeof h->name, "kfr%u-%u", (unsigned)getpid(), c->iter % 10000u);
	h->p = kof_chan_publish_open(h->name, 8);
	h->s = h->p ? kof_chan_sub_open(h->name, &why, &reason) : NULL;
	if (!h->p || !h->s) {
		if (h->s)
			kof_chan_sub_close(h->s);
		if (h->p)
			kof_chan_publish_close(h->p);
		free(h);
		return NULL;
	}
	h->cap = kof_chan_sub_header(h->s)->capacity;
	return h;
}

static int ch_op(struct fz_ctx *c, void *hh, unsigned op, uint64_t a, uint64_t b)
{
	struct chs *h = (struct chs *)hh;
	unsigned k, times = 1u + (unsigned)(a % 20u);

	(void)b;
	if (op == 0) {
		for (k = 0; k < times; k++) {
			struct kof_evt e;
			int rc;

			memset(&e, 0, sizeof e);
			e.verb = KOF_EVT_FILE_NEW;
			e.seq = h->next;
			e.pid = (uint32_t)h->next;
			rc = kof_chan_publish(h->p, &e);
			if (rc == 0) {
				FZ_CHECK(c, h->held < h->cap, "a publish succeeded on a full ring");
				h->next++;
				h->held++;
			} else {
				FZ_CHECK(c, rc == 1 && h->held == h->cap, "a publish was refused with room left");
				h->refused++;
			}
		}
	} else if (op == 1) {
		for (k = 0; k < times; k++) {
			struct kof_evt e;
			int got = kof_chan_next(h->s, &e, 0);

			FZ_CHECK(c, got == (h->held > 0), "the subscriber disagrees with the model about whether the ring is empty");
			if (!got)
				break;
			FZ_CHECK(c, e.seq == h->expect && e.pid == (uint32_t)h->expect, "a record out of order or torn");
			h->expect++;
			h->held--;
		}
	} else {
		const struct kof_chan_hdr *hd = kof_chan_sub_header(h->s);

		FZ_CHECK(c, hd->produced == h->next && hd->dropped == h->refused, "the header's counters differ from the model");
	}
	fz_digest(c, op ^ (h->held << 8));
	return 0;
}

static void ch_close(void *hh)
{
	struct chs *h = (struct chs *)hh;

	kof_chan_sub_close(h->s);
	kof_chan_publish_close(h->p);
	free(h);
}

FZ_ADAPTER(chan_ring, .name = "orbit/chan_ring", .covers = "kof_chan_publish_open kof_chan_publish kof_chan_publish_close", .shape = FZ_SEQ, .n_kinds = 3, .seeds = seeds_ops, .open = ch_open,
	   .op = ch_op, .close = ch_close);

/* ------------------------------------------------------------------------------------------------- fid */

static void seeds_fid(struct fz_corpus *c)
{
	struct kof_fid f;

	memset(&f, 0, sizeof f);
	f.node[0] = 7;
	f.size = 1000;
	f.born = 111;
	f.written = 222;
	fz_corpus_add(c, "fid", &f, sizeof f);
	fz_corpus_add(c, "zero", &f, 0);
}

static int run_fid(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kof_fid f, g;
	uint64_t k1, k2;
	size_t pos;
	char name[128], path[700];
	struct stat sb;
	int fd, rc;

	memset(&f, 0, sizeof f);
	memcpy(&f, in, n < sizeof f ? n : sizeof f);
	g = f;
	k1 = kof_fid_key(&f);
	k2 = kof_fid_key(&g);
	FZ_CHECK(c, k1 == k2, "the same identity gives two keys");
	FZ_CHECK(c, k1 != 0, "a key of zero is the empty slot of the set");
	pos = n ? (size_t)fz_below(c->rng, sizeof f) : 0u;
	((uint8_t *)&g)[pos] ^= (uint8_t)(1u << fz_below(c->rng, 8));
	FZ_CHECK(c, kof_fid_key(&g) != k1, "one changed bit of the identity left the key unchanged");
	fz_digest(c, k1);
	/* kof_fid_of on a file the input names (made, then removed) */
	{
		size_t i, l = n > 12 ? 12 : n;

		for (i = 0; i < l; i++)
			name[i] = (char)('a' + in[i] % 26u);
		name[l] = '\0';
	}
	snprintf(path, sizeof path, "%s/fid_%s_%u", ofx_dir(), name, c->iter % 5u);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		struct kof_fid out;

		if (n > 12)
			(void)write(fd, in + 12, n - 12u);
		close(fd);
		rc = kof_fid_of(path, &out);
		FZ_CHECK(c, rc == 1 && stat(path, &sb) == 0 && out.size == (uint64_t)sb.st_size, "the identity of a regular file is not its size and place");
		FZ_CHECK(c, kof_fid_key(&out) != 0, "a real file has a zero key");
		unlink(path);
		FZ_CHECK(c, kof_fid_of(path, &out) == 0, "a file that is gone has an identity");
		if (symlink("/etc/hostname", path) == 0) {
			FZ_CHECK(c, kof_fid_of(path, &out) == 0, "a symlink has the identity of its target");
			unlink(path);
		}
		if (mkdir(path, 0700) == 0) {
			FZ_CHECK(c, kof_fid_of(path, &out) == 0, "a directory has an identity");
			rmdir(path);
		}
		FZ_CHECK(c, kof_fid_of(NULL, &out) == 0 && kof_fid_of("", &out) == 0 && kof_fid_of(path, NULL) == 0, "a NULL or empty argument has an identity");
	}
	return (int)k1;
}

FZ_ADAPTER(fid, .name = "orbit/fid", .covers = "kof_fid_key kof_fid_of", .shape = FZ_REQ, .seeds = seeds_fid, .run = run_fid);

/* ------------------------------------------------------------------------------------------------- mkpath */

static int rm_cb(const char *p, const struct stat *sb, int type, struct FTW *f)
{
	(void)sb;
	(void)type;
	(void)f;
	return remove(p);
}

static void seeds_path(struct fz_corpus *c)
{
	fz_corpus_add(c, "path", "a/b/c/d", 7);
	fz_corpus_add(c, "slashes", "a//b///c/", 9);
}

static int run_mkpath(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char path[1200], rel[500];
	size_t i, l = n > 400 ? 400 : n;
	struct stat sb;
	int rc;

	/* the input is the path below the scratch root: no '..', no NUL, no leading slash that would leave the root */
	for (i = 0; i < l; i++) {
		unsigned char ch = in[i];

		rel[i] = (char)((ch == 0 || ch == '.' || ch == '\\') ? '_' : ch);
	}
	rel[l] = '\0';
	snprintf(path, sizeof path, "%s/mk%u/%s", ofx_dir(), c->iter % 7u, rel);
	rc = kof_report_mkpath(path);
	FZ_CHECK(c, rc == 0 || rc == KOF_ERR_OPEN, "mkpath answered something that is not 0 or KOF_ERR_OPEN");
	if (rc == 0 && l)
		FZ_CHECK(c, stat(path, &sb) == 0 && S_ISDIR(sb.st_mode), "mkpath said 0 and the directory is not there");
	fz_digest(c, (uint64_t)rc);
	snprintf(path, sizeof path, "%s/mk%u", ofx_dir(), c->iter % 7u);
	(void)nftw(path, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	return rc;
}

FZ_ADAPTER(mkpath, .name = "orbit/mkpath", .covers = "kof_report_mkpath", .shape = FZ_REQ, .seeds = seeds_path, .run = run_mkpath);

/* ------------------------------------------------------------------------------------------------- wevt */

static void seeds_wevt(struct fz_corpus *c)
{
	static const uint16_t verbs[] = { KOF_EVT_PROC_START, KOF_EVT_FILE_NEW, KOF_EVT_NET_CONNECT, KOF_EVT_REG_SET_VALUE, KOF_EVT_IMAGE_LOAD, KOF_EVT_AMSI_SCAN };
	unsigned i;

	for (i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
		struct kofw_evt e;

		memset(&e, 0, sizeof e);
		e.type = verbs[i];
		e.pid = 100u + i;
		e.ppid = 4;
		e.raiser_pid = 100u + i;
		e.stamp = 132000000000000000ull + i;
		e.provider = (uint8_t)(1u + i % 6u);
		e.off_image = 0;
		memcpy(e.text, "C:\\x\\a.exe", 11);
		e.off_object = 11;
		memcpy(e.text + 11, "C:\\Windows\\System32\\k.dll", 25);
		e.off_cmdline = KOF_TEXT_NONE;
		e.off_data = KOF_TEXT_NONE;
		e.text_len = 36;
		fz_corpus_add(c, "wevt", &e, sizeof e);
	}
}

static int run_wevt(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static struct fz_gb gb;
	static int have;
	static struct kofw_ptab tab;
	struct kofw_evt *e;
	struct kof_evt k;
	struct kofw_filter flt;
	unsigned char ident[256];
	size_t il;
	int coarse = 0, keep;
	uint8_t why = 0;

	if (!have) {
		if (!fz_gb_init(&gb, sizeof *e, 0, 0))
			return 0;
		have = 1;
	}
	e = (struct kofw_evt *)fz_gb_end(&gb, sizeof *e);
	memset(e, 0, sizeof *e);
	memcpy(e, in, n < sizeof *e ? n : sizeof *e);
	e->text[sizeof e->text - 1u] = '\0';
	/* what kofevt_log_read guarantees of a record it hands back: head + text_len inside the record. A record that breaks it makes
	 * kofw_evt_to_kof copy up to 56 bytes from beyond the source arena (finding WP12-19, tests_wp12/findings). */
	if (e->text_len > sizeof e->text)
		e->text_len = (uint16_t)sizeof e->text;
	FZ_CHECK(c, kofw_evt_image(e) && kofw_evt_object(e) && kofw_evt_cmdline(e), "an accessor returned NULL");
	FZ_CHECK(c, strlen(kofw_evt_image(e)) < sizeof e->text && strlen(kofw_evt_cmdline(e)) < sizeof e->text, "a string runs past the arena");
	FZ_CHECK(c, kofw_provider_name(e->provider) != NULL && kofw_sub_name(1u << (e->cpu % 32u)) != NULL, "a name function answered NULL");
	kofw_evt_to_kof(e, &k);
	FZ_CHECK(c, k.os == KOF_OS_WINDOWS && k.stamp == e->stamp && k.pid == e->pid, "the conversion changed the record's identity");
	FZ_CHECK(c, k.text_len <= sizeof k.text, "the converted arena is longer than the arena");
	il = kofw_evt_ident(e, ident, sizeof ident, &coarse);
	FZ_CHECK(c, il <= sizeof ident, "an identity longer than its buffer");
	memset(&tab, 0, sizeof tab);
	kofw_ptab_init(&tab);
	memset(&flt, 0, sizeof flt);
	flt.types = (uint32_t)fz_below(c->rng, 1u << 20) * (uint32_t)fz_below(c->rng, 2);
	flt.drop_loc = (uint32_t)fz_below(c->rng, 1u << 17) * (uint32_t)fz_below(c->rng, 2);
	flt.root_pid = fz_below(c->rng, 2) ? 0u : e->ppid;
	if (flt.root_pid)
		(void)kofw_ptab_add(&tab, flt.root_pid, 0, "root", 0);
	keep = kofw_filter_apply(&tab, &flt, e, &why);
	FZ_CHECK(c, keep == 0 || keep == 1, "the filter answered something that is not a boolean");
	FZ_CHECK(c, keep || why != KOFW_REFUSE_NONE, "a refusal with no reason");
	FZ_CHECK(c, tab.n <= KOFW_PTAB_MAX && tab.names_used <= KOFW_NAME_POOL, "the process table is over its size");
	fz_digest(c, il ^ ((uint64_t)keep << 40) ^ ((uint64_t)why << 48));
	return keep;
}

FZ_ADAPTER(wevt, .name = "orbit/wevt",
	   .covers = "kofw_evt_image kofw_evt_cmdline kofw_provider_name kofw_sub_name kofw_evt_to_kof kofw_evt_ident kofw_filter_apply",
	   .shape = FZ_REQ, .flags = FZ_KEEPS_STATE, .seeds = seeds_wevt, .run = run_wevt);
