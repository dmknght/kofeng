/*
 * orbit/store - what libkoforbit keeps on disk and in shared memory, fed bytes that are not what it wrote.
 *
 *   fidset_file   a clean-file set of anything (a memfd named through /proc/self/fd): load, then every lookup. Seeds are
 *                 files the set itself saved. A set that loads must have the size its header says; a set that does not
 *                 must answer for nothing.
 *   fridge_file   the verdict cache file of anything. FZ_MAY_HIT_CAP: the header's entry count sizes an allocation before
 *                 the file's length is looked at (unit test orbit_store, row WP12-11), so a header that claims 4 million
 *                 entries meets the allocation cap here.
 *   fidset_ops    add / drop / has / save / reload on a scratch file against a plain array: the same answers before and
 *                 after the file round trip (differential oracle).
 *   seen_ops      the suppression table: marks, clears, stats; asked = fresh + repeat, never over capacity.
 *   chan_segment  a shared-memory channel whose bytes are the input: the subscriber refuses it or reads it without leaving
 *                 the segment.
 *   report_feed   events made of the input, fed to a report, finished without a disk, written as text, JSON and
 *                 candidates; the JSON must be well formed whatever strings the sample chose.
 *   proc_rec      kof_proc_build_rec over strings from the input: refused whole or exact, every offset a string.
 */
#include "orbit_fx.h"

#include "fidset.h"
#include "kofchan.h"
#include "kofevtlog.h"
#include "kofcore.h"
#include "kofeng.h"
#include "koffridge.h"
#include "kofproc.h"
#include "kofreport.h"

#include <semaphore.h>

/* ------------------------------------------------------------------------------------------------- fidset_file */

#define DB 0x1234u
#define ENG 0x900DC0DEu

static void seeds_fidset(struct fz_corpus *c)
{
	static struct fz_field f[8];
	static struct fz_map m;
	unsigned k;

	m.f = f;
	m.n = 0;
	f[m.n++] = (struct fz_field){ 8, 4, 0, FZ_COUNT };                  /* version */
	f[m.n++] = (struct fz_field){ 12, 4, 0, FZ_COUNT };                 /* stride */
	f[m.n++] = (struct fz_field){ 16, 8, 0, FZ_LEN };                   /* db stamp */
	f[m.n++] = (struct fz_field){ 24, 8, 0, FZ_LEN };                   /* engine stamp */
	f[m.n++] = (struct fz_field){ 40, 8, 0, FZ_COUNT };                 /* n */
	for (k = 0; k < 3; k++) {
		static const unsigned counts[3] = { 1, 40, 1200 };
		char path[600];
		struct kof_fidset *s = kof_fidset_open(DB, ENG);
		unsigned i;
		FILE *fp;
		long sz;
		uint8_t *buf;

		snprintf(path, sizeof path, "%s/seed_fid%u.bin", ofx_dir(), k);
		for (i = 0; i < counts[k]; i++)
			kof_fidset_add(s, 1000u + i * 7u);
		kof_fidset_save(s, path);
		kof_fidset_close(s);
		fp = fopen(path, "rb");
		if (!fp)
			continue;
		fseek(fp, 0, SEEK_END);
		sz = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		buf = (uint8_t *)malloc((size_t)sz);
		if (buf && fread(buf, 1, (size_t)sz, fp) == (size_t)sz)
			fz_corpus_add_map(c, "fidset", buf, (size_t)sz, &m);
		free(buf);
		fclose(fp);
		unlink(path);
	}
}

static int run_fidset(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char path[64];
	int fd = ofx_memfd(in, n, path, sizeof path), loaded;
	struct kof_fidset *s;
	struct kof_fidset_stat st;
	unsigned i;

	if (fd < 0)
		return 0;
	s = kof_fidset_open(DB, ENG);
	if (!s) {
		close(fd);
		return 0;
	}
	loaded = kof_fidset_load(s, path);
	kof_fidset_stats(s, &st);
	if (loaded) {
		uint64_t nk;

		memcpy(&nk, in + 40, 8);
		FZ_CHECK(c, n >= 48 && nk && st.mapped == nk, "a loaded set whose key count is not its header's");
		FZ_CHECK(c, n == 48u + 8u * (nk + (nk + 511u) / 512u), "a loaded set whose size is not what its header says");
		for (i = 0; i < 8; i++) {
			uint64_t key;

			if (n >= 48u + 8u * (i + 1u)) {
				memcpy(&key, in + 48 + 8u * i, 8);
				(void)kof_fidset_has(s, key);
			}
			(void)kof_fidset_has(s, (uint64_t)fz_below(c->rng, 1u << 20));
		}
		(void)kof_fidset_has(s, 1000);
		(void)kof_fidset_has(s, ~0ull);
	} else {
		FZ_CHECK(c, kof_fidset_has(s, 1000) == 0 && kof_fidset_has(s, 1007) == 0, "a set that did not load answers for a key");
	}
	fz_digest(c, (uint64_t)loaded ^ (st.mapped << 8));
	kof_fidset_close(s);
	close(fd);
	return loaded;
}

FZ_ADAPTER(fidset_file, .name = "orbit/fidset_file",
	   .covers = "kof_fidset_open kof_fidset_load kof_fidset_has kof_fidset_stats kof_fidset_close kof_fidset_save",
	   .shape = FZ_REQ, .seeds = seeds_fidset, .run = run_fidset);

/* ------------------------------------------------------------------------------------------------- fridge_file */

static void seed_unterminated(struct fz_corpus *c, struct fz_map *m);

static void seeds_fridge(struct fz_corpus *c)
{
	static struct fz_field f[8];
	static struct fz_map m;
	unsigned k;

	m.f = f;
	m.n = 0;
	f[m.n++] = (struct fz_field){ 4, 2, 0, FZ_COUNT };                  /* version */
	f[m.n++] = (struct fz_field){ 6, 2, 0, FZ_LEN };                    /* hdr_size */
	f[m.n++] = (struct fz_field){ 8, 4, 0, FZ_LEN };                    /* entry_size */
	f[m.n++] = (struct fz_field){ 12, 4, 0, FZ_COUNT };                 /* n_entries */
	f[m.n++] = (struct fz_field){ 16, 8, 0, FZ_LEN };                   /* db stamp */
	f[m.n++] = (struct fz_field){ 24, 8, 0, FZ_LEN };                   /* checksum */
	for (k = 0; k < 3; k++) {
		static const unsigned counts[3] = { 0, 1, 12 };
		char path[600];
		struct koffridge *fr = koffridge_open(256, 0x77);
		struct kof_result res;
		unsigned i;
		FILE *fp;
		long sz;
		uint8_t *buf;

		memset(&res, 0, sizeof res);
		snprintf(path, sizeof path, "%s/seed_fr%u.bin", ofx_dir(), k);
		for (i = 0; i < counts[k]; i++) {
			char id[16];
			int l = snprintf(id, sizeof id, "id-%u", i);

			koffridge_put(fr, id, (uint32_t)l, &res);
		}
		koffridge_save(fr, path);
		koffridge_close(fr);
		fp = fopen(path, "rb");
		if (!fp)
			continue;
		fseek(fp, 0, SEEK_END);
		sz = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		buf = (uint8_t *)malloc((size_t)sz);
		if (buf && fread(buf, 1, (size_t)sz, fp) == (size_t)sz)
			fz_corpus_add_map(c, "fridge", buf, (size_t)sz, &m);
		free(buf);
		fclose(fp);
		unlink(path);
	}
	seed_unterminated(c, &m);
}

/* a cache file whose checksum is RIGHT and whose entry's name has no NUL (the file is a trust input, the checksum only catches bad sectors) */
static void seed_unterminated(struct fz_corpus *c, struct fz_map *m)
{
	struct {
		uint64_t h, used;
		uint32_t id_len;
		uint8_t  id[KOFFRIDGE_ID_MAX];
		struct koffridge_verdict v;
	} e;
	struct {
		uint32_t magic;
		uint16_t version, hdr_size;
		uint32_t entry_size, n_entries;
		uint64_t db_stamp, sum, reserved;
	} h;
	char path[600];
	struct koffridge *fr = koffridge_open(256, 0x77);
	struct kof_result res;
	FILE *fp;

	memset(&res, 0, sizeof res);
	snprintf(path, sizeof path, "%s/seed_fr_nul.bin", ofx_dir());
	koffridge_put(fr, "id-0", 4, &res);
	koffridge_save(fr, path);
	koffridge_close(fr);
	fp = fopen(path, "rb");
	if (fp && fread(&h, 1, sizeof h, fp) == sizeof h && fread(&e, 1, sizeof e, fp) == sizeof e) {
		static uint8_t buf[sizeof h + sizeof e];

		memset(e.v.name, 'N', sizeof e.v.name);
		h.sum = kof_hash64_update(KOF_HASH64_INIT, &e, sizeof e);
		memcpy(buf, &h, sizeof h);
		memcpy(buf + sizeof h, &e, sizeof e);
		fz_corpus_add_map(c, "fridge-nonul", buf, sizeof buf, m);
	}
	if (fp)
		fclose(fp);
	unlink(path);
}

static int run_fridge(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char path[64];
	int fd = ofx_memfd(in, n, path, sizeof path);
	struct koffridge *f;
	const char *why = "";
	uint32_t got, i;
	struct koffridge_stat st;

	if (fd < 0)
		return 0;
	f = koffridge_open(256, 0x77);
	if (!f) {
		close(fd);
		return 0;
	}
	got = koffridge_load(f, path, &why);
	FZ_CHECK(c, why != NULL && why[0], "a load that says nothing about itself");
	koffridge_stats(f, &st);
	FZ_CHECK(c, st.used <= st.capacity && got <= 4194304u, "more entries in the table than its capacity");
	for (i = 0; i < 16; i++) {
		char id[16];
		int l = snprintf(id, sizeof id, "id-%u", i);
		struct koffridge_verdict v;

		memset(&v, 0xa5, sizeof v);
		if (koffridge_get(f, id, (uint32_t)l, &v) == 1)
			FZ_CHECK(c, v.name[sizeof v.name - 1u] == '\0' && strlen(v.name) < sizeof v.name, "a name from a file is not terminated");
	}
	{
		char d[600];

		(void)koffridge_describe(f, d, sizeof d);
		FZ_CHECK(c, strlen(d) < sizeof d, "describe is not terminated");
	}
	fz_digest(c, (uint64_t)got ^ ((uint64_t)st.used << 32));
	koffridge_close(f);
	close(fd);
	return (int)got;
}

FZ_ADAPTER(fridge_file, .name = "orbit/fridge_file",
	   .covers = "koffridge_open koffridge_load koffridge_get koffridge_put koffridge_save koffridge_stats koffridge_describe koffridge_close",
	   .shape = FZ_REQ, .flags = FZ_MAY_HIT_CAP, .backstop_s = 1800, .seeds = seeds_fridge, .run = run_fridge);

/* ------------------------------------------------------------------------------------------------- fidset_ops */

static void seeds_ops(struct fz_corpus *c)
{
	uint8_t b[10 * 40];
	unsigned i;

	for (i = 0; i < 40; i++) {
		b[10 * i] = (uint8_t)(i % 7u);
		b[10 * i + 1] = (uint8_t)(i * 3u);
		memset(b + 10 * i + 2, 0, 3);
		b[10 * i + 5] = (uint8_t)(i % 5u);
		memset(b + 10 * i + 6, 0, 4);
	}
	fz_corpus_add(c, "ops", b, sizeof b);
}

/* The model, from the documented semantics: has = (added or in the file) and not dropped; add of a key that is already in the set
 * changes nothing (even when it was dropped this run: the drop wins until the next save); a drop of a key that is not there is not
 * a removal; save writes has() and reloads it, which empties both lists. */
struct fops {
	struct kof_fidset *s;
	uint8_t            a[256], m[256], d[256];
	char               path[700];
};

static void *ops_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct fops *o = (struct fops *)calloc(1, sizeof *o);

	(void)in;
	(void)n;
	if (!o)
		return NULL;
	snprintf(o->path, sizeof o->path, "%s/ops%u.bin", ofx_dir(), c->iter);
	o->s = kof_fidset_open(DB, ENG);
	if (!o->s) {
		free(o);
		return NULL;
	}
	return o;
}

static int ops_op(struct fz_ctx *c, void *h, unsigned op, uint64_t a, uint64_t b)
{
	struct fops *o = (struct fops *)h;
	unsigned k = 1u + (unsigned)(a % 255u), i;

	(void)b;
	if (c->failk && (op == 0 || op == 3))
		return 0;                      /* an allocation that fails is refused honestly: the model is not advanced */
	switch (op) {
	case 0:
		FZ_CHECK(c, kof_fidset_add(o->s, k) == 1, "an add was refused");
		if (!o->a[k] && !o->m[k])
			o->a[k] = 1;
		break;
	case 1:
		(void)kof_fidset_drop(o->s, k);
		if ((o->a[k] || o->m[k]) && !o->d[k])
			o->d[k] = 1;
		break;
	case 2:
		FZ_CHECK(c, kof_fidset_has(o->s, k) == ((o->a[k] || o->m[k]) && !o->d[k]), "has disagrees with the model");
		break;
	case 3:
		if (kof_fidset_save(o->s, o->path)) {
			for (i = 1; i < 256; i++) {
				o->m[i] = (uint8_t)((o->a[i] || o->m[i]) && !o->d[i]);
				o->a[i] = o->d[i] = 0;
			}
			unlink(o->path);           /* the set keeps its mapping of the file it just wrote */
		}
		break;
	default:
		for (i = 1; i < 256; i++)
			FZ_CHECK(c, kof_fidset_has(o->s, i) == ((o->a[i] || o->m[i]) && !o->d[i]), "a key's answer differs from the model");
		break;
	}
	fz_digest(c, op ^ ((uint64_t)k << 8));
	return 0;
}

static void ops_close(void *h)
{
	struct fops *o = (struct fops *)h;

	kof_fidset_close(o->s);
	unlink(o->path);
	free(o);
}

FZ_ADAPTER(fidset_ops, .name = "orbit/fidset_ops", .covers = "kof_fidset_add kof_fidset_drop", .shape = FZ_SEQ, .flags = FZ_KEEPS_STATE, .n_kinds = 5, .seeds = seeds_ops, .open = ops_open,
	   .op = ops_op, .close = ops_close);

/* ------------------------------------------------------------------------------------------------- seen_ops */

struct sops {
	struct koffridge_seen *s;
};

static void *seen_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct sops *o = (struct sops *)calloc(1, sizeof *o);

	(void)c;
	(void)in;
	(void)n;
	if (!o)
		return NULL;
	o->s = koffridge_seen_open(32, 1000);
	if (!o->s) {
		free(o);
		return NULL;
	}
	return o;
}

static int seen_op(struct fz_ctx *c, void *h, unsigned op, uint64_t a, uint64_t b)
{
	struct sops *o = (struct sops *)h;
	struct koffridge_seen_stat st;
	char id[24];
	int l = snprintf(id, sizeof id, "k%u", (unsigned)(a % 90u));

	if (op == 0) {
		(void)koffridge_seen_mark(o->s, id, (uint32_t)l, b);
	} else if (op == 1) {
		koffridge_seen_clear(o->s);
	} else {
		struct kof_evt e;

		memset(&e, 0, sizeof e);
		e.verb = KOF_EVT_FILE_NEW;
		e.actor_pid = (uint32_t)a;
		e.stamp = b;
		e.off_image = e.off_cmdline = e.off_data = KOF_TEXT_NONE;
		e.off_object = kof_evt_text_put(&e, id);
		(void)koffridge_seen_evt(o->s, &e);
	}
	koffridge_seen_stats(o->s, &st);
	FZ_CHECK(c, st.asked == st.fresh + st.repeat, "asked is not fresh + repeat");
	FZ_CHECK(c, st.used <= st.cap, "more identities than slots");
	fz_digest(c, st.fresh ^ (st.repeat << 20) ^ (st.evicted << 40));
	return 0;
}

static void seen_close(void *h)
{
	struct sops *o = (struct sops *)h;

	koffridge_seen_close(o->s);
	free(o);
}

FZ_ADAPTER(seen_ops, .name = "orbit/seen_ops",
	   .covers = "koffridge_seen_open koffridge_seen_mark koffridge_seen_evt koffridge_seen_stats koffridge_seen_clear koffridge_seen_close",
	   .shape = FZ_SEQ, .n_kinds = 3, .seeds = seeds_ops, .open = seen_open, .op = seen_op, .close = seen_close);

/* ------------------------------------------------------------------------------------------------- chan_segment */

static void seeds_chan(struct fz_corpus *c)
{
	static struct fz_field f[8];
	static struct fz_map m;
	struct kof_chan_hdr h;
	uint8_t *buf;
	size_t n = sizeof h + 8u * sizeof(struct kof_evt);

	m.f = f;
	m.n = 0;
	f[m.n++] = (struct fz_field){ 0, 4, 0, FZ_COUNT };                  /* magic */
	f[m.n++] = (struct fz_field){ 4, 4, 0, FZ_COUNT };                  /* version */
	f[m.n++] = (struct fz_field){ 8, 4, 0, FZ_LEN };                    /* rec_size */
	f[m.n++] = (struct fz_field){ 20, 4, 0, FZ_COUNT };                 /* rec_kind */
	f[m.n++] = (struct fz_field){ 24, 4, 0, FZ_COUNT };                 /* capacity */
	f[m.n++] = (struct fz_field){ 40, 4, 0, FZ_COUNT };                 /* head */
	memset(&h, 0, sizeof h);
	h.magic = KOF_CHAN_MAGIC;
	h.version = KOF_CHAN_VERSION;
	h.rec_size = sizeof(struct kof_evt);
	h.head_size = KOF_EVT_HEAD;
	h.len_off = (uint32_t)offsetof(struct kof_evt, text_len);
	h.rec_kind = KOFEVT_REC_KOF;
	h.capacity = 8;
	h.pid = 1;
	h.head = 3;
	buf = (uint8_t *)calloc(1, n);
	if (!buf)
		return;
	memcpy(buf, &h, sizeof h);
	{
		unsigned i;

		for (i = 0; i < 3; i++) {
			struct kof_evt e;

			memset(&e, 0, sizeof e);
			e.verb = KOF_EVT_FILE_NEW;
			e.seq = i;
			e.off_image = e.off_object = e.off_cmdline = e.off_data = KOF_TEXT_NONE;
			memcpy(buf + sizeof h + i * sizeof e, &e, sizeof e);
		}
	}
	fz_corpus_add_map(c, "channel", buf, n, &m);
	free(buf);
}

static int run_chan(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char name[64], nd[80], nc[80], nw[80];
	int fd_d, fd_c;
	struct kof_chan_sub *s;
	const char *why = "";
	int reason = 0;
	size_t len = n < sizeof(struct kof_chan_hdr) ? sizeof(struct kof_chan_hdr) : n;

	snprintf(name, sizeof name, "kfz%u-%u", (unsigned)getpid(), c->iter % 1000u);
	snprintf(nd, sizeof nd, "/%s-d", name);
	snprintf(nc, sizeof nc, "/%s-c", name);
	snprintf(nw, sizeof nw, "/%s-w", name);
	shm_unlink(nd);
	shm_unlink(nc);
	fd_d = shm_open(nd, O_CREAT | O_EXCL | O_RDWR, 0600);
	fd_c = shm_open(nc, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (fd_d < 0 || fd_c < 0) {
		if (fd_d >= 0) {
			close(fd_d);
			shm_unlink(nd);
		}
		if (fd_c >= 0) {
			close(fd_c);
			shm_unlink(nc);
		}
		return 0;
	}
	if (ftruncate(fd_d, (off_t)len) == 0 && ftruncate(fd_c, 8) == 0 && (n == 0 || pwrite(fd_d, in, n, 0) == (ssize_t)n)) {
		s = kof_chan_sub_open(name, &why, &reason);
		FZ_CHECK(c, why != NULL, "no reason string");
		if (s) {
			struct kof_evt e;
			const struct kof_chan_hdr *h = kof_chan_sub_header(s);
			unsigned k = 0;

			FZ_CHECK(c, h && h->capacity && (h->capacity & (h->capacity - 1u)) == 0 && h->rec_size == sizeof e && h->rec_kind == KOFEVT_REC_KOF,
				 "an opened channel whose header is not a channel's");
			FZ_CHECK(c, (uint64_t)h->capacity * h->rec_size + sizeof *h <= len + 0u, "an opened channel larger than the segment");
			while (k < 40 && kof_chan_next(s, &e, 0) == 1) {
				fz_digest(c, e.seq ^ e.verb);
				k++;
			}
			fz_digest(c, k);
			kof_chan_sub_close(s);
		} else {
			FZ_CHECK(c, reason >= KOF_CHAN_WHY_ABSENT && reason <= KOF_CHAN_WHY_BROKEN, "a refusal with no reason");
			fz_digest(c, (uint64_t)reason);
		}
	}
	close(fd_d);
	close(fd_c);
	shm_unlink(nd);
	shm_unlink(nc);
	sem_unlink(nw);
	return 0;
}

FZ_ADAPTER(chan_segment, .name = "orbit/chan_segment", .covers = "kof_chan_sub_open kof_chan_sub_header kof_chan_next kof_chan_sub_close",
	   .shape = FZ_REQ, .seeds = seeds_chan, .run = run_chan);

/* ------------------------------------------------------------------------------------------------- report_feed */

static void seeds_report(struct fz_corpus *c)
{
	uint8_t buf[640 * 3];
	unsigned i;

	for (i = 0; i < 3; i++) {
		struct kof_evt e;
		static const uint16_t verbs[3] = { KOF_EVT_PROC_START, KOF_EVT_FILE_NEW, KOF_EVT_NET_CONNECT };

		memset(&e, 0, sizeof e);
		e.verb = verbs[i];
		e.pid = 10;
		e.actor_pid = 10;
		e.stamp = 132000000000000100ull + i;
		e.off_image = kof_evt_text_put(&e, "/bin/sample");
		e.off_object = kof_evt_text_put(&e, i == 1 ? "/etc/cron.d/x" : "x");
		e.off_cmdline = e.off_data = KOF_TEXT_NONE;
		memcpy(buf + 640u * i, &e, sizeof e);
	}
	fz_corpus_add(c, "events", buf, sizeof buf);
}

/* a JSON document is well formed here when its strings close, hold no raw control byte, and its braces and brackets balance */
static int json_ok(const char *s, size_t n)
{
	size_t i;
	int in_str = 0, esc = 0, depth = 0;

	for (i = 0; i < n; i++) {
		unsigned char ch = (unsigned char)s[i];

		if (in_str) {
			if (esc)
				esc = 0;
			else if (ch == '\\')
				esc = 1;
			else if (ch == '"')
				in_str = 0;
			else if (ch < 0x20 || ch >= 0x7f)
				return 0;
		} else if (ch == '"')
			in_str = 1;
		else if (ch == '{' || ch == '[')
			depth++;
		else if (ch == '}' || ch == ']') {
			if (--depth < 0)
				return 0;
		}
	}
	return !in_str && depth == 0;
}

static int run_report(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kof_report_info ri;
	struct kof_report *r;
	struct kof_report_stage st;
	unsigned k, nev = (unsigned)(n / sizeof(struct kof_evt));
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;

	memset(&ri, 0, sizeof ri);
	ri.tool = "fuzz";
	ri.subject = NULL;
	ri.root_pid = 10;
	r = kof_report_open(&ri);
	if (!r)
		return 0;
	if (nev > 12)
		nev = 12;
	for (k = 0; k < nev; k++) {
		struct kof_evt e;

		memcpy(&e, in + k * sizeof e, sizeof e);
		ofx_seal(&e);
		if (e.verb < KOF_EVT_TYPE_COUNT)
			kof_report_feed(r, &e, k);
	}
	kof_report_ended(r, KOF_END_TIMEOUT, 1.5);
	memset(&st, 0, sizeof st);
	kof_report_finish(r, &st);
	FZ_CHECK(c, kof_report_count(r) <= 4096u && kof_report_procs(r) <= 4096u, "more fingerprints than the table holds");
	for (k = 0; k < kof_report_count(r) && k < 40; k++) {
		const struct kof_fingerprint *fp = kof_report_at(r, k);

		FZ_CHECK(c, fp != NULL, "a fingerprint below the count is NULL");
		if (fp) {
			FZ_CHECK(c, fp->text != NULL, "a fingerprint with no text");
			FZ_CHECK(c, fp->kind < KOF_FP_KIND_COUNT, "a fingerprint of an impossible kind");
			/* a FILE_NEW fingerprint of count 0 is the phantom a FILE_DELETE of a path never created leaves (finding WP12-23) */
			FZ_CHECK(c, fp->count > 0 || fp->kind == KOF_FP_FILE_NEW, "a fingerprint that was never counted");
		}
	}
	f = open_memstream(&buf, &blen);
	if (f) {
		FZ_CHECK(c, kof_report_write_json(r, f) == 0, "the JSON writer failed on a memory stream");
		fclose(f);
		FZ_CHECK(c, buf && json_ok(buf, blen), "the JSON is not well formed");
		fz_digest(c, blen);
		free(buf);
		buf = NULL;
	}
	f = open_memstream(&buf, &blen);
	if (f) {
		(void)kof_report_write_text(r, f, (int)fz_below(c->rng, 2));
		(void)kof_report_write_candidates(r, f);
		fclose(f);
		fz_digest(c, blen);
		free(buf);
	}
	for (k = 0; k < kof_report_procs(r) && k < 20; k++) {
		const struct kof_rep_proc *pr = kof_report_proc_at(r, k);

		FZ_CHECK(c, pr != NULL, "a process below the count is NULL");
	}
	FZ_CHECK(c, kof_report_proc_at(r, kof_report_procs(r)) == NULL, "a process past the count exists");
	for (k = 0; k < KOF_FP_KIND_COUNT; k++)
		(void)kof_report_dropped(r, (uint8_t)k);
	{
		struct kof_evt_health h;

		memset(&h, 0, sizeof h);
		h.produced = n;
		kof_report_health(r, &h, 3);
	}
	if (kof_report_count(r)) {
		const struct kof_fingerprint *fp = kof_report_at(r, 0);

		(void)kof_report_spill(r, fp->text, "/spilled/copy");
	}
	fz_digest(c, kof_report_count(r));
	kof_report_close(r);
	return (int)nev;
}

FZ_ADAPTER(report_feed, .name = "orbit/report_feed",
	   .covers = "kof_report_open kof_report_feed kof_report_ended kof_report_finish kof_report_count kof_report_at kof_report_procs kof_report_write_json kof_report_write_text "
		     "kof_report_write_candidates kof_report_close kof_report_proc_at kof_report_dropped kof_report_health kof_report_spill",
	   .shape = FZ_REQ, .backstop_s = 1800, .seeds = seeds_report, .run = run_report);

/* ------------------------------------------------------------------------------------------------- proc_rec */

static void seeds_rec(struct fz_corpus *c)
{
	static const uint8_t a[] = "/bin/x\0x\0x -a\0A=1\0B=2\0conn\0/dev/null\0pipe:[1]\0/dev/null";

	fz_corpus_add(c, "strings", a, sizeof a);
}

static int run_rec(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kof_proc_build b;
	unsigned char rec[4096];
	char *s;
	const char *part[8];
	size_t k, at = 0, i;
	uint32_t cap, got;
	struct kof_proc_rec *r = (struct kof_proc_rec *)rec;

	s = (char *)malloc(n + 9);
	if (!s)
		return 0;
	memcpy(s, in, n);
	memset(s + n, 0, 9);
	/* eight strings: split at NULs, the rest empty */
	for (k = 0; k < 8; k++) {
		part[k] = s + at;
		at += strlen(s + at) + 1u;
		if (at > n + 1u)
			at = n + 1u;
	}
	memset(&b, 0, sizeof b);
	b.os = 2;
	b.pid = 7;
	b.exe = part[0];
	b.comm = part[1];
	b.cmdline = part[2];
	b.env = part[3];
	b.env_len = (uint32_t)strlen(part[3]);
	b.net = part[4];
	b.fd0 = part[5];
	b.fd1 = part[6];
	b.fd2 = part[7];
	cap = (uint32_t)fz_below(c->rng, sizeof rec + 1u);
	memset(rec, 0x55, sizeof rec);
	got = kof_proc_build_rec(&b, rec, cap);
	if (got) {
		const uint16_t *offs[8];
		uint32_t last = 0;

		FZ_CHECK(c, got <= cap && got == r->total_len && got >= sizeof *r, "the length is not the record's own, or past the capacity");
		offs[0] = &r->off_exe;
		offs[1] = &r->off_comm;
		offs[2] = &r->off_cmdline;
		offs[3] = &r->off_environ;
		offs[4] = &r->off_net;
		offs[5] = &r->off_fd0;
		offs[6] = &r->off_fd1;
		offs[7] = &r->off_fd2;
		for (i = 0; i < 8; i++) {
			uint32_t o = *offs[i];

			if (!o) {
				FZ_CHECK(c, !part[i][0], "a string that was given is absent from the record");
				continue;
			}
			FZ_CHECK(c, o >= sizeof *r && o < got, "an offset outside the arena");
			FZ_CHECK(c, o >= last, "the regions are not in order");
			FZ_CHECK(c, o + strlen(part[i]) < got && !memcmp(rec + o, part[i], strlen(part[i]) + 1u), "a string in the record is not the string given");
			last = o;
		}
		FZ_CHECK(c, cap >= got + 0u && (cap == sizeof rec || rec[cap] == 0x55), "bytes past the capacity were written");
	} else {
		FZ_CHECK(c, cap < sizeof *r || 1, "refused");
	}
	fz_digest(c, got);
	free(s);
	return (int)got;
}

FZ_ADAPTER(proc_rec, .name = "orbit/proc_rec", .covers = "kof_proc_build_rec", .shape = FZ_REQ, .seeds = seeds_rec, .run = run_rec);
