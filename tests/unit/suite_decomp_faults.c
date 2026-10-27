/*
 * suite_decomp_faults - a LARGE decompress output meets a full disk, and a compressed file is read short: the decoders of the engine
 * under the engine's own fault seams, for the formats whose output the sink has to hold (a child over its 1 MiB spill point).
 *
 * mem_spill.c does this for one zip entry. The sink is shared, but the decoders are not: each decoder is told "no" in its own place
 * (a bzip2 block, an xz block, the inflate window, a PDF chain's last step) and each must end the entry the same way. Here the same
 * four rows run over gzip (stored deflate blocks, built here), a PDF /FlateDecode stream (zlib), bzip2 and xz (made by the tools, as
 * the other tests do; skipped visibly when the tool is not there), each decoding 1.5 MiB:
 *
 *   ENOSPC       the disk fills part-way through the child (the engine's own spill table, struct kof_spill_io): the object is DROPPED,
 *                not cut - no child of the full size and no clean answer: it is said (broken LIMIT on the root or the child,
 *                spill_full counts, no descriptor is left open) and the next object of the SAME scanner, the disk freed, scans whole
 *   NO PLACE     no directory can be made in, too little free space, a RAM filesystem the host did not name: the child is kept in
 *                memory, whole, and the reason is counted (spill_unavailable, spill_small, spill_ram)
 *   NO ROOM      no file and an allowance whose per-object cap is a little over 1 MiB: the child cannot stay in heap, so it is
 *                CUT at the cap (the bytes before it are its object, stamped LIMIT; a full-size child is never delivered), said
 *                (LIMIT, limit_hits; spill_ceiling when the sink made the refusal), and 64 MiB later the same object is whole
 *   SHORT READ   the compressed FILE is cut or fails to read part-way (the engine's read seam, kof_scan_read_hook): the root is
 *                DAMAGED and its bytes are the file's prefix; what the decoder produced from the prefix is the plain text's prefix and
 *                never longer than it
 *
 * Needs the built database, run from the repository root after make.
 */
#define _GNU_SOURCE

#include "../lib/uncoat/hostile_common.h"
#undef CK
#include "hostile_engine.h"
#include "../../libkofeng/scanners/objctx_int.h"
#include "../../libkofeng/scanners/objsrc.h"
#include "decomp_fixtures.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#define NPAY (1536u * 1024u)
#define DB "build/release/databases"

static uint8_t payload[NPAY];

struct got {
	uint64_t len;
	uint32_t broken;
	int      prefix;          /* the bytes (up to 4 KiB) are the payload's beginning */
	char     name[96];
};

static struct got G[16];
static unsigned NG;

static int cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	(void)user;
	if (NG < 16) {
		G[NG].len = len;
		G[NG].broken = res->broken;
		G[NG].prefix = bytes && !memcmp(bytes, payload, len < 4096u ? (size_t)len : 4096u);
		snprintf(G[NG].name, sizeof G[NG].name, "%s", name);
		NG++;
	}
	return 0;
}

/* ---- the formats ----------------------------------------------------------------------------- */

/*
 * `ceiling` is the resident allowance of the NO ROOM row. A child whose size the stream does not declare grows in the sink and
 * leaves for a file at 1 MiB, so with no file allowed it is refused once the per-object cap (half the allowance, less a record) is
 * met: 2 MiB + 16 KiB puts that cap just over 1 MiB. xz DECLARES its size (the index), the decoder writes into the final buffer and
 * the allowance is charged for it whole: 1.5 MiB fits in 2 MiB and is whole, so its row takes an allowance that does not fit it.
 */
struct fmt {
	const char *name, *root;
	int (*build)(struct he_w *w, const uint8_t *d, size_t n);
	uint64_t ceiling;
	int      counts_ceiling;      /* the refusal is the sink's (spill_ceiling moves); xz's is the ledger's */
};

static const struct fmt FM[] = {
	{ "gzip", "big.gz", b_gzip, (2u << 20) + (16u << 10), 1 }, { "pdf flate", "big.pdf", b_pdf, (2u << 20) + (16u << 10), 1 },
	{ "bzip2", "big.bz2", b_bz2, (2u << 20) + (16u << 10), 1 }, { "xz", "big.xz", b_xz, (5u << 18), 0 }
};

/* ---- the engine's seams ----------------------------------------------------------------------- */

struct sim {
	int      open_fails;
	uint64_t avail;
	int      ram;
	int64_t  fail_after;
	uint64_t written, opens, writes;
};

static int s_open(void *u, const char *first)
{
	struct sim *s = u;

	(void)first;
	__atomic_add_fetch(&s->opens, 1, __ATOMIC_RELAXED);
	if (s->open_fails)
		return -1;
	return memfd_create("kofspill", 0);
}

static int s_write(void *u, int fd, const void *p, uint64_t n)
{
	struct sim *s = u;

	__atomic_add_fetch(&s->writes, 1, __ATOMIC_RELAXED);
	if (s->fail_after >= 0 && s->written + n > (uint64_t)s->fail_after) {
		errno = ENOSPC;
		return 0;
	}
	s->written += n;
	return write(fd, p, (size_t)n) == (ssize_t)n;
}

static int s_space(void *u, int fd, uint64_t *avail, int *ram)
{
	struct sim *s = u;

	(void)fd;
	*ram = s->ram;
	if (!s->avail)
		return 0;
	*avail = s->avail;
	return 1;
}

static struct sim sim0(void)
{
	struct sim s;

	memset(&s, 0, sizeof s);
	s.avail = 1ull << 40;
	s.fail_after = -1;
	return s;
}

static int count_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		n++;
	closedir(d);
	return n;
}

static void scan(kof_scanner *sc, const struct he_w *w, const char *root, uint64_t resident, const char *scratch)
{
	struct kof_scan_option o;

	memset(&o, 0, sizeof o);
	o.heur_level = 1;
	o.emu_forbidden = 1;
	o.max_object_depth = 6;
	o.max_produced_bytes = 1ull << 40;
	o.max_resident_bytes = resident;
	o.max_object_bytes = 64u << 20;
	o.scratch_dir = scratch;
	NG = 0;
	(void)kscan_bytes(sc, w->p, w->n, root, &o, cb, NULL);
}

/* the child that holds the whole payload (and a clean root) */
static int whole(void)
{
	unsigned i;

	for (i = 1; i < NG; i++)
		if (G[i].len == NPAY && G[i].prefix && G[i].broken == 0)
			return NG && G[0].broken == 0;
	return 0;
}

static int said(void)
{
	unsigned i;

	for (i = 0; i < NG; i++)
		if (G[i].broken == KOF_BROKEN_LIMIT)
			return 1;
	return 0;
}

static int no_full_child(void)
{
	unsigned i;

	for (i = 1; i < NG; i++)
		if (G[i].len == NPAY)
			return 0;
	return 1;
}

static void spill_rows(kof_engine *eng, const struct fmt *f, const struct he_w *w)
{
	kof_scanner *sc = kscan_new(eng);
	struct kof_spill_io io = { s_open, s_write, s_space, NULL };
	struct sim sm = sim0();
	int fds;
	unsigned k;
	const struct kof_stats *st;

	CK(sc != NULL, "%s: no scanner", f->name);
	if (!sc)
		return;
	st = kscan_stats(sc);
	io.user = &sm;
	kof_scan_spill_hook(sc, &io);
	scan(sc, w, f->root, 256u << 20, "named");
	CK(whole(), "%s: the reference scan is not whole (%u objects, root broken %u)", f->name, NG, NG ? G[0].broken : 99u);
	CK(sm.writes > 0, "%s: the 1.5 MiB child did not spill (no write reached the seam)", f->name);
	fds = count_fds();

	for (k = 1; k <= 3; k++) {
		uint64_t full0 = st->spill_full;

		sm = sim0();
		sm.fail_after = 300000 * (int64_t)k;
		scan(sc, w, f->root, 256u << 20, "named");
		CK(said() && no_full_child(), "%s ENOSPC at %lld: not said, or a full child was delivered (%u objects, root broken %u)", f->name,
		   (long long)sm.fail_after, NG, NG ? G[0].broken : 99u);
		CK(st->spill_full > full0, "%s ENOSPC at %lld: spill_full did not move", f->name, (long long)sm.fail_after);
		CK(count_fds() == fds, "%s ENOSPC at %lld: a descriptor was left open (%d, was %d)", f->name, (long long)sm.fail_after, count_fds(), fds);
	}
	sm = sim0();
	kof_scan_spill_hook(sc, &io);
	scan(sc, w, f->root, 256u << 20, "named");
	CK(whole(), "%s: the disk freed, the same scanner does not scan whole (%u objects)", f->name, NG);

	sm = sim0();
	sm.open_fails = 1;
	kof_scan_spill_hook(sc, &io);
	{
		uint64_t u0 = st->spill_unavailable;

		scan(sc, w, f->root, 256u << 20, "no/such/dir");
		CK(whole() && st->spill_unavailable > u0, "%s: no place to make a file: not whole, or not counted (%u objects, spill_unavailable +%llu)", f->name, NG,
		   (unsigned long long)(st->spill_unavailable - u0));
	}
	sm = sim0();
	sm.avail = 1u << 20;
	kof_scan_spill_hook(sc, &io);
	{
		uint64_t s0 = st->spill_small;

		scan(sc, w, f->root, 256u << 20, NULL);
		CK(whole() && st->spill_small > s0, "%s: too little free space: not whole, or not counted (%u objects)", f->name, NG);
	}
	sm = sim0();
	sm.ram = 1;
	kof_scan_spill_hook(sc, &io);
	{
		uint64_t r0 = st->spill_ram;

		scan(sc, w, f->root, 256u << 20, NULL);
		CK(whole() && st->spill_ram > r0, "%s: a RAM filesystem: not whole, or not counted (%u objects)", f->name, NG);
	}
	/* no file and an allowance a little over 1 MiB for a child: refused, said, counted; then the 64 MiB allowance is whole */
	sm = sim0();
	sm.open_fails = 1;
	kof_scan_spill_hook(sc, &io);
	{
		uint64_t c0 = st->spill_ceiling, l0 = st->limit_hits;

		scan(sc, w, f->root, f->ceiling, NULL);
		CK(said() && no_full_child() && st->limit_hits > l0 && (!f->counts_ceiling || st->spill_ceiling > c0),
		   "%s: no file and a small allowance: not said (%u objects, limit_hits +%llu, spill_ceiling +%llu)", f->name, NG,
		   (unsigned long long)(st->limit_hits - l0), (unsigned long long)(st->spill_ceiling - c0));
		scan(sc, w, f->root, 64u << 20, NULL);
		CK(whole(), "%s: 64 MiB after a refusal is not whole (%u objects)", f->name, NG);
	}
	kof_scan_spill_hook(sc, NULL);
	kscan_free(sc);
}

/* ---- a compressed file read short ------------------------------------------------------------- */

struct rd {
	int      mode;           /* 1 EOF at the call, 2 EIO at the call */
	uint64_t at, calls, chunk;
};

static int64_t hook_read(void *u, int fd, void *buf, uint64_t n)
{
	struct rd *r = u;
	uint64_t call = ++r->calls;

	if (r->chunk && n > r->chunk)
		n = r->chunk;
	if (call >= r->at && r->mode == 1)
		return 0;
	if (call >= r->at && r->mode == 2) {
		errno = EIO;
		return -1;
	}
	return (int64_t)read(fd, buf, (size_t)n);
}

static void read_rows(kof_engine *eng, const struct fmt *f, const struct he_w *w, const char *dir)
{
	char path[300];
	FILE *fp;
	kof_scanner *sc = kscan_new(eng);
	struct rd r;
	struct kof_src_read_io io = { hook_read, &r };
	struct kof_scan_option o;
	unsigned m;

	snprintf(path, sizeof path, "%s/%s", dir, f->root);
	fp = fopen(path, "wb");
	CK(fp != NULL && sc != NULL, "%s: cannot make the file", f->name);
	if (!fp || !sc) {
		if (fp)
			fclose(fp);
		kscan_free(sc);
		return;
	}
	fwrite(w->p, 1, w->n, fp);
	fclose(fp);
	for (m = 1; m <= 2; m++) {
		unsigned at;

		for (at = 2; at <= 6; at += 2) {
			memset(&r, 0, sizeof r);
			r.mode = (int)m;
			r.at = at;
			r.chunk = (w->n / 8u) | 1u;                   /* the file is read in about eight calls */
			o = he_opt();
			o.heur_level = 1;
			o.emu_forbidden = 1;
			NG = 0;
			kof_scan_read_hook(sc, &io);
			(void)kscan_path(sc, path, &o, cb, NULL);
			kof_scan_read_hook(sc, NULL);
			CK(NG >= 1 && G[0].broken == KOF_BROKEN_DAMAGED, "%s %s at read %u: the root says broken %u, wanted DAMAGED", f->name, m == 1 ? "cut" : "EIO", at,
			   NG ? G[0].broken : 99u);
			{
				unsigned i;

				for (i = 1; i < NG; i++)
					CK(G[i].len < NPAY && G[i].prefix, "%s %s at read %u: a child of %llu bytes (the whole is %u) that %s the plain text's beginning", f->name,
					   m == 1 ? "cut" : "EIO", at, (unsigned long long)G[i].len, NPAY, G[i].prefix ? "is" : "is NOT");
			}
		}
	}
	(void)remove(path);
	kscan_free(sc);
}

static int run_all(void *arg)
{
	kof_engine *eng = keng_open(DB);
	char dir[64];
	size_t i, k;
	uint64_t rs = 0xfeedf00du;
	unsigned made = 0;

	(void)arg;
	if (!eng) {
		printf("suite_decomp_faults: no database (run from the repository root after make): nothing tested\n");
		return 1;
	}
	for (i = 0; i < NPAY; i++) {
		static const char *const words[8] = { "kernel ", "socket ", "connect ", "payload ", "stage ", "loader ", "decode ", "/bin/sh " };

		if (i % 64u == 0)
			memcpy(payload + i, words[hv_rng32(&rs) % 8u], 7);
		else
			payload[i] = (uint8_t)('a' + (hv_rng32(&rs) % 16u));
	}
	snprintf(dir, sizeof dir, "build/kof_decomp_faults_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("suite_decomp_faults: cannot make a directory under build/\n");
		keng_close(eng);
		return 1;
	}
	for (k = 0; k < sizeof FM / sizeof FM[0]; k++) {
		struct he_w w = { 0 };

		if (!FM[k].build(&w, payload, NPAY)) {
			printf("  SKIP %s: the tool is not here\n", FM[k].name);
			free(w.p);
			continue;
		}
		made++;
		spill_rows(eng, &FM[k], &w);
		read_rows(eng, &FM[k], &w, dir);
		free(w.p);
	}
	CK(made >= 2, "only %u formats could be built", made);
	(void)rmdir(dir);
	keng_close(eng);
	return he_fails ? 1 : 0;
}

int main(void)
{
	struct he_status st = he_child(run_all, NULL, 300);

	if (!st.exited || st.code) {
		printf("suite_decomp_faults: FAILED (exited %d code %d signal %d)\n", st.exited, st.code, st.sig);
		return 1;
	}
	printf("suite_decomp_faults: ok\n");
	return 0;
}
