/*
 * mem_engine - the memory work as the engine shows it, through kscan_bytes / kscan_path_mt.
 *
 *   LAZY VIEW        the normaliser takes its working buffer only when a view can result: an
 *                    object that cannot have one charges nothing (peak_norm 0) and one that can
 *                    charges the object and its two bitmaps, and the view it makes is the one
 *                    the findings of the parent say it should be.
 *   LEDGER           what the normaliser holds is charged and given back (resident is 0 when the
 *                    scan ends), peak_resident covers it, and against a REAL measurement - the
 *                    high-water mark of a child process that scanned a 24 MB object - the
 *                    ledger's peak is within a factor of two (it was 3.6 times short).
 *   ALLOWANCE        for every object the verdict path does not call incomplete, the findings at
 *                    64, 128 and 256 MiB are those of an unlimited run; an object that cannot
 *                    be finished says so.
 *   JOBS             the resident allowance of a parallel walk is shared out (floor 32 MiB) unless
 *                    the host says per-scanner; the share is reset when the walk ends.
 *   TRIM             kscan_trim is idempotent, a no-op inside a callback, safe on different
 *                    scanners from different threads, and changes no finding.
 */

#define _GNU_SOURCE
#include "caps_fix.h"
#include "caps_e2e.h"
#include "mem_fix.h"
#include "asking_db.h"
#include <unistd.h>
#include <sys/wait.h>

static uint8_t img[1u << 20], code[1u << 16];
static uint8_t big[26u << 20];
static kof_engine *zeng;        /* the shipped database: it has the archive openers the test one lacks */

static struct e2e run_with(kof_scanner *sc, const uint8_t *b, uint64_t n, uint64_t resident)
{
	struct kof_scan_option opt;
	struct e2e r;

	memset(&r, 0, sizeof r);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1ull << 40;
	opt.max_resident_bytes = resident;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(sc, b, n, "mem", &opt, e2e_on_object, &r);
	return r;
}

static void lazy_view(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct e2e r;
	uint64_t len;
	const struct kof_stats *st;
	unsigned i, has_view = 0;

	CK(sc != NULL);
	len = mf_noview_elf(img, sizeof img, code);
	r = run_with(sc, img, len, 256u << 20);
	st = kscan_stats(sc);
	CK(r.n >= 1);
	CK(st->peak_norm == 0);                         /* no view possible: nothing was taken */
	for (i = 0; i < r.n; i++)
		has_view |= r.o[i].entry_kind == KOF_ENT_NORMALIZED;
	CK(!has_view);
	kscan_trim(sc, KSCAN_TRIM_CACHES);
	CK(sc->ledger.resident == 0);

	len = mf_view_elf(img, sizeof img, code);
	r = run_with(sc, img, len, 256u << 20);
	st = kscan_stats(sc);
	CK(r.n >= 2);
	CK(st->peak_norm >= len);                       /* the object's size ... */
	CK(st->peak_norm <= len + len / 4u + 16u);      /* ... and a bitmap each for keep and drop */
	CK(st->peak_resident >= st->peak_norm);
	kscan_trim(sc, KSCAN_TRIM_CACHES);              /* the last object's analysis is held until here */
	CK(sc->ledger.resident == 0);                   /* all of it given back */
	has_view = 0;
	for (i = 1; i < r.n; i++)
		if (r.o[i].entry_kind == KOF_ENT_NORMALIZED) {
			has_view = 1;
			CK(e2e_verdict_is(&r.o[i], "Dropper") == e2e_verdict_is(&r.o[0], "Dropper"));
		}
	CK(has_view);
	kscan_free(sc);
}

static long hwm_kb(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char b[4096];
	size_t n;
	char *p;

	if (!f)
		return -1;
	n = fread(b, 1, sizeof b - 1u, f);
	fclose(f);
	b[n] = 0;
	p = strstr(b, "VmHWM:");
	return p ? atol(p + 6) : -1;
}

/* The ledger against reality: a child process scans a 24 MB object whose view the
 * normaliser makes, and says how far its high-water mark rose and what peak_resident was. */
static void ledger_vs_real(void)
{
	int fd[2];
	uint64_t len, rec[2];
	pid_t pid;

	if (pipe(fd))
		return;
	len = mf_view_elf(big, 24u << 20, code);
	len = 24u << 20;                                /* more zero padding: a bigger object, same view */
	pid = fork();
	if (pid == 0) {
		kof_scanner *sc = kscan_new(e2e_eng);
		long before, after;
		struct e2e r;

		before = hwm_kb();
		r = run_with(sc, big, len, 256u << 20);
		after = hwm_kb();
		rec[0] = (uint64_t)(after > before ? after - before : 0) * 1024u;
		rec[1] = kscan_stats(sc)->peak_resident;
		(void)!write(fd[1], rec, sizeof rec);
		_exit(r.n ? 0 : 1);
	}
	close(fd[1]);
	CK(read(fd[0], rec, sizeof rec) == (ssize_t)sizeof rec);
	close(fd[0]);
	{
		int st = 0;

		(void)waitpid(pid, &st, 0);
		CK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	}
	printf("    real high-water rise %.1f MB, ledger peak_resident %.1f MB\n",
	       (double)rec[0] / 1048576.0, (double)rec[1] / 1048576.0);
	/* the working buffer (24 MB) plus the view's copy in the sink is what really rose */
	CK(rec[1] * 2u >= rec[0]);
	CK(rec[1] <= rec[0] * 2u + (8u << 20));
}

static void allowances(void)
{
	static const uint64_t mib[] = { 64, 128, 256 };
	static uint8_t zipb[(3u << 20) + (1u << 16)], data[2u << 20];
	uint64_t zl, vl, k;
	unsigned which, a;

	memset(zipb, 0, sizeof zipb);
	zl = mf_zip(zipb, data, sizeof data);
	for (which = 0; which < 3u; which++) {
		const uint8_t *b;
		uint64_t n;
		kof_scanner *sc;
		struct e2e ref;
		struct mf_sig sref;

		if (which == 0)      { vl = mf_view_elf(img, sizeof img, code); b = img; n = vl; }
		else if (which == 1) { b = zipb; n = zl; }
		else                 { vl = mf_noview_elf(img, sizeof img, code); b = img; n = vl; }
		sc = kscan_new(which == 1 ? zeng : e2e_eng);
		ref = run_with(sc, b, n, 1ull << 40);
		if (which == 1)
			CK(ref.n >= 2);                         /* the entry was opened */           /* unlimited */
		mf_sig_of(&ref, &sref);
		kscan_free(sc);
		CK(sref.incomplete == 0);
		for (a = 0; a < 3u; a++) {
			struct e2e r;
			struct mf_sig s;

			sc = kscan_new(which == 1 ? zeng : e2e_eng);
			r = run_with(sc, b, n, mib[a] << 20);
			mf_sig_of(&r, &s);
			kscan_free(sc);
			if (s.incomplete == 0)
				CK(s.h == sref.h && s.n_obj == sref.n_obj);   /* identical findings */
			else
				printf("    object %u at %llu MiB is reported incomplete (allowed)\n",
				       which, (unsigned long long)mib[a]);
			/* the sizes here are far below 64 MiB: nothing may be cut */
			CK(s.incomplete == 0);
		}
	}
	/* an allowance too small for the object says so: the 24 MB view cannot be held in 8 MiB */
	{
		kof_scanner *sc = kscan_new(e2e_eng);
		struct e2e r;
		struct mf_sig s;

		k = mf_view_elf(big, 24u << 20, code);
		(void)k;
		r = run_with(sc, big, 24u << 20, 8u << 20);
		mf_sig_of(&r, &s);
		CK(s.incomplete > 0);
		CK(kscan_stats(sc)->limit_hits > 0);
		kscan_free(sc);
	}
}

/*
 * THE REBUILT IMAGE HANDED OVER. An ELF whose stub decodes the rest of the file in place, scanned
 * with the interpreter on (--heur 2) under the shipped database: the run's rebuilt image is taken
 * by the child instead of copied into it (kof_stats.emu_adopted), and the object that comes out is
 * the same bytes. The hash is that of the object on the tree before the change (the image was
 * copied then): 33f6485d048dc41a.
 */
static uint64_t fnv(const void *b, uint64_t n)
{
	const uint8_t *p = b;
	uint64_t x = 1469598103934665603ull, i;

	for (i = 0; i < n; i++)
		x = (x ^ p[i]) * 1099511628211ull;
	return x;
}

static uint64_t last_hash, last_len;

static int hash_cb(const char *n, const void *b, uint64_t l, const struct kof_result *r, void *u)
{
	(void)n; (void)r; (void)u;
	last_hash = fnv(b, l);
	last_len = l;
	return 0;
}

static void adopted_image(void)
{
	static uint8_t pay[1u << 19], cd[1u << 20];
	unsigned pn = 0, n = 0, key, k;
	uint64_t len;
	kof_scanner *sc = kscan_new(zeng);
	struct kof_scan_option o;

	for (k = 0; k < 3000u; k++) {
		pay[pn] = 0xbe; put32(pay, pn + 1u, k * 2654435761u); pn += 5;
		pay[pn++] = 0xb8; put32(pay, pn, 39); pn += 4;
		pay[pn++] = 0x0f; pay[pn++] = 0x05;
	}
	pay[pn++] = 0xb8; put32(pay, pn, 60); pn += 4;
	pay[pn++] = 0x31; pay[pn++] = 0xff; pay[pn++] = 0x0f; pay[pn++] = 0x05;
	for (key = 1; key < 256u; key++) {
		int ok = 1;

		for (k = 0; k + 1u < pn; k++) {
			uint8_t a = pay[k] ^ (uint8_t)key, b = pay[k + 1u] ^ (uint8_t)key;

			if ((a == 0x0f && b == 0x05) || (a == 0xcd && b == 0x80))
				ok = 0;
		}
		if (ok)
			break;
	}
	cd[n++] = 0x48; cd[n++] = 0x8d; cd[n++] = 0x35; put32(cd, n, 15); n += 4;
	cd[n++] = 0xb9; put32(cd, n, pn); n += 4;
	cd[n++] = 0x80; cd[n++] = 0x36; cd[n++] = (uint8_t)key;
	cd[n++] = 0x48; cd[n++] = 0xff; cd[n++] = 0xc6;
	cd[n++] = 0xe2; cd[n++] = (uint8_t)-8;
	for (k = 0; k < pn; k++)
		cd[n++] = pay[k] ^ (uint8_t)key;
	len = cf_elf64(img, sizeof img, cd, n);
	memset(&o, 0, sizeof o);
	o.heur_level = 2;
	CK(sc != NULL);
	(void)kscan_bytes(sc, img, len, "stub", &o, hash_cb, NULL);
	CK(kscan_stats(sc)->emu_adopted == 1);
	CK(last_len == 36149u && last_hash == 0x33f6485d048dc41aull);
	/* and again on the same scanner: handed over again, the same bytes */
	(void)kscan_bytes(sc, img, len, "stub", &o, hash_cb, NULL);
	CK(kscan_stats(sc)->emu_adopted == 2);
	CK(last_hash == 0x33f6485d048dc41aull);
	CK(sc->ledger.resident <= (1u << 20));          /* nothing left charged but the last object's own */
	kscan_free(sc);
}

static void jobs(void)
{
	kof_scanner *scs[4];
	struct kof_scan_option opt;
	unsigned i;
	int rc;

	/* the engine's own cap would lower these (mem_cap.c covers that); raised out of the way here */
	CK(keng_set_memory_cap(e2e_eng, 64ull << 30));
	for (i = 0; i < 4u; i++)
		scs[i] = kscan_new(e2e_eng);
	memset(&opt, 0, sizeof opt);
	opt.recurse_dirs = 1;
	opt.max_resident_bytes = 1024u << 20;
	rc = kscan_path_mt(scs, 4, "tests/fixtures", &opt, NULL, NULL);
	CK(rc >= 3);
	for (i = 0; i < 4u; i++) {
		CK(scs[i]->share == 1u);                        /* the walk is over: undivided again */
		if (scs[i]->ledger.resident_max)
			CK(scs[i]->ledger.resident_max == (256ull << 20));   /* 1 GiB / 4 */
	}
	/* the built-in allowance is shared too, and floored */
	opt.max_resident_bytes = 0;
	for (i = 0; i < 4u; i++)
		scs[i]->ledger.resident_max = 0;
	rc = kscan_path_mt(scs, 4, "tests/fixtures", &opt, NULL, NULL);
	CK(rc >= 3);
	for (i = 0; i < 4u; i++)
		if (scs[i]->ledger.resident_max)
			CK(scs[i]->ledger.resident_max == (32ull << 20));    /* 128 MiB / 4 */
	/* a host that already worked its figure out is taken at its word */
	opt.resident_per_scanner = 1;
	opt.max_resident_bytes = 1024u << 20;
	for (i = 0; i < 4u; i++)
		scs[i]->ledger.resident_max = 0;
	rc = kscan_path_mt(scs, 4, "tests/fixtures", &opt, NULL, NULL);
	CK(rc >= 3);
	for (i = 0; i < 4u; i++)
		if (scs[i]->ledger.resident_max)
			CK(scs[i]->ledger.resident_max == (1024ull << 20));
	/* the division itself, with the floor, on one scanner */
	opt.resident_per_scanner = 0;
	opt.max_resident_bytes = 64u << 20;
	scs[0]->share = 8;
	kof_scan_budget(scs[0], 1000, &opt);
	CK(scs[0]->ledger.resident_max == KOF_SHARE_MIN);       /* 8 MiB would be below it */
	opt.max_resident_bytes = 2048u << 20;
	kof_scan_budget(scs[0], 1000, &opt);
	CK(scs[0]->ledger.resident_max == (256ull << 20));
	scs[0]->share = 1;
	kof_scan_budget(scs[0], 1000, &opt);
	CK(scs[0]->ledger.resident_max == (2048ull << 20));
	for (i = 0; i < 4u; i++)
		kscan_free(scs[i]);
	(void)keng_set_memory_cap(e2e_eng, 0);
}

static kof_scanner *cb_sc;
static int cb_busy_seen, cb_views_kept;

static int trim_cb(const char *n, const void *b, uint64_t l, const struct kof_result *r, void *u)
{
	unsigned k, views = 0;

	(void)n; (void)b; (void)l; (void)r; (void)u;
	cb_busy_seen |= cb_sc->busy > 0;
	for (k = 0; k < KOF_TARGET_COUNT; k++)
		views += cb_sc->cache.view[k] != NULL;
	kscan_trim(cb_sc, 0);                           /* inside a scan: nothing is touched */
	for (k = 0; k < KOF_TARGET_COUNT; k++)
		views -= cb_sc->cache.view[k] != NULL;
	cb_views_kept |= views == 0;
	return 0;
}

struct th { kof_scanner *sc; uint64_t h, n; int ok; const uint8_t *b; };

static void *th_main(void *p)
{
	struct th *t = p;
	unsigned i;

	for (i = 0; i < 40u; i++) {
		struct e2e r = run_with(t->sc, t->b, t->n, 128u << 20);
		struct mf_sig s;

		mf_sig_of(&r, &s);
		if (s.h != t->h)
			t->ok = 0;
		kscan_trim(t->sc, i % 3u ? KSCAN_TRIM_CACHES : 0);
	}
	return NULL;
}

static void trimming(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct e2e r0, r1;
	struct mf_sig s0, s1;
	uint64_t len = mf_view_elf(img, sizeof img, code);
	unsigned k, views = 0;
	struct kof_scan_option opt;
	struct th t[4];
	pthread_t id[4];
	static uint8_t bufs[4][1u << 16];

	r0 = run_with(sc, img, len, 256u << 20);
	mf_sig_of(&r0, &s0);
	for (k = 0; k < KOF_TARGET_COUNT; k++)
		views += sc->cache.view[k] != NULL;
	CK(views > 0);                                  /* something is kept between objects */
	kscan_trim(sc, 0);
	for (k = 0, views = 0; k < KOF_TARGET_COUNT; k++)
		views += sc->cache.view[k] != NULL;
	CK(views == 0);
	CK(sc->syms.buf == NULL && sc->match.m.gram == NULL);
	CK(kscan_stats(sc)->scan_trims >= 1);
	kscan_trim(sc, 0);                              /* idempotent */
	kscan_trim(sc, KSCAN_TRIM_CACHES);
	kscan_trim(sc, KSCAN_TRIM_HEAP);
	kscan_trim(NULL, 0);
	r1 = run_with(sc, img, len, 256u << 20);        /* made again on demand, same answer */
	mf_sig_of(&r1, &s1);
	CK(s0.h == s1.h && s0.n_obj == s1.n_obj);

	/* inside a callback: refused */
	memset(&opt, 0, sizeof opt);
	cb_sc = sc;
	(void)kscan_bytes(sc, img, len, "cb", &opt, trim_cb, NULL);
	CK(cb_busy_seen);
	CK(cb_views_kept);

	/* different scanners, different threads, trimming while others scan */
	for (k = 0; k < 4u; k++) {
		uint8_t *b = bufs[k];
		uint64_t n;

		memset(b, 0, sizeof bufs[k]);
		{
			static uint8_t c2[1u << 14];
			unsigned m = cf_stager64(c2, 0), i;

			n = cf_elf64(b, sizeof bufs[k], c2, m);
			for (i = 0; i < 200u * (k + 1u); i++)
				b[n++] = (uint8_t)(1u + (i * 7u + k) % 250u);
		}
		t[k].sc = kscan_new(e2e_eng);
		t[k].b = b;
		t[k].n = n;
		t[k].ok = 1;
		{
			struct e2e r = run_with(t[k].sc, b, n, 128u << 20);
			struct mf_sig s;

			mf_sig_of(&r, &s);
			t[k].h = s.h;
		}
	}
	for (k = 0; k < 4u; k++)
		pthread_create(&id[k], NULL, th_main, &t[k]);
	for (k = 0; k < 4u; k++) {
		pthread_join(id[k], NULL);
		CK(t[k].ok);
		kscan_free(t[k].sc);
	}
	kscan_free(sc);
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("mem engine: no database\n");
		return 1;
	}
	zeng = keng_open(ad_db_asking());
	if (!zeng) {
		printf("mem engine: no shipped database\n");
		return 1;
	}
	lazy_view();
	ledger_vs_real();
	allowances();
	adopted_image();
	jobs();
	trimming();
	printf("mem engine: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
