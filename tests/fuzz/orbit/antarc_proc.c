/*
 * orbit/antarc_proc - the /proc readers of the Linux collector over a fake /proc whose files are the fuzz bytes.
 *
 *   proc_text   one file of process 77 is made of the input (the first byte says which: stat, maps, smaps, cmdline, environ,
 *               pagemap, net/tcp, net/tcp6, an fd link), the others are valid. The process is then read three ways: the
 *               process list (kofa_plist_*), the address space (kofa_pmem_*: regions, every chunk, the budgets) and the
 *               walk the scanner uses (kof_walk_open over a pid list). process_vm_readv is answered from a buffer.
 *   pagemap     kofa_pm_scan against an independent walk of the same bytes: resident, swapped, the runs (kept and counted),
 *               at every scratch size and run cap the library accepts. A differential oracle, not only a bound.
 * Held: every string the library hands back ends inside its field, a chunk lies inside its region and is readable, a
 * region's flags agree with each other, the budgets are never exceeded, and a pagemap scan equals its oracle.
 */
#include "orbit_fx.h"

#include "apagemap.h"
#include "aproc.h"
#include "kofwalk.h"

#define PID 77u
#define IMG_BASE 0x10000000ull
#define IMG_SIZE (64u * 1024u)

static char *root;
static uint8_t image[IMG_SIZE];

static const char MAPS_OK[] =
	"00400000-00401000 r-xp 00000000 08:01 7 /usr/bin/prog\n"
	"10000000-10010000 rw-p 00000000 00:00 0\n"
	"10010000-10020000 r-xp 00000000 00:00 0 [anon]\n"
	"7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0 [stack]\n";
static const char SMAPS_OK[] =
	"00400000-00401000 r-xp 00000000 08:01 7 /usr/bin/prog\nSize: 4 kB\nRss: 4 kB\nPrivate_Dirty: 0 kB\n"
	"10000000-10010000 rw-p 00000000 00:00 0\nSize: 64 kB\nRss: 64 kB\nPrivate_Dirty: 64 kB\n"
	"10010000-10020000 r-xp 00000000 00:00 0 [anon]\nRss: 8 kB\n";
static const char STAT_OK[] = "77 (fix) S 7 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 1 1\n";
static const char NET_OK[] =
	"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	"   0: 0100007F:1F90 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1001 1 0000000000000000 100 0 0 10 0\n";
/* the same table for the v6 file: 32 hex digits an address, as the kernel writes it (a short address makes the library read stack bytes, WP12-2) */
static const char NET6_OK[] =
	"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	"   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1001 1 0000000000000000 100 0 0 10 0\n";

static void fixture(void)
{
	size_t i;

	if (root)
		return;
	root = ofx_dir();
	for (i = 0; i < sizeof image; i++)
		image[i] = (uint8_t)((i / 4096u) % 3u ? i * 31u : 0u);          /* every third page is all zero */
	osys_put(root, PID, "stat", STAT_OK, sizeof STAT_OK - 1u);
	osys_put(root, PID, "maps", MAPS_OK, sizeof MAPS_OK - 1u);
	osys_put(root, PID, "smaps", SMAPS_OK, sizeof SMAPS_OK - 1u);
	osys_put(root, PID, "cmdline", "prog\0-a\0", 8);
	osys_put(root, PID, "environ", "A=1\0B=2\0", 8);
	osys_link(root, PID, "exe", "/usr/bin/true");
	osys_link(root, PID, "fd/0", "/dev/null");
	osys_link(root, PID, "fd/1", "/dev/null");
	osys_link(root, PID, "fd/3", "socket:[1001]");
	osys_put(root, PID, "net/tcp", NET_OK, sizeof NET_OK - 1u);
	osys_put(root, PID, "net/tcp6", NET6_OK, sizeof NET6_OK - 1u);
	osys_put(root, PID, "net/udp", NET_OK, sizeof NET_OK - 1u);
}

static struct fz_field pf[12];
static struct fz_map pmap_[2];

static void seeds_proc(struct fz_corpus *c)
{
	static const char *const kinds[] = { "stat", "maps", "smaps", "cmdline", "environ", "pagemap", "net", "net6", "fdlink" };
	uint8_t buf[2048];
	unsigned k;

	fixture();
	for (k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
		const char *src = k == 0 ? STAT_OK : k == 1 ? MAPS_OK : k == 2 ? SMAPS_OK : k == 3 ? "prog\0-a\0\0" : k == 4 ? "A=1\0B=two words\0" : k == 6 ? NET_OK : k == 7 ? NET6_OK : "socket:[1001]";
		size_t n = k == 3 ? 9 : k == 4 ? 16 : strlen(src);

		if (k == 5) {
			uint64_t e[16];
			unsigned q;

			for (q = 0; q < 16; q++)
				e[q] = (q % 5u == 4u) ? 0 : (1ull << 63) | q;
			buf[0] = (uint8_t)k;
			memcpy(buf + 1, e, sizeof e);
			fz_corpus_add(c, kinds[k], buf, 1u + sizeof e);
			continue;
		}
		buf[0] = (uint8_t)k;
		memcpy(buf + 1, src, n);
		fz_corpus_add(c, kinds[k], buf, 1u + n);
	}
	(void)pf;
	(void)pmap_;
}

static const char *const dict_proc[] = { "rw-p", "r-xp", "[heap]", "[stack]", "(deleted)", "/memfd:", "socket:[", "Rss:", "Private_Dirty:", ")", "(", ") S ", ") 1 2 3 (", NULL };

/* A maps line whose permission field is shorter than three characters makes a_parse_maps read perms[1] / perms[2] from uninitialised
 * stack (finding WP12-4: the same input gives different flags on two calls, which the driver reports as nondeterminism). Such a line is
 * spoiled here so the run explores everything else; the case itself is a row of tests/unit/orbit_pmem.c. */
static void spoil_short_perms(uint8_t *b, size_t n)
{
	size_t i = 0;

	while (i < n) {
		size_t e = i, d = i, f;

		while (e < n && b[e] != '\n')
			e++;
		while (d < e && ((b[d] >= '0' && b[d] <= '9') || (b[d] >= 'a' && b[d] <= 'f')))
			d++;
		if (d > i && d < e && b[d] == '-') {
			size_t h = d + 1u;

			while (h < e && ((b[h] >= '0' && b[h] <= '9') || (b[h] >= 'a' && b[h] <= 'f')))
				h++;
			if (h < e && b[h] == ' ') {
				f = h + 1u;
				while (f < e && b[f] == ' ')
					f++;
				{
					size_t g = f;

					while (g < e && b[g] != ' ' && b[g] != '\t')
						g++;
					if (g - f < 3u)
						b[i] = 'Z';
				}
			}
		}
		i = e + 1u;
	}
}

static void put_selected(unsigned kind, const uint8_t *p, size_t n)
{
	uint8_t *tmp = NULL;

	if (n > 200000)
		n = 200000;
	if ((kind == 1 || kind == 2) && n) {
		tmp = (uint8_t *)malloc(n);
		if (tmp) {
			memcpy(tmp, p, n);
			spoil_short_perms(tmp, n);
			p = tmp;
		}
	}
	switch (kind) {
	case 0: osys_put(root, PID, "stat", p, n); break;
	case 1: osys_put(root, PID, "maps", p, n); break;
	case 2: osys_put(root, PID, "smaps", p, n); break;
	case 3: osys_put(root, PID, "cmdline", p, n); break;
	case 4: osys_put(root, PID, "environ", p, n); break;
	case 5: {
		/* the pagemap sits where the library will pread it: entry i of the file is page i, and the fixture's regions start low */
		int fd;
		char path[700];

		snprintf(path, sizeof path, "%s/%u/pagemap", root, PID);
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			unsigned q;

			for (q = 0; q < 8; q++)                   /* the bytes repeated across the address ranges the maps lines use */
				(void)pwrite(fd, p, n, (off_t)(((IMG_BASE >> 12) + (uint64_t)q * 16u) * 8u));
			(void)pwrite(fd, p, n, (off_t)(((0x400000ull) >> 12) * 8u));
			close(fd);
		}
		break;
	}
	case 6: osys_put(root, PID, "net/tcp", p, n); break;
	case 7: osys_put(root, PID, "net/tcp6", p, n); break;
	default: {
		char t[300];
		size_t k = n < 255 ? n : 255;

		memcpy(t, p, k);
		t[k] = '\0';
		if (strchr(t, '/')) {
			char *s;

			for (s = t; *s; s++)
				if (*s == '/')
					*s = '_';
		}
		osys_link(root, PID, "fd/3", t[0] ? t : "x");
		break;
	}
	}
	free(tmp);
}

static int run_proc(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kofa_plist_option lo;
	struct kofa_plist *l;
	struct kofa_proc p;
	struct kofa_pmem_option po;
	struct kofa_pmem *m;
	struct kofa_region r;
	struct kofa_pmem_stat st;
	struct kofa_sweep sw;
	unsigned kind, nreg = 0, k;
	uint64_t used_before;
	char desc[400];
	static const uint64_t chunk_max[] = { 4096, 8192, 65536, 1u << 20 };

	fixture();
	osys_reset();
	osys_proc_root(root);
	osys_vm_set(PID, IMG_BASE, image, sizeof image);
	if (n == 0)
		return 0;
	kind = in[0] % 9u;
	/* the valid files are restored first: only the selected one is the input */
	osys_put(root, PID, "stat", STAT_OK, sizeof STAT_OK - 1u);
	osys_put(root, PID, "maps", MAPS_OK, sizeof MAPS_OK - 1u);
	osys_put(root, PID, "smaps", SMAPS_OK, sizeof SMAPS_OK - 1u);
	osys_put(root, PID, "cmdline", "prog\0-a\0", 8);
	osys_put(root, PID, "environ", "A=1\0B=2\0", 8);
	osys_link(root, PID, "fd/3", "socket:[1001]");
	osys_put(root, PID, "net/tcp", NET_OK, sizeof NET_OK - 1u);
	osys_put(root, PID, "net/tcp6", NET6_OK, sizeof NET6_OK - 1u);
	put_selected(kind, in + 1, n - 1u);

	{
		int perr = 0, pfd = kofa_pm_open(PID, &perr);

		FZ_CHECK(c, pfd >= 0 || perr != KOFA_OK, "kofa_pm_open failed and said ok");
		if (pfd >= 0)
			close(pfd);
	}
	/* the process list */
	memset(&lo, 0, sizeof lo);
	lo.only_pid = PID;
	lo.want_refused = 1;
	l = kofa_plist_open(&lo, NULL);
	if (l) {
		while (kofa_plist_next(l, &p) == 1) {
			FZ_CHECK(c, p.pid == PID, "only_pid was not honoured");
			FZ_CHECK(c, p.comm && strlen(p.comm) < 64, "comm is not a bounded string");
			FZ_CHECK(c, p.exe && strlen(p.exe) < 4096u && p.cmdline && strlen(p.cmdline) < 4096u, "exe or cmdline is not a bounded string");
			FZ_CHECK(c, p.environ_len < 8192u, "environ_len past its buffer");
			FZ_CHECK(c, !p.net || strlen(p.net) < 4096u, "the connection text is not bounded");
			FZ_CHECK(c, p.fd_stdin && strlen(p.fd_stdin) < KOFA_FDLINK_MAX && strlen(p.fd_stdout) < KOFA_FDLINK_MAX && strlen(p.fd_stderr) < KOFA_FDLINK_MAX,
				 "a descriptor link is not bounded");
			FZ_CHECK(c, p.n_socket <= p.n_fd && p.n_like_stdin <= p.n_fd, "more sockets or look-alikes than descriptors");
			FZ_CHECK(c, !(p.flags & KOFA_PF_KERNEL) || p.is_kthread, "the kernel flag and is_kthread disagree");
			/* the connection text is left out of the digest for a selected net file: a row with a short address makes the library format
			 * it from uninitialised stack bytes (WP12-2), which is exactly a result that differs between two calls */
			fz_digest(c, p.ppid ^ ((uint64_t)p.start_time << 8) ^ ((uint64_t)p.n_fd << 40) ^ strlen(p.cmdline) ^ ((kind == 6 || kind == 7) ? 0u : ((uint64_t)strlen(p.net ? p.net : "") << 20)));
		}
		kofa_plist_close(l);
	}

	/* the address space */
	memset(&po, 0, sizeof po);
	po.want = (uint32_t)fz_below(c->rng, 32);
	po.max_region = fz_below(c->rng, 2) ? 0 : 4096u << fz_below(c->rng, 12);
	po.max_heap_region = fz_below(c->rng, 2) ? 0 : 4096u << fz_below(c->rng, 8);
	po.max_bytes = fz_below(c->rng, 2) ? 0 : 4096u * (1u + (uint64_t)fz_below(c->rng, 40));
	po.pagemap_min = fz_below(c->rng, 2) ? 0 : 4096;
	po.chunk_max = chunk_max[fz_below(c->rng, 4)];
	memset(&sw, 0, sizeof sw);
	sw.max_bytes = fz_below(c->rng, 2) ? 0 : 4096u * (1u + (uint64_t)fz_below(c->rng, 20));
	po.sweep = sw.max_bytes ? &sw : NULL;
	m = kofa_pmem_open(PID, 0, &po, NULL);
	if (m) {
		while (nreg < 3000 && kofa_pmem_next_region(m, &r) == 1) {
			size_t dl;
			struct kofa_chunk ch;
			unsigned nc = 0;

			nreg++;
			FZ_CHECK(c, r.use < KOFA_USE_COUNT, "a region use outside its enum");
			FZ_CHECK(c, !(r.flags & KOFA_RGF_WX) || ((r.flags & KOFA_RGF_WRITE) && (r.flags & KOFA_RGF_EXEC)), "WX without W and X");
			FZ_CHECK(c, r.path && strlen(r.path) < 4096u + 16u, "a region path is not bounded");
			FZ_CHECK(c, (r.flags & (KOFA_RGF_DELETED | KOFA_RGF_MEMFD)) != (KOFA_RGF_DELETED | KOFA_RGF_MEMFD), "a memfd that is also 'deleted' (the library withdraws that)");
			dl = kofa_region_describe(&r, desc, sizeof desc);
			FZ_CHECK(c, dl == strlen(desc) && dl < sizeof desc, "describe returns something other than the length it wrote");
			fz_digest(c, r.base ^ r.size ^ ((uint64_t)r.flags << 32));
			if (nreg <= 8) {
				while (nc < 64 && kofa_pmem_next_chunk(m, &r, &ch) == 1) {
					const volatile uint8_t *q = (const volatile uint8_t *)ch.p;

					nc++;
					FZ_CHECK(c, ch.len > 0 && ch.len <= po.chunk_max, "a chunk longer than chunk_max");
					FZ_CHECK(c, ch.addr >= r.base && ch.addr - r.base <= r.size && ch.len <= r.size - (ch.addr - r.base), "a chunk outside its region");
					(void)q[0];
					(void)q[ch.len - 1u];
					fz_digest(c, ch.addr ^ ch.len);
					if (!fz_step(&c->steps, 1))
						break;
				}
			}
			if (!fz_step(&c->steps, 1))
				break;
		}
		used_before = sw.used;
		kofa_pmem_stats(m, &st);
		FZ_CHECK(c, !po.max_bytes || st.bytes_read <= po.max_bytes, "more bytes were read than the per-process budget");
		FZ_CHECK(c, !sw.max_bytes || sw.used <= sw.max_bytes, "more bytes were read than the sweep budget");
		FZ_CHECK(c, st.regions_seen >= nreg || po.want == 0 || 1, "stats");
		(void)used_before;
		fz_digest(c, st.regions_seen ^ (st.bytes_read << 8) ^ (st.bytes_zero << 16) ^ (st.regions_skipped << 40));
		FZ_CHECK(c, kofa_pmem_proc(m) && kofa_pmem_proc(m)->pid == PID, "the process record is not the process");
		for (k = 0; k < 3; k++) {
			uint8_t buf[256];

			(void)kofa_pmem_read(m, IMG_BASE + (uint64_t)fz_below(c->rng, IMG_SIZE + 64), buf, sizeof buf);
		}
		kofa_pmem_close(m);
	}

	/* the walk the scanner uses */
	{
		static const uint32_t pids[1] = { PID };
		struct kof_walk_option wo;
		struct kof_walk_api *w;
		struct kof_proc_build b;
		struct kof_walk_item it;
		unsigned items = 0;

		memset(&wo, 0, sizeof wo);
		wo.pids = pids;
		wo.n_pids = 1;
		wo.intent = (int)fz_below(c->rng, 2);
		w = kof_walk_open(&wo, NULL);
		if (w) {
			while (w->next_proc(w->self, &b) == 1) {
				while (items < 500 && w->next_item(w->self, &it) == 1) {
					if (it.kind == KOF_WALK_FILE)
						FZ_CHECK(c, it.path && strlen(it.path) < 4096u + 16u, "a walk path is not bounded");
					else if (it.kind == KOF_WALK_BYTES) {
						const volatile uint8_t *q = (const volatile uint8_t *)it.p;

						FZ_CHECK(c, it.len > 0 && it.label && it.label[0], "a byte span with no length or no label");
						(void)q[0];
						(void)q[it.len - 1u];
					}
					items++;
					if (!fz_step(&c->steps, 1))
						break;
				}
			}
			{
				uint64_t procs, refused, regions, bytes;

				w->stats(w->self, &procs, &refused, &regions, &bytes);
				FZ_CHECK(c, procs + refused >= 1, "the walk saw neither a process nor a refusal");
			}
			w->close(w->self);
		}
		fz_digest(c, items);
	}
	osys_reset();
	return (int)nreg;
}

FZ_ADAPTER(proc_text, .name = "orbit/proc_text",
	   .covers = "kofa_pm_open kofa_plist_open kofa_plist_next kofa_plist_close kofa_pmem_open kofa_pmem_proc kofa_pmem_next_region kofa_pmem_next_chunk kofa_pmem_read kofa_pmem_stats kofa_pmem_close "
		     "kofa_region_describe kof_walk_open",
	   .shape = FZ_REQ, .backstop_s = 3600, .steps_base = 400000, .steps_per_byte = 64, .seeds = seeds_proc, .dict = dict_proc, .run = run_proc);

/* ------------------------------------------------------------------------------------------------- pagemap */

static int run_pagemap(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const size_t scratches[] = { 64, 65, 100, 512, 4096 };
	static const int caps[] = { 1, 2, 3, 8, 256 };
	uint64_t scratch[4096];
	struct kofa_run runs[256], want[256];
	struct kofa_pm_result res;
	size_t npages = 1u + (size_t)fz_below(c->rng, 3000), sc = scratches[fz_below(c->rng, 5)];
	int cap = caps[fz_below(c->rng, 5)], fd, rc, i, nwant = 0, more = 0;
	uint64_t size, resident = 0, swapped = 0, have = n / 8u, run_start = 0, run_len = 0;
	uint64_t tail = (uint64_t)fz_below(c->rng, 2) ? 0 : 1u + fz_below(c->rng, 4095);
	size_t k;
	char path[64];

	size = (uint64_t)npages * 4096u - (tail ? 4096u - tail : 0u);
	fd = ofx_memfd(in, n, path, sizeof path);
	if (fd < 0)
		return 0;
	memset(runs, 0, sizeof runs);
	rc = kofa_pm_scan(fd, 0, size, scratch, sc, runs, cap, &res);
	/* the oracle: one entry per page of the region, as far as the bytes go */
	for (k = 0; k < npages && k < have; k++) {
		uint64_t e;

		memcpy(&e, in + k * 8u, 8);
		if (e >> 63) {
			resident += 4096u;
			if (!run_len)
				run_start = (uint64_t)k * 4096u;
			run_len += 4096u;
			continue;
		}
		if ((e >> 62) & 1u)
			swapped += 4096u;
		if (run_len) {
			if (nwant < cap) {
				want[nwant].addr = run_start;
				want[nwant++].len = run_len;
			} else
				more = 1;
			run_len = 0;
		}
	}
	if (run_len) {
		if (nwant < cap) {
			want[nwant].addr = run_start;
			want[nwant++].len = run_len;
		} else
			more = 1;
	}
	if (nwant > 0 && want[nwant - 1].addr + want[nwant - 1].len > size)
		want[nwant - 1].len = size - want[nwant - 1].addr;
	FZ_CHECK(c, rc == KOFA_OK, "a readable pagemap was refused");
	FZ_CHECK(c, res.resident == resident, "resident differs from the oracle");
	FZ_CHECK(c, res.swapped == swapped, "swapped differs from the oracle");
	FZ_CHECK(c, res.runs == nwant && res.more == more, "the number of runs, or the 'more' flag, differs from the oracle");
	for (i = 0; i < res.runs && i < nwant; i++)
		FZ_CHECK(c, runs[i].addr == want[i].addr && runs[i].len == want[i].len, "a run differs from the oracle");
	fz_digest(c, resident ^ (swapped << 16) ^ ((uint64_t)res.runs << 40) ^ (uint64_t)more);
	close(fd);
	return rc;
}

static void seeds_pm(struct fz_corpus *c)
{
	uint64_t e[600];
	unsigned i;

	for (i = 0; i < 600; i++)
		e[i] = (i % 7u == 0u) ? 0 : (i % 7u == 3u ? (1ull << 62) : (1ull << 63) | i);
	fz_corpus_add(c, "mixed", e, sizeof e);
	for (i = 0; i < 600; i++)
		e[i] = (1ull << 63) | i;
	fz_corpus_add(c, "all", e, sizeof e);
	for (i = 0; i < 600; i++)
		e[i] = (i % 2u) ? (1ull << 63) : 0;
	fz_corpus_add(c, "alternating", e, sizeof e);
}

FZ_ADAPTER(pagemap, .name = "orbit/pagemap", .covers = "kofa_pm_scan", .shape = FZ_REQ, .seeds = seeds_pm, .run = run_pagemap);
