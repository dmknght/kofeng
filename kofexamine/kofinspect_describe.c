#define _GNU_SOURCE

/*
 * kofinspect_describe.c - describing one collected event as lines, a region's
 * entropy, and what built an object (.NET, toolchain). Split from kofinspect.c by
 * job, no logic changed; see kofinspect.h for the line type.
 */

#include "kofinspect_private.h"

/* ---- describing one collected event ------------------------------------- */

/* The attribute, or nothing. One helper so every use below reads the same and
 * a NULL style cannot be forgotten at one of them. */
static const char *sty(const char *a) { return a ? a : ""; }

void kof_inspect_event_log(const struct kofevt_log_hdr *h,
			   uint64_t events, uint64_t records,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user)
{
	char line[256];

	if (!h || !out)
		return;
	snprintf(line, sizeof line, "  %s%-11s%s%s/%s",
		 sty(st ? st->id : NULL), "collected", sty(st ? st->off : NULL),
		 kof_evt_platform_name((uint8_t)h->platform),
		 kof_evt_arch_name((uint8_t)h->arch));
	out(user, line);

	/*
	 * NAMED FOR THE COMPONENT, NOT THE LIBRARY.
	 *
	 * "Windows watcher" is what collected this; libkoforbit/grille is the library
	 * it happens to be built from, and a reader of a log has no reason to
	 * know that name. The two are separable on purpose - the collector
	 * ships and versions on its own - so the log says which collector, and
	 * its version says which contract its records follow.
	 *
	 * A version of zero is a log written before collectors carried one. It
	 * is left off rather than shown as "0.0", which would read as a real
	 * answer.
	 */
	if (h->src_major || h->src_minor)
		snprintf(line, sizeof line, "  %s%-11s%s%s %u.%u  build %lu",
			 sty(st ? st->id : NULL), "collector",
			 sty(st ? st->off : NULL),
			 h->platform == KOF_PLAT_WINDOWS ? "Windows watcher"
			 : h->platform == KOF_PLAT_LINUX ? "Linux watcher"
							 : "watcher",
			 (unsigned)h->src_major, (unsigned)h->src_minor,
			 (unsigned long)h->build);
	else
		snprintf(line, sizeof line, "  %s%-11s%s%s  build %lu",
			 sty(st ? st->id : NULL), "collector",
			 sty(st ? st->off : NULL),
			 h->platform == KOF_PLAT_WINDOWS ? "Windows watcher"
			 : h->platform == KOF_PLAT_LINUX ? "Linux watcher"
							 : "watcher",
			 (unsigned long)h->build);
	out(user, line);

	/*
	 * BOTH NUMBERS, because they are different questions and the gap
	 * between them is a fact. A submission split over nine continuations
	 * is ten records and one event; a reader given only one of those two
	 * cannot tell a busy log from a chatty one.
	 */
	snprintf(line, sizeof line, "  %s%-11s%s%llu",
		 sty(st ? st->id : NULL), "events", sty(st ? st->off : NULL),
		 (unsigned long long)events);
	out(user, line);
	snprintf(line, sizeof line, "  %s%-11s%s%llu",
		 sty(st ? st->id : NULL), "records", sty(st ? st->off : NULL),
		 (unsigned long long)records);
	out(user, line);

	if (h->root_pid) {
		snprintf(line, sizeof line, "  %s%-11s%s%lu",
			 sty(st ? st->id : NULL), "traced pid",
			 sty(st ? st->off : NULL),
			 (unsigned long)h->root_pid);
		out(user, line);
	}
}

void kof_inspect_event(const struct kof_evt *e,
		       const struct kof_inspect_style *st,
		       kof_inspect_line out, void *user)
{
	char pend[256], line[512];
	unsigned k;
	int have_pend = 0;

	if (!e || !out)
		return;
	pend[0] = '\0';

	for (k = 0; ; k++) {
		char nm[32], vl[256], one[256];
		uint16_t fo = 0, fl = 0;

		if (!kof_evt_field(e, k, nm, sizeof nm, vl, sizeof vl))
			break;
		(void)kof_evt_field_extent(e, k, &fo, &fl);

		if (!fl) {
			/* A flag row, alone on its line - see the header. */
			if (have_pend) {
				out(user, pend);
				have_pend = 0;
			}
			snprintf(line, sizeof line, "       %s%-11s%.100s%s",
				 sty(st ? st->warn : NULL), nm, vl,
				 sty(st ? st->off : NULL));
			out(user, line);
			continue;
		}
		snprintf(one, sizeof one, "  %s%04X%s %s%-10s%s%-24.24s",
			 sty(st ? st->loc : NULL), (unsigned)fo,
			 sty(st ? st->off : NULL),
			 sty(st ? st->id : NULL), nm,
			 sty(st ? st->off : NULL), vl);
		if (!have_pend) {
			snprintf(pend, sizeof pend, "%s", one);
			have_pend = 1;
		} else {
			snprintf(line, sizeof line, "%s   %s", pend, one);
			out(user, line);
			have_pend = 0;
		}
	}
	if (have_pend)
		out(user, pend);
}

/* ---- what built an object ------------------------------------------------ */

uint32_t kof_inspect_region_entropy(const struct kof_obj_ctx *ctx,
				    kof_buf bytes, uint32_t mask)
{
	/*
	 * Static, and the reason is the size: KOF_SCAN_MAX_EXTENTS ranges is
	 * 64KB, which is more than an interactive tool should put on the stack
	 * and more than is worth allocating per row. kofexamine's own region
	 * loop already keeps one of these for the same reason.
	 *
	 * It is safe here because the callers are the two tools, both of which
	 * draw on one thread. A library that grew a threaded caller would have
	 * to take the buffer from it instead.
	 */
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	static uint32_t hist[256];
	uint64_t total = 0;
	uint32_t n, i;

	if (!ctx || !ctx->resolve_scan || !bytes.p || !bytes.n)
		return 0;
	n = ctx->resolve_scan(ctx, mask, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	memset(hist, 0, sizeof hist);
	for (i = 0; i < n; i++) {
		uint64_t off = ext[i].off, len = ext[i].len, k;

		if (off >= bytes.n)
			continue;
		if (len > bytes.n - off)
			len = bytes.n - off;
		for (k = 0; k < len; k++)
			hist[bytes.p[off + k]]++;
		total += len;
	}
	return kentropy_hist(hist, total);
}

/* One heap row, or nothing when the heap is absent. */
static void clr_row(const struct kof_inspect_style *st, kof_inspect_line out,
		    void *user, const char *name,
		    const struct kgenome_clr_stream *s)
{
	char line[256];

	if (!s->len)
		return;
	snprintf(line, sizeof line, "  %s%-11s %s0x%llx  %llu byte(s)",
		 sty(st ? st->id : NULL), name, sty(st ? st->off : NULL),
		 (unsigned long long)s->off, (unsigned long long)s->len);
	out(user, line);
}

void kof_inspect_dotnet(const struct kof_obj_ctx *ctx, const void *info,
			const struct kof_inspect_style *st,
			kof_inspect_line out, void *user)
{
	const struct kgenome_pe_info *p;
	const struct kgenome_clr_meta *m;
	char line[256];
	unsigned i;

	if (!ctx || !info || !out || ctx->format != KOF_FMT_PE)
		return;
	p = info;
	m = &p->clr;
	if (!kgenome_clr_present(m))
		return;

	snprintf(line, sizeof line,
		 "  %s%-11s %s0x%llx  %u stream(s)%s",
		 sty(st ? st->id : NULL), "metadata", sty(st ? st->off : NULL),
		 (unsigned long long)m->root_off, (unsigned)m->streams_read,
		 m->streams_read < m->streams ? "  (fewer than declared)" : "");
	out(user, line);

	clr_row(st, out, user, "#~", &m->tables);
	clr_row(st, out, user, "#Strings", &m->strings);
	clr_row(st, out, user, "#US", &m->us);
	clr_row(st, out, user, "#Blob", &m->blob);
	clr_row(st, out, user, "#GUID", &m->guid);

	if (m->res_len) {
		snprintf(line, sizeof line,
			 "  %s%-11s %s0x%llx  %llu byte(s)",
			 sty(st ? st->id : NULL), "resources",
			 sty(st ? st->off : NULL),
			 (unsigned long long)m->res_off,
			 (unsigned long long)m->res_len);
		out(user, line);
	}

	/*
	 * The anomalies, spelled out rather than as a hex word. They are the
	 * difference between "this heap is empty" and "this heap is somewhere
	 * this object does not reach", and a reader cannot tell those apart
	 * from the rows above.
	 */
	for (i = 0; i < KGENOME_CLR_ANOM_COUNT; i++) {
		if (!(m->anomalies & (1u << i)))
			continue;
		snprintf(line, sizeof line, "  %s%-11s %s%s",
			 sty(st ? st->warn : NULL), "", sty(st ? st->warn : NULL),
			 kgenome_clr_anomaly_name(i));
		out(user, line);
	}
}

void kof_inspect_toolchain(const struct kof_obj_ctx *ctx, const void *info,
			   kof_buf bytes,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user)
{
	char line[256];

	if (!ctx || !info || !out)
		return;

	if (ctx->format == KOF_FMT_PE) {
		const struct kgenome_pe_info *p = info;

		/*
		 * NOT A CLAIM: the runtime needs the CLI header to load the
		 * image at all, so an image carrying one IS managed whatever
		 * else it says. It also changes what every other row means -
		 * the entry point is a token rather than code, and the text
		 * section holds IL - which is worth knowing before reaching
		 * for a disassembler.
		 */
		if (p->clr_len) {
			snprintf(line, sizeof line,
				 "  %s%-11s %s.NET  runtime %u.%u  metadata %s%s",
				 sty(st ? st->id : NULL), "compiler",
				 sty(st ? st->off : NULL),
				 (unsigned)p->clr_major, (unsigned)p->clr_minor,
				 p->clr_version[0] ? p->clr_version : "?",
				 (p->clr_flags & 1u) ? "  IL only" : "");
			out(user, line);
		}
		/*
		 * The linker's own two bytes. 14.x is a modern MSVC, 6.x an old
		 * one, 2.x the GNU linker, and .NET assemblies conventionally
		 * write 8.0 or 48.0.
		 *
		 * NOTHING VERIFIES THEM and a packer may write anything there -
		 * which is said here, in the code, and not on the row: a caveat
		 * printed beside every value is one nobody reads twice.
		 */
		if (p->linker_major || p->linker_minor) {
			snprintf(line, sizeof line, "  %s%-11s %s%u.%u",
				 sty(st ? st->id : NULL), "linker",
				 sty(st ? st->off : NULL),
				 (unsigned)p->linker_major,
				 (unsigned)p->linker_minor);
			out(user, line);
		}
		return;
	}

	if (ctx->format == KOF_FMT_ELF) {
		const struct kgenome_elf_info *e = info;
		uint32_t i;
		int interp = 0;

		/*
		 * STATIC OR DYNAMIC, from the one structure that decides it: a
		 * PT_INTERP segment names the loader an image needs, and an
		 * image with no interpreter is one nothing has to load for it.
		 */
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			if (e->seg[i].type == 3u) {   /* PT_INTERP */
				interp = 1;
				break;
			}
		snprintf(line, sizeof line, "  %s%-11s %s%s",
			 sty(st ? st->id : NULL), "linking",
			 sty(st ? st->off : NULL),
			 interp ? "dynamic" : "static");
		out(user, line);

		/*
		 * The compiler's own stamp, which GCC and clang both write into
		 * .comment and neither is obliged to. Absent is common and says
		 * nothing - a stripped binary has none - so the row is left off
		 * rather than reported as unknown.
		 */
		for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			char txt[80];
			uint64_t off, len, k, w = 0;

			if (strcmp(e->sec[i].name, ".comment"))
				continue;
			off = e->sec[i].file_off;
			len = e->sec[i].file_size;
			if (!bytes.p || !len || off >= bytes.n)
				break;
			if (len > bytes.n - off)
				len = bytes.n - off;
			if (len > sizeof txt - 1u)
				len = sizeof txt - 1u;
			/* NUL separated; the first entry is what built the
			 * object, the rest are the linker's and its inputs'. */
			for (k = 0; k < len; k++) {
				char c = (char)bytes.p[off + k];

				if (!c)
					break;
				if (c >= 0x20 && c < 0x7f)
					txt[w++] = c;
			}
			txt[w] = '\0';
			if (w) {
				snprintf(line, sizeof line, "  %s%-11s %s%s",
					 sty(st ? st->id : NULL), "compiler",
					 sty(st ? st->off : NULL), txt);
				out(user, line);
			}
			break;
		}
	}
}

void kof_inspect_event_verbs(const uint64_t *count, uint32_t keep,
			     const struct kof_inspect_style *st,
			     kof_inspect_line out, void *user)
{
	char pend[160], line[320];
	int vb, have_pend = 0;

	if (!count || !out)
		return;
	pend[0] = '\0';
	for (vb = 1; vb < 32; vb++) {
		char one[160];

		if (!count[vb])
			continue;
		snprintf(one, sizeof one, "  %s%-11s %s%-10llu%s",
			 sty(st ? st->id : NULL),
			 kof_evt_verb_name((uint16_t)vb),
			 sty(st ? st->off : NULL),
			 (unsigned long long)count[vb],
			 (keep & (1u << (unsigned)vb)) ? "" : "hidden");
		if (!have_pend) {
			snprintf(pend, sizeof pend, "%s", one);
			have_pend = 1;
		} else {
			snprintf(line, sizeof line, "%s   %s", pend, one);
			out(user, line);
			have_pend = 0;
		}
	}
	if (have_pend)
		out(user, pend);
}

