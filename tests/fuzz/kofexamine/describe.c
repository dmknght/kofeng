/*
 * kofexamine/describe - the describers of kofinspect_describe.c and kof_declared_regions, driven by bytes that are the record /
 * the structure itself:
 *
 *   kofexamine/event      [log header][32 verb counts][one 640-byte event record]: kof_inspect_event_log, _event_verbs, _event;
 *   kofexamine/toolchain  offset, size, counts, a section name flag and the bytes of an object: kof_inspect_toolchain on an ELF
 *                         description and a PE description, kof_inspect_dotnet on a PE description (the CLR numbers from bytes);
 *   kofexamine/declared   a table of region declarations from bytes: kof_declared_regions.
 * Held: every line the callback gets is a terminated string shorter than the row buffer; no line is produced from outside the
 * bytes the object holds (a section past the object makes no compiler row); counts and sizes that wrap are tolerated; the row
 * count of an event is at most its field count; kof_declared_regions answers only rows that name the mask and have a length,
 * at most the room, in order.
 */
#include <stdlib.h>
#include <string.h>

#include "../../../kofexamine/kofinspect_private.h"
#include "../../lib/fuzz_drv.h"

struct lines {
	unsigned n, bad;
	uint64_t h;
};

static void take(void *u, const char *s)
{
	struct lines *l = u;
	size_t k, len = strnlen(s, 700);

	if (len >= 600)
		l->bad++;
	l->n++;
	for (k = 0; k < len && k < 64; k++)
		l->h = (l->h ^ (unsigned char)s[k]) * 0x100000001b3ull;
}

/* ------------------------------------------------------------------------------------------- event */

static void event_seeds(struct fz_corpus *c)
{
	uint8_t b[sizeof(struct kofevt_log_hdr) + 256 + KOF_EVT_SIZE];
	struct kofevt_log_hdr h;
	unsigned v;

	memset(b, 0, sizeof b);
	memset(&h, 0, sizeof h);
	h.platform = KOF_PLAT_LINUX;
	h.src_major = 1;
	h.root_pid = 42;
	memcpy(b, &h, sizeof h);
	for (v = 0; v < 32; v++)
		b[sizeof h + v * 8] = (uint8_t)(v * 3);
	{
		struct kof_evt e;

		memset(&e, 0, sizeof e);
		e.verb = KOF_EVT_FILE_NEW;
		e.pid = 100;
		e.stamp = 132000000000000000ull;
		memcpy(b + sizeof h + 256, &e, sizeof e);
	}
	fz_corpus_add(c, "event", b, sizeof b);
	memset(b, 0, sizeof b);
	fz_corpus_add(c, "zero", b, sizeof b);
}

static int event_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const struct kof_inspect_style st = { "<I>", "<L>", "<W>", "</>" };
	struct kofevt_log_hdr h;
	uint64_t counts[32];
	struct kof_evt e;
	struct lines l;
	size_t o = 0, k;
	uint64_t events = 0, records = 0;

	if (!n)
		return 0;
	memset(&h, 0, sizeof h);
	memset(counts, 0, sizeof counts);
	memset(&e, 0, sizeof e);
	k = n < sizeof h ? n : sizeof h;
	memcpy(&h, in, k);
	o = k;
	k = n - o < 256 ? n - o : 256;
	memcpy(counts, in + o, k);
	o += k;
	k = n - o < sizeof e ? n - o : sizeof e;
	memcpy(&e, in + o, k);
	/* What kofevt_log_read does before it hands a record out: the arena ends in a NUL (kofevtlog.c: "AND THE ARENA ENDS IN A NUL").
	 * A record that did not come through the reader can be unterminated, and the formatter then runs off the record in strlen
	 * (kofevtfmt.c:851, finding EX-13, tests_kx/findings/EX-13): counted, not held. */
	fz_digest(c, e.text[sizeof e.text - 1u] != 0);
	e.text[sizeof e.text - 1u] = 0;
	if (n >= 8) {
		memcpy(&events, in, 8);
		memcpy(&records, in + n - 8, 8);
	}
	memset(&l, 0, sizeof l);
	kof_inspect_event_log(&h, events, records, (in[0] & 1) ? &st : NULL, take, &l);
	FZ_CHECK(c, l.n >= 4 && l.n <= 5, "the log header describes in four or five rows");
	FZ_CHECK(c, !l.bad, "a log header row of 600 bytes or more");
	fz_digest(c, l.h ^ l.n);
	memset(&l, 0, sizeof l);
	kof_inspect_event_verbs(counts, (uint32_t)events, (in[0] & 2) ? &st : NULL, take, &l);
	FZ_CHECK(c, l.n <= 16 && !l.bad, "a verb summary of more than 16 rows, or a row too long");
	fz_digest(c, l.h ^ l.n);
	memset(&l, 0, sizeof l);
	kof_inspect_event(&e, (in[0] & 4) ? &st : NULL, take, &l);
	FZ_CHECK(c, l.n <= kof_evt_n_fields(&e), "an event described in more rows than it has fields");
	FZ_CHECK(c, !l.bad, "an event row of 600 bytes or more");
	fz_digest(c, l.h ^ l.n);
	return 0;
}

FZ_ADAPTER(kx_event, .name = "kofexamine/event",
	   .covers = "kof_inspect_event_log kof_inspect_event kof_inspect_event_verbs",
	   .shape = FZ_REQ, .seeds = event_seeds, .run = event_run);

/* --------------------------------------------------------------------------------------- toolchain */

/* offset(8) size(8) sec_count(1) seg_count(1) flags(1: bit0 name is .comment, bit1 PT_INTERP on seg 1, bit2 PE, bit3 CLR) rest...
 * then the CLR numbers (8 x u64: root, three stream offsets and lengths) and the object. */
static void tool_seeds(struct fz_corpus *c)
{
	uint8_t b[160];

	memset(b, 0, sizeof b);
	b[0] = 40; b[8] = 30; b[16] = 1; b[17] = 2; b[18] = 3;
	memcpy(b + 19 + 64, "GCC: (GNU) 13.2.0\0second", 24);
	fz_corpus_add(c, "elf", b, sizeof b);
	b[18] = 4 | 8;
	b[19] = 14; b[20] = 29;
	fz_corpus_add(c, "pe-clr", b, sizeof b);
}

static int tool_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const struct kof_inspect_style st = { "<I>", "<L>", "<W>", "</>" };
	static struct kgenome_elf_info el;
	static struct kgenome_pe_info pe;
	struct kof_obj_ctx ctx;
	struct lines l;
	uint64_t off = 0, size = 0;
	uint8_t flags;
	unsigned i;
	const uint8_t *obj;
	size_t on;

	if (n < 19 + 64)
		return 0;
	memcpy(&off, in, 8);
	memcpy(&size, in + 8, 8);
	flags = in[18];
	obj = in + 19 + 64;
	on = n - (19 + 64);
	memset(&ctx, 0, sizeof ctx);

	/* an ELF description: names, sizes and counts from the bytes; the name arrays are terminated as the parser leaves them */
	memset(&el, 0, sizeof el);
	el.sec_count = in[16] < 8 ? in[16] : (uint32_t)in[16] * 0x01010101u;
	el.seg_count = in[17] < 8 ? in[17] : (uint32_t)in[17] * 0x01010101u;
	for (i = 0; i < 4; i++) {
		el.sec[i].file_off = i ? off + i : off;
		el.sec[i].file_size = size;
		if (flags & 1)
			snprintf(el.sec[i].name, sizeof el.sec[i].name, ".comment");
		else
			snprintf(el.sec[i].name, sizeof el.sec[i].name, ".t%u", i);
		el.seg[i].type = (flags & 2) && i == 1 ? 3u : (uint32_t)in[19 + i];
	}
	ctx.format = KOF_FMT_ELF;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &el, kof_buf_make(obj, on), (flags & 16) ? &st : NULL, take, &l);
	FZ_CHECK(c, !l.bad && l.n <= 2, "an ELF toolchain description of more than two rows, or a row too long");
	/* a compiler row only for text the object really holds */
	if (off >= on || size == 0)
		FZ_CHECK(c, l.n <= 1, "a compiler row for a section that is outside the object");
	fz_digest(c, l.h ^ l.n);

	/* a PE description, and the CLR block */
	memset(&pe, 0, sizeof pe);
	pe.linker_major = in[19]; pe.linker_minor = in[20];
	pe.clr_len = (flags & 8) ? 72u : 0u; pe.clr_major = in[21]; pe.clr_minor = in[22]; pe.clr_flags = in[23];
	for (i = 0; i < sizeof pe.clr_version - 1u; i++)
		pe.clr_version[i] = (char)(in[24 + i % 32] | 0x20u);
	pe.clr_version[sizeof pe.clr_version - 1u] = 0;
	pe.clr_version[in[56] % 8u] = 0;
	if (flags & 4) {
		pe.clr.root_off = off | 1u;
		pe.clr.root_len = size;
		memcpy(&pe.clr.tables, in + 40, 16);
		memcpy(&pe.clr.strings, in + 40, 16);
		pe.clr.res_off = off; pe.clr.res_len = size;
		pe.clr.streams = in[57]; pe.clr.streams_read = in[58];
		pe.clr.anomalies = (uint32_t)in[59] * 0x01010101u;
		snprintf(pe.clr.version, sizeof pe.clr.version, "v4.0");
	}
	ctx.format = KOF_FMT_PE;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &pe, kof_buf_make(obj, on), &st, take, &l);
	FZ_CHECK(c, !l.bad && l.n <= 2, "a PE toolchain description of more than two rows, or a row too long");
	fz_digest(c, l.h ^ l.n);
	memset(&l, 0, sizeof l);
	kof_inspect_dotnet(&ctx, &pe, (flags & 32) ? &st : NULL, take, &l);
	FZ_CHECK(c, !l.bad && l.n <= 1 + 5 + 1 + KGENOME_CLR_ANOM_COUNT, "a .NET description of more rows than it has parts");
	FZ_CHECK(c, (flags & 4) || l.n == 0, "a .NET description of an image with no metadata root");
	fz_digest(c, l.h ^ l.n);
	return 0;
}

FZ_ADAPTER(kx_toolchain, .name = "kofexamine/toolchain", .covers = "kof_inspect_toolchain kof_inspect_dotnet",
	   .shape = FZ_REQ, .seeds = tool_seeds, .run = tool_run);

/* ------------------------------------------------------------------------------------------ declared */

static void decl_seeds(struct fz_corpus *c)
{
	uint8_t b[1 + 8 * 20];
	unsigned i;

	memset(b, 0, sizeof b);
	b[0] = 5;
	for (i = 0; i < 8; i++) {
		b[1 + i * 20] = (uint8_t)(1u << (i % 4));
		b[1 + i * 20 + 4] = (uint8_t)(i * 8);
		b[1 + i * 20 + 12] = (uint8_t)(i % 3 ? 4 : 0);
	}
	fz_corpus_add(c, "table", b, sizeof b);
}

static int decl_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kof_scan_region rg[8];
	struct kof_range out[8];
	uint32_t mask, room, got, i, want = 0;

	if (n < 1 + 8 * 20)
		return 0;
	memset(rg, 0, sizeof rg);
	for (i = 0; i < 8; i++) {
		memcpy(&rg[i].mask, in + 1 + i * 20, 4);
		memcpy(&rg[i].off, in + 1 + i * 20 + 4, 8);
		memcpy(&rg[i].len, in + 1 + i * 20 + 12, 8);
	}
	memcpy(&mask, in + 1, 4);
	room = in[0] % 10u;
	got = kof_declared_regions(rg, 8, mask, out, room > 8 ? 8 : room);
	for (i = 0; i < 8; i++)
		if ((rg[i].mask & mask) && rg[i].len)
			want++;
	FZ_CHECK(c, got == (want < (room > 8 ? 8 : room) ? want : (room > 8 ? 8 : room)), "kof_declared_regions: not the rows that name the mask and have a length, bounded by the room");
	{
		uint32_t j = 0;

		for (i = 0; i < 8 && j < got; i++)
			if ((rg[i].mask & mask) && rg[i].len) {
				FZ_CHECK(c, out[j].off == rg[i].off && out[j].len == rg[i].len, "kof_declared_regions out of order or altered");
				j++;
			}
	}
	fz_digest(c, got);
	return (int)got;
}

FZ_ADAPTER(kx_declared, .name = "kofexamine/declared", .covers = "kof_declared_regions", .shape = FZ_REQ, .seeds = decl_seeds,
	   .run = decl_run);
