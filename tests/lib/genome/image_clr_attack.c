/*
 * image_clr_attack - kgenome_clr_read and the claims it hands out (round 2, fix_engine2). The baseline
 * ran 81% of clr_image.c: the stream-name loop, the heap that two headers name, the resource area and
 * every anomaly but one were never reached, and the reader is the one function of the image code that
 * walks a table whose length the FILE chooses.
 *
 *   C2   a stream name whose first byte is the object's end: the loop left the name buffer untouched and
 *        the next line read name[0] - an uninitialised byte - to decide whether the header was short.
 *   C3   a stream name of 32 bytes or more that never ends: the buffer is cut at 31 characters and a
 *        terminator is stored at 31, and then the test "did the name end" looks at THAT terminator. The
 *        walk went on from the middle of the name, reading the rest of the name as the next header and
 *        reporting nothing. A name is 31 characters and its NUL, or the table is short.
 *
 * The object is built from values the test writes; the reader is given an identity RVA map.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"
#include "image_kit.h"

#define N 0x1000u

static uint8_t obj[N];

static uint64_t id_rva(const void *u, uint64_t rva)
{
	(void)u;
	return rva < N ? rva : KGENOME_BROKEN;
}

static void result(const char *id, const char *what, int before)
{
	printf("%s %s: %s\n", id, what, hk_fails == before ? "ok" : "FAILED");
}

/* CLI header at 0x100, metadata root at 0x200 with `n_decl` streams declared; headers follow the version. */
static uint32_t root(uint32_t vlen, uint16_t n_decl)
{
	memset(obj, 0, sizeof obj);
	ik_w32(obj + 0x100, 72);
	ik_w32(obj + 0x108, 0x200);
	ik_w32(obj + 0x10c, 0x400);
	ik_w32(obj + 0x200, 0x424a5342u);
	ik_w16(obj + 0x204, 1);
	ik_w16(obj + 0x206, 1);
	ik_w32(obj + 0x20c, vlen);
	memcpy(obj + 0x210, "v4.0.30319", 10);
	ik_w16(obj + 0x210 + vlen + 2u, n_decl);
	return 0x210 + vlen + 4u;       /* where the first stream header goes */
}

/* One stream header at `at`: offset (from the root), size, name padded to four. Returns the next position. */
static uint32_t stream(uint32_t at, uint32_t off, uint32_t len, const char *name)
{
	size_t l = strlen(name) + 1u;

	ik_w32(obj + at, off);
	ik_w32(obj + at + 4, len);
	memcpy(obj + at + 8, name, l);
	return 0x200u + ((at + 8u + (uint32_t)l - 0x200u + 3u) & ~3u);
}

static int read_meta(struct kgenome_clr_meta *m, uint64_t n)
{
	return kgenome_clr_read(kof_buf_make(obj, n), 0x100, id_rva, NULL, m);
}

static void c_valid(void)
{
	struct kgenome_clr_meta m;
	struct kof_range cl[16];
	struct kof_range rb[16];
	struct kof_rlist l;
	uint32_t at, n, k;
	int before = hk_fails;

	at = root(12, 5);
	at = stream(at, 0x100, 0x40, "#~");
	at = stream(at, 0x140, 0x40, "#Strings");
	at = stream(at, 0x180, 0x20, "#US");
	at = stream(at, 0x1a0, 0x20, "#Blob");
	at = stream(at, 0x1c0, 0x10, "#GUID");
	CK(read_meta(&m, N));
	CK(m.streams == 5 && m.streams_read == 5 && m.anomalies == 0);
	CK(m.root_off == 0x200 && m.root_len == at - 0x200u);
	CK(m.tables.off == 0x300 && m.tables.len == 0x40);
	CK(m.strings.off == 0x340 && m.strings.len == 0x40);
	CK(m.us.off == 0x380 && m.us.len == 0x20);
	CK(m.blob.off == 0x3a0 && m.blob.len == 0x20);
	CK(m.guid.off == 0x3c0 && m.guid.len == 0x10);
	CK(!strcmp(m.version, "v4.0.30319"));
	CK(kgenome_clr_present(&m));

	/* the claims are the root and the five heaps, in the order laid out, bounded by the caller's room */
	n = kgenome_clr_claims(&m, cl, 16);
	CK(n == 6u && cl[0].off == 0x200 && cl[1].off == 0x300 && cl[5].off == 0x3c0);
	CK(kgenome_clr_claims(&m, cl, 2) == 2u);
	CK(kgenome_clr_claims(&m, cl, 0) == 0u);
	CK(kgenome_clr_claims(NULL, cl, 16) == 0u && kgenome_clr_claims(&m, NULL, 16) == 0u);
	{
		struct kgenome_clr_meta none;

		memset(&none, 0, sizeof none);
		CK(!kgenome_clr_present(&none) && kgenome_clr_claims(&none, cl, 16) == 0u);
	}
	/* each region mask adds exactly its own bytes; the blob region is two heaps */
	{
		static const struct { uint32_t bit; uint32_t n; uint64_t first; } r[] = {
			{ KGENOME_SCAN_CLR_HEADER, 1, 0x200 }, { KGENOME_SCAN_CLR_TABLES, 1, 0x300 },
			{ KGENOME_SCAN_CLR_STRINGS, 1, 0x340 }, { KGENOME_SCAN_CLR_US, 1, 0x380 },
			{ KGENOME_SCAN_CLR_BLOB, 2, 0x3a0 },
		};

		for (k = 0; k < sizeof r / sizeof r[0]; k++) {
			kof_rl_init(&l, rb, 16);
			kgenome_clr_add_ranges(&m, r[k].bit, &l, N);
			CK(l.n == r[k].n && rb[0].off == r[k].first);
		}
		kof_rl_init(&l, rb, 16);
		kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, &l, N);
		CK(l.n == 6u);                      /* no resource area in this one */
		kof_rl_init(&l, rb, 16);
		kgenome_clr_add_ranges(&m, 0, &l, N);
		CK(l.n == 0u);
		kgenome_clr_add_ranges(NULL, KGENOME_SCAN_CLR_CLAIMED, &l, N);
		kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, NULL, N);
		CK(l.n == 0u);
	}
	CK(kgenome_clr_region_name(KGENOME_SCAN_CLR_HEADER) && !strcmp(kgenome_clr_region_name(KGENOME_SCAN_CLR_TABLES), "#~"));
	CK(!strcmp(kgenome_clr_region_name(KGENOME_SCAN_CLR_STRINGS), "#Strings") &&
	   !strcmp(kgenome_clr_region_name(KGENOME_SCAN_CLR_US), "#US") &&
	   !strcmp(kgenome_clr_region_name(KGENOME_SCAN_CLR_BLOB), "#Blob") &&
	   !strcmp(kgenome_clr_region_name(KGENOME_SCAN_CLR_RESOURCE), "CLR_RES"));
	CK(kgenome_clr_region_name(1u << 20) == NULL && kgenome_clr_region_name(0) == NULL);
	for (k = 0; k < KGENOME_CLR_ANOM_COUNT; k++)
		CK(strcmp(kgenome_clr_anomaly_name(k), "?") != 0);
	CK(!strcmp(kgenome_clr_anomaly_name(KGENOME_CLR_ANOM_COUNT), "?"));
	result("C1 ", "metadata reader, claims, regions, names", before);
}

static void c_streams(void)
{
	struct kgenome_clr_meta m;
	uint32_t at, k;
	int before = hk_fails;
	char name[64];

	/* "#-" is the tables, written the long way: an anomaly, the heap is kept */
	at = root(12, 1);
	at = stream(at, 0x100, 0x40, "#-");
	CK(read_meta(&m, N) && m.tables.len == 0x40 && (m.anomalies & KGENOME_CLR_ANOM_TABLES_RAW));
	/* two headers name one heap: the first wins, the second is said */
	at = root(12, 3);
	at = stream(at, 0x100, 0x40, "#Strings");
	at = stream(at, 0x200, 0x20, "#Strings");
	at = stream(at, 0x240, 0x20, "#Unknown");
	CK(read_meta(&m, N) && m.strings.off == 0x300 && m.strings.len == 0x40);
	CK((m.anomalies & KGENOME_CLR_ANOM_STREAM_OVER) != 0 && m.streams_read == 3u);
	/* a stream that runs past the object is clipped and said; one that starts past it keeps nothing */
	at = root(12, 2);
	at = stream(at, 0x400, 0x1000, "#Blob");
	at = stream(at, 0x5000, 0x10, "#US");
	CK(read_meta(&m, N));
	CK(m.blob.off == 0x600 && m.blob.len == N - 0x600u && m.us.off == 0 && m.us.len == 0);
	CK((m.anomalies & KGENOME_CLR_ANOM_STREAM_CUT) != 0);
	/* more headers declared than the walk reads: the first sixteen, and it says so */
	at = root(12, 40);
	for (k = 0; k < 20; k++) {
		snprintf(name, sizeof name, "#X%u", k);
		at = stream(at, 0x100, 0x10, name);
	}
	CK(read_meta(&m, N) && m.streams == 40u && m.streams_read == 16u);
	CK((m.anomalies & KGENOME_CLR_ANOM_STREAM_SHORT) != 0);
	/* the header table is cut by the end of the object */
	at = root(12, 3);
	at = stream(at, 0x100, 0x10, "#~");
	CK(read_meta(&m, at + 4u) && m.streams_read == 1u && (m.anomalies & KGENOME_CLR_ANOM_STREAM_SHORT));
	/* the declared size of the root is smaller than what the streams reach */
	at = root(12, 1);
	at = stream(at, 0x300, 0x40, "#~");
	ik_w32(obj + 0x10c, 0x10);
	CK(read_meta(&m, N) && (m.anomalies & KGENOME_CLR_ANOM_STREAM_CUT) != 0);
	/* the longest valid name (31 characters and its NUL) is read, and the header after it is where it should be */
	memset(name, 'n', 31);
	name[31] = 0;
	at = root(12, 2);
	at = stream(at, 0x100, 0x10, name);
	at = stream(at, 0x140, 0x30, "#Strings");
	CK(read_meta(&m, N));
	CK(m.streams_read == 2u && m.strings.off == 0x340 && m.strings.len == 0x30 && m.anomalies == 0);
	result("C2 ", "stream headers", before);

	/* C3: a name of 40 characters that never ends inside the room: the table is short, the garbage after
	 * it is not read as headers */
	before = hk_fails;
	memset(name, 'n', 40);
	name[40] = 0;
	at = root(12, 2);
	at = stream(at, 0x100, 0x10, name);
	/* where the old walk went on: the 32-byte step lands in the middle of the name; plant a valid
	 * #Strings header exactly there so that reading from the wrong place would find it */
	{
		const uint32_t wrong = 0x200u + ((0x210u + 12u + 4u + 8u + 32u - 0x200u + 3u) & ~3u);

		stream(wrong, 0x140, 0x30, "#Strings");
	}
	CK(read_meta(&m, N));
	if (m.strings.len != 0 || m.streams_read != 0)
		printf("  a 40-character name: %u stream(s) read, #Strings %#llx+%#llx\n", m.streams_read,
		       (unsigned long long)m.strings.off, (unsigned long long)m.strings.len);
	CK(m.streams_read == 0u && m.strings.len == 0);
	CK((m.anomalies & KGENOME_CLR_ANOM_STREAM_SHORT) != 0);
	/* the boundary of the room: 31 characters and the NUL read (C2 above), 32 characters do not - the
	 * name has no room for its NUL, and the table is short (a loop allowed to read the 32nd would store
	 * its terminator one byte past the buffer) */
	memset(name, 'm', 32);
	name[32] = 0;
	at = root(12, 2);
	at = stream(at, 0x100, 0x10, name);
	at = stream(at, 0x140, 0x30, "#Strings");
	CK(read_meta(&m, N));
	CK(m.streams_read == 0u && (m.anomalies & KGENOME_CLR_ANOM_STREAM_SHORT) != 0);
	/* C2: the name starts at the very end of the object: nothing there is a name */
	at = root(12, 1);
	ik_w32(obj + at, 0x100);
	ik_w32(obj + at + 4, 0x10);
	memset(obj + at + 8, 0xa5, 4);            /* whatever was on the stack must not be what is tested */
	CK(read_meta(&m, at + 8u));
	CK(m.streams_read == 0u && (m.anomalies & KGENOME_CLR_ANOM_STREAM_SHORT) != 0);
	/* the name is cut by the end of the object after some characters */
	at = root(12, 1);
	{
		const uint32_t first = at;

		(void)stream(at, 0x100, 0x10, "#Strings");
		CK(read_meta(&m, first + 8u + 4u));         /* "#Str" and then the end of the object */
		CK(m.streams_read == 0u && (m.anomalies & KGENOME_CLR_ANOM_STREAM_SHORT) != 0);
		CK(read_meta(&m, first + 8u + 9u) && m.streams_read == 1u);   /* the NUL is the last byte: whole */
	}
	result("C3 ", "stream names that do not end", before);
}

static void c_refusals(void)
{
	struct kgenome_clr_meta m;
	int before = hk_fails;

	(void)root(12, 1);
	CK(kgenome_clr_read(kof_buf_make(obj, N), 0x100, id_rva, NULL, NULL) == 0);
	CK(kgenome_clr_read(kof_buf_make(obj, N), 0x100, NULL, NULL, &m) == 0);
	CK(!kgenome_clr_present(&m));
	CK(kgenome_clr_read(kof_buf_make(obj, N), N - 10u, id_rva, NULL, &m) == 0);        /* the header does not fit */
	CK(kgenome_clr_read(kof_buf_make(obj, N), UINT64_MAX - 4u, id_rva, NULL, &m) == 0);
	/* a header size that is not 72 */
	ik_w32(obj + 0x100, 73);
	CK(read_meta(&m, N) == 0 && !kgenome_clr_present(&m));
	ik_w32(obj + 0x100, 72);
	/* no metadata address, one that resolves nowhere, one past the object */
	ik_w32(obj + 0x108, 0);
	CK(read_meta(&m, N) == 0);
	ik_w32(obj + 0x108, 0x9000);
	CK(read_meta(&m, N) == 0);
	ik_w32(obj + 0x108, 0x200);
	CK(read_meta(&m, 0x200) == 0);
	/* not BSJB */
	ik_w32(obj + 0x200, 0x12345678u);
	CK(read_meta(&m, N) == 0 && (m.anomalies & KGENOME_CLR_ANOM_NO_BSJB) != 0 && !kgenome_clr_present(&m));
	ik_w32(obj + 0x200, 0x424a5342u);
	/* a version length that leaves the object */
	ik_w32(obj + 0x20c, 0xffffffffu);
	CK(read_meta(&m, N) == 0);
	ik_w32(obj + 0x20c, N);
	CK(read_meta(&m, N) == 0);
	/* the stream count cannot be read: the object ends right after the version */
	(void)root(12, 1);
	CK(read_meta(&m, 0x210u + 12u + 3u) == 0);
	/* a version longer than the field is cut to 31 characters and its length still steps over it */
	{
		uint32_t at = root(96, 1);

		memset(obj + 0x210, 'v', 96);
		at = stream(at, 0x100, 0x10, "#~");
		CK(read_meta(&m, N));
		CK(strlen(m.version) == 31u && m.tables.len == 0x10);
	}
	result("C4 ", "refusals", before);
}

static void c_resources(void)
{
	struct kgenome_clr_meta m;
	struct kof_rlist l;
	struct kof_range rb[8];
	uint32_t at;
	int before = hk_fails;

	at = root(12, 1);
	at = stream(at, 0x100, 0x10, "#~");
	ik_w32(obj + 0x118, 0x600);
	ik_w32(obj + 0x11c, 0x80);
	CK(read_meta(&m, N) && m.res_off == 0x600 && m.res_len == 0x80 && m.anomalies == 0);
	kof_rl_init(&l, rb, 8);
	kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_RESOURCE, &l, N);
	CK(l.n == 1u && rb[0].off == 0x600 && rb[0].len == 0x80);
	CK(kgenome_clr_claims(&m, rb, 8) == 3u);
	/* cut by the end of the object: clipped and said; wholly outside or unresolvable: none */
	ik_w32(obj + 0x11c, 0x10000);
	CK(read_meta(&m, N) && m.res_len == N - 0x600u && (m.anomalies & KGENOME_CLR_ANOM_STREAM_CUT));
	ik_w32(obj + 0x118, 0x9000);
	CK(read_meta(&m, N) && m.res_len == 0 && m.res_off == 0);
	ik_w32(obj + 0x118, 0x600);
	ik_w32(obj + 0x11c, 0);
	CK(read_meta(&m, N) && m.res_len == 0);
	ik_w32(obj + 0x118, 0);
	ik_w32(obj + 0x11c, 0x10);
	CK(read_meta(&m, N) && m.res_len == 0);
	result("C5 ", "manifest resources", before);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	c_valid();
	c_streams();
	c_refusals();
	c_resources();
	if (hk_fails) {
		printf("image_clr_attack: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("image_clr_attack: ok\n");
	return 0;
}
