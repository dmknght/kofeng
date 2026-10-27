/*
 * suite_decomp_bcj2 - a 7z folder of FOUR streams (BCJ2) opened by the engine: oc_unpack_bcj2 and decode_stream
 * (libkofeng/scanners/objctx_decomp_folder.c), which no test reached.
 *
 * The archive is written here from the format document (the signature header, four packed streams, a header with the four coders
 * BCJ2 + LZMA main + LZMA call + LZMA jump, three bind pairs, the packed-stream order main, call, jump, rc). The three coded streams
 * are made by the xz tool (raw LZMA1, as cov_sevenzip_real.c does; skipped visibly when it is not installed); the four BCJ2 streams
 * by the encoder of tests/lib/uncoat/hostile_bcjenc.h over code-like bytes. The file the folder holds is compared with the original.
 *
 *   WHOLE        the folder opens to its original bytes (E8 calls and E9 jumps: all three channels carry data)
 *   EMPTY JUMP   a folder whose code has calls and no jumps: the jump channel is EMPTY (a packed stream of size 0), which is an
 *                ordinary shape and was once reported DAMAGED (the note in oc_unpack_bcj2)
 *   SHORT        the folder says it holds twice what the streams decode to: DAMAGED, and what was decoded is still handed on
 *   HUGE         a declared output past what the resident allowance holds: LIMIT, said, no allocation of that size
 *   NOT BCJ2     three packed streams where the shape needs four, and a packed size that runs past the file: no child of the
 *                folder, no crash
 *   BAD STREAM   a main stream that is not LZMA: no output from that folder and no crash
 *
 * Needs the built database and /usr/bin/xz; run from the repository root after make.
 */
#define _GNU_SOURCE

#include "../lib/uncoat/hostile_common.h"
#include "../lib/uncoat/hostile_lzenc.h"
#include "../lib/uncoat/hostile_bcjenc.h"
#undef CK
#include "hostile_engine.h"
#include "cov_fixtures_7z.h"

#define DB "build/release/databases"

struct kid {
	char     name[120];
	uint64_t len;
	uint8_t  data[4096];
	uint32_t broken;
};

static struct kid K[8];
static unsigned NK, NSEEN;
static uint32_t root_broken;

static int cb(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *user)
{
	(void)user;
	if (NSEEN++ == 0) {
		root_broken = r->broken;
		return 0;
	}
	if (NK < 8) {
		snprintf(K[NK].name, sizeof K[NK].name, "%s", name);
		K[NK].len = n;
		K[NK].broken = r->broken;
		memcpy(K[NK].data, b, n < sizeof K[NK].data ? (size_t)n : sizeof K[NK].data);
		NK++;
	}
	return 0;
}

static uint8_t orig[1600];
static struct b2 enc;
static uint8_t lz[3][4096];
static size_t lzn[3];
static uint8_t packed[16384], hdr[1024], arc[20000];

/* the header buffer through a pointer the compiler cannot see through: cov_fixtures_7z.h's wb_put is bounds-checked, and gcc's range analysis
 * reports a write past a known-size destination it cannot connect to that check */
static __attribute__((noinline)) uint8_t *hdr_buf(void)
{
	return hdr;
}

/* raw LZMA1 of `p` by the xz tool, with the properties the header declares (lc3 lp0 pb2, 1 MiB); empty stays empty */
static int lzma_of(const uint8_t *p, size_t n, uint8_t *out, size_t cap, size_t *got)
{
	if (!n) {
		*got = 0;
		return 1;
	}
	*got = via_tool("/usr/bin/xz -c --format=raw --lzma1=lc=3,lp=0,pb=2,dict=1MiB", p, n, out, cap);
	return *got > 0;
}

static void bcj2_coder_simple(struct wb *b, const struct coder *c)
{
	wb_coder(b, c);
}

/* The archive: packed = main | call | jump | rc. `sizes_out` is [main, call, jump, file], the unpack size of each coder's output as the header declares them. */
static __attribute__((noinline)) size_t build_archive(const uint64_t sizes_out[4], const uint64_t packed_sizes[4], unsigned n_packed, uint8_t *arc_out, size_t cap)
{
	struct wb b = { hdr_buf(), 0, sizeof hdr };
	static const uint8_t bcj2_id[4] = { 0x03, 0x03, 0x01, 0x1b };
	unsigned i;
	size_t at = 0;

	wb_u8(&b, ID_HEADER);
	wb_u8(&b, ID_MAINSTREAMS);
	wb_u8(&b, ID_PACKINFO);
	wb_num(&b, 0);
	wb_num(&b, n_packed);
	wb_u8(&b, ID_SIZE);
	for (i = 0; i < n_packed; i++)
		wb_num(&b, packed_sizes[i]);
	wb_u8(&b, ID_END);
	wb_u8(&b, ID_UNPACK);
	wb_u8(&b, ID_FOLDER);
	wb_num(&b, 1);
	wb_u8(&b, 0);
	wb_num(&b, 4);                                  /* coders: the three LZMA first, BCJ2 LAST (the parser reads the last coder as the filter) */
	for (i = 0; i < 3; i++)
		bcj2_coder_simple(&b, &C_LZMA);
	wb_u8(&b, 4u | 0x10u);                          /* BCJ2: an id of 4 bytes, "complex": its stream counts follow */
	wb_put(&b, bcj2_id, 4);
	wb_num(&b, 4);
	wb_num(&b, 1);
	wb_num(&b, 3); wb_num(&b, 0);                   /* BCJ2's input 0 (stream 3: main) is the output of coder 0 */
	wb_num(&b, 4); wb_num(&b, 1);                   /* input 1 (call) of coder 1 */
	wb_num(&b, 5); wb_num(&b, 2);                   /* input 2 (jump) of coder 2 */
	wb_num(&b, 0); wb_num(&b, 1); wb_num(&b, 2); wb_num(&b, 6);   /* the packed streams: the three LZMA inputs and BCJ2's range coder (input 3 = stream 6) */
	wb_u8(&b, ID_CODERSSIZE);
	for (i = 0; i < 4; i++)
		wb_num(&b, sizes_out[i]);
	wb_u8(&b, ID_END);
	wb_u8(&b, ID_SUBSTREAMS);
	wb_u8(&b, ID_NUMUNPACK);
	wb_num(&b, 1);
	wb_u8(&b, ID_END);
	wb_u8(&b, ID_END);
	{
		static const struct afile f[1] = { { "code.bin", 0, 0 } };

		wb_u8(&b, ID_FILES);
		wb_num(&b, 1);
		wb_names(&b, f, 1);
		wb_u8(&b, ID_END);
	}
	wb_u8(&b, ID_END);
	for (i = 0; i < n_packed; i++)
		at += (size_t)packed_sizes[i];
	return assemble(arc_out, cap, packed, at, hdr, b.n);
}

static kof_engine *eng;
static kof_scanner *sc;

static void scan(const uint8_t *a, size_t n, uint64_t resident)
{
	struct kof_scan_option o = he_opt();

	o.max_resident_bytes = resident;
	NK = NSEEN = 0;
	root_broken = 0;
	(void)kscan_bytes(sc, a, n, "x.7z", &o, cb, NULL);
}

/* The streams of `code` (n bytes), their LZMA, and the archive. 0 when the tool is missing. */
static int make(size_t n, unsigned convert_pct, int no_jumps, uint64_t declared_out, size_t *arc_n)
{
	uint64_t rs = 0xb2b2u, sz_out[4], sz_pack[4];
	size_t at = 0, i;

	code_bytes(orig, n, &rs, 1);
	if (no_jumps)
		for (i = 0; i < n; i++)
			if (orig[i] == 0xE9 || orig[i] == 0x0F)           /* no JMP and no two byte conditional jump: the jump channel is empty */
				orig[i] = 0x90;
	if (!b2_encode(&enc, orig, n, 77, convert_pct))
		return 0;
	if (!lzma_of(enc.main_s, enc.nm, lz[0], sizeof lz[0], &lzn[0]) || !lzma_of(enc.call_s, enc.nc, lz[1], sizeof lz[1], &lzn[1]) ||
	    !lzma_of(enc.jump_s, enc.nj, lz[2], sizeof lz[2], &lzn[2]))
		return 0;
	for (i = 0; i < 3; i++) {
		memcpy(packed + at, lz[i], lzn[i]);
		sz_pack[i] = lzn[i];
		at += lzn[i];
	}
	memcpy(packed + at, enc.rc_s, enc.nr);
	sz_pack[3] = enc.nr;
	sz_out[0] = enc.nm;
	sz_out[1] = enc.nc;
	sz_out[2] = enc.nj;
	sz_out[3] = declared_out ? declared_out : n;
	*arc_n = build_archive(sz_out, sz_pack, 4, arc, sizeof arc);
	return *arc_n > 0;
}

static int whole_child(size_t n)
{
	unsigned i;

	for (i = 0; i < NK; i++)
		if (K[i].len == n && !memcmp(K[i].data, orig, n < sizeof K[i].data ? n : sizeof K[i].data))
			return 1;
	return 0;
}

static void rows(void)
{
	size_t an, i;
	int made;

	/* WHOLE */
	made = make(1500, 100, 0, 0, &an);
	if (!made) {
		printf("  SKIP bcj2: the xz tool is not installed (or the archive did not fit)\n");
		return;
	}
	CK(enc.nc > 0 && enc.nj > 0, "the fixture has all three channels (call %zu, jump %zu bytes)", enc.nc, enc.nj);
#ifdef BCJ2_DUMP
	{ FILE *f = fopen("/mnt/games/normtest/tests_wp5/scratch/bcj2.7z", "wb"); fwrite(arc, 1, an, f); fclose(f); }
#endif
	scan(arc, an, 256u << 20);
	CK(whole_child(1500) && root_broken == 0, "a BCJ2 folder does not open to its original (%u children, root broken %u)", NK, root_broken);

	/* EMPTY JUMP CHANNEL */
	made = make(1200, 100, 1, 0, &an);
	CK(made && enc.nj == 0 && enc.nc > 0, "the no-jump fixture (call %zu, jump %zu)", enc.nc, enc.nj);
	scan(arc, an, 256u << 20);
	CK(whole_child(1200) && root_broken == 0, "an empty jump channel: %u children, root broken %u (once reported DAMAGED)", NK, root_broken);

	/* SHORT: the folder says twice what the streams decode to */
	made = make(1500, 100, 0, 3000, &an);
	CK(made, "short fixture");
	scan(arc, an, 256u << 20);
	{
		uint32_t b = root_broken;

		for (i = 0; i < NK; i++)
			b |= K[i].broken;
		CK(b == KOF_BROKEN_DAMAGED || root_broken == KOF_BROKEN_DAMAGED, "a folder that decodes to half of what it says: broken %u over %u children", b, NK);
	}

	/* HUGE: a declared output of 1 GiB under a 64 MiB allowance: LIMIT and no child of that size */
	made = make(1500, 100, 0, 1ull << 30, &an);
	CK(made, "huge fixture");
	{
		uint64_t hits0 = kscan_stats(sc)->limit_hits;

		scan(arc, an, 64u << 20);
		CK(root_broken == KOF_BROKEN_LIMIT || kscan_stats(sc)->limit_hits > hits0 || NK == 0, "a declared output of 1 GiB under 64 MiB: root broken %u, %u children", root_broken, NK);
		for (i = 0; i < NK; i++)
			CK(K[i].len < (1ull << 30), "a child of %llu bytes", (unsigned long long)K[i].len);
	}

	/* NOT BCJ2: three packed streams where four are needed; a packed size that runs past the file */
	made = make(1500, 100, 0, 0, &an);
	CK(made, "fixture");
	{
		uint64_t so[4] = { enc.nm, enc.nc, enc.nj, 1500 }, sp[4] = { lzn[0], lzn[1], lzn[2], enc.nr };

		an = build_archive(so, sp, 3, arc, sizeof arc);               /* PackInfo lists three; the folder needs four */
		scan(arc, an, 256u << 20);
		CK(!whole_child(1500), "three packed streams opened a BCJ2 folder");
		sp[0] = lzn[0] + 2000000u;
		an = build_archive(so, sp, 4, arc, sizeof arc);
		scan(arc, an, 256u << 20);
		CK(!whole_child(1500), "a packed size past the file opened a BCJ2 folder");
	}

	/* BAD STREAM: the main stream is not LZMA */
	made = make(1500, 100, 0, 0, &an);
	CK(made, "fixture");
	{
		uint64_t so[4] = { enc.nm, enc.nc, enc.nj, 1500 }, sp[4] = { lzn[0], lzn[1], lzn[2], enc.nr };

		memset(packed, 0xA5, lzn[0]);
		an = build_archive(so, sp, 4, arc, sizeof arc);
		scan(arc, an, 256u << 20);
		CK(!whole_child(1500), "a main stream of 0xA5 opened a BCJ2 folder to the original");
	}
}

static int run_all(void *arg)
{
	(void)arg;
	eng = keng_open(DB);
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		printf("suite_decomp_bcj2: no database (run from the repository root after make): nothing tested\n");
		return 1;
	}
	rows();
	kscan_free(sc);
	keng_close(eng);
	return he_fails ? 1 : 0;
}

int main(void)
{
	struct he_status st = he_child(run_all, NULL, 120);

	if (!st.exited || st.code) {
		printf("suite_decomp_bcj2: FAILED (exited %d code %d signal %d)\n", st.exited, st.code, st.sig);
		return 1;
	}
	printf("suite_decomp_bcj2: ok\n");
	return 0;
}
