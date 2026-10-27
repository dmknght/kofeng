/*
 * zip_cd_arith - the arithmetic kof_zip_parse does with the directory offset and size it reads (zip64 fields are 64 bits wide and the
 * file chooses them). The end record must sit where the directory ends, so the parse looks for the directory at eocd_off - cd_size and
 * moves to it when a central record is there (a self-extracting stub, a carved archive).
 *
 *   WP2-D15  the move was computed as `(int64_t)cd_off + delta`: signed overflow (undefined; the sanitised build stops at it) when a
 *            zip64 field is 2^62 or more, and, in a build where it wraps, a size just under 2^64 wrapped into a plausible offset and
 *            the walk moved to a central record the directory does not end at. Why the old tests missed it: (b) no test fed a zip64
 *            end record with a field at the top of the range; the fuzz adapters hit it and SKIPPED the input (ctr_zip64_ub).
 *
 * Rows: the control (a real stub still moves the offset), the range rows (nothing moves, the parse says the directory does not fit,
 * nothing is undefined), and the wrap row (the one that is wrong in a release build too).
 *
 * usage: zip_cd_arith
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofmod/zip.h"
#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"

static int checks, fails;

#define CK(cond, ...) do { checks++; if (!(cond)) { fails++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void p16(uint8_t *b, uint32_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static void p32(uint8_t *b, uint32_t v) { p16(b, v); p16(b + 2, v >> 16); }
static void p64(uint8_t *b, uint64_t v) { p32(b, (uint32_t)v); p32(b + 4, (uint32_t)(v >> 32)); }

#define CMT 120u

/*
 * [0]   local signature, zeros to 64
 * [64]  zip64 end record (56)   [120] locator (20)   [140] end record (22)   [162] comment (120 bytes)
 * a central signature is planted at `plant` when it is not 0.
 */
static size_t zip64_file(uint8_t *f, uint64_t cd_size, uint64_t cd_off, size_t plant)
{
	memset(f, 0, 162u + CMT);
	p32(f, 0x04034b50u);
	p32(f + 64, 0x06064b50u);
	p64(f + 64 + 0x20, 0);
	p64(f + 64 + 0x28, cd_size);
	p64(f + 64 + 0x30, cd_off);
	p32(f + 120, 0x07064b50u);
	p64(f + 120 + 8, 64);
	p32(f + 140, 0x06054b50u);
	p32(f + 140 + 12, 0xffffffffu);
	p32(f + 140 + 16, 0xffffffffu);
	p16(f + 140 + 20, CMT);
	if (plant)
		p32(f + plant, 0x02014b50u);
	return 162u + CMT;
}

static struct kof_zip_info *parse(const uint8_t *f, size_t n, int *rc)
{
	static struct kof_obj_ctx ctx;
	struct kof_zip_info *z = calloc(1, sizeof *z);

	memset(&ctx, 0, sizeof ctx);
	*rc = kof_zip_parse(kof_buf_make(f, n), z, &ctx);
	return z;
}

static void row(const char *what, uint64_t cd_size, uint64_t cd_off, size_t plant, int want_sfx, int want_past)
{
	uint8_t f[162u + CMT];
	size_t n = zip64_file(f, cd_size, cd_off, plant);
	int rc;
	struct kof_zip_info *z = parse(f, n, &rc);

	CK(rc != 0 && z->valid, "%s: the file is still a zip", what);
	CK(!!(z->anomalies & KOF_ZIP_ANOM_SFX) == want_sfx, "%s: SFX anomaly %d, wanted %d", what, !!(z->anomalies & KOF_ZIP_ANOM_SFX), want_sfx);
	CK(!!(z->anomalies & KOF_ZIP_ANOM_CD_PAST_EOF) == want_past, "%s: CD_PAST_EOF %d, wanted %d", what, !!(z->anomalies & KOF_ZIP_ANOM_CD_PAST_EOF), want_past);
	if (!want_sfx)
		CK(z->cd_off == cd_off && z->base_delta == 0, "%s: the offset stays as declared (%llu, delta %lld)", what, (unsigned long long)z->cd_off, (long long)z->base_delta);
	kof_zip_release(z);
	free(z);
}

int main(void)
{
	/* the control: a stub of 40 bytes in front of a one-record directory; the end record says the directory is at 0 */
	{
		uint8_t f[40 + 47 + 22];
		int rc;
		struct kof_zip_info *z;

		memset(f, 0, sizeof f);
		p32(f, 0x04034b50u);
		p32(f + 40, 0x02014b50u);
		f[40 + 0x1c] = 1;
		f[40 + 46] = 'a';
		p32(f + 87, 0x06054b50u);
		p16(f + 87 + 8, 1);
		p16(f + 87 + 10, 1);
		p32(f + 87 + 12, 47);
		p32(f + 87 + 16, 0);
		z = parse(f, sizeof f, &rc);
		CK(rc != 0 && (z->anomalies & KOF_ZIP_ANOM_SFX) && z->cd_off == 40 && z->base_delta == 40,
		   "control: a 40 byte stub still moves the directory to 40 (cd_off %llu, delta %lld)", (unsigned long long)z->cd_off, (long long)z->base_delta);
		kof_zip_release(z);
		free(z);
	}
	/* a zip64 pair whose signed sum overflows: the size and the offset both INT64_MAX */
	row("zip64 size = offset = 2^63-1", (uint64_t)INT64_MAX, (uint64_t)INT64_MAX, 0, 0, 1);
	/* the offset alone at 2^62, size 0: nothing at the end record is a central record */
	row("zip64 offset 2^62+5, size 0", 0, (1ull << 62) + 5u, 0, 0, 1);
	/* the size at 2^62 and the offset below it */
	row("zip64 size 2^62, offset 10", 1ull << 62, 10, 0, 0, 1);
	/* the top of the range */
	row("zip64 size = offset = 2^64-1", UINT64_MAX, UINT64_MAX, 0, 0, 1);
	/* the wrap: size 2^64-100 with offset 0 made the old sum land 100 bytes past the end record, where a central signature is planted */
	row("zip64 size 2^64-100, offset 0, a central signature at end record + 100", UINT64_MAX - 99u, 0, 140u + 100u, 0, 1);
	/* an offset above INT64_MAX has no signed distance to the directory the size points at: not moved, even with a signature there */
	row("zip64 size 60, offset 2^63+7, a central signature at end record - 60", 60, (1ull << 63) + 7u, 140u - 60u, 0, 1);
	/* the boundary of the size: one byte more than fits before the end record is reported, exactly what fits is not */
	row("zip64 size = end record offset + 1, offset 0", 141, 0, 0, 0, 1);
	row("zip64 size = end record offset, offset 0 (the directory would start at 0, where it is)", 140, 0, 0, 0, 0);
	/* the control of the range rows: a size that fits and a signature where the directory must start still moves it */
	row("zip64 size 60, offset 3, a central signature at end record - 60", 60, 3, 140u - 60u, 1, 0);
	printf("zip_cd_arith: %d check(s), %d failure(s)\n", checks, fails);
	return fails != 0;
}
