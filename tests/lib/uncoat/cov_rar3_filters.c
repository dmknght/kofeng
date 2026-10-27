/*
 * cov_rar3_filters - the RAR 3 filter declarations of rar3.c, which no test reached (std_filter_of, vbr_take and the wide forms of
 * vm_read_data were never run; the filter table, the uses table and the reset were never driven past their first line).
 *
 * The streams come from the LZ encoder of hostile_rarenc.h (filter-capable: symbol 257 has a code) and the declaration writer of
 * hostile_rarvm.h, with programs FORGED to the CRC32 and length RAR recognises (hostile_rarvm.h says how: a CRC is affine, four bytes
 * are solved for). The expected output is the plain bytes with each declared range run through an independent restatement of the
 * filter (hostile_rarvec.h ref_e8, ref_delta), in declaration order.
 *
 *   FILTERS      E8, E8+E9 (start by the +258 form), the channel delta with its register mask (scratch given), reuse of a program by
 *                index (first byte without the index bit, and with it), several uses of one program
 *   REFUSED      a delta with no scratch, the four recognised programs the decoder does not run (Itanium, RGB, audio, upcase), a
 *                program of the right shape and the wrong CRC, a program whose first byte is not the XOR of the rest, an index past the
 *                table, a 65th program, a 513th use, a range longer than the VM memory, a declaration cut short, a code block longer
 *                than the VM limit: each ends the decode UNSUPPORTED (or TRUNCATED for the cut one) and says so; bytes already
 *                decoded are reported
 *   DROPPED      a declaration of length zero costs nothing and the stream goes on; a range never reached is not applied
 *   RESET        index 0 drops the table and every use not yet passed
 *   NUMBERS      every width of RAR's variable width number: 6, 10, 14 (the small negative), 18 and 34 bits
 */
#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzhenc.h"
#include "hostile_rarenc.h"
#include "hostile_rarvec.h"
#include "hostile_rarvm.h"

#define SCR KUNCOAT_RAR3_SCRATCH

static uint8_t g_scratch[SCR];

struct use { size_t at, len; unsigned kind; uint32_t r0; int e9; };

struct S {
	struct hv_r3 e;
	uint8_t      out[40000], hist[40000];
	struct use   u[700];
	unsigned     nu;
	uint8_t      prog[HV_VM_KINDS][256];
	int          forged[HV_VM_KINDS];
	uint64_t     rs;
};

static struct S s;

static void s_begin(uint64_t seed)
{
	unsigned k;

	memset(&s, 0, sizeof s);
	s.rs = seed;
	hv_r3_init_ex(&s.e, s.out, sizeof s.out, s.hist, sizeof s.hist, 1);
	for (k = 0; k < HV_VM_KINDS; k++)
		s.forged[k] = hv_vm_forge(s.prog[k], HV_VM_STD[k].len, HV_VM_STD[k].crc, &s.rs);
}

/* n literals of code-like bytes: E8 / E9 followed by a small address, so a call filter has something to rewrite. */
static void s_code(unsigned n)
{
	unsigned i = 0;

	while (i < n) {
		uint32_t r = hv_rng32(&s.rs) % 10u;

		if (r < 3 && i + 5 <= n) {
			hv_r3_lit(&s.e, r == 0 ? 0xE9 : 0xE8);
			hv_r3_lit(&s.e, hv_rar_lit(hv_rng32(&s.rs) % 96u));
			hv_r3_lit(&s.e, 1);
			hv_r3_lit(&s.e, 0);
			hv_r3_lit(&s.e, 0);
			i += 5;
		} else {
			hv_r3_lit(&s.e, hv_rar_lit(hv_rng32(&s.rs) % 100u));
			i++;
		}
	}
}

static struct hv_vm_decl base_decl(uint32_t idx, uint32_t start, uint32_t blen)
{
	struct hv_vm_decl d;

	memset(&d, 0, sizeof d);
	d.flags = 0x80u | 0x20u;
	d.idx = idx;
	d.start = start;
	d.blen = blen;
	return d;
}

/* Declare a use; `kind` < 0 means no recognised program (the caller's own d.prog). Records what the decoder should do with it. */
static void s_decl(struct hv_vm_decl *d, int kind, unsigned r0, int e9)
{
	if (kind >= 0 && d->with_prog) {
		d->prog = s.prog[kind];
		d->vsize = HV_VM_STD[kind].len;
	}
	hv_r3_vm(&s.e, d);
	if (kind >= 0 && d->blen && d->blen <= 0x3c000u && (kind == HV_VM_E8 || kind == HV_VM_E8E9 || kind == HV_VM_DELTA) && s.nu < 700u && !d->cut &&
	    !d->neg) {
		s.u[s.nu].at = s.e.hn + d->start;
		s.u[s.nu].len = d->blen;
		s.u[s.nu].kind = (unsigned)kind;
		s.u[s.nu].r0 = r0;
		s.u[s.nu].e9 = e9;
		s.nu++;
	}
}

/* Finish and decode with `scratch` (or none): the expected bytes are the plain ones with the uses applied that the output reaches. */
static enum kuncoat_status s_decode(int with_scratch, size_t *want_n, uint8_t *want, uint8_t *got, size_t cap, uint64_t *produced, int finish)
{
	size_t n = finish ? hv_r3_finish(&s.e) : (hv_bw_align_msb(&s.e.w), s.e.w.n), i;

	CK(!s.e.w.over);
	memcpy(want, s.hist, s.e.hn < 40000u ? s.e.hn : 40000u);
	*want_n = s.e.hn;
	for (i = 0; i < s.nu; i++) {
		const struct use *u = &s.u[i];

		if (u->at + u->len > *want_n)
			continue;
		if (u->kind == HV_VM_DELTA)
			ref_delta(want + u->at, (uint32_t)u->len, u->r0);
		else
			ref_e8(want + u->at, (uint32_t)u->len, (uint32_t)u->at, u->e9);
	}
	return kuncoat_rar3_decode(s.out, n, got, cap, with_scratch ? g_scratch : NULL, SCR, produced);
}

static uint8_t want[40000], got[40000];

/* A stream that must decode whole to the filtered expectation. */
static void expect_ok(const char *what, int with_scratch)
{
	size_t wn;
	uint64_t p = 0;
	enum kuncoat_status st = s_decode(with_scratch, &wn, want, got, s.e.hn ? s.e.hn : 1, &p, 1);

	CKF(st == KUNCOAT_OK && p == wn && !memcmp(got, want, wn), "%s: %s, %llu of %zu bytes, %s", what, kuncoat_status_name(st),
	    (unsigned long long)p, wn, !memcmp(got, want, wn < p ? wn : (size_t)p) ? "bytes agree" : "bytes differ");
}

/* A stream that must end with `status`, the bytes before the declaration reported. */
static void expect_status(const char *what, enum kuncoat_status status, int with_scratch, size_t min_prefix)
{
	size_t wn;
	uint64_t p = 0;
	enum kuncoat_status st = s_decode(with_scratch, &wn, want, got, s.e.hn ? s.e.hn : 1, &p, 1);

	CKF(st == status, "%s: %s, wanted %s", what, kuncoat_status_name(st), kuncoat_status_name(status));
	CKF(p >= min_prefix && p <= wn, "%s: %llu bytes before the stop, at least %zu of %zu", what, (unsigned long long)p, min_prefix, wn);
}

static void forged_ok(void)
{
	unsigned k;

	for (k = 0; k < HV_VM_KINDS; k++)
		CKF(s.forged[k], "the forge found no program for kind %u", k);
}

static void filters_run(void)
{
	struct hv_vm_decl d;

	/* E8 over the first 300 bytes */
	s_begin(1);
	forged_ok();
	d = base_decl(1, 0, 300);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(500);
	expect_ok("E8", 0);

	/* E8+E9, start by the +258 form, in the middle of the output */
	s_begin(2);
	s_code(400);
	d = base_decl(1, 300, 200);
	d.flags |= 0x40u;
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8E9, 0, 1);
	s_code(600);
	expect_ok("E8E9 start+258", 0);

	/* the channel delta: three channels in R0, with the mask that carries it (and R1, and the unread registers) */
	s_begin(3);
	d = base_decl(1, 0, 240);
	d.flags |= 0x10u;
	d.mask = 0x7fu;
	d.reg[0] = 3; d.reg[1] = 9; d.reg[2] = 70000; d.reg[3] = 300; d.reg[4] = 17; d.reg[5] = 5; d.reg[6] = 1;
	d.with_prog = 1;
	s_decl(&d, HV_VM_DELTA, 3, 0);
	s_code(400);
	expect_ok("delta with every register", 1);

	/* delta with R0 only, a width of 16 bits for its number */
	s_begin(4);
	d = base_decl(1, 0, 600);
	d.flags |= 0x10u;
	d.mask = 1;
	d.reg[0] = 4;
	d.with_prog = 1;
	s_decl(&d, HV_VM_DELTA, 4, 0);
	s_code(900);
	expect_ok("delta R0", 1);

	/* the first use without the index bit: the index is the last one used (0), a fresh slot */
	s_begin(5);
	d = base_decl(0, 0, 100);
	d.flags = 0x20u;
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(300);
	expect_ok("first use without the index bit", 0);

	/* reuse: the program once, then by index with the bit and without it, the length repeated (no 0x20) */
	s_begin(6);
	d = base_decl(1, 0, 120);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(200);
	d = base_decl(1, 10, 80);                         /* index 1 again: not fresh, no program follows */
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(200);
	memset(&d, 0, sizeof d);                          /* no index, no length: the last index and the last length (80) */
	d.start = 5;
	d.blen = 80;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(300);
	expect_ok("reuse by index", 0);

	/* two programs, used in turn */
	s_begin(7);
	d = base_decl(1, 0, 150);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(160);
	d = base_decl(2, 0, 150);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8E9, 0, 1);
	s_code(160);
	d = base_decl(1, 0, 100);
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(120);
	expect_ok("two programs", 0);
}

static void dropped_run(void)
{
	struct hv_vm_decl d;

	/* a block of length zero: nothing recorded, the stream goes on (even for a program this build does not run) */
	s_begin(10);
	d = base_decl(1, 0, 0);
	d.with_prog = 1;
	s_decl(&d, HV_VM_ITANIUM, 0, 0);
	s_code(200);
	expect_ok("blen 0 (Itanium, dropped)", 0);

	/* ranges never reached are not applied: the start is far away, in the 18 and the 34 bit forms and the small negative form */
	s_begin(11);
	d = base_decl(1, 70000, 100);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	d = base_decl(1, 300, 100);
	s_decl(&d, HV_VM_E8, 0, 0);
	d = base_decl(1, 17, 100);
	d.neg = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(300);
	expect_ok("starts that are never reached", 0);

	/* a range that begins inside the output but runs past it: not applied */
	s_begin(12);
	d = base_decl(1, 100, 4000);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(300);
	expect_ok("range past the end", 0);

	/* a block longer than 255 bytes of code: the length goes as 16 bits (len code 7) */
	s_begin(13);
	d = base_decl(1, 0, 50);
	d.flags |= 0x10u;
	d.mask = 0x7fu;
	{
		unsigned i;

		for (i = 0; i < 7; i++)
			d.reg[i] = 70000u + i;                    /* 34 bit numbers: 7 x 34 bits */
	}
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(100);
	expect_ok("code block of 65 bytes with 34 bit numbers", 0);
}

static void refused_run(void)
{
	struct hv_vm_decl d;
	static const unsigned unsup[4] = { HV_VM_ITANIUM, HV_VM_RGB, HV_VM_AUDIO, HV_VM_UPCASE };
	unsigned k, i;

	s_begin(20);
	d = base_decl(1, 0, 100);
	d.with_prog = 1;
	s_code(50);
	s_decl(&d, HV_VM_DELTA, 3, 0);
	s_code(200);
	expect_status("delta without scratch", KUNCOAT_UNSUPPORTED, 0, 50);

	for (k = 0; k < 4; k++) {
		s_begin(21 + k);
		s_code(50);
		d = base_decl(1, 0, 100);
		d.with_prog = 1;
		s_decl(&d, (int)unsup[k], 0, 0);
		s_code(200);
		expect_status("a recognised program this build does not run", KUNCOAT_UNSUPPORTED, 1, 50);
	}

	/* the right size and a wrong CRC; a wrong first byte */
	for (k = 0; k < 2; k++) {
		s_begin(30 + k);
		s_code(50);
		d = base_decl(1, 0, 100);
		d.with_prog = 1;
		memcpy(s.prog[HV_VM_E8E9], s.prog[HV_VM_E8], HV_VM_STD[HV_VM_E8].len);
		if (k == 0)
			s.prog[HV_VM_E8E9][20] ^= 0x10;                   /* the XOR rule now fails... */
		else
			for (i = 1; i < HV_VM_STD[HV_VM_E8].len; i++)
				s.prog[HV_VM_E8E9][i] ^= 0;
		d.prog = s.prog[HV_VM_E8E9];
		d.vsize = HV_VM_STD[HV_VM_E8].len;
		if (k == 1) {                                          /* ...and here it holds but the CRC does not */
			uint8_t x = 0;

			s.prog[HV_VM_E8E9][20] ^= 0x10;
			for (i = 1; i < d.vsize; i++)
				x ^= s.prog[HV_VM_E8E9][i];
			s.prog[HV_VM_E8E9][0] = x;
		}
		hv_r3_vm(&s.e, &d);
		s_code(200);
		expect_status(k ? "a wrong CRC" : "a wrong XOR byte", KUNCOAT_UNSUPPORTED, 0, 50);
	}

	/* an index past the table */
	s_begin(35);
	s_code(50);
	d = base_decl(5, 0, 100);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(200);
	expect_status("index 5 with no program declared", KUNCOAT_UNSUPPORTED, 0, 50);

	/* the 65th program (RAR3_MAX_PRG is 64) */
	s_begin(36);
	s_code(50);
	for (i = 1; i <= 65; i++) {
		d = base_decl(i, 0, 5);
		d.with_prog = 1;
		s_decl(&d, HV_VM_E8, 0, 0);
	}
	s_code(200);
	expect_status("65 programs", KUNCOAT_UNSUPPORTED, 0, 50);

	/* the 513th use (RAR3_MAX_USES is 512) */
	s_begin(37);
	s_code(50);
	d = base_decl(1, 0, 5);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	for (i = 1; i <= 513; i++) {
		memset(&d, 0, sizeof d);
		d.flags = 0x20u;
		d.start = i;
		d.blen = 5;
		s_decl(&d, HV_VM_E8, 0, 0);
	}
	s_code(200);
	expect_status("513 uses", KUNCOAT_UNSUPPORTED, 0, 50);

	/* a range longer than the VM memory */
	s_begin(38);
	s_code(50);
	d = base_decl(1, 0, 0x3c001u);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(200);
	expect_status("range over the VM memory", KUNCOAT_UNSUPPORTED, 0, 50);

	/* the declaration cut short: the length field says more than is there */
	s_begin(39);
	s_code(50);
	d = base_decl(1, 0, 100);
	d.with_prog = 1;
	d.cut = 3;
	s_decl(&d, HV_VM_E8, 0, 0);
	{
		size_t wn;
		uint64_t p = 0;
		enum kuncoat_status st = s_decode(0, &wn, want, got, s.e.hn + 100u, &p, 0);   /* room for more: the decoder goes on reading */

		CKF(st == KUNCOAT_TRUNCATED || st == KUNCOAT_CORRUPT || st == KUNCOAT_UNSUPPORTED, "a declaration cut short: %s", kuncoat_status_name(st));
		CKF(p <= wn, "a declaration cut short: %llu bytes of %zu", (unsigned long long)p, wn);
	}

	/* a code block longer than the VM's own limit (1024) */
	s_begin(40);
	s_code(50);
	d = base_decl(1, 0, 100);
	d.with_prog = 1;
	d.len_override = 1025;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(200);
	expect_status("code block over 1024 bytes", KUNCOAT_UNSUPPORTED, 0, 50);
}

static void reset_run(void)
{
	struct hv_vm_decl d;

	/* index 0 after a use whose range is still ahead: the use is dropped and the table starts again */
	s_begin(50);
	d = base_decl(1, 100, 100);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8, 0, 0);
	s_code(40);
	s.nu = 0;                                           /* the reset below drops it: the expectation has no use */
	d = base_decl(0, 0, 80);
	d.with_prog = 1;
	s_decl(&d, HV_VM_E8E9, 0, 1);                      /* a reset carries its own program: index 0 then fresh slot 0 */
	s_code(300);
	{
		size_t wn;
		uint64_t p = 0;
		enum kuncoat_status st;
		unsigned i = s.nu;

		(void)i;
		st = s_decode(0, &wn, want, got, s.e.hn ? s.e.hn : 1, &p, 1);
		CKF(st == KUNCOAT_OK && p == wn && !memcmp(got, want, wn), "reset: %s, %llu of %zu", kuncoat_status_name(st), (unsigned long long)p, wn);
	}
}

HV_GROUP(filters_run)
HV_GROUP(dropped_run)
HV_GROUP(refused_run)
HV_GROUP(reset_run)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	hv_expect_clean("rar3 filters", hv_grp_filters_run, NULL, 60);
	hv_expect_clean("rar3 filters dropped and unreached", hv_grp_dropped_run, NULL, 60);
	hv_expect_clean("rar3 filters refused", hv_grp_refused_run, NULL, 60);
	hv_expect_clean("rar3 filter reset", hv_grp_reset_run, NULL, 60);
	return hv_done("cov_rar3_filters");
}
