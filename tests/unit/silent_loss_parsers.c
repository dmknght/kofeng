/*
 * silent_loss_parsers - the bounds of the normalisers and parsers: past one, the
 * result is either complete or says it is not.
 *
 * Two kinds of case live here, and they are told apart by what the product does
 * today. A bound that SAYS it was hit (a parse anomaly bit) is a CK. A bound that
 * drops the rest without a word is a KM_CHECK: it is evaluated every run, prints
 * KNOWN-MISS while the product loses the evidence, and turns the run red the day
 * the product stops - the marker must then become a CK.
 *
 * The decoders in analyzers/normalize/executables.c are the ones that matter most
 * here: they rewrite an encoded payload to its plain text so a literal can match,
 * each pass has a payload quota, and what the quota leaves is neither decoded nor
 * flagged. Every fixture is built in memory from bytes.
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofmod/script.h"
#include "../../libkofeng/kofcore/kofmod/zip.h"
#include "../../libkofeng/kofcore/kofmod/tar.h"
#include "../../libkofeng/kofcore/kofmod/reg.h"
#include "../../libkofeng/analyzers/normalize/executables.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_norm.h"
#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/reg_parse.h"
#include "known_miss.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* ---- a growing text buffer -------------------------------------------------- */

struct tb {
	uint8_t *p;
	size_t n, cap;
};

static void tb_put(struct tb *t, const void *s, size_t n)
{
	if (t->n + n + 1u > t->cap) {
		t->cap = (t->n + n + 1u) * 2u;
		t->p = realloc(t->p, t->cap);
		if (!t->p)
			exit(1);
	}
	memcpy(t->p + t->n, s, n);
	t->n += n;
	t->p[t->n] = 0;
}

static void tb_puts(struct tb *t, const char *s)
{
	tb_put(t, s, strlen(s));
}

/* Standard base64 with padding, into a malloc'd string. */
static char *b64(const uint8_t *in, size_t n)
{
	static const char A[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *o = malloc((n + 2u) / 3u * 4u + 1u), *w = o;
	size_t i;

	for (i = 0; i < n; i += 3u) {
		uint32_t v = (uint32_t)in[i] << 16;

		if (i + 1u < n)
			v |= (uint32_t)in[i + 1u] << 8;
		if (i + 2u < n)
			v |= in[i + 2u];
		*w++ = A[(v >> 18) & 63u];
		*w++ = A[(v >> 12) & 63u];
		*w++ = i + 1u < n ? A[(v >> 6) & 63u] : '=';
		*w++ = i + 2u < n ? A[v & 63u] : '=';
	}
	*w = 0;
	return o;
}

static unsigned count_of(const uint8_t *p, size_t n, const char *prefix, unsigned total)
{
	unsigned i, found = 0;
	char want[32];

	for (i = 0; i < total; i++) {
		snprintf(want, sizeof want, "%s%03u", prefix, i);
		if (memmem(p, n, want, strlen(want)))
			found++;
	}
	return found;
}

/* ---- base64: B64_MAX_PAY = 8 payloads a pass ---------------------------------- */

static void case_b64_quota(unsigned n)
{
	struct tb t = { 0 };
	unsigned i;
	char plain[48], line[160];

	for (i = 0; i < n; i++) {
		char *e;

		snprintf(plain, sizeof plain, "KOFB64%03u-and-some-padding-text", i);
		e = b64((const uint8_t *)plain, strlen(plain));
		snprintf(line, sizeof line, "echo %s | base64 -d | sh\n", e);
		tb_puts(&t, line);
		free(e);
	}
	CK(kof_exe_unb64(t.p, t.n) != 0);
	/* Every command carries its payload, so every payload has to come out plain -
	 * a payload left encoded is a literal no rule can match, and nothing said so. */
	if (n <= 6u)
		CK(count_of(t.p, t.n, "KOFB64", n) == n);     /* the fixture decodes under the quota */
	else
		KM_CHECK(count_of(t.p, t.n, "KOFB64", n) == n,
			 "12 `base64 -d` commands in one object: all 12 payloads decoded",
			 "B64_MAX_PAY executables.c:284 lost: payloads after the 8th in a range stay encoded, no signal");
	free(t.p);
}

/* ---- base64: B64_PAY_MAX = 64K characters of payload --------------------------- */

static void case_b64_long(size_t plen)
{
	struct tb t = { 0 };
	uint8_t *plain = malloc(plen);
	char *e;
	size_t i;

	for (i = 0; i < plen; i++)
		plain[i] = (uint8_t)('a' + i % 23u);
	memcpy(plain, "KOFLONG000", 10);
	e = b64(plain, plen);
	tb_puts(&t, "echo ");
	tb_put(&t, e, strlen(e));
	tb_puts(&t, " | base64 -d | sh\n");
	(void)kof_exe_unb64(t.p, t.n);
	if (plen < 40000u)
		CK(count_of(t.p, t.n, "KOFLONG", 1) == 1);     /* the fixture decodes under the bound */
	else
		KM_CHECK(count_of(t.p, t.n, "KOFLONG", 1) == 1,
			 "a 90000 byte payload piped to `base64 -d` is decoded",
			 "B64_PAY_MAX executables.c:274 lost: a payload over 65536 characters is not decoded, no signal");
	free(e);
	free(plain);
	free(t.p);
}

/* ---- hex: HEX_MAX_PAY = 32 bare payloads a pass ------------------------------- */

static void case_hex_quota(unsigned n)
{
	struct tb t = { 0 };
	unsigned i, k;
	char plain[40], line[200];

	for (i = 0; i < n; i++) {
		char hx[100];

		snprintf(plain, sizeof plain, "KOFHEX%03u-payload-text-here", i);
		for (k = 0; k < strlen(plain); k++)
			snprintf(hx + 2u * k, 3, "%02x", (unsigned)(uint8_t)plain[k]);
		snprintf(line, sizeof line, "x %s\n", hx);
		tb_puts(&t, line);
	}
	CK(kof_exe_unhex(t.p, t.n) != 0);
	if (n <= 20u)
		CK(count_of(t.p, t.n, "KOFHEX", n) == n);
	else
		KM_CHECK(count_of(t.p, t.n, "KOFHEX", n) == n,
			 "40 hex-spelled strings in one object: all 40 decoded",
			 "HEX_MAX_PAY executables.c:877 lost: bare hex payloads after the 32nd stay encoded, no signal");
	free(t.p);
}

/* ---- hex: HEXQ_MAX = 64 quoted literals put aside a range --------------------- */

static void case_hex_quoted(unsigned n)
{
	struct tb t = { 0 };
	unsigned i, k;
	char plain[16], line[80];

	tb_puts(&t, "<?php $T = [\n");
	for (i = 0; i < n; i++) {
		char hx[40];

		snprintf(plain, sizeof plain, "kofq%03u", i);
		for (k = 0; k < strlen(plain); k++)
			snprintf(hx + 2u * k, 3, "%02x", (unsigned)(uint8_t)plain[k]);
		snprintf(line, sizeof line, "  '%s',\n", hx);
		tb_puts(&t, line);
	}
	tb_puts(&t, "];\n");
	CK(kof_exe_unhex(t.p, t.n) != 0);
	if (n <= 40u)
		CK(count_of(t.p, t.n, "kofq", n) == n);
	else
		KM_CHECK(count_of(t.p, t.n, "kofq", n) == n,
			 "80 hex-spelled quoted literals: all 80 decoded",
			 "HEXQ_MAX executables.c:964 lost: quoted hex literals after the 64th in a range stay encoded, no signal");
	free(t.p);
}

/* ---- percent text: PCT_MAX_PAY = 32 runs a pass ------------------------------- */

static void case_pct_quota(unsigned n)
{
	struct tb t = { 0 };
	unsigned i, k;
	char plain[24], line[160];

	for (i = 0; i < n; i++) {
		char e[100];

		snprintf(plain, sizeof plain, "KOFPCT%03u-abc", i);
		for (k = 0; k < strlen(plain); k++)
			snprintf(e + 3u * k, 4, "%%%02X", (unsigned)(uint8_t)plain[k]);
		snprintf(line, sizeof line, "%s\n", e);
		tb_puts(&t, line);
	}
	CK(kof_exe_decode(t.p, t.n) != 0);
	if (n <= 20u)
		CK(count_of(t.p, t.n, "KOFPCT", n) == n);
	else
		KM_CHECK(count_of(t.p, t.n, "KOFPCT", n) == n,
			 "40 percent-escaped strings in one object: all 40 decoded",
			 "PCT_MAX_PAY executables.c:1189 lost: percent-escaped runs after the 32nd stay encoded, no signal");
	free(t.p);
}

/* ---- layers: DEC_MAX_ROUND = 4 ------------------------------------------------- */

static unsigned layered(unsigned layers)
{
	char *cur = strdup("KOFLAYER-innermost-payload-text");
	struct tb t = { 0 };
	unsigned i, found;

	for (i = 0; i < layers; i++) {
		char *e = b64((const uint8_t *)cur, strlen(cur));
		char *next = malloc(strlen(e) + 40u);

		snprintf(next, strlen(e) + 40u, "echo %s | base64 -d", e);
		free(e);
		free(cur);
		cur = next;
	}
	tb_puts(&t, cur);
	tb_puts(&t, "\n");
	(void)kof_exe_decode(t.p, t.n);
	found = memmem(t.p, t.n, "KOFLAYER", 8) != NULL;
	free(cur);
	free(t.p);
	return found;
}

static void case_rounds(void)
{
	/* The first layer is the command line itself; each decode peels one. */
	CK(layered(3) == 1u);
	CK(layered(4) == 1u);     /* four rounds are enough for four layers */
	KM_CHECK(layered(5) == 1u,
		 "a payload wrapped in five base64 layers is peeled to the bottom",
		 "DEC_MAX_ROUND executables.c:1144 lost: layers past the 4th round stay encoded, no signal");
}

/* ---- script folding: FOLD_MAX_VARS = 64 ---------------------------------------- */

static void case_fold_vars(unsigned fill)
{
	struct tb t = { 0 };
	const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_PHP);
	uint8_t out[1024];
	unsigned i;
	uint32_t n;
	char line[64];

	tb_puts(&t, "<?php\n");
	for (i = 0; i < fill; i++) {
		snprintf(line, sizeof line, "$f%02u='x';\n", i);
		tb_puts(&t, line);
	}
	tb_puts(&t, "$p='KOFFOLD';$q='MARKER!';$r=$p.$q;\n");
	n = kof_script_fold(lx, t.p, (uint32_t)t.n, out, sizeof out);
	CK(lx != NULL);
	if (fill < 20u) {
		CK(n >= 14u && memmem(out, n, "KOFFOLDMARKER!", 14) != NULL);
	} else
	KM_CHECK(n >= 14u && memmem(out, n, "KOFFOLDMARKER!", 14) != NULL,
		 "a constant built from two variables defined after 64 other variables is folded",
		 "FOLD_MAX_VARS script_norm.c:1077 lost: the 65th and later variable is not remembered, the join built from it is not folded, no signal");
	free(t.p);
}


/* ---- script folding: FOLD_MAX_DEPTH = 16 ---------------------------------------- */

static void case_fold_depth(unsigned levels)
{
	struct tb t = { 0 };
	const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_PHP);
	uint8_t out[512];
	unsigned i;
	uint32_t n;

	tb_puts(&t, "<?php $a=");
	for (i = 0; i < levels; i++)
		tb_puts(&t, "str_replace('~','',");
	tb_puts(&t, "'KOF~DEPTH~MARKER'");
	for (i = 0; i < levels; i++)
		tb_puts(&t, ")");
	tb_puts(&t, ";\n");
	n = kof_script_fold(lx, t.p, (uint32_t)t.n, out, sizeof out);
	if (levels <= 8u)
		CK(n == 14u && memmem(out, n, "KOFDEPTHMARKER", 14) != NULL);
	else
		KM_CHECK(n == 14u && memmem(out, n, "KOFDEPTHMARKER", 14) != NULL,
			 "str_replace nested 24 deep around a constant is folded",
			 "FOLD_MAX_DEPTH script_norm.c:1078 lost: a statement nested past 16 levels is not folded, no signal");
	free(t.p);
}

/* ---- reg: KOF_REG_MAX_EXTENTS = 2048 -------------------------------------------- */

static void case_reg_extents(void)
{
	struct tb t = { 0 };
	struct kof_reg_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx ctx;
	char line[160];
	unsigned i;

	tb_puts(&t, "Windows Registry Editor Version 5.00\r\n\r\n");
	for (i = 0; i < 1200; i++) {
		snprintf(line, sizeof line,
			 "[HKEY_LOCAL_MACHINE\\Software\\K%04u]\r\n\"v\"=\"x\"\r\n\r\n", i);
		tb_puts(&t, line);
	}
	memset(&ctx, 0, sizeof ctx);
	CK(kof_reg_parse(kof_buf_make(t.p, t.n), info, &ctx) != 0);
	/* REPORTS: the parse sets the bit. [Inference] It is a per-format info word the
	 * viewer prints; it is not copied into kof_result. */
	CK((info->anomalies & KOF_REG_ANOM_EXTENTS_FULL) != 0);
	free(info);
	free(t.p);
}

/* ---- zip and tar: the parse names the cap it hit -------------------------------- */

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v) { le16(p, v & 0xffffu); le16(p + 2, v >> 16); }

static void case_zip_tar_flag(void)
{
	unsigned n = KOF_ZIP_MAX_ENTRIES + 10u, i;
	size_t cap = (size_t)n * 160u + 64u, at = 0, cd;
	uint8_t *f = calloc(1, cap);
	struct kof_zip_info *z = calloc(1, sizeof *z);
	struct kof_obj_ctx ctx;
	char name[16];

	memset(&ctx, 0, sizeof ctx);
	for (i = 0; i < n; i++) {                 /* stored, 8 bytes each */
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", i);

		le32(f + at, 0x04034b50u);
		le16(f + at + 4, 10);
		le32(f + at + 18, 8);
		le32(f + at + 22, 8);
		le16(f + at + 26, nl);
		memcpy(f + at + 30, name, nl);
		at += 30u + nl + 8u;
	}
	cd = at;
	{
		size_t lo = 0;

		for (i = 0; i < n; i++) {
			unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", i);

			le32(f + at, 0x02014b50u);
			le16(f + at + 4, 20);
			le16(f + at + 6, 10);
			le32(f + at + 20, 8);
			le32(f + at + 24, 8);
			le16(f + at + 28, nl);
			le32(f + at + 42, (uint32_t)lo);
			memcpy(f + at + 46, name, nl);
			at += 46u + nl;
			lo += 30u + nl + 8u;
		}
	}
	le32(f + at, 0x06054b50u);
	le16(f + at + 8, n);
	le16(f + at + 10, n);
	le32(f + at + 12, (uint32_t)(at - cd));
	le32(f + at + 16, (uint32_t)cd);
	at += 22u;
	CK(kof_zip_parse(kof_buf_make(f, at), z, &ctx) != 0);
	CK(z->n_entries == KOF_ZIP_MAX_ENTRIES);
	CK((z->anomalies & KOF_ZIP_ANOM_ENTRIES_FULL) != 0);   /* REPORTS: the parse flag */
	free(z);
	free(f);

	{
		struct kof_tar_info *t = calloc(1, sizeof *t);
		unsigned m = KOF_TAR_MAX_ENTRIES + 10u, k, sum, j;
		uint8_t *g = calloc((size_t)m + 2u, 1024u);

		memset(&ctx, 0, sizeof ctx);
		for (i = 0; i < m; i++) {
			uint8_t *h = g + (size_t)i * 1024u;

			snprintf((char *)h, 100, "t%05u", i);
			memcpy(h + 100, "0000644", 8);
			memcpy(h + 124, "00000000001", 12);
			memset(h + 148, ' ', 8);
			h[156] = '0';
			memcpy(h + 257, "ustar", 6);
			memcpy(h + 263, "00", 2);
			for (sum = 0, j = 0; j < 512u; j++)
				sum += h[j];
			snprintf((char *)h + 148, 8, "%06o", sum);
			h[155] = ' ';
			h[512] = 'x';
		}
		k = m * 1024u + 1024u;
		CK(kof_tar_parse(kof_buf_make(g, k), t, &ctx) != 0);
		CK((t->anomalies & KOF_TAR_ANOM_ENTRIES_FULL) != 0);  /* REPORTS */
		free(g);
		free(t);
	}
}

int main(void)
{
	case_b64_quota(6);
	case_b64_quota(12);
	case_b64_long(30000u);
	case_b64_long(90000u);
	case_hex_quota(20);
	case_hex_quota(40);
	case_hex_quoted(20);
	case_hex_quoted(80);
	case_pct_quota(20);
	case_pct_quota(40);
	case_rounds();
	case_fold_vars(10);
	case_fold_vars(70);
	case_fold_depth(6);
	case_fold_depth(24);
	case_reg_extents();
	case_zip_tar_flag();
	return fails != 0 || km_failed();
}
