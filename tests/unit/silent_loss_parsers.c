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
	 * a payload left encoded is a literal no rule can match. There is no quota. */
	CK(count_of(t.p, t.n, "KOFB64", n) == n);
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
	CK(count_of(t.p, t.n, "KOFLONG", 1) == 1);     /* no bound on how long a payload is */
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
	CK(count_of(t.p, t.n, "KOFHEX", n) == n);
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
	CK(count_of(t.p, t.n, "kofq", n) == n);
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
	CK(count_of(t.p, t.n, "KOFPCT", n) == n);
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
	CK(layered(5) == 1u);     /* no count of rounds: a round that peels nothing ends it */
	CK(layered(12) == 1u);
}

/* ---- the one bound the layered decode keeps is a WORK bound, and it speaks ------- */

/* "%" + "25" * (depth - 1) + "41", four of them joined by "-" (a "+" would decode to a space and split the run): one percent decode peels one "25" and leaves the
 * run nearly as long, which is the shape a bound on rounds exists for. */
static void nest_pct(struct tb *t, unsigned depth)
{
	unsigned i;

	tb_puts(t, "%");
	for (i = 1; i < depth; i++)
		tb_puts(t, "25");
	tb_puts(t, "41");
}

static void pct_nest_fixture(struct tb *t, unsigned depth, unsigned filler)
{
	unsigned i;

	tb_puts(t, "x ");
	for (i = 0; i < 4; i++) {
		nest_pct(t, depth);
		tb_puts(t, "-");
	}
	for (i = 0; i < filler; i++)
		tb_puts(t, "a");
	tb_puts(t, "\n");
}

static void case_decode_limit(void)
{
	struct kof_exe_decode_res r;
	struct tb t = { 0 };
	struct tb u = { 0 };

	/* Honest layering ends of itself and reports nothing. */
	pct_nest_fixture(&t, 4, 2000);
	CK(kof_exe_decode_ex(t.p, t.n, &r) != 0);
	CK(r.limit == 0u && r.dropped == 0u && r.rounds >= 2u);
	/* A nest as deep as the object is long peels a layer a round over the whole
	 * run: the budget (eight times the object) ends it, and says so. */
	pct_nest_fixture(&u, 900, 20000);
	CK(kof_exe_decode_ex(u.p, u.n, &r) != 0);
	CK((r.limit & KOF_EXE_DEC_WORK) != 0u);
	CK(r.dropped > 0u && r.scanned <= 8u * u.n);
	free(t.p);
	free(u.p);
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
	CK(n >= 14u && memmem(out, n, "KOFFOLDMARKER!", 14) != NULL);
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
	CK(n == 14u && memmem(out, n, "KOFDEPTHMARKER", 14) != NULL);
	free(t.p);
}

/* ---- folding: what the folder keeps as a bound speaks, and the table is not one -- */

static void case_fold_limit(void)
{
	const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_PHP);
	struct tb t = { 0 };
	struct tb u = { 0 };
	uint8_t out[512];
	uint32_t n, lim = 0;
	unsigned i;
	char line[64];

	/* Five thousand variables ahead of the join: a table, not a bound. */
	tb_puts(&t, "<?php\n");
	for (i = 0; i < 5000u; i++) {
		snprintf(line, sizeof line, "$f%04u='x';\n", i);
		tb_puts(&t, line);
	}
	tb_puts(&t, "$p='KOFFOLD';$q='MARKER!';$r=$p.$q;\n");
	n = kof_script_fold_ex(lx, t.p, (uint32_t)t.n, out, sizeof out, &lim);
	CK(n >= 14u && memmem(out, n, "KOFFOLDMARKER!", 14) != NULL);
	CK(lim == 0u);
	/* A redefinition does not displace the first, as before. */
	tb_puts(&t, "$p='OTHER';$s=$p.$q;\n");
	n = kof_script_fold_ex(lx, t.p, (uint32_t)t.n, out, sizeof out, &lim);
	CK(n >= 14u && lim == 0u);
	/* The recursion bound is stack, kept, and said when it is met. */
	tb_puts(&u, "<?php $a=");
	for (i = 0; i < 300u; i++)
		tb_puts(&u, "str_replace('~','',");
	tb_puts(&u, "'KOF~DEPTH'");
	for (i = 0; i < 300u; i++)
		tb_puts(&u, ")");
	tb_puts(&u, ";\n");
	n = kof_script_fold_ex(lx, u.p, (uint32_t)u.n, out, sizeof out, &lim);
	CK(n == 0u && (lim & KOF_FOLD_DEPTH) != 0u);
	free(t.p);
	free(u.p);
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
	unsigned n = 4106u, i;      /* the fixed table was 4096 */
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
	/*
	 * The table is as long as the directory, so no count of entries is a limit: with no
	 * ledger set (a caller that keeps no account) every one is read and nothing is "full".
	 * What can stop the walk is the ledger, and it REPORTS: the room below holds a couple of thousand
	 * hundred rows, so the walk ends there with ENTRIES_FULL and the account never
	 * passed what it was given.
	 */
	CK(kof_zip_parse(kof_buf_make(f, at), z, &ctx) != 0);
	CK(z->n_entries == n && !(z->anomalies & KOF_ZIP_ANOM_ENTRIES_FULL));
	z->mem.room = 128u * 1024u;
	CK(kof_zip_parse(kof_buf_make(f, at), z, &ctx) != 0);
	CK(z->n_entries > 0u && z->n_entries < n);
	CK((z->anomalies & KOF_ZIP_ANOM_ENTRIES_FULL) != 0);   /* REPORTS: the parse flag */
	CK(z->mem.held <= 128u * 1024u);
	kof_zip_release(z);
	free(z);
	free(f);

	{
		/* tar, the same way: no count is a limit, the ledger is, and it REPORTS */
		struct kof_tar_info *t = calloc(1, sizeof *t);
		unsigned m = 2048u + 10u, k, sum, j;
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
		CK(t->n_entries == m && !(t->anomalies & (KOF_TAR_ANOM_ENTRIES_FULL | KOF_TAR_ANOM_EXTENTS_FULL)));
		t->mem.room = 64u * 1024u;
		CK(kof_tar_parse(kof_buf_make(g, k), t, &ctx) != 0);
		CK(t->n_entries > 0u && t->n_entries < m);
		CK((t->anomalies & (KOF_TAR_ANOM_ENTRIES_FULL | KOF_TAR_ANOM_EXTENTS_FULL)) != 0);  /* REPORTS */
		CK(t->mem.held <= 64u * 1024u);
		kof_tar_release(t);
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
	case_fold_limit();
	case_decode_limit();
	case_reg_extents();
	case_zip_tar_flag();
	return fails != 0 || km_failed();
}
