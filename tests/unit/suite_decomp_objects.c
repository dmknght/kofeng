/*
 * suite_decomp_objects - the engine's decompress glue (libkofeng/scanners/objctx_decomp_*.c) driven the way a scan drives it: a
 * container whose stream carries a CODING CHAIN is opened by the real module and the child's bytes are compared with the plain text.
 *
 * Reached through a PDF (the stream's /Filter array) and an RTF (\objdata hex): the codings that are text on the way in (ASCII85,
 * ASCIIHex, RunLength, RTF hex), LZW, Flate, and chains of them. What the unit tests of the lib say about each decoder is not repeated
 * here; this is the dispatch, the chain runner (oc_unpack_chain: every step but the last decodes into a buffer, the last streams) and
 * what each refusal of it REPORTS.
 *
 *   CODINGS     one coding alone, each of the six: the child is the plain text
 *   CHAINS      ascii85 then flate (a zlib stream), asciihex then ascii85 then flate (an intermediate that is released before the
 *               next is made), four steps (the most a chain holds), and the same text through an RTF hex blob with whitespace, a
 *               nested group, control words and control symbols between the digits
 *   REFUSED     flate in the MIDDLE of a chain (its output cannot be sized from its input): UNSUPPORTED and no child; a chain that
 *               ends in something other than flate over an intermediate: UNSUPPORTED; a middle step that disagrees with its coding
 *               (a character ascii85 does not have): DAMAGED and no child; a middle step that decodes to nothing: DAMAGED
 *   CEILING     a chain whose intermediate does not fit what the resident allowance has left: LIMIT, counted in limit_hits, no
 *               child, and the next object of the SAME scanner (a clean one) still opens
 *
 * Needs the built database (the unpackers are modules in it): run from the repository root after make.
 */
#define _GNU_SOURCE

#include "../lib/uncoat/hostile_common.h"
#undef CK
#include "hostile_engine.h"
#include "decomp_fixtures.h"

struct got {
	char     name[200];
	uint64_t len;
	uint32_t broken;
	uint8_t  head[4096];
};

static struct got G[64];
static unsigned NG;

static int cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	(void)user;
	if (NG < 64) {
		snprintf(G[NG].name, sizeof G[NG].name, "%s", name);
		G[NG].len = len;
		G[NG].broken = res->broken;
		if (bytes)
			memcpy(G[NG].head, bytes, len < sizeof G[NG].head ? (size_t)len : sizeof G[NG].head);
		NG++;
	}
	return 0;
}

static const uint8_t PLAIN[] = "decoded stream payload: kernel socket connect loader stage VirtualAlloc /bin/sh http://example.invalid/a.bin 0123456789";
#define PN (sizeof PLAIN - 1u)

static void pdf(struct he_w *w, const char *filt, const uint8_t *d, size_t n)
{
	w->n = 0;
	he_str(w, "%PDF-1.4\n1 0 obj\n<< /Length 9999 /Filter ");
	he_str(w, filt);
	he_str(w, " >>\nstream\n");
	he_put(w, d, n);
	he_str(w, "\nendstream\nendobj\n");
}

static kof_engine *eng;
static kof_scanner *sc;

static void scan(const struct he_w *w, const char *root, uint64_t resident)
{
	struct kof_scan_option o;

	memset(&o, 0, sizeof o);
	o.heur_level = 1;
	o.emu_forbidden = 1;
	o.max_object_depth = 8;
	o.max_produced_bytes = 64u << 20;
	o.max_object_bytes = 16u << 20;
	o.max_resident_bytes = resident;
	NG = 0;
	(void)kscan_bytes(sc, w->p, w->n, root, &o, cb, NULL);
}

/* The child of the scan that is exactly `want` (and the broken reason of the root). */
static int find_child(const uint8_t *want, size_t n)
{
	unsigned i;

	for (i = 1; i < NG; i++)
		if (G[i].len == n && !memcmp(G[i].head, want, n < sizeof G[i].head ? n : sizeof G[i].head))
			return 1;
	return 0;
}

static void expect_child(const char *what, const struct he_w *w, const uint8_t *want, size_t n)
{
	scan(w, "x.pdf", 256u << 20);
	CK(find_child(want, n), "%s: no child holds the plain text (%u objects, root broken %u)", what, NG, NG ? G[0].broken : 99u);
	CK(NG && G[0].broken == 0, "%s: the root says broken %u", what, NG ? G[0].broken : 99u);
}

static void expect_refused(const char *what, const struct he_w *w, unsigned broken)
{
	scan(w, "x.pdf", 256u << 20);
	CK(NG == 1, "%s: %u objects, wanted only the root", what, NG);
	CK(NG && G[0].broken == broken, "%s: the root says broken %u, wanted %u", what, NG ? G[0].broken : 99u, broken);
}

static void codings(void)
{
	static uint8_t t[4096];
	struct he_w w = { 0 };
	size_t n;

	n = hv_a85_enc(PLAIN, PN, t, sizeof t, 0);
	pdf(&w, "/ASCII85Decode", t, n);
	expect_child("ascii85 alone", &w, PLAIN, PN);
	n = hv_a85_enc(PLAIN, PN, t, sizeof t, 20);                        /* wrapped lines */
	pdf(&w, "/ASCII85Decode", t, n);
	expect_child("ascii85 with line breaks", &w, PLAIN, PN);
	n = hv_ahx_enc(PLAIN, PN, t, sizeof t, 0);
	pdf(&w, "/ASCIIHexDecode", t, n);
	expect_child("asciihex alone", &w, PLAIN, PN);
	n = hv_ahx_enc(PLAIN, PN, t, sizeof t, ' ');
	pdf(&w, "/ASCIIHexDecode", t, n);
	expect_child("asciihex with spaces", &w, PLAIN, PN);
	n = hv_rle_enc(PLAIN, PN, t, sizeof t);
	pdf(&w, "/RunLengthDecode", t, n);
	expect_child("runlength alone", &w, PLAIN, PN);
	n = hv_lzw_enc(PLAIN, PN, t, sizeof t);
	pdf(&w, "/LZWDecode", t, n);
	expect_child("lzw alone", &w, PLAIN, PN);
	n = zlib_stored(PLAIN, PN, t, sizeof t);
	pdf(&w, "/FlateDecode", t, n);
	expect_child("flate alone", &w, PLAIN, PN);
	free(w.p);
}

static void chains(void)
{
	static uint8_t z[1024], a[2048], h[4096], h2[8192], h3[16384];
	struct he_w w = { 0 };
	size_t nz = zlib_stored(PLAIN, PN, z, sizeof z), na = hv_a85_enc(z, nz, a, sizeof a, 0), nh = hv_ahx_enc(a, na, h, sizeof h, 0);

	pdf(&w, "[/ASCII85Decode /FlateDecode]", a, na);
	expect_child("ascii85 then flate", &w, PLAIN, PN);
	pdf(&w, "[/ASCIIHexDecode /ASCII85Decode /FlateDecode]", h, nh);
	expect_child("asciihex, ascii85, flate", &w, PLAIN, PN);
	{
		size_t nh2 = hv_ahx_enc(h, nh, h2, sizeof h2, 0), nh3 = hv_ahx_enc(h2, nh2, h3, sizeof h3, 0);

		pdf(&w, "[/ASCIIHexDecode /ASCIIHexDecode /ASCIIHexDecode /ASCII85Decode]", h3, nh3);
		scan(&w, "x.pdf", 256u << 20);
		/* four codings is the most a chain holds: this chain ends in ascii85, not flate, over an intermediate: refused, said */
		CK(NG == 1 && G[0].broken == KOF_BROKEN_UNSUPPORTED, "hex x3 then ascii85: %u objects, broken %u", NG, NG ? G[0].broken : 99u);
		/* the same four with flate last: the text of the zlib stream, three hex layers over ascii85: hex hex ascii85 flate */
		pdf(&w, "[/ASCIIHexDecode /ASCIIHexDecode /ASCII85Decode /FlateDecode]", h2, nh2);
		expect_child("hex, hex, ascii85, flate", &w, PLAIN, PN);
	}
	free(w.p);
}

static void refused(void)
{
	static uint8_t z[1024], a[2048], t[2048];
	struct he_w w = { 0 };
	size_t nz = zlib_stored(PLAIN, PN, z, sizeof z), na = hv_a85_enc(z, nz, a, sizeof a, 0), n;

	pdf(&w, "[/FlateDecode /ASCII85Decode]", a, na);
	expect_refused("flate in the middle", &w, KOF_BROKEN_UNSUPPORTED);
	n = hv_a85_enc(PLAIN, PN, t, sizeof t, 0);
	pdf(&w, "[/ASCII85Decode /RunLengthDecode]", t, n);
	expect_refused("ascii85 then runlength (not flate over an intermediate)", &w, KOF_BROKEN_UNSUPPORTED);
	memcpy(t, a, na);
	t[3] = '~';                                                         /* a character ascii85 does not have, inside the text */
	pdf(&w, "[/ASCII85Decode /FlateDecode]", t, na);
	expect_refused("a middle step that is not its coding", &w, KOF_BROKEN_DAMAGED);
	pdf(&w, "[/ASCII85Decode /FlateDecode]", (const uint8_t *)"~>", 2);
	expect_refused("a middle step that decodes to nothing", &w, KOF_BROKEN_DAMAGED);
	free(w.p);
}

/* RTF: a blob of hex between control words, one group nested inside it, the digits split by whitespace. */
static void rtf_hex(void)
{
	struct he_w w = { 0 };
	static uint8_t bin[256], flat[2];
	size_t i;
	char hex[3];
	unsigned k;

	for (i = 0; i < sizeof bin; i++)
		bin[i] = (uint8_t)(i * 7u + 3u);
	(void)flat;
	for (k = 0; k < 2; k++) {
		w.n = 0;
		he_str(&w, "{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata ");
		for (i = 0; i < sizeof bin; i++) {
			snprintf(hex, sizeof hex, "%02x", bin[i]);
			he_put(&w, hex, 2);
			if (k && i % 17 == 3)
				he_str(&w, " \r\n\t");
			if (k && i % 31 == 5)
				he_str(&w, "\\par ");                                    /* a control word, with the space that ends it */
			if (k && i % 43 == 7)
				he_str(&w, "\\*");                                       /* a control symbol */
			if (k && i % 59 == 11)
				he_str(&w, "{\\*\\bin0 deadbeef{nested}} ");              /* a group, skipped whole */
			if (k && i % 71 == 13)
				he_str(&w, "\\x-12 ");                                   /* a word with a negative number */
		}
		he_str(&w, "}}}");
		scan(&w, "x.rtf", 256u << 20);
		CK(find_child(bin, sizeof bin), "rtf hex blob (%s): no child holds the %zu bytes (%u objects)", k ? "with noise" : "plain", sizeof bin, NG);
	}
	free(w.p);
}

static int said_limit(uint64_t hits0)
{
	return kscan_stats(sc)->limit_hits > hits0 || (NG && G[0].broken == KOF_BROKEN_LIMIT);
}

/*
 * The resident allowance runs out part way through a chain. oc_unpack_chain charges the intermediate (it is the size of the
 * input) and the last step streams into the sink, which is charged as it fills: the answer is a prefix of the plain text and the
 * object SAYS it was cut (KOF_BROKEN_LIMIT on the root, or limit_hits). Then the same scanner, the allowance back, opens a small
 * chain whole: nothing is left stuck.
 */
static void ceiling(void)
{
	static uint8_t big[1u << 20], z[(1u << 20) + 4096], a[(1u << 20) * 2], plain_a[8000];
	struct he_w w = { 0 }, small = { 0 };
	size_t nz, na, i;
	static const uint64_t res[] = { 1572864u, 2097152u };
	unsigned k;

	for (i = 0; i < sizeof big; i++)
		big[i] = (uint8_t)('a' + (i * 7u + (i >> 8)) % 26u);
	nz = zlib_stored(big, sizeof big, z, sizeof z);
	na = hv_a85_enc(z, nz, a, sizeof a, 0);
	pdf(&w, "[/ASCII85Decode /FlateDecode]", a, na);
	{
		size_t n = hv_a85_enc(PLAIN, PN, plain_a, sizeof plain_a, 0);

		pdf(&small, "/ASCII85Decode", plain_a, n);
	}
	for (k = 0; k < sizeof res / sizeof res[0]; k++) {
		uint64_t hits0 = kscan_stats(sc)->limit_hits;

		scan(&w, "x.pdf", res[k]);
		CK(said_limit(hits0), "ceiling %llu: the cut is not said (root broken %u, limit_hits %llu)", (unsigned long long)res[k], NG ? G[0].broken : 99u,
		   (unsigned long long)kscan_stats(sc)->limit_hits);
		if (NG > 1) {
			CK(G[1].len < sizeof big, "ceiling %llu: the child holds %llu bytes, the whole is %zu", (unsigned long long)res[k], (unsigned long long)G[1].len, sizeof big);
			CK(!memcmp(G[1].head, big, G[1].len < sizeof G[1].head ? (size_t)G[1].len : sizeof G[1].head), "ceiling %llu: the child is not the beginning of the text", (unsigned long long)res[k]);
		}
		scan(&small, "y.pdf", 256u << 20);
		CK(find_child(PLAIN, PN) && G[0].broken == 0, "after a ceiling: the next object does not open whole (%u objects)", NG);
	}
	scan(&w, "x.pdf", 64u << 20);
	CK(NG == 2 && G[1].len == sizeof big && G[0].broken == 0 && !memcmp(G[1].head, big, sizeof G[1].head), "the same chain under 64 MiB is not whole (%u objects, %llu bytes)", NG, NG > 1 ? (unsigned long long)G[1].len : 0ull);
	/* a85 ALONE, longer than what is left: refused before the buffer is made (len > room) */
	{
		uint64_t hits0 = kscan_stats(sc)->limit_hits;

		na = hv_a85_enc(big, sizeof big, a, sizeof a, 0);
		pdf(&w, "/ASCII85Decode", a, na);
		scan(&w, "x.pdf", 2097152u);
		CK(said_limit(hits0) && NG == 1, "ascii85 alone over the ceiling: %u objects, root broken %u", NG, NG ? G[0].broken : 99u);
	}
	free(w.p);
	free(small.p);
}

static int run_all(void *arg)
{
	(void)arg;
	eng = keng_open("build/release/databases");
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		printf("suite_decomp_objects: no database (run from the repository root after make): nothing tested\n");
		return 1;
	}
	codings();
	chains();
	refused();
	rtf_hex();
	ceiling();
	kscan_free(sc);
	keng_close(eng);
	return he_fails ? 1 : 0;
}

int main(void)
{
	struct he_status st = he_child(run_all, NULL, 120);

	if (!st.exited || st.code) {
		printf("suite_decomp_objects: FAILED (exited %d code %d signal %d)\n", st.exited, st.code, st.sig);
		return 1;
	}
	printf("suite_decomp_objects: ok\n");
	return 0;
}
