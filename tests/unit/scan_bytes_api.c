/*
 * scan_bytes_api - kscan_bytes, the public wrapper that scans a buffer the
 * caller already has (kofeng.h; the viewer re-asks one object of a tree it has
 * built).
 *
 * WHAT IT PROMISES, each one a way it was or could be wrong:
 *
 *   ARGUMENTS     a NULL scanner, a NULL buffer, or no bytes is KOF_ERR_ARG and the
 *                 callback is not called - not a crash and not a scan of nothing.
 *   THE NAME      is what the callback reports for the top object; NULL is "" and
 *                 is accepted; a NULL option is the conservative defaults.
 *   THE COUNT     the return value is the number of objects the callback saw.
 *   BORROWED      the caller's bytes are neither copied-and-lost nor written: the
 *                 buffer is the same after the scan, whatever it held.
 *   THE SAME AS A FILE  the bytes scanned as a buffer and as a file at a path
 *                 (kscan_path) give the same objects and the same verdict. A
 *                 wrapper with its own idea of what a buffer is would be a second
 *                 scanner.
 *   REPEATABLE    scanning twice on one scanner, and a refused call in between,
 *                 gives the same answer: nothing the wrapper keeps leaks from
 *                 one call to the next.
 */

#include "caps_fix.h"
#include "caps_e2e.h"

static uint8_t img[1u << 16];
static uint8_t keep[1u << 16];
static uint8_t code[4096];

struct seen {
	unsigned n;
	char name0[96];
	char verdict0[112];
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t i;

	(void)bytes; (void)len;
	if (!s->n) {
		snprintf(s->name0, sizeof s->name0, "%s", name ? name : "(null)");
		if (res->has_verdict)
			snprintf(s->verdict0, sizeof s->verdict0, "%s", res->verdict.name);
	}
	s->n++;
	return 0;
}

static void opts(struct kof_scan_option *o)
{
	memset(o, 0, sizeof *o);
	o->max_produced_bytes = 64u << 20;
	o->max_resident_bytes = 256u << 20;
	o->max_object_bytes = 64u << 20;
}

int main(void)
{
	struct kof_scan_option opt;
	struct seen s, f;
	uint64_t len;
	unsigned n = cf_stager64(code, 0);
	kof_scanner *sc;
	FILE *fp;
	int rc, rc2;
	const char *path = "build/test/scan_bytes_api.tmp";

	CK(e2e_open(NULL));
	sc = e2e_sc;
	if (!sc)
		return 1;
	len = cf_elf64(img, sizeof img, code, n);
	memcpy(keep, img, (size_t)len);
	opts(&opt);

	/* arguments */
	memset(&s, 0, sizeof s);
	CK(kscan_bytes(NULL, img, len, "x", &opt, on_object, &s) == KOF_ERR_ARG);
	CK(kscan_bytes(sc, NULL, len, "x", &opt, on_object, &s) == KOF_ERR_ARG);
	CK(kscan_bytes(sc, img, 0, "x", &opt, on_object, &s) == KOF_ERR_ARG);
	CK(s.n == 0);

	/* the name, the count, the verdict */
	memset(&s, 0, sizeof s);
	rc = kscan_bytes(sc, img, len, "my-buffer", &opt, on_object, &s);
	CK(rc > 0 && (unsigned)rc == s.n);
	CK(!strcmp(s.name0, "my-buffer"));
	CK(strstr(s.verdict0, "Dropper") != NULL);

	/* a NULL name and a NULL option */
	memset(&f, 0, sizeof f);
	rc2 = kscan_bytes(sc, img, len, NULL, NULL, on_object, &f);
	CK(rc2 > 0 && (unsigned)rc2 == f.n);
	CK(f.name0[0] == 0);
	/* a NULL callback is allowed to be silent but must not crash */
	CK(kscan_bytes(sc, img, len, "x", &opt, NULL, NULL) >= 0);

	/* borrowed: not written */
	CK(!memcmp(img, keep, (size_t)len));

	/* the same as a file */
	fp = fopen(path, "wb");
	CK(fp != NULL);
	if (fp) {
		CK(fwrite(img, 1, (size_t)len, fp) == len);
		fclose(fp);
		memset(&f, 0, sizeof f);
		rc2 = kscan_path(sc, path, &opt, on_object, &f);
		CK(rc2 == rc);
		CK(f.n == s.n);
		CK(!strcmp(f.verdict0, s.verdict0));
		(void)remove(path);
	}

	/* repeatable, with a refused call in between */
	memset(&f, 0, sizeof f);
	(void)kscan_bytes(sc, NULL, 0, "x", &opt, on_object, &f);
	rc2 = kscan_bytes(sc, img, len, "my-buffer", &opt, on_object, &f);
	CK(rc2 == rc && f.n == s.n && !strcmp(f.verdict0, s.verdict0));

	printf("scan bytes api: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
