#define _GNU_SOURCE
/*
 * script_squeeze - L19 of the lexer audit, through the whole engine: objctx_script.c script_squeeze.
 *
 * A script's view is decoded in place (kof_exe_decode_ex, length preserving: what a decode vacates is filled with zeros) and the zeros are then taken out so that a
 * decoded string sits where the encoded one was. The comment on it said "a script that holds a NUL of its own keeps it", and the function removed EVERY zero byte of the
 * view after any decode that fired: the NUL inside a quoted string of the script was gone from the view, so a marker written on that string no longer matched there.
 * Only the zeros the decode made are taken out now.
 *
 * Asserted by scanning a shell script that holds a base64 payload (so the view is made and decoded) and strings with NULs of their own: one NUL, two in a row, a NUL as the
 * last byte of a string, a NUL right after the payload's line; each stays, in place, byte for byte, and the decoded canary is contiguous (the squeeze still works).
 *
 * Why the old tests missed it: (c) normalizer_engine.c scripts() builds scripts that hold no NUL, and checks that the canary is found, which the over-eager squeeze
 * satisfies equally well.
 *
 * usage: script_squeeze   (needs the test database: make test-sigs)
 */

#include <pthread.h>

#include "caps_fix.h"
#include "caps_e2e.h"
#include "notes.h"
#include "normalizer_ref.h"
#include "../../libkofeng/scanners/scan.h"

struct view {
	unsigned n_obj;
	uint32_t kind1;
	uint8_t *bytes;
	uint64_t len;
	int named;
};

static int collect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct view *v = user;
	struct note_list got;
	uint32_t i;

	(void)name;
	notes_here(&got);
	if (v->n_obj++ == 1u && res->entry_kind == KOF_ENT_NORMALIZED && len < (8u << 20)) {
		v->kind1 = res->entry_kind;
		v->bytes = malloc((size_t)len);
		if (v->bytes) {
			memcpy(v->bytes, bytes, (size_t)len);
			v->len = len;
		}
		for (i = 0; i < got.n; i++)
			if (strstr(got.name[i], "NormViewScript"))
				v->named = 1;
	}
	return 0;
}

static int find(const struct view *v, const void *needle, size_t n)
{
	return v->bytes && memmem(v->bytes, (size_t)v->len, needle, n) != NULL;
}

static void run(const char *label, const uint8_t *text, size_t n, const uint8_t *keep, size_t keep_n)
{
	struct kof_scan_option opt;
	struct view v;

	memset(&v, 0, sizeof v);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	opt.heur_level = 1;
	(void)kscan_bytes(e2e_sc, text, n, "squeeze", &opt, collect, &v);
	NCKF(v.kind1 == KOF_ENT_NORMALIZED && v.named, "%s: no decoded view (%u objects)", label, v.n_obj);
	NCKF(find(&v, keep, keep_n), "%s: the script's own NUL did not survive the view", label);
	free(v.bytes);
}

int main(void)
{
	char enc[256], head[512];
	uint8_t text[1024];
	size_t el, hl, n;
	static const uint8_t k1[] = "'x\0y'", k2[] = "'a\0\0b'", k3[] = "'tail\0'", k4[] = "exit 0\n\0";
	static const char tail1[] = "\n  MSG='x\0y'\n  rm -f /tmp/x\n  ls   -la\n   exit 0\n";
	static const char tail2[] = "\n  MSG='a\0\0b'\n  rm -f /tmp/x\n  ls   -la\n   exit 0\n";
	static const char tail3[] = "\n  MSG='tail\0'\n  rm -f /tmp/x\n  ls   -la\n   exit 0\n";
	static const char tail4[] = "\n  rm -f /tmp/x\n  ls   -la\n  exit 0\n\0\n";

	if (!e2e_open(NULL)) {
		printf("script_squeeze: cannot open the test database\n");
		return 2;
	}
	el = nr_b64_enc((const uint8_t *)"NormScriptB64-a1f0c2", 20u, enc, 1, 0, 0);
	enc[el] = 0;
	hl = (size_t)snprintf(head, sizeof head, "#!/bin/sh\n# a dropper\n  echo %s | base64 -d | sh\n\n", enc);
	memcpy(text, head, hl);
	memcpy(text + hl, tail1, sizeof tail1 - 1u);
	n = hl + sizeof tail1 - 1u;
	run("one NUL in a string", text, n, k1, sizeof k1 - 1u);
	memcpy(text + hl, tail2, sizeof tail2 - 1u);
	n = hl + sizeof tail2 - 1u;
	run("two NULs in a row", text, n, k2, sizeof k2 - 1u);
	memcpy(text + hl, tail3, sizeof tail3 - 1u);
	n = hl + sizeof tail3 - 1u;
	run("a NUL ending a string", text, n, k3, sizeof k3 - 1u);
	memcpy(text + hl, tail4, sizeof tail4 - 1u);
	n = hl + sizeof tail4 - 1u;
	run("a NUL at the end of the file", text, n, k4, sizeof k4 - 1u);
	printf("script_squeeze: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
