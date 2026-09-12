/*
 * sha256_vectors - the digest the whole toolset names artefacts by.
 *
 * WHY A TEST FOR TWELVE LINES OF ARITHMETIC. Because a wrong SHA-256 produces
 * sixty-four plausible hex characters and nothing else goes wrong: the report
 * prints a name, the signature source records a `Test sample:` line, a cache
 * keys a verdict on it, and every one of those is internally consistent and
 * matches nothing anybody else computed. There is no symptom to notice - which
 * is exactly the failure mode the fixed record format, the schema check and
 * the seq counter elsewhere in this tree are all built to refuse.
 *
 * The four FIPS 180-4 vectors, and then two properties no vector covers:
 *
 *   split feeds     a caller streaming a file in chunks and one handing over
 *                   the whole buffer must land on the same digest, or a
 *                   digest depends on the reader's buffer size.
 *   the file path   kof_sha256_file has its own loop and its own early exit,
 *                   so it is a second implementation of the same answer.
 *
 * The one-million-'a' vector is here rather than dropped as slow: it is the
 * one that catches a length counted in bytes where the padding wants bits, and
 * it exercises the multi-block path a byte at a time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"

static int failures;

static void check(const char *what, const char *got, const char *want)
{
	if (strcmp(got, want)) {
		printf("  FAIL %s:\n    got  %s\n    want %s\n", what, got, want);
		failures++;
	}
}

int main(void)
{
	static const struct { const char *in; const char *want; } v[] = {
		{ "",
		  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "abc",
		  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		/* 56 bytes: the length lands exactly where the padding has to
		 * spill into a second block, which is the off-by-one every
		 * hand-written SHA-2 gets wrong first. */
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" }
	};
	struct kof_sha256 s;
	uint8_t  d[32];
	char     hex[65], other[65];
	unsigned i;

	for (i = 0; i < sizeof v / sizeof v[0]; i++) {
		if (kof_sha256_bytes(v[i].in, strlen(v[i].in), hex)) {
			printf("  FAIL vector %u: refused\n", i);
			failures++;
			continue;
		}
		check(v[i].in[0] ? v[i].in : "(empty)", hex, v[i].want);
	}

	kof_sha256_init(&s);
	for (i = 0; i < 1000000u; i++)
		kof_sha256_update(&s, "a", 1);
	kof_sha256_final(&s, d);
	kof_sha256_hex(d, hex);
	check("one million 'a'", hex,
	      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

	/* --- the same bytes, fed in awkward pieces --- */
	{
		static unsigned char buf[5000];
		size_t off, step;

		for (i = 0; i < sizeof buf; i++)
			buf[i] = (unsigned char)(i * 31u + 7u);

		kof_sha256_bytes(buf, sizeof buf, hex);

		/* Steps that are neither a divisor of 64 nor of the length, so
		 * every call lands mid-block. */
		for (step = 1; step <= 130u; step += 7u) {
			kof_sha256_init(&s);
			for (off = 0; off < sizeof buf; off += step)
				kof_sha256_update(&s, buf + off,
						  off + step > sizeof buf
						   ? sizeof buf - off : step);
			kof_sha256_final(&s, d);
			kof_sha256_hex(d, other);
			if (strcmp(hex, other)) {
				printf("  FAIL split feed at step %zu:\n"
				       "    got  %s\n    want %s\n",
				       step, other, hex);
				failures++;
				break;
			}
		}

		/* A zero-length update in the middle must change nothing. */
		kof_sha256_init(&s);
		kof_sha256_update(&s, buf, 100);
		kof_sha256_update(&s, buf, 0);
		kof_sha256_update(&s, NULL, 0);
		kof_sha256_update(&s, buf + 100, sizeof buf - 100u);
		kof_sha256_final(&s, d);
		kof_sha256_hex(d, other);
		check("empty update between feeds", other, hex);

		/* --- and once more through the file path --- */
		{
			const char *tmp = "sha256_vectors.tmp";
			uint64_t    size = 0;
			FILE       *f = fopen(tmp, "wb");

			if (!f) {
				puts("  FAIL could not write a temporary file");
				failures++;
			} else {
				fwrite(buf, 1, sizeof buf, f);
				fclose(f);

				if (kof_sha256_file(tmp, other, &size)) {
					puts("  FAIL kof_sha256_file refused");
					failures++;
				} else {
					check("kof_sha256_file", other, hex);
					if (size != sizeof buf) {
						printf("  FAIL size: %llu, "
						       "want %zu\n",
						       (unsigned long long)size,
						       sizeof buf);
						failures++;
					}
				}
				remove(tmp);
			}
		}
	}

	/* A path that is not there is an error and not an empty digest: a
	 * caller that treated the two alike would name a missing file with the
	 * hash of nothing, which is a real digest of the wrong thing. */
	if (kof_sha256_file("no-such-file.no-such-extension", other, NULL)
	    != KOF_ERR_OPEN) {
		puts("  FAIL a missing file did not report KOF_ERR_OPEN");
		failures++;
	}

	printf("sha256: vectors, split feeds and the file path %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
