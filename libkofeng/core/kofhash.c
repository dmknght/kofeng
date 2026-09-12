/*
 * kofhash.c - SHA-256, because an artefact needs a name that is its own.
 *
 * WHY THE ENGINE OWNS THIS AND NOT WHOEVER NEEDED IT FIRST
 *
 * Four callers wanted the same twelve lines. The event report names a dropped
 * file; kofeditor writes a `Test sample:` line into every generated signature
 * source and has been getting it from whoever pasted it; koffridge keys a
 * verdict on an identity the caller supplies; and a tool that scans a
 * directory twice has no way to say two paths held the same bytes. Each of
 * those is a hash of a file, and four copies of a hash is four chances to
 * produce a digest nobody else reproduces.
 *
 * SHA-256 AND NOTHING ELSE, said plainly so the question does not reopen. It
 * is what every artefact exchange this toolset's output would ever meet
 * speaks - a sample name, a lookup by digest, the header comment every file
 * under bases/signatures/ already carries. MD5 would be shorter and is not a
 * second opinion: it is a weaker answer to the same question, and having both
 * invites a report that prints one and a database that keys on the other.
 *
 * NOT A CRYPTOGRAPHIC SERVICE. There is no HMAC, no signing and no
 * constant-time compare, because nothing here authenticates anything - a
 * digest is used to NAME bytes and to notice that two lots of bytes differ.
 * An attacker who can choose both sides of a collision gains the ability to
 * make two of their own samples share a name, which is not a threat this
 * toolset defends against and not one SHA-256 would lose.
 *
 * PORTABLE C AND NO INTRINSICS, deliberately. The measured cost is the one
 * that decides it: a report hashes the handful of files one traced process
 * created, and kofeditor hashes one sample per signature. At tens of megabytes
 * per file, plain C is already far below the I/O that fetched the bytes, so an
 * ARM64 sha2 path and an x86 SHA-NI path would be two more things to be wrong
 * in, for time nobody is waiting on. The moment something hashes a filesystem
 * walk, measure before changing this.
 */

#include <stdio.h>
#include <string.h>

#include "../kofeng.h"

/*
 * The constants are the first thirty-two bits of the fractional parts of the
 * cube roots of the first sixty-four primes, exactly as FIPS 180-4 gives them.
 * Written out rather than computed for the same reason a CRC table is: a
 * generator would have to be trusted, and this can be compared against the
 * standard by eye.
 */
static const uint32_t K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t ror(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32u - n));
}

/*
 * ONE BLOCK. Sixty-four bytes in, the state advanced, nothing returned.
 *
 * The message schedule is a rolling window of sixteen words rather than the
 * sixty-four the specification writes down, which is the same computation with
 * a quarter of the stack. Most implementations write the long form because the
 * specification indexes w[t-15]; the masks below do that.
 */
static void block(uint32_t h[8], const uint8_t *p)
{
	uint32_t w[16], a, b, c, d, e, f, g, hh, t1, t2, s0, s1;
	unsigned i;

	for (i = 0; i < 16u; i++)
		w[i] = ((uint32_t)p[4u * i] << 24) |
		       ((uint32_t)p[4u * i + 1u] << 16) |
		       ((uint32_t)p[4u * i + 2u] << 8) |
		        (uint32_t)p[4u * i + 3u];

	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	for (i = 0; i < 64u; i++) {
		if (i >= 16u) {
			s0 = ror(w[(i + 1u) & 15u], 7) ^
			     ror(w[(i + 1u) & 15u], 18) ^
			         (w[(i + 1u) & 15u] >> 3);
			s1 = ror(w[(i + 14u) & 15u], 17) ^
			     ror(w[(i + 14u) & 15u], 19) ^
			         (w[(i + 14u) & 15u] >> 10);
			w[i & 15u] += s0 + w[(i + 9u) & 15u] + s1;
		}

		t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) +
		     ((e & f) ^ (~e & g)) + K[i] + w[i & 15u];
		t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) +
		     ((a & b) ^ (a & c) ^ (b & c));

		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void kof_sha256_init(struct kof_sha256 *s)
{
	s->h[0] = 0x6a09e667u; s->h[1] = 0xbb67ae85u;
	s->h[2] = 0x3c6ef372u; s->h[3] = 0xa54ff53au;
	s->h[4] = 0x510e527fu; s->h[5] = 0x9b05688cu;
	s->h[6] = 0x1f83d9abu; s->h[7] = 0x5be0cd19u;
	s->len  = 0;
	s->n    = 0;
}

void kof_sha256_update(struct kof_sha256 *s, const void *bytes, uint64_t n)
{
	const uint8_t *p = (const uint8_t *)bytes;

	if (!p || !n)
		return;

	s->len += n;

	/* Finish whatever the last call left short of a block first, so a
	 * caller feeding a byte at a time and one feeding a whole file arrive
	 * at the same digest. */
	if (s->n) {
		uint64_t want = 64u - s->n;

		if (n < want) {
			memcpy(s->buf + s->n, p, (size_t)n);
			s->n += (uint32_t)n;
			return;
		}
		memcpy(s->buf + s->n, p, (size_t)want);
		block(s->h, s->buf);
		p += want;
		n -= want;
		s->n = 0;
	}

	while (n >= 64u) {
		block(s->h, p);
		p += 64u;
		n -= 64u;
	}

	if (n) {
		memcpy(s->buf, p, (size_t)n);
		s->n = (uint32_t)n;
	}
}

void kof_sha256_final(struct kof_sha256 *s, uint8_t out[32])
{
	uint64_t bits = s->len * 8u;
	uint8_t  tail[72];
	uint32_t pad;
	unsigned i;

	/*
	 * The padding is 0x80, then zeroes to eight short of a block boundary,
	 * then the length in BITS big-endian. Built in one buffer and fed
	 * through update so there is one block loop in this file and not two.
	 */
	tail[0] = 0x80u;
	pad = (s->n < 56u) ? (56u - s->n) : (120u - s->n);
	memset(tail + 1, 0, pad - 1u);
	for (i = 0; i < 8u; i++)
		tail[pad + i] = (uint8_t)(bits >> (56u - 8u * i));

	/* `len` is wrong by the padding after this call, and nothing reads it
	 * again - a finalised state is not resumable, and kofeng.h says so
	 * where a caller would look. */
	kof_sha256_update(s, tail, (uint64_t)pad + 8u);

	for (i = 0; i < 8u; i++) {
		out[4u * i]      = (uint8_t)(s->h[i] >> 24);
		out[4u * i + 1u] = (uint8_t)(s->h[i] >> 16);
		out[4u * i + 2u] = (uint8_t)(s->h[i] >> 8);
		out[4u * i + 3u] = (uint8_t)s->h[i];
	}
}

void kof_sha256_hex(const uint8_t digest[32], char out[65])
{
	static const char hex[] = "0123456789abcdef";
	unsigned i;

	/*
	 * LOWER CASE, and that is not a preference. It is what the sample
	 * filenames kofviewer opens are named with and what the `Test sample:`
	 * line in every file under bases/signatures/ already holds, and a
	 * report that printed the same digest in the other case would not match
	 * on a text search - which is how anybody actually looks one up.
	 */
	for (i = 0; i < 32u; i++) {
		out[2u * i]      = hex[digest[i] >> 4];
		out[2u * i + 1u] = hex[digest[i] & 15u];
	}
	out[64] = '\0';
}

int kof_sha256_bytes(const void *bytes, uint64_t n, char out[65])
{
	struct kof_sha256 s;
	uint8_t d[32];

	if (!out || (!bytes && n))
		return KOF_ERR_ARG;

	kof_sha256_init(&s);
	kof_sha256_update(&s, bytes, n);
	kof_sha256_final(&s, d);
	kof_sha256_hex(d, out);
	return 0;
}

int kof_sha256_file(const char *path, char out[65], uint64_t *size)
{
	/*
	 * 32KB ON THE STACK, and the number is the only thing in this function
	 * worth a comment. Large enough that the per-read overhead disappears
	 * against the copy, small enough to sit on the stack of a tool that is
	 * already holding a scanner - which is why it is not the megabyte a
	 * throughput benchmark would choose, and why it is not static: the
	 * engine hands several scanners to several threads (kof_scan_path_mt),
	 * and one shared buffer would digest two files into each other.
	 */
	enum { CHUNK = 32u * 1024u };
	unsigned char buf[CHUNK];
	struct kof_sha256 s;
	uint8_t  d[32];
	uint64_t total = 0;
	FILE    *f;

	if (!path || !out)
		return KOF_ERR_ARG;

	f = fopen(path, "rb");
	if (!f)
		return KOF_ERR_OPEN;

	kof_sha256_init(&s);
	for (;;) {
		size_t got = fread(buf, 1, CHUNK, f);

		if (got) {
			kof_sha256_update(&s, buf, got);
			total += got;
		}
		if (got < CHUNK) {
			/*
			 * A SHORT READ IS NOT END OF FILE ON ITS OWN, and a
			 * digest over part of a file is worse than no digest:
			 * it names bytes that were never the artefact. A file
			 * still being written while this reads it, or one on a
			 * share that went away, ends here with an error rather
			 * than with a plausible hash of a prefix.
			 */
			if (ferror(f)) {
				fclose(f);
				return KOF_ERR_READ;
			}
			break;
		}
	}
	fclose(f);

	kof_sha256_final(&s, d);
	kof_sha256_hex(d, out);
	if (size)
		*size = total;
	return 0;
}
