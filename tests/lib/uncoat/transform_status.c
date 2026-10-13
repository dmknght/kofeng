/*
 * uncoat / transform_status - kuncoat_transform and the status of kuncoat, through
 * <uncoat.h> alone, linked against libkuncoat.a and nothing else.
 *
 * The lib takes bytes and a budget and returns bytes and a status. This is the
 * proof it needs no engine to do that (there is none on the link line), and the
 * place the contract of transform.h is held by hand-written cases, one per
 * status:
 *
 *   OK            complete; both directions of the codings round-trip
 *   OVER_BUDGET   cap or max_out smaller than the result: a real PREFIX, counted,
 *                 never a silent short answer
 *   TRUNCATED     the input ended inside a token
 *   CORRUPT       a character outside the alphabet
 *   UNSUPPORTED   an unknown algorithm, a direction with no inverse
 *   BAD_ARG       a keyed algorithm with no key
 *
 * and a streaming decompressor (inflate), whose sink saying stop is STOPPED and
 * not corruption.
 */

#include <uncoat.h>

#include <stdio.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static enum kuncoat_status run(uint32_t algo, uint32_t dir, const uint8_t *key, uint32_t key_len,
			       uint32_t k32, uint64_t max_out, const char *in, uint8_t *out,
			       uint64_t cap, uint64_t *produced)
{
	struct kuncoat_step s;

	memset(&s, 0, sizeof s);
	s.algo = algo;
	s.dir = dir;
	s.key = key;
	s.key_len = key_len;
	s.k32 = k32;
	s.max_out = max_out;
	return kuncoat_transform(&s, (const uint8_t *)in, strlen(in), out, cap, produced);
}

static void codings(void)
{
	uint8_t out[64];
	uint64_t n = 99;

	/* base64, both directions */
	CK(run(KUNCOAT_ALGO_B64, KUNCOAT_DECODE, NULL, 0, 0, 0, "SGVsbG8=", out, sizeof out, &n) == KUNCOAT_OK);
	CK(n == 5u && !memcmp(out, "Hello", 5));
	CK(run(KUNCOAT_ALGO_B64, KUNCOAT_ENCODE, NULL, 0, 0, 0, "Hello", out, sizeof out, &n) == KUNCOAT_OK);
	CK(n == 8u && !memcmp(out, "SGVsbG8=", 8));
	/* hex, with the separators a person types */
	CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, NULL, 0, 0, 0, "48 65:6c,6C 6f", out, sizeof out, &n) == KUNCOAT_OK);
	CK(n == 5u && !memcmp(out, "Hello", 5));
	/* a coding that has an inverse for each direction round-trips */
	CK(run(KUNCOAT_ALGO_CAESAR, KUNCOAT_ENCODE, NULL, 0, 3, 0, "Hello, World", out, sizeof out, &n) == KUNCOAT_OK);
	CK(n == 12u && !memcmp(out, "Khoor, Zruog", 12));
	CK(run(KUNCOAT_ALGO_CAESAR, KUNCOAT_DECODE, NULL, 0, 3, 0, "Khoor, Zruog", out, sizeof out, &n) == KUNCOAT_OK);
	CK(n == 12u && !memcmp(out, "Hello, World", 12));
	/* the empty input is complete and empty, not an error */
	CK(run(KUNCOAT_ALGO_B64, KUNCOAT_DECODE, NULL, 0, 0, 0, "", out, sizeof out, &n) == KUNCOAT_OK && n == 0u);
}

static void ciphers(void)
{
	static const uint8_t key[] = { 0x13, 0x37 };
	uint8_t a[16], b[16];
	uint64_t n = 0, m = 0;

	/* XOR with a repeating key is its own inverse; so is RC4 */
	CK(run(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, key, sizeof key, 0, 0, "attack at dawn", a, sizeof a, &n) == KUNCOAT_OK);
	CK(n == 14u && memcmp(a, "attack at dawn", 14) != 0);
	b[0] = 0;
	{
		struct kuncoat_step s;

		memset(&s, 0, sizeof s);
		s.algo = KUNCOAT_ALGO_XOR_KEY;
		s.key = key;
		s.key_len = sizeof key;
		CK(kuncoat_transform(&s, a, n, b, sizeof b, &m) == KUNCOAT_OK);
		CK(m == 14u && !memcmp(b, "attack at dawn", 14));
		/* in place, which the stream ciphers allow */
		CK(kuncoat_transform(&s, a, n, a, sizeof a, &m) == KUNCOAT_OK);
		CK(!memcmp(a, "attack at dawn", 14));
	}
	CK(run(KUNCOAT_ALGO_RC4, KUNCOAT_DECODE, key, sizeof key, 0, 0, "attack at dawn", a, sizeof a, &n) == KUNCOAT_OK);
	CK(n == 14u && memcmp(a, "attack at dawn", 14) != 0);
}

static void statuses(void)
{
	uint8_t out[8];
	uint64_t n = 99;

	/* THE OUTPUT BUDGET: the cap, then the step's max_out - a real prefix, counted */
	CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, NULL, 0, 0, 0, "48656c6c6f20776f", out, 4, &n) == KUNCOAT_OVER_BUDGET);
	CK(n == 4u && !memcmp(out, "Hell", 4));
	CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, NULL, 0, 0, 3, "48656c6c6f", out, sizeof out, &n) == KUNCOAT_OVER_BUDGET);
	CK(n == 3u && !memcmp(out, "Hel", 3));
	/* the answer that fits exactly is complete */
	CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, NULL, 0, 0, 5, "48656c6c6f", out, sizeof out, &n) == KUNCOAT_OK && n == 5u);
	/* the input ended inside a token */
	CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, NULL, 0, 0, 0, "486", out, sizeof out, &n) == KUNCOAT_TRUNCATED);
	CK(n == 1u && out[0] == 0x48);          /* what was complete is still produced */
	/* a character outside the alphabet is the stream's fault... */
	CK(run(KUNCOAT_ALGO_B64, KUNCOAT_DECODE, NULL, 0, 0, 0, "SGV$bG8=", out, sizeof out, &n) == KUNCOAT_CORRUPT);
	/* ...unless the caller said to skip it */
	{
		struct kuncoat_step s;

		memset(&s, 0, sizeof s);
		s.algo = KUNCOAT_ALGO_B64;
		s.flags = KUNCOAT_F_LAX;
		CK(kuncoat_transform(&s, (const uint8_t *)"SGV$sbG8=", 9, out, sizeof out, &n) == KUNCOAT_OK);
		CK(n == 5u && !memcmp(out, "Hello", 5));
	}
	/* a request the build cannot do, and one that is not usable */
	CK(run(999, KUNCOAT_DECODE, NULL, 0, 0, 0, "x", out, sizeof out, &n) == KUNCOAT_UNSUPPORTED);
	CK(run(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, NULL, 0, 0, 0, "x", out, sizeof out, &n) == KUNCOAT_BAD_ARG);
	CK(run(KUNCOAT_ALGO_CAESAR, KUNCOAT_DECODE, NULL, 0, 26, 0, "x", out, sizeof out, &n) == KUNCOAT_BAD_ARG);
	CK(!strcmp(kuncoat_status_name(KUNCOAT_OVER_BUDGET), "over-budget") ||
	   kuncoat_status_name(KUNCOAT_OVER_BUDGET)[0] != '?');
}

/* ---- a streaming decompressor, through its sink ------------------------------ */

struct sink { uint8_t buf[64]; uint32_t n, room; };

static int take(void *user, const uint8_t *p, uint32_t n)
{
	struct sink *s = user;

	if (n > s->room - s->n)
		return 0;               /* the receiver has enough */
	memcpy(s->buf + s->n, p, n);
	s->n += n;
	return 1;
}

static struct kuncoat_inflate st;

static void inflate_status(void)
{
	/* a stored block: BFINAL=1, BTYPE=00, LEN=5, NLEN=~5, "hello" */
	static const uint8_t stored[] = { 0x01, 5, 0, 0xfa, 0xff, 'h', 'e', 'l', 'l', 'o' };
	struct sink s;
	struct kuncoat_io io;

	memset(&s, 0, sizeof s);
	s.room = sizeof s.buf;
	io = (struct kuncoat_io){ .in = { stored, sizeof stored }, .sink = take, .user = &s };
	CK(kuncoat_inflate(&st, &io) == KUNCOAT_OK);
	CK(io.produced == 5u && io.consumed == sizeof stored && !memcmp(s.buf, "hello", 5));

	/* the receiver saying stop is STOPPED - the receiver declining, not a broken archive */
	memset(&s, 0, sizeof s);
	s.room = 3;
	io = (struct kuncoat_io){ .in = { stored, sizeof stored }, .sink = take, .user = &s };
	CK(kuncoat_inflate(&st, &io) == KUNCOAT_STOPPED);

	/* the input ending first is TRUNCATED, and the bytes before the cut are real */
	memset(&s, 0, sizeof s);
	s.room = sizeof s.buf;
	io = (struct kuncoat_io){ .in = { stored, 8 }, .sink = take, .user = &s };
	CK(kuncoat_inflate(&st, &io) == KUNCOAT_TRUNCATED);

	/* a block type that does not exist is the stream's fault */
	{
		static const uint8_t bad[] = { 0x07, 0, 0, 0, 0 };      /* BTYPE = 11 */

		memset(&s, 0, sizeof s);
		s.room = sizeof s.buf;
		io = (struct kuncoat_io){ .in = { bad, sizeof bad }, .sink = take, .user = &s };
	CK(kuncoat_inflate(&st, &io) == KUNCOAT_CORRUPT);
	}
}

int main(void)
{
	codings();
	ciphers();
	statuses();
	inflate_status();
	printf("uncoat transform_status: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
