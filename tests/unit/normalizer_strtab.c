#define _GNU_SOURCE
/*
 * normalizer_strtab - the one-byte string table of executables_strtab.c against what it promises,
 * and against a reading written one byte at a time.
 *
 * WHAT IS PINNED
 *
 *   KNOWN ANSWER    a table built by an ENCODER OF THIS FILE (text xor K, the terminator xor K, one zero
 *                   after each record) comes back as the text, at its own offsets, terminator now zero,
 *                   every byte outside the records untouched; a second call finds nothing.
 *   EVERY KEY       K = 1..255: the key is read out of the records, no key is given to the call. A key
 *                   under which no character of the text is unreadable cannot be evidence (nothing in
 *                   the table says it is coded) and is left alone, as the header says.
 *   THE FLOORS      15 and 16 records, 255 and 256 characters: one below and one at each.
 *   KEPT BYTES      a free stretch is decoded and a kept one is not, and the evidence of a key is the
 *                   free stretch's own: a kept table does not make a free handful believed.
 *   NOT EVIDENCE    plain text that ends in the key's character, a last record no zero follows.
 *   DIFFERENTIAL    thousands of generated objects (random bytes, tables, plain strings, random keep
 *                   maps) through the product and through the slow reading below: bytes, return value
 *                   and counters must agree; idempotent; the probe never says "no" where the pass
 *                   writes (no keep map).
 *   GUARD PAGES     buffers flush against a PROT_NONE page, every length 0..80, both ends.
 *   HOSTILE         64 MB: random bytes, a table that is all records, a run of one byte, zeros. No
 *                   cap exists in the pass, so the answer is the whole object read, and the time is
 *                   printed.
 *
 * Deterministic: every generator is seeded from the loop index.
 */

#include <time.h>

#include "normalizer_ref.h"

/* ---- the reading, one byte at a time, from the contract in executables.h ---------- */

static int o_text(uint8_t c)
{
	return (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r';
}

static int o_letter(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int o_kept(const uint8_t *keep, uint64_t i)
{
	return keep && (keep[i >> 3] >> (i & 7u) & 1u);
}

/* One stretch [a, b): records are the non-zero runs a zero follows INSIDE the stretch. A key is
 * believed by a RUN of consecutive anchors (executables_strtab.c), then every record that ends in it
 * and reads as text is written. */
static void o_stretch(uint8_t *p, uint64_t a, uint64_t b, uint64_t *recs, uint64_t *chars, uint32_t *keys)
{
	uint8_t on[256] = { 0 };
	uint64_t s, e, i, rn = 0, rc = 0;
	uint8_t rk = 0;

	for (s = a; s < b;) {
		int anchor = 0;

		if (p[s] == 0) {
			s++;
			continue;
		}
		for (e = s; e < b && p[e] != 0; e++)
			;
		if (e >= b)
			break;
		if (e - 1 - s >= KOF_EXE_STR_LEN_MIN) {
			int plain = 1, reads = 1, letter = 0;
			uint8_t key = p[e - 1];

			for (i = s; i < e; i++)
				if (!o_text(p[i]))
					plain = 0;
			for (i = s; i < e - 1; i++) {
				if (!o_text((uint8_t)(p[i] ^ key)))
					reads = 0;
				if (o_letter((uint8_t)(p[i] ^ key)))
					letter = 1;
			}
			anchor = !plain && reads && letter;
		}
		if (anchor) {
			if (rn && p[e - 1] == rk) {
				rn++;
				rc += e - 1 - s;
			} else {
				rk = p[e - 1];
				rn = 1;
				rc = e - 1 - s;
			}
			if (rn >= KOF_EXE_STR_ANCHOR_MIN && rc >= KOF_EXE_STR_CHARS_MIN && !on[rk]) {
				on[rk] = 1;
				(*keys)++;
			}
		} else {
			rn = 0;
		}
		s = e + 1;
	}
	for (s = a; s < b;) {
		if (p[s] == 0) {
			s++;
			continue;
		}
		for (e = s; e < b && p[e] != 0; e++)
			;
		if (e >= b)
			break;
		if (e - s >= 2 && on[p[e - 1]]) {
			uint8_t key = p[e - 1];
			int reads = 1;

			for (i = s; i < e - 1; i++)
				if (!o_text((uint8_t)(p[i] ^ key)))
					reads = 0;
			if (reads) {
				for (i = s; i < e; i++)
					p[i] ^= key;
				(*recs)++;
				*chars += e - 1 - s;
			}
		}
		s = e + 1;
	}
}

static int oracle(uint8_t *p, uint64_t n, const uint8_t *keep, struct kof_exe_strtab_res *r)
{
	uint64_t i = 0;

	memset(r, 0, sizeof *r);
	while (i < n) {
		uint64_t a;

		while (i < n && o_kept(keep, i))
			i++;
		if (i >= n)
			break;
		a = i;
		while (i < n && !o_kept(keep, i))
			i++;
		r->stretches++;
		o_stretch(p, a, i, &r->records, &r->chars, &r->keys);
	}
	return r->records != 0;
}

/* ---- the encoder of this file ------------------------------------------------------ */

/* Neutral words: a table of the shape, not of anything's content. */
static const char *const WORDS[] = {
	"alpha record number one", "beta/gamma/delta", "region 42 north", "needs a space and 7 digits",
	"config=/etc/example.conf", "Some Mixed Case Words Here", "x", "tmp/work", "key: value; other: thing",
	"0123456789", "path/to/some/file.txt", "the quick brown fox", "jumps over 13 lazy dogs",
};
#define NWORDS (sizeof WORDS / sizeof WORDS[0])

/* A character that makes the record unreadable under `k` (so it is evidence), or 0 when none of the
 * printable set does. */
static uint8_t unreadable_char(uint8_t k)
{
	unsigned c;

	for (c = 0x20; c <= 0x7e; c++)
		if (!o_text((uint8_t)(c ^ k)) && c != k)
			return (uint8_t)c;
	return 0;
}

/* One record: `text` (a character equal to k is replaced, a zero must not appear), xor k, the
 * terminator k, then `pad` zeros. */
static size_t put_rec(uint8_t *o, const char *text, size_t tl, uint8_t k, uint8_t mark, unsigned pad)
{
	size_t i, n = 0;

	for (i = 0; i < tl; i++) {
		uint8_t c = (uint8_t)text[i];

		if (c == k || ((uint8_t)(c ^ k)) == 0)
			c = '_';
		o[n++] = (uint8_t)(c ^ k);
	}
	if (mark && n)
		o[0] = (uint8_t)(mark ^ k);     /* the unreadable character, so the record is evidence */
	o[n++] = k;
	while (pad--)
		o[n++] = 0;
	return n;
}

/* A table of `nrec` records with key k at `o`. `plain` gets the expected text. Returns the length. */
static size_t make_table(uint8_t *o, uint8_t *plain, unsigned nrec, uint8_t k, unsigned min_len, unsigned seed)
{
	struct nrng r;
	size_t n = 0, pn = 0;
	unsigned i;
	uint8_t mark = unreadable_char(k);

	nr_seed(&r, seed);
	for (i = 0; i < nrec; i++) {
		char text[200];
		const char *w = WORDS[nr_below(&r, NWORDS)];
		size_t tl = strlen(w), j, m;

		memcpy(text, w, tl);
		while (tl < min_len) {
			text[tl] = (char)('a' + (int)(tl % 26u));
			tl++;
		}
		m = put_rec(o + n, text, tl, k, mark, 1u + nr_below(&r, 3u));
		for (j = 0; j < tl; j++) {
			uint8_t c = (uint8_t)text[j];

			plain[pn++] = (j == 0 && mark) ? mark : (c == k ? '_' : c);
		}
		plain[pn++] = 0;
		/* zero pads follow in o; mirror them in plain */
		{
			size_t padn = m - tl - 1u;

			while (padn--)
				plain[pn++] = 0;
		}
		n += m;
	}
	return n;
}

/* ---- known answer ------------------------------------------------------------------ */

static void known_answer(void)
{
	static uint8_t obj[1u << 14], plain[1u << 14], keep[1u << 11];
	struct kof_exe_strtab_res res;
	size_t tn;
	uint8_t big[4096];

	tn = make_table(obj + 16, plain + 16, 24u, 0x22, 20u, 7u);
	memset(obj, 0x5a, 15);
	memset(plain, 0x5a, 15);
	obj[15] = plain[15] = 0;        /* a zero, or the sentinel and the first record are one record */
	memset(obj + 16 + tn, 0x5a, 16);
	memset(plain + 16 + tn, 0x5a, 16);
	NCK(kof_exe_strtab_would_change(obj, tn + 32u));
	NCK(kof_exe_strtab(obj, tn + 32u, NULL, &res) == 1);
	NCK(!memcmp(obj, plain, tn + 32u));
	NCKF(res.records == 24u && res.keys == 1u && res.stretches == 1u, "records %llu keys %u stretches %llu",
	     (unsigned long long)res.records, res.keys, (unsigned long long)res.stretches);
	/* idempotent: the records are text now and nothing in them is evidence */
	memcpy(big, obj, sizeof big);
	NCK(kof_exe_strtab(obj, tn + 32u, NULL, &res) == 0 && res.records == 0);
	NCK(!memcmp(obj, plain, tn + 32u) && !memcmp(big, obj, sizeof big));
	NCK(!kof_exe_strtab_would_change(obj, tn + 32u));
	/* the keep map of nothing is the same as no map */
	memset(keep, 0, sizeof keep);
	tn = make_table(obj, plain, 24u, 0x22, 20u, 7u);
	NCK(kof_exe_strtab(obj, tn, keep, &res) == 1 && !memcmp(obj, plain, tn));
	/* NULL and zero length are not an error */
	NCK(kof_exe_strtab(NULL, 0, NULL, &res) == 0);
	NCK(kof_exe_strtab(obj, 0, NULL, NULL) == 0);
	NCK(!kof_exe_strtab_would_change(NULL, 0));
}

static void every_key(void)
{
	static uint8_t obj[1u << 14], plain[1u << 14], orig[1u << 14];
	unsigned k, decoded = 0, left = 0;

	for (k = 1; k < 256u; k++) {
		struct kof_exe_strtab_res res, ref;
		uint8_t exp[1u << 14];
		size_t tn = make_table(obj, plain, 20u, (uint8_t)k, 24u, 100u + k);
		int want_decode = unreadable_char((uint8_t)k) != 0;

		memcpy(orig, obj, tn);
		memcpy(exp, obj, tn);
		(void)oracle(exp, tn, NULL, &ref);
		NCK(kof_exe_strtab(obj, tn, NULL, &res) == (res.records != 0));
		NCKF(!memcmp(obj, exp, tn) && res.records == ref.records && res.keys == ref.keys,
		     "key %u product %llu oracle %llu", k, (unsigned long long)res.records,
		     (unsigned long long)ref.records);
		if (want_decode) {
			NCKF(!memcmp(obj, plain, tn), "key %u: the table is not the text", k);
			decoded++;
		} else {
			NCKF(!memcmp(obj, orig, tn), "key %u: left alone", k);
			left++;
		}
	}
	NCKF(decoded >= 200u, "keys with an unreadable character: %u (left %u)", decoded, left);
}

/* ---- the floors ---------------------------------------------------------------------- */

static void floors(void)
{
	static uint8_t obj[1u << 14], plain[1u << 14], orig[1u << 14];
	struct kof_exe_strtab_res res;
	unsigned nrec;

	/* records: 15 is below, 16 is at; every record long enough that the characters are not the limit */
	for (nrec = 14; nrec <= 17; nrec++) {
		size_t tn = make_table(obj, plain, nrec, 0x22, 30u, 5u);

		memcpy(orig, obj, tn);
		kof_exe_strtab(obj, tn, NULL, &res);
		if (nrec < KOF_EXE_STR_ANCHOR_MIN)
			NCKF(!memcmp(obj, orig, tn) && res.records == 0, "%u records read", nrec);
		else
			NCKF(!memcmp(obj, plain, tn) && res.records == nrec, "%u records not read", nrec);
		NCK(kof_exe_strtab_would_change(orig, tn) == (nrec >= KOF_EXE_STR_ANCHOR_MIN));
	}
	/* characters: sixteen records of a fixed length. Each record is `len` characters, so the
	 * total is 16 * len: len 15 gives 240, len 16 gives 256 (the floor), and one record one
	 * character short of the floor is built by shortening the last. */
	{
		unsigned len;

		for (len = 15; len <= 17; len++) {
			size_t tn = make_table(obj, plain, 16u, 0x22, len, 9u), i;
			uint64_t chars = 0;
			int fixed = 1;

			/* WORDS shorter than `len` are padded to it; longer ones keep their length, so measure */
			(void)fixed;
			memcpy(orig, obj, tn);
			for (i = 0; i < tn;) {
				size_t e = i;

				while (e < tn && obj[e])
					e++;
				if (e > i)
					chars += e - i - 1u;
				i = e + 1u;
			}
			kof_exe_strtab(obj, tn, NULL, &res);
			NCKF((chars >= KOF_EXE_STR_CHARS_MIN) == (res.records == 16u),
			     "len %u: %llu characters, %llu records", len, (unsigned long long)chars,
			     (unsigned long long)res.records);
		}
	}
	/* exactly 255 and exactly 256: sixteen records of 16 characters, then one record trimmed by one */
	{
		unsigned want;

		for (want = 255; want <= 256; want++) {
			size_t n = 0;
			unsigned i, total = 0;

			memset(obj, 0, sizeof obj);
			for (i = 0; i < 16u; i++) {
				char text[32];
				unsigned l = (i == 15u) ? want - 15u * 16u : 16u;
				unsigned j;

				for (j = 0; j < l; j++)
					text[j] = (char)('a' + (int)((i + j) % 26u));
				text[0] = ' ';
				n += put_rec(obj + n, text, l, 0x22, 0, 1u);
				total += l;
			}
			NCK(total == want);
			memcpy(orig, obj, n);
			kof_exe_strtab(obj, n, NULL, &res);
			NCKF((want >= KOF_EXE_STR_CHARS_MIN) == (res.records == 16u),
			     "%u characters: %llu records", want, (unsigned long long)res.records);
		}
	}
}

/* ---- kept bytes ------------------------------------------------------------------------ */

static void kept(void)
{
	static uint8_t obj[1u << 15], plain[1u << 15], orig[1u << 15], keep[1u << 12];
	struct kof_exe_strtab_res res;
	size_t a = make_table(obj, plain, 30u, 0x22, 24u, 3u), b;
	size_t i;

	/* a kept table is not decoded */
	memset(keep, 0, sizeof keep);
	for (i = 0; i < a; i++)
		keep[i >> 3] |= (uint8_t)(1u << (i & 7u));
	memcpy(orig, obj, a);
	kof_exe_strtab(obj, a, keep, &res);
	NCK(!memcmp(obj, orig, a) && res.records == 0 && res.stretches == 0);
	/* free table after a kept one: only the free one */
	b = make_table(obj + a, plain + a, 30u, 0x22, 24u, 4u);
	memcpy(orig, obj, a + b);
	kof_exe_strtab(obj, a + b, keep, &res);
	NCK(!memcmp(obj, orig, a) && !memcmp(obj + a, plain + a, b) && res.records == 30u);
	/* the evidence is the free stretch's own: a kept table of 30 does not make 8 free records believed */
	{
		size_t c = make_table(obj + a, plain + a, 8u, 0x22, 40u, 5u);

		memcpy(orig, obj, a + c);
		kof_exe_strtab(obj, a + c, keep, &res);
		NCK(!memcmp(obj, orig, a + c) && res.records == 0);
		/* with no keep map the same bytes are 38 records: believed, and both tables are read */
		memcpy(obj, orig, a + c);
		kof_exe_strtab(obj, a + c, NULL, &res);
		NCK(res.records == 38u);
	}
	/* a table cut by the kept edge: the last record has no zero after it inside the stretch */
	{
		size_t n = make_table(obj, plain, 20u, 0x22, 24u, 6u), last, t = n, j;

		while (obj[t - 1u] == 0)
			t--;
		t--;                            /* the last record's terminator */
		last = t;
		while (last > 0 && obj[last - 1u] != 0)
			last--;
		memset(keep, 0, sizeof keep);
		for (j = t; j <= n; j++)
			keep[j >> 3] |= (uint8_t)(1u << (j & 7u));
		memcpy(orig, obj, n);
		kof_exe_strtab(obj, n, keep, &res);
		NCKF(res.records == 19u && !memcmp(obj + last, orig + last, n - last),
		     "cut table: %llu records", (unsigned long long)res.records);
	}
}

/* ---- not evidence ----------------------------------------------------------------------- */

static void not_evidence(void)
{
	static uint8_t obj[1u << 14], orig[1u << 14];
	struct kof_exe_strtab_res res;
	size_t n = 0;
	unsigned i;

	/* plain text records that end in the key's character: readable as they stand, no evidence */
	for (i = 0; i < 40u; i++) {
		static const char t[] = "say \"something quoted\"";

		memcpy(obj + n, t, sizeof t - 1u);
		n += sizeof t - 1u;
		obj[n++] = 0;
	}
	memcpy(orig, obj, n);
	NCK(kof_exe_strtab(obj, n, NULL, &res) == 0 && !memcmp(obj, orig, n));
	NCK(!kof_exe_strtab_would_change(obj, n));
	/* a plain record between two halves of a table ends the run: 15 + one plain + 15 is no table, and
	 * 16 + one plain + 5 is (the first run reaches the floor, the key is believed for the stretch) */
	{
		unsigned split;

		for (split = 15; split <= 16; split++) {
			size_t m = make_table(obj, orig, split, 0x22, 30u, 21u), m2;
			uint8_t pl2[1u << 13];

			memcpy(obj + m, "a plain record of text\0", 23u);
			m += 23u;
			m2 = make_table(obj + m, pl2, 15u, 0x22, 30u, 22u);
			m += m2;
			kof_exe_strtab(obj, m, NULL, &res);
			NCKF((split == 15u) == (res.records == 0u), "split %u: %llu records", split,
			     (unsigned long long)res.records);
		}
	}
	/* records of three characters are not anchors, whatever their number */
	{
		size_t m = 0;

		memset(obj, 0, sizeof obj);
		for (i = 0; i < 400u; i++)
			m += put_rec(obj + m, "a b", 3u, 0x22, 0, 1u);
		memcpy(orig, obj, m);
		NCK(kof_exe_strtab(obj, m, NULL, &res) == 0 && !memcmp(obj, orig, m));
		memset(obj, 0, sizeof obj);
		m = 0;
		for (i = 0; i < 400u; i++)
			m += put_rec(obj + m, "a bc", 4u, 0x22, 0, 1u);
		NCK(kof_exe_strtab(obj, m, NULL, &res) == 1 && res.records == 400u);
	}
	/* unreadable under the key but not one letter in the text: digits and punctuation are not a table */
	{
		size_t m = 0;

		memset(obj, 0, sizeof obj);
		for (i = 0; i < 40u; i++)
			m += put_rec(obj + m, "1234 5678 90 12-34", 18u, 0x22, 0, 1u);
		memcpy(orig, obj, m);
		NCK(kof_exe_strtab(obj, m, NULL, &res) == 0 && !memcmp(obj, orig, m));
		NCK(!kof_exe_strtab_would_change(obj, m));
	}
	/* a table with no zero after its last record: 15 counted, 16th not terminated */
	{
		size_t m = make_table(obj, orig, 16u, 0x22, 30u, 2u);

		while (obj[m - 1u] == 0)
			m--;                    /* now the last byte is the terminator K */
		memcpy(orig, obj, m);
		kof_exe_strtab(obj, m, NULL, &res);
		NCK(res.records == 0 && !memcmp(obj, orig, m));
		NCK(!kof_exe_strtab_would_change(obj, m));
		obj[m] = 0;
		kof_exe_strtab(obj, m + 1u, NULL, &res);
		NCK(res.records == 16u);
	}
	/* records of one byte or none are not records */
	memset(obj, 0x22, sizeof obj);
	for (i = 1; i < sizeof obj; i += 2u)
		obj[i] = 0;
	NCK(kof_exe_strtab(obj, sizeof obj, NULL, &res) == 0);
}

/* ---- differential ------------------------------------------------------------------------ */

static void gen(struct nrng *r, uint8_t *b, size_t n, size_t *tn_out)
{
	size_t at = 0;

	(void)tn_out;
	while (at < n) {
		unsigned kind = nr_below(r, 6u);
		size_t room = n - at, take;

		if (kind == 0) {                        /* random bytes */
			take = 1u + nr_below(r, 200u);
			if (take > room)
				take = room;
			while (take--)
				b[at++] = (uint8_t)nr_next(r);
		} else if (kind == 1) {                 /* zeros */
			take = 1u + nr_below(r, 40u);
			if (take > room)
				take = room;
			memset(b + at, 0, take);
			at += take;
		} else if (kind == 2) {                 /* a table */
			uint8_t pl[4096], tb[4096];
			unsigned nrec = 8u + nr_below(r, 30u);
			uint8_t k = (uint8_t)(1u + nr_below(r, 255u));
			size_t tn = make_table(tb, pl, nrec, k, 12u + nr_below(r, 30u), (unsigned)nr_next(r));

			if (tn > room)
				tn = room;
			memcpy(b + at, tb, tn);
			at += tn;
		} else if (kind == 3) {                 /* a plain string */
			static const char s[] = "some plain text of the object\0";

			take = sizeof s;
			if (take > room)
				take = room;
			memcpy(b + at, s, take);
			at += take;
		} else {                                /* text-like bytes, zero separated */
			take = 1u + nr_below(r, 120u);
			if (take > room)
				take = room;
			while (take--) {
				uint8_t c = (uint8_t)(0x1fu + nr_below(r, 0x62u));

				b[at++] = nr_below(r, 12u) ? c : 0;
			}
		}
	}
}

static void differential(void)
{
	unsigned seed, changed = 0, believed = 0;

	for (seed = 1; seed <= 3000u; seed++) {
		struct nrng r;
		static uint8_t a[6000], b[6000], c[6000], keep[800];
		size_t n = 64u + (seed * 37u) % 5900u, i;
		struct kof_exe_strtab_res pr, rr;
		const uint8_t *kp = NULL;
		int pc, rc;

		nr_seed(&r, seed);
		gen(&r, a, n, NULL);
		if (seed % 3u) {
			memset(keep, 0, sizeof keep);
			for (i = 0; i < n; i++)
				if (nr_below(&r, 400u) == 0u)
					for (size_t j = i; j < i + 200u && j < n; j++)
						keep[j >> 3] |= (uint8_t)(1u << (j & 7u));
			kp = keep;
		}
		memcpy(b, a, n);
		memcpy(c, a, n);
		pc = kof_exe_strtab(b, n, kp, &pr);
		rc = oracle(c, n, kp, &rr);
		NCKF(pc == rc && !memcmp(b, c, n) && pr.records == rr.records && pr.chars == rr.chars &&
		     pr.keys == rr.keys && pr.stretches == rr.stretches,
		     "seed %u n %zu: product %d/%llu oracle %d/%llu", seed, n, pc, (unsigned long long)pr.records, rc,
		     (unsigned long long)rr.records);
		if (pc)
			changed++;
		if (rr.keys)
			believed++;
		/* only a kept byte may differ from the object, and none does */
		if (kp)
			for (i = 0; i < n; i++)
				if (kp[i >> 3] >> (i & 7u) & 1u)
					NCKF(b[i] == a[i], "seed %u: a kept byte %zu moved", seed, i);
		/* idempotent */
		memcpy(c, b, n);
		NCKF(kof_exe_strtab(c, n, kp, NULL) == 0 && !memcmp(b, c, n), "seed %u: not idempotent", seed);
		/* the probe: with no map, no "no" where the pass writes */
		memcpy(c, a, n);
		{
			int w = kof_exe_strtab(c, n, NULL, NULL);

			NCKF(!w || kof_exe_strtab_would_change(a, n), "seed %u: the probe said no", seed);
			if (!kof_exe_strtab_would_change(a, n))
				NCKF(!w && !memcmp(c, a, n), "seed %u: probe no, pass wrote", seed);
		}
	}
	NCKF(changed > 300u && believed > 300u, "the generator reached a decode in %u of 3000 (%u believed)", changed,
	     believed);
}

/* ---- guard pages ------------------------------------------------------------------------- */

static int guard_group(void *arg)
{
	size_t n;
	int tail = *(int *)arg;

	for (n = 0; n <= 80u; n++) {
		struct gbuf g, kg;
		size_t i;
		uint8_t tmp[128];

		if (!gb_new(&g, n, tail) || !gb_new(&kg, (n + 7u) / 8u, tail))
			return 1;
		for (i = 0; i < n; i++)
			g.p[i] = (uint8_t)(n % 3u ? 0x22u ^ (uint8_t)(0x41u + i) : (i % 5u ? 0x22u : 0u));
		memcpy(tmp, g.p, n);
		(void)kof_exe_strtab(g.p, n, NULL, NULL);
		(void)kof_exe_strtab_would_change(g.p, n);
		memcpy(g.p, tmp, n);
		memset(kg.p, 0xaa, kg.n);
		(void)kof_exe_strtab(g.p, n, kg.p, NULL);
		memcpy(g.p, tmp, n);
		memset(kg.p, 0xff, kg.n);
		(void)kof_exe_strtab(g.p, n, kg.p, NULL);
		gb_free(&g);
		gb_free(&kg);
	}
	return 0;
}

static void guards(void)
{
	int tail;

	for (tail = 0; tail < 2; tail++)
		NCKF(nr_group("guard", guard_group, &tail) == 0, "guard pages, tail %d", tail);
}

/* ---- hostile, 64 MB ---------------------------------------------------------------------- */

#define BIG (64u << 20)

static double secs(struct timespec a, struct timespec b)
{
	return (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}

static int hostile_group(void *arg)
{
	uint8_t *o = malloc(BIG), *plain = malloc(BIG);
	struct kof_exe_strtab_res res;
	struct timespec t0, t1;
	size_t i, n;
	struct nrng r;
	(void)arg;

	if (!o || !plain)
		return 1;
	/* random bytes */
	nr_seed(&r, 99);
	for (i = 0; i < BIG; i++)
		o[i] = (uint8_t)nr_next(&r);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	(void)kof_exe_strtab(o, BIG, NULL, &res);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	printf("  hostile random 64 MB: %.3f s, %llu records\n", secs(t0, t1), (unsigned long long)res.records);
	/* zeros, and one byte */
	memset(o, 0, BIG);
	NCK(kof_exe_strtab(o, BIG, NULL, &res) == 0 && !kof_exe_strtab_would_change(o, BIG));
	memset(o, 0x01, BIG);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	NCK(kof_exe_strtab(o, BIG, NULL, &res) == 0 && !kof_exe_strtab_would_change(o, BIG));
	clock_gettime(CLOCK_MONOTONIC, &t1);
	printf("  hostile one byte 64 MB: %.3f s\n", secs(t0, t1));
	/* the same short records over and over: every one is an anchor of one key */
	n = 0;
	while (n + 64u < BIG) {
		uint8_t pl[64];
		size_t m = make_table(o + n, pl, 1u, 0x22, 40u, (unsigned)(n >> 6));

		memcpy(plain + n, pl, m);
		n += m;
	}
	memset(o + n, 0, BIG - n);
	memset(plain + n, 0, BIG - n);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	NCK(kof_exe_strtab(o, BIG, NULL, &res) == 1);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	NCKF(!memcmp(o, plain, BIG), "the whole 64 MB table is the text");
	NCKF(res.records > 1000000u, "records %llu", (unsigned long long)res.records);
	printf("  hostile table 64 MB: %.3f s, %llu records, nothing dropped\n", secs(t0, t1),
	       (unsigned long long)res.records);
	free(o);
	free(plain);
	return 0;
}

int main(void)
{
	known_answer();
	every_key();
	floors();
	kept();
	not_evidence();
	differential();
	guards();
	NCKF(nr_group("hostile", hostile_group, NULL) == 0, "hostile 64 MB group");
	printf("normalizer_strtab: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
