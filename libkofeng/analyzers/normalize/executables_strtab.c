/*
 * executables_strtab.c - the string table of a family that hides its strings with one byte: every
 * record is the text xor K, and K is also the record's own terminator (the NUL, xor K). See
 * kof_exe_strtab in executables.h. SCAN PATH: called from the normalise step (scan_norm.c), never
 * by a viewer.
 *
 * THE BASIS OF THE KEY, AND WHY IT IS NOT A TRIAL.
 *
 * A record is a run of non-zero bytes that a zero follows (a C string literal's own terminator),
 * and its LAST byte names the key it proposes: the author's source ends every entry with the
 * encoded NUL, so the byte before the real NUL is `0 ^ K`. That is one candidate per record, read
 * out of the record, and it is checked against the same record: every other byte xor K must be
 * text and at least one a letter. 256 keys are never tried over a stretch. A key is believed only
 * when the stretch itself carries the evidence: a run of KOF_EXE_STR_ANCHOR_MIN records next to
 * each other that end in it, are unreadable as they stand (a record that is already text is not
 * evidence of a coding) and read as text under it, KOF_EXE_STR_CHARS_MIN characters in all. The evidence is read
 * from the stretch that is rewritten, never from the code beside it: code is full of short
 * records whose last byte is 0x01.
 *
 * MEASURED (agent-reported, a python twin of the rule over the data sections of 1379 clean ELF:
 * /usr/bin and 900 libraries): the longest clean run of such records was 46 records / 184
 * characters (floors 16 / 256, records of 4 characters or more); the Mirai sample be0826d7 has a run
 * of 19 records / 1541 characters under 0x22 and 95 records of that key in all. The floors are a
 * trade: a table whose records are not next to each other, or are shorter, is left as it is.
 *
 * WHAT IT WRITES. Every record of the stretch whose last byte is a believed key and that reads as
 * text under it (a record that is already text and ends in K too is decoded: the table holds
 * printable ciphertext as well) is xored in place, terminator included, so the entry becomes a
 * C string. Length preserving and in the object's own offsets: nothing moves, so the offset map
 * and every region still name the original bytes, and a derived object inherits it.
 *
 * NO CAP. The work is one read of each stretch and one more of the records of a believed key, so
 * it follows the object and drops nothing; there is nothing to report as a limit (rule 4).
 */

#include <stdint.h>
#include <string.h>
#include <kofcore.h>
#include <uncoat.h>

#include "executables.h"
#include "executables_private.h"

/* Text for this purpose: printable ASCII and the three white space bytes a table entry may hold. */
static inline int str_text(uint8_t c)
{
	return kof_is_print(c) || c == '\t' || c == '\n' || c == '\r';
}

static inline int str_letter(uint8_t c)
{
	return (uint8_t)((c | 0x20u) - 'a') < 26u;
}

/* The record p[s..e) is text as it stands. */
static int str_plain(const uint8_t *p, uint64_t s, uint64_t e)
{
	for (; s < e; s++)
		if (!str_text(p[s]))
			return 0;
	return 1;
}

/* p[s..e) xor k is text; with `need_letter` at least one of them is a letter. */
static int str_reads(const uint8_t *p, uint64_t s, uint64_t e, uint8_t k, int need_letter)
{
	int letter = 0;

	for (; s < e; s++) {
		uint8_t c = (uint8_t)(p[s] ^ k);

		if (!str_text(c))
			return 0;
		letter |= str_letter(c);
	}
	return letter || !need_letter;
}

/*
 * The evidence of [a, b): a RUN of consecutive records (the empty ones between them, the zero
 * padding, do not break it) that end in one key, are KOF_EXE_STR_LEN_MIN or more characters
 * under it, are unreadable as they stand and read as text with a letter under it. A key is
 * believed when a run reaches KOF_EXE_STR_ANCHOR_MIN records and KOF_EXE_STR_CHARS_MIN characters.
 * Any other record - plain text, binary, too short - ends the run, and a record that no zero follows
 * inside the stretch is not known to be one and is not read. Sets the bits of the believed keys in
 * `keys` and returns how many.
 *
 * WHY A RUN AND NOT A COUNT. A count of such records over a stretch was measured first: 339 of 1445
 * clean ELF read a "table" in their data sections (relocation and hash tables are full of short
 * records whose last byte repeats and that read as text under a small key by chance). The records of
 * a coded string table are NEXT to each other, and a run of them is what a table is.
 */
static uint32_t str_keys(const uint8_t *p, uint64_t a, uint64_t b, uint8_t keys[32])
{
	uint64_t s = a, run_n = 0, run_c = 0;
	uint8_t run_k = 0;
	uint32_t got = 0;

	while (s < b) {
		const uint8_t *z;
		uint64_t e;

		if (!p[s]) {
			s++;
			continue;
		}
		z = memchr(p + s, 0, (size_t)(b - s));
		if (!z)
			break;
		e = (uint64_t)(z - p);
		if (e - s > KOF_EXE_STR_LEN_MIN && !str_plain(p, s, e) && str_reads(p, s, e - 1u, p[e - 1u], 1)) {
			if (run_n && p[e - 1u] == run_k) {
				run_n++;
				run_c += e - 1u - s;
			} else {
				run_k = p[e - 1u];
				run_n = 1;
				run_c = e - 1u - s;
			}
			if (run_n >= KOF_EXE_STR_ANCHOR_MIN && run_c >= KOF_EXE_STR_CHARS_MIN &&
			    !(keys[run_k >> 3] >> (run_k & 7u) & 1u)) {
				keys[run_k >> 3] |= (uint8_t)(1u << (run_k & 7u));
				got++;
			}
		} else {
			run_n = 0;
		}
		s = e + 1u;
	}
	return got;
}

/* Decode the records of [a, b) whose last byte is a believed key. */
static void str_decode(uint8_t *p, uint64_t a, uint64_t b, const uint8_t keys[32],
		       struct kof_exe_strtab_res *res)
{
	uint64_t s = a;

	while (s < b) {
		const uint8_t *z;
		uint64_t e;
		uint8_t k;

		if (!p[s]) {
			s++;
			continue;
		}
		z = memchr(p + s, 0, (size_t)(b - s));
		if (!z)
			break;
		e = (uint64_t)(z - p);
		k = p[e - 1u];
		if (e - s >= 2u && (keys[k >> 3] >> (k & 7u) & 1u) && str_reads(p, s, e - 1u, k, 0)) {
			struct kuncoat_step st = { .algo = KUNCOAT_ALGO_XOR_KEY, .dir = KUNCOAT_DECODE,
						   .flags = 0, .k32 = 0, .k32b = 0, .key = &k, .key_len = 1,
						   .max_out = 0 };
			uint64_t got = 0;

			if (kuncoat_transform(&st, p + s, e - s, p + s, e - s, &got) == KUNCOAT_OK && got == e - s) {
				res->records++;
				res->chars += e - 1u - s;
			}
		}
		s = e + 1u;
	}
}

/* The next stretch of bytes the keep map leaves free, from `*at`; 0 when there is none. */
static int str_stretch(const uint8_t *keep, uint64_t n, uint64_t *at, uint64_t *a, uint64_t *b)
{
	uint64_t i = *at;

	if (!keep) {
		if (i)
			return 0;
		*a = 0;
		*b = n;
		*at = n ? n : 1u;
		return n != 0;
	}
	while (i < n && keep[i >> 3] == 0xffu && !(i & 7u))
		i += 8u;
	while (i < n && (keep[i >> 3] >> (i & 7u) & 1u))
		i++;
	if (i >= n)
		return 0;
	*a = i;
	while (i < n && !(keep[i >> 3] >> (i & 7u) & 1u))
		i++;
	*b = i;
	*at = i;
	return 1;
}

int kof_exe_strtab(uint8_t *p, uint64_t n, const uint8_t *keep, struct kof_exe_strtab_res *res)
{
	struct kof_exe_strtab_res none;
	uint64_t at = 0, a, b;

	if (!res)
		res = &none;
	memset(res, 0, sizeof *res);
	if (!p || !n)
		return 0;
	while (str_stretch(keep, n, &at, &a, &b)) {
		uint8_t keys[32] = { 0 };
		uint32_t k;

		res->stretches++;
		k = str_keys(p, a, b, keys);
		if (!k)
			continue;
		res->keys += k;
		str_decode(p, a, b, keys, res);
	}
	return res->records != 0;
}

int kof_exe_strtab_would_change(const uint8_t *p, uint64_t n)
{
	uint8_t keys[32] = { 0 };

	if (!p || !n)
		return 0;
	return str_keys(p, 0, n, keys) != 0;
}
