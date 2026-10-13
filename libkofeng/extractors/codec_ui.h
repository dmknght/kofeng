#ifndef KOFENG_DECODERS_CODEC_UI_H
#define KOFENG_DECODERS_CODEC_UI_H

/*
 * codec_ui.h - the codings of text a PERSON picks and keys: names, which
 * take a key, a key read from typed text, and the step they mean.
 *
 * THIS IS THE USER-INTERFACE HALF. What a coding MEANS - bytes in, bytes out, in
 * either direction - is libuncoat's, one function for every coding and every cipher
 * (kuncoat_transform). What is here is what a reader of a tool chooses and types:
 * the word a coding is picked by, whether it takes a key, and a key read from text.
 * Those are not algorithms, so they are not in the lib.
 */

#include <stddef.h>
#include <stdint.h>
#include <uncoat.h>

/* ---- the string codings ----------------------------------------------------
 *
 * WHAT A SAMPLE WROTE ITS STRINGS IN, both ways through.
 *
 * EVERY ONE OF THESE EITHER HAS NO KEY OR HAS A KEY SOMEBODY CAN TYPE. A coding
 * whose key must be RECOVERED is a different problem and belongs in a module
 * that derives it, the way bases/unp/ezuri.c does.
 */
enum kof_codec {
	KOF_CODEC_B64 = 0,
	KOF_CODEC_HEX,
	/*
	 * URL, AND IT IS `%XX` AND NOTHING ELSE.
	 *
	 * The same one form the norm view decodes - unpct_range in
	 * normalize/executables.c - and for the same reason: an IoT dropper
	 * carries its commands percent-encoded by the protocol rather than by
	 * its author, so what is in the file is `wget+http%3A%2F%2F...` while
	 * what a rule is written against is the plain text. A reader needs
	 * both directions of exactly that, and neither of the other escape
	 * conventions - \xNN, &#NN; - belongs here with it.
	 *
	 * `+` reads as a space, because the samples that need this are form
	 * bodies. Writing escapes everything outside RFC 3986's unreserved
	 * set, `+` among them, so the two passes stay inverses.
	 */
	KOF_CODEC_URL,
	KOF_CODEC_XOR,          /* one byte, typed */
	KOF_CODEC_ADD,          /* byte + n, typed - subsumes a byte rotate */
	/*
	 * CAESAR, AND IT REPLACES BOTH A BIT ROTATE AND A FIXED ROT13.
	 *
	 * They were two controls for one idea and neither was the useful half.
	 * ROT13 is Caesar with the key written into its name, so it cannot
	 * decode the rot-7 next to it; a BIT rotate turns text into bytes
	 * outside ASCII almost every time, which is the opposite of what a
	 * coding for encoded TEXT is for.
	 *
	 * One coding with a typed key covers rot13 by typing 13, and every
	 * other shift by typing it.
	 */
	KOF_CODEC_CAESAR,
	KOF_CODEC_REVERSE,
	KOF_CODEC_COUNT
};

/* The word a reader picks it by. "?" for a value that is not a coding. */
const char *kof_codec_name(uint32_t codec);

/* Does this one take a key the reader types - see enum kof_codec. */
int kof_codec_keyed(uint32_t codec);

/*
 * A typed key as a number. Hex without a prefix, because a key written down
 * anywhere is written in hex - and "0x" is accepted for the reader who types it
 * out of habit. Stops at the first character that is not a hex digit, so a
 * half-typed key is worth what has been typed so far.
 */
uint32_t kof_codec_key(const char *text);

/*
 * The transform step a coding and a typed key mean, for kuncoat_transform
 * (<uncoat.h>) - the one place the text codings are run.
 *
 * `encode` chooses the direction: 0 reads the coding - "what does this say" - and
 * non-zero writes it - "what would this look like written that way", which is what
 * a researcher needs while WRITING a rule, because the pattern to be matched is the
 * encoded form. `keybyte` is storage for the xor key, which the step points at, so
 * it must outlive the call to kuncoat_transform.
 *
 * Returns 0 for a value that is not a coding (the step's algorithm is then NONE
 * and kuncoat_transform answers UNSUPPORTED), 1 otherwise.
 *
 * The result of the run is the lib's status plus a count. A tool that shows "this
 * coding cannot read this text" shows it when the status is not KUNCOAT_OK and
 * not KUNCOAT_OVER_BUDGET (a prefix of the answer is still the answer shown).
 * Which direction each one has is in transform.h.
 */
int kof_codec_step(uint32_t codec, uint32_t key, int encode, uint8_t keybyte[1],
		   struct kuncoat_step *step);

#endif /* KOFENG_DECODERS_CODEC_UI_H */
