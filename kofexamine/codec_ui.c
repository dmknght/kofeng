/*
 * codec_ui.c - what a PERSON types to pick and key a coding: the word it is
 * called by, whether it takes a key, and a key read out of text. The algorithms
 * are libuncoat's (kuncoat_transform); this is only the translation from the
 * reader's choice to a transform step.
 */

#include <kofcore.h>            /* kof_hex_val */
#include "codec_ui.h"


const char *kof_codec_name(uint32_t codec)
{
	switch (codec) {
	case KOF_CODEC_B64:     return "base64";
	case KOF_CODEC_HEX:     return "hex";
	case KOF_CODEC_URL:     return "url";
	case KOF_CODEC_XOR:     return "xor";
	case KOF_CODEC_ADD:     return "add";
	case KOF_CODEC_CAESAR:  return "caesar";
	case KOF_CODEC_REVERSE: return "reverse";
	default:                return "?";
	}
}

int kof_codec_keyed(uint32_t codec)
{
	return codec == KOF_CODEC_XOR || codec == KOF_CODEC_ADD ||
	       codec == KOF_CODEC_CAESAR;
}

uint32_t kof_codec_key(const char *text)
{
	uint32_t k = 0;

	if (!text)
		return 0;
	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
		text += 2;
	for (; *text; text++) {
		int d = kof_hex_val((uint8_t)*text);

		if (d < 0)
			return k;
		k = (k << 4) | (uint32_t)d;
	}
	return k;
}

int kof_codec_step(uint32_t codec, uint32_t key, int encode, uint8_t keybyte[1],
		   struct kuncoat_step *step)
{
	step->flags = 0;
	step->k32 = key;
	step->key = NULL;
	step->key_len = 0;
	step->max_out = 0;
	step->dir = encode ? KUNCOAT_ENCODE : KUNCOAT_DECODE;
	switch (codec) {
	case KOF_CODEC_B64:     step->algo = KUNCOAT_ALGO_B64; break;
	case KOF_CODEC_HEX:     step->algo = KUNCOAT_ALGO_HEX; break;
	case KOF_CODEC_URL:     step->algo = KUNCOAT_ALGO_URL; break;
	case KOF_CODEC_XOR:
		/* The typed xor is the repeating-key cipher with a one byte key:
		 * one xor in the lib, not two. */
		keybyte[0] = (uint8_t)key;
		step->algo = KUNCOAT_ALGO_XOR_KEY;
		step->key = keybyte;
		step->key_len = 1u;
		break;
	case KOF_CODEC_ADD:     step->algo = KUNCOAT_ALGO_ADD; break;
	case KOF_CODEC_CAESAR:  step->algo = KUNCOAT_ALGO_CAESAR; break;
	case KOF_CODEC_REVERSE: step->algo = KUNCOAT_ALGO_REVERSE; break;
	default:
		step->algo = KUNCOAT_ALGO_NONE;
		return 0;
	}
	return 1;
}
