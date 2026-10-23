/*
 * textual_anchor.c - the decoders a literal is put through, read from the code in front of it, for the
 * languages that call them by name (php's base64_decode, js's atob). What is language specific is the
 * list and three small spellings, and a lang row hands them over as a kgenome_textual_call_style.
 */

#include <string.h>

#include "textual_lang.h"

/* Does the name as written (`len` bytes) spell the row's `w`: the whole name, or - where names are qualified - its last words: a row
 * "decompress" is "zlib.decompress" too, and "gzip.decompress" is only that. */
static int spelled(const struct kgenome_textual_call_style *st, const uint8_t *name, uint32_t len, const char *w)
{
	uint32_t rl = (uint32_t)strlen(w);

	if (rl != len && !(st->qualify && rl < len && name[len - rl - 1u] == st->qualify))
		return 0;
	return st->fold ? kgenome_textual_ci_eq(name + (len - rl), w, rl) : memcmp(name + (len - rl), w, rl) == 0;
}

const struct kgenome_textual_decoder_row kgenome_textual_dotnet_decoders[] = {
	{ "frombase64string", KGENOME_TEXTUAL_DEC_B64 },
	{ "fromhexstring",    KGENOME_TEXTUAL_DEC_HEX },
	{ "urldecode",        KGENOME_TEXTUAL_DEC_URL },
	{ "unescapedatastring", KGENOME_TEXTUAL_DEC_RAWURL },   /* Uri.UnescapeDataString keeps "+"; UrlDecode reads it as a space [Unverified: no .NET here] */
};

static uint8_t decoder_of(const struct kgenome_textual_call_style *st, const uint8_t *name, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < st->n_rows; i++)
		if (spelled(st, name, len, st->rows[i].name))
			return st->rows[i].dec;
	for (i = 0; st->fns && i < st->fns->n; i++)
		if (st->fns->rows[i].fn.form == KGENOME_TEXTUAL_FN_FORM_NEVER && spelled(st, name, len, st->fns->rows[i].name))
			return (uint8_t)st->fns->rows[i].fn.op;
	return KGENOME_TEXTUAL_DEC_NONE;
}

uint32_t kgenome_textual_lang_chain(const struct kgenome_textual_lang *l, const uint8_t *tail, uint32_t n, uint8_t *chain,
				    uint32_t cap, uint32_t *from)
{
	if (l->call_chain)
		return l->call_chain(tail, n, chain, cap, from);
	if (l->calls)
		return kgenome_textual_call_chain(l->calls, tail, n, chain, cap, from);
	*from = n;
	return 0;
}

uint32_t kgenome_textual_call_chain(const struct kgenome_textual_call_style *st, const uint8_t *tail,
				    uint32_t n, uint8_t *chain, uint32_t cap, uint32_t *from_out)
{
	uint32_t i = n, k = 0, kept = n;

	while (k < cap && i && tail[i - 1u] == '(') {
		uint32_t end = i - 1u, s = end, from;
		uint8_t dec;

		while (s && (kgenome_textual_ident(tail[s - 1u]) || (st->dollar && tail[s - 1u] == '$')))
			s--;
		/* "a.b.name(": the words in front of it, up to a dot that has a name before it */
		while (st->qualify && s >= 2u && tail[s - 1u] == st->qualify && kgenome_textual_ident(tail[s - 2u])) {
			s--;
			while (s && kgenome_textual_ident(tail[s - 1u]))
				s--;
		}
		from = s;
		if (st->slash && s && tail[s - 1u] == '\\')
			s--;
		dec = decoder_of(st, tail + from, end - from);
		if (!dec)
			break;
		chain[k++] = dec;
		while (st->receiver && s >= 2u && tail[s - 1u] == '.' && kgenome_textual_ident(tail[s - 2u])) {
			s--;
			while (s && kgenome_textual_ident(tail[s - 1u]))
				s--;
		}
		i = s;
		while (st->silence && i && tail[i - 1u] == '@')
			i--;
		kept = i;
	}
	*from_out = kept;
	return k;
}
