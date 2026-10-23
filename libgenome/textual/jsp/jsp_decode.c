/*
 * jsp_decode.c - the java calls that decode a literal, read from the code in front of it (the lang row's
 * call_chain). The generic reader of textual_anchor.c reads "name(" and nothing before the name; java's
 * decoders are METHODS, so what decides is the qualifier, and `tail` has had its white space taken out
 * except where it parts two words ("new BASE64Decoder()" arrives as written, one space).
 *
 * WHAT IS RECOGNISED, as the text that ends the tail, and why only these:
 *   getDecoder().decode(  getMimeDecoder().decode(      java.util.Base64, standard alphabet
 *   new BASE64Decoder().decodeBuffer(  new sun.misc.BASE64Decoder().decodeBuffer(
 *   Base64.decodeBase64(  new Base64().decode(          commons-codec
 *   parseBase64Binary(                                  javax.xml.bind.DatatypeConverter
 *   parseHexBinary(                                     the same class, hex
 *   URLDecoder.decode(                                  java.net, percent decoding
 *
 * "decode(" ALONE IS NOT: Integer.decode, Long.decode, Color.decode and Charset.decode share the name, so
 * the method is taken only with the receiver that says which decoder it is (getDecoder(), a Base64 or a
 * URLDecoder). getUrlDecoder() is left out on purpose: its alphabet is "-_", and the hook's B64 reads the
 * standard one. A decoder held in a variable (`Decoder d = Base64.getDecoder(); d.decode("..")`) has no
 * receiver here and is not read. A literal that is not the whole argument ("a" + "b", or followed by
 * ".toCharArray()") is never applied: the form's hook acts only when ")" or "," follows the literal.
 * The qualifier in front ("java.util.Base64.") is walked over so a chain can go on outward:
 * new String(Base64.getDecoder().decode(URLDecoder.decode("..", "UTF-8"))) is URL, then B64.
 */

#include "jsp.h"

struct row {
	const char *tail;       /* what ends the tail */
	uint8_t     dec;        /* enum kgenome_textual_decoder */
};

static const struct row row_of[] = {
	{ "getDecoder().decode(",                       KGENOME_TEXTUAL_DEC_B64 },
	{ "getMimeDecoder().decode(",                   KGENOME_TEXTUAL_DEC_B64 },
	{ "new BASE64Decoder().decodeBuffer(",           KGENOME_TEXTUAL_DEC_B64 },
	{ "new sun.misc.BASE64Decoder().decodeBuffer(",  KGENOME_TEXTUAL_DEC_B64 },
	{ "Base64.decodeBase64(",                       KGENOME_TEXTUAL_DEC_B64 },
	{ "new Base64().decode(",                        KGENOME_TEXTUAL_DEC_B64 },
	{ "parseBase64Binary(",                         KGENOME_TEXTUAL_DEC_B64 },
	{ "parseHexBinary(",                            KGENOME_TEXTUAL_DEC_HEX },
	{ "URLDecoder.decode(",                         KGENOME_TEXTUAL_DEC_URL },
};

/* The row the first `n` bytes of `tail` end with, with a name boundary in front; NULL when none. */
static const struct row *row_at(const uint8_t *tail, uint32_t n, uint32_t *len)
{
	uint32_t k;

	for (k = 0; k < sizeof row_of / sizeof row_of[0]; k++) {
		uint32_t l = (uint32_t)strlen(row_of[k].tail);

		if (l <= n && memcmp(tail + n - l, row_of[k].tail, l) == 0 &&
		    (l == n || !kgenome_textual_ident(tail[n - l - 1u]))) {
			*len = l;
			return &row_of[k];
		}
	}
	return NULL;
}

uint32_t kgenome_textual_jsp_call_chain(const uint8_t *tail, uint32_t n, uint8_t *chain, uint32_t cap,
				    uint32_t *from)
{
	uint32_t k = 0, len;
	const struct row *r;

	while (k < cap && (r = row_at(tail, n, &len)) != NULL) {
		chain[k++] = r->dec;
		n -= len;
		while (n && (kgenome_textual_ident(tail[n - 1u]) || tail[n - 1u] == '.'))
			n--;            /* the qualifier: java.util.Base64. */
	}
	*from = n;
	return k;
}
