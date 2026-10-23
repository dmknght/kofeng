/*
 * ruby_lang.c - the row for ruby: its lexer, what the form keeps of white space, the decoders a script calls on its own
 * literals, and what the form needs to know.
 *
 * WHITE SPACE IS SYNTAX IN RUBY, in more places than a pair of bytes can say: "puts -x" is a call and "puts - x" a subtraction,
 * "foo /x/" a call with a pattern and "foo / x" a division, "p [1]" and "p[1]" differ, "puts (1)" and "puts(1)", "foo ?a" and
 * "foo?a", "foo {}" and "foo({})". So the row says `ws_significant`, as sh's does: white space between two tokens is kept as one
 * space wherever there was any, and `glue` is not asked. Not `glue`: it sees two bytes, and a space kept before "-" and dropped
 * after it would turn "a - 1" into "a -1". A line break stays one (a statement ends at it); the indentation, the blank lines and
 * the comments go; "\r\n" is "\n" and a lone "\r" is a blank (the interpreter's own reading, so there is no `universal_eol`); the
 * "#!" line stays (`keep_hashbang`). A backslash and its line break join two lines (`continuation`).
 *
 * WHAT THE FORM CANNOT KEEP, measured with ripper on the 21329 .rb files of this machine (the tree of the form, positions taken
 * out and spelled-out bytes written one way, against the tree of the file): 21319 are the same program. The 9 that are not are
 * files whose first lines hold a MAGIC COMMENT (`# encoding: binary`, `# -*- coding: binary -*-`) which makes a regexp or a string
 * with a high byte legal: the form takes every comment out, that one too, and then ruby refuses the text. Keeping them is
 * `keep_hashbang`'s job for line 1 only; the comment is on line 1 or 2. Reported, not worked around. The other known change is
 * a comment line (or a blank one) right after a line's backslash, which the form closes up ("x = 1 \<nl># c<nl>y = 2" is two
 * statements and its form is one): found by the form-of-a-form test, which is why ruby_lex.c reads it so, and never seen in a file.
 *
 * NO `concat`, ON PURPOSE. The form joins "a" + "b" into one literal when the join ends its argument, and it joins pieces that have
 * the same delimiters. In ruby that is sound for '...', "..." and %q %Q %( and for nothing else the lexer calls a STRING:
 * %w[a b] + %w[c] is an array sum and the form would write %w[a bc], and `a` + `b` runs two commands where `ab` runs one.
 * Measured on the same files: 352 joins in 151 files, and in 2 of those files (bindata/struct.rb, rex/random_identifier/
 * generator.rb) the join glued the last word of one %w list to the first of the next, a different program (ripper's tree of the
 * form is not the tree of the file). The form has no way to ask the row which pieces may join - the row's only say is the byte -
 * so the row does not offer it, and `"ev" + "al"` is kept as typed. Turning it on is `.concat = '+'` here plus a per-literal
 * test in textual_form.c's fold_held (a piece may join only when its delimiter is a quote or a %q %Q % opener). A join at the end
 * of a LINE would also need the form to end an expression at a ruby line break, which it does only for python's and vbscript's
 * line rules; and adjacent literals ("a" "b") would need the same, so there is no `concat_adjacent`.
 */

#include "ruby.h"

/*
 * THE DECODERS, as they are written - "Base64.decode64(" or "decode64(" after an include - read by the name and, where
 * a module qualifies it, by the module: the first row that ends the written name wins. Each was checked against
 * ruby 3.3 (Base64.methods, Zlib.methods, CGI.unescape and URI.decode_www_form_component run on a case each):
 *   - base64: Base64.decode64, strict_decode64 and urlsafe_decode64 - the last reads "-" and "_" for "+" and "/", which the
 *     engine's decoder skips ([Unverified]: read in libuncoat/decoders/codings.c, the hook of objctx_script_dec.c was not
 *     run here), so `ruby_payload_ok` keeps a value with either from it;
 *   - zlib: Zlib::Inflate.inflate, Zlib.inflate and Zlib::Inflate#inflate (the bare name "inflate" is all three; the
 *     engine's decoder reads raw deflate under that name too - [Unverified], from the comment of its zlib_hdr_len -
 *     which is what Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate needs), Zlib.gunzip as gzip;
 *   - url: CGI.unescape and URI.decode_www_form_component, which turn "+" into a space as the url decoder does
 *     (CGI.unescapeURIComponent and URI.decode_uri_component keep the "+", and are not here).
 * "::" is how a module is written and the call chain reads a name qualified by one byte, ".", so "Zlib::Inflate.inflate"
 * is read as the name "Inflate.inflate" and "Base64::decode64" as the bare "decode64".
 *
 * NOT EXPRESSIBLE, and so not here: `[x].pack("m")`, `x.unpack1("m")` and `x.unpack("H*")` are methods called ON a
 * literal - nothing is called over it, so the code in front of the literal says nothing; hex has no decoder that takes
 * a literal ("41".hex is a method on it, `["41"].pack("H*")` a pack); a call written without brackets
 * (`Base64.decode64 "..."`) has no "(" for the chain to read; Zlib::GzipReader.new(StringIO.new(x)) has two calls
 * in between; Rex::Text.decode_base64 is metasploit's and not the language's.
 */
static const struct kgenome_textual_decoder_row decoder_row[] = {
	{ "decode64",                 KGENOME_TEXTUAL_DEC_B64 },
	{ "strict_decode64",          KGENOME_TEXTUAL_DEC_B64 },
	{ "urlsafe_decode64",         KGENOME_TEXTUAL_DEC_B64 },
	{ "inflate",                  KGENOME_TEXTUAL_DEC_ZLIB },
	{ "gunzip",                   KGENOME_TEXTUAL_DEC_GZIP },
	{ "CGI.unescape",             KGENOME_TEXTUAL_DEC_URL },
	{ "decode_www_form_component", KGENOME_TEXTUAL_DEC_URL },
};

static const struct kgenome_textual_call_style style = {
	.rows = decoder_row, .n_rows = sizeof decoder_row / sizeof decoder_row[0], .qualify = '.',
};

/*
 * A base64 literal read by the engine's decoder is read with the standard alphabet; "-" and "_" are urlsafe_decode64's
 * and the decoder would skip them, so a value that has one is not offered. The standard text has neither, so nothing the
 * standard decoders read is lost.
 */
static int ruby_payload_ok(const uint8_t *value, uint32_t len, const uint8_t *chain, uint32_t n_chain)
{
	uint32_t i;

	if (!n_chain || chain[0] != KGENOME_TEXTUAL_DEC_B64)
		return 1;
	for (i = 0; i < len; i++)
		if (value[i] == '-' || value[i] == '_')
			return 0;
	return 1;
}

/* A single quoted string: only the quote and the backslash are read, as in php's, and every other byte is itself - a CR excepted: the interpreter reads
 * "\r\n" in the source as "\n", inside a literal too (ruby_value.c does the same, a lone CR with it), so a value with a CR is not written (tests/lib/genome/
 * textual_quote.c: "\r\n" came back as "\n"). */
static const struct kgenome_textual_quote quote = { .q = '\'', .bs = "\\", .refuse = "\r" };

const struct kgenome_textual_lang kgenome_textual_lang_ruby = {
	.name = "ruby",
	.id = KGENOME_TEXTUAL_LANG_RUBY,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH,
	.lex = kgenome_textual_ruby_lex,
	.glue = kgenome_textual_glue_always,
	.ws_significant = 1,
	.continuation = 1,
	.keep_hashbang = 1,
	.unescape_str = kgenome_textual_ruby_unescape,
	.calls = &style,
	.value = kgenome_textual_ruby_value,
	.payload_ok = ruby_payload_ok,
	.fn_table = &kgenome_textual_ruby_fn_table,
	.quote = &quote,
};
