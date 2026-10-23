/*
 * psh_lang.c - the row for PowerShell: its lexer, what the form needs to know, and the decoders a script calls on its own literals.
 *
 * WHITE SPACE IS SYNTAX (ws_significant): "Get-Item -Path x" is not "Get-Item-Path x", and a space after a command name
 * is what makes the next word an argument; the form keeps one space wherever there was any, as sh's does, and
 * `glue` is not asked. A line break ends a statement and the form keeps one of them. Two things the row cannot say
 * and the form therefore gets wrong, for a shared-file change and not for this directory:
 *   - a blank line after a continuation, which ends the statement in the language, is collapsed like any other (the
 *     continuation itself is the backtick - `continuation` names the byte - so "a`<nl>  b" keeps its break and loses only the
 *     indentation after it);
 *   - a lone CR is a line break to the language and `universal_eol` (python's rules) is not for this language, so
 *     the form writes a lone CR as a blank.
 * keep_hashbang: a first line "#!/usr/bin/env pwsh" names the interpreter on a unix, and is kept like python's.
 * concat '+' and nofold: "[Convert]::FromBase64String('ab'+'cd')" is a payload in pieces and the decoder is offered it; but a join is
 * never WRITTEN as one literal, because the form cannot tell an expression from a command's arguments - Write-Host "a" +
 * "b" has three, and "a$" + "b" joined would interpolate $b. Folding needs the language's own distinction (an expression
 * starts after "=", "(", "," or a keyword), which the row cannot yet say.
 */

#include "psh.h"

/*
 * THE DECODERS, by the name of the method, whatever the class in front of it ("[Convert]::", "[System.Convert]::", a
 * variable): PowerShell is case insensitive (fold), so the rows are lower case. Only calls that ARE one call over a
 * literal, and which the .NET class library has:
 *   - frombase64string: [Convert]::FromBase64String("...") - the one malicious scripts are built on;
 *   - fromhexstring: [Convert]::FromHexString("...") (.NET 5 and later);
 *   - unescapedatastring ([Uri]::) and urldecode ([System.Web.HttpUtility]:: and [System.Net.WebUtility]::): the percent
 *     coding. The first leaves a "+" alone and the others read it as a space, and the decoder id is one, so a literal
 *     with a "+" is not offered (psh_payload_ok).
 * NOT HERE, because the call is not over a literal or is not one call: [Text.Encoding]::UTF8.GetString and
 * ::Unicode.GetString (they take the bytes a decoder made, and have no decoder id: the UTF-16 text is what a caller
 * narrows afterwards), -join and [char[]] and -split/-replace (operators over an array), IO.Compression.GzipStream and
 * DeflateStream over an IO.MemoryStream built from a decode (an object built in three steps - the form decodes the
 * base64 inside it, and the bytes it yields are the gzip stream), [regex]::Unescape, ConvertTo-SecureString -Key (a
 * key the program holds) and Invoke-Expression/iex (what runs the text, not a coding).
 */
static const struct kgenome_textual_call_style style = {
	.rows = kgenome_textual_dotnet_decoders, .n_rows = KGENOME_TEXTUAL_DOTNET_ALL, .fold = 1,
};

/* A single quoted string: the quote written twice, and nothing else is read. Not a value with a byte 0xE2: it begins the typographic quotes (U+2018
 * to U+201B), which PowerShell reads as quotes too, and whether the lexer here does is not the question - a value the language would read as a
 * string that ends is not written. */
static const struct kgenome_textual_quote quote = { .q = '\'', .dbl = 1, .refuse = "\xE2" };

const struct kgenome_textual_lang kgenome_textual_lang_psh = {
	.name = "psh",
	.id = KGENOME_TEXTUAL_LANG_PSH,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH,
	.lex = kgenome_textual_psh_lex,
	.glue = kgenome_textual_glue_always,
	.ws_significant = 1,
	.keep_hashbang = 1,
	.continuation = '`',
	.concat = '+',
	.nofold = 1,
	.calls = &style,
	.fn_table = &kgenome_textual_psh_fn_table,
	.fn_fold = 1,
	.value = kgenome_textual_psh_value,
	.quote = &quote,
};
