/*
 * php_anchor.c - the calls php uses to take a payload apart, read from the code in front of a literal.
 *
 * `eval(@gzinflate(base64_decode("..."))` is read backwards from the literal: "(", a name, and if the
 * name is a decoder, the same again for the call around it. The first name that is not one (eval, assert,
 * a user function) ends it: what a script does with the decoded text is not this file's business, and
 * the literal is still worth decoding.
 *
 * ONLY A LITERAL THAT IS THE FIRST ARGUMENT, and the form further asks that it is the whole of it (a ")"
 * or "," follows): "base64_decode($a . 'x')" and "base64_decode('A' . 'B')" have a literal in them and
 * no payload to decode. Joining literals is the fold's job.
 */

#include "php.h"

/*
 * php function names are not case sensitive, "@" silences a call and "\\name" is the global one. The decoders are not listed here: they are the
 * rows of the function table (php_fn.c) whose form is NEVER, the same functions the evaluator and the form's call stage read, so a decoder
 * is named once.
 */
const struct kgenome_textual_call_style kgenome_textual_php_calls = {
	.fns = &kgenome_textual_php_fn_table, .fold = 1, .silence = 1, .slash = 1,
};
