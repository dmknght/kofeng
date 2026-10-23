/*
 * vbs_value.c - the value of a vbscript string literal: the text between the quotes, a doubled quote being one.
 * There is no backslash escape in the language, and nothing in a literal depends on the program.
 */

#include "vbs.h"

int kgenome_textual_vbs_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			      uint8_t flags, uint8_t *out, uint32_t *n)
{
	(void)flags;
	return kgenome_textual_undouble(lit + open_len, len - open_len - close_len, "\"", 0, out, n);
}
