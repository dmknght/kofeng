#ifndef KGENOME_TEXTUAL_PSH_H
#define KGENOME_TEXTUAL_PSH_H

/*
 * psh.h - the psh directory's one header, private to the family: its row, its lexer, its value reader, and
 * the two quote tests that the lexer and the value reader must agree on.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_psh;

/* The row's function table (psh_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_psh_fn_table;

void kgenome_textual_psh_lex(struct kgenome_textual_lexer *lx);

int kgenome_textual_psh_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);

/*
 * THE QUOTE CHARACTERS. PowerShell reads four characters as a single quote - ' and U+2018 U+2019 U+201A U+201B
 * (E2 80 98..9B in UTF-8) - and four as a double quote - " and U+201C U+201D U+201E (E2 80 9C..9E) - and any
 * of a class closes a string the other of that class opened (word processors make these). The text is read as
 * BYTES, so the typographic ones are the three-byte sequences; UTF-8 is self-synchronising, so E2 80 9x cannot be
 * found in the middle of another well-formed character. Answers the length of the quote character at `j`, or 0.
 * [Unverified: the sets are read from VS Code's PowerShell grammar and from memory of the tokenizer; no pwsh here.]
 */
static inline uint32_t kgenome_textual_psh_quote_len(const uint8_t *p, uint32_t n, uint32_t j, uint8_t plain, uint8_t lo, uint8_t hi)
{
	if (j >= n)
		return 0;
	if (p[j] == plain)
		return 1u;
	return n - j >= 3u && p[j] == 0xe2u && p[j + 1u] == 0x80u && p[j + 2u] >= lo && p[j + 2u] <= hi ? 3u : 0u;
}

static inline uint32_t kgenome_textual_psh_sq_len(const uint8_t *p, uint32_t n, uint32_t j)
{
	return kgenome_textual_psh_quote_len(p, n, j, '\'', 0x98u, 0x9bu);
}

static inline uint32_t kgenome_textual_psh_dq_len(const uint8_t *p, uint32_t n, uint32_t j)
{
	return kgenome_textual_psh_quote_len(p, n, j, '"', 0x9cu, 0x9eu);
}

#endif /* KGENOME_TEXTUAL_PSH_H */
