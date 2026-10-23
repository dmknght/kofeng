/*
 * lua_value.c - the value of a lua string literal.
 *
 * A LONG STRING, [[...]] or [=[...]=]: the bytes between the brackets, except that a line break right after the opening
 * bracket is skipped and that every line break - "\r\n", "\n\r", "\r", "\n" - is "\n" (llex.c read_long_string: the first
 * break is dropped, each one is saved as "\n" and a CR LF or LF CR pair is one; checked against lua 5.4.7 `load`).
 * No escape is read in it.
 * A SHORT STRING, '...' or "...": the escapes of lua_esc.c, which is also where the ones lua 5.4 refuses are listed. A
 * backslash and a line break is "\n"; "\z" and the white space after it vanish. An escape lua refuses ("\q", "\x4", "\256",
 * "\u{110000000}" - 5.1 reads some of these as a byte, 5.4 stops) gives the literal no value, never a value with a hole.
 * A literal that was not closed has none either.
 */

#include "lua.h"

static const char simple[] = KGENOME_TEXTUAL_LUA_CTL "\\\\\"\"''";

/* The content of a short string. 0 when an escape is one lua refuses. */
static int short_value(const uint8_t *p, uint32_t n, uint8_t *out, uint32_t *w_out)
{
	uint32_t i = 0, w = 0, l, v, nl;
	uint8_t sv;

	while (i < n) {
		uint8_t c = p[i];

		if (c != '\\') {
			out[w++] = c;
			i++;
			continue;
		}
		if (i + 1u >= n)
			return 0;
		c = p[i + 1u];
		if (kgenome_textual_pair_get(simple, c, &sv)) {
			out[w++] = sv;
			i += 2u;
		} else if ((nl = kgenome_textual_lua_nl(p, n, i + 1u)) != 0) {
			out[w++] = '\n';
			i += 1u + nl;
		} else if (c == 'z') {
			for (i += 2u; i < n && kof_is_space_byte(p[i]); i++)
				;
		} else if ((l = kgenome_textual_lua_esc_at(p, n, i, &v)) != 0) {
			if (c == 'u')
				w += kgenome_textual_utf8_put(out + w, v);
			else
				out[w++] = (uint8_t)v;
			i += l;
		} else {
			return 0;
		}
	}
	*w_out = w;
	return 1;
}

int kgenome_textual_lua_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len, i = 0, w = 0, nl;

	if (flags & KGENOME_TEXTUAL_F_OPEN)
		return 0;
	if (lit[0] != '[')
		return short_value(c, cn, out, n);
	i = kgenome_textual_lua_nl(c, cn, 0);
	while (i < cn) {
		nl = kgenome_textual_lua_nl(c, cn, i);
		out[w++] = nl ? '\n' : c[i];
		i += nl ? nl : 1u;
	}
	*n = w;
	return 1;
}
