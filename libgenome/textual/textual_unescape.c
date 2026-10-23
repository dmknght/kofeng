/*
 * textual_unescape.c - the loop that writes a string's spelled-out bytes as themselves, for the form. One driver for python,
 * lua, perl, ruby, tcl, javascript and php (and asp, which borrows php's); what each of them decides is in its own file,
 * as the function that reads one escape and the bytes it reserves. The contract is in textual_private.h.
 *
 * A BYTE IS WRITTEN WHEN the escape says it may be, it is printable ASCII (0x20 to 0x7e), the language does not reserve it
 * and no guard refuses it. Everything else is kept as typed, and a backslash and the byte after it are always one thing,
 * so "\\x41" is a backslash and the text x41. What is written can then never begin an escape, end the string or open an
 * interpolation, and so the form of the form is itself.
 */

#include <kofcore.h>

#include "textual_private.h"

static int name_byte(uint8_t c)
{
	return kof_is_digit(c) || kof_is_alpha(c) || c == '_' || c == ':';
}

/* The guards that a byte put after them leaves standing. */
static uint8_t guards_after(const struct kgenome_textual_unesc *u, uint8_t g, uint8_t c)
{
	uint8_t k = 0;

	if ((g & KGENOME_UNESC_HEX) && kof_hex_val(c) >= 0)
		k |= KGENOME_UNESC_HEX;
	if ((g & KGENOME_UNESC_NAME) && name_byte(c))
		k |= KGENOME_UNESC_NAME;
	if ((g & KGENOME_UNESC_BLANK) && (c == ' ' || (c < 0x20u && ((u->ws_ctl >> c) & 1u))))
		k |= KGENOME_UNESC_BLANK;
	return k;
}

/* May the byte be written, given the guards that stand. */
static int writable(const struct kgenome_textual_unesc *u, uint8_t g, uint32_t v)
{
	if (v < 0x20u || v > 0x7eu || ((u->ban[v >> 5] >> (v & 31u)) & 1u))
		return 0;
	if (!g)
		return 1;
	if (((g & KGENOME_UNESC_HEX) && kof_hex_val((uint8_t)v) >= 0) || ((g & KGENOME_UNESC_NAME) && name_byte((uint8_t)v)) ||
	    ((g & KGENOME_UNESC_BLANK) && v == ' '))
		return 0;
	if ((g & KGENOME_UNESC_OCT) && (uint8_t)(v - '0') < 8u)
		return 0;
	return !((g & KGENOME_UNESC_DEC) && kof_is_digit((uint8_t)v));
}

uint32_t kgenome_textual_unesc_run(const struct kgenome_textual_unesc *u, uint32_t from, uint8_t *out)
{
	const uint8_t *s = u->s;
	uint32_t i = from, w = from, len = u->len;
	uint8_t g = 0;

	memcpy(out, s, from);
	while (i < len) {
		struct kgenome_textual_unesc_hit h;
		uint32_t l;

		if (!g && !u->name_after) {
			/* no guard stands and none can begin: the bytes up to the next backslash (or, for a language with a skip, the next "{" or "$", the
			 * two bytes an interpolation begins with) are copied as they are */
			if (u->skip)
				while (i + 1u < len && s[i] != '\\' && s[i] != '{' && s[i] != '$')
					out[w++] = s[i++];
			else
				while (i + 1u < len && s[i] != '\\')
					out[w++] = s[i++];
			if (i >= len)
				break;
		}
		if (s[i] != '\\' || i + 1u >= len) {
			if (u->skip && (s[i] == '{' || s[i] == '$') && i + 1u < len && (l = u->skip(u, i)) > i) {
				/* not text: kept as typed, and no byte of it is a guard's business */
				memcpy(out + w, s + i, l - i);
				w += l - i;
				i = l;
				g = 0;
				continue;
			}
			out[w++] = s[i];
			g = g ? guards_after(u, g, s[i]) : 0;
			if (s[i++] == u->name_after && u->name_after)
				g |= KGENOME_UNESC_NAME;
			continue;
		}
		l = u->at(u, i, &h);
		if (!l) {
			memcpy(out, s, len);
			return len;
		}
		if (h.write && writable(u, g, h.v)) {
			out[w++] = (uint8_t)h.v;
			g = g ? guards_after(u, g, (uint8_t)h.v) : 0;
		} else {
			memcpy(out + w, s + i, l);
			w += l;
			g = h.guard;
		}
		i += l;
	}
	return w;
}
