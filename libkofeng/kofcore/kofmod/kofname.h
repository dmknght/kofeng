/*
 * kofname.h - what a family or variant name, and a comment carried into
 * generated C, may hold.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFNAME_H
#define KOFENG_KOFNAME_H

#include <stdint.h>

/*
 * ---- WHAT A NAME MAY HOLD, AND WHAT A COMMENT MAY HOLD -------------------
 *
 * Both are here because both are part of the signature contract, and because
 * three places need each of them: ksigbuilder, which compiles a source and is
 * the authority; kofviewer, which writes one; and kofeditor, which reads one
 * back. A rule the panel accepts and the builder refuses is a file the tool
 * reported as written and nothing can load.
 */

/*
 * A FAMILY OR VARIANT NAME.
 *
 * Letters, digits, hyphen and underscore. Nothing else, and that is not
 * conservatism for its own sake: the name reaches a filesystem path (the
 * generated source is named after the family), a C string literal, and a
 * verdict line a person reads out. A dot used to be allowed, which put ".."
 * one keystroke from a path - the filename derivation strips it today, so this
 * closes the hole at the source rather than downstream of it.
 *
 * The length is the shortest of the three buffers that carry it, so a name any
 * one of them accepts is a name all of them accept.
 */
#define KOF_NAME_MAX 63u

static inline int kof_name_char(int c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static inline int kof_name_ok(const char *s)
{
	uint32_t n;

	if (!s || !s[0])
		return 0;
	for (n = 0; s[n]; n++) {
		if (n >= KOF_NAME_MAX)
			return 0;
		if (!kof_name_char((unsigned char)s[n]))
			return 0;
	}
	return 1;
}

/*
 * TEXT BOUND FOR A C COMMENT.
 *
 * `*` and `/` are refused outright rather than the pair `*​/` being looked for,
 * because C HAS NO ESCAPE FOR IT: a comment ends at the first `*​/` and nothing
 * a writer can emit prevents that. Guarding the pair is also not enough on its
 * own - anything that truncates the text, or that joins two pieces of it, can
 * put the two characters next to each other after the check has run.
 *
 * What goes through here is not the author's prose alone. It is the sample's
 * name, taken from a path on the command line; the researcher, taken from
 * $USER; and the "Created" date, which is READ BACK OUT OF a file's own comment
 * when a rule is reopened - so a crafted source can carry a payload that only
 * becomes code the next time the rule is generated.
 */
static inline int kof_comment_char(int c)
{
	return c >= 0x20 && c < 0x7f && c != '*' && c != '/';
}

#endif /* KOFENG_KOFNAME_H */
