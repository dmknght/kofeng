/*
 * kofobjname.h - the object-name vocabulary: where one object's name ends and its
 * child's begins, the leaf, the label and the depth of a name. *
 * A part of <koftypes.h>, which includes it: a host still includes koftypes.h (or
 * kofeng.h) and nothing else. Split from it by purpose; nothing was changed.
 */

#ifndef KOFOBJNAME_H
#define KOFOBJNAME_H

#include <stddef.h>
#include <stdint.h>

/*
 * WHERE ONE OBJECT'S NAME ENDS AND ITS CHILD'S BEGINS.
 *
 * The engine joins a container to what it holds with this, so a result name is
 * "archive.zip//inner.elf" and a payload two layers down carries two of them.
 * It is written in scan.c and it was read - as the bare literal "//" - in the
 * scanner, in the examiner and in the viewer, each with its own loop.
 *
 * The word for what the tools do with it: a file's verdict is the worst of
 * everything under it, so they need the top level name, and a tree needs the
 * depth. Both are here so the separator is spelled once.
 */
#define KOF_OBJ_SEP     "//"
#define KOF_OBJ_SEP_LEN 2u

/* Length of the top-level file's name: everything before the first separator,
 * or the whole name when the object IS the file. */
static inline size_t kobj_toplevel_len(const char *name)
{
	const char *p = name;

	while (*p) {
		if (p[0] == '/' && p[1] == '/')
			return (size_t)(p - name);
		p++;
	}
	return (size_t)(p - name);
}

/* How many containers deep: 0 for the file itself. */
/*
 * The LAST segment of an object's name: what this object is, inside its parent.
 *
 * "archive.zip//3:bin/x86" gives "3:bin/x86", and a name with no separator at
 * all gives the whole thing - which is the right answer for the file itself.
 *
 * Here rather than in each tool because a tool that cut at the last '/' instead
 * got it right only while no label contained one: an archive member called
 * bin/x86 came out as "x86", and a name whose separator was missing came out as
 * the file's own basename. Both read as a different object from the one on the
 * row.
 */
static inline const char *kobj_leaf(const char *name)
{
	const char *p = name, *last = name;

	while (*p) {
		if (p[0] == KOF_OBJ_SEP[0] && p[1] == KOF_OBJ_SEP[1]) {
			p += KOF_OBJ_SEP_LEN;
			last = p;
			continue;
		}
		p++;
	}
	return last;
}

/*
 * WHAT THE ENGINE CALLED THIS OBJECT, out of its leaf.
 *
 * A produced object's leaf is "<index>:<label>" - "0:norm", "3:SCRIPT" - and
 * the label is the engine's own word for what it made. Spelled here for the
 * reason KOF_OBJ_SEP is: it is written in scan.c and read by the tools, and a
 * tool that spells it itself is a second vocabulary for one fact.
 *
 * NULL when the leaf carries no label, which is every object the engine did
 * not produce - a file, an archive member named after itself.
 */
static inline const char *kobj_label(const char *leaf)
{
	const char *p = leaf;

	if (!leaf || !*leaf)
		return NULL;
	while (*p >= '0' && *p <= '9')
		p++;
	return (p != leaf && *p == ':' && p[1]) ? p + 1 : NULL;
}

/* The label a NORMALISED VIEW carries - see norm_emit in scan.c, which is
 * what writes it. A view is not a sample: it is something the engine made out
 * of one, so a tool that records where a rule came from names the parent. */
#define KOF_OBJ_LABEL_NORM "norm"

static inline uint32_t kobj_depth(const char *name)
{
	uint32_t n = 0;
	const char *p = name;

	while (*p) {
		if (p[0] == '/' && p[1] == '/') {
			n++;
			p += 2;
		} else {
			p++;
		}
	}
	return n;
}

#endif /* KOFOBJNAME_H */
