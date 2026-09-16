/*
 * markup_parse.c - see markup_parse.h.
 */

#include <string.h>

#include "markup_parse.h"
#include "scantext.h"

/* The largest span one element may absorb - see the note in the header for
 * where the number comes from and what happens without it. */
#define MARKUP_SPAN_MAX 4096u

/* How deep the element stack goes. Past it the outermost elements are simply
 * not tracked, which costs a merge and never a wrong one. */
#define MARKUP_DEPTH 32u

/*
 * An element with no content, so it never opens a span. "<br>" is written
 * without a closing tag in every page there is, and tracking it would leave it
 * on the stack until something unrelated happened to close it.
 */
static int mk_void(const char *n)
{
	static const char *const v[] = {
		"br", "hr", "img", "input", "meta", "link", "area", "base",
		"col", "embed", "param", "source", "track", "wbr", NULL
	};
	unsigned i;

	for (i = 0; v[i]; i++)
		if (!strcmp(n, v[i]))
			return 1;
	return 0;
}

/*
 * AN ELEMENT THAT IS NOT A BLOCK OF MARKUP, for one of two reasons.
 *
 * THE DOCUMENT. <html> opens at the top and closes at the bottom, so on its own
 * it spans every island in the file; <body> and <head> are the same shape. The
 * blocks are their CHILDREN - a table, a form, a div.
 *
 * AND THE TWO WHOSE CONTENT IS NOT MARKUP AT ALL. <script runat="server"> is
 * where an ASP.NET page keeps its program, and svrpage_parse carves that
 * content out as an island on purpose. Absorbing it puts the whole shell back
 * into the markup it was just separated from - measured on a real one:
 * BODY 342 bytes to 0, every byte of the program declared to be page text.
 * <style> holds css for the same reason.
 */
static int mk_doc(const char *n)
{
	return !strcmp(n, "html") || !strcmp(n, "body") ||
	       !strcmp(n, "head") || !strcmp(n, "script") ||
	       !strcmp(n, "style");
}

/* The tag's name, lowered, and where the tag ends. 0 when this is not a tag. */
static int mk_tag(kof_buf f, uint64_t at, uint64_t end, int *close,
		  char *name, uint32_t cap, uint64_t *tag_end)
{
	uint32_t n = 0;
	uint64_t i = at + 1u;

	if (f.p[at] != '<' || i >= end)
		return 0;
	*close = 0;
	if (f.p[i] == '/') {
		*close = 1;
		i++;
	}
	while (i < end && n + 1u < cap) {
		uint8_t c = f.p[i];

		if (c >= 'A' && c <= 'Z')
			c = (uint8_t)(c + 32);
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
			break;
		name[n++] = (char)c;
		i++;
	}
	name[n] = 0;
	if (!n)
		return 0;
	while (i < end && f.p[i] != '>')
		i++;
	if (i >= end)
		return 0;
	*tag_end = i + 1u;
	/* "<x ... />" closes itself and never opens a span. */
	if (!*close && i > at && f.p[i - 1u] == '/')
		return 0;
	return 1;
}

/*
 * A BLOCK OF CODE IS NEVER PAGE TEXT, however it is wrapped.
 *
 * What this pass is for is the FRAGMENT: "<?= $r ?>" in a table cell, "<% Next
 * %>" closing a loop around one - a few tokens on a line of html, carved out as
 * a region of their own. Those are markup of a different kind and the element
 * around them says so.
 *
 * A block that OWNS ITS LINES is not that, and the only reason one was ever
 * absorbed is that somebody put a "<p>" around it:
 *
 *     <p>
 *     <% szCMD = request("cmd")
 *     thisDir = getCommandOutput("cmd /c" & szCMD)
 *     Response.Write(thisDir)%>
 *     </p>
 *
 * That is the shell, in newaspcmd.asp, and it was markup: never formed, so it
 * kept its spacing while the same file's other blocks lost theirs - which is
 * how it was noticed. A rule that turns code into page text because of the tag
 * it sits under is not deciding anything about the code.
 *
 * SO THE TEST IS THE NEWLINE, and it is the same fact as "owns its lines". It
 * needs no threshold and no list, and the motivating case is untouched: every
 * island in the table at the top of this file is one line of it.
 */
static int mk_inline(kof_buf f, uint64_t off, uint64_t len)
{
	uint64_t i, end = off + len;

	if (end > f.n)
		end = f.n;
	for (i = off; i < end; i++)
		if (f.p[i] == '\n')
			return 0;
	return 1;
}

void kof_markup_merge(kof_buf f, uint64_t from, struct kof_script_info *info)
{
	struct {
		char     name[16];
		uint16_t gap;
		uint64_t off;
	} st[MARKUP_DEPTH];
	uint8_t drop[KOF_SCRIPT_MAX_ISLAND];
	uint32_t depth = 0, n_drop = 0;
	uint16_t i, gap = 0, keep = 0;
	uint64_t at = from;

	if (!info->n_island || !f.p)
		return;
	memset(drop, 0, sizeof drop);

	/*
	 * The markup gaps are the complement of the islands, so they are walked
	 * from the same list rather than resolved again - two walks of one
	 * partition is two chances to disagree about where a gap is.
	 */
	for (i = 0; i <= info->n_island; i++, gap++) {
		uint64_t end = i < info->n_island ? info->island[i].off : f.n;
		uint64_t j;

		if (end > f.n)
			end = f.n;
		for (j = at; j + 1u < end; j++) {
			char nm[16];
			uint64_t te;
			int cl;

			if (f.p[j] != '<')
				continue;
			if (!mk_tag(f, j, end, &cl, nm, (uint32_t)sizeof nm,
				    &te)) {
				continue;
			}
			j = te - 1u;
			if (mk_void(nm) || mk_doc(nm))
				continue;
			if (!cl) {
				if (depth < MARKUP_DEPTH) {
					memcpy(st[depth].name, nm,
					       sizeof st[depth].name);
					st[depth].gap = gap;
					/* Where the element STARTS, so the
					 * span is measured from its "<". */
					st[depth].off = te - (te - j);
					depth++;
				}
				continue;
			}
			/* The innermost open element of this name, and
			 * everything inside it goes with it - unclosed tags
			 * left on the stack are not evidence of anything. */
			while (depth) {
				uint32_t k = depth - 1u;

				depth--;
				if (strcmp(st[k].name, nm))
					continue;
				if (st[k].gap != gap &&
				    te > st[k].off &&
				    te - st[k].off <= MARKUP_SPAN_MAX) {
					uint16_t m;

					for (m = 0; m < info->n_island; m++)
						if (info->island[m].off >=
						    st[k].off &&
						    info->island[m].off < te &&
						    mk_inline(f,
							info->island[m].off,
							info->island[m].len))
							drop[m] = 1;
				}
				break;
			}
		}
		if (i < info->n_island)
			at = (uint64_t)info->island[i].off +
			     info->island[i].len;
	}

	/*
	 * AND IT MAY NOT EMPTY THE LIST.
	 *
	 * No islands means "this is not a page" - the resolver then makes the
	 * whole object one BODY - so a merge that absorbed the last island
	 * would not turn the file into markup, it would turn it into a
	 * PROGRAM, and every byte of its markup into code. That is the
	 * opposite of what this pass is for, and it is what an element
	 * wrapping the only island does. Refused whole rather than partly:
	 * which island to keep would be an arbitrary choice, and leaving the
	 * page as it was carved is never wrong.
	 */
	for (i = 0; i < info->n_island; i++)
		if (drop[i])
			n_drop++;
	if (!n_drop || n_drop == info->n_island)
		return;
	for (i = 0; i < info->n_island; i++) {
		if (drop[i])
			continue;
		info->island[keep++] = info->island[i];
	}
	info->n_island = keep;
}
