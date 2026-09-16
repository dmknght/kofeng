/*
 * svrpage_parse.c - see svrpage_parse.h.
 */

#include <string.h>

#include "svrpage_parse.h"
#include "scantext.h"

uint8_t kof_svr_kind(kof_buf f, uint64_t look)
{
	if (kof_txt_has(f, look, "<jsp:") ||
	    kof_txt_has(f, look, "<%@ taglib") ||
	    kof_txt_has(f, look, "java.lang") ||
	    kof_txt_has(f, look, "java.io") ||
	    kof_txt_has(f, look, "Runtime.getRuntime"))
		return KOF_SCRIPT_JSP;
	if (kof_txt_has(f, look, "runat=\"server\"") ||
	    kof_txt_has(f, look, "<asp:") ||
	    kof_txt_has(f, look, "<%@ Import") ||
	    kof_txt_has(f, look, "System.Web"))
		return KOF_SCRIPT_ASPX;
	if (kof_txt_has(f, look, "<%@ Language") ||
	    kof_txt_has(f, look, "Server.CreateObject") ||
	    kof_txt_has(f, look, "<%@ LANGUAGE"))
		return KOF_SCRIPT_ASP;
	return KOF_SCRIPT_ANY;
}

/*
 * IS THE TAG CLOSED - which is what makes "<%" a magic number at all.
 *
 * "<%" on its own is two bytes of punctuation and it occurs in prose. Measured,
 * on this machine: it claimed 208 .pm, 76 .pod, 70 .py and 62 .tmpl files,
 * because Perl's POD writes a hash as C<%dependencies> and Mako opens a
 * template with <%inherit file="..."/>. Every one of those became
 * KOF_FMT_SCRIPT with no kind, which is the worst of both - the rules for TEXT
 * no longer saw them, and subtype 0 is never filtered, so every script rule
 * did.
 *
 * What none of them has is the OTHER HALF. A server page is "<% ... %>": the
 * pair is balanced by definition, because the server has to know where the code
 * ends. C<%dependencies> closes with ">" and the Mako tag with "/>", and
 * neither writes "%>" anywhere in the file - checked, zero occurrences across
 * the four sampled.
 *
 * So the magic is the PAIR, not the opener. That keeps every real page and
 * drops the prose, and it needs no guess about what the bytes in between are.
 */
static int pct_closed(kof_buf f, uint64_t at, uint64_t look)
{
	uint64_t j;

	for (j = at + 2u; j + 2u <= look; j++)
		if (f.p[j] == '%' && f.p[j + 1u] == '>')
			return 1;
	return 0;
}

/*
 * HOW LONG THE DIRECTIVE BLOCK IS, from the "<%@" at `at`.
 *
 * A page does not declare itself in three characters. It declares itself in a
 * RUN of directives, and reading only the "<%@" put every one of them in the
 * body:
 *
 *     <%@ Page Language="C#" Debug="true" %>     <-- header was these 3 bytes
 *     <%@ Import Namespace="System.Diagnostics" %>
 *     <%@ Import Namespace="System.IO" %>
 *     <script Language="c#" runat="server">      <-- and all of this was body
 *
 * So a rule asking for the PROGRAM was handed the directives as well, and the
 * directives - "Import Namespace=System.Diagnostics" is about as loud as an
 * ASP.NET marker gets - could not be named as a region at all.
 *
 * The run ends at the first thing that is not another directive, which is what
 * separates the two shapes that occur: a page whose directives are followed by
 * markup, and one whose "<%@ Language=VBScript %>" is followed by a plain "<%"
 * opening code. Whitespace between directives belongs to the run; anything else
 * ends it.
 *
 * The same rule the shebang branch already follows - the header is the whole of
 * what declared the interpreter, not the punctuation that opened it.
 *
 * Bounded by `look`, like everything else here. An unterminated directive ends
 * the run where it started rather than swallowing the file: a header that runs
 * to the end leaves no body, and a file that is all header is not what an
 * unterminated tag means.
 */
static uint32_t pct_directives(kof_buf f, uint64_t at, uint64_t look)
{
	uint64_t i = at, end = at;

	for (;;) {
		uint64_t j;

		while (i < look && (f.p[i] == ' ' || f.p[i] == '\t' ||
				    f.p[i] == '\r' || f.p[i] == '\n'))
			i++;
		if (!kof_txt_tag_at(f, i, "<%@", 3u))
			break;
		for (j = i + 3u; j + 2u <= look; j++)
			if (f.p[j] == '%' && f.p[j + 1u] == '>')
				break;
		if (j + 2u > look)
			break;          /* unterminated - the run stops here */
		i = j + 2u;
		/*
		 * THE RUN ENDS AT THE LAST "%>", not where the search for the
		 * next directive gave up.
		 *
		 * The whitespace between two directives belongs to the block;
		 * the whitespace after the LAST one belongs to whatever comes
		 * next. Returning `i` handed the header the newline under the
		 * final directive - and a page with ten blank lines under it
		 * would have handed over all ten.
		 */
		end = i;
	}
	return end > at ? (uint32_t)(end - at) : 3u;
}

/*
 * A SERVER <script> ELEMENT at or after `i`, or f.n when there is none.
 *
 * Reports the CODE, not the element: *body is the byte after the opening tag's
 * ">" and *end is the "<" of the closing tag, so the tags themselves fall into
 * the markup around it.
 *
 * That is deliberate and it is where this differs from "<% ... %>", whose
 * delimiters ARE part of the island. "<%" and "%>" are punctuation the form
 * pass leaves alone; an opening <script> tag is a list of attributes, and
 * running the server language's spacing rules over it would close
 * `Language="c#" runat="server"` up into one token. The attributes are markup
 * and they are treated as markup.
 *
 * WITHOUT A CLOSING TAG IT IS NOT AN ISLAND. Same discipline as pct_closed: the
 * pair is the evidence, not the opener.
 */
static uint64_t svr_element(kof_buf f, uint64_t i, uint64_t *body, uint64_t *end)
{
	for (; i + 7u <= f.n; i++) {
		uint64_t gt, k;
		int need = 0;

		if (!kof_txt_tag_at(f, i, "<script", 7u))
			continue;
		for (gt = i + 7u; gt < f.n && f.p[gt] != '>'; gt++)
			if (!need && kof_txt_tag_at(f, gt, "runat", 5u))
				need = 1;
		/*
		 * No "runat" is CLIENT-SIDE JAVASCRIPT - the browser runs it
		 * and the server copies it out. Left in the markup on purpose:
		 * forming it by the server language's rules would be the same
		 * mistake as forming html.
		 */
		if (gt >= f.n || !need)
			continue;
		for (k = gt + 1u; k + 8u <= f.n; k++)
			if (kof_txt_tag_at(f, k, "</script", 8u))
				break;
		if (k + 8u > f.n)
			continue;
		*body = gt + 1u;
		*end = k;
		return i;
	}
	return f.n;
}

uint64_t kof_svr_find_tag(kof_buf f, uint64_t look, uint32_t *taglen)
{
	uint64_t i;

	for (i = 0; i + 2u <= look; i++) {
		if (f.p[i] != '<')
			continue;
		if (kof_txt_tag_at(f, i, "<%@", 3u)) {
			/* Not `break`: an unclosed one earlier in the window
			 * must not hide a real page later in it. */
			if (!pct_closed(f, i, look))
				continue;
			*taglen = pct_directives(f, i, look);
			return i;
		}
		if (kof_txt_tag_at(f, i, "<%", 2u)) {
			if (!pct_closed(f, i, look))
				continue;
			*taglen = 2u;
			return i;
		}
	}
	return (uint64_t)-1;
}

/*
 * The walk. Over the WHOLE object and not just the sniff window: where a page's
 * code is is not a property of the first sixty-four kilobytes, and a shell at
 * the foot of a long template is the case that matters.
 *
 * BOTH FORMS, IN FILE ORDER. Each step asks where the next delimiter run starts
 * and where the next server <script> starts, and takes whichever comes first -
 * so a page that uses both, which is the ordinary ASP.NET shape, comes out as
 * one list of islands rather than as whichever form was looked for.
 *
 * "<%--" IS NOT AN ISLAND. It opens a JSP comment, and a comment is not what the
 * server runs; recorded as code it would be formed by Java's rules and offered
 * to every rule about the program. Skipped, it falls into the gap either side,
 * which is MARKUP - where a comment belongs.
 *
 * An unterminated run takes the rest of the object, for the reason kof_isl_seal
 * gives about the cap.
 */
/*
 * IS THIS ISLAND THE PROGRAM, OR GLUE - the same question php_block answers and
 * the same shape answers it. "<%= total %>" dropped into a table cell is a
 * value, not a program; "<% ... %>" owning its lines is a program.
 *
 * An element island is never glue: <script runat="server"> is how a page
 * carries a whole program, and it is already only the code between the tags.
 */
static int svr_block(kof_buf f, uint64_t open, uint64_t end)
{
	uint64_t j;

	for (j = open; j < end && j < f.n; j++)
		if (f.p[j] == '\n')
			return 1;
	for (j = open; j > 0; j--) {
		uint8_t c = f.p[j - 1u];

		if (c == '\n')
			break;
		if (c != ' ' && c != '\t' && c != '\r')
			return 0;
	}
	for (j = end; j < f.n; j++) {
		uint8_t c = f.p[j];

		if (c == '\n')
			break;
		if (c != ' ' && c != '\t' && c != '\r')
			return 0;
	}
	return 1;
}

void kof_svr_islands(kof_buf f, uint64_t from, struct kof_script_info *info)
{
	uint64_t i = from;

	while (i < f.n && info->n_island < KOF_SCRIPT_MAX_ISLAND) {
		uint64_t open, close, next;
		uint64_t e_open, e_body = 0, e_end = 0;

		for (open = i; open + 2u <= f.n; open++)
			if (kof_txt_tag_at(f, open, "<%", 2u))
				break;
		if (open + 2u > f.n)
			open = f.n;
		e_open = svr_element(f, i, &e_body, &e_end);
		if (open == f.n && e_open == f.n)
			break;

		if (e_open < open) {
			/* The tags are markup; the code between them is the
			 * island. `next` leaves the closing tag in the gap. */
			if (!kof_isl_add(info, e_body, e_end - e_body))
				break;
			next = e_end;
		} else {
			for (close = open + 2u; close + 2u <= f.n; close++)
				if (f.p[close] == '%' && f.p[close + 1u] == '>')
					break;
			if (close + 2u > f.n) {
				if (!kof_txt_tag_at(f, open, "<%--", 4u))
					kof_isl_add(info, open, f.n - open);
				break;
			}
			if (!kof_txt_tag_at(f, open, "<%--", 4u) &&
			    svr_block(f, open, close + 2u) &&
			    !kof_isl_add(info, open, close + 2u - open))
				break;
			next = close + 2u;
		}
		if (next <= i)
			break;          /* no progress: stop rather than spin */
		i = next;
	}
	kof_isl_seal(info, f.n);
}
