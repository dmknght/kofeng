/*
 * script_parse.c - the interpreter a text file names for itself.
 *
 * See script_parse.h for why this is in the parser table at all and script.h
 * for why a kind is not a format.
 *
 * NOTHING HERE GUESSES. Both signals are a file saying what it is: a "#!" line
 * is an instruction to the kernel, and "<?php" is a tag with one meaning. A
 * language recognised from its syntax would be a guess, and the cost of a wrong
 * one is not a missed detection but a WRONG PRECONDITION - a PHP rule declining
 * an object it should have seen, silently, because something decided the file
 * was Python.
 */

#include <string.h>

#include "script_parse.h"

const uint32_t kof_script_region_bits[] = {
	KOF_SCAN_SCRIPT_HEADER, KOF_SCAN_SCRIPT_BODY, KOF_SCAN_SCRIPT_MARKUP,
	KOF_SCAN_SCRIPT_FOOTER
};

const char *kof_script_region_name(uint32_t bit)
{
	switch (bit) {
	case KOF_SCAN_SCRIPT_HEADER: return "KOF_SCAN_SCRIPT_HEADER";
	case KOF_SCAN_SCRIPT_BODY:   return "KOF_SCAN_SCRIPT_BODY";
	case KOF_SCAN_SCRIPT_MARKUP: return "KOF_SCAN_SCRIPT_MARKUP";
	case KOF_SCAN_SCRIPT_FOOTER: return "KOF_SCAN_SCRIPT_FOOTER";
	default:                     return NULL;
	}
}

/*
 * THE PARTITION, which is the reason there are regions here at all.
 *
 * Every byte of an object belongs to exactly one region and the corpus fuzz
 * asserts it on every parse. A format with no regions fails that outright -
 * measured, on the first shebang script the corpus contained - so "a script has
 * no structure" is true about its syntax and false about this.
 *
 * Two extents, and between them they are [0, size) exactly: the header is the
 * line that named the interpreter and the body is the rest. Either may be
 * empty and an empty one is not emitted, which is what keeps the union exact
 * when a file is nothing but its shebang.
 */
static uint32_t script_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				    struct kof_range *out, uint32_t max_out)
{
	const struct kof_script_info *s =
		(const struct kof_script_info *)ctx->file_header;
	uint32_t n = 0;
	uint64_t hdr, foot, end;

	if (!s || !out || max_out == 0)
		return 0;
	hdr = s->tag_len < ctx->obj_size ? s->tag_len : ctx->obj_size;
	/*
	 * The footer is measured from the end and the header from the start, so
	 * a small object could have them overlap - and two regions claiming one
	 * byte is the one thing the partition may not do. The header wins,
	 * because it is what identified the object.
	 */
	foot = s->foot_len < ctx->obj_size - hdr ? s->foot_len : 0;
	end = ctx->obj_size - foot;

	if ((mask & KOF_SCAN_SCRIPT_HEADER) && hdr > 0) {
		out[n].off = 0;
		out[n].len = hdr;
		n++;
	}

	/*
	 * NO ISLANDS: the shape this format had before server pages, and the
	 * one every shebang script still has. The body is the rest, less a
	 * closing tag if there is one, and there is no markup.
	 */
	if (!s->n_island) {
		if ((mask & KOF_SCAN_SCRIPT_BODY) && hdr < end &&
		    n < max_out) {
			out[n].off = hdr;
			out[n].len = end - hdr;
			n++;
		}
		if ((mask & KOF_SCAN_SCRIPT_FOOTER) && foot && n < max_out) {
			out[n].off = end;
			out[n].len = foot;
			n++;
		}
		return n;
	}

	/*
	 * A SERVER PAGE, WALKED ONCE. The islands are in file order and do not
	 * overlap, so one walk emits both regions: each island is BODY and each
	 * gap before it is MARKUP. `at` is where the last region ended, which
	 * is what makes the union exact without a second pass to check it.
	 *
	 * Running out of `max_out` stops the walk rather than skipping ahead,
	 * because a caller that asked for fewer extents than the page has is
	 * asking for a prefix of it, not for a partition with a hole in it.
	 */
	{
		uint64_t at = hdr;
		uint16_t i;

		for (i = 0; i < s->n_island && n < max_out; i++) {
			uint64_t io = s->island[i].off;
			uint64_t il = s->island[i].len;

			if (io < at)
				continue;       /* inside the header */
			if ((mask & KOF_SCAN_SCRIPT_MARKUP) && io > at) {
				out[n].off = at;
				out[n].len = io - at;
				if (++n == max_out)
					break;
			}
			if ((mask & KOF_SCAN_SCRIPT_BODY) && il) {
				out[n].off = io;
				out[n].len = il;
				n++;
			}
			at = io + il;
		}
		if ((mask & KOF_SCAN_SCRIPT_MARKUP) && at < ctx->obj_size &&
		    n < max_out) {
			out[n].off = at;
			out[n].len = ctx->obj_size - at;
			n++;
		}
	}
	return n;
}

const char *kof_script_anomaly_name(unsigned index)
{
	(void)index;
	return NULL;
}

/*
 * HOW FAR IN TO LOOK.
 *
 * A shebang is at offset zero by definition. A tag need not be: a page opens
 * with HTML and reaches its first "<?php" wherever it reaches it. Four kilobytes
 * was measured too small on the first try - a file with four hundred lines of
 * comment above the tag came out unrecognised - so the window is sixty-four,
 * which is where a bound stops being about hiding and starts being about not
 * walking a large text file twice.
 */
#define SCRIPT_LOOK 65536u

/* A byte that does not occur in text. NUL is the one that matters: it is what
 * separates a script from a binary whose magic nothing recognised. */
static int binary_byte(uint8_t c)
{
	return c == 0x00u;
}

/*
 * TEXT UP TO THE THING THAT NAMED THE INTERPRETER, and no further.
 *
 * Scanning a fixed window instead threw away the case worth having: a PHP file
 * whose tail is a binary payload. hehe.php is exactly that shape - "<?php" at
 * offset zero, then __HALT_COMPILER() and a phar archive - and a NUL anywhere
 * in the first four kilobytes refused it. The bytes that decide whether this is
 * a script are the ones BEFORE the tag; what a script carries after it is the
 * scanner's business, not the sniff's.
 */
static int looks_like_text(kof_buf f, uint64_t n)
{
	uint64_t i;

	for (i = 0; i < n; i++)
		if (binary_byte(f.p[i]))
			return 0;
	return 1;
}

/* Case-insensitive compare of a fixed-length tag, for "<?PHP" and friends. */
static int tag_at(kof_buf f, uint64_t at, const char *tag, uint32_t len)
{
	uint32_t i;

	if (at + len > f.n)
		return 0;
	for (i = 0; i < len; i++) {
		uint8_t a = f.p[at + i], b = (uint8_t)tag[i];

		if (a >= 'A' && a <= 'Z')
			a = (uint8_t)(a + 32);
		if (b >= 'A' && b <= 'Z')
			b = (uint8_t)(b + 32);
		if (a != b)
			return 0;
	}
	return 1;
}

/*
 * THE OPENING TAGS, which are the only content that names a language outright.
 *
 *     <?php  <?=     PHP
 *     <%@            ASP.NET  - a page directive, "<%@ Page Language=..."
 *     <%             classic ASP
 *
 * "<%@" is tested before "<%" because it is a prefix of it and the longer one
 * is the more specific answer. Everything here is a thing a file says about
 * itself; nothing is inferred from what the code looks like.
 */
/* Is this text anywhere in the window? Case-insensitive, because every marker
 * below is written both ways in real files. */
static int has_text(kof_buf f, uint64_t look, const char *t)
{
	uint32_t len = 0;
	uint64_t i;

	while (t[len])
		len++;
	if (look < len)
		return 0;
	for (i = 0; i + len <= look; i++)
		if (tag_at(f, i, t, len))
			return 1;
	return 0;
}

/*
 * WHICH OF THE "<%" LANGUAGES, decided by a SECOND marker or not at all.
 *
 * "<%@" opens an ASP.NET page, a JSP page and plenty of classic ASP, so on its
 * own it is not an answer - taking it as one named cmdjsp.jsp "ASP.NET" and
 * cmdasp.asp the same, and a wrong kind makes every rule for the real language
 * decline the file. Each marker below belongs to exactly one of the three.
 *
 * Returning ANY is the correct outcome when none of them is present: the object
 * is still a script and kind 0 is never filtered on.
 */
static uint8_t pct_kind(kof_buf f, uint64_t look)
{
	if (has_text(f, look, "<jsp:") || has_text(f, look, "<%@ taglib") ||
	    has_text(f, look, "java.lang") || has_text(f, look, "java.io") ||
	    has_text(f, look, "Runtime.getRuntime"))
		return KOF_SCRIPT_JSP;
	if (has_text(f, look, "runat=\"server\"") ||
	    has_text(f, look, "<asp:") || has_text(f, look, "<%@ Import") ||
	    has_text(f, look, "System.Web"))
		return KOF_SCRIPT_ASPX;
	if (has_text(f, look, "<%@ Language") ||
	    has_text(f, look, "Server.CreateObject") ||
	    has_text(f, look, "<%@ LANGUAGE"))
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
 *
 * "<?php" needs no such test: five bytes that do not occur in passing, and a
 * PHP file is allowed to end without "?>" - most style guides ask for it.
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
		if (!tag_at(f, i, "<%@", 3u))
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
 * THE CODE ISLANDS, over the WHOLE object and not just the sniff window.
 *
 * A page is markup with runs of "<% ... %>" in it, and where those runs are is
 * not a property of the first eight kilobytes - a shell at the foot of a long
 * template is the case that matters. So this is the one walk here that reads
 * everything, and it is a scan for one byte until it finds "<%".
 *
 * "<%--" IS NOT AN ISLAND. It opens a JSP comment, and a comment is not what
 * the server runs; recorded as code it would be normalised by Java's rules and
 * offered to every rule about the program. Skipped, it falls into the gap
 * either side, which is MARKUP - where a comment belongs.
 *
 * An unterminated run takes the rest of the object. It is the same choice the
 * cap makes and for the same reason: a tail called code costs candidates, a
 * tail called markup would be code nothing ever looks at.
 */
static uint16_t pct_islands(kof_buf f, uint64_t from,
			    struct kof_script_info *info)
{
	uint64_t i = from;
	uint16_t n = 0;

	while (i + 2u <= f.n && n < KOF_SCRIPT_MAX_ISLAND) {
		uint64_t open, close;

		while (i + 2u <= f.n &&
		       !(f.p[i] == '<' && f.p[i + 1u] == '%'))
			i++;
		if (i + 2u > f.n)
			break;
		open = i;
		for (close = open + 2u; close + 2u <= f.n; close++)
			if (f.p[close] == '%' && f.p[close + 1u] == '>')
				break;
		if (close + 2u > f.n) {
			if (!tag_at(f, open, "<%--", 4u)) {
				info->island[n].off = (uint32_t)open;
				info->island[n].len = (uint32_t)(f.n - open);
				n++;
			}
			break;
		}
		if (!tag_at(f, open, "<%--", 4u)) {
			info->island[n].off = (uint32_t)open;
			info->island[n].len =
				(uint32_t)(close + 2u - open);
			n++;
		}
		i = close + 2u;
	}
	/* Past the cap, the last island swallows the tail - see the note on
	 * KOF_SCRIPT_MAX_ISLAND. */
	if (n == KOF_SCRIPT_MAX_ISLAND &&
	    (uint64_t)info->island[n - 1].off +
	    info->island[n - 1].len < f.n)
		info->island[n - 1].len =
			(uint32_t)(f.n - info->island[n - 1].off);
	return n;
}

static uint64_t find_tag(kof_buf f, uint64_t look, uint8_t *kind,
			 uint32_t *taglen)
{
	uint64_t i;

	for (i = 0; i + 2u <= look; i++) {
		if (f.p[i] != '<')
			continue;
		if (tag_at(f, i, "<?php", 5u)) {
			*kind = KOF_SCRIPT_PHP; *taglen = 5u; return i;
		}
		if (tag_at(f, i, "<?=", 3u)) {
			*kind = KOF_SCRIPT_PHP; *taglen = 3u; return i;
		}
		/*
		 * ONE RULE FOR THE WHOLE "<%" FAMILY, because the SYNTAX is
		 * theirs together - classic ASP, ASP.NET and JSP all declare
		 * themselves in "<%@ ... %>" and differ only in what they put
		 * inside it. Which of the three it is stays pct_kind's
		 * question; how far the declarations run is this one, and
		 * answering it per kind would be three copies of one answer.
		 */
		if (tag_at(f, i, "<%@", 3u)) {
			/* Not `break`: an unclosed one earlier in the window
			 * must not hide a real page later in it. */
			if (!pct_closed(f, i, look))
				continue;
			*kind = pct_kind(f, look);
			*taglen = pct_directives(f, i, look);
			return i;
		}
		if (tag_at(f, i, "<%", 2u)) {
			if (!pct_closed(f, i, look))
				continue;
			*kind = pct_kind(f, look); *taglen = 2u; return i;
		}
		/* ColdFusion: every tag is "<cf" and nothing else opens with
		 * it, so unlike "<%" one marker is the whole answer. */
		if (tag_at(f, i, "<cfoutput", 9u) ||
		    tag_at(f, i, "<cfexecute", 10u) ||
		    tag_at(f, i, "<cfset", 6u) || tag_at(f, i, "<cfquery", 8u) ||
		    tag_at(f, i, "<cfscript", 9u) || tag_at(f, i, "<cfparam", 8u)) {
			*kind = KOF_SCRIPT_CFM; *taglen = 3u; return i;
		}
	}
	/*
	 * A BATCH FILE HAS NO TAG, and "@echo off" is the nearest thing: it is
	 * the first line of most of them and is not a construct in any of the
	 * other languages here. Only near the start, where a first line is.
	 */
	if (has_text(f, look < 256u ? look : 256u, "@echo off")) {
		*kind = KOF_SCRIPT_BAT; *taglen = 0u; return 0;
	}
	return (uint64_t)-1;
}

int kof_script_sniff(kof_buf file)
{
	uint64_t look;

	if (!file.p || file.n < 3u)
		return 0;
	look = file.n < SCRIPT_LOOK ? file.n : SCRIPT_LOOK;

	/*
	 * A "#!" ONLY AT OFFSET ZERO. That is where the kernel looks, so it is
	 * the only place it means anything; "#!" further in is a comment.
	 */
	if (file.p[0] == '#' && file.p[1] == '!') {
		uint64_t e = 0;

		while (e < look && file.p[e] != '\n')
			e++;
		return looks_like_text(file, e);
	}

	{
		uint8_t kind = KOF_SCRIPT_ANY;
		uint32_t tl = 0;
		uint64_t tag = find_tag(file, look, &kind, &tl);

		if (tag != (uint64_t)-1)
			return looks_like_text(file, tag + tl);
	}

	return 0;
}

/*
 * The last path component of the shebang's first word, and the word after it
 * when that word is "env".
 *
 *     #!/bin/sh              -> sh
 *     #!/usr/bin/python3     -> python3
 *     #!/usr/bin/env perl    -> perl
 *
 * `env` is not a special case bolted on: it is how a portable script names an
 * interpreter, so a reader that stopped at the first word would answer "env"
 * for a large share of real scripts.
 */
static uint32_t shebang_word(kof_buf f, uint64_t line_end, char *out,
			     uint32_t cap)
{
	uint64_t i = 2u, start, end;
	uint32_t n = 0;
	int taken_env = 0;

again:
	while (i < line_end && (f.p[i] == ' ' || f.p[i] == '\t'))
		i++;
	start = i;
	while (i < line_end && f.p[i] != ' ' && f.p[i] != '\t' &&
	       f.p[i] != '\r')
		i++;
	end = i;
	if (end == start)
		return 0;
	/* The last path component. */
	{
		uint64_t k = end;

		while (k > start && f.p[k - 1u] != '/')
			k--;
		start = k;
	}
	n = 0;
	while (start + n < end && n + 1u < cap) {
		out[n] = (char)f.p[start + n];
		n++;
	}
	out[n] = 0;
	/* "env python3" - the interpreter is the NEXT word. Once only, so a
	 * pathological "env env env" cannot loop. */
	if (!taken_env && !strcmp(out, "env")) {
		taken_env = 1;
		goto again;
	}
	return n;
}

/* An interpreter name to a kind. Version suffixes are stripped by comparing a
 * prefix, because python3, python3.11 and perl5 are all the same answer. */
static uint8_t kind_of_interp(const char *w)
{
	static const struct { const char *word; uint8_t kind; int prefix; } t[] = {
		{ "sh",         KOF_SCRIPT_SHELL,       0 },
		{ "bash",       KOF_SCRIPT_SHELL,       0 },
		{ "dash",       KOF_SCRIPT_SHELL,       0 },
		{ "ksh",        KOF_SCRIPT_SHELL,       1 },
		{ "zsh",        KOF_SCRIPT_SHELL,       0 },
		{ "ash",        KOF_SCRIPT_SHELL,       0 },
		{ "busybox",    KOF_SCRIPT_SHELL,       0 },
		{ "python",     KOF_SCRIPT_PYTHON,      1 },
		{ "perl",       KOF_SCRIPT_PERL,        1 },
		{ "ruby",       KOF_SCRIPT_RUBY,        1 },
		{ "node",       KOF_SCRIPT_JS,      1 },
		{ "php",        KOF_SCRIPT_PHP,         1 },
		{ "lua",        KOF_SCRIPT_LUA,         1 },
		{ "tclsh",      KOF_SCRIPT_TCL,         1 },
		{ "wish",       KOF_SCRIPT_TCL,         1 },
		{ "expect",     KOF_SCRIPT_TCL,         0 },
		{ "pwsh",       KOF_SCRIPT_PSH,  1 },
		{ "powershell", KOF_SCRIPT_PSH,  1 }
	};
	unsigned i;

	for (i = 0; i < sizeof t / sizeof t[0]; i++) {
		size_t l = strlen(t[i].word);

		if (t[i].prefix ? !strncmp(w, t[i].word, l)
				: !strcmp(w, t[i].word))
			return t[i].kind;
	}
	return KOF_SCRIPT_ANY;
}

/*
 * THE CLOSING TAG AT THE END OF THE FILE, measured backwards from it.
 *
 * "?>" is the other half of "<?php" and belongs with it rather than with the
 * last statement - see KOF_SCAN_SCRIPT_FOOTER. Trailing whitespace goes with
 * it: an editor's final newline sits after the tag in almost every real file,
 * and a footer that stopped at ">" would leave that newline as the body's last
 * byte, which is the thing the region exists to stop.
 *
 * AT THE END AND NOWHERE ELSE. A "?>" in the middle of a file opens markup
 * that more code follows, and that shape is a page - BODY and MARKUP already
 * describe it. Reading a middle "?>" as a footer would call everything after
 * it a closing tag.
 *
 * NOT FOR THE "<%" FAMILY. There the "%>" is an island's own end, which
 * pct_islands already measured, and a page's last bytes are markup.
 */
static uint32_t closing_tag(kof_buf f, const struct kof_script_info *info)
{
	uint64_t e = f.n;

	if (info->n_island || f.n < 2u)
		return 0;
	while (e > 0 && (f.p[e - 1] == '\n' || f.p[e - 1] == '\r' ||
			 f.p[e - 1] == ' ' || f.p[e - 1] == '\t'))
		e--;
	if (e < 2u || f.p[e - 2] != '?' || f.p[e - 1] != '>')
		return 0;
	/* The whole of it has to sit after the header, or a file that is
	 * nothing but "<?php ?>" would have two regions claiming one byte. */
	if (e - 2u < info->tag_len)
		return 0;
	return (uint32_t)(f.n - (e - 2u));
}

int kof_script_parse(kof_buf file, struct kof_script_info *info,
		     struct kof_obj_ctx *ctx)
{
	uint64_t look, tag;

	memset(info, 0, sizeof *info);
	info->kind = KOF_SCRIPT_ANY;

	if (!file.p || !file.n)
		return 0;
	look = file.n < SCRIPT_LOOK ? file.n : SCRIPT_LOOK;

	if (file.p[0] == '#' && file.p[1] == '!') {
		char word[64];
		uint64_t e = 0;

		while (e < look && file.p[e] != '\n')
			e++;
		if (shebang_word(file, e, word, (uint32_t)sizeof word)) {
			info->kind = kind_of_interp(word);
			info->from_shebang = 1;
		}
		info->tag_len = (uint32_t)e;
	}

	/*
	 * THE TAG WINS OVER THE SHEBANG, and only in this direction.
	 *
	 * "#!/usr/bin/env php" and a "<?php" tag agree. What does not agree is
	 * a wrapper - a shell script that cats a PHP payload - and there the
	 * shebang is about the wrapper while the tag is about the bytes a rule
	 * would match. The bytes win.
	 */
	{
		uint8_t kind = KOF_SCRIPT_ANY;
		uint32_t tl = 0;

		tag = find_tag(file, look, &kind, &tl);
		if (tag != (uint64_t)-1) {
			info->kind = kind;
			if (!info->tag_len)
				info->tag_len = (uint32_t)(tag + tl);
			/*
			 * ONLY THE "<%" FAMILY HAS ISLANDS.
			 *
			 * A "<?php" file is a program that may end with some
			 * markup; a page is markup that CONTAINS programs, and
			 * only the second shape needs the body split. Left to
			 * the simple two-region partition, "<?php" behaves
			 * exactly as it did.
			 *
			 * The offsets are 32 bit, so an object that could not
			 * be described by them keeps the old partition rather
			 * than a truncated new one.
			 */
			if (tag_at(file, tag, "<%", 2u) &&
			    file.n <= 0xffffffffu)
				info->n_island =
					pct_islands(file, info->tag_len, info);
		}
	}

	info->foot_len = closing_tag(file, info);

	/* obj_size is the PARSER's to set - see any other collector. Leaving it
	 * zero made both regions come back empty, because the body is
	 * [tag_len, obj_size) and every parser's resolver measures against it. */
	ctx->obj_size = file.n;
	ctx->format = KOF_FMT_SCRIPT;
	ctx->subtype = info->kind;
	ctx->file_header = info;
	ctx->resolve_scan = script_resolve_scan;
	return 1;
}
