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
	KOF_SCAN_SCRIPT_HEADER, KOF_SCAN_SCRIPT_BODY
};

const char *kof_script_region_name(uint32_t bit)
{
	switch (bit) {
	case KOF_SCAN_SCRIPT_HEADER: return "KOF_SCAN_SCRIPT_HEADER";
	case KOF_SCAN_SCRIPT_BODY:   return "KOF_SCAN_SCRIPT_BODY";
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
	uint64_t hdr;

	if (!s || !out || max_out == 0)
		return 0;
	hdr = s->tag_len < ctx->obj_size ? s->tag_len : ctx->obj_size;

	if ((mask & KOF_SCAN_SCRIPT_HEADER) && hdr > 0) {
		out[n].off = 0;
		out[n].len = hdr;
		n++;
	}
	if ((mask & KOF_SCAN_SCRIPT_BODY) && hdr < ctx->obj_size &&
	    n < max_out) {
		out[n].off = hdr;
		out[n].len = ctx->obj_size - hdr;
		n++;
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
		if (tag_at(f, i, "<%@", 3u)) {
			*kind = pct_kind(f, look); *taglen = 3u; return i;
		}
		if (tag_at(f, i, "<%", 2u)) {
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
		}
	}

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
