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
#include "scantext.h"
#include "php_parse.h"
#include "svrpage_parse.h"
#include "markup_parse.h"
#include "cfm_parse.h"

const uint32_t kof_script_region_bits[] = {
	KOF_SCAN_SCRIPT_HEADER, KOF_SCAN_SCRIPT_BODY, KOF_SCAN_SCRIPT_MARKUP
};

/*
 * THE DELIMITERS OF ONE CODE BLOCK, longest first.
 *
 * Longest first because "<%" is a prefix of "<%=" and of "<%@": matching the
 * short one would leave a stray "=" behind and call a block that prints a value
 * something other than empty.
 */
static const char *const bare_php[] = { "<?php", "<?=", "<?", "?>", NULL };
static const char *const bare_pct[] = { "<%=", "<%@", "<%", "%>", NULL };

int kof_script_block_bare(uint8_t kind, const uint8_t *p, uint32_t n)
{
	const char *const *d;
	kof_buf b;
	uint32_t i;

	if (!p || !n)
		return 0;
	switch (kind) {
	case KOF_SCRIPT_PHP:                     d = bare_php; break;
	case KOF_SCRIPT_ASP:
	case KOF_SCRIPT_ASPX:
	case KOF_SCRIPT_JSP:                     d = bare_pct; break;
	default:                                 return 0;
	}
	b.p = p;
	b.n = n;
	/*
	 * EVERY delimiter in the run, not just the first and the last, because
	 * the join pass puts neighbours separated by nothing but whitespace
	 * into one island: two emptied blocks arrive here as "<%\n%>\n<%\n%>",
	 * and that is as empty as one of them.
	 */
	for (i = 0; i < n; ) {
		uint8_t c = p[i];
		uint32_t k;
		int hit = 0;

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			i++;
			continue;
		}
		for (k = 0; d[k]; k++) {
			uint32_t dl = (uint32_t)strlen(d[k]);

			if (kof_txt_tag_at(b, i, d[k], dl)) {
				i += dl;
				hit = 1;
				break;
			}
		}
		if (!hit)
			return 0;
	}
	return 1;
}

const char *kof_script_region_name(uint32_t bit)
{
	switch (bit) {
	case KOF_SCAN_SCRIPT_HEADER: return "KOF_SCAN_SCRIPT_HEADER";
	case KOF_SCAN_SCRIPT_BODY:   return "KOF_SCAN_SCRIPT_BODY";
	case KOF_SCAN_SCRIPT_MARKUP: return "KOF_SCAN_SCRIPT_MARKUP";
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
	uint64_t hdr, end, lead;

	if (!s || !out || max_out == 0)
		return 0;
	/*
	 * THREE MARKS: what the page opened with before its tag, where the
	 * header ends, and where the code starts. For php the last two are the
	 * same - it has no header, so its tag opens a body block like every
	 * other one.
	 */
	lead = s->tag_off < ctx->obj_size ? s->tag_off : ctx->obj_size;
	hdr = lead + s->head_len;
	if (hdr > ctx->obj_size)
		hdr = ctx->obj_size;
	end = ctx->obj_size;

	/*
	 * THE MARKUP A PAGE OPENS WITH, before it reaches its tag. Not the
	 * header: see kof_script_info.tag_off for what calling it one cost.
	 */
	if ((mask & KOF_SCAN_SCRIPT_MARKUP) && lead > 0) {
		out[n].off = 0;
		out[n].len = lead;
		n++;
	}
	if ((mask & KOF_SCAN_SCRIPT_HEADER) && hdr > lead && n < max_out) {
		out[n].off = lead;
		out[n].len = hdr - lead;
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
	/* By BIT POSITION, like every other format's - the reader walks the
	 * anomaly word and asks for each bit it finds set. */
	if (index == 0)
		return "ISLANDS_FULL";
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

/*
 * WHICH LANGUAGE CLAIMS THE FILE - asked of each in turn, and NOT answered
 * here.
 *
 *     <?php  <?=                     php_parse.c
 *     <%@  <%                        svrpage_parse.c   (asp, aspx, jsp)
 *     <cfoutput and friends          ColdFusion
 *     @echo off                      batch
 *
 * The first two are a call each because the rule for where a tag ends is the
 * LANGUAGE's - php's is five bytes, a server page's is the whole run of
 * directives - and a table of tags could only have said the short answer. The
 * last two are here because there is nothing more to them than the marker: no
 * regions to carve, no islands, and so no file to put them in.
 *
 * ASKED IN LENGTH ORDER WITHIN A FAMILY, which each file does for itself: "<%@"
 * before "<%" because the longer one is the more specific answer.
 */
/*
 * `fam` is the FAMILY and `kind` the language, and they are two answers because
 * a page can have the first without the second: kof_svr_kind declines when a
 * page carries no marker naming which of the three it is, and KOF_SCRIPT_ANY is
 * a correct answer there. The family is what decides how the file is CARVED, so
 * carving on the kind would have left exactly those pages unsplit.
 */
enum { FAM_NONE = 0, FAM_PHP, FAM_SVR, FAM_CFM };

static uint64_t find_tag(kof_buf f, uint64_t look, uint8_t *kind,
			 uint32_t *taglen, uint32_t *headlen, int *fam)
{
	uint64_t php, svr;
	uint32_t pl = 0, sl = 0, sh = 0;

	*fam = FAM_NONE;
	*headlen = 0;

	php = kof_php_find_tag(f, look, &pl);
	svr = kof_svr_find_tag(f, look, &sl, &sh);
	/*
	 * WHICHEVER COMES FIRST, because a file is opened by one language and
	 * the other marker is then content. A jsp that prints the string
	 * "<?php" in its markup is a jsp; asking php first would have made it a
	 * php file with a body of Java.
	 */
	if (php != (uint64_t)-1 && (svr == (uint64_t)-1 || php <= svr)) {
		*kind = KOF_SCRIPT_PHP;
		*taglen = pl;
		/* "<?php" opens a block of code, so it has no header at all -
		 * see KOF_SCAN_SCRIPT_HEADER. */
		*fam = FAM_PHP;
		return php;
	}
	if (svr != (uint64_t)-1) {
		*kind = kof_svr_kind(f, look);
		*taglen = sl;
		*headlen = sh;
		*fam = FAM_SVR;
		return svr;
	}

	/*
	 * COLDFUSION, whose tags ARE its statements - see cfm_parse.h.
	 *
	 * This used to name six tags by hand and report three bytes, which is
	 * neither the tag nor a header: "<cf" is the opening of a statement, so
	 * there is nothing to call a header and the tag is the whole of what
	 * named the language. The list is gone too - any "<cf" followed by a
	 * name is one of the language's tags, and the six that were written out
	 * were the six somebody happened to think of.
	 */
	{
		uint32_t cl = 0;
		uint64_t cf = kof_cfm_find_tag(f, look, &cl);

		if (cf != (uint64_t)-1) {
			*kind = KOF_SCRIPT_CFM;
			*taglen = cl;
			*fam = FAM_CFM;
			return cf;
		}
	}
	/*
	 * A BATCH FILE HAS NO TAG, and "@echo off" is the nearest thing: it is
	 * the first line of most of them and is not a construct in any of the
	 * other languages here. Only near the start, where a first line is.
	 */
	if (kof_txt_has(f, look < 256u ? look : 256u, "@echo off")) {
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
		uint32_t tl = 0, hl = 0;
		int fam = FAM_NONE;
		uint64_t tag = find_tag(file, look, &kind, &tl, &hl, &fam);

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
		info->tag_off = 0;
		info->tag_len = (uint32_t)e;
		info->head_len = (uint32_t)e;
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
		uint32_t tl = 0, hl = 0;
		int fam = FAM_NONE;

		tag = find_tag(file, look, &kind, &tl, &hl, &fam);
		if (tag != (uint64_t)-1) {
			info->kind = kind;
			if (!info->tag_len) {
				info->tag_off = (uint32_t)tag;
				info->tag_len = tl;
				/*
				 * AND THE HEADER IS THE DIRECTIVE'S ALONE.
				 *
				 * "<%@ ... %>" declares the page and is not
				 * code; "<?php" and a bare "<%" OPEN A BLOCK OF
				 * code, so they belong to the body they open -
				 * see KOF_SCAN_SCRIPT_HEADER, and
				 * kof_svr_find_tag for what calling a bare "<%"
				 * a header did to the first block of a page.
				 */
				info->head_len = hl;
			}
			/*
			 * BOTH FAMILIES HAVE ISLANDS, and php has them only
			 * when it is a page.
			 *
			 * "<% ... %>" is a page by construction - the syntax
			 * exists to put code inside markup - so its body is
			 * always split. "<?php" is a program in most files and
			 * a page in some, and php_is_page is what tells them
			 * apart: content after a "?>" and nothing else.
			 *
			 * A php program keeps the partition it had, which is
			 * what makes its closing tag a FOOTER; a php page is
			 * split like any other page, and its trailing markup
			 * is markup rather than the end of a program.
			 *
			 * The offsets are 32 bit, so an object that could not
			 * be described by them keeps the simple partition
			 * rather than a truncated split one.
			 */
			if (file.n <= 0xffffffffu) {
				uint64_t from = (uint64_t)info->tag_off +
						info->head_len;

				if (fam == FAM_PHP) {
					if (kof_php_is_page(file, from))
						kof_php_islands(file, from,
								info);
				} else if (fam == FAM_SVR) {
					kof_svr_islands(file, from, info);
				} else if (fam == FAM_CFM) {
					kof_cfm_islands(file, from, info);
				}
				/*
				 * AND ONE HTML ELEMENT THAT WRAPS CODE IS ONE
				 * BLOCK. A table emitted by a loop is a table,
				 * not five regions - see markup_parse.h for
				 * the two limits that keep it from being the
				 * whole file.
				 */
				/*
				 * THE ELEMENT WALK GOES FIRST, and the order
				 * is the difference between a fragment and a
				 * block.
				 *
				 * The walk absorbs an island only when it sits
				 * on one line - see mk_inline. Joining first
				 * put "<% Next %>", a blank line and "<% For
				 * each %>" into ONE island with a newline in
				 * it, so a pair of loop fragments around a
				 * table read as a block and the rule they were
				 * written for no longer reached them.
				 *
				 * So: absorb the fragments, then join what
				 * survives.
				 */
				/*
				 * AND NOT FOR COLDFUSION, where a one-line
				 * island is not presentation.
				 *
				 * The element walk absorbs an island that sits
				 * on a single line of html, because in a
				 * server page that island is "<?= $row ?>" -
				 * a value being printed. Every CFML statement
				 * is a one-line tag inside html, so the same
				 * rule would absorb <cfexecute> into the
				 * <form> around it and leave the page with no
				 * code at all.
				 */
				if (fam != FAM_CFM)
					kof_markup_merge(file, from, info);
				kof_isl_join_ws(file, from, info);
			}
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
