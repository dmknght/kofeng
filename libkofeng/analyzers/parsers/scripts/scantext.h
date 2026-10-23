/*
 * scantext.h - reading text without deciding what language it is.
 *
 * The three things every language file under scripts/ does before it can say
 * anything: compare a tag, look for a marker, and record an island. They are
 * here rather than in one of them because a copy in each is a chance for two
 * languages to disagree about what "the tag is present" means - and the one
 * that matters is CASE: "<?PHP" and "<Script Runat=" are both real, and a
 * comparison that missed either would hand the file to the rules for whatever
 * it was mistaken for.
 *
 * Nothing here knows a language. Everything that does lives in the file named
 * after it - php_parse.c, svrpage_parse.c - which is the arrangement
 * script_parse.c dispatches into.
 */

#ifndef KOFENG_SCRIPTS_SCANTEXT_H
#define KOFENG_SCRIPTS_SCANTEXT_H

#include <kofmod/script.h>

#include "../../../kofcore/kofcore.h"
#include <textual/textual.h>

/* Case-insensitive compare of a fixed-length tag, for "<?PHP" and friends. */
int kof_txt_tag_at(kof_buf f, uint64_t at, const char *tag, uint32_t len);

/* Is this text anywhere in the window? Case-insensitive, because every marker
 * a page declares itself with is written both ways in real files. */
int kof_txt_has(kof_buf f, uint64_t look, const char *t);

/*
 * WHERE IS IT - the same search, for the callers that need the position.
 *
 * Every language here closes something: "</script", "--->", "</cfscript>",
 * "%>". Each of them was written as `for (k = ...; ...; k++) if
 * (kof_txt_tag_at(f, k, ...)) break;`, which is a naive O(n*m) substring
 * search spelled out at the call site - a call and a case fold per byte of the
 * body to discover that byte zero is not '<'. That is exactly what kof_txt_has
 * was rewritten to stop doing, and the fix did not reach these because they
 * want the offset rather than a yes.
 *
 * Same guarantee as kof_txt_has: every position stepped over holds a byte that
 * folds to neither spelling of the tag's first character, which is precisely
 * kof_txt_tag_at's first comparison. Nothing that could have matched is
 * skipped.
 *
 * Searches positions p with from <= p and p + len <= min(to, f.n). Answers the
 * first such p, or KOF_TXT_NONE when there is none - a sentinel rather than
 * `to`, because three of the four callers pass a `to` they also use as a
 * fallback value and the two meanings must not be the same number.
 */
#define KOF_TXT_NONE ((uint64_t)-1)

uint64_t kof_txt_find(kof_buf f, uint64_t from, uint64_t to,
		      const char *tag, uint32_t len);

/*
 * THE ">" THAT ENDS A TAG whose attributes begin at `at`, a ">" inside a quoted attribute value not counting ("arguments=\"/c dir > out.txt\""
 * is the shape a shell in a page has, and a walk that stopped at the first ">" would cut the tag in half). The offset of the ">", or `end`
 * when there is none before it. The one reader of a tag's end for the html and coldfusion carvers.
 */
uint64_t kof_txt_tag_gt(kof_buf f, uint64_t at, uint64_t end);

/*
 * WHICH OF UP TO 32 MARKERS A TEXT HOLDS, in ONE walk of the window and not one walk each. What a tag-driven kind test (a server page's
 * jsp/aspx/asp, a Windows script's psh/js/vbs) depends on is WHICH markers are present somewhere in [0, look) - never where or how many - so the
 * presences are collected together and the caller's few tests are applied to them afterwards.
 *
 *   tag[]    the markers, matched with the fold of kof_txt_tag_at; `grp` 0 is the group that decides on its own.
 *   first[]  by byte, which markers can BEGIN there (both cases of a letter), so a byte that begins none costs one load and a test.
 *   n        how many markers `tag` holds (at most 32).
 *   veto     optional: asked for a marker of `veto_mask` that matched at `at`; 1 says that match is no evidence, it is not recorded
 *            (a marker that said nothing must not count towards anything later).
 * A position whose first byte begins markers is tested against their SECOND and THIRD bytes through two small tables built from `tag` at the head of each call (so the
 * marker list is the one source: no table of the pairs to keep in step with it), and only a marker that agrees on all three is compared in full - the 14 " -x " markers
 * of the tagless list begin at every space of a shell script, and each used to be a call that failed on its second byte.
 * Answers the bitmask of the markers seen. `*decided` is set - and the walk stops - at the first group-0 marker; the others do NOT stop it,
 * because a group-0 marker later in the text still outranks a group-1 one found first.
 */
struct kof_txt_tag {
	const char *s;
	uint8_t     len, grp;
};

struct kof_txt_tags {
	const struct kof_txt_tag *tag;
	uint32_t                  n;
	const uint32_t           *first;        /* 256 entries */
	uint32_t                  veto_mask;
	int                     (*veto)(kof_buf f, uint64_t at);
};

uint32_t kof_txt_tags_seen(kof_buf f, uint64_t look, const struct kof_txt_tags *ts, int *decided);

/*
 * Record one code island, in file order.
 *
 * Answers 0 when the table is full, which is a caller's signal to stop rather
 * than an error - see KOF_SCRIPT_MAX_ISLAND for what happens to the tail.
 */
int kof_isl_add(struct kof_script_info *info, uint64_t off, uint64_t len);

/*
 * IS THE ISLAND AT [open, end) A BLOCK RATHER THAN AN INSERTION?
 *
 * The distinction a template makes and a scanner has to make with it. A tag
 * that SPANS A LINE BREAK is code whatever surrounds it. A tag that fits on one
 * line is code only when it OWNS that line - nothing but blanks before it and
 * nothing but blanks after - because "<?= $name ?>" in the middle of a sentence
 * is a value being printed, not a program, and treating it as an island cuts
 * the sentence into three.
 *
 * php_parse.c and svrpage_parse.c had the same twenty lines under two names.
 * The rule is the same because the question is: PHP, ASP and JSP all inherited
 * it from the same idea of a template.
 *
 * COST, because the two outward loops (the run of blanks before `open` and
 * after `end`) have no bound of their own: each stops at the first byte that
 * is not a blank or a newline, so one call is bounded by the blank run NEXT TO
 * the island and the loop over the island itself by its length. Islands do not
 * overlap and a blank run touches at most the island before it and the one
 * after it, so a walk that asks about every island reads each byte of the
 * object a bounded number of times: linear, not quadratic. (Checked with 1 MB
 * of blanks between and around islands, one line, no newline.)
 */
int kof_script_is_block(kof_buf f, uint64_t open, uint64_t end);

/*
 * THE ISLANDS OF A PAGE, AS THE LIB'S LEXER READS THEM (kgenome_textual_islands): the one reader of where code is in php, asp, aspx and jsp. A "<?php ... ?>" or
 * "<% ... %>" island is recorded with its delimiters when it is a block (kof_script_is_block) or does not close; a server <script> element is recorded
 * as its BODY (the attributes of its tag are markup: running the server language's spacing rules over `Language="c#" runat="server"` would close it
 * into one token) and only when it closes. `from` is where code may begin: nothing before it is an island. Stops when the table is full.
 * php_parse.c and svrpage_parse.c each walked the bytes for this themselves; they read strings, comments and heredocs differently from the lexer the form
 * is made with, and from each other (docs/textual_pipeline.txt lists where, measured).
 */
void kof_isl_lex(kof_buf f, uint64_t from, struct kof_script_info *info, uint32_t lang);

/*
 * Close the list against the end of the object.
 *
 * The partition stays exact without doing anything to the extents: the
 * resolver makes the run after the last island MARKUP, which is what the
 * remainder of a page is. What this records is that the list is SHORT - see
 * KOF_SCRIPT_ANOM_ISLANDS_FULL for why the alternative was worse and why a
 * silent cap is the part that actually hurt.
 */
void kof_isl_seal(struct kof_script_info *info, uint64_t size);

/*
 * JOIN ISLANDS THAT NOTHING SEPARATES.
 *
 * Two runs of code with only whitespace between them are one run of code with a
 * blank line in it. Carved apart they produce a markup region holding "\n" -
 * 54 of the 279 markup runs in the measured corpus are four bytes or fewer, and
 * a region of two whitespace bytes is a row in the tree, an extent for the
 * matcher and a thing a reader has to look at and dismiss.
 *
 * THE ENDS COUNT TOO. The run before the first island and the run after the
 * last are gaps like any other, and a page whose directives are followed by a
 * newline, or which ends with one, produced a one-byte markup region at the top
 * or the bottom. `from` is where the code may start, so the leading gap can be
 * measured from something.
 *
 * A MERGE AND NOTHING ELSE: the whitespace becomes part of the island it sat
 * beside, so every byte still belongs to exactly one region and none of them
 * moves.
 */
void kof_isl_join_ws(kof_buf f, uint64_t from, struct kof_script_info *info);

#endif /* KOFENG_SCRIPTS_SCANTEXT_H */
