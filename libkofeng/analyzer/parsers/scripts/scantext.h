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

/* Case-insensitive compare of a fixed-length tag, for "<?PHP" and friends. */
int kof_txt_tag_at(kof_buf f, uint64_t at, const char *tag, uint32_t len);

/* Is this text anywhere in the window? Case-insensitive, because every marker
 * a page declares itself with is written both ways in real files. */
int kof_txt_has(kof_buf f, uint64_t look, const char *t);

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
 */
int kof_script_is_block(kof_buf f, uint64_t open, uint64_t end);

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
