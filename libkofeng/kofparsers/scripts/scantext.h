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

#include "../../core/kofcore.h"

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
 * Close the list against the end of the object.
 *
 * Past the cap the last island is extended to the end, which keeps the
 * partition exact - every byte still belongs to exactly one region - at the
 * cost of calling some markup code. Erring that way rather than the other is
 * deliberate: markup scanned as code costs a few false candidates, code
 * scanned as markup would be code no rule ever sees.
 */
void kof_isl_seal(struct kof_script_info *info, uint64_t size);

#endif /* KOFENG_SCRIPTS_SCANTEXT_H */
