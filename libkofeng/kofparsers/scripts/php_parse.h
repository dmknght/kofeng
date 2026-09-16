/*
 * php_parse.h - where a PHP file keeps its code.
 *
 * PHP and the "<% %>" family look alike from far enough away and are not the
 * same, which is why they are two files rather than one table with two rows.
 * The differences are each a rule the other does not have:
 *
 *   - PHP IS USUALLY A PROGRAM. "<% %>" exists to put code inside markup, so a
 *     page is what it always is; a .php is a program in most files and a page
 *     in some, and only PHP has to decide which - see kof_php_is_page.
 *   - ITS FIRST ISLAND HAS NO OPENER TO FIND. The tag that opens the first run
 *     of code is the tag that identified the file, and that tag is already the
 *     header.
 *   - IT HAS A FOOTER. "?>" at the end of a file closes it; "%>" is one
 *     island's own end and never the file's.
 *   - AND IT HAS NO SERVER <script> FORM, which is half of what ASP.NET is.
 *
 * Merged into one walk those became four flags, and a flag per difference is
 * the shape that says the merge was wrong.
 */

#ifndef KOFENG_SCRIPTS_PHP_PARSE_H
#define KOFENG_SCRIPTS_PHP_PARSE_H

#include <kofmod/script.h>

#include "../../core/kofcore.h"

/*
 * The offset of the tag that opens PHP code, or (uint64_t)-1.
 *
 * `taglen` is how long the tag itself is - "<?php" or "<?=" - so the caller can
 * make the header the whole of what named the language.
 */
uint64_t kof_php_find_tag(kof_buf f, uint64_t look, uint32_t *taglen);

/*
 * IS THIS A PAGE - markup with code in it - OR A PROGRAM?
 *
 * The difference is whether anything follows a "?>". Most php is a program that
 * may end with one, and that shape already has the partition it wants: HEADER,
 * BODY, and the closing tag as FOOTER. Splitting it into islands would gain
 * nothing and cost the footer, because an island ends at its own "?>".
 *
 * A file with CONTENT after a "?>" is the other thing: html that the server
 * copies out, with code cut into it. There the split is the whole point - the
 * rules the form pass applies are php's, and applied to markup they are wrong
 * in both directions: "//" in an unquoted href is not a comment, and closing up
 * the spaces in a sentence changes it.
 *
 * Whitespace after the last "?>" is not content: a final newline is how a file
 * ends, not a page.
 */
int kof_php_is_page(kof_buf f, uint64_t from);

/*
 * The code islands of a page, filled into info. `from` is the end of the
 * header, and the FIRST island starts there - its opener is the tag the header
 * already took, so a walk that looked for one would start at the second island
 * and call the first block markup.
 */
void kof_php_islands(kof_buf f, uint64_t from, struct kof_script_info *info);

/*
 * THE CLOSING TAG AT THE END OF THE FILE, measured backwards from it.
 *
 * "?>" is the other half of "<?php" and belongs with it rather than with the
 * last statement - see KOF_SCAN_SCRIPT_FOOTER. Trailing whitespace goes with
 * it: an editor's final newline sits after the tag in almost every real file,
 * and a footer that stopped at ">" would leave that newline as the body's last
 * byte, which is the thing the region exists to stop.
 *
 * AT THE END AND NOWHERE ELSE. A "?>" in the middle of a file opens markup that
 * more code follows, and that shape is a page - BODY and MARKUP already
 * describe it. Reading a middle "?>" as a footer would call everything after it
 * a closing tag.
 *
 * Answers 0 for a page, which has no footer: there the last bytes are markup.
 */
uint32_t kof_php_footer(kof_buf f, const struct kof_script_info *info);

#endif /* KOFENG_SCRIPTS_PHP_PARSE_H */
