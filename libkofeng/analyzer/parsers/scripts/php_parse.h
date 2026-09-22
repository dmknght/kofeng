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
 *   - IT HAS NO HEADER. "<?php" opens a block of code, so it belongs to the
 *     block it opens; "<%@ ... %>" declares a page and is not code at all.
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
 * BODY. Splitting it into islands would gain nothing: there is one run of code
 * and it is already the body.
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
 * The code islands of a page, filled into info. Each island is "<?php ... ?>"
 * including its delimiters - php has no header, so its opening tag is the first
 * byte of the block it opens.
 */
void kof_php_islands(kof_buf f, uint64_t from, struct kof_script_info *info);


#endif /* KOFENG_SCRIPTS_PHP_PARSE_H */
