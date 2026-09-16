/*
 * markup_parse.h - one html element that wraps code is ONE block of markup.
 *
 * A page emits a table by wrapping its rows in a loop, and the loop is written
 * in the server language while the row is written in html:
 *
 *     <table>
 *     <?php foreach ($rows as $r) { ?>
 *       <tr><td><?= $r ?></td></tr>
 *     <?php } ?>
 *     </table>
 *
 * Carved by tags alone that is five regions - markup, code, markup, code,
 * markup - and two of them are "<?php } ?>". What a reader sees is ONE table,
 * and what the code is doing is emitting it, so the whole of it is one block.
 *
 * So an element that OPENS in one markup run and CLOSES in a later one absorbs
 * the code between: the islands inside it are dropped from the list, which
 * leaves their bytes in the markup gap either side. Nothing is cut and nothing
 * moves - this only ever MERGES regions, which is what a partition is allowed
 * to do.
 *
 *
 * TWO LIMITS, AND BOTH ARE MEASURED, because the rule without them takes the
 * whole file.
 *
 * "<html>" opens at the top and closes at the bottom, so by itself it spans
 * every island there is. Over 101 shells the unbounded rule swallowed 74% of
 * all BODY bytes - 117956 of them inside one element.
 *
 *   1. HTML AND BODY ARE NOT BLOCKS. They are the document, and the blocks are
 *      their children - a table, a form, a div. Excluding those two alone
 *      still swallowed 45%, because of the second problem.
 *
 *   2. A SPAN CEILING, because webshell html IS NOT WELL FORMED. "<p>" and
 *      "<td>" are legal to leave unclosed, so a stack pairs one with a "</p>"
 *      thousands of lines further down and the span covers most of the file.
 *      No list of element names fixes that; a ceiling does, and it fixes it for
 *      elements nobody thought to list.
 *
 * AND NO LIST OF "FORMATTING" TAGS, which was the obvious third limit and is
 * not worth having. Excluding <p>, <b>, <font>, <center> and their kind helps a
 * great deal when there is no ceiling - 45% down to 23% - and almost nothing
 * once there is one: 1.70% down to 1.53%, while merging 27 fewer islands. The
 * ceiling already covers what the list was for, and it covers it for elements
 * nobody thought to write down.
 *
 * With both: 1.7% of BODY absorbed, the largest single absorption 2875 bytes.
 * The ceiling is 4096 because every <table> measured spans 466 to 3870 bytes -
 * the case this exists for fits under it with room - and it is the 84th
 * centile of every cross-island span in that corpus.
 *
 * WHAT IT COSTS, said plainly: code inside an absorbed span is markup, so the
 * form pass copies it verbatim instead of forming it. At 1% that is a fair
 * price for a page that reads as a page; at 45% it would not have been.
 */

#ifndef KOFENG_SCRIPTS_MARKUP_PARSE_H
#define KOFENG_SCRIPTS_MARKUP_PARSE_H

#include <kofmod/script.h>

#include "../../core/kofcore.h"

/*
 * Merge the islands that one html element wraps, in place.
 *
 * `from` is where the code may start - the end of the header - so the walk
 * never looks at the bytes that identified the file. Does nothing when the
 * object has no islands, which is every script that is one program.
 */
void kof_markup_merge(kof_buf f, uint64_t from, struct kof_script_info *info);

#endif /* KOFENG_SCRIPTS_MARKUP_PARSE_H */
