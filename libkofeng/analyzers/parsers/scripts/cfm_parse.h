/*
 * cfm_parse.h - where a ColdFusion page keeps its program.
 *
 * CFML IS NOT THE "<% %>" FAMILY AND THE DIFFERENCE IS WHERE THE CODE SITS.
 *
 * A server page puts its program BETWEEN delimiters - "<% ... %>", "<?php ...
 * ?>" - so carving the delimited runs carves the code. CFML has no delimiters:
 * it is markup whose own TAGS are the statements, and their arguments are
 * attributes of those tags.
 *
 *     <cfexecute name="cmd.exe" arguments="#form.cmd#" timeout="5">
 *     <cfif isdefined("form.cmd")>value="#form.cmd#"</cfif>
 *
 * Measured over the four ColdFusion shells in the sample tree - 60 "<cf" tags,
 * 21 "#...#" interpolations and NOT ONE <cfscript> block - that is all of it.
 * The header of script_parse.c used to say this and stop there, leaving a .cfm
 * with no islands at all: the whole file became BODY, html included, and a rule
 * scoped to the code searched the page as well.
 *
 * SO THE TAG IS THE ISLAND, delimiters included, exactly as "<% ... %>" is. The
 * html between tags is markup, the tags are the program, and nothing is cut:
 * every byte is still in exactly one region.
 *
 * <cfscript> IS THE ONE BLOCK FORM and it is taken whole - opening tag through
 * closing tag - because what is inside it is a program in the ordinary sense.
 * None of the samples has one; it is here because a rule written for the tag
 * form would not see a shell that used it.
 *
 * A CLOSING TAG IS MARKUP. "</cfif>" carries no argument and states nothing the
 * opening tag has not; an island for it would be six bytes of punctuation in
 * the code region and one more row for a reader to skip.
 *
 * "<!--- ... --->" IS A COMMENT AND IS MARKUP. It is html's comment with a
 * third dash, it holds no statement, and a walk that took it for a tag would
 * put a page's whole licence header in the code region.
 */

#ifndef KOFENG_SCRIPTS_CFM_PARSE_H
#define KOFENG_SCRIPTS_CFM_PARSE_H

#include <kofmod/script.h>

#include "../../../kofcore/kofcore.h"

/*
 * The offset of the first ColdFusion tag, or (uint64_t)-1.
 *
 * `taglen` is the whole of that tag - "<cfoutput>" - so the caller has what
 * named the language rather than the three bytes that opened it. There is no
 * HEADER either way: a <cf> tag is a statement, not a declaration, and it
 * belongs to the body it opens - the same rule php's "<?php" and a bare "<%"
 * follow.
 */
uint64_t kof_cfm_find_tag(kof_buf f, uint64_t look, uint32_t *taglen);

/* The code islands of a page, filled into info - see the note above. */
void kof_cfm_islands(kof_buf f, uint64_t from, struct kof_script_info *info);

#endif /* KOFENG_SCRIPTS_CFM_PARSE_H */
