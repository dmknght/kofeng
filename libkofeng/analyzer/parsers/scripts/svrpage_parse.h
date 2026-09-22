/*
 * svrpage_parse.h - classic ASP, ASP.NET and JSP: markup with code cut into it.
 *
 * ONE FILE FOR THE THREE, because the SYNTAX is theirs together. All three
 * declare themselves in "<%@ ... %>", all three run code in "<% ... %>", and
 * all three have the second form below. What differs is the language inside,
 * and that is a subtype - see kof_svr_kind - not a different parse.
 *
 * TWO PLACES A PAGE KEEPS CODE, AND THE SECOND IS WHERE THE WEBSHELLS ARE.
 *
 *     <% ... %>                         the delimiter form
 *     <script runat="server"> ... </script>    the element form
 *
 * The element form was missing, and missing it is not cosmetic. An ASP.NET
 * shell is most often a page directive and then a <script runat="server">
 * holding the whole program - so the whole program was MARKUP: never formed,
 * and offered to rules as text the server prints rather than as code it runs.
 *
 * "runat" IS THE DISCRIMINATOR AND IT IS REQUIRED. A <script> without it is
 * client-side JavaScript, which the browser runs and the server copies out
 * verbatim. Claiming that as server code would form JavaScript by the server
 * language's rules, which is the same class of mistake as forming html.
 */

#ifndef KOFENG_SCRIPTS_SVRPAGE_PARSE_H
#define KOFENG_SCRIPTS_SVRPAGE_PARSE_H

#include <kofmod/script.h>

#include "../../core/kofcore.h"

/*
 * WHICH OF THE THREE, decided by a SECOND marker or not at all.
 *
 * "<%@" opens an ASP.NET page, a JSP page and plenty of classic ASP, so on its
 * own it is not an answer - taking it as one named cmdjsp.jsp "ASP.NET" and
 * cmdasp.asp the same, and a wrong kind makes every rule for the real language
 * decline the file.
 *
 * Returning KOF_SCRIPT_ANY is the correct outcome when none of them is present:
 * the object is still a script and kind 0 is never filtered on.
 */
uint8_t kof_svr_kind(kof_buf f, uint64_t look);

/*
 * The offset of the tag that opens a server page, or (uint64_t)-1.
 *
 * `taglen` is how long the tag itself is - the whole directive block for "<%@",
 * two bytes for a bare "<%".
 *
 * `headlen` IS NOT THE SAME NUMBER, and the two were one for a while.
 *
 * "<%@ Page Language=..." DECLARES the page. It is not code, nothing runs it,
 * and a rule asking for the program does not want it - that is a header.
 * A bare "<%" declares nothing: it OPENS A BLOCK OF CODE, exactly as "<?php"
 * does, so it belongs to the body it opens and the header is empty.
 *
 * Reporting 2 for it cost more than a mislabelled pair of bytes, because the
 * island walk starts at the end of the header: it began one byte INSIDE the
 * first block, missed the "<%" that opened it, and the whole first block
 * became markup. Measured on a real shell - kacak.asp - that was 2691 bytes of
 * VBScript, its base64 encoder included, declared to be page text and copied
 * through the form pass untouched.
 */
uint64_t kof_svr_find_tag(kof_buf f, uint64_t look, uint32_t *taglen,
			  uint32_t *headlen);

/* The code islands of a page, filled into info. `from` is the end of the
 * header, so the directives are not code. */
void kof_svr_islands(kof_buf f, uint64_t from, struct kof_script_info *info);

#endif /* KOFENG_SCRIPTS_SVRPAGE_PARSE_H */
