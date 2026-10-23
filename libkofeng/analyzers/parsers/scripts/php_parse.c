/*
 * php_parse.c - see php_parse.h.
 */

#include <string.h>

#include "../../../kofcore/kofcore.h"
#include "php_parse.h"
#include "scantext.h"
#include <textual/textual.h>

/*
 * THE TAGS - where the first one is and how long it is, or none. WHAT A TAG IS, AND WHERE A "?>" REALLY CLOSES, IS THE LIB'S: the php lexer
 * (libgenome/textual/php/php_lex.c) is the one reader of both, asked through kgenome_textual_lex / kgenome_textual_islands. This file used to read them
 * a second time - the tag rule (php_open_at) and a walk for the close that skipped strings, heredocs and block comments (php_close, php_skip_str,
 * php_skip_heredoc) - and the two readers disagreed (docs/textual_pipeline.txt lists where, measured on the corpora): the engine's walk took a quote
 * in a `//` or `#` comment for the start of a string, read a backslash in a double quoted string without its interpolation, and ended a heredoc at a
 * label that a longer name begins. The question this file asks is the one the engine's parsers carve the object by, so it takes the lexer's answer.
 *
 * THE SHORT TAG "<?" IS THE LEXER'S RULE TOO: white space after it, which keeps "<?xml" markup (measured on 6264 files before it was believed: the
 * only file it newly claims is Cyber Shell.php, a 2006 shell that opens with a bare "<?").
 */
struct first_tag {
	uint64_t off;
	uint32_t len;
	int      found;
};

static int first_tag_sink(void *u, const struct kgenome_textual_island *is)
{
	struct first_tag *t = u;

	t->off = is->off;
	t->len = is->open_len;          /* the tag's own bytes: not the white space php takes after "<?php" */
	t->found = 1;
	return 0;                       /* the first is the answer: the lexer stops */
}

uint64_t kof_php_find_tag(kof_buf f, uint64_t look, uint32_t *taglen)
{
	struct first_tag t = { 0, 0, 0 };
	struct kgenome_textual_islands_req rq = { .in = f.p, .n = look > f.n ? (uint32_t)f.n : (uint32_t)look, .lang = KGENOME_TEXTUAL_LANG_PHP,
						  .sink = first_tag_sink, .user = &t };

	if (f.n > 0xffffffffu || !f.p)
		return (uint64_t)-1;
	(void)kgenome_textual_islands(&rq);
	if (!t.found)
		return (uint64_t)-1;
	*taglen = t.len;
	return t.off;
}

int kof_php_is_page(kof_buf f, uint64_t from)
{
	uint64_t i;

	for (i = from; i + 2u <= f.n; i++) {
		uint64_t j;

		if (f.p[i] != '?' || f.p[i + 1u] != '>')
			continue;
		for (j = i + 2u; j < f.n; j++)
			if (!kof_is_blank_byte(f.p[j]))
				return 1;
		return 0;
	}
	return 0;
}

/*
 * IS THIS ISLAND THE PROGRAM, OR IS IT GLUE HOLDING A PAGE TOGETHER?
 *
 * The question this file is answering is NOT "which bytes are printed to the
 * browser" - php prints most of its output from code, so that question has no
 * answer in the layout. It is "which code HANDLES the front end", and the two
 * kinds look nothing alike:
 *
 *     <a class="dir" href='<?php echo $self ?>?dir=<?php echo $d ?>'>
 *
 *   - two islands, and neither is a program. They are values dropped into an
 *     attribute, and the line is one line of html. Split at them the line
 *     became BODY(18) MARKUP(5) BODY(24) MARKUP(2) - four rows, one of them the
 *     five bytes "?dir=", none of which is a thing anybody reads.
 *
 *     <?php
 *       if ($cmd) { @system($cmd); }
 *     ?>
 *
 *   - one island and it IS a program.
 *
 * THE SHAPE SAYS WHICH, and it needs no guess about what the code does. An
 * island that spans a line break is a block, whatever else it is; an island
 * that sits inside a line with markup either side of it is interpolation, and
 * belongs to the line it is in.
 *
 * Interpolation is not recorded as an island at all, so it falls into the
 * markup gap around it - one MARKUP row for the whole line, which is what the
 * line is.
 *
 * WHAT IT COSTS, stated rather than discovered later: a one-line shell written
 * INSIDE a line of html - "<div><?php system($_GET[c]);?></div>" - is markup by
 * this rule, so a rule scoped to BODY will not see it and the form pass will
 * not form it. Every rule with a whole-object range still searches it, which is
 * most of them. The same shell on a line of its own is a block and is BODY.
 */
/*
 * The walk. Over the WHOLE object and not just the sniff window: where a page's
 * code is is not a property of the first sixty-four kilobytes, and a shell at
 * the foot of a long template is the case that matters.
 *
 * An unterminated run takes the rest of the object, for the reason kof_isl_seal
 * gives about the cap.
 */
void kof_php_islands(kof_buf f, uint64_t from, struct kof_script_info *info)
{
	kof_isl_lex(f, from, info, KGENOME_TEXTUAL_LANG_PHP);
}

