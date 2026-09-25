/*
 * php_parse.c - see php_parse.h.
 */

#include <string.h>

#include "php_parse.h"
#include "scantext.h"

/*
 * THE TAGS - how long the one at `at` is, or 0 for no tag.
 *
 * "<?php" is five bytes that do not occur in passing and "<?=" is the echo
 * shorthand. The third is the bare "<?" SHORT TAG, and it needs a rule because
 * it is three quarters of "<?xml".
 *
 * THE RULE IS THE WHITESPACE AFTER IT, and it comes from XML rather than from
 * php: a processing instruction is "<?target ... ?>" and the TARGET FOLLOWS THE
 * "<?" IMMEDIATELY - no space is allowed there. So "<?xml", "<?xml-stylesheet"
 * and every other PI carry a letter in the third byte, and "<? " or "<?\n"
 * cannot be one.
 *
 * MEASURED BEFORE IT WAS BELIEVED. Over 6264 files of real documentation, XML,
 * desktop entries and this source tree, five hold "<?" followed by whitespace
 * and every one of them is BINARY - four git objects and an object file - so
 * the sniff's own text test refuses them and the rule claims nothing it should
 * not. In the sample tree the only file it newly claims is the one it is for:
 * Cyber Shell.php, a 2006 shell that opens with a bare "<?" and was coming back
 * as an object no module targets.
 *
 * It is ONE rule in one place because two callers ask - the sniff and the
 * island walk - and a short tag recognised by one and not the other would make
 * a page whose blocks nothing can find.
 */
static uint32_t php_open_at(kof_buf f, uint64_t at, uint64_t end)
{
	if (kof_txt_tag_at(f, at, "<?php", 5u))
		return 5u;
	if (kof_txt_tag_at(f, at, "<?=", 3u))
		return 3u;
	if (at + 3u <= end && f.p[at] == '<' && f.p[at + 1u] == '?') {
		uint8_t c = f.p[at + 2u];

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			return 2u;
	}
	return 0;
}

uint64_t kof_php_find_tag(kof_buf f, uint64_t look, uint32_t *taglen)
{
	uint64_t i;

	for (i = 0; i + 2u <= look; i++) {
		uint32_t n;

		if (f.p[i] != '<')
			continue;
		n = php_open_at(f, i, look);
		if (n) {
			*taglen = n;
			return i;
		}
	}
	return (uint64_t)-1;
}

int kof_php_is_page(kof_buf f, uint64_t from)
{
	uint64_t i;

	for (i = from; i + 2u <= f.n; i++) {
		uint64_t j;

		if (f.p[i] != '?' || f.p[i + 1u] != '>')
			continue;
		for (j = i + 2u; j < f.n; j++)
			if (f.p[j] != '\n' && f.p[j] != '\r' &&
			    f.p[j] != ' ' && f.p[j] != '\t')
				return 1;
		return 0;
	}
	return 0;
}

/*
 * THE "?>" THAT REALLY CLOSES, walked as php rather than searched for.
 *
 * Looking for the two bytes finds them wherever they are, and in a webshell
 * they are very often somewhere that does not close anything:
 *
 *     $tpl = "<?php eval($_POST[x]); ?>";     a dropper writing a file
 *     preg_match('/\?>/', $s)                  a pattern about the tag
 *
 * Measured on this corpus: 66 of them, in 15 of 75 php files. Each one ended an
 * island early, so the code after it was called markup - and with the form pass
 * running the language's rules over BODY and leaving MARKUP alone, a wrong
 * boundary is not just a wrong label any more.
 *
 * WHAT IS SKIPPED, and the list is short because php's own rule is:
 *
 *   '...' "..."   a value. The tag inside one is text.
 *   <<<LABEL      likewise, and the body may hold anything at all.
 *   a block comment  likewise - "?>" inside one is commented out.
 *
 * AND WHAT IS NOT. A "//" or "#" comment does NOT protect it - php ends such a
 * comment at the end of the line OR at "?>", whichever comes first, and breaks
 * out of php mode there. So the naive scan was RIGHT about those, and making
 * them a special case would have introduced the bug it was meant to fix.
 * Measured too: zero occurrences in this corpus either way.
 */
static uint64_t php_skip_str(kof_buf f, uint64_t i)
{
	uint8_t q = f.p[i];

	for (i++; i < f.n; i++) {
		if (f.p[i] == '\\' && i + 1u < f.n) {
			/* In '...' a backslash escapes only a quote and itself;
			 * everything else is a literal backslash. Reading it as
			 * a general escape would swallow the closing quote. */
			if (q == '"' || f.p[i + 1u] == '\'' ||
			    f.p[i + 1u] == '\\')
				i++;
			continue;
		}
		if (f.p[i] == q)
			return i + 1u;
	}
	return f.n;
}

/* A heredoc or nowdoc body, which ends at its label alone on a line. */
static uint64_t php_skip_heredoc(kof_buf f, uint64_t i)
{
	uint8_t label[64];
	uint32_t n = 0;
	uint64_t j = i + 3u;

	while (j < f.n && (f.p[j] == ' ' || f.p[j] == '\t'))
		j++;
	if (j < f.n && (f.p[j] == '"' || f.p[j] == '\''))
		j++;
	while (j < f.n && n < sizeof label &&
	       ((f.p[j] >= 'a' && f.p[j] <= 'z') ||
		(f.p[j] >= 'A' && f.p[j] <= 'Z') ||
		(f.p[j] >= '0' && f.p[j] <= '9') || f.p[j] == '_'))
		label[n++] = f.p[j++];
	if (!n)
		return i + 3u;          /* not a heredoc after all */
	for (; j + n < f.n; j++) {
		if (f.p[j] != '\n')
			continue;
		{
			uint64_t k = j + 1u;

			while (k < f.n && (f.p[k] == ' ' || f.p[k] == '\t'))
				k++;
			if (k + n <= f.n && !memcmp(f.p + k, label, n))
				return k + n;
		}
	}
	return f.n;
}

static uint64_t php_close(kof_buf f, uint64_t i)
{
	while (i + 1u < f.n) {
		uint8_t c = f.p[i];

		if (c == '?' && f.p[i + 1u] == '>')
			return i;
		if (c == '\'' || c == '"') {
			i = php_skip_str(f, i);
			continue;
		}
		if (c == '/' && f.p[i + 1u] == '*') {
			uint64_t k = i + 2u;

			while (k + 1u < f.n &&
			       !(f.p[k] == '*' && f.p[k + 1u] == '/'))
				k++;
			i = k + 1u < f.n ? k + 2u : f.n;
			continue;
		}
		if (c == '<' && kof_txt_tag_at(f, i, "<<<", 3u)) {
			i = php_skip_heredoc(f, i);
			continue;
		}
		i++;
	}
	return f.n;
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
	uint64_t i = from;

	/*
	 * ONE BRANCH, BECAUSE THE FIRST ISLAND IS NOT SPECIAL ANY MORE.
	 *
	 * It used to be: the header ended after the opening tag, so the first
	 * island began where the tag stopped and every other one began at its
	 * own tag. That asymmetry needed a second variable to find the tag
	 * again for php_block, and it existed only because php was credited
	 * with a header it does not have. With the header gone every island is
	 * "<?php ... ?>" including its delimiters, which is also what the "<%"
	 * family has always been.
	 */
	while (i < f.n && info->n_island < KOF_SCRIPT_MAX_ISLAND) {
		uint64_t open, body, close;
		uint32_t o_len = 0;

		/* Forward from where the last run ended, and not through
		 * kof_php_find_tag: that searches from the start of the object
		 * and would keep answering with a run already passed. */
		for (open = i; open + 3u <= f.n; open++) {
			o_len = php_open_at(f, open, f.n);
			if (o_len)
				break;
		}
		if (open + 3u > f.n)
			break;
		body = open + o_len;
		close = php_close(f, body);
		if (close + 2u > f.n) {
			kof_isl_add(info, open, f.n - open);
			break;
		}
		/*
		 * Interpolation is passed over rather than recorded, which
		 * leaves it in the markup gap either side - see php_block. The
		 * walk still steps past it, or the next pass would find the
		 * same opener again.
		 */
		if (kof_script_is_block(f, open, close + 2u) &&
		    !kof_isl_add(info, open, close + 2u - open))
			break;
		i = close + 2u;
	}
	kof_isl_seal(info, f.n);
}

