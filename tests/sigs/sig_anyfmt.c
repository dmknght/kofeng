/*
 * sig_anyfmt.c - a module that needs no format header.
 *
 * Includes only kofsig.h, so it reads the common tier and searches bytes, and
 * never names an ELF or PE concept. file_content is part of the common tier, so
 * byte access needs no cast and no format view.
 *
 * There is a consequence worth stating: with no format header there is no format
 * in its target mask, so it applies to every object rather than to one kind. For
 * a plain byte search that is the right answer - the bytes do not care what parsed
 * them - but it also means the host cannot prefilter it away, so its cost is paid
 * on everything. Counting how many modules end up in this state is a useful
 * signal: a lot of them means the format specific vocabulary is too thin and
 * people are falling back to raw bytes.
 */

#include <kofmod/kofsig.h>

/* No format view, so it may apply to everything - and now actually does, rather
 * than being excluded by a hardcoded ELF dispatch. */
KOF_TARGET_FORMAT(KOF_FMT_ANY);

/* KOF_SCAN_ALL is the only region this module can name: it targets every format, so
 * there is no format whose region vocabulary it could use. The host answers this one
 * without a parser, which is what lets a module like this run against input nothing
 * identified. */
KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);
KOF_DEFINE_STR(gcc_comment, "GCC: (GNU)", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (ctx->obj_size < 64)
		return;

	if (kof_find_str(everything, gcc_comment))
		KOF_SCAN_MATCH("Test.GccComment", KOF_LVL_INFECT);
}
