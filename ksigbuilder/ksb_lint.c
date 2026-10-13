/*
 * ksb_lint.c - The performance lint: what the build can see about a rule that
 *    works and costs more than it needs.
 */

#include "ksb.h"

#include <stdarg.h>

/* ---- the performance lint ------------------------------------------------- */

/*
 * WHAT THE BUILD CAN SEE, AND WHY IT SHOULD SAY SO.
 *
 * Every cost in this engine that a signature author can accidentally double is
 * visible in the source. The author cannot see it: the extents a range resolves
 * to, whether the presence set can rule a marker out, which memo cell a call
 * lands in - none of that is in front of them while they are writing a rule.
 * The build has all of it, so the build is where it gets said.
 *
 * These are WARNINGS. Every one of them describes a rule that works and costs
 * more than it needs to, and a build that refused them would be refusing correct
 * signatures over a judgement about speed.
 *
 * TWO OPTIMISATIONS ARE ALREADY DONE AND ARE NOT REPEATED HERE, because knowing
 * they exist is what stops a third being invented:
 *
 *   - Two ranges with the same MASK share one memo column, across the whole
 *     database, not just within a module (dbloader.c gives each distinct mask a
 *     uid). Declaring the same region twice costs a name and nothing else.
 *   - The same marker declared by two modules is one uid and one answer.
 *
 * So what is left for a lint is the thing neither can fix: a rule that asks for
 * the same bytes twice in two different shapes.
 */

static void lwarn(struct ksb_ctx *ksb, int line, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s:%d: warning: ", ksb->src_name, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	ksb->lint.warnings++;
}

static int ident_at(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
	       (*p >= '0' && *p <= '9') || *p == '_') {
		if (n + 1 < cap)
			out[n++] = *p;
		p++;
	}
	out[n] = 0;
	return n != 0;
}

static int pat_index(struct ksb_ctx *ksb, const char *name)
{
	int i;

	for (i = 0; i < ksb->decl.npats; i++)
		if (strcmp(ksb->decl.pats[i].name, name) == 0)
			return i;
	return -1;
}

static int rng_index(struct ksb_ctx *ksb, const char *name)
{
	int i;

	for (i = 0; i < ksb->decl.nrngs; i++)
		if (strcmp(ksb->decl.rngs[i].name, name) == 0)
			return i;
	return -1;
}

static void use_add(struct ksb_ctx *ksb, int pi, int ri, int line)
{
	struct use *u = &ksb->lint.uses[pi];
	uint32_t k;

	if (ri < 0)
		return;
	for (k = 0; k < u->n_rng; k++)
		if (u->rng[k] == ri)
			return;
	if (u->n_rng >= KOF_MAX_RANGE_PER_MODULE)
		return;
	u->line[u->n_rng] = line;
	u->rng[u->n_rng++] = ri;
}

/*
 * Walk the call sites.
 *
 * A text scan, deliberately: the declarations were parsed properly above because
 * they become data in a pack, and a call site becomes nothing - it is compiled
 * code. What is wanted here is which names appear together inside one
 * kof_find_str_*(...), and that survives a scan intact. Anything this misreads
 * produces a warning that is wrong, never a pack that is.
 */
void ksb_lint_calls(struct ksb_ctx *ksb, const char *src, size_t len)
{
	size_t i;
	int line = 1;

	for (i = 0; i < len; i++) {
		const char *at = src + i;
		const char *open, *close, *p;
		char first[64];
		int ri = -1, ranged;

		if (src[i] == '\n') {
			line++;
			continue;
		}
		if (strncmp(at, "kof_find_str", 12) != 0)
			continue;
		open = strchr(at, '(');
		if (!open)
			continue;
		close = strchr(open, ')');
		if (!close)
			continue;
		/*
		 * The ranged forms take a range first; the offset forms take
		 * numbers. Both USE their markers - which is what "declared and
		 * never searched for" is about - and only the ranged ones say
		 * anything about regions. Treating _where as no use at all was
		 * this lint's own first false positive: it reported the UPX
		 * magic as dead in a module that searches for it on every
		 * object.
		 */
		ranged = !(strncmp(at, "kof_find_str_at", 15) == 0 ||
			   strncmp(at, "kof_find_str_in", 15) == 0 ||
			   strncmp(at, "kof_find_str_where", 18) == 0);
		if (ranged && ident_at(open + 1, first, sizeof first)) {
			ri = rng_index(ksb, first);
			if (ri >= 0)
				ksb->lint.rng_used[ri] = 1;
		}
		/* Every identifier inside this call that names a declared
		 * marker, whichever position it is in. */
		for (p = open + 1; p < close; p++) {
			char sname[64];
			int pi;

			if (!((*p >= 'A' && *p <= 'Z') ||
			      (*p >= 'a' && *p <= 'z') || *p == '_'))
				continue;
			if (p > open + 1 &&
			    ((p[-1] >= 'A' && p[-1] <= 'Z') ||
			     (p[-1] >= 'a' && p[-1] <= 'z') ||
			     (p[-1] >= '0' && p[-1] <= '9') || p[-1] == '_'))
				continue;

/* mid identifier */
			if (!ident_at(p, sname, sizeof sname))
				continue;
			pi = pat_index(ksb, sname);
			if (pi >= 0) {
				if (ri >= 0)
					use_add(ksb, pi, ri, line);
				else
					ksb->lint.uses[pi].used_unranged = 1;
			}
			p += strlen(sname) - 1u;
		}
	}
}

/* The header as the source names it: beside the source, not beside the cwd. */
static FILE *open_beside(const char *src, const char *rel)
{
	char full[1024];
	const char *slash = kof_path_sep_last(src);
	size_t n;

	if (!slash)
		return fopen(rel, "r");
	n = (size_t)(slash - src) + 1u;
	if (n + strlen(rel) + 1u > sizeof full)
		return NULL;
	memcpy(full, src, n);
	strcpy(full + n, rel);
	return fopen(full, "r");
}

/*
 * A kof_debug IN AN INCLUDED HEADER REPORTS A FACT NOBODY CAN NAME.
 *
 * The macro sends __LINE__ and nothing else, and the name for that line is
 * extracted from the source file named on the command line - this one. An
 * include is never opened, so a call inside one compiles, runs, calls the
 * host's debug hook, and arrives with an id the pack has no name for. The host
 * has nothing to print and prints nothing.
 *
 * That is the worst shape a defect can take: the call is there, the code runs,
 * and the only evidence is an absence. It cost three separate measurements in
 * one afternoon, each read as "this path never executes" when the truth was
 * "this path cannot say anything".
 *
 * NOT FIXED BY FOLLOWING THE INCLUDE, which is why this warns instead. Two
 * files both have a line 63; the id is the line and carries no file, so names
 * gathered from a header would collide with the source's own. Making it work
 * would mean changing what the macro sends, and that is the module ABI.
 *
 * Local includes only - <kofmod/...> is the SDK and has no rules in it.
 *
 * That exemption is why the shared module headers were moved INTO kofmod/
 * rather than left under bases/: they are SDK, they are reached by every
 * module the same way, and none of them calls kof_debug - checked when they
 * moved, and the thing to check again if one ever wants to.
 */
void ksb_lint_debug_in_headers(struct ksb_ctx *ksb, const char *src, size_t n)
{
	size_t i = 0;
	int line = 1;

	for (i = 0; i < n; i++) {
		char path[512];
		size_t k = 0, j;
		FILE *f;
		char buf[4096];
		int hline = 1;

		if (src[i] == '\n') {
			line++;
			continue;
		}
		if (src[i] != '#' || (i && src[i - 1] != '\n'))
			continue;
		j = i + 1u;
		while (j < n && (src[j] == ' ' || src[j] == '\t'))
			j++;
		if (j + 8u >= n || memcmp(src + j, "include", 7) != 0)
			continue;
		j += 7u;
		while (j < n && (src[j] == ' ' || src[j] == '\t'))
			j++;
		if (j >= n || src[j] != '"')
			continue;                       /* <> is the SDK */
		j++;
		while (j < n && src[j] != '"' && k + 1u < sizeof path)
			path[k++] = src[j++];
		path[k] = 0;
		f = open_beside(ksb->src_name, path);
        	if (!f)
			continue;
		while (fgets(buf, (int)sizeof buf, f)) {
			if (strstr(buf, "kof_debug("))
				lwarn(ksb, line,
				      "%s:%d calls kof_debug from an included "
				      "header; the fact has no name and the "
				      "host will drop it in silence",
				      path, hline);
			hline++;
		}
		fclose(f);
	}
}

void ksb_lint_report(struct ksb_ctx *ksb)
{
	int i;

	for (i = 0; i < ksb->decl.npats; i++) {
		struct use *u = &ksb->lint.uses[i];

		if (u->n_rng == 0 && !u->used_unranged) {
			lwarn(ksb, ksb->decl.pats[i].line,
			      "'%s' is declared and never searched for; it costs "
			      "space in the pack and can never match",
			      ksb->decl.pats[i].name);
			continue;
		}
		/*
		 * THERE WAS A WARNING HERE, AND WHAT REPLACED IT IS A
		 * MEASUREMENT.
		 *
		 * It said that a marker searched through two ranges costs a
		 * region scanned to exhaustion before the next is looked at,
		 * and it carried a number: 13426 objects, one marker in
		 * .rodata, 185 MB through one CODE|DATA range against 869 MB
		 * through two calls - 4.7x. It then told the author to merge
		 * the two ranges into one.
		 *
		 * Neither half of that survived the region sweep.
		 *
		 * THE COST. Re-measured over 4941 ELF objects, two ranges
		 * against one merged range:
		 *
		 *   sweep firing, marker absent    2037.08 MB both ways,
		 *                                  0 searches both ways
		 *   sweep declining, absent        2037.08 MB both ways
		 *   sweep declining, present       1933.42 against 1860.03 MB
		 *                                  - 3.9%, same 700 detections
		 *
		 * The reading moved. The scanner sweeps each REGION once for
		 * every marker any module declares on it, before a module runs,
		 * and a mask over several regions is answered by an OR over
		 * what that sweep already wrote - so how many ranges name a
		 * region decides how many memo lookups happen, not how many
		 * bytes are read. Where the sweep declines
		 * (KOF_MULTIMATCH_MIN_LIVE) both forms walk the extents in file
		 * order and stop at the first hit, which is why even there the
		 * difference is a few percent and not a factor.
		 *
		 * THE ADVICE, and this is the worse half: for a pair naming a
		 * symbol half it was BACKWARDS. Those bytes are not the
		 * object's. The symbol block is built for the object, searched
		 * through a matcher of its own, and its extents are chosen by
		 * an ATTRIBUTE - import against export binding - and walked
		 * last-record-first, because a rule scoped to a symbol is
		 * nearly always asking about one of the author's, and those sit
		 * at the end of the table. None of that is a file region and
		 * none of it is what the sweep does, so "one range, one pass"
		 * was never on offer.
		 *
		 * What merging actually buys is in c_find_str: a mask naming
		 * ONLY symbol halves is memoised, a mask naming only file
		 * regions is answered from the sweep, and a MIXED mask is
		 * memoised NOWHERE - one question over two buffers cannot stamp
		 * a cell after answering half of it. So the file half of a
		 * merged mask is searched with KOF_MEMO_NONE, from scratch,
		 * every call. Measured on the same 4941 objects with CODE and
		 * SYM_EXP:
		 *
		 *   two ranges     1563.83 MB swept, 0 searches
		 *   one merged     1563.83 MB swept, 5140 searches reading
		 *                  1563.83 MB - the whole of CODE, again
		 *
		 * Twice the bytes for taking the advice. Every instance of this
		 * warning in the tree was of that kind, and all of them were
		 * false.
		 *
		 * What is left is a question about MEANING and not about cost -
		 * two calls joined by "&&" ask whether one marker is in both
		 * regions, which is unusual enough to be worth a second look -
		 * and that is not what this said, so it is not kept here.
		 */
		/*
		 * Below the presence set's key width.
		 *
		 * gram_may_contain admits everything shorter than four bytes, so
		 * a marker this short can never be ruled out without reading the
		 * object - it is scanned for in every eligible file, forever.
		 */
		if (ksb->decl.pats[i].kind == KOF_STR_LITERAL && ksb->decl.pats[i].len < 4u)
			lwarn(ksb, ksb->decl.pats[i].line,
			      "'%s' is %u bytes; under four the presence set "
			      "cannot rule it out, so every eligible object is "
			      "scanned for it", ksb->decl.pats[i].name, ksb->decl.pats[i].len);
	}
	for (i = 0; i < ksb->decl.nrngs; i++)
		if (!ksb->lint.rng_used[i])
			lwarn(ksb, ksb->decl.rngs[i].line,
			      "range '%s' is declared and never used",
			      ksb->decl.rngs[i].name);
}
