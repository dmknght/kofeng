/*
 * cond_expr - what a condition's matcher list means, read and written.
 *
 * The property under test: the four readers of a condition's expression agree
 * about it. The panel asks which matchers a condition names and which of them
 * are negated; the buttons rewrite the list; the canonical form decides whether
 * the row is drawn as a list at all; and the emitter turns it into C. They are
 * separate walks over one string, and nothing at run time compares them.
 *
 * It matters because the failure is SILENT and it INVERTS A SIGNATURE. A "!"
 * dropped by one of the four leaves a panel showing "!1" over a file that tests
 * for 1, or the other way about - and the rule still compiles, still loads, and
 * still reports findings, just the wrong ones. No corpus run catches that,
 * because a corpus cannot say what the author meant.
 *
 * The brackets around a negated matcher get their own cases for the same
 * reason: a threshold matcher emits "m1 >= 3", and "!m1 >= 3" is "(!m1) >= 3",
 * which compiles, is always false, and reads exactly like what was asked for.
 *
 * Nothing here touches the filesystem or the engine, so it runs anywhere.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../kofexamine/kofeditor.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define EQ(a, b) do { \
	if (strcmp((a), (b))) { \
		printf("  FAIL %s:%d\n    got  \"%s\"\n    want \"%s\"\n", \
		       __FILE__, __LINE__, (a), (b)); \
		fails++; \
	} \
} while (0)

static struct kof_editor E;

/* emit_expr's output, as a string. */
static const char *emit(const char *expr)
{
	static char buf[512];
	FILE *f;
	long n;

	memset(buf, 0, sizeof buf);
	f = tmpfile();
	if (!f)
		return "";
	emit_expr(f, &E, expr);
	n = ftell(f);
	if (n < 0 || (size_t)n >= sizeof buf)
		n = 0;
	rewind(f);
	if (fread(buf, 1u, (size_t)n, f) != (size_t)n)
		n = 0;
	buf[n] = 0;
	fclose(f);
	return buf;
}

static void reading(void)
{
	struct cond c;

	memset(&c, 0, sizeof c);
	snprintf(c.expr, sizeof c.expr, "%s", "!1&2&!13");
	CK(cnd_uses(&c, 0) && cnd_uses(&c, 1) && cnd_uses(&c, 12));
	/* 1 and 13 share a digit, and 3 is a substring of 13: an id is a
	 * NUMBER here, not a character somewhere in the text. */
	CK(!cnd_uses(&c, 2));
	CK(cnd_neg(&c, 0) == 1);
	CK(cnd_neg(&c, 1) == 0);
	CK(cnd_neg(&c, 12) == 1);
	/* A matcher the condition does not name is not negated either. */
	CK(cnd_neg(&c, 2) == 0);

	/* A run of "!" is one negation - the same reading the emitter gives
	 * it, which is the point rather than the value. */
	snprintf(c.expr, sizeof c.expr, "%s", "!!1");
	CK(cnd_uses(&c, 0) && cnd_neg(&c, 0) == 1);
	EQ(emit("!!1"), emit("!1"));

	/* "!(" negates a GROUP the author typed. The list does not own it, so
	 * no id inside it reads as negated - and the emitter passes it
	 * through, so the two still agree. */
	snprintf(c.expr, sizeof c.expr, "%s", "!(1&2)");
	CK(cnd_uses(&c, 0) && cnd_neg(&c, 0) == 0);
}

static void rewriting(void)
{
	struct cond c;

	memset(&c, 0, sizeof c);
	snprintf(c.expr, sizeof c.expr, "%s", "!1&2&3");
	cnd_drop_matcher(&c, 1);
	EQ(c.expr, "!1&3");
	cnd_negate_matcher(&c, 2);
	EQ(c.expr, "!1&!3");
	/* Negating twice leaves the expression as it was found. */
	cnd_negate_matcher(&c, 0);
	EQ(c.expr, "1&!3");
	cnd_drop_matcher(&c, 0);
	EQ(c.expr, "!3");
	cnd_drop_matcher(&c, 2);
	EQ(c.expr, "");
	/* Dropping something that is not there changes nothing. */
	cnd_drop_matcher(&c, 4);
	EQ(c.expr, "");

	/* The join is the condition's own operator, not whatever was typed. */
	memset(&c, 0, sizeof c);
	c.op = 1;
	snprintf(c.expr, sizeof c.expr, "%s", "1&!2&3");
	cnd_drop_matcher(&c, 2);
	EQ(c.expr, "1|!2");
}

static void switching(void)
{
	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_cnd = 1;
	E.dr.n_grp = 7;

	/*
	 * A switch keeps the NEGATION with the id - a remove followed by an
	 * append would leave it behind - and puts the list back in the order
	 * the row draws it in, which is by number. A list that stopped being
	 * ordered would stop being drawn as a list, and the author who clicked
	 * a matcher would get a text box back.
	 */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!1&2&3");
	cnd_swap_matcher(&E, 0, 0, 6);
	EQ(E.dr.cnd[0].expr, "2&3&!7");

	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&!2&5");
	cnd_swap_matcher(&E, 0, 1, 3);
	EQ(E.dr.cnd[0].expr, "1&!4&5");

	/* A matcher that does not exist is not somewhere to switch to. */
	cnd_swap_matcher(&E, 0, 0, 99);
	EQ(E.dr.cnd[0].expr, "1&!4&5");
	cnd_swap_matcher(&E, 99, 0, 2);
	EQ(E.dr.cnd[0].expr, "1&!4&5");
}

static void canon(void)
{
	char out[64];

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_cnd = 1;
	E.dr.n_grp = 3;

	/*
	 * The canonical form carries the "!". Without it every negated
	 * condition would differ from its own canonical form, and the row falls
	 * back to a text box the moment those two disagree - so negating a
	 * matcher would have taken the id list away.
	 */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!1&3");
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "!1&3");

	E.dr.cnd[0].op = 1;
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "!1|3");
}

static void emitting(void)
{
	static struct object obs[2];

	memset(&E, 0, sizeof E);
	memset(obs, 0, sizeof obs);
	/* The editor points at the host's object array, and emit_call asks one
	 * of them what its regions are called. A WHOLE-FILE mask never reaches
	 * the format, so a zeroed object is all this needs. */
	E.obj = obs;

	E.dr.n_grp = 2;
	E.dr.n_decl = 2;
	E.dr.decl[0].grp = 1u;                  /* s0 is matcher 1's */
	E.dr.decl[1].grp = 2u;                  /* s1 is matcher 2's */
	E.dr.grp[0].mask = KOF_SCAN_ALL;
	E.dr.grp[1].mask = KOF_SCAN_ALL;
	E.dr.grp[0].rule = 1;                   /* find_any */
	E.dr.grp[1].rule = 2;                   /* find_multi, >= 2 */
	E.dr.grp[1].thresh = 2;

	EQ(emit("1"), "kof_find_str_any(scan_range_whole_file, s0)");
	EQ(emit("!1"), "!(kof_find_str_any(scan_range_whole_file, s0))");
	/* THE CASE THE BRACKETS EXIST FOR. */
	EQ(emit("2"), "kof_find_str_multi(scan_range_whole_file, s1) >= 2");
	EQ(emit("!2"),
	   "!(kof_find_str_multi(scan_range_whole_file, s1) >= 2)");
	EQ(emit("1&!2"),
	   "kof_find_str_any(scan_range_whole_file, s0) && "
	   "!(kof_find_str_multi(scan_range_whole_file, s1) >= 2)");
	EQ(emit("!(1|2)"),
	   "!(kof_find_str_any(scan_range_whole_file, s0) || "
	   "kof_find_str_multi(scan_range_whole_file, s1) >= 2)");
	/* An id past the end of the draft is a 0, not a call. */
	EQ(emit("!9"), "!(0)");
	/* An empty expression tests nothing, and says so. */
	EQ(emit(""), "1");
	/* Nothing that is not code survives - a "!" that negates nothing
	 * included. */
	EQ(emit("1;drop"), "kof_find_str_any(scan_range_whole_file, s0)");
	EQ(emit("!;1"), "kof_find_str_any(scan_range_whole_file, s0)");
}

int main(void)
{
	reading();
	rewriting();
	switching();
	canon();
	emitting();

	printf("condition expressions: read, rewrite, switch, canon, emit%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
