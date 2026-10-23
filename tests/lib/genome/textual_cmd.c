#define _GNU_SOURCE
/*
 * textual_cmd - the readers of the command languages' text: a WORD (kgenome_textual_word_read), a COMMAND (kgenome_textual_cmd_read) and the ASSIGNMENTS a command
 * makes (kgenome_textual_cmd_assigns), for sh, batch and tcl. What the evaluator asks of them is a fact about the source, not a value, so the cases pin what is
 * READ - which pieces, which events, which terminator - and what is REFUSED (0: the word is not one this reader says anything about).
 *
 *   - the word reader's events are written as one line: L[bytes] a literal piece, V[name] a variable (q when inside double quotes), E[name#row,arg,..] an expansion with
 *     its operands, C[text] a command substitution. The same event list for the same word, whatever the language writes it with;
 *   - the command reader is shown as one line per command: its words, the byte that ended it, the pipe/and-or/redirect marks, the paren delta, batch's raw rest and the
 *     assignments with their flags (hex: 1 RAW, 2 WORDS, 4 ENV, 8 LOCAL, 10 UNREAD, 20 CALL);
 *   - and what is true of any input: no reader goes past `limit`, however the text is cut. Every prefix of every case is read with a guard (the buffer ends at the cut),
 *     and the answer is the same as it would be on the whole text up to where the cut falls (never an event for bytes beyond the cut).
 *
 * The rules are written from each language's manual. bash is on the machine that built this and the sh cases were run through it by script_cmds.c (the evaluator's test);
 * batch and tcl are [Unverified] against cmd.exe and tclsh, which are not.
 */

#include "textual_check.h"

#include <stdarg.h>

static char evs[2048];
static const uint8_t *esrc;
static uint32_t elimit;

static void pf(const char *f, ...) __attribute__((format(printf, 1, 2)));
static void pf(const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	vsnprintf(evs + strlen(evs), sizeof evs - strlen(evs), f, ap);
	va_end(ap);
}

static int s_lit(void *u, const uint8_t *p, uint32_t n)
{
	(void)u;
	pf("L[%.*s]", (int)n, (const char *)p);
	return 1;
}

static int s_var(void *u, struct kgenome_textual_range r, int q)
{
	(void)u;
	CK(r.off + r.len <= elimit);
	pf("V[%.*s%s]", (int)r.len, (const char *)esrc + r.off, q ? "q" : "");
	return 1;
}

static int s_exp(void *u, struct kgenome_textual_range r, uint32_t row, const struct kgenome_textual_range *a, uint32_t n, int q)
{
	uint32_t i;

	(void)u;
	CK(r.off + r.len <= elimit);
	pf("E[%.*s#%u", (int)r.len, (const char *)esrc + r.off, row);
	for (i = 0; i < n; i++) {
		CK(a[i].off + a[i].len <= elimit);
		pf(",%.*s", (int)a[i].len, (const char *)esrc + a[i].off);
	}
	pf("%s]", q ? "q" : "");
	return 1;
}

static int s_cmd(void *u, struct kgenome_textual_range r, int q)
{
	(void)u;
	CK(r.off + r.len <= elimit);
	pf("C[%.*s%s]", (int)r.len, (const char *)esrc + r.off, q ? "q" : "");
	return 1;
}

static uint32_t word(uint32_t lang, uint32_t ctx, const char *in)
{
	struct kgenome_textual_word_sink sk = { NULL, s_lit, s_var, s_exp, s_cmd };
	uint32_t n = (uint32_t)strlen(in);
	uint8_t *g = malloc(n ? n : 1u);       /* the text ends where the buffer does: a read past `limit` is a read past the allocation */
	uint32_t e;

	memcpy(g, in, n);
	evs[0] = 0;
	esrc = g;
	elimit = n;
	e = kgenome_textual_word_read(lang, g, 0, n, ctx, &sk);
	CK(e <= n);
	free(g);
	return e;
}

struct wcase {
	const char *in;
	uint32_t    end;        /* 0: not a word this reader reads */
	const char *ev;         /* the events, or NULL when none is given (a refusal may have said some before it refused) */
};

static void words(uint32_t lang, uint32_t ctx, const char *tag, const struct wcase *c, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		uint32_t e = word(lang, ctx, c[i].in);

		if (e != c[i].end || (c[i].ev && strcmp(evs, c[i].ev))) {
			printf("  FAIL %s: [%s] read to %u '%s', want %u '%s'\n", tag, c[i].in, e, evs, c[i].end, c[i].ev ? c[i].ev : "-");
			fails++;
		}
	}
}

static void sh_words(void)
{
	static const struct wcase t[] = {
		{ "abc", 3, "L[abc]" },
		{ "a\"b c\"d", 7, "L[a]L[b c]L[d]" },
		{ "'a b'c", 6, "L[a b]L[c]" },
		{ "$x", 2, "V[x]" },
		{ "${x}", 4, "V[x]" },
		{ "\"$x y\"", 6, "V[xq]L[ y]" },
		{ "a$x", 3, "L[a]V[x]" },
		{ "${x//a/b}", 9, "E[x#0,a,b]" },
		{ "\"${x//a/b}\"", 11, "E[x#0,a,bq]" },
		{ "${#x}", 5, "E[x#11]" },
		{ "${x:1:2}", 8, "E[x#6,1,2]" },
		{ "$(echo hi)", 10, "C[echo hi]" },
		{ "\"$(echo hi)\"", 12, "C[echo hiq]" },
		{ "`echo hi`", 9, "C[echo hi]" },
		{ "$(echo $(echo a))", 17, "C[echo $(echo a)]" },
		{ "a\\ b", 4, "L[a]L[ ]L[b]" },
		{ "\"a\\\"b\"", 6, "L[a]L[\"]L[b]" },
		{ "\"a\\$b\"", 6, "L[a]L[$]L[b]" },
		{ "a;b", 1, "L[a]" },                  /* a word ends at a terminator */
		{ "a b", 1, "L[a]" },
		{ "\"a\\`b\"", 6, "L[a]L[`]L[b]" },
		{ "a~b", 3, "L[a~b]" },
		{ "\"x\"~b", 5, "L[x]L[~b]" },           /* a tilde is a home directory only at the start of a word */
		{ "\"a\\\nb\"", 6, "L[a]L[b]" },             /* backslash-newline inside double quotes continues the line */
		{ "a\\\nb", 4, "L[a]L[b]" },
		{ "\"a$\"", 4, "L[a]L[$]" },
		{ "$", 1, "L[$]" },
		{ "a$", 2, "L[a]L[$]" },
		{ "\"${x}y\"", 7, "V[xq]L[y]" },
		{ "\"it's\"", 6, "L[it's]" },
		{ "'a\"b'", 5, "L[a\"b]" },
		{ "${x#a*}", 7, "E[x#2,a*]" },                /* the operand is said as written: the row refuses a glob, not the reader */
		{ "${x%%a}", 7, "E[x#5,a]" },
		{ "${x/a}", 6, "E[x#1,a]" },
		{ "${x//}", 6, "E[x#0,]" },
		{ "${x:1:2:3}", 10, "E[x#6,1,2:3]" },
		{ "$_a1", 4, "V[_a1]" },
		{ "$a-b", 4, "V[a]L[-b]" },
		{ "\"$a-b\"", 6, "V[aq]L[-b]" },
		{ "`a`b", 4, "C[a]L[b]" },
		{ "$(a)b", 5, "C[a]L[b]" },
		{ "$( a )", 6, "C[ a ]" },
		/* refused: the reader says nothing it is not sure of */
		{ "${x^^a}", 0, "" },
		{ "${#}", 0, "" },
		{ "${#x#a}", 0, "" },
		{ "${}", 0, "" },
		{ "${x-}", 0, "" },
		{ "$\"a\"", 0, "" },
		{ "$((a))", 0, "" },
		{ "$(a", 0, "" },
		{ "~a", 0, "" },
		{ "`echo a\\$b`", 0, "" },          /* a backslash inside backticks is read by the shell before the command is */
		{ "\"a\\", 0, NULL },
		{ "$((1+2))", 0, "" },
		{ "$'a'", 0, "" },
		{ "~", 0, "" },
		{ "{a,b}", 0, "" },
		{ "${x", 0, "" },
		{ "\"abc", 0, NULL },
		{ "$(echo", 0, "" },
		{ "$@", 0, "" },
		{ "$1", 0, "" },
		{ "a*", 0, NULL },
		{ "a?", 0, NULL },
		{ "a[b]", 0, NULL },
	};

	words(KGENOME_TEXTUAL_LANG_SH, KGENOME_TEXTUAL_CTX_WORD, "sh word", t, sizeof t / sizeof t[0]);
}

static void bat_words(void)
{
	static const struct wcase t[] = {
		{ "abc", 3, "L[abc]" },
		{ "%v%", 3, "V[v]" },
		{ "a%v%b", 5, "L[a]V[v]L[b]" },
		{ "%v:a=b%", 7, "E[v#1,a,b]" },
		{ "%v:~1,2%", 8, "E[v#0,1,2]" },
		{ "%v:~-3%", 7, "E[v#0,-3]" },
		{ "%v:a=%", 6, "E[v#1,a,]" },
		{ "%%", 2, "L[%]" },
		{ "100%%", 5, "L[100]L[%]" },
		{ "%1", 0, "" },
		{ "%1%", 0, "" },
		{ "%*%", 0, "" },
		{ "%v:a%", 0, "" },
		{ "%*", 0, "" },
		{ "!v!", 0, "" },
		{ "a^b", 0, NULL },
		{ "%v:~1,2", 0, "" },
		{ "%v", 0, "" },
		{ "%~dp0", 0, "" },
	};

	words(KGENOME_TEXTUAL_LANG_BAT, KGENOME_TEXTUAL_CTX_TEXT, "bat text", t, sizeof t / sizeof t[0]);
}

static void tcl_words(void)
{
	static const struct wcase t[] = {
		{ "abc", 3, "L[abc]" },
		{ "$v", 2, "V[v]" },
		{ "${v}", 4, "V[v]" },
		{ "a$v", 3, "L[a]V[v]" },
		{ "\"a $v b\"", 8, "L[a ]V[v]L[ b]" },
		{ "{a b}", 5, "L[a b]" },
		{ "{a {b} c}", 9, "L[a {b} c]" },
		{ "[string toupper $v]", 19, "C[string toupper $v]" },
		{ "\"[string toupper $v]\"", 21, "C[string toupper $v]" },
		{ "a[concat x y]", 13, "L[a]C[concat x y]" },
		{ "\"a\\nb\"", 6, "L[a\nb]" },
		{ "$v(1)", 0, "" },
		{ "{a", 0, "" },
		{ "{a}b", 0, NULL },
		{ "\"a\"b", 0, NULL },
		{ "$::v", 4, "V[::v]" },
		{ "\"a", 0, NULL },
		{ "[x", 0, "" },
		{ "$", 1, "L[$]" },
	};

	words(KGENOME_TEXTUAL_LANG_TCL, KGENOME_TEXTUAL_CTX_WORD, "tcl word", t, sizeof t / sizeof t[0]);
}

/* ---- commands ------------------------------------------------------------------------------------------------------- */

static void show(uint32_t lang, const uint8_t *in, uint32_t n, char *out, size_t cap)
{
	struct kgenome_textual_cmd c;
	uint32_t at = 0;
	size_t w = 0;

	memset(&c, 0, sizeof c);
	out[0] = 0;
	while (at <= n && kgenome_textual_cmd_read(lang, in, at, n, &c)) {
		struct kgenome_textual_assign a[8];
		uint32_t na = kgenome_textual_cmd_assigns(lang, in, &c, a, 8), i;

		CK(c.end <= n);
		w += (size_t)snprintf(out + w, cap - w, "n=%u", c.n);
		for (i = 0; i < c.n; i++) {
			CK(c.w[i].off + c.w[i].len <= n);
			w += (size_t)snprintf(out + w, cap - w, " <%.*s>", (int)c.w[i].len, (const char *)in + c.w[i].off);
		}
		w += (size_t)snprintf(out + w, cap - w, " t=%c", c.term ? (c.term == '\n' ? 'N' : c.term) : '0');
		if (c.pipe)
			w += (size_t)snprintf(out + w, cap - w, " pipe");
		if (c.andor)
			w += (size_t)snprintf(out + w, cap - w, " andor");
		if (c.redirect)
			w += (size_t)snprintf(out + w, cap - w, " redir");
		if (c.paren)
			w += (size_t)snprintf(out + w, cap - w, " paren=%d", c.paren);
		if (c.rest.len)
			w += (size_t)snprintf(out + w, cap - w, " rest=<%.*s>", (int)c.rest.len, (const char *)in + c.rest.off);
		for (i = 0; i < na; i++)
			w += (size_t)snprintf(out + w, cap - w, " A[%.*s=%.*s f=%x]", (int)a[i].name.len, (const char *)in + a[i].name.off,
					      (int)a[i].value.len, (const char *)in + a[i].value.off, a[i].flags);
		w += (size_t)snprintf(out + w, cap - w, "\n");
		if (c.end <= at && !c.n && !c.term)
			break;
		at = c.end;
		if (at >= n)
			break;
		if (w + 512u > cap)
			break;
	}
}

static void cmds(uint32_t lang, const char *tag, const char *src, const char *want)
{
	static char got[8192];
	uint32_t n = (uint32_t)strlen(src);
	uint8_t *g = malloc(n ? n : 1u);

	memcpy(g, src, n);
	show(lang, g, n, got, sizeof got);
	free(g);
	if (strcmp(got, want)) {
		printf("  FAIL %s:\n--- got\n%s--- want\n%s---\n", tag, got, want);
		fails++;
	}
}

static void sh_cmds(void)
{
	cmds(KGENOME_TEXTUAL_LANG_SH, "sh assigns",
	     "x=1\nexport y=2 z=3\nlocal l=4\nreadonly r=5\nw+=6\nv=7 cmd arg\ndeclare -x d=1\ndeclare -i\n",
	     "n=1 <x=1> t=N A[x=1 f=0]\n"
	     "n=3 <export> <y=2> <z=3> t=N A[y=2 f=0] A[z=3 f=0]\n"
	     "n=2 <local> <l=4> t=N A[l=4 f=8]\n"
	     "n=2 <readonly> <r=5> t=N A[r=5 f=0]\n"
	     "n=1 <w+=6> t=N A[w=6 f=10]\n"
	     "n=3 <v=7> <cmd> <arg> t=N A[v=7 f=4]\n"
	     "n=3 <declare> <-x> <d=1> t=N A[d=1 f=0]\n"
	     "n=2 <declare> <-i> t=N\n");
	cmds(KGENOME_TEXTUAL_LANG_SH, "sh leading keywords",
	     "while IFS== read k; do\ndone\nif true; then t=1; fi\n! n=1\nthen_x=1\n",
	     "n=4 <while> <IFS==> <read> <k> t=; A[IFS== f=4]\n"
	     "n=1 <do> t=N\n"
	     "n=1 <done> t=N\n"
	     "n=2 <if> <true> t=;\n"
	     "n=2 <then> <t=1> t=; A[t=1 f=10]\n"
	     "n=1 <fi> t=N\n"
	     "n=2 <!> <n=1> t=N A[n=1 f=0]\n"
	     "n=1 <then_x=1> t=N A[then_x=1 f=0]\n");
	cmds(KGENOME_TEXTUAL_LANG_SH, "sh arrays and groups",
	     "arr=(a b)\nf() { g=1; }\n(a=1)\n",
	     "n=1 <arr=> t=( paren=1 A[arr= f=10]\n"
	     "n=2 <a> <b> t=) paren=-1\n"
	     "n=0 t=N\n"
	     "n=1 <f> t=( paren=1\n"
	     "n=0 t=) paren=-1\n"
	     "n=2 <{> <g=1> t=;\n"
	     "n=1 <}> t=N\n"
	     "n=0 t=( paren=1\n"
	     "n=1 <a=1> t=) paren=-1 A[a=1 f=0]\n"
	     "n=0 t=N\n");
	cmds(KGENOME_TEXTUAL_LANG_SH, "sh pipes, lists and comments",
	     "echo a | tr a b && echo \"x y\" # c\ncat <<EOF\nx=9\nEOF\ncat >o 2>&1 <i\n",
	     "n=2 <echo> <a> t=| pipe\n"
	     "n=3 <tr> <a> <b> t=& andor\n"
	     "n=2 <echo> <\"x y\"> t=N\n"
	     "n=1 <cat> t=N redir\n"
	     "n=1 <cat> t=N redir\n");
}

static void bat_cmds(void)
{
	cmds(KGENOME_TEXTUAL_LANG_BAT, "bat set",
	     "set v=hello \nset \"w=a b\" tail\ncall set c=%v%\necho %v% & set e=1\n@set at=1\nset v\nset\n",
	     "n=2 <set> <v=hello> t=N rest=<v=hello > A[v=hello  f=1]\n"
	     "n=3 <set> <\"w=a b\"> <tail> t=N rest=<\"w=a b\" tail> A[w=a b f=1]\n"
	     "n=3 <call> <set> <c=%v%> t=N rest=<set c=%v%> A[c=%v% f=21]\n"
	     "n=2 <echo> <%v%> t=& rest=<%v% >\n"
	     "n=2 <set> <e=1> t=N rest=<e=1> A[e=1 f=1]\n"
	     "n=2 <set> <at=1> t=N rest=<at=1> A[at=1 f=1]\n"
	     "n=2 <set> <v> t=N rest=<v>\n"
	     "n=1 <set> t=N\n");
	/* set /a and set /p: every name in them is written and no value is read (UNREAD, f=10) - conservative: `Prompt` is no variable and is listed too */
	cmds(KGENOME_TEXTUAL_LANG_BAT, "bat lists",
	     "echo a && echo b\necho a & echo b\necho a | find b\n",
	     "n=2 <echo> <a> t=& andor rest=<a >\n"
	     "n=2 <echo> <b> t=N rest=<b>\n"
	     "n=2 <echo> <a> t=& rest=<a >\n"
	     "n=2 <echo> <b> t=N rest=<b>\n"
	     "n=2 <echo> <a> t=| pipe rest=<a >\n"
	     "n=2 <find> <b> t=N rest=<b>\n");
	cmds(KGENOME_TEXTUAL_LANG_BAT, "bat set /a /p",
	     "set /a n=1+2\nset /p q=Prompt\n",
	     "n=3 <set> </a> <n=1+2> t=N rest=</a n=1+2> A[n= f=10] A[1= f=10] A[2= f=10]\n"
	     "n=3 <set> </p> <q=Prompt> t=N rest=</p q=Prompt> A[q= f=10] A[Prompt= f=10]\n");
	/* a remark and a label are no commands; a block is counted by its parentheses; `if` is not the command that sets */
	cmds(KGENOME_TEXTUAL_LANG_BAT, "bat rem, labels, blocks",
	     "rem set z=1\n:: set zz=2\n:lbl\n( set p=1\n)\nif 1==1 set i=1\n",
	     "n=0 t=N\n"
	     "n=0 t=N\n"
	     "n=0 t=N\n"
	     "n=3 <(> <set> <p=1> t=N paren=1 rest=<set p=1>\n"
	     "n=1 <)> t=N paren=-1\n"
	     "n=4 <if> <1==1> <set> <i=1> t=N rest=<1==1 set i=1>\n");
}

static void tcl_cmds(void)
{
	cmds(KGENOME_TEXTUAL_LANG_TCL, "tcl set, append",
	     "set v hello\nset w \"a b\"\nset x [string toupper $v]; append y a b\nset z\nset {a b} 1\nset arr(1) 2\nset v2 {a\nb}\n",
	     "n=3 <set> <v> <hello> t=N A[v=hello f=0]\n"
	     "n=3 <set> <w> <\"a b\"> t=N A[w=\"a b\" f=0]\n"
	     "n=3 <set> <x> <[string toupper $v]> t=; A[x=[string toupper $v] f=0]\n"
	     "n=4 <append> <y> <a> <b> t=N A[y=a b f=2]\n"
	     "n=2 <set> <z> t=N\n"
	     "n=3 <set> <{a b}> <1> t=N\n"
	     "n=3 <set> <arr(1)> <2> t=N\n"
	     "n=3 <set> <v2> <{a\nb}> t=N A[v2={a\nb} f=0]\n");
	cmds(KGENOME_TEXTUAL_LANG_TCL, "tcl set with too many words, continuation",
	     "set a b c\nset v \\\nhello\nset w x\n",
	     "n=4 <set> <a> <b> <c> t=N A[a=b f=10]\n"
	     "n=3 <set> <v> <hello> t=N A[v=hello f=0]\n"
	     "n=3 <set> <w> <x> t=N A[w=x f=0]\n");
	cmds(KGENOME_TEXTUAL_LANG_TCL, "tcl proc, comment",
	     "proc f {} {\n set q 1\n}\nputs \"x y\"\n# set c 1\nset d 4 ;# c\n",
	     "n=4 <proc> <f> <{}> <{\n set q 1\n}> t=N\n"
	     "n=2 <puts> <\"x y\"> t=N\n"
	     "n=0 t=N\n"
	     "n=3 <set> <d> <4> t=; A[d=4 f=0]\n"
	     "n=0 t=N\n");
}

/* ---- every cut of every case -------------------------------------------------------------------------------------- */

/* The readers are given a text that ENDS at the cut (the allocation ends there): any read beyond it is an address error under the sanitised build, and here the check is that no range
 * they report lies beyond the cut and that the answer for a cut does not depend on what lies after it (compared with the reading of the same bytes copied alone). */
static void cuts(void)
{
	static const struct { uint32_t lang; const char *s; } t[] = {
		{ KGENOME_TEXTUAL_LANG_SH, "x=$(echo \"a b\" | tr a-z A-Z)\ny=${x//a/b}${#x}\ncat <<EOF\n$x\nEOF\nz='q'\"w\"\n" },
		{ KGENOME_TEXTUAL_LANG_BAT, "set \"v=a b\"\nset w=%v:~1,2%%v:a=b%\ncall set q=%w%\n( set p=1\n)\n" },
		{ KGENOME_TEXTUAL_LANG_TCL, "set v {a b}\nset w [string map {a b} $v]\nappend y \"x $v\"\n" },
	};
	unsigned k;

	for (k = 0; k < sizeof t / sizeof t[0]; k++) {
		uint32_t n = (uint32_t)strlen(t[k].s), cut;

		for (cut = 0; cut <= n; cut++) {
			char a[8192];
			uint8_t *whole = malloc(n + 1u), *part = malloc(cut ? cut : 1u);

			memcpy(whole, t[k].s, n);
			memcpy(part, t[k].s, cut);
			show(t[k].lang, part, cut, a, sizeof a);
			/* the same text with more after it, limit at the cut: the answer is the same */
			{
				struct kgenome_textual_cmd c;
				uint32_t at = 0;
				struct kgenome_textual_cmd d;
				uint32_t at2 = 0;
				int same = 1;

				memset(&c, 0, sizeof c);
				memset(&d, 0, sizeof d);
				for (;;) {
					int r1 = kgenome_textual_cmd_read(t[k].lang, whole, at, cut, &c);
					int r2 = kgenome_textual_cmd_read(t[k].lang, part, at2, cut, &d);

					if (r1 != r2 || (r1 && (c.n != d.n || c.end != d.end || c.term != d.term || c.paren != d.paren))) {
						same = 0;
						break;
					}
					if (!r1 || c.end <= at || c.end >= cut)
						break;
					at = at2 = c.end;
				}
				CK(same);
			}
			free(whole);
			free(part);
		}
	}
}

int main(void)
{
	CK(kgenome_textual_has_words(KGENOME_TEXTUAL_LANG_SH));
	CK(kgenome_textual_has_words(KGENOME_TEXTUAL_LANG_BAT));
	CK(kgenome_textual_has_words(KGENOME_TEXTUAL_LANG_TCL));
	CK(!kgenome_textual_has_words(KGENOME_TEXTUAL_LANG_PHP));
	CK(!kgenome_textual_has_words(KGENOME_TEXTUAL_LANG_NONE));
	{   /* a braced run of 4096 bytes is read, one of 4097 is not (the reader keeps no allocation for data that long) */
		static char big[4200];
		uint32_t e;

		memset(big, 'a', sizeof big);
		big[0] = '{';
		big[4097] = '}';
		big[4098] = 0;
		e = word(KGENOME_TEXTUAL_LANG_TCL, KGENOME_TEXTUAL_CTX_WORD, big);
		CK(e == 4098u);
		big[4097] = 'a';
		big[4098] = '}';
		big[4099] = 0;
		e = word(KGENOME_TEXTUAL_LANG_TCL, KGENOME_TEXTUAL_CTX_WORD, big);
		CK(e == 0);
	}
	sh_words();
	bat_words();
	tcl_words();
	sh_cmds();
	bat_cmds();
	tcl_cmds();
	cuts();
	printf("textual cmd: %s\n", fails ? "FAILED" : "ok");
	return fails ? 1 : 0;
}
