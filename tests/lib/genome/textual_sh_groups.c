/*
 * genome / textual_sh_groups - where a shell group ends: `$( )` and `${ }` read by ONE walker (group_end in textual/sh/sh_cmd.c, which two near-identical walkers had been),
 * through the readers that call it: the words of a simple command (kgenome_textual_cmd_read) and an expansion's operands (kgenome_textual_word_read).
 * The cases are hand-written and checked against bash's grammar (a quote inside a group is a quote, a "}" in `$( )` or a ")" in `${ }` is its own, groups nest); each names the
 * rule it pins. The ends are asserted, not "some words": word 1 of the line is exactly the span a shell would read as one word.
 *
 * usage: textual_sh_groups
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <textual/textual.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* the text of word `k` of the command read from the start of `line`, "" when there is no such word */
static int word_is(const char *line, uint32_t k, const char *want, uint32_t nwords)
{
	struct kgenome_textual_cmd c;
	const uint8_t *in = (const uint8_t *)line;
	int ok;

	memset(&c, 0, sizeof c);
	ok = kgenome_textual_cmd_read(KGENOME_TEXTUAL_LANG_SH, in, 0, (uint32_t)strlen(line), &c);
	if (!ok || c.n != nwords || k >= c.n) {
		printf("  line: %s -> ok %d, %u words (want %u)\n", line, ok, c.n, nwords);
		return 0;
	}
	if (!kgenome_textual_range_is(in, c.w[k], want)) {
		printf("  line: %s -> word %u is [%.*s], want [%s]\n", line, k, (int)c.w[k].len, line + c.w[k].off, want);
		return 0;
	}
	return 1;
}

struct ops {
	int n_expand;
	uint32_t n_arg;
	struct kgenome_textual_range arg[4];
	char name[16];
};

static int on_expand(void *u, struct kgenome_textual_range name, uint32_t row, const struct kgenome_textual_range *arg, uint32_t n_arg, int quoted)
{
	struct ops *o = u;
	uint32_t i;

	(void)row;
	(void)quoted;
	o->n_expand++;
	o->n_arg = n_arg;
	for (i = 0; i < n_arg && i < 4u; i++)
		o->arg[i] = arg[i];
	snprintf(o->name, sizeof o->name, "%u", name.len);
	return 1;
}

static int on_other(void *u, struct kgenome_textual_range r, int q)
{
	(void)u; (void)r; (void)q;
	return 1;
}

static int on_lit(void *u, const uint8_t *p, uint32_t n)
{
	(void)u; (void)p; (void)n;
	return 1;
}

static int on_cmd(void *u, struct kgenome_textual_range r, int q)
{
	return on_other(u, r, q);
}

/* one word `${...}` read as an expansion: its end (the byte after the closing brace) and the operands as written */
static uint32_t read_expansion(const char *w, struct ops *o)
{
	struct kgenome_textual_word_sink sk = { .user = o, .lit = on_lit, .var = on_other, .expand = on_expand, .cmd = on_cmd };

	memset(o, 0, sizeof *o);
	return kgenome_textual_word_read(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)w, 0, (uint32_t)strlen(w), KGENOME_TEXTUAL_CTX_WORD, &sk);
}

static int arg_is(const char *w, struct kgenome_textual_range r, const char *want)
{
	return kgenome_textual_range_is((const uint8_t *)w, r, want);
}

int main(void)
{
	struct ops o;
	uint32_t e;

	/* "$( )" in double quotes: the walker is entered from the quote reader, a quote inside the group is its own */
	CK(word_is("echo \"$(echo \")\")\" x", 1, "\"$(echo \")\")\"", 3));
	CK(word_is("echo \"$(echo \")\")\" x", 2, "x", 3));
	/* "${ }" in double quotes: a ")" inside is its own, a "}" in a nested "${ }" closes that one */
	CK(word_is("echo \"a${x}b\" y", 1, "\"a${x}b\"", 3));
	CK(word_is("echo \"${x:-)}\" y", 1, "\"${x:-)}\"", 3));
	CK(word_is("echo \"${x:-${y}}\" y", 1, "\"${x:-${y}}\"", 3));
	CK(word_is("echo \"${x:-\"a b\"}\" y", 1, "\"${x:-\"a b\"}\"", 3));
	CK(word_is("echo \"$(echo \"a b\")\" y", 1, "\"$(echo \"a b\")\"", 3));
	/* $( ) in a bare word: a ")" in single quotes does not close it; groups nest, the depth is counted */
	CK(word_is("echo $(echo ')') y", 1, "$(echo ')')", 3));
	CK(word_is("echo $(echo $(echo a) b) y", 1, "$(echo $(echo a) b)", 3));
	CK(word_is("echo $(echo $(echo a) b) y", 2, "y", 3));
	CK(word_is("echo $(a (b) c) y", 1, "$(a (b) c)", 3));
	/* ${ }: a "}" in single quotes does not close it, a "$( )" inside is a group of its own and its "}" does not close the brace */
	CK(word_is("echo ${x:-'}'} y", 1, "${x:-'}'}", 3));
	CK(word_is("echo ${x:-$(echo })} y", 1, "${x:-$(echo })}", 3));
	CK(word_is("echo ${x:-$(echo $(echo }))} y", 1, "${x:-$(echo $(echo }))}", 3));
	CK(word_is("echo ${x:-${y:-z}} y", 1, "${x:-${y:-z}}", 3));
	/* a backslash keeps the next byte out of the count */
	CK(word_is("echo $(echo \\)) y", 1, "$(echo \\))", 3));
	CK(word_is("echo ${x:-\\}} y", 1, "${x:-\\}}", 3));
	/* the expansion's operands: the separator is the first "/" outside a group, so a "/" inside `$( )` or `${ }` is the operand's own */
	e = read_expansion("${x/a${y}b/c}", &o);
	CK(e == (uint32_t)strlen("${x/a${y}b/c}"));
	CK(o.n_expand == 1 && o.n_arg == 2u && arg_is("${x/a${y}b/c}", o.arg[0], "a${y}b") && arg_is("${x/a${y}b/c}", o.arg[1], "c"));
	e = read_expansion("${x/a$(echo /)b/c}", &o);
	CK(e == (uint32_t)strlen("${x/a$(echo /)b/c}"));
	CK(o.n_expand == 1 && o.n_arg == 2u && arg_is("${x/a$(echo /)b/c}", o.arg[0], "a$(echo /)b") && arg_is("${x/a$(echo /)b/c}", o.arg[1], "c"));
	e = read_expansion("${x/\"a/b\"/c}", &o);
	CK(e == (uint32_t)strlen("${x/\"a/b\"/c}"));
	CK(o.n_expand == 1 && o.n_arg == 2u && arg_is("${x/\"a/b\"/c}", o.arg[0], "\"a/b\"") && arg_is("${x/\"a/b\"/c}", o.arg[1], "c"));
	/* the separator past a double quoted run that holds a group: `"${y}/"` is one operand, the "/" after it is the separator */
	e = read_expansion("${x/\"${y}/\"/c}", &o);
	CK(e == (uint32_t)strlen("${x/\"${y}/\"/c}"));
	CK(o.n_expand == 1 && o.n_arg == 2u && arg_is("${x/\"${y}/\"/c}", o.arg[0], "\"${y}/\"") && arg_is("${x/\"${y}/\"/c}", o.arg[1], "c"));
	e = read_expansion("${x/\"$(echo /)\"/c}", &o);
	CK(o.n_expand == 1 && o.n_arg == 2u && arg_is("${x/\"$(echo /)\"/c}", o.arg[0], "\"$(echo /)\"") && arg_is("${x/\"$(echo /)\"/c}", o.arg[1], "c"));
	printf("genome textual_sh_groups: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
