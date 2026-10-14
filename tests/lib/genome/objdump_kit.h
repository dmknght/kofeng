/*
 * objdump_kit - reading GNU objdump's listing of x86 code, shared by the tests that use it as the reference for an
 * instruction's LENGTH and NAME (cov_x86_objdump.c on real code, diff_decode_cover.c on generated encodings).
 *
 * `parse` takes one line of `objdump -d -w` ("  4000:\tf3 0f 1e fa          \tendbr64") into its address, bytes and
 * text; `first_word` takes the mnemonic of that text, past the prefix words, in one spelling; `canon` brings the
 * spellings the two decoders differ on to one (jz/je, retn/ret, the compare predicates, ...). Header-only and
 * static: every test is a program of its own.
 */
#ifndef KOFENG_TESTS_OBJDUMP_KIT_H
#define KOFENG_TESTS_OBJDUMP_KIT_H

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OD_UNUSED __attribute__((unused))

struct ins {
	uint64_t addr;
	uint8_t  b[16];
	unsigned n;
	char     text[160];
};

OD_UNUSED static int hexv(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/* one line of `objdump -d -w`: "  4000:\tf3 0f 1e fa          \tendbr64" */
OD_UNUSED static int parse(const char *ln, struct ins *o)
{
	char *e;
	const char *p;

	memset(o, 0, sizeof *o);
	while (*ln == ' ')
		ln++;
	if (hexv(*ln) < 0)
		return 0;
	o->addr = strtoull(ln, &e, 16);
	if (*e != ':' || e[1] != '\t')
		return 0;
	p = e + 2;
	while (hexv(p[0]) >= 0 && hexv(p[1]) >= 0 && (p[2] == ' ' || p[2] == '\t')) {
		if (o->n >= 15)
			return 0;
		o->b[o->n++] = (uint8_t)(hexv(p[0]) * 16 + hexv(p[1]));
		p += 2;
		while (*p == ' ')
			p++;
	}
	while (*p == ' ' || *p == '\t')
		p++;
	snprintf(o->text, sizeof o->text, "%s", p);
	{
		size_t l = strlen(o->text);

		while (l && (o->text[l - 1] == '\n' || o->text[l - 1] == ' '))
			o->text[--l] = 0;
	}
	return o->n > 0;
}

/* lower case, no blanks, no "0x", and without a trailing comment or symbol: the two spellings meet */
OD_UNUSED static void norm(const char *in, char *out, size_t cap)
{
	size_t k = 0;

	for (; *in && k + 1 < cap; in++) {
		if (*in == '#' || *in == '<')
			break;
		if (*in == ' ' || *in == '\t')
			continue;
		if (*in == '0' && (in[1] == 'x' || in[1] == 'X')) {
			in++;
			continue;
		}
		out[k++] = (char)tolower((unsigned char)*in);
	}
	out[k] = 0;
}

/* the words objdump (and the formatter) put in front of a mnemonic that are prefixes, not part of it */
OD_UNUSED static int is_prefix(const char *w)
{
	static const char *const p[] = { "cs", "ds", "es", "ss", "fs", "gs", "data16", "addr32", "addr16", "notrack", "dnt", "repz",
					 "repnz", "rep", "repe", "repne", "lock", "bnd", "xacquire", "xrelease", "{vex}",
					 "{vex3}", "{evex}", "{rex}", "{disp8}", "{disp32}", "bht", "bhnt" };
	unsigned i;

	if (!strncmp(w, "rex", 3))
		return 1;
	for (i = 0; i < sizeof p / sizeof p[0]; i++)
		if (!strcmp(w, p[i]))
			return 1;
	return 0;
}

/* a condition spelled one way or the other: jz/je, setnle/setg, cmovnc/cmovae ... to one spelling */
OD_UNUSED static void cc_canon(char *m, size_t pre)
{
	static const char *const alias[][2] = {
		{ "nbe", "a" }, { "nae", "b" }, { "nge", "l" }, { "nle", "g" }, { "nz", "ne" }, { "nc", "ae" },
		{ "nb", "ae" }, { "na", "be" }, { "ng", "le" }, { "nl", "ge" }, { "pe", "p" }, { "po", "np" },
		{ "z", "e" }, { "c", "b" }
	};
	unsigned i;

	for (i = 0; i < sizeof alias / sizeof alias[0]; i++)
		if (!strcmp(m + pre, alias[i][0])) {
			strcpy(m + pre, alias[i][1]);
			return;
		}
}

OD_UNUSED static void canon(char *m)
{
	size_t l = strlen(m);

	if (!strncmp(m, "cmov", 4))
		cc_canon(m, 4);
	else if (!strncmp(m, "set", 3))
		cc_canon(m, 3);
	else if (m[0] == 'j' && strcmp(m, "jmp") && strcmp(m, "jmpe"))
		cc_canon(m, 1);
	if (!strcmp(m, "retn") || !strcmp(m, "retq"))
		strcpy(m, "ret");
	else if (!strcmp(m, "pushfq") || !strcmp(m, "pushfd"))
		strcpy(m, "pushf");
	else if (!strcmp(m, "popfq") || !strcmp(m, "popfd"))
		strcpy(m, "popf");
	else if (!strcmp(m, "movabs"))
		strcpy(m, "mov");
	else if (!strcmp(m, "fwait"))
		strcpy(m, "wait");
	else if (!strcmp(m, "ins") || !strcmp(m, "insb") || !strcmp(m, "insw") || !strcmp(m, "insd"))
		strcpy(m, "ins");
	else if (!strcmp(m, "outs") || !strcmp(m, "outsb") || !strcmp(m, "outsw") || !strcmp(m, "outsd"))
		strcpy(m, "outs");
	/* the SSE/AVX compares with a predicate in the name: cmpltsd -> cmpsd, vcmpnlesd -> vcmpsd */
	if ((!strncmp(m, "cmp", 3) || !strncmp(m, "vcmp", 4)) && l > 5) {
		char t[3];

		memcpy(t, m + l - 2, 3);
		if ((!strcmp(t, "ss") || !strcmp(t, "sd") || !strcmp(t, "ps") || !strcmp(t, "pd")) &&
		    strcmp(m, "cmpss") && strcmp(m, "cmpsd") && strcmp(m, "cmpps") && strcmp(m, "cmppd") &&
		    strcmp(m, "vcmpss") && strcmp(m, "vcmpsd") && strcmp(m, "vcmpps") && strcmp(m, "vcmppd") &&
		    strcmp(m, "cmpxchg")) {
			snprintf(m, 24, "%scmp%s", m[0] == 'v' ? "v" : "", t);
		}
	}
	if (!strncmp(m, "vpclmul", 7) || !strncmp(m, "pclmul", 6))
		snprintf(m, 24, "%spclmulqdq", m[0] == 'v' ? "v" : "");
	if (!strncmp(m, "vpcmp", 5) && (l > 7) && strncmp(m, "vpcmpistr", 9) && strncmp(m, "vpcmpestr", 9))
		strcpy(m, "vpcmp");     /* the EVEX compares with a predicate name vs the generic form + immediate */
}

/* the mnemonic of a line, past the prefix words, in one spelling; `second` is the text after it */
OD_UNUSED static void first_word(const char *text, char *m, size_t cap)
{
	unsigned i;

	for (;;) {
		i = 0;
		while (text[i] && text[i] != ' ' && i + 1 < cap) {
			m[i] = (char)tolower((unsigned char)text[i]);
			i++;
		}
		m[i] = 0;
		text += i;
		while (*text == ' ')
			text++;
		if (!is_prefix(m) || !*text)
			break;
	}
	canon(m);
}


/*
 * Do two mnemonics - each already in first_word's one spelling - name the same instruction? The two readers spell some
 * instructions differently without disagreeing about them, and every such spelling is a rule here, so that a mnemonic that
 * differs for any other reason is a finding:
 *   the string operations (objdump: movs; here: movsb, movsw, movsd, movsq), the sized forms objdump gives a letter (callw,
 *   retfq, sysretd, enterw) and the ones this decoder gives (iretd, xlatb), SHL and its alias SAL, the far branches
 *   (call / callf), the PREFETCH family by one name, a PREFETCHIT that objdump reads as a NOP, the CMPccXADD condition spellings
 *   (cmpbxadd / cmpcxadd), LOOPE and LOOPZ (one opcode, two spellings), the AVX-512 integer compares with the predicate in the name or in an immediate, and XCHG AX,AX
 *   which objdump prints for the two-byte NOP.
 */
OD_UNUSED static int names_agree(const char *theirs, const char *ours)
{
	static const char *const sop[] = { "movs", "stos", "lods", "scas", "cmps", "ins", "outs" };
	static const char *const ev[] = { "vpcmpb", "vpcmpub", "vpcmpw", "vpcmpuw", "vpcmpd", "vpcmpud", "vpcmpq", "vpcmpuq" };
	size_t lt = strlen(theirs), lo = strlen(ours), i;

	if (!strcmp(theirs, ours))
		return 1;
	for (i = 0; i < sizeof sop / sizeof sop[0]; i++) {
		const size_t l = strlen(sop[i]);

		if (!strcmp(theirs, sop[i]) && !strncmp(ours, sop[i], l) && lo == l + 1u && strchr("bwdq", ours[l]))
			return 1;
	}
	for (i = 0; i < sizeof ev / sizeof ev[0]; i++)
		if (!strcmp(ours, ev[i]) && !strncmp(theirs, "vpcmp", 5))
			return 1;
	if (lt == lo + 1u && !strncmp(theirs, ours, lo) && strchr("wdq", theirs[lo]))
		return 1;                                               /* callw, retfq, sysretd, pcmpestriq */
	if (lo == lt + 1u && !strncmp(theirs, ours, lt) && strchr("dbfq", ours[lt]))
		return 1;                                               /* iretd, xlatb, callf, jmpf */
	if (!strcmp(theirs, "shl") && !strcmp(ours, "sal"))
		return 1;
	if ((!strcmp(theirs, "loope") && !strcmp(ours, "loopz")) || (!strcmp(theirs, "loopne") && !strcmp(ours, "loopnz")))
		return 1;
	if (!strcmp(theirs, "prefetch") && !strncmp(ours, "prefetch", 8))
		return 1;
	if (!strcmp(theirs, "nop") && !strncmp(ours, "prefetchit", 10))
		return 1;
	if (!strcmp(theirs, "xchg") && !strcmp(ours, "nop"))
		return 1;
	if (!strncmp(theirs, "cmp", 3) && !strncmp(ours, "cmp", 3) && lt > 7 && lo > 7 && !strcmp(theirs + lt - 4, "xadd") &&
	    !strcmp(ours + lo - 4, "xadd")) {
		char a[24], b[24];

		snprintf(a, sizeof a, "%.*s", (int)(lt - 7), theirs + 3);
		snprintf(b, sizeof b, "%.*s", (int)(lo - 7), ours + 3);
		cc_canon(a, 0);
		cc_canon(b, 0);
		return !strcmp(a, b);
	}
	return 0;
}

/*
 * The SHAPE of an instruction's text: how many operands, and whether each is a register (r), memory (m) or an immediate or
 * branch target (i). Both readers write Intel syntax, so the text is enough: an operand is memory when it has a bracket, an
 * (or names its size, "dword ptr", or its segment) and an immediate when it begins with a digit or a minus sign, a register
 * otherwise. `out` gets one letter an operand, in order.
 */
OD_UNUSED static void shape_of(const char *text, char *out, size_t cap)
{
	char m[24];
	size_t n = 0, depth = 0;
	int have = 0;
	const char *p = text;
	char tok[96];
	size_t tl = 0;

	for (;;) {                                                  /* skip the prefix words and the mnemonic */
		size_t i = 0;

		while (p[i] && p[i] != ' ' && p[i] != '\t')
			i++;
		if (!i)
			break;
		snprintf(m, sizeof m, "%.*s", (int)(i < 23 ? i : 23), p);
		for (size_t q = 0; m[q]; q++)
			m[q] = (char)tolower((unsigned char)m[q]);
		p += i;
		while (*p == ' ' || *p == '\t')
			p++;
		if (!is_prefix(m) || !*p)
			break;
	}
	out[0] = 0;
	for (;; p++) {
		const char c = *p;

		if (c == '[' || c == '{')
			depth++;
		if (c == ']' || c == '}')
			depth = depth ? depth - 1 : 0;
		if ((c == ',' && !depth) || !c) {
			if (have) {
				size_t k = 0;
				char kind = 'r';

				while (tok[k] == ' ' || tok[k] == '\t')
					k++;
				if (strchr(tok, '[') || strchr(tok, ':') || strstr(tok, "ptr") || strstr(tok, "PTR"))
					kind = 'm';
				else if ((tok[k] >= '0' && tok[k] <= '9') || tok[k] == '-' || !strncmp(tok + k, "0x", 2))
					kind = 'i';
				if (n + 1 < cap) {
					out[n++] = kind;
					out[n] = 0;
				}
			}
			tl = 0;
			have = 0;
			if (!c)
				break;
			continue;
		}
		if (c == '#' || c == '<')
			depth = 0;
		if (tl + 1 < sizeof tok) {
			tok[tl++] = c;
			tok[tl] = 0;
			if (c != ' ' && c != '\t')
				have = 1;
		}
	}
}

#endif
