/*
 * genome / textual_defect_attack - the lexers the audit did not read in full (ruby, python, tcl, powershell, coldfusion, lua, batch, and the page languages) attacked
 * the way this suite attacks everything else: every text of a small alphabet of the language's own syntax, listed and not drawn, against the properties any text must have.
 *
 *   partition   the spans cover the text from 0 to n, none empty, the tag and close lengths inside their span (textual_check.h lex);
 *   open        the status is OPEN exactly when the result counts an open span, and the count is the number of spans that carry F_OPEN;
 *   refusal     a sink that answers 0 at the k-th span stops the walk: the status is REFUSED and exactly k + 1 spans were delivered, for k = 0, 1, 2;
 *   form        the form is made (OK or OPEN) in exactly KGENOME_TEXTUAL_FORM_CAP(n) bytes, fits it, is SMALL (and writes nothing) one byte short, and is its own form;
 *   spans of the form  the form's output lexes as a partition too.
 * The alphabets hold the bytes that matter in each language - its quotes, comment openers, heredoc and tag bytes, "#!" and the white space that is a line break in some
 * and a byte in others (CR, VT, FF) - and the texts are all of them up to 6 bytes: 20 million lexes. A language is a failure when one text breaks one property; the first
 * three are printed, minimal because the list goes by length.
 *
 * Why the old tests missed what this finds: (b) form_property_for and partition_for draw 40000 random texts of up to 160 bytes from an alphabet of about twenty; a
 * pair of bytes that matters is a one in 400 draw at length two and the property is checked once, so the 190 forms the audit found were found by 5 million draws over
 * real files, and nothing in the suite lists the short texts.
 *
 * usage: textual_defect_attack
 */

#include "textual_check.h"

struct lang_alpha {
	uint32_t    lang;
	const char *name, *alpha;
};

static const struct lang_alpha la[] = {
	{ KGENOME_TEXTUAL_LANG_PHP,   "php",   "<?ph \n\r\"'#/" },
	{ KGENOME_TEXTUAL_LANG_SH,    "sh",    "<EO \n\r\v$\"'#(" },
	{ KGENOME_TEXTUAL_LANG_JS,    "js",    "a \n\r\v\"'/*`#!" },
	{ KGENOME_TEXTUAL_LANG_VBS,   "vbs",   "a \n\r\"'_&[#" },
	{ KGENOME_TEXTUAL_LANG_ASP,   "asp",   "<%>\n\r\"'[a " },
	{ KGENOME_TEXTUAL_LANG_JSP,   "jsp",   "<%>\n\r\"'/-a " },
	{ KGENOME_TEXTUAL_LANG_ASPX,  "aspx",  "<%>\n\r\"'@$a " },
	{ KGENOME_TEXTUAL_LANG_PY,    "py",    "a \n\r\v\"'#\\(" },
	{ KGENOME_TEXTUAL_LANG_PERL,  "perl",  "a <\n\r\"'#=$" },
	{ KGENOME_TEXTUAL_LANG_RUBY,  "ruby",  "a <\n\r\"'#=%" },
	{ KGENOME_TEXTUAL_LANG_LUA,   "lua",   "a \n\r\"'-[]#!" },
	{ KGENOME_TEXTUAL_LANG_TCL,   "tcl",   "a \n\r{}[]\"\\#$" },
	{ KGENOME_TEXTUAL_LANG_BAT,   "bat",   "a \n\r\"%^&:@<>" },
	{ KGENOME_TEXTUAL_LANG_PSH,   "psh",   "a \n\r\"'`#<@!" },
	{ KGENOME_TEXTUAL_LANG_CFM,   "cfm",   "<cf a>\n\r#\"'/" },
};

struct walk {
	const uint8_t *in;
	uint32_t n, next, spans, opens, refuse_at;
	int      broken;
};

static int wsink(void *u, const struct kgenome_textual_span *s)
{
	struct walk *w = u;

	if (s->off != w->next || !s->len || (uint64_t)s->off + s->len > w->n || (uint64_t)s->open_len + s->close_len > s->len)
		w->broken = 1;
	w->next = s->off + s->len;
	w->opens += (s->flags & KGENOME_TEXTUAL_F_OPEN) != 0;
	return ++w->spans != w->refuse_at;
}

static const char *check(uint32_t lang, const uint8_t *b, uint32_t n)
{
	static uint8_t o1[256], o2[256];
	struct kgenome_textual_lex_res lr;
	struct walk w;
	enum kgenome_textual_status st;
	struct kgenome_textual_form_req rq;
	struct kgenome_textual_form_res rs, rs2;
	uint32_t k, n1;

	memset(&w, 0, sizeof w);
	w.in = b;
	w.n = n;
	{
		struct kgenome_textual_lex_req lq = { .in = b, .n = n, .lang = lang, .sink = wsink, .user = &w };

		st = kgenome_textual_lex(&lq, &lr);
	}
	if (w.broken || w.next != n)
		return "the spans do not partition the text";
	if ((st == KGENOME_TEXTUAL_OPEN) != (w.opens != 0) || lr.n_open != w.opens)
		return "the status or the count of open spans does not say what the spans carry";
	for (k = 1; k <= 3u && k <= w.spans; k++) {
		struct walk r;
		struct kgenome_textual_lex_req lq;
		struct kgenome_textual_lex_res lr2;

		memset(&r, 0, sizeof r);
		r.in = b;
		r.n = n;
		r.refuse_at = k;
		lq = (struct kgenome_textual_lex_req){ .in = b, .n = n, .lang = lang, .sink = wsink, .user = &r };
		st = kgenome_textual_lex(&lq, &lr2);
		if (st != KGENOME_TEXTUAL_REFUSED || r.spans != k)
			return "a sink that refuses at span k did not stop the walk at k";
	}
	rq = (struct kgenome_textual_form_req){ .in = b, .n = n, .lang = lang, .out = o1, .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
	st = kgenome_textual_form(&rq, &rs);
	if (st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN)
		return "the form was not made in the room it is promised";
	n1 = rs.n_out;
	if (n1 > KGENOME_TEXTUAL_FORM_CAP(n))
		return "the form is longer than its cap";
	if (n) {
		struct kgenome_textual_form_req small = rq;

		small.cap = KGENOME_TEXTUAL_FORM_CAP(n) - 1u;
		if (kgenome_textual_form(&small, &rs2) != KGENOME_TEXTUAL_SMALL || rs2.n_out != 0)
			return "a cap one byte short of the promise is not SMALL";
	}
	rq = (struct kgenome_textual_form_req){ .in = o1, .n = n1, .lang = lang, .out = o2, .cap = KGENOME_TEXTUAL_FORM_CAP(n1) };
	st = kgenome_textual_form(&rq, &rs2);
	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || rs2.n_out != n1 || memcmp(o1, o2, n1))
		return "the form is not its own form";
	memset(&w, 0, sizeof w);
	w.in = o1;
	w.n = n1;
	{
		struct kgenome_textual_lex_req lq = { .in = o1, .n = n1, .lang = lang, .sink = wsink, .user = &w };

		(void)kgenome_textual_lex(&lq, &lr);
	}
	if (w.broken || w.next != n1)
		return "the form's output is not a partition";
	return NULL;
}

static void sweep(const struct lang_alpha *a, uint32_t len)
{
	uint32_t na = (uint32_t)strlen(a->alpha), l, k, idx[8], shown = 0;
	uint8_t b[8];
	uint64_t cases = 0, bad = 0;

	for (l = 1; l <= len; l++) {
		for (k = 0; k < l; k++)
			idx[k] = 0;
		for (;;) {
			const char *why;

			for (k = 0; k < l; k++)
				b[k] = (uint8_t)a->alpha[idx[k]];
			cases++;
			why = check(a->lang, b, l);
			if (why) {
				bad++;
				if (shown < 3u) {
					printf("  FAIL %s [", a->name);
					for (k = 0; k < l; k++)
						printf(b[k] >= 0x20 && b[k] < 0x7f && b[k] != '\\' ? "%c" : "\\x%02x", b[k]);
					printf("]: %s\n", why);
					shown++;
				}
			}
			for (k = 0; k < l && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == l)
				break;
		}
	}
	if (bad) {
		printf("  FAIL %s: %llu of %llu texts break a property\n", a->name, (unsigned long long)bad, (unsigned long long)cases);
		fails++;
	}
}

int main(void)
{
	uint32_t k;

	for (k = 0; k < sizeof la / sizeof la[0]; k++)
		sweep(&la[k], 6);
	printf(fails ? "textual_defect_attack: %d FAILED\n" : "textual_defect_attack: ok\n", fails);
	return fails != 0;
}
