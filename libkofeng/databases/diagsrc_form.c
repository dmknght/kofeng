/*
 * diagsrc_form.c - the detection form of a diagnose source: reading its declarations, writing them back and resolving
 * them into a struct kof_form (pack/diagform.h). See diagsrc.h.
 *
 * THE DECLARATIONS ARE THE ONES A SIGNATURE MADE, WITH THE SAME SPELLING AND THE SAME RULES, so what a researcher knows
 * from a module reads the same here and the old sources move over line by line:
 *
 *     KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);
 *     KOF_DEFINE_STR(s0, "text", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
 *     KOF_DEFINE_STR_WIDE(s1, "text", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
 *     KOF_DEFINE_HEXSTR(s2, "E8 ?? ?? 5D");              (the case and word options are optional, as in a module)
 *     KOF_DEFINE_REGEX(s3, "GET /[a-z]{4}\\.php");
 *     KOF_MUTATION_BLOCK(b0, KOF_SCAN_ELF_CODE, 0x1a2b3c4du, ...);      (_LIB for a library block)
 *
 * and the two things a module wrote as C in its kof_scan, now declarations, because a diagnose has no code:
 *
 *     KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0, s1);         kof_find_str_any / _all / KOF_FIND_MULTI(n): kof_find_str_multi >= n
 *     KOF_DIAG_FIND(m1, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 236), s2);      kof_find_str_at(ctx->entry_off + 236, s2)
 *     KOF_DIAG_SIMILAR(m2, 60, b0);                           kof_mutation_score(b0) >= 60
 *     KOF_DIAG_EXPR(m0 && !m1 || m2);                         the condition of the old `if`: && || ! and parentheses
 *
 * ONE DECLARATION A LINE (the patcher edits by line), the expression optional (absent: every matcher, ANDed).
 * THE READERS OF THE ARGUMENTS ARE THE BUILDER'S, MOVED HERE: the region table, the six escapes of a literal and the
 * regex unescape were ksigbuilder's; a reader that exists once is the one that cannot disagree with the other.
 */

#include "../kofcore/kofdebug.h"
#include "diagsrc_int.h"
#include "pack/diagform.h"
#include "pack/hexprog.h"
#include "pack/dbcore.h"

#include <celllysis/mutation_window.h>
#include <kofmod/kofmutation.h>

/* The region lists, one per format: the table below is generated from them rather than restating them. */
#include "../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../analyzers/parsers/binaries/pe/pe_parse.h"
#include "../analyzers/parsers/containers/gzip_parse.h"
#include "../analyzers/parsers/containers/docole_parse.h"
#include "../analyzers/parsers/containers/zip_parse.h"
#include "../analyzers/parsers/containers/tar_parse.h"
#include "../analyzers/parsers/containers/sevenzip_parse.h"
#include "../analyzers/parsers/containers/rar_parse.h"
#include "../analyzers/parsers/containers/xz_parse.h"
#include "../analyzers/parsers/scripts/script_parse.h"
#include "../analyzers/parsers/containers/rtf_parse.h"
#include "../analyzers/parsers/containers/pdf_parse.h"
#include "../analyzers/parsers/containers/lha_parse.h"
#include "../analyzers/parsers/containers/chm_parse.h"
#include "../analyzers/parsers/containers/cab_parse.h"
#include "../analyzers/parsers/containers/arj_parse.h"
#include "../analyzers/parsers/containers/bz2_parse.h"
#include "../analyzers/parsers/containers/lnk_parse.h"
#include "../analyzers/parsers/containers/reg_parse.h"
#include <kofmod/amsi.h>
#include <kofmod/proc.h>      /* KOF_SCAN_PROC_LIST */
#include <stdarg.h>

/* ---- the words ------------------------------------------------------------- */

/*
 * The region names a range or a block may be built from, bound to the enums rather than copied from them (the table
 * ksigbuilder carried: a region added to a format header is named here by its list, and a name that is not here is a
 * refusal that lists what is). A format's regions share bit numbers with another's, so a name is a WORD and its bit is
 * only meaningful beside the target format - which is why a mask is written in words and never in numbers.
 */
struct rgn_name {
	const char   *name;
	unsigned long bit;
	uint8_t       fam;          /* which format's list it came from: a bit is a format's own number, see kof_dsrc_region_word */
};

enum rgn_fam {
	F_ANY = 0,                  /* the whole file, the symbol halves: every format has them */
	F_ELF, F_PE, F_GZIP, F_DOCOLE, F_ZIP, F_TAR, F_SZ, F_RAR, F_XZ, F_RTF, F_PDF, F_SCRIPT, F_AMSI, F_PROC,
	F_LHA, F_CHM, F_CAB, F_ARJ, F_BZ2, F_LNK, F_REG,
	F_NONE
};

/* A row of one family. The lists that hold the bare suffix (ELF_REGIONS: X(SCAN_ELF_CODE)) say the word is "KOF_" #x and the
 * bit is KGENOME_##x; the others hold the whole word, which has to be stringised HERE (a name passed through another macro is
 * expanded first, and KOF_SCAN_ALL would come out as its value). One wrapper per family: a list calls X with one argument. */
#define ROW_S(f, x) { "KOF_" #x, (unsigned long)(KGENOME_##x), (f) },
#define R_ANY(x)    { #x, (unsigned long)(x), F_ANY },
#define R_ELF(x)    ROW_S(F_ELF, x)
#define R_PE(x)     ROW_S(F_PE, x)
#define R_GZIP(x)   { #x, (unsigned long)(x), F_GZIP },
#define R_DOCOLE(x) { #x, (unsigned long)(x), F_DOCOLE },
#define R_ZIP(x)    { #x, (unsigned long)(x), F_ZIP },
#define R_TAR(x)    { #x, (unsigned long)(x), F_TAR },
#define R_SZ(x)     { #x, (unsigned long)(x), F_SZ },
#define R_RAR(x)    { #x, (unsigned long)(x), F_RAR },
#define R_XZ(x)     { #x, (unsigned long)(x), F_XZ },
#define R_RTF(x)    { #x, (unsigned long)(x), F_RTF },
#define R_PDF(x)    { #x, (unsigned long)(x), F_PDF },
#define R_SCRIPT(x) { #x, (unsigned long)(x), F_SCRIPT },
#define R_AMSI(x)   { #x, (unsigned long)(x), F_AMSI },
#define R_PROC(x)   { #x, (unsigned long)(x), F_PROC },
#define R_LHA(x)    { #x, (unsigned long)(x), F_LHA },
#define R_CHM(x)    { #x, (unsigned long)(x), F_CHM },
#define R_CAB(x)    { #x, (unsigned long)(x), F_CAB },
#define R_ARJ(x)    { #x, (unsigned long)(x), F_ARJ },
#define R_BZ2(x)    { #x, (unsigned long)(x), F_BZ2 },
#define R_LNK(x)    { #x, (unsigned long)(x), F_LNK },
#define R_REG(x)    { #x, (unsigned long)(x), F_REG },
static const struct rgn_name rgn_names[] = {
	R_ANY(KOF_SCAN_ALL)
	/* Not a format's: the symbol block means the same for every input that has one. */
	R_ANY(KOF_SCAN_SYM_IMP)
	R_ANY(KOF_SCAN_SYM_EXP)
	ELF_REGIONS(R_ELF)
	PE_REGIONS(R_PE)
	GZIP_REGIONS(R_GZIP)
	DOCOLE_REGIONS(R_DOCOLE)
	ZIP_REGIONS(R_ZIP)
	TAR_REGIONS(R_TAR)
	SZ_REGIONS(R_SZ)
	RAR_REGIONS(R_RAR)
	XZ_REGIONS(R_XZ)
	RTF_REGIONS(R_RTF)
	PDF_REGIONS(R_PDF)
	SCRIPT_REGIONS(R_SCRIPT)
	AMSI_REGIONS(R_AMSI)
	/* A process's three searchable fields; META and FD are fields a rule reads, not byte ranges. */
	KOF_SCAN_PROC_LIST(R_PROC)
	/* The seven families the builder's table had never been given (a property test over every format's own list found them: a
	 * region of a cabinet, a link or a registry file could not be named by a signature). */
	LHA_REGIONS(R_LHA)
	CHM_REGIONS(R_CHM)
	CAB_REGIONS(R_CAB)
	ARJ_REGIONS(R_ARJ)
	BZ2_REGIONS(R_BZ2)
	LNK_REGIONS(R_LNK)
	REG_REGIONS(R_REG)
	{ NULL, 0, F_NONE }
};

/* The family a format's regions are listed under, F_NONE for a format with no regions of its own. */
static uint8_t fam_of(uint8_t format)
{
	switch (format) {
	case KOF_FMT_ELF:    return F_ELF;
	case KOF_FMT_PE:     return F_PE;
	case KOF_FMT_GZIP:   return F_GZIP;
	case KOF_FMT_DOCOLE: return F_DOCOLE;
	case KOF_FMT_ZIP: case KOF_FMT_DOCZIP: return F_ZIP;
	case KOF_FMT_TAR:    return F_TAR;
	case KOF_FMT_7Z:     return F_SZ;
	case KOF_FMT_RAR:    return F_RAR;
	case KOF_FMT_XZ:     return F_XZ;
	case KOF_FMT_RTF:    return F_RTF;
	case KOF_FMT_PDF:    return F_PDF;
	case KOF_FMT_SCRIPT: return F_SCRIPT;
	case KOF_FMT_LHA:    return F_LHA;
	case KOF_FMT_CHM:    return F_CHM;
	case KOF_FMT_CAB:    return F_CAB;
	case KOF_FMT_ARJ:    return F_ARJ;
	case KOF_FMT_BZIP2:  return F_BZ2;
	case KOF_FMT_LNK:    return F_LNK;
	case KOF_FMT_REG:    return F_REG;
	case KOF_EVT_AMSI:   return F_AMSI;       /* an event is a target like a format, with a parser of its own */
	case KOF_EVT_PROC:   return F_PROC;
	default:             return F_NONE;
	}
}

const char *kof_dsrc_region_word(uint8_t format, uint32_t bit)
{
	uint8_t fam = fam_of(format);
	size_t i;

	for (i = 0; rgn_names[i].name; i++)
		if ((uint32_t)rgn_names[i].bit == bit && (rgn_names[i].fam == F_ANY || rgn_names[i].fam == fam))
			return rgn_names[i].name;
	return NULL;
}

const char *kof_dsrc_region_at(size_t i, uint32_t *bit)
{
	size_t n = 0;

	while (rgn_names[n].name)
		n++;
	if (i >= n)
		return NULL;
	if (bit)
		*bit = (uint32_t)rgn_names[i].bit;
	return rgn_names[i].name;
}

int kof_dsrc_mask_of(const char *words, uint32_t *mask, char *why, size_t why_cap)
{
	const char *p = words;
	uint32_t m = 0;

	if (mask)
		*mask = 0;
	if (why && why_cap)
		why[0] = 0;
	for (;;) {
		char tok[64];
		size_t n = 0, i;

		while (*p == ' ' || *p == '\t')
			p++;
		while (*p && *p != '|' && n + 1u < sizeof tok)
			tok[n++] = *p++;
		while (n && (tok[n - 1u] == ' ' || tok[n - 1u] == '\t'))
			n--;
		tok[n] = 0;
		if (*p && *p != '|') {
			if (why)
				snprintf(why, why_cap, "a region name is too long");
			return 0;
		}
		if (!n) {
			if (why)
				snprintf(why, why_cap, "empty term in the region mask");
			return 0;
		}
		for (i = 0; rgn_names[i].name; i++)
			if (!strcmp(tok, rgn_names[i].name))
				break;
		if (!rgn_names[i].name) {
			if (why)
				snprintf(why, why_cap, "unknown region \"%.40s\"", tok);
			return 0;
		}
		/* KNOWN DEFECT DF-6 (2026-10-30, M) [sev M]: kof_dsrc_mask_of keeps the bit and drops rgn_names[i].fam: a bit is a format's own number, so KOF_SCAN_ELF_CODE is read as the PE region of the same bit.
		 * Trigger: a diagnose that names KOF_SCAN_ELF_CODE with no KOF_TARGET_FORMAT(ELF). Effect: it builds and matches a marker in a PE code section (kofregion.h promises the build refuses it; ksb_read_mask has no such test either, R).
		 * Reproducer: /mnt/games/normtest/fix_detacc2_fmt/defects/df_repro.c (prints "DF-6 REPRODUCED").
		 * Fix: give the reader the target format (or the module's format) and refuse a region whose fam is not that format's, naming both. */
		m |= (uint32_t)rgn_names[i].bit;
		if (!*p)
			break;
		p++;
	}
	if (mask)
		*mask = m;
	return 1;
}

const char *kof_dsrc_text(struct kof_dsrc *d, const char *t, size_t n)
{
	char *p;

	if (!d || (n && !t) || n > KOF_DSRC_POOL || d->pool_n + n + 1u > KOF_DSRC_POOL)
		return NULL;
	p = d->pool + d->pool_n;
	if (n)
		memcpy(p, t, n);
	p[n] = 0;
	d->pool_n += (uint32_t)n + 1u;
	return p;
}

/* A literal's bytes as the C text the reader accepts. Six escapes and printable ASCII, nothing else: a byte with no
 * spelling is a hex pattern's. */
size_t kof_dsrc_lit_escape(const uint8_t *p, size_t n, char *out, size_t cap)
{
	size_t i, o = 0;

	for (i = 0; i < n; i++) {
		uint8_t c = p[i];
		const char *e = NULL;
		char one[2] = { (char)c, 0 };

		switch (c) {
		case '\\': e = "\\\\"; break;
		case '"':  e = "\\\""; break;
		case '?':  e = "\\?"; break;
		case '\t': e = "\\t"; break;
		case '\n': e = "\\n"; break;
		case '\r': e = "\\r"; break;
		default:
			if (c < 0x20u || c > 0x7eu)
				return 0;
			e = one;
		}
		if (o + strlen(e) + 1u > cap)
			return 0;
		memcpy(out + o, e, strlen(e));
		o += strlen(e);
	}
	if (o >= cap)
		return 0;
	out[o] = 0;
	return o;
}

void kof_dsrc_view_free(struct kof_dsrc_view *v)
{
	if (!v)
		return;
	kof_form_free(v->form);
	v->form = NULL;
}

/* ---- reading --------------------------------------------------------------- */

struct farg {
	const char *p;
	size_t      n;
};

#define FARG_MAX 160

/*
 * THE ARGUMENTS OF THE CALL THAT STARTS AT `p`, as spans of the line: split at the commas of the top level, a string
 * literal (and the escapes in it) and a parenthesis keeping what they hold. -1 when there is no call, a literal or a
 * parenthesis is left open, the call is never closed or it has more than `cap` arguments. A missing ')' is an error here
 * and not a call that reads as closed (the old splitter's defect WD-1 is a graph line's, not repeated for a form).
 */
static int fargs(const char *p, struct farg *a, int cap, const char **after)
{
	const char *q = strchr(p, '(');
	int n = 0, depth = 0;
	const char *start;

	if (!q)
		return -1;
	q++;
	start = q;
	for (;; q++) {
		char c = *q;

		if (!c)
			return -1;
		if (c == '"') {
			q++;
			while (*q && *q != '"') {
				if (*q == '\\' && q[1])
					q++;
				q++;
			}
			if (!*q)
				return -1;
			continue;
		}
		if (c == '(') {
			depth++;
			continue;
		}
		if ((c == ',' && !depth) || (c == ')' && !depth)) {
			const char *s = start, *e = q;

			while (s < e && (*s == ' ' || *s == '\t' || *s == '\r'))
				s++;
			while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
				e--;
			if (n >= cap)
				return -1;
			a[n].p = s;
			a[n].n = (size_t)(e - s);
			n++;
			start = q + 1;
			if (c == ')') {
				if (after)
					*after = q + 1;
				return n;
			}
			continue;
		}
		if (c == ')')
			depth--;
	}
}

static int ident_ok(const struct farg *a)
{
	size_t i;

	if (!a->n || a->n >= KOF_DSRC_NAME_LEN)
		return 0;
	for (i = 0; i < a->n; i++) {
		char c = a->p[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
			return 0;
	}
	return 1;
}

static int word_is(const struct farg *a, const char *w)
{
	return strlen(w) == a->n && !memcmp(a->p, w, a->n);
}

static void copy_name(char *dst, const struct farg *a)
{
	memcpy(dst, a->p, a->n);
	dst[a->n] = 0;
}

/* The text between the quotes of a string-literal argument, raw (no escape undone): NULL when the argument is not one. */
static int quoted(const struct farg *a, const char **in, size_t *n)
{
	if (a->n < 2u || a->p[0] != '"' || a->p[a->n - 1u] != '"')
		return 0;
	*in = a->p + 1;
	*n = a->n - 2u;
	return 1;
}

/* One reader of the case option and the word option (arguments c and w), the builder's wording. */
static int read_options(const struct farg *c, const struct farg *w, unsigned *opt, char *why, size_t cap)
{
	*opt = KDS_OPT_GIVEN;
	if (word_is(c, "KOF_CASE_ICASE"))
		*opt |= KDS_OPT_ICASE;
	else if (!word_is(c, "KOF_CASE_EXACT")) {
		snprintf(why, cap, "the case option must be KOF_CASE_EXACT or KOF_CASE_ICASE, not \"%.30s\"", c->p);
		return 0;
	}
	if (word_is(w, "KOF_WORD_FULLWORD"))
		*opt |= KDS_OPT_FULLWORD;
	else if (word_is(w, "KOF_WORD_TOKEN"))
		*opt |= KDS_OPT_TOKEN;
	else if (!word_is(w, "KOF_WORD_SUBSTRING")) {
		snprintf(why, cap, "the word option must be KOF_WORD_SUBSTRING, KOF_WORD_FULLWORD or KOF_WORD_TOKEN, not \"%.30s\"",
			 w->p);
		return 0;
	}
	return 1;
}

/*
 * A literal's text with the six escapes undone: the bytes, or -1 with a reason. THE ONE READER of the escapes - the
 * builder's module path (ksb_read_literal) calls it too - so a literal means the same in a signature and a diagnose.
 * Three escapes stand for themselves (a backslash, a quote and a question mark, which C would read as syntax or as a
 * trigraph), three are whitespace; not \x, which is greedy and makes a pattern's length depend on what follows it: a hex
 * pattern spells bytes that are not text.
 */
long kof_dsrc_lit_unescape(const char *in, size_t n, uint8_t *out, size_t cap, const char **why)
{
	size_t i, o = 0;

	for (i = 0; i < n; i++) {
		char c = in[i];

		if (c == '\\') {
			if (i + 1u >= n) {
				*why = "an unterminated escape";
				return -1;
			}
			switch (in[i + 1u]) {
			case '\\': case '"': case '?': c = in[i + 1u]; break;
			case 't': c = '\t'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			default:
				*why = "only \\\\, \\\", \\?, \\t, \\n and \\r are supported in patterns - use a hex pattern for anything else";
				return -1;
			}
			i++;
		}
		if (o >= cap) {
			*why = "pattern literal too long";
			return -1;
		}
		out[o++] = (uint8_t)c;
	}
	return (long)o;
}

/* An ASCII literal as UTF-16LE: one byte and a zero for each. REFUSED, NOT ENCODED WRONG - above 0x7F the real encoding
 * is another number of bytes with other values, and a marker that is not the text the author wrote never fires. The one
 * widening, for the builder's module path and for a diagnose. -1 with a reason, else the length written. */
long kof_dsrc_widen(const uint8_t *in, size_t n, uint8_t *out, size_t cap, const char **why)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (in[i] >= 0x80u) {
			*why = "a wide pattern must be ASCII: a byte above 0x7F is not one UTF-16 unit";
			return -1;
		}
	if (n * 2u > cap) {
		*why = "wide pattern too long once widened";
		return -1;
	}
	for (i = 0; i < n; i++) {
		out[i * 2u] = in[i];
		out[i * 2u + 1u] = 0;
	}
	return (long)(n * 2u);
}

/* Only the two escapes C forces on a regex are undone; every other sequence belongs to the regex. */
static long unescape_rx(const char *in, size_t n, char *out, const char **why)
{
	size_t i, o = 0;

	for (i = 0; i < n; i++) {
		char c = in[i];

		if (c == '\\' && i + 1u < n && (in[i + 1u] == '\\' || in[i + 1u] == '"')) {
			c = in[i + 1u];
			i++;
		}
		if (o >= KOF_DSRC_TEXT_MAX) {
			*why = "the pattern is too long";
			return -1;
		}
		out[o++] = c;
	}
	return (long)o;
}

struct fcx {
	struct kof_dsrc              *d;
	const struct kof_dsrc_report *r;
	int                          *errs;
	unsigned                      line;
};

static void ferr(const struct fcx *x, const char *msg)
{
	kof_dsrc_say_err(x->r, x->errs, (int)x->line, msg);
}

/* One item with its text; NULL (said) when the list or the pool is full. */
static struct kof_dsrc_item *fitem(const struct fcx *x, unsigned kind)
{
	return kof_dsrc_add_item(x->d, x->errs, x->r, x->line, kind);
}

static int ftext(const struct fcx *x, const char **dst, uint32_t *dn, const char *t, size_t n)
{
	const char *p = kof_dsrc_text(x->d, t, n);

	if (!p) {
		ferr(x, "the declarations of a form are over the size of the source reader's text pool");
		return 0;
	}
	*dst = p;
	*dn = (uint32_t)n;
	return 1;
}

static void read_range(const struct fcx *x, const struct farg *a, int na)
{
	struct kof_dsrc_item *it;
	uint32_t mask = 0;
	char why[96];
	char words[256];

	if (na != 2 || !ident_ok(&a[0])) {
		ferr(x, "KOF_TARGET_RANGE(name, regions): a plain name and the regions joined by |");
		return;
	}
	if (a[1].n >= sizeof words) {
		ferr(x, "region mask term too long");
		return;
	}
	memcpy(words, a[1].p, a[1].n);
	words[a[1].n] = 0;
	if (!kof_dsrc_mask_of(words, &mask, why, sizeof why)) {
		ferr(x, why);
		return;
	}
	if (!(it = fitem(x, KDS_RANGE)))
		return;
	copy_name(it->s1, &a[0]);
	it->v = mask;
	if (!ftext(x, &it->t1, &it->n1, words, strlen(words)))
		return;
	x->d->n++;
}

/* kind: KDS_STR_*. */
static void read_str(const struct fcx *x, const struct farg *a, int na, unsigned flavour)
{
	struct kof_dsrc_item *it;
	const char *in = NULL, *why = NULL;
	size_t n = 0;
	unsigned opt = 0;
	char buf[KOF_DSRC_LIT_MAX + 1u], wmsg[160];
	long got;
	int want_opts = flavour == KDS_STR_PLAIN || flavour == KDS_STR_WIDE;

	if ((want_opts ? na != 4 : (na != 2 && na != 4)) || !ident_ok(&a[0])) {
		ferr(x, want_opts ? "KOF_DEFINE_STR(name, \"literal\", case, word) wants a plain name, a literal and both options"
				  : "KOF_DEFINE_HEXSTR / KOF_DEFINE_REGEX(name, \"pattern\"[, case, word])");
		return;
	}
	if (!quoted(&a[1], &in, &n)) {
		ferr(x, "the second argument must be a string literal");
		return;
	}
	if (na == 4 && !read_options(&a[2], &a[3], &opt, wmsg, sizeof wmsg)) {
		ferr(x, wmsg);
		return;
	}
	if (flavour == KDS_STR_PLAIN || flavour == KDS_STR_WIDE) {
		got = kof_dsrc_lit_unescape(in, n, (uint8_t *)buf, KOF_DSRC_LIT_MAX, &why);
		if (got < 0) {
			ferr(x, why);
			return;
		}
		if (!got) {
			ferr(x, "empty pattern");
			return;
		}
	} else if (flavour == KDS_STR_REGEX) {
		got = unescape_rx(in, n, buf, &why);
		if (got < 0) {
			ferr(x, why);
			return;
		}
		if (!got) {
			ferr(x, "an empty pattern");
			return;
		}
	} else {
		if (n > KOF_DSRC_TEXT_MAX) {
			ferr(x, "hex pattern too long");
			return;
		}
		memcpy(buf, in, n);
		got = (long)n;
	}
	if (!(it = fitem(x, KDS_STR)))
		return;
	copy_name(it->s1, &a[0]);
	it->a = (uint16_t)flavour;
	it->b = (uint16_t)opt;
	if (!ftext(x, &it->t1, &it->n1, buf, (size_t)got))
		return;
	x->d->n++;
}

static int read_u32(const char *p, size_t n, uint32_t *out)
{
	char tmp[24], *end = NULL;
	unsigned long long v;
	size_t i;

	if (!n || n >= sizeof tmp)
		return 0;
	memcpy(tmp, p, n);
	tmp[n] = 0;
	v = strtoull(tmp, &end, 0);
	if (end == tmp || v > 0xffffffffull)
		return 0;
	for (i = (size_t)(end - tmp); tmp[i]; i++)
		if (tmp[i] != 'u' && tmp[i] != 'U' && tmp[i] != 'l' && tmp[i] != 'L')
			return 0;
	*out = (uint32_t)v;
	return 1;
}

static void read_block(const struct fcx *x, const struct farg *a, int na, int lib)
{
	struct kof_dsrc_item *it;
	uint32_t mask = 0, hv[KOF_FORM_HASH_MAX + 1u], k, nh;
	char words[256], why[96];

	if (na < 3 || !ident_ok(&a[0])) {
		ferr(x, "KOF_MUTATION_BLOCK(name, regions, hashes...)");
		return;
	}
	if (a[1].n >= sizeof words) {
		ferr(x, "region mask term too long");
		return;
	}
	memcpy(words, a[1].p, a[1].n);
	words[a[1].n] = 0;
	if (!kof_dsrc_mask_of(words, &mask, why, sizeof why)) {
		ferr(x, why);
		return;
	}
	nh = (uint32_t)(na - 2);
	if (nh > KOF_FORM_HASH_MAX) {
		ferr(x, "more hashes than a block may carry");
		return;
	}
	for (k = 0; k < nh; k++)
		if (!read_u32(a[2 + k].p, a[2 + k].n, &hv[k])) {
			ferr(x, "a hash that is not a number (or wider than 32 bits)");
			return;
		}
	if (!(it = fitem(x, KDS_BLOCK)))
		return;
	copy_name(it->s1, &a[0]);
	it->b = lib ? (uint16_t)KGENOME_MUTATION_SIDE_LIB : (uint16_t)KGENOME_MUTATION_SIDE_USER;
	it->v = mask;
	KOF_TRACE("[src] block %s: regions '%s' = mask %x, %s, %u hash(es), first %08x last %08x\n", it->s1, words,
		  (unsigned)mask, lib ? "library side" : "user side", (unsigned)nh, (unsigned)hv[0],
		  (unsigned)hv[nh - 1u]);
	if (!ftext(x, &it->t1, &it->n1, words, strlen(words)) ||
	    !ftext(x, &it->t2, &it->n2, (const char *)hv, (size_t)nh * sizeof hv[0]))
		return;
	x->d->n++;
}

/* A comma joined list of names, from the arguments a[from..na). */
static int join_names(const struct fcx *x, const struct farg *a, int from, int na, char *out, size_t cap)
{
	size_t o = 0;
	int k;

	out[0] = 0;
	for (k = from; k < na; k++) {
		if (!ident_ok(&a[k])) {
			ferr(x, "a name here is a plain identifier");
			return 0;
		}
		if (o + a[k].n + 3u > cap) {
			ferr(x, "too many names on one line");
			return 0;
		}
		if (k > from) {
			out[o++] = ',';
			out[o++] = ' ';
		}
		memcpy(out + o, a[k].p, a[k].n);
		o += a[k].n;
		out[o] = 0;
	}
	return 1;
}

static int read_int(const char *p, size_t n, long long *out)
{
	char tmp[32], *end = NULL;

	if (!n || n >= sizeof tmp)
		return 0;
	memcpy(tmp, p, n);
	tmp[n] = 0;
	*out = strtoll(tmp, &end, 0);
	return end != tmp && !*end;
}

static void read_find(const struct fcx *x, const struct farg *a, int na)
{
	struct kof_dsrc_item *it;
	char names[KOF_FORM_MAX_ARG * (KOF_DSRC_NAME_LEN + 2u) + 8u];
	unsigned rule, th = 0;
	long long step = 0;
	int first = 3;
	const struct farg *r = &a[1];
	char range[KOF_DSRC_NAME_LEN] = "";

	if (na < 3 || !ident_ok(&a[0])) {
		ferr(x, "KOF_DIAG_FIND(name, rule, range, markers...)");
		return;
	}
	if (word_is(r, "KOF_FIND_ALL"))
		rule = KOF_FORM_R_ALL;
	else if (word_is(r, "KOF_FIND_ANY"))
		rule = KOF_FORM_R_ANY;
	else if (r->n > 15u && !memcmp(r->p, "KOF_FIND_MULTI(", 15u) && r->p[r->n - 1u] == ')') {
		long long v;

		rule = KOF_FORM_R_MULTI;
		if (!read_int(r->p + 15, r->n - 16u, &v) || v < 1 || v > 255) {
			ferr(x, "KOF_FIND_MULTI(n) wants a whole number from 1 to 255");
			return;
		}
		th = (unsigned)v;
	} else if (r->n > 12u && !memcmp(r->p, "KOF_FIND_AT(", 12u) && r->p[r->n - 1u] == ')') {
		struct farg in[2];
		const char *after;
		int ni = fargs(r->p, in, 2, &after);

		rule = KOF_FORM_R_AT;
		if (ni != 2 || after != r->p + r->n) {
			ferr(x, "KOF_FIND_AT(anchor, step)");
			return;
		}
		if (word_is(&in[0], "KOF_ANCHOR_BOF"))
			th = KOF_FORM_ANCHOR_BOF;
		else if (word_is(&in[0], "KOF_ANCHOR_ENTRY"))
			th = KOF_FORM_ANCHOR_ENTRY;
		else if (word_is(&in[0], "KOF_ANCHOR_EOF"))
			th = KOF_FORM_ANCHOR_EOF;
		else {
			ferr(x, "the anchor is KOF_ANCHOR_BOF, KOF_ANCHOR_ENTRY or KOF_ANCHOR_EOF");
			return;
		}
		if (!read_int(in[1].p, in[1].n, &step)) {
			ferr(x, "the step of KOF_FIND_AT is a whole number");
			return;
		}
	} else {
		ferr(x, "the rule is KOF_FIND_ALL, KOF_FIND_ANY, KOF_FIND_MULTI(n) or KOF_FIND_AT(anchor, step)");
		return;
	}
	if (rule == KOF_FORM_R_AT) {
		first = 2;                         /* an AT matcher names no range: it compares at one place */
	} else {
		if (!ident_ok(&a[2])) {
			ferr(x, "the range is the name of a KOF_TARGET_RANGE");
			return;
		}
		copy_name(range, &a[2]);
	}
	if (na - first < 1 || na - first > (int)KOF_FORM_MAX_ARG) {
		ferr(x, "a matcher lists from one to sixteen markers");
		return;
	}
	if (!join_names(x, a, first, na, names, sizeof names))
		return;
	if (!(it = fitem(x, KDS_FIND)))
		return;
	copy_name(it->s1, &a[0]);
	memcpy(it->s2, range, sizeof it->s2);
	it->a = (uint16_t)rule;
	it->b = (uint16_t)th;
	it->v = (uint64_t)step;
	if (!ftext(x, &it->t1, &it->n1, names, strlen(names)))
		return;
	x->d->n++;
}

static void read_similar(const struct fcx *x, const struct farg *a, int na)
{
	struct kof_dsrc_item *it;
	char names[KOF_FORM_MAX_ARG * (KOF_DSRC_NAME_LEN + 2u) + 8u];
	long long pct;

	if (na < 3 || !ident_ok(&a[0]) || !read_int(a[1].p, a[1].n, &pct) || pct < 1 || pct > 100) {
		ferr(x, "KOF_DIAG_SIMILAR(name, percent, blocks...): a percentage from 1 to 100 and the blocks it holds");
		return;
	}
	if (na - 2 > (int)KOF_FORM_MAX_ARG) {
		ferr(x, "a matcher lists from one to sixteen blocks");
		return;
	}
	if (!join_names(x, a, 2, na, names, sizeof names))
		return;
	if (!(it = fitem(x, KDS_SIMILAR)))
		return;
	copy_name(it->s1, &a[0]);
	it->a = (uint16_t)pct;
	KOF_TRACE("[src] similar %s: %u%% of block(s) %s\n", it->s1, (unsigned)pct, names);
	if (!ftext(x, &it->t1, &it->n1, names, strlen(names)))
		return;
	x->d->n++;
}

static void read_expr(const struct fcx *x, const struct farg *a, int na)
{
	struct kof_dsrc_item *it;
	char buf[256];

	if (na != 1 || a[0].n >= sizeof buf) {
		ferr(x, "KOF_DIAG_EXPR(expression): one expression over matcher names, no comma, under 256 characters");
		return;
	}
	memcpy(buf, a[0].p, a[0].n);
	buf[a[0].n] = 0;
	if (!(it = fitem(x, KDS_EXPR)))
		return;
	if (!ftext(x, &it->t1, &it->n1, buf, a[0].n))
		return;
	x->d->n++;
}

int kof_dsrc_form_line(struct kof_dsrc *d, const struct kof_dsrc_report *r, int *errs, unsigned lineno, const char *line)
{
	static const struct { const char *m; int id; } mac[] = {
		{ "KOF_DEFINE_HEXSTR(", 1 }, { "KOF_DEFINE_REGEX(", 2 }, { "KOF_DEFINE_STR_WIDE(", 3 },
		{ "KOF_DEFINE_STR(", 4 }, { "KOF_TARGET_RANGE(", 5 }, { "KOF_MUTATION_BLOCK_LIB(", 6 },
		{ "KOF_MUTATION_BLOCK(", 7 }, { "KOF_DIAG_FIND(", 8 }, { "KOF_DIAG_SIMILAR(", 9 },
		{ "KOF_DIAG_EXPR(", 10 }
	};
	struct fcx x;
	struct farg a[FARG_MAX];
	const char *after = NULL;
	size_t i;
	int na, id = 0;

	while (*line == ' ' || *line == '\t')
		line++;
	for (i = 0; i < sizeof mac / sizeof mac[0]; i++)
		if (!strncmp(line, mac[i].m, strlen(mac[i].m))) {
			id = mac[i].id;
			break;
		}
	if (!id)
		return 0;
	x.d = d;
	x.r = r;
	x.errs = errs;
	x.line = lineno;
	na = fargs(line, a, FARG_MAX, &after);
	if (na < 0) {
		ferr(&x, "the declaration is not closed on its line (a quote or a parenthesis is open, or it has too many arguments)");
		return 1;
	}
	switch (id) {
	case 1: read_str(&x, a, na, KDS_STR_HEX); break;
	case 2: read_str(&x, a, na, KDS_STR_REGEX); break;
	case 3: read_str(&x, a, na, KDS_STR_WIDE); break;
	case 4: read_str(&x, a, na, KDS_STR_PLAIN); break;
	case 5: read_range(&x, a, na); break;
	case 6: read_block(&x, a, na, 1); break;
	case 7: read_block(&x, a, na, 0); break;
	case 8: read_find(&x, a, na); break;
	case 9: read_similar(&x, a, na); break;
	default: {
		/* Past the closing parenthesis only the end of the statement may follow: a surplus ")" is not read as m1. */
		const char *t = after;

		while (t && (*t == ' ' || *t == '\t'))
			t++;
		if (t && *t && *t != ';' && *t != '/')
			ferr(&x, "KOF_DIAG_EXPR(expression) has text after its closing parenthesis");
		else
			read_expr(&x, a, na);
		break;
	}
	}
	return 1;
}

/* ---- writing --------------------------------------------------------------- */

/* One line of text, appended to `out` at *o; 0 when it does not fit. */
static int put(char *out, size_t cap, size_t *o, const char *fmt, ...) __attribute__((format(printf, 4, 5)));

static int put(char *out, size_t cap, size_t *o, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*o >= cap)
		return 0;
	va_start(ap, fmt);
	n = vsnprintf(out + *o, cap - *o, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= cap - *o)
		return 0;
	*o += (size_t)n;
	return 1;
}

static const char *case_word(unsigned b) { return (b & KDS_OPT_ICASE) ? "KOF_CASE_ICASE" : "KOF_CASE_EXACT"; }
static const char *word_word(unsigned b)
{
	return (b & KDS_OPT_TOKEN) ? "KOF_WORD_TOKEN" : (b & KDS_OPT_FULLWORD) ? "KOF_WORD_FULLWORD" : "KOF_WORD_SUBSTRING";
}

size_t kof_dsrc_form_print(const struct kof_dsrc_item *it, char *out, size_t cap)
{
	size_t o = 0;
	uint32_t k;

	switch (it->kind) {
	case KDS_RANGE:
		if (!it->t1 || !put(out, cap, &o, "KOF_TARGET_RANGE(%s, %s);", it->s1, it->t1))
			return 0;
		return o;
	case KDS_STR: {
		static const char *const macro[] = { "KOF_DEFINE_STR", "KOF_DEFINE_STR_WIDE", "KOF_DEFINE_HEXSTR",
						     "KOF_DEFINE_REGEX" };
		char esc[2u * KOF_DSRC_LIT_MAX + 8u];
		size_t i, e = 0;

		if (it->a > KDS_STR_REGEX || !it->t1)
			return 0;
		if (it->a == KDS_STR_PLAIN || it->a == KDS_STR_WIDE) {
			if (!kof_dsrc_lit_escape((const uint8_t *)it->t1, it->n1, esc, sizeof esc))
				return 0;
		} else if (it->a == KDS_STR_REGEX) {
			for (i = 0; i < it->n1; i++) {
				if (e + 3u >= sizeof esc)
					return 0;
				if (it->t1[i] == '\\' || it->t1[i] == '"')
					esc[e++] = '\\';
				esc[e++] = it->t1[i];
			}
			esc[e] = 0;
		} else {
			if (it->n1 >= sizeof esc || memchr(it->t1, '"', it->n1))
				return 0;
			memcpy(esc, it->t1, it->n1);
			esc[it->n1] = 0;
		}
		if (!put(out, cap, &o, "%s(%s, \"%s\"", macro[it->a], it->s1, esc))
			return 0;
		if ((it->a == KDS_STR_PLAIN || it->a == KDS_STR_WIDE || (it->b & KDS_OPT_GIVEN)) &&
		    !put(out, cap, &o, ", %s, %s", case_word(it->b), word_word(it->b)))
			return 0;
		if (!put(out, cap, &o, ");"))
			return 0;
		return o;
	}
	case KDS_BLOCK: {
		if (!it->t1 || !it->t2 || (it->n2 & 3u) || it->b > 1u ||
		    !put(out, cap, &o, "%s(%s, %s", it->b ? "KOF_MUTATION_BLOCK_LIB" : "KOF_MUTATION_BLOCK", it->s1,
			 it->t1))
			return 0;
		for (k = 0; k < it->n2 / 4u; k++) {
			uint32_t h;

			memcpy(&h, it->t2 + 4u * k, 4u);
			if (!put(out, cap, &o, ", 0x%08xu", (unsigned)h))
				return 0;
		}
		if (!put(out, cap, &o, ");"))
			return 0;
		return o;
	}
	case KDS_FIND: {
		char rule[96];

		if (!it->t1)
			return 0;
		if (it->a == KOF_FORM_R_ALL)
			snprintf(rule, sizeof rule, "KOF_FIND_ALL");
		else if (it->a == KOF_FORM_R_ANY)
			snprintf(rule, sizeof rule, "KOF_FIND_ANY");
		else if (it->a == KOF_FORM_R_MULTI)
			snprintf(rule, sizeof rule, "KOF_FIND_MULTI(%u)", (unsigned)it->b);
		else if (it->a == KOF_FORM_R_AT && it->b <= KOF_FORM_ANCHOR_EOF)
			snprintf(rule, sizeof rule, "KOF_FIND_AT(%s, %lld)",
				 it->b == KOF_FORM_ANCHOR_ENTRY ? "KOF_ANCHOR_ENTRY"
				 : it->b == KOF_FORM_ANCHOR_EOF ? "KOF_ANCHOR_EOF" : "KOF_ANCHOR_BOF",
				 (long long)(int64_t)it->v);
		else
			return 0;
		if (it->a == KOF_FORM_R_AT) {
			if (!put(out, cap, &o, "KOF_DIAG_FIND(%s, %s, %s);", it->s1, rule, it->t1))
				return 0;
		} else if (!put(out, cap, &o, "KOF_DIAG_FIND(%s, %s, %s, %s);", it->s1, rule, it->s2, it->t1)) {
			return 0;
		}
		return o;
	}
	case KDS_SIMILAR:
		if (!it->t1 || !put(out, cap, &o, "KOF_DIAG_SIMILAR(%s, %u, %s);", it->s1, (unsigned)it->a, it->t1))
			return 0;
		return o;
	case KDS_EXPR:
		if (!it->t1 || !put(out, cap, &o, "KOF_DIAG_EXPR(%s);", it->t1))
			return 0;
		return o;
	default:
		return 0;
	}
}

int kof_dsrc_form_item_same(const struct kof_dsrc_item *a, const struct kof_dsrc_item *b)
{
	return a->n1 == b->n1 && a->n2 == b->n2 &&
	       (!a->n1 || (a->t1 && b->t1 && !memcmp(a->t1, b->t1, a->n1))) &&
	       (!a->n2 || (a->t2 && b->t2 && !memcmp(a->t2, b->t2, a->n2)));
}

