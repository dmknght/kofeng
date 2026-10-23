/*
 * ksb_scan.c - --extract, the scan: find each declaration macro in a line and
 *    read it into the context.
 */

#include "ksb.h"

/* ============================================================================
 * EXTRACT - read the declarations out of a signature source
 *
 * Not a C parser: it looks for its own macro names and reads their arguments.
 * Errors stop the build with a file and a line, which is the point of having a
 * compile step at all - a malformed declaration should fail here rather than
 * silently match nothing.
 * ============================================================================ */
/*
 * The macros a declaration can be written with.
 *
 * Order matters: a shorter name that is a prefix of a longer one would shadow it,
 * so KOF_DEFINE_HEXSTR has to be tested before KOF_DEFINE_STR would match inside
 * it. Getting that wrong is silent - the hex text would be read as a literal.
 */
enum decl_kind {
	DECL_RANGE = 0,
	DECL_STR,
	DECL_STRWIDE,
	DECL_HEXSTR,
	DECL_REGEX,
	DECL_NAME,
	DECL_MUTATION,
	DECL_DISEASE
};

struct macro {
	const char    *name;
	enum decl_kind kind;
};

static const struct macro macros[] = {
	{ "KOF_TARGET_RANGE",  DECL_RANGE   },
	{ "KOF_TARGET_NAME",   DECL_NAME    },
	{ "KOF_DECLARE_DISEASE", DECL_DISEASE },
	{ "KOF_DEFINE_HEXSTR", DECL_HEXSTR  },
	{ "KOF_DEFINE_REGEX",  DECL_REGEX   },
	/* BEFORE KOF_DEFINE_STR, which is a prefix of it - see the note on the
	 * enum above. Tested the other way round, every wide declaration would
	 * be read as a plain one and silently look for the unencoded bytes. */
	{ "KOF_DEFINE_STR_WIDE", DECL_STRWIDE },
	{ "KOF_DEFINE_STR",    DECL_STR     },
	/*
	 * BEFORE KOF_MUTATION_BLOCK, which is a prefix of it - the same trap
	 * KOF_DEFINE_STR_WIDE sits in above, and the same consequence: read the
	 * other way round, every library block would be packed as an ordinary
	 * one, credited by author-code windows, and the separation it exists
	 * for would be gone with nothing to show it.
	 *
	 * Declared the same way and packed the same way otherwise; the only
	 * difference is the side it records - see enum kgenome_mutation_side.
	 */
	{ "KOF_MUTATION_BLOCK_LIB", DECL_MUTATION },
	{ "KOF_MUTATION_BLOCK",  DECL_MUTATION  },
	{ NULL, DECL_RANGE }
};

/*
 * Turn a literal into the bytes a UTF-16LE target holds, in place.
 *
 * The whole of the wide support: one interleave at build time and an ordinary
 * pool entry afterwards. See KOF_DEFINE_STR_WIDE for why it is done here and
 * not as a compare mode in the matcher.
 */
static int widen(struct ksb_ctx *ksb, struct pat *o, int line)
{
	uint8_t out[KOF_HEX_MAX_PROG];
	uint32_t i;

	/*
	 * REFUSED, NOT ENCODED WRONG. One byte and a zero is UTF-16LE only for
	 * ASCII; for anything above it the real encoding is a different number
	 * of bytes with different values, so writing two here would produce a
	 * marker that is not the text the author wrote and would never fire.
	 */
	for (i = 0; i < o->len; i++) {
		if (o->bytes[i] >= 0x80u) {
			ksb_err(ksb, line, "a wide pattern must be ASCII: a byte above "
					   "0x7F is not one UTF-16 unit");
			return 0;
		}
	}
	if (o->len * 2u > sizeof out) {
		ksb_err(ksb, line, "wide pattern too long once widened");
		return 0;
	}

	/* Kept before the bytes are replaced - it is what every report shows. */
	if (o->len < sizeof o->shown) {
		memcpy(o->shown, o->bytes, o->len);
		o->shown[o->len] = '\0';
	}
	o->wide = 1;

	for (i = 0; i < o->len; i++) {
		out[i * 2u]      = o->bytes[i];
		out[i * 2u + 1u] = 0;
	}
	o->len *= 2u;
	memcpy(o->bytes, out, o->len);
	return 1;
}

/* What one source line names: the macro (NULL for a note name, which is kof_debug). */
struct scan_hit {
	const struct macro *m;
	char *p;                   /* where the macro name starts */
};

/* Find, within the line, the macro the line names. Zero when it names none. */
static int scan_find(char *at, size_t line_len, struct scan_hit *h)
{
	const struct macro *m = NULL;
	char *p;
	char saved = at[line_len];

	/* Find within the line; read arguments from the full buffer. Comments were
	 * blanked before this ran, so anything found here is code. */
	at[line_len] = 0;

	/* A note's name is keyed by __LINE__, so the host resolves it through one lookup. */
	p = strstr(at, "kof_debug");
	if (!p)
		for (m = macros; m->name; m++) {
			p = strstr(at, m->name);
			if (p)
				break;
		}
	at[line_len] = saved;   /* p stays valid: it points into the same buffer */

	h->m = m;
	h->p = p;
	return p != NULL;
}

/* A note's name: kof_debug. */
static void scan_name_hit(struct ksb_ctx *ksb, const struct scan_hit *h,
			  int lineno)
{
	char *p = h->p;
	struct dname *nm;

	if (ksb->decl.nnames >= MAX_NAMES) {
		ksb_err(ksb, lineno, "too many note names in one source file");
		return;
	}
	nm = &ksb->decl.names[ksb->decl.nnames];
	nm->line = lineno;
	if (!ksb_read_name(ksb, p, lineno, nm->text, sizeof nm->text))
		return;
	/* The engine's slot is the smallest thing on the way through, so
	 * it is the limit. Refused here, where the message can name the
	 * line, rather than cut silently in two places downstream. */
	if (strlen(nm->text) >= KOF_NAME_MAX_LEN) {
		fprintf(stderr, "%s:%d: error: note name is %zu "
			"characters; the engine stores %u\n", ksb->src_name,
			lineno, strlen(nm->text), KOF_NAME_MAX_LEN - 1u);
		ksb->errors++;
		return;
	}
	ksb->decl.nnames++;
}

/* The case option and the word option, arguments three and four. */
static int scan_options(struct ksb_ctx *ksb, char *p, int lineno, struct pat *o)
{
	static const struct ksb_enum_names words = {
		"KOF_WORD_SUBSTRING", "KOF_WORD_FULLWORD", "KOF_WORD_TOKEN"
	};

	if (!ksb_read_enum(ksb, p, 3, lineno, "the case option",
			   "KOF_CASE_EXACT", "KOF_CASE_ICASE", &o->icase))
		return 0;
	return ksb_read_enum3(ksb, p, 4, lineno, "the word option", &words,
			      &o->fullword);
}

/* KOF_TARGET_NAME: the family and the type of malware. */
static void scan_decl_name(struct ksb_ctx *ksb, char *p, int lineno)
{
	int type_idx;

	if (ksb->decl.have_name) {
		ksb_err(ksb, lineno, "KOF_TARGET_NAME declared more than once; a "
				     "module has one family");
		return;
	}
	if (!ksb_read_maltype(ksb, p, lineno, &type_idx))
		return;
	if (!ksb_read_family(ksb, p, lineno, ksb->decl.family, sizeof ksb->decl.family))
		return;
	/* The file name said it too, so the two must agree - see
	 * nameform_read. */
	if (ksb->decl.name_type >= 0 && ksb->decl.name_type != type_idx) {
		ksb_err(ksb, lineno, "KOF_TARGET_NAME disagrees with the type "
				     "in the file name");
		return;
	}
	ksb->decl.maltype = type_idx;
	ksb->decl.have_name = 1;
}

/* KOF_DECLARE_DISEASE in a module: refused. What a match FINDS is a diagnose's to
 * say - a module names no object - so a declaration here would be one nothing
 * reads. */
static void scan_decl_disease(struct ksb_ctx *ksb, char *p, int lineno)
{
	(void)p;
	ksb_err(ksb, lineno, "KOF_DECLARE_DISEASE in a module; only a diagnose "
			     "declares a disease");
}

/* KOF_TARGET_RANGE: a named set of regions. */
static void scan_decl_range(struct ksb_ctx *ksb, char *p, int lineno)
{
	struct rng *r;

	if (ksb->decl.nrngs >= MAX_PATTERNS) {
		ksb_err(ksb, lineno, "too many declared ranges");
		return;
	}
	if (ksb->decl.nrngs >= KOF_MAX_RANGE_PER_MODULE) {
		ksb_err(ksb, lineno, "more declared ranges than a module may have");
		return;
	}
	r = &ksb->decl.rngs[ksb->decl.nrngs];
	memset(r, 0, sizeof *r);
	r->line = lineno;
	if (!ksb_read_ident(ksb, p, lineno, r->name, sizeof r->name))
		return;
	if (ksb_rng_name_taken(ksb, r->name)) {
		ksb_err(ksb, lineno, "a range with this name is already declared");
		return;
	}
	if (!ksb_read_mask(ksb, p, lineno, r))
		return;
	ksb->decl.nrngs++;
}

/* KOF_MUTATION_BLOCK and KOF_MUTATION_BLOCK_LIB: a similarity block. */
static void scan_decl_block(struct ksb_ctx *ksb, const struct macro *m,
			    char *p, int lineno)
{
	struct blk *b;
	struct rng tmp;

	if (ksb->decl.nblks >= MAX_PATTERNS) {
		ksb_err(ksb, lineno, "too many declared blocks");
		return;
	}
	b = &ksb->decl.blks[ksb->decl.nblks];
	memset(b, 0, sizeof *b);
	b->line = lineno;
	/* Which of the two spellings was matched is the whole of the
	 * difference between them. */
	b->side = strcmp(m->name, "KOF_MUTATION_BLOCK_LIB") == 0
		? (uint32_t)KGENOME_MUTATION_SIDE_LIB
		: (uint32_t)KGENOME_MUTATION_SIDE_USER;
	if (!ksb_read_ident(ksb, p, lineno, b->name, sizeof b->name))
		return;
	if (ksb_blk_name_taken(ksb, b->name)) {
		ksb_err(ksb, lineno, "a block with this name is already declared");
		return;
	}
	/* The region is spelled exactly as a range's is, so it is read
	 * by the same code - a second spelling of the same thing is a
	 * second place for the two to drift. */
	memset(&tmp, 0, sizeof tmp);
	if (!ksb_read_mask(ksb, p, lineno, &tmp))
		return;
	b->mask = tmp.mask;
	if (!ksb_read_norm(ksb, p, lineno, b))
		return;
	if (!ksb_read_hashes(ksb, p, lineno, b))
		return;
	ksb->decl.nblks++;
}

/* KOF_DEFINE_HEXSTR and KOF_DEFINE_REGEX: the text is a program, compiled here. */
static void scan_hex_string(struct ksb_ctx *ksb, const struct macro *m,
			    char *p, int lineno, struct pat *o)
{
	/*
	 * The hex text is read the same way a literal is - argument
	 * two and nowhere else - and then compiled. Case and word
	 * options do not apply: a hex pattern is bytes, and folding
	 * case on a byte that may be a wildcard means nothing.
	 */
	char text[MAX_LITERAL];
	struct kof_hex_stat st;

	if (m->kind == DECL_REGEX) {
		if (!ksb_read_regex_text(ksb, p, lineno, text,
					 sizeof text))
			return;
	} else if (!ksb_read_hex_text(ksb, p, lineno, text,
				      sizeof text)) {
		return;
	}
	/*
	 * TWO SYNTAXES, ONE PROGRAM - so the kind stored is
	 * KOF_STR_HEX either way and nothing downstream has to
	 * know which was written. See kof_regex_compile.
	 */
	o->len = m->kind == DECL_REGEX
	       ? kof_regex_compile(text, o->bytes,
				   sizeof o->bytes, &st)
	       : kof_hex_compile(text, o->bytes,
				 sizeof o->bytes, &st);
	if (o->len == 0) {
		ksb_err(ksb, lineno, kof_hex_error());
		return;
	}
	o->kind = KOF_STR_HEX;
	o->open_gaps = st.open_gaps;
	/*
	 * THE OPTIONS, WHEN THEY WERE WRITTEN.
	 *
	 * Two forms are accepted: the bare one every existing
	 * rule uses, and the one that names a case and a word
	 * option the way a literal does. Two rather than one
	 * because 45 declarations in bases/ and tests/ use the
	 * short form and a flag day would have changed them all
	 * in the same commit that taught the matcher a new
	 * rule - two things to bisect instead of one.
	 *
	 * The defaults are what the short form has always
	 * meant: bytes as written, matching anywhere.
	 */
	if (ksb_arg_count(p) >= 4) {
		if (!scan_options(ksb, p, lineno, o))
			return;
	}
	/* The anchor length is printed because it is the number a
	 * researcher can act on and the one nothing else would
	 * surface: below four the presence set cannot rule this
	 * pattern out, so it is searched on every object of its
	 * format, forever. */
	printf("   %-3s %-22s %u step(s) %u alt(s) span %u..%u "
	       "anchor %u%s\n",
	       m->kind == DECL_REGEX ? "re" : "hex",
	       o->name, st.n_steps, st.n_alts,
	       st.min_span, st.max_span, st.anchor_len,
	       st.anchor_len < 4 ? "  (too short for the presence "
				   "set)" : "");
	ksb->decl.npats++;
}

/* KOF_DEFINE_STR, KOF_DEFINE_STR_WIDE and, through scan_hex_string, the hex and
 * regex forms: one declared string. */
static void scan_decl_string(struct ksb_ctx *ksb, const struct macro *m,
			     char *p, int lineno)
{
	struct pat *o;

	if (ksb->decl.npats >= MAX_PATTERNS) {
		ksb_err(ksb, lineno, "too many declared strings in one source file");
		return;
	}
	if (ksb->decl.npats >= KOF_MAX_STR_PER_MODULE) {
		ksb_err(ksb, lineno, "more declared strings than a module may have; the "
				     "answers are a 64 bit mask");
		return;
	}
	o = &ksb->decl.pats[ksb->decl.npats];

	memset(o, 0, sizeof *o);
	o->line = lineno;
	if (!ksb_read_ident(ksb, p, lineno, o->name, sizeof o->name))
		return;
	if (ksb_str_name_taken(ksb, o->name)) {
		ksb_err(ksb, lineno, "a string with this name is already declared");
		return;
	}

	if (m->kind == DECL_HEXSTR || m->kind == DECL_REGEX) {
		scan_hex_string(ksb, m, p, lineno, o);
		return;
	}

	o->kind = KOF_STR_LITERAL;
	if (!ksb_read_literal(ksb, p, lineno, o))
		return;
	if (!scan_options(ksb, p, lineno, o))
		return;

	if (m->kind == DECL_STRWIDE && !widen(ksb, o, lineno))
		return;
	ksb->decl.npats++;
}

void ksb_scan_line(struct ksb_ctx *ksb, char *at, size_t line_len, int lineno)
{
	struct scan_hit h;

	if (!scan_find(at, line_len, &h))
		return;

	/*
	 * The opening parenthesis has to be on this line. Searching the rest of the
	 * buffer for one would treat a bare mention of the macro as an invocation and
	 * then read arguments from whatever call came next in the file.
	 */
	{
		const char *r = h.p;
		while (*r && *r != '(' && *r != '\n')
			r++;
		if (*r != '(')
			return;
	}

	if (h.m == NULL) {
		scan_name_hit(ksb, &h, lineno);
		return;
	}
	switch (h.m->kind) {
	case DECL_NAME:
		scan_decl_name(ksb, h.p, lineno);
		break;
	case DECL_DISEASE:
		scan_decl_disease(ksb, h.p, lineno);
		break;
	case DECL_RANGE:
		scan_decl_range(ksb, h.p, lineno);
		break;
	case DECL_MUTATION:
		scan_decl_block(ksb, h.m, h.p, lineno);
		break;
	case DECL_STR:
	case DECL_STRWIDE:
	case DECL_HEXSTR:
	case DECL_REGEX:
		scan_decl_string(ksb, h.m, h.p, lineno);
		break;
	}
}
