#ifndef KOFENG_DATABASES_DIAGSRC_H
#define KOFENG_DATABASES_DIAGSRC_H

/*
 * diagsrc.h - a diagnose, read from its source and written back to it.
 *
 * ONE READER AND ONE WRITER, for the two programs that handle a diagnose's
 * source: ksigbuilder turns it into a record, and the editor lets a person
 * change it. The reader was a static function in ksigbuilder, which left the
 * editor two choices - a second parser, or not reading diagnoses at all - and
 * CLAUDE.md rules out the first.
 *
 * THE MODEL IS THE LIST OF DECLARATIONS, in the order the file has them, and
 * not the tree they describe. A rule's source is a handful of one-line macros
 * between paragraphs of comment, and the comments are where its evidence is
 * (MEASURED on 0 of 900 clean modules, and the like). Writing a diagnose back
 * by regenerating the file would delete exactly that, so an edit is a change to
 * the list and a write is a PATCH: a line whose declaration is unchanged is
 * left byte for byte as the author wrote it, a removed declaration loses its
 * line, a new one gains a line, and everything that is not a declaration
 * passes through untouched.
 *
 * THE TREE IS A VIEW OF THE LIST - kof_dsrc_resolve - and it is where every
 * rule about what a diagnose may say is checked, in one place, for both
 * callers: one head, tails after it, a symbol attached to something, a gate
 * derived from the nodes. The builder serialises the view; the editor shows it.
 */

#include <stddef.h>
#include <stdint.h>
#include <kofmod/kofdiagtree.h>
#include "pack/diagform.h"

/* 96 were enough for a graph; a form lists a marker, a range, a block or a matcher a line each (KOF_FORM_MAX_*: 64 + 64 + 32 +
 * 64 and an expression) beside the graph's own few. */
#define KOF_DSRC_MAX_ITEM   320u
/* The node bound is the loader's: ONE carrier (KOF_DIAG_MAX_NODE, kofdiagtree.h), so a
 * diagnose the builder accepts is one the loader reads. */
#define KOF_DSRC_MAX_NODE   KOF_DIAG_MAX_NODE
#define KOF_DSRC_NAME_LEN   64u
/* The words of a KOF_TARGET_FORMAT / KOF_TARGET_SUBTYPE line ("KOF_FMT_A | KOF_FMT_B ..."): every format a header can name
 * (KOF_FMT_COUNT, 29 identifiers of at most 15 characters and the " | " between them) is under this. It is the width of
 * a declaration's first text, which holds a name in every other kind. */
#define KOF_DSRC_WORDS_LEN  640u

enum kof_dsrc_kind {
	KDS_NONE = 0,
	KDS_NAME,       /* s1 = the name                                      */
	KDS_ANALYSIS,   /* a  = KOF_DIAG_ANALYSIS_* bits                      */
	KDS_USE_EMU,
	KDS_FORMAT,     /* v  = KOF_TARGET_FORMAT value; s1 = the words it was written in */
	KDS_SUBTYPE,    /* v  = KOF_TARGET_SUBTYPE value; s1 likewise         */
	KDS_ATTRB,      /* a  = fact, v = the value it must have              */
	KDS_SYMBOL,     /* s1 = label, s2 = the symbol's name                 */
	KDS_HEAD,       /* a  = capability, b = KOF_FLOWF_* it must carry     */
	KDS_TAIL,       /* a  = capability, b = KOF_DIAG_B_PRODUCED/_SHARED   */
	KDS_ACTION,     /* a  = the head's capability, b = the action, v = value */
	KDS_FIELD,      /* a  = capability, s1 = the symbol's label           */
	KDS_SEQUENCE,   /* a  = first capability, b = then                    */
	KDS_DISEASE,    /* a  = kof_maltype, s1 = the disease                  */
	KDS_FAMILY,     /* s1 = the family's catalog name                     */
	KDS_VARIANT,    /* s1 = the variant's LETTERS ("A", "AB"), no family */
	KDS_TYPE,       /* a  = kof_maltype: the diagnose's ONE type          */
	KDS_TAG,        /* s1 = the tag's catalog name                        */
	/*
	 * THE DETECTION FORM (see pack/diagform.h): the declarations a signature used to make, spelled as it spelled them.
	 * A line each, read by the same reader and printed by the same printer; text too long for s1 / s2 is in t1 / t2.
	 */
	KDS_RANGE,      /* KOF_TARGET_RANGE(name, mask): s1 = name, v = mask, t1 = the mask's words as written */
	KDS_STR,        /* KOF_DEFINE_STR[_WIDE] / _HEXSTR / _REGEX: s1 = name, a = KDS_STR_*, b = KDS_OPT_*, t1 = the
			 * marker's bytes (a literal) or its text (hex, regex), the C escapes undone */
	KDS_BLOCK,      /* KOF_MUTATION_BLOCK[_LIB]: s1 = name, b = side, v = mask, t1 = mask words, t2 = hashes */
	KDS_FIND,       /* KOF_DIAG_FIND(name, rule, range, markers...): s1 = name, s2 = range, a = kof_form_rule, b =
			 * the threshold (MULTI) or the anchor (AT), v = the step (AT), t1 = the marker names, comma joined */
	KDS_SIMILAR,    /* KOF_DIAG_SIMILAR(name, pct, blocks...): s1 = name, a = pct, t1 = the block names, comma joined */
	KDS_EXPR        /* KOF_DIAG_EXPR(expression over matcher names): t1 = the expression as written */
};

/* KDS_STR's a: which declaration it was. */
#define KDS_STR_PLAIN 0u
#define KDS_STR_WIDE  1u
#define KDS_STR_HEX   2u
#define KDS_STR_REGEX 3u
/* KDS_STR's b: the case option, the word option and whether they were written (a hex or regex marker has a short
 * form without them, and a line that said it so is kept saying it). */
#define KDS_OPT_ICASE    1u
#define KDS_OPT_FULLWORD 2u
#define KDS_OPT_TOKEN    4u
#define KDS_OPT_GIVEN    8u

/* The longest hex or regex text a source holds, and the longest literal: the builder's own bounds (MAX_LITERAL). */
#define KOF_DSRC_TEXT_MAX 511u
#define KOF_DSRC_LIT_MAX  512u

/*
 * ONE DECLARATION. `line` is where it was read from, 1 based, and 0 for one
 * that has no line yet: that number is what lets a patch recognise the lines it
 * may leave alone.
 */
struct kof_dsrc_item {
	uint8_t  kind;
	uint16_t a, b;
	uint64_t v;
	uint32_t line;
	char     s1[KOF_DSRC_WORDS_LEN];
	char     s2[KOF_DSRC_NAME_LEN];
	/* Two texts that do not fit a name, NUL terminated and counted (a marker may hold a NUL): in the pool of the
	 * struct kof_dsrc the item belongs to, or NULL. kof_dsrc_text puts one there. */
	const char *t1, *t2;
	uint32_t    n1, n2;
};

/* The text of the form's markers, hash lists and expression: 64 markers at the longest (512 bytes, escaped: twice) is
 * under this. A source that needs more is an error, never cut (kof_dsrc_text answers NULL). */
#define KOF_DSRC_POOL (128u * 1024u)

struct kof_dsrc {
	struct kof_dsrc_item item[KOF_DSRC_MAX_ITEM];
	uint32_t n;
	uint32_t lines;         /* lines in the text it was read from */
	uint32_t bad;           /* declarations it could not read */
	uint32_t pool_n;        /* bytes of `pool` in use */
	char     pool[KOF_DSRC_POOL];
};

/* Put `n` bytes (and a terminator) in the pool and answer where, or NULL when the pool is full. The item's t1 / t2 are
 * set from the answer by the caller. */
const char *kof_dsrc_text(struct kof_dsrc *d, const char *t, size_t n);

/* Errors and warnings go to the caller, which knows its file's name. `line` is
 * 0 for a statement about the whole file. */
struct kof_dsrc_report {
	void (*error)(void *ud, int line, const char *msg);
	void (*warn)(void *ud, const char *msg);
	void *ud;
};

/* One error: count it in *n and tell the caller. Shared by the diagnose and the
 * disease declaration reader, which reports the same way. */
void kof_dsrc_say_err(const struct kof_dsrc_report *r, int *n, int line,
		      const char *msg);

/*
 * THE DIAGNOSE AS THE ENGINE WILL HAVE IT: the star of nodes, the gate, and the
 * conditions. Field names are the record's.
 */
struct kof_dsrc_node {
	uint16_t cap;
	uint16_t flags;
	uint8_t  role;          /* derived by the engine; always 0 here */
	uint8_t  bits;          /* KOF_DIAG_B_* */
	uint64_t val;           /* when KOF_DIAG_B_VAL */
	char     sym[KOF_DSRC_NAME_LEN];   /* when KOF_DIAG_B_FIELD_OF */
};

#define KOF_DSRC_META_FAMILY  1u
#define KOF_DSRC_META_VARIANT 2u
#define KOF_DSRC_META_TYPE    4u
#define KOF_DSRC_META_TAG     8u
#define KOF_DSRC_META_ALL     15u

struct kof_dsrc_view {
	char     name[KOF_DSRC_NAME_LEN];
	char     disease[KOF_DSRC_NAME_LEN];   /* "" when the diagnose has none */
	uint8_t  disease_type;                 /* a kof_maltype, when there is one */
	/* The catalog facts, by NAME (the build resolves them to ids): KOF_DSRC_META_* says which
	 * of the four were declared; a view that passes kof_dsrc_resolve has all four or none. */
	char     family[KOF_DSRC_NAME_LEN];
	char     variant[KOF_DSRC_NAME_LEN];
	char     tag[KOF_DSRC_NAME_LEN];
	uint8_t  type;                         /* a kof_maltype, when KOF_DSRC_META_TYPE */
	unsigned meta;
	unsigned analysis;      /* KOF_DIAG_ANALYSIS_* | KOF_DIAG_USES_EMU */
	struct kof_dsrc_node nd[KOF_DSRC_MAX_NODE];
	int      n_nd;
	uint16_t need[KOF_DIAG_MAX_NEED];
	int      n_need;        /* declared by the sequence, or derived */
	char     ref[KOF_DIAG_MAX_NEED][KOF_DIAG_NEED_LEN];
	int      n_ref;
	struct kof_diag_when when[KOF_DIAG_MAX_WHEN];
	int      n_when;
	int      has_seq;
	uint16_t seq_first, seq_then;
	/*
	 * THE DETECTION FORM, when the source declares one (see pack/diagform.h): resolved, every name turned into an
	 * index, every marker compiled. NULL for a graph. Allocated by kof_dsrc_resolve and given back by
	 * kof_dsrc_view_free; a view copied by value shares it.
	 */
	struct kof_form *form;
};

/* Read the declarations out of `text`. Comments are not read: a macro named
 * in a comment is a mention, not a declaration. Returns the number of errors.
 *
 * A line that calls a KOF_ macro this reader does not know is not dropped silently: it is
 * a WARNING ("line N: unknown declaration KOF_X"), not an error, so a source written for a
 * newer reader still reads. The text of the line is left alone by the patcher. */
int kof_dsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		   const struct kof_dsrc_report *r);

/* The tree the list describes, with every rule checked. Returns the number of
 * errors; the view is only meaningful at 0. A diagnose is a graph OR a form: the rules of a form (the names, the
 * compiled markers, the expression's tree, one stage) are checked here too, by the same function for every caller. */
int kof_dsrc_resolve(const struct kof_dsrc *d, struct kof_dsrc_view *v,
		     const struct kof_dsrc_report *r);

/* Give back what the view holds (its form). Safe on a view kof_dsrc_resolve filled, whatever the answer was. */
void kof_dsrc_view_free(struct kof_dsrc_view *v);

/*
 * THE FORM'S WORDS, one table: the region names a KOF_TARGET_RANGE or a block may be built from (read out of the format
 * headers, the table ksigbuilder used to carry), the hash spelling. ksigbuilder and the editor
 * ask these and spell none of them.
 *
 * kof_dsrc_mask_of reads "KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA" (words joined by |, any spacing) into a mask: 1, or 0
 * with a reason in `why` (the unknown word is named). kof_dsrc_region_at lists the table (i from 0) for an error that
 * names what is known.
 */
int         kof_dsrc_mask_of(const char *words, uint32_t *mask, char *why, size_t why_cap);
const char *kof_dsrc_region_at(size_t i, uint32_t *bit);
/* The word for region `bit` of a FORMAT (a bit is that format's own number; the whole-file and symbol words are every format's),
 * or NULL when the format has no such region: what a tool spells a mask with. */
const char *kof_dsrc_region_word(uint8_t format, uint32_t bit);
/* THE ONE READER OF A LITERAL'S ESCAPES and the one widening, shared by ksigbuilder's module path and the diagnose reader:
 * the bytes (or -1 with `*why` set) and the length written. */
long kof_dsrc_lit_unescape(const char *in, size_t n, uint8_t *out, size_t cap, const char **why);
long kof_dsrc_widen(const uint8_t *in, size_t n, uint8_t *out, size_t cap, const char **why);
/* A literal's bytes as the C text ksigbuilder reads (the escapes it accepts), without the quotes: the number of bytes
 * written, or 0 when a byte has no spelling (use a hex pattern) or it does not fit. */
size_t kof_dsrc_lit_escape(const uint8_t *p, size_t n, char *out, size_t cap);

/* One declaration as a line of source, without the newline. Returns its
 * length, or 0 when the item is not one that can be written. */
size_t kof_dsrc_print(const struct kof_dsrc_item *it, char *out, size_t cap);

/* The letters of a variant as the catalog makes them: one to eight capital letters (A..Z, AA..). The
 * family is named by KOF_DIAG_FAMILY, so "Mirai_A" is not a variant here and is refused. */
int kof_dsrc_variant_word_ok(const char *w);

/* A name the catalog declarations may carry: letters, digits, '_' and '-', 1 to 63 characters. */
int kof_dsrc_catalog_word_ok(const char *w);

/* Two declarations that say the same thing, wherever they were read from. */
int kof_dsrc_same(const struct kof_dsrc_item *a, const struct kof_dsrc_item *b);
/* A hash of what a resolved diagnose looks for (nodes, conditions, form), not of its name, disease, catalog facts or local labels. */
uint64_t kof_dsrc_view_body_hash(const struct kof_dsrc_view *v);
/* Two resolved diagnoses that are one: the same family, variant, type and tag (all four declared) and the same body. */
int kof_dsrc_view_same(const struct kof_dsrc_view *a, const struct kof_dsrc_view *b);

/* Every comment blanked in place, newlines kept - see the definition. */
void kof_dsrc_blank_comments(char *s, size_t n);

/*
 * THE DIAGNOSES A MODULE SOURCE READS, from the calls it makes - kof_diag(A),
 * kof_diag_share(CAP, A, B), kof_diag_str_any/all(A, ...): calls `fn` once per name,
 * in source order, over the text with its comments blanked. The build uses it to say
 * which diagnoses somebody reads (the engine runs only those and the ones that declare
 * a disease). No shape is required of the module.
 */
void kof_dsrc_reads(const char *text, size_t n,
		    void (*fn)(void *ud, const char *diag), void *ud);

/*
 * THE SOURCE WITH `edited` IN PLACE OF ITS DECLARATIONS, as described above.
 * `edited` is what kof_dsrc_parse returned for `text`, changed: an item kept
 * whole keeps its `line`, a replaced one keeps its line and changes its
 * content, a new one has line 0, a removed one is simply no longer there.
 * Returns a malloc'd, NUL terminated text and its length, or NULL.
 */
char *kof_dsrc_patch(const char *text, size_t n, const struct kof_dsrc *edited,
		     size_t *out_n);

/* The i-th argument of "MACRO(a, b, c)" - the splitter every reader of a
 * diagnose call shares. */
int kof_dsrc_arg(const char *p, int i, char *out, size_t cap);

/* The vocabulary, both ways. A capability is written as its enumerator. */
int         kof_dsrc_cap_of(const char *word, uint16_t *out);
const char *kof_dsrc_cap_word(uint16_t cap);
const char *kof_dsrc_cap_at(size_t i, uint16_t *cap);

/* 1 when every capability the engine names can be written. A build failure
 * when not: a cap no diagnose can name is a gap nobody would see. */
int kof_dsrc_cap_table_check(void);

/*
 * THE HEADER COMMENT OF A DIAGNOSE SOURCE: where it came from, in the block the old signatures opened with.
 *
 *      Generated by KOFViewer.
 *
 *      Test sample: <name>  sha256:<hex>
 *      Researcher:  <who>
 *      Created <date>, updated <date>
 *      Engine:      db format <major>.<minor>, module ABI <n>
 *
 * A COMMENT, so the reader and the builder see none of it (kof_dsrc_blank_comments runs before either looks). The caller
 * gives what only the host knows: the sample's name and digest (the engine's object), the account (`who`) and the date;
 * a field the caller does not know (NULL) is left out, never made up. The engine numbers are the engine's own constants.
 * `date` is required (NULL answers NULL).
 *
 * What `text` already holds decides what happens, told apart by structure and not by a marker: the block IS this tool's when
 * the text starts with a block comment whose first line is the banner `Generated by KOFViewer.`; a header any other comment opens
 * is somebody's.
 *   KOF_DSRC_HEAD_NEW        no leading comment: the block is put in front, then one blank line, then `text`.
 *   KOF_DSRC_HEAD_REFRESHED  this tool's block: `Created` is kept, `updated` becomes `date` and the Engine line is today's; every
 *                            other byte of the text is kept.
 *   KOF_DSRC_HEAD_HAND       a comment that is not this tool's: the text comes back unchanged.
 * What is written into a NEW block keeps only the characters kof_comment_char allows. Returns a malloc'd, NUL terminated text
 * (length in `*out_n`) and the case in `*how`, or NULL.
 */
struct kof_dsrc_meta {
	const char *name;      /* the sample's file name, or NULL */
	const char *sha256;    /* its digest as the engine's object holds it (hex), or NULL */
	const char *who;       /* the researcher, or NULL */
	const char *date;      /* the host's date today */
};
enum { KOF_DSRC_HEAD_NEW = 1, KOF_DSRC_HEAD_REFRESHED, KOF_DSRC_HEAD_HAND };
char *kof_dsrc_head(const char *text, size_t n, const struct kof_dsrc_meta *m, int *how, size_t *out_n);

#endif /* KOFENG_DATABASES_DIAGSRC_H */
