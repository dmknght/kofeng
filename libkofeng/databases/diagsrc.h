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
#include <kofmod/kofpathogen.h>

#define KOF_DSRC_MAX_ITEM   96u
#define KOF_DSRC_MAX_NODE   64u
#define KOF_DSRC_NAME_LEN   64u

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
	/* A VERDICT'S OWN DECLARATION - see kof_dsrc_cond. */
	KDS_VNAME       /* s1 = KOF_MALTYPE_* word, s2 = the family name       */
};

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
	char     s1[KOF_DSRC_NAME_LEN];
	char     s2[KOF_DSRC_NAME_LEN];
};

/*
 * THE CONDITION OF A VERDICT THAT READS DIAGNOSES: a conjunction of terms,
 *
 *     if (kof_diag(A) && kof_diag(B) && kof_diag_share(CAP, A, B))
 *             KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
 *
 * which is the whole of what the five verdicts of this kind say. It is one
 * unit and not a list of lines, because a wrapped `if` has no line of its own
 * to keep or drop; `at`..`end` is its byte span in the text it was read from,
 * so a patch replaces exactly that and nothing around it.
 *
 * ANYTHING ELSE IN THE FUNCTION IS NOT READ, and a file the reader cannot
 * follow is refused rather than guessed at: an `||`, a count, a second
 * statement. The editor then leaves that verdict alone.
 */
#define KOF_DSRC_MAX_TERM 16u

enum kof_dsrc_term_kind {
	KVT_DIAG = 0,   /* kof_diag(a)                                        */
	KVT_SHARE,      /* kof_diag_share(cap, a, b)                          */
	KVT_STR_ANY,    /* kof_diag_str_any(a, "s", ...) - one of the names   */
	KVT_STR_ALL     /* kof_diag_str_all(a, "s", ...) - every one of them  */
};

#define KOF_DSRC_MAX_STR 8u
#define KOF_DSRC_STR_LEN 48u

struct kof_dsrc_term {
	uint8_t  kind;                  /* enum kof_dsrc_term_kind                    */
	uint16_t cap;                   /* share: the node both must meet at          */
	char     a[KOF_DSRC_NAME_LEN];  /* a diagnose, as the source spells it        */
	char     b[KOF_DSRC_NAME_LEN];  /* share: the other                           */
	uint8_t  n_str;                 /* str_*: the names it asks about             */
	char     str[KOF_DSRC_MAX_STR][KOF_DSRC_STR_LEN];
};

struct kof_dsrc_cond {
	uint32_t n;
	struct kof_dsrc_term t[KOF_DSRC_MAX_TERM];
	char     infect[48];            /* the KOF_MALVAR_* word it reports           */
	size_t   at, end;               /* "if" .. its closing ")", in the source     */
};

struct kof_dsrc {
	struct kof_dsrc_item item[KOF_DSRC_MAX_ITEM];
	struct kof_dsrc_cond cond;
	int      has_cond;              /* the file is a verdict that reads diagnoses */
	uint32_t n;
	uint32_t lines;         /* lines in the text it was read from */
	uint32_t bad;           /* declarations it could not read */
};

/* Errors and warnings go to the caller, which knows its file's name. `line` is
 * 0 for a statement about the whole file. */
struct kof_dsrc_report {
	void (*error)(void *ud, int line, const char *msg);
	void (*warn)(void *ud, const char *msg);
	void *ud;
};

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

struct kof_dsrc_view {
	char     name[KOF_DSRC_NAME_LEN];
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
};

/* Read the declarations out of `text`. Comments are not read: a macro named
 * in a comment is a mention, not a declaration. Returns the number of errors. */
int kof_dsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		   const struct kof_dsrc_report *r);

/* The tree the list describes, with every rule checked. Returns the number of
 * errors; the view is only meaningful at 0. */
int kof_dsrc_resolve(const struct kof_dsrc *d, struct kof_dsrc_view *v,
		     const struct kof_dsrc_report *r);

/* One declaration as a line of source, without the newline. Returns its
 * length, or 0 when the item is not one that can be written. */
size_t kof_dsrc_print(const struct kof_dsrc_item *it, char *out, size_t cap);

/* Two declarations that say the same thing, wherever they were read from. */
int kof_dsrc_same(const struct kof_dsrc_item *a, const struct kof_dsrc_item *b);
int kof_dsrc_cond_same(const struct kof_dsrc_cond *a, const struct kof_dsrc_cond *b);

/* The condition as source: "if (...)" with the terms wrapped the way the shipped
 * verdicts wrap them, ready to stand where the old one stood. */
size_t kof_dsrc_cond_print(const struct kof_dsrc_cond *c, char *out, size_t cap);
/* One term of it, for a caller that shows them one to a row. 0 if it cannot be written. */
size_t kof_dsrc_term_print(const struct kof_dsrc_term *t, char *out, size_t cap);

/* Every comment blanked in place, newlines kept - see the definition. */
void kof_dsrc_blank_comments(char *s, size_t n);

/*
 * THE DIAGNOSES A VERDICT SOURCE READS, from the condition kof_dsrc_parse read:
 * each term's names, in order, `a` and then `b` for a join. Calls `fn` once per
 * name. Nothing for a source with no condition.
 */
void kof_dsrc_cond_names(const struct kof_dsrc_cond *c,
			 void (*fn)(void *ud, const char *diag), void *ud);

/*
 * WHAT A VERDICT MUST SAY, checked where the diagnose's own rules are: a
 * format, a name, at least one term, and a join whose two diagnoses are terms
 * of the same condition (a join of something the verdict never asked is a
 * statement about nothing). Returns the number of errors. That each name is a
 * diagnose that exists is the build's to check - it has the database.
 */
int kof_dsrc_verdict_check(const struct kof_dsrc *d,
			   const struct kof_dsrc_report *r);

/* A whole verdict file for `d` - includes, declarations, the function - for a
 * verdict that does not exist yet. malloc'd, or NULL. */
char *kof_dsrc_verdict_new(const struct kof_dsrc *d, size_t *out_n);

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
 * diagnose call shares, a verdict's call to kof_diag_share included. */
int kof_dsrc_arg(const char *p, int i, char *out, size_t cap);

/* The vocabulary, both ways. A capability is written as its enumerator. */
int         kof_dsrc_cap_of(const char *word, uint16_t *out);
const char *kof_dsrc_cap_word(uint16_t cap);
size_t      kof_dsrc_cap_count(void);
const char *kof_dsrc_cap_at(size_t i, uint16_t *cap);

/* 1 when every capability the engine names can be written. A build failure
 * when not: a cap no diagnose can name is a gap nobody would see. */
int kof_dsrc_cap_table_check(void);

#endif /* KOFENG_DATABASES_DIAGSRC_H */
