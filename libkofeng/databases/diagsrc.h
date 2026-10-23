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

#define KOF_DSRC_MAX_ITEM   96u
/* The node bound is the loader's: ONE carrier (KOF_DIAG_MAX_NODE, kofdiagtree.h), so a
 * diagnose the builder accepts is one the loader reads. */
#define KOF_DSRC_MAX_NODE   KOF_DIAG_MAX_NODE
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
	KDS_DISEASE     /* a  = kof_maltype, s1 = the disease                  */
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

struct kof_dsrc {
	struct kof_dsrc_item item[KOF_DSRC_MAX_ITEM];
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

struct kof_dsrc_view {
	char     name[KOF_DSRC_NAME_LEN];
	char     disease[KOF_DSRC_NAME_LEN];   /* "" when the diagnose has none */
	uint8_t  disease_type;                 /* a kof_maltype, when there is one */
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

/*
 * THE SAME PATCH FOR ANOTHER KIND OF SOURCE. `parse` reads the original text
 * (the number of errors, 0 when it can be patched) and `print` writes one
 * declaration as a line, without the newline (0 when it cannot be written);
 * `ud` is handed to `print`. Items are `struct kof_dsrc_item`s, and an item kept
 * whole is recognised by kof_dsrc_same, so a kind of file picks its own `kind`
 * values and the loop does not care what they mean.
 */
struct kof_dsrc_ops {
	int    (*parse)(const char *text, size_t n, struct kof_dsrc *d);
	size_t (*print)(const struct kof_dsrc_item *it, void *ud, char *out,
			size_t cap);
	void   *ud;
};

char *kof_dsrc_patch_with(const struct kof_dsrc_ops *ops, const char *text,
			  size_t n, const struct kof_dsrc *edited,
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

#endif /* KOFENG_DATABASES_DIAGSRC_H */
