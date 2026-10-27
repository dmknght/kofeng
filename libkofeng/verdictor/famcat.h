/*
 * famcat.h - THE MALWARE FAMILY CATALOG as a library: families, the variants of a family, and the malware types of a
 * variant. In memory only, and the caller owns the memory: kof_famcat_init is handed the arrays and their sizes, so the
 * limit on entries is the caller's and is NAMED by kof_famcat_cap_family / kof_famcat_cap_variant; an add past it
 * answers KOF_FAMCAT_FULL and never drops anything silently.
 *
 * STORAGE is famcat_store.c (save, load, below): one file per family in a directory the host names. This file, the model, reads
 * and writes no file.
 *
 * NAMES: a FAMILY name is typed: the engine's name rule (below), 1..KOF_NAME_MAX (63) characters,
 * kept as typed, unique among families IGNORING LETTER CASE ("Mirai" and "mirai" are one name: it becomes a lower-case file name). A VARIANT name is never typed: the
 * library letters it, "<family>_A", "<family>_B", ... "<family>_Z", "<family>_AA", "<family>_AB", ... (spreadsheet style, bijective
 * base 26, upper case; the family's counter, which never goes down; with `reuse` the smallest letter no variant uses any more;
 * kof_famcat_variant_name says what the next one is).
 *
 * THE 63-CHARACTER RULE (KOF_NAME_MAX) is checked against the LONGEST suffix the catalog can reach, so a family that was accepted can never meet
 * the limit later. The caller's variant table holds cap_variant entries, so a family can have at most that many variants; the
 * suffix of variant n has 1 letter up to n = 26, 2 letters up to 702, 3 letters up to 18278. The viewer's table of 256 variants
 * therefore needs 2 letters: "<family>_" + 2 letters = family + 3 characters, so a family of 61..63 characters is refused with
 * KOF_FAMCAT_VARIANT_NAME and one of 60 characters is accepted (its names are at most 63 characters). A catalog of more than 702
 * variants would need 3 letters and refuse families longer than 59. kof_famcat_family_max says the longest family name a catalog
 * takes (KOF_NAME_MAX - 1 - letters of its table size); the viewer prints that number in the refusal.
 *
 * A VARIANT IS ITS TYPE SET: it carries at least one type (KOF_FAMCAT_NO_TYPE otherwise) and no two variants of a family
 * have the same set (KOF_FAMCAT_DUP_TYPES), so two variants of one family are never indistinguishable. Both rules hold for
 * add_family (its first variant), add_variant and set_types.
 *
 * TYPES: a variant's types are a bitmask over enum kof_maltype (kofmod/kofverdict.h; bit n is value n). The selectable
 * types are the engine's list minus Packer (the engine declares it "not malware, a recognised wrapper"); the names come
 * from kof_maltype_name, there is no table of them here.
 *
 * No writable global state; safe on many threads as long as one catalog is used by one thread at a time.
 */
#ifndef KOF_FAMCAT_H
#define KOF_FAMCAT_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofname.h>

/* THE NAME RULE IS THE ENGINE'S (kofmod/kofname.h: kof_name_ok, kof_name_char, KOF_NAME_MAX), not a copy: letters, digits, '-' and '_',
 * at most KOF_NAME_MAX characters, whole name included (a variant's too). '.' and everything else is refused on purpose: a name
 * reaches a filesystem path, a C string literal and the verdict line. */
#define KOF_FAMCAT_NAME_MAX KOF_NAME_MAX

enum kof_famcat_status {
	KOF_FAMCAT_OK = 0,
	KOF_FAMCAT_EMPTY,          /* no name */
	KOF_FAMCAT_TOO_LONG,       /* more than KOF_FAMCAT_NAME_MAX characters */
	KOF_FAMCAT_BAD_CHAR,       /* a character outside letters, digits, '_' and '-' */
	KOF_FAMCAT_DUP_FAMILY,     /* a family of that name exists */
	KOF_FAMCAT_DUP_VARIANT,    /* a variant of that name exists in the catalog */
	KOF_FAMCAT_BAD_TYPE,       /* a type that is not in the engine's list, or is Packer */
	KOF_FAMCAT_FULL,           /* the caller's family or variant table is full (see the caps) */
	KOF_FAMCAT_NO_FAMILY,      /* no such family or variant index */
	KOF_FAMCAT_NO_TYPE,        /* a variant needs at least one type */
	KOF_FAMCAT_DUP_TYPES,      /* another variant of the family has exactly this set of types */
	KOF_FAMCAT_VARIANT_NAME,   /* the lettered name "<family>_X" would be longer than KOF_NAME_MAX */
	KOF_FAMCAT_BAD_COMMENT,    /* a character kof_comment_char refuses (non-printable, '*' or '/') */
	KOF_FAMCAT_COMMENT_TOO_LONG, /* more than KOF_FAMCAT_COMMENT_MAX characters */
	KOF_FAMCAT_NO_FREE_LETTER   /* reuse asked and the family has no deleted variant name to take */
};

/* The longest comment of a variant (a comment belongs to a VARIANT only; a family has none). A bound on what a person types into a dialog row (the table column scrolls
 * sideways), chosen to keep one catalog line readable; the character rule is the engine's kof_comment_char, not a copy. */
#define KOF_FAMCAT_COMMENT_MAX 120

/* A family carries a COUNTER of the next variant letter (1 = "A"; it starts at 1 and NEVER goes down: deleting a variant does not
 * lower it, so by default a variant name is never used twice). A variant carries its own letter number. What Save will have to
 * write later, per family, is this counter and the letter of every variant (the names follow from the family name and the
 * letters); nothing is written now. */
struct kof_famcat_fam {
	char     name[KOF_FAMCAT_NAME_MAX + 1];
	uint32_t next;              /* the letter number the next variant takes unless it reuses a free one */
};

struct kof_famcat_var {
	char     name[KOF_FAMCAT_NAME_MAX + 1];
	char     comment[KOF_FAMCAT_COMMENT_MAX + 1];
	uint32_t letter;            /* its letter number in the family: 1 = A, 26 = Z, 27 = AA (bijective base 26) */
	uint32_t family;            /* index of its family */
	uint32_t types;             /* bitmask over enum kof_maltype */
};

struct kof_famcat {
	struct kof_famcat_fam *fam;
	struct kof_famcat_var *var;
	uint32_t cap_fam, cap_var, n_fam, n_var;
	/* A REVISION: bumped by every call that changes the catalog (kof_famcat_touch, the one place), so a reader that keeps something it
	 * derived (the dialog's rows, sizes and dirty flag) keeps the number beside it and recomputes only when it moved. Not part of
	 * the catalog's value: kof_famcat_dirty does not compare it. */
	uint32_t rev;
};

/* Record that the catalog changed. Called by every mutating function of the library on its way out; nothing else calls it. */
static inline void kof_famcat_touch(struct kof_famcat *c)
{
	c->rev++;
}

/* One line of the catalog in display order: a family, or a variant under it. */
struct kof_famcat_item {
	uint32_t family;
	int32_t  variant;           /* -1 for the family's own line */
};

void kof_famcat_init(struct kof_famcat *c, struct kof_famcat_fam *fam, uint32_t cap_fam,
		     struct kof_famcat_var *var, uint32_t cap_var);
uint32_t kof_famcat_cap_family(const struct kof_famcat *c);
uint32_t kof_famcat_cap_variant(const struct kof_famcat *c);

/* The word for a status, one line, for a dialog's error row. */
const char *kof_famcat_status_text(enum kof_famcat_status st);

/* The engine's name rule as a status (empty, too long, bad character); no catalog needed. */
enum kof_famcat_status kof_famcat_name_check(const char *name);
/* The longest family name this catalog accepts: its longest variant name must still fit KOF_NAME_MAX. */
uint32_t kof_famcat_family_max(const struct kof_famcat *c);

/* The selectable types: n of them, the i-th is the engine value kof_famcat_type_value(i), spelled kof_famcat_type_name(i). */
uint32_t kof_famcat_type_count(void);
uint32_t kof_famcat_type_value(uint32_t i);
const char *kof_famcat_type_name(uint32_t i);
/* The mask of every selectable type: a mask with another bit is KOF_FAMCAT_BAD_TYPE. */
uint32_t kof_famcat_type_mask_all(void);

/* The comment rule as a status: empty is fine, kof_comment_char on every character, at most KOF_FAMCAT_COMMENT_MAX characters.
 * The one check add_family, add_variant and set_comment use. */
enum kof_famcat_status kof_famcat_comment_check(const char *comment);

/* Add a family and its first variant "<name>_A" carrying `types` and `comment` (NULL = none; the first variant's comment, a family
 * has none). On OK *fam is the family's index. Nothing is added on a failure. */
enum kof_famcat_status kof_famcat_add_family(struct kof_famcat *c, const char *name, const char *comment, uint32_t types,
					     uint32_t *fam);
/* The name the next variant of family `fam` would get, into out[cap] (KOF_FAMCAT_NAME_MAX + 1 is always enough). One function:
 * add_variant takes its name from here, so what a dialog shows is what is created. */
enum kof_famcat_status kof_famcat_variant_name(const struct kof_famcat *c, uint32_t fam, int reuse, char *out, uint32_t cap);
/* How many letters below the family's counter no variant uses any more (deleted ones): what `reuse` can take. */
uint32_t kof_famcat_free_letters(const struct kof_famcat *c, uint32_t fam);
/* The name of the FIRST variant of a family that does not exist yet ("<family>_A"): what an Add family dialog shows while the name
 * is typed. The same spelling and the same length rule as add_family; KOF_FAMCAT_VARIANT_NAME when add_family would refuse it. */
enum kof_famcat_status kof_famcat_first_variant_name(const struct kof_famcat *c, const char *family, char *out, uint32_t cap);
/* Add the next lettered variant to family `fam` with the given types; `comment` (NULL = none) is the VARIANT's. On OK *var is its
 * index. */
enum kof_famcat_status kof_famcat_add_variant(struct kof_famcat *c, uint32_t fam, const char *comment, uint32_t types,
					      int reuse, uint32_t *var);
/* Replace the types of variant `var` (the same rules: not empty, not the set of a sibling). */
enum kof_famcat_status kof_famcat_set_types(struct kof_famcat *c, uint32_t var, uint32_t types);

/* Replace the types of variant `var` and its comment together, or neither (the edit dialog's OK): the rules of set_types and
 * set_comment. */
enum kof_famcat_status kof_famcat_set_variant(struct kof_famcat *c, uint32_t var, const char *comment, uint32_t types);
/* Rename family `fam`: the family rules of add_family (name rule, the 63-character rule with the longest variant suffix, no other
 * family of that name ignoring letter case). Every variant of it is renamed with it: "<family>_<letters>", the letters stay. */
enum kof_famcat_status kof_famcat_rename_family(struct kof_famcat *c, uint32_t fam, const char *name);
/* Remove a variant, or a family with all its variants; the others keep their order and indices shift down. A freed letter is
 * the family's counter is NOT lowered (a deleted name is not used again unless add_variant is asked to reuse one). A family left with no variant stays. */
enum kof_famcat_status kof_famcat_delete_variant(struct kof_famcat *c, uint32_t var);
enum kof_famcat_status kof_famcat_delete_family(struct kof_famcat *c, uint32_t fam);
/* Replace the comment of variant `var`; types and names are never touched. NO_FAMILY for an index the catalog does not have. */
enum kof_famcat_status kof_famcat_set_comment(struct kof_famcat *c, uint32_t var, const char *comment);

/* The comment of variant `var` ("" when there is none or the index is not the catalog's). */
const char *kof_famcat_comment(const struct kof_famcat *c, uint32_t var);

/* Display order: families in creation order, each followed by its variants in creation order. Writes at most `cap`
 * items and returns how many the catalog has (so a short buffer is seen, not silent). */
uint32_t kof_famcat_list(const struct kof_famcat *c, struct kof_famcat_item *out, uint32_t cap);

/* ---- restoring a saved catalog: the three steps a loader takes, each with the checks of the dialog's own call --------------- */

/* A family with no variant and the counter at 1 (add_family always makes its first variant). The name rules of add_family. */
enum kof_famcat_status kof_famcat_load_family(struct kof_famcat *c, const char *name, uint32_t *fam);
/* Raise the counter of family `fam` to `next` (it never goes down: a lower number is accepted and changes nothing); the name rule
 * of rename_family on the longest suffix. */
enum kof_famcat_status kof_famcat_load_next(struct kof_famcat *c, uint32_t fam, uint32_t next);
/* A variant with letter number `letter` (kof_famcat_letter_parse of the suffix): the rules of add_variant, and its letter must be
 * unused; a letter at or above the counter raises the counter past it. */
enum kof_famcat_status kof_famcat_load_variant(struct kof_famcat *c, uint32_t fam, uint32_t letter, const char *comment,
					       uint32_t types, uint32_t *var);
/* The number of "A".."Z", "AA".. (1-based, bijective base 26); 0 when it is not one to five capital letters. */
uint32_t kof_famcat_letter_parse(const char *letters);
/* The way there: the letters of number n into out[cap] (the one spelling a variant's name and a saved file use); their count, 0 when n is 0 or they do not fit. */
uint32_t kof_famcat_letter_text(uint32_t n, char *out, uint32_t cap);

/* ---- the snapshot: what Discard goes back to ---------------------------------------------------------------------------- */

/* `snap` is a catalog the caller initialised with arrays of its own at least as big as `c`'s entries (FULL otherwise). Copy c into
 * snap; restore copies it back. dirty: 1 when c differs from snap by value (counts, names, letters, counters, comments, types, order). */
enum kof_famcat_status kof_famcat_snapshot(const struct kof_famcat *c, struct kof_famcat *snap);
enum kof_famcat_status kof_famcat_restore(struct kof_famcat *c, const struct kof_famcat *snap);
int kof_famcat_dirty(const struct kof_famcat *c, const struct kof_famcat *snap);

/* ---- storage (famcat_store.c) ----------------------------------------------------------------------------------------- */

/* ONE FILE PER FAMILY in one directory, named by the family in LOWER CASE, "<family>.c" (kof_famcat_file_name). It is DATA, never
 * compiled, read line by line:
 *     // Generated by Manage > Pathogens; edit by hand with care.
 *     KOF_MALWARE_FAMILY_NAME("Mirai");
 *     KOF_MALWARE_NEXT_VARIANT("C");
 *     // comment of the variant (a variant has at most one; none = no line)
 *     KOF_MALWARE_VARIANT("A", KOF_MALTYPE_ROOTKIT, KOF_MALTYPE_BOTNET);
 * `KOF_MALWARE_NEXT_VARIANT` is the family's counter (the letters suffix of the next variant, "C" = 3); the variant lines carry the
 * letters suffix only and the engine's KOF_MALTYPE_* names, in engine order; variants are written in letter order. A reader takes
 * the lines it knows and counts the others (blank lines and comments that belong to no variant excepted). */

#define KOF_FAMCAT_FILE_MAX     (256u * 1024u)  /* a file larger than this is not read (a family of 256 variants is about 100 KB) */
#define KOF_FAMCAT_LINE_MAX     1024u           /* a longer line makes its file unreadable (the longest line written is under 400) */
#define KOF_FAMCAT_FILES_MAX    256u            /* the files a directory may hold for this store to know them */
#define KOF_FAMCAT_FILENAME_MAX (KOF_FAMCAT_NAME_MAX + 2u)  /* "<family>.c" */

enum kof_famcat_io {
	KOF_FAMCAT_IO_OK = 0,
	KOF_FAMCAT_IO_NO_DIR,       /* the host named no directory */
	KOF_FAMCAT_IO_COLLISION,    /* two families would share a file, or a file that was not loaded is in the way */
	KOF_FAMCAT_IO_FAIL          /* a directory or file could not be read, created, written or removed */
};

/* What the directory held when it was last loaded or saved: the files Save may rewrite and remove (a file that was not loaded is
 * never touched), and the line the host shows. */
struct kof_famcat_store {
	uint32_t n_file;
	char     file[KOF_FAMCAT_FILES_MAX][KOF_FAMCAT_FILENAME_MAX + 1u];
	uint32_t n_bad;             /* the last load: files not loaded */
	uint32_t n_ignored;         /* the last load: lines of loaded files that were not understood */
	char     note[320];         /* ONE line saying what the last load or save found or refused ("" when nothing to say) */
};

void kof_famcat_store_init(struct kof_famcat_store *s);
/* "<family>.c", the family in lower case. */
void kof_famcat_file_name(const char *family, char *out, size_t cap);
/* The text of family `fam`'s file; returns its length (snprintf rule: more than cap - 1 means it did not fit, nothing past cap). */
size_t kof_famcat_family_text(const struct kof_famcat *c, uint32_t fam, char *out, size_t cap);
/* Read one file's text into the catalog: all of it or none (a failure leaves c as it was). `ignored` (may be NULL) gets the number
 * of lines not understood; `why` (may be NULL) the reason on failure. Returns 1 when loaded. */
int kof_famcat_load_text(struct kof_famcat *c, const char *text, size_t len, uint32_t *ignored, const char **why);
/* Empty the catalog and load every `*.c` of `dir` (sorted by name) with load_text; a file that does not load is counted and named
 * in s->note and is remembered by nothing: Save never touches a file it did not load. A directory that does not exist is an empty
 * catalog. */
enum kof_famcat_io kof_famcat_load(struct kof_famcat *c, struct kof_famcat_store *s, const char *dir);
/* Write every family's file into `dir` (created when missing), directly, then remove the files of families that are gone. Refused,
 * with nothing written, when two families would share a file name or a file that was not loaded is in the way. A failure is one line
 * in s->note; the catalog is never changed. */
enum kof_famcat_io kof_famcat_save(const struct kof_famcat *c, struct kof_famcat_store *s, const char *dir);

#endif /* KOF_FAMCAT_H */
