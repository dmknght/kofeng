/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
#ifndef KOFENG_DATABASES_TAGSRC_H
#define KOFENG_DATABASES_TAGSRC_H

/*
 * tagsrc.h - the tag sources: what a diagnose is labelled with, read from the
 * files a researcher keeps and written back to them.
 *
 * THE UNIT OF CLASSIFICATION IS THE TAG, and a tag has four parts: a name, its
 * activities (what the code does: network, memory, linux-kernel...), its types
 * (what kind of malware: botnet, trojan...) and a family plus the file
 * attributes it is about (formats, architectures, subtypes). Each activity,
 * type, family and tag is an ENTITY with an id of its own, written in its own
 * file, and a tag names its activities, types and family by ID: renaming one
 * changes a label and nothing that refers to it. No part is ever joined into a
 * string with another ("network/c2" does not exist anywhere).
 *
 * ONE FILE PER ENTITY, `<kind>_<name>_<first 8 hex of id>.c`, in one directory
 * (bases/syndromes by default). They are DATA: nothing compiles them, no pack
 * carries them, and the verdictor and the engine do not read them - the tools
 * do, through this module and through nothing else.
 *
 *     KOF_TAG_ID(0x00000000000002a1);
 *     KOF_TAG_NAME("c2");
 *     KOF_TAG_ACTIVITY(0x0000000000000100);   - network
 *     KOF_TAG_TYPE(0x0000000000000003);       - botnet
 *     KOF_TAG_FAMILY(0x3f9a1c42b7d05e11);     - optional, one
 *     KOF_TAG_FORMAT(KOF_FMT_ELF);            - repeated, the engine's names
 *     KOF_TAG_ARCH(KOF_ARCH_X86_64);
 *     KOF_TAG_SUBTYPE(KOF_ELF_EXEC);
 *     KOF_TAG_COMMENT("...");                 - optional
 *
 * The same shape for KOF_ACTIVITY_*, KOF_TYPE_* and KOF_FAMILY_* with ID, NAME
 * and COMMENT. The KIND OF A FILE IS ITS FIRST DECLARATION - not its name, not
 * the directory it sits in.
 *
 * READ, PRINT AND PATCH ARE THE DIAGNOSE SOURCE'S MACHINERY (diagsrc.h): the
 * file is a list of `struct kof_dsrc_item`, comments are blanked before it is
 * read, a write is the one kof_dsrc_patch_with loop - a line whose declaration
 * is unchanged stays byte for byte, a line this module does not know passes
 * through untouched (a newer tool's declaration survives an older tool's
 * save), and the author's comments are not deleted. What is new here is only
 * what a line says: the printer appends the NAME of every id it writes as a
 * trailing comment for people, and the reader never reads it back.
 *
 * WHAT IS CHECKED IS CHECKED HERE, ONCE, for the viewer and for
 * `ksigbuilder --tags`: kof_tagset_check.
 */

#include <stddef.h>
#include <stdint.h>
#include "diagsrc.h"

#define KOF_TAGSRC_NAME_LEN     KOF_DSRC_NAME_LEN   /* 63 characters */
/* A comment is held in the two strings an item has: 63 + 63 characters. */
#define KOF_TAGSRC_COMMENT_LEN  127u
#define KOF_TAGSRC_REFS         16u    /* activities or types of one tag */
#define KOF_TAGSRC_ATTRS        16u    /* words of one attribute class */
#define KOF_TAGSRC_PATH         512u
/* One entity file: a DoS bound on what is read, and said when it fires. */
#define KOF_TAGSRC_FILE_MAX     (64u * 1024u)
/* Ids below this are the seeds'; a generated id is never in it. */
#define KOF_TAGSRC_ID_SEED_MAX  0x10000u

enum kof_tagsrc_kind {
	KOF_TAGSRC_K_NONE = 0,
	KOF_TAGSRC_K_ACTIVITY,
	KOF_TAGSRC_K_TYPE,
	KOF_TAGSRC_K_FAMILY,
	KOF_TAGSRC_K_TAG,
	KOF_TAGSRC_K_COUNT
};

/* What one declaration says: the `kind` of a kof_dsrc_item of these sources. */
enum kof_tagsrc_what {
	KOF_TAGSRC_W_ID = 32,
	KOF_TAGSRC_W_NAME,
	KOF_TAGSRC_W_COMMENT,
	KOF_TAGSRC_W_ACTIVITY,      /* a tag's: v = the activity's id */
	KOF_TAGSRC_W_TYPE,
	KOF_TAGSRC_W_FAMILY,
	KOF_TAGSRC_W_FORMAT,        /* s1 = the engine's enumerator name */
	KOF_TAGSRC_W_ARCH,
	KOF_TAGSRC_W_SUBTYPE
};

/* The three classes of file attribute, and the vocabulary of each. */
enum kof_tagsrc_attr { KOF_TAGSRC_A_FORMAT = 0, KOF_TAGSRC_A_ARCH,
		       KOF_TAGSRC_A_SUBTYPE, KOF_TAGSRC_A_COUNT };

/* The vocabulary comes out of the engine's own lists (KOF_TARGET_LIST,
 * KOF_ARCH_LIST, KOF_ELF_TYPE_LIST, KOF_PE_IMAGE_LIST, KOF_SCRIPT_TYPE_LIST),
 * so a word the engine adds is a word here and a word it does not have cannot
 * be written. `i` indexes the class; the word is the enumerator as written. */
size_t      kof_tagsrc_vocab_n(unsigned cls);
const char *kof_tagsrc_vocab_word(unsigned cls, size_t i);
int         kof_tagsrc_vocab_find(unsigned cls, const char *word);

const char *kof_tagsrc_kind_word(unsigned kind);   /* "activity", "tag"... */

/*
 * A NAME is lower case [a-z0-9-], 1 to 63 characters. kof_tagsrc_name_norm is
 * what a field applies as it is typed: upper case folded, a space or an
 * underscore written as '-', anything else dropped. Returns the length.
 */
int    kof_tagsrc_name_ok(const char *s);
size_t kof_tagsrc_name_norm(char *dst, size_t cap, const char *src);

/* ---- one entity ------------------------------------------------------- */

struct kof_tagent {
	uint8_t  kind;          /* enum kof_tagsrc_kind */
	uint8_t  dirty;         /* differs from its file, or has no file yet */
	uint8_t  fresh;         /* has no file yet */
	uint8_t  removed;       /* gone from the table; its file goes at save */
	uint64_t id;
	char     name[KOF_TAGSRC_NAME_LEN];
	char     comment[KOF_TAGSRC_COMMENT_LEN];
	/* A tag's own: the ids it names, in the order it declares them. */
	uint64_t act[KOF_TAGSRC_REFS];
	uint64_t typ[KOF_TAGSRC_REFS];
	uint64_t fam;
	uint8_t  n_act, n_typ, has_fam;
	/* Indexes into kof_tagsrc_vocab_word(class, .), declaration order. */
	uint16_t attr[KOF_TAGSRC_A_COUNT][KOF_TAGSRC_ATTRS];
	uint8_t  n_attr[KOF_TAGSRC_A_COUNT];
	/* Filled by kof_tagset_count: tags using an activity, type or family;
	 * diagnose sources naming a tag. */
	uint32_t used;
	char     path[KOF_TAGSRC_PATH];
	char    *text;          /* the file as it was read, owned */
	size_t   text_n;
};

/*
 * THE SOURCE INTO ITS DECLARATIONS, and the declarations into one entity.
 * Both report through kof_dsrc_report (the line, or 0 for the whole file);
 * both return the number of errors, and the entity is meaningful at 0.
 * A declaration of a known kind with a word this module does not know is
 * reported as a WARNING and kept as written when the file is saved.
 */
int kof_tagsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		     const struct kof_dsrc_report *r);
int kof_tagsrc_entity(const struct kof_dsrc *d, struct kof_tagent *e,
		      const struct kof_dsrc_report *r);

struct kof_tagset;

/*
 * The declarations of `e`, in the order a file is written, each carrying the
 * line of the declaration in `old` it says the same as - and a single-valued
 * one (name, comment, family) the line of the one it replaces - so a patch
 * touches only what changed. `old` may be NULL.
 */
void kof_tagsrc_items(const struct kof_tagent *e, const struct kof_dsrc *old,
		      struct kof_dsrc *out);

/* One declaration as a line without its newline, with the trailing comment
 * naming the entities an id refers to. 0 when it cannot be written. */
size_t kof_tagsrc_print(const struct kof_dsrc_item *it,
			const struct kof_tagset *names, char *out, size_t cap);

/* The file text for `e`: patched out of `text` when there is one, or written
 * whole. malloc'd and NUL terminated; NULL on failure or when `text` could not
 * be read. */
char *kof_tagsrc_patch(const char *text, size_t n, const struct kof_tagent *e,
		       const struct kof_tagset *names, size_t *out_n);
char *kof_tagsrc_new(const struct kof_tagent *e, const struct kof_tagset *names,
		     size_t *out_n);

/* `<kind>_<name>_<first 8 hex of the id>.c` */
void kof_tagsrc_file_name(const struct kof_tagent *e, char *out, size_t cap);

/* ---- the directory ---------------------------------------------------- */

/* A file that could not be taken in, and why: kept, so the Check says it. */
struct kof_tagprob {
	char file[96];
	char msg[160];
};

struct kof_tagset {
	struct kof_tagent *e;
	size_t             n, cap;
	struct kof_tagprob *prob;
	size_t             n_prob, cap_prob;
	char               dir[KOF_TAGSRC_PATH];
};

enum { KOF_TAGSRC_INFO = 0, KOF_TAGSRC_WARN = 1, KOF_TAGSRC_ERROR = 2 };

struct kof_tagsrc_report {
	void (*say)(void *ud, int level, const char *subject, const char *msg);
	void *ud;
};

void kof_tagset_init(struct kof_tagset *s);
void kof_tagset_free(struct kof_tagset *s);

/*
 * Every `*.c` file of `dir`, sorted by name, each read once (at most
 * KOF_TAGSRC_FILE_MAX bytes). A file that cannot be an entity goes to the
 * problem list, not to the floor. Returns 0 when the directory cannot be read,
 * 1 otherwise - an empty directory is a set with nothing in it.
 */
int kof_tagset_load(struct kof_tagset *s, const char *dir);

/* The live entity with this id of this kind (kind 0: any), or NULL. */
struct kof_tagent *kof_tagset_find(const struct kof_tagset *s, unsigned kind,
				   uint64_t id);
const char *kof_tagset_name(const struct kof_tagset *s, unsigned kind,
			    uint64_t id);

/*
 * A NEW ID: 64 random bits, not below KOF_TAGSRC_ID_SEED_MAX, not the id of any
 * entity of the set. `gen` supplies the bits (NULL: the operating system's);
 * after 64 collisions it refuses (0) rather than reuse one.
 */
int kof_tagset_new_id(const struct kof_tagset *s,
		      uint64_t (*gen)(void *ud), void *ud, uint64_t *out);

/*
 * Make `proto` an entity of the set: a generated id (the caller's `id` is
 * ignored), the file name made from it - and no file named like it on disk or
 * in the set, so another entity's file is never written over. Returns the
 * entity, or NULL (the reason in `why`, which may be NULL).
 */
struct kof_tagent *kof_tagset_add(struct kof_tagset *s,
				  const struct kof_tagent *proto,
				  uint64_t (*gen)(void *ud), void *ud,
				  const char **why);

/* Mark an entity gone (its file is removed at save); a new one is dropped. */
void kof_tagset_remove(struct kof_tagset *s, struct kof_tagent *e);

/* The names of `n` ids of one kind, joined with ", " (a name that is not there
 * is "?"). The one place a list of activities or types is spelled for a person:
 * a table cell and a Tag cell read the same words. Returns the length written. */
size_t kof_tagset_join(const struct kof_tagset *s, unsigned kind,
		       const uint64_t *ids, uint32_t n, char *out, size_t cap);

/* The entities that name `e` (a tag naming an activity, type or family): the
 * number of them, and their names into `out` when it is not NULL (at most
 * `cap` of them; the count is always the whole). */
size_t kof_tagset_refs(const struct kof_tagset *s, const struct kof_tagent *e,
		       const struct kof_tagent **out, size_t cap);

/* Fill `used`: tags naming each activity, type and family. */
void kof_tagset_count(struct kof_tagset *s);

/* `used` of the tags: diagnose sources under `dir` that name the tag in a
 * KOF_DIAG_TAG(<id>) line. A missing directory counts as none. */
void kof_tagset_count_diagnoses(struct kof_tagset *s, const char *dir);

/*
 * Write what changed and nothing else: each dirty entity through
 * kof_write_file_atomic (a patch of its own text, or the whole file for a new
 * one), each removed entity's file removed. Returns the number of files written
 * or removed, or -1 on the first failure (`why` names it).
 */
int kof_tagset_save(struct kof_tagset *s, char *why, size_t why_cap);

/*
 * THE CHECK. Errors: duplicate id, invalid id, empty name, bad characters, a
 * tag with neither an activity nor a type, a reference to a missing activity,
 * type or family, and every file that could not be read. Warnings: two tags
 * with one meaning (name, activities, types, family) and different ids, an
 * activity, type or family nothing uses, two names of one table one edit
 * apart. Information: tags that share a name, with how their type sets
 * relate (disjoint, overlap, subset, equal). Returns the number of errors.
 */
int kof_tagset_check(struct kof_tagset *s, const struct kof_tagsrc_report *r);

#endif /* KOFENG_DATABASES_TAGSRC_H */
