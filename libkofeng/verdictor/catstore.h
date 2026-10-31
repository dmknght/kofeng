/*
 * catstore.h - what the two catalogs (famcat.h: Manage > Pathogens, tagcat.h: Manage > Syndromes) share on disk: the function that
 * makes the id of an item and the directory of source files they are kept in. One implementation, so the two cannot drift: the
 * catalogs supply only what differs (which file an item lives in, the text of a file, what a line means).
 *
 * IDS ARE MADE FROM NAMES, WHEN THEY ARE NEEDED, AND ARE STORED NOWHERE. A source file of a catalog (and of a diagnose) holds names
 * and nothing else; the pack's catalog section holds the id the BUILD made. The id is kof_catid_of: a 64-bit hash of a key that
 * carries its kind, the lower-cased name and, for a variant, the lower-cased family and letters:
 *     family   "F:" name                 "F:mirai"
 *     variant  "V:" family "." letters   "V:mirai.a"
 *     tag      "T:" name                 "T:mirai-flood"
 * so the id is the same on every machine, in every build and whatever the order of the files, and one spelling in any letter case (a
 * name is one name in any case: the catalogs' uniqueness rule). A rename is a new id; the pack and the host's catalog are both made
 * from the sources, so they agree again at the next build. An id below KOF_CATID_SEED_MAX (reserved for the seeds) is moved out of it
 * by one fixed rule (kof_catid_of). Two names that make one id (a collision, 2^-64 a pair) are refused by the catalog that is asked
 * to hold them, which names the other (KOF_FAMCAT_ID_CLASH, KOF_TAGCAT_ID_CLASH); the hash is a parameter of a catalog only so a
 * test can force that. Nothing here reads the environment or keeps writable global state.
 *
 * Source files that still carry the old id lines (KOF_MALWARE_FAMILY_ID, KOF_MALWARE_VARIANT_ID, KOF_TAG_ID) are read: the lines are
 * counted as ignored and the next Save writes the file without them.
 *
 * DIRECTORY. A catalog is kept as a set of "*.c" files in one directory, DATA that is never compiled, read line by line. Load reads
 * every file (sorted by name) through the catalog's own text reader; Save writes the catalog's files and removes the files of items
 * that are gone, and never touches a file it did not load. The numbers named below bound the work done on a hostile directory.
 */
#ifndef KOF_CATSTORE_H
#define KOF_CATSTORE_H

#include <stddef.h>
#include <stdint.h>

/* ---- ids -------------------------------------------------------------------------------------------------------------- */

#define KOF_CATID_SEED_MAX 0x10000u   /* ids below this are reserved; an id kof_catid_of makes is never in it */

/* The hash of a key (a test passes its own to force a collision); NULL means kof_catid_hash. */
typedef uint64_t (*kof_catid_hash_fn)(void *ud, const char *key, size_t len);
uint64_t kof_catid_hash(void *ud, const char *key, size_t len);

/* Is `id` one a catalog may hold: not 0 and not a seed. */
int kof_catid_valid(uint64_t id);

/* THE ONE FUNCTION: the id of the item of `kind` ('F' family, 'V' variant, 'T' tag) named `a` (a variant: family `a`, letters `b`; else
 * b is NULL). 0 when a name is empty or NULL, a variant has no letters, another kind has some, or the key does not fit. Letter case is folded here, once. */
uint64_t kof_catid_of(kof_catid_hash_fn fn, void *ud, char kind, const char *a, const char *b);
#define kof_catid_family(name)            kof_catid_of(NULL, NULL, 'F', (name), NULL)
#define kof_catid_variant(family, letters) kof_catid_of(NULL, NULL, 'V', (family), (letters))
#define kof_catid_tag(name)               kof_catid_of(NULL, NULL, 'T', (name), NULL)

/* ---- the text of a file ----------------------------------------------------------------------------------------------- */

/* A string literal at p ("name", no escapes) copied without the quotes into out[cap]; the pointer past the closing quote, or NULL. */
const char *kof_catfmt_lit(const char *p, char *out, size_t cap);
const char *kof_catfmt_skip(const char *p);
/* `t` must start with the keyword and then "(" ; the text after the "(" (blanks skipped), or NULL when the line is not that keyword's. */
const char *kof_catfmt_after(const char *t, const char *kw);
/* The end of a call: ");" and nothing after. */
int kof_catfmt_call_end(const char *p);
/* An identifier of capital letters, digits and '_' at p copied into out[cap]; the pointer past it (out empty when there is none). */
const char *kof_catfmt_ident(const char *p, char *out, size_t cap);

/* ---- the comment above an item ------------------------------------------------------------------------------------------- */

/* The longest comment of an item of either catalog (a variant's, a tag's): a bound on what a person types into a dialog row (a table
 * column scrolls sideways), chosen to keep one source line readable. The character rule is the engine's kof_comment_char. ONE constant
 * for both, so the two catalogs cannot drift (KOF_FAMCAT_COMMENT_MAX and KOF_TAGCAT_COMMENT_MAX are this). */
#define KOF_CATSTORE_COMMENT_MAX 120

enum kof_catcomment { KOF_CATCOMMENT_OK = 0, KOF_CATCOMMENT_BAD_CHAR, KOF_CATCOMMENT_TOO_LONG };
/* The comment rule: empty (or NULL) is fine, kof_comment_char on every character, at most KOF_CATSTORE_COMMENT_MAX characters. */
enum kof_catcomment kof_catcomment_check(const char *comment);
/* The one line a dialog shows for a refusal of the comment rule ("" for OK); both catalogs' status texts and the dialogs' Comment fields
 * say it through this. */
const char *kof_catcomment_text(enum kof_catcomment st);

/* The comment lines read directly above an item, joined with one blank. Both catalogs keep an item's comment as `// text` lines right
 * above the item's first line, and read it back through this. One byte over the limit is kept so the catalog's own check can say "too
 * long" instead of the reader cutting it silently. */
struct kof_catpend {
	char   text[KOF_CATSTORE_COMMENT_MAX + 2u];
	size_t len;
};
void kof_catpend_clear(struct kof_catpend *p);
/* `t` is a trimmed line. When it starts with "//" its text (one blank after the slashes dropped) is added and 1 is returned, else 0. An
 * empty comment line adds nothing (a joining blank would not survive the next read). */
int kof_catpend_line(struct kof_catpend *p, const char *t);

#define KOF_CATSTORE_FILE_MAX     (256u * 1024u)  /* a file larger than this is not read (a family of 256 variants is about 100 KB) */
#define KOF_CATSTORE_LINE_MAX     1024u           /* a longer line makes its file unreadable (the longest line written is under 400) */
#define KOF_CATSTORE_FILES_MAX    256u            /* the files a directory may hold for the store to know them */
#define KOF_CATSTORE_FILENAME_MAX 255u            /* the longest file name (the file system's own limit) */

/* One trimmed, NUL-terminated line, or NULL when the line holds a NUL (not text). A blank line arrives as "". Answer 0 understood,
 * 1 not understood (counted in `ignored`), -1 breaks a rule and *why says which. */
typedef int (*kof_catfmt_line)(void *user, char *line, const char **why);
/* Split text[len] into lines and give each to `fn`; stops at the first -1 (then *why is its reason, or "line too long"). The number of
 * lines answered 1 is *ignored (may be NULL). Returns 1 when every line was taken. */
int kof_catfmt_lines(const char *text, size_t len, kof_catfmt_line fn, void *user, uint32_t *ignored, const char **why);

enum kof_catstore_io {
	KOF_CATSTORE_IO_OK = 0,
	KOF_CATSTORE_IO_NO_DIR,       /* the host named no directory */
	KOF_CATSTORE_IO_COLLISION,    /* two items would share a file, or a file that was not loaded is in the way */
	KOF_CATSTORE_IO_FAIL          /* a directory or file could not be read, created, written or removed */
};

/* What the directory held when it was last loaded or saved: the files Save may rewrite and remove, and the line the host shows. */
struct kof_catstore {
	uint32_t n_file;
	char     file[KOF_CATSTORE_FILES_MAX][KOF_CATSTORE_FILENAME_MAX + 1u];
	uint32_t n_bad;             /* the last load: files not loaded */
	uint32_t n_ignored;         /* the last load: lines of loaded files that were not understood */
	char     note[320];         /* ONE line saying what the last load or save found or refused ("" when nothing to say) */
};

void kof_catstore_init(struct kof_catstore *s);

/* What a catalog gives Load: its text reader (all of a file or none; 1 when loaded) and the words of the no-directory note. */
struct kof_catstore_in {
	void       *user;
	int       (*load)(void *user, const char *text, size_t len, uint32_t *ignored, const char **why);
	const char *what;           /* "pathogens" */
	const char *option;         /* "--pathogens" */
};
/* Read every `*.c` of `dir` (sorted by name) through in->load. A file that does not load is counted and named in s->note and is
 * remembered by nothing. A directory that does not exist is an empty catalog (OK). The caller empties its catalog first. */
enum kof_catstore_io kof_catstore_load(struct kof_catstore *s, const char *dir, const struct kof_catstore_in *in);

/* How much a directory holds: the number of `*.c` files (kof_catstore_load reads the first KOF_CATSTORE_FILES_MAX of them by name and says
 * how many it left) and their bytes (each at most KOF_CATSTORE_FILE_MAX, the size past which a file is not read), so a reader that must
 * size a table first can bound what it will be asked to hold. A directory that does not exist is OK with 0 and 0; one that cannot be read is FAIL. */
enum kof_catstore_io kof_catstore_dir_size(const char *dir, uint64_t *bytes, uint32_t *files);

/* What a catalog gives Save: n files, the name of file i and its text (snprintf rule: a length of cap or more means it did not fit). */
struct kof_catstore_out {
	void       *user;
	uint32_t    n;
	void      (*name)(void *user, uint32_t i, char *out, size_t cap);
	size_t    (*text)(void *user, uint32_t i, char *out, size_t cap);
	const char *what;
	const char *option;
};
/* Write every file into `dir` (created when missing), directly, then remove the files that are gone. Refused, with nothing written,
 * when two files would share a name or a file that was not loaded is in the way. A failure is one line in s->note. */
enum kof_catstore_io kof_catstore_save(struct kof_catstore *s, const char *dir, const struct kof_catstore_out *o);

#endif /* KOF_CATSTORE_H */
