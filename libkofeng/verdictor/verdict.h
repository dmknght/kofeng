/*
 * verdict.h - how the verdictor spells a verdict, and what an object is called.
 *
 * The functions of verdictor/: the one place the standard name form
 * is written (kofeng.h includes this, so a host still needs only <kofeng.h>).
 * They were declared in koftypes.h, which is core and so below the verdictor
 * that defines them - a declaration the include-direction check cannot see.
 * The types they take (struct kof_finding, struct kof_verdict_in) stay in
 * koftypes.h, where every layer that fills them can reach them.
 */

#ifndef KOFENG_VERDICT_H
#define KOFENG_VERDICT_H

#include <stdint.h>
#include <stddef.h>

#include <koftypes.h>

/*
 * GET THE VERDICT NAME: the one place the standard form is written.
 *
 *     <verdict>#<target>-<arch>/<Type>:<behaviour>!<engine>?<reason>
 *
 * (the word is kof_verdict_word of the finding's verdict; the behaviour is the lead
 * disease's path with '.' for '/'; the engine word is there only when a diagnose
 * matched.)
 *
 * EVERY FIELD IS OPTIONAL EXCEPT THE TYPE AND THE BEHAVIOUR, and an absent one
 * takes its separator with it - a trailing `?` would read as a field the engine
 * failed to fill rather than one it had nothing to say in.
 *
 * WHY A FUNCTION AND NOT A CONVENTION. The order, the separators and the words were
 * once decided in five places, each composing the string it needed. The engine now
 * stores VALUES - see the enums on kof_finding - and this is the only code that knows
 * how they are written down. Change the form here and every reader changes with it,
 * including the ones in other programs.
 *
 * Writes into `f->name` and sets the spans, so a caller that wants a part
 * rather than the line does not search for a separator this just placed.
 */
void kof_verdict_name(struct kof_finding *f, const char *family,
		      const char *reason);

/*
 * WHAT TO CALL AN OBJECT, from the state the engine holds about it.
 *
 * One answer, crafted here, so a tool shows it and does not compose it:
 *
 *   "Unwrap:Gzip?Deflate"  the module that opened it, when one did - what the
 *                          engine said in kof_result.packer_build
 *   "Norm"                 a normalised view of another object
 *   "PHP"                  a script, by its language
 *   "PE", "ELF"            anything else, by the name of its format
 *
 * `packer` may be NULL or empty. `subtype` is the format's own vocabulary and
 * is read only for a script. Cut at `cap`, never past it.
 */
void kof_object_label(uint32_t entry_kind, const char *packer, uint8_t format,
		      uint8_t subtype, char *out, size_t cap);

/*
 * The target word a finding is scoped to: "ELF-x64", or "ELF" when the object
 * has no architecture to speak of.
 *
 * Composed in three places inside the scanner before this, with the same
 * two-line rule about KGENOME_ARCH_ANY written out each time.
 */
void kverdict_target(char *out, size_t cap, uint8_t format, uint8_t arch);

/*
 * THE OBJECT'S VERDICT, from the diseases it has: "<Type>:<behaviour>[?<types>]" as
 * a finding that also carries the ids of the diagnoses that matched and of the
 * diseases (kof_finding.diag, .disease). Call only with in->n_dis non-zero. The rule
 * is written where the function is, and in CLAUDE.md.
 */
void kof_verdict_make(const struct kof_verdict_in *in, struct kof_finding *f);

/*
 * ONE VERDICT PER TOP-LEVEL FILE, rolled up from every object inside it.
 *
 * A packed or carrying file is scanned as a tree - the file, then whatever the
 * unpackers made of it - and the malware is usually in a child, not the root, so
 * the root's own result is not the file's verdict: reporting it as such calls an
 * infected file clean. A file's verdict is the first verdict made anywhere in its
 * tree (kof_result.verdict; the walk is parent first), and a host that wants it
 * should not have to work out how objects belong to files (the name up to the
 * first KOF_OBJ_SEP). Evidence (kof_result.v) is not read: it is not a verdict.
 *
 * Fed one object at a time, from the on-object callback:
 *
 *     kverdict_filemap *m = kverdict_filemap_new();
 *     ... in the callback:   kverdict_filemap_fold(m, name, res, 0);
 *     ... afterwards:        for (i = 0; i < kverdict_filemap_count(m); i++)
 *                                 use(kverdict_filemap_at(m, i));
 *     kverdict_filemap_free(m);
 *
 * One map belongs to one caller; it is not thread safe, and the engine's callback is
 * serialised even under kscan_path_mt, so a host that folds from the callback needs no
 * lock. Objects of two files may interleave (a parallel walk), which is why this is a
 * map keyed by the file and not a running "current file".
 */
typedef struct kverdict_filemap kverdict_filemap;

#define KVERDICT_FILE_NAME 224u    /* room for a verdict's composed name */

struct kverdict_file {
	/* The top-level file's name: "a.zip" for the object "a.zip//3:x". Owned by the map. */
	const char *file;
	/* 1 when any object of the file had a verdict. */
	int         has_verdict;
	/* The first KOF_BROKEN_* reason any object of the file reported, or 0. */
	uint32_t    broken;
	/*
	 * Whether ANY module ran on any object of the file. A file every applicable module
	 * cleared and a file nothing was eligible for both have no verdict, and are not the
	 * same answer. An OR across the file's objects: a container whose members were
	 * examined has been examined, even if its own bytes matched nothing.
	 */
	int         examined;
	/* The verdict's composed name, or empty. */
	char        name[KVERDICT_FILE_NAME];
	/* The caller's own bookkeeping, zero when the entry is made. The engine never reads
	 * or writes it. */
	int         host;
};

kverdict_filemap *kverdict_filemap_new(void);
void              kverdict_filemap_free(kverdict_filemap *);

/*
 * FOLD ONE OBJECT'S RESULT into the verdict of the file it belongs to.
 *
 * `object` is the name the callback was given, `res` what it was given. Returns the
 * file's entry, or NULL when the object left none: an object that is clean and was
 * examined has nothing to roll up, so it touches no entry unless `keep_clean` asks for
 * one (a host that lists every file, clean ones included). An object with a verdict, a
 * broken reason or no module eligible for it always gets one - it is not clean - and
 * NULL is also what an allocation failure returns.
 *
 * Also counts the file: an object whose name carries no KOF_OBJ_SEP is a root, and each
 * root is one file (kverdict_filemap_files).
 */
struct kverdict_file *kverdict_filemap_fold(kverdict_filemap *, const char *object,
					    const struct kof_result *res,
					    int keep_clean);

/* An entry by its file name (`flen` bytes, not NUL terminated), or NULL when there is none. */
struct kverdict_file *kverdict_filemap_find(kverdict_filemap *, const char *file,
					    size_t flen);

/* How many entries there are, and the i-th in the order they were first made. */
size_t                kverdict_filemap_count(const kverdict_filemap *);
struct kverdict_file *kverdict_filemap_at(kverdict_filemap *, size_t i);

/* How many top-level files were folded, clean ones included. */
uint64_t              kverdict_filemap_files(const kverdict_filemap *);

#endif /* KOFENG_VERDICT_H */
