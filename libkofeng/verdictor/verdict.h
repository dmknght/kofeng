/*
 * verdict.h - how the verdictor spells a detection, and what an object is called.
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
 * HOW A DETECTION IS SPELLED, IN ONE PLACE.
 *
 *     kverdict_compose(buf, sizeof buf, "ELF-x64", "Botnet", "Mirai", "Gen")
 *     -> "ELF-x64/Botnet:Mirai#Gen"
 *
 * The engine composes this for every finding, and three other things reproduce
 * it: kofexaminer and kofviewer to show a marker row, and kofinspect to decide
 * WHICH module a scan result belongs to. That last one is not display - it is
 * one half of a string comparison whose other half the engine wrote - so a
 * spelling that drifts there does not look wrong, it silently stops matching.
 *
 * It drifted exactly that way: the family/variant separator moved from "-" to
 * "#" in the engine, kofinspect kept the "-", and every detected sample
 * reported "Hit 0, Skip 1" in the viewer and no verdict at all in kofexaminer
 * while the scanner called the same file infected.
 *
 * `target` and `variant` may be NULL or empty and are left out when they are.
 */
void kverdict_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant);

/*
 * The same composition, onto a finding, recording where each part landed.
 *
 * This is what the engine itself uses; kverdict_compose above stays for a
 * caller that only wants the string - kofinspect builds one to compare against
 * a result it did not produce.
 *
 * `shape` is the heuristic's, appended after a '!'. NULL or empty for a
 * detector's finding, which has no such thing to admit.
 */
void kverdict_name(struct kof_finding *f, const char *target,
		      const char *maltype, const char *family,
		      const char *variant, const char *shape);

/*
 * GET THE VERDICT NAME: the one place the standard form is written.
 *
 *     <verdict>#<target>-<arch>/<Type>:<Family>.<variant>!<engine>?<reason>
 *
 *     Infected#PE-x86/Virus:Sality.01!Pattern
 *     Heur#PE-x86/Anomalies:WriteExec!Analyzer
 *
 * EVERY FIELD IS OPTIONAL EXCEPT THE TYPE AND THE FAMILY, and an absent one
 * takes its separator with it - a trailing `#` or a bare `?` would read as a
 * field the engine failed to fill rather than one it had nothing to say in.
 *
 * WHY A FUNCTION AND NOT A CONVENTION. The order, the separators and the
 * words were decided in five places in scan.c, each composing the string it
 * needed; a sixth would have decided again. The engine now stores VALUES -
 * see the enums on kof_finding - and this is the only code that knows how
 * they are written down. Change the form here and every reader changes with
 * it, including the ones in other programs.
 *
 * Writes into `f->name` and sets the spans, so a caller that wants a part
 * rather than the line does not search for a separator this just placed.
 */
void kof_verdict_name(struct kof_finding *f, const char *family,
		      const char *variant, const char *reason);

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

/* The syndrome verdict as a finding: "Infected <type>:Agent", the Predict and
 * Ambiguous forms, or Unresolved. Call only when synd->n_query is non-zero. */
void kof_verdict_syndrome(const struct kof_verdict_in *in, struct kof_finding *f);

/*
 * ONE VERDICT PER TOP-LEVEL FILE, rolled up from every object inside it.
 *
 * A packed or carrying file is scanned as a tree - the file, then whatever the
 * unpackers made of it - and the malware is usually in a child, not the root, so
 * the root's own result is not the file's verdict: reporting it as such calls an
 * infected file clean. A file's verdict is the WORST thing found anywhere in its
 * tree, and a host that wants it should not have to work out how objects belong to
 * files (the name up to the first KOF_OBJ_SEP) or which of three levels outranks
 * which (kverdict_level_rank) - both were rewritten by every tool that wanted one.
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

#define KVERDICT_FILE_NAME 224u    /* room for a finding's composed name */
#define KVERDICT_FILE_KIND 48u     /* room for a heuristic's shape or family word */

struct kverdict_file {
	/* The top-level file's name: "a.zip" for the object "a.zip//3:x". Owned by the map. */
	const char *file;
	/* The worst KOF_LEVEL_* any object of the file reported, or -1 for none. Ordered by
	 * kverdict_level_rank - the constants themselves are not in rank order. */
	int         level;
	/* The first KOF_BROKEN_* reason any object of the file reported, or 0. */
	uint32_t    broken;
	/*
	 * Whether ANY module ran on any object of the file. A file every applicable module
	 * cleared and a file nothing was eligible for both have no findings, and are not the
	 * same answer. An OR across the file's objects: a container whose members were
	 * examined has been examined, even if its own bytes matched nothing.
	 */
	int         examined;
	/* The worst finding's composed name, or empty. */
	char        name[KVERDICT_FILE_NAME];
	/* For a heuristic's worst finding: the shape it recognised, or the family when it
	 * offered none ("Shellcode", "Truncated"); empty otherwise. */
	char        kind[KVERDICT_FILE_KIND];
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
 * one (a host that lists every file, clean ones included). An object with a finding, a
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
