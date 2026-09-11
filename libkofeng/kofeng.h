/*
 * kofeng.h - the engine, as seen from outside.
 *
 * This is the whole public surface for a host that wants to scan things. Everything
 * else under libkofeng is internal: the parsers, the matcher, the database loader, the
 * per-object routine. A consumer that needs one of those is a consumer this header has
 * failed, and the fix belongs here rather than in an include path.
 *
 * There is a second, separate public surface with a different audience: core/kofmod/
 * is the ABI a signature module is written against. The two never meet - a host does
 * not include kofmod, a module does not include this.
 *
 * Shape:
 *
 *     kof_engine  *eng = kof_engine_open("/var/lib/kofeng/db");
 *     kof_scanner *sc  = kof_scanner_new(eng);          // one per thread
 *
 *     struct kof_result r;
 *     if (kof_scan_path(sc, path, &r) > 0)
 *             for (i = 0; i < r.n; i++) ... r.v[i].name ...
 *
 *     kof_scanner_free(sc);
 *     kof_engine_close(eng);
 *
 * The engine is immutable once open, so one engine serves every thread. That is safe
 * rather than safe-by-convention: module code has no writable data and needs no
 * relocation, so the mapped code is read-only. The mutable and expensive parts - a
 * 32MB presence table, the search memo, the parsed view - belong to the scanner and
 * are allocated per thread and reused across objects.
 */

#ifndef KOFENG_H
#define KOFENG_H

#include <stdint.h>
#include <stddef.h>

/* How strongly a finding is asserted. Mirrors enum kof_level on the module side; a
 * host must not have to include the module ABI to read a result. */
#define KOF_LEVEL_SUSPECT 0
#define KOF_LEVEL_INFECT  1
/*
 * Decided by structure rather than by a signature, and counted apart from both.
 *
 * Its own level and not a kind of SUSPECT, because the two answer differently to
 * an operator: a SUSPECT came from a module that names a family and chose the
 * weaker verdict, while this came from traces that name nothing. Folding them
 * together meant a heuristic could not be measured, tuned or switched off in the
 * report - which is most of what anyone wants to do with one.
 */
#define KOF_LEVEL_HEUR    2

/*
 * WHICH VERDICT IS STRONGER.
 *
 * The numbers above do not say. SUSPECT is 0, INFECT is 1 and HEUR is 2, so
 * comparing the constants gets the order exactly wrong, and every host that
 * needed to pick the worst of several findings worked the order out for itself
 * - the scanner in a switch returning 3/2/1, the viewer in a chain of ifs
 * beside a comment restating the same rule. Two spellings of one fact, neither
 * of them here, where the constants are.
 *
 * Higher is stronger. The values are ranks and nothing else: do not store them,
 * do not send them anywhere, and do not assume the gaps mean anything.
 */
static inline int kof_level_rank(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return 3;
	if (level == KOF_LEVEL_SUSPECT)
		return 2;
	return level == KOF_LEVEL_HEUR ? 1 : 0;
}

/*
 * WHERE ONE OBJECT'S NAME ENDS AND ITS CHILD'S BEGINS.
 *
 * The engine joins a container to what it holds with this, so a result name is
 * "archive.zip//inner.elf" and a payload two layers down carries two of them.
 * It is written in scan.c and it was read - as the bare literal "//" - in the
 * scanner, in the examiner and in the viewer, each with its own loop.
 *
 * The word for what the tools do with it: a file's verdict is the worst of
 * everything under it, so they need the top level name, and a tree needs the
 * depth. Both are here so the separator is spelled once.
 */
#define KOF_OBJ_SEP     "//"
#define KOF_OBJ_SEP_LEN 2u

/* Length of the top-level file's name: everything before the first separator,
 * or the whole name when the object IS the file. */
static inline size_t kof_obj_toplevel_len(const char *name)
{
	const char *p = name;

	while (*p) {
		if (p[0] == '/' && p[1] == '/')
			return (size_t)(p - name);
		p++;
	}
	return (size_t)(p - name);
}

/* How many containers deep: 0 for the file itself. */
/*
 * The LAST segment of an object's name: what this object is, inside its parent.
 *
 * "archive.zip//3:bin/x86" gives "3:bin/x86", and a name with no separator at
 * all gives the whole thing - which is the right answer for the file itself.
 *
 * Here rather than in each tool because a tool that cut at the last '/' instead
 * got it right only while no label contained one: an archive member called
 * bin/x86 came out as "x86", and a name whose separator was missing came out as
 * the file's own basename. Both read as a different object from the one on the
 * row.
 */
static inline const char *kof_obj_leaf(const char *name)
{
	const char *p = name, *last = name;

	while (*p) {
		if (p[0] == KOF_OBJ_SEP[0] && p[1] == KOF_OBJ_SEP[1]) {
			p += KOF_OBJ_SEP_LEN;
			last = p;
			continue;
		}
		p++;
	}
	return last;
}

static inline uint32_t kof_obj_depth(const char *name)
{
	uint32_t n = 0;
	const char *p = name;

	while (*p) {
		if (p[0] == '/' && p[1] == '/') {
			n++;
			p += 2;
		} else {
			p++;
		}
	}
	return n;
}



/*
 * Findings are accumulated, not overwritten: two families can match one object, and
 * keeping only the last silently drops one. Over the cap they are counted, because a
 * truncated list that says nothing about being truncated reads as a complete list.
 */
#define KOF_MAX_FINDINGS 16

/*
 * WHERE ONE PART OF A NAME SITS INSIDE IT.
 *
 * Offsets rather than pointers, because a finding is copied by value all over
 * this tree and a pointer into a struct does not survive that. `n` of 0 means
 * the part is absent; the text is name[at] for n bytes and is NOT terminated
 * there, so print it with "%.*s".
 */
struct kof_name_span {
	uint16_t at, n;
};

struct kof_finding {
	uint32_t level;                  /* KOF_LEVEL_* */

	/*
	 * <target>/<maltype>:<family>#<variant>, composed by the engine - for
	 * example "ELF-x64/Botnet:Mirai#Gen", and for a heuristic
	 * "ELF-x64/Heur:Meterp#g7q2x?Shellcode". The target is not authored, so
	 * a module cannot claim a format it was not run against.
	 */
	char     name[224];

	/*
	 * THE SAME NAME, ALREADY TAKEN APART.
	 *
	 * Because the alternative was every reader taking it apart again. The
	 * scanner walked the string for the '?' and then for the '#' to group
	 * heuristics by shape; the examiner cut at the '/' to compare the rest;
	 * each knew the punctuation the engine had just finished writing. A
	 * separator that changed - and one has, '-' to '#' - broke them
	 * silently, one at a time.
	 *
	 * The engine knows all five parts before it joins them, so it says so.
	 * `shape` is the word after the '?' and only a heuristic has one: it is
	 * what the rule actually recognised, where `family` is only what it
	 * guesses the object is.
	 */
	struct kof_name_span target, maltype, family, variant, shape;
};

/* Non-zero when this finding is a heuristic's - the maltype word is "Heur",
 * which is the engine's and never a module's family. */
static inline int kof_finding_is_heur(const struct kof_finding *f)
{
	return f->maltype.n == 4 &&
	       f->name[f->maltype.at + 0] == 'H' &&
	       f->name[f->maltype.at + 1] == 'e' &&
	       f->name[f->maltype.at + 2] == 'u' &&
	       f->name[f->maltype.at + 3] == 'r';
}

/*
 * "This object did not come from an entry" - the root of a walk, a payload an
 * emulator wrote, anything a container did not describe.
 *
 * Not zero, because zero is a real entry index and the first one at that. Not
 * KOF_NA either: that is UINT64_MAX and this field is 32 bits, so spelling it
 * with the wider constant would truncate to 0xffffffff by accident rather than
 * by decision. One name, stated once, is what stops the two being confused.
 */
#define KOF_ENTRY_NONE 0xffffffffu

struct kof_result {
	struct kof_finding v[KOF_MAX_FINDINGS];
	uint32_t n;
	uint32_t dropped;

	/*
	 * The engine stopped before it had finished with this object, because a
	 * limit ran out - almost always the produced-bytes budget on something
	 * that expands far beyond its own size.
	 *
	 * A separate field and not a level, because it is not a finding: the
	 * verdict is "do not know", and it has to be distinguishable from "clean".
	 * Reporting an exhausted budget as clean is what turns a decompression
	 * bomb from a nuisance into a way of not being scanned.
	 *
	 * The VALUE says why, because the three reasons call for different actions
	 * and a single bit made them one word. A limit is the caller's own setting
	 * and can be raised; an unsupported coding is this engine's gap and a bug
	 * report; a damaged object is the file's own problem and neither of those.
	 * Telling somebody "not fully examined" when the answer is "this build has
	 * no LZMA" wastes their afternoon.
	 */
	uint32_t broken;      /* enum kof_broken, zero when the object was finished */

	/*
	 * HOW MANY MODULES ACTUALLY RAN ON THIS OBJECT.
	 *
	 * Zero means NOTHING EVALUATED IT, and that has to be distinguishable
	 * from "everything applicable evaluated it and found nothing" - for the
	 * same reason `broken` above is a separate field. Both are the verdict
	 * "do not know" arriving by different routes, and both were being
	 * reported as clean.
	 *
	 * It happens: a formatless blob - a payload lifted out of a variable,
	 * a decoder's output, anything with no header - matches no module's
	 * declared target, so the prefilter excludes every one of them and the
	 * object comes back with no findings. Measured on one: 40 modules
	 * considered, 0 ran, all 40 excluded by target. That object reported
	 * exactly as /usr/bin/ls, which had 31 run on it.
	 *
	 * A COUNT and not a flag, because "one module ran" and "thirty-one ran"
	 * are different amounts of confidence in a clean verdict, and a caller
	 * that wants to say so has the number.
	 */
	uint32_t examined;

	/*
	 * WHICH ENTRY OF ITS PARENT THIS OBJECT CAME FROM, or KOF_ENTRY_NONE.
	 *
	 * The link between the two halves of what a parse says about one thing.
	 * ctx->entries describes a stream WHERE IT LIES IN THE FILE - coded,
	 * with its chain and its length; the child is that stream's CONTENT,
	 * which has no offset in the file at all. They are one thing in two
	 * states, and nothing connected them: a host saw a row for the coded
	 * stream and a row for the decoded object and had no way to know they
	 * were the same stream.
	 *
	 * IN THE RESULT AND NOT IN THE NAME. A host learns about a child
	 * through the scan callback, which hands it a name, some bytes and this
	 * - so the result is the only channel that reaches it. Putting the index
	 * in the composed name instead would have changed what every dump
	 * filename and every finding is called, to carry one number.
	 *
	 * Appended rather than inserted, like every other field here: a caller
	 * built against an older header still reads the ones it knows.
	 */
	uint32_t entry_of;

	/*
	 * WHAT THE PRODUCER SAID THIS OBJECT IS - enum kof_entry_kind.
	 *
	 * Beside entry_of because a host needs both and for the same reason:
	 * the FORMAT of decoded content is almost always KOF_FMT_UNKNOWN, so a
	 * host deciding what to offer for an object cannot decide it from the
	 * format alone. "Disassemble" is right for a payload a decoder peeled
	 * out of a stub and wrong for a page description stream, and both
	 * arrive formatless.
	 *
	 * KOF_ENT_UNKNOWN when nothing said, which is the honest default and
	 * is what an unidentified blob genuinely is.
	 */
	uint32_t entry_kind;

	/*
	 * WHAT THE HEURISTIC MADE OF THIS OBJECT, WHETHER OR NOT IT REPORTED.
	 *
	 * Here rather than left to be recomputed, because it was being
	 * recomputed and the copy drifted. kofviewer built its own facts from
	 * what it could see - tree depth, a name it had been handed - and once
	 * the engine learned to tell a packer from a container the two answers
	 * stopped agreeing. A panel that scores an object differently from the
	 * scanner is worse than one that shows nothing: both look authoritative
	 * and only one is.
	 *
	 * So the engine computes it once, on the object it is looking at, with
	 * the facts only it has, and hands the whole of it back. A caller that
	 * wants to explain the number reads the model - kof_heur_default() - for
	 * the words, and never re-derives the evidence.
	 *
	 * `heur_scored` is 0 when the heuristic did not run (switched off) or no
	 * model covers this format, and that is NOT the same as a score of zero.
	 */
	uint8_t  heur_scored;
	uint8_t  heur_depth;        /* executable packer layers above this object */
	/*
	 * Was this object produced BY an executable packer, as opposed to having
	 * been carried by a container. The viewer's own name-matching guess at
	 * this is exactly what this field exists to retire.
	 */
	uint8_t  from_packer;
	int32_t  heur_score;        /* centinats */
	uint32_t heur_flags;        /* KOF_HEUR_FL(KOF_HEUR_F_*) */
	uint64_t heur_anomalies;    /* the format's own anomaly word */
};

/*
 * Why an object was not finished. Ordered by how specific the reason is, which is
 * also the order they take precedence in: the first reason recorded is kept, since
 * whatever stopped things first is what explains the rest.
 */
enum kof_broken {
	KOF_BROKEN_NONE = 0,
	/* A budget, a memory ceiling or a child count ran out. The caller set
	 * these and can set them higher. */
	KOF_BROKEN_LIMIT,
	/* A compression method, packer version or format this build does not
	 * implement. The object is fine; the engine is short of something. */
	KOF_BROKEN_UNSUPPORTED,
	/* The object's own structure does not hold together - a stream that does
	 * not decode, a header that contradicts itself. */
	KOF_BROKEN_DAMAGED,
	/*
	 * The content is encrypted and no key was supplied.
	 *
	 * Its own reason rather than a kind of UNSUPPORTED, because the two lead
	 * somewhere different. UNSUPPORTED is a gap in this build that a later one can
	 * close; this cannot be closed by any amount of work on the engine, and an
	 * operator reading it needs to know that the file will keep coming back the
	 * same way. Every container format that carries encryption reports it with this
	 * value, so a scan says the same thing whether the archive was a zip, a
	 * document, a RAR or a 7z.
	 */
	KOF_BROKEN_ENCRYPTED,

	/*
	 * One past the last, so a caller can size a table of reasons.
	 *
	 * Here because the alternative was a literal, and the literal was wrong the
	 * moment a reason was added: the scanner counted reasons below 4 and printed
	 * reasons below 4, so the first new one was tallied into the total and then
	 * left out of the breakdown - 81 objects broken, 53 accounted for. A count
	 * that does not add up is worse than no count.
	 */
	KOF_BROKEN_COUNT
};

const char *kof_broken_name(uint32_t reason);

/*
 * HOW A DETECTION IS SPELLED, IN ONE PLACE.
 *
 *     kof_name_compose(buf, sizeof buf, "ELF-x64", "Botnet", "Mirai", "Gen")
 *     -> "ELF-x64/Botnet:Mirai#Gen"
 *
 * The engine composes this for every finding, and three other things reproduce
 * it: kofexamine and kofviewer to show a marker row, and kofinspect to decide
 * WHICH module a scan result belongs to. That last one is not display - it is
 * one half of a string comparison whose other half the engine wrote - so a
 * spelling that drifts there does not look wrong, it silently stops matching.
 *
 * It drifted exactly that way: the family/variant separator moved from "-" to
 * "#" in the engine, kofinspect kept the "-", and every detected sample
 * reported "Hit 0, Skip 1" in the viewer and no verdict at all in kofexamine
 * while the scanner called the same file infected.
 *
 * `target` and `variant` may be NULL or empty and are left out when they are.
 */
void kof_name_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant);

/*
 * The same composition, onto a finding, recording where each part landed.
 *
 * This is what the engine itself uses; kof_name_compose above stays for a
 * caller that only wants the string - kofinspect builds one to compare against
 * a result it did not produce.
 *
 * `shape` is the heuristic's, appended after a '?'. NULL or empty for a
 * detector's finding, which has no such thing to admit.
 */
void kof_finding_name(struct kof_finding *f, const char *target,
		      const char *maltype, const char *family,
		      const char *variant, const char *shape);

/*
 * The target word a finding is scoped to: "ELF-x64", or "ELF" when the object
 * has no architecture to speak of.
 *
 * Composed in three places inside the scanner before this, with the same
 * two-line rule about KOF_ARCH_ANY written out each time.
 */
void kof_name_target(char *out, size_t cap, uint8_t format, uint8_t arch);


/*
 * What a scan cost. Exposed because the design rests on a module being cheap for the
 * objects it does not detect, and a number nobody can read is a number nobody keeps
 * honest.
 *
 * `ran` against `considered` is how much the preconditions removed; `bytes_searched`
 * against `object_bytes` is how many times over the content was read.
 */
struct kof_stats {
	uint64_t objects, object_bytes;

	/* Objects the walk reached but could not read. Counted, because the walk is the
	 * engine's now: without this the caller has no way to learn that a file was
	 * skipped, and a scan that silently omits what it could not open reads as a
	 * scan that found nothing there. */
	uint64_t unreadable;

	uint64_t considered, ran;
	uint64_t by_target, by_size, by_arch, by_subtype, by_region;

	uint64_t gram_bytes;             /* cost of building presence sets */
	uint64_t gram_answers;           /* searches answered without scanning */

	/*
	 * WHAT THE BATCHED SWEEP DID, AND WHAT IT COST.
	 *
	 * `multi_bytes` against `bytes_searched` is the whole claim this engine
	 * makes about its own scaling: the first is what a region cost read once
	 * for all of its markers, the second is what was left to read one marker
	 * at a time. A build where the second grows with the database and the
	 * first does not is a build where the sweep stopped working, and there is
	 * no other way to see that from outside.
	 *
	 * `multi_hash4` and `multi_wumanber` say which routine the router picked,
	 * split because they are picked for opposite reasons - short markers and
	 * long ones - and a base drifting from one to the other is worth seeing.
	 */
	uint64_t multi_passes;           /* regions read once for all their markers */
	uint64_t multi_hash4, multi_wumanber;   /* which routine did it */
	uint64_t multi_bytes;            /* bytes those passes walked */
	uint64_t multi_answers;            /* answers written without a search */

	uint64_t searches, bytes_searched;

	/*
	 * The most produced data alive at once, over the whole scan.
	 *
	 * The one number that says whether the memory ceiling actually held. Peak
	 * rather than current, because the interesting question about a bomb is not
	 * where it ended up but how high it got, and reported rather than merely
	 * enforced: a limit nothing can observe is a limit nobody can show works.
	 */
	uint64_t peak_resident;

	/*
	 * How many times a heuristic rule's ask for the emulator was honoured.
	 *
	 * Reported because it is a cost a FILE's contents can choose - a rule
	 * fires on what it finds, and interpreting is the most expensive thing
	 * this engine does. There is a ceiling on it; this is how a reader sees
	 * how close a scan came to it. See KOF_HEUR_WANT in kofmod/heur.h.
	 */
	uint64_t heur_emu;
};

typedef struct kof_engine  kof_engine;
typedef struct kof_scanner kof_scanner;

/*
 * Open a database: a directory of packs, or a single one.
 *
 * NULL if nothing could be loaded.
 */
kof_engine *kof_engine_open(const char *db_path);
void        kof_engine_close(kof_engine *);

/*
 * What the database holds, counted as two numbers because it is two things.
 *
 * A RECORD is one detection: something that names a family and can call an object
 * bad. An UNPACKER opens containers and names nothing. Adding them gives a number
 * that answers no question anybody has - "how much do I detect" is the records,
 * and "what can I see inside" is the unpackers - and a database of ten unpackers
 * and no detections would report ten and find nothing.
 *
 * Neither is the number of literals. That is larger, moves when a signature is
 * rewritten without any signature being added, and is a fact about the engine's
 * internals rather than about the database.
 */
uint32_t    kof_engine_records(const kof_engine *);
uint32_t    kof_engine_unpackers(const kof_engine *);
/* How many heuristic rules the database holds. Its own count because a rule is
 * neither a record nor an unpacker, and a database whose rules were invisible in
 * the banner is one nobody checks the loading of. */
uint32_t    kof_engine_heur_rules(const kof_engine *);

/*
 * WHAT THE MULTI-PATTERN TABLES COST, AND HOW BAD THEIR WORST BUCKET IS.
 *
 * Two numbers this design rests on, and neither is visible from anywhere else.
 *
 * `bytes` is the memory the tables took. It is CHOSEN and not incurred - the
 * bucket counts are derived from the marker count and bounded - and the claim
 * that a base can grow without the matcher's footprint following it is only
 * checkable if the footprint can be read.
 *
 * `max_chain` is the longest bucket in any of them, which is what bounds the
 * worst case: a bucket hit costs one verify per marker on its chain, so a base
 * where many markers share their first four bytes turns a file full of those
 * bytes into a slow scan. Four on the shipping base. Nothing in the engine acts
 * on it yet - a threshold cannot be fitted on a hundred markers - so it is
 * reported rather than enforced, which is the honest state of it.
 *
 * Either pointer may be NULL. Zero-filled and non-zero return when the database
 * has no tables, which is not an error: it means every marker is searched one
 * at a time, as this engine did before 2.0.
 */
int         kof_engine_multimatch(const kof_engine *, uint64_t *bytes,
				  uint32_t *max_chain);

/*
 * WHAT THE LOADED DATABASE ACTUALLY SAYS ABOUT ITSELF.
 *
 * Read out of the packs, not taken from a constant of this build - and the
 * difference is new. While a pack was refused unless its version matched
 * exactly, the loaded value could only be this build's, so a constant was the
 * same answer; the comment here said so. A minor that is accepted when it is
 * LOWER ends that: an engine at 1.7 happily loads a 1.3 database, and reporting
 * 1.7 would be reporting the reader rather than what was read.
 *
 * THE OLDEST OF THE PACKS, because that is the question an operator is asking.
 * A database directory is many files, and it is only as fresh as its stalest
 * part: reporting the newest would hide exactly the pack that needs updating.
 *
 * Zero-filled and non-zero return when there is no database.
 */
/*
 * THE ENGINE'S OWN VERSION, AND IT GATES NOTHING.
 *
 * Worth saying first, because a number in a header invites a comparison. Every
 * compatibility question here is already answered by a field that describes an
 * ARTEFACT: a pack says which layout it has and which module ABI its code was
 * built against, and the loader refuses on those. There is nothing left for an
 * engine version to decide, and a check written against one would be inventing
 * a rule rather than enforcing one.
 *
 * What it is for: the number a person quotes in a bug report, and the line an
 * operator reads to see whether the binary in front of them is the one they
 * think it is.
 *
 * A FUNCTION AND NOT JUST THE MACROS, because the two answer different
 * questions once this is a shared library: the macros say what the caller was
 * COMPILED against, the call says what is actually loaded. When they disagree
 * that is itself the bug being reported.
 */
/*
 * 2.0 - THE SCAN STOPPED BEING ONE SEARCH PER MARKER.
 *
 * A major rather than a minor because the thing an operator quotes in a bug
 * report should change when the scan's shape does, and this one changed: a
 * region is now read once for every marker declared against it, by a routine
 * the build chooses from the marker set. Nothing about the artefacts moved -
 * a pack still says its own layout and module ABI, and those are still what
 * the loader refuses on - so this gates nothing, exactly as the note above
 * says it must not.
 */
#define KOFENG_MAJOR 2u
/*
 * 1 - the database loader and writer changed together.
 *
 * kofpackw stopped page aligning the code section and kofdb stopped expecting
 * it to be, which is a change in this library's own code and so belongs here as
 * well as in KOF_PACK_MINOR. It still gates nothing: a pack says its own layout
 * and that is what the loader refuses on.
 *
 * 2 - the object tree: entries, children and smart deep scan.
 *
 * A capability rather than a layout move, which is what this number is for.
 * What a caller can do that it could not before:
 *
 *   READ WHAT A CONTAINER DECLARES without opening any of it. ctx->entries
 *   publishes one row per thing the parse found - kind, name, coding chain -
 *   so a host can show a document's contents without a decompressor running.
 *
 *   SEPARATE ON DEMAND. heur_off gates opening those rows into objects, so a
 *   caller can look first and descend afterwards, and a region still covers
 *   every byte either way.
 *
 *   HAVE THE ENGINE NOT OPEN WHAT NOTHING WOULD LOOK AT. A producer asks
 *   fmt_wanted and the answer comes from the loaded database, so what a scan
 *   spends follows the rules it was given rather than a list in the engine.
 *
 * THE DATABASE FORMAT DID NOT MOVE, and that is not an oversight. Everything
 * above rides in fields the pack already had - one more bit in a module's
 * heur_want mask, two more values on the format axis - so KOF_PACK_MINOR
 * stays where it is, exactly as the rule beside it in kofpack.h requires:
 * that number moves when the LAYOUT moves and not when the engine grows a
 * capability. A rebuild is needed; a refusal is not.
 */
#define KOFENG_MINOR 2u

/* The Makefile passes the real stamp; this only keeps a stray compilation
 * building, the same way KOF_PACK_BUILD does. */
#ifndef KOFENG_BUILD
#define KOFENG_BUILD 0u
#endif

struct kof_version {
	uint16_t major;
	uint16_t minor;
	uint32_t build;      /* YYYYMMDDHH in UTC, as the database's is */
};

void        kof_engine_version(struct kof_version *);

struct kof_db_version {
	uint16_t major;
	uint16_t minor;
	uint32_t build;      /* YYYYMMDDHH in UTC; 0 when the pack did not say */
	uint32_t machine;    /* enum kof_pack_machine, as the packs were built */
};

int         kof_engine_db_version(const kof_engine *, struct kof_db_version *);

/* One scanner per thread. The engine it is made from must outlive it. */
kof_scanner *kof_scanner_new(const kof_engine *);
void         kof_scanner_free(kof_scanner *);

const struct kof_stats *kof_scanner_stats(const kof_scanner *);

/* Error returns, distinct from a finding count of zero. */
#define KOF_ERR_OPEN (-1)      /* could not be opened, or is not a regular file */
#define KOF_ERR_READ (-2)      /* could not be mapped */
#define KOF_ERR_ARG  (-3)

/*
 * Reported once per object the engine scanned, including ones with no findings.
 *
 * `name` is what the object was reached by - a path for a file, later a member name
 * inside an archive - so one callback covers the whole tree with no special case for
 * the root. Return 0 to carry on, non-zero to abort the walk.
 *
 * A callback rather than one result per call, because an object can yield children: a
 * directory yields files, and an archive will yield members. One result cannot hold a
 * tree, and a caller that had to poll for the next one would be reimplementing the
 * walk it just delegated.
 */
/*
 * Called once per object, including the ones the engine produced itself.
 *
 * `bytes` and `len` are the object as it was scanned, and for a produced object -
 * a decompressed archive entry, an unpacked executable - they are the only place
 * it exists: it was never a file and it is gone once this returns. A host that
 * wants to write out what an unpacker recovered has nothing else to write, which
 * is why they are here rather than left to a second, richer callback that could
 * disagree with this one.
 *
 * The pointer is valid for the duration of the call and no longer. Copy what you
 * mean to keep.
 *
 * Return non-zero to abandon the walk.
 */
typedef int (*kof_on_object)(const char *name, const void *bytes, uint64_t len,
			     const struct kof_result *res, void *user);

/*
 * How a scan is allowed to spread, and how thorough it has to be.
 *
 * Data, and passed per scan rather than set on the engine: a limit is the caller's
 * business, not a property of the database, and two callers in one process must be
 * able to differ.
 *
 * Zeroing the struct gives the conservative answer everywhere - no recursion - so a
 * caller that forgets a field does not get a surprise, it gets less.
 */
/*
 * Values for kof_scan_option.emu_use, and NEVER is the one a memset gives.
 *
 * The other options here default to the useful setting because they cost
 * nothing when they do not apply. This one is different: interpreting an object
 * is the largest thing a scan can do - measured, a UPX-with-LZMA sample needs
 * forty million instructions to reach its payload and the biggest in the corpus
 * needed two hundred and fifty - so a caller gets it by asking, not by omitting
 * a field. kofscanner asks for it at --heur 2.
 */
enum kof_emu_use {
	KOF_EMU_NEVER = 0,  /* interpret nothing, whatever the object looks like */
	KOF_EMU_AUTO  = 1,  /* after every unpacker declined, if the gate fires */
	KOF_EMU_ONLY  = 2   /* interpret instead of the packer modules, ungated */
};

/*
 * The highest heuristic level this build knows.
 *
 * For a caller that means "everything" rather than a particular number -
 * kofexamine and kofviewer both do, because they look at one object somebody
 * is sitting in front of. Named so that adding a level moves this and not
 * every caller, which is what the comment in kofexamine has always said it
 * wanted and could not have until levels existed.
 */
#define KOF_HEUR_LEVEL_MAX 2u

struct kof_scan_option {
	int      recurse_dirs;     /* descend into directories */
	/*
	 * HOW DEEP INTO DIRECTORIES, and that is now all it means.
	 *
	 * It used to mean both: the walk applied it to directory depth AND to
	 * object depth, so a caller asking for three levels of folders also
	 * said "stop unpacking after three layers", and a caller wanting a
	 * flat scan of a deep tree could not say so at all. Two policies on
	 * one number, and neither expressible alone.
	 *
	 * That is the same mistake this file already fixed once, and said so:
	 * see `pdepth` in scan.c, split from `depth` because "conflating them
	 * was the bug". This is the third axis and it gets its own field for
	 * the same reason.
	 */
	uint32_t max_depth;        /* 0 -> a built-in ceiling applies */
	/*
	 * THERE IS NO SEPARATE DEEP-SCAN FLAG. It is heur_off, below.
	 *
	 * There WAS one, and a second switch for it was the mistake: --heur 0
	 * already means "name families and nothing else - gather no facts, score
	 * nothing, produce no evidence that is not a match", and descending into
	 * a file is exactly that kind of evidence. A caller asking for the
	 * cheapest possible pass was therefore asking for both, and two switches
	 * meant they could be set inconsistently - a scan that gathered nothing
	 * and still paid to open every container, or the reverse.
	 *
	 * So: heur 0 does not descend, heur 1 and above do. One question, one
	 * field, and the levels already document what each one is for.
	 *
	 * What NOT descending does not turn off: the parse. A container still
	 * declares what it holds - see ctx->entries - so a caller still learns
	 * that there are twenty-five images inside without paying to open one,
	 * and a region still covers their bytes so a rule can still search them.
	 * Not descending means "do not open", never "do not look".
	 */
	/*
	 * HOW DEEP INTO THE OBJECT TREE, when descending at all.
	 *
	 * Zero means the built-in allowance, which is not a constant: it falls
	 * with the size of the thing being descended into, from 64 layers for
	 * something small to a floor of 4 for anything past 64MB. See
	 * depth_allowance in scan.c for why a floor matters as much as a
	 * ceiling.
	 */
	uint32_t max_object_depth;
	int      follow_symlinks;  /* off is the only safe default: a link into an
				    * ancestor turns a walk into a loop */

	/*
	 * Keep going after the first finding on an object.
	 *
	 * Off by default, which is both the cheap answer and the conservative one:
	 * once an object has been named, running the rest of the database on it buys
	 * a longer list and nothing else. An on-access hook only ever needs to know
	 * whether to block.
	 *
	 * On costs the whole database per infected object and is what a report wants:
	 * an object can belong to two families, and a list that stops at one is a
	 * list that says nothing about the other.
	 *
	 * The trade to know about: with this off, which name is reported depends on
	 * where the matching module happens to sit in the database, because the scan
	 * stops at the first one that fires. Every scanner that stops early has this
	 * property; naming it here is cheaper than rediscovering it from a bug report
	 * about a sample that changed its name after a database update.
	 */
	int      all_matches;

	/*
	 * SCAN THESE BYTES AS THIS FORMAT, skipping the sniff chain.
	 *
	 * Zero - what a memset gives - identifies the object the ordinary way,
	 * from its bytes, and that is right for anything that came off a disk.
	 *
	 * It is not right for everything. A collected event has no magic to
	 * sniff and a submitted script block is not a file format at all, so
	 * both come out unidentified - and an unidentified object is offered to
	 * no module, because format is what the prefilter rules on. The caller
	 * that pulled the record off a channel is the only side that knows what
	 * it is holding, so this is how it says.
	 *
	 * The declared format's parser still runs and may still refuse: being
	 * told is not being right, and a refusal leaves the object unidentified
	 * exactly as a failed sniff would.
	 */
	uint8_t  as_format;

	/*
	 * WHAT THE BYTES DO NOT SAY, for the parser named by as_format.
	 *
	 * as_format says what this object is. This says the part of "what it
	 * is" that is not in the object at all, and there are two of those
	 * already. A collected event carries its submitted content somewhere in
	 * the middle of the record, and only the client that took the record
	 * off the channel knows where. An image read out of a process is a PE
	 * whose sections sit at their VIRTUAL addresses rather than their file
	 * offsets, and only the caller that read it knows that; a PE parsed the
	 * ordinary way would resolve every region to the wrong bytes and match
	 * nothing, quietly.
	 *
	 * Both are already fields of the parser's own view - kof_amsi_view has
	 * obj_off, kof_pe_info has layout - so this is a PREFIX OF THAT VIEW,
	 * copied in before the parse runs. Not a second vocabulary: adding a
	 * declared input to a format means adding a field to its view near the
	 * front, and nothing here changes.
	 *
	 * WHY IT HAD TO EXIST. Before it, the view on the declared path was
	 * zeroed on the first scan and reused unzeroed on every one after, so
	 * an AMSI object's content extent was 0 the first time - OBJDATA
	 * swallowed the metadata and METADATA came back empty - and stale the
	 * rest of the time. The two regions did not partition anything and no
	 * caller could make them.
	 *
	 * Borrowed for the duration of the call. Ignored without as_format, and
	 * ignored - not truncated - if it is longer than the view it is for: a
	 * caller and an engine that disagree about a view's size disagree about
	 * its layout too, and half-copying one would put arbitrary bytes into
	 * fields the parse trusts.
	 */
	const void *as_view;
	uint32_t    as_view_len;

	/*
	 * THE HEURISTIC'S OFF SWITCH, AND WHY IT IS AN OFF SWITCH.
	 *
	 * Zero - the default a memset gives - RUNS the heuristic. It used to be
	 * the other way round and that was wrong: the evidence level 0 scores is
	 * evidence the parse and the unpackers have already produced by the time
	 * this is reached, so having to ask for it meant paying for the facts and
	 * then throwing them away. A caller who wants nothing but named families
	 * sets this, and then nothing is gathered and nothing is scored - the
	 * collector is not entered at all.
	 *
	 * What a heuristic reports is always its own level and never INFECT. It
	 * works from traces that cannot establish identity, only that something
	 * is worth a look, and a verdict that named a family from this evidence
	 * would be claiming more than it measured.
	 */
	uint32_t heur_off;

	/*
	 * WHICH --heur LEVEL THIS SCAN IS, so a rule can be gated to one.
	 *
	 * ZERO MEANS UNSTATED and is read as 1, which is what every rule ran at
	 * before there was a choice. That is deliberate rather than tidy: there
	 * is no initialiser for this struct - callers declare it on the stack
	 * and clear it - so a field whose useful default is 1 arrives as 0, and
	 * treating 0 as "off" would silently disable every heuristic for every
	 * caller that has not been updated.
	 *
	 * Level 0 is not spelled here either; it is heur_off above. A rule
	 * declaring KOF_HEUR_LEVEL higher than this is not entered. See
	 * kofmod/heur.h.
	 */
	uint32_t heur_level;

	/*
	 * WHEN THE INTERPRETER RUNS, and zero is the useful default - like
	 * heur_off above and for a related reason: it costs nothing on an
	 * object it declines.
	 *
	 * It is entered only after every unpacker has declined the object, and
	 * only when the object either hides its code behind something too dense
	 * to be code or carries a header that cannot be loaded as written.
	 * Measured over 1 246 clean binaries - /usr/bin and the unpacked half
	 * of the packed-ELF corpus - that gate selects none of them, so an
	 * ordinary scan never reaches the interpreter at all.
	 *
	 * KOF_EMU_NEVER is for a caller whose answer must not depend on running
	 * anything: the interpreter never executes a guest instruction on the
	 * host, but it is still the largest thing a scan can be asked to do,
	 * and a caller with a hard time bound has a right to refuse it.
	 *
	 * KOF_EMU_ONLY is not a faster AUTO and is not for scanning. It skips
	 * the packer modules and interprets whatever it is given, gate or no
	 * gate, because a person has asked to see what the object does rather
	 * than what a module says about it. Comparing the two answers is the
	 * whole point of having it - a static unpacker and an interpreter
	 * disagreeing about the same file is a finding.
	 */
	uint32_t emu_use;

	/*
	 * The caller said never and means it, so a heuristic rule may not ask
	 * for the emulator on any object.
	 *
	 * A separate flag because emu_use cannot tell the two apart: --heur 1
	 * leaves it NEVER meaning "not on by default", and --emu never leaves it
	 * NEVER meaning "not at all". A rule's ask is exactly the thing that
	 * should turn the first into emulation and must not touch the second.
	 */
	uint32_t emu_forbidden;


	/*
	 * What producing children is allowed to cost.
	 *
	 * Two different limits, because they answer two different questions and
	 * conflating them was a mistake worth recording. One bounds MEMORY AT ANY
	 * INSTANT; the other bounds TOTAL WORK over the whole tree. A single number
	 * cannot do both: made small enough to protect memory it refuses ordinary
	 * archives, and made large enough for those it stops protecting memory.
	 *
	 * max_resident_bytes is the hard one, and the reason this engine exists in
	 * the shape it does. Objects are mapped, not read, so a 12GB scan holds a
	 * few megabytes; producing children is the only path that allocates, and it
	 * must not throw that away. Default 128MB. Counted over everything produced
	 * and still alive - the object being emitted plus every child not yet
	 * scanned - and released as each child is finished with.
	 *
	 * It is counted even for output written to a temporary file. That looks
	 * over-cautious and is not: a temporary directory is very often tmpfs, where
	 * the "spill to disk" is still memory and is additionally capped by a mount
	 * option this engine cannot see.
	 *
	 * max_produced_bytes is the bomb defence: total bytes a whole tree may
	 * yield, not per child. Per-child limits are how a container full of entries
	 * that are each individually reasonable adds up to something that is not.
	 * A single layer of DEFLATE reaches about 1000:1, so a bomb needs no nesting
	 * and a depth limit never sees it. Zero means max(64MB, object size x 64).
	 *
	 * max_object_bytes is the third, and it is the one that decides how much
	 * WORK a scan does rather than how much memory it holds. The other two are
	 * reached only by an object that is trying; this one is reached constantly,
	 * because inflating an entry is the expensive thing a scan does and most
	 * entries are tiny while a few are enormous. Measured over 1352 real zip
	 * entries: median 255 bytes, 95th percentile 92KB, and the handful above
	 * 8MB accounted for 98.2% of every byte decoded.
	 *
	 * Zero means 16MB, which is as low as it goes without losing a detection -
	 * 8MB was measured and drops one, because a UPX packed miner unpacking to
	 * 13MB is a large object rather than a padded one. Raising it buys the tails
	 * of large entries and costs decompression on every archive holding one.
	 *
	 * A child that is a window into its parent costs none of the three: nothing
	 * was produced and nothing is resident that was not already. Those are
	 * bounded by max_children and max_depth.
	 */
	uint64_t max_resident_bytes;
	uint64_t max_produced_bytes;
	uint64_t max_object_bytes;
	uint32_t max_children;     /* 0 -> a built-in ceiling applies */
};

/*
 * Told what a module worked out, as it works it out.
 *
 * `what` is the module's own name for what it worked out and `value` the one
 * number it attached - a version, a count. Called during the module's run, so it
 * arrives before any finding that module goes on to report, which is the order
 * that makes it useful when the finding never comes.
 *
 * Diagnostics, not results: nothing here is a verdict and no scan depends on it.
 * Set it and a debugging tool sees a module's reasoning; leave it unset, which is
 * the default, and modules that emit notes cost a NULL test each.
 */
/*
 * A NOTE, WITH A NUMBER TO MATCH ON RATHER THAN A NAME TO PARSE.
 *
 * `what` is the authored text - "UPX.ELF.version", "Rar.entries" - and is for
 * showing. `fact` is a stable id for the FIELD part of it, the text after the
 * last dot, so a consumer that wants "the version, whoever said it" compares one
 * integer instead of finding a dot and running strcmp.
 *
 * Stable by construction: it is a hash of the field text, so the same field from
 * a later build or a different module is the same id, and a module adding a new
 * field needs no registry and no allocation. Two modules that choose the same
 * field word do collide - which is the same thing that was true when consumers
 * matched on that word, and the module name is right there to tell them apart.
 *
 * Costs nothing to ignore. It exists because the note channel is turning into
 * something a scan path may read per object, and finding a dot in a string per
 * fact per object is the wrong shape for that.
 */
typedef void (*kof_on_debug)(uint32_t fact, const char *what, uint64_t value,
			     void *user);

/*
 * The id for a field name, so a caller can compute the handful it cares about
 * once and then compare integers:
 *
 *     static uint32_t f_version;
 *     if (!f_version) f_version = kof_fact_id("version");
 *     if (fact == f_version) ...
 *
 * Takes the field alone, not the full name - kof_fact_id("version"), not
 * kof_fact_id("UPX.ELF.version").
 */
uint32_t kof_fact_id(const char *field);

void kof_scanner_on_debug(kof_scanner *, kof_on_debug, void *user);

/*
 * Scan whatever `path` names.
 *
 * A file is one object. A directory is a container the engine walks, which is where it
 * belongs: a directory yielding files and an archive yielding members are the same
 * shape, and having the caller do one of them means the walk exists twice.
 *
 * Returns the number of objects scanned, or a KOF_ERR_*. Findings arrive through the
 * callback; zero findings on an object is a result and is still reported.
 */
/*
 * Scan bytes the caller already holds, under a name of its choosing.
 *
 * For a tool that has scanned a file and now wants to ask a different question
 * about ONE object inside it - the viewer runs the interpreter on a node the
 * reader picked, having built the tree with the static unpackers. Re-scanning
 * the file with different options would answer that question about every
 * object rather than the one that was asked about.
 *
 * The bytes are borrowed and must outlive the call. Returns the number of
 * objects scanned, or a KOF_ERR_*.
 */
int kof_scan_bytes(kof_scanner *, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *,
		   kof_on_object, void *user);

int kof_scan_path(kof_scanner *, const char *path, const struct kof_scan_option *,
		  kof_on_object cb, void *user);

/*
 * The same scan, over several scanners at once.
 *
 * WHY IT EXISTS, in one measurement: a scan of 12.9GB spends 71% of its
 * instructions in memmem and keeps exactly one core busy. Nothing in the engine
 * was waiting for a disk - the work is literal search - so the only thing left
 * to give it is more than one core.
 *
 * The caller supplies the scanners, one per thread, because that has always been
 * this API's division: the engine is immutable and shared, a scanner is not. A
 * caller that wants four threads makes four scanners from one engine and hands
 * them in. Nothing here allocates one, so per-worker budgets stay the caller's
 * to set - and they SHOULD be set: max_resident_bytes is per scanner, so four
 * workers with the default may hold four times what one did.
 *
 * `path` a directory: the files under it are spread across the scanners. `path`
 * a file, or n_sc of 1: identical to kof_scan_path, threads and all skipped.
 *
 * The callback is serialised and needs no locking of its own. The ORDER objects
 * arrive in is not preserved - they come back as workers finish - which is the
 * one thing a caller gives up by asking for this.
 *
 * Returns the number of objects scanned, or a KOF_ERR_*.
 */
int kof_scan_path_mt(kof_scanner **, unsigned n_scanners, const char *path,
		     const struct kof_scan_option *, kof_on_object cb, void *user);

#endif /* KOFENG_H */