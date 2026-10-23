/*
 * kofoption.h - what a scan is asked with: the engine and scanner handles, the
 * callbacks (object, event, debug) and struct kof_scan_option. *
 * A part of <koftypes.h>, which includes it: a host still includes koftypes.h (or
 * kofeng.h) and nothing else. Split from it by purpose; nothing was changed.
 */

#ifndef KOFOPTION_H
#define KOFOPTION_H

#include <stddef.h>
#include <stdint.h>
#include "kofresult.h"

typedef struct kof_engine  kof_engine;
typedef struct kof_scanner kof_scanner;

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
 * A VERDICT WAS REACHED. Called once per verdict, with it already decoded.
 *
 * This exists because the alternative was every host walking the findings
 * array and deciding which entries count - and that decision is the
 * ENGINE'S. A scanner is an interface: it takes what the user asked for and
 * shows what the engine answered. The moment it filters findings it is
 * deciding what a scan reports, and the next tool decides differently.
 *
 * `verdict` is the composed line, through kof_verdict_name, so a host never
 * assembles one and two hosts cannot assemble it differently. `f` is behind
 * it for a host that wants the parts as values rather than as text - the
 * enums on kof_finding - and `object` is where it was found, which is the
 * object's name and not the file's.
 *
 * WHEN IT FIRES. Once per object that has a verdict (kof_result.verdict), with
 * the verdict itself as `f`: its name is composed from the diseases the object
 * has, and `f` carries the ids of the diagnoses that matched and of the diseases
 * (kof_finding.diag, .disease) so the host can walk back from the verdict to what
 * made it. A detector's, rule's or unpacker's finding is evidence: it stays in
 * kof_result for an examiner and never reaches here.
 */
typedef void (*kof_on_event_detected)(const char *object,
				      const char *verdict,
				      const struct kof_finding *f,
				      void *user);

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
 * kofexaminer and kofviewer both do, because they look at one object somebody
 * is sitting in front of. Named so that adding a level moves this and not
 * every caller, which is what the comment in kofexaminer has always said it
 * wanted and could not have until levels existed.
 */
#define KOF_HEUR_LEVEL_MAX 2u

/* The smallest share of a divided resident allowance one scanner is given. */
#define KOF_SHARE_MIN (32ull << 20)

struct kof_scan_option {
	/*
	 * Where a verdict goes when the engine reaches one - see
	 * kof_on_event_detected. NULL for a caller that only wants the results.
	 */
	kof_on_event_detected on_event_detected;
	void                 *event_user;

	/*
	 * WHETHER A SCAN DECIDES TO ANALYSE IS THE DATABASE'S: a diagnose
	 * declares the symbols or the file attributes that make an object worth
	 * the walk, and the engine routes on that declaration. There is no switch
	 * that turns the analysis on for every object, because a switch beside the
	 * declaration was a second way to make one decision, and the one that
	 * could not be measured - it ran the most expensive thing the engine does
	 * on files nothing had recognised.
	 *
	 * report_diag IS A DIFFERENT QUESTION: not "should this object be
	 * analysed" but "tell me what each diagnose made of it", asked by a tool
	 * for the one object a person is looking at. It is not a verdict and it
	 * changes none: the report is built after every verdict is final. See
	 * kof_result.diag.
	 */
	int      report_diag;

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
	/* 0 -> no limit of the engine's own. The walk is still finite: it hands every
	 * directory to opendir by its full path, the kernel refuses a path past PATH_MAX,
	 * and a directory it refuses is counted in kof_stats.unreadable. */
	uint32_t max_depth;
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
	/*
	 * DEPRECATED AND IGNORED. THE ENGINE NEVER FOLLOWS A SYMBOLIC LINK, whatever this
	 * says: the directory walk skips links, and a path that is a link is refused when
	 * it is opened (a symlink-attack defence - a link swapped in for a file between the
	 * walk and the open must not be read - and the end of the loops a link to an
	 * ancestor made). The field stays so that the layout of this struct does not move
	 * for a host built against an earlier header; writing it has no effect.
	 */
	int      follow_symlinks;

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
	 * obj_off, kgenome_pe_info has layout - so this is a PREFIX OF THAT VIEW,
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
	 * of a level higher than this is not entered.
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
	 * The caller said never and means it, so no module or diagnose may ask
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
	uint32_t max_children;     /* 0 -> the root's length over the smallest stored record of any format (5 bytes, a chm entry), at least 4096 */

	/*
	 * ALREADY ANSWERED, AND THE ENGINE NEVER LEARNS WHAT ANSWERED IT.
	 *
	 * A sweep of a machine meets the same files every time, and reading the
	 * whole database against a file that has not changed since the last run
	 * is the work a cache exists to avoid. The walk that meets those files
	 * is in here - see kscan_path, and the note there on why a directory
	 * and an archive are the same shape - so the question has to be asked
	 * from in here too.
	 *
	 * WHAT MUST NOT BE IN HERE IS THE CACHE. Two reasons, and they point
	 * the same way:
	 *
	 *   - THE LAYERING. libkoforbit may know this library's types; this
	 *     library must never know orbit's. An identity is whatever the
	 *     PLATFORM says about a file, and a platform is the thing libkofeng
	 *     is deliberately free of - it takes bytes and says what they are.
	 *
	 *   - THE TRUST. Whoever can write a cache decides what this scanner
	 *     calls clean. That is a policy about a machine, and it belongs to
	 *     the tool that was configured for that machine rather than to an
	 *     engine that is the same everywhere.
	 *
	 * So the engine says three things through pointers and is told nothing
	 * else: `seen` before opening a file, `keep` after finding it clean,
	 * `drop` after finding it not. The key is opaque bytes; the engine does
	 * not compute it, read it, or know what it is made of.
	 *
	 * WHY `drop` EXISTS, WHICH IS NOT SYMMETRY WITH `keep`.
	 *
	 * A finding on a file that a cache elsewhere calls clean is the one
	 * piece of news a cache must not miss. It arrives whenever the scan
	 * that found it did not consult that cache - a run told not to trust it
	 * on a machine somebody else has been on, or one under a database whose
	 * answers the stored ones predate. Without this the deep run reports the
	 * detection, the stale entry survives it, and the NEXT ordinary run
	 * skips the file in silence.
	 *
	 * IN A PARALLEL WALK these are called from the worker threads, several at
	 * once, and unlike the object callback they are NOT serialised: a host
	 * whose cache is not safe to share has to lock it itself.
	 *
	 * All NULL - the default - and nothing is cached and nothing is asked.
	 */
	int  (*cache_seen)(void *user, const char *path);
	void (*cache_keep)(void *user, const char *path);
	void (*cache_drop)(void *user, const char *path);
	void  *cache_user;

	/*
	 * ASKED, OFTEN, WHETHER TO GIVE UP. Non-zero means stop.
	 *
	 * The callback already lets a host abandon a walk - "Return non-zero to
	 * abandon the walk" - and for a directory of ordinary files that is
	 * enough, because the callback runs once per object and an object is
	 * quick. It is not enough for the object that is slow: a caller which
	 * asked to stop waits for the CURRENT object to finish first, and
	 * measured on /usr/lib that was 150 to 456 milliseconds, bounded by
	 * whatever the largest shared object in the tree happens to cost.
	 *
	 * So this is asked INSIDE an object as well - between modules, and
	 * between the children an unpacker produced - where the callback
	 * cannot reach. The engine stops at the next one of those rather than
	 * at the next object.
	 *
	 * IT MUST BE CHEAP AND IT MUST NOT BLOCK. It is called on a hot path
	 * and may be called from several threads at once; reading a flag is
	 * what it is for. It must not print, allocate or take a lock that the
	 * caller's own callback also takes.
	 *
	 * AN OBJECT STOPPED THIS WAY is reported with what it had found so far, and
	 * is never offered to cache_keep - it was not fully examined, and a cache
	 * that remembered it as clean would skip the file for good.
	 *
	 * NULL - the default - is never asked, and nothing changes for a host
	 * that does not want this.
	 */
	int  (*should_stop)(void *user);
	void  *stop_user;

	/*
	 * APPENDED (memory work): both zero in a caller that predates them.
	 *
	 * HOW max_resident_bytes IS SHARED OUT. Every scanner of a parallel walk
	 * (kscan_path_mt) holds its own heap, so one allowance given to each of N
	 * workers bounds nothing: N workers were measured at 822 MB against 89 MB for
	 * one, with the same allowance. Left at zero, the allowance - the one given, or
	 * the built-in 128 MiB when none was - is therefore the ceiling of the WHOLE
	 * walk and each worker's share is allowance / workers, but never below
	 * KOF_SHARE_MIN (32 MiB): a share smaller than that cannot unpack an ordinary
	 * object, so a walk with so many workers that the floor binds holds
	 * workers x 32 MiB. A host that has already worked out what each of its
	 * scanners may hold (or that scans with kscan_path / kscan_bytes on threads of
	 * its own, where nothing is divided) sets this non-zero, and
	 * max_resident_bytes is then taken per scanner exactly as given.
	 */
	uint32_t resident_per_scanner;
	/*
	 * WHERE AN OBJECT TOO BIG FOR MEMORY IS SPILLED: a directory the host
	 * chooses, tried before the platform's own (kof_tmpdir, which is /tmp on
	 * POSIX and so is very often a RAM filesystem). The engine reads no
	 * environment, so this is the one way a host puts the spill somewhere that is
	 * disk. The bytes spilled are still counted against max_resident_bytes: a
	 * spill is not a promise that the place is not memory. NULL - the default -
	 * is the platform's directory. The string must stay valid for the scan.
	 */
	const char *scratch_dir;
	/*
	 * APPENDED: HOW MANY INSTRUCTIONS THE INTERPRETER MAY EXECUTE FOR ONE WHOLE TREE (a
	 * top-level object and everything under it), the unpack runs, the heuristic runs and
	 * the diagnose scan's emulations together. Zero - the default - derives it from the
	 * ROOT object's size alone (64 Mi instructions plus 512 per byte of the root, at most
	 * 4 Gi): what a child holds was produced from the root, so its size buys no time, and
	 * an archive of a thousand tiny programs that spin costs what its one file may, not a
	 * thousand per-object floors. What a run is denied is said (the object reads
	 * KOF_BROKEN_LIMIT, kof_stats.limit_hits and emu_budget_denied move).
	 */
	uint64_t max_emu_insn;
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

#endif /* KOFOPTION_H */
