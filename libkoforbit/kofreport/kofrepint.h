/*
 * kofrepint.h - what the three kofreport .c files share and nobody else sees.
 *
 * The report is one object with three jobs - accumulate, collect, present -
 * and they are in three files because they fail for different reasons and
 * because reading one should not mean reading the others. That split needs the
 * structure visible to all three, and this is the smallest way to do it that
 * keeps it out of the public header.
 *
 * NOT INSTALLED AND NOT INCLUDED FROM ANYWHERE ELSE. A host reads a report
 * through kofreport.h, which hands out const pointers to struct
 * kof_fingerprint and nothing that can be written. The moment a tool includes
 * this instead, the tables' ceilings and the arena's lifetime become its
 * business too, and both are promises this library makes rather than facts a
 * caller may rely on.
 */

#ifndef KOFREPINT_H
#define KOFREPINT_H

#include "kofreport.h"

/*
 * kof_evt_content lives in kofevtfmt.h rather than kofevt.h - the accessor for
 * an event that carries CONTENT instead of a path sits with the presentation
 * half, because until now only a printer needed it. A report needs the same
 * bytes for a different reason, and takes them the same way: by LENGTH, never
 * as a string, since a submission may hold NULs.
 */
#include "kofevtfmt.h"

/*
 * AND THE ENGINE, for all three files rather than for the one that scans.
 *
 * kofrepart.c needs it to scan and to hash. The emitters need it too, and the
 * reason is worth stating: a report carries the engine's OWN answers -
 * kof_result.broken, a composed finding name - and presenting them means
 * printing them in the engine's vocabulary. kof_broken_name is that
 * vocabulary, and a second set of words for the same reasons here would be a
 * report that disagrees with the scanner about why a scan stopped.
 *
 * This is the direction the dependency is allowed to run: orbit may know the
 * engine's types, the engine may never know orbit's - koffridge.h states the
 * same rule about itself. The public kofreport.h stays free of it, so a host
 * that only reads a report does not acquire the engine's headers.
 */
#include "kofeng.h"

/*
 * THE CEILINGS.
 *
 * Chosen from what a dropper actually produces rather than from a round
 * number: a noisy installer under trace yields a few hundred distinct files
 * and a couple of thousand distinct registry values, and a sample that
 * produces more than this has told a reader what it is long before the table
 * fills. The memory is a handful of allocations at open - about 1.5MB - which
 * is less than the ring the trace itself holds.
 */
enum {
	KOFREP_FP_MAX   = 4096u,
	KOFREP_PROC_MAX = 1024u,
	KOFREP_SLOTS    = 8192u,   /* a power of two, > 2 * FP_MAX */
	KOFREP_ABLOCK   = 64u * 1024u,

	/* Defaults for struct kof_report_stage's zeros. 32MB per file is
	 * above every dropper stage worth keeping and below the point where
	 * collecting one is a surprise; 16MB of read-back covers a few
	 * thousand appended ranges. */
	KOFREP_MAX_FILE     = 32u * 1024u * 1024u,
	KOFREP_MAX_EVIDENCE = 16u * 1024u * 1024u
};

/*
 * CHUNKED, AND NEVER REALLOCATED, which is the only property that matters.
 *
 * struct kof_fingerprint hands out `const char *` into this arena and those
 * pointers stay valid until the report is closed. One growable buffer would
 * move under them on the next realloc, and the failure is not a crash: it is a
 * report whose earlier strings have become whatever now occupies that address.
 * So blocks are allocated and filled, never moved, and a string too long for a
 * fresh block gets a block of its own.
 */
struct kofrep_ablock {
	struct kofrep_ablock *next;
	size_t                cap, used;
	char                 *p;
};

struct kofrep_arena {
	struct kofrep_ablock *head;
	uint64_t              bytes;
};

const char *kofrep_arena_put(struct kofrep_arena *, const char *, size_t);
const char *kofrep_arena_str(struct kofrep_arena *, const char *);
void        kofrep_arena_free(struct kofrep_arena *);

struct kof_report {
	struct kof_report_info info;      /* strings owned by `arena` */
	struct kofrep_arena    arena;

	struct kof_fingerprint *fp;
	uint32_t                n_fp;
	uint64_t                dropped[KOF_FP_KIND_COUNT];

	/*
	 * Open addressing, linear probing, indices into fp[] biased by one so
	 * that zero means empty. A table rather than a scan because feed is
	 * per event, and a scan would make the report quadratic in the trace -
	 * the same mistake koffridge.h describes about scanning one module two
	 * hundred times.
	 */
	uint32_t               *slot;

	struct kof_rep_proc    *proc;
	uint32_t                n_proc;
	uint64_t                proc_dropped;

	/* Reading order, rebuilt when the set has changed. */
	uint32_t               *order;
	uint32_t                n_order;
	int                     order_stale;

	struct kof_evt_health   health;
	uint64_t                out_of_tree;
	int                     have_health;

	enum kof_rep_end        ended;
	double                  seconds;

	/* First and last event stamp, so a report dates itself from the trace
	 * rather than from the clock of whoever printed it. */
	uint64_t                first_stamp, last_stamp;
	uint64_t                n_events;

	/*
	 * Set by kofrepart.c when the second phase has run, so an emitter can
	 * tell "no digest because nobody looked" from "no digest because the
	 * file was gone". Without it every unfinished report would read as a
	 * run whose artefacts had all vanished.
	 */
	int                     finished;
	int                     had_engine;
	uint64_t                evidence_bytes;
	uint32_t                collected, collect_failed;

	/* The subject's own identity, filled by the finish phase: what the
	 * report is ABOUT, as opposed to what it observed. */
	char                    subject_sha256[65];
	uint64_t                subject_size;
	struct kof_fp_verdict   subject_verdict;
};

/* Make a directory and every level above it. In kofrepart.c with the other
 * filesystem work; shared because a host wants it BEFORE the run - see
 * kof_report_mkpath. */
int kofrep_ensure_dir(const char *path);

/* Find an existing fingerprint, or NULL. The finish phase needs this to hang
 * bytes and verdicts on what the feed phase recorded, and must never create
 * one: a fingerprint that exists only because somebody looked for it is a
 * report of the report. */
struct kof_fingerprint *kofrep_find(struct kof_report *, uint8_t kind,
				    const char *text);

#endif /* KOFREPINT_H */
