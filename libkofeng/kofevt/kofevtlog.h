/*
 * wtrace.h - writing a collected stream to a file, and reading it back.
 *
 * WHY THIS EXISTS AND WHY IT IS THE FILE EVERYTHING ELSE WAITED FOR
 *
 * kofgrille.h has said from the first commit that the record is normalised
 * rather than handed out as an EVENT_RECORD because "a fixed record can be
 * WRITTEN TO A FILE AND REPLAYED - that is what makes any of this testable: a
 * detection rule that cannot be run against a recorded trace cannot be
 * regression tested, and a false positive nobody can reproduce cannot be
 * fixed." It said that, and there was no writer. This is it.
 *
 * Three things follow from it and none is optional:
 *
 *   - A rule engine over events can be tested at all. Without a recording,
 *     every rule is validated by running a live sample on a live machine and
 *     hoping the same thing happens twice, on a stream that is explicitly
 *     documented as arriving out of order.
 *   - The Linux CI can run that engine. Nothing here touches ETW or Windows,
 *     so a trace recorded on Windows replays on a host with neither.
 *   - A trace becomes evidence somebody else can open. That is the half
 *     kofviewer would read.
 *
 *
 * THE FORMAT, AND WHAT IT REFUSES
 *
 *   [ struct kofw_trace_hdr ]  [ struct kofw_evt ] [ struct kofw_evt ] ...
 *
 * Fixed records, no index, no compression. A reader can seek to record N by
 * multiplying, a writer can append without rewriting anything, and a file
 * truncated by a crash loses its last record and not the ones before it -
 * which for a trace of something that crashed the machine is the case that
 * matters.
 *
 * The header carries `rec_size` AND `rec_kind`, and a reader REFUSES a file
 * that does not match both rather than reading it anyway. Size alone does not
 * identify a record - two collectors can easily produce different 512-byte
 * records, and reading one as the other is the failure this pair exists to
 * make impossible. That is the whole safety
 * argument of the format: struct kofw_evt is going to grow - it grew twice
 * while this library was being written - and a reader that trusted the layout
 * without checking would decode every field from the wrong offset and produce
 * a trace that looks completely plausible and is entirely wrong.
 *
 * LITTLE-ENDIAN ONLY, stated rather than handled. Both platforms this collects
 * from are little-endian, a byte-swapping reader would be code nothing runs,
 * and the header records the fact so that a big-endian reader can refuse
 * instead of quietly transposing every pid.
 */

#ifndef KOFEVT_LOG_H
#define KOFEVT_LOG_H

#include <stdio.h>
#include <stdint.h>

#include "kofevt.h"

/*
 * NO RECORD TYPE IS INCLUDED HERE, ON PURPOSE.
 *
 * This file used to include kofgrille.h and write struct kofw_evt, which made
 * it the Windows collector's log format wearing a neutral name. It now writes
 * FIXED-SIZE OPAQUE RECORDS whose size and kind the caller declares, so:
 *
 *   - libkofgrille records struct kofw_evt today,
 *   - a Linux collector records its own,
 *   - and when the neutral struct kof_evt in kofevt.h is implemented, the same
 *     code records that without being touched.
 *
 * It is also what lets this live under libkofeng without dragging the engine
 * into libkofgrille: stdio and stdint, and nothing else.
 */

/* "KOFT" - and it is checked before anything else is believed. */
#define KOFEVT_LOG_MAGIC 0x54464f4bu

/*
 * WHICH record the file holds. Size is not identity: two collectors can
 * produce different records of the same length, and a reader that checked only
 * the length would decode one as the other and be completely wrong while
 * looking completely plausible.
 */
enum kofevt_rec_kind {
	KOFEVT_REC_NONE  = 0,
	KOFEVT_REC_KOFW  = 1,   /* struct kofw_evt, the Windows collector's */
	KOFEVT_REC_KOF   = 2    /* struct kof_evt, the neutral one - kofevt.h */
};

/*
 * Bumped when the meaning of an existing field changes; `rec_size` already
 * covers the record growing, which is the common case and must not need a
 * version bump - otherwise every added field orphans every recorded trace.
 */
/*
 * 2 - records became variable length. A v1 file is fixed-size records and this
 * build does not read one; nothing has shipped, so there is nothing to keep
 * compatible with, and a reader that guessed would read every field of every
 * record from the wrong offset.
 */
#define KOFEVT_LOG_VERSION 2u

#define KOFEVT_LOG_HDR_SIZE 64u

struct kofevt_log_hdr {
	uint32_t magic;        /* KOFEVT_LOG_MAGIC */
	uint16_t version;      /* KOFEVT_LOG_VERSION */
	uint16_t hdr_size;     /* this header; a reader skips to it, not past a
				* constant it compiled in */
	uint32_t rec_size;     /* size of the record THAT WROTE THIS */
	uint32_t build;        /* the collector's build stamp */

	/* When the session started, in the same units the records' own stamps
	 * use, so a reader can turn a relative trace into wall clock. */
	uint64_t started;

	uint32_t sub_asked;    /* KOFW_SUB_* the run requested */
	uint32_t sub_enabled;  /* what the providers actually accepted - a trace
				* is incomplete in a way its records cannot show */
	uint32_t root_pid;     /* the traced subtree, or 0 for a whole machine */
	/*
	 * WHICH MACHINE WROTE THIS, one byte each.
	 *
	 * The most important thing in the header after the record's identity:
	 * a log is opened by something that did not produce it, on a different
	 * platform, possibly years later - and almost every field in a record
	 * means something platform-shaped. A pid, a path separator, whether an
	 * address is 32 or 64 bits wide. A reader that has to guess gets it
	 * right until the day it does not.
	 */
	uint8_t  platform;     /* enum kof_evt_platform */
	uint8_t  arch;         /* enum kof_evt_arch */
	uint16_t rec_kind;     /* enum kofevt_rec_kind */

	/*
	 * Written at CLOSE, so a file killed mid-run has zero here and a reader
	 * knows to count instead of trust. Not a defect: a count that is only
	 * correct when the writer exited cleanly has to be distinguishable from
	 * one that was never written.
	 */
	uint64_t n_records;

	/*
	 * THE SHAPE OF A RECORD, so this file can walk one without knowing
	 * what any field means.
	 *
	 * `head_size` is the fixed part. `len_off` is where a uint16 giving the
	 * text length sits inside it. Together they are the whole contract
	 * between a variable-length log and a record type it has never heard
	 * of - which is what keeps kofevt's log usable by a Linux collector
	 * whose record has different fields in a different order.
	 */
	uint16_t head_size;
	uint16_t len_off;

	uint8_t  reserved[12];
};

/*
 * WHAT A RUN WAS, filled by the caller because none of it can be derived here.
 *
 * `rec_size` and `rec_kind` together identify the record; both are written into
 * the header and both are checked on the way back in.
 */
struct kofevt_log_info {
	/* The whole record, which bounds how much text one may claim. */
	uint32_t rec_size;
	/* The fixed part, and where the uint16 text length lives in it. Both
	 * are offsetof/sizeof at the caller, which is the only place that
	 * knows the record's layout. */
	uint16_t head_size;
	uint16_t len_off;
	uint32_t rec_kind;     /* enum kofevt_rec_kind */
	uint32_t build;        /* the collector's build stamp */
	uint8_t  platform;     /* enum kof_evt_platform; 0 asks for this host */
	uint8_t  arch;         /* enum kof_evt_arch;     0 asks for this host */
	uint32_t root_pid;     /* the traced subtree, or 0 */
	uint32_t sub_asked;
	uint32_t sub_enabled;
	uint64_t started;
};

/* --------------------------------------------------------------- writing */

struct kofevt_log_w;

/*
 * Open `path` for writing. NULL on failure, including a zero or absurd
 * rec_size - a fixed-record file whose record size is wrong is not recoverable
 * later, so it is refused at the only point where refusing is free.
 *
 * NOT SAFE FROM AN EVENT CALLBACK, and that is a property of the design rather
 * than a caveat. A write is file I/O, file I/O raises file events, and a
 * collector that logged from inside its own callback would feed itself. Call it
 * from the consumer thread.
 */
struct kofevt_log_w *kofevt_log_create(const char *path,
				       const struct kofevt_log_info *);

/* Append one record of exactly the declared size. Non-zero on a write error,
 * after which the writer stops trying - a partially written record would
 * desynchronise every later one. */
int kofevt_log_write(struct kofevt_log_w *, const void *rec);

/* Finish the header and close. Returns the record count, or 0. */
uint64_t kofevt_log_close(struct kofevt_log_w *);

/* --------------------------------------------------------------- reading */

struct kofevt_log_r;

/*
 * Open a recorded log, refusing one whose record does not match what the
 * caller can decode. `why` gets a short reason and may be NULL.
 *
 * Pass want_rec_kind KOFEVT_REC_NONE to accept any kind - for a tool that only
 * reports what a file contains and never decodes a record.
 */
struct kofevt_log_r *kofevt_log_open(const char *path, uint32_t want_rec_size,
				     uint32_t want_rec_kind, const char **why);

/* The header, for a reader that wants to say what it is holding. */
const struct kofevt_log_hdr *kofevt_log_header(const struct kofevt_log_r *);

/* 1 and fills `out` with one record, 0 at the end. A short final record is the
 * end, not an error: a log of something that took the machine down is
 * truncated by definition, and refusing to read the 40 000 records before the
 * truncation would be losing the evidence to a technicality. */
int kofevt_log_read(struct kofevt_log_r *, void *out);

/* ------------------------------------------------------- for a viewer */

/*
 * HOW MANY RECORDS, without reading them.
 *
 * The header's own count when the writer closed cleanly, and a counted walk
 * when it did not - a log of something that took the machine down has zero
 * there, and that is the case a viewer most needs to open.
 *
 * The walk reads heads and SEEKS PAST text rather than reading it, so counting
 * a large log costs seeks and not memory.
 */
uint64_t kofevt_log_count(struct kofevt_log_r *);

/*
 * Position at record `n`, so the next kofevt_log_read returns it.
 *
 * WHY THIS IS NOT A MULTIPLICATION ANY MORE, and what replaces it.
 *
 * Records are variable length, so record N is not at a computable offset. A
 * viewer scrolling a list still needs to jump, and the two obvious answers are
 * both wrong: walking from the start on every scroll is O(n) per keystroke,
 * and remembering every record's offset is 8 bytes per event - 800MB on a log
 * with a hundred million of them, which is the overflow this is supposed to
 * avoid.
 *
 * So: a CHECKPOINT every KOFEVT_LOG_STRIDE records, built once, and a walk of
 * at most that many from the nearest one. A hundred million events cost under
 * a megabyte of index and never more than 1023 records of walking.
 *
 * Non-zero on success. The index is built on the first call, not at open, so a
 * consumer that only streams never pays for it.
 */
#define KOFEVT_LOG_STRIDE 1024u

int kofevt_log_seek(struct kofevt_log_r *, uint64_t n);

/*
 * WHERE RECORD `n` LIVES IN THE FILE - its offset and its length on disk.
 *
 * For a UI that maps the file and wants to show one event's actual bytes: a
 * viewer with the log mapped can point a hex pane at exactly this slice
 * without reading the record at all, and without copying anything.
 *
 * The length is the ON-DISK length - the fixed head plus this record's own
 * text - not sizeof the struct. Those differ, and a pane sized from the struct
 * would show the next record's opening bytes as though they were this one's.
 *
 * Non-zero on success. Uses the same sparse index kofevt_log_seek does, so the
 * first call pays for it and the rest are a checkpoint plus a short walk.
 */
int kofevt_log_extent(struct kofevt_log_r *, uint64_t n, uint64_t *off,
		      uint32_t *len);

void kofevt_log_free(struct kofevt_log_r *);

#endif /* KOFEVT_LOG_H */
