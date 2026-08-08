/*
 * scan.h - scan one object.
 *
 * This is the leaf of the scan tree and the only place a module is ever entered. It
 * takes bytes, never a path: producing bytes - from a file now, from a descriptor,
 * memory or a decompressor later - belongs to whatever calls this.
 *
 * All mutable state lives in kof_scanner, one per thread, and the engine it points
 * at is immutable. That split is what makes the expensive parts affordable: the
 * presence table is 32MB, so it is allocated once per thread and reused for every
 * object, not per file and not per module.
 */

#ifndef KOFENG_SCAN_H
#define KOFENG_SCAN_H

#include "../kofeng.h"
#include "../kofdb/kofdb.h"
#include "../kofmatchers/kofmatch.h"
#include "../kofparsers/elf/elf_parse.h"

/*
 * Why modules were not run. The measurement the whole precondition idea stands or
 * falls on: a filter that rules nothing out is overhead, and only counting says which.
 */

struct kof_scanner;

struct kof_scanner *kof_scan_new(const struct kof_engine *);
void                 kof_scan_free(struct kof_scanner *);

const struct kof_stats *kof_scan_stats(const struct kof_scanner *);

/*
 * Scan one object. Appends to `out`.
 *
 * `name` is metadata, not a path: a file name and a member name inside an archive are
 * the same field, which is what keeps the tree uniform with no special case for the
 * root. May be NULL.
 *
 * Returns the number of findings appended.
 */
uint32_t kof_scan_object(struct kof_scanner *, kof_buf buf, const char *name,
			 struct kof_result *out);

/*
 * Scan whatever a path names, from the orchestrator. Returns a finding count or a
 * KOF_ERR_*. The facade in kofeng.c is the only intended caller.
 */
/* Only the walk touches this: it counts what it could not open. */
void kof_scan_count_unreadable(struct kof_scanner *);

int kof_scan_walk(struct kof_scanner *, const char *path,
			  const struct kof_policy *, kof_on_object cb,
			  void *user);

#endif /* KOFENG_SCAN_H */