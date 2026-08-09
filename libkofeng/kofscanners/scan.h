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
#include "../kofparsers/pe/pe_parse.h"

/*
 * Why modules were not run. The measurement the whole precondition idea stands or
 * falls on: a filter that rules nothing out is overhead, and only counting says which.
 */

/*
 * Everything mutable, one per thread.
 *
 * The engine it points at is immutable and shared. Splitting them is what keeps the
 * 32MB presence table out of the per-file path: it belongs to the thread, is allocated
 * once, and is reused for every object.
 */
struct kof_scanner {
	const struct kof_engine *eng;

	struct kof_match_ctx m;
	/*
	 * One parsed view per format, allocated the first time an object of that
	 * format is seen and kept for the life of the scanner.
	 *
	 * Not all of them up front: a view is kilobytes, and a scanner on a Linux
	 * host never meets a PE, so allocating every format's view would make the
	 * cost of supporting a format something every scanner pays whether or not
	 * it ever meets one. Not per object either, which is what this was avoiding
	 * in the first place - that puts a malloc of kilobytes in the hot path for
	 * every file.
	 *
	 * Indexed by enum kof_format, so adding a format adds a table row and no
	 * field here.
	 */
	void *view[KOF_FMT_COUNT];


	/* Set while a module runs: find_str is called from inside one, and the ids it
	 * passes are module local, so the host has to know whose they are. */
	const struct kof_module *cur_mod;

	/* What the running module reported. A module cannot hold state, so a finding
	 * has to land here. */
	uint32_t rep_level, rep_name_id;
	int      rep_valid;

	struct kof_stats st;
};

struct kof_scanner *kof_scan_new(const struct kof_engine *);
void                 kof_scan_free(struct kof_scanner *);

const struct kof_stats *kof_scan_stats(const struct kof_scanner *);

/*
 * Scan whatever a path names, from the orchestrator. Returns a finding count or a
 * KOF_ERR_*. The facade in kofeng.c is the only intended caller.
 */
/*
 * Present an object to a module: fills in every field a module can reach.
 *
 * Defined in objctx.c, which is the whole untrusted boundary - every entry bounds
 * checks, and nothing else in the tree lets module code near memory.
 */
void kof_mod_attach(struct kof_obj_ctx *, struct kof_scanner *);

/* Turn a named range into extents. objctx.c needs it; the parse is what knows. */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *, uint32_t scan_mask,
				struct kof_range *ext);

/* Recover the scanner from a context handed to a module. */
struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *);

int kof_scan_walk(struct kof_scanner *, const char *path,
			  const struct kof_scan_option *, kof_on_object cb,
			  void *user);

#endif /* KOFENG_SCAN_H */