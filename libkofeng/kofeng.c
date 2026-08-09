/*
 * kofeng.c - the API boundary.
 *
 * Delegation and nothing else: validate what came in, own the lifetimes, translate
 * between the public types and the internal ones. The work is in kofdb (materialise
 * the database) and kofscanners (walk an object).
 *
 * Worth being this thin. The public header is the promise; if the promise is kept by
 * a file small enough to read in one go, there is nowhere for it to be quietly broken.
 */

#include "kofeng.h"
#include "kofdb/kofdb.h"
#include "kofscanners/scan.h"

kof_engine *kof_engine_open(const char *db_path)
{
	if (!db_path)
		return NULL;
	return kof_db_load(db_path);
}

void kof_engine_close(kof_engine *e)
{
	kof_db_free(e);
}

uint32_t kof_engine_modules(const kof_engine *e)
{
	return e ? e->n_mods : 0;
}

uint32_t kof_engine_strings(const kof_engine *e)
{
	return e ? e->n_str : 0;
}

kof_scanner *kof_scanner_new(const kof_engine *e)
{
	if (!e)
		return NULL;
	return kof_scan_new(e);
}

void kof_scanner_free(kof_scanner *sc)
{
	kof_scan_free(sc);
}

const struct kof_stats *kof_scanner_stats(const kof_scanner *sc)
{
	return sc ? kof_scan_stats(sc) : NULL;
}

int kof_scan_path(kof_scanner *sc, const char *path,
		  const struct kof_scan_option *opt, kof_on_object cb, void *user)
{
	static const struct kof_scan_option conservative;   /* all zero: no recursion */

	if (!sc || !path)
		return KOF_ERR_ARG;
	return kof_scan_walk(sc, path, opt ? opt : &conservative, cb, user);
}
