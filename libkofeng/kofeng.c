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

uint32_t kof_engine_records(const kof_engine *e)
{
	return e ? e->n_mods : 0;
}

uint32_t kof_engine_unpackers(const kof_engine *e)
{
	return e ? e->n_unp : 0;
}

/*
 * A reason in words, for whoever has to read the scan.
 *
 * Here and not in the caller because the vocabulary is the engine's: a host that
 * spelled these itself would drift from what the engine actually reports the day a
 * reason is added.
 */
const char *kof_broken_name(uint32_t reason)
{
	switch (reason) {
	case KOF_BROKEN_LIMIT:       return "a limit was reached";
	case KOF_BROKEN_UNSUPPORTED: return "not supported by this build";
	case KOF_BROKEN_DAMAGED:     return "the object is damaged";
	case KOF_BROKEN_ENCRYPTED:   return "the content is encrypted";
	default:                     return "unknown";
	}
}

uint32_t kof_engine_db_version(const kof_engine *e)
{
	/* Not read back out of the engine: a pack whose version differs from this one
	 * never became part of it, so the loaded version and this constant are the
	 * same number by construction. Taking the argument anyway keeps the call
	 * shaped like the rest, and keeps the answer meaningless without a database -
	 * which is what it is. */
	return e ? KOF_PACK_VERSION : 0;
}

kof_scanner *kof_scanner_new(const kof_engine *e)
{
	if (!e)
		return NULL;
	return kof_scan_new(e);
}

/*
 * Ask to be told what modules work out.
 *
 * Per scanner rather than per engine: the engine is shared by every thread and is
 * immutable, and one thread wanting diagnostics must not turn them on for the rest.
 */
void kof_scanner_on_debug(kof_scanner *sc, kof_on_debug cb, void *user)
{
	if (!sc)
		return;
	sc->debug_cb = cb;
	sc->debug_user = user;
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
