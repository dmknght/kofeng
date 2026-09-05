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

uint32_t kof_engine_heur_rules(const kof_engine *e)
{
	return e ? e->n_heur : 0;
}

/*
 * A reason in words, for whoever has to read the scan.
 *
 * Here and not in the caller because the vocabulary is the engine's: a host that
 * spelled these itself would drift from what the engine actually reports the day a
 * reason is added.
 *
 * NOUN PHRASES, SENTENCE CASE. They were clauses - "the content is encrypted" -
 * from when they only ever appeared after a colon. The scanner now prints the
 * most specific thing it knows in the first column, so a reason starts a line,
 * and a clause reads as a fragment there. A noun phrase reads correctly in both
 * places.
 */
const char *kof_broken_name(uint32_t reason)
{
	switch (reason) {
	case KOF_BROKEN_LIMIT:       return "Limit reached";
	case KOF_BROKEN_UNSUPPORTED: return "Unsupported by this build";
	case KOF_BROKEN_DAMAGED:     return "Damaged object";
	case KOF_BROKEN_ENCRYPTED:   return "Encrypted content";
	default:                     return "Unknown";
	}
}

/*
 * What this build of the library is. See kofeng.h for why it decides nothing.
 */
void kof_engine_version(struct kof_version *out)
{
	if (!out)
		return;
	out->major = KOFENG_MAJOR;
	out->minor = KOFENG_MINOR;
	out->build = KOFENG_BUILD;
}

/*
 * The oldest version among the loaded packs - see kofeng.h for why oldest.
 *
 * The header is already resident: a pack is mapped and kof_db_pack keeps the
 * mapping, so this reads the bytes the loader validated rather than a copy made
 * beside them. Nothing stores these values anywhere, which is the point - one
 * source, and it is the file.
 */
int kof_engine_db_version(const kof_engine *e, struct kof_db_version *out)
{
	uint32_t i;
	int have = 0;

	if (!out)
		return 0;
	out->major = out->minor = 0;
	out->build = out->machine = 0;
	if (!e)
		return 0;
	for (i = 0; i < e->n_packs; i++) {
		const struct kof_pack_hdr *h = e->packs[i].map;

		if (!h)
			continue;
		if (!have || h->major < out->major ||
		    (h->major == out->major && h->minor < out->minor) ||
		    (h->major == out->major && h->minor == out->minor &&
		     h->build < out->build)) {
			out->major   = h->major;
			out->minor   = h->minor;
			out->build   = h->build;
			out->machine = h->machine;
		}
		have = 1;
	}
	return have;
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

int kof_scan_path_mt(kof_scanner **scs, unsigned n_sc, const char *path,
		     const struct kof_scan_option *opt, kof_on_object cb,
		     void *user)
{
	static const struct kof_scan_option conservative;   /* all zero: no recursion */

	if (!scs || !n_sc || !path)
		return KOF_ERR_ARG;
	return kof_scan_walk_mt(scs, n_sc, path, opt ? opt : &conservative,
				cb, user);
}
