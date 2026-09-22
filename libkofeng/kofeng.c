/*
 * kofeng.c - the API boundary.
 *
 * Delegation and nothing else: validate what came in, own the lifetimes, translate
 * between the public types and the internal ones. The work is in dbloader (materialise
 * the database) and scanners (walk an object).
 *
 * Worth being this thin. The public header is the promise; if the promise is kept by
 * a file small enough to read in one go, there is nowhere for it to be quietly broken.
 */

#include "kofeng.h"
#include "databases/dbloader.h"
#include "detector/matchers/kofmultimatch.h"
#include "scanners/scan.h"

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
int kof_engine_multimatch(const kof_engine *e, uint64_t *bytes,
			  uint32_t *max_chain)
{
	uint32_t i, worst = 0;

	if (bytes)
		*bytes = 0;
	if (max_chain)
		*max_chain = 0;
	if (!e || !e->multi)
		return -1;
	if (bytes)
		*bytes = (uint64_t)e->multi->bytes;
	for (i = 0; i < KOF_MULTIMATCH_BITS; i++)
		if (e->multi->tab[i].max_chain > worst)
			worst = e->multi->tab[i].max_chain;
	if (max_chain)
		*max_chain = worst;
	return 0;
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
uint64_t kof_engine_db_stamp(const kof_engine *e)
{
	uint64_t acc = 0;
	uint32_t i, n = 0;

	if (!e)
		return 0;
	for (i = 0; i < e->n_packs; i++) {
		const struct kof_pack_hdr *h = e->packs[i].map;
		uint64_t m;

		if (!h)
			continue;
		/*
		 * THE CHECKSUM IS THE PACK'S CONTENT, already computed and
		 * already verified at load - see dbcore.h, step 5. The length
		 * and the build go in beside it so that two files could not
		 * agree by a crc collision alone.
		 */
		m = (uint64_t)h->crc32;
		m = m * 1099511628211ull + h->file_len;
		m = m * 1099511628211ull + h->build;
		m = m * 1099511628211ull +
		    (((uint64_t)h->major << 48) | ((uint64_t)h->minor << 32) |
		     h->machine);
		/*
		 * ADDED, NOT CHAINED, so the answer does not depend on the
		 * order a directory walk happened to hand the packs over in -
		 * two runs over one database must agree, and nothing promises
		 * readdir order.
		 */
		acc += m;
		n++;
	}
	if (!n)
		return 0;
	/* The COUNT as well, so that a pack removed is not hidden by one added
	 * whose mix happens to sum the same. */
	acc = acc * 1099511628211ull + n;
	return acc ? acc : 1ull;
}

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

/*
 * See kofeng.h. The arithmetic is the emulator gate's, lifted here rather than
 * copied: emu_unpack.c now calls this, so there is one implementation and one
 * place for the test in tests/unit/emu_gate.c to check.
 */
uint32_t kof_entropy_hist(const uint32_t hist[256], uint64_t total)
{
	uint64_t acc = 0, n = total;
	unsigned k;

	if (!hist || !n)
		return 0;
	for (k = 0; k < 256u; k++) {
		uint64_t c = hist[k], scaled, base, frac;
		unsigned lg = 0;

		if (!c)
			continue;
		/*
		 * -log2(c/n) = log2(n) - log2(c), computed on n*256/c so the
		 * fraction survives the integer log.
		 */
		scaled = (n << 8) / c;
		while (scaled >> (lg + 1u))
			lg++;
		base = (uint64_t)1 << lg;
		frac = ((scaled - base) << 3) / base;
		acc += c * (((uint64_t)lg << 3) + frac - (8u << 3));
	}
	return (uint32_t)(acc / n);
}

uint32_t kof_entropy_eighths(const void *bytes, uint64_t n)
{
	const uint8_t *p = bytes;
	uint32_t hist[256];
	uint64_t i;

	if (!p || !n)
		return 0;
	memset(hist, 0, sizeof hist);
	for (i = 0; i < n; i++)
		hist[p[i]]++;
	return kof_entropy_hist(hist, n);
}
